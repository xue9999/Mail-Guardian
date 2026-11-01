"""Security-focused unit tests for candidate selection; no network or Docker."""

import contextlib
import io
import json
import sys
import unittest
import urllib.error
from unittest import mock

import image_candidates as candidates


CURRENT = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64
NEWER = "sha256:" + "c" * 64


class ParsePinTests(unittest.TestCase):
    def test_known_repositories_and_variants(self):
        samples = (
            ("redis:7.4.9-alpine@" + CURRENT, "redis", "library/redis", "7.4.9-alpine", (7, 4, 9), "-alpine"),
            ("rspamd/rspamd:4.1.2@" + CURRENT, "rspamd/rspamd", "rspamd/rspamd", "4.1.2", (4, 1, 2), ""),
            ("klutchell/unbound:1.25.2@" + CURRENT, "klutchell/unbound", "klutchell/unbound", "1.25.2", (1, 25, 2), ""),
        )
        for ref, repo, hub_repo, tag, version, suffix in samples:
            with self.subTest(reference=ref):
                pin = candidates.parse_pin(ref)
                self.assertEqual(pin["repo"], repo)
                self.assertEqual(pin["hub_repo"], hub_repo)
                self.assertEqual(pin["tag"], tag)
                self.assertEqual(pin["digest"], CURRENT)
                self.assertEqual((pin["major"], pin["minor"], pin["patch"]), version)
                self.assertEqual(pin["suffix"], suffix)

    def test_malformed_or_ambiguous_pins_are_rejected(self):
        refs = (
            "redis:7.4.9-alpine",  # no immutable digest
            "redis:7.4.9-alpine@sha256:not-a-digest",
            "redis:7.4.9-alpine@sha256:" + "A" * 64,
            "redis:7.4@" + CURRENT,
            "redis:7.4.9-rc1@" + CURRENT,
            "redis:7.4.9-alpine;echo@" + CURRENT,
            "redis:7.4.9-alpine@" + CURRENT + "\n",
            "attacker.example/redis:7.4.9-alpine@" + CURRENT,
        )
        for ref in refs:
            with self.subTest(reference=ref), self.assertRaises((ValueError, TypeError)):
                candidates.parse_pin(ref)


class PatchSelectionTests(unittest.TestCase):
    def setUp(self):
        self.pin = candidates.parse_pin("redis:7.4.9-alpine@" + CURRENT)

    def test_numeric_patch_order_not_lexical(self):
        rows = [
            {"name": "7.4.10-alpine", "digest": NEWER},
            {"name": "7.4.9-alpine", "digest": CURRENT},
            {"name": "7.4.8-alpine", "digest": NEW},
        ]
        chosen = candidates.select_patch(self.pin, rows)
        self.assertEqual(chosen["name"], "7.4.10-alpine")
        self.assertEqual(chosen["digest"], NEWER)

    def test_candidate_must_retain_major_minor_and_variant(self):
        rows = [
            {"name": "8.4.99-alpine", "digest": NEW},
            {"name": "7.5.99-alpine", "digest": NEW},
            {"name": "7.4.99", "digest": NEW},
            {"name": "7.4.99-alpine3.99", "digest": NEW},
            {"name": "7.4.99-alpine-rc1", "digest": NEW},
            {"name": "7.4.8-alpine", "digest": NEW},
        ]
        self.assertIsNone(candidates.select_patch(self.pin, rows))

    def test_same_tag_new_digest_is_candidate_but_same_digest_is_not(self):
        self.assertIsNone(candidates.select_patch(self.pin, [{"name": "7.4.9-alpine", "digest": CURRENT}]))
        chosen = candidates.select_patch(self.pin, [{"name": "7.4.9-alpine", "digest": NEW}])
        self.assertEqual(chosen["name"], "7.4.9-alpine")
        self.assertEqual(chosen["digest"], NEW)

    def test_nonversion_tags_prereleases_and_injection_are_ignored(self):
        rows = [
            {"name": "latest", "digest": NEW},
            {"name": "7.4.10-rc1", "digest": NEW},
            {"name": "7.4.10-alpine-rc1", "digest": NEW},
            {"name": "7.4.10-alpine;echo", "digest": NEW},
            {"name": "7.4.10-alpine\n", "digest": NEW},
        ]
        self.assertIsNone(candidates.select_patch(self.pin, rows))

    def test_matching_candidate_with_invalid_digest_fails_closed(self):
        rows = [{"name": "7.4.10-alpine", "digest": "sha256:broken"}]
        with self.assertRaises((ValueError, TypeError)):
            candidates.select_patch(self.pin, rows)

    def test_conflicting_digest_for_same_candidate_fails_closed(self):
        rows = [
            {"name": "7.4.10-alpine", "digest": NEW},
            {"name": "7.4.10-alpine", "digest": NEWER},
        ]
        with self.assertRaises((ValueError, TypeError)):
            candidates.select_patch(self.pin, rows)


class FakeResponse:
    def __init__(self, url, payload):
        self.url, self.payload = url, payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return self.url

    def read(self, size):
        return json.dumps(self.payload).encode()


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.pin = candidates.parse_pin("redis:7.4.9-alpine@" + CURRENT)
        self.current = {"name": "7.4.9-alpine", "digest": CURRENT}
        self.next_tag = {"name": "7.4.10-alpine", "digest": NEW}
        self.page2 = "https://hub.docker.com/v2/repositories/library/redis/tags?name=7.4.&page=2"

    def opener_for(self, responses):
        opener = mock.Mock()

        def open_page(request, timeout):
            payload = responses.pop(0)
            if isinstance(payload, Exception):
                raise payload
            return FakeResponse(request.full_url, payload)

        opener.open.side_effect = open_page
        return opener

    def test_all_pages_read_and_installed_tag_seen(self):
        opener = self.opener_for([
            {"count": 2, "results": [self.current], "next": self.page2},
            {"count": 2, "results": [self.next_tag], "next": None},
        ])
        with mock.patch.object(candidates.urllib.request, "build_opener", return_value=opener):
            rows = candidates.tags_for(self.pin)
        self.assertEqual([x["name"] for x in rows], [self.current["name"], self.next_tag["name"]])
        self.assertEqual(opener.open.call_count, 2)

    def test_changed_count_fails(self):
        opener = self.opener_for([
            {"count": 2, "results": [self.current], "next": self.page2},
            {"count": 3, "results": [self.next_tag], "next": None},
        ])
        with mock.patch.object(candidates.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(ValueError, "count changed"):
                candidates.tags_for(self.pin)

    def test_missing_rows_and_missing_current_tag_fail(self):
        scenarios = [
            {"count": 2, "results": [self.current], "next": None},
            {"count": 1, "results": [self.next_tag], "next": None},
        ]
        for payload in scenarios:
            with self.subTest(payload=payload):
                opener = self.opener_for([payload])
                with mock.patch.object(candidates.urllib.request, "build_opener", return_value=opener):
                    with self.assertRaises(ValueError):
                        candidates.tags_for(self.pin)

    def test_cross_origin_next_page_rejected_before_request(self):
        payload = {"count": 2, "results": [self.current], "next": "https://attacker.invalid/v2/repositories/library/redis/tags?page=2"}
        opener = self.opener_for([payload])
        with mock.patch.object(candidates.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(ValueError, "unexpected registry URL"):
                candidates.tags_for(self.pin)
        self.assertEqual(opener.open.call_count, 1)

    def test_next_page_must_retain_exact_filter(self):
        paths = (
            "https://hub.docker.com/v2/repositories/library/redis/tags?page=2",
            "https://hub.docker.com/v2/repositories/library/redis/tags?name=7.5.&page=2",
        )
        for next_url in paths:
            with self.subTest(next_url=next_url):
                opener = self.opener_for([{"count": 2, "results": [self.current], "next": next_url}])
                with mock.patch.object(candidates.urllib.request, "build_opener", return_value=opener):
                    with self.assertRaises(ValueError):
                        candidates.tags_for(self.pin)
                self.assertEqual(opener.open.call_count, 1)

    def test_duplicate_rows_even_with_same_digest_fail(self):
        opener = self.opener_for([
            {"count": 2, "results": [self.current], "next": self.page2},
            {"count": 2, "results": [self.current], "next": None},
        ])
        with mock.patch.object(candidates.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(ValueError):
                candidates.tags_for(self.pin)

    def test_http_failure_surfaces_as_error(self):
        error = urllib.error.HTTPError("https://hub.docker.com/", 429, "rate limited", {}, None)
        opener = self.opener_for([error])
        with mock.patch.object(candidates.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(urllib.error.HTTPError):
                candidates.tags_for(self.pin)

    def test_missing_amd64_reports_error_not_clean(self):
        row = {"name": "7.4.10-alpine", "digest": NEW, "images": [
            {"os": "linux", "architecture": "arm64", "digest": NEWER}
        ]}
        output = io.StringIO()
        with mock.patch.object(candidates, "image_pins", return_value=[self.pin]), \
             mock.patch.object(candidates, "tags_for", return_value=[row]), \
             mock.patch.object(sys, "argv", ["image_candidates.py"]), \
             contextlib.redirect_stdout(output):
            code = candidates.main()
        report = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertTrue(report["errors"])
        self.assertIn("linux/amd64", report["errors"][0])


if __name__ == "__main__":
    unittest.main()
