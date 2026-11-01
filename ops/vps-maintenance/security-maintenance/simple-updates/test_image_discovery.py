import io
import json
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import image_discovery as d


def release(ident, tag, prerelease=False, draft=False):
    return {"id": ident, "tag_name": tag, "prerelease": prerelease, "draft": draft}


def image(tag, index="1", platform="2"):
    return {"name": tag, "tag_status": "active", "digest": "sha256:" + index * 64,
            "images": [{"os": "linux", "architecture": "amd64", "digest": "sha256:" + platform * 64}]}


def pins():
    return {repo: {"version": "1.0.0", "digest": "sha256:" + "1" * 64, "ref": "irrelevant"} for repo in d.SPECS}


class DiscoveryTests(unittest.TestCase):
    def test_highest_numeric_across_pages_and_no_prereleases(self):
        first = [release(i, f"1.0.{i}") for i in range(100)]
        second = [release(101, "2.0.0"), release(102, "20.0.0", True), release(103, "30.0.0", draft=True), release(104, "2.1.0-rc1")]
        pages = iter([first, second])
        self.assertEqual(d.latest_release("a/b", "", lambda _: next(pages)), "2.0.0")

    def test_prefix_and_release_format(self):
        rows = [release(1, "release-1.26.2"), release(2, "release-2.0.0-rc1"), release(3, "unrelated-9.9.9")]
        self.assertEqual(d.latest_release("x/y", "release-", lambda _: rows), "1.26.2")

    def test_page_limit_and_duplicates_fail_closed(self):
        with mock.patch.object(d, "MAX_PAGES", 1), self.assertRaises(d.DiscoveryError):
            d.latest_release("x/y", "", lambda _: [release(i, f"1.0.{i}") for i in range(100)])
        rows = [release(1, "1.0.0"), release(1, "1.0.1")]
        with self.assertRaises(d.DiscoveryError):
            d.latest_release("x/y", "", lambda _: rows)

    def test_malformed_record_fails_not_silent(self):
        with self.assertRaises(d.DiscoveryError):
            d.latest_release("x/y", "", lambda _: [{"id": 1, "tag_name": "1.0.0", "draft": False}])

    def test_image_requires_exact_active_index_and_platform(self):
        for entry in [dict(image("1.0.0"), name="other"), dict(image("1.0.0"), tag_status="inactive"),
                      dict(image("1.0.0"), digest="bad"), dict(image("1.0.0"), images=[]),
                      dict(image("1.0.0"), images=image("1.0.0")["images"] * 2)]:
            with self.subTest(entry=entry), self.assertRaises(d.DiscoveryError):
                d.image_for("x/y", "1.0.0", lambda _: entry)

    def test_discovery_major_and_digest_change(self):
        def fetch(url):
            if "api.github.com" in url:
                return [release(1, "release-2.0.0" if "NLnetLabs" in url else "2.0.0")]
            return image(url.rsplit("/", 1)[1], "3")
        result = d.discover(pins(), fetch)
        self.assertEqual(result["errors"], [])
        self.assertTrue(result["attention"])
        self.assertEqual(result["images"][0]["candidate"]["tag"], "2.0.0-alpine")
        self.assertTrue(result["images"][0]["candidate"]["ref"].endswith("sha256:" + "3" * 64))
        def same_version(url):
            if "api.github.com" in url:
                return [release(1, "release-1.0.0" if "NLnetLabs" in url else "1.0.0")]
            return image(url.rsplit("/", 1)[1], "3")
        self.assertTrue(d.discover(pins(), same_version)["attention"])

    def test_missing_image_and_older_upstream_are_errors(self):
        def missing(url):
            if "api.github.com" in url:
                return [release(1, "release-1.0.1" if "NLnetLabs" in url else "1.0.1")]
            raise OSError("not found")
        errors = d.discover(pins(), missing)["errors"]
        self.assertEqual(len(errors), 3)
        self.assertIn("upstream 1.0.1: image library/redis:1.0.1-alpine", errors[0]["error"])
        def old(url):
            return [release(1, "release-0.9.9" if "NLnetLabs" in url else "0.9.9")]
        self.assertEqual(len(d.discover(pins(), old)["errors"]), 3)

    def test_missing_latest_image_reports_blocker_and_same_minor_fallback(self):
        def fetch(url):
            if 'api.github.com' in url:
                return [release(1, 'release-2.0.0' if 'NLnetLabs' in url else '2.0.0')]
            if '/tags?' in url:
                suffix = '-alpine' if 'library/redis' in url else ''
                return {'count': 2, 'next': None, 'results': [
                    {'name': '1.0.0' + suffix, 'tag_status': 'active'},
                    {'name': '1.0.1' + suffix, 'tag_status': 'active'}]}
            tag = url.rsplit('/', 1)[-1]
            if tag.startswith('2.0.0'):
                raise urllib.error.HTTPError(url, 404, 'missing', None, None)
            return image(tag, '3')
        result = d.discover(pins(), fetch)
        self.assertEqual(len(result['errors']), 3)
        self.assertEqual(len(result['images']), 3)
        self.assertEqual(result['images'][0]['candidate']['tag'], '1.0.1-alpine')
        self.assertTrue(result['images'][0]['fallback'])

    def test_parse_compose_variants_and_unexpected_images(self):
        lines = [f"  image: {repo}:1.0.0{spec[3]}@sha256:{'1' * 64}\n" for repo, spec in d.SPECS.items()]
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "compose.yaml"
            p.write_text("".join(lines))
            self.assertEqual(set(d.parse_compose(p)), set(d.SPECS))
            p.write_text("".join(lines) + lines[0])
            with self.assertRaises(d.DiscoveryError):
                d.parse_compose(p)
            p.write_text("".join(lines).replace("1.0.0-alpine", "1.0.0"))
            with self.assertRaises(d.DiscoveryError):
                d.parse_compose(p)

    def test_scheduled_check_defers_new_line_but_keeps_same_minor_patch(self):
        def fetch(url):
            if 'api.github.com' in url:
                return [release(1, 'release-2.0.0' if 'NLnetLabs' in url else '2.0.0')]
            if '/tags?' in url:
                suffix = '-alpine' if 'library/redis' in url else ''
                return {'count': 2, 'next': None, 'results': [
                    {'name': '1.0.0' + suffix, 'tag_status': 'active'},
                    {'name': '1.0.1' + suffix, 'tag_status': 'active'}]}
            self.assertNotIn('/tags/2.0.0', url)
            return image(url.rsplit('/', 1)[-1], '3')
        result = d.discover(pins(), fetch, patch_only=True)
        self.assertEqual(result['errors'], [])
        self.assertEqual(len(result['manual_review']), 3)
        self.assertTrue(result['attention'])
        self.assertEqual(result['images'][0]['candidate']['tag'], '1.0.1-alpine')

    def test_main_incomplete_takes_precedence(self):
        partial = {"images": [{"candidate": {}}], "errors": [{"error": "failed"}], "attention": True}
        with mock.patch.object(d, "parse_compose", return_value={}), mock.patch.object(d, "discover", return_value=partial), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(d.main([]), 1)
            self.assertEqual(json.loads(output.getvalue())["errors"], partial["errors"])


if __name__ == "__main__":
    unittest.main()
