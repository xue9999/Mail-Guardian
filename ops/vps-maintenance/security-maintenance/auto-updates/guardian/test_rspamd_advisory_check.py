import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import rspamd_advisory_check as check


def row(tag, ident, body="Routine changes", **extra):
    result = {"id": ident, "tag_name": tag, "draft": False, "prerelease": False,
              "body": body, "published_at": "2026-10-01T10:09:18Z"}
    result.update(extra)
    return result


class Response:
    def __init__(self, url, data, link=None):
        self.url = url
        self.data = json.dumps(data).encode()
        self.headers = {"Link": link} if link is not None else {}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def geturl(self):
        return self.url

    def read(self, amount):
        return self.data[:amount]


class FakeOpener:
    def __init__(self, pages):
        self.pages = iter(pages)
        self.seen = []

    def open(self, request, timeout):
        self.seen.append(request.full_url)
        self.assert_timeout(timeout)
        return next(self.pages)

    @staticmethod
    def assert_timeout(timeout):
        if timeout != 20:
            raise AssertionError("unexpected timeout")


class InstalledVersionTests(unittest.TestCase):
    def test_rendered_running_rspamd_and_helper_must_all_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            compose = Path(directory) / "compose.yml"
            pin = "rspamd/rspamd:4.1.2@sha256:" + "a" * 64
            compose.write_text("identical release and active config\n")
            fake = mock.Mock()
            fake.expected_service_images.return_value = {"rspamd": pin, "redis": "redis-pin", "unbound": "dns-pin"}
            fake.rspamd_helper_image.return_value = pin
            fake.running_container_images.return_value = [
                {"service": name, "matches_compose": True, "status": "running"}
                for name in ("redis", "rspamd", "unbound")]
            self.assertEqual(check.installed_version(compose, fake, compose), (4, 1, 2))
            fake.expected_service_images.return_value = {"rspamd": "redis:7.4.9@sha256:" + "a" * 64,
                                                         "redis": pin, "unbound": "dns-pin"}
            with self.assertRaises(ValueError):
                check.installed_version(compose, fake, compose)
            fake.expected_service_images.return_value = {"rspamd": pin, "redis": "redis-pin", "unbound": "dns-pin"}
            fake.running_container_images.return_value[1]["matches_compose"] = False
            with self.assertRaises(ValueError):
                check.installed_version(compose, fake, compose)


def feed(*versions):
    return {tuple(int(x) for x in version.split(".")): {
        "security_language_present": version == "4.2.1", "notes_present": True,
        "release_notes": "https://docs.rspamd.com/changelog/" + version} for version in versions}


class ReviewTests(unittest.TestCase):
    def test_every_newer_minor_is_actionable_even_without_security_keyword(self):
        rows = [row("4.1.2", 1), row("4.1.5", 2, "security fix"),
                row("4.2.0", 3), row("4.2.1", 4, "Security fixes include HTTP memory safety"),
                row("4.3.0-rc1", 5, prerelease=True), row("5.0.0", 6, draft=True)]
        newer = check.review((4, 1, 2), rows, feed("4.1.2", "4.1.5", "4.2.0", "4.2.1"))
        self.assertEqual([entry["version"] for entry in newer], ["4.2.1", "4.2.0"])
        self.assertTrue(newer[0]["security_language_present"])
        self.assertFalse(newer[1]["security_language_present"])
        self.assertEqual(newer[0]["release_notes"], "https://docs.rspamd.com/changelog/4.2.1")

    def test_installed_version_must_be_in_enumerated_releases(self):
        with self.assertRaisesRegex(ValueError, "absent"):
            check.review((4, 1, 2), [row("4.2.1", 1)], feed("4.2.1"))

    def test_unknown_published_version_is_not_silently_ignored(self):
        with self.assertRaisesRegex(ValueError, "unrecognized"):
            check.review((4, 1, 2), [row("4.1.2", 1), row("release-special", 2)], feed("4.1.2"))

    def test_missing_official_notes_are_an_incomplete_check(self):
        with self.assertRaisesRegex(ValueError, "does not cover"):
            check.review((4, 1, 2), [row("4.1.2", 1), row("4.2.1", 2, None)], feed("4.1.2"))

    def test_release_missing_from_api_or_duplicate_semver_is_incomplete(self):
        with self.assertRaisesRegex(ValueError, "API does not cover"):
            check.review((4, 1, 2), [row("4.1.2", 1)], feed("4.1.2", "4.2.1"))
        with self.assertRaisesRegex(ValueError, "repeat a semantic version"):
            check.review((4, 1, 2), [row("4.1.2", 1), row("v4.1.2", 2)], feed("4.1.2"))


class FeedTests(unittest.TestCase):
    def test_official_changelog_is_used_and_security_words_are_only_a_hint(self):
        xml = b'''<rss><channel><item><link>https://docs.rspamd.com/changelog/4.2.1</link><description>Security fix</description></item><item><link>https://docs.rspamd.com/changelog/4.1.2</link><description>Prior release</description></item></channel></rss>'''
        response = Response(check.FEED_URL, [])
        response.data = xml
        output = check.changelog_feed(FakeOpener([response]))
        self.assertTrue(output[(4, 2, 1)]["security_language_present"])
        self.assertFalse(output[(4, 1, 2)]["security_language_present"])

    def test_dtd_or_cross_origin_feed_is_rejected(self):
        response = Response(check.FEED_URL, [])
        response.data = b'<!DOCTYPE rss [<!ENTITY x "boom">]><rss><channel/></rss>'
        with self.assertRaises(ValueError):
            check.changelog_feed(FakeOpener([response]))
        # UTF-16 can hide entity declarations from byte-oriented filters.
        response.data = '<!DOCTYPE rss [<!ENTITY x "boom">]><rss><channel/></rss>'.encode("utf-16")
        with self.assertRaises((ValueError, UnicodeError)):
            check.changelog_feed(FakeOpener([response]))
        # UTF-16 without a BOM can appear as valid UTF-8 containing NULs.
        response.data = '<!DOCTYPE rss [<!ENTITY x "boom">]><rss><channel/></rss>'.encode("utf-16-le")
        with self.assertRaises(ValueError):
            check.changelog_feed(FakeOpener([response]))
        response = Response("https://attacker.example/rss/changelog.xml", [])
        with self.assertRaises(ValueError):
            check.changelog_feed(FakeOpener([response]))


class PaginationTests(unittest.TestCase):
    def setUp(self):
        self.page1 = "https://api.github.com/repos/rspamd/rspamd/releases?per_page=100&page=1"
        self.page2 = "https://api.github.com/repos/rspamd/rspamd/releases?per_page=100&page=2"

    def test_fetches_all_pages_and_preserves_filter(self):
        one = Response(self.page1, [row("4.2.1", 1)], '<' + self.page2 + '>; rel="next"')
        two = Response(self.page2, [row("4.1.2", 2)])
        opener = FakeOpener([one, two])
        self.assertEqual(len(check.releases(opener)), 2)
        self.assertEqual(opener.seen, [self.page1, self.page2])

    def test_cross_origin_and_changed_page_are_rejected(self):
        for target in ("https://evil.example/repos/rspamd/rspamd/releases?per_page=100&page=2",
                       "https://api.github.com/repos/rspamd/rspamd/releases?per_page=30&page=2",
                       "https://api.github.com/repos/rspamd/rspamd/releases?per_page=100&page=7"):
            with self.subTest(target=target):
                opener = FakeOpener([Response(self.page1, [row("4.1.2", 1)], '<' + target + '>; rel="next"')])
                with self.assertRaises(ValueError):
                    check.releases(opener)

    def test_repeated_release_or_full_unlinked_page_fails_closed(self):
        one = Response(self.page1, [row("4.1.2", 1)], '<' + self.page2 + '>; rel="next"')
        two = Response(self.page2, [row("4.1.2", 2)])
        with self.assertRaisesRegex(ValueError, "repeated"):
            check.releases(FakeOpener([one, two]))
        with self.assertRaisesRegex(ValueError, "no next-page"):
            check.releases(FakeOpener([Response(self.page1, [row("4.1." + str(i), i) for i in range(100)])]))

    def test_last_page_header_cannot_hide_missing_next_page(self):
        opener = FakeOpener([Response(self.page1, [row("4.1.2", 1)], '<' + self.page2 + '>; rel="last"')])
        with self.assertRaisesRegex(ValueError, "omits its next"):
            check.releases(opener)
        unrelated = "https://evil.example/repos/rspamd/rspamd/releases?per_page=100&page=1"
        with self.assertRaises(ValueError):
            check.releases(FakeOpener([Response(self.page1, [row("4.1.2", 1)], '<' + unrelated + '>; rel="last"')]))

    def test_api_failure_is_error_not_clean(self):
        with mock.patch.object(check, "load_host_checker"), \
                mock.patch.object(check, "installed_version", return_value=(4, 1, 2)), \
                mock.patch.object(check, "releases", side_effect=OSError("untrusted secret text")), \
                mock.patch.object(sys, "argv", ["check"]), mock.patch("builtins.print") as output:
            self.assertEqual(check.main(), 1)
        report = json.loads(output.call_args.args[0])
        self.assertFalse(report["attention"])
        self.assertEqual(report["errors"], ["release review incomplete: OSError"])
        self.assertNotIn("untrusted secret text", str(report))


if __name__ == "__main__":
    unittest.main()
