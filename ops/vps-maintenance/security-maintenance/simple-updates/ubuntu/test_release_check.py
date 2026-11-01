import importlib.util
import io
import json
from http.client import HTTPResponse, IncompleteRead
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("release_check", Path(__file__).with_name("release_check.py"))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

CURRENT = "Dist: resolute\nVersion: 26.04.1 LTS\nSupported: 1\n"
NEW = "\nDist: stonking\nVersion: 26.10\nSupported: 1\n"
HASH = "a" * 64


def fixture(new_feed=False, final=True):
    values = {check.RELEASE_ROOT: '<a href="26.04.1/">old</a><a href="26.10/">new</a>',
              check.NORMAL_FEED: CURRENT + (NEW if new_feed else ""),
              check.RELEASE_ROOT + "26.10/SHA256SUMS": HASH + " *ubuntu-26.10-" + ("live-server" if final else "beta-live-server") + "-amd64.iso\n"}
    return values.__getitem__


class ReleaseTests(unittest.TestCase):
    def test_published_release_not_yet_offered_is_explicit_blocker(self):
        report = check.collect("26.04", "lts", fixture())
        self.assertEqual(report["status"], "attention")
        self.assertEqual(report["newer_stable_release"], "26.10")
        self.assertFalse(report["newest_stable_normally_offered"])
        self.assertEqual(len(report["blockers"]), 3)
        self.assertFalse(report["installation_performed"])

    def test_offered_release_still_requires_qualification(self):
        report = check.collect("26.04", "normal", fixture(new_feed=True))
        self.assertTrue(report["newest_stable_normally_offered"])
        self.assertEqual(report["next_normal_supported_release"]["release"], "26.10")
        self.assertEqual(len(report["blockers"]), 1)
        self.assertIn("not established", report["qualification"])

    def test_beta_image_does_not_establish_stable_publication(self):
        report = check.collect("26.04", "normal", fixture(final=False))
        self.assertEqual(report["status"], "current")
        self.assertIsNone(report["newer_stable_release"])

    def test_catalog_ignores_untrusted_and_non_numeric_links(self):
        releases = check.released_versions('<a href="https://evil.example/99.10/">x</a><a href="../">up</a><a href="27.04/">future</a><a href="26.10/">stable</a>')
        self.assertEqual(releases, ["27.04", "26.10"])
        for url in ("http://releases.ubuntu.com/", "https://releases.ubuntu.com.evil/a", "https://user@releases.ubuntu.com/", "https://releases.ubuntu.com/a?q=secret", "https://releases.ubuntu.com:invalid/", "https://releases.ubuntu.com:99999/"):
            self.assertFalse(check.valid_url(url))

    def test_truncated_http_response_is_sanitized_check_failure(self):
        fetch = check.Fetcher()
        response = MagicMock()
        response.url = check.RELEASE_ROOT
        response.headers = {}
        response.read1.side_effect = IncompleteRead(b"private-response-content", 99)
        fetch.opener = MagicMock()
        fetch.opener.open.return_value.__enter__.return_value = response
        with self.assertRaises(check.CheckError) as error:
            fetch(check.RELEASE_ROOT)
        self.assertNotIn("private", str(error.exception))
        self.assertEqual(fetch.evidence, [])

    def test_fetcher_stops_oversized_metadata_before_parsing(self):
        fetch = check.Fetcher()
        response = MagicMock()
        response.url = check.RELEASE_ROOT
        response.headers = {}
        response.read1.side_effect = [b"a" * 65536] * 33
        fetch.opener = MagicMock()
        fetch.opener.open.return_value.__enter__.return_value = response
        with self.assertRaisesRegex(check.CheckError, "size limit"):
            fetch(check.RELEASE_ROOT)
        self.assertEqual(fetch.evidence, [])

    def test_actual_httpresponse_premature_eof_rejects_valid_catalog_prefix(self):
        body = b'<a href="26.04/">26.04</a>'
        class Socket:
            def makefile(self, *args, **kwargs):
                return io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + body)
        response = HTTPResponse(Socket())
        response.begin()
        response.url = check.RELEASE_ROOT
        fetch = check.Fetcher()
        fetch.opener = MagicMock()
        fetch.opener.open.return_value = response
        with self.assertRaisesRegex(check.CheckError, "declared length"):
            fetch(check.RELEASE_ROOT)
        self.assertEqual(response.length, 100 - len(body))
        self.assertEqual(fetch.evidence, [])

    def test_duplicate_or_unrecognized_metadata_fails(self):
        for text in ("garbage", "Dist: stonking\nVersion: 26.10\nSupported: maybe", CURRENT + "Version: 26.04\n"):
            with self.subTest(text=text), self.assertRaises(check.CheckError):
                check.normal_releases(text)
        with self.assertRaises(check.CheckError):
            check.released_versions("no versions")
        with self.assertRaises(check.CheckError):
            check.final_server_image((HASH + " *ubuntu-26.10-live-server-amd64.iso\n") * 2, "26.10")
        with self.assertRaises(check.CheckError):
            check.final_server_image("unrecognized manifest", "26.10")

    def test_point_release_artifact_does_not_trigger_series_upgrade(self):
        report = check.collect("26.04", "lts", {check.RELEASE_ROOT: '<a href="26.04.1/">point</a>', check.NORMAL_FEED: CURRENT}.__getitem__)
        self.assertEqual(report["status"], "current")

    def test_contradictory_offering_and_publication_is_unknown(self):
        with self.assertRaises(check.CheckError):
            check.collect("26.04", "normal", fixture(new_feed=True, final=False))

    def test_unreachable_or_malformed_check_is_unknown_not_current(self):
        for error in (check.CheckError("Official HTTPS metadata could not be retrieved or decoded."), check.CheckError("catalog malformed")):
            with patch.object(check, "read_local", return_value=("26.04", "lts")), patch.object(check, "collect", side_effect=error), patch("builtins.print") as output:
                self.assertEqual(check.main(["--json"]), 1)
                self.assertEqual(json.loads(output.call_args.args[0])["status"], "unknown")

    def test_local_settings_require_unambiguous_ubuntu_and_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            os_path, prompt_path = Path(directory) / "os", Path(directory) / "prompt"
            os_path.write_text('ID=ubuntu\nVERSION_ID="26.04"\n')
            prompt_path.write_text("# config\nPrompt=lts\n")
            self.assertEqual(check.read_local(os_path, prompt_path), ("26.04", "lts"))
            prompt_path.write_text("Prompt=lts\nPrompt=normal\n")
            with self.assertRaises(check.CheckError):
                check.read_local(os_path, prompt_path)


if __name__ == "__main__":
    unittest.main()
