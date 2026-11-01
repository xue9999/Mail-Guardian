"""Focused aggregate-contract tests; no system packages or VPS are touched."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest import mock

path = Path(__file__).with_name("vps_security_review.py")
spec = importlib.util.spec_from_file_location("vps_security_review", path)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)

DIGEST = "sha256:" + "a" * 64


def docker(attention=False, errors=None):
    return {"checked_at_utc": "2026-10-31T18:00:00+00:00", "attention": attention, "errors": errors or [],
            "packages": [{"name": "docker-ce", "installed": "5:29.9.1-1~ubuntu.26.04~resolute",
                          "candidate": "5:29.9.2-1~ubuntu.26.04~resolute", "update_available": attention}],
            "patch_candidates": [{"repo": "redis", "installed_tag": "7.4.9-alpine",
                                  "candidate": {"tag": "7.4.12-alpine", "digest": DIGEST} if attention else None},
                                 {"repo": "rspamd/rspamd", "installed_tag": "4.1.2", "candidate": None},
                                 {"repo": "klutchell/unbound", "installed_tag": "1.25.2", "candidate": None}],
            "images": [{"tag": "redis:7.4.9-alpine", "pinned_digest": DIGEST, "tag_digest": DIGEST, "digest_changed": False},
                       {"tag": "rspamd/rspamd:4.1.2", "pinned_digest": DIGEST, "tag_digest": DIGEST, "digest_changed": False},
                       {"tag": "klutchell/unbound:1.25.2", "pinned_digest": DIGEST, "tag_digest": DIGEST, "digest_changed": False}],
            "compose_matches_release": True, "rspamd_helper_matches_compose": True,
            "runtime_images_match_compose": True}


def rspamd(attention=False, errors=None):
    return {"checked_at_utc": "2026-10-31T18:00:00Z", "mode": "release_review_only", "attention": attention, "errors": errors or [],
            "installed_version": "4.1.2", "newer_release_lines": [
                {"version": "4.2.3", "security_language_present": True,
                 "description": "DO-NOT-ECHO-UNTRUSTED-SECRET"}] if attention else []}


def unbound(attention=False, errors=None):
    return {"checked_at_utc": "2026-10-31T18:00:00+00:00", "mode": "advisory_only", "attention": attention, "errors": errors or [],
            "installed": "1.25.2", "upstream_current": "1.26.2" if attention else "1.25.2", "newer_upstream": attention,
            "version_range_advisories": [{"cve": "CVE-2026-81642",
                                          "affects": "DO-NOT-ECHO-UNTRUSTED-SECRET"}] if attention else []}


class AggregateTests(unittest.TestCase):
    def setUp(self):
        self.checks = (("docker", "/x", 1), ("rspamd", "/y", 1), ("unbound", "/z", 1))

    def test_attention_with_all_checks_and_sanitized_summaries(self):
        results = [(2, docker(True)), (2, rspamd(True)), (2, unbound(True))]
        with mock.patch.object(review, "CHECKS", self.checks), \
                mock.patch.object(review, "trusted"), \
                mock.patch.object(review, "run_bounded", side_effect=results) as run:
            report = review.review()
        self.assertEqual(run.call_count, 3)
        self.assertTrue(report["attention"])
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["checks"]["docker"]["findings"]["patch_candidates"][0]["candidate"]["tag"], "7.4.12-alpine")
        self.assertEqual(report["checks"]["unbound"]["findings"]["version_range_advisories"], ["CVE-2026-81642"])
        self.assertNotIn("DO-NOT-ECHO", json.dumps(report))

    def test_failure_does_not_skip_later_checks_or_hide_attention(self):
        with mock.patch.object(review, "CHECKS", self.checks), \
                mock.patch.object(review, "trusted"), \
                mock.patch.object(review, "run_bounded", side_effect=[review.CheckError("SECRET"),
                    (2, rspamd(True)), (1, unbound(True, ["SECRET"]))]) as run:
            report = review.review()
        self.assertEqual(run.call_count, 3)
        self.assertTrue(report["attention"])
        self.assertEqual(len(report["errors"]), 2)
        self.assertEqual(report["checks"]["unbound"]["error_count"], 1)
        self.assertNotIn("SECRET", json.dumps(report))
        with mock.patch.object(review, "review", return_value=report), mock.patch("builtins.print"):
            self.assertEqual(review.main(), 1)

    def test_clean_and_attention_status(self):
        for attention, expected in ((False, 0), (True, 2)):
            with mock.patch.object(review, "review", return_value={"errors": [], "attention": attention}), \
                    mock.patch("builtins.print"):
                self.assertEqual(review.main(), expected)

    def test_inconsistent_exit_or_malformed_schema_fails_closed(self):
        for rc, data in ((0, docker(True)), (2, docker(False)), (1, docker(False)),
                         (0, {"attention": 0, "errors": []}),
                         (0, {"attention": False, "errors": ["x"]})):
            with self.subTest(rc=rc, data=data), self.assertRaises(review.CheckError):
                review.summarize("docker", rc, data)

    def test_untrusted_values_are_not_emitted(self):
        bad = docker(True)
        bad["patch_candidates"][0]["candidate"]["tag"] = "7.4.12-alpine\nsecret"
        with self.assertRaises(review.CheckError):
            review.summarize("docker", 2, bad)
        bad = unbound(True)
        bad["version_range_advisories"][0]["cve"] = "CVE-2026-81642 secret"
        with self.assertRaises(review.CheckError):
            review.summarize("unbound", 2, bad)

    def test_false_clean_or_incomplete_findings_fail_closed(self):
        first = docker(False)
        first["packages"][0]["update_available"] = True
        second = docker(False)
        second["images"] = second["images"][:2]
        third = rspamd(False)
        third["newer_release_lines"] = [{"version": "4.2.3", "security_language_present": True}]
        fourth = unbound(False)
        fourth["version_range_advisories"] = [{"cve": "CVE-2026-81642"}]
        for name, data in (("docker", first), ("docker", second), ("rspamd", third), ("unbound", fourth)):
            with self.subTest(name=name, data=data), self.assertRaises(review.CheckError):
                review.summarize(name, 0, data)

    def test_missing_array_cannot_be_mistaken_for_clean(self):
        for name, data, key in (("docker", docker(False), "packages"),
                                ("rspamd", rspamd(False), "newer_release_lines"),
                                ("unbound", unbound(False), "version_range_advisories")):
            data.pop(key)
            with self.subTest(name=name), self.assertRaises(review.CheckError):
                review.summarize(name, 0, data)

    def test_newer_version_cannot_be_mistaken_for_clean(self):
        data = unbound(False)
        data["upstream_current"] = "1.26.2"
        with self.assertRaises(review.CheckError):
            review.summarize("unbound", 0, data)

    def test_duplicate_package_and_release_fail_closed(self):
        data = docker(False)
        data["packages"].append(dict(data["packages"][0]))
        with self.assertRaises(review.CheckError):
            review.summarize("docker", 0, data)
        data = rspamd(True)
        data["newer_release_lines"].append(dict(data["newer_release_lines"][0]))
        with self.assertRaises(review.CheckError):
            review.summarize("rspamd", 2, data)

    def test_invalid_timestamp_is_not_echoed(self):
        data = docker(False)
        data["checked_at_utc"] = "invalid-secret-value"
        with self.assertRaises(review.CheckError) as exc:
            review.summarize("docker", 0, data)
        self.assertNotIn("secret", str(exc.exception))


class BoundedProcessTests(unittest.TestCase):
    def script(self, code):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
        self.addCleanup(lambda: Path(f.name).unlink(missing_ok=True))
        f.write(code)
        f.close()
        return f.name

    def test_real_process_and_error_suppression(self):
        p = self.script("import json,sys\nprint('sensitive stderr', file=sys.stderr)\n"
                        "print(json.dumps({'attention': True, 'errors': []}))\nsys.exit(2)\n")
        code, data = review.run_bounded(p, 5)
        self.assertEqual(code, 2)
        self.assertEqual(data, {"attention": True, "errors": []})

    def test_timeout_kills_process_group(self):
        with tempfile.TemporaryDirectory() as d:
            pid_file = Path(d) / "child_pid"
            p = self.script("import subprocess,sys,time\n"
                            "c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])\n"
                            f"open({str(pid_file)!r},'w').write(str(c.pid))\n"
                            "time.sleep(30)\n")
            with self.assertRaisesRegex(review.CheckError, "timed out"):
                review.run_bounded(p, .5)
            self.assertTrue(pid_file.exists())
            pid = int(pid_file.read_text())
            # A killed child can transiently be a zombie; /proc state is not
            # portable to macOS. A live signalable process must exit promptly.
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(.05)
            else:
                # On Linux the child may be reparented and remain as a zombie.
                stat_path = Path(f"/proc/{pid}/stat")
                self.assertTrue(stat_path.exists() and stat_path.read_text().split()[2] == "Z")

    def test_output_overflow_is_bounded(self):
        p = self.script("import sys,time\nsys.stdout.write('x'*100000)\nsys.stdout.flush()\ntime.sleep(30)\n")
        with mock.patch.object(review, "MAX_OUTPUT", 4096):
            with self.assertRaisesRegex(review.CheckError, "output exceeded"):
                review.run_bounded(p, 5)

    def test_invalid_json_is_not_echoed(self):
        p = self.script("print('DO-NOT-ECHO-SECRET')\n")
        with self.assertRaisesRegex(review.CheckError, "invalid JSON") as exc:
            review.run_bounded(p, 5)
        self.assertNotIn("SECRET", str(exc.exception))


if __name__ == "__main__":
    unittest.main()
