"""No-op update safety tests; mock external commands and never contact VPS-1."""

from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import engine


class NoopApplyTests(unittest.TestCase):
    def run_apply(self, *, safety_error=None, skipped=None):
        baseline = {"docker-ce": "5:29.9.2-1~ubuntu.26.04~resolute"}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", ["engine", "--apply"]))
            run = stack.enter_context(mock.patch.object(
                engine, "run", return_value=subprocess.CompletedProcess([], 0, "", "")))
            stack.enter_context(mock.patch.object(engine, "candidates", return_value=(baseline, {}, skipped or {})))
            simulation = stack.enter_context(mock.patch.object(engine, "simulation"))
            apply = stack.enter_context(mock.patch.object(engine, "apply"))
            check = stack.enter_context(mock.patch.object(
                engine, "assert_noop_safe", create=True, side_effect=safety_error))
            output = stack.enter_context(mock.patch("builtins.print"))
            status = engine.main()
            report = json.loads(output.call_args.args[0])
            run.assert_called_once()
            simulation.assert_called_once_with({}, baseline)
            apply.assert_not_called()
            check.assert_called_once()
            return status, report

    def test_preexisting_guardian_fence_cannot_report_clean(self):
        status, report = self.run_apply(safety_error=engine.UpdateError("Guardian fence remains"))
        self.assertEqual(status, 1)
        self.assertIn("Guardian fence remains", report["error"])

    def test_unresolved_prior_journal_cannot_report_clean(self):
        status, report = self.run_apply(safety_error=engine.UpdateError("previous update needs reconciliation"))
        self.assertEqual(status, 1)
        self.assertIn("previous update needs reconciliation", report["error"])

    def test_valid_noop_returns_clean_without_applying(self):
        status, report = self.run_apply()
        self.assertEqual(status, 0)
        self.assertEqual(report["mode"], "apply")
        self.assertFalse(report["application_attempted"])
        self.assertEqual(report["patch_candidates"], {})

    def test_noop_with_deferred_candidate_still_checks_safety(self):
        skipped = {"docker-ce": {"installed": "old", "candidate": "new"}}
        status, report = self.run_apply(skipped=skipped)
        self.assertEqual(status, 2)
        self.assertFalse(report["application_attempted"])
        self.assertEqual(report["deferred_candidates"], skipped)


class NoopSafetyFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.marker = self.root / "migration-pending"
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(engine, "STATE", self.state))
        self.stack.enter_context(mock.patch.object(engine, "MARKER", self.marker))

    def with_state_and_lock(self):
        self.state.mkdir(mode=0o700)
        fd = os.open(self.root / "fake-lock", os.O_CREAT | os.O_RDONLY, 0o600)
        self.fd = fd
        self.stack.enter_context(mock.patch.object(engine, "acquire_updater_lock", return_value=fd))
        self.stack.enter_context(mock.patch.object(engine, "cleanup_terminal_transactions", create=True))
        actual = os.lstat
        def root_owned(path, *args, **kwargs):
            info = actual(path, *args, **kwargs)
            if Path(path) == self.state:
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0)
            return info
        self.stack.enter_context(mock.patch.object(engine.os, "lstat", side_effect=root_owned))

    def test_no_state_and_no_marker_is_a_clean_noop(self):
        engine.assert_noop_safe()
        self.assertFalse(self.state.exists())

    def test_marker_with_no_state_is_not_a_clean_noop(self):
        self.marker.write_text("existing fence")
        with self.assertRaises(engine.UpdateError):
            engine.assert_noop_safe()
        self.assertTrue(self.marker.exists())
        self.assertFalse(self.state.exists())

    def test_unresolved_journal_propagates_and_releases_global_lock(self):
        self.with_state_and_lock()
        self.stack.enter_context(mock.patch.object(
            engine, "assert_no_unresolved_journals", side_effect=engine.UpdateError("unresolved")))
        with self.assertRaisesRegex(engine.UpdateError, "unresolved"):
            engine.assert_noop_safe()
        self.assertFalse(self.marker.exists())
        with self.assertRaises(OSError) as error:
            os.fstat(self.fd)
        self.assertEqual(error.exception.errno, errno.EBADF)

    def test_marker_appearing_during_journal_scan_cannot_report_clean(self):
        self.with_state_and_lock()
        self.stack.enter_context(mock.patch.object(
            engine, "assert_no_unresolved_journals", side_effect=lambda: self.marker.write_text("new fence")))
        with self.assertRaises(engine.UpdateError):
            engine.assert_noop_safe()
        self.assertTrue(self.marker.exists())

    def test_marker_appearing_during_preflight_cleanup_cannot_report_clean(self):
        self.with_state_and_lock()
        (self.state / ".preflight").mkdir(mode=0o700)
        self.stack.enter_context(mock.patch.object(engine, "assert_no_unresolved_journals"))
        self.stack.enter_context(mock.patch.object(
            engine, "cleanup_preflight", side_effect=lambda *args: self.marker.write_text("new fence")))
        with self.assertRaises(engine.UpdateError):
            engine.assert_noop_safe()
        self.assertTrue(self.marker.exists())

    def test_symlinked_state_directory_is_rejected(self):
        target = self.root / "target"
        target.mkdir(mode=0o700)
        self.state.symlink_to(target, target_is_directory=True)
        with self.assertRaises(engine.UpdateError):
            engine.assert_noop_safe()


if __name__ == "__main__":
    unittest.main()
