"""Local-only watcher tests; no server, package, container or mailbox changes."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import update_watchdog as watchdog


TXN = "20261031T190000Z-abcdefgh"
OTHER = "20261031T190001Z-abcdefgh"
MARKER = (b"owned-marker", (1, 2), TXN)
STOPPED = {"load": "loaded", "active": "inactive", "result": "success", "exit": 0,
           "active_age_seconds": None}
ACTIVE = {"load": "loaded", "active": "active", "result": "success", "exit": 0,
          "active_age_seconds": 3.0}
MISSING = {"load": "not-found", "active": "inactive", "result": "unknown", "exit": None,
           "active_age_seconds": None}
TIMER = {"configured": True, "active": "active", "enabled": "enabled", "next_set": True,
         "last_age_seconds": 100.0}


def record(phase="fenced", transaction=TXN):
    # Journal binding itself is verified by journal.read before evaluate.
    return {"phase": phase, "transaction_id": transaction}


class EvaluationTests(unittest.TestCase):
    def test_missing_updater_is_actionable(self):
        self.assertEqual(watchdog.evaluate(MISSING, None, [])["code"], "updater_not_configured")
        self.assertEqual(watchdog.evaluate(MISSING, None, [])["level"], "attention")

    def test_updater_active_bounded_and_unknown_duration_not_clean(self):
        self.assertEqual(watchdog.evaluate(ACTIVE, None, [])["code"], "update_in_progress")
        for age, expected in ((None, "updater_active_time_unknown"),
                              (watchdog.MAX_ACTIVE_SECONDS + 1, "updater_active_too_long")):
            unit = dict(ACTIVE, active_age_seconds=age)
            self.assertEqual(watchdog.evaluate(unit, None, [])["code"], expected)

    def test_idle_requires_enabled_active_fresh_timer(self):
        self.assertEqual(watchdog.evaluate(STOPPED, None, [], timer=TIMER)["code"], "idle")
        cases = ((None, "updater_timer_not_configured"),
                 (dict(TIMER, enabled="disabled"), "updater_timer_not_active"),
                 (dict(TIMER, active="inactive"), "updater_timer_not_active"),
                 (dict(TIMER, next_set=False), "updater_timer_not_active"),
                 (dict(TIMER, last_age_seconds=None), "updater_timer_not_yet_triggered"),
                 (dict(TIMER, last_age_seconds=watchdog.MAX_TIMER_AGE_SECONDS + 1), "updater_timer_stale"))
        for timer, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(watchdog.evaluate(STOPPED, None, [], timer=timer)["code"], expected)

    def test_failed_and_deferred_results_are_actionable(self):
        failed = dict(STOPPED, active="failed", result="exit-code", exit=1)
        deferred = dict(STOPPED, exit=2)
        self.assertEqual(watchdog.evaluate(failed, None, [], timer=TIMER)["code"], "last_update_failed")
        self.assertEqual(watchdog.evaluate(deferred, None, [], timer=TIMER)["code"], "updates_deferred_for_review")

    def test_post_mutation_phases_never_call_recovery(self):
        for phase in ("mutation_pending", "verified", "unfence_intent", "recovery_required"):
            with self.subTest(phase=phase):
                recover = mock.Mock()
                result = watchdog.evaluate(STOPPED, MARKER, [record(phase)], timer=TIMER,
                                           allow_recovery=True, recover=recover)
                self.assertEqual(result["code"], "manual_post_mutation_recovery_required")
                recover.assert_not_called()

    def test_matching_pre_mutation_requires_explicit_recovery_opt_in(self):
        recover = mock.Mock()
        result = watchdog.evaluate(STOPPED, MARKER, [record()], timer=TIMER, recover=recover)
        self.assertEqual(result["code"], "pre_mutation_recovery_available")
        recover.assert_not_called()
        result = watchdog.evaluate(STOPPED, MARKER, [record()], timer=TIMER,
                                   allow_recovery=True, recover=recover)
        self.assertEqual(result["code"], "pre_mutation_recovered")
        recover.assert_called_once_with()

    def test_prepared_transaction_with_marker_cannot_recover(self):
        recover = mock.Mock()
        result = watchdog.evaluate(STOPPED, MARKER, [record("prepared")], timer=TIMER,
                                   allow_recovery=True, recover=recover)
        self.assertEqual(result["code"], "unexpected_marker_for_prepared_transaction")
        recover.assert_not_called()

    def test_missing_marker_pre_mutation_may_be_reconciled(self):
        for phase in ("prepared", "fence_creating", "fenced", "pre_mutation_clear_intent"):
            recover = mock.Mock()
            result = watchdog.evaluate(STOPPED, None, [record(phase)], timer=TIMER,
                                       allow_recovery=True, recover=recover)
            self.assertEqual(result["code"], "pre_mutation_recovered")
            recover.assert_called_once_with()

    def test_unknown_foreign_marker_and_multiple_records_never_recover(self):
        for marker, records in ((MARKER, []), (MARKER, [record(transaction=OTHER)]),
                                (MARKER, [record(), record(transaction=OTHER)]),
                                ((b"not-valid",), [record()])):
            recover = mock.Mock()
            result = watchdog.evaluate(STOPPED, marker, records, timer=TIMER,
                                       allow_recovery=True, recover=recover)
            self.assertEqual(result["level"], "attention")
            recover.assert_not_called()

    def test_recovery_failure_does_not_leak_exception_details(self):
        recover = mock.Mock(side_effect=RuntimeError("sensitive-private-text"))
        result = watchdog.evaluate(STOPPED, MARKER, [record()], timer=TIMER,
                                   allow_recovery=True, recover=recover)
        self.assertEqual(result["code"], "pre_mutation_recovery_deferred")
        self.assertNotIn("sensitive-private-text", json.dumps(result))

    def test_timer_query_failure_does_not_prevent_pre_mutation_recovery(self):
        timer_reader = mock.Mock(side_effect=RuntimeError("offline"))
        recover = mock.Mock()
        result = watchdog.check_once(status_reader=lambda: STOPPED, state_reader=lambda: (MARKER, [record()]),
                                     timer_reader=timer_reader, allow_recovery=True, recover=recover)
        self.assertEqual(result["code"], "pre_mutation_recovered")
        recover.assert_called_once_with()
        timer_reader.assert_not_called()

    def test_updater_started_during_snapshot_prevents_recovery(self):
        status_reader = mock.Mock(side_effect=[STOPPED, ACTIVE])
        recover = mock.Mock()
        result = watchdog.check_once(status_reader=status_reader, state_reader=lambda: (MARKER, [record()]),
                                     timer_reader=lambda: TIMER, allow_recovery=True, recover=recover)
        self.assertEqual(result["code"], "update_in_progress")
        recover.assert_not_called()

    def test_reader_failure_is_actionable_and_sanitized(self):
        def fail():
            raise RuntimeError("sensitive-private-text")
        result = watchdog.check_once(status_reader=lambda: STOPPED, state_reader=fail,
                                     timer_reader=lambda: TIMER)
        self.assertEqual(result["code"], "watchdog_state_unverifiable")
        self.assertNotIn("sensitive-private-text", json.dumps(result))

    def test_failed_service_is_reported_even_if_timer_query_would_fail(self):
        failed = dict(STOPPED, active="failed", result="exit-code", exit=1)
        timer_reader = mock.Mock(side_effect=RuntimeError("timer unavailable"))
        result = watchdog.check_once(status_reader=lambda: failed, state_reader=lambda: (None, []),
                                     timer_reader=timer_reader)
        self.assertEqual(result["code"], "last_update_failed")
        timer_reader.assert_not_called()


class SystemdTests(unittest.TestCase):
    def test_service_properties_and_monotonic_age(self):
        text = ("LoadState=loaded\nActiveState=active\nResult=success\n"
                "ExecMainStartTimestampMonotonic=95000000\nExecMainStatus=0\n")
        with mock.patch.object(watchdog.engine, "run", return_value=subprocess.CompletedProcess([], 0, text, "")), \
             mock.patch.object(watchdog.time, "monotonic", return_value=100):
            self.assertEqual(watchdog.unit_status()["active_age_seconds"], 5)

    def test_service_missing_or_malformed(self):
        for output, expected in (("LoadState=not-found\n", "not-found"),):
            with mock.patch.object(watchdog.engine, "run", return_value=subprocess.CompletedProcess([], 1, output, "")):
                self.assertEqual(watchdog.unit_status()["load"], expected)
        with mock.patch.object(watchdog.engine, "run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            with self.assertRaises(watchdog.WatchdogError):
                watchdog.unit_status()

    def test_timer_properties_parse_and_elapsed(self):
        output = ("LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n"
                  "LastTriggerUSec=Sat 2026-10-31 10:00:00 UTC\n"
                  "NextElapseUSecRealtime=Sun 2026-11-01 10:00:00 UTC\n")
        calls = [subprocess.CompletedProcess([], 0, output, ""),
                 subprocess.CompletedProcess([], 0, "1000\n", "")]
        with mock.patch.object(watchdog.engine, "run", side_effect=calls), \
             mock.patch.object(watchdog.time, "time", return_value=1060):
            self.assertEqual(watchdog.timer_status(), dict(TIMER, last_age_seconds=60.0))


class LocalStatusTests(unittest.TestCase):
    def test_fifo_marker_is_rejected_without_blocking(self):
        # O_NONBLOCK must prevent a FIFO without a writer from hanging the
        # privileged watcher before it can classify unsafe marker metadata. A
        # subprocess timeout prevents a regression from hanging the test suite.
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "migration-pending"
            os.mkfifo(fifo, 0o600)
            code = ("import pathlib,sys,update_watchdog as w; "
                    "w.engine.MARKER=pathlib.Path(sys.argv[1]); "
                    "\ntry: w.owned_marker()\n"
                    "except Exception: sys.exit(0)\n"
                    "sys.exit(1)\n")
            result = subprocess.run([sys.executable, "-c", code, str(fifo)],
                                    cwd=Path(__file__).parent, timeout=3, capture_output=True)
            self.assertEqual(result.returncode, 0)

    def test_verified_publication_alias_is_accepted_without_exposing_content(self):
        marker = (b"private-marker-bytes", (1, 2), TXN)
        class Stat:
            st_mode = 0o100600
            st_uid = 0
            st_nlink = 2
            st_dev = 1
            st_ino = 2
        with mock.patch.object(watchdog.recovery, "_marker_optional", return_value=marker), \
             mock.patch.object(watchdog.os, "lstat", return_value=Stat()):
            self.assertEqual(watchdog.owned_marker(), marker)

    def test_status_file_is_private_atomic_and_has_only_selected_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            with mock.patch.object(watchdog, "_open_status_root", return_value=root_fd), \
                 mock.patch.object(watchdog.syslog, "openlog"), \
                 mock.patch.object(watchdog.syslog, "syslog") as log, \
                 mock.patch.object(watchdog.syslog, "closelog"):
                watchdog.write_status({"code": "last_update_failed", "level": "attention"})
            status = Path(directory) / "status.json"
            self.assertEqual(status.stat().st_mode & 0o777, 0o600)
            self.assertEqual(set(json.loads(status.read_text())), {"schema", "checked_at_utc", "code", "level"})
            log.assert_called_once()
            self.assertEqual([x.name for x in Path(directory).iterdir()], ["status.json"])

    def test_code_and_transaction_are_strictly_bounded_ascii(self):
        for result in ({"code": "secret\nvalue", "level": "attention"},
                       {"code": "ą", "level": "attention"},
                       {"code": "valid", "level": "attention", "transaction_id": "../../unsafe"},
                       {"code": "valid", "level": "attention", "secret": "not permitted"}):
            with self.subTest(result=result), self.assertRaises(watchdog.WatchdogError):
                watchdog.write_status(result)

    def test_symlink_previous_status_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "status.json").symlink_to("/etc/passwd")
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(OSError):
                    watchdog._previous(fd)
            finally:
                os.close(fd)


class StateSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state_patch = mock.patch.object(watchdog.engine, "STATE", self.root)
        self.state_patch.start()
        self.addCleanup(self.state_patch.stop)
        self.marker_patch = mock.patch.object(watchdog, "owned_marker", return_value=None)
        self.marker_patch.start()
        self.addCleanup(self.marker_patch.stop)
        self.root_patch = mock.patch.object(
            watchdog.journal, "_open_state_root", side_effect=lambda *args: os.open(self.root, os.O_RDONLY | os.O_DIRECTORY))
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.original_lstat = Path.lstat

    def pretend_root(self, path):
        actual = self.original_lstat(path)
        return SimpleNamespace(st_mode=actual.st_mode, st_uid=0, st_nlink=actual.st_nlink)

    def test_private_retired_directory_is_ignored_but_active_journal_is_seen(self):
        (self.root / ".retired").mkdir(mode=0o700)
        (self.root / TXN).mkdir(mode=0o700)
        with mock.patch.object(Path, "lstat", autospec=True, side_effect=self.pretend_root), \
             mock.patch.object(watchdog.journal, "read", return_value=record("fenced")) as read:
            self.assertEqual(watchdog.state_snapshot(), (None, [record("fenced")]))
            read.assert_called_once_with(self.root, TXN)

    def test_retired_directory_must_be_real_root_owned_and_mode_0700(self):
        retired = self.root / ".retired"
        for kind in ("symlink", "mode", "owner"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    retired.symlink_to(self.root, target_is_directory=True)
                else:
                    retired.mkdir(mode=0o700)
                    if kind == "mode":
                        retired.chmod(0o755)
                def metadata(path):
                    actual = self.original_lstat(path)
                    return SimpleNamespace(st_mode=actual.st_mode,
                                           st_uid=1234 if kind == "owner" else 0,
                                           st_nlink=actual.st_nlink)
                try:
                    with mock.patch.object(Path, "lstat", autospec=True, side_effect=metadata):
                        with self.assertRaisesRegex(watchdog.WatchdogError, "unsafe private update directory"):
                            watchdog.state_snapshot()
                finally:
                    if retired.is_symlink():
                        retired.unlink()
                    else:
                        retired.rmdir()

    def test_fifo_previous_status_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "status.json"
            os.mkfifo(fifo, 0o600)
            code = ("import os,sys,update_watchdog as w; "
                    "fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY); "
                    "\ntry: w._previous(fd)\n"
                    "except Exception: sys.exit(0)\n"
                    "sys.exit(1)\n")
            result = subprocess.run([sys.executable, "-c", code, directory],
                                    cwd=Path(__file__).parent, timeout=3, capture_output=True)
            self.assertEqual(result.returncode, 0)


class CommandLineTests(unittest.TestCase):
    def test_check_does_not_request_recovery_and_recovery_flag_opts_in(self):
        for flag, expected in (("--check", False), ("--recover-pre-mutation", True)):
            with self.subTest(flag=flag), mock.patch.object(sys, "argv", ["watchdog", flag]), \
                 mock.patch.object(watchdog.os, "geteuid", return_value=0), \
                 mock.patch.object(watchdog, "check_once", return_value={"code": "idle", "level": "info"}) as check, \
                 mock.patch.object(watchdog, "write_status"), mock.patch("builtins.print"):
                self.assertEqual(watchdog.main(), 0)
                check.assert_called_once_with(allow_recovery=expected)

    def test_attention_exit_status_is_two(self):
        with mock.patch.object(sys, "argv", ["watchdog", "--check"]), \
             mock.patch.object(watchdog.os, "geteuid", return_value=0), \
             mock.patch.object(watchdog, "check_once", return_value={"code": "last_update_failed", "level": "attention"}), \
             mock.patch.object(watchdog, "write_status"), mock.patch("builtins.print"):
            self.assertEqual(watchdog.main(), 2)


if __name__ == "__main__":
    unittest.main()
