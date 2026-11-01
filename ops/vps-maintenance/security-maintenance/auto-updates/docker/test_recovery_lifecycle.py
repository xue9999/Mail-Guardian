"""Recovery sequencing tests with fake service and package state only."""

from contextlib import ExitStack
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import pre_mutation_recovery as recovery


class RecoveryLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.events = []
        self.transaction = "20261031T120000Z-12345678"
        self.raw_marker = b"owned marker"
        self.marker = (self.raw_marker, (1, 2), self.transaction)
        self.record = {"transaction_id": self.transaction, "phase": "fenced",
                       "generation": 2, "plan_sha256": "a" * 64,
                       "plan": {"inventory": {"docker-ce": "1.0"},
                                "containers": {"redis": "fixture"}}}
        self.marker_mock = self.stack.enter_context(mock.patch.object(recovery, "_marker_optional", return_value=self.marker))
        self.stack.enter_context(mock.patch.object(recovery.journal, "_open_state_root",
                                                   side_effect=lambda *_: os.open(self.tmp.name, os.O_RDONLY)))
        self.unresolved = self.stack.enter_context(mock.patch.object(recovery, "_find_unresolved", return_value=self.record))
        self.stack.enter_context(mock.patch.object(recovery.os, "geteuid", return_value=0))
        self.updater_lock_path = Path(self.tmp.name) / "updater.lock"
        self.updater_fd = os.open(self.updater_lock_path, os.O_RDONLY | os.O_CREAT, 0o600)
        self.stack.enter_context(mock.patch.object(recovery.engine, "acquire_updater_lock", return_value=self.updater_fd))
        self.lock_path = Path(self.tmp.name) / "migration.lock"
        self.fence_fd = os.open(self.lock_path, os.O_RDONLY | os.O_CREAT, 0o600)
        self.stack.enter_context(mock.patch.object(recovery.engine, "acquire_fence", return_value=self.fence_fd))
        self.dpkg_locks = self.stack.enter_context(mock.patch.object(recovery, "_lock_dpkg"))
        self.state = self.stack.enter_context(mock.patch.object(recovery.engine, "unit_state", return_value="inactive"))
        self.stack.enter_context(mock.patch.object(recovery.engine, "run", return_value=subprocess.CompletedProcess([], 0, "", "")))
        self.inventory = self.stack.enter_context(mock.patch.object(recovery.engine, "installed_inventory", return_value={"docker-ce": "1.0"}))
        self.stack.enter_context(mock.patch.object(recovery.engine, "container_snapshot", return_value={"redis": "snapshot"}))
        self.stack.enter_context(mock.patch.object(recovery.journal, "container_evidence", return_value={"redis": "fixture"}))
        self.health = self.stack.enter_context(mock.patch.object(recovery.engine, "health"))
        self.read = self.stack.enter_context(mock.patch.object(recovery.journal, "read", return_value=self.record))
        self.advance = self.stack.enter_context(mock.patch.object(recovery.journal, "advance", side_effect=self.fake_advance))
        self.alias = self.stack.enter_context(mock.patch.object(recovery, "_remove_marker_alias", side_effect=self.fake_alias))
        self.clear = self.stack.enter_context(mock.patch.object(recovery.engine, "clear_own_marker", side_effect=self.fake_clear))

    def fake_advance(self, root, transaction, digest, phase, generation, next_phase):
        self.events.append(("journal", next_phase))
        return {**self.record, "phase": next_phase, "generation": generation + 1}

    def fake_clear(self, payload, *, expected_identity=None):
        self.events.append(("clear", payload, expected_identity))

    def fake_alias(self, identity):
        self.events.append(("alias", identity))

    def test_journal_intent_is_persisted_before_owned_marker_is_removed(self):
        self.assertEqual(recovery.recover_once(), "pre-mutation fence recovered")
        self.dpkg_locks.assert_called_once()
        self.health.assert_called_once()
        self.assertEqual(self.events, [("journal", "pre_mutation_clear_intent"),
                                       ("alias", (1, 2)),
                                       ("clear", self.raw_marker, (1, 2)),
                                       ("journal", "pre_mutation_recovered")])
        with self.assertRaises(OSError):
            os.fstat(self.fence_fd)
        with self.assertRaises(OSError):
            os.fstat(self.updater_fd)

    def test_lock_order_is_updater_then_guardian_then_dpkg(self):
        order = []
        def take_updater():
            order.append("updater")
            return self.updater_fd
        def take_guardian():
            order.append("guardian")
            return self.fence_fd
        def take_dpkg(stack):
            order.append("dpkg")
        recovery.engine.acquire_updater_lock.side_effect = take_updater
        recovery.engine.acquire_fence.side_effect = take_guardian
        self.dpkg_locks.side_effect = take_dpkg
        recovery.recover_once()
        self.assertEqual(order, ["updater", "guardian", "dpkg"])

    def test_contended_updater_lock_never_takes_guardian_fence(self):
        recovery.engine.acquire_updater_lock.side_effect = BlockingIOError("busy")
        with self.assertRaises(BlockingIOError):
            recovery.recover_once()
        recovery.engine.acquire_fence.assert_not_called()
        self.dpkg_locks.assert_not_called()
        self.clear.assert_not_called()
        # The mocked lock creator did not consume this temporary descriptor.
        os.close(self.updater_fd)
        os.close(self.fence_fd)

    def test_pending_or_later_mutation_never_removes_marker(self):
        for phase in ("mutation_pending", "verified", "unfence_intent", "completed", "recovery_required"):
            with self.subTest(phase=phase):
                self.record["phase"] = phase
                # One fresh file descriptor per attempt; recover_once closes it.
                if phase != "mutation_pending":
                    self.fence_fd = os.open(self.lock_path, os.O_RDONLY)
                    recovery.engine.acquire_fence.return_value = self.fence_fd
                    self.updater_fd = os.open(self.updater_lock_path, os.O_RDONLY)
                    recovery.engine.acquire_updater_lock.return_value = self.updater_fd
                with self.assertRaises(recovery.RecoveryError):
                    recovery.recover_once()
                self.clear.assert_not_called()
                self.advance.assert_not_called()

    def test_changed_marker_is_not_removed(self):
        self.marker_mock.side_effect = [self.marker, (b"different", (1, 3), self.transaction)]
        with self.assertRaisesRegex(recovery.RecoveryError, "marker changed"):
            recovery.recover_once()
        self.clear.assert_not_called()
        self.advance.assert_not_called()

    def test_prepared_without_marker_is_aborted_only_after_checks(self):
        self.record["phase"] = "prepared"
        self.record["generation"] = 0
        self.marker_mock.return_value = None
        self.assertEqual(recovery.recover_once(), "pre-mutation transaction safely aborted")
        self.health.assert_called_once()
        self.assertEqual(self.events, [("journal", "aborted")])
        self.clear.assert_not_called()

    def test_prepared_with_marker_is_never_cleared(self):
        self.record["phase"] = "prepared"
        with self.assertRaisesRegex(recovery.RecoveryError, "unexpectedly has a marker"):
            recovery.recover_once()
        self.clear.assert_not_called()
        self.advance.assert_not_called()
        os.close(self.fence_fd)  # Guard was not acquired on this error path.

    def test_absent_marker_can_finish_known_pre_mutation_transaction(self):
        self.marker_mock.return_value = None
        self.assertEqual(recovery.recover_once(), "pre-mutation fence recovered")
        self.assertEqual(self.events, [("journal", "pre_mutation_clear_intent"),
                                       ("journal", "pre_mutation_recovered")])
        self.clear.assert_not_called()

    def test_absent_marker_after_clear_intent_can_finish_recovery(self):
        self.record["phase"] = "pre_mutation_clear_intent"
        self.record["generation"] = 3
        self.marker_mock.return_value = None
        self.assertEqual(recovery.recover_once(), "pre-mutation fence recovered")
        self.assertEqual(self.events, [("journal", "pre_mutation_recovered")])
        self.clear.assert_not_called()

    def test_absent_marker_is_not_enough_after_mutation_may_have_started(self):
        self.record["phase"] = "mutation_pending"
        self.marker_mock.return_value = None
        with self.assertRaises(recovery.RecoveryError):
            recovery.recover_once()
        self.clear.assert_not_called()
        self.advance.assert_not_called()

    def test_foreign_marker_or_mismatched_transaction_never_clears(self):
        self.marker_mock.return_value = (b"other", (1, 5), "20261031T120001Z-12345678")
        with self.assertRaisesRegex(recovery.RecoveryError, "does not match"):
            recovery.recover_once()
        self.clear.assert_not_called()
        self.advance.assert_not_called()
        os.close(self.fence_fd)  # Guard was not acquired on this error path.

    def test_foreign_marker_is_rejected_before_guardian_lock(self):
        self.marker_mock.side_effect = recovery.RecoveryError("marker is not an owned updater fence")
        with self.assertRaisesRegex(recovery.RecoveryError, "not an owned updater fence"):
            recovery.recover_once()
        recovery.engine.acquire_fence.assert_not_called()
        self.clear.assert_not_called()
        self.advance.assert_not_called()
        os.close(self.fence_fd)  # Guard was not acquired on this error path.

    def test_multiple_or_missing_unfinished_transactions_never_clear(self):
        self.unresolved.side_effect = recovery.RecoveryError("expected exactly one unfinished update transaction")
        with self.assertRaisesRegex(recovery.RecoveryError, "exactly one"):
            recovery.recover_once()
        self.clear.assert_not_called()
        self.advance.assert_not_called()
        os.close(self.fence_fd)  # Guard was not acquired on this error path.

    def test_unfinished_transaction_changing_during_checks_never_clears(self):
        self.unresolved.side_effect = [self.record, {**self.record, "phase": "mutation_pending"}]
        with self.assertRaisesRegex(recovery.RecoveryError, "unfinished transaction changed"):
            recovery.recover_once()
        self.clear.assert_not_called()
        self.advance.assert_not_called()

    def test_changed_baseline_after_health_is_not_removed(self):
        self.inventory.side_effect = [{"docker-ce": "1.0"}, {"docker-ce": "2.0"}]
        with self.assertRaisesRegex(recovery.RecoveryError, "state changed"):
            recovery.recover_once()
        self.clear.assert_not_called()
        self.advance.assert_not_called()

    def test_failed_health_keeps_fence(self):
        self.health.side_effect = recovery.RecoveryError("health failed")
        with self.assertRaisesRegex(recovery.RecoveryError, "health failed"):
            recovery.recover_once()
        self.clear.assert_not_called()
        self.advance.assert_not_called()

    def test_unpersisted_clear_intent_never_removes_marker(self):
        self.advance.side_effect = recovery.RecoveryError("journal write failed")
        with self.assertRaisesRegex(recovery.RecoveryError, "journal write failed"):
            recovery.recover_once()
        self.clear.assert_not_called()

    def test_failed_marker_clear_never_records_recovered(self):
        self.clear.side_effect = recovery.RecoveryError("unlink failed")
        with self.assertRaisesRegex(recovery.RecoveryError, "unlink failed"):
            recovery.recover_once()
        self.assertEqual(self.events, [("journal", "pre_mutation_clear_intent"), ("alias", (1, 2))])

    def test_failed_completion_write_is_reported_after_marker_clear(self):
        def fail_last(root, transaction, digest, phase, generation, next_phase):
            if next_phase == "pre_mutation_recovered":
                raise recovery.RecoveryError("completion sync failed")
            return self.fake_advance(root, transaction, digest, phase, generation, next_phase)
        self.advance.side_effect = fail_last
        with self.assertRaisesRegex(recovery.RecoveryError, "completion sync failed"):
            recovery.recover_once()
        self.assertEqual(self.events, [("journal", "pre_mutation_clear_intent"),
                                       ("alias", (1, 2)),
                                       ("clear", self.raw_marker, (1, 2))])


class RealAdvisoryLockTests(unittest.TestCase):
    def test_both_dpkg_locks_remain_held_until_exit_stack_closes(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / "frontend", Path(directory) / "database"]
            for path in paths:
                path.touch(mode=0o600)
            original_fstat = os.fstat
            def pretend_root(fd):
                actual = original_fstat(fd)
                return SimpleNamespace(st_mode=actual.st_mode, st_uid=0, st_nlink=actual.st_nlink)
            child = ("import fcntl,os,sys\n"
                     "f=os.open(sys.argv[1],os.O_RDWR)\n"
                     "try:\n fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\n"
                     "except BlockingIOError:\n sys.exit(9)\n"
                     "else:\n sys.exit(0)\n")
            with ExitStack() as held, mock.patch.object(recovery, "DPKG_LOCKS", tuple(paths)):
                with mock.patch.object(recovery.os, "fstat", side_effect=pretend_root):
                    recovery._lock_dpkg(held)
                for path in paths:
                    result = subprocess.run([sys.executable, "-c", child, str(path)], timeout=5)
                    self.assertEqual(result.returncode, 9)
            for path in paths:
                result = subprocess.run([sys.executable, "-c", child, str(path)], timeout=5)
                self.assertEqual(result.returncode, 0)


class UnfinishedJournalScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state_patch = mock.patch.object(recovery.engine, "STATE", self.root)
        self.state_patch.start()
        self.addCleanup(self.state_patch.stop)
        original_lstat = Path.lstat
        def pretend_root(path):
            actual = original_lstat(path)
            return SimpleNamespace(st_mode=actual.st_mode, st_uid=0, st_nlink=actual.st_nlink)
        self.lstat_patch = mock.patch.object(Path, "lstat", autospec=True, side_effect=pretend_root)
        self.lstat_patch.start()
        self.addCleanup(self.lstat_patch.stop)

    def make_transaction(self, name, phase):
        (self.root / name).mkdir(mode=0o700)
        return {"transaction_id": name, "phase": phase}

    def test_one_unresolved_ignores_completed_and_fixed_state_files(self):
        active = self.make_transaction("20261031T120000Z-12345678", "fenced")
        done = self.make_transaction("20261031T120001Z-12345678", "completed")
        (self.root / ".updater.lock").touch(mode=0o600)
        (self.root / ".preflight").mkdir(mode=0o700)
        mapping = {r["transaction_id"]: r for r in (active, done)}
        with mock.patch.object(recovery.journal, "read", side_effect=lambda root, name: mapping[name]):
            self.assertEqual(recovery._find_unresolved(), active)

    def test_multiple_unresolved_fail_closed(self):
        first = self.make_transaction("20261031T120000Z-12345678", "fenced")
        second = self.make_transaction("20261031T120001Z-12345678", "mutation_pending")
        mapping = {r["transaction_id"]: r for r in (first, second)}
        with mock.patch.object(recovery.journal, "read", side_effect=lambda root, name: mapping[name]):
            with self.assertRaisesRegex(recovery.RecoveryError, "exactly one"):
                recovery._find_unresolved()

    def test_no_unresolved_fails_closed(self):
        done = self.make_transaction("20261031T120000Z-12345678", "completed")
        with mock.patch.object(recovery.journal, "read", return_value=done):
            with self.assertRaisesRegex(recovery.RecoveryError, "exactly one"):
                recovery._find_unresolved()

    def test_unknown_state_entry_is_not_ignored(self):
        self.make_transaction("20261031T120000Z-12345678", "fenced")
        (self.root / "unexpected-file").touch()
        with mock.patch.object(recovery.journal, "read", return_value={"phase": "fenced"}):
            with self.assertRaisesRegex(recovery.RecoveryError, "unknown update state"):
                recovery._find_unresolved()

    def test_unreadable_journal_is_not_assumed_safe(self):
        self.make_transaction("20261031T120000Z-12345678", "fenced")
        with mock.patch.object(recovery.journal, "read", side_effect=recovery.journal.JournalError("invalid")):
            with self.assertRaises(recovery.journal.JournalError):
                recovery._find_unresolved()


if __name__ == "__main__":
    unittest.main()
