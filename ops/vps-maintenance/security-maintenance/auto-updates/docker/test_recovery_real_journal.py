"""Isolated journal/fence integration: no VPS, real packages, or mailbox access."""

from contextlib import ExitStack
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import engine
import pre_mutation_recovery as recovery
import transaction_journal as journal


class RealJournalRecoveryTests(unittest.TestCase):
    def setUp(self):
        # The journal deliberately rejects world-writable ancestors such as /tmp.
        # Use a private pre-existing user directory, not a production VPS path.
        parent = Path.home() / ".codex" / "backups" / "vps-1"
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="recovery-test-", dir=parent)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.instance = self.root / "instance"
        self.state.mkdir(mode=0o700)
        self.instance.mkdir(mode=0o700)
        self.marker = self.instance / "migration-pending"
        self.guardian_lock = self.instance / "migration.lock"
        self.guardian_lock.touch(mode=0o640)
        self.guardian_lock.chmod(0o640)
        self.updater_lock = self.state / ".updater.lock"
        self.updater_lock.touch(mode=0o600)
        self.dpkg_locks = (self.root / "lock-frontend", self.root / "lock-database")
        for item in self.dpkg_locks:
            item.touch(mode=0o600)
        self.transaction = "20261031T120000Z-12345678"
        (self.state / self.transaction).mkdir(mode=0o700)
        self.uid = os.getuid()
        self.inventory = {"docker-ce": "5:29.9.1-1~ubuntu.26.04~resolute"}
        self.snapshot = {
            service: ["sha256:" + digit * 64, "[]", "{}"]
            for service, digit in (("redis", "1"), ("rspamd", "2"), ("unbound", "3"))
        }
        self.plan = {"packages": [{"name": "docker-ce", "installed": self.inventory["docker-ce"],
                                   "target": "5:29.9.2-1~ubuntu.26.04~resolute",
                                   "old_sha256": "a" * 64, "new_sha256": "b" * 64}],
                     "inventory": self.inventory,
                     "containers": journal.container_evidence(self.snapshot)}
        self.original_read = journal.read
        self.original_advance = journal.advance
        self.original_open_root = journal._open_state_root
        self.original_fstat = os.fstat
        self.original_lstat = os.lstat
        self.original_path_lstat = Path.lstat
        self.original_clear = engine.clear_own_marker
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(engine, "STATE", self.state))
        self.stack.enter_context(mock.patch.object(engine, "INSTANCE", self.instance))
        self.stack.enter_context(mock.patch.object(engine, "LOCK", self.guardian_lock))
        self.stack.enter_context(mock.patch.object(engine, "MARKER", self.marker))
        self.stack.enter_context(mock.patch.object(recovery, "DPKG_LOCKS", self.dpkg_locks))
        self.stack.enter_context(mock.patch.object(engine.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=os.getgid())))
        self.stack.enter_context(mock.patch.object(recovery.os, "geteuid", return_value=0))
        self.stack.enter_context(mock.patch.object(engine, "unit_state", return_value="inactive"))
        self.stack.enter_context(mock.patch.object(engine, "run", return_value=subprocess.CompletedProcess([], 0, "", "")))
        self.stack.enter_context(mock.patch.object(engine, "installed_inventory", return_value=self.inventory))
        self.stack.enter_context(mock.patch.object(engine, "container_snapshot", return_value=self.snapshot))
        self.stack.enter_context(mock.patch.object(engine, "health"))

    @staticmethod
    def fake_root(info):
        return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=info.st_gid,
                               st_nlink=info.st_nlink, st_dev=info.st_dev, st_ino=info.st_ino)

    def make_fenced_record(self, phase):
        record = journal.initialize(self.state, self.transaction, self.plan, _test_expected_uid=self.uid)
        record = journal.advance(self.state, self.transaction, record["plan_sha256"], "prepared", 0,
                                 "fence_creating", _test_expected_uid=self.uid)
        payload = engine.create_marker(self.transaction)
        record = journal.advance(self.state, self.transaction, record["plan_sha256"], "fence_creating", 1,
                                 "fenced", _test_expected_uid=self.uid)
        if phase == "mutation_pending":
            record = journal.advance(self.state, self.transaction, record["plan_sha256"], "fenced", 2,
                                     "mutation_pending", _test_expected_uid=self.uid)
        return record, payload

    def make_publication_window_record(self):
        record = journal.initialize(self.state, self.transaction, self.plan, _test_expected_uid=self.uid)
        record = journal.advance(self.state, self.transaction, record["plan_sha256"], "prepared", 0,
                                 "fence_creating", _test_expected_uid=self.uid)
        payload = engine.create_marker(self.transaction)
        return record, payload

    def patched_real_io(self):
        # Simulate root ownership only for this private test's lock/marker
        # inodes and STATE entries. Journal files retain the real test UID.
        special = [item for item in [self.guardian_lock, self.updater_lock, self.marker, *self.dpkg_locks]
                   if item.exists()]
        # Pin the ownership-model inodes. Otherwise ext4 can reuse a removed
        # marker's inode for a newly written journal, and the fixture would
        # falsely turn that ordinary test-UID journal into a root-owned file.
        held = [os.open(p, os.O_RDONLY | os.O_NOFOLLOW) for p in special]
        for fd in held:
            self.stack.callback(os.close, fd)
        inodes = {(self.original_fstat(fd).st_dev, self.original_fstat(fd).st_ino) for fd in held}
        def fake_fstat(fd):
            info = self.original_fstat(fd)
            return self.fake_root(info) if (info.st_dev, info.st_ino) in inodes else info
        def fake_lstat(path, *args, **kwargs):
            info = self.original_lstat(path, *args, **kwargs)
            try:
                item = Path(path)
            except TypeError:
                return info
            if item in special or item.parent == self.state or item.parent == self.instance:
                return self.fake_root(info)
            return info
        def fake_path_lstat(path):
            info = self.original_path_lstat(path)
            return self.fake_root(info) if path.parent in (self.state, self.instance) else info
        def read_as_owner(root, transaction):
            return self.original_read(root, transaction, _test_expected_uid=self.uid)
        def advance_as_owner(root, transaction, digest, phase, generation, next_phase):
            return self.original_advance(root, transaction, digest, phase, generation, next_phase,
                                         _test_expected_uid=self.uid)
        def open_as_owner(root, expected_uid):
            return self.original_open_root(root, self.uid if expected_uid == 0 else expected_uid)
        self.stack.enter_context(mock.patch.object(os, "fstat", side_effect=fake_fstat))
        self.stack.enter_context(mock.patch.object(os, "lstat", side_effect=fake_lstat))
        self.stack.enter_context(mock.patch.object(Path, "lstat", autospec=True, side_effect=fake_path_lstat))
        self.stack.enter_context(mock.patch.object(journal, "read", side_effect=read_as_owner))
        self.stack.enter_context(mock.patch.object(journal, "advance", side_effect=advance_as_owner))
        self.stack.enter_context(mock.patch.object(journal, "_open_state_root", side_effect=open_as_owner))

    def test_real_journal_intent_is_durable_before_real_owned_marker_removal(self):
        self.make_fenced_record("fenced")
        self.patched_real_io()
        seen = []
        def verify_intent_then_clear(payload, *, expected_identity=None):
            record = self.original_read(self.state, self.transaction, _test_expected_uid=self.uid)
            seen.append(record["phase"])
            self.assertEqual(record["phase"], "pre_mutation_clear_intent")
            self.assertTrue(self.marker.is_file())
            return self.original_clear(payload, expected_identity=expected_identity)
        with mock.patch.object(engine, "clear_own_marker", side_effect=verify_intent_then_clear):
            self.assertEqual(recovery.recover_once(), "pre-mutation fence recovered")
        self.assertEqual(seen, ["pre_mutation_clear_intent"])
        self.assertFalse(self.marker.exists())
        final = self.original_read(self.state, self.transaction, _test_expected_uid=self.uid)
        self.assertEqual(final["phase"], "pre_mutation_recovered")
        self.assertEqual(final["generation"], 4)

    def test_real_mutation_pending_journal_never_removes_real_marker(self):
        record, payload = self.make_fenced_record("mutation_pending")
        self.patched_real_io()
        with self.assertRaisesRegex(recovery.RecoveryError, "may have reached package mutation"):
            recovery.recover_once()
        self.assertEqual(self.marker.read_bytes(), payload)
        final = self.original_read(self.state, self.transaction, _test_expected_uid=self.uid)
        self.assertEqual(final, record)

    def test_real_clear_intent_without_marker_reconciles_after_interruption(self):
        record, _ = self.make_fenced_record("fenced")
        journal.advance(self.state, self.transaction, record["plan_sha256"], "fenced", 2,
                        "pre_mutation_clear_intent", _test_expected_uid=self.uid)
        # Simulate interruption after unlink and before journal completion.
        self.marker.unlink()
        self.patched_real_io()
        self.assertEqual(recovery.recover_once(), "pre-mutation fence recovered")
        self.assertFalse(self.marker.exists())
        final = self.original_read(self.state, self.transaction, _test_expected_uid=self.uid)
        self.assertEqual(final["phase"], "pre_mutation_recovered")

    def test_real_prepared_journal_without_marker_can_be_aborted(self):
        journal.initialize(self.state, self.transaction, self.plan, _test_expected_uid=self.uid)
        self.patched_real_io()
        self.assertEqual(recovery.recover_once(), "pre-mutation transaction safely aborted")
        self.assertFalse(self.marker.exists())
        final = self.original_read(self.state, self.transaction, _test_expected_uid=self.uid)
        self.assertEqual(final["phase"], "aborted")

    def test_real_post_mutation_journal_without_marker_is_not_reconciled(self):
        record, _ = self.make_fenced_record("mutation_pending")
        self.marker.unlink()
        self.patched_real_io()
        with self.assertRaisesRegex(recovery.RecoveryError, "may have reached package mutation"):
            recovery.recover_once()
        final = self.original_read(self.state, self.transaction, _test_expected_uid=self.uid)
        self.assertEqual(final, record)

    def test_interrupted_hardlink_publication_recovers_only_own_alias_after_intent(self):
        self.make_publication_window_record()
        alias = self.instance / ".vps-docker-marker-abc_0123"
        unrelated = self.instance / ".vps-docker-marker-zzzzzzzz"
        os.link(self.marker, alias)
        unrelated.write_text("unrelated")
        unrelated.chmod(0o600)
        self.assertEqual(self.marker.stat().st_nlink, 2)
        self.patched_real_io()
        original_remove = recovery._remove_marker_alias
        phases = []
        def verify_intent_then_remove(identity):
            record = self.original_read(self.state, self.transaction, _test_expected_uid=self.uid)
            phases.append(record["phase"])
            self.assertEqual(record["phase"], "pre_mutation_clear_intent")
            self.assertTrue(alias.exists())
            self.assertEqual(self.marker.stat().st_nlink, 2)
            original_remove(identity)
            self.assertFalse(alias.exists())
            self.assertEqual(self.marker.stat().st_nlink, 1)
        with mock.patch.object(recovery, "_remove_marker_alias", side_effect=verify_intent_then_remove):
            self.assertEqual(recovery.recover_once(), "pre-mutation fence recovered")
        self.assertEqual(phases, ["pre_mutation_clear_intent"])
        self.assertFalse(self.marker.exists())
        self.assertEqual(unrelated.read_text(), "unrelated")
        final = self.original_read(self.state, self.transaction, _test_expected_uid=self.uid)
        self.assertEqual(final["phase"], "pre_mutation_recovered")

    def test_sigkill_in_real_hardlink_window_is_recovered_after_durable_intent(self):
        record = journal.initialize(self.state, self.transaction, self.plan, _test_expected_uid=self.uid)
        journal.advance(self.state, self.transaction, record["plan_sha256"], "prepared", 0,
                        "fence_creating", _test_expected_uid=self.uid)
        signal_file = self.root / "hardlink-published"
        code = r'''
import os,sys,time
from pathlib import Path
import engine
engine.INSTANCE=Path(sys.argv[1]);engine.MARKER=engine.INSTANCE/"migration-pending"
original_link=os.link
def publish_then_wait(*args, **kwargs):
    original_link(*args, **kwargs)
    Path(sys.argv[2]).write_text("ready")
    while True: time.sleep(1)
engine.os.link=publish_then_wait
engine.create_marker(sys.argv[3])
'''
        child = subprocess.Popen([sys.executable, "-c", code, str(self.instance), str(signal_file),
                                  self.transaction], cwd=Path(__file__).parent,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while not signal_file.exists():
                if child.poll() is not None:
                    self.fail("marker child exited early: " + child.stderr.read()[-1500:])
                if time.monotonic() >= deadline:
                    self.fail("marker child did not reach hardlink window")
                time.sleep(0.02)
            child.kill()
            child.wait(timeout=5)
            aliases = list(self.instance.glob(".vps-docker-marker-*"))
            self.assertEqual(len(aliases), 1)
            self.assertEqual(self.marker.stat().st_nlink, 2)
            self.assertEqual(self.marker.stat().st_ino, aliases[0].stat().st_ino)
            self.patched_real_io()
            original_remove = recovery._remove_marker_alias
            observed = []
            def assert_intent_then_remove(identity):
                current = self.original_read(self.state, self.transaction, _test_expected_uid=self.uid)
                observed.append(current["phase"])
                self.assertEqual(current["phase"], "pre_mutation_clear_intent")
                return original_remove(identity)
            with mock.patch.object(recovery, "_remove_marker_alias", side_effect=assert_intent_then_remove):
                self.assertEqual(recovery.recover_once(), "pre-mutation fence recovered")
            self.assertEqual(observed, ["pre_mutation_clear_intent"])
            self.assertFalse(self.marker.exists())
            self.assertFalse(aliases[0].exists())
            final = self.original_read(self.state, self.transaction, _test_expected_uid=self.uid)
            self.assertEqual(final["phase"], "pre_mutation_recovered")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            if child.stderr:
                child.stderr.close()

    def test_marker_with_missing_in_directory_alias_is_not_removed(self):
        record, payload = self.make_publication_window_record()
        outside_alias = self.root / "outside-alias"
        os.link(self.marker, outside_alias)
        self.patched_real_io()
        with self.assertRaisesRegex(recovery.RecoveryError, "alias is missing or ambiguous"):
            recovery.recover_once()
        self.assertEqual(self.marker.read_bytes(), payload)
        self.assertTrue(outside_alias.exists())
        self.assertEqual(self.original_read(self.state, self.transaction, _test_expected_uid=self.uid), record)

    def test_marker_with_multiple_hardlinks_is_not_removed(self):
        record, payload = self.make_publication_window_record()
        first = self.instance / ".vps-docker-marker-abc_0123"
        second = self.instance / ".vps-docker-marker-def_4567"
        os.link(self.marker, first)
        os.link(self.marker, second)
        self.patched_real_io()
        with self.assertRaisesRegex(recovery.RecoveryError, "unsafe migration marker"):
            recovery.recover_once()
        self.assertEqual(self.marker.read_bytes(), payload)
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())
        self.assertEqual(self.original_read(self.state, self.transaction, _test_expected_uid=self.uid), record)

    def test_marker_with_foreign_named_alias_is_not_removed(self):
        record, payload = self.make_publication_window_record()
        foreign = self.instance / ".not-the-updater-marker"
        os.link(self.marker, foreign)
        self.patched_real_io()
        with self.assertRaisesRegex(recovery.RecoveryError, "alias is missing or ambiguous"):
            recovery.recover_once()
        self.assertEqual(self.marker.read_bytes(), payload)
        self.assertTrue(foreign.exists())
        self.assertEqual(self.original_read(self.state, self.transaction, _test_expected_uid=self.uid), record)

    def test_matching_alias_with_untrusted_owner_is_not_removed(self):
        record, payload = self.make_publication_window_record()
        alias = self.instance / ".vps-docker-marker-abc_0123"
        os.link(self.marker, alias)
        self.patched_real_io()
        def untrusted_alias(path):
            info = self.original_path_lstat(path)
            if path == alias:
                return SimpleNamespace(st_mode=info.st_mode, st_uid=12345, st_gid=info.st_gid,
                                       st_nlink=info.st_nlink, st_dev=info.st_dev, st_ino=info.st_ino)
            return self.fake_root(info) if path.parent in (self.state, self.instance) else info
        with mock.patch.object(Path, "lstat", new=untrusted_alias):
            with self.assertRaisesRegex(recovery.RecoveryError, "unsafe marker alias"):
                recovery.recover_once()
        self.assertEqual(self.marker.read_bytes(), payload)
        self.assertTrue(alias.exists())
        self.assertEqual(self.original_read(self.state, self.transaction, _test_expected_uid=self.uid), record)

    def test_symlink_that_looks_like_alias_is_never_followed(self):
        record, payload = self.make_publication_window_record()
        outside_alias = self.root / "outside-alias"
        os.link(self.marker, outside_alias)
        symlink = self.instance / ".vps-docker-marker-abc_0123"
        symlink.symlink_to(self.marker)
        self.patched_real_io()
        with self.assertRaisesRegex(recovery.RecoveryError, "alias is missing or ambiguous"):
            recovery.recover_once()
        self.assertEqual(self.marker.read_bytes(), payload)
        self.assertTrue(symlink.is_symlink())
        self.assertTrue(outside_alias.exists())
        self.assertEqual(self.original_read(self.state, self.transaction, _test_expected_uid=self.uid), record)

    def test_hardlink_alias_is_not_removed_after_mutation_intent(self):
        record, payload = self.make_fenced_record("mutation_pending")
        alias = self.instance / ".vps-docker-marker-abc_0123"
        os.link(self.marker, alias)
        self.patched_real_io()
        with self.assertRaisesRegex(recovery.RecoveryError, "may have reached package mutation"):
            recovery.recover_once()
        self.assertEqual(self.marker.read_bytes(), payload)
        self.assertTrue(alias.exists())
        self.assertEqual(self.marker.stat().st_nlink, 2)
        self.assertEqual(self.original_read(self.state, self.transaction, _test_expected_uid=self.uid), record)


class FifoMarkerTests(unittest.TestCase):
    def test_fifo_marker_is_rejected_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "migration-pending"
            os.mkfifo(path, 0o600)
            code = r'''
import sys
from pathlib import Path
import engine, pre_mutation_recovery as recovery
engine.MARKER = Path(sys.argv[1])
for check in (recovery._marker, lambda: engine.marker_identity(b"x")):
    try:
        check()
    except (engine.UpdateError, recovery.RecoveryError):
        continue
    raise SystemExit("FIFO was incorrectly accepted")
'''
            result = subprocess.run([sys.executable, "-c", code, str(path)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=3, text=True, cwd=Path(__file__).parent)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
