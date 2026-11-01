"""Real temporary-file and process tests; never touches VPS services or data."""

import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from types import SimpleNamespace

import engine


class MarkerFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.instance = Path(self.tmp.name)
        self.marker = self.instance / "migration-pending"
        self.instance_patch = mock.patch.object(engine, "INSTANCE", self.instance)
        self.marker_patch = mock.patch.object(engine, "MARKER", self.marker)
        self.instance_patch.start()
        self.marker_patch.start()
        self.addCleanup(self.instance_patch.stop)
        self.addCleanup(self.marker_patch.stop)

    def test_existing_marker_is_not_overwritten(self):
        self.marker.write_bytes(b"another transaction")
        with self.assertRaises(FileExistsError):
            engine.create_marker("test-transaction")
        self.assertEqual(self.marker.read_bytes(), b"another transaction")

    def test_marker_creation_file_sync_failure_removes_own_marker_before_mutation(self):
        with mock.patch.object(engine.os, "fsync", side_effect=OSError("injected fsync failure")):
            with self.assertRaises(OSError):
                engine.create_marker("test-transaction")
        self.assertFalse(self.marker.exists())

    def test_marker_identity_read_failure_does_not_leave_new_empty_fence(self):
        with mock.patch.object(engine.os, "fstat", side_effect=OSError("injected fstat failure")):
            with self.assertRaises(OSError):
                engine.create_marker("test-transaction")
        self.assertFalse(self.marker.exists())

    def test_marker_creation_directory_sync_failure_removes_own_marker_before_mutation(self):
        calls = 0
        real_fsync = os.fsync
        def fail_directory_once(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected directory sync failure")
            return real_fsync(fd)
        with mock.patch.object(engine.os, "fsync", side_effect=fail_directory_once):
            with self.assertRaises(OSError):
                engine.create_marker("test-transaction")
        self.assertFalse(self.marker.exists())

    def test_creation_cleanup_does_not_remove_replaced_marker(self):
        calls = 0
        real_fsync = os.fsync
        def replace_then_fail(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.marker.unlink()
                self.marker.write_bytes(b"another transaction")
                raise OSError("injected sync failure after replacement")
            return real_fsync(fd)
        with mock.patch.object(engine.os, "fsync", side_effect=replace_then_fail):
            with self.assertRaises(OSError):
                engine.create_marker("test-transaction")
        self.assertEqual(self.marker.read_bytes(), b"another transaction")

    def test_tampered_marker_is_never_removed(self):
        original = engine.create_marker("test-transaction")
        self.marker.write_bytes(b"replacement marker")
        with self.assertRaises(engine.UpdateError):
            engine.clear_own_marker(original, _test_expected_uid=os.getuid())
        self.assertEqual(self.marker.read_bytes(), b"replacement marker")

    def test_replacement_marker_with_same_bytes_is_never_removed_when_inode_known(self):
        payload = engine.create_marker("test-transaction")
        original = self.marker.stat()
        os.replace(self.marker, self.instance / "original-marker")
        self.marker.write_bytes(payload)
        self.marker.chmod(0o600)
        with self.assertRaises(engine.UpdateError):
            engine.clear_own_marker(payload, expected_identity=(original.st_dev, original.st_ino),
                                    _test_expected_uid=os.getuid())
        self.assertEqual(self.marker.read_bytes(), payload)

    def test_unlink_followed_by_directory_sync_failure_restores_fence(self):
        # Clearing the fence must not be treated as durable if the directory
        # could not be synced; restore the transaction marker if possible.
        payload = engine.create_marker("test-transaction")
        with mock.patch.object(engine.os, "fsync", side_effect=OSError("injected directory sync failure")):
            with self.assertRaises((OSError, engine.UpdateError)):
                engine.clear_own_marker(payload, _test_expected_uid=os.getuid())
        self.assertEqual(self.marker.read_bytes(), payload)

    def test_clear_sync_failure_does_not_overwrite_replacement_marker(self):
        payload = engine.create_marker("test-transaction")
        def replace_then_fail(fd):
            self.marker.write_bytes(b"another transaction")
            raise OSError("injected directory sync failure")
        with mock.patch.object(engine.os, "fsync", side_effect=replace_then_fail):
            with self.assertRaises((OSError, engine.UpdateError)):
                engine.clear_own_marker(payload, _test_expected_uid=os.getuid())
        self.assertEqual(self.marker.read_bytes(), b"another transaction")


class InterruptedMutationTests(unittest.TestCase):
    def test_kill_during_mutation_retains_real_marker_and_releases_real_lock(self):
        self._exercise_interruption("mutation")

    def test_kill_during_preflight_does_not_block_next_update(self):
        self._exercise_interruption("preflight")

    def _exercise_interruption(self, stop_at):
        # The child uses real flock and marker file operations in a private temp
        # directory, but mocks every external command, data source and service.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child_code = r'''
import fcntl, hashlib, json, os, pathlib, shutil, stat, subprocess, sys, time
from types import SimpleNamespace
import engine, transaction_journal as journal
root = pathlib.Path(sys.argv[1]).resolve(); stop_at = sys.argv[2]; owner = os.stat(root).st_uid
instance = root / "instance"; instance.mkdir()
engine.INSTANCE = instance
engine.MARKER = instance / "migration-pending"
engine.LOCK = instance / "migration.lock"
engine.STATE = root / "state"
engine.LOCK.write_bytes(b"")
engine.os.geteuid = lambda: 0
original_lstat = os.lstat
def fake_lstat(path):
    r = original_lstat(path)
    if pathlib.Path(path) in (engine.STATE, engine.STATE / ".preflight"):
        return SimpleNamespace(st_mode=r.st_mode, st_uid=0)
    return r
engine.os.lstat = fake_lstat
engine.unit_active = lambda name, *args: name in engine.TIMERS
engine.unit_busy = lambda name: False
engine.require_recent_backup = lambda: None
engine.container_snapshot = lambda *args: {"redis": "fixture"}
engine.health = lambda *args: None
baseline = {"docker-ce": "5:29.9.1-1~ubuntu.26.04~resolute"}
targets = {"docker-ce": "5:29.9.2-1~ubuntu.26.04~resolute"}
engine.candidates = lambda: (baseline, targets, {})
engine.simulation = lambda *args: None
engine.installed_inventory = lambda: baseline
def fake_packages(path, versions, selected):
    if stop_at == "preflight":
        (root / "preflight-started").write_text("ready")
        while True: time.sleep(1)
    result = {}
    for name in selected:
        p = path / (name + ".deb"); b = versions[name].encode(); p.write_bytes(b)
        result[name] = (str(p), hashlib.sha256(b).hexdigest())
    return result
engine.save_packages = fake_packages
engine.shutil.disk_usage = lambda path: shutil._ntuple_diskusage(10**10, 0, 10**10)
def acquire():
    fd = os.open(engine.LOCK, os.O_RDONLY)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd
engine.acquire_fence = acquire
def acquire_updater_lock():
    fd = os.open(root / "updater.lock", os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd
engine.acquire_updater_lock = acquire_updater_lock
def acquire_frontend_lock():
    fd = os.open(root / "frontend.lock", os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd
engine.acquire_frontend_lock = acquire_frontend_lock
engine.assert_frontend_lock_held = lambda fd: None
engine.assert_no_unresolved_journals = lambda: None
engine.cleanup_preflight = lambda *args: None
engine.cleanup_terminal_transactions = lambda *args: None
def initialize_journal(directory, baseline, targets, old_packages, new_packages, inventory, containers):
    name = "docker-ce"; digest = "a" * 64
    plan = {"packages": [{"name": name, "installed": baseline[name], "target": targets[name],
                           "old_sha256": old_packages[name][1], "new_sha256": new_packages[name][1]}],
            "inventory": inventory,
            "containers": {x: {"image_id": "sha256:" + digest, "mounts_sha256": digest,
                                "ports_sha256": digest} for x in ("redis", "rspamd", "unbound")}}
    return journal.initialize(directory.parent, directory.name, plan, _test_expected_uid=owner)
def advance_journal(record, phase):
    return journal.advance(engine.STATE, record["transaction_id"], record["plan_sha256"],
                           record["phase"], record["generation"], phase, _test_expected_uid=owner)
engine.initialize_journal = initialize_journal
engine.advance_journal = advance_journal
original_marker_identity = engine.marker_identity
engine.marker_identity = lambda payload: original_marker_identity(payload, _test_expected_uid=owner)
def fake_run(args, **kwargs):
    if args[:2] == ["dpkg", "--refuse-downgrade"]:
        assert kwargs.get("frontend_locked") is True
        (root / "mutation-started").write_text("ready")
        while True: time.sleep(1)
    return subprocess.CompletedProcess(args, 0, "", "")
engine.run = fake_run
engine.apply(baseline, targets)
'''
            child = subprocess.Popen([sys.executable, "-c", child_code, str(root), stop_at],
                                     cwd=Path(__file__).parent, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 15
                started = root / (stop_at + "-started")
                while not started.exists():
                    if child.poll() is not None:
                        self.fail("isolated child failed before mutation: " + child.stderr.read()[-2000:])
                    if time.monotonic() >= deadline:
                        self.fail("isolated child did not enter mutation")
                    time.sleep(0.02)
                marker = root / "instance" / "migration-pending"
                lock = root / "instance" / "migration.lock"
                if stop_at == "mutation":
                    self.assertTrue(marker.is_file())
                    records = list((root / "state").glob("*/transaction.json"))
                    self.assertEqual(len(records), 1)
                    # Real atomic journal write/fsync happened before fake dpkg.
                    self.assertEqual(json.loads(records[0].read_text())["phase"], "mutation_pending")
                    with lock.open("rb") as stream:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with (root / "frontend.lock").open("r+b") as stream:
                        with self.assertRaises((BlockingIOError, OSError)):
                            fcntl.lockf(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with (root / "updater.lock").open("rb") as stream:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                child.kill()
                child.wait(timeout=5)
                with (root / "updater.lock").open("rb") as stream:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(stream, fcntl.LOCK_UN)
                if stop_at == "mutation":
                    self.assertTrue(marker.is_file())
                    self.assertIs(json.loads(marker.read_text())["worker_authorized"], False)
                    with lock.open("rb") as stream:
                        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(stream, fcntl.LOCK_UN)
                    with (root / "frontend.lock").open("r+b") as stream:
                        fcntl.lockf(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.lockf(stream, fcntl.LOCK_UN)
                else:
                    self.assertFalse(marker.exists())
                    state = root.resolve() / "state"
                    self.assertEqual({p.name for p in state.iterdir()}, {".preflight"})
                    actual_lstat = Path.lstat
                    def fake_lstat(path, *args, **kwargs):
                        info = actual_lstat(path, *args, **kwargs)
                        if path == state / ".preflight":
                            from types import SimpleNamespace
                            return SimpleNamespace(st_mode=info.st_mode, st_uid=0,
                                                   st_nlink=info.st_nlink, st_dev=info.st_dev,
                                                   st_ino=info.st_ino)
                        return info
                    with mock.patch.object(engine, "STATE", state), mock.patch.object(Path, "lstat", fake_lstat):
                        engine.assert_no_unresolved_journals()
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                if child.stderr:
                    child.stderr.close()


class LockReplacementTests(unittest.TestCase):
    def test_replacement_during_updater_flock_cannot_split_lock(self):
        self._test_replacement("updater")

    def test_replacement_during_guardian_flock_cannot_split_lock(self):
        self._test_replacement("guardian")

    def _test_replacement(self, kind):
        # Simulate an administrator replacing the lock name between open and
        # flock. Both locks must reject an fd that no longer names the inode.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / (".updater.lock" if kind == "updater" else "migration.lock")
            lock.touch(mode=0o600 if kind == "updater" else 0o640)
            lock.chmod(0o600 if kind == "updater" else 0o640)
            actual_fstat, actual_lstat, actual_flock = os.fstat, os.lstat, fcntl.flock
            def root_owned(info):
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=info.st_gid,
                                       st_nlink=info.st_nlink, st_dev=info.st_dev, st_ino=info.st_ino)
            def fake_fstat(fd):
                return root_owned(actual_fstat(fd))
            def fake_lstat(path, *args, **kwargs):
                info = actual_lstat(path, *args, **kwargs)
                return root_owned(info) if Path(path) == lock else info
            def replace_then_lock(fd, operation):
                os.replace(lock, root / "old-lock")
                lock.touch(mode=0o600 if kind == "updater" else 0o640)
                lock.chmod(0o600 if kind == "updater" else 0o640)
                return actual_flock(fd, operation)
            returned_fd = None
            with mock.patch.object(engine, "STATE", root), mock.patch.object(engine, "LOCK", lock), \
                    mock.patch.object(engine.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=os.getgid())), \
                    mock.patch.object(engine.os, "fstat", side_effect=fake_fstat), \
                    mock.patch.object(engine.os, "lstat", side_effect=fake_lstat), \
                    mock.patch.object(engine.fcntl, "flock", side_effect=replace_then_lock):
                try:
                    with self.assertRaises(engine.UpdateError):
                        returned_fd = (engine.acquire_updater_lock() if kind == "updater" else engine.acquire_fence())
                finally:
                    if returned_fd is not None:
                        os.close(returned_fd)
            with (root / "old-lock").open("rb") as stream:
                actual_flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                actual_flock(stream, fcntl.LOCK_UN)


if __name__ == "__main__":
    unittest.main()
