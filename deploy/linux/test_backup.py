#!/usr/bin/env python3
"""Private synthetic backup fixtures; never access Docker or real state."""

import contextlib
import hashlib
import importlib.util
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("guardian_backup", Path(__file__).with_name("backup.py"))
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="guardian-backup-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def copy(self, source, destination):
        fd = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            backup.copy_file_at(fd, source.name, destination, [0, 0])
        finally:
            os.close(fd)

    def test_symlink_and_hardlink_are_rejected_without_copy(self):
        source = self.root / "source"
        source.write_bytes(b"retained")
        alias = self.root / "alias"
        alias.symlink_to(source)
        with self.assertRaises(OSError):
            self.copy(alias, self.root / "copied")
        alias.unlink()
        os.link(source, alias)
        with self.assertRaises(backup.BackupError):
            self.copy(alias, self.root / "copied")
        self.assertFalse((self.root / "copied").exists())
        self.assertEqual(source.read_bytes(), b"retained")

    def test_nested_symlink_is_rejected(self):
        source = self.root / "tree"
        source.mkdir()
        (source / "outside").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            backup.copy_tree(source, self.root / "copied", [0, 0])

    def test_byte_and_file_budgets_fail_before_opening_output(self):
        source = self.root / "source"
        source.write_bytes(b"too many bytes")
        with patch.object(backup, "MAX_TOTAL", 3):
            with self.assertRaises(backup.BackupError):
                self.copy(source, self.root / "copy")
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(backup.BackupError):
                backup.copy_file_at(fd, "source", self.root / "copy", [0, 100000])
        finally:
            os.close(fd)
        self.assertFalse((self.root / "copy").exists())

    def test_snapshot_includes_committed_wal_and_preserves_original_bytes(self):
        source = self.root / "source"
        stage = self.root / "stage"
        source.mkdir()
        stage.mkdir(mode=0o700)
        database = source / "guardian.db"
        with contextlib.closing(sqlite3.connect(database)) as live:
            live.execute("PRAGMA journal_mode=WAL")
            live.execute("PRAGMA wal_autocheckpoint=0")
            live.execute("CREATE TABLE evidence(value TEXT)")
            live.execute("INSERT INTO evidence VALUES ('committed only in WAL')")
            live.commit()
            wal = source / "guardian.db-wal"
            old_db = hashlib.sha256(database.read_bytes()).hexdigest()
            old_wal = hashlib.sha256(wal.read_bytes()).hexdigest()
            fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
            try:
                backup.snapshot_database(fd, stage, stage / "guardian.db", [0, 0])
            finally:
                os.close(fd)
            self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), old_db)
            self.assertEqual(hashlib.sha256(wal.read_bytes()).hexdigest(), old_wal)
        with contextlib.closing(sqlite3.connect(stage / "guardian.db")) as restored:
            self.assertEqual(restored.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
            self.assertEqual(restored.execute("SELECT value FROM evidence").fetchall(),
                             [("committed only in WAL",)])
        self.assertFalse((stage / "guardian.db-wal").exists())
        self.assertEqual((stage / "guardian.db").stat().st_mode & 0o777, 0o600)

    def test_scanner_resumes_when_capture_fails_and_no_backup_is_sealed(self):
        config = self.root / "configuration"
        instance = config / "pilot"
        instance.mkdir(parents=True)
        (instance / "backup-recipient").write_text("age1" + "q" * 58 + "\n")
        calls = []

        class Dispatcher:
            def dispatch(self, operation):
                calls.append(operation)

            def compose(self, *args, **kwargs):
                calls.append(args)

            def ping(self):
                calls.append("ping")

        class Maintenance:
            def trusted_path(self, path, **kwargs):
                return Path(path)

            def Dispatcher(self, instance):
                return Dispatcher()

            def run(self, *args, **kwargs):
                raise AssertionError("must not seal failed capture")

        @contextlib.contextmanager
        def lock(*args):
            yield

        with patch.object(backup, "BASE", config), patch.object(backup, "BACKUPS", self.root / "backups"), \
                patch.object(backup, "exclusive_locks", lock), \
                patch.object(backup, "capture", side_effect=backup.BackupError("fixture capture failed")):
            with self.assertRaises(backup.BackupError):
                backup.backup("pilot", Maintenance())
        self.assertIn(("stop", "--timeout", "30", "rspamd"), calls)
        self.assertIn(("up", "--detach", "--wait", "rspamd"), calls)
        self.assertIn("ping", calls)
        self.assertEqual(list((self.root / "backups" / "pilot").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
