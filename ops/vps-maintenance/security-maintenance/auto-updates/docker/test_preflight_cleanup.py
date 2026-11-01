"""Real temporary-file cleanup tests; never touches live VPS state."""

import fcntl
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import engine


class PreflightCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name).resolve() / "state"
        self.state.mkdir(mode=0o700)
        self.preflight = self.state / ".preflight"
        self.preflight.mkdir(mode=0o700)
        self.txn = "20261031T190000Z-abcdefgh"
        self.stage = self.preflight / self.txn
        self.stage.mkdir(mode=0o700)
        self.lock = self.state / ".updater.lock"
        self.fd = os.open(self.lock, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(os.close, self.fd)
        self.state_patch = mock.patch.object(engine, "STATE", self.state)
        self.state_patch.start()
        self.addCleanup(self.state_patch.stop)

    def cleanup_preflight(self):
        return engine.cleanup_preflight(self.preflight, self.fd, _test_expected_uid=os.getuid())

    def test_removes_own_stale_stages_without_touching_published_transactions(self):
        for name in ("old", "new"):
            directory = self.stage / name
            directory.mkdir(mode=0o700)
            (directory / "docker-ce_29.9.1_amd64.deb").write_bytes(b"synthetic package")
        (self.stage / "transaction.json").write_text("synthetic journal")
        (self.stage / ".journal.lock").touch(mode=0o600)
        (self.stage / (".journal-" + "a" * 32)).write_text("incomplete journal")
        partial = self.preflight / "20261031T190001Z-abcdefgh"
        partial.mkdir(mode=0o700)
        published = self.state / "20261031T190002Z-abcdefgh"
        published.mkdir(mode=0o700)
        (published / "must-remain").write_bytes(b"published transaction")
        self.cleanup_preflight()
        self.assertEqual(list(self.preflight.iterdir()), [])
        self.assertEqual((published / "must-remain").read_bytes(), b"published transaction")

    def test_rejects_unknown_transaction_directory_without_deleting_it(self):
        unknown = self.preflight / "unrecognized"
        unknown.mkdir(mode=0o700)
        with self.assertRaises((engine.UpdateError, OSError, ValueError)):
            self.cleanup_preflight()
        self.assertTrue(unknown.is_dir())

    def test_rejects_unknown_file_without_deleting_it(self):
        unexpected = self.stage / "do-not-remove.txt"
        unexpected.write_text("unrecognized content")
        with self.assertRaises((engine.UpdateError, OSError, ValueError)):
            self.cleanup_preflight()
        self.assertTrue(unexpected.is_file())

    def test_rejects_symlink_without_touching_target(self):
        outside = self.state / "external"
        outside.write_bytes(b"outside data")
        (self.stage / "transaction.json").symlink_to(outside)
        with self.assertRaises((engine.UpdateError, OSError, ValueError)):
            self.cleanup_preflight()
        self.assertEqual(outside.read_bytes(), b"outside data")

    def test_rejects_hardlink_without_touching_target(self):
        outside = self.state / "external"
        outside.write_bytes(b"outside data")
        old = self.stage / "old"
        old.mkdir(mode=0o700)
        os.link(outside, old / "docker-ce_29.9.1_amd64.deb")
        with self.assertRaises((engine.UpdateError, OSError, ValueError)):
            self.cleanup_preflight()
        self.assertEqual(outside.read_bytes(), b"outside data")
        self.assertTrue((old / "docker-ce_29.9.1_amd64.deb").exists())

    def test_rejects_group_or_other_writable_artifact(self):
        old = self.stage / "old"
        old.mkdir(mode=0o700)
        package = old / "docker-ce_29.9.1_amd64.deb"
        package.write_bytes(b"synthetic package")
        package.chmod(0o666)
        with self.assertRaises((engine.UpdateError, OSError, ValueError)):
            self.cleanup_preflight()
        self.assertTrue(package.exists())

    def test_rejects_cleanup_without_symlink_safe_rmtree(self):
        with mock.patch.object(shutil.rmtree, "avoids_symlink_attacks", False):
            with self.assertRaises((engine.UpdateError, OSError, ValueError)):
                self.cleanup_preflight()
        self.assertTrue(self.stage.is_dir())

    def test_rejects_wrong_owner_expectation(self):
        with self.assertRaises((engine.UpdateError, OSError, ValueError)):
            engine.cleanup_preflight(self.preflight, self.fd, _test_expected_uid=os.getuid() + 1)
        self.assertTrue(self.stage.is_dir())

    def test_rejects_unheld_or_unrelated_global_lock(self):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        with self.assertRaises((engine.UpdateError, OSError, ValueError)):
            self.cleanup_preflight()
        self.assertTrue(self.stage.is_dir())

    def test_rejects_a_held_lock_for_a_different_inode(self):
        unrelated = self.state / "unrelated.lock"
        fd = os.open(unrelated, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises((engine.UpdateError, OSError, ValueError)):
                engine.cleanup_preflight(self.preflight, fd, _test_expected_uid=os.getuid())
        finally:
            os.close(fd)
        self.assertTrue(self.stage.is_dir())

    def test_rejects_a_caller_supplied_directory_other_than_preflight(self):
        elsewhere = self.state / "not-preflight"
        elsewhere.mkdir(mode=0o700)
        published = elsewhere / self.txn
        published.mkdir(mode=0o700)
        old = published / "old"
        old.mkdir(mode=0o700)
        artifact = old / "docker-ce_29.9.1_amd64.deb"
        artifact.write_bytes(b"must survive")
        with self.assertRaises((engine.UpdateError, OSError, ValueError)):
            engine.cleanup_preflight(elsewhere, self.fd, _test_expected_uid=os.getuid())
        self.assertEqual(artifact.read_bytes(), b"must survive")


if __name__ == "__main__":
    unittest.main()
