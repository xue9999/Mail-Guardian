"""Retention tests use real temporary journal files, never VPS data or packages."""

from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import engine
import transaction_journal as journal


class TerminalRetentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.marker = self.root / "migration-pending"
        self.owner = os.getuid()
        self.now = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
        self.state_patch = mock.patch.object(engine, "STATE", self.state)
        self.marker_patch = mock.patch.object(engine, "MARKER", self.marker)
        self.state_patch.start()
        self.marker_patch.start()
        self.addCleanup(self.state_patch.stop)
        self.addCleanup(self.marker_patch.stop)
        self.fd = os.open(self.state / ".updater.lock", os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(os.close, self.fd)

    def make_transaction(self, days_old, phase="completed", suffix="abcdefgh"):
        timestamp = (self.now - timedelta(days=days_old)).strftime("%Y%m%dT%H%M%SZ")
        transaction = timestamp + "-" + suffix
        directory = self.state / transaction
        directory.mkdir(mode=0o700)
        old_bytes, new_bytes = b"synthetic old deb", b"synthetic new deb"
        for label, data in (("old", old_bytes), ("new", new_bytes)):
            part = directory / label
            part.mkdir(mode=0o700)
            version = "29.9.1" if label == "old" else "29.9.2"
            (part / f"docker-ce_{version}_amd64.deb").write_bytes(data)
        digest = "a" * 64
        plan = {
            "packages": [{"name": "docker-ce", "installed": "5:29.9.1-1~ubuntu.26.04~resolute",
                          "target": "5:29.9.2-1~ubuntu.26.04~resolute",
                          "old_sha256": hashlib.sha256(old_bytes).hexdigest(),
                          "new_sha256": hashlib.sha256(new_bytes).hexdigest()}],
            "inventory": {"docker-ce": "5:29.9.1-1~ubuntu.26.04~resolute"},
            "containers": {name: {"image_id": "sha256:" + digest, "mounts_sha256": digest,
                                   "ports_sha256": digest} for name in ("redis", "rspamd", "unbound")},
        }
        state = journal.initialize(self.state, transaction, plan, _test_expected_uid=self.owner)
        chains = {
            "prepared": (),
            "aborted": ("aborted",),
            "fenced": ("fence_creating", "fenced"),
            "mutation_pending": ("fence_creating", "fenced", "mutation_pending"),
            "pre_mutation_recovered": ("fence_creating", "pre_mutation_clear_intent", "pre_mutation_recovered"),
            "completed": ("fence_creating", "fenced", "mutation_pending", "verified", "unfence_intent", "completed"),
        }
        for step in chains[phase]:
            state = journal.advance(self.state, transaction, state["plan_sha256"], state["phase"],
                                    state["generation"], step, _test_expected_uid=self.owner)
        terminal_time = self.now - timedelta(days=days_old)
        os.utime(directory / "transaction.json", (terminal_time.timestamp(), terminal_time.timestamp()))
        return directory

    def cleanup(self):
        return engine.cleanup_terminal_transactions(self.fd, now=self.now, _test_expected_uid=self.owner)

    def older_completed_candidates(self):
        newest = [self.make_transaction(n) for n in (1, 2, 3)]
        old = self.make_transaction(45)
        return newest, old

    def test_keeps_latest_three_completed_and_young_terminals(self):
        completed = [self.make_transaction(n) for n in (10, 31, 32, 33, 34)]
        aborted_old = self.make_transaction(45, "aborted")
        recovered_old = self.make_transaction(46, "pre_mutation_recovered")
        aborted_young = self.make_transaction(5, "aborted")
        self.cleanup()
        self.assertTrue(all(p.is_dir() for p in completed[:3]))
        self.assertFalse(any(p.exists() for p in completed[3:]))
        self.assertFalse(aborted_old.exists())
        self.assertFalse(recovered_old.exists())
        self.assertTrue(aborted_young.is_dir())

    def test_never_deletes_nonterminal_even_if_older_than_retention(self):
        active = [self.make_transaction(n, phase) for n, phase in
                  ((51, "prepared"), (52, "fenced"), (53, "mutation_pending"))]
        self.cleanup()
        self.assertTrue(all(p.is_dir() for p in active))

    def test_retention_age_uses_journal_mtime_not_transaction_start_time(self):
        delayed = self.make_transaction(80, "aborted")
        terminal_time = self.now - timedelta(days=2)
        os.utime(delayed / "transaction.json", (terminal_time.timestamp(), terminal_time.timestamp()))
        self.cleanup()
        self.assertTrue(delayed.is_dir())

    def test_recent_three_completed_are_ordered_by_journal_mtime(self):
        completed = [self.make_transaction(n) for n in (40, 41, 42, 43, 44)]
        terminal_time = self.now - timedelta(days=1)
        os.utime(completed[-1] / "transaction.json", (terminal_time.timestamp(), terminal_time.timestamp()))
        self.cleanup()
        self.assertTrue(completed[-1].is_dir())
        self.assertTrue(completed[0].is_dir())
        self.assertTrue(completed[1].is_dir())
        self.assertFalse(completed[2].exists())
        self.assertFalse(completed[3].exists())

    def test_marker_present_blocks_all_deletion(self):
        _, old = self.older_completed_candidates()
        self.marker.write_text("unresolved guardian fence")
        with self.assertRaises((engine.UpdateError, journal.JournalError, OSError, ValueError)):
            self.cleanup()
        self.assertTrue(old.is_dir())

    def test_corrupt_journal_blocks_deletion(self):
        _, old = self.older_completed_candidates()
        (old / "transaction.json").write_text("not a journal")
        with self.assertRaises((engine.UpdateError, journal.JournalError, OSError, ValueError)):
            self.cleanup()
        self.assertTrue(old.is_dir())

    def test_symlink_artifact_cannot_delete_foreign_data(self):
        _, old = self.older_completed_candidates()
        target = self.root / "foreign"
        target.write_bytes(b"must remain")
        package = old / "old" / "docker-ce_29.9.1_amd64.deb"
        package.unlink()
        package.symlink_to(target)
        with self.assertRaises((engine.UpdateError, journal.JournalError, OSError, ValueError)):
            self.cleanup()
        self.assertEqual(target.read_bytes(), b"must remain")
        self.assertTrue(old.is_dir())

    def test_hardlinked_artifact_cannot_delete_foreign_data(self):
        _, old = self.older_completed_candidates()
        target = self.root / "foreign"
        target.write_bytes(b"must remain")
        package = old / "old" / "docker-ce_29.9.1_amd64.deb"
        package.unlink()
        os.link(target, package)
        with self.assertRaises((engine.UpdateError, journal.JournalError, OSError, ValueError)):
            self.cleanup()
        self.assertEqual(target.read_bytes(), b"must remain")
        self.assertTrue(old.is_dir())

    def test_unrecognized_file_is_not_deleted(self):
        _, old = self.older_completed_candidates()
        extra = old / "foreign.txt"
        extra.write_bytes(b"must remain")
        with self.assertRaises((engine.UpdateError, journal.JournalError, OSError, ValueError)):
            self.cleanup()
        self.assertEqual(extra.read_bytes(), b"must remain")

    def test_unbound_package_named_file_is_not_deleted(self):
        _, old = self.older_completed_candidates()
        extra = old / "old" / "docker-ce_foreign_amd64.deb"
        extra.write_bytes(b"must remain; not bound by the journal plan")
        with self.assertRaises((engine.UpdateError, journal.JournalError, OSError, ValueError)):
            self.cleanup()
        self.assertEqual(extra.read_bytes(), b"must remain; not bound by the journal plan")

    def test_package_content_not_matching_journal_is_not_deleted(self):
        _, old = self.older_completed_candidates()
        artifact = old / "old" / "docker-ce_29.9.1_amd64.deb"
        artifact.write_bytes(b"tampered package bytes")
        with self.assertRaises((engine.UpdateError, journal.JournalError, OSError, ValueError)):
            self.cleanup()
        self.assertTrue(artifact.exists())
        self.assertEqual(artifact.read_bytes(), b"tampered package bytes")

    def test_retired_transaction_with_unbound_package_is_not_deleted(self):
        _, old = self.older_completed_candidates()
        retired = self.state / ".retired"
        retired.mkdir(mode=0o700)
        destination = retired / old.name
        os.rename(old, destination)
        extra = destination / "old" / "docker-ce_foreign_amd64.deb"
        extra.write_bytes(b"not bound by retained journal")
        with self.assertRaises((engine.UpdateError, journal.JournalError, OSError, ValueError)):
            self.cleanup()
        self.assertEqual(extra.read_bytes(), b"not bound by retained journal")

    def test_no_cleanup_without_held_global_lock(self):
        _, old = self.older_completed_candidates()
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        with self.assertRaises((engine.UpdateError, journal.JournalError, OSError, ValueError)):
            self.cleanup()
        self.assertTrue(old.is_dir())

    def test_no_cleanup_without_symlink_safe_rmtree(self):
        _, old = self.older_completed_candidates()
        with mock.patch.object(shutil.rmtree, "avoids_symlink_attacks", False):
            with self.assertRaises((engine.UpdateError, journal.JournalError, OSError, ValueError)):
                self.cleanup()
        self.assertTrue(old.is_dir())

    def test_failed_partial_removal_leaves_an_incomplete_transaction_for_review(self):
        _, old = self.older_completed_candidates()
        retired = self.state / ".retired" / old.name
        actual_unlink = os.unlink
        removed_packages = []
        def partial_unlink(path, *args, **kwargs):
            if str(path).endswith(".deb"):
                if removed_packages:
                    raise OSError("injected interrupted artifact removal")
                removed_packages.append(str(path))
            return actual_unlink(path, *args, **kwargs)
        with mock.patch.object(engine.os, "unlink", side_effect=partial_unlink):
            with self.assertRaises(OSError):
                self.cleanup()
        self.assertFalse(old.exists())
        self.assertTrue(retired.is_dir())
        self.assertEqual(len(removed_packages), 1)
        self.assertTrue((retired / "transaction.json").is_file())
        # A retry can verify the retained plan, then remove remaining artifacts.
        # No active transaction is left without its journal.
        self.cleanup()
        self.assertFalse(retired.exists())

    def test_journalless_nonempty_retired_directory_is_not_deleted(self):
        retired = self.state / ".retired"
        retired.mkdir(mode=0o700)
        incomplete = retired / "20260831T120000Z-abcdefgh"
        incomplete.mkdir(mode=0o700)
        old = incomplete / "old"
        old.mkdir(mode=0o700)
        artifact = old / "docker-ce_foreign_amd64.deb"
        artifact.write_bytes(b"must survive without a journal")
        with self.assertRaises((engine.UpdateError, journal.JournalError, OSError, ValueError)):
            self.cleanup()
        self.assertEqual(artifact.read_bytes(), b"must survive without a journal")

    def test_empty_journalless_retired_directory_can_be_cleaned(self):
        retired = self.state / ".retired"
        retired.mkdir(mode=0o700)
        incomplete = retired / "20260831T120000Z-abcdefgh"
        incomplete.mkdir(mode=0o700)
        self.cleanup()
        self.assertFalse(incomplete.exists())

    def test_directory_sync_failure_during_retirement_is_reported(self):
        keep, old = self.older_completed_candidates()
        with mock.patch.object(engine, "sync_directory", side_effect=OSError("injected directory sync failure")):
            with self.assertRaises(OSError):
                self.cleanup()
        self.assertTrue(old.exists() or (self.state / ".retired" / old.name).exists())
        self.assertTrue(all(path.is_dir() for path in keep))

    def test_fence_appearing_during_scan_prevents_deletion(self):
        _, old = self.older_completed_candidates()
        actual = os.path.lexists
        calls = 0
        def fence_appears(path):
            nonlocal calls
            if Path(path) == self.marker:
                calls += 1
                if calls == 2:
                    self.marker.write_text("new fence")
            return actual(path)
        with mock.patch.object(engine.os.path, "lexists", side_effect=fence_appears):
            with self.assertRaises(engine.UpdateError):
                self.cleanup()
        self.assertTrue(old.is_dir())
        self.assertTrue(self.marker.exists())

    def test_future_and_exact_thirty_day_transactions_are_preserved(self):
        recent = self.make_transaction(-1, "aborted")
        boundary = self.make_transaction(30, "aborted")
        self.cleanup()
        self.assertTrue(recent.is_dir())
        self.assertTrue(boundary.is_dir())

    def test_wrong_owner_and_naive_clock_are_rejected(self):
        _, old = self.older_completed_candidates()
        with self.assertRaises((engine.UpdateError, journal.JournalError, OSError, ValueError)):
            engine.cleanup_terminal_transactions(self.fd, now=self.now, _test_expected_uid=self.owner + 1)
        with self.assertRaises((engine.UpdateError, journal.JournalError, OSError, ValueError)):
            engine.cleanup_terminal_transactions(self.fd, now=self.now.replace(tzinfo=None),
                                                 _test_expected_uid=self.owner)
        self.assertTrue(old.is_dir())


if __name__ == "__main__":
    unittest.main()
