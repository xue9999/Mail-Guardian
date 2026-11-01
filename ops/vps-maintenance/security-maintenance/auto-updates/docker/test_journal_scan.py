"""Test prior-transaction scan with real directories and no host changes."""

from contextlib import ExitStack
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import engine
import transaction_journal


class JournalScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name).resolve() / "state"
        self.state.mkdir(mode=0o700)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(engine, "STATE", self.state))
        self.entries = {}
        self.read = self.stack.enter_context(mock.patch.object(
            transaction_journal, "read", side_effect=self.read_fixture))
        actual_lstat = Path.lstat
        def fake_lstat(path, *args, **kwargs):
            result = actual_lstat(path, *args, **kwargs)
            try:
                candidate = Path(path)
                if candidate == self.state or candidate.parent == self.state:
                    return SimpleNamespace(st_mode=result.st_mode, st_uid=0,
                                           st_gid=result.st_gid, st_nlink=result.st_nlink,
                                           st_dev=result.st_dev, st_ino=result.st_ino)
            except (TypeError, ValueError):
                pass
            return result
        self.stack.enter_context(mock.patch.object(Path, "lstat", fake_lstat))

    def read_fixture(self, root, transaction_id, *args, **kwargs):
        self.assertEqual(Path(root), self.state)
        value = self.entries[transaction_id]
        if isinstance(value, BaseException):
            raise value
        return {"transaction_id": transaction_id, "phase": value}

    def transaction(self, name, phase):
        (self.state / name).mkdir(mode=0o700)
        self.entries[name] = phase

    def test_empty_state_is_safe(self):
        engine.assert_no_unresolved_journals()

    def test_private_preflight_directory_does_not_block_later_runs(self):
        preflight = self.state / ".preflight"
        preflight.mkdir(mode=0o700)
        (preflight / "20261031T190000Z-abcdefgh").mkdir(mode=0o700)
        engine.assert_no_unresolved_journals()
        self.read.assert_not_called()

    def test_private_retired_directory_does_not_block_later_runs(self):
        retired = self.state / ".retired"
        retired.mkdir(mode=0o700)
        (retired / "20261031T190000Z-abcdefgh").mkdir(mode=0o700)
        engine.assert_no_unresolved_journals()
        self.read.assert_not_called()

    def test_unsafe_retired_entry_blocks(self):
        retired = self.state / ".retired"
        retired.symlink_to(self.state / "absent")
        with self.assertRaises((engine.UpdateError, transaction_journal.JournalError, OSError)):
            engine.assert_no_unresolved_journals()

    def test_private_regular_updater_lock_does_not_block_scan(self):
        lock = self.state / ".updater.lock"
        lock.touch(mode=0o600)
        engine.assert_no_unresolved_journals()
        self.read.assert_not_called()

    def test_unsafe_updater_lock_blocks(self):
        lock = self.state / ".updater.lock"
        lock.symlink_to(self.state / "absent")
        with self.assertRaises((engine.UpdateError, transaction_journal.JournalError, OSError)):
            engine.assert_no_unresolved_journals()

    def test_writable_or_hardlinked_updater_lock_blocks(self):
        lock = self.state / ".updater.lock"
        lock.touch(mode=0o600)
        lock.chmod(0o644)
        with self.assertRaises((engine.UpdateError, transaction_journal.JournalError, OSError)):
            engine.assert_no_unresolved_journals()
        lock.chmod(0o600)
        os.link(lock, Path(self.temp.name) / "extra-link")
        with self.assertRaises((engine.UpdateError, transaction_journal.JournalError, OSError)):
            engine.assert_no_unresolved_journals()

    def test_unsafe_preflight_entry_blocks(self):
        preflight = self.state / ".preflight"
        preflight.symlink_to(self.state / "absent")
        with self.assertRaises((engine.UpdateError, transaction_journal.JournalError, OSError)):
            engine.assert_no_unresolved_journals()

    def test_writable_preflight_directory_blocks(self):
        preflight = self.state / ".preflight"
        preflight.mkdir(mode=0o700)
        preflight.chmod(0o755)
        with self.assertRaises((engine.UpdateError, transaction_journal.JournalError, OSError)):
            engine.assert_no_unresolved_journals()

    def test_only_terminal_outcomes_are_safe(self):
        for index, phase in enumerate(("completed", "aborted", "pre_mutation_recovered")):
            self.transaction(f"20261031T19000{index}Z-abcdefgh", phase)
        engine.assert_no_unresolved_journals()
        self.assertEqual(self.read.call_count, 3)

    def test_each_unresolved_phase_blocks_without_a_guardian_marker(self):
        phases = ("prepared", "fence_creating", "fenced", "pre_mutation_clear_intent",
                  "mutation_pending", "verified", "unfence_intent", "recovery_required")
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(dir=self.state) as parent:
                # Use an exact normal transaction name within a fresh private state root.
                root = Path(parent)
                name = "20261031T190000Z-abcdefgh"
                (root / name).mkdir(mode=0o700)
                self.entries[name] = phase
                with mock.patch.object(engine, "STATE", root), \
                        mock.patch.object(self, "state", root):
                    with self.assertRaises((engine.UpdateError, transaction_journal.JournalError)):
                        engine.assert_no_unresolved_journals()

    def test_corrupt_journal_blocks(self):
        self.transaction("20261031T190000Z-abcdefgh", transaction_journal.JournalError("corrupt"))
        with self.assertRaises((engine.UpdateError, transaction_journal.JournalError)):
            engine.assert_no_unresolved_journals()

    def test_unexpected_file_and_directory_block(self):
        for entry_type in ("file", "directory", "symlink"):
            with self.subTest(entry_type=entry_type), tempfile.TemporaryDirectory(dir=self.state) as parent:
                root = Path(parent)
                entry = root / "unexpected"
                if entry_type == "file":
                    entry.write_text("not a transaction")
                elif entry_type == "directory":
                    entry.mkdir()
                else:
                    entry.symlink_to(root / "absent")
                with mock.patch.object(engine, "STATE", root), \
                        mock.patch.object(self, "state", root):
                    with self.assertRaises((engine.UpdateError, transaction_journal.JournalError, OSError)):
                        engine.assert_no_unresolved_journals()


if __name__ == "__main__":
    unittest.main()
