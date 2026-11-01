"""Real temporary-filesystem tests; no packages, services or VPS state change."""

import copy
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

import transaction_journal as journal


class TransactionJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve() / "state"
        self.root.mkdir(mode=0o700)
        self.owner = os.geteuid()
        self.txn = "20261031T190000Z-abcdefgh"
        self.directory = self.root / self.txn
        self.directory.mkdir(mode=0o700)
        self.kw = {"_test_expected_uid": self.owner}
        sha = "a" * 64
        self.plan = {
            "packages": [{"name": "docker-ce", "installed": "5:29.9.1-1~ubuntu.26.04~resolute",
                          "target": "5:29.9.2-1~ubuntu.26.04~resolute", "old_sha256": sha,
                          "new_sha256": "b" * 64}],
            "inventory": {"docker-ce": "5:29.9.1-1~ubuntu.26.04~resolute", "bash": "5.3-1"},
            "containers": {name: {"image_id": "sha256:" + sha, "mounts_sha256": sha,
                                   "ports_sha256": sha}
                           for name in ("redis", "rspamd", "unbound")},
        }

    def initial(self):
        return journal.initialize(self.root, self.txn, self.plan, **self.kw)

    def step(self, record, target):
        return journal.advance(self.root, self.txn, record["plan_sha256"], record["phase"],
                               record["generation"], target, **self.kw)

    def test_full_ordered_lifecycle_persists(self):
        state = self.initial()
        for phase in ("fence_creating", "fenced", "mutation_pending", "verified", "unfence_intent", "completed"):
            state = self.step(state, phase)
            self.assertEqual(journal.read(self.root, self.txn, **self.kw), state)
        self.assertEqual(state["generation"], 6)
        self.assertEqual((self.directory / journal.RECORD).stat().st_mode & 0o777, 0o600)

    def test_pre_mutation_recovery_paths_are_ordered(self):
        for fence_phase in ("fence_creating", "fenced"):
            with self.subTest(fence_phase=fence_phase), tempfile.TemporaryDirectory() as fresh:
                self.root = Path(fresh).resolve() / "state"
                self.root.mkdir(mode=0o700)
                (self.root / self.txn).mkdir(mode=0o700)
                state = self.step(self.initial(), "fence_creating")
                if fence_phase == "fenced":
                    state = self.step(state, "fenced")
                state = self.step(state, "pre_mutation_clear_intent")
                state = self.step(state, "pre_mutation_recovered")
                self.assertEqual(journal.read(self.root, self.txn, **self.kw), state)
                with self.assertRaises(journal.JournalError):
                    self.step(state, "mutation_pending")

    def test_pre_mutation_recovery_cannot_follow_mutation_intent(self):
        state = self.initial()
        for phase in ("fence_creating", "fenced", "mutation_pending"):
            state = self.step(state, phase)
        with self.assertRaises(journal.JournalError):
            self.step(state, "pre_mutation_clear_intent")

    def test_early_abort_and_failure_are_terminal(self):
        state = self.step(self.initial(), "aborted")
        with self.assertRaises(journal.JournalError):
            self.step(state, "fence_creating")

    def test_stale_generation_hash_and_skipped_phase_fail(self):
        state = self.initial()
        with self.assertRaises(journal.JournalError):
            self.step(state, "mutation_pending")
        with self.assertRaises(journal.JournalError):
            journal.advance(self.root, self.txn, "c" * 64, "prepared", 0, "fence_creating", **self.kw)
        state = self.step(state, "fence_creating")
        with self.assertRaises(journal.JournalError):
            journal.advance(self.root, self.txn, state["plan_sha256"], "fence_creating", 0, "fenced", **self.kw)

    def test_initialize_cannot_replace_existing_journal(self):
        before = self.initial()
        with self.assertRaises(journal.JournalError):
            self.initial()
        self.assertEqual(journal.read(self.root, self.txn, **self.kw), before)

    def test_plan_rejects_extra_fields_or_inconsistent_inventory(self):
        for mutation in ("secret", "missing_package", "extra_service", "bad_image", "duplicate"):
            plan = copy.deepcopy(self.plan)
            if mutation == "secret": plan["password"] = "not permitted"
            if mutation == "missing_package": del plan["inventory"]["docker-ce"]
            if mutation == "extra_service": plan["containers"]["unexpected"] = {}
            if mutation == "bad_image": plan["containers"]["redis"]["image_id"] = "latest"
            if mutation == "duplicate": plan["packages"].append(copy.deepcopy(plan["packages"][0]))
            with self.subTest(mutation=mutation), self.assertRaises(journal.JournalError):
                journal.validate_plan(plan)

    def test_plan_sha_is_canonical_and_bound_to_all_inventory_and_container_fields(self):
        first = journal.plan_digest(self.plan)
        reordered = {k: self.plan[k] for k in reversed(list(self.plan))}
        self.assertEqual(first, journal.plan_digest(reordered))
        changed = copy.deepcopy(self.plan)
        changed["inventory"]["bash"] = "5.3-2"
        self.assertNotEqual(first, journal.plan_digest(changed))
        changed = copy.deepcopy(self.plan)
        changed["containers"]["redis"]["mounts_sha256"] = "c" * 64
        self.assertNotEqual(first, journal.plan_digest(changed))

    def test_container_evidence_is_normalized_and_contains_no_mount_paths(self):
        sha = "a" * 64
        snapshot = {name: ["sha256:" + sha, '[{"Source":"/private/path","X":1}]', '{"b":2,"a":1}']
                    for name in ("redis", "rspamd", "unbound")}
        first = journal.container_evidence(snapshot)
        snapshot["redis"][2] = '{"a":1,"b":2}'
        self.assertEqual(first, journal.container_evidence(snapshot))
        self.assertNotIn("/private/path", json.dumps(first))
        snapshot["redis"][1] = '[{"Source":"/other","X":1}]'
        self.assertNotEqual(first["redis"], journal.container_evidence(snapshot)["redis"])

    def test_container_evidence_rejects_invalid_json_and_missing_service(self):
        sha = "a" * 64
        snapshot = {name: ["sha256:" + sha, "[]", "{}"] for name in ("redis", "rspamd", "unbound")}
        snapshot["redis"][1] = '{"x":1,"x":2}'
        with self.assertRaises(journal.JournalError):
            journal.container_evidence(snapshot)
        del snapshot["unbound"]
        with self.assertRaises(journal.JournalError):
            journal.container_evidence(snapshot)

    def test_modified_plan_or_impossible_phase_generation_is_rejected(self):
        state = self.initial()
        record = self.directory / journal.RECORD
        state["plan"]["inventory"]["bash"] = "5.3-2"
        record.write_text(json.dumps(state))
        with self.assertRaises(journal.JournalError):
            journal.read(self.root, self.txn, **self.kw)
        state["plan_sha256"] = journal.plan_digest(state["plan"])
        state["phase"] = "completed"
        state["generation"] = 0
        record.write_text(json.dumps(state))
        with self.assertRaises(journal.JournalError):
            journal.read(self.root, self.txn, **self.kw)

    def test_duplicate_json_fields_and_unexpected_types_fail_cleanly(self):
        self.initial()
        record = self.directory / journal.RECORD
        record.write_text('{"schema":1,"schema":1}')
        with self.assertRaises(journal.JournalError):
            journal.read(self.root, self.txn, **self.kw)
        with self.assertRaises(journal.JournalError):
            journal.advance(self.root, self.txn, "a" * 64, [], 0, "fenced", **self.kw)

    def test_unsafe_transaction_and_symlinked_state_root_are_rejected(self):
        for name in ("../escape", "20261031T190000Z-ABCDefgh", "20261031T190000Z-abcdefgh/evil"):
            with self.subTest(name=name), self.assertRaises(journal.JournalError):
                journal.initialize(self.root, name, self.plan, **self.kw)
        link = self.root.parent / "alias"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises((journal.JournalError, OSError)):
            journal.initialize(link, self.txn, self.plan, **self.kw)

    def test_writable_ancestor_or_nonprivate_transaction_fails(self):
        self.root.chmod(0o777)
        with self.assertRaises(journal.JournalError):
            self.initial()
        self.root.chmod(0o700)
        self.directory.chmod(0o755)
        with self.assertRaises(journal.JournalError):
            self.initial()

    def test_tampered_mode_hardlink_and_symlink_fail(self):
        self.initial()
        path = self.directory / journal.RECORD
        path.chmod(0o644)
        with self.assertRaises(journal.JournalError):
            journal.read(self.root, self.txn, **self.kw)
        path.chmod(0o600)
        extra = self.directory / "extra"
        os.link(path, extra)
        with self.assertRaises(journal.JournalError):
            journal.read(self.root, self.txn, **self.kw)
        extra.unlink()
        path.unlink()
        path.symlink_to("/dev/null")
        with self.assertRaises((journal.JournalError, OSError)):
            journal.read(self.root, self.txn, **self.kw)

    def test_lock_contention_defers_instead_of_mutating(self):
        state = self.initial()
        with (self.directory / journal.LOCK).open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.step(state, "fence_creating")
            fcntl.flock(lock, fcntl.LOCK_UN)
        self.assertEqual(journal.read(self.root, self.txn, **self.kw), state)

    def test_lock_replacement_during_acquisition_is_rejected(self):
        self.initial()
        lock_path = self.directory / journal.LOCK
        real_flock = fcntl.flock
        def replace_after_lock(fd, operation):
            real_flock(fd, operation)
            lock_path.unlink()
            lock_path.write_bytes(b"")
            lock_path.chmod(0o600)
        with mock.patch.object(journal.fcntl, "flock", side_effect=replace_after_lock):
            with self.assertRaises(journal.JournalError):
                journal.read(self.root, self.txn, **self.kw)

    def test_fifo_record_is_rejected_without_blocking(self):
        self.initial()
        path = self.directory / journal.RECORD
        path.unlink()
        os.mkfifo(path, 0o600)
        with self.assertRaises(journal.JournalError):
            journal.read(self.root, self.txn, **self.kw)

    def test_final_serialized_newline_obeys_size_limit(self):
        record = {"x": "test"}
        exact = len(journal._canonical(record))
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with mock.patch.object(journal, "MAX_BYTES", exact):
                with self.assertRaises(journal.JournalError):
                    journal._write(fd, record)
            self.assertFalse((self.directory / journal.RECORD).exists())
        finally:
            os.close(fd)

    def test_file_fsync_failure_stops_and_preserves_preceding_state(self):
        state = self.initial()
        with mock.patch.object(journal.os, "fsync", side_effect=OSError("injected")):
            with self.assertRaises(journal.DurabilityError):
                self.step(state, "fence_creating")
        self.assertEqual(journal.read(self.root, self.txn, **self.kw), state)

    def test_directory_fsync_failure_reports_uncertain_state(self):
        state = self.initial()
        real = os.fsync
        calls = 0
        def fail_directory(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected directory fsync error")
            return real(fd)
        with mock.patch.object(journal.os, "fsync", side_effect=fail_directory):
            with self.assertRaises(journal.DurabilityError):
                self.step(state, "fence_creating")
        # The new record may be visible even though durability was not proven.
        # The caller must stop and reconcile instead of proceeding to mutation.
        observed = journal.read(self.root, self.txn, **self.kw)
        self.assertIn(observed["phase"], {"prepared", "fence_creating"})

    def test_kill_after_mutation_intent_preserves_bound_recovery_state(self):
        # A real child uses only private temporary journal files; it executes no
        # installer, service or Guardian operation. The result is not a reboot test.
        program = r'''
import json, sys, time
from pathlib import Path
import transaction_journal as j
root, txn, plan_json, uid = sys.argv[1:]
kw = {"_test_expected_uid": int(uid)}
state = j.initialize(root, txn, json.loads(plan_json), **kw)
for phase in ("fence_creating", "fenced", "mutation_pending"):
    state = j.advance(root, txn, state["plan_sha256"], state["phase"], state["generation"], phase, **kw)
(Path(root).parent / "child-ready").write_text("ready")
while True: time.sleep(1)
'''
        child = subprocess.Popen([sys.executable, "-c", program, str(self.root), self.txn,
                                  json.dumps(self.plan), str(self.owner)],
                                 cwd=Path(__file__).parent, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while True:
                if child.poll() is not None:
                    self.fail("child exited before intent: " + child.stderr.read()[-1000:])
                # The child announces only after releasing its last journal
                # lock. Polling journal.read here could otherwise take that
                # nonblocking lock between the child's phase transitions.
                if (self.root.parent / "child-ready").exists():
                    break
                if time.monotonic() >= deadline:
                    self.fail("child did not reach mutation intent")
                time.sleep(0.01)
            child.kill()
            child.wait(timeout=5)
            recovered = journal.read(self.root, self.txn, **self.kw)
            self.assertEqual(recovered["phase"], "mutation_pending")
            self.assertEqual(recovered["plan_sha256"], journal.plan_digest(self.plan))
            with self.assertRaises(journal.JournalError):
                self.step(recovered, "pre_mutation_clear_intent")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            child.stderr.close()


if __name__ == "__main__":
    unittest.main()
