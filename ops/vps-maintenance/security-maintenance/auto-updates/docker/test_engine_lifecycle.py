"""Mocked lifecycle checks; these never invoke system commands or touch the VPS."""

from contextlib import ExitStack
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
import hashlib
import shutil
import stat
from types import SimpleNamespace
import sys
from unittest import mock

import engine


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.baseline = {"docker-ce": "5:29.9.1-1~ubuntu.26.04~resolute"}
        self.targets = {"docker-ce": "5:29.9.2-1~ubuntu.26.04~resolute"}
        self.calls = []
        self.install_failure = False
        self.install_timeout = False
        self.unit = self.stack.enter_context(mock.patch.object(
            engine, "unit_active", side_effect=lambda name, *args: name in engine.TIMERS))
        self.busy = self.stack.enter_context(mock.patch.object(engine, "unit_busy", return_value=False))
        self.stack.enter_context(mock.patch.object(engine.os, "geteuid", return_value=0))
        self.stack.enter_context(mock.patch.object(engine.os.path, "lexists", return_value=False))
        state = Path(self.temp.name) / "state"
        self.stack.enter_context(mock.patch.object(engine, "STATE", state))
        original_lstat = os.lstat
        self.stack.enter_context(mock.patch.object(engine.os, "lstat", side_effect=lambda p: (
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
            if Path(p) in (state, state / ".preflight") else original_lstat(p))))
        self.stack.enter_context(mock.patch.object(engine, "require_recent_backup"))
        self.stack.enter_context(mock.patch.object(engine, "container_snapshot", return_value={"redis": "original"}))
        self.health = self.stack.enter_context(mock.patch.object(engine, "health"))
        self.stack.enter_context(mock.patch.object(engine, "candidates", return_value=(self.baseline, self.targets, {})))
        self.sim = self.stack.enter_context(mock.patch.object(engine, "simulation"))
        self.stack.enter_context(mock.patch.object(engine, "save_packages", side_effect=self.fake_packages))
        self.stack.enter_context(mock.patch.object(engine, "installed_inventory", side_effect=[self.baseline, self.targets]))
        self.stack.enter_context(mock.patch.object(engine.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(10**10, 0, 10**10)))
        self.fence = self.stack.enter_context(mock.patch.object(engine, "acquire_fence", side_effect=self.make_fence))
        self.updater_lock = self.stack.enter_context(mock.patch.object(
            engine, "acquire_updater_lock", create=True, side_effect=self.make_updater_lock))
        self.frontend_lock = self.stack.enter_context(mock.patch.object(
            engine, "acquire_frontend_lock", create=True, side_effect=self.make_frontend_lock))
        self.check_frontend_lock = self.stack.enter_context(mock.patch.object(
            engine, "assert_frontend_lock_held"))
        self.marker = self.stack.enter_context(mock.patch.object(engine, "create_marker", return_value=b"mock-owner"))
        self.marker_identity = self.stack.enter_context(mock.patch.object(
            engine, "marker_identity", create=True, return_value=(11, 12)))
        self.clear = self.stack.enter_context(mock.patch.object(engine, "clear_own_marker"))
        self.journal_events = []
        self.journal = self.stack.enter_context(mock.patch.object(
            engine, "initialize_journal", create=True, side_effect=self.fake_initialize_journal))
        self.advance = self.stack.enter_context(mock.patch.object(
            engine, "advance_journal", create=True, side_effect=self.fake_advance_journal))
        self.scan = self.stack.enter_context(mock.patch.object(
            engine, "assert_no_unresolved_journals", create=True))
        self.preflight_cleanup = self.stack.enter_context(mock.patch.object(
            engine, "cleanup_preflight", create=True))
        self.retention_cleanup = self.stack.enter_context(mock.patch.object(
            engine, "cleanup_terminal_transactions", create=True))
        self.run = self.stack.enter_context(mock.patch.object(engine, "run", side_effect=self.fake_run))

    def fake_initialize_journal(self, *args):
        self.journal_events.append("prepared")
        return {"phase": "prepared", "generation": 0, "plan_sha256": "a" * 64}

    def fake_advance_journal(self, record, phase):
        self.journal_events.append(phase)
        return dict(record, phase=phase, generation=record["generation"] + 1)

    def make_fence(self):
        return os.open(Path(self.temp.name) / "lock", os.O_CREAT | os.O_RDONLY, 0o600)

    def make_updater_lock(self):
        return os.open(Path(self.temp.name) / "updater-lock", os.O_CREAT | os.O_RDONLY, 0o600)

    def make_frontend_lock(self):
        return os.open(Path(self.temp.name) / "frontend-lock", os.O_CREAT | os.O_RDWR, 0o600)

    def fake_packages(self, directory, versions, targets):
        result = {}
        for name in targets:
            path = directory / (name + ".deb")
            data = versions[name].encode()
            path.write_bytes(data)
            result[name] = (str(path), hashlib.sha256(data).hexdigest())
        return result

    def fake_run(self, args, **kwargs):
        self.calls.append(tuple(args))
        if args[:2] == ["dpkg", "--refuse-downgrade"]:
            self.assertTrue(kwargs.get("frontend_locked"), "package transaction must inherit frontend-lock state")
            self.journal_events.append("dpkg")
        else:
            self.assertFalse(kwargs.get("frontend_locked", False), "only dpkg may bypass frontend locking")
        if args[:2] == ["dpkg", "--refuse-downgrade"] and self.install_failure:
            raise engine.UpdateError("mock install failed")
        if args[:2] == ["dpkg", "--refuse-downgrade"] and self.install_timeout:
            raise subprocess.TimeoutExpired(args, 900)
        return subprocess.CompletedProcess(args, 0, "", "")

    def service_calls(self, action):
        return [call for call in self.calls if call[:2] == ("systemctl", action)]

    def test_success_does_not_change_timers_and_clears_marker(self):
        engine.apply(self.baseline, self.targets)
        self.assertEqual(self.service_calls("stop"), [])
        self.assertEqual(self.service_calls("start"), [])
        self.clear.assert_called_once_with(b"mock-owner", expected_identity=(11, 12))
        self.assertEqual(self.health.call_count, 2)
        self.assertTrue(any(call[:2] == ("dpkg", "--refuse-downgrade") for call in self.calls))

    def test_journal_records_mutation_pending_before_any_package_mutation(self):
        engine.apply(self.baseline, self.targets)
        self.assertEqual(self.journal_events,
                         ["prepared", "fence_creating", "fenced", "mutation_pending",
                          "dpkg", "verified", "unfence_intent", "completed"])

    def test_lost_frontend_lock_before_mutation_stays_fenced(self):
        self.check_frontend_lock.side_effect = engine.UpdateError("lost frontend lock")
        with self.assertRaises(engine.UpdateError):
            engine.apply(self.baseline, self.targets)
        self.clear.assert_not_called()
        self.assertNotIn("mutation_pending", self.journal_events)
        self.assertFalse(any(call[:2] == ("dpkg", "--refuse-downgrade") for call in self.calls))

    def test_lost_frontend_lock_after_mutation_stays_fenced(self):
        self.check_frontend_lock.side_effect = [None, None, engine.UpdateError("lost frontend lock")]
        with self.assertRaisesRegex(engine.UpdateError, "remains fenced"):
            engine.apply(self.baseline, self.targets)
        self.assertIn("dpkg", self.journal_events)
        self.assertNotIn("verified", self.journal_events)
        self.clear.assert_not_called()

    def test_journal_failure_before_mutation_retains_marker_and_never_runs_dpkg(self):
        def advance(record, phase):
            if phase == "mutation_pending":
                raise engine.UpdateError("injected journal sync failure")
            return self.fake_advance_journal(record, phase)
        self.advance.side_effect = advance
        with self.assertRaisesRegex(engine.UpdateError, "journal sync failure"):
            engine.apply(self.baseline, self.targets)
        self.marker.assert_called_once()
        self.clear.assert_not_called()
        self.assertFalse(any(call[:2] == ("dpkg", "--refuse-downgrade") for call in self.calls))

    def test_journal_failure_after_package_mutation_retains_marker(self):
        def advance(record, phase):
            if phase == "verified":
                raise engine.UpdateError("injected journal sync failure")
            return self.fake_advance_journal(record, phase)
        self.advance.side_effect = advance
        with self.assertRaisesRegex(engine.UpdateError, "remains fenced"):
            engine.apply(self.baseline, self.targets)
        self.assertTrue(any(call[:2] == ("dpkg", "--refuse-downgrade") for call in self.calls))
        self.clear.assert_not_called()

    def test_final_journal_failure_occurs_after_marker_clear_and_requires_reconciliation(self):
        # This is the current multi-file transaction boundary: once the marker
        # has been cleared, a failed 'completed' journal write leaves the last
        # durable phase at unfence_intent. A production monitor must reconcile
        # that state and must not infer that the marker is still present.
        def advance(record, phase):
            if phase == "completed":
                raise engine.UpdateError("injected completion sync failure")
            return self.fake_advance_journal(record, phase)
        self.advance.side_effect = advance
        with self.assertRaisesRegex(engine.UpdateError, "completion sync failure"):
            engine.apply(self.baseline, self.targets)
        self.assertEqual(self.journal_events[-1], "unfence_intent")
        self.clear.assert_called_once()

    def test_failed_install_stays_fenced_without_automatic_rollback(self):
        self.install_failure = True
        with self.assertRaisesRegex(engine.UpdateError, "remains fenced"):
            engine.apply(self.baseline, self.targets)
        self.assertFalse(any(call[:2] == ("dpkg", "-i") for call in self.calls))
        self.assertEqual(self.service_calls("start"), [])
        self.clear.assert_not_called()
        self.assertEqual(len(list(engine.STATE.glob("*/old/docker-ce.deb"))), 1)

    def test_failed_post_install_health_keeps_fence_without_rollback(self):
        self.health.side_effect = [None, engine.UpdateError("mock health failure")]
        with self.assertRaisesRegex(engine.UpdateError, "remains fenced"):
            engine.apply(self.baseline, self.targets)
        self.clear.assert_not_called()
        self.assertFalse(any(call[:2] == ("dpkg", "-i") for call in self.calls))
        self.assertEqual(self.service_calls("start"), [])

    def test_timed_out_install_stays_fenced_without_racing_rollback(self):
        self.install_timeout = True
        with self.assertRaisesRegex(engine.UpdateError, "timed out"):
            engine.apply(self.baseline, self.targets)
        self.assertFalse(any(call[:2] == ("dpkg", "-i") for call in self.calls))
        self.clear.assert_not_called()

    def test_unexpected_inventory_change_keeps_fence_without_rollback(self):
        engine.installed_inventory.side_effect = [self.baseline, {"docker-ce": "unexpected"}, {"docker-ce": "unexpected"}]
        with self.assertRaisesRegex(engine.UpdateError, "remains fenced"):
            engine.apply(self.baseline, self.targets)
        self.assertFalse(any(call[:2] == ("dpkg", "-i") for call in self.calls))
        self.clear.assert_not_called()

    def test_cannot_clear_marker_must_not_restart_timers(self):
        self.clear.side_effect = engine.UpdateError("marker changed")
        with self.assertRaisesRegex(engine.UpdateError, "marker changed"):
            engine.apply(self.baseline, self.targets)
        self.assertEqual(self.service_calls("start"), [])

    def test_active_worker_defers_without_stopping_timers(self):
        self.busy.side_effect = lambda name: name == engine.WORKERS[0]
        with self.assertRaises(engine.UpdateError):
            engine.apply(self.baseline, self.targets)
        self.assertEqual(self.service_calls("stop"), [])
        self.marker.assert_not_called()

    def test_fence_contention_leaves_timers_unchanged(self):
        self.fence.side_effect = engine.UpdateError("mock contention")
        with self.assertRaisesRegex(engine.UpdateError, "mock contention"):
            engine.apply(self.baseline, self.targets)
        self.assertEqual(self.service_calls("start"), [])
        self.assertEqual(self.service_calls("stop"), [])
        self.marker.assert_not_called()

    def test_failed_preflight_download_does_not_leave_unjournaled_state(self):
        engine.save_packages.side_effect = engine.UpdateError("download unavailable")
        with self.assertRaisesRegex(engine.UpdateError, "download unavailable"):
            engine.apply(self.baseline, self.targets)
        for entry in engine.STATE.iterdir():
            if entry.name in (".preflight", ".updater.lock"):
                continue
            self.assertTrue((entry / "transaction.json").is_file(),
                            "preflight left an unjournaled directory which blocks all later updates")

    def test_stale_preflight_cleanup_is_attempted_even_when_disk_space_is_low(self):
        engine.shutil.disk_usage.return_value = shutil._ntuple_diskusage(10**10, 9 * 10**9, 10**9)
        with self.assertRaisesRegex(engine.UpdateError, "less than 2 GiB"):
            engine.apply(self.baseline, self.targets)
        self.preflight_cleanup.assert_called_once()

    def test_fence_contention_does_not_leave_unjournaled_state(self):
        self.fence.side_effect = engine.UpdateError("mock contention")
        with self.assertRaisesRegex(engine.UpdateError, "mock contention"):
            engine.apply(self.baseline, self.targets)
        for entry in engine.STATE.iterdir():
            if entry.name in (".preflight", ".updater.lock"):
                continue
            self.assertTrue((entry / "transaction.json").is_file(),
                            "lock contention left an unjournaled directory which blocks later updates")

    def test_changed_candidates_after_fencing_defers(self):
        engine.candidates.return_value = ({"docker-ce": "unexpected"}, self.targets, {})
        with self.assertRaisesRegex(engine.UpdateError, "candidates changed"):
            engine.apply(self.baseline, self.targets)
        self.assertEqual(self.service_calls("start"), [])
        self.marker.assert_not_called()

    def test_simulation_rejection_defers(self):
        self.sim.side_effect = engine.UpdateError("mock unsafe transaction")
        with self.assertRaisesRegex(engine.UpdateError, "unsafe transaction"):
            engine.apply(self.baseline, self.targets)
        self.assertEqual(self.service_calls("start"), [])
        self.marker.assert_not_called()
        self.assertFalse(any(call[:2] == ("dpkg", "--refuse-downgrade") for call in self.calls))


class UnitStateTests(unittest.TestCase):
    def test_failed_worker_is_busy_and_inactive_worker_is_not(self):
        with mock.patch.object(engine, "unit_state", return_value="failed"):
            self.assertTrue(engine.unit_busy("mail-guardian@pilot.service"))
        with mock.patch.object(engine, "unit_state", return_value="inactive"):
            self.assertFalse(engine.unit_busy("mail-guardian@pilot.service"))

    def test_missing_or_unknown_unit_state_fails_closed(self):
        for stdout in ("LoadState=not-found\nActiveState=inactive\n",
                       "LoadState=loaded\nActiveState=unknown\n", ""):
            with self.subTest(stdout=stdout), mock.patch.object(
                    engine, "run", return_value=subprocess.CompletedProcess([], 0, stdout, "")):
                with self.assertRaises(engine.UpdateError):
                    engine.unit_state("mail-guardian@pilot.service")


class CandidateSelectionTests(unittest.TestCase):
    def test_newer_major_is_reported_but_highest_same_line_patch_is_selected(self):
        old = "5:29.9.1-1~ubuntu.26.04~resolute"
        patch_a = "5:29.9.2-1~ubuntu.26.04~resolute"
        patch_b = "5:29.9.3-1~ubuntu.26.04~resolute"
        major = "5:30.0.0-1~ubuntu.26.04~resolute"
        order = {old: 0, patch_a: 1, patch_b: 2, major: 3}
        origin = SimpleNamespace(origin="Docker", archive="resolute", component="stable", site="download.docker.com")
        version = lambda v, priority=500: SimpleNamespace(version=v, origins=[origin], policy_priority=priority)
        pkg = SimpleNamespace(is_installed=True, installed=version(old), candidate=version(major),
                              versions=[version(old), version(patch_b), version(major), version(patch_a)])
        apt = SimpleNamespace(Cache=lambda: {"docker-ce": pkg})
        apt_pkg = SimpleNamespace(version_compare=lambda a, b: (order[a] > order[b]) - (order[a] < order[b]))
        with mock.patch.dict(sys.modules, {"apt": apt, "apt_pkg": apt_pkg}), \
             mock.patch.object(engine, "PACKAGES", ("docker-ce",)), \
             mock.patch.object(engine, "run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
             mock.patch("docker_auto_update.version_is_newer", side_effect=lambda a, b: order[b] > order[a]):
            baseline, targets, skipped = engine.candidates()
        self.assertEqual(baseline, {"docker-ce": old})
        self.assertEqual(targets, {"docker-ce": patch_b})
        self.assertEqual(skipped["docker-ce"]["candidate"], major)

    def test_negative_pin_priority_patch_is_not_selected(self):
        old = "5:29.9.1-1~ubuntu.26.04~resolute"
        allowed = "5:29.9.2-1~ubuntu.26.04~resolute"
        blocked = "5:29.9.3-1~ubuntu.26.04~resolute"
        origin = SimpleNamespace(origin="Docker", archive="resolute", component="stable", site="download.docker.com")
        version = lambda v, priority=500: SimpleNamespace(version=v, origins=[origin], policy_priority=priority)
        pkg = SimpleNamespace(is_installed=True, installed=version(old), candidate=version(allowed),
                              versions=[version(old), version(allowed), version(blocked, -1)])
        apt = SimpleNamespace(Cache=lambda: {"docker-ce": pkg})
        apt_pkg = SimpleNamespace(version_compare=lambda a, b: (a > b) - (a < b))
        with mock.patch.dict(sys.modules, {"apt": apt, "apt_pkg": apt_pkg}), \
             mock.patch.object(engine, "PACKAGES", ("docker-ce",)), \
             mock.patch.object(engine, "run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
             mock.patch("docker_auto_update.version_is_newer", side_effect=lambda a, b: b != old):
            _, targets, _ = engine.candidates()
        self.assertEqual(targets, {"docker-ce": allowed})

    def test_held_package_is_reported_but_not_selected(self):
        old = "5:29.9.1-1~ubuntu.26.04~resolute"
        new = "5:29.9.2-1~ubuntu.26.04~resolute"
        pkg = SimpleNamespace(is_installed=True, installed=SimpleNamespace(version=old),
                              candidate=SimpleNamespace(version=new))
        apt = SimpleNamespace(Cache=lambda: {"docker-ce": pkg})
        with mock.patch.dict(sys.modules, {"apt": apt, "apt_pkg": SimpleNamespace()}), \
             mock.patch.object(engine, "PACKAGES", ("docker-ce",)), \
             mock.patch.object(engine, "run", return_value=subprocess.CompletedProcess([], 0, "docker-ce\n", "")):
            baseline, targets, skipped = engine.candidates()
        self.assertEqual(baseline, {"docker-ce": old})
        self.assertEqual(targets, {})
        self.assertEqual(skipped["docker-ce"]["reason"], "package is held")

    def test_untrusted_candidate_source_fails_closed(self):
        old, new = "5:29.9.1-1~ubuntu.26.04~resolute", "5:29.9.2-1~ubuntu.26.04~resolute"
        origin = SimpleNamespace(origin="Other", archive="resolute", component="stable", site="example.invalid")
        version = lambda v: SimpleNamespace(version=v, origins=[origin], policy_priority=500)
        pkg = SimpleNamespace(is_installed=True, installed=version(old), candidate=version(new), versions=[version(new)])
        with mock.patch.dict(sys.modules, {"apt": SimpleNamespace(Cache=lambda: {"docker-ce": pkg}),
                                         "apt_pkg": SimpleNamespace()}), \
             mock.patch.object(engine, "PACKAGES", ("docker-ce",)), \
             mock.patch.object(engine, "run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            with self.assertRaisesRegex(engine.UpdateError, "not Docker stable"):
                engine.candidates()


if __name__ == "__main__":
    unittest.main()
