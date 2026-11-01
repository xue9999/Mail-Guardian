import importlib.util
from contextlib import ExitStack
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("simple_docker_updater", Path(__file__).with_name("updater.py"))
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.codename = patch.object(u.e,"ubuntu_codename",return_value="resolute")
        self.codename.start();self.addCleanup(self.codename.stop)

    def test_no_update_only_never_recovers_pending_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            pending = Path(tmp) / "pending.json"
            pending.write_text("fixture")
            with patch.object(u.os, "geteuid", return_value=0), \
                 patch.object(u, "PENDING", pending), patch.object(u, "ensure_state"), \
                 patch.object(u, "acquire_global", side_effect=lambda: os.open(os.devnull, os.O_RDONLY)), \
                 patch.object(u, "recover_pending_locked") as recover:
                with self.assertRaises(u.e.UpdateError):
                    u.execute(no_update_only=True)
                recover.assert_not_called()

    def test_plan_accepts_signed_ubuntu_dependency_and_pins_it(self):
        docker = SimpleNamespace(origin="Docker", archive="resolute", component="stable", site="download.docker.com", trusted=True)
        ubuntu = SimpleNamespace(origin="Ubuntu", archive="resolute-updates", component="main", site="archive.ubuntu.com", trusted=True)
        cache = {"docker-ce": SimpleNamespace(candidate=SimpleNamespace(version="2", origins=[docker])),
                 "new-lib": SimpleNamespace(candidate=SimpleNamespace(version="3", origins=[ubuntu]))}
        output = "Inst docker-ce [1] (2 Docker:resolute [amd64])\nInst new-lib (3 Ubuntu:resolute-updates [amd64])\n"
        def run(args, **kwargs):
            return SimpleNamespace(stdout=output if args[0] == "apt-get" else "")
        with patch.dict(sys.modules, {"apt": SimpleNamespace(Cache=lambda: cache)}), patch.object(u.e, "run", side_effect=run):
            self.assertEqual(u.apt_plan({"docker-ce": "2"}), {"docker-ce": "2", "new-lib": "3"})

    def test_plan_rejects_removal(self):
        output = "Inst docker-ce [1] (2 Docker:resolute [amd64])\nRemv important-package [1]\n"
        with patch.dict(sys.modules, {"apt": SimpleNamespace()}), patch.object(u.e, "run", return_value=SimpleNamespace(stdout=output)):
            with self.assertRaises(u.e.UpdateError):
                u.apt_plan({"docker-ce": "2"})

    def test_plan_rejects_dependency_from_other_vendor(self):
        docker = SimpleNamespace(origin="Docker", archive="resolute", component="stable", site="download.docker.com", trusted=True)
        other = SimpleNamespace(origin="Other", archive="resolute", component="main", site="example.invalid", trusted=True)
        cache = {"docker-ce": SimpleNamespace(candidate=SimpleNamespace(version="2", origins=[docker])),
                 "new-lib": SimpleNamespace(candidate=SimpleNamespace(version="3", origins=[other]))}
        output = "Inst docker-ce [1] (2 Docker:resolute [amd64])\nInst new-lib (3 Other:resolute [amd64])\n"
        def run(args, **kwargs):
            return SimpleNamespace(stdout=output if args[0] == "apt-get" else "")
        with patch.dict(sys.modules, {"apt": SimpleNamespace(Cache=lambda: cache)}), patch.object(u.e, "run", side_effect=run):
            with self.assertRaises(u.e.UpdateError):
                u.apt_plan({"docker-ce": "2"})

    def test_guardian_snapshot_only_inspects_guardian_containers(self):
        seen = []
        def inspect(args, **kwargs):
            name = args[-1]
            seen.append(name)
            service = u.e.EXPECTED[name]
            return SimpleNamespace(stdout=f"mail-guardian-pilot|{service}|true|healthy|image|[]|{{}}")
        with patch.object(u.e, "run", side_effect=inspect):
            snapshot = u.guardian_snapshot()
        self.assertEqual(set(snapshot), {"redis", "rspamd", "unbound"})
        self.assertEqual(set(seen), set(u.e.EXPECTED))

    def test_shared_lock_contention_is_benign_and_does_not_touch_apt(self):
        with patch.object(u.os, "geteuid", return_value=0), \
             patch.object(u, "acquire_global", side_effect=BlockingIOError), \
             patch.object(u.e, "run") as run:
            u.execute()
            u.recover()
        run.assert_not_called()

    def test_new_line_waits_for_manual_review_while_patch_is_selected(self):
        origin = SimpleNamespace(origin="Docker", archive="resolute", component="stable", site="download.docker.com", trusted=True)
        installed = SimpleNamespace(version="5:29.9.2-1~ubuntu.26.04~resolute")
        candidate = SimpleNamespace(version="5:30.1.0-1~ubuntu.26.04~resolute", origins=[origin])
        patch_version = SimpleNamespace(version="5:29.9.3-1~ubuntu.26.04~resolute", origins=[origin])
        pkg = SimpleNamespace(is_installed=True, installed=installed, candidate=candidate,
                              versions=[candidate, patch_version, installed])
        cache = {name: pkg for name in u.PACKAGES}
        apt = SimpleNamespace(Cache=lambda: cache)
        apt_pkg = SimpleNamespace(version_compare=lambda a, b: (a > b) - (a < b))
        with patch.dict(sys.modules, {"apt": apt, "apt_pkg": apt_pkg}), patch.object(u.e, "run", return_value=SimpleNamespace(stdout="")):
            _, targets = u.candidates()
        self.assertEqual(set(targets), set(u.PACKAGES))
        self.assertTrue(all(version == patch_version.version for version in targets.values()))

    def test_new_line_without_patch_has_no_automatic_candidate(self):
        package = SimpleNamespace(candidate=SimpleNamespace(version="30.1.0"), versions=[])
        self.assertIsNone(u.patch_candidate(package, "29.9.2", lambda a, b: (a > b) - (a < b)))

    def test_docker_epoch_and_package_revision_do_not_change_version_line(self):
        self.assertEqual(u.version_line("5:29.9.2-1~ubuntu.26.04~resolute"), (29, 9))
        with self.assertRaises(u.e.UpdateError):
            u.version_line("unknown")

    def test_qualified_new_ubuntu_codename_uses_its_signed_docker_and_dependency_sources(self):
        docker=SimpleNamespace(origin="Docker",archive="stonking",component="stable",site="download.docker.com",trusted=True)
        ubuntu=SimpleNamespace(origin="Ubuntu",archive="stonking-updates",component="main",site="archive.ubuntu.com",trusted=True)
        cache={"docker-ce":SimpleNamespace(candidate=SimpleNamespace(version="2",origins=[docker])),
               "new-lib":SimpleNamespace(candidate=SimpleNamespace(version="3",origins=[ubuntu]))}
        output="Inst docker-ce [1] (2 Docker:stonking [amd64])\nInst new-lib (3 Ubuntu:stonking-updates [amd64])\n"
        with patch.object(u.e,"ubuntu_codename",return_value="stonking"), \
             patch.dict(sys.modules,{"apt":SimpleNamespace(Cache=lambda:cache)}), \
             patch.object(u.e,"run",side_effect=lambda args,**kw:SimpleNamespace(stdout=output if args[0]=="apt-get" else "")):
            self.assertEqual(u.apt_plan({"docker-ce":"2"}),{"docker-ce":"2","new-lib":"3"})


class ReleaseMetadataTests(unittest.TestCase):
    def test_known_release_metadata_and_unknown_line(self):
        with tempfile.TemporaryDirectory() as raw:
            path=Path(raw)/"os-release"
            for version,name in (("24.04","noble"),("26.04","resolute"),("26.10","stonking")):
                path.write_text(f'ID=ubuntu\nVERSION_ID="{version}"\nVERSION_CODENAME={name}\n')
                self.assertEqual(u.e.ubuntu_codename(path),name)
            path.write_text('ID=ubuntu\nVERSION_ID="28.04"\nVERSION_CODENAME=new\n')
            with self.assertRaisesRegex(u.e.UpdateError,"qualification"):
                u.e.ubuntu_codename(path)

    def test_local_ssh_check_rejects_non_ssh_banner(self):
        conn = SimpleNamespace(settimeout=lambda _: None, recv=lambda _: b"HTTP/1.1 200 OK\r\n")
        class SocketContext:
            def __enter__(self):
                return conn
            def __exit__(self, *args):
                return False
        with patch.object(u.e, "run"), patch.object(u.socket, "create_connection", return_value=SocketContext()):
            with self.assertRaises(u.e.UpdateError):
                u.check_ssh_local()


class TransactionTests(unittest.TestCase):
    def run_scenario(self, *, targets, fail_dpkg=False, fail_ssh=False, fail_worker=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            marker = root / "migration-pending"
            events = []
            baseline = {"docker-ce": "old"}
            def fake_run(args, **kwargs):
                events.append(tuple(args))
                if args[0] == "apt-get" and "-y" in args and fail_dpkg:
                    raise u.e.UpdateError("synthetic interrupted apt")
                return SimpleNamespace(stdout="", returncode=0)
            def create_marker(_):
                marker.write_text("owned")
                return b"owned"
            def clear_marker(*args, **kwargs):
                marker.unlink()
            def save_packages(work, target, _):
                import hashlib
                path = work / "docker.deb"
                path.write_bytes(b"package")
                return {"docker-ce": (str(path), hashlib.sha256(b"package").hexdigest())}
            def make_state():
                state.mkdir(mode=0o700, exist_ok=True)
            def make_fd():
                return os.open(os.devnull, os.O_RDONLY)
            def ssh_check():
                events.append(("ssh-local-check",))
                if fail_ssh:
                    raise u.e.UpdateError("synthetic SSH failure")
            def worker():
                events.append(("actual-worker",))
                if fail_worker:
                    raise u.e.UpdateError("synthetic worker failure")
            patches = [
                patch.object(u, "STATE", state), patch.object(u, "PENDING", state / "pending.json"),
                patch.object(u.e, "MARKER", marker), patch.object(u.os, "geteuid", return_value=0),
                patch.object(u, "acquire_global", side_effect=make_fd), patch.object(u, "ensure_state", side_effect=make_state),
                patch.object(u, "candidates", return_value=(baseline, targets)), patch.object(u.e, "run", side_effect=fake_run),
                patch.object(u, "apt_plan", return_value=targets),
                patch.object(u.e, "simulation"), patch.object(u.e, "unit_active", return_value=True),
                patch.object(u.e, "container_snapshot", return_value={"redis": "unchanged"}), patch.object(u.e, "health"),
                patch.object(u.e, "save_packages", side_effect=save_packages), patch.object(u.e, "sync_directory"),
                patch.object(u, "wait_inactive"), patch.object(u, "properties", return_value={}),
                patch.object(u, "worker_snapshot", return_value={"actual": {"id": 1}}),
                patch.object(u, "settle_backup"),
                patch.object(u, "fresh_backup", return_value="fresh.age"), patch.object(u.e, "acquire_fence", side_effect=make_fd),
                patch.object(u.e, "unit_busy", return_value=False), patch.object(u.e, "acquire_frontend_lock", side_effect=make_fd),
                patch.object(u.e, "installed_inventory", return_value={}), patch.object(u.e, "inventory_matches", return_value=True),
                patch.object(u.e, "create_marker", side_effect=create_marker), patch.object(u.e, "marker_identity", return_value=(1, 1)),
                patch.object(u.e, "clear_own_marker", side_effect=clear_marker), patch.object(u.e, "assert_frontend_lock_held"),
                patch.object(u, "unit_file_states", side_effect=[["enabled", "enabled"], ["masked", "masked"], ["masked", "masked"], ["enabled", "enabled"]]),
                patch.object(u, "check_ssh_local", side_effect=ssh_check), patch.object(u, "run_worker", side_effect=worker)
            ]
            with ExitStack() as stack:
                for item in patches:
                    stack.enter_context(item)
                if fail_dpkg or fail_ssh or fail_worker:
                    with self.assertRaises(u.e.UpdateError):
                        u.execute()
                else:
                    u.execute()
                return events, marker.exists(), (state / "pending.json").read_text() if (state / "pending.json").exists() else None

    def test_no_update_does_not_stop_timers_or_start_backup(self):
        events, marker, pending = self.run_scenario(targets={})
        self.assertEqual(events, [("apt-get", "update")])
        self.assertFalse(marker)
        self.assertIsNone(pending)

    def test_interrupted_install_leaves_durable_fence_and_no_timer_restart(self):
        events, marker, pending = self.run_scenario(targets={"docker-ce": "new"}, fail_dpkg=True)
        self.assertTrue(marker)
        self.assertIn('"phase": "mutation_pending"', pending)
        self.assertFalse(any(row[:2] == ("systemctl", "start") for row in events))
        self.assertNotIn(("actual-worker",), events)
        self.assertTrue(any(row[:2] == ("systemctl", "mask") for row in events))
        self.assertFalse(any(row[:2] == ("systemctl", "unmask") for row in events))

    def test_ssh_failure_keeps_marker_and_masks_after_install(self):
        events, marker, pending = self.run_scenario(targets={"docker-ce": "new"}, fail_ssh=True)
        self.assertTrue(marker)
        self.assertIn('"phase": "mutation_pending"', pending)
        self.assertIn(("ssh-local-check",), events)
        self.assertFalse(any(row[:2] == ("systemctl", "unmask") for row in events))
        self.assertNotIn(("actual-worker",), events)

    def test_failed_worker_keeps_timers_masked_for_recovery(self):
        events, marker, pending = self.run_scenario(targets={"docker-ce": "new"}, fail_worker=True)
        self.assertFalse(marker)
        self.assertIn('"phase": "guardian_run"', pending)
        self.assertFalse(any(row[:2] == ("systemctl", "unmask") for row in events))

    def test_success_runs_worker_before_restarting_timers(self):
        events, marker, pending = self.run_scenario(targets={"docker-ce": "new"})
        self.assertFalse(marker)
        self.assertIsNone(pending)
        worker_index = events.index(("actual-worker",))
        mask_index = next(i for i, row in enumerate(events) if row[:2] == ("systemctl", "mask"))
        dpkg_index = next(i for i, row in enumerate(events) if row[0] == "apt-get" and "-y" in row)
        unmask_index = next(i for i, row in enumerate(events) if row[:2] == ("systemctl", "unmask"))
        timer_index = next(i for i, row in enumerate(events) if row[:2] == ("systemctl", "start"))
        self.assertLess(mask_index, dpkg_index)
        self.assertLess(worker_index, unmask_index)
        self.assertLess(worker_index, timer_index)


class RecoveryTests(unittest.TestCase):
    def exercise(self, phase, marker=False, changed_package=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pending = root / "pending.json"
            pending.write_text("fixture")
            fence_marker = root / "migration-pending"
            if marker:
                fence_marker.write_text("existing")
            baseline = {name: "1" for name in u.PACKAGES}
            inventory = dict(baseline)
            if changed_package:
                inventory[u.PACKAGES[0]] = "2"
            state = {"phase": phase, "timers": list(u.TIMERS), "baseline": baseline}
            events = []
            def run(args, **kwargs):
                events.append(tuple(args))
                return SimpleNamespace(stdout="")
            patches = [
                patch.object(u, "PENDING", pending), patch.object(u, "STATE", root),
                patch.object(u.e, "MARKER", fence_marker), patch.object(u, "read_pending", return_value=state),
                patch.object(u.e, "run", side_effect=run), patch.object(u.e, "installed_inventory", return_value=inventory),
                patch.object(u, "wait_inactive"), patch.object(u, "settle_backup"),
                patch.object(u.e, "acquire_fence", side_effect=lambda: os.open(os.devnull, os.O_RDONLY)),
                patch.object(u.e, "unit_busy", return_value=False),
                patch.object(u.e, "container_snapshot", return_value={}), patch.object(u.e, "health"),
                patch.object(u, "check_ssh_local"),
                patch.object(u, "unit_file_states", side_effect=[["masked", "enabled"], ["enabled", "enabled"]]),
                patch.object(u.e, "unit_active", return_value=True), patch.object(u.e, "sync_directory")
            ]
            with ExitStack() as stack:
                for item in patches:
                    stack.enter_context(item)
                if phase not in ("masking_timers", "backup") or marker or changed_package:
                    with self.assertRaises(u.e.UpdateError):
                        u.recover_pre_mutation_locked()
                else:
                    self.assertTrue(u.recover_pre_mutation_locked())
                return events, pending.exists()

    def test_pre_mutation_recovers_partial_mask(self):
        events, pending = self.exercise("masking_timers")
        self.assertFalse(pending)
        self.assertTrue(any(row[:2] == ("systemctl", "unmask") for row in events))
        self.assertTrue(any(row[:2] == ("systemctl", "start") for row in events))

    def test_post_mutation_never_unmasks_or_discards_pending(self):
        events, pending = self.exercise("mutation_pending")
        self.assertTrue(pending)
        self.assertFalse(any(row[:2] == ("systemctl", "unmask") for row in events))

    def test_marker_or_changed_packages_blocks_recovery(self):
        for kwargs in ({"marker": True}, {"changed_package": True}):
            with self.subTest(kwargs=kwargs):
                events, pending = self.exercise("backup", **kwargs)
                self.assertTrue(pending)
                self.assertFalse(any(row[:2] == ("systemctl", "unmask") for row in events))


class ForwardRecoveryTests(unittest.TestCase):
    def exercise(self, incomplete=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "migration-pending"
            marker.write_text("owned")
            pending = root / "pending.json"
            pending.write_text("fixture")
            baseline = {name: "1" for name in u.PACKAGES}
            state = {"phase": "mutation_pending", "timers": list(u.TIMERS), "baseline": baseline,
                     "targets": {u.PACKAGES[0]: "2"}, "plan": {u.PACKAGES[0]: "2"}, "transaction": "simple-docker-packages-abc123",
                     "containers": {"redis": [], "rspamd": [], "unbound": []}}
            inventory = dict(baseline)
            if not incomplete:
                inventory[u.PACKAGES[0]] = "2"
            events = []
            def run(args, **kwargs):
                events.append(tuple(args))
                return SimpleNamespace(stdout="")
            def clear(*args, **kwargs):
                events.append(("clear-marker",))
                marker.unlink()
            patches = [
                patch.object(u, "PENDING", pending), patch.object(u, "STATE", root), patch.object(u.e, "MARKER", marker),
                patch.object(u, "unit_file_states", return_value=["masked", "masked"]),
                patch.object(u.e, "unit_state", return_value="inactive"), patch.object(u, "wait_inactive"),
                patch.object(u, "settle_backup"), patch.object(u.e, "run", side_effect=run),
                patch.object(u.e, "acquire_fence", side_effect=lambda: os.open(os.devnull, os.O_RDONLY)),
                patch.object(u.e, "acquire_frontend_lock", side_effect=lambda: os.open(os.devnull, os.O_RDONLY)),
                patch.object(u.e, "assert_frontend_lock_held"), patch.object(u.e, "unit_busy", return_value=False),
                patch.object(u.e, "installed_inventory", return_value=inventory), patch.object(u.e, "health"),
                patch.object(u, "check_ssh_local"), patch.object(u.e, "marker_identity", return_value=(1, 2)),
                patch.object(u.e, "clear_own_marker", side_effect=clear),
                patch.object(u, "run_worker", side_effect=lambda: events.append(("worker",))),
                patch.object(u, "restore_timers", side_effect=lambda: events.append(("restore-timers",))),
                patch.object(u.e, "sync_directory")
            ]
            with ExitStack() as stack:
                for item in patches:
                    stack.enter_context(item)
                if incomplete:
                    with self.assertRaises(u.e.UpdateError):
                        u.recover_forward_locked(state)
                else:
                    u.recover_forward_locked(state)
                return events, marker.exists(), pending.exists()

    def test_verified_update_runs_guardian_and_restores_timers(self):
        events, marker, pending = self.exercise()
        self.assertFalse(marker)
        self.assertFalse(pending)
        self.assertLess(events.index(("clear-marker",)), events.index(("worker",)))
        self.assertLess(events.index(("worker",)), events.index(("restore-timers",)))

    def test_incomplete_update_keeps_marker_and_never_runs_worker(self):
        events, marker, pending = self.exercise(incomplete=True)
        self.assertTrue(marker)
        self.assertTrue(pending)
        self.assertNotIn(("worker",), events)
        self.assertNotIn(("restore-timers",), events)


if __name__ == "__main__":
    unittest.main()
