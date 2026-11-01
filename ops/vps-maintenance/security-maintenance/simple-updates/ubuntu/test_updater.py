import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace as NS
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("ubuntu_updater_under_test", Path(__file__).with_name("updater.py"))
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)


def version(value, origin="Ubuntu", archive="resolute-updates", trusted=True, multi=""):
    return NS(version=value, architecture="amd64", record={"Multi-Arch": multi},
              origins=[NS(origin=origin, archive=archive, trusted=trusted, component="main")])


class PackageSelectionTests(unittest.TestCase):
    def test_stable_updates_include_major_and_ubuntu_snapshot_versions(self):
        cache = {"app": NS(candidate=version("2.0~rc1-0ubuntu1")),
                 "docker-ce": NS(candidate=version("100", origin="Docker"))}
        result = u.candidates({"app": "1", "docker-ce": "1"}, "resolute", cache,
                              compare=lambda a, b: 1, holds=set())
        self.assertEqual(result, {"app": "2.0~rc1-0ubuntu1"})

    def test_unknown_and_unsigned_and_other_release_origins_fail(self):
        for kwargs in ({"origin": "PPA"}, {"trusted": False}, {"archive": "stonking"},
                       {"archive": "resolute-proposed"}, {"archive": "resolute-backports"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(u.e.UpdateError):
                u.candidates({"app": "1"}, "resolute", {"app": NS(candidate=version("2", **kwargs))},
                             compare=lambda a, b: 1, holds=set())

    def test_hold_requires_explicit_review(self):
        with self.assertRaisesRegex(u.e.UpdateError, "held"):
            u.candidates({"app": "1"}, "resolute", {"app": NS(candidate=version("2"))},
                         compare=lambda a, b: 1, holds={"app"})

    def test_new_kernel_abi_dependency_is_allowed(self):
        cache = {"linux-virtual": NS(candidate=version("2")),
                 "linux-image-7.0.0-43-generic": NS(candidate=version("2"))}
        output = "Inst linux-virtual [1] (2 Ubuntu:26.04/resolute-updates [amd64])\nInst linux-image-7.0.0-43-generic (2 Ubuntu:26.04/resolute-updates [amd64])"
        self.assertEqual(u.parse_plan(output, {"linux-virtual": "2"}, {"linux-virtual": "1"},
                                     "resolute", cache, set()),
                         {"linux-virtual": "2", "linux-image-7.0.0-43-generic": "2"})

    def test_plan_removals_and_untrusted_new_dependencies_fail(self):
        with self.assertRaisesRegex(u.e.UpdateError, "removals"):
            u.parse_plan("Remv obsolete [1]", {}, {}, "resolute", {}, set())
        with self.assertRaisesRegex(u.e.UpdateError, "untrusted"):
            u.parse_plan("Inst bad (2 vendor [amd64])", {}, {}, "resolute",
                         {"bad": NS(candidate=version("2", origin="vendor"))}, set())

    def test_multiarch_plan_matches_dpkg_inventory_and_new_dependency(self):
        cache = {"liba": NS(candidate=version("2", multi="same")),
                 "libb": NS(candidate=version("2", multi="same"))}
        result = u.parse_plan("Inst liba [1] (2 Ubuntu [amd64])\nInst libb (2 Ubuntu [amd64])",
                              {"liba:amd64": "2"}, {"liba:amd64": "1"}, "resolute", cache, set())
        self.assertEqual(result, {"liba:amd64": "2", "libb:amd64": "2"})


class ActivationTests(unittest.TestCase):
    def test_packaged_needrestart_exclusions_match_checked_bytes(self):
        self.assertEqual(Path(__file__).with_name("99-vps-guardian-updates.conf").read_bytes(),
                         u.NEEDRESTART_CONFIG_BYTES)
        self.assertEqual(u.e.ENV["NEEDRESTART_SUSPEND"],"1")

    def test_missing_needrestart_exclusion_config_requires_fallback(self):
        with tempfile.TemporaryDirectory() as root, patch.object(u,"NEEDRESTART_CONFIG",Path(root)/"absent"):
            self.assertFalse(u.needrestart_configured())

    def test_actual_boot_vmlinuz_link_layout_and_root_fallback(self):
        with tempfile.TemporaryDirectory() as root:
            boot=Path(root)/"boot"
            boot.mkdir()
            kernel=boot/"vmlinuz-7.0.0-42-generic"
            kernel.write_bytes(b"kernel")
            link=boot/"vmlinuz"
            link.symlink_to(kernel.name)
            original=Path.lstat
            def stat_as_root(p,*args,**kwargs):
                value=original(p,*args,**kwargs)
                return NS(st_uid=0,st_mode=value.st_mode)
            with patch.object(Path,"lstat",stat_as_root):
                self.assertEqual(u.expected_kernel(boot,Path(root)/"vmlinuz"),"7.0.0-42-generic")
                link.unlink()
                fallback=Path(root)/"vmlinuz"
                fallback.symlink_to(kernel)
                self.assertEqual(u.expected_kernel(boot,fallback),"7.0.0-42-generic")

    def test_needrestart_requires_complete_kernel_and_no_stale_services(self):
        self.assertTrue(u.needrestart_clean("NEEDRESTART-KSTA: 1\nNEEDRESTART-UCSTA: 1\n"))
        for raw in ("", "NEEDRESTART-KSTA: 3\n", "NEEDRESTART-KSTA: 1\nNEEDRESTART-SVC: ssh.service",
                    "NEEDRESTART-KSTA: 1\nNEEDRESTART-UCSTA: 2"):
            self.assertFalse(u.needrestart_clean(raw))

    def test_reboot_intent_is_durable_before_request_and_failure_retains_it(self):
        state = {"phase": "activation_pending", "expected_kernel": "7.0-test"}
        order = []
        def save(value):
            order.append(("journal", value["phase"]))
        def reboot(*args, **kwargs):
            order.append(("command", args[0]))
            raise u.e.UpdateError("reboot unavailable")
        with patch.object(u.d, "write_state", side_effect=save), patch.object(u.e, "run", side_effect=reboot):
            with self.assertRaises(u.e.UpdateError):
                u.request_reboot(state)
        self.assertEqual(order[0], ("journal", "reboot_requested"))
        self.assertEqual(state["phase"], "reboot_requested")


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pending = Path(self.tmp.name) / "pending.json"
        self.marker = Path(self.tmp.name) / "marker"
        self.state = {"phase": "reboot_requested", "transaction": "ubuntu-" + "a" * 32,
                      "timers": list(u.TIMERS), "inventory": {"base": "1"}, "plan": {"base": "2"},
                      "containers": {"redis": [], "rspamd": [], "unbound": []},
                      "boot_id": "old", "expected_kernel": "7.0-test", "rehearsal": False}
        self.pending.write_text("pending")
        self.marker.write_bytes(u.marker_payload(self.state))
        self.patches = [patch.object(u, "PENDING", self.pending), patch.object(u.e, "MARKER", self.marker),
                        patch.object(u, "read_pending", side_effect=lambda: dict(self.state)),
                        patch.object(u, "verify_inventory"), patch.object(u.d, "unit_file_states", return_value=["masked"] * 2),
                        patch.object(u.e, "unit_state", return_value="inactive"), patch.object(u.d, "wait_inactive"),
                        patch.object(u.d, "settle_backup"), patch.object(u.e, "acquire_fence", side_effect=lambda: os.open(os.devnull, os.O_RDONLY)),
                        patch.object(u.e, "acquire_frontend_lock", side_effect=lambda: os.open(os.devnull, os.O_RDONLY)),
                        patch.object(u.e, "assert_frontend_lock_held"),
                        patch.object(u.e, "unit_busy", return_value=False), patch.object(u.e, "marker_identity", return_value=(1, 2)),
                        patch.object(u, "boot_id", return_value="new"), patch.object(u.os, "uname", return_value=NS(release="7.0-test")),
                        patch.object(u, "expected_kernel", return_value="7.0-test"), patch.object(u, "REBOOT_REQUIRED", Path(self.tmp.name)/"reboot-required"),
                        patch.object(u.e, "health"), patch.object(u.d, "check_ssh_local"), patch.object(u.d, "write_state"),
                        patch.object(u.e, "clear_own_marker"), patch.object(u.d, "run_worker"), patch.object(u.d, "restore_timers"),
                        patch.object(u.e, "sync_directory")]
        for p in self.patches: p.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(self.patches)])
        self.addCleanup(self.tmp.cleanup)

    def test_same_boot_reissues_request_and_never_unfences(self):
        with patch.object(u, "boot_id", return_value="old"), patch.object(u, "request_reboot") as request:
            u.recover_locked()
        request.assert_called_once()
        u.e.clear_own_marker.assert_not_called()
        u.d.run_worker.assert_not_called()
        self.assertTrue(self.pending.exists())

    def test_new_boot_wrong_kernel_stays_fenced(self):
        with patch.object(u.os, "uname", return_value=NS(release="wrong")):
            with self.assertRaisesRegex(u.e.UpdateError, "kernel"):
                u.recover_locked()
        u.e.clear_own_marker.assert_not_called()
        self.assertTrue(self.pending.exists())

    def test_missing_marker_stays_fenced(self):
        self.marker.unlink()
        with self.assertRaisesRegex(u.e.UpdateError, "marker is missing"):
            u.recover_locked()
        u.d.run_worker.assert_not_called()

    def test_foreign_marker_stays_fenced(self):
        u.e.marker_identity.side_effect = u.e.UpdateError("marker changed")
        with self.assertRaisesRegex(u.e.UpdateError, "marker changed"):
            u.recover_locked()
        u.e.clear_own_marker.assert_not_called()

    def test_complete_boot_runs_worker_before_restoring_timers(self):
        order=[]
        u.d.run_worker.side_effect=lambda:order.append("worker")
        u.d.restore_timers.side_effect=lambda:order.append("timers")
        u.recover_locked()
        self.assertEqual(order,["worker","timers"])
        self.assertFalse(self.pending.exists())
        u.e.assert_frontend_lock_held.assert_called_once()

    def test_package_manager_lock_failure_retains_fence(self):
        u.e.acquire_frontend_lock.side_effect=u.e.UpdateError("dpkg frontend busy")
        with self.assertRaisesRegex(u.e.UpdateError,"frontend busy"):
            u.recover_locked()
        u.e.clear_own_marker.assert_not_called()
        u.d.run_worker.assert_not_called()
        self.assertTrue(self.pending.exists())

    def test_failed_actual_run_keeps_journal_and_masks_for_retry(self):
        u.d.run_worker.side_effect=u.e.UpdateError("IMAP unavailable")
        with self.assertRaisesRegex(u.e.UpdateError,"IMAP"):
            u.recover_locked()
        u.d.restore_timers.assert_not_called()
        self.assertTrue(self.pending.exists())

    def test_crash_before_marker_mutation_recovers_current_state(self):
        self.state["phase"]="backup"
        self.marker.unlink()
        u.recover_locked()
        self.assertFalse(u.verify_inventory.call_args.args[1])
        u.d.run_worker.assert_called_once()

    def test_crash_after_publication_before_mutation_recovers_owned_marker(self):
        self.state["phase"]="publishing_marker"
        u.recover_locked()
        self.assertFalse(u.verify_inventory.call_args.args[1])
        u.e.clear_own_marker.assert_called_once()

    def test_interrupted_rehearsal_still_requires_boot(self):
        self.state.update(phase="mutation_pending",rehearsal=True)
        with patch.object(u,"boot_id",return_value="old"), patch.object(u,"request_reboot") as request:
            u.recover_locked()
        request.assert_called_once()
        u.d.run_worker.assert_not_called()


class InventoryTests(unittest.TestCase):
    def test_partial_update_or_unexpected_package_removal_fails(self):
        state={"inventory":{"base":"1","keep":"1"},"plan":{"base":"2"}}
        with patch.object(u.e,"run",return_value=NS(stdout="")), patch.object(u.e,"installed_inventory",return_value={"base":"2"}):
            with self.assertRaisesRegex(u.e.UpdateError,"incomplete/changed"):
                u.verify_inventory(state,True)


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        root=Path(self.tmp.name)
        self.pending=root/"pending.json"
        self.marker=root/"marker"
        self.foreign=root/"app-pending.json"
        self.saved=[]
        self.patches=[patch.object(u.os,"geteuid",return_value=0),
                      patch.object(u.d,"acquire_global",side_effect=lambda:os.open(os.devnull,os.O_RDONLY)),
                      patch.object(u.d,"ensure_state"),patch.object(u,"PENDING",self.pending),
                      patch.object(u.e,"MARKER",self.marker),patch.object(u,"OTHER_PENDING",(self.foreign,)),
                      patch.object(u.e,"run",return_value=NS(stdout="",returncode=0)),
                      patch.object(u.e,"installed_inventory",return_value={"base":"1"}),
                      patch.object(u,"codename",return_value="resolute"),patch.object(u,"candidates",return_value={}),
                      patch.object(u,"apt_plan",return_value={}),patch.object(u,"expected_kernel",return_value="test-kernel"),
                      patch.object(u.os,"uname",return_value=NS(release="test-kernel")),
                      patch.object(u,"REBOOT_REQUIRED",root/"reboot-required"),
                      patch.object(u.d,"unit_file_states",return_value=["enabled"]*2),
                      patch.object(u.e,"unit_active",return_value=True),
                      patch.object(u.e,"container_snapshot",return_value={"redis":[],"rspamd":[],"unbound":[]}),
                      patch.object(u.e,"health"),patch.object(u,"boot_id",return_value="old"),
                      patch.object(u.d,"write_state",side_effect=lambda state:self.saved.append(dict(state))),
                      patch.object(u.d,"wait_inactive"),patch.object(u.d,"settle_backup"),
                      patch.object(u.d,"properties",return_value={"InvocationID":"prior-run"}),
                      patch.object(u.d,"worker_snapshot",return_value={"actual":{"id":1}}),
                      patch.object(u.d,"fresh_backup"),patch.object(u,"recover_locked"),
                      patch.object(u,"request_reboot")]
        for p in self.patches:p.start()
        self.addCleanup(lambda:[p.stop() for p in reversed(self.patches)])
        self.addCleanup(self.tmp.cleanup)

    def test_no_update_does_not_backup_restart_or_reboot(self):
        u.execute()
        u.d.fresh_backup.assert_not_called()
        u.request_reboot.assert_not_called()
        self.assertFalse(self.saved)

    def test_check_cannot_recover_existing_journal(self):
        self.pending.write_text("pending")
        with self.assertRaisesRegex(u.e.UpdateError,"inspection"):
            u.execute(check=True)
        u.recover_locked.assert_not_called()
        u.e.run.assert_not_called()

    def test_app_transaction_before_marker_blocks_ubuntu_mutation(self):
        self.foreign.write_text("pending-app")
        with self.assertRaisesRegex(u.e.UpdateError,"application update is pending"):
            u.execute()
        u.e.run.assert_not_called()
        self.assertFalse(self.saved)

    def test_metadata_refresh_treats_partial_repo_failure_as_error(self):
        u.execute(check=True)
        self.assertEqual(u.e.run.call_args_list[0].args[0],
                         ["apt-get","-o","APT::Update::Error-Mode=any","update"])

    def test_rehearsal_refuses_real_package_candidates(self):
        u.candidates.return_value={"base":"2"}
        u.apt_plan.return_value={"base":"2"}
        with self.assertRaisesRegex(u.e.UpdateError,"rehearsal refuses"):
            u.execute(rehearse=True)
        u.d.fresh_backup.assert_not_called()
        self.assertFalse(self.saved)

    def test_failed_backup_preserves_durable_pre_mutation_intent(self):
        u.d.unit_file_states.side_effect=[["enabled"]*2,["masked"]*2]
        u.d.fresh_backup.side_effect=u.e.UpdateError("backup failed")
        with self.assertRaisesRegex(u.e.UpdateError,"backup failed"):
            u.execute(rehearse=True)
        self.assertEqual(self.saved[0]["phase"],"masking_timers")
        self.assertFalse(self.marker.exists())
        u.request_reboot.assert_not_called()


if __name__ == "__main__":
    unittest.main()
