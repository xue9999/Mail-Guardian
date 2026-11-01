#!/usr/bin/env python3
"""Pure fixture tests for inactive-pilot package update boundaries.

These tests never access a host service, mailbox, worker state or credentials.
"""

import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("guardian_pilot_update", Path(__file__).with_name("pilot_update.py"))
pilot_update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot_update)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def package(root, entries=None):
    entries = entries or {
        "VERSION": b"0.6.1\n",
        "guardian": b"old-worker",
        "maintenance.py": b"old-helper",
        "check_host.py": b"old-host-check",
        "deploy/compose.yaml": b"services: {}\n",
    }
    for name, content in entries.items():
        file = root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content)
    manifest = "".join(f"{digest(content)}  {name}\n" for name, content in sorted(entries.items())).encode()
    (root / "SHA256SUMS").write_bytes(manifest)
    return digest(manifest), {name: digest(content) for name, content in entries.items()}


class PackageValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "release"
        self.root.mkdir(mode=0o700)
        self.expected, self.entries = package(self.root)

    def test_valid_manifest_and_files(self):
        self.assertEqual(pilot_update.verify_package(self.root, self.expected), self.entries)

    def test_independent_manifest_digest_is_required(self):
        for expected in ("0" * 64, "not-a-digest", ""):
            with self.subTest(expected=expected), self.assertRaises((ValueError, OSError)):
                pilot_update.verify_package(self.root, expected)

    def test_corrupt_or_missing_file_and_unlisted_file_are_rejected(self):
        file = self.root / "maintenance.py"
        original = file.read_bytes()
        file.write_bytes(b"changed")
        with self.assertRaises((ValueError, OSError)):
            pilot_update.verify_package(self.root, self.expected)
        file.unlink()
        with self.assertRaises((ValueError, OSError)):
            pilot_update.verify_package(self.root, self.expected)
        file.write_bytes(original)
        (self.root / "unexpected").write_bytes(b"unlisted")
        with self.assertRaises((ValueError, OSError)):
            pilot_update.verify_package(self.root, self.expected)

    def test_symlink_is_rejected_even_if_its_contents_match(self):
        file = self.root / "maintenance.py"
        copy = Path(self.tmp.name) / "outside"
        copy.write_bytes(file.read_bytes())
        file.unlink()
        file.symlink_to(copy)
        with self.assertRaises((ValueError, OSError)):
            pilot_update.verify_package(self.root, self.expected)

    def test_parent_symlink_is_rejected(self):
        directory = self.root / "deploy"
        moved = Path(self.tmp.name) / "outside-deploy"
        directory.rename(moved)
        directory.symlink_to(moved, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            pilot_update.verify_package(self.root, self.expected)

    def test_duplicate_traversal_and_absolute_manifest_entries_are_rejected(self):
        manifest = self.root / "SHA256SUMS"
        original = manifest.read_bytes()
        for line in (original.splitlines()[0] + b"\n", b"0" * 64 + b"  ../outside\n", b"0" * 64 + b"  /etc/passwd\n"):
            with self.subTest(line=line):
                modified = original + line
                manifest.write_bytes(modified)
                with self.assertRaises((ValueError, OSError)):
                    pilot_update.verify_package(self.root, digest(modified))


class AllowedChangesTests(unittest.TestCase):
    def setUp(self):
        self.old = {"guardian": "a", "maintenance.py": "b", "check_host.py": "c", "deploy/compose.yaml": "d"}

    def test_helper_and_host_checker_change_is_allowed(self):
        candidate = dict(self.old, **{"maintenance.py": "updated", "check_host.py": "updated"})
        self.assertIsNone(pilot_update.validate_changes(self.old, candidate))

    def test_helper_alone_is_allowed(self):
        candidate = dict(self.old, **{"maintenance.py": "updated"})
        self.assertIsNone(pilot_update.validate_changes(self.old, candidate))

    def test_no_helper_change_or_worker_or_compose_change_is_rejected(self):
        candidates = [dict(self.old), dict(self.old, **{"check_host.py": "updated"}),
                      dict(self.old, **{"maintenance.py": "updated", "guardian": "changed"}),
                      dict(self.old, **{"maintenance.py": "updated", "deploy/compose.yaml": "changed"})]
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                pilot_update.validate_changes(self.old, candidate)

    def test_added_or_removed_paths_are_rejected(self):
        added = dict(self.old, **{"maintenance.py": "updated", "extra": "x"})
        missing = dict(self.old, **{"maintenance.py": "updated"})
        del missing["guardian"]
        for candidate in (added, missing):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                pilot_update.validate_changes(self.old, candidate)


class UpdateTransactionTests(unittest.TestCase):
    """Exercise release switching in a temporary tree, with host checks mocked."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.base = self.root / "opt"
        self.releases = self.base / "releases"
        self.releases.mkdir(parents=True)
        self.conf = self.root / "etc"
        self.conf.mkdir()
        self.libexec = self.root / "libexec"
        self.libexec.mkdir()
        self.helper = self.libexec / "mail-guardian-maintenance"
        self.old_root = self.releases / "0.6.1"
        self.old_root.mkdir()
        self.old_sha, self.old = package(self.old_root)
        self.helper.write_bytes((self.old_root / "maintenance.py").read_bytes())
        (self.base / "current").symlink_to(self.old_root)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        self.new_sha, self.new = package(self.candidate, {
            "VERSION": b"0.6.1\n",
            "guardian": b"old-worker",
            "maintenance.py": b"fixed-helper",
            "check_host.py": b"fixed-host-check",
            "deploy/compose.yaml": b"services: {}\n",
        })
        real_fstat = os.fstat
        def admin_fstat(fd):
            values = list(real_fstat(fd))
            values[4] = 0
            return os.stat_result(values)
        mocks = [
            patch.object(pilot_update, "BASE", self.base),
            patch.object(pilot_update, "CONF", self.conf),
            patch.object(pilot_update, "HELPER", self.helper),
            patch.object(pilot_update, "RUNLOCK", self.root / "maintenance.lock"),
            patch.object(pilot_update, "MARKER", self.conf / "pilot-update-pending"),
            patch.object(pilot_update, "trusted"),
            patch.object(pilot_update, "guard"),
            patch.object(pilot_update, "command", return_value=""),
            patch.object(pilot_update, "sync_dir"),
            patch.object(pilot_update.os, "geteuid", return_value=0),
            patch.object(pilot_update.os, "chown"),
            patch.object(pilot_update.os, "fchown"),
            patch.object(pilot_update.os, "fstat", side_effect=admin_fstat),
        ]
        for mocker in mocks:
            mocker.start()
            self.addCleanup(mocker.stop)

    def perform(self, check=False):
        pilot_update.update(self.candidate, self.old_sha, self.new_sha, check=check)

    def test_update_preserves_old_release_and_switches_only_reviewed_helper(self):
        self.perform()
        target = (self.base / "current").readlink()
        self.assertNotEqual(target, self.old_root)
        self.assertTrue(target.is_dir())
        self.assertEqual(pilot_update.verify_package(target, self.new_sha), self.new)
        self.assertEqual(pilot_update.verify_package(self.old_root, self.old_sha), self.old)
        self.assertEqual(self.helper.read_bytes(), b"fixed-helper")
        self.assertFalse((self.conf / "pilot-update-pending").exists())
        self.assertEqual(pilot_update.guard.call_count, 3)
        self.assertEqual(pilot_update.command.call_count, 2)

    def test_switch_failure_restores_old_helper_and_retains_pending_marker(self):
        original = pilot_update.replace_current
        calls = 0
        def fail_first(target):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("synthetic interrupted switch")
            return original(target)
        with patch.object(pilot_update, "replace_current", side_effect=fail_first):
            with self.assertRaisesRegex(OSError, "synthetic"):
                self.perform()
        self.assertEqual((self.base / "current").readlink(), self.old_root)
        self.assertEqual(self.helper.read_bytes(), b"old-helper")
        self.assertTrue((self.conf / "pilot-update-pending").is_file())
        with self.assertRaisesRegex(ValueError, "previous update"):
            self.perform()

    def test_preflight_failure_leaves_active_release_and_helper_untouched(self):
        pilot_update.command.side_effect = ValueError("synthetic host failure")
        with self.assertRaisesRegex(ValueError, "synthetic"):
            self.perform()
        self.assertEqual((self.base / "current").readlink(), self.old_root)
        self.assertEqual(self.helper.read_bytes(), b"old-helper")
        self.assertFalse((self.conf / "pilot-update-pending").exists())

    def test_check_mode_does_not_stage_or_switch(self):
        self.perform(check=True)
        self.assertEqual(list(self.releases.iterdir()), [self.old_root])
        self.assertEqual((self.base / "current").readlink(), self.old_root)
        self.assertEqual(self.helper.read_bytes(), b"old-helper")
        self.assertFalse((self.conf / "pilot-update-pending").exists())

    def test_post_stage_guard_failure_keeps_marker_and_restores_old(self):
        pilot_update.guard.side_effect = [None, ValueError("pilot changed during staging")]
        with self.assertRaisesRegex(ValueError, "during staging"):
            self.perform()
        self.assertEqual((self.base / "current").readlink(), self.old_root)
        self.assertEqual(self.helper.read_bytes(), b"old-helper")
        self.assertTrue((self.conf / "pilot-update-pending").is_file())

    def test_post_switch_host_failure_rolls_back_and_blocks_retry(self):
        pilot_update.command.side_effect = ["", ValueError("synthetic post-switch failure")]
        with self.assertRaisesRegex(ValueError, "post-switch"):
            self.perform()
        self.assertEqual((self.base / "current").readlink(), self.old_root)
        self.assertEqual(self.helper.read_bytes(), b"old-helper")
        self.assertTrue((self.conf / "pilot-update-pending").is_file())

    def test_guard_failure_or_existing_marker_prevents_changes(self):
        pilot_update.guard.side_effect = ValueError("configured pilot")
        with self.assertRaisesRegex(ValueError, "configured pilot"):
            self.perform()
        self.assertEqual((self.base / "current").readlink(), self.old_root)
        self.assertEqual(self.helper.read_bytes(), b"old-helper")
        self.assertEqual(list(self.releases.iterdir()), [self.old_root])
        pilot_update.guard.reset_mock(side_effect=True)
        (self.conf / "pilot-update-pending").write_text("existing")
        with self.assertRaisesRegex(ValueError, "previous update"):
            self.perform()
        pilot_update.guard.assert_not_called()
        self.assertEqual((self.base / "current").readlink(), self.old_root)

    def test_changed_candidate_worker_is_rejected_before_host_checks(self):
        (self.candidate / "guardian").write_bytes(b"different-worker")
        with self.assertRaises(ValueError):
            self.perform()
        pilot_update.guard.assert_not_called()
        self.assertEqual((self.base / "current").readlink(), self.old_root)
        self.assertEqual(self.helper.read_bytes(), b"old-helper")


class HostGuardTests(unittest.TestCase):
    """Check fail-closed decisions using synthetic filesystem and command state."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.base = root / "opt"
        self.old = self.base / "releases" / "0.6.1"
        self.old.mkdir(parents=True)
        (self.base / "current").symlink_to(self.old)
        self.conf = root / "etc"
        self.pilot = self.conf / "pilot"
        (self.pilot / "credentials").mkdir(parents=True)
        (self.pilot / "deploy").mkdir()
        (self.conf / "instance").write_text("pilot\n")
        self.data = root / "worker-data"
        self.data.mkdir(mode=0o700)
        self.runtime = root / "run"
        self.runtime.mkdir()
        self.helper = root / "helper"
        self.helper.write_bytes(b"old-helper")
        self.sudoers = root / "sudoers"
        self.sudoers.write_text('Defaults:mg-pilot env_reset\nmg-pilot ALL=(root) NOPASSWD: ' +
            ', '.join('/usr/local/libexec/mail-guardian-maintenance pilot ' + op for op in
                      ('up', 'down', 'status', 'deep-check', 'check-storage', 'check-persistence', 'export-redis')) + '\n')
        self.sudoers.chmod(0o440)
        self.units = root / "units"
        self.units.mkdir()
        entries = {"maintenance.py": digest(b"old-helper"), "deploy/compose.yaml": digest(b"compose")}
        for unit in ("mail-guardian@.service", "mail-guardian@.timer"):
            (self.units / unit).write_bytes(unit.encode())
            entries[unit] = digest(unit.encode())
        self.entries = entries
        self.state = {"active": "inactive", "enabled": "disabled", "container": "", "volume": "", "network": ""}
        real_path = Path
        def mapped_path(value):
            if value == "/var/lib/mail-guardian/pilot":
                return self.data
            if value == "/etc/systemd/system":
                return self.units
            if value == "/etc/sudoers.d/mail-guardian":
                return self.sudoers
            return real_path(value)
        original_lstat = type(self.base).lstat
        def lstat_as_admin(path):
            value = original_lstat(path)
            if path == self.base / 'current':
                fields = list(value)
                fields[4] = 0
                return os.stat_result(fields)
            return value
        def command(args, expected=0):
            if "is-active" in args:
                return self.state["active"]
            if "is-enabled" in args:
                return self.state["enabled"]
            if "ps" in args:
                return self.state["container"]
            if "volume" in args:
                return self.state["volume"]
            if "network" in args:
                return self.state["network"]
            return ""
        patches = [
            patch.object(pilot_update, "BASE", self.base),
            patch.object(pilot_update, "CONF", self.conf),
            patch.object(pilot_update, "RUNTIME", self.runtime),
            patch.object(pilot_update, "HELPER", self.helper),
            patch.object(pilot_update, "Path", side_effect=mapped_path),
            patch.object(pilot_update, "trusted"),
            patch.object(pilot_update, "tree_digests", return_value={"compose.yaml": digest(b"compose")}),
            patch.object(pilot_update, "command", side_effect=command),
            patch.object(pilot_update.pwd, "getpwnam", return_value=types.SimpleNamespace(
                pw_uid=os.getuid(), pw_gid=9876, pw_shell='/usr/sbin/nologin', pw_dir=str(self.data))),
            patch.object(pilot_update.grp, "getgrgid", return_value=types.SimpleNamespace(gr_name='mg-pilot')),
            patch.object(pilot_update.grp, "getgrall", return_value=[]),
            patch.object(type(self.base), 'lstat', lstat_as_admin),
            patch.object(pilot_update.subprocess, "run", return_value=types.SimpleNamespace(returncode=1)),
        ]
        for mocker in patches:
            mocker.start()
            self.addCleanup(mocker.stop)

    def guard(self):
        pilot_update.guard(self.old, self.entries)

    def test_untouched_empty_inactive_pilot_is_accepted(self):
        self.assertIsNone(self.guard())

    def test_configuration_credential_or_runtime_prevents_update(self):
        for target in (self.pilot / "config.toml", self.pilot / "credentials" / "imap-password", self.runtime / "pilot"):
            with self.subTest(target=target):
                target.write_bytes(b"present")
                with self.assertRaises(ValueError):
                    self.guard()
                target.unlink()

    def test_running_or_enabled_state_prevents_update(self):
        for key, value in (("active", "active"), ("enabled", "enabled")):
            with self.subTest(key=key):
                previous = self.state[key]
                self.state[key] = value
                with self.assertRaises(ValueError):
                    self.guard()
                self.state[key] = previous

    def test_any_project_container_volume_or_network_prevents_update(self):
        for key in ("container", "volume", "network"):
            with self.subTest(key=key):
                self.state[key] = "synthetic-resource-id"
                with self.assertRaises(ValueError):
                    self.guard()
                self.state[key] = ""

    def test_unexpected_worker_process_prevents_update(self):
        pilot_update.subprocess.run.return_value.returncode = 0
        with self.assertRaises(ValueError):
            self.guard()

    def test_worker_and_sudo_policy_changes_prevent_update(self):
        worker = pilot_update.pwd.getpwnam.return_value
        for attr, value in (("pw_shell", "/bin/bash"), ("pw_uid", 0), ("pw_dir", "/tmp")):
            with self.subTest(attr=attr):
                old = getattr(worker, attr)
                setattr(worker, attr, value)
                with self.assertRaises(ValueError):
                    self.guard()
                setattr(worker, attr, old)
        pilot_update.grp.getgrall.return_value = [types.SimpleNamespace(gr_gid=100, gr_mem=['mg-pilot'])]
        with self.assertRaises(ValueError):
            self.guard()
        pilot_update.grp.getgrall.return_value = []
        self.sudoers.chmod(0o644)
        with self.assertRaises(ValueError):
            self.guard()
        self.sudoers.chmod(0o640)
        self.sudoers.write_text('unsafe')
        self.sudoers.chmod(0o440)
        with self.assertRaises(ValueError):
            self.guard()

    def test_helper_unit_or_deploy_modification_prevents_update(self):
        self.helper.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.guard()
        self.helper.write_bytes(b"old-helper")
        (self.units / "mail-guardian@.service").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.guard()
        (self.units / "mail-guardian@.service").write_bytes(b"mail-guardian@.service")
        pilot_update.tree_digests.return_value = {"compose.yaml": digest(b"changed")}
        with self.assertRaises(ValueError):
            self.guard()


if __name__ == "__main__":
    unittest.main()
