#!/usr/bin/env python3
"""Disposable boundary tests; no host services, credentials or mailbox access."""

import importlib.util
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location("guardian_linux_" + name, ROOT / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


maintenance = module("maintenance")
installer = module("install")


class MigrationFenceTests(unittest.TestCase):
    def test_new_fence_is_exclusive_when_published_and_inode_is_stable(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            held = []
            try:
                with patch.object(installer, "reject_symlink"), patch.object(installer.os, "fchown"):
                    installer.install_migration_lock(root, os.getgid(), held)
                path = root / "migration.lock"
                self.assertEqual(len(held), 1)
                self.assertEqual(path.stat().st_nlink, 1)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
                with path.open("rb") as worker:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(worker, fcntl.LOCK_SH | fcntl.LOCK_NB)
                inode = path.stat().st_ino
                held.pop().close()
                with path.open("rb") as worker:
                    fcntl.flock(worker, fcntl.LOCK_SH | fcntl.LOCK_NB)
                self.assertEqual(path.stat().st_ino, inode)
            finally:
                for lock in held:
                    lock.close()

    def test_lock_interlocks_and_pending_fails_closed(self):
        # Exercise real flock while substituting the administrator UID in
        # metadata because this unit suite runs as an unprivileged Mac user.
        real_lstat, real_fstat = Path.lstat, os.fstat

        def admin_lstat(path):
            values = list(real_lstat(path))
            values[4] = 0
            return os.stat_result(values)

        def admin_fstat(fd):
            values = list(real_fstat(fd))
            values[4] = 0
            return os.stat_result(values)

        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / "pilot"
            root.mkdir(mode=0o750)
            lock_path = root / "migration.lock"
            lock_path.touch(mode=0o640)
            lock_path.chmod(0o640)
            with patch.object(maintenance, "INSTANCE_BASE", Path(scratch)), \
                 patch.object(maintenance, "trusted_path", side_effect=lambda path, **kwargs: Path(path)), \
                 patch.object(maintenance.grp, "getgrnam", return_value=types.SimpleNamespace(gr_gid=os.getgid())), \
                 patch.object(Path, "lstat", admin_lstat), patch.object(os, "fstat", admin_fstat):
                with maintenance.shared_migration_fence("pilot"):
                    with lock_path.open("rb") as admin:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(admin, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with lock_path.open("rb") as admin:
                    fcntl.flock(admin, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with self.assertRaises(maintenance.MaintenanceError):
                        with maintenance.shared_migration_fence("pilot"):
                            pass
                (root / "migration-pending").symlink_to("missing")
                with self.assertRaises(maintenance.MaintenanceError):
                    with maintenance.shared_migration_fence("pilot"):
                        pass
                (root / "migration-pending").unlink()
                lock_path.chmod(0o660)
                with self.assertRaises(maintenance.MaintenanceError):
                    with maintenance.shared_migration_fence("pilot"):
                        pass
                lock_path.unlink()
                with self.assertRaises(FileNotFoundError):
                    with maintenance.shared_migration_fence("pilot"):
                        pass


class PlatformTests(unittest.TestCase):
    def test_qualified_ubuntu_releases_on_amd64(self):
        for version in ("24.04", "26.04", "26.10"):
            with self.subTest(version=version):
                installer.validate_platform({"ID": "ubuntu", "VERSION_ID": version}, "x86_64")

    def test_other_releases_derivatives_and_architectures_fail_closed(self):
        cases = [
            ({"ID": "ubuntu", "VERSION_ID": version}, "x86_64")
            for version in ("22.04", "24.10", "27.04", "28.04", "26.04.1", "")
        ]
        cases += [
            ({"ID": distro, "ID_LIKE": "ubuntu", "VERSION_ID": "26.04"}, "x86_64")
            for distro in ("debian", "linuxmint", "Ubuntu", "")
        ]
        cases += [
            ({"ID": "ubuntu", "VERSION_ID": "26.04"}, machine)
            for machine in ("aarch64", "arm64", "i686", "AMD64", "")
        ]
        cases += [({}, "x86_64"), ({"ID": "ubuntu"}, "x86_64"),
                  ({"VERSION_ID": "26.04"}, "x86_64")]
        for release, machine in cases:
            with self.subTest(release=release, machine=machine), self.assertRaisesRegex(ValueError, "Ubuntu 24.04, 26.04 or 26.10 on amd64"):
                installer.validate_platform(release, machine)


class AuthorizationTests(unittest.TestCase):
    def test_only_fixed_ops_and_matching_worker(self):
        for operation in maintenance.OPERATIONS:
            self.assertEqual(maintenance.parse_request(["pilot", operation], 0, "mg-pilot"), ("pilot", operation))
        for args, uid, user in ((["../pilot", "up"], 0, "root"), (["pilot", "up", "--file=x"], 0, "root"),
                                (["pilot", "exec"], 0, "root"), (["pilot", "up"], 1000, "mg-pilot"),
                                (["pilot", "up"], 0, "mg-other"), (["pilot\n", "up"], 0, "root")):
            with self.subTest(args=args, uid=uid, user=user), self.assertRaises(maintenance.MaintenanceError):
                maintenance.parse_request(args, uid, user)

    def test_symlink_untrusted_owner_and_writable_parent_rejected(self):
        original = Path.lstat
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            safe = root / "config"
            safe.write_text("safe")
            safe.chmod(0o600)
            link = root / "link"
            link.symlink_to(safe)

            def admin_stat(path):
                info = original(path)
                values = list(info)
                values[4] = 0
                if path != root and root not in path.parents:
                    values[0] &= ~0o022
                return os.stat_result(values)

            with patch.object(Path, "lstat", admin_stat):
                self.assertEqual(maintenance.trusted_path(safe, private=True), safe)
                with self.assertRaises(maintenance.MaintenanceError):
                    maintenance.trusted_path(link)
                root.chmod(0o777)
                with self.assertRaises(maintenance.MaintenanceError):
                    maintenance.trusted_path(safe)
                root.chmod(0o700)
            # uid 0 is required regardless of mode.
            def wrong_owner(path):
                info = admin_stat(path)
                values = list(info)
                if path == safe:
                    values[4] = 1234
                return os.stat_result(values)
            with patch.object(Path, "lstat", wrong_owner), self.assertRaises(maintenance.MaintenanceError):
                maintenance.trusted_path(safe)


class DispatcherTests(unittest.TestCase):
    def dispatcher(self):
        value = object.__new__(maintenance.Dispatcher)
        value.instance = "pilot"
        return value

    def test_persistence_failures_and_sync_policy_fail_closed(self):
        value = self.dispatcher()
        info = b"aof_enabled:1\naof_last_write_status:ok\nrdb_last_bgsave_status:ok\n"
        with patch.object(value, "storage"), patch.object(value, "compose", side_effect=[info, b"appendfsync\nalways\n"]):
            value.persistence()
        for data, fsync in ((info.replace(b"status:ok", b"status:err"), b"appendfsync\nalways\n"),
                            (info, b"appendfsync\neverysec\n"), (b"", b"appendfsync\nalways\n")):
            with self.subTest(data=data, fsync=fsync), patch.object(value, "storage"), \
                 patch.object(value, "compose", side_effect=[data, fsync]), self.assertRaises(maintenance.MaintenanceError):
                value.persistence()

    def test_export_requires_persistence_before_streaming(self):
        value = self.dispatcher()
        with patch.object(value, "persistence", side_effect=maintenance.MaintenanceError("blocked")), patch.object(value, "compose") as compose:
            with self.assertRaises(maintenance.MaintenanceError):
                value.dispatch("export-redis")
            compose.assert_not_called()
        with patch.object(value, "persistence"), patch.object(value, "compose", return_value=b"raw-rdb") as compose:
            self.assertEqual(value.dispatch("export-redis"), b"raw-rdb")
            self.assertEqual(compose.call_args.kwargs["max_output"], 128 << 20)

    def test_container_status_requires_all_three_healthy_services(self):
        value = self.dispatcher()
        rows = [{"Service": name, "State": "running", "Health": "" if name == "rspamd" else "healthy"} for name in ("redis", "rspamd", "unbound")]
        for output in (json.dumps(rows).encode(), b"\n".join(json.dumps(row).encode() for row in rows)):
            with patch.object(value, "compose", return_value=output), patch.object(value, "ping"):
                self.assertEqual(value.dispatch("status"), output)
        for output in (b"[]", json.dumps(rows[:2]).encode(), b"garbage", json.dumps([dict(row, Health="starting") for row in rows]).encode()):
            with patch.object(value, "compose", return_value=output), patch.object(value, "ping") as ping:
                with self.assertRaises(maintenance.MaintenanceError):
                    value.dispatch("status")
                ping.assert_not_called()

    def test_process_limits_clean_env_and_no_raw_diagnostics(self):
        result = maintenance.run([sys.executable, "-c", "import os; print(os.environ.get('DOCKER_HOST', 'clean'))"])
        self.assertEqual(result, b"clean\n")
        with self.assertRaisesRegex(maintenance.MaintenanceError, "limit"):
            maintenance.run([sys.executable, "-c", "print('x'*10000)"], max_output=20)
        with self.assertRaisesRegex(maintenance.MaintenanceError, "timed out"):
            maintenance.run([sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.05)
        # A child that never consumes stdin must still observe the deadline.
        with self.assertRaisesRegex(maintenance.MaintenanceError, "timed out"):
            maintenance.run([sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.05, input_data=b"x" * 16384)
        with self.assertRaises(maintenance.MaintenanceError) as error:
            maintenance.run([sys.executable, "-c", "import sys; print('private-mail-content', file=sys.stderr); sys.exit(1)"])
        self.assertNotIn("private-mail-content", str(error.exception))

    def test_controller_password_is_stdin_only(self):
        with tempfile.TemporaryDirectory() as scratch:
            value = self.dispatcher()
            value.root = Path(scratch) / "config"
            value.runtime = Path(scratch) / "runtime"
            (value.root / "credentials").mkdir(parents=True)
            value.runtime.mkdir()
            password = b"disposable-password-never-an-argument"
            (value.root / "credentials/rspamd-password").write_bytes(password + b"\n")
            def accept(path, **kwargs):
                return Path(path)
            with patch.object(maintenance, "trusted_path", side_effect=accept), \
                 patch.object(value, "require_unmapped_docker"), \
                 patch.object(maintenance, "RSPAMD_GID", os.getgid()), \
                 patch.object(os, "fchown") as chown, \
                 patch.object(maintenance, "run", return_value=b"$2$abcdefghjkmnpqrstuvwxyz$abcdefghjkmnpqrstuvwxyz\n") as run:
                self.assertTrue(value.controller())
                target = value.runtime / "rspamd/worker-controller.inc"
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
                chown.assert_called_once()
                arguments = run.call_args.args[0]
                self.assertNotIn(password.decode(), " ".join(arguments))
                self.assertNotIn("--password", arguments)
                self.assertEqual(run.call_args.kwargs["input_data"], password + b"\n")
                self.assertIn("rspamadm.pw_encrypt", arguments[-1])
                run.reset_mock()
                self.assertFalse(value.controller())
                run.assert_not_called()
                target.chmod(0o600)  # legacy helper file cannot serve Rspamd
                self.assertTrue(value.controller())
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
                run.assert_called_once()
                run.reset_mock()
                with patch.object(maintenance, "RSPAMD_GID", os.getgid() + 1):
                    self.assertTrue(value.controller())  # an incorrect cached group cannot be reused
                    run.assert_called_once()

    def test_controller_rejects_unsafe_partial_runtime(self):
        with tempfile.TemporaryDirectory() as scratch:
            value = self.dispatcher()
            value.root = Path(scratch) / "config"
            value.runtime = Path(scratch) / "runtime"
            (value.root / "credentials").mkdir(parents=True)
            folder = value.runtime / "rspamd"
            folder.mkdir(parents=True, mode=0o700)
            (value.root / "credentials/rspamd-password").write_bytes(b"password\n")
            def check(path, **kwargs):
                path = Path(path)
                if path.is_symlink():
                    raise maintenance.MaintenanceError("symlink")
                return path
            for name in ("worker-controller.inc", ".credential-sha256"):
                with self.subTest(name=name):
                    link = folder / name
                    link.symlink_to(folder / "missing")
                    with patch.object(maintenance, "trusted_path", side_effect=check), \
                         patch.object(value, "require_unmapped_docker"), \
                         patch.object(maintenance, "run") as run, self.assertRaises(maintenance.MaintenanceError):
                        value.controller()
                    run.assert_not_called()
                    link.unlink()

    def test_controller_crash_between_file_and_fingerprint_then_password_revert(self):
        with tempfile.TemporaryDirectory() as scratch:
            value = self.dispatcher()
            value.root = Path(scratch) / "config"
            value.runtime = Path(scratch) / "runtime"
            (value.root / "credentials").mkdir(parents=True)
            value.runtime.mkdir()
            credential = value.root / "credentials/rspamd-password"
            target = value.runtime / "rspamd/worker-controller.inc"
            fingerprint = value.runtime / "rspamd/.credential-sha256"
            def accept(path, **kwargs):
                return Path(path)
            a = b"$2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA\n"
            b = b"$2$BBBBBBBBBBBBBBBBBBBBBB$BBBBBBBBBBBBBBBBBBBBBB\n"
            a_again = b"$2$CCCCCCCCCCCCCCCCCCCCCC$CCCCCCCCCCCCCCCCCCCCCC\n"
            replace = os.replace
            def fail_fingerprint(source, destination):
                if Path(destination) == fingerprint:
                    raise OSError("synthetic interruption")
                return replace(source, destination)
            with patch.object(maintenance, "trusted_path", side_effect=accept), \
                 patch.object(value, "require_unmapped_docker"), \
                 patch.object(maintenance, "RSPAMD_GID", os.getgid()), \
                 patch.object(os, "fchown"), \
                 patch.object(maintenance, "run", side_effect=[a, b, a_again]) as run:
                credential.write_bytes(b"password-A\n")
                self.assertTrue(value.controller())
                credential.write_bytes(b"password-B\n")
                with patch.object(os, "replace", side_effect=fail_fingerprint), self.assertRaises(OSError):
                    value.controller()
                self.assertIn(b.strip(), target.read_bytes())
                credential.write_bytes(b"password-A\n")
                self.assertTrue(value.controller())
                self.assertIn(a_again.strip(), target.read_bytes())
                self.assertEqual(run.call_count, 3)
                self.assertFalse(value.controller())

    def test_controller_rejects_docker_remapped_or_invalid_daemon_metadata(self):
        value = self.dispatcher()
        for response in (b'["name=userns"]', b'["name=rootless"]', b'{}', b'[1]', b'invalid'):
            with self.subTest(response=response), patch.object(maintenance, "run", return_value=response):
                with self.assertRaises(maintenance.MaintenanceError):
                    value.require_unmapped_docker()
        with patch.object(maintenance, "run", return_value=b'["name=apparmor", "name=seccomp,profile=default"]'):
            value.require_unmapped_docker()

    def test_ping_requires_pong(self):
        from unittest.mock import MagicMock
        value = self.dispatcher()
        for content, accepted in ((b"pong\r\n", True), (b"unrelated server", False), (b"", False)):
            response = MagicMock()
            response.__enter__.return_value = response
            response.status = 200
            response.read.return_value = content
            client = MagicMock()
            client.open.return_value = response
            with patch.object(maintenance.urllib.request, "build_opener", return_value=client):
                if accepted:
                    value.ping()
                    self.assertEqual(client.open.call_count, 2)
                else:
                    with self.assertRaises(maintenance.MaintenanceError):
                        value.ping()

    def test_storage_signatures_cover_linux_filesystems(self):
        for line in ("I/O error, dev vda", "EXT4-fs error (device vda)", "XFS (vda): Corruption detected", "BTRFS error (device vda): checksum mismatch"):
            self.assertTrue(maintenance.STORAGE_ERRORS.search(line))
        self.assertFalse(maintenance.STORAGE_ERRORS.search("ordinary firewall warning"))


class PackageIntegrityTests(unittest.TestCase):
    def test_manifest_rejects_tampering_and_path_escape(self):
        import hashlib
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "guardian").write_bytes(b"test")
            good = hashlib.sha256(b"test").hexdigest() + "  guardian\n"
            (root / "SHA256SUMS").write_text(good)
            self.assertEqual(installer.verify_package(root), {"guardian"})
            (root / "guardian").write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                installer.verify_package(root)
            (root / "SHA256SUMS").write_text(good.replace("guardian", "../guardian"))
            with self.assertRaises(ValueError):
                installer.verify_package(root)

    def test_manifest_rejects_unlisted_file_and_symlink(self):
        import hashlib
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "guardian").write_bytes(b"test")
            (root / "SHA256SUMS").write_text(hashlib.sha256(b"test").hexdigest() + "  guardian\n")
            (root / "credential").write_text("unexpected")
            with self.assertRaises(ValueError):
                installer.verify_package(root)
            (root / "credential").unlink()
            (root / "link").symlink_to(root / "guardian")
            with self.assertRaises(ValueError):
                installer.verify_package(root)


if __name__ == "__main__":
    unittest.main()
