"""Persistent controller bind-state fixtures; no host Docker or service actions.

Only administrator ownership is virtualized for an unprivileged Mac test run.
Filesystem object types, permissions, path rejection and cache writes stay real.
"""

import contextlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('guardian_persistent_runtime', Path(__file__).with_name('maintenance.py'))
maintenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(maintenance)


@contextlib.contextmanager
def administrator_metadata(*, wrong_owner=None):
    original = Path.lstat

    def lstat(path):
        result = list(original(path))
        result[4] = 12345 if Path(path) == wrong_owner else 0
        return os.stat_result(result)

    with patch.object(Path, 'lstat', side_effect=lstat, autospec=True):
        yield


class PersistentRuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.base = self.root / 'admin-state'

    def test_persistent_base_and_instance_are_private_under_open_umask(self):
        self.assertEqual(maintenance.ADMIN_RUNTIME_BASE, Path('/var/lib/mail-guardian-admin'))
        previous = os.umask(0o002)
        try:
            with patch.object(maintenance, 'ADMIN_RUNTIME_BASE', self.base), administrator_metadata():
                runtime = maintenance.private_runtime('pilot')
                self.assertEqual(runtime, self.base / 'pilot')
                for directory in (self.base, runtime):
                    self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                inode = runtime.stat().st_ino
                retained = runtime / 'retained-controller-fixture'
                retained.write_bytes(b'generated hash fixture')
                retained.chmod(0o600)
                self.assertEqual(maintenance.private_runtime('pilot').stat().st_ino, inode)
                self.assertEqual(retained.read_bytes(), b'generated hash fixture')
        finally:
            os.umask(previous)

    def test_existing_unsafe_directory_or_symlink_is_rejected_without_repair(self):
        for kind in ('public-base', 'public-instance', 'symlink-base', 'symlink-instance', 'wrong-owner'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=self.root) as scratch:
                parent = Path(scratch)
                parent.chmod(0o700)
                base = parent / 'state'
                runtime = base / 'pilot'
                if kind == 'symlink-base':
                    destination = parent / 'retained'
                    destination.mkdir(mode=0o700)
                    base.symlink_to(destination)
                else:
                    base.mkdir(mode=0o700)
                    if kind == 'public-base':
                        base.chmod(0o750)
                    elif kind == 'symlink-instance':
                        destination = parent / 'retained'
                        destination.mkdir(mode=0o700)
                        runtime.symlink_to(destination)
                    else:
                        runtime.mkdir(mode=0o700)
                        if kind == 'public-instance':
                            runtime.chmod(0o750)
                wrong = base if kind == 'wrong-owner' else None
                with patch.object(maintenance, 'ADMIN_RUNTIME_BASE', base), administrator_metadata(wrong_owner=wrong):
                    with self.assertRaises(maintenance.MaintenanceError):
                        maintenance.private_runtime('pilot')
                if kind == 'public-base':
                    self.assertEqual(stat.S_IMODE(base.stat().st_mode), 0o750)
                    self.assertFalse(runtime.exists())
                elif kind == 'public-instance':
                    self.assertEqual(stat.S_IMODE(runtime.stat().st_mode), 0o750)
                elif kind == 'symlink-base':
                    self.assertTrue(base.is_symlink())
                    self.assertEqual(list(destination.iterdir()), [])
                elif kind == 'symlink-instance':
                    self.assertTrue(runtime.is_symlink())
                    self.assertEqual(list(destination.iterdir()), [])

    def test_invalid_instance_does_not_create_the_persistent_base(self):
        with patch.object(maintenance, 'ADMIN_RUNTIME_BASE', self.base):
            for instance in ('', '../escape', '-pilot', 'pilot/subdir', 'pilot;id'):
                with self.subTest(instance=instance), self.assertRaises(maintenance.MaintenanceError):
                    maintenance.private_runtime(instance)
            self.assertFalse(self.base.exists())

    def test_controller_hash_and_fingerprint_remain_private_and_reusable(self):
        config = self.root / 'config'
        credentials = config / 'credentials'
        config.mkdir(mode=0o700)
        credentials.mkdir(mode=0o700)
        (credentials / 'rspamd-password').write_bytes(b'synthetic credential only\n')
        (credentials / 'rspamd-password').chmod(0o600)
        previous = os.umask(0o002)
        try:
            with patch.object(maintenance, 'ADMIN_RUNTIME_BASE', self.base), administrator_metadata(), \
                    patch.object(maintenance, 'RSPAMD_GID', os.getegid()), patch.object(os, 'fchown') as chown, \
                    patch.object(maintenance, 'run', return_value=b'$2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA\n') as run:
                value = maintenance.Dispatcher.__new__(maintenance.Dispatcher)
                value.root = config
                value.runtime = maintenance.private_runtime('pilot')
                with patch.object(value, 'require_unmapped_docker'):
                    self.assertTrue(value.controller())
                    target = value.runtime / 'rspamd/worker-controller.inc'
                    fingerprint = value.runtime / 'rspamd/.credential-sha256'
                    self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
                    self.assertEqual(stat.S_IMODE(fingerprint.stat().st_mode), 0o600)
                    self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o700)
                    chown.assert_called_once()
                    self.assertEqual(chown.call_args.args[1:], (0, os.getegid()))
                    generated, proof = target.read_bytes(), fingerprint.read_bytes()
                    self.assertNotIn(b'synthetic credential only', generated)
                    run.reset_mock()
                    # Reconstruct the helper on the persistent path: the
                    # exact generated hash and its bound fingerprint survive.
                    value.runtime = maintenance.private_runtime('pilot')
                    self.assertFalse(value.controller())
                    self.assertEqual(target.read_bytes(), generated)
                    self.assertEqual(fingerprint.read_bytes(), proof)
                    run.assert_not_called()
        finally:
            os.umask(previous)


if __name__ == '__main__':
    unittest.main()
