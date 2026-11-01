"""Real private POSIX lock + isolated subprocess tests; no package writes."""

import errno
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import engine


class FrontendLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "lock-frontend"
        self.path.touch(mode=0o640)
        self.path.chmod(0o640)

    @contextmanager
    def frontend_fixture_root(self):
        real_fstat, real_lstat = os.fstat, os.lstat
        def root_owned(info):
            return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=info.st_gid,
                                   st_nlink=info.st_nlink, st_dev=info.st_dev, st_ino=info.st_ino)
        def fstat(fd):
            return root_owned(real_fstat(fd))
        def lstat(path, *args, **kwargs):
            result = real_lstat(path, *args, **kwargs)
            return root_owned(result) if Path(path) == self.path else result
        with mock.patch.object(engine, "DPKG_FRONTEND_LOCK", self.path), \
                mock.patch.object(engine.os, "fstat", side_effect=fstat), \
                mock.patch.object(engine.os, "lstat", side_effect=lstat):
            yield

    def acquire_as_fixture_root(self):
        with self.frontend_fixture_root():
            return engine.acquire_frontend_lock()

    def test_assert_frontend_lock_held_accepts_live_lock(self):
        fd = self.acquire_as_fixture_root()
        try:
            with self.frontend_fixture_root():
                engine.assert_frontend_lock_held(fd)
        finally:
            os.close(fd)

    def test_assert_frontend_lock_held_rejects_released_lock(self):
        fd = self.acquire_as_fixture_root()
        try:
            # Closing any descriptor for this inode in the owning process can
            # silently release its POSIX locks while fd still looks valid.
            other_fd = os.open(self.path, os.O_RDWR)
            os.close(other_fd)
            with self.frontend_fixture_root(), self.assertRaises(engine.UpdateError):
                engine.assert_frontend_lock_held(fd)
        finally:
            os.close(fd)

    def test_assert_frontend_lock_held_rejects_foreign_lock_owner(self):
        fd = self.acquire_as_fixture_root()
        ready = Path(self.tmp.name) / "foreign-owner-ready"
        program = r'''
import fcntl, os, pathlib, sys, time
fd = os.open(sys.argv[1], os.O_RDWR)
fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
pathlib.Path(sys.argv[2]).write_text(str(os.getpid()))
while True: time.sleep(1)
'''
        child = None
        try:
            # Reproduce the ownership race: our fd remains open but its lock
            # was lost, then a separate package frontend takes the same lock.
            fcntl.lockf(fd, fcntl.LOCK_UN)
            child = subprocess.Popen([sys.executable, "-c", program, str(self.path), str(ready)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            deadline = time.monotonic() + 10
            while not ready.exists():
                if child.poll() is not None:
                    self.fail("foreign lock holder failed: " + child.stderr.read()[-1000:])
                if time.monotonic() >= deadline:
                    self.fail("foreign lock holder did not start")
                time.sleep(0.02)
            self.assertNotEqual(int(ready.read_text()), os.getpid())
            with self.frontend_fixture_root(), self.assertRaises(engine.UpdateError):
                engine.assert_frontend_lock_held(fd)
        finally:
            if child is not None:
                child.kill()
                child.wait(timeout=5)
                child.stderr.close()
            os.close(fd)

    def test_assert_frontend_lock_held_rejects_partial_lock(self):
        fd = self.acquire_as_fixture_root()
        try:
            # A same-owner F_GETLK answer is insufficient if only part of the
            # lock remains and another frontend can lock the missing byte.
            fcntl.lockf(fd, fcntl.LOCK_UN, 1, 0, os.SEEK_SET)
            with self.frontend_fixture_root(), self.assertRaises(engine.UpdateError):
                engine.assert_frontend_lock_held(fd)
        finally:
            os.close(fd)

    def test_assert_frontend_lock_held_rejects_replaced_path(self):
        fd = self.acquire_as_fixture_root()
        try:
            os.replace(self.path, Path(self.tmp.name) / "old-lock")
            self.path.touch(mode=0o640)
            self.path.chmod(0o640)
            with self.frontend_fixture_root(), self.assertRaises(engine.UpdateError):
                engine.assert_frontend_lock_held(fd)
        finally:
            os.close(fd)

    def test_real_posix_lock_blocks_other_process_until_released(self):
        fd = self.acquire_as_fixture_root()
        try:
            probe = r'''
import errno, fcntl, os, sys
fd=os.open(sys.argv[1],os.O_RDWR)
try:
    fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
except OSError as e:
    sys.exit(8 if e.errno in (errno.EACCES,errno.EAGAIN) else 9)
sys.exit(0)
'''
            result = subprocess.run([sys.executable, "-c", probe, str(self.path)], timeout=5)
            self.assertEqual(result.returncode, 8)
        finally:
            os.close(fd)
        result = subprocess.run([sys.executable, "-c", probe, str(self.path)], timeout=5)
        self.assertEqual(result.returncode, 0)

    def test_lock_held_by_other_process_fails_closed(self):
        ready = Path(self.tmp.name) / "ready"
        program = r'''
import fcntl, os, pathlib, sys, time
fd=os.open(sys.argv[1],os.O_RDWR)
fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
pathlib.Path(sys.argv[2]).write_text("ready")
while True: time.sleep(1)
'''
        child = subprocess.Popen([sys.executable, "-c", program, str(self.path), str(ready)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while not ready.exists():
                if child.poll() is not None:
                    self.fail("lock-holder failed: " + child.stderr.read()[-1000:])
                if time.monotonic() >= deadline:
                    self.fail("lock-holder did not start")
                time.sleep(0.02)
            with self.assertRaises((BlockingIOError, OSError)) as error:
                self.acquire_as_fixture_root()
            self.assertIn(error.exception.errno, (errno.EACCES, errno.EAGAIN))
        finally:
            child.kill()
            child.wait(timeout=5)
            child.stderr.close()
        fd = self.acquire_as_fixture_root()
        os.close(fd)

    def test_symlink_and_hardlinked_lock_are_rejected(self):
        foreign = Path(self.tmp.name) / "foreign"
        foreign.write_bytes(b"untouched")
        self.path.unlink()
        self.path.symlink_to(foreign)
        with self.assertRaises(OSError):
            self.acquire_as_fixture_root()
        self.assertEqual(foreign.read_bytes(), b"untouched")
        self.path.unlink()
        os.link(foreign, self.path)
        with self.assertRaises(engine.UpdateError):
            self.acquire_as_fixture_root()
        self.assertEqual(foreign.read_bytes(), b"untouched")

    def test_group_writable_frontend_lock_is_rejected(self):
        self.path.chmod(0o660)
        with self.assertRaises(engine.UpdateError):
            self.acquire_as_fixture_root()

    def test_lock_replaced_between_open_and_acquire_is_rejected(self):
        actual = fcntl.lockf
        def swap_then_lock(fd, operation):
            os.replace(self.path, Path(self.tmp.name) / "old-lock")
            self.path.touch(mode=0o640)
            self.path.chmod(0o640)
            return actual(fd, operation)
        returned_fd = None
        with mock.patch.object(engine.fcntl, "lockf", side_effect=swap_then_lock):
            try:
                with self.assertRaises(engine.UpdateError):
                    returned_fd = self.acquire_as_fixture_root()
            finally:
                if returned_fd is not None:
                    os.close(returned_fd)


class ChildEnvironmentTests(unittest.TestCase):
    def test_frontend_bypass_is_only_present_for_explicit_child(self):
        command = [sys.executable, "-c",
                   "import json,os;print(json.dumps(os.environ.get('DPKG_FRONTEND_LOCKED')))" ]
        with mock.patch.dict(os.environ, {"DPKG_FRONTEND_LOCKED": "inherited-danger"}):
            guarded = engine.run(command, frontend_locked=True)
            ordinary = engine.run(command)
        self.assertEqual(json.loads(guarded.stdout), "1")
        self.assertIsNone(json.loads(ordinary.stdout))
        self.assertNotIn("DPKG_FRONTEND_LOCKED", engine.ENV)


if __name__ == "__main__":
    unittest.main()
