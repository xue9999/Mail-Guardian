"""Offline empty-pilot bootstrap boundaries; no system paths or services change."""

import hashlib
import importlib.util
from pathlib import Path
import os
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("empty_pilot", Path(__file__).with_name("upgrade_empty_pilot.py"))
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class BootstrapTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        return root

    def test_empty_directory_requires_real_existing_private_inode(self):
        root = self.fixture()
        empty = root / "empty"
        empty.mkdir(mode=0o700)
        bootstrap.assert_empty(empty, os.geteuid(), os.getegid())
        with self.assertRaises(FileNotFoundError):
            bootstrap.assert_empty(root / "missing", os.geteuid())
        linked = root / "linked"
        linked.symlink_to(empty)
        with self.assertRaises(ValueError):
            bootstrap.assert_empty(linked, os.geteuid())
        empty.chmod(0o755)
        with self.assertRaises(ValueError):
            bootstrap.assert_empty(empty, os.geteuid())

    def test_empty_pilot_rejects_any_child_including_empty_subdirectory(self):
        root = self.fixture()
        for kind in ("file", "directory", "symlink", "fifo"):
            empty = root / kind
            empty.mkdir(mode=0o700)
            child = empty / "child"
            if kind == "file":
                child.write_bytes(b"state")
            elif kind == "directory":
                child.mkdir()
            elif kind == "symlink":
                child.symlink_to(root / "missing")
            else:
                os.mkfifo(child, 0o600)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                bootstrap.assert_empty(empty, os.geteuid())

    def package(self, root, count=21):
        entries = {}
        for i in range(count):
            name = "payload-" + str(i)
            data = ("fixture " + str(i)).encode()
            (root / name).write_bytes(data)
            entries[name] = hashlib.sha256(data).hexdigest()
        manifest = root / "SHA256SUMS"
        manifest.write_text("".join(value + "  " + name + "\n" for name, value in entries.items()))
        return entries, hashlib.sha256(manifest.read_bytes()).hexdigest()

    def test_old_manifest_file_count_is_not_tied_to_current_package(self):
        root = self.fixture()
        entries, expected = self.package(root)
        # This test isolates manifest/content compatibility from root ownership;
        # production trusted() remains mandatory and is independently tested.
        with patch.object(bootstrap, "trusted"):
            self.assertEqual(bootstrap.verify_package(root, expected), entries)
            (root / "payload-1").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "checksum"):
                bootstrap.verify_package(root, expected)

    def test_manifest_has_independent_digest_and_rejects_traversal_duplicates(self):
        root = self.fixture()
        entries, expected = self.package(root, 1)
        with patch.object(bootstrap, "trusted"):
            with self.assertRaisesRegex(ValueError, "digest"):
                bootstrap.verify_package(root, "0" * 64)
            for name in ("../outside", "/outside", "./payload-0", "payload-0\n" + entries["payload-0"] + "  payload-0"):
                manifest = root / "SHA256SUMS"
                manifest.write_text(entries["payload-0"] + "  " + name + "\n")
                with self.subTest(name=name), self.assertRaises(ValueError):
                    bootstrap.verify_package(root, hashlib.sha256(manifest.read_bytes()).hexdigest())

    def test_manifest_rejects_unlisted_files(self):
        root = self.fixture()
        entries, expected = self.package(root, 1)
        (root / "not-in-manifest").write_bytes(b"extra")
        with patch.object(bootstrap, "trusted"), self.assertRaisesRegex(ValueError, "unlisted"):
            bootstrap.verify_package(root, expected)

    def test_stopped_check_rejects_unknown_unit_state_and_project_volumes(self):
        def result(args, expected=0):
            if "is-active" in args:
                return b"inactive\n"
            if "is-enabled" in args:
                return b"disabled\n"
            return b""
        with patch.object(bootstrap, "run", side_effect=result):
            bootstrap.assert_stopped()
        def unknown(args, expected=0):
            return b"unknown\n" if "is-active" in args else result(args, expected)
        with patch.object(bootstrap, "run", side_effect=unknown), self.assertRaises(ValueError):
            bootstrap.assert_stopped()
        def volume(args, expected=0):
            return b"existing-volume\n" if "volume" in args else result(args, expected)
        with patch.object(bootstrap, "run", side_effect=volume), self.assertRaisesRegex(ValueError, "resources"):
            bootstrap.assert_stopped()

    def test_trusted_requires_absolute_non_symlink_regular_paths(self):
        with self.assertRaisesRegex(ValueError, "absolute"):
            bootstrap.trusted(Path("relative"))
        # Root inode is trusted, but cannot be used where a regular file is
        # required. A symlink must be rejected even if its destination is root.
        with self.assertRaises(ValueError):
            bootstrap.trusted(Path("/"))
        root = self.fixture()
        linked = root / "link"
        linked.symlink_to("/")
        with self.assertRaises(ValueError):
            bootstrap.trusted(linked, directory=True)

    def test_interrupted_copy_keeps_pending_marker_and_old_current(self):
        root = self.fixture()
        filesystem = root / "filesystem"

        def mapped(name):
            path = Path(name)
            return filesystem / str(path).lstrip("/") if path.is_absolute() else path

        old = mapped("/opt/mail-guardian/releases/old")
        old.mkdir(parents=True)
        mapped("/opt/mail-guardian/current").symlink_to(old)
        for name in ("/usr/local/libexec/mail-guardian-maintenance",
                     "/etc/systemd/system/mail-guardian@.service",
                     "/etc/systemd/system/mail-guardian@.timer"):
            file = mapped(name)
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b"preserved old component")
        mapped("/var/backups").mkdir(parents=True)
        release = root / "candidate"
        release.mkdir()
        (release / "VERSION").write_text("0.6.1\n")
        (release / "SHA256SUMS").write_bytes(b"fixture candidate manifest")
        config = root / "config"
        config.mkdir()
        data = root / "data"
        data.mkdir()
        worker = SimpleNamespace(pw_uid=os.geteuid())
        args = SimpleNamespace(expected_installed_manifest="a" * 64)
        with patch.object(bootstrap, "Path", side_effect=mapped), patch.object(
                bootstrap, "trusted"), patch.object(bootstrap, "assert_empty"), patch.object(
                bootstrap, "assert_stopped"), patch.object(bootstrap.os, "fchown"), patch.object(
                bootstrap.shutil, "copytree", side_effect=RuntimeError("injected interruption")):
            with self.assertRaisesRegex(RuntimeError, "injected interruption"):
                bootstrap.apply_upgrade(args, release, SimpleNamespace(), old, config,
                                        data, worker, os.getegid())
        self.assertTrue((config / "migration-pending").is_file())
        self.assertIn(str(old), (config / "migration-pending").read_text())
        self.assertEqual(mapped("/opt/mail-guardian/current").resolve(), old)
        self.assertFalse(any(mapped("/var/backups/mail-guardian").rglob("receipt.json")))


if __name__ == "__main__":
    unittest.main()
