import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("capture_mac", Path(__file__).with_name("capture_mac.py"))
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


class CaptureTests(unittest.TestCase):
    def test_current_macos_enabled_disabled_fixture(self):
        fixture = '''disabled services = {
            "pl.o2.mail-guardian" => enabled
            "pl.o2.mail-guardian-ui" => disabled
        }
        '''
        self.assertFalse(capture.launchd_disabled(fixture, capture.LABELS[0]))
        self.assertTrue(capture.launchd_disabled(fixture, capture.LABELS[1]))

    def test_legacy_launchctl_booleans_and_missing_override(self):
        fixture = '''disabled services = {
            "pl.o2.mail-guardian" => true,
            "pl.o2.mail-guardian-ui" => false
        }
        '''
        self.assertTrue(capture.launchd_disabled(fixture, capture.LABELS[0]))
        self.assertFalse(capture.launchd_disabled(fixture, capture.LABELS[1]))
        self.assertFalse(capture.launchd_disabled('disabled services = {\n}\n', capture.LABELS[0]))

    def test_unknown_or_malformed_target_disabled_state_fails_closed(self):
        for fixture in ('"pl.o2.mail-guardian" => unknown', '"pl.o2.mail-guardian" = disabled',
                        '"pl.o2.mail-guardian" => disabled,,',
                        '"pl.o2.mail-guardian" => enabled\n"pl.o2.mail-guardian" => disabled'):
            with self.subTest(fixture=fixture), self.assertRaises(capture.CaptureError):
                capture.launchd_disabled(fixture, capture.LABELS[0])

    def test_pause_receipt_is_atomic_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "receipt.json"
            capture.atomic_json_private(receipt, {"original": True})
            with self.assertRaises(FileExistsError):
                capture.atomic_json_private(receipt, {"original": False})
            self.assertEqual(json.loads(receipt.read_text()), {"original": True})
            self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(root.iterdir()), [receipt])

    def test_pause_writes_original_state_receipt_before_first_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = root / "baseline"
            baseline.mkdir()
            (root / "config.toml").write_text("fixture")
            cfg = {"runtime": {"compose_file": "/fixture/o2-mail-guardian/deploy/compose.yaml"}}
            changed = []

            def fake(args, **kwargs):
                if args[:2] == ["/bin/launchctl", "disable"]:
                    receipt = json.loads((baseline / "pause-receipt.json").read_text())
                    self.assertEqual(receipt["launchd"][capture.LABELS[0]], {"loaded": True, "disabled": False})
                    changed.append(args)
                output = b""
                if "--services" in args:
                    output = b"redis\nrspamd\n"
                if "LIST" in args:
                    output = b"id=1 self-only\n"
                return subprocess.CompletedProcess(args, 0, output, b"")

            with patch.object(capture.shutil, "which", return_value="/fixture/docker"), patch.object(capture, "guardian_processes", return_value=[]):
                pauser = capture.MacPause(root, cfg, baseline, run=fake)
                pauser.keep_paused = True
                pauser.pause()
            self.assertEqual(len(changed), 2)
            self.assertTrue(json.loads((baseline / "pause-receipt.json").read_text())["keep_paused"])

    def test_tree_rejects_links_without_reading_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            secret = root / "secret"
            secret.write_bytes(b"never copy through a link")
            (source / "link").symlink_to(secret)
            with self.assertRaises(capture.CaptureError):
                capture.copy_tree(source, root / "copy")
            self.assertFalse((root / "copy/link").exists())
            self.assertEqual(secret.read_bytes(), b"never copy through a link")

    def test_snapshot_includes_committed_wal_and_preserves_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.db"
            db = sqlite3.connect(source)
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE messages (status TEXT)")
            db.execute("CREATE TABLE runs (id INTEGER, command TEXT, dry_run INTEGER, status TEXT, errors INTEGER)")
            db.commit()
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            before = source.read_bytes()
            db.execute("INSERT INTO messages VALUES ('quarantined')")
            db.execute("INSERT INTO runs VALUES (2,'run',0,'ok',0)")
            db.commit()
            capture.snapshot_database(source, root / "captured.db")
            copied = sqlite3.connect(root / "captured.db")
            self.assertEqual(copied.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 1)
            copied.close()
            self.assertEqual((root / "captured.db").read_bytes()[18:20], b"\x01\x01")
            self.assertFalse((root / "captured.db-wal").exists())
            self.assertFalse((root / "captured.db-shm").exists())
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual((root / "captured.db").stat().st_mode & 0o777, 0o600)
            db.close()

    def test_snapshot_rejects_pending_move(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.db"
            db = sqlite3.connect(source)
            db.execute("CREATE TABLE messages (status TEXT)")
            db.execute("INSERT INTO messages VALUES ('pending_move')")
            db.commit()
            db.close()
            with self.assertRaisesRegex(capture.CaptureError, "unresolved"):
                capture.snapshot_database(source, root / "captured.db")
            self.assertFalse((root / "captured.db").exists())

    def test_resume_retains_preexisting_disabled_states(self):
        calls = []

        def fake(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 1 if "print" in args else 0, b"", b"")

        pauser = object.__new__(capture.MacPause)
        pauser.home = Path("/fixture")
        pauser.domain = "gui/1"
        pauser.run = fake
        pauser.changed = list(capture.LABELS)
        pauser.original = {capture.LABELS[0]: {"loaded": True, "disabled": False},
                           capture.LABELS[1]: {"loaded": False, "disabled": True}}
        pauser.scanner_stopped = False
        pauser.resume()
        self.assertEqual([c[2] for c in calls if c[1] == "enable"], ["gui/1/" + capture.LABELS[0]])
        self.assertEqual(len([c for c in calls if c[1] == "bootstrap"]), 1)

    def test_failed_scanner_resume_does_not_start_worker(self):
        calls = []

        def fake(args, **kwargs):
            calls.append(args)
            raise capture.CaptureError("dependency failed")

        pauser = object.__new__(capture.MacPause)
        pauser.run, pauser.scanner_stopped = fake, True
        pauser.compose, pauser.env = ["docker", "compose"], {}
        pauser.changed = list(capture.LABELS)
        pauser.original = {label: {"loaded": True, "disabled": False} for label in capture.LABELS}
        with self.assertRaisesRegex(capture.CaptureError, "Rspamd"):
            pauser.resume()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][2:], ["start", "--wait", "rspamd"])

    def test_capture_failure_resumes_mac_and_leaves_incomplete_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            os.chmod(parent, 0o700)
            home = parent / "home"
            binary = home / ".local/bin/o2-mail-guardian/guardian"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"fixture binary")
            data = home / "data"
            data.mkdir()
            (data / "guardian.lock").write_bytes(b"")
            cfg = home / "config.toml"
            cfg.write_text('[runtime]\ndata_dir="' + str(data) + '"\ndatabase="' + str(data / 'guardian.db') + '"\n')
            state = []

            class FakePause:
                def __init__(self, *args):
                    pass

                def pause(self):
                    state.append("paused")

                def assert_quiescent(self):
                    pass

                def resume(self):
                    state.append("resumed")

            with patch.object(capture.sys, "platform", "darwin"), patch.object(capture, "MacPause", FakePause), patch.object(
                    capture, "snapshot_database", side_effect=capture.CaptureError("injected copy failure")):
                with self.assertRaisesRegex(capture.CaptureError, "injected"):
                    capture.capture(home, cfg, parent / "recovery", parent / "stage")
            self.assertEqual(state, ["paused", "resumed"])
            self.assertTrue((parent / "stage/INCOMPLETE").is_file())
            self.assertFalse((parent / "stage/COMPLETE").exists())

    def simulate_successful_capture(self, parent, *, keep_paused, fail_publication=False):
        home = parent / "home"
        binary = home / ".local/bin/o2-mail-guardian/guardian"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"fixture binary")
        data = home / "data"
        data.mkdir()
        (data / "guardian.lock").write_bytes(b"")
        cfg = home / "config.toml"
        cfg.write_text('[runtime]\ndata_dir="' + str(data) + '"\ndatabase="' + str(data / 'guardian.db')
                       + '"\narchive_dir="' + str(data / 'archive') + '"\ncompose_file="/fixture/o2-mail-guardian/deploy/compose.yaml"'
                       + '\narchive_keychain_service="archive"\n[account]\nemail="fixture@example.invalid"'
                       + '\n[rspamd]\npassword_keychain_service="rspamd"\n')
        state = []

        class FakePause:
            def __init__(self, *args):
                self.env = {}

            def pause(self):
                state.append("paused")

            def assert_quiescent(self):
                pass

            def assert_paused(self):
                state.append("verified-paused")

            def resume(self):
                state.append("resumed")

        def fake_command(args, **kwargs):
            output = b"{}"
            if args[0] == "/usr/bin/security":
                output = b"synthetic-secret\n"
            return subprocess.CompletedProcess(args, 0, output, b"")

        def fake_tree(source, destination):
            destination.mkdir()
            return [0, 0]

        with patch.object(capture.sys, "platform", "darwin"), patch.object(capture, "MacPause", FakePause), patch.object(
                capture, "snapshot_database"), patch.object(capture, "command", side_effect=fake_command), patch.object(
                capture, "copy_tree", side_effect=fake_tree):
            if fail_publication:
                with patch.object(capture, "publish_capture", side_effect=capture.CaptureError("publication failed")):
                    with self.assertRaisesRegex(capture.CaptureError, "publication"):
                        capture.capture(home, cfg, parent / "recovery", parent / "stage", keep_paused=keep_paused)
            else:
                capture.capture(home, cfg, parent / "recovery", parent / "stage", keep_paused=keep_paused)
        return state

    def test_final_capture_keeps_mac_paused_only_after_successful_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            os.chmod(parent, 0o700)
            state = self.simulate_successful_capture(parent, keep_paused=True)
            self.assertEqual(state, ["paused", "verified-paused"])
            self.assertTrue((parent / "stage/COMPLETE").is_file())
            self.assertFalse((parent / "stage/INCOMPLETE").exists())
            self.assertEqual(json.loads((parent / "stage/capture.json").read_text())["mac_state"], "paused")

    def test_final_capture_publication_failure_resumes_mac(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            os.chmod(parent, 0o700)
            state = self.simulate_successful_capture(parent, keep_paused=True, fail_publication=True)
            self.assertEqual(state, ["paused", "verified-paused", "resumed"])
            self.assertTrue((parent / "stage/INCOMPLETE").exists())
            self.assertFalse((parent / "stage/COMPLETE").exists())

    def test_successful_rehearsal_still_resumes_mac(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            os.chmod(parent, 0o700)
            state = self.simulate_successful_capture(parent, keep_paused=False)
            self.assertEqual(state, ["paused", "resumed"])
            self.assertEqual(json.loads((parent / "stage/capture.json").read_text())["mac_state"], "resumed")

    def test_late_publication_sync_failure_revokes_complete_marker_and_resumes(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            os.chmod(parent, 0o700)
            original = capture.publish_capture

            def late_failure(output, report, *, keep_paused):
                original(output, report, keep_paused=keep_paused)
                raise capture.CaptureError("publication failed")

            with patch.object(capture, "publish_capture", side_effect=late_failure):
                with self.assertRaisesRegex(capture.CaptureError, "publication"):
                    self.simulate_successful_capture(parent, keep_paused=True)
            self.assertTrue((parent / "stage/INCOMPLETE").exists())
            self.assertFalse((parent / "stage/COMPLETE").exists())

    def test_resume_receipt_rejects_changed_source_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            home = parent / "home"
            cfg = home / "Library/Application Support/O2 Mail Guardian/config.toml"
            cfg.parent.mkdir(parents=True)
            cfg.write_text("changed config")
            stage = parent / "stage"
            stage.mkdir(mode=0o700)
            baseline = stage / "baseline"
            baseline.mkdir(mode=0o700)
            capture.atomic_json_private(baseline / "pause-receipt.json", {
                "version": 1, "uid": os.getuid(), "home": str(home), "gui_was_running": False,
                "scanner_was_running": True, "source_config_sha256": "0" * 64,
                "launchd": {label: {"loaded": True, "disabled": False} for label in capture.LABELS},
            })
            with patch.object(capture.sys, "platform", "darwin"), patch.object(capture, "MacPause") as pauser:
                with self.assertRaisesRegex(capture.CaptureError, "configuration changed"):
                    capture.resume_from_receipt(home, stage)
                pauser.assert_not_called()


if __name__ == "__main__":
    unittest.main()
