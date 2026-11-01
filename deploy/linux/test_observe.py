#!/usr/bin/env python3
"""Observer fixtures use private temporary SQLite files and fake HTTP only."""

import contextlib
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error

spec = importlib.util.spec_from_file_location("guardian_observe", Path(__file__).with_name("observe.py"))
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)

NOW = dt.datetime(2026, 10, 30, 20, 0, tzinfo=dt.timezone.utc)
SECRET = "https://hc-ping.com/12345678-1234-4234-8234-123456789abc"


def stamp(seconds):
    return (NOW + dt.timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


class Fixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="guardian-observer-")
        self.root = Path(self.tmp.name).resolve()
        self.state, self.config = self.root / "state", self.root / "config"
        self.data, self.conf = self.state / "pilot", self.config / "pilot"
        # mkdir(parents=True, mode=0700) does not apply that mode to its
        # intermediate parents. Explicitly make the whole fixture private,
        # including on Ubuntu's common collaborative umask0002.
        for directory in (self.root, self.state, self.config, self.data, self.conf):
            if directory != self.root:
                directory.mkdir(mode=0o700)
            directory.chmod(0o700)
        self.machine = self.root / "machine-id"
        self.machine.write_text("c" * 32 + "\n")
        self.machine.chmod(0o644)
        self.toml = '''version=2
instance_id="11111111111111111111111111111111"
[account]
id="22222222222222222222222222222222"
provider="o2"
email="fixture@example.invalid"
username="fixture@example.invalid"
host="poczta.o2.pl"
port=993
tls=true
auth_method="password"
[folders]
inbox="INBOX"
server_spam="Spam"
quarantine="Quarantine"
review="Review"
train_spam="TrainSpam"
train_ham="TrainHam"
[runtime]
data_dir="/var/lib/mail-guardian/pilot"
database="/var/lib/mail-guardian/pilot/guardian.db"
archive_dir="/var/lib/mail-guardian/pilot/archive"
log_file="/var/lib/mail-guardian/pilot/guardian.log"
compose_file="/etc/mail-guardian/pilot/deploy/compose.yaml"
[safety]
mode="protect"
purge_enabled=false
'''
        self.config_path = self.conf / "config.toml"
        self.write_config()
        self.identity = observer.config_identity(self.toml.encode(), "pilot", "c" * 32)
        self.database = self.data / "guardian.db"
        self.sql = sqlite3.connect(self.database)
        self.sql.executescript('''
CREATE TABLE messages(account TEXT,status TEXT);
CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE runs(id INTEGER PRIMARY KEY,started_at TEXT,finished_at TEXT,command TEXT,dry_run INTEGER,status TEXT,errors INTEGER);
''')
        for key, value in zip(("mailbox_fingerprint", "authorization_fingerprint", "deployment_identity"), self.identity[1:]):
            self.sql.execute("INSERT INTO settings VALUES(?,?)", (key, value))
        self.sql.execute("INSERT INTO settings VALUES('model_checkpoint_required','')")
        self.sql.execute("INSERT INTO settings VALUES('configuration_dry_run_required','1')")
        self.sql.execute("INSERT INTO settings VALUES('first_dry_run_completed_at',?)", (stamp(-200),))
        self.sql.execute("INSERT INTO messages VALUES(?, 'kept')", (self.identity[0],))
        self.sql.execute("INSERT INTO runs VALUES(1,?,?, 'run',0,'ok',0)", (stamp(-120), stamp(-110)))
        self.sql.commit()
        self.database.chmod(0o600)
        self.heartbeat = {"protocol": 1, "last_attempt": stamp(-125),
                          "last_success": stamp(-105), "stage": "ok", "version": "fixture"}
        self.heartbeat_path = self.data / "service-health.json"
        self.write_heartbeat()

    def write_config(self):
        self.config_path.write_text(self.toml)
        self.config_path.chmod(0o640)

    def write_heartbeat(self):
        self.heartbeat_path.write_text(json.dumps(self.heartbeat))
        self.heartbeat_path.chmod(0o600)

    def update(self, sql, values=()):
        self.sql.execute(sql, values)
        self.sql.commit()

    def check(self):
        return observer.observe("pilot", now=NOW, state_root=self.state, config_root=self.config,
                                machine_path=self.machine, config_owner=os.geteuid())

    def running(self):
        self.heartbeat.update(stage="mailbox", last_attempt=stamp(-10))
        self.write_heartbeat()
        self.update("INSERT INTO runs VALUES(2,?,NULL,'run',0,'running',0)", (stamp(-9),))

    def close(self):
        self.sql.close()
        self.tmp.cleanup()


class ObserverStateTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.addCleanup(self.f.close)

    def assert_bad(self, code=None):
        with self.assertRaises(observer.ObservationError) as caught:
            self.f.check()
        if code:
            self.assertEqual(str(caught.exception), code)

    def test_matching_completed_actual_run_is_healthy_and_read_only(self):
        before = hashlib.sha256(self.f.database.read_bytes()).hexdigest()
        self.assertEqual(self.f.check(), "healthy")
        self.assertEqual(hashlib.sha256(self.f.database.read_bytes()).hexdigest(), before)
        self.assertEqual(self.f.sql.execute("SELECT count(*) FROM runs").fetchone()[0], 1)

    def test_current_active_policy_with_deletion_off_is_accepted(self):
        self.f.toml = self.f.toml.replace('mode="protect"', 'mode="active"')
        self.f.write_config()
        self.assertEqual(self.f.check(), "healthy")

    def test_purge_or_mismatched_config_policy_is_rejected(self):
        self.f.toml = self.f.toml.replace("purge_enabled=false", "purge_enabled=true")
        self.f.write_config()
        self.assert_bad("unsupported_safety_policy")

    def test_heartbeat_failure_or_future_or_stale_or_malformed_cannot_pass(self):
        original = dict(self.f.heartbeat)
        for change in ({"stage": "failed", "error_code": "UNKNOWN"},
                       {"last_success": stamp(-10801)}, {"last_success": stamp(61)},
                       {"protocol": True}, {"stage": "new_stage"}, {"unexpected": "field"}):
            with self.subTest(change=change):
                self.f.heartbeat = dict(original, **change)
                self.f.write_heartbeat()
                self.assert_bad()

    def test_duplicate_heartbeat_fields_fail(self):
        self.f.heartbeat_path.write_text('{"protocol":1,"protocol":1}')
        self.assert_bad("duplicate_json_field")

    def test_stopped_worker_is_not_healthy_after_twenty_minutes(self):
        # The observer may still run normally when the worker timer is stopped.
        # Such pings must not conceal an outage longer than the alert objective.
        self.f.heartbeat.update(last_attempt=stamp(-1260), last_success=stamp(-1250))
        self.f.write_heartbeat()
        self.f.update("UPDATE runs SET started_at=?,finished_at=?", (stamp(-1259), stamp(-1251)))
        self.assert_bad("stale_heartbeat")

    def test_newer_failed_actual_run_cannot_hide_behind_old_success_or_dryrun(self):
        self.f.update("INSERT INTO runs VALUES(2,?,?,'run',0,'error',1)", (stamp(-90), stamp(-80)))
        self.f.update("INSERT INTO runs VALUES(3,?,?,'run',1,'ok',0)", (stamp(-70), stamp(-60)))
        self.assert_bad("latest_actual_run_failed")

    def test_newer_unknown_manual_command_does_not_get_filtered_out(self):
        self.f.update("INSERT INTO runs VALUES(2,?,?,'restore',0,'ok',0)", (stamp(-90), stamp(-80)))
        self.assert_bad("invalid_run_state")

    def test_only_dry_run_is_not_actual_success(self):
        self.f.update("UPDATE runs SET dry_run=1")
        self.assert_bad("actual_run_missing")

    def test_unfinished_or_mismatched_run_fails(self):
        self.f.update("UPDATE runs SET finished_at=NULL,status='running'")
        self.assert_bad("latest_actual_run_failed")

    def test_heartbeat_must_cover_same_actual_run(self):
        self.f.update("UPDATE runs SET started_at=?,finished_at=?", (stamp(-104), stamp(-103)))
        self.assert_bad("heartbeat_run_mismatch")

    def test_all_pending_ambiguous_blocked_error_unknown_states_fail_when_complete(self):
        for status in ("pending_move", "pending_learn", "pending_restore", "move_ambiguous", "blocked", "error", "future_status", None):
            with self.subTest(status=status):
                self.f.update("UPDATE messages SET status=?", (status,))
                self.assert_bad()

    def test_checkpoint_and_authorization_requirements_fail(self):
        self.f.update("UPDATE settings SET value='1' WHERE key='model_checkpoint_required'")
        self.assert_bad("model_checkpoint_required")
        self.f.update("UPDATE settings SET value='' WHERE key IN ('model_checkpoint_required','first_dry_run_completed_at')")
        self.assert_bad("operational_authorization_missing")

    def test_running_exact_actual_row_defers_even_transient_pending_marker(self):
        self.f.running()
        self.f.update("UPDATE settings SET value='1' WHERE key='model_checkpoint_required'")
        self.f.update("UPDATE messages SET status='pending_move'")
        self.assertEqual(self.f.check(), "defer")

    def test_running_stage_without_current_run_does_not_mask_unresolved_work(self):
        self.f.heartbeat.update(stage="mailbox", last_attempt=stamp(-10))
        self.f.write_heartbeat()
        self.f.update("UPDATE messages SET status='pending_move'")
        self.assert_bad("inconsistent_running_state")

    def test_running_unknown_schema_or_foreign_identity_never_defers(self):
        self.f.running()
        self.f.update("UPDATE messages SET status='future_status'")
        self.assert_bad("unsupported_message_state")
        self.f.update("UPDATE messages SET status='kept',account=NULL")
        self.assert_bad("database_identity_mismatch")

    def test_running_deferral_is_bounded_and_does_not_mask_failed_run(self):
        self.f.running()
        self.f.heartbeat.update(last_attempt=stamp(-901), last_success=stamp(-1000))
        self.f.write_heartbeat()
        self.assert_bad()
        self.f.heartbeat.update(last_attempt=stamp(-10), last_success=stamp(-105))
        self.f.write_heartbeat()
        self.f.update("UPDATE runs SET status='error',errors=1,finished_at=? WHERE id=2", (stamp(-1),))
        self.assert_bad("latest_actual_run_failed")

    def test_all_identity_pins_and_foreign_account_are_checked(self):
        for key in ("mailbox_fingerprint", "authorization_fingerprint", "deployment_identity"):
            old = self.f.sql.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()[0]
            with self.subTest(key=key):
                self.f.update("UPDATE settings SET value=? WHERE key=?", ("0" * 64, key))
                self.assert_bad("database_identity_mismatch")
                self.f.update("UPDATE settings SET value=? WHERE key=?", (old, key))
        self.f.update("UPDATE messages SET account='other@example.invalid'")
        self.assert_bad("database_identity_mismatch")

    def test_missing_schema_or_view_is_rejected_without_migration(self):
        self.f.update("DROP TABLE messages")
        self.assert_bad("unsupported_database_schema")
        self.f.update("CREATE VIEW messages AS SELECT 'fixture@example.invalid' AS account,'kept' AS status")
        self.assert_bad("unsupported_database_schema")

    def test_unknown_schema_version_or_missing_identity_marker_fails(self):
        self.f.update("PRAGMA user_version=1")
        self.assert_bad("unsupported_database_schema")
        self.f.update("PRAGMA user_version=0")
        self.f.update("DELETE FROM settings WHERE key='model_checkpoint_required'")
        self.assert_bad("unsupported_database_state")

    def test_clean_stack_phase_before_matching_run_defers_for_at_most_three_minutes(self):
        self.f.heartbeat.update(stage="stack", last_attempt=stamp(-10))
        self.f.write_heartbeat()
        self.assertEqual(self.f.check(), "defer")
        self.f.heartbeat.update(last_attempt=stamp(-181), last_success=stamp(-200))
        self.f.write_heartbeat()
        self.f.update("UPDATE runs SET started_at=?,finished_at=?", (stamp(-220), stamp(-210)))
        self.assert_bad("inconsistent_running_state")

    def test_fingerprints_match_independent_go_encoding_json_literals(self):
        self.assertEqual(self.f.identity[1], "2407440e719cfbe87ff585399c4c2bde59547d4cd986d4ffe0e8236eb3454cd3")
        changed = self.f.toml.replace('review="Review"', 'review="\u2028<żółć&>"')
        identity = observer.config_identity(changed.encode(), "pilot", "c" * 32)
        self.assertEqual(identity[2], "787167043ec5e6d2dcd5903492ffab91db2159c56a776b37ffd6d8ad871470f9")

    def test_oversized_database_setting_is_bounded_before_allocation(self):
        self.f.update("UPDATE settings SET value=? WHERE key='mailbox_fingerprint'", ("x" * (65 << 10),))
        self.assert_bad("database_unavailable")

    def test_live_wal_changes_are_observed(self):
        self.f.sql.execute("PRAGMA journal_mode=WAL")
        self.f.sql.execute("PRAGMA wal_autocheckpoint=0")
        self.f.update("INSERT INTO messages VALUES(?, 'pending_move')", (self.f.identity[0],))
        self.assertTrue(Path(str(self.f.database) + "-wal").exists())
        self.assert_bad("unresolved_or_unknown_message_state")

    def test_symlink_database_and_symlink_parent_fail(self):
        alternate = self.f.data / "saved.db"
        self.f.database.rename(alternate)
        self.f.database.symlink_to(alternate)
        with self.assertRaises((OSError, observer.ObservationError)):
            self.f.check()
        self.f.database.unlink()
        alternate.rename(self.f.database)
        self.f.conf.rename(self.f.config / "saved")
        self.f.conf.symlink_to(self.f.config / "saved", target_is_directory=True)
        with self.assertRaises((OSError, observer.ObservationError)):
            self.f.check()

    def test_change_in_heartbeat_after_database_view_defers(self):
        original = observer.database_state
        def changing(*args, **kwargs):
            result = original(*args, **kwargs)
            self.f.heartbeat.update(stage="mailbox", last_attempt=stamp(-1))
            self.f.write_heartbeat()
            return result
        with patch.object(observer, "database_state", side_effect=changing):
            self.assertEqual(self.f.check(), "defer")

    def test_instance_and_root_paths_have_no_cli_escape(self):
        for instance in ("", "../pilot", "-pilot", "x;id", "x" * 30):
            with self.subTest(instance=instance), self.assertRaises(observer.ObservationError):
                observer.observe(instance)


class FixturePortabilityTests(unittest.TestCase):
    def test_fixture_ancestors_are_private_under_collaborative_umask(self):
        previous = os.umask(0o002)
        try:
            fixture = Fixture()
        finally:
            os.umask(previous)
        self.addCleanup(fixture.close)
        for directory in (fixture.root, fixture.state, fixture.config, fixture.data, fixture.conf):
            with self.subTest(directory=directory.name):
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(fixture.check(), "healthy")


class FakeResponse:
    def __init__(self, status=200, body=b"OK"):
        self.status, self.body = status, body
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, size):
        return self.body[:size]


class FakeOpener:
    def __init__(self, response=None, error=None):
        self.response, self.error = response or FakeResponse(), error
        self.requests = []
    def open(self, request, **kwargs):
        self.requests.append((request, kwargs))
        if self.error:
            raise self.error
        return self.response


class MonitorTransportTests(unittest.TestCase):
    def test_secret_url_is_strict_canonical_https_without_extra_components(self):
        self.assertEqual(observer.validate_ping_url((SECRET + "\n").encode()), SECRET)
        for bad in (SECRET.replace("https:", "http:"), SECRET + "/fail", SECRET + "?x=1",
                    SECRET + "#x", SECRET.replace("hc-ping.com", "hc-ping.com:443"),
                    SECRET.replace("hc-ping.com", "user@hc-ping.com"),
                    SECRET.replace("hc-ping.com", "hc-ping.com.evil.invalid"),
                    SECRET.upper(), "https://hc-ping.com/not-a-uuid"):
            with self.subTest(bad=bad), self.assertRaises(observer.ObservationError):
                observer.validate_ping_url(bad.encode())

    def test_credential_is_private_single_link_bounded_and_nofollow(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp).resolve()
            secret = directory / "healthchecks-url"
            secret.write_text(SECRET)
            secret.chmod(0o400)
            self.assertEqual(observer.credential_url(str(directory)), SECRET)
            secret.chmod(0o644)
            with self.assertRaises(observer.ObservationError):
                observer.credential_url(str(directory))
            secret.chmod(0o600)
            linked = directory / "saved"
            os.link(secret, linked)
            with self.assertRaises(observer.ObservationError):
                observer.credential_url(str(directory))
            linked.unlink()
            secret.rename(linked)
            secret.symlink_to(linked)
            with self.assertRaises(OSError):
                observer.credential_url(str(directory))
            secret.unlink()
            secret.write_text("x" * 257)
            secret.chmod(0o600)
            with self.assertRaises(observer.ObservationError):
                observer.credential_url(str(directory))

    def test_success_and_failure_send_only_empty_bounded_post(self):
        for healthy in (True, False):
            opener = FakeOpener()
            observer.send_ping(SECRET, healthy, opener=opener)
            request, options = opener.requests[0]
            self.assertEqual(request.full_url, SECRET + ("" if healthy else "/fail"))
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(request.data, b"")
            self.assertEqual(options, {"timeout": 5})

    def test_systemd_root_owned_read_only_credential_mount_is_supported(self):
        info = SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o100440)
        directory = '/run/credentials/mail-guardian-observe@pilot.service'
        with patch.object(Path, 'lstat', return_value=info), \
             patch.object(observer, 'read_private', return_value=SECRET.encode()) as read:
            self.assertEqual(observer.credential_url(directory), SECRET)
        self.assertEqual(read.call_args.kwargs, {'owner': 0, 'private': False, 'maximum': 256})

    def test_redirects_and_bad_or_oversized_responses_fail(self):
        with self.assertRaises(observer.ObservationError):
            observer.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://evil.invalid/")
        for response in (FakeResponse(302), FakeResponse(500), FakeResponse(200, b"wrong"), FakeResponse(200, b"x" * 1025)):
            with self.assertRaises(observer.ObservationError):
                observer.send_ping(SECRET, True, opener=FakeOpener(response))

    def test_default_transport_disables_proxies_and_installs_redirect_guard(self):
        fake = FakeOpener()
        with patch.object(observer.urllib.request, "build_opener", return_value=fake) as builder:
            observer.send_ping(SECRET, True)
        handlers = builder.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], observer.NoRedirect)

    def test_delivery_errors_are_redacted(self):
        error = urllib.error.URLError("secret failure " + SECRET)
        with self.assertRaises(observer.ObservationError) as caught:
            observer.send_ping(SECRET, True, opener=FakeOpener(error=error))
        self.assertEqual(str(caught.exception), "monitor_delivery_failed")
        self.assertNotIn("12345678", str(caught.exception))

    def cli(self, result=None, error=None, ping_error=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(observer.os, "geteuid", return_value=1234))
            stack.enter_context(patch.object(observer.pwd, "getpwuid", return_value=SimpleNamespace(pw_name="mg-pilot")))
            stack.enter_context(patch.object(observer, "credential_url", return_value=SECRET))
            stack.enter_context(patch.object(observer, "observe", return_value=result, side_effect=error))
            ping = stack.enter_context(patch.object(observer, "send_ping", side_effect=ping_error))
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(err))
            code = observer.main(["--instance", "pilot"])
        return code, out.getvalue() + err.getvalue(), ping

    def test_defer_sends_no_ping_and_completed_outcomes_choose_correct_signal(self):
        code, _, ping = self.cli("defer")
        self.assertEqual(code, 0)
        ping.assert_not_called()
        code, _, ping = self.cli("healthy")
        self.assertEqual(code, 0)
        ping.assert_called_once_with(SECRET, True)
        code, _, ping = self.cli(error=RuntimeError("private mailbox data " + SECRET))
        self.assertEqual(code, 1)
        ping.assert_called_once_with(SECRET, False)

    def test_cli_never_logs_url_or_dependency_exception(self):
        code, output, _ = self.cli("healthy", ping_error=RuntimeError(SECRET))
        self.assertEqual(code, 2)
        self.assertNotIn("12345678", output)
        self.assertNotIn("hc-ping", output)

    def test_cli_rejects_root_or_wrong_instance_user_before_reading_secret(self):
        for uid, name in ((0, "root"), (1234, "ubuntu"), (1234, "mg-other")):
            with self.subTest(uid=uid, name=name), patch.object(observer.os, "geteuid", return_value=uid), patch.object(observer.pwd, "getpwuid", return_value=SimpleNamespace(pw_name=name)), patch.object(observer, "credential_url") as credential, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(observer.main(["--instance", "pilot"]), 2)
                credential.assert_not_called()


if __name__ == "__main__":
    unittest.main()
