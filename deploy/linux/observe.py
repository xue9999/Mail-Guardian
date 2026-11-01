#!/usr/bin/python3 -I
"""Optional read-only Guardian observer; no mailbox access or backup claim.

Install separately as root-owned /usr/local/libexec/mail-guardian-observe.
The five-minute timer and Healthchecks period=5m/grace=10m are opt-in. Running
work receives no success ping and defers for at most fifteen minutes; a longer
run alerts even though the worker's separate hard timeout is two hours.
Stack startup before a matching row defers for at most three minutes, only
while the prior actual run is healthy and no unresolved/checkpoint state exists.
SQLite uses mode=ro/query_only and no migration; its normal WAL/SHM bookkeeping
may create sidecars, so the unit permits writes only to its instance data path.
The unit's 30-second timeout also bounds DNS calls that urllib cannot interrupt.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import sqlite3
import ssl
import stat
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAX_STATE_BYTES = 32 << 10
MAX_CONFIG_BYTES = 64 << 10
MAX_DATABASE_BYTES = 512 << 20
# Bound missed-worker detection as well as host/observer failure detection.
# Repeated observer pings must not keep a stopped worker green for hours.
# Twenty minutes also tolerates the previous 15-minute worker schedule.
STALE_SECONDS = 20 * 60
RUN_GRACE_SECONDS = 15 * 60
START_GRACE_SECONDS = 3 * 60
FUTURE_SECONDS = 60
QUERY_SECONDS = 5
PING_SECONDS = 5
INSTANCE = re.compile(r"[a-z0-9][a-z0-9-]{0,28}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[0-9a-f]{32}\Z")
STAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z\Z")
FINAL_STATUSES = frozenset(("kept", "observed", "quarantined", "rescued", "review",
                            "purged", "restored", "superseded"))
KNOWN_STATUSES = FINAL_STATUSES | frozenset(("pending_move", "pending_learn",
                                            "pending_restore", "move_ambiguous", "blocked", "error"))


class ObservationError(Exception):
    """Only fixed codes are allowed in diagnostics; never dependency details."""


def fail(code):
    raise ObservationError(code) from None


def exact_int(value, minimum=0):
    return type(value) is int and value >= minimum


def timestamp(value):
    if not isinstance(value, str) or not STAMP.fullmatch(value):
        fail("invalid_timestamp")
    try:
        return dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail("invalid_timestamp")


def no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail("duplicate_json_field")
        value[key] = item
    return value


def metadata(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def open_regular(path, *, owner, private, maximum):
    """Open without following any path component symlink; retain the file fd."""
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        fail("invalid_local_path")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=directory)
            os.close(directory)
            directory = new
            ancestor = os.fstat(directory)
            if (ancestor.st_uid not in (0, owner) or
                    (ancestor.st_mode & 0o022 and not (ancestor.st_uid == 0 and ancestor.st_mode & stat.S_ISVTX))):
                fail("unsafe_local_directory")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
    finally:
        os.close(directory)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or
                info.st_nlink != 1 or info.st_mode & 0o7000 or
                info.st_mode & (0o077 if private is True else 0o027 if private is False else 0o022) or
                info.st_size < 0 or info.st_size > maximum):
            fail("unsafe_local_file")
        return fd, info
    except BaseException:
        os.close(fd)
        raise


def read_private(path, *, owner, private=True, maximum=MAX_STATE_BYTES):
    fd, before = open_regular(path, owner=owner, private=private, maximum=maximum)
    try:
        content = bytearray()
        while True:
            part = os.read(fd, min(8192, maximum + 1 - len(content)))
            if not part:
                break
            content.extend(part)
            if len(content) > maximum:
                fail("local_file_too_large")
        if metadata(before) != metadata(os.fstat(fd)):
            fail("local_file_changed")
        return bytes(content)
    finally:
        os.close(fd)


def go_json_hash(value):
    # Go encoding/json's default string escaping; fingerprints are the worker's
    # existing contract. Config fields are decoded strict Unicode strings.
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    for char, escaped in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"),
                          ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        raw = raw.replace(char, escaped)
    return hashlib.sha256(raw.encode("utf-8", "strict")).hexdigest()


def config_identity(raw, instance, machine_id):
    try:
        cfg = tomllib.loads(raw.decode("utf-8", "strict"))
        account, folders, runtime = cfg["account"], cfg["folders"], cfg["runtime"]
        instance_id, account_id = cfg["instance_id"], account["id"]
        if (type(cfg["version"]) is not int or cfg["version"] != 2 or
                not ID.fullmatch(instance_id) or not ID.fullmatch(account_id) or
                account["tls"] is not True):
            fail("unsupported_config")
        if (cfg["safety"]["purge_enabled"] is not False or
                cfg["safety"]["mode"] not in ("protect", "active")):
            fail("unsupported_safety_policy")
        email, host = account["email"], account["host"].lower()
        provider = account.get("provider", "o2") or "o2"
        auth = account.get("auth_method", "password") or "password"
        username = account.get("username", "") or email
        port = account["port"]
        if (not all(isinstance(x, str) and x and not any(c in x for c in "\r\n\x00")
                    for x in (email, host, username)) or auth != "password" or
                provider not in ("o2", "custom") or not exact_int(port, 1) or port > 65535 or
                (provider == "o2" and (host != "poczta.o2.pl" or port != 993))):
            fail("unsupported_config")
        data = "/var/lib/mail-guardian/" + instance
        paths = {"data_dir": data, "database": data + "/guardian.db",
                 "archive_dir": data + "/archive", "log_file": data + "/guardian.log",
                 "compose_file": "/etc/mail-guardian/" + instance + "/deploy/compose.yaml"}
        if any(runtime.get(key) != expected for key, expected in paths.items()):
            fail("configuration_path_mismatch")
        roles = {}
        for name, key in (("Inbox", "inbox"), ("ServerSpam", "server_spam"),
                          ("Quarantine", "quarantine"), ("Review", "review"),
                          ("TrainSpam", "train_spam"), ("TrainHam", "train_ham")):
            value = folders[key]
            if not isinstance(value, str) or not value or len(value.encode()) > 4096:
                fail("unsupported_config")
            roles[name] = value
        mailbox = go_json_hash([instance_id, account_id, provider, host, str(port), username, email, auth])
        authorization = go_json_hash({"Mailbox": mailbox, "Folders": roles})
        if not re.fullmatch(r"[0-9a-fA-F]{32}", machine_id):
            fail("invalid_machine_identity")
        deployment = hashlib.sha256((machine_id + "\x00" + data + "\x00" + instance_id).encode()).hexdigest()
        return email, mailbox, authorization, deployment
    except ObservationError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError, AttributeError):
        fail("unsupported_config")


def heartbeat_state(raw, now):
    try:
        item = json.loads(raw, object_pairs_hook=no_duplicates)
    except (ValueError, UnicodeError):
        fail("invalid_heartbeat")
    expected = {"protocol", "last_attempt", "last_success", "stage", "error_code", "version"}
    if (not isinstance(item, dict) or set(item) - expected or
            type(item.get("protocol")) is not int or item["protocol"] != 1 or
            not isinstance(item.get("error_code", ""), str)):
        fail("unsupported_heartbeat")
    attempt, success = timestamp(item.get("last_attempt")), timestamp(item.get("last_success"))
    if any((value - now).total_seconds() > FUTURE_SECONDS for value in (attempt, success)):
        fail("future_heartbeat")
    if (now - success).total_seconds() > STALE_SECONDS:
        fail("stale_heartbeat")
    if item.get("stage") == "failed" or item.get("error_code"):
        fail("failed_heartbeat")
    if item.get("stage") in ("starting", "stack", "mailbox"):
        if success > attempt or (now - attempt).total_seconds() > RUN_GRACE_SECONDS:
            fail("overdue_running_work")
        return "defer", attempt, success
    if item.get("stage") != "ok" or success < attempt:
        fail("unsupported_heartbeat")
    return "healthy", attempt, success


def database_state(path, identity, attempt, success, now, running, *, owner):
    email, mailbox, authorization, deployment = identity
    fd, before = open_regular(path, owner=owner, private=True, maximum=MAX_DATABASE_BYTES)
    db = None
    try:
        # Use the actual pathname so SQLite sees its real WAL/SHM, never
        # immutable=1 or /proc/fd aliases that could hide committed WAL changes.
        uri = "file:" + urllib.parse.quote(str(path), safe="/") + "?mode=ro"
        db = sqlite3.connect(uri, uri=True, timeout=1, isolation_level=None)
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 64 << 10)
        db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 16 << 10)
        db.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 64)
        deadline = time.monotonic() + QUERY_SECONDS
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA cache_size=-2048")
        db.execute("BEGIN")
        if db.execute("PRAGMA user_version").fetchone()[0] != 0:
            fail("unsupported_database_schema")
        types = dict(db.execute("SELECT name,type FROM sqlite_master WHERE name IN ('messages','runs','settings')"))
        if types != {"messages": "table", "runs": "table", "settings": "table"}:
            fail("unsupported_database_schema")
        if db.execute("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view'))").fetchone()[0]:
            fail("unsupported_database_schema")
        required = {"messages": {"account": "TEXT", "status": "TEXT"},
                    "runs": {"id": "INTEGER", "started_at": "TEXT", "finished_at": "TEXT", "command": "TEXT", "dry_run": "INTEGER", "status": "TEXT", "errors": "INTEGER"},
                    "settings": {"key": "TEXT", "value": "TEXT"}}
        for table, columns in required.items():
            actual = {row[1]: row[2].upper() for row in db.execute("PRAGMA table_info(" + table + ")")}
            if any(actual.get(name) != kind for name, kind in columns.items()):
                fail("unsupported_database_schema")
        if db.execute("PRAGMA quick_check(1)").fetchall() != [("ok",)]:
            fail("database_integrity")
        values = dict(db.execute("SELECT key,value FROM settings WHERE key IN ('mailbox_fingerprint','authorization_fingerprint','deployment_identity','model_checkpoint_required','configuration_dry_run_required','first_dry_run_completed_at')"))
        expected_settings = {"mailbox_fingerprint", "authorization_fingerprint", "deployment_identity",
                             "model_checkpoint_required", "configuration_dry_run_required", "first_dry_run_completed_at"}
        if (set(values) != expected_settings or
                not all(isinstance(value, str) and len(value) <= 4096 for value in values.values()) or
                values["model_checkpoint_required"] not in ("", "1") or
                values["configuration_dry_run_required"] not in ("", "1")):
            fail("unsupported_database_state")
        if (values.get("mailbox_fingerprint") != mailbox or
                values.get("authorization_fingerprint") != authorization or
                values.get("deployment_identity") != deployment):
            fail("database_identity_mismatch")
        checkpoint_required = bool(values.get("model_checkpoint_required", ""))
        if values.get("configuration_dry_run_required", "") and not values.get("first_dry_run_completed_at"):
            fail("operational_authorization_missing")
        placeholders = ",".join("?" for _ in FINAL_STATUSES)
        if db.execute("SELECT EXISTS(SELECT 1 FROM messages WHERE account IS NULL OR account<>?)", (email,)).fetchone()[0]:
            fail("database_identity_mismatch")
        known_placeholders = ",".join("?" for _ in KNOWN_STATUSES)
        if db.execute("SELECT EXISTS(SELECT 1 FROM messages WHERE status IS NULL OR status NOT IN (" + known_placeholders + "))", tuple(KNOWN_STATUSES)).fetchone()[0]:
            fail("unsupported_message_state")
        unresolved = bool(db.execute("SELECT EXISTS(SELECT 1 FROM messages WHERE status IS NULL OR status NOT IN (" + placeholders + "))", tuple(FINAL_STATUSES)).fetchone()[0])
        if db.execute("SELECT EXISTS(SELECT 1 FROM runs WHERE dry_run NOT IN (0,1) OR dry_run IS NULL)").fetchone()[0]:
            fail("invalid_run_state")
        row = db.execute("SELECT started_at,finished_at,command,status,errors FROM runs WHERE dry_run=0 ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            fail("actual_run_missing")
        started, finished, command, status_value, errors = row
        start = timestamp(started)
        if (start - now).total_seconds() > FUTURE_SECONDS or not exact_int(errors) or command != "run":
            fail("invalid_run_state")
        if running:
            # Pending/required-marker states are expected during a modifying
            # run. A positively matched current running row gets no signal,
            # never success. The heartbeat bounds this deferral to 15 minutes.
            # Foreign identity and a newer failed/manual run still fail.
            if status_value == "error" or errors:
                fail("latest_actual_run_failed")
            if status_value == "running" and finished is None and start >= attempt:
                return "defer"
            if (status_value == "ok" and finished is not None and
                    (now - attempt).total_seconds() <= START_GRACE_SECONDS and
                    not checkpoint_required and not unresolved):
                end = timestamp(finished)
                if start <= end <= success <= attempt and not db.execute("SELECT EXISTS(SELECT 1 FROM runs WHERE status='running' OR finished_at IS NULL)").fetchone()[0]:
                    return "defer"
            fail("inconsistent_running_state")
        if checkpoint_required:
            fail("model_checkpoint_required")
        if unresolved:
            fail("unresolved_or_unknown_message_state")
        if command != "run" or status_value != "ok" or errors != 0 or finished is None:
            fail("latest_actual_run_failed")
        end = timestamp(finished)
        if not attempt <= start <= end <= success or (now - end).total_seconds() > STALE_SECONDS:
            fail("heartbeat_run_mismatch")
        if db.execute("SELECT EXISTS(SELECT 1 FROM runs WHERE status='running' OR finished_at IS NULL)").fetchone()[0]:
            fail("unfinished_run")
        return "healthy"
    except sqlite3.Error:
        fail("database_unavailable")
    finally:
        if db is not None:
            db.close()
        try:
            if not os.path.samestat(before, os.stat(path, follow_symlinks=False)):
                fail("database_path_changed")
        finally:
            os.close(fd)


def observe(instance, *, now=None, state_root=Path("/var/lib/mail-guardian"),
            config_root=Path("/etc/mail-guardian"), machine_path=Path("/etc/machine-id"),
            state_owner=None, config_owner=0):
    """Local test seams are Python-only; CLI never accepts alternate roots."""
    if not isinstance(instance, str) or not INSTANCE.fullmatch(instance):
        fail("invalid_instance")
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        fail("invalid_clock")
    owner = os.geteuid() if state_owner is None else state_owner
    data = state_root / instance
    config = read_private(config_root / instance / "config.toml", owner=config_owner,
                          private=False, maximum=MAX_CONFIG_BYTES)
    machine_id = read_private(machine_path, owner=config_owner, private=None, maximum=128).decode("ascii").strip()
    identity = config_identity(config, instance, machine_id)
    heartbeat_path = data / "service-health.json"
    before = read_private(heartbeat_path, owner=owner)
    stage, attempt, success = heartbeat_state(before, now)
    result = database_state(data / "guardian.db", identity, attempt, success, now,
                            stage == "defer", owner=owner)
    if before != read_private(heartbeat_path, owner=owner):
        return "defer"
    if config != read_private(config_root / instance / "config.toml", owner=config_owner,
                              private=False, maximum=MAX_CONFIG_BYTES):
        fail("configuration_changed")
    return result


def validate_ping_url(raw):
    try:
        text = raw.decode("ascii", "strict").strip()
        parts = urllib.parse.urlsplit(text)
        token = parts.path[1:]
        if (parts.scheme != "https" or parts.netloc != "hc-ping.com" or
                parts.query or parts.fragment or str(uuid.UUID(token)) != token):
            fail("invalid_monitor_credential")
        return "https://hc-ping.com/" + token
    except (UnicodeError, ValueError):
        fail("invalid_monitor_credential")


def credential_url(directory):
    if not directory:
        fail("monitor_credential_unavailable")
    path = Path(directory) / "healthchecks-url"
    info = path.lstat()
    # Current systemd exposes root:root 0440 credentials with a service-user
    # ACL in its protected read-only mount. It need not chown them to User=.
    # Keep the ordinary private-user path for older managers and test fixtures.
    managed = (Path(directory).parent == Path('/run/credentials')
               and info.st_uid == 0 and info.st_gid == 0
               and stat.S_IMODE(info.st_mode) == 0o440)
    return validate_ping_url(read_private(path, owner=0 if managed else os.geteuid(),
                                          private=False if managed else True, maximum=256))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fail("monitor_redirect_rejected")


def send_ping(url, healthy, *, opener=None):
    # Revalidate even when the URL came from the credential reader. Redirects
    # and environment proxy settings cannot carry the secret elsewhere.
    url = validate_ping_url(url.encode("ascii")) + ("" if healthy else "/fail")
    if opener is None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                             urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, data=b"", method="POST",
                                     headers={"User-Agent": "mail-guardian-observer/1"})
    try:
        with opener.open(request, timeout=PING_SECONDS) as response:
            body = response.read(1025)
            if response.status != 200 or len(body) > 1024 or body.strip() != b"OK":
                fail("monitor_response_rejected")
    except Exception:
        # urllib errors contain the URL, including its bearer token. Never
        # surface an exception string to stderr, the journal or the caller.
        fail("monitor_delivery_failed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance", required=True)
    args = parser.parse_args(argv)
    if not INSTANCE.fullmatch(args.instance):
        print("guardian observer: invalid instance", file=sys.stderr)
        return 2
    try:
        if os.geteuid() == 0 or pwd.getpwuid(os.geteuid()).pw_name != "mg-" + args.instance:
            fail("wrong_observer_user")
    except Exception:
        print("guardian observer: dedicated instance user required", file=sys.stderr)
        return 2
    try:
        url = credential_url(os.environ.get("CREDENTIALS_DIRECTORY"))
    except Exception:
        print("guardian observer: monitor credential unavailable", file=sys.stderr)
        return 2
    healthy, deferred = False, False
    try:
        result = observe(args.instance)
        healthy, deferred = result == "healthy", result == "defer"
    except Exception:
        # Local TOML/SQLite errors can include account data or paths. Log only
        # the aggregate outcome; the worker's private diagnostics remain local.
        pass
    if deferred:
        print("guardian observer: work in progress; no health signal sent")
        return 0
    try:
        send_ping(url, healthy)
    except Exception:
        print("guardian observer: monitor delivery failed", file=sys.stderr)
        return 2
    print("guardian observer: " + ("healthy" if healthy else "unhealthy") + "; signal delivered")
    return 0 if healthy else 1


if __name__ == "__main__":
    sys.exit(main())
