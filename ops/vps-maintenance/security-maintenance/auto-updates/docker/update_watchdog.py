#!/usr/bin/env python3
"""EXPERIMENTAL local-only Docker-update watchdog; not installed or qualified.

This module emits a bounded local status record and local syslog events only.
It does not provide independently delivered notifications. A separate opt-in
CLI flag exercises pre-mutation recovery only; neither mode is qualified for
production and no timer is installed.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import syslog
import time

import engine
import pre_mutation_recovery as recovery
import transaction_journal as journal

UPDATER = recovery.UPDATER
UPDATER_TIMER = "vps-docker-auto-update.timer"
STATUS_ROOT = Path("/var/lib/vps-docker-update-monitor")
STATUS_FILE = "status.json"
TERMINAL = {"completed", "aborted", "pre_mutation_recovered"}
PRE_MUTATION = {"prepared", "fence_creating", "fenced", "pre_mutation_clear_intent"}
ACTIVE = {"active", "activating", "deactivating", "reloading"}
STOPPED = {"inactive", "failed"}
MAX_STATUS = 8192
MAX_ACTIVE_SECONDS = 30 * 60
# This bound assumes the prospective updater timer is configured daily. It is
# not appropriate for a weekly timer without changing the reviewed policy.
MAX_TIMER_AGE_SECONDS = 48 * 60 * 60
CODE = re.compile(r"[a-z0-9_]{1,80}\Z")


class WatchdogError(RuntimeError):
    pass


def unit_status():
    """Read only the fixed updater unit's bounded metadata; never parse logs."""
    result = engine.run(["systemctl", "show", UPDATER, "-p", "LoadState", "-p", "ActiveState",
                         "-p", "Result", "-p", "ExecMainStatus",
                         "-p", "ExecMainStartTimestampMonotonic"], timeout=10, check=False)
    fields = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            raise WatchdogError("invalid updater status")
        key, value = line.split("=", 1)
        if key in fields:
            raise WatchdogError("duplicate updater status")
        fields[key] = value
    if fields.get("LoadState") == "not-found":
        return {"load": "not-found", "active": "inactive", "result": "unknown", "exit": None,
                "active_age_seconds": None}
    if (result.returncode or fields.get("LoadState") != "loaded" or
            fields.get("ActiveState") not in ACTIVE | STOPPED or
            not fields.get("Result") or not fields.get("ExecMainStatus", "").isdigit() or
            not fields.get("ExecMainStartTimestampMonotonic", "").isdigit()):
        raise WatchdogError("cannot establish updater status")
    status = int(fields["ExecMainStatus"])
    if not 0 <= status <= 255:
        raise WatchdogError("invalid updater exit status")
    age = None
    started = int(fields["ExecMainStartTimestampMonotonic"])
    if fields["ActiveState"] in ACTIVE:
        if started <= 0:
            raise WatchdogError("updater start time is unknown")
        age = time.monotonic() - started / 1_000_000
        if age < 0:
            raise WatchdogError("updater start time is invalid")
    return {"load": "loaded", "active": fields["ActiveState"],
            "result": fields["Result"], "exit": status, "active_age_seconds": age}


def timer_status():
    """Read the timer's enablement and last/next trigger without changing it."""
    result = engine.run(["systemctl", "show", UPDATER_TIMER, "-p", "LoadState", "-p", "ActiveState",
                         "-p", "UnitFileState", "-p", "LastTriggerUSec", "-p", "NextElapseUSecRealtime"],
                        timeout=10, check=False)
    fields = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            raise WatchdogError("invalid updater timer status")
        key, value = line.split("=", 1)
        if key in fields:
            raise WatchdogError("duplicate updater timer status")
        fields[key] = value
    if fields.get("LoadState") == "not-found":
        return {"configured": False}
    if (result.returncode or fields.get("LoadState") != "loaded" or
            not {"ActiveState", "UnitFileState", "LastTriggerUSec", "NextElapseUSecRealtime"} <= set(fields)):
        raise WatchdogError("cannot establish updater timer status")
    last = fields["LastTriggerUSec"].strip()
    last_age = None
    if last not in {"", "n/a", "0"}:
        parsed = engine.run(["date", "--date", last, "+%s"], timeout=3, check=False)
        stamp = parsed.stdout.strip()
        if parsed.returncode or not stamp.isdigit():
            raise WatchdogError("cannot parse last updater timer trigger")
        last_age = time.time() - int(stamp)
        if last_age < -300:
            raise WatchdogError("updater timer trigger is in the future")
    return {"configured": True, "active": fields["ActiveState"], "enabled": fields["UnitFileState"],
            "next_set": fields["NextElapseUSecRealtime"].strip() not in {"", "n/a", "0"},
            "last_age_seconds": last_age}


def owned_marker():
    """Read the updater marker using the same nonblocking guarded parser as recovery."""
    marker = recovery._marker_optional()
    if marker is None:
        return None
    # A publication crash may leave one verified same-inode temporary alias;
    # recovery validates that exact case. Recheck the final path identity after
    # the parser returns so a replaced path is never reported as our marker.
    current = os.lstat(engine.MARKER)
    if (not stat.S_ISREG(current.st_mode) or current.st_uid != 0 or
            stat.S_IMODE(current.st_mode) != 0o600 or current.st_nlink not in (1, 2) or
            (current.st_dev, current.st_ino) != marker[1]):
        raise WatchdogError("migration marker changed")
    return marker


def state_snapshot():
    """Read owned marker and validated journals, rejecting unknown local state."""
    marker = owned_marker()
    if not os.path.lexists(engine.STATE):
        return marker, []
    fd = journal._open_state_root(engine.STATE, 0)
    os.close(fd)
    records = []
    for path in engine.STATE.iterdir():
        info = path.lstat()
        if path.name == ".updater.lock":
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o600):
                raise WatchdogError("unsafe updater lock")
            continue
        if path.name in {".preflight", ".retired"}:
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                raise WatchdogError("unsafe private update directory")
            continue
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                stat.S_IMODE(info.st_mode) != 0o700 or not journal.IDENTIFIER.fullmatch(path.name)):
            raise WatchdogError("unknown update state")
        record = journal.read(engine.STATE, path.name)
        if record["phase"] not in TERMINAL:
            records.append(record)
    return marker, records


def _result(code, level, transaction=None):
    # Only a fixed status code and validated transaction ID leave memory.
    result = {"code": code, "level": level}
    if transaction is not None:
        if not isinstance(transaction, str) or not journal.IDENTIFIER.fullmatch(transaction):
            raise WatchdogError("invalid transaction identity")
        result["transaction_id"] = transaction
    return result


def evaluate(unit, marker, records, *, timer=None, allow_recovery=False, recover=None):
    """Attempt recovery only after conservative prechecks; the adapter rechecks.

    `recover` must be the separately qualified implementation of recover_once.
    It must acquire the global, Guardian and dpkg locks and revalidate every
    baseline and service state. Successful unit tests here do not qualify it.
    """
    if not isinstance(unit, dict) or not isinstance(records, list):
        raise WatchdogError("invalid watchdog input")
    if not isinstance(unit.get("active"), str):
        raise WatchdogError("invalid updater state")
    if unit["active"] in ACTIVE:
        age = unit.get("active_age_seconds")
        if not isinstance(age, (int, float)) or isinstance(age, bool) or age < 0:
            return _result("updater_active_time_unknown", "attention")
        if age > MAX_ACTIVE_SECONDS:
            return _result("updater_active_too_long", "attention")
        return _result("update_in_progress", "info")
    if unit.get("active") not in STOPPED:
        return _result("updater_state_unknown", "attention")
    if len(records) > 1:
        return _result("multiple_unfinished_transactions", "attention")
    if any(not isinstance(record, dict) for record in records):
        raise WatchdogError("invalid journal snapshot")
    if marker is not None:
        if (not isinstance(marker, tuple) or len(marker) != 3 or
                not isinstance(marker[2], str) or not journal.IDENTIFIER.fullmatch(marker[2])):
            return _result("marker_unverifiable", "attention")
        if not records or records[0].get("transaction_id") != marker[2]:
            return _result("marker_without_matching_journal", "attention")
    if records:
        record = records[0]
        txn, phase = record.get("transaction_id"), record.get("phase")
        if not isinstance(txn, str) or not journal.IDENTIFIER.fullmatch(txn):
            raise WatchdogError("invalid transaction identity")
        if unit.get("load") != "loaded":
            return _result("updater_not_loaded_with_unfinished_transaction", "attention", txn)
        if not isinstance(phase, str) or phase not in PRE_MUTATION:
            return _result("manual_post_mutation_recovery_required", "attention", txn)
        if phase == "prepared" and marker is not None:
            return _result("unexpected_marker_for_prepared_transaction", "attention", txn)
        if not allow_recovery:
            return _result("pre_mutation_recovery_available", "attention", txn)
        if recover is None:
            raise WatchdogError("recovery adapter unavailable")
        try:
            recover()
        except Exception:
            # Never propagate potentially sensitive subprocess stderr, paths,
            # HTTP headers, or raw journal/marker content into status output.
            return _result("pre_mutation_recovery_deferred", "attention", txn)
        return _result("pre_mutation_recovered", "info", txn)
    if unit.get("load") == "not-found":
        return _result("updater_not_configured", "attention")
    if unit.get("load") != "loaded":
        return _result("updater_state_unknown", "attention")
    if unit.get("active") == "failed" or unit.get("result") != "success":
        return _result("last_update_failed", "attention")
    if unit.get("exit") == 2:
        return _result("updates_deferred_for_review", "attention")
    if unit.get("exit") != 0:
        return _result("updater_exit_unknown", "attention")
    if not isinstance(timer, dict) or timer.get("configured") is not True:
        return _result("updater_timer_not_configured", "attention")
    if timer.get("enabled") != "enabled" or timer.get("active") != "active" or timer.get("next_set") is not True:
        return _result("updater_timer_not_active", "attention")
    age = timer.get("last_age_seconds")
    if age is None:
        return _result("updater_timer_not_yet_triggered", "attention")
    if not isinstance(age, (int, float)) or isinstance(age, bool) or age < -300:
        return _result("updater_timer_time_unknown", "attention")
    if age > MAX_TIMER_AGE_SECONDS:
        return _result("updater_timer_stale", "attention")
    return _result("idle", "info")


def check_once(*, allow_recovery=False, status_reader=unit_status,
               state_reader=state_snapshot, timer_reader=timer_status, recover=recovery.recover_once):
    """Return only non-secret, local status; recovery is opt-in and unqualified."""
    try:
        unit = status_reader()
        if isinstance(unit, dict) and unit.get("active") in ACTIVE:
            return evaluate(unit, None, [])
        marker, records = state_reader()
        # Detect a service that started while the marker/journal snapshot was
        # read; recover_once itself independently takes and rechecks all locks.
        unit = status_reader()
        if isinstance(unit, dict) and unit.get("active") in ACTIVE:
            return evaluate(unit, None, [])
        # A broken timer query must not prevent an otherwise safe recovery of
        # an already fenced pre-mutation transaction. The recovery adapter
        # independently revalidates all locks, baseline and worker states.
        timer = (timer_reader() if isinstance(unit, dict) and unit.get("load") == "loaded" and
                 unit.get("active") == "inactive" and unit.get("result") == "success" and
                 unit.get("exit") == 0 and marker is None and not records else None)
        return evaluate(unit, marker, records, timer=timer, allow_recovery=allow_recovery, recover=recover)
    except recovery.RecoveryError:
        return _result("marker_or_recovery_state_unverifiable", "attention")
    except Exception:
        return _result("watchdog_state_unverifiable", "attention")


def _open_status_root():
    """Create only the fixed root-owned status directory under trusted /var/lib."""
    if STATUS_ROOT != Path("/var/lib/vps-docker-update-monitor"):
        raise WatchdogError("unexpected status destination")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    root = os.open("/", flags)
    try:
        var = os.open("var", flags, dir_fd=root)
        try:
            info = os.fstat(var)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise WatchdogError("unsafe status ancestor")
            parent = os.open("lib", flags, dir_fd=var)
        finally:
            os.close(var)
    finally:
        os.close(root)
    try:
        info = os.fstat(parent)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise WatchdogError("unsafe status parent")
        try:
            os.mkdir(STATUS_ROOT.name, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
        fd = os.open(STATUS_ROOT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                raise WatchdogError("unsafe status directory")
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


def _previous(fd):
    try:
        status = os.open(STATUS_FILE, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(status)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600):
            raise WatchdogError("unsafe previous status")
        data = os.read(status, MAX_STATUS + 1)
        if len(data) > MAX_STATUS:
            raise WatchdogError("status size limit exceeded")
        try:
            previous = json.loads(data, object_pairs_hook=journal._pairs)
        except (ValueError, UnicodeError, journal.JournalError) as exc:
            raise WatchdogError("invalid previous status") from exc
        if not isinstance(previous, dict):
            raise WatchdogError("invalid previous status")
        return (previous.get("code"), previous.get("level"), previous.get("transaction_id"))
    finally:
        os.close(status)


def write_status(result):
    """Atomically store a root-only status; syslog reports changes locally only."""
    if (not isinstance(result, dict) or set(result) - {"code", "level", "transaction_id"} or
            result.get("level") not in {"info", "attention"} or
            not isinstance(result.get("code"), str) or not CODE.fullmatch(result["code"])):
        raise WatchdogError("invalid status")
    if ("transaction_id" in result and (not isinstance(result["transaction_id"], str) or
                                       not journal.IDENTIFIER.fullmatch(result["transaction_id"]))):
        raise WatchdogError("invalid transaction identity")
    record = {"schema": 1, "checked_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), **result}
    data = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(data) > MAX_STATUS:
        raise WatchdogError("status size limit exceeded")
    parent = _open_status_root()
    temporary = ".status-" + secrets.token_hex(16)
    fd = None
    try:
        previous = _previous(parent)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        offset = 0
        while offset < len(data):
            count = os.write(fd, data[offset:])
            if count <= 0:
                raise OSError("short status write")
            offset += count
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(temporary, STATUS_FILE, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
        current = (result["code"], result["level"], result.get("transaction_id"))
        if previous != current:
            syslog.openlog("vps-docker-update-watchdog", syslog.LOG_PID, syslog.LOG_DAEMON)
            syslog.syslog(syslog.LOG_ERR if result["level"] == "attention" else syslog.LOG_INFO,
                          "local status: " + result["code"])
            syslog.closelog()
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true",
                      help="record local status only; do not attempt recovery")
    mode.add_argument("--recover-pre-mutation", action="store_true",
                      help="experimental: attempt only qualified pre-mutation reconciliation")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("local status check requires root")
    result = check_once(allow_recovery=args.recover_pre_mutation)
    try:
        write_status(result)
    except (OSError, WatchdogError):
        print(json.dumps(_result("local_status_write_failed", "attention"), sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 2 if result["level"] == "attention" else 0


if __name__ == "__main__":
    sys.exit(main())
