#!/usr/bin/env python3
"""EXPERIMENTAL pre-mutation fence reconciliation; not enabled or qualified.

This never reverts packages or model data. A journal that reached
``mutation_pending`` or later is deliberately outside automatic recovery.
The production command-line entry point is disabled pending disposable-host
and power-loss qualification and an independently delivered failure alert.
"""

from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import re
import stat

import engine
import transaction_journal as journal

UPDATER = "vps-docker-auto-update.service"
DPKG_LOCKS = (Path("/var/lib/dpkg/lock-frontend"), Path("/var/lib/dpkg/lock"))
SAFE_PHASES = {"prepared", "fence_creating", "fenced", "pre_mutation_clear_intent"}
SAFE_STOPPED_STATES = {"inactive", "failed"}
TEMP_MARKER_NAME = re.compile(r"\.vps-docker-marker-[a-z0-9_]{8}\Z")


class RecoveryError(RuntimeError):
    pass


def authorize(record, current_inventory, current_containers, updater_state, worker_states, dpkg_clean):
    """Reject ambiguity; a journal alone is not an authorization to clear a fence."""
    if (not isinstance(record, dict) or not isinstance(record.get("phase"), str) or
            record["phase"] not in SAFE_PHASES):
        raise RecoveryError("transaction may have reached package mutation")
    plan = record.get("plan")
    if not isinstance(plan, dict) or not isinstance(plan.get("inventory"), dict) or not isinstance(plan.get("containers"), dict):
        raise RecoveryError("incomplete transaction baseline")
    if not isinstance(updater_state, str) or updater_state not in SAFE_STOPPED_STATES:
        raise RecoveryError("updater has not stopped")
    if (not isinstance(worker_states, dict) or set(worker_states) != set(engine.WORKERS) or
            any(value != "inactive" for value in worker_states.values())):
        raise RecoveryError("Guardian worker or backup is active, failed or unknown")
    if dpkg_clean is not True:
        raise RecoveryError("package database is not known clean")
    if not isinstance(current_inventory, dict) or current_inventory != plan["inventory"]:
        raise RecoveryError("installed packages changed from the transaction baseline")
    if not isinstance(current_containers, dict) or current_containers != plan["containers"]:
        raise RecoveryError("Guardian containers differ from the transaction baseline")


def _marker():
    fd = os.open(engine.MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink not in (1, 2)):
            raise RecoveryError("unsafe migration marker")
        raw = os.read(fd, 4097)
        if not raw or len(raw) > 4096:
            raise RecoveryError("invalid migration marker")
        try:
            data = json.loads(raw, object_pairs_hook=journal._pairs)
        except (ValueError, UnicodeError) as exc:
            raise RecoveryError("invalid migration marker") from exc
        if (not isinstance(data, dict) or set(data) != {"owner", "transaction", "worker_authorized"} or
                data.get("owner") != "vps-docker-auto-update" or data.get("worker_authorized") is not False or
                not isinstance(data.get("transaction"), str) or
                not journal.IDENTIFIER.fullmatch(data["transaction"])):
            raise RecoveryError("marker is not an owned updater fence")
        identity = (info.st_dev, info.st_ino)
        if info.st_nlink == 2:
            _marker_alias(identity)
        return raw, identity, data["transaction"]
    finally:
        os.close(fd)


def _marker_alias(identity):
    """Find the sole own temporary alias left by interrupted publication."""
    aliases = []
    for path in engine.INSTANCE.iterdir():
        if not TEMP_MARKER_NAME.fullmatch(path.name):
            continue
        info = path.lstat()
        if (info.st_dev, info.st_ino) == identity:
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 2):
                raise RecoveryError("unsafe marker alias")
            aliases.append(path)
    if len(aliases) != 1:
        raise RecoveryError("marker alias is missing or ambiguous")
    return aliases[0]


def _remove_marker_alias(identity):
    info = os.lstat(engine.MARKER)
    if (info.st_dev, info.st_ino) != identity:
        raise RecoveryError("marker identity changed")
    if info.st_nlink == 1:
        return
    if info.st_nlink != 2:
        raise RecoveryError("unsafe marker link count")
    alias = _marker_alias(identity)
    alias.unlink()
    engine.sync_directory(engine.INSTANCE)


def _marker_optional():
    if not os.path.lexists(engine.MARKER):
        return None
    return _marker()


def _find_unresolved():
    """Require exactly one valid unfinished transaction, with no unknown state."""
    terminal = {"completed", "aborted", "pre_mutation_recovered"}
    found = []
    for path in engine.STATE.iterdir():
        info = path.lstat()
        if path.name == ".updater.lock":
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o600):
                raise RecoveryError("unsafe updater lock")
            continue
        if path.name in {".preflight", ".retired"}:
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                raise RecoveryError("unsafe preflight directory")
            continue
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                stat.S_IMODE(info.st_mode) != 0o700 or not journal.IDENTIFIER.fullmatch(path.name)):
            raise RecoveryError("unknown update state")
        record = journal.read(engine.STATE, path.name)
        if record["phase"] not in terminal:
            found.append(record)
    if len(found) != 1:
        raise RecoveryError("expected exactly one unfinished update transaction")
    return found[0]


def _lock_dpkg(stack):
    # dpkg uses POSIX record locks, acquired frontend then database. No lock
    # files are created or removed. Any contention leaves the fence intact.
    for path in DPKG_LOCKS:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
            raise RecoveryError("unsafe dpkg lock")
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RecoveryError("another package operation is active") from exc


def recover_once():
    """Try only a proven pre-dpkg recovery; never enable without full qualification."""
    if os.geteuid() != 0:
        raise RecoveryError("recovery requires root")
    root_fd = journal._open_state_root(engine.STATE, 0)
    os.close(root_fd)
    updater_fd = engine.acquire_updater_lock()
    try:
        initial = _marker_optional()
        record = _find_unresolved()
        if initial is not None and initial[2] != record["transaction_id"]:
            raise RecoveryError("marker does not match the unfinished transaction")
        if initial is not None and record["phase"] == "prepared":
            raise RecoveryError("prepared transaction unexpectedly has a marker")
        if engine.unit_state(UPDATER) not in SAFE_STOPPED_STATES:
            raise RecoveryError("updater has not stopped")
        fence_fd = engine.acquire_fence()
        try:
            with ExitStack() as stack:
                return _recover_under_locks(stack, initial, record)
        finally:
            os.close(fence_fd)
    finally:
        os.close(updater_fd)


def _recover_under_locks(stack, initial, record):
    """Run while both global updater and Guardian exclusive locks are held."""
    _lock_dpkg(stack)
    if _marker_optional() != initial:
        raise RecoveryError("marker changed")
    transaction = record["transaction_id"]
    if _find_unresolved() != record:
        raise RecoveryError("unfinished transaction changed")
    state = engine.unit_state(UPDATER)
    workers = {unit: engine.unit_state(unit) for unit in engine.WORKERS}
    audit = engine.run(["dpkg", "--audit"], timeout=10).stdout.strip() == ""
    snapshot = engine.container_snapshot()
    evidence = journal.container_evidence(snapshot)
    authorize(record, engine.installed_inventory(), evidence, state, workers, audit)
    # A reference match is not model-integrity proof. In this narrow
    # branch no updater package mutation could have started, and the
    # existing stack must also pass its direct bounded health checks.
    engine.health(snapshot, timeout=30)
    if (_marker_optional() != initial or _find_unresolved() != record or
            engine.unit_state(UPDATER) not in SAFE_STOPPED_STATES or
            any(engine.unit_state(unit) != "inactive" for unit in engine.WORKERS) or
            engine.installed_inventory() != record["plan"]["inventory"] or
            journal.container_evidence(engine.container_snapshot()) != record["plan"]["containers"]):
        raise RecoveryError("state changed during recovery")
    if record["phase"] == "prepared":
        journal.advance(engine.STATE, transaction, record["plan_sha256"], record["phase"],
                        record["generation"], "aborted")
        return "pre-mutation transaction safely aborted"
    if record["phase"] != "pre_mutation_clear_intent":
        record = journal.advance(engine.STATE, transaction, record["plan_sha256"], record["phase"],
                                 record["generation"], "pre_mutation_clear_intent")
    if initial is not None:
        _remove_marker_alias(initial[1])
        engine.clear_own_marker(initial[0], expected_identity=initial[1])
    journal.advance(engine.STATE, transaction, record["plan_sha256"], record["phase"],
                    record["generation"], "pre_mutation_recovered")
    return "pre-mutation fence recovered"

if __name__ == "__main__":
    raise SystemExit("Experimental recovery library: no production CLI or timer is enabled")
