#!/usr/bin/env python3
"""Experimental, local-only write-ahead journal for Docker patch transactions.

This module records a bounded, plan-bound inventory and ordered phases. It does
not update packages, verify Guardian health, own a Guardian fence, emit alerts,
or authorize recovery. In particular, journal commit and removal of Guardian's
separate migration marker are not atomic. Do not deploy this prototype without
an independently qualified reconciliation and recovery design. Per-transaction
locks also do not serialize different transactions: the updater needs its own
stable global lock and Guardian's qualified fence.
"""

import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat


class JournalError(RuntimeError):
    pass


class DurabilityError(JournalError):
    """A failed write/fsync may have left an old or new state on disk."""


PACKAGES = frozenset({"docker-ce", "docker-ce-cli", "containerd.io",
                      "docker-buildx-plugin", "docker-compose-plugin"})
SERVICES = frozenset({"redis", "rspamd", "unbound"})
IDENTIFIER = re.compile(r"[0-9]{8}T[0-9]{6}Z-[a-z0-9_]{8}\Z")
PACKAGE = re.compile(r"[a-z0-9][a-z0-9.+:-]{0,127}\Z")
VERSION = re.compile(r"[A-Za-z0-9.+:~_-]{1,160}\Z")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
IMAGE = re.compile(r"sha256:[a-f0-9]{64}\Z")
MAX_BYTES = 4 * 1024 * 1024
MAX_INVENTORY = 20000
LOCK = ".journal.lock"
RECORD = "transaction.json"
NEXT = {
    "prepared": frozenset({"fence_creating", "aborted"}),
    "fence_creating": frozenset({"fenced", "pre_mutation_clear_intent", "recovery_required"}),
    "fenced": frozenset({"mutation_pending", "pre_mutation_clear_intent", "recovery_required"}),
    "pre_mutation_clear_intent": frozenset({"pre_mutation_recovered", "recovery_required"}),
    "mutation_pending": frozenset({"verified", "recovery_required"}),
    "verified": frozenset({"unfence_intent", "recovery_required"}),
    "unfence_intent": frozenset({"completed", "recovery_required"}),
    "aborted": frozenset(),
    "completed": frozenset(),
    "pre_mutation_recovered": frozenset(),
    "recovery_required": frozenset(),
}
PHASE_GENERATIONS = {
    "prepared": frozenset({0}), "fence_creating": frozenset({1}),
    "fenced": frozenset({2}), "mutation_pending": frozenset({3}),
    "verified": frozenset({4}), "unfence_intent": frozenset({5}),
    "completed": frozenset({6}), "aborted": frozenset({1}),
    "pre_mutation_clear_intent": frozenset({2, 3}),
    "pre_mutation_recovered": frozenset({3, 4}),
    "recovery_required": frozenset({2, 3, 4, 5, 6}),
}


def _keys(value, required):
    return isinstance(value, dict) and set(value) == set(required)


def _text(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def validate_plan(plan):
    """Reject extra fields: plans contain identities and hashes, never secrets."""
    if not _keys(plan, {"packages", "inventory", "containers"}):
        raise JournalError("invalid plan fields")
    inventory = plan["inventory"]
    if (not isinstance(inventory, dict) or not 1 <= len(inventory) <= MAX_INVENTORY or
            any(not _text(k, PACKAGE) or not _text(v, VERSION) for k, v in inventory.items())):
        raise JournalError("invalid installed package inventory")
    packages = plan["packages"]
    if not isinstance(packages, list) or not 1 <= len(packages) <= len(PACKAGES):
        raise JournalError("invalid target package list")
    names = set()
    for item in packages:
        if not _keys(item, {"name", "installed", "target", "old_sha256", "new_sha256"}):
            raise JournalError("invalid target package fields")
        name = item["name"]
        if (not isinstance(name, str) or name not in PACKAGES or name in names or
                not _text(item["installed"], VERSION) or not _text(item["target"], VERSION) or
                item["installed"] == item["target"] or inventory.get(name) != item["installed"] or
                not _text(item["old_sha256"], SHA256) or not _text(item["new_sha256"], SHA256)):
            raise JournalError("invalid target package identity")
        names.add(name)
    containers = plan["containers"]
    if not isinstance(containers, dict) or set(containers) != SERVICES:
        raise JournalError("invalid Guardian container snapshot")
    for item in containers.values():
        if (not _keys(item, {"image_id", "mounts_sha256", "ports_sha256"}) or
                not _text(item["image_id"], IMAGE) or
                not _text(item["mounts_sha256"], SHA256) or
                not _text(item["ports_sha256"], SHA256)):
            raise JournalError("invalid Guardian container identity")
    return plan


def _canonical(value):
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise JournalError("invalid JSON value") from exc
    if len(encoded) > MAX_BYTES:
        raise JournalError("journal size limit exceeded")
    return encoded


def plan_digest(plan):
    return hashlib.sha256(_canonical(validate_plan(plan))).hexdigest()


def container_evidence(snapshot):
    """Bind the actual three-service snapshot without retaining mount paths.

    `snapshot` is the updater's `{service: [image_id, mounts_json, ports_json]}`.
    JSON object keys are sorted before hashing; array order is preserved. An
    ambiguous or reordered result may therefore defer recovery conservatively.
    This is identity evidence only, not a health or model-integrity check.
    """
    if not isinstance(snapshot, dict) or set(snapshot) != SERVICES:
        raise JournalError("invalid Guardian container snapshot")
    evidence = {}
    for name, row in snapshot.items():
        if (not isinstance(row, (list, tuple)) or len(row) != 3 or
                not _text(row[0], IMAGE) or not all(isinstance(x, str) for x in row[1:]) or
                any(len(x) > MAX_BYTES for x in row[1:])):
            raise JournalError("invalid Guardian container snapshot entry")
        try:
            mounts = json.loads(row[1], object_pairs_hook=_pairs)
            ports = json.loads(row[2], object_pairs_hook=_pairs)
        except (ValueError, UnicodeError) as exc:
            raise JournalError("invalid Guardian mount or port data") from exc
        evidence[name] = {"image_id": row[0],
                          "mounts_sha256": hashlib.sha256(_canonical(mounts)).hexdigest(),
                          "ports_sha256": hashlib.sha256(_canonical(ports)).hexdigest()}
    return evidence


def _private_dir(fd, owner):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
        raise JournalError("unsafe private journal directory")


def _open_state_root(path, owner):
    """Walk from / with no symlinks and no untrusted writable ancestors."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or path == Path("/"):
        raise JournalError("journal root must be an absolute non-root path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, owner} or
                    stat.S_IMODE(info.st_mode) & 0o022):
                raise JournalError("unsafe journal ancestor")
        _private_dir(fd, owner)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_txn(state_root, transaction_id, owner):
    if not _text(transaction_id, IDENTIFIER):
        raise JournalError("invalid transaction identity")
    root = _open_state_root(state_root, owner)
    try:
        fd = os.open(transaction_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=root)
    finally:
        os.close(root)
    try:
        _private_dir(fd, owner)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_private_file(parent, name, owner, flags):
    # Do not block if a corrupted path names a FIFO; fstat below then rejects it.
    fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=parent)
    try:
        opened = os.fstat(fd)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != owner or
                stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1 or
                (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)):
            raise JournalError("unsafe journal file")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _lock(parent, owner, create=False):
    flags = os.O_RDWR | (os.O_CREAT if create else 0)
    fd = _open_private_file(parent, LOCK, owner, flags)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Check again after acquiring the lock: a replaced name must never
        # allow two processes to coordinate on different inodes.
        opened = os.fstat(fd)
        current = os.stat(LOCK, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != owner or
                stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1 or
                (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)):
            raise JournalError("journal lock changed while acquiring it")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise JournalError("duplicate journal field")
        result[key] = value
    return result


def _read(parent, transaction_id, owner):
    fd = _open_private_file(parent, RECORD, owner, os.O_RDONLY)
    try:
        data = bytearray()
        while len(data) <= MAX_BYTES:
            block = os.read(fd, min(65536, MAX_BYTES + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        if len(data) > MAX_BYTES:
            raise JournalError("journal size limit exceeded")
    finally:
        os.close(fd)
    try:
        record = json.loads(data, object_pairs_hook=_pairs)
    except (ValueError, UnicodeError) as exc:
        raise JournalError("invalid journal JSON") from exc
    if (not _keys(record, {"schema", "transaction_id", "phase", "generation", "plan", "plan_sha256"}) or
            not isinstance(record["schema"], int) or isinstance(record["schema"], bool) or record["schema"] != 1 or
            record["transaction_id"] != transaction_id or not isinstance(record["phase"], str) or record["phase"] not in NEXT or
            isinstance(record["generation"], bool) or not isinstance(record["generation"], int) or
            record["generation"] not in PHASE_GENERATIONS[record["phase"]] or
            not _text(record["plan_sha256"], SHA256) or
            not hmac.compare_digest(record["plan_sha256"], plan_digest(record["plan"]))):
        raise JournalError("journal record or plan binding is invalid")
    return record


def _write(parent, record):
    data = _canonical(record) + b"\n"
    if len(data) > MAX_BYTES:
        raise JournalError("journal size limit exceeded")
    temporary = ".journal-" + secrets.token_hex(16)
    fd = None
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("short journal write")
            offset += written
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(temporary, RECORD, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    except OSError as exc:
        # An fsync/rename failure means the persisted phase can be either old
        # or new. Callers must halt and retain the separate Guardian fence.
        raise DurabilityError("journal write failed; durable state is uncertain") from exc
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass


def initialize(state_root, transaction_id, plan, *, _test_expected_uid=None):
    """Initialize an existing private transaction directory exactly once.

    Production callers omit `_test_expected_uid`; non-root overrides are solely
    for isolated temporary-directory tests, not a production CLI or service.
    """
    owner = 0 if _test_expected_uid is None else _test_expected_uid
    digest = plan_digest(plan)
    parent = _open_txn(state_root, transaction_id, owner)
    try:
        lock = _lock(parent, owner, create=True)
        try:
            try:
                os.stat(RECORD, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise JournalError("transaction already initialized")
            record = {"schema": 1, "transaction_id": transaction_id, "phase": "prepared",
                      "generation": 0, "plan": plan, "plan_sha256": digest}
            _write(parent, record)
            return record
        finally:
            os.close(lock)
    finally:
        os.close(parent)


def read(state_root, transaction_id, *, _test_expected_uid=None):
    owner = 0 if _test_expected_uid is None else _test_expected_uid
    parent = _open_txn(state_root, transaction_id, owner)
    try:
        lock = _lock(parent, owner)
        try:
            return _read(parent, transaction_id, owner)
        finally:
            os.close(lock)
    finally:
        os.close(parent)


def advance(state_root, transaction_id, plan_sha256, expected_phase, expected_generation,
            next_phase, *, _test_expected_uid=None):
    """Append one ordered state transition; callers enforce real-world guards."""
    owner = 0 if _test_expected_uid is None else _test_expected_uid
    if (not _text(plan_sha256, SHA256) or not isinstance(expected_phase, str) or
            expected_phase not in NEXT or not isinstance(next_phase, str) or next_phase not in NEXT or
            isinstance(expected_generation, bool) or not isinstance(expected_generation, int)):
        raise JournalError("invalid transition arguments")
    parent = _open_txn(state_root, transaction_id, owner)
    try:
        lock = _lock(parent, owner)
        try:
            record = _read(parent, transaction_id, owner)
            if (not hmac.compare_digest(record["plan_sha256"], plan_sha256) or
                    record["phase"] != expected_phase or record["generation"] != expected_generation or
                    next_phase not in NEXT[expected_phase]):
                raise JournalError("stale, mismatched or disallowed transition")
            record["phase"] = next_phase
            record["generation"] += 1
            _write(parent, record)
            return record
        finally:
            os.close(lock)
    finally:
        os.close(parent)
