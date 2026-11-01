#!/usr/bin/python3 -I
"""Root-only encrypted application backup, serialized with the Linux worker.

No retention deletion or remote upload is performed. The distinct backup
identity stays off the VPS; only its public age recipient is installed here.
"""

import contextlib
import datetime as dt
import fcntl
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile
import time
import tomllib

BASE = Path("/etc/mail-guardian")
STATE = Path("/var/lib/mail-guardian")
BACKUPS = Path("/var/backups/mail-guardian")
HELPER = Path("/usr/local/libexec/mail-guardian-maintenance")
CURRENT = Path("/opt/mail-guardian/current")
MAX_FILE = 256 << 20
MAX_TOTAL = 2 << 30
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}


class BackupError(Exception):
    pass


def copy_file_at(directory, name, target, budget):
    """Open relative to a pinned directory; links and special files fail closed."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=directory)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_size < 0 or before.st_size > MAX_FILE or
                budget[0] + before.st_size > MAX_TOTAL or budget[1] >= 100000):
            raise BackupError("backup source has an unsafe type, link or size")
        budget[0] += before.st_size
        budget[1] += 1
        with target.open("xb") as output:
            os.chmod(target, 0o600)
            remaining = before.st_size
            while remaining:
                block = source.read(min(remaining, 64 << 10))
                if not block:
                    raise BackupError("backup source was truncated")
                output.write(block)
                remaining -= len(block)
            if source.read(1):
                raise BackupError("backup source grew during capture")
            output.flush()
            os.fsync(output.fileno())
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise BackupError("backup source changed during capture")


def copy_tree_fd(source, target, budget):
    target.mkdir(mode=0o700)
    before = os.fstat(source)
    for name in sorted(os.listdir(source)):
        info = os.stat(name, dir_fd=source, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=source)
            try:
                copy_tree_fd(fd, target / name, budget)
            finally:
                os.close(fd)
        else:
            copy_file_at(source, name, target / name, budget)
    after = os.fstat(source)
    if (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
        raise BackupError("backup source directory changed during capture")


def copy_tree(source, target, budget):
    fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        copy_tree_fd(fd, target, budget)
    finally:
        os.close(fd)


def snapshot_database(source_dir, staging, destination, budget):
    """Copy frozen DB/WAL bytes without following worker-controlled links.

    SQLite then backs up the private copied view, including committed WAL.
    There is no root SQLite connection through a mutable worker-owned path.
    """
    with tempfile.TemporaryDirectory(prefix=".database-input-", dir=staging) as raw:
        raw = Path(raw)
        copy_file_at(source_dir, "guardian.db", raw / "guardian.db", budget)
        for suffix in ("-wal", "-journal"):
            try:
                copy_file_at(source_dir, "guardian.db" + suffix,
                             raw / ("guardian.db" + suffix), budget)
            except FileNotFoundError:
                pass
        deadline = time.monotonic() + 60

        def progress(_status, _remaining, _total):
            if time.monotonic() > deadline:
                raise BackupError("database capture timed out")

        with contextlib.closing(sqlite3.connect(raw / "guardian.db")) as source:
            with contextlib.closing(sqlite3.connect(destination)) as output:
                source.backup(output, pages=128, progress=progress)
                output.execute("PRAGMA journal_mode=DELETE")
                output.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
                if output.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                    raise BackupError("database integrity check failed")
        os.chmod(destination, 0o600)
        if destination.stat().st_size > MAX_FILE:
            raise BackupError("database capture exceeds size limit")


@contextlib.contextmanager
def exclusive_locks(instance, maintenance):
    """Use the same stable inode and lock order as the worker and helper."""
    root = BASE / instance
    maintenance.trusted_path(root, directory=True)
    with contextlib.ExitStack() as held:
        for path, mode in ((root / "migration.lock", 0o640),
                           (Path("/run/mail-guardian-maintenance-" + instance + ".lock"), 0o600)):
            if path.parent == Path("/run"):
                maintenance.trusted_path("/run", directory=True)
                fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
            else:
                maintenance.trusted_path(path)
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            lock = held.enter_context(os.fdopen(fd, "rb"))
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                    stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1):
                raise BackupError("unsafe backup serialization lock")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if os.path.lexists(root / "migration-pending"):
            raise BackupError("migration requires administrator recovery")
        yield


def capture(instance, staging, maintenance):
    root, state = BASE / instance, STATE / instance
    config = maintenance.trusted_path(root / "config.toml").read_bytes()
    if not config or len(config) > 64 << 10:
        raise BackupError("configuration exceeds the backup limit")
    parsed = tomllib.loads(config.decode())
    runtime = parsed.get("runtime", {})
    if (runtime.get("data_dir") != str(state) or
            runtime.get("database") != str(state / "guardian.db") or
            runtime.get("archive_dir") != str(state / "archive") or
            runtime.get("compose_file") != str(root / "deploy" / "compose.yaml")):
        raise BackupError("configuration does not match the fixed backup paths")
    budget = [0, 0]
    (staging / "configuration").mkdir(mode=0o700)
    (staging / "configuration" / "config.toml").write_bytes(config)
    credentials = root / "credentials"
    maintenance.trusted_path(credentials, directory=True, private=True)
    destination_credentials = staging / "configuration" / "credentials"
    destination_credentials.mkdir(mode=0o700)
    fd = os.open(credentials, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for name in ("imap-password", "rspamd-password", "archive-identity"):
            maintenance.trusted_path(credentials / name, private=True)
            copy_file_at(fd, name, destination_credentials / name, budget)
    finally:
        os.close(fd)
    copy_tree(root / "deploy", staging / "configuration" / "deploy", budget)
    fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        snapshot_database(fd, staging, staging / "guardian.db", budget)
        archive = os.open("archive", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=fd)
        try:
            copy_tree_fd(archive, staging / "archive", budget)
        finally:
            os.close(archive)
    finally:
        os.close(fd)
    release = CURRENT.resolve(strict=True)
    if release.parent != Path("/opt/mail-guardian/releases"):
        raise BackupError("release is outside the fixed release directory")
    maintenance.trusted_path(release, directory=True)
    copy_tree(release, staging / "release", budget)
    return budget[0]


def backup(instance, maintenance):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,28}", instance):
        raise BackupError("invalid instance")
    root = BASE / instance
    recipient = maintenance.trusted_path(root / "backup-recipient")
    if not re.fullmatch(r"age1[0-9a-z]{58}\n?", recipient.read_text()):
        raise BackupError("backup requires a distinct public age recipient")
    maintenance.trusted_path("/var/backups", directory=True)
    BACKUPS.mkdir(mode=0o700, exist_ok=True)
    maintenance.trusted_path(BACKUPS, directory=True, private=True)
    target = BACKUPS / instance
    target.mkdir(mode=0o700, exist_ok=True)
    maintenance.trusted_path(target, directory=True, private=True)
    space = os.statvfs(target)
    # Worst-case staging plus encrypted output must preserve the existing
    # two-GiB stop threshold, including the private SQLite working copy.
    reserve = (2 << 30) + 2 * (MAX_TOTAL + (128 << 20)) + MAX_FILE
    if space.f_flag & getattr(os, "ST_RDONLY", 1) or space.f_bavail * space.f_frsize < reserve:
        raise BackupError("backup storage cannot preserve its free-space reserve")
    with exclusive_locks(instance, maintenance):
        dispatcher = maintenance.Dispatcher(instance)
        dispatcher.dispatch("deep-check")
        with tempfile.TemporaryDirectory(prefix=".staging-", dir=target) as temporary:
            staging = Path(temporary)
            paused = False
            try:
                # Rspamd can write autonomous model updates. Stop it before
                # crossing the database/archive/model capture boundary.
                paused = True
                dispatcher.compose("stop", "--timeout", "30", "rspamd", timeout=60)
                captured = capture(instance, staging, maintenance)
                recovery = CURRENT / "guardian-recovery"
                maintenance.trusted_path(recovery.resolve(strict=True))
                inspected = maintenance.run([str(recovery), "inspect-snapshot", "--config",
                                             str(staging / "configuration" / "config.toml"),
                                             "--database", str(staging / "guardian.db"),
                                             "--max-database-mib", "256"], timeout=90)
                # Pending mail/model intent must be reconciled before a
                # generation is advertised as a complete application backup.
                (staging / "inspection.json").write_bytes(inspected)
                # Verify every reference, decrypting with the original archive
                # identity and matching the stored complete message digest.
                # The verifier changes only its disposable output database;
                # the backup preserves the original journal bytes untouched.
                checked_database = staging / ".archive-verification.db"
                archive_report = maintenance.run([
                    str(recovery), "relocate-snapshot", "--config",
                    str(staging / "configuration" / "config.toml"),
                    "--source", str(staging / "guardian.db"), "--database", str(checked_database),
                    "--archive-root", str(staging / "archive"), "--target-archive-root",
                    str(STATE / instance / "archive"), "--identity-file",
                    str(staging / "configuration" / "credentials" / "archive-identity"),
                    "--preserve-policy-history"], timeout=300)
                checked_database.unlink()
                (staging / "archive-verification.json").write_bytes(archive_report)
                model = dispatcher.dispatch("export-redis")
                if len(model) < 16 or not re.fullmatch(b"REDIS[0-9]{4}", model[:9]):
                    raise BackupError("fresh model export is invalid")
                (staging / "redis.rdb").write_bytes(model)
                (staging / "backup.json").write_text(json.dumps({
                    "version": 1, "instance": instance,
                    "captured_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "scope": "coherent Linux application capture; no mailbox recovery or off-host copy proven",
                    "copied_source_bytes": captured,
                    "redis_bytes": len(model), "redis_sha256": hashlib.sha256(model).hexdigest(),
                }, indent=2) + "\n")
            finally:
                if paused:
                    dispatcher.compose("up", "--detach", "--wait", "rspamd", timeout=180)
                    dispatcher.ping()
            name = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + ".age"
            destination = target / name
            recovery = CURRENT / "guardian-recovery"
            maintenance.trusted_path(recovery.resolve(strict=True))
            sealed = maintenance.run([str(recovery), "seal-directory", "--source", str(staging),
                                      "--destination", str(destination), "--recipient-file", str(recipient)],
                                     timeout=300)
            receipt = json.loads(sealed)
            if not re.fullmatch(r"[0-9a-f]{64}", receipt.get("sha256", "")):
                raise BackupError("backup sealing receipt is invalid")
            # Retain this alongside the ciphertext on the Mac. Publication of
            # the receipt, after encryption, identifies a completed generation.
            receipt_fd, receipt_temporary = tempfile.mkstemp(prefix=".receipt-", dir=target)
            try:
                with os.fdopen(receipt_fd, "w") as output:
                    os.fchmod(output.fileno(), 0o600)
                    output.write(receipt["sha256"] + "  " + name + "\n")
                    output.flush()
                    os.fsync(output.fileno())
                os.link(receipt_temporary, target / (name + ".sha256"))
            finally:
                Path(receipt_temporary).unlink(missing_ok=True)
            directory = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            # Only completed encrypted generations are named *.age. No local
            # decryption identity is needed or retained by this uploader.
            print("Encrypted Guardian application backup completed: " + name)


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise BackupError("use root and one instance argument")
    os.umask(0o077)
    # Validate the dispatcher and each ancestor before importing root code.
    for path in (HELPER, *HELPER.parents):
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise BackupError("unsafe maintenance dispatcher")
    maintenance = importlib.machinery.SourceFileLoader("guardian_maintenance", str(HELPER)).load_module()
    backup(sys.argv[1], maintenance)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Source paths and dependency diagnostics can contain mailbox metadata.
        print("Guardian application backup failed; administrator inspection required.", file=sys.stderr)
        sys.exit(1)
