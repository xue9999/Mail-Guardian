#!/usr/bin/python3
"""Candidate updater backup primitive; caller must own both Guardian locks.

This module does not acquire locks or restart services. The caller must retain
its fence and the stopped scanner until the deployment decision is complete.
It reuses the installed backup's snapshot and archive-verification functions.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile

VOLUME_ROOT = Path('/var/lib/docker/volumes')
VOLUMES = {'rspamd': 'mail-guardian-pilot_rspamd_data',
           'unbound': 'mail-guardian-pilot_unbound_state'}


def checked_command(maintenance, stage, args, timeout):
    try:
        return maintenance.run(args, timeout=timeout)
    except Exception as exc:
        raise RuntimeError('backup ' + stage + ' failed') from exc


def volume_tar(source, destination):
    """Capture stopped volume content; sockets are ephemeral, links forbidden."""
    total = 0
    with tarfile.open(destination, 'x:gz') as archive:
        for base, dirs, files in os.walk(source, followlinks=False):
            base = Path(base)
            for name in sorted(dirs + files):
                path = base / name
                info = path.lstat()
                if stat.S_ISSOCK(info.st_mode):
                    continue
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    raise RuntimeError('unsupported special file in stopped volume')
                if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                    raise RuntimeError('hard-linked file in stopped volume')
                total += info.st_size if stat.S_ISREG(info.st_mode) else 0
                if total > 1 << 30:
                    raise RuntimeError('stopped volume exceeds capture limit')
                archive.add(path, arcname=str(path.relative_to(source)), recursive=False)
                after = path.lstat()
                if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise RuntimeError('stopped volume changed during capture')


def save_backup(backup, maintenance, dispatcher, assert_fence, validate_model=None):
    """Create an encrypted generation with DB, archives, release and model.

    `assert_fence` must check real lock ownership and writer quiescence; a
    caller-provided boolean alone is not evidence of a continuous fence.
    This candidate is not enabled on the live host.
    """
    instance = 'pilot'
    assert_fence()
    root = backup.BASE / instance
    recipient = maintenance.trusted_path(root / 'backup-recipient')
    if not re.fullmatch(r'age1[0-9a-z]{58}\n?', recipient.read_text()):
        raise RuntimeError('invalid backup recipient')
    target = backup.BACKUPS / instance
    maintenance.trusted_path(target, directory=True, private=True)
    space = os.statvfs(target)
    reserve = (2 << 30) + 2 * (backup.MAX_TOTAL + (128 << 20)) + backup.MAX_FILE
    if space.f_flag & getattr(os, 'ST_RDONLY', 1) or space.f_bavail * space.f_frsize < reserve:
        raise RuntimeError('insufficient backup storage')
    with tempfile.TemporaryDirectory(prefix='.update-staging-', dir=target) as temporary:
        staging = Path(temporary)
        assert_fence()
        captured = backup.capture(instance, staging, maintenance)
        # Installed backup.capture inherits its caller's umask; recovery's
        # config reader requires this file to be private even if invoked from
        # a unit with a permissive default umask.
        os.chmod(staging / 'configuration/config.toml', 0o600)
        recovery = backup.CURRENT / 'guardian-recovery'
        maintenance.trusted_path(recovery.resolve(strict=True))
        inspected = checked_command(maintenance, 'snapshot inspection', [str(recovery), 'inspect-snapshot', '--config',
                                     str(staging / 'configuration/config.toml'), '--database',
                                     str(staging / 'guardian.db'), '--max-database-mib', '256'], timeout=90)
        (staging / 'inspection.json').write_bytes(inspected)
        verification = staging / '.archive-verification.db'
        archive_report = checked_command(maintenance, 'archive verification', [
            str(recovery), 'relocate-snapshot', '--config', str(staging / 'configuration/config.toml'),
            '--source', str(staging / 'guardian.db'), '--database', str(verification),
            '--archive-root', str(staging / 'archive'), '--target-archive-root',
            str(backup.STATE / instance / 'archive'), '--identity-file',
            str(staging / 'configuration/credentials/archive-identity'), '--preserve-policy-history'], timeout=300)
        verification.unlink()
        (staging / 'archive-verification.json').write_bytes(archive_report)
        assert_fence()
        try:
            model = dispatcher.dispatch('export-redis')
        except Exception as exc:
            raise RuntimeError('backup Redis export failed') from exc
        if len(model) < 16 or not re.fullmatch(b'REDIS[0-9]{4}', model[:9]):
            raise RuntimeError('invalid Redis model export')
        if validate_model is not None:
            validate_model(model)
            assert_fence()
        (staging / 'redis.rdb').write_bytes(model)
        for component, volume in VOLUMES.items():
            source = VOLUME_ROOT / volume / '_data'
            # Docker owns each volume parent; the data directory itself is
            # normally owned by the container's unprivileged UID.
            maintenance.trusted_path(source.parent, directory=True)
            if not stat.S_ISDIR(source.lstat().st_mode):
                raise RuntimeError('volume data is not a directory')
            volume_tar(source, staging / (component + '-volume.tar.gz'))
        assert_fence()
        (staging / 'backup.json').write_text(json.dumps({
            'version': 1, 'instance': instance, 'captured_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'scope': 'update capture, requires same-fence and stopped scanner/resolver',
            'copied_source_bytes': captured, 'redis_bytes': len(model),
            'redis_sha256': hashlib.sha256(model).hexdigest(),
        }) + '\n')
        name = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ') + '.age'
        destination = target / name
        result = checked_command(maintenance, 'encryption', [str(recovery), 'seal-directory', '--source', str(staging),
                                  '--destination', str(destination), '--recipient-file', str(recipient)], timeout=300)
        receipt = json.loads(result)
        digest = receipt.get('sha256', '')
        if not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise RuntimeError('invalid encrypted backup receipt')
        fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size < 1:
                raise RuntimeError('unsafe encrypted backup')
            hasher = hashlib.sha256()
            with os.fdopen(os.dup(fd), 'rb') as source:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    hasher.update(block)
            if hasher.hexdigest() != digest:
                raise RuntimeError('encrypted backup digest mismatch')
            os.fsync(fd)
        finally:
            os.close(fd)
        assert_fence()
        sidecar = target / (name + '.sha256')
        fd = os.open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'w') as output:
            output.write(digest + '  ' + name + '\n')
            output.flush()
            os.fsync(output.fileno())
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try: os.fsync(fd)
        finally: os.close(fd)
        return {'name': name, 'sha256': digest, 'redis_sha256': hashlib.sha256(model).hexdigest()}
