#!/usr/bin/env python3
"""Publish one verified Guardian pilot state while migration-pending stays set.

This one-time administrator tool never starts mail work, adopts a policy, removes
migration-pending, or overwrites an existing configuration/credential/state. An
interruption retains the marker, phase journal, prepared tree and original empty
data directory for explicit recovery. It does not provide automatic failback.
"""

import argparse
import contextlib
import ctypes
import fcntl
import hashlib
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import tempfile
import time
import uuid

INSTANCE = Path('/etc/mail-guardian/pilot')
DATA = Path('/var/lib/mail-guardian/pilot')
CURRENT = Path('/opt/mail-guardian/current')
RELEASES = Path('/opt/mail-guardian/releases')
PROJECT = 'mail-guardian-pilot'
TARGET_VOLUME = PROJECT + '_redis_data'
MODEL_LABEL = 'org.mailguardian.model-import'
REDIS_IMAGE = 'redis:7.4.9-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8'}
MAX_FILES = 50_000
MAX_BYTES = 1 << 30
REQUIRED = {'config.toml', 'guardian.db', 'credentials/rspamd-password', 'credentials/archive-identity'}


def sha(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
        raise ValueError('an explicit SHA-256 digest is required')
    return value


def digest(path):
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_BYTES:
            raise ValueError('unsupported publication file')
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('publication file changed while reading')
    return h.hexdigest()


def trusted(path, *, directory=False, private=False):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(path):
        raise ValueError('absolute normalized administrator path required')
    for entry in reversed((path, *path.parents)):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe administrator path')
        if entry != path and not stat.S_ISDIR(info.st_mode):
            raise ValueError('unsafe administrator parent')
    info = path.lstat()
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError('unexpected administrator object type')
    if not directory and info.st_nlink != 1:
        raise ValueError('linked administrator file')
    if private and stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
        raise ValueError('private administrator object required')
    return info


def run(args, *, expected=0, timeout=120):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=ENV, timeout=timeout)
    if result.returncode != expected:
        raise RuntimeError('publication dependency failed; diagnostics suppressed')
    return result.stdout


def docker(*args):
    return run(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', *args])


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def rename_new(source, target):
    # Linux renameat2 makes the no-overwrite requirement atomic for directories.
    libc = ctypes.CDLL(None, use_errno=True)
    operation = getattr(libc, 'renameat2', None)
    if operation is None:
        raise RuntimeError('atomic no-replace rename is unavailable')
    operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    operation.restype = ctypes.c_int
    if operation(-100, os.fsencode(source), -100, os.fsencode(target), 1) != 0:
        raise OSError(ctypes.get_errno(), 'atomic publication rename failed')


def file_identity(info):
    # Reading may update access time; content/ownership/identity must not change.
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise ValueError('publication destination already exists')


def copy_exclusive(source, target, expected, *, mode=0o600, gid=0):
    # Both parent trees were checked under the exclusive migration fence.
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as incoming:
        before = os.fstat(incoming.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_BYTES:
            raise ValueError('unsupported copy source')
        out_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(out_fd, 'wb') as outgoing:
            h = hashlib.sha256()
            for block in iter(lambda: incoming.read(1 << 20), b''):
                outgoing.write(block)
                h.update(block)
            after = os.fstat(incoming.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or h.hexdigest() != expected:
                raise ValueError('publication source checksum changed')
            os.fchown(outgoing.fileno(), 0, gid)
            os.fchmod(outgoing.fileno(), mode)
            outgoing.flush()
            os.fsync(outgoing.fileno())
    sync_dir(target.parent)


def read_json(path, expected):
    trusted(path, private=True)
    if path.stat().st_size > 4 << 20 or digest(path) != sha(expected):
        raise ValueError('publication metadata checksum mismatch')
    return json.loads(path.read_text())


def verify_payload(payload, manifest, expected):
    trusted(payload, directory=True, private=True)
    metadata = read_json(manifest, expected)
    if set(metadata) != {'version', 'files'} or metadata['version'] != 1 or not isinstance(metadata['files'], dict):
        raise ValueError('unsupported payload manifest')
    files = metadata['files']
    if not REQUIRED <= set(files) or len(files) > MAX_FILES:
        raise ValueError('payload lacks required files or exceeds limit')
    for name, wanted in files.items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or str(relative) != name or (name not in REQUIRED and not name.startswith('archive/')):
            raise ValueError('unsupported payload manifest path')
        sha(wanted)
    actual, total = set(), 0
    for path in payload.rglob('*'):
        info = path.lstat()
        if path.is_symlink() or info.st_uid != 0:
            raise ValueError('unsafe payload object')
        if stat.S_ISDIR(info.st_mode):
            if stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('payload directories must be private')
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600:
            name = str(path.relative_to(payload))
            if name not in files or digest(path) != files[name]:
                raise ValueError('payload checksum mismatch or unlisted file')
            actual.add(name)
            total += info.st_size
        else:
            raise ValueError('unsupported payload object')
    if actual != set(files) or total > MAX_BYTES or not (payload / 'archive').is_dir():
        raise ValueError('payload inventory mismatch or byte limit exceeded')
    return files, total


def verify_release(expected):
    sha(expected)
    trusted(CURRENT.parent, directory=True)
    pointer = CURRENT.lstat()
    if pointer.st_uid != 0 or not stat.S_ISLNK(pointer.st_mode):
        raise ValueError('unsafe current release pointer')
    release = CURRENT.resolve(strict=True)
    if release.parent != RELEASES:
        raise ValueError('unexpected current release directory')
    trusted(release, directory=True)
    manifest = release / 'SHA256SUMS'
    trusted(manifest)
    if digest(manifest) != expected:
        raise ValueError('installed release manifest checksum mismatch')
    entries = {}
    for line in manifest.read_text().splitlines():
        match = re.fullmatch('([a-f0-9]{64})  (.+)', line)
        if not match:
            raise ValueError('invalid installed release manifest')
        wanted, name = match.groups()
        rel = Path(name)
        if rel.is_absolute() or '..' in rel.parts or str(rel) != name or name in entries:
            raise ValueError('unsafe installed release entry')
        trusted(release / name)
        if digest(release / name) != wanted:
            raise ValueError('installed release file checksum mismatch')
        entries[name] = wanted
    if not {'guardian', 'guardian-recovery'} <= set(entries):
        raise ValueError('release lacks publication validators')
    return release


def verify_model(report_path, report_sha, model_sha, release_sha):
    report = read_json(report_path, report_sha)
    if (report.get('success') is not True or report.get('cleanup_complete') is not True or
            report.get('normal_config_aof_restart') is not True or report.get('cleanup_errors') != 0 or
            report.get('target_volume') != TARGET_VOLUME or report.get('retained_volumes') != [TARGET_VOLUME] or
            report.get('image') != REDIS_IMAGE or
            report.get('source_sha256') != sha(model_sha) or report.get('release_manifest_sha256') != release_sha or
            not re.fullmatch('[a-f0-9]{32}', report.get('token', ''))):
        raise ValueError('model importer report is incomplete or mismatched')
    comparisons = report.get('comparisons')
    if not isinstance(comparisons, list) or len(comparisons) != 3 or any(item.get('equivalent') is not True for item in comparisons):
        raise ValueError('model importer equivalence checks are incomplete')
    labels = json.loads(docker('volume', 'inspect', '--format', '{{json .Labels}}', TARGET_VOLUME))
    if (labels.get(MODEL_LABEL) != report['token'] or labels.get('com.docker.compose.project') != PROJECT or labels.get('com.docker.compose.volume') != 'redis_data'):
        raise ValueError('target model volume does not match importer report')
    if docker('ps', '--all', '--filter', 'volume=' + TARGET_VOLUME, '--format', '{{.ID}}').strip():
        raise ValueError('target model volume is still attached to a container')
    return report


@contextlib.contextmanager
def exclusive_fence():
    root = trusted(INSTANCE, directory=True)
    lock = INSTANCE / 'migration.lock'
    before = trusted(lock)
    if stat.S_IMODE(root.st_mode) != 0o750 or stat.S_IMODE(before.st_mode) != 0o640 or before.st_gid != root.st_gid:
        raise ValueError('unsafe migration fence')
    fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('migration fence changed')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        trusted(INSTANCE / 'migration-pending', private=True)
        yield
    finally:
        os.close(fd)


def quiescent():
    for unit in ('mail-guardian@pilot.service', 'mail-guardian@pilot.timer'):
        if run(['/usr/bin/systemctl', 'show', '--property=ActiveState', '--value', unit]).strip() != b'inactive':
            raise ValueError('Guardian service and timer must be inactive')
    if run(['/usr/bin/systemctl', 'show', '--property=UnitFileState', '--value', 'mail-guardian@pilot.timer']).strip() != b'disabled':
        raise ValueError('Guardian timer must be disabled')
    run(['/usr/bin/pgrep', '-u', 'mg-pilot'], expected=1)
    if docker('ps', '--all', '--filter', 'label=com.docker.compose.project=' + PROJECT, '--format', '{{.ID}}').strip():
        raise ValueError('pilot Compose containers must be absent')


def empty_target(worker):
    trusted(DATA.parent, directory=True)
    info = DATA.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != worker.pw_uid or info.st_gid != worker.pw_gid or stat.S_IMODE(info.st_mode) != 0o700 or any(DATA.iterdir()):
        raise ValueError('original worker data directory must be completely empty and private')
    trusted(INSTANCE / 'credentials', directory=True, private=True)
    if {p.name for p in (INSTANCE / 'credentials').iterdir()} - {'imap-password'}:
        raise ValueError('unexpected existing target credentials')
    for name in ('config.toml', 'credentials/rspamd-password', 'credentials/archive-identity'):
        absent(INSTANCE / name)
    # A separately provisioned IMAP secret belongs to the coordinator. Preserve
    # its exact bytes/inode metadata and never copy, replace or print it here.
    imap = INSTANCE / 'credentials/imap-password'
    try:
        trusted(imap, private=True)
    except FileNotFoundError:
        return None
    return (file_identity(imap.stat()), digest(imap))


def verify_recovery(payload, release, files):
    cfg, db = payload / 'config.toml', payload / 'guardian.db'
    run([str(release / 'guardian'), '--config', str(cfg), 'server', 'validate-config', '--instance', 'pilot'])
    inspection = json.loads(run([str(release / 'guardian-recovery'), 'inspect-snapshot', '--config', str(cfg), '--database', str(db)]))
    if (inspection.get('database_ready') is not True or inspection.get('database_sha256') != files['guardian.db'] or inspection.get('latest_actual_run_status') != 'ok' or inspection.get('latest_actual_run_errors') != 0):
        raise ValueError('staged database inspection did not establish current healthy state')
    work = Path(tempfile.mkdtemp(prefix='.publication-verify-', dir=payload.parent))
    try:
        report = json.loads(run([str(release / 'guardian-recovery'), 'relocate-snapshot', '--config', str(cfg), '--source', str(db), '--database', str(work / 'verified.db'), '--archive-root', str(payload / 'archive'), '--target-archive-root', str(DATA / 'archive'), '--identity-file', str(payload / 'credentials/archive-identity'), '--preserve-policy-history'], timeout=660))
        if (report.get('source_database_sha256') != files['guardian.db'] or report.get('verified_archives') != inspection.get('distinct_archives') or report.get('policy_history_preserved') is not True):
            raise ValueError('complete staged archive verification failed')
    finally:
        shutil.rmtree(work)
    if digest(db) != files['guardian.db']:
        raise ValueError('source database changed during recovery verification')
    return inspection


def append_phase(journal, phase, **values):
    record = {'phase': phase, 'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), **values}
    with journal.open('a') as stream:
        stream.write(json.dumps(record) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def publish(payload, files, worker, report_path, inspection, inputs):
    # The journal is created before the first target-tree mutation. Keep every
    # partial object on failure; migration-pending remains the recovery fence.
    absent(report_path)
    journal = report_path.with_name(report_path.name + '.journal')
    fd = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    sync_dir(journal.parent)
    token = uuid.uuid4().hex
    transaction = DATA.parent / ('.pilot-publication-' + token)
    incoming = transaction / 'new-data'
    original = transaction / 'original-empty'
    phase = 'verified'
    append_phase(journal, phase, transaction=str(transaction))
    try:
        transaction.mkdir(mode=0o700)
        incoming.mkdir(mode=0o700)
        (incoming / 'archive').mkdir(mode=0o700)
        for name, wanted in sorted(files.items()):
            if name != 'guardian.db' and not name.startswith('archive/'):
                continue
            target = incoming / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            copy_exclusive(payload / name, target, wanted)
        for directory in sorted((p for p in incoming.rglob('*') if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
            sync_dir(directory)
        sync_dir(incoming)
        for entry in [*incoming.rglob('*'), incoming]:
            os.chown(entry, worker.pw_uid, worker.pw_gid, follow_symlinks=False)
        sync_dir(transaction)
        quiescent()
        imap_before = empty_target(worker)
        phase = 'prepared'
        append_phase(journal, phase)
        rename_new(DATA, original)
        os.chown(original, 0, 0)
        sync_dir(DATA.parent)
        sync_dir(transaction)
        phase = 'original-empty-retained'
        append_phase(journal, phase)
        # DATA is absent and its parent is root-controlled. No runtime may pass
        # migration-pending while these independent publications are incomplete.
        rename_new(incoming, DATA)
        sync_dir(DATA.parent)
        phase = 'data-published'
        append_phase(journal, phase)
        for name in ('config.toml', 'credentials/rspamd-password', 'credentials/archive-identity'):
            copy_exclusive(payload / name, INSTANCE / name, files[name], mode=0o640 if name == 'config.toml' else 0o600, gid=worker.pw_gid if name == 'config.toml' else 0)
            phase = 'published-' + name.replace('/', '-')
            append_phase(journal, phase)
        if imap_before is not None:
            imap = INSTANCE / 'credentials/imap-password'
            if file_identity(imap.stat()) != imap_before[0] or digest(imap) != imap_before[1]:
                raise ValueError('independent IMAP credential changed during publication')
        if digest(DATA / 'guardian.db') != files['guardian.db'] or digest(INSTANCE / 'config.toml') != files['config.toml']:
            raise ValueError('published state checksum mismatch')
        trusted(INSTANCE / 'migration-pending', private=True)
        phase = 'complete-awaiting-policy-adoption'
        report = {'success': True, 'phase': phase, 'migration_pending_preserved': True,
                  'mailbox_access': False, 'scheduling_changed': False,
                  'original_empty_directory': str(original), 'journal': str(journal),
                  'database_sha256': files['guardian.db'], 'config_sha256': files['config.toml'],
                  'archives': inspection['distinct_archives'], 'messages': inspection['messages'], **inputs}
        fd = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(report, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        sync_dir(report_path.parent)
        append_phase(journal, phase)
        return report
    except BaseException:
        append_phase(journal, 'interrupted-or-failed', last_phase=phase, transaction=str(transaction), migration_pending_preserved=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload', type=Path, required=True)
    parser.add_argument('--payload-manifest', type=Path, required=True)
    parser.add_argument('--payload-manifest-sha256', required=True)
    parser.add_argument('--model-report', type=Path, required=True)
    parser.add_argument('--model-report-sha256', required=True)
    parser.add_argument('--model-sha256', required=True)
    parser.add_argument('--release-manifest-sha256', required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    if not args.publish:
        print(json.dumps({'will_publish': False, 'instance': 'pilot', 'migration_pending_will_remain': True}))
        return
    if os.geteuid() != 0:
        raise ValueError('publication requires root')
    os.umask(0o077)
    trusted(args.report.parent, directory=True, private=True)
    absent(args.report)
    with exclusive_fence():
        quiescent()
        worker = pwd.getpwnam('mg-pilot')
        if (worker.pw_uid == 0 or worker.pw_dir != str(DATA) or
                worker.pw_shell not in ('/usr/sbin/nologin', '/sbin/nologin') or
                grp.getgrgid(worker.pw_gid).gr_name != 'mg-pilot'):
            raise ValueError('unexpected Guardian worker identity')
        empty_target(worker)
        files, total = verify_payload(args.payload, args.payload_manifest, args.payload_manifest_sha256)
        release = verify_release(args.release_manifest_sha256)
        verify_model(args.model_report, args.model_report_sha256, args.model_sha256, args.release_manifest_sha256)
        inspection = verify_recovery(args.payload, release, files)
        available = os.statvfs(DATA.parent).f_bavail * os.statvfs(DATA.parent).f_frsize
        if available < (2 << 30) + 2 * total:
            raise ValueError('publication needs payload space plus two GiB reserve')
        # Recheck exact staged bytes after all dependency checks, then publish.
        verify_payload(args.payload, args.payload_manifest, args.payload_manifest_sha256)
        report = publish(args.payload, files, worker, args.report, inspection,
                         {'payload_manifest_sha256': args.payload_manifest_sha256,
                          'model_sha256': args.model_sha256,
                          'model_import_report_sha256': args.model_report_sha256,
                          'release_manifest_sha256': args.release_manifest_sha256})
    print(json.dumps({'success': True, 'phase': report['phase'], 'migration_pending_preserved': True, 'report': str(args.report)}))


if __name__ == '__main__':
    main()
