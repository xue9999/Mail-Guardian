#!/usr/bin/python3
"""Supervised systemd job for updating Guardian's pinned container images."""
import fcntl
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import image_discovery
import fenced_backup

BASE = Path('/etc/mail-guardian/pilot')
CURRENT = Path('/opt/mail-guardian/current')
RELEASES = Path('/opt/mail-guardian/releases')
RUNTIME = BASE / 'deploy' / 'compose.yaml'
HELPER = Path('/usr/local/libexec/mail-guardian-maintenance')
STATE = Path('/var/lib/mail-guardian-admin/auto-image-update')
MARKER = BASE / 'migration-pending'
JOURNAL = STATE / 'transaction.json'
DOCKER_PENDING = Path('/var/lib/vps-docker-simple-update/pending.json')
FOREIGN_PENDING = (
    Path('/var/lib/vps-ubuntu-update/pending.json'),
    Path('/var/lib/mail-guardian-application-update/pending.json'),
)
PACKAGES = {'redis', 'rspamd/rspamd', 'klutchell/unbound'}
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8'}
# Installed only after local checks and a supervised same-image rehearsal.
PRODUCTION_READY = True


def run(*args, capture=False, check=True):
    return subprocess.run(list(args), check=check, text=True, env=ENV,
                          timeout=180,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)


def atomic(path, data, mode):
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    tmp = Path(name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
        d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(d)
        finally: os.close(d)
    finally:
        tmp.unlink(missing_ok=True)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try: os.fsync(fd)
    finally: os.close(fd)


def durable_unlink(path):
    path.unlink()
    sync_dir(path.parent)


def sync_tree(root):
    """Flush staged files and directories before publishing a release."""
    dirs = [root]
    for base, children, files in os.walk(root, followlinks=False):
        base = Path(base)
        for name in children:
            child = base / name
            if child.is_symlink() or not child.is_dir():
                raise RuntimeError('unsafe staged directory')
            dirs.append(child)
        for name in files:
            fd = os.open(base / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try: os.fsync(fd)
            finally: os.close(fd)
    for directory in reversed(dirs): sync_dir(directory)


def check_release(root):
    manifest = (root / 'SHA256SUMS').read_text()
    expected = {}
    for line in manifest.splitlines():
        if not re.fullmatch(r'[a-f0-9]{64}  [A-Za-z0-9_./@-]+', line):
            raise RuntimeError('invalid release manifest')
        digest, name = line.split('  ', 1)
        if name.startswith('/') or '..' in Path(name).parts or name in expected:
            raise RuntimeError('unsafe release manifest path')
        expected[name] = digest
    actual = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and p.name != 'SHA256SUMS'}
    if actual != set(expected) or any(p.is_symlink() for p in root.rglob('*')):
        raise RuntimeError('release contents differ from manifest')
    for name, digest in expected.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError('release checksum mismatch')


def wait_inactive(unit):
    for _ in range(600):
        result = run('systemctl', 'show', unit, '-p', 'ActiveState', '--value', capture=True).stdout.strip()
        if result in ('inactive', 'failed'): return
        time.sleep(1)
    raise RuntimeError(unit + ' did not finish')


def make_release(rows):
    old = CURRENT.resolve(strict=True)
    if old.parent != RELEASES or RUNTIME.read_bytes() != (old / 'deploy/compose.yaml').read_bytes() or HELPER.read_bytes() != (old / 'maintenance.py').read_bytes():
        raise RuntimeError('installed Guardian release and configuration do not match')
    check_release(old)
    refs = [(x['installed']['ref'], x['candidate']['ref']) for x in rows if x['candidate']]
    stage = STATE / 'staging'
    if stage.exists(): shutil.rmtree(stage)
    shutil.copytree(old, stage)
    for oldref, newref in refs:
        for filename in (['deploy/compose.yaml', 'maintenance.py'] if oldref.startswith('rspamd/rspamd:') else ['deploy/compose.yaml']):
            path = stage / filename
            data = path.read_bytes()
            if data.count(oldref.encode()) != 1: raise RuntimeError('unexpected image pin in release')
            path.write_bytes(data.replace(oldref.encode(), newref.encode()))
    entries = []
    for line in (old / 'SHA256SUMS').read_text().splitlines():
        _, name = line.split('  ', 1)
        entries.append(hashlib.sha256((stage / name).read_bytes()).hexdigest() + '  ' + name + '\n')
    (stage / 'SHA256SUMS').write_text(''.join(entries))
    check_release(stage)
    sync_tree(stage)
    digest = hashlib.sha256((stage / 'SHA256SUMS').read_bytes()).hexdigest()
    target = RELEASES / ('0.6.1-auto-' + digest[:16])
    if target.exists():
        check_release(target)
        if (target / 'SHA256SUMS').read_bytes() != (stage / 'SHA256SUMS').read_bytes(): raise RuntimeError('release collision')
        shutil.rmtree(stage)
    else:
        os.rename(stage, target)
        sync_dir(RELEASES)
        sync_dir(STATE)
    return old, target


def isolated_command(ref, command, mounts=(), extra=()):
    """Run a bounded synthetic check with no network or production secrets."""
    name = 'guardian-update-check-' + uuid.uuid4().hex
    args = ['docker', 'run', '--rm', '--name', name, '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
            '--memory', '256m', '--cpus', '0.5', '--pids-limit', '64',
            '--tmpfs', '/tmp:rw,nosuid,size=16m,mode=1777', '--tmpfs', '/run:rw,nosuid,size=16m']
    for source, destination in mounts:
        args.extend(['--mount', f'type=bind,src={source},dst={destination},readonly'])
    args.extend(extra)
    try:
        return run(*args, '--entrypoint', command[0], ref, *command[1:], capture=True).stdout
    finally:
        # --rm handles ordinary exit; a client timeout can leave this exact
        # isolated container behind. Never prune or touch Guardian resources.
        run('docker', 'rm', '-f', name, capture=True, check=False)


def preflight(rows):
    """Check exact cached image identity, platform, user and config syntax."""
    for row in rows:
        candidate = row.get('candidate')
        if not candidate:
            continue
        ref, repo = candidate['ref'], row['repo']
        info = json.loads(run('docker', 'image', 'inspect', '--format', '{{json .}}', ref, capture=True).stdout)
        if info.get('Os') != 'linux' or info.get('Architecture') != 'amd64':
            raise RuntimeError('candidate image has wrong architecture')
        expected_digest = repo + '@' + candidate['index_digest']
        if expected_digest not in (info.get('RepoDigests') or []):
            raise RuntimeError('candidate image digest does not match reviewed index')
        config = info.get('Config') or {}
        volumes = set((config.get('Volumes') or {}).keys())
        if repo == 'rspamd/rspamd':
            if config.get('User') != '11333:11333' or volumes != {'/var/lib/rspamd'}:
                raise RuntimeError('Rspamd candidate changed its runtime user or volume layout')
            directory = BASE / 'deploy/rspamd/local.d'
            names = ('classifier-bayes.conf', 'fuzzy_check.conf', 'logging.inc',
                     'neural.conf', 'options.inc', 'redis.conf', 'url_redirector.conf')
            mounts = [(directory / name, '/etc/rspamd/local.d/' + name) for name in names]
            isolated_command(ref, ['rspamadm', 'configtest'], mounts,
                             ['--tmpfs', '/var/lib/rspamd:rw,nosuid,size=64m,uid=11333,gid=11333'])
        elif repo == 'redis':
            if volumes: raise RuntimeError('Redis candidate changed its image volume layout')
            output = isolated_command(ref, ['redis-server', '--version'])
            expected_version = candidate['tag'].removesuffix('-alpine')
            if not re.search(r'\bv=' + re.escape(expected_version) + r'(?=\s|$)', output):
                raise RuntimeError('Redis binary version does not match candidate')
        elif repo == 'klutchell/unbound':
            if volumes: raise RuntimeError('Unbound candidate changed its image volume layout')
            conf = BASE / 'deploy/unbound/unbound.conf'
            isolated_command(ref, ['/usr/sbin/unbound-checkconf', '/etc/unbound/unbound.conf'],
                             [(conf, '/etc/unbound/custom.conf.d/guardian.conf')])
        else:
            raise RuntimeError('unsupported Guardian image')


def check_redis_model(ref, model):
    """Boot candidate on a disposable read-only copy of the current model."""
    name = 'guardian-update-redis-' + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='redis-probe-', dir=STATE) as raw:
        directory = Path(raw)
        directory.chmod(0o755)
        path = directory / 'model.rdb'
        path.write_bytes(model)
        path.chmod(0o444)
        try:
            run('docker', 'run', '--detach', '--rm', '--name', name,
                '--network', 'none', '--read-only', '--user', 'redis',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--memory', '256m', '--cpus', '0.5', '--pids-limit', '96',
                '--tmpfs', '/tmp:rw,nosuid,size=16m,mode=1777',
                '--mount', f'type=bind,src={directory},dst=/model,readonly',
                ref, 'redis-server', '--dir', '/model', '--dbfilename', 'model.rdb',
                '--save', '', '--appendonly', 'no', '--port', '0',
                '--unixsocket', '/tmp/redis.sock', '--unixsocketperm', '700', capture=True)
            for _ in range(30):
                result = run('docker', 'exec', name, 'redis-cli', '-s', '/tmp/redis.sock',
                             '--raw', 'ping', capture=True, check=False)
                if result.returncode == 0 and result.stdout.strip() == 'PONG':
                    return
                time.sleep(1)
            raise RuntimeError('Redis candidate could not load the captured model')
        finally:
            run('docker', 'rm', '-f', name, capture=True, check=False)


def replace_current(release):
    atomic(RUNTIME, (release / 'deploy/compose.yaml').read_bytes(), 0o644)
    atomic(HELPER, (release / 'maintenance.py').read_bytes(), 0o755)
    link = CURRENT.with_name('current.auto-tmp')
    link.unlink(missing_ok=True)
    os.symlink(release, link)
    os.replace(link, CURRENT)
    d = os.open(RELEASES.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(d)
    finally: os.close(d)


def assert_fence_and_quiescence(migration, maint):
    """Check both held Linux flock descriptors and stopped model writers."""
    for fd, path in ((migration, BASE / 'migration.lock'),
                     (maint, Path('/run/mail-guardian-maintenance-pilot.lock'))):
        opened, named = os.fstat(fd), os.stat(path, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise RuntimeError('Guardian lock inode changed')
        info = Path('/proc/self/fdinfo') / str(fd)
        if not re.search(r'^lock:\s+\d+:\s+FLOCK\s+ADVISORY\s+WRITE\s+', info.read_text(), re.M):
            raise RuntimeError('Guardian exclusive lock is not held')
    if not MARKER.is_file() or MARKER.is_symlink():
        raise RuntimeError('Guardian marker missing or invalid')
    for name in ('mail-guardian-pilot-rspamd-1', 'mail-guardian-pilot-unbound-1'):
        status = run('docker', 'inspect', '--format', '{{.State.Running}}', name, capture=True).stdout.strip()
        if status != 'false':
            raise RuntimeError('Guardian dependent service is not stopped')


def locked_update(target, expected_old):
    migration = os.open(BASE / 'migration.lock', os.O_RDONLY | os.O_NOFOLLOW)
    maint = os.open('/run/mail-guardian-maintenance-pilot.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(migration, fcntl.LOCK_EX)
        fcntl.flock(maint, fcntl.LOCK_EX)
        if CURRENT.resolve() != expected_old or MARKER.exists() or not JOURNAL.exists():
            raise RuntimeError('Guardian changed during update preparation')
        if (RUNTIME.read_bytes() != (expected_old / 'deploy/compose.yaml').read_bytes()
                or HELPER.read_bytes() != (expected_old / 'maintenance.py').read_bytes()):
            raise RuntimeError('runtime configuration changed during update preparation')
        check_release(expected_old)
        atomic(MARKER, b'auto-image-update\n', 0o600)
        check_release(target)
        # Stopping the scanner also prevents autonomous writes to the Redis model.
        old_helper = importlib.machinery.SourceFileLoader('old_guardian_maintenance', str(HELPER)).load_module()
        dispatcher = old_helper.Dispatcher('pilot')
        dispatcher.dispatch('deep-check')
        try:
            dispatcher.compose('stop', '--timeout', '30', 'rspamd', 'unbound', timeout=90)
        except Exception as exc:
            raise RuntimeError('stopping Guardian scanner and resolver failed') from exc
        backup = importlib.machinery.SourceFileLoader('installed_guardian_backup', '/usr/local/libexec/mail-guardian-backup').load_module()
        previous = image_discovery.parse_compose(expected_old / 'deploy/compose.yaml')['redis']['ref']
        candidate = image_discovery.parse_compose(target / 'deploy/compose.yaml')['redis']['ref']
        validator = (lambda model: check_redis_model(candidate, model)) if candidate != previous else None
        receipt = fenced_backup.save_backup(backup, old_helper, dispatcher,
                                            lambda: assert_fence_and_quiescence(migration, maint), validator)
        assert_fence_and_quiescence(migration, maint)
        atomic(JOURNAL, json.dumps({'release': str(target), 'old_release': str(expected_old),
                                   'phase': 'backup_complete', 'backup': receipt}).encode(), 0o600)
        replace_current(target)
        new_helper = importlib.machinery.SourceFileLoader('new_guardian_maintenance', str(HELPER)).load_module()
        dispatcher = new_helper.Dispatcher('pilot')
        dispatcher.dispatch('up')
        dispatcher.dispatch('deep-check')
        # The worker requires no marker. Timers remain persistently disabled
        # and the journal remains until an actual postflight run succeeds.
        durable_unlink(MARKER)
    finally:
        os.close(maint); os.close(migration)


def ssh_check():
    run('systemctl', 'is-active', '--quiet', 'ssh.service')
    out = run('ssh-keyscan', '-T', '5', '-t', 'ed25519', '127.0.0.1', capture=True).stdout
    if not out.strip(): raise RuntimeError('SSH did not answer on loopback')


def recover_pending():
    """Recover forward only; never replace mailbox or model with older data."""
    if not JOURNAL.is_file() or JOURNAL.is_symlink():
        raise RuntimeError('orphan Guardian marker needs manual inspection')
    data = json.loads(JOURNAL.read_text())
    old, target = Path(data['old_release']), Path(data['release'])
    phase = data.get('phase')
    if (old.parent != RELEASES or target.parent != RELEASES or
            (target != old and not target.name.startswith('0.6.1-auto-')) or phase not in ('prepared', 'backup_complete')):
        raise RuntimeError('invalid Guardian update journal')
    check_release(old)
    check_release(target)
    if phase == 'backup_complete':
        receipt = data['backup']
        name, expected = receipt['name'], receipt['sha256']
        if not re.fullmatch(r'[0-9]{8}T[0-9]{6}\.[0-9]{6}Z\.age', name) or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise RuntimeError('invalid Guardian recovery point receipt')
        path = Path('/var/backups/mail-guardian/pilot') / name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            digest = hashlib.sha256()
            with os.fdopen(os.dup(fd), 'rb') as source:
                for block in iter(lambda: source.read(1024 * 1024), b''): digest.update(block)
            if digest.hexdigest() != expected:
                raise RuntimeError('Guardian recovery point digest mismatch')
        finally: os.close(fd)
    migration = os.open(BASE / 'migration.lock', os.O_RDONLY | os.O_NOFOLLOW)
    maint = os.open('/run/mail-guardian-maintenance-pilot.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(migration, fcntl.LOCK_EX)
        fcntl.flock(maint, fcntl.LOCK_EX)
        if MARKER.exists():
            if MARKER.is_symlink() or MARKER.read_bytes() != b'auto-image-update\n':
                raise RuntimeError('foreign Guardian migration marker')
        else:
            atomic(MARKER, b'auto-image-update\n', 0o600)
        # In 'prepared', publication had not begun. In 'backup_complete',
        # only move forward to the staged release and keep the current data.
        if phase == 'prepared':
            if (CURRENT.resolve() != old or RUNTIME.read_bytes() != (old / 'deploy/compose.yaml').read_bytes()
                    or HELPER.read_bytes() != (old / 'maintenance.py').read_bytes()):
                raise RuntimeError('pre-backup state changed; manual review required')
            destination = old
        else:
            destination = target
        module = importlib.machinery.SourceFileLoader('recovery_maintenance', str(HELPER)).load_module()
        dispatcher = module.Dispatcher('pilot')
        dispatcher.compose('stop', '--timeout', '30', 'rspamd', 'unbound', timeout=90)
        replace_current(destination)
        module = importlib.machinery.SourceFileLoader('recovered_maintenance', str(HELPER)).load_module()
        dispatcher = module.Dispatcher('pilot')
        dispatcher.dispatch('up')
        dispatcher.dispatch('deep-check')
        durable_unlink(MARKER)
    finally:
        os.close(maint)
        os.close(migration)
    ssh_check()
    run('systemctl', 'start', 'mail-guardian@pilot.service')
    run('systemctl', 'enable', '--now', 'mail-guardian@pilot.timer', 'mail-guardian-backup@pilot.timer')
    durable_unlink(JOURNAL)


def execute(recovery_only=False, no_update_only=False, allow_new_lines=False):
    if not PRODUCTION_READY:
        raise RuntimeError('automatic activation disabled: coherent fenced backup and candidate qualification are not implemented')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    foreign = [str(path) for path in FOREIGN_PENDING if os.path.lexists(path)]
    if foreign:
        if JOURNAL.exists() or no_update_only:
            raise RuntimeError('another updater has pending recovery: ' + ', '.join(foreign))
        print('Another updater has pending recovery; image update deferred: ' + ', '.join(foreign))
        return
    if no_update_only and (DOCKER_PENDING.exists() or JOURNAL.exists() or MARKER.exists()):
        raise RuntimeError('pending update prevents no-update-only check')
    if DOCKER_PENDING.exists():
        if JOURNAL.exists():
            raise RuntimeError('both Docker and Guardian image update journals are present')
        print('Docker package update requires recovery; image update deferred.', file=sys.stderr)
        return
    if JOURNAL.exists() or MARKER.exists():
        run('systemctl', 'disable', '--now', 'mail-guardian@pilot.timer', 'mail-guardian-backup@pilot.timer')
        wait_inactive('mail-guardian@pilot.service')
        wait_inactive('mail-guardian-backup@pilot.service')
        recover_pending()
        return
    if recovery_only:
        return
    report = image_discovery.discover(image_discovery.parse_compose(RUNTIME), patch_only=not allow_new_lines)
    if report.get('manual_review'):
        print('Image versions awaiting manual review: ' + json.dumps(report['manual_review']))
    blockers = report['errors']
    if blockers:
        print('Image update discovery blockers: ' + json.dumps(blockers), file=sys.stderr)
    if not report['attention']:
        if blockers: raise RuntimeError('image discovery incomplete; no compatible candidate found')
        print('Guardian images are current; no changes required.')
        return
    if no_update_only:
        raise RuntimeError('image candidate exists; no-update-only will not install it')
    for row in report['images']:
        if row['candidate']:
            run('docker', 'pull', row['candidate']['ref'])
    preflight(report['images'])
    old, target = make_release(report['images'])
    # Record intent before disabling the timers. Before the marker is created
    # no release or production volume is modified.
    atomic(JOURNAL, json.dumps({'release': str(target), 'old_release': str(old), 'phase': 'prepared'}).encode(), 0o600)
    try:
        run('systemctl', 'disable', '--now', 'mail-guardian@pilot.timer', 'mail-guardian-backup@pilot.timer')
        wait_inactive('mail-guardian@pilot.service')
        wait_inactive('mail-guardian-backup@pilot.service')
        locked_update(target, old)
        ssh_check()
        run('systemctl', 'start', 'mail-guardian@pilot.service')
        run('systemctl', 'enable', '--now', 'mail-guardian@pilot.timer', 'mail-guardian-backup@pilot.timer')
        durable_unlink(JOURNAL)
        print('Guardian image update finished and mailbox run succeeded.')
    except BaseException:
        # A mailbox run may already have modified state. Never restore an old
        # model automatically, and retain the journal for manual inspection.
        run('systemctl', 'disable', '--now', 'mail-guardian@pilot.timer', 'mail-guardian-backup@pilot.timer', check=False)
        raise
    if blockers:
        raise RuntimeError('some image updates remain blocked; see discovery errors')


def main():
    if os.geteuid() != 0: raise RuntimeError('root required')
    os.umask(0o077)
    if not PRODUCTION_READY:
        raise RuntimeError('automatic activation disabled: coherent fenced backup and candidate qualification are not implemented')
    if sys.argv[1:] not in ([], ['--recover'], ['--no-update-only'], ['--allow-new-lines']):
        raise RuntimeError('unsupported argument')
    fd = os.open('/run/mail-guardian-auto-update.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Another update holds the shared lock; retry on the next scheduled run.')
            return
        execute(recovery_only=(sys.argv[1:] == ['--recover']), no_update_only=(sys.argv[1:] == ['--no-update-only']),
                allow_new_lines=(sys.argv[1:] == ['--allow-new-lines']))
    finally: os.close(fd)


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        print('Guardian automatic image update failed: ' + str(exc), file=sys.stderr)
        sys.exit(1)
