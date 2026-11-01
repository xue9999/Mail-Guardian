#!/usr/bin/python3 -I
"""One-off update for an unused, unconfigured Linux pilot; not a general updater.

Requires externally trusted SHA-256 hashes of old and candidate manifests.
The candidate must be the exact installed package except the independently
reviewed maintenance.py and check_host.py. No mailbox or populated instance is
accepted. Scheduling stays off; old release is retained. An interrupted update
leaves a root-only pending marker requiring manual investigation/rollback.
"""

import argparse
import fcntl
import grp
import hashlib
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile

BASE = Path('/opt/mail-guardian')
CONF = Path('/etc/mail-guardian')
RUNTIME = Path('/run/mail-guardian-admin')
HELPER = Path('/usr/local/libexec/mail-guardian-maintenance')
RUNLOCK = Path('/run/mail-guardian-maintenance-pilot.lock')
MARKER = CONF / 'pilot-update-pending'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8'}
CHANGES = frozenset({'maintenance.py', 'check_host.py'})


def digest(file):
    h = hashlib.sha256()
    with file.open('rb') as source:
        for block in iter(lambda: source.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def verify_package(root, expected_manifest_sha256):
    if not re.fullmatch(r'[a-f0-9]{64}', expected_manifest_sha256):
        raise ValueError('trusted manifest digest is required')
    if not root.is_dir() or root.is_symlink():
        raise ValueError('release root must be a directory')
    manifest = root / 'SHA256SUMS'
    if manifest.is_symlink() or not manifest.is_file() or digest(manifest) != expected_manifest_sha256:
        raise ValueError('manifest digest mismatch')
    entries = {}
    for line in manifest.read_text().splitlines():
        if '  ' not in line:
            raise ValueError('invalid manifest')
        expected, name = line.split('  ', 1)
        rel = Path(name)
        if (not re.fullmatch(r'[a-f0-9]{64}', expected) or not name or rel.is_absolute()
                or '..' in rel.parts or str(rel) != name or name in entries or name == 'SHA256SUMS'):
            raise ValueError('invalid manifest entry')
        file = root / rel
        if file.is_symlink() or not file.is_file() or digest(file) != expected:
            raise ValueError('package file mismatch')
        entries[name] = expected
    actual = set()
    for item in root.rglob('*'):
        if item.is_symlink() or not (item.is_file() or item.is_dir()):
            raise ValueError('package contains unsupported filesystem entry')
        if item.is_file() and item != manifest:
            actual.add(str(item.relative_to(root)))
    if actual != set(entries):
        raise ValueError('package contains missing or unlisted files')
    return entries


def validate_changes(old, new):
    if old.keys() != new.keys():
        raise ValueError('candidate must have exactly the old package files')
    changed = {name for name in old if old[name] != new[name]}
    if not changed <= CHANGES or 'maintenance.py' not in changed:
        raise ValueError('candidate changes are not the reviewed pilot helper fix')


def trusted(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('an absolute path is required')
    for part in reversed((path, *path.parents)):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('path must be root-owned, non-writable and free of symlinks')


def command(args, expected=0):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, env=ENV, timeout=30)
    if result.returncode != expected:
        raise ValueError('required host check failed')
    return result.stdout.decode('utf-8', 'strict').strip()


def tree_digests(root):
    entries = {}
    for path in root.rglob('*'):
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError('unsafe deployment tree')
        if path.is_file():
            entries[str(path.relative_to(root))] = digest(path)
        elif not path.is_dir():
            raise ValueError('unexpected deployment object')
    return entries


def guard(old_root, old):
    trusted(CONF)
    trusted(CONF / 'instance')
    trusted(CONF / 'pilot')
    trusted(CONF / 'pilot' / 'credentials')
    trusted(CONF / 'pilot' / 'deploy')
    trusted(HELPER)
    if (CONF / 'instance').read_text().strip() != 'pilot':
        raise ValueError('not the expected pilot')
    if set(p.name for p in (CONF / 'pilot').iterdir()) != {'credentials', 'deploy'}:
        raise ValueError('pilot is configured or has unexpected state')
    if any((CONF / 'pilot' / 'credentials').iterdir()):
        raise ValueError('pilot credentials exist')
    data = Path('/var/lib/mail-guardian/pilot')
    info = data.lstat()
    worker = pwd.getpwnam('mg-pilot')
    if (worker.pw_uid == 0 or worker.pw_shell not in ('/usr/sbin/nologin', '/sbin/nologin')
            or worker.pw_dir != str(data) or grp.getgrgid(worker.pw_gid).gr_name != 'mg-pilot'
            or any(g.gr_gid != worker.pw_gid and 'mg-pilot' in g.gr_mem for g in grp.getgrall())):
        raise ValueError('worker identity or group policy changed')
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != worker.pw_uid or info.st_mode & 0o077:
        raise ValueError('unsafe worker directory')
    sudoers = Path('/etc/sudoers.d/mail-guardian')
    trusted(sudoers)
    if stat.S_IMODE(sudoers.stat().st_mode) != 0o440:
        raise ValueError('unsafe sudoers permissions')
    expected_sudo = ('Defaults:mg-pilot env_reset\nmg-pilot ALL=(root) NOPASSWD: ' +
                     ', '.join('/usr/local/libexec/mail-guardian-maintenance pilot ' + operation
                               for operation in ('up', 'down', 'status', 'deep-check', 'check-storage',
                                                 'check-persistence', 'export-redis')) + '\n')
    if sudoers.read_text() != expected_sudo:
        raise ValueError('pilot sudoers policy changed')
    command(['/usr/sbin/visudo', '-c'])
    # Probe the effective policy as well as the managed file. These probes
    # do not prove that no other command is permitted by a separate rule.
    command(['/usr/bin/sudo', '-n', '-u', 'mg-pilot', '/usr/bin/sudo', '-n', '-l',
             str(HELPER), 'pilot', 'status'])
    command(['/usr/bin/sudo', '-n', '-u', 'mg-pilot', '/usr/bin/sudo', '-n', '-l',
             '/usr/bin/id'], expected=1)
    # The unprivileged owner, not root, checks the worker-owned directory.
    command(['/usr/bin/sudo', '-n', '-u', 'mg-pilot', '/usr/bin/python3', '-I', '-c',
             'import os,sys; sys.exit(1 if any(os.scandir(sys.argv[1])) else 0)', str(data)])
    active = command(['/usr/bin/systemctl', 'is-active', 'mail-guardian@pilot.service'], expected=3)
    timer_active = command(['/usr/bin/systemctl', 'is-active', 'mail-guardian@pilot.timer'], expected=3)
    enabled = command(['/usr/bin/systemctl', 'is-enabled', 'mail-guardian@pilot.timer'], expected=1)
    if active != 'inactive' or timer_active != 'inactive' or enabled != 'disabled':
        raise ValueError('pilot is not stopped and disabled')
    pgrep = subprocess.run(['/usr/bin/pgrep', '-u', 'mg-pilot'], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, env=ENV, timeout=10)
    if pgrep.returncode != 1:
        raise ValueError('worker process exists or process check failed')
    for typ, args in [('container', ['ps', '-aq']), ('volume', ['volume', 'ls', '-q']),
                      ('network', ['network', 'ls', '-q'])]:
        output = command(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', *args,
                          '--filter', 'label=com.docker.compose.project=mail-guardian-pilot'])
        if output:
            raise ValueError('pilot Docker ' + typ + ' exists')
    if (RUNTIME / 'pilot').exists() or (RUNTIME / 'pilot').is_symlink():
        raise ValueError('pilot administrator runtime exists')
    if digest(HELPER) != old['maintenance.py']:
        raise ValueError('installed helper differs from old release')
    for unit in ('mail-guardian@.service', 'mail-guardian@.timer'):
        installed = Path('/etc/systemd/system') / unit
        trusted(installed)
        if digest(installed) != old[unit]:
            raise ValueError('installed systemd unit differs from old release')
    expected = {k[len('deploy/'):]: v for k, v in old.items() if k.startswith('deploy/')}
    if tree_digests(CONF / 'pilot' / 'deploy') != expected:
        raise ValueError('installed deployment tree differs from old release')
    current = BASE / 'current'
    current_info = current.lstat()
    if not stat.S_ISLNK(current_info.st_mode) or current_info.st_uid != 0 or current.readlink() != old_root:
        raise ValueError('current release changed')


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def replace_helper(source):
    fd, tmp = tempfile.mkstemp(prefix='.guardian-helper-', dir=HELPER.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(source.read_bytes())
            os.fchown(out.fileno(), 0, 0)
            os.fchmod(out.fileno(), 0o755)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, HELPER)
        sync_dir(HELPER.parent)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def replace_current(target):
    tmp = BASE / ('.guardian-current-' + str(os.getpid()))
    os.symlink(str(target), tmp)
    try:
        os.replace(tmp, BASE / 'current')
        sync_dir(BASE)
    finally:
        if tmp.is_symlink():
            tmp.unlink()


def update(candidate, old_sha, new_sha, check=False):
    if os.geteuid() != 0:
        raise ValueError('must run as root')
    for path in (BASE, BASE / 'releases', candidate, CONF, HELPER.parent):
        trusted(path)
    old_root = BASE / 'releases' / '0.6.1'
    trusted(old_root)
    for entry in old_root.rglob('*'):
        trusted(entry)
    for entry in candidate.rglob('*'):
        trusted(entry)
    old = verify_package(old_root, old_sha)
    new = verify_package(candidate, new_sha)
    validate_changes(old, new)
    if (old_root / 'VERSION').read_text().strip() != '0.6.1':
        raise ValueError('unexpected installed version')
    if MARKER.exists() or MARKER.is_symlink():
        raise ValueError('a previous update requires manual recovery')
    fd = os.open(RUNLOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+b') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('unsafe maintenance lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        guard(old_root, old)
        command(['/usr/bin/python3', '-I', str(candidate / 'check_host.py')])
        target = BASE / 'releases' / ('0.6.1-pilotfix-' + new_sha[:16])
        if target.exists() or target.is_symlink():
            raise ValueError('candidate release path already exists')
        if check:
            print('Unused pilot and candidate checks passed; no release or helper changed.')
            return
        # This marker precedes any staged release or switch. It is a recovery
        # record, not a service fence: after a crash an administrator must
        # inspect and restore the old helper and pointer before provisioning
        # or running the instance. This tool only accepts an empty pilot.
        marker_fd = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(marker_fd, 'w') as out:
            out.write('old=' + str(old_root) + '\nnew=' + str(target) + '\n')
            out.flush()
            os.fsync(out.fileno())
        sync_dir(CONF)
        helper_attempted = False
        pointer_attempted = False
        try:
            tmp = Path(tempfile.mkdtemp(prefix='.guardian-pilotfix-', dir=BASE / 'releases'))
            try:
                shutil.copytree(candidate, tmp, dirs_exist_ok=True)
                for entry in [tmp, *tmp.rglob('*')]:
                    os.chown(entry, 0, 0)
                    os.chmod(entry, 0o755 if entry.is_dir() or entry.name in ('guardian', 'maintenance.py', 'install.sh', 'install.py') else 0o644)
                verify_package(tmp, new_sha)
                for entry in tmp.rglob('*'):
                    if entry.is_file():
                        with entry.open('rb') as source:
                            os.fsync(source.fileno())
                directories = [entry for entry in tmp.rglob('*') if entry.is_dir()]
                for directory in sorted(directories, key=lambda p: len(p.parts), reverse=True):
                    sync_dir(directory)
                sync_dir(tmp)
                os.rename(tmp, target)
                sync_dir(target.parent)
            finally:
                if tmp.exists():
                    shutil.rmtree(tmp)
            guard(old_root, old)
            helper_attempted = True
            replace_helper(target / 'maintenance.py')
            pointer_attempted = True
            replace_current(target)
            if digest(HELPER) != new['maintenance.py'] or BASE.joinpath('current').readlink() != target:
                raise ValueError('post-update verification failed')
            verify_package(target, new_sha)
            command(['/usr/bin/python3', '-I', str(target / 'check_host.py')])
            guard(target, new)
        except Exception:
            # Preserve pending marker even if rollback appears successful; a
            # human must inspect the old and candidate releases before retry.
            if helper_attempted:
                try:
                    replace_helper(old_root / 'maintenance.py')
                except Exception:
                    pass
            if pointer_attempted:
                try:
                    replace_current(old_root)
                except Exception:
                    pass
            raise
        MARKER.unlink()
        sync_dir(CONF)
        print('Updated unused pilot; scheduling remains disabled. Old release retained: ' + str(old_root))
        print('New release: ' + str(target))
        print('Candidate manifest SHA-256: ' + new_sha)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate', required=True, type=Path)
    p.add_argument('--old-manifest-sha256', required=True)
    p.add_argument('--new-manifest-sha256', required=True)
    p.add_argument('--check', action='store_true', help='check the unused host and candidate without switching')
    args = p.parse_args()
    try:
        update(args.candidate, args.old_manifest_sha256, args.new_manifest_sha256, args.check)
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as exc:
        print('Pilot update stopped: ' + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
