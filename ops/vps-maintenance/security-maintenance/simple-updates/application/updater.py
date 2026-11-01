#!/usr/bin/python3
"""Guardian application dependency updates from a private approved source tree.

Builds have no live mounts or credentials. Activation reuses the installed
image updater's same-fence backup, forward recovery and actual-run postflight.
Only the two Go binaries change; installed Compose/helper/image pins survive.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

# Works under isolated Python (-I), without an ambient user import path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import source_snapshot as snapshots

STATE = Path('/var/lib/mail-guardian-application-update')
BASELINE = STATE / 'baseline.json'
PENDING = STATE / 'pending.json'
IMAGE_MODULE = Path('/opt/vps-maintenance/security-maintenance/simple-updates/guardian_images.py')
OTHER_PENDING = (Path('/var/lib/vps-ubuntu-update/pending.json'),
                 Path('/var/lib/vps-docker-simple-update/pending.json'),
                 Path('/var/lib/mail-guardian-admin/auto-image-update/transaction.json'))
GLOBAL_LOCK = Path('/run/mail-guardian-auto-update.lock')
TRUSTED_REMOTE = 'https://github.com/xue9999/Mail-Guardian.git'


def trusted_file(path, limit=8 << 20):
    path = Path(path)
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('application channel ancestor is not root controlled')
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > limit):
        raise RuntimeError('application channel file is not root controlled')


def artifact_path(path, work):
    """Reject sandbox paths that could make privileged promotion read outside it."""
    path, work = Path(path), Path(work)
    if not path.is_absolute() or path != work and work not in path.parents:
        raise RuntimeError('build artifact escaped its fixed workspace')
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeError('symlink or special parent in sandbox output')
        if parent == work: break
    if path.is_symlink(): raise RuntimeError('symlink in sandbox output')
    return path


def copy_artifact(source, destination, limit=64 << 20, minimum=1):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not minimum <= info.st_size <= limit:
            raise RuntimeError('unsafe candidate application artifact')
        out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(os.dup(fd), 'rb') as src, os.fdopen(os.dup(out), 'wb') as dst:
                remaining = info.st_size
                while remaining:
                    block = src.read(min(1024 * 1024, remaining))
                    if not block: raise RuntimeError('candidate artifact truncated')
                    dst.write(block); remaining -= len(block)
                if src.read(1): raise RuntimeError('candidate artifact grew')
                dst.flush(); os.fsync(out)
        finally: os.close(out)
        after = os.fstat(fd)
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RuntimeError('candidate artifact changed while copied')
    finally: os.close(fd)


def atomic(path, value):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(snapshots.canonical(value)); output.flush(); os.fsync(output.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        Path(name).unlink(missing_ok=True)


def load_engine():
    trusted_file(IMAGE_MODULE)
    sys.path.insert(0, str(IMAGE_MODULE.parent))
    spec = importlib.util.spec_from_file_location('application_image_engine', IMAGE_MODULE)
    engine = importlib.util.module_from_spec(spec); spec.loader.exec_module(engine)
    engine.STATE, engine.JOURNAL = STATE, PENDING
    return engine


def source_record(directory, manifest, parent=None, compiler_version=None, binaries=None):
    snapshots.verify_tree(directory, manifest)
    tree_hash = hashlib.sha256(snapshots.canonical(manifest)).hexdigest()
    sources = STATE / 'sources'; sources.mkdir(mode=0o700, exist_ok=True)
    target = sources / tree_hash
    if target.exists():
        snapshots.verify_tree(target, manifest, root_owned=True)
    else:
        snapshots.export(directory, manifest, target)
        # Copy was made by root, never the unprivileged build container.
        for path in target.rglob('*'):
            if path.is_file():
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try: os.fsync(fd)
                finally: os.close(fd)
        for path in [*sorted((x for x in target.rglob('*') if x.is_dir()), reverse=True), target, sources]:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
    return {'schema': 1, 'tree_sha256': tree_hash, 'source_directory': str(target),
            'files': manifest, 'parent_tree_sha256': parent,
            'compiler_version': compiler_version.removeprefix('go') if compiler_version else None,
            'applied_binary_sha256': binaries or {},
            'trust': 'private administrator-installed source; no automatic public publishing'}


def check_record(record):
    if record.get('schema') != 1:
        raise RuntimeError('unsupported source baseline schema')
    manifest = record['files']
    expected = hashlib.sha256(snapshots.canonical(manifest)).hexdigest()
    root = Path(record['source_directory'])
    if root != STATE / 'sources' / expected or record['tree_sha256'] != expected:
        raise RuntimeError('source baseline identity or location differs')
    snapshots.verify_tree(root, manifest, root_owned=True)
    return root


def load_baseline():
    trusted_file(BASELINE)
    record = json.loads(BASELINE.read_text())
    check_record(record)
    return record


def remote_discovery(installed_version):
    """Monitor the real owner repository; never install its older Mac release."""
    try:
        result = subprocess.run(['git', '-c', 'credential.helper=', 'ls-remote', '--tags', TRUSTED_REMOTE],
                                capture_output=True, text=True, check=True, timeout=60,
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/nonexistent',
                                     'GIT_TERMINAL_PROMPT': '0'})
        versions = {}
        for line in result.stdout.splitlines():
            match = re.fullmatch(r'([0-9a-f]{40})\s+refs/tags/v([0-9]+\.[0-9]+\.[0-9]+)(\^\{\})?', line)
            if match:
                version, commit = match[2], match[1]
                if match[3] or version not in versions: versions[version] = commit
        latest = max(versions, key=lambda value: tuple(map(int, value.split('.')))) if versions else None
        newer = latest is not None and tuple(map(int, latest.split('.'))) > tuple(map(int, installed_version.split('.')))
        return {'repository': TRUSTED_REMOTE, 'latest_stable_tag': latest,
                'commit': versions.get(latest), 'newer_source_release_detected': newer,
                'source_installation_blocker': ('New owner source must supply a reviewed Linux-compatible '
                                               'source generation before replacing the private server baseline.') if newer else None,
                'scope': 'source release detection; dependency updates independently use the approved private source'}
    except Exception as exc:
        return {'repository': TRUSTED_REMOTE, 'discovery_error': type(exc).__name__,
                'scope': 'source discovery incomplete; this does not block an independent compatible dependency fix'}


def promote_from_current(engine):
    """Finish source-baseline publication after success or a recovered crash."""
    release = engine.CURRENT.resolve(strict=True)
    metadata = release / 'application-build.json'
    if not metadata.exists(): return
    engine.check_release(release)
    trusted_file(metadata)
    data = json.loads(metadata.read_text())
    record = data['source_baseline']
    # The authenticated application backup includes this release payload.
    # Reconstruct the private update channel after a whole-server recovery.
    expected = hashlib.sha256(snapshots.canonical(record['files'])).hexdigest()
    expected_source = STATE / 'sources' / expected
    if record.get('tree_sha256') != expected or Path(record['source_directory']) != expected_source:
        raise RuntimeError('installed source recovery identity is invalid')
    if not expected_source.exists() and not expected_source.is_symlink():
        embedded = release / 'application-source'
        snapshots.verify_tree(embedded, record['files'], root_owned=True)
        source_record(embedded, record['files'], record.get('parent_tree_sha256'),
                      record.get('compiler_version'), record['applied_binary_sha256'])
    check_record(record)
    if set(record['applied_binary_sha256']) != {'guardian', 'guardian-recovery'}:
        raise RuntimeError('source promotion receipt omitted application binaries')
    for name, expected in record['applied_binary_sha256'].items():
        if name not in ('guardian', 'guardian-recovery') or snapshots.digest(engine.CURRENT / name) != expected:
            raise RuntimeError('installed application differs from source promotion receipt')
    if BASELINE.exists():
        current = load_baseline()
        if (current['tree_sha256'] == record['tree_sha256']
                and current['applied_binary_sha256'] == record['applied_binary_sha256']):
            return  # Retain a newer successful scan/fingerprint on the same source and binaries.
    atomic(BASELINE, record)


def make_release(engine, binaries, record, report):
    old = engine.CURRENT.resolve(strict=True)
    engine.check_release(old)
    if (engine.RUNTIME.read_bytes() != (old / 'deploy/compose.yaml').read_bytes()
            or engine.HELPER.read_bytes() != (old / 'maintenance.py').read_bytes()):
        raise RuntimeError('live Guardian runtime drift prevents application update')
    stage = STATE / ('stage-' + uuid.uuid4().hex)
    shutil.copytree(old, stage)
    try:
        embedded = stage / 'application-source'
        if embedded.exists(): shutil.rmtree(embedded)
        snapshots.export(Path(record['source_directory']), record['files'], embedded)
        for name in ('guardian', 'guardian-recovery'):
            path = Path(binaries[name]); info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 64 << 20:
                raise RuntimeError('unsafe candidate application binary')
            expected = record['applied_binary_sha256'][name]
            copy_artifact(path, stage / name); (stage / name).chmod(0o755)
            if snapshots.digest(stage / name) != expected:
                raise RuntimeError('candidate application changed during publication')
            with (stage / name).open('rb') as binary: header = binary.read(20)
            if header[:6] != b'\x7fELF\x02\x01' or header[18:20] != b'\x3e\x00':
                raise RuntimeError('candidate is not a 64-bit ELF')
        atomic(stage / 'application-build.json', {'schema': 1, 'source_baseline': record,
                                                'qualification': report})
        entries = sorted(str(p.relative_to(stage)) for p in stage.rglob('*')
                         if p.is_file() and p.name != 'SHA256SUMS')
        (stage / 'SHA256SUMS').write_text(''.join(snapshots.digest(stage / name) + '  ' + name + '\n' for name in entries))
        engine.check_release(stage); engine.sync_tree(stage)
        digest = snapshots.digest(stage / 'SHA256SUMS')
        # The shared forward-recovery implementation recognizes this prefix.
        target = engine.RELEASES / ('0.6.1-auto-' + digest[:16])
        if target.exists():
            engine.check_release(target)
            if (stage / 'SHA256SUMS').read_bytes() != (target / 'SHA256SUMS').read_bytes():
                raise RuntimeError('application release identity collision')
            shutil.rmtree(stage)
        else:
            os.rename(stage, target); engine.sync_dir(engine.RELEASES); engine.sync_dir(STATE)
        return old, target
    finally:
        if stage.exists(): shutil.rmtree(stage)


def activate(engine, old, target):
    atomic(PENDING, {'old_release': str(old), 'release': str(target), 'phase': 'prepared'})
    try:
        engine.run('systemctl', 'disable', '--now', 'mail-guardian@pilot.timer', 'mail-guardian-backup@pilot.timer')
        engine.wait_inactive('mail-guardian@pilot.service'); engine.wait_inactive('mail-guardian-backup@pilot.service')
        engine.locked_update(target, old)
        engine.ssh_check()
        engine.run('systemctl', 'start', 'mail-guardian@pilot.service')
        engine.run('systemctl', 'enable', '--now', 'mail-guardian@pilot.timer', 'mail-guardian-backup@pilot.timer')
        promote_from_current(engine)
        engine.durable_unlink(PENDING)
    except BaseException:
        engine.run('systemctl', 'disable', '--now', 'mail-guardian@pilot.timer', 'mail-guardian-backup@pilot.timer', check=False)
        raise


def qualified_inbox(engine, inbox, expected_receipt, adopt_only=False):
    """Accept one explicitly reviewed private candidate, never a public upload.

    The independent qualification receipt's expected SHA is supplied by the
    administrator over authenticated SSH. Every input is root controlled.
    """
    inbox = Path(inbox)
    if not re.fullmatch(r'[a-f0-9]{64}', expected_receipt or ''):
        raise RuntimeError('explicit reviewed qualification SHA-256 required')
    for path in (inbox / 'candidate.json', inbox / 'dependency-qualification.json',
                 inbox / 'source-manifest.json'):
        trusted_file(path)
    receipt = inbox / 'dependency-qualification.json'
    if snapshots.digest(receipt) != expected_receipt:
        raise RuntimeError('qualification receipt differs from the reviewed candidate')
    metadata = json.loads((inbox / 'candidate.json').read_text())
    report = json.loads(receipt.read_text())
    manifest = json.loads((inbox / 'source-manifest.json').read_text())
    if (snapshots.digest(inbox / 'source-manifest.json') != metadata['source_manifest_sha256']
            or metadata['source_manifest_sha256'] != report['source_file_manifest']['sha256']
            or report['candidate_files_differing_from_baseline'] != ['go.mod', 'go.sum']
            or report['vulnerability_scan']['reachable_symbols'] != 0
            or report['vulnerability_scan']['imported_packages'] != 0):
        raise RuntimeError('private candidate qualification or source identity is incomplete')
    snapshots.verify_tree(inbox / 'source', manifest, root_owned=True)
    if (manifest['go.mod'] != report['go_mod_sha256'] or manifest['go.sum'] != report['go_sum_sha256']):
        raise RuntimeError('dependency lockfiles differ from the reviewed qualification')
    version = (inbox / 'source/VERSION').read_text().strip()
    if version != (engine.CURRENT / 'VERSION').read_text().strip():
        raise RuntimeError('dependency-only promotion must preserve the application version')
    payload = {name: inbox / 'payload' / name for name in ('guardian', 'guardian-recovery')}
    for name, path in payload.items():
        trusted_file(path, limit=64 << 20)
        if (snapshots.digest(path) != metadata['payload'][name]['sha256']
                or metadata['payload'][name]['sha256'] != report['candidate_package']['binaries'][name]):
            raise RuntimeError('private candidate binary differs from its review')
        baseline_field = 'parent_original_guardian_sha256' if name == 'guardian' else 'parent_original_recovery_sha256'
        if metadata['production_baseline_rebuilt_exactly'][name] != report['baseline_binary_rebuild'][baseline_field]:
            raise RuntimeError('production baseline differs from its reviewed source binding')
        current_hash = snapshots.digest(engine.CURRENT / name)
        allowed = {metadata['production_baseline_rebuilt_exactly'][name], metadata['payload'][name]['sha256']}
        if current_hash not in allowed:
            raise RuntimeError('live application changed since candidate qualification')
        if adopt_only and current_hash != metadata['payload'][name]['sha256']:
            raise RuntimeError('adoption requires these qualified binaries already installed')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if PENDING.exists() or engine.MARKER.exists() or any(x.exists() for x in OTHER_PENDING):
        raise RuntimeError('pending update prevents private application promotion')
    record = source_record(inbox / 'source', manifest, compiler_version=report['go_version'].split()[0],
                           binaries={name: metadata['payload'][name]['sha256'] for name in payload})
    scan = report['vulnerability_scan']['config']
    record['qualification_config'] = {'govulncheck_version': scan['scanner_version'],
                                      'vulnerability_db_modified': scan['db_last_modified']}
    if adopt_only:
        engine.check_release(engine.CURRENT.resolve(strict=True))
        embedded = engine.CURRENT.resolve(strict=True) / 'application-source'
        if not embedded.is_dir():
            raise RuntimeError('adoption needs a release containing recoverable source; use --apply-qualified')
        snapshots.verify_tree(embedded, manifest, root_owned=True)
        atomic(BASELINE, record)
        atomic(STATE / 'bootstrap-qualification.json', {'reviewed_receipt_sha256': expected_receipt,
                                                       'qualification': report, 'adopted_installed_binaries': True})
        print('Private source baseline adopted for the already installed qualified application.'); return
    old, target = make_release(engine, payload, record, {'reviewed_receipt_sha256': expected_receipt,
                                                        'qualification': report})
    activate(engine, old, target)
    print('Reviewed application dependency candidate installed; actual Guardian run passed.')


def no_candidate_since_qualification(discovery, baseline):
    if baseline.get('discovery_fingerprint') == discovery['fingerprint']: return True
    if baseline.get('discovery_fingerprint'): return False
    config = baseline.get('qualification_config', {})
    return (all(item['current'] == item['candidate'] for item in discovery['dependency_plan']['modules'].values())
            and baseline.get('compiler_version', '').removeprefix('go') == discovery['compiler_version'].removeprefix('go')
            and config.get('govulncheck_version', '').removeprefix('v') == discovery['govulncheck_version'].removeprefix('v')
            and config.get('vulnerability_db_modified') == discovery['vulnerability_db_modified'])


def preserve_failure(work, exc):
    """Retain bounded private diagnostics, never a dependency cache or sandbox."""
    destination = STATE / 'last-failure'
    if destination.is_symlink(): raise RuntimeError('unsafe failure evidence directory')
    if destination.exists(): shutil.rmtree(destination)
    destination.mkdir(mode=0o700)
    logs = []
    for name in ('image-pull.log', 'prepare.log', 'download-and-scan.log', 'offline-qualification.log'):
        path = Path(work) / name
        if not path.exists() and not path.is_symlink(): continue
        trusted_file(path, limit=16 << 20)
        copy_artifact(path, destination / name, limit=16 << 20, minimum=0)
        logs.append(name)
    atomic(destination / 'failure.json', {
        'observed_unix': int(time.time()), 'error_type': type(exc).__name__, 'reason': str(exc)[:4096],
        'retained_logs': logs,
        'next_action': 'Inspect the last failed phase and upstream/module compatibility blocker; qualify a compatible candidate. Pending activation must recover forward with current VPS data.',
        'scope': 'Bounded host diagnostics retained; no production data or dependency cache copied.'})


def execute(recovery=False, check_only=False, qualify_only=False, allow_new_lines=False):
    engine = load_engine()
    if not check_only: STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    for other in OTHER_PENDING:
        if other.exists() or other.is_symlink():
            if check_only: raise RuntimeError('pending update prevents a read-only application check')
            if PENDING.exists(): raise RuntimeError('multiple update journals require inspection')
            print('Another updater requires recovery; application update deferred.'); return
    if PENDING.exists() or PENDING.is_symlink():
        if check_only: raise RuntimeError('application update is pending; --check will not recover it')
        trusted_file(PENDING)
        engine.run('systemctl', 'disable', '--now', 'mail-guardian@pilot.timer', 'mail-guardian-backup@pilot.timer')
        engine.wait_inactive('mail-guardian@pilot.service'); engine.wait_inactive('mail-guardian-backup@pilot.service')
        engine.recover_pending(); promote_from_current(engine)
        return
    if engine.MARKER.exists(): raise RuntimeError('foreign Guardian migration marker needs inspection')
    if recovery: return
    if not check_only: promote_from_current(engine)
    baseline = load_baseline(); source = check_record(baseline)
    source_version = (source / 'VERSION').read_text().strip()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', source_version):
        raise RuntimeError('approved application version is not a stable numeric version')
    discovery = remote_discovery(source_version)
    if check_only:
        print(json.dumps({'baseline_tree': baseline['tree_sha256'], 'source_discovery': discovery})); return
    atomic(STATE / 'source-discovery.json', discovery)
    import builder
    dependency_discovery = (builder.discover(source) if allow_new_lines else
                            builder.discover(source, patch_only=True,
                                             compiler_version=baseline.get('compiler_version')))
    atomic(STATE / 'dependency-discovery.json', dependency_discovery)
    if not qualify_only and no_candidate_since_qualification(dependency_discovery, baseline):
        baseline['discovery_fingerprint'] = dependency_discovery['fingerprint']
        atomic(BASELINE, baseline)
        print('Guardian application dependencies/compiler are current; vulnerability database unchanged since qualification.')
        return
    work = STATE / ('build-' + uuid.uuid4().hex)
    # builder owns atomic creation; an existing workspace must be rejected.
    try:
        result = builder.build_candidate(source, work, discovery=dependency_discovery)
        binaries = result.get('binaries') or result.get('payload_paths')
        if not binaries or set(binaries) != {'guardian', 'guardian-recovery'}:
            raise RuntimeError('qualification omitted required application binaries')
        candidate_source = artifact_path(Path(result['source_dir']), work)
        if not stat.S_ISDIR(candidate_source.lstat().st_mode):
            raise RuntimeError('candidate source is not a regular directory')
        for name, path in binaries.items(): artifact_path(path, work)
        manifest = dict(baseline['files'])
        for name in ('go.mod', 'go.sum'): manifest[name] = snapshots.digest(candidate_source / name)
        # This rejects every source change except the two dependency lockfiles.
        for name, expected in manifest.items():
            path = artifact_path(candidate_source / name, work)
            if snapshots.digest(path) != expected:
                raise RuntimeError('dependency build changed approved application source')
        binary_hashes = {name: snapshots.digest(path) for name, path in binaries.items()}
        # Preserve full qualification evidence even on the no-update path.
        report = {key: value for key, value in result.items() if key not in ('source_dir', 'binaries', 'payload_paths')}
        atomic(STATE / 'last-qualification.json', report)
        installed_matches = (all(snapshots.digest(engine.CURRENT / name) == digest for name, digest in binary_hashes.items())
                             and manifest == baseline['files'])
        if installed_matches:
            baseline['discovery_fingerprint'] = dependency_discovery['fingerprint']
            baseline['qualification_config'] = {'govulncheck_version': result['govulncheck_version'],
                                                'vulnerability_db_modified': result['vulnerability_db_modified']}
            atomic(BASELINE, baseline)
            print('Guardian application dependencies and compiler are current; qualification passed.'); return
        if qualify_only:
            print('Candidate qualification passed; --qualify-only did not activate it.'); return
        record = source_record(candidate_source, manifest, baseline['tree_sha256'],
                               result.get('compiler_version'), binary_hashes)
        record['qualification_config'] = {'govulncheck_version': result['govulncheck_version'],
                                          'vulnerability_db_modified': result['vulnerability_db_modified']}
        # A changed dependency source produces a new discovery fingerprint on
        # its next check; only seed this one when the source itself is unchanged.
        if manifest == baseline['files']: record['discovery_fingerprint'] = dependency_discovery['fingerprint']
        old, target = make_release(engine, binaries, record, report)
        activate(engine, old, target)
        print('Guardian application dependencies updated; SSH/supporting services/actual mailbox run passed.')
    except BaseException as exc:
        preserve_failure(work, exc)
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recover', action='store_true')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--qualify-only', action='store_true')
    parser.add_argument('--allow-new-lines', action='store_true',
                        help='manual operator review only; never add to the scheduled service')
    parser.add_argument('--apply-qualified', type=Path)
    parser.add_argument('--adopt-qualified', type=Path)
    parser.add_argument('--qualification-sha256')
    args = parser.parse_args()
    if os.geteuid() != 0: raise RuntimeError('root required')
    os.umask(0o077)
    fd = os.open(GLOBAL_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('unsafe global update lock')
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Another updater holds the lock; retry next scheduled run.'); return
        if args.apply_qualified or args.adopt_qualified:
            if args.recover or args.check or args.qualify_only or args.apply_qualified and args.adopt_qualified:
                raise RuntimeError('choose exactly one application action')
            qualified_inbox(load_engine(), args.apply_qualified or args.adopt_qualified,
                            args.qualification_sha256, adopt_only=bool(args.adopt_qualified))
        else:
            if args.qualify_only and (args.recover or args.check):
                raise RuntimeError('choose exactly one application action')
            execute(recovery=args.recover, check_only=args.check, qualify_only=args.qualify_only,
                    allow_new_lines=args.allow_new_lines)
    finally: os.close(fd)


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        print('Guardian application update failed; inspect its journal and qualification: ' + str(exc), file=sys.stderr)
        sys.exit(1)
