#!/usr/bin/python3
"""Export and verify the owner's explicit, immutable Guardian source channel.

This never checks out, commits, publishes or edits the original working tree.
Only files in a reviewed SHA-256 allowlist are copied. The VPS trusts a source
generation only after its administrator installs baseline.json root-owned.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat

PREFIXES = ('cmd/', 'internal/', 'scripts/', 'deploy/', 'tools/', 'docs/', '.github/')
ROOT_FILES = {'go.mod', 'go.sum', 'VERSION', 'Makefile', 'LICENSE', 'README.md'}
FORBIDDEN_PARTS = {'.git', '__pycache__', 'secrets', 'credentials', 'node_modules', '.build'}
SUFFIXES = {'.go', '.py', '.sh', '.command', '.mod', '.sum', '.md', '.json', '.yaml',
            '.yml', '.toml', '.conf', '.inc', '.service', '.timer', '.example'}


def digest(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 64 << 20:
            raise RuntimeError('unsafe or oversized application artifact')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            result = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(fd)
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RuntimeError('application artifact changed while read')
        return result
    finally:
        os.close(fd)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def validate_name(name):
    path = Path(name)
    # This is the reviewed Go implementation package, not stored credentials.
    secret_source = (len(path.parts) == 3 and path.parts[:2] == ('internal', 'secrets')
                     and path.suffix == '.go')
    if (not isinstance(name, str) or path.is_absolute() or '..' in path.parts
            or any(x in FORBIDDEN_PARTS and not (x == 'secrets' and secret_source) for x in path.parts)
            or path.name.startswith('.') or not re.fullmatch(r'[A-Za-z0-9_./@+-]+', name)):
        raise RuntimeError('unsafe source allowlist entry')
    if name not in ROOT_FILES and not (name.startswith(PREFIXES) and path.suffix in SUFFIXES):
        raise RuntimeError('file is outside the explicit application source scope: ' + name)


def validate_manifest(manifest):
    if not isinstance(manifest, dict) or not 10 <= len(manifest) <= 2000:
        raise RuntimeError('source manifest must contain an explicit bounded file allowlist')
    for name, value in manifest.items():
        validate_name(name)
        if not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{64}', value):
            raise RuntimeError('invalid source SHA-256')
    for required in ('go.mod', 'go.sum', 'VERSION', 'cmd/guardian/main.go',
                     'cmd/guardian-recovery/main.go'):
        if required not in manifest:
            raise RuntimeError('incomplete Guardian source generation')


def verify_tree(root, manifest, root_owned=False):
    root = Path(root)
    validate_manifest(manifest)
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError('unsafe source generation directory')
    if root_owned:
        for parent in (root, *root.parents):
            info = parent.lstat()
            if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISDIR(info.st_mode):
                raise RuntimeError('source ancestor is not root controlled')
    actual = set()
    total = 0
    for path in root.rglob('*'):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            if root_owned and (info.st_uid != 0 or info.st_mode & 0o022):
                raise RuntimeError('source directory is not root controlled')
            continue
        name = str(path.relative_to(root))
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('source contains a link or special file')
        if root_owned and (info.st_uid != 0 or info.st_mode & 0o022):
            raise RuntimeError('source file is not root controlled')
        total += info.st_size
        if total > 64 << 20 or info.st_size > 8 << 20:
            raise RuntimeError('source exceeds the bounded application scope')
        if name not in manifest or digest(path) != manifest[name]:
            raise RuntimeError('source differs from its approved manifest: ' + name)
        actual.add(name)
    if actual != set(manifest):
        raise RuntimeError('source generation is incomplete')


def export(source, manifest, destination):
    """Copy only reviewed files; extra build outputs in source are ignored."""
    source, destination = Path(source), Path(destination)
    validate_manifest(manifest)
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        for name, expected in manifest.items():
            path = source / name
            for parent in (path, *list(path.parents)[:len(Path(name).parts) - 1]):
                if parent.is_symlink():
                    raise RuntimeError('symlink in source allowlist')
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or digest(path) != expected:
                raise RuntimeError('reviewed source changed: ' + name)
            target = destination / name
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            target.chmod(0o644)
        # The container mounts only this source directory, without secrets.
        for path in destination.rglob('*'):
            if path.is_dir(): path.chmod(0o755)
        destination.chmod(0o755)
        verify_tree(destination, manifest)
    except BaseException:
        shutil.rmtree(destination)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    export(args.source, manifest, args.destination)
    print(json.dumps({'source': str(args.destination), 'files': len(manifest),
                      'tree_sha256': hashlib.sha256(canonical(manifest)).hexdigest()}))


if __name__ == '__main__':
    main()
