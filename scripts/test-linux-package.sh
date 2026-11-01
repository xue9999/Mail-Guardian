#!/bin/bash
set -Eeuo pipefail
GUARDIAN_TEST_PROJECT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
GUARDIAN_TEST_TEMP="$(mktemp -d "${TMPDIR:-/tmp}/guardian-linux-package-test.XXXXXX")"
trap 'rm -rf -- "$GUARDIAN_TEST_TEMP"' EXIT
python3 -m unittest discover -s "$GUARDIAN_TEST_PROJECT/deploy/linux" -p 'test_*.py'
python3 -m unittest discover -s "$GUARDIAN_TEST_PROJECT/tools/provisioning" -p 'test_*.py'
python3 -m unittest discover -s "$GUARDIAN_TEST_PROJECT/tools/backup" -p 'test_*.py'
GUARDIAN_DIST_DIR="$GUARDIAN_TEST_TEMP" bash "$GUARDIAN_TEST_PROJECT/scripts/package-linux.sh"
python3 - "$GUARDIAN_TEST_TEMP" "$GUARDIAN_TEST_PROJECT" <<'PY'
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tarfile
sys.dont_write_bytecode = True
root, project = map(Path, sys.argv[1:])
archive, = root.glob('*.tar.gz')
expected, name = archive.with_suffix(archive.suffix + '.sha256').read_text().strip().split('  ')
assert name == archive.name and hashlib.sha256(archive.read_bytes()).hexdigest() == expected
with tarfile.open(archive) as package:
    for item in package.getmembers():
        assert not item.name.startswith('/') and '..' not in Path(item.name).parts
        assert not item.issym() and not item.islnk()
        assert not any(key.startswith(('LIBARCHIVE.', 'SCHILY.')) for key in item.pax_headers)
        assert not any(part.startswith('._') for part in Path(item.name).parts)
    package.extractall(root / 'extracted', filter='data')
release, = (root / 'extracted').iterdir()
assert (release / 'check_host.py').is_file(), 'read-only host preflight is missing'
spec = importlib.util.spec_from_file_location('installer', project / 'deploy/linux/install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
installer.verify_package(release)
for name in ('guardian', 'guardian-recovery'):
    binary = (release / name).read_bytes()
    assert binary[:5] == b'\x7fELF\x02' and binary[18:20] == b'\x3e\x00', 'not amd64 ELF'
    assert os.access(release / name, os.X_OK), 'packaged binary is not executable'
    build_info = subprocess.check_output([os.environ.get('GO', 'go'), 'version', '-m', str(release / name)], text=True)
    assert 'GOAMD64=v1' in build_info, 'ambient GOAMD64 changed the portable binary target'
names = {path.name for path in release.rglob('*')}
assert not names & {'config.toml', 'guardian.db', 'imap-password', 'rspamd-password', 'archive-identity', 'healthchecks-url', '.env'}
assert (release / 'observe.py').is_file(), 'optional health observer is missing'
assert (release / 'backup.py').is_file(), 'daily encrypted backup coordinator is missing'
assert 'User=root' in (release / 'mail-guardian-backup@.service').read_text()
assert 'Persistent=true' in (release / 'mail-guardian-backup@.timer').read_text()
observer = (release / 'mail-guardian-observe@.service').read_text()
assert 'User=mg-%i' in observer and 'NoNewPrivileges=yes' in observer
assert 'healthchecks-url' in observer and '/usr/local/libexec/mail-guardian-observe' in observer
compose = (release / 'deploy/compose.yaml').read_text()
assert 'container_name:' not in compose and 'name: o2-mail-guardian' not in compose
assert compose.count('127.0.0.1:1133') == 2
assert compose.count('@sha256:') == 3
assert 'ports:' not in compose.split('  redis:', 1)[1].split('  rspamd:', 1)[0]
service = (release / 'mail-guardian@.service').read_text()
assert 'User=mg-%i' in service and service.count('LoadCredential=') == 3
assert 'docker.sock' not in service and 'SupplementaryGroups=docker' not in service
timer = (release / 'mail-guardian@.timer').read_text()
assert 'Persistent=true' in timer and '*:00/15:00' in timer
install = (release / 'install.py').read_text()
assert '["/usr/bin/systemctl", "enable"' not in install
print('Linux package integrity, target, isolation and no-auto-start checks passed.')
PY
