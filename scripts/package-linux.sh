#!/bin/bash
set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
GUARDIAN_PACKAGE_VERSION="$(tr -d '[:space:]' < "$PROJECT_DIR/VERSION")"
GUARDIAN_PACKAGE_DIST="${GUARDIAN_DIST_DIR:-$PROJECT_DIR/dist}"
GUARDIAN_PACKAGE_TEMP="$(mktemp -d "${TMPDIR:-/tmp}/mail-guardian-linux.XXXXXX")"
trap 'rm -rf -- "$GUARDIAN_PACKAGE_TEMP"' EXIT
[[ "$GUARDIAN_PACKAGE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9]+)*$ ]]
GUARDIAN_PACKAGE_NAME="Mail-Guardian-${GUARDIAN_PACKAGE_VERSION}-linux-amd64"
GUARDIAN_PACKAGE_ROOT="$GUARDIAN_PACKAGE_TEMP/$GUARDIAN_PACKAGE_NAME"
mkdir -p "$GUARDIAN_PACKAGE_ROOT/deploy" "$GUARDIAN_PACKAGE_DIST"
GO="${GO:-go}"
(
  cd "$PROJECT_DIR"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 "$GO" build -trimpath -ldflags "-s -w -X main.version=${GUARDIAN_PACKAGE_VERSION}" -o "$GUARDIAN_PACKAGE_ROOT/guardian" ./cmd/guardian
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 "$GO" build -trimpath -ldflags "-s -w" -o "$GUARDIAN_PACKAGE_ROOT/guardian-recovery" ./cmd/guardian-recovery
)
for file in VERSION LICENSE; do
  cp "$PROJECT_DIR/$file" "$GUARDIAN_PACKAGE_ROOT/$file"
done
for file in maintenance.py install.py install.sh check_host.py observe.py backup.py BACKUP.md mail-guardian-backup@.service mail-guardian-backup@.timer mail-guardian-observe@.service mail-guardian-observe@.timer mail-guardian@.service mail-guardian@.timer README.md; do
  cp "$PROJECT_DIR/deploy/linux/$file" "$GUARDIAN_PACKAGE_ROOT/$file"
done
for directory in redis rspamd unbound; do
  cp -R "$PROJECT_DIR/deploy/$directory" "$GUARDIAN_PACKAGE_ROOT/deploy/$directory"
done
# Keep the installed Mac resource names/volumes untouched. Linux uses a
# separate project without explicit legacy container/network/volume names.
python3 - "$PROJECT_DIR/deploy/compose.yaml" "$GUARDIAN_PACKAGE_ROOT/deploy/compose.yaml" <<'PY'
from pathlib import Path
import sys
source = Path(sys.argv[1]).read_text()
lines = []
for line in source.splitlines():
    if line.startswith('name: ') or line.strip().startswith('container_name:'):
        continue
    if line.strip().startswith('name: o2-mail-guardian'):
        continue
    if '${GUARDIAN_RUNTIME_DIR:' in line:
        line = line.replace('${GUARDIAN_RUNTIME_DIR:?Uruchom scripts/02-uruchom-silnik.command}', '${GUARDIAN_RUNTIME_DIR:?Administrator runtime is required}')
    lines.append(line)
# Removed explicit volume names leave empty mapping values, valid Compose YAML.
Path(sys.argv[2]).write_text('\n'.join(lines) + '\n')
PY
chmod 755 "$GUARDIAN_PACKAGE_ROOT/guardian" "$GUARDIAN_PACKAGE_ROOT/guardian-recovery" "$GUARDIAN_PACKAGE_ROOT/install.sh" "$GUARDIAN_PACKAGE_ROOT/install.py" "$GUARDIAN_PACKAGE_ROOT/maintenance.py"
python3 - "$GUARDIAN_PACKAGE_ROOT" <<'PY'
import hashlib
from pathlib import Path
import sys
root = Path(sys.argv[1])
with (root / 'SHA256SUMS').open('w') as manifest:
    for path in sorted(root.rglob('*')):
        if path.is_file() and path.name != 'SHA256SUMS':
            manifest.write(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + str(path.relative_to(root)) + '\n')
PY
python3 - "$GUARDIAN_PACKAGE_ROOT" "$GUARDIAN_PACKAGE_TEMP/$GUARDIAN_PACKAGE_NAME.tar.gz" <<'PY'
from pathlib import Path
import sys
import tarfile
root, archive = map(Path, sys.argv[1:])
# A portable archive must not copy macOS quarantine/provenance/File Provider
# extended attributes or AppleDouble entries onto the Linux target.
with tarfile.open(archive, 'w:gz', format=tarfile.PAX_FORMAT) as package:
    for path in [root, *sorted(root.rglob('*'))]:
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise SystemExit('Linux package contains a link or special entry')
        name = str(Path(root.name) / path.relative_to(root))
        info = package.gettarinfo(str(path), arcname=name)
        info.uid = info.gid = 0
        info.uname = info.gname = 'root'
        info.pax_headers = {}
        if path.is_file():
            with path.open('rb') as content:
                package.addfile(info, content)
        else:
            package.addfile(info)
PY
mv -f "$GUARDIAN_PACKAGE_TEMP/$GUARDIAN_PACKAGE_NAME.tar.gz" "$GUARDIAN_PACKAGE_DIST/$GUARDIAN_PACKAGE_NAME.tar.gz"
python3 - "$GUARDIAN_PACKAGE_DIST/$GUARDIAN_PACKAGE_NAME.tar.gz" <<'PY'
import hashlib
from pathlib import Path
import sys
path = Path(sys.argv[1])
path.with_suffix(path.suffix + '.sha256').write_text(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n')
PY
printf 'Linux deployment candidate: %s\n' "$GUARDIAN_PACKAGE_DIST/$GUARDIAN_PACKAGE_NAME.tar.gz"
