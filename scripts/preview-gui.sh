#!/bin/bash
# Build an isolated demo app. No access to real mail, Keychain or launchd.
set -Eeuo pipefail
PROJECT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
source "${PROJECT_DIR}/scripts/swift-common.sh"
SCENARIO="${1:-healthy}"
THEME="${2:-system}"
case "$THEME" in system|dark) ;; *) printf 'Nieznany motyw: %s\n' "$THEME" >&2; exit 2 ;; esac
case "$SCENARIO" in healthy|active|ready|attention|critical|manual|unconfigured|empty|offline|archive-error) ;; *) printf 'Nieznany scenariusz: %s\n' "$SCENARIO" >&2; exit 2 ;; esac
guardian_swift build --package-path "$PROJECT_DIR/macos" --product O2MailGuardianApp >&2
BINARY_DIR="$(guardian_swift build --package-path "$PROJECT_DIR/macos" --show-bin-path)"
PREVIEW_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/o2-guardian-preview.XXXXXX")"
APP="$PREVIEW_ROOT/Mail Guardian Preview.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$PROJECT_DIR/scripts/mock-gui-backend.sh" "$APP/Contents/Resources/mock-gui-backend.sh"
cp "$PROJECT_DIR/macos/Info.plist" "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Set :CFBundleIdentifier pl.o2.mail-guardian.preview' "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Set :CFBundleDisplayName Mail Guardian Preview' "$APP/Contents/Info.plist"
cp "$BINARY_DIR/O2MailGuardianApp" "$APP/Contents/MacOS/GuardianPreviewBinary"
{
  printf '#!/bin/bash\n'
  printf 'export GUARDIAN_PREVIEW=1\n'
  printf 'CONTENTS="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"\n'
  printf 'export GUARDIAN_BIN="$CONTENTS/Resources/mock-gui-backend.sh"\n'
  printf 'DEMO_STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o2-guardian-demo-state.XXXXXX")"\n'
  printf 'export GUARDIAN_MOCK_STATE="$DEMO_STATE_DIR/state"\n'
  printf 'export GUARDIAN_MOCK_SCENARIO=%q\n' "$SCENARIO"
  printf 'export GUARDIAN_PREVIEW_THEME=%q\n' "$THEME"
  printf 'exec "$(dirname "$0")/GuardianPreviewBinary" "$@"\n'
} > "$APP/Contents/MacOS/O2MailGuardianApp"
chmod 755 "$APP/Contents/MacOS/O2MailGuardianApp"
printf '%s\n' "$APP"
