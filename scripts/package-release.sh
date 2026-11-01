#!/bin/bash

set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
VERSION="$(/usr/bin/tr -d '[:space:]' < "${PROJECT_DIR}/VERSION")"
DIST_DIR="${GUARDIAN_DIST_DIR:-${PROJECT_DIR}/dist}"
STAGE_ROOT="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/o2-mail-guardian-package.XXXXXX")"
PACKAGE_ROOT="${STAGE_ROOT}/O2 Mail Guardian ${VERSION}"
PAYLOAD="${PACKAGE_ROOT}/.payload"
ARCHIVE_TMP="${STAGE_ROOT}/O2-Mail-Guardian-${VERSION}-macos-arm64.zip"
ARCHIVE="${DIST_DIR}/O2-Mail-Guardian-${VERSION}-macos-arm64.zip"

source "${PROJECT_DIR}/scripts/release-common.sh"
source "${PROJECT_DIR}/scripts/swift-common.sh"
GO="${GO:-go}"
safe_go_version "$(cd "$PROJECT_DIR"; "$GO" env GOVERSION)" || { release_error 'wymagane Go 1.26.10 lub 1.27.3 albo nowsze'; exit 1; }

cleanup() {
  case "${STAGE_ROOT}" in
    "${TMPDIR:-/tmp}"/o2-mail-guardian-package.*|/tmp/o2-mail-guardian-package.*)
      /bin/rm -rf -- "${STAGE_ROOT}"
      ;;
  esac
}
trap cleanup EXIT

[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9]+)*$ ]]
/bin/mkdir -p "${PAYLOAD}" "${DIST_DIR}"

/bin/cp "${PROJECT_DIR}/Install.command" "${PACKAGE_ROOT}/Install.command"
/bin/chmod 755 "${PACKAGE_ROOT}/Install.command"
/bin/cp "${PROJECT_DIR}/LICENSE" "${PACKAGE_ROOT}/LICENSE"

printf '%s\n' \
  'O2 MAIL GUARDIAN — ZACZNIJ TUTAJ' \
  '' \
  'Paczka dla Maców Apple Silicon (macOS 13 lub nowszy).' \
  'Programy są gotowe; instalator nie kompiluje Guardiana.' \
  'Podpis lokalny ad hoc, bez notaryzacji Apple.' \
  '' \
  '1. Kliknij dwukrotnie Install.command.' \
  '2. Naciśnij Enter, aby rozpocząć.' \
  '3. Poczekaj, aż otworzy się aplikacja.' \
  '4. Przejdź trzy krótkie ekrany konfiguracji.' \
  '' \
  'Jeśli macOS zablokuje dwuklik: kliknij Install.command z klawiszem Control,' \
  'wybierz Otwórz, a potem ponownie Otwórz. Nie wyłączaj zabezpieczeń Maca.' \
  '' \
  'W aplikacji potrzebujesz osobnego hasła aplikacyjnego o2, nie zwykłego' \
  'hasła do poczty. Pierwszy ekran zawiera odnośnik do instrukcji o2.' \
  '' \
  'Nie otwieraj katalogu .payload — zawiera wyłącznie techniczne składniki instalatora.' \
  'Instalator nie pyta w Terminalu o hasło do poczty i nie włącza trwałego usuwania.' \
  > "${PACKAGE_ROOT}/ZACZNIJ-TUTAJ.txt"

for file in VERSION go.mod go.sum README.md CHANGELOG.md LICENSE Guardian.command Uruchom-teraz.command Sprawdz-stan.command; do
  /bin/cp "${PROJECT_DIR}/${file}" "${PAYLOAD}/${file}"
done
for command_file in Guardian.command Uruchom-teraz.command Sprawdz-stan.command; do
  /bin/chmod 755 "${PAYLOAD}/${command_file}"
done
for directory in cmd internal deploy docs scripts; do
  /usr/bin/ditto --norsrc --noqtn "${PROJECT_DIR}/${directory}" "${PAYLOAD}/${directory}"
done

# SwiftPM potrzebuje wyłącznie tych źródeł. Celowo nie pakujemy .build,
# lokalnych artefaktów, logów, baz ani ustawień deweloperskich.
/bin/mkdir -p "${PAYLOAD}/macos"
for file in Package.swift Info.plist; do
  /bin/cp "${PROJECT_DIR}/macos/${file}" "${PAYLOAD}/macos/${file}"
done
/usr/bin/ditto --norsrc --noqtn "${PROJECT_DIR}/macos/Sources" "${PAYLOAD}/macos/Sources"

[[ "$(uname -m)" == arm64 ]] || { printf 'Budowanie paczki wymaga Apple Silicon.\n' >&2; exit 1; }
printf 'prebuilt\n' > "${PAYLOAD}/DISTRIBUTION"
PREBUILT="${PAYLOAD}/prebuilt"
APP="${PREBUILT}/O2 Mail Guardian.app"
mkdir -p "${APP}/Contents/MacOS" "${APP}/Contents/Resources"
(cd "$PROJECT_DIR"; CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 "$GO" build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "${PREBUILT}/guardian" ./cmd/guardian)
MACOSX_DEPLOYMENT_TARGET=13.0 guardian_swift build --package-path "$PROJECT_DIR/macos" --configuration release --arch arm64 --product O2MailGuardianApp >&2
SWIFT_BIN_DIR="$(guardian_swift build --package-path "$PROJECT_DIR/macos" --configuration release --arch arm64 --show-bin-path)"
cp "${SWIFT_BIN_DIR}/O2MailGuardianApp" "${APP}/Contents/MacOS/O2MailGuardianApp"
cp "$PROJECT_DIR/macos/Info.plist" "$APP/Contents/Info.plist"
# Validate deployment metadata at build time, without requiring Xcode on the recipient Mac.
for binary in "$PREBUILT/guardian" "$APP/Contents/MacOS/O2MailGuardianApp"; do
  minimum="$(/usr/bin/otool -l "$binary" | awk '/LC_BUILD_VERSION/ {build=1} build && /minos/ {print $2; exit} /LC_VERSION_MIN_MACOSX/ {legacy=1} legacy && /version/ {print $2; exit}')"
  [[ -n "$minimum" ]] && awk -v v="$minimum" 'BEGIN {split(v,a,"."); exit !(a[1] < 13 || (a[1] == 13 && a[2] == 0))}' || { printf 'Nieobsługiwany minimalny macOS: %s\n' "$minimum" >&2; exit 1; }
done
/usr/bin/codesign --force --sign - "$PREBUILT/guardian"
/usr/bin/codesign --force --deep --sign - "$APP"
verify_prebuilt "$PAYLOAD" "$VERSION"
release_manifest "$PAYLOAD" "$VERSION" > "$PAYLOAD/RELEASE-MANIFEST"
verify_release "$PAYLOAD" "$VERSION"

/usr/bin/ditto -c -k --norsrc --noqtn --keepParent "${PACKAGE_ROOT}" "${ARCHIVE_TMP}"
/bin/mv -f "${ARCHIVE_TMP}" "${ARCHIVE}"
/bin/chmod 644 "${ARCHIVE}"
printf 'Gotowa prosta paczka: %s\n' "${ARCHIVE}"

(cd "$DIST_DIR"; /usr/bin/shasum -a 256 "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256")
