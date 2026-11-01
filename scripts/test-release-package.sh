#!/bin/bash

set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
TEST_ROOT="$(/usr/bin/mktemp -d /tmp/o2-guardian-release-test.XXXXXX)"
PACKAGE_TEST_HOME="$(/usr/bin/mktemp -d /tmp/o2-guardian-installer-test.XXXXXX)"
DIST_DIR="${TEST_ROOT}/dist"
EXTRACT_DIR="${TEST_ROOT}/extract"
cleanup() {
  case "${TEST_ROOT}" in
    /tmp/o2-guardian-release-test.*) /bin/rm -rf -- "${TEST_ROOT}" ;;
  esac
  case "${PACKAGE_TEST_HOME}" in
    /tmp/o2-guardian-installer-test.*) /bin/rm -rf -- "${PACKAGE_TEST_HOME}" ;;
  esac
}
trap cleanup EXIT

GUARDIAN_DIST_DIR="${DIST_DIR}" /bin/bash "${PROJECT_DIR}/scripts/package-release.sh" >/dev/null
archive="$(find "${DIST_DIR}" -maxdepth 1 -type f -name 'Mail-Guardian-*.zip' -print -quit)"
[[ -n "${archive}" ]]
if /usr/bin/unzip -Z1 "${archive}" | /usr/bin/grep -Eq '(^|/)__MACOSX/|/\._'; then
  printf 'Package contains visible macOS metadata.\n' >&2
  exit 1
fi
/bin/mkdir -p "${EXTRACT_DIR}"
/usr/bin/ditto -x -k "${archive}" "${EXTRACT_DIR}"
package_root="$(find "${EXTRACT_DIR}" -mindepth 1 -maxdepth 1 -type d -name 'Mail Guardian *' -print -quit)"
[[ -n "${package_root}" ]]

visible="$(find "${package_root}" -mindepth 1 -maxdepth 1 ! -name '.*' -print | /usr/bin/sed "s#${package_root}/##" | LC_ALL=C /usr/bin/sort)"
expected=$'Install.command\nLICENSE\nSTART-HERE.txt'
[[ "${visible}" == "${expected}" ]] || {
  printf 'Package exposes unexpected files:\n%s\n' "${visible}" >&2
  exit 1
}

[[ -x "${package_root}/Install.command" ]]
[[ -f "${package_root}/.payload/scripts/install-core.sh" ]]
[[ -f "${package_root}/.payload/macos/Sources/O2MailGuardianApp/O2MailGuardianApp.swift" ]]
[[ -f "${package_root}/.payload/LICENSE" ]]
[[ -f "${package_root}/.payload/CHANGELOG.md" ]]
/usr/bin/cmp "${PROJECT_DIR}/VERSION" "${package_root}/.payload/VERSION"
/usr/bin/cmp "${PROJECT_DIR}/macos/Sources/O2MailGuardianApp/GuardianDesign.swift" "${package_root}/.payload/macos/Sources/O2MailGuardianApp/GuardianDesign.swift"
/usr/bin/cmp "${PROJECT_DIR}/macos/Sources/O2MailGuardianApp/GuardianWorkflows.swift" "${package_root}/.payload/macos/Sources/O2MailGuardianApp/GuardianWorkflows.swift"
release_version="$(/usr/bin/tr -d '[:space:]' < "${PROJECT_DIR}/VERSION")"
bundle_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "${package_root}/.payload/macos/Info.plist")"
[[ "${release_version}" == "${bundle_version}" ]]

[[ ! -e "${package_root}/.payload/macos/Tests" ]]
/usr/bin/grep -Fq -- '--self-test' "${package_root}/.payload/scripts/install-core.sh"
/usr/bin/grep -Fq 'Control' "${package_root}/START-HERE.txt"
/usr/bin/grep -Fq 'separate app password' "${package_root}/START-HERE.txt"
if find "${package_root}" \( -name .build -o -name .git -o -name bin -o -name '*.db' -o -name '*.log' \) -print -quit | /usr/bin/grep -q .; then
  printf 'Package contains local artifacts or runtime data.\n' >&2
  exit 1
fi

cancel_output="$(printf 'N\n' | HOME="${TEST_ROOT}/home" GUARDIAN_SKIP_PAUSE=1 /bin/bash "${package_root}/Install.command" 2>&1)"
[[ "${cancel_output}" == *"nothing changed"* ]]

HOME="${PACKAGE_TEST_HOME}" \
XDG_CONFIG_HOME="${PACKAGE_TEST_HOME}/config" \
GUARDIAN_INSTALL_SELF_TEST=1 \
/bin/bash "${package_root}/Install.command" >/dev/null

source "$PROJECT_DIR/scripts/release-common.sh"
verify_release "$package_root/.payload" "$release_version"
verify_prebuilt "$package_root/.payload" "$release_version"
(cd "$DIST_DIR"; /usr/bin/shasum -a 256 -c "$(basename "$archive").sha256")
bash "$PROJECT_DIR/scripts/test-install-prebuilt.sh" "$package_root"
# Mutation cases use the same verified extraction and restore each changed file.
payload="$package_root/.payload"
cp "$payload/RELEASE-MANIFEST" "$TEST_ROOT/manifest"
printf '#!/bin/bash\nprintf unexpected > "$HOME/external-called"\nexit 95\n' > "$PACKAGE_TEST_HOME/driver.sh"
for mutation in missing corrupt version arch marker manifest extra executable; do
  case "$mutation" in
    missing) mv "$payload/prebuilt/guardian" "$TEST_ROOT/guardian" ;;
    corrupt) cp "$payload/prebuilt/guardian" "$TEST_ROOT/guardian"; printf x >> "$payload/prebuilt/guardian" ;;
    version) printf '9.9.9\n' > "$payload/VERSION" ;;
    arch) /usr/bin/sed 's/architecture=arm64/architecture=x86_64/' "$TEST_ROOT/manifest" > "$payload/RELEASE-MANIFEST" ;;
    marker) mv "$payload/DISTRIBUTION" "$TEST_ROOT/distribution" ;;
    manifest) mv "$payload/RELEASE-MANIFEST" "$TEST_ROOT/missing-manifest" ;;
    executable)
      cp "$payload/prebuilt/guardian" "$TEST_ROOT/guardian"
      printf '#!/bin/bash\nexit 96\n' > "$payload/prebuilt/guardian"
      release_manifest "$payload" "$release_version" > "$payload/RELEASE-MANIFEST" ;;
    extra) touch "$payload/unlisted-file" ;;
  esac
  if HOME="$PACKAGE_TEST_HOME" XDG_CONFIG_HOME="$PACKAGE_TEST_HOME/config" GUARDIAN_SKIP_PAUSE=1 \
    GUARDIAN_INSTALL_INTEGRATION_TEST=1 GUARDIAN_INSTALL_TEST_DRIVER="$PACKAGE_TEST_HOME/driver.sh" \
    /bin/bash "$payload/scripts/install-core.sh" > "$TEST_ROOT/rejected" 2>&1; then
    printf 'Corrupt package accepted: %s\n' "$mutation" >&2; exit 1
  fi
  [[ ! -e "$PACKAGE_TEST_HOME/external-called" ]]
  grep -Eq 'Package is incomplete|Prebuilt programs failed' "$TEST_ROOT/rejected"
  case "$mutation" in
    missing|corrupt) mv "$TEST_ROOT/guardian" "$payload/prebuilt/guardian" ;;
    version) cp "$PROJECT_DIR/VERSION" "$payload/VERSION" ;;
    arch) cp "$TEST_ROOT/manifest" "$payload/RELEASE-MANIFEST" ;;
    marker) mv "$TEST_ROOT/distribution" "$payload/DISTRIBUTION" ;;
    manifest) mv "$TEST_ROOT/missing-manifest" "$payload/RELEASE-MANIFEST" ;;
    executable) mv "$TEST_ROOT/guardian" "$payload/prebuilt/guardian"; cp "$TEST_ROOT/manifest" "$payload/RELEASE-MANIFEST" ;;
    extra) /bin/rm "$payload/unlisted-file" ;;
  esac
done
verify_release "$payload" "$release_version"
printf 'Release package: OK\n'
