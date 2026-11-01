#!/bin/bash

set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
RUNTIME_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/o2-mail-guardian"
INSTALL_DIR="${HOME}/.local/bin/o2-mail-guardian"
GUARDIAN_BIN="${INSTALL_DIR}/guardian"
DATA_DIR="${HOME}/Library/Application Support/O2 Mail Guardian"
CONFIG_FILE="${DATA_DIR}/config.toml"
SERVICE_PLIST="${HOME}/Library/LaunchAgents/pl.o2.mail-guardian.plist"
UI_SERVICE_PLIST="${HOME}/Library/LaunchAgents/pl.o2.mail-guardian-ui.plist"
APP_PARENT="${HOME}/Applications"
APP_DIR="${APP_PARENT}/O2 Mail Guardian.app"
VERSION_FILE="${PROJECT_DIR}/VERSION"
source "${PROJECT_DIR}/scripts/install-lock.sh"
install_lock_acquire || exit 1
trap install_lock_release EXIT
source "${PROJECT_DIR}/scripts/release-common.sh"
source "${PROJECT_DIR}/scripts/swift-common.sh"
source "${PROJECT_DIR}/scripts/install-runtime.sh"
DISTRIBUTION=source
if [[ "$(basename "$PROJECT_DIR")" == .payload || -e "$PROJECT_DIR/DISTRIBUTION" || -e "$PROJECT_DIR/prebuilt" ]]; then
  DISTRIBUTION=prebuilt
fi

[[ -f "${VERSION_FILE}" ]] || {
  printf '%s\n' "Błąd: w paczce brakuje pliku VERSION." >&2
  exit 1
}
GUARDIAN_VERSION="$(/usr/bin/tr -d '[:space:]' < "${VERSION_FILE}")"
[[ "${GUARDIAN_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9]+)*$ ]] || {
  printf 'Błąd: nieprawidłowa wersja w VERSION: %q\n' "${GUARDIAN_VERSION}" >&2
  exit 1
}

DEPLOY_STAGE=""
DEPLOY_BACKUP=""
DEPLOY_BACKUP_ROOT=""
BUILD_TMP=""
APP_STAGE_ROOT=""
APP_STAGE=""
APP_BACKUP_ROOT=""
APP_BACKUP=""
BIN_ROLLBACK=""
UI_PLIST_ROLLBACK=""
DEPLOY_SWITCHED=0
HAD_DEPLOY=0
APP_SWITCHED=0
HAD_APP=0
BIN_SWITCHED=0
HAD_BIN=0
UI_PLIST_SWITCHED=0
HAD_UI_PLIST=0
SERVICE_SUSPENDED=0
UI_SUSPENDED=0
ROLLBACK_FAILED=0
INSTALL_RESULT=success
FAIL_IN_PROGRESS=0
CURRENT_STAGE="przygotowanie instalacji"

emit_ui() {
  [[ "${GUARDIAN_INSTALL_UI_FD:-}" == "3" ]] || return 0
  printf '%s\n' "$*" >&3
}
blue() { CURRENT_STAGE="$*"; printf '\033[1;34m%s\033[0m\n' "$*"; emit_ui "→ $*"; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; emit_ui "✓ $*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; emit_ui "! $*"; }
# Szczegóły błędu trafiają do prywatnego logu. Widoczny wrapper pokaże tylko
# jedną, zredagowaną poradę zapisaną przez fail() w pliku statusu.
red() { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }
inject_failure() {
  if [[ "${GUARDIAN_FAIL_AT:-}" == "$1" ]]; then
    red "Test instalatora: wymuszona awaria w punkcie $1."
    return 97
  fi
}
pause_at_end() {
  if [[ "${GUARDIAN_SKIP_PAUSE:-0}" != "1" && -t 0 ]]; then
    printf '\n'
    read -r -p "Naciśnij Enter, aby zamknąć to okno…" _
  fi
}
safe_remove_temp() {
  local target="${1:-}"
  [[ -n "${target}" ]] || return 0
  case "${target}" in
    "${RUNTIME_DIR}"/.deploy-stage.*|"${RUNTIME_DIR}"/.deploy-failed.*|"${RUNTIME_DIR}"/.deploy-backup.*)
      /bin/rm -rf -- "${target}"
      ;;
    "${INSTALL_DIR}"/.guardian-build.*)
      /bin/rm -f -- "${target}"
      ;;
    "${INSTALL_DIR}"/.guardian-rollback.*)
      /bin/rm -f -- "${target}"
      ;;
    "${APP_PARENT}"/.o2-guardian-app-stage.*|"${APP_PARENT}"/.o2-guardian-app-backup.*)
      /bin/rm -rf -- "${target}"
      ;;
    "${HOME}/Library/LaunchAgents"/.o2-mail-guardian-ui.*)
      /bin/rm -f -- "${target}"
      ;;
  esac
}
cleanup_temporary_files() {
  (( ROLLBACK_FAILED == 0 )) || return 0
  safe_remove_temp "${DEPLOY_STAGE}"
  safe_remove_temp "${DEPLOY_BACKUP_ROOT}"
  safe_remove_temp "${BUILD_TMP}"
  safe_remove_temp "${APP_STAGE_ROOT}"
  safe_remove_temp "${APP_BACKUP_ROOT}"
  safe_remove_temp "${BIN_ROLLBACK}"
  safe_remove_temp "${UI_PLIST_ROLLBACK}"
}
rollback_deploy() {
  (( DEPLOY_SWITCHED == 1 )) || return 0
  local failed_root=""
  if [[ -d "${RUNTIME_DIR}/deploy" ]]; then
    if [[ "${GUARDIAN_INSTALL_SELF_TEST:-0}" != "1" ]]; then
      GUARDIAN_RUNTIME_DIR="${RUNTIME_DIR}" install_external compose --context colima compose \
        --project-name o2-mail-guardian --file "${RUNTIME_DIR}/deploy/compose.yaml" \
        down --remove-orphans >/dev/null 2>&1 || true
    fi
    failed_root="$(/usr/bin/mktemp -d "${RUNTIME_DIR}/.deploy-failed.XXXXXX")" || return 1
    /bin/mv "${RUNTIME_DIR}/deploy" "${failed_root}/deploy" || return 1
  fi
  if (( HAD_DEPLOY == 1 )); then
    [[ -d "${DEPLOY_BACKUP}" ]] || return 1
    /bin/mv "${DEPLOY_BACKUP}" "${RUNTIME_DIR}/deploy" || return 1
    yellow "Przywrócono poprzednią konfigurację lokalnego silnika."
    if [[ "${GUARDIAN_INSTALL_SELF_TEST:-0}" != "1" ]]; then
      GUARDIAN_SKIP_PAUSE=1 install_external start-stack >/dev/null 2>&1 \
        || return 1
    fi
  fi
  safe_remove_temp "${failed_root}"
  DEPLOY_SWITCHED=0
}
rollback_application() {
  (( APP_SWITCHED == 1 )) || return 0
  if [[ -d "${APP_DIR}" ]]; then
    /bin/mv "${APP_DIR}" "${APP_STAGE_ROOT}/failed.app" || return 1
  fi
  if (( HAD_APP == 1 )); then
    [[ -d "${APP_BACKUP}" ]] || return 1
    /bin/mv "${APP_BACKUP}" "${APP_DIR}" || return 1
    yellow "Przywrócono poprzednią aplikację."
  fi
  APP_SWITCHED=0
}
rollback_binary() {
  (( BIN_SWITCHED == 1 )) || return 0
  if (( HAD_BIN == 1 )); then
    [[ -f "${BIN_ROLLBACK}" ]] || return 1
    /bin/mv -f "${BIN_ROLLBACK}" "${GUARDIAN_BIN}" || return 1
    yellow "Przywrócono poprzedni silnik Guardian."
  else
    /bin/rm -f -- "${GUARDIAN_BIN}" || return 1
  fi
  BIN_SWITCHED=0
}
rollback_ui_plist() {
  (( UI_PLIST_SWITCHED == 1 )) || return 0
  install_external launchctl bootout "gui/${UID}/pl.o2.mail-guardian-ui" >/dev/null 2>&1 || true
  if (( HAD_UI_PLIST == 1 )); then
    [[ -f "${UI_PLIST_ROLLBACK}" ]] || return 1
    /bin/mv -f "${UI_PLIST_ROLLBACK}" "${UI_SERVICE_PLIST}" || return 1
    UI_SUSPENDED=1
  else
    /bin/rm -f -- "${UI_SERVICE_PLIST}" || return 1
    UI_SUSPENDED=0
  fi
  UI_PLIST_SWITCHED=0
}
resume_scanner_if_needed() {
  if (( SERVICE_SUSPENDED == 1 )); then
    [[ -f "${SERVICE_PLIST}" ]] || return 1
    install_external launchctl bootstrap "gui/${UID}" "${SERVICE_PLIST}" >/dev/null 2>&1 || return 1
    SERVICE_SUSPENDED=0
  fi
}
resume_ui_if_needed() {
  if (( UI_SUSPENDED == 1 )); then
    [[ -f "$UI_SERVICE_PLIST" ]] || return 1
    install_external launchctl bootstrap "gui/${UID}" "$UI_SERVICE_PLIST" >/dev/null 2>&1 || return 1
    UI_SUSPENDED=0
  fi
}
rollback_all() {
  local failed=0
  rollback_ui_plist || failed=1
  rollback_application || failed=1
  rollback_binary || failed=1
  rollback_deploy || failed=1
  # Do not start services against a partially recovered installation.
  if (( failed == 0 )); then
    resume_scanner_if_needed || failed=1
    resume_ui_if_needed || failed=1
  fi
  if (( failed )); then ROLLBACK_FAILED=1; return 1; fi
}
fail() {
  if (( FAIL_IN_PROGRESS == 0 )); then
    FAIL_IN_PROGRESS=1
    set +e
    rollback_all || ROLLBACK_FAILED=1
  fi
  if (( ROLLBACK_FAILED )); then
    red "Nie udało się w pełni przywrócić poprzedniej instalacji. Zachowano kopie aktualizacyjne; potrzebna jest pomoc techniczna."
    if [[ -n "${GUARDIAN_INSTALL_STATUS_FILE:-}" ]]; then
      printf '%s\n' "Przywracanie poprzedniej instalacji nie powiodło się w pełni. Nie usuwaj kopii aktualizacyjnych; przekaż log osobie pomagającej." > "${GUARDIAN_INSTALL_STATUS_FILE}"
    fi
  fi
  write_install_result failed
  red "Instalacja została zatrzymana."
  red "${1:-Nieznany błąd.}"
  red "Nie usunięto ani nie przeniesiono żadnej wiadomości."
  if [[ -n "${GUARDIAN_INSTALL_STATUS_FILE:-}" && "$ROLLBACK_FAILED" == 0 ]]; then
    (umask 077; printf '%s\n' "${1:-Nieznany błąd.}" > "${GUARDIAN_INSTALL_STATUS_FILE}") || true
  fi
  pause_at_end
  exit 1
}
on_error() {
  local line="${1:-?}"
  set +e
  printf 'Błąd techniczny w wierszu %s podczas etapu: %s\n' "${line}" "${CURRENT_STAGE}" >&2
  fail "Nie udało się ukończyć etapu „${CURRENT_STAGE}”. Uruchom Install.command ponownie. Jeśli problem wróci, przekaż plik instalacja.log osobie pomagającej."
}
on_signal() {
  # Terminal może zostać zamknięty albo użytkownik może nacisnąć Ctrl+C w
  # najgorszym możliwym momencie — po odsunięciu starej wersji. Wyłączamy
  # kolejne sygnały na czas rollbacku i przywracamy pełny poprzedni komplet.
  trap '' HUP INT TERM
  set +e
  fail "Instalacja została przerwana. Sprawdź wynik przywracania w logu."
}
write_install_result() {
  if [[ -n "${GUARDIAN_INSTALL_RESULT_FILE:-}" ]]; then
    (umask 077; printf '%s\n' "$1" > "${GUARDIAN_INSTALL_RESULT_FILE}")
  fi
}
trap 'on_error "${LINENO}"' ERR
trap on_signal HUP INT TERM
trap 'cleanup_temporary_files; install_lock_release' EXIT

if [[ "${GUARDIAN_INSTALL_SELF_TEST:-0}" == "1" ]]; then
  case "${HOME}" in
    /tmp/o2-guardian-installer-test.*) ;;
    *) fail "test rollbacku wymaga izolowanego HOME w /tmp/o2-guardian-installer-test.*" ;;
  esac
  mkdir -p "${INSTALL_DIR}" "${APP_PARENT}" "${HOME}/Library/LaunchAgents"

  if [[ "${GUARDIAN_INSTALL_ERROR_SELF_TEST:-0}" == "1" ]]; then
    blue "bezpieczny test nazwy etapu"
    false
  fi

  selftest_prepare_deploy() {
    mkdir -p "${RUNTIME_DIR}/deploy"
    printf 'old-deploy\n' > "${RUNTIME_DIR}/deploy/marker"
    DEPLOY_BACKUP_ROOT="$(/usr/bin/mktemp -d "${RUNTIME_DIR}/.deploy-backup.XXXXXX")"
    DEPLOY_BACKUP="${DEPLOY_BACKUP_ROOT}/deploy"
    /bin/mv "${RUNTIME_DIR}/deploy" "${DEPLOY_BACKUP}"
    mkdir -p "${RUNTIME_DIR}/deploy"
    printf 'new-deploy\n' > "${RUNTIME_DIR}/deploy/marker"
    HAD_DEPLOY=1; DEPLOY_SWITCHED=1
  }
  selftest_prepare_binary() {
    printf 'old-binary\n' > "${GUARDIAN_BIN}"
    BIN_ROLLBACK="$(/usr/bin/mktemp "${INSTALL_DIR}/.guardian-rollback.XXXXXX")"
    printf 'old-binary\n' > "${BIN_ROLLBACK}"
    printf 'new-binary\n' > "${GUARDIAN_BIN}"
    HAD_BIN=1; BIN_SWITCHED=1
  }
  selftest_prepare_app() {
    mkdir -p "${APP_DIR}/Contents"
    printf 'old-app\n' > "${APP_DIR}/Contents/marker"
    APP_BACKUP_ROOT="$(/usr/bin/mktemp -d "${APP_PARENT}/.o2-guardian-app-backup.XXXXXX")"
    APP_BACKUP="${APP_BACKUP_ROOT}/O2 Mail Guardian.app"
    /bin/mv "${APP_DIR}" "${APP_BACKUP}"
    mkdir -p "${APP_DIR}/Contents"
    printf 'new-app\n' > "${APP_DIR}/Contents/marker"
    APP_STAGE_ROOT="$(/usr/bin/mktemp -d "${APP_PARENT}/.o2-guardian-app-stage.XXXXXX")"
    HAD_APP=1; APP_SWITCHED=1
  }
  selftest_prepare_ui() {
    printf 'old-ui\n' > "${UI_SERVICE_PLIST}"
    UI_PLIST_ROLLBACK="$(/usr/bin/mktemp "${HOME}/Library/LaunchAgents/.o2-mail-guardian-ui.XXXXXX")"
    printf 'old-ui\n' > "${UI_PLIST_ROLLBACK}"
    printf 'new-ui\n' > "${UI_SERVICE_PLIST}"
    HAD_UI_PLIST=1; UI_PLIST_SWITCHED=1
  }
  selftest_cleanup_stage_roots() {
    safe_remove_temp "${DEPLOY_BACKUP_ROOT}"
    safe_remove_temp "${APP_STAGE_ROOT}"
    safe_remove_temp "${APP_BACKUP_ROOT}"
    safe_remove_temp "${BIN_ROLLBACK}"
    safe_remove_temp "${UI_PLIST_ROLLBACK}"
    DEPLOY_BACKUP=""; DEPLOY_BACKUP_ROOT=""
    APP_STAGE_ROOT=""; APP_BACKUP_ROOT=""; APP_BACKUP=""
    BIN_ROLLBACK=""; UI_PLIST_ROLLBACK=""
    HAD_DEPLOY=0; HAD_BIN=0; HAD_APP=0; HAD_UI_PLIST=0
  }

  if [[ "${GUARDIAN_INSTALL_SIGNAL_SELF_TEST:-0}" == "1" ]]; then
    selftest_prepare_deploy
    selftest_prepare_binary
    selftest_prepare_app
    selftest_prepare_ui
    /bin/kill -TERM "$$"
    exit 98
  fi

  if [[ "${GUARDIAN_INSTALL_ROLLBACK_FAILURE_TEST:-0}" == 1 ]]; then
    selftest_prepare_binary
    /bin/mv "$BIN_ROLLBACK" "$BIN_ROLLBACK.saved"
    fail "Wymuszona awaria przywracania."
  fi

  for checkpoint in after-deploy after-backend after-app after-ui-plist; do
    selftest_prepare_deploy
    if [[ "${checkpoint}" != "after-deploy" ]]; then selftest_prepare_binary; fi
    if [[ "${checkpoint}" == "after-app" || "${checkpoint}" == "after-ui-plist" ]]; then selftest_prepare_app; fi
    if [[ "${checkpoint}" == "after-ui-plist" ]]; then selftest_prepare_ui; fi

    rollback_all
    /usr/bin/grep -Fqx 'old-deploy' "${RUNTIME_DIR}/deploy/marker"
    if [[ "${checkpoint}" != "after-deploy" ]]; then
      /usr/bin/grep -Fqx 'old-binary' "${GUARDIAN_BIN}"
    fi
    if [[ "${checkpoint}" == "after-app" || "${checkpoint}" == "after-ui-plist" ]]; then
      /usr/bin/grep -Fqx 'old-app' "${APP_DIR}/Contents/marker"
    fi
    if [[ "${checkpoint}" == "after-ui-plist" ]]; then
      /usr/bin/grep -Fqx 'old-ui' "${UI_SERVICE_PLIST}"
    fi
    selftest_cleanup_stage_roots
    green "Rollback po punkcie ${checkpoint}: OK."
  done
  green "Testy wstrzykiwania awarii: wszystkie etapy przywracają poprzednią instalację."
  exit 0
fi

printf '\n'
blue "O2 Mail Guardian ${GUARDIAN_VERSION} — instalacja lub bezpieczna aktualizacja"
printf '%s\n\n' "────────────────────────────────────────────"

[[ "$(uname -s)" == "Darwin" ]] || {
  red "Ten instalator jest przeznaczony dla macOS."
  pause_at_end
  exit 1
}

MACOS_MAJOR="$(/usr/bin/sw_vers -productVersion | /usr/bin/awk -F. '{print $1}')"
[[ "${MACOS_MAJOR}" =~ ^[0-9]+$ ]] && (( MACOS_MAJOR >= 13 )) \
  || fail "O2 Mail Guardian wymaga macOS 13 lub nowszego."
CPU_COUNT="$(/usr/sbin/sysctl -n hw.ncpu)"
MEMORY_BYTES="$(/usr/sbin/sysctl -n hw.memsize)"
FREE_KIB="$(/bin/df -Pk "${HOME}" | /usr/bin/awk 'NR==2 {print $4}')"
[[ "${CPU_COUNT}" =~ ^[0-9]+$ ]] && (( CPU_COUNT >= 2 )) \
  || fail "potrzebne są co najmniej 2 rdzenie CPU."
[[ "${MEMORY_BYTES}" =~ ^[0-9]+$ ]] && (( MEMORY_BYTES >= 2147483648 )) \
  || fail "potrzebne są co najmniej 2 GB pamięci RAM."
[[ "${FREE_KIB}" =~ ^[0-9]+$ ]] && (( FREE_KIB >= 20*1024*1024 )) \
  || fail "potrzebne jest co najmniej 20 GB wolnego miejsca na dysku."

if [[ "$DISTRIBUTION" == prebuilt ]]; then
  [[ "$(uname -m)" == arm64 ]] || fail "Ta paczka wymaga Maca Apple Silicon."
  verify_release "$PROJECT_DIR" "$GUARDIAN_VERSION" || fail "Paczka jest niekompletna lub uszkodzona. Pobierz ponownie cały ZIP."
  verify_prebuilt "$PROJECT_DIR" "$GUARDIAN_VERSION" || fail "Gotowe programy nie przeszły samokontroli. Pobierz ponownie paczkę."
else
  if ! /usr/bin/xcrun --find swift >/dev/null 2>&1; then
    /usr/bin/xcode-select --install >/dev/null 2>&1 || true
    fail "Dokończ instalację narzędzi Apple i uruchom Install.command ponownie."
  fi
fi

blue "Sprawdzam, czy ten Mac jest gotowy."
printf '  ✓ macOS %s\n  ✓ architektura %s\n  ✓ CPU: %s rdzeni, pamięć: %s GB\n  ✓ wolne miejsce: %s GB\n' \
  "$(/usr/bin/sw_vers -productVersion)" "$(uname -m)" "${CPU_COUNT}" \
  "$(( MEMORY_BYTES / 1024 / 1024 / 1024 ))" "$(( FREE_KIB / 1024 / 1024 ))"
green "Mac spełnia wymagania programu."

printf '%s\n' \
  "Instalator przygotuje lokalny silnik i program Guardian." \
  "Dopiero końcowa kontrola (lub kreator pierwszej instalacji) połączy się z o2 przez szyfrowany IMAP." \
  "System rozpocznie pracę bez trwałego kasowania wiadomości."
printf '\n'
if [[ "${GUARDIAN_INSTALL_CONFIRMED:-0}" != "1" ]]; then
  read -r -p "Rozpocząć? [T/n] " start_answer
  case "${start_answer:-T}" in
    [Nn]*) yellow "Instalacja anulowana."; pause_at_end; exit 0 ;;
  esac
fi

export GUARDIAN_SKIP_PAUSE=1
export GUARDIAN_NONINTERACTIVE=1
blue "Przygotowuję brakujące składniki."
install_external dependencies

if [[ -x /opt/homebrew/bin/brew ]]; then
  PATH="/opt/homebrew/bin:/opt/homebrew/sbin:${PATH}"
elif [[ -x /usr/local/bin/brew ]]; then
  PATH="/usr/local/bin:/usr/local/sbin:${PATH}"
fi
export PATH
export GOTOOLCHAIN=auto

if [[ "$DISTRIBUTION" == prebuilt ]]; then
  blue "Sprawdzam nową wersję przed instalacją…"
  mkdir -p "$INSTALL_DIR" "$APP_PARENT"
  chmod 700 "$INSTALL_DIR"
  BUILD_TMP="$(/usr/bin/mktemp "$INSTALL_DIR/.guardian-build.XXXXXX")"
  cp "$PROJECT_DIR/prebuilt/guardian" "$BUILD_TMP"
  chmod 755 "$BUILD_TMP"
  blue "Przygotowuję okno aplikacji…"
  APP_STAGE_ROOT="$(/usr/bin/mktemp -d "$APP_PARENT/.o2-guardian-app-stage.XXXXXX")"
  APP_STAGE="$APP_STAGE_ROOT/O2 Mail Guardian.app"
  /usr/bin/ditto "$PROJECT_DIR/prebuilt/O2 Mail Guardian.app" "$APP_STAGE"
  /usr/bin/codesign --verify --strict "$BUILD_TMP"
  /usr/bin/codesign --verify --deep --strict "$APP_STAGE"
  "$BUILD_TMP" version | /usr/bin/grep -F "O2 Mail Guardian $GUARDIAN_VERSION ("
  "$BUILD_TMP" self-test
  "$APP_STAGE/Contents/MacOS/O2MailGuardianApp" --self-test
else
if ! command -v go >/dev/null 2>&1; then
  blue "Instaluję brakujące narzędzie programu…"
  if ! brew install go; then
    fail "nie udało się zainstalować Go. Uruchom „brew doctor”, a potem ponownie Install.command."
  fi
fi
command -v swift >/dev/null 2>&1 \
  || fail "brakuje kompilatora Swift. Zainstaluj bezpłatne Command Line Tools poleceniem xcode-select --install."
command -v codesign >/dev/null 2>&1 || fail "brakuje systemowego programu codesign."

blue "Sprawdzam nową wersję przed instalacją…"
mkdir -p "${INSTALL_DIR}"
chmod 700 "${INSTALL_DIR}"
BUILD_TMP="$(/usr/bin/mktemp "${INSTALL_DIR}/.guardian-build.XXXXXX")"
(
  cd "${PROJECT_DIR}"
  go test ./...
  go vet ./...
  go build \
    -trimpath \
    -ldflags "-s -w -X main.version=${GUARDIAN_VERSION}" \
    -o "${BUILD_TMP}" \
    ./cmd/guardian
)
chmod 755 "${BUILD_TMP}"
BUILD_GO_VERSION="$(go version -m "${BUILD_TMP}" | /usr/bin/awk 'NR==1 {print $2}')"
safe_go_version "${BUILD_GO_VERSION}" \
  || fail "Guardian został zbudowany podatną wersją ${BUILD_GO_VERSION:-nieznaną}; wymagane Go 1.26.10 lub 1.27.3 albo nowsze."
"${BUILD_TMP}" version | /usr/bin/grep -F "O2 Mail Guardian ${GUARDIAN_VERSION}" >/dev/null \
  || fail "zbudowany program nie zgłasza oczekiwanej wersji ${GUARDIAN_VERSION}."

blue "Przygotowuję okno aplikacji…"
guardian_swift build --package-path "${PROJECT_DIR}/macos" --configuration release --product O2MailGuardianApp
SWIFT_BIN_DIR="$(guardian_swift build --package-path "${PROJECT_DIR}/macos" --configuration release --show-bin-path)"
[[ -x "${SWIFT_BIN_DIR}/O2MailGuardianApp" ]] \
  || fail "nie znaleziono zbudowanej aplikacji SwiftUI."
"${SWIFT_BIN_DIR}/O2MailGuardianApp" --self-test \
  || fail "aplikacja nie przeszła lokalnej samokontroli; poprzednia instalacja pozostała bez zmian."
mkdir -p "${APP_PARENT}"
APP_STAGE_ROOT="$(/usr/bin/mktemp -d "${APP_PARENT}/.o2-guardian-app-stage.XXXXXX")"
APP_STAGE="${APP_STAGE_ROOT}/O2 Mail Guardian.app"
mkdir -p "${APP_STAGE}/Contents/MacOS" "${APP_STAGE}/Contents/Resources"
/bin/cp "${SWIFT_BIN_DIR}/O2MailGuardianApp" "${APP_STAGE}/Contents/MacOS/O2MailGuardianApp"
/bin/cp "${PROJECT_DIR}/macos/Info.plist" "${APP_STAGE}/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString ${GUARDIAN_VERSION}" "${APP_STAGE}/Contents/Info.plist"
/usr/bin/plutil -lint "${APP_STAGE}/Contents/Info.plist" >/dev/null
/usr/bin/codesign --force --deep --sign - "${APP_STAGE}"
/usr/bin/codesign --verify --deep --strict "${APP_STAGE}"

fi

EXISTING_CONFIG=0
if [[ -e "${CONFIG_FILE}" ]]; then
  if [[ ! -f "${CONFIG_FILE}" ]]; then
    fail "ścieżka konfiguracji istnieje, ale nie jest zwykłym plikiem: ${CONFIG_FILE}"
  fi
  if install_external backend "${BUILD_TMP}" --config "${CONFIG_FILE}" mode status >/dev/null 2>&1; then
    EXISTING_CONFIG=1
  else
    fail "istniejąca konfiguracja jest nieczytelna. Poprzednia instalacja pozostała bez zmian; najpierw odzyskaj config.toml z kopii."
  fi
fi
SERVICE_WAS_INSTALLED=0
[[ -f "${SERVICE_PLIST}" ]] && SERVICE_WAS_INSTALLED=1
[[ -d "${APP_DIR}" ]] && HAD_APP=1
[[ -f "${UI_SERVICE_PLIST}" ]] && HAD_UI_PLIST=1
if (( HAD_UI_PLIST == 1 )); then
  UI_SUSPENDED=1
  install_external launchctl bootout "gui/${UID}/pl.o2.mail-guardian-ui" >/dev/null 2>&1 || true
fi
if (( SERVICE_WAS_INSTALLED == 1 )); then
  blue "Na chwilę wstrzymuję sprawdzanie poczty podczas aktualizacji…"
  install_external launchctl bootout "gui/${UID}/pl.o2.mail-guardian" >/dev/null 2>&1 || true
  SERVICE_SUSPENDED=1
fi

blue "Przygotowuję lokalną ochronę antyspamową…"
mkdir -p "${RUNTIME_DIR}"
chmod 700 "${RUNTIME_DIR}"
DEPLOY_STAGE="$(/usr/bin/mktemp -d "${RUNTIME_DIR}/.deploy-stage.XXXXXX")"
/usr/bin/ditto "${PROJECT_DIR}/deploy" "${DEPLOY_STAGE}"
[[ -f "${DEPLOY_STAGE}/compose.yaml" ]] \
  || fail "paczka nie zawiera deploy/compose.yaml."
GUARDIAN_RUNTIME_DIR="${RUNTIME_DIR}" \
  install_external compose compose \
    --project-name o2-mail-guardian \
    --file "${DEPLOY_STAGE}/compose.yaml" \
    config --quiet \
  || fail "nowa konfiguracja kontenerów jest nieprawidłowa; działająca wersja nie została zmieniona."

if [[ -d "${RUNTIME_DIR}/deploy" ]]; then
  DEPLOY_BACKUP_ROOT="$(/usr/bin/mktemp -d "${RUNTIME_DIR}/.deploy-backup.XXXXXX")"
  DEPLOY_BACKUP="${DEPLOY_BACKUP_ROOT}/deploy"
  /bin/mv "${RUNTIME_DIR}/deploy" "${DEPLOY_BACKUP}"
  HAD_DEPLOY=1
  # Od tej chwili każdy błąd musi przywrócić odsunięty katalog, nawet jeśli
  # następne atomowe mv nowej wersji samo się nie powiedzie.
  DEPLOY_SWITCHED=1
elif [[ -e "${RUNTIME_DIR}/deploy" ]]; then
  fail "${RUNTIME_DIR}/deploy istnieje, ale nie jest katalogiem; niczego nie nadpisano."
fi
/bin/mv "${DEPLOY_STAGE}" "${RUNTIME_DIR}/deploy"
DEPLOY_STAGE=""
DEPLOY_SWITCHED=1
inject_failure "after-deploy"

if ! install_external start-stack; then
  fail "nowy silnik nie przeszedł kontroli; sprawdź wynik przywracania w logu."
fi

blue "Włączam sprawdzoną nową wersję…"
if [[ -x "${GUARDIAN_BIN}" ]]; then
  HAD_BIN=1
  BIN_ROLLBACK="$(/usr/bin/mktemp "${INSTALL_DIR}/.guardian-rollback.XXXXXX")"
  /bin/cp -p "${GUARDIAN_BIN}" "${BIN_ROLLBACK}"
fi
/bin/mv -f "${BUILD_TMP}" "${GUARDIAN_BIN}"
BUILD_TMP=""
chmod 755 "${GUARDIAN_BIN}"
BIN_SWITCHED=1
inject_failure "after-backend"

blue "Umieszczam aplikację w folderze Aplikacje…"
if (( HAD_APP == 1 )); then
  APP_BACKUP_ROOT="$(/usr/bin/mktemp -d "${APP_PARENT}/.o2-guardian-app-backup.XXXXXX")"
  APP_BACKUP="${APP_BACKUP_ROOT}/O2 Mail Guardian.app"
  /bin/mv "${APP_DIR}" "${APP_BACKUP}"
  APP_SWITCHED=1
elif [[ -e "${APP_DIR}" ]]; then
  fail "${APP_DIR} istnieje, ale nie jest aplikacją-katalogiem; niczego nie nadpisano."
fi
/bin/mv "${APP_STAGE}" "${APP_DIR}"
APP_SWITCHED=1
inject_failure "after-app"

# Pierwsza wersja GUI domyślnie startuje po zalogowaniu. Jeżeli użytkownik w
# późniejszej aktualizacji wyłączył tę opcję, brak plist jest zachowywany.
if (( HAD_APP == 0 || HAD_UI_PLIST == 1 )); then
  mkdir -p "${HOME}/Library/LaunchAgents"
  if (( HAD_UI_PLIST == 1 )); then
    UI_PLIST_ROLLBACK="$(/usr/bin/mktemp "${HOME}/Library/LaunchAgents/.o2-mail-guardian-ui.XXXXXX")"
    /bin/cp -p "${UI_SERVICE_PLIST}" "${UI_PLIST_ROLLBACK}"
  fi
  UI_PLIST_SWITCHED=1
  install_external backend "${GUARDIAN_BIN}" app-service install
  UI_SUSPENDED=0
fi
inject_failure "after-ui-plist"

# Komenda działa od razu w nowych oknach Terminala, bez edycji ręcznej.
PROFILE="${HOME}/.zprofile"
PATH_LINE='export PATH="$HOME/.local/bin/o2-mail-guardian:$PATH"'
if [[ ! -f "${PROFILE}" ]] || ! grep -Fqx "${PATH_LINE}" "${PROFILE}"; then
  printf '\n%s\n' '# O2 Mail Guardian' "${PATH_LINE}" >> "${PROFILE}"
fi
export PATH="${INSTALL_DIR}:${PATH}"

green "Pliki programu zostały zainstalowane."
printf '\n'
if (( EXISTING_CONFIG == 0 )); then
  blue "To pierwsza instalacja — kreator konta otworzy się w aplikacji."
else
  green "Zachowano Twoje ustawienia i dotychczasowe dane ochrony."
  blue "Wykonuję kontrolę po aktualizacji bez ponownego pytania o hasło…"
  if ! install_external backend "${GUARDIAN_BIN}" doctor; then
    INSTALL_RESULT=attention
    yellow "Aktualizacja programu zakończyła się, ale kontrola wykryła problem operacyjny."
    yellow "Otwórz aplikację O2 Mail Guardian i wybierz „Sprawdź i napraw”. Nie zmieniono zapisanego hasła."
  else
    green "Kontrola po aktualizacji zakończyła się pomyślnie."
  fi
  if (( SERVICE_WAS_INSTALLED == 1 )); then
    if ! install_external backend "${GUARDIAN_BIN}" service install; then
      INSTALL_RESULT=attention
      yellow "Nie udało się wznowić sprawdzania w tle. W aplikacji wybierz „Sprawdź i napraw”."
    else
      SERVICE_SUSPENDED=0
    fi
  fi
fi

# Dopiero po pomyślnym wdrożeniu wszystkich elementów poprzednie wersje stają
# się zwykłą kopią aktualizacyjną. Do tego miejsca trap może cofnąć całość.
if (( HAD_DEPLOY == 1 )); then
  PREVIOUS_DEPLOY="${RUNTIME_DIR}/deploy.previous"
  [[ ! -e "${PREVIOUS_DEPLOY}" ]] || /bin/rm -rf -- "${PREVIOUS_DEPLOY}"
  /bin/mv "${DEPLOY_BACKUP}" "${PREVIOUS_DEPLOY}"
  /bin/rmdir "${DEPLOY_BACKUP_ROOT}"
  DEPLOY_BACKUP_ROOT=""
fi
DEPLOY_SWITCHED=0
if (( HAD_BIN == 1 )); then
  /bin/mv -f "${BIN_ROLLBACK}" "${INSTALL_DIR}/guardian.previous"
  BIN_ROLLBACK=""
fi
BIN_SWITCHED=0
safe_remove_temp "${APP_BACKUP_ROOT}"
APP_BACKUP_ROOT=""
APP_SWITCHED=0
safe_remove_temp "${APP_STAGE_ROOT}"
APP_STAGE_ROOT=""
safe_remove_temp "${UI_PLIST_ROLLBACK}"
UI_PLIST_ROLLBACK=""
UI_PLIST_SWITCHED=0
resume_scanner_if_needed || INSTALL_RESULT=attention

printf '\n'
green "Instalacja O2 Mail Guardian ${GUARDIAN_VERSION} zakończona."
printf '%s\n' \
  "Aplikacja jest w folderze ~/Applications." \
  "Awaryjnie nadal możesz użyć Guardian.command lub polecenia guardian menu."

if ! install_external open "${APP_DIR}"; then
  install_external open -R "${APP_DIR}" >/dev/null 2>&1 || true
  INSTALL_RESULT=attention
  yellow "Instalacja jest gotowa, ale aplikacja nie otworzyła się automatycznie. Finder wskazał ją — kliknij dwukrotnie."
fi
write_install_result "$INSTALL_RESULT"
pause_at_end
