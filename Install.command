#!/bin/bash

# Jedyny plik, który użytkownik musi uruchomić. Cała techniczna instalacja
# znajduje się w scripts/install-core.sh i zapisuje szczegóły do prywatnego
# logu, dzięki czemu to okno pokazuje tylko zrozumiałe etapy.
set -uo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
CORE="${PROJECT_DIR}/scripts/install-core.sh"
LOG_DIR="${HOME}/Library/Logs/O2 Mail Guardian"
LOG_FILE="${LOG_DIR}/instalacja.log"
STATUS_FILE="${LOG_DIR}/instalacja-status.txt"
RESULT_FILE="${LOG_DIR}/instalacja-wynik.txt"

# W repozytorium rdzeń jest w scripts/. W gotowej paczce wydania cały
# techniczny payload jest schowany, aby użytkownik widział tylko instalator.
if [[ ! -f "${CORE}" && -f "${PROJECT_DIR}/.payload/scripts/install-core.sh" ]]; then
  CORE="${PROJECT_DIR}/.payload/scripts/install-core.sh"
fi

if [[ "${GUARDIAN_INSTALL_WRAPPER_TEST:-0}" == "1" ]]; then
  case "${HOME}" in
    /tmp/o2-guardian-wrapper-test.*) ;;
    *) printf '%s\n' "Test interfejsu instalatora wymaga izolowanego HOME." >&2; exit 2 ;;
  esac
  CORE="${GUARDIAN_INSTALL_TEST_CORE:?brakuje testowego rdzenia instalatora}"
fi

red() { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
pause_at_end() {
  if [[ "${GUARDIAN_SKIP_PAUSE:-0}" != "1" && -t 0 ]]; then
    printf '\n'
    read -r -p "Press Enter to close this window…" _
  fi
}

[[ -f "${CORE}" ]] || {
  red "Installer components are missing. Download the complete application folder again."
  pause_at_end
  exit 1
}

# Test rollbacku ma własny izolowany interfejs i nie powinien tworzyć logu w
# prawdziwym katalogu użytkownika.
if [[ "${GUARDIAN_INSTALL_SELF_TEST:-0}" == "1" ]]; then
  exec /bin/bash "${CORE}"
fi

printf '\n\033[1;34mMail Guardian — installation\033[0m\n'
printf '%s\n' \
  "This prepares local email protection and opens the setup wizard." \
  "No email address or password is requested at this stage." \
  "Installation will not enable permanent message deletion."

if [[ "${GUARDIAN_INSTALL_CONFIRMED:-0}" != "1" && "${GUARDIAN_LAUNCHED_FROM_SHORTCUT:-0}" != "1" ]]; then
  printf '\n'
  read -r -p "Press Enter to start, or type N and Enter to cancel: " answer
  case "${answer:-}" in
    [Nn]*) printf '%s\n' "Installation cancelled — nothing changed."; pause_at_end; exit 0 ;;
  esac
fi

LOCK_HELPER="${PROJECT_DIR}/scripts/install-lock.sh"
[[ -f "$LOCK_HELPER" ]] || LOCK_HELPER="${PROJECT_DIR}/.payload/scripts/install-lock.sh"
source "$LOCK_HELPER" || exit 1
install_lock_acquire || exit 1
trap install_lock_release EXIT
child_pid=""
stop_install() {
  trap '' HUP INT TERM
  if [[ -n "$child_pid" ]]; then kill -TERM "$child_pid" 2>/dev/null || true; wait "$child_pid" || true; fi
  exit 130
}
trap stop_install HUP INT TERM
umask 077
/bin/mkdir -p "${LOG_DIR}" || {
  red "Could not prepare a private installation log."
  pause_at_end
  exit 1
}
/bin/chmod 700 "${LOG_DIR}" 2>/dev/null || true
: > "${LOG_FILE}"
: > "${STATUS_FILE}"
: > "${RESULT_FILE}"
/bin/chmod 600 "${LOG_FILE}" "${STATUS_FILE}" 2>/dev/null || true

printf '\n%s\n' "You may leave this window open. Installation usually takes several minutes."
printf '%s\n\n' "macOS may request an administrator password once while installing supporting tools."

# Deskryptor 3 służy wyłącznie do krótkich komunikatów dla użytkownika.
# Pełny zapis techniczny trafia do prywatnego pliku instalacja.log.
exec 3>&1
GUARDIAN_INSTALL_CONFIRMED=1 \
   GUARDIAN_INSTALL_UI_FD=3 \
   GUARDIAN_INSTALL_STATUS_FILE="${STATUS_FILE}" \
   GUARDIAN_INSTALL_RESULT_FILE="${RESULT_FILE}" \
   GUARDIAN_SKIP_PAUSE=1 \
   /bin/bash "${CORE}" >"${LOG_FILE}" 2>&1 &
child_pid=$!
core_status=0
wait "$child_pid" || core_status=$?
child_pid=""
result="$(cat "$RESULT_FILE")"
if [[ "$core_status" == 0 && "$result" == attention ]]; then
  printf '\n%s\n' "Application installed — protection needs attention." "Open the application and choose Check and repair. Details: ${LOG_FILE}"
  exit 0
fi
if [[ "$core_status" == 0 && "$result" == success ]]; then
  printf '\n'
  green "Done. Mail Guardian is installed."
  printf '%s\n' "Continue setup in the application."
  exit 0
fi

printf '\n'
red "Installation completion was not confirmed. Read the message below and the rollback result in the log."
if [[ -s "${STATUS_FILE}" ]]; then
  while IFS= read -r line; do red "${line}"; done < "${STATUS_FILE}"
fi
printf '%s\n' "Read the guidance above. If rollback failed, retain backups and share the log with your support contact." >&2
printf '%s\n' "Technical support details saved here:" "${LOG_FILE}" >&2
if [[ "${GUARDIAN_INSTALL_WRAPPER_TEST:-0}" != "1" ]]; then
  /usr/bin/open -R "${LOG_FILE}" >/dev/null 2>&1 || true
fi
pause_at_end
exit 1
