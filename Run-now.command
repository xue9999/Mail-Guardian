#!/bin/bash

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/scripts/_launcher-common.sh"

if ! ensure_guardian_installed; then
  launcher_pause
  exit 1
fi

if ! "${GUARDIAN_BIN}" stack status >/dev/null 2>&1; then
  launcher_yellow "Local engine is not ready. Attempting a safe start…"
  if ! "${GUARDIAN_BIN}" stack up; then
    launcher_red "Could not start the local engine."
    if ! offer_guardian_repair; then
      launcher_pause
      exit 1
    fi
  fi
fi

if "${GUARDIAN_BIN}" run; then
  launcher_green "Mailbox check completed successfully."
  result=0
else
  launcher_red "Mailbox check failed. Safety guards remain in effect."
  if offer_guardian_repair; then
    launcher_yellow "Ponawiam sprawdzanie po udanej naprawie…"
    if "${GUARDIAN_BIN}" run; then
      launcher_green "Repeated check completed successfully."
      result=0
    else
      launcher_red "Retry also failed. Open Mail Guardian and choose Check and repair."
      result=1
    fi
  else
    result=1
  fi
fi

printf '\n'
launcher_pause
exit "${result}"
