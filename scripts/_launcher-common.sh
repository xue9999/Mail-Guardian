#!/bin/bash

# Shared messages for double-click launchers.

set -u

LAUNCHER_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
LAUNCHER_PROJECT_DIR="$(cd -- "${LAUNCHER_SCRIPT_DIR}/.." && pwd -P)"
GUARDIAN_BIN="${HOME}/.local/bin/o2-mail-guardian/guardian"

launcher_green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
launcher_yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
launcher_red() { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

launcher_pause() {
  if [[ -t 0 ]]; then
    printf '\n'
    read -r -p "Press Enter to close this window…" _
  fi
}

launcher_confirm() {
  local question="$1"
  local answer
  if [[ ! -t 0 ]]; then
    return 1
  fi
  read -r -p "${question} [Y/n] " answer
  case "${answer:-Y}" in
    [Nn]*) return 1 ;;
    *) return 0 ;;
  esac
}

ensure_guardian_installed() {
  if [[ -x "${GUARDIAN_BIN}" ]]; then
    return 0
  fi
  launcher_yellow "Mail Guardian is not installed yet."
  if [[ ! -f "${LAUNCHER_PROJECT_DIR}/Install.command" ]]; then
    launcher_red "Install.command is missing. Download the complete package again."
    return 1
  fi
  if ! launcher_confirm "Run the safe installer now?"; then
    launcher_yellow "Installation skipped."
    return 1
  fi
  if ! GUARDIAN_LAUNCHED_FROM_SHORTCUT=1 /bin/bash "${LAUNCHER_PROJECT_DIR}/Install.command"; then
    launcher_red "Installation did not complete. Read the error above."
    return 1
  fi
  if [[ ! -x "${GUARDIAN_BIN}" ]]; then
    launcher_red "Installer exited, but the program is still unavailable."
    return 1
  fi
}

offer_guardian_repair() {
  launcher_yellow "The program can attempt a safe repair without changing messages."
  if ! launcher_confirm "Check and repair the application?"; then
    launcher_yellow "Repair skipped. No message was deleted as a result."
    return 1
  fi
  if ! "${GUARDIAN_BIN}" napraw; then
    launcher_red "Automatic repair did not resolve the problem."
    launcher_red "Open Mail Guardian and save a safe report from Help."
    return 1
  fi
  launcher_green "Repair completed successfully."
}
