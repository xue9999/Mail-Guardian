#!/bin/bash

# Shared functions for macOS command scripts.
# shellcheck disable=SC1111

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
DEPLOY_DIR="${PROJECT_DIR}/deploy"
RUNTIME_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/o2-mail-guardian"
if [[ -f "${RUNTIME_DIR}/deploy/compose.yaml" ]]; then
  COMPOSE_CONFIG_DIR="${RUNTIME_DIR}/deploy"
else
  COMPOSE_CONFIG_DIR="${DEPLOY_DIR}"
fi
COMPOSE_FILE="${COMPOSE_CONFIG_DIR}/compose.yaml"

export GUARDIAN_RUNTIME_DIR="${RUNTIME_DIR}"

blue() {
  printf '\033[1;34m%s\033[0m\n' "$*"
}

green() {
  printf '\033[1;32m%s\033[0m\n' "$*"
}

yellow() {
  printf '\033[1;33m%s\033[0m\n' "$*"
}

red() {
  printf '\033[1;31m%s\033[0m\n' "$*" >&2
}

header() {
  printf '\n'
  blue "Mail Guardian — $*"
  printf '%s\n\n' "────────────────────────────────────────────"
}

pause_at_end() {
  if [[ "${GUARDIAN_SKIP_PAUSE:-0}" == "1" ]]; then
    return 0
  fi
  if [[ -t 0 ]]; then
    printf '\n'
    read -r -p "Press Enter to close this window…" _
  fi
}

fail() {
  red "Failed: $*"
  red "No mailbox messages or engine data were deleted."
  pause_at_end
  exit 1
}

require_macos() {
  [[ "$(uname -s)" == "Darwin" ]] || fail "this installer requires macOS."
}

setup_homebrew_path() {
  if [[ -x /opt/homebrew/bin/brew ]]; then
    PATH="/opt/homebrew/bin:/opt/homebrew/sbin:${PATH}"
  elif [[ -x /usr/local/bin/brew ]]; then
    PATH="/usr/local/bin:/usr/local/sbin:${PATH}"
  fi
  export PATH
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing $1. Run 01-zainstaluj-wymagania.command first."
}

choose_compose() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker --context colima compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    fail "Docker Compose not found. Run prerequisite installation again."
  fi
}

wait_for_docker() {
  local attempt
  for attempt in {1..60}; do
    # An explicit context preserves the user-wide Docker setting.
    if docker --context colima info >/dev/null 2>&1; then
      return 0
    fi
    : "${attempt}"
    sleep 2
  done
  fail "Docker engine did not start within two minutes."
}

compose() {
  DOCKER_CONTEXT=colima "${COMPOSE[@]}" --project-name o2-mail-guardian --file "${COMPOSE_FILE}" "$@"
}

wait_for_rspamd() {
  local attempt port healthy response
  for attempt in {1..60}; do
    healthy=1
    for port in 11333 11334; do
      response="$(/usr/bin/curl -fsS --max-time 2 "http://127.0.0.1:${port}/ping" 2>/dev/null || true)"
      if [[ "${response%$'\r'}" != "pong" ]]; then
        healthy=0
        break
      fi
    done
    if (( healthy == 1 )); then
      return 0
    fi
    : "${attempt}"
    sleep 1
  done
  fail "Rspamd did not respond on local ports 11333 and 11334 within one minute."
}

notify_user() {
  local message="$1"
  /usr/bin/osascript -e "display notification \"${message//\"/\\\"}\" with title \"Mail Guardian\"" >/dev/null 2>&1 || true
}
