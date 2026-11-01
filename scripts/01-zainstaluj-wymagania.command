#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/_infra-common.sh"

trap 'fail "prerequisite installation interrupted (line ${LINENO})."' ERR

header "installing required tools"
require_macos
setup_homebrew_path

printf '%s\n' \
  "This installs Homebrew, Colima, Docker and Compose." \
  "It does not connect to a mailbox or change messages."
printf '\n'
if [[ "${GUARDIAN_NONINTERACTIVE:-0}" != "1" ]]; then
  read -r -p "Continue? [Y/n] " answer
  case "${answer:-Y}" in
    [Nn]*) yellow "Installation cancelled."; pause_at_end; exit 0 ;;
  esac
fi

if ! command -v brew >/dev/null 2>&1; then
  blue "Installing Homebrew with the official installer…"
  NONINTERACTIVE=1 /bin/bash -c "$(/usr/bin/curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  setup_homebrew_path
fi

command -v brew >/dev/null 2>&1 || fail "Homebrew unavailable after installation."
if ! brew config >/dev/null 2>&1; then
  fail "Homebrew is installed but not working correctly. Run brew doctor and fix only the reported directories; this installer does not recursively change /opt/homebrew ownership."
fi

packages=(colima docker docker-compose)
missing=()
for package in "${packages[@]}"; do
  if ! brew list --formula "${package}" >/dev/null 2>&1; then
    missing+=("${package}")
  fi
done

if (( ${#missing[@]} > 0 )); then
  blue "Installing: ${missing[*]}…"
  if ! brew install "${missing[@]}"; then
    fail "Homebrew did not install required tools. Run brew doctor; do not use chown -R on all of /opt/homebrew."
  fi
else
  green "All required tools are already installed."
fi

require_command colima
require_command docker

# Homebrew installs Compose outside the Docker CLI default plugin path.
# A private user-directory link preserves ~/.docker/config.json.
if ! docker compose version >/dev/null 2>&1; then
  compose_source="$(brew --prefix)/lib/docker/cli-plugins/docker-compose"
  compose_target="${HOME}/.docker/cli-plugins/docker-compose"
  [[ -x "${compose_source}" ]] || fail "Docker Compose plugin not found after installation."
  mkdir -p "${HOME}/.docker/cli-plugins"
  if [[ -L "${compose_target}" ]]; then
    ln -sfn "${compose_source}" "${compose_target}"
  elif [[ ! -e "${compose_target}" ]]; then
    ln -s "${compose_source}" "${compose_target}"
  elif [[ ! -x "${compose_target}" ]]; then
    fail "${compose_target} exists but is not a working plugin. Move that one file to a safe location and retry installation."
  fi
fi

if ! docker compose version >/dev/null 2>&1; then
  fail "Docker Compose unavailable. Inspect the existing plugin in ~/.docker/cli-plugins."
fi

green "Required tools are ready."
printf '%s\n' "Teraz uruchom dwuklikiem: 02-uruchom-silnik.command"
pause_at_end
