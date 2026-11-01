#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/_infra-common.sh"

trap 'fail "engine shutdown interrupted (line ${LINENO})."' ERR

header "stopping the engine safely"
require_macos
setup_homebrew_path
require_command docker

if ! docker --context colima info >/dev/null 2>&1; then
  yellow "Docker is already stopped."
  pause_at_end
  exit 0
fi

choose_compose
blue "Stopping three containers…"
compose down --remove-orphans

green "Engine stopped."
printf '%s\n' \
  "Trained Bayes data and configuration retained." \
  "This script does not delete volumes, passwords or messages."
notify_user "Spam protection engine stopped."
pause_at_end
