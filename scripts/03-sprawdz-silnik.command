#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/_infra-common.sh"

trap 'fail "engine test interrupted (line ${LINENO})."' ERR

header "checking engine health"
require_macos
setup_homebrew_path
require_command colima
require_command docker

if ! colima status >/dev/null 2>&1; then
  fail "Colima is not running. Run 02-uruchom-silnik.command."
fi

wait_for_docker
choose_compose

printf 'Colima:  '
green "working"

printf '\nKontenery:\n'
compose ps

blue "Testing Redis…"
[[ "$(docker --context colima exec o2-mail-guardian-redis redis-cli --raw ping)" == "PONG" ]] \
  || fail "Redis is not responding."

blue "Testing secure DNS…"
docker --context colima exec o2-mail-guardian-unbound drill-hc @127.0.0.1 dnssec.works >/dev/null \
  || fail "Unbound is not resolving DNS correctly."

blue "Testing Rspamd configuration…"
docker --context colima exec o2-mail-guardian-rspamd rspamadm configtest >/dev/null \
  || fail "konfiguracja Rspamd jest niepoprawna."

for rspamd_port in 11333 11334; do
  [[ "$(/usr/bin/curl -fsS --max-time 5 "http://127.0.0.1:${rspamd_port}/ping")" == "pong" ]] \
    || fail "local Rspamd port ${rspamd_port} is not responding."
done

green "All tests passed."
printf '%s\n' "Panel diagnostyczny: http://127.0.0.1:11334"
notify_user "All engine tests passed."
pause_at_end
