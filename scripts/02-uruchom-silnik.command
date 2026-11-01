#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/_infra-common.sh"
source "${SCRIPT_DIR}/storage-health.sh"

trap 'fail "engine startup interrupted (line ${LINENO})."' ERR

KEYCHAIN_SERVICE="pl.o2.mail-guardian.rspamd"
KEYCHAIN_ACCOUNT="controller"
RSPAMD_IMAGE="rspamd/rspamd:4.1.2@sha256:15dfe447f8913516c4ff24933a0727aff53d88bf38ef1937fb74f5152568f496"
CONTROLLER_CONFIG="${RUNTIME_DIR}/rspamd/worker-controller.inc"
CONTROLLER_TEMPLATE="${COMPOSE_CONFIG_DIR}/rspamd/worker-controller.inc.example"

header "starting the local spam engine"
require_macos
setup_homebrew_path
require_command colima
require_command docker
require_command security

if ! colima status >/dev/null 2>&1; then
  blue "Pierwsze uruchomienie Colimy (2 CPU, 2 GB RAM, 20 GB dysku)…"
  colima start --runtime docker --cpus 2 --memory 2 --disk 20 --activate=false
fi

wait_for_docker
guardian_check_guest_storage || fail "Colima disk check blocked restart; model and engine files unchanged."
choose_compose

mkdir -p "${RUNTIME_DIR}/rspamd"
chmod 700 "${RUNTIME_DIR}" "${RUNTIME_DIR}/rspamd"

if controller_password="$(security find-generic-password -a "${KEYCHAIN_ACCOUNT}" -s "${KEYCHAIN_SERVICE}" -w 2>/dev/null)"; then
  green "Existing controller password found in Keychain."
else
  blue "Creating a random controller password and saving it in macOS Keychain…"
  controller_password="$(/usr/bin/openssl rand -hex 32)"
  # security(1) prompts twice when -w is last. Send the value through stdin
  # so it never appears in process arguments visible to ps.
  printf '%s\n%s\n' "${controller_password}" "${controller_password}" |
    security add-generic-password \
      -a "${KEYCHAIN_ACCOUNT}" \
      -s "${KEYCHAIN_SERVICE}" \
      -l "Mail Guardian — Rspamd" \
      -j "Local Rspamd controller; this is not an email password." \
      -U \
      -w >/dev/null
fi

blue "Pobieram zweryfikowany obraz Rspamd 4.1.2…"
docker --context colima pull "${RSPAMD_IMAGE}" >/dev/null

controller_hash="$(
  # Rspamd 4.1.2 pw does not read stdin. Pass the secret through stdin to an
  # isolated container so it stays out of Mac process arguments.
  # Kontener nie ma sieci i znika po wygenerowaniu hasha.
  printf '%s\n' "${controller_password}" |
    docker --context colima run --rm --interactive --network none --read-only --cap-drop ALL \
      --entrypoint /bin/sh "${RSPAMD_IMAGE}" \
      -c 'IFS= read -r password; exec rspamadm pw --quiet --password "$password"'
)"
[[ "${controller_hash}" == \$* ]] || fail "Rspamd did not generate a valid controller hash."

runtime_tmp="${CONTROLLER_CONFIG}.tmp.$$"
sed "s|__RSPAMD_PASSWORD_HASH__|${controller_hash}|g" \
  "${CONTROLLER_TEMPLATE}" > "${runtime_tmp}"
chmod 600 "${runtime_tmp}"
mv -f "${runtime_tmp}" "${CONTROLLER_CONFIG}"
unset controller_password controller_hash

blue "Checking configuration and pulling remaining images…"
compose config --quiet
compose pull

blue "Uruchamiam Rspamd, Redis i Unbound…"
compose up --detach --wait --force-recreate --remove-orphans

wait_for_rspamd

blue "Verifying running Rspamd configuration…"
compose exec -T rspamd rspamadm configtest >/dev/null \
  || fail "Rspamd started, but its configuration failed final checks."

green "Spam protection engine works correctly."
printf '%s\n' \
  "Panel diagnostyczny: http://127.0.0.1:11334" \
  "Trained Bayes data is retained across restarts."
notify_user "Local spam protection engine works."
pause_at_end
