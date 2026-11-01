#!/bin/bash

set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
MOCK="${PROJECT_DIR}/scripts/mock-gui-backend.sh"
STATE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/o2-mail-guardian-mock-test.XXXXXX")"
STATE_FILE="${STATE_ROOT}/state"
trap '/bin/rm -rf -- "${STATE_ROOT}"' EXIT

export GUARDIAN_MOCK_SCENARIO=unconfigured
export GUARDIAN_MOCK_STATE="${STATE_FILE}"

require_json() {
  local document="$1"
  local fragment="$2"
  if [[ "${document}" != *"${fragment}"* ]]; then
    printf 'Missing expected JSON fragment: %s\nResponse: %s\n' "${fragment}" "${document}" >&2
    exit 1
  fi
}

snapshot="$("${MOCK}" api snapshot)"
require_json "${snapshot}" '"configured":false'
require_json "${snapshot}" '"first_dry_run":false'

commit_request='{"email":"test@o2.pl","password":"secret-only-for-local-mock","spam_folder":"Spam","accept_existing_training":true}'
commit="$(printf '%s' "${commit_request}" | "${MOCK}" api setup commit)"
require_json "${commit}" '"configured":true'

snapshot="$("${MOCK}" api snapshot)"
require_json "${snapshot}" '"configured":true'
require_json "${snapshot}" '"automation":"off"'
require_json "${snapshot}" '"first_dry_run":false'

"${MOCK}" api run dry-run >/dev/null
snapshot="$("${MOCK}" api snapshot)"
require_json "${snapshot}" '"first_dry_run":true'

"${MOCK}" api service enable >/dev/null
snapshot="$("${MOCK}" api snapshot)"
require_json "${snapshot}" '"automation":"on"'

if rg -q 'secret-only-for-local-mock|test@o2.pl' "${STATE_FILE}"; then
  printf 'Mock saved account data or secret in state file.\n' >&2
  exit 1
fi

printf 'Mock GUI onboarding: OK\n'
