#!/bin/bash

set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
source "${PROJECT_DIR}/scripts/swift-common.sh"
SWIFT_ARGS=(test --package-path "${PROJECT_DIR}/macos")
DEVELOPER_FRAMEWORKS="/Library/Developer/CommandLineTools/Library/Developer/Frameworks"

# Testuje również prawdziwy most Process -> JSON używany przez GUI, ale wyłącznie
# przeciw lokalnej atrapie bez dostępu do poczty, Keychain i usług systemowych.
export GUARDIAN_BIN="${PROJECT_DIR}/scripts/mock-gui-backend.sh"
export GUARDIAN_MOCK_SCENARIO=healthy
export GUARDIAN_MOCK_STATE="${TMPDIR:-/tmp}/o2-mail-guardian-swift-test.$$.state"
trap '/bin/rm -f -- "${GUARDIAN_MOCK_STATE}"' EXIT

# Pełny Xcode konfiguruje framework testowy sam. Samodzielne Command Line
# Tools 26 zawierają go, lecz nie dodają automatycznie ścieżki do SwiftPM.
if [[ "${DEVELOPER_DIR:-$(/usr/bin/xcode-select -p)}" == /Library/Developer/CommandLineTools ]] && [[ -d "${DEVELOPER_FRAMEWORKS}/Testing.framework" ]]; then
  SWIFT_ARGS+=(
    -Xswiftc -F -Xswiftc "${DEVELOPER_FRAMEWORKS}"
    -Xlinker -F -Xlinker "${DEVELOPER_FRAMEWORKS}"
    -Xlinker -rpath -Xlinker "${DEVELOPER_FRAMEWORKS}"
  )
  TESTING_PLUGIN="/Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing/libTestingMacros.dylib"
  if [[ -f "${TESTING_PLUGIN}" ]]; then
    SWIFT_ARGS+=(-Xswiftc -load-plugin-library -Xswiftc "${TESTING_PLUGIN}")
  fi
fi

guardian_swift "${SWIFT_ARGS[@]}"
