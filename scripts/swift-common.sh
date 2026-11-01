#!/bin/bash
# Prefer a complete SwiftUI toolchain without changing xcode-select globally.
# An explicit DEVELOPER_DIR remains authoritative.
if [[ -z "${DEVELOPER_DIR:-}" && -d /Applications/Xcode.app/Contents/Developer ]]; then
  if [[ "$(/usr/bin/xcode-select -p 2>/dev/null)" == /Library/Developer/CommandLineTools ]]; then
    export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
  fi
fi

guardian_swift() {
  if [[ -n "${GUARDIAN_SWIFT_SCRATCH_DIR:-}" ]]; then
    /usr/bin/swift "$@" --scratch-path "$GUARDIAN_SWIFT_SCRATCH_DIR"
  else
    /usr/bin/swift "$@"
  fi
}
