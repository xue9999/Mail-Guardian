#!/bin/bash
set -Eeuo pipefail
PROJECT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
source "$PROJECT_DIR/scripts/release-common.sh"
for version in go1.26.10 go1.26.11 go1.27.3 go1.27.10 go1.28.0; do
  safe_go_version "$version" || { printf 'Odrzucono poprawione Go: %s\n' "$version" >&2; exit 1; }
done
for version in go1.25.13 go1.26.6 go1.26.8 go1.26.9 go1.27.0 go1.27.1 go1.27.2 go1.27.3rc1 go1.27.2garbage unknown ''; do
  if safe_go_version "$version"; then
    printf 'Przyjęto podatne lub nieznane Go: %s\n' "$version" >&2; exit 1
  fi
done
# Respect a developer directory selected by the caller, even when it is CLT.
DEVELOPER_DIR=/Library/Developer/CommandLineTools
source "$PROJECT_DIR/scripts/swift-common.sh"
[[ "$DEVELOPER_DIR" == /Library/Developer/CommandLineTools ]]
unset DEVELOPER_DIR
source "$PROJECT_DIR/scripts/swift-common.sh"
if [[ -d /Applications/Xcode.app/Contents/Developer && "$(/usr/bin/xcode-select -p)" == /Library/Developer/CommandLineTools ]]; then
  [[ "$DEVELOPER_DIR" == /Applications/Xcode.app/Contents/Developer ]]
fi
printf 'Poprawione Go i wybór narzędzi Swift: OK\n'
