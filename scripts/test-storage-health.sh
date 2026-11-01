#!/bin/bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
source "$SCRIPT_DIR/storage-health.sh"
for message in 'I/O error, dev vdb, sector 25538456' 'Buffer I/O error on device vdb1' 'EXT4-fs (vdb1): failed to convert unwritten extents to written extents -- potential data loss!'; do
  if guardian_check_storage_log "$message" >/dev/null 2>&1; then printf 'Pominięto błąd dysku\n' >&2; exit 1; fi
done
guardian_check_storage_log 'EXT4-fs (vdb1): mounted filesystem r/w'
guardian_check_storage_log ''
colima() { return 93; }
if guardian_check_guest_storage >/dev/null 2>&1; then printf 'Brak odczytu dysku uznano za sukces\n' >&2; exit 1; fi
printf 'Błędy zapisu dysku blokują start i instalację: OK\n'
