#!/bin/bash
# Match the fail-closed storage gate used by internal/stack/storage_health.go.
guardian_check_storage_log() {
  if printf '%s\n' "$1" | /usr/bin/grep -Eiq 'I/O error(,| on)|EXT4-fs.*(failed to convert unwritten|Aborting journal|Remounting filesystem read-only)|EXT4-fs error'; then
    printf '%s\n' 'Colima virtual disk reported a write error. Retain backups and check the disk offline; this update will not restart an engine with that error.' >&2
    return 1
  fi
}
guardian_check_guest_storage() {
  local storage_log
  storage_log="$(colima ssh -- sudo dmesg --level=err,warn)" || {
    printf '%s\n' 'Cannot confirm Colima disk health.' >&2
    return 1
  }
  guardian_check_storage_log "$storage_log"
}
