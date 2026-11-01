#!/bin/bash
# Match the fail-closed storage gate used by internal/stack/storage_health.go.
guardian_check_storage_log() {
  if printf '%s\n' "$1" | /usr/bin/grep -Eiq 'I/O error(,| on)|EXT4-fs.*(failed to convert unwritten|Aborting journal|Remounting filesystem read-only)|EXT4-fs error'; then
    printf '%s\n' 'Wirtualny dysk Colimy zgłosił błąd zapisu. Zachowaj kopie i sprawdź dysk offline; aktualizacja nie zrestartuje silnika z takim błędem.' >&2
    return 1
  fi
}
guardian_check_guest_storage() {
  local storage_log
  storage_log="$(colima ssh -- sudo dmesg --level=err,warn)" || {
    printf '%s\n' 'Nie można potwierdzić sprawności dysku Colimy.' >&2
    return 1
  }
  guardian_check_storage_log "$storage_log"
}
