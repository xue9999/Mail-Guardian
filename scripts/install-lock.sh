#!/bin/bash
# The wrapper owns the lock across the child core, including rollback.
install_lock_acquire() {
  INSTALL_LOCK_DIR="${HOME}/Library/Logs/O2 Mail Guardian/install.lock"
  INSTALL_LOCK_OWNED=0
  local parent_owner="${GUARDIAN_INSTALL_LOCK_OWNER:-}"
  if [[ "$parent_owner" == "$PPID" && -f "$INSTALL_LOCK_DIR/owner" && "$(cat "$INSTALL_LOCK_DIR/owner")" == "$parent_owner" ]]; then
    return 0
  fi
  umask 077
  mkdir -p "$(dirname "$INSTALL_LOCK_DIR")" || return 1
  if ! mkdir "$INSTALL_LOCK_DIR" 2>/dev/null; then
    printf 'Another installation is running or left a lock: %s\n' "$INSTALL_LOCK_DIR" >&2
    printf 'Wait for the installer to close. After a crash, verify in Activity Monitor that the installer and its children have exited before removing install.lock and retrying.\n' >&2
    return 1
  fi
  printf '%s\n' "$$" > "$INSTALL_LOCK_DIR/owner" || return 1
  INSTALL_LOCK_OWNED=1
  export GUARDIAN_INSTALL_LOCK_OWNER="$$"
}
install_lock_release() {
  if [[ "${INSTALL_LOCK_OWNED:-0}" == 1 && -f "$INSTALL_LOCK_DIR/owner" && "$(cat "$INSTALL_LOCK_DIR/owner")" == "$$" ]]; then
    /bin/rm "$INSTALL_LOCK_DIR/owner"
    /bin/rmdir "$INSTALL_LOCK_DIR"
  fi
}
