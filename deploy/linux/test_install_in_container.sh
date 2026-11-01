#!/bin/bash
# Initial-install test. Run only in a throwaway Ubuntu container with no
# host filesystem, Docker socket, production credentials or mailbox mounted.
set -Eeuo pipefail
[[ "${GUARDIAN_DISPOSABLE_CONTAINER:-}" == 1 && -f /.dockerenv && "$(id -u)" == 0 ]] || {
  printf 'This test requires an explicitly authorized disposable root container.\n' >&2
  exit 1
}
[[ $# == 1 && -f "$1/SHA256SUMS" ]] || { printf 'Pass the extracted package directory.\n' >&2; exit 1; }
GUARDIAN_NATIVE_PACKAGE="$(cd -- "$1" && pwd -P)"
[[ -x /usr/sbin/useradd && -x /usr/sbin/visudo && -x /usr/bin/sudo && -x /usr/bin/systemctl ]] || {
  printf 'Install passwd, systemd and the release-default sudo implementation inside the disposable container first.\n' >&2
  exit 1
}
[[ ! -e /etc/mail-guardian && ! -e /opt/mail-guardian ]] || { printf 'Container must start without a Guardian installation.\n' >&2; exit 1; }
# Retain the installed release's actual version while stubbing service actions;
# a container without booted systemd cannot prove service or reboot acceptance.
GUARDIAN_FIXTURE_SYSTEMD_VERSION="$(/usr/bin/systemctl --version)"
printf '%s\n' "${GUARDIAN_FIXTURE_SYSTEMD_VERSION%%$'\n'*}" > /tmp/guardian-fixture-systemd-version
cat > /usr/bin/docker <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >> /tmp/guardian-docker-calls
case "$*" in
  '--host unix:///var/run/docker.sock compose version') printf 'Docker Compose version v2.29.7\n';;
  *) exit 2;;
esac
STUB
cat > /usr/bin/systemctl <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >> /tmp/guardian-systemctl-calls
case "$1" in
  --version) cat /tmp/guardian-fixture-systemd-version;;
  is-active) [ -f /tmp/guardian-unit-active ] && exit 0 || exit 3;;
  is-enabled) [ -f /tmp/guardian-timer-enabled ] && exit 0 || exit 1;;
  daemon-reload) exit 0;;
  *) exit 2;;
esac
STUB
chmod 755 /usr/bin/docker /usr/bin/systemctl
install -m 600 /dev/null /run/mail-guardian-provision.lock
exec 8<> /run/mail-guardian-provision.lock
flock -x 8
if "$GUARDIAN_NATIVE_PACKAGE/install.sh" --instance pilot; then
  printf 'Concurrent fresh provisioning was accepted unexpectedly.\n' >&2; exit 1
fi
flock -u 8
exec 8<&-
[[ ! -e /etc/mail-guardian && ! -e /opt/mail-guardian ]]
"$GUARDIAN_NATIVE_PACKAGE/guardian" server init-config --provider custom --host imap.example.invalid --instance pilot --email pilot@example.invalid --server-spam Spam --output /root/pilot.toml
"$GUARDIAN_NATIVE_PACKAGE/install.sh" --instance pilot --config /root/pilot.toml --check
[[ ! -e /etc/mail-guardian && ! -e /opt/mail-guardian ]]
umask 000
"$GUARDIAN_NATIVE_PACKAGE/install.sh" --instance pilot --config /root/pilot.toml
umask 022
[[ "$(stat -c '%U:%G:%a' /opt/mail-guardian)" == root:root:755 ]]
[[ "$(stat -c '%U:%G:%a' /opt/mail-guardian/releases)" == root:root:755 ]]
[[ "$(stat -c '%U:%G:%a' /etc/mail-guardian/pilot/config.toml)" == root:mg-pilot:640 ]]
[[ "$(stat -c '%U:%G:%a' /var/lib/mail-guardian/pilot)" == mg-pilot:mg-pilot:700 ]]
[[ "$(stat -c '%U:%G:%a' /etc/mail-guardian/pilot/credentials)" == root:root:700 ]]
[[ "$(stat -c '%U:%G:%a' /etc/mail-guardian/pilot/migration.lock)" == root:mg-pilot:640 ]]
[[ "$(stat -c '%U:%G:%a' /var/lib/mail-guardian-admin)" == root:root:700 ]]
[[ "$(cat /etc/tmpfiles.d/mail-guardian.conf)" == 'd /var/lib/mail-guardian-admin 0700 root root -' ]]
GUARDIAN_FENCE_INODE="$(stat -c '%d:%i' /etc/mail-guardian/pilot/migration.lock)"
[[ "$(id -Gn mg-pilot)" == mg-pilot ]]
[[ "$(getent passwd mg-pilot | cut -d: -f7)" == /usr/sbin/nologin ]]
[[ "$(readlink /opt/mail-guardian/current)" == /opt/mail-guardian/releases/* ]]
su -s /bin/sh -c '/opt/mail-guardian/current/guardian version >/dev/null' mg-pilot
# Exercise the installed Linux binary and Python helper against the same
# persistent fence before there is any synthetic SQLite state or credential.
# No real Docker socket or mailbox is available in this disposable container.
GUARDIAN_FIXTURE_LOCK=/etc/mail-guardian/pilot/migration.lock
GUARDIAN_FIXTURE_CONFIG=/etc/mail-guardian/pilot/config.toml
GUARDIAN_FIXTURE_DOCKER_BEFORE="$(sha256sum /tmp/guardian-docker-calls)"
check_runtime_blocked() {
  local expected="$1" command
  for command in 'run --dry-run' 'status' 'doctor' 'preflight' 'stack status' 'service-run' 'archive list'; do
    local -a arguments
    read -r -a arguments <<< "$command"
    if sudo -n -u mg-pilot /opt/mail-guardian/current/guardian --config "$GUARDIAN_FIXTURE_CONFIG" "${arguments[@]}" > /tmp/fence-worker-output 2>&1; then
      printf 'Blocked worker command succeeded unexpectedly: %s\n' "$command" >&2; exit 1
    fi
    if ! grep -q "$expected" /tmp/fence-worker-output; then
      printf 'Worker command did not report the fence: %s\n' "$command" >&2
      cat /tmp/fence-worker-output >&2
      exit 1
    fi
  done
  if sudo -n -u mg-pilot sudo -n /usr/local/libexec/mail-guardian-maintenance pilot status > /tmp/fence-helper-output 2>&1; then
    printf 'Blocked helper operation succeeded unexpectedly.\n' >&2; exit 1
  fi
  grep -q 'Mail Guardian maintenance failed' /tmp/fence-helper-output
  [[ ! -e /var/lib/mail-guardian/pilot/guardian.db ]]
  [[ "$(sha256sum /tmp/guardian-docker-calls)" == "$GUARDIAN_FIXTURE_DOCKER_BEFORE" ]]
}
exec 7<> "$GUARDIAN_FIXTURE_LOCK"
flock -x 7
check_runtime_blocked 'migration fence is held or unavailable'
flock -u 7
exec 7<&-
touch /etc/mail-guardian/pilot/migration-pending
check_runtime_blocked 'migration is pending'
rm /etc/mail-guardian/pilot/migration-pending
# Hold the actual Python helper's shared fence; a Go worker must be able to
# take a concurrent shared fence, but an exclusive administrator lock cannot.
python3 -I - <<'PY' &
import importlib.machinery
import importlib.util
import time
loader = importlib.machinery.SourceFileLoader('guardian_test_helper', '/usr/local/libexec/mail-guardian-maintenance')
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
with module.shared_migration_fence('pilot'):
    open('/tmp/fence-python-ready', 'w').close()
    time.sleep(30)
PY
GUARDIAN_FIXTURE_FENCE_PID=$!
trap 'kill "$GUARDIAN_FIXTURE_FENCE_PID" 2>/dev/null || true' EXIT
for attempt in {1..100}; do
  [[ -f /tmp/fence-python-ready ]] && break
  kill -0 "$GUARDIAN_FIXTURE_FENCE_PID" 2>/dev/null || { printf 'Python helper fence exited early.\n' >&2; exit 1; }
  sleep 0.05
done
[[ -f /tmp/fence-python-ready ]]
if flock -n -x "$GUARDIAN_FIXTURE_LOCK" true; then
  printf 'Administrator fence was acquired while the Python helper held it shared.\n' >&2; exit 1
fi
if sudo -n -u mg-pilot /opt/mail-guardian/current/guardian --config "$GUARDIAN_FIXTURE_CONFIG" status --fence-test-invalid > /tmp/fence-worker-output 2>&1; then
  printf 'Invalid status argument unexpectedly succeeded.\n' >&2; exit 1
fi
grep -q 'flag provided but not defined' /tmp/fence-worker-output
[[ ! -e /var/lib/mail-guardian/pilot/guardian.db ]]
kill "$GUARDIAN_FIXTURE_FENCE_PID"
wait "$GUARDIAN_FIXTURE_FENCE_PID" 2>/dev/null || true
trap - EXIT
printf 'disposable-state\n' > /var/lib/mail-guardian/pilot/preserve-me
chown mg-pilot:mg-pilot /var/lib/mail-guardian/pilot/preserve-me
printf 'disposable-credential\n' > /etc/mail-guardian/pilot/credentials/imap-password
chmod 600 /etc/mail-guardian/pilot/credentials/imap-password
GUARDIAN_CONFIG_BEFORE="$(sha256sum /etc/mail-guardian/pilot/config.toml)"
GUARDIAN_HELPER_BEFORE="$(sha256sum /usr/local/libexec/mail-guardian-maintenance)"
"$GUARDIAN_NATIVE_PACKAGE/install.sh" --instance pilot --config /root/pilot.toml
[[ "$(stat -c '%d:%i' /etc/mail-guardian/pilot/migration.lock)" == "$GUARDIAN_FENCE_INODE" ]]
[[ "$(sha256sum /etc/mail-guardian/pilot/config.toml)" == "$GUARDIAN_CONFIG_BEFORE" ]]
[[ "$(cat /var/lib/mail-guardian/pilot/preserve-me)" == disposable-state ]]
[[ "$(cat /etc/mail-guardian/pilot/credentials/imap-password)" == disposable-credential ]]
exec 9< /etc/mail-guardian/pilot/migration.lock
flock -s 9
if "$GUARDIAN_NATIVE_PACKAGE/install.sh" --instance pilot; then
  printf 'Provisioning accepted a shared worker fence unexpectedly.\n' >&2; exit 1
fi
flock -u 9
exec 9<&-
ln -s /nonexistent /etc/mail-guardian/pilot/migration-pending
if "$GUARDIAN_NATIVE_PACKAGE/install.sh" --instance pilot; then
  printf 'A pending migration was accepted unexpectedly.\n' >&2; exit 1
fi
rm /etc/mail-guardian/pilot/migration-pending
chmod 660 /etc/mail-guardian/pilot/migration.lock
if "$GUARDIAN_NATIVE_PACKAGE/install.sh" --instance pilot; then
  printf 'An unsafe migration fence was accepted unexpectedly.\n' >&2; exit 1
fi
chmod 640 /etc/mail-guardian/pilot/migration.lock
"$GUARDIAN_NATIVE_PACKAGE/guardian" server init-config --provider custom --host imap.example.invalid --instance pilot --email changed@example.invalid --server-spam Spam --output /root/changed.toml
if "$GUARDIAN_NATIVE_PACKAGE/install.sh" --instance pilot --config /root/changed.toml; then
  printf 'Configuration overwrite was accepted unexpectedly.\n' >&2; exit 1
fi
[[ "$(sha256sum /usr/local/libexec/mail-guardian-maintenance)" == "$GUARDIAN_HELPER_BEFORE" ]]
[[ "$(sha256sum /etc/mail-guardian/pilot/config.toml)" == "$GUARDIAN_CONFIG_BEFORE" ]]
if "$GUARDIAN_NATIVE_PACKAGE/install.sh" --instance second; then
  printf 'A second instance was accepted unexpectedly.\n' >&2; exit 1
fi
! getent passwd mg-second
touch /tmp/guardian-unit-active
if "$GUARDIAN_NATIVE_PACKAGE/install.sh" --instance pilot; then
  printf 'Active timer/worker was accepted unexpectedly.\n' >&2; exit 1
fi
rm /tmp/guardian-unit-active
touch /tmp/guardian-timer-enabled
if "$GUARDIAN_NATIVE_PACKAGE/install.sh" --instance pilot; then
  printf 'An enabled but inactive timer was accepted unexpectedly.\n' >&2; exit 1
fi
rm /tmp/guardian-timer-enabled
usermod -aG sys mg-pilot
if "$GUARDIAN_NATIVE_PACKAGE/install.sh" --instance pilot; then
  printf 'A worker with supplementary privileges was accepted unexpectedly.\n' >&2; exit 1
fi
gpasswd -d mg-pilot sys >/dev/null
visudo -c
# Exercise the installed sudo implementation's real command-argument policy.
# These list checks do not execute maintenance or access Docker/mailbox state.
su -s /bin/sh -c 'sudo -n -l /usr/local/libexec/mail-guardian-maintenance pilot check-storage >/dev/null' mg-pilot
if su -s /bin/sh -c 'sudo -n -l /usr/local/libexec/mail-guardian-maintenance pilot exec >/dev/null 2>&1' mg-pilot; then
  printf 'An arbitrary maintenance dispatch was authorized unexpectedly.\n' >&2; exit 1
fi
! grep -E '^(enable|start|restart|enable --now) ' /tmp/guardian-systemctl-calls
! grep -E '(^| )(run|up|exec|pull)( |$)' /tmp/guardian-docker-calls
[[ ! -e /etc/systemd/system/timers.target.wants/mail-guardian@pilot.timer ]]
printf 'Disposable Linux install, repeat-install preservation and sudo policy/rejection checks passed.\n'
