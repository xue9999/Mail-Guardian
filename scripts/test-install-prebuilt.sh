#!/bin/bash
# Exercise the real installer and real signed binaries; isolate external effects.
set -Eeuo pipefail
PACKAGE_ROOT="${1:?Provide extracted package}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
TEST_HOME="$(mktemp -d /tmp/o2-guardian-installer-test.XXXXXX)"
trap '/bin/rm -rf "$TEST_HOME"' EXIT
cat > "$TEST_HOME/driver.sh" <<'DRIVER'
#!/bin/bash
set -eu
printf '%s\n' "$*" >> "$HOME/external-calls"
action="$1"; shift
case "$action" in
  dependencies)
    if [[ "${TEST_HOLD:-0}" == 1 ]]; then
      touch "$HOME/held"
      while [[ ! -f "$HOME/release" ]]; do sleep 0.1; done
    fi ;;
  backend)
    shift
    case "$1" in
      --config) exit 0 ;;
      app-service) mkdir -p "$HOME/Library/LaunchAgents"; printf 'ui\n' > "$HOME/Library/LaunchAgents/pl.o2.mail-guardian-ui.plist" ;;
      doctor) [[ "${TEST_FAIL:-}" != doctor ]] ;;
      service) [[ "${TEST_FAIL:-}" != service ]] ;;
      *) exit 92 ;;
    esac ;;
  launchctl) [[ "${TEST_FAIL:-}" != service || "$1" != bootstrap ]] ;;
  start-stack|compose|open) : ;;
  *) exit 93 ;;
esac
DRIVER
# Any unexpected source-build tools are fatal. The process must use prebuilt files.
mkdir "$TEST_HOME/tools"
for tool in go swift; do
  printf '#!/bin/bash\nprintf "unexpected compiler\\n" >> "$HOME/compiler-called"\nexit 94\n' > "$TEST_HOME/tools/$tool"
  chmod +x "$TEST_HOME/tools/$tool"
done
common=(HOME="$TEST_HOME" XDG_CONFIG_HOME="$TEST_HOME/config" PATH="$TEST_HOME/tools:$PATH"
  GUARDIAN_INSTALL_INTEGRATION_TEST=1 GUARDIAN_INSTALL_TEST_DRIVER="$TEST_HOME/driver.sh"
  GUARDIAN_INSTALL_CONFIRMED=1 GUARDIAN_SKIP_PAUSE=1 GUARDIAN_INSTALL_RESULT_FILE="$TEST_HOME/result")
run_install() {
  local code=0
  env "${common[@]}" "$@" /bin/bash -x "$PACKAGE_ROOT/.payload/scripts/install-core.sh" > "$TEST_HOME/output" 2>&1 || code=$?
  if grep -Eq '^\++ ((/usr/bin/)?swift (build|test)|go (build|test|vet)|brew install go)' "$TEST_HOME/output"; then
    printf 'Prebuilt installation invoked a compiler.\n' >&2; exit 1
  fi
  return "$code"
}
run_install
[[ "$(cat "$TEST_HOME/result")" == success ]]
[[ -x "$TEST_HOME/.local/bin/o2-mail-guardian/guardian" ]]
[[ -x "$TEST_HOME/Applications/O2 Mail Guardian.app/Contents/MacOS/O2MailGuardianApp" ]]
# Model a configured installation with independent user data and enabled service.
mkdir -p "$TEST_HOME/Library/Application Support/O2 Mail Guardian/archive"
printf 'account-marker\n' > "$TEST_HOME/Library/Application Support/O2 Mail Guardian/config.toml"
printf 'database-marker\n' > "$TEST_HOME/Library/Application Support/O2 Mail Guardian/state.db"
printf 'archive-marker\n' > "$TEST_HOME/Library/Application Support/O2 Mail Guardian/archive/copy"
printf 'service\n' > "$TEST_HOME/Library/LaunchAgents/pl.o2.mail-guardian.plist"
run_install
run_install
[[ "$(cat "$TEST_HOME/result")" == success ]]
for kind in doctor service; do
  run_install TEST_FAIL="$kind"
  [[ "$(cat "$TEST_HOME/result")" == attention ]]
done
# Every actual staging checkpoint restores the old complete set.
for point in after-deploy after-backend after-app after-ui-plist; do
  if run_install GUARDIAN_FAIL_AT="$point"; then printf 'Failure was not injected: %s\n' "$point" >&2; exit 1; fi
  [[ "$(cat "$TEST_HOME/result")" == failed ]]
  cmp "$PACKAGE_ROOT/.payload/prebuilt/guardian" "$TEST_HOME/.local/bin/o2-mail-guardian/guardian"
  cmp "$PACKAGE_ROOT/.payload/prebuilt/O2 Mail Guardian.app/Contents/MacOS/O2MailGuardianApp" "$TEST_HOME/Applications/O2 Mail Guardian.app/Contents/MacOS/O2MailGuardianApp"
  [[ -f "$TEST_HOME/config/o2-mail-guardian/deploy/compose.yaml" ]]
done
# Explicitly preserve a user's disabled schedules/autostart on reinstall.
/bin/rm "$TEST_HOME/Library/LaunchAgents/pl.o2.mail-guardian.plist" "$TEST_HOME/Library/LaunchAgents/pl.o2.mail-guardian-ui.plist"
run_install
[[ ! -e "$TEST_HOME/Library/LaunchAgents/pl.o2.mail-guardian.plist" && ! -e "$TEST_HOME/Library/LaunchAgents/pl.o2.mail-guardian-ui.plist" ]]
[[ "$(cat "$TEST_HOME/Library/Application Support/O2 Mail Guardian/config.toml")" == account-marker ]]
[[ "$(cat "$TEST_HOME/Library/Application Support/O2 Mail Guardian/state.db")" == database-marker ]]
[[ "$(cat "$TEST_HOME/Library/Application Support/O2 Mail Guardian/archive/copy")" == archive-marker ]]
[[ ! -e "$TEST_HOME/compiler-called" ]]
# Run through wrapper: a direct core invocation must respect its lock.
env "${common[@]}" TEST_HOLD=1 /bin/bash "$PACKAGE_ROOT/Install.command" > "$TEST_HOME/wrapper-output" 2>&1 &
wrapper_pid=$!
for ((i=0; i<200; i++)); do [[ ! -f "$TEST_HOME/held" ]] || break; sleep 0.1; done
[[ -f "$TEST_HOME/held" ]]
log="$TEST_HOME/Library/Logs/O2 Mail Guardian/instalacja.log"
log_sum="$(shasum "$log")"
if run_install; then exit 1; fi
grep -q 'Another installation' "$TEST_HOME/output"
if env "${common[@]}" /bin/bash "$PACKAGE_ROOT/Install.command" > "$TEST_HOME/second-wrapper" 2>&1; then exit 1; fi
[[ "$(shasum "$log")" == "$log_sum" ]]
touch "$TEST_HOME/release"
wait "$wrapper_pid"
[[ ! -d "$TEST_HOME/Library/Logs/O2 Mail Guardian/install.lock" ]]
# SIGTERM releases an owned core lock after rollback/cleanup.
/bin/rm "$TEST_HOME/release" "$TEST_HOME/held"
env "${common[@]}" TEST_HOLD=1 /bin/bash "$PACKAGE_ROOT/.payload/scripts/install-core.sh" > "$TEST_HOME/signal-output" 2>&1 &
core_pid=$!
for ((i=0; i<200; i++)); do [[ ! -f "$TEST_HOME/held" ]] || break; sleep 0.1; done
[[ -f "$TEST_HOME/held" ]]
kill -TERM "$core_pid"
touch "$TEST_HOME/release"
if wait "$core_pid"; then exit 1; fi
[[ ! -d "$TEST_HOME/Library/Logs/O2 Mail Guardian/install.lock" ]]
printf 'Prebuilt installation, update, failures, lock and signal: OK\n'
