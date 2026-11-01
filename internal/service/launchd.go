package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const Label = "pl.o2.mail-guardian"

const runnerFileName = "service-runner.sh"

type Manager struct {
	Executable string
	DataDir    string
	LogFile    string
}

func (m Manager) PlistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", Label+".plist"), nil
}

// Installed reports whether the scanner has a persistent login-agent
// definition. An unloaded plist can still start at the next login, so it must
// count as installed while an account is being reconfigured.
func (m Manager) Installed() bool {
	if runtime.GOOS == "linux" {
		_, err := m.systemdStatus()
		return err == nil
	}
	path, err := m.PlistPath()
	if err != nil {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func (m Manager) Install() error {
	if runtime.GOOS == "linux" {
		return errors.New("Linux scheduling must be enabled by the administrator after server acceptance")
	}
	if err := m.validate(); err != nil {
		return err
	}
	path, err := m.PlistPath()
	if err != nil {
		return err
	}
	runnerPath := filepath.Join(m.DataDir, runnerFileName)
	for _, dir := range []string{filepath.Dir(path), m.DataDir, filepath.Dir(m.LogFile)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("przygotowanie katalogu usługi %q: %w", dir, err)
		}
	}
	if err := os.Chmod(m.DataDir, 0o700); err != nil {
		return fmt.Errorf("prywatne uprawnienia katalogu danych: %w", err)
	}
	log, err := os.OpenFile(m.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("przygotowanie logu usługi: %w", err)
	}
	if err := log.Close(); err != nil {
		return err
	}
	if err := os.Chmod(m.LogFile, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(runnerPath, []byte(serviceRunner()), 0o700); err != nil {
		return fmt.Errorf("instalacja bezpiecznego programu usługi: %w", err)
	}
	content := plist(runnerPath, m.Executable, m.DataDir, m.LogFile)
	if err := validatePlist(content); err != nil {
		return err
	}
	previous, readErr := os.ReadFile(path)
	hadPrevious := readErr == nil
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("kopia poprzedniej usługi: %w", readErr)
	}
	if err := writeAtomic(path, []byte(content), 0o600); err != nil {
		return err
	}

	domain := "gui/" + strconv.Itoa(os.Getuid())
	launchCtx, launchCancel := context.WithTimeout(context.Background(), 20*time.Second)
	_ = exec.CommandContext(launchCtx, "/bin/launchctl", "bootout", domain+"/"+Label).Run()
	launchCancel()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/launchctl", "bootstrap", domain, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		bootstrapErr := fmt.Errorf("launchctl nie uruchomił automatycznego sprawdzania: %w (%s)", err, bytes.TrimSpace(out))
		if rollbackErr := rollbackPlist(path, previous, hadPrevious, domain, Label); rollbackErr != nil {
			return fmt.Errorf("%v; dodatkowo nie udało się przywrócić poprzedniej usługi: %w", bootstrapErr, rollbackErr)
		}
		return fmt.Errorf("%v; poprzednia konfiguracja usługi została przywrócona", bootstrapErr)
	}
	enableCtx, enableCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer enableCancel()
	if out, err := exec.CommandContext(enableCtx, "/bin/launchctl", "enable", domain+"/"+Label).CombinedOutput(); err != nil {
		enableErr := fmt.Errorf("launchctl nie włączył usługi: %w (%s)", err, bytes.TrimSpace(out))
		if rollbackErr := rollbackPlist(path, previous, hadPrevious, domain, Label); rollbackErr != nil {
			return fmt.Errorf("%v; dodatkowo nie udało się przywrócić poprzedniej usługi: %w", enableErr, rollbackErr)
		}
		return fmt.Errorf("%v; poprzednia konfiguracja usługi została przywrócona", enableErr)
	}
	return nil
}

func (m Manager) Uninstall() error {
	if runtime.GOOS == "linux" {
		return errors.New("Linux scheduling must be paused by the administrator through systemd")
	}
	path, err := m.PlistPath()
	if err != nil {
		return err
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	_ = exec.CommandContext(ctx, "/bin/launchctl", "bootout", domain+"/"+Label).Run()
	cancel()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (m Manager) Status() (string, error) {
	if runtime.GOOS == "linux" {
		return m.systemdStatus()
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/launchctl", "print", domain+"/"+Label).CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", errors.New("sprawdzanie usługi przekroczyło 10 sekund; uruchom „guardian napraw”")
		}
		return "", errors.New("automatyczne uruchamianie nie jest aktywne; wybierz „Napraw instalację” albo uruchom „guardian napraw”")
	}
	return string(out), nil
}

func (m Manager) validate() error {
	if !filepath.IsAbs(m.Executable) {
		return errors.New("ścieżka programu guardian musi być bezwzględna")
	}
	info, err := os.Stat(m.Executable)
	if err != nil {
		return fmt.Errorf("nie znaleziono programu guardian %q: %w", m.Executable, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%q nie jest wykonywalnym programem guardian", m.Executable)
	}
	if !filepath.IsAbs(m.DataDir) || !filepath.IsAbs(m.LogFile) {
		return errors.New("katalog danych i log usługi muszą mieć ścieżki bezwzględne")
	}
	return nil
}

func plist(runner, executable, dataDir, logFile string) string {
	escape := func(s string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	// StartInterval drops a firing while macOS sleeps. Calendar triggers
	// coalesce missed firings into one run on wake, so a short awake session
	// can still catch up instead of leaving mail unchecked for another two hours.
	var schedule strings.Builder
	for hour := 0; hour < 24; hour += 2 {
		fmt.Fprintf(&schedule, "    <dict><key>Hour</key><integer>%d</integer><key>Minute</key><integer>0</integer></dict>\n", hour)
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>` + Label + `</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>` + escape(runner) + `</string>
    <string>` + escape(executable) + `</string>
    <string>` + escape(dataDir) + `</string>
    <string>` + escape(logFile) + `</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StartCalendarInterval</key>
  <array>
` + schedule.String() + `  </array>
  <key>ThrottleInterval</key>
  <integer>300</integer>
  <key>ProcessType</key>
  <string>Background</string>
  <key>WorkingDirectory</key>
  <string>` + escape(dataDir) + `</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
</dict>
</plist>
`
}

func serviceRunner() string {
	return `#!/bin/bash

set -u

GUARDIAN_BIN="${1:?brakuje ścieżki guardian}"
DATA_DIR="${2:?brakuje katalogu danych}"
LOG_FILE="${3:?brakuje ścieżki logu}"
NOTICE_FILE="${DATA_DIR}/service-error-notified-at"
MAX_LOG_BYTES=5242880

rotate_log() {
  [[ -f "${LOG_FILE}" ]] || return 0
  local size
  size="$(/usr/bin/stat -f '%z' "${LOG_FILE}" 2>/dev/null || printf '0')"
  [[ "${size}" =~ ^[0-9]+$ ]] || size=0
  if (( size <= MAX_LOG_BYTES )); then
    return 0
  fi
  [[ -f "${LOG_FILE}.1" ]] && /bin/mv -f "${LOG_FILE}.1" "${LOG_FILE}.2"
  /bin/mv -f "${LOG_FILE}" "${LOG_FILE}.1"
  (umask 077; : > "${LOG_FILE}")
  /bin/chmod 600 "${LOG_FILE}"
}

notify_failure() {
  local now last
  now="$(/bin/date +%s)"
  last=0
  if [[ -f "${NOTICE_FILE}" ]]; then
    read -r last < "${NOTICE_FILE}" || last=0
    [[ "${last}" =~ ^[0-9]+$ ]] || last=0
  fi
  if (( now - last < 86400 )); then
    return 0
  fi
  /usr/bin/osascript -e 'display notification "Automatyczne sprawdzanie nie powiodło się. Otwórz aplikację O2 Mail Guardian i wybierz Sprawdź i napraw." with title "O2 Mail Guardian"' >/dev/null 2>&1 || true
  local tmp="${NOTICE_FILE}.tmp.$$"
  (umask 077; printf '%s\n' "${now}" > "${tmp}")
  /bin/mv -f "${tmp}" "${NOTICE_FILE}"
}

rotate_log

# Przekierowanie jest otwierane dopiero po rotacji. Dzięki temu bieżący
# przebieg zawsze zapisuje do guardian.log, a nie do przeniesionego .1.
if ! GUARDIAN_SERVICE_RUNNER=1 "${GUARDIAN_BIN}" service-run >>"${LOG_FILE}" 2>&1; then
	printf '%s\n' "Automatyczne sprawdzanie skrzynki nie powiodło się. Uruchom guardian doctor." >&2
	notify_failure
	exit 1
fi

# Zachowujemy timestamp także po udanym przebiegu. Dzięki temu dwa odrębne
# błędy rozdzielone sukcesem nie zasypią użytkownika powiadomieniami tego
# samego dnia. Po 24 godzinach notify_failure sam nadpisze znacznik.
`
}

func validatePlist(content string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/plutil", "-lint", "-")
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wygenerowana usługa launchd jest nieprawidłowa: %w (%s)", err, bytes.TrimSpace(out))
	}
	return nil
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	ok = true
	return os.Chmod(path, mode)
}

func rollbackPlist(path string, previous []byte, hadPrevious bool, domain, label string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	_ = exec.CommandContext(ctx, "/bin/launchctl", "bootout", domain+"/"+label).Run()
	cancel()
	if !hadPrevious {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := writeAtomic(path, previous, 0o600); err != nil {
		return err
	}
	bootstrapCtx, bootstrapCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer bootstrapCancel()
	out, err := exec.CommandContext(bootstrapCtx, "/bin/launchctl", "bootstrap", domain, path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl bootstrap poprzedniej usługi: %w (%s)", err, bytes.TrimSpace(out))
	}
	return nil
}
