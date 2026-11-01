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
			return fmt.Errorf("preparing service directory %q: %w", dir, err)
		}
	}
	if err := os.Chmod(m.DataDir, 0o700); err != nil {
		return fmt.Errorf("prywatne uprawnienia katalogu danych: %w", err)
	}
	log, err := os.OpenFile(m.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("preparing service log: %w", err)
	}
	if err := log.Close(); err != nil {
		return err
	}
	if err := os.Chmod(m.LogFile, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(runnerPath, []byte(serviceRunner()), 0o700); err != nil {
		return fmt.Errorf("installing the secure service runner: %w", err)
	}
	content := plist(runnerPath, m.Executable, m.DataDir, m.LogFile)
	if err := validatePlist(content); err != nil {
		return err
	}
	previous, readErr := os.ReadFile(path)
	hadPrevious := readErr == nil
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("backing up previous service: %w", readErr)
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
		bootstrapErr := fmt.Errorf("launchctl did not start automatic checks: %w (%s)", err, bytes.TrimSpace(out))
		if rollbackErr := rollbackPlist(path, previous, hadPrevious, domain, Label); rollbackErr != nil {
			return fmt.Errorf("%v; also failed to restore the previous service: %w", bootstrapErr, rollbackErr)
		}
		return fmt.Errorf("%v; previous service configuration restored", bootstrapErr)
	}
	enableCtx, enableCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer enableCancel()
	if out, err := exec.CommandContext(enableCtx, "/bin/launchctl", "enable", domain+"/"+Label).CombinedOutput(); err != nil {
		enableErr := fmt.Errorf("launchctl did not enable service: %w (%s)", err, bytes.TrimSpace(out))
		if rollbackErr := rollbackPlist(path, previous, hadPrevious, domain, Label); rollbackErr != nil {
			return fmt.Errorf("%v; also failed to restore the previous service: %w", enableErr, rollbackErr)
		}
		return fmt.Errorf("%v; previous service configuration restored", enableErr)
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
			return "", errors.New("service check exceeded 10 seconds; run guardian repair")
		}
		return "", errors.New("autostart is inactive; choose Repair installation or run guardian repair")
	}
	return string(out), nil
}

func (m Manager) validate() error {
	if !filepath.IsAbs(m.Executable) {
		return errors.New("guardian executable path must be absolute")
	}
	info, err := os.Stat(m.Executable)
	if err != nil {
		return fmt.Errorf("guardian executable %q not found: %w", m.Executable, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%q is not an executable guardian program", m.Executable)
	}
	if !filepath.IsAbs(m.DataDir) || !filepath.IsAbs(m.LogFile) {
		return errors.New("data directory and service log must use absolute paths")
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
	return "#!/bin/bash\n\nset -u\n\nGUARDIAN_BIN=\"${1:?missing guardian path}\"\nDATA_DIR=\"${2:?missing data directory}\"\nLOG_FILE=\"${3:?missing log path}\"\nNOTICE_FILE=\"${DATA_DIR}/service-error-notified-at\"\nMAX_LOG_BYTES=5242880\n\nrotate_log() {\n  [[ -f \"${LOG_FILE}\" ]] || return 0\n  local size\n  size=\"$(/usr/bin/stat -f '%z' \"${LOG_FILE}\" 2>/dev/null || printf '0')\"\n  [[ \"${size}\" =~ ^[0-9]+$ ]] || size=0\n  if (( size <= MAX_LOG_BYTES )); then\n    return 0\n  fi\n  [[ -f \"${LOG_FILE}.1\" ]] && /bin/mv -f \"${LOG_FILE}.1\" \"${LOG_FILE}.2\"\n  /bin/mv -f \"${LOG_FILE}\" \"${LOG_FILE}.1\"\n  (umask 077; : > \"${LOG_FILE}\")\n  /bin/chmod 600 \"${LOG_FILE}\"\n}\n\nnotify_failure() {\n  local now last\n  now=\"$(/bin/date +%s)\"\n  last=0\n  if [[ -f \"${NOTICE_FILE}\" ]]; then\n    read -r last < \"${NOTICE_FILE}\" || last=0\n    [[ \"${last}\" =~ ^[0-9]+$ ]] || last=0\n  fi\n  if (( now - last < 86400 )); then\n    return 0\n  fi\n  /usr/bin/osascript -e 'display notification \"Automatic check failed. Open Mail Guardian and choose Check and repair.\" with title \"Mail Guardian\"' >/dev/null 2>&1 || true\n  local tmp=\"${NOTICE_FILE}.tmp.$$\"\n  (umask 077; printf '%s\\n' \"${now}\" > \"${tmp}\")\n  /bin/mv -f \"${tmp}\" \"${NOTICE_FILE}\"\n}\n\nrotate_log\n\n# Open redirection after rotation so the current run writes guardian.log.\nif ! GUARDIAN_SERVICE_RUNNER=1 \"${GUARDIAN_BIN}\" service-run >>\"${LOG_FILE}\" 2>&1; then\n\tprintf '%s\\n' \"Automatic mailbox check failed. Run guardian doctor.\" >&2\n\tnotify_failure\n\texit 1\nfi\n\n# Retain the timestamp after success to rate-limit separate failures to one notice per day.\n"
}

func validatePlist(content string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/plutil", "-lint", "-")
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("generated launchd service is invalid: %w (%s)", err, bytes.TrimSpace(out))
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
		return fmt.Errorf("launchctl bootstrap of previous service: %w (%s)", err, bytes.TrimSpace(out))
	}
	return nil
}
