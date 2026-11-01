package service

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPlistEscapesPathsAndUsesSafeInterval(t *testing.T) {
	value := plist(
		"/tmp/data path/service&runner.sh",
		"/tmp/a&b/guardian",
		"/tmp/data path",
		"/tmp/log<guardian>",
	)
	for _, expected := range []string{
		"<string>/bin/bash</string>",
		"/tmp/data path/service&amp;runner.sh",
		"/tmp/a&amp;b/guardian",
		"/tmp/data path",
		"/tmp/log&lt;guardian&gt;",
		"<key>StartCalendarInterval</key>",
		"<integer>300</integer>",
	} {
		if !strings.Contains(value, expected) {
			t.Fatalf("plist missing %q:\n%s", expected, value)
		}
	}
	if strings.Contains(value, "StandardOutPath") || strings.Contains(value, "StandardErrorPath") {
		t.Fatal("launchd must not pre-open the log before the runner rotates it")
	}
}

func TestScannerCalendarCatchesUpAfterSleepEveryTwoHours(t *testing.T) {
	value := plist("/tmp/runner", "/tmp/guardian", "/tmp/data", "/tmp/log")
	if strings.Contains(value, "<key>StartInterval</key>") {
		t.Fatal("StartInterval misses firings during sleep; use calendar wake catch-up")
	}
	var document struct {
		Dict struct {
			Entries []struct {
				Value string `xml:",chardata"`
				Dicts []struct {
					Keys     []string `xml:"key"`
					Integers []int    `xml:"integer"`
				} `xml:"dict"`
			} `xml:",any"`
		} `xml:"dict"`
	}
	if err := xml.Unmarshal([]byte(value), &document); err != nil {
		t.Fatal(err)
	}
	for i, entry := range document.Dict.Entries {
		if strings.TrimSpace(entry.Value) != "StartCalendarInterval" {
			continue
		}
		if i+1 >= len(document.Dict.Entries) {
			t.Fatal("calendar schedule has no value")
		}
		schedule := document.Dict.Entries[i+1].Dicts
		if len(schedule) != 12 {
			t.Fatalf("calendar has %d firings, want 12", len(schedule))
		}
		for index, trigger := range schedule {
			if len(trigger.Keys) != 2 || trigger.Keys[0] != "Hour" || trigger.Keys[1] != "Minute" ||
				len(trigger.Integers) != 2 || trigger.Integers[0] != index*2 || trigger.Integers[1] != 0 {
				t.Fatalf("calendar trigger %d = %#v, want hour %d, minute 0", index, trigger, index*2)
			}
		}
		return
	}
	t.Fatal("calendar schedule missing")
}

func TestGeneratedPlistPassesMacOSValidation(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("plutil is a macOS system tool")
	}
	value := plist(
		"/tmp/guardian data/service-runner.sh",
		"/tmp/guardian bin/guardian",
		"/tmp/guardian data",
		"/tmp/guardian data/guardian.log",
	)
	if err := validatePlist(value); err != nil {
		t.Fatal(err)
	}
}

func TestInstalledDetectsPersistentScannerDefinition(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("persistent LaunchAgent definitions apply to macOS")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	manager := Manager{}
	if manager.Installed() {
		t.Fatal("scanner without a plist was reported as installed")
	}
	path, err := manager.PlistPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !manager.Installed() {
		t.Fatal("persistent scanner plist was not detected")
	}
}

func TestServiceRunnerRecoversNotifiesAndRotatesBoundedly(t *testing.T) {
	value := serviceRunner()
	for _, expected := range []string{
		`GUARDIAN_SERVICE_RUNNER=1 "${GUARDIAN_BIN}" service-run`,
		`>>"${LOG_FILE}" 2>&1`,
		"MAX_LOG_BYTES=5242880",
		`"${LOG_FILE}.1"`,
		`"${LOG_FILE}.2"`,
		"now - last < 86400",
		"display notification",
		"Retain the timestamp",
	} {
		if !strings.Contains(value, expected) {
			t.Fatalf("runner missing %q:\n%s", expected, value)
		}
	}
	if strings.Contains(value, "find-generic-password") {
		t.Fatal("service runner must not read or print secrets")
	}
	if !strings.Contains(value, "Open Mail Guardian and choose Check and repair") {
		t.Fatal("service notification must point a nontechnical user to the GUI")
	}
	if strings.Contains(value, "Open Guardian.command") {
		t.Fatal("service notification must not require the emergency command script")
	}
}

func TestServiceRunnerRotatesCurrentLogAndKeepsPrevious(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("runner uses the macOS stat syntax")
	}
	dir := t.TempDir()
	runner := filepath.Join(dir, "runner.sh")
	guardian := filepath.Join(dir, "guardian")
	logFile := filepath.Join(dir, "guardian.log")
	if err := os.WriteFile(runner, []byte(serviceRunner()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(guardian, []byte("#!/bin/bash\nprintf 'new-run\\n'\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	large := make([]byte, 5*1024*1024+1)
	if err := os.WriteFile(logFile, large, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/bin/bash", runner, guardian, dir, logFile).CombinedOutput(); err != nil {
		t.Fatalf("runner: %v (%s)", err, out)
	}
	rotated, err := os.Stat(logFile + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Size() != int64(len(large)) {
		t.Fatalf("rotated size = %d, want %d", rotated.Size(), len(large))
	}
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new-run\n" {
		t.Fatalf("new run was not written to current log: %q", content)
	}
}
