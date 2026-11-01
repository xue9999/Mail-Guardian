package service

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUIPlistIsBackgroundOnlyAndEscapesPath(t *testing.T) {
	value := uiPlist("/Users/name & family/Applications/O2 Mail Guardian.app/Contents/MacOS/O2MailGuardianApp")
	for _, expected := range []string{UILabel, "name &amp; family", "--background", "<key>RunAtLoad</key><true/>"} {
		if !strings.Contains(value, expected) {
			t.Fatalf("UI plist missing %q: %s", expected, value)
		}
	}
	if strings.Contains(value, "purge") || strings.Contains(value, "service-run") {
		t.Fatal("UI login item must not run mailbox or purge commands")
	}
	if runtime.GOOS == "darwin" {
		if err := validatePlist(value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUIInstallOnlyPersistsLoginItem(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("UI login items apply to macOS")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	app := filepath.Join(home, "Applications", "O2 Mail Guardian.app")
	executable := filepath.Join(app, "Contents", "MacOS", "O2MailGuardianApp")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	manager := UIManager{AppPath: app}
	if err := manager.Install(); err != nil {
		t.Fatal(err)
	}
	if !manager.Status() {
		t.Fatal("persisted login item was not reported as enabled")
	}
	path, err := manager.PlistPath()
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "--background") {
		t.Fatal("persisted login item does not start the UI in background mode")
	}
}
