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
	"strconv"
	"time"
)

const UILabel = "pl.o2.mail-guardian-ui"

type UIManager struct {
	AppPath string
}

func DefaultUIAppPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Applications", "O2 Mail Guardian.app"), nil
}

func (m UIManager) executable() string {
	return filepath.Join(m.AppPath, "Contents", "MacOS", "O2MailGuardianApp")
}

func (m UIManager) PlistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", UILabel+".plist"), nil
}

func (m UIManager) Install() error {
	if !filepath.IsAbs(m.AppPath) {
		return errors.New("application path must be absolute")
	}
	info, err := os.Stat(m.executable())
	if err != nil {
		return fmt.Errorf("Mail Guardian application is incomplete: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("Mail Guardian application contains no executable")
	}
	path, err := m.PlistPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	content := uiPlist(m.executable())
	if err := validatePlist(content); err != nil {
		return err
	}
	if err := writeAtomic(path, []byte(content), 0o600); err != nil {
		return err
	}
	return nil
}

func (m UIManager) Uninstall() error {
	path, err := m.PlistPath()
	if err != nil {
		return err
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	_ = exec.CommandContext(ctx, "/bin/launchctl", "bootout", domain+"/"+UILabel).Run()
	cancel()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (m UIManager) Status() bool {
	path, err := m.PlistPath()
	if err != nil {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func uiPlist(executable string) string {
	var escaped bytes.Buffer
	_ = xml.EscapeText(&escaped, []byte(executable))
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + UILabel + `</string>
  <key>ProgramArguments</key>
  <array>
    <string>` + escaped.String() + `</string>
    <string>--background</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
`
}
