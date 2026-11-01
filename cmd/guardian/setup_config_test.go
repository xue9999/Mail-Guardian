package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/store"
)

func TestSetupResolutionKeepsLegacyProtocolAndCustomIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	a := &application{configPath: path}
	legacy, err := readSetupRequest(strings.NewReader(`{"email":"me@o2.pl","password":"fixture"}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg, exists, err := a.resolveSetupConfiguration(legacy)
	if err != nil || exists || cfg.Account.Host != "poczta.o2.pl" || cfg.Account.Username != legacy.Email {
		t.Fatalf("legacy request: %v", err)
	}
	custom := setupRequest{Email: "me@example.org", Provider: "custom", Host: "imap.example.org", Port: 993, Username: "login-123"}
	cfg, _, err = a.resolveSetupConfiguration(custom)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LegacyCompatible() || cfg.Folders.Review != "Guardian-Review" {
		t.Fatal("custom setup inherited legacy installation")
	}
	cfg.Folders.ServerSpam = "Junk"
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := a.resolveSetupConfiguration(setupRequest{Email: custom.Email})
	if err != nil || !exists || loaded.Account.Username != "login-123" || loaded.Account.Host != custom.Host {
		t.Fatalf("omitted settings redirected custom account: %v", err)
	}
	custom.Host = "another.example.org"
	if _, _, err := a.resolveSetupConfiguration(custom); !errors.Is(err, store.ErrMailboxIdentity) {
		t.Fatalf("setup redirected existing state: %v", err)
	}
	if err := os.WriteFile(path, []byte("broken = ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.resolveSetupConfiguration(legacy); err == nil {
		t.Fatal("unreadable config overwritten")
	}
}

func TestCustomSetupRequiresExplicitEndpoint(t *testing.T) {
	a := &application{configPath: filepath.Join(t.TempDir(), "config.toml")}
	if _, _, err := a.resolveSetupConfiguration(setupRequest{Email: "me@example.org", Provider: "custom"}); err == nil {
		t.Fatal("custom setup inherited o2 endpoint")
	}
}
