package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	cfg := Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Account.Email != cfg.Account.Email || loaded.Folders.Quarantine != "AI-Kwarantanna" {
		t.Fatalf("unexpected config: %#v", loaded)
	}
}

func TestValidateRejectsUnsafeRetention(t *testing.T) {
	cfg := Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
	cfg.Safety.QuarantineDays = 7
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected retention validation error")
	}
	cfg.Safety.QuarantineDays = 30
	cfg.Safety.ArchiveDays = 29
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected archive retention validation error")
	}
}

func TestValidateRejectsOverlappingFolders(t *testing.T) {
	cfg := Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Folders.ServerSpam = "INBOX"
	if err := cfg.Validate(); err == nil {
		t.Fatal("server spam must not equal inbox")
	}
	cfg.Folders.ServerSpam = "Spam"
	cfg.Folders.Review = "spam"
	if err := cfg.Validate(); err == nil {
		t.Fatal("folder comparison must be case-insensitive")
	}
}

func TestValidateRejectsWeakenedSafetyGates(t *testing.T) {
	valid := Default()
	valid.Account.Email = "test@o2.pl"
	valid.Folders.ServerSpam = "Spam"
	tests := []func(*Config){
		func(c *Config) { c.Safety.ProtectDays = 13 },
		func(c *Config) { c.Safety.ArchiveDays = 34 },
		func(c *Config) { c.Safety.MinLearnSpam = 199 },
		func(c *Config) { c.Safety.RequireAuthForRescue = false },
		func(c *Config) { c.Rspamd.SpamScore = 5.9 },
		func(c *Config) { c.Rspamd.HamScore = -1.9 },
		func(c *Config) { c.Safety.PurgeEnabled = true },
		func(c *Config) { c.Account.TLS = false },
		func(c *Config) { c.Account.Host = "imap.example.org" },
		func(c *Config) { c.Rspamd.ScanURL = "https://scanner.example.org/checkv2" },
		func(c *Config) { c.Rspamd.LearnURL = "http://localhost:11334" },
	}
	for i, mutate := range tests {
		cfg := valid
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatalf("case %d should be rejected", i)
		}
	}
}

func TestParseSince(t *testing.T) {
	tests := map[string]time.Duration{
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"30m": 30 * time.Minute,
	}
	for input, want := range tests {
		got, err := ParseSince(input)
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		if got != want {
			t.Fatalf("%s: got %v, want %v", input, got, want)
		}
	}
}
