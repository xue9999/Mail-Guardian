package config

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestV1MigrationPreservesInstallationAndDoesNotRewriteSource(t *testing.T) {
	legacy := Default()
	legacy.Account.Email = "Legacy@o2.pl"
	legacy.Folders.ServerSpam = "Poczta/SPAM"
	legacy.Folders.TrainHam = "Moje-Wazne"
	legacy.Runtime.DataDir = t.TempDir()
	var raw bytes.Buffer
	if err := toml.NewEncoder(&raw).Encode(legacy); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, raw.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != 2 || !first.LegacyCompatible() || first.InstanceID != second.InstanceID || first.Account.ID != second.Account.ID {
		t.Fatalf("unstable migration: %+v", first.Account)
	}
	if !reflect.DeepEqual(first.Runtime, legacy.Runtime) || first.Folders != legacy.Folders || first.Safety != legacy.Safety || first.Account.PasswordKeychainService != legacy.Account.PasswordKeychainService {
		t.Fatal("migration changed installed paths, secrets, folders or safety")
	}
	unchanged, _ := os.ReadFile(path)
	if !bytes.Equal(unchanged, raw.Bytes()) {
		t.Fatal("Load rewrote v1 config")
	}
	if err := Save(path, first); err != nil {
		t.Fatal(err)
	}
	persisted, err := Load(path)
	if err != nil || !reflect.DeepEqual(first, persisted) {
		t.Fatalf("v2 round trip: %v", err)
	}
}

func TestV2SupportsIndependentLoginAndRejectsUnknownSchemaOrAuthentication(t *testing.T) {
	cfg, err := NewInstance()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Account.Email, cfg.Folders.ServerSpam = "me@example.org", "Junk"
	cfg.Account.Provider, cfg.Account.Host, cfg.Account.Username = "custom", "imap.example.org", "mailbox-123"
	resolved, err := cfg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Account.LoginUsername() != "mailbox-123" || resolved.Account.Email != "me@example.org" {
		t.Fatal("login and address were conflated")
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Version = 3 },
		func(c *Config) { c.Account.AuthMethod = "oauth2" },
		func(c *Config) { c.Account.TLS = false },
		func(c *Config) { c.InstanceID = "../other" },
		func(c *Config) { c.Account.Port = 65536 },
	} {
		invalid := resolved
		mutate(&invalid)
		if _, err := invalid.Resolve(); err == nil {
			t.Fatal("unsafe config was accepted")
		}
	}
	other, err := NewInstance()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InstanceID == other.InstanceID || cfg.Account.ID == other.Account.ID {
		t.Fatal("new instances share identity")
	}
}

func TestV1CannotSmuggleV2EndpointOrLogin(t *testing.T) {
	cfg := Default()
	cfg.Account.Email, cfg.Folders.ServerSpam = "me@o2.pl", "Spam"
	cfg.Account.Host = "imap.example.org"
	if _, err := cfg.Resolve(); err == nil {
		t.Fatal("v1 endpoint restriction bypassed")
	}
	cfg.Account.Host, cfg.Account.Username = "poczta.o2.pl", "another-login"
	if _, err := cfg.Resolve(); err == nil {
		t.Fatal("v2 login silently migrated as legacy")
	}
}

func TestFreshProfileRequiresEndpointAndKeepsLegacyPaths(t *testing.T) {
	cfg, err := NewInstance()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Account.Email, cfg.Folders.ServerSpam = "fixture@example.org", "Junk"
	if cfg.Account.Provider != "custom" || cfg.Account.Host != "" || cfg.Folders.Review != "Guardian-Review" {
		t.Fatal("fresh installation inherited a provider or legacy folder names")
	}
	if _, err := cfg.Resolve(); err == nil {
		t.Fatal("missing explicit endpoint accepted")
	}
	cfg.Account.Host = "imap.example.org"
	resolved, err := cfg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if resolved.LegacyCompatible() || resolved.Safety.PurgeEnabled || resolved.Account.LoginUsername() != cfg.Account.Email {
		t.Fatal("fresh account inherited legacy authorization or unsafe defaults")
	}
	if cfg.Runtime.DataDir != Default().Runtime.DataDir || filepath.Base(DefaultDataDir()) != "O2 Mail Guardian" {
		t.Fatal("product rename changed persisted storage paths")
	}
}
