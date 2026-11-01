package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/o2-mail-guardian/guardian/internal/provider"
)

const (
	AppName = "O2 Mail Guardian"
)

type Config struct {
	Version    int    `toml:"version"`
	InstanceID string `toml:"instance_id"`

	Account Account `toml:"account"`
	Folders Folders `toml:"folders"`
	Rspamd  Rspamd  `toml:"rspamd"`
	Safety  Safety  `toml:"safety"`
	Runtime Runtime `toml:"runtime"`
}

type Account struct {
	ID                      string `toml:"id"`
	Provider                string `toml:"provider"`
	Username                string `toml:"username"`
	AuthMethod              string `toml:"auth_method"`
	Email                   string `toml:"email"`
	Host                    string `toml:"host"`
	Port                    int    `toml:"port"`
	TLS                     bool   `toml:"tls"`
	PasswordKeychainService string `toml:"password_keychain_service"`
}

type Folders struct {
	Inbox      string `toml:"inbox"`
	ServerSpam string `toml:"server_spam"`
	Quarantine string `toml:"quarantine"`
	Review     string `toml:"review"`
	TrainSpam  string `toml:"train_spam"`
	TrainHam   string `toml:"train_ham"`
}

type Rspamd struct {
	ScanURL                 string  `toml:"scan_url"`
	LearnURL                string  `toml:"learn_url"`
	PasswordKeychainService string  `toml:"password_keychain_service"`
	SpamScore               float64 `toml:"spam_score"`
	HamScore                float64 `toml:"ham_score"`
	TimeoutSeconds          int     `toml:"timeout_seconds"`
}

type Safety struct {
	Mode                 string `toml:"mode"`
	PurgeEnabled         bool   `toml:"purge_enabled"`
	QuarantineDays       int    `toml:"quarantine_days"`
	ArchiveDays          int    `toml:"archive_days"`
	MaxMessageMiB        int64  `toml:"max_message_mib"`
	ProtectDays          int    `toml:"protect_days"`
	MinLearnSpam         int    `toml:"min_learn_spam"`
	MinLearnHam          int    `toml:"min_learn_ham"`
	RequireAuthForRescue bool   `toml:"require_auth_for_rescue"`
	ScanLookbackDays     int    `toml:"scan_lookback_days"`
	MaxMessagesPerFolder int    `toml:"max_messages_per_folder"`
}

type Runtime struct {
	DataDir                string `toml:"data_dir"`
	Database               string `toml:"database"`
	ArchiveDir             string `toml:"archive_dir"`
	LogFile                string `toml:"log_file"`
	ComposeFile            string `toml:"compose_file"`
	ArchiveKeychainService string `toml:"archive_keychain_service"`
}

func Default() Config {
	base := DefaultDataDir()
	return Config{
		Version: 1,
		Account: Account{
			Host:                    "poczta.o2.pl",
			Port:                    993,
			TLS:                     true,
			PasswordKeychainService: "pl.o2.mail-guardian.imap",
		},
		Folders: Folders{
			Inbox:      "INBOX",
			ServerSpam: "",
			Quarantine: "AI-Kwarantanna",
			Review:     "AI-Do-sprawdzenia",
			TrainSpam:  "AI-Naucz-spam",
			TrainHam:   "AI-Naucz-wazne",
		},
		Rspamd: Rspamd{
			ScanURL:                 "http://127.0.0.1:11333/checkv2",
			LearnURL:                "http://127.0.0.1:11334",
			PasswordKeychainService: "pl.o2.mail-guardian.rspamd",
			SpamScore:               12,
			HamScore:                -2,
			TimeoutSeconds:          45,
		},
		Safety: Safety{
			Mode:                 "protect",
			PurgeEnabled:         false,
			QuarantineDays:       30,
			ArchiveDays:          35,
			MaxMessageMiB:        25,
			ProtectDays:          14,
			MinLearnSpam:         200,
			MinLearnHam:          200,
			RequireAuthForRescue: true,
			ScanLookbackDays:     14,
			MaxMessagesPerFolder: 500,
		},
		Runtime: Runtime{
			DataDir:                base,
			Database:               filepath.Join(base, "guardian.db"),
			ArchiveDir:             filepath.Join(base, "archive"),
			LogFile:                filepath.Join(base, "guardian.log"),
			ComposeFile:            filepath.Join(DefaultRuntimeDir(), "deploy", "compose.yaml"),
			ArchiveKeychainService: "pl.o2.mail-guardian.archive",
		},
	}
}

func DefaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".guardian")
	}
	return filepath.Join(home, "Library", "Application Support", AppName)
}

func DefaultRuntimeDir() string {
	if base := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); base != "" && filepath.IsAbs(base) {
		return filepath.Join(base, "o2-mail-guardian")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".guardian-runtime")
	}
	return filepath.Join(home, ".config", "o2-mail-guardian")
}

func DefaultPath() string {
	return filepath.Join(DefaultDataDir(), "config.toml")
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		path = DefaultPath()
	}
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return Config{}, fmt.Errorf("nie mogę odczytać konfiguracji %q: %w", path, err)
	}
	return cfg.Resolve()
}

func (c Config) Validate() error {
	var problems []string
	if c.Version != 1 && c.Version != 2 {
		problems = append(problems, "nieobsługiwana wersja konfiguracji")
	}
	if c.Version == 2 {
		if !validID(c.InstanceID) || !validID(c.Account.ID) {
			problems = append(problems, "brakuje prawidłowej tożsamości instancji lub konta")
		}
		if _, err := provider.Resolve(c.Account.Provider, c.Account.Host, c.Account.Port, c.Account.Username, c.Account.Email, c.Account.AuthMethod); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if !strings.Contains(c.Account.Email, "@") {
		problems = append(problems, "adres konta e-mail jest nieprawidłowy")
	}
	if c.Account.Host == "" || c.Account.Port < 1 || c.Account.Port > 65535 {
		problems = append(problems, "brakuje adresu lub portu IMAP")
	}
	if !c.Account.TLS {
		problems = append(problems, "połączenie IMAP musi używać TLS")
	}
	if c.Version == 1 && (!strings.EqualFold(c.Account.Host, "poczta.o2.pl") || c.Account.Port != 993) {
		problems = append(problems, "Guardian łączy się wyłącznie z poczta.o2.pl na szyfrowanym porcie 993")
	}
	if c.Folders.Inbox == "" || c.Folders.ServerSpam == "" {
		problems = append(problems, "nie wybrano folderu Odebrane lub SPAM")
	}
	folderValues := []string{
		c.Folders.Inbox, c.Folders.ServerSpam, c.Folders.Quarantine,
		c.Folders.Review, c.Folders.TrainSpam, c.Folders.TrainHam,
	}
	seen := map[string]bool{}
	for _, folder := range folderValues {
		if strings.TrimSpace(folder) == "" {
			problems = append(problems, "nazwa folderu robota nie może być pusta")
			continue
		}
		key := strings.ToLower(folder)
		if seen[key] {
			problems = append(problems, "folder Odebrane, SPAM i foldery robota muszą mieć różne nazwy")
		}
		seen[key] = true
	}
	if c.Safety.Mode != "protect" && c.Safety.Mode != "active" {
		problems = append(problems, "tryb musi mieć wartość protect albo active")
	}
	if c.Safety.QuarantineDays < 30 {
		problems = append(problems, "kwarantanna nie może być krótsza niż 30 dni")
	}
	if c.Safety.ArchiveDays < c.Safety.QuarantineDays {
		problems = append(problems, "lokalna kopia musi być przechowywana co najmniej tak długo jak kwarantanna")
	}
	if c.Safety.ArchiveDays < 35 {
		problems = append(problems, "lokalna kopia nie może być przechowywana krócej niż 35 dni")
	}
	if c.Safety.ProtectDays < 14 {
		problems = append(problems, "tryb ochronny nie może być krótszy niż 14 dni")
	}
	if c.Safety.MinLearnSpam < 200 || c.Safety.MinLearnHam < 200 {
		problems = append(problems, "trwałe usuwanie wymaga progów uczenia co najmniej 200 spam i 200 ważnych")
	}
	if !c.Safety.RequireAuthForRescue {
		problems = append(problems, "automatyczne ratowanie wymaga uwierzytelnienia nadawcy")
	}
	if c.Safety.PurgeEnabled && c.Safety.Mode != "active" {
		problems = append(problems, "trwałe usuwanie wymaga trybu aktywnego")
	}
	if c.Safety.MaxMessageMiB < 1 || c.Safety.MaxMessageMiB > 100 {
		problems = append(problems, "limit rozmiaru musi mieścić się między 1 a 100 MiB")
	}
	if c.Safety.ScanLookbackDays < 1 || c.Safety.ScanLookbackDays > 90 {
		problems = append(problems, "okres skanowania musi mieścić się między 1 a 90 dni")
	}
	if c.Safety.MaxMessagesPerFolder < 1 || c.Safety.MaxMessagesPerFolder > 5000 {
		problems = append(problems, "limit wiadomości na przebieg musi mieścić się między 1 a 5000")
	}
	if c.Rspamd.SpamScore <= c.Rspamd.HamScore {
		problems = append(problems, "próg spamu musi być wyższy od progu wiadomości prawidłowej")
	}
	if c.Rspamd.SpamScore < 6 {
		problems = append(problems, "próg spamu nie może być niższy niż 6; próg poniżej 12 wymaga odrębnej oceny jakości")
	}
	if c.Rspamd.HamScore > -2 {
		problems = append(problems, "próg automatycznego ratowania nie może być wyższy niż -2")
	}
	if !localRspamdURL(c.Rspamd.ScanURL, "11333", "/checkv2") {
		problems = append(problems, "adres skanowania Rspamd musi wskazywać lokalny http://127.0.0.1:11333/checkv2")
	}
	if !localRspamdURL(c.Rspamd.LearnURL, "11334", "") {
		problems = append(problems, "adres uczenia Rspamd musi wskazywać lokalny http://127.0.0.1:11334")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func localRspamdURL(raw, port, path string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return u.Hostname() == "127.0.0.1" && u.Port() == port &&
		strings.TrimRight(u.EscapedPath(), "/") == strings.TrimRight(path, "/")
}

func Save(path string, cfg Config) error {
	if path == "" {
		path = DefaultPath()
	}
	var err error
	cfg, err = cfg.Resolve()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmp)
		}
	}()
	enc := toml.NewEncoder(f)
	err = enc.Encode(cfg)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	renamed = true
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr = dir.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func ParseSince(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n := strings.TrimSuffix(s, "d")
		d, err := time.ParseDuration(n + "h")
		if err != nil {
			return 0, fmt.Errorf("nieprawidłowy okres %q", s)
		}
		return d * 24, nil
	}
	return time.ParseDuration(s)
}
