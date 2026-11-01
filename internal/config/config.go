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

	"github.com/xue9999/Mail-Guardian/internal/provider"
)

const (
	AppName = "Mail Guardian"
	// LegacyDataName is a persisted installation path, not the product name.
	LegacyDataName = "O2 Mail Guardian"
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
	return filepath.Join(home, "Library", "Application Support", LegacyDataName)
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
		return Config{}, fmt.Errorf("cannot read configuration %q: %w", path, err)
	}
	return cfg.Resolve()
}

func (c Config) Validate() error {
	var problems []string
	if c.Version != 1 && c.Version != 2 {
		problems = append(problems, "unsupported configuration version")
	}
	if c.Version == 2 {
		if !validID(c.InstanceID) || !validID(c.Account.ID) {
			problems = append(problems, "missing valid instance or account identity")
		}
		if _, err := provider.Resolve(c.Account.Provider, c.Account.Host, c.Account.Port, c.Account.Username, c.Account.Email, c.Account.AuthMethod); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if !strings.Contains(c.Account.Email, "@") {
		problems = append(problems, "invalid account email address")
	}
	if c.Account.Host == "" || c.Account.Port < 1 || c.Account.Port > 65535 {
		problems = append(problems, "missing IMAP hostname or port")
	}
	if !c.Account.TLS {
		problems = append(problems, "IMAP connection must use TLS")
	}
	if c.Version == 1 && (!strings.EqualFold(c.Account.Host, "poczta.o2.pl") || c.Account.Port != 993) {
		problems = append(problems, "The legacy o2 profile requires poczta.o2.pl on encrypted port 993")
	}
	if c.Folders.Inbox == "" || c.Folders.ServerSpam == "" {
		problems = append(problems, "Inbox or spam folder not selected")
	}
	folderValues := []string{
		c.Folders.Inbox, c.Folders.ServerSpam, c.Folders.Quarantine,
		c.Folders.Review, c.Folders.TrainSpam, c.Folders.TrainHam,
	}
	seen := map[string]bool{}
	for _, folder := range folderValues {
		if strings.TrimSpace(folder) == "" {
			problems = append(problems, "Guardian folder name must not be empty")
			continue
		}
		key := strings.ToLower(folder)
		if seen[key] {
			problems = append(problems, "Inbox, spam and Guardian folders must have different names")
		}
		seen[key] = true
	}
	if c.Safety.Mode != "protect" && c.Safety.Mode != "active" {
		problems = append(problems, "mode must be protect or active")
	}
	if c.Safety.QuarantineDays < 30 {
		problems = append(problems, "quarantine must last at least 30 days")
	}
	if c.Safety.ArchiveDays < c.Safety.QuarantineDays {
		problems = append(problems, "local backup retention must be at least as long as quarantine")
	}
	if c.Safety.ArchiveDays < 35 {
		problems = append(problems, "local backup retention must be at least 35 days")
	}
	if c.Safety.ProtectDays < 14 {
		problems = append(problems, "protect mode must last at least 14 days")
	}
	if c.Safety.MinLearnSpam < 200 || c.Safety.MinLearnHam < 200 {
		problems = append(problems, "permanent deletion requires training thresholds of at least 200 spam and 200 ham")
	}
	if !c.Safety.RequireAuthForRescue {
		problems = append(problems, "automatic rescue requires authenticated sender")
	}
	if c.Safety.PurgeEnabled && c.Safety.Mode != "active" {
		problems = append(problems, "permanent deletion requires active mode")
	}
	if c.Safety.MaxMessageMiB < 1 || c.Safety.MaxMessageMiB > 100 {
		problems = append(problems, "size limit must be between 1 and 100 MiB")
	}
	if c.Safety.ScanLookbackDays < 1 || c.Safety.ScanLookbackDays > 90 {
		problems = append(problems, "scan lookback must be between 1 and 90 days")
	}
	if c.Safety.MaxMessagesPerFolder < 1 || c.Safety.MaxMessagesPerFolder > 5000 {
		problems = append(problems, "per-run message limit must be between 1 and 5000")
	}
	if c.Rspamd.SpamScore <= c.Rspamd.HamScore {
		problems = append(problems, "spam threshold must exceed ham threshold")
	}
	if c.Rspamd.SpamScore < 6 {
		problems = append(problems, "spam threshold must be at least 6; below 12 requires independent quality evaluation")
	}
	if c.Rspamd.HamScore > -2 {
		problems = append(problems, "automatic rescue threshold must not exceed -2")
	}
	if !localRspamdURL(c.Rspamd.ScanURL, "11333", "/checkv2") {
		problems = append(problems, "Rspamd scan URL must be local http://127.0.0.1:11333/checkv2")
	}
	if !localRspamdURL(c.Rspamd.LearnURL, "11334", "") {
		problems = append(problems, "Rspamd learning URL must be local http://127.0.0.1:11334")
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
			return 0, fmt.Errorf("invalid period %q", s)
		}
		return d * 24, nil
	}
	return time.ParseDuration(s)
}
