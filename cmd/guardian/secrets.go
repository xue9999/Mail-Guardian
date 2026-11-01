package main

import (
	"os"
	"runtime"

	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/keychain"
	"github.com/o2-mail-guardian/guardian/internal/secrets"
)

func runtimeSecrets(cfg config.Config) secrets.Store {
	if runtime.GOOS == "darwin" {
		return keychain.New()
	}
	return secrets.Credentials{
		Directory: os.Getenv("CREDENTIALS_DIRECTORY"),
		Bindings: map[secrets.Key]string{
			{Service: cfg.Account.PasswordKeychainService, Account: cfg.Account.Email}: "imap-password",
			{Service: cfg.Rspamd.PasswordKeychainService, Account: "controller"}:       "rspamd-password",
			{Service: cfg.Runtime.ArchiveKeychainService, Account: cfg.Account.Email}:  "archive-identity",
		},
	}
}
