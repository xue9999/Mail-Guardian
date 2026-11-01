package main

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/imapmail"
	"github.com/xue9999/Mail-Guardian/internal/store"
)

func dialMailbox(ctx context.Context, cfg config.Config, password string) (*imapmail.Client, error) {
	// Diagnostics and the CLI wizard can connect without opening runtimeApp.
	// They must apply the same identity check before sending saved credentials.
	if _, err := os.Stat(cfg.Runtime.Database); err == nil {
		db, err := store.Open(cfg.Runtime.Database)
		if err != nil {
			return nil, err
		}
		_, bindingErr := db.ConfigurationMatches(ctx, cfg)
		closeErr := db.Close()
		if err := errors.Join(bindingErr, closeErr); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return imapmail.DialAuthenticated(ctx, cfg.Account.Host, cfg.Account.Port, imapmail.Authentication{
		Method: cfg.Account.AuthMethod, Username: cfg.Account.LoginUsername(), Secret: password,
	})
}

// Existing protocol-1 requests remain valid. Omitted connection settings keep
// the configured profile; they never redirect a custom account to o2.
func (a *application) resolveSetupConfiguration(request setupRequest) (config.Config, bool, error) {
	cfg, err := config.Load(a.configPath)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return config.Config{}, false, err
	}
	if exists {
		if !strings.EqualFold(cfg.Account.Email, request.Email) {
			return config.Config{}, true, errors.New("existing data belongs to another account")
		}
	} else {
		if request.Provider == "" {
			// Protocol-1 clients without connection fields retain the v1 profile.
			cfg = config.Default()
		} else {
			cfg, err = config.NewInstance()
			if err != nil {
				return config.Config{}, false, err
			}
		}
		cfg.Account.Email = request.Email
	}
	previous := cfg
	if request.Provider != "" {
		cfg.Account.Provider = request.Provider
	}
	if request.Host != "" {
		cfg.Account.Host = request.Host
	}
	if request.Port != 0 {
		cfg.Account.Port = request.Port
	}
	if request.Username != "" {
		cfg.Account.Username = request.Username
	}
	if request.AuthMethod != "" {
		cfg.Account.AuthMethod = request.AuthMethod
	}
	cfg, err = cfg.ResolveIdentity()
	if err != nil {
		return config.Config{}, exists, err
	}
	if exists && cfg.MailboxFingerprint() != previous.MailboxFingerprint() {
		return config.Config{}, true, store.ErrMailboxIdentity
	}
	return cfg, exists, nil
}
