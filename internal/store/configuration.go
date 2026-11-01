package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/config"
)

var ErrMailboxIdentity = errors.New("instance state belongs to another mailbox; use a separate instance or explicit migration")

// BindConfiguration must run under the instance run lock before accessing mail.
// Mailbox identity is immutable; folder changes revoke operational permission.
// Historical messages, corrections, runs and model high-water marks survive.
func (db *DB) BindConfiguration(ctx context.Context, cfg config.Config, now time.Time) error {
	c, err := cfg.ResolveIdentity()
	if err != nil {
		return err
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	get := func(key string) (string, error) {
		var value string
		err := tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&value)
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return value, err
	}
	mailbox, err := get("mailbox_fingerprint")
	if err != nil {
		return err
	}
	if mailbox != "" && mailbox != c.MailboxFingerprint() {
		return ErrMailboxIdentity
	}
	if mailbox == "" {
		var populated, foreign int
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM messages)+(SELECT count(*) FROM runs)+(SELECT count(*) FROM settings)`).Scan(&populated); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM messages WHERE account<>?`, c.Account.Email).Scan(&foreign); err != nil {
			return err
		}
		if foreign > 0 || (populated > 0 && !c.LegacyCompatible()) {
			return ErrMailboxIdentity
		}
	}
	previous, err := get("authorization_fingerprint")
	if err != nil {
		return err
	}
	if (mailbox == "") != (previous == "") {
		return errors.New("configuration binding record is incomplete; operations remain blocked")
	}
	values := map[string]string{
		"mailbox_fingerprint":       c.MailboxFingerprint(),
		"authorization_fingerprint": c.AuthorizationFingerprint(),
	}
	if mailbox == "" && !c.LegacyCompatible() {
		// A new instance cannot inherit the legacy successful-run migration.
		values["first_dry_run_completed_at"] = ""
		values["configuration_dry_run_required"] = "1"
	}
	if previous != "" && previous != c.AuthorizationFingerprint() {
		var pending int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM messages WHERE status IN ('pending_move','pending_restore')`).Scan(&pending); err != nil {
			return err
		}
		if pending > 0 {
			return errors.New("reconcile pending operations under the previous folder configuration first")
		}
		values["first_dry_run_completed_at"] = ""
		values["configuration_dry_run_required"] = "1"
		values["active_since"] = ""
		values["protect_since"] = now.UTC().Format(time.RFC3339Nano)
	}
	for key, value := range values {
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) RequireOperationalAuthorization(ctx context.Context) error {
	required, err := db.GetSetting(ctx, "configuration_dry_run_required")
	if err != nil {
		return err
	}
	if required != "" {
		proof, err := db.GetSetting(ctx, "first_dry_run_completed_at")
		if err != nil {
			return err
		}
		if proof == "" {
			return errors.New("configuration requires a new dry-run; mailbox operations blocked")
		}
	}
	return nil
}

// ConfigurationMatches is read-only, so a status query cannot rebind a worker
// running with another configuration. A changed layout is never authorized.
func (db *DB) ConfigurationMatches(ctx context.Context, cfg config.Config) (bool, error) {
	c, err := cfg.ResolveIdentity()
	if err != nil {
		return false, err
	}
	mailbox, err := db.GetSetting(ctx, "mailbox_fingerprint")
	if err != nil {
		return false, err
	}
	if mailbox == "" {
		if !c.LegacyCompatible() {
			var populated int
			if err := db.sql.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM messages)+(SELECT count(*) FROM runs)+(SELECT count(*) FROM settings)`).Scan(&populated); err != nil {
				return false, err
			}
			if populated > 0 {
				return false, ErrMailboxIdentity
			}
			return false, nil // new instances need an explicitly bound dry-run
		}
		var foreign int
		if err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM messages WHERE account<>?`, c.Account.Email).Scan(&foreign); err != nil {
			return false, err
		}
		if foreign > 0 {
			return false, ErrMailboxIdentity
		}
		return true, nil
	}
	if mailbox != c.MailboxFingerprint() {
		return false, ErrMailboxIdentity
	}
	authorization, err := db.GetSetting(ctx, "authorization_fingerprint")
	if err != nil {
		return false, err
	}
	return authorization == c.AuthorizationFingerprint(), nil
}

func (db *DB) DryRunAuthorizedFor(ctx context.Context, cfg config.Config) (bool, error) {
	matches, err := db.ConfigurationMatches(ctx, cfg)
	if err != nil || !matches {
		return false, err
	}
	return db.DryRunAuthorized(ctx)
}

// RequireConfiguration protects activation paths that do not open the worker.
func (db *DB) RequireConfiguration(ctx context.Context, cfg config.Config) error {
	matches, err := db.ConfigurationMatches(ctx, cfg)
	if err != nil {
		return err
	}
	if !matches {
		return fmt.Errorf("configuration changed; complete a new dry-run before activation")
	}
	return db.RequireOperationalAuthorization(ctx)
}
