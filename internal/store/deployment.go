package store

import (
	"context"
	"errors"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/config"
)

// BindDeployment revokes operational permission on the first server use or a
// changed host. This is separate from mailbox identity: moving the same v2
// account must still require fresh dry-run acceptance. History is preserved.
func (db *DB) BindDeployment(ctx context.Context, identity string, now time.Time) error {
	if identity == "" {
		return errors.New("missing deployment identity")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previous string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT value FROM settings WHERE key='deployment_identity'),'')`).Scan(&previous); err != nil {
		return err
	}
	if previous == identity {
		return nil
	}
	for key, value := range map[string]string{
		"deployment_identity":            identity,
		"first_dry_run_completed_at":     "",
		"configuration_dry_run_required": "1",
		"active_since":                   "",
		"protect_since":                  now.UTC().Format(time.RFC3339Nano),
	} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ReauthorizeDeployment preserves factual policy history during an explicit
// same-mailbox handover. The caller must hold the instance and exclusive
// migration locks and validate the existing engine activation-quality gate.
// The transaction binds the new host and revokes all inherited dry-run proof;
// it never authorizes a run. Ordinary BindDeployment remains conservative.
func (db *DB) ReauthorizeDeployment(ctx context.Context, cfg config.Config, identity string) error {
	resolved, err := cfg.Resolve()
	if err != nil {
		return err
	}
	if identity == "" || resolved.Safety.PurgeEnabled {
		return errors.New("valid deployment identity and permanent deletion disabled are required")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previous string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT value FROM settings WHERE key='deployment_identity'),'')`).Scan(&previous); err != nil {
		return err
	}
	if previous != "" {
		return errors.New("policy handover requires an explicitly unbound imported snapshot before any destination runtime command")
	}
	for key, expected := range map[string]string{
		"mailbox_fingerprint":       resolved.MailboxFingerprint(),
		"authorization_fingerprint": resolved.AuthorizationFingerprint(),
	} {
		var actual string
		if err := tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key=?", key).Scan(&actual); err != nil || actual != expected {
			return errors.New("policy handover requires the exact existing mailbox and folder identities")
		}
	}
	var invalid int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM messages WHERE account<>? OR status NOT IN ('kept','observed','quarantined','rescued','review','superseded','restored','purged'))
		OR EXISTS(SELECT 1 FROM reconciliations)
		OR EXISTS(SELECT 1 FROM runs WHERE finished_at IS NULL OR finished_at='' OR status NOT IN ('ok','error'))
		OR EXISTS(SELECT 1 FROM settings WHERE key IN ('model_checkpoint_required','bayes_rollback_at') AND value<>'')`, resolved.Account.Email).Scan(&invalid); err != nil {
		return err
	} else if invalid != 0 {
		return errors.New("policy handover requires reconciled state without pending operations or model recovery markers")
	}
	var status string
	var errorsCount int
	if err := tx.QueryRowContext(ctx, `SELECT status,errors FROM runs WHERE command='run' AND dry_run=0 ORDER BY id DESC LIMIT 1`).Scan(&status, &errorsCount); err != nil || status != "ok" || errorsCount != 0 {
		return errors.New("policy handover requires a successful latest actual filtering run")
	}
	for key, value := range map[string]string{
		"deployment_identity":            identity,
		"first_dry_run_completed_at":     "",
		"configuration_dry_run_required": "1",
	} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value); err != nil {
			return err
		}
	}
	return tx.Commit()
}
