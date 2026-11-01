package migration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RevokeSnapshotAuthorization produces a fresh private SQLite snapshot with
// inherited operational and activation proofs revoked. It does not modify the
// source database, remove history, bind the destination, or authorize a run.
// BindDeployment on the destination must still run before accessing mail.
//
// This is an offline building block, not a complete handover. The caller must
// fence writers and hold the instance run lock across all related captures.
// The output must not exist; its parent must be a private staging directory
// owned by the calling user. Failed outputs are removed.
func RevokeSnapshotAuthorization(ctx context.Context, sourceDB, outputDB string, now time.Time) (retErr error) {
	return revokeSnapshotAuthorization(ctx, sourceDB, outputDB, now, false)
}

// RevokeSnapshotOperationalAuthorization creates a new standalone snapshot that
// clears inherited deployment and dry-run authority while preserving historical
// active/protect timestamps and quality evidence. The explicit server policy
// adoption gate must validate this history before binding the target; ordinary
// deployment binding remains conservative. This does not authorize mail work.
func RevokeSnapshotOperationalAuthorization(ctx context.Context, sourceDB, outputDB string, now time.Time) error {
	return revokeSnapshotAuthorization(ctx, sourceDB, outputDB, now, true)
}

func revokeSnapshotAuthorization(ctx context.Context, sourceDB, outputDB string, now time.Time, preserveHistory bool) (retErr error) {
	if now.IsZero() {
		return errors.New("a valid protection-window start is required")
	}
	for _, path := range []string{sourceDB, outputDB} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("database paths must be clean and absolute")
		}
	}
	parent, err := os.Lstat(filepath.Dir(outputDB))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return errors.New("output parent must be a real directory")
	}
	if err := SnapshotDatabase(ctx, sourceDB, outputDB); err != nil {
		return fmt.Errorf("create authorization snapshot: %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = os.Remove(outputDB)
			for _, suffix := range []string{"-wal", "-shm", "-journal"} {
				_ = os.Remove(outputDB + suffix)
			}
		}
	}()
	uri, err := sqliteURI(outputDB, "rw")
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	closed := false
	defer func() {
		if !closed {
			retErr = errors.Join(retErr, db.Close())
		}
	}()
	var tables, triggers int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='settings'").Scan(&tables); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'").Scan(&triggers); err != nil {
		return err
	}
	if tables != 1 || triggers != 0 {
		return errors.New("unsupported database schema: missing settings table or unexpected triggers")
	}
	if _, err := db.ExecContext(ctx, "PRAGMA synchronous=FULL"); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	values := map[string]string{
		"deployment_identity":            "",
		"first_dry_run_completed_at":     "",
		"configuration_dry_run_required": "1",
	}
	if !preserveHistory {
		values["active_since"] = ""
		values["protect_since"] = now.UTC().Format(time.RFC3339Nano)
	}
	for key, value := range values {
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value); err != nil {
			return fmt.Errorf("revoke inherited authorization: %w", err)
		}
	}
	for key, expected := range values {
		var actual string
		if err := tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key=?", key).Scan(&actual); err != nil || actual != expected {
			return errors.New("authorization revocation could not be verified")
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := integrityCheck(ctx, db); err != nil {
		return err
	}
	if err := db.Close(); err != nil {
		return err
	}
	closed = true
	f, err := os.OpenFile(outputDB, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(outputDB))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
