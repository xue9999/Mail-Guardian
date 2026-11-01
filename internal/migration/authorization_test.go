package migration

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/o2-mail-guardian/guardian/internal/store"
)

func authorizationFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	source, output := filepath.Join(dir, "source.sqlite"), filepath.Join(dir, "output.sqlite")
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE history (message TEXT NOT NULL);
INSERT INTO history VALUES('original evidence');
INSERT INTO settings VALUES
('deployment_identity','old-host'),('first_dry_run_completed_at','old-proof'),
('configuration_dry_run_required',''),('active_since','old-active'),
('protect_since','old-protect'),('mailbox_fingerprint','mailbox'),
('authorization_fingerprint','authorization'),('bayes_spam_revision_highwater','321')`); err != nil {
		t.Fatal(err)
	}
	return source, output
}

func readAuthorization(t *testing.T, path string) map[string]string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT key,value FROM settings")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			t.Fatal(err)
		}
		result[key] = value
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRevokeSnapshotAuthorizationPreservesHistoryAndRequiresRebinding(t *testing.T) {
	ctx := context.Background()
	source, output := authorizationFixture(t)
	now := time.Date(2026, 10, 30, 18, 30, 0, 123, time.FixedZone("test", 3600))
	if err := RevokeSnapshotAuthorization(ctx, source, output, now); err != nil {
		t.Fatal(err)
	}
	original, result := readAuthorization(t, source), readAuthorization(t, output)
	for key, want := range map[string]string{"deployment_identity": "old-host", "first_dry_run_completed_at": "old-proof", "active_since": "old-active", "protect_since": "old-protect"} {
		if original[key] != want {
			t.Fatalf("source %s=%q, want %q", key, original[key], want)
		}
	}
	for key, want := range map[string]string{"deployment_identity": "", "first_dry_run_completed_at": "", "configuration_dry_run_required": "1", "active_since": "", "protect_since": now.UTC().Format(time.RFC3339Nano), "mailbox_fingerprint": "mailbox", "authorization_fingerprint": "authorization", "bayes_spam_revision_highwater": "321"} {
		if result[key] != want {
			t.Fatalf("snapshot %s=%q, want %q", key, result[key], want)
		}
	}
	check, err := sql.Open("sqlite", output)
	if err != nil {
		t.Fatal(err)
	}
	var history string
	if err := check.QueryRow("SELECT message FROM history").Scan(&history); err != nil || history != "original evidence" {
		t.Fatalf("history=%q err=%v", history, err)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}
	worker, err := store.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	if err := worker.RequireOperationalAuthorization(ctx); err == nil {
		t.Fatal("revoked snapshot was authorized")
	}
	if err := worker.BindDeployment(ctx, "new-host", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := worker.RequireOperationalAuthorization(ctx); err == nil {
		t.Fatal("deployment binding silently authorized operations")
	}
	if err := RevokeSnapshotAuthorization(ctx, source, output, now); err == nil {
		t.Fatal("existing output overwritten")
	}
}

func TestRevokeSnapshotOperationalAuthorizationPreservesPolicyEvidence(t *testing.T) {
	source, output := authorizationFixture(t)
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := RevokeSnapshotOperationalAuthorization(context.Background(), source, output, time.Now()); err != nil {
		t.Fatal(err)
	}
	original, result := readAuthorization(t, source), readAuthorization(t, output)
	for key, value := range original {
		want := value
		switch key {
		case "deployment_identity", "first_dry_run_completed_at":
			want = ""
		case "configuration_dry_run_required":
			want = "1"
		}
		if result[key] != want {
			t.Fatalf("key %s changed incorrectly: %q want %q", key, result[key], want)
		}
	}
	after, err := os.ReadFile(source)
	if err != nil || string(after) != string(before) {
		t.Fatal("source policy evidence changed")
	}
}

func TestRevokeSnapshotAuthorizationFailsClosed(t *testing.T) {
	for _, test := range []string{"zero-time", "missing-settings", "trigger", "preexisting-sidecar"} {
		t.Run(test, func(t *testing.T) {
			source, output := authorizationFixture(t)
			now := time.Now()
			if test == "zero-time" {
				now = time.Time{}
			}
			if test == "preexisting-sidecar" {
				if err := os.WriteFile(output+"-wal", []byte("do not remove"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if test == "missing-settings" || test == "trigger" {
				db, err := sql.Open("sqlite", source)
				if err != nil {
					t.Fatal(err)
				}
				statement := "DROP TABLE settings"
				if test == "trigger" {
					statement = "CREATE TRIGGER change_history AFTER UPDATE ON settings BEGIN DELETE FROM history; END"
				}
				if _, err := db.Exec(statement); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := RevokeSnapshotAuthorization(context.Background(), source, output, now); err == nil {
				t.Fatal("unsafe snapshot accepted")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("failed output retained: %v", err)
			}
			if test == "preexisting-sidecar" {
				if data, err := os.ReadFile(output + "-wal"); err != nil || string(data) != "do not remove" {
					t.Fatal("existing sidecar changed")
				}
			}
		})
	}
}
