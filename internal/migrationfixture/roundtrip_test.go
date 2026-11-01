// Package migrationfixture exercises only synthetic, offline data. This is not
// a migration command and deliberately omits live fencing, Redis and credentials.
package migrationfixture

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/migration"
	"github.com/xue9999/Mail-Guardian/internal/recoverybundle"
	_ "modernc.org/sqlite"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// This fixture checks the interfaces between snapshot, encrypted transport,
// extraction and archive relocation. It cannot establish that a real snapshot
// is coherent, establish cross-host ownership, import Redis, or authorize mail.
func TestOfflineSyntheticSnapshotAndRecovery(t *testing.T) {
	root := t.TempDir()
	must(t, os.Chmod(root, 0700))
	stage := filepath.Join(root, "stage")
	must(t, os.Mkdir(stage, 0700))
	archiveRoot := filepath.Join(stage, "archive")
	must(t, os.MkdirAll(filepath.Join(archiveRoot, "2026", "10"), 0700))
	archiveIdentity, err := age.GenerateX25519Identity()
	must(t, err)
	backupIdentity, err := age.GenerateX25519Identity()
	must(t, err)
	raw := []byte("From: fixture@example.invalid\r\n\r\nsynthetic mail\r\n")
	digest := sha256.Sum256(raw)
	archiveRelative := filepath.Join("2026", "10", "fixture.age")
	f, err := os.OpenFile(filepath.Join(archiveRoot, archiveRelative), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(t, err)
	aw, err := age.Encrypt(f, archiveIdentity.Recipient())
	must(t, err)
	_, err = aw.Write(raw)
	must(t, err)
	must(t, aw.Close())
	must(t, f.Close())
	// The original archive identity belongs inside the encrypted backup; a
	// different generated identity protects the backup itself in this fixture.
	must(t, os.WriteFile(filepath.Join(stage, "archive-identity"), []byte(archiveIdentity.String()), 0600))

	oldRoot := filepath.Join(root, "old-host", "archive")
	oldArchive := filepath.Join(oldRoot, archiveRelative)
	source := filepath.Join(root, "source.db")
	db, err := sql.Open("sqlite", source)
	must(t, err)
	defer db.Close()
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE messages (id INTEGER PRIMARY KEY, archive_path TEXT NOT NULL, raw_sha256 TEXT NOT NULL, state TEXT NOT NULL); CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT); INSERT INTO settings VALUES ('history','preserved')`)
	must(t, err)
	_, err = db.Exec(`INSERT INTO settings VALUES ('first_dry_run_completed_at','2026-01-01T00:00:00Z'), ('configuration_dry_run_required','0'), ('deployment_identity','old-fixture')`)
	must(t, err)
	_, err = db.Exec(`INSERT INTO messages VALUES (1,?,?,?), (2,?,?,?)`, oldArchive, hex.EncodeToString(digest[:]), "first", oldArchive, hex.EncodeToString(digest[:]), "second")
	must(t, err)
	if st, err := os.Stat(source + "-wal"); err != nil || st.Size() == 0 {
		t.Fatalf("expected committed WAL: %v", err)
	}
	must(t, migration.SnapshotDatabase(context.Background(), source, filepath.Join(stage, "guardian.db")))

	cfg, err := config.NewInstance()
	cfg.Account.Provider = "o2"
	must(t, err)
	cfg.Account.Email = "fixture@example.invalid"
	cfg.Folders.ServerSpam = "Spam"
	cfg.Runtime.DataDir = filepath.Join(root, "old-host")
	cfg.Safety.Mode, cfg.Safety.PurgeEnabled = "active", true
	resolved, err := cfg.Resolve()
	must(t, err)
	mapped, err := migration.LinuxConfig(cfg, "pilot")
	must(t, err)
	if mapped.MailboxFingerprint() != resolved.MailboxFingerprint() || mapped.AuthorizationFingerprint() != resolved.AuthorizationFingerprint() || mapped.Safety.Mode != resolved.Safety.Mode || mapped.Safety.PurgeEnabled {
		t.Fatal("config identity or safety changed unexpectedly")
	}
	mappedBytes, err := json.Marshal(mapped)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(stage, "fixture-config.json"), mappedBytes, 0600))

	bundle := filepath.Join(root, "fixture.age")
	must(t, recoverybundle.Seal(stage, bundle, backupIdentity.Recipient()))
	sealed, err := os.ReadFile(bundle)
	must(t, err)
	receipt := sha256.Sum256(sealed)
	expected := hex.EncodeToString(receipt[:])
	limits := recoverybundle.Limits{MaxBytes: 8 << 20, MaxFiles: 100, ReserveBytes: 2 << 30}
	restored := filepath.Join(root, "restored")
	must(t, recoverybundle.Open(bundle, restored, backupIdentity, expected, limits))
	configBytes, err := os.ReadFile(filepath.Join(restored, "fixture-config.json"))
	must(t, err)
	var restoredConfig config.Config
	must(t, json.Unmarshal(configBytes, &restoredConfig))
	if restoredConfig.MailboxFingerprint() != resolved.MailboxFingerprint() || restoredConfig.AuthorizationFingerprint() != resolved.AuthorizationFingerprint() || restoredConfig.Safety.Mode != resolved.Safety.Mode || restoredConfig.Safety.PurgeEnabled {
		t.Fatal("restored config identity or safety changed")
	}
	identityText, err := os.ReadFile(filepath.Join(restored, "archive-identity"))
	must(t, err)
	restoredIdentity, err := age.ParseX25519Identity(string(identityText))
	must(t, err)
	targetRoot := "/var/lib/mail-guardian/pilot/archive"
	relocated := filepath.Join(restored, "relocated.db")
	count, err := migration.RelocateSnapshot(context.Background(), filepath.Join(restored, "guardian.db"), relocated, oldRoot, filepath.Join(restored, "archive"), targetRoot, restoredIdentity)
	must(t, err)
	if count != 1 {
		t.Fatalf("expected one unique verified archive, got %d", count)
	}
	rdb, err := sql.Open("sqlite", relocated)
	must(t, err)
	defer rdb.Close()
	var refs int
	err = rdb.QueryRow("SELECT count(*) FROM messages WHERE archive_path = ?", filepath.Join(targetRoot, archiveRelative)).Scan(&refs)
	must(t, err)
	if refs != 2 {
		t.Fatalf("expected two relocated references, got %d", refs)
	}
	var history string
	err = rdb.QueryRow("SELECT value FROM settings WHERE key = 'history'").Scan(&history)
	must(t, err)
	if history != "preserved" {
		t.Fatal("history not preserved")
	}
	revoked := filepath.Join(restored, "revoked.db")
	must(t, migration.RevokeSnapshotAuthorization(context.Background(), relocated, revoked, time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)))
	vdb, err := sql.Open("sqlite", revoked)
	must(t, err)
	defer vdb.Close()
	var required, proof, deployment string
	err = vdb.QueryRow(`SELECT (SELECT value FROM settings WHERE key='configuration_dry_run_required'), (SELECT value FROM settings WHERE key='first_dry_run_completed_at'), (SELECT value FROM settings WHERE key='deployment_identity')`).Scan(&required, &proof, &deployment)
	must(t, err)
	if required != "1" || proof != "" || deployment != "" {
		t.Fatal("restored snapshot inherited operational authorization")
	}
	err = vdb.QueryRow("SELECT value FROM settings WHERE key = 'history'").Scan(&history)
	must(t, err)
	if history != "preserved" {
		t.Fatal("authorization revocation lost history")
	}
	err = db.QueryRow("SELECT count(*) FROM messages WHERE archive_path = ?", oldArchive).Scan(&refs)
	must(t, err)
	if refs != 2 {
		t.Fatal("source database was modified")
	}
	file, err := os.Open(filepath.Join(restored, "archive", archiveRelative))
	must(t, err)
	defer file.Close()
	plain, err := age.Decrypt(file, restoredIdentity)
	must(t, err)
	plaintext, err := io.ReadAll(plain)
	must(t, err)
	if sha256.Sum256(plaintext) != digest {
		t.Fatal("restored archive content differs")
	}

	wrong, err := age.GenerateX25519Identity()
	must(t, err)
	if err := recoverybundle.Open(bundle, filepath.Join(root, "wrong-key"), wrong, expected, limits); err == nil {
		t.Fatal("wrong backup key accepted")
	}
	if err := recoverybundle.Open(bundle, filepath.Join(root, "wrong-receipt"), backupIdentity, strings.Repeat("0", 64), limits); err == nil {
		t.Fatal("mismatched receipt accepted")
	}
	must(t, os.WriteFile(filepath.Join(restored, "archive", archiveRelative), []byte("damaged"), 0600))
	badOutput := filepath.Join(restored, "bad.db")
	if _, err := migration.RelocateSnapshot(context.Background(), filepath.Join(restored, "guardian.db"), badOutput, oldRoot, filepath.Join(restored, "archive"), targetRoot, restoredIdentity); err == nil {
		t.Fatal("corrupt archive accepted")
	}
	if _, err := os.Lstat(badOutput); !os.IsNotExist(err) {
		t.Fatalf("failed relocation left output: %v", err)
	}
}
