package migration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

type fixture struct {
	dir, source, output, oldRoot, stage, target, rel, digest string
	identity                                                 *age.X25519Identity
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestVerifyPlaintextRejectsOversizeAndCancellation(t *testing.T) {
	if err := verifyPlaintext(context.Background(), io.LimitReader(zeros{}, maxArchiveBytes+1), ""); err == nil {
		t.Fatal("oversize archive accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyPlaintext(ctx, zeros{}, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled verification returned %v", err)
	}
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f := fixture{dir: dir, source: filepath.Join(dir, "source.sqlite"), output: filepath.Join(dir, "output.sqlite"),
		oldRoot: "/old/archive", stage: filepath.Join(dir, "archive"), target: "/var/lib/mail-guardian/pilot/archive", rel: "2026/10/message.age"}
	var err error
	f.identity, err = age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.stage, "2026/10"), 0o700); err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: test@example.invalid\r\n\r\nfixture mail\r\n")
	sum := sha256.Sum256(raw)
	f.digest = hex.EncodeToString(sum[:])
	file, err := os.OpenFile(filepath.Join(f.stage, f.rel), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	w, err := age.Encrypt(file, f.identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", f.source)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE messages (id INTEGER PRIMARY KEY, archive_path TEXT NOT NULL, raw_sha256 TEXT NOT NULL, state TEXT NOT NULL); CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT); INSERT INTO settings VALUES('history','preserved')`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO messages VALUES (1,?,?,?), (2,?,?,?), (3,'','',?)", filepath.Join(f.oldRoot, f.rel), f.digest, "first", filepath.Join(f.oldRoot, f.rel), f.digest, "second", "unarchived"); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) run() (int, error) {
	return RelocateSnapshot(context.Background(), f.source, f.output, f.oldRoot, f.stage, f.target, f.identity)
}

func TestRelocateSnapshotPreservesSourceAndHistory(t *testing.T) {
	f := newFixture(t)
	count, err := f.run()
	if err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	for _, test := range []struct{ path, archive string }{{f.source, filepath.Join(f.oldRoot, f.rel)}, {f.output, filepath.Join(f.target, f.rel)}} {
		db, err := sql.Open("sqlite", test.path)
		if err != nil {
			t.Fatal(err)
		}
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM messages WHERE archive_path = ?", test.archive).Scan(&count); err != nil || count != 2 {
			t.Fatalf("path count=%d err=%v", count, err)
		}
		var history string
		if err := db.QueryRow("SELECT value FROM settings WHERE key='history'").Scan(&history); err != nil || history != "preserved" {
			t.Fatalf("history=%q err=%v", history, err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.run(); err == nil {
		t.Fatal("overwrote existing output")
	}
}

func TestRelocateSnapshotNeverRemovesExistingSidecar(t *testing.T) {
	f := newFixture(t)
	sidecar := f.output + "-wal"
	if err := os.WriteFile(sidecar, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run(); err == nil {
		t.Fatal("accepted a pre-existing sidecar")
	}
	content, err := os.ReadFile(sidecar)
	if err != nil || string(content) != "existing" {
		t.Fatalf("sidecar changed: %q %v", content, err)
	}
}

func TestRelocateSnapshotFailsClosed(t *testing.T) {
	for _, name := range []string{"wrong-key", "corrupt", "missing", "symlink", "symlink-directory", "insecure-stage", "insecure-output-directory", "outside-root", "traversal", "conflicting-hashes", "invalid-hash"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			path := filepath.Join(f.stage, f.rel)
			switch name {
			case "wrong-key":
				f.identity, _ = age.GenerateX25519Identity()
			case "corrupt":
				if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".real", path); err != nil {
					t.Fatal(err)
				}
			case "symlink-directory":
				parent := filepath.Join(f.stage, "2026")
				if err := os.Rename(parent, parent+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(parent+".real", parent); err != nil {
					t.Fatal(err)
				}
			case "insecure-stage":
				if err := os.Chmod(f.stage, 0o755); err != nil {
					t.Fatal(err)
				}
			case "insecure-output-directory":
				if err := os.Chmod(f.dir, 0o755); err != nil {
					t.Fatal(err)
				}
			default:
				db, err := sql.Open("sqlite", f.source)
				if err != nil {
					t.Fatal(err)
				}
				var q string
				switch name {
				case "outside-root":
					q = "UPDATE messages SET archive_path='/elsewhere/message.age' WHERE id=1"
				case "traversal":
					q = "UPDATE messages SET archive_path='/old/archive/../escape.age' WHERE id=1"
				case "conflicting-hashes":
					q = "UPDATE messages SET raw_sha256='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE id=2"
				case "invalid-hash":
					q = "UPDATE messages SET raw_sha256='invalid' WHERE id IN (1,2)"
				}
				if _, err := db.Exec(q); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.run(); err == nil {
				t.Fatal("unsafe snapshot accepted")
			}
			if _, err := os.Lstat(f.output); !os.IsNotExist(err) {
				t.Fatalf("failed output retained: %v", err)
			}
		})
	}
}
