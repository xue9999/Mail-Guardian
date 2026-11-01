package migration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/store"
)

func readinessTestLimits() ReadinessLimits {
	return ReadinessLimits{
		MaxDatabaseBytes:     8 << 20,
		MaxRows:              10000,
		MaxArchiveReferences: 100,
		MaxArchives:          100,
		MaxInventoryBytes:    1 << 20,
		MaxPathBytes:         4096,
	}
}

func readinessFixture(t *testing.T) (string, config.Config) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.NewInstance()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Account.Email = "readiness@example.invalid"
	cfg.Folders.ServerSpam = "Spam"
	cfg.Runtime.DataDir = root
	cfg.Runtime.ArchiveDir = filepath.Join(root, "archive")
	cfg, err = cfg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "source.db")
	db, err := store.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Date(2026, 10, 30, 19, 0, 0, 0, time.UTC)
	if err := db.BindConfiguration(ctx, cfg, now); err != nil {
		db.Close()
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"bayes_spam_revision_highwater": "261",
		"bayes_ham_revision_highwater":  "161",
	} {
		if err := db.SetSetting(ctx, key, value); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	archive := filepath.Join(root, "archive", "2026", "10", "one.age")
	for i := 1; i <= 3; i++ {
		message := &store.Message{
			Account: cfg.Account.Email, SourceFolder: "INBOX", CurrentFolder: "INBOX",
			UIDValidity: 1, UID: uint32(i), MessageIDHash: strings.Repeat("b", 64),
			RawSHA256: strings.Repeat("a", 64), SizeBytes: 100,
			Verdict: "ham", Action: "keep", Status: "kept", FirstSeen: now, LastScanned: now,
		}
		if i < 3 {
			message.ArchivePath = archive
		}
		if i == 2 {
			// A skipped or superseded correction can retain differing intent;
			// this is history, not by itself an unresolved mailbox operation.
			message.Status, message.Feedback, message.FeedbackIntent = "superseded", "ham", "spam"
		}
		if _, err := db.UpsertMessage(ctx, message); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	run, err := db.BeginRun(ctx, "run", false)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	run.Errors = 1
	if err := db.FinishRun(ctx, run, errors.New("historical completed fixture failure")); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(root, "snapshot.db")
	if err := SnapshotDatabase(ctx, source, snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot, cfg
}

func readinessExec(t *testing.T, path, statement string, args ...any) {
	t.Helper()
	uri, err := sqliteURI(path, "rw")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(statement, args...); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func readinessFileHash(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func TestInspectSnapshotRealSchemaAggregatesArchivesWithoutChangingSource(t *testing.T) {
	path, cfg := readinessFixture(t)
	before := readinessFileHash(t, path)
	info, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.DatabaseSHA256 != before || info.DatabaseBytes != fileInfo.Size() {
		t.Fatalf("database identity differs: %+v", info)
	}
	if info.MailboxFingerprint != cfg.MailboxFingerprint() || info.AuthorizationFingerprint != cfg.AuthorizationFingerprint() {
		t.Fatal("configuration fingerprints not retained")
	}
	if info.Messages != 3 || info.ArchiveReferences != 2 || len(info.Archives) != 1 {
		t.Fatalf("inventory counts: %+v", info)
	}
	archive := info.Archives[0]
	if archive.Path != filepath.Join(cfg.Runtime.DataDir, "archive", "2026", "10", "one.age") || archive.RawSHA256 != strings.Repeat("a", 64) || archive.SizeBytes != 100 || archive.References != 2 {
		t.Fatalf("archive aggregation differs: %+v", archive)
	}
	if info.SpamRevisionHighWater != 261 || info.HamRevisionHighWater != 161 {
		t.Fatalf("model revisions: %+v", info)
	}
	if info.TotalRows < info.Messages+1 {
		t.Fatalf("row budget omitted history/settings: %+v", info)
	}
	if after := readinessFileHash(t, path); after != before {
		t.Fatal("inspection changed source database")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			t.Fatalf("inspection left source sidecar %q: %v", suffix, err)
		}
	}
}

func TestInspectSnapshotRejectsUnresolvedStatusesAndUnknownState(t *testing.T) {
	for _, status := range []string{"pending_move", "pending_learn", "pending_restore", "move_ambiguous", "blocked", "error", "future_unknown_status"} {
		t.Run("message-"+status, func(t *testing.T) {
			path, cfg := readinessFixture(t)
			readinessExec(t, path, "UPDATE messages SET status=? WHERE id=1", status)
			if _, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits()); err == nil {
				t.Fatalf("accepted message status %q", status)
			}
		})
	}
	for name, statement := range map[string]string{
		"unfinished-run":       "UPDATE runs SET status='running',finished_at=NULL",
		"unknown-run-status":   "UPDATE runs SET status='future-status'",
		"running-with-finish":  "UPDATE runs SET status='running'",
		"missing-finish":       "UPDATE runs SET finished_at=NULL",
		"empty-finish":         "UPDATE runs SET finished_at=''",
		"malformed-finish":     "UPDATE runs SET finished_at='not-a-completion-time'",
		"malformed-start":      "UPDATE runs SET started_at='not-a-start-time'",
		"checkpoint-required":  "INSERT INTO settings(key,value) VALUES('model_checkpoint_required','1')",
		"rollback-unresolved":  "INSERT INTO settings(key,value) VALUES('bayes_rollback_at','2026-10-30T18:00:00Z')",
		"stale-reconciliation": "INSERT INTO reconciliations(message_id,source_cursor,updated_at) VALUES(1,12,'2026-10-30T18:00:00Z')",
	} {
		t.Run(name, func(t *testing.T) {
			path, cfg := readinessFixture(t)
			readinessExec(t, path, statement)
			before := readinessFileHash(t, path)
			if _, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits()); err == nil {
				t.Fatalf("accepted unresolved state %s", name)
			}
			if after := readinessFileHash(t, path); after != before {
				t.Fatalf("inspection changed unresolved state %s", name)
			}
		})
	}
}

func TestInspectSnapshotAcceptsSupportedFinalStatuses(t *testing.T) {
	for _, status := range []string{"kept", "observed", "quarantined", "rescued", "review", "superseded", "restored", "purged"} {
		t.Run(status, func(t *testing.T) {
			path, cfg := readinessFixture(t)
			readinessExec(t, path, "UPDATE messages SET status=? WHERE id=1", status)
			if _, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits()); err != nil {
				t.Fatalf("rejected supported final status %s: %v", status, err)
			}
		})
	}
}

func TestInspectSnapshotPreservesHistoricalRunStatusMismatches(t *testing.T) {
	path, cfg := readinessFixture(t)
	readinessExec(t, path, "UPDATE runs SET status='ok',errors=3")
	readinessExec(t, path, `INSERT INTO runs(started_at,finished_at,command,dry_run,status,errors)
		VALUES('2026-10-30T19:00:00Z','2026-10-30T19:01:00Z','run',0,'ok',0)`)
	before := readinessFileHash(t, path)
	info, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if info.HistoricalRunStatusMismatches != 1 || info.LatestActualRunStatus != "ok" || info.LatestActualRunErrors != 0 {
		t.Fatalf("historical/current run diagnostics differ: %+v", info)
	}
	if readinessFileHash(t, path) != before {
		t.Fatal("inspection rewrote historical run evidence")
	}
}

func TestInspectSnapshotLatestActualRunCannotBeMasked(t *testing.T) {
	for _, later := range []string{"none", "dry-run", "purge"} {
		t.Run(later, func(t *testing.T) {
			path, cfg := readinessFixture(t)
			readinessExec(t, path, "UPDATE runs SET status='ok',errors=1")
			switch later {
			case "dry-run":
				readinessExec(t, path, `INSERT INTO runs(started_at,finished_at,command,dry_run,status,errors)
					VALUES('2026-10-30T19:02:00Z','2026-10-30T19:03:00Z','run',1,'ok',0)`)
			case "purge":
				readinessExec(t, path, `INSERT INTO runs(started_at,finished_at,command,dry_run,status,errors)
					VALUES('2026-10-30T19:02:00Z','2026-10-30T19:03:00Z','purge',0,'ok',0)`)
			}
			before := readinessFileHash(t, path)
			if _, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits()); err == nil {
				t.Fatal("accepted contradictory latest actual filtering run")
			}
			if readinessFileHash(t, path) != before {
				t.Fatal("rejection changed historical run evidence")
			}
		})
	}
}

func TestInspectSnapshotRejectsBlobCommandThatCouldHideANewerActualRun(t *testing.T) {
	path, cfg := readinessFixture(t)
	readinessExec(t, path, "UPDATE runs SET status='ok',errors=0")
	readinessExec(t, path, `INSERT INTO runs(started_at,finished_at,command,dry_run,status,errors)
		VALUES('2026-10-30T19:02:00Z','2026-10-30T19:03:00Z',CAST('run' AS BLOB),0,'ok',1)`)
	before := readinessFileHash(t, path)
	if _, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits()); err == nil {
		t.Fatal("BLOB command hid a newer contradictory filtering run behind old success")
	}
	if readinessFileHash(t, path) != before {
		t.Fatal("BLOB command rejection rewrote source history")
	}
}

func TestInspectSnapshotReportsCoherentFailedGenerationWithoutAuthorizingIt(t *testing.T) {
	for _, count := range []int{0, 2} {
		path, cfg := readinessFixture(t)
		readinessExec(t, path, "UPDATE runs SET status='error',errors=?", count)
		before := readinessFileHash(t, path)
		info, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits())
		if err != nil {
			t.Fatal(err)
		}
		if info.LatestActualRunStatus != "error" || info.LatestActualRunErrors != int64(count) || info.HistoricalRunStatusMismatches != 0 {
			t.Fatalf("failed generation was hidden or rewritten: %+v", info)
		}
		if readinessFileHash(t, path) != before {
			t.Fatal("inspection rewrote a completed failed generation")
		}
	}
}

func TestInspectSnapshotDoesNotInventActualRunForAnEmptyHistory(t *testing.T) {
	path, cfg := readinessFixture(t)
	readinessExec(t, path, "DELETE FROM runs")
	info, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if info.LatestActualRunStatus != "" || info.LatestActualRunErrors != 0 {
		t.Fatalf("invented an actual filtering run: %+v", info)
	}
}

func TestInspectSnapshotBindsExactMailboxFolderAndModelIdentity(t *testing.T) {
	for name, statement := range map[string]string{
		"foreign-account":        "UPDATE messages SET account='foreign@example.invalid' WHERE id=1",
		"foreign-mailbox":        "UPDATE settings SET value='wrong' WHERE key='mailbox_fingerprint'",
		"foreign-folders":        "UPDATE settings SET value='wrong' WHERE key='authorization_fingerprint'",
		"missing-mailbox":        "DELETE FROM settings WHERE key='mailbox_fingerprint'",
		"missing-authorization":  "DELETE FROM settings WHERE key='authorization_fingerprint'",
		"missing-spam-watermark": "DELETE FROM settings WHERE key='bayes_spam_revision_highwater'",
		"missing-ham-watermark":  "DELETE FROM settings WHERE key='bayes_ham_revision_highwater'",
		"negative-watermark":     "UPDATE settings SET value='-1' WHERE key='bayes_spam_revision_highwater'",
		"malformed-watermark":    "UPDATE settings SET value='261junk' WHERE key='bayes_spam_revision_highwater'",
		"whitespace-watermark":   "UPDATE settings SET value=' 261' WHERE key='bayes_spam_revision_highwater'",
		"overflow-watermark":     "UPDATE settings SET value='18446744073709551616' WHERE key='bayes_spam_revision_highwater'",
		"unknown-setting":        "INSERT INTO settings(key,value) VALUES('future_unreviewed_setting','value')",
		"blob-setting-value":     "UPDATE settings SET value=CAST(value AS BLOB) WHERE key='bayes_spam_revision_highwater'",
		"blob-setting-key":       "UPDATE settings SET key=CAST(key AS BLOB) WHERE key='bayes_spam_revision_highwater'",
	} {
		t.Run(name, func(t *testing.T) {
			path, cfg := readinessFixture(t)
			readinessExec(t, path, statement)
			if _, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits()); err == nil {
				t.Fatalf("accepted invalid identity %s", name)
			}
		})
	}
	t.Run("changed-config-folders", func(t *testing.T) {
		path, cfg := readinessFixture(t)
		cfg.Folders.ServerSpam = "DifferentSpam"
		if _, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits()); err == nil {
			t.Fatal("accepted changed configured folders")
		}
	})
}

func TestInspectSnapshotAcceptsZeroAndFullWidthModelRevisions(t *testing.T) {
	path, cfg := readinessFixture(t)
	readinessExec(t, path, "UPDATE settings SET value='0' WHERE key='bayes_spam_revision_highwater'")
	readinessExec(t, path, "UPDATE settings SET value='18446744073709551615' WHERE key='bayes_ham_revision_highwater'")
	info, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if info.SpamRevisionHighWater != 0 || info.HamRevisionHighWater != ^uint64(0) {
		t.Fatalf("valid unsigned model revisions changed: %+v", info)
	}
}

func TestInspectSnapshotRejectsUnsupportedSchema(t *testing.T) {
	for name, statement := range map[string]string{
		"extra-table":   "CREATE TABLE future_data (id INTEGER)",
		"extra-column":  "ALTER TABLE messages ADD COLUMN future_payload TEXT",
		"view":          "CREATE VIEW unexpected_view AS SELECT id FROM messages",
		"trigger":       "CREATE TRIGGER unexpected_trigger AFTER INSERT ON settings BEGIN SELECT 1; END",
		"extra-index":   "CREATE INDEX unexpected_index ON messages(raw_sha256)",
		"missing-table": "DROP TABLE events",
		"missing-index": "DROP INDEX idx_messages_location",
	} {
		t.Run(name, func(t *testing.T) {
			path, cfg := readinessFixture(t)
			readinessExec(t, path, statement)
			if _, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits()); err == nil {
				t.Fatalf("accepted unsupported schema %s", name)
			}
		})
	}
	for name, replacement := range map[string][2]string{
		"changed-default":  {"archive_path TEXT NOT NULL DEFAULT ''", "archive_path TEXT NOT NULL DEFAULT 'changed'"},
		"space-default":    {"archive_path TEXT NOT NULL DEFAULT ''", "archive_path TEXT NOT NULL DEFAULT ' '"},
		"custom-check":     {"score REAL NOT NULL", "score REAL NOT NULL CHECK(score>=0)"},
		"custom-collation": {"account TEXT NOT NULL", "account TEXT NOT NULL COLLATE NOCASE"},
	} {
		t.Run(name, func(t *testing.T) {
			path, cfg := readinessFixture(t)
			uri, err := sqliteURI(path, "rw")
			if err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", uri)
			if err != nil {
				t.Fatal(err)
			}
			var original string
			if err := db.QueryRow("SELECT sql FROM sqlite_schema WHERE name='messages'").Scan(&original); err != nil {
				db.Close()
				t.Fatal(err)
			}
			changed := strings.Replace(original, replacement[0], replacement[1], 1)
			if changed == original {
				db.Close()
				t.Fatal("fixture DDL no longer contains expected clause")
			}
			if _, err := db.Exec("PRAGMA writable_schema=ON"); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if _, err := db.Exec("UPDATE sqlite_schema SET sql=? WHERE name='messages'", changed); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if _, err := db.Exec("PRAGMA writable_schema=OFF"); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits()); err == nil {
				t.Fatalf("accepted unsupported DDL clause %s", name)
			}
		})
	}
}

func TestInspectSnapshotRejectsInvalidOrConflictingArchiveReferences(t *testing.T) {
	for name, statement := range map[string]string{
		"relative-path":       "UPDATE messages SET archive_path='relative/one.age' WHERE id=1",
		"unclean-path":        "UPDATE messages SET archive_path=archive_path||'/../other.age' WHERE id=1",
		"outside-root":        "UPDATE messages SET archive_path='/unrelated-private-archive/one.age' WHERE id=1",
		"path-control":        "UPDATE messages SET archive_path=archive_path||char(10) WHERE id=1",
		"empty-hash":          "UPDATE messages SET raw_sha256='' WHERE id=1",
		"invalid-hash":        "UPDATE messages SET raw_sha256='not-sha256' WHERE id=1",
		"nul-hash-suffix":     "UPDATE messages SET raw_sha256=raw_sha256||char(0)||'hidden' WHERE id=1",
		"nul-hash-unarchived": "UPDATE messages SET raw_sha256=raw_sha256||char(0)||'hidden' WHERE id=3",
		"negative-size":       "UPDATE messages SET size_bytes=-1 WHERE id=1",
		"hash-conflict":       "UPDATE messages SET raw_sha256='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' WHERE id=2",
		"size-conflict":       "UPDATE messages SET size_bytes=101 WHERE id=2",
	} {
		t.Run(name, func(t *testing.T) {
			path, cfg := readinessFixture(t)
			readinessExec(t, path, statement)
			if _, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits()); err == nil {
				t.Fatalf("accepted invalid archive reference %s", name)
			}
		})
	}
	t.Run("archive-root-prefix-collision", func(t *testing.T) {
		path, cfg := readinessFixture(t)
		readinessExec(t, path, "UPDATE messages SET archive_path=? WHERE id=1", cfg.Runtime.ArchiveDir+"-other/one.age")
		if _, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits()); err == nil {
			t.Fatal("accepted archive outside root with matching path prefix")
		}
	})
}

func TestInspectSnapshotEnforcesInventoryLimits(t *testing.T) {
	for name, mutate := range map[string]func(*ReadinessLimits){
		"database-bytes":       func(l *ReadinessLimits) { l.MaxDatabaseBytes = 1 },
		"total-rows":           func(l *ReadinessLimits) { l.MaxRows = 1 },
		"archive-references":   func(l *ReadinessLimits) { l.MaxArchiveReferences = 1 },
		"inventory-bytes":      func(l *ReadinessLimits) { l.MaxInventoryBytes = 1 },
		"path-bytes":           func(l *ReadinessLimits) { l.MaxPathBytes = 1 },
		"zero-database-bound":  func(l *ReadinessLimits) { l.MaxDatabaseBytes = 0 },
		"zero-row-bound":       func(l *ReadinessLimits) { l.MaxRows = 0 },
		"zero-reference-bound": func(l *ReadinessLimits) { l.MaxArchiveReferences = 0 },
		"zero-archive-bound":   func(l *ReadinessLimits) { l.MaxArchives = 0 },
		"zero-inventory-bound": func(l *ReadinessLimits) { l.MaxInventoryBytes = 0 },
		"zero-path-bound":      func(l *ReadinessLimits) { l.MaxPathBytes = 0 },
		"negative-bound":       func(l *ReadinessLimits) { l.MaxRows = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			path, cfg := readinessFixture(t)
			limits := readinessTestLimits()
			mutate(&limits)
			if _, err := InspectSnapshot(context.Background(), path, cfg, limits); err == nil {
				t.Fatalf("accepted exceeded/invalid bound %s", name)
			}
		})
	}
	t.Run("unique-archives", func(t *testing.T) {
		path, cfg := readinessFixture(t)
		readinessExec(t, path, "UPDATE messages SET archive_path=archive_path||'.other' WHERE id=2")
		limits := readinessTestLimits()
		limits.MaxArchives = 1
		if _, err := InspectSnapshot(context.Background(), path, cfg, limits); err == nil {
			t.Fatal("accepted more unique archives than allowed")
		}
	})
	t.Run("exact-boundaries", func(t *testing.T) {
		path, cfg := readinessFixture(t)
		info, err := InspectSnapshot(context.Background(), path, cfg, readinessTestLimits())
		if err != nil {
			t.Fatal(err)
		}
		limits := readinessTestLimits()
		limits.MaxDatabaseBytes, limits.MaxRows = info.DatabaseBytes, info.TotalRows
		limits.MaxArchiveReferences, limits.MaxArchives = info.ArchiveReferences, int64(len(info.Archives))
		limits.MaxInventoryBytes = int64(len(info.Archives[0].Path) + len(info.Archives[0].RawSHA256))
		limits.MaxPathBytes = len(info.Archives[0].Path)
		if _, err := InspectSnapshot(context.Background(), path, cfg, limits); err != nil {
			t.Fatalf("rejected exact resource boundaries: %v", err)
		}
	})
}

func TestInspectSnapshotRejectsUnsafeSourceAndSidecars(t *testing.T) {
	for _, kind := range []string{"relative", "unclean", "file-symlink", "parent-symlink", "hardlink", "public-file", "public-parent", "wal", "shm", "journal", "wal-header", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			path, cfg := readinessFixture(t)
			source := path
			switch kind {
			case "relative":
				var err error
				cwd, err := os.Getwd()
				if err != nil {
					t.Fatal(err)
				}
				source, err = filepath.Rel(cwd, path)
				if err != nil {
					t.Fatal(err)
				}
			case "unclean":
				source = filepath.Dir(path) + "/./" + filepath.Base(path)
			case "file-symlink":
				source = filepath.Join(filepath.Dir(path), "link.db")
				if err := os.Symlink(path, source); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				link := filepath.Join(filepath.Dir(path), "linked-parent")
				if err := os.Symlink(filepath.Dir(path), link); err != nil {
					t.Fatal(err)
				}
				source = filepath.Join(link, filepath.Base(path))
			case "hardlink":
				if err := os.Link(path, filepath.Join(filepath.Dir(path), "alias.db")); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "public-parent":
				if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
			case "wal", "shm", "journal":
				if err := os.WriteFile(path+"-"+kind, []byte("preserve sidecar"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wal-header":
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data[18], data[19] = 2, 2
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "truncated":
				if err := os.WriteFile(path, []byte("SQLite format 3\x00"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := readinessFileHash(t, path)
			if _, err := InspectSnapshot(context.Background(), source, cfg, readinessTestLimits()); err == nil {
				t.Fatalf("accepted unsafe source %s", kind)
			}
			if after := readinessFileHash(t, path); after != before {
				t.Fatal("rejected inspection changed database bytes")
			}
			if kind == "wal" || kind == "shm" || kind == "journal" {
				if data, err := os.ReadFile(path + "-" + kind); err != nil || string(data) != "preserve sidecar" {
					t.Fatal("rejected inspection changed existing sidecar")
				}
			}
		})
	}
	t.Run("context-cancelled", func(t *testing.T) {
		path, cfg := readinessFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := InspectSnapshot(ctx, path, cfg, readinessTestLimits()); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation was not preserved: %v", err)
		}
	})
}
