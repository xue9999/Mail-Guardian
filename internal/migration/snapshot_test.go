package migration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotIncludesCommittedWALWithoutReplacingDestination(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "source ?#.db")
	sourceURI, err := sqliteURI(source, "rwc")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sourceURI)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT); INSERT INTO messages VALUES (1, 'committed in WAL')`); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(source + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("expected a nonempty WAL, got %v %v", info, err)
	}
	dest := filepath.Join(dir, "snapshot ?#.db")
	if err := SnapshotDatabase(context.Background(), source, dest); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(dest + suffix); !os.IsNotExist(err) {
			t.Fatalf("snapshot requires an unexpected SQLite sidecar %s: %v", suffix, err)
		}
	}
	copyURI, err := sqliteURI(dest, "ro")
	if err != nil {
		t.Fatal(err)
	}
	copyDB, err := sql.Open("sqlite", copyURI)
	if err != nil {
		t.Fatal(err)
	}
	defer copyDB.Close()
	var body string
	if err := copyDB.QueryRow(`SELECT body FROM messages WHERE id=1`).Scan(&body); err != nil || body != "committed in WAL" {
		t.Fatalf("backup did not preserve committed WAL content: %q %v", body, err)
	}
	before, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := SnapshotDatabase(context.Background(), source, dest); err == nil {
		t.Fatal("existing destination was accepted")
	}
	after, err := os.ReadFile(dest)
	if err != nil || string(before) != string(after) {
		t.Fatal("existing destination was modified")
	}
	info, err := os.Stat(dest)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot permissions: %v %v", info, err)
	}
}

func TestSnapshotFailsClosedOnCorruptionCancellationAndUnsafeDestination(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "broken.db")
	if err := os.WriteFile(source, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "snapshot.db")
	if err := SnapshotDatabase(context.Background(), source, dest); err == nil {
		t.Fatal("corrupt database accepted")
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		t.Fatalf("failed output left behind: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := SnapshotDatabase(ctx, source, dest); err == nil {
		t.Fatal("canceled snapshot accepted")
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		t.Fatalf("canceled output left behind: %v", err)
	}
	unsafe := filepath.Join(dir, "shared")
	if err := os.Mkdir(unsafe, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SnapshotDatabase(context.Background(), source, filepath.Join(unsafe, "snapshot.db")); err == nil {
		t.Fatal("shared destination accepted")
	}
	dirLink := filepath.Join(dir, "linked-directory")
	if err := os.Symlink(dir, dirLink); err != nil {
		t.Fatal(err)
	}
	if err := SnapshotDatabase(context.Background(), source, filepath.Join(dirLink, "snapshot.db")); err == nil {
		t.Fatal("symlink destination directory accepted")
	}
	link := filepath.Join(dir, "linked.db")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if err := SnapshotDatabase(context.Background(), link, dest); err == nil {
		t.Fatal("symlink source accepted")
	}
	if err := os.WriteFile(dest+"-wal", []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SnapshotDatabase(context.Background(), source, dest); err == nil {
		t.Fatal("preexisting SQLite sidecar accepted")
	}
	if content, err := os.ReadFile(dest + "-wal"); err != nil || string(content) != "existing" {
		t.Fatal("preexisting sidecar changed")
	}
}

func boundedSnapshotFixture(t *testing.T, pageSize int64) (string, *sql.DB, int64) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "source.db")
	uri, err := sqliteURI(source, "rwc")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA page_size=%d; PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE content(id INTEGER PRIMARY KEY, body BLOB); INSERT INTO content(body) VALUES(zeroblob(%d))`, pageSize, 20*pageSize)); err != nil {
		t.Fatal(err)
	}
	var pages int64
	if err := db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	return source, db, pages * pageSize
}

func TestSnapshotBoundedHonorsPageSizesAndExactImageLimit(t *testing.T) {
	for _, pageSize := range []int64{1024, 4096, 65536} {
		t.Run(fmt.Sprint(pageSize), func(t *testing.T) {
			source, _, bytes := boundedSnapshotFixture(t, pageSize)
			for _, extra := range []int64{0, pageSize - 1} {
				dest := filepath.Join(filepath.Dir(source), fmt.Sprintf("bounded-%d.db", extra))
				if err := SnapshotDatabaseBounded(context.Background(), source, dest, bytes+extra); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(dest)
				if err != nil || info.Size() != bytes || info.Size() > bytes+extra {
					t.Fatalf("main image bound: size=%v expected=%d err=%v", info, bytes, err)
				}
				uri, err := sqliteURI(dest, "ro")
				if err != nil {
					t.Fatal(err)
				}
				db, err := sql.Open("sqlite", uri)
				if err != nil {
					t.Fatal(err)
				}
				var actualSize, rows int64
				if err := db.QueryRow("PRAGMA page_size").Scan(&actualSize); err != nil || actualSize != pageSize {
					t.Fatalf("page size changed: %d %v", actualSize, err)
				}
				if err := db.QueryRow("SELECT count(*) FROM content").Scan(&rows); err != nil || rows != 1 {
					t.Fatalf("WAL record absent: %d %v", rows, err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			for i, limit := range []int64{-1, 0, 1, bytes - 1} {
				dest := filepath.Join(filepath.Dir(source), fmt.Sprintf("over-%d.db", i))
				if err := SnapshotDatabaseBounded(context.Background(), source, dest, limit); err == nil {
					t.Fatalf("accepted insufficient limit %d for %d-byte image", limit, bytes)
				}
				assertSnapshotAbsent(t, dest)
			}
		})
	}
}

func TestSnapshotPinnedReadViewExcludesLaterWALGrowth(t *testing.T) {
	source, writer, bytes := boundedSnapshotFixture(t, 4096)
	uri, err := sqliteURI(source, "ro")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := sql.Open("sqlite", uri)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	conn, err := reader.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	view, pageSize, pages, maxPages, err := beginSnapshotView(context.Background(), conn, bytes)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Rollback()
	// This commit exceeds the byte cap in the newer source view. The copy must
	// remain on the read transaction that supplied the earlier bounds.
	if _, err := writer.Exec("INSERT INTO content(body) VALUES(zeroblob(1048576))"); err != nil {
		t.Fatal(err)
	}
	var currentPages int64
	if err := writer.QueryRow("PRAGMA page_count").Scan(&currentPages); err != nil || currentPages <= maxPages {
		t.Fatalf("fixture did not grow after pin: %d %d %v", currentPages, maxPages, err)
	}
	dest := filepath.Join(filepath.Dir(source), "pinned.db")
	if err := os.WriteFile(dest, nil, 0600); err != nil {
		t.Fatal(err)
	}
	dstURI, err := boundedSnapshotURI(dest, pageSize, maxPages)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Raw(func(raw any) error {
		return copySnapshotPages(context.Background(), raw.(sqliteBackuper), dstURI, pages, maxPages)
	}); err != nil {
		t.Fatal(err)
	}
	copyURI, err := sqliteURI(dest, "ro")
	if err != nil {
		t.Fatal(err)
	}
	copied, err := sql.Open("sqlite", copyURI)
	if err != nil {
		t.Fatal(err)
	}
	defer copied.Close()
	var rows int
	if err := copied.QueryRow("SELECT count(*) FROM content").Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("snapshot drifted onto later WAL view: %d %v", rows, err)
	}
	if info, err := os.Stat(dest); err != nil || info.Size() != bytes {
		t.Fatalf("pinned output escaped bound: %v %v", info, err)
	}
}

func TestSnapshotDestinationSQLiteCapStopsAnOverlargeCopy(t *testing.T) {
	for _, pageSize := range []int64{1024, 65536} {
		t.Run(fmt.Sprint(pageSize), func(t *testing.T) {
			source, _, bytes := boundedSnapshotFixture(t, pageSize)
			uri, err := sqliteURI(source, "ro")
			if err != nil {
				t.Fatal(err)
			}
			reader, err := sql.Open("sqlite", uri)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			conn, err := reader.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			view, _, pages, _, err := beginSnapshotView(context.Background(), conn, bytes)
			if err != nil {
				t.Fatal(err)
			}
			defer view.Rollback()
			dest := filepath.Join(filepath.Dir(source), "sqlite-full.db")
			if err := os.WriteFile(dest, nil, 0600); err != nil {
				t.Fatal(err)
			}
			dstURI, err := boundedSnapshotURI(dest, pageSize, 2)
			if err != nil {
				t.Fatal(err)
			}
			err = conn.Raw(func(raw any) error {
				return copySnapshotPages(context.Background(), raw.(sqliteBackuper), dstURI, pages, 2)
			})
			if err == nil {
				t.Fatal("SQLite destination cap accepted overlarge source")
			}
			if info, err := os.Stat(dest); err != nil || info.Size() > 2*pageSize {
				t.Fatalf("SQLite image cap ineffective: %v %v", info, err)
			}
		})
	}
}

func TestSnapshotBoundedRejectsUnsafeSourcesAndPreservesExistingArtifacts(t *testing.T) {
	source, _, bytes := boundedSnapshotFixture(t, 4096)
	dir := filepath.Dir(source)
	dest := filepath.Join(dir, "bounded.db")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := SnapshotDatabaseBounded(ctx, source, dest, bytes); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was not preserved: %v", err)
	}
	assertSnapshotAbsent(t, dest)
	linkDir := filepath.Join(dir, "source-parent-link")
	if err := os.Symlink(dir, linkDir); err != nil {
		t.Fatal(err)
	}
	if err := SnapshotDatabaseBounded(context.Background(), filepath.Join(linkDir, "source.db"), dest, bytes); err == nil {
		t.Fatal("source symlink parent accepted")
	}
	assertSnapshotAbsent(t, dest)
	// Keep existing destination sidecar data even when no output DB exists.
	if err := os.WriteFile(dest+"-journal", []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SnapshotDatabaseBounded(context.Background(), source, dest, bytes); err == nil {
		t.Fatal("existing output sidecar accepted")
	}
	if data, err := os.ReadFile(dest + "-journal"); err != nil || string(data) != "keep" {
		t.Fatal("existing sidecar overwritten or removed")
	}
	// A source's nonexistent journal may not redirect SQLite through a link.
	if err := os.Symlink(dest+"-journal", source+"-journal"); err != nil {
		t.Fatal(err)
	}
	if err := SnapshotDatabaseBounded(context.Background(), source, filepath.Join(dir, "unsafe-source.db"), bytes); err == nil {
		t.Fatal("source sidecar symlink accepted")
	}
}

func assertSnapshotAbsent(t *testing.T, path string) {
	t.Helper()
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			t.Fatalf("failed output or sidecar remains (%s): %v", suffix, err)
		}
	}
}

func TestSnapshotEmptyDatabaseRemainsSupported(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "empty.db")
	if err := os.WriteFile(source, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := SnapshotDatabase(context.Background(), source, filepath.Join(dir, "empty-copy.db")); err != nil {
		t.Fatal(err)
	}
}

// cancelOnSecondSnapshotCheck provides a deterministic interruption between
// partial backup steps without depending on disk speed or scheduler timing.
type cancelOnSecondSnapshotCheck struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *cancelOnSecondSnapshotCheck) Err() error {
	c.checks++
	if c.checks == 2 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestSnapshotCancellationDuringPartialCopyDoesNotCommitOutput(t *testing.T) {
	source, writer, _ := boundedSnapshotFixture(t, 4096)
	if _, err := writer.Exec("INSERT INTO content(body) VALUES(zeroblob(1048576))"); err != nil {
		t.Fatal(err)
	}
	uri, err := sqliteURI(source, "ro")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := sql.Open("sqlite", uri)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	conn, err := reader.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	view, pageSize, pages, maxPages, err := beginSnapshotView(context.Background(), conn, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Rollback()
	if pages <= 64 {
		t.Fatal("fixture must require a partial step")
	}
	dest := filepath.Join(filepath.Dir(source), "interrupted.db")
	if err := os.WriteFile(dest, nil, 0600); err != nil {
		t.Fatal(err)
	}
	destURI, err := boundedSnapshotURI(dest, pageSize, maxPages)
	if err != nil {
		t.Fatal(err)
	}
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cancelOnSecondSnapshotCheck{Context: base, cancel: cancel}
	err = conn.Raw(func(raw any) error {
		return copySnapshotPages(ctx, raw.(sqliteBackuper), destURI, pages, maxPages)
	})
	if !errors.Is(err, context.Canceled) || ctx.checks != 2 {
		t.Fatalf("partial copy accepted or cancellation not preserved: checks=%d err=%v", ctx.checks, err)
	}
	// Finish rolls back the incomplete output and closes its destination
	// connection; a new writer can acquire the destination and create schema.
	db, err := sql.Open("sqlite", destURI)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var copiedTables int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_schema WHERE name='content'").Scan(&copiedTables); err != nil || copiedTables != 0 {
		t.Fatalf("interrupted copy left committed source schema: %d %v", copiedTables, err)
	}
	if _, err := db.Exec("PRAGMA locking_mode=EXCLUSIVE; CREATE TABLE reusable (id INTEGER)"); err != nil {
		t.Fatalf("interrupted backup left its destination locked: %v", err)
	}
}
