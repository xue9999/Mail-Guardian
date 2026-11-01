// Package migration contains offline building blocks for a future controlled
// handover. It does not fence a running owner or authorize mailbox operations.
package migration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"modernc.org/sqlite"
)

type sqliteBackuper interface {
	NewBackup(string) (*sqlite.Backup, error)
}

func sqliteURI(path, mode string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
	q := u.Query()
	q.Set("mode", mode)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// SnapshotDatabase creates a standalone, integrity-checked online SQLite backup
// without overwriting anything. It includes committed WAL content. The caller
// must fence all owners and hold Guardian's run lock across this operation AND
// the associated Redis and archive capture; this function cannot establish a
// cross-component or cross-host consistent checkpoint by itself.
//
// The output directory must be private and owned by the calling user; it is a
// staging directory, not a production database directory. A failed snapshot is
// removed. The source database must already exist and be a regular file.
func SnapshotDatabase(ctx context.Context, source, destination string) error {
	return SnapshotDatabaseBounded(ctx, source, destination, math.MaxInt64)
}

// SnapshotDatabaseBounded has the same offline consistency contract as
// SnapshotDatabase, and additionally bounds the completed main database image
// to maxBytes. It pins a source read transaction before inspecting its page
// size/count, and SQLite's destination max_page_count enforces the image bound
// while copying. Journal, WAL, SHM and temporary-file overhead is outside this
// bound: callers must independently reserve and limit total staging disk use.
//
// Cancellation is checked between SQLite backup steps. The driver's raw Step
// call cannot be interrupted by ctx; this is NOT a hard wall-clock deadline.
// A caller needing a hard deadline must isolate the operation in a controlled
// subprocess. The caller must exclude path replacement by the same owning user
// as well as cross-component writers; path/identity checks here do not establish
// an OS or mailbox ownership boundary.
func SnapshotDatabaseBounded(ctx context.Context, source, destination string, maxBytes int64) (retErr error) {
	if source == "" || destination == "" {
		return errors.New("source and destination are required")
	}
	if maxBytes <= 0 {
		return errors.New("snapshot byte limit must be positive")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("source database must be an existing regular file")
	}
	sourceParentPath := filepath.Dir(source)
	sourceParent, err := os.Lstat(sourceParentPath)
	if err != nil || !sourceParent.IsDir() || sourceParent.Mode()&os.ModeSymlink != 0 {
		return errors.New("source database parent must be a real directory")
	}
	if err := snapshotSourceSidecars(source); err != nil {
		return err
	}
	parentPath := filepath.Dir(destination)
	parent, err := os.Lstat(parentPath)
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		return errors.New("snapshot destination directory must be private")
	}
	owner, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() {
		return errors.New("snapshot destination directory must be owned by the caller")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(destination + suffix); !errors.Is(err, os.ErrNotExist) {
			return errors.New("snapshot destination has a preexisting SQLite sidecar or cannot be checked")
		}
	}
	file, err := os.OpenFile(destination, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	created, err := file.Stat()
	if err != nil {
		_ = file.Close()
		_ = os.Remove(destination)
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, file.Close())
		if retErr != nil {
			// Never remove an unrelated file that replaced our output.
			if current, err := os.Lstat(destination); err == nil && os.SameFile(created, current) {
				_ = os.Remove(destination)
				for _, suffix := range []string{"-wal", "-shm", "-journal"} {
					_ = os.Remove(destination + suffix)
				}
			}
		}
	}()
	srcURI, err := sqliteURI(source, "ro")
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", srcURI)
	if err != nil {
		return err
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	view, pageSize, pages, maxPages, err := beginSnapshotView(ctx, conn, maxBytes)
	if err != nil {
		return err
	}
	defer view.Rollback()
	if err := snapshotFileIdentity(source, info); err != nil {
		return errors.New("source database changed while opening its read view")
	}
	if err := snapshotFileIdentity(sourceParentPath, sourceParent); err != nil {
		return errors.New("source database parent changed while opening its read view")
	}
	if err := snapshotSourceSidecars(source); err != nil {
		return err
	}
	if err := snapshotFileIdentity(parentPath, parent); err != nil {
		return errors.New("snapshot destination directory changed")
	}
	dstURI, err := boundedSnapshotURI(destination, pageSize, maxPages)
	if err != nil {
		return err
	}
	err = conn.Raw(func(raw any) error {
		b, ok := raw.(sqliteBackuper)
		if !ok {
			return errors.New("SQLite driver does not support online backup")
		}
		return copySnapshotPages(ctx, b, dstURI, pages, maxPages)
	})
	if err != nil {
		return fmt.Errorf("SQLite backup: %w", err)
	}
	if err := snapshotFileIdentity(source, info); err != nil {
		return errors.New("source database path changed during backup")
	}
	if err := snapshotFileIdentity(sourceParentPath, sourceParent); err != nil {
		return errors.New("source database parent changed during backup")
	}
	if err := snapshotFileIdentity(parentPath, parent); err != nil {
		return errors.New("snapshot destination directory changed")
	}
	if err := snapshotFileIdentity(destination, created); err != nil {
		return errors.New("snapshot output changed during backup")
	}

	// The source may use WAL mode. Make the private copy self-contained before
	// packaging it: an artifact consisting only of the main database must not
	// silently depend on a separate WAL or SHM sidecar.
	checkURI, err := boundedSnapshotURI(destination, pageSize, maxPages)
	if err != nil {
		return err
	}
	check, err := sql.Open("sqlite", checkURI)
	if err != nil {
		return err
	}
	var journalMode string
	if err := check.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&journalMode); err != nil || journalMode != "delete" {
		check.Close()
		return errors.Join(err, errors.New("snapshot could not be made independent of SQLite WAL"))
	}
	rows, err := check.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		check.Close()
		return err
	}
	count := 0
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			rows.Close()
			check.Close()
			return err
		}
		count++
		if result != "ok" {
			rows.Close()
			check.Close()
			return errors.New("snapshot integrity check failed")
		}
	}
	err = errors.Join(rows.Err(), rows.Close(), check.Close())
	if err != nil || count != 1 {
		return errors.Join(err, errors.New("snapshot integrity check incomplete"))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := snapshotFileIdentity(destination, created); err != nil {
		return errors.New("snapshot output changed during verification")
	}
	finalInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if finalInfo.Size() > maxBytes {
		return errors.New("snapshot exceeds its byte limit")
	}
	if err := file.Sync(); err != nil {
		return err
	}

	dir, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

// beginSnapshotView pins the connection's SQLite read view before deriving its
// bounds. A separate writer may subsequently commit WAL changes, but those
// changes cannot restart this backup onto a newer view.
func beginSnapshotView(ctx context.Context, conn *sql.Conn, maxBytes int64) (_ *sql.Tx, pageSize, pages, maxPages int64, retErr error) {
	if maxBytes <= 0 {
		return nil, 0, 0, 0, errors.New("snapshot byte limit must be positive")
	}
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, 0, 0, err
	}
	defer func() {
		if retErr != nil {
			_ = tx.Rollback()
		}
	}()
	// BEGIN is deferred; reading sqlite_schema establishes the snapshot before
	// either metadata query. Do not bind resource checks to an earlier view.
	var schemaEntries int64
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema").Scan(&schemaEntries); err != nil {
		return nil, 0, 0, 0, err
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return nil, 0, 0, 0, err
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return nil, 0, 0, 0, err
	}
	// Valid SQLite page sizes are powers of two from 512 through 65536.
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 || pages < 0 {
		return nil, 0, 0, 0, errors.New("invalid SQLite page metadata")
	}
	// Divide rather than multiply untrusted metadata to avoid overflow.
	maxPages = maxBytes / pageSize
	const sqliteMaxPages int64 = 4294967294
	if maxPages > sqliteMaxPages {
		maxPages = sqliteMaxPages
	}
	if maxPages == 0 || pages > maxPages {
		return nil, 0, 0, 0, errors.New("source database exceeds snapshot byte limit")
	}
	return tx, pageSize, pages, maxPages, nil
}

func boundedSnapshotURI(destination string, pageSize, maxPages int64) (string, error) {
	uri, err := sqliteURI(destination, "rw")
	if err != nil {
		return "", err
	}
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Add("_pragma", "page_size("+strconv.FormatInt(pageSize, 10)+")")
	q.Add("_pragma", "max_page_count("+strconv.FormatInt(maxPages, 10)+")")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func copySnapshotPages(ctx context.Context, source sqliteBackuper, destinationURI string, expectedPages, maxPages int64) (retErr error) {
	backup, err := source.NewBackup(destinationURI)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, backup.Finish()) }()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		more, err := backup.Step(64)
		if err != nil {
			return err
		}
		pages := int64(backup.PageCount())
		if pages != expectedPages || pages > maxPages {
			return errors.New("SQLite backup source view or page bound changed")
		}
		if !more {
			// Finish can return nil for a partial backup, so only a successful
			// Step reporting DONE is accepted as a completed copy.
			return ctx.Err()
		}
	}
}

func snapshotSourceSidecars(source string) error {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		info, err := os.Lstat(source + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("source database has an unsafe SQLite sidecar")
		}
	}
	return nil
}

func snapshotFileIdentity(path string, expected os.FileInfo) error {
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(expected, current) || current.Mode()&os.ModeSymlink != 0 {
		return errors.New("snapshot path identity changed")
	}
	return nil
}
