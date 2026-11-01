// Package migration contains offline-only migration building blocks. It does
// not fence a running owner or make a checkpoint of the Redis model.
package migration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"golang.org/x/sys/unix"
)

// RelocateSnapshot creates a new, isolated SQLite snapshot without modifying
// sourceDB. Every referenced archive is decrypted from stagedArchiveRoot using
// the original identity and checked against its stored raw SHA-256 before any
// reference is rewritten. targetArchiveRoot is the intended absolute path on
// the destination, not necessarily a path on the machine running this code.
//
// The caller MUST fence all writers, produce a consistent model checkpoint and
// stage an immutable private archive tree before invoking this helper. This
// function does not establish cross-host fencing, transfer a Redis model, check
// deployment authorization, or provision credentials. It is not an importer.
// outputDB must not exist and must be in an administrator-controlled private
// staging directory. On failure the newly created snapshot is removed.
func RelocateSnapshot(ctx context.Context, sourceDB, outputDB, oldArchiveRoot, stagedArchiveRoot, targetArchiveRoot string, identity *age.X25519Identity) (count int, retErr error) {
	if identity == nil {
		return 0, errors.New("archive identity is required")
	}
	for _, path := range []string{sourceDB, outputDB, oldArchiveRoot, stagedArchiveRoot, targetArchiveRoot} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
			return 0, errors.New("all paths must be clean absolute non-root paths")
		}
	}
	info, err := os.Lstat(sourceDB)
	if err != nil || !info.Mode().IsRegular() {
		return 0, errors.New("source database must be a regular file")
	}
	rootInfo, err := os.Lstat(stagedArchiveRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("staged archive root must be a real directory")
	}
	rootFD, err := unix.Open(stagedArchiveRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, errors.New("cannot open staged archive root")
	}
	defer unix.Close(rootFD)
	if err := privateDirectory(rootFD); err != nil {
		return 0, errors.New("staged archive root must be private and owned by the current user")
	}
	outputDirFD, err := unix.Open(filepath.Dir(outputDB), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, errors.New("cannot open output directory")
	}
	defer unix.Close(outputDirFD)
	if err := privateDirectory(outputDirFD); err != nil {
		return 0, errors.New("output directory must be private and owned by the current user")
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if _, err := os.Lstat(outputDB + suffix); err == nil {
			return 0, errors.New("output database sidecar already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
	}
	if err := SnapshotDatabase(ctx, sourceDB, outputDB); err != nil {
		return 0, fmt.Errorf("snapshot database: %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = os.Remove(outputDB)
			_ = os.Remove(outputDB + "-journal")
			_ = os.Remove(outputDB + "-wal")
			_ = os.Remove(outputDB + "-shm")
		}
	}()
	dbURI, err := sqliteURI(outputDB, "rw")
	if err != nil {
		return 0, err
	}
	db, err := sql.Open("sqlite", dbURI)
	if err != nil {
		return 0, err
	}
	db.SetMaxOpenConns(1)
	dbClosed := false
	defer func() {
		if !dbClosed {
			retErr = errors.Join(retErr, db.Close())
		}
	}()
	if _, err = db.ExecContext(ctx, "PRAGMA journal_mode=DELETE"); err != nil {
		return 0, err
	}
	if _, err = db.ExecContext(ctx, "PRAGMA synchronous=FULL"); err != nil {
		return 0, err
	}
	if err = integrityCheck(ctx, db); err != nil {
		return 0, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT id, archive_path, raw_sha256 FROM messages WHERE archive_path <> ''")
	if err != nil {
		return 0, err
	}
	paths := make(map[string]string)
	type entry struct {
		id   int64
		path string
	}
	var entries []entry
	for rows.Next() {
		var id int64
		var path, digest string
		if err = rows.Scan(&id, &path, &digest); err != nil {
			_ = rows.Close()
			return 0, err
		}
		if previous, ok := paths[path]; ok && previous != digest {
			_ = rows.Close()
			return 0, errors.New("archive referenced with conflicting hashes")
		}
		paths[path] = digest
		entries = append(entries, entry{id: id, path: path})
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	if err = rows.Close(); err != nil {
		return 0, err
	}
	for path, digest := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return 0, errors.New("unclean archive reference")
		}
		rel, err := filepath.Rel(oldArchiveRoot, path)
		if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return 0, errors.New("archive reference is outside source root")
		}
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != digest {
			return 0, errors.New("invalid archive digest")
		}
		if err := verifyArchive(ctx, rootFD, rel, identity, digest); err != nil {
			return 0, err
		}
	}
	// All validation precedes updates; any SQL failure rolls back the snapshot.
	for _, item := range entries {
		rel, _ := filepath.Rel(oldArchiveRoot, item.path)
		result, err := tx.ExecContext(ctx, "UPDATE messages SET archive_path = ? WHERE id = ? AND archive_path = ?", filepath.Join(targetArchiveRoot, rel), item.id, item.path)
		if err != nil {
			return 0, err
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return 0, errors.New("archive reference update was inconclusive")
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if err := integrityCheck(ctx, db); err != nil {
		return 0, err
	}
	if err := db.Close(); err != nil {
		return 0, err
	}
	dbClosed = true
	outFD, err := unix.Openat(outputDirFD, filepath.Base(outputDB), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, errors.New("cannot reopen output database for sync")
	}
	syncErr := unix.Fsync(outFD)
	closeErr := unix.Close(outFD)
	if err := errors.Join(syncErr, closeErr); err != nil {
		return 0, err
	}
	if err := unix.Fsync(outputDirFD); err != nil {
		return 0, err
	}
	return len(paths), nil
}

func privateDirectory(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0o077 != 0 {
		return errors.New("directory is not private to the current user")
	}
	return nil
}

func integrityCheck(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			return err
		}
		count++
		if result != "ok" {
			return errors.New("SQLite integrity check failed")
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if count != 1 {
		return errors.New("SQLite integrity check was inconclusive")
	}
	return nil
}

// This matches the engine's absolute per-message archive limit; the reader
// must consume EOF so age authenticates the entire encrypted payload.
const maxArchiveBytes = 100 << 20

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func verifyArchive(ctx context.Context, rootFD int, rel string, identity *age.X25519Identity, digest string) error {
	components := strings.Split(rel, string(filepath.Separator))
	parent, err := unix.Dup(rootFD)
	if err != nil {
		return err
	}
	for i, component := range components {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(components)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(parent, component, flags, 0)
		_ = unix.Close(parent)
		if openErr != nil {
			return errors.New("archive is missing or contains a symlink")
		}
		parent = next
	}
	f := os.NewFile(uintptr(parent), "archive")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("archive must be a regular file")
	}
	plaintext, err := age.Decrypt(f, identity)
	if err != nil {
		return errors.New("archive decryption failed")
	}
	return verifyPlaintext(ctx, plaintext, digest)
}

func verifyPlaintext(ctx context.Context, plaintext io.Reader, digest string) error {
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx: ctx, r: io.LimitReader(plaintext, maxArchiveBytes+1)})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("archive decryption failed")
	}
	if n > maxArchiveBytes {
		return errors.New("archive exceeds the message size limit")
	}
	if hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("archive content hash mismatch")
	}
	return nil
}
