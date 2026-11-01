package migration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/xue9999/Mail-Guardian/internal/config"
	"golang.org/x/sys/unix"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var ErrSnapshotPreparation = errors.New("offline snapshot preparation failed")

// SnapshotPreparation records only an explicit offline clone transformation.
// SourceSHA256 identifies the preserved original; PreparedSHA256 identifies
// the strict-inspected result. Neither digest proves origin or freshness.
type SnapshotPreparation struct {
	SourceSHA256, PreparedSHA256 string
	RemovedSupersededProgress    int64
}

// PrepareSnapshot creates a new private standalone clone, discarding only
// abandoned reconciliation cursors whose messages are currently superseded in
// the same bound account. Every other readiness check remains strict. It never
// edits the source or message/event/run/settings history and never cleans up a
// live database. A cursor associated with any other status, missing message or
// account blocks preparation. Superseded means inactive at this snapshot, not
// a promise that a row can never be used by another operation in the future.
//
// The caller must retain the original snapshot, use an exclusively controlled
// private staging directory, and record a trusted completion receipt before
// consuming the new file. Ordinary failure removes only this call's new output;
// a crash can leave an incomplete private clone and no completion receipt.
// This helper does not revoke inherited authorization, capture archives/Redis,
// prove owner fencing or coherence, install state, or authorize activation.
// Its cancellation/resource guarantees are the same as InspectSnapshot.
func PrepareSnapshot(ctx context.Context, source, destination string, cfg config.Config, limits ReadinessLimits) (result SnapshotPreparation, retErr error) {
	if ctx == nil || source == destination || !validReadinessLimits(limits) {
		return result, ErrSnapshotPreparation
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if strings.HasSuffix(destination, suffix) {
			return result, ErrSnapshotPreparation
		}
	}
	resolved, err := cfg.Resolve()
	if err != nil {
		return result, ErrSnapshotPreparation
	}
	before, err := inspectSnapshot(ctx, source, resolved, limits, readinessPrepareSupersededProgress)
	if err != nil {
		return result, errors.Join(ErrSnapshotPreparation, err)
	}
	data, err := readPreparationSource(ctx, source, before.DatabaseSHA256, limits.MaxDatabaseBytes)
	if err != nil {
		return result, preparationFailure(ctx)
	}
	parent, name, err := openReadinessParent(destination)
	if err != nil {
		return result, ErrSnapshotPreparation
	}
	defer unix.Close(parent)
	if readinessSidecars(parent, name) != nil {
		return result, ErrSnapshotPreparation
	}
	fd, err := unix.Openat(parent, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return result, ErrSnapshotPreparation
	}
	out := os.NewFile(uintptr(fd), "new offline clone")
	var created unix.Stat_t
	if err := unix.Fstat(fd, &created); err != nil {
		_ = out.Close()
		// No other process can replace a name in the caller's exclusively
		// controlled private parent; do not remove an unverified identity.
		return result, ErrSnapshotPreparation
	}
	closed, complete := false, false
	defer func() {
		if !closed {
			_ = out.Close()
		}
		if !complete {
			if err := removePreparationOutput(parent, name, created); err != nil {
				retErr = errors.Join(retErr, ErrSnapshotPreparation)
			}
		}
	}()
	// First materialize an exact byte clone. The original is never passed to
	// SQLite. Subsequent SQL operates on an in-memory copy, so destination path
	// substitution cannot redirect a DELETE to a live/source database.
	if err := writePreparationImage(ctx, out, data, limits.MaxDatabaseBytes); err != nil {
		return SnapshotPreparation{}, preparationFailure(ctx)
	}
	prepared, removed, err := prepareImage(ctx, data, resolved.Account.Email, before.supersededProgress)
	if err != nil || int64(len(prepared)) > limits.MaxDatabaseBytes || !standaloneSQLiteHeader(prepared) {
		return SnapshotPreparation{}, preparationFailure(ctx)
	}
	if err := writePreparationImage(ctx, out, prepared, limits.MaxDatabaseBytes); err != nil {
		return SnapshotPreparation{}, preparationFailure(ctx)
	}
	if err := errors.Join(out.Sync(), unix.Fsync(parent)); err != nil {
		return SnapshotPreparation{}, ErrSnapshotPreparation
	}
	if err := checkPreparationOutput(parent, name, created); err != nil {
		return SnapshotPreparation{}, ErrSnapshotPreparation
	}
	after, err := InspectSnapshot(ctx, destination, resolved, limits)
	if err != nil {
		return SnapshotPreparation{}, errors.Join(ErrSnapshotPreparation, err)
	}
	digest := sha256.Sum256(prepared)
	if after.DatabaseSHA256 != hex.EncodeToString(digest[:]) {
		return SnapshotPreparation{}, ErrSnapshotPreparation
	}
	// Revalidate the preserved original after writing and inspecting the clone.
	// As with inspection, these are drift checks, not an external owner fence.
	unchanged, err := inspectSnapshot(ctx, source, resolved, limits, readinessPrepareSupersededProgress)
	if err != nil || unchanged.DatabaseSHA256 != before.DatabaseSHA256 || unchanged.supersededProgress != removed {
		return SnapshotPreparation{}, preparationFailure(ctx)
	}
	if err := unix.Fsync(parent); err != nil {
		return SnapshotPreparation{}, ErrSnapshotPreparation
	}
	if err := checkPreparationOutput(parent, name, created); err != nil {
		return SnapshotPreparation{}, ErrSnapshotPreparation
	}
	if err := out.Close(); err != nil {
		closed = true
		return SnapshotPreparation{}, ErrSnapshotPreparation
	}
	closed = true
	result = SnapshotPreparation{
		SourceSHA256: before.DatabaseSHA256, PreparedSHA256: after.DatabaseSHA256,
		RemovedSupersededProgress: removed,
	}
	complete = true
	return result, nil
}

func preparationFailure(ctx context.Context) error {
	return errors.Join(ErrSnapshotPreparation, ctx.Err())
}

func readPreparationSource(ctx context.Context, source, expected string, maximum int64) ([]byte, error) {
	f, parent, name, err := openReadinessSnapshot(source)
	if err != nil {
		return nil, ErrSnapshotPreparation
	}
	defer f.Close()
	defer unix.Close(parent)
	info, err := f.Stat()
	if err != nil || info.Size() > maximum || readinessSidecars(parent, name) != nil {
		return nil, ErrSnapshotPreparation
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, r: f}, maximum+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || int64(len(data)) > maximum || int64(len(data)) != info.Size() || !sameReadinessFile(info, after) {
		return nil, preparationFailure(ctx)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expected {
		return nil, ErrSnapshotPreparation
	}
	return data, nil
}

func writePreparationImage(ctx context.Context, out *os.File, data []byte, maximum int64) error {
	if int64(len(data)) > maximum || ctx.Err() != nil {
		return preparationFailure(ctx)
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return ErrSnapshotPreparation
	}
	if err := out.Truncate(0); err != nil {
		return ErrSnapshotPreparation
	}
	for offset := 0; offset < len(data); {
		if ctx.Err() != nil {
			return preparationFailure(ctx)
		}
		end := offset + 256<<10
		if end > len(data) {
			end = len(data)
		}
		n, err := out.Write(data[offset:end])
		if err != nil || n != end-offset {
			return ErrSnapshotPreparation
		}
		offset = end
	}
	return out.Truncate(int64(len(data)))
}

func prepareImage(ctx context.Context, image []byte, account string, expected int64) ([]byte, int64, error) {
	if expected == 0 {
		return image, 0, nil
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, 0, ErrSnapshotPreparation
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, 0, preparationFailure(ctx)
	}
	defer conn.Close()
	if err := conn.Raw(func(raw any) error {
		loader, ok := raw.(interface{ Deserialize([]byte) error })
		if !ok {
			return ErrSnapshotPreparation
		}
		return loader.Deserialize(image)
	}); err != nil {
		return nil, 0, ErrSnapshotPreparation
	}
	if _, err := sqlite.Limit(conn, sqlite3.SQLITE_LIMIT_LENGTH, 1<<20); err != nil {
		return nil, 0, ErrSnapshotPreparation
	}
	for _, statement := range []string{"PRAGMA trusted_schema=OFF", "PRAGMA foreign_keys=ON", "PRAGMA temp_store=MEMORY"} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return nil, 0, preparationFailure(ctx)
		}
	}
	// Recheck the schema before the only modifying statement. The trusted
	// original digest binds this image to the complete prior readiness pass.
	if err := inspectReadinessSchema(ctx, conn); err != nil {
		return nil, 0, ErrSnapshotPreparation
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, preparationFailure(ctx)
	}
	defer tx.Rollback()
	var total, eligible int64
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM reconciliations").Scan(&total); err != nil {
		return nil, 0, preparationFailure(ctx)
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM reconciliations r JOIN messages m ON m.id=r.message_id
		WHERE m.account=? AND m.status='superseded'`, account).Scan(&eligible); err != nil || total != expected || eligible != total {
		return nil, 0, preparationFailure(ctx)
	}
	deleted, err := tx.ExecContext(ctx, `DELETE FROM reconciliations WHERE message_id IN
		(SELECT id FROM messages WHERE account=? AND status='superseded')`, account)
	if err != nil {
		return nil, 0, preparationFailure(ctx)
	}
	changed, err := deleted.RowsAffected()
	if err != nil || changed != expected {
		return nil, 0, ErrSnapshotPreparation
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM reconciliations").Scan(&total); err != nil || total != 0 {
		return nil, 0, preparationFailure(ctx)
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, preparationFailure(ctx)
	}
	var result []byte
	if err := conn.Raw(func(raw any) error {
		serializer, ok := raw.(interface{ Serialize() ([]byte, error) })
		if !ok {
			return ErrSnapshotPreparation
		}
		result, err = serializer.Serialize()
		return err
	}); err != nil {
		return nil, 0, ErrSnapshotPreparation
	}
	return result, changed, nil
}

func removePreparationOutput(parent int, name string, created unix.Stat_t) error {
	var current unix.Stat_t
	if err := unix.Fstatat(parent, name, &current, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil || current.Dev != created.Dev || current.Ino != created.Ino || current.Mode&unix.S_IFMT != unix.S_IFREG {
		return ErrSnapshotPreparation
	}
	if err := unix.Unlinkat(parent, name, 0); err != nil {
		return ErrSnapshotPreparation
	}
	return unix.Fsync(parent)
}

func checkPreparationOutput(parent int, name string, created unix.Stat_t) error {
	var current unix.Stat_t
	if err := unix.Fstatat(parent, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil || current.Dev != created.Dev || current.Ino != created.Ino ||
		current.Mode&unix.S_IFMT != unix.S_IFREG || current.Mode&0o7077 != 0 || current.Uid != uint32(os.Geteuid()) || current.Nlink != 1 {
		return ErrSnapshotPreparation
	}
	return nil
}
