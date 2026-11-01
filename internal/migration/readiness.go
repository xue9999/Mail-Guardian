package migration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/o2-mail-guardian/guardian/internal/config"
	"golang.org/x/sys/unix"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// ErrSnapshotReadiness deliberately omits database values, account names and
// archive paths. A rejected input is not eligible for an offline candidate.
var ErrSnapshotReadiness = errors.New("offline snapshot readiness check failed")

// ReadinessLimits bound the standalone database and the returned inventory.
// MaxRows is the combined row budget for all five supported tables. These are
// resource bounds, not proof of storage reserve or a hard wall-clock deadline.
// MaxInventoryBytes counts distinct path and digest string bytes; the separate
// archive/reference count limits bound slice and record overhead as well.
type ReadinessLimits struct {
	MaxDatabaseBytes     int64
	MaxRows              int64
	MaxArchiveReferences int64
	MaxArchives          int64
	MaxInventoryBytes    int64
	MaxPathBytes         int
}

type ArchiveReference struct {
	Path, RawSHA256       string
	SizeBytes, References int64
}

type SnapshotInventory struct {
	DatabaseBytes, TotalRows, Messages, ArchiveReferences int64
	DatabaseSHA256, MailboxFingerprint                    string
	AuthorizationFingerprint                              string
	SpamRevisionHighWater, HamRevisionHighWater           uint64
	HistoricalRunStatusMismatches, LatestActualRunErrors  int64
	LatestActualRunStatus                                 string
	Archives                                              []ArchiveReference
	supersededProgress                                    int64
}

type readinessPolicy uint8

const (
	readinessStrict readinessPolicy = iota
	readinessPrepareSupersededProgress
)

// InspectSnapshot examines an already-completed, private, standalone SQLite
// snapshot. It never opens the source through SQLite, migrates a schema, repairs
// state, or creates source sidecars. Bounded bytes are read through a no-symlink
// descriptor traversal and deserialized into a query-only in-memory connection.
// The caller must use clean absolute paths with real directory ancestors.
//
// This is OFFLINE inspection. It does not take a live checkpoint, prove that
// source writers or mailbox sessions are fenced, establish Redis/archive
// coherence, authenticate provenance, or authorize activation. A caller using
// the source again must verify DatabaseSHA256 against those exact bytes; the
// returned inventory cannot make a later pathname read immutable. Source
// identity/content checks detect ordinary drift, not a hostile same-user writer
// that can deliberately reverse its changes. Context cancellation is cooperative
// around file IO and supported SQLite queries, not a hard IO deadline.
func InspectSnapshot(ctx context.Context, path string, cfg config.Config, limits ReadinessLimits) (result SnapshotInventory, retErr error) {
	return inspectSnapshot(ctx, path, cfg, limits, readinessStrict)
}

// The private preparation policy relaxes only the cursor-table prohibition.
// It cannot be supplied by an external caller as an ownership/fencing proof.
func inspectSnapshot(ctx context.Context, path string, cfg config.Config, limits ReadinessLimits, policy readinessPolicy) (result SnapshotInventory, retErr error) {
	if ctx == nil || !validReadinessLimits(limits) {
		return result, ErrSnapshotReadiness
	}
	if err := ctx.Err(); err != nil {
		return result, errors.Join(ErrSnapshotReadiness, err)
	}
	resolved, err := cfg.Resolve()
	if err != nil || !filepath.IsAbs(resolved.Runtime.ArchiveDir) || filepath.Clean(resolved.Runtime.ArchiveDir) != resolved.Runtime.ArchiveDir || resolved.Runtime.ArchiveDir == "/" {
		return result, ErrSnapshotReadiness
	}
	f, parent, name, err := openReadinessSnapshot(path)
	if err != nil {
		return result, ErrSnapshotReadiness
	}
	defer f.Close()
	defer unix.Close(parent)
	before, err := f.Stat()
	if err != nil || before.Size() < 100 || before.Size() > limits.MaxDatabaseBytes || readinessSidecars(parent, name) != nil {
		return result, ErrSnapshotReadiness
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, r: f}, limits.MaxDatabaseBytes+1))
	if err != nil || int64(len(data)) != before.Size() || int64(len(data)) > limits.MaxDatabaseBytes || !standaloneSQLiteHeader(data) {
		return result, readinessFailure(ctx)
	}
	digest := sha256.Sum256(data)
	result.DatabaseBytes = int64(len(data))
	result.DatabaseSHA256 = hex.EncodeToString(digest[:])
	// The in-memory copy removes the SQLite pathname-open race and prevents
	// inspection queries from creating or following source WAL/SHM files.
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return SnapshotInventory{}, ErrSnapshotReadiness
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return SnapshotInventory{}, readinessFailure(ctx)
	}
	defer conn.Close()
	if err := conn.Raw(func(raw any) error {
		loader, ok := raw.(interface{ Deserialize([]byte) error })
		if !ok {
			return ErrSnapshotReadiness
		}
		return loader.Deserialize(data)
	}); err != nil {
		return SnapshotInventory{}, ErrSnapshotReadiness
	}
	if _, err := sqlite.Limit(conn, sqlite3.SQLITE_LIMIT_LENGTH, 1<<20); err != nil {
		return SnapshotInventory{}, ErrSnapshotReadiness
	}
	for _, query := range []string{"PRAGMA query_only=ON", "PRAGMA trusted_schema=OFF", "PRAGMA temp_store=MEMORY", "PRAGMA busy_timeout=0"} {
		if _, err := conn.ExecContext(ctx, query); err != nil {
			return SnapshotInventory{}, readinessFailure(ctx)
		}
	}
	if err := inspectReadinessSchema(ctx, conn); err != nil {
		return SnapshotInventory{}, readinessFailure(ctx)
	}
	var check string
	if err := conn.QueryRowContext(ctx, "PRAGMA integrity_check(1)").Scan(&check); err != nil || check != "ok" {
		return SnapshotInventory{}, readinessFailure(ctx)
	}
	foreign, err := conn.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return SnapshotInventory{}, readinessFailure(ctx)
	}
	badForeign := foreign.Next()
	if err := errors.Join(foreign.Err(), foreign.Close()); err != nil || badForeign {
		return SnapshotInventory{}, readinessFailure(ctx)
	}
	for _, table := range []string{"messages", "runs", "events", "settings", "reconciliations"} {
		var count int64
		// LIMIT stops counting as soon as the remaining combined budget fails.
		if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM (SELECT 1 FROM "+table+" LIMIT ?)", limits.MaxRows-result.TotalRows+1).Scan(&count); err != nil || count > limits.MaxRows-result.TotalRows {
			return SnapshotInventory{}, readinessFailure(ctx)
		}
		result.TotalRows += count
		if table == "messages" {
			result.Messages = count
		}
		// A cursor left behind after a finalized message is still residual
		// operation state. Do not silently adopt it or delete it while inspecting.
		if table == "reconciliations" && count != 0 {
			if policy != readinessPrepareSupersededProgress {
				return SnapshotInventory{}, ErrSnapshotReadiness
			}
			var disallowed int
			if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM reconciliations r
				LEFT JOIN messages m ON m.id=r.message_id
				WHERE m.id IS NULL OR m.account<>? OR m.status<>'superseded')`, resolved.Account.Email).Scan(&disallowed); err != nil || disallowed != 0 {
				return SnapshotInventory{}, readinessFailure(ctx)
			}
			result.supersededProgress = count
		}
	}
	if err := inspectReadinessSettings(ctx, conn, resolved, &result); err != nil {
		return SnapshotInventory{}, readinessFailure(ctx)
	}
	var invalid int
	if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM messages WHERE
		typeof(account)<>'text' OR account<>? OR typeof(status)<>'text' OR
		status NOT IN ('kept','observed','quarantined','rescued','review','superseded','restored','purged') OR
		typeof(id)<>'integer' OR id<=0 OR typeof(uid)<>'integer' OR uid<0 OR uid>4294967295 OR
		typeof(uidvalidity)<>'integer' OR uidvalidity<0 OR uidvalidity>4294967295 OR
		typeof(raw_sha256)<>'text' OR length(CAST(raw_sha256 AS BLOB))<>64 OR raw_sha256 GLOB '*[^0-9a-f]*' OR
		typeof(size_bytes)<>'integer' OR size_bytes<0 OR size_bytes>104857600 OR
		typeof(archive_path)<>'text' OR length(CAST(archive_path AS BLOB))>? OR
		typeof(feedback)<>'text' OR feedback NOT IN ('','ham','spam') OR
		typeof(feedback_intent)<>'text' OR feedback_intent NOT IN ('','ham','spam'))`, resolved.Account.Email, limits.MaxPathBytes).Scan(&invalid); err != nil || invalid != 0 {
		return SnapshotInventory{}, readinessFailure(ctx)
	}
	// Completed historical failures and legitimate skipped-learning intents are
	// history. They do not become new unresolved operations merely by inspection.
	if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM runs WHERE
		finished_at IS NULL OR typeof(finished_at)<>'text' OR finished_at='' OR status NOT IN ('ok','error') OR typeof(status)<>'text' OR
		typeof(command)<>'text' OR typeof(started_at)<>'text' OR length(CAST(started_at AS BLOB))>64 OR length(CAST(finished_at AS BLOB))>64 OR
		typeof(dry_run)<>'integer' OR dry_run NOT IN (0,1) OR typeof(errors)<>'integer' OR errors<0)`).Scan(&invalid); err != nil || invalid != 0 {
		return SnapshotInventory{}, readinessFailure(ctx)
	}
	runs, err := conn.QueryContext(ctx, "SELECT started_at,finished_at FROM runs")
	if err != nil {
		return SnapshotInventory{}, readinessFailure(ctx)
	}
	for runs.Next() {
		var started, finished string
		if err := runs.Scan(&started, &finished); err != nil {
			_ = runs.Close()
			return SnapshotInventory{}, readinessFailure(ctx)
		}
		for _, value := range []string{started, finished} {
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil || parsed.IsZero() {
				_ = runs.Close()
				return SnapshotInventory{}, ErrSnapshotReadiness
			}
		}
	}
	if err := errors.Join(runs.Err(), runs.Close()); err != nil {
		return SnapshotInventory{}, readinessFailure(ctx)
	}
	// Older versions recorded some completed status='ok' runs with item errors.
	// Preserve that history verbatim and report its inconsistency. A later dry
	// run or maintenance command must not hide a contradiction in the latest
	// actual filtering run. A coherent status='error' generation remains valid
	// for offline backup; the separate cutover gate must assess its health.
	err = conn.QueryRowContext(ctx, `SELECT status,errors FROM runs
		WHERE command='run' AND dry_run=0 ORDER BY id DESC LIMIT 1`).Scan(&result.LatestActualRunStatus, &result.LatestActualRunErrors)
	if !errors.Is(err, sql.ErrNoRows) && err != nil {
		return SnapshotInventory{}, readinessFailure(ctx)
	}
	if result.LatestActualRunStatus == "ok" && result.LatestActualRunErrors != 0 {
		return SnapshotInventory{}, ErrSnapshotReadiness
	}
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM runs WHERE status='ok' AND errors>0`).Scan(&result.HistoricalRunStatusMismatches); err != nil {
		return SnapshotInventory{}, readinessFailure(ctx)
	}
	if err := inspectReadinessArchives(ctx, conn, resolved.Runtime.ArchiveDir, limits, &result); err != nil {
		return SnapshotInventory{}, readinessFailure(ctx)
	}
	// Check the original descriptor, namespace and complete content once more.
	// No SQLite connection has ever opened the source file.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return SnapshotInventory{}, ErrSnapshotReadiness
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(contextReader{ctx: ctx, r: f}, limits.MaxDatabaseBytes+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || n != before.Size() || !sameReadinessFile(before, after) || !bytes.Equal(h.Sum(nil), digest[:]) || readinessSidecars(parent, name) != nil {
		return SnapshotInventory{}, readinessFailure(ctx)
	}
	again, againParent, _, err := openReadinessSnapshot(path)
	if err != nil {
		return SnapshotInventory{}, ErrSnapshotReadiness
	}
	againInfo, infoErr := again.Stat()
	closeErr := errors.Join(again.Close(), unix.Close(againParent))
	if infoErr != nil || closeErr != nil || !sameReadinessFile(before, againInfo) {
		return SnapshotInventory{}, ErrSnapshotReadiness
	}
	return result, nil
}

func readinessFailure(ctx context.Context) error {
	return errors.Join(ErrSnapshotReadiness, ctx.Err())
}

func validReadinessLimits(l ReadinessLimits) bool {
	return l.MaxDatabaseBytes >= 512 && l.MaxDatabaseBytes <= 256<<20 && l.MaxRows > 0 && l.MaxRows <= 10000000 &&
		l.MaxArchiveReferences > 0 && l.MaxArchiveReferences <= 10000000 && l.MaxArchives > 0 && l.MaxArchives <= 100000 &&
		l.MaxInventoryBytes > 0 && l.MaxInventoryBytes <= 256<<20 && l.MaxPathBytes > 0 && l.MaxPathBytes <= 65536
}

func standaloneSQLiteHeader(data []byte) bool {
	if len(data) < 100 || !bytes.Equal(data[:16], []byte("SQLite format 3\x00")) || data[18] != 1 || data[19] != 1 {
		return false
	}
	pageSize := int64(binary.BigEndian.Uint16(data[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	pages := int64(binary.BigEndian.Uint32(data[28:32]))
	return pageSize >= 512 && pageSize <= 65536 && pageSize&(pageSize-1) == 0 && pages > 0 && pages*pageSize == int64(len(data))
}

func openReadinessSnapshot(path string) (*os.File, int, string, error) {
	parent, name, err := openReadinessParent(path)
	if err != nil {
		return nil, -1, "", err
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(parent)
		return nil, -1, "", ErrSnapshotReadiness
	}
	var file unix.Stat_t
	if err := unix.Fstat(fd, &file); err != nil || file.Mode&unix.S_IFMT != unix.S_IFREG || file.Mode&0o7077 != 0 || file.Uid != uint32(os.Geteuid()) || file.Nlink != 1 {
		_ = unix.Close(fd)
		_ = unix.Close(parent)
		return nil, -1, "", ErrSnapshotReadiness
	}
	return os.NewFile(uintptr(fd), "offline snapshot"), parent, name, nil
}

func openReadinessParent(path string) (int, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, 0) {
		return -1, "", ErrSnapshotReadiness
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	parent, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", ErrSnapshotReadiness
	}
	for _, component := range parts[:len(parts)-1] {
		next, err := unix.Openat(parent, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(parent)
		if err != nil {
			return -1, "", ErrSnapshotReadiness
		}
		parent = next
	}
	var directory unix.Stat_t
	if err := unix.Fstat(parent, &directory); err != nil || directory.Uid != uint32(os.Geteuid()) || directory.Mode&0o077 != 0 {
		_ = unix.Close(parent)
		return -1, "", ErrSnapshotReadiness
	}
	name := parts[len(parts)-1]
	return parent, name, nil
}

func readinessSidecars(parent int, name string) error {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		var st unix.Stat_t
		if err := unix.Fstatat(parent, name+suffix, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			return ErrSnapshotReadiness
		}
	}
	return nil
}

func sameReadinessFile(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.Mode() == b.Mode() && a.ModTime().Equal(b.ModTime())
}

type readinessColumn struct {
	typeName string
	notNull  int
	primary  int
}

func readinessColumns() map[string]map[string]readinessColumn {
	result := map[string]map[string]readinessColumn{}
	add := func(table, kind, names string, notNull int) {
		if result[table] == nil {
			result[table] = map[string]readinessColumn{}
		}
		for _, name := range strings.Fields(names) {
			result[table][name] = readinessColumn{kind, notNull, 0}
		}
	}
	add("messages", "TEXT", "account source_folder current_folder message_id_hash raw_sha256 verdict symbols_json action status first_seen last_scanned archive_path feedback feedback_intent last_error initial_verdict initial_action", 1)
	add("messages", "TEXT", "quarantined_at delete_after archive_until", 0)
	add("messages", "INTEGER", "uidvalidity uid size_bytes", 1)
	add("messages", "REAL", "score", 1)
	add("events", "INTEGER", "message_id", 0)
	add("events", "TEXT", "at action detail", 1)
	add("runs", "TEXT", "started_at command status", 1)
	add("runs", "TEXT", "finished_at", 0)
	add("runs", "INTEGER", "dry_run scanned kept rescued quarantined review learned_spam learned_ham purged errors", 1)
	add("settings", "TEXT", "value", 1)
	add("settings", "TEXT", "key", 0)
	add("reconciliations", "INTEGER", "source_uidvalidity source_cursor source_complete source_matches source_match_uid destination_uidvalidity destination_cursor destination_complete destination_matches destination_match_uid", 1)
	add("reconciliations", "TEXT", "updated_at", 1)
	for _, table := range []string{"messages", "events", "runs"} {
		result[table]["id"] = readinessColumn{"INTEGER", 0, 1}
	}
	result["settings"]["key"] = readinessColumn{"TEXT", 0, 1}
	result["reconciliations"]["message_id"] = readinessColumn{"INTEGER", 0, 1}
	return result
}

func inspectReadinessSchema(ctx context.Context, conn *sql.Conn) error {
	tables := readinessColumns()
	indexes := map[string]string{
		"idx_messages_location":        "CREATE INDEX idx_messages_location ON messages(account,current_folder,uidvalidity,uid)",
		"idx_messages_location_unique": "CREATE UNIQUE INDEX idx_messages_location_unique ON messages(account,current_folder,uidvalidity,uid) WHERE uid > 0",
		"idx_messages_purge":           "CREATE INDEX idx_messages_purge ON messages(status,delete_after)",
	}
	objects, err := conn.QueryContext(ctx, "SELECT type,name,tbl_name,sql FROM sqlite_schema")
	if err != nil {
		return ErrSnapshotReadiness
	}
	seenTables, seenIndexes := map[string]bool{}, map[string]bool{}
	for objects.Next() {
		var kind, name, table string
		var ddl sql.NullString
		if err := objects.Scan(&kind, &name, &table, &ddl); err != nil {
			_ = objects.Close()
			return ErrSnapshotReadiness
		}
		switch {
		case kind == "table" && tables[name] != nil && table == name && ddl.Valid && supportedReadinessTableSQL(name, ddl.String, tables[name]):
			seenTables[name] = true
		case kind == "index" && table == "messages" && indexes[name] != "" && ddl.Valid && normalizeReadinessSQL(ddl.String) == normalizeReadinessSQL(indexes[name]):
			seenIndexes[name] = true
		case kind == "index" && name == "sqlite_autoindex_settings_1" && table == "settings" && !ddl.Valid:
		default:
			_ = objects.Close()
			return ErrSnapshotReadiness
		}
	}
	if err := errors.Join(objects.Err(), objects.Close()); err != nil || len(seenTables) != len(tables) || len(seenIndexes) != len(indexes) {
		return ErrSnapshotReadiness
	}
	for table, expected := range tables {
		rows, err := conn.QueryContext(ctx, "PRAGMA main.table_xinfo("+table+")")
		if err != nil {
			return ErrSnapshotReadiness
		}
		seen := map[string]bool{}
		for rows.Next() {
			var cid, notNull, primary, hidden int
			var name, kind string
			var defaultValue any
			if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primary, &hidden); err != nil {
				_ = rows.Close()
				return ErrSnapshotReadiness
			}
			column, ok := expected[name]
			if !ok || seen[name] || strings.ToUpper(kind) != column.typeName || notNull != column.notNull || primary != column.primary || hidden != 0 {
				_ = rows.Close()
				return ErrSnapshotReadiness
			}
			seen[name] = true
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil || len(seen) != len(expected) {
			return ErrSnapshotReadiness
		}
		fk, err := conn.QueryContext(ctx, "PRAGMA main.foreign_key_list("+table+")")
		if err != nil {
			return ErrSnapshotReadiness
		}
		count := 0
		for fk.Next() {
			var id, seq int
			var target, from, to, update, deletion, match string
			if err := fk.Scan(&id, &seq, &target, &from, &to, &update, &deletion, &match); err != nil {
				_ = fk.Close()
				return ErrSnapshotReadiness
			}
			count++
			wantDelete := "CASCADE"
			if table == "events" {
				wantDelete = "SET NULL"
			}
			if (table != "events" && table != "reconciliations") || id != 0 || seq != 0 || target != "messages" || from != "message_id" || to != "id" || update != "NO ACTION" || deletion != wantDelete || match != "NONE" {
				_ = fk.Close()
				return ErrSnapshotReadiness
			}
		}
		want := 0
		if table == "events" || table == "reconciliations" {
			want = 1
		}
		if err := errors.Join(fk.Err(), fk.Close()); err != nil || count != want {
			return ErrSnapshotReadiness
		}
	}
	return nil
}

func normalizeReadinessSQL(s string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s))
}

// Require only the declarations emitted by the current store, while allowing
// column order to differ after supported ADD COLUMN migrations. Extra CHECK,
// COLLATE, generated/default expressions and table options are not adopted.
func supportedReadinessTableSQL(table, ddl string, columns map[string]readinessColumn) bool {
	// Current schemas contain only empty SQL string literals for defaults.
	// Do not erase whitespace inside a nonempty literal during normalization.
	for i := 0; i < len(ddl); i++ {
		if ddl[i] == '\'' {
			if i+1 >= len(ddl) || ddl[i+1] != '\'' {
				return false
			}
			i++
		}
	}
	ddl = normalizeReadinessSQL(ddl)
	prefix := "createtable" + table + "("
	if !strings.HasPrefix(ddl, prefix) || !strings.HasSuffix(ddl, ")") {
		return false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(ddl, prefix), ")")
	want := map[string]bool{}
	for name, col := range columns {
		declaration := name + strings.ToLower(col.typeName)
		if col.primary != 0 {
			declaration += "primarykey"
		}
		if col.notNull != 0 {
			declaration += "notnull"
		}
		switch {
		case table == "messages" && (name == "archive_path" || name == "feedback" || name == "feedback_intent" || name == "last_error" || name == "initial_verdict" || name == "initial_action"):
			declaration += "default''"
		case table == "events" && name == "detail":
			declaration += "default''"
		case table == "runs" && col.typeName == "INTEGER" && name != "id" && name != "dry_run":
			declaration += "default0"
		case table == "reconciliations" && col.typeName == "INTEGER" && name != "message_id":
			declaration += "default0"
		}
		want[declaration] = true
	}
	if table == "events" {
		want["foreignkey(message_id)referencesmessages(id)ondeletesetnull"] = true
	}
	if table == "reconciliations" {
		want["foreignkey(message_id)referencesmessages(id)ondeletecascade"] = true
	}
	for _, declaration := range strings.Split(body, ",") {
		if !want[declaration] {
			return false
		}
		delete(want, declaration)
	}
	return len(want) == 0
}

func inspectReadinessSettings(ctx context.Context, conn *sql.Conn, cfg config.Config, result *SnapshotInventory) error {
	var invalid int
	if err := conn.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM settings WHERE typeof(key)<>'text' OR typeof(value)<>'text')").Scan(&invalid); err != nil || invalid != 0 {
		return ErrSnapshotReadiness
	}
	rows, err := conn.QueryContext(ctx, "SELECT key,value FROM settings")
	if err != nil {
		return ErrSnapshotReadiness
	}
	defer rows.Close()
	values := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil || len(key) > 128 || len(value) > 1<<20 {
			return ErrSnapshotReadiness
		}
		if _, exists := values[key]; exists {
			return ErrSnapshotReadiness
		}
		switch key {
		case "mailbox_fingerprint", "authorization_fingerprint", "deployment_identity":
			if value != "" && !readinessDigest(value) {
				return ErrSnapshotReadiness
			}
		case "bayes_spam_revision_highwater", "bayes_ham_revision_highwater":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil || strconv.FormatUint(v, 10) != value {
				return ErrSnapshotReadiness
			}
		case "configuration_dry_run_required":
			if value != "" && value != "1" {
				return ErrSnapshotReadiness
			}
		case "model_checkpoint_required", "bayes_rollback_at":
			if value != "" {
				return ErrSnapshotReadiness
			}
		case "installed_at", "protect_since", "active_since", "first_dry_run_completed_at", "last_notification", "last_failure_notification":
			if value != "" {
				parsed, err := time.Parse(time.RFC3339Nano, value)
				if err != nil || parsed.IsZero() {
					return ErrSnapshotReadiness
				}
			}
		case "filter_qualification_v1":
			// Preserve historical quality evidence. This inspection does not
			// adopt it as fresh operational or activation authorization.
			if value != "" && (!json.Valid([]byte(value)) || !strings.HasPrefix(strings.TrimSpace(value), "{")) {
				return ErrSnapshotReadiness
			}
		default:
			return ErrSnapshotReadiness
		}
		values[key] = value
	}
	if err := rows.Err(); err != nil || values["mailbox_fingerprint"] != cfg.MailboxFingerprint() || values["authorization_fingerprint"] != cfg.AuthorizationFingerprint() {
		return ErrSnapshotReadiness
	}
	for _, key := range []string{"bayes_spam_revision_highwater", "bayes_ham_revision_highwater"} {
		if _, present := values[key]; !present {
			return ErrSnapshotReadiness
		}
	}
	result.MailboxFingerprint, result.AuthorizationFingerprint = values["mailbox_fingerprint"], values["authorization_fingerprint"]
	result.SpamRevisionHighWater, _ = strconv.ParseUint(values["bayes_spam_revision_highwater"], 10, 64)
	result.HamRevisionHighWater, _ = strconv.ParseUint(values["bayes_ham_revision_highwater"], 10, 64)
	return nil
}

func readinessDigest(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size
}

func inspectReadinessArchives(ctx context.Context, conn *sql.Conn, archiveRoot string, limits ReadinessLimits, result *SnapshotInventory) error {
	rows, err := conn.QueryContext(ctx, "SELECT archive_path,raw_sha256,size_bytes FROM messages WHERE archive_path<>'' ORDER BY archive_path")
	if err != nil {
		return ErrSnapshotReadiness
	}
	defer rows.Close()
	var inventoryBytes int64
	for rows.Next() {
		var path, digest string
		var size int64
		if err := rows.Scan(&path, &digest, &size); err != nil || result.ArchiveReferences >= limits.MaxArchiveReferences || len(path) > limits.MaxPathBytes || !readinessDigest(digest) {
			return ErrSnapshotReadiness
		}
		result.ArchiveReferences++
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\\') || strings.IndexFunc(path, unicode.IsControl) >= 0 {
			return ErrSnapshotReadiness
		}
		rel, err := filepath.Rel(archiveRoot, path)
		if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return ErrSnapshotReadiness
		}
		if len(result.Archives) != 0 && result.Archives[len(result.Archives)-1].Path == path {
			previous := &result.Archives[len(result.Archives)-1]
			if previous.RawSHA256 != digest || previous.SizeBytes != size {
				return ErrSnapshotReadiness
			}
			previous.References++
			continue
		}
		amount := int64(len(path) + len(digest))
		if int64(len(result.Archives)) >= limits.MaxArchives || amount > limits.MaxInventoryBytes-inventoryBytes {
			return ErrSnapshotReadiness
		}
		inventoryBytes += amount
		result.Archives = append(result.Archives, ArchiveReference{Path: path, RawSHA256: digest, SizeBytes: size, References: 1})
	}
	return rows.Err()
}
