package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	sql *sql.DB
}

type Message struct {
	ID             int64
	Account        string
	SourceFolder   string
	CurrentFolder  string
	UIDValidity    uint32
	UID            uint32
	MessageIDHash  string
	RawSHA256      string
	SizeBytes      int64
	Verdict        string
	Score          float64
	Symbols        []string
	Action         string
	Status         string
	FirstSeen      time.Time
	LastScanned    time.Time
	QuarantinedAt  *time.Time
	DeleteAfter    *time.Time
	ArchivePath    string
	ArchiveUntil   *time.Time
	Feedback       string
	FeedbackIntent string
	LastError      string
}

type Run struct {
	ID          int64
	StartedAt   time.Time
	FinishedAt  *time.Time
	Command     string
	DryRun      bool
	Status      string
	Scanned     int
	Kept        int
	Rescued     int
	Quarantined int
	Review      int
	LearnedSpam int
	LearnedHam  int
	Purged      int
	Errors      int
}

type Summary struct {
	Runs              int `json:"runs"`
	DryRuns           int `json:"dry_runs"`
	Scanned           int `json:"scanned"`
	Kept              int `json:"kept"`
	Rescued           int `json:"rescued"`
	Quarantined       int `json:"quarantined"`
	Review            int `json:"review"`
	LearnedSpam       int `json:"learned_spam"`
	LearnedHam        int `json:"learned_ham"`
	Purged            int `json:"purged"`
	Errors            int `json:"errors"`
	WaitingQuarantine int `json:"waiting_quarantine"`
	WaitingReview     int `json:"waiting_review"`
	PendingMoves      int `json:"pending_moves"`
	PurgeEligible     int `json:"purge_eligible"`
}

type ActivationQuality struct {
	FalsePositives       int
	FalseRescues         int
	SpamFeedback         int
	SpamPreviouslySpam   int
	SpamPreviouslyReview int
	SpamUnexplained      int
}

type ReconcileProgress struct {
	MessageID              int64
	SourceUIDValidity      uint32
	SourceCursor           uint32
	SourceComplete         bool
	SourceMatches          int
	SourceMatchUID         uint32
	DestinationUIDValidity uint32
	DestinationCursor      uint32
	DestinationComplete    bool
	DestinationMatches     int
	DestinationMatchUID    uint32
	UpdatedAt              time.Time
}

func (q ActivationQuality) Ready() bool {
	return q.FalsePositives == 0 &&
		q.FalseRescues == 0 &&
		q.SpamFeedback > 0 &&
		q.SpamPreviouslySpam*100 >= q.SpamFeedback*90 &&
		q.SpamUnexplained == 0
}

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("inicjalizacja SQLite: %w", err)
		}
	}
	s := &DB{sql: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("ustawianie prywatnych uprawnień bazy: %w", err)
	}
	return s, nil
}

func (db *DB) Close() error { return db.sql.Close() }

// RequireFreshDryRun atomically invalidates the previous onboarding proof and
// starts a new protection observation window. A changed account or folder
// layout must never inherit unattended-operation permission from an older
// configuration.
func (db *DB) RequireFreshDryRun(ctx context.Context, protectSince time.Time) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	values := map[string]string{
		"first_dry_run_completed_at": "",
		"active_since":               "",
		"protect_since":              protectSince.UTC().Format(time.RFC3339Nano),
	}
	for key, value := range values {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO settings(key,value) VALUES(?,?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value); err != nil {
			return fmt.Errorf("reset zabezpieczeń konfiguracji: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("utrwalenie resetu zabezpieczeń konfiguracji: %w", err)
	}
	return nil
}

// IntegrityCheck verifies SQLite's structural invariants before Guardian
// performs mailbox mutations. Any diagnostic other than the single "ok" row
// is treated as corruption and returned to the caller.
func (db *DB) IntegrityCheck(ctx context.Context) error {
	rows, err := db.sql.QueryContext(ctx, `PRAGMA quick_check`)
	if err != nil {
		return fmt.Errorf("SQLite quick_check: %w", err)
	}
	defer rows.Close()

	var diagnostics []string
	for rows.Next() {
		var diagnostic string
		if err := rows.Scan(&diagnostic); err != nil {
			return fmt.Errorf("odczyt SQLite quick_check: %w", err)
		}
		if !strings.EqualFold(strings.TrimSpace(diagnostic), "ok") && len(diagnostics) < 10 {
			diagnostics = append(diagnostics, diagnostic)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("SQLite quick_check: %w", err)
	}
	if len(diagnostics) != 0 {
		return fmt.Errorf("baza SQLite jest uszkodzona: %s", strings.Join(diagnostics, "; "))
	}
	return nil
}

// PruneTechnicalHistory bounds growth of diagnostic rows without deleting
// message state or user feedback. Both deletions commit atomically.
func (db *DB) PruneTechnicalHistory(ctx context.Context, before time.Time) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	cutoff := before.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE at<?`, cutoff); err != nil {
		return fmt.Errorf("retencja zdarzeń technicznych: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM runs WHERE started_at<?`, cutoff); err != nil {
		return fmt.Errorf("retencja historii uruchomień: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("utrwalenie retencji technicznej: %w", err)
	}
	return nil
}

func (db *DB) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS messages (
	id INTEGER PRIMARY KEY,
	account TEXT NOT NULL,
	source_folder TEXT NOT NULL,
	current_folder TEXT NOT NULL,
	uidvalidity INTEGER NOT NULL,
	uid INTEGER NOT NULL,
	message_id_hash TEXT NOT NULL,
	raw_sha256 TEXT NOT NULL,
	size_bytes INTEGER NOT NULL,
	verdict TEXT NOT NULL,
	score REAL NOT NULL,
	symbols_json TEXT NOT NULL,
	action TEXT NOT NULL,
	status TEXT NOT NULL,
	first_seen TEXT NOT NULL,
	last_scanned TEXT NOT NULL,
	quarantined_at TEXT,
	delete_after TEXT,
	archive_path TEXT NOT NULL DEFAULT '',
	archive_until TEXT,
	feedback TEXT NOT NULL DEFAULT '',
	feedback_intent TEXT NOT NULL DEFAULT '',
	last_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_messages_location
	ON messages(account, current_folder, uidvalidity, uid);
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_location_unique
	ON messages(account, current_folder, uidvalidity, uid)
	WHERE uid > 0;
CREATE INDEX IF NOT EXISTS idx_messages_purge
	ON messages(status, delete_after);

CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY,
	message_id INTEGER,
	at TEXT NOT NULL,
	action TEXT NOT NULL,
	detail TEXT NOT NULL DEFAULT '',
	FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS runs (
	id INTEGER PRIMARY KEY,
	started_at TEXT NOT NULL,
	finished_at TEXT,
	command TEXT NOT NULL,
	dry_run INTEGER NOT NULL,
	status TEXT NOT NULL,
	scanned INTEGER NOT NULL DEFAULT 0,
	kept INTEGER NOT NULL DEFAULT 0,
	rescued INTEGER NOT NULL DEFAULT 0,
	quarantined INTEGER NOT NULL DEFAULT 0,
	review INTEGER NOT NULL DEFAULT 0,
	learned_spam INTEGER NOT NULL DEFAULT 0,
	learned_ham INTEGER NOT NULL DEFAULT 0,
	purged INTEGER NOT NULL DEFAULT 0,
	errors INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reconciliations (
	message_id INTEGER PRIMARY KEY,
	source_uidvalidity INTEGER NOT NULL DEFAULT 0,
	source_cursor INTEGER NOT NULL DEFAULT 0,
	source_complete INTEGER NOT NULL DEFAULT 0,
	source_matches INTEGER NOT NULL DEFAULT 0,
	source_match_uid INTEGER NOT NULL DEFAULT 0,
	destination_uidvalidity INTEGER NOT NULL DEFAULT 0,
	destination_cursor INTEGER NOT NULL DEFAULT 0,
	destination_complete INTEGER NOT NULL DEFAULT 0,
	destination_matches INTEGER NOT NULL DEFAULT 0,
	destination_match_uid INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL,
	FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE
);`
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rozpoczęcie migracji bazy: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("tworzenie struktury bazy: %w", err)
	}
	if err := ensureColumn(ctx, tx, "messages", "feedback_intent", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migracja intencji korekt: %w", err)
	}
	for _, column := range []string{"initial_verdict", "initial_action"} {
		if err := ensureColumn(ctx, tx, "messages", column, "TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("zachowanie pierwszej oceny wiadomości: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE messages SET initial_verdict=verdict,initial_action=action WHERE initial_verdict=''`); err != nil {
		return fmt.Errorf("utrwalenie historycznych ocen: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("utrwalenie migracji bazy: %w", err)
	}
	return nil
}

func ensureColumn(ctx context.Context, tx *sql.Tx, table, column, definition string) error {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid int
		var name, kind string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		if name == column {
			found = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = tx.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN `+column+` `+definition)
	return err
}

func (db *DB) BeginRun(ctx context.Context, command string, dryRun bool) (*Run, error) {
	now := time.Now().UTC()
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	// The process-wide Guardian lock permits only one run. Therefore any older
	// unfinished row necessarily comes from a crash or forced termination.
	if _, err := tx.ExecContext(ctx, `
UPDATE runs SET status='error',finished_at=?
WHERE status='running' AND finished_at IS NULL`, now.Format(time.RFC3339Nano)); err != nil {
		return nil, fmt.Errorf("uzgadnianie przerwanego uruchomienia: %w", err)
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO runs(started_at,command,dry_run,status) VALUES(?,?,?,'running')`,
		now.Format(time.RFC3339Nano), command, boolInt(dryRun))
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Run{ID: id, StartedAt: now, Command: command, DryRun: dryRun, Status: "running"}, nil
}

func (db *DB) FinishRun(ctx context.Context, run *Run, runErr error) error {
	now := time.Now().UTC()
	run.FinishedAt = &now
	run.Status = "ok"
	if runErr != nil || run.Errors > 0 {
		run.Status = "error"
	}
	_, err := db.sql.ExecContext(ctx, `
UPDATE runs SET finished_at=?,status=?,scanned=?,kept=?,rescued=?,quarantined=?,
 review=?,learned_spam=?,learned_ham=?,purged=?,errors=? WHERE id=?`,
		now.Format(time.RFC3339Nano), run.Status, run.Scanned, run.Kept, run.Rescued,
		run.Quarantined, run.Review, run.LearnedSpam, run.LearnedHam, run.Purged,
		run.Errors, run.ID)
	return err
}

func (db *DB) HasSuccessfulRun(ctx context.Context) (bool, error) {
	var found int
	err := db.sql.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM runs WHERE status='ok')`).Scan(&found)
	return found != 0, err
}

// DryRunAuthorized returns the durable onboarding gate. Only databases that
// genuinely predate the gate may migrate an older successful run; an
// explicitly present empty value is a deliberate revocation and stays false.
func (db *DB) DryRunAuthorized(ctx context.Context) (bool, error) {
	proof, exists, err := db.GetSettingWithPresence(ctx, "first_dry_run_completed_at")
	if err != nil {
		return false, err
	}
	if exists {
		return proof != "", nil
	}
	successful, err := db.HasSuccessfulRun(ctx)
	if err != nil || !successful {
		return false, err
	}
	if err := db.SetSetting(ctx, "first_dry_run_completed_at", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return false, err
	}
	return true, nil
}

func (db *DB) LastRunTimes(ctx context.Context) (attempt, success *time.Time, err error) {
	read := func(column, where string) (*time.Time, error) {
		var value string
		err := db.sql.QueryRowContext(ctx, `SELECT `+column+` FROM runs WHERE `+where+` ORDER BY id DESC LIMIT 1`).Scan(&value)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return nil, err
		}
		parsed = parsed.UTC()
		return &parsed, nil
	}
	attempt, err = read(`started_at`, `dry_run=0`)
	if err != nil {
		return nil, nil, err
	}
	success, err = read(`finished_at`, `dry_run=0 AND status='ok' AND finished_at IS NOT NULL`)
	return attempt, success, err
}

// LatestLiveRunOutcome excludes onboarding dry runs and historical errors from
// the current service health signal. Historical counts remain in Summary.
func (db *DB) LatestLiveRunOutcome(ctx context.Context) (status string, errorsCount int, err error) {
	err = db.sql.QueryRowContext(ctx, `SELECT status,errors FROM runs WHERE dry_run=0 AND finished_at IS NOT NULL ORDER BY id DESC LIMIT 1`).Scan(&status, &errorsCount)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	return status, errorsCount, err
}

func (db *DB) LocationProcessed(ctx context.Context, account, folder string, uidValidity uint32, uid uint32, activeMode bool) (bool, error) {
	return db.LocationProcessedSince(ctx, account, folder, uidValidity, uid, activeMode, time.Time{})
}

// LocationProcessedSince expires only automatic keep decisions. Completed
// moves and explicit feedback never become eligible for repeated processing.
func (db *DB) LocationProcessedSince(ctx context.Context, account, folder string, uidValidity uint32, uid uint32, activeMode bool, rescanBefore time.Time) (bool, error) {
	var n int
	query := `SELECT COUNT(*) FROM messages WHERE account=? AND current_folder=? AND uidvalidity=? AND uid=? AND status NOT IN ('error','restored','pending_move','pending_learn')`
	args := []any{account, folder, uidValidity, uid}
	if activeMode {
		query += ` AND status<>'observed'`
	}
	if !rescanBefore.IsZero() {
		query += ` AND NOT (action='keep' AND status IN ('observed','kept') AND feedback='' AND feedback_intent='' AND julianday(last_scanned)<julianday(?))`
		args = append(args, formatTime(rescanBefore))
	}
	err := db.sql.QueryRowContext(ctx, query, args...).Scan(&n)
	return n > 0, err
}

func (db *DB) LocationPending(ctx context.Context, account, folder string, uidValidity, uid uint32) (bool, error) {
	var found int
	err := db.sql.QueryRowContext(ctx, `
SELECT EXISTS(
 SELECT 1 FROM messages
 WHERE account=? AND current_folder=? AND uidvalidity=? AND uid=?
   AND status IN ('pending_move','move_ambiguous')
)`, account, folder, uidValidity, uid).Scan(&found)
	return found != 0, err
}

// TrainingLocationProcessed retries blocked explicit corrections. Their raw
// content may be unlearnable, but the user's folder choice is still actionable.
func (db *DB) TrainingLocationProcessed(ctx context.Context, account, folder string, uidValidity, uid uint32) (bool, error) {
	var n int
	err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM messages WHERE account=? AND current_folder=? AND uidvalidity=? AND uid=? AND status NOT IN ('error','restored','pending_move','pending_learn','observed','blocked')`, account, folder, uidValidity, uid).Scan(&n)
	return n > 0, err
}

// PendingMessages returns moves whose durable intent was recorded before the
// IMAP operation, but whose final location was not confirmed. They must never
// be treated as completed work.
func (db *DB) PendingMessages(ctx context.Context, account string) ([]Message, error) {
	rows, err := db.sql.QueryContext(ctx, `
SELECT id,account,source_folder,current_folder,uidvalidity,uid,message_id_hash,raw_sha256,
 size_bytes,verdict,score,symbols_json,action,status,first_seen,last_scanned,
 quarantined_at,delete_after,archive_path,archive_until,feedback,feedback_intent,last_error
FROM messages
WHERE account=? AND status IN ('pending_move','move_ambiguous')
ORDER BY first_seen,id`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// PendingRestores returns explicit restore intents whose APPEND result was not
// durably confirmed. A later normal run may safely reconcile them by raw
// SHA-256 and finish the already-authorized restore without user guesswork.
func (db *DB) PendingRestores(ctx context.Context, account string) ([]Message, error) {
	rows, err := db.sql.QueryContext(ctx, `
SELECT id,account,source_folder,current_folder,uidvalidity,uid,message_id_hash,raw_sha256,
 size_bytes,verdict,score,symbols_json,action,status,first_seen,last_scanned,
 quarantined_at,delete_after,archive_path,archive_until,feedback,feedback_intent,last_error
FROM messages
WHERE account=? AND status='pending_restore'
ORDER BY first_seen,id`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (db *DB) UpsertMessage(ctx context.Context, m *Message) (int64, error) {
	if m.FirstSeen.IsZero() {
		m.FirstSeen = time.Now().UTC()
	}
	if m.LastScanned.IsZero() {
		m.LastScanned = time.Now().UTC()
	}
	symbols, _ := json.Marshal(m.Symbols)
	id := m.ID
	if id == 0 && m.UID > 0 {
		_ = db.sql.QueryRowContext(ctx,
			`SELECT id FROM messages WHERE account=? AND current_folder=? AND uidvalidity=? AND uid=?`,
			m.Account, m.CurrentFolder, m.UIDValidity, m.UID).Scan(&id)
	}
	if id > 0 {
		_, err := db.sql.ExecContext(ctx, `
UPDATE messages SET
 source_folder=?,current_folder=?,uidvalidity=?,uid=?,message_id_hash=?,raw_sha256=?,
 size_bytes=?,verdict=?,score=?,symbols_json=?,action=?,status=?,last_scanned=?,
 quarantined_at=COALESCE(quarantined_at,?),delete_after=COALESCE(delete_after,?),
 archive_path=CASE WHEN ?='' THEN archive_path ELSE ? END,
 archive_until=COALESCE(?,archive_until),
 feedback=CASE WHEN ?='' THEN feedback ELSE ? END,
 feedback_intent=CASE WHEN ?='' THEN feedback_intent ELSE ? END,last_error=?
WHERE id=?`,
			m.SourceFolder, m.CurrentFolder, m.UIDValidity, m.UID, m.MessageIDHash,
			m.RawSHA256, m.SizeBytes, m.Verdict, m.Score, string(symbols), m.Action,
			m.Status, formatTime(m.LastScanned), formatTimePtr(m.QuarantinedAt),
			formatTimePtr(m.DeleteAfter), m.ArchivePath, m.ArchivePath,
			formatTimePtr(m.ArchiveUntil), m.Feedback, m.Feedback,
			m.FeedbackIntent, m.FeedbackIntent, m.LastError, id)
		if err != nil {
			return 0, err
		}
		m.ID = id
		return id, nil
	}
	res, err := db.sql.ExecContext(ctx, `
INSERT INTO messages(account,source_folder,current_folder,uidvalidity,uid,message_id_hash,
 raw_sha256,size_bytes,verdict,score,symbols_json,action,status,first_seen,last_scanned,initial_verdict,initial_action,
 quarantined_at,delete_after,archive_path,archive_until,feedback,feedback_intent,last_error)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		m.Account, m.SourceFolder, m.CurrentFolder, m.UIDValidity, m.UID,
		m.MessageIDHash, m.RawSHA256, m.SizeBytes, m.Verdict, m.Score, string(symbols),
		m.Action, m.Status, formatTime(m.FirstSeen), formatTime(m.LastScanned), m.Verdict, m.Action,
		formatTimePtr(m.QuarantinedAt), formatTimePtr(m.DeleteAfter), m.ArchivePath,
		formatTimePtr(m.ArchiveUntil), m.Feedback, m.FeedbackIntent, m.LastError)
	if err != nil {
		return 0, err
	}
	id, _ = res.LastInsertId()
	m.ID = id
	return id, nil
}

func (db *DB) UpdateLocation(ctx context.Context, id int64, folder string, uidValidity, uid uint32, status string) error {
	_, err := db.sql.ExecContext(ctx,
		`UPDATE messages SET current_folder=?,uidvalidity=?,uid=?,status=? WHERE id=?`,
		folder, uidValidity, uid, status, id)
	return err
}

func (db *DB) FinalizeMove(
	ctx context.Context,
	id int64,
	folder string,
	uidValidity, uid uint32,
	status string,
	finalizedAt time.Time,
	quarantineDays, archiveDays int,
) error {
	finalizedAt = finalizedAt.UTC()
	archiveUntil := finalizedAt.AddDate(0, 0, archiveDays)
	if status == "quarantined" {
		deleteAfter := finalizedAt.AddDate(0, 0, quarantineDays)
		_, err := db.sql.ExecContext(ctx, `
UPDATE messages
SET current_folder=?,uidvalidity=?,uid=?,status=?,
    quarantined_at=?,delete_after=?,
    archive_until=CASE
      WHEN archive_until IS NULL OR archive_until<? THEN ?
      ELSE archive_until
    END,
    last_error=''
WHERE id=?`,
			folder, uidValidity, uid, status,
			formatTime(finalizedAt), formatTime(deleteAfter),
			formatTime(archiveUntil), formatTime(archiveUntil), id)
		return err
	}
	_, err := db.sql.ExecContext(ctx, `
UPDATE messages
SET current_folder=?,uidvalidity=?,uid=?,status=?,
    archive_until=CASE
      WHEN archive_until IS NULL OR archive_until<? THEN ?
      ELSE archive_until
    END,
    last_error=''
WHERE id=?`,
		folder, uidValidity, uid, status,
		formatTime(archiveUntil), formatTime(archiveUntil), id)
	return err
}

func (db *DB) MarkLearned(ctx context.Context, id int64, feedback string) error {
	if feedback != "spam" && feedback != "ham" {
		return fmt.Errorf("nieprawidłowa etykieta uczenia %q", feedback)
	}
	_, err := db.sql.ExecContext(ctx, `
UPDATE messages SET status='pending_move',feedback=?,action='learn_'||?,last_error=''
WHERE id=?`, feedback, feedback, id)
	return err
}

func (db *DB) MarkFeedbackIntent(ctx context.Context, id int64, feedback string) error {
	if feedback != "spam" && feedback != "ham" {
		return fmt.Errorf("nieprawidłowa intencja uczenia %q", feedback)
	}
	_, err := db.sql.ExecContext(ctx, `
UPDATE messages SET feedback_intent=?,last_error='' WHERE id=?`, feedback, id)
	return err
}

func (db *DB) MarkMoveUncertain(ctx context.Context, id int64, detail string) error {
	if len(detail) > 500 {
		detail = detail[:500]
	}
	_, err := db.sql.ExecContext(ctx,
		`UPDATE messages SET status='pending_move',last_error=? WHERE id=?`,
		detail, id)
	return err
}

func (db *DB) MarkRestorePending(ctx context.Context, id int64, account string) error {
	res, err := db.sql.ExecContext(ctx, `
UPDATE messages SET status='pending_restore',last_error=''
WHERE id=? AND account=?
  AND (status='pending_restore' OR current_folder='' OR uid=0 OR uidvalidity=0)`, id, account)
	if err != nil {
		return err
	}
	updated, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return errors.New("wiadomość nadal ma zapisaną lokalizację; przywrócenie przez APPEND jest zablokowane")
	}
	return nil
}

func (db *DB) FinalizeRestore(ctx context.Context, id int64, account, folder string, uidValidity, uid uint32) error {
	if uidValidity == 0 || uid == 0 {
		return errors.New("przywrócenie nie ma jednoznacznego UID i UIDVALIDITY")
	}
	res, err := db.sql.ExecContext(ctx, `
UPDATE messages
SET current_folder=?,uidvalidity=?,uid=?,status='restored',last_error=''
WHERE id=? AND account=? AND status IN ('pending_restore','restored')`,
		folder, uidValidity, uid, id, account)
	if err != nil {
		return err
	}
	updated, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return errors.New("nie znaleziono oczekującego przywrócenia dla tego konta")
	}
	return nil
}

func (db *DB) MarkPurged(ctx context.Context, id int64) error {
	_, err := db.sql.ExecContext(ctx,
		`UPDATE messages SET status='purged',current_folder='' WHERE id=?`, id)
	return err
}

func (db *DB) SupersedeOtherCopies(ctx context.Context, account, rawSHA256 string, keepID int64) error {
	_, err := db.sql.ExecContext(ctx, `
UPDATE messages SET status='superseded'
WHERE account=? AND raw_sha256=? AND id<>?
  AND status NOT IN ('purged','restored','pending_restore','superseded')`,
		account, rawSHA256, keepID)
	return err
}

func (db *DB) AddEvent(ctx context.Context, messageID int64, action, detail string) error {
	if len(detail) > 500 {
		detail = detail[:500]
	}
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO events(message_id,at,action,detail) VALUES(?,?,?,?)`,
		nullableID(messageID), time.Now().UTC().Format(time.RFC3339Nano), action, detail)
	return err
}

func (db *DB) PurgeCandidates(ctx context.Context, account string, now time.Time) ([]Message, error) {
	rows, err := db.sql.QueryContext(ctx, `
SELECT id,account,source_folder,current_folder,uidvalidity,uid,message_id_hash,raw_sha256,
 size_bytes,verdict,score,symbols_json,action,status,first_seen,last_scanned,
 quarantined_at,delete_after,archive_path,archive_until,feedback,feedback_intent,last_error
FROM messages
WHERE account=? AND status='quarantined' AND delete_after IS NOT NULL AND delete_after<=?
ORDER BY delete_after`, account, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (db *DB) Archived(ctx context.Context, account string, limit int) ([]Message, error) {
	return db.ArchivedPage(ctx, account, limit, 0)
}

func (db *DB) ArchivedPage(ctx context.Context, account string, limit, offset int) ([]Message, error) {
	return db.ArchivedPageFiltered(ctx, account, limit, offset, "")
}

// Filter before pagination, never only the visible page. Keep every query
// scoped to the account; headers are still decrypted only on explicit preview.
func (db *DB) ArchivedPageFiltered(ctx context.Context, account string, limit, offset int, status string) ([]Message, error) {
	return db.ArchivedPageInRange(ctx, account, limit, offset, status, time.Time{}, time.Time{})
}

// Date bounds are inclusive at the start and exclusive at the end.
func (db *DB) ArchivedPageInRange(ctx context.Context, account string, limit, offset int, status string, start, end time.Time) ([]Message, error) {
	from, until := "", ""
	if !start.IsZero() {
		from = start.UTC().Format(time.RFC3339Nano)
	}
	if !end.IsZero() {
		until = end.UTC().Format(time.RFC3339Nano)
	}

	if limit < 1 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := db.sql.QueryContext(ctx, `
SELECT id,account,source_folder,current_folder,uidvalidity,uid,message_id_hash,raw_sha256,
 size_bytes,verdict,score,symbols_json,action,status,first_seen,last_scanned,
 quarantined_at,delete_after,archive_path,archive_until,feedback,feedback_intent,last_error
FROM messages WHERE account=? AND archive_path<>'' AND (?='' OR status=?)
AND (?='' OR julianday(first_seen)>=julianday(?))
AND (?='' OR julianday(first_seen)<julianday(?))
ORDER BY first_seen DESC, id DESC LIMIT ? OFFSET ?`,
		account, status, status, from, from, until, until, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (db *DB) ArchiveCleanupCandidates(ctx context.Context, account string, now time.Time) ([]Message, error) {
	rows, err := db.sql.QueryContext(ctx, `
SELECT id,account,source_folder,current_folder,uidvalidity,uid,message_id_hash,raw_sha256,
 size_bytes,verdict,score,symbols_json,action,status,first_seen,last_scanned,
 quarantined_at,delete_after,archive_path,archive_until,feedback,feedback_intent,last_error
FROM messages
WHERE account=? AND archive_path<>'' AND archive_until IS NOT NULL AND archive_until<=?
  AND status IN ('purged','rescued','review','restored','superseded')
  AND NOT EXISTS (
    SELECT 1 FROM messages AS other
    WHERE other.archive_path=messages.archive_path
      AND other.id<>messages.id
      AND (
        other.archive_until>?
        OR other.status IN ('quarantined','pending_move','pending_learn','pending_restore','move_ambiguous','error')
      )
  )
GROUP BY archive_path
ORDER BY archive_until`,
		account, now.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (db *DB) ClearArchivePath(ctx context.Context, path string) error {
	_, err := db.sql.ExecContext(ctx,
		`UPDATE messages SET archive_path='',archive_until=NULL WHERE archive_path=?`, path)
	return err
}

func (db *DB) MessageByID(ctx context.Context, id int64) (Message, error) {
	row := db.sql.QueryRowContext(ctx, `
SELECT id,account,source_folder,current_folder,uidvalidity,uid,message_id_hash,raw_sha256,
 size_bytes,verdict,score,symbols_json,action,status,first_seen,last_scanned,
 quarantined_at,delete_after,archive_path,archive_until,feedback,feedback_intent,last_error
FROM messages WHERE id=?`, id)
	return scanMessage(row)
}

func (db *DB) Summary(ctx context.Context, since time.Time) (Summary, error) {
	var s Summary
	err := db.sql.QueryRowContext(ctx, `
SELECT
 COUNT(*),
 COALESCE(SUM(CASE WHEN dry_run=1 THEN 1 ELSE 0 END),0),
 COALESCE(SUM(CASE WHEN dry_run=0 THEN scanned ELSE 0 END),0),
 COALESCE(SUM(CASE WHEN dry_run=0 THEN kept ELSE 0 END),0),
 COALESCE(SUM(CASE WHEN dry_run=0 THEN rescued ELSE 0 END),0),
 COALESCE(SUM(CASE WHEN dry_run=0 THEN quarantined ELSE 0 END),0),
 COALESCE(SUM(CASE WHEN dry_run=0 THEN review ELSE 0 END),0),
 COALESCE(SUM(CASE WHEN dry_run=0 THEN learned_spam ELSE 0 END),0),
 COALESCE(SUM(CASE WHEN dry_run=0 THEN learned_ham ELSE 0 END),0),
 COALESCE(SUM(CASE WHEN dry_run=0 THEN purged ELSE 0 END),0),
	 COALESCE(SUM(CASE
	   WHEN dry_run=0 AND status='error' AND errors=0 THEN 1
	   WHEN dry_run=0 THEN errors
	   ELSE 0
	 END),0)
FROM runs WHERE started_at>=?`, since.UTC().Format(time.RFC3339Nano)).
		Scan(&s.Runs, &s.DryRuns, &s.Scanned, &s.Kept, &s.Rescued, &s.Quarantined,
			&s.Review, &s.LearnedSpam, &s.LearnedHam, &s.Purged, &s.Errors)
	if err != nil {
		return s, err
	}
	if err := db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM messages WHERE status='quarantined'`).Scan(&s.WaitingQuarantine); err != nil {
		return s, fmt.Errorf("podsumowanie kwarantanny: %w", err)
	}
	if err := db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM messages WHERE status='review'`).Scan(&s.WaitingReview); err != nil {
		return s, fmt.Errorf("podsumowanie ręcznej weryfikacji: %w", err)
	}
	if err := db.sql.QueryRowContext(ctx, `
SELECT COUNT(*) FROM messages
WHERE status IN ('pending_learn','pending_move','pending_restore','move_ambiguous')`).
		Scan(&s.PendingMoves); err != nil {
		return s, fmt.Errorf("podsumowanie nierozstrzygniętych operacji: %w", err)
	}
	if err := db.sql.QueryRowContext(ctx, `
SELECT COUNT(*) FROM messages
WHERE status='quarantined' AND delete_after IS NOT NULL AND delete_after<=?`,
		time.Now().UTC().Format(time.RFC3339Nano)).Scan(&s.PurgeEligible); err != nil {
		return s, fmt.Errorf("podsumowanie gotowych do usunięcia: %w", err)
	}
	return s, nil
}

func (db *DB) TrainingTotals(ctx context.Context, account string) (spam, ham int, err error) {
	err = db.sql.QueryRowContext(ctx, `
SELECT
 COUNT(DISTINCT CASE WHEN feedback='spam' THEN raw_sha256 END),
 COUNT(DISTINCT CASE WHEN feedback='ham' THEN raw_sha256 END)
FROM messages
WHERE account=?`, account).Scan(&spam, &ham)
	return spam, ham, err
}

// HasHamFeedback is deliberately independent of the current message status:
// one explicit "important" correction permanently blocks automatic deletion
// of every stored copy with the same raw SHA-256.
func (db *DB) HasHamFeedback(ctx context.Context, account, rawSHA256 string) (bool, error) {
	return db.hasFeedback(ctx, account, rawSHA256, "ham")
}

func (db *DB) HasSpamFeedback(ctx context.Context, account, rawSHA256 string) (bool, error) {
	return db.hasFeedback(ctx, account, rawSHA256, "spam")
}

// HasLearnedFeedback only deduplicates the latest confirmed class. A newer
// opposite intent makes the external model uncertain: Rspamd could have learned
// it even if its reply was lost before SQLite recorded the confirmation.
func (db *DB) HasLearnedFeedback(ctx context.Context, account, rawSHA256, feedback string) (bool, error) {
	var matches bool
	err := db.sql.QueryRowContext(ctx, `
SELECT confirmed.feedback=?
 AND (confirmed.feedback_intent='' OR confirmed.feedback_intent=confirmed.feedback)
 AND NOT EXISTS (
  SELECT 1 FROM messages newer
  WHERE newer.account=confirmed.account AND newer.raw_sha256=confirmed.raw_sha256
    AND newer.id>confirmed.id
    AND COALESCE(NULLIF(newer.feedback_intent,''),newer.feedback) IN ('ham','spam')
    AND COALESCE(NULLIF(newer.feedback_intent,''),newer.feedback)<>confirmed.feedback
 )
FROM messages confirmed
WHERE confirmed.account=? AND confirmed.raw_sha256=? AND confirmed.feedback<>''
ORDER BY confirmed.id DESC LIMIT 1`, feedback, account, rawSHA256).Scan(&matches)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return matches, err
}

// LatestFeedback follows the user's most recent explicit correction, including
// an intent whose external learn has not succeeded. Historical ham corrections
// remain available through HasHamFeedback as permanent vetoes for deletion.
func (db *DB) LatestFeedback(ctx context.Context, account, rawSHA256 string) (string, error) {
	var latest string
	err := db.sql.QueryRowContext(ctx, `
SELECT COALESCE(NULLIF(feedback_intent,''),feedback) FROM messages
WHERE account=? AND raw_sha256=? AND (feedback<>'' OR feedback_intent<>'')
ORDER BY id DESC LIMIT 1`, account, rawSHA256).Scan(&latest)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return latest, err
}

func (db *DB) hasFeedback(ctx context.Context, account, rawSHA256, feedback string) (bool, error) {
	var found int
	err := db.sql.QueryRowContext(ctx, `
SELECT EXISTS(
 SELECT 1 FROM messages
 WHERE account=? AND raw_sha256=? AND (feedback=? OR feedback_intent=?)
)`, account, rawSHA256, feedback, feedback).Scan(&found)
	return found != 0, err
}

// ActivationQuality summarizes the explicitly reviewed examples collected
// since installation. Every metric counts unique raw messages, so repeatedly
// dragging the same delivery cannot satisfy a quality gate.
func (db *DB) ActivationQuality(ctx context.Context, account string, since time.Time) (ActivationQuality, error) {
	return db.ActivationQualityUntil(ctx, account, since, time.Now().UTC())
}

// ActivationQualityUntil freezes the activation sample at the moment active
// mode was enabled. Corrections made later are handled by the rolling purge
// gate and must not permanently disable ordinary protective processing.
func (db *DB) ActivationQualityUntil(ctx context.Context, account string, since, until time.Time) (ActivationQuality, error) {
	const priorSpam = `EXISTS (
 SELECT 1 FROM messages prior
 WHERE prior.account=feedback_rows.account
   AND prior.raw_sha256=feedback_rows.raw_sha256
   AND prior.id<>feedback_rows.id
   AND prior.feedback=''
   AND prior.initial_verdict='spam'
   AND prior.first_seen<=feedback_rows.first_seen
)`
	const priorHam = `EXISTS (
 SELECT 1 FROM messages prior
 WHERE prior.account=feedback_rows.account
   AND prior.raw_sha256=feedback_rows.raw_sha256
   AND prior.id<>feedback_rows.id
   AND prior.feedback=''
   AND prior.initial_verdict='ham'
   AND prior.first_seen<=feedback_rows.first_seen
)`
	const priorReview = `EXISTS (
 SELECT 1 FROM messages prior
 WHERE prior.account=feedback_rows.account
   AND prior.raw_sha256=feedback_rows.raw_sha256
   AND prior.id<>feedback_rows.id
   AND prior.feedback=''
   AND prior.initial_action='review'
   AND prior.first_seen<=feedback_rows.first_seen
)`
	query := `
WITH feedback_rows AS (
 SELECT MIN(id) AS id,account,raw_sha256,feedback,MIN(first_seen) AS first_seen
 FROM messages
 WHERE account=? AND feedback<>'' AND first_seen>=? AND first_seen<=?
 GROUP BY account,raw_sha256,feedback
)
SELECT
 COUNT(DISTINCT CASE WHEN feedback='ham' AND ` + priorSpam + ` THEN raw_sha256 END),
 COUNT(DISTINCT CASE WHEN feedback='spam' AND ` + priorHam + ` THEN raw_sha256 END),
 COUNT(DISTINCT CASE WHEN feedback='spam' THEN raw_sha256 END),
 COUNT(DISTINCT CASE WHEN feedback='spam' AND ` + priorSpam + ` THEN raw_sha256 END),
 COUNT(DISTINCT CASE WHEN feedback='spam' AND ` + priorReview + ` THEN raw_sha256 END),
 COUNT(DISTINCT CASE WHEN feedback='spam' AND NOT (` + priorSpam + ` OR ` + priorReview + `) THEN raw_sha256 END)
FROM feedback_rows`
	var q ActivationQuality
	err := db.sql.QueryRowContext(
		ctx,
		query,
		account,
		since.UTC().Format(time.RFC3339Nano),
		until.UTC().Format(time.RFC3339Nano),
	).Scan(
		&q.FalsePositives,
		&q.FalseRescues,
		&q.SpamFeedback,
		&q.SpamPreviouslySpam,
		&q.SpamPreviouslyReview,
		&q.SpamUnexplained,
	)
	return q, err
}

// MisclassificationsSince counts explicit user corrections that contradict a
// prior automatic verdict for the same raw message.
func (db *DB) MisclassificationsSince(ctx context.Context, account string, since time.Time) (falseSpam, falseHam int, err error) {
	err = db.sql.QueryRowContext(ctx, `
SELECT
 COUNT(DISTINCT CASE WHEN feedback='ham' AND EXISTS (
   SELECT 1 FROM messages prior
   WHERE prior.account=feedback_rows.account
     AND prior.raw_sha256=feedback_rows.raw_sha256
     AND prior.id<>feedback_rows.id
     AND prior.feedback=''
     AND prior.initial_verdict='spam'
     AND prior.first_seen<=feedback_rows.first_seen
 ) THEN raw_sha256 END),
 COUNT(DISTINCT CASE WHEN feedback='spam' AND EXISTS (
   SELECT 1 FROM messages prior
   WHERE prior.account=feedback_rows.account
     AND prior.raw_sha256=feedback_rows.raw_sha256
     AND prior.id<>feedback_rows.id
     AND prior.feedback=''
     AND prior.initial_verdict='ham'
     AND prior.first_seen<=feedback_rows.first_seen
 ) THEN raw_sha256 END)
FROM messages AS feedback_rows
WHERE account=? AND feedback<>'' AND first_seen>=?`, account, since.UTC().Format(time.RFC3339Nano)).
		Scan(&falseSpam, &falseHam)
	return falseSpam, falseHam, err
}

func (db *DB) GetSetting(ctx context.Context, key string) (string, error) {
	value, _, err := db.GetSettingWithPresence(ctx, key)
	return value, err
}

// GetSettingWithPresence distinguishes a legacy database with no key from an
// explicitly cleared safety gate. An empty value can be security-significant.
func (db *DB) GetSettingWithPresence(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := db.sql.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return value, err == nil, err
}

func (db *DB) SetSetting(ctx context.Context, key, value string) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value)
	return err
}

func (db *DB) ReconcileProgress(ctx context.Context, messageID int64) (ReconcileProgress, error) {
	var p ReconcileProgress
	var sourceComplete, destinationComplete int
	var updated string
	err := db.sql.QueryRowContext(ctx, `
SELECT message_id,source_uidvalidity,source_cursor,source_complete,source_matches,source_match_uid,
 destination_uidvalidity,destination_cursor,destination_complete,destination_matches,destination_match_uid,updated_at
FROM reconciliations WHERE message_id=?`, messageID).Scan(
		&p.MessageID, &p.SourceUIDValidity, &p.SourceCursor, &sourceComplete,
		&p.SourceMatches, &p.SourceMatchUID, &p.DestinationUIDValidity,
		&p.DestinationCursor, &destinationComplete, &p.DestinationMatches,
		&p.DestinationMatchUID, &updated,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ReconcileProgress{MessageID: messageID}, nil
	}
	if err != nil {
		return p, err
	}
	p.SourceComplete = sourceComplete != 0
	p.DestinationComplete = destinationComplete != 0
	p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return p, nil
}

func (db *DB) SaveReconcileProgress(ctx context.Context, p ReconcileProgress) error {
	if p.MessageID <= 0 {
		return errors.New("postęp uzgadniania nie ma identyfikatora wiadomości")
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = time.Now().UTC()
	}
	_, err := db.sql.ExecContext(ctx, `
INSERT INTO reconciliations(
 message_id,source_uidvalidity,source_cursor,source_complete,source_matches,source_match_uid,
 destination_uidvalidity,destination_cursor,destination_complete,destination_matches,destination_match_uid,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(message_id) DO UPDATE SET
 source_uidvalidity=excluded.source_uidvalidity,source_cursor=excluded.source_cursor,
 source_complete=excluded.source_complete,source_matches=excluded.source_matches,
 source_match_uid=excluded.source_match_uid,
 destination_uidvalidity=excluded.destination_uidvalidity,destination_cursor=excluded.destination_cursor,
 destination_complete=excluded.destination_complete,destination_matches=excluded.destination_matches,
 destination_match_uid=excluded.destination_match_uid,updated_at=excluded.updated_at`,
		p.MessageID, p.SourceUIDValidity, p.SourceCursor, boolInt(p.SourceComplete),
		p.SourceMatches, p.SourceMatchUID, p.DestinationUIDValidity, p.DestinationCursor,
		boolInt(p.DestinationComplete), p.DestinationMatches, p.DestinationMatchUID,
		formatTime(p.UpdatedAt))
	return err
}

func (db *DB) DeleteReconcileProgress(ctx context.Context, messageID int64) error {
	_, err := db.sql.ExecContext(ctx, `DELETE FROM reconciliations WHERE message_id=?`, messageID)
	return err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanMessage(row scanner) (Message, error) {
	var m Message
	var symbolsJSON, firstSeen, lastScanned string
	var quarantinedAt, deleteAfter, archiveUntil sql.NullString
	err := row.Scan(&m.ID, &m.Account, &m.SourceFolder, &m.CurrentFolder, &m.UIDValidity,
		&m.UID, &m.MessageIDHash, &m.RawSHA256, &m.SizeBytes, &m.Verdict, &m.Score,
		&symbolsJSON, &m.Action, &m.Status, &firstSeen, &lastScanned, &quarantinedAt,
		&deleteAfter, &m.ArchivePath, &archiveUntil, &m.Feedback, &m.FeedbackIntent, &m.LastError)
	if err != nil {
		return m, err
	}
	_ = json.Unmarshal([]byte(symbolsJSON), &m.Symbols)
	m.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeen)
	m.LastScanned, _ = time.Parse(time.RFC3339Nano, lastScanned)
	m.QuarantinedAt = parseNullTime(quarantinedAt)
	m.DeleteAfter = parseNullTime(deleteAfter)
	m.ArchiveUntil = parseNullTime(archiveUntil)
	return m, nil
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func formatTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}
func parseNullTime(v sql.NullString) *time.Time {
	if !v.Valid {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, v.String)
	if err != nil {
		return nil
	}
	return &t
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func nullableID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}
