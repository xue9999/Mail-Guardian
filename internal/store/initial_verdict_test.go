package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRescanCannotRewriteHistoricalActivationEvidence(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	prior := &Message{Account: "test@o2.pl", SourceFolder: "inbox", CurrentFolder: "INBOX", UIDValidity: 1, UID: 1, MessageIDHash: "same", RawSHA256: "same", Verdict: "ham", Action: "keep", Status: "observed", FirstSeen: now.Add(-time.Hour), LastScanned: now.Add(-time.Hour)}
	if _, err := db.UpsertMessage(ctx, prior); err != nil {
		t.Fatal(err)
	}
	correction := *prior
	correction.ID, correction.UID = 0, 2
	correction.CurrentFolder, correction.Verdict, correction.Action, correction.Status, correction.Feedback = "AI-Kwarantanna", "spam", "learn_spam", "quarantined", "spam"
	correction.FirstSeen, correction.LastScanned = now, now
	if _, err := db.UpsertMessage(ctx, &correction); err != nil {
		t.Fatal(err)
	}
	before, err := db.ActivationQuality(ctx, prior.Account, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	prior.Verdict, prior.LastScanned = "spam", now
	if _, err := db.UpsertMessage(ctx, prior); err != nil {
		t.Fatal(err)
	}
	after, err := db.ActivationQuality(ctx, prior.Account, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if before != after || after.FalseRescues != 1 || after.SpamPreviouslySpam != 0 || after.Ready() {
		t.Fatalf("rescan laundered historical evidence: before=%+v after=%+v", before, after)
	}
}

func TestMigrationPreservesLegacyVerdictAcrossReopenAndRescan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, now := context.Background(), time.Now().UTC()
	msg := &Message{Account: "test@o2.pl", SourceFolder: "inbox", CurrentFolder: "INBOX", UIDValidity: 1, UID: 1, MessageIDHash: "legacy", RawSHA256: "legacy", Verdict: "uncertain", Action: "keep", Status: "observed", FirstSeen: now, LastScanned: now}
	if _, err := db.UpsertMessage(ctx, msg); err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"initial_verdict", "initial_action"} {
		if _, err := db.sql.ExecContext(ctx, "ALTER TABLE messages DROP COLUMN "+column); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	msg.Verdict = "spam"
	if _, err := db.UpsertMessage(ctx, msg); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var verdict, action string
	if err := db.sql.QueryRowContext(ctx, "SELECT initial_verdict,initial_action FROM messages WHERE id=?", msg.ID).Scan(&verdict, &action); err != nil {
		t.Fatal(err)
	}
	if verdict != "uncertain" || action != "keep" {
		t.Fatalf("migration changed the original verdict: %s/%s", verdict, action)
	}
}
