package store

import (
	"context"
	"encoding/json"
	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/qualification"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCurrentQualificationPreservesHistoryAndRevokesAfterNewFalsePositive(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := config.Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
	cfg.Rspamd.SpamScore = 6
	cfg, err = cfg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	ctx, now := context.Background(), time.Now().UTC()
	if err := db.BindConfiguration(ctx, cfg, now.Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, "protect_since", now.Add(-20*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../qualification/testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	var r qualification.Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	r.AuthorizationFingerprint = cfg.AuthorizationFingerprint()
	r.CreatedAt = now.Add(-time.Hour)
	if err := db.SaveQualification(ctx, cfg, r, now); err != nil {
		t.Fatal(err)
	}
	got, err := db.CurrentQualification(ctx, cfg, now)
	if err != nil || got == nil {
		t.Fatalf("new qualification missing: %v", err)
	}
	protect, _ := db.GetSetting(ctx, "protect_since")
	if protect != now.Add(-20*24*time.Hour).Format(time.RFC3339) {
		t.Fatal("qualification reset historical observation")
	}
	prior := &Message{Account: cfg.Account.Email, SourceFolder: "inbox", CurrentFolder: "AI-Kwarantanna", UIDValidity: 1, UID: 1, RawSHA256: "wrongly-moved", MessageIDHash: "wrongly-moved", Verdict: "spam", Action: "quarantined", Status: "superseded", FirstSeen: now.Add(-30 * time.Minute), LastScanned: now.Add(-30 * time.Minute)}
	if _, err := db.UpsertMessage(ctx, prior); err != nil {
		t.Fatal(err)
	}
	correction := *prior
	correction.ID = 0
	correction.UID = 2
	correction.Verdict = "ham"
	correction.Action = "learn_ham"
	correction.Status = "rescued"
	correction.Feedback = "ham"
	correction.FeedbackIntent = "ham"
	correction.FirstSeen = now
	correction.LastScanned = now
	if _, err := db.UpsertMessage(ctx, &correction); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CurrentQualification(ctx, cfg, now); err == nil {
		t.Fatal("new false positive did not revoke qualification")
	}
}
