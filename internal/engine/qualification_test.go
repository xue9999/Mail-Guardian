package engine

import (
	"context"
	"encoding/json"
	"github.com/o2-mail-guardian/guardian/internal/archive"
	"github.com/o2-mail-guardian/guardian/internal/qualification"
	"github.com/o2-mail-guardian/guardian/internal/store"
	"os"
	"testing"
	"time"
)

func TestDisjointQualificationEnablesSortingWithoutErasingOldMisses(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, _ := newTestEngine(t, now, true)
	e.Config.Rspamd.SpamScore = 6
	ctx := context.Background()
	if _, err := db.UpsertMessage(ctx, &store.Message{Account: e.Config.Account.Email, SourceFolder: "training", CurrentFolder: "old-feedback", UIDValidity: 1, UID: 1, RawSHA256: "historical-miss", MessageIDHash: "historical-miss", Verdict: "spam", Action: "learn_spam", Status: "quarantined", Feedback: "spam", FirstSeen: now.Add(-2 * time.Hour), LastScanned: now.Add(-2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	mail.add("INBOX", mailMessage("spam-current", now))
	if _, err := e.Run(ctx, RunOptions{}); err == nil {
		t.Fatal("lower threshold activated without independent qualification")
	}
	data, err := os.ReadFile("../qualification/testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	var r qualification.Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	cfg, err := e.Config.ResolveIdentity()
	if err != nil {
		t.Fatal(err)
	}
	r.AuthorizationFingerprint = cfg.AuthorizationFingerprint()
	r.CreatedAt = now.Add(-time.Hour)
	if err := db.SaveQualification(ctx, e.Config, r, now); err != nil {
		t.Fatal(err)
	}
	run, err := e.Run(ctx, RunOptions{})
	if err != nil || run.Errors != 0 || run.Quarantined != 1 || mail.count("INBOX") != 0 {
		t.Fatalf("qualified model did not sort: %+v %v", run, err)
	}
	quality, err := db.ActivationQuality(ctx, e.Config.Account.Email, now.Add(-30*24*time.Hour))
	if err != nil || quality.SpamUnexplained == 0 || quality.Ready() {
		t.Fatalf("history was laundered by qualification: %+v %v", quality, err)
	}
}

func TestRevokedQualificationStillProcessesLaterExplicitCorrections(t *testing.T) {
	now, ctx := time.Now().UTC(), context.Background()
	e, mail, db, scanner := newTestEngine(t, now, true)
	e.Config.Rspamd.SpamScore = 6
	if err := db.BindConfiguration(ctx, e.Config, now); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../qualification/testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	var report qualification.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	resolved, err := e.Config.ResolveIdentity()
	if err != nil {
		t.Fatal(err)
	}
	report.AuthorizationFingerprint = resolved.AuthorizationFingerprint()
	report.CreatedAt = now.Add(-time.Hour)
	if err := db.SaveQualification(ctx, e.Config, report, now); err != nil {
		t.Fatal(err)
	}
	wronglyQuarantined := mailMessage("ham-corrected-after-quarantine", now)
	if _, err := db.UpsertMessage(ctx, &store.Message{
		Account: e.Config.Account.Email, SourceFolder: sourceInbox, CurrentFolder: "old-quarantine",
		UIDValidity: 99, UID: 1, RawSHA256: archive.SHA256(wronglyQuarantined.Raw),
		Verdict: "spam", Action: "quarantined", Status: "superseded",
		FirstSeen: now.Add(-30 * time.Minute), LastScanned: now.Add(-30 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	mail.add(e.Config.Folders.TrainHam, wronglyQuarantined)
	inboxUID := mail.add(e.Config.Folders.Inbox, mailMessage("spam-automatic-must-wait", now))
	spamUID := mail.add(e.Config.Folders.ServerSpam, mailMessage("ham-automatic-must-wait", now))
	first, err := e.Run(ctx, RunOptions{})
	if err == nil || first.LearnedHam != 1 || first.Rescued != 1 {
		t.Fatalf("first correction did not revoke automatic sorting after completing: run=%+v err=%v", first, err)
	}
	if _, err := db.CurrentQualification(ctx, e.Config, now); err == nil {
		t.Fatal("wrong automatic move did not revoke qualification")
	}
	pendingInbox := insertPending(t, db, e.Config.Account.Email, mail.folders[e.Config.Folders.Inbox][inboxUID], "quarantined", now)
	pendingRescue := insertPending(t, db, e.Config.Account.Email, mail.folders[e.Config.Folders.ServerSpam][spamUID], "rescued", now)
	mail.add(e.Config.Folders.TrainSpam, mailMessage("spam-later-explicit-correction", now))
	second, err := e.Run(ctx, RunOptions{})
	if err == nil || second.LearnedSpam != 1 || second.Quarantined != 1 {
		t.Fatalf("revoked qualification blocked a later explicit correction: run=%+v err=%v", second, err)
	}
	if scanner.learnCalls != 2 || scanner.scanCalls != 0 || mail.count(e.Config.Folders.TrainHam) != 0 || mail.count(e.Config.Folders.TrainSpam) != 0 {
		t.Fatalf("unexpected training or automatic scanning: learns=%d scans=%d", scanner.learnCalls, scanner.scanCalls)
	}
	if _, ok := mail.folders[e.Config.Folders.Inbox][inboxUID]; !ok {
		t.Fatal("automatic inbox quarantine continued without qualification")
	}
	if _, ok := mail.folders[e.Config.Folders.ServerSpam][spamUID]; !ok {
		t.Fatal("automatic rescue continued without qualification")
	}
	for _, id := range []int64{pendingInbox, pendingRescue} {
		pending, err := db.MessageByID(ctx, id)
		if err != nil || pending.Status != "pending_move" {
			t.Fatalf("automatic pending move was reconciled without qualification: %+v %v", pending, err)
		}
	}
	if e.Config.Safety.Mode != "active" || e.Config.Safety.PurgeEnabled {
		t.Fatal("processing explicit corrections silently changed the configured mode")
	}
}

func TestReconciliationWithAutomaticMovesBlockedStillFinishesExplicitCorrection(t *testing.T) {
	now, ctx := time.Now().UTC(), context.Background()
	e, mail, db, _ := newTestEngine(t, now, true)
	uid := mail.add(e.Config.Folders.TrainSpam, mailMessage("spam-explicit-pending", now))
	message := mail.folders[e.Config.Folders.TrainSpam][uid]
	id := insertPending(t, db, e.Config.Account.Email, message, "learn_spam", now)
	if err := db.MarkFeedbackIntent(ctx, id, "spam"); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkLearned(ctx, id, "spam"); err != nil {
		t.Fatal(err)
	}
	if err := e.reconcilePendingWithPolicy(ctx, false); err != nil {
		t.Fatal(err)
	}
	finished, err := db.MessageByID(ctx, id)
	if err != nil || finished.Status != "quarantined" || mail.count(e.Config.Folders.TrainSpam) != 0 || mail.count(e.Config.Folders.Quarantine) != 1 {
		t.Fatalf("explicit pending correction was blocked with automatic moves: %+v %v", finished, err)
	}
}
