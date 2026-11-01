package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/store"
)

func TestProtectionProgressFailsClosedAndDistinguishesTimeFromQuality(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := config.Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Safety.ProtectDays = 14
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, installed, reset string
		remaining              int
		period                 bool
	}{
		{"missing", "", "", 14, false},
		{"invalid", "broken", "", 14, false},
		{"future", now.Add(time.Hour).Format(time.RFC3339), "", 14, false},
		{"one second left", now.Add(-14*24*time.Hour + time.Second).Format(time.RFC3339), "", 1, false},
		{"period complete without feedback", now.Add(-14 * 24 * time.Hour).Format(time.RFC3339), "", 0, true},
		{"new observation", now.Add(-30 * 24 * time.Hour).Format(time.RFC3339), now.Add(-2 * 24 * time.Hour).Format(time.RFC3339), 12, false},
		{"invalid reset", now.Add(-30 * 24 * time.Hour).Format(time.RFC3339), "broken", 14, false},
		{"reset before installation", now.Add(-30 * 24 * time.Hour).Format(time.RFC3339), now.Add(-40 * 24 * time.Hour).Format(time.RFC3339), 14, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := db.SetSetting(context.Background(), "installed_at", tc.installed); err != nil {
				t.Fatal(err)
			}
			if err := db.SetSetting(context.Background(), "protect_since", tc.reset); err != nil {
				t.Fatal(err)
			}
			got := protectionProgress(cfg, db, now)
			if got.Ready || got.QualityReady || got.RemainingDays != tc.remaining || got.PeriodComplete != tc.period || got.Message == "" {
				t.Fatalf("unexpected progress: %+v", got)
			}
		})
	}
}

func TestCompletedObservationExplainsHistoricalBlockInsteadOfPromisingMoreWaiting(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, now := context.Background(), time.Now().UTC()
	cfg := config.Default()
	cfg.Account.Email = "test@o2.pl"
	if err := db.SetSetting(ctx, "installed_at", now.Add(-20*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpsertMessage(ctx, &store.Message{Account: cfg.Account.Email, CurrentFolder: "training", SourceFolder: "training", UIDValidity: 1, UID: 1, RawSHA256: "unknown-history", MessageIDHash: "unknown-history", Verdict: "spam", Action: "learn_spam", Status: "quarantined", Feedback: "spam", FirstSeen: now.Add(-time.Hour), LastScanned: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	p := protectionProgress(cfg, db, now)
	if !p.PeriodComplete || p.Ready || !strings.Contains(p.Message, "Samo czekanie ani dalsza nauka nie usuną tych blokad") {
		t.Fatalf("misleading readiness message: %+v", p)
	}
}

func TestAPIRunResultUsesExactRunAndNeverExportsMailMetadata(t *testing.T) {
	run := &store.Run{ID: 1234, DryRun: true, Scanned: 8, Kept: 6, Review: 2, Errors: 1}
	raw, err := json.Marshal(apiRunResult(run, nil))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Completed bool
		Summary   struct {
			DryRun                  bool `json:"dry_run"`
			Scanned, Review, Errors int
		}
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Completed || !got.Summary.DryRun || got.Summary.Scanned != 8 || got.Summary.Review != 2 || got.Summary.Errors != 1 {
		t.Fatalf("incorrect run: %s", raw)
	}
	for _, forbidden := range []string{"1234", "subject", "from", "account", "StartedAt"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("metadata leak: %s", raw)
		}
	}
	failed := apiRunResult(run, errors.New("failed"))
	if failed["completed"] != false || failed["summary"] != nil {
		t.Fatalf("failed run reported success: %+v", failed)
	}
}

func TestPartialDryRunCannotAuthorizeFirstAutomationOrReplaceEarlierProof(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	for _, run := range []*store.Run{nil, {DryRun: true, Errors: 2}, {DryRun: false}} {
		if err := recordSuccessfulDryRun(db, run, now); err != nil {
			t.Fatal(err)
		}
		if _, exists, err := db.GetSettingWithPresence(ctx, "first_dry_run_completed_at"); err != nil || exists {
			t.Fatalf("incomplete or live scan authorized first automation: run=%+v exists=%v err=%v", run, exists, err)
		}
	}
	if err := recordSuccessfulDryRun(db, &store.Run{DryRun: true}, now); err != nil {
		t.Fatal(err)
	}
	if err := recordSuccessfulDryRun(db, &store.Run{DryRun: true, Errors: 1}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	proof, err := db.GetSetting(ctx, "first_dry_run_completed_at")
	if err != nil || proof != now.Format(time.RFC3339Nano) {
		t.Fatalf("partial retry replaced the previous successful proof: %q err=%v", proof, err)
	}
}

func TestCLIAndAPIRequireAnErrorFreeRun(t *testing.T) {
	for _, run := range []*store.Run{nil, {Errors: 1}, {DryRun: true, Errors: 2}} {
		if requireSuccessfulRun(run, nil) == nil || apiRunResult(run, nil)["completed"] != false {
			t.Fatalf("incomplete run reported success: %+v", run)
		}
	}
	run := &store.Run{Scanned: 2}
	if requireSuccessfulRun(run, nil) != nil || apiRunResult(run, nil)["completed"] != true {
		t.Fatal("clean run was rejected")
	}
	want := errors.New("interrupted")
	if !errors.Is(requireSuccessfulRun(run, want), want) {
		t.Fatal("underlying failure was lost")
	}
}

func TestProtectionProgressReadyAgreesWithTheActivationGate(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := config.Default()
	cfg.Account.Email = "test@o2.pl"
	now := time.Now().UTC()
	start := now.Add(-15 * 24 * time.Hour).Truncate(time.Second)
	if err := db.SetSetting(context.Background(), "installed_at", start.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	seedReadyActivationQuality(t, db, cfg.Account.Email, start)
	got := protectionProgress(cfg, db, now)
	if !got.Ready || !got.PeriodComplete || !got.QualityReady || got.RemainingDays != 0 {
		t.Fatalf("ready gate not reflected: %+v", got)
	}
	// A new observation period cannot inherit the previous period's readiness.
	if err := db.SetSetting(context.Background(), "protect_since", now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if got := protectionProgress(cfg, db, now); got.Ready || got.PeriodComplete {
		t.Fatalf("reset bypassed observation: %+v", got)
	}
}

func TestQualityChecklistAgreesWithAuthoritativeGate(t *testing.T) {
	for _, q := range []store.ActivationQuality{
		{}, {SpamFeedback: 10, SpamPreviouslySpam: 9},
		{SpamFeedback: 10, SpamPreviouslySpam: 8},
		{SpamFeedback: 10, SpamPreviouslySpam: 10, FalsePositives: 1},
		{SpamFeedback: 10, SpamPreviouslySpam: 10, FalseRescues: 1},
		{SpamFeedback: 10, SpamPreviouslySpam: 10, SpamUnexplained: 1},
	} {
		all := true
		checks := qualityChecks(q)
		if len(checks) != 5 {
			t.Fatalf("missing conditions: %+v", checks)
		}
		for _, check := range checks {
			all = all && check.Passed
			if check.Detail == "" {
				t.Fatal("missing explanation")
			}
		}
		if all != q.Ready() {
			t.Fatalf("checklist contradicts activation gate: %+v", q)
		}
	}
}
