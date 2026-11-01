package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/qualification"
	"github.com/o2-mail-guardian/guardian/internal/store"
)

func policyAdoptionReviewFixture(t *testing.T) (config.Config, *store.DB, time.Time) {
	t.Helper()
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	cfg := config.Default()
	cfg.Account.Email = "fixture@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
	cfg.Runtime.DataDir = t.TempDir()
	cfg.Safety.Mode, cfg.Safety.PurgeEnabled = "active", false
	cfg.Rspamd.SpamScore = 6
	var err error
	cfg, err = cfg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(cfg.Runtime.DataDir, "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.BindConfiguration(ctx, cfg, now); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"installed_at":                  now.Add(-45 * 24 * time.Hour).Format(time.RFC3339),
		"protect_since":                 now.Add(-40 * 24 * time.Hour).Format(time.RFC3339),
		"active_since":                  now.Add(-15 * 24 * time.Hour).Format(time.RFC3339),
		"deployment_identity":           "",
		"first_dry_run_completed_at":    "source-dry-run-proof",
		"bayes_spam_revision_highwater": "264",
		"bayes_ham_revision_highwater":  "162",
		"retained_history":              "original evidence",
	} {
		if err := db.SetSetting(ctx, key, value); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile("../../internal/qualification/testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	var report qualification.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	report.AuthorizationFingerprint = cfg.AuthorizationFingerprint()
	report.CreatedAt = now.Add(-24 * time.Hour)
	if err := db.SaveQualification(ctx, cfg, report, now); err != nil {
		t.Fatal(err)
	}
	run, err := db.BeginRun(ctx, "run", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.FinishRun(ctx, run, nil); err != nil {
		t.Fatal(err)
	}
	return cfg, db, now
}

func adoptionReviewSettings(t *testing.T, db *store.DB) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, key := range []string{"installed_at", "protect_since", "active_since", "deployment_identity", "first_dry_run_completed_at", "configuration_dry_run_required", "bayes_spam_revision_highwater", "bayes_ham_revision_highwater", "retained_history", "filter_qualification_v1"} {
		value, err := db.GetSetting(context.Background(), key)
		if err != nil {
			t.Fatal(err)
		}
		result[key] = value
	}
	return result
}

func TestPolicyAdoptionReviewPreservesHistoryButRevokesSourceDryRun(t *testing.T) {
	cfg, db, now := policyAdoptionReviewFixture(t)
	ctx := context.Background()
	before := adoptionReviewSettings(t, db)
	if err := adoptPolicyState(ctx, cfg, db, "destination-owner", now); err != nil {
		t.Fatal(err)
	}
	// The first ordinary runtime opening must not reset factual protection or
	// activation dates after the explicit handover has bound this exact host.
	if err := db.BindDeployment(ctx, "destination-owner", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	after := adoptionReviewSettings(t, db)
	for key, value := range before {
		switch key {
		case "deployment_identity":
			value = "destination-owner"
		case "first_dry_run_completed_at":
			value = ""
		case "configuration_dry_run_required":
			value = "1"
		}
		if after[key] != value {
			t.Fatalf("%s changed unexpectedly: got %q, want %q", key, after[key], value)
		}
	}
	if err := db.RequireOperationalAuthorization(ctx); err == nil {
		t.Fatal("handover reused source dry-run authority")
	}
	if err := recordSuccessfulDryRun(db, &store.Run{DryRun: true, Status: "ok"}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := db.RequireOperationalAuthorization(ctx); err != nil {
		t.Fatalf("fresh destination dry-run did not authorize the exact adopted configuration: %v", err)
	}
}

func TestPolicyAdoptionReviewRejectsUnsafeHistoryWithoutChangingAuthority(t *testing.T) {
	for _, name := range []string{"already-bound", "missing-qualification", "changed-threshold", "future-activation", "pending-move", "model-checkpoint", "model-rollback", "latest-actual-failure", "changed-folder", "purge-enabled"} {
		t.Run(name, func(t *testing.T) {
			cfg, db, now := policyAdoptionReviewFixture(t)
			ctx := context.Background()
			set := func(key, value string) {
				if err := db.SetSetting(ctx, key, value); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "already-bound":
				set("deployment_identity", "earlier-owner")
			case "missing-qualification":
				set("filter_qualification_v1", "")
			case "changed-threshold":
				cfg.Rspamd.SpamScore = 7
			case "future-activation":
				set("active_since", now.Add(time.Hour).Format(time.RFC3339))
			case "pending-move":
				_, err := db.UpsertMessage(ctx, &store.Message{Account: cfg.Account.Email, SourceFolder: "INBOX", CurrentFolder: "INBOX", UIDValidity: 1, UID: 1, MessageIDHash: "pending", RawSHA256: "pending", Status: "pending_move", Action: "quarantined", FirstSeen: now, LastScanned: now})
				if err != nil {
					t.Fatal(err)
				}
			case "model-checkpoint":
				set("model_checkpoint_required", "1")
			case "model-rollback":
				set("bayes_rollback_at", now.Format(time.RFC3339))
			case "latest-actual-failure":
				run, err := db.BeginRun(ctx, "run", false)
				if err != nil {
					t.Fatal(err)
				}
				if err := db.FinishRun(ctx, run, errors.New("fixture failure")); err != nil {
					t.Fatal(err)
				}
				// A newer successful preview cannot conceal a failed real run.
				run, err = db.BeginRun(ctx, "run", true)
				if err != nil {
					t.Fatal(err)
				}
				if err := db.FinishRun(ctx, run, nil); err != nil {
					t.Fatal(err)
				}
			case "changed-folder":
				cfg.Folders.Review = "Different-review"
			case "purge-enabled":
				cfg.Safety.PurgeEnabled = true
			}
			before := adoptionReviewSettings(t, db)
			if err := adoptPolicyState(ctx, cfg, db, "destination-owner", now); err == nil {
				t.Fatal("unsafe policy history accepted")
			}
			after := adoptionReviewSettings(t, db)
			for key, value := range before {
				if after[key] != value {
					t.Fatalf("rejected adoption changed %s", key)
				}
			}
		})
	}
}
