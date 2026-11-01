package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestDeploymentChangeRevokesAuthorizationAndPreservesModelHistory(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "guardian.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for key, value := range map[string]string{"first_dry_run_completed_at": "old-proof", "active_since": "old-active", "bayes_spam_revision_highwater": "321", "adverse_history": "keep"} {
		if err := db.SetSetting(ctx, key, value); err != nil {
			t.Fatal(err)
		}
	}
	for _, identity := range []string{"host-a", "host-b"} {
		if err := db.BindDeployment(ctx, identity, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := db.RequireOperationalAuthorization(ctx); err == nil {
			t.Fatal("new deployment inherited old operational permission")
		}
		if err := db.SetSetting(ctx, "first_dry_run_completed_at", "new-proof"); err != nil {
			t.Fatal(err)
		}
		if err := db.BindDeployment(ctx, identity, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := db.RequireOperationalAuthorization(ctx); err != nil {
			t.Fatal("routine restart revoked acceptance", err)
		}
	}
	for key, want := range map[string]string{"bayes_spam_revision_highwater": "321", "adverse_history": "keep"} {
		if got, err := db.GetSetting(ctx, key); err != nil || got != want {
			t.Fatalf("history changed: %s=%s, %v", key, got, err)
		}
	}
}
