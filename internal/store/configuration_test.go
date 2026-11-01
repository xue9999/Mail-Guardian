package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/config"
)

func bindingFixture(t *testing.T) (*DB, config.Config) {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "guardian.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c := config.Default()
	c.Account.Email, c.Folders.ServerSpam = "me@o2.pl", "Spam"
	c, err = c.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	return db, c
}

func TestMailboxIdentityCannotRedirectExistingPendingState(t *testing.T) {
	db, cfg := bindingFixture(t)
	ctx, now := context.Background(), time.Now().UTC()
	if err := db.BindConfiguration(ctx, cfg, now); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, "first_dry_run_completed_at", "accepted"); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*config.Config){
		func(c *config.Config) { c.Account.Provider, c.Account.Host = "custom", "imap.example.org" },
		func(c *config.Config) { c.Account.Username = "other-login" },
		func(c *config.Config) { c.Account.Email = "other@o2.pl" },
		func(c *config.Config) { c.Account.ID = "0123456789abcdef0123456789abcdef" },
		func(c *config.Config) { c.InstanceID = "0123456789abcdef0123456789abcdef" },
	} {
		other := cfg
		mutate(&other)
		if err := db.BindConfiguration(ctx, other, now); !errors.Is(err, ErrMailboxIdentity) {
			t.Fatalf("mailbox redirect accepted: %v", err)
		}
		if _, err := db.DryRunAuthorizedFor(ctx, other); !errors.Is(err, ErrMailboxIdentity) {
			t.Fatalf("foreign config authorized: %v", err)
		}
	}
	if accepted, err := db.DryRunAuthorizedFor(ctx, cfg); err != nil || !accepted {
		t.Fatalf("rejected redirect damaged original authorization: %v", err)
	}
}

func TestFolderChangeRevokesPermissionAndRetainsHistoryAcrossRestart(t *testing.T) {
	db, cfg := bindingFixture(t)
	ctx, now := context.Background(), time.Now().UTC()
	if err := db.BindConfiguration(ctx, cfg, now); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"first_dry_run_completed_at": "accepted", "protect_since": "old-window", "active_since": "old-active", "bayes_spam_revision_highwater": "247"} {
		if err := db.SetSetting(ctx, key, value); err != nil {
			t.Fatal(err)
		}
	}
	run, err := db.BeginRun(ctx, "run", false)
	if err != nil {
		t.Fatal(err)
	}
	run.Errors = 2
	if err := db.FinishRun(ctx, run, errors.New("quality history")); err != nil {
		t.Fatal(err)
	}
	changed := cfg
	changed.Folders.ServerSpam = "Junk"
	if ok, err := db.DryRunAuthorizedFor(ctx, changed); err != nil || ok {
		t.Fatalf("stale layout authorized: %v", err)
	}
	proof, _ := db.GetSetting(ctx, "first_dry_run_completed_at")
	if proof != "accepted" {
		t.Fatal("status mutated worker state")
	}
	if err := db.BindConfiguration(ctx, changed, now); err != nil {
		t.Fatal(err)
	}
	if err := db.RequireOperationalAuthorization(ctx); err == nil {
		t.Fatal("live operations allowed before fresh dry-run")
	}
	for key, want := range map[string]string{"first_dry_run_completed_at": "", "active_since": "", "protect_since": now.Format(time.RFC3339Nano), "bayes_spam_revision_highwater": "247"} {
		got, err := db.GetSetting(ctx, key)
		if err != nil || got != want {
			t.Fatalf("%s=%q want %q (%v)", key, got, want, err)
		}
	}
	if err := db.BindConfiguration(ctx, changed, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	window, _ := db.GetSetting(ctx, "protect_since")
	if window != now.Format(time.RFC3339Nano) {
		t.Fatal("restart reset observation history")
	}
	status, count, err := db.LatestLiveRunOutcome(ctx)
	if err != nil || status != "error" || count != 2 {
		t.Fatal("historical error erased")
	}
	if err := db.SetSetting(ctx, "first_dry_run_completed_at", "fresh"); err != nil {
		t.Fatal(err)
	}
	if err := db.RequireOperationalAuthorization(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyAdoptionCannotAuthorizeCustomOrNewMailbox(t *testing.T) {
	db, cfg := bindingFixture(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "first_dry_run_completed_at", "old-proof"); err != nil {
		t.Fatal(err)
	}
	other := cfg
	other.Account.Provider, other.Account.Host = "custom", "imap.example.org"
	if err := db.BindConfiguration(ctx, other, time.Now()); !errors.Is(err, ErrMailboxIdentity) {
		t.Fatalf("legacy state adopted by custom endpoint: %v", err)
	}
	if err := db.BindConfiguration(ctx, cfg, time.Now()); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.DryRunAuthorizedFor(ctx, cfg); err != nil || !ok {
		t.Fatalf("legacy proof not preserved: %v", err)
	}
}

func TestNewInstanceNeedsItsOwnSuccessfulDryRun(t *testing.T) {
	db, _ := bindingFixture(t)
	cfg, err := config.NewInstance()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Account.Email, cfg.Folders.ServerSpam = "me@example.org", "Spam"
	cfg.Account.Provider, cfg.Account.Host = "custom", "imap.example.org"
	ctx := context.Background()
	if err := db.BindConfiguration(ctx, cfg, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.RequireOperationalAuthorization(ctx); err == nil {
		t.Fatal("new instance inherited permission")
	}
	if ok, err := db.DryRunAuthorizedFor(ctx, cfg); err != nil || ok {
		t.Fatalf("new instance authorized: %v", err)
	}
}

func TestIncompleteBindingCannotSilentlyAdoptCurrentLayout(t *testing.T) {
	db, cfg := bindingFixture(t)
	ctx := context.Background()
	if err := db.BindConfiguration(ctx, cfg, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `DELETE FROM settings WHERE key='authorization_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	if err := db.BindConfiguration(ctx, cfg, time.Now()); err == nil {
		t.Fatal("incomplete binding authorized a layout")
	}
}
