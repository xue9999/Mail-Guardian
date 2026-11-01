package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/store"
)

func TestChangedEndpointCannotRunOrRestoreExistingJournal(t *testing.T) {
	ctx, now := context.Background(), time.Now().UTC()
	e, mail, db, scanner := newTestEngine(t, now, false)
	uid := mail.add("INBOX", mailMessage("pending", now))
	message := mail.folders["INBOX"][uid]
	id := insertPending(t, db, e.Config.Account.Email, message, "quarantine", now)
	if err := db.BindConfiguration(ctx, e.Config, now); err != nil {
		t.Fatal(err)
	}
	resolved, err := e.Config.ResolveIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e.Config = resolved
	e.Config.Account.Provider, e.Config.Account.Host = "custom", "imap.example.org"
	if _, err := e.Run(ctx, RunOptions{}); !errors.Is(err, store.ErrMailboxIdentity) {
		t.Fatalf("live run reached wrong mailbox: %v", err)
	}
	if _, err := e.Run(ctx, RunOptions{DryRun: true}); !errors.Is(err, store.ErrMailboxIdentity) {
		t.Fatalf("dry-run reused old journal: %v", err)
	}
	if err := e.Restore(ctx, id); !errors.Is(err, store.ErrMailboxIdentity) {
		t.Fatalf("restore reached wrong mailbox: %v", err)
	}
	if mail.count("INBOX") != 1 || scanner.scanCalls != 0 || scanner.learnCalls != 0 {
		t.Fatal("mail accessed after identity mismatch")
	}
	stored, err := db.MessageByID(ctx, id)
	if err != nil || stored.Status != "pending_move" {
		t.Fatal("pending state lost")
	}
}

func TestFolderChangeBlocksMutationUntilFreshDryRun(t *testing.T) {
	ctx, now := context.Background(), time.Now().UTC()
	e, mail, db, scanner := newTestEngine(t, now, false)
	if err := db.BindConfiguration(ctx, e.Config, now); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, "first_dry_run_completed_at", "accepted"); err != nil {
		t.Fatal(err)
	}
	e.Config.Folders.ServerSpam = "Junk"
	mail.add("Junk", mailMessage("spam", now))
	if _, err := e.Run(ctx, RunOptions{}); err == nil {
		t.Fatal("changed layout mutated without dry-run")
	}
	if scanner.scanCalls != 0 || mail.count("Junk") != 1 {
		t.Fatal("work began before authorization")
	}
	if _, err := e.Run(ctx, RunOptions{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if mail.count("Junk") != 1 || scanner.learnCalls != 0 {
		t.Fatal("dry-run mutated mail")
	}
}
