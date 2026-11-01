package engine

import (
	"context"
	"testing"
	"time"

	"github.com/o2-mail-guardian/guardian/internal/archive"
)

func TestMalformedExplicitCorrectionsPreserveOriginalWithoutBayesLearning(t *testing.T) {
	for _, spam := range []bool{false, true} {
		for _, failMove := range []bool{false, true} {
			e, mail, db, scanner := newTestEngine(t, time.Now().UTC(), false)
			folder, destination, feedback := e.Config.Folders.TrainHam, e.Config.Folders.Inbox, "ham"
			if spam {
				folder, destination, feedback = e.Config.Folders.TrainSpam, e.Config.Folders.Quarantine, "spam"
			}
			msg := mailMessage("malformed-explicit-correction", time.Now().UTC())
			msg.Raw = []byte("From: test@example.test\r\nContent-Transfer-Encoding: base64\r\n\r\n<invalid>")
			uid := mail.add(folder, msg)
			original := mail.folders[folder][uid]
			// Reproduce the pre-fix persisted blocked entry, including its placeholder hash.
			ctx := context.Background()
			e.recordMetadataError(ctx, original, folder, "invalid MIME")
			preview, err := e.Run(ctx, RunOptions{DryRun: true})
			if err != nil || preview.Errors != 0 || mail.count(folder) != 1 || scanner.learnCalls != 0 {
				t.Fatalf("unsafe preview: %+v %v", preview, err)
			}
			if failMove {
				mail.moveFailures = 1
			}
			run, err := e.Run(ctx, RunOptions{})
			if err != nil || scanner.learnCalls != 0 {
				t.Fatalf("invalid content was sent for learning: %+v %v", run, err)
			}
			if failMove {
				if run.Errors != 1 || mail.count(folder) != 1 {
					t.Fatalf("failed move lost durable intent: %+v", run)
				}
				run, err = e.Run(ctx, RunOptions{})
			}
			if err != nil || run.Errors != 0 || mail.count(folder) != 0 || mail.count(destination) != 1 || scanner.learnCalls != 0 {
				t.Fatalf("correction failed: %+v %v", run, err)
			}
			hash := archive.SHA256(original.Raw)
			learned, err := db.HasLearnedFeedback(ctx, e.Config.Account.Email, hash, feedback)
			if err != nil || learned {
				t.Fatalf("Bayes learning invented: %v", err)
			}
			guarded, err := db.HasHamFeedback(ctx, e.Config.Account.Email, hash)
			if spam {
				guarded, err = db.HasSpamFeedback(ctx, e.Config.Account.Email, hash)
			}
			if err != nil || !guarded {
				t.Fatalf("explicit exact-content correction was lost: %v", err)
			}
			spams, hams, err := db.TrainingTotals(ctx, e.Config.Account.Email)
			if err != nil || spams != 0 || hams != 0 {
				t.Fatalf("learning counters changed: %d/%d %v", spams, hams, err)
			}
			for _, got := range mail.folders[destination] {
				if archive.SHA256(got.Raw) != hash {
					t.Fatal("original message changed")
				}
			}
			pending, err := db.PendingMessages(ctx, e.Config.Account.Email)
			if err != nil || len(pending) != 0 {
				t.Fatalf("pending moves remain: %v %v", pending, err)
			}
			if next, err := e.Run(ctx, RunOptions{}); err != nil || next.Errors != 0 || scanner.learnCalls != 0 || mail.count(destination) != 1 {
				t.Fatalf("retry duplicated work: %+v %v", next, err)
			}
		}
	}
}
