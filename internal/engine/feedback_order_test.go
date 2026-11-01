package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/archive"
	"github.com/xue9999/Mail-Guardian/internal/rspamd"
	"github.com/xue9999/Mail-Guardian/internal/store"
)

type feedbackOrderScanner struct {
	*fakeScanner
	classes []bool
}

func (s *feedbackOrderScanner) Learn(ctx context.Context, raw []byte, spam bool) error {
	if err := s.fakeScanner.Learn(ctx, raw, spam); err != nil {
		return err
	}
	s.classes = append(s.classes, spam)
	return nil
}

func TestAlternatingCorrectionsRelearnLatestClassAndKeepPurgeVeto(t *testing.T) {
	for _, firstSpam := range []bool{true, false} {
		name := "ham-spam-ham"
		if firstSpam {
			name = "spam-ham-spam"
		}
		t.Run(name, func(t *testing.T) {
			now, ctx := time.Now().UTC(), context.Background()
			e, mail, db, scanner := newTestEngine(t, now, false)
			ordered := &feedbackOrderScanner{fakeScanner: scanner}
			e.Rspamd = ordered
			message := mailMessage("alternating-correction", now)
			currentFolder := ""
			var currentUID uint32
			for i, spam := range []bool{firstSpam, !firstSpam, firstSpam, firstSpam} {
				training, destination := e.Config.Folders.TrainHam, e.Config.Folders.Inbox
				latest, opposite := "ham", "spam"
				if spam {
					training, destination = e.Config.Folders.TrainSpam, e.Config.Folders.Quarantine
					latest, opposite = "spam", "ham"
				}
				if i == 0 {
					mail.add(training, message)
				} else if _, err := mail.Move(currentFolder, mail.uidValidity[currentFolder], currentUID, training, false); err != nil {
					t.Fatal(err)
				}
				run, err := e.Run(ctx, RunOptions{})
				wantCalls := i + 1
				if i == 3 {
					wantCalls = 3 // Repeating the final class still deduplicates.
				}
				if err != nil || run.Errors != 0 || len(ordered.classes) != wantCalls || ordered.classes[wantCalls-1] != spam {
					t.Fatalf("correction %d did not preserve model order: run=%+v classes=%v err=%v", i, run, ordered.classes, err)
				}
				currentFolder, currentUID = destination, mail.nextUID[destination]-1
				if mail.count(training) != 0 || mail.count(destination) != 1 {
					t.Fatal("explicit correction did not move exactly one original")
				}
				matching, err := e.applyFeedbackGuard(ctx, message.Raw, rspamd.Decision{Verdict: latest})
				if err != nil || matching.Verdict != latest {
					t.Fatalf("old correction blocked current choice %q: %+v %v", latest, matching, err)
				}
				contrary, err := e.applyFeedbackGuard(ctx, message.Raw, rspamd.Decision{Verdict: opposite})
				if err != nil || contrary.Verdict != "uncertain" {
					t.Fatalf("current correction did not guard contrary verdict: %+v %v", contrary, err)
				}
			}
			veto, err := db.HasHamFeedback(ctx, e.Config.Account.Email, archive.SHA256(message.Raw))
			if err != nil || !veto {
				t.Fatalf("historical ham deletion veto lost: %v", err)
			}
		})
	}
}

func TestRepeatedKnownCorrectionSupersedesNewerUnlearnedIntent(t *testing.T) {
	now, ctx := time.Now().UTC(), context.Background()
	e, mail, db, scanner := newTestEngine(t, now, false)
	message := mailMessage("spam-known-correction", now)
	mail.add(e.Config.Folders.TrainSpam, message)
	if _, err := e.Run(ctx, RunOptions{}); err != nil {
		t.Fatal(err)
	}
	// An unconfirmed contrary intent could have reached the external model.
	// Reconfirm the requested class instead of trusting the older confirmation.
	if _, err := db.UpsertMessage(ctx, &store.Message{
		Account: e.Config.Account.Email, CurrentFolder: "old-intent", UIDValidity: 99, UID: 1,
		RawSHA256: archive.SHA256(message.Raw), FeedbackIntent: "ham", Status: "superseded",
		FirstSeen: now, LastScanned: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := mail.Move(e.Config.Folders.Quarantine, mail.uidValidity[e.Config.Folders.Quarantine], mail.nextUID[e.Config.Folders.Quarantine]-1, e.Config.Folders.TrainSpam, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Run(ctx, RunOptions{}); err != nil {
		t.Fatal(err)
	}
	latest, err := db.LatestFeedback(ctx, e.Config.Account.Email, archive.SHA256(message.Raw))
	if err != nil || latest != "spam" || scanner.learnCalls != 2 {
		t.Fatalf("repeated correction was not authoritative: %q calls=%d %v", latest, scanner.learnCalls, err)
	}
}

type droppedLearnReplyScanner struct {
	*fakeScanner
	modelSpam bool
	dropReply bool
}

func (s *droppedLearnReplyScanner) Learn(_ context.Context, _ []byte, spam bool) error {
	s.learnCalls++
	s.modelSpam = spam
	if s.dropReply {
		s.dropReply = false
		return errors.New("learning reply lost after external commit")
	}
	return nil
}

func TestCorrectionAfterDroppedLearnReplyReconfirmsExternalModel(t *testing.T) {
	now, ctx := time.Now().UTC(), context.Background()
	e, mail, _, scanner := newTestEngine(t, now, false)
	dropped := &droppedLearnReplyScanner{fakeScanner: scanner}
	e.Rspamd = dropped
	message := mailMessage("same-content-dropped-learn-reply", now)
	mail.add(e.Config.Folders.TrainSpam, message)
	if _, err := e.Run(ctx, RunOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := mail.Move(e.Config.Folders.Quarantine, mail.uidValidity[e.Config.Folders.Quarantine], mail.nextUID[e.Config.Folders.Quarantine]-1, e.Config.Folders.TrainHam, false); err != nil {
		t.Fatal(err)
	}
	dropped.dropReply = true
	failed, err := e.Run(ctx, RunOptions{})
	if err != nil || failed.Errors != 1 || dropped.modelSpam || mail.count(e.Config.Folders.TrainHam) != 1 {
		t.Fatalf("test did not reproduce externally committed ham with lost reply: %+v modelSpam=%v %v", failed, dropped.modelSpam, err)
	}
	if _, err := mail.Move(e.Config.Folders.TrainHam, mail.uidValidity[e.Config.Folders.TrainHam], mail.nextUID[e.Config.Folders.TrainHam]-1, e.Config.Folders.TrainSpam, false); err != nil {
		t.Fatal(err)
	}
	corrected, err := e.Run(ctx, RunOptions{})
	if err != nil || corrected.Errors != 0 || corrected.LearnedSpam != 1 || !dropped.modelSpam || dropped.learnCalls != 3 {
		t.Fatalf("older spam confirmation concealed a newer ham model: %+v modelSpam=%v learns=%d %v", corrected, dropped.modelSpam, dropped.learnCalls, err)
	}
}
