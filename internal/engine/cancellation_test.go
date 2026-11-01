package engine

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/imapmail"
	"github.com/xue9999/Mail-Guardian/internal/store"
)

type cancelingFetchMail struct {
	*fakeMail
	cancel      context.CancelCauseFunc
	cause       error
	cancelOnRaw bool
	fetchCalls  int
}

func (m *cancelingFetchMail) Fetch(folder string, uid uint32, raw bool) (imapmail.Message, error) {
	m.fetchCalls++
	if raw == m.cancelOnRaw {
		m.cancel(m.cause)
		return imapmail.Message{}, errors.New("IMAP transport closed by command watchdog")
	}
	return m.fakeMail.Fetch(folder, uid, raw)
}

func assertCanceledRun(t *testing.T, db *store.DB, run *store.Run, err, cause error) {
	t.Helper()
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cause) {
		t.Fatalf("cancellation lost the command's deadline cause: %v", err)
	}
	if run == nil || run.Errors != 1 || run.Status != "error" || run.FinishedAt == nil {
		t.Fatalf("canceled run was not completed as one failure: %+v", run)
	}
	status, count, outcomeErr := db.LatestLiveRunOutcome(context.Background())
	if outcomeErr != nil || status != "error" || count != 1 {
		t.Fatalf("canceled context prevented durable run outcome: %s %d %v", status, count, outcomeErr)
	}
}

func TestCommandCancellationStopsFetchWithoutTryingFurtherUIDs(t *testing.T) {
	for _, phase := range []string{"metadata", "body", "training"} {
		t.Run(phase, func(t *testing.T) {
			now := time.Now().UTC()
			e, mail, db, scanner := newTestEngine(t, now, false)
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			cause := fmt.Errorf("fixture FETCH command exceeded its deadline: %w", context.DeadlineExceeded)
			canceling := &cancelingFetchMail{fakeMail: mail, cancel: cancel, cause: cause, cancelOnRaw: phase != "metadata"}
			e.Mail = canceling
			folder := e.Config.Folders.Inbox
			if phase == "training" {
				folder = e.Config.Folders.TrainSpam
			}
			for i := 0; i < 3; i++ {
				mail.add(folder, mailMessage(fmt.Sprintf("spam-cancel-fetch-%d", i), now))
			}
			run, err := e.Run(ctx, RunOptions{})
			assertCanceledRun(t, db, run, err, cause)
			wantCalls := 1
			if phase == "body" {
				wantCalls = 2 // Metadata succeeded; the first raw-body command timed out.
			}
			if run.Scanned != 1 || canceling.fetchCalls != wantCalls || scanner.scanCalls != 0 || scanner.learnCalls != 0 || mail.count(folder) != 3 {
				t.Fatalf("run continued after its session was canceled: run=%+v fetches=%d scans=%d learns=%d", run, canceling.fetchCalls, scanner.scanCalls, scanner.learnCalls)
			}
		})
	}
}

func TestCancellationDuringScanDoesNotMoveMailOrTryAnotherUID(t *testing.T) {
	for _, source := range []string{"inbox", "server_spam"} {
		t.Run(source, func(t *testing.T) {
			now := time.Now().UTC()
			e, mail, db, scanner := newTestEngine(t, now, true)
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			cause := fmt.Errorf("fixture session command timed out while scanning: %w", context.DeadlineExceeded)
			scanner.scanHook = func() { cancel(cause) }
			folder := e.Config.Folders.Inbox
			if source == "server_spam" {
				folder = e.Config.Folders.ServerSpam
			}
			mail.add(folder, mailMessage("spam-cancel-during-scan-1", now))
			mail.add(folder, mailMessage("spam-cancel-during-scan-2", now))
			run, err := e.Run(ctx, RunOptions{})
			assertCanceledRun(t, db, run, err, cause)
			if run.Scanned != 1 || scanner.scanCalls != 1 || mail.rawFetches != 1 || mail.count(folder) != 2 || mail.count(e.Config.Folders.Quarantine) != 0 || mail.count(e.Config.Folders.Review) != 0 {
				t.Fatalf("canceled scan continued or moved mail: run=%+v scans=%d rawFetches=%d", run, scanner.scanCalls, mail.rawFetches)
			}
		})
	}
}

type cancelingLearnScanner struct {
	*fakeScanner
	cancel context.CancelCauseFunc
	cause  error
}

func (s *cancelingLearnScanner) Learn(context.Context, []byte, bool) error {
	s.learnCalls++
	s.cancel(s.cause)
	return errors.New("fixture learning interrupted after session cancellation")
}

func TestCancellationDuringLearningPreservesIntentWithoutFurtherUIDs(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, scanner := newTestEngine(t, now, false)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	cause := fmt.Errorf("fixture session deadline during learning: %w", context.DeadlineExceeded)
	e.Rspamd = &cancelingLearnScanner{fakeScanner: scanner, cancel: cancel, cause: cause}
	mail.add(e.Config.Folders.TrainSpam, mailMessage("spam-cancel-learn-1", now))
	mail.add(e.Config.Folders.TrainSpam, mailMessage("spam-cancel-learn-2", now))
	run, err := e.Run(ctx, RunOptions{})
	assertCanceledRun(t, db, run, err, cause)
	if run.Scanned != 1 || scanner.learnCalls != 1 || mail.rawFetches != 1 || mail.count(e.Config.Folders.TrainSpam) != 2 || mail.count(e.Config.Folders.Quarantine) != 0 {
		t.Fatalf("learning cancellation continued or moved originals: run=%+v learns=%d rawFetches=%d", run, scanner.learnCalls, mail.rawFetches)
	}
	items, err := db.Archived(context.Background(), e.Config.Account.Email, 10)
	if err != nil || len(items) != 1 || items[0].FeedbackIntent != "spam" || items[0].Feedback != "" {
		t.Fatalf("cancellation lost the durable correction intent: %+v %v", items, err)
	}
}

func TestCancellationDuringReconciliationStopsBeforeTrainingAndOtherUIDs(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, scanner := newTestEngine(t, now, true)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	cause := fmt.Errorf("fixture pending FETCH command timed out: %w", context.DeadlineExceeded)
	canceling := &cancelingFetchMail{fakeMail: mail, cancel: cancel, cause: cause}
	e.Mail = canceling
	for i := 0; i < 2; i++ {
		uid := mail.add(e.Config.Folders.Inbox, mailMessage(fmt.Sprintf("spam-pending-cancel-%d", i), now))
		insertPending(t, db, e.Config.Account.Email, mail.folders[e.Config.Folders.Inbox][uid], "quarantined", now)
	}
	mail.add(e.Config.Folders.TrainSpam, mailMessage("spam-unstarted-training", now))
	run, err := e.Run(ctx, RunOptions{})
	assertCanceledRun(t, db, run, err, cause)
	if canceling.fetchCalls != 1 || scanner.scanCalls != 0 || scanner.learnCalls != 0 || mail.count(e.Config.Folders.Inbox) != 2 || mail.count(e.Config.Folders.TrainSpam) != 1 {
		t.Fatalf("reconciliation cancellation continued to another operation: run=%+v fetches=%d scans=%d learns=%d", run, canceling.fetchCalls, scanner.scanCalls, scanner.learnCalls)
	}
}
