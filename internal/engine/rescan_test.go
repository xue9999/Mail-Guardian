package engine

import (
	"context"
	"testing"
	"time"

	"github.com/o2-mail-guardian/guardian/internal/rspamd"
)

type changingScanner struct {
	*fakeScanner
	spam bool
}

func (s *changingScanner) Scan(ctx context.Context, raw []byte, recipient string) (rspamd.Result, error) {
	result, err := s.fakeScanner.Scan(ctx, raw, recipient)
	if s.spam {
		result.Score, result.Action = 15, "reject"
	}
	return result, err
}

func (s *changingScanner) Learn(ctx context.Context, raw []byte, spam bool) error {
	err := s.fakeScanner.Learn(ctx, raw, spam)
	if err == nil {
		s.spam = true
	}
	return err
}

func TestRetainedInboxIsRevisitedDailyAndMovedOnlyOnce(t *testing.T) {
	now := time.Now().UTC()
	start := now
	e, mail, _, scanner := newTestEngine(t, now, true)
	e.Now = func() time.Time { return now }
	changing := &changingScanner{fakeScanner: scanner}
	e.Rspamd = changing
	mail.add("INBOX", mailMessage("uncertain-recheck", now))
	for i, elapsed := range []time.Duration{0, 2 * time.Hour, 25 * time.Hour, 26 * time.Hour} {
		now = start.Add(elapsed)
		if i > 0 {
			changing.spam = true
		}
		run, err := e.Run(context.Background(), RunOptions{})
		if err != nil || run.Errors != 0 {
			t.Fatalf("run %d: %+v, %v", i, run, err)
		}
		want := []int{1, 0, 1, 0}[i]
		if run.Scanned != want {
			t.Fatalf("run %d scanned %d, want %d", i, run.Scanned, want)
		}
	}
	if scanner.scanCalls != 2 || mail.count("INBOX") != 0 || mail.count(e.Config.Folders.Quarantine) != 1 {
		t.Fatal("retained mail was not reclassified exactly once after its decision expired")
	}
}

func TestConfirmedLearningRevisitsObservedInboxWithoutActivatingSorting(t *testing.T) {
	now := time.Now().UTC()
	e, mail, _, scanner := newTestEngine(t, now, false)
	e.Now = func() time.Time { return now }
	e.Rspamd = &changingScanner{fakeScanner: scanner}
	mail.add("INBOX", mailMessage("uncertain-before-learning", now))
	if _, err := e.Run(context.Background(), RunOptions{}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	mail.add(e.Config.Folders.TrainSpam, mailMessage("spam-new-correction", now))
	run, err := e.Run(context.Background(), RunOptions{})
	if err != nil || run.Errors != 0 || run.LearnedSpam != 1 || run.Scanned != 2 || scanner.scanCalls != 2 {
		t.Fatalf("learning did not refresh the previous decision: %+v, %v", run, err)
	}
	if mail.count("INBOX") != 1 || mail.count(e.Config.Folders.Quarantine) != 1 {
		t.Fatal("reclassification changed protect-mode movement permissions")
	}
}
