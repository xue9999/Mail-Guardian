package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestFeedbackOrderSeparatesCurrentChoiceConfirmedModelAndDeletionVeto(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, now := context.Background(), time.Now().UTC()
	const account, hash = "test@o2.pl", "same-content"
	for i, item := range []struct {
		feedback, intent, latest, learned string
	}{
		{feedback: "spam", latest: "spam", learned: "spam"},
		{feedback: "ham", latest: "ham", learned: "ham"},
		{feedback: "spam", latest: "spam", learned: "spam"},
		{intent: "ham", latest: "ham", learned: ""},
		{feedback: "spam", intent: "ham", latest: "ham", learned: ""},
	} {
		if _, err := db.UpsertMessage(ctx, &Message{
			Account: account, RawSHA256: hash, Feedback: item.feedback, FeedbackIntent: item.intent,
			Status: "superseded", FirstSeen: now.Add(time.Duration(i) * time.Second), LastScanned: now,
		}); err != nil {
			t.Fatal(err)
		}
		latest, err := db.LatestFeedback(ctx, account, hash)
		if err != nil || latest != item.latest {
			t.Fatalf("step %d current choice=%q want %q: %v", i, latest, item.latest, err)
		}
		for _, class := range []string{"spam", "ham"} {
			learned, err := db.HasLearnedFeedback(ctx, account, hash, class)
			if err != nil || learned != (class == item.learned) {
				t.Fatalf("step %d class %s dedup=%v: %v", i, class, learned, err)
			}
		}
		if i > 0 {
			veto, err := db.HasHamFeedback(ctx, account, hash)
			if err != nil || !veto {
				t.Fatalf("step %d lost historical ham deletion veto: %v", i, err)
			}
		}
	}
	if latest, err := db.LatestFeedback(ctx, "another@o2.pl", hash); err != nil || latest != "" {
		t.Fatalf("another account inherited a correction: %q %v", latest, err)
	}
	if learned, err := db.HasLearnedFeedback(ctx, account, "new-content", "spam"); err != nil || learned {
		t.Fatalf("unknown content inherited a learned class: %v %v", learned, err)
	}
}
