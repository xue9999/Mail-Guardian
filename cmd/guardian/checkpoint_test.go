package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/rspamd"
	"github.com/o2-mail-guardian/guardian/internal/store"
)

func checkpointRuntime(t *testing.T) *runtimeApp {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &runtimeApp{ctx: context.Background(), db: db, cfg: config.Default()}
}

func checkpointMarker(t *testing.T, rt *runtimeApp) string {
	t.Helper()
	value, err := rt.db.GetSetting(context.Background(), modelCheckpointRequired)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestLinuxCheckpointFailureSurvivesRestartAndBlocksPreparation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	rt := &runtimeApp{db: db}
	failure := errors.New("fixture persistence failure")
	calls := 0
	a := &application{backupModel: func(ctx context.Context, actual *runtimeApp) error {
		calls++
		if actual != rt || checkpointMarker(t, rt) != "1" {
			t.Fatal("checkpoint ran before its durable marker was written")
		}
		return failure
	}}
	if err := a.prepareLinuxMutation(rt); !errors.Is(err, failure) {
		t.Fatalf("preparation hid failed persistence: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rt.db = db
	if checkpointMarker(t, rt) != "1" {
		t.Fatal("restart lost the required checkpoint")
	}
	if err := a.prepareLinuxMutation(rt); !errors.Is(err, failure) || calls != 2 {
		t.Fatalf("next mutation did not repeat and fail checkpoint: calls=%d err=%v", calls, err)
	}
	if checkpointMarker(t, rt) != "1" {
		t.Fatal("failed recovery cleared the required checkpoint")
	}
}

func TestLinuxCheckpointPreparationAndCompletionBothVerifyModel(t *testing.T) {
	rt := checkpointRuntime(t)
	mailCtx, cancel := context.WithCancel(context.Background())
	cancel()
	rt.ctx = mailCtx
	calls := 0
	a := &application{backupModel: func(ctx context.Context, actual *runtimeApp) error {
		calls++
		if actual != rt || ctx.Err() != nil {
			t.Fatal("mailbox cancellation disabled local checkpoint")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 3*time.Minute {
			t.Fatal("checkpoint has no bounded independent context")
		}
		if checkpointMarker(t, rt) != "1" {
			t.Fatal("model operation has no durable incomplete marker")
		}
		return nil
	}}
	if err := a.prepareLinuxMutation(rt); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || checkpointMarker(t, rt) != "1" {
		t.Fatal("preparation did not verify before leaving the mutation pending")
	}
	if err := a.finishLinuxMutation(rt); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || checkpointMarker(t, rt) != "" {
		t.Fatal("completion did not verify before clearing the marker")
	}
}

func TestLinuxCheckpointCompletionFailureRemainsRequiredUntilVerifiedRecovery(t *testing.T) {
	rt := checkpointRuntime(t)
	failure := errors.New("fixture disk error")
	fail := false
	calls := 0
	a := &application{backupModel: func(context.Context, *runtimeApp) error {
		calls++
		if fail {
			return failure
		}
		return nil
	}}
	if err := a.prepareLinuxMutation(rt); err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := a.finishLinuxMutation(rt); !errors.Is(err, failure) || checkpointMarker(t, rt) != "1" {
		t.Fatalf("failed completion hid the required checkpoint: %v", err)
	}
	if err := a.prepareLinuxMutation(rt); !errors.Is(err, failure) || checkpointMarker(t, rt) != "1" {
		t.Fatalf("failed checkpoint did not block the next mutation: %v", err)
	}
	fail = false
	if err := a.prepareLinuxMutation(rt); err != nil || checkpointMarker(t, rt) != "1" {
		t.Fatalf("verified recovery did not permit a new pending mutation: %v", err)
	}
	if err := a.finishLinuxMutation(rt); err != nil || checkpointMarker(t, rt) != "" || calls != 5 {
		t.Fatalf("verified completion did not clear marker: calls=%d err=%v", calls, err)
	}
}

func TestLinuxCheckpointCannotStartWithoutDurableMarker(t *testing.T) {
	rt := checkpointRuntime(t)
	_ = rt.db.Close()
	calls := 0
	a := &application{backupModel: func(context.Context, *runtimeApp) error { calls++; return nil }}
	if err := a.prepareLinuxMutation(rt); err == nil || calls != 0 {
		t.Fatalf("mutation could begin without durable guard: calls=%d err=%v", calls, err)
	}
	if err := a.finishLinuxMutation(rt); err == nil || calls != 0 {
		t.Fatalf("completion could succeed without durable guard: calls=%d err=%v", calls, err)
	}
}

func TestLinuxCheckpointRejectsRegressedOrUnavailableModelBeforeMaintenance(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{name: "regressed spam", code: http.StatusOK, body: `{"statfiles":[{"revision":9,"symbol":"BAYES_SPAM"},{"revision":8,"symbol":"BAYES_HAM"}]}`},
		{name: "regressed ham", code: http.StatusOK, body: `{"statfiles":[{"revision":12,"symbol":"BAYES_SPAM"},{"revision":7,"symbol":"BAYES_HAM"}]}`},
		{name: "unavailable", code: http.StatusServiceUnavailable, body: `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := checkpointRuntime(t)
			for key, value := range map[string]string{"bayes_spam_revision_highwater": "12", "bayes_ham_revision_highwater": "8"} {
				if err := rt.db.SetSetting(context.Background(), key, value); err != nil {
					t.Fatal(err)
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/stat" {
					t.Errorf("unexpected checkpoint endpoint: %s", r.URL.Path)
				}
				w.WriteHeader(tc.code)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			rt.scanner = rspamd.New(server.URL+"/checkv2", server.URL, "fixture", time.Second)
			a := &application{}
			if err := a.prepareLinuxMutation(rt); err == nil || checkpointMarker(t, rt) != "1" {
				t.Fatalf("unsafe model checkpoint accepted: %v", err)
			} else if strings.HasPrefix(tc.name, "regressed") && !strings.Contains(fmt.Sprint(err), "cofnął") {
				t.Fatalf("model regression was not rejected before helper dispatch: %v", err)
			}
		})
	}
}
