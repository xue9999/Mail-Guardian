package main

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/o2-mail-guardian/guardian/internal/store"
)

func TestModelBackupAfterPartialRunUsesIndependentContextAndPreservesFailure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		learned     int
		dryRun      bool
		runErr      error
		backupFails bool
		wantCalls   int
	}{
		{name: "timeout after learning", learned: 1, runErr: context.DeadlineExceeded, wantCalls: 1},
		{name: "both errors retained", learned: 1, runErr: context.DeadlineExceeded, backupFails: true, wantCalls: 1},
		{name: "timeout before learning", runErr: context.DeadlineExceeded},
		{name: "completed run", wantCalls: 1},
		{name: "dry run", dryRun: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			run, err := db.BeginRun(context.Background(), "run", tc.dryRun)
			if err != nil {
				t.Fatal(err)
			}
			run.LearnedSpam = tc.learned
			if tc.runErr != nil {
				run.Errors = 1
			}
			if err := db.FinishRun(context.Background(), run, tc.runErr); err != nil {
				t.Fatal(err)
			}
			mailCtx, cancel := context.WithCancelCause(context.Background())
			cancel(context.DeadlineExceeded)
			rt := &runtimeApp{ctx: mailCtx, db: db}
			calls := 0
			backupErr := errors.New("fixture backup failed")
			a := &application{out: io.Discard, errOut: io.Discard, backupModel: func(ctx context.Context, actual *runtimeApp) error {
				calls++
				if actual != rt || ctx.Err() != nil {
					t.Fatal("mailbox cancellation disabled the local backup")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("local model request has no bounded context")
				}
				if tc.backupFails {
					return backupErr
				}
				return nil
			}}
			got := a.secureRunModel(rt, run, tc.runErr, tc.dryRun)
			wantCalls := tc.wantCalls
			if runtime.GOOS == "linux" && !tc.dryRun {
				// Linux must settle the durable checkpoint even when the worker
				// stopped before learning anything in this invocation.
				wantCalls = 1
			}
			if calls != wantCalls || (tc.runErr != nil && !errors.Is(got, tc.runErr)) || (tc.runErr == nil && !tc.backupFails && got != nil) {
				t.Fatalf("backup orchestration: calls=%d want=%d err=%v", calls, wantCalls, got)
			}
			if tc.backupFails {
				status, errorsCount, err := db.LatestLiveRunOutcome(context.Background())
				if !errors.Is(got, backupErr) || err != nil || status != "error" || errorsCount != 2 {
					t.Fatalf("backup failure hid the partial run or lost its own error: %v status=%s errors=%d db=%v", got, status, errorsCount, err)
				}
			}
		})
	}
}
