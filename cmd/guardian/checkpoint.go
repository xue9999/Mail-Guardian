package main

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

const modelCheckpointRequired = "model_checkpoint_required"

// prepareLinuxMutation and finishLinuxMutation run while the caller owns the
// instance lock. The durable marker survives interruption between a mailbox or
// learning operation and its verified local model checkpoint. Every modifying
// entry point must pass preparation again, including after an earlier failure.
func (a *application) prepareLinuxMutation(rt *runtimeApp) error {
	if err := setModelCheckpointRequired(rt, "1"); err != nil {
		return err
	}
	if err := a.linuxModelCheckpoint(rt); err != nil {
		return fmt.Errorf("operacje na skrzynce są zablokowane do czasu poprawnej kontroli modelu: %w", err)
	}
	return nil
}

func (a *application) finishLinuxMutation(rt *runtimeApp) error {
	// Be defensive if a caller reaches completion without preparation. A failed
	// checkpoint must still leave a durable failure rather than an empty marker.
	if err := setModelCheckpointRequired(rt, "1"); err != nil {
		return err
	}
	if err := a.linuxModelCheckpoint(rt); err != nil {
		return fmt.Errorf("nie udało się zabezpieczyć modelu; kolejne operacje wymagają ponownej kontroli: %w", err)
	}
	return setModelCheckpointRequired(rt, "")
}

func setModelCheckpointRequired(rt *runtimeApp, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rt.db.SetSetting(ctx, modelCheckpointRequired, value); err != nil {
		return fmt.Errorf("nie udało się zapisać obowiązkowej kontroli modelu: %w", err)
	}
	return nil
}

// Mailbox cancellation must not cancel the checkpoint of corrections already
// committed to Redis. The injected hook covers the entire checkpoint contract,
// including persistence and storage verification, for isolated orchestration
// tests. The production implementation never treats a mode downgrade after a
// model regression as proof of continuity.
func (a *application) linuxModelCheckpoint(rt *runtimeApp) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if a.backupModel != nil {
		return a.backupModel(ctx, rt)
	}
	stats, err := rt.scanner.Stats(ctx)
	if err != nil {
		return err
	}
	if err := compareBayesHighWater(ctx, rt.db, rt.cfg.Account.Email, stats); err != nil {
		return err
	}
	manager := runtimeStack(rt.cfg)
	if err := manager.CheckPersistence(); err != nil {
		return err
	}
	if err := manager.BackupRedis(rt.cfg.Runtime.DataDir, stats.SpamRevision, stats.HamRevision); err != nil {
		return err
	}
	if err := manager.CheckPersistence(); err != nil {
		return err
	}
	for key, revision := range map[string]uint64{
		"bayes_spam_revision_highwater": stats.SpamRevision,
		"bayes_ham_revision_highwater":  stats.HamRevision,
	} {
		if err := rt.db.SetSetting(ctx, key, strconv.FormatUint(revision, 10)); err != nil {
			return err
		}
	}
	return nil
}
