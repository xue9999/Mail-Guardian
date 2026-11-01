package main

import (
	"context"
	"fmt"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/store"
)

// Read-only presentation of the existing activation rules. modeCommand and
// the engine remain authoritative and recheck every rule before moving mail.
type apiQualityCheck struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Passed bool   `json:"passed"`
}

type apiProtection struct {
	RequiredDays   int               `json:"required_days"`
	RemainingDays  int               `json:"remaining_days"`
	PeriodComplete bool              `json:"period_complete"`
	QualityReady   bool              `json:"quality_ready"`
	Ready          bool              `json:"ready"`
	Message        string            `json:"message"`
	QualityChecks  []apiQualityCheck `json:"quality_checks,omitempty"`
}

func protectionProgress(cfg config.Config, db *store.DB, now time.Time) *apiProtection {
	p := &apiProtection{RequiredDays: cfg.Safety.ProtectDays, RemainingDays: cfg.Safety.ProtectDays,
		Message: "Readiness cannot yet be confirmed. Check and repair protection."}
	ctx := context.Background()
	installed, err := db.GetSetting(ctx, "installed_at")
	if err != nil {
		return p
	}
	start, err := time.Parse(time.RFC3339, installed)
	if err != nil || start.After(now) {
		return p
	}
	reset, err := db.GetSetting(ctx, "protect_since")
	if err != nil {
		return p
	}
	if reset != "" {
		value, err := time.Parse(time.RFC3339, reset)
		if err != nil || value.Before(start) || value.After(now) {
			return p
		}
		start = value
	}
	remaining := start.Add(time.Duration(cfg.Safety.ProtectDays) * 24 * time.Hour).Sub(now)
	p.RemainingDays = max(0, int((remaining+24*time.Hour-1)/(24*time.Hour)))
	p.PeriodComplete = remaining <= 0
	qualified, qualificationErr := db.CurrentQualification(ctx, cfg, now)
	if qualificationErr != nil {
		p.Message = "The current filter qualification is invalid. Run quality evaluation again."
		return p
	}
	if qualified != nil {
		m := qualified.Metrics()
		p.QualityReady = true
		p.Ready = p.PeriodComplete
		p.QualityChecks = []apiQualityCheck{
			{"disjoint", "Separate training and evaluation", "Test messages and similar subjects were excluded from training and threshold selection.", true},
			{"accuracy", "New spam recognition", fmt.Sprintf("In held-out evaluation: %d of %d spam messages. At least 90%% required.", m.SpamDetected, m.SpamTested), true},
			{"important", "Legitimate mail without false holds", fmt.Sprintf("Incorrectly held: %d of %d legitimate messages. Required: zero.", m.FalsePositives, m.HamTested), true},
			{"rescues", "Spam without false rescues", fmt.Sprintf("Spam messages incorrectly rescued: %d. Required: zero.", m.FalseRescues), true},
			{"model", "Bayes model tested", fmt.Sprintf("Minimum statistical examples in each class: %d. Permanent deletion has separate requirements.", qualified.MinLearns), true},
		}
		p.Message = "The current filter passed a separate test. Historical mistakes remain recorded."
		if !p.PeriodComplete {
			p.Message = "The filter passed qualification; the observation period is still running."
		}
		return p
	}
	quality, err := db.ActivationQualityUntil(ctx, cfg.Account.Email, start, now)
	if err != nil {
		return p
	}
	p.QualityChecks = qualityChecks(quality)
	p.QualityReady = quality.Ready()
	p.Ready = p.PeriodComplete && p.QualityReady
	switch {
	case p.Ready:
		p.Message = "Requirements met. You may enable moving spam from Inbox to quarantine."
	case quality.SpamFeedback == 0:
		p.Message = "Your spam confirmation is required. Move recognized spam to the configured spam-training folder and process corrections. Do not label legitimate messages merely to finish observation."
	case p.PeriodComplete && (quality.FalsePositives > 0 || quality.FalseRescues > 0 || quality.SpamUnexplained > 0):
		p.Message = "Observation has ended, but historical errors block Inbox cleanup. Waiting or further training will not clear these blocks. Repair and a new independent filter evaluation are required."
	case !p.QualityReady:
		p.Message = "Corrections show the filter needs more training. Inbox moves remain disabled."
	default:
		p.Message = "Decision quality confirmed. Wait until the observation period ends."
	}
	return p
}

// Only aggregate counts leave the backend. Headers, identifiers and message
// contents are deliberately absent, including for the initial dry-run.
func apiRunResult(run *store.Run, err error) map[string]any {
	result := map[string]any{"completed": requireSuccessfulRun(run, err) == nil}
	if err == nil && run != nil {
		result["summary"] = map[string]any{
			"dry_run": run.DryRun, "scanned": run.Scanned, "kept": run.Kept,
			"rescued": run.Rescued, "quarantined": run.Quarantined,
			"review": run.Review, "errors": run.Errors,
		}
	}
	return result
}

func qualityChecks(q store.ActivationQuality) []apiQualityCheck {
	return []apiQualityCheck{
		{"sample", "Confirmed spam", fmt.Sprintf("Messages you marked as spam during this period: %d. At least one required.", q.SpamFeedback), q.SpamFeedback > 0},
		{"accuracy", "Correct spam recognition", fmt.Sprintf("Guardian previously recognized %d of %d confirmed spam messages. At least 90%% required.", q.SpamPreviouslySpam, q.SpamFeedback), q.SpamFeedback > 0 && q.SpamPreviouslySpam*100 >= q.SpamFeedback*90},
		{"important", "Legitimate messages without false spam classification", fmt.Sprintf("Errors confirmed by you: %d. Required: zero during this observation period.", q.FalsePositives), q.FalsePositives == 0},
		{"rescues", "Spam without false ham classification", fmt.Sprintf("Errors confirmed by you: %d. Required: zero during this observation period.", q.FalseRescues), q.FalseRescues == 0},
		{"history", "Known earlier decision", fmt.Sprintf("Confirmed spam without an earlier spam or review decision: %d. Required: zero.", q.SpamUnexplained), q.SpamUnexplained == 0},
	}
}
