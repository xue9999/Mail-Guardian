package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/qualification"
)

const qualificationKey = "filter_qualification_v1"

func (db *DB) SaveQualification(ctx context.Context, cfg config.Config, report qualification.Report, now time.Time) error {
	if err := report.Validate(cfg, now); err != nil {
		return err
	}
	if err := db.RequireConfiguration(ctx, cfg); err != nil {
		return err
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return db.SetSetting(ctx, qualificationKey, string(raw))
}

// CurrentQualification does not erase old observations. New confirmed false
// positives after this policy's validation revoke it and require re-evaluation.
func (db *DB) CurrentQualification(ctx context.Context, cfg config.Config, now time.Time) (*qualification.Report, error) {
	raw, err := db.GetSetting(ctx, qualificationKey)
	if err != nil || raw == "" {
		return nil, err
	}
	var r qualification.Report
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, err
	}
	if err := r.Validate(cfg, now); err != nil {
		return nil, err
	}
	var mistakes int
	err = db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM messages correction WHERE account=? AND COALESCE(NULLIF(feedback_intent,''),feedback) IN ('ham','spam') AND first_seen>? AND EXISTS (SELECT 1 FROM messages prior WHERE prior.account=correction.account AND prior.raw_sha256=correction.raw_sha256 AND prior.id<>correction.id AND prior.feedback='' AND ((COALESCE(NULLIF(correction.feedback_intent,''),correction.feedback)='ham' AND prior.action='quarantined' AND prior.verdict='spam') OR (COALESCE(NULLIF(correction.feedback_intent,''),correction.feedback)='spam' AND prior.action='rescued' AND prior.verdict='ham')) AND prior.last_scanned>? AND prior.last_scanned<=correction.first_seen)`, cfg.Account.Email, r.CreatedAt.UTC().Format(time.RFC3339Nano), r.CreatedAt.UTC().Format(time.RFC3339Nano)).Scan(&mistakes)
	if err != nil {
		return nil, err
	}
	if mistakes > 0 {
		return nil, errors.New("new correction confirms an incorrect move; filter reevaluation required")
	}
	return &r, nil
}
