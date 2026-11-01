package qualification

import (
	"encoding/json"
	"github.com/o2-mail-guardian/guardian/internal/config"
	"os"
	"testing"
	"time"
)

func fixture(t *testing.T) (Report, config.Config, time.Time) {
	t.Helper()
	data, err := os.ReadFile("testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
	cfg.Rspamd.SpamScore = 6
	cfg, err = cfg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	r.AuthorizationFingerprint = cfg.AuthorizationFingerprint()
	return r, cfg, r.CreatedAt.Add(time.Hour)
}

func TestQualificationRequiresDisjointEvidenceAndNoWrongMoves(t *testing.T) {
	for _, name := range []string{"valid", "duplicate", "shared family", "wrong policy", "changed threshold", "bad tuning", "too few ham", "false positive", "false rescue", "low recall", "untrained"} {
		t.Run(name, func(t *testing.T) {
			r, cfg, now := fixture(t)
			switch name {
			case "duplicate":
				r.Validation[0].Hash = r.Training[0].Hash
			case "shared family":
				r.Validation[0].Group = r.Calibration[0].Group
			case "wrong policy":
				r.Policy = "old-policy"
			case "changed threshold":
				cfg.Rspamd.SpamScore = 7
			case "bad tuning":
				r.Calibration[len(r.Calibration)-1].Score = 12
			case "too few ham":
				r.Validation = r.Validation[:70]
			case "false positive":
				r.Validation[len(r.Validation)-1].Verdict = "spam"
				r.Validation[len(r.Validation)-1].Score = 10
			case "false rescue":
				r.Validation[0].Verdict = "ham"
			case "low recall":
				for i := 0; i < 11; i++ {
					r.Validation[i].Verdict = "uncertain"
				}
			case "untrained":
				r.TrainingStats.HamRevision = 99
			}
			err := r.Validate(cfg, now)
			if (err == nil) != (name == "valid") {
				t.Fatalf("unexpected qualification result: %v", err)
			}
		})
	}
}
