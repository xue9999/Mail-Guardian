// Package qualification verifies disjoint evidence for the current filtering
// policy. Historical mistakes are retained; only a new measured policy can
// replace the old activation gate.
package qualification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/rspamd"
)

const Policy = "delivered-imap-v2-bayes100-dns-quarantine"
const MinLearns = 100

// Recall measures usefulness, while false positives/false rescues are the
// safety gates. Missing a spam delivery must not prevent safe quarantine of
// other confidently detected spam forever. Deletion has independent gates.
const MinimumRecallPercent = 90

type Evidence struct {
	Hash, Label, Group string
	Bucket             int
	Score              float64
	Verdict            string
	Incomplete         bool
	Bayes              float64
}

type Report struct {
	Protocol                 int               `json:"protocol"`
	Method                   string            `json:"method"`
	Policy                   string            `json:"policy"`
	CreatedAt                time.Time         `json:"created_at"`
	AuthorizationFingerprint string            `json:"authorization_fingerprint"`
	MinLearns                int               `json:"min_learns"`
	SpamThreshold            float64           `json:"spam_threshold"`
	TrainingStats            rspamd.BayesStats `json:"training_stats"`
	Training                 []Evidence        `json:"training"`
	Calibration              []Evidence        `json:"calibration"`
	Validation               []Evidence        `json:"validation"`
	Excluded                 int               `json:"excluded"`
}

type Metrics struct{ SpamTested, SpamDetected, HamTested, FalsePositives, FalseRescues, Incomplete int }

func (r Report) Metrics() Metrics {
	var m Metrics
	for _, e := range r.Validation {
		detected := e.Verdict == "spam" && e.Score >= r.SpamThreshold
		if e.Label == "spam" {
			m.SpamTested++
			if detected {
				m.SpamDetected++
			}
			if e.Verdict == "ham" {
				m.FalseRescues++
			}
		} else {
			m.HamTested++
			if detected {
				m.FalsePositives++
			}
		}
		if e.Incomplete {
			m.Incomplete++
		}
	}
	return m
}

func validHash(s string) bool { b, err := hex.DecodeString(s); return err == nil && len(b) == 32 }

func (r Report) Validate(cfg config.Config, now time.Time) error {
	if r.Protocol != 1 || r.Policy != Policy || r.Method != "subject-grouped-disjoint-70-10-20" {
		return errors.New("evaluation uses another filtering-rules version")
	}
	c, err := cfg.ResolveIdentity()
	if err != nil {
		return err
	}
	if r.AuthorizationFingerprint != c.AuthorizationFingerprint() {
		return errors.New("evaluation belongs to another mailbox configuration")
	}
	if r.CreatedAt.IsZero() || r.CreatedAt.After(now.Add(time.Minute)) {
		return errors.New("invalid evaluation date")
	}
	if r.MinLearns != MinLearns || r.TrainingStats.SpamRevision < MinLearns || r.TrainingStats.HamRevision < MinLearns {
		return errors.New("validation model was insufficiently trained")
	}
	if math.IsNaN(r.SpamThreshold) || math.IsInf(r.SpamThreshold, 0) || r.SpamThreshold < 6 || math.Abs(r.SpamThreshold-cfg.Rspamd.SpamScore) > 0.000001 || cfg.Rspamd.HamScore != -2 || !cfg.Safety.RequireAuthForRescue {
		return errors.New("filter thresholds or rules changed since evaluation")
	}
	hashes := map[string]bool{}
	groups := map[string]int{}
	train := [2]int{}
	cal := [2]int{}
	for role, set := range [][]Evidence{r.Training, r.Calibration, r.Validation} {
		for _, e := range set {
			if !validHash(e.Hash) || !validHash(e.Group) || hashes[e.Hash] || (e.Label != "ham" && e.Label != "spam") || math.IsNaN(e.Score) || math.IsInf(e.Score, 0) {
				return errors.New("invalid or duplicate evaluation example")
			}
			hashes[e.Hash] = true
			if previous, ok := groups[e.Group]; ok && previous != role {
				return errors.New("similar message subjects cross the training/test boundary")
			}
			groups[e.Group] = role
			class := 0
			if e.Label == "ham" {
				class = 1
			}
			if role == 0 {
				train[class]++
			}
			if role == 1 {
				cal[class]++
			}
		}
	}
	if train[0] < 100 || train[1] < 100 || cal[0] < 20 || cal[1] < 10 {
		return errors.New("insufficient held-out training or tuning examples")
	}
	threshold := 6.0
	for _, e := range r.Calibration {
		if e.Label == "ham" && e.Score+1 > threshold {
			threshold = e.Score + 1
		}
	}
	if math.Abs(threshold-r.SpamThreshold) > 0.000001 {
		return errors.New("threshold does not match frozen tuning result")
	}
	m := r.Metrics()
	if m.SpamTested < 40 || m.HamTested < 30 || m.SpamDetected*100 < m.SpamTested*MinimumRecallPercent || m.FalsePositives != 0 || m.FalseRescues != 0 {
		return fmt.Errorf("evaluation requirements not met: spam %d/%d, ham %d, false spam %d, false rescues %d", m.SpamDetected, m.SpamTested, m.HamTested, m.FalsePositives, m.FalseRescues)
	}
	return nil
}

func (r Report) Digest() string {
	raw, _ := json.Marshal(r)
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}
