package main

import (
	"context"
	"fmt"
	"time"

	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/store"
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
		Message: "Nie można jeszcze potwierdzić gotowości. Sprawdź i napraw ochronę."}
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
		p.Message = "Aktualna ocena filtra jest nieważna. Uruchom ponowną ocenę jakości."
		return p
	}
	if qualified != nil {
		m := qualified.Metrics()
		p.QualityReady = true
		p.Ready = p.PeriodComplete
		p.QualityChecks = []apiQualityCheck{
			{"disjoint", "Oddzielna nauka i sprawdzenie", "Wiadomości testowe i podobne tematy były wyłączone z nauki oraz doboru progu.", true},
			{"accuracy", "Rozpoznanie nowego spamu", fmt.Sprintf("W oddzielonym teście: %d z %d wiadomości spamu. Wymagane co najmniej 90%%.", m.SpamDetected, m.SpamTested), true},
			{"important", "Ważna poczta bez błędnego zatrzymania", fmt.Sprintf("Błędnie zatrzymane: %d z %d ważnych wiadomości. Wymagane zero.", m.FalsePositives, m.HamTested), true},
			{"rescues", "Spam bez błędnego ratowania", fmt.Sprintf("Błędnie ratowane wiadomości spamu: %d. Wymagane zero.", m.FalseRescues), true},
			{"model", "Model Bayesa sprawdzony w teście", fmt.Sprintf("Minimalna liczba przykładów statystycznych w obu klasach: %d. Trwałe usuwanie ma osobne wymagania.", qualified.MinLearns), true},
		}
		p.Message = "Aktualny filtr przeszedł oddzielny test. Historyczne pomyłki pozostały w ewidencji."
		if !p.PeriodComplete {
			p.Message = "Filtr przeszedł test; trwa jeszcze okres obserwacji."
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
		p.Message = "Warunki spełnione. Możesz włączyć przenoszenie spamu z Odebranych do kwarantanny."
	case quality.SpamFeedback == 0:
		p.Message = "Potrzebne jest Twoje potwierdzenie spamu. Przenieś rozpoznany spam do AI-Naucz-spam i przetwórz korekty. Nie oznaczaj prawidłowych wiadomości tylko po to, by zakończyć obserwację."
	case p.PeriodComplete && (quality.FalsePositives > 0 || quality.FalseRescues > 0 || quality.SpamUnexplained > 0):
		p.Message = "Okres obserwacji zakończony, ale historyczne pomyłki blokują porządkowanie Odebranych. Samo czekanie ani dalsza nauka nie usuną tych blokad. Potrzebna jest naprawa i nowa niezależna ocena filtra."
	case !p.QualityReady:
		p.Message = "Korekty wskazują, że filtr wymaga dalszej nauki. Przenoszenie z Odebranych pozostaje wyłączone."
	default:
		p.Message = "Jakość decyzji potwierdzona. Poczekaj do końca okresu obserwacji."
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
		{"sample", "Potwierdzony spam", fmt.Sprintf("Wiadomości oznaczone przez Ciebie jako spam w tym okresie: %d. Potrzebna jest co najmniej jedna.", q.SpamFeedback), q.SpamFeedback > 0},
		{"accuracy", "Trafne rozpoznanie spamu", fmt.Sprintf("Guardian wcześniej rozpoznał jako spam %d z %d potwierdzonych wiadomości. Wymagane co najmniej 90%%.", q.SpamPreviouslySpam, q.SpamFeedback), q.SpamFeedback > 0 && q.SpamPreviouslySpam*100 >= q.SpamFeedback*90},
		{"important", "Ważne wiadomości bez błędnego oznaczenia jako spam", fmt.Sprintf("Potwierdzone przez Ciebie pomyłki: %d. Wymagane zero w tym okresie obserwacji.", q.FalsePositives), q.FalsePositives == 0},
		{"rescues", "Spam bez błędnego uznania za ważną wiadomość", fmt.Sprintf("Potwierdzone przez Ciebie pomyłki: %d. Wymagane zero w tym okresie obserwacji.", q.FalseRescues), q.FalseRescues == 0},
		{"history", "Znana wcześniejsza decyzja", fmt.Sprintf("Potwierdzony spam bez wcześniejszej decyzji „spam” lub „do sprawdzenia”: %d. Wymagane zero.", q.SpamUnexplained), q.SpamUnexplained == 0},
	}
}
