package main

import (
	"time"

	"github.com/o2-mail-guardian/guardian/internal/apperror"
	"github.com/o2-mail-guardian/guardian/internal/service"
)

// Keep the dashboard and deep diagnostics on the same freshness thresholds.
// Loading a LaunchAgent proves only that it is scheduled, not that it ran.
func heartbeatFreshnessError(heartbeat service.Heartbeat, now time.Time) *apperror.Error {
	if heartbeat.LastSuccess == nil || heartbeat.LastSuccess.IsZero() {
		return &apperror.Error{
			Code: apperror.ServiceStale, Severity: "attention",
			Message:  "Brakuje potwierdzenia udanego automatycznego sprawdzenia.",
			Recovery: "Uruchom pierwsze sprawdzenie skrzynki.",
		}
	}
	age := now.Sub(*heartbeat.LastSuccess)
	if age > 48*time.Hour {
		return &apperror.Error{
			Code: apperror.ServiceStale, Severity: "critical",
			Message:  "Ostatni udany przebieg jest starszy niż 48 godzin.",
			Recovery: "Uruchom Napraw; automat nie zakończył pracy od ponad 48 godzin.",
		}
	}
	if age > 4*time.Hour {
		return &apperror.Error{
			Code: apperror.ServiceStale, Severity: "attention",
			Message:  "Ostatni udany przebieg jest starszy niż 4 godziny.",
			Recovery: "Sprawdź teraz skrzynkę albo uruchom Napraw.",
		}
	}
	return nil
}
