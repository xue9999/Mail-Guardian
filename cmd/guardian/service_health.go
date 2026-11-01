package main

import (
	"time"

	"github.com/xue9999/Mail-Guardian/internal/apperror"
	"github.com/xue9999/Mail-Guardian/internal/service"
)

// Keep the dashboard and deep diagnostics on the same freshness thresholds.
// Loading a LaunchAgent proves only that it is scheduled, not that it ran.
func heartbeatFreshnessError(heartbeat service.Heartbeat, now time.Time) *apperror.Error {
	if heartbeat.LastSuccess == nil || heartbeat.LastSuccess.IsZero() {
		return &apperror.Error{
			Code: apperror.ServiceStale, Severity: "attention",
			Message:  "No confirmed successful automatic check.",
			Recovery: "Run the first mailbox check.",
		}
	}
	age := now.Sub(*heartbeat.LastSuccess)
	if age > 48*time.Hour {
		return &apperror.Error{
			Code: apperror.ServiceStale, Severity: "critical",
			Message:  "The last successful run is over 48 hours old.",
			Recovery: "Run Repair; automation has not completed a run for over 48 hours.",
		}
	}
	if age > 4*time.Hour {
		return &apperror.Error{
			Code: apperror.ServiceStale, Severity: "attention",
			Message:  "The last successful run is over 4 hours old.",
			Recovery: "Check the mailbox now or run Repair.",
		}
	}
	return nil
}
