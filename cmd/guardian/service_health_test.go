package main

import (
	"testing"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/apperror"
	"github.com/xue9999/Mail-Guardian/internal/service"
)

func TestHeartbeatFreshnessMatchesDashboardAndDeepDiagnostics(t *testing.T) {
	now := time.Date(2026, 10, 24, 21, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		age      time.Duration
		missing  bool
		zero     bool
		severity string
	}{
		{name: "never completed", missing: true, severity: "attention"},
		{name: "zero timestamp", zero: true, severity: "attention"},
		{name: "recent", age: 2 * time.Hour},
		{name: "four hour grace boundary", age: 4 * time.Hour},
		{name: "missed two schedules", age: 4*time.Hour + time.Second, severity: "attention"},
		{name: "day old", age: 24 * time.Hour, severity: "attention"},
		{name: "critical boundary", age: 48 * time.Hour, severity: "attention"},
		{name: "more than two days", age: 48*time.Hour + time.Second, severity: "critical"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var heartbeat service.Heartbeat
			if !tc.missing {
				lastSuccess := now.Add(-tc.age)
				if tc.zero {
					lastSuccess = time.Time{}
				}
				heartbeat.LastSuccess = &lastSuccess
			}
			err := heartbeatFreshnessError(heartbeat, now)
			if tc.severity == "" {
				if err != nil {
					t.Fatalf("recent service reported stale: %v", err)
				}
				return
			}
			if err == nil || err.Code != apperror.ServiceStale || err.Severity != tc.severity || err.Message == "" || err.Recovery == "" {
				t.Fatalf("freshness = %#v, want SERVICE_STALE/%s", err, tc.severity)
			}
		})
	}
}
