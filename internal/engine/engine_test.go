package engine

import (
	"testing"

	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/rspamd"
)

func TestMIMEValidationRejectsMalformedStructureAndEncoding(t *testing.T) {
	tests := []string{
		"From: sender@example.org\r\nContent-Type: multipart/mixed\r\n\r\nmissing boundary",
		"From: sender@example.org\r\nContent-Transfer-Encoding: base64\r\n\r\n%%%not-base64%%%",
		"From: sender@example.org\r\nContent-Type: text/plain; charset=\"unterminated\r\n\r\nbody",
	}
	for _, raw := range tests {
		if err := validateRFC822MIME([]byte(raw)); err == nil {
			t.Fatalf("malformed message was accepted: %q", raw)
		}
	}
	valid := "From: sender@example.org\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n"
	if err := validateRFC822MIME([]byte(valid)); err != nil {
		t.Fatalf("valid MIME rejected: %v", err)
	}
}

func TestDecisionMatrix(t *testing.T) {
	cfg := config.Default()
	cfg.Safety.Mode = "active"
	e := &Engine{Config: cfg}
	tests := []struct {
		source, verdict, action, destination string
	}{
		{sourceInbox, "spam", "quarantine", cfg.Folders.Quarantine},
		{sourceInbox, "ham", "keep", ""},
		{sourceSpam, "spam", "quarantine", cfg.Folders.Quarantine},
		{sourceSpam, "ham", "rescue", cfg.Folders.Inbox},
		{sourceSpam, "uncertain", "review", cfg.Folders.Review},
		{sourceSpam, "error", "review", cfg.Folders.Review},
	}
	for _, tc := range tests {
		action, dest, _ := e.decide(tc.source, rspamd.Decision{Verdict: tc.verdict}, true)
		if action != tc.action || dest != tc.destination {
			t.Fatalf("%s/%s: got %s/%s", tc.source, tc.verdict, action, dest)
		}
	}
}

func TestProtectModeNeverMovesInbox(t *testing.T) {
	e := &Engine{Config: config.Default()}
	for _, verdict := range []string{"spam", "ham", "uncertain", "error"} {
		action, _, _ := e.decide(sourceInbox, rspamd.Decision{Verdict: verdict}, false)
		if action != "keep" {
			t.Fatalf("protect mode moved inbox verdict %s", verdict)
		}
	}
	action, destination, _ := e.decide(sourceSpam, rspamd.Decision{Verdict: "ham"}, false)
	if action != "review" || destination != e.Config.Folders.Review {
		t.Fatal("server spam must be preserved in review during protect mode")
	}
}
