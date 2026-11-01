package main

import "testing"

func TestLinuxSelfTestIgnoresInstanceTMPDIR(t *testing.T) {
	t.Setenv("TMPDIR", "/var/lib/mail-guardian/pilot")
	if got := selfTestTempParent("linux"); got != "/tmp" {
		t.Fatalf("Linux self-test chose %q, want fixed /tmp", got)
	}
	if got := selfTestTempParent("darwin"); got != "" {
		t.Fatalf("other platforms unexpectedly changed: %q", got)
	}
}
