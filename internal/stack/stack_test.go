package stack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitForRspamdRequiresPongFromEveryEndpoint(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("pong"))
	}))
	defer healthy.Close()
	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "starting", http.StatusServiceUnavailable)
	}))
	defer unhealthy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	err := waitForRspamd(ctx, []string{healthy.URL, unhealthy.URL}, 10*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "no pong response") {
		t.Fatalf("waitForRspamd() error = %v", err)
	}
}

func TestWaitForRspamdRetriesUntilReady(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("pong"))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitForRspamd(ctx, []string{server.URL}, 10*time.Millisecond); err != nil {
		t.Fatalf("waitForRspamd() = %v", err)
	}
	if calls.Load() < 3 {
		t.Fatalf("calls = %d, want retry", calls.Load())
	}
}

func TestDockerComposeArgsPinsContextAndProject(t *testing.T) {
	manager := Manager{ComposeFile: "/tmp/compose.yaml", RuntimeDir: "/tmp/runtime"}
	got := strings.Join(manager.dockerComposeArgs("up", "-d"), " ")
	for _, expected := range []string{
		"--context colima",
		"--project-name o2-mail-guardian",
		"--file /tmp/compose.yaml",
		"up -d",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("docker args %q missing %q", got, expected)
		}
	}
}

func TestColimaStartArgsArePrivateAndResourceBounded(t *testing.T) {
	got := strings.Join(colimaStartArgs(), " ")
	for _, expected := range []string{
		"start",
		"--runtime docker",
		"--cpus 2",
		"--memory 2",
		"--disk 20",
		"--activate=false",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("colima args %q missing %q", got, expected)
		}
	}
	if strings.Contains(got, "--activate=true") {
		t.Fatalf("colima args unexpectedly change the global Docker context: %q", got)
	}
}

func TestSafeOutputIsBounded(t *testing.T) {
	got := safeOutput([]byte(strings.Repeat("x", 2000)))
	if len(got) > 1010 || !strings.HasSuffix(got, "…") {
		t.Fatalf("safeOutput length/suffix = %d, %q", len(got), got[len(got)-3:])
	}
}
