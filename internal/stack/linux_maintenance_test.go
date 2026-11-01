package stack

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLinuxMaintenancePinsPrivilegeBoundary(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "/secret/credentials")
	t.Setenv("DOCKER_HOST", "tcp://untrusted.example:2375")
	for _, operation := range []string{"up", "down", "status", "deep-check", "check-storage", "check-persistence", "export-redis"} {
		cmd, err := linuxMaintenanceCommand(context.Background(), "test-instance", operation)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"/usr/bin/sudo", "-n", "--", linuxMaintenanceHelper, "test-instance", operation}
		if cmd.Path != "/usr/bin/sudo" || !reflect.DeepEqual(cmd.Args, want) || cmd.Dir != "/" {
			t.Fatalf("unexpected privileged command: %s %#v (%s)", cmd.Path, cmd.Args, cmd.Dir)
		}
		if !reflect.DeepEqual(cmd.Env, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}) || cmd.Stdin != nil {
			t.Fatalf("helper inherited worker state: %#v", cmd.Env)
		}
	}
	for _, instance := range []string{"", "../prod", "prod/../other", "-flag", "prod;id", "prod\nstatus", strings.Repeat("a", 65)} {
		if cmd, err := linuxMaintenanceCommand(context.Background(), instance, "status"); err == nil || cmd != nil {
			t.Fatalf("invalid instance accepted: %q", instance)
		}
	}
	for _, operation := range []string{"", "exec", "status --all", "export-model", "up\nstatus"} {
		if cmd, err := linuxMaintenanceCommand(context.Background(), "prod", operation); err == nil || cmd != nil {
			t.Fatalf("invalid operation accepted: %q", operation)
		}
	}
}

func TestLinuxMaintenanceRejectsFailureWithoutDisclosingOutput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "printf 'secret-output'; printf 'secret-error' >&2; exit 1")
	got, err := captureLinuxMaintenance(ctx, cmd, 64<<10)
	if err == nil || got != nil || strings.Contains(err.Error(), "secret-") {
		t.Fatalf("failed helper leaked or accepted output: %q %v", got, err)
	}
	var processErr *redisExportProcessError
	if !errors.As(err, &processErr) {
		t.Fatal("process failure lost its bounded-export retry classification")
	}
}

func TestLinuxMaintenanceBoundsBothStreams(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr", "both"} {
		t.Run(stream, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			script := "head -c 70000 /dev/zero"
			if stream == "stderr" {
				script += " >&2"
			} else if stream == "both" {
				script += "; head -c 70000 /dev/zero >&2"
			}
			cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
			got, err := captureLinuxMaintenance(ctx, cmd, 64<<10)
			if got != nil || !errors.Is(err, errMaintenanceOutputLimit) {
				t.Fatalf("unbounded %s accepted: %d bytes, %v", stream, len(got), err)
			}
		})
	}
}

func TestLinuxMaintenanceRetainsDeadlineAndSuccess(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	got, err := captureLinuxMaintenance(ctx, exec.CommandContext(ctx, "/bin/sh", "-c", "printf ok"), 64<<10)
	if got != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline lost: %q %v", got, err)
	}
	ctx = context.Background()
	got, err = captureLinuxMaintenance(ctx, exec.CommandContext(ctx, "/bin/sh", "-c", "printf ok"), 64<<10)
	if err != nil || string(got) != "ok" {
		t.Fatalf("successful helper rejected: %q %v", got, err)
	}
}

func TestLinuxWorkerRejectsMissingInstanceBeforeHostCommands(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux dispatch")
	}
	m := Manager{ComposeFile: "/worker/path/compose.yaml", RuntimeDir: "/worker/runtime"}
	for _, call := range []func() error{m.Up, m.Down, m.DeepCheck, m.CheckStorage, m.CheckPersistence, func() error {
		_, err := m.Status()
		return err
	}, func() error { return m.BackupRedis(t.TempDir(), 0, 0) }} {
		if err := call(); err == nil || !strings.Contains(err.Error(), "instancji") {
			t.Fatalf("Linux dispatch reached a host command without an instance: %v", err)
		}
	}
	if sandbox, err := m.NewQualificationSandbox(context.Background(), t.TempDir()); err == nil || sandbox != nil {
		t.Fatal("Linux qualification attempted an unprivileged Docker sandbox")
	}
}
