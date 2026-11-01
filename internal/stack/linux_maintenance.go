package stack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/platform"
)

const linuxMaintenanceHelper = "/usr/local/libexec/mail-guardian-maintenance"

var errMaintenanceOutputLimit = errors.New("administrator response exceeds limit")

// No executable, Compose file, output path, environment setting or arbitrary
// command crosses this boundary. The helper resolves its administrator-owned
// paths from the validated instance and independently validates both arguments.
func linuxMaintenanceCommand(ctx context.Context, instance, operation string) (*exec.Cmd, error) {
	if _, err := platform.LinuxPaths(instance); err != nil {
		return nil, err
	}
	switch operation {
	case "up", "down", "status", "deep-check", "check-storage", "check-persistence", "export-redis":
	default:
		return nil, errors.New("unsupported Linux administrator operation")
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", "-n", "--", linuxMaintenanceHelper, instance, operation)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Dir = "/"
	return cmd, nil
}

func (m Manager) linuxMaintenance(operation string) ([]byte, error) {
	timeout := shortCommandTimeout
	if operation == "up" || operation == "down" || operation == "deep-check" {
		timeout = composeTimeout + healthTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd, err := linuxMaintenanceCommand(ctx, m.Instance, operation)
	if err != nil {
		return nil, err
	}
	return captureLinuxMaintenance(ctx, cmd, 64<<10)
}

type maintenanceBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *maintenanceBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		b.overflow = true
		return 0, errMaintenanceOutputLimit
	}
	return b.buffer.Write(p)
}

// Helper output is bounded independently for stdout and stderr. Failed output
// is never returned or included in diagnostics: even an administrator helper
// could encounter a dependency that prints sensitive configuration.
func captureLinuxMaintenance(ctx context.Context, cmd *exec.Cmd, maxOutput int) ([]byte, error) {
	output := &maintenanceBuffer{limit: maxOutput}
	diagnostic := &maintenanceBuffer{limit: 64 << 10}
	cmd.Stdout, cmd.Stderr = output, diagnostic
	// A subprocess that leaves inherited pipes open must not outlive its bound.
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	// exec.Cmd may report the subprocess exit status (for example SIGPIPE)
	// instead of the pipe writer's error. Cmd.Run waits for both pipe writers,
	// so their overflow flags are settled before inspecting them here.
	if output.overflow || diagnostic.overflow {
		return nil, errMaintenanceOutputLimit
	}
	if err != nil {
		return nil, &redisExportProcessError{fmt.Errorf("Linux administrator operation failed: %w", errors.Join(err, ctx.Err()))}
	}
	return output.buffer.Bytes(), nil
}
