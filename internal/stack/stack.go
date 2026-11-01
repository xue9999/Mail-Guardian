package stack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	shortCommandTimeout = 15 * time.Second
	startTimeout        = 3 * time.Minute
	composeTimeout      = 3 * time.Minute
	healthTimeout       = 60 * time.Second
)

var rspamdPingURLs = []string{
	"http://127.0.0.1:11333/ping",
	"http://127.0.0.1:11334/ping",
}

type Manager struct {
	ComposeFile string
	RuntimeDir  string
	// Instance is the administrator-provisioned Linux instance slug. Linux
	// workers never pass Compose or runtime paths across the privilege boundary.
	Instance string
}

func (m Manager) Up() error {
	if runtime.GOOS == "linux" {
		_, err := m.linuxMaintenance("up")
		return err
	}
	if err := m.validate(); err != nil {
		return err
	}
	colima := commandPath("colima")
	if colima == "" {
		return errors.New("Colima not found; run Install.command")
	}
	statusCtx, statusCancel := context.WithTimeout(context.Background(), shortCommandTimeout)
	statusErr := stackCommand(statusCtx, colima, "status").Run()
	statusCancel()
	if statusErr != nil {
		ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
		defer cancel()
		cmd := stackCommand(ctx, colima, colimaStartArgs()...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return errors.New("starting Colima exceeded 3 minutes; run guardian repair again")
			}
			return fmt.Errorf("starting Colima: %w (%s)", err, safeOutput(output))
		}
	}
	docker := commandPath("docker")
	if docker == "" {
		return errors.New("docker executable not found; run Install.command")
	}
	if err := waitForDocker(docker, healthTimeout); err != nil {
		return err
	}
	if err := m.CheckStorage(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), composeTimeout)
	defer cancel()
	if err := m.compose(ctx, "up", "-d", "--remove-orphans", "--wait"); err != nil {
		return err
	}
	if err := m.checkRedisPersistence(); err != nil {
		return err
	}
	healthCtx, healthCancel := context.WithTimeout(context.Background(), healthTimeout)
	defer healthCancel()
	if err := waitForRspamd(healthCtx, rspamdPingURLs, time.Second); err != nil {
		return fmt.Errorf("containers started, but Rspamd is not ready yet: %w", err)
	}
	return nil
}

func (m Manager) Down() error {
	if runtime.GOOS == "linux" {
		_, err := m.linuxMaintenance("down")
		return err
	}
	if err := m.validate(); err != nil {
		return err
	}
	colima := commandPath("colima")
	if colima != "" {
		ctx, cancel := context.WithTimeout(context.Background(), shortCommandTimeout)
		err := stackCommand(ctx, colima, "status").Run()
		cancel()
		if err != nil {
			// An already stopped VM means that the requested end state has
			// been reached. Volumes remain on disk.
			return nil
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), composeTimeout)
	defer cancel()
	return m.compose(ctx, "down", "--remove-orphans")
}

func (m Manager) Status() (string, error) {
	if runtime.GOOS == "linux" {
		out, err := m.linuxMaintenance("status")
		return string(out), err
	}
	if err := m.validate(); err != nil {
		return "", err
	}
	colima := commandPath("colima")
	if colima == "" {
		return "", errors.New("Colima not found; run Install.command")
	}
	statusCtx, statusCancel := context.WithTimeout(context.Background(), shortCommandTimeout)
	statusErr := stackCommand(statusCtx, colima, "status").Run()
	statusCancel()
	if statusErr != nil {
		return "", errors.New("local engine stopped; choose Repair installation or run guardian repair")
	}
	docker := commandPath("docker")
	if docker == "" {
		return "", errors.New("docker executable not found; run Install.command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), shortCommandTimeout)
	defer cancel()
	args := m.dockerComposeArgs("ps")
	cmd := stackCommand(ctx, docker, args...)
	cmd.Env = append(cmd.Env, "GUARDIAN_RUNTIME_DIR="+m.RuntimeDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", errors.New("container check exceeded 15 seconds; choose Repair installation")
		}
		return "", fmt.Errorf("engine status: %w (%s)", err, safeOutput(out))
	}
	healthCtx, healthCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer healthCancel()
	if err := waitForRspamd(healthCtx, rspamdPingURLs, 500*time.Millisecond); err != nil {
		return string(out), fmt.Errorf("containers are visible, but Rspamd is unresponsive: %w; choose Repair installation", err)
	}
	return string(out), nil
}

// DeepCheck verifies the individual stateful and network dependencies used by
// Guardian. It is intentionally read-only and never restarts containers.
func (m Manager) DeepCheck() error {
	if runtime.GOOS == "linux" {
		_, err := m.linuxMaintenance("deep-check")
		return err
	}
	if _, err := m.Status(); err != nil {
		return err
	}
	if err := m.checkRedisPersistence(); err != nil {
		return err
	}
	docker := commandPath("docker")
	for _, check := range []struct {
		name string
		args []string
		want string
	}{
		{name: "Compose configuration", args: []string{"config", "--quiet"}},
		{name: "Rspamd configuration", args: []string{"exec", "-T", "rspamd", "rspamadm", "configtest"}},
		{name: "Redis", args: []string{"exec", "-T", "redis", "redis-cli", "--raw", "ping"}, want: "PONG"},
		{name: "DNS Unbound", args: []string{"exec", "-T", "unbound", "drill-hc", "@127.0.0.1", "dnssec.works"}},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := stackCommand(ctx, docker, m.dockerComposeArgs(check.args...)...)
		cmd.Env = append(cmd.Env, "GUARDIAN_RUNTIME_DIR="+m.RuntimeDir)
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			return fmt.Errorf("%s: %w (%s)", check.name, err, safeOutput(output))
		}
		if check.want != "" && !strings.Contains(string(output), check.want) {
			return fmt.Errorf("%s did not return expected response %q", check.name, check.want)
		}
	}
	colima := commandPath("colima")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	output, err := stackCommand(ctx, colima, "ssh", "--", "df", "-Pk", "/").CombinedOutput()
	cancel()
	if err != nil {
		return fmt.Errorf("Colima disk space: %w (%s)", err, safeOutput(output))
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) < 2 {
		return errors.New("Colima disk space: unrecognized df response")
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 4 {
		return errors.New("Colima disk space: unrecognized df response")
	}
	availableKiB, err := strconv.ParseUint(fields[3], 10, 64)
	if err != nil {
		return fmt.Errorf("Colima disk space: %w", err)
	}
	if availableKiB < 2*1024*1024 {
		return fmt.Errorf("less than 2 GiB disk space remains in Colima")
	}
	return nil
}

func (m Manager) validate() error {
	if m.RuntimeDir == "" {
		return errors.New("missing runtime directory")
	}
	info, err := os.Stat(m.ComposeFile)
	if err != nil {
		return fmt.Errorf("missing %s; run Install.command", m.ComposeFile)
	}
	if info.IsDir() {
		return errors.New("compose path points to a directory")
	}
	return nil
}

func (m Manager) compose(ctx context.Context, args ...string) error {
	docker := commandPath("docker")
	if docker == "" {
		return errors.New("docker executable not found; run Install.command")
	}
	full := m.dockerComposeArgs(args...)
	cmd := stackCommand(ctx, docker, full...)
	cmd.Env = append(cmd.Env, "GUARDIAN_RUNTIME_DIR="+m.RuntimeDir)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("docker compose %s exceeded %s; retry using guardian repair", strings.Join(args, " "), composeTimeout)
		}
		return fmt.Errorf("docker compose %v: %w", args, err)
	}
	return nil
}

func colimaStartArgs() []string {
	return []string{
		"start",
		"--runtime", "docker",
		"--cpus", "2",
		"--memory", "2",
		"--disk", "20",
		"--activate=false",
	}
}

func (m Manager) dockerComposeArgs(args ...string) []string {
	full := []string{
		"--context", "colima",
		"compose",
		"--project-name", "o2-mail-guardian",
		"--file", m.ComposeFile,
	}
	return append(full, args...)
}

func waitForDocker(docker string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		lastErr = stackCommand(ctx, docker, "--context", "colima", "info").Run()
		cancel()
		if lastErr == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("Docker did not become ready within %s: %w", timeout, lastErr)
}

func waitForRspamd(ctx context.Context, urls []string, interval time.Duration) error {
	if len(urls) == 0 {
		return errors.New("missing Rspamd health endpoints")
	}
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	client := &http.Client{Timeout: 3 * time.Second}
	var lastErr error
	for {
		allHealthy := true
		for _, url := range urls {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			response, err := client.Do(request)
			if err != nil {
				lastErr = err
				allHealthy = false
				break
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 32))
			closeErr := response.Body.Close()
			if readErr != nil {
				lastErr = readErr
				allHealthy = false
				break
			}
			if closeErr != nil {
				lastErr = closeErr
				allHealthy = false
				break
			}
			if response.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "pong" {
				lastErr = fmt.Errorf("%s returned HTTP %d and response %q", url, response.StatusCode, strings.TrimSpace(string(body)))
				allHealthy = false
				break
			}
		}
		if allHealthy {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			return fmt.Errorf("no pong response before deadline: %w", lastErr)
		case <-timer.C:
		}
	}
}

func safeOutput(out []byte) string {
	const max = 1000
	out = bytes.TrimSpace(out)
	if len(out) > max {
		out = append(out[:max], []byte("…")...)
	}
	return string(out)
}

// Native macOS apps inherit a minimal PATH. Finding Colima by absolute path
// is insufficient: Colima invokes limactl, and Docker invokes Compose helpers.
// Give every stack subprocess the same explicit dependency search path.
func stackCommand(ctx context.Context, executable string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, executable, args...)
	path := strings.Join([]string{filepath.Dir(executable), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin", os.Getenv("PATH")}, string(os.PathListSeparator))
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "PATH=") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "PATH="+path)
	return cmd
}

func commandPath(name string) string {
	for _, path := range []string{
		filepath.Join("/opt/homebrew/bin", name),
		filepath.Join("/usr/local/bin", name),
	} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	path, _ := exec.LookPath(name)
	return path
}
