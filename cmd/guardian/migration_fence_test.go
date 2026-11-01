package main

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fenceFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "instance")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, "migration.lock")
	if err := os.WriteFile(lock, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lock, 0o640); err != nil {
		t.Fatal(err)
	}
	return dir, lock
}

func TestMigrationFenceCrossLanguageFlock(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux cross-language flock integration")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	dir, path := fenceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	worker, err := acquireMigrationFence(dir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	const exclusiveProbe = `import fcntl, sys
with open(sys.argv[1], 'rb') as f:
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit(0)
    sys.exit(1)
`
	if output, err := exec.CommandContext(ctx, python, "-I", "-c", exclusiveProbe, path).CombinedOutput(); err != nil {
		t.Fatalf("Python acquired exclusive lock during Go shared lock: %v %s", err, output)
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	const sharedHolder = `import fcntl, sys
with open(sys.argv[1], 'rb') as f:
    fcntl.flock(f, fcntl.LOCK_SH | fcntl.LOCK_NB)
    print('ready', flush=True)
    sys.stdin.read(1)
`
	cmd := exec.CommandContext(ctx, python, "-I", "-c", sharedHolder, path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stdin.Close(); _ = cmd.Wait() }()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("Python shared lock not ready: %q %v", line, err)
	}
	admin, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if err := unix.Flock(int(admin.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
		t.Fatal("Go administrator acquired exclusive lock during Python shared lock")
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(admin.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("Go administrator could not acquire lock after Python exited: %v", err)
	}
	if err := unix.Flock(int(admin.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationFenceSerializesAdministratorAndWorker(t *testing.T) {
	dir, path := fenceFixture(t)
	worker, err := acquireMigrationFence(dir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if err := unix.Flock(int(admin.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
		t.Fatal("administrator acquired exclusive fence while worker held it")
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(admin.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("administrator could not acquire released fence: %v", err)
	}
	if _, err := acquireMigrationFence(dir, uint32(os.Getuid())); err == nil {
		t.Fatal("worker entered while administrator held exclusive fence")
	}
	if err := unix.Flock(int(admin.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	worker, err = acquireMigrationFence(dir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	worker.Close()
}

func TestMigrationFenceRejectsPendingAndUntrustedState(t *testing.T) {
	for _, tc := range []struct {
		name       string
		breakFence func(*testing.T, string, string)
	}{
		{"pending", func(t *testing.T, dir, _ string) {
			if err := os.WriteFile(filepath.Join(dir, "migration-pending"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"pending symlink", func(t *testing.T, dir, _ string) {
			if err := os.Symlink("missing", filepath.Join(dir, "migration-pending")); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing lock", func(t *testing.T, _, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink lock", func(t *testing.T, _, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/dev/null", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable lock", func(t *testing.T, _, path string) {
			if err := os.Chmod(path, 0o660); err != nil {
				t.Fatal(err)
			}
		}},
		{"special lock", func(t *testing.T, _, path string) {
			if err := os.Chmod(path, 0o640|os.ModeSetgid); err != nil {
				t.Fatal(err)
			}
		}},
		{"hard linked lock", func(t *testing.T, dir, path string) {
			if err := os.Link(path, filepath.Join(dir, "other")); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable directory", func(t *testing.T, dir, _ string) {
			if err := os.Chmod(dir, 0o770); err != nil {
				t.Fatal(err)
			}
		}},
		{"special directory", func(t *testing.T, dir, _ string) {
			if err := os.Chmod(dir, 0o750|os.ModeSetgid); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := fenceFixture(t)
			tc.breakFence(t, dir, path)
			if lock, err := acquireMigrationFence(dir, uint32(os.Getuid())); err == nil {
				lock.Close()
				t.Fatal("unsafe migration fence accepted")
			}
		})
	}
}
