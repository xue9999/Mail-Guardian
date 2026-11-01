package stack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func freshFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	data, err := hex.DecodeString(emptyRDBHex)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fresh.rdb")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return data, path
}

func freshShell(ctx context.Context, script string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "/bin/sh", append([]string{"-c", script, "fresh-export"}, args...)...)
}

func TestFreshRedisAlwaysExportsAndLeavesOrdinaryBackupAlone(t *testing.T) {
	valid, path := freshFixture(t)
	current := filepath.Join(t.TempDir(), "redis-backup", "current")
	if err := os.MkdirAll(current, 0700); err != nil {
		t.Fatal(err)
	}
	// A preexisting ordinary generation is deliberately not an input to the
	// fresh API. Both calls must execute a new exporter and leave it untouched.
	cache := filepath.Join(current, "model.rdb")
	if err := os.WriteFile(cache, []byte("preserved ordinary generation"), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(cache)
	started := time.Now().UTC()
	attempts := 0
	build := func(ctx context.Context) (*exec.Cmd, error) {
		attempts++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > redisFreshExportTimeout {
			t.Fatal("fresh export did not acquire its runtime limit")
		}
		return freshShell(ctx, `cat "$1"`, path), nil
	}
	for i := 0; i < 2; i++ {
		got, info, err := exportRedisFresh(context.Background(), build, redisFreshExportBytes)
		if err != nil || !bytes.Equal(got, valid) {
			t.Fatalf("fresh export failed: %v", err)
		}
		digest := sha256.Sum256(valid)
		if info.SHA256 != hex.EncodeToString(digest[:]) || info.Bytes != int64(len(valid)) || info.StartedUTC.Before(started) || info.CompletedUTC.Before(info.StartedUTC) || info.CompletedUTC.After(time.Now().UTC()) {
			t.Fatalf("incorrect observation metadata: %+v", info)
		}
	}
	after, _ := os.ReadFile(cache)
	if attempts != 2 || !bytes.Equal(before, after) {
		t.Fatalf("fresh calls reused or changed ordinary backup: attempts=%d", attempts)
	}
}

func TestFreshRedisRejectsFailedExporterWithoutLeakingDiagnostics(t *testing.T) {
	_, path := freshFixture(t)
	for _, exit := range []string{"0", "1"} {
		got, info, err := exportRedisFresh(context.Background(), func(ctx context.Context) (*exec.Cmd, error) {
			return freshShell(ctx, `cat "$1"; printf 'private-model-diagnostic' >&2; exit "$2"`, path, exit), nil
		}, redisFreshExportBytes)
		if exit == "0" {
			if err != nil || got == nil || info.Bytes == 0 {
				t.Fatalf("successful exporter rejected: %v", err)
			}
		} else if err == nil || got != nil || info != (RedisExportInfo{}) || strings.Contains(err.Error(), "private-model") {
			t.Fatalf("failed exporter accepted or leaked data: %d %+v %v", len(got), info, err)
		}
	}
}

func TestFreshRedisBoundsBothStreamsAndRejectsOnOverflow(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			script := "head -c 4097 /dev/zero"
			if stream == "stderr" {
				script = "head -c 65537 /dev/zero >&2"
			}
			got, info, err := exportRedisFresh(ctx, func(ctx context.Context) (*exec.Cmd, error) {
				return freshShell(ctx, script), nil
			}, 4096)
			if got != nil || info != (RedisExportInfo{}) || !errors.Is(err, errMaintenanceOutputLimit) {
				t.Fatalf("unbounded %s accepted: %d %+v %v", stream, len(got), info, err)
			}
		})
	}
}

func TestFreshRedisHonorsCallerCancellationAndDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	startedCommand := false
	got, info, err := exportRedisFresh(ctx, func(ctx context.Context) (*exec.Cmd, error) {
		startedCommand = true
		return freshShell(ctx, "exit 0"), nil
	}, redisFreshExportBytes)
	if got != nil || info != (RedisExportInfo{}) || !errors.Is(err, context.Canceled) || startedCommand {
		t.Fatalf("cancelled call started exporter or returned state: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	got, info, err = exportRedisFresh(ctx, func(ctx context.Context) (*exec.Cmd, error) {
		deadline, _ := ctx.Deadline()
		if time.Until(deadline) > 100*time.Millisecond {
			t.Fatal("internal timeout replaced earlier caller deadline")
		}
		return freshShell(ctx, "sleep 10"), nil
	}, redisFreshExportBytes)
	if got != nil || info != (RedisExportInfo{}) || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("caller deadline was lost: %v", err)
	}
}

func TestFreshRedisRejectsOrphanHeldPipes(t *testing.T) {
	_, path := freshFixture(t)
	start := time.Now()
	got, info, err := exportRedisFresh(context.Background(), func(ctx context.Context) (*exec.Cmd, error) {
		return freshShell(ctx, `cat "$1"; sleep 10 & exit 0`, path), nil
	}, redisFreshExportBytes)
	if got != nil || info != (RedisExportInfo{}) || !errors.Is(err, exec.ErrWaitDelay) || time.Since(start) > 3*time.Second {
		t.Fatalf("orphan-held pipes accepted or unbounded: %v", err)
	}
}

func TestFreshRedisRequiresNumericHeaderChecksumAndExactTrailer(t *testing.T) {
	valid, _ := freshFixture(t)
	badHeader := append([]byte(nil), valid...)
	badHeader[5] = 'x'
	// Give the malformed header a correct CRC, so rejection is due to the
	// envelope rather than coincidental checksum damage.
	var checksum uint64
	for _, b := range badHeader[:len(badHeader)-8] {
		checksum ^= uint64(b)
		for i := 0; i < 8; i++ {
			if checksum&1 != 0 {
				checksum = (checksum >> 1) ^ 0x95ac9329ac4bc9b5
			} else {
				checksum >>= 1
			}
		}
	}
	binary.LittleEndian.PutUint64(badHeader[len(badHeader)-8:], checksum)
	if err := validateRedisRDB(badHeader); err != nil {
		t.Fatalf("fixture did not isolate stricter header validation: %v", err)
	}
	corrupt := append([]byte(nil), valid...)
	corrupt[len(corrupt)-1] ^= 1
	for _, data := range [][]byte{nil, valid[:len(valid)-1], corrupt, badHeader, append(append([]byte(nil), valid...), []byte(strings.Repeat("z", 40))...)} {
		if got, err := freshRedisPayload(context.Background(), data); got != nil || err == nil {
			t.Fatal("invalid fresh RDB accepted")
		}
	}
	stream := append(append([]byte(nil), valid...), []byte(strings.Repeat("a", 40))...)
	if got, err := freshRedisPayload(context.Background(), stream); err != nil || !bytes.Equal(got, valid) {
		t.Fatalf("exact valid replication trailer rejected: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := freshRedisPayload(ctx, valid); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("validation ignored cancellation: %v", err)
	}
}

func TestFreshRedisCommandRetainsPlatformBoundaries(t *testing.T) {
	ctx := context.Background()
	m := Manager{Instance: "pilot", ComposeFile: "/ignored-on-linux", RuntimeDir: "/ignored-on-linux"}
	cmd, err := m.freshRedisCommand(ctx, "linux", func(string) string { t.Fatal("Linux looked for worker Docker"); return "" })
	if err != nil || !reflect.DeepEqual(cmd.Args, []string{"/usr/bin/sudo", "-n", "--", linuxMaintenanceHelper, "pilot", "export-redis"}) || cmd.Dir != "/" || !reflect.DeepEqual(cmd.Env, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}) {
		t.Fatalf("Linux export crossed helper boundary: %#v %v", cmd, err)
	}
	m.Instance = "../escape"
	if cmd, err := m.freshRedisCommand(ctx, "linux", nil); cmd != nil || err == nil {
		t.Fatal("invalid Linux instance accepted")
	}
	compose := filepath.Join(t.TempDir(), "compose.yaml")
	if err := os.WriteFile(compose, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	m = Manager{ComposeFile: compose, RuntimeDir: t.TempDir()}
	cmd, err = m.freshRedisCommand(ctx, "darwin", func(name string) string {
		if name != "docker" {
			t.Fatalf("unexpected executable: %s", name)
		}
		return "/fixture/docker"
	})
	want := []string{"/fixture/docker", "--context", "colima", "compose", "--project-name", "o2-mail-guardian", "--file", compose, "exec", "-T", "redis", "redis-cli", "--rdb", "-"}
	if err != nil || !reflect.DeepEqual(cmd.Args, want) || !strings.Contains(strings.Join(cmd.Env, "\n"), "GUARDIAN_RUNTIME_DIR="+m.RuntimeDir) {
		t.Fatalf("Mac export lost explicit context/runtime: %#v %v", cmd, err)
	}
	if cmd, err := m.freshRedisCommand(ctx, "windows", nil); cmd != nil || err == nil {
		t.Fatal("unsupported platform accepted")
	}
}
