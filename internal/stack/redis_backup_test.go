package stack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRedisExportRequiresSuccessfulProcessAndValidChecksum(t *testing.T) {
	valid, _ := hex.DecodeString(emptyRDBHex)
	path := filepath.Join(t.TempDir(), "snapshot.rdb")
	if err := os.WriteFile(path, valid, 0600); err != nil {
		t.Fatal(err)
	}
	for _, exit := range []string{"0", "1"} {
		cmd := exec.Command("/bin/sh", "-c", `cat "$1"; printf 'Transfer finished with success\n' >&2; exit "$2"`, "export", path, exit)
		payload, err := captureRedisRDBExport(context.Background(), cmd)
		if exit == "0" {
			if err != nil || string(payload) != string(valid) {
				t.Fatalf("successful valid export rejected: %v", err)
			}
		} else if err == nil || payload != nil {
			t.Fatal("nonzero process exit was accepted because output looked successful")
		}
	}
	if err := os.WriteFile(path, valid[:len(valid)-1], 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", `cat "$1"`, "export", path)
	if payload, err := captureRedisRDBExport(context.Background(), cmd); err == nil || payload != nil {
		t.Fatal("successful process exit concealed an invalid RDB")
	}
}

func TestRedisExportReportsItsDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "exit 0")
	payload, err := captureRedisRDBExport(ctx, cmd)
	var processErr *redisExportProcessError
	if payload != nil || !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &processErr) {
		t.Fatalf("export lost deadline evidence: %v", err)
	}
}

func TestRedisExportRetriesFreshAttemptAndRemainsBounded(t *testing.T) {
	valid, _ := hex.DecodeString(emptyRDBHex)
	firstFailure := errors.New("first export failed")
	var firstContext context.Context
	attempts := 0
	payload, err := retryRedisRDBExport(func(ctx context.Context) ([]byte, error) {
		attempts++
		if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
			t.Fatal("export has no fresh bounded context")
		}
		if attempts == 1 {
			firstContext = ctx
			return nil, &redisExportProcessError{firstFailure}
		}
		if ctx == firstContext || firstContext.Err() == nil {
			t.Fatal("retry reused the failed export context")
		}
		return valid, nil
	})
	if err != nil || attempts != 2 || string(payload) != string(valid) {
		t.Fatalf("fresh retry did not recover: attempts=%d err=%v", attempts, err)
	}
	attempts = 0
	if payload, err := retryRedisRDBExport(func(context.Context) ([]byte, error) {
		attempts++
		return nil, &redisExportProcessError{firstFailure}
	}); payload != nil || !errors.Is(err, firstFailure) || attempts != 2 {
		t.Fatalf("export failure did not remain bounded: attempts=%d err=%v", attempts, err)
	}
	attempts = 0
	if payload, err := retryRedisRDBExport(func(context.Context) ([]byte, error) {
		attempts++
		return nil, firstFailure
	}); payload != nil || !errors.Is(err, firstFailure) || attempts != 1 {
		t.Fatalf("non-process failure was retried: attempts=%d err=%v", attempts, err)
	}
}

// Minimal empty Redis RDB with its independently computed Jones CRC64.
const emptyRDBHex = "524544495330303131ffc0228a8d74389762"

func TestRedisRDBRejectsTruncationAndCorruption(t *testing.T) {
	valid, _ := hex.DecodeString(emptyRDBHex)
	if err := validateRedisRDB(valid); err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), valid...)
	corrupt[7] ^= 1
	for _, data := range [][]byte{nil, valid[:len(valid)-1], []byte("Redis backup failed"), corrupt} {
		if err := validateRedisRDB(data); err == nil {
			t.Fatal("invalid model snapshot was accepted")
		}
	}
}

func TestRedisCLIReplicationMarkerRequiresValidPayloadChecksum(t *testing.T) {
	valid, _ := hex.DecodeString(emptyRDBHex)
	stream := append(append([]byte(nil), valid...), []byte(strings.Repeat("a", 40))...)
	payload, err := redisRDBPayload(stream)
	if err != nil || string(payload) != string(valid) {
		t.Fatalf("valid stdout replication stream rejected: %v", err)
	}
	stream[7] ^= 1
	if _, err := redisRDBPayload(stream); err == nil {
		t.Fatal("marker concealed corrupt model")
	}
}

func TestRedisBackupPreservesLastGoodModelOnRollback(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "redis-backup", "current")
	if err := os.MkdirAll(current, 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := hex.DecodeString(emptyRDBHex)
	hash := sha256.Sum256(data)
	info := redisBackupInfo{Spam: 154, Ham: 137, SHA256: hex.EncodeToString(hash[:]), Created: time.Now().UTC()}
	meta, _ := json.Marshal(info)
	if err := os.WriteFile(filepath.Join(current, "model.rdb"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(current, "metadata.json"), meta, 0600); err != nil {
		t.Fatal(err)
	}
	m := Manager{}
	if err := m.backupRedis(dir, 154, 137); err != nil {
		t.Fatalf("fresh verified snapshot unexpectedly needs Docker: %v", err)
	}
	for _, revisions := range [][2]uint64{{0, 0}, {153, 137}, {154, 136}} {
		if err := m.backupRedis(dir, revisions[0], revisions[1]); err == nil || !strings.Contains(err.Error(), "rolled back") {
			t.Fatalf("rollback accepted: %v", err)
		}
	}
	got, _ := os.ReadFile(filepath.Join(current, "model.rdb"))
	if string(got) != string(data) {
		t.Fatal("last good model was changed")
	}
	gotMeta, _ := os.ReadFile(filepath.Join(current, "metadata.json"))
	if string(gotMeta) != string(meta) {
		t.Fatal("last good metadata was changed")
	}
}

func TestRedisPersistenceRequiresWorkingAOFAndRDB(t *testing.T) {
	valid := "aof_enabled:1\r\naof_last_write_status:ok\r\nrdb_last_bgsave_status:ok\r\n"
	if err := validateRedisPersistence(valid); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{"PONG", strings.Replace(valid, "aof_enabled:1", "aof_enabled:0", 1), strings.Replace(valid, "aof_last_write_status:ok", "aof_last_write_status:err", 1), strings.Replace(valid, "rdb_last_bgsave_status:ok", "rdb_last_bgsave_status:err", 1)} {
		if err := validateRedisPersistence(data); err == nil {
			t.Fatal("unprotected Redis accepted as healthy")
		}
	}
}

func TestRedisPersistenceCommandsHaveIndependentDeadlines(t *testing.T) {
	const timeout = 200 * time.Millisecond
	started := time.Now()
	attempts := 0
	err := checkRedisPersistenceCommands(timeout, func(ctx context.Context, args ...string) ([]byte, error) {
		attempts++
		select {
		case <-time.After(150 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if args[0] == "INFO" {
			return []byte("aof_enabled:1\r\naof_last_write_status:ok\r\nrdb_last_bgsave_status:ok\r\n"), nil
		}
		return []byte("appendfsync\nalways\n"), nil
	})
	if err != nil || attempts != 2 {
		t.Fatalf("individually timely commands failed: attempts=%d err=%v", attempts, err)
	}
	if elapsed := time.Since(started); elapsed <= timeout {
		t.Fatalf("regression did not exceed the former shared allowance: %s", elapsed)
	}
}

func TestRedisPersistenceRetriesOnlyFailedCommandsAndRejectsBadState(t *testing.T) {
	valid := []byte("aof_enabled:1\r\naof_last_write_status:ok\r\nrdb_last_bgsave_status:ok\r\n")
	for _, failCommand := range []string{"INFO", "CONFIG"} {
		t.Run(failCommand, func(t *testing.T) {
			attempts := map[string]int{}
			var failed context.Context
			err := checkRedisPersistenceCommands(time.Second, func(ctx context.Context, args ...string) ([]byte, error) {
				attempts[args[0]]++
				if args[0] == failCommand && attempts[args[0]] == 1 {
					failed = ctx
					return nil, errors.New("transport process failed")
				}
				if failed != nil && (ctx == failed || failed.Err() == nil) {
					t.Fatal("retry inherited the failed command's context")
				}
				if args[0] == "INFO" {
					return valid, nil
				}
				return []byte("appendfsync\nalways\n"), nil
			})
			if err != nil || attempts[failCommand] != 2 {
				t.Fatalf("read-only process retry failed: attempts=%v err=%v", attempts, err)
			}
		})
	}
	for _, bad := range []string{"persistence", "fsync"} {
		t.Run("bad "+bad, func(t *testing.T) {
			attempts := map[string]int{}
			err := checkRedisPersistenceCommands(time.Second, func(_ context.Context, args ...string) ([]byte, error) {
				attempts[args[0]]++
				if args[0] == "INFO" {
					if bad == "persistence" {
						return []byte("aof_enabled:0\n"), nil
					}
					return valid, nil
				}
				return []byte("appendfsync\neverysec\n"), nil
			})
			if err == nil || attempts["INFO"] != 1 || attempts["CONFIG"] > 1 {
				t.Fatalf("unsafe state was accepted or retried: attempts=%v err=%v", attempts, err)
			}
		})
	}
}

func TestRedisBackupRotationAndInterruptedPublicationPreserveBaseline(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "redis-backup")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := hex.DecodeString(emptyRDBHex)
	hash := sha256.Sum256(data)
	for _, revision := range []uint64{1, 2, 3} {
		info := redisBackupInfo{Spam: revision, Ham: revision, SHA256: hex.EncodeToString(hash[:]), Created: time.Now().UTC()}
		if err := publishRedisBackup(root, data, info); err != nil {
			t.Fatal(err)
		}
	}
	for name, revision := range map[string]uint64{"current": 3, "previous": 2} {
		meta, err := os.ReadFile(filepath.Join(root, name, "metadata.json"))
		if err != nil {
			t.Fatal(err)
		}
		var info redisBackupInfo
		if err := json.Unmarshal(meta, &info); err != nil || info.Spam != revision {
			t.Fatalf("incorrect %s generation: %s %v", name, meta, err)
		}
		stat, err := os.Stat(filepath.Join(root, name, "model.rdb"))
		if err != nil || stat.Mode().Perm() != 0600 {
			t.Fatalf("snapshot permissions: %v %v", stat, err)
		}
	}
	// A crash between current -> previous and stage -> current still retains
	// the rollback guard. It cannot replace the model with an empty baseline.
	if err := os.RemoveAll(filepath.Join(root, "previous")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "current"), filepath.Join(root, "previous")); err != nil {
		t.Fatal(err)
	}
	if err := (Manager{}).BackupRedis(dir, 0, 0); err == nil {
		t.Fatal("interrupted publication lost its rollback guard")
	}
}
