package stack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type redisBackupInfo struct {
	Spam    uint64    `json:"spam_revision"`
	Ham     uint64    `json:"ham_revision"`
	SHA256  string    `json:"sha256"`
	Created time.Time `json:"created_at"`
}

func validateRedisRDB(data []byte) error {
	if len(data) < 18 || !bytes.HasPrefix(data, []byte("REDIS")) || data[len(data)-9] != 0xff {
		return errors.New("nieprawidłowy zrzut Redis")
	}
	var table [256]uint64
	for i := range table {
		v := uint64(i)
		for n := 0; n < 8; n++ {
			if v&1 != 0 {
				v = (v >> 1) ^ 0x95ac9329ac4bc9b5
			} else {
				v >>= 1
			}
		}
		table[i] = v
	}
	var checksum uint64
	for _, b := range data[:len(data)-8] {
		checksum = table[byte(checksum)^b] ^ (checksum >> 8)
	}
	if checksum != binary.LittleEndian.Uint64(data[len(data)-8:]) {
		return errors.New("błędna suma kontrolna kopii Redis")
	}
	return nil
}

func redisRDBPayload(data []byte) ([]byte, error) {
	if err := validateRedisRDB(data); err == nil {
		return data, nil
	}
	// redis-cli cannot truncate stdout, so diskless --rdb - may retain the
	// 40-byte replication EOF marker. Strip it only if the RDB checksum proves
	// the exact preceding bytes are a complete, uncorrupted RDB.
	if len(data) >= 58 {
		marker := data[len(data)-40:]
		if _, err := hex.DecodeString(string(marker)); err == nil {
			payload := data[:len(data)-40]
			if err := validateRedisRDB(payload); err == nil {
				return payload, nil
			}
		}
	}
	return nil, errors.New("otrzymano uszkodzoną lub niepełną kopię Redis")
}

// Do not embed bytes.Buffer: its promoted ReadFrom method would let io.Copy
// bypass Write and silently defeat the size bound on subprocess output.
type rdbBuffer struct{ buffer bytes.Buffer }

func (b *rdbBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *rdbBuffer) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > 128<<20 {
		return 0, errors.New("kopia Redis przekracza 128 MiB")
	}
	return b.buffer.Write(p)
}

// BackupRedis preserves two checksummed generations outside the VM. A model
// rollback cannot replace the last good generation. Paired metadata and RDB
// are published as one directory, so a crash cannot mix their contents.
func (m Manager) BackupRedis(dataDir string, spam, ham uint64) error {
	if runtime.GOOS == "linux" {
		// A recent snapshot is not evidence that current Redis writes or the
		// host disk remain healthy. Check even when no new export is needed.
		if err := m.checkRedisPersistence(); err != nil {
			return err
		}
	}
	return m.backupRedis(dataDir, spam, ham)
}

func (m Manager) backupRedis(dataDir string, spam, ham uint64) error {
	root := filepath.Join(dataDir, "redis-backup")
	current, previous := filepath.Join(root, "current"), filepath.Join(root, "previous")
	baseline := current
	if _, err := os.Stat(current); os.IsNotExist(err) {
		baseline = previous
	}
	if meta, err := os.ReadFile(filepath.Join(baseline, "metadata.json")); err == nil {
		var old redisBackupInfo
		if err := json.Unmarshal(meta, &old); err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(baseline, "model.rdb"))
		if err != nil {
			return err
		}
		if err := validateRedisRDB(data); err != nil {
			return err
		}
		hash := sha256.Sum256(data)
		if hex.EncodeToString(hash[:]) != old.SHA256 {
			return errors.New("kopia Redis nie zgadza się z metadanymi")
		}
		if spam < old.Spam || ham < old.Ham {
			return errors.New("model Bayesa cofnął się; poprzednia kopia została zachowana")
		}
		if spam == old.Spam && ham == old.Ham && time.Since(old.Created) < 12*time.Hour {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	payload, err := retryRedisRDBExport(func(ctx context.Context) ([]byte, error) {
		if runtime.GOOS == "linux" {
			cmd, err := linuxMaintenanceCommand(ctx, m.Instance, "export-redis")
			if err != nil {
				return nil, err
			}
			output, err := captureLinuxMaintenance(ctx, cmd, 128<<20)
			if err != nil {
				return nil, err
			}
			return redisRDBPayload(output)
		}
		docker := commandPath("docker")
		if docker == "" {
			return nil, errors.New("brakuje Dockera do zabezpieczenia modelu")
		}
		cmd := stackCommand(ctx, docker, m.dockerComposeArgs("exec", "-T", "redis", "redis-cli", "--rdb", "-")...)
		cmd.Env = append(cmd.Env, "GUARDIAN_RUNTIME_DIR="+m.RuntimeDir)
		return captureRedisRDBExport(ctx, cmd)
	})
	if err != nil {
		return err
	}
	hash := sha256.Sum256(payload)
	info := redisBackupInfo{Spam: spam, Ham: ham, SHA256: hex.EncodeToString(hash[:]), Created: time.Now().UTC()}
	return publishRedisBackup(root, payload, info)
}

// Export is read-only. One fresh retry can recover a transient Docker process
// or transport failure without publishing the incomplete first attempt.
func retryRedisRDBExport(export func(context.Context) ([]byte, error)) ([]byte, error) {
	var failures error
	for attempt := 1; attempt <= 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		payload, err := export(ctx)
		cancel()
		if err == nil {
			return payload, nil
		}
		var processErr *redisExportProcessError
		if !errors.As(err, &processErr) {
			return nil, err
		}
		failures = errors.Join(failures, fmt.Errorf("próba %d: %w", attempt, err))
	}
	return nil, failures
}

type redisExportProcessError struct{ error }

func (e *redisExportProcessError) Unwrap() error { return e.error }

func captureRedisRDBExport(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
	var output rdbBuffer
	var diagnostic bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &diagnostic
	if err := cmd.Run(); err != nil {
		// A transfer-success diagnostic or even valid captured bytes cannot
		// substitute for successful termination of the exporting process.
		return nil, &redisExportProcessError{fmt.Errorf("eksport modelu Redis: %w (%s)", errors.Join(err, ctx.Err()), safeOutput(diagnostic.Bytes()))}
	}
	return redisRDBPayload(output.Bytes())
}

func publishRedisBackup(root string, payload []byte, info redisBackupInfo) error {
	if err := validateRedisRDB(payload); err != nil {
		return err
	}
	hash := sha256.Sum256(payload)
	if info.SHA256 != hex.EncodeToString(hash[:]) {
		return errors.New("metadane nie zgadzają się z kopią Redis")
	}
	current, previous := filepath.Join(root, "current"), filepath.Join(root, "previous")
	meta, _ := json.Marshal(info)
	stage, err := os.MkdirTemp(root, ".stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for name, data := range map[string][]byte{"model.rdb": payload, "metadata.json": meta} {
		f, err := os.OpenFile(filepath.Join(stage, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(data)
		syncErr, closeErr := f.Sync(), f.Close()
		if writeErr != nil {
			return writeErr
		}
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if _, err := os.Stat(current); err == nil {
		if err := os.RemoveAll(previous); err != nil {
			return err
		}
		if err := os.Rename(current, previous); err != nil {
			return err
		}
	}
	if err := os.Rename(stage, current); err != nil {
		return err
	}
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validateRedisPersistence(output string) error {
	fields := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok {
			fields[key] = value
		}
	}
	for _, key := range []string{"aof_last_write_status", "rdb_last_bgsave_status"} {
		if fields[key] != "ok" {
			return errors.New("Redis nie potwierdza poprawnego zapisu danych; filtr wymaga sprawdzenia dysku Colimy")
		}
	}
	if fields["aof_enabled"] != "1" {
		return errors.New("dziennik trwałego zapisu Redis jest wyłączony")
	}
	return nil
}

// CheckPersistence checks host storage plus synchronous Redis persistence.
// Every unattended mutation must pass this gate before opening the mailbox.
func (m Manager) CheckPersistence() error { return m.checkRedisPersistence() }

func (m Manager) checkRedisPersistence() error {
	if runtime.GOOS == "linux" {
		_, err := m.linuxMaintenance("check-persistence")
		return err
	}
	if err := m.CheckStorage(); err != nil {
		return err
	}
	return checkRedisPersistenceCommands(shortCommandTimeout, func(ctx context.Context, args ...string) ([]byte, error) {
		commandArgs := append([]string{"exec", "-T", "redis", "redis-cli", "--raw"}, args...)
		cmd := stackCommand(ctx, commandPath("docker"), m.dockerComposeArgs(commandArgs...)...)
		cmd.Env = append(cmd.Env, "GUARDIAN_RUNTIME_DIR="+m.RuntimeDir)
		output, err := cmd.Output()
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			err = fmt.Errorf("%w (%s)", err, safeOutput(exit.Stderr))
		}
		return output, err
	})
}

func checkRedisPersistenceCommands(timeout time.Duration, command func(context.Context, ...string) ([]byte, error)) error {
	read := func(args ...string) ([]byte, error) {
		var failures error
		for attempt := 1; attempt <= 2; attempt++ {
			// Each read and retry gets its own full allowance. Sharing one
			// deadline made a healthy second command inherit the first's delay.
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			output, err := command(ctx, args...)
			if err != nil {
				err = errors.Join(err, ctx.Err())
			}
			cancel()
			if err == nil {
				return output, nil
			}
			failures = errors.Join(failures, fmt.Errorf("próba %d: %w", attempt, err))
		}
		return nil, failures
	}
	output, err := read("INFO", "persistence")
	if err != nil {
		return fmt.Errorf("kontrola trwałości Redis: %w", err)
	}
	if err := validateRedisPersistence(string(output)); err != nil {
		return err
	}
	config, err := read("CONFIG", "GET", "appendfsync")
	if err != nil {
		return fmt.Errorf("kontrola fsync Redis: %w", err)
	}
	if strings.Join(strings.Fields(string(config)), " ") != "appendfsync always" {
		return errors.New("Redis nie potwierdza synchronicznego zapisu AOF; wymagane appendfsync always")
	}
	return nil
}
