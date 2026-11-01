package stack

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	redisFreshExportTimeout = time.Minute
	redisFreshExportBytes   = 128 << 20
	redisFreshDiagnosticMax = 64 << 10
	redisFreshWaitDelay     = time.Second
)

// RedisExportInfo describes only the bytes returned by ExportRedisFresh and
// the local observation window. It does not attest writer exclusion, source
// identity, complete RDB structure, model revisions or model equivalence.
type RedisExportInfo struct {
	SHA256       string    `json:"sha256"`
	Bytes        int64     `json:"bytes"`
	StartedUTC   time.Time `json:"started_utc"`
	CompletedUTC time.Time `json:"completed_utc"`
}

// ExportRedisFresh performs one new read-only Redis export. It neither reads
// the ordinary twelve-hour backup cache nor publishes a backup generation.
// Output is limited to 128 MiB and dependency diagnostics to 64 KiB. The
// subprocess receives the earlier of the caller's context and a one-minute
// deadline, with a one-second inherited-pipe wait policy. These control whether
// this API can return a result, not whether every privileged or Docker-side
// descendant has stopped. Dependency output is never logged
// or returned on failure. Returned bytes have a numeric RDB header and valid
// Jones CRC64, not a full independent structural/semantic validation.
//
// The caller must hold the actual ownership/capture boundary and independently
// validate the restored model, revisions and expiration semantics. Cancelling
// sudo cannot prove that a privileged Linux helper or Docker-side export has
// stopped: an error invalidates this capture, and the caller must retain its
// fence and establish helper/stack quiescence before proceeding.
func (m Manager) ExportRedisFresh(ctx context.Context) ([]byte, RedisExportInfo, error) {
	return exportRedisFresh(ctx, func(ctx context.Context) (*exec.Cmd, error) {
		return m.freshRedisCommand(ctx, runtime.GOOS, commandPath)
	}, redisFreshExportBytes)
}

// Keep command construction separate from execution so tests can inspect the
// same platform boundaries without invoking sudo or an actual Docker daemon.
func (m Manager) freshRedisCommand(ctx context.Context, goos string, locate func(string) string) (*exec.Cmd, error) {
	if goos == "linux" {
		return linuxMaintenanceCommand(ctx, m.Instance, "export-redis")
	}
	if goos != "darwin" {
		return nil, errors.New("fresh Redis export requires a supported Guardian platform")
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	docker := locate("docker")
	if docker == "" {
		return nil, errors.New("Docker is unavailable for fresh Redis export")
	}
	cmd := stackCommand(ctx, docker, m.dockerComposeArgs("exec", "-T", "redis", "redis-cli", "--rdb", "-")...)
	cmd.Env = append(cmd.Env, "GUARDIAN_RUNTIME_DIR="+m.RuntimeDir)
	return cmd, nil
}

func exportRedisFresh(ctx context.Context, build func(context.Context) (*exec.Cmd, error), maxBytes int) ([]byte, RedisExportInfo, error) {
	if ctx == nil {
		return nil, RedisExportInfo{}, errors.New("fresh Redis export requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, RedisExportInfo{}, err
	}
	if maxBytes <= 0 || maxBytes > redisFreshExportBytes {
		return nil, RedisExportInfo{}, errors.New("invalid fresh Redis export byte limit")
	}
	ctx, cancel := context.WithTimeout(ctx, redisFreshExportTimeout)
	defer cancel()
	started := time.Now().UTC()
	cmd, err := build(ctx)
	if err != nil {
		return nil, RedisExportInfo{}, err
	}
	if cmd == nil {
		return nil, RedisExportInfo{}, errors.New("fresh Redis exporter is unavailable")
	}
	payload, err := captureFreshRedisProcess(ctx, cmd, maxBytes)
	if err != nil {
		return nil, RedisExportInfo{}, err
	}
	payload, err = freshRedisPayload(ctx, payload)
	if err != nil {
		return nil, RedisExportInfo{}, err
	}
	// Chunked hashing keeps cancellation effective during validation as well as
	// while the subprocess is running, even at the maximum output size.
	h := sha256.New()
	for offset := 0; offset < len(payload); {
		if err := ctx.Err(); err != nil {
			return nil, RedisExportInfo{}, err
		}
		end := min(offset+(64<<10), len(payload))
		_, _ = h.Write(payload[offset:end])
		offset = end
	}
	if err := ctx.Err(); err != nil {
		return nil, RedisExportInfo{}, err
	}
	return payload, RedisExportInfo{SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: int64(len(payload)), StartedUTC: started, CompletedUTC: time.Now().UTC()}, nil
}

func captureFreshRedisProcess(ctx context.Context, cmd *exec.Cmd, maxBytes int) ([]byte, error) {
	output := &maintenanceBuffer{limit: maxBytes}
	diagnostic := &maintenanceBuffer{limit: redisFreshDiagnosticMax}
	cmd.Stdout, cmd.Stderr = output, diagnostic
	cmd.WaitDelay = redisFreshWaitDelay
	// A dedicated process group allows cancellation/cleanup of ordinary local
	// CLI descendants. This is best effort for setuid sudo/root helpers and is
	// deliberately not treated as proof of privileged or Docker-side quiescence.
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	killGroup := func() error {
		if cmd.Process == nil {
			return nil
		}
		err := unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if err == nil || errors.Is(err, unix.ESRCH) {
			return nil
		}
		return cmd.Process.Kill()
	}
	// All production commands are CommandContext. Setting Cancel also makes
	// the cleanup policy explicit for injectable test commands.
	cmd.Cancel = killGroup
	err := cmd.Run()
	// A successful/reaped command must not be signalled again: its former
	// process-group identifier could be reused. ErrWaitDelay indicates an
	// inherited pipe remains open; clean up that ordinary descendant group on
	// a best-effort basis. Privileged helpers still require external fencing.
	if errors.Is(err, exec.ErrWaitDelay) {
		_ = killGroup()
	}
	if output.overflow || diagnostic.overflow {
		return nil, errMaintenanceOutputLimit
	}
	if err != nil || ctx.Err() != nil {
		return nil, fmt.Errorf("fresh Redis export process failed: %w", errors.Join(err, ctx.Err()))
	}
	return output.buffer.Bytes(), nil
}

func freshRedisPayload(ctx context.Context, data []byte) ([]byte, error) {
	if err := validateFreshRedisRDB(ctx, data); err == nil {
		return data, nil
	} else if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// redis-cli can retain a 40-byte replication EOF token on stdout. A token
	// is stripped only if its exact preceding payload independently validates.
	if len(data) >= 58 {
		if _, err := hex.DecodeString(string(data[len(data)-40:])); err == nil {
			payload := data[:len(data)-40]
			if err := validateFreshRedisRDB(ctx, payload); err == nil {
				return payload, nil
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("fresh Redis export has an invalid RDB header or checksum")
}

func validateFreshRedisRDB(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(data) < 18 || string(data[:5]) != "REDIS" || data[len(data)-9] != 0xff {
		return errors.New("invalid RDB envelope")
	}
	for _, digit := range data[5:9] {
		if digit < '0' || digit > '9' {
			return errors.New("invalid RDB version header")
		}
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
	for i, b := range data[:len(data)-8] {
		if i&0xffff == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		checksum = table[byte(checksum)^b] ^ (checksum >> 8)
	}
	if checksum != binary.LittleEndian.Uint64(data[len(data)-8:]) {
		return errors.New("invalid RDB checksum")
	}
	return ctx.Err()
}
