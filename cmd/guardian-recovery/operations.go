package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/BurntSushi/toml"
	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/migration"
	"github.com/xue9999/Mail-Guardian/internal/recoverybundle"
	"github.com/xue9999/Mail-Guardian/internal/redismodel"
	"github.com/xue9999/Mail-Guardian/internal/stack"
	"golang.org/x/sys/unix"
)

func commandFlags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	return f
}

func recoveryLimits() migration.ReadinessLimits {
	return migration.ReadinessLimits{MaxDatabaseBytes: 64 << 20, MaxRows: 1_000_000,
		MaxArchiveReferences: 100_000, MaxArchives: 50_000, MaxInventoryBytes: 16 << 20, MaxPathBytes: 4096}
}

// Caller quiescence is deliberately an operational precondition, not a boolean
// flag that could be mistaken for proof. No command in this file fences owners.
func runRedisExport(ctx context.Context, args []string, out io.Writer) error {
	f := commandFlags("export-redis")
	cfgPath := f.String("config", "", "explicit private source configuration")
	destination := f.String("output", "", "new private RDB file")
	instance := f.String("instance", "", "Linux instance slug; unused on Mac")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || *cfgPath == "" || *destination == "" {
		return errors.New("export-redis requires --config FILE --output NEW_RDB [--instance SLUG]")
	}
	cfg, err := readConfiguration(*cfgPath)
	if err != nil {
		return err
	}
	// Open the exclusive destination before invoking Redis, so an unsafe output
	// path cannot trigger an otherwise unnecessary source snapshot.
	file, err := createPrivateOutput(*destination)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(*destination)
		}
	}()
	m := exportManager(cfg, *instance)
	payload, info, err := m.ExportRedisFresh(ctx)
	if err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		return errors.New("fresh model could not be written")
	}
	if err := finishPrivateOutput(file, *destination); err != nil {
		return err
	}
	complete = true
	return json.NewEncoder(out).Encode(struct {
		Scope string `json:"scope"`
		stack.RedisExportInfo
	}{"fresh RDB export; source writers must be stopped; restored model not yet validated", info})
}

func exportManager(cfg config.Config, instance string) stack.Manager {
	// Match the installed Mac stack's controller-mount location. DataDir holds
	// mailbox state and is deliberately a different directory. On Linux the
	// privileged helper resolves all paths from the explicit instance slug.
	return stack.Manager{ComposeFile: cfg.Runtime.ComposeFile, RuntimeDir: config.DefaultRuntimeDir(), Instance: instance}
}

func runMapConfig(ctx context.Context, args []string, out io.Writer) error {
	f := commandFlags("map-config")
	source := f.String("config", "", "explicit private source configuration")
	instance := f.String("instance", "", "target Linux instance slug")
	destination := f.String("output", "", "new private Linux configuration")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || *source == "" || *instance == "" || *destination == "" {
		return errors.New("map-config requires --config SOURCE --instance SLUG --output NEW_PRIVATE_CONFIG")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	cfg, err := readConfiguration(*source)
	if err != nil {
		return err
	}
	mapped, err := migration.LinuxConfig(cfg, *instance)
	if err != nil {
		return err
	}
	file, err := createPrivateOutput(*destination)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(*destination)
		}
	}()
	if err := toml.NewEncoder(file).Encode(mapped); err != nil {
		return errors.New("mapped configuration could not be encoded")
	}
	if err := finishPrivateOutput(file, *destination); err != nil {
		return err
	}
	complete = true
	digest, size, err := fileDigest(*destination)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		Scope        string `json:"scope"`
		SHA256       string `json:"sha256"`
		Bytes        int64  `json:"bytes"`
		Mode         string `json:"mode"`
		PurgeEnabled bool   `json:"purge_enabled"`
	}{"offline Linux configuration mapping; no state import or target authorization", digest, size, mapped.Safety.Mode, mapped.Safety.PurgeEnabled})
}

func runRelocate(ctx context.Context, args []string, out io.Writer) error {
	f := commandFlags("relocate-snapshot")
	cfgPath := f.String("config", "", "explicit private source configuration")
	source := f.String("source", "", "prepared standalone source database")
	destination := f.String("database", "", "new relocated database")
	archives := f.String("archive-root", "", "private staged encrypted archive tree")
	target := f.String("target-archive-root", "", "absolute target archive path")
	key := f.String("identity-file", "", "private original archive identity file")
	preserveHistory := f.Bool("preserve-policy-history", false, "preserve activation history for separate explicit target policy adoption")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || *cfgPath == "" || *source == "" || *destination == "" || *archives == "" || *target == "" || *key == "" {
		return errors.New("relocate-snapshot requires --config FILE --source PREPARED_DB --database NEW_DB --archive-root STAGED_TREE --target-archive-root TARGET_PATH --identity-file PRIVATE_KEY_FILE")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cfg, err := readConfiguration(*cfgPath)
	if err != nil {
		return err
	}
	identity, err := readIdentity(*key)
	if err != nil {
		return err
	}
	before, err := migration.InspectSnapshot(ctx, *source, cfg, recoveryLimits())
	if err != nil {
		return err
	}
	// Keep a private intermediate beside the target. The final path is created
	// only by RevokeSnapshotAuthorization and never inherits an activation proof.
	if err := privateParent(*destination); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(*destination), ".relocate-")
	if err != nil {
		return errors.New("could not create private relocation workspace")
	}
	defer os.RemoveAll(stage)
	intermediate := filepath.Join(stage, "relocated.db")
	count, err := migration.RelocateSnapshot(ctx, *source, intermediate, cfg.Runtime.ArchiveDir, *archives, *target, identity)
	if err != nil {
		return err
	}
	unchanged, err := migration.InspectSnapshot(ctx, *source, cfg, recoveryLimits())
	if err != nil || before.DatabaseSHA256 != unchanged.DatabaseSHA256 || count != len(before.Archives) {
		return errors.New("source changed during archive validation")
	}
	revoke := migration.RevokeSnapshotAuthorization
	if *preserveHistory {
		revoke = migration.RevokeSnapshotOperationalAuthorization
	}
	if err := revoke(ctx, intermediate, *destination, time.Now().UTC()); err != nil {
		return err
	}
	digest, size, err := fileDigest(*destination)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		Scope                  string `json:"scope"`
		SourceSHA256           string `json:"source_database_sha256"`
		SHA256                 string `json:"database_sha256"`
		Bytes                  int64  `json:"database_bytes"`
		Archives               int    `json:"verified_archives"`
		References             int64  `json:"archive_references"`
		AuthorizationRevoked   bool   `json:"inherited_authorization_revoked"`
		PolicyHistoryPreserved bool   `json:"policy_history_preserved"`
	}{"offline archive verification and database relocation; no ownership or Redis validation", before.DatabaseSHA256, digest, size, count, before.ArchiveReferences, true, *preserveHistory})
}

func loopbackAddress(value string) bool {
	host, port, err := net.SplitHostPort(value)
	n, portErr := strconv.Atoi(port)
	ip := net.ParseIP(host)
	return err == nil && portErr == nil && n > 0 && n <= 65535 && ip != nil && ip.IsLoopback()
}

func runRedisCompare(ctx context.Context, args []string, out io.Writer) error {
	f := commandFlags("compare-redis")
	a := f.String("a", "", "first explicit numeric loopback endpoint")
	b := f.String("b", "", "second explicit numeric loopback endpoint")
	verified := f.Bool("verified-no-additional-state", false, "operator verified isolated RDBs contain no auxiliary state")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || !loopbackAddress(*a) || !loopbackAddress(*b) || *a == *b || !*verified {
		return errors.New("compare-redis requires distinct --a and --b numeric loopback endpoints and --verified-no-additional-state; both servers must be isolated from writers")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	dialer := net.Dialer{Timeout: 5 * time.Second}
	left, err := dialer.DialContext(ctx, "tcp", *a)
	if err != nil {
		return errors.New("first isolated Redis endpoint unavailable")
	}
	defer left.Close()
	right, err := dialer.DialContext(ctx, "tcp", *b)
	if err != nil {
		return errors.New("second isolated Redis endpoint unavailable")
	}
	defer right.Close()
	opts := redismodel.RESPOptions{MaxReplyBytes: 16 << 20, MaxItems: 100_000, CommandTimeout: 10 * time.Second, VerifiedNoAdditionalState: true}
	x, err := redismodel.NewRESPReader(left, opts)
	if err != nil {
		return err
	}
	y, err := redismodel.NewRESPReader(right, opts)
	if err != nil {
		return err
	}
	// A complete hash/zset reply can contain two elements per allowed key or
	// field plus RESP framing. Keep this bound within the reader's 100k item
	// ceiling (2*40k+8), rather than configuring a limit the reader must reject.
	result, err := redismodel.Compare(ctx, x, y, redismodel.Limits{MaxDatabases: 16, MaxKeys: 40_000, MaxPages: 100_000,
		MaxReplyBytes: 16 << 20, MaxTotalBytes: 256 << 20, MaxClockSkewMillis: 1000, MaxDuration: 90 * time.Second})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		Scope      string `json:"scope"`
		Equivalent bool   `json:"equivalent"`
		Databases  int    `json:"databases"`
		Keys       uint64 `json:"keys"`
		Started    int64  `json:"started_millis"`
		Finished   int64  `json:"finished_millis"`
	}{"bounded read-only comparison; writer isolation and RDB auxiliary-state inspection are operator preconditions", true, result.Databases, result.Keys, result.StartedMillis, result.FinishedMillis})
}

func runSeal(ctx context.Context, args []string, out io.Writer) error {
	f := commandFlags("seal-directory")
	source := f.String("source", "", "private complete recovery directory")
	destination := f.String("destination", "", "new encrypted bundle")
	f.StringVar(destination, "output", "", "alias for --destination")
	recipientFile := f.String("recipient-file", "", "age recipient file, contains public identity only")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || *source == "" || *destination == "" || *recipientFile == "" {
		return errors.New("seal-directory requires --source PRIVATE_DIRECTORY --destination NEW_AGE_FILE --recipient-file FILE")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := readPrivateSmallFile(*recipientFile)
	if err != nil {
		return err
	}
	recipient, err := age.ParseX25519Recipient(strings.TrimSpace(string(data)))
	if err != nil {
		return errors.New("backup recipient is invalid")
	}
	if err := recoverybundle.Seal(*source, *destination, recipient); err != nil {
		return err
	}
	digest, size, err := fileDigest(*destination)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		Scope  string `json:"scope"`
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	}{"encrypted directory; component coherence and independent recovery are caller responsibilities", digest, size})
}

func runOpen(ctx context.Context, args []string, out io.Writer) error {
	f := commandFlags("open-bundle")
	source := f.String("source", "", "encrypted bundle")
	destination := f.String("destination", "", "new private recovery directory")
	f.StringVar(destination, "output", "", "alias for --destination")
	key := f.String("identity-file", "", "private backup identity")
	expected := f.String("sha256", "", "expected encrypted bundle digest from separately retained receipt")
	maxMiB := f.Int64("max-mib", 1024, "maximum unpacked bytes, 1 through 16384 MiB")
	reserveMiB := f.Int64("reserve-mib", 2048, "minimum free space after extraction, at least 2048 MiB")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || *source == "" || *destination == "" || *key == "" || *maxMiB < 1 || *maxMiB > 16384 || *reserveMiB < 2048 || *reserveMiB > 1048576 {
		return errors.New("open-bundle requires --source BUNDLE --destination NEW_DIRECTORY --identity-file PRIVATE_KEY --sha256 RECEIPT_DIGEST [--max-mib 1024 --reserve-mib 2048]")
	}
	decoded, err := hex.DecodeString(*expected)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != *expected {
		return errors.New("expected bundle digest is invalid")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	identity, err := readIdentity(*key)
	if err != nil {
		return err
	}
	if err := recoverybundle.Open(*source, *destination, identity, *expected, recoverybundle.Limits{MaxBytes: *maxMiB << 20, MaxFiles: 100_000, ReserveBytes: uint64(*reserveMiB) << 20}); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		Scope    string `json:"scope"`
		SHA256   string `json:"bundle_sha256"`
		Restored bool   `json:"extracted_and_verified"`
	}{"authenticated encrypted extraction; database, archives and model still require their own validation", *expected, true})
}

func runKeygen(ctx context.Context, args []string, out io.Writer) error {
	f := commandFlags("keygen")
	identityFile := f.String("identity-file", "", "new private backup identity file")
	recipientFile := f.String("recipient-file", "", "new private public-recipient file")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || *identityFile == "" || *recipientFile == "" || *identityFile == *recipientFile {
		return errors.New("keygen requires distinct --identity-file NEW_PRIVATE_FILE --recipient-file NEW_FILE")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return errors.New("backup identity generation failed")
	}
	secret, err := createPrivateOutput(*identityFile)
	if err != nil {
		return err
	}
	defer secret.Close()
	// Once created, retain this private identity even if the recipient write
	// fails. This makes interrupted setup visible and avoids replacing a key.
	if _, err := io.WriteString(secret, identity.String()+"\n"); err != nil {
		return errors.New("backup identity write failed")
	}
	if err := finishPrivateOutput(secret, *identityFile); err != nil {
		return err
	}
	public, err := createPrivateOutput(*recipientFile)
	if err != nil {
		return err
	}
	defer public.Close()
	if _, err := io.WriteString(public, identity.Recipient().String()+"\n"); err != nil {
		return errors.New("backup recipient write failed")
	}
	if err := finishPrivateOutput(public, *recipientFile); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		Generated bool   `json:"generated"`
		Scope     string `json:"scope"`
	}{true, "distinct backup encryption identity; retain independently from the protected host"})
}

func readIdentity(path string) (*age.X25519Identity, error) {
	data, err := readPrivateSmallFile(path)
	if err != nil {
		return nil, err
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, errors.New("private identity file is invalid")
	}
	return identity, nil
}

func readPrivateSmallFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("explicit private key or recipient file unavailable")
	}
	f := os.NewFile(uintptr(fd), "private recovery material")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() <= 0 || info.Size() > 4096 {
		return nil, errors.New("recovery material must be a private bounded regular file")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || st.Nlink != 1 {
		return nil, errors.New("recovery material must be owned by the caller and have one link")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return nil, errors.New("recovery material exceeds its read limit")
	}
	return data, nil
}

func privateParent(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("output path must be clean and absolute")
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("output parent must be a private real directory")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return errors.New("output parent must be owned by the caller")
	}
	return nil
}

func createPrivateOutput(path string) (*os.File, error) {
	if err := privateParent(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, errors.New("output must be a new private file")
	}
	return f, nil
}

func finishPrivateOutput(file *os.File, path string) error {
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return errors.New("output could not be durably written")
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func fileDigest(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, errors.New("completed output could not be read")
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, errors.New("completed output could not be hashed")
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
