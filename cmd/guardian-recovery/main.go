// Command guardian-recovery provides explicitly selected recovery operations.
// It never accesses IMAP or Keychain and never starts a mail worker. The
// export-redis command reads Redis; every other command is offline except the
// read-only compare-redis operation against explicit private endpoints.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/migration"
	"golang.org/x/sys/unix"
)

const maxConfigBytes = 64 << 10

type inspection struct {
	Version                  int    `json:"version"`
	Scope                    string `json:"scope"`
	Ready                    bool   `json:"database_ready"`
	ObservedUTC              string `json:"observed_utc"`
	DatabaseBytes            int64  `json:"database_bytes"`
	DatabaseSHA256           string `json:"database_sha256"`
	Rows                     int64  `json:"rows"`
	Messages                 int64  `json:"messages"`
	ArchiveReferences        int64  `json:"archive_references"`
	DistinctArchives         int    `json:"distinct_archives"`
	MailboxFingerprint       string `json:"mailbox_fingerprint"`
	AuthorizationFingerprint string `json:"authorization_fingerprint"`
	SpamHighWater            uint64 `json:"spam_revision_highwater"`
	HamHighWater             uint64 `json:"ham_revision_highwater"`
	SourceDatabaseSHA256     string `json:"source_database_sha256,omitempty"`
	RemovedSupersededCursors int64  `json:"removed_superseded_cursors,omitempty"`
	HistoricalRunMismatches  int64  `json:"historical_run_status_mismatches,omitempty"`
	LatestActualRunStatus    string `json:"latest_actual_run_status,omitempty"`
	LatestActualRunErrors    int64  `json:"latest_actual_run_errors"`
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "guardian-recovery:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) != 0 {
		switch args[0] {
		case "export-redis":
			return runRedisExport(ctx, args[1:], out)
		case "map-config":
			return runMapConfig(ctx, args[1:], out)
		case "relocate-snapshot":
			return runRelocate(ctx, args[1:], out)
		case "compare-redis":
			return runRedisCompare(ctx, args[1:], out)
		case "seal-directory", "seal-bundle":
			return runSeal(ctx, args[1:], out)
		case "open-bundle", "restore-bundle":
			return runOpen(ctx, args[1:], out)
		case "keygen":
			return runKeygen(ctx, args[1:], out)
		}
	}
	if len(args) == 0 || (args[0] != "inspect-snapshot" && args[0] != "prepare-snapshot") {
		return errors.New("usage: guardian-recovery inspect-snapshot|prepare-snapshot|export-redis|map-config|relocate-snapshot|compare-redis|seal-bundle|restore-bundle|keygen; all paths and recovery material must be supplied explicitly")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configuration := flags.String("config", "", "explicit existing configuration; read only")
	database := flags.String("database", "", "private standalone snapshot to inspect")
	source := flags.String("source", "", "optional existing database to copy into a new snapshot first")
	maximum := flags.Int64("max-database-mib", 64, "maximum main SQLite image, 1 to 256 MiB")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return errors.New("invalid inspect-snapshot arguments")
	}
	if *configuration == "" || *database == "" || *maximum < 1 || *maximum > 256 {
		return errors.New("explicit config/database and a database limit from 1 to 256 MiB are required")
	}
	if args[0] == "prepare-snapshot" && *source == "" {
		return errors.New("prepare-snapshot requires an explicit private standalone --source and a new --database")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cfg, err := readConfiguration(*configuration)
	if err != nil {
		return err
	}
	maxBytes := *maximum << 20
	limits := migration.ReadinessLimits{
		MaxDatabaseBytes: maxBytes, MaxRows: 1_000_000,
		MaxArchiveReferences: 100_000, MaxArchives: 50_000,
		MaxInventoryBytes: 16 << 20, MaxPathBytes: 4096,
	}
	var preparation migration.SnapshotPreparation
	if args[0] == "prepare-snapshot" {
		preparation, err = migration.PrepareSnapshot(ctx, *source, *database, cfg, limits)
		if err != nil {
			return fmt.Errorf("prepare isolated database copy: %w", err)
		}
	} else if *source != "" {
		// This is only an online database view. No cross-component owner fence,
		// archive/model capture, or backup freshness proof is established here.
		if err := migration.SnapshotDatabaseBounded(ctx, *source, *database, maxBytes); err != nil {
			return fmt.Errorf("create database-only snapshot: %w", err)
		}
	}
	inventory, err := migration.InspectSnapshot(ctx, *database, cfg, limits)
	if err != nil {
		return fmt.Errorf("database readiness rejected: %w", err)
	}
	if args[0] == "prepare-snapshot" && inventory.DatabaseSHA256 != preparation.PreparedSHA256 {
		return errors.New("prepared database changed before its final inspection")
	}
	result := inspection{
		Version: 1, Scope: "database-only inspection; no archive decryption, model validation, ownership fence, coherent capture or mailbox authorization",
		Ready: true, ObservedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		DatabaseBytes: inventory.DatabaseBytes, DatabaseSHA256: inventory.DatabaseSHA256,
		Rows: inventory.TotalRows, Messages: inventory.Messages,
		ArchiveReferences: inventory.ArchiveReferences, DistinctArchives: len(inventory.Archives),
		MailboxFingerprint: inventory.MailboxFingerprint, AuthorizationFingerprint: inventory.AuthorizationFingerprint,
		SpamHighWater: inventory.SpamRevisionHighWater, HamHighWater: inventory.HamRevisionHighWater,
		SourceDatabaseSHA256: preparation.SourceSHA256, RemovedSupersededCursors: preparation.RemovedSupersededProgress,
		HistoricalRunMismatches: inventory.HistoricalRunStatusMismatches,
		LatestActualRunStatus:   inventory.LatestActualRunStatus, LatestActualRunErrors: inventory.LatestActualRunErrors,
	}
	return json.NewEncoder(out).Encode(result)
}

func readConfiguration(path string) (config.Config, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return config.Config{}, errors.New("explicit private configuration is unavailable")
	}
	f := os.NewFile(uintptr(fd), "configuration")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() <= 0 || info.Size() > maxConfigBytes {
		return config.Config{}, errors.New("configuration must be a private bounded regular file")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || st.Nlink != 1 {
		return config.Config{}, errors.New("configuration must be owned by the caller and have one link")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil || len(data) > maxConfigBytes {
		return config.Config{}, errors.New("configuration could not be read within its limit")
	}
	cfg := config.Default()
	metadata, err := toml.Decode(string(data), &cfg)
	if err != nil || len(metadata.Undecoded()) != 0 {
		return config.Config{}, errors.New("configuration is malformed")
	}
	cfg, err = cfg.Resolve()
	if err != nil {
		return config.Config{}, errors.New("configuration is invalid")
	}
	return cfg, nil
}
