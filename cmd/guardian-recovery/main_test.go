package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/store"
)

func recoveryFixture(t *testing.T, status string) (string, string, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.NewInstance()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Account.Email, cfg.Folders.ServerSpam = "fixture@example.invalid", "Spam"
	cfg.Runtime.DataDir = root
	cfg.Runtime.Database = filepath.Join(root, "source.db")
	cfg.Runtime.ArchiveDir = filepath.Join(root, "archive")
	configuration := filepath.Join(root, "config.toml")
	if err := config.Save(configuration, cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := db.BindConfiguration(ctx, cfg, time.Now()); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"bayes_spam_revision_highwater": "19", "bayes_ham_revision_highwater": "23"} {
		if err := db.SetSetting(ctx, key, value); err != nil {
			t.Fatal(err)
		}
	}
	run, err := db.BeginRun(ctx, "run", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.FinishRun(ctx, run, nil); err != nil {
		t.Fatal(err)
	}
	message := store.Message{
		Account: cfg.Account.Email, SourceFolder: "Spam", CurrentFolder: "AI-Do-sprawdzenia",
		UID: 1, UIDValidity: 7, RawSHA256: strings.Repeat("a", 64), SizeBytes: 32,
		Verdict: "uncertain", Action: "review", Status: status,
		FirstSeen: time.Now(), LastScanned: time.Now(),
		ArchivePath: filepath.Join(cfg.Runtime.ArchiveDir, "fixture.age"),
	}
	if _, err := db.UpsertMessage(ctx, &message); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return configuration, cfg.Runtime.Database, filepath.Join(root, "snapshot.db")
}

func TestSnapshotCheckUsesRealSchemaAndBindsInspectedDigest(t *testing.T) {
	configuration, source, snapshot := recoveryFixture(t, "review")
	var output bytes.Buffer
	err := run(context.Background(), []string{"inspect-snapshot", "--config", configuration, "--source", source, "--database", snapshot}, &output)
	if err != nil {
		t.Fatal(err)
	}
	var report inspection
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if !report.Ready || report.Messages != 1 || report.DistinctArchives != 1 || report.ArchiveReferences != 1 || report.DatabaseSHA256 != hex.EncodeToString(digest[:]) || report.SpamHighWater != 19 || report.HamHighWater != 23 {
		t.Fatalf("unexpected inspection: %+v", report)
	}
	if strings.Contains(output.String(), "fixture@example.invalid") || strings.Contains(output.String(), "fixture.age") || !strings.Contains(report.Scope, "no archive decryption") {
		t.Fatal("output exposed mailbox inventory or overstated its scope")
	}
	// No-replace behavior matters for preserving a prior recovery generation.
	output.Reset()
	if err := run(context.Background(), []string{"inspect-snapshot", "--config", configuration, "--source", source, "--database", snapshot}, &output); err == nil || output.Len() != 0 {
		t.Fatal("existing candidate was overwritten or reported ready")
	}
}

func TestSnapshotCheckRejectsUnresolvedMoveWithoutSuccessOutput(t *testing.T) {
	configuration, source, snapshot := recoveryFixture(t, "pending_move")
	var output bytes.Buffer
	err := run(context.Background(), []string{"inspect-snapshot", "--config", configuration, "--source", source, "--database", snapshot}, &output)
	if err == nil || output.Len() != 0 {
		t.Fatal("unresolved move accepted or success output emitted")
	}
	if _, err := os.Stat(snapshot); err != nil {
		t.Fatal("completed diagnostic copy should remain available after readiness rejection")
	}
}

func TestSnapshotCheckRequiresExplicitPrivateConfiguration(t *testing.T) {
	configuration, source, _ := recoveryFixture(t, "review")
	for _, mutate := range []string{"symlink", "public", "unknown-field"} {
		t.Run(mutate, func(t *testing.T) {
			data, err := os.ReadFile(configuration)
			if err != nil {
				t.Fatal(err)
			}
			candidate := filepath.Join(filepath.Dir(configuration), mutate+".toml")
			snapshot := filepath.Join(filepath.Dir(configuration), mutate+".db")
			switch mutate {
			case "symlink":
				err = os.Symlink(configuration, candidate)
			case "public":
				err = os.WriteFile(candidate, data, 0644)
				if err == nil {
					err = os.Chmod(candidate, 0644)
				}
			case "unknown-field":
				err = os.WriteFile(candidate, append(data, []byte("\nunknown_setting = true\n")...), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err = run(context.Background(), []string{"inspect-snapshot", "--config", candidate, "--source", source, "--database", snapshot}, &output)
			if err == nil || output.Len() != 0 {
				t.Fatal("unsafe configuration accepted")
			}
			if _, err := os.Stat(snapshot); !os.IsNotExist(err) {
				t.Fatal("configuration rejection created a database candidate")
			}
		})
	}
}

func TestPrepareSnapshotNormalizesOnlyTheNewCopy(t *testing.T) {
	configuration, source, rawSnapshot := recoveryFixture(t, "superseded")
	var output bytes.Buffer
	if err := run(context.Background(), []string{"inspect-snapshot", "--config", configuration, "--source", source, "--database", rawSnapshot}, &output); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", rawSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO reconciliations(message_id,source_cursor,updated_at) VALUES(1,999,?)", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(rawSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	prepared := filepath.Join(filepath.Dir(rawSnapshot), "prepared.db")
	output.Reset()
	if err := run(context.Background(), []string{"prepare-snapshot", "--config", configuration, "--source", rawSnapshot, "--database", prepared}, &output); err != nil {
		t.Fatal(err)
	}
	var report inspection
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(before)
	if !report.Ready || report.RemovedSupersededCursors != 1 || report.SourceDatabaseSHA256 != hex.EncodeToString(digest[:]) || report.DatabaseSHA256 == report.SourceDatabaseSHA256 || report.Messages != 1 {
		t.Fatalf("preparation did not bind its exact transformation: %+v", report)
	}
	after, err := os.ReadFile(rawSnapshot)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("preparation changed its raw input")
	}
	output.Reset()
	if err := run(context.Background(), []string{"inspect-snapshot", "--config", configuration, "--database", rawSnapshot}, &output); err == nil || output.Len() != 0 {
		t.Fatal("strict inspection accepted the untouched raw cursor")
	}
}
