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

	"filippo.io/age"
	"github.com/xue9999/Mail-Guardian/internal/config"
)

func commandPrivateRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestRecoveryKeygenAndEncryptedRoundtrip(t *testing.T) {
	root := commandPrivateRoot(t)
	secret, recipient := filepath.Join(root, "backup-identity"), filepath.Join(root, "recipient")
	var out bytes.Buffer
	if err := run(context.Background(), []string{"keygen", "--identity-file", secret, "--recipient-file", recipient}, &out); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(key, []byte("AGE-SECRET-KEY-")) || bytes.Contains(out.Bytes(), bytes.TrimSpace(key)) {
		t.Fatal("key generation leaked or failed")
	}
	for _, path := range []string{secret, recipient} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("recovery material is not private")
		}
	}
	out.Reset()
	if err := run(context.Background(), []string{"keygen", "--identity-file", secret, "--recipient-file", recipient}, &out); err == nil || out.Len() != 0 {
		t.Fatal("replaced existing recovery key")
	}
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	plain := []byte("synthetic private recovery material\x00\xff")
	if err := os.WriteFile(filepath.Join(stage, "data"), plain, 0600); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "bundle.age")
	out.Reset()
	if err := run(context.Background(), []string{"seal-bundle", "--source", stage, "--output", bundle, "--recipient-file", recipient}, &out); err != nil {
		t.Fatal(err)
	}
	var report struct {
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	cipher, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(cipher)
	if report.SHA256 != hex.EncodeToString(digest[:]) || report.Bytes != int64(len(cipher)) || bytes.Contains(cipher, plain) {
		t.Fatal("bundle receipt does not bind encrypted bytes")
	}
	bad := filepath.Join(root, "bad")
	out.Reset()
	if err := run(context.Background(), []string{"restore-bundle", "--source", bundle, "--output", bad, "--identity-file", secret, "--sha256", strings.Repeat("0", 64)}, &out); err == nil || out.Len() != 0 {
		t.Fatal("mismatched receipt accepted")
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("bad restore left consumable directory")
	}
	restored := filepath.Join(root, "restored")
	if err := run(context.Background(), []string{"open-bundle", "--source", bundle, "--destination", restored, "--identity-file", secret, "--sha256", report.SHA256}, &out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(restored, "data"))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("encrypted roundtrip failed")
	}
}

func TestRelocationVerifiesArchiveAndPreservesPolicyOnlyExplicitly(t *testing.T) {
	configuration, source, snapshot := recoveryFixture(t, "review")
	root := filepath.Dir(source)
	cfg, err := readConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cfg.Runtime.ArchiveDir, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(root, "archive-identity")
	if err := os.WriteFile(key, []byte(identity.String()), 0600); err != nil {
		t.Fatal(err)
	}
	plain := []byte("synthetic archived message\r\n")
	digest := sha256.Sum256(plain)
	archivePath := filepath.Join(cfg.Runtime.ArchiveDir, "fixture.age")
	file, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	w, err := age.Encrypt(file, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE messages SET raw_sha256=?,size_bytes=?", hex.EncodeToString(digest[:]), len(plain)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO settings(key,value) VALUES ('active_since','2026-10-01T00:00:00Z'),('protect_since','2026-09-01T00:00:00Z') ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"inspect-snapshot", "--config", configuration, "--source", source, "--database", snapshot}, &out); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	targetRoot := "/var/lib/mail-guardian/pilot/archive"
	args := []string{"relocate-snapshot", "--config", configuration, "--source", snapshot, "--database", filepath.Join(root, "target.db"), "--archive-root", cfg.Runtime.ArchiveDir, "--target-archive-root", targetRoot, "--identity-file", key, "--preserve-policy-history"}
	out.Reset()
	if err := run(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Archives   int  `json:"verified_archives"`
		References int  `json:"archive_references"`
		Preserved  bool `json:"policy_history_preserved"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Archives != 1 || report.References != 1 || !report.Preserved || strings.Contains(out.String(), cfg.Account.Email) || strings.Contains(out.String(), archivePath) {
		t.Fatal("archive verification receipt incorrect or exposed inventory")
	}
	target, err := sql.Open("sqlite", filepath.Join(root, "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var actualPath, active, protect, required, deployment string
	if err := target.QueryRow("SELECT archive_path FROM messages").Scan(&actualPath); err != nil {
		t.Fatal(err)
	}
	if err := target.QueryRow(`SELECT (SELECT value FROM settings WHERE key='active_since'),(SELECT value FROM settings WHERE key='protect_since'),(SELECT value FROM settings WHERE key='configuration_dry_run_required'),(SELECT value FROM settings WHERE key='deployment_identity')`).Scan(&active, &protect, &required, &deployment); err != nil {
		t.Fatal(err)
	}
	if actualPath != filepath.Join(targetRoot, "fixture.age") || active != "2026-10-01T00:00:00Z" || protect != "2026-09-01T00:00:00Z" || required != "1" || deployment != "" {
		t.Fatal("relocation lost policy history or retained inherited operational authorization")
	}
	after, err := os.ReadFile(snapshot)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("relocation changed source")
	}
	if err := os.WriteFile(archivePath, []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	args[6] = filepath.Join(root, "bad.db") // --database value
	out.Reset()
	if err := run(context.Background(), args, &out); err == nil || out.Len() != 0 {
		t.Fatal("corrupted archive was accepted")
	}
	if _, err := os.Stat(filepath.Join(root, "bad.db")); !os.IsNotExist(err) {
		t.Fatal("failed relocation left final database")
	}
}

func TestRecoveryCommandsRejectPublicEndpointsAndUnsafeMaterials(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{
		{"compare-redis", "--a", "192.0.2.1:6379", "--b", "127.0.0.1:6379", "--verified-no-additional-state"},
		{"compare-redis", "--a", "localhost:16379", "--b", "127.0.0.1:6379", "--verified-no-additional-state"},
		{"compare-redis", "--a", "127.0.0.1:16379", "--b", "127.0.0.1:16379", "--verified-no-additional-state"},
		{"compare-redis", "--a", "127.0.0.1:16379", "--b", "127.0.0.1:26379"},
	} {
		if err := run(context.Background(), args, &out); err == nil || out.Len() != 0 {
			t.Fatal("unsafe comparison arguments accepted")
		}
	}
	root := commandPrivateRoot(t)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	publicKey := filepath.Join(root, "public-key")
	if err := os.WriteFile(publicKey, []byte(identity.String()), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(publicKey, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentity(publicKey); err == nil {
		t.Fatal("public-readable identity accepted")
	}
	private := filepath.Join(root, "private-key")
	if err := os.WriteFile(private, []byte(identity.String()), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentity(link); err == nil {
		t.Fatal("symlink identity accepted")
	}
}

func TestRedisExportPreservesExistingOutputBeforeContactingRedis(t *testing.T) {
	configuration, _, _ := recoveryFixture(t, "review")
	output := filepath.Join(filepath.Dir(configuration), "existing.rdb")
	data := []byte("existing model checkpoint")
	if err := os.WriteFile(output, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"export-redis", "--config", configuration, "--output", output}, &out); err == nil || out.Len() != 0 {
		t.Fatal("existing model output accepted")
	}
	got, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("existing model checkpoint changed")
	}
}

func TestRedisExportUsesInstalledStackRuntimeLocation(t *testing.T) {
	cfg := config.Default()
	cfg.Runtime.DataDir = "/private/mailbox-state"
	cfg.Runtime.ComposeFile = "/private/installed-stack/deploy/compose.yaml"
	m := exportManager(cfg, "pilot")
	if m.RuntimeDir != config.DefaultRuntimeDir() || m.RuntimeDir == cfg.Runtime.DataDir || m.ComposeFile != cfg.Runtime.ComposeFile || m.Instance != "pilot" {
		t.Fatal("fresh export does not match installed stack controller configuration")
	}
}

func TestMapConfigPreservesResolvedIdentityAndPolicyWithoutReplacingFiles(t *testing.T) {
	root := commandPrivateRoot(t)
	cfg := config.Default()
	cfg.Account.Email, cfg.Folders.ServerSpam = "fixture@example.invalid", "Spam"
	cfg.Runtime.DataDir = filepath.Join(root, "legacy-state")
	cfg.Safety.Mode, cfg.Safety.PurgeEnabled = "active", true
	source, destination := filepath.Join(root, "source.toml"), filepath.Join(root, "linux.toml")
	if err := config.Save(source, cfg); err != nil {
		t.Fatal(err)
	}
	resolved, err := cfg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	args := []string{"map-config", "--config", source, "--instance", "pilot", "--output", destination}
	if err := run(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	mapped, err := readConfiguration(destination)
	if err != nil {
		t.Fatal(err)
	}
	if mapped.InstanceID != resolved.InstanceID || mapped.MailboxFingerprint() != resolved.MailboxFingerprint() || mapped.AuthorizationFingerprint() != resolved.AuthorizationFingerprint() || mapped.Safety.Mode != "active" || mapped.Safety.PurgeEnabled || mapped.Runtime.Database != "/var/lib/mail-guardian/pilot/guardian.db" || mapped.Runtime.ArchiveDir != "/var/lib/mail-guardian/pilot/archive" {
		t.Fatal("mapping changed identities/policy or used incorrect target paths")
	}
	if strings.Contains(out.String(), cfg.Account.Email) {
		t.Fatal("mapping output exposed account")
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("mapped configuration is not private")
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("mapping changed source")
	}
	produced, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run(context.Background(), args, &out); err == nil || out.Len() != 0 {
		t.Fatal("mapping replaced existing configuration")
	}
	unchanged, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(produced, unchanged) {
		t.Fatal("existing output changed")
	}
}
