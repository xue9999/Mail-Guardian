package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/apperror"
	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/engine"
	"github.com/xue9999/Mail-Guardian/internal/keychain"
	"github.com/xue9999/Mail-Guardian/internal/rspamd"
	"github.com/xue9999/Mail-Guardian/internal/store"
)

type memorySecrets struct {
	values    map[string]string
	setErr    error
	deleteErr error
}

func (m *memorySecrets) key(service, account string) string { return service + "\x00" + account }
func (m *memorySecrets) Get(service, account string) (string, error) {
	value, ok := m.values[m.key(service, account)]
	if !ok {
		return "", keychain.ErrNotFound
	}
	return value, nil
}
func (m *memorySecrets) Set(service, account, value, _ string) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.values[m.key(service, account)] = value
	return nil
}
func (m *memorySecrets) Delete(service, account string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.values, m.key(service, account))
	return nil
}

func TestSetupSecretRollbackRestoresOldOrRemovesNewValue(t *testing.T) {
	for _, tc := range []struct {
		name, previous string
	}{
		{name: "restore previous", previous: "old-secret"},
		{name: "remove newly created"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &memorySecrets{values: map[string]string{}}
			if tc.previous != "" {
				_ = store.Set("service", "account", tc.previous, "")
			}
			rollback, err := replaceSecret(store, "service", "account", "new-secret", "label")
			if err != nil {
				t.Fatal(err)
			}
			if err := rollback(); err != nil {
				t.Fatal(err)
			}
			got, err := store.Get("service", "account")
			if tc.previous == "" {
				if !errors.Is(err, keychain.ErrNotFound) {
					t.Fatalf("new secret remained after rollback: %q err=%v", got, err)
				}
			} else if err != nil || got != tc.previous {
				t.Fatalf("previous secret was not restored: %q err=%v", got, err)
			}
		})
	}
}

func TestSetupSecretRollbackReportsKeychainFailure(t *testing.T) {
	deleteFailure := errors.New("delete failed")
	store := &memorySecrets{values: map[string]string{}, deleteErr: deleteFailure}
	rollback, err := replaceSecret(store, "service", "account", "new-secret", "label")
	if err != nil {
		t.Fatal(err)
	}
	if err := rollback(); !errors.Is(err, deleteFailure) {
		t.Fatalf("rollback failure was hidden: %v", err)
	}
}

func TestSetupAlwaysReturnsToProtection(t *testing.T) {
	cfg := config.Default()
	cfg.Safety.Mode = "active"
	cfg.Safety.PurgeEnabled = true
	enforceSetupProtection(&cfg)
	if cfg.Safety.Mode != "protect" || cfg.Safety.PurgeEnabled {
		t.Fatalf("unsafe setup state: %#v", cfg.Safety)
	}
}

func TestMissingArchiveKeyCannotBeSilentlyReplacedOverExistingData(t *testing.T) {
	for _, tc := range []struct {
		name      string
		prepare   func(t *testing.T, archiveDir, database string)
		wantError bool
	}{
		{name: "empty fresh installation"},
		{
			name: "encrypted copy exists", wantError: true,
			prepare: func(t *testing.T, archiveDir, _ string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Join(archiveDir, "2026", "08"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(archiveDir, "2026", "08", "copy.eml.age"), []byte("encrypted"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "state database exists", wantError: true,
			prepare: func(t *testing.T, _ string, database string) {
				t.Helper()
				if err := os.WriteFile(database, []byte("sqlite-state"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			archiveDir := filepath.Join(dir, "archive")
			database := filepath.Join(dir, "guardian.db")
			if tc.prepare != nil {
				tc.prepare(t, archiveDir, database)
			}
			err := validateNewArchiveIdentity(archiveDir, database)
			if tc.wantError && err == nil {
				t.Fatal("existing Guardian data allowed creation of a replacement archive key")
			}
			if !tc.wantError && err != nil {
				t.Fatalf("fresh installation was rejected: %v", err)
			}
			if tc.wantError && apperror.From(err).Code != apperror.ArchiveKey {
				t.Fatalf("error code = %q, want %q", apperror.From(err).Code, apperror.ArchiveKey)
			}
		})
	}
}

func TestArchiveIdentityRollbackPreservesAKeyOnceDependentStateExists(t *testing.T) {
	for _, tc := range []struct {
		name        string
		createState bool
		wantKey     bool
	}{
		{name: "unused new key is removed", wantKey: false},
		{name: "key matching new database is preserved", createState: true, wantKey: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			database := filepath.Join(dir, "guardian.db")
			if tc.createState {
				if err := os.WriteFile(database, []byte("sqlite-state"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			secrets := &memorySecrets{values: map[string]string{}}
			if err := secrets.Set("archive", "account", "new-key", ""); err != nil {
				t.Fatal(err)
			}
			if err := rollbackNewArchiveIdentity(secrets, "archive", "account", filepath.Join(dir, "archive"), database); err != nil {
				t.Fatal(err)
			}
			_, err := secrets.Get("archive", "account")
			keyExists := err == nil
			if keyExists != tc.wantKey {
				t.Fatalf("key exists = %v, want %v", keyExists, tc.wantKey)
			}
		})
	}
}

func TestAPIUnconfiguredSnapshotUsesVersionedEnvelope(t *testing.T) {
	var output bytes.Buffer
	a := &application{
		configPath: filepath.Join(t.TempDir(), "missing.toml"),
		in:         bufio.NewReader(strings.NewReader("")), out: &output, errOut: io.Discard,
	}
	if err := a.apiCommand([]string{"snapshot"}); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Protocol int `json:"protocol"`
		OK       bool
		Data     apiSnapshot `json:"data"`
	}
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Protocol != 1 || !envelope.OK || envelope.Data.Configured {
		t.Fatalf("unexpected envelope: %#v", envelope)
	}
}

func TestAPIRequestRejectsUnknownFieldsAndOversize(t *testing.T) {
	if _, err := readSetupRequest(strings.NewReader(`{"email":"a@o2.pl","password":"secret","unexpected":true}`)); err == nil {
		t.Fatal("unknown API field was accepted")
	}
	if _, err := readSetupRequest(strings.NewReader(strings.Repeat("x", (64<<10)+1))); err == nil {
		t.Fatal("oversized API request was accepted")
	}
}

func TestSetupRequestAcceptsShippedGUIAndSnakeCase(t *testing.T) {
	for _, input := range []string{
		`{"email":"a@o2.pl","password":"synthetic","spamFolder":"Spam","acceptExistingTraining":true}`,
		`{"email":"a@o2.pl","password":"synthetic","spam_folder":"Spam","accept_existing_training":true}`,
	} {
		request, err := readSetupRequest(strings.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		if request.SpamFolder != "Spam" || !request.AcceptExistingTraining {
			t.Fatalf("request not normalized: %#v", request)
		}
	}
	if _, err := readSetupRequest(strings.NewReader(
		`{"email":"a@o2.pl","password":"synthetic","spam_folder":"Spam","spamFolder":"INBOX"}`,
	)); err == nil {
		t.Fatal("conflicting folder values were accepted")
	}
}

func TestDiagnosticFailureRedactsUnknownInternalText(t *testing.T) {
	failure := redactedDiagnosticFailure(errors.New(
		"konto test@o2.pl temat Prywatny raw_sha256=deadbeef sekret=abc",
	))
	encoded, err := json.Marshal(failure)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, forbidden := range []string{"test@o2.pl", "Prywatny", "deadbeef", "abc"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("diagnostic failure leaked %q: %s", forbidden, text)
		}
	}
	if failure.Code != string(apperror.Unknown) || failure.Recovery == "" {
		t.Fatalf("unexpected redacted failure: %#v", failure)
	}
}

func TestDiagnosticsCanBeExportedWhenConfigurationIsBroken(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	configPath := filepath.Join(home, "broken-config.toml")
	privateMarker := "test@o2.pl PrywatnyTemat deadbeef"
	if err := os.WriteFile(configPath, []byte("broken = [\""+privateMarker+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &application{configPath: configPath, out: io.Discard, errOut: io.Discard}
	result, err := a.exportDiagnostics()
	if err != nil {
		t.Fatalf("diagnostics should survive a broken configuration: %v", err)
	}
	path, ok := result.(map[string]any)["path"].(string)
	if !ok || path == "" {
		t.Fatalf("missing diagnostic path: %#v", result)
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if len(reader.File) != 1 || reader.File[0].Name != "report.json" {
		t.Fatalf("unexpected diagnostic archive: %#v", reader.File)
	}
	entry, err := reader.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(entry)
	_ = entry.Close()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), privateMarker) || strings.Contains(string(body), "test@o2.pl") {
		t.Fatalf("diagnostic archive leaked private input: %s", body)
	}
	if !bytes.Contains(body, []byte(`"snapshot_available":false`)) ||
		!bytes.Contains(body, []byte(`"code":"CONFIG_INVALID"`)) {
		t.Fatalf("diagnostic archive does not explain unavailable snapshot: %s", body)
	}
}

func TestSetupPasswordIsNeverEchoedInAPIResponse(t *testing.T) {
	const secret = "VERY-PRIVATE-APPLICATION-PASSWORD"
	var output bytes.Buffer
	a := &application{
		configPath: filepath.Join(t.TempDir(), "config.toml"),
		in:         bufio.NewReader(strings.NewReader(`{"email":"","password":"` + secret + `"}`)),
		out:        &output, errOut: io.Discard,
	}
	if err := a.apiCommand([]string{"setup", "probe"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatal("setup password leaked into API JSON")
	}
	var envelope apiEnvelope
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil || envelope.OK || envelope.Error == nil {
		t.Fatalf("expected a structured validation error: envelope=%#v err=%v", envelope, err)
	}
}

func TestAutomationCannotBeEnabledBeforeSuccessfulDryRun(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
	cfg.Runtime.DataDir = dir
	cfg.Runtime.Database = filepath.Join(dir, "guardian.db")
	cfg.Runtime.ArchiveDir = filepath.Join(dir, "archive")
	cfg.Runtime.LogFile = filepath.Join(dir, "guardian.log")
	path := filepath.Join(dir, "config.toml")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	a := &application{configPath: path}
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(context.Background(), "first_dry_run_completed_at", "old-proof"); err != nil {
		t.Fatal(err)
	}
	if err := db.RequireFreshDryRun(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.apiService([]string{"enable"}); err == nil || !strings.Contains(err.Error(), "dry-run") {
		t.Fatalf("automation gate did not block enable: %v", err)
	}
}

func TestGUIActiveModeConfirmationReachesTheCLITransition(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
	cfg.Runtime.DataDir = dir
	cfg.Runtime.Database = filepath.Join(dir, "guardian.db")
	cfg.Runtime.ArchiveDir = filepath.Join(dir, "archive")
	cfg.Runtime.LogFile = filepath.Join(dir, "guardian.log")
	path := filepath.Join(dir, "config.toml")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		t.Fatal(err)
	}
	installedAt := time.Now().UTC().Add(-15 * 24 * time.Hour).Truncate(time.Second)
	if err := db.SetSetting(ctx, "installed_at", installedAt.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	seedReadyActivationQuality(t, db, cfg.Account.Email, installedAt)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	a := &application{
		configPath: path,
		in:         bufio.NewReader(strings.NewReader(`{"value":"active","confirm":"AKTYWNY"}`)),
		out:        io.Discard,
		errOut:     io.Discard,
	}
	if _, err := a.apiMode(); err != nil {
		t.Fatalf("GUI confirmation did not activate the mode: %v", err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Safety.Mode != "active" || loaded.Safety.PurgeEnabled {
		t.Fatalf("mode after GUI transition = %q, purge=%v", loaded.Safety.Mode, loaded.Safety.PurgeEnabled)
	}
}

func TestSnapshotDoesNotRestoreExplicitlyInvalidatedDryRun(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
	cfg.Runtime.DataDir = dir
	cfg.Runtime.Database = filepath.Join(dir, "guardian.db")
	cfg.Runtime.ArchiveDir = filepath.Join(dir, "archive")
	cfg.Runtime.LogFile = filepath.Join(dir, "guardian.log")
	path := filepath.Join(dir, "config.toml")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		t.Fatal(err)
	}
	run, err := db.BeginRun(context.Background(), "run", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.FinishRun(context.Background(), run, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.RequireFreshDryRun(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	a := &application{configPath: path}
	snapshot, err := a.buildAPISnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.FirstDryRun {
		t.Fatal("an older successful run restored an explicitly invalidated dry-run")
	}
}

func TestSnapshotMigratesLegacySuccessfulInstallation(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Account.Email = "legacy@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
	cfg.Runtime.DataDir = dir
	cfg.Runtime.Database = filepath.Join(dir, "guardian.db")
	cfg.Runtime.ArchiveDir = filepath.Join(dir, "archive")
	cfg.Runtime.LogFile = filepath.Join(dir, "guardian.log")
	path := filepath.Join(dir, "config.toml")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		t.Fatal(err)
	}
	run, err := db.BeginRun(context.Background(), "legacy-run", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.FinishRun(context.Background(), run, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	a := &application{configPath: path}
	snapshot, err := a.buildAPISnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.FirstDryRun {
		t.Fatal("legacy successful installation lost backward compatibility")
	}
	db, err = store.Open(cfg.Runtime.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	proof, exists, err := db.GetSettingWithPresence(context.Background(), "first_dry_run_completed_at")
	if err != nil || !exists || proof == "" {
		t.Fatalf("legacy proof was not migrated: proof=%q exists=%v err=%v", proof, exists, err)
	}
}

func TestBayesHighWaterDoesNotConfuseRawCorrectionsWithStatisticalLearns(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "guardian.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for i, hash := range []string{"delivery-a", "delivery-b"} {
		_, err := db.UpsertMessage(ctx, &store.Message{Account: "test@o2.pl", SourceFolder: "AI-Naucz-spam", CurrentFolder: "AI-Kwarantanna", UIDValidity: 1, UID: uint32(i + 1), RawSHA256: hash, MessageIDHash: hash, Feedback: "spam", Action: "learn_spam", Status: "quarantined", FirstSeen: time.Now(), LastScanned: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
	}
	for key, value := range map[string]string{"bayes_spam_revision_highwater": "1", "bayes_ham_revision_highwater": "0"} {
		if err := db.SetSetting(ctx, key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := compareBayesHighWater(ctx, db, "test@o2.pl", rspamd.BayesStats{SpamRevision: 1}); err != nil {
		t.Fatalf("content deduplication was treated as rollback: %v", err)
	}
	if err := compareBayesHighWater(ctx, db, "test@o2.pl", rspamd.BayesStats{}); err == nil {
		t.Fatal("real model reset was accepted")
	}
}

func TestBayesRollbackPreservesHighWaterAndDisablesUnsafeModes(t *testing.T) {
	passwordSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passwordSeen = r.Header.Get("Password") == "controller-secret"
		_, _ = io.WriteString(w, `{"statfiles":[{"revision":0,"symbol":"BAYES_SPAM"},{"revision":0,"symbol":"BAYES_HAM"}]}`)
	}))
	defer server.Close()

	dir := t.TempDir()
	cfg := config.Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
	cfg.Safety.Mode = "active"
	cfg.Safety.PurgeEnabled = true
	cfg.Runtime.DataDir = dir
	cfg.Runtime.Database = filepath.Join(dir, "guardian.db")
	cfg.Runtime.ArchiveDir = filepath.Join(dir, "archive")
	cfg.Runtime.LogFile = filepath.Join(dir, "guardian.log")
	configPath := filepath.Join(dir, "config.toml")
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for key, value := range map[string]string{
		"bayes_spam_revision_highwater": "100",
		"bayes_ham_revision_highwater":  "90",
		"active_since":                  time.Now().Add(-31 * 24 * time.Hour).Format(time.RFC3339Nano),
	} {
		if err := db.SetSetting(context.Background(), key, value); err != nil {
			t.Fatal(err)
		}
	}
	scanner := rspamd.New(server.URL+"/checkv2", server.URL, "controller-secret", time.Second)
	rt := &runtimeApp{cfg: cfg, db: db, scanner: scanner, engine: &engine.Engine{Config: cfg}}
	a := &application{configPath: configPath}
	rolledBack, err := a.ensureBayesContinuity(context.Background(), rt)
	if err != nil || !rolledBack {
		t.Fatalf("rollback was not detected: rolledBack=%v err=%v", rolledBack, err)
	}
	if !passwordSeen {
		t.Fatal("Rspamd /stat was not authenticated")
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Safety.Mode != "protect" || loaded.Safety.PurgeEnabled {
		t.Fatalf("unsafe modes remained enabled: %#v", loaded.Safety)
	}
	spamHigh, _ := db.GetSetting(context.Background(), "bayes_spam_revision_highwater")
	hamHigh, _ := db.GetSetting(context.Background(), "bayes_ham_revision_highwater")
	activeSince, _ := db.GetSetting(context.Background(), "active_since")
	if spamHigh != "100" || hamHigh != "90" || activeSince != "" {
		t.Fatalf("high-water or observation reset is wrong: spam=%q ham=%q active=%q", spamHigh, hamHigh, activeSince)
	}
}

func TestArchiveDateRangeValidation(t *testing.T) {
	for _, pair := range [][2]string{{"bad", "2026-09-02T00:00:00Z"}, {"2026-09-01T00:00:00Z", "bad"}, {"2026-09-02T00:00:00Z", "2026-09-01T00:00:00Z"}, {"2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"}} {
		if _, _, err := archiveDateRange(pair[0], pair[1]); err == nil {
			t.Fatalf("accepted invalid range: %v", pair)
		}
	}
	start, end, err := archiveDateRange("2026-10-25T00:00:00+02:00", "2026-10-26T00:00:00+01:00")
	if err != nil || end.Sub(start) != 25*time.Hour {
		t.Fatalf("timezone boundary lost: %v %v %v", start, end, err)
	}
}

func TestSuccessfulDiagnosticsExcludeLocalConnectionAndFolderMetadata(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg, err := config.NewInstance()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Account.Email, cfg.Account.Host, cfg.Account.Username = "private@example.org", "imap.private.example", "private-login"
	cfg.Folders.ServerSpam, cfg.Folders.Review = "Junk", "private-review-folder"
	cfg.Runtime.DataDir, cfg.Runtime.Database = home, filepath.Join(home, "guardian.db")
	cfg.Runtime.ArchiveDir, cfg.Runtime.LogFile = filepath.Join(home, "archive"), filepath.Join(home, "guardian.log")
	path := filepath.Join(home, "config.toml")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	a := &application{configPath: path, out: io.Discard, errOut: io.Discard}
	snapshot, err := a.buildAPISnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Connection == nil || snapshot.MailboxFolders == nil || snapshot.Connection.Username != "private-login" {
		t.Fatal("UI snapshot omitted the metadata this regression must exercise")
	}
	result, err := a.exportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.OpenReader(result.(map[string]any)["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	entry, err := reader.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Close()
	body, err := io.ReadAll(entry)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"snapshot_available":true`)) {
		t.Fatalf("successful snapshot was not exported: %s", body)
	}
	for _, private := range []string{"private@example.org", "imap.private.example", "private-login", "private-review-folder", `"connection"`, `"mailbox_folders"`} {
		if bytes.Contains(body, []byte(private)) {
			t.Fatalf("diagnostics leaked %q", private)
		}
	}
}
