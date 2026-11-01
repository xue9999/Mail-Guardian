package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/o2-mail-guardian/guardian/internal/archive"
	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/imapmail"
	"github.com/o2-mail-guardian/guardian/internal/store"
)

func TestChooseMailboxExcludesInboxAndRobotFolders(t *testing.T) {
	var out bytes.Buffer
	app := &application{
		in:     bufio.NewReader(strings.NewReader("2\n")),
		out:    &out,
		errOut: &out,
	}
	boxes := []imapmail.Mailbox{
		{Name: "INBOX"},
		{Name: "ai-kwarantanna"},
		{Name: "AI-Do-sprawdzenia"},
		{Name: "AI-Naucz-spam"},
		{Name: "AI-Naucz-wazne"},
		{Name: "Spam"},
		{Name: "Niechciane"},
	}

	got, err := app.chooseMailbox(
		boxes,
		"INBOX",
		"AI-Kwarantanna",
		"AI-Do-sprawdzenia",
		"AI-Naucz-spam",
		"AI-Naucz-wazne",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got != "Niechciane" {
		t.Fatalf("chooseMailbox() = %q, want Niechciane", got)
	}
	for _, forbidden := range []string{"INBOX", "ai-kwarantanna", "AI-Do-sprawdzenia", "AI-Naucz-spam", "AI-Naucz-wazne"} {
		if strings.Contains(out.String(), forbidden) {
			t.Fatalf("excluded folder %q appeared in chooser:\n%s", forbidden, out.String())
		}
	}
}

func TestChooseMailboxRejectsListWithOnlyProtectedFolders(t *testing.T) {
	var out bytes.Buffer
	app := &application{
		in:     bufio.NewReader(strings.NewReader("")),
		out:    &out,
		errOut: &out,
	}
	boxes := []imapmail.Mailbox{
		{Name: "INBOX"},
		{Name: "AI-Kwarantanna"},
		{Name: "AI-Do-sprawdzenia"},
	}

	_, err := app.chooseMailbox(boxes, "INBOX", "AI-Kwarantanna", "AI-Do-sprawdzenia")
	if err == nil || !strings.Contains(err.Error(), "nie ma folderu") {
		t.Fatalf("chooseMailbox() error = %v, want a friendly no-folder error", err)
	}
}

func TestSelectableMailboxesExcludeInboxGuardianAndNoSelect(t *testing.T) {
	boxes := []imapmail.Mailbox{
		{Name: "INBOX"},
		{Name: "AI-Kwarantanna"},
		{Name: "Poczta", Attributes: []string{`\Noselect`}},
		{Name: "Spam"},
		{Name: "Niechciane"},
	}

	got := selectableMailboxes(boxes, "AI-Kwarantanna")
	if len(got) != 2 || got[0].Name != "Spam" || got[1].Name != "Niechciane" {
		t.Fatalf("selectableMailboxes() = %#v, want only real selectable spam candidates", got)
	}
}

func TestMailboxNameSetKeepsHiddenTrainingFoldersForSafetyChecks(t *testing.T) {
	boxes := []imapmail.Mailbox{
		{Name: "INBOX"},
		{Name: "Spam"},
		{Name: "AI-Naucz-spam"},
		{Name: "AI-Naucz-wazne"},
	}

	names := mailboxNameSet(boxes)
	for _, required := range []string{"AI-Naucz-spam", "AI-Naucz-wazne"} {
		if !names[required] {
			t.Fatalf("hidden training folder %q disappeared from internal safety checks", required)
		}
	}
}

func TestAcquireRunLockSerializesCLICommands(t *testing.T) {
	dataDir := t.TempDir()
	first, err := acquireRunLock(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	if _, err := acquireRunLock(dataDir); err == nil {
		t.Fatal("second acquireRunLock succeeded while the first lock was held")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireRunLock(dataDir)
	if err != nil {
		t.Fatalf("lock was not reusable after release: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNonemptyFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.db")
	if found, err := nonemptyFile(missing); err != nil || found {
		t.Fatalf("nonemptyFile(missing) = %v, %v", found, err)
	}

	empty := filepath.Join(dir, "empty.db")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if found, err := nonemptyFile(empty); err != nil || found {
		t.Fatalf("nonemptyFile(empty) = %v, %v", found, err)
	}

	nonempty := filepath.Join(dir, "guardian.db")
	if err := os.WriteFile(nonempty, []byte("prior state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if found, err := nonemptyFile(nonempty); err != nil || !found {
		t.Fatalf("nonemptyFile(nonempty) = %v, %v", found, err)
	}
}

func TestMenuBeforeSetupShowsOnlyTheNecessaryChoice(t *testing.T) {
	var out bytes.Buffer
	app := &application{
		configPath: filepath.Join(t.TempDir(), "missing.toml"),
		in:         bufio.NewReader(strings.NewReader("0\n")),
		out:        &out,
		errOut:     &out,
	}
	if err := app.menu(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Rozpocznij pierwszą konfigurację", "Żadna wiadomość nie została zmieniona"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("menu output does not contain %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "Tryb aktywny") || strings.Contains(out.String(), "Stan lokalnego silnika") {
		t.Fatalf("menu before setup exposes unnecessary advanced choices:\n%s", out.String())
	}
}

func TestConfiguredMenuUsesPlainLanguage(t *testing.T) {
	cfg, configPath := saveCLIConfig(t)
	var out bytes.Buffer
	app := &application{
		configPath: configPath,
		in:         bufio.NewReader(strings.NewReader("0\n")),
		out:        &out,
		errOut:     &out,
	}
	if err := app.menu(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Sprawdź skrzynkę teraz",
		"Pokaż stan i zalecenia",
		"Sprawdź i napraw program",
		"Jak poprawić pomyłkę robota",
		"Odzyskaj wiadomość z kopii",
		modeName(cfg.Safety.Mode),
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("configured menu does not contain %q:\n%s", want, out.String())
		}
	}
}

func TestHelpUsesPolishAliasesAndPointsToMenu(t *testing.T) {
	var out bytes.Buffer
	app := &application{out: &out, errOut: &out}
	if err := app.execute([]string{"pomoc"}); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" {
		for _, want := range []string{"Linux pilot", "--config", "--dry-run", "systemd", "Protect mode can move mail"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("Linux help does not contain %q: %s", want, out.String())
			}
		}
		return
	}
	for _, want := range []string{"guardian napraw", "guardian konfiguruj", "guardian stan", "guardian sprawdz", "Nie musisz zapamiętywać"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("help does not contain %q:\n%s", want, out.String())
		}
	}
}

func TestAskReturnsEOFInsteadOfLooping(t *testing.T) {
	app := &application{
		in:  bufio.NewReader(strings.NewReader("")),
		out: io.Discard,
	}
	if _, err := app.ask("Pytanie", ""); !errors.Is(err, io.EOF) {
		t.Fatalf("ask() error = %v, want io.EOF", err)
	}
}

func TestRepairIsFailClosedWhenHealthCheckFails(t *testing.T) {
	_, configPath := saveCLIConfig(t)
	var out bytes.Buffer
	var steps []string
	app := &application{
		configPath: configPath,
		in:         bufio.NewReader(strings.NewReader("")),
		out:        &out,
		errOut:     &out,
		startFilter: func(config.Config) error {
			steps = append(steps, "filter")
			return nil
		},
		checkInstallation: func() error {
			steps = append(steps, "check")
			return errors.New("testowa awaria kontroli")
		},
		automationStatus: func(config.Config) error {
			steps = append(steps, "status")
			return nil
		},
		enableAutomation: func(config.Config) error {
			steps = append(steps, "enable")
			return nil
		},
	}
	err := app.repair()
	if err == nil || !strings.Contains(err.Error(), "Automatyzacja i ustawienia bezpieczeństwa pozostały bez zmian") {
		t.Fatalf("repair() error = %v, want fail-closed explanation", err)
	}
	if got := strings.Join(steps, ","); got != "filter,check" {
		t.Fatalf("repair steps = %q, want filter,check", got)
	}
}

func TestRepairAsksBeforeEnablingAutomation(t *testing.T) {
	_, configPath := saveCLIConfig(t)
	var out bytes.Buffer
	var steps []string
	app := &application{
		configPath:  configPath,
		in:          bufio.NewReader(strings.NewReader("tak\n")),
		out:         &out,
		errOut:      &out,
		interactive: true,
		startFilter: func(config.Config) error {
			steps = append(steps, "filter")
			return nil
		},
		checkInstallation: func() error {
			steps = append(steps, "check")
			return nil
		},
		automationStatus: func(config.Config) error {
			steps = append(steps, "status")
			return errors.New("nieaktywna")
		},
		enableAutomation: func(config.Config) error {
			steps = append(steps, "enable")
			lock, err := acquireRunLock(filepath.Dir(configPath))
			if err != nil {
				return fmt.Errorf("repair still held guardian.lock while enabling automation: %w", err)
			}
			return lock.Close()
		},
	}
	if err := app.repair(); err != nil {
		t.Fatalf("repair() failed: %v\n%s", err, out.String())
	}
	if got := strings.Join(steps, ","); got != "filter,check,status,enable" {
		t.Fatalf("repair steps = %q", got)
	}
	for _, want := range []string{
		"nie przenosi ani nie usuwa wiadomości",
		"Czy włączyć je teraz?",
		"Automatyczne sprawdzanie co 2 godziny zostało włączone",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("repair output does not contain %q:\n%s", want, out.String())
		}
	}
}

func TestRepairRespectsDeclinedAutomation(t *testing.T) {
	_, configPath := saveCLIConfig(t)
	enabled := false
	app := &application{
		configPath:        configPath,
		in:                bufio.NewReader(strings.NewReader("nie\n")),
		out:               io.Discard,
		errOut:            io.Discard,
		interactive:       true,
		startFilter:       func(config.Config) error { return nil },
		checkInstallation: func() error { return nil },
		automationStatus:  func(config.Config) error { return errors.New("nieaktywna") },
		enableAutomation: func(config.Config) error {
			enabled = true
			return nil
		},
	}
	if err := app.repair(); err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("repair enabled automation after the user declined")
	}
}

func TestNonInteractiveRepairPreservesManualModeWithoutPrompt(t *testing.T) {
	_, configPath := saveCLIConfig(t)
	var out bytes.Buffer
	enabled := false
	app := &application{
		configPath:        configPath,
		in:                bufio.NewReader(strings.NewReader("")),
		out:               &out,
		errOut:            &out,
		interactive:       false,
		startFilter:       func(config.Config) error { return nil },
		checkInstallation: func() error { return nil },
		automationStatus:  func(config.Config) error { return errors.New("tryb ręczny") },
		enableAutomation:  func(config.Config) error { enabled = true; return nil },
	}
	if err := app.repair(); err != nil {
		t.Fatal(err)
	}
	if enabled || strings.Contains(out.String(), "Czy włączyć") || !strings.Contains(out.String(), "Zachowano tryb ręczny") {
		t.Fatalf("non-interactive repair changed or prompted for automation: enabled=%v output=%q", enabled, out.String())
	}
}

func TestRepairRefreshesAlreadyEnabledAutomation(t *testing.T) {
	_, configPath := saveCLIConfig(t)
	var steps []string
	app := &application{
		configPath: configPath,
		in:         bufio.NewReader(strings.NewReader("")),
		out:        io.Discard,
		errOut:     io.Discard,
		startFilter: func(config.Config) error {
			steps = append(steps, "filter")
			return nil
		},
		checkInstallation: func() error {
			steps = append(steps, "check")
			return nil
		},
		automationStatus: func(config.Config) error {
			steps = append(steps, "status")
			return nil
		},
		enableAutomation: func(config.Config) error {
			steps = append(steps, "refresh")
			lock, err := acquireRunLock(filepath.Dir(configPath))
			if err != nil {
				return fmt.Errorf("repair still held guardian.lock while refreshing automation: %w", err)
			}
			return lock.Close()
		},
	}
	if err := app.repair(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(steps, ","); got != "filter,check,status,refresh" {
		t.Fatalf("repair steps = %q, want filter,check,status,refresh", got)
	}
}

func TestRepairCannotEnableAutomationAfterDryRunRevocation(t *testing.T) {
	cfg, configPath := saveCLIConfig(t)
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RequireFreshDryRun(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	var steps []string
	app := &application{
		configPath:        configPath,
		in:                bufio.NewReader(strings.NewReader("tak\n")),
		out:               io.Discard,
		errOut:            io.Discard,
		startFilter:       func(config.Config) error { steps = append(steps, "filter"); return nil },
		checkInstallation: func() error { steps = append(steps, "check"); return nil },
		automationStatus:  func(config.Config) error { steps = append(steps, "status"); return nil },
		enableAutomation:  func(config.Config) error { steps = append(steps, "enable"); return nil },
		disableAutomation: func(config.Config) error { steps = append(steps, "disable"); return nil },
	}
	if err := app.repair(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(steps, ","); got != "filter,check,disable" {
		t.Fatalf("repair crossed the revoked dry-run gate: %q", got)
	}
	if serviceErr := app.serviceCommand([]string{"install"}); serviceErr == nil || !strings.Contains(serviceErr.Error(), "dry-run") {
		t.Fatalf("CLI service install crossed the revoked dry-run gate: %v", serviceErr)
	}
}

func TestVerifyAndStorePasswordNeverStoresAnUnverifiedSecret(t *testing.T) {
	var sequence []string
	verifyErr := errors.New("odrzucone")
	err := verifyAndStorePassword(
		"nowe-haslo",
		func(string) error {
			sequence = append(sequence, "verify")
			return verifyErr
		},
		func(string) error {
			sequence = append(sequence, "store")
			return nil
		},
	)
	if !errors.Is(err, verifyErr) {
		t.Fatalf("verifyAndStorePassword() error = %v", err)
	}
	if got := strings.Join(sequence, ","); got != "verify" {
		t.Fatalf("sequence after failed verification = %q, want verify only", got)
	}

	sequence = nil
	if err := verifyAndStorePassword(
		"nowe-haslo",
		func(string) error {
			sequence = append(sequence, "verify")
			return nil
		},
		func(string) error {
			sequence = append(sequence, "store")
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sequence, ","); got != "verify,store" {
		t.Fatalf("successful sequence = %q, want verify,store", got)
	}
}

func TestAuthenticationFailureIsDistinguishedFromNetworkFailure(t *testing.T) {
	if !isIMAPAuthenticationError(fmt.Errorf("login: %w", imapmail.ErrAuthentication)) {
		t.Fatal("authentication error was not recognized")
	}
	for _, err := range []error{
		errors.New("połączenie TLS z poczta.o2.pl: timeout"),
		errors.New("brak internetu"),
		nil,
	} {
		if isIMAPAuthenticationError(err) {
			t.Fatalf("network error %v was mistaken for rejected credentials", err)
		}
	}
}

func TestStatusRejectsUnsafeTimeRangesBeforeOpeningDatabase(t *testing.T) {
	app := &application{
		configPath: filepath.Join(t.TempDir(), "missing.toml"),
		out:        io.Discard,
		errOut:     io.Discard,
	}
	for _, args := range [][]string{
		{"--since", "0h"},
		{"--since", "-1h"},
		{"--since", "367d"},
	} {
		if err := app.statusCommand(args); err == nil {
			t.Fatalf("statusCommand(%q) accepted an unsafe range", args)
		}
	}
}

func TestStatusAdviceUsesMenuActions(t *testing.T) {
	advice := statusAdvice(store.Summary{
		Errors:        1,
		WaitingReview: 2,
		PendingMoves:  1,
	}, 10, 20, 200, 200)
	text := strings.Join(advice, "\n")
	for _, want := range []string{"Sprawdź skrzynkę teraz", "Sprawdź i napraw program", "AI-Do-sprawdzenia", "AI-Naucz-spam"} {
		if !strings.Contains(text, want) {
			t.Fatalf("status advice does not contain %q:\n%s", want, text)
		}
	}
}

func TestFailureNotificationIsGenericAndThrottled(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var notifications []string
	app := &application{
		interactive: false,
		out:         io.Discard,
		errOut:      io.Discard,
		sendNotification: func(title, message string) error {
			notifications = append(notifications, title+"\n"+message)
			return nil
		},
	}
	app.maybeNotifyRunFailure(db)
	app.maybeNotifyRunFailure(db)
	if len(notifications) != 1 {
		t.Fatalf("notification count = %d, want 1", len(notifications))
	}
	for _, want := range []string{"wymaga uwagi", "Poczta nie została usunięta", "Sprawdź i napraw program"} {
		if !strings.Contains(notifications[0], want) {
			t.Fatalf("notification does not contain %q:\n%s", want, notifications[0])
		}
	}
	for _, forbidden := range []string{"@", "hasło", "Message-ID", "Subject"} {
		if strings.Contains(notifications[0], forbidden) {
			t.Fatalf("notification unexpectedly contains potentially sensitive text %q:\n%s", forbidden, notifications[0])
		}
	}
}

func TestFailureNotificationIsSilentDuringInteractiveUse(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	called := false
	app := &application{
		interactive: true,
		out:         io.Discard,
		errOut:      io.Discard,
		sendNotification: func(string, string) error {
			called = true
			return nil
		},
	}
	app.maybeNotifyRunFailure(db)
	if called {
		t.Fatal("interactive failure displayed a redundant macOS notification")
	}
}

func TestHasEncryptedArchiveFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "archive")
	found, err := archive.HasEncryptedFiles(root)
	if err != nil || found {
		t.Fatalf("archive.HasEncryptedFiles(missing) = %v, %v", found, err)
	}
	nested := filepath.Join(root, "2026", "07")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "notes.txt"), []byte("not encrypted mail"), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err = archive.HasEncryptedFiles(root)
	if err != nil || found {
		t.Fatalf("archive.HasEncryptedFiles(with unrelated file) = %v, %v", found, err)
	}
	if err := os.WriteFile(filepath.Join(nested, "message.eml.age"), []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err = archive.HasEncryptedFiles(root)
	if err != nil || !found {
		t.Fatalf("archive.HasEncryptedFiles(with archive) = %v, %v", found, err)
	}
}

func TestArchivePreviewDecodesHeadersWithoutTerminalControls(t *testing.T) {
	raw := []byte(
		"From: =?UTF-8?Q?Jan_Kowalski?= <jan@example.org>\r\n" +
			"Subject: Ważna\x1b]8;;https://example.invalid\a wiadomość\r\n" +
			"Date: Sat, 25 Jul 2026 08:00:00 +0200\r\n" +
			"\r\n" +
			"<html>untrusted body</html>",
	)
	preview, err := parseArchiveHeaderPreview(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(preview.From, "Jan Kowalski") ||
		!strings.Contains(preview.Subject, "Ważna") ||
		!strings.Contains(preview.Date, "2026-07-25") {
		t.Fatalf("unexpected preview: %#v", preview)
	}
	combined := preview.From + preview.Subject + preview.Date
	if strings.ContainsAny(combined, "\x1b\a\r\n") ||
		strings.Contains(combined, "untrusted body") ||
		strings.Contains(combined, "https://example.invalid") {
		t.Fatalf("preview exposed controls, a link, or body content: %#v", preview)
	}
}

func TestActivationQualityProblem(t *testing.T) {
	ready := store.ActivationQuality{
		SpamFeedback:         10,
		SpamPreviouslySpam:   9,
		SpamPreviouslyReview: 1,
	}
	if err := activationQualityProblem(ready); err != nil {
		t.Fatalf("ready quality rejected: %v", err)
	}

	notReady := store.ActivationQuality{
		FalsePositives:       1,
		FalseRescues:         2,
		SpamFeedback:         10,
		SpamPreviouslySpam:   8,
		SpamPreviouslyReview: 1,
		SpamUnexplained:      1,
	}
	err := activationQualityProblem(notReady)
	if err == nil {
		t.Fatal("unsafe activation quality was accepted")
	}
	for _, want := range []string{"ważnych wiadomości", "automatycznie uratowanych", "co najmniej 90%", "ręcznego sprawdzenia"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("activation error %q does not explain %q", err, want)
		}
	}
}

func TestStatusWarnsAboutPendingMoves(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
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
	_, err = db.UpsertMessage(context.Background(), &store.Message{
		Account:       cfg.Account.Email,
		SourceFolder:  cfg.Folders.Inbox,
		CurrentFolder: cfg.Folders.Inbox,
		UIDValidity:   1,
		UID:           1,
		MessageIDHash: "pending-message",
		RawSHA256:     "pending-hash",
		SizeBytes:     1,
		Verdict:       "spam",
		Action:        "quarantine",
		Status:        "pending_move",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	app := &application{configPath: configPath, out: &out, errOut: &out}
	if err := app.statusCommand([]string{"--since", "24h"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Ruchy wymagające uzgodnienia:    1", "Sprawdź skrzynkę teraz"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("status output does not contain %q:\n%s", want, out.String())
		}
	}
}

func TestModeTransitionResetsActiveSince(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
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
	installedAt := time.Now().UTC().Add(-15 * 24 * time.Hour).Truncate(time.Second)
	if err := db.SetSetting(ctx, "installed_at", installedAt.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	oldActiveSince := installedAt.Add(-60 * 24 * time.Hour).Format(time.RFC3339)
	if err := db.SetSetting(ctx, "active_since", oldActiveSince); err != nil {
		t.Fatal(err)
	}
	seedReadyActivationQuality(t, db, cfg.Account.Email, installedAt)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	app := &application{
		configPath: configPath,
		in:         bufio.NewReader(strings.NewReader("AKTYWUJ\n")),
		out:        &out,
		errOut:     &out,
	}
	transitionStarted := time.Now().UTC().Add(-time.Second)
	if err := app.modeCommand([]string{"active"}); err != nil {
		t.Fatalf("mode active failed: %v\n%s", err, out.String())
	}
	activeConfig, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if activeConfig.Safety.Mode != "active" || activeConfig.Safety.PurgeEnabled {
		t.Fatalf("unsafe config after activation: mode=%q purge=%v", activeConfig.Safety.Mode, activeConfig.Safety.PurgeEnabled)
	}

	db, err = store.Open(cfg.Runtime.Database)
	if err != nil {
		t.Fatal(err)
	}
	activeValue, err := db.GetSetting(ctx, "active_since")
	if err != nil {
		t.Fatal(err)
	}
	activeSince, err := time.Parse(time.RFC3339, activeValue)
	if err != nil {
		t.Fatalf("active_since = %q: %v", activeValue, err)
	}
	if activeSince.Before(transitionStarted) {
		t.Fatalf("active_since was not reset on activation: got %s, old %s", activeSince, oldActiveSince)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if err := app.modeCommand([]string{"protect"}); err != nil {
		t.Fatalf("mode protect failed: %v", err)
	}
	db, err = store.Open(cfg.Runtime.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	activeValue, err = db.GetSetting(ctx, "active_since")
	if err != nil {
		t.Fatal(err)
	}
	if activeValue != "" {
		t.Fatalf("active_since after mode protect = %q, want empty", activeValue)
	}
}

func saveCLIConfig(t *testing.T) (config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
	cfg.Runtime.DataDir = dir
	cfg.Runtime.Database = filepath.Join(dir, "guardian.db")
	cfg.Runtime.ArchiveDir = filepath.Join(dir, "archive")
	cfg.Runtime.LogFile = filepath.Join(dir, "guardian.log")
	cfg.Runtime.ComposeFile = filepath.Join(dir, "compose.yaml")
	configPath := filepath.Join(dir, "config.toml")
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(context.Background(), "first_dry_run_completed_at", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return cfg, configPath
}

func seedReadyActivationQuality(t *testing.T, db *store.DB, account string, installedAt time.Time) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		hash := fmt.Sprintf("hash-%d", i)
		prior := &store.Message{
			Account:       account,
			SourceFolder:  "INBOX",
			CurrentFolder: "INBOX",
			UIDValidity:   1,
			UID:           uint32(i + 1),
			MessageIDHash: fmt.Sprintf("prior-%d", i),
			RawSHA256:     hash,
			SizeBytes:     1,
			Verdict:       "spam",
			Action:        "quarantine",
			Status:        "observed",
			FirstSeen:     installedAt.Add(time.Hour),
			LastScanned:   installedAt.Add(time.Hour),
		}
		if i == 9 {
			prior.Verdict = "uncertain"
			prior.Action = "review"
			prior.Status = "review"
		}
		if _, err := db.UpsertMessage(ctx, prior); err != nil {
			t.Fatal(err)
		}
		feedback := &store.Message{
			Account:       account,
			SourceFolder:  "AI-Naucz-spam",
			CurrentFolder: "AI-Naucz-spam",
			UIDValidity:   2,
			UID:           uint32(i + 1),
			MessageIDHash: fmt.Sprintf("feedback-%d", i),
			RawSHA256:     hash,
			SizeBytes:     1,
			Verdict:       "spam",
			Action:        "learn_spam",
			Status:        "learned",
			Feedback:      "spam",
			FirstSeen:     installedAt.Add(2 * time.Hour),
			LastScanned:   installedAt.Add(2 * time.Hour),
		}
		if _, err := db.UpsertMessage(ctx, feedback); err != nil {
			t.Fatal(err)
		}
	}
}
