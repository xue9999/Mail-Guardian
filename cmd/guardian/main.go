package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	netmail "net/mail"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/xue9999/Mail-Guardian/internal/apperror"
	"github.com/xue9999/Mail-Guardian/internal/archive"
	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/engine"
	"github.com/xue9999/Mail-Guardian/internal/imapmail"
	"github.com/xue9999/Mail-Guardian/internal/keychain"
	"github.com/xue9999/Mail-Guardian/internal/qualification"
	"github.com/xue9999/Mail-Guardian/internal/rspamd"
	"github.com/xue9999/Mail-Guardian/internal/runlock"
	"github.com/xue9999/Mail-Guardian/internal/service"
	"github.com/xue9999/Mail-Guardian/internal/stack"
	"github.com/xue9999/Mail-Guardian/internal/store"
)

var (
	version = "dev"
	commit  = "none"
)

const (
	bold   = "\033[1m"
	reset  = "\033[0m"
	green  = "\033[32m"
	yellow = "\033[33m"
	red    = "\033[31m"
	blue   = "\033[34m"
)

type application struct {
	configPath string
	in         *bufio.Reader
	out        io.Writer
	errOut     io.Writer
	color      bool

	// Repair test injection points. Nil in production selects real operations.
	startFilter       func(config.Config) error
	checkInstallation func() error
	automationStatus  func(config.Config) error
	enableAutomation  func(config.Config) error
	disableAutomation func(config.Config) error
	sendNotification  func(title, message string) error
	backupModel       func(context.Context, *runtimeApp) error
	interactive       bool
}

type runtimeApp struct {
	ctx     context.Context
	cfg     config.Config
	db      *store.DB
	mail    *imapmail.Client
	scanner *rspamd.Client
	archive *archive.Manager
	engine  *engine.Engine
}

func main() {
	app := &application{
		configPath:  config.DefaultPath(),
		in:          bufio.NewReader(os.Stdin),
		out:         os.Stdout,
		errOut:      os.Stderr,
		color:       term.IsTerminal(int(os.Stdout.Fd())),
		interactive: term.IsTerminal(int(os.Stdin.Fd())),
	}
	if value := os.Getenv("GUARDIAN_CONFIG"); value != "" {
		app.configPath = value
	}
	if err := app.execute(os.Args[1:]); err != nil {
		app.problem(err)
		os.Exit(1)
	}
}

func (a *application) execute(args []string) error {
	if len(args) == 0 {
		if runtime.GOOS == "linux" {
			a.help()
			return nil
		}
		if term.IsTerminal(int(os.Stdin.Fd())) {
			return a.menu()
		}
		a.help()
		return nil
	}
	if args[0] == "--config" {
		if len(args) < 3 {
			return errors.New("provide a path and command after --config")
		}
		a.configPath = args[1]
		args = args[2:]
	}
	if runtime.GOOS == "linux" {
		switch args[0] {
		case "help", "pomoc", "-h", "--help", "version", "wersja", "--version", "self-test", "server":
		case "run", "uruchom", "sprawdz", "status", "stan", "doctor", "kontrola", "preflight", "stack", "service-run", "archive":
			if err := a.validateLinuxRuntime(); err != nil {
				return err
			}
			// Even status/doctor/archive inspection can open or migrate SQLite.
			// Hold the shared migration fence for the entire runtime command,
			// including any mailbox work and privileged maintenance dispatch.
			fence, err := acquireMigrationFence(filepath.Dir(a.configPath), 0)
			if err != nil {
				return err
			}
			defer fence.Close()
			// An administrator may have changed the configuration after the
			// initial path validation and before the fence was acquired. Check
			// it again while publication is excluded.
			if err := a.validateLinuxRuntime(); err != nil {
				return err
			}
		default:
			return errors.New("this Linux pilot supports server configuration, status, doctor, stack, run, service-run and archive commands; manage the timer as an administrator through systemd")
		}
	}
	switch args[0] {
	case "server":
		return a.serverCommand(args[1:])
	case "help", "pomoc", "-h", "--help":
		a.help()
		return nil
	case "version", "wersja", "--version":
		fmt.Fprintf(a.out, "Mail Guardian %s (%s)\n", version, commit)
		fmt.Fprintf(a.out, "Go: %s\n", runtime.Version())
		return nil
	case "self-test":
		return a.selfTest()
	case "setup", "konfiguruj":
		return a.setup()
	case "menu":
		return a.menu()
	case "doctor", "kontrola":
		return a.doctorCommand(args[1:])
	case "preflight":
		return a.doctor(true, false)
	case "repair", "napraw":
		return a.repair()
	case "run", "uruchom", "sprawdz":
		return a.runCommand(args[1:])
	case "status", "stan":
		return a.statusCommand(args[1:])
	case "qualify":
		return a.qualifyCommand(args[1:])
	case "purge":
		return a.purgeCommand(args[1:])
	case "archive":
		return a.archiveCommand(args[1:])
	case "mode":
		return a.modeCommand(args[1:])
	case "service":
		return a.serviceCommand(args[1:])
	case "app-service":
		return a.appServiceCommand(args[1:])
	case "stack":
		return a.stackCommand(args[1:])
	case "api":
		return a.apiCommand(args[1:])
	case "service-run":
		return a.serviceRun()
	default:
		return fmt.Errorf(
			"unknown command %q\nRun Guardian without a command to open the menu",
			args[0],
		)
	}
}

func (a *application) appServiceCommand(args []string) error {
	if len(args) != 1 {
		return errors.New("use: guardian app-service install|uninstall|status")
	}
	appPath, err := service.DefaultUIAppPath()
	if err != nil {
		return err
	}
	manager := service.UIManager{AppPath: appPath}
	switch args[0] {
	case "install":
		return manager.Install()
	case "uninstall":
		return manager.Uninstall()
	case "status":
		if !manager.Status() {
			return errors.New("dashboard does not start at login")
		}
		return nil
	default:
		return errors.New("use: guardian app-service install|uninstall|status")
	}
}

func (a *application) doctorCommand(args []string) error {
	deep := false
	for _, arg := range args {
		if arg != "--deep" {
			return errors.New("use: guardian doctor [--deep]")
		}
		deep = true
	}
	return a.doctor(deep, deep)
}

func (a *application) serviceRun() (retErr error) {
	if runtime.GOOS == "linux" {
		return a.linuxServiceRun()
	}
	dataDir := config.DefaultDataDir()
	if cfg, err := config.Load(a.configPath); err == nil {
		dataDir = cfg.Runtime.DataDir
	}
	heartbeat, _ := service.ReadHeartbeat(dataDir)
	now := time.Now().UTC()
	heartbeat.LastAttempt = &now
	heartbeat.Stage = "starting"
	heartbeat.ErrorCode = ""
	heartbeat.Version = version
	_ = service.WriteHeartbeat(dataDir, heartbeat)
	defer func() {
		finished := time.Now().UTC()
		if retErr == nil {
			heartbeat.LastSuccess = &finished
			heartbeat.Stage = "ok"
			heartbeat.ErrorCode = ""
		} else {
			heartbeat.Stage = "failed"
			heartbeat.ErrorCode = string(apperror.From(retErr).Code)
		}
		_ = service.WriteHeartbeat(dataDir, heartbeat)
	}()
	heartbeat.Stage = "stack"
	_ = service.WriteHeartbeat(dataDir, heartbeat)
	if err := a.stackCommand([]string{"up"}); err != nil {
		return err
	}
	heartbeat.Stage = "mailbox"
	_ = service.WriteHeartbeat(dataDir, heartbeat)
	run, err := a.runCommandResult(nil)
	return requireSuccessfulRun(run, err)
}

func (a *application) help() {
	if runtime.GOOS == "linux" {
		fmt.Fprintln(a.out, `Mail Guardian — Linux pilot (protect/active policies, permanent deletion disabled)

Create a new offline configuration:
  guardian server init-config --instance NAME --email EMAIL --server-spam FOLDER [--mode protect|active] --output NEW-FILE
  guardian --config FILE server validate-config --instance NAME

After verified same-mailbox state import, before any normal runtime command:
  sudo guardian --config /etc/mail-guardian/NAME/config.toml server adopt-policy --instance NAME --preserve-policy
This preserves validated source policy history and requires a new server dry-run.

Use the explicitly provisioned instance and systemd credentials:
  guardian --config /etc/mail-guardian/NAME/config.toml run --dry-run
  guardian --config /etc/mail-guardian/NAME/config.toml run
  guardian --config /etc/mail-guardian/NAME/config.toml status
  guardian --config /etc/mail-guardian/NAME/config.toml doctor --deep
  guardian --config /etc/mail-guardian/NAME/config.toml archive list|show|restore

The administrator manages the systemd timer after pilot and recovery acceptance.
Protect mode can move mail and process corrections. Read the Linux pilot runbook.`)
		return
	}
	fmt.Fprintln(a.out, "\nMail Guardian — a private IMAP mailbox guardian\n\nStart here:\n  guardian                     open the interactive menu\n  guardian repair              check and safely repair installation\n\nAccount and mail:\n  guardian setup               configuration wizard\n  guardian status              readable status summary\n  guardian run --dry-run       preview without moves or learning\n  guardian run                 check the mailbox safely\n  guardian doctor              diagnose without repairs\n\nSafety and recovery:\n  guardian mode status         current protection mode\n  guardian archive list        encrypted backup list\n  guardian archive show ID     safe header preview\n  guardian archive restore ID  restore to the configured review folder\n  guardian purge --dry-run     preview deletion eligibility\n\nAutomation and services:\n  guardian service install|status|uninstall\n  guardian stack up|status|down\n  guardian server init-config|validate-config\n\nDaily actions are also available in the menu. Permanent deletion is disabled by default and requires separate qualification and authorization.")
}

func (a *application) setup() (retErr error) {
	a.header("First-time setup wizard")
	if runtime.GOOS != "darwin" {
		return errors.New("secure Keychain wizard requires macOS")
	}
	cfg, newErr := config.NewInstance()
	if newErr != nil {
		return newErr
	}
	firstSetup := true
	configurationSaved := false
	identityCreated := false
	var rollbackPassword func() error
	var scannerManager service.Manager
	scannerPaused := false
	defer func() {
		if retErr == nil || configurationSaved {
			return
		}
		var rollbackErrors []error
		if rollbackPassword != nil {
			if err := rollbackPassword(); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("restoring previous password: %w", err))
			}
		}
		if identityCreated {
			kc := keychain.New()
			if err := kc.Delete(cfg.Runtime.ArchiveKeychainService, cfg.Account.Email); err != nil && !errors.Is(err, keychain.ErrNotFound) {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("removing incomplete archive key: %w", err))
			}
		}
		if scannerPaused {
			if err := scannerManager.Install(); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("resuming previous automation: %w", err))
			}
		}
		retErr = errors.Join(retErr, errors.Join(rollbackErrors...))
	}()
	if _, err := os.Stat(a.configPath); err == nil {
		existing, err := config.Load(a.configPath)
		if err != nil {
			return fmt.Errorf(
				"existing configuration is unreadable and will not be overwritten: %w\nRepair %s or restore it from backup",
				err, a.configPath,
			)
		}
		cfg = existing
		firstSetup = false
		a.info("Existing configuration found. The wizard will update it safely.")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot check configuration file %s: %w", a.configPath, err)
	}
	if err := os.MkdirAll(cfg.Runtime.DataDir, 0o700); err != nil {
		return fmt.Errorf("cannot prepare private data directory: %w", err)
	}
	lock, err := acquireRunLock(cfg.Runtime.DataDir)
	if err != nil {
		return err
	}
	defer lock.Close()

	email, err := a.ask("Email address", cfg.Account.Email)
	if err != nil {
		return err
	}
	email = strings.TrimSpace(email)
	if !strings.Contains(email, "@") {
		return errors.New("email address appears invalid")
	}
	if !firstSetup && !strings.EqualFold(email, cfg.Account.Email) {
		return errors.New("existing installation belongs to another account; create a separate installation to avoid mixing databases and encrypted backups")
	}
	if !firstSetup {
		// Preserve the exact Keychain account identifier used during the first
		// setup even if the user typed different letter casing.
		email = cfg.Account.Email
	}
	cfg.Account.Email = email
	if firstSetup {
		profile, err := a.ask("Connection profile (custom or o2)", "custom")
		if err != nil {
			return err
		}
		cfg.Account.Provider = strings.TrimSpace(profile)
		if cfg.Account.Provider == "custom" {
			cfg.Account.Host, err = a.ask("IMAP hostname (implicit TLS)", "")
			if err != nil {
				return err
			}
			port, err := a.ask("IMAP port", "993")
			if err != nil {
				return err
			}
			if cfg.Account.Port, err = strconv.Atoi(port); err != nil {
				return err
			}
		}
		cfg.Account.Username, err = a.ask("IMAP login", email)
		if err != nil {
			return err
		}
		cfg, err = cfg.ResolveIdentity()
		if err != nil {
			return err
		}
	}

	kc := keychain.New()
	identityExisted := true
	if _, err := archive.LoadIdentity(kc, cfg.Runtime.ArchiveKeychainService, email); err != nil {
		if !errors.Is(err, keychain.ErrNotFound) {
			return fmt.Errorf("cannot check backup encryption key in Keychain: %w", err)
		}
		if err := validateNewArchiveIdentity(cfg.Runtime.ArchiveDir, cfg.Runtime.Database); err != nil {
			return err
		}
		identityExisted = false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	var mail *imapmail.Client
	savedPassword, savedPasswordErr := kc.Get(cfg.Account.PasswordKeychainService, email)
	if savedPasswordErr != nil && !errors.Is(savedPasswordErr, keychain.ErrNotFound) {
		return fmt.Errorf("cannot read IMAP password from Keychain: %w", savedPasswordErr)
	}
	if !firstSetup && savedPasswordErr == nil {
		a.info("Checking the saved password — no need to enter it again…")
		mail, err = dialMailbox(ctx, cfg, savedPassword)
		if err == nil {
			a.success("The saved password still works.")
		} else if !isIMAPAuthenticationError(err) {
			return fmt.Errorf(
				"cannot check saved password now: %w\n"+
					"The Keychain password was not changed; check your connection and retry",
				err,
			)
		} else {
			a.warning("Mail server rejected the saved password. It remains unchanged until a new one is verified.")
		}
	}

	if mail == nil {
		fmt.Fprintln(a.out, "\nEnable IMAP access with your email provider. Use a separate app password where supported, and follow your provider's account security instructions. Guardian supports password authentication over verified implicit TLS; accounts requiring OAuth are not supported. The secret is saved in Keychain only after successful authentication.")
		if ok, confirmErr := a.confirm("Do you have the account or app password ready?", true); confirmErr != nil {
			return confirmErr
		} else if !ok {
			return errors.New("setup stopped; return when the account/app password is ready")
		}
		password, passwordErr := a.readHiddenPassword("Account or app password")
		if passwordErr != nil {
			return passwordErr
		}
		a.info("Checking the new password over encrypted IMAP…")
		verify := func(candidate string) error {
			var dialErr error
			mail, dialErr = dialMailbox(ctx, cfg, candidate)
			return dialErr
		}
		save := func(candidate string) error {
			var saveErr error
			rollbackPassword, saveErr = replaceSecret(
				kc,
				cfg.Account.PasswordKeychainService,
				email,
				candidate,
				"Mail Guardian - IMAP password",
			)
			return saveErr
		}
		if err := verifyAndStorePassword(password, verify, save); err != nil {
			if mail != nil {
				_ = mail.Close()
			}
			return fmt.Errorf(
				"%w\nThe new password did not replace the existing Keychain password",
				err,
			)
		}
		a.success("The new password works and was saved securely in Keychain.")
	}
	defer mail.Close()
	boxes, err := mail.ListMailboxes()
	if err != nil {
		return err
	}
	spamFolder := imapmail.DetectSpamFolder(boxes)
	if spamFolder != "" {
		ok, err := a.confirm(fmt.Sprintf("Spam folder detected: %q. Use it?", spamFolder), true)
		if err != nil {
			return err
		}
		if !ok {
			spamFolder = ""
		}
	}
	if spamFolder == "" {
		spamFolder, err = a.chooseMailbox(
			boxes,
			cfg.Folders.Inbox,
			cfg.Folders.Quarantine,
			cfg.Folders.Review,
			cfg.Folders.TrainSpam,
			cfg.Folders.TrainHam,
		)
		if err != nil {
			return err
		}
	}
	cfg.Folders.ServerSpam = spamFolder
	enforceSetupProtection(&cfg)
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("selected folder layout is unsafe and will not be created: %w", err)
	}
	if !mail.SafeMoveSupported() {
		return errors.New("server did not advertise native IMAP MOVE; refusing an unsafe fallback move")
	}
	var existingRobotFolders []string
	existingRobotFolder := make(map[string]bool)
	for _, target := range []string{cfg.Folders.Quarantine, cfg.Folders.Review, cfg.Folders.TrainSpam, cfg.Folders.TrainHam} {
		for _, box := range boxes {
			if box.Name == target {
				existingRobotFolders = append(existingRobotFolders, target)
				existingRobotFolder[target] = true
				break
			}
			if strings.EqualFold(box.Name, target) {
				return fmt.Errorf(
					"existing folder %q differs from required name %q only by case; rename it and retry the wizard",
					box.Name,
					target,
				)
			}
		}
	}
	if len(existingRobotFolders) > 0 {
		ok, err := a.confirm("Folders "+strings.Join(existingRobotFolders, ", ")+" already exist. Reuse them?", false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("setup stopped; rename conflicting folders in existing configuration or empty them")
		}
	}
	if existingRobotFolder[cfg.Folders.TrainSpam] || existingRobotFolder[cfg.Folders.TrainHam] {
		trainingCounts := make(map[string]int)
		for _, folder := range []string{cfg.Folders.TrainSpam, cfg.Folders.TrainHam} {
			if !existingRobotFolder[folder] {
				continue
			}
			uids, _, err := mail.SearchSince(folder, time.Time{}, 0)
			if err != nil {
				return fmt.Errorf("cannot safely inspect training folder %q: %w", folder, err)
			}
			trainingCounts[folder] = len(uids)
		}
		totalTraining := trainingCounts[cfg.Folders.TrainSpam] + trainingCounts[cfg.Folders.TrainHam]
		if totalTraining > 0 {
			fmt.Fprintf(
				a.out,
				"\nWarning: existing training folders contain messages:\n  %s: %d\n  %s: %d\n",
				cfg.Folders.TrainSpam,
				trainingCounts[cfg.Folders.TrainSpam],
				cfg.Folders.TrainHam,
				trainingCounts[cfg.Folders.TrainHam],
			)
			ok, err := a.confirmDanger(
				"On the next run, each message becomes an explicit filter correction and will be moved.",
				"UCZ",
			)
			if err != nil || !ok {
				return errors.New("setup stopped; empty existing training folders or restart the wizard and explicitly accept their contents")
			}
		}
	}
	a.printFolderMapping(cfg)
	if firstSetup {
		ok, err := a.confirm("Is this folder layout correct, and may I create it?", false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("setup stopped before folder creation; no Guardian folders added")
		}
	}
	if err := mail.EnsureMailboxes(cfg.Folders.Quarantine, cfg.Folders.Review, cfg.Folders.TrainSpam, cfg.Folders.TrainHam); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.Runtime.ArchiveDir, 0o700); err != nil {
		return err
	}
	archiveIdentity, err := archive.EnsureIdentity(kc, cfg.Runtime.ArchiveKeychainService, email)
	if err != nil {
		return err
	}
	identityCreated = !identityExisted
	if _, err := archive.New(cfg.Runtime.ArchiveDir, archiveIdentity); err != nil {
		return fmt.Errorf("encrypted-backup directory is unsafe: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate executable before changing configuration: %w", err)
	}
	scannerManager = service.Manager{Executable: exe, DataDir: cfg.Runtime.DataDir, LogFile: cfg.Runtime.LogFile}
	if scannerManager.Installed() {
		scannerPaused = true
		if err := scannerManager.Uninstall(); err != nil {
			return fmt.Errorf("cannot safely pause automation before configuration change: %w", err)
		}
	}
	if err := config.Save(a.configPath, cfg); err != nil {
		return err
	}
	configurationSaved = true
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		return err
	}
	defer db.Close()
	settingsCtx := context.Background()
	value, err := db.GetSetting(settingsCtx, "installed_at")
	if err != nil {
		return fmt.Errorf("cannot read protection-period start: %w", err)
	}
	if value == "" {
		started := time.Now().UTC().Format(time.RFC3339)
		if err := db.SetSetting(settingsCtx, "installed_at", started); err != nil {
			return err
		}
	}
	if err := db.RequireFreshDryRun(settingsCtx, time.Now()); err != nil {
		return err
	}
	a.success("The connection works, folders are ready, and backups will be encrypted.")
	// launchd installation may start a run immediately. Configuration and
	// folders are coherent; release the lock before bootstrap.
	if err := lock.Close(); err != nil {
		return fmt.Errorf("configuration is ready, but the application lock could not be safely released: %w", err)
	}

	controller, err := kc.Get(cfg.Rspamd.PasswordKeychainService, "controller")
	if err != nil {
		a.warning("The local filter is not ready yet. Choose Check and repair in the menu.")
	} else if pingErr := rspamd.New(cfg.Rspamd.ScanURL, cfg.Rspamd.LearnURL, controller, 5*time.Second).Ping(ctx); pingErr != nil {
		a.warning("The local filter is not responding yet. Choose Check and repair in the menu.")
	} else {
		a.success("Local spam filter responds.")
	}
	a.header("Required safe dry-run")
	a.info("Guardian will preview decisions without moving messages or training the filter.")
	if err := a.runCommand([]string{"--dry-run"}); err != nil {
		return apperror.Wrap(
			apperror.Rspamd, "attention", "The dry-run did not complete successfully.",
			"Fix the reported problem and retry setup; automation was not enabled.", err,
		)
	}
	a.success("The dry-run succeeded. The mailbox was unchanged.")
	if _, statusErr := scannerManager.Status(); statusErr == nil {
		a.success("Automatic checks every 2 hours are already active.")
	} else if ok, confirmErr := a.confirm("Enable automatic checks every 2 hours?", true); confirmErr != nil {
		return confirmErr
	} else if ok {
		if err := scannerManager.Install(); err != nil {
			a.warning("Could not enable automation: " + err.Error())
		} else {
			a.success("Automatic checks are active.")
		}
	} else {
		a.info("Automatic checks remain off as requested.")
	}
	fmt.Fprintln(a.out, "\nDone. A new protection period of at least 14 days has started. Permanent deletion is disabled.")
	return nil
}

func (a *application) chooseMailbox(boxes []imapmail.Mailbox, excludedNames ...string) (string, error) {
	fmt.Fprintln(a.out, "\nThe spam folder could not be detected automatically.")
	fmt.Fprintln(a.out, "Select the folder where your email provider places unwanted mail:")
	selectable := selectableMailboxes(boxes, excludedNames...)
	for index, box := range selectable {
		fmt.Fprintf(a.out, "  %d. %s\n", index+1, box.Name)
	}
	if len(selectable) == 0 {
		return "", errors.New("no folder can safely be selected as spam; create a spam folder with your provider and retry")
	}
	value, err := a.ask("Enter spam folder number", "")
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > len(selectable) {
		return "", fmt.Errorf("no folder numbered %q; enter one of the listed numbers", value)
	}
	return selectable[n-1].Name, nil
}

// selectableMailboxes gives both wizards the same safe spam-folder choices,
// excluding Inbox, Guardian folders and \Noselect containers.
func selectableMailboxes(boxes []imapmail.Mailbox, excludedNames ...string) []imapmail.Mailbox {
	excluded := make(map[string]struct{}, len(excludedNames)+1)
	excluded["inbox"] = struct{}{}
	for _, name := range excludedNames {
		excluded[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}

	selectable := make([]imapmail.Mailbox, 0, len(boxes))
	for _, box := range boxes {
		if _, skip := excluded[strings.ToLower(strings.TrimSpace(box.Name))]; skip {
			continue
		}
		noSelect := false
		for _, attribute := range box.Attributes {
			if strings.EqualFold(strings.TrimSpace(attribute), `\Noselect`) {
				noSelect = true
				break
			}
		}
		if !noSelect {
			selectable = append(selectable, box)
		}
	}
	return selectable
}

func (a *application) printFolderMapping(cfg config.Config) {
	fmt.Fprintln(a.out, "\nGuardian will use these folders:")
	fmt.Fprintf(a.out, "  Inbox (INBOX):             %s\n", cfg.Folders.Inbox)
	fmt.Fprintf(a.out, "  Provider spam folder:      %s\n", cfg.Folders.ServerSpam)
	fmt.Fprintf(a.out, "  Confident spam in quarantine: %s\n", cfg.Folders.Quarantine)
	fmt.Fprintf(a.out, "  Manual review:             %s\n", cfg.Folders.Review)
	fmt.Fprintf(a.out, "  Training — spam:           %s\n", cfg.Folders.TrainSpam)
	fmt.Fprintf(a.out, "  Training — ham:            %s\n", cfg.Folders.TrainHam)
}

func (a *application) doctor(verbose, deep bool) error {
	a.header("Installation check")
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return apperror.Wrap(apperror.Config, "critical", "Guardian configuration is unreadable.", "Open the application and run Repair or first-time setup.", err)
	}
	failures := 0
	var firstFailure error
	check := func(label string, err error) {
		if err != nil {
			failures++
			if firstFailure == nil {
				firstFailure = err
			}
			a.problem(fmt.Errorf("%s: %w", label, err))
		} else {
			a.success(label)
		}
	}
	info, err := os.Stat(a.configPath)
	if err == nil && runtime.GOOS == "linux" {
		err = validateAdministratorPath(a.configPath)
	} else if err == nil && info.Mode().Perm()&0o077 != 0 {
		err = fmt.Errorf("permissions %o are too broad; expected 600", info.Mode().Perm())
	}
	check("Configuration is private", err)
	kc := runtimeSecrets(cfg)
	_, err = kc.Get(cfg.Account.PasswordKeychainService, cfg.Account.Email)
	if err != nil {
		err = apperror.Wrap(apperror.Keychain, "critical", "Cannot read the IMAP password from Keychain.", "Unlock Keychain or save the account/app password again in settings.", err)
	}
	check("The IMAP password is in Keychain", err)
	controller, ctrlErr := kc.Get(cfg.Rspamd.PasswordKeychainService, "controller")
	if ctrlErr != nil {
		ctrlErr = apperror.Wrap(apperror.Keychain, "critical", "Cannot read the local filter password.", "Run Install.command to safely repair the engine.", ctrlErr)
	}
	check("The local filter password is in Keychain", ctrlErr)
	archiveIdentity, err := archive.LoadIdentity(kc, cfg.Runtime.ArchiveKeychainService, cfg.Account.Email)
	if err != nil {
		err = apperror.Wrap(apperror.ArchiveKey, "critical", "Cannot read the encrypted-backup key.", "Do not delete the archive; unlock Keychain and run Repair.", err)
	}
	check("The backup key is in Keychain", err)
	db, err := store.Open(cfg.Runtime.Database)
	check("The state database works", err)
	if db != nil {
		defer db.Close()
		integrityErr := db.IntegrityCheck(context.Background())
		check("The state database passes integrity checks", integrityErr)
		if integrityErr == nil && archiveIdentity != nil {
			archiver, archiveErr := archive.New(cfg.Runtime.ArchiveDir, archiveIdentity)
			if archiveErr == nil {
				archiveErr = (&engine.Engine{Config: cfg, Store: db, Archive: archiver}).CheckArchiveFiles(context.Background())
			}
			check("The 25 newest encrypted backups pass integrity checks", archiveErr)
		}
	}
	free, diskErr := freeBytes(cfg.Runtime.DataDir)
	if diskErr == nil && free < 1<<30 {
		diskErr = fmt.Errorf("less than 1 GiB disk space remains")
	}
	check("Disk space is available for safe backups", diskErr)
	scanner := rspamd.New(cfg.Rspamd.ScanURL, cfg.Rspamd.LearnURL, controller, 8*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pingErr := scanner.Ping(ctx)
	if pingErr != nil {
		pingErr = apperror.Wrap(apperror.Rspamd, "critical", "The local spam filter is not responding.", "Run Repair.", pingErr)
	}
	check("Local spam filter responds", pingErr)
	if pingErr == nil {
		testMessage := []byte(
			"From: guardian@example.invalid\r\n" +
				"To: guardian@example.invalid\r\n" +
				"Message-ID: <guardian-preflight@example.invalid>\r\n" +
				"Subject: Guardian preflight\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
				"Local configuration check.\r\n",
		)
		result, scanErr := scanner.Scan(ctx, testMessage, "")
		if scanErr == nil {
			decision := rspamd.Classify(result, cfg.Rspamd.SpamScore, cfg.Rspamd.HamScore, cfg.Safety.RequireAuthForRescue)
			if decision.Incomplete {
				scanErr = errors.New("test Rspamd scan was incomplete")
			}
		}
		check("Local filter performs a complete test", scanErr)
		if verbose {
			stats, statsErr := scanner.Stats(ctx)
			if statsErr == nil && db != nil {
				statsErr = compareBayesHighWater(ctx, db, cfg.Account.Email, stats)
			}
			check("Bayes statistics are available and complete", statsErr)
		}
	}
	password, passErr := kc.Get(cfg.Account.PasswordKeychainService, cfg.Account.Email)
	if passErr == nil {
		mail, mailErr := dialMailbox(ctx, cfg, password)
		check("Encrypted IMAP authentication works", mailErr)
		if mailErr == nil {
			defer mail.Close()
			boxes, listErr := mail.ListMailboxes()
			check("The IMAP folder list is available", listErr)
			if listErr == nil {
				required := []string{cfg.Folders.ServerSpam, cfg.Folders.Quarantine, cfg.Folders.Review, cfg.Folders.TrainSpam, cfg.Folders.TrainHam}
				for _, name := range required {
					found := false
					for _, box := range boxes {
						if box.Name == name {
							found = true
							break
						}
					}
					if !found {
						failures++
						a.problem(fmt.Errorf("missing folder %q", name))
					}
				}
				caps := mail.Capabilities()
				check("Native IMAP MOVE is supported", boolError(mail.SafeMoveSupported(), "native MOVE unavailable"))
				if !mail.SafeDeleteSupported() {
					a.warning("UIDPLUS is unavailable: permanent deletion will be blocked.")
				}
				if verbose {
					fmt.Fprintf(a.out, "\nSpam folder: %s\nFolder delimiter: %q\nIMAP: %s\n",
						cfg.Folders.ServerSpam, delimiterOf(boxes), strings.Join(caps.Names, ", "))
					fmt.Fprintln(a.out, "The application does not make SMTP connections or send email.")
				}
			}
		}
	}
	if deep {
		executable, _ := os.Executable()
		manager := service.Manager{Executable: executable, DataDir: cfg.Runtime.DataDir, LogFile: cfg.Runtime.LogFile}
		check("The automatic service is active", func() error { _, statusErr := manager.Status(); return statusErr }())
		heartbeat, heartbeatErr := service.ReadHeartbeat(cfg.Runtime.DataDir)
		if heartbeatErr == nil {
			if stale := heartbeatFreshnessError(heartbeat, time.Now()); stale != nil {
				heartbeatErr = stale
			}
		}
		check("The automatic-check heartbeat is current", heartbeatErr)
		managerStack := runtimeStack(cfg)
		stackErr := managerStack.DeepCheck()
		check("Redis, DNS and Rspamd work in the local stack", stackErr)
	}
	if failures > 0 {
		return firstFailure
	}
	a.success("All checks passed.")
	return nil
}

func compareBayesHighWater(ctx context.Context, db *store.DB, account string, stats rspamd.BayesStats) error {
	trainedSpam, trainedHam, err := db.TrainingTotals(ctx, account)
	if err != nil {
		return err
	}
	for _, item := range []struct {
		key     string
		current uint64
		minimum uint64
	}{
		{key: "bayes_spam_revision_highwater", current: stats.SpamRevision, minimum: uint64(trainedSpam)},
		{key: "bayes_ham_revision_highwater", current: stats.HamRevision, minimum: uint64(trainedHam)},
	} {
		value, err := db.GetSetting(ctx, item.key)
		if err != nil {
			return err
		}
		highest := item.minimum
		if value != "" {
			parsed, parseErr := strconv.ParseUint(value, 10, 64)
			if parseErr != nil {
				return apperror.Wrap(
					apperror.BayesRollback, "critical", "The Bayes model check record is corrupt.",
					"Remain in protect mode and run Repair; do not enable purge.", parseErr,
				)
			}
			// Rspamd deduplicates statistical content, while SQLite counts
			// distinct raw messages. Only an observed Rspamd revision can
			// prove a regression once that authoritative baseline exists.
			highest = parsed
		}
		if item.current < highest {
			return apperror.Wrap(
				apperror.BayesRollback, "critical", "The local Bayes model rolled back or was reset.",
				"Remain in protect mode and run Repair; do not enable purge.", nil,
			)
		}
	}
	return nil
}

func (a *application) runCommand(args []string) error {
	run, err := a.runCommandResult(args)
	return requireSuccessfulRun(run, err)
}

func requireSuccessfulRun(run *store.Run, err error) error {
	if err != nil {
		return err
	}
	if run == nil {
		return errors.New("no confirmed scan result")
	}
	if run.Errors > 0 {
		return fmt.Errorf("run completed with %d errors; some operations need attention", run.Errors)
	}
	return nil
}

func recordSuccessfulDryRun(db *store.DB, run *store.Run, now time.Time) error {
	if run == nil || !run.DryRun || requireSuccessfulRun(run, nil) != nil {
		return nil
	}
	return db.SetSetting(context.Background(), "first_dry_run_completed_at", now.UTC().Format(time.RFC3339Nano))
}

// Return the exact run to the GUI; a daily aggregate cannot describe a dry-run.
func (a *application) runCommandResult(args []string) (*store.Run, error) {
	return a.runCommandResultLocked(args, false)
}

func (a *application) runCommandResultLocked(args []string, locked bool) (*store.Run, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(a.errOut)
	dryRun := fs.Bool("dry-run", false, "preview decisions only")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, errors.New("check command accepts no extra text; run Guardian without a command and choose a menu action")
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return nil, fmt.Errorf("%w\nOpen the menu and start first-time setup", err)
	}
	if !locked {
		lock, err := acquireRunLock(cfg.Runtime.DataDir)
		if err != nil {
			return nil, err
		}
		defer lock.Close()
	}
	rt, cleanup, err := a.openRuntime(true)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	if !*dryRun {
		rolledBack, continuityErr := a.ensureBayesContinuity(context.Background(), rt)
		if continuityErr != nil {
			return nil, continuityErr
		}
		if rolledBack {
			a.warning("Local Bayes model rollback detected. Protect mode enabled and permanent deletion disabled.")
		}
		if runtime.GOOS == "linux" {
			if err := a.prepareLinuxMutation(rt); err != nil {
				return nil, err
			}
		}
	}
	a.header("Checking mailbox")
	if *dryRun {
		a.warning("DRY-RUN: no messages will be moved or learned.")
	}
	run, err := rt.engine.Run(rt.ctx, engine.RunOptions{DryRun: *dryRun})
	err = a.secureRunModel(rt, run, err, *dryRun)
	if err != nil {
		if !*dryRun && os.Getenv("GUARDIAN_SERVICE_RUNNER") != "1" {
			a.maybeNotifyRunFailure(rt.db)
		}
		return run, err
	}
	if *dryRun {
		if err := recordSuccessfulDryRun(rt.db, run, time.Now()); err != nil {
			return nil, fmt.Errorf("dry-run succeeded, but its confirmation was not saved: %w", err)
		}
	}
	a.printRun(run)
	if rt.cfg.Safety.PurgeEnabled && !*dryRun {
		purgeRun, purgeErr := rt.engine.Purge(rt.ctx, false)
		if purgeErr != nil {
			a.warning("Automatic quarantine cleanup skipped: " + purgeErr.Error())
		} else if purgeRun.Purged > 0 {
			fmt.Fprintf(a.out, "Permanently deleted after revalidation: %d\n", purgeRun.Purged)
		}
	}
	if !*dryRun {
		if cleaned, cleanupErr := rt.engine.CleanupExpiredArchives(context.Background()); cleanupErr != nil {
			a.warning("Expired local backups were not removed: " + cleanupErr.Error())
		} else if cleaned > 0 {
			fmt.Fprintf(a.out, "Expired local backups removed: %d\n", cleaned)
		}
	}
	if !*dryRun {
		a.maybeNotify(rt.db)
	}
	return run, nil
}

// A timed-out mailbox must not prevent backing up corrections already learned
// earlier in that run. Local model checks use a fresh independent context.
func (a *application) secureRunModel(rt *runtimeApp, run *store.Run, runErr error, dryRun bool) error {
	if runtime.GOOS == "linux" && !dryRun {
		checkpointErr := a.finishLinuxMutation(rt)
		combined := errors.Join(runErr, checkpointErr)
		if checkpointErr != nil && run != nil {
			run.Errors++
			combined = errors.Join(combined, rt.db.FinishRun(context.Background(), run, combined))
		}
		return combined
	}
	if dryRun || run == nil || (runErr != nil && run.LearnedSpam == 0 && run.LearnedHam == 0) {
		return runErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	backup := a.backupModel
	if backup == nil {
		backup = func(ctx context.Context, rt *runtimeApp) error {
			if _, statsErr := a.ensureBayesContinuity(ctx, rt); statsErr != nil {
				a.warning("Could not save the current Bayes state: " + statsErr.Error())
			}
			stats, err := rt.scanner.Stats(ctx)
			if err != nil {
				return err
			}
			manager := runtimeStack(rt.cfg)
			if err := manager.BackupRedis(rt.cfg.Runtime.DataDir, stats.SpamRevision, stats.HamRevision); err != nil {
				return err
			}
			return manager.CheckStorage()
		}
	}
	if err := backup(ctx, rt); err != nil {
		run.Errors++
		combined := errors.Join(runErr, fmt.Errorf("could not back up Bayes model on Mac: %w", err))
		if finishErr := rt.db.FinishRun(context.Background(), run, combined); finishErr != nil {
			return errors.Join(combined, finishErr)
		}
		return combined
	}
	return runErr
}

func (a *application) statusCommand(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(a.errOut)
	sinceValue := fs.String("since", "24h", "period, e.g. 24h or 7d")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("report accepts no extra text; choose Show status and recommendations in the menu")
	}
	duration, err := config.ParseSince(*sinceValue)
	if err != nil {
		return fmt.Errorf("invalid report period %q; use e.g. 24h or 7d", *sinceValue)
	}
	if duration <= 0 {
		return errors.New("report period must be positive, e.g. 24h or 7d")
	}
	if duration > 366*24*time.Hour {
		return errors.New("report period must not exceed 366 days")
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		return err
	}
	defer db.Close()
	summary, err := db.Summary(context.Background(), time.Now().Add(-duration))
	if err != nil {
		return err
	}
	trainedSpam, trainedHam, err := db.TrainingTotals(context.Background(), cfg.Account.Email)
	if err != nil {
		return err
	}
	falseSpam, falseHam, err := db.MisclassificationsSince(context.Background(), cfg.Account.Email, time.Now().Add(-30*24*time.Hour))
	if err != nil {
		return err
	}
	a.header("Worker status")
	fmt.Fprintf(a.out, "Mode: %s\nPermanent deletion: %s\nReport period: %s\n\n",
		modeName(cfg.Safety.Mode), yesNo(cfg.Safety.PurgeEnabled), *sinceValue)
	fmt.Fprintf(a.out, "Runs:                  %d (including dry-runs: %d)\n", summary.Runs, summary.DryRuns)
	fmt.Fprintf(a.out, "Messages scanned:      %d\n", summary.Scanned)
	fmt.Fprintf(a.out, "Rescued from spam:      %d\n", summary.Rescued)
	fmt.Fprintf(a.out, "Moved to quarantine: %d\n", summary.Quarantined)
	fmt.Fprintf(a.out, "For manual review:          %d\n", summary.Review)
	fmt.Fprintf(a.out, "Learned as spam/ham:        %d/%d\n", summary.LearnedSpam, summary.LearnedHam)
	fmt.Fprintf(a.out, "Errors without mail loss:   %d\n\n", summary.Errors)
	fmt.Fprintf(a.out, "Currently recorded in quarantine: %d\n", summary.WaitingQuarantine)
	fmt.Fprintf(a.out, "Currently awaiting review: %d\n", summary.WaitingReview)
	fmt.Fprintf(a.out, "Moves needing reconciliation: %d\n", summary.PendingMoves)
	if summary.PendingMoves > 0 {
		a.warning("Some moves require safe reconciliation with the server. Messages remain protected.")
	}
	fmt.Fprintf(a.out, "Older than the quarantine period (not yet deletion-eligible): %d\n", summary.PurgeEligible)
	fmt.Fprintf(a.out, "\nFilter training: spam %d/%d, ham %d/%d\n",
		trainedSpam, qualification.MinLearns, trainedHam, qualification.MinLearns)
	fmt.Fprintf(a.out, "Errors detected through your corrections (30 days): ham marked spam %d, spam marked ham %d\n",
		falseSpam, falseHam)

	fmt.Fprintln(a.out, "\nNext action:")
	current := summary
	if _, errorCount, outcomeErr := db.LatestLiveRunOutcome(context.Background()); outcomeErr == nil {
		current.Errors = errorCount
	}
	for _, advice := range statusAdvice(current, trainedSpam, trainedHam, qualification.MinLearns, qualification.MinLearns) {
		fmt.Fprintf(a.out, "  • %s\n", advice)
	}
	fmt.Fprintf(a.out, "\nApplication data: %s\nBackup archive: %s\n", cfg.Runtime.DataDir, cfg.Runtime.ArchiveDir)
	if runtime.GOOS == "linux" {
		fmt.Fprintf(a.out, "Linux instance: %s (%s)\n", linuxInstance(cfg), cfg.InstanceID)
		value, err := db.GetSetting(context.Background(), modelCheckpointRequired)
		if err != nil {
			return err
		}
		if value != "" {
			return errors.New("model checkpoint is required; mailbox changes remain blocked until a verified checkpoint succeeds")
		}
	}
	return nil
}

func statusAdvice(summary store.Summary, trainedSpam, trainedHam, minSpam, minHam int) []string {
	var advice []string
	if summary.PendingMoves > 0 {
		advice = append(advice, "Choose Check mailbox now in the menu to finish reconciling moves.")
	}
	if summary.Errors > 0 {
		advice = append(advice, "Choose Check and repair in the menu; failed operations did not delete mail.")
	}
	if summary.WaitingReview > 0 {
		advice = append(advice, fmt.Sprintf(
			"Review the configured review folder — %d messages are waiting.",
			summary.WaitingReview,
		))
	}
	if trainedSpam < minSpam || trainedHam < minHam {
		advice = append(advice, "Correct classifications using the configured spam-training and ham-training folders.")
	}
	if len(advice) == 0 {
		advice = append(advice, "No action required. Guardian is working correctly.")
	}
	return advice
}

func (a *application) purgeCommand(args []string) error {
	if len(args) > 0 && (args[0] == "enable" || args[0] == "disable") {
		return a.setPurge(args[0] == "enable")
	}
	fs := flag.NewFlagSet("purge", flag.ContinueOnError)
	fs.SetOutput(a.errOut)
	dryRun := fs.Bool("dry-run", false, "preview without deleting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("purge command accepts no extra text")
	}
	if !*dryRun {
		ok, err := a.confirmDanger("This can permanently delete only spam older than 30 days.", "USUN")
		if err != nil {
			return err
		}
		if !ok {
			return apperror.ErrCancelled
		}
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return fmt.Errorf("%w\nOpen the menu and start first-time setup", err)
	}
	lock, err := acquireRunLock(cfg.Runtime.DataDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	rt, cleanup, err := a.openRuntime(true)
	if err != nil {
		return err
	}
	defer cleanup()
	if rolledBack, continuityErr := a.ensureBayesContinuity(context.Background(), rt); continuityErr != nil {
		return continuityErr
	} else if rolledBack {
		return apperror.Wrap(apperror.BayesRollback, "critical",
			"The local Bayes model rolled back; purge was disabled.",
			"Remain in protect mode and collect confirmed examples again.", nil)
	}
	run, err := rt.engine.Purge(rt.ctx, *dryRun)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Messages meeting all requirements: %d; safely skipped due to error or safeguard: %d\n", run.Purged, run.Errors)
	return nil
}

func (a *application) setPurge(enable bool) error {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	lock, err := acquireRunLock(cfg.Runtime.DataDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	if !enable {
		cfg.Safety.PurgeEnabled = false
		if err := config.Save(a.configPath, cfg); err != nil {
			return err
		}
		a.success("Permanent deletion is disabled.")
		return nil
	}
	if cfg.Safety.Mode != "active" {
		return errors.New("complete protect mode and enable active mode first")
	}
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.RequireConfiguration(context.Background(), cfg); err != nil {
		return err
	}
	activeValue, _ := db.GetSetting(context.Background(), "active_since")
	activeAt, _ := time.Parse(time.RFC3339, activeValue)
	if activeAt.IsZero() || time.Since(activeAt) < 30*24*time.Hour {
		return errors.New("active mode has not run for 30 full days; permanent deletion remains disabled")
	}
	trainedSpam, trainedHam, err := db.TrainingTotals(context.Background(), cfg.Account.Email)
	if err != nil {
		return err
	}
	if trainedSpam < cfg.Safety.MinLearnSpam || trainedHam < cfg.Safety.MinLearnHam {
		return fmt.Errorf(
			"insufficient confirmed examples: spam %d/%d, ham %d/%d; permanent deletion remains disabled",
			trainedSpam, cfg.Safety.MinLearnSpam, trainedHam, cfg.Safety.MinLearnHam,
		)
	}
	falseSpam, falseHam, err := db.MisclassificationsSince(context.Background(), cfg.Account.Email, time.Now().Add(-30*24*time.Hour))
	if err != nil {
		return err
	}
	if falseSpam > 0 || falseHam > 0 {
		return fmt.Errorf(
			"conflicting corrections in the last 30 days (ham→spam: %d, spam→ham: %d); permanent deletion remains disabled",
			falseSpam, falseHam,
		)
	}
	ok, err := a.confirmDanger("Guardian will permanently delete reconfirmed spam after 30 days in quarantine.", "ENABLE")
	if err != nil || !ok {
		return apperror.ErrCancelled
	}
	cfg.Safety.PurgeEnabled = true
	if err := config.Save(a.configPath, cfg); err != nil {
		return err
	}
	a.success("Permanent deletion after 30 days is enabled. Every deletion still requires an encrypted backup, matching checksum and a fresh spam verdict.")
	return nil
}

func (a *application) modeCommand(args []string) error {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "status" {
		fmt.Fprintf(a.out, "Mode: %s; permanent deletion: %s\n", modeName(cfg.Safety.Mode), yesNo(cfg.Safety.PurgeEnabled))
		return nil
	}
	lock, err := acquireRunLock(cfg.Runtime.DataDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	switch args[0] {
	case "protect":
		if cfg.Safety.Mode == "protect" {
			a.info("Protect mode is already enabled. The current observation period was not reset.")
			return nil
		}
		cfg.Safety.Mode = "protect"
		cfg.Safety.PurgeEnabled = false
		if err := config.Save(a.configPath, cfg); err != nil {
			return err
		}
		db, err := store.Open(cfg.Runtime.Database)
		if err != nil {
			return fmt.Errorf("protect mode enabled, but active-mode clock could not be reset: %w", err)
		}
		defer db.Close()
		if err := db.SetSetting(context.Background(), "active_since", ""); err != nil {
			return fmt.Errorf("protect mode enabled, but active-mode clock could not be reset: %w", err)
		}
		if err := db.SetSetting(context.Background(), "protect_since", time.Now().UTC().Format(time.RFC3339)); err != nil {
			return fmt.Errorf("protect mode enabled, but a new observation period could not be started: %w", err)
		}
		a.success("Protect mode enabled. Inbox messages will not be moved automatically.")
		return nil
	case "active":
		if cfg.Safety.Mode == "active" {
			a.info("Active mode is already enabled. The permanent-deletion safety clock is unchanged.")
			return nil
		}
		db, err := store.Open(cfg.Runtime.Database)
		if err != nil {
			return err
		}
		defer db.Close()
		ctx := context.Background()
		if err := db.RequireConfiguration(ctx, cfg); err != nil {
			return err
		}
		installedValue, err := db.GetSetting(ctx, "installed_at")
		if err != nil {
			return fmt.Errorf("cannot check protection-period start: %w", err)
		}
		installedAt, err := time.Parse(time.RFC3339, installedValue)
		if err != nil {
			return errors.New("no valid protection-period start date; run guardian setup to repair configuration")
		}
		protectAt := installedAt
		protectValue, err := db.GetSetting(ctx, "protect_since")
		if err != nil {
			return fmt.Errorf("cannot check current protection-period start: %w", err)
		}
		if protectValue != "" {
			protectAt, err = time.Parse(time.RFC3339, protectValue)
			if err != nil || protectAt.Before(installedAt) {
				return errors.New("invalid current protection-period date; run guardian setup")
			}
		}
		protectDuration := time.Duration(cfg.Safety.ProtectDays) * 24 * time.Hour
		if elapsed := time.Since(protectAt); elapsed < protectDuration {
			remaining := protectDuration - elapsed
			remainingDays := int((remaining + 24*time.Hour - 1) / (24 * time.Hour))
			return fmt.Errorf(
				"active mode is still blocked for safety: protection period is %d days; retry in about %d days",
				cfg.Safety.ProtectDays, remainingDays,
			)
		}
		qualified, err := db.CurrentQualification(ctx, cfg, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("current filter evaluation: %w", err)
		}
		quality, err := db.ActivationQuality(ctx, cfg.Account.Email, protectAt)
		if err != nil {
			return fmt.Errorf("cannot evaluate earlier decision quality: %w", err)
		}
		if qualified == nil {
			if cfg.Rspamd.SpamScore < 12 {
				return errors.New("threshold below 12 requires independent evaluation: guardian qualify")
			}
			if err := activationQualityProblem(quality); err != nil {
				return err
			}
		}
		ok, err := a.confirmDanger("Active mode will start moving confident spam from Inbox to reversible quarantine.", "AKTYWUJ")
		if err != nil || !ok {
			return apperror.ErrCancelled
		}
		cfg.Safety.Mode = "active"
		cfg.Safety.PurgeEnabled = false
		if err := db.SetSetting(ctx, "active_since", time.Now().UTC().Format(time.RFC3339)); err != nil {
			return fmt.Errorf("could not start safety clock; active mode remains disabled: %w", err)
		}
		if err := config.Save(a.configPath, cfg); err != nil {
			_ = db.SetSetting(ctx, "active_since", "")
			return err
		}
		a.success("Active mode enabled. Permanent deletion remains disabled.")
		return nil
	default:
		return errors.New("use: guardian mode status|protect|active")
	}
}

func (a *application) archiveCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("use: guardian archive list or guardian archive restore ID")
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("archive list", flag.ContinueOnError)
		fs.SetOutput(a.errOut)
		page := fs.Int("page", 1, "page number")
		limit := fs.Int("limit", 100, "entries per page")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("use: guardian archive list [--page N] [--limit N]")
		}
		if *page < 1 || *page > 1_000_000 {
			return errors.New("page number must be between 1 and 1000000")
		}
		if *limit < 1 || *limit > 200 {
			return errors.New("page size must be between 1 and 200")
		}
		db, err := store.Open(cfg.Runtime.Database)
		if err != nil {
			return err
		}
		defer db.Close()
		offset := (*page - 1) * *limit
		items, err := db.ArchivedPage(context.Background(), cfg.Account.Email, *limit, offset)
		if err != nil {
			return err
		}
		a.header(fmt.Sprintf("Encrypted backups — page %d", *page))
		if len(items) == 0 {
			if *page == 1 {
				fmt.Fprintln(a.out, "No backups.")
			} else {
				fmt.Fprintln(a.out, "No more backups on this page. Return to the previous page.")
			}
			return nil
		}
		fmt.Fprintln(a.out, "ID    date                 verdict       status")
		for _, item := range items {
			fmt.Fprintf(a.out, "%-5d %-20s %-13s %s\n", item.ID, item.FirstSeen.Local().Format("2006-01-02 15:04"), item.Verdict, item.Status)
		}
		fmt.Fprintln(a.out, "\nTo identify a message: guardian archive show ID")
		fmt.Fprintln(a.out, "To recover: guardian archive restore ID")
		if len(items) == *limit {
			fmt.Fprintf(a.out, "Next page: guardian archive list --page %d --limit %d\n", *page+1, *limit)
		}
		return nil
	case "show":
		if len(args) != 2 {
			return errors.New("provide ID, e.g. guardian archive show 12")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil || id < 1 {
			return errors.New("ID must be a positive integer")
		}
		db, err := store.Open(cfg.Runtime.Database)
		if err != nil {
			return err
		}
		defer db.Close()
		record, err := db.MessageByID(context.Background(), id)
		if err != nil {
			return fmt.Errorf("backup ID %d not found: %w", id, err)
		}
		if record.Account != cfg.Account.Email {
			return errors.New("this backup belongs to another account")
		}
		if record.ArchivePath == "" {
			return errors.New("local backup of this message expired or was never created")
		}
		kc := runtimeSecrets(cfg)
		identity, err := archive.LoadIdentity(kc, cfg.Runtime.ArchiveKeychainService, cfg.Account.Email)
		if err != nil {
			return fmt.Errorf("cannot open encrypted-backup key: %w", err)
		}
		archiver, err := archive.New(cfg.Runtime.ArchiveDir, identity)
		if err != nil {
			return err
		}
		raw, err := archiver.Read(record.ArchivePath)
		if err != nil {
			return err
		}
		if archive.SHA256(raw) != record.RawSHA256 {
			return errors.New("decrypted backup checksum mismatch")
		}
		preview, err := parseArchiveHeaderPreview(raw)
		if err != nil {
			return fmt.Errorf("backup remains recoverable, but its headers are damaged: %w", err)
		}
		a.header(fmt.Sprintf("Preview backup ID %d", id))
		fmt.Fprintf(a.out, "From:    %s\nSubject: %s\nDate:    %s\n", preview.From, preview.Subject, preview.Date)
		fmt.Fprintln(a.out, "\nOnly sanitized headers are shown. Message body, HTML, links and attachments were not opened.")
		return nil
	case "restore":
		if len(args) != 2 {
			return errors.New("provide ID, e.g. guardian archive restore 12")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil || id < 1 {
			return errors.New("ID must be a positive integer")
		}
		ok, err := a.confirm("Restore the backup to the configured review folder as unread?", true)
		if err != nil || !ok {
			return apperror.ErrCancelled
		}
		lock, err := acquireRunLock(cfg.Runtime.DataDir)
		if err != nil {
			return err
		}
		defer lock.Close()
		rt, cleanup, err := a.openRuntime(true)
		if err != nil {
			return err
		}
		defer cleanup()
		if runtime.GOOS == "linux" {
			if err := a.prepareLinuxMutation(rt); err != nil {
				return err
			}
		}
		restoreErr := rt.engine.Restore(rt.ctx, id)
		if runtime.GOOS == "linux" {
			if checkpointErr := a.finishLinuxMutation(rt); checkpointErr != nil {
				return errors.Join(restoreErr, checkpointErr)
			}
		}
		if err := restoreErr; err != nil {
			if errors.Is(err, engine.ErrRestoreAlreadyPresent) {
				a.info("The message still exists in its recorded folder. No unnecessary duplicate created.")
				return nil
			}
			return err
		}
		a.success("Message recovered to the configured review folder. Nothing was sent.")
		return nil
	default:
		return errors.New("use: guardian archive list or guardian archive restore ID")
	}
}

func (a *application) serviceCommand(args []string) error {
	if len(args) != 1 {
		return errors.New("use: guardian service install|status|uninstall")
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	manager := service.Manager{Executable: exe, DataDir: cfg.Runtime.DataDir, LogFile: cfg.Runtime.LogFile}
	switch args[0] {
	case "install":
		authorized, err := dryRunAuthorized(cfg)
		if err != nil {
			return fmt.Errorf("checking dry-run authorization: %w", err)
		}
		if !authorized {
			return errors.New("first complete guardian run --dry-run successfully; automation remains off")
		}
		if err := manager.Install(); err != nil {
			return err
		}
		a.success("Automatic checks every 2 hours are active.")
	case "status":
		status, err := manager.Status()
		if err != nil {
			return err
		}
		if strings.Contains(status, "state = running") {
			a.success("The service is running now.")
		} else {
			a.success("The service is installed and waiting for the next run.")
		}
	case "uninstall":
		if err := manager.Uninstall(); err != nil {
			return err
		}
		a.success("Autostart disabled. Messages and data are unchanged.")
	default:
		return errors.New("use: guardian service install|status|uninstall")
	}
	return nil
}

func dryRunAuthorized(cfg config.Config) (bool, error) {
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		return false, err
	}
	defer db.Close()
	return db.DryRunAuthorizedFor(context.Background(), cfg)
}

func (a *application) stackCommand(args []string) error {
	if len(args) != 1 {
		return errors.New("use: guardian stack up|status|down")
	}
	cfg := config.Default()
	if loaded, err := config.Load(a.configPath); err == nil {
		cfg = loaded
	} else if runtime.GOOS == "linux" {
		return err
	}
	manager := runtimeStack(cfg)
	if runtime.GOOS == "linux" && (args[0] == "up" || args[0] == "down") {
		lock, err := acquireRunLock(cfg.Runtime.DataDir)
		if err != nil {
			return err
		}
		defer lock.Close()
	}
	switch args[0] {
	case "up":
		if err := manager.Up(); err != nil {
			return err
		}
		a.success("The local engine works.")
	case "status":
		value, err := manager.Status()
		if err != nil {
			return err
		}
		fmt.Fprint(a.out, value)
	case "down":
		if err := manager.Down(); err != nil {
			return err
		}
		a.success("Engine stopped. Bayes data retained.")
	default:
		return errors.New("use: guardian stack up|status|down")
	}
	return nil
}

// repair performs reversible local repairs without changing protection
// mode, enabling permanent deletion or moving messages.
func (a *application) repair() error {
	a.header("Check and repair")
	fmt.Fprintln(a.out, "This check does not move or delete messages or change protection mode.")

	cfg, err := config.Load(a.configPath)
	if err != nil {
		return fmt.Errorf("application not configured yet: %w\nOpen the menu and choose Start first-time setup", err)
	}
	lock, err := acquireRunLock(cfg.Runtime.DataDir)
	if err != nil {
		return err
	}
	defer lock.Close()

	a.info("Step 1 of 3: starting the local spam filter…")
	startFilter := a.startFilter
	if startFilter == nil {
		startFilter = func(cfg config.Config) error {
			return (stack.Manager{
				ComposeFile: cfg.Runtime.ComposeFile,
				RuntimeDir:  config.DefaultRuntimeDir(),
			}).Up()
		}
	}
	if err := startFilter(cfg); err != nil {
		return fmt.Errorf(
			"could not start local filter: %w\nAutomation and safety settings unchanged",
			err,
		)
	}
	a.success("The local filter is running.")

	a.info("Step 2 of 3: checking encryption, backups, filter and IMAP connection…")
	checkInstallation := a.checkInstallation
	if checkInstallation == nil {
		checkInstallation = func() error { return a.doctor(false, false) }
	}
	if err := checkInstallation(); err != nil {
		return fmt.Errorf(
			"check failed: %w\nAutomation and safety settings are unchanged",
			err,
		)
	}
	// Bootstrap may start a run immediately; release the repair lock first.
	if err := lock.Close(); err != nil {
		return fmt.Errorf("checks passed, but the application lock could not be safely released; automation unchanged: %w", err)
	}

	a.info("Step 3 of 3: checking automatic startup…")
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate executable; automation unchanged: %w", err)
	}
	manager := service.Manager{Executable: exe, DataDir: cfg.Runtime.DataDir, LogFile: cfg.Runtime.LogFile}
	dryRunReady, err := dryRunAuthorized(cfg)
	if err != nil {
		return fmt.Errorf("cannot confirm required dry-run: %w", err)
	}
	if !dryRunReady {
		disableAutomation := a.disableAutomation
		if disableAutomation == nil {
			disableAutomation = func(config.Config) error { return manager.Uninstall() }
		}
		if err := disableAutomation(cfg); err != nil {
			return fmt.Errorf("a new dry-run is required, but automation could not be stopped: %w", err)
		}
		a.warning("Automation remains off because a new safe dry-run is required.")
		a.success("Other checks and repairs completed successfully.")
		return nil
	}
	automationStatus := a.automationStatus
	if automationStatus == nil {
		automationStatus = func(config.Config) error {
			_, statusErr := manager.Status()
			return statusErr
		}
	}
	enableAutomation := a.enableAutomation
	if enableAutomation == nil {
		enableAutomation = func(config.Config) error { return manager.Install() }
	}
	if err := automationStatus(cfg); err == nil {
		a.info("Automatic checks are active. Refreshing launch files and safeguards…")
		if err := enableAutomation(cfg); err != nil {
			return fmt.Errorf("checks passed, but automation could not be safely refreshed: %w", err)
		}
		a.success("Automatic checks every 2 hours are active and refreshed.")
		a.success("The application works correctly. No further action required.")
		return nil
	}

	a.warning("Automatic checks every 2 hours are inactive.")
	if !a.interactive {
		a.info("Manual mode retained. Enable automation separately after repair completes.")
		a.success("Other checks completed successfully.")
		return nil
	}
	ok, err := a.confirm("Enable it now?", true)
	if err != nil {
		return fmt.Errorf("automation remains off: %w", err)
	}
	if !ok {
		a.info("Automation remains off as requested.")
		a.success("Other checks completed successfully.")
		return nil
	}
	if err := enableAutomation(cfg); err != nil {
		return fmt.Errorf("checks passed, but automation could not be enabled: %w", err)
	}
	a.success("Automatic checks every 2 hours enabled.")
	a.success("The application works correctly. No further action required.")
	return nil
}

func (a *application) menu() error {
	for {
		cfg, cfgErr := config.Load(a.configPath)
		a.header("Menu")
		if cfgErr != nil {
			fmt.Fprintln(a.out, "Guardian is waiting for first-time setup. No messages were changed.")
			fmt.Fprintln(a.out, "\n  1. Start first-time setup\n  0. Quit")
			choice, err := a.ask("Choose a number", "")
			if err != nil {
				return err
			}
			switch choice {
			case "1":
				if actionErr := a.setup(); actionErr != nil {
					a.problemWithAdvice(actionErr)
				}
				_, _ = a.ask("Press Enter to return to the menu", "")
			case "0", "q", "Q":
				return nil
			default:
				a.warning("Enter 1 to start or 0 to quit.")
			}
			continue
		}

		fmt.Fprintf(a.out, "Mode: %s | permanent deletion: %s\n", modeName(cfg.Safety.Mode), yesNo(cfg.Safety.PurgeEnabled))
		fmt.Fprintln(a.out, "\n  1. Check mailbox now\n  2. Show status and recommendations\n  3. Check and repair\n  4. Correct a classification\n  5. Recover a message from backup\n  6. Settings and advanced options\n  0. Quit")
		choice, err := a.ask("Choose a number", "")
		if err != nil {
			return err
		}
		var actionErr error
		switch choice {
		case "1":
			actionErr = a.runCommand(nil)
		case "2":
			actionErr = a.statusCommand([]string{"--since", "24h"})
		case "3":
			actionErr = a.repair()
		case "4":
			a.trainingInstructions()
		case "5":
			actionErr = a.archiveMenu()
		case "6":
			actionErr = a.optionsMenu(cfg)
		case "0", "q", "Q":
			return nil
		default:
			a.warning("No such option. Enter a number from 0 to 6.")
		}
		if actionErr != nil {
			a.problemWithAdvice(actionErr)
		}
		_, _ = a.ask("Press Enter to return to the menu", "")
	}
}

func (a *application) optionsMenu(cfg config.Config) error {
	fmt.Fprintln(a.out, "\n  1. Protection mode settings\n  2. Dry-run without moving messages\n  3. Update account configuration\n  4. Show local filter technical status\n  0. Back to main menu")
	value, err := a.ask("Choose a number", "")
	if err != nil {
		return err
	}
	switch value {
	case "1":
		return a.modeMenu(cfg, nil)
	case "2":
		return a.runCommand([]string{"--dry-run"})
	case "3":
		return a.setup()
	case "4":
		return a.stackCommand([]string{"status"})
	case "0", "":
		return nil
	default:
		return errors.New("no such option; choose a number from 0 to 4")
	}
}

func (a *application) modeMenu(cfg config.Config, cfgErr error) error {
	if cfgErr != nil {
		return cfgErr
	}
	fmt.Fprintln(a.out, "\n  1. Enable protect mode (safest)\n  2. Enable active mode\n  3. Enable permanent deletion after 30 days\n  4. Disable permanent deletion\n  0. Back without changes")
	value, err := a.ask("Choose a number", "")
	if err != nil {
		return err
	}
	switch value {
	case "1":
		return a.modeCommand([]string{"protect"})
	case "2":
		return a.modeCommand([]string{"active"})
	case "3":
		return a.setPurge(true)
	case "4":
		return a.setPurge(false)
	case "0", "":
		return nil
	default:
		return errors.New("no such option; choose a number from 0 to 4")
	}
}

func (a *application) archiveMenu() error {
	for page := 1; ; page++ {
		if err := a.archiveCommand([]string{"list", "--page", strconv.Itoa(page), "--limit", "100"}); err != nil {
			return err
		}
		value, err := a.ask("Enter an ID, N for the next page, or Enter to return", "")
		if err != nil || value == "" {
			return err
		}
		if strings.EqualFold(strings.TrimSpace(value), "n") {
			continue
		}
		if err := a.archiveCommand([]string{"show", value}); err != nil {
			return err
		}
		return a.archiveCommand([]string{"restore", value})
	}
}

type archiveHeaderPreview struct {
	From    string `json:"from"`
	Subject string `json:"subject"`
	Date    string `json:"date"`
}

func parseArchiveHeaderPreview(raw []byte) (archiveHeaderPreview, error) {
	message, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return archiveHeaderPreview{}, err
	}
	decode := func(value string) string {
		const maxHeaderInput = 16 << 10
		if len(value) > maxHeaderInput {
			value = value[:maxHeaderInput]
		}
		decoded, decodeErr := (&mime.WordDecoder{}).DecodeHeader(value)
		if decodeErr == nil {
			value = decoded
		}
		value = sanitizeHeaderForTerminal(value, 180)
		if value == "" {
			return "(none)"
		}
		return value
	}
	date := decode(message.Header.Get("Date"))
	if parsed, dateErr := message.Header.Date(); dateErr == nil {
		date = parsed.Local().Format("2006-01-02 15:04 MST")
	}
	return archiveHeaderPreview{
		From:    decode(message.Header.Get("From")),
		Subject: decode(message.Header.Get("Subject")),
		Date:    date,
	}, nil
}

func sanitizeHeaderForTerminal(value string, limit int) string {
	value = stripTerminalEscapeSequences(value)
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if limit > 0 && len(runes) > limit {
		value = string(runes[:limit]) + "…"
	}
	return value
}

func stripTerminalEscapeSequences(value string) string {
	runes := []rune(value)
	var clean strings.Builder
	for i := 0; i < len(runes); {
		switch runes[i] {
		case '\x1b':
			if i+1 >= len(runes) {
				i++
				continue
			}
			switch runes[i+1] {
			case '[':
				i = skipControlSequence(runes, i+2)
			case ']', 'P', 'X', '^', '_':
				i = skipStringControl(runes, i+2)
			default:
				// ANSI two-character escape sequence.
				i += 2
			}
		case '\u009b':
			i = skipControlSequence(runes, i+1)
		case '\u0090', '\u0098', '\u009d', '\u009e', '\u009f':
			i = skipStringControl(runes, i+1)
		default:
			clean.WriteRune(runes[i])
			i++
		}
	}
	return clean.String()
}

func skipControlSequence(runes []rune, i int) int {
	for i < len(runes) {
		r := runes[i]
		i++
		if r >= 0x40 && r <= 0x7e {
			break
		}
	}
	return i
}

func skipStringControl(runes []rune, i int) int {
	for i < len(runes) {
		switch runes[i] {
		case '\a', '\u009c':
			return i + 1
		case '\x1b':
			if i+1 < len(runes) && runes[i+1] == '\\' {
				return i + 2
			}
		}
		i++
	}
	return i
}

func (a *application) trainingInstructions() {
	fmt.Fprintln(a.out, "\nTo correct a classification, move the message in your email client to the configured spam-training or ham-training folder. Guardian learns from it on the next run and moves it to the appropriate destination. You do not need to open the message or follow any links. See your configuration for the exact folder names.")
}

func (a *application) openRuntime(withMail bool) (*runtimeApp, func(), error) {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return nil, func() {}, apperror.Wrap(apperror.Config, "critical", "Guardian configuration is unreadable.", "Open the application and start setup or use Repair.", err)
	}
	if err := os.MkdirAll(cfg.Runtime.DataDir, 0o700); err != nil {
		return nil, func() {}, err
	}
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { _ = db.Close() }
	if err := db.BindConfiguration(context.Background(), cfg, time.Now()); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	if runtime.GOOS == "linux" {
		if err := bindLinuxDeployment(context.Background(), &runtimeApp{cfg: cfg, db: db}); err != nil {
			cleanup()
			return nil, func() {}, err
		}
	}
	kc := runtimeSecrets(cfg)
	controller, err := kc.Get(cfg.Rspamd.PasswordKeychainService, "controller")
	if err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("cannot read Rspamd controller secret: %w", err)
	}
	scanner := rspamd.New(cfg.Rspamd.ScanURL, cfg.Rspamd.LearnURL, controller, time.Duration(cfg.Rspamd.TimeoutSeconds)*time.Second)
	id, err := archive.LoadIdentity(kc, cfg.Runtime.ArchiveKeychainService, cfg.Account.Email)
	if err != nil {
		cleanup()
		return nil, func() {}, apperror.Wrap(apperror.ArchiveKey, "critical", "Cannot read the encrypted-backup key.", "Do not delete the archive; unlock Keychain and run Repair.", err)
	}
	archiver, err := archive.New(cfg.Runtime.ArchiveDir, id)
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	rt := &runtimeApp{ctx: context.Background(), cfg: cfg, db: db, scanner: scanner, archive: archiver}
	if withMail {
		password, err := kc.Get(cfg.Account.PasswordKeychainService, cfg.Account.Email)
		if err != nil {
			cleanup()
			return nil, func() {}, apperror.Wrap(apperror.Keychain, "critical", "Cannot read the IMAP password from Keychain.", "Unlock Keychain or save the account/app password again.", err)
		}
		// Command deadlines belong to the IMAP client. Healthy sessions may
		// outlive ten minutes; interruption or a failed command cancels the same
		// context passed to the engine, stopping before the next message.
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		mail, err := dialMailbox(ctx, cfg, password)
		if err != nil {
			cancel()
			cleanup()
			return nil, func() {}, err
		}
		rt.mail = mail
		rt.ctx = mail.Context()
		previous := cleanup
		cleanup = func() {
			_ = mail.Close()
			cancel()
			previous()
		}
	}
	rt.engine = &engine.Engine{
		Config: cfg, Mail: rt.mail, Rspamd: scanner, Store: db, Archive: archiver,
		Now: time.Now, Report: a.report,
	}
	return rt, cleanup, nil
}

func (a *application) ensureBayesContinuity(ctx context.Context, rt *runtimeApp) (bool, error) {
	stats, err := rt.scanner.Stats(ctx)
	if err != nil {
		if rt.cfg.Safety.Mode == "active" || rt.cfg.Safety.PurgeEnabled {
			return false, apperror.Wrap(
				apperror.Rspamd, "critical", "Cannot confirm continuity of the local Bayes model.",
				"Run Repair before Guardian makes automatic decisions.", err,
			)
		}
		return false, nil
	}
	readRevision := func(key string) (uint64, bool, error) {
		value, err := rt.db.GetSetting(ctx, key)
		if err != nil {
			return 0, false, err
		}
		if value == "" {
			return 0, false, nil
		}
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return 0, true, fmt.Errorf("invalid counter %s", key)
		}
		return parsed, true, nil
	}
	previousSpam, spamKnown, err := readRevision("bayes_spam_revision_highwater")
	if err != nil {
		return false, err
	}
	previousHam, hamKnown, err := readRevision("bayes_ham_revision_highwater")
	if err != nil {
		return false, err
	}
	regressed := (spamKnown && stats.SpamRevision < previousSpam) ||
		(hamKnown && stats.HamRevision < previousHam)
	highestSpam, highestHam := stats.SpamRevision, stats.HamRevision
	if spamKnown && previousSpam > highestSpam {
		highestSpam = previousSpam
	}
	if hamKnown && previousHam > highestHam {
		highestHam = previousHam
	}
	if !spamKnown || !hamKnown {
		trainedSpam, trainedHam, totalsErr := rt.db.TrainingTotals(ctx, rt.cfg.Account.Email)
		if totalsErr != nil {
			return false, totalsErr
		}
		regressed = regressed || stats.SpamRevision < uint64(trainedSpam) || stats.HamRevision < uint64(trainedHam)
		if uint64(trainedSpam) > highestSpam {
			highestSpam = uint64(trainedSpam)
		}
		if uint64(trainedHam) > highestHam {
			highestHam = uint64(trainedHam)
		}
	}
	if err := rt.db.SetSetting(ctx, "bayes_spam_revision_highwater", strconv.FormatUint(highestSpam, 10)); err != nil {
		return false, err
	}
	if err := rt.db.SetSetting(ctx, "bayes_ham_revision_highwater", strconv.FormatUint(highestHam, 10)); err != nil {
		return false, err
	}
	if !regressed {
		if err := rt.db.SetSetting(ctx, "bayes_rollback_at", ""); err != nil {
			return false, err
		}
		return false, nil
	}
	wasUnsafe := rt.cfg.Safety.Mode == "active" || rt.cfg.Safety.PurgeEnabled
	previousRollback, err := rt.db.GetSetting(ctx, "bayes_rollback_at")
	if err != nil {
		return false, err
	}
	rt.cfg.Safety.Mode = "protect"
	rt.cfg.Safety.PurgeEnabled = false
	rt.engine.Config = rt.cfg
	if err := config.Save(a.configPath, rt.cfg); err != nil {
		return false, err
	}
	if wasUnsafe || previousRollback == "" {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if err := rt.db.SetSetting(ctx, "protect_since", now); err != nil {
			return false, err
		}
		if err := rt.db.SetSetting(ctx, "active_since", ""); err != nil {
			return false, err
		}
	}
	if previousRollback == "" {
		if err := rt.db.SetSetting(ctx, "bayes_rollback_at", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (a *application) maybeNotify(db *store.DB) {
	if runtime.GOOS != "darwin" && a.sendNotification == nil {
		return
	}
	ctx := context.Background()
	value, _ := db.GetSetting(ctx, "last_notification")
	last, _ := time.Parse(time.RFC3339, value)
	if !last.IsZero() && time.Since(last) < 24*time.Hour {
		return
	}
	since := time.Now().Add(-24 * time.Hour)
	if !last.IsZero() && last.Before(time.Now()) {
		since = last
	}
	summary, err := db.Summary(ctx, since)
	if err != nil {
		a.warning("Could not prepare the daily notification: " + err.Error())
		return
	}
	message := fmt.Sprintf("Rescued: %d, quarantined: %d, review: %d, errors: %d",
		summary.Rescued, summary.Quarantined, summary.WaitingReview, summary.Errors)
	if err := a.notify("Mail Guardian", message); err != nil {
		a.warning("Could not display the daily notification.")
		return
	}
	_ = db.SetSetting(ctx, "last_notification", time.Now().UTC().Format(time.RFC3339))
}

func (a *application) maybeNotifyRunFailure(db *store.DB) {
	if runtime.GOOS != "darwin" && a.sendNotification == nil {
		return
	}
	if a.interactive || db == nil {
		return
	}
	ctx := context.Background()
	value, _ := db.GetSetting(ctx, "last_failure_notification")
	last, _ := time.Parse(time.RFC3339, value)
	if !last.IsZero() && time.Since(last) >= 0 && time.Since(last) < 12*time.Hour {
		return
	}
	if err := a.notify(
		"Mail Guardian needs attention",
		"The automatic check failed. Mail was not deleted. Open Guardian and choose Check and repair.",
	); err != nil {
		a.warning("Could not display the problem notification.")
		return
	}
	if err := db.SetSetting(ctx, "last_failure_notification", time.Now().UTC().Format(time.RFC3339)); err != nil {
		a.warning("Could not save the problem-notification timestamp.")
	}
}

func (a *application) notify(title, message string) error {
	if a.sendNotification != nil {
		return a.sendNotification(title, message)
	}
	escapeAppleScript := func(value string) string {
		value = strings.ReplaceAll(value, `\`, `\\`)
		return strings.ReplaceAll(value, `"`, `\"`)
	}
	script := `display notification "` + escapeAppleScript(message) + `" with title "` + escapeAppleScript(title) + `"`
	return exec.Command("/usr/bin/osascript", "-e", script).Run()
}

func (a *application) printRun(run *store.Run) {
	fmt.Fprintln(a.out, "\nSummary:")
	fmt.Fprintf(a.out, "  Sprawdzone:      %d\n", run.Scanned)
	fmt.Fprintf(a.out, "  Rescued:         %d\n", run.Rescued)
	fmt.Fprintf(a.out, "  Quarantined:     %d\n", run.Quarantined)
	fmt.Fprintf(a.out, "  Review:          %d\n", run.Review)
	fmt.Fprintf(a.out, "  Learned spam/ham: %d/%d\n", run.LearnedSpam, run.LearnedHam)
	fmt.Fprintf(a.out, "  Errors without mail loss: %d\n", run.Errors)
	if run.Errors > 0 {
		a.warning("Some messages could not be checked. They remain safe on the server; choose Check and repair in the menu.")
	} else if run.Review > 0 {
		a.info("Check the configured review folder — messages await your decision.")
	} else {
		a.success("Check complete.")
	}
}

func (a *application) readHiddenPassword(question string) (string, error) {
	fmt.Fprintf(a.out, "%s (characters will be hidden): ", question)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(a.out)
		return "", errors.New("secure password entry requires an interactive Terminal; open Guardian.command and retry setup")
	}
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(a.out)
	if err != nil {
		return "", fmt.Errorf("cannot read password securely: %w", err)
	}
	password := strings.TrimSpace(string(value))
	if password == "" {
		return "", errors.New("account/app password must not be empty")
	}
	if strings.ContainsAny(password, "\r\n\x00") {
		return "", errors.New("invalid account/app password format")
	}
	return password, nil
}

func verifyAndStorePassword(password string, verify, storeSecret func(string) error) error {
	if password == "" {
		return errors.New("account/app password must not be empty")
	}
	if err := verify(password); err != nil {
		return fmt.Errorf("mail server rejected the new password or connection failed: %w", err)
	}
	if err := storeSecret(password); err != nil {
		return fmt.Errorf("password works, but could not be saved in Keychain: %w", err)
	}
	return nil
}

func isIMAPAuthenticationError(err error) bool {
	return errors.Is(err, imapmail.ErrAuthentication)
}

func (a *application) ask(question, defaultValue string) (string, error) {
	if defaultValue != "" {
		fmt.Fprintf(a.out, "%s [%s]: ", question, defaultValue)
	} else {
		fmt.Fprintf(a.out, "%s: ", question)
	}
	value, err := a.in.ReadString('\n')
	if errors.Is(err, io.EOF) && value == "" {
		return "", io.EOF
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		value = defaultValue
	}
	return value, nil
}

func (a *application) confirm(question string, defaultYes bool) (bool, error) {
	hint := "[Y/n]"
	if !defaultYes {
		hint = "[y/N]"
	}
	value, err := a.ask(question+" "+hint, "")
	if err != nil {
		return false, err
	}
	if value == "" {
		return defaultYes, nil
	}
	switch strings.ToLower(value) {
	case "t", "tak", "y", "yes":
		return true, nil
	case "n", "nie", "no":
		return false, nil
	default:
		return false, errors.New("answer yes or no")
	}
}

func (a *application) confirmDanger(message, phrase string) (bool, error) {
	fmt.Fprintf(a.out, "\n%s\nTo confirm, type exactly %s: ", message, phrase)
	value, err := a.in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	value = strings.TrimSpace(value)
	return value == phrase || (phrase == "ENABLE" && value == "WLACZ"), nil
}

func (a *application) header(title string) {
	fmt.Fprintf(a.out, "\n%s%sMail Guardian — %s%s\n", a.c(blue), a.c(bold), title, a.c(reset))
	fmt.Fprintln(a.out, "────────────────────────────────────────────")
}
func (a *application) info(message string) {
	fmt.Fprintf(a.out, "%s•%s %s\n", a.c(blue), a.c(reset), message)
}
func (a *application) success(message string) {
	fmt.Fprintf(a.out, "%s✓%s %s\n", a.c(green), a.c(reset), message)
}
func (a *application) warning(message string) {
	fmt.Fprintf(a.out, "%s!%s %s\n", a.c(yellow), a.c(reset), message)
}
func (a *application) problem(err error) {
	fmt.Fprintf(a.errOut, "%sError:%s %v\n", a.c(red), a.c(reset), err)
}
func (a *application) problemWithAdvice(err error) {
	userError := apperror.From(err)
	if userError.Severity == "info" {
		a.info(userError.Message + " " + userError.Recovery)
		return
	}
	a.problem(errors.New(userError.Message))
	if userError.Recovery != "" {
		a.info("What you can do: " + userError.Recovery)
	}
}
func (a *application) report(kind, message string) {
	switch kind {
	case "success":
		a.success(message)
	case "warning":
		a.warning(message)
	case "error":
		a.problem(errors.New(message))
	default:
		a.info(message)
	}
}
func (a *application) c(value string) string {
	if a.color {
		return value
	}
	return ""
}

func acquireRunLock(dataDir string) (*runlock.Lock, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot prepare private data directory: %w", err)
	}
	lock, err := runlock.Acquire(filepath.Join(dataDir, "guardian.lock"))
	if err != nil {
		return nil, apperror.Wrap(
			apperror.Busy, "attention", "Guardian is already performing another operation.",
			"Wait a few minutes and retry.", err,
		)
	}
	return lock, nil
}

func nonemptyFile(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", path)
	}
	return info.Size() > 0, nil
}

// validateNewArchiveIdentity prevents silent key rotation. A newly generated
// identity is safe only when there are no earlier encrypted copies and no
// existing state database that could refer to them.
func validateNewArchiveIdentity(archiveDir, database string) error {
	hasDependentData, err := archiveIdentityHasDependentData(archiveDir, database)
	if err != nil {
		return apperror.Wrap(
			apperror.ArchiveKey, "critical", "Cannot safely inspect existing Guardian data.",
			"Do not create a new key; run Repair and retain the database and archive.", err,
		)
	}
	if hasDependentData {
		return apperror.Wrap(
			apperror.ArchiveKey, "critical", "The previous encryption key is missing, but Guardian data already exists.",
			"Restore the archive key in Keychain. Guardian will not replace it with a new key.", nil,
		)
	}
	return nil
}

func archiveIdentityHasDependentData(archiveDir, database string) (bool, error) {
	hasEncryptedFiles, err := archive.HasEncryptedFiles(archiveDir)
	if err != nil {
		return false, fmt.Errorf("checking encrypted backups: %w", err)
	}
	hasDatabase, err := nonemptyFile(database)
	if err != nil {
		return false, fmt.Errorf("checking Guardian database: %w", err)
	}
	return hasEncryptedFiles || hasDatabase, nil
}

func rollbackNewArchiveIdentity(store secretStore, service, account, archiveDir, database string) error {
	hasDependentData, err := archiveIdentityHasDependentData(archiveDir, database)
	if err != nil {
		return fmt.Errorf("cannot confirm that new archive key is unnecessary; retained it: %w", err)
	}
	if hasDependentData {
		// A database may have been created just before a later setup step failed.
		// Keeping its matching key is safer than making that state unrecoverable.
		return nil
	}
	if err := store.Delete(service, account); err != nil && !errors.Is(err, keychain.ErrNotFound) {
		return err
	}
	return nil
}

func activationQualityProblem(quality store.ActivationQuality) error {
	var reasons []string
	if quality.FalsePositives > 0 {
		reasons = append(reasons, fmt.Sprintf(
			"%d legitimate messages previously received a confident spam verdict",
			quality.FalsePositives,
		))
	}
	if quality.FalseRescues > 0 {
		reasons = append(reasons, fmt.Sprintf(
			"%d messages later marked as spam were previously rescued automatically",
			quality.FalseRescues,
		))
	}
	if quality.SpamFeedback == 0 {
		reasons = append(reasons, "no messages have been marked in the configured spam-training folder")
	} else {
		percent := quality.SpamPreviouslySpam * 100 / quality.SpamFeedback
		if quality.SpamPreviouslySpam*100 < quality.SpamFeedback*90 {
			reasons = append(reasons, fmt.Sprintf(
				"only %d of %d marked messages were previously confident spam (%d%%); at least 90%% required",
				quality.SpamPreviouslySpam, quality.SpamFeedback, percent,
			))
		}
	}
	if quality.SpamUnexplained > 0 {
		reasons = append(reasons, fmt.Sprintf(
			"%d spam corrections had no earlier spam or manual-review verdict",
			quality.SpamUnexplained,
		))
	}
	if len(reasons) == 0 && !quality.Ready() {
		reasons = append(reasons, "collected results do not yet meet all safety requirements")
	}
	if len(reasons) == 0 {
		return nil
	}
	return errors.New(
		"active mode remains disabled because:\n  • " +
			strings.Join(reasons, "\n  • ") +
			"\nRemain in protect mode, correct classifications using the training folders, and retry after further observation",
	)
}

func modeName(mode string) string {
	if mode == "active" {
		return "active (quarantine)"
	}
	return "protect"
}
func yesNo(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}
func boolError(ok bool, message string) error {
	if ok {
		return nil
	}
	return errors.New(message)
}
func delimiterOf(boxes []imapmail.Mailbox) rune {
	for _, box := range boxes {
		if box.Delimiter != 0 {
			return box.Delimiter
		}
	}
	return 0
}

func freeBytes(path string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}
