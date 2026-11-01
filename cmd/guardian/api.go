package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/apperror"
	"github.com/xue9999/Mail-Guardian/internal/archive"
	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/engine"
	"github.com/xue9999/Mail-Guardian/internal/imapmail"
	"github.com/xue9999/Mail-Guardian/internal/keychain"
	"github.com/xue9999/Mail-Guardian/internal/qualification"
	"github.com/xue9999/Mail-Guardian/internal/secrets"
	"github.com/xue9999/Mail-Guardian/internal/service"
	"github.com/xue9999/Mail-Guardian/internal/store"
)

const apiProtocolVersion = 1

type apiEnvelope struct {
	Protocol int         `json:"protocol"`
	OK       bool        `json:"ok"`
	Data     any         `json:"data,omitempty"`
	Error    *apiFailure `json:"error,omitempty"`
}

type apiFailure struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Recovery string `json:"recovery,omitempty"`
}

// Public connection metadata never includes secrets or secret-store identifiers.
type apiConnection struct {
	Email    string `json:"email"`
	Provider string `json:"provider"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
}
type apiFolders struct {
	Quarantine string `json:"quarantine"`
	Review     string `json:"review"`
	TrainSpam  string `json:"train_spam"`
	TrainHam   string `json:"train_ham"`
}

func publicFolders(cfg config.Config) apiFolders {
	return apiFolders{cfg.Folders.Quarantine, cfg.Folders.Review, cfg.Folders.TrainSpam, cfg.Folders.TrainHam}
}

type apiSnapshot struct {
	Connection     *apiConnection `json:"connection,omitempty"`
	MailboxFolders *apiFolders    `json:"mailbox_folders,omitempty"`
	Configured     bool           `json:"configured"`
	Health         string         `json:"health"`
	HealthLabel    string         `json:"health_label"`
	Recommendation string         `json:"recommendation"`
	Automation     string         `json:"automation"`
	Mode           string         `json:"mode"`
	PurgeEnabled   bool           `json:"purge_enabled"`
	LastAttempt    *time.Time     `json:"last_attempt,omitempty"`
	LastSuccess    *time.Time     `json:"last_success,omitempty"`
	Stage          string         `json:"stage,omitempty"`
	ErrorCode      string         `json:"error_code,omitempty"`
	Summary        store.Summary  `json:"summary"`
	TrainedSpam    int            `json:"trained_spam"`
	TrainedHam     int            `json:"trained_ham"`
	RequiredSpam   int            `json:"required_spam"`
	RequiredHam    int            `json:"required_ham"`
	FirstDryRun    bool           `json:"first_dry_run"`
	AppAutostart   bool           `json:"app_autostart"`
	Version        string         `json:"version"`
	Protection     *apiProtection `json:"protection,omitempty"`
}

func (a *application) apiCommand(args []string) error {
	originalOut, originalErr, originalColor := a.out, a.errOut, a.color
	var capturedOut, capturedErr bytes.Buffer
	a.out, a.errOut, a.color = &capturedOut, &capturedErr, false
	var data any
	var actionErr error
	if len(args) == 0 {
		actionErr = errors.New("missing API command")
	} else {
		switch args[0] {
		case "snapshot":
			if len(args) != 1 {
				actionErr = errors.New("use guardian api snapshot")
			} else {
				data, actionErr = a.buildAPISnapshot()
			}
		case "setup":
			data, actionErr = a.apiSetup(args[1:])
		case "run":
			if len(args) > 2 || (len(args) == 2 && args[1] != "dry-run") {
				actionErr = errors.New("use guardian api run [dry-run]")
			} else {
				runArgs := []string(nil)
				if len(args) == 2 {
					runArgs = []string{"--dry-run"}
				}
				var run *store.Run
				run, actionErr = a.runCommandResult(runArgs)
				data = apiRunResult(run, actionErr)
			}
		case "doctor":
			deep := len(args) > 1 && args[1] == "deep"
			if len(args) > 2 || (len(args) == 2 && !deep) {
				actionErr = errors.New("use guardian api doctor [deep]")
			} else {
				actionErr = a.doctor(deep, deep)
			}
			data = map[string]any{"completed": actionErr == nil}
		case "repair":
			if len(args) != 1 {
				actionErr = errors.New("use guardian api repair")
			} else {
				actionErr = a.repair()
				data = map[string]any{"completed": actionErr == nil}
			}
		case "qualify":
			if len(args) != 1 {
				actionErr = errors.New("use guardian api qualify")
			} else {
				actionErr = a.qualifyCommand(nil)
				data = map[string]any{"completed": actionErr == nil}
			}
		case "service":
			data, actionErr = a.apiService(args[1:])
		case "app-autostart":
			data, actionErr = a.apiAppAutostart(args[1:])
		case "archive":
			data, actionErr = a.apiArchive(args[1:])
		case "mode":
			if len(args) != 1 {
				actionErr = errors.New("use guardian api mode")
			} else {
				data, actionErr = a.apiMode()
			}
		case "purge":
			if len(args) != 1 {
				actionErr = errors.New("use guardian api purge")
			} else {
				data, actionErr = a.apiPurge()
			}
		case "diagnostics":
			if len(args) != 1 {
				actionErr = errors.New("use guardian api diagnostics")
			} else {
				data, actionErr = a.exportDiagnostics()
			}
		default:
			actionErr = fmt.Errorf("unknown API command %q", args[0])
		}
	}
	a.out, a.errOut, a.color = originalOut, originalErr, originalColor
	envelope := apiEnvelope{Protocol: apiProtocolVersion, OK: actionErr == nil, Data: data}
	if actionErr != nil {
		userError := apperror.From(actionErr)
		envelope.Data = nil
		envelope.Error = &apiFailure{
			Code: string(userError.Code), Severity: userError.Severity,
			Message: userError.Message, Recovery: userError.Recovery,
		}
	}
	encoder := json.NewEncoder(originalOut)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(envelope)
}

func readAPIRequest(reader io.Reader, destination any) error {
	body, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
	if err != nil {
		return err
	}
	if len(body) > 64<<10 {
		return errors.New("API request exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("invalid API request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("API request contains extra data")
	}
	return nil
}

func (a *application) buildAPISnapshot() (apiSnapshot, error) {
	snapshot := apiSnapshot{
		Health: "unconfigured", HealthLabel: "Setup required",
		Recommendation: "Complete first-time setup.", Automation: "off",
		Mode: "protect", Version: version,
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return snapshot, nil
		}
		return snapshot, apperror.Wrap(apperror.Config, "critical", "Guardian configuration is unreadable.", "Run Repair or restore config.toml from backup.", err)
	}
	snapshot.Configured = true
	snapshot.Connection = &apiConnection{cfg.Account.Email, cfg.Account.Provider, cfg.Account.Host, cfg.Account.Port, cfg.Account.LoginUsername()}
	folders := publicFolders(cfg)
	snapshot.MailboxFolders = &folders
	snapshot.Mode, snapshot.PurgeEnabled = cfg.Safety.Mode, cfg.Safety.PurgeEnabled
	snapshot.RequiredSpam, snapshot.RequiredHam = qualification.MinLearns, qualification.MinLearns
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		return snapshot, err
	}
	defer db.Close()
	snapshot.Protection = protectionProgress(cfg, db, time.Now())
	snapshot.Summary, err = db.Summary(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		return snapshot, err
	}
	snapshot.LastAttempt, snapshot.LastSuccess, err = db.LastRunTimes(context.Background())
	if err != nil {
		return snapshot, err
	}
	latestStatus, latestErrors, err := db.LatestLiveRunOutcome(context.Background())
	if err != nil {
		return snapshot, err
	}
	snapshot.TrainedSpam, snapshot.TrainedHam, err = db.TrainingTotals(context.Background(), cfg.Account.Email)
	if err != nil {
		return snapshot, err
	}
	snapshot.FirstDryRun, err = db.DryRunAuthorizedFor(context.Background(), cfg)
	if err != nil {
		return snapshot, err
	}
	if appPath, pathErr := service.DefaultUIAppPath(); pathErr == nil {
		snapshot.AppAutostart = (service.UIManager{AppPath: appPath}).Status()
	}
	heartbeat, heartbeatErr := service.ReadHeartbeat(cfg.Runtime.DataDir)
	if heartbeatErr == nil {
		snapshot.LastAttempt = laterTime(snapshot.LastAttempt, heartbeat.LastAttempt)
		snapshot.LastSuccess = laterTime(snapshot.LastSuccess, heartbeat.LastSuccess)
		snapshot.Stage, snapshot.ErrorCode = heartbeat.Stage, heartbeat.ErrorCode
	}
	executable, _ := os.Executable()
	manager := service.Manager{Executable: executable, DataDir: cfg.Runtime.DataDir, LogFile: cfg.Runtime.LogFile}
	_, serviceErr := manager.Status()
	if serviceErr != nil {
		snapshot.Health, snapshot.HealthLabel = "manual", "Manual mode"
		snapshot.Recommendation = "Enable automatic checks or run them manually."
		return snapshot, nil
	}
	snapshot.Automation = "on"
	snapshot.Health, snapshot.HealthLabel = "healthy", "Everything works"
	snapshot.Recommendation = "No action required."
	if stale := heartbeatFreshnessError(heartbeat, time.Now()); stale != nil {
		snapshot.Health, snapshot.HealthLabel = "attention", "Needs attention"
		snapshot.Recommendation = stale.Recovery
		if stale.Severity == "critical" {
			snapshot.Health, snapshot.HealthLabel = "critical", "Not working"
		}
	}
	if latestStatus == "error" || latestErrors > 0 || snapshot.Summary.PendingMoves > 0 || heartbeatErr != nil {
		if snapshot.Health == "healthy" {
			snapshot.Health, snapshot.HealthLabel = "attention", "Needs attention"
		}
		snapshot.Recommendation = "Choose Check and repair; messages remain protected."
	}
	if !snapshot.FirstDryRun {
		if snapshot.Health == "healthy" {
			snapshot.Health, snapshot.HealthLabel = "attention", "Needs attention"
		}
		snapshot.Recommendation = "Complete a successful dry-run for the current configuration before enabling automation."
	}
	if snapshot.Health == "healthy" && snapshot.Mode == "protect" && snapshot.Protection != nil {
		snapshot.Recommendation = snapshot.Protection.Message
	}
	return snapshot, nil
}

func laterTime(first, second *time.Time) *time.Time {
	if first == nil {
		return second
	}
	if second != nil && second.After(*first) {
		return second
	}
	return first
}

type setupRequest struct {
	Provider               string `json:"provider,omitempty"`
	Host                   string `json:"host,omitempty"`
	Port                   int    `json:"port,omitempty"`
	Username               string `json:"username,omitempty"`
	AuthMethod             string `json:"auth_method,omitempty"`
	Email                  string `json:"email"`
	Password               string `json:"password"`
	SpamFolder             string `json:"spam_folder,omitempty"`
	AcceptExistingTraining bool   `json:"accept_existing_training,omitempty"`
}

type setupRequestWire struct {
	Provider                    string  `json:"provider"`
	Host                        string  `json:"host"`
	Port                        int     `json:"port"`
	Username                    string  `json:"username"`
	AuthMethod                  string  `json:"auth_method"`
	Email                       string  `json:"email"`
	Password                    string  `json:"password"`
	SpamFolder                  *string `json:"spam_folder"`
	SpamFolderCamel             *string `json:"spamFolder"`
	AcceptExistingTraining      *bool   `json:"accept_existing_training"`
	AcceptExistingTrainingCamel *bool   `json:"acceptExistingTraining"`
}

func readSetupRequest(reader io.Reader) (setupRequest, error) {
	var wire setupRequestWire
	if err := readAPIRequest(reader, &wire); err != nil {
		return setupRequest{}, err
	}
	if wire.SpamFolder != nil && wire.SpamFolderCamel != nil && *wire.SpamFolder != *wire.SpamFolderCamel {
		return setupRequest{}, errors.New("conflicting spam-folder values")
	}
	if wire.AcceptExistingTraining != nil && wire.AcceptExistingTrainingCamel != nil &&
		*wire.AcceptExistingTraining != *wire.AcceptExistingTrainingCamel {
		return setupRequest{}, errors.New("conflicting training-folder confirmations")
	}
	request := setupRequest{Email: wire.Email, Password: wire.Password,
		Provider: wire.Provider, Host: wire.Host, Port: wire.Port, Username: wire.Username, AuthMethod: wire.AuthMethod}
	if wire.SpamFolder != nil {
		request.SpamFolder = *wire.SpamFolder
	} else if wire.SpamFolderCamel != nil {
		request.SpamFolder = *wire.SpamFolderCamel
	}
	if wire.AcceptExistingTraining != nil {
		request.AcceptExistingTraining = *wire.AcceptExistingTraining
	} else if wire.AcceptExistingTrainingCamel != nil {
		request.AcceptExistingTraining = *wire.AcceptExistingTrainingCamel
	}
	return request, nil
}

type setupProbe struct {
	MailboxFolders apiFolders `json:"mailbox_folders"`
	DetectedSpam   string     `json:"detected_spam"`
	Folders        []string   `json:"folders"`
	SafeMove       bool       `json:"safe_move"`
}

func (a *application) apiSetup(args []string) (any, error) {
	if len(args) != 1 || (args[0] != "probe" && args[0] != "commit") {
		return nil, errors.New("use guardian api setup probe|commit")
	}
	request, err := readSetupRequest(a.in)
	if err != nil {
		return nil, err
	}
	request.Email = strings.TrimSpace(request.Email)
	if request.Email == "" || !strings.Contains(request.Email, "@") || request.Password == "" {
		return nil, apperror.Wrap(apperror.IMAPAuth, "attention", "Enter your full email address and account/app password.", "Check your provider's login requirements; use an app password where supported.", nil)
	}
	cfg, hadConfig, err := a.resolveSetupConfiguration(request)
	if err != nil {
		return nil, err
	}
	previousConfig := cfg
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	mail, err := dialMailbox(ctx, cfg, request.Password)
	if err != nil {
		code := apperror.Unknown
		if errors.Is(err, imapmail.ErrAuthentication) {
			code = apperror.IMAPAuth
		}
		return nil, apperror.Wrap(code, "attention", "Could not authenticate to the mail server.", "Check IMAP access and your provider's authentication requirements.", err)
	}
	defer mail.Close()
	boxes, err := mail.ListMailboxes()
	if err != nil {
		return nil, err
	}
	defaultFolders := cfg.Folders
	excludedFolders := []string{
		defaultFolders.Inbox, defaultFolders.Quarantine, defaultFolders.Review,
		defaultFolders.TrainSpam, defaultFolders.TrainHam,
	}
	// Exclude existing custom Guardian folders so upgrades cannot propose
	// a worker-owned folder as the provider spam folder.
	if existing, loadErr := config.Load(a.configPath); loadErr == nil {
		excludedFolders = append(excludedFolders,
			existing.Folders.Inbox, existing.Folders.Quarantine, existing.Folders.Review,
			existing.Folders.TrainSpam, existing.Folders.TrainHam,
		)
	}
	selectable := selectableMailboxes(boxes, excludedFolders...)
	probe := setupProbe{MailboxFolders: publicFolders(cfg), DetectedSpam: imapmail.DetectSpamFolder(selectable), SafeMove: mail.SafeMoveSupported()}
	for _, box := range selectable {
		probe.Folders = append(probe.Folders, box.Name)
	}
	if args[0] == "probe" {
		return probe, nil
	}
	if !probe.SafeMove {
		return nil, errors.New("server did not advertise safe IMAP MOVE")
	}
	spamFolder := strings.TrimSpace(request.SpamFolder)
	if spamFolder == "" {
		spamFolder = probe.DetectedSpam
	}
	found := false
	for _, name := range probe.Folders {
		if name == spamFolder {
			found = true
		}
	}
	if !found || strings.EqualFold(spamFolder, "INBOX") {
		return nil, errors.New("selected spam folder does not exist or points to Inbox")
	}
	request.Email = cfg.Account.Email
	cfg.Folders.ServerSpam = spamFolder
	// A dry-run and observation period accepted for an older mailbox layout
	// cannot authorize unattended decisions for this configuration.
	enforceSetupProtection(&cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	lock, err := acquireRunLock(cfg.Runtime.DataDir)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	// Check the existing journal before creating folders or replacing secrets.
	if _, err := os.Stat(cfg.Runtime.Database); err == nil {
		db, err := store.Open(cfg.Runtime.Database)
		if err != nil {
			return nil, err
		}
		bindingErr := db.BindConfiguration(context.Background(), previousConfig, time.Now())
		closeErr := db.Close()
		if err := errors.Join(bindingErr, closeErr); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// Inspect the full list separately from selectable GUI spam folders.
	// Hidden training folders still require explicit content acceptance.
	existingFolders := mailboxNameSet(boxes)
	for _, folder := range []string{cfg.Folders.TrainSpam, cfg.Folders.TrainHam} {
		if !existingFolders[folder] {
			continue
		}
		uids, _, searchErr := mail.SearchSince(folder, time.Time{}, 0)
		if searchErr != nil {
			return nil, fmt.Errorf("cannot safely inspect folder %s: %w", folder, searchErr)
		}
		if len(uids) > 0 && !request.AcceptExistingTraining {
			return nil, fmt.Errorf("folder %s contains messages; explicit confirmation required", folder)
		}
	}
	if err := mail.EnsureMailboxes(cfg.Folders.Quarantine, cfg.Folders.Review, cfg.Folders.TrainSpam, cfg.Folders.TrainHam); err != nil {
		return nil, err
	}
	kc := keychain.New()
	rollbackPassword, err := replaceSecret(
		kc, cfg.Account.PasswordKeychainService, request.Email, request.Password,
		"Mail Guardian - IMAP password",
	)
	if err != nil {
		return nil, err
	}
	identityExisted := true
	if _, identityErr := archive.LoadIdentity(kc, cfg.Runtime.ArchiveKeychainService, request.Email); identityErr != nil {
		if !errors.Is(identityErr, keychain.ErrNotFound) {
			return nil, errors.Join(identityErr, rollbackPassword())
		}
		if err := validateNewArchiveIdentity(cfg.Runtime.ArchiveDir, cfg.Runtime.Database); err != nil {
			return nil, errors.Join(err, rollbackPassword())
		}
		identityExisted = false
	}
	identity, err := archive.EnsureIdentity(kc, cfg.Runtime.ArchiveKeychainService, request.Email)
	if err != nil {
		return nil, errors.Join(err, rollbackPassword())
	}
	var scanner service.Manager
	scannerWasInstalled := false
	scannerPaused := false
	rollback := func() error {
		var rollbackErrors []error
		if err := rollbackPassword(); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("restoring account/app password: %w", err))
		}
		if !identityExisted {
			if err := rollbackNewArchiveIdentity(
				kc,
				cfg.Runtime.ArchiveKeychainService,
				request.Email,
				cfg.Runtime.ArchiveDir,
				cfg.Runtime.Database,
			); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("restoring archive key: %w", err))
			}
		}
		if hadConfig {
			if err := config.Save(a.configPath, previousConfig); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("restoring configuration: %w", err))
			}
		} else {
			if err := os.Remove(a.configPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("removing incomplete configuration: %w", err))
			}
		}
		if scannerPaused && scannerWasInstalled {
			if err := scanner.Install(); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("resuming previous automation: %w", err))
			}
		}
		return errors.Join(rollbackErrors...)
	}
	rollbackFailure := func(cause error) error { return errors.Join(cause, rollback()) }
	if _, err := archive.New(cfg.Runtime.ArchiveDir, identity); err != nil {
		return nil, rollbackFailure(err)
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, rollbackFailure(err)
	}
	scanner = service.Manager{Executable: executable, DataDir: cfg.Runtime.DataDir, LogFile: cfg.Runtime.LogFile}
	scannerWasInstalled = scanner.Installed()
	if scannerWasInstalled {
		// The run lock is already held, so no old scan can cross this boundary.
		// Mark the service as paused before bootout so a partial failure also
		// triggers a best-effort restoration of the old definition.
		scannerPaused = true
		if err := scanner.Uninstall(); err != nil {
			return nil, rollbackFailure(fmt.Errorf("cannot safely pause automation before configuration change: %w", err))
		}
	}
	if err := config.Save(a.configPath, cfg); err != nil {
		return nil, rollbackFailure(err)
	}
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		return nil, rollbackFailure(err)
	}
	defer db.Close()
	if err := db.BindConfiguration(context.Background(), cfg, time.Now()); err != nil {
		return nil, rollbackFailure(err)
	}
	installedAt, err := db.GetSetting(context.Background(), "installed_at")
	if err != nil {
		return nil, rollbackFailure(err)
	}
	if installedAt == "" {
		installedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := db.SetSetting(context.Background(), "installed_at", installedAt); err != nil {
			return nil, rollbackFailure(err)
		}
	}
	if err := db.RequireFreshDryRun(context.Background(), time.Now()); err != nil {
		return nil, rollbackFailure(err)
	}
	return map[string]any{
		"configured": true, "spam_folder": spamFolder,
		"folders": cfg.Folders, "first_dry_run_required": true,
	}, nil
}

func mailboxNameSet(boxes []imapmail.Mailbox) map[string]bool {
	names := make(map[string]bool, len(boxes))
	for _, box := range boxes {
		names[box.Name] = true
	}
	return names
}

func enforceSetupProtection(cfg *config.Config) {
	cfg.Safety.Mode = "protect"
	cfg.Safety.PurgeEnabled = false
}

type secretStore = secrets.Store

func replaceSecret(store secretStore, service, account, value, label string) (func() error, error) {
	previous, previousErr := store.Get(service, account)
	if previousErr != nil && !errors.Is(previousErr, keychain.ErrNotFound) {
		return nil, previousErr
	}
	if err := store.Set(service, account, value, label); err != nil {
		return nil, err
	}
	return func() error {
		if previousErr == nil {
			return store.Set(service, account, previous, label)
		}
		return store.Delete(service, account)
	}, nil
}

func (a *application) apiService(args []string) (any, error) {
	if len(args) != 1 || (args[0] != "enable" && args[0] != "disable") {
		return nil, errors.New("use guardian api service enable|disable")
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return nil, err
	}
	if args[0] == "enable" {
		authorized, proofErr := dryRunAuthorized(cfg)
		if proofErr != nil {
			return nil, proofErr
		}
		if !authorized {
			return nil, errors.New("complete a successful dry-run first")
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	manager := service.Manager{Executable: executable, DataDir: cfg.Runtime.DataDir, LogFile: cfg.Runtime.LogFile}
	if args[0] == "enable" {
		err = manager.Install()
	} else {
		err = manager.Uninstall()
	}
	return map[string]any{"automation": args[0]}, err
}

func (a *application) apiAppAutostart(args []string) (any, error) {
	if len(args) != 1 || (args[0] != "enable" && args[0] != "disable") {
		return nil, errors.New("use guardian api app-autostart enable|disable")
	}
	appPath, err := service.DefaultUIAppPath()
	if err != nil {
		return nil, err
	}
	manager := service.UIManager{AppPath: appPath}
	if args[0] == "enable" {
		err = manager.Install()
	} else {
		err = manager.Uninstall()
	}
	return map[string]any{"app_autostart": args[0] == "enable"}, err
}

func (a *application) apiArchive(args []string) (any, error) {
	if len(args) == 0 {
		return nil, errors.New("use archive list|preview|restore")
	}
	page := 1
	if len(args) > 1 {
		var pageErr error
		page, pageErr = strconv.Atoi(args[1])
		if pageErr != nil || page < 1 {
			return nil, errors.New("page number or ID must be positive")
		}
	}
	if args[0] == "list" {
		if len(args) > 5 || len(args) == 4 {
			return nil, errors.New("use archive list [page] [all|quarantined|review|restored] [from-RFC3339 to-RFC3339]")
		}
		status := ""
		if len(args) >= 3 {
			switch args[2] {
			case "all":
			case "quarantined", "review", "restored":
				status = args[2]
			default:
				return nil, errors.New("unknown backup category")
			}
		}
		var start, end time.Time
		if len(args) == 5 {
			var err error
			start, end, err = archiveDateRange(args[3], args[4])
			if err != nil {
				return nil, err
			}
		}
		rt, cleanup, err := a.openRuntime(false)
		if err != nil {
			return nil, err
		}
		defer cleanup()
		items, err := rt.db.ArchivedPageInRange(context.Background(), rt.cfg.Account.Email, 11, (page-1)*10, status, start, end)
		if err != nil {
			return nil, err
		}
		hasNext := len(items) > 10
		if hasNext {
			items = items[:10]
		}
		result := make([]map[string]any, 0, len(items))
		for _, item := range items {
			result = append(result, map[string]any{"id": item.ID, "date": item.FirstSeen, "verdict": item.Verdict, "status": item.Status})
		}
		return map[string]any{"page": page, "items": result, "has_next": hasNext}, nil
	}
	if len(args) != 2 {
		return nil, errors.New("provide backup ID")
	}
	id, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil || id <= 0 {
		return nil, errors.New("invalid backup ID")
	}
	if args[0] == "preview" {
		rt, cleanup, err := a.openRuntime(false)
		if err != nil {
			return nil, err
		}
		defer cleanup()
		record, err := rt.db.MessageByID(context.Background(), id)
		if err != nil {
			return nil, err
		}
		if record.Account != rt.cfg.Account.Email {
			return nil, errors.New("this backup belongs to another account and will not be shown")
		}
		raw, err := rt.archive.Read(record.ArchivePath)
		if err != nil {
			return nil, err
		}
		if archive.SHA256(raw) != record.RawSHA256 {
			return nil, errors.New("backup checksum mismatch")
		}
		preview, err := parseArchiveHeaderPreview(raw)
		if err != nil {
			return nil, err
		}
		return preview, nil
	}
	if args[0] == "restore" {
		cfg, err := config.Load(a.configPath)
		if err != nil {
			return nil, err
		}
		lock, err := acquireRunLock(cfg.Runtime.DataDir)
		if err != nil {
			return nil, err
		}
		defer lock.Close()
		rt, cleanup, err := a.openRuntime(true)
		if err != nil {
			return nil, err
		}
		defer cleanup()
		err = rt.engine.Restore(rt.ctx, id)
		if errors.Is(err, engine.ErrRestoreAlreadyPresent) {
			return map[string]any{"restored": false, "already_present": true}, nil
		}
		return map[string]any{"restored": err == nil}, err
	}
	return nil, errors.New("unknown archive operation")
}

type confirmationRequest struct {
	Value   string `json:"value"`
	Confirm string `json:"confirm"`
}

func (a *application) apiMode() (any, error) {
	var request confirmationRequest
	if err := readAPIRequest(a.in, &request); err != nil {
		return nil, err
	}
	if request.Value != "protect" && request.Value != "active" {
		return nil, errors.New("mode must be protect or active")
	}
	if request.Value == "active" && request.Confirm != "ACTIVE" && request.Confirm != "AKTYWNY" {
		return nil, errors.New("confirmation ACTIVE required")
	}
	oldInput := a.in
	if request.Value == "active" {
		// API validates the phrase shown by the GUI, then supplies the separate
		// CLI confirmation expected by modeCommand. Keeping the adapter here
		// prevents UI wording from weakening or accidentally breaking the CLI.
		a.in = bufio.NewReader(strings.NewReader("AKTYWUJ\n"))
	}
	err := a.modeCommand([]string{request.Value})
	a.in = oldInput
	return map[string]any{"mode": request.Value}, err
}

func (a *application) apiPurge() (any, error) {
	var request confirmationRequest
	if err := readAPIRequest(a.in, &request); err != nil {
		return nil, err
	}
	enable := request.Value == "enable"
	if request.Value != "enable" && request.Value != "disable" {
		return nil, errors.New("purge must be enable or disable")
	}
	if enable && request.Confirm != "ENABLE" && request.Confirm != "WLACZ" {
		return nil, errors.New("confirmation ENABLE required")
	}
	oldInput := a.in
	if enable {
		a.in = bufio.NewReader(strings.NewReader("ENABLE\n"))
	}
	err := a.setPurge(enable)
	a.in = oldInput
	return map[string]any{"purge_enabled": enable}, err
}

func (a *application) exportDiagnostics() (any, error) {
	snapshot, snapshotErr := a.buildAPISnapshot()
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, "Desktop", "Mail-Guardian-diagnostics-"+time.Now().Format("20060102-150405")+".zip")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".guardian-diagnostics-*.zip")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	writer := zip.NewWriter(tmp)
	entry, err := writer.Create("report.json")
	if err != nil {
		return nil, err
	}
	report := map[string]any{
		"generated_at": time.Now().UTC(), "guardian_version": version,
		"os": runtime.GOOS, "architecture": runtime.GOARCH,
	}
	if snapshotErr == nil {
		report["snapshot_available"] = true
		// Local UI metadata can identify the mailbox or contain private custom
		// folder names. Keep it out of the shareable diagnostic archive.
		snapshot.Connection, snapshot.MailboxFolders = nil, nil
		report["snapshot"] = snapshot
	} else {
		report["snapshot_available"] = false
		report["snapshot_error"] = redactedDiagnosticFailure(snapshotErr)
	}
	if err := json.NewEncoder(entry).Encode(report); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	ok = true
	return map[string]any{"path": path}, nil
}

func redactedDiagnosticFailure(err error) apiFailure {
	userError := apperror.From(err)
	failure := apiFailure{
		Code: string(userError.Code), Severity: userError.Severity,
		Message: userError.Message, Recovery: userError.Recovery,
	}
	if userError.Code == apperror.Unknown {
		// Unknown library errors may contain paths, account addresses or data.
		// Exclude them from the shareable diagnostic package.
		failure.Message = "Could not read Guardian's current status."
		failure.Recovery = "Run Check and repair; include this report if the problem persists."
	}
	return failure
}

// Accept explicit instants so GUI calendar days retain the user's timezone.
func archiveDateRange(from, until string) (time.Time, time.Time, error) {
	start, startErr := time.Parse(time.RFC3339, from)
	end, endErr := time.Parse(time.RFC3339, until)
	if startErr != nil || endErr != nil || !start.Before(end) {
		return time.Time{}, time.Time{}, errors.New("select a valid date range: start must precede end")
	}
	return start, end, nil
}
