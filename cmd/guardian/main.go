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

	"github.com/o2-mail-guardian/guardian/internal/apperror"
	"github.com/o2-mail-guardian/guardian/internal/archive"
	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/engine"
	"github.com/o2-mail-guardian/guardian/internal/imapmail"
	"github.com/o2-mail-guardian/guardian/internal/keychain"
	"github.com/o2-mail-guardian/guardian/internal/qualification"
	"github.com/o2-mail-guardian/guardian/internal/rspamd"
	"github.com/o2-mail-guardian/guardian/internal/runlock"
	"github.com/o2-mail-guardian/guardian/internal/service"
	"github.com/o2-mail-guardian/guardian/internal/stack"
	"github.com/o2-mail-guardian/guardian/internal/store"
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

	// Punkty wstrzykiwania używane przez testy polecenia naprawczego. W zwykłym
	// programie pozostają nil i uruchamiane są prawdziwe, bezpieczne operacje.
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
			return errors.New("po --config podaj ścieżkę i polecenie")
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
		fmt.Fprintf(a.out, "O2 Mail Guardian %s (%s)\n", version, commit)
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
			"nie znam polecenia %q\nUruchom Guardian bez wpisywania polecenia — pojawi się proste menu",
			args[0],
		)
	}
}

func (a *application) appServiceCommand(args []string) error {
	if len(args) != 1 {
		return errors.New("użyj: guardian app-service install|uninstall|status")
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
			return errors.New("panel nie jest uruchamiany po zalogowaniu")
		}
		return nil
	default:
		return errors.New("użyj: guardian app-service install|uninstall|status")
	}
}

func (a *application) doctorCommand(args []string) error {
	deep := false
	for _, arg := range args {
		if arg != "--deep" {
			return errors.New("użyj: guardian doctor [--deep]")
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
	fmt.Fprintln(a.out, `
O2 Mail Guardian — lokalny strażnik skrzynki o2.pl

Najprościej:
  guardian                     otwiera proste menu po polsku
  guardian napraw              sprawdza i bezpiecznie naprawia instalację

Polecenia dodatkowe:
  guardian konfiguruj          kreator konfiguracji
  guardian stan                czytelne podsumowanie
  guardian uruchom --dry-run   próba bez przenoszenia wiadomości
  guardian sprawdz             bezpieczne sprawdzenie skrzynki
  guardian kontrola            kontrola bez naprawiania

Bezpieczeństwo i odzyskiwanie:
  guardian mode status         aktualny tryb ochrony
  guardian archive list        lista zaszyfrowanych kopii
  guardian archive show ID     bezpieczny podgląd nagłówków jednej kopii
  guardian archive restore ID  odzyskanie kopii do AI-Do-sprawdzenia
  guardian purge --dry-run     podgląd, co kwalifikuje się do usunięcia

Automatyzacja i silnik:
  guardian service install|status|uninstall
  guardian stack up|status|down
  guardian server init-config|validate-config

Nie musisz zapamiętywać tych poleceń — wszystkie codzienne działania są w menu.
Trwałe kasowanie jest domyślnie wyłączone i nie może zostać uruchomione przed
zakończeniem okresu ochronnego.`)
}

func (a *application) setup() (retErr error) {
	a.header("Kreator pierwszej konfiguracji")
	if runtime.GOOS != "darwin" {
		return errors.New("kreator bezpiecznego pęku kluczy wymaga macOS")
	}
	cfg := config.Default()
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
				rollbackErrors = append(rollbackErrors, fmt.Errorf("przywrócenie poprzedniego hasła: %w", err))
			}
		}
		if identityCreated {
			kc := keychain.New()
			if err := kc.Delete(cfg.Runtime.ArchiveKeychainService, cfg.Account.Email); err != nil && !errors.Is(err, keychain.ErrNotFound) {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("usunięcie nieukończonego klucza archiwum: %w", err))
			}
		}
		if scannerPaused {
			if err := scannerManager.Install(); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("wznowienie poprzedniego automatu: %w", err))
			}
		}
		retErr = errors.Join(retErr, errors.Join(rollbackErrors...))
	}()
	if _, err := os.Stat(a.configPath); err == nil {
		existing, err := config.Load(a.configPath)
		if err != nil {
			return fmt.Errorf(
				"istniejąca konfiguracja jest nieczytelna i nie zostanie nadpisana: %w\nNapraw plik %s albo odtwórz go z kopii zapasowej",
				err, a.configPath,
			)
		}
		cfg = existing
		firstSetup = false
		a.info("Znaleziono istniejącą konfigurację. Kreator bezpiecznie ją zaktualizuje.")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("nie mogę sprawdzić pliku konfiguracji %s: %w", a.configPath, err)
	}
	if err := os.MkdirAll(cfg.Runtime.DataDir, 0o700); err != nil {
		return fmt.Errorf("nie mogę przygotować prywatnego katalogu danych: %w", err)
	}
	lock, err := acquireRunLock(cfg.Runtime.DataDir)
	if err != nil {
		return err
	}
	defer lock.Close()

	email, err := a.ask("Adres e-mail o2.pl", cfg.Account.Email)
	if err != nil {
		return err
	}
	email = strings.TrimSpace(email)
	if !strings.Contains(email, "@") {
		return errors.New("adres e-mail wygląda na nieprawidłowy")
	}
	if !firstSetup && !strings.EqualFold(email, cfg.Account.Email) {
		return errors.New("istniejąca instalacja jest przypisana do innego konta; dla bezpieczeństwa utwórz osobną instalację zamiast mieszać bazy i zaszyfrowane kopie")
	}
	if !firstSetup {
		// Preserve the exact Keychain account identifier used during the first
		// setup even if the user typed different letter casing.
		email = cfg.Account.Email
	}
	cfg.Account.Email = email

	kc := keychain.New()
	identityExisted := true
	if _, err := archive.LoadIdentity(kc, cfg.Runtime.ArchiveKeychainService, email); err != nil {
		if !errors.Is(err, keychain.ErrNotFound) {
			return fmt.Errorf("nie mogę sprawdzić klucza szyfrowania kopii w pęku kluczy: %w", err)
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
		return fmt.Errorf("nie mogę odczytać hasła o2 z pęku kluczy: %w", savedPasswordErr)
	}
	if !firstSetup && savedPasswordErr == nil {
		a.info("Sprawdzam zapisane hasło aplikacyjne — nie musisz wpisywać go ponownie…")
		mail, err = dialMailbox(ctx, cfg, savedPassword)
		if err == nil {
			a.success("Zapisane hasło aplikacyjne nadal działa.")
		} else if !isIMAPAuthenticationError(err) {
			return fmt.Errorf(
				"nie mogę teraz sprawdzić zapisanego hasła: %w\n"+
					"Hasło w pęku kluczy nie zostało zmienione; sprawdź internet i spróbuj ponownie",
				err,
			)
		} else {
			a.warning("o2 odrzuciło zapisane hasło aplikacyjne. Dotychczasowe hasło pozostanie bez zmian, dopóki nowe nie zostanie sprawdzone.")
		}
	}

	if mail == nil {
		fmt.Fprintln(a.out, `
Najpierw włącz logowanie dwustopniowe w o2 i utwórz osobne „hasło do
aplikacji”. Nie podawaj tutaj głównego hasła do konta.

Instrukcja: https://pomoc.o2.pl/wpkonto/hasla-do-aplikacji-zewnetrznej
Nowe hasło zostanie zapisane w pęku kluczy dopiero po poprawnym logowaniu.`)
		if ok, confirmErr := a.confirm("Czy masz już hasło do aplikacji?", true); confirmErr != nil {
			return confirmErr
		} else if !ok {
			return errors.New("konfiguracja zatrzymana; wróć po utworzeniu hasła do aplikacji")
		}
		password, passwordErr := a.readHiddenPassword("Hasło aplikacyjne o2")
		if passwordErr != nil {
			return passwordErr
		}
		a.info("Sprawdzam nowe hasło przez szyfrowane połączenie z o2…")
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
				"O2 Mail Guardian - hasło IMAP",
			)
			return saveErr
		}
		if err := verifyAndStorePassword(password, verify, save); err != nil {
			if mail != nil {
				_ = mail.Close()
			}
			return fmt.Errorf(
				"%w\nNowe hasło nie zastąpiło dotychczasowego hasła w pęku kluczy",
				err,
			)
		}
		a.success("Nowe hasło działa i zostało bezpiecznie zapisane w pęku kluczy.")
	}
	defer mail.Close()
	boxes, err := mail.ListMailboxes()
	if err != nil {
		return err
	}
	spamFolder := imapmail.DetectSpamFolder(boxes)
	if spamFolder != "" {
		ok, err := a.confirm(fmt.Sprintf("Wykryto folder SPAM: %q. Użyć go?", spamFolder), true)
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
		return fmt.Errorf("wybrany układ folderów jest niebezpieczny i nie zostanie utworzony: %w", err)
	}
	if !mail.SafeMoveSupported() {
		return errors.New("o2 nie zgłosiło natywnego IMAP MOVE; robot nie wykona niebezpiecznego zastępczego przenoszenia")
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
					"istniejący folder %q różni się od wymaganej nazwy %q tylko wielkością liter; dla bezpieczeństwa zmień jego nazwę i uruchom kreator ponownie",
					box.Name,
					target,
				)
			}
		}
	}
	if len(existingRobotFolders) > 0 {
		ok, err := a.confirm("Foldery "+strings.Join(existingRobotFolders, ", ")+" już istnieją. Użyć ich ponownie?", false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("konfiguracja zatrzymana; zmień nazwy folderów w istniejącej konfiguracji albo opróżnij konflikt")
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
				return fmt.Errorf("nie mogę bezpiecznie sprawdzić zawartości folderu uczącego %q: %w", folder, err)
			}
			trainingCounts[folder] = len(uids)
		}
		totalTraining := trainingCounts[cfg.Folders.TrainSpam] + trainingCounts[cfg.Folders.TrainHam]
		if totalTraining > 0 {
			fmt.Fprintf(
				a.out,
				"\nUwaga: istniejące foldery uczące zawierają wiadomości:\n  %s: %d\n  %s: %d\n",
				cfg.Folders.TrainSpam,
				trainingCounts[cfg.Folders.TrainSpam],
				cfg.Folders.TrainHam,
				trainingCounts[cfg.Folders.TrainHam],
			)
			ok, err := a.confirmDanger(
				"Przy następnym przebiegu każda z tych wiadomości stanie się świadomą korektą filtra i zostanie przeniesiona.",
				"UCZ",
			)
			if err != nil || !ok {
				return errors.New("konfiguracja zatrzymana; opróżnij istniejące foldery uczące albo uruchom kreator ponownie i świadomie potwierdź ich zawartość")
			}
		}
	}
	a.printFolderMapping(cfg)
	if firstSetup {
		ok, err := a.confirm("Czy ten układ folderów jest prawidłowy i mogę go utworzyć?", false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("konfiguracja zatrzymana przed utworzeniem folderów; żaden folder Guardiana nie został dodany")
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
		return fmt.Errorf("katalog zaszyfrowanych kopii nie jest bezpieczny: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("nie mogę ustalić położenia programu przed zmianą konfiguracji: %w", err)
	}
	scannerManager = service.Manager{Executable: exe, DataDir: cfg.Runtime.DataDir, LogFile: cfg.Runtime.LogFile}
	if scannerManager.Installed() {
		scannerPaused = true
		if err := scannerManager.Uninstall(); err != nil {
			return fmt.Errorf("nie udało się bezpiecznie wstrzymać automatu przed zmianą konfiguracji: %w", err)
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
		return fmt.Errorf("nie udało się odczytać początku okresu ochronnego: %w", err)
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
	a.success("Połączenie działa, foldery są gotowe, a kopie będą szyfrowane.")
	// Instalacja usługi launchd może natychmiast uruchomić pierwszy przebieg.
	// Konfiguracja i foldery są już spójne, więc zwolnij blokadę przed bootstrapem.
	if err := lock.Close(); err != nil {
		return fmt.Errorf("konfiguracja jest gotowa, ale nie mogę bezpiecznie zwolnić blokady programu: %w", err)
	}

	controller, err := kc.Get(cfg.Rspamd.PasswordKeychainService, "controller")
	if err != nil {
		a.warning("Lokalny filtr nie jest jeszcze gotowy. W menu wybierz „Sprawdź i napraw program”.")
	} else if pingErr := rspamd.New(cfg.Rspamd.ScanURL, cfg.Rspamd.LearnURL, controller, 5*time.Second).Ping(ctx); pingErr != nil {
		a.warning("Lokalny filtr jeszcze nie odpowiada. W menu wybierz „Sprawdź i napraw program”.")
	} else {
		a.success("Lokalny filtr antyspamowy odpowiada.")
	}
	a.header("Obowiązkowa bezpieczna próba")
	a.info("Guardian pokaże decyzje bez przenoszenia wiadomości i bez uczenia filtra.")
	if err := a.runCommand([]string{"--dry-run"}); err != nil {
		return apperror.Wrap(
			apperror.Rspamd, "attention", "Próba nie zakończyła się pomyślnie.",
			"Napraw wskazany problem i ponów konfigurację; automatyzacja nie została włączona.", err,
		)
	}
	a.success("Próba zakończyła się pomyślnie. Skrzynka nie została zmieniona.")
	if _, statusErr := scannerManager.Status(); statusErr == nil {
		a.success("Automatyczne sprawdzanie co 2 godziny jest już aktywne.")
	} else if ok, confirmErr := a.confirm("Włączać automatyczne sprawdzanie co 2 godziny?", true); confirmErr != nil {
		return confirmErr
	} else if ok {
		if err := scannerManager.Install(); err != nil {
			a.warning("Nie udało się włączyć automatyzacji: " + err.Error())
		} else {
			a.success("Automatyczne sprawdzanie jest aktywne.")
		}
	} else {
		a.info("Automatyczne sprawdzanie pozostało wyłączone zgodnie z Twoim wyborem.")
	}
	fmt.Fprintln(a.out, "\nGotowe. Rozpoczął się nowy, co najmniej 14-dniowy tryb ochronny i nic nie będzie trwale usuwane.")
	return nil
}

func (a *application) chooseMailbox(boxes []imapmail.Mailbox, excludedNames ...string) (string, error) {
	fmt.Fprintln(a.out, "\nNie rozpoznałem automatycznie folderu SPAM.")
	fmt.Fprintln(a.out, "Wybierz folder, do którego poczta o2 sama odkłada niechciane wiadomości:")
	selectable := selectableMailboxes(boxes, excludedNames...)
	for index, box := range selectable {
		fmt.Fprintf(a.out, "  %d. %s\n", index+1, box.Name)
	}
	if len(selectable) == 0 {
		return "", errors.New("na koncie nie ma folderu, który można bezpiecznie wskazać jako SPAM; utwórz folder SPAM w o2 i spróbuj ponownie")
	}
	value, err := a.ask("Wpisz numer folderu SPAM", "")
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > len(selectable) {
		return "", fmt.Errorf("nie ma folderu o numerze %q; wpisz jeden z numerów pokazanych na liście", value)
	}
	return selectable[n-1].Name, nil
}

// selectableMailboxes centralizuje listę folderów, które wolno wskazać jako
// systemowy SPAM. GUI i awaryjny kreator tekstowy muszą pokazywać identyczny,
// bezpieczny wybór: bez INBOX, folderów Guardiana i kontenerów \Noselect.
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
	fmt.Fprintln(a.out, "\nTak Guardian będzie używać folderów:")
	fmt.Fprintf(a.out, "  Odebrane (INBOX):          %s\n", cfg.Folders.Inbox)
	fmt.Fprintf(a.out, "  SPAM obsługiwany przez o2: %s\n", cfg.Folders.ServerSpam)
	fmt.Fprintf(a.out, "  Pewny spam w kwarantannie: %s\n", cfg.Folders.Quarantine)
	fmt.Fprintf(a.out, "  Do sprawdzenia ręcznego:   %s\n", cfg.Folders.Review)
	fmt.Fprintf(a.out, "  Nauka — to jest spam:      %s\n", cfg.Folders.TrainSpam)
	fmt.Fprintf(a.out, "  Nauka — to jest ważne:     %s\n", cfg.Folders.TrainHam)
}

func (a *application) doctor(verbose, deep bool) error {
	a.header("Kontrola instalacji")
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return apperror.Wrap(apperror.Config, "critical", "Konfiguracja Guardiana jest nieczytelna.", "Otwórz aplikację i uruchom Napraw albo pierwszą konfigurację.", err)
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
		err = fmt.Errorf("uprawnienia %o są zbyt szerokie; oczekiwano 600", info.Mode().Perm())
	}
	check("Konfiguracja jest prywatna", err)
	kc := runtimeSecrets(cfg)
	_, err = kc.Get(cfg.Account.PasswordKeychainService, cfg.Account.Email)
	if err != nil {
		err = apperror.Wrap(apperror.Keychain, "critical", "Nie można odczytać hasła o2 z pęku kluczy.", "Odblokuj pęk kluczy lub zapisz ponownie hasło aplikacyjne w ustawieniach.", err)
	}
	check("Hasło o2 jest w pęku kluczy", err)
	controller, ctrlErr := kc.Get(cfg.Rspamd.PasswordKeychainService, "controller")
	if ctrlErr != nil {
		ctrlErr = apperror.Wrap(apperror.Keychain, "critical", "Nie można odczytać hasła lokalnego filtra.", "Uruchom Install.command, aby bezpiecznie naprawić silnik.", ctrlErr)
	}
	check("Hasło lokalnego filtra jest w pęku kluczy", ctrlErr)
	archiveIdentity, err := archive.LoadIdentity(kc, cfg.Runtime.ArchiveKeychainService, cfg.Account.Email)
	if err != nil {
		err = apperror.Wrap(apperror.ArchiveKey, "critical", "Nie można odczytać klucza zaszyfrowanych kopii.", "Nie usuwaj archiwum; odblokuj pęk kluczy i uruchom Napraw.", err)
	}
	check("Klucz kopii jest w pęku kluczy", err)
	db, err := store.Open(cfg.Runtime.Database)
	check("Baza stanu działa", err)
	if db != nil {
		defer db.Close()
		integrityErr := db.IntegrityCheck(context.Background())
		check("Baza stanu ma prawidłową integralność", integrityErr)
		if integrityErr == nil && archiveIdentity != nil {
			archiver, archiveErr := archive.New(cfg.Runtime.ArchiveDir, archiveIdentity)
			if archiveErr == nil {
				archiveErr = (&engine.Engine{Config: cfg, Store: db, Archive: archiver}).CheckArchiveFiles(context.Background())
			}
			check("25 najnowszych zaszyfrowanych kopii przechodzi kontrolę integralności", archiveErr)
		}
	}
	free, diskErr := freeBytes(cfg.Runtime.DataDir)
	if diskErr == nil && free < 1<<30 {
		diskErr = fmt.Errorf("pozostało mniej niż 1 GiB wolnego miejsca")
	}
	check("Na dysku jest miejsce na bezpieczne kopie", diskErr)
	scanner := rspamd.New(cfg.Rspamd.ScanURL, cfg.Rspamd.LearnURL, controller, 8*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pingErr := scanner.Ping(ctx)
	if pingErr != nil {
		pingErr = apperror.Wrap(apperror.Rspamd, "critical", "Lokalny filtr antyspamowy nie odpowiada.", "Uruchom Napraw.", pingErr)
	}
	check("Lokalny filtr antyspamowy odpowiada", pingErr)
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
				scanErr = errors.New("testowy skan Rspamd był niekompletny")
			}
		}
		check("Lokalny filtr wykonuje kompletny test", scanErr)
		if verbose {
			stats, statsErr := scanner.Stats(ctx)
			if statsErr == nil && db != nil {
				statsErr = compareBayesHighWater(ctx, db, cfg.Account.Email, stats)
			}
			check("Statystyki Bayesa są dostępne i kompletne", statsErr)
		}
	}
	password, passErr := kc.Get(cfg.Account.PasswordKeychainService, cfg.Account.Email)
	if passErr == nil {
		mail, mailErr := dialMailbox(ctx, cfg, password)
		check("Szyfrowane logowanie do o2 działa", mailErr)
		if mailErr == nil {
			defer mail.Close()
			boxes, listErr := mail.ListMailboxes()
			check("Lista folderów IMAP jest dostępna", listErr)
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
						a.problem(fmt.Errorf("brakuje folderu %q", name))
					}
				}
				caps := mail.Capabilities()
				check("Natywne przenoszenie IMAP MOVE jest obsługiwane", boolError(mail.SafeMoveSupported(), "brak natywnego MOVE"))
				if !mail.SafeDeleteSupported() {
					a.warning("Brak UIDPLUS: trwałe kasowanie będzie zablokowane.")
				}
				if verbose {
					fmt.Fprintf(a.out, "\nFolder SPAM: %s\nSeparator folderów: %q\nIMAP: %s\n",
						cfg.Folders.ServerSpam, delimiterOf(boxes), strings.Join(caps.Names, ", "))
					fmt.Fprintln(a.out, "Program nie tworzy połączeń SMTP i nie wysyła wiadomości.")
				}
			}
		}
	}
	if deep {
		executable, _ := os.Executable()
		manager := service.Manager{Executable: executable, DataDir: cfg.Runtime.DataDir, LogFile: cfg.Runtime.LogFile}
		check("Automatyczna usługa jest aktywna", func() error { _, statusErr := manager.Status(); return statusErr }())
		heartbeat, heartbeatErr := service.ReadHeartbeat(cfg.Runtime.DataDir)
		if heartbeatErr == nil {
			if stale := heartbeatFreshnessError(heartbeat, time.Now()); stale != nil {
				heartbeatErr = stale
			}
		}
		check("Heartbeat automatycznego sprawdzania jest aktualny", heartbeatErr)
		managerStack := runtimeStack(cfg)
		stackErr := managerStack.DeepCheck()
		check("Redis, DNS i Rspamd działają w lokalnym stosie", stackErr)
	}
	if failures > 0 {
		return firstFailure
	}
	a.success("Wszystkie kontrole zakończone pomyślnie.")
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
					apperror.BayesRollback, "critical", "Zapis kontroli modelu Bayesa jest uszkodzony.",
					"Pozostaw tryb ochronny i uruchom Napraw; nie włączaj purge.", parseErr,
				)
			}
			// Rspamd deduplicates statistical content, while SQLite counts
			// distinct raw messages. Only an observed Rspamd revision can
			// prove a regression once that authoritative baseline exists.
			highest = parsed
		}
		if item.current < highest {
			return apperror.Wrap(
				apperror.BayesRollback, "critical", "Lokalny model Bayesa cofnął się lub został wyzerowany.",
				"Pozostaw tryb ochronny i uruchom Napraw; nie włączaj purge.", nil,
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
		return errors.New("brak potwierdzonego wyniku sprawdzania")
	}
	if run.Errors > 0 {
		return fmt.Errorf("przebieg zakończony z błędami: %d; część operacji wymaga sprawdzenia", run.Errors)
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
	dryRun := fs.Bool("dry-run", false, "tylko pokaż decyzje")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, errors.New("polecenie sprawdzania nie przyjmuje dodatkowego tekstu; uruchom Guardian bez polecenia i wybierz działanie z menu")
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return nil, fmt.Errorf("%w\nOtwórz menu i rozpocznij pierwszą konfigurację", err)
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
			a.warning("Wykryto cofnięcie lokalnego modelu Bayesa. Włączono tryb ochronny i wyłączono trwałe usuwanie.")
		}
		if runtime.GOOS == "linux" {
			if err := a.prepareLinuxMutation(rt); err != nil {
				return nil, err
			}
		}
	}
	a.header("Sprawdzanie skrzynki")
	if *dryRun {
		a.warning("PRÓBA: żadna wiadomość nie zostanie przeniesiona ani nauczona.")
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
			return nil, fmt.Errorf("próba się udała, ale nie zapisano jej potwierdzenia: %w", err)
		}
	}
	a.printRun(run)
	if rt.cfg.Safety.PurgeEnabled && !*dryRun {
		purgeRun, purgeErr := rt.engine.Purge(rt.ctx, false)
		if purgeErr != nil {
			a.warning("Automatyczne czyszczenie kwarantanny zostało pominięte: " + purgeErr.Error())
		} else if purgeRun.Purged > 0 {
			fmt.Fprintf(a.out, "Trwale usunięto po ponownej weryfikacji: %d\n", purgeRun.Purged)
		}
	}
	if !*dryRun {
		if cleaned, cleanupErr := rt.engine.CleanupExpiredArchives(context.Background()); cleanupErr != nil {
			a.warning("Nie usunięto wygasłych kopii lokalnych: " + cleanupErr.Error())
		} else if cleaned > 0 {
			fmt.Fprintf(a.out, "Usunięto wygasłe kopie lokalne: %d\n", cleaned)
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
				a.warning("Nie udało się zapisać aktualnego stanu Bayesa: " + statsErr.Error())
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
		combined := errors.Join(runErr, fmt.Errorf("nie udało się zabezpieczyć modelu Bayesa na Macu: %w", err))
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
	sinceValue := fs.String("since", "24h", "okres, np. 24h lub 7d")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("raport nie przyjmuje dodatkowego tekstu; wybierz „Pokaż stan i zalecenia” w menu")
	}
	duration, err := config.ParseSince(*sinceValue)
	if err != nil {
		return fmt.Errorf("nieprawidłowy okres raportu %q; użyj np. 24h albo 7d", *sinceValue)
	}
	if duration <= 0 {
		return errors.New("okres raportu musi być dłuższy niż zero, np. 24h albo 7d")
	}
	if duration > 366*24*time.Hour {
		return errors.New("okres raportu nie może być dłuższy niż 366 dni")
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
	a.header("Stan robota")
	fmt.Fprintf(a.out, "Tryb: %s\nTrwałe usuwanie: %s\nOkres raportu: %s\n\n",
		modeName(cfg.Safety.Mode), yesNo(cfg.Safety.PurgeEnabled), *sinceValue)
	fmt.Fprintf(a.out, "Przebiegi:              %d (w tym próbne: %d)\n", summary.Runs, summary.DryRuns)
	fmt.Fprintf(a.out, "Sprawdzone wiadomości:  %d\n", summary.Scanned)
	fmt.Fprintf(a.out, "Uratowane z SPAM-u:     %d\n", summary.Rescued)
	fmt.Fprintf(a.out, "Przeniesione do kwarantanny: %d\n", summary.Quarantined)
	fmt.Fprintf(a.out, "Do ręcznego sprawdzenia:     %d\n", summary.Review)
	fmt.Fprintf(a.out, "Nauczone jako spam/ważne:    %d/%d\n", summary.LearnedSpam, summary.LearnedHam)
	fmt.Fprintf(a.out, "Błędy bez utraty poczty:     %d\n\n", summary.Errors)
	fmt.Fprintf(a.out, "Obecnie w ewidencji kwarantanny: %d\n", summary.WaitingQuarantine)
	fmt.Fprintf(a.out, "Obecnie oczekuje na sprawdzenie: %d\n", summary.WaitingReview)
	fmt.Fprintf(a.out, "Ruchy wymagające uzgodnienia:    %d\n", summary.PendingMoves)
	if summary.PendingMoves > 0 {
		a.warning("Niektóre przeniesienia trzeba bezpiecznie uzgodnić z serwerem. Wiadomości pozostały zabezpieczone.")
	}
	fmt.Fprintf(a.out, "Starsze niż okres kwarantanny (to jeszcze nie oznacza usunięcia): %d\n", summary.PurgeEligible)
	fmt.Fprintf(a.out, "\nPostęp uczenia filtra: spam %d/%d, ważne %d/%d\n",
		trainedSpam, qualification.MinLearns, trainedHam, qualification.MinLearns)
	fmt.Fprintf(a.out, "Pomyłki wykryte dzięki Twoim poprawkom (30 dni): ważne uznane za spam %d, spam uznany za ważny %d\n",
		falseSpam, falseHam)

	fmt.Fprintln(a.out, "\nCo zrobić teraz:")
	current := summary
	if _, errorCount, outcomeErr := db.LatestLiveRunOutcome(context.Background()); outcomeErr == nil {
		current.Errors = errorCount
	}
	for _, advice := range statusAdvice(current, trainedSpam, trainedHam, qualification.MinLearns, qualification.MinLearns) {
		fmt.Fprintf(a.out, "  • %s\n", advice)
	}
	fmt.Fprintf(a.out, "\nDane programu: %s\nArchiwum kopii: %s\n", cfg.Runtime.DataDir, cfg.Runtime.ArchiveDir)
	if runtime.GOOS == "linux" {
		fmt.Fprintf(a.out, "Instancja Linux: %s (%s)\n", linuxInstance(cfg), cfg.InstanceID)
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
		advice = append(advice, "W menu wybierz „Sprawdź skrzynkę teraz”, aby dokończyć uzgadnianie przeniesień.")
	}
	if summary.Errors > 0 {
		advice = append(advice, "W menu wybierz „Sprawdź i napraw program”; błędne operacje nie usunęły poczty.")
	}
	if summary.WaitingReview > 0 {
		advice = append(advice, fmt.Sprintf(
			"Przejrzyj folder AI-Do-sprawdzenia — czeka tam %d wiadomości.",
			summary.WaitingReview,
		))
	}
	if trainedSpam < minSpam || trainedHam < minHam {
		advice = append(advice, "Poprawiaj pomyłki robota za pomocą folderów AI-Naucz-spam i AI-Naucz-wazne.")
	}
	if len(advice) == 0 {
		advice = append(advice, "Nie musisz nic robić. Guardian działa prawidłowo.")
	}
	return advice
}

func (a *application) purgeCommand(args []string) error {
	if len(args) > 0 && (args[0] == "enable" || args[0] == "disable") {
		return a.setPurge(args[0] == "enable")
	}
	fs := flag.NewFlagSet("purge", flag.ContinueOnError)
	fs.SetOutput(a.errOut)
	dryRun := fs.Bool("dry-run", false, "pokaż bez usuwania")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("polecenie czyszczenia nie przyjmuje dodatkowego tekstu")
	}
	if !*dryRun {
		ok, err := a.confirmDanger("To może trwale usunąć wyłącznie spam starszy niż 30 dni.", "USUN")
		if err != nil {
			return err
		}
		if !ok {
			return apperror.ErrCancelled
		}
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return fmt.Errorf("%w\nOtwórz menu i rozpocznij pierwszą konfigurację", err)
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
			"Lokalny model Bayesa cofnął się; purge został wyłączony.",
			"Pozostań w trybie ochronnym i ponownie zbierz potwierdzone przykłady.", nil)
	}
	run, err := rt.engine.Purge(rt.ctx, *dryRun)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Wiadomości spełniające wszystkie warunki: %d; bezpiecznie pominięte z powodu błędu lub blokady: %d\n", run.Purged, run.Errors)
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
		a.success("Trwałe usuwanie jest wyłączone.")
		return nil
	}
	if cfg.Safety.Mode != "active" {
		return errors.New("najpierw trzeba zakończyć tryb ochronny i włączyć tryb aktywny")
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
		return errors.New("tryb aktywny nie działa jeszcze od pełnych 30 dni; trwałe usuwanie pozostaje wyłączone")
	}
	trainedSpam, trainedHam, err := db.TrainingTotals(context.Background(), cfg.Account.Email)
	if err != nil {
		return err
	}
	if trainedSpam < cfg.Safety.MinLearnSpam || trainedHam < cfg.Safety.MinLearnHam {
		return fmt.Errorf(
			"za mało potwierdzonych przykładów: spam %d/%d, ważne %d/%d; trwałe usuwanie pozostaje wyłączone",
			trainedSpam, cfg.Safety.MinLearnSpam, trainedHam, cfg.Safety.MinLearnHam,
		)
	}
	falseSpam, falseHam, err := db.MisclassificationsSince(context.Background(), cfg.Account.Email, time.Now().Add(-30*24*time.Hour))
	if err != nil {
		return err
	}
	if falseSpam > 0 || falseHam > 0 {
		return fmt.Errorf(
			"w ostatnich 30 dniach wystąpiły sprzeczne korekty (ważne→spam: %d, spam→ważne: %d); trwałe usuwanie pozostaje wyłączone",
			falseSpam, falseHam,
		)
	}
	ok, err := a.confirmDanger("Od tej chwili robot będzie kasował ponownie potwierdzony spam po 30 dniach kwarantanny.", "WLACZ")
	if err != nil || !ok {
		return apperror.ErrCancelled
	}
	cfg.Safety.PurgeEnabled = true
	if err := config.Save(a.configPath, cfg); err != nil {
		return err
	}
	a.success("Trwałe usuwanie po 30 dniach jest włączone. Każde usunięcie nadal wymaga zaszyfrowanej kopii, zgodnej sumy kontrolnej i ponownego wyniku „spam”.")
	return nil
}

func (a *application) modeCommand(args []string) error {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "status" {
		fmt.Fprintf(a.out, "Tryb: %s; trwałe usuwanie: %s\n", modeName(cfg.Safety.Mode), yesNo(cfg.Safety.PurgeEnabled))
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
			a.info("Tryb ochronny jest już włączony. Bieżący okres obserwacji nie został zresetowany.")
			return nil
		}
		cfg.Safety.Mode = "protect"
		cfg.Safety.PurgeEnabled = false
		if err := config.Save(a.configPath, cfg); err != nil {
			return err
		}
		db, err := store.Open(cfg.Runtime.Database)
		if err != nil {
			return fmt.Errorf("tryb ochronny jest włączony, ale nie udało się wyzerować zegara trybu aktywnego: %w", err)
		}
		defer db.Close()
		if err := db.SetSetting(context.Background(), "active_since", ""); err != nil {
			return fmt.Errorf("tryb ochronny jest włączony, ale nie udało się wyzerować zegara trybu aktywnego: %w", err)
		}
		if err := db.SetSetting(context.Background(), "protect_since", time.Now().UTC().Format(time.RFC3339)); err != nil {
			return fmt.Errorf("tryb ochronny jest włączony, ale nie udało się uruchomić nowego okresu obserwacji: %w", err)
		}
		a.success("Włączono tryb ochronny. Odebrane nie będą automatycznie przenoszone.")
		return nil
	case "active":
		if cfg.Safety.Mode == "active" {
			a.info("Tryb aktywny jest już włączony. Zegar bezpieczeństwa dla trwałego usuwania nie został zmieniony.")
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
			return fmt.Errorf("nie mogę sprawdzić początku okresu ochronnego: %w", err)
		}
		installedAt, err := time.Parse(time.RFC3339, installedValue)
		if err != nil {
			return errors.New("nie mam prawidłowej daty rozpoczęcia okresu ochronnego; uruchom guardian setup, aby naprawić konfigurację")
		}
		protectAt := installedAt
		protectValue, err := db.GetSetting(ctx, "protect_since")
		if err != nil {
			return fmt.Errorf("nie mogę sprawdzić początku bieżącego okresu ochronnego: %w", err)
		}
		if protectValue != "" {
			protectAt, err = time.Parse(time.RFC3339, protectValue)
			if err != nil || protectAt.Before(installedAt) {
				return errors.New("data bieżącego okresu ochronnego jest nieprawidłowa; uruchom guardian setup")
			}
		}
		protectDuration := time.Duration(cfg.Safety.ProtectDays) * 24 * time.Hour
		if elapsed := time.Since(protectAt); elapsed < protectDuration {
			remaining := protectDuration - elapsed
			remainingDays := int((remaining + 24*time.Hour - 1) / (24 * time.Hour))
			return fmt.Errorf(
				"tryb aktywny jest jeszcze zablokowany dla bezpieczeństwa: okres ochronny trwa %d dni, spróbuj ponownie za około %d dni",
				cfg.Safety.ProtectDays, remainingDays,
			)
		}
		qualified, err := db.CurrentQualification(ctx, cfg, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("aktualna ocena filtra: %w", err)
		}
		quality, err := db.ActivationQuality(ctx, cfg.Account.Email, protectAt)
		if err != nil {
			return fmt.Errorf("nie mogę ocenić jakości dotychczasowych decyzji: %w", err)
		}
		if qualified == nil {
			if cfg.Rspamd.SpamScore < 12 {
				return errors.New("próg poniżej 12 wymaga odrębnej oceny: guardian qualify")
			}
			if err := activationQualityProblem(quality); err != nil {
				return err
			}
		}
		ok, err := a.confirmDanger("Tryb aktywny zacznie przenosić pewny spam z Odebranych do odwracalnej kwarantanny.", "AKTYWUJ")
		if err != nil || !ok {
			return apperror.ErrCancelled
		}
		cfg.Safety.Mode = "active"
		cfg.Safety.PurgeEnabled = false
		if err := db.SetSetting(ctx, "active_since", time.Now().UTC().Format(time.RFC3339)); err != nil {
			return fmt.Errorf("nie udało się uruchomić zegara bezpieczeństwa; tryb aktywny pozostaje wyłączony: %w", err)
		}
		if err := config.Save(a.configPath, cfg); err != nil {
			_ = db.SetSetting(ctx, "active_since", "")
			return err
		}
		a.success("Włączono tryb aktywny. Trwałe usuwanie nadal jest wyłączone.")
		return nil
	default:
		return errors.New("użyj: guardian mode status|protect|active")
	}
}

func (a *application) archiveCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("użyj: guardian archive list albo guardian archive restore ID")
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("archive list", flag.ContinueOnError)
		fs.SetOutput(a.errOut)
		page := fs.Int("page", 1, "numer strony")
		limit := fs.Int("limit", 100, "liczba pozycji na stronie")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("użyj: guardian archive list [--page N] [--limit N]")
		}
		if *page < 1 || *page > 1_000_000 {
			return errors.New("numer strony musi mieścić się między 1 a 1000000")
		}
		if *limit < 1 || *limit > 200 {
			return errors.New("liczba pozycji na stronie musi mieścić się między 1 a 200")
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
		a.header(fmt.Sprintf("Zaszyfrowane kopie — strona %d", *page))
		if len(items) == 0 {
			if *page == 1 {
				fmt.Fprintln(a.out, "Brak kopii.")
			} else {
				fmt.Fprintln(a.out, "Na tej stronie nie ma już kopii. Wróć do wcześniejszej strony.")
			}
			return nil
		}
		fmt.Fprintln(a.out, "ID    data                 werdykt       stan")
		for _, item := range items {
			fmt.Fprintf(a.out, "%-5d %-20s %-13s %s\n", item.ID, item.FirstSeen.Local().Format("2006-01-02 15:04"), item.Verdict, item.Status)
		}
		fmt.Fprintln(a.out, "\nAby rozpoznać wiadomość: guardian archive show ID")
		fmt.Fprintln(a.out, "Aby odzyskać: guardian archive restore ID")
		if len(items) == *limit {
			fmt.Fprintf(a.out, "Następna strona: guardian archive list --page %d --limit %d\n", *page+1, *limit)
		}
		return nil
	case "show":
		if len(args) != 2 {
			return errors.New("podaj ID, np. guardian archive show 12")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil || id < 1 {
			return errors.New("ID musi być dodatnią liczbą")
		}
		db, err := store.Open(cfg.Runtime.Database)
		if err != nil {
			return err
		}
		defer db.Close()
		record, err := db.MessageByID(context.Background(), id)
		if err != nil {
			return fmt.Errorf("nie znaleziono kopii o ID %d: %w", id, err)
		}
		if record.Account != cfg.Account.Email {
			return errors.New("ta kopia należy do innego konta")
		}
		if record.ArchivePath == "" {
			return errors.New("lokalna kopia tej wiadomości już wygasła albo nie została utworzona")
		}
		kc := runtimeSecrets(cfg)
		identity, err := archive.LoadIdentity(kc, cfg.Runtime.ArchiveKeychainService, cfg.Account.Email)
		if err != nil {
			return fmt.Errorf("nie mogę otworzyć klucza zaszyfrowanej kopii: %w", err)
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
			return errors.New("suma kontrolna odszyfrowanej kopii nie pasuje")
		}
		preview, err := parseArchiveHeaderPreview(raw)
		if err != nil {
			return fmt.Errorf("kopię można nadal odzyskać, ale jej nagłówki są uszkodzone: %w", err)
		}
		a.header(fmt.Sprintf("Podgląd kopii ID %d", id))
		fmt.Fprintf(a.out, "Od:    %s\nTemat: %s\nData:  %s\n", preview.From, preview.Subject, preview.Date)
		fmt.Fprintln(a.out, "\nPokazano wyłącznie oczyszczone nagłówki. Treść, HTML, odnośniki i załączniki nie zostały otwarte.")
		return nil
	case "restore":
		if len(args) != 2 {
			return errors.New("podaj ID, np. guardian archive restore 12")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil || id < 1 {
			return errors.New("ID musi być dodatnią liczbą")
		}
		ok, err := a.confirm("Przywrócić kopię do AI-Do-sprawdzenia jako nieprzeczytaną?", true)
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
				a.info("Wiadomość nadal istnieje w zapisanym folderze. Nie utworzono niepotrzebnego duplikatu.")
				return nil
			}
			return err
		}
		a.success("Wiadomość została odzyskana do AI-Do-sprawdzenia. Niczego nie wysłano.")
		return nil
	default:
		return errors.New("użyj: guardian archive list albo guardian archive restore ID")
	}
}

func (a *application) serviceCommand(args []string) error {
	if len(args) != 1 {
		return errors.New("użyj: guardian service install|status|uninstall")
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
			return fmt.Errorf("sprawdzenie zgody dry-run: %w", err)
		}
		if !authorized {
			return errors.New("najpierw wykonaj udany guardian run --dry-run; automatyzacja pozostała wyłączona")
		}
		if err := manager.Install(); err != nil {
			return err
		}
		a.success("Automatyczne sprawdzanie co 2 godziny jest aktywne.")
	case "status":
		status, err := manager.Status()
		if err != nil {
			return err
		}
		if strings.Contains(status, "state = running") {
			a.success("Usługa działa właśnie teraz.")
		} else {
			a.success("Usługa jest zainstalowana i czeka na kolejny przebieg.")
		}
	case "uninstall":
		if err := manager.Uninstall(); err != nil {
			return err
		}
		a.success("Automatyczne uruchamianie wyłączone. Wiadomości i dane pozostały bez zmian.")
	default:
		return errors.New("użyj: guardian service install|status|uninstall")
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
		return errors.New("użyj: guardian stack up|status|down")
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
		a.success("Lokalny silnik działa.")
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
		a.success("Silnik zatrzymany. Dane Bayesa pozostały zachowane.")
	default:
		return errors.New("użyj: guardian stack up|status|down")
	}
	return nil
}

// repair wykonuje wyłącznie odwracalne naprawy lokalnej instalacji. Nie zmienia
// trybu ochrony, nie włącza trwałego usuwania i nie przenosi wiadomości.
func (a *application) repair() error {
	a.header("Sprawdź i napraw program")
	fmt.Fprintln(a.out, "Ta kontrola nie przenosi ani nie usuwa wiadomości i nie zmienia trybu ochrony.")

	cfg, err := config.Load(a.configPath)
	if err != nil {
		return fmt.Errorf("program nie jest jeszcze skonfigurowany: %w\nOtwórz menu i wybierz „Rozpocznij pierwszą konfigurację”", err)
	}
	lock, err := acquireRunLock(cfg.Runtime.DataDir)
	if err != nil {
		return err
	}
	defer lock.Close()

	a.info("Etap 1 z 3: uruchamiam lokalny filtr antyspamowy…")
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
			"nie udało się uruchomić lokalnego filtra: %w\nAutomatyzacja i ustawienia bezpieczeństwa pozostały bez zmian",
			err,
		)
	}
	a.success("Lokalny filtr jest uruchomiony.")

	a.info("Etap 2 z 3: sprawdzam szyfrowanie, kopie, filtr i połączenie z o2…")
	checkInstallation := a.checkInstallation
	if checkInstallation == nil {
		checkInstallation = func() error { return a.doctor(false, false) }
	}
	if err := checkInstallation(); err != nil {
		return fmt.Errorf(
			"kontrola nie została zaliczona: %w\nAutomatyzacja i ustawienia bezpieczeństwa pozostały bez zmian",
			err,
		)
	}
	// Bootstrap usługi launchd może od razu uruchomić pierwszy przebieg.
	// Zwolnij blokadę, aby ten bezpieczny przebieg nie odbił się od naprawy.
	if err := lock.Close(); err != nil {
		return fmt.Errorf("kontrole przeszły pomyślnie, ale nie mogę bezpiecznie zwolnić blokady programu; automatyzacja pozostała bez zmian: %w", err)
	}

	a.info("Etap 3 z 3: sprawdzam automatyczne uruchamianie…")
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("nie mogę ustalić położenia programu; automatyzacja pozostała bez zmian: %w", err)
	}
	manager := service.Manager{Executable: exe, DataDir: cfg.Runtime.DataDir, LogFile: cfg.Runtime.LogFile}
	dryRunReady, err := dryRunAuthorized(cfg)
	if err != nil {
		return fmt.Errorf("nie można potwierdzić obowiązkowej próby bez zmian: %w", err)
	}
	if !dryRunReady {
		disableAutomation := a.disableAutomation
		if disableAutomation == nil {
			disableAutomation = func(config.Config) error { return manager.Uninstall() }
		}
		if err := disableAutomation(cfg); err != nil {
			return fmt.Errorf("dry-run wymaga ponownego wykonania, ale nie udało się zatrzymać automatu: %w", err)
		}
		a.warning("Automatyzacja pozostaje wyłączona, ponieważ trzeba ponownie wykonać bezpieczny dry-run.")
		a.success("Pozostałe kontrole i naprawy zakończono pomyślnie.")
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
		a.info("Automatyczne sprawdzanie jest aktywne. Odświeżam jego pliki startowe i zabezpieczenia…")
		if err := enableAutomation(cfg); err != nil {
			return fmt.Errorf("kontrole przeszły pomyślnie, ale nie udało się bezpiecznie odświeżyć automatyzacji: %w", err)
		}
		a.success("Automatyczne sprawdzanie co 2 godziny jest aktywne i odświeżone.")
		a.success("Program działa prawidłowo. Nie trzeba nic więcej robić.")
		return nil
	}

	a.warning("Automatyczne sprawdzanie co 2 godziny nie jest aktywne.")
	if !a.interactive {
		a.info("Zachowano tryb ręczny. Automat możesz włączyć osobnym przełącznikiem po zakończeniu naprawy.")
		a.success("Pozostałe kontrole zakończono pomyślnie.")
		return nil
	}
	ok, err := a.confirm("Czy włączyć je teraz?", true)
	if err != nil {
		return fmt.Errorf("automatyzacja pozostała wyłączona: %w", err)
	}
	if !ok {
		a.info("Automatyzacja pozostała wyłączona zgodnie z Twoim wyborem.")
		a.success("Pozostałe kontrole zakończono pomyślnie.")
		return nil
	}
	if err := enableAutomation(cfg); err != nil {
		return fmt.Errorf("kontrole przeszły pomyślnie, ale nie udało się włączyć automatyzacji: %w", err)
	}
	a.success("Automatyczne sprawdzanie co 2 godziny zostało włączone.")
	a.success("Program działa prawidłowo. Nie trzeba nic więcej robić.")
	return nil
}

func (a *application) menu() error {
	for {
		cfg, cfgErr := config.Load(a.configPath)
		a.header("Menu")
		if cfgErr != nil {
			fmt.Fprintln(a.out, "Guardian czeka na pierwszą konfigurację. Żadna wiadomość nie została zmieniona.")
			fmt.Fprintln(a.out, `
  1. Rozpocznij pierwszą konfigurację
  0. Zakończ`)
			choice, err := a.ask("Wybierz numer", "")
			if err != nil {
				return err
			}
			switch choice {
			case "1":
				if actionErr := a.setup(); actionErr != nil {
					a.problemWithAdvice(actionErr)
				}
				_, _ = a.ask("Naciśnij Enter, aby wrócić do menu", "")
			case "0", "q", "Q":
				return nil
			default:
				a.warning("Wpisz 1, aby rozpocząć, albo 0, aby zakończyć.")
			}
			continue
		}

		fmt.Fprintf(a.out, "Tryb: %s | trwałe usuwanie: %s\n", modeName(cfg.Safety.Mode), yesNo(cfg.Safety.PurgeEnabled))
		fmt.Fprintln(a.out, `
  1. Sprawdź skrzynkę teraz
  2. Pokaż stan i zalecenia
  3. Sprawdź i napraw program
  4. Jak poprawić pomyłkę robota
  5. Odzyskaj wiadomość z kopii
  6. Ustawienia i opcje dodatkowe
  0. Zakończ`)
		choice, err := a.ask("Wybierz numer", "")
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
			a.warning("Nie ma takiej pozycji. Wpisz numer od 0 do 6.")
		}
		if actionErr != nil {
			a.problemWithAdvice(actionErr)
		}
		_, _ = a.ask("Naciśnij Enter, aby wrócić do menu", "")
	}
}

func (a *application) optionsMenu(cfg config.Config) error {
	fmt.Fprintln(a.out, `
  1. Ustawienia trybu ochrony
  2. Próba bez przenoszenia wiadomości
  3. Zaktualizuj konfigurację konta
  4. Pokaż techniczny stan lokalnego filtra
  0. Wróć do głównego menu`)
	value, err := a.ask("Wybierz numer", "")
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
		return errors.New("nie ma takiej pozycji; wybierz numer od 0 do 4")
	}
}

func (a *application) modeMenu(cfg config.Config, cfgErr error) error {
	if cfgErr != nil {
		return cfgErr
	}
	fmt.Fprintln(a.out, `
  1. Włącz tryb ochronny (najbezpieczniejszy)
  2. Włącz tryb aktywny
  3. Włącz trwałe usuwanie po 30 dniach
  4. Wyłącz trwałe usuwanie
  0. Wróć bez zmian`)
	value, err := a.ask("Wybierz numer", "")
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
		return errors.New("nie ma takiej pozycji; wybierz numer od 0 do 4")
	}
}

func (a *application) archiveMenu() error {
	for page := 1; ; page++ {
		if err := a.archiveCommand([]string{"list", "--page", strconv.Itoa(page), "--limit", "100"}); err != nil {
			return err
		}
		value, err := a.ask("Podaj ID, N aby zobaczyć następną stronę albo Enter, aby wrócić", "")
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
			return "(brak)"
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
	fmt.Fprintln(a.out, `
Gdy robot się pomyli, przeciągnij wiadomość w webmailu lub programie pocztowym:

  • przeoczony spam         → AI-Naucz-spam
  • ważna wiadomość w złym miejscu → AI-Naucz-wazne

Przy kolejnym przebiegu robot nauczy Rspamd i przeniesie wiadomość do właściwego
folderu. Nie trzeba otwierać wiadomości ani klikać żadnych odnośników.`)
}

func (a *application) openRuntime(withMail bool) (*runtimeApp, func(), error) {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return nil, func() {}, apperror.Wrap(apperror.Config, "critical", "Konfiguracja Guardiana jest nieczytelna.", "Otwórz aplikację i rozpocznij konfigurację albo użyj Napraw.", err)
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
		return nil, func() {}, fmt.Errorf("nie można odczytać sekretu kontrolera Rspamd: %w", err)
	}
	scanner := rspamd.New(cfg.Rspamd.ScanURL, cfg.Rspamd.LearnURL, controller, time.Duration(cfg.Rspamd.TimeoutSeconds)*time.Second)
	id, err := archive.LoadIdentity(kc, cfg.Runtime.ArchiveKeychainService, cfg.Account.Email)
	if err != nil {
		cleanup()
		return nil, func() {}, apperror.Wrap(apperror.ArchiveKey, "critical", "Nie można odczytać klucza zaszyfrowanych kopii.", "Nie usuwaj archiwum; odblokuj pęk kluczy i uruchom Napraw.", err)
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
			return nil, func() {}, apperror.Wrap(apperror.Keychain, "critical", "Nie można odczytać hasła o2 z pęku kluczy.", "Odblokuj pęk kluczy lub zapisz ponownie hasło aplikacyjne.", err)
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
				apperror.Rspamd, "critical", "Nie można potwierdzić ciągłości lokalnego modelu Bayesa.",
				"Uruchom „Napraw”, zanim Guardian wykona automatyczne decyzje.", err,
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
			return 0, true, fmt.Errorf("nieprawidłowy licznik %s", key)
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
		a.warning("Nie udało się przygotować dziennego powiadomienia: " + err.Error())
		return
	}
	message := fmt.Sprintf("Uratowane: %d, kwarantanna: %d, do sprawdzenia: %d, błędy: %d",
		summary.Rescued, summary.Quarantined, summary.WaitingReview, summary.Errors)
	if err := a.notify("O2 Mail Guardian", message); err != nil {
		a.warning("Nie udało się wyświetlić dziennego powiadomienia.")
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
		"O2 Mail Guardian wymaga uwagi",
		"Automatyczne sprawdzanie nie zakończyło się poprawnie. Poczta nie została usunięta. Otwórz Guardian i wybierz „Sprawdź i napraw program”.",
	); err != nil {
		a.warning("Nie udało się wyświetlić powiadomienia o problemie.")
		return
	}
	if err := db.SetSetting(ctx, "last_failure_notification", time.Now().UTC().Format(time.RFC3339)); err != nil {
		a.warning("Nie udało się zapisać czasu powiadomienia o problemie.")
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
	fmt.Fprintln(a.out, "\nPodsumowanie:")
	fmt.Fprintf(a.out, "  Sprawdzone:      %d\n", run.Scanned)
	fmt.Fprintf(a.out, "  Uratowane:       %d\n", run.Rescued)
	fmt.Fprintf(a.out, "  Kwarantanna:     %d\n", run.Quarantined)
	fmt.Fprintf(a.out, "  Do sprawdzenia:  %d\n", run.Review)
	fmt.Fprintf(a.out, "  Nauczone spam/ważne: %d/%d\n", run.LearnedSpam, run.LearnedHam)
	fmt.Fprintf(a.out, "  Błędy bez utraty poczty: %d\n", run.Errors)
	if run.Errors > 0 {
		a.warning("Nie wszystkie wiadomości udało się sprawdzić. Pozostały bezpiecznie na serwerze; wybierz w menu „Sprawdź i napraw program”.")
	} else if run.Review > 0 {
		a.info("Zajrzyj do folderu AI-Do-sprawdzenia — są tam wiadomości wymagające Twojej decyzji.")
	} else {
		a.success("Sprawdzanie zakończone.")
	}
}

func (a *application) readHiddenPassword(question string) (string, error) {
	fmt.Fprintf(a.out, "%s (wpisywane znaki nie będą widoczne): ", question)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(a.out)
		return "", errors.New("bezpieczne wpisanie hasła wymaga interaktywnego okna Terminala; otwórz Guardian.command i ponów konfigurację")
	}
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(a.out)
	if err != nil {
		return "", fmt.Errorf("nie mogę bezpiecznie odczytać hasła: %w", err)
	}
	password := strings.TrimSpace(string(value))
	if password == "" {
		return "", errors.New("hasło aplikacyjne nie może być puste")
	}
	if strings.ContainsAny(password, "\r\n\x00") {
		return "", errors.New("hasło aplikacyjne ma niedozwolony format")
	}
	return password, nil
}

func verifyAndStorePassword(password string, verify, storeSecret func(string) error) error {
	if password == "" {
		return errors.New("hasło aplikacyjne nie może być puste")
	}
	if err := verify(password); err != nil {
		return fmt.Errorf("o2 odrzuciło nowe hasło lub połączenie nie powiodło się: %w", err)
	}
	if err := storeSecret(password); err != nil {
		return fmt.Errorf("hasło działa, ale nie udało się zapisać go w pęku kluczy: %w", err)
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
	hint := "[T/n]"
	if !defaultYes {
		hint = "[t/N]"
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
		return false, errors.New("odpowiedz „tak” albo „nie”")
	}
}

func (a *application) confirmDanger(message, phrase string) (bool, error) {
	fmt.Fprintf(a.out, "\n%s\nAby potwierdzić, wpisz dokładnie %s: ", message, phrase)
	value, err := a.in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return strings.TrimSpace(value) == phrase, nil
}

func (a *application) header(title string) {
	fmt.Fprintf(a.out, "\n%s%sO2 Mail Guardian — %s%s\n", a.c(blue), a.c(bold), title, a.c(reset))
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
	fmt.Fprintf(a.errOut, "%sBłąd:%s %v\n", a.c(red), a.c(reset), err)
}
func (a *application) problemWithAdvice(err error) {
	userError := apperror.From(err)
	if userError.Severity == "info" {
		a.info(userError.Message + " " + userError.Recovery)
		return
	}
	a.problem(errors.New(userError.Message))
	if userError.Recovery != "" {
		a.info("Co możesz zrobić: " + userError.Recovery)
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
		return nil, fmt.Errorf("nie mogę przygotować prywatnego katalogu danych: %w", err)
	}
	lock, err := runlock.Acquire(filepath.Join(dataDir, "guardian.lock"))
	if err != nil {
		return nil, apperror.Wrap(
			apperror.Busy, "attention", "Guardian wykonuje już inną operację.",
			"Poczekaj kilka minut i spróbuj ponownie.", err,
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
		return false, fmt.Errorf("%s nie jest zwykłym plikiem", path)
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
			apperror.ArchiveKey, "critical", "Nie można bezpiecznie sprawdzić wcześniejszych danych Guardiana.",
			"Nie twórz nowego klucza; uruchom Napraw i zachowaj bazę oraz archiwum.", err,
		)
	}
	if hasDependentData {
		return apperror.Wrap(
			apperror.ArchiveKey, "critical", "Brakuje dotychczasowego klucza szyfrowania, ale istnieją wcześniejsze dane Guardiana.",
			"Odtwórz klucz archiwum w pęku kluczy. Guardian nie zastąpi go nowym kluczem.", nil,
		)
	}
	return nil
}

func archiveIdentityHasDependentData(archiveDir, database string) (bool, error) {
	hasEncryptedFiles, err := archive.HasEncryptedFiles(archiveDir)
	if err != nil {
		return false, fmt.Errorf("sprawdzenie zaszyfrowanych kopii: %w", err)
	}
	hasDatabase, err := nonemptyFile(database)
	if err != nil {
		return false, fmt.Errorf("sprawdzenie bazy Guardiana: %w", err)
	}
	return hasEncryptedFiles || hasDatabase, nil
}

func rollbackNewArchiveIdentity(store secretStore, service, account, archiveDir, database string) error {
	hasDependentData, err := archiveIdentityHasDependentData(archiveDir, database)
	if err != nil {
		return fmt.Errorf("nie można potwierdzić, że nowy klucz archiwum jest zbędny; został zachowany: %w", err)
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
			"%d ważnych wiadomości otrzymało wcześniej pewny werdykt „spam”",
			quality.FalsePositives,
		))
	}
	if quality.FalseRescues > 0 {
		reasons = append(reasons, fmt.Sprintf(
			"%d wiadomości oznaczonych później jako spam zostało wcześniej automatycznie uratowanych",
			quality.FalseRescues,
		))
	}
	if quality.SpamFeedback == 0 {
		reasons = append(reasons, "nie oznaczono jeszcze żadnej wiadomości w folderze AI-Naucz-spam")
	} else {
		percent := quality.SpamPreviouslySpam * 100 / quality.SpamFeedback
		if quality.SpamPreviouslySpam*100 < quality.SpamFeedback*90 {
			reasons = append(reasons, fmt.Sprintf(
				"robot rozpoznał wcześniej jako pewny spam tylko %d z %d oznaczonych wiadomości (%d%%); wymagane jest co najmniej 90%%",
				quality.SpamPreviouslySpam, quality.SpamFeedback, percent,
			))
		}
	}
	if quality.SpamUnexplained > 0 {
		reasons = append(reasons, fmt.Sprintf(
			"%d oznaczonych spamów nie miało wcześniej werdyktu „spam” ani „do ręcznego sprawdzenia”",
			quality.SpamUnexplained,
		))
	}
	if len(reasons) == 0 && !quality.Ready() {
		reasons = append(reasons, "zebrane wyniki nie spełniają jeszcze wszystkich warunków bezpieczeństwa")
	}
	if len(reasons) == 0 {
		return nil
	}
	return errors.New(
		"tryb aktywny pozostaje wyłączony, ponieważ:\n  • " +
			strings.Join(reasons, "\n  • ") +
			"\nPozostań w trybie ochronnym, poprawiaj pomyłki w folderach nauki i spróbuj ponownie po dalszej obserwacji",
	)
}

func modeName(mode string) string {
	if mode == "active" {
		return "aktywny (kwarantanna)"
	}
	return "ochronny"
}
func yesNo(v bool) string {
	if v {
		return "włączone"
	}
	return "wyłączone"
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
