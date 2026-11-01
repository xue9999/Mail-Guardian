package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/platform"
	"github.com/o2-mail-guardian/guardian/internal/service"
	"github.com/o2-mail-guardian/guardian/internal/stack"
)

// Linux supports the existing protect/active policies. Active mailbox work
// still passes the engine's normal history/quality and dry-run gates.
func validateLinuxConfig(cfg config.Config, instance string) error {
	if len(instance) > 29 {
		return errors.New("Linux instance name exceeds the dedicated user name limit (29 characters)")
	}
	paths, err := platform.LinuxPaths(instance)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	for _, pair := range [][2]string{
		{cfg.Runtime.DataDir, paths.Data}, {cfg.Runtime.Database, paths.Database},
		{cfg.Runtime.ArchiveDir, paths.Archive}, {cfg.Runtime.LogFile, paths.Log},
		{cfg.Runtime.ComposeFile, paths.Compose},
	} {
		if pair[0] != pair[1] {
			return fmt.Errorf("Linux instance %q requires path %s", instance, pair[1])
		}
	}
	if cfg.Safety.PurgeEnabled {
		return errors.New("Linux deployment requires permanent deletion disabled")
	}
	return nil
}

func linuxInstance(cfg config.Config) string { return filepath.Base(cfg.Runtime.DataDir) }

func runtimeStack(cfg config.Config) stack.Manager {
	m := stack.Manager{ComposeFile: cfg.Runtime.ComposeFile, RuntimeDir: config.DefaultRuntimeDir()}
	if runtime.GOOS == "linux" {
		m.Instance = linuxInstance(cfg)
	}
	return m
}

func (a *application) validateLinuxRuntime() error {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	instance := linuxInstance(cfg)
	if err := validateLinuxConfig(cfg, instance); err != nil {
		return err
	}
	paths, _ := platform.LinuxPaths(instance)
	if a.configPath != paths.Config {
		return fmt.Errorf("Linux worker requires explicit --config %s", paths.Config)
	}
	return validateAdministratorPath(paths.Config)
}

func validateAdministratorPath(path string) error {
	for current := path; current != "/"; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("administrator-owned path required: %s", current)
		}
		if current == path && (!info.Mode().IsRegular() || info.Mode().Perm()&0o007 != 0) {
			return errors.New("Linux configuration must be a private regular file")
		}
	}
	return nil
}

func (a *application) serverCommand(args []string) error {
	return a.serverCommandWithConfigWriter(args, nil)
}

// A separate writer allows unit tests to use an isolated private fixture;
// production always selects the platform-specific implementation below.
func (a *application) serverCommandWithConfigWriter(args []string, writer func(string, []byte) error) error {
	if len(args) == 0 {
		return errors.New("use: guardian server init-config|validate-config|adopt-policy")
	}
	fs := flag.NewFlagSet("server "+args[0], flag.ContinueOnError)
	fs.SetOutput(a.errOut)
	instance := fs.String("instance", "", "Linux instance name")
	if args[0] == "adopt-policy" {
		preserve := fs.Bool("preserve-policy", false, "explicitly retain validated source policy history; a new dry-run remains required")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || !*preserve {
			return errors.New("use: guardian --config /etc/mail-guardian/NAME/config.toml server adopt-policy --instance NAME --preserve-policy")
		}
		return a.adoptLinuxPolicy(*instance)
	}
	if args[0] == "validate-config" {
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected validation arguments")
		}
		cfg, err := config.Load(a.configPath)
		if err != nil {
			return err
		}
		if err := validateLinuxConfig(cfg, *instance); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "Linux configuration valid for instance %s; no mailbox accessed.\n", *instance)
		return nil
	}
	if args[0] != "init-config" {
		return errors.New("use: guardian server init-config|validate-config|adopt-policy")
	}
	email := fs.String("email", "", "mailbox email")
	mode := fs.String("mode", "protect", "filtering policy: protect or active (activation history and fresh dry-run remain required)")
	spam := fs.String("server-spam", "", "confirmed server spam folder")
	output := fs.String("output", "", "new configuration file (never overwritten)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *output == "" {
		return errors.New("use: guardian server init-config --instance NAME --email EMAIL --server-spam FOLDER --output NEW-FILE")
	}
	paths, err := platform.LinuxPaths(*instance)
	if err != nil {
		return err
	}
	cfg, err := config.NewInstance()
	if err != nil {
		return err
	}
	cfg.Account.Email, cfg.Account.Username = *email, *email
	cfg.Safety.Mode = *mode
	cfg.Folders.ServerSpam = *spam
	cfg.Runtime.DataDir, cfg.Runtime.Database = paths.Data, paths.Database
	cfg.Runtime.ArchiveDir, cfg.Runtime.LogFile, cfg.Runtime.ComposeFile = paths.Archive, paths.Log, paths.Compose
	if err := validateLinuxConfig(cfg, *instance); err != nil {
		return err
	}
	var data bytes.Buffer
	if err := toml.NewEncoder(&data).Encode(cfg); err != nil {
		return err
	}
	if writer != nil {
		if err := writer(*output, data.Bytes()); err != nil {
			return err
		}
	} else if runtime.GOOS == "linux" {
		if err := writeLinuxInitialConfig(*output, data.Bytes()); err != nil {
			return err
		}
	} else {
		f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(data.Bytes())
		syncErr, closeErr := f.Sync(), f.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			_ = os.Remove(*output)
			return err
		}
	}
	fmt.Fprintf(a.out, "Created %s. Scheduling is off; credentials and mailbox acceptance are still required.\n", *output)
	return nil
}

// Bind a copied database to this deployment as well as to its mailbox. Runtime
// paths alone are not a mailbox fingerprint and must not inherit authorization.
func linuxDeploymentID(cfg config.Config) (string, error) {
	machine, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(machine))
	if raw, err := hex.DecodeString(id); err != nil || len(raw) != 16 {
		return "", errors.New("Linux host has no valid machine-id")
	}
	sum := sha256.Sum256([]byte(id + "\x00" + cfg.Runtime.DataDir + "\x00" + cfg.InstanceID))
	return hex.EncodeToString(sum[:]), nil
}

// Keep the readiness checks, heartbeat, and all modifying work under the same
// lock. A concurrent invocation cannot overwrite the active worker's heartbeat.
func (a *application) linuxServiceRun() (retErr error) {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	lock, err := acquireRunLock(cfg.Runtime.DataDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	heartbeat, _ := service.ReadHeartbeat(cfg.Runtime.DataDir)
	now := time.Now().UTC()
	heartbeat.LastAttempt, heartbeat.Stage, heartbeat.ErrorCode, heartbeat.Version = &now, "stack", "", version
	if err := service.WriteHeartbeat(cfg.Runtime.DataDir, heartbeat); err != nil {
		return err
	}
	defer func() {
		finished := time.Now().UTC()
		if retErr == nil {
			heartbeat.LastSuccess, heartbeat.Stage, heartbeat.ErrorCode = &finished, "ok", ""
		} else {
			heartbeat.Stage, heartbeat.ErrorCode = "failed", "server_run_failed"
		}
		retErr = errors.Join(retErr, service.WriteHeartbeat(cfg.Runtime.DataDir, heartbeat))
	}()
	if err := runtimeStack(cfg).Up(); err != nil {
		return err
	}
	heartbeat.Stage = "mailbox"
	if err := service.WriteHeartbeat(cfg.Runtime.DataDir, heartbeat); err != nil {
		return err
	}
	run, err := a.runCommandResultLocked(nil, true)
	return requireSuccessfulRun(run, err)
}

func bindLinuxDeployment(ctx context.Context, rt *runtimeApp) error {
	id, err := linuxDeploymentID(rt.cfg)
	if err != nil {
		return err
	}
	return rt.db.BindDeployment(ctx, id, time.Now())
}
