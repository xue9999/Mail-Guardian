package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/engine"
	"github.com/o2-mail-guardian/guardian/internal/platform"
	"github.com/o2-mail-guardian/guardian/internal/store"
	"golang.org/x/sys/unix"
)

// adoptLinuxPolicy is an explicit administrator action after verified state
// import. It does not read credentials, connect to mail, start containers or
// enable scheduling. Source-owner fencing and complete recovery verification
// remain the deployment coordinator's responsibility.
func (a *application) adoptLinuxPolicy(instance string) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("server adopt-policy requires the Linux administrator")
	}
	paths, err := platform.LinuxPaths(instance)
	if err != nil {
		return err
	}
	if a.configPath != paths.Config {
		return fmt.Errorf("policy adoption requires explicit --config %s", paths.Config)
	}
	if err := a.validateLinuxRuntime(); err != nil {
		return err
	}
	fence, err := acquireMigrationFenceMode(filepath.Dir(a.configPath), 0, unix.LOCK_EX)
	if err != nil {
		return err
	}
	defer fence.Close()
	if err := a.validateLinuxRuntime(); err != nil {
		return err
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	lock, err := acquirePolicyRunLock(cfg.Runtime.DataDir, instance)
	if err != nil {
		return err
	}
	defer lock.Close()
	info, err := os.Lstat(cfg.Runtime.Database)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("policy adoption requires an existing private database")
	}
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		return err
	}
	defer db.Close()
	id, err := linuxDeploymentID(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := adoptPolicyState(ctx, cfg, db, id, time.Now().UTC()); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Existing filtering policy history validated and retained for this host. A new successful server dry-run is required; no mailbox accessed and scheduling remains unchanged.")
	return nil
}

// Adoption runs as root before the worker's first invocation. Create its lock
// without following links and give it the worker's ownership; otherwise a new
// root-owned 0600 lock would prevent the first real worker from starting.
func acquirePolicyRunLock(dataDir, instance string) (*os.File, error) {
	account, err := user.Lookup("mg-" + instance)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return nil, err
	}
	return acquirePolicyRunLockForOwner(dataDir, uid, gid)
}

func acquirePolicyRunLockForOwner(dataDir string, uid, gid int) (*os.File, error) {
	dirFD, err := unix.Open(dataDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFD)
	var dirInfo unix.Stat_t
	if err := unix.Fstat(dirFD, &dirInfo); err != nil || dirInfo.Uid != uint32(uid) || dirInfo.Gid != uint32(gid) || dirInfo.Mode&0o7777 != 0o700 {
		return nil, errors.New("policy adoption requires the private worker-owned data directory")
	}
	fd, err := unix.Openat(dirFD, "guardian.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(dataDir, "guardian.lock"))
	valid := false
	defer func() {
		if !valid {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || st.Nlink != 1 || (st.Uid != 0 && st.Uid != uint32(uid)) {
		return nil, errors.New("policy adoption requires a private regular instance lock")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("instance lock held or unavailable: %w", err)
	}
	if err := f.Chown(uid, gid); err != nil {
		return nil, err
	}
	valid = true
	return f, nil
}

func adoptPolicyState(ctx context.Context, cfg config.Config, db *store.DB, identity string, now time.Time) error {
	if err := db.IntegrityCheck(ctx); err != nil {
		return err
	}
	if cfg.Safety.PurgeEnabled {
		return errors.New("permanent deletion must remain disabled")
	}
	matches, err := db.ConfigurationMatches(ctx, cfg)
	if err != nil {
		return err
	}
	if !matches {
		return errors.New("imported history does not match the destination mailbox and folders")
	}
	if cfg.Safety.Mode == "active" {
		proof := engine.Engine{Config: cfg, Store: db, Now: func() time.Time { return now }}
		if err := proof.ValidateActivePolicy(ctx); err != nil {
			return fmt.Errorf("existing active policy is not qualified: %w", err)
		}
	}
	return db.ReauthorizeDeployment(ctx, cfg, identity)
}
