package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// acquireMigrationFence holds the administrator-owned shared lock for a
// complete Linux runtime command. The administrator must hold its exclusive
// counterpart whenever creating/removing migration-pending or publishing a
// migration. This avoids a marker check racing an ongoing command. A missing
// lock is intentionally an error, including on partially upgraded systems.
// The caller has already validated the configuration path and its ancestors.
func acquireMigrationFence(instanceDir string, administratorUID uint32) (*os.File, error) {
	return acquireMigrationFenceMode(instanceDir, administratorUID, unix.LOCK_SH)
}

func acquireMigrationFenceMode(instanceDir string, administratorUID uint32, mode int) (*os.File, error) {
	info, err := os.Lstat(instanceDir)
	if err != nil {
		return nil, fmt.Errorf("migration fence directory unavailable: %w", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		info.Mode().Perm() != 0o750 || st.Uid != administratorUID {
		return nil, errors.New("migration fence directory is not administrator-controlled")
	}
	lockPath := filepath.Join(instanceDir, "migration.lock")
	fd, err := unix.Open(lockPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("migration fence unavailable: %w", err)
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	valid := false
	defer func() {
		if !valid {
			_ = lock.Close()
		}
	}()
	lockInfo, err := lock.Stat()
	if err != nil {
		return nil, fmt.Errorf("migration fence metadata unavailable: %w", err)
	}
	lockStat, ok := lockInfo.Sys().(*syscall.Stat_t)
	if !ok || !lockInfo.Mode().IsRegular() || lockInfo.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || lockInfo.Mode().Perm() != 0o640 ||
		lockStat.Uid != administratorUID || lockStat.Gid != st.Gid || lockStat.Nlink != 1 {
		return nil, errors.New("migration fence has unsafe owner, group, mode or links")
	}
	if err := unix.Flock(fd, mode|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("migration fence is held or unavailable: %w", err)
	}
	// Check after taking the shared lock. The administrator's exclusive-lock
	// protocol keeps this result stable until the command releases its lock.
	_, err = os.Lstat(filepath.Join(instanceDir, "migration-pending"))
	if err == nil {
		return nil, errors.New("migration is pending; Guardian operations are blocked")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("migration state unavailable: %w", err)
	}
	valid = true
	return lock, nil
}
