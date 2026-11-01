package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// A Linux configuration is staged in /root and later reviewed and installed
// by the administrator. It must never write inside a live instance tree (or
// via a symlink to one), including while a migration is fenced. Restricting
// the parent to the fixed root directory also avoids path aliases and ancestor
// traversal; opening the directory and then the new file pins the destination.
func writeLinuxInitialConfig(output string, data []byte) error {
	if os.Geteuid() != 0 {
		return errors.New("Linux server init-config must run as root and write a new file directly under /root")
	}
	return createPrivateInitialConfig("/root", output, data, 0)
}

func createPrivateInitialConfig(directory, output string, data []byte, requiredUID uint32) error {
	if !filepath.IsAbs(output) || filepath.Clean(output) != output || filepath.Dir(output) != directory {
		return errors.New("configuration output must be a new file directly under the private administrator directory")
	}
	name := filepath.Base(output)
	if name == "." || name == ".." || name == "/" {
		return errors.New("invalid configuration filename")
	}
	dirFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("private administrator directory unavailable: %w", err)
	}
	dir := os.NewFile(uintptr(dirFD), directory)
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || st.Uid != requiredUID ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("administrator directory must be private and owned by the administrator")
	}
	fd, err := unix.Openat(dirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), output)
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = unix.Unlinkat(dirFD, name, 0)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	n, err := f.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	keep = true
	return nil
}
