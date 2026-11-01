package secrets

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Credentials reads the three named files delivered by systemd. Bindings are
// explicit so an unrelated service/account cannot read another credential.
// Provisioning and onboarding writes belong to a separate administrator path.
type Credentials struct {
	Directory string
	Bindings  map[Key]string
}

type credentialAccess struct {
	uid, gid    uint32
	systemdView bool
}

// Group-readable delivery is permitted only for systemd's fixed Linux runtime
// credential tree and the exact directory selected for this service. Ordinary
// credential directories retain their private-file requirement.
func systemdCredentialDirectory(directory, goos, environment string) bool {
	return goos == "linux" && directory == environment && filepath.IsAbs(directory) &&
		filepath.Clean(directory) == directory &&
		strings.HasPrefix(directory, "/run/credentials/") &&
		filepath.Base(directory) != "." && filepath.Base(directory) != "credentials" &&
		filepath.Dir(directory) == "/run/credentials"
}

func credentialDirectoryAccess(info os.FileInfo, access credentialAccess) (bool, error) {
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false, errors.New("credentials directory must be private and not a symlink")
	}
	if info.Mode().Perm()&0o077 == 0 && (metadata.Uid == 0 || metadata.Uid == access.uid) {
		return false, nil
	}
	if access.systemdView && metadata.Uid == 0 && (metadata.Gid == access.gid || metadata.Gid == 0) && info.Mode().Perm() == 0o550 {
		return true, nil
	}
	return false, errors.New("credentials directory has unsafe ownership, group or permissions")
}

func validateCredentialFile(info os.FileInfo, access credentialAccess, groupView bool) error {
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || metadata.Nlink != 1 {
		return errors.New("credential must be a regular file without links")
	}
	if groupView {
		if access.systemdView && metadata.Uid == 0 && (metadata.Gid == access.gid || metadata.Gid == 0) && info.Mode().Perm() == 0o440 {
			return nil
		}
	} else if info.Mode().Perm()&0o077 == 0 && (metadata.Uid == 0 || metadata.Uid == access.uid) {
		return nil
	}
	return errors.New("credential has unsafe ownership, group or permissions")
}

// Linux systemd may expose root:root files with a POSIX ACL granting the
// service UID read access. The stat group bits are then the ACL mask, not a
// grant to root's group. Accept exactly that five-entry read-only ACL, with no
// additional named user/group entries or effective group/other access.
func validSystemdCredentialACL(raw []byte, uid uint32, directory bool) bool {
	if len(raw) != 4+5*8 || binary.LittleEndian.Uint32(raw[:4]) != 2 {
		return false
	}
	permission := uint16(4)
	if directory {
		permission = 5
	}
	expected := [5]struct {
		tag, permission uint16
		id              uint32
	}{
		{1, permission, ^uint32(0)},  // ACL_USER_OBJ
		{2, permission, uid},         // the one service UID
		{4, 0, ^uint32(0)},           // ACL_GROUP_OBJ
		{16, permission, ^uint32(0)}, // ACL_MASK
		{32, 0, ^uint32(0)},          // ACL_OTHER
	}
	for i, entry := range expected {
		offset := 4 + i*8
		if binary.LittleEndian.Uint16(raw[offset:]) != entry.tag ||
			binary.LittleEndian.Uint16(raw[offset+2:]) != entry.permission ||
			binary.LittleEndian.Uint32(raw[offset+4:]) != entry.id {
			return false
		}
	}
	return true
}

func validateSystemdCredentialACL(raw []byte, info os.FileInfo, access credentialAccess, directory bool) error {
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !access.systemdView || metadata.Uid != 0 {
		return errors.New("cannot confirm systemd access to credential")
	}
	if len(raw) == 0 {
		// Conventional root:service-group delivery has no extended ACL.
		if metadata.Gid == access.gid {
			return nil
		}
	} else if metadata.Gid == 0 && validSystemdCredentialACL(raw, access.uid, directory) {
		return nil
	}
	return errors.New("systemd credential access list has unsafe permissions")
}

func systemdCredentialACLSnapshot(fd int, info os.FileInfo, access credentialAccess, groupView, directory bool) ([]byte, error) {
	if !groupView {
		return nil, nil
	}
	// The only accepted ACL is 44 bytes. One extra byte plus ERANGE ensures an
	// arbitrary-size or extra-entry ACL is rejected before any secret is read.
	buffer := make([]byte, 45)
	size, err := unix.Fgetxattr(fd, "system.posix_acl_access", buffer)
	var raw []byte
	if errors.Is(err, unix.ENODATA) {
		raw = nil
	} else if err != nil || size <= 0 || size > len(buffer) {
		return nil, errors.New("cannot inspect systemd credential access list")
	} else {
		raw = buffer[:size]
	}
	if err := validateSystemdCredentialACL(raw, info, access, directory); err != nil {
		return nil, err
	}
	return raw, nil
}

func sameCredentialMetadata(before, after os.FileInfo, file bool) bool {
	a, aOK := before.Sys().(*syscall.Stat_t)
	b, bOK := after.Sys().(*syscall.Stat_t)
	return aOK && bOK && os.SameFile(before, after) && before.Mode() == after.Mode() &&
		a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink &&
		(!file || (before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())))
}

func (s Credentials) Get(service, account string) (string, error) {
	name, ok := s.Bindings[Key{service, account}]
	if !ok {
		return "", ErrNotFound
	}
	if !filepath.IsAbs(s.Directory) || filepath.Clean(s.Directory) != s.Directory || name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return "", errors.New("invalid credentials location")
	}
	info, err := os.Lstat(s.Directory)
	if err != nil {
		return "", fmt.Errorf("credentials directory unavailable: %w", err)
	}
	access := credentialAccess{uid: uint32(os.Geteuid()), gid: uint32(os.Getegid()),
		systemdView: systemdCredentialDirectory(s.Directory, runtime.GOOS, os.Getenv("CREDENTIALS_DIRECTORY"))}
	groupView, err := credentialDirectoryAccess(info, access)
	if err != nil {
		return "", err
	}
	directoryInfo := info
	directoryFD, err := unix.Open(s.Directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("opening credentials directory: %w", err)
	}
	directory := os.NewFile(uintptr(directoryFD), s.Directory)
	defer directory.Close()
	openedDirectory, err := directory.Stat()
	if err != nil || !sameCredentialMetadata(directoryInfo, openedDirectory, false) {
		return "", errors.New("credentials directory changed while opening")
	}
	if _, err := credentialDirectoryAccess(openedDirectory, access); err != nil {
		return "", err
	}
	directoryACL, err := systemdCredentialACLSnapshot(directoryFD, openedDirectory, access, groupView, true)
	if err != nil {
		return "", err
	}
	path := filepath.Join(s.Directory, name)
	info, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("reading credential: %w", err)
	}
	if err := validateCredentialFile(info, access, groupView); err != nil {
		return "", err
	}
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", fmt.Errorf("opening credential: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !sameCredentialMetadata(info, opened, true) {
		return "", errors.New("credential file changed while reading")
	}
	if err := validateCredentialFile(opened, access, groupView); err != nil {
		return "", err
	}
	fileACL, err := systemdCredentialACLSnapshot(fd, opened, access, groupView, false)
	if err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16<<10+1))
	if err != nil {
		return "", fmt.Errorf("reading credential: %w", err)
	}
	if len(raw) > 16<<10 {
		return "", errors.New("credential exceeds size limit")
	}
	finalFile, fileErr := f.Stat()
	finalDirectory, directoryErr := directory.Stat()
	namedDirectory, nameErr := os.Lstat(s.Directory)
	namedFile, fileNameErr := os.Lstat(path)
	if fileErr != nil || directoryErr != nil || nameErr != nil || fileNameErr != nil ||
		!sameCredentialMetadata(opened, finalFile, true) ||
		!sameCredentialMetadata(opened, namedFile, true) ||
		!sameCredentialMetadata(openedDirectory, finalDirectory, false) ||
		!sameCredentialMetadata(openedDirectory, namedDirectory, false) {
		return "", errors.New("credential location or permissions changed while reading")
	}
	finalDirectoryACL, err := systemdCredentialACLSnapshot(directoryFD, finalDirectory, access, groupView, true)
	if err != nil {
		return "", err
	}
	finalFileACL, err := systemdCredentialACLSnapshot(fd, finalFile, access, groupView, false)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(directoryACL, finalDirectoryACL) || !bytes.Equal(fileACL, finalFileACL) {
		return "", errors.New("systemd credential access list changed while reading")
	}
	// Credential files may have a single terminal newline. Preserve spaces in
	// passwords; do not silently change them with TrimSpace.
	value := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("invalid credential format")
	}
	return value, nil
}

func (Credentials) Set(service, account, value, label string) error { return ErrReadOnly }
func (Credentials) Delete(service, account string) error            { return ErrReadOnly }
