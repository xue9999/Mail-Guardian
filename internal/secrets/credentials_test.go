package secrets

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCredentialsAreBoundPrivateBoundedAndReadOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "imap-password")
	s := Credentials{Directory: dir, Bindings: map[Key]string{{"imap", "account"}: "imap-password"}}
	if err := os.WriteFile(path, []byte(" password with spaces \n"), 0o400); err != nil {
		t.Fatal(err)
	}
	value, err := s.Get("imap", "account")
	if err != nil || value != " password with spaces " {
		t.Fatalf("secret altered: %q %v", value, err)
	}
	if _, err := s.Get("imap", "other-account"); !errors.Is(err, ErrNotFound) {
		t.Fatal("credential binding bypassed")
	}
	if !errors.Is(s.Set("imap", "account", "replacement", ""), ErrReadOnly) || !errors.Is(s.Delete("imap", "account"), ErrReadOnly) {
		t.Fatal("worker can write credentials")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("imap", "account"); err == nil {
		t.Fatal("public credential accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("imap", "account"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing credential error lost")
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("imap", "account"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("symlink treated as missing or safe")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", "secret\nsecond", "secret\x00", strings.Repeat("x", (16<<10)+1)} {
		if err := os.WriteFile(path, []byte(raw), 0o400); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get("imap", "account"); err == nil {
			t.Fatal("invalid credential accepted")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("imap", "account"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("insecure directory treated as missing")
	}
}

type credentialFixtureInfo struct {
	mode os.FileMode
	stat syscall.Stat_t
}

func (i credentialFixtureInfo) Name() string       { return "fixture" }
func (i credentialFixtureInfo) Size() int64        { return 7 }
func (i credentialFixtureInfo) Mode() os.FileMode  { return i.mode }
func (i credentialFixtureInfo) ModTime() time.Time { return time.Unix(1, 0) }
func (i credentialFixtureInfo) IsDir() bool        { return i.mode.IsDir() }
func (i credentialFixtureInfo) Sys() any           { return &i.stat }

func TestSystemdCredentialDirectoryScope(t *testing.T) {
	path := "/run/credentials/mail-guardian@pilot.service"
	if !systemdCredentialDirectory(path, "linux", path) {
		t.Fatal("actual Linux systemd delivery path rejected")
	}
	for _, item := range [][3]string{
		{path, "darwin", path},
		{path, "linux", ""},
		{path, "linux", "/run/credentials/other.service"},
		{"/tmp/credentials/unit.service", "linux", "/tmp/credentials/unit.service"},
		{"/run/credentials/unit.service/child", "linux", "/run/credentials/unit.service/child"},
		{"/run/credentials/../other", "linux", "/run/credentials/../other"},
		{"/run/credentials", "linux", "/run/credentials"},
		{"/run/credentials/", "linux", "/run/credentials/"},
	} {
		if systemdCredentialDirectory(item[0], item[1], item[2]) {
			t.Fatalf("unrelated credential directory accepted: %v", item)
		}
	}
}

func TestSystemdCredentialMetadataIsNarrowlyReadOnly(t *testing.T) {
	access := credentialAccess{uid: 1234, gid: 2345, systemdView: true}
	directory := credentialFixtureInfo{mode: os.ModeDir | 0o550,
		stat: syscall.Stat_t{Uid: 0, Gid: access.gid, Nlink: 2}}
	file := credentialFixtureInfo{mode: 0o440,
		stat: syscall.Stat_t{Uid: 0, Gid: access.gid, Nlink: 1}}
	group, err := credentialDirectoryAccess(directory, access)
	if err != nil || !group || validateCredentialFile(file, access, group) != nil {
		t.Fatal("root-owned readonly systemd group view rejected")
	}
	for _, mutate := range []func(*credentialFixtureInfo){
		func(i *credentialFixtureInfo) { i.stat.Uid = access.uid },
		func(i *credentialFixtureInfo) { i.stat.Uid = 9999 },
		func(i *credentialFixtureInfo) { i.stat.Gid++ },
		func(i *credentialFixtureInfo) { i.mode = os.ModeDir | 0o750 },
		func(i *credentialFixtureInfo) { i.mode = os.ModeDir | 0o570 },
		func(i *credentialFixtureInfo) { i.mode = os.ModeDir | 0o555 },
		func(i *credentialFixtureInfo) { i.mode |= os.ModeSymlink },
		func(i *credentialFixtureInfo) { i.mode |= os.ModeSetgid },
	} {
		bad := directory
		mutate(&bad)
		if _, err := credentialDirectoryAccess(bad, access); err == nil {
			t.Fatalf("unsafe systemd directory accepted: mode=%v uid=%d gid=%d", bad.mode, bad.stat.Uid, bad.stat.Gid)
		}
	}
	for _, mutate := range []func(*credentialFixtureInfo){
		func(i *credentialFixtureInfo) { i.stat.Uid = access.uid },
		func(i *credentialFixtureInfo) { i.stat.Uid = 9999 },
		func(i *credentialFixtureInfo) { i.stat.Gid++ },
		func(i *credentialFixtureInfo) { i.stat.Nlink = 2 },
		func(i *credentialFixtureInfo) { i.mode = 0o640 },
		func(i *credentialFixtureInfo) { i.mode = 0o460 },
		func(i *credentialFixtureInfo) { i.mode = 0o444 },
		func(i *credentialFixtureInfo) { i.mode |= os.ModeSymlink },
		func(i *credentialFixtureInfo) { i.mode |= os.ModeSetgid },
		func(i *credentialFixtureInfo) { i.mode |= os.ModeNamedPipe },
	} {
		bad := file
		mutate(&bad)
		if err := validateCredentialFile(bad, access, true); err == nil {
			t.Fatalf("unsafe systemd credential accepted: mode=%v uid=%d gid=%d links=%d", bad.mode, bad.stat.Uid, bad.stat.Gid, bad.stat.Nlink)
		}
	}
	access.systemdView = false
	if _, err := credentialDirectoryAccess(directory, access); err == nil {
		t.Fatal("group-readable directory accepted outside systemd scope")
	}
	if validateCredentialFile(file, access, true) == nil {
		t.Fatal("group-readable file accepted outside systemd scope")
	}
	access.systemdView = true
	if validateCredentialFile(file, access, false) == nil {
		t.Fatal("group-readable file accepted under ordinary private directory")
	}
}

func TestSystemdRootACLMatchesActualDeliveryAndRejectsBroaderAccess(t *testing.T) {
	directoryHex := "0200000001000500ffffffff02000500e703000004000000ffffffff10000500ffffffff20000000ffffffff"
	fileHex := "0200000001000400ffffffff02000400e703000004000000ffffffff10000400ffffffff20000000ffffffff"
	for _, fixture := range []struct {
		raw       string
		directory bool
		mode      os.FileMode
	}{
		{directoryHex, true, os.ModeDir | 0o550},
		{fileHex, false, 0o440},
	} {
		raw, err := hex.DecodeString(fixture.raw)
		if err != nil {
			t.Fatal(err)
		}
		access := credentialAccess{uid: 999, gid: 982, systemdView: true}
		info := credentialFixtureInfo{mode: fixture.mode, stat: syscall.Stat_t{Uid: 0, Gid: 0, Nlink: 1}}
		if !validSystemdCredentialACL(raw, access.uid, fixture.directory) ||
			validateSystemdCredentialACL(raw, info, access, fixture.directory) != nil {
			t.Fatal("actual systemd root:root ACL granting only the service UID was rejected")
		}
		if validateSystemdCredentialACL(nil, info, access, fixture.directory) == nil {
			t.Fatal("root:root group bits were accepted without the service UID ACL")
		}
		for name, mutate := range map[string]func([]byte) []byte{
			"wrong-version": func(data []byte) []byte { data[0] = 3; return data },
			"wrong-uid":     func(data []byte) []byte { data[16]++; return data },
			"owner-write":   func(data []byte) []byte { data[6] |= 2; return data },
			"user-write":    func(data []byte) []byte { data[14] |= 2; return data },
			"group-access":  func(data []byte) []byte { data[22] = 4; return data },
			"mask-write":    func(data []byte) []byte { data[30] |= 2; return data },
			"other-read":    func(data []byte) []byte { data[38] = 4; return data },
			"extra-entry":   func(data []byte) []byte { return append(data, make([]byte, 8)...) },
			"truncated":     func(data []byte) []byte { return data[:len(data)-1] },
			"named-group":   func(data []byte) []byte { data[12] = 8; return data },
		} {
			bad := mutate(append([]byte(nil), raw...))
			if validSystemdCredentialACL(bad, access.uid, fixture.directory) ||
				validateSystemdCredentialACL(bad, info, access, fixture.directory) == nil {
				t.Fatalf("unsafe ACL accepted: %s directory=%t", name, fixture.directory)
			}
		}
		badInfo := info
		badInfo.stat.Gid = access.gid
		if validateSystemdCredentialACL(raw, badInfo, access, fixture.directory) == nil {
			t.Fatal("extended ACL accepted outside exact root:root delivery")
		}
		access.systemdView = false
		if validateSystemdCredentialACL(raw, info, access, fixture.directory) == nil {
			t.Fatal("systemd ACL accepted outside Linux credential namespace")
		}
	}
}

func TestPrivateCredentialRejectsHardlinkAndDirectorySymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "imap-password")
	if err := os.WriteFile(path, []byte("fixture-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := Credentials{Directory: dir, Bindings: map[Key]string{{"imap", "account"}: "imap-password"}}
	if _, err := s.Get("imap", "account"); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(dir, "second-name")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("imap", "account"); err == nil {
		t.Fatal("hard-linked credential accepted")
	}
	if err := os.Remove(filepath.Join(dir, "second-name")); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	s.Directory = alias
	if _, err := s.Get("imap", "account"); err == nil {
		t.Fatal("credential directory symlink accepted")
	}
}

func TestSystemdCredentialRootGroupDeliveryNative(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires Linux root for real root-owned credential delivery metadata")
	}
	if _, err := os.Stat("/run/credentials"); err != nil {
		t.Skip("systemd runtime credential tree is unavailable")
	}
	dir, err := os.MkdirTemp("/run/credentials", "guardian-secrets-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
		_ = os.RemoveAll(dir)
	})
	path := filepath.Join(dir, "imap-password")
	if err := os.WriteFile(path, []byte("fixture-password\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o550); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	s := Credentials{Directory: dir, Bindings: map[Key]string{{"imap", "account"}: "imap-password"}}
	if got, err := s.Get("imap", "account"); err != nil || got != "fixture-password" {
		t.Fatalf("real Linux root/group delivery rejected: %v", err)
	}
	for _, mode := range []os.FileMode{0o640, 0o460, 0o444} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get("imap", "account"); err == nil {
			t.Fatalf("unsafe native credential mode %o accepted", mode)
		}
	}
	t.Run("root-root-service-uid-ACL", func(t *testing.T) {
		directoryACL, err := hex.DecodeString("0200000001000500ffffffff02000500e703000004000000ffffffff10000500ffffffff20000000ffffffff")
		if err != nil {
			t.Fatal(err)
		}
		fileACL, err := hex.DecodeString("0200000001000400ffffffff02000400e703000004000000ffffffff10000400ffffffff20000000ffffffff")
		if err != nil {
			t.Fatal(err)
		}
		dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(dirFD)
		fileFD, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fileFD)
		if err := unix.Fsetxattr(dirFD, "system.posix_acl_access", directoryACL, 0); err != nil {
			if errors.Is(err, unix.ENOTSUP) {
				t.Skip("isolated runtime filesystem does not support POSIX ACLs")
			}
			t.Fatal(err)
		}
		if err := unix.Fsetxattr(fileFD, "system.posix_acl_access", fileACL, 0); err != nil {
			t.Fatal(err)
		}
		access := credentialAccess{uid: 999, gid: 982, systemdView: true}
		for _, item := range []struct {
			fd        int
			path      string
			directory bool
		}{
			{dirFD, dir, true}, {fileFD, path, false},
		} {
			info, err := os.Stat(item.path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := systemdCredentialACLSnapshot(item.fd, info, access, true, item.directory); err != nil {
				t.Fatalf("actual ACL xattr on isolated Linux inode rejected: %v", err)
			}
			wrongUID := access
			wrongUID.uid++
			if _, err := systemdCredentialACLSnapshot(item.fd, info, wrongUID, true, item.directory); err == nil {
				t.Fatal("ACL for another service UID accepted")
			}
		}
		if _, err := s.Get("imap", "account"); err == nil {
			t.Fatal("root reader accepted an ACL bound to a different effective UID")
		}
	})
}
