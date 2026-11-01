package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestInitialConfigIsConfinedToPrivateAdministratorDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	path := filepath.Join(dir, "pilot.toml")
	data := []byte("test configuration")
	if err := createPrivateInitialConfig(dir, path, data, uid); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("configuration permissions: %v %v", info, err)
	}
	if err := createPrivateInitialConfig(dir, path, []byte("replacement"), uid); err == nil {
		t.Fatal("existing file was overwritten")
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("original changed: %q %v", got, err)
	}
	for _, bad := range []string{
		filepath.Join(dir, "nested", "config.toml"),
		filepath.Join(filepath.Dir(dir), "outside.toml"),
		dir + "/../outside.toml",
		"relative.toml",
	} {
		if err := createPrivateInitialConfig(dir, bad, data, uid); err == nil {
			t.Fatalf("unsafe destination accepted: %s", bad)
		}
	}
}

func TestInitialConfigRejectsAliasesAndUnsafeDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "alias")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := createPrivateInitialConfig(dir, link, []byte("overwrite"), uid); err == nil {
		t.Fatal("symlink output accepted")
	}
	if got, _ := os.ReadFile(target); string(got) != "untouched" {
		t.Fatal("symlink target changed")
	}
	linkDir := filepath.Join(t.TempDir(), "admin")
	if err := os.Symlink(dir, linkDir); err != nil {
		t.Fatal(err)
	}
	if err := createPrivateInitialConfig(linkDir, filepath.Join(linkDir, "config"), nil, uid); err == nil {
		t.Fatal("symlink directory accepted")
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := createPrivateInitialConfig(dir, filepath.Join(dir, "config"), nil, uid); err == nil {
		t.Fatal("non-private directory accepted")
	}
}
