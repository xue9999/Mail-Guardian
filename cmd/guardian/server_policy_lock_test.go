package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPolicyAdoptionLockIsPrivateAndExclusive(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := acquirePolicyRunLockForOwner(dir, os.Geteuid(), os.Getegid())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if info, err := os.Stat(filepath.Join(dir, "guardian.lock")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock is not private: %v %v", info, err)
	}
	if other, err := acquirePolicyRunLockForOwner(dir, os.Geteuid(), os.Getegid()); err == nil {
		other.Close()
		t.Fatal("second adopter entered the held instance lock")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := acquirePolicyRunLockForOwner(dir, os.Geteuid(), os.Getegid())
	if err != nil {
		t.Fatal(err)
	}
	other.Close()
}

func TestPolicyAdoptionLockRejectsSymlinksAndUnsafeDataDirectory(t *testing.T) {
	for _, unsafe := range []string{"symlink", "public-directory"} {
		t.Run(unsafe, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "untouched")
			if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}
			if unsafe == "symlink" {
				if err := os.Symlink(target, filepath.Join(dir, "guardian.lock")); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Chmod(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			if lock, err := acquirePolicyRunLockForOwner(dir, os.Geteuid(), os.Getegid()); err == nil {
				lock.Close()
				t.Fatal("unsafe lock boundary accepted")
			}
			if data, err := os.ReadFile(target); err != nil || string(data) != "preserve" {
				t.Fatal("symlink target changed")
			}
		})
	}
}

func TestPolicyAdoptionMigrationFenceExcludesReaders(t *testing.T) {
	dir, _ := fenceFixture(t)
	uid := uint32(os.Geteuid())
	reader, err := acquireMigrationFence(dir, uid)
	if err != nil {
		t.Fatal(err)
	}
	if writer, err := acquireMigrationFenceMode(dir, uid, unix.LOCK_EX); err == nil {
		writer.Close()
		t.Fatal("adoption entered while a worker held the migration fence")
	}
	reader.Close()
	writer, err := acquireMigrationFenceMode(dir, uid, unix.LOCK_EX)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if reader, err := acquireMigrationFence(dir, uid); err == nil {
		reader.Close()
		t.Fatal("worker entered while adoption held the migration fence")
	}
}
