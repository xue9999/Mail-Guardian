package recoverybundle

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func privateTemp(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if err := os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func openFixture(bundle, destination string, identity *age.X25519Identity) error {
	contents, err := os.ReadFile(bundle)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(contents)
	return Open(bundle, destination, identity, hex.EncodeToString(sum[:]), Limits{MaxBytes: 8 << 20, MaxFiles: 100, ReserveBytes: 2 << 30})
}

func TestEncryptedRoundTripAndIsolation(t *testing.T) {
	root := privateTemp(t)
	source := filepath.Join(root, "stage")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	data := map[string]string{"guardian.db": "private database", "secrets/archive-identity": "private archive identity", "archive/2026/message.eml.age": "encrypted mail"}
	for name, content := range data {
		writeFile(t, filepath.Join(source, name), []byte(content))
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(root, "backup.age")
	if err = Seal(source, backup, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	sealed, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range data {
		if bytes.Contains(sealed, []byte(content)) {
			t.Fatal("plaintext found in encrypted backup")
		}
	}
	info, err := os.Stat(backup)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("backup permissions: %v %v", info, err)
	}
	dest := filepath.Join(root, "restored")
	if err = openFixture(backup, dest, identity); err != nil {
		t.Fatal(err)
	}
	for name, content := range data {
		actual, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil || string(actual) != content {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err = openFixture(backup, dest, identity); err == nil {
		t.Fatal("restored over existing destination")
	}
	if err = Seal(source, backup, identity.Recipient()); err == nil {
		t.Fatal("overwrote existing backup")
	}
	if err = Seal(source, filepath.Join(source, "self.age"), identity.Recipient()); err == nil {
		t.Fatal("accepted backup inside source")
	}
}

func TestCorruptionWrongIdentityAndTruncationFailClosed(t *testing.T) {
	root := privateTemp(t)
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(source, "config"), []byte(strings.Repeat("sensitive ", 30000)))
	identity, _ := age.GenerateX25519Identity()
	wrong, _ := age.GenerateX25519Identity()
	backup := filepath.Join(root, "valid.age")
	if err := Seal(source, backup, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	if err := openFixture(backup, filepath.Join(root, "wrong"), wrong); err == nil {
		t.Fatal("wrong identity accepted")
	}
	raw, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"truncated", append([]byte(nil), raw[:len(raw)-1]...)},
		{"modified", func() []byte { p := append([]byte(nil), raw...); p[len(p)/2] ^= 0x80; return p }()},
		{"trailing", append(append([]byte(nil), raw...), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(root, tc.name+".age")
			writeFile(t, p, tc.data)
			dest := filepath.Join(root, tc.name)
			if err := openFixture(p, dest, identity); err == nil {
				t.Fatal("invalid encrypted stream accepted")
			}
			if _, err := os.Lstat(dest); !os.IsNotExist(err) {
				t.Fatalf("partial restore left behind: %v", err)
			}
		})
	}
}

func craft(t *testing.T, name string, identity *age.X25519Identity, entries []struct {
	name     string
	contents string
}) string {
	t.Helper()
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := age.Encrypt(f, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(encrypted)
	for _, e := range entries {
		if err = tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0600, Size: int64(len(e.contents))}); err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(tw, e.contents); err != nil {
			t.Fatal(err)
		}
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = encrypted.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	return name
}
func TestRejectsHostileAuthenticatedArchive(t *testing.T) {
	root := privateTemp(t)
	identity, _ := age.GenerateX25519Identity()
	for _, tc := range []struct {
		name    string
		entries []struct {
			name     string
			contents string
		}
	}{
		{"traversal", []struct {
			name     string
			contents string
		}{{"../escape", "unsafe"}}},
		{"duplicate", []struct {
			name     string
			contents string
		}{{"same", "one"}, {"same", "two"}}},
		{"missing-manifest", []struct {
			name     string
			contents string
		}{{"db", "one"}}},
		{"bad-hash", []struct {
			name     string
			contents string
		}{{"db", "one"}, {manifestName, `{"version":1,"files":{"db":"incorrect"}}`}}},
		{"extra-after-manifest", []struct {
			name     string
			contents string
		}{{"db", "one"}, {manifestName, `{"version":1,"files":{"db":"incorrect"}}`}, {"extra", "value"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backup := craft(t, filepath.Join(root, tc.name+".age"), identity, tc.entries)
			dest := filepath.Join(root, tc.name)
			if err := openFixture(backup, dest, identity); err == nil {
				t.Fatal("hostile backup accepted")
			}
			if _, err := os.Stat(dest); !os.IsNotExist(err) {
				t.Fatal("partial restore left")
			}
		})
	}
	if _, err := os.Stat(filepath.Join(root, "escape")); !os.IsNotExist(err) {
		t.Fatal("path escaped restore")
	}
}
func TestRejectSymlinkAndPublicStaging(t *testing.T) {
	root := privateTemp(t)
	identity, _ := age.GenerateX25519Identity()
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "outside"), []byte("x"))
	if err := os.Symlink(filepath.Join(root, "outside"), filepath.Join(stage, "link")); err != nil {
		t.Fatal(err)
	}
	if err := Seal(stage, filepath.Join(root, "bad.age"), identity.Recipient()); err == nil {
		t.Fatal("accepted symlink")
	}
	if err := os.Remove(filepath.Join(stage, "link")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(stage, "item"), []byte("x"))
	if err := os.Chmod(stage, 0755); err != nil {
		t.Fatal(err)
	}
	if err := Seal(stage, filepath.Join(root, "bad2.age"), identity.Recipient()); err == nil {
		t.Fatal("accepted non-private staging")
	}
}

func TestRequiresIndependentReceiptAndLimits(t *testing.T) {
	root := privateTemp(t)
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(stage, "one"), []byte("one"))
	writeFile(t, filepath.Join(stage, "two"), []byte("two"))
	identity, _ := age.GenerateX25519Identity()
	backup := filepath.Join(root, "backup.age")
	if err := Seal(stage, backup, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes)
	digest := hex.EncodeToString(sum[:])
	good := Limits{MaxBytes: 100, MaxFiles: 10, ReserveBytes: 2 << 30}
	tests := []struct {
		name, digest string
		limits       Limits
	}{
		{"no-receipt", "", good}, {"wrong-receipt", strings.Repeat("0", 64), good}, {"byte-limit", digest, Limits{MaxBytes: 4, MaxFiles: 10, ReserveBytes: 2 << 30}}, {"file-limit", digest, Limits{MaxBytes: 100, MaxFiles: 1, ReserveBytes: 2 << 30}}, {"no-reserve", digest, Limits{MaxBytes: 100, MaxFiles: 10}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dest := filepath.Join(root, tc.name)
			if err := Open(backup, dest, identity, tc.digest, tc.limits); err == nil {
				t.Fatal("accepted invalid receipt or limits")
			}
			if _, err := os.Stat(dest); !os.IsNotExist(err) {
				t.Fatal("failed restore left destination")
			}
		})
	}
}
