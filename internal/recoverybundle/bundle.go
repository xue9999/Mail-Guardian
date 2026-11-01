// Package recoverybundle encrypts and verifies an already-prepared snapshot.
// It does not take application/ownership locks, establish state consistency, or
// validate Guardian state. The separate receipt catalog serializes only its own
// watermark publication; it does not fence mail workers. This package does not
// install a restored snapshot. Callers must do those things independently.
package recoverybundle

import (
	"archive/tar"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"filippo.io/age"
)

const (
	manifestName       = ".guardian-bundle-manifest.json"
	maxManifest        = 16 << 20
	maxFiles           = 100000
	maxFileSize  int64 = 32 << 30
	maxTotalSize int64 = 64 << 30
)

// Limits bound extraction to protect the storage hosting an isolated restore.
// ReserveBytes is a free-space floor, not a quota or protection from concurrent writers.
type Limits struct {
	MaxBytes     int64
	MaxFiles     int
	ReserveBytes uint64
}

type manifest struct {
	Version int               `json:"version"`
	Files   map[string]string `json:"files"`
}

func validName(name string) bool {
	return name != "" && name != "." && name != manifestName && !strings.Contains(name, "\\") &&
		!strings.HasPrefix(name, "/") && path.Clean(name) == name && name != ".." && !strings.HasPrefix(name, "../")
}

func privateDirectory(name string) error {
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("directory must be private and must not be a symlink")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("directory must be owned by the effective user")
	}
	return nil
}

// Seal encrypts the contents of an already-consistent, private staging
// directory. Destination must not exist, and cannot be inside the source.
// Data and the integrity manifest are encrypted to a distinct age recipient;
// the recipient's private identity must be held independently of the backup.
func Seal(source, destination string, recipient *age.X25519Recipient) (err error) {
	if recipient == nil {
		return errors.New("missing backup recipient")
	}
	if err = privateDirectory(source); err != nil {
		return err
	}
	root, err := filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(destination))
	if err != nil {
		return err
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return err
	}
	if err = privateDirectory(parent); err != nil {
		return err
	}
	target := filepath.Join(parent, filepath.Base(destination))
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("backup destination must be outside the staging directory")
	}
	if _, err = os.Lstat(target); err == nil {
		return errors.New("backup destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".guardian-backup-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = tmp.Close(); _ = os.Remove(tmpName) }()
	if err = tmp.Chmod(0600); err != nil {
		return err
	}
	encrypted, err := age.Encrypt(tmp, recipient)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(encrypted)
	entries := make(map[string]string)
	var total int64
	err = filepath.WalkDir(root, func(file string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if file == root {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("staging contains a symlink")
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("staging contains a special file")
		}
		rel, err := filepath.Rel(root, file)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if !validName(name) || len(entries) >= maxFiles || info.Size() < 0 || info.Size() > maxFileSize || total > maxTotalSize-info.Size() {
			return errors.New("invalid staging path or size limit exceeded")
		}
		// Staging is required to be quiescent and exclusively controlled by
		// the caller. Lstat plus same-file check catches accidental replacement.
		in, err := os.Open(file)
		if err != nil {
			return err
		}
		defer in.Close()
		opened, err := in.Stat()
		if err != nil {
			return err
		}
		if !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
			return errors.New("staging file changed while opening")
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: info.Size(), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		sum := sha256.New()
		n, err := io.CopyN(io.MultiWriter(tw, sum), in, info.Size())
		if err != nil || n != info.Size() {
			return errors.New("staging file changed while reading")
		}
		after, err := in.Stat()
		if err != nil {
			return err
		}
		if after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
			return errors.New("staging file changed while reading")
		}
		total += n
		entries[name] = hex.EncodeToString(sum.Sum(nil))
		return nil
	})
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New("empty snapshot")
	}
	data, err := json.Marshal(manifest{Version: 1, Files: entries})
	if err != nil {
		return err
	}
	if len(data) > maxManifest {
		return errors.New("manifest exceeds size limit")
	}
	if err = tw.WriteHeader(&tar.Header{Name: manifestName, Mode: 0600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	if _, err = tw.Write(data); err != nil {
		return err
	}
	if err = tw.Close(); err != nil {
		return err
	}
	if err = encrypted.Close(); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	// Link atomically fails if the destination already exists, unlike Rename.
	if err = os.Link(tmpName, target); err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = os.Remove(target)
		}
	}()
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return err
	}
	published = true
	return nil
}

// Open checks the ciphertext digest against a value from a separately trusted
// catalog, then decrypts and verifies the bundle into a newly created,
// private isolated directory. It never accepts an existing destination and
// removes its own incomplete output on ordinary failure. A crash can leave
// partial plaintext behind. No live state is installed. The digest alone does
// not establish freshness or origin unless its catalog does; a signed receipt
// or independent trusted channel and rollback policy are required. Callers
// must use trusted ancestors and enforce a filesystem quota or other isolation.
func openCiphertext(bundle string) (*os.File, error) {
	fd, err := unix.Open(bundle, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "backup")
	if f == nil {
		_ = unix.Close(fd)
		return nil, errors.New("cannot open backup")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, errors.New("backup must be a regular file")
	}
	return f, nil
}

type countingReader struct {
	source io.Reader
	count  int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	r.count += int64(n)
	return n, err
}

func Open(bundle, destination string, identity *age.X25519Identity, expectedSHA256 string, limits Limits) error {
	f, err := openCiphertext(bundle)
	if err != nil {
		return err
	}
	defer f.Close()
	return openFile(f, destination, identity, expectedSHA256, -1, limits)
}

func openFile(f *os.File, destination string, identity *age.X25519Identity, expectedSHA256 string, expectedBytes int64, limits Limits) (err error) {
	if identity == nil {
		return errors.New("missing backup identity")
	}
	expectedDigest, err := hex.DecodeString(expectedSHA256)
	if err != nil || len(expectedDigest) != sha256.Size || len(expectedSHA256) != 64 || expectedSHA256 != strings.ToLower(expectedSHA256) {
		return errors.New("expected trusted ciphertext SHA-256 required")
	}
	if limits.MaxBytes <= 0 || limits.MaxBytes > maxTotalSize || limits.MaxFiles <= 0 || limits.MaxFiles > maxFiles || limits.ReserveBytes < 2<<30 {
		return errors.New("invalid restore resource limits")
	}
	parent := filepath.Dir(destination)
	if err = privateDirectory(parent); err != nil {
		return err
	}
	if expectedBytes >= 0 {
		info, e := f.Stat()
		if e != nil {
			return e
		}
		if info.Size() != expectedBytes {
			return errors.New("ciphertext size does not match signed receipt")
		}
	}
	cipherDigest := sha256.New()
	counted := &countingReader{source: f}
	decrypted, err := age.Decrypt(io.TeeReader(counted, cipherDigest), identity)
	if err != nil {
		return err
	}
	if err = os.Mkdir(destination, 0700); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(destination)
		}
	}()
	tr := tar.NewReader(decrypted)
	actual := make(map[string]string)
	var expected manifest
	seenManifest := false
	var total int64
	for {
		hdr, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return errors.New("non-regular entry in backup")
		}
		if hdr.Name == manifestName {
			if seenManifest || hdr.Size < 0 || hdr.Size > maxManifest {
				return errors.New("invalid bundle manifest")
			}
			seenManifest = true
			data, e := io.ReadAll(io.LimitReader(tr, maxManifest+1))
			if e != nil {
				return e
			}
			if len(data) > maxManifest {
				return errors.New("manifest exceeds size limit")
			}
			dec := json.NewDecoder(strings.NewReader(string(data)))
			dec.DisallowUnknownFields()
			if e = dec.Decode(&expected); e != nil {
				return errors.New("invalid bundle manifest")
			}
			var trailing any
			if e = dec.Decode(&trailing); e != io.EOF {
				return errors.New("invalid manifest trailing data")
			}
			continue
		}
		if seenManifest || !validName(hdr.Name) || len(actual) >= limits.MaxFiles || hdr.Size < 0 || hdr.Size > maxFileSize || hdr.Size > limits.MaxBytes || total > limits.MaxBytes-hdr.Size {
			return errors.New("invalid entry or size limit exceeded")
		}
		if _, ok := actual[hdr.Name]; ok {
			return errors.New("duplicate bundle entry")
		}
		var space unix.Statfs_t
		if e = unix.Statfs(destination, &space); e != nil {
			return e
		}
		free := uint64(space.Bavail) * uint64(space.Bsize)
		if free < limits.ReserveBytes || uint64(hdr.Size) > free-limits.ReserveBytes {
			return errors.New("insufficient free-space reserve for restore")
		}
		target := filepath.Join(destination, filepath.FromSlash(hdr.Name))
		if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			return e
		}
		out, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		sum := sha256.New()
		n, e := io.CopyN(io.MultiWriter(out, sum), tr, hdr.Size)
		if e == nil {
			e = out.Sync()
		}
		closeErr := out.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		if n != hdr.Size {
			return errors.New("incomplete bundle entry")
		}
		total += n
		actual[hdr.Name] = hex.EncodeToString(sum.Sum(nil))
	}
	// Read through the age stream's authenticated end marker. tar may stop
	// before that marker; never treat a valid prefix as a complete backup.
	n, err := io.Copy(io.Discard, decrypted)
	if err != nil {
		return err
	}
	if n != 0 {
		return errors.New("unexpected trailing bundle data")
	}
	if expectedBytes >= 0 && counted.count != expectedBytes {
		return errors.New("ciphertext size does not match signed receipt")
	}
	if subtle.ConstantTimeCompare(cipherDigest.Sum(nil), expectedDigest) != 1 {
		return errors.New("ciphertext does not match trusted receipt")
	}
	if !seenManifest || expected.Version != 1 || len(expected.Files) != len(actual) || len(actual) == 0 {
		return errors.New("bundle manifest does not match")
	}
	for name, hash := range actual {
		if expected.Files[name] != hash {
			return fmt.Errorf("bundle integrity mismatch for %q", name)
		}
	}
	// Persist directory entries before reporting success. This still is a
	// staging area, not an installed or semantically accepted recovery.
	var dirs []string
	if err = filepath.WalkDir(destination, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			dirs = append(dirs, name)
		}
		return nil
	}); err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		dir, e := os.Open(dirs[i])
		if e != nil {
			return e
		}
		e = dir.Sync()
		closeErr := dir.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	dir, e := os.Open(parent)
	if e != nil {
		return e
	}
	e = dir.Sync()
	closeErr := dir.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	complete = true
	return nil
}
