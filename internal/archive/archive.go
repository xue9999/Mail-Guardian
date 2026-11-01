package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/o2-mail-guardian/guardian/internal/secrets"
)

type Manager struct {
	Root     string
	Identity *age.X25519Identity
}

func EnsureIdentity(kc secrets.Store, service, account string) (*age.X25519Identity, error) {
	value, err := kc.Get(service, account)
	if err == nil {
		id, parseErr := age.ParseX25519Identity(value)
		if parseErr != nil {
			return nil, fmt.Errorf("zapisany klucz archiwum jest uszkodzony: %w", parseErr)
		}
		return id, nil
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		return nil, err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generowanie klucza archiwum: %w", err)
	}
	if err := kc.Set(service, account, id.String(), "O2 Mail Guardian - klucz archiwum"); err != nil {
		return nil, err
	}
	return id, nil
}

func LoadIdentity(kc secrets.Reader, service, account string) (*age.X25519Identity, error) {
	value, err := kc.Get(service, account)
	if err != nil {
		return nil, err
	}
	id, err := age.ParseX25519Identity(value)
	if err != nil {
		return nil, fmt.Errorf("nieprawidłowy klucz archiwum: %w", err)
	}
	return id, nil
}

func New(root string, identity *age.X25519Identity) (*Manager, error) {
	if identity == nil {
		return nil, errors.New("brakuje klucza szyfrowania archiwum")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("tworzenie katalogu archiwum: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("katalog archiwum nie może być dowiązaniem ani zwykłym plikiem")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, err
	}
	return &Manager{Root: root, Identity: identity}, nil
}

// HasEncryptedFiles reports whether an existing archive contains any Guardian
// message copy. Errors are returned instead of being treated as an empty
// archive so callers never rotate a key on an uncertain filesystem state.
func HasEncryptedFiles(root string) (bool, error) {
	_, err := os.Stat(root)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false, err
	}
	found := false
	err = filepath.WalkDir(resolvedRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("archiwum zawiera dowiązanie symboliczne %q", path)
		}
		if entry.Type().IsRegular() && strings.HasSuffix(strings.ToLower(entry.Name()), ".eml.age") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found, err
}

func (m *Manager) Save(raw []byte, hash string, now time.Time) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("nie można zarchiwizować pustej wiadomości")
	}
	actual := SHA256(raw)
	if hash != "" && actual != hash {
		return "", errors.New("skrót wiadomości zmienił się przed archiwizacją")
	}
	if hash == "" {
		hash = actual
	}
	dir, err := ensureArchiveDir(m.Root, now.UTC().Format("2006"), now.UTC().Format("01"))
	if err != nil {
		return "", err
	}
	if !within(m.Root, dir) {
		return "", errors.New("katalog docelowy kopii wychodzi poza archiwum")
	}
	path := filepath.Join(dir, hash+".eml.age")
	if _, err := os.Stat(path); err == nil {
		if err := m.Verify(path, hash); err != nil {
			return "", fmt.Errorf("istniejąca kopia jest uszkodzona: %w", err)
		}
		return path, nil
	}
	tmp, err := os.CreateTemp(dir, "."+hash+".*.tmp")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return "", err
	}
	w, err := age.Encrypt(tmp, m.Identity.Recipient())
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(w, bytes.NewReader(raw)); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return "", err
	}
	if err := syncDirectory(dir); err != nil {
		return "", fmt.Errorf("utrwalenie katalogu archiwum: %w", err)
	}
	ok = true
	if err := m.Verify(path, hash); err != nil {
		return "", err
	}
	return path, nil
}

func (m *Manager) Read(path string) ([]byte, error) {
	if !within(m.Root, path) {
		return nil, errors.New("ścieżka kopii jest poza katalogiem archiwum")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, m.Identity)
	if err != nil {
		return nil, fmt.Errorf("odszyfrowanie kopii: %w", err)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (m *Manager) Verify(path, expectedHash string) error {
	raw, err := m.Read(path)
	if err != nil {
		return err
	}
	if SHA256(raw) != expectedHash {
		return errors.New("suma kontrolna odszyfrowanej kopii nie pasuje")
	}
	return nil
}

func (m *Manager) Delete(path, expectedHash string) error {
	if err := m.Verify(path, expectedHash); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("usunięcie wygasłej kopii: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func SHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func within(root, path string) bool {
	absRoot, err1 := filepath.EvalSymlinks(root)
	absPath, err2 := filepath.EvalSymlinks(path)
	if err1 != nil {
		return false
	}
	if err2 != nil {
		// A missing final file can be a legitimate state after a crash between
		// unlinking the archive and clearing its SQLite reference. Resolve the
		// existing parent so a symlink still cannot escape the archive root.
		parent, parentErr := filepath.EvalSymlinks(filepath.Dir(path))
		if parentErr != nil {
			return false
		}
		absPath = filepath.Join(parent, filepath.Base(path))
	}
	rel, err := filepath.Rel(absRoot, absPath)
	return err == nil && rel != ".." && !filepath.IsAbs(rel) &&
		len(rel) > 0 && rel[:1] != string(filepath.Separator)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func ensureArchiveDir(root string, components ...string) (string, error) {
	current := root
	for _, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil {
				return "", err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("element katalogu archiwum %q nie jest bezpiecznym katalogiem", current)
		}
		if err := os.Chmod(current, 0o700); err != nil {
			return "", err
		}
	}
	return current, nil
}
