package recoverybundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"golang.org/x/sys/unix"
)

const (
	catalogStateName   = "catalog.json"
	catalogLockName    = "catalog.lock"
	catalogPendingName = ".catalog.pending"
	catalogNextName    = ".catalog.next"
	catalogMaxBytes    = 16 << 10
	catalogLockText    = "mail-guardian/recovery-catalog-lock/v1\n"
)

var (
	// ErrCatalogBusy is returned immediately when another catalog operation holds
	// the stable lock. A caller can retry under its own bounded retry policy.
	ErrCatalogBusy = errors.New("recovery catalog is busy")
	// ErrCatalogRecoveryRequired means publication or initialization was
	// interrupted, or the exclusive catalog directory contains unexpected files.
	// Never delete those files or reset the watermark automatically. Reconcile
	// them with independently trusted recovery records before using this catalog.
	ErrCatalogRecoveryRequired = errors.New("recovery catalog requires reconciliation")
)

// CatalogPins must be obtained independently of backup/restored data. A catalog
// is bound to one source, signer and encryption recipient for its entire life.
type CatalogPins struct {
	SourceID  string
	Signer    ed25519.PublicKey
	Recipient *age.X25519Recipient
}

type catalogFloor struct {
	Sequence      uint64 `json:"sequence"`
	PayloadSHA256 string `json:"payload_sha256"`
}

type catalogRecord struct {
	Version         int          `json:"version"`
	SourceID        string       `json:"source_id"`
	SignerSHA256    string       `json:"signer_sha256"`
	RecipientSHA256 string       `json:"recipient_sha256"`
	Bootstrap       catalogFloor `json:"bootstrap"`
	Current         catalogFloor `json:"current"`
	LastReceipt     *Receipt     `json:"last_receipt,omitempty"`
}

func toCatalogFloor(mark Watermark) catalogFloor {
	return catalogFloor{Sequence: mark.Sequence, PayloadSHA256: mark.PayloadSHA256}
}

func (f catalogFloor) watermark() Watermark {
	return Watermark{Sequence: f.Sequence, PayloadSHA256: f.PayloadSHA256}
}

func validCatalogFloor(f catalogFloor) bool {
	return (f.Sequence == 0 && f.PayloadSHA256 == "") || (f.Sequence > 0 && hexDigest(f.PayloadSHA256))
}

func catalogPins(pins CatalogPins) (catalogRecord, error) {
	if !hexDigest(pins.SourceID) || len(pins.Signer) != ed25519.PublicKeySize {
		return catalogRecord{}, errors.New("invalid independent recovery catalog pins")
	}
	recipient, err := RecipientDigest(pins.Recipient)
	if err != nil {
		return catalogRecord{}, err
	}
	signer := sha256.Sum256(pins.Signer)
	return catalogRecord{Version: 1, SourceID: pins.SourceID, SignerSHA256: hex.EncodeToString(signer[:]), RecipientSHA256: recipient}, nil
}

// InitializeCatalog explicitly establishes a new local watermark store in an
// existing empty mode-0700 directory owned by the effective user. The absolute
// clean directory path and all its ancestors must be real directories, without
// symlinks (resolve a platform's /tmp alias before selecting the directory).
// Ancestors must be root/caller-owned and not group/world-writable, except
// root-owned sticky shared directories such as /private/tmp.
// It refuses existing or partial catalog artifacts; it never resets a store.
// initial must be an independently trusted floor, or an explicitly chosen zero
// bootstrap floor. A zero bootstrap floor cannot detect replay at bootstrap.
//
// The directory must be outside restored payloads and independently protected
// and backed up by the operator. Local files alone cannot prevent their owner
// from replacing the entire catalog with an older valid copy, establish
// independent key custody, or detect suppression of newer producer receipts.
func InitializeCatalog(directory string, pins CatalogPins, initial Watermark) error {
	record, err := catalogPins(pins)
	if err != nil || !validCatalogFloor(toCatalogFloor(initial)) {
		return errors.Join(err, errors.New("invalid recovery catalog initialization"))
	}
	record.Bootstrap, record.Current = toCatalogFloor(initial), toCatalogFloor(initial)
	dir, err := openCatalogDirectory(directory)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	names, err := catalogNames(dir)
	if err != nil || len(names) != 0 {
		return errors.Join(err, errors.New("recovery catalog directory must be empty for explicit initialization"))
	}
	lock, err := unix.Openat(dir, catalogLockName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return fmt.Errorf("create recovery catalog lock: %w", err)
	}
	defer unix.Close(lock)
	if err := unix.Fchmod(lock, 0600); err != nil {
		return errors.Join(ErrCatalogRecoveryRequired, err)
	}
	if err := unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.Join(ErrCatalogRecoveryRequired, err)
	}
	if err := writeCatalogFD(lock, []byte(catalogLockText)); err != nil {
		return errors.Join(ErrCatalogRecoveryRequired, err)
	}
	if err := unix.Fsync(dir); err != nil {
		return errors.Join(ErrCatalogRecoveryRequired, err)
	}
	return commitCatalog(dir, lock, directory, record, nil)
}

// CatalogWatermark reads the persisted floor while holding the stable exclusive
// lock. Missing, corrupt, noncanonical, unsafe or interrupted state fails closed.
// The stored signed receipt remains a floor after its freshness window expires;
// freshness is checked when accepting a new receipt, not when reading history.
func CatalogWatermark(directory string, pins CatalogPins) (Watermark, error) {
	dir, lock, record, err := lockedCatalog(directory, pins)
	if err != nil {
		return Watermark{}, err
	}
	defer unix.Close(dir)
	defer unix.Close(lock)
	return record.Current.watermark(), nil
}

// VerifyAndAdvanceCatalog verifies a candidate receipt and durably records its
// watermark and signed payload before returning success. Verification, loading
// and publication are serialized. policy.Watermark is an additional independent
// producer floor; it never replaces or weakens the persisted catalog floor.
// The exact same receipt is idempotent while its candidate freshness policy
// still permits it; lower or conflicting sequences fail.
//
// This accepts a receipt, not the ciphertext or restored state. It does not
// decrypt/validate a bundle, prove coherence, fence mailbox owners, or authorize
// deployment. A caller must independently validate all state, hold its deployment
// fence and prevent adoption of an older concurrently staged generation. After
// an indeterminate publication error, stop and reconcile the protected catalog.
func VerifyAndAdvanceCatalog(directory string, receipt Receipt, recipient *age.X25519Recipient, policy ReceiptPolicy) (VerifiedReceipt, error) {
	pins := CatalogPins{SourceID: policy.ExpectedSourceID, Signer: policy.TrustedSigner, Recipient: recipient}
	dir, lock, record, err := lockedCatalog(directory, pins)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	defer unix.Close(dir)
	defer unix.Close(lock)
	// Preserve the caller's independent floor, including its conflict semantics.
	if _, err := VerifyReceipt(receipt, recipient, policy); err != nil {
		return VerifiedReceipt{}, err
	}
	policy.Watermark = record.Current.watermark()
	verified, err := VerifyReceipt(receipt, recipient, policy)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	if record.Current == toCatalogFloor(verified.NextWatermark) && record.LastReceipt != nil {
		return verified, nil
	}
	record.Current, record.LastReceipt = toCatalogFloor(verified.NextWatermark), &receipt
	if err := checkCatalogBinding(dir, directory); err != nil {
		return VerifiedReceipt{}, err
	}
	if err := commitCatalog(dir, lock, directory, record, nil); err != nil {
		return VerifiedReceipt{}, err
	}
	return verified, nil
}

func openCatalogDirectory(directory string) (int, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return -1, errors.New("recovery catalog requires a clean absolute non-root directory")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, name := range strings.Split(strings.TrimPrefix(directory, "/"), string(filepath.Separator)) {
		next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return -1, errors.New("recovery catalog path must contain only real directories")
		}
		fd = next
		var ancestor unix.Stat_t
		if err := unix.Fstat(fd, &ancestor); err != nil || !safeCatalogAncestor(ancestor) {
			unix.Close(fd)
			return -1, errors.New("recovery catalog ancestors must have trusted owners and protected write permissions")
		}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0700 {
		unix.Close(fd)
		return -1, errors.New("recovery catalog directory must be caller-owned mode 0700")
	}
	return fd, nil
}

func safeCatalogAncestor(st unix.Stat_t) bool {
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || st.Mode&(unix.S_ISUID|unix.S_ISGID) != 0 {
		return false
	}
	return st.Mode&0022 == 0 || (st.Uid == 0 && st.Mode&unix.S_ISVTX != 0)
}

func checkCatalogBinding(dir int, directory string) error {
	check, err := openCatalogDirectory(directory)
	if err != nil {
		return err
	}
	defer unix.Close(check)
	var before, after unix.Stat_t
	if unix.Fstat(dir, &before) != nil || unix.Fstat(check, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino {
		return errors.New("recovery catalog directory changed during operation")
	}
	return nil
}

func catalogNames(dir int) ([]string, error) {
	fd, err := unix.Openat(dir, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "recovery catalog directory")
	defer f.Close()
	// A valid directory has two files (and at most two interrupted artifacts).
	// Stop reading hostile/accidentally reused directories after a fixed bound.
	names, err := f.Readdirnames(5)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return names, err
}

func catalogRegular(fd int, expectedSize int64) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0600 || st.Nlink != 1 || st.Size < 0 || (expectedSize >= 0 && st.Size != expectedSize) {
		return errors.New("recovery catalog file has unsafe type, owner, mode, size or links")
	}
	return nil
}

func checkCatalogLock(dir, lock int) error {
	var opened, linked unix.Stat_t
	if catalogRegular(lock, int64(len(catalogLockText))) != nil || unix.Fstat(lock, &opened) != nil || unix.Fstatat(dir, catalogLockName, &linked, unix.AT_SYMLINK_NOFOLLOW) != nil || opened.Dev != linked.Dev || opened.Ino != linked.Ino || opened.Nlink != 1 {
		return errors.New("recovery catalog lock changed during operation")
	}
	return nil
}

func lockedCatalog(directory string, pins CatalogPins) (dir, lock int, record catalogRecord, retErr error) {
	expected, err := catalogPins(pins)
	if err != nil {
		return -1, -1, record, err
	}
	dir, err = openCatalogDirectory(directory)
	if err != nil {
		return -1, -1, record, err
	}
	lock = -1
	defer func() {
		if retErr != nil {
			if lock >= 0 {
				unix.Close(lock)
			}
			unix.Close(dir)
		}
	}()
	lock, err = unix.Openat(dir, catalogLockName, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return dir, lock, record, errors.New("recovery catalog lock is missing or unsafe; initialization cannot be inferred")
	}
	if err := catalogRegular(lock, int64(len(catalogLockText))); err != nil {
		return dir, lock, record, err
	}
	if err := unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return dir, lock, record, ErrCatalogBusy
		}
		return dir, lock, record, err
	}
	if err := checkCatalogLock(dir, lock); err != nil {
		return dir, lock, record, err
	}
	if err := checkCatalogBinding(dir, directory); err != nil {
		return dir, lock, record, err
	}
	names, err := catalogNames(dir)
	if err != nil && !errors.Is(err, io.EOF) {
		return dir, lock, record, err
	}
	if len(names) != 2 {
		return dir, lock, record, ErrCatalogRecoveryRequired
	}
	for _, name := range names {
		if name != catalogLockName && name != catalogStateName {
			return dir, lock, record, ErrCatalogRecoveryRequired
		}
	}
	data, err := readCatalogState(dir)
	if err != nil {
		return dir, lock, record, err
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return dir, lock, record, errors.New("invalid recovery catalog state")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, data) || record.Version != 1 || record.SourceID != expected.SourceID || record.SignerSHA256 != expected.SignerSHA256 || record.RecipientSHA256 != expected.RecipientSHA256 || !validCatalogFloor(record.Bootstrap) || !validCatalogFloor(record.Current) || record.Current.Sequence < record.Bootstrap.Sequence {
		return dir, lock, record, errors.New("noncanonical, mismatched or invalid recovery catalog state")
	}
	if record.LastReceipt == nil {
		if record.Current != record.Bootstrap {
			return dir, lock, record, errors.New("recovery catalog lacks its accepted signed receipt")
		}
	} else {
		message, err := receiptMessage(record.LastReceipt.Payload)
		if err != nil || len(record.LastReceipt.Signature) != ed25519.SignatureSize || !ed25519.Verify(pins.Signer, message, record.LastReceipt.Signature) {
			return dir, lock, record, errors.New("recovery catalog receipt signature is invalid")
		}
		sum := sha256.Sum256(message)
		payload := record.LastReceipt.Payload
		if payload.SourceID != record.SourceID || payload.RecipientSHA256 != record.RecipientSHA256 || record.Current != (catalogFloor{Sequence: payload.Sequence, PayloadSHA256: hex.EncodeToString(sum[:])}) || (record.Current.Sequence == record.Bootstrap.Sequence && record.Current != record.Bootstrap) {
			return dir, lock, record, errors.New("recovery catalog receipt and watermark disagree")
		}
	}
	if err := checkCatalogLock(dir, lock); err != nil {
		return dir, lock, record, err
	}
	if err := checkCatalogBinding(dir, directory); err != nil {
		return dir, lock, record, err
	}
	return dir, lock, record, nil
}

func readCatalogState(dir int) ([]byte, error) {
	fd, err := unix.Openat(dir, catalogStateName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("recovery catalog state is missing or unsafe")
	}
	f := os.NewFile(uintptr(fd), "recovery catalog state")
	defer f.Close()
	if err := catalogRegular(fd, -1); err != nil {
		return nil, err
	}
	before, err := f.Stat()
	if err != nil || before.Size() == 0 || before.Size() > catalogMaxBytes {
		return nil, errors.New("recovery catalog state exceeds its size bound")
	}
	data, err := io.ReadAll(io.LimitReader(f, catalogMaxBytes+1))
	if err != nil || len(data) > catalogMaxBytes {
		return nil, errors.New("recovery catalog state could not be read within its size bound")
	}
	after, err := f.Stat()
	var linked unix.Stat_t
	if err != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || len(data) != int(after.Size()) || catalogRegular(fd, -1) != nil || unix.Fstatat(dir, catalogStateName, &linked, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return nil, errors.New("recovery catalog state changed while reading")
	}
	var opened unix.Stat_t
	if unix.Fstat(fd, &opened) != nil || opened.Dev != linked.Dev || opened.Ino != linked.Ino {
		return nil, errors.New("recovery catalog state path changed while reading")
	}
	return data, nil
}

func writeCatalogFD(fd int, data []byte) error {
	for len(data) != 0 {
		n, err := unix.Write(fd, data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return unix.Fsync(fd)
}

// hook is an internal test-only interruption seam. Production callers cannot
// supply assertions or override filesystem durability with a callback.
func commitCatalog(dir, lock int, directory string, record catalogRecord, hook func(string) error) (retErr error) {
	data, err := json.Marshal(record)
	if err != nil || len(data) > catalogMaxBytes {
		return errors.Join(err, errors.New("recovery catalog publication exceeds its size bound"))
	}
	if err := checkCatalogBinding(dir, directory); err != nil {
		return err
	}
	if err := checkCatalogLock(dir, lock); err != nil {
		return err
	}
	pending, err := unix.Openat(dir, catalogPendingName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.Join(ErrCatalogRecoveryRequired, err)
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(ErrCatalogRecoveryRequired, retErr)
		}
	}()
	sum := sha256.Sum256(data)
	intent := []byte("mail-guardian/recovery-catalog-pending/v1 " + hex.EncodeToString(sum[:]) + "\n")
	err = errors.Join(unix.Fchmod(pending, 0600), writeCatalogFD(pending, intent), unix.Close(pending), unix.Fsync(dir))
	if err != nil {
		return err
	}
	step := func(name string) error {
		if err := checkCatalogBinding(dir, directory); err != nil {
			return err
		}
		if err := checkCatalogLock(dir, lock); err != nil {
			return err
		}
		if hook != nil {
			return hook(name)
		}
		return nil
	}
	if err := step("after-intent-sync"); err != nil {
		return err
	}
	next, err := unix.Openat(dir, catalogNextName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	err = errors.Join(unix.Fchmod(next, 0600), writeCatalogFD(next, data), unix.Close(next))
	if err != nil {
		return err
	}
	if err := step("after-file-sync"); err != nil {
		return err
	}
	if err := unix.Renameat(dir, catalogNextName, dir, catalogStateName); err != nil {
		return err
	}
	if err := step("after-rename"); err != nil {
		return err
	}
	if err := unix.Fsync(dir); err != nil {
		return err
	}
	if err := step("after-state-sync"); err != nil {
		return err
	}
	if err := unix.Unlinkat(dir, catalogPendingName, 0); err != nil {
		return err
	}
	if err := unix.Fsync(dir); err != nil {
		return err
	}
	return errors.Join(checkCatalogBinding(dir, directory), checkCatalogLock(dir, lock))
}
