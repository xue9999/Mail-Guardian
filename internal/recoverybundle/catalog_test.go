package recoverybundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"golang.org/x/sys/unix"
)

func catalogFixture(t *testing.T) (string, Receipt, ed25519.PrivateKey, *age.X25519Identity, ReceiptPolicy, CatalogPins) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	receipt, priv, identity, policy := receiptFixture(t)
	pins := CatalogPins{SourceID: policy.ExpectedSourceID, Signer: policy.TrustedSigner, Recipient: identity.Recipient()}
	return directory, receipt, priv, identity, policy, pins
}

func catalogResign(t *testing.T, receipt Receipt, privateKey ed25519.PrivateKey, sequence uint64, digest string) Receipt {
	t.Helper()
	payload := receipt.Payload
	payload.Sequence = sequence
	if digest != "" {
		payload.CipherSHA256 = digest
	}
	result, err := SignReceipt(payload, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestCatalogDurableMonotonicReceiptAdmission(t *testing.T) {
	directory, receipt, priv, identity, policy, pins := catalogFixture(t)
	if _, err := CatalogWatermark(directory, pins); err == nil {
		t.Fatal("missing state must not become a zero watermark")
	}
	if err := InitializeCatalog(directory, pins, Watermark{}); err != nil {
		t.Fatal(err)
	}
	initial, err := CatalogWatermark(directory, pins)
	if err != nil || initial != (Watermark{}) {
		t.Fatalf("explicit bootstrap: %v %v", initial, err)
	}
	first, err := VerifyAndAdvanceCatalog(directory, receipt, identity.Recipient(), policy)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := CatalogWatermark(directory, pins)
	if err != nil || stored != first.NextWatermark {
		t.Fatalf("persisted floor differs: %v %v", stored, err)
	}
	before, err := os.ReadFile(filepath.Join(directory, catalogStateName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAndAdvanceCatalog(directory, receipt, identity.Recipient(), policy); err != nil {
		t.Fatalf("same signed receipt is idempotent: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(directory, catalogStateName))
	if !bytes.Equal(before, after) {
		t.Fatal("idempotent admission rewrote history")
	}
	for _, invalid := range []Receipt{
		catalogResign(t, receipt, priv, 2, ""),
		catalogResign(t, receipt, priv, 3, strings.Repeat("d", 64)),
	} {
		if _, err := VerifyAndAdvanceCatalog(directory, invalid, identity.Recipient(), policy); err == nil {
			t.Fatal("accepted lower or conflicting sequence")
		}
	}
	// The caller cannot weaken disk state with its own zero/older floor.
	policy.Watermark = Watermark{}
	if _, err := VerifyAndAdvanceCatalog(directory, catalogResign(t, receipt, priv, 2, ""), identity.Recipient(), policy); err == nil {
		t.Fatal("external zero watermark overrode persisted history")
	}
	newer := catalogResign(t, receipt, priv, 4, "")
	advanced, err := VerifyAndAdvanceCatalog(directory, newer, identity.Recipient(), policy)
	if err != nil || advanced.NextWatermark.Sequence != 4 {
		t.Fatalf("newer sequence: %v %v", advanced, err)
	}
	if err := InitializeCatalog(directory, pins, Watermark{}); err == nil {
		t.Fatal("explicit initialization reset an established catalog")
	}
	for _, name := range []string{catalogLockName, catalogStateName} {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != 0600 || !info.Mode().IsRegular() {
			t.Fatalf("unsafe published file %s: %v", name, err)
		}
	}
	names, err := os.ReadDir(directory)
	if err != nil || len(names) != 2 {
		t.Fatalf("successful publication left incomplete artifacts: %v", err)
	}
}

func TestCatalogExplicitBootstrapAndIndependentProducerFloor(t *testing.T) {
	directory, receipt, priv, identity, policy, pins := catalogFixture(t)
	prior := catalogResign(t, receipt, priv, 2, "")
	verified, err := VerifyReceipt(prior, identity.Recipient(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := InitializeCatalog(directory, pins, verified.NextWatermark); err != nil {
		t.Fatal(err)
	}
	if mark, err := CatalogWatermark(directory, pins); err != nil || mark != verified.NextWatermark {
		t.Fatalf("explicit nonzero floor: %v %v", mark, err)
	}
	if _, err := VerifyAndAdvanceCatalog(directory, prior, identity.Recipient(), policy); err != nil {
		t.Fatalf("receipt matching bootstrap floor: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(directory, catalogStateName))
	if err != nil {
		t.Fatal(err)
	}
	var bootstrapped catalogRecord
	if err := json.Unmarshal(data, &bootstrapped); err != nil || bootstrapped.LastReceipt == nil || bootstrapped.Current != toCatalogFloor(verified.NextWatermark) {
		t.Fatalf("admitting bootstrap-matching receipt did not persist its signature: %v", err)
	}
	producerReceipt := catalogResign(t, receipt, priv, 4, "")
	producer, err := VerifyReceipt(producerReceipt, identity.Recipient(), policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.Watermark = producer.NextWatermark
	if _, err := VerifyAndAdvanceCatalog(directory, receipt, identity.Recipient(), policy); err == nil {
		t.Fatal("catalog ignored independently supplied higher producer floor")
	}
	if _, err := VerifyAndAdvanceCatalog(directory, producerReceipt, identity.Recipient(), policy); err != nil {
		t.Fatal(err)
	}
	policy.Now = policy.Now.Add(30 * 24 * time.Hour)
	if _, err := CatalogWatermark(directory, pins); err != nil {
		t.Fatalf("historical accepted floor must not age out: %v", err)
	}
	if _, err := VerifyAndAdvanceCatalog(directory, catalogResign(t, receipt, priv, 5, ""), identity.Recipient(), policy); err == nil {
		t.Fatal("stale new receipt was accepted")
	}
}

func TestCatalogPinnedIdentityAndCanonicalState(t *testing.T) {
	mutations := map[string]func([]byte) []byte{
		"trailing-newline": func(data []byte) []byte { return append(data, '\n') },
		"unknown-key": func(data []byte) []byte {
			return bytes.Replace(data, []byte(`"version":1`), []byte(`"version":1,"unknown":1`), 1)
		},
		"duplicate-key": func(data []byte) []byte {
			return bytes.Replace(data, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
		},
		"oversized": func([]byte) []byte { return bytes.Repeat([]byte(" "), catalogMaxBytes+1) },
		"truncated": func(data []byte) []byte { return data[:len(data)/2] },
		"mismatched-floor": func(data []byte) []byte {
			var record catalogRecord
			_ = json.Unmarshal(data, &record)
			record.Current.Sequence++
			out, _ := json.Marshal(record)
			return out
		},
		"invalid-signature": func(data []byte) []byte {
			var record catalogRecord
			_ = json.Unmarshal(data, &record)
			record.LastReceipt.Signature[0] ^= 1
			out, _ := json.Marshal(record)
			return out
		},
		"missing-signature": func(data []byte) []byte {
			var record catalogRecord
			_ = json.Unmarshal(data, &record)
			record.LastReceipt = nil
			out, _ := json.Marshal(record)
			return out
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			directory, receipt, _, identity, policy, pins := catalogFixture(t)
			if err := InitializeCatalog(directory, pins, Watermark{}); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyAndAdvanceCatalog(directory, receipt, identity.Recipient(), policy); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(directory, catalogStateName)
			data, _ := os.ReadFile(name)
			if err := os.WriteFile(name, mutate(data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := CatalogWatermark(directory, pins); err == nil {
				t.Fatal("corrupt/noncanonical catalog accepted")
			}
			if _, err := VerifyAndAdvanceCatalog(directory, receipt, identity.Recipient(), policy); err == nil {
				t.Fatal("corrupt history was replaced with incoming signed receipt")
			}
		})
	}
	directory, receipt, _, identity, policy, pins := catalogFixture(t)
	if err := InitializeCatalog(directory, pins, Watermark{}); err != nil {
		t.Fatal(err)
	}
	wrongIdentity, _ := age.GenerateX25519Identity()
	cases := []CatalogPins{
		{SourceID: strings.Repeat("b", 64), Signer: pins.Signer, Recipient: pins.Recipient},
		{SourceID: pins.SourceID, Signer: bytes.Repeat([]byte{1}, ed25519.PublicKeySize), Recipient: pins.Recipient},
		{SourceID: pins.SourceID, Signer: pins.Signer, Recipient: wrongIdentity.Recipient()},
	}
	for _, wrong := range cases {
		if _, err := CatalogWatermark(directory, wrong); err == nil {
			t.Fatal("different independently pinned identity accepted")
		}
	}
	policy.TrustedSigner = cases[1].Signer
	if _, err := VerifyAndAdvanceCatalog(directory, receipt, identity.Recipient(), policy); err == nil {
		t.Fatal("different signer adopted established catalog")
	}
}

func TestCatalogUnsafeFilesPathsAndPartialInitialization(t *testing.T) {
	for _, filename := range []string{catalogLockName, catalogStateName} {
		for _, damage := range []string{"symlink", "hardlink", "public", "fifo", "missing"} {
			t.Run(filename+"-"+damage, func(t *testing.T) {
				directory, _, _, _, _, pins := catalogFixture(t)
				if err := InitializeCatalog(directory, pins, Watermark{}); err != nil {
					t.Fatal(err)
				}
				name := filepath.Join(directory, filename)
				sibling := filepath.Join(filepath.Dir(directory), filepath.Base(directory)+"-outside")
				defer os.Remove(sibling)
				switch damage {
				case "symlink":
					if err := os.Rename(name, sibling); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(sibling, name); err != nil {
						t.Fatal(err)
					}
				case "hardlink":
					if err := os.Link(name, sibling); err != nil {
						t.Fatal(err)
					}
				case "public":
					if err := os.Chmod(name, 0644); err != nil {
						t.Fatal(err)
					}
				case "fifo":
					if err := os.Remove(name); err != nil {
						t.Fatal(err)
					}
					if err := unix.Mkfifo(name, 0600); err != nil {
						t.Fatal(err)
					}
				case "missing":
					if err := os.Remove(name); err != nil {
						t.Fatal(err)
					}
				}
				started := time.Now()
				if _, err := CatalogWatermark(directory, pins); err == nil {
					t.Fatal("unsafe catalog accepted")
				}
				if time.Since(started) > time.Second {
					t.Fatal("special-file read blocked")
				}
				if err := InitializeCatalog(directory, pins, Watermark{}); err == nil {
					t.Fatal("partial/corrupt state was silently reinitialized")
				}
			})
		}
	}
	t.Run("directory-symlink", func(t *testing.T) {
		directory, _, _, _, _, pins := catalogFixture(t)
		link := directory + "-link"
		defer os.Remove(link)
		if err := os.Symlink(directory, link); err != nil {
			t.Fatal(err)
		}
		if err := InitializeCatalog(link, pins, Watermark{}); err == nil {
			t.Fatal("catalog directory symlink accepted")
		}
	})
	t.Run("ancestor-symlink", func(t *testing.T) {
		directory, _, _, _, _, pins := catalogFixture(t)
		parent, name := filepath.Dir(directory), filepath.Base(directory)
		link := parent + "-alias"
		defer os.Remove(link)
		if err := os.Symlink(parent, link); err != nil {
			t.Fatal(err)
		}
		if err := InitializeCatalog(filepath.Join(link, name), pins, Watermark{}); err == nil {
			t.Fatal("catalog ancestor symlink accepted")
		}
	})
	t.Run("public-directory", func(t *testing.T) {
		directory, _, _, _, _, pins := catalogFixture(t)
		if err := os.Chmod(directory, 0750); err != nil {
			t.Fatal(err)
		}
		if err := InitializeCatalog(directory, pins, Watermark{}); err == nil {
			t.Fatal("nonprivate catalog directory accepted")
		}
	})
	t.Run("writable-parent", func(t *testing.T) {
		parent, _, _, _, _, pins := catalogFixture(t)
		directory := filepath.Join(parent, "catalog")
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0777); err != nil {
			t.Fatal(err)
		}
		if err := InitializeCatalog(directory, pins, Watermark{}); err == nil {
			t.Fatal("attacker-writable parent accepted")
		}
	})
	for _, artifact := range []string{catalogPendingName, catalogNextName, "unexpected"} {
		t.Run("leftover-"+artifact, func(t *testing.T) {
			directory, _, _, _, _, pins := catalogFixture(t)
			if err := InitializeCatalog(directory, pins, Watermark{}); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, artifact), []byte("interrupted"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := CatalogWatermark(directory, pins); !errors.Is(err, ErrCatalogRecoveryRequired) {
				t.Fatalf("unexpected artifact did not require reconciliation: %v", err)
			}
		})
	}
}

func TestCatalogAncestorTrustPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   unix.Stat_t
		want bool
	}{
		{"root-owned", unix.Stat_t{Uid: 0, Mode: unix.S_IFDIR | 0755}, true},
		{"caller-owned", unix.Stat_t{Uid: uint32(os.Geteuid()), Mode: unix.S_IFDIR | 0700}, true},
		{"root-sticky-shared", unix.Stat_t{Uid: 0, Mode: unix.S_IFDIR | 01777}, true},
		{"writable-root", unix.Stat_t{Uid: 0, Mode: unix.S_IFDIR | 0777}, false},
		{"untrusted-owner", unix.Stat_t{Uid: uint32(os.Geteuid()) + 100, Mode: unix.S_IFDIR | 0700}, false},
		{"setgid", unix.Stat_t{Uid: 0, Mode: unix.S_IFDIR | 02755}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeCatalogAncestor(tc.st); got != tc.want {
				t.Fatalf("ancestor trust = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCatalogLockContentionAndConcurrentWriters(t *testing.T) {
	directory, receipt, priv, identity, policy, pins := catalogFixture(t)
	if err := InitializeCatalog(directory, pins, Watermark{}); err != nil {
		t.Fatal(err)
	}
	lock, err := unix.Open(filepath.Join(directory, catalogLockName), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := CatalogWatermark(directory, pins); !errors.Is(err, ErrCatalogBusy) {
		t.Fatalf("independent open did not contend: %v", err)
	}
	if _, err := VerifyAndAdvanceCatalog(directory, receipt, identity.Recipient(), policy); !errors.Is(err, ErrCatalogBusy) {
		t.Fatalf("writer did not contend: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("busy operations blocked")
	}
	unix.Close(lock)
	const writers = 20
	var wg sync.WaitGroup
	errorsSeen := make(chan error, writers)
	for sequence := 1; sequence <= writers; sequence++ {
		r := catalogResign(t, receipt, priv, uint64(sequence), "")
		wg.Add(1)
		go func() {
			defer wg.Done()
			deadline := time.Now().Add(3 * time.Second)
			for {
				_, err := VerifyAndAdvanceCatalog(directory, r, identity.Recipient(), policy)
				if errors.Is(err, ErrCatalogBusy) && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
					continue
				}
				if err != nil && !strings.Contains(err.Error(), "stale or conflicting") {
					errorsSeen <- err
				}
				return
			}
		}()
	}
	wg.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	mark, err := CatalogWatermark(directory, pins)
	if err != nil || mark.Sequence != writers {
		t.Fatalf("highest sequence not durable: %+v %v", mark, err)
	}
	// At one shared sequence, mutually conflicting signed receipts cannot both win.
	var winners atomic.Int32
	errorsSeen = make(chan error, 2)
	for _, digest := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		r := catalogResign(t, receipt, priv, writers+1, digest)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for attempt := 0; attempt < 100; attempt++ {
				_, err := VerifyAndAdvanceCatalog(directory, r, identity.Recipient(), policy)
				if errors.Is(err, ErrCatalogBusy) {
					time.Sleep(time.Millisecond)
					continue
				}
				if err == nil {
					winners.Add(1)
				} else if !strings.Contains(err.Error(), "stale or conflicting") {
					errorsSeen <- err
				}
				return
			}
			errorsSeen <- errors.New("conflicting writer did not acquire lock within bound")
		}()
	}
	wg.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	if winners.Load() != 1 {
		t.Fatalf("conflicting winning writers = %d", winners.Load())
	}
}

func TestCatalogInterruptedPublicationRemainsBlocked(t *testing.T) {
	for _, boundary := range []string{"after-intent-sync", "after-file-sync", "after-rename", "after-state-sync"} {
		t.Run(boundary, func(t *testing.T) {
			directory, receipt, _, identity, policy, pins := catalogFixture(t)
			if err := InitializeCatalog(directory, pins, Watermark{}); err != nil {
				t.Fatal(err)
			}
			dir, lock, record, err := lockedCatalog(directory, pins)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := VerifyReceipt(receipt, identity.Recipient(), policy)
			if err != nil {
				t.Fatal(err)
			}
			record.Current, record.LastReceipt = toCatalogFloor(verified.NextWatermark), &receipt
			err = commitCatalog(dir, lock, directory, record, func(stage string) error {
				if stage == boundary {
					return fmt.Errorf("synthetic interruption at %s", stage)
				}
				return nil
			})
			unix.Close(lock)
			unix.Close(dir)
			if !errors.Is(err, ErrCatalogRecoveryRequired) {
				t.Fatalf("interruption not classified: %v", err)
			}
			if _, err := CatalogWatermark(directory, pins); !errors.Is(err, ErrCatalogRecoveryRequired) {
				t.Fatalf("interrupted publication was consumable: %v", err)
			}
			if _, err := VerifyAndAdvanceCatalog(directory, receipt, identity.Recipient(), policy); !errors.Is(err, ErrCatalogRecoveryRequired) {
				t.Fatalf("incoming receipt cleared interruption: %v", err)
			}
			data, err := os.ReadFile(filepath.Join(directory, catalogStateName))
			if err != nil {
				t.Fatal(err)
			}
			var complete catalogRecord
			if err := json.Unmarshal(data, &complete); err != nil {
				t.Fatalf("publication tore its old/new state: %v", err)
			}
			if boundary == "after-rename" || boundary == "after-state-sync" {
				if complete.Current != record.Current {
					t.Fatal("renamed generation differs")
				}
			} else if complete.Current != (catalogFloor{}) {
				t.Fatal("pre-rename interruption changed current floor")
			}
		})
	}
}

func TestCatalogAnchorsDirectoryAndDetectsLockReplacement(t *testing.T) {
	for _, replacement := range []string{"directory", "lock"} {
		t.Run(replacement, func(t *testing.T) {
			directory, _, _, _, _, pins := catalogFixture(t)
			if err := InitializeCatalog(directory, pins, Watermark{}); err != nil {
				t.Fatal(err)
			}
			dir, lock, record, err := lockedCatalog(directory, pins)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(dir)
			defer unix.Close(lock)
			oldDirectory := directory + "-held"
			defer os.RemoveAll(oldDirectory)
			err = commitCatalog(dir, lock, directory, record, func(stage string) error {
				if stage != "after-file-sync" {
					return nil
				}
				if replacement == "directory" {
					if err := os.Rename(directory, oldDirectory); err != nil {
						return err
					}
					return os.Mkdir(directory, 0700)
				}
				if err := os.Remove(filepath.Join(directory, catalogLockName)); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(directory, catalogLockName), []byte(catalogLockText), 0600)
			})
			if !errors.Is(err, ErrCatalogRecoveryRequired) {
				t.Fatalf("path replacement not detected: %v", err)
			}
			if replacement == "directory" {
				entries, err := os.ReadDir(directory)
				if err != nil || len(entries) != 0 {
					t.Fatalf("anchored commit wrote to substitute directory: %v", err)
				}
			}
		})
	}
}

func TestCatalogPersistedReceiptDigestIsDomainSeparated(t *testing.T) {
	directory, receipt, _, identity, policy, pins := catalogFixture(t)
	if err := InitializeCatalog(directory, pins, Watermark{}); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyAndAdvanceCatalog(directory, receipt, identity.Recipient(), policy)
	if err != nil {
		t.Fatal(err)
	}
	message, err := receiptMessage(receipt.Payload)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(message)
	if verified.NextWatermark.PayloadSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("stored receipt floor lost domain separation")
	}
}
