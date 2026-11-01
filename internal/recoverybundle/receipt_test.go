package recoverybundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"golang.org/x/sys/unix"
)

func receiptFixture(t *testing.T) (Receipt, ed25519.PrivateKey, *age.X25519Identity, ReceiptPolicy) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := RecipientDigest(identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	payload := ReceiptPayload{Version: 1, SourceID: strings.Repeat("a", 64), Sequence: 3, CreatedUTC: now.Add(-time.Minute).Format(time.RFC3339Nano), CipherSHA256: strings.Repeat("c", 64), CipherBytes: 123, RecipientSHA256: recipient}
	receipt, err := SignReceipt(payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	return receipt, priv, identity, ReceiptPolicy{TrustedSigner: pub, ExpectedSourceID: payload.SourceID, Now: now, MaxAge: 24 * time.Hour, MaxFutureSkew: time.Minute}
}

func TestSignedReceiptRoundTripAndReplayFloor(t *testing.T) {
	receipt, priv, identity, policy := receiptFixture(t)
	wire, err := EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReceipt(wire)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyReceipt(parsed, identity.Recipient(), policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.Watermark = verified.NextWatermark
	if _, err = VerifyReceipt(receipt, identity.Recipient(), policy); err != nil {
		t.Fatalf("same receipt should be reusable: %v", err)
	}
	older := receipt.Payload
	older.Sequence--
	oldReceipt, err := SignReceipt(older, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyReceipt(oldReceipt, identity.Recipient(), policy); err == nil {
		t.Fatal("accepted replay below watermark")
	}
	conflict := receipt.Payload
	conflict.CipherSHA256 = strings.Repeat("d", 64)
	conflictReceipt, err := SignReceipt(conflict, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyReceipt(conflictReceipt, identity.Recipient(), policy); err == nil {
		t.Fatal("accepted conflicting payload at same sequence")
	}
	newer := receipt.Payload
	newer.Sequence++
	newReceipt, err := SignReceipt(newer, priv)
	if err != nil {
		t.Fatal(err)
	}
	next, err := VerifyReceipt(newReceipt, identity.Recipient(), policy)
	if err != nil || next.NextWatermark.Sequence != newer.Sequence {
		t.Fatalf("newer receipt: %v", err)
	}
}

func TestReceiptRejectsWrongIssuerRecipientSourceAndFreshness(t *testing.T) {
	receipt, priv, identity, policy := receiptFixture(t)
	wrongIdentity, _ := age.GenerateX25519Identity()
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name     string
		receipt  Receipt
		identity *age.X25519Identity
		policy   ReceiptPolicy
	}{
		{"issuer", receipt, identity, func() ReceiptPolicy { p := policy; p.TrustedSigner = otherPub; return p }()},
		{"recipient", receipt, wrongIdentity, policy},
		{"source", receipt, identity, func() ReceiptPolicy { p := policy; p.ExpectedSourceID = strings.Repeat("b", 64); return p }()},
		{"stale", receipt, identity, func() ReceiptPolicy { p := policy; p.Now = p.Now.Add(25 * time.Hour); return p }()},
		{"future", receipt, identity, func() ReceiptPolicy { p := policy; p.Now = p.Now.Add(-time.Hour); return p }()},
		{"tampered", func() Receipt { r := receipt; r.Payload.Sequence++; return r }(), identity, policy},
		{"no-age-limit", receipt, identity, func() ReceiptPolicy { p := policy; p.MaxAge = 0; return p }()},
		{"bad-watermark", receipt, identity, func() ReceiptPolicy { p := policy; p.Watermark = Watermark{Sequence: 2}; return p }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyReceipt(tc.receipt, tc.identity.Recipient(), tc.policy); err == nil {
				t.Fatal("invalid receipt accepted")
			}
		})
	}
	invalid := receipt.Payload
	invalid.CreatedUTC = "2026-10-30T13:00:00+01:00"
	if _, err := SignReceipt(invalid, priv); err == nil {
		t.Fatal("noncanonical time accepted")
	}
	if _, err := SignReceipt(receipt.Payload, ed25519.PrivateKey{}); err == nil {
		t.Fatal("bad key accepted")
	}
}

func TestReceiptCanonicalParsing(t *testing.T) {
	receipt, _, _, _ := receiptFixture(t)
	wire, err := EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{append(append([]byte(nil), wire...), '\n'), []byte(strings.Replace(string(wire), `"version":1`, `"version":1,"version":1`, 1)), []byte(strings.Replace(string(wire), `"version":1`, `"version":1,"unknown":1`, 1)), []byte(`{}`)}
	for _, data := range cases {
		if _, err := ParseReceipt(data); err == nil {
			t.Fatalf("accepted noncanonical receipt: %q", data)
		}
	}
}

func TestOpenVerifiedRequiresSignedContentAndSize(t *testing.T) {
	receipt, priv, identity, policy := receiptFixture(t)
	root := privateTemp(t)
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(stage, "guardian.db"), []byte("fixture"))
	backup := filepath.Join(root, "fixture.age")
	if err := Seal(stage, backup, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	p := receipt.Payload
	p.CipherSHA256 = hex.EncodeToString(sum[:])
	p.CipherBytes = int64(len(data))
	receipt, err = SignReceipt(p, priv)
	if err != nil {
		t.Fatal(err)
	}
	limits := Limits{MaxBytes: 100, MaxFiles: 10, ReserveBytes: 2 << 30}
	dest := filepath.Join(root, "restored")
	verified, err := OpenVerified(backup, dest, identity, receipt, policy, limits)
	if err != nil {
		t.Fatal(err)
	}
	if verified.NextWatermark.Sequence != p.Sequence {
		t.Fatal("wrong watermark")
	}
	p.CipherBytes++
	bad, err := SignReceipt(p, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenVerified(backup, filepath.Join(root, "size"), identity, bad, policy, limits); err == nil {
		t.Fatal("accepted wrong signed size")
	}
	p.CipherBytes--
	p.CipherSHA256 = strings.Repeat("0", 64)
	bad, err = SignReceipt(p, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenVerified(backup, filepath.Join(root, "digest"), identity, bad, policy, limits); err == nil {
		t.Fatal("accepted wrong signed digest")
	}
}

func TestOpenCiphertextRejectsSpecialAndSymlinkAndPinsInode(t *testing.T) {
	root := privateTemp(t)
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(stage, "db"), []byte("x"))
	identity, _ := age.GenerateX25519Identity()
	backup := filepath.Join(root, "valid.age")
	if err := Seal(stage, backup, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "link")
	if err := os.Symlink(backup, symlink); err != nil {
		t.Fatal(err)
	}
	if f, err := openCiphertext(symlink); err == nil {
		f.Close()
		t.Fatal("accepted symlink")
	}
	fifo := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if f, err := openCiphertext(fifo); err == nil {
		f.Close()
		t.Fatal("accepted FIFO")
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	f, err := openCiphertext(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = os.Rename(backup, filepath.Join(root, "moved.age")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, backup, []byte("replacement"))
	if err = openFile(f, filepath.Join(root, "restored"), identity, digest, int64(len(data)), Limits{MaxBytes: 100, MaxFiles: 10, ReserveBytes: 2 << 30}); err != nil {
		t.Fatalf("opened inode not preserved: %v", err)
	}
}
