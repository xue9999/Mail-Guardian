package recoverybundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"filippo.io/age"
)

// ReceiptPayload identifies a completed encrypted snapshot. SourceID is the
// 32-byte deployment identity encoded as lowercase hexadecimal. CreatedUTC
// must be the canonical UTC RFC3339Nano string at snapshot completion.
type ReceiptPayload struct {
	Version         int    `json:"version"`
	SourceID        string `json:"source_id"`
	Sequence        uint64 `json:"sequence"`
	CreatedUTC      string `json:"created_utc"`
	CipherSHA256    string `json:"cipher_sha256"`
	CipherBytes     int64  `json:"cipher_bytes"`
	RecipientSHA256 string `json:"recipient_sha256"`
}

type Receipt struct {
	Payload   ReceiptPayload `json:"payload"`
	Signature []byte         `json:"signature"`
}

// Watermark must be held in a protected, independently maintained store. The
// hash covers every signed field, so a reused sequence with any differing
// payload is rejected, even if its ciphertext digest is unchanged.
type Watermark struct {
	Sequence      uint64
	PayloadSHA256 string
}

// ReceiptPolicy requires an independently pinned signer and source identity,
// a trusted clock, explicit age limits and a separately stored watermark.
// An initial zero watermark does not protect against replay at bootstrap.
type ReceiptPolicy struct {
	TrustedSigner    ed25519.PublicKey
	ExpectedSourceID string
	Now              time.Time
	MaxAge           time.Duration
	MaxFutureSkew    time.Duration
	Watermark        Watermark
}

type VerifiedReceipt struct {
	CipherSHA256  string
	CipherBytes   int64
	NextWatermark Watermark
}

func hexDigest(s string) bool {
	if len(s) != 64 || s != strings.ToLower(s) {
		return false
	}
	value, err := hex.DecodeString(s)
	return err == nil && len(value) == sha256.Size
}

func validatePayload(p ReceiptPayload) error {
	if p.Version != 1 || !hexDigest(p.SourceID) || !hexDigest(p.CipherSHA256) || !hexDigest(p.RecipientSHA256) || p.Sequence == 0 || p.CipherBytes <= 0 {
		return errors.New("invalid recovery receipt payload")
	}
	created, err := time.Parse(time.RFC3339Nano, p.CreatedUTC)
	if err != nil || created.IsZero() || created.UTC().Format(time.RFC3339Nano) != p.CreatedUTC {
		return errors.New("invalid recovery receipt timestamp")
	}
	return nil
}

func receiptMessage(p ReceiptPayload) ([]byte, error) {
	if err := validatePayload(p); err != nil {
		return nil, err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return append([]byte("mail-guardian/recovery-receipt/v1\x00"), data...), nil
}

// RecipientDigest binds a receipt to the public recipient corresponding to
// the identity used to decrypt the bundle. The signer is a separate key.
func RecipientDigest(recipient *age.X25519Recipient) (string, error) {
	if recipient == nil {
		return "", errors.New("missing backup recipient")
	}
	sum := sha256.Sum256([]byte(recipient.String()))
	return hex.EncodeToString(sum[:]), nil
}

// SignReceipt must be called only after the producer has completed and
// independently verified its snapshot. It does not validate state coherence.
// The private signer must be kept outside both backup and restored payload.
func SignReceipt(payload ReceiptPayload, privateKey ed25519.PrivateKey) (Receipt, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Receipt{}, errors.New("invalid signing key")
	}
	message, err := receiptMessage(payload)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{Payload: payload, Signature: ed25519.Sign(privateKey, message)}, nil
}

// EncodeReceipt and ParseReceipt define an exact, bounded canonical wire
// representation. Parse rejects duplicate/unknown keys and alternative JSON
// spellings by requiring a byte-for-byte canonical re-encoding.
func EncodeReceipt(receipt Receipt) ([]byte, error) {
	if _, err := receiptMessage(receipt.Payload); err != nil {
		return nil, err
	}
	if len(receipt.Signature) != ed25519.SignatureSize {
		return nil, errors.New("invalid receipt signature")
	}
	return json.Marshal(receipt)
}

func ParseReceipt(data []byte) (Receipt, error) {
	if len(data) == 0 || len(data) > 4096 {
		return Receipt{}, errors.New("invalid receipt length")
	}
	var receipt Receipt
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&receipt); err != nil {
		return Receipt{}, errors.New("invalid receipt encoding")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return Receipt{}, errors.New("invalid receipt encoding")
	}
	canonical, err := EncodeReceipt(receipt)
	if err != nil || !bytes.Equal(data, canonical) {
		return Receipt{}, errors.New("noncanonical receipt encoding")
	}
	return receipt, nil
}

// VerifyReceipt checks issuer, deployment, encryption recipient, time and the
// prior protected watermark. The caller must serialize verification and
// durably advance the returned watermark in an independent trusted store
// before any restored data can be used. Enforce a current producer-side floor
// as well if suppression of newer backups must be detected. A signature does
// not establish database, archive or Redis consistency.
func VerifyReceipt(receipt Receipt, recipient *age.X25519Recipient, policy ReceiptPolicy) (VerifiedReceipt, error) {
	if len(policy.TrustedSigner) != ed25519.PublicKeySize || !hexDigest(policy.ExpectedSourceID) || policy.Now.IsZero() || policy.MaxAge <= 0 || policy.MaxFutureSkew < 0 {
		return VerifiedReceipt{}, errors.New("invalid recovery receipt policy")
	}
	if (policy.Watermark.Sequence == 0 && policy.Watermark.PayloadSHA256 != "") || (policy.Watermark.Sequence > 0 && !hexDigest(policy.Watermark.PayloadSHA256)) {
		return VerifiedReceipt{}, errors.New("invalid recovery watermark")
	}
	message, err := receiptMessage(receipt.Payload)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	if len(receipt.Signature) != ed25519.SignatureSize || !ed25519.Verify(policy.TrustedSigner, message, receipt.Signature) {
		return VerifiedReceipt{}, errors.New("receipt signature verification failed")
	}
	recipientDigest, err := RecipientDigest(recipient)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	p := receipt.Payload
	if p.SourceID != policy.ExpectedSourceID || p.RecipientSHA256 != recipientDigest {
		return VerifiedReceipt{}, errors.New("receipt source or recipient mismatch")
	}
	created, _ := time.Parse(time.RFC3339Nano, p.CreatedUTC)
	now := policy.Now.UTC()
	if created.After(now.Add(policy.MaxFutureSkew)) || created.Before(now.Add(-policy.MaxAge)) {
		return VerifiedReceipt{}, errors.New("recovery receipt outside freshness window")
	}
	sum := sha256.Sum256(message)
	digest := hex.EncodeToString(sum[:])
	if p.Sequence < policy.Watermark.Sequence || (p.Sequence == policy.Watermark.Sequence && digest != policy.Watermark.PayloadSHA256) {
		return VerifiedReceipt{}, errors.New("stale or conflicting recovery receipt")
	}
	return VerifiedReceipt{CipherSHA256: p.CipherSHA256, CipherBytes: p.CipherBytes, NextWatermark: Watermark{Sequence: p.Sequence, PayloadSHA256: digest}}, nil
}

// OpenVerified verifies the receipt and exact ciphertext size before opening a
// bundle into isolated staging. Open independently compares the bytes it
// decrypts to the signed digest. The returned watermark is NOT persisted; the
// caller must persist it independently and durably before adopting any state.
func OpenVerified(bundle, destination string, identity *age.X25519Identity, receipt Receipt, policy ReceiptPolicy, limits Limits) (VerifiedReceipt, error) {
	if identity == nil {
		return VerifiedReceipt{}, errors.New("missing backup identity")
	}
	verified, err := VerifyReceipt(receipt, identity.Recipient(), policy)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	f, err := openCiphertext(bundle)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	defer f.Close()
	if err = openFile(f, destination, identity, verified.CipherSHA256, verified.CipherBytes, limits); err != nil {
		return VerifiedReceipt{}, err
	}
	return verified, nil
}
