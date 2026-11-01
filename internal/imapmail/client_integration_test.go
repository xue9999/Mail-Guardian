package imapmail

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

type uidValidityFlipSession struct {
	imapserver.Session
	flipOnSelect atomic.Int32
	selects      atomic.Int32
	expunges     atomic.Int32
	stores       atomic.Int32
	moves        atomic.Int32
}

func (s *uidValidityFlipSession) Select(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
	data, err := s.Session.Select(mailbox, options)
	if err != nil {
		return nil, err
	}
	if s.selects.Add(1) == s.flipOnSelect.Load() {
		changed := *data
		changed.UIDValidity++
		return &changed, nil
	}
	return data, nil
}

func (s *uidValidityFlipSession) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	s.expunges.Add(1)
	return s.Session.Expunge(w, uids)
}

func (s *uidValidityFlipSession) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	s.stores.Add(1)
	return s.Session.Store(w, numSet, flags, options)
}

func (s *uidValidityFlipSession) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	s.moves.Add(1)
	mover, ok := s.Session.(imapserver.SessionMove)
	if !ok {
		return errors.New("memory session does not support MOVE")
	}
	return mover.Move(w, numSet, dest)
}

func TestIMAPLifecycleAgainstMemoryServer(t *testing.T) {
	serverTLS, roots := testTLS(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(ln, serverTLS)

	backend := imapmemserver.New()
	user := imapmemserver.NewUser("test@o2.pl", "app-password")
	for _, mailbox := range []string{"INBOX", "Junk"} {
		if err := user.Create(mailbox, nil); err != nil {
			t.Fatal(err)
		}
	}
	raw := []byte("From: sender@example.org\r\nTo: test@o2.pl\r\nDate: Sat, 25 Jul 2026 08:00:00 +0200\r\nMessage-ID: <test-1@example.org>\r\nSubject: test\r\n\r\nbody")
	if _, err := user.Append("Junk", bytes.NewReader(raw), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen}, Time: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	backend.AddUser(user)
	server := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return backend.NewSession(), nil, nil
		},
		Caps: imap.CapSet{
			imap.CapIMAP4rev2: {},
			imap.CapMove:      {},
			imap.CapUIDPlus:   {},
		},
	})
	go func() { _ = server.Serve(tlsListener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = ln.Close()
	})

	_, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portText)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := dialWithTLSConfig(ctx, "localhost", port, "test@o2.pl", "app-password", &tls.Config{
		ServerName: "localhost", RootCAs: roots, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	boxes, err := client.ListMailboxes()
	if err != nil {
		t.Fatal(err)
	}
	if got := DetectSpamFolder(boxes); got != "Junk" {
		t.Fatalf("detected spam folder %q", got)
	}
	if err := client.EnsureMailboxes("AI-Kwarantanna", "AI-Do-sprawdzenia", "AI-Naucz-spam", "AI-Naucz-wazne"); err != nil {
		t.Fatal(err)
	}
	uids, uidValidity, err := client.SearchSince("Junk", time.Now().Add(-24*time.Hour), 100)
	if err != nil || len(uids) != 1 || uidValidity == 0 {
		t.Fatalf("search: uids=%v uidvalidity=%d err=%v", uids, uidValidity, err)
	}
	msg, err := client.Fetch("Junk", uids[0], true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg.Raw, raw) || msg.MessageID != "test-1@example.org" {
		t.Fatalf("unexpected fetched message: %#v", msg)
	}
	moved, err := client.Move("Junk", msg.UIDValidity, msg.UID, "INBOX", true)
	if err != nil {
		t.Fatal(err)
	}
	if moved.UID == 0 {
		t.Fatal("server did not return destination UID")
	}
	rescued, err := client.Fetch("INBOX", moved.UID, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range rescued.Flags {
		if flag == string(imap.FlagSeen) {
			t.Fatal("rescued message must be unread")
		}
	}

	appended, err := client.AppendUnread("AI-Kwarantanna", raw, time.Now())
	if err != nil || appended.UID == 0 {
		t.Fatalf("append: %#v %v", appended, err)
	}
	if err := client.DeleteUID("AI-Kwarantanna", appended.UIDValidity, appended.UID); err != nil {
		t.Fatal(err)
	}
	remaining, _, err := client.SearchSince("AI-Kwarantanna", time.Time{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("message was not deleted: %v", remaining)
	}
}

func TestMoveWithRawResolvesMissingCopyUID(t *testing.T) {
	serverTLS, roots := testTLS(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := imapmemserver.New()
	user := imapmemserver.NewUser("test@o2.pl", "app-password")
	for _, folder := range []string{"INBOX", "Review"} {
		if err := user.Create(folder, nil); err != nil {
			t.Fatal(err)
		}
	}
	raw := []byte("From: sender@example.org\r\nTo: test@o2.pl\r\nMessage-ID: <fallback@example.org>\r\nSubject: fallback\r\n\r\nbody")
	if _, err := user.Append("INBOX", bytes.NewReader(raw), &imap.AppendOptions{Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	backend.AddUser(user)
	server := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return backend.NewSession(), nil, nil
		},
		Caps:         imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapMove: {}},
		InsecureAuth: true, // The fixture wraps the TLS connection.
	})
	withoutMapping := &noCopyUIDListener{Listener: tls.NewListener(ln, serverTLS)}
	go func() { _ = server.Serve(withoutMapping) }()
	t.Cleanup(func() { _ = server.Close(); _ = ln.Close() })
	_, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portText)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := dialWithTLSConfig(ctx, "localhost", port, "test@o2.pl", "app-password", &tls.Config{ServerName: "localhost", RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	msgUIDs, validity, err := client.SearchSince("INBOX", time.Time{}, 0)
	if err != nil || len(msgUIDs) != 1 {
		t.Fatalf("source: %v %v", msgUIDs, err)
	}
	sum := sha256.Sum256(raw)
	moved, err := client.MoveWithRaw("INBOX", validity, msgUIDs[0], "Review", false, hex.EncodeToString(sum[:]))
	if err != nil || moved.UID == 0 || moved.UIDValidity == 0 {
		t.Fatalf("unresolved move: %+v %v", moved, err)
	}
	if withoutMapping.omitted.Load() != 1 {
		t.Fatal("test did not omit the server's COPYUID response")
	}
	if got, err := client.Fetch("Review", moved.UID, true); err != nil || !bytes.Equal(got.Raw, raw) {
		t.Fatalf("wrong destination: %+v %v", got, err)
	}
}

func TestDeleteUIDRechecksUIDValidityImmediatelyBeforeExpunge(t *testing.T) {
	serverTLS, roots := testTLS(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(ln, serverTLS)

	backend := imapmemserver.New()
	user := imapmemserver.NewUser("test@o2.pl", "app-password")
	if err := user.Create("AI-Kwarantanna", nil); err != nil {
		t.Fatal(err)
	}
	backend.AddUser(user)
	var wrapped *uidValidityFlipSession
	server := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			wrapped = &uidValidityFlipSession{Session: backend.NewSession()}
			wrapped.flipOnSelect.Store(2)
			return wrapped, nil, nil
		},
		Caps: imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}},
	})
	go func() { _ = server.Serve(tlsListener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = ln.Close()
	})

	_, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portText)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := dialWithTLSConfig(ctx, "localhost", port, "test@o2.pl", "app-password", &tls.Config{
		ServerName: "localhost", RootCAs: roots, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	raw := []byte("From: sender@example.org\r\nMessage-ID: <expunge-guard@example.org>\r\n\r\nbody")
	appended, err := client.AppendUnread("AI-Kwarantanna", raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	err = client.DeleteUID("AI-Kwarantanna", appended.UIDValidity, appended.UID)
	if !errors.Is(err, ErrUIDValidityChanged) {
		t.Fatalf("UIDVALIDITY change before UID EXPUNGE was not detected: %v", err)
	}
	if wrapped == nil || wrapped.expunges.Load() != 0 {
		t.Fatalf("UID EXPUNGE ran after UIDVALIDITY changed: session=%v expunges=%d", wrapped != nil, wrapped.expunges.Load())
	}
}

func TestMoveAndFlagMutationRecheckUIDValidityBeforeCommands(t *testing.T) {
	serverTLS, roots := testTLS(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(ln, serverTLS)

	backend := imapmemserver.New()
	user := imapmemserver.NewUser("test@o2.pl", "app-password")
	for _, name := range []string{"INBOX", "Source"} {
		if err := user.Create(name, nil); err != nil {
			t.Fatal(err)
		}
	}
	backend.AddUser(user)
	var wrapped *uidValidityFlipSession
	server := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			wrapped = &uidValidityFlipSession{Session: backend.NewSession()}
			wrapped.flipOnSelect.Store(1)
			return wrapped, nil, nil
		},
		Caps: imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapMove: {}, imap.CapUIDPlus: {}},
	})
	go func() { _ = server.Serve(tlsListener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = ln.Close()
	})

	_, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portText)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := dialWithTLSConfig(ctx, "localhost", port, "test@o2.pl", "app-password", &tls.Config{
		ServerName: "localhost", RootCAs: roots, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	raw := []byte("From: sender@example.org\r\nMessage-ID: <mutation-guard@example.org>\r\n\r\nbody")

	source, err := client.AppendUnread("Source", raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Move("Source", source.UIDValidity, source.UID, "INBOX", false); !errors.Is(err, ErrUIDValidityChanged) {
		t.Fatalf("MOVE did not stop after UIDVALIDITY changed: %v", err)
	}
	if wrapped.moves.Load() != 0 {
		t.Fatalf("MOVE command reached the server after UIDVALIDITY changed: %d", wrapped.moves.Load())
	}

	inbox, err := client.AppendUnread("INBOX", raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wrapped.selects.Store(0)
	wrapped.flipOnSelect.Store(1)
	if err := client.MarkUnread("INBOX", inbox.UIDValidity, inbox.UID); !errors.Is(err, ErrUIDValidityChanged) {
		t.Fatalf("flag mutation did not stop after UIDVALIDITY changed: %v", err)
	}
	if wrapped.stores.Load() != 0 {
		t.Fatalf("STORE command reached the server after UIDVALIDITY changed: %d", wrapped.stores.Load())
	}
}

func TestDetectSpamFolderPrefersSpecialUse(t *testing.T) {
	boxes := []Mailbox{
		{Name: "Spam", IsJunk: false},
		{Name: "Niechciane przez serwer", IsJunk: true},
	}
	if got := DetectSpamFolder(boxes); got != "Niechciane przez serwer" {
		t.Fatalf("got %q", got)
	}
}

func testTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(mustParseCert(t, der))
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, roots
}

func mustParseCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
