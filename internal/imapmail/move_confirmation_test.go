package imapmail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

// The memory server always sends COPYUID, even without advertising UIDPLUS.
// Replace its response code with an unknown, equal-length extension so these
// tests really exercise an OK MOVE without a destination mapping over TLS.
type noCopyUIDListener struct {
	net.Listener
	omitted atomic.Int32
}

func (l *noCopyUIDListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &noCopyUIDConn{Conn: c, omitted: &l.omitted}, nil
}

type noCopyUIDConn struct {
	net.Conn
	omitted *atomic.Int32
}

func (c *noCopyUIDConn) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("[COPYUID ")) {
		c.omitted.Add(1)
		p = bytes.ReplaceAll(p, []byte("[COPYUID "), []byte("[XOPYUID "))
	}
	return c.Conn.Write(p)
}

type confirmationSession struct {
	imapserver.Session
	user             *imapmemserver.User
	raw              []byte
	mode             string
	moved            atomic.Bool
	moves            atomic.Int32
	confirmations    atomic.Int32
	envelopeRequests atomic.Int32
	cancel           context.CancelFunc
}

func (s *confirmationSession) Move(w *imapserver.MoveWriter, set imap.NumSet, dest string) error {
	s.moves.Add(1)
	if s.mode == "unrelated-envelope" {
		if _, err := s.user.Append(dest, bytes.NewReader([]byte("Subject: unrelated\r\n\r\nother")), &imap.AppendOptions{}); err != nil {
			return err
		}
	}
	if err := s.Session.(imapserver.SessionMove).Move(w, set, dest); err != nil {
		return err
	}
	if s.mode == "duplicate" {
		if _, err := s.user.Append(dest, bytes.NewReader(s.raw), &imap.AppendOptions{}); err != nil {
			return err
		}
	}
	s.moved.Store(true)
	return nil
}

func (s *confirmationSession) Select(folder string, options *imap.SelectOptions) (*imap.SelectData, error) {
	data, err := s.Session.Select(folder, options)
	if err != nil || folder != "Review" || !options.ReadOnly || !s.moved.Load() {
		return data, err
	}
	n := s.confirmations.Add(1)
	copy := *data
	switch s.mode {
	case "delayed", "cancel":
		if n == 1 {
			copy.UIDNext-- // First destination snapshot has not caught up yet.
			if s.mode == "cancel" {
				s.cancel()
			}
		}
	case "never-visible":
		copy.UIDNext--
	case "epoch-changed":
		copy.UIDValidity++
	}
	return &copy, nil
}

func (s *confirmationSession) Fetch(w *imapserver.FetchWriter, set imap.NumSet, options *imap.FetchOptions) error {
	if s.mode == "unrelated-envelope" && s.moved.Load() && options.Envelope {
		s.envelopeRequests.Add(1)
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "unavailable envelope"}
	}
	return s.Session.Fetch(w, set, options)
}

func TestMoveConfirmationWithoutCopyUID(t *testing.T) {
	for _, mode := range []string{"delayed", "unrelated-envelope", "duplicate", "epoch-changed", "never-visible", "cancel"} {
		t.Run(mode, func(t *testing.T) {
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
			raw := []byte("From: sender@example.org\r\nMessage-ID: <confirm@example.org>\r\nSubject: confirm\r\n\r\nbody")
			if _, err := user.Append("INBOX", bytes.NewReader(raw), &imap.AppendOptions{Flags: []imap.Flag{imap.FlagSeen}}); err != nil {
				t.Fatal(err)
			}
			// An existing identical copy must not be mistaken for this move.
			if _, err := user.Append("Review", bytes.NewReader(raw), &imap.AppendOptions{}); err != nil {
				t.Fatal(err)
			}
			backend.AddUser(user)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			session := &confirmationSession{user: user, raw: raw, mode: mode, cancel: cancel}
			server := imapserver.New(&imapserver.Options{
				NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
					session.Session = backend.NewSession()
					return session, nil, nil
				},
				Caps:         imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapMove: {}},
				InsecureAuth: true, // The fixture wraps TLS, hiding its concrete type.
			})
			listener := &noCopyUIDListener{Listener: tls.NewListener(ln, serverTLS)}
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(func() { _ = server.Close(); _ = ln.Close() })
			_, portText, _ := net.SplitHostPort(ln.Addr().String())
			port, _ := strconv.Atoi(portText)
			client, err := dialWithTLSConfig(ctx, "localhost", port, "test@o2.pl", "app-password", &tls.Config{ServerName: "localhost", RootCAs: roots, MinVersion: tls.VersionTLS12})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			uids, validity, err := client.SearchSince("INBOX", time.Time{}, 0)
			if err != nil || len(uids) != 1 {
				t.Fatalf("source: %v %v", uids, err)
			}
			sum := sha256.Sum256(raw)
			started := time.Now()
			result, err := client.MoveWithRaw("INBOX", validity, uids[0], "Review", true, hex.EncodeToString(sum[:]))
			if session.moves.Load() != 1 || listener.omitted.Load() != 1 {
				t.Fatalf("MOVE repeated or mapping not suppressed: moves=%d omitted=%d", session.moves.Load(), listener.omitted.Load())
			}
			switch mode {
			case "delayed", "unrelated-envelope":
				if err != nil || result.UID <= 1 || result.UIDValidity == 0 {
					t.Fatalf("confirmation failed: %+v %v", result, err)
				}
				if mode == "delayed" && session.confirmations.Load() != 2 {
					t.Fatal("did not retry stale destination view")
				}
				if session.envelopeRequests.Load() != 0 {
					t.Fatal("confirmation fetched an unnecessary envelope")
				}
				items, fetchErr := client.client.Fetch(imap.UIDSetNum(imap.UID(result.UID)), &imap.FetchOptions{UID: true, Flags: true}).Collect()
				if fetchErr != nil || len(items) != 1 {
					t.Fatalf("flags: %v %v", items, fetchErr)
				}
				for _, flag := range items[0].Flags {
					if flag == imap.FlagSeen {
						t.Fatal("rescued message remains read")
					}
				}

			case "cancel":
				if result.UID != 0 || time.Since(started) > time.Second {
					t.Fatalf("cancellation ignored: %+v %v", result, err)
				}
				if !errors.Is(context.Cause(ctx), context.Canceled) {
					t.Fatal("fixture did not cancel")
				}
			default:
				if err != nil || result.UID != 0 {
					t.Fatalf("uncertain move falsely confirmed: %+v %v", result, err)
				}
				want := int32(1)
				if mode == "never-visible" {
					want = 3
				}
				if session.confirmations.Load() != want {
					t.Fatalf("unexpected confirmation attempts: %d", session.confirmations.Load())
				}
			}
		})
	}
}
