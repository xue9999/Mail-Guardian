package imapmail

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/emersion/go-imap/v2"
)

func TestUnsupportedAuthenticationFailsBeforeOpeningAConnection(t *testing.T) {
	if _, err := DialAuthenticated(context.Background(), "", 0, Authentication{Method: "xoauth2", Username: "fixture", Secret: "never-log-this"}); err == nil {
		t.Fatal("unsupported authentication fell back to password LOGIN")
	}
}

func TestLoginFailureDistinguishesCredentialsFromTransportAndServerOutage(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
		auth  bool
	}{
		{"incorrect password", &imap.Error{Type: imap.StatusResponseTypeNo, Code: "AUTHENTICATIONFAILED"}, true},
		{"legacy login rejection", &imap.Error{Type: imap.StatusResponseTypeNo}, true},
		{"connection closed", io.ErrUnexpectedEOF, false},
		{"server unavailable", &imap.Error{Type: imap.StatusResponseTypeNo, Code: "UNAVAILABLE"}, false},
		{"server shutdown", &imap.Error{Type: imap.StatusResponseTypeBye}, false},
		{"protocol error", &imap.Error{Type: imap.StatusResponseTypeBad}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := loginError(tc.cause)
			if errors.Is(err, ErrAuthentication) != tc.auth || !errors.Is(err, tc.cause) {
				t.Fatalf("misclassified or lost original login failure: %v", err)
			}
		})
	}
}

func TestSafeMoveSupported(t *testing.T) {
	tests := []struct {
		name string
		caps Capabilities
		want bool
	}{
		{
			name: "UIDPLUS alone is rejected",
			caps: Capabilities{UIDPlus: true},
			want: false,
		},
		{
			name: "MOVE is accepted",
			caps: Capabilities{Move: true},
			want: true,
		},
		{
			name: "IMAP4rev2 is accepted",
			caps: Capabilities{IMAP4rev2: true},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeMoveSupported(tt.caps); got != tt.want {
				t.Fatalf("safeMoveSupported(%+v) = %t, want %t", tt.caps, got, tt.want)
			}
		})
	}
}

func TestRequireUIDValidityFailsClosed(t *testing.T) {
	for _, values := range [][2]uint32{{0, 7}, {7, 0}, {7, 8}} {
		err := requireUIDValidity("INBOX", values[0], values[1])
		if !errors.Is(err, ErrUIDValidityChanged) {
			t.Fatalf("expected UIDVALIDITY error for %v, got %v", values, err)
		}
	}
	if err := requireUIDValidity("INBOX", 7, 7); err != nil {
		t.Fatalf("matching UIDVALIDITY was rejected: %v", err)
	}
}
