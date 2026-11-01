// Package provider resolves connection settings without performing network IO.
package provider

import (
	"errors"
	"net"
	"strings"
)

const Password = "password"

type Connection struct {
	Provider, Host, Username, AuthMethod string
	Port                                 int
}

// Resolve supplies defaults only for known profiles. Custom IMAP always needs
// an explicit endpoint; every supported profile uses verified implicit TLS.
func Resolve(profile, host string, port int, username, email, auth string) (Connection, error) {
	if profile == "" {
		profile = "o2"
	}
	if auth == "" {
		auth = Password
	}
	if auth != Password {
		return Connection{}, errors.New("unsupported IMAP authentication method")
	}
	switch profile {
	case "o2":
		if host == "" {
			host = "poczta.o2.pl"
		}
		if port == 0 {
			port = 993
		}
		if !strings.EqualFold(host, "poczta.o2.pl") || port != 993 {
			return Connection{}, errors.New("o2 profile requires poczta.o2.pl:993; use custom for another server")
		}
	case "custom":
	default:
		return Connection{}, errors.New("unsupported email provider profile")
	}
	if host == "" || strings.TrimSpace(host) != host || strings.ContainsAny(host, "/\\@\r\n\x00 \t") || port < 1 || port > 65535 {
		return Connection{}, errors.New("invalid IMAP host or port")
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return Connection{}, errors.New("IMAP host must not include a scheme or port")
	}
	if username == "" {
		username = email
	}
	if username == "" || strings.ContainsAny(username, "\r\n\x00") {
		return Connection{}, errors.New("missing valid IMAP login name")
	}
	return Connection{profile, strings.ToLower(host), username, auth, port}, nil
}
