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
		return Connection{}, errors.New("nieobsługiwana metoda uwierzytelniania IMAP")
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
			return Connection{}, errors.New("profil o2 wymaga poczta.o2.pl:993; dla innego serwera wybierz custom")
		}
	case "custom":
	default:
		return Connection{}, errors.New("nieobsługiwany profil dostawcy poczty")
	}
	if host == "" || strings.TrimSpace(host) != host || strings.ContainsAny(host, "/\\@\r\n\x00 \t") || port < 1 || port > 65535 {
		return Connection{}, errors.New("nieprawidłowy adres lub port IMAP")
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return Connection{}, errors.New("adres IMAP nie może zawierać schematu ani portu")
	}
	if username == "" {
		username = email
	}
	if username == "" || strings.ContainsAny(username, "\r\n\x00") {
		return Connection{}, errors.New("brakuje prawidłowej nazwy logowania IMAP")
	}
	return Connection{profile, strings.ToLower(host), username, auth, port}, nil
}
