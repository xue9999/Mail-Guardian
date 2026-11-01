// Package secrets defines platform-independent access to runtime credentials.
package secrets

import "errors"

var (
	ErrNotFound = errors.New("sekret nie istnieje")
	ErrReadOnly = errors.New("magazyn sekretów jest tylko do odczytu")
)

type Reader interface {
	Get(service, account string) (string, error)
}

type Store interface {
	Reader
	Set(service, account, value, label string) error
	Delete(service, account string) error
}

type Key struct{ Service, Account string }
