package archive

import (
	"errors"
	"testing"

	"filippo.io/age"
	"github.com/xue9999/Mail-Guardian/internal/secrets"
)

type identityStore struct {
	value  string
	err    error
	writes int
}

func (s *identityStore) Get(service, account string) (string, error) { return s.value, s.err }
func (s *identityStore) Set(service, account, value, label string) error {
	s.writes++
	s.value = value
	return nil
}
func (s *identityStore) Delete(service, account string) error { return nil }

func TestArchiveSecretBoundaryNeverReplacesUnreadableOrInvalidIdentity(t *testing.T) {
	for _, s := range []*identityStore{{err: errors.New("credential unavailable")}, {value: "corrupt identity"}} {
		if _, err := EnsureIdentity(s, "archive", "account"); err == nil {
			t.Fatal("invalid key accepted")
		}
		if s.writes != 0 {
			t.Fatal("unreadable key replaced")
		}
	}
	missing := &identityStore{err: secrets.ErrNotFound}
	if _, err := LoadIdentity(missing, "archive", "account"); !errors.Is(err, secrets.ErrNotFound) || missing.writes != 0 {
		t.Fatal("load generated replacement key")
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	existing := &identityStore{value: id.String()}
	loaded, err := EnsureIdentity(existing, "archive", "account")
	if err != nil || loaded.String() != id.String() || existing.writes != 0 {
		t.Fatal("existing archive identity changed")
	}
}
