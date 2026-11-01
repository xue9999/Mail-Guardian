package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/o2-mail-guardian/guardian/internal/provider"
)

// NewInstance creates identities for a new isolated installation. Default is
// retained as the v1 template so old callers/configurations keep their meaning.
func NewInstance() (Config, error) {
	c := Default()
	c.Version = 2
	for _, target := range []*string{&c.InstanceID, &c.Account.ID} {
		var value [16]byte
		if _, err := rand.Read(value[:]); err != nil {
			return Config{}, err
		}
		*target = hex.EncodeToString(value[:])
	}
	c.Account.Provider, c.Account.AuthMethod = "o2", provider.Password
	return c, nil
}

func validID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16 && id == strings.ToLower(id)
}

func identityHash(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (c Config) legacyIDs() (string, string) {
	account := identityHash([]string{"mail-guardian/legacy-o2-account/v1", strings.ToLower(c.Account.Email)})[:32]
	instance := identityHash([]string{"mail-guardian/legacy-instance/v1", account, c.Runtime.DataDir})[:32]
	return instance, account
}

// Resolve migrates v1 in memory. Loading never rewrites a file or changes paths,
// folder names, secret identifiers, scheduling or safety/quality history.
func (c Config) Resolve() (Config, error) {
	c, err := c.ResolveIdentity()
	if err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// ResolveIdentity normalizes identity without changing filtering thresholds.
func (c Config) ResolveIdentity() (Config, error) {
	if c.Version == 1 {
		if !strings.EqualFold(c.Account.Host, "poczta.o2.pl") || c.Account.Port != 993 || !c.Account.TLS {
			return Config{}, fmt.Errorf("konfiguracja v1 wymaga szyfrowanego połączenia o2:993")
		}
		if c.InstanceID != "" || c.Account.ID != "" || c.Account.Provider != "" || c.Account.Username != "" || c.Account.AuthMethod != "" {
			return Config{}, fmt.Errorf("konfiguracja v1 zawiera pola v2; jawnie wybierz wersję 2")
		}
		c.InstanceID, c.Account.ID = c.legacyIDs()
		c.Version = 2
		c.Account.Provider = "o2"
	}
	connection, err := provider.Resolve(c.Account.Provider, c.Account.Host, c.Account.Port, c.Account.Username, c.Account.Email, c.Account.AuthMethod)
	if err != nil {
		return Config{}, err
	}
	c.Account.Provider, c.Account.Host, c.Account.Port = connection.Provider, connection.Host, connection.Port
	c.Account.Username, c.Account.AuthMethod = connection.Username, connection.AuthMethod
	if c.Version != 2 || !validID(c.InstanceID) || !validID(c.Account.ID) || !c.Account.TLS {
		return Config{}, fmt.Errorf("nieprawidłowa wersja lub tożsamość konfiguracji")
	}
	return c, nil
}

// LegacyCompatible permits adoption of existing unbound o2 state only with the
// deterministic migration identity and the original mailbox connection.
func (c Config) LegacyCompatible() bool {
	instance, account := c.legacyIDs()
	return c.InstanceID == instance && c.Account.ID == account && c.Account.Provider == "o2" &&
		c.Account.Host == "poczta.o2.pl" && c.Account.Port == 993 && c.Account.Username == c.Account.Email && c.Account.AuthMethod == provider.Password
}

func (c Config) MailboxFingerprint() string {
	return identityHash([]string{c.InstanceID, c.Account.ID, c.Account.Provider, c.Account.Host,
		fmt.Sprint(c.Account.Port), c.Account.Username, c.Account.Email, c.Account.AuthMethod})
}

func (c Config) AuthorizationFingerprint() string {
	return identityHash(struct {
		Mailbox string
		Folders Folders
	}{c.MailboxFingerprint(), c.Folders})
}

func (a Account) LoginUsername() string {
	if a.Username != "" {
		return a.Username
	}
	return a.Email
}
