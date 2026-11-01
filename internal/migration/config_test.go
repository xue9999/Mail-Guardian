package migration

import (
	"reflect"
	"strings"
	"testing"

	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/platform"
)

func TestLinuxConfigPreservesResolvedIdentityAndPolicy(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			source := config.Default()
			if version == 2 {
				var err error
				source, err = config.NewInstance()
				source.Account.Provider = "o2"
				if err != nil {
					t.Fatal(err)
				}
			}
			source.Account.Email = "owner@example.invalid"
			source.Folders.ServerSpam = "Spam"
			source.Runtime.DataDir = "/Users/owner/Library/Application Support/Guardian"
			source.Safety.Mode, source.Safety.PurgeEnabled = "active", true
			source.Rspamd.SpamScore = 13
			resolved, err := source.Resolve()
			if err != nil {
				t.Fatal(err)
			}
			mapped, err := LinuxConfig(source, "pilot")
			if err != nil {
				t.Fatal(err)
			}
			paths, err := platform.LinuxPaths("pilot")
			if err != nil {
				t.Fatal(err)
			}
			if mapped.Runtime.DataDir != paths.Data || mapped.Runtime.Database != paths.Database || mapped.Runtime.ArchiveDir != paths.Archive || mapped.Runtime.LogFile != paths.Log || mapped.Runtime.ComposeFile != paths.Compose {
				t.Fatal("wrong Linux paths")
			}
			if mapped.Safety.Mode != source.Safety.Mode || mapped.Safety.PurgeEnabled {
				t.Fatal("source filtering mode changed or permanent deletion retained")
			}
			if mapped.MailboxFingerprint() != resolved.MailboxFingerprint() || mapped.AuthorizationFingerprint() != resolved.AuthorizationFingerprint() {
				t.Fatal("identity or folder authorization changed")
			}
			mapped.Runtime = resolved.Runtime
			mapped.Safety = resolved.Safety
			if !reflect.DeepEqual(mapped, resolved) {
				t.Fatal("other configuration fields changed")
			}
		})
	}
}

func TestLinuxConfigRejectsInvalidInstanceAndSource(t *testing.T) {
	source, err := config.NewInstance()
	source.Account.Provider = "o2"
	if err != nil {
		t.Fatal(err)
	}
	source.Account.Email, source.Folders.ServerSpam = "owner@example.invalid", "Spam"
	for _, name := range []string{"", "../escape", strings.Repeat("a", 30)} {
		if _, err := LinuxConfig(source, name); err == nil {
			t.Fatalf("accepted invalid instance %q", name)
		}
	}
	source.Account.TLS = false
	if _, err := LinuxConfig(source, "pilot"); err == nil {
		t.Fatal("accepted invalid source config")
	}
}
