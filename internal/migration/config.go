package migration

import (
	"errors"

	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/platform"
)

// LinuxConfig maps a source configuration to the existing Linux pilot paths.
// Resolve legacy identity before changing any path: the legacy instance ID is
// derived from the original data directory. The returned value is only a
// configuration candidate; it does not import data or authorize mailbox work.
func LinuxConfig(source config.Config, instance string) (config.Config, error) {
	if len(instance) > 29 {
		return config.Config{}, errors.New("Linux instance name exceeds the worker account limit")
	}
	source, err := source.Resolve()
	if err != nil {
		return config.Config{}, err
	}
	paths, err := platform.LinuxPaths(instance)
	if err != nil {
		return config.Config{}, err
	}
	mailbox, authorization := source.MailboxFingerprint(), source.AuthorizationFingerprint()
	result := source
	result.Runtime.DataDir, result.Runtime.Database = paths.Data, paths.Database
	result.Runtime.ArchiveDir, result.Runtime.LogFile, result.Runtime.ComposeFile = paths.Archive, paths.Log, paths.Compose
	// Moving the same mailbox does not change the user's filtering policy.
	// Operational authorization is renewed separately on the destination;
	// the ordinary activation-quality gate remains mandatory for active mode.
	result.Safety.PurgeEnabled = false
	if err := result.Validate(); err != nil {
		return config.Config{}, err
	}
	if result.MailboxFingerprint() != mailbox || result.AuthorizationFingerprint() != authorization {
		return config.Config{}, errors.New("mailbox or folder identity changed during configuration mapping")
	}
	return result, nil
}
