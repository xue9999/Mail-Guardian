// Package platform contains explicit host contracts. Existing installation
// paths are configuration data and must not change when the product is renamed.
package platform

import (
	"errors"
	"path/filepath"
	"strings"
)

type Paths struct {
	Config, Data, Database, Archive, Log, Compose string
}

// LinuxPaths describes administrator-provisioned locations. It does not create
// them or grant the worker access to Docker or administrator credentials.
func LinuxPaths(instance string) (Paths, error) {
	if instance == "" || len(instance) > 64 || strings.Trim(instance, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" || strings.HasPrefix(instance, "-") {
		return Paths{}, errors.New("invalid Linux instance name")
	}
	configRoot := filepath.Join("/etc/mail-guardian", instance)
	data := filepath.Join("/var/lib/mail-guardian", instance)
	return Paths{
		Config: filepath.Join(configRoot, "config.toml"), Data: data,
		Database: filepath.Join(data, "guardian.db"), Archive: filepath.Join(data, "archive"),
		Log: filepath.Join(data, "guardian.log"), Compose: filepath.Join(configRoot, "deploy", "compose.yaml"),
	}, nil
}
