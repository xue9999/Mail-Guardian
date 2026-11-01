package service

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/platform"
)

func (m Manager) systemdStatus() (string, error) {
	instance := filepath.Base(m.DataDir)
	paths, err := platform.LinuxPaths(instance)
	if err != nil || m.DataDir != paths.Data {
		return "", errors.New("invalid Linux service instance")
	}
	unit := "mail-guardian@" + instance + ".timer"
	for _, state := range []string{"is-enabled", "is-active"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := exec.CommandContext(ctx, "/usr/bin/systemctl", state, "--quiet", unit).Run()
		cancel()
		if err != nil {
			return "", fmt.Errorf("Linux timer %s is not enabled and active", unit)
		}
	}
	return "Linux timer " + unit + " is enabled and active\n", nil
}
