package stack

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"runtime"
)

var storageFailurePattern = regexp.MustCompile(`(?i)I/O error(?:,| on)|EXT4-fs.*(?:failed to convert unwritten|Aborting journal|Remounting filesystem read-only)|EXT4-fs error`)
var ErrStorageIO = errors.New("Colima virtual disk reported a write error; model protection blocked. Retain backups and check the disk offline before restarting Colima")

func validateStorageLog(log string) error {
	if storageFailurePattern.MatchString(log) {
		return ErrStorageIO
	}
	return nil
}

// CheckStorage rejects latent guest write errors even when Redis still serves
// its in-memory model and reports successful later writes.
func (m Manager) CheckStorage() error {
	if runtime.GOOS == "linux" {
		_, err := m.linuxMaintenance("check-storage")
		return err
	}
	colima := commandPath("colima")
	if colima == "" {
		return errors.New("Colima unavailable for model disk check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), shortCommandTimeout)
	defer cancel()
	output, err := stackCommand(ctx, colima, "ssh", "--", "sudo", "dmesg", "--level=err,warn").Output()
	if err != nil {
		return fmt.Errorf("cannot confirm Colima disk health: %w", err)
	}
	return validateStorageLog(string(output))
}
