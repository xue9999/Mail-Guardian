package stack

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"runtime"
)

var storageFailurePattern = regexp.MustCompile(`(?i)I/O error(?:,| on)|EXT4-fs.*(?:failed to convert unwritten|Aborting journal|Remounting filesystem read-only)|EXT4-fs error`)
var ErrStorageIO = errors.New("wirtualny dysk Colimy zgłosił błąd zapisu; ochrona modelu została zablokowana. Zachowaj kopie i sprawdź dysk offline przed ponownym uruchomieniem Colimy")

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
		return errors.New("brakuje Colimy do kontroli dysku modelu")
	}
	ctx, cancel := context.WithTimeout(context.Background(), shortCommandTimeout)
	defer cancel()
	output, err := stackCommand(ctx, colima, "ssh", "--", "sudo", "dmesg", "--level=err,warn").Output()
	if err != nil {
		return fmt.Errorf("nie można potwierdzić sprawności dysku Colimy: %w", err)
	}
	return validateStorageLog(string(output))
}
