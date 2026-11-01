package stack

import (
	"errors"
	"testing"
)

func TestStorageGateDetectsTheActualAOFWriteFailure(t *testing.T) {
	for _, line := range []string{
		"I/O error, dev vdb, sector 25538456 op 0x1:(WRITE)",
		"Buffer I/O error on device vdb1, logical block 3192051",
		"EXT4-fs (vdb1): failed to convert unwritten extents to written extents -- potential data loss! (inode 786578, error -5)",
		"EXT4-fs error (device vdb1): bad block",
		"EXT4-fs (vdb1): Aborting journal",
	} {
		if !errors.Is(validateStorageLog(line), ErrStorageIO) {
			t.Fatalf("write failure ignored: %s", line)
		}
	}
	for _, line := range []string{"", "ACPI: Remapped I/O", "EXT4-fs (vdb1): mounted filesystem r/w", "FAT-fs (vda15): Volume was not properly unmounted"} {
		if err := validateStorageLog(line); err != nil {
			t.Fatalf("unrelated boot message blocked storage: %s", line)
		}
	}
}
