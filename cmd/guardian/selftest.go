package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/store"
)

// Runs without user configuration, Keychain, IMAP, or services.
func (a *application) selfTest() error {
	root, err := os.MkdirTemp(selfTestTempParent(runtime.GOOS), "guardian-self-test-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	db, err := store.Open(filepath.Join(root, "test.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Summary(context.Background(), time.Now()); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Engine self-check: OK")
	return nil
}

func selfTestTempParent(goos string) string {
	if goos == "linux" {
		// The synthetic self-test must not honor TMPDIR pointing into an
		// instance while an administrator is publishing a migration.
		return "/tmp"
	}
	return ""
}
