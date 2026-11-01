package keychain

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/xue9999/Mail-Guardian/internal/secrets"
)

// ErrNotFound remains an alias for compatibility with existing callers.
var ErrNotFound = secrets.ErrNotFound

var _ secrets.Store = Store{}

type Store struct {
	SecurityPath string
}

func New() Store {
	return Store{SecurityPath: "/usr/bin/security"}
}

func (s Store) Available() bool {
	return runtime.GOOS == "darwin" && fileExists(s.SecurityPath)
}

func (s Store) Get(service, account string) (string, error) {
	if !s.Available() {
		return "", errors.New("macOS Keychain unavailable")
	}
	cmd := exec.Command(s.SecurityPath, "find-generic-password", "-s", service, "-a", account, "-w")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if strings.Contains(strings.ToLower(stderr.String()), "could not be found") ||
			strings.Contains(stderr.String(), "SecKeychainSearchCopyNext") {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("reading Keychain: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Set stores a generated secret without involving a shell or placing the
// secret in the process argument list. macOS security(1) accepts the password
// twice on standard input when -w is the final option.
func (s Store) Set(service, account, value, label string) error {
	if !s.Available() {
		return errors.New("macOS Keychain unavailable")
	}
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("invalid secret format for storage")
	}
	args := []string{"add-generic-password", "-s", service, "-a", account, "-U"}
	if label != "" {
		args = append(args, "-l", label)
	}
	args = append(args, "-w")
	cmd := exec.Command(s.SecurityPath, args...)
	cmd.Stdin = strings.NewReader(value + "\n" + value + "\n")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("writing Keychain: %w", err)
	}
	return nil
}

// PromptAndSet delegates hidden password input to the macOS security utility.
func (s Store) PromptAndSet(service, account, label string) error {
	if !s.Available() {
		return errors.New("macOS Keychain unavailable")
	}
	args := []string{"add-generic-password", "-s", service, "-a", account, "-U"}
	if label != "" {
		args = append(args, "-l", label)
	}
	args = append(args, "-w")
	cmd := exec.Command(s.SecurityPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("saving password in Keychain: %w", err)
	}
	return nil
}

func (s Store) Delete(service, account string) error {
	cmd := exec.Command(s.SecurityPath, "delete-generic-password", "-s", service, "-a", account)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("deleting from Keychain: %w", err)
	}
	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
