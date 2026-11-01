package apperror

import (
	"errors"

	"github.com/xue9999/Mail-Guardian/internal/imapmail"
)

type Code string

const (
	Unknown         Code = "UNKNOWN"
	Cancelled       Code = "CANCELLED"
	Config          Code = "CONFIG_INVALID"
	IMAPAuth        Code = "IMAP_AUTH"
	IMAPUIDValidity Code = "IMAP_UIDVALIDITY"
	Keychain        Code = "KEYCHAIN_UNAVAILABLE"
	ArchiveKey      Code = "ARCHIVE_KEY"
	Rspamd          Code = "RSPAMD_UNAVAILABLE"
	BayesRollback   Code = "BAYES_ROLLBACK"
	ServiceStale    Code = "SERVICE_STALE"
	Busy            Code = "GUARDIAN_BUSY"
)

var ErrCancelled = errors.New("anulowano")

type Error struct {
	Code     Code
	Severity string
	Message  string
	Recovery string
	Cause    error
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return string(e.Code)
}

func (e *Error) Unwrap() error { return e.Cause }

func Wrap(code Code, severity, message, recovery string, cause error) error {
	return &Error{Code: code, Severity: severity, Message: message, Recovery: recovery, Cause: cause}
}

func From(err error) *Error {
	if err == nil {
		return nil
	}
	var typed *Error
	if errors.As(err, &typed) {
		return typed
	}
	if errors.Is(err, imapmail.ErrAuthentication) {
		return &Error{Code: IMAPAuth, Severity: "attention", Message: "The mail server rejected authentication.", Recovery: "Check your provider's account security and create a new app password where supported.", Cause: err}
	}
	if errors.Is(err, imapmail.ErrUIDValidityChanged) {
		return &Error{Code: IMAPUIDValidity, Severity: "attention", Message: "The server changed the folder identity; the operation was stopped safely.", Recovery: "Run Check now or Repair again.", Cause: err}
	}
	if errors.Is(err, ErrCancelled) {
		return &Error{Code: Cancelled, Severity: "info", Message: "Operation cancelled.", Recovery: "Nothing was changed.", Cause: err}
	}
	return &Error{
		Code: Unknown, Severity: "error", Message: err.Error(),
		Recovery: "Choose Check and repair. Guardian left mail safely on the server.",
		Cause:    err,
	}
}
