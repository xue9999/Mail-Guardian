package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/o2-mail-guardian/guardian/internal/archive"
	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/imapmail"
	"github.com/o2-mail-guardian/guardian/internal/rspamd"
	"github.com/o2-mail-guardian/guardian/internal/store"
)

const (
	absoluteArchiveLimit          = 100 << 20
	technicalHistoryRetentionDays = 180
)

var ErrRestoreAlreadyPresent = errors.New("wiadomość już istnieje w zapisanym folderze; nie utworzono duplikatu")

type Reporter func(kind, message string)

type MailClient interface {
	SafeMoveSupported() bool
	SafeDeleteSupported() bool
	EnsureMailboxes(names ...string) error
	SearchSince(folder string, since time.Time, limit int) ([]uint32, uint32, error)
	SearchUIDPage(folder string, afterUID uint32, limit int) ([]uint32, uint32, bool, error)
	Fetch(folder string, uid uint32, withRaw bool) (imapmail.Message, error)
	Move(folder string, uidValidity, uid uint32, destination string, markUnread bool) (imapmail.MoveResult, error)
	MarkUnread(folder string, uidValidity, uid uint32) error
	AppendUnread(folder string, raw []byte, internalDate time.Time) (imapmail.MoveResult, error)
	DeleteUID(folder string, uidValidity, uid uint32) error
}

type SpamScanner interface {
	Scan(ctx context.Context, raw []byte, recipient string) (rspamd.Result, error)
	Learn(ctx context.Context, raw []byte, spam bool) error
}

type Engine struct {
	Config  config.Config
	Mail    MailClient
	Rspamd  SpamScanner
	Store   *store.DB
	Archive *archive.Manager
	Report  Reporter
	Now     func() time.Time
}

type RunOptions struct {
	DryRun bool
}

func (e *Engine) Run(ctx context.Context, options RunOptions) (run *store.Run, retErr error) {
	e.setDefaults()
	if err := e.prepareStore(ctx); err != nil {
		return nil, err
	}
	run, err := e.Store.BeginRun(ctx, "run", options.DryRun)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cause := context.Cause(ctx); cause != nil {
			retErr = cause
			if run.Errors == 0 {
				run.Errors = 1
			}
		}
		if finishErr := e.Store.FinishRun(context.Background(), run, retErr); finishErr != nil && retErr == nil {
			retErr = finishErr
		}
	}()

	if !options.DryRun {
		if err := e.Store.RequireOperationalAuthorization(ctx); err != nil {
			return run, err
		}
		if !e.Mail.SafeMoveSupported() {
			return run, errors.New("serwer nie zapewnia natywnego IMAP MOVE; przenoszenie wiadomości jest zablokowane")
		}
		if err := e.Mail.EnsureMailboxes(
			e.Config.Folders.Quarantine,
			e.Config.Folders.Review,
			e.Config.Folders.TrainSpam,
			e.Config.Folders.TrainHam,
		); err != nil {
			return run, err
		}
		allowAutomaticReconciliation := true
		if e.Config.Safety.Mode == "active" {
			allowAutomaticReconciliation = e.requireActivationQuality(ctx) == nil
		}
		if err := e.reconcilePendingWithPolicy(ctx, allowAutomaticReconciliation); err != nil {
			return run, err
		}
	}

	e.Report("info", "Sprawdzam foldery uczące…")
	if err := e.processTraining(ctx, run, e.Config.Folders.TrainSpam, true, options.DryRun); err != nil {
		return run, err
	}
	if err := e.processTraining(ctx, run, e.Config.Folders.TrainHam, false, options.DryRun); err != nil {
		return run, err
	}
	if !options.DryRun && e.Config.Safety.Mode == "active" {
		if err := e.requireActivationQuality(ctx); err != nil {
			return run, err
		}
	}

	e.Report("info", "Sprawdzam folder SPAM o2…")
	if err := e.processFolder(ctx, run, e.Config.Folders.ServerSpam, sourceSpam, options.DryRun); err != nil {
		return run, err
	}
	e.Report("info", "Sprawdzam Odebrane…")
	if err := e.processFolder(ctx, run, e.Config.Folders.Inbox, sourceInbox, options.DryRun); err != nil {
		return run, err
	}
	if !options.DryRun {
		if err := e.reconcilePendingRestores(ctx); err != nil {
			return run, err
		}
		pending, err := e.Store.PendingMessages(ctx, e.Config.Account.Email)
		if err != nil {
			return run, err
		}
		restores, err := e.Store.PendingRestores(ctx, e.Config.Account.Email)
		if err != nil {
			return run, err
		}
		if remaining := len(pending) + len(restores); remaining > 0 && run.Errors == 0 {
			run.Errors = remaining
			e.Report("warning", "Przebieg nie jest w pełni zakończony: pozostały operacje do automatycznego uzgodnienia.")
		}
	}
	return run, nil
}

const (
	sourceInbox = "inbox"
	sourceSpam  = "server_spam"
)

func (e *Engine) setDefaults() {
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Report == nil {
		e.Report = func(string, string) {}
	}
}

func (e *Engine) prepareStore(ctx context.Context) error {
	if err := e.Store.IntegrityCheck(ctx); err != nil {
		return fmt.Errorf("kontrola integralności stanu zablokowała działanie: %w", err)
	}
	if err := e.Store.BindConfiguration(ctx, e.Config, e.Now()); err != nil {
		return err
	}
	before := e.Now().UTC().AddDate(0, 0, -technicalHistoryRetentionDays)
	if err := e.Store.PruneTechnicalHistory(ctx, before); err != nil {
		return fmt.Errorf("retencja technicznej historii: %w", err)
	}
	return nil
}

func (e *Engine) requireActivationQuality(ctx context.Context) error {
	now := e.Now().UTC()
	installedRaw, err := e.Store.GetSetting(ctx, "installed_at")
	if err != nil {
		return fmt.Errorf("odczyt daty instalacji: %w", err)
	}
	installedAt, err := parseSettingTime(installedRaw)
	if err != nil {
		return errors.New("brakuje prawidłowej daty instalacji; tryb aktywny pozostaje zablokowany")
	}
	protectRaw, err := e.Store.GetSetting(ctx, "protect_since")
	if err != nil {
		return fmt.Errorf("odczyt początku trybu ochronnego: %w", err)
	}
	protectAt := installedAt
	if protectRaw != "" {
		protectAt, err = parseSettingTime(protectRaw)
		if err != nil || protectAt.Before(installedAt) || protectAt.After(now) {
			return errors.New("brakuje prawidłowej daty trybu ochronnego; tryb aktywny pozostaje zablokowany")
		}
	}
	if now.Before(protectAt.Add(time.Duration(e.Config.Safety.ProtectDays) * 24 * time.Hour)) {
		return fmt.Errorf("tryb ochronny musi działać co najmniej %d pełnych dni", e.Config.Safety.ProtectDays)
	}
	activeRaw, err := e.Store.GetSetting(ctx, "active_since")
	if err != nil {
		return fmt.Errorf("odczyt daty aktywacji: %w", err)
	}
	activeAt, err := parseSettingTime(activeRaw)
	if err != nil || activeAt.Before(protectAt) || activeAt.After(now) {
		return errors.New("brakuje prawidłowej daty aktywacji; automatyczne ruchy pozostają zablokowane")
	}
	qualified, err := e.Store.CurrentQualification(ctx, e.Config, now)
	if err != nil {
		return fmt.Errorf("aktualna ocena filtra: %w", err)
	}
	if qualified != nil {
		return nil
	}
	if e.Config.Rspamd.SpamScore < 12 {
		return errors.New("próg poniżej 12 wymaga odrębnej oceny filtra")
	}
	quality, err := e.Store.ActivationQualityUntil(ctx, e.Config.Account.Email, protectAt, activeAt)
	if err != nil {
		return fmt.Errorf("sprawdzenie jakości okresu ochronnego: %w", err)
	}
	if !quality.Ready() {
		return fmt.Errorf(
			"okres ochronny nie spełnia kryteriów jakości (błędny spam: %d, błędne ratowanie: %d, oznaczony spam: %d, trafnie wykryty: %d, bez wyjaśnienia: %d)",
			quality.FalsePositives,
			quality.FalseRescues,
			quality.SpamFeedback,
			quality.SpamPreviouslySpam,
			quality.SpamUnexplained,
		)
	}
	return nil
}

func parseSettingTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errors.New("brak daty")
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC(), nil
	}
	return time.Time{}, errors.New("nieprawidłowa data")
}

func (e *Engine) reconcilePending(ctx context.Context) error {
	return e.reconcilePendingWithPolicy(ctx, true)
}

// Explicit corrections remain actionable after qualification is revoked.
// Automatic pending moves require the same quality gate as new decisions.
func (e *Engine) reconcilePendingWithPolicy(ctx context.Context, allowAutomatic bool) error {
	pending, err := e.Store.PendingMessages(ctx, e.Config.Account.Email)
	if err != nil {
		return fmt.Errorf("odczyt nierozstrzygniętych ruchów: %w", err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for _, record := range pending {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		explicitCorrection := record.Feedback == "ham" || record.Feedback == "spam" || record.FeedbackIntent == "ham" || record.FeedbackIntent == "spam"
		if !allowAutomatic && !explicitCorrection {
			continue
		}
		if time.Now().After(deadline) {
			e.Report("info", "Uzgadnianie przerwanych ruchów będzie kontynuowane w następnym przebiegu")
			break
		}
		destination, finalStatus, ok := e.pendingDestination(record.Action)
		if !ok {
			_ = e.Store.AddEvent(ctx, record.ID, "move_ambiguous", "nieznany docelowy stan ruchu")
			if err := e.Store.UpdateLocation(ctx, record.ID, record.CurrentFolder, record.UIDValidity, record.UID, "move_ambiguous"); err != nil {
				return err
			}
			_ = e.Store.DeleteReconcileProgress(ctx, record.ID)
			continue
		}
		if _, ok := e.Mail.(interface {
			SearchExactSize(string, int64) ([]uint32, uint32, error)
		}); ok {
			if err := e.reconcileBySize(ctx, record, destination, finalStatus, deadline); err != nil {
				_ = e.Store.AddEvent(ctx, record.ID, "move_uncertain", err.Error())
			}
			continue
		}
		if record.Status == "move_ambiguous" {
			// A user or server may have removed one of the conflicting copies.
			// Start a new bounded pass instead of trusting the old ambiguity.
			_ = e.Store.DeleteReconcileProgress(ctx, record.ID)
		}
		progress, err := e.Store.ReconcileProgress(ctx, record.ID)
		if err != nil {
			return err
		}
		if !progress.SourceComplete {
			if err := e.scanReconcilePage(ctx, record.CurrentFolder, record, &progress, true, deadline); err != nil {
				_ = e.Store.AddEvent(ctx, record.ID, "move_uncertain", "nie udało się sprawdzić strony folderu źródłowego")
				continue
			}
		}
		if !progress.DestinationComplete && time.Now().Before(deadline) {
			if err := e.scanReconcilePage(ctx, destination, record, &progress, false, deadline); err != nil {
				_ = e.Store.AddEvent(ctx, record.ID, "move_uncertain", "nie udało się sprawdzić strony folderu docelowego")
				continue
			}
		}
		progress.UpdatedAt = e.Now().UTC()
		if err := e.Store.SaveReconcileProgress(ctx, progress); err != nil {
			return err
		}
		if !progress.SourceComplete || !progress.DestinationComplete {
			_ = e.Store.AddEvent(ctx, record.ID, "move_reconcile_progress", "zapisano częściowy postęp bez blokowania nowej poczty")
			continue
		}
		if err := e.finishReconciliation(ctx, record, destination, finalStatus, progress); err != nil {
			_ = e.Store.AddEvent(ctx, record.ID, "move_uncertain", err.Error())
			continue
		}
	}
	return context.Cause(ctx)
}

// Unrelated server messages can fail ENVELOPE/BODY fetch permanently. Search
// by exact RFC822 size first, then require full content matches on both sides.
// A failed search or candidate read cannot prove absence and never retries MOVE.
func (e *Engine) reconcileBySize(ctx context.Context, record store.Message, destination, finalStatus string, deadline time.Time) error {
	search := e.Mail.(interface {
		SearchExactSize(string, int64) ([]uint32, uint32, error)
	})
	p := store.ReconcileProgress{}
	for _, source := range []bool{true, false} {
		folder := destination
		if source {
			folder = record.CurrentFolder
		}
		uids, validity, err := search.SearchExactSize(folder, record.SizeBytes)
		if err != nil {
			return err
		}
		if validity == 0 || len(uids) > 1000 {
			return errors.New("uzgadnianie wymaga pełnego, ograniczonego wyniku wyszukiwania")
		}
		for _, uid := range uids {
			if err := context.Cause(ctx); err != nil {
				return err
			}
			if time.Now().After(deadline) {
				return errors.New("uzgadnianie będzie kontynuowane w następnym przebiegu")
			}
			message, err := e.Mail.Fetch(folder, uid, true)
			if err != nil {
				return err
			}
			if !messageMatchesRecord(message, record) {
				continue
			}
			if source {
				p.SourceMatches++
				p.SourceMatchUID = uid
			} else {
				p.DestinationMatches++
				p.DestinationMatchUID = uid
			}
		}
		if source {
			p.SourceUIDValidity, p.SourceComplete = validity, true
		} else {
			p.DestinationUIDValidity, p.DestinationComplete = validity, true
		}
	}
	return e.finishReconciliation(ctx, record, destination, finalStatus, p)
}

func (e *Engine) scanReconcilePage(ctx context.Context, folder string, record store.Message, progress *store.ReconcileProgress, source bool, deadline time.Time) error {
	cursor := progress.DestinationCursor
	knownValidity := progress.DestinationUIDValidity
	if source {
		cursor = progress.SourceCursor
		knownValidity = progress.SourceUIDValidity
	}
	uids, uidValidity, pageComplete, err := e.Mail.SearchUIDPage(folder, cursor, 250)
	if err != nil {
		return err
	}
	if knownValidity != 0 && knownValidity != uidValidity {
		cursor = 0
		uids, uidValidity, pageComplete, err = e.Mail.SearchUIDPage(folder, 0, 250)
		if err != nil {
			return err
		}
		if source {
			progress.SourceCursor, progress.SourceMatches, progress.SourceMatchUID = 0, 0, 0
		} else {
			progress.DestinationCursor, progress.DestinationMatches, progress.DestinationMatchUID = 0, 0, 0
		}
	}
	processedAll := true
	for _, uid := range uids {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			processedAll = false
			break
		}
		metadata, err := e.Mail.Fetch(folder, uid, false)
		if err != nil {
			return err
		}
		matched := false
		if metadata.Size == record.SizeBytes && hashText(metadata.MessageID) == record.MessageIDHash {
			message, err := e.Mail.Fetch(folder, uid, true)
			if err != nil {
				return err
			}
			matched = messageMatchesRecord(message, record)
		}
		if source {
			progress.SourceCursor = uid
			if matched {
				progress.SourceMatches++
				if progress.SourceMatchUID == 0 {
					progress.SourceMatchUID = uid
				}
			}
		} else {
			progress.DestinationCursor = uid
			if matched {
				progress.DestinationMatches++
				if progress.DestinationMatchUID == 0 {
					progress.DestinationMatchUID = uid
				}
			}
		}
	}
	if source {
		progress.SourceUIDValidity = uidValidity
		progress.SourceComplete = processedAll && pageComplete
	} else {
		progress.DestinationUIDValidity = uidValidity
		progress.DestinationComplete = processedAll && pageComplete
	}
	return nil
}

func (e *Engine) finishReconciliation(ctx context.Context, record store.Message, destination, finalStatus string, p store.ReconcileProgress) error {
	markUnread := record.Action == "rescued" || record.Action == "rescue" || record.Action == "learn_ham"
	switch {
	case p.SourceMatches > 1 || p.DestinationMatches > 1 || (p.SourceMatches == 1 && p.DestinationMatches == 1):
		if err := e.Store.UpdateLocation(ctx, record.ID, record.CurrentFolder, 0, 0, "move_ambiguous"); err != nil {
			return err
		}
		return errors.New("ruch pozostaje niejednoznaczny, ponieważ znaleziono więcej niż jedną zgodną kopię")
	case p.SourceMatches == 1 && p.DestinationMatches == 0:
		message, err := e.Mail.Fetch(record.CurrentFolder, p.SourceMatchUID, true)
		if err != nil || !messageMatchesRecord(message, record) {
			_ = e.Store.DeleteReconcileProgress(ctx, record.ID)
			return errors.New("kopii źródłowej nie udało się ponownie potwierdzić; skan zostanie wznowiony")
		}
		if err := e.Store.UpdateLocation(ctx, record.ID, record.CurrentFolder, message.UIDValidity, message.UID, "pending_move"); err != nil {
			return err
		}
		if err := e.movePending(ctx, record.ID, message, destination, finalStatus, markUnread); err != nil {
			return fmt.Errorf("ponowienie ruchu ID %d: %w", record.ID, err)
		}
		_ = e.Store.DeleteReconcileProgress(ctx, record.ID)
		return e.Store.AddEvent(ctx, record.ID, "move_retry", "ponowiono ruch po pełnym, stronicowanym uzgodnieniu")
	case p.SourceMatches == 0 && p.DestinationMatches == 1:
		message, err := e.Mail.Fetch(destination, p.DestinationMatchUID, true)
		if err != nil || !messageMatchesRecord(message, record) {
			_ = e.Store.DeleteReconcileProgress(ctx, record.ID)
			return errors.New("kopii docelowej nie udało się ponownie potwierdzić; skan zostanie wznowiony")
		}
		if markUnread {
			if err := e.Mail.MarkUnread(destination, message.UIDValidity, message.UID); err != nil {
				_ = e.Store.AddEvent(ctx, record.ID, "unread_warning", "nie udało się usunąć flagi przeczytania")
			}
		}
		if err := e.Store.FinalizeMove(ctx, record.ID, destination, message.UIDValidity, message.UID, finalStatus, e.Now().UTC(), e.Config.Safety.QuarantineDays, e.Config.Safety.ArchiveDays); err != nil {
			return err
		}
		_ = e.Store.DeleteReconcileProgress(ctx, record.ID)
		return e.Store.AddEvent(ctx, record.ID, "move_reconciled", "potwierdzono jedną zgodną kopię docelową")
	default:
		if err := e.Store.UpdateLocation(ctx, record.ID, record.CurrentFolder, 0, 0, "move_ambiguous"); err != nil {
			return err
		}
		return errors.New("nie znaleziono potwierdzonej kopii źródłowej ani docelowej; zaszyfrowana kopia lokalna została zachowana")
	}
}

func (e *Engine) reconcilePendingRestores(ctx context.Context) error {
	pending, err := e.Store.PendingRestores(ctx, e.Config.Account.Email)
	if err != nil {
		return fmt.Errorf("odczyt nierozstrzygniętych przywróceń: %w", err)
	}
	for _, record := range pending {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if err := e.Restore(ctx, record.ID); err != nil {
			return fmt.Errorf("uzgadnianie przywrócenia ID %d: %w", record.ID, err)
		}
		e.Report("success", "Dokończono wcześniej przerwane odzyskiwanie wiadomości")
	}
	return nil
}

func (e *Engine) pendingDestination(action string) (destination, finalStatus string, ok bool) {
	switch action {
	case "quarantine", "quarantined", "learn_spam":
		return e.Config.Folders.Quarantine, "quarantined", true
	case "review":
		return e.Config.Folders.Review, "review", true
	case "rescue", "rescued", "learn_ham":
		return e.Config.Folders.Inbox, "rescued", true
	default:
		return "", "", false
	}
}

func (e *Engine) findMatchingMessages(ctx context.Context, folder string, record store.Message) ([]imapmail.Message, error) {
	// MOVE/COPY preserves InternalDate, so a recent first_seen window could miss
	// an old message. Reconciliation intentionally searches the full folder.
	uids, _, err := e.Mail.SearchSince(folder, time.Time{}, 0)
	if err != nil {
		return nil, err
	}
	var matches []imapmail.Message
	for _, uid := range uids {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		metadata, err := e.Mail.Fetch(folder, uid, false)
		if err != nil {
			return nil, err
		}
		if metadata.Size != record.SizeBytes || hashText(metadata.MessageID) != record.MessageIDHash {
			continue
		}
		message, err := e.Mail.Fetch(folder, uid, true)
		if err != nil {
			return nil, err
		}
		if messageMatchesRecord(message, record) {
			matches = append(matches, message)
		}
	}
	return matches, nil
}

func (e *Engine) findMessagesByRawHash(ctx context.Context, folder, rawSHA256 string, sizeBytes int64) ([]imapmail.Message, error) {
	uids, _, err := e.Mail.SearchSince(folder, time.Time{}, 0)
	if err != nil {
		return nil, err
	}
	var matches []imapmail.Message
	for _, uid := range uids {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		metadata, err := e.Mail.Fetch(folder, uid, false)
		if err != nil {
			return nil, err
		}
		if sizeBytes > 0 && metadata.Size != sizeBytes {
			continue
		}
		message, err := e.Mail.Fetch(folder, uid, true)
		if err != nil {
			return nil, err
		}
		if len(message.Raw) > 0 && archive.SHA256(message.Raw) == rawSHA256 {
			matches = append(matches, message)
			if len(matches) > 1 {
				return matches, nil
			}
		}
	}
	return matches, nil
}

func messageMatchesRecord(message imapmail.Message, record store.Message) bool {
	return len(message.Raw) > 0 &&
		archive.SHA256(message.Raw) == record.RawSHA256 &&
		hashText(message.MessageID) == record.MessageIDHash
}

func (e *Engine) processFolder(ctx context.Context, run *store.Run, folder, source string, dryRun bool) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	since := e.Now().AddDate(0, 0, -e.Config.Safety.ScanLookbackDays)
	uids, uidValidity, err := e.Mail.SearchSince(folder, since, 0)
	if err != nil {
		return err
	}
	active := e.Config.Safety.Mode == "active"
	// DNS results and the learned model can change after the first scan.
	// Revisit retained mail daily, or immediately after a confirmed learn.
	rescanBefore := e.Now().UTC().Add(-24 * time.Hour)
	if run.LearnedSpam > 0 || run.LearnedHam > 0 {
		rescanBefore = e.Now().UTC()
	}
	handled := 0
	for _, uid := range uids {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if !dryRun {
			pending, err := e.Store.LocationPending(ctx, e.Config.Account.Email, folder, uidValidity, uid)
			if err != nil {
				return err
			}
			if pending {
				continue
			}
			processed, err := e.Store.LocationProcessedSince(ctx, e.Config.Account.Email, folder, uidValidity, uid, active, rescanBefore)
			if err != nil {
				return err
			}
			if processed {
				continue
			}
		}
		if handled >= e.Config.Safety.MaxMessagesPerFolder {
			break
		}
		handled++
		run.Scanned++
		msg, err := e.Mail.Fetch(folder, uid, false)
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		if err != nil {
			run.Errors++
			e.Report("error", fmt.Sprintf("%s: nie udało się odczytać UID %d", folder, uid))
			continue
		}
		if msg.Size > absoluteArchiveLimit {
			run.Errors++
			e.recordMetadataError(ctx, msg, source, "wiadomość przekracza bezwzględny limit kopii 100 MiB")
			e.Report("warning", fmt.Sprintf("%s UID %d: ponad 100 MiB — pozostawiam bez zmian", folder, uid))
			continue
		}
		msg, err = e.Mail.Fetch(folder, uid, true)
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		if err != nil {
			run.Errors++
			e.Report("error", fmt.Sprintf("%s UID %d: nie udało się pobrać bezpiecznej kopii", folder, uid))
			continue
		}
		if len(msg.Raw) > absoluteArchiveLimit {
			run.Errors++
			e.recordMetadataError(ctx, msg, source, "pełna wiadomość przekracza bezwzględny limit kopii 100 MiB")
			e.Report("warning", fmt.Sprintf("%s UID %d: pełna wiadomość ma ponad 100 MiB — pozostawiam bez zmian", folder, uid))
			continue
		}
		if int64(len(msg.Raw)) > e.Config.Safety.MaxMessageMiB<<20 {
			if source == sourceSpam {
				if err := e.archiveAndMove(ctx, run, msg, source, rspamd.Decision{Verdict: "uncertain"}, e.Config.Folders.Review, "review", dryRun, false, "wiadomość ponad limit skanowania"); err != nil {
					run.Errors++
					e.Report("error", fmt.Sprintf("%s UID %d: %v", folder, uid, err))
				} else {
					run.Review++
				}
			} else {
				run.Kept++
				e.recordKept(ctx, msg, source, rspamd.Decision{Verdict: "uncertain"}, "kept", "wiadomość ponad limit skanowania", dryRun)
			}
			continue
		}
		if mimeErr := validateRFC822MIME(msg.Raw); mimeErr != nil {
			decision := rspamd.Decision{Verdict: "uncertain"}
			detail := "nieprawidłowa struktura RFC822/MIME"
			if source == sourceSpam {
				if err := e.archiveAndMove(ctx, run, msg, source, decision, e.Config.Folders.Review, "review", dryRun, false, detail); err != nil {
					run.Errors++
					e.Report("error", fmt.Sprintf("%s UID %d: %v", folder, uid, err))
				} else {
					run.Review++
				}
			} else {
				run.Kept++
				status := "kept"
				if !active || dryRun {
					status = "observed"
				}
				e.recordKept(ctx, msg, source, decision, status, detail, dryRun)
			}
			e.Report("warning", fmt.Sprintf("%s UID %d: nieprawidłowy RFC822/MIME — brak automatycznej klasyfikacji", folder, uid))
			continue
		}

		result, scanErr := e.Rspamd.Scan(ctx, msg.Raw, e.Config.Account.Email)
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		if scanErr != nil {
			decision := rspamd.Decision{Verdict: "error"}
			run.Errors++
			if source == sourceSpam {
				if err := e.archiveAndMove(ctx, run, msg, source, decision, e.Config.Folders.Review, "review", dryRun, false, scanErr.Error()); err != nil {
					run.Errors++
				} else {
					run.Review++
				}
			} else {
				e.recordKept(ctx, msg, source, decision, "error", scanErr.Error(), dryRun)
			}
			e.Report("warning", fmt.Sprintf("%s UID %d: Rspamd niedostępny — niczego nie kasuję", folder, uid))
			continue
		}
		decision := rspamd.ClassifyDelivery(result, e.Config.Rspamd.SpamScore, e.Config.Rspamd.HamScore, e.Config.Safety.RequireAuthForRescue)
		decision, err = e.applyFeedbackGuard(ctx, msg.Raw, decision)
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		if err != nil {
			run.Errors++
			decision = rspamd.Decision{Verdict: "error"}
			e.Report("warning", fmt.Sprintf("%s UID %d: nie udało się sprawdzić korekt użytkownika", folder, uid))
		}
		action, destination, markUnread := e.decide(source, decision, active)
		switch action {
		case "keep":
			run.Kept++
			status := "kept"
			if !active || dryRun {
				status = "observed"
			}
			e.recordKept(ctx, msg, source, decision, status, "", dryRun)
		case "rescue":
			if err := e.archiveAndMove(ctx, run, msg, source, decision, destination, "rescued", dryRun, markUnread, ""); err != nil {
				run.Errors++
				e.Report("error", fmt.Sprintf("%s UID %d: %v", folder, uid, err))
			} else {
				run.Rescued++
				e.Report("success", "Uratowano prawidłową wiadomość z folderu SPAM")
			}
		case "quarantine":
			if err := e.archiveAndMove(ctx, run, msg, source, decision, destination, "quarantined", dryRun, false, ""); err != nil {
				run.Errors++
				e.Report("error", fmt.Sprintf("%s UID %d: %v", folder, uid, err))
			} else {
				run.Quarantined++
			}
		case "review":
			if err := e.archiveAndMove(ctx, run, msg, source, decision, destination, "review", dryRun, false, ""); err != nil {
				run.Errors++
				e.Report("error", fmt.Sprintf("%s UID %d: %v", folder, uid, err))
			} else {
				run.Review++
			}
		}
	}
	return context.Cause(ctx)
}

func (e *Engine) decide(source string, decision rspamd.Decision, active bool) (action, destination string, markUnread bool) {
	if source == sourceInbox {
		if active && decision.Verdict == "spam" {
			return "quarantine", e.Config.Folders.Quarantine, false
		}
		return "keep", "", false
	}
	if !active {
		return "review", e.Config.Folders.Review, false
	}
	switch decision.Verdict {
	case "spam":
		return "quarantine", e.Config.Folders.Quarantine, false
	case "ham":
		return "rescue", e.Config.Folders.Inbox, true
	default:
		return "review", e.Config.Folders.Review, false
	}
}

func (e *Engine) applyFeedbackGuard(ctx context.Context, raw []byte, decision rspamd.Decision) (rspamd.Decision, error) {
	rawHash := archive.SHA256(raw)
	latest, err := e.Store.LatestFeedback(ctx, e.Config.Account.Email, rawHash)
	if err != nil {
		return decision, err
	}
	if decision.Verdict == "spam" && latest == "ham" {
		decision.Verdict = "uncertain"
		decision.Symbols = append(decision.Symbols, "USER_FEEDBACK_HAM")
	}
	if decision.Verdict == "ham" && latest == "spam" {
		decision.Verdict = "uncertain"
		decision.Symbols = append(decision.Symbols, "USER_FEEDBACK_SPAM")
	}
	return decision, nil
}

func (e *Engine) processTraining(ctx context.Context, run *store.Run, folder string, spam, dryRun bool) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	uids, uidValidity, err := e.Mail.SearchSince(folder, time.Time{}, 0)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		// During a first dry run the training folders may not exist yet.
		if dryRun {
			return nil
		}
		return err
	}
	handled := 0
	for _, uid := range uids {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if !dryRun {
			processed, err := e.Store.TrainingLocationProcessed(ctx, e.Config.Account.Email, folder, uidValidity, uid)
			if err != nil {
				return err
			}
			if processed {
				continue
			}
		}
		if handled >= e.Config.Safety.MaxMessagesPerFolder {
			break
		}
		handled++
		run.Scanned++
		msg, err := e.Mail.Fetch(folder, uid, true)
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		if err != nil {
			run.Errors++
			continue
		}
		if len(msg.Raw) == 0 || len(msg.Raw) > int(e.Config.Safety.MaxMessageMiB<<20) {
			run.Errors++
			e.recordMetadataError(ctx, msg, folder, "wiadomość ucząca jest pusta lub przekracza limit")
			continue
		}
		invalidMIME := validateRFC822MIME(msg.Raw) != nil
		verdict := "ham"
		action := "learn_ham"
		destination := e.Config.Folders.Inbox
		status := "rescued"
		if spam {
			verdict = "spam"
			action = "learn_spam"
			destination = e.Config.Folders.Quarantine
			status = "quarantined"
		}
		decision := rspamd.Decision{Verdict: verdict}
		if dryRun {
			if invalidMIME {
				e.Report("warning", "Próba: zachowam oryginał i Twoją korektę; nieprawidłowy MIME wyklucza uczenie Bayesa, ale nie przeniesienie zgodne z folderem nauki.")
			} else {
				e.Report("info", fmt.Sprintf("Próba: UID %d czeka na uczenie jako %s", uid, verdict))
			}
			continue
		}
		alreadyLearned, err := e.feedbackAlreadyLearned(ctx, msg.Raw, spam)
		if err != nil {
			run.Errors++
			e.Report("error", "Nie udało się sprawdzić, czy ta korekta była już nauczona")
			continue
		}
		if alreadyLearned {
			if err := e.archiveKnownTrainingAndMove(ctx, msg, folder, decision, destination, status, !spam); err != nil {
				run.Errors++
				e.Report("error", err.Error())
				continue
			}
			if spam {
				run.Quarantined++
			} else {
				run.Rescued++
			}
			e.Report("info", "Ta sama korekta była już zapamiętana; wiadomość przeniesiono bez ponownego uczenia")
			continue
		}
		var learningErr error
		if invalidMIME {
			learningErr = e.archiveUnlearnableAndMove(ctx, msg, folder, decision, destination, status, !spam, verdict)
		} else {
			learningErr = e.archiveLearnAndMove(ctx, msg, folder, decision, destination, status, !spam, action, spam)
		}
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		if err := learningErr; err != nil {
			if errors.Is(err, rspamd.ErrLearningSkipped) {
				if spam {
					run.Quarantined++
				} else {
					run.Rescued++
				}
				e.Report("warning", "Zapamiętano Twoją korektę i przeniesiono oryginalną wiadomość. Uczenie Bayesa pominięte; przykład nie zwiększa postępu filtra.")
				continue
			}
			run.Errors++
			e.Report("error", err.Error())
			continue
		}
		if spam {
			run.LearnedSpam++
			run.Quarantined++
		} else {
			run.LearnedHam++
			run.Rescued++
		}
		e.Report("success", "Rspamd zapamiętał korektę")
	}
	return context.Cause(ctx)
}

func (e *Engine) archiveUnlearnableAndMove(ctx context.Context, msg imapmail.Message, source string, decision rspamd.Decision, destination, finalStatus string, markUnread bool, feedback string) error {
	id, record, err := e.preparePending(ctx, msg, source, decision, finalStatus, "pending_learn", "invalid_mime: uczenie pominięte")
	if err != nil {
		return err
	}
	if err := e.Store.MarkFeedbackIntent(ctx, id, feedback); err != nil {
		return err
	}
	record.FeedbackIntent = feedback
	return e.finishUnlearnedCorrection(ctx, id, record, msg, destination, finalStatus, markUnread, "invalid_mime: zachowano oryginał i jawną korektę bez wysyłania wadliwej treści do uczenia")
}

func (e *Engine) finishUnlearnedCorrection(ctx context.Context, id int64, record store.Message, msg imapmail.Message, destination, finalStatus string, markUnread bool, detail string) error {
	if err := e.Store.UpdateLocation(ctx, id, msg.Folder, msg.UIDValidity, msg.UID, "pending_move"); err != nil {
		return err
	}
	if err := e.Store.AddEvent(ctx, id, "learn_skipped", detail); err != nil {
		return err
	}
	if err := e.Store.SupersedeOtherCopies(ctx, record.Account, record.RawSHA256, id); err != nil {
		return err
	}
	if err := e.movePending(ctx, id, msg, destination, finalStatus, markUnread); err != nil {
		return err
	}
	return rspamd.ErrLearningSkipped
}

func (e *Engine) feedbackAlreadyLearned(ctx context.Context, raw []byte, spam bool) (bool, error) {
	rawHash := archive.SHA256(raw)
	feedback := "ham"
	if spam {
		feedback = "spam"
	}
	return e.Store.HasLearnedFeedback(ctx, e.Config.Account.Email, rawHash, feedback)
}

func (e *Engine) archiveKnownTrainingAndMove(
	ctx context.Context,
	msg imapmail.Message,
	source string,
	decision rspamd.Decision,
	destination, finalStatus string,
	markUnread bool,
) error {
	id, record, err := e.preparePending(ctx, msg, source, decision, finalStatus, "pending_move", "")
	if err != nil {
		return err
	}
	if err := e.Store.MarkFeedbackIntent(ctx, id, decision.Verdict); err != nil {
		return fmt.Errorf("nie zapisano ponowionej korekty: %w", err)
	}
	if err := e.Store.SupersedeOtherCopies(ctx, record.Account, record.RawSHA256, id); err != nil {
		return fmt.Errorf("nie uzgodniono poprzedniej kopii tej samej korekty: %w", err)
	}
	return e.movePending(ctx, id, msg, destination, finalStatus, markUnread)
}

func (e *Engine) archiveAndMove(
	ctx context.Context,
	run *store.Run,
	msg imapmail.Message,
	source string,
	decision rspamd.Decision,
	destination, finalStatus string,
	dryRun, markUnread bool,
	detail string,
) error {
	if dryRun {
		e.Report("info", fmt.Sprintf("Próba: %s → %s (%s, wynik %.1f)", msg.Folder, destination, decision.Verdict, decision.Score))
		return nil
	}
	id, _, err := e.preparePending(ctx, msg, source, decision, finalStatus, "pending_move", detail)
	if err != nil {
		return err
	}
	return e.movePending(ctx, id, msg, destination, finalStatus, markUnread)
}

func (e *Engine) archiveLearnAndMove(
	ctx context.Context,
	msg imapmail.Message,
	source string,
	decision rspamd.Decision,
	destination, finalStatus string,
	markUnread bool,
	action string,
	spam bool,
) error {
	id, record, err := e.preparePending(ctx, msg, source, decision, action, "pending_learn", "")
	if err != nil {
		return err
	}
	feedback := "ham"
	if spam {
		feedback = "spam"
	}
	// The user's explicit correction must become durable before the external
	// learning request. In particular, a ham intent is already a permanent
	// veto for purge even if Rspamd is unavailable or the process crashes.
	if err := e.Store.MarkFeedbackIntent(ctx, id, feedback); err != nil {
		return fmt.Errorf("nie zapisano intencji korekty; uczenie zostało zablokowane: %w", err)
	}
	record.FeedbackIntent = feedback
	if err := e.Rspamd.Learn(ctx, msg.Raw, spam); err != nil {
		if errors.Is(err, rspamd.ErrLearningSkipped) {
			// Preserve the exact-content correction without pretending Bayes
			// learned it. The intent already guards classification and ham purge.
			return e.finishUnlearnedCorrection(ctx, id, record, msg, destination, finalStatus, markUnread, "HTTP 204: zachowano korektę użytkownika bez potwierdzenia uczenia Bayesa")
		}
		record.Status = "error"
		record.LastError = err.Error()
		_, _ = e.Store.UpsertMessage(ctx, &record)
		_ = e.Store.AddEvent(ctx, id, "learn_error", err.Error())
		return fmt.Errorf("uczenie nie powiodło się; wiadomość została w folderze uczącym: %w", err)
	}
	if err := e.Store.MarkLearned(ctx, id, feedback); err != nil {
		return fmt.Errorf("Rspamd przyjął korektę, ale nie zapisano jej stanu: %w", err)
	}
	if err := e.Store.SupersedeOtherCopies(ctx, record.Account, record.RawSHA256, id); err != nil {
		return fmt.Errorf("Rspamd przyjął korektę, ale nie uzgodniono poprzedniej lokalizacji: %w", err)
	}
	return e.movePending(ctx, id, msg, destination, finalStatus, markUnread)
}

func (e *Engine) preparePending(
	ctx context.Context,
	msg imapmail.Message,
	source string,
	decision rspamd.Decision,
	action, status, detail string,
) (int64, store.Message, error) {
	rawHash := archive.SHA256(msg.Raw)
	now := e.Now().UTC()
	archivePath, err := e.Archive.Save(msg.Raw, rawHash, now)
	if err != nil {
		return 0, store.Message{}, fmt.Errorf("nie zapisano zaszyfrowanej kopii; działanie zablokowane: %w", err)
	}
	archiveUntil := now.AddDate(0, 0, e.Config.Safety.ArchiveDays)
	record := &store.Message{
		Account: e.Config.Account.Email, SourceFolder: source, CurrentFolder: msg.Folder,
		UIDValidity: msg.UIDValidity, UID: msg.UID, MessageIDHash: hashText(msg.MessageID),
		RawSHA256: rawHash, SizeBytes: int64(len(msg.Raw)), Verdict: decision.Verdict,
		Score: decision.Score, Symbols: decision.Symbols, Action: action,
		Status: status, FirstSeen: now, LastScanned: now,
		ArchivePath: archivePath, ArchiveUntil: &archiveUntil, LastError: detail,
	}
	id, err := e.Store.UpsertMessage(ctx, record)
	if err != nil {
		return 0, store.Message{}, fmt.Errorf("nie zapisano stanu; działanie zablokowane: %w", err)
	}
	record.ID = id
	return id, *record, nil
}

func (e *Engine) movePending(
	ctx context.Context,
	id int64,
	msg imapmail.Message,
	destination, finalStatus string,
	markUnread bool,
) error {
	var move imapmail.MoveResult
	var err error
	if verified, ok := e.Mail.(interface {
		MoveWithRaw(string, uint32, uint32, string, bool, string) (imapmail.MoveResult, error)
	}); ok {
		move, err = verified.MoveWithRaw(msg.Folder, msg.UIDValidity, msg.UID, destination, markUnread, archive.SHA256(msg.Raw))
	} else {
		move, err = e.Mail.Move(msg.Folder, msg.UIDValidity, msg.UID, destination, markUnread)
	}
	if err != nil {
		if move.UID > 0 && move.UIDValidity > 0 {
			if stateErr := e.Store.FinalizeMove(
				ctx,
				id,
				destination,
				move.UIDValidity,
				move.UID,
				finalStatus,
				e.Now().UTC(),
				e.Config.Safety.QuarantineDays,
				e.Config.Safety.ArchiveDays,
			); stateErr != nil {
				return fmt.Errorf("wiadomość przeniesiona, ale stan wymaga naprawy: %w", stateErr)
			}
			_ = e.Store.AddEvent(ctx, id, "move_warning", "przeniesiono, lecz nie ustawiono wszystkich flag")
			return nil
		}
		_ = e.Store.MarkMoveUncertain(ctx, id, err.Error())
		_ = e.Store.AddEvent(ctx, id, "move_uncertain", err.Error())
		return err
	}
	if move.UID == 0 || move.UIDValidity == 0 {
		_ = e.Store.MarkMoveUncertain(ctx, id, "serwer potwierdził ruch bez jednoznacznego docelowego UID")
		_ = e.Store.AddEvent(ctx, id, "move_uncertain", "brak docelowego UID lub UIDVALIDITY")
		return errors.New("wiadomość została przeniesiona, ale serwer nie podał docelowego UID; stan zostanie bezpiecznie uzgodniony przy następnym przebiegu")
	}
	if err := e.Store.FinalizeMove(
		ctx,
		id,
		destination,
		move.UIDValidity,
		move.UID,
		finalStatus,
		e.Now().UTC(),
		e.Config.Safety.QuarantineDays,
		e.Config.Safety.ArchiveDays,
	); err != nil {
		_ = e.Store.AddEvent(ctx, id, "state_error", err.Error())
		return fmt.Errorf("wiadomość przeniesiona, lecz aktualizacja stanu wymaga naprawy: %w", err)
	}
	return e.Store.AddEvent(ctx, id, finalStatus, "")
}

func (e *Engine) recordKept(ctx context.Context, msg imapmail.Message, source string, decision rspamd.Decision, status, detail string, dryRun bool) {
	if dryRun || len(msg.Raw) == 0 {
		return
	}
	now := e.Now().UTC()
	_, _ = e.Store.UpsertMessage(ctx, &store.Message{
		Account: e.Config.Account.Email, SourceFolder: source, CurrentFolder: msg.Folder,
		UIDValidity: msg.UIDValidity, UID: msg.UID, MessageIDHash: hashText(msg.MessageID),
		RawSHA256: archive.SHA256(msg.Raw), SizeBytes: int64(len(msg.Raw)),
		Verdict: decision.Verdict, Score: decision.Score, Symbols: decision.Symbols,
		Action: "keep", Status: status, FirstSeen: now, LastScanned: now, LastError: detail,
	})
}

func (e *Engine) recordMetadataError(ctx context.Context, msg imapmail.Message, source, detail string) {
	now := e.Now().UTC()
	fallback := fmt.Sprintf("%s:%d:%d", msg.Folder, msg.UIDValidity, msg.UID)
	_, _ = e.Store.UpsertMessage(ctx, &store.Message{
		Account: e.Config.Account.Email, SourceFolder: source, CurrentFolder: msg.Folder,
		UIDValidity: msg.UIDValidity, UID: msg.UID, MessageIDHash: hashText(msg.MessageID),
		RawSHA256: hashText(fallback), SizeBytes: msg.Size, Verdict: "error",
		Action: "keep", Status: "blocked", FirstSeen: now, LastScanned: now, LastError: detail,
	})
}

func (e *Engine) Purge(ctx context.Context, dryRun bool) (run *store.Run, retErr error) {
	e.setDefaults()
	if err := e.prepareStore(ctx); err != nil {
		return nil, err
	}
	run, err := e.Store.BeginRun(ctx, "purge", dryRun)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = e.Store.FinishRun(context.Background(), run, retErr)
	}()
	if !dryRun {
		if err := e.Store.RequireOperationalAuthorization(ctx); err != nil {
			return run, err
		}
	}
	if !dryRun && !e.Config.Safety.PurgeEnabled {
		return run, errors.New("trwałe usuwanie jest wyłączone; włącz je świadomie w menu po okresie próbnym")
	}
	if e.Config.Safety.Mode != "active" {
		return run, errors.New("trwałe usuwanie wymaga trybu aktywnego")
	}
	if err := e.requirePurgeQuality(ctx); err != nil {
		return run, err
	}
	if !e.Mail.SafeDeleteSupported() {
		return run, errors.New("serwer nie obsługuje UIDPLUS; trwałe usuwanie pozostaje zablokowane")
	}
	// A correction can be copied to the learning folder while its original is
	// still present in quarantine. Block all deletion until the normal run has
	// durably recorded and learned every explicit "important" correction.
	pendingHam, _, err := e.Mail.SearchSince(e.Config.Folders.TrainHam, time.Time{}, 1)
	if err != nil {
		return run, fmt.Errorf("sprawdzenie folderu korekt ważnych przed purge: %w", err)
	}
	if len(pendingHam) != 0 {
		return run, errors.New("trwałe usuwanie jest zablokowane, ponieważ AI-Naucz-wazne zawiera nierozliczoną korektę")
	}
	candidates, err := e.Store.PurgeCandidates(ctx, e.Config.Account.Email, e.Now())
	if err != nil {
		return run, err
	}
	for _, candidate := range candidates {
		run.Scanned++
		hasHamFeedback, err := e.Store.HasHamFeedback(ctx, candidate.Account, candidate.RawSHA256)
		if err != nil {
			return run, fmt.Errorf("sprawdzenie korekt użytkownika: %w", err)
		}
		if hasHamFeedback {
			run.Errors++
			_ = e.Store.AddEvent(ctx, candidate.ID, "purge_blocked", "wiadomość ma jawną korektę ważne")
			continue
		}
		if candidate.ArchivePath == "" {
			run.Errors++
			continue
		}
		if err := e.Archive.Verify(candidate.ArchivePath, candidate.RawSHA256); err != nil {
			run.Errors++
			continue
		}
		if candidate.CurrentFolder != e.Config.Folders.Quarantine {
			run.Errors++
			continue
		}
		if candidate.QuarantinedAt == nil ||
			e.Now().UTC().Before(candidate.QuarantinedAt.AddDate(0, 0, e.Config.Safety.QuarantineDays)) {
			run.Errors++
			_ = e.Store.AddEvent(ctx, candidate.ID, "purge_blocked", "nie upłynął pełny okres od potwierdzonej kwarantanny")
			continue
		}
		if candidate.UID == 0 || candidate.UIDValidity == 0 {
			run.Errors++
			_ = e.Store.AddEvent(ctx, candidate.ID, "purge_blocked", "brak jednoznacznego UID i UIDVALIDITY")
			continue
		}
		msg, err := e.Mail.Fetch(e.Config.Folders.Quarantine, candidate.UID, true)
		if err == nil && (msg.UIDValidity != candidate.UIDValidity ||
			archive.SHA256(msg.Raw) != candidate.RawSHA256 ||
			hashText(msg.MessageID) != candidate.MessageIDHash) {
			err = errors.New("UID, UIDVALIDITY, Message-ID lub SHA-256 nie pasuje")
		}
		if err != nil {
			run.Errors++
			_ = e.Store.AddEvent(ctx, candidate.ID, "purge_blocked", "niezgodność tożsamości wiadomości")
			continue
		}
		if importantFlags(msg.Flags) {
			run.Errors++
			_ = e.Store.AddEvent(ctx, candidate.ID, "purge_blocked", "wiadomość jest oznaczona jako ważna")
			continue
		}
		result, err := e.Rspamd.Scan(ctx, msg.Raw, e.Config.Account.Email)
		if err != nil {
			run.Errors++
			continue
		}
		decision := rspamd.ClassifyPermanent(result, e.Config.Rspamd.SpamScore, e.Config.Rspamd.HamScore, e.Config.Safety.RequireAuthForRescue)
		if decision.Verdict != "spam" {
			run.Errors++
			_ = e.Store.AddEvent(ctx, candidate.ID, "purge_blocked", "ponowny skan nie potwierdził spamu")
			continue
		}
		if dryRun {
			run.Purged++
			continue
		}
		// Scanning can take tens of seconds. Re-read the exact UID immediately
		// before deletion so a flag added by the user in the meantime blocks
		// the irreversible operation.
		latest, err := e.Mail.Fetch(e.Config.Folders.Quarantine, msg.UID, true)
		if err != nil ||
			latest.UIDValidity != candidate.UIDValidity ||
			archive.SHA256(latest.Raw) != candidate.RawSHA256 ||
			hashText(latest.MessageID) != candidate.MessageIDHash ||
			importantFlags(latest.Flags) {
			run.Errors++
			_ = e.Store.AddEvent(ctx, candidate.ID, "purge_blocked", "tożsamość lub flagi zmieniły się podczas ponownego skanowania")
			continue
		}
		if err := e.Mail.DeleteUID(e.Config.Folders.Quarantine, latest.UIDValidity, latest.UID); err != nil {
			run.Errors++
			_ = e.Store.AddEvent(ctx, candidate.ID, "purge_delete_uncertain", "serwer nie potwierdził bezpiecznego UID EXPUNGE")
			continue
		}
		if err := e.Store.MarkPurged(ctx, candidate.ID); err != nil {
			run.Errors++
			continue
		}
		_ = e.Store.AddEvent(ctx, candidate.ID, "purged", "")
		run.Purged++
	}
	return run, nil
}

func (e *Engine) requirePurgeQuality(ctx context.Context) error {
	if err := e.requireActivationQuality(ctx); err != nil {
		return err
	}
	now := e.Now().UTC()
	activeRaw, err := e.Store.GetSetting(ctx, "active_since")
	if err != nil {
		return err
	}
	activeAt, err := parseSettingTime(activeRaw)
	if err != nil || now.Before(activeAt.Add(30*24*time.Hour)) {
		return errors.New("trwałe usuwanie wymaga co najmniej 30 pełnych dni trybu aktywnego")
	}
	trainedSpam, trainedHam, err := e.Store.TrainingTotals(ctx, e.Config.Account.Email)
	if err != nil {
		return fmt.Errorf("sprawdzenie liczby korekt: %w", err)
	}
	if trainedSpam < e.Config.Safety.MinLearnSpam || trainedHam < e.Config.Safety.MinLearnHam {
		return fmt.Errorf(
			"za mało unikalnych przykładów do trwałego usuwania (spam %d/%d, ważne %d/%d)",
			trainedSpam,
			e.Config.Safety.MinLearnSpam,
			trainedHam,
			e.Config.Safety.MinLearnHam,
		)
	}
	falseSpam, falseHam, err := e.Store.MisclassificationsSince(ctx, e.Config.Account.Email, now.Add(-30*24*time.Hour))
	if err != nil {
		return fmt.Errorf("sprawdzenie ostatnich pomyłek: %w", err)
	}
	if falseSpam != 0 || falseHam != 0 {
		return fmt.Errorf("w ostatnich 30 dniach były sprzeczne korekty (ważne: %d, spam: %d)", falseSpam, falseHam)
	}
	return nil
}

func importantFlags(flags []string) bool {
	for _, flag := range flags {
		switch strings.ToLower(strings.TrimSpace(flag)) {
		case `\flagged`, "$important", "important":
			return true
		}
	}
	return false
}

func (e *Engine) Restore(ctx context.Context, id int64) error {
	e.setDefaults()
	if err := e.prepareStore(ctx); err != nil {
		return err
	}
	if err := e.Store.RequireOperationalAuthorization(ctx); err != nil {
		return err
	}
	record, err := e.Store.MessageByID(ctx, id)
	if err != nil {
		return err
	}
	if record.Account != e.Config.Account.Email {
		return errors.New("ta kopia należy do innego konta i nie zostanie przywrócona")
	}
	if record.Status == "restored" {
		if record.CurrentFolder != e.Config.Folders.Review || record.UID == 0 || record.UIDValidity == 0 {
			return errors.New("poprzedniego przywrócenia nie można jednoznacznie potwierdzić; nie tworzę duplikatu")
		}
		existing, err := e.Mail.Fetch(record.CurrentFolder, record.UID, true)
		if err != nil {
			return fmt.Errorf("nie można potwierdzić poprzednio przywróconej kopii; nie tworzę duplikatu: %w", err)
		}
		if existing.UIDValidity != record.UIDValidity || archive.SHA256(existing.Raw) != record.RawSHA256 {
			return errors.New("poprzednio przywrócona lokalizacja nie pasuje; nie tworzę duplikatu")
		}
		return fmt.Errorf("%w: %s", ErrRestoreAlreadyPresent, record.CurrentFolder)
	}
	if record.Status != "pending_restore" &&
		record.CurrentFolder != "" &&
		record.UID != 0 &&
		record.UIDValidity != 0 {
		existing, err := e.Mail.Fetch(record.CurrentFolder, record.UID, true)
		if err != nil {
			return fmt.Errorf("nie można jednoznacznie potwierdzić zapisanej lokalizacji; nie tworzę kopii przez APPEND: %w", err)
		}
		if existing.UIDValidity != record.UIDValidity ||
			archive.SHA256(existing.Raw) != record.RawSHA256 ||
			hashText(existing.MessageID) != record.MessageIDHash {
			return errors.New("zapisana lokalizacja wskazuje inną wiadomość; przywracanie zablokowane")
		}
		_ = e.Store.AddEvent(ctx, id, "restore_skipped_existing", "wiadomość nadal istnieje w zapisanym folderze")
		return fmt.Errorf("%w: %s", ErrRestoreAlreadyPresent, record.CurrentFolder)
	}

	if record.Status == "pending_restore" {
		matches, err := e.findMessagesByRawHash(
			ctx,
			e.Config.Folders.Review,
			record.RawSHA256,
			record.SizeBytes,
		)
		if err != nil {
			return fmt.Errorf("uzgadnianie poprzedniej próby przywrócenia: %w", err)
		}
		switch len(matches) {
		case 1:
			match := matches[0]
			if err := e.Store.FinalizeRestore(
				ctx,
				id,
				e.Config.Account.Email,
				e.Config.Folders.Review,
				match.UIDValidity,
				match.UID,
			); err != nil {
				return err
			}
			return e.Store.AddEvent(ctx, id, "restore_reconciled", "potwierdzono istniejącą kopię bez tworzenia duplikatu")
		case 0:
			// APPEND either never happened or left no copy. The encrypted archive
			// below is still required before retrying.
		default:
			return errors.New("w folderze ręcznej weryfikacji istnieje wiele zgodnych kopii; nie tworzę kolejnej")
		}
	}

	if record.ArchivePath == "" {
		return errors.New("ta pozycja nie ma lokalnej kopii")
	}
	raw, err := e.Archive.Read(record.ArchivePath)
	if err != nil {
		return err
	}
	if archive.SHA256(raw) != record.RawSHA256 {
		return errors.New("suma kontrolna kopii nie pasuje; przywracanie zablokowane")
	}
	if record.Status != "pending_restore" {
		if err := e.Store.MarkRestorePending(ctx, id, e.Config.Account.Email); err != nil {
			return fmt.Errorf("nie zapisano zamiaru przywrócenia; APPEND zablokowany: %w", err)
		}
	}
	appended, err := e.Mail.AppendUnread(e.Config.Folders.Review, raw, record.FirstSeen)
	if err != nil {
		return fmt.Errorf("przywracanie nie zostało jednoznacznie potwierdzone; przed ponowieniem zostanie uzgodniony folder docelowy: %w", err)
	}
	if appended.UID == 0 || appended.UIDValidity == 0 {
		return errors.New("serwer przyjął APPEND bez jednoznacznego UID; stan zostanie uzgodniony przed ponowieniem")
	}
	if err := e.Store.FinalizeRestore(
		ctx,
		id,
		e.Config.Account.Email,
		e.Config.Folders.Review,
		appended.UIDValidity,
		appended.UID,
	); err != nil {
		return err
	}
	return e.Store.AddEvent(ctx, id, "restored", "do folderu ręcznej weryfikacji")
}

func (e *Engine) CheckArchiveFiles(ctx context.Context) error {
	// A full archive may be very large. Verifying the newest 25 copies catches
	// storage/key problems without making the friendly diagnostic run for hours.
	items, err := e.Store.Archived(ctx, e.Config.Account.Email, 25)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.ArchivePath == "" {
			continue
		}
		if err := e.Archive.Verify(item.ArchivePath, item.RawSHA256); err != nil {
			return fmt.Errorf("nieprawidłowa kopia dla ID %d: %w", item.ID, err)
		}
	}
	return nil
}

func (e *Engine) CleanupExpiredArchives(ctx context.Context) (int, error) {
	e.setDefaults()
	if err := e.prepareStore(ctx); err != nil {
		return 0, err
	}
	items, err := e.Store.ArchiveCleanupCandidates(ctx, e.Config.Account.Email, e.Now())
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, item := range items {
		if err := e.Archive.Delete(item.ArchivePath, item.RawSHA256); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			return deleted, err
		}
		if err := e.Store.ClearArchivePath(ctx, item.ArchivePath); err != nil {
			return deleted, err
		}
		_ = e.Store.AddEvent(ctx, item.ID, "archive_expired", "")
		deleted++
	}
	return deleted, nil
}

func hashText(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(strings.ToLower(value))))
	return hex.EncodeToString(sum[:])
}
