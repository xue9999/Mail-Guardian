package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/xue9999/Mail-Guardian/internal/archive"
	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/imapmail"
	"github.com/xue9999/Mail-Guardian/internal/rspamd"
	"github.com/xue9999/Mail-Guardian/internal/store"
)

func TestPendingMoveCrashBeforeMoveRetriesAndRefreshesRetention(t *testing.T) {
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	e, mail, db, _ := newTestEngine(t, now, false)
	message := mailMessage("spam-delayed", now.Add(-100*24*time.Hour))
	uid := mail.add("INBOX", message)
	stored := mail.folders["INBOX"][uid]
	attempted := now.Add(-10 * 24 * time.Hour)
	oldArchiveUntil := attempted.Add(35 * 24 * time.Hour)
	record := &store.Message{
		Account: e.Config.Account.Email, SourceFolder: sourceInbox, CurrentFolder: "INBOX",
		UIDValidity: stored.UIDValidity, UID: stored.UID, MessageIDHash: hashText(stored.MessageID),
		RawSHA256: archive.SHA256(stored.Raw), SizeBytes: int64(len(stored.Raw)),
		Verdict: "spam", Action: "quarantined", Status: "pending_move",
		FirstSeen: attempted, LastScanned: attempted, ArchiveUntil: &oldArchiveUntil,
	}
	id, err := db.UpsertMessage(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := e.Run(context.Background(), RunOptions{}); err != nil {
		t.Fatal(err)
	}
	if mail.count("INBOX") != 0 || mail.count(e.Config.Folders.Quarantine) != 1 {
		t.Fatal("pending source was not moved exactly once")
	}
	got, err := db.MessageByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "quarantined" || got.QuarantinedAt == nil || !got.QuarantinedAt.Equal(now) {
		t.Fatalf("unexpected finalized record: %#v", got)
	}
	if got.DeleteAfter == nil || !got.DeleteAfter.Equal(now.AddDate(0, 0, e.Config.Safety.QuarantineDays)) {
		t.Fatalf("retention was shortened: %v", got.DeleteAfter)
	}
	if got.ArchiveUntil == nil || !got.ArchiveUntil.Equal(now.AddDate(0, 0, e.Config.Safety.ArchiveDays)) {
		t.Fatalf("archive retention was not refreshed: %v", got.ArchiveUntil)
	}
}

func TestUIDValidityChangeImmediatelyBeforeEveryUIDMutationBlocksOperation(t *testing.T) {
	now := time.Now().UTC()
	t.Run("MOVE", func(t *testing.T) {
		mail := newFakeMail(now)
		uid := mail.add("INBOX", mailMessage("move-target", now))
		other := mail.add("INBOX", mailMessage("move-other", now))
		expected := mail.uidValidity["INBOX"]
		mail.beforeMove = func(folder string) { mail.uidValidity[folder]++; mail.beforeMove = nil }
		if _, err := mail.Move("INBOX", expected, uid, "Spam", false); !errors.Is(err, imapmail.ErrUIDValidityChanged) {
			t.Fatalf("MOVE was not blocked: %v", err)
		}
		if mail.count("INBOX") != 2 || mail.count("Spam") != 0 || mail.folders["INBOX"][other].MessageID == "" {
			t.Fatal("MOVE changed a message after UIDVALIDITY mismatch")
		}
	})
	t.Run("flags", func(t *testing.T) {
		mail := newFakeMail(now)
		message := mailMessage("flag-target", now)
		message.Flags = []string{`\Seen`}
		uid := mail.add("INBOX", message)
		expected := mail.uidValidity["INBOX"]
		mail.beforeMarkUnread = func(folder string) { mail.uidValidity[folder]++; mail.beforeMarkUnread = nil }
		if err := mail.MarkUnread("INBOX", expected, uid); !errors.Is(err, imapmail.ErrUIDValidityChanged) {
			t.Fatalf("flag mutation was not blocked: %v", err)
		}
		if !containsFlag(mail.folders["INBOX"][uid].Flags, `\Seen`) {
			t.Fatal("flags changed after UIDVALIDITY mismatch")
		}
	})
	t.Run("UID EXPUNGE", func(t *testing.T) {
		mail := newFakeMail(now)
		uid := mail.add("AI-Kwarantanna", mailMessage("delete-target", now))
		other := mail.add("AI-Kwarantanna", mailMessage("delete-other", now))
		expected := mail.uidValidity["AI-Kwarantanna"]
		mail.beforeDelete = func(folder string) { mail.uidValidity[folder]++; mail.beforeDelete = nil }
		if err := mail.DeleteUID("AI-Kwarantanna", expected, uid); !errors.Is(err, imapmail.ErrUIDValidityChanged) {
			t.Fatalf("UID EXPUNGE was not blocked: %v", err)
		}
		if mail.count("AI-Kwarantanna") != 2 || mail.folders["AI-Kwarantanna"][other].MessageID == "" {
			t.Fatal("UID EXPUNGE changed a message after UIDVALIDITY mismatch")
		}
	})
}

func containsFlag(flags []string, wanted string) bool {
	for _, flag := range flags {
		if flag == wanted {
			return true
		}
	}
	return false
}

func TestPendingMoveCrashAfterMoveReconcilesExactDestination(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, _ := newTestEngine(t, now, false)
	uid := mail.add("INBOX", mailMessage("spam-after", now))
	stored := mail.folders["INBOX"][uid]
	id := insertPending(t, db, e.Config.Account.Email, stored, "quarantined", now)
	if _, err := mail.Move("INBOX", mail.uidValidity["INBOX"], uid, e.Config.Folders.Quarantine, false); err != nil {
		t.Fatal(err)
	}

	run, err := e.Run(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Scanned != 0 {
		t.Fatalf("reconciled move was unexpectedly rescanned: %#v", run)
	}
	got, err := db.MessageByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "quarantined" || got.CurrentFolder != e.Config.Folders.Quarantine || got.UID == 0 {
		t.Fatalf("move not reconciled: %#v", got)
	}
}

func TestPendingMoveRebindsUniqueSourceAfterUIDValidityChange(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, _ := newTestEngine(t, now, false)
	uid := mail.add("INBOX", mailMessage("spam-uidvalidity", now))
	stored := mail.folders["INBOX"][uid]
	id := insertPending(t, db, e.Config.Account.Email, stored, "quarantined", now)

	delete(mail.folders["INBOX"], uid)
	mail.uidValidity["INBOX"]++
	mail.add("INBOX", stored)

	if _, err := e.Run(context.Background(), RunOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := db.MessageByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "quarantined" || got.CurrentFolder != e.Config.Folders.Quarantine ||
		mail.count("INBOX") != 0 || mail.count(e.Config.Folders.Quarantine) != 1 {
		t.Fatalf("unique source was not safely rebound and moved: %#v", got)
	}
}

func TestPendingMoveWithSourceAndDestinationIsMarkedAmbiguous(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, _ := newTestEngine(t, now, false)
	uid := mail.add("INBOX", mailMessage("spam-copy", now))
	source := mail.folders["INBOX"][uid]
	id := insertPending(t, db, e.Config.Account.Email, source, "quarantined", now)
	mail.add(e.Config.Folders.Quarantine, source)

	if _, err := e.Run(context.Background(), RunOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := db.MessageByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "move_ambiguous" || mail.count("INBOX") != 1 || mail.count(e.Config.Folders.Quarantine) != 1 {
		t.Fatalf("ambiguous partial copy was modified: %#v", got)
	}
	delete(mail.folders["INBOX"], uid)
	if _, err := e.Run(context.Background(), RunOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err = db.MessageByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "quarantined" || got.CurrentFolder != e.Config.Folders.Quarantine {
		t.Fatalf("resolved ambiguous move was not reconciled: %#v", got)
	}
}

func TestPagedReconciliationResumesResetsOnUIDValidityAndDoesNotBlockNewMail(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, _ := newTestEngine(t, now, true)
	e.Config.Safety.MaxMessagesPerFolder = 10
	old := now.Add(-100 * 24 * time.Hour)
	for i := 0; i < 600; i++ {
		mail.add("INBOX", mailMessage(fmt.Sprintf("old-decoy-%03d", i), old))
	}
	targetUID := mail.add("INBOX", mailMessage("spam-paged-target", old))
	target := mail.folders["INBOX"][targetUID]
	id := insertPending(t, db, e.Config.Account.Email, target, "quarantined", now)

	if _, err := e.Run(context.Background(), RunOptions{}); err != nil {
		t.Fatal(err)
	}
	progress, err := db.ReconcileProgress(context.Background(), id)
	if err != nil || progress.SourceCursor != 250 || progress.SourceComplete {
		t.Fatalf("first page was not persisted: %#v err=%v", progress, err)
	}
	if mail.rawFetches != 0 {
		t.Fatalf("full bodies were fetched for size/Message-ID mismatches: %d", mail.rawFetches)
	}

	mail.uidValidity["INBOX"]++
	for uid, message := range mail.folders["INBOX"] {
		message.UIDValidity = mail.uidValidity["INBOX"]
		mail.folders["INBOX"][uid] = message
	}
	mail.add(e.Config.Folders.ServerSpam, mailMessage("uncertain-new-mail", now))
	if _, err := e.Run(context.Background(), RunOptions{}); err != nil {
		t.Fatal(err)
	}
	progress, err = db.ReconcileProgress(context.Background(), id)
	if err != nil || progress.SourceUIDValidity != mail.uidValidity["INBOX"] || progress.SourceCursor != 250 {
		t.Fatalf("UIDVALIDITY change did not reset the durable cursor: %#v err=%v", progress, err)
	}
	if mail.count(e.Config.Folders.Review) != 1 {
		t.Fatal("unresolved reconciliation blocked processing of new mail")
	}

	for i := 0; i < 2; i++ {
		if _, err := e.Run(context.Background(), RunOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	record, err := db.MessageByID(context.Background(), id)
	if err != nil || record.Status != "quarantined" || record.CurrentFolder != e.Config.Folders.Quarantine {
		t.Fatalf("paged reconciliation did not finish: %#v err=%v", record, err)
	}
}

func TestOldestUnprocessedMessagesDoNotStarve(t *testing.T) {
	now := time.Now().UTC()
	e, mail, _, _ := newTestEngine(t, now, false)
	e.Config.Safety.MaxMessagesPerFolder = 2
	for i := 1; i <= 4; i++ {
		mail.add("INBOX", mailMessage("uncertain-"+string(rune('0'+i)), now))
	}
	first, err := e.Run(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.Run(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	third, err := e.Run(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Scanned != 2 || second.Scanned != 2 || third.Scanned != 0 {
		t.Fatalf("limits did not count oldest unprocessed messages: %d/%d/%d", first.Scanned, second.Scanned, third.Scanned)
	}
}

func TestDryRunNeverMovesLearnsOrCreatesArchiveRecords(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, scanner := newTestEngine(t, now, false)
	mail.add(e.Config.Folders.TrainSpam, mailMessage("spam-training-dry", now))
	mail.add(e.Config.Folders.ServerSpam, mailMessage("spam-server-dry", now))
	mail.add("INBOX", mailMessage("spam-inbox-dry", now))

	run, err := e.Run(context.Background(), RunOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if scanner.learnCalls != 0 || mail.count(e.Config.Folders.TrainSpam) != 1 ||
		mail.count(e.Config.Folders.ServerSpam) != 1 || mail.count("INBOX") != 1 ||
		mail.count(e.Config.Folders.Quarantine) != 0 || mail.count(e.Config.Folders.Review) != 0 {
		t.Fatalf("dry-run mutated mailbox or learned: run=%#v learns=%d", run, scanner.learnCalls)
	}
	archives, err := db.Archived(context.Background(), e.Config.Account.Email, 10)
	if err != nil || len(archives) != 0 {
		t.Fatalf("dry-run created archive state: %#v err=%v", archives, err)
	}
}

func TestTrainingLimitSkipsProcessedAndReachesOldestUnprocessed(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, scanner := newTestEngine(t, now, false)
	e.Config.Safety.MaxMessagesPerFolder = 1
	var messages []imapmail.Message
	for i := 1; i <= 3; i++ {
		uid := mail.add(e.Config.Folders.TrainSpam, mailMessage("spam-training-"+string(rune('0'+i)), now))
		messages = append(messages, mail.folders[e.Config.Folders.TrainSpam][uid])
	}
	for _, message := range messages[1:] {
		_, err := db.UpsertMessage(context.Background(), &store.Message{
			Account: e.Config.Account.Email, SourceFolder: "training", CurrentFolder: message.Folder,
			UIDValidity: message.UIDValidity, UID: message.UID, MessageIDHash: hashText(message.MessageID),
			RawSHA256: archive.SHA256(message.Raw), Verdict: "spam", Action: "learn_spam",
			Status: "quarantined", Feedback: "spam", FirstSeen: now, LastScanned: now,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	run, err := e.Run(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if run.LearnedSpam != 1 || scanner.learnCalls != 1 {
		t.Fatalf("oldest unprocessed training message starved: %#v learns=%d", run, scanner.learnCalls)
	}
	if _, ok := mail.folders[e.Config.Folders.TrainSpam][messages[0].UID]; ok {
		t.Fatal("oldest unprocessed training UID was not handled")
	}
}

func TestLearnIsNotRepeatedAfterUncertainMoveFailure(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, scanner := newTestEngine(t, now, false)
	mail.add(e.Config.Folders.TrainSpam, mailMessage("spam-learn-once", now))
	mail.moveFailures = 1

	first, err := e.Run(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Errors != 1 || scanner.learnCalls != 1 {
		t.Fatalf("unexpected first run: %#v learns=%d", first, scanner.learnCalls)
	}
	pending, err := db.PendingMessages(context.Background(), e.Config.Account.Email)
	if err != nil || len(pending) != 1 || pending[0].Action != "learn_spam" {
		t.Fatalf("learned move was not left pending: %#v err=%v", pending, err)
	}

	if _, err := e.Run(context.Background(), RunOptions{}); err != nil {
		t.Fatal(err)
	}
	if scanner.learnCalls != 1 || mail.count(e.Config.Folders.TrainSpam) != 0 ||
		mail.count(e.Config.Folders.Quarantine) != 1 {
		t.Fatalf("retry relearned or failed to move: learns=%d", scanner.learnCalls)
	}
}

func TestIdenticalTrainingFeedbackDoesNotBiasBayesTwice(t *testing.T) {
	now := time.Now().UTC()
	e, mail, _, scanner := newTestEngine(t, now, false)
	mail.add(e.Config.Folders.TrainSpam, mailMessage("spam-deduplicated", now))

	first, err := e.Run(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if first.LearnedSpam != 1 || scanner.learnCalls != 1 {
		t.Fatalf("first correction was not learned exactly once: %#v learns=%d", first, scanner.learnCalls)
	}
	quarantinedUID := mail.nextUID[e.Config.Folders.Quarantine] - 1
	if _, err := mail.Move(e.Config.Folders.Quarantine, mail.uidValidity[e.Config.Folders.Quarantine], quarantinedUID, e.Config.Folders.TrainSpam, false); err != nil {
		t.Fatal(err)
	}

	second, err := e.Run(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if second.LearnedSpam != 0 || second.Quarantined != 1 || scanner.learnCalls != 1 ||
		mail.count(e.Config.Folders.TrainSpam) != 0 || mail.count(e.Config.Folders.Quarantine) != 1 {
		t.Fatalf("duplicate correction biased Bayes or was not moved: %#v learns=%d", second, scanner.learnCalls)
	}
}

func TestMalformedMIMEIsNeverAutomaticallyClassified(t *testing.T) {
	now := time.Now().UTC()
	e, mail, _, scanner := newTestEngine(t, now, false)
	raw := []byte("From: sender@example.org\r\nContent-Type: multipart/mixed\r\n\r\nbody")
	broken := imapmail.Message{Raw: raw, Size: int64(len(raw)), MessageID: "broken@example.org", InternalDate: now}
	mail.add("INBOX", broken)
	mail.add(e.Config.Folders.ServerSpam, broken)

	run, err := e.Run(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if scanner.scanCalls != 0 || run.Kept != 1 || run.Review != 1 ||
		mail.count("INBOX") != 1 || mail.count(e.Config.Folders.Review) != 1 {
		t.Fatalf("malformed MIME got an automatic verdict or unsafe move: %#v scans=%d", run, scanner.scanCalls)
	}
}

func TestOversizedServerSpamIsCountedAndMovedToReview(t *testing.T) {
	now := time.Now().UTC()
	e, mail, _, scanner := newTestEngine(t, now, false)
	e.Config.Safety.MaxMessageMiB = 1
	raw := append(
		[]byte("From: sender@example.org\r\nMessage-ID: <large@example.org>\r\n\r\n"),
		make([]byte, (1<<20)+1)...,
	)
	mail.add(e.Config.Folders.ServerSpam, imapmail.Message{
		Raw: raw, Size: int64(len(raw)), MessageID: "large@example.org", InternalDate: now,
	})

	run, err := e.Run(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if scanner.scanCalls != 0 || run.Review != 1 || run.Errors != 0 ||
		mail.count(e.Config.Folders.ServerSpam) != 0 || mail.count(e.Config.Folders.Review) != 1 {
		t.Fatalf("oversized server spam was not safely reported: %#v scans=%d", run, scanner.scanCalls)
	}
}

func TestScannerFailureInServerSpamIsCountedAndMovedToReview(t *testing.T) {
	now := time.Now().UTC()
	e, mail, _, _ := newTestEngine(t, now, false)
	mail.add(e.Config.Folders.ServerSpam, mailMessage("error", now))

	run, err := e.Run(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Review != 1 || run.Errors != 1 ||
		mail.count(e.Config.Folders.ServerSpam) != 0 || mail.count(e.Config.Folders.Review) != 1 {
		t.Fatalf("scanner failure was not safely reported: %#v", run)
	}
}

func TestFullPayloadCannotBypassAbsoluteLimitWithFalseMetadataSize(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a 100 MiB boundary payload")
	}
	now := time.Now().UTC()
	e, mail, _, scanner := newTestEngine(t, now, false)
	raw := make([]byte, absoluteArchiveLimit+1)
	copy(raw, []byte("From: sender@example.org\r\n\r\n"))
	mail.add("INBOX", imapmail.Message{
		Raw: raw, Size: 1, MessageID: "oversized@example.org", InternalDate: now,
	})

	run, err := e.Run(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if scanner.scanCalls != 0 || run.Errors != 1 || mail.count("INBOX") != 1 ||
		mail.count(e.Config.Folders.Quarantine) != 0 {
		t.Fatalf("full-payload limit was bypassed: %#v scans=%d", run, scanner.scanCalls)
	}
}

func TestExplicitFeedbackOverridesAutomaticMovement(t *testing.T) {
	now := time.Now().UTC()
	e, _, db, _ := newTestEngine(t, now, false)
	spamRaw := mailMessage("spam-feedback", now).Raw
	hamRaw := mailMessage("ham-feedback", now).Raw
	addFeedback(t, db, e.Config.Account.Email, archive.SHA256(spamRaw), "ham", now)
	addFeedback(t, db, e.Config.Account.Email, archive.SHA256(hamRaw), "spam", now)

	spamDecision, err := e.applyFeedbackGuard(context.Background(), spamRaw, rspamd.Decision{Verdict: "spam"})
	if err != nil || spamDecision.Verdict != "uncertain" {
		t.Fatalf("ham feedback did not block quarantine: %#v err=%v", spamDecision, err)
	}
	hamDecision, err := e.applyFeedbackGuard(context.Background(), hamRaw, rspamd.Decision{Verdict: "ham"})
	if err != nil || hamDecision.Verdict != "uncertain" {
		t.Fatalf("spam feedback did not block rescue: %#v err=%v", hamDecision, err)
	}
	if action, _, _ := e.decide(sourceInbox, spamDecision, true); action != "keep" {
		t.Fatal("ham feedback did not keep the inbox message")
	}
	if action, _, _ := e.decide(sourceSpam, hamDecision, true); action != "review" {
		t.Fatal("spam feedback did not downgrade rescue to review")
	}
}

func TestRestoreIsIdempotent(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, _ := newTestEngine(t, now, false)
	message := mailMessage("restore-once", now)
	rawHash := archive.SHA256(message.Raw)
	path, err := e.Archive.Save(message.Raw, rawHash, now)
	if err != nil {
		t.Fatal(err)
	}
	record := &store.Message{
		Account: e.Config.Account.Email, SourceFolder: sourceInbox, CurrentFolder: "",
		MessageIDHash: hashText(message.MessageID), RawSHA256: rawHash,
		Verdict: "spam", Action: "quarantined", Status: "purged",
		FirstSeen: now, LastScanned: now, ArchivePath: path,
	}
	id, err := db.UpsertMessage(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Restore(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := e.Restore(context.Background(), id); !errors.Is(err, ErrRestoreAlreadyPresent) {
		t.Fatalf("repeated restore did not return the explicit outcome: %v", err)
	}
	if mail.appendCalls != 1 || mail.count(e.Config.Folders.Review) != 1 {
		t.Fatalf("restore created a duplicate: appends=%d", mail.appendCalls)
	}
}

func TestRestoreReconcilesLostAppendResponseWithoutDuplicate(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, _ := newTestEngine(t, now, false)
	message := mailMessage("restore-lost-response", now)
	rawHash := archive.SHA256(message.Raw)
	path, err := e.Archive.Save(message.Raw, rawHash, now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.UpsertMessage(context.Background(), &store.Message{
		Account: e.Config.Account.Email, SourceFolder: sourceInbox, CurrentFolder: "",
		MessageIDHash: hashText(message.MessageID), RawSHA256: rawHash,
		SizeBytes: int64(len(message.Raw)), Verdict: "spam", Action: "quarantined",
		Status: "purged", FirstSeen: now, LastScanned: now, ArchivePath: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	mail.appendFailuresAfterWrite = 1

	if err := e.Restore(context.Background(), id); err == nil {
		t.Fatal("lost APPEND response must remain unresolved")
	}
	pending, err := db.MessageByID(context.Background(), id)
	if err != nil || pending.Status != "pending_restore" ||
		mail.appendCalls != 1 || mail.count(e.Config.Folders.Review) != 1 {
		t.Fatalf("restore intent was not preserved: %#v err=%v", pending, err)
	}

	if err := e.Restore(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	restored, err := db.MessageByID(context.Background(), id)
	if err != nil || restored.Status != "restored" ||
		mail.appendCalls != 1 || mail.count(e.Config.Folders.Review) != 1 {
		t.Fatalf("retry created a duplicate or failed reconciliation: %#v err=%v", restored, err)
	}
}

func TestNormalRunFinishesPendingRestoreWithoutDuplicate(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, _ := newTestEngine(t, now, false)
	message := mailMessage("restore-finished-by-run", now)
	rawHash := archive.SHA256(message.Raw)
	path, err := e.Archive.Save(message.Raw, rawHash, now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.UpsertMessage(context.Background(), &store.Message{
		Account: e.Config.Account.Email, SourceFolder: sourceInbox, CurrentFolder: "",
		MessageIDHash: hashText(message.MessageID), RawSHA256: rawHash,
		SizeBytes: int64(len(message.Raw)), Verdict: "spam", Action: "quarantined",
		Status: "purged", FirstSeen: now, LastScanned: now, ArchivePath: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	mail.appendFailuresAfterWrite = 1
	if err := e.Restore(context.Background(), id); err == nil {
		t.Fatal("lost APPEND response must remain unresolved initially")
	}

	if _, err := e.Run(context.Background(), RunOptions{}); err != nil {
		t.Fatalf("normal run did not reconcile the restore: %v", err)
	}
	restored, err := db.MessageByID(context.Background(), id)
	if err != nil || restored.Status != "restored" {
		t.Fatalf("pending restore remained unresolved: %#v err=%v", restored, err)
	}
	if mail.appendCalls != 1 || mail.count(e.Config.Folders.Review) != 1 {
		t.Fatalf("normal run created a restore duplicate: appends=%d copies=%d", mail.appendCalls, mail.count(e.Config.Folders.Review))
	}
}

func TestRestoreBlocksWhenMultipleDestinationCopiesMatch(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, _ := newTestEngine(t, now, false)
	message := mailMessage("restore-ambiguous", now)
	rawHash := archive.SHA256(message.Raw)
	path, err := e.Archive.Save(message.Raw, rawHash, now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.UpsertMessage(context.Background(), &store.Message{
		Account: e.Config.Account.Email, SourceFolder: sourceInbox, CurrentFolder: "",
		MessageIDHash: hashText(message.MessageID), RawSHA256: rawHash,
		SizeBytes: int64(len(message.Raw)), Verdict: "spam", Action: "quarantined",
		Status: "purged", FirstSeen: now, LastScanned: now, ArchivePath: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.MarkRestorePending(context.Background(), id, e.Config.Account.Email); err != nil {
		t.Fatal(err)
	}
	mail.add(e.Config.Folders.Review, message)
	mail.add(e.Config.Folders.Review, message)

	err = e.Restore(context.Background(), id)
	if err == nil || !strings.Contains(err.Error(), "multiple matching copies") {
		t.Fatalf("ambiguous restore was not blocked: %v", err)
	}
	if mail.appendCalls != 0 || mail.count(e.Config.Folders.Review) != 2 {
		t.Fatal("ambiguous restore created another copy")
	}
}

func TestRestoreDoesNotAppendWhenRecordedCopyStillExists(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, _ := newTestEngine(t, now, false)
	message := mailMessage("restore-existing", now)
	uid := mail.add(e.Config.Folders.Quarantine, message)
	stored := mail.folders[e.Config.Folders.Quarantine][uid]
	rawHash := archive.SHA256(stored.Raw)
	path, err := e.Archive.Save(stored.Raw, rawHash, now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.UpsertMessage(context.Background(), &store.Message{
		Account: e.Config.Account.Email, SourceFolder: sourceInbox,
		CurrentFolder: e.Config.Folders.Quarantine,
		UIDValidity:   stored.UIDValidity, UID: stored.UID,
		MessageIDHash: hashText(stored.MessageID), RawSHA256: rawHash,
		SizeBytes: int64(len(stored.Raw)), Verdict: "spam", Action: "quarantined",
		Status: "quarantined", FirstSeen: now, LastScanned: now, ArchivePath: path,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := e.Restore(context.Background(), id); !errors.Is(err, ErrRestoreAlreadyPresent) {
		t.Fatalf("existing message did not return the explicit outcome: %v", err)
	}
	if mail.appendCalls != 0 || mail.count(e.Config.Folders.Review) != 0 ||
		mail.count(e.Config.Folders.Quarantine) != 1 {
		t.Fatal("restore duplicated a message that still existed")
	}
}

func TestRestoreFailsClosedWhenRecordedLocationCannotBeVerified(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, _ := newTestEngine(t, now, false)
	message := mailMessage("restore-unverifiable", now)
	rawHash := archive.SHA256(message.Raw)
	path, err := e.Archive.Save(message.Raw, rawHash, now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.UpsertMessage(context.Background(), &store.Message{
		Account: e.Config.Account.Email, SourceFolder: sourceInbox,
		CurrentFolder: e.Config.Folders.Quarantine,
		UIDValidity:   42, UID: 99, MessageIDHash: hashText(message.MessageID),
		RawSHA256: rawHash, SizeBytes: int64(len(message.Raw)), Verdict: "spam",
		Action: "quarantined", Status: "quarantined", FirstSeen: now,
		LastScanned: now, ArchivePath: path,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := e.Restore(context.Background(), id); err == nil {
		t.Fatal("unverifiable recorded location was treated as absent")
	}
	if mail.appendCalls != 0 || mail.count(e.Config.Folders.Review) != 0 {
		t.Fatal("restore appended after an ambiguous FETCH failure")
	}
}

func TestArchiveCleanupRecoversAfterFileWasAlreadyDeleted(t *testing.T) {
	now := time.Now().UTC()
	e, _, db, _ := newTestEngine(t, now, false)
	expired := now.Add(-time.Hour)
	missingPath := filepath.Join(e.Archive.Root, "2026", "07", "missing.eml.age")
	if err := os.MkdirAll(filepath.Dir(missingPath), 0o700); err != nil {
		t.Fatal(err)
	}
	id, err := db.UpsertMessage(context.Background(), &store.Message{
		Account: e.Config.Account.Email, SourceFolder: sourceInbox, CurrentFolder: "",
		MessageIDHash: "missing", RawSHA256: archive.SHA256([]byte("missing")),
		Verdict: "spam", Action: "quarantine", Status: "purged",
		FirstSeen: now.Add(-40 * 24 * time.Hour), LastScanned: now,
		ArchivePath: missingPath, ArchiveUntil: &expired,
	})
	if err != nil {
		t.Fatal(err)
	}

	cleaned, err := e.CleanupExpiredArchives(context.Background())
	if err != nil || cleaned != 1 {
		t.Fatalf("idempotent cleanup failed: cleaned=%d err=%v", cleaned, err)
	}
	record, err := db.MessageByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if record.ArchivePath != "" {
		t.Fatalf("stale archive reference remained: %#v", record)
	}
}

func newTestEngine(t *testing.T, now time.Time, active bool) (*Engine, *fakeMail, *store.DB, *fakeScanner) {
	t.Helper()
	cfg := config.Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
	if active {
		cfg.Safety.Mode = "active"
	}
	mail := newFakeMail(now)
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	archiver, err := archive.New(filepath.Join(t.TempDir(), "archive"), identity)
	if err != nil {
		t.Fatal(err)
	}
	scanner := &fakeScanner{}
	engine := &Engine{
		Config: cfg, Mail: mail, Rspamd: scanner, Store: db, Archive: archiver,
		Now: func() time.Time { return now },
	}
	if active {
		enableActiveForTest(t, db, cfg, now, time.Hour)
	}
	return engine, mail, db, scanner
}

func insertPending(t *testing.T, db *store.DB, account string, message imapmail.Message, action string, at time.Time) int64 {
	t.Helper()
	id, err := db.UpsertMessage(context.Background(), &store.Message{
		Account: account, SourceFolder: sourceInbox, CurrentFolder: message.Folder,
		UIDValidity: message.UIDValidity, UID: message.UID, MessageIDHash: hashText(message.MessageID),
		RawSHA256: archive.SHA256(message.Raw), SizeBytes: int64(len(message.Raw)),
		Verdict: "spam", Action: action, Status: "pending_move",
		FirstSeen: at, LastScanned: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func addFeedback(t *testing.T, db *store.DB, account, rawHash, feedback string, at time.Time) {
	t.Helper()
	_, err := db.UpsertMessage(context.Background(), &store.Message{
		Account: account, SourceFolder: "training", CurrentFolder: "feedback-" + feedback,
		UIDValidity: uint32(at.Unix()), UID: 1, MessageIDHash: rawHash, RawSHA256: rawHash,
		Verdict: feedback, Action: "learn_" + feedback, Status: "superseded", Feedback: feedback,
		FirstSeen: at, LastScanned: at,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestActiveRunRequiresProtectionQualityGate(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, _ := newTestEngine(t, now, false)
	e.Config.Safety.Mode = "active"
	mail.add("INBOX", mailMessage("spam-gated", now))
	if err := db.SetSetting(context.Background(), "installed_at", now.Add(-15*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(context.Background(), "active_since", now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	_, err := e.Run(context.Background(), RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "quality criteria") {
		t.Fatalf("active run was not blocked by quality gate: %v", err)
	}
	if mail.count("INBOX") != 1 || mail.count(e.Config.Folders.Quarantine) != 0 {
		t.Fatal("mail moved despite failed activation gate")
	}
}

func TestPurgeQualityGatesAreEnforcedInsideEngine(t *testing.T) {
	now := time.Now().UTC()
	t.Run("active mode shorter than 30 days", func(t *testing.T) {
		e, _, _, _ := newTestEngine(t, now, true)
		e.Config.Safety.PurgeEnabled = true
		e.Config.Safety.MinLearnSpam = 0
		e.Config.Safety.MinLearnHam = 0
		_, err := e.Purge(context.Background(), false)
		if err == nil || !strings.Contains(err.Error(), "30 full days") {
			t.Fatalf("missing active-duration gate: %v", err)
		}
	})
	t.Run("too few unique learned examples", func(t *testing.T) {
		e, _, db, _ := newTestEngine(t, now, true)
		e.Config.Safety.PurgeEnabled = true
		e.Config.Safety.MinLearnSpam = 2
		e.Config.Safety.MinLearnHam = 1
		if err := db.SetSetting(context.Background(), "active_since", now.Add(-31*24*time.Hour).Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
		_, err := e.Purge(context.Background(), false)
		if err == nil || !strings.Contains(err.Error(), "insufficient unique") {
			t.Fatalf("missing training-count gate: %v", err)
		}
	})
}

func TestPurgeAlwaysBlocksHamFeedbackImportantFlagsAndMissingUID(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name        string
		flags       []string
		hamFeedback bool
		missingUID  bool
	}{
		{name: "explicit ham feedback", hamFeedback: true},
		{name: "flagged", flags: []string{`\Flagged`}},
		{name: "dollar important", flags: []string{"$IMPORTANT"}},
		{name: "important keyword", flags: []string{"important"}},
		{name: "missing exact UID mapping", missingUID: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, mail, db, _ := newTestEngine(t, now, true)
			e.Config.Safety.PurgeEnabled = true
			e.Config.Safety.MinLearnSpam = 0
			e.Config.Safety.MinLearnHam = 0
			if err := db.SetSetting(context.Background(), "active_since", now.Add(-31*24*time.Hour).Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}

			message := mailMessage("spam-purge-block", now.Add(-31*24*time.Hour))
			message.Flags = append([]string(nil), tc.flags...)
			uid := mail.add(e.Config.Folders.Quarantine, message)
			stored := mail.folders[e.Config.Folders.Quarantine][uid]
			rawHash := archive.SHA256(stored.Raw)
			archivePath, err := e.Archive.Save(stored.Raw, rawHash, now.Add(-31*24*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			quarantinedAt := now.Add(-31 * 24 * time.Hour)
			deleteAfter := now.Add(-24 * time.Hour)
			archiveUntil := now.Add(4 * 24 * time.Hour)
			recordUID, recordUIDValidity := stored.UID, stored.UIDValidity
			if tc.missingUID {
				recordUID, recordUIDValidity = 0, 0
			}
			_, err = db.UpsertMessage(context.Background(), &store.Message{
				Account: e.Config.Account.Email, SourceFolder: sourceInbox,
				CurrentFolder: e.Config.Folders.Quarantine,
				UIDValidity:   recordUIDValidity, UID: recordUID,
				MessageIDHash: hashText(stored.MessageID), RawSHA256: rawHash,
				SizeBytes: int64(len(stored.Raw)), Verdict: "spam", Action: "quarantined",
				Status: "quarantined", FirstSeen: quarantinedAt, LastScanned: quarantinedAt,
				QuarantinedAt: &quarantinedAt, DeleteAfter: &deleteAfter,
				ArchivePath: archivePath, ArchiveUntil: &archiveUntil,
			})
			if err != nil {
				t.Fatal(err)
			}
			if tc.hamFeedback {
				addFeedback(t, db, e.Config.Account.Email, rawHash, "ham", now.Add(-60*24*time.Hour))
			}

			run, err := e.Purge(context.Background(), false)
			if err != nil {
				t.Fatal(err)
			}
			if run.Purged != 0 || run.Errors != 1 || mail.count(e.Config.Folders.Quarantine) != 1 {
				t.Fatalf("unsafe purge was not blocked: %#v", run)
			}
		})
	}
}

func TestPurgeRechecksFlagsImmediatelyBeforeDelete(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, scanner := newTestEngine(t, now, true)
	e.Config.Safety.PurgeEnabled = true
	e.Config.Safety.MinLearnSpam = 0
	e.Config.Safety.MinLearnHam = 0
	if err := db.SetSetting(context.Background(), "active_since", now.Add(-31*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	message := mailMessage("spam-flagged-during-scan", now.Add(-31*24*time.Hour))
	uid := mail.add(e.Config.Folders.Quarantine, message)
	stored := mail.folders[e.Config.Folders.Quarantine][uid]
	rawHash := archive.SHA256(stored.Raw)
	archivePath, err := e.Archive.Save(stored.Raw, rawHash, now.Add(-31*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	quarantinedAt := now.Add(-31 * 24 * time.Hour)
	deleteAfter := now.Add(-24 * time.Hour)
	archiveUntil := now.Add(4 * 24 * time.Hour)
	if _, err := db.UpsertMessage(context.Background(), &store.Message{
		Account: e.Config.Account.Email, SourceFolder: sourceInbox,
		CurrentFolder: e.Config.Folders.Quarantine,
		UIDValidity:   stored.UIDValidity, UID: stored.UID,
		MessageIDHash: hashText(stored.MessageID), RawSHA256: rawHash,
		SizeBytes: int64(len(stored.Raw)), Verdict: "spam", Action: "quarantined",
		Status: "quarantined", FirstSeen: quarantinedAt, LastScanned: quarantinedAt,
		QuarantinedAt: &quarantinedAt, DeleteAfter: &deleteAfter,
		ArchivePath: archivePath, ArchiveUntil: &archiveUntil,
	}); err != nil {
		t.Fatal(err)
	}
	scanner.scanHook = func() {
		changed := mail.folders[e.Config.Folders.Quarantine][uid]
		changed.Flags = append(changed.Flags, `\Flagged`)
		mail.folders[e.Config.Folders.Quarantine][uid] = changed
		scanner.scanHook = nil
	}

	run, err := e.Purge(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if run.Purged != 0 || run.Errors != 1 || mail.count(e.Config.Folders.Quarantine) != 1 {
		t.Fatalf("flag added during scan did not block purge: %#v", run)
	}
}

func TestSkippedLearningPreservesCorrectionWithoutBayesCountOrRetryLoop(t *testing.T) {
	for _, spam := range []bool{false, true} {
		t.Run(fmt.Sprint(spam), func(t *testing.T) {
			now := time.Now().UTC()
			e, mail, db, scanner := newTestEngine(t, now, false)
			folder, destination, feedback := e.Config.Folders.TrainHam, e.Config.Folders.Inbox, "ham"
			if spam {
				folder, destination, feedback = e.Config.Folders.TrainSpam, e.Config.Folders.Quarantine, "spam"
			}
			msg := mailMessage("short-correction", now)
			mail.add(folder, msg)
			scanner.learnErr = rspamd.ErrLearningSkipped
			ctx := context.Background()
			run, err := e.Run(ctx, RunOptions{})
			if err != nil || run.Errors != 0 || run.LearnedSpam != 0 || run.LearnedHam != 0 || mail.count(folder) != 0 || mail.count(destination) != 1 {
				t.Fatalf("skipped learn did not safely complete the correction: run=%+v err=%v", run, err)
			}
			hash := archive.SHA256(msg.Raw)
			var guarded bool
			if spam {
				guarded, err = db.HasSpamFeedback(ctx, e.Config.Account.Email, hash)
			} else {
				guarded, err = db.HasHamFeedback(ctx, e.Config.Account.Email, hash)
			}
			if err != nil || !guarded {
				t.Fatalf("correction guard missing: %v", err)
			}
			learned, err := db.HasLearnedFeedback(ctx, e.Config.Account.Email, hash, feedback)
			if err != nil || learned {
				t.Fatalf("skipped learn was reported as Bayes learning: %v", err)
			}
			spams, hams, err := db.TrainingTotals(ctx, e.Config.Account.Email)
			if err != nil || spams != 0 || hams != 0 {
				t.Fatalf("incorrect Bayes totals: %d/%d %v", spams, hams, err)
			}
			if run, err := e.Run(ctx, RunOptions{}); err != nil || run.Errors != 0 || scanner.learnCalls != 1 {
				t.Fatalf("correction entered a retry loop: calls=%d run=%+v err=%v", scanner.learnCalls, run, err)
			}
			pending, err := db.PendingMessages(ctx, e.Config.Account.Email)
			if err != nil || len(pending) != 0 {
				t.Fatalf("pending moves remain: %v %v", pending, err)
			}
		})
	}
}

func TestSkippedLearningWithFailedMoveRemainsPendingAndRetriesOnlyMove(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, scanner := newTestEngine(t, now, false)
	mail.add(e.Config.Folders.TrainSpam, mailMessage("skipped-learn-move-failure", now))
	scanner.learnErr = rspamd.ErrLearningSkipped
	mail.moveFailures = 1
	ctx := context.Background()
	first, err := e.Run(ctx, RunOptions{})
	if err != nil || first.Errors != 1 || first.Status != "error" || first.LearnedSpam != 0 || mail.count(e.Config.Folders.TrainSpam) != 1 {
		t.Fatalf("failed move incorrectly completed: %+v %v", first, err)
	}
	pending, err := db.PendingMessages(ctx, e.Config.Account.Email)
	if err != nil || len(pending) != 1 {
		t.Fatalf("missing durable move: %v %v", pending, err)
	}
	second, err := e.Run(ctx, RunOptions{})
	if err != nil || second.Errors != 0 || scanner.learnCalls != 1 || mail.count(e.Config.Folders.Quarantine) != 1 || mail.count(e.Config.Folders.TrainSpam) != 0 {
		t.Fatalf("move retry failed or relearned: %+v %v calls=%d", second, err, scanner.learnCalls)
	}
	spam, ham, err := db.TrainingTotals(ctx, e.Config.Account.Email)
	if err != nil || spam != 0 || ham != 0 {
		t.Fatalf("retry invented Bayes learning: %d/%d %v", spam, ham, err)
	}
}

func TestFailedHamLearningCreatesPermanentPurgeVeto(t *testing.T) {
	now := time.Now().UTC()
	e, mail, db, scanner := newTestEngine(t, now, true)
	e.Config.Safety.PurgeEnabled = true
	e.Config.Safety.MinLearnSpam = 0
	e.Config.Safety.MinLearnHam = 0
	if err := db.SetSetting(context.Background(), "active_since", now.Add(-31*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	message := mailMessage("spam-ham-intent-veto", now.Add(-31*24*time.Hour))
	quarantineUID := mail.add(e.Config.Folders.Quarantine, message)
	stored := mail.folders[e.Config.Folders.Quarantine][quarantineUID]
	rawHash := archive.SHA256(stored.Raw)
	archivePath, err := e.Archive.Save(stored.Raw, rawHash, now.Add(-31*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	quarantinedAt := now.Add(-31 * 24 * time.Hour)
	deleteAfter := now.Add(-time.Hour)
	archiveUntil := now.Add(4 * 24 * time.Hour)
	if _, err := db.UpsertMessage(context.Background(), &store.Message{
		Account: e.Config.Account.Email, SourceFolder: sourceInbox,
		CurrentFolder: e.Config.Folders.Quarantine,
		UIDValidity:   stored.UIDValidity, UID: stored.UID,
		MessageIDHash: hashText(stored.MessageID), RawSHA256: rawHash,
		SizeBytes: int64(len(stored.Raw)), Verdict: "spam", Action: "quarantined",
		Status: "quarantined", FirstSeen: quarantinedAt, LastScanned: quarantinedAt,
		QuarantinedAt: &quarantinedAt, DeleteAfter: &deleteAfter,
		ArchivePath: archivePath, ArchiveUntil: &archiveUntil,
	}); err != nil {
		t.Fatal(err)
	}
	trainingUID := mail.add(e.Config.Folders.TrainHam, message)
	scanner.learnErr = errors.New("simulated /learnham failure")
	if run, err := e.Run(context.Background(), RunOptions{}); err != nil || run.Errors == 0 {
		t.Fatalf("failed learning was not recorded safely: run=%#v err=%v", run, err)
	}
	hasIntent, err := db.HasHamFeedback(context.Background(), e.Config.Account.Email, rawHash)
	if err != nil || !hasIntent {
		t.Fatalf("ham intent was not durable after learning failure: %v", err)
	}

	// Even if the user removes the copy from the learning folder before retry,
	// the already-recorded intent must remain a purge veto.
	delete(mail.folders[e.Config.Folders.TrainHam], trainingUID)
	run, err := e.Purge(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if run.Purged != 0 || mail.count(e.Config.Folders.Quarantine) != 1 {
		t.Fatalf("purge ignored durable ham intent: %#v", run)
	}
}
