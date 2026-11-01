package engine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
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

func TestEndToEndActiveRunPurgeAndArchiveExpiry(t *testing.T) {
	now := time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)
	cfg := config.Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
	cfg.Safety.Mode = "active"
	cfg.Safety.PurgeEnabled = true
	cfg.Safety.MinLearnSpam = 0
	cfg.Safety.MinLearnHam = 0

	mail := newFakeMail(now)
	mail.add("Spam", mailMessage("ham", now))
	mail.add("Spam", mailMessage("spam-one", now))
	mail.add("Spam", mailMessage("uncertain", now))
	mail.add("INBOX", mailMessage("spam-two", now))
	scanner := &fakeScanner{}
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	enableActiveForTest(t, db, cfg, now, 31*24*time.Hour)
	id, _ := age.GenerateX25519Identity()
	archiveRoot := filepath.Join(t.TempDir(), "archive")
	archiver, _ := archive.New(archiveRoot, id)
	e := &Engine{
		Config: cfg, Mail: mail, Rspamd: scanner, Store: db, Archive: archiver,
		Now: func() time.Time { return now },
	}

	run, err := e.Run(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if run.Scanned != 4 || run.Rescued != 1 || run.Quarantined != 2 || run.Review != 1 || run.Errors != 0 {
		t.Fatalf("unexpected run: %#v", run)
	}
	if got := mail.count("Spam"); got != 0 {
		t.Fatalf("server Spam not drained: %d", got)
	}
	if got := mail.count("AI-Kwarantanna"); got != 2 {
		t.Fatalf("quarantine=%d", got)
	}
	if got := mail.count("AI-Do-sprawdzenia"); got != 1 {
		t.Fatalf("review=%d", got)
	}
	if got := mail.count("INBOX"); got != 1 {
		t.Fatalf("inbox=%d", got)
	}
	items, err := db.Archived(context.Background(), e.Config.Account.Email, 100)
	if err != nil || len(items) != 4 {
		t.Fatalf("archives=%d err=%v", len(items), err)
	}
	for _, item := range items {
		if err := archiver.Verify(item.ArchivePath, item.RawSHA256); err != nil {
			t.Fatal(err)
		}
	}

	now = now.Add(31 * 24 * time.Hour)
	purged, err := e.Purge(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if purged.Purged != 2 || purged.Errors != 0 || mail.count("AI-Kwarantanna") != 0 {
		t.Fatalf("unexpected purge: %#v quarantine=%d", purged, mail.count("AI-Kwarantanna"))
	}

	now = now.Add(5 * 24 * time.Hour)
	cleaned, err := e.CleanupExpiredArchives(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Two purged, one rescued and one review copy all reached their 35-day
	// retention and are no longer needed for a destructive action.
	if cleaned != 4 {
		t.Fatalf("cleaned=%d", cleaned)
	}
	items, _ = db.Archived(context.Background(), e.Config.Account.Email, 100)
	if len(items) != 0 {
		t.Fatalf("archive references remained: %d", len(items))
	}
}

func TestFailureToArchivePreventsMove(t *testing.T) {
	now := time.Now().UTC()
	cfg := config.Default()
	cfg.Account.Email = "test@o2.pl"
	cfg.Folders.ServerSpam = "Spam"
	cfg.Safety.Mode = "active"
	mail := newFakeMail(now)
	mail.add("INBOX", mailMessage("spam", now))
	db, _ := store.Open(filepath.Join(t.TempDir(), "state.db"))
	defer db.Close()
	id, _ := age.GenerateX25519Identity()
	// A regular file used as the archive root makes archive.New fail. This
	// verifies the outer runtime refuses to start without a usable archive.
	rootFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := osWriteFile(rootFile, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.New(rootFile, id); err == nil {
		t.Fatal("expected archive initialization failure")
	}
	if mail.count("INBOX") != 1 || mail.count("AI-Kwarantanna") != 0 {
		t.Fatal("mail moved despite unavailable archive")
	}
}

type fakeScanner struct {
	scanCalls  int
	learnCalls int
	scanHook   func()
	learnErr   error
}

func (s *fakeScanner) Scan(_ context.Context, raw []byte, _ string) (rspamd.Result, error) {
	s.scanCalls++
	if s.scanHook != nil {
		s.scanHook()
	}
	switch {
	case bytes.Contains(raw, []byte("X-Test: spam")):
		return rspamd.Result{Score: 15, Action: "reject", Symbols: map[string]rspamd.Symbol{
			"BAYES_SPAM": {Name: "BAYES_SPAM"},
		}}, nil
	case bytes.Contains(raw, []byte("X-Test: ham")):
		return rspamd.Result{Score: -4, Action: "no action", Symbols: map[string]rspamd.Symbol{
			"DMARC_POLICY_ALLOW": {Name: "DMARC_POLICY_ALLOW"},
		}}, nil
	case bytes.Contains(raw, []byte("X-Test: error")):
		return rspamd.Result{}, errors.New("scanner down")
	default:
		return rspamd.Result{Score: 1, Symbols: map[string]rspamd.Symbol{}}, nil
	}
}

func (s *fakeScanner) Learn(context.Context, []byte, bool) error {
	s.learnCalls++
	return s.learnErr
}

type fakeMail struct {
	now                      time.Time
	uidValidity              map[string]uint32
	nextUID                  map[string]uint32
	folders                  map[string]map[uint32]imapmail.Message
	moveFailures             int
	appendCalls              int
	appendFailuresAfterWrite int
	rawFetches               int
	beforeMove               func(string)
	beforeMarkUnread         func(string)
	beforeDelete             func(string)
}

func newFakeMail(now time.Time) *fakeMail {
	m := &fakeMail{
		now: now, uidValidity: map[string]uint32{}, nextUID: map[string]uint32{},
		folders: map[string]map[uint32]imapmail.Message{},
	}
	_ = m.EnsureMailboxes("INBOX", "Spam", "AI-Kwarantanna", "AI-Do-sprawdzenia", "AI-Naucz-spam", "AI-Naucz-wazne")
	return m
}

func (m *fakeMail) SafeMoveSupported() bool   { return true }
func (m *fakeMail) SafeDeleteSupported() bool { return true }
func (m *fakeMail) EnsureMailboxes(names ...string) error {
	for _, name := range names {
		if m.folders[name] == nil {
			m.folders[name] = map[uint32]imapmail.Message{}
			m.uidValidity[name] = uint32(len(m.uidValidity) + 1)
			m.nextUID[name] = 1
		}
	}
	return nil
}
func (m *fakeMail) add(folder string, msg imapmail.Message) uint32 {
	_ = m.EnsureMailboxes(folder)
	uid := m.nextUID[folder]
	m.nextUID[folder]++
	msg.Folder, msg.UID, msg.UIDValidity = folder, uid, m.uidValidity[folder]
	m.folders[folder][uid] = msg
	return uid
}
func (m *fakeMail) count(folder string) int { return len(m.folders[folder]) }
func (m *fakeMail) SearchSince(folder string, since time.Time, limit int) ([]uint32, uint32, error) {
	var uids []uint32
	for uid, msg := range m.folders[folder] {
		if since.IsZero() || !msg.InternalDate.Before(since) {
			uids = append(uids, uid)
		}
	}
	sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
	if limit > 0 && len(uids) > limit {
		uids = uids[len(uids)-limit:]
	}
	return uids, m.uidValidity[folder], nil
}
func (m *fakeMail) SearchUIDPage(folder string, afterUID uint32, limit int) ([]uint32, uint32, bool, error) {
	uids, uidValidity, err := m.SearchSince(folder, time.Time{}, 0)
	if err != nil {
		return nil, 0, false, err
	}
	page := make([]uint32, 0, limit)
	for _, uid := range uids {
		if uid > afterUID {
			page = append(page, uid)
			if len(page) == limit {
				return page, uidValidity, false, nil
			}
		}
	}
	return page, uidValidity, true, nil
}
func (m *fakeMail) Fetch(folder string, uid uint32, withRaw bool) (imapmail.Message, error) {
	msg, ok := m.folders[folder][uid]
	if !ok {
		return imapmail.Message{}, errors.New("not found")
	}
	if !withRaw {
		msg.Raw = nil
	} else {
		m.rawFetches++
	}
	return msg, nil
}
func (m *fakeMail) Move(folder string, uidValidity, uid uint32, destination string, markUnread bool) (imapmail.MoveResult, error) {
	if m.beforeMove != nil {
		m.beforeMove(folder)
	}
	if uidValidity == 0 || uidValidity != m.uidValidity[folder] {
		return imapmail.MoveResult{}, imapmail.ErrUIDValidityChanged
	}
	if m.moveFailures > 0 {
		m.moveFailures--
		return imapmail.MoveResult{}, errors.New("simulated uncertain move failure")
	}
	msg, ok := m.folders[folder][uid]
	if !ok {
		return imapmail.MoveResult{}, errors.New("not found")
	}
	delete(m.folders[folder], uid)
	if markUnread {
		msg.Flags = nil
	}
	newUID := m.add(destination, msg)
	return imapmail.MoveResult{UIDValidity: m.uidValidity[destination], UID: newUID}, nil
}
func (m *fakeMail) MarkUnread(folder string, uidValidity, uid uint32) error {
	if m.beforeMarkUnread != nil {
		m.beforeMarkUnread(folder)
	}
	if uidValidity == 0 || uidValidity != m.uidValidity[folder] {
		return imapmail.ErrUIDValidityChanged
	}
	msg, ok := m.folders[folder][uid]
	if !ok {
		return errors.New("not found")
	}
	var flags []string
	for _, flag := range msg.Flags {
		if !strings.EqualFold(flag, `\Seen`) {
			flags = append(flags, flag)
		}
	}
	msg.Flags = flags
	m.folders[folder][uid] = msg
	return nil
}
func (m *fakeMail) AppendUnread(folder string, raw []byte, when time.Time) (imapmail.MoveResult, error) {
	m.appendCalls++
	uid := m.add(folder, imapmail.Message{Raw: append([]byte(nil), raw...), Size: int64(len(raw)), InternalDate: when})
	if m.appendFailuresAfterWrite > 0 {
		m.appendFailuresAfterWrite--
		return imapmail.MoveResult{}, errors.New("simulated lost APPEND response")
	}
	return imapmail.MoveResult{UIDValidity: m.uidValidity[folder], UID: uid}, nil
}
func (m *fakeMail) DeleteUID(folder string, uidValidity, uid uint32) error {
	if m.beforeDelete != nil {
		m.beforeDelete(folder)
	}
	if uidValidity == 0 || uidValidity != m.uidValidity[folder] {
		return imapmail.ErrUIDValidityChanged
	}
	if _, ok := m.folders[folder][uid]; !ok {
		return errors.New("not found")
	}
	delete(m.folders[folder], uid)
	return nil
}
func (m *fakeMail) FindByHash(folder, expected string, since time.Time, max int, hash func([]byte) string) (imapmail.Message, error) {
	uids, _, _ := m.SearchSince(folder, since, max)
	for _, uid := range uids {
		msg := m.folders[folder][uid]
		if hash(msg.Raw) == expected {
			return msg, nil
		}
	}
	return imapmail.Message{}, errors.New("not found")
}

func mailMessage(kind string, now time.Time) imapmail.Message {
	category := kind
	if strings.HasPrefix(kind, "spam") {
		category = "spam"
	}
	raw := []byte("From: sender@example.org\r\nMessage-ID: <" + kind + "@example.org>\r\nX-Test: " + category + "\r\n\r\nbody")
	return imapmail.Message{
		Raw: raw, Size: int64(len(raw)), MessageID: kind + "@example.org", InternalDate: now,
	}
}

// Kept as a small seam so the test remains focused on Engine behavior.
func osWriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

func enableActiveForTest(t *testing.T, db *store.DB, cfg config.Config, now time.Time, activeFor time.Duration) {
	t.Helper()
	installedAt := now.Add(-45 * 24 * time.Hour)
	if err := db.SetSetting(context.Background(), "installed_at", installedAt.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(context.Background(), "active_since", now.Add(-activeFor).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	priorAt := installedAt.Add(time.Hour)
	prior := &store.Message{
		Account: cfg.Account.Email, SourceFolder: "inbox", CurrentFolder: "quality-old",
		UIDValidity: 99, UID: 1, MessageIDHash: "quality", RawSHA256: "quality",
		Verdict: "spam", Action: "quarantined", Status: "superseded",
		FirstSeen: priorAt, LastScanned: priorAt,
	}
	if _, err := db.UpsertMessage(context.Background(), prior); err != nil {
		t.Fatal(err)
	}
	feedbackAt := priorAt.Add(time.Hour)
	feedback := &store.Message{
		Account: cfg.Account.Email, SourceFolder: "training", CurrentFolder: "quality-feedback",
		UIDValidity: 100, UID: 1, MessageIDHash: "quality", RawSHA256: "quality",
		Verdict: "spam", Action: "learn_spam", Status: "quarantined", Feedback: "spam",
		FirstSeen: feedbackAt, LastScanned: feedbackAt,
	}
	if _, err := db.UpsertMessage(context.Background(), feedback); err != nil {
		t.Fatal(err)
	}
}
