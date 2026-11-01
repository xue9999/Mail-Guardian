package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/imapmail"
)

type sizedMail struct {
	*fakeMail
	failSearch, failCandidate bool
	unrelatedUID              uint32
}

func (m *sizedMail) SearchExactSize(folder string, size int64) ([]uint32, uint32, error) {
	if m.failSearch {
		return nil, 0, errors.New("search failed")
	}
	var uids []uint32
	for uid, message := range m.folders[folder] {
		if int64(len(message.Raw)) == size {
			uids = append(uids, uid)
		}
	}
	return uids, m.uidValidity[folder], nil
}

func (m *sizedMail) Fetch(folder string, uid uint32, raw bool) (imapmail.Message, error) {
	if folder == "INBOX" && uid == m.unrelatedUID {
		return imapmail.Message{}, errors.New("unrelated damaged envelope")
	}
	if m.failCandidate {
		return imapmail.Message{}, errors.New("candidate fetch failed")
	}
	return m.fakeMail.Fetch(folder, uid, raw)
}

func TestAutomaticReconciliationSkipsUnrelatedUnreadableMessages(t *testing.T) {
	for _, failure := range []string{"none", "search", "candidate", "duplicate"} {
		t.Run(failure, func(t *testing.T) {
			now := time.Now().UTC()
			e, mail, db, _ := newTestEngine(t, now, false)
			uid := mail.add("INBOX", mailMessage("spam-pending", now))
			stored := mail.folders["INBOX"][uid]
			id := insertPending(t, db, e.Config.Account.Email, stored, "quarantined", now)
			if _, err := mail.Move("INBOX", stored.UIDValidity, uid, e.Config.Folders.Quarantine, false); err != nil {
				t.Fatal(err)
			}
			unrelated := mailMessage("unrelated-envelope-is-broken-and-has-a-different-size", now)
			unrelatedUID := mail.add("INBOX", unrelated)
			if failure == "duplicate" {
				mail.add(e.Config.Folders.Quarantine, stored)
			}
			e.Mail = &sizedMail{fakeMail: mail, failSearch: failure == "search", failCandidate: failure == "candidate", unrelatedUID: unrelatedUID}
			moves := 0
			mail.beforeMove = func(string) { moves++ }
			if err := e.reconcilePending(context.Background()); err != nil {
				t.Fatal(err)
			}
			got, err := db.MessageByID(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "none" && got.Status != "quarantined" {
				t.Fatalf("valid move not reconciled: %#v", got)
			}
			if failure != "none" && got.Status != "pending_move" && got.Status != "move_ambiguous" {
				t.Fatalf("uncertain move finalized: %#v", got)
			}
			if moves != 0 {
				t.Fatal("reconciliation repeated an already completed move")
			}
			// The scheduler must not advertise an unresolved move as a
			// successful scan, even if no new message produced an error.
			delete(mail.folders["INBOX"], unrelatedUID)
			run, err := e.Run(context.Background(), RunOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if failure != "none" && (run.Errors == 0 || run.Status != "error") {
				t.Fatal("unresolved move reported as a successful run")
			}
		})
	}
}
