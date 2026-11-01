//go:build ignore

// Read-only verification of quarantine moves against inspect_filtering reports.
// Run individually with go run tools/verify_filtering_moves.go.
package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/archive"
	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/imapmail"
	"github.com/xue9999/Mail-Guardian/internal/keychain"
	_ "modernc.org/sqlite"
)

type moveBaselines []string

func (b *moveBaselines) String() string { return fmt.Sprintf("%d baseline files", len(*b)) }
func (b *moveBaselines) Set(v string) error {
	if !filepath.IsAbs(v) {
		return errors.New("baseline_requires_absolute_path")
	}
	*b = append(*b, v)
	return nil
}

type moveBaselineMessage struct {
	UID, UIDValidity uint32
	Size             int64
	SHA256           string
	Error            string `json:"error"`
}
type moveBaselineFolder struct {
	Folder   string                `json:"folder"`
	Messages []moveBaselineMessage `json:"messages"`
	Error    string                `json:"error"`
}
type moveBaselineReport struct {
	Folders []moveBaselineFolder `json:"folders"`
}
type moveProof struct {
	SourceFolder                           string `json:"source_folder"`
	SourceUID, SourceUIDValidity           uint32
	LiveSourceUIDValidity                  uint32 `json:"live_source_uidvalidity"`
	LiveSourceCount                        int    `json:"live_source_count"`
	SHA256                                 string `json:"sha256"`
	Size                                   int64  `json:"size"`
	RecordID                               int64  `json:"record_id,omitempty"`
	DestinationUID, DestinationUIDValidity uint32
	SourceAbsent                           bool     `json:"source_absent"`
	ExactDestination                       bool     `json:"exact_destination"`
	Verified                               bool     `json:"verified"`
	Notes                                  []string `json:"notes,omitempty"`
	Errors                                 []string `json:"errors,omitempty"`
}
type moveReport struct {
	CreatedAt                  time.Time `json:"created_at"`
	AfterID                    int64     `json:"after_id"`
	Expected, Verified, Errors int
	Messages                   []moveProof `json:"messages"`
}
type moveSource struct {
	validity uint32
	uids     map[uint32]bool
	failed   bool
}

func main() {
	if err := verifyFilteringMoves(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func verifyFilteringMoves() error {
	var baselines moveBaselines
	flag.Var(&baselines, "baseline", "absolute inspect_filtering JSON path; repeat for multiple files")
	afterID := flag.Int64("after-id", 0, "accept only destination database records with a greater ID")
	out := flag.String("out", "", "absolute path for a new private JSON report")
	flag.Parse()
	if flag.NArg() != 0 || len(baselines) == 0 || !filepath.IsAbs(*out) || *afterID < 0 {
		return errors.New("require_baseline_after_id_and_absolute_new_out")
	}
	cfg, err := config.Load("")
	if err != nil {
		return errors.New("configuration_unavailable")
	}
	report := moveReport{CreatedAt: time.Now().UTC(), AfterID: *afterID}
	seen := map[string]bool{}
	for _, path := range baselines {
		raw, err := os.ReadFile(path)
		if err != nil {
			return errors.New("baseline_read_failed")
		}
		var baseline moveBaselineReport
		if json.Unmarshal(raw, &baseline) != nil {
			return errors.New("baseline_json_invalid")
		}
		for _, folder := range baseline.Folders {
			if folder.Folder != cfg.Folders.TrainSpam && folder.Folder != cfg.Folders.TrainHam && folder.Folder != cfg.Folders.ServerSpam {
				continue
			}
			if folder.Error != "" {
				return errors.New("baseline_source_folder_incomplete")
			}
			for _, m := range folder.Messages {
				key := fmt.Sprintf("%s:%d:%d", folder.Folder, m.UIDValidity, m.UID)
				if seen[key] {
					continue
				}
				seen[key] = true
				p := moveProof{SourceFolder: folder.Folder, SourceUID: m.UID, SourceUIDValidity: m.UIDValidity, SHA256: m.SHA256, Size: m.Size}
				hash, decodeErr := hex.DecodeString(m.SHA256)
				if m.Error != "" || decodeErr != nil || len(hash) != 32 || m.Size < 1 || m.UID == 0 || m.UIDValidity == 0 {
					p.Errors = append(p.Errors, "baseline_message_incomplete")
				}
				report.Messages = append(report.Messages, p)
			}
		}
	}
	report.Expected = len(report.Messages)
	if report.Expected == 0 {
		return errors.New("baseline_has_no_selected_source_messages")
	}
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("cannot_create_new_private_report")
	}
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	password, err := keychain.New().Get(cfg.Account.PasswordKeychainService, cfg.Account.Email)
	if err != nil {
		return errors.New("imap_credential_unavailable")
	}
	mail, err := imapmail.Dial(ctx, cfg.Account.Host, cfg.Account.Port, cfg.Account.Email, password)
	password = ""
	if err != nil {
		return errors.New("imap_connection_failed")
	}
	defer mail.Close()
	dsn := (&url.URL{Scheme: "file", Path: cfg.Runtime.Database, RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return errors.New("readonly_database_unavailable")
	}
	defer db.Close()
	sources := map[string]moveSource{}
	for _, p := range report.Messages {
		if _, ok := sources[p.SourceFolder]; ok {
			continue
		}
		uids, validity, searchErr := mail.SearchSince(p.SourceFolder, time.Time{}, 0)
		s := moveSource{validity: validity, uids: map[uint32]bool{}, failed: searchErr != nil}
		for _, uid := range uids {
			s.uids[uid] = true
		}
		sources[p.SourceFolder] = s
	}
	for i := range report.Messages {
		p := &report.Messages[i]
		if len(p.Errors) > 0 {
			continue
		}
		source := sources[p.SourceFolder]
		p.LiveSourceUIDValidity = source.validity
		p.LiveSourceCount = len(source.uids)
		if source.failed {
			p.Errors = append(p.Errors, "source_search_failed")
		} else if len(source.uids) == 0 {
			// A successful full-folder search proves that no source message
			// remains, even when the empty mailbox has a new UID namespace.
			p.SourceAbsent = true
			if source.validity != p.SourceUIDValidity {
				p.Notes = append(p.Notes, "source_empty_uidvalidity_changed")
			}
		} else if source.validity != p.SourceUIDValidity {
			p.Errors = append(p.Errors, "source_uidvalidity_changed")
		} else if source.uids[p.SourceUID] {
			p.Errors = append(p.Errors, "source_uid_still_present")
		} else {
			p.SourceAbsent = true
		}
		rows, queryErr := db.QueryContext(ctx, `SELECT id,uid,uidvalidity FROM messages WHERE account=? AND id>? AND current_folder=? AND status='quarantined' AND raw_sha256=? AND size_bytes=? ORDER BY id`, cfg.Account.Email, *afterID, cfg.Folders.Quarantine, p.SHA256, p.Size)
		if queryErr != nil {
			p.Errors = append(p.Errors, "destination_record_query_failed")
			continue
		}
		count := 0
		recordError := false
		for rows.Next() {
			var id int64
			var uid, validity uint32
			if rows.Scan(&id, &uid, &validity) != nil {
				recordError = true
				break
			}
			count++
			p.RecordID = id
			p.DestinationUID = uid
			p.DestinationUIDValidity = validity
		}
		if rows.Err() != nil {
			recordError = true
		}
		rows.Close()
		if recordError {
			p.Errors = append(p.Errors, "destination_record_read_failed")
			continue
		}
		if count != 1 || p.DestinationUID == 0 || p.DestinationUIDValidity == 0 {
			p.Errors = append(p.Errors, "destination_record_not_unique")
			continue
		}
		msg, fetchErr := mail.Fetch(cfg.Folders.Quarantine, p.DestinationUID, true)
		if fetchErr != nil {
			p.Errors = append(p.Errors, "destination_fetch_failed")
			continue
		}
		if msg.UIDValidity != p.DestinationUIDValidity {
			p.Errors = append(p.Errors, "destination_uidvalidity_changed")
		} else if msg.Size != p.Size || int64(len(msg.Raw)) != p.Size || archive.SHA256(msg.Raw) != p.SHA256 {
			p.Errors = append(p.Errors, "destination_content_mismatch")
		} else {
			p.ExactDestination = true
		}
		msg.Raw = nil
		p.Verified = p.SourceAbsent && p.ExactDestination && len(p.Errors) == 0
	}
	for _, p := range report.Messages {
		if p.Verified {
			report.Verified++
		} else {
			report.Errors++
		}
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if encoder.Encode(report) != nil || file.Sync() != nil {
		return errors.New("verification_report_write_failed")
	}
	fmt.Printf("expected=%d verified=%d errors=%d\n", report.Expected, report.Verified, report.Errors)
	if report.Errors != 0 {
		return errors.New("verification_failed_see_private_report")
	}
	return nil
}
