//go:build ignore

// Run this file individually: go run tools/inspect_filtering.go --out /private/report.json.
// It reads IMAP using BODY.PEEK and scans locally. It never moves, learns,
// modifies the Guardian database, or writes message bodies to disk.
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"mime"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/o2-mail-guardian/guardian/internal/archive"
	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/engine"
	"github.com/o2-mail-guardian/guardian/internal/imapmail"
	"github.com/o2-mail-guardian/guardian/internal/keychain"
	"github.com/o2-mail-guardian/guardian/internal/rspamd"
	_ "modernc.org/sqlite"
)

type filteringPrior struct {
	ID                                                        int64 `json:"id"`
	Folder, Verdict, Action, Status, Feedback, FeedbackIntent string
	Score                                                     float64
	FirstSeen, LastScanned                                    string
}
type filteringSymbol struct {
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}
type filteringResult struct {
	Action  string                     `json:"action"`
	Score   float64                    `json:"score"`
	Skipped bool                       `json:"is_skipped"`
	Symbols map[string]filteringSymbol `json:"symbols"`
}
type filteringMessage struct {
	UID, UIDValidity      uint32
	Size                  int64
	InternalDate          time.Time
	SHA256, Subject, From string
	MIMEValid             bool
	Error                 string           `json:"error,omitempty"`
	Result                *filteringResult `json:"result,omitempty"`
	Decision              *rspamd.Decision `json:"decision,omitempty"`
	Prior                 []filteringPrior `json:"prior,omitempty"`
}
type filteringFolder struct {
	Folder                    string `json:"folder"`
	Matched, Selected, Errors int
	Verdicts                  map[string]int     `json:"verdicts"`
	Messages                  []filteringMessage `json:"messages"`
	Error                     string             `json:"error,omitempty"`
}
type filteringReport struct {
	CreatedAt                   time.Time `json:"created_at"`
	LookbackDays                int       `json:"lookback_days"`
	SpamThreshold, HamThreshold float64
	Folders                     []filteringFolder `json:"folders"`
	Errors                      int               `json:"errors"`
}

func main() {
	if err := inspectFiltering(); err != nil {
		// Avoid echoing IMAP/server responses, credentials, or mail into logs.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func inspectFiltering() error {
	out := flag.String("out", "", "required absolute path for a new private report (contains mail headers)")
	folders := flag.String("folders", "inbox,spam,train-spam,train-ham", "comma-separated inbox,spam,train-spam,train-ham,review,quarantine")
	days := flag.Int("days", 14, "lookback in days; training folders are read in full")
	limit := flag.Int("limit", 500, "maximum newest messages inspected per folder")
	flag.Parse()
	if flag.NArg() != 0 || !filepath.IsAbs(*out) || *days < 1 || *limit < 1 {
		return errors.New("require --out /absolute/new-report.json, positive --days and --limit")
	}
	cfg, err := config.Load("")
	if err != nil {
		return errors.New("configuration_unavailable")
	}
	names := map[string]string{"inbox": cfg.Folders.Inbox, "spam": cfg.Folders.ServerSpam, "train-spam": cfg.Folders.TrainSpam, "train-ham": cfg.Folders.TrainHam, "review": cfg.Folders.Review, "quarantine": cfg.Folders.Quarantine}
	var requested []string
	seen := map[string]bool{}
	for _, alias := range strings.Split(*folders, ",") {
		name, ok := names[strings.TrimSpace(alias)]
		if !ok || name == "" {
			return errors.New("unknown_or_unconfigured_folder")
		}
		if !seen[name] {
			requested = append(requested, name)
			seen[name] = true
		}
	}
	// O_EXCL rejects an existing report or symlink. Header-bearing reports
	// belong in the private repair directory, never inside the repository.
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("cannot_create_new_private_report")
	}
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	password, err := keychain.New().Get(cfg.Account.PasswordKeychainService, cfg.Account.Email)
	if err != nil {
		return errors.New("imap_credential_unavailable")
	}
	client, err := imapmail.Dial(ctx, cfg.Account.Host, cfg.Account.Port, cfg.Account.Email, password)
	password = ""
	if err != nil {
		return errors.New("imap_connection_failed")
	}
	defer client.Close()
	dsn := (&url.URL{Scheme: "file", Path: cfg.Runtime.Database, RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return errors.New("readonly_database_unavailable")
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return errors.New("readonly_database_unavailable")
	}
	scanner := rspamd.New(cfg.Rspamd.ScanURL, cfg.Rspamd.LearnURL, "", time.Duration(cfg.Rspamd.TimeoutSeconds)*time.Second)
	report := filteringReport{CreatedAt: time.Now().UTC(), LookbackDays: *days, SpamThreshold: cfg.Rspamd.SpamScore, HamThreshold: cfg.Rspamd.HamScore}
	for _, folder := range requested {
		f := filteringFolder{Folder: folder, Verdicts: map[string]int{}}
		since := time.Now().AddDate(0, 0, -*days)
		if folder == cfg.Folders.TrainSpam || folder == cfg.Folders.TrainHam {
			since = time.Time{}
		}
		uids, validity, err := client.SearchSince(folder, since, 0)
		if err != nil {
			f.Error = "search_failed"
			f.Errors++
			report.Errors++
			report.Folders = append(report.Folders, f)
			continue
		}
		f.Matched = len(uids)
		if len(uids) > *limit {
			uids = uids[len(uids)-*limit:]
		}
		f.Selected = len(uids)
		for _, uid := range uids {
			m := filteringMessage{UID: uid, UIDValidity: validity}
			meta, err := client.Fetch(folder, uid, false)
			if err != nil {
				m.Error = "metadata_fetch_failed"
			} else if meta.Size > cfg.Safety.MaxMessageMiB<<20 {
				m.Size = meta.Size
				m.InternalDate = meta.InternalDate
				m.Error = "message_over_scan_limit"
			} else {
				msg, fetchErr := client.Fetch(folder, uid, true)
				if fetchErr != nil {
					m.Error = "body_fetch_failed"
				} else if msg.UIDValidity != validity {
					m.Error = "uidvalidity_changed"
				} else if len(msg.Raw) == 0 || int64(len(msg.Raw)) > cfg.Safety.MaxMessageMiB<<20 {
					m.Error = "body_empty_or_over_scan_limit"
				} else {
					m.Size = int64(len(msg.Raw))
					m.InternalDate = msg.InternalDate
					m.SHA256 = archive.SHA256(msg.Raw)
					if parsed, parseErr := mail.ReadMessage(bytes.NewReader(msg.Raw)); parseErr == nil {
						m.Subject = filteringHeader(parsed.Header.Get("Subject"))
						m.From = filteringHeader(parsed.Header.Get("From"))
						if addresses, addressErr := parsed.Header.AddressList("From"); addressErr == nil {
							var safe []string
							for _, a := range addresses {
								safe = append(safe, filteringHeader(a.String()))
							}
							m.From = strings.Join(safe, ", ")
						}
					}
					m.Prior, err = filteringHistory(ctx, db, cfg.Account.Email, m.SHA256)
					if err != nil {
						m.Error = "history_read_failed"
					} else if engine.ValidateMessageMIME(msg.Raw) != nil {
						m.Error = "invalid_mime"
					} else {
						m.MIMEValid = true
						result, scanErr := scanner.Scan(ctx, msg.Raw, cfg.Account.Email)
						if scanErr != nil {
							m.Error = "scan_failed"
						} else {
							safe := filteringResult{Action: result.Action, Score: result.Score, Skipped: result.IsSkipped, Symbols: map[string]filteringSymbol{}}
							for key, s := range result.Symbols {
								safe.Symbols[key] = filteringSymbol{Name: s.Name, Score: s.Score}
							}
							decision := rspamd.ClassifyDelivery(result, cfg.Rspamd.SpamScore, cfg.Rspamd.HamScore, cfg.Safety.RequireAuthForRescue)
							m.Result = &safe
							m.Decision = &decision
							f.Verdicts[decision.Verdict]++
						}
					}
					// Release each original body before the next FETCH.
					msg.Raw = nil
				}
			}
			if m.Error != "" {
				f.Errors++
				report.Errors++
			}
			f.Messages = append(f.Messages, m)
		}
		report.Folders = append(report.Folders, f)
		fmt.Printf("folder=%s selected=%d matched=%d verdicts=%v errors=%d\n", folder, f.Selected, f.Matched, f.Verdicts, f.Errors)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return errors.New("report_write_failed")
	}
	if err := file.Sync(); err != nil {
		return errors.New("report_sync_failed")
	}
	fmt.Printf("report=%s errors=%d\n", *out, report.Errors)
	if report.Errors > 0 {
		return errors.New("inspection_incomplete_see_private_report")
	}
	return nil
}

var filteringURL = regexp.MustCompile(`(?i)(?:https?://|www\.)\S+`)

func filteringHeader(value string) string {
	if decoded, err := new(mime.WordDecoder).DecodeHeader(value); err == nil {
		value = decoded
	}
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = filteringURL.ReplaceAllString(value, "[link removed]")
	if len(value) > 1000 {
		value = value[:1000]
	}
	return value
}

func filteringHistory(ctx context.Context, db *sql.DB, account, hash string) ([]filteringPrior, error) {
	rows, err := db.QueryContext(ctx, `SELECT id,current_folder,verdict,score,action,status,feedback,feedback_intent,first_seen,last_scanned FROM messages WHERE account=? AND raw_sha256=? ORDER BY id DESC LIMIT 12`, account, hash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []filteringPrior
	for rows.Next() {
		var p filteringPrior
		if err := rows.Scan(&p.ID, &p.Folder, &p.Verdict, &p.Score, &p.Action, &p.Status, &p.Feedback, &p.FeedbackIntent, &p.FirstSeen, &p.LastScanned); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
