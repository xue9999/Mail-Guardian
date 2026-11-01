// Command inspect_pending_mail compares unresolved moves against live IMAP.
// By default it is read-only and prints only aggregate counts, never headers.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/xue9999/Mail-Guardian/internal/config"
	"github.com/xue9999/Mail-Guardian/internal/engine"
	"github.com/xue9999/Mail-Guardian/internal/imapmail"
	"github.com/xue9999/Mail-Guardian/internal/keychain"
	"github.com/xue9999/Mail-Guardian/internal/store"
	_ "modernc.org/sqlite"
)

type record struct {
	id               int64
	action, sha, mid string
	size             int64
	current          string
}
type location struct {
	folder        string
	validity, uid uint32
}
type folderResult struct {
	Count   int            `json:"count"`
	Matches map[string]int `json:"pending_matches,omitempty"`
}

func main() {
	deep := flag.Bool("deep", false, "match unresolved messages by complete SHA-256")
	apply := flag.Bool("apply", false, "finalize only unique exact matches in the expected destination")
	findOther := flag.Bool("find-other", false, "search every IMAP folder for remaining unresolved messages")
	ackTrash := flag.Bool("ack-trash", false, "mark uniquely verified messages now in Trash as superseded without moving them")
	resolveDestination := flag.Bool("resolve-destination", false, "finalize unique exact matches in their intended destination using size-narrowed searches across all folders")
	probeFolder := flag.String("probe-folder", "", "read-only diagnostic folder")
	probeUID := flag.Uint("probe-uid", 0, "read-only diagnostic UID")
	probeLearn := flag.Bool("probe-learn-spam", false, "retry the explicit spam correction UID and report only HTTP confirmation metadata")
	flag.Parse()
	if *probeLearn {
		if err := probeLearning(uint32(*probeUID)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *probeFolder != "" && *probeUID > 0 {
		if err := probe(*probeFolder, uint32(*probeUID)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *findOther || *ackTrash || *resolveDestination {
		if *ackTrash && *resolveDestination {
			fmt.Fprintln(os.Stderr, "choose one repair operation")
			os.Exit(1)
		}
		if err := findRemaining(*ackTrash, *resolveDestination); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := inspect(*deep || *apply, *apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func probeLearning(uid uint32) error {
	if uid == 0 {
		return fmt.Errorf("specify a training UID")
	}
	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	kc := keychain.New()
	password, err := kc.Get(cfg.Account.PasswordKeychainService, cfg.Account.Email)
	if err != nil {
		return err
	}
	mail, err := imapmail.Dial(ctx, cfg.Account.Host, cfg.Account.Port, cfg.Account.Email, password)
	password = ""
	if err != nil {
		return err
	}
	defer mail.Close()
	msg, err := mail.Fetch(cfg.Folders.TrainSpam, uid, true)
	if err != nil {
		return err
	}
	controller, err := kc.Get(cfg.Rspamd.PasswordKeychainService, "controller")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.Rspamd.LearnURL, "/")+"/learnspam", bytes.NewReader(msg.Raw))
	if err != nil {
		return err
	}
	req.Header.Set("Password", controller)
	req.Header.Set("Content-Type", "message/rfc822")
	client := &http.Client{Timeout: 45 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var reply struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	jsonErr := json.Unmarshal(body, &reply)
	category := "other"
	for _, s := range []string{"less tokens", "more tokens", "already learned as spam", "denied learning"} {
		if strings.Contains(reply.Error, s) {
			category = s
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"uid": uid, "status": resp.StatusCode, "body_bytes": len(body), "json_valid": jsonErr == nil, "success": reply.Success, "error_category": category, "content_type": resp.Header.Get("Content-Type")})
}

func probe(folder string, uid uint32) error {
	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	password, err := keychain.New().Get(cfg.Account.PasswordKeychainService, cfg.Account.Email)
	if err != nil {
		return err
	}
	mail, err := imapmail.Dial(ctx, cfg.Account.Host, cfg.Account.Port, cfg.Account.Email, password)
	password = ""
	if err != nil {
		return err
	}
	defer mail.Close()
	meta, metaErr := mail.Fetch(folder, uid, false)
	full, fullErr := mail.Fetch(folder, uid, true)
	out := map[string]any{"folder": folder, "uid": uid, "metadata_ok": metaErr == nil, "body_ok": fullErr == nil}
	if metaErr != nil {
		out["metadata_error"] = metaErr.Error()
	} else {
		out["reported_size"] = meta.Size
	}
	if fullErr != nil {
		out["body_error"] = fullErr.Error()
	} else {
		out["body_bytes"] = len(full.Raw)
		out["raw_sha256"] = fmt.Sprintf("%x", sha256.Sum256(full.Raw))
		mimeErr := engine.ValidateMessageMIME(full.Raw)
		out["mime_valid"] = mimeErr == nil
		if mimeErr != nil {
			out["mime_problem"] = safeMIMEProblem(mimeErr)
		}
	}
	if metaErr != nil || fullErr != nil {
		checks, err := mail.ProbeFetch(folder, uid)
		if err == nil {
			out["fetch_items"] = checks
		}
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func safeMIMEProblem(err error) string {
	var badBase64 base64.CorruptInputError
	if errors.As(err, &badBase64) {
		return fmt.Sprintf("invalid_base64_at_byte_%d", badBase64)
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "unexpected_eof"
	}
	message := err.Error()
	for _, problem := range []struct{ fragment, code string }{
		{"RFC822:", "invalid_rfc822_headers"},
		{"Content-Type:", "invalid_content_type"},
		{"Content-Disposition:", "invalid_content_disposition"},
		{"bez granicy", "missing_multipart_boundary"},
		{"pusty multipart", "empty_multipart"},
		{"zagnieżdżona", "excessive_mime_depth"},
		{"Content-Transfer-Encoding", "unknown_transfer_encoding"},
	} {
		if strings.Contains(message, problem.fragment) {
			return problem.code
		}
	}
	return "invalid_mime_structure"
}

func findRemaining(ackTrash, resolveDestination bool) error {
	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	if resolveDestination && cfg.Safety.PurgeEnabled {
		return fmt.Errorf("permanent deletion is enabled; reconciliation stopped")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	db, err := sql.Open("sqlite", "file:"+cfg.Runtime.Database+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, "SELECT id,action,raw_sha256,message_id_hash,size_bytes,current_folder FROM messages WHERE account=? AND status IN ('pending_move','move_ambiguous') ORDER BY id", cfg.Account.Email)
	if err != nil {
		return err
	}
	var records []record
	for rows.Next() {
		var r record
		if err := rows.Scan(&r.id, &r.action, &r.sha, &r.mid, &r.size, &r.current); err != nil {
			rows.Close()
			return err
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	password, err := keychain.New().Get(cfg.Account.PasswordKeychainService, cfg.Account.Email)
	if err != nil {
		return err
	}
	mail, err := imapmail.Dial(ctx, cfg.Account.Host, cfg.Account.Port, cfg.Account.Email, password)
	password = ""
	if err != nil {
		return err
	}
	defer mail.Close()
	boxes, err := mail.ListMailboxes()
	if err != nil {
		return err
	}
	type found struct {
		ID     int64  `json:"id"`
		Folder string `json:"folder"`
		UID    uint32 `json:"uid"`
	}
	var matches []found
	for _, box := range boxes {
		for _, r := range records {
			if err := ctx.Err(); err != nil {
				return err
			}
			uids, _, err := mail.SearchExactSize(box.Name, r.size)
			if err != nil {
				if resolveDestination {
					return fmt.Errorf("incomplete scan of folder %q: %w", box.Name, err)
				}
				continue
			}
			for _, uid := range uids {
				meta, err := mail.Fetch(box.Name, uid, false)
				if err != nil {
					if resolveDestination {
						return err
					}
					continue
				}
				mid := sha256.Sum256([]byte(strings.TrimSpace(strings.ToLower(meta.MessageID))))
				if hex.EncodeToString(mid[:]) != r.mid {
					continue
				}
				full, err := mail.Fetch(box.Name, uid, true)
				if err != nil {
					if resolveDestination {
						return err
					}
					continue
				}
				sum := sha256.Sum256(full.Raw)
				if hex.EncodeToString(sum[:]) == r.sha {
					matches = append(matches, found{r.id, box.Name, uid})
				}
			}
		}
	}
	if resolveDestination {
		byID := map[int64][]found{}
		owners := map[string]int{}
		for _, m := range matches {
			byID[m.ID] = append(byID[m.ID], m)
			owners[fmt.Sprintf("%s:%d", m.Folder, m.UID)]++
		}
		writeDB, err := store.Open(cfg.Runtime.Database)
		if err != nil {
			return err
		}
		defer writeDB.Close()
		for _, r := range records {
			var destination, status string
			switch r.action {
			case "review":
				destination, status = cfg.Folders.Review, "review"
			case "learn_spam", "quarantine":
				destination, status = cfg.Folders.Quarantine, "quarantined"
			case "learn_ham", "rescue":
				destination, status = cfg.Folders.Inbox, "rescued"
			default:
				return fmt.Errorf("nieznany ruch %d", r.id)
			}
			found := byID[r.id]
			if len(found) != 1 || found[0].Folder != destination || destination == r.current || owners[fmt.Sprintf("%s:%d", found[0].Folder, found[0].UID)] != 1 {
				return fmt.Errorf("move %d has no single exact copy in the expected folder", r.id)
			}
			message, err := mail.Fetch(destination, found[0].UID, true)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(message.Raw)
			if hex.EncodeToString(sum[:]) != r.sha {
				return fmt.Errorf("move %d content changed", r.id)
			}
			if err := writeDB.FinalizeMove(ctx, r.id, destination, message.UIDValidity, message.UID, status, time.Now().UTC(), cfg.Safety.QuarantineDays, cfg.Safety.ArchiveDays); err != nil {
				return err
			}
			if err := writeDB.DeleteReconcileProgress(ctx, r.id); err != nil {
				return err
			}
			if err := writeDB.AddEvent(ctx, r.id, "move_reconciled", "one exact copy confirmed by size and SHA-256 across all folders"); err != nil {
				return err
			}
		}
	}
	if ackTrash {
		byID := map[int64][]found{}
		for _, m := range matches {
			byID[m.ID] = append(byID[m.ID], m)
		}
		if len(byID) != len(records) {
			return fmt.Errorf("not all unresolved messages were found unambiguously")
		}
		for _, r := range records {
			found := byID[r.id]
			if len(found) != 1 || !strings.EqualFold(found[0].Folder, "Trash") || strings.EqualFold(r.current, "Trash") {
				return fmt.Errorf("move %d has no single confirmed Trash location", r.id)
			}
		}
		writeDB, err := store.Open(cfg.Runtime.Database)
		if err != nil {
			return err
		}
		defer writeDB.Close()
		for _, r := range records {
			m := byID[r.id][0]
			message, err := mail.Fetch(m.Folder, m.UID, true)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(message.Raw)
			if hex.EncodeToString(sum[:]) != r.sha {
				return fmt.Errorf("move %d content changed", r.id)
			}
			if err := writeDB.UpdateLocation(ctx, r.id, m.Folder, message.UIDValidity, m.UID, "superseded"); err != nil {
				return err
			}
			if err := writeDB.AddEvent(ctx, r.id, "external_move", "exact Trash copy confirmed without modifying message"); err != nil {
				return err
			}
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"remaining": len(records), "matches": matches})
}

func inspect(deep, apply bool) error {
	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	password, err := keychain.New().Get(cfg.Account.PasswordKeychainService, cfg.Account.Email)
	if err != nil {
		return fmt.Errorf("Keychain: %w", err)
	}
	mail, err := imapmail.Dial(ctx, cfg.Account.Host, cfg.Account.Port, cfg.Account.Email, password)
	password = ""
	if err != nil {
		return err
	}
	defer mail.Close()
	pending := map[string][]record{}
	records := map[int64]record{}
	locations := map[int64][]location{}
	if deep {
		db, err := sql.Open("sqlite", "file:"+cfg.Runtime.Database+"?mode=ro")
		if err != nil {
			return err
		}
		defer db.Close()
		rows, err := db.QueryContext(ctx, "SELECT id, action, raw_sha256, message_id_hash, size_bytes, current_folder FROM messages WHERE account=? AND status IN ('pending_move','move_ambiguous')", cfg.Account.Email)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r record
			if err := rows.Scan(&r.id, &r.action, &r.sha, &r.mid, &r.size, &r.current); err != nil {
				rows.Close()
				return err
			}
			pending[fmt.Sprintf("%d:%s", r.size, r.mid)] = append(pending[fmt.Sprintf("%d:%s", r.size, r.mid)], r)
			records[r.id] = r
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	folders := map[string]string{"o2_spam": cfg.Folders.ServerSpam, "review": cfg.Folders.Review, "train_spam": cfg.Folders.TrainSpam, "train_ham": cfg.Folders.TrainHam, "quarantine": cfg.Folders.Quarantine, "inbox": cfg.Folders.Inbox}
	out := map[string]folderResult{}
	for _, name := range []string{"o2_spam", "review", "train_spam", "train_ham", "quarantine", "inbox"} {
		folder := folders[name]
		uids, _, err := mail.SearchSince(folder, time.Time{}, 0)
		if err != nil {
			return fmt.Errorf("folder %s: %w", name, err)
		}
		result := folderResult{Count: len(uids), Matches: map[string]int{}}
		if deep {
			if name == "inbox" && len(uids) > 1000 {
				uids = uids[len(uids)-1000:]
			}
			for _, uid := range uids {
				if err := ctx.Err(); err != nil {
					return err
				}
				metadata, err := mail.Fetch(folder, uid, false)
				if err != nil {
					continue
				}
				mid := sha256.Sum256([]byte(strings.TrimSpace(strings.ToLower(metadata.MessageID))))
				candidates := pending[fmt.Sprintf("%d:%s", metadata.Size, hex.EncodeToString(mid[:]))]
				if len(candidates) == 0 {
					continue
				}
				full, err := mail.Fetch(folder, uid, true)
				if err != nil {
					continue
				}
				digest := sha256.Sum256(full.Raw)
				sha := hex.EncodeToString(digest[:])
				for _, r := range candidates {
					if sha == r.sha {
						result.Matches[r.action]++
						locations[r.id] = append(locations[r.id], location{folder: folder, validity: full.UIDValidity, uid: full.UID})
					}
				}
			}
		}
		out[name] = result
	}
	if !apply {
		return json.NewEncoder(os.Stdout).Encode(out)
	}
	if cfg.Safety.PurgeEnabled {
		return fmt.Errorf("permanent deletion is enabled; reconciliation stopped")
	}
	owned := map[string]int{}
	for _, found := range locations {
		for _, l := range found {
			owned[fmt.Sprintf("%s:%d:%d", l.folder, l.validity, l.uid)]++
		}
	}
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		return err
	}
	defer db.Close()
	resolved := map[string]int{}
	for id, r := range records {
		var destination, status string
		switch r.action {
		case "review":
			destination, status = cfg.Folders.Review, "review"
		case "learn_spam":
			destination, status = cfg.Folders.Quarantine, "quarantined"
		case "learn_ham":
			destination, status = cfg.Folders.Inbox, "rescued"
		default:
			continue
		}
		found := locations[id]
		if len(found) != 1 || found[0].folder != destination || found[0].folder == r.current {
			continue
		}
		l := found[0]
		if owned[fmt.Sprintf("%s:%d:%d", l.folder, l.validity, l.uid)] != 1 {
			continue
		}
		// Recheck the exact candidate immediately before writing the local state.
		message, err := mail.Fetch(destination, l.uid, true)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(message.Raw)
		if hex.EncodeToString(sum[:]) != r.sha || message.UIDValidity != l.validity {
			continue
		}
		if r.action == "learn_ham" {
			_ = mail.MarkUnread(destination, l.validity, l.uid)
		}
		if err := db.FinalizeMove(ctx, id, destination, l.validity, l.uid, status, time.Now().UTC(), cfg.Safety.QuarantineDays, cfg.Safety.ArchiveDays); err != nil {
			return err
		}
		resolved[r.action]++
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"resolved": resolved, "remaining": len(records) - resolved["review"] - resolved["learn_spam"] - resolved["learn_ham"]})
}
