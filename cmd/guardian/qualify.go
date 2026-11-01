// Local, disjoint model qualification. Plaintext mail exists only in memory.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"mime"
	"net/mail"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/o2-mail-guardian/guardian/internal/archive"
	"github.com/o2-mail-guardian/guardian/internal/config"
	"github.com/o2-mail-guardian/guardian/internal/engine"
	"github.com/o2-mail-guardian/guardian/internal/keychain"
	"github.com/o2-mail-guardian/guardian/internal/qualification"
	"github.com/o2-mail-guardian/guardian/internal/rspamd"
	"github.com/o2-mail-guardian/guardian/internal/stack"
	"github.com/o2-mail-guardian/guardian/internal/store"
	_ "modernc.org/sqlite"
)

type sample struct {
	Hash, Label, Group string
	Raw                []byte
	Bucket             int
}
type observation = qualification.Evidence

func (a *application) qualifyCommand(args []string) error {
	fs := flag.NewFlagSet("qualify", flag.ContinueOnError)
	fs.SetOutput(a.errOut)
	importPath := fs.String("import", "", "import a previously generated disjoint evaluation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("użyj guardian qualify [--import raport.json]")
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(signalContext, 30*time.Minute)
	defer cancel()
	lock, err := acquireRunLock(cfg.Runtime.DataDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	if *importPath != "" {
		data, err := os.ReadFile(*importPath)
		if err != nil {
			return err
		}
		var report qualification.Report
		if err := json.Unmarshal(data, &report); err != nil {
			return err
		}
		return a.installQualification(cfg, report)
	}
	manager := stack.Manager{ComposeFile: cfg.Runtime.ComposeFile, RuntimeDir: config.DefaultRuntimeDir()}
	sandbox, err := manager.NewQualificationSandbox(ctx, cfg.Runtime.DataDir)
	if err != nil {
		return err
	}
	defer sandbox.Close()
	scanner := rspamd.New(sandbox.ScanURL, sandbox.LearnURL, sandbox.Password, 45*time.Second)
	deadlinePing := time.Now().Add(30 * time.Second)
	for scanner.Ping(ctx) != nil {
		if time.Now().After(deadlinePing) {
			return errors.New("odrębny silnik testowy nie odpowiedział")
		}
		time.Sleep(time.Second)
	}
	a.info("Oceniam odrębny, nowy model na oddzielonych przykładach. Poczta pozostaje w swoich folderach.")
	id, err := archive.LoadIdentity(keychain.New(), cfg.Runtime.ArchiveKeychainService, cfg.Account.Email)
	if err != nil {
		return err
	}
	arch := &archive.Manager{Root: cfg.Runtime.ArchiveDir, Identity: id}
	db, err := sql.Open("sqlite", "file:"+cfg.Runtime.Database+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT raw_sha256,MIN(archive_path),MIN(COALESCE(NULLIF(feedback_intent,''),feedback)),COUNT(DISTINCT COALESCE(NULLIF(feedback_intent,''),feedback)) FROM messages WHERE account=? AND archive_path<>'' AND (feedback<>'' OR feedback_intent<>'') GROUP BY raw_sha256 ORDER BY raw_sha256`, cfg.Account.Email)
	if err != nil {
		return err
	}
	var samples []*sample
	skipped := 0
	for rows.Next() {
		var hash, path, label string
		var labels int
		if err := rows.Scan(&hash, &path, &label, &labels); err != nil {
			return err
		}
		if labels != 1 {
			skipped++
			continue
		}
		raw, err := arch.Read(path)
		if err != nil {
			return err
		}
		if archive.SHA256(raw) != hash {
			return errors.New("archive content hash mismatch")
		}
		if engine.ValidateMessageMIME(raw) != nil {
			skipped++
			continue
		}
		m, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			return err
		}
		sub, err := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
		if err != nil {
			sub = m.Header.Get("Subject")
		}
		normalized := strings.Map(func(r rune) rune {
			if unicode.IsDigit(r) {
				return '0'
			}
			if unicode.IsLetter(r) {
				return unicode.ToLower(r)
			}
			return ' '
		}, sub)
		normalized = strings.Join(strings.Fields(normalized), " ")
		if normalized == "" {
			normalized = hash
		}
		sum := sha256.Sum256([]byte(normalized))
		samples = append(samples, &sample{Hash: hash, Label: label, Group: hex.EncodeToString(sum[:]), Raw: raw})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	// Subject families stay together. Greedy assignment balances class counts
	// without consulting scores or any future validation outcome.
	groups := map[string][]*sample{}
	for _, s := range samples {
		groups[s.Group] = append(groups[s.Group], s)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(groups[keys[i]]) != len(groups[keys[j]]) {
			return len(groups[keys[i]]) > len(groups[keys[j]])
		}
		return keys[i] < keys[j]
	})
	counts := [10][2]int{}
	for _, k := range keys {
		g := groups[k]
		spam, ham := 0, 0
		for _, s := range g {
			if s.Label == "spam" {
				spam++
			} else {
				ham++
			}
		}
		best := 0
		cost := int(^uint(0) >> 1)
		for b := 0; b < 10; b++ {
			v := counts[b][0]*spam + counts[b][1]*ham
			if v < cost {
				best, cost = b, v
			}
		}
		for _, s := range g {
			s.Bucket = best
		}
		counts[best][0] += spam
		counts[best][1] += ham
	}
	enc := json.NewEncoder(a.out)
	// Buckets 5 and 6 were reserved from exploratory measurements. The
	// mapping is deterministic; neither scores nor labels of the test set
	// influence threshold selection.
	for _, entry := range samples {
		switch entry.Bucket {
		case 0:
			entry.Bucket = 5
		case 1:
			entry.Bucket = 6
		case 5:
			entry.Bucket = 0
		case 6:
			entry.Bucket = 1
		}
	}
	enc.Encode(map[string]any{"samples": len(samples), "groups": len(groups), "excluded": skipped, "buckets": counts})
	learned, skipLearn := 0, 0
	for _, s := range samples {
		if s.Bucket < 3 {
			continue
		}
		err := scanner.Learn(ctx, s.Raw, s.Label == "spam")
		if errors.Is(err, rspamd.ErrLearningSkipped) {
			skipLearn++
			continue
		}
		if err != nil {
			return err
		}
		learned++
	}
	stats, err := scanner.Stats(ctx)
	if err != nil {
		return err
	}
	enc.Encode(map[string]any{"train_confirmed": learned, "train_skipped": skipLearn, "bayes": stats})
	deadline := time.Now().Add(60 * time.Second)
	for (stats.SpamRevision < 100 || stats.HamRevision < 100) && time.Now().Before(deadline) {
		time.Sleep(time.Second)
		stats, err = scanner.Stats(ctx)
		if err != nil {
			return err
		}
	}
	if stats.SpamRevision < 100 || stats.HamRevision < 100 {
		return errors.New("training partition has fewer than 100 learns per class")
	}
	scan := func(bucket func(int) bool) ([]observation, error) {
		var selected []*sample
		for _, s := range samples {
			if bucket(s.Bucket) {
				selected = append(selected, s)
			}
		}
		jobs := make(chan *sample)
		var mu sync.Mutex
		var wg sync.WaitGroup
		var observations []observation
		var errs []error
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for s := range jobs {
					r, err := scanner.Scan(ctx, s.Raw, cfg.Account.Email)
					mu.Lock()
					if err != nil {
						errs = append(errs, err)
					} else {
						d := rspamd.ClassifyDelivery(r, 6, -2, true)
						observations = append(observations, observation{Hash: s.Hash, Label: s.Label, Group: s.Group, Bucket: s.Bucket, Score: r.Score, Verdict: d.Verdict, Incomplete: d.Incomplete, Bayes: r.Symbols["BAYES_SPAM"].Score})
					}
					mu.Unlock()
				}
			}()
		}
		for _, s := range selected {
			jobs <- s
		}
		close(jobs)
		wg.Wait()
		return observations, errors.Join(errs...)
	}
	calibration, err := scan(func(b int) bool { return b == 2 })
	if err != nil {
		return err
	}
	threshold := 6.0
	for _, o := range calibration {
		if o.Label == "ham" && o.Score+1 > threshold {
			threshold = o.Score + 1
		}
	}
	enc.Encode(map[string]any{"calibration_samples": len(calibration), "frozen_spam_threshold": threshold})
	validation, err := scan(func(b int) bool { return b < 2 })
	if err != nil {
		return err
	}
	spam, ham, tp, fp, incomplete := 0, 0, 0, 0, 0
	for _, o := range validation {
		detected := o.Verdict == "spam" && o.Score >= threshold
		if o.Label == "spam" {
			spam++
			if detected {
				tp++
			}
		} else {
			ham++
			if detected {
				fp++
			}
		}
		if o.Incomplete {
			incomplete++
		}
	}
	var training []qualification.Evidence
	for _, entry := range samples {
		if entry.Bucket >= 3 {
			training = append(training, qualification.Evidence{Hash: entry.Hash, Label: entry.Label, Group: entry.Group, Bucket: entry.Bucket})
		}
	}
	report := qualification.Report{Protocol: 1, Method: "subject-grouped-disjoint-70-10-20", Policy: qualification.Policy, CreatedAt: time.Now().UTC(), AuthorizationFingerprint: cfg.AuthorizationFingerprint(), MinLearns: qualification.MinLearns, SpamThreshold: threshold, TrainingStats: stats, Training: training, Calibration: calibration, Validation: validation, Excluded: skipped}
	metrics := report.Metrics()
	enc.Encode(map[string]any{"spam_tested": spam, "spam_detected": tp, "ham_tested": ham, "false_positives": fp, "incomplete": incomplete, "false_rescues": metrics.FalseRescues})
	if err := ctx.Err(); err != nil {
		return err
	}
	return a.installQualification(cfg, report)
}

func (a *application) installQualification(cfg config.Config, report qualification.Report) error {
	candidate := cfg
	candidate.Rspamd.SpamScore = report.SpamThreshold
	if err := candidate.Validate(); err != nil {
		return err
	}
	if err := report.Validate(candidate, time.Now().UTC()); err != nil {
		return err
	}
	db, err := store.Open(cfg.Runtime.Database)
	if err != nil {
		return err
	}
	defer db.Close()
	previous, err := db.GetSetting(context.Background(), "filter_qualification_v1")
	if err != nil {
		return err
	}
	root := filepath.Join(cfg.Runtime.DataDir, "qualification-history")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(root, report.Digest()+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	if err := db.SaveQualification(context.Background(), candidate, report, time.Now().UTC()); err != nil {
		return err
	}
	if err := config.Save(a.configPath, candidate); err != nil {
		rollback := db.SetSetting(context.Background(), "filter_qualification_v1", previous)
		return errors.Join(err, rollback)
	}
	m := report.Metrics()
	a.success(fmt.Sprintf("Ocena zapisana: spam %d/%d, ważne %d, błędny spam %d, błędne ratowanie %d. Próg kwarantanny %.2f.", m.SpamDetected, m.SpamTested, m.HamTested, m.FalsePositives, m.FalseRescues, report.SpamThreshold))
	return nil
}
