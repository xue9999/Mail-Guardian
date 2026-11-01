package rspamd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Client struct {
	ScanURL  string
	LearnURL string
	Password string
	HTTP     *http.Client
}

type Symbol struct {
	Name        string   `json:"name"`
	Score       float64  `json:"score"`
	Description string   `json:"description"`
	Options     []string `json:"options"`
}

type Result struct {
	Action        string            `json:"action"`
	Score         float64           `json:"score"`
	RequiredScore float64           `json:"required_score"`
	MessageID     string            `json:"message-id"`
	IsSkipped     bool              `json:"is_skipped"`
	Symbols       map[string]Symbol `json:"symbols"`
}

type Decision struct {
	Verdict       string
	Score         float64
	Action        string
	Symbols       []string
	Authenticated bool
	HighRisk      bool
	Incomplete    bool
}

type BayesStats struct {
	SpamRevision uint64 `json:"spam_revision"`
	HamRevision  uint64 `json:"ham_revision"`
}

// HTTP 204 is Rspamd's explicit refusal under its learning conditions. It
// confirms neither a Bayes update nor an already learned message.
var ErrLearningSkipped = errors.New("Rspamd skipped learning under classifier conditions")

func New(scanURL, learnURL, password string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	return &Client{
		ScanURL:  strings.TrimRight(scanURL, "/"),
		LearnURL: strings.TrimRight(learnURL, "/"),
		Password: password,
		HTTP: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				Proxy:             nil,
				DialContext:       (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				ForceAttemptHTTP2: false,
				MaxIdleConns:      2,
				IdleConnTimeout:   30 * time.Second,
			},
		},
	}
}

func (c *Client) Ping(ctx context.Context) error {
	u, err := url.Parse(c.ScanURL)
	if err != nil {
		return err
	}
	u.Path = "/ping"
	u.RawQuery = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("Rspamd not responding: %w", err)
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, 1024)
	if err != nil {
		return fmt.Errorf("reading Rspamd /ping response: %w", err)
	}
	if resp.StatusCode/100 != 2 || !strings.Contains(strings.ToLower(string(body)), "pong") {
		return fmt.Errorf("Rspamd returned %s", resp.Status)
	}
	return nil
}

func (c *Client) Scan(ctx context.Context, raw []byte, recipient string) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ScanURL, bytes.NewReader(raw))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "message/rfc822")
	req.Header.Set("Flags", "groups,no_log")
	// IMAP scans do not arrive through an SMTP worker, so ask Rspamd to run
	// every applicable check. We deliberately do not invent a source IP from
	// untrusted Received headers.
	req.Header.Set("Pass", "all")
	// These messages have already been delivered. SMTP greylisting cannot
	// defer their delivery; its soft reject would hide an otherwise complete
	// spam verdict. Disable only the two greylisting callbacks, retaining real
	// timeout/DNS failure checks and the fail-closed soft-reject handling.
	req.Header.Set("Settings", `{"symbols_disabled":["GREYLIST_CHECK","GREYLIST_SAVE"]}`)
	if recipient != "" {
		req.Header.Set("Deliver-To", recipient)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("Rspamd scan: %w", err)
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, 2<<20)
	if err != nil {
		return Result{}, err
	}
	if resp.StatusCode/100 != 2 {
		return Result{}, fmt.Errorf("Rspamd /checkv2 returned %s", resp.Status)
	}
	var result Result
	if err := json.Unmarshal(body, &result); err != nil {
		return Result{}, fmt.Errorf("invalid Rspamd response: %w", err)
	}
	return result, nil
}

func Classify(result Result, spamScore, hamScore float64, requireAuth bool) Decision {
	names := make([]string, 0, len(result.Symbols))
	authenticated := false
	highRisk := false
	incomplete := result.IsSkipped || strings.EqualFold(strings.TrimSpace(result.Action), "soft reject")
	for key, symbol := range result.Symbols {
		keyName := strings.ToUpper(key)
		name := keyName
		if symbol.Name != "" {
			name = strings.ToUpper(symbol.Name)
		}
		names = append(names, name)
		identifiers := []string{keyName, name}
		for _, identifier := range identifiers {
			for _, marker := range []string{"TIMEOUT", "DNSFAIL", "TEMPFAIL"} {
				if strings.Contains(identifier, marker) {
					incomplete = true
					break
				}
			}
		}
		switch name {
		case "DMARC_POLICY_ALLOW":
			authenticated = true
		}
		for _, identifier := range identifiers {
			for _, marker := range []string{
				"PHISH", "FORGED", "SPOOF", "MALWARE", "VIRUS",
				"DKIM_REJECT", "DMARC_POLICY_REJECT", "ARC_REJECT",
				"MISSING_FROM", "MIME_BAD", "BAD_ATTACHMENT", "EXECUTABLE",
				"OLETOOLS", "RANSOMWARE", "ENCRYPTED_ARCHIVE", "SUSPICIOUS",
				"URL_REDIRECTOR", "SURBL", "URIBL",
			} {
				if strings.Contains(identifier, marker) {
					highRisk = true
					break
				}
			}
		}
	}
	action := strings.ToLower(strings.TrimSpace(result.Action))
	if action != "no action" {
		highRisk = true
	}
	if incomplete {
		names = append(names, "RSPAMD_INCOMPLETE")
		highRisk = true
	}
	sort.Strings(names)
	if len(names) > 20 {
		names = names[:20]
	}
	decision := Decision{
		Verdict: "uncertain", Score: result.Score, Action: result.Action,
		Symbols: names, Authenticated: authenticated, HighRisk: highRisk,
		Incomplete: incomplete,
	}
	if incomplete {
		return decision
	}
	if result.Score >= spamScore {
		decision.Verdict = "spam"
		return decision
	}
	authOK := authenticated || !requireAuth
	if result.Score <= hamScore && authOK && !highRisk {
		decision.Verdict = "ham"
	}
	return decision
}

// ClassifyDelivery permits reversible quarantine on positive spam evidence
// even when a supplementary DNS check failed. Such a result remains incomplete:
// it must never authorize rescue or permanent deletion. Whole-task timeouts,
// skipped scans and soft rejects still fail closed, regardless of score.
func ClassifyDelivery(result Result, spamScore, hamScore float64, requireAuth bool) Decision {
	d := Classify(result, spamScore, hamScore, requireAuth)
	if !d.Incomplete || result.IsSkipped || strings.EqualFold(strings.TrimSpace(result.Action), "soft reject") {
		return d
	}
	networkFailure := false
	bayesSpam := 0.0
	for key, symbol := range result.Symbols {
		for _, name := range []string{strings.ToUpper(key), strings.ToUpper(symbol.Name)} {
			if strings.Contains(name, "TIMEOUT") {
				return d
			}
			if strings.Contains(name, "DNSFAIL") || strings.Contains(name, "TEMPFAIL") {
				networkFailure = true
			}
			if name == "BAYES_SPAM" && symbol.Score > bayesSpam {
				bayesSpam = symbol.Score
			}
		}
	}
	if networkFailure && result.Score >= spamScore && (result.Score >= 12 || bayesSpam >= 3) {
		d.Verdict = "spam"
		d.Symbols = append(d.Symbols, "QUARANTINE_ONLY_DNS_INCOMPLETE")
	}
	return d
}

// Permanent deletion retains the original score floor and requires every
// check to complete, independently of the validated quarantine threshold.
func ClassifyPermanent(result Result, spamScore, hamScore float64, requireAuth bool) Decision {
	if spamScore < 12 {
		spamScore = 12
	}
	return Classify(result, spamScore, hamScore, requireAuth)
}

func (c *Client) Learn(ctx context.Context, raw []byte, spam bool) error {
	endpoint := "/learnham"
	if spam {
		endpoint = "/learnspam"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.LearnURL+endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "message/rfc822")
	if c.Password != "" {
		req.Header.Set("Password", c.Password)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("Rspamd learning: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return ErrLearningSkipped
	}
	body, err := readLimited(resp.Body, 1<<20)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return errors.New("Rspamd returned no learning acknowledgement")
	}
	var status struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("Rspamd %s returned %s", endpoint, resp.Status)
		}
		return fmt.Errorf("invalid Rspamd learning response: %w", err)
	}
	class := "ham"
	if spam {
		class = "spam"
	}
	// Rspamd's learn cache deliberately rejects an exact duplicate with a
	// non-2xx response. If Guardian crashed after Rspamd committed the learn
	// but before SQLite recorded it, this precise same-class reply is the
	// idempotent confirmation needed to finish the pending correction.
	if alreadyLearnedAs(status.Error, class) {
		return nil
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("Rspamd %s returned %s", endpoint, resp.Status)
	}
	if status.Error != "" {
		return errors.New("Rspamd rejected learning")
	}
	if !status.Success {
		return errors.New("Rspamd did not confirm learning")
	}
	return nil
}

func (c *Client) Stats(ctx context.Context) (BayesStats, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.LearnURL+"/stat", nil)
	if err != nil {
		return BayesStats{}, err
	}
	if c.Password != "" {
		req.Header.Set("Password", c.Password)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return BayesStats{}, fmt.Errorf("Rspamd statistics: %w", err)
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, 2<<20)
	if err != nil {
		return BayesStats{}, err
	}
	if resp.StatusCode/100 != 2 {
		return BayesStats{}, fmt.Errorf("Rspamd /stat returned %s", resp.Status)
	}
	var payload struct {
		Statfiles []struct {
			Revision uint64 `json:"revision"`
			Symbol   string `json:"symbol"`
		} `json:"statfiles"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return BayesStats{}, fmt.Errorf("invalid Rspamd statistics: %w", err)
	}
	var stats BayesStats
	var spamSeen, hamSeen bool
	for _, statfile := range payload.Statfiles {
		switch strings.ToUpper(strings.TrimSpace(statfile.Symbol)) {
		case "BAYES_SPAM":
			stats.SpamRevision, spamSeen = statfile.Revision, true
		case "BAYES_HAM":
			stats.HamRevision, hamSeen = statfile.Revision, true
		}
	}
	if !spamSeen || !hamSeen {
		return BayesStats{}, errors.New("Rspamd /stat is missing BAYES_SPAM or BAYES_HAM statistics")
	}
	return stats, nil
}

func alreadyLearnedAs(message, class string) bool {
	message = strings.ToLower(strings.TrimSpace(message))
	class = strings.ToLower(strings.TrimSpace(class))
	return (class == "spam" || class == "ham") &&
		strings.Contains(message, "has been already learned as "+class)
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return body, nil
}
