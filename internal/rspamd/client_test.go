package rspamd

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestClassifyConservativeHam(t *testing.T) {
	result := Result{Score: -4, Action: "no action", Symbols: map[string]Symbol{
		"DMARC_POLICY_ALLOW": {Name: "DMARC_POLICY_ALLOW"},
	}}
	got := Classify(result, 12, -2, true)
	if got.Verdict != "ham" || !got.Authenticated {
		t.Fatalf("got %#v", got)
	}
	result.Symbols["PHISHING"] = Symbol{Name: "PHISHING"}
	got = Classify(result, 12, -2, true)
	if got.Verdict != "uncertain" || !got.HighRisk {
		t.Fatalf("phishing must not be rescued: %#v", got)
	}
}

func TestClassifyDoesNotTreatARCAloneAsAlignedDMARC(t *testing.T) {
	result := Result{Score: -4, Symbols: map[string]Symbol{
		"ARC_ALLOW": {Name: "ARC_ALLOW"},
	}}
	got := Classify(result, 12, -2, true)
	if got.Verdict != "uncertain" || got.Authenticated {
		t.Fatalf("ARC alone must not authorize an automatic rescue: %#v", got)
	}
}

func TestClassifyDoesNotRescueHighRiskAuthenticatedMail(t *testing.T) {
	for _, symbol := range []string{"MIME_BAD_ATTACHMENT", "URIBL_BLACK", "OLETOOLS_FOUND"} {
		t.Run(symbol, func(t *testing.T) {
			result := Result{Score: -4, Symbols: map[string]Symbol{
				"DMARC_POLICY_ALLOW": {Name: "DMARC_POLICY_ALLOW"},
				symbol:               {Name: symbol},
			}}
			got := Classify(result, 12, -2, true)
			if got.Verdict != "uncertain" || !got.HighRisk {
				t.Fatalf("high-risk message must require review: %#v", got)
			}
		})
	}
}

func TestClassifySpamWins(t *testing.T) {
	got := Classify(Result{Score: 12.1, Symbols: map[string]Symbol{
		"DMARC_POLICY_ALLOW": {Name: "DMARC_POLICY_ALLOW"},
	}}, 12, -2, true)
	if got.Verdict != "spam" {
		t.Fatalf("got %s", got.Verdict)
	}
}

func TestClassifyNeverTrustsSkippedOrTimedOutScan(t *testing.T) {
	for _, result := range []Result{
		{Score: 30, Action: "soft reject"},
		{Score: 30, Action: "reject", IsSkipped: true},
		{Score: 30, Action: "reject", Symbols: map[string]Symbol{
			"R_DKIM_TEMPFAIL": {Name: "R_DKIM_TEMPFAIL"},
		}},
	} {
		got := Classify(result, 12, -2, true)
		if got.Verdict != "uncertain" || !got.HighRisk || !got.Incomplete ||
			!contains(got.Symbols, "RSPAMD_INCOMPLETE") {
			t.Fatalf("incomplete scan produced an actionable verdict: %#v", got)
		}
	}
}

func TestDeliveryDNSFailureAllowsOnlyReversibleSpamDecision(t *testing.T) {
	for _, test := range []struct {
		name              string
		score, bayes      float64
		action, failed    string
		skipped, wantSpam bool
	}{
		{"strong local evidence", 18, 0, "add header", "RDNS_DNSFAIL", false, true},
		{"bayes evidence", 9, 5.1, "add header", "R_DKIM_TEMPFAIL", false, true},
		{"insufficient evidence", 9, 0, "add header", "R_DKIM_TEMPFAIL", false, false},
		{"whole task timeout", 30, 5.1, "soft reject", "TASK_TIMEOUT", false, false},
		{"skipped", 30, 5.1, "reject", "RDNS_DNSFAIL", true, false},
		{"ham cannot be rescued", -5, 0, "no action", "RDNS_DNSFAIL", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := Result{Score: test.score, Action: test.action, IsSkipped: test.skipped, Symbols: map[string]Symbol{test.failed: {Name: test.failed}, "BAYES_SPAM": {Name: "BAYES_SPAM", Score: test.bayes}, "DMARC_POLICY_ALLOW": {Name: "DMARC_POLICY_ALLOW"}}}
			d := ClassifyDelivery(r, 6, -2, true)
			if (d.Verdict == "spam") != test.wantSpam || !d.Incomplete || d.Verdict == "ham" {
				t.Fatalf("unsafe delivery decision: %+v", d)
			}
			if strict := Classify(r, 6, -2, true); strict.Verdict != "uncertain" {
				t.Fatal("permanent-deletion classifier was weakened")
			}
		})
	}
}

func TestValidatedQuarantineThresholdDoesNotLowerPermanentDeletionThreshold(t *testing.T) {
	r := Result{Score: 9, Action: "add header"}
	if got := ClassifyDelivery(r, 6, -2, true); got.Verdict != "spam" {
		t.Fatalf("delivery: %+v", got)
	}
	if got := ClassifyPermanent(r, 6, -2, true); got.Verdict != "uncertain" {
		t.Fatalf("destructive threshold weakened: %+v", got)
	}
}

func TestClassifyUsesSymbolKeyAndRejectsUnsafeHamAction(t *testing.T) {
	maskedTimeout := Result{
		Score:  -4,
		Action: "no action",
		Symbols: map[string]Symbol{
			"R_DKIM_TEMPFAIL":    {Name: "DISPLAY_NAME_ONLY"},
			"DMARC_POLICY_ALLOW": {Name: "DMARC_POLICY_ALLOW"},
		},
	}
	if got := Classify(maskedTimeout, 12, -2, true); got.Verdict != "uncertain" || !got.Incomplete {
		t.Fatalf("timeout hidden in the symbol key was trusted: %#v", got)
	}

	unsafeAction := Result{
		Score:  -4,
		Action: "reject",
		Symbols: map[string]Symbol{
			"DMARC_POLICY_ALLOW": {Name: "DMARC_POLICY_ALLOW"},
		},
	}
	if got := Classify(unsafeAction, 12, -2, true); got.Verdict != "uncertain" || !got.HighRisk {
		t.Fatalf("inconsistent Rspamd action was trusted as ham: %#v", got)
	}

	for _, action := range []string{"", "unknown"} {
		result := Result{
			Score:  -4,
			Action: action,
			Symbols: map[string]Symbol{
				"DMARC_POLICY_ALLOW": {Name: "DMARC_POLICY_ALLOW"},
			},
		}
		if got := Classify(result, 12, -2, true); got.Verdict != "uncertain" || !got.HighRisk {
			t.Fatalf("missing or unknown action %q was trusted as ham: %#v", action, got)
		}
	}
}

func TestHTTPClientScanLearnAndPing(t *testing.T) {
	var learned, passwordSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ping":
			_, _ = io.WriteString(w, "pong")
		case "/checkv2":
			if r.Header.Get("Deliver-To") != "test@o2.pl" {
				t.Error("missing recipient")
			}
			if r.Header.Get("Pass") != "all" {
				t.Error("IMAP scan did not request all applicable checks")
			}
			if r.Header.Get("Settings") != `{"symbols_disabled":["GREYLIST_CHECK","GREYLIST_SAVE"]}` {
				t.Error("delivered IMAP message can still be deferred by SMTP greylisting")
			}
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "Subject: test") {
				t.Error("message body missing")
			}
			_, _ = io.WriteString(w, `{"action":"add header","score":13,"required_score":15,"symbols":{"BAYES_SPAM":{"name":"BAYES_SPAM","score":5}}}`)
		case "/learnspam":
			learned = true
			passwordSeen = r.Header.Get("Password") == "controller-secret"
			_, _ = io.WriteString(w, `{"success":true}`)
		case "/stat":
			passwordSeen = r.Header.Get("Password") == "controller-secret"
			_, _ = io.WriteString(w, `{"statfiles":[{"revision":12,"symbol":"BAYES_SPAM"},{"revision":8,"symbol":"BAYES_HAM"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := New(server.URL+"/checkv2", server.URL, "controller-secret", 2*time.Second)
	if err := client.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	result, err := client.Scan(context.Background(), []byte("Subject: test\r\n\r\nbody"), "test@o2.pl")
	if err != nil {
		t.Fatal(err)
	}
	if Classify(result, 12, -2, true).Verdict != "spam" {
		t.Fatal("expected spam")
	}
	if err := client.Learn(context.Background(), []byte("mail"), true); err != nil {
		t.Fatal(err)
	}
	stats, err := client.Stats(context.Background())
	if err != nil || stats.SpamRevision != 12 || stats.HamRevision != 8 {
		t.Fatalf("stats=%#v err=%v", stats, err)
	}
	if !learned || !passwordSeen {
		t.Fatal("learning request was not authenticated")
	}
}

func TestLearnNoContentIsSkippedRatherThanConfirmed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := New(server.URL+"/checkv2", server.URL, "", time.Second)
	for _, spam := range []bool{false, true} {
		if err := client.Learn(context.Background(), []byte("mail"), spam); !errors.Is(err, ErrLearningSkipped) {
			t.Fatalf("HTTP 204 must be a skipped learn, got %v", err)
		}
	}
}

func TestLearnRequiresExplicitValidConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "empty", body: ""},
		{name: "invalid JSON", body: "learned"},
		{name: "missing success", body: `{}`},
		{name: "explicit failure", body: `{"success":false}`},
		{name: "error", body: `{"success":true,"error":"rejected"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client := New(server.URL+"/checkv2", server.URL, "", time.Second)
			if err := client.Learn(context.Background(), []byte("mail"), true); err == nil {
				t.Fatal("unconfirmed learning response was accepted")
			}
		})
	}
}

func TestLearnTreatsExactSameClassDuplicateAsIdempotentSuccess(t *testing.T) {
	for _, tc := range []struct {
		name        string
		spam        bool
		errorText   string
		wantSuccess bool
	}{
		{
			name:        "spam duplicate after interrupted commit",
			spam:        true,
			errorText:   "<private-message-id> has been already learned as spam, ignore it",
			wantSuccess: true,
		},
		{
			name:        "ham duplicate after interrupted commit",
			spam:        false,
			errorText:   "<private-message-id> has been already learned as ham, ignore it",
			wantSuccess: true,
		},
		{
			name:      "opposite class remains an error",
			spam:      true,
			errorText: "<private-message-id> has been already learned as ham, ignore it",
		},
		{
			name:      "unrelated rejection remains an error",
			spam:      true,
			errorText: "all learn conditions denied learning",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"error":`+strconv.Quote(tc.errorText)+`}`)
			}))
			defer server.Close()
			client := New(server.URL+"/checkv2", server.URL, "", time.Second)
			err := client.Learn(context.Background(), []byte("mail"), tc.spam)
			if tc.wantSuccess && err != nil {
				t.Fatalf("idempotent duplicate was rejected: %v", err)
			}
			if !tc.wantSuccess && err == nil {
				t.Fatal("unsafe learning error was accepted")
			}
		})
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	var redirected bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected = true
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	client := New(source.URL+"/checkv2", source.URL, "secret", time.Second)
	if err := client.Learn(context.Background(), []byte("private mail"), true); err == nil {
		t.Fatal("redirect response was accepted")
	}
	if redirected {
		t.Fatal("email or controller secret was sent to redirect target")
	}
}

func TestReadLimitedRejectsOversizedResponse(t *testing.T) {
	if _, err := readLimited(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("oversized response was silently truncated")
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
