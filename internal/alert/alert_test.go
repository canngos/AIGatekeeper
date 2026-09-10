package alert

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/identity"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// recorder captures what a notifier was asked to send.
type recorder struct {
	mu    sync.Mutex
	name  string
	sent  []Alert
	to    [][]string
	fail  error
	calls int
}

func (r *recorder) Name() string { return r.name }
func (r *recorder) Send(_ context.Context, a Alert, recipients []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.fail != nil {
		return r.fail
	}
	r.sent = append(r.sent, a)
	r.to = append(r.to, recipients)
	return nil
}
func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sent)
}

func blockEvent(user string, at time.Time) audit.Event {
	return audit.Event{
		Time: at, Kind: audit.KindRequest, RequestID: "R", User: user, Device: "laptop-" + user, ClientIP: "10.0.0.5",
		Service: "openai", Host: "api.openai.com", Path: "/v1/chat/completions", Action: audit.ActionBlock, Rule: "secrets",
		Findings: []audit.FindingSummary{{Detector: "aws_access_key", Severity: "critical", Preview: "AKIA****EY"}},
	}
}

func testEngine(t *testing.T, rule Rule, notifiers map[string]Notifier, dir identity.Directory) (*Engine, *MemoryStore) {
	t.Helper()
	store := NewMemoryStore()
	e := New(Options{Rules: []Rule{rule}, Store: store, Notifiers: notifiers, Directory: dir, Logger: quiet})
	return e, store
}

func defaultRule() Rule {
	return Rule{
		ID: "repeat-offender", GroupBy: GroupUser, Threshold: 3, Window: time.Hour, Cooldown: 24 * time.Hour,
		Notify: []Target{{Type: "email", To: []string{"security@corp.example"}}},
	}
}

func TestEngineRaisesOnThreshold(t *testing.T) {
	email := &recorder{name: "email"}
	e, store := testEngine(t, defaultRule(), map[string]Notifier{"email": email}, nil)
	now := time.Now()

	for i := 0; i < 2; i++ {
		if err := e.Observe(context.Background(), blockEvent("alice", now.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	if email.count() != 0 {
		t.Fatal("an alert fired before the threshold was reached")
	}
	if err := e.Observe(context.Background(), blockEvent("alice", now.Add(2*time.Minute))); err != nil {
		t.Fatal(err)
	}
	if email.count() != 1 {
		t.Fatalf("expected one alert at the threshold, got %d", email.count())
	}

	a := email.sent[0]
	if a.User != "alice" || a.Count != 3 || a.GroupBy != GroupUser || a.Severity != "critical" {
		t.Fatalf("unexpected alert: %+v", a)
	}
	if len(a.Events) != 3 || a.Events[0].Previews[0] != "AKIA****EY" {
		t.Fatalf("contributing events missing or unmasked: %+v", a.Events)
	}
	if email.to[0][0] != "security@corp.example" {
		t.Fatalf("recipients: %v", email.to[0])
	}
	if got := store.Alerts(); len(got) != 1 || got[0].Status != "open" {
		t.Fatalf("alert not stored: %+v", got)
	}
	// The alert must never carry the raw secret.
	raw, _ := json.Marshal(a)
	if strings.Contains(string(raw), "AKIAIOSFODNN7REALKEY") {
		t.Fatal("the alert payload leaked a raw secret")
	}
}

func TestEngineCooldownAndFreshRun(t *testing.T) {
	email := &recorder{name: "email"}
	e, _ := testEngine(t, defaultRule(), map[string]Notifier{"email": email}, nil)
	now := time.Now()
	e.now = func() time.Time { return now }

	for i := 0; i < 6; i++ {
		_ = e.Observe(context.Background(), blockEvent("alice", now))
	}
	if email.count() != 1 {
		t.Fatalf("cooldown should hold further alerts, got %d", email.count())
	}
	if _, suppressed := e.Stats(); suppressed == 0 {
		t.Error("suppressed alerts should be counted")
	}

	// Once the cooldown lapses, a fresh run of violations alerts again.
	now = now.Add(25 * time.Hour)
	for i := 0; i < 3; i++ {
		_ = e.Observe(context.Background(), blockEvent("alice", now))
	}
	if email.count() != 2 {
		t.Fatalf("expected a second alert after the cooldown, got %d", email.count())
	}
}

func TestEngineGroupsSeparatelyAndFallsBack(t *testing.T) {
	email := &recorder{name: "email"}
	e, _ := testEngine(t, defaultRule(), map[string]Notifier{"email": email}, nil)
	now := time.Now()

	// Three events split across two people do not reach either threshold.
	_ = e.Observe(context.Background(), blockEvent("alice", now))
	_ = e.Observe(context.Background(), blockEvent("bob", now))
	_ = e.Observe(context.Background(), blockEvent("alice", now))
	if email.count() != 0 {
		t.Fatal("events from different people must not be counted together")
	}
	_ = e.Observe(context.Background(), blockEvent("alice", now))
	if email.count() != 1 || email.sent[0].User != "alice" {
		t.Fatalf("expected one alert for alice, got %d", email.count())
	}

	// With no user, grouping falls back to the device.
	anon := blockEvent("", now)
	anon.User = ""
	anon.Device = "kiosk-3"
	e2, _ := testEngine(t, defaultRule(), map[string]Notifier{"email": email}, nil)
	for i := 0; i < 3; i++ {
		_ = e2.Observe(context.Background(), anon)
	}
	last := email.sent[len(email.sent)-1]
	if last.GroupBy != GroupDevice || last.GroupKey != "kiosk-3" {
		t.Fatalf("expected the device fallback, got %s=%s", last.GroupBy, last.GroupKey)
	}
}

func TestEngineWindowExpiry(t *testing.T) {
	email := &recorder{name: "email"}
	rule := defaultRule()
	rule.Window = 10 * time.Minute
	e, _ := testEngine(t, rule, map[string]Notifier{"email": email}, nil)
	now := time.Now()
	e.now = func() time.Time { return now }

	_ = e.Observe(context.Background(), blockEvent("alice", now.Add(-30*time.Minute)))
	_ = e.Observe(context.Background(), blockEvent("alice", now.Add(-20*time.Minute)))
	_ = e.Observe(context.Background(), blockEvent("alice", now))
	if email.count() != 0 {
		t.Fatal("events older than the window must not count towards the threshold")
	}
}

func TestMatchSelectsEvents(t *testing.T) {
	base := blockEvent("alice", time.Now())
	cases := []struct {
		name  string
		match Match
		event audit.Event
		want  bool
	}{
		{"default counts blocks", Match{}, base, true},
		{"default counts monitors", Match{}, func() audit.Event { e := base; e.Action = audit.ActionMonitor; return e }(), true},
		{"default ignores allows", Match{}, func() audit.Event { e := base; e.Action = audit.ActionAllow; return e }(), false},
		{"ignores non-request kinds", Match{}, func() audit.Event { e := base; e.Kind = audit.KindTunnel; return e }(), false},
		{"service filter", Match{Services: []string{"copilot"}}, base, false},
		{"rule filter", Match{Rules: []string{"secrets"}}, base, true},
		{"min severity met", Match{MinSeverity: "high"}, base, true},
		{"min severity not met", Match{MinSeverity: "critical"}, func() audit.Event {
			e := base
			e.Findings = []audit.FindingSummary{{Detector: "email", Severity: "medium"}}
			return e
		}(), false},
		{"detector filter", Match{Detectors: []string{"github_token"}}, base, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.match.Matches(c.event); got != c.want {
				t.Errorf("Matches() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestRecipientsFromDirectory(t *testing.T) {
	email := &recorder{name: "email"}
	rule := defaultRule()
	rule.Notify = []Target{{Type: "email", To: []string{"security@corp.example"}, ToManager: true, ToUser: true}}
	dir := identity.StaticDirectory{"alice": {"alice@corp.example", "mona@corp.example"}}
	e, _ := testEngine(t, rule, map[string]Notifier{"email": email}, dir)

	now := time.Now()
	for i := 0; i < 3; i++ {
		_ = e.Observe(context.Background(), blockEvent("alice", now))
	}
	got := email.to[0]
	want := []string{"security@corp.example", "mona@corp.example", "alice@corp.example"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("recipients = %v, want %v", got, want)
	}

	// An LDAP manager attribute is a DN rather than an address, so it is
	// skipped rather than handed to the relay.
	dnDir := identity.StaticDirectory{"bob": {"bob@corp.example", "CN=Mona,OU=Users,DC=corp"}}
	email2 := &recorder{name: "email"}
	e2, _ := testEngine(t, rule, map[string]Notifier{"email": email2}, dnDir)
	for i := 0; i < 3; i++ {
		_ = e2.Observe(context.Background(), blockEvent("bob", now))
	}
	for _, addr := range email2.to[0] {
		if strings.HasPrefix(addr, "CN=") {
			t.Fatalf("a distinguished name was used as an address: %v", email2.to[0])
		}
	}
}

func TestNotifierFailureStillRecordsTheAlert(t *testing.T) {
	failing := &recorder{name: "email", fail: context.DeadlineExceeded}
	e, store := testEngine(t, defaultRule(), map[string]Notifier{"email": failing}, nil)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if err := e.Observe(context.Background(), blockEvent("alice", now)); err != nil {
			t.Fatal(err)
		}
	}
	alerts := store.Alerts()
	if len(alerts) != 1 {
		t.Fatalf("the alert should still be recorded, got %d", len(alerts))
	}
	if len(alerts[0].NotifyErrs) != 1 || len(alerts[0].Notified) != 0 {
		t.Fatalf("the delivery failure should be recorded on the alert: %+v", alerts[0])
	}
}

func TestWebhookNotifier(t *testing.T) {
	var gotSig, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody, gotSig = string(body), r.Header.Get("X-AIGatekeeper-Signature")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n, err := NewWebhookNotifier("soc", srv.URL, "shhh", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	a := Alert{RuleID: "repeat-offender", User: "alice", Count: 3}
	if err := n.Send(context.Background(), a, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotBody, `"aigatekeeper.alert"`) || !strings.Contains(gotBody, `"user":"alice"`) {
		t.Fatalf("payload: %s", gotBody)
	}
	if !strings.HasPrefix(gotSig, "sha256=") || len(gotSig) != 71 {
		t.Fatalf("signature: %q", gotSig)
	}
	if n.Name() != "webhook:soc" {
		t.Errorf("name = %q", n.Name())
	}

	// A 4xx is not retried; a 5xx is.
	var attempts int
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()
	nf, _ := NewWebhookNotifier("soc", failing.URL, "", 500*time.Millisecond)
	if err := nf.Send(context.Background(), a, nil); err == nil {
		t.Error("expected an error after retries")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts for a 5xx, got %d", attempts)
	}
}

func TestEmailNotifierRendersMessage(t *testing.T) {
	var to []string
	var msg string
	n, err := NewEmailNotifier(EmailConfig{Host: "smtp.corp.example", From: "aigk@corp.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	n.send = func(_ EmailConfig, recipients []string, m []byte) error {
		to, msg = recipients, string(m)
		return nil
	}
	a := Alert{
		Time: time.Now(), RuleID: "repeat-offender", User: "alice", Device: "laptop-alice", Count: 3,
		Window: "24h0m0s", Severity: "critical", Services: []string{"openai"}, Detectors: []string{"aws_access_key"},
		Events: []Event{{Time: time.Now(), Service: "openai", Host: "api.openai.com", Path: "/v1/chat/completions",
			Action: "block", Detectors: []string{"aws_access_key"}, Previews: []string{"AKIA****EY"}}},
	}
	if err := n.Send(context.Background(), a, []string{"security@corp.example"}); err != nil {
		t.Fatal(err)
	}
	if len(to) != 1 || to[0] != "security@corp.example" {
		t.Fatalf("recipients: %v", to)
	}
	for _, want := range []string{
		"Subject: AIGatekeeper: 3 blocked prompts from alice",
		"From: aigk@corp.example",
		"Auto-Submitted: auto-generated",
		"Rule:      repeat-offender",
		"aws_access_key",
		"AKIA****EY",
		"Matched values are masked",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
	if !strings.Contains(msg, "\r\n") {
		t.Error("SMTP messages need CRLF line endings")
	}
	// No recipients is a no-op rather than an error.
	if err := n.Send(context.Background(), a, nil); err != nil {
		t.Errorf("empty recipients should be a no-op: %v", err)
	}
}

func TestSendTestOverridesRecipients(t *testing.T) {
	email := &recorder{name: "email"}
	rule := defaultRule()
	e, _ := testEngine(t, rule, map[string]Notifier{"email": email}, nil)
	results := e.SendTest(context.Background(), rule, Alert{RuleID: rule.ID, User: "sample"}, []string{"me@corp.example"})
	if len(results) != 1 || results[0].Error != "" || results[0].Recipients[0] != "me@corp.example" {
		t.Fatalf("results: %+v", results)
	}
	if email.count() != 1 {
		t.Fatal("the test alert was not delivered")
	}
	// A missing notifier is reported rather than silently skipped.
	missing := Rule{ID: "x", Notify: []Target{{Type: "webhook", Webhook: "nope"}}}
	results = e.SendTest(context.Background(), missing, Alert{}, nil)
	if len(results) != 1 || results[0].Error == "" {
		t.Fatalf("expected a reported failure, got %+v", results)
	}
}

func TestEngineAsAuditSink(t *testing.T) {
	email := &recorder{name: "email"}
	e, _ := testEngine(t, defaultRule(), map[string]Notifier{"email": email}, nil)
	d := audit.NewDispatcher()
	d.Add("alerts", e, audit.SinkOptions{Queue: 16, Overflow: audit.OverflowBlock})
	now := time.Now()
	for i := 0; i < 3; i++ {
		d.Log(blockEvent("alice", now))
	}
	if err := d.Close(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	if email.count() != 1 {
		t.Fatalf("expected the engine to raise through the dispatcher, got %d", email.count())
	}
}
