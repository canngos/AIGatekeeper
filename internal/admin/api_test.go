package admin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/policy"
	"github.com/canngos/aigatekeeper/internal/reload"
)

const adminTestConfig = `version: 1
services:
  - {name: openai, hosts: ['^api\.openai\.com$'], extractor: openai, block_mode: reject, rules: [secrets]}
rules:
  - {id: secrets, severity: critical, action: block, detectors: [aws_access_key]}
`

const testPassword = "correct horse battery"
const testToken = "0123456789abcdef0123456789abcdef"

type apiHarness struct {
	srv     *httptest.Server
	client  *http.Client
	manager *reload.Manager
	history *audit.SQLiteStore
	events  *audit.Dispatcher
	cfgPath string
	csrf    string
}

func newAPIHarness(t *testing.T, withAuth bool, withHistory bool) *apiHarness {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "aigatekeeper.yaml")
	if err := os.WriteFile(cfgPath, []byte(adminTestConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := reload.NewManager(cfgPath, policy.NewStore(nil), audit.Discard, quiet)
	if _, err := m.Load(context.Background()); err != nil {
		t.Fatal(err)
	}

	h := &apiHarness{manager: m, cfgPath: cfgPath, events: audit.NewDispatcher()}
	opts := Options{
		Version: "test", Manager: m, Events: h.events, Logger: quiet,
		Listeners: map[string]string{"forward": "127.0.0.1:8080"},
		Reload: func(ctx context.Context) (bool, string, error) {
			l, changed, err := m.ReloadFromDisk(ctx, "admin")
			v := ""
			if l != nil {
				v = l.Hash
			}
			return changed, v, err
		},
	}
	if withAuth {
		hash, err := HashPassword(testPassword)
		if err != nil {
			t.Fatal(err)
		}
		opts.Auth = AuthConfig{PasswordHash: hash, Token: testToken, SessionTTL: time.Hour}
	}
	if withHistory {
		store, err := audit.OpenSQLite(filepath.Join(dir, "audit.db"), audit.SQLiteOptions{})
		if err != nil {
			t.Fatal(err)
		}
		h.history = store
		opts.History = store
		t.Cleanup(func() { store.Close() })
	}
	h.srv = httptest.NewServer(New(opts).Handler())
	t.Cleanup(h.srv.Close)
	jar, _ := cookiejar.New(nil)
	h.client = &http.Client{Jar: jar, Timeout: 10 * time.Second}
	return h
}

func (h *apiHarness) do(t *testing.T, method, path string, body any, hdr map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && h.csrf != "" {
		req.Header.Set(csrfHeader, h.csrf)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &m)
	return resp, m
}

func (h *apiHarness) login(t *testing.T) {
	t.Helper()
	resp, m := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": testPassword}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %d %v", resp.StatusCode, m)
	}
	h.csrf, _ = m["csrf_token"].(string)
	if h.csrf == "" {
		t.Fatal("login did not return a CSRF token")
	}
}

func TestAuthLoginSessionAndCSRF(t *testing.T) {
	h := newAPIHarness(t, true, false)

	if resp, _ := h.do(t, http.MethodGet, "/api/v1/status", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status should be 401, got %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": "wrong"}, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password should be 401, got %d", resp.StatusCode)
	}

	resp, m := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": testPassword}, nil)
	if resp.StatusCode != http.StatusOK || m["authenticated"] != true {
		t.Fatalf("login: %d %v", resp.StatusCode, m)
	}
	var sessionCookieSet, csrfCookieSet bool
	for _, c := range resp.Cookies() {
		switch c.Name {
		case sessionCookie:
			sessionCookieSet = true
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				t.Errorf("session cookie must be HttpOnly and SameSite=Strict: %+v", c)
			}
		case csrfCookie:
			csrfCookieSet = true
			if c.HttpOnly {
				t.Error("CSRF cookie must be readable by the page")
			}
		}
	}
	if !sessionCookieSet || !csrfCookieSet {
		t.Fatal("login must set both cookies")
	}
	h.csrf, _ = m["csrf_token"].(string)

	if resp, _ := h.do(t, http.MethodGet, "/api/v1/status", nil, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated status should be 200, got %d", resp.StatusCode)
	}
	// A cookie-authenticated POST without the CSRF header is refused.
	saved := h.csrf
	h.csrf = ""
	if resp, _ := h.do(t, http.MethodPost, "/api/v1/reload", nil, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF header should be 403, got %d", resp.StatusCode)
	}
	h.csrf = saved
	if resp, _ := h.do(t, http.MethodPost, "/api/v1/reload", nil, map[string]string{"Sec-Fetch-Site": "cross-site"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site request should be 403, got %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, http.MethodPost, "/api/v1/reload", nil, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("reload with CSRF should succeed, got %d", resp.StatusCode)
	}

	_, me := h.do(t, http.MethodGet, "/api/v1/auth/me", nil, nil)
	if me["authenticated"] != true || me["method"] != "session" {
		t.Fatalf("me: %v", me)
	}
	if resp, _ := h.do(t, http.MethodPost, "/api/v1/auth/logout", nil, nil); resp.StatusCode != http.StatusOK {
		t.Fatal("logout failed")
	}
	if resp, _ := h.do(t, http.MethodGet, "/api/v1/status", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session should be invalid after logout, got %d", resp.StatusCode)
	}
}

func TestAuthBearerTokenSkipsCSRF(t *testing.T) {
	h := newAPIHarness(t, true, false)
	hdr := map[string]string{"Authorization": "Bearer " + testToken}
	if resp, _ := h.do(t, http.MethodGet, "/api/v1/status", nil, hdr); resp.StatusCode != http.StatusOK {
		t.Fatalf("bearer GET: %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, http.MethodPost, "/api/v1/reload", nil, hdr); resp.StatusCode != http.StatusOK {
		t.Fatalf("bearer POST without CSRF should work: %d", resp.StatusCode)
	}
	bad := map[string]string{"Authorization": "Bearer wrong-token-value-here"}
	if resp, _ := h.do(t, http.MethodGet, "/api/v1/status", nil, bad); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad bearer token: %d", resp.StatusCode)
	}
}

func TestAuthLoginRateLimit(t *testing.T) {
	h := newAPIHarness(t, true, false)
	var limited bool
	for i := 0; i < 8; i++ {
		resp, _ := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{"password": "wrong"}, nil)
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("expected login attempts to be rate limited")
	}
}

func TestAPIDisabledWithoutCredential(t *testing.T) {
	h := newAPIHarness(t, false, false)
	resp, m := h.do(t, http.MethodGet, "/api/v1/status", nil, nil)
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(m["hint"].(string), "hash-password") {
		t.Fatalf("expected 503 with setup hint, got %d %v", resp.StatusCode, m)
	}
	// Operational endpoints stay reachable so a loopback deployment still works.
	if resp, _ := h.do(t, http.MethodGet, "/-/policy", nil, nil); resp.StatusCode == http.StatusUnauthorized {
		t.Fatal("operational endpoints should not require auth when none is configured")
	}
	if resp, _ := h.do(t, http.MethodGet, "/healthz", nil, nil); resp.StatusCode != http.StatusOK {
		t.Fatal("healthz must stay open")
	}
}

func TestConfigGetValidateApply(t *testing.T) {
	h := newAPIHarness(t, true, false)
	h.login(t)

	resp, m := h.do(t, http.MethodGet, "/api/v1/config", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(m["yaml"].(string), "aws_access_key") {
		t.Fatalf("get config: %d %v", resp.StatusCode, m)
	}
	version := m["version"].(string)
	if m["config"] == nil {
		t.Fatal("get config should include the parsed document")
	}

	// Validation reports every problem with its path.
	_, v := h.do(t, http.MethodPost, "/api/v1/config/validate", map[string]string{
		"yaml": "version: 1\nservices: [{name: a, hosts: ['('], extractor: openai, block_mode: nope, rules: [missing]}]\n"}, nil)
	if v["ok"] != false {
		t.Fatalf("expected invalid: %v", v)
	}
	problems, _ := json.Marshal(v["errors"])
	for _, want := range []string{"services[0].hosts[0]", "services[0].block_mode", "services[0].rules[0]"} {
		if !strings.Contains(string(problems), want) {
			t.Errorf("missing problem %s in %s", want, problems)
		}
	}

	// A stale base version is refused.
	good := strings.Replace(adminTestConfig, "block_mode: reject", "block_mode: synthetic", 1)
	if resp, _ := h.do(t, http.MethodPost, "/api/v1/config/apply", map[string]string{"yaml": good, "base_version": "stale"}, nil); resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale apply should be 409, got %d", resp.StatusCode)
	}
	// Applying writes the file and swaps the policy.
	resp, applied := h.do(t, http.MethodPost, "/api/v1/config/apply", map[string]string{"yaml": good, "base_version": version}, nil)
	if resp.StatusCode != http.StatusOK || applied["applied"] != true {
		t.Fatalf("apply: %d %v", resp.StatusCode, applied)
	}
	onDisk, _ := os.ReadFile(h.cfgPath)
	if string(onDisk) != good {
		t.Fatal("apply did not write the configuration file")
	}
	if svc := h.manager.Store().Load().ServiceByName("openai"); svc.BlockMode != "synthetic" {
		t.Fatalf("policy not swapped: %+v", svc)
	}
	// The watcher's follow-up read is a no-op because the hash matches.
	if _, changed, err := h.manager.ReloadFromDisk(context.Background(), "file"); err != nil || changed {
		t.Fatal("reload after apply must not re-apply")
	}
	// Invalid apply is refused with problems and leaves the file alone.
	if resp, _ := h.do(t, http.MethodPost, "/api/v1/config/apply", map[string]string{"yaml": "version: 9\n"}, nil); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("invalid apply should be 422, got %d", resp.StatusCode)
	}
	after, _ := os.ReadFile(h.cfgPath)
	if string(after) != good {
		t.Fatal("failed apply must not modify the file")
	}
}

func TestConfigApplyFromFormDocument(t *testing.T) {
	h := newAPIHarness(t, true, false)
	h.login(t)
	_, cfg := h.do(t, http.MethodGet, "/api/v1/config", nil, nil)
	doc := cfg["config"].(map[string]any)
	doc["mode"] = map[string]any{"monitor": true}

	resp, m := h.do(t, http.MethodPost, "/api/v1/config/validate", map[string]any{"config": doc}, nil)
	if resp.StatusCode != http.StatusOK || m["ok"] != true || !strings.Contains(m["yaml"].(string), "monitor: true") {
		t.Fatalf("validate from document: %d %v", resp.StatusCode, m)
	}
	resp, _ = h.do(t, http.MethodPost, "/api/v1/config/apply", map[string]any{"config": doc, "base_version": cfg["version"]}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("apply from document: %d", resp.StatusCode)
	}
	if !h.manager.Store().Load().Monitor {
		t.Fatal("monitor mode not applied")
	}

	// The file an operator reads and diffs must stay in schema order and
	// must not spell out every empty default. Marshalling the form's
	// generic document directly would sort keys alphabetically instead.
	written, err := os.ReadFile(h.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(written)
	if !strings.HasPrefix(text, "version:") {
		t.Errorf("applied file should start with version, got:\n%s", text)
	}
	if strings.Index(text, "\nservices:") > strings.Index(text, "\nrules:") {
		t.Error("applied file should keep services before rules (schema order, not alphabetical)")
	}
	for _, clutter := range []string{"passthrough_paths: []", "options: {}", "regex: []", `upstream_proxy: ""`} {
		if strings.Contains(text, clutter) {
			t.Errorf("applied file should omit empty defaults, found %q in:\n%s", clutter, text)
		}
	}
	// Booleans that default to true must still be written explicitly, or
	// omitting a false would read back as true on the next load.
	if !strings.Contains(text, "tunnel_unmatched:") {
		t.Error("tunnel_unmatched must always be written explicitly")
	}
}

func TestApplyRoundTripPreservesFalseDefaults(t *testing.T) {
	h := newAPIHarness(t, true, false)
	h.login(t)
	_, cfg := h.do(t, http.MethodGet, "/api/v1/config", nil, nil)
	doc := cfg["config"].(map[string]any)
	// Turning off a setting whose default is true must survive the round trip.
	doc["tunnel_unmatched"] = false
	doc["audit"] = map[string]any{"stdout": false, "log_allowed": false, "include_preview": false}

	resp, _ := h.do(t, http.MethodPost, "/api/v1/config/apply", map[string]any{"config": doc, "base_version": cfg["version"]}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("apply: %d", resp.StatusCode)
	}
	loaded := h.manager.Current().Config
	if loaded.TunnelUnmatched || loaded.Audit.Stdout || loaded.Audit.LogAllowed || loaded.Audit.IncludePreview {
		t.Fatalf("false values were lost in the round trip: %+v", loaded.Audit)
	}
}

func TestTesterEndpoint(t *testing.T) {
	h := newAPIHarness(t, true, false)
	h.login(t)

	_, m := h.do(t, http.MethodPost, "/api/v1/test", map[string]string{"text": "key AKIAIOSFODNN7REALKEY"}, nil)
	dec := m["decision"].(map[string]any)
	if dec["action"] != "block" || dec["rule"] != "secrets" {
		t.Fatalf("expected block: %v", m)
	}
	findings := m["findings"].([]any)
	if len(findings) != 1 || findings[0].(map[string]any)["preview"] == "key AKIAIOSFODNN7REALKEY" {
		t.Fatalf("findings: %v", findings)
	}

	// A full request body is parsed with the service's extractor.
	_, m = h.do(t, http.MethodPost, "/api/v1/test", map[string]string{
		"service": "openai",
		"body":    `{"model":"gpt-4o","messages":[{"role":"user","content":"AKIAIOSFODNN7REALKEY"}]}`}, nil)
	ex := m["extraction"].(map[string]any)
	if ex["model"] != "gpt-4o" || len(ex["segments"].([]any)) != 1 {
		t.Fatalf("extraction: %v", ex)
	}

	// A candidate configuration is evaluated without touching the live policy.
	candidate := strings.Replace(adminTestConfig, "action: block", "action: monitor", 1)
	_, m = h.do(t, http.MethodPost, "/api/v1/test", map[string]string{"text": "AKIAIOSFODNN7REALKEY", "yaml": candidate}, nil)
	if m["decision"].(map[string]any)["action"] != "monitor" {
		t.Fatalf("candidate policy not used: %v", m)
	}
	if live := h.manager.Store().Load(); live.Rules["secrets"].Action != "block" {
		t.Fatal("live policy was modified by the tester")
	}
	// Clean text is allowed.
	_, m = h.do(t, http.MethodPost, "/api/v1/test", map[string]string{"text": "hello world"}, nil)
	if m["decision"].(map[string]any)["action"] != "allow" || len(m["findings"].([]any)) != 0 {
		t.Fatalf("clean text: %v", m)
	}
	// Errors are reported, not panics.
	if resp, _ := h.do(t, http.MethodPost, "/api/v1/test", map[string]string{}, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatal("empty tester request should be 400")
	}
	if resp, _ := h.do(t, http.MethodPost, "/api/v1/test", map[string]string{"text": "x", "yaml": "version: 9"}, nil); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatal("invalid candidate config should be 422")
	}
	if resp, _ := h.do(t, http.MethodPost, "/api/v1/test", map[string]string{"text": "x", "service": "nope"}, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatal("unknown service should be 400")
	}
}

func TestEventsAndStatsEndpoints(t *testing.T) {
	h := newAPIHarness(t, true, true)
	h.login(t)

	now := time.Now()
	for i := 0; i < 25; i++ {
		e := audit.Event{Time: now.Add(-time.Duration(i) * time.Minute), Kind: audit.KindRequest, RequestID: "r", ClientIP: "10.0.0.1",
			Service: "openai", Host: "api.openai.com", Path: "/v1/chat/completions", Action: audit.ActionAllow, UpstreamStatus: 200}
		if i%5 == 0 {
			e.Action = audit.ActionBlock
			e.Rule = "secrets"
			e.Findings = []audit.FindingSummary{{Detector: "aws_access_key", Severity: "critical", Preview: "AKIA****EY"}}
		}
		h.history.Write(e)
	}
	if err := h.history.Flush(); err != nil {
		t.Fatal(err)
	}

	_, m := h.do(t, http.MethodGet, "/api/v1/events?limit=10", nil, nil)
	items := m["items"].([]any)
	if len(items) != 10 || m["next_cursor"] == nil {
		t.Fatalf("events page: %d items, cursor %v", len(items), m["next_cursor"])
	}
	_, m = h.do(t, http.MethodGet, "/api/v1/events?action=block", nil, nil)
	items = m["items"].([]any)
	if len(items) != 5 {
		t.Fatalf("filtered events: %d", len(items))
	}
	first := items[0].(map[string]any)
	id := int64(first["id"].(float64))
	if len(first["findings"].([]any)) != 1 {
		t.Fatalf("findings not attached: %v", first)
	}
	resp, one := h.do(t, http.MethodGet, "/api/v1/events/"+strconv.FormatInt(id, 10), nil, nil)
	if resp.StatusCode != http.StatusOK || one["rule"] != "secrets" {
		t.Fatalf("get event: %d %v", resp.StatusCode, one)
	}
	if resp, _ := h.do(t, http.MethodGet, "/api/v1/events/999999", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatal("missing event should be 404")
	}

	_, sum := h.do(t, http.MethodGet, "/api/v1/stats/summary?range=24h", nil, nil)
	if sum["total"].(float64) != 25 {
		t.Fatalf("summary total: %v", sum["total"])
	}
	_, ts := h.do(t, http.MethodGet, "/api/v1/stats/timeseries?range=1h&group=action", nil, nil)
	if ts["series"] == nil {
		t.Fatalf("timeseries: %v", ts)
	}
	if resp, _ := h.do(t, http.MethodGet, "/api/v1/stats/timeseries?group=nonsense", nil, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatal("invalid group should be 400")
	}
}

func TestEventsUnavailableWithoutHistory(t *testing.T) {
	h := newAPIHarness(t, true, false)
	h.login(t)
	for _, path := range []string{"/api/v1/events", "/api/v1/stats/summary", "/api/v1/stats/timeseries"} {
		if resp, m := h.do(t, http.MethodGet, path, nil, nil); resp.StatusCode != http.StatusServiceUnavailable || m["error"] == nil {
			t.Errorf("%s should report 503 when the history store is off, got %d", path, resp.StatusCode)
		}
	}
	_, status := h.do(t, http.MethodGet, "/api/v1/status", nil, nil)
	if status["history"] != false {
		t.Fatalf("status should report history disabled: %v", status["history"])
	}
}

func TestEventStream(t *testing.T) {
	h := newAPIHarness(t, true, false)
	h.login(t)

	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/v1/events/stream", nil)
	for _, c := range h.client.Jar.Cookies(req.URL) {
		req.AddCookie(c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := h.client.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	br := bufio.NewReader(resp.Body)
	if line, _ := br.ReadString('\n'); !strings.HasPrefix(line, ": connected") {
		t.Fatalf("expected the connected comment first, got %q", line)
	}

	// Give the subscription a moment to register, then emit an event.
	deadline := time.Now().Add(2 * time.Second)
	for h.events.Subscribers() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	h.events.Log(audit.Event{Kind: audit.KindRequest, Service: "openai", Action: audit.ActionBlock, Rule: "secrets"})

	var gotEvent, gotData bool
	for i := 0; i < 10 && !gotData; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading stream: %v", err)
		}
		switch {
		case strings.HasPrefix(line, "event: audit"):
			gotEvent = true
		case gotEvent && strings.HasPrefix(line, "data: "):
			var e map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &e); err != nil {
				t.Fatalf("event payload: %v", err)
			}
			if e["rule"] != "secrets" || e["action"] != "block" {
				t.Fatalf("unexpected event: %v", e)
			}
			gotData = true
		}
	}
	if !gotData {
		t.Fatal("no audit event arrived on the stream")
	}
}

func TestStaticUIFallback(t *testing.T) {
	h := newAPIHarness(t, true, false)
	resp, _ := h.do(t, http.MethodGet, "/", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("root: %d", resp.StatusCode)
	}
	body := fetchBody(t, h.client, h.srv.URL+"/")
	if !strings.Contains(body, "without the web UI") {
		t.Fatalf("expected the not-built page, got %q", body[:min(len(body), 200)])
	}
	// Unknown API routes stay JSON rather than falling through to the SPA.
	if resp, m := h.do(t, http.MethodGet, "/api/v1/nope", nil, nil); resp.StatusCode != http.StatusNotFound || m["error"] == nil {
		t.Fatalf("unknown API route: %d %v", resp.StatusCode, m)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newAPIHarness(t, true, false)
	resp, _ := h.do(t, http.MethodGet, "/healthz", nil, nil)
	for k, want := range map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "default-src 'self'",
	} {
		if got := resp.Header.Get(k); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func fetchBody(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
