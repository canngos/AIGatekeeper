package proxy_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/canngos/aigatekeeper/internal/action"
	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/config"
	"github.com/canngos/aigatekeeper/internal/parser"
	"github.com/canngos/aigatekeeper/internal/policy"
	"github.com/canngos/aigatekeeper/internal/proxy"
)

const enforceConfig = `
version: 1
block_message: "Blocked by {rule}: {detectors} [{request_id}]"
services:
  - name: openai
    hosts: ['^127\.0\.0\.1$']
    extractor: openai
    block_mode: %s
    rules: [secrets, internal]
rules:
  - { id: secrets, severity: critical, action: block, detectors: [aws_access_key] }
  - { id: internal, severity: low, action: monitor, keywords: { list: ["project falcon"], case_insensitive: true } }
allowlist:
  header_bypass: { name: X-AIGK-Bypass, token: "let-me-through" }
`

type enforceHarness struct {
	srv      *httptest.Server
	rec      *audit.Recorder
	upstream *atomic.Int32
	lastHdr  http.Header
}

func newEnforceHarness(t *testing.T, blockMode string, mutate func(*config.Config)) *enforceHarness {
	t.Helper()
	cfg, err := config.Parse([]byte(strings.Replace(enforceConfig, "%s", blockMode, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(cfg)
	}
	pol, err := policy.Compile(cfg, "t")
	if err != nil {
		t.Fatal(err)
	}
	store := policy.NewStore(pol)
	h := &enforceHarness{rec: &audit.Recorder{}, upstream: &atomic.Int32{}}
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.upstream.Add(1)
		h.lastHdr = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	})
	chain := proxy.Chain(final,
		proxy.Audited(h.rec, true),
		proxy.Route(store),
		proxy.ReadBody(proxy.BodyLimits{MaxBodyBytes: 1024, MaxDecodedBytes: 4096}),
		proxy.Parse(parser.Default()),
		proxy.Enforce(store),
	)
	h.srv = httptest.NewServer(chain)
	t.Cleanup(h.srv.Close)
	return h
}

func (h *enforceHarness) post(t *testing.T, path, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (h *enforceHarness) lastEvent(t *testing.T) audit.Event {
	t.Helper()
	evs := h.rec.Events()
	if len(evs) == 0 {
		t.Fatal("no audit events")
	}
	return evs[len(evs)-1]
}

const secretBody = `{"model":"gpt-4o","messages":[{"role":"user","content":"AKIAIOSFODNN7REALKEY"}]}`
const secretStreamBody = `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"AKIAIOSFODNN7REALKEY"}]}`

func TestEnforceRejectsSecretWithoutContactingUpstream(t *testing.T) {
	h := newEnforceHarness(t, "reject", nil)
	resp := h.post(t, "/v1/chat/completions", secretBody, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if resp.Header.Get(action.BlockedHeader) != "secrets" {
		t.Fatal("missing blocked header")
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	msg := body["error"].(map[string]any)["message"].(string)
	if !strings.Contains(msg, "Blocked by secrets: aws_access_key [") {
		t.Fatalf("message = %q", msg)
	}
	if h.upstream.Load() != 0 {
		t.Fatal("upstream must not be contacted for a blocked request")
	}
	ev := h.lastEvent(t)
	if ev.Action != audit.ActionBlock || ev.Rule != "secrets" || ev.Reason != "dlp" || ev.BlockMode != "reject" ||
		len(ev.Findings) != 1 || ev.Findings[0].Detector != "aws_access_key" || ev.UpstreamStatus != http.StatusForbidden {
		t.Fatalf("unexpected audit event: %+v", ev)
	}
	if strings.Contains(ev.Findings[0].Preview, "AKIAIOSFODNN7REALKEY") {
		t.Fatal("audit preview leaks the secret")
	}
	if !strings.Contains(msg, ev.RequestID) {
		t.Fatal("block message should reference the audit request id")
	}
}

func TestEnforceSyntheticStreamingReply(t *testing.T) {
	h := newEnforceHarness(t, "synthetic", nil)
	resp := h.post(t, "/v1/chat/completions", secretStreamBody, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("status %d content-type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	if !strings.HasSuffix(strings.TrimSpace(buf.String()), "data: [DONE]") || !strings.Contains(buf.String(), "Blocked by secrets") {
		t.Fatalf("unexpected stream: %s", buf.String())
	}
	if h.upstream.Load() != 0 {
		t.Fatal("upstream must not be contacted")
	}
	ev := h.lastEvent(t)
	if ev.Action != audit.ActionBlock || !ev.Stream || ev.Model != "gpt-4o" || ev.BlockMode != "synthetic" {
		t.Fatalf("unexpected audit event: %+v", ev)
	}
}

func TestEnforceMonitorForwardsAndAudits(t *testing.T) {
	h := newEnforceHarness(t, "reject", nil)
	resp := h.post(t, "/v1/chat/completions", `{"messages":[{"role":"user","content":"about Project Falcon"}]}`, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || h.upstream.Load() != 1 {
		t.Fatalf("monitor rule must forward: status %d upstream %d", resp.StatusCode, h.upstream.Load())
	}
	ev := h.lastEvent(t)
	if ev.Action != audit.ActionMonitor || ev.Rule != "internal" || len(ev.Findings) != 1 {
		t.Fatalf("unexpected audit event: %+v", ev)
	}
}

func TestEnforceGlobalMonitorMode(t *testing.T) {
	h := newEnforceHarness(t, "reject", func(c *config.Config) { c.Mode.Monitor = true })
	resp := h.post(t, "/v1/chat/completions", secretBody, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || h.upstream.Load() != 1 {
		t.Fatalf("monitor mode must forward: status %d", resp.StatusCode)
	}
	ev := h.lastEvent(t)
	if ev.Action != audit.ActionMonitor || ev.Reason != "monitor_mode" || ev.Rule != "secrets" {
		t.Fatalf("unexpected audit event: %+v", ev)
	}
}

func TestEnforceBypassHeaderIsHonouredAndStripped(t *testing.T) {
	h := newEnforceHarness(t, "reject", nil)
	resp := h.post(t, "/v1/chat/completions", secretBody, map[string]string{"X-AIGK-Bypass": "let-me-through"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("bypass not honoured: %d", resp.StatusCode)
	}
	if h.lastHdr.Get("X-AIGK-Bypass") != "" {
		t.Fatal("bypass header leaked upstream")
	}
	if ev := h.lastEvent(t); ev.Reason != "allowlist_header" || ev.Action != audit.ActionAllow {
		t.Fatalf("unexpected audit event: %+v", ev)
	}
	resp = h.post(t, "/v1/chat/completions", secretBody, map[string]string{"X-AIGK-Bypass": "wrong"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatal("wrong bypass token must not bypass")
	}
}

func TestEnforceOversizeBlocks(t *testing.T) {
	h := newEnforceHarness(t, "reject", nil)
	big := `{"messages":[{"role":"user","content":"` + strings.Repeat("a", 2000) + `"}]}`
	resp := h.post(t, "/v1/chat/completions", big, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || h.upstream.Load() != 0 {
		t.Fatalf("oversize should block by default: %d", resp.StatusCode)
	}
	if ev := h.lastEvent(t); ev.Reason != "oversize" || ev.Action != audit.ActionBlock {
		t.Fatalf("unexpected audit event: %+v", ev)
	}
}

func TestEnforceCleanRequestPasses(t *testing.T) {
	h := newEnforceHarness(t, "reject", nil)
	resp := h.post(t, "/v1/chat/completions", `{"messages":[{"role":"user","content":"hi"}]}`, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || h.upstream.Load() != 1 {
		t.Fatalf("clean request should pass: %d", resp.StatusCode)
	}
	if ev := h.lastEvent(t); ev.Action != audit.ActionAllow || len(ev.Findings) != 0 {
		t.Fatalf("unexpected audit event: %+v", ev)
	}
}
