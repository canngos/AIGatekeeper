package policy

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/canngos/aigatekeeper/internal/config"
	"github.com/canngos/aigatekeeper/internal/parser"
)

const testConfig = `
version: 1
services:
  - name: openai
    hosts: ['^api\.openai\.com$']
    extractor: openai
    block_mode: synthetic
    passthrough_paths: ['^/v1/models$']
    rules: [secrets, internal, pii_monitor]
  - name: quiet
    hosts: ['^quiet\.example$']
    extractor: generic
    rules: []
rules:
  - { id: secrets, severity: critical, action: block, detectors: [aws_access_key, github_token] }
  - id: internal
    severity: medium
    action: monitor
    keywords: { file: keywords.txt, case_insensitive: true, word_boundary: true }
    regex: [{ id: codename, pattern: '(?i)\bproject[- ]?orion\b' }]
  - { id: pii_monitor, severity: high, detectors: [credit_card] }
allowlist:
  values: [AKIAIOSFODNN7ALLOWED]
  client_cidrs: ["10.0.0.0/8"]
  header_bypass: { name: X-AIGK-Bypass, token: "s3cret" }
  segment_paths: ['/tools/*/input_schema/**']
`

func compileTest(t *testing.T, yaml string, mutate func(*config.Config)) *Policy {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keywords.txt"), []byte("# comment\nProject Falcon\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetBaseDir(dir)
	if mutate != nil {
		mutate(cfg)
	}
	p, err := Compile(cfg, "h")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func ex(texts ...string) *parser.Extraction {
	e := &parser.Extraction{Extractor: "test"}
	for i, t := range texts {
		e.Segments = append(e.Segments, parser.Segment{Path: "/messages/" + string(rune('0'+i)) + "/content", Role: parser.RoleUser, Text: t})
	}
	return e
}

func TestCompileErrors(t *testing.T) {
	cfg, _ := config.Parse([]byte(`
version: 1
services: [{ name: a, hosts: ['^a$'], extractor: openai, rules: [r] }]
rules: [{ id: r, severity: high, detectors: [not_a_detector] }]
`))
	if _, err := Compile(cfg, ""); err == nil {
		t.Error("expected unknown detector to fail compilation")
	}
	cfg, _ = config.Parse([]byte(`
version: 1
services: [{ name: a, hosts: ['^a$'], extractor: openai, rules: [r] }]
rules: [{ id: r, severity: high, keywords: { file: /nonexistent/keywords.txt } }]
`))
	if _, err := Compile(cfg, ""); err == nil {
		t.Error("expected missing keyword file to fail compilation")
	}
}

func TestEvaluateDecisions(t *testing.T) {
	p := compileTest(t, testConfig, nil)
	svc := p.ServiceByName("openai")
	if svc == nil || len(svc.Rules) != 3 || svc.RuleIDs()[0] != "secrets" {
		t.Fatalf("service not compiled: %+v", svc)
	}
	ctx := context.Background()
	key := "AKIAIOSFODNN7REALKEY"

	cases := []struct {
		name      string
		in        Input
		action    string
		rule      string
		reason    string
		nFindings int
		detectors []string
	}{
		{name: "no service", in: Input{Extraction: ex(key)}, action: ActionAllow},
		{name: "passthrough", in: Input{Service: svc, Passthrough: true, Extraction: ex(key)}, action: ActionAllow, reason: ReasonPassthrough},
		{name: "client cidr bypass", in: Input{Service: svc, ClientIP: net.ParseIP("10.1.2.3"), Extraction: ex(key)}, action: ActionAllow, reason: ReasonClientCIDR},
		{name: "header bypass", in: Input{Service: svc, BypassToken: "s3cret", Extraction: ex(key)}, action: ActionAllow, reason: ReasonHeader},
		{name: "wrong header token", in: Input{Service: svc, BypassToken: "nope", Extraction: ex(key)}, action: ActionBlock, rule: "secrets", reason: ReasonDLP, nFindings: 1},
		{name: "oversize blocks by default", in: Input{Service: svc, Oversize: true}, action: ActionBlock, reason: ReasonOversize},
		{name: "parse error allows by default", in: Input{Service: svc, ParseErr: errors.New("bad json")}, action: ActionAllow, reason: ReasonParseError},
		{name: "clean prompt", in: Input{Service: svc, Extraction: ex("hello world")}, action: ActionAllow},
		{name: "secret blocks", in: Input{Service: svc, Extraction: ex("key " + key)}, action: ActionBlock, rule: "secrets", reason: ReasonDLP, nFindings: 1, detectors: []string{"aws_access_key"}},
		{name: "allowlisted value", in: Input{Service: svc, Extraction: ex("AKIAIOSFODNN7ALLOWED")}, action: ActionAllow},
		{name: "keyword monitors", in: Input{Service: svc, Extraction: ex("we discussed project falcon")}, action: ActionMonitor, rule: "internal", reason: ReasonDLP, nFindings: 1, detectors: []string{"internal"}},
		{name: "regex monitors", in: Input{Service: svc, Extraction: ex("Project-Orion launch")}, action: ActionMonitor, rule: "internal", nFindings: 1, detectors: []string{"codename"}},
		{name: "rule without action uses default block", in: Input{Service: svc, Extraction: ex("card 4111111111111111")}, action: ActionBlock, rule: "pii_monitor", nFindings: 1},
		{name: "block outranks monitor", in: Input{Service: svc, Extraction: ex("project falcon " + key)}, action: ActionBlock, rule: "secrets", nFindings: 2, detectors: []string{"aws_access_key", "internal"}},
		{name: "segment path skipped", in: Input{Service: svc, Extraction: &parser.Extraction{Segments: []parser.Segment{{Path: "/tools/0/input_schema/properties/x", Text: key}}}}, action: ActionAllow},
		{name: "service without rules", in: Input{Service: p.ServiceByName("quiet"), Extraction: ex(key)}, action: ActionAllow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := p.Evaluate(ctx, tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if d.Action != tc.action {
				t.Errorf("action = %s, want %s (%+v)", d.Action, tc.action, d)
			}
			if tc.rule != "" && d.Rule != tc.rule {
				t.Errorf("rule = %s, want %s", d.Rule, tc.rule)
			}
			if tc.reason != "" && d.Reason != tc.reason {
				t.Errorf("reason = %s, want %s", d.Reason, tc.reason)
			}
			if tc.nFindings > 0 && len(d.Findings) != tc.nFindings {
				t.Errorf("findings = %d, want %d: %+v", len(d.Findings), tc.nFindings, d.Findings)
			}
			if tc.detectors != nil {
				got := map[string]bool{}
				for _, id := range d.Detectors {
					got[id] = true
				}
				for _, want := range tc.detectors {
					if !got[want] {
						t.Errorf("detector %s missing from %v", want, d.Detectors)
					}
				}
			}
			if tc.in.Service != nil && d.BlockMode != tc.in.Service.BlockMode {
				t.Errorf("block mode not propagated")
			}
			for _, f := range d.Summaries() {
				if f.Preview == key {
					t.Error("summary leaks raw value")
				}
			}
		})
	}
}

func TestMonitorModeDowngradesBlocks(t *testing.T) {
	p := compileTest(t, testConfig, func(c *config.Config) { c.Mode.Monitor = true })
	svc := p.ServiceByName("openai")
	d, _ := p.Evaluate(context.Background(), Input{Service: svc, Extraction: ex("AKIAIOSFODNN7REALKEY")})
	if d.Action != ActionMonitor || d.Reason != ReasonMonitorMode || d.Rule != "secrets" {
		t.Fatalf("expected monitor-mode downgrade, got %+v", d)
	}
	d, _ = p.Evaluate(context.Background(), Input{Service: svc, Oversize: true})
	if d.Action != ActionMonitor {
		t.Fatalf("oversize should be downgraded in monitor mode, got %+v", d)
	}
}

func TestOversizeAndParseErrorActionsConfigurable(t *testing.T) {
	p := compileTest(t, testConfig, func(c *config.Config) {
		c.Limits.OversizeAction = config.ActionAllow
		c.Limits.ParseErrorAction = config.ActionBlock
	})
	svc := p.ServiceByName("openai")
	if d, _ := p.Evaluate(context.Background(), Input{Service: svc, Oversize: true}); d.Action != ActionAllow {
		t.Errorf("oversize allow not honoured: %+v", d)
	}
	if d, _ := p.Evaluate(context.Background(), Input{Service: svc, ParseErr: errors.New("x")}); d.Action != ActionBlock {
		t.Errorf("parse error block not honoured: %+v", d)
	}
}

func TestMatchSegmentGlob(t *testing.T) {
	cases := []struct {
		glob, path string
		want       bool
	}{
		{"/tools/*/input_schema/**", "/tools/0/input_schema/properties/x", true},
		{"/tools/*/input_schema/**", "/tools/0/input_schema", true},
		{"/tools/*/input_schema/**", "/tools/0/description", false},
		{"/messages/*/content", "/messages/3/content", true},
		{"/messages/*/content", "/messages/3/content/0/text", false},
		{"/**", "/anything/at/all", true},
		{"/system", "/system", true},
		{"/system", "/systemx", false},
	}
	for _, c := range cases {
		if got := MatchSegmentGlob(c.glob, c.path); got != c.want {
			t.Errorf("MatchSegmentGlob(%q, %q) = %v, want %v", c.glob, c.path, got, c.want)
		}
	}
}

func TestStoreSwap(t *testing.T) {
	p1 := compileTest(t, testConfig, nil)
	p2 := compileTest(t, testConfig, func(c *config.Config) { c.TunnelUnmatched = false })
	s := NewStore(p1)
	if !s.TunnelUnmatched() || !s.Intercept("api.openai.com") || s.Intercept("github.com") {
		t.Fatal("store does not reflect initial policy")
	}
	if old := s.Swap(p2); old != p1 {
		t.Fatal("swap did not return previous policy")
	}
	if s.TunnelUnmatched() {
		t.Fatal("store does not reflect swapped policy")
	}
}
