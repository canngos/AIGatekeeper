package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/canngos/aigatekeeper/internal/config"
	"github.com/canngos/aigatekeeper/internal/parser"
)

// A deployment knows key formats nobody else does: an internal gateway's
// tokens, a national identity number. Those go in as patterns alongside the
// built-in detectors, and each may rank itself.
func TestCustomPatternsDetectAndRankThemselves(t *testing.T) {
	cfg, err := config.Parse([]byte(`
version: 1
services:
  - name: openai
    hosts: ['^api\.openai\.com$']
    extractor: openai
    rules: [secrets]
rules:
  - id: secrets
    severity: medium
    action: block
    regex:
      - id: corp_gateway_key
        pattern: '\bCORPKEY-[A-Z0-9]{24}\b'
        severity: critical
        group: Keys and tokens
      - id: staff_number
        pattern: '\bSTAFF-[0-9]{6}\b'
        group: Personal data
      - id: too_short_to_matter
        pattern: '\bREF-[0-9]+\b'
        min_length: 12
`))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := Compile(cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	rule := pol.Rules["secrets"]
	ex := &parser.Extraction{Segments: []parser.Segment{{
		Path: "/messages/0/content", Role: parser.RoleUser,
		Text: "CORPKEY-ABCDEFGH01234567IJKLMNOP and STAFF-004217 and REF-99",
	}}}
	findings, err := rule.Scanner.Scan(context.Background(), ex)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, f := range findings {
		got[f.Detector] = f.Severity
		if f.Preview == "" {
			t.Errorf("%s reported no masked preview", f.Detector)
		}
	}
	if got["corp_gateway_key"] != "critical" {
		t.Errorf("a pattern that ranks itself keeps its own severity, got %q", got["corp_gateway_key"])
	}
	if got["staff_number"] != "medium" {
		t.Errorf("a pattern that does not takes the rule's, got %q", got["staff_number"])
	}
	if _, found := got["too_short_to_matter"]; found {
		t.Error("REF-99 is shorter than min_length and should not be reported")
	}
}

func TestCustomPatternProblemsAreReportedWithTheirPath(t *testing.T) {
	_, err := config.Parse([]byte(`
version: 1
rules:
  - id: secrets
    severity: medium
    regex:
      - { id: broken, pattern: '[' }
      - { id: broken, pattern: 'ok' }
      - { id: bad_rank, pattern: 'ok', severity: urgent }
      - { pattern: 'ok' }
`))
	if err == nil {
		t.Fatal("expected the problems to be reported")
	}
	msg := err.Error()
	for _, want := range []string{
		"rules[0].regex[0].pattern",
		"rules[0].regex[1].id",
		"rules[0].regex[2].severity",
		"rules[0].regex[3].id",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("expected %q in:\n%s", want, msg)
		}
	}
}
