package config

import (
	"strings"
	"testing"
)

// A generic map marshals alphabetically, which would write every access key
// prefix as "length, note, prefix". The file is reviewed by people, so the
// order has to be the one that reads.
func TestDetectorOptionsKeepAReadableKeyOrder(t *testing.T) {
	cfg := Default()
	cfg.Rules = []RuleConfig{{
		ID: "secrets", Severity: "critical", Detectors: []string{"access_keys"},
		Options: map[string]DetectorOptions{"access_keys": {
			"max_length": 40,
			"min_length": 16,
			"prefixes": []any{
				map[string]any{"note": "AWS long-term", "prefix": "AKIA", "length": 16},
				map[string]any{"prefix": "CORP", "zzz_unknown": true},
			},
		}},
	}}

	out, err := Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)

	for _, want := range []string{
		"prefixes:",
		"- prefix: AKIA",
		"length: 16",
		"note: AWS long-term",
		"min_length: 16",
		"max_length: 40",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in:\n%s", want, got)
		}
	}
	if order(got, "prefixes:") > order(got, "min_length:") {
		t.Error("the list should come before the numbers that only apply to part of it")
	}
	if order(got, "- prefix: AKIA") > order(got, "note: AWS long-term") {
		t.Error("a prefix entry should start with the prefix")
	}
	if order(got, "min_length:") > order(got, "max_length:") {
		t.Error("shortest should come before longest")
	}
	// An unknown key still round-trips; it just sorts after the known ones.
	if !strings.Contains(got, "zzz_unknown: true") {
		t.Error("unknown options must survive being rewritten")
	}
}

func order(s, sub string) int { return strings.Index(s, sub) }

// A detector is handed its options as a plain map. The named type used to
// order the file must not reach the values inside it.
func TestDetectorOptionsDecodeAsPlainMaps(t *testing.T) {
	cfg, err := Parse([]byte(`
version: 1
rules:
  - id: secrets
    severity: critical
    detectors: [access_keys]
    options:
      access_keys:
        prefixes:
          - prefix: AKIA
            length: 16
          - CORP
`))
	if err != nil {
		t.Fatal(err)
	}
	list, ok := cfg.Rules[0].Options["access_keys"]["prefixes"].([]any)
	if !ok {
		t.Fatalf("prefixes should decode as a list, got %T", cfg.Rules[0].Options["access_keys"]["prefixes"])
	}
	if _, ok := list[0].(map[string]any); !ok {
		t.Errorf("a nested table must be a plain map, got %T", list[0])
	}
	if _, ok := list[1].(string); !ok {
		t.Errorf("a bare prefix must stay a string, got %T", list[1])
	}
}
