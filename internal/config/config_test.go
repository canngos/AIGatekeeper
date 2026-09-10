package config

import (
	"strings"
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"":      0,
		"0":     0,
		"300ms": 300 * time.Millisecond,
		"12h":   12 * time.Hour,
		"397d":  397 * 24 * time.Hour,
		"1.5d":  36 * time.Hour,
		"45":    45 * time.Second,
	}
	for in, want := range cases {
		got, err := ParseDuration(in)
		if err != nil {
			t.Errorf("%q: unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q: got %v want %v", in, got, want)
		}
	}
	if _, err := ParseDuration("soon"); err == nil {
		t.Error("expected error for invalid duration")
	}
	if Duration(397*24*time.Hour).String() != "397d" {
		t.Error("expected whole days to render with d suffix")
	}
}

func TestParseByteSize(t *testing.T) {
	cases := map[string]int64{
		"1024":   1024,
		"8MiB":   8 << 20,
		"8 MiB":  8 << 20,
		"32MB":   32_000_000,
		"512KiB": 512 << 10,
		"1G":     1 << 30,
		"0.5MiB": 512 << 10,
	}
	for in, want := range cases {
		got, err := ParseByteSize(in)
		if err != nil {
			t.Errorf("%q: unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q: got %d want %d", in, got, want)
		}
	}
	if _, err := ParseByteSize("lots"); err == nil {
		t.Error("expected error for invalid byte size")
	}
	if ByteSize(8<<20).String() != "8MiB" {
		t.Error("expected 8MiB rendering")
	}
}

const sampleYAML = `
version: 1
listen:
  forward: "0.0.0.0:8080"
  reverse:
    - { name: ollama, listen: "127.0.0.1:11434", upstream: "http://127.0.0.1:11435", service: ollama }
ca: { cert: ./certs/ca.crt, key: ./certs/ca.key, leaf_ttl: 30d }
limits: { max_body_bytes: 4MiB, max_decoded_bytes: 16MiB, upstream_timeout: 90s }
services:
  - { name: openai, hosts: ['^api\.openai\.com$'], extractor: openai, rules: [secrets] }
  - { name: ollama, hosts: [], extractor: ollama, block_mode: synthetic, rules: [secrets] }
rules:
  - { id: secrets, severity: critical, action: block, detectors: [aws_access_key] }
`

func TestParseAppliesDefaultsAndValidates(t *testing.T) {
	cfg, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen.Admin != "127.0.0.1:9090" {
		t.Errorf("expected default admin listener, got %q", cfg.Listen.Admin)
	}
	if cfg.CA.LeafTTL.Std() != 30*24*time.Hour {
		t.Errorf("leaf_ttl not parsed: %v", cfg.CA.LeafTTL)
	}
	if cfg.Limits.MaxBodyBytes != 4<<20 {
		t.Errorf("max_body_bytes not parsed: %d", cfg.Limits.MaxBodyBytes)
	}
	if cfg.Services[0].BlockMode != BlockModeReject {
		t.Errorf("expected default block_mode reject, got %q", cfg.Services[0].BlockMode)
	}
	if !cfg.TunnelUnmatched {
		t.Error("expected tunnel_unmatched default true")
	}
}

func TestParseRejectsUnknownFieldsAndBadValues(t *testing.T) {
	if _, err := Parse([]byte("version: 1\nlisten:\n  fowrard: x\n")); err == nil {
		t.Error("expected unknown field to be rejected")
	}
	bad := `
version: 1
services:
  - { name: a, hosts: ['('], extractor: openai, block_mode: nope, rules: [missing] }
  - { name: a, hosts: [], extractor: openai }
listen:
  reverse:
    - { name: r, listen: "bad", upstream: "ftp://x", service: zzz }
`
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("expected validation errors")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
	joined := err.Error()
	for _, want := range []string{
		"services[0].hosts[0]", "services[0].block_mode", "services[0].rules[0]",
		"services[1].name", "listen.reverse[0].listen", "listen.reverse[0].upstream", "listen.reverse[0].service",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected problem at %s in:\n%s", want, joined)
		}
	}
	if len(ve.Problems) < 7 {
		t.Errorf("expected at least 7 problems, got %d", len(ve.Problems))
	}
}

func TestApplyEnv(t *testing.T) {
	cfg := Default()
	env := map[string]string{
		"AIGK_LISTEN_FORWARD":       "0.0.0.0:3128",
		"AIGK_MODE_MONITOR":         "true",
		"AIGK_RELOAD_POLL_INTERVAL": "5s",
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	if err := ApplyEnv(cfg, lookup); err != nil {
		t.Fatal(err)
	}
	if cfg.Listen.Forward != "0.0.0.0:3128" || !cfg.Mode.Monitor || cfg.Reload.PollInterval.Std() != 5*time.Second {
		t.Errorf("env overrides not applied: %+v", cfg)
	}
	env["AIGK_MODE_MONITOR"] = "maybe"
	if err := ApplyEnv(cfg, lookup); err == nil {
		t.Error("expected invalid boolean to error")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	cfg, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(out)
	if err != nil {
		t.Fatalf("re-parse of marshalled config failed: %v\n%s", err, out)
	}
	if back.CA.LeafTTL != cfg.CA.LeafTTL || back.Limits.MaxBodyBytes != cfg.Limits.MaxBodyBytes {
		t.Error("round trip changed values")
	}
}
