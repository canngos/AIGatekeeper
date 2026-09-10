package main

import (
	"path/filepath"
	"testing"

	"github.com/canngos/aigatekeeper/internal/config"
	"github.com/canngos/aigatekeeper/internal/parser"
	"github.com/canngos/aigatekeeper/internal/policy"
)

// TestShippedConfigCompiles guards the default configuration: every rule,
// detector, keyword file and extractor name it references must resolve.
func TestShippedConfigCompiles(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "aigatekeeper.yaml")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Compile(cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	reg := parser.Default()
	for _, s := range pol.Services {
		if _, ok := reg.Get(s.Extractor); !ok {
			t.Errorf("service %s references unknown extractor %q", s.Name, s.Extractor)
		}
		if len(s.Rules) == 0 {
			t.Errorf("service %s has no rules", s.Name)
		}
	}
	for _, want := range []string{"openai", "copilot", "anthropic", "gemini", "tabnine", "ollama"} {
		if pol.ServiceByName(want) == nil {
			t.Errorf("shipped config is missing service %s", want)
		}
	}
	if !pol.Intercept("api.githubcopilot.com") || !pol.Intercept("copilot-proxy.githubusercontent.com") || pol.Intercept("github.com") {
		t.Error("host matching for Copilot is wrong")
	}
	if cfg.ResolvePath(cfg.CA.Cert) != filepath.Join("..", "..", "configs", "..", "certs", "ca.crt") {
		t.Errorf("CA path resolves to %s", cfg.ResolvePath(cfg.CA.Cert))
	}
}

func TestRunVersionAndUsage(t *testing.T) {
	var out, errOut testWriter
	if code := run([]string{"version"}, &out, &errOut); code != 0 || out.String() == "" {
		t.Fatalf("version: code %d out %q", code, out.String())
	}
	if code := run(nil, &out, &errOut); code != 2 {
		t.Fatalf("no args should exit 2, got %d", code)
	}
	if code := run([]string{"bogus"}, &out, &errOut); code != 2 {
		t.Fatalf("unknown command should exit 2, got %d", code)
	}
}

type testWriter struct{ b []byte }

func (w *testWriter) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }
func (w *testWriter) String() string              { return string(w.b) }
