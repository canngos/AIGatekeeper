package policy

import (
	"strings"
	"testing"

	"github.com/canngos/aigatekeeper/internal/config"
)

const disabledFixture = `
version: 1
tunnel_unmatched: true
services:
  - name: openai
    enabled: false
    hosts: ['^api\.openai\.com$']
    extractor: openai
    rules: [secrets]
  - name: anthropic
    hosts: ['^api\.anthropic\.com$']
    extractor: anthropic
    rules: [secrets]
listen:
  reverse:
    - { name: local, listen: 127.0.0.1:11434, upstream: http://127.0.0.1:11435, service: openai }
rules:
  - { id: secrets, severity: critical, action: block, detectors: [access_keys] }
`

// Turning a destination off has to stop it being inspected without deleting
// the configuration, so it can be turned back on unchanged.
func TestDisabledServiceIsNotInspected(t *testing.T) {
	cfg, err := config.Parse([]byte(disabledFixture))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := Compile(cfg, "test")
	if err != nil {
		t.Fatal(err)
	}

	if pol.ServiceForHost("api.openai.com") != nil {
		t.Error("a disabled destination must not match, so its traffic is tunnelled")
	}
	if pol.Intercept("api.openai.com") {
		t.Error("a disabled destination must not be decrypted")
	}
	if pol.ServiceForHost("api.anthropic.com") == nil {
		t.Error("the other destinations are unaffected")
	}
	// A reverse listener pointing at it forwards without inspecting rather
	// than failing to compile.
	if pol.ServiceForListener("local") != nil {
		t.Error("a reverse listener bound to a disabled service must not inspect")
	}
	// The service is still there, so the console can show it and switch it
	// back on.
	if s := pol.ServiceByName("openai"); s == nil || s.Enabled {
		t.Errorf("the service should still be present and marked disabled, got %+v", s)
	}
}

func TestServicesAreEnabledUnlessSaidOtherwise(t *testing.T) {
	cfg, err := config.Parse([]byte(strings.Replace(disabledFixture, "    enabled: false\n", "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := Compile(cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	if pol.ServiceForHost("api.openai.com") == nil {
		t.Error("a service with no enabled field is inspected")
	}
	if pol.ServiceForListener("local") == nil {
		t.Error("its reverse listener inspects too")
	}
}

// The flag has to survive the console rewriting the file, and an untouched
// service must not gain an enabled line it never had.
func TestDisabledSurvivesARewrite(t *testing.T) {
	cfg, err := config.Parse([]byte(disabledFixture))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := config.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "enabled: false") {
		t.Fatalf("the flag was dropped:\n%s", raw)
	}
	if strings.Contains(string(raw), "enabled: true") {
		t.Errorf("an enabled service should stay silent about it:\n%s", raw)
	}

	back, err := config.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := Compile(back, "test")
	if err != nil {
		t.Fatal(err)
	}
	if pol.ServiceForHost("api.openai.com") != nil {
		t.Error("the destination came back on after a rewrite")
	}
}
