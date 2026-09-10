package main

import (
	"path/filepath"
	"testing"

	"github.com/canngos/aigatekeeper/internal/config"
	"github.com/canngos/aigatekeeper/internal/policy"
)

// The console rewrites the whole file from the schema whenever someone
// applies a change from the forms. Anything the writer cannot express would
// be silently dropped, so the shipped configuration has to survive a full
// round trip and still compile to the same policy.
func TestShippedConfigSurvivesBeingRewritten(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "aigatekeeper.yaml")
	first, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := config.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("the file the console would write does not parse: %v\n%s", err, raw)
	}
	second.SetBaseDir(filepath.Dir(path))
	if _, err := policy.Compile(second, "test"); err != nil {
		t.Fatalf("the file the console would write does not compile: %v\n%s", err, raw)
	}

	// And again, to prove the writer has reached a fixed point rather than
	// drifting a little on every save.
	again, err := config.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(raw) {
		t.Errorf("rewriting twice is not stable:\nfirst:\n%s\nsecond:\n%s", raw, again)
	}
}
