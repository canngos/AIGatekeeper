package reload

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/policy"
)

const baseConfig = `
version: 1
tunnel_unmatched: %s
services:
  - { name: openai, hosts: ['^api\.openai\.com$'], extractor: openai, rules: [secrets] }
rules:
  - { id: secrets, severity: critical, action: block, detectors: [aws_access_key] }
`

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func setup(t *testing.T) (*Manager, string, *audit.Recorder) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "aigatekeeper.yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(baseConfig, "%s", "true", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := &audit.Recorder{}
	m := NewManager(path, policy.NewStore(nil), rec, quiet)
	if _, err := m.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return m, path, rec
}

func countReloadEvents(rec *audit.Recorder) (ok, failed int) {
	for _, e := range rec.Events() {
		if e.Kind != audit.KindConfigReload {
			continue
		}
		if e.Error != "" {
			failed++
		} else {
			ok++
		}
	}
	return
}

func TestManagerLoadAndNoOpReload(t *testing.T) {
	m, _, rec := setup(t)
	cur := m.Current()
	if cur == nil || cur.Source != "startup" || !m.Store().TunnelUnmatched() {
		t.Fatalf("initial load wrong: %+v", cur)
	}
	l, changed, err := m.ReloadFromDisk(context.Background(), "file")
	if err != nil || changed || l != cur {
		t.Fatalf("unchanged file must be a no-op: changed=%v err=%v", changed, err)
	}
	if ok, _ := countReloadEvents(rec); ok != 1 {
		t.Fatalf("expected exactly one reload event, got %d", ok)
	}
}

func TestManagerReloadSwapsAndInvalidKeepsOld(t *testing.T) {
	m, path, rec := setup(t)
	if err := os.WriteFile(path, []byte(strings.Replace(baseConfig, "%s", "false", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	_, changed, err := m.ReloadFromDisk(context.Background(), "file")
	if err != nil || !changed || m.Store().TunnelUnmatched() {
		t.Fatalf("reload did not swap policy: changed=%v err=%v", changed, err)
	}
	oldHash := m.Current().Hash

	if err := os.WriteFile(path, []byte("version: 1\nservices: [{ name: x, hosts: ['('], extractor: openai }]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, changed, err = m.ReloadFromDisk(context.Background(), "file")
	if err == nil || changed {
		t.Fatal("invalid config must fail and not swap")
	}
	if m.Current().Hash != oldHash || m.Store().TunnelUnmatched() {
		t.Fatal("previous policy must be kept after a failed reload")
	}
	reloads, failures, lastErr := m.Stats()
	if reloads != 2 || failures != 1 || lastErr == "" {
		t.Fatalf("stats = %d %d %q", reloads, failures, lastErr)
	}
	if ok, failed := countReloadEvents(rec); ok != 2 || failed != 1 {
		t.Fatalf("reload events ok=%d failed=%d", ok, failed)
	}
}

func TestManagerApply(t *testing.T) {
	m, path, _ := setup(t)
	newRaw := []byte(strings.Replace(baseConfig, "%s", "false", 1))

	if _, err := m.Apply(context.Background(), newRaw, "stale-hash", "admin"); !errors.Is(err, ErrStale) {
		t.Fatalf("expected ErrStale, got %v", err)
	}
	l, err := m.Apply(context.Background(), newRaw, m.Current().Hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if l.Source != "admin" || m.Store().TunnelUnmatched() {
		t.Fatalf("apply did not install: %+v", l)
	}
	onDisk, _ := os.ReadFile(path)
	if string(onDisk) != string(newRaw) {
		t.Fatal("apply did not write the file")
	}
	// The watcher would now see a write event; the hash check makes it a no-op.
	if _, changed, err := m.ReloadFromDisk(context.Background(), "file"); err != nil || changed {
		t.Fatal("reload after apply must be a no-op")
	}
	if _, err := m.Apply(context.Background(), []byte("version: 1\nlisten: { forward: nope }\n"), "", "admin"); err == nil {
		t.Fatal("invalid apply must fail")
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func TestWatchReloadsOnAtomicReplace(t *testing.T) {
	for _, mode := range []string{"fsnotify", "poll"} {
		t.Run(mode, func(t *testing.T) {
			m, path, _ := setup(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opts := WatchOptions{Debounce: 50 * time.Millisecond, Logger: quiet}
			if mode == "poll" {
				opts.DisableFsnotify = true
				opts.PollInterval = 50 * time.Millisecond
			}
			go func() { _ = Watch(ctx, m, opts) }()
			time.Sleep(150 * time.Millisecond) // let the watcher arm

			// Editors write a temp file then rename it over the original;
			// mtime granularity can be coarse, so make sure it moves.
			time.Sleep(20 * time.Millisecond)
			if err := WriteAtomic(path, []byte(strings.Replace(baseConfig, "%s", "false", 1))); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if !m.Store().TunnelUnmatched() {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
			t.Fatalf("policy not reloaded within deadline (%s)", mode)
		})
	}
}
