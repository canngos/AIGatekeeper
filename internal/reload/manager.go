// Package reload owns the lifecycle of the configuration file: initial
// load, hot reload from disk (file watcher, poll, signal, admin endpoint)
// and atomic writes from the admin API. Every path funnels through one
// Manager so the policy store is swapped consistently and duplicate reloads
// are recognised by content hash.
package reload

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/config"
	"github.com/canngos/aigatekeeper/internal/policy"
)

// ErrStale is returned by Apply when the caller's base version no longer
// matches the loaded configuration (someone else changed it first).
var ErrStale = errors.New("configuration changed since it was read; reload and retry")

// Loaded is one successfully compiled configuration.
type Loaded struct {
	Raw      []byte
	Hash     string
	Config   *config.Config
	Policy   *policy.Policy
	LoadedAt time.Time
	Source   string // startup | file | poll | signal | admin | api
}

// Manager coordinates reloads and applies.
type Manager struct {
	path   string
	store  *policy.Store
	audit  audit.Logger
	logger *slog.Logger

	mu      sync.Mutex // serialises reloads and applies
	current atomic.Pointer[Loaded]

	reloads  atomic.Int64
	failures atomic.Int64
	lastErr  atomic.Pointer[string]
}

// NewManager creates a manager for the configuration file at path. Call
// Load before serving.
func NewManager(path string, store *policy.Store, auditLog audit.Logger, logger *slog.Logger) *Manager {
	if auditLog == nil {
		auditLog = audit.Discard
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{path: path, store: store, audit: auditLog, logger: logger}
}

// Path returns the configuration file path.
func (m *Manager) Path() string { return m.path }

// Current returns the most recently loaded configuration, or nil.
func (m *Manager) Current() *Loaded { return m.current.Load() }

// Store returns the policy store the manager swaps.
func (m *Manager) Store() *policy.Store { return m.store }

// Stats reports reload counters for the admin API.
func (m *Manager) Stats() (reloads, failures int64, lastError string) {
	if p := m.lastErr.Load(); p != nil {
		lastError = *p
	}
	return m.reloads.Load(), m.failures.Load(), lastError
}

// Load performs the initial load and installs the policy.
func (m *Manager) Load(ctx context.Context) (*Loaded, error) {
	l, _, err := m.ReloadFromDisk(ctx, "startup")
	if err != nil {
		return nil, err
	}
	return l, nil
}

// Compile parses and compiles raw without installing it.
func (m *Manager) Compile(raw []byte) (*Loaded, error) {
	cfg, err := config.Parse(raw)
	if err != nil {
		return nil, err
	}
	cfg.SetBaseDir(filepath.Dir(m.path))
	hash := config.Hash(raw)
	pol, err := policy.Compile(cfg, hash)
	if err != nil {
		return nil, err
	}
	return &Loaded{Raw: raw, Hash: hash, Config: cfg, Policy: pol}, nil
}

// ReloadFromDisk re-reads the file. It returns changed=false without
// touching the policy when the content hash equals the loaded one, which is
// what stops an admin Apply from triggering a second reload via the watcher.
func (m *Manager) ReloadFromDisk(ctx context.Context, source string) (*Loaded, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	raw, err := os.ReadFile(m.path)
	if err != nil {
		return m.recordFailure(source, fmt.Errorf("read config: %w", err))
	}
	if cur := m.current.Load(); cur != nil && cur.Hash == config.Hash(raw) {
		return cur, false, nil
	}
	l, err := m.Compile(raw)
	if err != nil {
		return m.recordFailure(source, err)
	}
	m.install(l, source)
	return l, true, nil
}

// Apply validates raw, writes it atomically to the config file and installs
// it. baseVersion, when non-empty, must equal the current hash.
func (m *Manager) Apply(ctx context.Context, raw []byte, baseVersion, source string) (*Loaded, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cur := m.current.Load()
	if baseVersion != "" && cur != nil && baseVersion != cur.Hash {
		return cur, ErrStale
	}
	l, err := m.Compile(raw)
	if err != nil {
		return cur, err
	}
	if cur != nil && cur.Hash == l.Hash {
		return cur, nil
	}
	if err := WriteAtomic(m.path, raw); err != nil {
		return cur, err
	}
	m.install(l, source)
	return l, nil
}

func (m *Manager) install(l *Loaded, source string) {
	l.LoadedAt = time.Now()
	l.Source = source
	prev := m.current.Swap(l)
	m.store.Swap(l.Policy)
	m.reloads.Add(1)
	empty := ""
	m.lastErr.Store(&empty)
	msg := "configuration loaded"
	if prev != nil {
		msg = "configuration reloaded"
	}
	m.logger.Info(msg, "source", source, "hash", short(l.Hash), "services", len(l.Policy.Services), "rules", len(l.Policy.Rules), "monitor", l.Policy.Monitor)
	m.audit.Log(audit.Event{
		Time: l.LoadedAt, Kind: audit.KindConfigReload, Reason: source, Message: l.Hash,
	})
}

func (m *Manager) recordFailure(source string, err error) (*Loaded, bool, error) {
	m.failures.Add(1)
	s := err.Error()
	m.lastErr.Store(&s)
	cur := m.current.Load()
	if cur != nil {
		m.logger.Error("configuration reload failed; keeping previous policy", "source", source, "error", err)
		m.audit.Log(audit.Event{Time: time.Now(), Kind: audit.KindConfigReload, Reason: source, Error: s, Message: cur.Hash})
	}
	return cur, false, err
}

// WriteAtomic writes data to path via a temp file in the same directory and
// a rename, so readers never observe a partial file.
func WriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".aigatekeeper-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("sync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if info, err := os.Stat(path); err == nil {
		_ = os.Chmod(tmpName, info.Mode().Perm())
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
