// Package config defines the YAML configuration schema, defaults, loading
// with environment overrides, validation, and hot reload.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Block modes selectable per service.
const (
	BlockModeReject    = "reject"    // HTTP 403 with a service-native JSON error
	BlockModeSynthetic = "synthetic" // HTTP 200 with a fake completion explaining the block
)

// Actions selectable per rule / as the default.
const (
	ActionAllow   = "allow"
	ActionBlock   = "block"
	ActionMonitor = "monitor"
)

// Config is the root of aigatekeeper.yaml.
type Config struct {
	Version int          `yaml:"version"`
	Listen  ListenConfig `yaml:"listen"`
	CA      CAConfig     `yaml:"ca"`
	TLS     TLSConfig    `yaml:"tls"`
	Limits  LimitsConfig `yaml:"limits"`
	Mode    ModeConfig   `yaml:"mode"`
	Reload  ReloadConfig `yaml:"reload"`
	Audit   AuditConfig  `yaml:"audit"`
	Admin   AdminConfig  `yaml:"admin"`

	TunnelUnmatched bool   `yaml:"tunnel_unmatched"`
	DefaultAction   string `yaml:"default_action"`
	BlockMessage    string `yaml:"block_message"`

	Services  []ServiceConfig `yaml:"services"`
	Rules     []RuleConfig    `yaml:"rules"`
	Allowlist AllowlistConfig `yaml:"allowlist"`

	baseDir string
}

// ListenConfig holds listener addresses.
type ListenConfig struct {
	Forward string          `yaml:"forward"`
	Admin   string          `yaml:"admin"`
	Reverse []ReverseConfig `yaml:"reverse"`
}

// ReverseConfig defines a reverse-proxy listener in front of a local model
// server such as Ollama, for clients that bypass proxies for localhost.
type ReverseConfig struct {
	Name     string `yaml:"name"`
	Listen   string `yaml:"listen"`
	Upstream string `yaml:"upstream"`
	Service  string `yaml:"service"`
}

// CAConfig locates the root CA and tunes leaf issuance.
type CAConfig struct {
	Cert      string   `yaml:"cert"`
	Key       string   `yaml:"key"`
	LeafTTL   Duration `yaml:"leaf_ttl"`
	CacheSize int      `yaml:"cache_size"`
}

// TLSConfig tunes client-facing and upstream TLS.
type TLSConfig struct {
	AdvertiseHTTP2     bool     `yaml:"advertise_http2"`
	UpstreamExtraRoots []string `yaml:"upstream_extra_roots"`
	UpstreamInsecure   bool     `yaml:"upstream_insecure"`
	UpstreamProxy      string   `yaml:"upstream_proxy"`
}

// LimitsConfig bounds request handling.
type LimitsConfig struct {
	MaxBodyBytes     ByteSize `yaml:"max_body_bytes"`
	MaxDecodedBytes  ByteSize `yaml:"max_decoded_bytes"`
	OversizeAction   string   `yaml:"oversize_action"`
	ParseErrorAction string   `yaml:"parse_error_action"`
	UpstreamTimeout  Duration `yaml:"upstream_timeout"`
}

// ModeConfig holds global behaviour switches.
type ModeConfig struct {
	Monitor bool `yaml:"monitor"`
}

// ReloadConfig tunes configuration hot reload.
type ReloadConfig struct {
	Watch        bool     `yaml:"watch"`
	Debounce     Duration `yaml:"debounce"`
	PollInterval Duration `yaml:"poll_interval"`
}

// AuditConfig configures audit sinks.
type AuditConfig struct {
	Stdout         bool              `yaml:"stdout"`
	File           string            `yaml:"file"`
	IncludePreview bool              `yaml:"include_preview"`
	LogAllowed     bool              `yaml:"log_allowed"`
	SQLite         AuditSQLiteConfig `yaml:"sqlite"`
}

// AuditSQLiteConfig configures the embedded history store that backs the
// admin UI. Stdout logging is independent of this.
type AuditSQLiteConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Path          string   `yaml:"path"`
	MaxAge        Duration `yaml:"max_age"`
	MaxRows       int64    `yaml:"max_rows"`
	BatchSize     int      `yaml:"batch_size"`
	BatchInterval Duration `yaml:"batch_interval"`
	SweepInterval Duration `yaml:"sweep_interval"`
	Queue         int      `yaml:"queue"`
}

// AdminConfig configures the admin API / UI listener.
type AdminConfig struct {
	Auth        AdminAuthConfig `yaml:"auth"`
	TLSCert     string          `yaml:"tls_cert"`
	TLSKey      string          `yaml:"tls_key"`
	CORSOrigins []string        `yaml:"cors_origins"`
	UI          bool            `yaml:"ui"`
}

// AdminAuthConfig holds the single admin credential. Generate the hash with
// `aigatekeeper admin hash-password`; either field may come from the
// environment instead (AIGK_ADMIN_PASSWORD_HASH, AIGK_ADMIN_TOKEN).
type AdminAuthConfig struct {
	PasswordHash   string   `yaml:"password_hash"`
	Token          string   `yaml:"token"`
	SessionTTL     Duration `yaml:"session_ttl"`
	LoginBurst     int      `yaml:"login_burst"`
	LoginPerMinute int      `yaml:"login_per_minute"`
}

// Configured reports whether an admin credential is set.
func (a AdminAuthConfig) Configured() bool { return a.PasswordHash != "" || a.Token != "" }

// ServiceConfig describes one intercepted GenAI service.
type ServiceConfig struct {
	Name             string   `yaml:"name"`
	Hosts            []string `yaml:"hosts"`
	Extractor        string   `yaml:"extractor"`
	BlockMode        string   `yaml:"block_mode"`
	PassthroughPaths []string `yaml:"passthrough_paths"`
	Rules            []string `yaml:"rules"`
}

// RuleConfig groups detectors with a severity and an action.
type RuleConfig struct {
	ID        string                    `yaml:"id"`
	Severity  string                    `yaml:"severity"`
	Action    string                    `yaml:"action"`
	Detectors []string                  `yaml:"detectors"`
	Options   map[string]map[string]any `yaml:"options"`
	Keywords  KeywordsConfig            `yaml:"keywords"`
	Regex     []RegexConfig             `yaml:"regex"`
}

// KeywordsConfig configures a keyword list detector for a rule.
type KeywordsConfig struct {
	File            string   `yaml:"file"`
	List            []string `yaml:"list"`
	CaseInsensitive bool     `yaml:"case_insensitive"`
	WordBoundary    bool     `yaml:"word_boundary"`
}

// RegexConfig is a user-defined regex detector.
type RegexConfig struct {
	ID        string `yaml:"id"`
	Pattern   string `yaml:"pattern"`
	MinLength int    `yaml:"min_length"`
}

// AllowlistConfig lists exceptions that suppress findings or bypass scanning.
type AllowlistConfig struct {
	Values       []string           `yaml:"values"`
	Patterns     []string           `yaml:"patterns"`
	EmailDomains []string           `yaml:"email_domains"`
	ClientCIDRs  []string           `yaml:"client_cidrs"`
	HeaderBypass HeaderBypassConfig `yaml:"header_bypass"`
	SegmentPaths []string           `yaml:"segment_paths"`
}

// HeaderBypassConfig lets trusted automation skip DLP with a shared secret.
type HeaderBypassConfig struct {
	Name  string `yaml:"name"`
	Token string `yaml:"token"`
}

// Default returns a Config populated with safe defaults.
func Default() *Config {
	return &Config{
		Version: 1,
		Listen: ListenConfig{
			Forward: "127.0.0.1:8080",
			Admin:   "127.0.0.1:9090",
		},
		CA: CAConfig{
			Cert:      "./certs/ca.crt",
			Key:       "./certs/ca.key",
			LeafTTL:   Duration(397 * 24 * time.Hour),
			CacheSize: 1024,
		},
		Limits: LimitsConfig{
			MaxBodyBytes:     8 << 20,
			MaxDecodedBytes:  32 << 20,
			OversizeAction:   ActionBlock,
			ParseErrorAction: ActionAllow,
			UpstreamTimeout:  Duration(120 * time.Second),
		},
		Reload: ReloadConfig{
			Watch:    true,
			Debounce: Duration(300 * time.Millisecond),
		},
		Audit: AuditConfig{
			Stdout:         true,
			IncludePreview: true,
			LogAllowed:     true,
			SQLite: AuditSQLiteConfig{
				Path:          "./data/audit.db",
				MaxAge:        Duration(720 * time.Hour),
				MaxRows:       1_000_000,
				BatchSize:     256,
				BatchInterval: Duration(200 * time.Millisecond),
				SweepInterval: Duration(time.Hour),
				Queue:         8192,
			},
		},
		Admin: AdminConfig{
			UI:   true,
			Auth: AdminAuthConfig{SessionTTL: Duration(12 * time.Hour), LoginBurst: 5, LoginPerMinute: 5},
		},
		TunnelUnmatched: true,
		DefaultAction:   ActionBlock,
		BlockMessage:    "[AIGatekeeper] Request blocked by policy {rule} ({detectors}). Ref {request_id}.",
		Allowlist: AllowlistConfig{
			HeaderBypass: HeaderBypassConfig{Name: "X-AIGK-Bypass"},
		},
	}
}

// ValidationError collects every problem found in a configuration so the UI
// can show them all at once.
type ValidationError struct {
	Problems []Problem
}

// Problem is one validation failure with a YAML-ish path.
type Problem struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (e *ValidationError) Error() string {
	var b strings.Builder
	b.WriteString("configuration is invalid:")
	for _, p := range e.Problems {
		b.WriteString("\n  ")
		b.WriteString(p.Path)
		b.WriteString(": ")
		b.WriteString(p.Message)
	}
	return b.String()
}

func (e *ValidationError) add(path, format string, args ...any) {
	e.Problems = append(e.Problems, Problem{Path: path, Message: fmt.Sprintf(format, args...)})
}

var identRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// Validate checks structural constraints that do not depend on other
// packages. Extractor and detector names are validated when the policy is
// compiled, because their registries live in the parser and dlp packages.
func (c *Config) Validate() error {
	ve := &ValidationError{}

	if c.Version != 1 {
		ve.add("version", "unsupported version %d (expected 1)", c.Version)
	}
	if err := validateAddr(c.Listen.Forward); err != nil {
		ve.add("listen.forward", "%v", err)
	}
	if c.Listen.Admin != "" {
		if err := validateAddr(c.Listen.Admin); err != nil {
			ve.add("listen.admin", "%v", err)
		}
	}
	if c.CA.Cert == "" {
		ve.add("ca.cert", "path is required")
	}
	if c.CA.Key == "" {
		ve.add("ca.key", "path is required")
	}
	if c.CA.LeafTTL.Std() <= 0 || c.CA.LeafTTL.Std() > 398*24*time.Hour {
		ve.add("ca.leaf_ttl", "must be between 1s and 398d")
	}
	if c.CA.CacheSize <= 0 {
		ve.add("ca.cache_size", "must be positive")
	}
	if c.TLS.UpstreamProxy != "" {
		if u, err := url.Parse(c.TLS.UpstreamProxy); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
			ve.add("tls.upstream_proxy", "must be an http://, https:// or socks5:// URL")
		}
	}
	if c.Limits.MaxBodyBytes <= 0 {
		ve.add("limits.max_body_bytes", "must be positive")
	}
	if c.Limits.MaxDecodedBytes < c.Limits.MaxBodyBytes {
		ve.add("limits.max_decoded_bytes", "must be at least max_body_bytes")
	}
	if !isOneOf(c.Limits.OversizeAction, ActionBlock, ActionAllow) {
		ve.add("limits.oversize_action", "must be block or allow")
	}
	if !isOneOf(c.Limits.ParseErrorAction, ActionBlock, ActionAllow) {
		ve.add("limits.parse_error_action", "must be block or allow")
	}
	if !isOneOf(c.DefaultAction, ActionBlock, ActionMonitor, ActionAllow) {
		ve.add("default_action", "must be block, monitor or allow")
	}
	if c.Audit.SQLite.Enabled && c.Audit.SQLite.Path == "" {
		ve.add("audit.sqlite.path", "is required when the history store is enabled")
	}
	if h := c.Admin.Auth.PasswordHash; h != "" && !strings.HasPrefix(h, "$2") {
		ve.add("admin.auth.password_hash", "must be a bcrypt hash; generate one with `aigatekeeper admin hash-password`")
	}
	if t := c.Admin.Auth.Token; t != "" && len(t) < 16 {
		ve.add("admin.auth.token", "must be at least 16 characters")
	}
	if (c.Admin.TLSCert == "") != (c.Admin.TLSKey == "") {
		ve.add("admin.tls_cert", "tls_cert and tls_key must be set together")
	}

	serviceNames := map[string]bool{}
	for i, s := range c.Services {
		p := fmt.Sprintf("services[%d]", i)
		if s.Name == "" {
			ve.add(p+".name", "is required")
		} else if !identRe.MatchString(s.Name) {
			ve.add(p+".name", "must be alphanumeric with _ . -")
		} else if serviceNames[s.Name] {
			ve.add(p+".name", "duplicate service name %q", s.Name)
		}
		serviceNames[s.Name] = true
		for j, h := range s.Hosts {
			if _, err := regexp.Compile(h); err != nil {
				ve.add(fmt.Sprintf("%s.hosts[%d]", p, j), "invalid regex: %v", err)
			}
		}
		for j, h := range s.PassthroughPaths {
			if _, err := regexp.Compile(h); err != nil {
				ve.add(fmt.Sprintf("%s.passthrough_paths[%d]", p, j), "invalid regex: %v", err)
			}
		}
		if s.Extractor == "" {
			ve.add(p+".extractor", "is required")
		}
		if !isOneOf(s.BlockMode, BlockModeReject, BlockModeSynthetic) {
			ve.add(p+".block_mode", "must be reject or synthetic")
		}
	}

	ruleIDs := map[string]bool{}
	for i, r := range c.Rules {
		p := fmt.Sprintf("rules[%d]", i)
		if r.ID == "" {
			ve.add(p+".id", "is required")
		} else if ruleIDs[r.ID] {
			ve.add(p+".id", "duplicate rule id %q", r.ID)
		}
		ruleIDs[r.ID] = true
		if !isOneOf(r.Severity, "low", "medium", "high", "critical") {
			ve.add(p+".severity", "must be low, medium, high or critical")
		}
		if r.Action != "" && !isOneOf(r.Action, ActionBlock, ActionMonitor, ActionAllow) {
			ve.add(p+".action", "must be block, monitor or allow")
		}
		if len(r.Detectors) == 0 && len(r.Regex) == 0 && r.Keywords.File == "" && len(r.Keywords.List) == 0 {
			ve.add(p, "rule has no detectors, regex or keywords")
		}
		for j, rx := range r.Regex {
			if rx.ID == "" {
				ve.add(fmt.Sprintf("%s.regex[%d].id", p, j), "is required")
			}
			if _, err := regexp.Compile(rx.Pattern); err != nil {
				ve.add(fmt.Sprintf("%s.regex[%d].pattern", p, j), "invalid regex: %v", err)
			}
		}
	}
	for i, s := range c.Services {
		for j, ref := range s.Rules {
			if !ruleIDs[ref] {
				ve.add(fmt.Sprintf("services[%d].rules[%d]", i, j), "unknown rule %q", ref)
			}
		}
	}

	reverseNames := map[string]bool{}
	for i, r := range c.Listen.Reverse {
		p := fmt.Sprintf("listen.reverse[%d]", i)
		if r.Name == "" {
			ve.add(p+".name", "is required")
		} else if reverseNames[r.Name] {
			ve.add(p+".name", "duplicate listener name %q", r.Name)
		}
		reverseNames[r.Name] = true
		if err := validateAddr(r.Listen); err != nil {
			ve.add(p+".listen", "%v", err)
		}
		if u, err := url.Parse(r.Upstream); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			ve.add(p+".upstream", "must be an http:// or https:// URL")
		}
		if r.Service == "" {
			ve.add(p+".service", "is required")
		} else if !serviceNames[r.Service] {
			ve.add(p+".service", "unknown service %q", r.Service)
		}
	}

	for i, pat := range c.Allowlist.Patterns {
		if _, err := regexp.Compile(pat); err != nil {
			ve.add(fmt.Sprintf("allowlist.patterns[%d]", i), "invalid regex: %v", err)
		}
	}
	for i, cidr := range c.Allowlist.ClientCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			ve.add(fmt.Sprintf("allowlist.client_cidrs[%d]", i), "invalid CIDR: %v", err)
		}
	}

	if len(ve.Problems) > 0 {
		return ve
	}
	return nil
}

func validateAddr(addr string) error {
	if addr == "" {
		return errors.New("address is required")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("invalid host:port address %q", addr)
	}
	return nil
}

func isOneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}
