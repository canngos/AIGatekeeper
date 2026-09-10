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
	Listen  ListenConfig `yaml:"listen,omitempty"`
	CA      CAConfig     `yaml:"ca,omitempty"`
	TLS     TLSConfig    `yaml:"tls,omitempty"`
	Limits  LimitsConfig `yaml:"limits,omitempty"`
	Mode    ModeConfig   `yaml:"mode,omitempty"`
	Reload  ReloadConfig `yaml:"reload,omitempty"`
	Audit   AuditConfig  `yaml:"audit,omitempty"`
	Admin   AdminConfig  `yaml:"admin,omitempty"`

	TunnelUnmatched bool   `yaml:"tunnel_unmatched"`
	DefaultAction   string `yaml:"default_action,omitempty"`
	BlockMessage    string `yaml:"block_message,omitempty"`

	Services  []ServiceConfig `yaml:"services,omitempty"`
	Rules     []RuleConfig    `yaml:"rules,omitempty"`
	Allowlist AllowlistConfig `yaml:"allowlist,omitempty"`

	baseDir string
}

// ListenConfig holds listener addresses.
type ListenConfig struct {
	Forward string          `yaml:"forward,omitempty"`
	Admin   string          `yaml:"admin,omitempty"`
	Reverse []ReverseConfig `yaml:"reverse,omitempty"`
}

// ReverseConfig defines a reverse-proxy listener in front of a local model
// server such as Ollama, for clients that bypass proxies for localhost.
type ReverseConfig struct {
	Name     string `yaml:"name"`
	Listen   string `yaml:"listen,omitempty"`
	Upstream string `yaml:"upstream,omitempty"`
	Service  string `yaml:"service,omitempty"`
}

// CAConfig locates the root CA and tunes leaf issuance.
type CAConfig struct {
	Cert      string   `yaml:"cert,omitempty"`
	Key       string   `yaml:"key,omitempty"`
	LeafTTL   Duration `yaml:"leaf_ttl,omitempty"`
	CacheSize int      `yaml:"cache_size,omitempty"`
}

// TLSConfig tunes client-facing and upstream TLS.
type TLSConfig struct {
	AdvertiseHTTP2     bool     `yaml:"advertise_http2,omitempty"`
	UpstreamExtraRoots []string `yaml:"upstream_extra_roots,omitempty"`
	UpstreamInsecure   bool     `yaml:"upstream_insecure,omitempty"`
	UpstreamProxy      string   `yaml:"upstream_proxy,omitempty"`
}

// LimitsConfig bounds request handling.
type LimitsConfig struct {
	MaxBodyBytes     ByteSize `yaml:"max_body_bytes,omitempty"`
	MaxDecodedBytes  ByteSize `yaml:"max_decoded_bytes,omitempty"`
	OversizeAction   string   `yaml:"oversize_action,omitempty"`
	ParseErrorAction string   `yaml:"parse_error_action,omitempty"`
	UpstreamTimeout  Duration `yaml:"upstream_timeout,omitempty"`
}

// ModeConfig holds global behaviour switches.
type ModeConfig struct {
	Monitor bool `yaml:"monitor,omitempty"`
}

// ReloadConfig tunes configuration hot reload.
type ReloadConfig struct {
	Watch        bool     `yaml:"watch"`
	Debounce     Duration `yaml:"debounce,omitempty"`
	PollInterval Duration `yaml:"poll_interval,omitempty"`
}

// AuditConfig configures audit sinks.
type AuditConfig struct {
	Stdout         bool              `yaml:"stdout"`
	File           string            `yaml:"file,omitempty"`
	IncludePreview bool              `yaml:"include_preview"`
	LogAllowed     bool              `yaml:"log_allowed"`
	SQLite         AuditSQLiteConfig `yaml:"sqlite,omitempty"`
}

// AuditSQLiteConfig configures the embedded history store that backs the
// admin UI. Stdout logging is independent of this.
type AuditSQLiteConfig struct {
	Enabled       bool     `yaml:"enabled,omitempty"`
	Path          string   `yaml:"path,omitempty"`
	MaxAge        Duration `yaml:"max_age,omitempty"`
	MaxRows       int64    `yaml:"max_rows,omitempty"`
	BatchSize     int      `yaml:"batch_size,omitempty"`
	BatchInterval Duration `yaml:"batch_interval,omitempty"`
	SweepInterval Duration `yaml:"sweep_interval,omitempty"`
	Queue         int      `yaml:"queue,omitempty"`
}

// AdminConfig configures the admin API / UI listener.
type AdminConfig struct {
	Auth        AdminAuthConfig `yaml:"auth,omitempty"`
	TLSCert     string          `yaml:"tls_cert,omitempty"`
	TLSKey      string          `yaml:"tls_key,omitempty"`
	CORSOrigins []string        `yaml:"cors_origins,omitempty"`
	UI          bool            `yaml:"ui"`
}

// AdminAuthConfig holds the single admin credential. Generate the hash with
// `aigatekeeper admin hash-password`; either field may come from the
// environment instead (AIGK_ADMIN_PASSWORD_HASH, AIGK_ADMIN_TOKEN).
type AdminAuthConfig struct {
	PasswordHash   string   `yaml:"password_hash,omitempty"`
	Token          string   `yaml:"token,omitempty"`
	SessionTTL     Duration `yaml:"session_ttl,omitempty"`
	LoginBurst     int      `yaml:"login_burst,omitempty"`
	LoginPerMinute int      `yaml:"login_per_minute,omitempty"`
}

// Configured reports whether an admin credential is set.
func (a AdminAuthConfig) Configured() bool { return a.PasswordHash != "" || a.Token != "" }

// ServiceConfig describes one intercepted GenAI service.
type ServiceConfig struct {
	Name             string   `yaml:"name"`
	Hosts            []string `yaml:"hosts,omitempty"`
	Extractor        string   `yaml:"extractor,omitempty"`
	BlockMode        string   `yaml:"block_mode,omitempty"`
	PassthroughPaths []string `yaml:"passthrough_paths,omitempty"`
	Rules            []string `yaml:"rules,omitempty"`
}

// RuleConfig groups detectors with a severity and an action.
type RuleConfig struct {
	ID        string                    `yaml:"id"`
	Severity  string                    `yaml:"severity"`
	Action    string                    `yaml:"action,omitempty"`
	Detectors []string                  `yaml:"detectors,omitempty"`
	Options   map[string]map[string]any `yaml:"options,omitempty"`
	Keywords  KeywordsConfig            `yaml:"keywords,omitempty"`
	Regex     []RegexConfig             `yaml:"regex,omitempty"`
}

// KeywordsConfig configures a keyword list detector for a rule.
type KeywordsConfig struct {
	File            string   `yaml:"file,omitempty"`
	List            []string `yaml:"list,omitempty"`
	CaseInsensitive bool     `yaml:"case_insensitive,omitempty"`
	WordBoundary    bool     `yaml:"word_boundary,omitempty"`
}

// RegexConfig is a user-defined regex detector.
type RegexConfig struct {
	ID        string `yaml:"id"`
	Pattern   string `yaml:"pattern,omitempty"`
	MinLength int    `yaml:"min_length,omitempty"`
}

// AllowlistConfig lists exceptions that suppress findings or bypass scanning.
type AllowlistConfig struct {
	Values       []string           `yaml:"values,omitempty"`
	Patterns     []string           `yaml:"patterns,omitempty"`
	EmailDomains []string           `yaml:"email_domains,omitempty"`
	ClientCIDRs  []string           `yaml:"client_cidrs,omitempty"`
	HeaderBypass HeaderBypassConfig `yaml:"header_bypass,omitempty"`
	SegmentPaths []string           `yaml:"segment_paths,omitempty"`
}

// HeaderBypassConfig lets trusted automation skip DLP with a shared secret.
type HeaderBypassConfig struct {
	Name  string `yaml:"name"`
	Token string `yaml:"token,omitempty"`
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
