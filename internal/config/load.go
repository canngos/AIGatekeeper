package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// EnvPrefix is the prefix for environment variable overrides.
const EnvPrefix = "AIGK_"

// Load reads, parses, applies environment overrides to, and validates the
// configuration file at path. Relative paths inside the file resolve
// against the file's directory.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	cfg.SetBaseDir(filepath.Dir(path))
	return cfg, nil
}

// SetBaseDir sets the directory relative paths are resolved against.
func (c *Config) SetBaseDir(dir string) { c.baseDir = dir }

// BaseDir returns the directory relative paths are resolved against.
func (c *Config) BaseDir() string { return c.baseDir }

// ResolvePath makes a configured path absolute relative to the config file
// directory (or the working directory when no base is set).
func (c *Config) ResolvePath(p string) string {
	if p == "" || filepath.IsAbs(p) || c.baseDir == "" {
		return p
	}
	return filepath.Join(c.baseDir, p)
}

// Parse parses YAML bytes on top of defaults, applies environment overrides,
// and validates the result.
func Parse(raw []byte) (*Config, error) {
	cfg := Default()
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !isEOF(err) {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	applyDefaultsToSlices(cfg)
	if err := ApplyEnv(cfg, os.LookupEnv); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func isEOF(err error) bool { return err != nil && err.Error() == "EOF" }

// applyDefaultsToSlices fills per-item defaults that cannot be expressed on
// the root Default() value.
func applyDefaultsToSlices(cfg *Config) {
	for i := range cfg.Services {
		if cfg.Services[i].BlockMode == "" {
			cfg.Services[i].BlockMode = BlockModeReject
		}
		if cfg.Services[i].Extractor == "" {
			cfg.Services[i].Extractor = "generic"
		}
	}
	for i := range cfg.Rules {
		if cfg.Rules[i].Severity == "" {
			cfg.Rules[i].Severity = "medium"
		}
	}
}

// ApplyEnv overrides selected fields from environment variables. lookup is
// injectable for tests.
func ApplyEnv(cfg *Config, lookup func(string) (string, bool)) error {
	str := func(key string, dst *string) {
		if v, ok := lookup(EnvPrefix + key); ok && v != "" {
			*dst = v
		}
	}
	boolean := func(key string, dst *bool) error {
		v, ok := lookup(EnvPrefix + key)
		if !ok || v == "" {
			return nil
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("%s%s: invalid boolean %q", EnvPrefix, key, v)
		}
		*dst = b
		return nil
	}
	dur := func(key string, dst *Duration) error {
		v, ok := lookup(EnvPrefix + key)
		if !ok || v == "" {
			return nil
		}
		d, err := ParseDuration(v)
		if err != nil {
			return fmt.Errorf("%s%s: %v", EnvPrefix, key, err)
		}
		*dst = Duration(d)
		return nil
	}

	str("LISTEN_FORWARD", &cfg.Listen.Forward)
	str("LISTEN_ADMIN", &cfg.Listen.Admin)
	str("CA_CERT", &cfg.CA.Cert)
	str("CA_KEY", &cfg.CA.Key)
	str("AUDIT_FILE", &cfg.Audit.File)
	str("AUDIT_SQLITE_PATH", &cfg.Audit.SQLite.Path)
	str("ADMIN_PASSWORD_HASH", &cfg.Admin.Auth.PasswordHash)
	str("ADMIN_TOKEN", &cfg.Admin.Auth.Token)
	str("UPSTREAM_PROXY", &cfg.TLS.UpstreamProxy)
	str("SMTP_PASSWORD", &cfg.Alerts.Email.Password)
	str("LDAP_BIND_PASSWORD", &cfg.Identity.ProxyAuth.LDAP.BindPassword)

	// Secrets may also name an environment variable to read, which keeps
	// them out of the file the admin console rewrites.
	if v := cfg.Identity.ProxyAuth.LDAP.BindPasswordEnv; v != "" {
		if secret, ok := lookup(v); ok {
			cfg.Identity.ProxyAuth.LDAP.BindPassword = secret
		}
	}
	if v := cfg.Alerts.Email.PasswordEnv; v != "" {
		if secret, ok := lookup(v); ok {
			cfg.Alerts.Email.Password = secret
		}
	}
	for i := range cfg.Alerts.Webhooks {
		if v := cfg.Alerts.Webhooks[i].SecretEnv; v != "" {
			if secret, ok := lookup(v); ok {
				cfg.Alerts.Webhooks[i].Secret = secret
			}
		}
	}
	for _, f := range []func() error{
		func() error { return boolean("MODE_MONITOR", &cfg.Mode.Monitor) },
		func() error { return boolean("TUNNEL_UNMATCHED", &cfg.TunnelUnmatched) },
		func() error { return boolean("TLS_UPSTREAM_INSECURE", &cfg.TLS.UpstreamInsecure) },
		func() error { return boolean("AUDIT_STDOUT", &cfg.Audit.Stdout) },
		func() error { return dur("RELOAD_POLL_INTERVAL", &cfg.Reload.PollInterval) },
	} {
		if err := f(); err != nil {
			return err
		}
	}
	return nil
}

// Hash returns the hex SHA-256 of raw configuration bytes; used to detect
// no-op reloads and as the optimistic-concurrency version for the admin API.
func Hash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Marshal renders a Config back to YAML.
func Marshal(cfg *Config) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ServiceByName returns the service with the given name, or nil.
func (c *Config) ServiceByName(name string) *ServiceConfig {
	for i := range c.Services {
		if strings.EqualFold(c.Services[i].Name, name) {
			return &c.Services[i]
		}
	}
	return nil
}
