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
//
// Every override records what the file said, because the admin console
// rewrites the whole file from this struct: without that, applying a policy
// change would bake the deployment's environment into the operator's
// configuration, secrets included. See Config.AsWritten.
func ApplyEnv(cfg *Config, lookup func(string) (string, bool)) error {
	// Fields are named by an accessor rather than a bare pointer so the same
	// closure can restore the value into a copy of the configuration.
	str := func(key string, field func(*Config) *string) {
		v, ok := lookup(EnvPrefix + key)
		if !ok || v == "" {
			return
		}
		p := field(cfg)
		cfg.rememberFileValue(*p, func(c *Config, prior string) { *field(c) = prior })
		*p = v
	}
	boolean := func(key string, field func(*Config) *bool) error {
		v, ok := lookup(EnvPrefix + key)
		if !ok || v == "" {
			return nil
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("%s%s: invalid boolean %q", EnvPrefix, key, v)
		}
		p := field(cfg)
		prior := *p
		cfg.fromEnv = append(cfg.fromEnv, func(c *Config) { *field(c) = prior })
		*p = b
		return nil
	}
	dur := func(key string, field func(*Config) *Duration) error {
		v, ok := lookup(EnvPrefix + key)
		if !ok || v == "" {
			return nil
		}
		d, err := ParseDuration(v)
		if err != nil {
			return fmt.Errorf("%s%s: %v", EnvPrefix, key, err)
		}
		p := field(cfg)
		prior := *p
		cfg.fromEnv = append(cfg.fromEnv, func(c *Config) { *field(c) = prior })
		*p = Duration(d)
		return nil
	}

	str("LISTEN_FORWARD", func(c *Config) *string { return &c.Listen.Forward })
	str("LISTEN_ADMIN", func(c *Config) *string { return &c.Listen.Admin })
	str("CA_CERT", func(c *Config) *string { return &c.CA.Cert })
	str("CA_KEY", func(c *Config) *string { return &c.CA.Key })
	str("AUDIT_FILE", func(c *Config) *string { return &c.Audit.File })
	str("AUDIT_SQLITE_PATH", func(c *Config) *string { return &c.Audit.SQLite.Path })
	str("ADMIN_PASSWORD_HASH", func(c *Config) *string { return &c.Admin.Auth.PasswordHash })
	str("ADMIN_TOKEN", func(c *Config) *string { return &c.Admin.Auth.Token })
	str("UPSTREAM_PROXY", func(c *Config) *string { return &c.TLS.UpstreamProxy })
	str("SMTP_PASSWORD", func(c *Config) *string { return &c.Alerts.Email.Password })
	str("LDAP_BIND_PASSWORD", func(c *Config) *string { return &c.Identity.ProxyAuth.LDAP.BindPassword })

	// A secret may instead name the variable to read it from, which is the
	// better habit. Either way the value is remembered as the file had it.
	fromNamedVar := func(name string, field func(*Config) *string) {
		if name == "" {
			return
		}
		secret, ok := lookup(name)
		if !ok {
			return
		}
		p := field(cfg)
		cfg.rememberFileValue(*p, func(c *Config, prior string) { *field(c) = prior })
		*p = secret
	}
	fromNamedVar(cfg.Identity.ProxyAuth.LDAP.BindPasswordEnv,
		func(c *Config) *string { return &c.Identity.ProxyAuth.LDAP.BindPassword })
	fromNamedVar(cfg.Alerts.Email.PasswordEnv,
		func(c *Config) *string { return &c.Alerts.Email.Password })
	for i := range cfg.Alerts.Webhooks {
		fromNamedVar(cfg.Alerts.Webhooks[i].SecretEnv,
			func(c *Config) *string { return &c.Alerts.Webhooks[i].Secret })
	}

	for _, f := range []func() error{
		func() error { return boolean("MODE_MONITOR", func(c *Config) *bool { return &c.Mode.Monitor }) },
		func() error { return boolean("TUNNEL_UNMATCHED", func(c *Config) *bool { return &c.TunnelUnmatched }) },
		func() error {
			return boolean("TLS_UPSTREAM_INSECURE", func(c *Config) *bool { return &c.TLS.UpstreamInsecure })
		},
		func() error { return boolean("AUDIT_STDOUT", func(c *Config) *bool { return &c.Audit.Stdout }) },
		func() error {
			return dur("RELOAD_POLL_INTERVAL", func(c *Config) *Duration { return &c.Reload.PollInterval })
		},
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
	cfg = cfg.AsWritten()
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
