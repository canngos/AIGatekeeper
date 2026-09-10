package config

import (
	"strings"
	"testing"
)

// The console rewrites the whole file whenever a policy change is applied.
// A secret handed to the process by its environment must not end up in that
// file: it is kept out of the file on purpose, and the file is usually in
// version control.
func TestRewritingNeverBakesTheEnvironmentIntoTheFile(t *testing.T) {
	const file = `
version: 1
ca:
  cert: ../certs/ca.crt
  key: ../certs/ca.key
listen:
  admin: 127.0.0.1:9090
alerts:
  email:
    host: smtp.corp.local
    password_env: CORP_SMTP_PASSWORD
  webhooks:
    - name: soc
      url: https://example.invalid/hook
      secret_env: CORP_WEBHOOK_SECRET
identity:
  proxy_auth:
    ldap:
      bind_password_env: CORP_LDAP_PASSWORD
`
	for k, v := range map[string]string{
		"AIGK_CA_CERT":              "/certs/ca.crt",
		"AIGK_CA_KEY":               "/certs/ca.key",
		"AIGK_LISTEN_ADMIN":         "0.0.0.0:9090",
		"AIGK_ADMIN_PASSWORD_HASH":  "$2a$10$hash-from-the-environment",
		"AIGK_ADMIN_TOKEN":          "token-from-the-environment",
		"AIGK_AUDIT_SQLITE_PATH":    "/data/audit.db",
		"AIGK_MODE_MONITOR":         "true",
		"AIGK_RELOAD_POLL_INTERVAL": "5s",
		"CORP_SMTP_PASSWORD":        "smtp-secret",
		"CORP_WEBHOOK_SECRET":       "webhook-secret",
		"CORP_LDAP_PASSWORD":        "ldap-secret",
	} {
		t.Setenv(k, v)
	}

	cfg, err := Parse([]byte(file))
	if err != nil {
		t.Fatal(err)
	}

	// The running proxy uses the environment.
	if cfg.CA.Cert != "/certs/ca.crt" || cfg.Alerts.Email.Password != "smtp-secret" || !cfg.Mode.Monitor {
		t.Fatalf("the environment should win at runtime: %+v", cfg.CA)
	}

	raw, err := Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	written := string(raw)

	for _, secret := range []string{
		"hash-from-the-environment", "token-from-the-environment",
		"smtp-secret", "webhook-secret", "ldap-secret",
	} {
		if strings.Contains(written, secret) {
			t.Errorf("the file must not contain %q:\n%s", secret, written)
		}
	}
	for _, want := range []string{
		"cert: ../certs/ca.crt",
		"key: ../certs/ca.key",
		"admin: 127.0.0.1:9090",
		"password_env: CORP_SMTP_PASSWORD",
		"secret_env: CORP_WEBHOOK_SECRET",
	} {
		if !strings.Contains(written, want) {
			t.Errorf("the file should still say %q:\n%s", want, written)
		}
	}
	if strings.Contains(written, "monitor: true") {
		t.Errorf("a boolean from the environment should not be written either:\n%s", written)
	}

	// Marshalling must not disturb the configuration the proxy is running on.
	if cfg.CA.Cert != "/certs/ca.crt" || cfg.Alerts.Email.Password != "smtp-secret" {
		t.Error("AsWritten must not modify the live configuration")
	}
	if len(cfg.Alerts.Webhooks) != 1 || cfg.Alerts.Webhooks[0].Secret != "webhook-secret" {
		t.Error("AsWritten must not modify the live webhook secrets")
	}
}
