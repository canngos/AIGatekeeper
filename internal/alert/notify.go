package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"text/template"
	"time"
)

// EmailConfig points at an SMTP relay.
type EmailConfig struct {
	Host     string
	Port     int
	TLS      string // starttls | tls | none
	Username string
	Password string
	From     string
	Timeout  time.Duration
}

// EmailNotifier sends alerts through an SMTP relay.
type EmailNotifier struct {
	cfg  EmailConfig
	tmpl *template.Template
	// send is overridable for tests.
	send func(cfg EmailConfig, to []string, msg []byte) error
}

// NewEmailNotifier validates the relay settings.
func NewEmailNotifier(cfg EmailConfig, tmpl *template.Template) (*EmailNotifier, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("alerts.email.host is required")
	}
	if cfg.From == "" {
		return nil, fmt.Errorf("alerts.email.from is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	if cfg.TLS == "" {
		cfg.TLS = "starttls"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if tmpl == nil {
		tmpl = DefaultTemplates()
	}
	return &EmailNotifier{cfg: cfg, tmpl: tmpl, send: sendSMTP}, nil
}

// Name implements Notifier.
func (n *EmailNotifier) Name() string { return "email" }

// Send implements Notifier.
func (n *EmailNotifier) Send(_ context.Context, a Alert, recipients []string) error {
	if len(recipients) == 0 {
		return nil
	}
	subject, err := n.render("subject", a)
	if err != nil {
		return err
	}
	body, err := n.render("body", a)
	if err != nil {
		return err
	}
	msg := buildMessage(n.cfg.From, recipients, strings.TrimSpace(subject), body)
	return n.send(n.cfg, recipients, msg)
}

func (n *EmailNotifier) render(name string, a Alert) (string, error) {
	var buf bytes.Buffer
	if err := n.tmpl.ExecuteTemplate(&buf, name, a); err != nil {
		return "", fmt.Errorf("render %s: %w", name, err)
	}
	return buf.String(), nil
}

func buildMessage(from string, to []string, subject, body string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	return b.Bytes()
}

func sendSMTP(cfg EmailConfig, to []string, msg []byte) error {
	addr := net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port))
	dialer := &net.Dialer{Timeout: cfg.Timeout}

	var conn net.Conn
	var err error
	if cfg.TLS == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect to %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))

	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return err
	}
	defer c.Close()

	if cfg.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
				return fmt.Errorf("start TLS: %w", err)
			}
		}
	}
	if cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return fmt.Errorf("authenticate: %w", err)
		}
	}
	if err := c.Mail(cfg.From); err != nil {
		return err
	}
	for _, addr := range to {
		if err := c.Rcpt(addr); err != nil {
			return fmt.Errorf("recipient %s: %w", addr, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// WebhookNotifier posts the alert as JSON, signed so the receiver can tell
// it came from this gatekeeper.
type WebhookNotifier struct {
	name    string
	url     string
	secret  string
	client  *http.Client
	retries int
}

// NewWebhookNotifier builds a webhook notifier.
func NewWebhookNotifier(name, url, secret string, timeout time.Duration) (*WebhookNotifier, error) {
	if url == "" {
		return nil, fmt.Errorf("alerts.webhooks[%s].url is required", name)
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &WebhookNotifier{name: name, url: url, secret: secret, client: &http.Client{Timeout: timeout}, retries: 2}, nil
}

// Name implements Notifier.
func (n *WebhookNotifier) Name() string { return "webhook:" + n.name }

// Send implements Notifier.
func (n *WebhookNotifier) Send(ctx context.Context, a Alert, _ []string) error {
	payload, err := json.Marshal(map[string]any{
		"type":  "aigatekeeper.alert",
		"alert": a,
		"text":  a.Subject(),
	})
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt <= n.retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "AIGatekeeper")
		if n.secret != "" {
			mac := hmac.New(sha256.New, []byte(n.secret))
			mac.Write(payload)
			req.Header.Set("X-AIGatekeeper-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
		resp, err := n.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("webhook returned %d", resp.StatusCode)
		if resp.StatusCode < 500 {
			break // a client error will not fix itself on retry
		}
	}
	return lastErr
}

const defaultSubject = `AIGatekeeper: {{.Count}} blocked prompts from {{.Who}}`

const defaultBody = `{{.Who}} had {{.Count}} prompts stopped or flagged by AIGatekeeper in the last {{.Window}}.

Rule:      {{.RuleID}}
Severity:  {{.Severity}}
{{if .User}}User:      {{.User}}
{{end}}{{if .Device}}Device:    {{.Device}}
{{end}}{{if .ClientIP}}Address:   {{.ClientIP}}
{{end}}Services:  {{join .Services ", "}}
Found:     {{join .Detectors ", "}}

Requests:
{{range .Events}}  {{.Time.UTC.Format "15:04:05"}}  {{.Service}}  {{.Host}}{{.Path}}  {{.Action}}  {{join .Detectors ", "}}  {{join .Previews " "}}
{{end}}
Matched values are masked. The full record is in the AIGatekeeper console.
`

// DefaultTemplates returns the built-in subject and body templates.
func DefaultTemplates() *template.Template {
	t := template.New("alert").Funcs(templateFuncs())
	template.Must(t.New("subject").Parse(defaultSubject))
	template.Must(t.New("body").Parse(defaultBody))
	return t
}

// ParseTemplates layers operator-supplied templates over the defaults.
// Each file defines "subject" or "body" via {{define}}.
func ParseTemplates(paths ...string) (*template.Template, error) {
	t := DefaultTemplates()
	for _, p := range paths {
		if p == "" {
			continue
		}
		var err error
		t, err = t.ParseFiles(p)
		if err != nil {
			return nil, fmt.Errorf("parse alert template %s: %w", p, err)
		}
	}
	return t, nil
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"join": strings.Join,
	}
}
