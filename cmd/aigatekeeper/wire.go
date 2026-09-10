package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/canngos/aigatekeeper/internal/alert"
	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/config"
	"github.com/canngos/aigatekeeper/internal/identity"
)

// identityStack is everything built from the identity section.
type identityStack struct {
	Chain     identity.Chain
	ProxyAuth *identity.ProxyAuth
	Directory identity.Directory
	Close     func()
}

// Identify adapts the chain to the proxy's callback. The second result
// says whether the request may proceed: when proxy authentication is on,
// an unauthenticated caller is challenged instead of forwarded.
func (s *identityStack) Identify(r *http.Request, clientIP net.IP) (identity.Identity, bool) {
	if s == nil || len(s.Chain) == 0 {
		return identity.Identity{}, true
	}
	ctx := r.Context()
	if s.ProxyAuth != nil {
		id, _, allowed := s.ProxyAuth.Authenticate(ctx, r, clientIP)
		if !allowed {
			return identity.Identity{}, false
		}
		// Fill the device in from the rest of the chain.
		for _, res := range s.Chain {
			if res == identity.Resolver(s.ProxyAuth) {
				continue
			}
			if extra, ok := res.Resolve(ctx, r, clientIP); ok && extra.Device != "" {
				id.Device = extra.Device
				break
			}
		}
		if id.User != "" {
			id.Source = s.ProxyAuth.Name()
		}
		return id, true
	}
	id, _ := s.Chain.Resolve(ctx, r, clientIP)
	return id, true
}

// buildIdentity assembles the resolver chain described by the config.
func buildIdentity(cfg *config.Config, logger *slog.Logger) (*identityStack, error) {
	stack := &identityStack{Close: func() {}}

	var ldapVerifier *identity.LDAPVerifier
	if pa := cfg.Identity.ProxyAuth; pa.Enabled {
		var verifier identity.Verifier
		switch pa.Backend {
		case "htpasswd":
			v, err := identity.NewHtpasswdVerifier(cfg.ResolvePath(pa.Htpasswd.File))
			if err != nil {
				return nil, err
			}
			logger.Info("proxy authentication enabled", "backend", "htpasswd", "users", v.Users())
			verifier = v
		case "ldap":
			v, err := identity.NewLDAPVerifier(identity.LDAPConfig{
				URL: pa.LDAP.URL, BindDN: pa.LDAP.BindDN, BindPassword: pa.LDAP.BindPassword,
				BaseDN: pa.LDAP.BaseDN, UserFilter: pa.LDAP.UserFilter,
				MailAttr: pa.LDAP.MailAttr, ManagerAttr: pa.LDAP.ManagerAttr,
				StartTLS: pa.LDAP.StartTLS, Insecure: pa.LDAP.Insecure, Timeout: pa.LDAP.Timeout.Std(),
			})
			if err != nil {
				return nil, err
			}
			if pa.LDAP.Insecure {
				logger.Warn("identity.proxy_auth.ldap.insecure is on: the directory certificate is NOT verified")
			}
			logger.Info("proxy authentication enabled", "backend", "ldap", "url", pa.LDAP.URL)
			ldapVerifier, verifier = v, v
		default:
			return nil, fmt.Errorf("identity.proxy_auth.backend %q is not supported", pa.Backend)
		}
		auth, err := identity.NewProxyAuth(verifier, identity.ProxyAuthOptions{
			Realm: pa.Realm, ExemptCIDRs: pa.ExemptCIDRs, CacheTTL: pa.CacheTTL.Std(),
		})
		if err != nil {
			return nil, err
		}
		stack.ProxyAuth = auth
		stack.Chain = append(stack.Chain, auth)
		stack.Close = func() { _ = auth.Close() }
	}

	if cfg.Identity.ReverseDNS.Enabled {
		stack.Chain = append(stack.Chain, identity.NewReverseDNS(identity.ReverseDNSOptions{
			CacheTTL: cfg.Identity.ReverseDNS.CacheTTL.Std(),
			Timeout:  cfg.Identity.ReverseDNS.Timeout.Std(),
		}))
		logger.Info("workstation names resolved by reverse DNS")
	}

	switch {
	case cfg.Identity.Directory.CSV != "":
		d, err := identity.NewCSVDirectory(cfg.ResolvePath(cfg.Identity.Directory.CSV))
		if err != nil {
			return nil, err
		}
		logger.Info("user directory loaded", "source", "csv", "users", d.Users())
		stack.Directory = d
	case cfg.Identity.Directory.LDAP && ldapVerifier != nil:
		stack.Directory = identity.NewLDAPDirectory(ldapVerifier)
		logger.Info("user directory loaded", "source", "ldap")
	}
	return stack, nil
}

// buildAlerts assembles the alert engine, or returns nil when no rules are
// configured.
func buildAlerts(cfg *config.Config, history *audit.SQLiteStore, dir identity.Directory, logger *slog.Logger) (*alert.Engine, error) {
	if len(cfg.Alerts.Rules) == 0 {
		return nil, nil
	}
	tmplPaths := make([]string, 0, len(cfg.Alerts.Templates))
	for _, p := range cfg.Alerts.Templates {
		tmplPaths = append(tmplPaths, cfg.ResolvePath(p))
	}
	tmpl, err := alert.ParseTemplates(tmplPaths...)
	if err != nil {
		return nil, err
	}

	notifiers := map[string]alert.Notifier{}
	if cfg.Alerts.Email.Host != "" {
		n, err := alert.NewEmailNotifier(alert.EmailConfig{
			Host: cfg.Alerts.Email.Host, Port: cfg.Alerts.Email.Port, TLS: cfg.Alerts.Email.TLS,
			Username: cfg.Alerts.Email.Username, Password: cfg.Alerts.Email.Password,
			From: cfg.Alerts.Email.From, Timeout: cfg.Alerts.Email.Timeout.Std(),
		}, tmpl)
		if err != nil {
			return nil, err
		}
		notifiers["email"] = n
	}
	for _, w := range cfg.Alerts.Webhooks {
		n, err := alert.NewWebhookNotifier(w.Name, w.URL, w.Secret, w.Timeout.Std())
		if err != nil {
			return nil, err
		}
		notifiers["webhook:"+w.Name] = n
	}

	rules := make([]alert.Rule, 0, len(cfg.Alerts.Rules))
	for _, r := range cfg.Alerts.Rules {
		rule := alert.Rule{
			ID: r.ID, GroupBy: r.GroupBy, Threshold: r.Threshold,
			Window: r.Window.Std(), Cooldown: r.Cooldown.Std(), Template: r.Template,
			Match: alert.Match{
				Actions: r.Match.Actions, MinSeverity: r.Match.MinSeverity,
				Services: r.Match.Services, Rules: r.Match.Rules, Detectors: r.Match.Detectors,
			},
		}
		for _, n := range r.Notify {
			rule.Notify = append(rule.Notify, alert.Target{
				Type: n.Type, To: n.To, ToManager: n.ToManager, ToUser: n.ToUser, Webhook: n.Name,
			})
		}
		rules = append(rules, rule)
	}

	var store alert.Store
	if history != nil {
		store = alert.NewSQLiteStore(history)
	} else {
		store = alert.NewMemoryStore()
		logger.Warn("alerts are configured without audit.sqlite, so cooldowns and history are lost on restart")
	}

	engine := alert.New(alert.Options{
		Rules: rules, Store: store, Directory: dir, Notifiers: notifiers, Logger: logger,
	})
	var toUser bool
	for _, r := range cfg.Alerts.Rules {
		for _, n := range r.Notify {
			if n.ToUser {
				toUser = true
			}
		}
	}
	logger.Info("alerting enabled", "rules", len(rules), "notifiers", len(notifiers))
	if toUser {
		logger.Warn("an alert rule emails the person who triggered it; confirm this is allowed where your staff work")
	}
	return engine, nil
}

// alertTimeout bounds how long a notification may take before the audit
// pipeline moves on.
const alertTimeout = 30 * time.Second
