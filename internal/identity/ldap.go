package identity

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig points at a directory server.
type LDAPConfig struct {
	URL          string // ldaps://dc.corp.local:636 or ldap://...
	BindDN       string // service account used to look up users; optional
	BindPassword string
	BaseDN       string
	UserFilter   string // {user} is replaced with the escaped account name
	MailAttr     string
	ManagerAttr  string
	StartTLS     bool
	Insecure     bool // skip certificate verification; lab use only
	Timeout      time.Duration
}

// LDAPVerifier authenticates a user by binding as them, which is the only
// way to check a password without the directory handing one out.
type LDAPVerifier struct {
	cfg LDAPConfig
	mu  sync.Mutex

	// dial is overridable for tests.
	dial func(cfg LDAPConfig) (ldapConn, error)
}

// ldapConn is the slice of the client this package uses.
type ldapConn interface {
	Bind(username, password string) error
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// NewLDAPVerifier validates the configuration and returns a verifier.
func NewLDAPVerifier(cfg LDAPConfig) (*LDAPVerifier, error) {
	if cfg.URL == "" {
		return nil, errors.New("identity.proxy_auth.ldap.url is required")
	}
	if cfg.BaseDN == "" {
		return nil, errors.New("identity.proxy_auth.ldap.base_dn is required")
	}
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(sAMAccountName={user})"
	}
	if !strings.Contains(cfg.UserFilter, "{user}") {
		return nil, errors.New("identity.proxy_auth.ldap.user_filter must contain {user}")
	}
	if cfg.MailAttr == "" {
		cfg.MailAttr = "mail"
	}
	if cfg.ManagerAttr == "" {
		cfg.ManagerAttr = "manager"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &LDAPVerifier{cfg: cfg, dial: dialLDAP}, nil
}

// Name implements Verifier.
func (v *LDAPVerifier) Name() string { return "ldap" }

// Close implements Verifier.
func (v *LDAPVerifier) Close() error { return nil }

func dialLDAP(cfg LDAPConfig) (ldapConn, error) {
	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: cfg.Timeout})}
	if strings.HasPrefix(cfg.URL, "ldaps://") {
		opts = append(opts, ldap.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: cfg.Insecure, //nolint:gosec // explicit operator opt-in
			MinVersion:         tls.VersionTLS12,
		}))
	}
	conn, err := ldap.DialURL(cfg.URL, opts...)
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(cfg.Timeout)
	if cfg.StartTLS {
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: cfg.Insecure, MinVersion: tls.VersionTLS12}); err != nil { //nolint:gosec
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// Verify binds as the user and reads their contact attributes.
func (v *LDAPVerifier) Verify(ctx context.Context, user, password string) (Identity, bool) {
	if password == "" {
		return Identity{}, false // an empty password is an anonymous bind, which would succeed
	}
	conn, err := v.dial(v.cfg)
	if err != nil {
		return Identity{}, false
	}
	defer conn.Close()

	// Find the user's DN with the service account, then bind as the user.
	if v.cfg.BindDN != "" {
		if err := conn.Bind(v.cfg.BindDN, v.cfg.BindPassword); err != nil {
			return Identity{}, false
		}
	}
	filter := strings.ReplaceAll(v.cfg.UserFilter, "{user}", ldap.EscapeFilter(user))
	res, err := conn.Search(ldap.NewSearchRequest(
		v.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(v.cfg.Timeout.Seconds()), false,
		filter, []string{"dn", v.cfg.MailAttr, v.cfg.ManagerAttr}, nil,
	))
	if err != nil || len(res.Entries) != 1 {
		return Identity{}, false
	}
	entry := res.Entries[0]
	if err := conn.Bind(entry.DN, password); err != nil {
		return Identity{}, false
	}
	return Identity{
		User:    normalizeUser(user),
		Email:   entry.GetAttributeValue(v.cfg.MailAttr),
		Manager: entry.GetAttributeValue(v.cfg.ManagerAttr),
	}, true
}

// LDAPDirectory looks up contact details without authenticating, for
// notifications about users identified some other way.
type LDAPDirectory struct{ v *LDAPVerifier }

// NewLDAPDirectory wraps a verifier's connection settings as a Directory.
func NewLDAPDirectory(v *LDAPVerifier) *LDAPDirectory { return &LDAPDirectory{v: v} }

// Lookup implements Directory.
func (d *LDAPDirectory) Lookup(_ context.Context, user string) (string, string, error) {
	cfg := d.v.cfg
	if cfg.BindDN == "" {
		return "", "", errors.New("ldap directory lookups need a bind_dn")
	}
	conn, err := d.v.dial(cfg)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return "", "", err
	}
	filter := strings.ReplaceAll(cfg.UserFilter, "{user}", ldap.EscapeFilter(user))
	res, err := conn.Search(ldap.NewSearchRequest(
		cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(cfg.Timeout.Seconds()), false,
		filter, []string{"dn", cfg.MailAttr, cfg.ManagerAttr}, nil,
	))
	if err != nil {
		return "", "", err
	}
	if len(res.Entries) == 0 {
		return "", "", fmt.Errorf("user %q not found in the directory", user)
	}
	e := res.Entries[0]
	return e.GetAttributeValue(cfg.MailAttr), e.GetAttributeValue(cfg.ManagerAttr), nil
}
