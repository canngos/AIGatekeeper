package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// AuthConfig holds the single admin credential.
type AuthConfig struct {
	PasswordHash string        // bcrypt hash; empty disables password login
	Token        string        // static bearer token; empty disables token auth
	SessionTTL   time.Duration // sliding session lifetime (default 12h)
	// LoginBurst and LoginPerMinute bound login attempts per client IP.
	LoginBurst     int
	LoginPerMinute int
}

// Configured reports whether any credential is set.
func (c AuthConfig) Configured() bool { return c.PasswordHash != "" || c.Token != "" }

const (
	sessionCookie = "aigk_session"
	csrfCookie    = "aigk_csrf"
	csrfHeader    = "X-CSRF-Token"
)

// authMethod identifies how a request was authenticated.
type authMethod string

const (
	authNone    authMethod = ""
	authSession authMethod = "session"
	authToken   authMethod = "token"
)

type session struct {
	csrf    string
	expires time.Time
}

// authenticator implements login, sessions, CSRF and rate limiting.
type authenticator struct {
	cfg AuthConfig

	mu       sync.Mutex
	sessions map[string]*session
	attempts map[string]*bucket
	now      func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newAuthenticator(cfg AuthConfig) *authenticator {
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if cfg.LoginBurst <= 0 {
		cfg.LoginBurst = 5
	}
	if cfg.LoginPerMinute <= 0 {
		cfg.LoginPerMinute = 5
	}
	return &authenticator{cfg: cfg, sessions: map[string]*session{}, attempts: map[string]*bucket{}, now: time.Now}
}

// HashPassword produces a bcrypt hash for the configuration file.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// allowAttempt applies a token bucket per client IP to login attempts.
func (a *authenticator) allowAttempt(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	b, ok := a.attempts[ip]
	if !ok {
		b = &bucket{tokens: float64(a.cfg.LoginBurst), last: now}
		a.attempts[ip] = b
	}
	refill := now.Sub(b.last).Minutes() * float64(a.cfg.LoginPerMinute)
	b.tokens = min(float64(a.cfg.LoginBurst), b.tokens+refill)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	if len(a.attempts) > 10000 { // bound memory under scanning
		for k, v := range a.attempts {
			if now.Sub(v.last) > time.Hour {
				delete(a.attempts, k)
			}
		}
	}
	return true
}

// checkPassword verifies a password against the configured hash.
func (a *authenticator) checkPassword(password string) bool {
	if a.cfg.PasswordHash == "" || password == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(a.cfg.PasswordHash), []byte(password)) == nil
}

// checkToken verifies a bearer token in constant time.
func (a *authenticator) checkToken(token string) bool {
	if a.cfg.Token == "" || token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(a.cfg.Token)) == 1
}

// createSession returns a new session id, its CSRF token and expiry.
func (a *authenticator) createSession() (id, csrf string, expires time.Time) {
	id, csrf = randomToken(), randomToken()
	expires = a.now().Add(a.cfg.SessionTTL)
	a.mu.Lock()
	a.sessions[id] = &session{csrf: csrf, expires: expires}
	if len(a.sessions) > 1000 {
		for k, s := range a.sessions {
			if s.expires.Before(a.now()) {
				delete(a.sessions, k)
			}
		}
	}
	a.mu.Unlock()
	return id, csrf, expires
}

// lookupSession validates and slides a session.
func (a *authenticator) lookupSession(id string) (*session, bool) {
	if id == "" {
		return nil, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[id]
	if !ok {
		return nil, false
	}
	now := a.now()
	if s.expires.Before(now) {
		delete(a.sessions, id)
		return nil, false
	}
	s.expires = now.Add(a.cfg.SessionTTL)
	copyS := *s
	return &copyS, true
}

func (a *authenticator) deleteSession(id string) {
	a.mu.Lock()
	delete(a.sessions, id)
	a.mu.Unlock()
}

// authenticate resolves the caller's auth method and session.
func (a *authenticator) authenticate(r *http.Request) (authMethod, *session) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
		if a.checkToken(strings.TrimSpace(h[7:])) {
			return authToken, nil
		}
		return authNone, nil
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if s, ok := a.lookupSession(c.Value); ok {
			return authSession, s
		}
	}
	return authNone, nil
}

// csrfOK enforces double-submit CSRF for cookie sessions on unsafe methods.
func csrfOK(r *http.Request, s *session) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	hdr := r.Header.Get(csrfHeader)
	c, err := r.Cookie(csrfCookie)
	if hdr == "" || err != nil || c.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hdr), []byte(c.Value)) == 1 &&
		subtle.ConstantTimeCompare([]byte(hdr), []byte(s.csrf)) == 1
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func secureCookies(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
