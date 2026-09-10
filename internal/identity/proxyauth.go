package identity

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ProxyAuthHeader is the header a client sends credentials in.
const ProxyAuthHeader = "Proxy-Authorization"

// Verifier checks a user's password.
type Verifier interface {
	Name() string
	// Verify reports whether the credentials are valid, and returns any
	// contact details the backend knows.
	Verify(ctx context.Context, user, password string) (Identity, bool)
	Close() error
}

// ProxyAuth authenticates callers from the Proxy-Authorization header.
// Requests without valid credentials are answered with 407 by the proxy,
// which makes clients retry with the credentials configured for the proxy.
type ProxyAuth struct {
	verifier    Verifier
	realm       string
	exempt      []*net.IPNet
	cacheTTL    time.Duration
	mu          sync.Mutex
	cache       map[string]cachedAuth
	now         func() time.Time
	failures    int64
	successes   int64
	cacheHits   int64
	cacheMisses int64
}

type cachedAuth struct {
	id      Identity
	hash    string // hash of the presented password, so a changed password re-verifies
	expires time.Time
}

// ProxyAuthOptions configure ProxyAuth.
type ProxyAuthOptions struct {
	Realm       string
	ExemptCIDRs []string
	CacheTTL    time.Duration
}

// NewProxyAuth builds a proxy authenticator over a verifier.
func NewProxyAuth(v Verifier, opts ProxyAuthOptions) (*ProxyAuth, error) {
	if opts.Realm == "" {
		opts.Realm = "AIGatekeeper"
	}
	if opts.CacheTTL <= 0 {
		opts.CacheTTL = 5 * time.Minute
	}
	p := &ProxyAuth{verifier: v, realm: opts.Realm, cacheTTL: opts.CacheTTL, cache: map[string]cachedAuth{}, now: time.Now}
	for _, c := range opts.ExemptCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("identity.proxy_auth.exempt_cidrs %q: %w", c, err)
		}
		p.exempt = append(p.exempt, n)
	}
	return p, nil
}

// Name implements Resolver.
func (p *ProxyAuth) Name() string { return "proxy_auth" }

// Realm returns the realm offered in the challenge.
func (p *ProxyAuth) Realm() string { return p.realm }

// Exempt reports whether a client address skips authentication.
func (p *ProxyAuth) Exempt(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range p.exempt {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Resolve implements Resolver: it validates the header if present.
func (p *ProxyAuth) Resolve(ctx context.Context, r *http.Request, clientIP net.IP) (Identity, bool) {
	id, ok, _ := p.Authenticate(ctx, r, clientIP)
	return id, ok
}

// Authenticate validates the Proxy-Authorization header. The third result
// says whether the request may proceed: exempt clients proceed unnamed.
func (p *ProxyAuth) Authenticate(ctx context.Context, r *http.Request, clientIP net.IP) (Identity, bool, bool) {
	if p.Exempt(clientIP) {
		return Identity{}, false, true
	}
	user, password, ok := parseBasic(r.Header.Get(ProxyAuthHeader))
	if !ok {
		return Identity{}, false, false
	}
	if id, hit := p.fromCache(user, password); hit {
		return id, true, true
	}
	id, valid := p.verifier.Verify(ctx, user, password)
	p.mu.Lock()
	if valid {
		p.successes++
		id.User = normalizeUser(user)
		p.cache[id.User] = cachedAuth{id: id, hash: passwordFingerprint(password), expires: p.now().Add(p.cacheTTL)}
	} else {
		p.failures++
	}
	p.mu.Unlock()
	if !valid {
		return Identity{}, false, false
	}
	return id, true, true
}

func (p *ProxyAuth) fromCache(user, password string) (Identity, bool) {
	key := normalizeUser(user)
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.cache[key]
	if !ok || entry.expires.Before(p.now()) || entry.hash != passwordFingerprint(password) {
		p.cacheMisses++
		return Identity{}, false
	}
	p.cacheHits++
	return entry.id, true
}

// Stats reports authentication counters for the status endpoint.
func (p *ProxyAuth) Stats() map[string]int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return map[string]int64{
		"successes": p.successes, "failures": p.failures,
		"cache_hits": p.cacheHits, "cache_misses": p.cacheMisses, "cached_users": int64(len(p.cache)),
	}
}

// Close releases the verifier.
func (p *ProxyAuth) Close() error {
	if p.verifier == nil {
		return nil
	}
	return p.verifier.Close()
}

// Challenge writes the 407 response that asks a client for credentials.
func (p *ProxyAuth) Challenge(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="`+p.realm+`", charset="UTF-8"`)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusProxyAuthRequired)
	_, _ = w.Write([]byte("AIGatekeeper requires proxy credentials.\n"))
}

// ChallengeRaw writes the 407 directly to a hijacked connection, for the
// CONNECT path where the response writer is no longer usable.
func ChallengeRaw(realm string) []byte {
	body := "AIGatekeeper requires proxy credentials.\n"
	return []byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
		`Proxy-Authenticate: Basic realm="` + realm + `", charset="UTF-8"` + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"Connection: close\r\n\r\n" + body)
}

func parseBasic(header string) (user, password string, ok bool) {
	const prefix = "basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	user, password, found := strings.Cut(string(raw), ":")
	if !found || user == "" {
		return "", "", false
	}
	return user, password, true
}

// passwordFingerprint keys the cache without keeping the password around.
func passwordFingerprint(password string) string {
	sum := sha256Sum(password)
	return sum
}

// HtpasswdVerifier checks credentials against a bcrypt htpasswd-style file
// that is re-read when it changes on disk.
type HtpasswdVerifier struct {
	path string

	mu      sync.RWMutex
	users   map[string]string // user -> bcrypt hash
	modTime time.Time
	size    int64
}

// NewHtpasswdVerifier loads the file once; later changes are picked up.
func NewHtpasswdVerifier(path string) (*HtpasswdVerifier, error) {
	v := &HtpasswdVerifier{path: path, users: map[string]string{}}
	if err := v.reload(); err != nil {
		return nil, err
	}
	return v, nil
}

// Name implements Verifier.
func (v *HtpasswdVerifier) Name() string { return "htpasswd" }

// Close implements Verifier.
func (v *HtpasswdVerifier) Close() error { return nil }

// Users returns how many accounts are loaded.
func (v *HtpasswdVerifier) Users() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.users)
}

func (v *HtpasswdVerifier) reload() error {
	info, err := os.Stat(v.path)
	if err != nil {
		return fmt.Errorf("read user file: %w", err)
	}
	v.mu.RLock()
	unchanged := info.ModTime().Equal(v.modTime) && info.Size() == v.size
	v.mu.RUnlock()
	if unchanged {
		return nil
	}
	f, err := os.Open(v.path)
	if err != nil {
		return fmt.Errorf("read user file: %w", err)
	}
	defer f.Close()

	users := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, hash, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		hash = strings.TrimSpace(hash)
		if !strings.HasPrefix(hash, "$2") {
			// Only bcrypt is accepted; MD5 and SHA1 htpasswd formats are
			// too weak to guard a network credential.
			continue
		}
		users[normalizeUser(name)] = hash
	}
	if err := sc.Err(); err != nil {
		return err
	}
	v.mu.Lock()
	v.users, v.modTime, v.size = users, info.ModTime(), info.Size()
	v.mu.Unlock()
	return nil
}

// Verify implements Verifier.
func (v *HtpasswdVerifier) Verify(_ context.Context, user, password string) (Identity, bool) {
	_ = v.reload() // a failed reload keeps the last good table
	v.mu.RLock()
	hash, ok := v.users[normalizeUser(user)]
	v.mu.RUnlock()
	if !ok {
		// Compare against a dummy hash anyway so a missing user and a wrong
		// password take a similar amount of time.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"), []byte(password))
		return Identity{}, false
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return Identity{}, false
	}
	return Identity{User: normalizeUser(user)}, true
}
