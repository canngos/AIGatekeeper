package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func sha256Sum(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// ReverseDNS names the workstation behind a client address. It is a
// best-effort hint, not authentication: a lookup that fails or takes too
// long simply leaves the device blank.
type ReverseDNS struct {
	ttl     time.Duration
	timeout time.Duration
	lookup  func(ctx context.Context, addr string) ([]string, error)

	mu    sync.Mutex
	cache map[string]rdnsEntry
	now   func() time.Time
}

type rdnsEntry struct {
	name    string
	expires time.Time
}

// ReverseDNSOptions configure the resolver.
type ReverseDNSOptions struct {
	CacheTTL time.Duration
	Timeout  time.Duration
	// Lookup overrides the resolver, for tests.
	Lookup func(ctx context.Context, addr string) ([]string, error)
}

// NewReverseDNS builds a cached reverse lookup resolver.
func NewReverseDNS(opts ReverseDNSOptions) *ReverseDNS {
	if opts.CacheTTL <= 0 {
		opts.CacheTTL = 10 * time.Minute
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 500 * time.Millisecond
	}
	lookup := opts.Lookup
	if lookup == nil {
		lookup = net.DefaultResolver.LookupAddr
	}
	return &ReverseDNS{ttl: opts.CacheTTL, timeout: opts.Timeout, lookup: lookup, cache: map[string]rdnsEntry{}, now: time.Now}
}

// Name implements Resolver.
func (r *ReverseDNS) Name() string { return "reverse_dns" }

// Resolve implements Resolver.
func (r *ReverseDNS) Resolve(ctx context.Context, _ *http.Request, clientIP net.IP) (Identity, bool) {
	if clientIP == nil {
		return Identity{}, false
	}
	key := clientIP.String()
	now := r.now()

	r.mu.Lock()
	entry, ok := r.cache[key]
	r.mu.Unlock()
	if ok && entry.expires.After(now) {
		return Identity{Device: entry.name}, entry.name != ""
	}

	lookupCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	names, err := r.lookup(lookupCtx, key)

	name := ""
	if err == nil && len(names) > 0 {
		name = shortHost(names[0])
	}
	r.mu.Lock()
	// Negative results are cached too, so an unresolvable address is not
	// looked up again on every request.
	r.cache[key] = rdnsEntry{name: name, expires: now.Add(r.ttl)}
	if len(r.cache) > 4096 {
		for k, v := range r.cache {
			if v.expires.Before(now) {
				delete(r.cache, k)
			}
		}
	}
	r.mu.Unlock()
	return Identity{Device: name}, name != ""
}

// shortHost trims the trailing dot and the domain, so LAPTOP-ALICE.corp.local
// is recorded as laptop-alice.
func shortHost(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if i := strings.IndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	return strings.ToLower(name)
}
