package ca

import (
	"container/list"
	"crypto/tls"
	"sync"
	"time"
)

// DefaultCacheSize bounds the number of leaf certificates kept in memory.
const DefaultCacheSize = 1024

// refreshFraction is the point in a leaf's lifetime at which it is reissued.
const refreshFraction = 0.8

// Cache is an LRU cache of issued leaf certificates keyed by host. Leaves are
// reissued once they pass 80% of their TTL so clients never see one expire.
type Cache struct {
	signer *Signer
	max    int
	now    func() time.Time

	mu      sync.Mutex
	entries map[string]*list.Element
	lru     *list.List

	hits, misses uint64
}

type cacheEntry struct {
	host    string
	cert    *tls.Certificate
	refresh time.Time
}

// NewCache wraps signer with an LRU cache holding at most max leaves.
func NewCache(signer *Signer, max int) *Cache {
	if max <= 0 {
		max = DefaultCacheSize
	}
	return &Cache{
		signer:  signer,
		max:     max,
		now:     time.Now,
		entries: make(map[string]*list.Element),
		lru:     list.New(),
	}
}

// Get returns a valid leaf certificate for host, issuing one if necessary.
func (c *Cache) Get(host string) (*tls.Certificate, error) {
	host = NormalizeHost(host)
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.entries[host]; ok {
		e := el.Value.(*cacheEntry)
		if c.now().Before(e.refresh) {
			c.lru.MoveToFront(el)
			c.hits++
			return e.cert, nil
		}
		c.lru.Remove(el)
		delete(c.entries, host)
	}
	c.misses++

	cert, err := c.signer.Sign(host)
	if err != nil {
		return nil, err
	}
	ttl := c.signer.TTL()
	e := &cacheEntry{
		host:    host,
		cert:    cert,
		refresh: c.now().Add(time.Duration(float64(ttl) * refreshFraction)),
	}
	c.entries[host] = c.lru.PushFront(e)
	for c.lru.Len() > c.max {
		oldest := c.lru.Back()
		c.lru.Remove(oldest)
		delete(c.entries, oldest.Value.(*cacheEntry).host)
	}
	return cert, nil
}

// GetCertificate adapts the cache to tls.Config.GetCertificate. When the
// client sends no SNI the fallback host is used, which the proxy sets to the
// CONNECT target.
func (c *Cache) GetCertificate(fallbackHost string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := hello.ServerName
		if name == "" {
			name = fallbackHost
		}
		return c.Get(name)
	}
}

// Len returns the number of cached leaves.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// Stats returns cache hit and miss counters.
func (c *Cache) Stats() (hits, misses uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses
}
