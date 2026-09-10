package policy

import "sync/atomic"

// Store holds the live policy and lets it be swapped atomically on reload.
// Readers never block; they see either the old or the new policy in full.
type Store struct {
	p atomic.Pointer[Policy]
}

// NewStore creates a store holding p.
func NewStore(p *Policy) *Store {
	s := &Store{}
	s.p.Store(p)
	return s
}

// Load returns the current policy.
func (s *Store) Load() *Policy { return s.p.Load() }

// Swap installs p and returns the previous policy.
func (s *Store) Swap(p *Policy) *Policy { return s.p.Swap(p) }

// Hash returns the content hash of the current policy.
func (s *Store) Hash() string {
	if p := s.p.Load(); p != nil {
		return p.Hash
	}
	return ""
}

// Intercept adapts the store to the proxy's intercept callback.
func (s *Store) Intercept(host string) bool {
	p := s.p.Load()
	return p != nil && p.Intercept(host)
}

// TunnelUnmatched adapts the store to the proxy's tunnel policy callback.
func (s *Store) TunnelUnmatched() bool {
	p := s.p.Load()
	return p != nil && p.TunnelUnmatched
}
