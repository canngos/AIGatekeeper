// Package policy compiles the configuration into the immutable, ready-to-use
// structures the proxy consults on every request, and evaluates requests
// against them.
package policy

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/canngos/aigatekeeper/internal/config"
)

// Service is a compiled config.ServiceConfig.
type Service struct {
	Name             string
	Hosts            []*regexp.Regexp
	Extractor        string
	BlockMode        string
	PassthroughPaths []*regexp.Regexp
	RuleIDs          []string
}

// MatchesHost reports whether host matches one of the service host patterns.
func (s *Service) MatchesHost(host string) bool {
	for _, re := range s.Hosts {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

// IsPassthroughPath reports whether the request path bypasses inspection.
func (s *Service) IsPassthroughPath(path string) bool {
	for _, re := range s.PassthroughPaths {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// Policy is the compiled, immutable view of a configuration.
type Policy struct {
	Config          *config.Config
	Hash            string
	Services        []*Service
	byName          map[string]*Service
	byListener      map[string]*Service
	TunnelUnmatched bool
	Monitor         bool
}

// Compile validates and compiles cfg. hash is the content hash of the source
// bytes (may be empty).
func Compile(cfg *config.Config, hash string) (*Policy, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	p := &Policy{
		Config:          cfg,
		Hash:            hash,
		byName:          make(map[string]*Service),
		byListener:      make(map[string]*Service),
		TunnelUnmatched: cfg.TunnelUnmatched,
		Monitor:         cfg.Mode.Monitor,
	}
	for _, sc := range cfg.Services {
		s := &Service{
			Name:      sc.Name,
			Extractor: sc.Extractor,
			BlockMode: sc.BlockMode,
			RuleIDs:   sc.Rules,
		}
		for _, h := range sc.Hosts {
			re, err := regexp.Compile(h)
			if err != nil {
				return nil, fmt.Errorf("service %s host %q: %w", sc.Name, h, err)
			}
			s.Hosts = append(s.Hosts, re)
		}
		for _, ph := range sc.PassthroughPaths {
			re, err := regexp.Compile(ph)
			if err != nil {
				return nil, fmt.Errorf("service %s passthrough path %q: %w", sc.Name, ph, err)
			}
			s.PassthroughPaths = append(s.PassthroughPaths, re)
		}
		p.Services = append(p.Services, s)
		p.byName[strings.ToLower(s.Name)] = s
	}
	for _, r := range cfg.Listen.Reverse {
		s := p.byName[strings.ToLower(r.Service)]
		if s == nil {
			return nil, fmt.Errorf("reverse listener %s: unknown service %q", r.Name, r.Service)
		}
		p.byListener[r.Name] = s
	}
	return p, nil
}

// ServiceForHost returns the first service whose host patterns match, or nil.
func (p *Policy) ServiceForHost(host string) *Service {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, s := range p.Services {
		if s.MatchesHost(host) {
			return s
		}
	}
	return nil
}

// ServiceForListener returns the service bound to a reverse listener, or nil.
func (p *Policy) ServiceForListener(name string) *Service {
	return p.byListener[name]
}

// ServiceByName returns the named service, or nil.
func (p *Policy) ServiceByName(name string) *Service {
	return p.byName[strings.ToLower(name)]
}

// Intercept reports whether CONNECTs to host should be decrypted.
func (p *Policy) Intercept(host string) bool {
	return p.ServiceForHost(host) != nil
}
