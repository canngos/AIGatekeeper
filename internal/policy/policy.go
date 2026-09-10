// Package policy compiles the configuration into the immutable, ready-to-use
// structures the proxy consults on every request, and evaluates requests
// against them.
package policy

import (
	"crypto/subtle"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/canngos/aigatekeeper/internal/config"
	"github.com/canngos/aigatekeeper/internal/dlp"
)

// Service is a compiled config.ServiceConfig.
type Service struct {
	Name             string
	Hosts            []*regexp.Regexp
	Extractor        string
	BlockMode        string
	PassthroughPaths []*regexp.Regexp
	Rules            []*Rule
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

// RuleIDs lists the rule identifiers attached to the service.
func (s *Service) RuleIDs() []string {
	out := make([]string, len(s.Rules))
	for i, r := range s.Rules {
		out[i] = r.ID
	}
	return out
}

// Rule is a compiled config.RuleConfig: a scanner plus the action to take.
type Rule struct {
	ID       string
	Severity string
	Action   string // block | monitor | allow; empty = policy default
	Scanner  dlp.Scanner
}

// Allowlist holds the compiled exceptions that bypass or soften scanning.
type Allowlist struct {
	Values       *dlp.Allowlist
	ClientCIDRs  []*net.IPNet
	HeaderName   string
	HeaderToken  string
	SegmentGlobs []string
}

// SkipSegment reports whether a JSON pointer path is exempt from scanning.
func (a *Allowlist) SkipSegment(path string) bool {
	for _, g := range a.SegmentGlobs {
		if MatchSegmentGlob(g, path) {
			return true
		}
	}
	return false
}

// ClientBypasses reports whether the client IP is in an exempt CIDR.
func (a *Allowlist) ClientBypasses(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range a.ClientCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// HeaderBypasses reports whether the request carries the bypass token.
func (a *Allowlist) HeaderBypasses(value string) bool {
	if a.HeaderToken == "" || value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(value), []byte(a.HeaderToken)) == 1
}

// MatchSegmentGlob matches JSON pointer paths against globs where "*"
// matches one path element and "**" matches any remaining elements.
func MatchSegmentGlob(glob, path string) bool {
	g := strings.Split(strings.Trim(glob, "/"), "/")
	p := strings.Split(strings.Trim(path, "/"), "/")
	return matchGlobParts(g, p)
}

func matchGlobParts(g, p []string) bool {
	for len(g) > 0 {
		switch g[0] {
		case "**":
			if len(g) == 1 {
				return true
			}
			for i := 0; i <= len(p); i++ {
				if matchGlobParts(g[1:], p[i:]) {
					return true
				}
			}
			return false
		case "*":
			if len(p) == 0 {
				return false
			}
		default:
			if len(p) == 0 || g[0] != p[0] {
				return false
			}
		}
		g, p = g[1:], p[1:]
	}
	return len(p) == 0
}

// Policy is the compiled, immutable view of a configuration.
type Policy struct {
	Config          *config.Config
	Hash            string
	Services        []*Service
	Rules           map[string]*Rule
	Allowlist       *Allowlist
	TunnelUnmatched bool
	Monitor         bool
	DefaultAction   string
	OversizeAction  string
	ParseErrAction  string
	BlockMessage    string

	byName     map[string]*Service
	byListener map[string]*Service
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
		Rules:           make(map[string]*Rule),
		byName:          make(map[string]*Service),
		byListener:      make(map[string]*Service),
		TunnelUnmatched: cfg.TunnelUnmatched,
		Monitor:         cfg.Mode.Monitor,
		DefaultAction:   cfg.DefaultAction,
		OversizeAction:  cfg.Limits.OversizeAction,
		ParseErrAction:  cfg.Limits.ParseErrorAction,
		BlockMessage:    cfg.BlockMessage,
	}

	al, err := compileAllowlist(cfg.Allowlist)
	if err != nil {
		return nil, err
	}
	p.Allowlist = al

	scanOpts := dlp.Options{Allowlist: al.Values, SkipSegment: al.SkipSegment}
	for _, rc := range cfg.Rules {
		rule, err := compileRule(cfg, rc, scanOpts)
		if err != nil {
			return nil, err
		}
		p.Rules[rule.ID] = rule
	}

	for _, sc := range cfg.Services {
		s := &Service{Name: sc.Name, Extractor: sc.Extractor, BlockMode: sc.BlockMode}
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
		for _, id := range sc.Rules {
			r, ok := p.Rules[id]
			if !ok {
				return nil, fmt.Errorf("service %s: unknown rule %q", sc.Name, id)
			}
			s.Rules = append(s.Rules, r)
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

func compileAllowlist(ac config.AllowlistConfig) (*Allowlist, error) {
	values, err := dlp.NewAllowlist(ac.Values, ac.Patterns, ac.EmailDomains)
	if err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	al := &Allowlist{
		Values:       values,
		HeaderName:   ac.HeaderBypass.Name,
		HeaderToken:  ac.HeaderBypass.Token,
		SegmentGlobs: ac.SegmentPaths,
	}
	for _, cidr := range ac.ClientCIDRs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("allowlist client_cidrs %q: %w", cidr, err)
		}
		al.ClientCIDRs = append(al.ClientCIDRs, n)
	}
	return al, nil
}

func compileRule(cfg *config.Config, rc config.RuleConfig, opts dlp.Options) (*Rule, error) {
	var detectors []dlp.Detector
	for _, id := range rc.Detectors {
		d, err := dlp.NewBuiltin(id, rc.Options[id])
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rc.ID, err)
		}
		if d != nil {
			detectors = append(detectors, d)
		}
	}
	for _, rx := range rc.Regex {
		d, err := dlp.NewCustomRegexDetector(rx.ID, rc.Severity, rx.Pattern, rx.MinLength)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rc.ID, err)
		}
		detectors = append(detectors, d)
	}
	keywords := append([]string(nil), rc.Keywords.List...)
	if rc.Keywords.File != "" {
		fromFile, err := dlp.LoadKeywordFile(cfg.ResolvePath(rc.Keywords.File))
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rc.ID, err)
		}
		keywords = append(keywords, fromFile...)
	}
	if len(keywords) > 0 {
		d, err := dlp.NewKeywordDetector("keyword:"+rc.ID, rc.Severity, keywords, dlp.KeywordOptions{
			CaseInsensitive: rc.Keywords.CaseInsensitive,
			WordBoundary:    rc.Keywords.WordBoundary,
		})
		if err != nil {
			return nil, err
		}
		detectors = append(detectors, d)
	}
	return &Rule{
		ID:       rc.ID,
		Severity: rc.Severity,
		Action:   rc.Action,
		Scanner:  dlp.NewScanner(rc.ID, detectors, opts),
	}, nil
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
