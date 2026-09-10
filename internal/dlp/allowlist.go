package dlp

import (
	"fmt"
	"regexp"
	"strings"
)

// Allowlist suppresses findings whose matched value is known-safe.
type Allowlist struct {
	values       map[string]struct{}
	patterns     []*regexp.Regexp
	emailDomains map[string]struct{}
}

// NewAllowlist compiles literal values, regex patterns and email domains.
func NewAllowlist(values, patterns, emailDomains []string) (*Allowlist, error) {
	a := &Allowlist{values: map[string]struct{}{}, emailDomains: map[string]struct{}{}}
	for _, v := range values {
		a.values[strings.TrimSpace(v)] = struct{}{}
	}
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("allowlist pattern %q: %w", p, err)
		}
		a.patterns = append(a.patterns, re)
	}
	for _, d := range emailDomains {
		a.emailDomains[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
	}
	return a, nil
}

// Allows reports whether the matched value is allow-listed.
func (a *Allowlist) Allows(value string) bool {
	if a == nil {
		return false
	}
	if _, ok := a.values[strings.TrimSpace(value)]; ok {
		return true
	}
	for _, re := range a.patterns {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

// AllowsEmailDomain reports whether domain (or a parent domain) is allowed.
func (a *Allowlist) AllowsEmailDomain(domain string) bool {
	if a == nil {
		return false
	}
	domain = strings.ToLower(domain)
	for {
		if _, ok := a.emailDomains[domain]; ok {
			return true
		}
		dot := strings.IndexByte(domain, '.')
		if dot < 0 {
			return false
		}
		domain = domain[dot+1:]
	}
}
