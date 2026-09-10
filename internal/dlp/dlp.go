// Package dlp scans extracted prompt text for secrets, personal data and
// organisation-specific terms. Detectors return matches; the Scanner
// applies allow-lists, placeholder filtering and de-duplication and emits
// findings that carry only a masked preview of the matched value.
package dlp

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/canngos/aigatekeeper/internal/parser"
)

// Severity levels, ordered from least to most severe.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// SeverityRank orders severities for comparisons; unknown values rank lowest.
func SeverityRank(s string) int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	}
	return 0
}

// Match is a raw detector hit. Value is the matched text and never leaves
// this package unmasked.
type Match struct {
	Offset     int
	Length     int
	Value      string
	Confidence float64 // 0..1; 1 when validated structurally
}

// Detector finds one class of sensitive data in a piece of text.
type Detector interface {
	ID() string
	Severity() string
	Detect(text string) []Match
}

// Finding is the audit-safe result of a detector hit.
type Finding struct {
	Detector   string  `json:"detector"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	Segment    string  `json:"segment"`
	Role       string  `json:"role,omitempty"`
	Offset     int     `json:"offset"`
	Length     int     `json:"length"`
	Preview    string  `json:"preview"`
}

// Scanner runs a set of detectors over an extraction.
type Scanner interface {
	Name() string
	Scan(ctx context.Context, ex *parser.Extraction) ([]Finding, error)
}

// Options tune a RegexScanner.
type Options struct {
	Allowlist       *Allowlist
	SkipSegment     func(path string) bool
	MaxFindings     int     // cap per scan; 0 = 100
	AssistantWeight float64 // confidence multiplier for assistant-role segments; 0 = 1
}

// RegexScanner is the built-in Scanner over regex/heuristic detectors.
type RegexScanner struct {
	name      string
	detectors []Detector
	opts      Options
}

// NewScanner creates a scanner named name over detectors.
func NewScanner(name string, detectors []Detector, opts Options) *RegexScanner {
	if opts.MaxFindings <= 0 {
		opts.MaxFindings = 100
	}
	if opts.AssistantWeight <= 0 {
		opts.AssistantWeight = 1
	}
	return &RegexScanner{name: name, detectors: detectors, opts: opts}
}

// Name implements Scanner.
func (s *RegexScanner) Name() string { return s.name }

// Detectors returns the configured detectors.
func (s *RegexScanner) Detectors() []Detector { return s.detectors }

// Scan implements Scanner.
func (s *RegexScanner) Scan(ctx context.Context, ex *parser.Extraction) ([]Finding, error) {
	if ex == nil {
		return nil, nil
	}
	var findings []Finding
	seen := map[string]struct{}{}
	for _, seg := range ex.Segments {
		if err := ctx.Err(); err != nil {
			return findings, err
		}
		if s.opts.SkipSegment != nil && s.opts.SkipSegment(seg.Path) {
			continue
		}
		for _, d := range s.detectors {
			for _, m := range d.Detect(seg.Text) {
				if s.suppressed(d, m) {
					continue
				}
				key := d.ID() + "\x00" + m.Value
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				conf := m.Confidence
				if conf <= 0 {
					conf = 1
				}
				if seg.Role == parser.RoleAssistant {
					conf *= s.opts.AssistantWeight
				}
				findings = append(findings, Finding{
					Detector:   d.ID(),
					Severity:   d.Severity(),
					Confidence: conf,
					Segment:    seg.Path,
					Role:       seg.Role,
					Offset:     m.Offset,
					Length:     m.Length,
					Preview:    Redact(m.Value),
				})
				if len(findings) >= s.opts.MaxFindings {
					return findings, nil
				}
			}
		}
	}
	return findings, nil
}

func (s *RegexScanner) suppressed(d Detector, m Match) bool {
	if IsPlaceholder(m.Value) {
		return true
	}
	if s.opts.Allowlist == nil {
		return false
	}
	if s.opts.Allowlist.Allows(m.Value) {
		return true
	}
	if d.ID() == IDEmail {
		if at := strings.LastIndexByte(m.Value, '@'); at >= 0 && s.opts.Allowlist.AllowsEmailDomain(m.Value[at+1:]) {
			return true
		}
	}
	return false
}

// Info describes a built-in detector for documentation and the admin UI.
//
// ID is what configuration and audit records use. Name and Group exist so
// the console can offer detectors in the words a security lead would use,
// rather than making them read identifiers.
type Info struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Group       string       `json:"group"`
	Description string       `json:"description"`
	Severity    string       `json:"severity"`
	Options     []OptionInfo `json:"options,omitempty"`
	// Deprecated marks a detector kept only so existing configuration and
	// audit history keep working. The console offers it only to a rule that
	// already uses it, alongside its replacement.
	Deprecated bool   `json:"deprecated,omitempty"`
	ReplacedBy string `json:"replaced_by,omitempty"`
}

// Detector groups, in the order the console shows them.
const (
	GroupKeys     = "Keys and tokens"
	GroupPersonal = "Personal data"
)

// GroupOrder lists the groups in presentation order.
var GroupOrder = []string{GroupKeys, GroupPersonal}

// OptionInfo documents one tunable of a detector.
type OptionInfo struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Type        string `json:"type"` // bool | number | string | prefix_list
	Default     any    `json:"default"`
	Description string `json:"description"`
}

// Builtin detector identifiers.
const (
	IDAccessKeys   = "access_keys"
	IDAWSAccessKey = "aws_access_key" // deprecated: use IDAccessKeys

	IDAWSSecretKey      = "aws_secret_key"
	IDGitHubToken       = "github_token"
	IDSlackToken        = "slack_token"
	IDGoogleAPIKey      = "google_api_key"
	IDOpenAIKey         = "openai_key"
	IDAnthropicKey      = "anthropic_key"
	IDJWT               = "jwt"
	IDPrivateKey        = "private_key"
	IDHighEntropySecret = "high_entropy_secret"
	IDCreditCard        = "credit_card"
	IDEmail             = "email"
	IDUSSSN             = "us_ssn"
	IDIBAN              = "iban"
)

type builtinFactory struct {
	info Info
	make func(opts map[string]any) (Detector, error)
}

var builtins = map[string]builtinFactory{}

func register(info Info, mk func(opts map[string]any) (Detector, error)) {
	builtins[info.ID] = builtinFactory{info: info, make: mk}
}

// Builtin lists the built-in detectors, sorted by ID.
func Builtin() []Info {
	out := make([]Info, 0, len(builtins))
	for _, f := range builtins {
		out = append(out, f.info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// IsBuiltin reports whether id names a built-in detector.
func IsBuiltin(id string) bool {
	_, ok := builtins[id]
	return ok
}

// NewBuiltin instantiates a built-in detector with per-deployment options.
// It returns (nil, nil) when opts disable the detector via "enabled: false".
func NewBuiltin(id string, opts map[string]any) (Detector, error) {
	f, ok := builtins[id]
	if !ok {
		return nil, fmt.Errorf("unknown detector %q", id)
	}
	if enabled, present := optBool(opts, "enabled", true); present && !enabled {
		return nil, nil
	}
	return f.make(opts)
}

func optBool(opts map[string]any, key string, def bool) (bool, bool) {
	if opts == nil {
		return def, false
	}
	v, ok := opts[key]
	if !ok {
		return def, false
	}
	b, ok := v.(bool)
	if !ok {
		return def, false
	}
	return b, true
}

func optFloat(opts map[string]any, key string, def float64) float64 {
	if opts == nil {
		return def
	}
	switch v := opts[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	}
	return def
}

// simpleDetector wraps a detection function.
type simpleDetector struct {
	id       string
	severity string
	detect   func(text string) []Match
}

func (d *simpleDetector) ID() string              { return d.id }
func (d *simpleDetector) Severity() string        { return d.severity }
func (d *simpleDetector) Detect(t string) []Match { return d.detect(t) }
