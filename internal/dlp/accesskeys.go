package dlp

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// AccessKeyPrefix is one vendor's access key identifier prefix.
//
// Every cloud provider stamps its access key IDs with a short fixed prefix
// followed by a run of random characters. Naming the prefixes rather than
// hard-coding one vendor lets a deployment cover whatever it actually uses,
// including an internal system nobody outside the company has heard of.
type AccessKeyPrefix struct {
	Prefix string `json:"prefix" yaml:"prefix"`
	// Length is the exact number of characters that follow the prefix.
	// Zero means the detector's min_length..max_length range applies, which
	// is the right choice when a vendor's key length varies or is unknown.
	Length int `json:"length,omitempty" yaml:"length,omitempty"`
	// Note names the vendor. It is documentation for whoever reads the
	// policy next, and has no effect on matching.
	Note string `json:"note,omitempty" yaml:"note,omitempty"`
}

// DefaultAccessKeyPrefixes ship with the detector. The AWS entries are
// pinned to their exact length, which is what stops ASIAPACIFICREGIONDATA
// from reading as a key; the others allow a range because their published
// lengths have changed over time.
var DefaultAccessKeyPrefixes = []AccessKeyPrefix{
	{Prefix: "AKIA", Length: 16, Note: "AWS long-term"},
	{Prefix: "ASIA", Length: 16, Note: "AWS temporary (STS)"},
	{Prefix: "ABIA", Length: 16, Note: "AWS bearer"},
	{Prefix: "ACCA", Length: 16, Note: "AWS context-specific"},
	{Prefix: "AKID", Length: 32, Note: "Tencent Cloud"},
	{Prefix: "LTAI", Note: "Alibaba Cloud"},
}

// Bounds on the run of characters after a prefix. A key shorter than this
// is not random enough to be one, and nothing in use is longer.
const (
	accessKeyMinLength = 8
	accessKeyMaxLength = 128
	// Below this, the characters after the prefix are a word rather than a
	// random string. Real keys sit well above it.
	accessKeyMinEntropy = 3.0
)

var prefixRe = regexp.MustCompile(`^[A-Za-z0-9_-]{2,16}$`)

func init() {
	register(Info{
		ID: IDAccessKeys, Name: "Cloud access key IDs", Group: GroupKeys, Severity: SeverityCritical,
		Description: "Access key identifiers matched by vendor prefix. Ships with AWS, Alibaba and Tencent; add your own.",
		Options: []OptionInfo{
			{
				Name: "prefixes", Label: "Prefixes", Type: "prefix_list", Default: DefaultAccessKeyPrefixes,
				Description: "A key is the prefix followed by random characters. Give an exact length when the vendor publishes one; leave it blank to accept the range below.",
			},
			{
				Name: "min_length", Label: "Shortest key", Type: "number", Default: 16,
				Description: "Fewest characters after a prefix that has no exact length.",
			},
			{
				Name: "max_length", Label: "Longest key", Type: "number", Default: 40,
				Description: "Most characters after such a prefix.",
			},
		},
	}, func(opts map[string]any) (Detector, error) {
		prefixes, err := accessKeyPrefixesFrom(opts)
		if err != nil {
			return nil, err
		}
		minLen := int(optFloat(opts, "min_length", 16))
		maxLen := int(optFloat(opts, "max_length", 40))
		return newAccessKeyDetector(IDAccessKeys, prefixes, minLen, maxLen)
	})

	// Kept so configuration written against earlier versions still loads and
	// so audit history keeps one name for the same class of finding. It is
	// the AWS half of access_keys and nothing more.
	register(Info{
		ID: IDAWSAccessKey, Name: "AWS access key IDs", Group: GroupKeys, Severity: SeverityCritical,
		Description: "AWS access key IDs only.",
		Deprecated:  true, ReplacedBy: IDAccessKeys,
	}, func(map[string]any) (Detector, error) {
		return newAccessKeyDetector(IDAWSAccessKey, DefaultAccessKeyPrefixes[:4], 16, 16)
	})
}

func accessKeyPrefixesFrom(opts map[string]any) ([]AccessKeyPrefix, error) {
	raw, ok := opts["prefixes"]
	if !ok || raw == nil {
		return DefaultAccessKeyPrefixes, nil
	}
	list, ok := raw.([]any)
	if !ok {
		// Already typed, which is the case when Go code builds the options.
		if typed, ok := raw.([]AccessKeyPrefix); ok {
			return typed, nil
		}
		return nil, fmt.Errorf("prefixes: expected a list, got %T", raw)
	}
	out := make([]AccessKeyPrefix, 0, len(list))
	for i, item := range list {
		p, err := parseAccessKeyPrefix(item)
		if err != nil {
			return nil, fmt.Errorf("prefixes[%d]: %w", i, err)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("prefixes: at least one prefix is required, or remove the option to use the defaults")
	}
	return out, nil
}

// parseAccessKeyPrefix accepts either a bare prefix or a table giving the
// prefix an exact length and a vendor note.
func parseAccessKeyPrefix(item any) (AccessKeyPrefix, error) {
	switch v := item.(type) {
	case string:
		return AccessKeyPrefix{Prefix: strings.TrimSpace(v)}, nil
	case AccessKeyPrefix:
		return v, nil
	case map[string]any:
		p := AccessKeyPrefix{}
		if s, ok := v["prefix"].(string); ok {
			p.Prefix = strings.TrimSpace(s)
		}
		if s, ok := v["note"].(string); ok {
			p.Note = s
		}
		switch n := v["length"].(type) {
		case int:
			p.Length = n
		case int64:
			p.Length = int(n)
		case float64:
			p.Length = int(n)
		case nil:
		default:
			return p, fmt.Errorf("length: expected a number, got %T", v["length"])
		}
		return p, nil
	default:
		return AccessKeyPrefix{}, fmt.Errorf("expected a prefix or a table, got %T", item)
	}
}

// newAccessKeyDetector compiles one pattern per distinct length so that a
// prefix with an exact length stays exact.
func newAccessKeyDetector(id string, prefixes []AccessKeyPrefix, minLen, maxLen int) (Detector, error) {
	if minLen < accessKeyMinLength || maxLen > accessKeyMaxLength || minLen > maxLen {
		return nil, fmt.Errorf("key length range %d..%d is outside %d..%d", minLen, maxLen, accessKeyMinLength, accessKeyMaxLength)
	}
	byLength := map[int][]string{}
	known := make([]AccessKeyPrefix, 0, len(prefixes))
	for _, p := range prefixes {
		if !prefixRe.MatchString(p.Prefix) {
			return nil, fmt.Errorf("prefix %q must be 2 to 16 letters, digits, underscores or hyphens", p.Prefix)
		}
		if p.Length != 0 && (p.Length < accessKeyMinLength || p.Length > accessKeyMaxLength) {
			return nil, fmt.Errorf("prefix %s: length %d is outside %d..%d", p.Prefix, p.Length, accessKeyMinLength, accessKeyMaxLength)
		}
		byLength[p.Length] = append(byLength[p.Length], p.Prefix)
		known = append(known, p)
	}

	lengths := make([]int, 0, len(byLength))
	for l := range byLength {
		lengths = append(lengths, l)
	}
	sort.Ints(lengths)

	patterns := make([]*regexp.Regexp, 0, len(lengths))
	for _, l := range lengths {
		group := byLength[l]
		sort.Strings(group)
		quoted := make([]string, len(group))
		for i, p := range group {
			quoted[i] = regexp.QuoteMeta(p)
		}
		run := fmt.Sprintf("{%d}", l)
		if l == 0 {
			run = fmt.Sprintf("{%d,%d}", minLen, maxLen)
		}
		re, err := regexp.Compile(`\b((?:` + strings.Join(quoted, "|") + `)[A-Za-z0-9]` + run + `)\b`)
		if err != nil {
			return nil, fmt.Errorf("prefixes %v: %w", group, err)
		}
		patterns = append(patterns, re)
	}

	// Longest prefix first, so ACCA is not stripped from a longer prefix
	// that happens to start with it.
	sort.SliceStable(known, func(i, j int) bool { return len(known[i].Prefix) > len(known[j].Prefix) })

	return &regexDetector{
		id: id, severity: SeverityCritical,
		patterns: patterns,
		validate: func(v string) (float64, bool) {
			if strings.HasSuffix(v, "EXAMPLE") {
				return 0, false
			}
			for _, p := range known {
				if !strings.HasPrefix(v, p.Prefix) {
					continue
				}
				// An exact length is already specific enough: the length and
				// the word boundary together are what keep ASIAPACIFICREGION
				// out. Asking for randomness on top of that would throw away
				// the occasional real key that happens to have no digit.
				if p.Length != 0 {
					return 1, true
				}
				return 1, looksRandom(v[len(p.Prefix):])
			}
			return 1, true
		},
	}, nil
}

// looksRandom separates a generated key from a run of ordinary words that
// happens to start with the same few letters. It guards only the prefixes
// with no fixed length, where the pattern alone would accept a phrase.
//
// A key drawn at random over letters and digits contains at least one of
// each with near-certainty, and spreads its characters more evenly than
// English does.
func looksRandom(s string) bool {
	var digits, letters int
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			letters++
		}
	}
	if digits == 0 || letters == 0 {
		return false
	}
	return Entropy(s) >= accessKeyMinEntropy
}
