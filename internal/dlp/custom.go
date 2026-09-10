package dlp

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// KeywordDetector flags organisation-specific terms (project code names,
// internal hostnames) from a configured list.
type KeywordDetector struct {
	id       string
	severity string
	re       *regexp.Regexp
}

// KeywordOptions configure a KeywordDetector.
type KeywordOptions struct {
	CaseInsensitive bool
	WordBoundary    bool
}

// NewKeywordDetector compiles the keyword list into a single alternation.
func NewKeywordDetector(id, severity string, keywords []string, opts KeywordOptions) (*KeywordDetector, error) {
	var quoted []string
	for _, k := range keywords {
		k = strings.TrimSpace(k)
		if k == "" || strings.HasPrefix(k, "#") {
			continue
		}
		quoted = append(quoted, regexp.QuoteMeta(k))
	}
	if len(quoted) == 0 {
		return nil, fmt.Errorf("keyword detector %s: no keywords", id)
	}
	// Longest first so overlapping terms prefer the most specific match.
	sortByLengthDesc(quoted)
	pattern := "(" + strings.Join(quoted, "|") + ")"
	if opts.WordBoundary {
		pattern = `\b` + pattern + `\b`
	}
	if opts.CaseInsensitive {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("keyword detector %s: %w", id, err)
	}
	if severity == "" {
		severity = SeverityMedium
	}
	return &KeywordDetector{id: id, severity: severity, re: re}, nil
}

// LoadKeywordFile reads one keyword per line, ignoring blanks and # comments.
func LoadKeywordFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("keyword file: %w", err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// ID implements Detector.
func (d *KeywordDetector) ID() string { return d.id }

// Severity implements Detector.
func (d *KeywordDetector) Severity() string { return d.severity }

// Detect implements Detector.
func (d *KeywordDetector) Detect(text string) []Match {
	var out []Match
	for _, loc := range d.re.FindAllStringIndex(text, -1) {
		out = append(out, Match{Offset: loc[0], Length: loc[1] - loc[0], Value: text[loc[0]:loc[1]], Confidence: 1})
	}
	return out
}

func sortByLengthDesc(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && len(s[j]) > len(s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// NewCustomRegexDetector wraps a user-supplied RE2 pattern. Group 1, when
// present, is the value; otherwise the whole match.
func NewCustomRegexDetector(id, severity, pattern string, minLength int) (Detector, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("regex detector %s: %w", id, err)
	}
	if severity == "" {
		severity = SeverityMedium
	}
	return &regexDetector{
		id: id, severity: severity, patterns: []*regexp.Regexp{re},
		validate: func(v string) (float64, bool) { return 1, len(v) >= minLength },
	}, nil
}
