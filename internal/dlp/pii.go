package dlp

import (
	"regexp"
	"strings"
)

var (
	cardCandidateRe = regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`)
	nonDigitRe      = regexp.MustCompile(`[^0-9]`)
	emailRe         = regexp.MustCompile(`\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b`)
	ssnRe           = regexp.MustCompile(`\b(\d{3})([- ]?)(\d{2})([- ]?)(\d{4})\b`)
	ssnContextRe    = regexp.MustCompile(`(?i)\b(?:ssn|social[ -]?security)\b`)
	ibanRe          = regexp.MustCompile(`\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?)\b`)
)

func init() {
	register(Info{ID: IDCreditCard, Name: "Payment card numbers", Group: GroupPersonal, Severity: SeverityHigh, Description: "Payment card numbers (13-19 digits, Luhn-valid, known issuer prefix)"},
		func(map[string]any) (Detector, error) {
			return &simpleDetector{id: IDCreditCard, severity: SeverityHigh, detect: detectCreditCards}, nil
		})

	register(Info{
		ID: IDEmail, Name: "Email addresses", Group: GroupPersonal, Severity: SeverityMedium,
		Description: "Email addresses (noisy in source code; enable per deployment and allow-list corporate domains)",
	}, func(map[string]any) (Detector, error) {
		return &regexDetector{
			id: IDEmail, severity: SeverityMedium,
			patterns: []*regexp.Regexp{emailRe},
			validate: func(v string) (float64, bool) {
				lower := strings.ToLower(v)
				if strings.HasPrefix(lower, "noreply@") || strings.HasPrefix(lower, "no-reply@") {
					return 0, false
				}
				for _, d := range []string{"example.com", "example.org", "example.net", "test.com", "localhost"} {
					if strings.HasSuffix(lower, "@"+d) {
						return 0, false
					}
				}
				return 0.8, true
			},
		}, nil
	})

	register(Info{
		ID: IDUSSSN, Name: "US Social Security numbers", Group: GroupPersonal, Severity: SeverityHigh,
		Description: "US Social Security numbers",
		Options: []OptionInfo{
			{Name: "require_context", Label: "Only with a nearby label", Type: "bool", Default: false, Description: "Require the words SSN or social security near the number, even when it is written with dashes."},
		},
	}, func(opts map[string]any) (Detector, error) {
		requireContext, _ := optBool(opts, "require_context", false)
		return &simpleDetector{id: IDUSSSN, severity: SeverityHigh, detect: func(text string) []Match {
			return detectSSN(text, requireContext)
		}}, nil
	})

	register(Info{ID: IDIBAN, Name: "Bank account numbers (IBAN)", Group: GroupPersonal, Severity: SeverityHigh, Description: "International bank account numbers (country length and mod-97 validated)"},
		func(map[string]any) (Detector, error) {
			return &regexDetector{
				id: IDIBAN, severity: SeverityHigh,
				patterns: []*regexp.Regexp{ibanRe},
				validate: func(v string) (float64, bool) { return 1, ValidIBAN(v) },
			}, nil
		})
}

func detectCreditCards(text string) []Match {
	var out []Match
	for _, loc := range cardCandidateRe.FindAllStringIndex(text, -1) {
		raw := text[loc[0]:loc[1]]
		digits := nonDigitRe.ReplaceAllString(raw, "")
		if len(digits) < 13 || len(digits) > 19 {
			continue
		}
		if !knownIssuer(digits) || !Luhn(digits) || trivialDigits(digits) {
			continue
		}
		out = append(out, Match{Offset: loc[0], Length: loc[1] - loc[0], Value: raw, Confidence: 0.95})
	}
	return out
}

// knownIssuer checks the leading digits against major card networks.
func knownIssuer(d string) bool {
	switch {
	case d[0] == '4': // Visa
		return len(d) == 13 || len(d) == 16 || len(d) == 19
	case len(d) == 16 && d[0] == '5' && d[1] >= '1' && d[1] <= '5': // Mastercard
		return true
	case len(d) == 16 && d[0] == '2': // Mastercard 2221-2720
		n := atoi(d[:4])
		return n >= 2221 && n <= 2720
	case len(d) == 15 && d[0] == '3' && (d[1] == '4' || d[1] == '7'): // Amex
		return true
	case len(d) >= 16 && (strings.HasPrefix(d, "6011") || strings.HasPrefix(d, "65") || strings.HasPrefix(d, "644") || strings.HasPrefix(d, "645") || strings.HasPrefix(d, "646") || strings.HasPrefix(d, "647") || strings.HasPrefix(d, "648") || strings.HasPrefix(d, "649")): // Discover
		return true
	case len(d) == 16 && strings.HasPrefix(d, "35"): // JCB
		return true
	case len(d) == 14 && (strings.HasPrefix(d, "36") || strings.HasPrefix(d, "38") || strings.HasPrefix(d, "39") || strings.HasPrefix(d, "300") || strings.HasPrefix(d, "301") || strings.HasPrefix(d, "302") || strings.HasPrefix(d, "303") || strings.HasPrefix(d, "304") || strings.HasPrefix(d, "305")): // Diners
		return true
	}
	return false
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// trivialDigits rejects all-identical or strictly sequential digit runs.
func trivialDigits(d string) bool {
	same, asc, desc := true, true, true
	for i := 1; i < len(d); i++ {
		if d[i] != d[0] {
			same = false
		}
		if d[i] != d[i-1]+1 {
			asc = false
		}
		if d[i] != d[i-1]-1 {
			desc = false
		}
	}
	return same || asc || desc
}

func detectSSN(text string, requireContext bool) []Match {
	var out []Match
	for _, loc := range ssnRe.FindAllStringSubmatchIndex(text, -1) {
		area := text[loc[2]:loc[3]]
		sep1 := text[loc[4]:loc[5]]
		group := text[loc[6]:loc[7]]
		sep2 := text[loc[8]:loc[9]]
		serial := text[loc[10]:loc[11]]
		if area == "000" || area == "666" || area[0] == '9' || group == "00" || serial == "0000" {
			continue
		}
		hasSeparators := sep1 != "" && sep1 == sep2
		if !hasSeparators && (sep1 != "" || sep2 != "") {
			continue // mixed separators are not an SSN layout
		}
		start := loc[0] - 40
		if start < 0 {
			start = 0
		}
		hasContext := ssnContextRe.MatchString(text[start:loc[0]])
		if !hasContext && (requireContext || !hasSeparators) {
			continue
		}
		conf := 0.7
		if hasContext {
			conf = 0.95
		}
		out = append(out, Match{Offset: loc[0], Length: loc[1] - loc[0], Value: text[loc[0]:loc[1]], Confidence: conf})
	}
	return out
}
