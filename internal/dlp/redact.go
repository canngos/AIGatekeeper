package dlp

import (
	"regexp"
	"strings"
)

// Redact masks a matched value for audit logs and the UI: the first four
// and last two characters remain so an analyst can recognise the credential
// without the log itself becoming a leak.
func Redact(value string) string {
	v := strings.TrimSpace(value)
	if strings.HasPrefix(v, "-----BEGIN") {
		if nl := strings.IndexAny(v, "\r\n"); nl > 0 {
			return v[:nl] + " …"
		}
		return v
	}
	if nl := strings.IndexAny(v, "\r\n"); nl >= 0 {
		v = v[:nl]
	}
	r := []rune(v)
	switch {
	case len(r) >= 12:
		return string(r[:4]) + "****" + string(r[len(r)-2:])
	case len(r) >= 8:
		return string(r[:2]) + "****" + string(r[len(r)-1:])
	default:
		return "****"
	}
}

var placeholderRe = regexp.MustCompile(`(?i)(x{4,}|\*{3,}|\.{3}|<[^>]{0,40}>|example|redacted|changeme|change_me|placeholder|your[-_ ]?(api[-_ ]?)?key|dummy|insert[-_ ]here|\{\{[^}]*\}\}|\$\{[^}]*\})`)

// IsPlaceholder reports whether value is an obvious stand-in rather than a
// real secret (documentation samples, templates, masked values).
func IsPlaceholder(value string) bool {
	return placeholderRe.MatchString(value)
}
