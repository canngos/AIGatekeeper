package dlp

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"regexp"
	"strings"
)

// Entropy returns the Shannon entropy of s in bits per byte.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// Luhn reports whether a digit string passes the Luhn checksum.
func Luhn(digits string) bool {
	if len(digits) < 2 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// ibanLengths maps country codes to their IBAN length.
var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29,
	"BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29,
	"ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
	"HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
	"LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24, "ME": 22, "MK": 19,
	"MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29,
	"RO": 24, "RS": 22, "SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28,
	"TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}

// ValidIBAN checks country length and the ISO 7064 mod-97 checksum.
func ValidIBAN(iban string) bool {
	iban = strings.ToUpper(strings.ReplaceAll(iban, " ", ""))
	if len(iban) < 15 || len(iban) > 34 {
		return false
	}
	want, ok := ibanLengths[iban[:2]]
	if !ok || len(iban) != want {
		return false
	}
	rearranged := iban[4:] + iban[:4]
	rem := 0
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
			rem = (rem*10 + v) % 97
		case c >= 'A' && c <= 'Z':
			v = int(c-'A') + 10
			rem = (rem*100 + v) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// ValidJWTHeader reports whether the first JWT segment is base64url JSON
// containing an "alg" claim.
func ValidJWTHeader(token string) bool {
	dot := strings.IndexByte(token, '.')
	if dot <= 0 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(token[:dot], "="))
	if err != nil {
		return false
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(raw, &hdr) != nil {
		return false
	}
	return hdr.Alg != ""
}

var (
	uuidRe     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexRe      = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	pathLikeRe = regexp.MustCompile(`^(?:[A-Za-z]:)?[\\/][^\s]*$|^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$`)
)

// IsUUID reports whether s is a canonical UUID.
func IsUUID(s string) bool { return uuidRe.MatchString(s) }

// IsHex reports whether s consists solely of hex digits.
func IsHex(s string) bool { return hexRe.MatchString(s) }

// looksLikeWord reports whether s reads like natural language or an
// identifier rather than random key material: mostly letters with a
// plausible vowel share and no digit clusters.
func looksLikeWord(s string) bool {
	letters, vowels, digits := 0, 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			letters++
			switch c | 0x20 {
			case 'a', 'e', 'i', 'o', 'u':
				vowels++
			}
		case c >= '0' && c <= '9':
			digits++
		}
	}
	if letters == 0 {
		return false
	}
	ratio := float64(vowels) / float64(letters)
	return digits <= 2 && ratio >= 0.25 && ratio <= 0.6
}

// isPlaceholderLike is shared by the entropy detector to reject values that
// are obviously not secrets (paths, URLs, identifiers).
func isNoiseCandidate(s string) bool {
	if IsUUID(s) {
		return true
	}
	if strings.Contains(s, "://") || strings.HasPrefix(s, "/") || pathLikeRe.MatchString(s) {
		return true
	}
	return looksLikeWord(s)
}
