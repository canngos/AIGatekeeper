package dlp

import (
	"regexp"
	"strings"
)

// regexDetector applies one or more patterns; group 1 (or the whole match)
// is the value, then an optional validator filters and scores it.
type regexDetector struct {
	id       string
	severity string
	patterns []*regexp.Regexp
	validate func(value string) (float64, bool)
}

func (d *regexDetector) ID() string       { return d.id }
func (d *regexDetector) Severity() string { return d.severity }

func (d *regexDetector) Detect(text string) []Match {
	var out []Match
	for _, re := range d.patterns {
		for _, loc := range re.FindAllStringSubmatchIndex(text, -1) {
			start, end := loc[0], loc[1]
			if len(loc) >= 4 && loc[2] >= 0 {
				start, end = loc[2], loc[3]
			}
			value := text[start:end]
			conf := 1.0
			if d.validate != nil {
				c, ok := d.validate(value)
				if !ok {
					continue
				}
				conf = c
			}
			out = append(out, Match{Offset: start, Length: end - start, Value: value, Confidence: conf})
		}
	}
	return out
}

func mustCompile(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}

func init() {
	register(Info{ID: IDAWSAccessKey, Severity: SeverityCritical, Description: "AWS access key ID (AKIA/ASIA/ABIA/ACCA prefix)"},
		func(map[string]any) (Detector, error) {
			return &regexDetector{
				id: IDAWSAccessKey, severity: SeverityCritical,
				patterns: mustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b`),
				validate: func(v string) (float64, bool) { return 1, !strings.HasSuffix(v, "EXAMPLE") },
			}, nil
		})

	register(Info{ID: IDAWSSecretKey, Severity: SeverityCritical, Description: "AWS secret access key next to an aws/secret/key label"},
		func(map[string]any) (Detector, error) {
			return &regexDetector{
				id: IDAWSSecretKey, severity: SeverityCritical,
				patterns: mustCompile(`(?i)aws[^\n]{0,30}?(?:secret|access)[^\n]{0,12}?key[^\n]{0,8}?["'=:\s]+([A-Za-z0-9/+=]{40})(?:[^A-Za-z0-9/+=]|$)`),
				validate: func(v string) (float64, bool) { return 0.9, Entropy(v) > 3.5 },
			}, nil
		})

	register(Info{ID: IDGitHubToken, Severity: SeverityCritical, Description: "GitHub personal access, OAuth, app and fine-grained tokens"},
		func(map[string]any) (Detector, error) {
			return &regexDetector{
				id: IDGitHubToken, severity: SeverityCritical,
				patterns: mustCompile(
					`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b`,
					`\b(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b`,
				),
			}, nil
		})

	register(Info{ID: IDSlackToken, Severity: SeverityCritical, Description: "Slack bot/user/app tokens and incoming webhook URLs"},
		func(map[string]any) (Detector, error) {
			return &regexDetector{
				id: IDSlackToken, severity: SeverityCritical,
				patterns: mustCompile(
					`\b(xox[abprs]-[0-9]{10,13}-[0-9]{10,13}[-A-Za-z0-9]*)`,
					`(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})`,
				),
			}, nil
		})

	register(Info{ID: IDGoogleAPIKey, Severity: SeverityHigh, Description: "Google Cloud / Maps / Firebase API key (AIza prefix)"},
		func(map[string]any) (Detector, error) {
			return &regexDetector{
				id: IDGoogleAPIKey, severity: SeverityHigh,
				patterns: mustCompile(`\b(AIza[0-9A-Za-z_-]{35})\b`),
			}, nil
		})

	register(Info{ID: IDOpenAIKey, Severity: SeverityCritical, Description: "OpenAI API keys (sk-, sk-proj-, sk-svcacct-, sk-admin-)"},
		func(map[string]any) (Detector, error) {
			return &regexDetector{
				id: IDOpenAIKey, severity: SeverityCritical,
				patterns: mustCompile(`\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})\b`),
				validate: func(v string) (float64, bool) {
					if strings.HasPrefix(v, "sk-ant-") {
						return 0, false // Anthropic keys are handled by their own detector
					}
					return 0.9, Entropy(v) > 3.5
				},
			}, nil
		})

	register(Info{ID: IDAnthropicKey, Severity: SeverityCritical, Description: "Anthropic API and admin keys (sk-ant-)"},
		func(map[string]any) (Detector, error) {
			return &regexDetector{
				id: IDAnthropicKey, severity: SeverityCritical,
				patterns: mustCompile(`\b(sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{80,})`),
			}, nil
		})

	register(Info{ID: IDJWT, Severity: SeverityHigh, Description: "JSON Web Tokens with a decodable header"},
		func(map[string]any) (Detector, error) {
			return &regexDetector{
				id: IDJWT, severity: SeverityHigh,
				patterns: mustCompile(`\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b`),
				validate: func(v string) (float64, bool) { return 1, ValidJWTHeader(v) },
			}, nil
		})

	register(Info{ID: IDPrivateKey, Severity: SeverityCritical, Description: "PEM private key blocks (RSA, EC, DSA, OpenSSH, PGP)"},
		func(map[string]any) (Detector, error) {
			return &regexDetector{
				id: IDPrivateKey, severity: SeverityCritical,
				patterns: mustCompile(`(?s)(-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----(?:.*?-----END (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----)?)`),
			}, nil
		})

	register(Info{
		ID: IDHighEntropySecret, Severity: SeverityHigh,
		Description: "High-entropy value assigned to a key/secret/token/password-like name",
		Options: []OptionInfo{
			{Name: "min_entropy", Type: "number", Default: 4.0, Description: "Minimum Shannon entropy (bits/byte) for base64-like values; hex values use 3.0"},
		},
	}, func(opts map[string]any) (Detector, error) {
		minEntropy := optFloat(opts, "min_entropy", 4.0)
		// No leading \b: names like db_password or STRIPE_SECRET_KEY put the
		// keyword after an underscore, which is a word character.
		re := regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|auth|bearer|credential|private[_-]?key|access[_-]?key)[a-z0-9_.-]{0,20}["']?\s*(?:[:=]|=>|:=)\s*["'` + "`" + `]?([A-Za-z0-9_\-+/=.]{20,80})`)
		return &regexDetector{
			id: IDHighEntropySecret, severity: SeverityHigh,
			patterns: []*regexp.Regexp{re},
			validate: func(v string) (float64, bool) {
				v = strings.TrimRight(v, ".")
				if isNoiseCandidate(v) {
					return 0, false
				}
				if IsHex(v) {
					// Hex tokens (including 40/64-char values that may be digests)
					// are reported with lower confidence.
					return 0.5, Entropy(v) >= 3.0
				}
				return 0.7, Entropy(v) >= minEntropy
			},
		}, nil
	})
}
