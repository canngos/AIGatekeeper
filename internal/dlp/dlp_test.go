package dlp

import (
	"context"
	"strings"
	"testing"

	"github.com/canngos/aigatekeeper/internal/parser"
)

func mustDetector(t testing.TB, id string, opts map[string]any) Detector {
	t.Helper()
	d, err := NewBuiltin(id, opts)
	if err != nil {
		t.Fatal(err)
	}
	if d == nil {
		t.Fatalf("detector %s disabled", id)
	}
	return d
}

const (
	validJWT     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	anthropicKey = "sk-ant-api03-" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz-AA"
	privateKey   = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AH6M\n-----END RSA PRIVATE KEY-----"
)

func TestDetectorsPositivesAndNegatives(t *testing.T) {
	cases := []struct {
		id        string
		opts      map[string]any
		positives []string
		negatives []string
	}{
		{
			id:        IDAWSAccessKey,
			positives: []string{"key AKIAIOSFODNN7REALKEY here", "ASIA1234567890ABCDEF"},
			negatives: []string{"AKIAIOSFODNN7EXAMPLE", "AKIA123", "akiaiosfodnn7realkey"},
		},
		{
			id: IDAccessKeys,
			positives: []string{
				"key AKIAIOSFODNN7REALKEY here",
				"ASIA1234567890ABCDEF",
				"LTAI5tGk8mQ2rWx9Yz3Bv7Nc",             // Alibaba, matched by the length range
				"AKID7Hc2pQfqm3rY2vXb9LkT5wNzA8sD1eF4", // Tencent, exactly 32 after the prefix
			},
			negatives: []string{
				"AKIAIOSFODNN7EXAMPLE",
				"AKIA123",
				"akiaiosfodnn7realkey",
				"ASIAPACIFICREGIONDATA",  // an exact length is what rules this out
				"LTAIRPORTTERMINALCODES", // a range prefix, ruled out by having no digits
			},
		},
		{
			id: IDAccessKeys,
			opts: map[string]any{"prefixes": []any{
				"CORP",
				map[string]any{"prefix": "SVC", "length": 12, "note": "internal service"},
			}},
			positives: []string{"CORP7Hc2pQfqm3rY2vXb9", "SVC7Hc2pQfqm3rY"},
			negatives: []string{
				"AKIAIOSFODNN7REALKEY", // replacing the list replaces the defaults
				"SVC7Hc2pQ",            // too short for the exact length
			},
		},
		{
			id:        IDAWSSecretKey,
			positives: []string{"aws_secret_access_key = 7HcpQfqm3rY2vXb9LkT5wNzA8sD1eF4gH6jK0lM2", `AWS Secret Key: "7HcpQfqm3rY2vXb9LkT5wNzA8sD1eF4gH6jK0lM2"`},
			negatives: []string{"aws_secret_access_key = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "secret_key = 7HcpQfqm3rY2vXb9LkT5wNzA8sD1eF4gH6jK0lM2"},
		},
		{
			id:        IDGitHubToken,
			positives: []string{"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "github_pat_ABCDEFGHIJKLMNOPQRSTUV_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"},
			negatives: []string{"ghp_short", "ghx_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"},
		},
		{
			id:        IDSlackToken,
			positives: []string{"xoxb-123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx", "https://hooks.slack.com/services/T0ABCDEFG/B0ABCDEFG/AbCdEfGhIjKlMnOpQrStUvWx"},
			negatives: []string{"xoxb-123-456", "https://hooks.slack.com/services/short"},
		},
		{
			id:        IDGoogleAPIKey,
			positives: []string{"AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"},
			negatives: []string{"AIzaShort", "BIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"},
		},
		{
			id:        IDOpenAIKey,
			positives: []string{"sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cDe0f", "OPENAI_API_KEY=sk-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cDe0fGhIjKl"},
			negatives: []string{"sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", anthropicKey, "sk-short"},
		},
		{
			id:        IDAnthropicKey,
			positives: []string{anthropicKey},
			negatives: []string{"sk-ant-api03-tooshort"},
		},
		{
			id:        IDJWT,
			positives: []string{"Authorization: Bearer " + validJWT},
			negatives: []string{"eyJub3RhandvIjoxfQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "eyJ.eyJ.sig"},
		},
		{
			id:        IDPrivateKey,
			positives: []string{privateKey, "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc\n-----END PGP PRIVATE KEY BLOCK-----"},
			negatives: []string{"-----BEGIN PUBLIC KEY-----", "-----BEGIN CERTIFICATE-----"},
		},
		{
			id: IDHighEntropySecret,
			positives: []string{
				`API_KEY = "q8Zt2mV5xR7nB3kL9pW4yC6sD1fG0hJ2"`,
				`db_password: 'Xk9#'`[:0] + `db_password: Xk9vB2nM4qR7tY1wE5uI8oP3aS6dF0gH`,
				`export STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc`,
				`"token": "7f3a9c2e1b8d4f6a0c5e2b9d7a1f3c8e6b4d2a9f"`,
			},
			negatives: []string{
				`token = "my_local_dev_token_value_here"`,
				`secret = "/etc/ssl/private/server.key"`,
				`api_key = "550e8400-e29b-41d4-a716-446655440000"`,
				`password = "https://example.com/reset?token=abc"`,
				`auth_url = "https://login.corp.example/oauth2/authorize"`,
			},
		},
		{
			id:        IDCreditCard,
			positives: []string{"card 4111111111111111", "4111 1111 1111 1111", "5500-0000-0000-0004", "378282246310005", "6011111111111117"},
			negatives: []string{"4000000000000000", "1234567890123456", "4111111111111112", "phone 555 123 4567 8901", "order 2024011500000012"},
		},
		{
			id:        IDEmail,
			positives: []string{"contact alice.smith@corp-mail.internal", "bob+tag@sub.domain.co.uk"},
			negatives: []string{"noreply@corp.internal", "user@example.com", "not an email @ all", "root@localhost"},
		},
		{
			id:        IDUSSSN,
			positives: []string{"SSN: 123-45-6789", "123-45-6789", "social security 123456789", "ssn 123 45 6789"},
			negatives: []string{"123456789", "000-12-3456", "123-00-4567", "123-45-0000", "999-12-3456", "123-45 6789", "version 1.2.3-45-6789x"},
		},
		{
			id:        IDUSSSN,
			opts:      map[string]any{"require_context": true},
			positives: []string{"SSN 123-45-6789"},
			negatives: []string{"123-45-6789"},
		},
		{
			id:        IDIBAN,
			positives: []string{"GB82 WEST 1234 5698 7654 32", "DE89370400440532013000", "IBAN: NL91ABNA0417164300"},
			negatives: []string{"GB82WEST12345698765433", "XX82WEST12345698765432", "GB82 WEST 1234"},
		},
	}
	for _, tc := range cases {
		name := tc.id
		if tc.opts != nil {
			name += "+opts"
		}
		t.Run(name, func(t *testing.T) {
			d := mustDetector(t, tc.id, tc.opts)
			for _, p := range tc.positives {
				if len(d.Detect(p)) == 0 {
					t.Errorf("expected match in %q", p)
				}
			}
			for _, n := range tc.negatives {
				if m := d.Detect(n); len(m) != 0 {
					t.Errorf("unexpected match %q in %q", m[0].Value, n)
				}
			}
		})
	}
}

func TestBuiltinRegistry(t *testing.T) {
	infos := Builtin()
	if len(infos) != 15 {
		t.Fatalf("expected 15 builtin detectors, got %d", len(infos))
	}
	for _, info := range infos {
		if info.Name == "" || info.Group == "" {
			t.Errorf("%s needs a name and a group: the console offers detectors by name", info.ID)
		}
		if info.Deprecated && info.ReplacedBy == "" {
			t.Errorf("%s is deprecated but names no replacement", info.ID)
		}
	}
	for i := 1; i < len(infos); i++ {
		if infos[i-1].ID >= infos[i].ID {
			t.Fatal("Builtin() must be sorted by id")
		}
	}
	if _, err := NewBuiltin("nope", nil); err == nil {
		t.Error("unknown detector should error")
	}
	d, err := NewBuiltin(IDEmail, map[string]any{"enabled": false})
	if err != nil || d != nil {
		t.Errorf("enabled:false should yield nil detector, got %v %v", d, err)
	}
}

func TestValidators(t *testing.T) {
	if !Luhn("4111111111111111") || Luhn("4111111111111112") || Luhn("") {
		t.Error("luhn")
	}
	if !ValidIBAN("GB82 WEST 1234 5698 7654 32") || ValidIBAN("GB82WEST12345698765433") || ValidIBAN("ZZ82WEST12345698765432") {
		t.Error("iban")
	}
	if !ValidJWTHeader(validJWT) || ValidJWTHeader("eyJub3RhandvIjoxfQ.x.y") || ValidJWTHeader("nodots") {
		t.Error("jwt")
	}
	if e := Entropy("aaaa"); e != 0 {
		t.Errorf("entropy of aaaa = %v", e)
	}
	if e := Entropy("q8Zt2mV5xR7nB3kL9pW4yC6sD1fG0hJ2"); e < 4.5 {
		t.Errorf("entropy of random string too low: %v", e)
	}
	if !IsUUID("550e8400-e29b-41d4-a716-446655440000") || IsUUID("550e8400") {
		t.Error("uuid")
	}
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"AKIAIOSFODNN7REALKEY":  "AKIA****EY",
		"ghp_ABCDEFGHIJKLMNOPQ": "ghp_****PQ",
		"12345678":              "12****8",
		"short":                 "****",
		privateKey:              "-----BEGIN RSA PRIVATE KEY----- …",
		"line1\nline2xxxxxxxxx": "****",
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
	for _, v := range []string{"AKIAIOSFODNN7EXAMPLE", "sk-xxxxxxxxxxxxxxxxxxxx", "<your-api-key>", "REDACTED_TOKEN", "${SECRET}", "{{ token }}"} {
		if !IsPlaceholder(v) {
			t.Errorf("%q should be a placeholder", v)
		}
	}
	if IsPlaceholder("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij") {
		t.Error("real-looking token flagged as placeholder")
	}
}

func allBuiltins(t testing.TB) []Detector {
	t.Helper()
	var out []Detector
	for _, info := range Builtin() {
		if info.Deprecated {
			continue
		}
		out = append(out, mustDetector(t, info.ID, nil))
	}
	return out
}

func extraction(segs ...parser.Segment) *parser.Extraction {
	return &parser.Extraction{Extractor: "test", Segments: segs}
}

func TestScannerFindingsAreMaskedAndDeduplicated(t *testing.T) {
	s := NewScanner("secrets", allBuiltins(t), Options{})
	key := "AKIAIOSFODNN7REALKEY"
	ex := extraction(
		parser.Segment{Path: "/messages/0/content", Role: parser.RoleUser, Text: "first " + key},
		parser.Segment{Path: "/messages/1/content", Role: parser.RoleUser, Text: "again " + key + " and " + validJWT},
	)
	findings, err := s.Scan(context.Background(), ex)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (deduplicated key + jwt), got %+v", findings)
	}
	for _, f := range findings {
		if strings.Contains(f.Preview, key) || strings.Contains(f.Preview, validJWT) {
			t.Fatalf("preview leaks the secret: %q", f.Preview)
		}
		if f.Segment == "" || f.Severity == "" || f.Confidence <= 0 {
			t.Fatalf("incomplete finding: %+v", f)
		}
	}
	if findings[0].Detector != IDAccessKeys || findings[0].Segment != "/messages/0/content" || findings[0].Offset != 6 {
		t.Fatalf("unexpected first finding: %+v", findings[0])
	}
}

func TestScannerAllowlistAndPlaceholders(t *testing.T) {
	al, err := NewAllowlist([]string{"AKIAIOSFODNN7ALLOWED"}, []string{`(?i)^ghp_test`}, []string{"corp.internal"})
	if err != nil {
		t.Fatal(err)
	}
	dets := []Detector{mustDetector(t, IDAWSAccessKey, nil), mustDetector(t, IDGitHubToken, nil), mustDetector(t, IDEmail, nil)}
	s := NewScanner("r", dets, Options{Allowlist: al})
	ex := extraction(parser.Segment{Path: "/p", Text: strings.Join([]string{
		"AKIAIOSFODNN7ALLOWED",                     // literal allow
		"AKIAIOSFODNN7EXAMPLE",                     // placeholder
		"ghp_testABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", // pattern allow
		"alice@corp.internal",                      // domain allow
		"alice@mail.corp.internal",                 // parent domain allow
		"bob@other.internal",                       // flagged
		"AKIAIOSFODNN7REALKEY",                     // flagged
	}, " ")})
	findings, _ := s.Scan(context.Background(), ex)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %+v", findings)
	}
}

func TestScannerSkipCapAndWeight(t *testing.T) {
	d := mustDetector(t, IDAWSAccessKey, nil)
	var keys []string
	for i := 0; i < 20; i++ {
		keys = append(keys, "AKIA"+strings.Repeat(string(rune('A'+i)), 16))
	}
	ex := extraction(
		parser.Segment{Path: "/tools/0/input_schema", Text: keys[0]},
		parser.Segment{Path: "/messages/0/content", Role: parser.RoleAssistant, Text: strings.Join(keys, " ")},
	)
	s := NewScanner("r", []Detector{d}, Options{
		MaxFindings:     5,
		AssistantWeight: 0.5,
		SkipSegment:     func(p string) bool { return strings.HasPrefix(p, "/tools/") },
	})
	findings, _ := s.Scan(context.Background(), ex)
	if len(findings) != 5 {
		t.Fatalf("cap not applied: %d", len(findings))
	}
	for _, f := range findings {
		if f.Segment != "/messages/0/content" {
			t.Fatalf("skipped segment produced a finding: %+v", f)
		}
		if f.Confidence != 0.5 {
			t.Fatalf("assistant weight not applied: %+v", f)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Scan(ctx, ex); err == nil {
		t.Error("expected context error")
	}
}

func TestKeywordAndCustomRegexDetectors(t *testing.T) {
	kw, err := NewKeywordDetector("internal", SeverityMedium, []string{"Project Falcon", "# comment", "orion"}, KeywordOptions{CaseInsensitive: true, WordBoundary: true})
	if err != nil {
		t.Fatal(err)
	}
	if m := kw.Detect("we ship project falcon next week; Orion too, but not orionids"); len(m) != 2 {
		t.Fatalf("keyword matches = %+v", m)
	}
	if _, err := NewKeywordDetector("empty", "", []string{"# only comment"}, KeywordOptions{}); err == nil {
		t.Error("expected error for empty keyword list")
	}
	rx, err := NewCustomRegexDetector("host", SeverityLow, `\b([a-z0-9-]+\.corp\.example\.com)\b`, 10)
	if err != nil {
		t.Fatal(err)
	}
	if m := rx.Detect("ssh db-01.corp.example.com and a.corp.example.com"); len(m) != 2 {
		t.Fatalf("custom regex matches = %+v", m)
	}
	if _, err := NewCustomRegexDetector("bad", "", `(`, 0); err == nil {
		t.Error("expected compile error")
	}
}

func FuzzDetectors(f *testing.F) {
	dets := allBuiltins(f)
	f.Add("AKIAIOSFODNN7REALKEY 4111 1111 1111 1111 " + validJWT)
	f.Add("-----BEGIN RSA PRIVATE KEY-----")
	f.Add("api_key = \"q8Zt2mV5xR7nB3kL9pW4yC6sD1fG0hJ2\"")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		for _, d := range dets {
			for _, m := range d.Detect(s) {
				if m.Offset < 0 || m.Offset+m.Length > len(s) {
					t.Fatalf("%s: match out of range", d.ID())
				}
				_ = Redact(m.Value)
			}
		}
	})
}

func BenchmarkScan1MiB(b *testing.B) {
	line := "func handler(w http.ResponseWriter, r *http.Request) { token := os.Getenv(\"TOKEN\"); log.Printf(\"%s %s\", r.Method, r.URL.Path) }\n"
	var sb strings.Builder
	for sb.Len() < 1<<20 {
		sb.WriteString(line)
		if sb.Len()%(64<<10) < len(line) {
			sb.WriteString("aws_access_key_id = AKIAIOSFODNN7REALKEY\n")
		}
	}
	ex := extraction(parser.Segment{Path: "/messages/0/content", Text: sb.String()})
	s := NewScanner("all", allBuiltins(b), Options{})
	b.SetBytes(int64(sb.Len()))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Scan(context.Background(), ex); err != nil {
			b.Fatal(err)
		}
	}
}
