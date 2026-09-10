package identity

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func hash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func basicHeader(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func requestWith(header string) *http.Request {
	r, _ := http.NewRequest(http.MethodConnect, "https://api.openai.com", nil)
	if header != "" {
		r.Header.Set(ProxyAuthHeader, header)
	}
	return r
}

func writeHtpasswd(t *testing.T, lines string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.htpasswd")
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNormalizeUser(t *testing.T) {
	for in, want := range map[string]string{
		"Alice":              "alice",
		"CORP\\Alice":        "alice",
		"alice@corp.example": "alice",
		"  Bob  ":            "bob",
		"corp/carol":         "carol",
	} {
		if got := normalizeUser(in); got != want {
			t.Errorf("normalizeUser(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHtpasswdVerifier(t *testing.T) {
	path := writeHtpasswd(t, "# comment\nalice:"+hash(t, "s3cret")+"\nCORP\\\\Bob:"+hash(t, "other")+"\nlegacy:{SHA}weak\n\n")
	v, err := NewHtpasswdVerifier(path)
	if err != nil {
		t.Fatal(err)
	}
	if v.Users() != 2 {
		t.Fatalf("expected 2 usable accounts (the SHA line is refused), got %d", v.Users())
	}
	if _, ok := v.Verify(context.Background(), "alice", "s3cret"); !ok {
		t.Error("valid credentials rejected")
	}
	if _, ok := v.Verify(context.Background(), "ALICE", "s3cret"); !ok {
		t.Error("user names should be case insensitive")
	}
	if _, ok := v.Verify(context.Background(), "alice", "wrong"); ok {
		t.Error("wrong password accepted")
	}
	if _, ok := v.Verify(context.Background(), "nobody", "s3cret"); ok {
		t.Error("unknown user accepted")
	}
	if _, ok := v.Verify(context.Background(), "legacy", "weak"); ok {
		t.Error("a non-bcrypt hash must not authenticate")
	}

	// A joiner added to the file is picked up without a restart.
	if err := os.WriteFile(path, []byte("alice:"+hash(t, "s3cret")+"\ncarol:"+hash(t, "hunter2")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := v.Verify(context.Background(), "carol", "hunter2"); ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("a new account in the file was not picked up")
}

func TestProxyAuth(t *testing.T) {
	path := writeHtpasswd(t, "alice:"+hash(t, "s3cret")+"\n")
	v, _ := NewHtpasswdVerifier(path)
	auth, err := NewProxyAuth(v, ProxyAuthOptions{Realm: "Corp", ExemptCIDRs: []string{"10.9.0.0/16"}, CacheTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	client := net.ParseIP("192.168.1.5")

	if _, _, allowed := auth.Authenticate(ctx, requestWith(""), client); allowed {
		t.Error("a request without credentials must not be allowed through")
	}
	if _, _, allowed := auth.Authenticate(ctx, requestWith("Basic not-base64"), client); allowed {
		t.Error("a malformed header must not be allowed through")
	}
	if _, _, allowed := auth.Authenticate(ctx, requestWith(basicHeader("alice", "wrong")), client); allowed {
		t.Error("a wrong password must not be allowed through")
	}
	id, ok, allowed := auth.Authenticate(ctx, requestWith(basicHeader("alice", "s3cret")), client)
	if !ok || !allowed || id.User != "alice" {
		t.Fatalf("valid credentials rejected: %+v %v %v", id, ok, allowed)
	}
	// The second call comes from the cache rather than a fresh bcrypt compare.
	if _, _, allowed := auth.Authenticate(ctx, requestWith(basicHeader("alice", "s3cret")), client); !allowed {
		t.Error("cached credentials rejected")
	}
	// "failures" counts credentials that were checked and rejected. A
	// request with no header at all is the normal first exchange of every
	// connection, so it is not counted as a failure.
	if stats := auth.Stats(); stats["cache_hits"] != 1 || stats["successes"] != 1 || stats["failures"] != 1 {
		t.Errorf("unexpected stats: %v", stats)
	}
	// A changed password must not be served from the cache.
	if _, _, allowed := auth.Authenticate(ctx, requestWith(basicHeader("alice", "different")), client); allowed {
		t.Error("the cache must be keyed on the presented password")
	}

	// Exempt sources skip authentication entirely.
	if id, ok, allowed := auth.Authenticate(ctx, requestWith(""), net.ParseIP("10.9.3.4")); !allowed || ok || id.Known() {
		t.Errorf("an exempt source should pass unnamed: %+v %v %v", id, ok, allowed)
	}
	if _, err := NewProxyAuth(v, ProxyAuthOptions{ExemptCIDRs: []string{"not-a-cidr"}}); err == nil {
		t.Error("an invalid CIDR should be rejected at construction")
	}
}

func TestReverseDNS(t *testing.T) {
	var calls int
	r := NewReverseDNS(ReverseDNSOptions{CacheTTL: time.Minute, Lookup: func(context.Context, string) ([]string, error) {
		calls++
		return []string{"LAPTOP-ALICE.corp.local."}, nil
	}})
	id, ok := r.Resolve(context.Background(), nil, net.ParseIP("10.0.0.7"))
	if !ok || id.Device != "laptop-alice" {
		t.Fatalf("got %+v", id)
	}
	r.Resolve(context.Background(), nil, net.ParseIP("10.0.0.7"))
	if calls != 1 {
		t.Errorf("expected the lookup to be cached, ran %d times", calls)
	}

	// A failure is cached too, so an unresolvable address is not retried
	// on every single request.
	failing := NewReverseDNS(ReverseDNSOptions{Lookup: func(context.Context, string) ([]string, error) {
		calls++
		return nil, errors.New("nxdomain")
	}})
	calls = 0
	if _, ok := failing.Resolve(context.Background(), nil, net.ParseIP("10.0.0.8")); ok {
		t.Error("a failed lookup should not report a device")
	}
	failing.Resolve(context.Background(), nil, net.ParseIP("10.0.0.8"))
	if calls != 1 {
		t.Errorf("expected the failure to be cached, ran %d times", calls)
	}
	if _, ok := failing.Resolve(context.Background(), nil, nil); ok {
		t.Error("a nil address should resolve to nothing")
	}
}

type fixedResolver struct {
	name string
	id   Identity
}

func (f fixedResolver) Name() string { return f.name }
func (f fixedResolver) Resolve(context.Context, *http.Request, net.IP) (Identity, bool) {
	return f.id, f.id.User != "" || f.id.Device != ""
}

func TestChainPrefersFirstUserAndFillsDevice(t *testing.T) {
	chain := Chain{
		fixedResolver{name: "empty"},
		fixedResolver{name: "auth", id: Identity{User: "alice", Email: "alice@corp.example"}},
		fixedResolver{name: "dns", id: Identity{Device: "laptop-alice", User: "should-be-ignored"}},
	}
	id, ok := chain.Resolve(context.Background(), nil, nil)
	if !ok || id.User != "alice" || id.Source != "auth" || id.Device != "laptop-alice" || id.Email != "alice@corp.example" {
		t.Fatalf("got %+v", id)
	}
	if empty, ok := (Chain{fixedResolver{name: "empty"}}).Resolve(context.Background(), nil, nil); ok || empty.Known() {
		t.Error("an empty chain result should report nothing found")
	}
}

func TestIdentityLabelAndContext(t *testing.T) {
	cases := []struct {
		id   Identity
		want string
	}{
		{Identity{User: "alice", Device: "laptop"}, "alice"},
		{Identity{Device: "laptop"}, "laptop"},
		{Identity{}, "10.0.0.1"},
	}
	for _, c := range cases {
		if got := c.id.Label("10.0.0.1"); got != c.want {
			t.Errorf("Label() = %q, want %q", got, c.want)
		}
	}
	ctx := WithIdentity(context.Background(), Identity{User: "bob"})
	if FromContext(ctx).User != "bob" {
		t.Error("identity did not survive the context")
	}
	if FromContext(context.Background()).Known() {
		t.Error("an empty context should yield an unknown identity")
	}
}

func TestCSVDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.csv")
	body := "user,email,manager_email\nalice,alice@corp.example,mona@corp.example\nbob,bob@corp.example\n# comment\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := NewCSVDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Users() != 2 {
		t.Fatalf("expected 2 entries, got %d", d.Users())
	}
	email, manager, err := d.Lookup(context.Background(), "ALICE")
	if err != nil || email != "alice@corp.example" || manager != "mona@corp.example" {
		t.Fatalf("lookup: %q %q %v", email, manager, err)
	}
	if _, manager, err := d.Lookup(context.Background(), "bob"); err != nil || manager != "" {
		t.Fatalf("a missing manager column should be empty: %q %v", manager, err)
	}
	if _, _, err := d.Lookup(context.Background(), "nobody"); err == nil {
		t.Error("an unknown user should report an error")
	}
}

func TestChallengeRaw(t *testing.T) {
	raw := string(ChallengeRaw("Corp"))
	for _, want := range []string{"407 Proxy Authentication Required", `Basic realm="Corp"`, "Content-Length:"} {
		if !contains(raw, want) {
			t.Errorf("challenge missing %q:\n%s", want, raw)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
