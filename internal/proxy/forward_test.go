package proxy

import (
	"net/http"
	"testing"
)

func TestCleanHeadersStripsHopByHopAndConnectionListed(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer x")
	h.Set("Proxy-Authorization", "Basic y")
	h.Set("Proxy-Connection", "keep-alive")
	h.Set("Connection", "X-Custom-Hop, keep-alive")
	h.Set("X-Custom-Hop", "1")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Content-Type", "application/json")

	out := cleanHeaders(h)
	for _, gone := range []string{"Proxy-Authorization", "Proxy-Connection", "Connection", "X-Custom-Hop", "Transfer-Encoding"} {
		if out.Get(gone) != "" {
			t.Errorf("%s should have been stripped", gone)
		}
	}
	for _, kept := range []string{"Authorization", "Content-Type"} {
		if out.Get(kept) == "" {
			t.Errorf("%s should have been kept", kept)
		}
	}
	if h.Get("Proxy-Authorization") == "" {
		t.Error("cleanHeaders must not mutate its input")
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct{ in, host, port string }{
		{"api.openai.com:443", "api.openai.com", "443"},
		{"api.openai.com", "api.openai.com", "443"},
		{"[::1]:8443", "::1", "8443"},
	}
	for _, c := range cases {
		host, port, err := splitHostPort(c.in, "443")
		if err != nil || host != c.host || port != c.port {
			t.Errorf("%q: got %q %q %v", c.in, host, port, err)
		}
	}
	if _, _, err := splitHostPort("", "443"); err == nil {
		t.Error("expected error for empty target")
	}
}
