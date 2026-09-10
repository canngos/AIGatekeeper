package proxy_test

import (
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/identity"
)

// identifyFor accepts one hard-coded credential and always names the device,
// standing in for the htpasswd and reverse DNS resolvers.
func identifyFor(user, password string) func(*http.Request, net.IP) (identity.Identity, bool) {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	return func(r *http.Request, _ net.IP) (identity.Identity, bool) {
		if r.Header.Get(identity.ProxyAuthHeader) != want {
			return identity.Identity{}, false
		}
		return identity.Identity{User: user, Device: "laptop-" + user, Source: "proxy_auth"}, true
	}
}

func newIdentityHarness(t *testing.T, upstreamCerts []*x509.Certificate, identify func(*http.Request, net.IP) (identity.Identity, bool)) *harness {
	t.Helper()
	h := newHarness(t, upstreamCerts, interceptLoopback, true)
	h.restartWith(t, identify)
	return h
}

func TestProxyAuthChallengeAndAttribution(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(echoHandler))
	defer upstream.Close()
	h := newIdentityHarness(t, []*x509.Certificate{upstream.Certificate()}, identifyFor("alice", "s3cret"))

	t.Run("connect without credentials is challenged", func(t *testing.T) {
		client := h.client(h.ca.Cert)
		_, err := client.Post(upstream.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{}`))
		if err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
			t.Fatalf("expected a 407 challenge, got %v", err)
		}
		ev := h.waitForEvent(audit.KindAuth)
		if ev.Reason != "proxy_auth_required" || ev.Action != audit.ActionBlock {
			t.Fatalf("unexpected auth event: %+v", ev)
		}
	})

	t.Run("valid credentials name the user on every request in the tunnel", func(t *testing.T) {
		h.rec.Reset()
		client := h.clientWithAuth(h.ca.Cert, "alice", "s3cret")
		// Two requests share one CONNECT, so the second is attributed from
		// the connection rather than a header it never sends.
		for i := 0; i < 2; i++ {
			resp, err := client.Post(upstream.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"messages":[]}`))
			if err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		events := requestEvents(h)
		if len(events) < 2 {
			t.Fatalf("expected two request events, got %d", len(events))
		}
		for _, ev := range events {
			if ev.User != "alice" || ev.Device != "laptop-alice" || ev.UserSource != "proxy_auth" {
				t.Fatalf("request not attributed: %+v", ev)
			}
		}
	})

	t.Run("credentials never reach the upstream", func(t *testing.T) {
		client := h.clientWithAuth(h.ca.Cert, "alice", "s3cret")
		resp, err := client.Post(upstream.URL+"/echo-headers", "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(body), "Proxy-Authorization") {
			t.Fatal("the proxy credential was forwarded to the upstream")
		}
	})

	t.Run("wrong credentials are challenged", func(t *testing.T) {
		client := h.clientWithAuth(h.ca.Cert, "alice", "wrong")
		_, err := client.Get(upstream.URL + "/")
		if err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
			t.Fatalf("expected a 407 challenge, got %v", err)
		}
	})
}

func TestTunnelledTrafficIsAttributedToo(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(echoHandler))
	defer upstream.Close()
	h := newHarness(t, nil, func(string) bool { return false }, true)
	h.restartWith(t, identifyFor("bob", "pw"))

	client := h.clientWithAuth(upstream.Certificate(), "bob", "pw")
	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	client.CloseIdleConnections()

	ev := h.waitForEvent(audit.KindTunnel)
	if ev.User != "bob" || ev.Device != "laptop-bob" {
		t.Fatalf("a tunnelled connection should still be attributed: %+v", ev)
	}
}

func requestEvents(h *harness) []audit.Event {
	var out []audit.Event
	for _, e := range h.rec.Events() {
		if e.Kind == audit.KindRequest {
			out = append(out, e)
		}
	}
	return out
}
