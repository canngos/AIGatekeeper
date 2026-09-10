package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/ca"
	"github.com/canngos/aigatekeeper/internal/proxy"
)

const testCACN = "AIGatekeeper Test CA"

var quietLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

type echoReply struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Host   string `json:"host"`
	Body   string `json:"body"`
	Proto  string `json:"proto"`
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Upstream", "echo")
	_ = json.NewEncoder(w).Encode(echoReply{
		Method: r.Method, Path: r.URL.Path, Host: r.Host, Body: string(body), Proto: r.Proto,
	})
}

type harness struct {
	t        *testing.T
	ca       *ca.CA
	cache    *ca.Cache
	rec      *audit.Recorder
	proxyURL *url.URL
	cancel   context.CancelFunc
}

func newHarness(t *testing.T, upstreamCerts []*x509.Certificate, intercept func(string) bool, tunnelUnmatched bool) *harness {
	t.Helper()
	rootCA, err := ca.Generate(testCACN, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ca.NewSigner(rootCA, time.Hour)
	cache := ca.NewCache(signer, 16)
	rec := &audit.Recorder{}

	transport, err := proxy.NewTransport(proxy.TransportConfig{ExtraRoots: upstreamCerts})
	if err != nil {
		t.Fatal(err)
	}
	inspect := proxy.Chain(proxy.NewForwarder(transport, quietLogger), proxy.Audited(rec, true))
	srv := proxy.New(proxy.Options{
		Certs:           cache,
		Intercept:       intercept,
		TunnelUnmatched: func() bool { return tunnelUnmatched },
		Inspect:         inspect,
		Transport:       transport,
		Audit:           rec,
		Logger:          quietLogger,
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(cancel)
	pu, _ := url.Parse("http://" + ln.Addr().String())
	return &harness{t: t, ca: rootCA, cache: cache, rec: rec, proxyURL: pu, cancel: cancel}
}

// client returns an HTTP client that uses the proxy and trusts the given roots.
func (h *harness) client(roots ...*x509.Certificate) *http.Client {
	pool := x509.NewCertPool()
	for _, c := range roots {
		pool.AddCert(c)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(h.proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
}

func (h *harness) waitForEvent(kind string) *audit.Event {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range h.rec.Events() {
			if e.Kind == kind {
				return &e
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatalf("no %s audit event within timeout; events: %+v", kind, h.rec.Events())
	return nil
}

func interceptLoopback(host string) bool { return host == "127.0.0.1" }

func TestMITMInterceptsAndForwards(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(echoHandler))
	defer upstream.Close()
	h := newHarness(t, []*x509.Certificate{upstream.Certificate()}, interceptLoopback, true)
	client := h.client(h.ca.Cert)

	resp, err := client.Post(upstream.URL+"/v1/chat/completions?x=1", "application/json", strings.NewReader(`{"messages":[]}`))
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if resp.TLS == nil || resp.TLS.PeerCertificates[0].Issuer.CommonName != testCACN {
		t.Fatalf("expected leaf issued by our CA, got %+v", resp.TLS)
	}
	if resp.Header.Get(proxy.RequestIDHeader) == "" {
		t.Error("missing request id header")
	}
	if resp.Header.Get("X-Upstream") != "echo" {
		t.Error("upstream headers not relayed")
	}
	var reply echoReply
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		t.Fatal(err)
	}
	if reply.Method != "POST" || reply.Path != "/v1/chat/completions" || reply.Body != `{"messages":[]}` {
		t.Fatalf("unexpected echo: %+v", reply)
	}
	upstreamHost := strings.TrimPrefix(upstream.URL, "https://")
	if reply.Host != upstreamHost {
		t.Fatalf("Host header %q, want %q", reply.Host, upstreamHost)
	}

	ev := h.waitForEvent(audit.KindRequest)
	if ev.Host != upstreamHost || ev.Path != "/v1/chat/completions" || ev.UpstreamStatus != 200 || ev.Action != audit.ActionAllow || ev.Listener != proxy.ListenerForward {
		t.Fatalf("unexpected audit event: %+v", ev)
	}
	if ev.RequestID != resp.Header.Get(proxy.RequestIDHeader) {
		t.Error("audit request id does not match response header")
	}
}

func TestUnmatchedHostIsTunnelledOpaquely(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(echoHandler))
	defer upstream.Close()
	h := newHarness(t, nil, func(string) bool { return false }, true)
	// Trust only the upstream's own certificate: if the proxy had intercepted,
	// verification would fail.
	client := h.client(upstream.Certificate())

	resp, err := client.Get(upstream.URL + "/tunnel")
	if err != nil {
		t.Fatalf("tunnelled request failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.TLS.PeerCertificates[0].Issuer.CommonName == testCACN {
		t.Fatal("tunnelled connection was intercepted")
	}
	if resp.Header.Get(proxy.RequestIDHeader) != "" {
		t.Fatal("tunnelled response must not be touched by the proxy")
	}
	client.CloseIdleConnections()
	ev := h.waitForEvent(audit.KindTunnel)
	if ev.Action != audit.ActionAllow || ev.BytesIn == 0 || ev.BytesOut == 0 {
		t.Fatalf("unexpected tunnel event: %+v", ev)
	}
	for _, e := range h.rec.Events() {
		if e.Kind == audit.KindRequest {
			t.Fatal("tunnelled traffic produced a request event")
		}
	}
}

func TestUnmatchedHostRefusedWhenTunnellingDisabled(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(echoHandler))
	defer upstream.Close()
	h := newHarness(t, nil, func(string) bool { return false }, false)
	client := h.client(upstream.Certificate())
	_, err := client.Get(upstream.URL + "/refused")
	if err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("expected CONNECT to be refused with 403 Forbidden, got %v", err)
	}
	ev := h.waitForEvent(audit.KindTunnel)
	if ev.Action != audit.ActionBlock {
		t.Fatalf("expected block event, got %+v", ev)
	}
}

func TestPlainHTTPAbsoluteRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(echoHandler))
	defer upstream.Close()

	t.Run("intercepted host is inspected", func(t *testing.T) {
		h := newHarness(t, nil, interceptLoopback, true)
		resp, err := h.client().Get(upstream.URL + "/plain")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.Header.Get(proxy.RequestIDHeader) == "" {
			t.Fatal("expected inspection (request id header)")
		}
		ev := h.waitForEvent(audit.KindRequest)
		if ev.Path != "/plain" {
			t.Fatalf("unexpected event %+v", ev)
		}
	})
	t.Run("other host is passed through", func(t *testing.T) {
		h := newHarness(t, nil, func(string) bool { return false }, true)
		resp, err := h.client().Get(upstream.URL + "/pass")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
		ev := h.waitForEvent(audit.KindPassthrough)
		if ev.Path != "/pass" || ev.UpstreamStatus != 200 {
			t.Fatalf("unexpected event %+v", ev)
		}
	})
}

func TestReverseListenerRewritesToUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(echoHandler))
	defer upstream.Close()
	rec := &audit.Recorder{}
	inspect := proxy.Chain(proxy.NewForwarder(http.DefaultTransport, quietLogger), proxy.Audited(rec, true))
	rl, err := proxy.NewReverseListener("ollama", upstream.URL, inspect, quietLogger, rec)
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = rl.Serve(ctx, ln) }()

	resp, err := http.Post("http://"+ln.Addr().String()+"/api/chat", "application/json", strings.NewReader(`{"model":"llama3"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var reply echoReply
	_ = json.NewDecoder(resp.Body).Decode(&reply)
	if reply.Host != strings.TrimPrefix(upstream.URL, "http://") || reply.Path != "/api/chat" || reply.Body != `{"model":"llama3"}` {
		t.Fatalf("unexpected echo: %+v", reply)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range rec.Events() {
			if e.Kind == audit.KindRequest {
				if e.Listener != "ollama" {
					t.Fatalf("expected listener ollama, got %+v", e)
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no request audit event")
}

func TestStreamingResponsesAreNotBuffered(t *testing.T) {
	gate := make(chan struct{})
	timedOut := make(chan bool, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-gate:
			timedOut <- false
		case <-time.After(3 * time.Second):
			timedOut <- true
		}
		io.WriteString(w, "data: second\n\n")
	}))
	defer upstream.Close()
	h := newHarness(t, []*x509.Certificate{upstream.Certificate()}, interceptLoopback, true)
	client := h.client(h.ca.Cert)

	resp, err := client.Get(upstream.URL + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil || line != "data: first\n" {
		t.Fatalf("first chunk not received promptly: %q %v", line, err)
	}
	close(gate)
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "data: second") {
		t.Fatalf("second chunk missing: %q", rest)
	}
	if <-timedOut {
		t.Fatal("proxy buffered the stream: first chunk did not reach the client before the upstream timed out")
	}
}

func TestUpstreamFailureProducesGatewayError(t *testing.T) {
	// Point at a closed port: dial fails quickly.
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := closed.Addr().String()
	closed.Close()

	h := newHarness(t, nil, interceptLoopback, true)
	client := h.client(h.ca.Cert)
	resp, err := client.Get("https://" + addr + "/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
	ev := h.waitForEvent(audit.KindRequest)
	if ev.Error == "" || ev.UpstreamStatus != http.StatusBadGateway {
		t.Fatalf("expected error recorded, got %+v", ev)
	}
}
