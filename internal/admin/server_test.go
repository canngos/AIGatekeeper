package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T, opts Options) *httptest.Server {
	t.Helper()
	opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(New(opts).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func TestHealthReadyAndCA(t *testing.T) {
	ready := false
	srv := newTestServer(t, Options{CACertPEM: []byte("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"), Version: "1.2.3", Ready: func() bool { return ready }})

	if code, m := get(t, srv.URL+"/healthz"); code != 200 || m["version"] != "1.2.3" {
		t.Fatalf("healthz: %d %v", code, m)
	}
	if code, _ := get(t, srv.URL+"/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("readyz should be 503 before ready, got %d", code)
	}
	ready = true
	if code, _ := get(t, srv.URL+"/readyz"); code != 200 {
		t.Fatalf("readyz should be 200 when ready, got %d", code)
	}
	resp, _ := http.Get(srv.URL + "/ca.crt")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Header.Get("Content-Type") != "application/x-pem-file" || !strings.HasPrefix(string(body), "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("ca.crt: %s %q", resp.Header.Get("Content-Type"), body)
	}
}

func TestReloadEndpoint(t *testing.T) {
	calls := 0
	var reloadErr error
	srv := newTestServer(t, Options{Reload: func(context.Context) (bool, string, error) {
		calls++
		return calls == 1, "hash123", reloadErr
	}})

	resp, _ := http.Post(srv.URL+"/-/reload", "", nil)
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	if resp.StatusCode != 200 || m["changed"] != true || m["version"] != "hash123" {
		t.Fatalf("first reload: %d %v", resp.StatusCode, m)
	}
	resp, _ = http.Post(srv.URL+"/-/reload", "", nil)
	_ = json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	if m["changed"] != false {
		t.Fatalf("second reload should report unchanged: %v", m)
	}
	reloadErr = errors.New("bad yaml")
	resp, _ = http.Post(srv.URL+"/-/reload", "", nil)
	_ = json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity || m["error"] != "bad yaml" {
		t.Fatalf("failed reload: %d %v", resp.StatusCode, m)
	}
	if code, _ := get(t, srv.URL+"/-/reload"); code != http.StatusMethodNotAllowed {
		t.Fatalf("GET reload should be 405, got %d", code)
	}
}

func TestPolicyAndMetrics(t *testing.T) {
	srv := newTestServer(t, Options{PolicyInfo: func() any { return map[string]any{"services": []string{"openai"}} }})
	if code, m := get(t, srv.URL+"/-/policy"); code != 200 || m["services"] == nil {
		t.Fatalf("policy: %d %v", code, m)
	}
	code, m := get(t, srv.URL+"/metrics")
	if code != 200 {
		t.Fatalf("metrics status %d", code)
	}
	if _, ok := m["memstats"]; !ok {
		t.Fatalf("expected expvar output, got %v", m)
	}
}
