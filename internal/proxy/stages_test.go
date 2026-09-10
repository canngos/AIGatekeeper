package proxy_test

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/andybalholm/brotli"

	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/config"
	"github.com/canngos/aigatekeeper/internal/parser"
	"github.com/canngos/aigatekeeper/internal/policy"
	"github.com/canngos/aigatekeeper/internal/proxy"
)

const stagesConfig = `
version: 1
services:
  - name: openai
    hosts: ['^127\.0\.0\.1$']
    extractor: openai
    passthrough_paths: ['^/v1/models$']
    rules: [secrets]
rules:
  - { id: secrets, severity: critical, action: block, detectors: [aws_access_key] }
`

// capture records the transaction and the body the terminal handler received.
type capture struct {
	mu   sync.Mutex
	tx   *proxy.Transaction
	body []byte
	hdr  http.Header
}

func (c *capture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.tx = proxy.TransactionFrom(r.Context())
	c.body = body
	c.hdr = r.Header.Clone()
	c.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func newStagesServer(t *testing.T, limits proxy.BodyLimits) (*httptest.Server, *capture) {
	t.Helper()
	cfg, err := config.Parse([]byte(stagesConfig))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Compile(cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	cap := &capture{}
	chain := proxy.Chain(cap,
		proxy.Audited(audit.Discard, true),
		proxy.Route(policy.NewStore(pol)),
		proxy.ReadBody(limits),
		proxy.Parse(parser.Default()),
	)
	srv := httptest.NewServer(chain)
	t.Cleanup(srv.Close)
	return srv, cap
}

func compress(t *testing.T, enc string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w io.WriteCloser
	switch enc {
	case "gzip":
		w = gzip.NewWriter(&buf)
	case "deflate":
		w = zlib.NewWriter(&buf)
	case "br":
		w = brotli.NewWriter(&buf)
	default:
		t.Fatalf("unknown encoding %s", enc)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func post(t *testing.T, url, path string, body []byte, headers map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

const chatBody = `{"model":"gpt-4o","messages":[{"role":"user","content":"my key is AKIAIOSFODNN7EXAMPLE"}]}`

func TestStagesPlainJSON(t *testing.T) {
	srv, cap := newStagesServer(t, proxy.BodyLimits{MaxBodyBytes: 1024, MaxDecodedBytes: 4096})
	post(t, srv.URL, "/v1/chat/completions", []byte(chatBody), nil)

	tx := cap.tx
	if tx.Service == nil || tx.Service.Name != "openai" {
		t.Fatalf("service not routed: %+v", tx.Service)
	}
	if string(tx.RawBody) != chatBody || string(tx.Body) != chatBody {
		t.Fatalf("body not captured: raw=%q body=%q", tx.RawBody, tx.Body)
	}
	if string(cap.body) != chatBody {
		t.Fatalf("forwarded body altered: %q", cap.body)
	}
	if tx.Extraction == nil || len(tx.Extraction.Segments) != 1 || !strings.Contains(tx.Extraction.Segments[0].Text, "AKIA") {
		t.Fatalf("extraction missing: %+v", tx.Extraction)
	}
	if tx.Model != "gpt-4o" || tx.Encoding != "" || tx.Oversize || tx.ParseErr != nil {
		t.Fatalf("unexpected tx fields: %+v", tx)
	}
}

func TestStagesDecodeCompressedBodies(t *testing.T) {
	for _, enc := range []string{"gzip", "deflate", "br"} {
		t.Run(enc, func(t *testing.T) {
			srv, cap := newStagesServer(t, proxy.BodyLimits{MaxBodyBytes: 4096, MaxDecodedBytes: 1 << 20})
			compressed := compress(t, enc, []byte(chatBody))
			post(t, srv.URL, "/v1/chat/completions", compressed, map[string]string{"Content-Encoding": enc})

			tx := cap.tx
			if !bytes.Equal(tx.RawBody, compressed) {
				t.Fatal("raw body should be the compressed bytes")
			}
			if string(tx.Body) != chatBody {
				t.Fatalf("decoded body mismatch: %q", tx.Body)
			}
			if tx.Encoding != enc {
				t.Fatalf("encoding = %q", tx.Encoding)
			}
			if !bytes.Equal(cap.body, compressed) || cap.hdr.Get("Content-Encoding") != enc {
				t.Fatal("compressed body must be forwarded verbatim with its Content-Encoding header")
			}
			if tx.Extraction == nil || len(tx.Extraction.Segments) != 1 {
				t.Fatalf("extraction missing after decode: %+v", tx.Extraction)
			}
		})
	}
}

func TestStagesRawDeflateFallback(t *testing.T) {
	srv, cap := newStagesServer(t, proxy.BodyLimits{MaxBodyBytes: 4096, MaxDecodedBytes: 1 << 20})
	// Strip the 2-byte zlib header and 4-byte adler trailer to get raw DEFLATE.
	z := compress(t, "deflate", []byte(chatBody))
	raw := z[2 : len(z)-4]
	post(t, srv.URL, "/v1/chat/completions", raw, map[string]string{"Content-Encoding": "deflate"})
	if string(cap.tx.Body) != chatBody {
		t.Fatalf("raw deflate not decoded: %q (err %v)", cap.tx.Body, cap.tx.ParseErr)
	}
}

func TestStagesOversizeRawBodyIsStillForwarded(t *testing.T) {
	srv, cap := newStagesServer(t, proxy.BodyLimits{MaxBodyBytes: 32, MaxDecodedBytes: 128})
	big := []byte(`{"messages":[{"role":"user","content":"` + strings.Repeat("x", 200) + `"}]}`)
	post(t, srv.URL, "/v1/chat/completions", big, nil)
	tx := cap.tx
	if !tx.Oversize || tx.Body != nil || tx.Extraction != nil {
		t.Fatalf("expected oversize with no parse, got %+v", tx)
	}
	if !bytes.Equal(cap.body, big) {
		t.Fatalf("oversize body must still be forwarded intact (got %d of %d bytes)", len(cap.body), len(big))
	}
}

func TestStagesDecompressionBomb(t *testing.T) {
	srv, cap := newStagesServer(t, proxy.BodyLimits{MaxBodyBytes: 64 << 10, MaxDecodedBytes: 1024})
	bomb := compress(t, "gzip", bytes.Repeat([]byte("0"), 100_000)) // ~100 bytes compressed
	post(t, srv.URL, "/v1/chat/completions", bomb, map[string]string{"Content-Encoding": "gzip"})
	tx := cap.tx
	if !tx.Oversize || tx.Body != nil {
		t.Fatalf("expected decoded-size cap to trigger oversize, got oversize=%v decoded=%d bytes err=%v", tx.Oversize, len(tx.Body), tx.ParseErr)
	}
	if !bytes.Equal(cap.body, bomb) {
		t.Fatal("body should still be forwarded verbatim")
	}
}

func TestStagesCorruptEncodingRecordsParseError(t *testing.T) {
	srv, cap := newStagesServer(t, proxy.BodyLimits{MaxBodyBytes: 4096, MaxDecodedBytes: 4096})
	post(t, srv.URL, "/v1/chat/completions", []byte("not gzip at all"), map[string]string{"Content-Encoding": "gzip"})
	if cap.tx.ParseErr == nil || cap.tx.Body != nil {
		t.Fatalf("expected parse error for corrupt gzip, got %+v", cap.tx)
	}
}

func TestStagesInvalidJSONRecordsParseError(t *testing.T) {
	srv, cap := newStagesServer(t, proxy.BodyLimits{MaxBodyBytes: 4096, MaxDecodedBytes: 4096})
	post(t, srv.URL, "/v1/chat/completions", []byte(`{"messages": [`), nil)
	if !errors.Is(cap.tx.ParseErr, parser.ErrNotJSON) {
		t.Fatalf("expected ErrNotJSON, got %v", cap.tx.ParseErr)
	}
}

func TestStagesNonJSONBodyIsNotParsed(t *testing.T) {
	srv, cap := newStagesServer(t, proxy.BodyLimits{MaxBodyBytes: 4096, MaxDecodedBytes: 4096})
	post(t, srv.URL, "/v1/audio", []byte("RIFF....WAVE"), map[string]string{"Content-Type": "audio/wav"})
	if cap.tx.Extraction != nil || cap.tx.ParseErr != nil || cap.tx.Body == nil {
		t.Fatalf("binary body should be buffered but not parsed: %+v", cap.tx)
	}
}

func TestStagesPassthroughPathAndGetSkipBuffering(t *testing.T) {
	srv, cap := newStagesServer(t, proxy.BodyLimits{MaxBodyBytes: 4096, MaxDecodedBytes: 4096})
	post(t, srv.URL, "/v1/models", []byte(chatBody), nil)
	if !cap.tx.Passthrough || cap.tx.RawBody != nil {
		t.Fatalf("passthrough path should skip buffering: %+v", cap.tx)
	}
	if string(cap.body) != chatBody {
		t.Fatal("passthrough body must still reach upstream")
	}

	resp, err := http.Get(srv.URL + "/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if cap.tx.RawBody != nil || cap.tx.Extraction != nil {
		t.Fatalf("GET should not be buffered: %+v", cap.tx)
	}
}

func TestStagesUnroutedHostIsUntouched(t *testing.T) {
	cfg, _ := config.Parse([]byte(strings.Replace(stagesConfig, `'^127\.0\.0\.1$'`, `'^api\.example\.com$'`, 1)))
	pol, _ := policy.Compile(cfg, "test")
	cap := &capture{}
	srv := httptest.NewServer(proxy.Chain(cap,
		proxy.Audited(audit.Discard, true),
		proxy.Route(policy.NewStore(pol)),
		proxy.ReadBody(proxy.BodyLimits{MaxBodyBytes: 4096, MaxDecodedBytes: 4096}),
		proxy.Parse(nil),
	))
	defer srv.Close()
	post(t, srv.URL, "/v1/chat/completions", []byte(chatBody), nil)
	if cap.tx.Service != nil || cap.tx.RawBody != nil {
		t.Fatalf("unrouted request should not be inspected: %+v", cap.tx)
	}
}
