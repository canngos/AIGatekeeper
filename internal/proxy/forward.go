package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// TransportConfig tunes the upstream HTTP transport.
type TransportConfig struct {
	// ExtraRootPEMFiles are appended to the system roots (private upstreams).
	ExtraRootPEMFiles []string
	// ExtraRoots are appended to the system roots (tests).
	ExtraRoots []*x509.Certificate
	// Insecure disables upstream certificate verification. Never default on.
	Insecure bool
	// UpstreamProxy routes upstream connections through another proxy.
	UpstreamProxy string
	// ResponseHeaderTimeout bounds the wait for upstream response headers.
	ResponseHeaderTimeout time.Duration
}

// NewTransport builds the shared upstream transport with system roots,
// HTTP/2 support and sane timeouts.
func NewTransport(cfg TransportConfig) (*http.Transport, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, path := range cfg.ExtraRootPEMFiles {
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read upstream root %s: %w", path, err)
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("upstream root %s: no certificates found", path)
		}
	}
	for _, c := range cfg.ExtraRoots {
		pool.AddCert(c)
	}
	var proxyFunc func(*http.Request) (*url.URL, error)
	if cfg.UpstreamProxy != "" {
		u, err := url.Parse(cfg.UpstreamProxy)
		if err != nil {
			return nil, fmt.Errorf("upstream proxy: %w", err)
		}
		proxyFunc = http.ProxyURL(u)
	}
	headerTimeout := cfg.ResponseHeaderTimeout
	if headerTimeout <= 0 {
		headerTimeout = 120 * time.Second
	}
	return &http.Transport{
		Proxy:                 proxyFunc,
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: headerTimeout,
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.Insecure, //nolint:gosec // explicit operator opt-in
		},
	}, nil
}

// Forwarder relays a request (whose URL is absolute) to its origin and
// streams the response back, flushing after every chunk so SSE and NDJSON
// streams are not buffered.
type Forwarder struct {
	Transport http.RoundTripper
	Logger    *slog.Logger
}

// NewForwarder creates a Forwarder over rt.
func NewForwarder(rt http.RoundTripper, logger *slog.Logger) *Forwarder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Forwarder{Transport: rt, Logger: logger}
}

// hopByHopHeaders must not be forwarded (RFC 9110 §7.6.1) and neither must
// proxy-specific headers the client addressed to us.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// ServeHTTP implements http.Handler.
func (f *Forwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tx := TransactionFrom(r.Context())

	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Header = cleanHeaders(r.Header)
	out.Header.Del(RequestIDHeader)
	if out.URL.Scheme == "" {
		out.URL.Scheme = "https"
	}
	if out.URL.Host == "" {
		out.URL.Host = r.Host
	}
	if out.Host == "" {
		out.Host = out.URL.Host
	}
	if out.Body == nil || out.Body == http.NoBody {
		out.Body = http.NoBody
		out.ContentLength = 0
	}

	resp, err := f.Transport.RoundTrip(out)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			status = http.StatusGatewayTimeout
		}
		if tx != nil {
			tx.Err = err
			tx.UpstreamStatus = status
		}
		f.Logger.Warn("upstream request failed", "host", out.URL.Host, "path", out.URL.Path, "error", err)
		WriteJSONError(w, status, "upstream_error", "AIGatekeeper could not reach the upstream service: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if tx != nil {
		tx.UpstreamStatus = resp.StatusCode
	}
	dst := w.Header()
	for k, vv := range cleanHeaders(resp.Header) {
		dst[k] = vv
	}
	w.WriteHeader(resp.StatusCode)
	flushingCopy(w, resp.Body)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// cleanHeaders copies h without hop-by-hop headers and without any header
// named in the Connection field.
func cleanHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vv := range h {
		out[k] = append([]string(nil), vv...)
	}
	for _, conn := range h.Values("Connection") {
		for _, name := range strings.Split(conn, ",") {
			if name = strings.TrimSpace(name); name != "" {
				out.Del(name)
			}
		}
	}
	for _, k := range hopByHopHeaders {
		out.Del(k)
	}
	return out
}

// flushingCopy streams src to w, flushing after each read so the client sees
// chunks as soon as the upstream produces them.
func flushingCopy(w http.ResponseWriter, src io.Reader) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// WriteJSONError writes a generic JSON error body. Service-native shapes are
// produced by the action package for blocked requests.
func WriteJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"type":    "aigatekeeper_error",
			"code":    code,
			"message": message,
		},
	})
}
