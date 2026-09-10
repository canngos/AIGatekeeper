package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/ca"
	"github.com/canngos/aigatekeeper/internal/identity"
)

// Options configures the forward proxy server.
type Options struct {
	// Certs issues leaf certificates for intercepted hosts.
	Certs *ca.Cache
	// Intercept decides whether CONNECTs to host are decrypted and inspected.
	Intercept func(host string) bool
	// TunnelUnmatched decides whether CONNECTs to other hosts are tunnelled
	// opaquely (true) or refused (false).
	TunnelUnmatched func() bool
	// Inspect handles decrypted requests and plain-HTTP requests to
	// intercepted hosts. r.URL is absolute.
	Inspect http.Handler
	// Passthrough handles plain-HTTP absolute-URI requests to hosts that are
	// not intercepted. Defaults to a bare Forwarder over Transport.
	Passthrough http.Handler
	// Transport is used for tunnel dialling defaults and the default
	// Passthrough handler.
	Transport http.RoundTripper
	// AdvertiseHTTP2 offers "h2" to intercepted clients via ALPN.
	AdvertiseHTTP2 bool
	// Identify resolves who sent a request. ok=false means the caller must
	// be challenged for proxy credentials before anything is forwarded.
	// A nil Identify means identity is switched off and everything passes.
	Identify func(r *http.Request, clientIP net.IP) (identity.Identity, bool)
	// AuthRealm names the realm offered in a 407 challenge.
	AuthRealm string
	// DialTimeout bounds tunnel dials.
	DialTimeout time.Duration
	// HandshakeTimeout bounds the client-facing TLS handshake.
	HandshakeTimeout time.Duration
	Audit            audit.Logger
	Logger           *slog.Logger
}

// Server is the forward proxy.
type Server struct {
	opts   Options
	srv    *http.Server
	dialer *net.Dialer

	mu   sync.Mutex
	addr net.Addr
}

// New creates a forward proxy server. Call Serve or ListenAndServe to run it.
func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Audit == nil {
		opts.Audit = audit.Discard
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 15 * time.Second
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = 15 * time.Second
	}
	if opts.TunnelUnmatched == nil {
		opts.TunnelUnmatched = func() bool { return true }
	}
	if opts.Intercept == nil {
		opts.Intercept = func(string) bool { return false }
	}
	if opts.Passthrough == nil {
		rt := opts.Transport
		if rt == nil {
			rt = http.DefaultTransport
		}
		opts.Passthrough = NewForwarder(rt, opts.Logger)
	}
	s := &Server{
		opts:   opts,
		dialer: &net.Dialer{Timeout: opts.DialTimeout, KeepAlive: 30 * time.Second},
	}
	s.srv = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(opts.Logger.Handler(), slog.LevelDebug),
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return WithListener(ctx, ListenerForward)
		},
	}
	return s
}

// ListenAndServe listens on addr and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	return s.Serve(ctx, ln)
}

// Serve serves on ln until ctx is cancelled, then shuts down gracefully.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.mu.Lock()
	s.addr = ln.Addr()
	s.mu.Unlock()

	s.opts.Audit.Log(audit.Event{Time: time.Now(), Kind: audit.KindProxyStart, Listener: ListenerForward, Message: ln.Addr().String()})
	s.opts.Logger.Info("forward proxy listening", "addr", ln.Addr().String())

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.srv.Shutdown(shutdownCtx)
		case <-done:
		}
	}()
	err := s.srv.Serve(ln)
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Addr returns the bound address once Serve has been called.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// ServeHTTP dispatches proxy requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		s.handleConnect(w, r)
	case r.URL.IsAbs():
		s.handleAbsolute(w, r)
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "AIGatekeeper is a forward proxy. Configure it as your HTTP/HTTPS proxy; it does not serve pages directly.\n")
	}
}

// identify runs the identity chain, writing a 407 challenge when the
// caller must authenticate first. It reports whether to continue.
func (s *Server) identify(w http.ResponseWriter, r *http.Request) (identity.Identity, bool) {
	if s.opts.Identify == nil {
		return identity.Identity{}, true
	}
	id, ok := s.opts.Identify(r, net.ParseIP(clientIP(r.RemoteAddr)))
	if ok {
		return id, true
	}
	realm := s.opts.AuthRealm
	if realm == "" {
		realm = "AIGatekeeper"
	}
	w.Header().Set("Proxy-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusProxyAuthRequired)
	_, _ = io.WriteString(w, "AIGatekeeper requires proxy credentials.\n")
	s.opts.Audit.Log(audit.Event{
		Time: time.Now(), Kind: audit.KindAuth, ClientIP: clientIP(r.RemoteAddr), Listener: ListenerFrom(r.Context()),
		Method: r.Method, Host: r.Host, Action: audit.ActionBlock, Reason: "proxy_auth_required",
	})
	return identity.Identity{}, false
}

// handleAbsolute serves plain-HTTP requests sent through the proxy
// (GET http://host/path). Intercepted hosts are inspected; others are relayed.
func (s *Server) handleAbsolute(w http.ResponseWriter, r *http.Request) {
	id, ok := s.identify(w, r)
	if !ok {
		return
	}
	r = r.WithContext(identity.WithIdentity(r.Context(), id))
	r.Header.Del(identity.ProxyAuthHeader)
	host := ca.NormalizeHost(r.URL.Hostname())
	if s.opts.Intercept(host) && s.opts.Inspect != nil {
		s.opts.Inspect.ServeHTTP(w, r)
		return
	}
	if !s.opts.TunnelUnmatched() {
		WriteJSONError(w, http.StatusForbidden, "host_not_permitted", "requests to this host are not permitted by policy")
		return
	}
	start := time.Now()
	rec := &responseRecorder{ResponseWriter: w}
	s.opts.Passthrough.ServeHTTP(rec, r)
	s.opts.Audit.Log(audit.Event{
		Time:           start,
		Kind:           audit.KindPassthrough,
		ClientIP:       clientIP(r.RemoteAddr),
		Listener:       ListenerForward,
		Method:         r.Method,
		Host:           r.URL.Host,
		Path:           r.URL.Path,
		Action:         audit.ActionAllow,
		UpstreamStatus: rec.status,
		BytesOut:       rec.bytes,
		LatencyMS:      time.Since(start).Milliseconds(),
	})
}

// handleConnect establishes either an opaque tunnel or a TLS interception
// session for CONNECT host:port.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Credentials ride on the CONNECT request only; every request later
	// decrypted inside the tunnel belongs to the same caller, so the
	// identity is resolved once here and carried on the connection.
	id, allowed := s.identify(w, r)
	if !allowed {
		return
	}
	host, port, err := splitHostPort(r.Host, "443")
	if err != nil {
		WriteJSONError(w, http.StatusBadRequest, "bad_connect_target", err.Error())
		return
	}
	host = ca.NormalizeHost(host)
	intercept := s.opts.Intercept(host) && s.opts.Inspect != nil && s.opts.Certs != nil

	if !intercept && !s.opts.TunnelUnmatched() {
		s.opts.Audit.Log(audit.Event{
			Time: time.Now(), Kind: audit.KindTunnel, ClientIP: clientIP(r.RemoteAddr), Listener: ListenerForward,
			Method: r.Method, Host: r.Host, Action: audit.ActionBlock, Reason: "host_not_permitted",
		})
		WriteJSONError(w, http.StatusForbidden, "host_not_permitted", "CONNECT to this host is not permitted by policy")
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		WriteJSONError(w, http.StatusInternalServerError, "hijack_unsupported", "connection cannot be hijacked")
		return
	}

	var upstream net.Conn
	if !intercept {
		upstream, err = s.dialer.DialContext(r.Context(), "tcp", net.JoinHostPort(host, port))
		if err != nil {
			s.opts.Logger.Warn("tunnel dial failed", "target", r.Host, "error", err)
			WriteJSONError(w, http.StatusBadGateway, "dial_failed", "could not connect to "+r.Host+": "+err.Error())
			return
		}
	}

	clientConn, bufrw, err := hijacker.Hijack()
	if err != nil {
		if upstream != nil {
			upstream.Close()
		}
		s.opts.Logger.Warn("hijack failed", "error", err)
		return
	}
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		if upstream != nil {
			upstream.Close()
		}
		return
	}
	conn := &bufferedConn{Conn: clientConn, r: bufrw.Reader}

	if intercept {
		s.mitm(conn, host, port, id)
		return
	}
	s.tunnel(conn, upstream, r.Host, id)
}

// tunnel copies bytes in both directions until either side closes.
func (s *Server) tunnel(client, upstream net.Conn, target string, id identity.Identity) {
	start := time.Now()
	var inBytes, outBytes int64
	done := make(chan struct{}, 2)

	go func() {
		n, _ := io.Copy(upstream, client)
		inBytes = n
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(client, upstream)
		outBytes = n
		closeWrite(client)
		done <- struct{}{}
	}()

	<-done
	// Give the other direction a moment to drain after a half-close, then
	// tear everything down so nothing leaks.
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}
	client.Close()
	upstream.Close()

	s.opts.Audit.Log(audit.Event{
		Time:       start,
		Kind:       audit.KindTunnel,
		ClientIP:   clientIP(client.RemoteAddr().String()),
		User:       id.User,
		Device:     id.Device,
		UserSource: id.Source,
		Listener:   ListenerForward,
		Method:     http.MethodConnect,
		Host:       target,
		Action:     audit.ActionAllow,
		BytesIn:    inBytes,
		BytesOut:   outBytes,
		LatencyMS:  time.Since(start).Milliseconds(),
	})
}

func closeWrite(c net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	switch cw := c.(type) {
	case closeWriter:
		_ = cw.CloseWrite()
	case *bufferedConn:
		closeWrite(cw.Conn)
	default:
		_ = c.Close()
	}
}

func splitHostPort(authority, defaultPort string) (string, string, error) {
	if authority == "" {
		return "", "", errors.New("empty CONNECT target")
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			return authority, defaultPort, nil
		}
		return "", "", fmt.Errorf("invalid CONNECT target %q", authority)
	}
	if port == "" {
		port = defaultPort
	}
	return host, port, nil
}

// bufferedConn serves bytes the HTTP server already buffered before the
// hijack (for example an eagerly sent TLS ClientHello) ahead of the socket.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
