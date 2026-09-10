package proxy

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/identity"
)

// mitm terminates TLS on the client connection with a certificate for host
// and serves the decrypted HTTP requests through the Inspect handler.
func (s *Server) mitm(client net.Conn, host, port string, id identity.Identity) {
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: s.opts.Certs.GetCertificate(host),
		NextProtos:     []string{"http/1.1"},
	}
	if s.opts.AdvertiseHTTP2 {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}

	tlsConn := tls.Server(client, cfg)
	_ = tlsConn.SetDeadline(time.Now().Add(s.opts.HandshakeTimeout))
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		s.opts.Logger.Debug("client TLS handshake failed", "host", host, "client", client.RemoteAddr().String(), "error", err)
		s.opts.Audit.Log(audit.Event{
			Time: time.Now(), Kind: audit.KindTLSError, ClientIP: clientIP(client.RemoteAddr().String()),
			Listener: ListenerForward, Host: host, Error: err.Error(),
		})
		tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	authority := host
	if port != "443" {
		authority = net.JoinHostPort(host, port)
	}
	handler := &mitmHandler{authority: authority, inspect: s.opts.Inspect}
	// The caller authenticated on CONNECT; everything inside this tunnel
	// is theirs.
	baseCtx := identity.WithIdentity(WithListener(context.Background(), ListenerForward), id)

	if tlsConn.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
		h2 := &http2.Server{IdleTimeout: 2 * time.Minute}
		h2.ServeConn(tlsConn, &http2.ServeConnOpts{
			Context: baseCtx,
			Handler: handler,
		})
		return
	}

	ln := newOneConnListener(tlsConn)
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(s.opts.Logger.Handler(), slog.LevelDebug),
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
	}
	_ = srv.Serve(ln)
}

// mitmHandler rewrites decrypted requests into absolute form and hands them
// to the inspection chain.
type mitmHandler struct {
	authority string
	inspect   http.Handler
}

func (h *mitmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.URL.Scheme = "https"
	if r.URL.Host == "" {
		r.URL.Host = h.authority
	}
	if r.Host == "" {
		r.Host = h.authority
	}
	h.inspect.ServeHTTP(w, r)
}

// oneConnListener hands a single, already-established connection to
// http.Server.Serve and reports closed once that connection is done, so the
// serving goroutine returns instead of leaking.
type oneConnListener struct {
	conn      net.Conn
	once      sync.Once
	closeOnce sync.Once
	done      chan struct{}
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{done: make(chan struct{})}
	l.conn = &notifyConn{Conn: c, onClose: l.Close}
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// notifyConn signals its listener when the served connection is closed.
type notifyConn struct {
	net.Conn
	onClose func() error
	once    sync.Once
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { _ = c.onClose() })
	return err
}
