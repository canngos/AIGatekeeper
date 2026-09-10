package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/canngos/aigatekeeper/internal/audit"
)

// ReverseListener fronts a local model server (for example Ollama on a
// different port) for clients that never send localhost traffic through a
// proxy. Requests are rewritten to the upstream and pass through the same
// inspection chain as intercepted forward-proxy traffic.
type ReverseListener struct {
	Name     string
	Upstream *url.URL
	Inspect  http.Handler
	Audit    audit.Logger
	Logger   *slog.Logger

	srv *http.Server
}

// NewReverseListener validates upstream and builds the listener.
func NewReverseListener(name, upstream string, inspect http.Handler, logger *slog.Logger, auditLog audit.Logger) (*ReverseListener, error) {
	u, err := url.Parse(upstream)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("reverse listener %s: invalid upstream %q", name, upstream)
	}
	if logger == nil {
		logger = slog.Default()
	}
	if auditLog == nil {
		auditLog = audit.Discard
	}
	rl := &ReverseListener{Name: name, Upstream: u, Inspect: inspect, Audit: auditLog, Logger: logger}
	rl.srv = &http.Server{
		Handler:           rl,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return WithListener(ctx, name)
		},
	}
	return rl, nil
}

// ServeHTTP rewrites the request to the upstream and inspects it.
func (rl *ReverseListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.URL.Scheme = rl.Upstream.Scheme
	r.URL.Host = rl.Upstream.Host
	r.Host = rl.Upstream.Host
	rl.Inspect.ServeHTTP(w, r)
}

// ListenAndServe listens on addr until ctx is cancelled.
func (rl *ReverseListener) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("reverse listener %s: listen %s: %w", rl.Name, addr, err)
	}
	return rl.Serve(ctx, ln)
}

// Serve serves on ln until ctx is cancelled.
func (rl *ReverseListener) Serve(ctx context.Context, ln net.Listener) error {
	rl.Audit.Log(audit.Event{Time: time.Now(), Kind: audit.KindProxyStart, Listener: rl.Name, Message: ln.Addr().String() + " -> " + rl.Upstream.String()})
	rl.Logger.Info("reverse listener listening", "name", rl.Name, "addr", ln.Addr().String(), "upstream", rl.Upstream.String())
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = rl.srv.Shutdown(shutdownCtx)
		case <-done:
		}
	}()
	err := rl.srv.Serve(ln)
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
