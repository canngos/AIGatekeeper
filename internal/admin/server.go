// Package admin serves health endpoints, the CA certificate, operational
// endpoints (reload, policy summary, metrics) and, in later phases, the JSON
// API and embedded web UI.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// ReloadFunc re-reads the configuration; it reports whether the policy
// changed and the resulting version hash.
type ReloadFunc func(ctx context.Context) (changed bool, version string, err error)

// Options configures the admin server.
type Options struct {
	CACertPEM []byte
	Version   string
	Ready     func() bool
	Reload    ReloadFunc
	// PolicyInfo returns a JSON-serialisable, secret-free summary of the
	// live policy.
	PolicyInfo func() any
	Logger     *slog.Logger
}

// Server is the admin HTTP server.
type Server struct {
	opts Options
	mux  *http.ServeMux
	srv  *http.Server
}

// New builds the admin server.
func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Ready == nil {
		opts.Ready = func() bool { return true }
	}
	s := &Server{opts: opts, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /readyz", s.handleReady)
	s.mux.HandleFunc("GET /ca.crt", s.handleCACert)
	s.mux.HandleFunc("POST /-/reload", s.handleReload)
	s.mux.HandleFunc("GET /-/policy", s.handlePolicy)
	s.mux.Handle("GET /metrics", expvar.Handler())
	s.srv = &http.Server{
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Minute,
		ErrorLog:          slog.NewLogLogger(opts.Logger.Handler(), slog.LevelDebug),
	}
	return s
}

// Handler exposes the router (for tests and composition).
func (s *Server) Handler() http.Handler { return s.mux }

// ListenAndServe serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("admin listen %s: %w", addr, err)
	}
	s.opts.Logger.Info("admin listening", "addr", ln.Addr().String())
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
	err = s.srv.Serve(ln)
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": s.opts.Version})
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if !s.opts.Ready() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (s *Server) handleCACert(w http.ResponseWriter, _ *http.Request) {
	if len(s.opts.CACertPEM) == 0 {
		http.Error(w, "CA certificate not loaded", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="aigatekeeper-ca.crt"`)
	_, _ = w.Write(s.opts.CACertPEM)
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if s.opts.Reload == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]any{"error": "reload not available"})
		return
	}
	changed, version, err := s.opts.Reload(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"reloaded": false, "version": version, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reloaded": true, "changed": changed, "version": version})
}

func (s *Server) handlePolicy(w http.ResponseWriter, _ *http.Request) {
	if s.opts.PolicyInfo == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "policy summary not available"})
		return
	}
	writeJSON(w, http.StatusOK, s.opts.PolicyInfo())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
