// Package admin serves the operational endpoints (health, CA download,
// reload, metrics), the JSON API behind the web UI, and the embedded UI.
//
// Access model: when an admin credential is configured every endpoint
// except /healthz, /readyz, /ca.crt and the login route requires it. When
// no credential is configured the operational endpoints stay open (the
// listener binds to loopback by default) and the /api/v1 routes answer 503
// so the UI can explain how to set one up.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/dlp"
	"github.com/canngos/aigatekeeper/internal/parser"
	"github.com/canngos/aigatekeeper/internal/reload"
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
	// live policy (served at /-/policy).
	PolicyInfo func() any

	Auth      AuthConfig
	Manager   *reload.Manager    // config read/validate/apply and policy access
	History   *audit.SQLiteStore // may be nil: history endpoints answer 503
	Events    *audit.Dispatcher  // may be nil: stream endpoint answers 503
	Detectors []dlp.Info
	Parsers   parser.Registry
	Listeners map[string]string // name -> address, for the status page
	UI        fs.FS
	UIBuilt   bool
	// CORSOrigins allows a Vite dev server to call the API with credentials.
	CORSOrigins []string
	// TLSCert and TLSKey serve the admin listener over HTTPS, which is
	// required when it is not bound to loopback.
	TLSCert string
	TLSKey  string
	Logger  *slog.Logger
}

// Server is the admin HTTP server.
type Server struct {
	opts    Options
	auth    *authenticator
	mux     *http.ServeMux
	srv     *http.Server
	started time.Time
}

// New builds the admin server.
func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Ready == nil {
		opts.Ready = func() bool { return true }
	}
	if opts.Parsers == nil {
		opts.Parsers = parser.Default()
	}
	if opts.Detectors == nil {
		opts.Detectors = dlp.Builtin()
	}
	s := &Server{opts: opts, auth: newAuthenticator(opts.Auth), mux: http.NewServeMux(), started: time.Now()}

	// Always open.
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /readyz", s.handleReady)
	s.mux.HandleFunc("GET /ca.crt", s.handleCACert)
	s.mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("GET /api/v1/auth/me", s.handleMe)

	// Operational endpoints: protected only when a credential exists. The
	// explicit /-/ guard keeps a wrong method or a typo from falling through
	// to the SPA fallback and answering with an HTML page.
	s.mux.Handle("POST /-/reload", s.protected(http.HandlerFunc(s.handleReload)))
	s.mux.Handle("GET /-/policy", s.protected(http.HandlerFunc(s.handlePolicy)))
	s.mux.Handle("GET /metrics", s.protected(expvar.Handler()))
	s.mux.HandleFunc("/-/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/reload":
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "use POST /-/reload"})
		case "/-/policy":
			w.Header().Set("Allow", http.MethodGet)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "use GET /-/policy"})
		default:
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "unknown endpoint"})
		}
	})

	// JSON API: requires a configured credential.
	api := func(pattern string, h http.HandlerFunc) {
		s.mux.Handle(pattern, s.protectedAPI(h))
	}
	api("POST /api/v1/auth/logout", s.handleLogout)
	api("GET /api/v1/status", s.handleStatus)
	api("GET /api/v1/detectors", s.handleDetectors)
	api("GET /api/v1/config", s.handleGetConfig)
	api("POST /api/v1/config/validate", s.handleValidateConfig)
	api("POST /api/v1/config/apply", s.handleApplyConfig)
	api("POST /api/v1/reload", s.handleReload)
	api("POST /api/v1/test", s.handleTest)
	api("GET /api/v1/events", s.handleEvents)
	api("GET /api/v1/events/stream", s.handleEventStream)
	api("GET /api/v1/events/{id}", s.handleEvent)
	api("GET /api/v1/stats/summary", s.handleStatsSummary)
	api("GET /api/v1/stats/timeseries", s.handleStatsTimeseries)
	s.mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "unknown API route"})
	})

	// Everything else is the SPA.
	s.mux.HandleFunc("/", s.handleUI)

	s.srv = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Minute,
		ErrorLog:          slog.NewLogLogger(opts.Logger.Handler(), slog.LevelDebug),
	}
	return s
}

// Handler exposes the full handler chain (security headers, CORS, router).
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		if s.cors(w, r) {
			return
		}
		s.mux.ServeHTTP(w, r)
	})
}

// cors handles the Vite dev-server case; returns true when the request was
// a preflight that has been answered.
func (s *Server) cors(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || len(s.opts.CORSOrigins) == 0 {
		return false
	}
	allowed := false
	for _, o := range s.opts.CORSOrigins {
		if strings.EqualFold(o, origin) {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, "+csrfHeader)
	h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	h.Set("Vary", "Origin")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

// protected requires auth only when a credential is configured.
func (s *Server) protected(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.opts.Auth.Configured() {
			next.ServeHTTP(w, r)
			return
		}
		if !s.authorize(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// protectedAPI always requires a configured credential.
func (s *Server) protectedAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.opts.Auth.Configured() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": "admin authentication is not configured",
				"hint":  "run `aigatekeeper admin hash-password` and set admin.auth.password_hash (or AIGK_ADMIN_TOKEN)",
			})
			return
		}
		if !s.authorize(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) bool {
	method, sess := s.auth.authenticate(r)
	switch method {
	case authToken:
		return true
	case authSession:
		if !csrfOK(r, sess) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "missing or invalid CSRF token"})
			return false
		}
		return true
	default:
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return false
	}
}

// ListenAndServe serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("admin listen %s: %w", addr, err)
	}
	if host, _, _ := net.SplitHostPort(addr); !isLoopbackHost(host) {
		if !s.opts.Auth.Configured() {
			s.opts.Logger.Warn("admin listener is reachable from the network without authentication; set admin.auth", "addr", addr)
		}
		if s.opts.TLSCert == "" {
			s.opts.Logger.Warn("admin listener is reachable from the network without TLS; set admin.tls_cert and admin.tls_key", "addr", addr)
		}
	}
	s.opts.Logger.Info("admin listening", "addr", ln.Addr().String(), "auth", s.opts.Auth.Configured(), "ui", s.opts.UIBuilt, "tls", s.opts.TLSCert != "")
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
	if s.opts.TLSCert != "" {
		err = s.srv.ServeTLS(ln, s.opts.TLSCert, s.opts.TLSKey)
	} else {
		err = s.srv.Serve(ln)
	}
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func isLoopbackHost(host string) bool {
	if host == "" {
		return false // an empty host means all interfaces
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body: " + err.Error()})
		return false
	}
	return true
}
