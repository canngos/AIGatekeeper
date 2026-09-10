package admin

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/config"
	"github.com/canngos/aigatekeeper/internal/dlp"
	"github.com/canngos/aigatekeeper/internal/parser"
	"github.com/canngos/aigatekeeper/internal/policy"
	"github.com/canngos/aigatekeeper/internal/reload"
)

// ---- auth ----

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.opts.Auth.Configured() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "admin authentication is not configured"})
		return
	}
	if !s.auth.allowAttempt(clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many login attempts; try again later"})
		return
	}
	var body struct {
		Password string `json:"password"`
		Token    string `json:"token"`
	}
	if !readJSON(w, r, &body, 64<<10) {
		return
	}
	if !s.auth.checkPassword(body.Password) && !s.auth.checkToken(body.Token) {
		time.Sleep(250 * time.Millisecond) // blunt online guessing a little more
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	id, csrf, expires := s.auth.createSession()
	secure := secureCookies(r)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, Expires: expires})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: csrf, Path: "/", HttpOnly: false, Secure: secure, SameSite: http.SameSiteStrictMode, Expires: expires})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "csrf_token": csrf, "expires_at": expires.UTC()})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.auth.deleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	method, sess := s.auth.authenticate(r)
	out := map[string]any{
		"authenticated":   method != authNone,
		"method":          string(method),
		"auth_configured": s.opts.Auth.Configured(),
		"ui_built":        s.opts.UIBuilt,
		"version":         s.opts.Version,
	}
	if sess != nil {
		out["expires_at"] = sess.expires.UTC()
		out["csrf_token"] = sess.csrf
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- status & detectors ----

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{
		"version":        s.opts.Version,
		"uptime_seconds": int64(time.Since(s.started).Seconds()),
		"listeners":      s.opts.Listeners,
		"ui_built":       s.opts.UIBuilt,
		"history":        s.opts.History != nil,
	}
	if m := s.opts.Manager; m != nil {
		reloads, failures, lastErr := m.Stats()
		out["reload"] = map[string]any{"reloads": reloads, "failures": failures, "last_error": lastErr, "path": m.Path()}
		if l := m.Current(); l != nil {
			out["policy"] = map[string]any{
				"version": l.Hash, "loaded_at": l.LoadedAt.UTC(), "source": l.Source, "monitor": l.Policy.Monitor,
				"services": len(l.Policy.Services), "rules": len(l.Policy.Rules), "tunnel_unmatched": l.Policy.TunnelUnmatched,
			}
		}
	}
	if d := s.opts.Events; d != nil {
		out["audit_sinks"] = d.Stats()
	}
	if h := s.opts.History; h != nil {
		written, errs, lastErr := h.Stats()
		out["history_store"] = map[string]any{"written": written, "errors": errs, "last_error": lastErr}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDetectors(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"detectors": s.opts.Detectors, "extractors": s.opts.Parsers.Names()})
}

// ---- configuration ----

func (s *Server) requireManager(w http.ResponseWriter) *reload.Manager {
	if s.opts.Manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "configuration management not available"})
		return nil
	}
	return s.opts.Manager
}

func (s *Server) handleGetConfig(w http.ResponseWriter, _ *http.Request) {
	m := s.requireManager(w)
	if m == nil {
		return
	}
	l := m.Current()
	if l == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no configuration loaded"})
		return
	}
	doc, err := configToDoc(l.Config)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"yaml":      string(l.Raw),
		"config":    doc,
		"version":   l.Hash,
		"loaded_at": l.LoadedAt.UTC(),
		"source":    l.Source,
		"path":      m.Path(),
	})
}

type configRequest struct {
	YAML        string         `json:"yaml"`
	Config      map[string]any `json:"config"`
	BaseVersion string         `json:"base_version"`
}

// rawFrom returns the YAML to validate or apply. Raw text is used as typed.
// A form document is normalised through the schema first: marshalling the
// generic map directly would sort keys alphabetically and spell out every
// empty default, which makes the file operators read and diff much worse.
func (req configRequest) rawFrom() ([]byte, error) {
	if req.YAML != "" {
		return []byte(req.YAML), nil
	}
	if req.Config == nil {
		return nil, errors.New("provide either yaml or config")
	}
	intermediate, err := yaml.Marshal(req.Config)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Parse(intermediate)
	if err != nil {
		return nil, err // may be a *config.ValidationError; handlers report its problems
	}
	return config.Marshal(cfg)
}

func (s *Server) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	m := s.requireManager(w)
	if m == nil {
		return
	}
	var req configRequest
	if !readJSON(w, r, &req, 4<<20) {
		return
	}
	raw, err := req.rawFrom()
	if err != nil {
		if isValidationError(err) {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "errors": problems(err), "yaml": ""})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	l, err := m.Compile(raw)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "errors": problems(err), "yaml": string(raw)})
		return
	}
	doc, _ := configToDoc(l.Config)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "errors": []any{}, "yaml": string(raw), "config": doc, "version": l.Hash})
}

func (s *Server) handleApplyConfig(w http.ResponseWriter, r *http.Request) {
	m := s.requireManager(w)
	if m == nil {
		return
	}
	var req configRequest
	if !readJSON(w, r, &req, 4<<20) {
		return
	}
	raw, err := req.rawFrom()
	if err != nil {
		if isValidationError(err) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "configuration is invalid", "errors": problems(err)})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	l, err := m.Apply(r.Context(), raw, req.BaseVersion, "admin")
	switch {
	case errors.Is(err, reload.ErrStale):
		current := ""
		if l != nil {
			current = l.Hash
		}
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "version": current})
	case err != nil:
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "configuration is invalid", "errors": problems(err)})
	default:
		s.opts.Logger.Info("configuration applied from admin API", "version", l.Hash[:12])
		writeJSON(w, http.StatusOK, map[string]any{"applied": true, "version": l.Hash, "loaded_at": l.LoadedAt.UTC()})
	}
}

// problems flattens validation errors into {path, message} items.
func problems(err error) []config.Problem {
	var ve *config.ValidationError
	if errors.As(err, &ve) {
		return ve.Problems
	}
	return []config.Problem{{Path: "", Message: err.Error()}}
}

func isValidationError(err error) bool {
	var ve *config.ValidationError
	return errors.As(err, &ve)
}

// configToDoc renders the effective configuration (defaults applied) as a
// generic document with the YAML key names, for the form editor.
func configToDoc(cfg *config.Config) (map[string]any, error) {
	raw, err := config.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// ---- rule tester ----

type testRequest struct {
	Text    string `json:"text"`
	Body    string `json:"body"`
	Service string `json:"service"`
	Path    string `json:"path"`
	YAML    string `json:"yaml"` // optional candidate configuration
}

func (s *Server) handleTest(w http.ResponseWriter, r *http.Request) {
	m := s.requireManager(w)
	if m == nil {
		return
	}
	var req testRequest
	if !readJSON(w, r, &req, 8<<20) {
		return
	}
	var pol *policy.Policy
	if req.YAML != "" {
		l, err := m.Compile([]byte(req.YAML))
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "candidate configuration is invalid", "errors": problems(err)})
			return
		}
		pol = l.Policy
	} else if l := m.Current(); l != nil {
		pol = l.Policy
	}
	if pol == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no policy loaded"})
		return
	}

	var svc *policy.Service
	if req.Service != "" {
		svc = pol.ServiceByName(req.Service)
		if svc == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("unknown service %q", req.Service)})
			return
		}
	}

	var ex *parser.Extraction
	switch {
	case req.Body != "":
		extractor := "generic"
		if svc != nil {
			extractor = svc.Extractor
		}
		path := req.Path
		if path == "" {
			path = defaultPathFor(extractor)
		}
		var err error
		ex, err = s.opts.Parsers.Extract(extractor, parser.Request{Method: http.MethodPost, Path: path, Body: []byte(req.Body)})
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "body could not be parsed: " + err.Error()})
			return
		}
	case req.Text != "":
		ex = &parser.Extraction{Extractor: "text", Segments: []parser.Segment{{Path: "/text", Role: parser.RoleUser, Text: req.Text}}}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "provide text or body"})
		return
	}

	if svc == nil {
		// No service chosen: evaluate against every rule in the policy.
		svc = &policy.Service{Name: "*", Extractor: "generic", BlockMode: config.BlockModeReject}
		for _, rule := range pol.Rules {
			svc.Rules = append(svc.Rules, rule)
		}
	}
	d, err := pol.Evaluate(r.Context(), policy.Input{Service: svc, Extraction: ex})
	out := map[string]any{
		"extraction": ex,
		"findings":   emptyIfNil(d.Findings),
		"decision": map[string]any{
			"action": d.Action, "rule": d.Rule, "reason": d.Reason, "block_mode": d.BlockMode, "detectors": emptyIfNilStrings(d.Detectors),
		},
		"service": svc.Name,
	}
	if err != nil {
		out["warning"] = err.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

func defaultPathFor(extractor string) string {
	switch extractor {
	case "anthropic":
		return "/v1/messages"
	case "gemini":
		return "/v1beta/models/gemini-2.5-pro:generateContent"
	case "ollama":
		return "/api/chat"
	case "copilot":
		return "/chat/completions"
	default:
		return "/v1/chat/completions"
	}
}

func emptyIfNil(f []dlp.Finding) []dlp.Finding {
	if f == nil {
		return []dlp.Finding{}
	}
	return f
}

func emptyIfNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ---- events & stats ----

func (s *Server) requireHistory(w http.ResponseWriter) *audit.SQLiteStore {
	if s.opts.History == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "audit history store is disabled (audit.sqlite.enabled: false)"})
		return nil
	}
	return s.opts.History
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.UnixMilli(ms), nil
	}
	return time.Time{}, fmt.Errorf("invalid time %q (use RFC3339 or unix milliseconds)", s)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	h := s.requireHistory(w)
	if h == nil {
		return
	}
	q := r.URL.Query()
	from, err := parseTime(q.Get("from"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	to, err := parseTime(q.Get("to"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	cursor, _ := strconv.ParseInt(q.Get("cursor"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	page, err := h.Query(r.Context(), audit.Query{
		From: from, To: to, Kind: q.Get("kind"), Service: q.Get("service"), Action: q.Get("action"), Rule: q.Get("rule"),
		Client: q.Get("client"), Host: q.Get("host"), User: q.Get("user"), Detector: q.Get("detector"), Text: q.Get("q"),
		Cursor: cursor, Limit: limit,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if page.Items == nil {
		page.Items = []audit.StoredEvent{}
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request) {
	h := s.requireHistory(w)
	if h == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid id"})
		return
	}
	e, err := h.Get(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if e == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "event not found"})
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	if s.opts.Events == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "live events not available"})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "streaming unsupported"})
		return
	}
	q := r.URL.Query()
	filterService, filterAction, filterKind := q.Get("service"), q.Get("action"), q.Get("kind")

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	sub := s.opts.Events.Subscribe(256)
	defer sub.Close()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	var reported int64
	// reportDrops tells the viewer their feed skipped events, so a quiet
	// stream is never mistaken for a complete one.
	reportDrops := func() {
		if dropped := sub.Dropped(); dropped > reported {
			fmt.Fprintf(w, "event: dropped\ndata: {\"dropped\":%d}\n\n", dropped-reported)
			reported = dropped
		}
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			reportDrops()
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case e, ok := <-sub.C:
			if !ok {
				return
			}
			if (filterService != "" && e.Service != filterService) || (filterAction != "" && e.Action != filterAction) || (filterKind != "" && e.Kind != filterKind) {
				continue
			}
			b, err := jsonMarshal(e)
			if err != nil {
				continue
			}
			reportDrops()
			fmt.Fprintf(w, "event: audit\ndata: %s\n\n", b)
			flusher.Flush()
		}
	}
}

func rangeFrom(q string) (time.Duration, time.Duration) {
	switch q {
	case "1h":
		return time.Hour, time.Minute
	case "7d":
		return 7 * 24 * time.Hour, 6 * time.Hour
	case "30d":
		return 30 * 24 * time.Hour, 24 * time.Hour
	default:
		return 24 * time.Hour, time.Hour
	}
}

func (s *Server) handleStatsSummary(w http.ResponseWriter, r *http.Request) {
	h := s.requireHistory(w)
	if h == nil {
		return
	}
	span, _ := rangeFrom(r.URL.Query().Get("range"))
	now := time.Now()
	sum, err := h.Summary(r.Context(), now.Add(-span), now)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

func (s *Server) handleStatsTimeseries(w http.ResponseWriter, r *http.Request) {
	h := s.requireHistory(w)
	if h == nil {
		return
	}
	q := r.URL.Query()
	span, bucket := rangeFrom(q.Get("range"))
	if b := q.Get("bucket"); b != "" {
		d, err := config.ParseDuration(b)
		if err != nil || d <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid bucket"})
			return
		}
		bucket = d
	}
	now := time.Now()
	from := now.Add(-span).Truncate(bucket)
	series, err := h.Timeseries(r.Context(), from, now, bucket, q.Get("group"))
	if err != nil {
		if strings.Contains(err.Error(), "invalid group") {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if series == nil {
		series = []audit.Bucket{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"from": from.UTC(), "to": now.UTC(), "bucket": bucket.String(), "series": series})
}
