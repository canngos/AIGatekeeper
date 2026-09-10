package admin

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

const notBuiltPage = `<!doctype html><meta charset="utf-8"><title>AIGatekeeper</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#1f2937}code{background:#f3f4f6;padding:.1rem .3rem;border-radius:.25rem}</style>
<h1>AIGatekeeper admin</h1>
<p>The proxy is running, but this binary was built without the web UI.</p>
<p>Build it with <code>cd web &amp;&amp; npm ci &amp;&amp; npm run build</code> (or <code>make build</code>) and rebuild the binary,
or use the JSON API under <code>/api/v1/</code>. Health: <a href="/healthz">/healthz</a> &middot; CA certificate: <a href="/ca.crt">/ca.crt</a>.</p>`

// handleUI serves the embedded single-page app with history-API fallback.
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.opts.UIBuilt || s.opts.UI == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(notBuiltPage))
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		name = "index.html"
	}
	if st, err := fs.Stat(s.opts.UI, name); err == nil && !st.IsDir() {
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
		http.ServeFileFS(w, r, s.opts.UI, name)
		return
	}
	// Client-side route: hand out the shell.
	w.Header().Set("Cache-Control", "no-store")
	r.URL.Path = "/"
	http.ServeFileFS(w, r, s.opts.UI, "index.html")
}
