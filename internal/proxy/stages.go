package proxy

import (
	"net"
	"net/http"
	"strings"

	"github.com/canngos/aigatekeeper/internal/ca"
	"github.com/canngos/aigatekeeper/internal/parser"
	"github.com/canngos/aigatekeeper/internal/policy"
)

// Route resolves which configured service (if any) a request belongs to:
// by listener name for reverse listeners, by host for the forward proxy.
// Requests to passthrough paths are marked so later stages skip them.
func Route(store *policy.Store) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tx := TransactionFrom(r.Context())
			pol := store.Load()
			if tx != nil && pol != nil {
				if tx.Listener != ListenerForward {
					tx.Service = pol.ServiceForListener(tx.Listener)
				}
				if tx.Service == nil {
					host := r.URL.Hostname()
					if host == "" {
						host = hostOnly(r.Host)
					}
					tx.Service = pol.ServiceForHost(ca.NormalizeHost(host))
				}
				if tx.Service != nil && tx.Service.IsPassthroughPath(r.URL.Path) {
					tx.Passthrough = true
					tx.Reason = "passthrough_path"
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Parse extracts prompt text from decoded JSON bodies using the service's
// configured extractor, falling back to the generic walker.
func Parse(reg parser.Registry) Middleware {
	if reg == nil {
		reg = parser.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tx := TransactionFrom(r.Context())
			if tx == nil || tx.Service == nil || tx.Passthrough || tx.Body == nil || tx.ParseErr != nil {
				next.ServeHTTP(w, r)
				return
			}
			isJSON := parser.IsJSONContentType(r.Header.Get("Content-Type"))
			if !isJSON && !parser.LooksLikeJSON(tx.Body) {
				// Form posts, multipart uploads, protobuf: nothing to extract.
				next.ServeHTTP(w, r)
				return
			}
			ex, err := reg.Extract(tx.Service.Extractor, parser.Request{
				Method: r.Method,
				Path:   r.URL.Path,
				Query:  r.URL.RawQuery,
				Header: r.Header,
				Body:   tx.Body,
			})
			if err != nil {
				tx.ParseErr = err
			} else {
				tx.Extraction = ex
				tx.Model = ex.Model
				tx.Stream = ex.Stream
			}
			next.ServeHTTP(w, r)
		})
	}
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}
