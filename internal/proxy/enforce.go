package proxy

import (
	"net"
	"net/http"

	"github.com/canngos/aigatekeeper/internal/action"
	"github.com/canngos/aigatekeeper/internal/policy"
)

// Enforce evaluates the policy for routed requests and either writes a block
// response or lets the request continue to the forwarder. It also strips
// the bypass header so the shared secret never reaches the upstream.
func Enforce(store *policy.Store) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tx := TransactionFrom(r.Context())
			pol := store.Load()
			if tx == nil || pol == nil || tx.Service == nil {
				next.ServeHTTP(w, r)
				return
			}

			in := policy.Input{
				Service:     tx.Service,
				Passthrough: tx.Passthrough,
				ClientIP:    net.ParseIP(clientIP(tx.ClientAddr)),
				Oversize:    tx.Oversize,
				ParseErr:    tx.ParseErr,
				Extraction:  tx.Extraction,
			}
			if name := pol.Allowlist.HeaderName; name != "" {
				in.BypassToken = r.Header.Get(name)
				r.Header.Del(name)
			}

			d, err := pol.Evaluate(r.Context(), in)
			if err != nil && tx.Err == nil {
				tx.Err = err
			}
			tx.Action = d.Action
			tx.Rule = d.Rule
			if d.Reason != "" {
				tx.Reason = d.Reason
			}
			tx.BlockMode = d.BlockMode
			tx.Findings = d.Summaries()

			if d.Action != policy.ActionBlock {
				next.ServeHTTP(w, r)
				return
			}

			req := action.Request{
				Extractor: tx.Service.Extractor,
				Path:      r.URL.Path,
				Query:     r.URL.RawQuery,
				Model:     tx.Model,
				Stream:    tx.Stream,
				RequestID: tx.ID,
				Rule:      d.Rule,
				Detectors: d.Detectors,
				BlockMode: d.BlockMode,
			}
			if req.Rule == "" {
				req.Rule = d.Reason
			}
			req.Message = action.RenderMessage(pol.BlockMessage, req)
			action.Respond(w, req)
		})
	}
}
