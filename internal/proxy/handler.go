// Package proxy implements the forward proxy (CONNECT tunnelling and TLS
// interception), the reverse listeners, and the inspection middleware chain
// that later stages (body decoding, parsing, policy) plug into.
package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/parser"
	"github.com/canngos/aigatekeeper/internal/policy"
)

// ListenerForward is the listener name recorded for the forward proxy.
const ListenerForward = "forward"

// RequestIDHeader is echoed on every response the proxy produces or relays.
const RequestIDHeader = "X-AIGatekeeper-Request-Id"

// Transaction carries per-request state through the middleware chain.
type Transaction struct {
	ID         string
	Start      time.Time
	ClientAddr string
	Listener   string
	Method     string
	Host       string // authority (host or host:port) the client addressed
	Path       string

	// Populated by later stages.
	RawBody  []byte // bytes as received (possibly compressed); forwarded verbatim
	Body     []byte // decoded body for parsing; never logged
	Encoding string
	Oversize bool

	Service     *policy.Service
	Passthrough bool // service matched but the path is exempt from inspection
	Extraction  *parser.Extraction
	ParseErr    error
	Action      string
	BlockMode   string
	Reason      string
	Rule        string
	Findings    []audit.FindingSummary
	Model       string
	Stream      bool

	UpstreamStatus int
	BytesOut       int64
	Err            error
}

type txKey struct{}
type listenerKey struct{}

// WithTransaction stores tx in ctx.
func WithTransaction(ctx context.Context, tx *Transaction) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// TransactionFrom returns the Transaction stored in ctx, or nil.
func TransactionFrom(ctx context.Context) *Transaction {
	tx, _ := ctx.Value(txKey{}).(*Transaction)
	return tx
}

// WithListener records which listener accepted the connection.
func WithListener(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, listenerKey{}, name)
}

// ListenerFrom returns the listener name from ctx, defaulting to "forward".
func ListenerFrom(ctx context.Context) string {
	if name, ok := ctx.Value(listenerKey{}).(string); ok && name != "" {
		return name
	}
	return ListenerForward
}

// NewRequestID returns a random, URL-safe request identifier.
func NewRequestID() string {
	return rand.Text()
}

// Middleware wraps an http.Handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middlewares so that mws[0] is the outermost.
func Chain(final http.Handler, mws ...Middleware) http.Handler {
	h := final
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// Audited is the outermost middleware: it creates the Transaction, records
// the response status and size, and emits one audit event per request.
func Audited(logger audit.Logger, logAllowed bool) Middleware {
	if logger == nil {
		logger = audit.Discard
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tx := &Transaction{
				ID:         NewRequestID(),
				Start:      time.Now(),
				ClientAddr: r.RemoteAddr,
				Listener:   ListenerFrom(r.Context()),
				Method:     r.Method,
				Host:       r.URL.Host,
				Path:       r.URL.Path,
			}
			if tx.Host == "" {
				tx.Host = r.Host
			}
			w.Header().Set(RequestIDHeader, tx.ID)
			rec := &responseRecorder{ResponseWriter: w}
			ctx := WithTransaction(r.Context(), tx)
			next.ServeHTTP(rec, r.WithContext(ctx))

			if tx.UpstreamStatus == 0 {
				tx.UpstreamStatus = rec.status
			}
			tx.BytesOut = rec.bytes
			if tx.Action == "" {
				tx.Action = audit.ActionAllow
			}
			if tx.Action == audit.ActionAllow && !logAllowed {
				return
			}
			logger.Log(tx.Event())
		})
	}
}

// Event projects the transaction into an audit event.
func (tx *Transaction) Event() audit.Event {
	e := audit.Event{
		Time:           tx.Start,
		Kind:           audit.KindRequest,
		RequestID:      tx.ID,
		ClientIP:       clientIP(tx.ClientAddr),
		Listener:       tx.Listener,
		Method:         tx.Method,
		Host:           tx.Host,
		Path:           tx.Path,
		Model:          tx.Model,
		Stream:         tx.Stream,
		Action:         tx.Action,
		BlockMode:      tx.BlockMode,
		Reason:         tx.Reason,
		Rule:           tx.Rule,
		Findings:       tx.Findings,
		BytesIn:        int64(len(tx.RawBody)),
		BytesOut:       tx.BytesOut,
		Encoding:       tx.Encoding,
		UpstreamStatus: tx.UpstreamStatus,
		LatencyMS:      time.Since(tx.Start).Milliseconds(),
	}
	if tx.Service != nil {
		e.Service = tx.Service.Name
	}
	if tx.Err != nil {
		e.Error = tx.Err.Error()
	}
	return e
}

func clientIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// responseRecorder captures status and byte count while preserving
// streaming (Flush) and hijacking for the wrapped writer.
type responseRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (r *responseRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(p []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(p)
	r.bytes += int64(n)
	return n, err
}

func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("response writer does not support hijacking")
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *responseRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
