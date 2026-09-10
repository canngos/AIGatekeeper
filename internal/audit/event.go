// Package audit defines the structured audit event emitted for every proxied
// transaction and the sinks that receive it.
package audit

import "time"

// Event kinds.
const (
	KindRequest      = "request"       // an inspected HTTP request
	KindTunnel       = "tunnel"        // an opaque CONNECT tunnel to a non-intercepted host
	KindPassthrough  = "passthrough"   // a plain-HTTP absolute-URI request to a non-intercepted host
	KindTLSError     = "tls_error"     // the client rejected or failed our interception handshake
	KindProxyStart   = "proxy_start"   // the proxy started listening
	KindConfigReload = "config_reload" // the policy was (re)loaded
	KindAuth         = "auth"          // a caller was challenged for proxy credentials
)

// Actions recorded on request events.
const (
	ActionAllow   = "allow"
	ActionBlock   = "block"
	ActionMonitor = "monitor"
)

// Event is one audit record. Prompt text is never included; findings carry
// only a masked preview of the matched value.
type Event struct {
	Time       time.Time `json:"ts"`
	Kind       string    `json:"kind"`
	RequestID  string    `json:"request_id,omitempty"`
	ClientIP   string    `json:"client_ip,omitempty"`
	User       string    `json:"user,omitempty"`
	Device     string    `json:"device,omitempty"`
	UserSource string    `json:"user_source,omitempty"`
	Listener   string    `json:"listener,omitempty"`
	Method     string    `json:"method,omitempty"`
	Host       string    `json:"host,omitempty"`
	Path       string    `json:"path,omitempty"`
	Service    string    `json:"service,omitempty"`
	Model      string    `json:"model,omitempty"`
	Stream     bool      `json:"stream,omitempty"`

	Action    string           `json:"action,omitempty"`
	BlockMode string           `json:"block_mode,omitempty"`
	Reason    string           `json:"reason,omitempty"`
	Rule      string           `json:"rule,omitempty"`
	Findings  []FindingSummary `json:"findings,omitempty"`

	// Prompt carries the extracted prompt text. It is populated only when
	// audit.capture_prompts is switched on, which is off by default: a DLP
	// proxy that records what everyone types is a bigger liability than the
	// leaks it prevents. Useful for a single-machine pilot.
	Prompt []PromptSegment `json:"prompt,omitempty"`

	BytesIn        int64  `json:"bytes_in,omitempty"`
	BytesOut       int64  `json:"bytes_out,omitempty"`
	Encoding       string `json:"encoding,omitempty"`
	UpstreamStatus int    `json:"upstream_status,omitempty"`
	LatencyMS      int64  `json:"latency_ms"`
	Error          string `json:"error,omitempty"`
	Message        string `json:"message,omitempty"`
}

// PromptSegment is one piece of extracted prompt text with its location.
type PromptSegment struct {
	Path string `json:"path"`
	Role string `json:"role,omitempty"`
	Text string `json:"text"`
}

// FindingSummary is the audit-safe projection of a DLP finding.
type FindingSummary struct {
	Detector   string  `json:"detector"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence,omitempty"`
	Segment    string  `json:"segment,omitempty"`
	Role       string  `json:"role,omitempty"`
	Preview    string  `json:"preview,omitempty"`
}
