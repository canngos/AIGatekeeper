// Package metrics publishes operational counters through expvar, served by
// the admin listener at /metrics.
package metrics

import (
	"expvar"
	"time"

	"github.com/canngos/aigatekeeper/internal/audit"
)

var (
	// Events counts audit events by kind.
	Events = expvar.NewMap("aigk_events_total")
	// Requests counts inspected requests by action (allow, block, monitor).
	Requests = expvar.NewMap("aigk_requests_total")
	// RequestsByService counts inspected requests by service.
	RequestsByService = expvar.NewMap("aigk_requests_by_service_total")
	// Findings counts DLP findings by detector.
	Findings = expvar.NewMap("aigk_findings_total")
	// Blocks counts blocked requests by rule.
	Blocks = expvar.NewMap("aigk_blocks_by_rule_total")
	// TunnelBytes sums bytes relayed through opaque tunnels.
	TunnelBytes = expvar.NewInt("aigk_tunnel_bytes_total")
	// ConfigReloads counts successful and failed reloads.
	ConfigReloads = expvar.NewMap("aigk_config_reloads_total")

	start = time.Now()
)

func init() {
	expvar.Publish("aigk_uptime_seconds", expvar.Func(func() any { return int64(time.Since(start).Seconds()) }))
}

// Counting wraps an audit logger so every event updates the counters
// before being forwarded.
func Counting(next audit.Logger) audit.Logger {
	if next == nil {
		next = audit.Discard
	}
	return audit.LoggerFunc(func(e audit.Event) {
		Events.Add(e.Kind, 1)
		switch e.Kind {
		case audit.KindRequest:
			Requests.Add(e.Action, 1)
			if e.Service != "" {
				RequestsByService.Add(e.Service, 1)
			}
			for _, f := range e.Findings {
				Findings.Add(f.Detector, 1)
			}
			if e.Action == audit.ActionBlock && e.Rule != "" {
				Blocks.Add(e.Rule, 1)
			}
		case audit.KindTunnel:
			TunnelBytes.Add(e.BytesIn + e.BytesOut)
		case audit.KindConfigReload:
			if e.Error != "" {
				ConfigReloads.Add("failed", 1)
			} else {
				ConfigReloads.Add("ok", 1)
			}
		}
		next.Log(e)
	})
}
