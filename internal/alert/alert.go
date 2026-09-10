// Package alert watches the audit stream for repeated policy violations by
// the same person and tells someone about them.
//
// The engine is deliberately conservative: it counts only what the policy
// already acted on, groups by the best identity available, and holds a
// cooldown per group so a bad afternoon produces one message rather than
// fifty. Nothing here ever carries the matched secret; findings travel as
// the same masked previews the audit log keeps.
package alert

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/dlp"
)

// Grouping keys.
const (
	GroupUser     = "user"
	GroupDevice   = "device"
	GroupClientIP = "client_ip"
)

// Rule decides when to raise an alert.
type Rule struct {
	ID    string
	Match Match
	// GroupBy is the preferred key; when the event has no value for it the
	// engine falls back to device, then client address, so an anonymous
	// deployment still groups sensibly.
	GroupBy   string
	Threshold int
	Window    time.Duration
	Cooldown  time.Duration
	Notify    []Target
	Template  string
}

// Match selects which events a rule counts.
type Match struct {
	Actions     []string // allow | monitor | block; empty means block and monitor
	MinSeverity string   // low | medium | high | critical
	Services    []string
	Rules       []string
	Detectors   []string
}

// Matches reports whether an event counts towards the rule.
func (m Match) Matches(e audit.Event) bool {
	if e.Kind != audit.KindRequest {
		return false
	}
	actions := m.Actions
	if len(actions) == 0 {
		actions = []string{audit.ActionBlock, audit.ActionMonitor}
	}
	if !contains(actions, e.Action) {
		return false
	}
	if len(m.Services) > 0 && !contains(m.Services, e.Service) {
		return false
	}
	if len(m.Rules) > 0 && !contains(m.Rules, e.Rule) {
		return false
	}
	if m.MinSeverity != "" || len(m.Detectors) > 0 {
		min := dlp.SeverityRank(m.MinSeverity)
		ok := false
		for _, f := range e.Findings {
			if min > 0 && dlp.SeverityRank(f.Severity) < min {
				continue
			}
			if len(m.Detectors) > 0 && !contains(m.Detectors, f.Detector) {
				continue
			}
			ok = true
			break
		}
		if !ok {
			return false
		}
	}
	return true
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// Target names who to tell.
type Target struct {
	Type      string   // email | webhook
	To        []string // explicit addresses
	ToManager bool     // look the person's manager up in the directory
	ToUser    bool     // tell the person themselves; off unless explicitly enabled
	Webhook   string   // webhook name
}

// Alert is a raised alert, stored and handed to notifiers.
type Alert struct {
	ID         int64     `json:"id"`
	Time       time.Time `json:"ts"`
	RuleID     string    `json:"rule_id"`
	GroupKey   string    `json:"group_key"`
	GroupBy    string    `json:"group_by"`
	User       string    `json:"user,omitempty"`
	Device     string    `json:"device,omitempty"`
	ClientIP   string    `json:"client_ip,omitempty"`
	Email      string    `json:"email,omitempty"`
	Manager    string    `json:"manager,omitempty"`
	Count      int       `json:"count"`
	Window     string    `json:"window"`
	Since      time.Time `json:"since"`
	Severity   string    `json:"severity"`
	Services   []string  `json:"services"`
	Detectors  []string  `json:"detectors"`
	Events     []Event   `json:"events"`
	Status     string    `json:"status"` // open | acknowledged
	AckBy      string    `json:"acknowledged_by,omitempty"`
	AckAt      time.Time `json:"acknowledged_at,omitempty"`
	Notified   []string  `json:"notified,omitempty"`
	NotifyErrs []string  `json:"notify_errors,omitempty"`
}

// Event is the audit-safe summary of one contributing request.
type Event struct {
	Time      time.Time `json:"ts"`
	RequestID string    `json:"request_id"`
	Service   string    `json:"service"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	Action    string    `json:"action"`
	Rule      string    `json:"rule"`
	Detectors []string  `json:"detectors"`
	Previews  []string  `json:"previews"`
}

// Subject renders a short human description used in messages.
func (a Alert) Subject() string {
	who := a.Who()
	return fmt.Sprintf("AIGatekeeper: %d blocked prompts from %s", a.Count, who)
}

// Who returns the best available name for the person or machine.
func (a Alert) Who() string {
	switch {
	case a.User != "":
		return a.User
	case a.Device != "":
		return a.Device
	default:
		return a.ClientIP
	}
}

// Notifier delivers an alert.
type Notifier interface {
	Name() string
	Send(ctx context.Context, a Alert, recipients []string) error
}

// summarise folds the contributing events into the alert's roll-up fields.
func summarise(a *Alert, events []Event) {
	services := map[string]bool{}
	detectors := map[string]bool{}
	for _, e := range events {
		if e.Service != "" {
			services[e.Service] = true
		}
		for _, d := range e.Detectors {
			detectors[d] = true
		}
	}
	a.Services = sortedKeys(services)
	a.Detectors = sortedKeys(detectors)
	a.Events = events
	a.Count = len(events)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// eventFrom projects an audit event into the alert-safe shape.
func eventFrom(e audit.Event) Event {
	out := Event{
		Time: e.Time, RequestID: e.RequestID, Service: e.Service, Host: e.Host, Path: e.Path,
		Action: e.Action, Rule: e.Rule,
	}
	seen := map[string]bool{}
	for _, f := range e.Findings {
		id := strings.TrimPrefix(f.Detector, "keyword:")
		if !seen[id] {
			seen[id] = true
			out.Detectors = append(out.Detectors, id)
		}
		if f.Preview != "" {
			out.Previews = append(out.Previews, f.Preview)
		}
	}
	return out
}

// highestSeverity returns the most severe finding across events.
func highestSeverity(events []audit.Event) string {
	best, rank := "", 0
	for _, e := range events {
		for _, f := range e.Findings {
			if r := dlp.SeverityRank(f.Severity); r > rank {
				best, rank = f.Severity, r
			}
		}
	}
	return best
}
