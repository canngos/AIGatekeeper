package alert

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/identity"
)

// Store persists alerts and the cooldown state that stops a repeat.
type Store interface {
	Insert(ctx context.Context, a *Alert) error
	LastFired(ctx context.Context, ruleID, groupKey string) (time.Time, error)
	MarkFired(ctx context.Context, ruleID, groupKey string, at time.Time) error
}

// Engine counts matching events per group and raises alerts.
type Engine struct {
	rules     []Rule
	store     Store
	directory identity.Directory
	notifiers map[string]Notifier
	logger    *slog.Logger
	now       func() time.Time

	mu      sync.Mutex
	windows map[string][]audit.Event // ruleID\x00groupKey -> recent matching events

	raised  int
	skipped int
}

// Options configure the engine.
type Options struct {
	Rules     []Rule
	Store     Store
	Directory identity.Directory
	Notifiers map[string]Notifier
	Logger    *slog.Logger
}

// New builds an engine.
func New(opts Options) *Engine {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Notifiers == nil {
		opts.Notifiers = map[string]Notifier{}
	}
	return &Engine{
		rules: opts.Rules, store: opts.Store, directory: opts.Directory, notifiers: opts.Notifiers,
		logger: opts.Logger, now: time.Now, windows: map[string][]audit.Event{},
	}
}

// Rules returns the configured rules.
func (e *Engine) Rules() []Rule { return e.rules }

// Stats reports how many alerts were raised and suppressed.
func (e *Engine) Stats() (raised, suppressed int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.raised, e.skipped
}

// Write implements audit.Sink so the engine can be attached to the
// dispatcher like any other destination.
func (e *Engine) Write(ev audit.Event) {
	if err := e.Observe(context.Background(), ev); err != nil {
		e.logger.Warn("alert engine", "error", err)
	}
}

// Close implements audit.Sink.
func (e *Engine) Close() error { return nil }

// Name identifies the sink.
func (e *Engine) Name() string { return "alerts" }

// Observe feeds one audit event through the rules.
func (e *Engine) Observe(ctx context.Context, ev audit.Event) error {
	for _, rule := range e.rules {
		if !rule.Match.Matches(ev) {
			continue
		}
		groupBy, key := groupFor(rule.GroupBy, ev)
		if key == "" {
			continue // nothing to attribute this to
		}
		events, reached := e.record(rule, key, ev)
		if !reached {
			continue
		}
		if err := e.raise(ctx, rule, groupBy, key, events); err != nil {
			return err
		}
	}
	return nil
}

// record appends the event to the rule's sliding window and reports
// whether the threshold is now met.
func (e *Engine) record(rule Rule, key string, ev audit.Event) ([]audit.Event, bool) {
	window := rule.Window
	if window <= 0 {
		window = 24 * time.Hour
	}
	cutoff := e.now().Add(-window)
	id := rule.ID + "\x00" + key

	e.mu.Lock()
	defer e.mu.Unlock()
	kept := e.windows[id][:0]
	for _, old := range e.windows[id] {
		if old.Time.After(cutoff) {
			kept = append(kept, old)
		}
	}
	kept = append(kept, ev)
	e.windows[id] = kept

	threshold := rule.Threshold
	if threshold <= 0 {
		threshold = 1
	}
	if len(kept) < threshold {
		return nil, false
	}
	out := make([]audit.Event, len(kept))
	copy(out, kept)
	return out, true
}

// raise stores an alert and notifies, unless the group is in cooldown.
func (e *Engine) raise(ctx context.Context, rule Rule, groupBy, key string, events []audit.Event) error {
	now := e.now()
	cooldown := rule.Cooldown
	if cooldown <= 0 {
		cooldown = 24 * time.Hour
	}
	if e.store != nil {
		last, err := e.store.LastFired(ctx, rule.ID, key)
		if err != nil {
			return err
		}
		if !last.IsZero() && now.Sub(last) < cooldown {
			e.mu.Lock()
			e.skipped++
			e.mu.Unlock()
			return nil
		}
	}

	newest := events[len(events)-1]
	a := &Alert{
		Time: now, RuleID: rule.ID, GroupKey: key, GroupBy: groupBy,
		User: newest.User, Device: newest.Device, ClientIP: newest.ClientIP,
		Window: rule.Window.String(), Since: events[0].Time,
		Severity: highestSeverity(events), Status: "open",
	}
	projected := make([]Event, 0, len(events))
	for _, ev := range events {
		projected = append(projected, eventFrom(ev))
	}
	summarise(a, projected)

	if e.directory != nil && a.User != "" {
		if email, manager, err := e.directory.Lookup(ctx, a.User); err == nil {
			a.Email, a.Manager = email, manager
		} else {
			e.logger.Debug("no directory entry for user", "user", a.User, "error", err)
		}
	}

	e.notify(ctx, rule, a)

	if e.store != nil {
		if err := e.store.Insert(ctx, a); err != nil {
			return err
		}
		if err := e.store.MarkFired(ctx, rule.ID, key, now); err != nil {
			return err
		}
	}
	e.mu.Lock()
	e.raised++
	// The window is cleared so the next alert needs a fresh run of
	// violations rather than re-firing on the same ones after cooldown.
	delete(e.windows, rule.ID+"\x00"+key)
	e.mu.Unlock()

	e.logger.Warn("policy violations repeated by one source",
		"rule", rule.ID, "group", key, "count", a.Count, "severity", a.Severity, "notified", a.Notified)
	return nil
}

// TestResult reports what one notifier did with a test alert.
type TestResult struct {
	Notifier   string   `json:"notifier"`
	Recipients []string `json:"recipients,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// SendTest delivers a sample alert through a rule's notifiers, so an
// operator can confirm the relay works before relying on it. Overriding
// the recipients keeps a test out of a real distribution list.
func (e *Engine) SendTest(ctx context.Context, rule Rule, sample Alert, overrideTo []string) []TestResult {
	results := make([]TestResult, 0, len(rule.Notify))
	for _, target := range rule.Notify {
		n, ok := e.notifiers[target.Type]
		if target.Type == "webhook" && target.Webhook != "" {
			n, ok = e.notifiers["webhook:"+target.Webhook]
		}
		if !ok || n == nil {
			results = append(results, TestResult{Notifier: target.Type, Error: "no such notifier is configured"})
			continue
		}
		recipients := recipientsFor(target, &sample)
		if len(overrideTo) > 0 && target.Type == "email" {
			recipients = overrideTo
		}
		res := TestResult{Notifier: n.Name(), Recipients: recipients}
		if target.Type == "email" && len(recipients) == 0 {
			res.Error = "no recipient resolved for this target"
		} else if err := n.Send(ctx, sample, recipients); err != nil {
			res.Error = err.Error()
		}
		results = append(results, res)
	}
	return results
}

// notify delivers to every target, recording what succeeded and what did
// not. A failing notifier never stops the alert being recorded.
func (e *Engine) notify(ctx context.Context, rule Rule, a *Alert) {
	for _, target := range rule.Notify {
		n, ok := e.notifiers[target.Type]
		if target.Type == "webhook" && target.Webhook != "" {
			n, ok = e.notifiers["webhook:"+target.Webhook]
		}
		if !ok || n == nil {
			a.NotifyErrs = append(a.NotifyErrs, target.Type+": no such notifier is configured")
			continue
		}
		recipients := recipientsFor(target, a)
		if target.Type == "email" && len(recipients) == 0 {
			continue // nothing to send to; not an error
		}
		if err := n.Send(ctx, *a, recipients); err != nil {
			a.NotifyErrs = append(a.NotifyErrs, n.Name()+": "+err.Error())
			e.logger.Error("alert notification failed", "notifier", n.Name(), "rule", rule.ID, "error", err)
			continue
		}
		a.Notified = append(a.Notified, n.Name())
	}
}

func recipientsFor(t Target, a *Alert) []string {
	if t.Type != "email" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(addr string) {
		addr = trimAddress(addr)
		if addr != "" && !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	for _, addr := range t.To {
		add(addr)
	}
	if t.ToManager {
		add(a.Manager)
	}
	if t.ToUser {
		add(a.Email)
	}
	return out
}

func trimAddress(s string) string {
	s = trimSpace(s)
	// An LDAP manager attribute is a DN; only a mail address is usable.
	if s == "" || !containsRune(s, '@') {
		return ""
	}
	return s
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func containsRune(s string, r byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == r {
			return true
		}
	}
	return false
}

// groupFor picks the grouping key, falling back through the identity
// chain so a deployment without proxy authentication still groups by
// workstation rather than lumping everyone together.
func groupFor(preferred string, ev audit.Event) (string, string) {
	order := []string{preferred, GroupUser, GroupDevice, GroupClientIP}
	for _, key := range order {
		switch key {
		case GroupUser:
			if ev.User != "" {
				return GroupUser, ev.User
			}
		case GroupDevice:
			if ev.Device != "" {
				return GroupDevice, ev.Device
			}
		case GroupClientIP:
			if ev.ClientIP != "" {
				return GroupClientIP, ev.ClientIP
			}
		}
	}
	return "", ""
}
