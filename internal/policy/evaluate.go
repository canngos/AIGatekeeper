package policy

import (
	"context"
	"net"
	"strings"

	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/config"
	"github.com/canngos/aigatekeeper/internal/dlp"
	"github.com/canngos/aigatekeeper/internal/parser"
)

// Actions a decision can carry.
const (
	ActionAllow   = config.ActionAllow
	ActionBlock   = config.ActionBlock
	ActionMonitor = config.ActionMonitor
)

// Decision reasons.
const (
	ReasonNone        = ""
	ReasonDLP         = "dlp"
	ReasonMonitorMode = "monitor_mode"
	ReasonOversize    = "oversize"
	ReasonParseError  = "parse_error"
	ReasonClientCIDR  = "allowlist_client"
	ReasonHeader      = "allowlist_header"
	ReasonPassthrough = "passthrough_path"
)

// Input is what Evaluate needs to know about a request.
type Input struct {
	Service     *Service
	Passthrough bool
	ClientIP    net.IP
	BypassToken string // value of the configured bypass header, if present
	Oversize    bool
	ParseErr    error
	Extraction  *parser.Extraction
}

// Decision is the outcome of evaluating a request.
type Decision struct {
	Action    string
	Rule      string // rule that determined the action (highest severity)
	Reason    string
	BlockMode string
	Findings  []dlp.Finding
	Detectors []string // distinct detector ids across findings
}

// Summaries projects findings into the audit-safe form.
func (d Decision) Summaries() []audit.FindingSummary {
	if len(d.Findings) == 0 {
		return nil
	}
	out := make([]audit.FindingSummary, len(d.Findings))
	for i, f := range d.Findings {
		out[i] = audit.FindingSummary{
			Detector: f.Detector, Severity: f.Severity, Confidence: f.Confidence,
			Segment: f.Segment, Role: f.Role, Preview: f.Preview,
		}
	}
	return out
}

// Evaluate decides what to do with a request. It never returns an error
// for scanner failures: a scan error is treated as "no findings" so the
// proxy fails open only for that rule, and the error is returned for logging.
func (p *Policy) Evaluate(ctx context.Context, in Input) (Decision, error) {
	d := Decision{Action: ActionAllow}
	if in.Service == nil {
		return d, nil
	}
	d.BlockMode = in.Service.BlockMode
	if in.Passthrough {
		d.Reason = ReasonPassthrough
		return d, nil
	}
	if p.Allowlist.ClientBypasses(in.ClientIP) {
		d.Reason = ReasonClientCIDR
		return d, nil
	}
	if p.Allowlist.HeaderBypasses(in.BypassToken) {
		d.Reason = ReasonHeader
		return d, nil
	}
	if in.Oversize {
		d.Reason = ReasonOversize
		d.Action = p.enforce(p.OversizeAction)
		return d, nil
	}
	if in.ParseErr != nil {
		d.Reason = ReasonParseError
		d.Action = p.enforce(p.ParseErrAction)
		return d, nil
	}
	if in.Extraction == nil || len(in.Extraction.Segments) == 0 {
		return d, nil
	}

	var firstErr error
	bestRank := -1
	for _, rule := range in.Service.Rules {
		findings, err := rule.Scanner.Scan(ctx, in.Extraction)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if len(findings) == 0 {
			continue
		}
		d.Findings = append(d.Findings, findings...)
		action := rule.Action
		if action == "" {
			action = p.DefaultAction
		}
		rank := actionRank(action)*10 + dlp.SeverityRank(rule.Severity)
		if rank > bestRank {
			bestRank = rank
			d.Action = action
			d.Rule = rule.ID
		}
	}
	if len(d.Findings) == 0 {
		return d, firstErr
	}
	d.Reason = ReasonDLP
	d.Detectors = distinctDetectors(d.Findings)
	if d.Action == ActionBlock && p.Monitor {
		d.Action = ActionMonitor
		d.Reason = ReasonMonitorMode
	}
	return d, firstErr
}

// enforce applies global monitor mode to a configured action.
func (p *Policy) enforce(action string) string {
	if action == ActionBlock && p.Monitor {
		return ActionMonitor
	}
	if action == "" {
		return ActionAllow
	}
	return action
}

func actionRank(a string) int {
	switch a {
	case ActionBlock:
		return 2
	case ActionMonitor:
		return 1
	}
	return 0
}

func distinctDetectors(findings []dlp.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		id := strings.TrimPrefix(f.Detector, "keyword:")
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
