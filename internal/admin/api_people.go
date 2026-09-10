package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/canngos/aigatekeeper/internal/alert"
	"github.com/canngos/aigatekeeper/internal/audit"
)

// handleUsers lists the people or workstations with the most findings.
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	h := s.requireHistory(w)
	if h == nil {
		return
	}
	span, _ := rangeFrom(r.URL.Query().Get("range"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	now := time.Now()
	users, err := h.Users(r.Context(), now.Add(-span), now, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if users == nil {
		users = []audit.UserSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"users":      users,
		"from":       now.Add(-span).UTC(),
		"to":         now.UTC(),
		"attributed": s.opts.Identity != nil && s.opts.Identity["proxy_auth"] == true,
	})
}

// handleAlerts lists raised alerts.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	h := s.requireHistory(w)
	if h == nil {
		return
	}
	q := r.URL.Query()
	cursor, _ := strconv.ParseInt(q.Get("cursor"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	page, err := h.Alerts(r.Context(), audit.AlertQuery{
		Status: q.Get("status"), RuleID: q.Get("rule"), User: q.Get("user"), Cursor: cursor, Limit: limit,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if page.Items == nil {
		page.Items = []audit.StoredAlert{}
	}
	open, _ := h.OpenAlerts(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"items": page.Items, "next_cursor": page.NextCursor, "open": open, "rules": s.alertRuleIDs(),
	})
}

// handleAcknowledgeAlert marks an alert as handled.
func (s *Server) handleAcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	h := s.requireHistory(w)
	if h == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid id"})
		return
	}
	changed, err := h.AcknowledgeAlert(r.Context(), id, "admin")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if !changed {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no open alert with that id"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true, "id": id})
}

func (s *Server) alertRuleIDs() []string {
	out := []string{}
	if s.opts.Alerts == nil {
		return out
	}
	for _, r := range s.opts.Alerts.Rules() {
		out = append(out, r.ID)
	}
	return out
}

// handleTestAlert sends a sample alert through the configured notifiers so
// an operator can confirm the relay works before relying on it.
func (s *Server) handleTestAlert(w http.ResponseWriter, r *http.Request) {
	if s.opts.Alerts == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no alert rules are configured"})
		return
	}
	var req struct {
		Rule string   `json:"rule"`
		To   []string `json:"to"`
	}
	if !readJSON(w, r, &req, 64<<10) {
		return
	}
	rules := s.opts.Alerts.Rules()
	if len(rules) == 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no alert rules are configured"})
		return
	}
	rule := rules[0]
	if req.Rule != "" {
		found := false
		for _, candidate := range rules {
			if candidate.ID == req.Rule {
				rule, found = candidate, true
				break
			}
		}
		if !found {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown alert rule " + req.Rule})
			return
		}
	}
	sample := alert.Alert{
		Time: time.Now(), RuleID: rule.ID, GroupBy: "user", GroupKey: "sample.user", User: "sample.user",
		Device: "sample-workstation", ClientIP: "203.0.113.10", Count: rule.Threshold, Window: rule.Window.String(),
		Since: time.Now().Add(-rule.Window), Severity: "critical", Status: "open",
		Services: []string{"openai"}, Detectors: []string{"aws_access_key"},
		Events: []alert.Event{{
			Time: time.Now(), RequestID: "SAMPLE", Service: "openai", Host: "api.openai.com",
			Path: "/v1/chat/completions", Action: "block", Rule: "secrets",
			Detectors: []string{"aws_access_key"}, Previews: []string{"AKIA****EY"},
		}},
	}
	results := s.opts.Alerts.SendTest(r.Context(), rule, sample, req.To)
	status := http.StatusOK
	for _, res := range results {
		if res.Error != "" {
			status = http.StatusBadGateway
		}
	}
	writeJSON(w, status, map[string]any{"rule": rule.ID, "results": results})
}
