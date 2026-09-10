package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Alert store schema, applied alongside the event schema.
const alertSchemaSQL = `
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  rule_id TEXT NOT NULL,
  group_key TEXT NOT NULL,
  group_by TEXT NOT NULL DEFAULT '',
  user TEXT NOT NULL DEFAULT '',
  device TEXT NOT NULL DEFAULT '',
  client_ip TEXT NOT NULL DEFAULT '',
  count INTEGER NOT NULL DEFAULT 0,
  window TEXT NOT NULL DEFAULT '',
  since INTEGER NOT NULL DEFAULT 0,
  severity TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',
  acknowledged_by TEXT NOT NULL DEFAULT '',
  acknowledged_at INTEGER NOT NULL DEFAULT 0,
  payload TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS alerts_status_ts ON alerts(status, ts);
CREATE INDEX IF NOT EXISTS alerts_rule_ts ON alerts(rule_id, ts);
CREATE INDEX IF NOT EXISTS alerts_group ON alerts(rule_id, group_key);
CREATE TABLE IF NOT EXISTS alert_state (
  rule_id TEXT NOT NULL,
  group_key TEXT NOT NULL,
  last_fired_ts INTEGER NOT NULL,
  PRIMARY KEY (rule_id, group_key)
);
`

// StoredAlert is one alert row. Payload carries the full alert document as
// written by the alert package, so the store does not need to know its shape.
type StoredAlert struct {
	ID             int64           `json:"id"`
	Time           time.Time       `json:"ts"`
	RuleID         string          `json:"rule_id"`
	GroupKey       string          `json:"group_key"`
	GroupBy        string          `json:"group_by"`
	User           string          `json:"user,omitempty"`
	Device         string          `json:"device,omitempty"`
	ClientIP       string          `json:"client_ip,omitempty"`
	Count          int             `json:"count"`
	Window         string          `json:"window"`
	Since          time.Time       `json:"since"`
	Severity       string          `json:"severity"`
	Status         string          `json:"status"`
	AcknowledgedBy string          `json:"acknowledged_by,omitempty"`
	AcknowledgedAt time.Time       `json:"acknowledged_at,omitempty"`
	Payload        json.RawMessage `json:"detail,omitempty"`
}

// AlertInput is what the alert engine hands the store.
type AlertInput struct {
	Time     time.Time
	RuleID   string
	GroupKey string
	GroupBy  string
	User     string
	Device   string
	ClientIP string
	Count    int
	Window   string
	Since    time.Time
	Severity string
	Payload  []byte
}

// InsertAlert records a raised alert and returns its id.
func (s *SQLiteStore) InsertAlert(ctx context.Context, in AlertInput) (int64, error) {
	if len(in.Payload) == 0 {
		in.Payload = []byte("{}")
	}
	res, err := s.writer.ExecContext(ctx,
		`INSERT INTO alerts (ts, rule_id, group_key, group_by, user, device, client_ip, count, window, since, severity, status, payload)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,'open',?)`,
		in.Time.UnixMilli(), in.RuleID, in.GroupKey, in.GroupBy, in.User, in.Device, in.ClientIP,
		in.Count, in.Window, in.Since.UnixMilli(), in.Severity, string(in.Payload))
	if err != nil {
		return 0, s.recordErr(err)
	}
	return res.LastInsertId()
}

// LastAlertFired returns when a rule last fired for a group, or the zero
// time when it never has.
func (s *SQLiteStore) LastAlertFired(ctx context.Context, ruleID, groupKey string) (time.Time, error) {
	var ms int64
	err := s.reader.QueryRowContext(ctx, "SELECT last_fired_ts FROM alert_state WHERE rule_id = ? AND group_key = ?", ruleID, groupKey).Scan(&ms)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(ms).UTC(), nil
}

// MarkAlertFired records the cooldown anchor for a rule and group.
func (s *SQLiteStore) MarkAlertFired(ctx context.Context, ruleID, groupKey string, at time.Time) error {
	_, err := s.writer.ExecContext(ctx,
		`INSERT INTO alert_state (rule_id, group_key, last_fired_ts) VALUES (?,?,?)
		 ON CONFLICT(rule_id, group_key) DO UPDATE SET last_fired_ts = excluded.last_fired_ts`,
		ruleID, groupKey, at.UnixMilli())
	if err != nil {
		return s.recordErr(err)
	}
	return nil
}

// AlertQuery filters the alert list.
type AlertQuery struct {
	Status string
	RuleID string
	User   string
	Cursor int64
	Limit  int
}

// AlertPage is one page of alerts.
type AlertPage struct {
	Items      []StoredAlert `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

const alertColumns = `id, ts, rule_id, group_key, group_by, user, device, client_ip, count, window, since, severity, status, acknowledged_by, acknowledged_at, payload`

func scanAlert(sc interface{ Scan(...any) error }) (StoredAlert, error) {
	var a StoredAlert
	var ts, since, ackAt int64
	var payload string
	err := sc.Scan(&a.ID, &ts, &a.RuleID, &a.GroupKey, &a.GroupBy, &a.User, &a.Device, &a.ClientIP,
		&a.Count, &a.Window, &since, &a.Severity, &a.Status, &a.AcknowledgedBy, &ackAt, &payload)
	if err != nil {
		return a, err
	}
	a.Time = time.UnixMilli(ts).UTC()
	a.Since = time.UnixMilli(since).UTC()
	if ackAt > 0 {
		a.AcknowledgedAt = time.UnixMilli(ackAt).UTC()
	}
	a.Payload = json.RawMessage(payload)
	return a, nil
}

// Alerts returns a page of alerts, newest first.
func (s *SQLiteStore) Alerts(ctx context.Context, q AlertQuery) (AlertPage, error) {
	if q.Limit <= 0 || q.Limit > 200 {
		q.Limit = 50
	}
	var where []string
	var args []any
	if q.Status != "" {
		where = append(where, "status = ?")
		args = append(args, q.Status)
	}
	if q.RuleID != "" {
		where = append(where, "rule_id = ?")
		args = append(args, q.RuleID)
	}
	if q.User != "" {
		where = append(where, "user = ?")
		args = append(args, q.User)
	}
	if q.Cursor > 0 {
		where = append(where, "id < ?")
		args = append(args, q.Cursor)
	}
	sqlStr := "SELECT " + alertColumns + " FROM alerts"
	if len(where) > 0 {
		sqlStr += " WHERE " + strings.Join(where, " AND ")
	}
	sqlStr += " ORDER BY id DESC LIMIT ?"
	args = append(args, q.Limit+1)

	rows, err := s.reader.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return AlertPage{}, err
	}
	defer rows.Close()
	var page AlertPage
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return AlertPage{}, err
		}
		page.Items = append(page.Items, a)
	}
	if err := rows.Err(); err != nil {
		return AlertPage{}, err
	}
	if len(page.Items) > q.Limit {
		page.Items = page.Items[:q.Limit]
		page.NextCursor = strconv.FormatInt(page.Items[len(page.Items)-1].ID, 10)
	}
	return page, nil
}

// AcknowledgeAlert marks an alert handled. It reports whether a row changed.
func (s *SQLiteStore) AcknowledgeAlert(ctx context.Context, id int64, by string) (bool, error) {
	res, err := s.writer.ExecContext(ctx,
		"UPDATE alerts SET status = 'acknowledged', acknowledged_by = ?, acknowledged_at = ? WHERE id = ? AND status <> 'acknowledged'",
		by, time.Now().UnixMilli(), id)
	if err != nil {
		return false, s.recordErr(err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// OpenAlerts counts alerts still waiting for someone to look at them.
func (s *SQLiteStore) OpenAlerts(ctx context.Context) (int64, error) {
	var n int64
	err := s.reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts WHERE status = 'open'").Scan(&n)
	return n, err
}

// UserSummary aggregates one person's or workstation's activity.
type UserSummary struct {
	User     string    `json:"user,omitempty"`
	Device   string    `json:"device,omitempty"`
	ClientIP string    `json:"client_ip,omitempty"`
	Requests int64     `json:"requests"`
	Blocked  int64     `json:"blocked"`
	Flagged  int64     `json:"flagged"`
	LastSeen time.Time `json:"last_seen"`
}

// Users lists the people or workstations with the most findings in a range.
func (s *SQLiteStore) Users(ctx context.Context, from, to time.Time, limit int) ([]UserSummary, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	// Group by whichever identity the events carry, preferring the user.
	rows, err := s.reader.QueryContext(ctx, `
		SELECT
		  CASE WHEN user <> '' THEN user ELSE '' END AS u,
		  CASE WHEN user <> '' THEN '' ELSE device END AS d,
		  CASE WHEN user <> '' OR device <> '' THEN '' ELSE client_ip END AS ip,
		  COUNT(*),
		  SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END),
		  SUM(CASE WHEN action = 'monitor' THEN 1 ELSE 0 END),
		  MAX(ts)
		FROM events
		WHERE kind = 'request' AND ts BETWEEN ? AND ?
		GROUP BY u, d, ip
		ORDER BY SUM(CASE WHEN action IN ('block','monitor') THEN 1 ELSE 0 END) DESC, COUNT(*) DESC
		LIMIT ?`, from.UnixMilli(), to.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserSummary
	for rows.Next() {
		var u UserSummary
		var last int64
		if err := rows.Scan(&u.User, &u.Device, &u.ClientIP, &u.Requests, &u.Blocked, &u.Flagged, &last); err != nil {
			return nil, err
		}
		u.LastSeen = time.UnixMilli(last).UTC()
		out = append(out, u)
	}
	return out, rows.Err()
}
