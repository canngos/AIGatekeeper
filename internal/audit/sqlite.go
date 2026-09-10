package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// SQLiteOptions tune the history store.
type SQLiteOptions struct {
	BatchSize     int           // rows per insert transaction (default 256)
	FlushInterval time.Duration // max time a row waits in the batch (default 200ms)
	MaxAge        time.Duration // delete events older than this (0 = keep)
	MaxRows       int64         // keep at most this many events (0 = unlimited)
	SweepInterval time.Duration // retention sweep cadence (default 1h)
}

// SQLiteStore persists audit events for the admin UI and serves queries.
// It implements Sink; the dispatcher calls Write from one goroutine.
type SQLiteStore struct {
	writer *sql.DB
	reader *sql.DB
	opts   SQLiteOptions

	mu      sync.Mutex
	batch   []Event
	flushC  chan struct{}
	stop    chan struct{}
	done    chan struct{}
	written int64
	errs    int64
	lastErr string
}

const schemaVersion = 1

const schemaSQL = `
CREATE TABLE IF NOT EXISTS schema_version (v INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  request_id TEXT NOT NULL DEFAULT '',
  client_ip TEXT NOT NULL DEFAULT '',
  user TEXT NOT NULL DEFAULT '',
  device TEXT NOT NULL DEFAULT '',
  user_source TEXT NOT NULL DEFAULT '',
  listener TEXT NOT NULL DEFAULT '',
  method TEXT NOT NULL DEFAULT '',
  host TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  service TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  stream INTEGER NOT NULL DEFAULT 0,
  action TEXT NOT NULL DEFAULT '',
  block_mode TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  rule TEXT NOT NULL DEFAULT '',
  bytes_in INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  encoding TEXT NOT NULL DEFAULT '',
  upstream_status INTEGER NOT NULL DEFAULT 0,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL DEFAULT '',
  findings_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_kind_ts ON events(kind, ts);
CREATE INDEX IF NOT EXISTS events_service_ts ON events(service, ts);
CREATE INDEX IF NOT EXISTS events_action_ts ON events(action, ts);
CREATE INDEX IF NOT EXISTS events_rule_ts ON events(rule, ts);
CREATE INDEX IF NOT EXISTS events_client_ts ON events(client_ip, ts);
CREATE INDEX IF NOT EXISTS events_user_ts ON events(user, ts);
CREATE INDEX IF NOT EXISTS events_request_id ON events(request_id);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  detector TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT '',
  confidence REAL NOT NULL DEFAULT 0,
  segment TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT '',
  preview TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS findings_event ON findings(event_id);
CREATE INDEX IF NOT EXISTS findings_detector ON findings(detector);
`

// OpenSQLite opens (creating if needed) the history database at path.
func OpenSQLite(path string, opts SQLiteOptions) (*SQLiteStore, error) {
	if opts.BatchSize <= 0 {
		opts.BatchSize = 256
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 200 * time.Millisecond
	}
	if opts.SweepInterval <= 0 {
		opts.SweepInterval = time.Hour
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create audit db directory: %w", err)
		}
	}
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"
	writer, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}
	writer.SetMaxOpenConns(1)
	reader, err := sql.Open("sqlite", dsn)
	if err != nil {
		writer.Close()
		return nil, fmt.Errorf("open audit db (reader): %w", err)
	}
	reader.SetMaxOpenConns(4)

	if _, err := writer.Exec(schemaSQL); err != nil {
		writer.Close()
		reader.Close()
		return nil, fmt.Errorf("init audit schema: %w", err)
	}
	var v sql.NullInt64
	_ = writer.QueryRow("SELECT v FROM schema_version LIMIT 1").Scan(&v)
	if !v.Valid {
		_, _ = writer.Exec("INSERT INTO schema_version (v) VALUES (?)", schemaVersion)
	}

	s := &SQLiteStore{
		writer: writer, reader: reader, opts: opts,
		flushC: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
	}
	go s.loop()
	return s, nil
}

// Write implements Sink.
func (s *SQLiteStore) Write(e Event) {
	s.mu.Lock()
	s.batch = append(s.batch, e)
	full := len(s.batch) >= s.opts.BatchSize
	s.mu.Unlock()
	if full {
		select {
		case s.flushC <- struct{}{}:
		default:
		}
	}
}

// Flush writes any buffered events synchronously (tests, shutdown).
func (s *SQLiteStore) Flush() error {
	s.mu.Lock()
	batch := s.batch
	s.batch = nil
	s.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	return s.insert(batch)
}

// Close flushes and closes the database.
func (s *SQLiteStore) Close() error {
	select {
	case <-s.stop:
	default:
		close(s.stop)
		<-s.done
	}
	err := s.Flush()
	_ = s.reader.Close()
	if werr := s.writer.Close(); err == nil {
		err = werr
	}
	return err
}

// Stats reports write counters.
func (s *SQLiteStore) Stats() (written, errs int64, lastErr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.written, s.errs, s.lastErr
}

func (s *SQLiteStore) loop() {
	defer close(s.done)
	flush := time.NewTicker(s.opts.FlushInterval)
	defer flush.Stop()
	sweep := time.NewTicker(s.opts.SweepInterval)
	defer sweep.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-s.flushC:
			_ = s.Flush()
		case <-flush.C:
			_ = s.Flush()
		case <-sweep.C:
			_ = s.Sweep(context.Background())
		}
	}
}

func (s *SQLiteStore) insert(batch []Event) error {
	tx, err := s.writer.Begin()
	if err != nil {
		return s.recordErr(err)
	}
	evStmt, err := tx.Prepare(`INSERT INTO events (ts, kind, request_id, client_ip, user, device, user_source, listener, method, host, path,
		service, model, stream, action, block_mode, reason, rule, bytes_in, bytes_out, encoding, upstream_status, latency_ms, error, message, findings_count)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return s.recordErr(err)
	}
	defer evStmt.Close()
	fStmt, err := tx.Prepare(`INSERT INTO findings (event_id, detector, severity, confidence, segment, role, preview) VALUES (?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return s.recordErr(err)
	}
	defer fStmt.Close()

	for _, e := range batch {
		res, err := evStmt.Exec(e.Time.UnixMilli(), e.Kind, e.RequestID, e.ClientIP, e.User, e.Device, e.UserSource, e.Listener, e.Method, e.Host, e.Path,
			e.Service, e.Model, boolInt(e.Stream), e.Action, e.BlockMode, e.Reason, e.Rule, e.BytesIn, e.BytesOut, e.Encoding, e.UpstreamStatus, e.LatencyMS, e.Error, e.Message, len(e.Findings))
		if err != nil {
			tx.Rollback()
			return s.recordErr(err)
		}
		id, _ := res.LastInsertId()
		for _, f := range e.Findings {
			if _, err := fStmt.Exec(id, f.Detector, f.Severity, f.Confidence, f.Segment, f.Role, f.Preview); err != nil {
				tx.Rollback()
				return s.recordErr(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return s.recordErr(err)
	}
	s.mu.Lock()
	s.written += int64(len(batch))
	s.mu.Unlock()
	return nil
}

func (s *SQLiteStore) recordErr(err error) error {
	s.mu.Lock()
	s.errs++
	s.lastErr = err.Error()
	s.mu.Unlock()
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Sweep applies the retention policy.
func (s *SQLiteStore) Sweep(ctx context.Context) error {
	if s.opts.MaxAge > 0 {
		cutoff := time.Now().Add(-s.opts.MaxAge).UnixMilli()
		if _, err := s.writer.ExecContext(ctx, "DELETE FROM events WHERE ts < ?", cutoff); err != nil {
			return s.recordErr(err)
		}
	}
	if s.opts.MaxRows > 0 {
		if _, err := s.writer.ExecContext(ctx,
			"DELETE FROM events WHERE id <= (SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?)", s.opts.MaxRows); err != nil {
			return s.recordErr(err)
		}
	}
	return nil
}

// StoredEvent is an event with its database id.
type StoredEvent struct {
	ID int64 `json:"id"`
	Event
}

// Query filters the history.
type Query struct {
	From, To time.Time
	Kind     string
	Service  string
	Action   string
	Rule     string
	Client   string
	Host     string
	User     string
	Detector string
	Text     string // free text over host, path, client_ip, rule, request_id, user
	Cursor   int64  // return events with id < Cursor
	Limit    int
}

// Page is one page of query results.
type Page struct {
	Items      []StoredEvent `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

const eventColumns = `id, ts, kind, request_id, client_ip, user, device, user_source, listener, method, host, path, service, model, stream,
	action, block_mode, reason, rule, bytes_in, bytes_out, encoding, upstream_status, latency_ms, error, message`

func scanEvent(sc interface{ Scan(...any) error }) (StoredEvent, error) {
	var e StoredEvent
	var ts int64
	var stream int
	err := sc.Scan(&e.ID, &ts, &e.Kind, &e.RequestID, &e.ClientIP, &e.User, &e.Device, &e.UserSource, &e.Listener, &e.Method, &e.Host, &e.Path,
		&e.Service, &e.Model, &stream, &e.Action, &e.BlockMode, &e.Reason, &e.Rule, &e.BytesIn, &e.BytesOut, &e.Encoding, &e.UpstreamStatus,
		&e.LatencyMS, &e.Error, &e.Message)
	if err != nil {
		return e, err
	}
	e.Time = time.UnixMilli(ts).UTC()
	e.Stream = stream == 1
	return e, nil
}

// Query returns a page of events, newest first.
func (s *SQLiteStore) Query(ctx context.Context, q Query) (Page, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		if q.Limit > 500 {
			q.Limit = 500
		} else {
			q.Limit = 100
		}
	}
	where, args := buildWhere(q)
	if q.Cursor > 0 {
		where = append(where, "e.id < ?")
		args = append(args, q.Cursor)
	}
	sqlStr := "SELECT " + eventColumns + " FROM events e"
	if q.Detector != "" {
		sqlStr += " WHERE EXISTS (SELECT 1 FROM findings f WHERE f.event_id = e.id AND f.detector = ?)"
		args = append([]any{q.Detector}, args...)
		if len(where) > 0 {
			sqlStr += " AND " + strings.Join(where, " AND ")
		}
	} else if len(where) > 0 {
		sqlStr += " WHERE " + strings.Join(where, " AND ")
	}
	sqlStr += " ORDER BY e.id DESC LIMIT ?"
	args = append(args, q.Limit+1)

	rows, err := s.reader.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return Page{}, err
	}
	defer rows.Close()
	var page Page
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return Page{}, err
		}
		page.Items = append(page.Items, e)
	}
	if err := rows.Err(); err != nil {
		return Page{}, err
	}
	if len(page.Items) > q.Limit {
		page.Items = page.Items[:q.Limit]
		page.NextCursor = strconv.FormatInt(page.Items[len(page.Items)-1].ID, 10)
	}
	if err := s.attachFindings(ctx, page.Items); err != nil {
		return Page{}, err
	}
	return page, nil
}

func buildWhere(q Query) ([]string, []any) {
	var where []string
	var args []any
	add := func(cond string, v any) {
		where = append(where, cond)
		args = append(args, v)
	}
	if !q.From.IsZero() {
		add("e.ts >= ?", q.From.UnixMilli())
	}
	if !q.To.IsZero() {
		add("e.ts <= ?", q.To.UnixMilli())
	}
	if q.Kind != "" {
		add("e.kind = ?", q.Kind)
	}
	if q.Service != "" {
		add("e.service = ?", q.Service)
	}
	if q.Action != "" {
		add("e.action = ?", q.Action)
	}
	if q.Rule != "" {
		add("e.rule = ?", q.Rule)
	}
	if q.Client != "" {
		add("e.client_ip = ?", q.Client)
	}
	if q.Host != "" {
		add("e.host = ?", q.Host)
	}
	if q.User != "" {
		add("e.user = ?", q.User)
	}
	if q.Text != "" {
		like := "%" + q.Text + "%"
		where = append(where, "(e.host LIKE ? OR e.path LIKE ? OR e.client_ip LIKE ? OR e.rule LIKE ? OR e.request_id LIKE ? OR e.user LIKE ? OR e.device LIKE ?)")
		args = append(args, like, like, like, like, like, like, like)
	}
	return where, args
}

func (s *SQLiteStore) attachFindings(ctx context.Context, items []StoredEvent) error {
	if len(items) == 0 {
		return nil
	}
	ids := make([]any, 0, len(items))
	index := map[int64]int{}
	for i, e := range items {
		ids = append(ids, e.ID)
		index[e.ID] = i
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	rows, err := s.reader.QueryContext(ctx, "SELECT event_id, detector, severity, confidence, segment, role, preview FROM findings WHERE event_id IN ("+placeholders+") ORDER BY id", ids...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var eid int64
		var f FindingSummary
		if err := rows.Scan(&eid, &f.Detector, &f.Severity, &f.Confidence, &f.Segment, &f.Role, &f.Preview); err != nil {
			return err
		}
		if i, ok := index[eid]; ok {
			items[i].Findings = append(items[i].Findings, f)
		}
	}
	return rows.Err()
}

// Get returns one event with its findings.
func (s *SQLiteStore) Get(ctx context.Context, id int64) (*StoredEvent, error) {
	row := s.reader.QueryRowContext(ctx, "SELECT "+eventColumns+" FROM events e WHERE id = ?", id)
	e, err := scanEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	items := []StoredEvent{e}
	if err := s.attachFindings(ctx, items); err != nil {
		return nil, err
	}
	return &items[0], nil
}

// Count is a label/count pair for summaries.
type Count struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// Summary aggregates request events over a time range.
type Summary struct {
	From         time.Time `json:"from"`
	To           time.Time `json:"to"`
	Total        int64     `json:"total"`
	ByAction     []Count   `json:"by_action"`
	ByService    []Count   `json:"by_service"`
	ByRule       []Count   `json:"by_rule"`
	ByDetector   []Count   `json:"by_detector"`
	TopClients   []Count   `json:"top_clients"`
	TopUsers     []Count   `json:"top_users"`
	TopHosts     []Count   `json:"top_hosts"`
	TunnelEvents int64     `json:"tunnel_events"`
}

// Summary computes aggregate counters between from and to.
func (s *SQLiteStore) Summary(ctx context.Context, from, to time.Time) (Summary, error) {
	sum := Summary{From: from, To: to}
	f, t := from.UnixMilli(), to.UnixMilli()
	group := func(query string, args ...any) ([]Count, error) {
		rows, err := s.reader.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []Count
		for rows.Next() {
			var c Count
			if err := rows.Scan(&c.Key, &c.Count); err != nil {
				return nil, err
			}
			out = append(out, c)
		}
		return out, rows.Err()
	}
	var err error
	if err = s.reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE kind = 'request' AND ts BETWEEN ? AND ?", f, t).Scan(&sum.Total); err != nil {
		return sum, err
	}
	if err = s.reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE kind = 'tunnel' AND ts BETWEEN ? AND ?", f, t).Scan(&sum.TunnelEvents); err != nil {
		return sum, err
	}
	base := " FROM events WHERE kind = 'request' AND ts BETWEEN ? AND ? AND %s <> '' GROUP BY %s ORDER BY COUNT(*) DESC LIMIT %d"
	if sum.ByAction, err = group("SELECT action, COUNT(*)"+fmt.Sprintf(base, "action", "action", 10), f, t); err != nil {
		return sum, err
	}
	if sum.ByService, err = group("SELECT service, COUNT(*)"+fmt.Sprintf(base, "service", "service", 20), f, t); err != nil {
		return sum, err
	}
	if sum.ByRule, err = group("SELECT rule, COUNT(*) FROM events WHERE kind = 'request' AND ts BETWEEN ? AND ? AND action IN ('block','monitor') AND rule <> '' GROUP BY rule ORDER BY COUNT(*) DESC LIMIT 20", f, t); err != nil {
		return sum, err
	}
	if sum.ByDetector, err = group("SELECT fi.detector, COUNT(*) FROM findings fi JOIN events e ON e.id = fi.event_id WHERE e.ts BETWEEN ? AND ? GROUP BY fi.detector ORDER BY COUNT(*) DESC LIMIT 20", f, t); err != nil {
		return sum, err
	}
	if sum.TopClients, err = group("SELECT client_ip, COUNT(*) FROM events WHERE kind = 'request' AND ts BETWEEN ? AND ? AND action IN ('block','monitor') AND client_ip <> '' GROUP BY client_ip ORDER BY COUNT(*) DESC LIMIT 10", f, t); err != nil {
		return sum, err
	}
	if sum.TopUsers, err = group("SELECT user, COUNT(*) FROM events WHERE kind = 'request' AND ts BETWEEN ? AND ? AND action IN ('block','monitor') AND user <> '' GROUP BY user ORDER BY COUNT(*) DESC LIMIT 10", f, t); err != nil {
		return sum, err
	}
	if sum.TopHosts, err = group("SELECT host, COUNT(*)"+fmt.Sprintf(base, "host", "host", 10), f, t); err != nil {
		return sum, err
	}
	return sum, nil
}

// Bucket is one time-series point.
type Bucket struct {
	Time  time.Time `json:"ts"`
	Group string    `json:"group"`
	Count int64     `json:"count"`
}

var timeseriesGroups = map[string]string{"action": "action", "service": "service", "rule": "rule", "": "''"}

// Timeseries counts request events per bucket, optionally split by group
// (action, service or rule).
func (s *SQLiteStore) Timeseries(ctx context.Context, from, to time.Time, bucket time.Duration, group string) ([]Bucket, error) {
	col, ok := timeseriesGroups[group]
	if !ok {
		return nil, fmt.Errorf("invalid group %q", group)
	}
	if bucket <= 0 {
		bucket = time.Hour
	}
	ms := bucket.Milliseconds()
	rows, err := s.reader.QueryContext(ctx,
		"SELECT (ts / ?) * ? AS b, "+col+", COUNT(*) FROM events WHERE kind = 'request' AND ts BETWEEN ? AND ? GROUP BY b, "+col+" ORDER BY b",
		ms, ms, from.UnixMilli(), to.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Bucket
	for rows.Next() {
		var b Bucket
		var ts int64
		if err := rows.Scan(&ts, &b.Group, &b.Count); err != nil {
			return nil, err
		}
		b.Time = time.UnixMilli(ts).UTC()
		out = append(out, b)
	}
	return out, rows.Err()
}

// MarshalJSON keeps the embedded Event's field layout while adding id.
func (e StoredEvent) MarshalJSON() ([]byte, error) {
	type alias Event
	return json.Marshal(struct {
		ID int64 `json:"id"`
		alias
	}{e.ID, alias(e.Event)})
}
