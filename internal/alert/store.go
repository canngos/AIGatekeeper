package alert

import (
	"context"
	"encoding/json"
	"time"

	"github.com/canngos/aigatekeeper/internal/audit"
)

// SQLiteStore adapts the audit history database to the engine's Store.
type SQLiteStore struct{ db *audit.SQLiteStore }

// NewSQLiteStore wraps the audit store.
func NewSQLiteStore(db *audit.SQLiteStore) *SQLiteStore { return &SQLiteStore{db: db} }

// Insert implements Store.
func (s *SQLiteStore) Insert(ctx context.Context, a *Alert) error {
	payload, err := json.Marshal(a)
	if err != nil {
		return err
	}
	id, err := s.db.InsertAlert(ctx, audit.AlertInput{
		Time: a.Time, RuleID: a.RuleID, GroupKey: a.GroupKey, GroupBy: a.GroupBy,
		User: a.User, Device: a.Device, ClientIP: a.ClientIP,
		Count: a.Count, Window: a.Window, Since: a.Since, Severity: a.Severity, Payload: payload,
	})
	if err != nil {
		return err
	}
	a.ID = id
	return nil
}

// LastFired implements Store.
func (s *SQLiteStore) LastFired(ctx context.Context, ruleID, groupKey string) (time.Time, error) {
	return s.db.LastAlertFired(ctx, ruleID, groupKey)
}

// MarkFired implements Store.
func (s *SQLiteStore) MarkFired(ctx context.Context, ruleID, groupKey string, at time.Time) error {
	return s.db.MarkAlertFired(ctx, ruleID, groupKey, at)
}

// MemoryStore keeps alerts in memory, for deployments without the history
// database and for tests.
type MemoryStore struct {
	alerts []Alert
	fired  map[string]time.Time
	nextID int64
}

// NewMemoryStore creates an in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{fired: map[string]time.Time{}}
}

// Insert implements Store.
func (m *MemoryStore) Insert(_ context.Context, a *Alert) error {
	m.nextID++
	a.ID = m.nextID
	m.alerts = append(m.alerts, *a)
	if len(m.alerts) > 500 {
		m.alerts = m.alerts[len(m.alerts)-500:]
	}
	return nil
}

// LastFired implements Store.
func (m *MemoryStore) LastFired(_ context.Context, ruleID, groupKey string) (time.Time, error) {
	return m.fired[ruleID+"\x00"+groupKey], nil
}

// MarkFired implements Store.
func (m *MemoryStore) MarkFired(_ context.Context, ruleID, groupKey string, at time.Time) error {
	m.fired[ruleID+"\x00"+groupKey] = at
	return nil
}

// Alerts returns the stored alerts, newest first.
func (m *MemoryStore) Alerts() []Alert {
	out := make([]Alert, len(m.alerts))
	for i, a := range m.alerts {
		out[len(m.alerts)-1-i] = a
	}
	return out
}
