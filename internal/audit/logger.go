package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Logger receives audit events. Implementations must be safe for concurrent
// use and must not block the caller for long; the proxy hot path calls Log.
type Logger interface {
	Log(Event)
}

// LoggerFunc adapts a function to the Logger interface.
type LoggerFunc func(Event)

// Log implements Logger.
func (f LoggerFunc) Log(e Event) { f(e) }

// Discard drops every event.
var Discard Logger = LoggerFunc(func(Event) {})

// Multi fans one event out to several loggers in order.
type Multi []Logger

// Log implements Logger.
func (m Multi) Log(e Event) {
	for _, l := range m {
		l.Log(e)
	}
}

// JSONLogger writes one JSON object per line to an io.Writer (stdout, a file).
type JSONLogger struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONLogger creates a line-delimited JSON logger.
func NewJSONLogger(w io.Writer) *JSONLogger {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSONLogger{enc: enc}
}

// Log implements Logger.
func (l *JSONLogger) Log(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(e)
}

// Recorder keeps events in memory; intended for tests.
type Recorder struct {
	mu     sync.Mutex
	events []Event
}

// Log implements Logger.
func (r *Recorder) Log(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// Events returns a copy of the recorded events.
func (r *Recorder) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, len(r.events))
	copy(out, r.events)
	return out
}

// Reset clears recorded events.
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = nil
}
