package audit

import (
	"sync"
	"sync/atomic"
	"time"
)

// Sink is a destination for audit events. Write is called from a dedicated
// goroutine per sink, so implementations may block (write to a file, insert
// into a database) without affecting the proxy.
type Sink interface {
	Write(Event)
	Close() error
}

// Overflow policies for a sink queue.
const (
	OverflowBlock = "block" // Log waits for space: no event is ever lost (default for stdout)
	OverflowDrop  = "drop"  // Log drops the event and counts it (default for optional sinks)
)

// SinkOptions tune one sink's queue.
type SinkOptions struct {
	Queue    int
	Overflow string
}

// SinkStats reports a sink's queue state.
type SinkStats struct {
	Name    string `json:"name"`
	Queued  int    `json:"queued"`
	Dropped int64  `json:"dropped"`
	Written int64  `json:"written"`
}

// Dispatcher fans events out to sinks asynchronously. Log never performs
// I/O on the caller's goroutine.
type Dispatcher struct {
	mu      sync.RWMutex
	runners []*sinkRunner
	subs    map[int]*subscriber
	nextSub int
	closed  atomic.Bool
	wg      sync.WaitGroup
}

type sinkRunner struct {
	name    string
	sink    Sink
	ch      chan Event
	block   bool
	dropped atomic.Int64
	written atomic.Int64
}

type subscriber struct {
	ch      chan Event
	dropped atomic.Int64
}

// NewDispatcher creates an empty dispatcher; add sinks with Add.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{subs: map[int]*subscriber{}}
}

// Add registers a sink and starts its goroutine.
func (d *Dispatcher) Add(name string, sink Sink, opts SinkOptions) {
	if opts.Queue <= 0 {
		opts.Queue = 1024
	}
	r := &sinkRunner{name: name, sink: sink, ch: make(chan Event, opts.Queue), block: opts.Overflow != OverflowDrop}
	d.mu.Lock()
	d.runners = append(d.runners, r)
	d.mu.Unlock()
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		for e := range r.ch {
			r.sink.Write(e)
			r.written.Add(1)
		}
		_ = r.sink.Close()
	}()
}

// Log implements Logger.
func (d *Dispatcher) Log(e Event) {
	if d.closed.Load() {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, r := range d.runners {
		if r.block {
			r.ch <- e
			continue
		}
		select {
		case r.ch <- e:
		default:
			r.dropped.Add(1)
		}
	}
	for _, s := range d.subs {
		select {
		case s.ch <- e:
		default:
			s.dropped.Add(1)
		}
	}
}

// Subscription is a live feed of events. Events are dropped for a
// subscriber that cannot keep up; Dropped reports how many, so the consumer
// can tell the viewer their feed skipped entries.
type Subscription struct {
	C       <-chan Event
	sub     *subscriber
	cancel  func()
	dropped func() int64
}

// Dropped returns the number of events skipped for this subscriber so far.
func (s *Subscription) Dropped() int64 { return s.dropped() }

// Close unsubscribes and closes the channel.
func (s *Subscription) Close() { s.cancel() }

// Subscribe returns a live feed of every event from now on. Call Close when
// the consumer goes away.
func (d *Dispatcher) Subscribe(buf int) *Subscription {
	if buf <= 0 {
		buf = 256
	}
	s := &subscriber{ch: make(chan Event, buf)}
	d.mu.Lock()
	id := d.nextSub
	d.nextSub++
	d.subs[id] = s
	d.mu.Unlock()
	var once sync.Once
	return &Subscription{
		C:   s.ch,
		sub: s,
		cancel: func() {
			once.Do(func() {
				d.mu.Lock()
				if _, ok := d.subs[id]; ok {
					delete(d.subs, id)
					close(s.ch)
				}
				d.mu.Unlock()
			})
		},
		dropped: func() int64 { return s.dropped.Load() },
	}
}

// Subscribers reports how many live feeds are attached.
func (d *Dispatcher) Subscribers() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.subs)
}

// Stats reports each sink's queue state.
func (d *Dispatcher) Stats() []SinkStats {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]SinkStats, 0, len(d.runners))
	for _, r := range d.runners {
		out = append(out, SinkStats{Name: r.name, Queued: len(r.ch), Dropped: r.dropped.Load(), Written: r.written.Load()})
	}
	return out
}

// Dropped returns the total number of events dropped across sinks.
func (d *Dispatcher) Dropped() int64 {
	var n int64
	for _, s := range d.Stats() {
		n += s.Dropped
	}
	return n
}

// Close stops accepting events, drains queues and closes sinks, waiting at
// most timeout for the drain.
func (d *Dispatcher) Close(timeout time.Duration) error {
	if !d.closed.CompareAndSwap(false, true) {
		return nil
	}
	d.mu.Lock()
	for _, r := range d.runners {
		close(r.ch)
	}
	for id, s := range d.subs {
		close(s.ch)
		delete(d.subs, id)
	}
	d.mu.Unlock()
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return errAuditDrainTimeout
	}
}

var errAuditDrainTimeout = timeoutError("audit sinks did not drain before shutdown timeout")

type timeoutError string

func (e timeoutError) Error() string { return string(e) }

// Write implements Sink for JSONLogger.
func (l *JSONLogger) Write(e Event) { l.Log(e) }

// Close implements Sink for JSONLogger; the underlying writer is owned by
// the caller.
func (l *JSONLogger) Close() error { return nil }

// WriterSink is a JSON line sink that closes its writer on Close.
type WriterSink struct {
	*JSONLogger
	closer func() error
}

// NewWriterSink creates a sink over a closable writer (a log file).
func NewWriterSink(w interface {
	Write([]byte) (int, error)
	Close() error
}) *WriterSink {
	return &WriterSink{JSONLogger: NewJSONLogger(w), closer: w.Close}
}

// Close implements Sink.
func (s *WriterSink) Close() error { return s.closer() }
