package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

type slowSink struct {
	mu     sync.Mutex
	gate   chan struct{}
	events []Event
	closed bool
}

func (s *slowSink) Write(e Event) {
	<-s.gate
	s.mu.Lock()
	s.events = append(s.events, e)
	s.mu.Unlock()
}

func (s *slowSink) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *slowSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func TestDispatcherDropPolicyNeverBlocks(t *testing.T) {
	sink := &slowSink{gate: make(chan struct{})}
	d := NewDispatcher()
	d.Add("slow", sink, SinkOptions{Queue: 2, Overflow: OverflowDrop})

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			d.Log(Event{Kind: KindRequest, RequestID: string(rune('a' + i))})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Log blocked with a drop-policy sink")
	}
	stats := d.Stats()[0]
	if stats.Dropped < 7 || stats.Dropped > 8 { // 2 queued + possibly 1 in flight
		t.Fatalf("expected ~7-8 drops, got %+v", stats)
	}
	close(sink.gate)
	if err := d.Close(time.Second); err != nil {
		t.Fatal(err)
	}
	if !sink.closed || sink.count()+int(stats.Dropped) != 10 {
		t.Fatalf("sink state after close: closed=%v written=%d dropped=%d", sink.closed, sink.count(), stats.Dropped)
	}
}

func TestDispatcherBlockPolicyDeliversEverything(t *testing.T) {
	sink := &slowSink{gate: make(chan struct{})}
	d := NewDispatcher()
	d.Add("strict", sink, SinkOptions{Queue: 2, Overflow: OverflowBlock})
	close(sink.gate) // sink is fast now
	for i := 0; i < 100; i++ {
		d.Log(Event{Kind: KindRequest})
	}
	if err := d.Close(time.Second); err != nil {
		t.Fatal(err)
	}
	if sink.count() != 100 || d.Dropped() != 0 {
		t.Fatalf("expected 100 delivered, got %d (dropped %d)", sink.count(), d.Dropped())
	}
	d.Log(Event{Kind: KindRequest}) // after close: ignored, must not panic
}

func TestDispatcherSubscribe(t *testing.T) {
	d := NewDispatcher()
	sub := d.Subscribe(1)
	if d.Subscribers() != 1 {
		t.Fatalf("subscribers = %d", d.Subscribers())
	}
	d.Log(Event{Kind: KindRequest, RequestID: "1"})
	d.Log(Event{Kind: KindRequest, RequestID: "2"}) // dropped: buffer of 1 is full
	if e := <-sub.C; e.RequestID != "1" {
		t.Fatalf("got %+v", e)
	}
	if dropped := sub.Dropped(); dropped != 1 {
		t.Fatalf("expected 1 dropped for slow subscriber, got %d", dropped)
	}
	sub.Close()
	if _, ok := <-sub.C; ok {
		t.Fatal("channel should be closed after Close")
	}
	sub.Close() // idempotent
	if d.Subscribers() != 0 {
		t.Fatalf("subscribers after close = %d", d.Subscribers())
	}
	_ = d.Close(time.Second)
}

func TestJSONLoggerSchema(t *testing.T) {
	var buf bytes.Buffer
	l := NewJSONLogger(&buf)
	l.Log(Event{
		Kind: KindRequest, RequestID: "abc", ClientIP: "10.0.0.1", Listener: "forward", Method: "POST",
		Host: "api.openai.com", Path: "/v1/chat/completions", Service: "openai", Model: "gpt-4o", Stream: true,
		Action: ActionBlock, BlockMode: "reject", Reason: "dlp", Rule: "secrets",
		Findings: []FindingSummary{{Detector: "aws_access_key", Severity: "critical", Segment: "/messages/0/content", Preview: "AKIA****EY"}},
		BytesIn:  120, UpstreamStatus: 403, LatencyMS: 3,
	})
	line := buf.String()
	if strings.Count(line, "\n") != 1 {
		t.Fatalf("expected exactly one line, got %q", line)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"ts", "kind", "request_id", "client_ip", "listener", "method", "host", "path", "service", "model", "stream", "action", "block_mode", "reason", "rule", "findings", "bytes_in", "upstream_status", "latency_ms"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing key %s in %s", key, line)
		}
	}
	if _, ok := m["error"]; ok {
		t.Error("empty error must be omitted")
	}
	if !strings.HasSuffix(m["ts"].(string), "Z") {
		t.Errorf("timestamp must be UTC RFC3339: %v", m["ts"])
	}
	f := m["findings"].([]any)[0].(map[string]any)
	if f["preview"] != "AKIA****EY" {
		t.Errorf("finding preview: %v", f)
	}
}
