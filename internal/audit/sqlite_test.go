package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestStore(t *testing.T, opts SQLiteOptions) (*SQLiteStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	s, err := OpenSQLite(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func sampleEvents(n int, base time.Time) []Event {
	out := make([]Event, 0, n)
	for i := 0; i < n; i++ {
		e := Event{
			Time: base.Add(time.Duration(i) * time.Minute), Kind: KindRequest, RequestID: "req" + string(rune('A'+i%26)),
			ClientIP: "10.0.0." + string(rune('1'+i%3)), Listener: "forward", Method: "POST",
			Host: "api.openai.com", Path: "/v1/chat/completions", Service: "openai", Model: "gpt-4o",
			Action: ActionAllow, UpstreamStatus: 200, LatencyMS: int64(i),
		}
		if i%4 == 0 {
			e.Action = ActionBlock
			e.Rule = "secrets"
			e.Reason = "dlp"
			e.Service = "copilot"
			e.Host = "api.githubcopilot.com"
			e.Findings = []FindingSummary{{Detector: "aws_access_key", Severity: "critical", Confidence: 1, Segment: "/messages/0/content", Preview: "AKIA****EY"}}
		}
		if i%10 == 5 {
			e.Action = ActionMonitor
			e.Rule = "internal"
			e.Findings = []FindingSummary{{Detector: "keyword:internal", Severity: "medium", Preview: "Proj****on"}}
		}
		out = append(out, e)
	}
	return out
}

func TestSQLiteInsertQueryAndGet(t *testing.T) {
	s, _ := openTestStore(t, SQLiteOptions{BatchSize: 8, FlushInterval: 10 * time.Millisecond})
	base := time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)
	for _, e := range sampleEvents(50, base) {
		s.Write(e)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	page, err := s.Query(ctx, Query{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 20 || page.NextCursor == "" {
		t.Fatalf("expected 20 items and a cursor, got %d %q", len(page.Items), page.NextCursor)
	}
	if page.Items[0].ID <= page.Items[1].ID {
		t.Fatal("items must be newest first")
	}
	// Follow the cursor to the end.
	total := len(page.Items)
	for page.NextCursor != "" {
		var cursor int64
		for _, c := range page.NextCursor {
			cursor = cursor*10 + int64(c-'0')
		}
		page, err = s.Query(ctx, Query{Limit: 20, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		total += len(page.Items)
	}
	if total != 50 {
		t.Fatalf("pagination returned %d of 50", total)
	}

	blocked, _ := s.Query(ctx, Query{Action: ActionBlock})
	if len(blocked.Items) != 13 {
		t.Fatalf("expected 13 blocked, got %d", len(blocked.Items))
	}
	for _, e := range blocked.Items {
		if len(e.Findings) != 1 || e.Findings[0].Detector != "aws_access_key" || e.Findings[0].Preview != "AKIA****EY" {
			t.Fatalf("findings not attached: %+v", e)
		}
	}
	byDetector, _ := s.Query(ctx, Query{Detector: "keyword:internal"})
	if len(byDetector.Items) != 5 {
		t.Fatalf("expected 5 keyword events, got %d", len(byDetector.Items))
	}
	byText, _ := s.Query(ctx, Query{Text: "githubcopilot"})
	if len(byText.Items) != 13 {
		t.Fatalf("free text search returned %d", len(byText.Items))
	}
	ranged, _ := s.Query(ctx, Query{From: base.Add(10 * time.Minute), To: base.Add(19 * time.Minute)})
	if len(ranged.Items) != 10 {
		t.Fatalf("time range returned %d", len(ranged.Items))
	}

	got, err := s.Get(ctx, blocked.Items[0].ID)
	if err != nil || got == nil || got.Rule != "secrets" || got.Time.IsZero() || len(got.Findings) != 1 {
		t.Fatalf("get: %v %+v", err, got)
	}
	if missing, err := s.Get(ctx, 999999); err != nil || missing != nil {
		t.Fatalf("missing id should return nil, got %v %v", missing, err)
	}
	if written, errs, _ := s.Stats(); written != 50 || errs != 0 {
		t.Fatalf("stats written=%d errs=%d", written, errs)
	}
}

func TestSQLiteSummaryAndTimeseries(t *testing.T) {
	s, _ := openTestStore(t, SQLiteOptions{})
	base := time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)
	for _, e := range sampleEvents(40, base) {
		s.Write(e)
	}
	s.Write(Event{Time: base, Kind: KindTunnel, Host: "github.com:443", Action: ActionAllow})
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sum, err := s.Summary(ctx, base.Add(-time.Hour), base.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Total != 40 || sum.TunnelEvents != 1 {
		t.Fatalf("totals: %+v", sum)
	}
	counts := map[string]int64{}
	for _, c := range sum.ByAction {
		counts[c.Key] = c.Count
	}
	if counts[ActionBlock] != 10 || counts[ActionMonitor] != 4 || counts[ActionAllow] != 26 {
		t.Fatalf("by action: %v", sum.ByAction)
	}
	if len(sum.ByRule) != 2 || sum.ByRule[0].Key != "secrets" || sum.ByRule[0].Count != 10 {
		t.Fatalf("by rule: %v", sum.ByRule)
	}
	if len(sum.ByDetector) != 2 || sum.ByDetector[0].Key != "aws_access_key" {
		t.Fatalf("by detector: %v", sum.ByDetector)
	}
	if len(sum.TopClients) == 0 || len(sum.ByService) != 2 {
		t.Fatalf("top clients %v services %v", sum.TopClients, sum.ByService)
	}

	series, err := s.Timeseries(ctx, base, base.Add(time.Hour), 15*time.Minute, "action")
	if err != nil {
		t.Fatal(err)
	}
	var blocks int64
	for _, b := range series {
		if b.Group == ActionBlock {
			blocks += b.Count
		}
		if b.Time.Before(base) || b.Time.After(base.Add(time.Hour)) {
			t.Fatalf("bucket outside range: %+v", b)
		}
	}
	if blocks != 10 {
		t.Fatalf("timeseries blocks = %d", blocks)
	}
	if _, err := s.Timeseries(ctx, base, base, time.Minute, "client_ip"); err == nil {
		t.Fatal("invalid group must be rejected")
	}
}

func TestSQLiteRetention(t *testing.T) {
	s, _ := openTestStore(t, SQLiteOptions{MaxRows: 10})
	base := time.Now().Add(-48 * time.Hour)
	for _, e := range sampleEvents(30, base) {
		s.Write(e)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	page, _ := s.Query(context.Background(), Query{Limit: 500})
	if len(page.Items) != 10 {
		t.Fatalf("max_rows retention left %d", len(page.Items))
	}
	var orphans int
	if err := s.reader.QueryRow("SELECT COUNT(*) FROM findings f LEFT JOIN events e ON e.id = f.event_id WHERE e.id IS NULL").Scan(&orphans); err != nil || orphans != 0 {
		t.Fatalf("findings not cascaded: %d %v", orphans, err)
	}

	s2, _ := openTestStore(t, SQLiteOptions{MaxAge: time.Hour})
	for _, e := range sampleEvents(5, base) {
		s2.Write(e)
	}
	s2.Write(Event{Time: time.Now(), Kind: KindRequest, Action: ActionAllow})
	_ = s2.Flush()
	_ = s2.Sweep(context.Background())
	page, _ = s2.Query(context.Background(), Query{})
	if len(page.Items) != 1 {
		t.Fatalf("max_age retention left %d", len(page.Items))
	}
}

func TestSQLiteNeverStoresRawSecrets(t *testing.T) {
	s, path := openTestStore(t, SQLiteOptions{})
	secret := "AKIAIOSFODNN7REALKEY"
	s.Write(Event{Time: time.Now(), Kind: KindRequest, Action: ActionBlock, Rule: "secrets",
		Findings: []FindingSummary{{Detector: "aws_access_key", Preview: "AKIA****EY"}}})
	_ = s.Flush()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("database file contains the raw secret")
	}
	if !strings.Contains(string(raw), "AKIA****EY") {
		t.Fatal("database should contain the masked preview")
	}
}

func TestSQLiteAsDispatcherSink(t *testing.T) {
	s, _ := openTestStore(t, SQLiteOptions{FlushInterval: 10 * time.Millisecond})
	d := NewDispatcher()
	d.Add("sqlite", s, SinkOptions{Queue: 16, Overflow: OverflowDrop})
	for i := 0; i < 5; i++ {
		d.Log(Event{Kind: KindRequest, Action: ActionAllow})
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if page, _ := s.Query(context.Background(), Query{}); len(page.Items) == 5 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("events did not reach sqlite through the dispatcher")
}
