package proxy

import (
	"strings"
	"testing"

	"github.com/canngos/aigatekeeper/internal/parser"
)

func extractionOf(texts ...string) *parser.Extraction {
	ex := &parser.Extraction{}
	roles := []string{"system", "user", "assistant"}
	for i, t := range texts {
		ex.Segments = append(ex.Segments, parser.Segment{
			Path: "/input/" + string(rune('0'+i)), Role: roles[i%len(roles)], Text: t,
		})
	}
	return ex
}

func TestPromptSegmentsKeepsTheNewestTurn(t *testing.T) {
	// A chat client resends the whole thread each turn: a huge system
	// prompt and context block at the front, the question just typed at
	// the end. The end is the part worth keeping.
	boilerplate := strings.Repeat("you are a helpful assistant. ", 400) // ~11 KB
	context := strings.Repeat("<file>irrelevant context</file>", 400)   // ~12 KB
	question := "why does my deploy script fail?"

	tx := &Transaction{Extraction: extractionOf(boilerplate, context, question)}
	got := tx.PromptSegments(8 << 10)

	last := got[len(got)-1]
	if last.Text != question {
		t.Fatalf("the newest message must survive truncation, got %q", last.Text[:min(len(last.Text), 60)])
	}
	if got[0].Role != "note" || !strings.Contains(got[0].Text, "not recorded") {
		t.Fatalf("dropped messages should be reported, got %+v", got[0])
	}
	if !strings.Contains(got[0].Text, "still scanned") {
		t.Error("the note should say the dropped text was still scanned")
	}
}

func TestPromptSegmentsKeepsOrderAndWholeSmallThreads(t *testing.T) {
	tx := &Transaction{Extraction: extractionOf("first", "second", "third")}
	got := tx.PromptSegments(8 << 10)
	if len(got) != 3 {
		t.Fatalf("a small thread should be kept whole, got %d", len(got))
	}
	for i, want := range []string{"first", "second", "third"} {
		if got[i].Text != want {
			t.Fatalf("segment %d = %q, want %q (order must be preserved)", i, got[i].Text, want)
		}
	}
	if got[0].Role != "system" || got[0].Path != "/input/0" {
		t.Errorf("role and path should survive: %+v", got[0])
	}
}

func TestPromptSegmentsTruncatesOnRuneBoundary(t *testing.T) {
	// Budget lands mid-character: the result must still be valid UTF-8.
	tx := &Transaction{Extraction: extractionOf(strings.Repeat("é", 100))}
	got := tx.PromptSegments(11)
	if len(got) != 1 {
		t.Fatalf("expected one segment, got %d", len(got))
	}
	text := strings.TrimSuffix(got[0].Text, "…")
	if strings.ContainsRune(text, '�') || !isValidUTF8(text) {
		t.Fatalf("truncation split a character: %q", got[0].Text)
	}
	if !strings.HasSuffix(got[0].Text, "…") {
		t.Error("a truncated segment should be marked as such")
	}
}

func TestPromptSegmentsEmpty(t *testing.T) {
	if got := (&Transaction{}).PromptSegments(1024); got != nil {
		t.Fatalf("no extraction should yield nothing, got %+v", got)
	}
	if got := (&Transaction{Extraction: &parser.Extraction{}}).PromptSegments(1024); got != nil {
		t.Fatalf("an empty extraction should yield nothing, got %+v", got)
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
