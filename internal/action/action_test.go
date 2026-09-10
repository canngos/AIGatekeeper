package action

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderMessage(t *testing.T) {
	req := Request{Rule: "secrets", Detectors: []string{"aws_access_key", "jwt"}, RequestID: "abc"}
	got := RenderMessage("Blocked by {rule} ({detectors}) ref {request_id}", req)
	if got != "Blocked by secrets (aws_access_key, jwt) ref abc" {
		t.Fatalf("got %q", got)
	}
	if !strings.Contains(RenderMessage("", Request{Rule: "r", RequestID: "x"}), "policy r (policy)") {
		t.Fatal("default template not applied")
	}
}

func TestFamilyFor(t *testing.T) {
	cases := []struct {
		extractor, path string
		want            Family
	}{
		{"openai", "/v1/chat/completions", FamilyOpenAIChat},
		{"openai", "/v1/completions", FamilyOpenAICompletions},
		{"openai", "/v1/responses", FamilyOpenAIResponses},
		{"openai", "/v1/embeddings", FamilyGenericError},
		{"copilot", "/chat/completions", FamilyOpenAIChat},
		{"copilot", "/v1/engines/gpt-4o-copilot/completions", FamilyCopilotInline},
		{"anthropic", "/v1/messages", FamilyAnthropic},
		{"gemini", "/v1beta/models/gemini-2.5-pro:generateContent", FamilyGemini},
		{"ollama", "/api/chat", FamilyOllamaChat},
		{"ollama", "/api/generate", FamilyOllamaGenerate},
		{"ollama", "/v1/chat/completions", FamilyOpenAIChat},
		{"ollama", "/api/tags", FamilyGenericError},
		{"generic", "/anything", FamilyOpenAIChat},
	}
	for _, c := range cases {
		if got := FamilyFor(c.extractor, c.path); got != c.want {
			t.Errorf("FamilyFor(%s, %s) = %s, want %s", c.extractor, c.path, got, c.want)
		}
	}
}

func respond(t *testing.T, req Request) *httptest.ResponseRecorder {
	t.Helper()
	req.RequestID = "REQ1"
	req.Rule = "secrets"
	req.Message = "blocked because reasons"
	rec := httptest.NewRecorder()
	Respond(rec, req)
	if rec.Header().Get(BlockedHeader) != "secrets" {
		t.Errorf("missing %s header", BlockedHeader)
	}
	return rec
}

func decode(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("invalid JSON %q: %v", body, err)
	}
	return m
}

func sseDataLines(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "data: ") {
			out = append(out, strings.TrimPrefix(line, "data: "))
		}
	}
	return out
}

func TestRejectShapes(t *testing.T) {
	cases := []struct {
		extractor, path string
		check           func(t *testing.T, m map[string]any)
	}{
		{"openai", "/v1/chat/completions", func(t *testing.T, m map[string]any) {
			e := m["error"].(map[string]any)
			if e["code"] != "dlp_blocked" || e["message"] != "blocked because reasons" || e["rule"] != "secrets" {
				t.Errorf("openai error shape: %v", e)
			}
		}},
		{"anthropic", "/v1/messages", func(t *testing.T, m map[string]any) {
			if m["type"] != "error" || m["error"].(map[string]any)["type"] != "permission_error" {
				t.Errorf("anthropic error shape: %v", m)
			}
		}},
		{"gemini", "/v1beta/models/x:generateContent", func(t *testing.T, m map[string]any) {
			e := m["error"].(map[string]any)
			if e["status"] != "PERMISSION_DENIED" || e["code"] != float64(403) {
				t.Errorf("gemini error shape: %v", e)
			}
		}},
		{"ollama", "/api/chat", func(t *testing.T, m map[string]any) {
			if m["error"] != "blocked because reasons" {
				t.Errorf("ollama error shape: %v", m)
			}
		}},
		{"openai", "/v1/embeddings", func(t *testing.T, m map[string]any) {
			if _, ok := m["error"]; !ok {
				t.Errorf("embeddings should reject: %v", m)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.extractor+c.path, func(t *testing.T) {
			rec := respond(t, Request{Extractor: c.extractor, Path: c.path, BlockMode: "reject"})
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status %d", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Fatalf("content-type %q", ct)
			}
			c.check(t, decode(t, rec.Body.String()))
		})
	}
	// Synthetic mode on a family without a completion shape still rejects.
	rec := respond(t, Request{Extractor: "openai", Path: "/v1/embeddings", BlockMode: "synthetic"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("embeddings synthetic should fall back to 403, got %d", rec.Code)
	}
}

func TestSyntheticNonStreaming(t *testing.T) {
	t.Run("openai chat", func(t *testing.T) {
		rec := respond(t, Request{Extractor: "openai", Path: "/v1/chat/completions", BlockMode: "synthetic", Model: "gpt-4o"})
		m := decode(t, rec.Body.String())
		choice := m["choices"].([]any)[0].(map[string]any)
		if rec.Code != 200 || m["object"] != "chat.completion" || m["model"] != "gpt-4o" ||
			choice["message"].(map[string]any)["content"] != "blocked because reasons" || choice["finish_reason"] != "stop" {
			t.Errorf("shape: %v", m)
		}
	})
	t.Run("openai completions", func(t *testing.T) {
		rec := respond(t, Request{Extractor: "openai", Path: "/v1/completions", BlockMode: "synthetic"})
		m := decode(t, rec.Body.String())
		if m["object"] != "text_completion" || m["choices"].([]any)[0].(map[string]any)["text"] != "blocked because reasons" {
			t.Errorf("shape: %v", m)
		}
	})
	t.Run("copilot inline inserts nothing", func(t *testing.T) {
		rec := respond(t, Request{Extractor: "copilot", Path: "/v1/engines/gpt-4o-copilot/completions", BlockMode: "synthetic"})
		m := decode(t, rec.Body.String())
		if m["choices"].([]any)[0].(map[string]any)["text"] != "" {
			t.Errorf("inline completion must be empty: %v", m)
		}
	})
	t.Run("openai responses", func(t *testing.T) {
		rec := respond(t, Request{Extractor: "openai", Path: "/v1/responses", BlockMode: "synthetic"})
		m := decode(t, rec.Body.String())
		out := m["output"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)
		if m["object"] != "response" || m["status"] != "completed" || out["text"] != "blocked because reasons" {
			t.Errorf("shape: %v", m)
		}
	})
	t.Run("anthropic", func(t *testing.T) {
		rec := respond(t, Request{Extractor: "anthropic", Path: "/v1/messages", BlockMode: "synthetic", Model: "claude-sonnet-5"})
		m := decode(t, rec.Body.String())
		block := m["content"].([]any)[0].(map[string]any)
		if m["type"] != "message" || m["role"] != "assistant" || m["stop_reason"] != "end_turn" || block["text"] != "blocked because reasons" {
			t.Errorf("shape: %v", m)
		}
	})
	t.Run("gemini", func(t *testing.T) {
		rec := respond(t, Request{Extractor: "gemini", Path: "/v1beta/models/g:generateContent", BlockMode: "synthetic"})
		m := decode(t, rec.Body.String())
		cand := m["candidates"].([]any)[0].(map[string]any)
		part := cand["content"].(map[string]any)["parts"].([]any)[0].(map[string]any)
		if cand["finishReason"] != "STOP" || part["text"] != "blocked because reasons" {
			t.Errorf("shape: %v", m)
		}
	})
	t.Run("gemini stream without sse is a JSON array", func(t *testing.T) {
		rec := respond(t, Request{Extractor: "gemini", Path: "/v1beta/models/g:streamGenerateContent", BlockMode: "synthetic", Stream: true})
		var arr []any
		if err := json.Unmarshal(rec.Body.Bytes(), &arr); err != nil || len(arr) != 1 {
			t.Errorf("expected single-element array, got %s", rec.Body.String())
		}
	})
	t.Run("ollama chat and generate", func(t *testing.T) {
		rec := respond(t, Request{Extractor: "ollama", Path: "/api/chat", BlockMode: "synthetic", Model: "llama3"})
		m := decode(t, rec.Body.String())
		if m["done"] != true || m["message"].(map[string]any)["content"] != "blocked because reasons" {
			t.Errorf("chat shape: %v", m)
		}
		rec = respond(t, Request{Extractor: "ollama", Path: "/api/generate", BlockMode: "synthetic"})
		m = decode(t, rec.Body.String())
		if m["done"] != true || m["response"] != "blocked because reasons" {
			t.Errorf("generate shape: %v", m)
		}
	})
}

func TestSyntheticStreaming(t *testing.T) {
	t.Run("openai chat sse", func(t *testing.T) {
		rec := respond(t, Request{Extractor: "openai", Path: "/v1/chat/completions", BlockMode: "synthetic", Stream: true})
		if rec.Header().Get("Content-Type") != "text/event-stream" {
			t.Fatalf("content-type %q", rec.Header().Get("Content-Type"))
		}
		lines := sseDataLines(rec.Body.String())
		if len(lines) != 4 || lines[3] != "[DONE]" {
			t.Fatalf("expected 3 chunks + [DONE], got %v", lines)
		}
		content := decode(t, lines[1])["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["content"]
		if content != "blocked because reasons" {
			t.Errorf("content chunk: %v", lines[1])
		}
		if decode(t, lines[2])["choices"].([]any)[0].(map[string]any)["finish_reason"] != "stop" {
			t.Errorf("finish chunk: %v", lines[2])
		}
	})
	t.Run("copilot inline sse", func(t *testing.T) {
		rec := respond(t, Request{Extractor: "copilot", Path: "/v1/engines/e/completions", BlockMode: "synthetic", Stream: true})
		lines := sseDataLines(rec.Body.String())
		if len(lines) != 2 || lines[1] != "[DONE]" || decode(t, lines[0])["choices"].([]any)[0].(map[string]any)["text"] != "" {
			t.Fatalf("unexpected inline stream: %v", lines)
		}
	})
	t.Run("anthropic event sequence", func(t *testing.T) {
		rec := respond(t, Request{Extractor: "anthropic", Path: "/v1/messages", BlockMode: "synthetic", Stream: true})
		body := rec.Body.String()
		for _, ev := range []string{"message_start", "content_block_start", "content_block_delta", "content_block_stop", "message_delta", "message_stop"} {
			if !strings.Contains(body, "event: "+ev+"\n") {
				t.Errorf("missing event %s", ev)
			}
		}
		if !strings.Contains(body, `"text":"blocked because reasons"`) || !strings.Contains(body, `"type":"text_delta"`) {
			t.Errorf("delta text missing: %s", body)
		}
	})
	t.Run("gemini alt=sse", func(t *testing.T) {
		rec := respond(t, Request{Extractor: "gemini", Path: "/v1beta/models/g:streamGenerateContent", Query: "alt=sse", BlockMode: "synthetic", Stream: true})
		lines := sseDataLines(rec.Body.String())
		if len(lines) != 1 || !strings.Contains(lines[0], `"finishReason":"STOP"`) {
			t.Fatalf("gemini sse: %v", lines)
		}
	})
	t.Run("ollama ndjson", func(t *testing.T) {
		rec := respond(t, Request{Extractor: "ollama", Path: "/api/chat", BlockMode: "synthetic", Stream: true})
		if rec.Header().Get("Content-Type") != "application/x-ndjson" {
			t.Fatalf("content-type %q", rec.Header().Get("Content-Type"))
		}
		if m := decode(t, strings.TrimSpace(rec.Body.String())); m["done"] != true {
			t.Errorf("ndjson line: %v", m)
		}
	})
	t.Run("responses api sse", func(t *testing.T) {
		rec := respond(t, Request{Extractor: "openai", Path: "/v1/responses", BlockMode: "synthetic", Stream: true})
		body := rec.Body.String()
		if !strings.Contains(body, "event: response.completed") || !strings.Contains(body, "event: response.output_text.delta") {
			t.Errorf("responses sse: %s", body)
		}
	})
}
