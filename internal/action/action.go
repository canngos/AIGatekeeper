// Package action writes the response a client receives when its request is
// blocked. Two modes exist: "reject" answers with HTTP 403 and an error body
// in the service's own error format; "synthetic" answers with HTTP 200 and a
// fake completion (or stream) whose text explains the block, so IDE
// extensions render the explanation instead of failing.
package action

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/canngos/aigatekeeper/internal/config"
	"github.com/canngos/aigatekeeper/internal/parser"
)

// BlockedHeader carries the rule id on every blocked response.
const BlockedHeader = "X-AIGatekeeper-Blocked"

// Request describes the blocked request well enough to shape the reply.
type Request struct {
	Extractor string // openai | copilot | anthropic | gemini | ollama | generic
	Path      string
	Query     string
	Model     string
	Stream    bool
	RequestID string
	Rule      string
	Detectors []string
	BlockMode string // reject | synthetic
	Message   string // rendered block message
}

// RenderMessage fills {rule}, {detectors} and {request_id} placeholders.
func RenderMessage(tmpl string, req Request) string {
	if tmpl == "" {
		tmpl = "[AIGatekeeper] Request blocked by policy {rule} ({detectors}). Ref {request_id}."
	}
	detectors := strings.Join(req.Detectors, ", ")
	if detectors == "" {
		detectors = "policy"
	}
	r := strings.NewReplacer("{rule}", req.Rule, "{detectors}", detectors, "{request_id}", req.RequestID)
	return r.Replace(tmpl)
}

// Family identifies which response shape to produce.
type Family string

// Response families.
const (
	FamilyOpenAIChat        Family = "openai_chat"
	FamilyOpenAICompletions Family = "openai_completions"
	FamilyOpenAIResponses   Family = "openai_responses"
	FamilyCopilotInline     Family = "copilot_inline"
	FamilyAnthropic         Family = "anthropic"
	FamilyGemini            Family = "gemini"
	FamilyOllamaChat        Family = "ollama_chat"
	FamilyOllamaGenerate    Family = "ollama_generate"
	FamilyGenericError      Family = "generic" // no sensible synthetic shape; always rejects
)

// FamilyFor picks the response family from the extractor and path.
func FamilyFor(extractor, path string) Family {
	switch strings.ToLower(extractor) {
	case "copilot":
		if parser.IsInlineCompletionPath(path) {
			return FamilyCopilotInline
		}
		return openAIFamily(path)
	case "openai":
		return openAIFamily(path)
	case "anthropic":
		return FamilyAnthropic
	case "gemini":
		return FamilyGemini
	case "ollama":
		switch {
		case strings.HasPrefix(path, "/v1/"):
			return openAIFamily(path)
		case strings.HasSuffix(path, "/api/generate"):
			return FamilyOllamaGenerate
		case strings.HasSuffix(path, "/api/chat"):
			return FamilyOllamaChat
		default:
			return FamilyGenericError
		}
	default:
		return FamilyOpenAIChat
	}
}

func openAIFamily(path string) Family {
	switch {
	case strings.HasSuffix(path, "/chat/completions"):
		return FamilyOpenAIChat
	case strings.HasSuffix(path, "/completions"):
		return FamilyOpenAICompletions
	case strings.HasSuffix(path, "/responses"):
		return FamilyOpenAIResponses
	case strings.HasSuffix(path, "/embeddings"), strings.HasSuffix(path, "/moderations"):
		return FamilyGenericError
	default:
		return FamilyOpenAIChat
	}
}

// Respond writes the block response for req.
func Respond(w http.ResponseWriter, req Request) {
	w.Header().Set(BlockedHeader, req.Rule)
	w.Header().Set("Cache-Control", "no-store")
	fam := FamilyFor(req.Extractor, req.Path)
	if req.BlockMode == config.BlockModeSynthetic && fam != FamilyGenericError {
		writeSynthetic(w, fam, req)
		return
	}
	writeReject(w, fam, req)
}

// writeReject emits HTTP 403 in the service's native error format.
func writeReject(w http.ResponseWriter, fam Family, req Request) {
	var body any
	switch fam {
	case FamilyAnthropic:
		body = map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "permission_error",
				"message": req.Message,
			},
			"request_id": req.RequestID,
		}
	case FamilyGemini:
		body = map[string]any{
			"error": map[string]any{
				"code":    http.StatusForbidden,
				"message": req.Message,
				"status":  "PERMISSION_DENIED",
			},
		}
	case FamilyOllamaChat, FamilyOllamaGenerate:
		body = map[string]any{"error": req.Message}
	default:
		body = map[string]any{
			"error": map[string]any{
				"message": req.Message,
				"type":    "aigatekeeper_policy_violation",
				"code":    "dlp_blocked",
				"param":   nil,
				"rule":    req.Rule,
			},
		}
	}
	writeJSON(w, http.StatusForbidden, body)
}

func writeSynthetic(w http.ResponseWriter, fam Family, req Request) {
	now := time.Now().Unix()
	id := "aigk-" + req.RequestID
	model := req.Model
	if model == "" {
		model = "aigatekeeper"
	}
	switch fam {
	case FamilyOpenAIChat:
		if req.Stream {
			s := newSSE(w)
			s.data(map[string]any{"id": id, "object": "chat.completion.chunk", "created": now, "model": model,
				"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant", "content": ""}, "finish_reason": nil}}})
			s.data(map[string]any{"id": id, "object": "chat.completion.chunk", "created": now, "model": model,
				"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": req.Message}, "finish_reason": nil}}})
			s.data(map[string]any{"id": id, "object": "chat.completion.chunk", "created": now, "model": model,
				"choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}}})
			s.done()
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id": id, "object": "chat.completion", "created": now, "model": model,
			"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": req.Message}, "finish_reason": "stop"}},
			"usage":   zeroUsage(),
		})

	case FamilyOpenAICompletions, FamilyCopilotInline:
		text := req.Message
		if fam == FamilyCopilotInline {
			text = "" // never inject text into the editor; the audit trail explains the block
		}
		if req.Stream {
			s := newSSE(w)
			s.data(map[string]any{"id": id, "object": "text_completion", "created": now, "model": model,
				"choices": []any{map[string]any{"index": 0, "text": text, "finish_reason": "stop"}}})
			s.done()
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id": id, "object": "text_completion", "created": now, "model": model,
			"choices": []any{map[string]any{"index": 0, "text": text, "finish_reason": "stop"}},
			"usage":   zeroUsage(),
		})

	case FamilyOpenAIResponses:
		resp := map[string]any{
			"id": "resp_" + req.RequestID, "object": "response", "created_at": now, "status": "completed", "model": model,
			"output": []any{map[string]any{
				"id": "msg_" + req.RequestID, "type": "message", "role": "assistant", "status": "completed",
				"content": []any{map[string]any{"type": "output_text", "text": req.Message, "annotations": []any{}}},
			}},
			"usage": map[string]any{"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
		}
		if req.Stream {
			s := newSSE(w)
			s.event("response.created", map[string]any{"type": "response.created", "sequence_number": 0, "response": resp})
			s.event("response.output_text.delta", map[string]any{"type": "response.output_text.delta", "sequence_number": 1, "item_id": "msg_" + req.RequestID, "output_index": 0, "content_index": 0, "delta": req.Message})
			s.event("response.completed", map[string]any{"type": "response.completed", "sequence_number": 2, "response": resp})
			return
		}
		writeJSON(w, http.StatusOK, resp)

	case FamilyAnthropic:
		msgID := "msg_" + req.RequestID
		if req.Stream {
			s := newSSE(w)
			s.event("message_start", map[string]any{"type": "message_start", "message": map[string]any{
				"id": msgID, "type": "message", "role": "assistant", "model": model, "content": []any{},
				"stop_reason": nil, "stop_sequence": nil, "usage": map[string]any{"input_tokens": 0, "output_tokens": 0}}})
			s.event("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}})
			s.event("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": req.Message}})
			s.event("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
			s.event("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": map[string]any{"output_tokens": 0}})
			s.event("message_stop", map[string]any{"type": "message_stop"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id": msgID, "type": "message", "role": "assistant", "model": model,
			"content":     []any{map[string]any{"type": "text", "text": req.Message}},
			"stop_reason": "end_turn", "stop_sequence": nil,
			"usage": map[string]any{"input_tokens": 0, "output_tokens": 0},
		})

	case FamilyGemini:
		candidate := map[string]any{
			"candidates": []any{map[string]any{
				"content":      map[string]any{"parts": []any{map[string]any{"text": req.Message}}, "role": "model"},
				"finishReason": "STOP", "index": 0,
			}},
			"usageMetadata": map[string]any{"promptTokenCount": 0, "candidatesTokenCount": 0, "totalTokenCount": 0},
			"modelVersion":  model,
		}
		switch {
		case strings.Contains(req.Query, "alt=sse"):
			s := newSSE(w)
			s.data(candidate)
		case req.Stream:
			writeJSON(w, http.StatusOK, []any{candidate})
		default:
			writeJSON(w, http.StatusOK, candidate)
		}

	case FamilyOllamaChat, FamilyOllamaGenerate:
		body := map[string]any{
			"model": model, "created_at": time.Now().UTC().Format(time.RFC3339Nano),
			"done": true, "done_reason": "stop",
			"total_duration": 0, "load_duration": 0, "prompt_eval_count": 0, "eval_count": 0,
		}
		if fam == FamilyOllamaChat {
			body["message"] = map[string]any{"role": "assistant", "content": req.Message}
		} else {
			body["response"] = req.Message
		}
		if req.Stream {
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(body)
			return
		}
		writeJSON(w, http.StatusOK, body)

	default:
		writeReject(w, fam, req)
	}
}

func zeroUsage() map[string]any {
	return map[string]any{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// sse writes server-sent events and flushes after each one.
type sse struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func newSSE(w http.ResponseWriter) *sse {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	f, _ := w.(http.Flusher)
	return &sse{w: w, flusher: f}
}

func (s *sse) data(v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(s.w, "data: %s\n\n", b)
	s.flush()
}

func (s *sse) event(name string, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", name, b)
	s.flush()
}

func (s *sse) done() {
	fmt.Fprint(s.w, "data: [DONE]\n\n")
	s.flush()
}

func (s *sse) flush() {
	if s.flusher != nil {
		s.flusher.Flush()
	}
}
