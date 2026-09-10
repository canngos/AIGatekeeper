package parser

import (
	"encoding/json"
	"strconv"
)

// Anthropic handles the Messages API (POST /v1/messages): "system" is a
// string or text blocks; each message's "content" is a string or an array of
// blocks (text, image, document, tool_use, tool_result, thinking).
type Anthropic struct{}

// Name implements Extractor.
func (Anthropic) Name() string { return "anthropic" }

type anthropicRequest struct {
	Model    string          `json:"model"`
	Stream   bool            `json:"stream"`
	System   json.RawMessage `json:"system"`
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
	Tools []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"tools"`
}

type anthropicBlock struct {
	Type    string          `json:"type"`
	Text    string          `json:"text"`
	Input   json.RawMessage `json:"input"`   // tool_use
	Content json.RawMessage `json:"content"` // tool_result: string | blocks
}

// Extract implements Extractor.
func (a Anthropic) Extract(req Request) (*Extraction, error) {
	if !looksLikeJSON(req.Body) {
		return nil, ErrNotJSON
	}
	var body anthropicRequest
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return nil, ErrNotJSON
	}
	ex := &Extraction{Extractor: a.Name(), Model: body.Model, Stream: body.Stream}
	if len(body.System) > 0 {
		appendAnthropicContent(ex, "/system", RoleSystem, body.System)
	}
	for i, m := range body.Messages {
		appendAnthropicContent(ex, "/messages/"+strconv.Itoa(i)+"/content", normalizeRole(m.Role), m.Content)
	}
	for i, t := range body.Tools {
		ex.add("/tools/"+strconv.Itoa(i)+"/description", RoleTool, t.Description)
	}
	if len(body.Messages) == 0 && len(body.System) == 0 {
		return ex, ErrUnsupportedShape
	}
	return ex, nil
}

func appendAnthropicContent(ex *Extraction, path, role string, raw json.RawMessage) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		ex.add(path, role, s)
		return
	}
	var blocks []anthropicBlock
	if json.Unmarshal(raw, &blocks) != nil {
		return
	}
	for i, b := range blocks {
		bpath := path + "/" + strconv.Itoa(i)
		switch b.Type {
		case "text", "thinking":
			ex.add(bpath+"/text", role, b.Text)
		case "tool_use":
			if len(b.Input) > 0 {
				// Tool arguments are model-authored but may echo user data; scan
				// them as compact JSON.
				ex.add(bpath+"/input", RoleAssistant, string(compactJSON(b.Input)))
			}
		case "tool_result":
			if len(b.Content) > 0 {
				appendAnthropicContent(ex, bpath+"/content", RoleTool, b.Content)
			}
		default:
			// image, document, etc.: skip binary payloads but keep any text.
			if b.Text != "" {
				ex.add(bpath+"/text", role, b.Text)
			}
		}
	}
}

func compactJSON(raw json.RawMessage) []byte {
	var buf []byte
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	buf, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return buf
}
