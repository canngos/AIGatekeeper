package parser

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Ollama handles the native API (/api/chat, /api/generate, /api/embed) and
// delegates its OpenAI-compatible /v1 routes to the OpenAI extractor.
// Note that Ollama streams by default: "stream" is true unless set false.
type Ollama struct{}

// Name implements Extractor.
func (Ollama) Name() string { return "ollama" }

type ollamaRequest struct {
	Model    string `json:"model"`
	Stream   *bool  `json:"stream"`
	Prompt   string `json:"prompt"`
	Suffix   string `json:"suffix"`
	System   string `json:"system"`
	Template string `json:"template"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	Input json.RawMessage `json:"input"` // /api/embed: string | []string
	Tools []struct {
		Function struct {
			Description string `json:"description"`
		} `json:"function"`
	} `json:"tools"`
}

// Extract implements Extractor.
func (o Ollama) Extract(req Request) (*Extraction, error) {
	if strings.HasPrefix(req.Path, "/v1/") {
		ex, err := OpenAI{}.Extract(req)
		if ex != nil {
			ex.Extractor = o.Name()
		}
		return ex, err
	}
	if !looksLikeJSON(req.Body) {
		return nil, ErrNotJSON
	}
	var body ollamaRequest
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return nil, ErrNotJSON
	}
	ex := &Extraction{Extractor: o.Name(), Model: body.Model, Stream: body.Stream == nil || *body.Stream}
	ex.add("/system", RoleSystem, body.System)
	ex.add("/template", RoleSystem, body.Template)
	ex.add("/prompt", RolePrompt, body.Prompt)
	ex.add("/suffix", RoleSuffix, body.Suffix)
	for i, m := range body.Messages {
		ex.add("/messages/"+strconv.Itoa(i)+"/content", normalizeRole(m.Role), m.Content)
	}
	if len(body.Input) > 0 {
		appendStringOrList(ex, "/input", RoleUser, body.Input)
		ex.Stream = false
	}
	for i, t := range body.Tools {
		ex.add("/tools/"+strconv.Itoa(i)+"/function/description", RoleTool, t.Function.Description)
	}
	if body.Prompt == "" && len(body.Messages) == 0 && len(body.Input) == 0 {
		return ex, ErrUnsupportedShape
	}
	return ex, nil
}
