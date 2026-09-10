package parser

import (
	"encoding/json"
	"strconv"
)

// OpenAI handles the OpenAI-compatible API family: chat completions,
// legacy completions, the Responses API and embeddings. Azure OpenAI,
// OpenRouter, Groq, vLLM, LM Studio and Ollama's /v1 routes share it.
type OpenAI struct{}

// Name implements Extractor.
func (OpenAI) Name() string { return "openai" }

type openAIRequest struct {
	Model        string           `json:"model"`
	Stream       bool             `json:"stream"`
	Messages     []openAIMessage  `json:"messages"`
	Prompt       json.RawMessage  `json:"prompt"`       // legacy completions: string | []string
	Suffix       string           `json:"suffix"`       // legacy completions (Copilot inline)
	Input        json.RawMessage  `json:"input"`        // responses API / embeddings
	Instructions string           `json:"instructions"` // responses API system prompt
	Tools        []openAITool     `json:"tools"`
	Functions    []openAIFunction `json:"functions"` // deprecated function-calling shape
}

type openAIMessage struct {
	Role      string           `json:"role"`
	Content   json.RawMessage  `json:"content"`
	Name      string           `json:"name"`
	ToolCalls []openAIToolCall `json:"tool_calls"`
}

type openAIToolCall struct {
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type openAITool struct {
	Type     string         `json:"type"`
	Function openAIFunction `json:"function"`
}

type openAIFunction struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Extract implements Extractor.
func (o OpenAI) Extract(req Request) (*Extraction, error) {
	if !looksLikeJSON(req.Body) {
		return nil, ErrNotJSON
	}
	var body openAIRequest
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return nil, ErrNotJSON
	}
	ex := &Extraction{Extractor: o.Name(), Model: body.Model, Stream: body.Stream}

	for i, m := range body.Messages {
		base := "/messages/" + strconv.Itoa(i)
		role := normalizeRole(m.Role)
		appendContent(ex, base+"/content", role, m.Content)
		for j, tc := range m.ToolCalls {
			if tc.Function.Arguments != "" {
				ex.add(base+"/tool_calls/"+strconv.Itoa(j)+"/function/arguments", RoleAssistant, tc.Function.Arguments)
			}
		}
	}
	if len(body.Prompt) > 0 {
		appendStringOrList(ex, "/prompt", RolePrompt, body.Prompt)
	}
	if body.Suffix != "" {
		ex.add("/suffix", RoleSuffix, body.Suffix)
	}
	if body.Instructions != "" {
		ex.add("/instructions", RoleSystem, body.Instructions)
	}
	if len(body.Input) > 0 {
		appendResponsesInput(ex, "/input", body.Input)
	}
	for i, t := range body.Tools {
		if t.Function.Description != "" {
			ex.add("/tools/"+strconv.Itoa(i)+"/function/description", RoleTool, t.Function.Description)
		}
	}
	for i, f := range body.Functions {
		if f.Description != "" {
			ex.add("/functions/"+strconv.Itoa(i)+"/description", RoleTool, f.Description)
		}
	}

	if len(ex.Segments) == 0 && len(body.Messages) == 0 && len(body.Prompt) == 0 && len(body.Input) == 0 {
		return ex, ErrUnsupportedShape
	}
	return ex, nil
}

func (e *Extraction) add(path, role, text string) {
	if text == "" {
		return
	}
	e.Segments = append(e.Segments, Segment{Path: path, Role: role, Text: text})
}

func normalizeRole(r string) string {
	switch r {
	case "system", "developer":
		return RoleSystem
	case "user":
		return RoleUser
	case "assistant", "model":
		return RoleAssistant
	case "tool", "function":
		return RoleTool
	}
	return r
}

// appendContent handles OpenAI-style content: a string, or an array of
// parts where text parts carry {"type":"text"|"input_text"|"output_text",
// "text": "..."}; image/audio parts are skipped.
func appendContent(ex *Extraction, path, role string, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		ex.add(path, role, s)
		return
	}
	var parts []struct {
		Type    string          `json:"type"`
		Text    string          `json:"text"`
		Refusal string          `json:"refusal"`
		Content json.RawMessage `json:"content"` // nested (rare)
	}
	if json.Unmarshal(raw, &parts) == nil {
		for i, p := range parts {
			ppath := path + "/" + strconv.Itoa(i)
			switch {
			case p.Text != "":
				ex.add(ppath+"/text", role, p.Text)
			case p.Refusal != "":
				ex.add(ppath+"/refusal", role, p.Refusal)
			case len(p.Content) > 0:
				appendContent(ex, ppath+"/content", role, p.Content)
			}
		}
		return
	}
	// Unknown structure: harvest any strings inside it.
	_ = WalkStrings(raw, func(sub, s string) {
		if !isOpaque(s) {
			ex.add(path+sub, role, s)
		}
	})
}

// appendStringOrList handles "prompt": "..." or "prompt": ["...", "..."].
func appendStringOrList(ex *Extraction, path, role string, raw json.RawMessage) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		ex.add(path, role, s)
		return
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		for i, item := range list {
			ex.add(path+"/"+strconv.Itoa(i), role, item)
		}
		return
	}
	_ = WalkStrings(raw, func(sub, s string) {
		if !isOpaque(s) {
			ex.add(path+sub, role, s)
		}
	})
}

// appendResponsesInput handles the Responses API "input": string |
// [{role, content: string | [{type, text}]}] and embeddings' string lists.
func appendResponsesInput(ex *Extraction, path string, raw json.RawMessage) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		ex.add(path, RoleUser, s)
		return
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return
	}
	for i, item := range items {
		ipath := path + "/" + strconv.Itoa(i)
		var str string
		if json.Unmarshal(item, &str) == nil {
			ex.add(ipath, RoleUser, str)
			continue
		}
		var msg struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
			Type    string          `json:"type"`
			Output  string          `json:"output"` // function_call_output
		}
		if json.Unmarshal(item, &msg) == nil {
			role := normalizeRole(msg.Role)
			if role == "" {
				role = RoleUser
			}
			appendContent(ex, ipath+"/content", role, msg.Content)
			if msg.Output != "" {
				ex.add(ipath+"/output", RoleTool, msg.Output)
			}
		}
	}
}
