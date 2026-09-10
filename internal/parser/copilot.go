package parser

import (
	"encoding/json"
	"regexp"
)

// Copilot handles GitHub Copilot traffic. Chat and agent requests to
// api.githubcopilot.com use the OpenAI chat shape; inline code suggestions
// go to copilot-proxy.githubusercontent.com/v1/engines/<engine>/completions
// with a prompt/suffix body and an SSE legacy-completions response.
type Copilot struct{}

// Name implements Extractor.
func (Copilot) Name() string { return "copilot" }

var copilotInlinePathRe = regexp.MustCompile(`^/v1/engines/([^/]+)/completions$`)

type copilotInlineRequest struct {
	Prompt string `json:"prompt"`
	Suffix string `json:"suffix"`
	Stream bool   `json:"stream"`
	Extra  struct {
		Language string `json:"language"`
	} `json:"extra"`
}

// Extract implements Extractor.
func (c Copilot) Extract(req Request) (*Extraction, error) {
	if !looksLikeJSON(req.Body) {
		return nil, ErrNotJSON
	}
	if m := copilotInlinePathRe.FindStringSubmatch(req.Path); m != nil {
		var body copilotInlineRequest
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return nil, ErrNotJSON
		}
		ex := &Extraction{Extractor: c.Name(), Model: m[1], Stream: body.Stream}
		ex.add("/prompt", RolePrompt, body.Prompt)
		ex.add("/suffix", RoleSuffix, body.Suffix)
		return ex, nil
	}
	ex, err := OpenAI{}.Extract(req)
	if ex != nil {
		ex.Extractor = c.Name()
	}
	return ex, err
}

// IsInlineCompletionPath reports whether path is a Copilot inline
// completion endpoint (used by the action package to pick the response shape).
func IsInlineCompletionPath(path string) bool {
	return copilotInlinePathRe.MatchString(path)
}
