// Package parser isolates the prompt-bearing text inside GenAI request
// bodies so the DLP engine scans only what the developer typed (and the
// context their tool attached), not the whole JSON envelope.
package parser

import (
	"bytes"
	"errors"
	"net/http"
	"sort"
	"strings"
)

// Roles attached to segments.
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
	RolePrompt    = "prompt"
	RoleSuffix    = "suffix"
)

// ErrUnsupportedShape signals that a service-specific extractor did not
// recognise the body; callers fall back to the Generic extractor.
var ErrUnsupportedShape = errors.New("request body shape not recognised")

// ErrNotJSON signals that the body is not valid JSON at all.
var ErrNotJSON = errors.New("request body is not valid JSON")

// Request is the subset of the HTTP request an extractor may consult.
type Request struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   []byte
}

// Segment is one piece of extracted text with its JSON pointer location.
type Segment struct {
	Path string `json:"path"`
	Role string `json:"role,omitempty"`
	Text string `json:"text"`
}

// Extraction is the result of parsing one request.
type Extraction struct {
	Extractor string    `json:"extractor"`
	Model     string    `json:"model,omitempty"`
	Stream    bool      `json:"stream"`
	Segments  []Segment `json:"segments"`
}

// TextLen returns the total number of bytes across all segments.
func (e *Extraction) TextLen() int {
	n := 0
	for _, s := range e.Segments {
		n += len(s.Text)
	}
	return n
}

// Extractor turns a request into text segments.
type Extractor interface {
	// Name is the identifier used in configuration (services[].extractor).
	Name() string
	// Extract parses req.Body. It returns ErrUnsupportedShape when the body
	// is valid JSON but not a shape it knows, and ErrNotJSON for non-JSON.
	Extract(req Request) (*Extraction, error)
}

// Registry maps extractor names to implementations.
type Registry map[string]Extractor

// Default returns the built-in extractors.
func Default() Registry {
	r := Registry{}
	for _, e := range []Extractor{
		Generic{},
		OpenAI{},
		Copilot{},
		Anthropic{},
		Gemini{},
		Ollama{},
	} {
		r[e.Name()] = e
	}
	return r
}

// Get returns the named extractor.
func (r Registry) Get(name string) (Extractor, bool) {
	e, ok := r[strings.ToLower(name)]
	return e, ok
}

// Names lists registered extractor names, sorted.
func (r Registry) Names() []string {
	names := make([]string, 0, len(r))
	for n := range r {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Extract runs the named extractor and falls back to Generic when the
// specific extractor does not recognise the shape or finds no text.
func (r Registry) Extract(name string, req Request) (*Extraction, error) {
	e, ok := r.Get(name)
	if !ok {
		e = Generic{}
	}
	ex, err := e.Extract(req)
	switch {
	case err == nil && len(ex.Segments) > 0:
		return ex, nil
	case err != nil && !errors.Is(err, ErrUnsupportedShape):
		return nil, err
	}
	// Unsupported shape or nothing found: try the generic walker so unknown
	// endpoints of a known service are still scanned.
	gen, gerr := Generic{}.Extract(req)
	if gerr != nil {
		return nil, gerr
	}
	if ex != nil {
		// Keep model/stream hints the specific extractor discovered.
		if gen.Model == "" {
			gen.Model = ex.Model
		}
		gen.Stream = gen.Stream || ex.Stream
	}
	gen.Extractor = e.Name() + "+generic"
	return gen, nil
}

// LooksLikeJSON reports whether body starts with a JSON object or array.
func LooksLikeJSON(body []byte) bool { return looksLikeJSON(body) }

// looksLikeJSON is a cheap pre-check before attempting to parse.
func looksLikeJSON(body []byte) bool {
	trimmed := bytes.TrimLeft(body, " \t\r\n\xef\xbb\xbf")
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

// IsJSONContentType reports whether the Content-Type denotes JSON.
func IsJSONContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	return ct == "application/json" || ct == "text/json" || strings.HasSuffix(ct, "+json")
}
