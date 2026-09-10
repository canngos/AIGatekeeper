package parser

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type want struct {
	model    string
	stream   bool
	segments map[string]string // path -> text (substring match)
	absent   []string          // paths that must not appear
	count    int               // exact segment count, 0 = don't check
	roles    map[string]string // path -> role
}

func TestExtractors(t *testing.T) {
	reg := Default()
	cases := []struct {
		name      string
		extractor string
		fixture   string
		path      string
		query     string
		want      want
	}{
		{
			name: "openai chat string content", extractor: "openai", fixture: "openai_chat_string.json", path: "/v1/chat/completions",
			want: want{model: "gpt-4o", stream: true, count: 4,
				segments: map[string]string{"/messages/1/content": "wJalrXUtnFEMI", "/messages/0/content": "helpful coding"},
				roles:    map[string]string{"/messages/0/content": RoleSystem, "/messages/1/content": RoleUser, "/messages/2/content": RoleAssistant}},
		},
		{
			name: "openai chat content parts and tool calls", extractor: "openai", fixture: "openai_chat_parts.json", path: "/v1/chat/completions",
			want: want{model: "gpt-4o-mini",
				segments: map[string]string{
					"/messages/0/content/0/text":                  "What is in this image",
					"/messages/1/tool_calls/0/function/arguments": "4111 1111",
					"/messages/2/content":                         `{"result":"ok"}`,
					"/tools/0/function/description":               "Look up a customer",
				},
				absent: []string{"/messages/0/content/1/image_url/url"},
				roles:  map[string]string{"/messages/2/content": RoleTool, "/messages/1/tool_calls/0/function/arguments": RoleAssistant}},
		},
		{
			name: "openai legacy completions prompt list", extractor: "openai", fixture: "openai_completions.json", path: "/v1/completions",
			want: want{model: "gpt-3.5-turbo-instruct", count: 3,
				segments: map[string]string{"/prompt/0": "first prompt", "/prompt/1": "second prompt", "/suffix": "the end"},
				roles:    map[string]string{"/prompt/0": RolePrompt, "/suffix": RoleSuffix}},
		},
		{
			name: "openai responses api", extractor: "openai", fixture: "openai_responses.json", path: "/v1/responses",
			want: want{model: "gpt-4.1", count: 3,
				segments: map[string]string{"/instructions": "Answer briefly", "/input/0/content/0/text": "incident report", "/input/1/output": "hunter2"},
				roles:    map[string]string{"/instructions": RoleSystem, "/input/1/output": RoleTool}},
		},
		{
			name: "openai embeddings", extractor: "openai", fixture: "openai_embeddings.json", path: "/v1/embeddings",
			want: want{model: "text-embedding-3-small", count: 2, segments: map[string]string{"/input/0": "embed me", "/input/1": "and me"}},
		},
		{
			name: "copilot inline completion", extractor: "copilot", fixture: "copilot_inline.json", path: "/v1/engines/gpt-4o-copilot/completions",
			want: want{model: "gpt-4o-copilot", stream: true, count: 2,
				segments: map[string]string{"/prompt": "AKIAIOSFODNN7EXAMPLE", "/suffix": "return client"},
				roles:    map[string]string{"/prompt": RolePrompt, "/suffix": RoleSuffix}},
		},
		{
			name: "copilot chat delegates to openai", extractor: "copilot", fixture: "copilot_chat.json", path: "/chat/completions",
			want: want{model: "gpt-4o", stream: true, count: 2, segments: map[string]string{"/messages/1/content": "Refactor"}},
		},
		{
			name: "anthropic string system", extractor: "anthropic", fixture: "anthropic_string_system.json", path: "/v1/messages",
			want: want{model: "claude-sonnet-5", stream: true, count: 2,
				segments: map[string]string{"/system": "terse", "/messages/0/content": "Hello there"},
				roles:    map[string]string{"/system": RoleSystem, "/messages/0/content": RoleUser}},
		},
		{
			name: "anthropic content blocks with tools", extractor: "anthropic", fixture: "anthropic_blocks.json", path: "/v1/messages",
			want: want{model: "claude-opus-5",
				segments: map[string]string{
					"/system/0/text":                       "System block one",
					"/system/1/text":                       "System block two",
					"/messages/0/content/0/text":           "Look at this document",
					"/messages/1/content/0/input":          "123-45-6789",
					"/messages/2/content/0/content/1/text": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
					"/tools/0/description":                 "Fetch a user",
				},
				absent: []string{"/messages/0/content/1/source/data"},
				roles:  map[string]string{"/messages/1/content/0/input": RoleAssistant, "/messages/2/content/0/content/0/text": RoleTool}},
		},
		{
			name: "gemini generate content", extractor: "gemini", fixture: "gemini_generate.json", path: "/v1beta/models/gemini-2.5-pro:generateContent",
			want: want{model: "gemini-2.5-pro", stream: false,
				segments: map[string]string{
					"/systemInstruction/parts/0/text":             "You are Gemini",
					"/contents/0/parts/0/text":                    "Translate this",
					"/contents/1/parts/0/text":                    "Sure",
					"/contents/2/parts/0/functionResponse":        "xoxb-",
					"/tools/0/functionDeclarations/0/description": "Looks things up",
				},
				absent: []string{"/contents/0/parts/1/inline_data/data"},
				roles:  map[string]string{"/contents/1/parts/0/text": RoleAssistant, "/contents/0/parts/0/text": RoleUser}},
		},
		{
			name: "gemini streaming via path and alt=sse", extractor: "gemini", fixture: "gemini_generate.json", path: "/v1beta/models/gemini-2.5-flash:streamGenerateContent", query: "alt=sse",
			want: want{model: "gemini-2.5-flash", stream: true},
		},
		{
			name: "ollama chat streams by default", extractor: "ollama", fixture: "ollama_chat.json", path: "/api/chat",
			want: want{model: "llama3.1", stream: true, count: 2, segments: map[string]string{"/messages/1/content": "2+2"}},
		},
		{
			name: "ollama generate with stream false", extractor: "ollama", fixture: "ollama_generate.json", path: "/api/generate",
			want: want{model: "codellama:7b", stream: false, count: 3,
				segments: map[string]string{"/prompt": "fibonacci", "/suffix": "return result", "/system": "Complete code"},
				absent:   []string{"/images/0"}},
		},
		{
			name: "ollama v1 routes use openai shape", extractor: "ollama", fixture: "openai_chat_string.json", path: "/v1/chat/completions",
			want: want{model: "gpt-4o", stream: true, count: 4},
		},
		{
			name: "generic walker on unknown shape", extractor: "generic", fixture: "generic_unknown.json", path: "/x",
			want: want{model: "custom-1", stream: true,
				segments: map[string]string{
					"/query":                   "find the config",
					"/context/files/0/content": "SECRET_KEY",
					"/context/files/0/name":    "settings.py",
					"/context/a~1b~0c":         "escaped key",
					"/model":                   "custom-1",
				}},
		},
		{
			name: "generic skips opaque binary strings", extractor: "generic", fixture: "generic_opaque.json", path: "/x",
			want: want{count: 1, segments: map[string]string{"/text": "short prose"}, absent: []string{"/image", "/uri"}},
		},
		{
			name: "unknown service falls back to generic", extractor: "openai", fixture: "generic_unknown.json", path: "/x",
			want: want{model: "custom-1", stream: true, segments: map[string]string{"/query": "find the config"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ex, err := reg.Extract(tc.extractor, Request{Method: "POST", Path: tc.path, Query: tc.query, Body: fixture(t, tc.fixture)})
			if err != nil {
				t.Fatalf("extract: %v", err)
			}
			if ex.Model != tc.want.model {
				t.Errorf("model = %q, want %q", ex.Model, tc.want.model)
			}
			if ex.Stream != tc.want.stream {
				t.Errorf("stream = %v, want %v", ex.Stream, tc.want.stream)
			}
			if tc.want.count > 0 && len(ex.Segments) != tc.want.count {
				t.Errorf("segment count = %d, want %d: %+v", len(ex.Segments), tc.want.count, ex.Segments)
			}
			byPath := map[string]Segment{}
			for _, s := range ex.Segments {
				byPath[s.Path] = s
			}
			for path, sub := range tc.want.segments {
				s, ok := byPath[path]
				if !ok {
					t.Errorf("missing segment %s; have %v", path, paths(ex.Segments))
					continue
				}
				if !strings.Contains(s.Text, sub) {
					t.Errorf("segment %s = %q, want substring %q", path, s.Text, sub)
				}
			}
			for _, path := range tc.want.absent {
				if _, ok := byPath[path]; ok {
					t.Errorf("segment %s should have been skipped", path)
				}
			}
			for path, role := range tc.want.roles {
				if s, ok := byPath[path]; ok && s.Role != role {
					t.Errorf("segment %s role = %q, want %q", path, s.Role, role)
				}
			}
		})
	}
}

func paths(segs []Segment) []string {
	out := make([]string, len(segs))
	for i, s := range segs {
		out[i] = s.Path
	}
	return out
}

func TestInvalidJSON(t *testing.T) {
	reg := Default()
	for _, body := range []string{"", "not json", "{\"a\":", "{}trailing", "<xml/>"} {
		for _, name := range reg.Names() {
			ex, err := reg.Extract(name, Request{Method: "POST", Path: "/v1/chat/completions", Body: []byte(body)})
			if err == nil {
				t.Errorf("%s: expected error for body %q, got %+v", name, body, ex)
			}
			if body != "" && body != "not json" && body != "<xml/>" && !errors.Is(err, ErrNotJSON) {
				t.Errorf("%s: expected ErrNotJSON for %q, got %v", name, body, err)
			}
		}
	}
}

func TestEmptyObjectYieldsNoSegments(t *testing.T) {
	ex, err := Default().Extract("anthropic", Request{Method: "POST", Path: "/v1/messages", Body: []byte(`{"model":"x","max_tokens":5}`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.Segments) != 1 || ex.Segments[0].Path != "/model" {
		t.Fatalf("expected only the model string via generic fallback, got %+v", ex.Segments)
	}
	if ex.Model != "x" {
		t.Errorf("model hint lost: %q", ex.Model)
	}
}

func TestWalkStringsPointerEscaping(t *testing.T) {
	var got []string
	err := WalkStrings([]byte(`{"a/b":{"c~d":"v","list":["x",{"k":"y"}]}}`), func(p, s string) { got = append(got, p+"="+s) })
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/a~1b/c~0d=v", "/a~1b/list/0=x", "/a~1b/list/1/k=y"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestIsJSONContentType(t *testing.T) {
	for ct, want := range map[string]bool{
		"application/json":                  true,
		"application/json; charset=utf-8":   true,
		"Application/JSON":                  true,
		"application/problem+json":          true,
		"text/plain":                        false,
		"":                                  false,
		"application/x-www-form-urlencoded": false,
	} {
		if IsJSONContentType(ct) != want {
			t.Errorf("%q: want %v", ct, want)
		}
	}
}

func TestRegistryNames(t *testing.T) {
	names := Default().Names()
	want := "anthropic,copilot,gemini,generic,ollama,openai"
	if strings.Join(names, ",") != want {
		t.Fatalf("names = %v", names)
	}
}
