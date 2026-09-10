package parser

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Generic walks any JSON document and collects every string leaf with its
// JSON pointer path. It is the fallback for unknown services and shapes.
type Generic struct{}

// Name implements Extractor.
func (Generic) Name() string { return "generic" }

// maxOpaqueString is the length above which a string that looks like
// base64/hex (an image, a file) is skipped instead of scanned.
const maxOpaqueString = 1024

var opaqueRe = regexp.MustCompile(`^[A-Za-z0-9+/=_-]+$`)

// Extract implements Extractor.
func (g Generic) Extract(req Request) (*Extraction, error) {
	if !looksLikeJSON(req.Body) {
		return nil, ErrNotJSON
	}
	ex := &Extraction{Extractor: g.Name()}
	err := WalkStrings(req.Body, func(path, s string) {
		if isOpaque(s) {
			return
		}
		ex.Segments = append(ex.Segments, Segment{Path: path, Role: roleFromPath(path), Text: s})
	})
	if err != nil {
		return nil, ErrNotJSON
	}
	ex.Model = firstString(req.Body, "model")
	ex.Stream = firstBool(req.Body, "stream")
	return ex, nil
}

// isOpaque reports whether s is probably binary content (base64, hex) rather
// than prose or code.
func isOpaque(s string) bool {
	if len(s) < maxOpaqueString {
		return false
	}
	if strings.HasPrefix(s, "data:") {
		return true
	}
	return opaqueRe.MatchString(s)
}

// roleFromPath infers a role for common message layouts so findings inside
// assistant turns can be weighted differently.
func roleFromPath(path string) string {
	switch {
	case strings.HasPrefix(path, "/system"):
		return RoleSystem
	case strings.HasPrefix(path, "/prompt"):
		return RolePrompt
	case strings.HasPrefix(path, "/suffix"):
		return RoleSuffix
	}
	return ""
}

// WalkStrings streams through a JSON document and calls fn for every string
// value with its RFC 6901 JSON pointer. Object keys are not reported.
func WalkStrings(body []byte, fn func(path, s string)) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if err := walkValue(dec, tok, "", fn); err != nil {
		return err
	}
	// Reject trailing garbage so "{}xyz" is not treated as valid.
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return ErrNotJSON
		}
		return err
	}
	return nil
}

func walkValue(dec *json.Decoder, tok json.Token, path string, fn func(string, string)) error {
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				key, _ := keyTok.(string)
				valTok, err := dec.Token()
				if err != nil {
					return err
				}
				if err := walkValue(dec, valTok, path+"/"+escapePointer(key), fn); err != nil {
					return err
				}
			}
			_, err := dec.Token() // consume '}'
			return err
		case '[':
			for i := 0; dec.More(); i++ {
				valTok, err := dec.Token()
				if err != nil {
					return err
				}
				if err := walkValue(dec, valTok, path+"/"+strconv.Itoa(i), fn); err != nil {
					return err
				}
			}
			_, err := dec.Token() // consume ']'
			return err
		}
	case string:
		if v != "" {
			fn(path, v)
		}
	}
	return nil
}

func escapePointer(key string) string {
	key = strings.ReplaceAll(key, "~", "~0")
	return strings.ReplaceAll(key, "/", "~1")
}

// firstString returns the top-level string field named key, if any.
func firstString(body []byte, key string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	var s string
	if raw, ok := m[key]; ok && json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

// firstBool returns the top-level boolean field named key, if any.
func firstBool(body []byte, key string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return false
	}
	var b bool
	if raw, ok := m[key]; ok && json.Unmarshal(raw, &b) == nil {
		return b
	}
	return false
}
