package parser

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// Gemini handles generateContent / streamGenerateContent requests:
// contents[].parts[].text plus systemInstruction.parts[].text. The model
// name lives in the path (/v1beta/models/{model}:generateContent).
type Gemini struct{}

// Name implements Extractor.
func (Gemini) Name() string { return "gemini" }

var geminiPathRe = regexp.MustCompile(`/models/([^/:]+):(generateContent|streamGenerateContent|countTokens|embedContent)$`)

type geminiRequest struct {
	Contents []struct {
		Role  string       `json:"role"`
		Parts []geminiPart `json:"parts"`
	} `json:"contents"`
	SystemInstruction      *geminiContent `json:"systemInstruction"`
	SystemInstructionSnake *geminiContent `json:"system_instruction"`
	Tools                  []struct {
		FunctionDeclarations []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"functionDeclarations"`
	} `json:"tools"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text             string          `json:"text"`
	FunctionCall     json.RawMessage `json:"functionCall"`
	FunctionResponse json.RawMessage `json:"functionResponse"`
}

// Extract implements Extractor.
func (g Gemini) Extract(req Request) (*Extraction, error) {
	if !looksLikeJSON(req.Body) {
		return nil, ErrNotJSON
	}
	var body geminiRequest
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return nil, ErrNotJSON
	}
	ex := &Extraction{Extractor: g.Name()}
	if m := geminiPathRe.FindStringSubmatch(req.Path); m != nil {
		ex.Model = m[1]
		ex.Stream = m[2] == "streamGenerateContent"
	}
	if strings.Contains(req.Query, "alt=sse") {
		ex.Stream = true
	}

	sys := body.SystemInstruction
	sysPath := "/systemInstruction"
	if sys == nil && body.SystemInstructionSnake != nil {
		sys = body.SystemInstructionSnake
		sysPath = "/system_instruction"
	}
	if sys != nil {
		for i, p := range sys.Parts {
			ex.add(sysPath+"/parts/"+strconv.Itoa(i)+"/text", RoleSystem, p.Text)
		}
	}
	for i, c := range body.Contents {
		role := normalizeRole(c.Role)
		if role == "" {
			role = RoleUser
		}
		for j, p := range c.Parts {
			ppath := "/contents/" + strconv.Itoa(i) + "/parts/" + strconv.Itoa(j)
			ex.add(ppath+"/text", role, p.Text)
			if len(p.FunctionCall) > 0 {
				ex.add(ppath+"/functionCall", RoleAssistant, string(compactJSON(p.FunctionCall)))
			}
			if len(p.FunctionResponse) > 0 {
				ex.add(ppath+"/functionResponse", RoleTool, string(compactJSON(p.FunctionResponse)))
			}
		}
	}
	for i, t := range body.Tools {
		for j, f := range t.FunctionDeclarations {
			ex.add("/tools/"+strconv.Itoa(i)+"/functionDeclarations/"+strconv.Itoa(j)+"/description", RoleTool, f.Description)
		}
	}
	if len(body.Contents) == 0 && sys == nil {
		return ex, ErrUnsupportedShape
	}
	return ex, nil
}
