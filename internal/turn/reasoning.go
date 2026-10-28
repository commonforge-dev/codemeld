package turn

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/openai/openai-go/v3/packages/respjson"

	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/sessions"
)

type reasoningAcc struct {
	text    strings.Builder
	details []map[string]json.RawMessage
}

func (a *reasoningAcc) add(extra map[string]respjson.Field) {
	if f, ok := extra["reasoning"]; ok {
		var s string
		if json.Unmarshal([]byte(f.Raw()), &s) == nil {
			a.text.WriteString(s)
		}
	}
	f, ok := extra["reasoning_details"]
	if !ok {
		return
	}
	var frags []map[string]json.RawMessage
	if json.Unmarshal([]byte(f.Raw()), &frags) != nil {
		return
	}
	for _, frag := range frags {
		if n := len(a.details); n > 0 && sameDetailBlock(a.details[n-1], frag) {
			mergeDetail(a.details[n-1], frag)
			continue
		}
		a.details = append(a.details, frag)
	}
}

func sameDetailBlock(a, b map[string]json.RawMessage) bool {
	return bytes.Equal(a["type"], b["type"]) && bytes.Equal(a["index"], b["index"])
}

// ponytail: only text and summary are joined across fragments; a split encrypted data
// blob keeps its first fragment, revisit if a provider streams one in pieces.
func mergeDetail(dst, src map[string]json.RawMessage) {
	for k, v := range src {
		if k == "text" || k == "summary" {
			var a, b string
			_ = json.Unmarshal(dst[k], &a)
			_ = json.Unmarshal(v, &b)
			dst[k], _ = json.Marshal(a + b)
			continue
		}
		if cur, ok := dst[k]; !ok || string(cur) == "null" || string(cur) == `""` {
			dst[k] = v
		}
	}
}

func (a *reasoningAcc) record(sel model.Selection) *sessions.Reasoning {
	if a.text.Len() == 0 && len(a.details) == 0 {
		return nil
	}
	r := &sessions.Reasoning{Provider: sel.Provider, ModelID: sel.ID, Text: a.text.String()}
	if len(a.details) > 0 {
		r.Details, _ = json.Marshal(a.details)
	}
	return r
}
