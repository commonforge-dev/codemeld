// Extracts a one-line human-readable message from a provider HTTP-error body for the TUI notice.
package provider

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"codemeld.dev/codemeld/internal/fserrors"
)

// FriendlyHTTPMessage returns the one-line notice text for a provider non-2xx
// response. It leads with the synthetic prefix "provider <name> returned HTTP
// <status>" and, when the body carries a usable human sentence, appends it after
// ": " — preferring error.metadata.raw (the provider-specific sentence) over the
// often-generic error.message. A non-JSON body, an empty body, or one with no
// usable field yields the bare prefix with no JSON shown. The extracted
// text has its newlines/tabs collapsed to single spaces so the body's own control
// characters cannot break the one-line notice.
//
// This extractor copies a sentence out of body verbatim and never redacts: for a
// credentialed provider (the OpenAI ChatGPT adapter) the caller must pass a body
// already scrubbed via redactCredentials, since the *HTTPError.Body it reads is
// stored pre-redacted. Keep new extraction logic body-derived so it
// cannot reintroduce a token or account-derived value the body no longer contains.
func FriendlyHTTPMessage(name string, status int, body string) string {
	prefix := fmt.Sprintf("provider %s returned HTTP %d", name, status)
	if msg := extractFriendlyMessage(body); msg != "" {
		return prefix + ": " + msg
	}
	return prefix
}

func FriendlyRoutingExhaustionMessage(name string, e *RoutingExhaustionError) string {
	friendly := FriendlyHTTPMessage(name, e.HTTP.Status, e.HTTP.Body)
	model := collapseLine(e.Model)
	var filters, remedies []string
	if e.MaxPrice.HasPrompt || e.MaxPrice.HasCompletion {
		f := "max_price"
		if e.MaxPrice.HasPrompt {
			f += " prompt " + strconv.FormatFloat(e.MaxPrice.Prompt, 'f', -1, 64)
		}
		if e.MaxPrice.HasCompletion {
			f += " completion " + strconv.FormatFloat(e.MaxPrice.Completion, 'f', -1, 64)
		}
		filters = append(filters, f)
	}
	if e.DataCollectionDeny {
		filters = append(filters, "data_collection deny")
	}
	if e.RequireParameters {
		filters = append(filters, "require_parameters true")
	}
	if len(e.Quantization.Levels) > 0 {
		levels := make([]string, len(e.Quantization.Levels))
		for i, level := range e.Quantization.Levels {
			levels[i] = collapseLine(level)
		}
		filters = append(filters, "quantizations "+collapseLine(e.Quantization.Mode)+" ["+strings.Join(levels, " ")+"] (each tried in order)")
	}
	if len(filters) > 0 {
		remedies = append(remedies, "Change provider.openrouter.routing to let a provider through.")
	}
	if len(e.Ignore) > 0 {
		ids := make([]string, len(e.Ignore))
		for i, id := range e.Ignore {
			ids[i] = collapseLine(id)
		}
		filters = append(filters, "ignore ["+strings.Join(ids, " ")+"]")
		remedies = append(remedies, "The ignore list is session-only; start a new session to clear it.")
	}
	if len(filters) == 0 {
		return fmt.Sprintf("%s (model %s; codemeld sent no routing filters). Check the provider settings in your OpenRouter account.", friendly, model)
	}
	return fmt.Sprintf("%s (model %s; filters sent: %s). %s", friendly, model, strings.Join(filters, ", "), strings.Join(remedies, " "))
}

// extractFriendlyMessage parses body as a JSON object and returns the first
// present, non-empty string of error.metadata.raw then error.message, collapsed
// to a single line. It is deliberately forgiving: a non-object body, a missing
// error object, or non-string fields yield "" so the caller falls back to the
// synthetic prefix rather than surfacing struct keys or a generic placeholder.
func extractFriendlyMessage(body string) string {
	var root map[string]any
	if err := json.Unmarshal([]byte(body), &root); err != nil {
		return ""
	}
	errObj, ok := root["error"].(map[string]any)
	if !ok {
		return ""
	}
	if meta, ok := errObj["metadata"].(map[string]any); ok {
		if raw, ok := meta["raw"].(string); ok {
			if line := collapseLine(raw); line != "" {
				return line
			}
		}
	}
	if msg, ok := errObj["message"].(string); ok {
		if line := collapseLine(msg); line != "" {
			return line
		}
	}
	return ""
}

// collapseLine collapses a body field's control characters to single spaces
// (reusing the same one-line normalization other notices use) and trims the
// surrounding whitespace a leading/trailing newline would leave behind.
func collapseLine(s string) string {
	return strings.TrimSpace(fserrors.CollapseControls(s))
}
