// Tests for the product-authored `bash` tool definition and its required-command schema.
package provider

import (
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"

	"codemeld.dev/codemeld/internal/testsupport"
)

// BashToolDefinition carries the pinned `bash` name and a required single string
// `command` property with no additional properties — the shape the dispatch decoder
// (decodeBashCommand) expects.
func TestBashToolDefinition_NameAndSchema(t *testing.T) {
	d := BashToolDefinition()
	if d.Name != "bash" {
		t.Fatalf("Name = %q, want %q (the pinned dispatch name)", d.Name, "bash")
	}
	const wantDesc = "Run a shell command and return its output. Structured tools come first: reach for bash only when no structured tool covers the operation, such as a build, a test run, or file inspection no structured tool provides. " +
		"Issue independent operations as separate bash calls, in parallel where they do not depend on each other, instead of joining them into one command with `;`, and do not add `echo`/`printf` separator labels or exit-status wrappers such as `echo \"exit=$?\"`. " +
		"Do not append `2>/dev/null` or other output redirections to hide stderr: stderr is returned to you with the result and is usually the part worth reading, and a redirection sends a command that would otherwise run directly through an extra `sh -c` layer."
	if d.Description != wantDesc {
		t.Errorf("Description =\n%s\nwant\n%s", d.Description, wantDesc)
	}
	if got := d.Parameters["type"]; got != "object" {
		t.Fatalf("Parameters[type] = %v, want object", got)
	}
	props, ok := d.Parameters["properties"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters[properties] = %T, want map[string]any", d.Parameters["properties"])
	}
	cmd, ok := props["command"].(map[string]any)
	if !ok {
		t.Fatalf("properties[command] missing or wrong type: %T", props["command"])
	}
	if cmd["type"] != "string" {
		t.Fatalf("command.type = %v, want string", cmd["type"])
	}
	if req, ok := d.Parameters["required"].([]string); !ok || !reflect.DeepEqual(req, []string{"command"}) {
		t.Fatalf("Parameters[required] = %v, want [command]", d.Parameters["required"])
	}
	if d.Parameters["additionalProperties"] != false {
		t.Fatalf("additionalProperties = %v, want false", d.Parameters["additionalProperties"])
	}
}

// Each call returns a fresh Parameters map so a caller mutating the advertised schema
// cannot corrupt the shared product-authored definition.
func TestBashToolDefinition_ReturnsFreshSchema(t *testing.T) {
	first := BashToolDefinition()
	first.Parameters["injected"] = true
	second := BashToolDefinition()
	if _, mutated := second.Parameters["injected"]; mutated {
		t.Fatal("BashToolDefinition shares its Parameters map across calls; want a fresh copy each call")
	}
}

// SuggestFollowupToolDefinition carries the pinned `suggest_followup` name and a schema
// requiring two string properties (label, prompt) with no additional properties — the
// shape the turn loop intercepts and routes to the UI.
func TestSuggestFollowupToolDefinition_NameAndSchema(t *testing.T) {
	d := SuggestFollowupToolDefinition()
	if SuggestFollowupToolName != "suggest_followup" {
		t.Fatalf("SuggestFollowupToolName = %q, want the pinned literal suggest_followup", SuggestFollowupToolName)
	}
	if d.Name != SuggestFollowupToolName {
		t.Fatalf("Name = %q, want %q (the pinned interception name)", d.Name, SuggestFollowupToolName)
	}
	wantDesc := "Offer ONE follow-up action the user can accept next by pressing Tab. " +
		"This tool produces no visible reply, so never call it as your whole response: first answer the user's request or summarize the completed work in prose, and only then call it, at most once per turn, to offer the single action that follows. " +
		"That action must be concrete, within your advertised tools, allowed in the current mode, and safe and reversible — never a destructive or irreversible action, never on a trivial turn, and never a restatement of work already done. " +
		"What you offer is work the user may accept, not work you have performed: after a read-only diagnosis, present your findings and the fix you would make, then use this tool to offer implementing that fix, never wording it as though the fix already ran. " +
		"When you would otherwise write a prose-only offer such as \"If you want, I can ...\", call this tool instead and do not also repeat the same offer in your reply. " +
		"`label` is the short imperative the user would say to ask for it (e.g. \"Add before/after LOC deltas to each task\"); `prompt` is the full instruction text to prefill into the input."
	if d.Description != wantDesc {
		t.Errorf("Description =\n%s\nwant\n%s", d.Description, wantDesc)
	}
	if got := d.Parameters["type"]; got != "object" {
		t.Fatalf("Parameters[type] = %v, want object", got)
	}
	props, ok := d.Parameters["properties"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters[properties] = %T, want map[string]any", d.Parameters["properties"])
	}
	for _, name := range []string{"label", "prompt"} {
		p, ok := props[name].(map[string]any)
		if !ok {
			t.Fatalf("properties[%s] missing or wrong type: %T", name, props[name])
		}
		if p["type"] != "string" {
			t.Fatalf("%s.type = %v, want string", name, p["type"])
		}
	}
	if req, ok := d.Parameters["required"].([]string); !ok || !reflect.DeepEqual(req, []string{"label", "prompt"}) {
		t.Fatalf("Parameters[required] = %v, want [label prompt]", d.Parameters["required"])
	}
	if d.Parameters["additionalProperties"] != false {
		t.Fatalf("additionalProperties = %v, want false", d.Parameters["additionalProperties"])
	}
}

func TestAskUserToolDefinition_NameAndSchema(t *testing.T) {
	d := AskUserToolDefinition()
	if AskUserToolName != "ask_user" {
		t.Fatalf("AskUserToolName = %q, want the pinned literal ask_user", AskUserToolName)
	}
	if d.Name != AskUserToolName {
		t.Fatalf("Name = %q, want %q (the pinned interactive dispatch name)", d.Name, AskUserToolName)
	}
	for _, tc := range []struct {
		phrase string
		want   string
	}{
		{"required way to ask the user", "the tool is the required way to ask when it is advertised"},
		{"instead of writing the questions as prose", "prose interviews are ruled out"},
		{"Send every open question in one call", "every open question goes into one form"},
		{"never guess, infer, or pre-pick an answer", "answers are never inferred"},
		{"control or zero-width character, is refused", "displayed text must be text a terminal can show"},
		{"Set `context` whenever a reasonable person could need to know why you are asking", "context is expected for a decision the user cannot judge unaided"},
		{"Leave it out only for a choice that explains itself", "a simple question stays valid without context"},
		{`{"clarification":"..."} with no answers at all`, "the clarification result is mutually exclusive with answers"},
		{"your reply restated as `context`", "the explanation must come back as the next call's context"},
	} {
		if !strings.Contains(d.Description, tc.phrase) {
			t.Errorf("Description does not state that %s (missing %q)", tc.want, tc.phrase)
		}
	}
	if got := d.Parameters["type"]; got != "object" {
		t.Fatalf("Parameters[type] = %v, want object", got)
	}
	if req, ok := d.Parameters["required"].([]string); !ok || !reflect.DeepEqual(req, []string{"questions"}) {
		t.Fatalf("Parameters[required] = %v, want [questions]", d.Parameters["required"])
	}
	if d.Parameters["additionalProperties"] != false {
		t.Fatalf("additionalProperties = %v, want false (the decoder rejects unknown fields)", d.Parameters["additionalProperties"])
	}
	props, ok := d.Parameters["properties"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters[properties] = %T, want map[string]any", d.Parameters["properties"])
	}
	if got := slices.Sorted(maps.Keys(props)); !reflect.DeepEqual(got, []string{"context", "questions"}) {
		t.Fatalf("Parameters[properties] keys = %v, want exactly [context questions]", got)
	}
	sharedContext, ok := props["context"].(map[string]any)
	if !ok {
		t.Fatalf("properties[context] missing or wrong type: %T", props["context"])
	}
	if sharedContext["type"] != "string" {
		t.Fatalf("context.type = %v, want string", sharedContext["type"])
	}
	if sharedContext["maxLength"] != MaxAskUserContextRunes {
		t.Fatalf("context.maxLength = %v, want %d (its own bound, not the displayed-field one)", sharedContext["maxLength"], MaxAskUserContextRunes)
	}
	if MaxAskUserContextRunes <= MaxAskUserTextRunes {
		t.Fatalf("MaxAskUserContextRunes = %d, want more room than a displayed field's %d", MaxAskUserContextRunes, MaxAskUserTextRunes)
	}
	if sharedContext["pattern"] != AskUserTextPattern {
		t.Fatalf("context.pattern = %v, want %q (context is displayed text under the same character rules)", sharedContext["pattern"], AskUserTextPattern)
	}
	for _, phrase := range []string{"no line breaks or tabs", "not markdown"} {
		if got := sharedContext["description"].(string); !strings.Contains(got, phrase) {
			t.Errorf("context description = %q, want it to state %q", got, phrase)
		}
	}
	questions, ok := props["questions"].(map[string]any)
	if !ok {
		t.Fatalf("properties[questions] missing or wrong type: %T", props["questions"])
	}
	if questions["type"] != "array" {
		t.Fatalf("questions.type = %v, want array", questions["type"])
	}
	if questions["minItems"] != 1 {
		t.Fatalf("questions.minItems = %v, want 1 (an empty form is refused)", questions["minItems"])
	}
	if questions["maxItems"] != MaxAskUserQuestions {
		t.Fatalf("questions.maxItems = %v, want %d", questions["maxItems"], MaxAskUserQuestions)
	}
	item, ok := questions["items"].(map[string]any)
	if !ok {
		t.Fatalf("questions.items missing or wrong type: %T", questions["items"])
	}
	if item["type"] != "object" {
		t.Fatalf("questions.items.type = %v, want object", item["type"])
	}
	if req, ok := item["required"].([]string); !ok || !reflect.DeepEqual(req, []string{"id", "prompt", "options"}) {
		t.Fatalf("question required = %v, want [id prompt options]", item["required"])
	}
	if item["additionalProperties"] != false {
		t.Fatalf("question additionalProperties = %v, want false", item["additionalProperties"])
	}
	fields, ok := item["properties"].(map[string]any)
	if !ok {
		t.Fatalf("question properties = %T, want map[string]any", item["properties"])
	}
	wantFields := []string{"allow_custom", "id", "multi_select", "options", "prompt"}
	if got := slices.Sorted(maps.Keys(fields)); !reflect.DeepEqual(got, wantFields) {
		t.Fatalf("question properties keys = %v, want exactly %v", got, wantFields)
	}
	for name, wantType := range map[string]string{
		"id":           "string",
		"prompt":       "string",
		"options":      "array",
		"multi_select": "boolean",
		"allow_custom": "boolean",
	} {
		field, ok := fields[name].(map[string]any)
		if !ok {
			t.Fatalf("question properties[%s] missing or wrong type: %T", name, fields[name])
		}
		if field["type"] != wantType {
			t.Fatalf("%s.type = %v, want %s", name, field["type"], wantType)
		}
	}
	options := fields["options"].(map[string]any)
	if options["minItems"] != 1 {
		t.Fatalf("options.minItems = %v, want 1 (a question with nothing to choose is refused)", options["minItems"])
	}
	if options["maxItems"] != MaxAskUserOptions {
		t.Fatalf("options.maxItems = %v, want %d", options["maxItems"], MaxAskUserOptions)
	}
	if options["uniqueItems"] != true {
		t.Fatalf("options.uniqueItems = %v, want true (the decoder refuses a repeated label)", options["uniqueItems"])
	}
	label, ok := options["items"].(map[string]any)
	if !ok {
		t.Fatalf("options.items missing or wrong type: %T", options["items"])
	}
	if label["type"] != "string" || label["maxLength"] != MaxAskUserTextRunes {
		t.Fatalf("options.items = %v, want a string bounded to %d characters", label, MaxAskUserTextRunes)
	}
	for _, text := range []map[string]any{fields["id"].(map[string]any), fields["prompt"].(map[string]any), label} {
		if text["maxLength"] != MaxAskUserTextRunes {
			t.Fatalf("%v maxLength = %v, want %d", text["description"], text["maxLength"], MaxAskUserTextRunes)
		}
		if text["pattern"] != AskUserTextPattern {
			t.Fatalf("%v pattern = %v, want %q (the decoder refuses a value with nothing to show)", text["description"], text["pattern"], AskUserTextPattern)
		}
	}
	if got := fields["multi_select"].(map[string]any)["description"]; !strings.Contains(got.(string), "at most one listed option") {
		t.Errorf("multi_select description = %q, want it to state that a single-select question allows at most one listed option", got)
	}
}

// TestAskUserTextPattern_StaysLooserThanTheRenderableRule pins the advertised rule itself,
// not just its presence in the schema. internal/bootstrap asserts its decoder against the
// same shared table, which is what keeps the two layers from drifting apart again — and the
// direction of any remaining difference is what is pinned here: the schema may advertise
// text the form then refuses in band, never the reverse, which would be a value the model
// is told to send and can never get accepted.
func TestAskUserTextPattern_StaysLooserThanTheRenderableRule(t *testing.T) {
	re, err := regexp.Compile(AskUserTextPattern)
	if err != nil {
		t.Fatalf("AskUserTextPattern does not compile: %v", err)
	}
	for _, tc := range testsupport.AskUserTextCases {
		if got := re.MatchString(tc.Text); got != tc.Pattern {
			t.Errorf("AskUserTextPattern matched %q = %v, want %v", tc.Text, got, tc.Pattern)
		}
		if got := AskUserTextRenderable(tc.Text); got != tc.Valid {
			t.Errorf("AskUserTextRenderable(%q) = %v, want %v", tc.Text, got, tc.Valid)
		}
		if tc.Valid && !tc.Pattern {
			t.Errorf("%q is renderable but the advertised pattern refuses it", tc.Text)
		}
	}
}

// TestAskUserTextPattern_DivergesOnlyWhereAPatternCannotFollow states the difference between
// the two layers as a class rather than as the values a review happened to name: for every
// code point Go can put in a string, the advertised pattern and the renderable rule must
// agree, except where a JSON Schema pattern cannot follow at all. Three such places are left,
// all refused in band by the decoder — a code point Unicode has not assigned, which no fixed
// class can enumerate without going stale at the next revision; one outside the BMP, which an
// ECMA-262 engine without the `u` flag reads as surrogate code units (an astral range there
// is a range in the wrong order, and the whole pattern stops compiling); and U+0000, which
// some provider regex engines read as the end of the pattern. The
// third difference, that some grapheme must occupy a cell, is the combining-mark case in the
// shared table. A newly assigned BMP format character fails this rather than quietly
// reopening the gap.
func TestAskUserTextPattern_DivergesOnlyWhereAPatternCannotFollow(t *testing.T) {
	re, err := regexp.Compile(AskUserTextPattern)
	if err != nil {
		t.Fatalf("AskUserTextPattern does not compile: %v", err)
	}
	if strings.ContainsRune(AskUserTextPattern, 0) {
		t.Fatalf("AskUserTextPattern contains U+0000, which some provider regex engines read as the end of the pattern")
	}
	// Not unicode.C: that table is the complement of the graphic categories, so it carries
	// every unassigned code point too. The four concrete "other" categories are the assigned
	// ones.
	assigned := []*unicode.RangeTable{
		unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z,
		unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs,
	}
	loose, strict := &runeRanges{}, &runeRanges{}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue // a surrogate is not a rune a Go string can carry
		}
		// The leading "a" satisfies the one rule the pattern cannot express, so what is left
		// to compare is the character class itself.
		text := "a" + string(r)
		matched, renderable := re.MatchString(text), AskUserTextRenderable(text)
		strict.track(r, renderable && !matched)
		loose.track(r, matched && !renderable && r != 0 && r <= 0xFFFF && unicode.In(r, assigned...))
	}
	if got := strict.done(); len(got) > 0 {
		t.Errorf("the advertised pattern refuses renderable characters, so the model is told to send what it cannot: %s", strings.Join(got, " "))
	}
	if got := loose.done(); len(got) > 0 {
		t.Errorf("the advertised pattern accepts assigned characters the decoder refuses in band; add them to askUserTextBlocked: %s", strings.Join(got, " "))
	}
}

// runeRanges collapses the code points a sweep flagged into ranges, so a failure names the
// class to fix rather than printing a rune per line.
type runeRanges struct {
	out        []string
	start, end rune
	open       bool
}

func (g *runeRanges) track(r rune, flagged bool) {
	switch {
	case flagged && g.open && r == g.end+1:
		g.end = r
	case flagged:
		g.close()
		g.start, g.end, g.open = r, r, true
	default:
		g.close()
	}
}

func (g *runeRanges) close() {
	if !g.open {
		return
	}
	if g.start == g.end {
		g.out = append(g.out, fmt.Sprintf("%U", g.start))
	} else {
		g.out = append(g.out, fmt.Sprintf("%U-%U", g.start, g.end))
	}
	g.open = false
}

func (g *runeRanges) done() []string {
	g.close()
	return g.out
}

func TestAskUserTextRenderable_AcceptsTheAdvertisedMaximum(t *testing.T) {
	for name, text := range map[string]string{
		"wide":      strings.Repeat(string(rune(0x754C)), MaxAskUserTextRunes),
		"combining": strings.Repeat("e"+string(rune(0x0301)), MaxAskUserTextRunes/2),
		"ascii":     strings.Repeat("a", MaxAskUserTextRunes),
	} {
		if !AskUserTextRenderable(text) {
			t.Errorf("%s: a %d-rune value the schema advertises as valid is not renderable", name, MaxAskUserTextRunes)
		}
	}
}

func TestAskUserToolDefinition_ReturnsFreshSchema(t *testing.T) {
	first := AskUserToolDefinition()
	first.Parameters["injected"] = true
	second := AskUserToolDefinition()
	if _, mutated := second.Parameters["injected"]; mutated {
		t.Fatal("AskUserToolDefinition shares its Parameters map across calls; want a fresh copy each call")
	}
}

// Each call returns a fresh Parameters map so a caller mutating the advertised schema
// cannot corrupt the shared product-authored definition.
func TestSuggestFollowupToolDefinition_ReturnsFreshSchema(t *testing.T) {
	first := SuggestFollowupToolDefinition()
	first.Parameters["injected"] = true
	second := SuggestFollowupToolDefinition()
	if _, mutated := second.Parameters["injected"]; mutated {
		t.Fatal("SuggestFollowupToolDefinition shares its Parameters map across calls; want a fresh copy each call")
	}
}

// The accepted request is what both production dispatch and /resume replay build on, so the
// checker has to hand back exactly the text the model sent, not a normalized copy of it.
func TestDecodeAskUserRequest_ReturnsTheAcceptedCallVerbatim(t *testing.T) {
	req, err := DecodeAskUserRequest(`{"context":"Sessions are replayed on /resume.","questions":[` +
		`{"id":"storage","prompt":"Where should sessions be stored?","options":["Local disk","Object store"],"multi_select":true},` +
		`{"id":"name","prompt":"What should it be called?","options":["ask"],"allow_custom":true}]}`)

	if err != nil {
		t.Fatalf("DecodeAskUserRequest error = %v, want nil", err)
	}
	want := AskUserRequest{
		Context: "Sessions are replayed on /resume.",
		Questions: []AskUserQuestion{
			{ID: "storage", Prompt: "Where should sessions be stored?", Options: []string{"Local disk", "Object store"}, MultiSelect: true},
			{ID: "name", Prompt: "What should it be called?", Options: []string{"ask"}, AllowCustom: true},
		},
	}
	if !reflect.DeepEqual(req, want) {
		t.Errorf("request = %+v, want %+v", req, want)
	}
}

func TestDecodeAskUserRequest_AcceptsACallWithoutContext(t *testing.T) {
	req, err := DecodeAskUserRequest(`{"questions":[{"id":"storage","prompt":"Where?","options":["Local disk"]}]}`)

	if err != nil {
		t.Fatalf("DecodeAskUserRequest error = %v, want nil (context is optional)", err)
	}
	if req.Context != "" {
		t.Errorf("context = %q, want empty", req.Context)
	}
}

// encoding/json keeps the last of two members sharing a name, so without this the checker
// would validate a value the closed schema never saw and the discarded one would decide
// nothing — a call carrying an empty "questions" beside a real one still mounted a form.
func TestDecodeAskUserRequest_RefusesARepeatedMember(t *testing.T) {
	for _, tc := range []struct {
		name string
		args string
	}{
		{"questions at the root", `{"questions":[],"questions":[{"id":"a","prompt":"p","options":["x"]}]}`},
		{"context at the root", `{"context":"one","context":"two","questions":[{"id":"a","prompt":"p","options":["x"]}]}`},
		{"id in a question", `{"questions":[{"id":"a","id":"b","prompt":"p","options":["x"]}]}`},
		{"prompt in a question", `{"questions":[{"id":"a","prompt":"p","prompt":"q","options":["x"]}]}`},
		{"options in a question", `{"questions":[{"id":"a","prompt":"p","options":["x"],"options":["y"]}]}`},
		{"multi_select in a question", `{"questions":[{"id":"a","prompt":"p","options":["x"],"multi_select":false,"multi_select":true}]}`},
		{"allow_custom in a question", `{"questions":[{"id":"a","prompt":"p","options":["x"],"allow_custom":false,"allow_custom":true}]}`},
		{"a member of the second question", `{"questions":[{"id":"a","prompt":"p","options":["x"]},{"id":"b","prompt":"q","prompt":"r","options":["y"]}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeAskUserRequest(tc.args); err == nil {
				t.Fatalf("DecodeAskUserRequest(%q) error = nil, want a repeated member refused", tc.args)
			}
		})
	}
}
