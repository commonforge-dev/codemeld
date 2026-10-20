// Provider-agnostic tool definitions advertised on a chat-completion request, the
// product-authored `bash` definition that lives outside the tool registry, and the strict
// checker that turns raw `ask_user` arguments into an accepted request.
package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// ToolDefinition is one advertised tool in codemeld's internal provider contract:
// a stable Name (a registry name such as `vcs_commit`, or the pinned `bash`), a
// one-line Description the model reads to choose when to call it, and Parameters —
// a JSON-Schema object in the OpenAI function-tool shape describing the call's
// arguments. It is provider-agnostic so request builders assemble it without
// importing any provider SDK; ChatCompletion maps it onto the openai-go function
// tool. A nil Parameters advertises a function with no parameters.
type ToolDefinition struct {
	Name        string
	Description string
	Parameters  map[string]any
}

// bashToolName is the pinned name the `bash` tool is advertised under. It must match
// the dispatch-routed name in internal/bootstrap (bashToolName) so a model tool call
// the model learns from this advertisement is routed to the shell path; a bootstrap
// test pins the two to the same literal.
const bashToolName = "bash"

// SuggestFollowupToolName is the pinned name of the product-authored
// `suggest_followup` tool. The turn loop matches a model tool call against this exact
// literal to intercept it (it is never dispatched, never persisted), so the
// advertised definition and the interception point share this single constant.
const SuggestFollowupToolName = "suggest_followup"

const AskUserToolName = "ask_user"

const (
	MaxAskUserQuestions = 5
	MaxAskUserOptions   = 8
	MaxAskUserTextRunes = 200
	// Context is a scrollable paragraph rather than a row the form has to fit, so it carries
	// its own bound: raising the shared one would let a single option label fill the terminal.
	MaxAskUserContextRunes = 2000
)

// askUserTextBlocked names every character AskUserTextRenderable refuses, as far as a fixed
// class can: the separators and the assigned control, format and private-use code points —
// Unicode categories Z, Cc, Cf and Co — less the ASCII space, which the form draws, plus the
// graphic-but-blank code points askUserBlank names. It
// spells the class out as characters (the escapes below are Go string escapes, so the
// advertised pattern carries the characters themselves) rather than using `\s`: ECMA-262
// `\s` and Go's `\s` cover different sets, so a class written with either would mean one
// thing to the provider validating the call and another to the test compiling it here.
// Three kinds of code point are deliberately left out, and the decoder refuses all three in
// band instead. One is anything outside the BMP: a JSON Schema pattern is ECMA-262, and an
// engine compiling it without the `u` flag reads an astral character as two surrogate code
// units, so a range between two of them is a range between code units in the wrong order and
// the whole pattern fails to compile — naming them would risk the entire advertised schema for
// the sake of a tag character. Another is a code point Unicode has not assigned, which a fixed
// class cannot enumerate without going stale at the next revision. The third is U+0000: some
// provider regex engines read a NUL as the end of the pattern and reject the schema as an
// unclosed class. Those three are the only ones:
// TestAskUserTextPattern_DivergesOnlyWhereAPatternCannotFollow sweeps every remaining code
// point for agreement between the layers.
const askUserTextBlocked = "\u0001-\u001f" + askUserTextBlockedAboveASCIIControls

const askUserTextBlockedAboveASCIIControls = "\u007f-\u00a0\u00ad" +
	"\u0600-\u0605\u061c\u06dd\u070f\u0890-\u0891\u08e2\u115f-\u1160\u1680\u180e" +
	"\u2000-\u200f\u2028-\u202f\u205f\u2060-\u2064\u2066-\u206f\u2800\u3000\u3164" +
	"\ue000-\uf8ff\ufeff\uffa0\ufff9-\ufffb"

// askUserBlank names the graphic characters that draw nothing: the braille blank and the
// Hangul fillers. Unicode classifies them as symbols and letters rather than as whitespace,
// so unicode.IsPrint admits them and unicode.IsSpace does not exclude them, yet a label made
// of them mounts as a row the reader cannot tell from an empty one, and two options can be
// distinct values that both look blank. They are in askUserTextBlocked as well, so the two
// layers refuse them in the same places.
func askUserBlank(r rune) bool {
	switch r {
	case 0x115F, 0x1160, 0x2800, 0x3164, 0xFFA0:
		return true
	}
	return false
}

// AskUserTextPattern is anchored so a blocked character is refused wherever it sits, not
// only in a value with nothing else to show: a tab or newline beside visible text is still
// text the terminal cannot draw at the width the form measured it at.
const AskUserTextPattern = "^[^" + askUserTextBlocked + "]*[^" + askUserTextBlocked + " ][^" + askUserTextBlocked + "]*$"

// AskUserTextRenderable reports whether the question form can show s in full. It is the
// authoritative rule for every displayed field and stays at least as strict as
// AskUserTextPattern, which cannot require that any grapheme occupy a cell (text made only
// of combining marks mounts as an empty prompt or an unreadable row) and cannot name the
// code points askUserTextBlocked leaves out. Every rune must be printable — unicode.IsPrint
// admits the ASCII space but no other whitespace, so a tab or newline beside visible text is
// refused here for the same reason the pattern refuses it.
func AskUserTextRenderable(s string) bool {
	visible := false
	for _, r := range s {
		if !unicode.IsPrint(r) || askUserBlank(r) {
			return false
		}
		if !unicode.IsSpace(r) && !unicode.Is(unicode.Mn, r) && !unicode.Is(unicode.Me, r) {
			visible = true
		}
	}
	return visible
}

const askUserContextBlocked = "\u0001-\u0009\u000b-\u001f" + askUserTextBlockedAboveASCIIControls

const AskUserContextPattern = "^[^" + askUserContextBlocked + "]*[^" + askUserContextBlocked + " \n][^" + askUserContextBlocked + "]*$"

func AskUserContextRenderable(s string) bool {
	return AskUserTextRenderable(strings.ReplaceAll(s, "\n", " "))
}

func AskUserToolDefinition() ToolDefinition {
	return ToolDefinition{
		Name: AskUserToolName,
		Description: "Ask the user one or more multiple-choice questions and wait for the answers. " +
			"Whenever this tool is advertised it is the required way to ask the user for a decision, a preference, or a missing detail: ask through it instead of writing the questions as prose and asking the user to type a reply. " +
			"Send every open question in one call — they are shown together in a single form — and never guess, infer, or pre-pick an answer you have not been given. " +
			"Each question needs a stable `id`, the `prompt` to show, and the `options` to choose from; set `multi_select` when more than one option may be chosen, and `allow_custom` when a typed answer instead of the listed options makes sense. " +
			"Every id, prompt, option label and option description is shown in a terminal, so each must contain visible text: a value that is blank, or that carries a control or zero-width character, is refused. " +
			"Set a question's `context` whenever a reasonable person could need to know why you are asking it, what the choice affects, or what a technical term in it means — without it the user is deciding blind. Each question's `context` is shown only on that question's screen, so it explains that question alone; never put background for another question in it. Leave it out only for a question that explains itself. " +
			"Put the trade-offs between choices in each option's `description` rather than in the context, so the user reads each consequence beside the choice it belongs to. " +
			"The result reports each question's selected options and custom text; a question the user left unanswered comes back empty, and a dismissed form comes back cancelled, so read what you were actually given before continuing. " +
			"Instead of answering, the user may ask you a question of their own: the result is then exactly {\"clarification\":\"...\"} with no answers at all. Reply to it, then call this tool again with the same questions and your reply restated in the `context` of the question or questions it concerns — the form covers the screen when it opens, so an explanation left only in your reply is not what the user is reading.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"questions": map[string]any{
					"type":        "array",
					"description": "Every question to show in one form, in the order they should be read.",
					"minItems":    1,
					"maxItems":    MaxAskUserQuestions,
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"id": map[string]any{
								"type":        "string",
								"description": "Stable identifier for this question, unique within the call; the answer is returned under it, exactly as sent.",
								"pattern":     AskUserTextPattern,
								"maxLength":   MaxAskUserTextRunes,
							},
							"prompt": map[string]any{
								"type":        "string",
								"description": "The question shown above its options.",
								"pattern":     AskUserTextPattern,
								"maxLength":   MaxAskUserTextRunes,
							},
							"context": map[string]any{
								"type":        "string",
								"description": "Plain-language background for this question only, shown in a scrollable section on this question's screen and on no other. Written for the user, not for you: say why this decision is needed, what it affects, and what any technical term in it means; explain only this question. It is displayed literally, so it is not markdown. Separate paragraphs with a line feed (\\n); tabs and other control characters are refused.",
								"pattern":     AskUserContextPattern,
								"maxLength":   MaxAskUserContextRunes,
							},
							"options": map[string]any{
								"type":        "array",
								"description": "The selectable answers for this question. Every option's label must differ from every other option's label in the question, even when their descriptions differ.",
								"minItems":    1,
								"maxItems":    MaxAskUserOptions,
								"uniqueItems": true,
								"items": map[string]any{
									"type": "object",
									"properties": map[string]any{
										"label": map[string]any{
											"type":        "string",
											"description": "The answer shown as the option's row and returned in `selected` when chosen.",
											"pattern":     AskUserTextPattern,
											"maxLength":   MaxAskUserTextRunes,
										},
										"description": map[string]any{
											"type":        "string",
											"description": "Optional explanation shown under the label: what choosing this option means and what it trades off against the others.",
											"pattern":     AskUserTextPattern,
											"maxLength":   MaxAskUserTextRunes,
										},
									},
									"required":             []string{"label"},
									"additionalProperties": false,
								},
							},
							"multi_select": map[string]any{
								"type":        "boolean",
								"description": "True when the user may choose any number of the options; false or absent allows at most one listed option (the user may still leave the question unanswered or answer it in their own words).",
							},
							"allow_custom": map[string]any{
								"type":        "boolean",
								"description": "True to offer \"Type your own answer\" so the user can answer this question in their own words.",
							},
						},
						"required":             []string{"id", "prompt", "options"},
						"additionalProperties": false,
					},
				},
			},
			"required":             []string{"questions"},
			"additionalProperties": false,
		},
	}
}

// SuggestFollowupToolDefinition returns the product-authored advertising definition
// for the `suggest_followup` tool — the model→UI side-channel for a single end-of-turn
// follow-up suggestion. Like `bash` it has no registry Tool: the turn loop
// special-cases the pinned name, routing {label, prompt} to a TUI ghost-text surface
// rather than executing or persisting anything. The Description carries the usage
// contract so a weak model is steered away from firing it on trivial turns; the schema
// requires the two string properties and forbids any other key, and a fresh Parameters
// map is returned on each call so a caller cannot mutate shared advertising state.
func SuggestFollowupToolDefinition() ToolDefinition {
	return ToolDefinition{
		Name: SuggestFollowupToolName,
		Description: "Offer ONE follow-up action the user can accept next by pressing Tab. " +
			"This tool produces no visible reply, so never call it as your whole response: first answer the user's request or summarize the completed work in prose, and only then call it, at most once per turn, to offer the single action that follows. " +
			"That action must be concrete, within your advertised tools, allowed in the current mode, and safe and reversible — never a destructive or irreversible action, never on a trivial turn, and never a restatement of work already done. " +
			"What you offer is work the user may accept, not work you have performed: after a read-only diagnosis, present your findings and the fix you would make, then use this tool to offer implementing that fix, never wording it as though the fix already ran. " +
			"When you would otherwise write a prose-only offer such as \"If you want, I can ...\", call this tool instead and do not also repeat the same offer in your reply. " +
			"`label` is the short imperative the user would say to ask for it (e.g. \"Add before/after LOC deltas to each task\"); `prompt` is the full instruction text to prefill into the input.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"label": map[string]any{
					"type":        "string",
					"description": "Short imperative naming the follow-up action, shown as the Tab hint.",
				},
				"prompt": map[string]any{
					"type":        "string",
					"description": "The full instruction text to prefill into the input when the user accepts with Tab.",
				},
			},
			"required":             []string{"label", "prompt"},
			"additionalProperties": false,
		},
	}
}

// BashToolDefinition returns the product-authored advertising definition for the
// `bash` shell tool. `bash` has no registry Tool — dispatch special-cases the pinned
// name and runs the raw command through the shell path — so its definition is authored
// here rather than enumerated from the registry, and it is advertised in every mode
// (Plan's read-only restriction is enforced per-invocation by posture, not at advertise
// time). The schema requires a single string `command` property and forbids any other
// key, mirroring the dispatch decoder (decodeBashCommand). A fresh Parameters map is
// returned on each call so a caller cannot mutate shared advertising state.
func BashToolDefinition() ToolDefinition {
	return ToolDefinition{
		Name: bashToolName,
		Description: "Run a shell command and return its output. Structured tools come first: reach for bash only when no structured tool covers the operation, such as a build, a test run, or file inspection no structured tool provides. " +
			"Issue independent operations as separate bash calls, in parallel where they do not depend on each other, instead of joining them into one command with `;`, and do not add `echo`/`printf` separator labels or exit-status wrappers such as `echo \"exit=$?\"`. " +
			"Do not append `2>/dev/null` or other output redirections to hide stderr: stderr is returned to you with the result and is usually the part worth reading, and a redirection sends a command that would otherwise run directly through an extra `sh -c` layer.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"command": map[string]any{
					"type":        "string",
					"description": "The shell command line to execute.",
				},
			},
			"required":             []string{"command"},
			"additionalProperties": false,
		},
	}
}

// askUserTopKeys and askUserQuestionKeys are the exact property names the advertised closed
// schema permits. encoding/json matches a struct field case-insensitively even with
// DisallowUnknownFields set, so decoding through raw key maps is what keeps `"Questions"` or
// `"ID"` — which the schema rejects — from mounting a form.
var (
	askUserTopKeys      = []string{"questions"}
	askUserQuestionKeys = []string{"id", "prompt", "context", "options", "multi_select", "allow_custom"}
	askUserOptionKeys   = []string{"label", "description"}
)

// AskUserQuestion and AskUserRequest are one accepted `ask_user` call. They are the single
// definition of what a valid call is: production dispatch maps an accepted request onto the
// TUI form, and /resume replay runs a saved call's raw arguments back through the same
// checker, so a call the live form would refuse can never render on replay.
type AskUserQuestion struct {
	ID                 string
	Prompt             string
	Context            string
	Options            []string
	OptionDescriptions []string
	MultiSelect        bool
	AllowCustom        bool
}

type AskUserRequest struct {
	Questions []AskUserQuestion
}

func DecodeAskUserRequest(arguments string) (AskUserRequest, error) {
	dec := json.NewDecoder(strings.NewReader(arguments))
	var root map[string]json.RawMessage
	if err := dec.Decode(&root); err != nil {
		return AskUserRequest{}, fmt.Errorf("invalid %s arguments: %w", AskUserToolName, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return AskUserRequest{}, askUserArgError("expected one JSON object, got trailing content")
	}
	if !askUserUniqueKeys(arguments) {
		return AskUserRequest{}, askUserArgError("an object repeats a member name")
	}
	var faults askUserFaults
	faults.collect(askUserExactKeys(root, askUserTopKeys, ""))
	var decoded []json.RawMessage
	if raw, ok := root["questions"]; ok {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			faults.add("", "%q must be an array of question objects", "questions")
			return AskUserRequest{}, faults.err()
		}
	}
	if len(decoded) == 0 {
		faults.add("", "missing %q", "questions")
		return AskUserRequest{}, faults.err()
	}
	if len(decoded) > MaxAskUserQuestions {
		faults.add(askUserAt(MaxAskUserQuestions), "%q has %d entries, at most %d allowed", "questions", len(decoded), MaxAskUserQuestions)
	}
	req := AskUserRequest{Questions: make([]AskUserQuestion, 0, len(decoded))}
	ids := make(map[string]int, len(decoded))
	for index, rawQuestion := range decoded {
		before := len(faults)
		var q map[string]json.RawMessage
		if err := json.Unmarshal(rawQuestion, &q); err != nil {
			faults.add(askUserAt(index), "must be a JSON object")
			continue
		}
		at := askUserAt(index)
		id, idErr := askUserText(q["id"], at, "id")
		switch first, dup := ids[id]; {
		case idErr != nil:
			faults.collect(idErr)
		case dup:
			faults.add(at, "%q duplicates the id of question %d", "id", first)
		default:
			ids[id] = index
			at = askUserNamed(id)
		}
		faults.collect(askUserExactKeys(q, askUserQuestionKeys, at))
		prompt, err := askUserText(q["prompt"], at, "prompt")
		faults.collect(err)
		questionContext, err := askUserContext(q["context"], at)
		faults.collect(err)
		multiSelect, err := askUserFlag(q["multi_select"], at, "multi_select")
		faults.collect(err)
		allowCustom, err := askUserFlag(q["allow_custom"], at, "allow_custom")
		faults.collect(err)
		options, descriptions := askUserOptions(q["options"], at, &faults)
		if len(faults) != before {
			continue
		}
		req.Questions = append(req.Questions, AskUserQuestion{
			ID:                 id,
			Prompt:             prompt,
			Context:            questionContext,
			Options:            options,
			OptionDescriptions: descriptions,
			MultiSelect:        multiSelect,
			AllowCustom:        allowCustom,
		})
	}
	if err := faults.err(); err != nil {
		return AskUserRequest{}, err
	}
	return req, nil
}

func askUserOptions(raw json.RawMessage, at string, faults *askUserFaults) ([]string, []string) {
	var rawOptions []json.RawMessage
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &rawOptions); err != nil {
			faults.add(at, "%q must be an array of option objects", "options")
			return nil, nil
		}
	}
	switch {
	case len(rawOptions) == 0:
		faults.add(at, "%q is empty", "options")
		return nil, nil
	case len(rawOptions) > MaxAskUserOptions:
		faults.add(askUserOptionAt(at, MaxAskUserOptions), "%q has %d entries, at most %d allowed", "options", len(rawOptions), MaxAskUserOptions)
	}
	labels := make([]string, 0, len(rawOptions))
	descriptions := make([]string, 0, len(rawOptions))
	seen := make(map[string]int, len(rawOptions))
	for index, rawOption := range rawOptions {
		optionAt := askUserOptionAt(at, index)
		var option map[string]json.RawMessage
		if err := json.Unmarshal(rawOption, &option); err != nil || option == nil {
			faults.add(optionAt, "must be an object with a %q", "label")
			continue
		}
		before := len(*faults)
		faults.collect(askUserExactKeys(option, askUserOptionKeys, optionAt))
		label, err := askUserText(option["label"], optionAt, "label")
		faults.collect(err)
		description := ""
		if rawDescription, ok := option["description"]; ok {
			description, err = askUserText(rawDescription, optionAt, "description")
			faults.collect(err)
		}
		if len(*faults) != before {
			continue
		}
		if first, dup := seen[label]; dup {
			faults.add(optionAt, "repeats the label of option %d", first)
			continue
		}
		seen[label] = index
		labels = append(labels, label)
		descriptions = append(descriptions, description)
	}
	return labels, descriptions
}

// askUserFaults reports every independently detectable failure in one refusal: stopping at
// the first costs the model a round per violated field kind, each round revealing one more.
type askUserFaults []string

func (f *askUserFaults) add(at, format string, args ...any) {
	*f = append(*f, askUserFault(at, format, args...).Error())
}

func (f *askUserFaults) collect(err error) {
	if err != nil {
		*f = append(*f, err.Error())
	}
}

func (f askUserFaults) err() error {
	if len(f) == 0 {
		return nil
	}
	return askUserArgError("%s", strings.Join(f, "; "))
}

// askUserAt, askUserNamed and askUserOptionAt place a fault by position, and only an id the
// decoder has already accepted is ever named: the refusal is persisted and read back by the
// model, so an over-long value naming itself would inflate the message it has to act on.
func askUserAt(index int) string { return fmt.Sprintf("question %d", index) }

func askUserNamed(id string) string { return fmt.Sprintf("question %q", id) }

func askUserOptionAt(at string, index int) string { return fmt.Sprintf("%s option %d", at, index) }

func askUserFault(at, format string, args ...any) error {
	detail := fmt.Sprintf(format, args...)
	if at == "" {
		return errors.New(detail)
	}
	return fmt.Errorf("%s: %s", at, detail)
}

func askUserExactKeys(object map[string]json.RawMessage, allowed []string, at string) error {
	unknown := 0
	for key := range object {
		if !slices.Contains(allowed, key) {
			unknown++
		}
	}
	if unknown == 0 {
		return nil
	}
	return askUserFault(at, "unknown fields: %d (allowed: %s)", unknown, strings.Join(allowed, ", "))
}

func askUserText(raw json.RawMessage, at, field string) (string, error) {
	var text string
	if len(raw) > 0 {
		if !AskUserDecodesUnchanged(raw) {
			return "", askUserFault(at, "%q carries malformed Unicode", field)
		}
		if err := json.Unmarshal(raw, &text); err != nil {
			return "", askUserFault(at, "%q must be a string", field)
		}
	}
	return checkAskUserText(text, at, field)
}

// AskUserDecodesUnchanged reports whether encoding/json will decode the raw token without
// substituting anything: it repairs a lone surrogate escape or an invalid UTF-8 byte into
// U+FFFD and returns no error, and a value repaired that way is neither the id the model
// correlates its answer by nor the label the user was shown. U+FFFD sent as itself is
// ordinary printable text and stays accepted; only text that would be rewritten into it is
// refused. The renderability rule cannot stand in for this, because the substitute passes it.
func AskUserDecodesUnchanged(raw json.RawMessage) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for i := 0; i < len(raw); {
		if raw[i] != '\\' {
			i++
			continue
		}
		if i+1 >= len(raw) {
			return false
		}
		if raw[i+1] != 'u' {
			i += 2
			continue
		}
		escaped, ok := askUserEscapedRune(raw[i:])
		if !ok {
			return false
		}
		i += 6
		if !utf16.IsSurrogate(escaped) {
			continue
		}
		low, ok := askUserEscapedRune(raw[i:])
		if !ok || utf16.DecodeRune(escaped, low) == utf8.RuneError {
			return false
		}
		i += 6
	}
	return true
}

func askUserEscapedRune(raw []byte) (rune, bool) {
	if len(raw) < 6 || raw[0] != '\\' || raw[1] != 'u' {
		return 0, false
	}
	value, err := strconv.ParseUint(string(raw[2:6]), 16, 32)
	if err != nil {
		return 0, false
	}
	return rune(value), true
}

// checkAskUserText bounds the raw string the model sent and refuses one the form cannot
// display, then returns that string unchanged: an id is the key the answer comes back
// under, so rewriting accepted text here would hand the model a different identifier
// than it sent.
func checkAskUserText(raw, at, field string) (string, error) {
	if measured := utf8.RuneCountInString(raw); measured > MaxAskUserTextRunes {
		return "", askUserFault(at, "%q is longer than %d characters (%d sent)", field, MaxAskUserTextRunes, measured)
	}
	if !AskUserTextRenderable(raw) {
		return "", askUserFault(at, "%q has no text the form can display", field)
	}
	return raw, nil
}

// An absent key is the ordinary question with no context, while a present but blank one is
// refused rather than silently dropped.
func askUserContext(raw json.RawMessage, at string) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	if !AskUserDecodesUnchanged(raw) {
		return "", askUserFault(at, "%q carries malformed Unicode", "context")
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return "", askUserFault(at, "%q must be a string", "context")
	}
	if measured := utf8.RuneCountInString(text); measured > MaxAskUserContextRunes {
		return "", askUserFault(at, "%q is longer than %d characters (%d sent)", "context", MaxAskUserContextRunes, measured)
	}
	if !AskUserContextRenderable(text) {
		return "", askUserFault(at, "%q has no text the form can display", "context")
	}
	return text, nil
}

func askUserFlag(raw json.RawMessage, at, field string) (bool, error) {
	if len(raw) == 0 {
		return false, nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, askUserFault(at, "%q must be true or false", field)
	}
	flag, ok := value.(bool)
	if !ok {
		return false, askUserFault(at, "%q must be true or false", field)
	}
	return flag, nil
}

// encoding/json keeps only the last of two members sharing a name, so a call carrying both
// `"questions":[]` and a real `"questions"` — or a question with two `id`s — would pass every
// check below on a value the closed schema never saw. The result of a form is compared against
// what QuestionResult.Encode writes instead, but these bytes come from the model, so there is
// nothing to compare them to and the schema has to refuse the repeat itself.
func askUserUniqueKeys(arguments string) bool {
	dec := json.NewDecoder(strings.NewReader(arguments))
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	return askUserUniqueKeysUnder(dec, tok)
}

// tok is the token that opened a value; only an object or array has anything under it. Decode
// has already accepted the same bytes, so the nesting this recurses through is bounded by the
// decoder's own depth limit.
func askUserUniqueKeysUnder(dec *json.Decoder, tok json.Token) bool {
	delim, nested := tok.(json.Delim)
	if !nested {
		return true
	}
	seen := make(map[string]bool)
	for dec.More() {
		next, err := dec.Token()
		if err != nil {
			return false
		}
		if delim == '{' {
			key, isKey := next.(string)
			if !isKey || seen[key] {
				return false
			}
			seen[key] = true
			if next, err = dec.Token(); err != nil {
				return false
			}
		}
		if !askUserUniqueKeysUnder(dec, next) {
			return false
		}
	}
	_, err := dec.Token()
	return err == nil
}

func askUserArgError(format string, args ...any) error {
	return fmt.Errorf("invalid %s arguments: %s", AskUserToolName, fmt.Sprintf(format, args...))
}
