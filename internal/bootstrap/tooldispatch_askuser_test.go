package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/testsupport"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/turn"
)

func TestProductionDispatcher_AskUserReturnsTheSubmittedAnswersAsTheToolResult(t *testing.T) {
	auth := &recordingAuthorizer{decision: allow()}
	d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, auth)
	asker := &fakeQuestionAsker{res: tui.QuestionResult{Answers: []tui.QuestionAnswer{
		{ID: "storage", Prompt: "Where should sessions be stored?", Selected: []string{"Object store"}},
		{ID: "targets", Prompt: "Which platforms?", Selected: []string{}, Custom: "BSD only"},
	}}}
	d.setAskUser(asker.ask)

	res, err := d.Dispatch(context.Background(), askUserCall(askUserValidArgs))

	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	want := `{"answers":[` +
		`{"id":"storage","prompt":"Where should sessions be stored?","selected":["Object store"]},` +
		`{"id":"targets","prompt":"Which platforms?","selected":[],"custom":"BSD only"}]}`
	if res.Content != want {
		t.Errorf("tool result =\n%s\nwant\n%s", res.Content, want)
	}
	if res.Denied {
		t.Error("an answered question form came back denied")
	}
	if auth.callCount() != 0 {
		t.Errorf("authorizer calls = %d, want 0 (asking the user is not a permissioned action)", auth.callCount())
	}
	if asker.callCount() != 1 {
		t.Fatalf("form mounts = %d, want 1", asker.callCount())
	}
	if got := asker.req.Questions; len(got) != 2 ||
		got[0].ID != "storage" || got[0].MultiSelect || got[0].AllowCustom ||
		got[1].ID != "targets" || !got[1].MultiSelect || !got[1].AllowCustom {
		t.Errorf("decoded questions = %+v, want both questions with their declared response modes", got)
	}
}

func TestProductionDispatcher_AskUserCancellationReturnsInBandAndContinues(t *testing.T) {
	d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
	d.setAskUser((&fakeQuestionAsker{res: tui.QuestionResult{Cancelled: true}}).ask)

	res, err := d.Dispatch(context.Background(), askUserCall(askUserValidArgs))

	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil (a dismissed form must not abort the turn)", err)
	}
	if res.Content != `{"answers":[],"cancelled":true}` {
		t.Errorf("tool result = %q, want an explicit cancelled result", res.Content)
	}
	if res.Terminal {
		t.Error("the cancelled result is terminal; the turn must continue to the next provider round")
	}
	if res.Denied {
		t.Error("a dismissed form came back denied; cancelling answers nothing, it refuses nothing")
	}
}

func TestProductionDispatcher_AskUserClarificationReplacesTheAnswersEntirely(t *testing.T) {
	d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
	asker := &fakeQuestionAsker{res: tui.QuestionResult{Clarification: `what does "object store" mean here?`}}
	d.setAskUser(asker.ask)

	res, err := d.Dispatch(context.Background(), askUserCall(askUserValidArgs))

	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil (a clarification is an ordinary tool result)", err)
	}
	want := `{"clarification":"what does \"object store\" mean here?"}`
	if res.Content != want {
		t.Errorf("tool result =\n%s\nwant\n%s", res.Content, want)
	}
	if strings.Contains(res.Content, "answers") {
		t.Errorf("tool result = %q, want no answers key: a clarification answered no question", res.Content)
	}
	if res.Terminal || res.Denied {
		t.Error("a clarification came back terminal or denied; the model must get the chance to explain")
	}
}

func TestProductionDispatcher_AskUserContextIsOptionalAndCarriesItsOwnBound(t *testing.T) {
	atBound := strings.Repeat("x", provider.MaxAskUserContextRunes)
	// A context this long is refused for every question field, which is what proves the
	// 2,000-rune bound is its own rather than the shared displayed-text one.
	pastQuestionBound := strings.Repeat("y", provider.MaxAskUserTextRunes+1)

	for _, tc := range []struct {
		name string
		args string
		want string
	}{
		{"omitted", askUserValidArgs, ""},
		{"one line", `{"context":"Sessions are replayed on /resume.","questions":[{"id":"a","prompt":"p","options":["x"]}]}`, "Sessions are replayed on /resume."},
		{"past the question-field bound", `{"context":"` + pastQuestionBound + `","questions":[{"id":"a","prompt":"p","options":["x"]}]}`, pastQuestionBound},
		{"at the maximum", `{"context":"` + atBound + `","questions":[{"id":"a","prompt":"p","options":["x"]}]}`, atBound},
		{"padded and tag-shaped", `{"context":" [red]not a tag[-] ","questions":[{"id":"a","prompt":"p","options":["x"]}]}`, " [red]not a tag[-] "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asker := &fakeQuestionAsker{}
			d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
			d.setAskUser(asker.ask)

			if _, err := d.Dispatch(context.Background(), askUserCall(tc.args)); err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}

			if asker.callCount() != 1 {
				t.Fatalf("form mounts = %d, want 1", asker.callCount())
			}
			if asker.req.Context != tc.want {
				t.Errorf("decoded context = %q, want %q exactly as sent", asker.req.Context, tc.want)
			}
			if len(asker.req.Questions) == 0 {
				t.Error("context decoding dropped the questions")
			}
		})
	}
}

func TestProductionDispatcher_AskUserKeepsAcceptedTextExactlyAsSent(t *testing.T) {
	multibyte := strings.Repeat("é", provider.MaxAskUserTextRunes)
	args := `{"questions":[{"id":" q ","prompt":"` + multibyte + `","options":["a"," a","a "]}]}`

	asker := &fakeQuestionAsker{}
	d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
	d.setAskUser(asker.ask)

	if _, err := d.Dispatch(context.Background(), askUserCall(args)); err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}

	if asker.callCount() != 1 {
		t.Fatalf("form mounts = %d, want 1 (padded values and a %d-rune multibyte prompt are valid)", asker.callCount(), provider.MaxAskUserTextRunes)
	}
	got := asker.req.Questions
	if len(got) != 1 {
		t.Fatalf("decoded questions = %d, want 1", len(got))
	}
	if got[0].ID != " q " {
		t.Errorf("question id = %q, want it returned exactly as sent: the model correlates the answer by it", got[0].ID)
	}
	if got[0].Prompt != multibyte {
		t.Errorf("a %d-rune multibyte prompt was altered or dropped", provider.MaxAskUserTextRunes)
	}
	if want := []string{"a", " a", "a "}; !slices.Equal(got[0].Options, want) {
		t.Errorf("options = %q, want %q — labels the schema calls unique stay distinct and unmodified", got[0].Options, want)
	}
}

// TestProductionDispatcher_AskUserAppliesTheRenderableTextRule drives the same shared table
// the provider test compiles AskUserTextPattern against, so the advertised schema and the
// rule the decoder actually applies cannot drift apart again.
func TestProductionDispatcher_AskUserAppliesTheRenderableTextRule(t *testing.T) {
	for _, tc := range testsupport.AskUserTextCases {
		for _, field := range []string{"id", "prompt", "option"} {
			args := `{"questions":[{"id":"q","prompt":"p","options":["x"]}]}`
			switch field {
			case "id":
				args = `{"questions":[{"id":` + mustJSON(t, tc.Text) + `,"prompt":"p","options":["x"]}]}`
			case "prompt":
				args = `{"questions":[{"id":"q","prompt":` + mustJSON(t, tc.Text) + `,"options":["x"]}]}`
			case "option":
				args = `{"questions":[{"id":"q","prompt":"p","options":[` + mustJSON(t, tc.Text) + `]}]}`
			}

			asker := &fakeQuestionAsker{}
			d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
			d.setAskUser(asker.ask)
			res, err := d.Dispatch(context.Background(), askUserCall(args))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}

			mounted := asker.callCount() == 1
			if mounted != tc.Valid {
				t.Errorf("%s = %q: form mounted = %v, want %v (result %q)", field, tc.Text, mounted, tc.Valid, res.Content)
			}
			if !tc.Valid && !strings.Contains(res.Content, "invalid ask_user arguments") {
				t.Errorf("%s = %q: result = %q, want an in-band ask_user argument error", field, tc.Text, res.Content)
			}
		}
	}
}

// TestProductionDispatcher_AskUserRefusesTextThatWouldMountBlank works from the wire
// payload rather than the shared table: a form is only as readable as what actually
// arrives, and each of these decodes to a one-rune prompt that passes every length, id and
// option check and then occupies no terminal cell.
func TestProductionDispatcher_AskUserRefusesTextThatWouldMountBlank(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		mounts  bool
	}{
		{"bom-only", `{"questions":[{"id":"q","prompt":"\uFEFF","options":["Yes"]}]}`, false},
		{"nel-only", `{"questions":[{"id":"q","prompt":"\u0085","options":["Yes"]}]}`, false},
		{"nul-only", `{"questions":[{"id":"q","prompt":"\u0000","options":["Yes"]}]}`, false},
		{"zero-width-option", `{"questions":[{"id":"q","prompt":"p","options":["\u200b"]}]}`, false},
		{"nul-inside-label", `{"questions":[{"id":"q","prompt":"p","options":["Ye\u0000s"]}]}`, false},
		// Graphic characters that draw no ink: two options that are distinct values and both
		// mount as blank rows, and one hidden beside text. The code point next to the braille
		// blank does draw, so the rule stays on the characters that are actually blank.
		{"two-blank-options", `{"questions":[{"id":"q","prompt":"p","options":["\u2800","\u3164"]}]}`, false},
		{"hangul-filler-prompt", `{"questions":[{"id":"q","prompt":"\u115f","options":["Yes"]}]}`, false},
		{"blank-beside-text", `{"questions":[{"id":"q","prompt":"p","options":["Ye\u2800s"]}]}`, false},
		{"braille-with-a-dot", `{"questions":[{"id":"q","prompt":"p","options":["\u2801"]}]}`, true},
		{"boundary-wide-prompt", `{"questions":[{"id":"q","prompt":"` + strings.Repeat(string(rune(0x754C)), provider.MaxAskUserTextRunes) + `","options":["Yes"]}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asker := &fakeQuestionAsker{}
			d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
			d.setAskUser(asker.ask)

			res, err := d.Dispatch(context.Background(), askUserCall(tc.payload))

			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}
			if mounted := asker.callCount() == 1; mounted != tc.mounts {
				t.Fatalf("form mounted = %v, want %v (result %q)", mounted, tc.mounts, res.Content)
			}
			if !tc.mounts && !strings.Contains(res.Content, "invalid ask_user arguments") {
				t.Errorf("result = %q, want an in-band ask_user argument error", res.Content)
			}
		})
	}
}

// askUserEscapes writes UTF-16 code units the way a model sends them on the wire, as \uXXXX
// text inside the JSON string. Only that form reaches the repair encoding/json performs; a
// Go escape in this file would already be the decoded rune.
func askUserEscapes(units ...uint16) string {
	var b strings.Builder
	for _, unit := range units {
		fmt.Fprintf(&b, `\u%04x`, unit)
	}
	return b.String()
}

// TestProductionDispatcher_AskUserRefusesMalformedUnicodeRatherThanRepairingIt covers the
// one way accepted text can still stop being the text that was sent: encoding/json turns a
// lone surrogate escape or an invalid UTF-8 byte into U+FFFD and reports no error, and the
// substitute is printable, so every later check passes on a value the model never sent. Two
// distinct malformed ids would also collapse onto the same answer key.
func TestProductionDispatcher_AskUserRefusesMalformedUnicodeRatherThanRepairingIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		token  string
		mounts bool
		want   string
	}{
		{"lone high surrogate", `"` + askUserEscapes(0xD800) + `"`, false, ""},
		{"lone low surrogate", `"` + askUserEscapes(0xDC00) + `"`, false, ""},
		{"high surrogate before a plain escape", `"` + askUserEscapes(0xD83D, 0x0041) + `"`, false, ""},
		{"high surrogate before plain text", `"` + askUserEscapes(0xD83D) + `A"`, false, ""},
		{"invalid utf-8 byte", "\"a\xffb\"", false, ""},
		{"escaped surrogate pair", `"` + askUserEscapes(0xD83D, 0xDE00) + `"`, true, "😀"},
		{"escaped replacement character", `"` + askUserEscapes(0xFFFD) + `"`, true, "�"},
		{"replacement character sent as itself", "\"�\"", true, "�"},
	} {
		for _, field := range []string{"id", "prompt", "option"} {
			t.Run(tc.name+"/"+field, func(t *testing.T) {
				args := `{"questions":[{"id":"q","prompt":"p","options":["x"]}]}`
				switch field {
				case "id":
					args = `{"questions":[{"id":` + tc.token + `,"prompt":"p","options":["x"]}]}`
				case "prompt":
					args = `{"questions":[{"id":"q","prompt":` + tc.token + `,"options":["x"]}]}`
				case "option":
					args = `{"questions":[{"id":"q","prompt":"p","options":[` + tc.token + `]}]}`
				}

				asker := &fakeQuestionAsker{}
				d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
				d.setAskUser(asker.ask)

				res, err := d.Dispatch(context.Background(), askUserCall(args))

				if err != nil {
					t.Fatalf("Dispatch error = %v, want nil", err)
				}
				if mounted := asker.callCount() == 1; mounted != tc.mounts {
					t.Fatalf("form mounted = %v, want %v (result %q)", mounted, tc.mounts, res.Content)
				}
				if !tc.mounts {
					if !strings.Contains(res.Content, "carries malformed Unicode") {
						t.Errorf("result = %q, want the malformed value named in band rather than repaired", res.Content)
					}
					return
				}
				got := asker.req.Questions[0]
				value := map[string]string{"id": got.ID, "prompt": got.Prompt, "option": got.Options[0]}[field]
				if value != tc.want {
					t.Errorf("%s = %q, want %q exactly as sent", field, value, tc.want)
				}
			})
		}
	}
}

// TestProductionDispatcher_AskUserAcceptsEveryValidStringEscape walks the escape forms the
// schema permits but the malformed-Unicode cases never reach: the raw token is inspected
// before encoding/json decodes it, and only \uXXXX is six bytes long, so a walker that
// mis-measures a short escape either refuses schema-valid text or reads the bytes after it as
// an escape of their own.
func TestProductionDispatcher_AskUserAcceptsEveryValidStringEscape(t *testing.T) {
	args := `{"questions":[{"id":"a\"b\\c\/d","prompt":"p\"q\\r\/s",` +
		`"options":["o\"p\\q\/r","\\ud800 is text, not a lone surrogate"]}]}`

	asker := &fakeQuestionAsker{}
	d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
	d.setAskUser(asker.ask)

	res, err := d.Dispatch(context.Background(), askUserCall(args))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if asker.callCount() != 1 {
		t.Fatalf("form mounts = %d, want 1: every escape here is schema-valid (result %q)", asker.callCount(), res.Content)
	}
	got := asker.req.Questions[0]
	if want := `a"b\c/d`; got.ID != want {
		t.Errorf("id = %q, want %q decoded once and left alone", got.ID, want)
	}
	if want := `p"q\r/s`; got.Prompt != want {
		t.Errorf("prompt = %q, want %q decoded once and left alone", got.Prompt, want)
	}
	want := []string{`o"p\q/r`, `\ud800 is text, not a lone surrogate`}
	if !slices.Equal(got.Options, want) {
		t.Errorf("options = %q, want %q", got.Options, want)
	}
}

// blockingQuestionAsker waits on the context it was handed, which is what the real form does:
// AskQuestions returns when its own context is done. A callback that ignores its context
// cannot tell the turn's context from any other, so dispatching with the wrong one would go
// unnoticed while the mounted form stayed up after the turn was cancelled.
type blockingQuestionAsker struct {
	entered chan struct{}
}

func (b *blockingQuestionAsker) ask(ctx context.Context, _ tui.QuestionRequest) (tui.QuestionResult, error) {
	close(b.entered)
	<-ctx.Done()
	return tui.QuestionResult{}, ctx.Err()
}

func TestProductionDispatcher_AskUserWaitsOnTheTurnsOwnContext(t *testing.T) {
	asker := &blockingQuestionAsker{entered: make(chan struct{})}
	d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
	d.setAskUser(asker.ask)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type outcome struct {
		res turn.ToolResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := d.Dispatch(ctx, askUserCall(askUserValidArgs))
		done <- outcome{res, err}
	}()

	select {
	case <-asker.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the dispatcher never reached the question form")
	}
	cancel()

	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) {
			t.Errorf("Dispatch error = %v, want context.Canceled", got.err)
		}
		if got.res.Content != "" {
			t.Errorf("content = %q, want no tool result for a cancelled dispatch", got.res.Content)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelling the turn left the form waiting: it was handed a context the turn does not own")
	}
}

func TestProductionDispatcher_AskUserKeepsExplicitlyFalseResponseModes(t *testing.T) {
	args := `{"questions":[{"id":"a","prompt":"p","options":["x"],"multi_select":false,"allow_custom":false}]}`

	asker := &fakeQuestionAsker{}
	d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
	d.setAskUser(asker.ask)

	if _, err := d.Dispatch(context.Background(), askUserCall(args)); err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if asker.callCount() != 1 {
		t.Fatalf("form mounts = %d, want 1 (explicit false is a valid response mode)", asker.callCount())
	}
	if got := asker.req.Questions[0]; got.MultiSelect || got.AllowCustom {
		t.Errorf("decoded response modes = %+v, want both false: a question sent as single-select must not become multi-select", got)
	}
}

func mustJSON(t *testing.T, text string) string {
	t.Helper()
	encoded, err := json.Marshal(text)
	if err != nil {
		t.Fatalf("marshal %q: %v", text, err)
	}
	return string(encoded)
}

func TestProductionDispatcher_AskUserInvalidPayloadsNeverMountTheForm(t *testing.T) {
	longText := strings.Repeat("x", provider.MaxAskUserTextRunes+1)
	atBound := strings.Repeat("x", provider.MaxAskUserTextRunes)
	tooManyQuestions := make([]string, 0, provider.MaxAskUserQuestions+1)
	for i := 0; i <= provider.MaxAskUserQuestions; i++ {
		tooManyQuestions = append(tooManyQuestions, fmt.Sprintf(`{"id":"q%d","prompt":"p","options":["a"]}`, i))
	}
	tooManyOptions := make([]string, 0, provider.MaxAskUserOptions+1)
	for i := 0; i <= provider.MaxAskUserOptions; i++ {
		tooManyOptions = append(tooManyOptions, fmt.Sprintf(`"o%d"`, i))
	}

	for _, tc := range []struct {
		name string
		args string
		want string
	}{
		{"malformed JSON", `{"questions":`, "invalid ask_user arguments"},
		{"repeated questions member", `{"questions":[],"questions":[{"id":"a","prompt":"p","options":["x"]}]}`, "an object repeats a member name"},
		{"repeated context member", `{"context":"one","context":"two","questions":[{"id":"a","prompt":"p","options":["x"]}]}`, "an object repeats a member name"},
		{"repeated id member", `{"questions":[{"id":"a","id":"b","prompt":"p","options":["x"]}]}`, "an object repeats a member name"},
		{"repeated options member", `{"questions":[{"id":"a","prompt":"p","options":["x"],"options":["y"]}]}`, "an object repeats a member name"},
		{"repeated multi_select member", `{"questions":[{"id":"a","prompt":"p","options":["x"],"multi_select":false,"multi_select":true}]}`, "an object repeats a member name"},
		{"repeated allow_custom member", `{"questions":[{"id":"a","prompt":"p","options":["x"],"allow_custom":false,"allow_custom":true}]}`, "an object repeats a member name"},
		{"unknown field", `{"questions":[{"id":"a","prompt":"p","options":["x"],"style":"grid"}]}`, `question "a": unknown fields: 1`},
		{"wrong-case questions", `{"Questions":[{"id":"a","prompt":"p","options":["x"]}]}`, `unknown fields: 1 (allowed: questions, context)`},
		{"wrong-case id", `{"questions":[{"ID":"a","prompt":"p","options":["x"]}]}`, `question 0: unknown fields: 1`},
		{"wrong-case prompt", `{"questions":[{"id":"a","Prompt":"p","options":["x"]}]}`, `question "a": unknown fields: 1`},
		{"wrong-case options", `{"questions":[{"id":"a","prompt":"p","Options":["x"]}]}`, `question "a": unknown fields: 1`},
		{"wrong-case multi_select", `{"questions":[{"id":"a","prompt":"p","options":["x"],"Multi_Select":true}]}`, `question "a": unknown fields: 1`},
		{"wrong-case allow_custom", `{"questions":[{"id":"a","prompt":"p","options":["x"],"Allow_Custom":true}]}`, `question "a": unknown fields: 1`},
		{"no questions", `{"questions":[]}`, `missing "questions"`},
		{"missing questions key", `{}`, `missing "questions"`},
		// null takes its own conversion path per target type: into a map or slice it leaves
		// the zero value, and into a string it succeeds and yields "", so each null shape has
		// to be refused where it lands rather than by one check standing in for the rest.
		{"null root", `null`, `missing "questions"`},
		{"null questions", `{"questions":null}`, `missing "questions"`},
		{"null question", `{"questions":[null]}`, `question 0: "id" has no text the form can display`},
		{"null id", `{"questions":[{"id":null,"prompt":"p","options":["x"]}]}`, `question 0: "id" has no text the form can display`},
		{"null prompt", `{"questions":[{"id":"a","prompt":null,"options":["x"]}]}`, `question "a": "prompt" has no text the form can display`},
		{"null options", `{"questions":[{"id":"a","prompt":"p","options":null}]}`, `question "a": "options" is empty`},
		{"null option element", `{"questions":[{"id":"a","prompt":"p","options":["x",null]}]}`, `question "a" option 1: "option" has no text the form can display`},
		{"too many questions", `{"questions":[` + strings.Join(tooManyQuestions, ",") + `]}`, `question 5: "questions" has 6 entries, at most 5 allowed`},
		{"blank id", `{"questions":[{"id":"  ","prompt":"p","options":["x"]}]}`, `question 0: "id" has no text the form can display`},
		{"duplicate id", `{"questions":[{"id":"a","prompt":"p","options":["x"]},{"id":"a","prompt":"q","options":["y"]}]}`, `question 1: "id" duplicates the id of question 0`},
		{"blank prompt", `{"questions":[{"id":"a","prompt":"","options":["x"]}]}`, `question "a": "prompt" has no text the form can display`},
		{"over-long prompt", `{"questions":[{"id":"a","prompt":"` + longText + `","options":["x"]}]}`, `question "a": "prompt" is longer than 200 characters (201 sent)`},
		{"no options", `{"questions":[{"id":"a","prompt":"p","options":[]}]}`, `question "a": "options" is empty`},
		{"too many options", `{"questions":[{"id":"a","prompt":"p","options":[` + strings.Join(tooManyOptions, ",") + `]}]}`, `question "a" option 8: "options" has 9 entries, at most 8 allowed`},
		{"blank option", `{"questions":[{"id":"a","prompt":"p","options":["x","  "]}]}`, `question "a" option 1: "option" has no text the form can display`},
		{"duplicate option", `{"questions":[{"id":"a","prompt":"p","options":["x","x"]}]}`, `question "a" option 1: repeats option 0`},
		{"trailing JSON value", `{"questions":[{"id":"a","prompt":"p","options":["x"]}]}{"extra":true}`, "trailing content"},
		{"trailing garbage", `{"questions":[{"id":"a","prompt":"p","options":["x"]}]} nope`, "trailing content"},
		{"null multi_select", `{"questions":[{"id":"a","prompt":"p","options":["x"],"multi_select":null}]}`, `question "a": "multi_select" must be true or false`},
		{"string multi_select", `{"questions":[{"id":"a","prompt":"p","options":["x"],"multi_select":"true"}]}`, `question "a": "multi_select" must be true or false`},
		{"null allow_custom", `{"questions":[{"id":"a","prompt":"p","options":["x"],"allow_custom":null}]}`, `question "a": "allow_custom" must be true or false`},
		{"numeric allow_custom", `{"questions":[{"id":"a","prompt":"p","options":["x"],"allow_custom":1}]}`, `question "a": "allow_custom" must be true or false`},
		{"questions is not an array", `{"questions":{"id":"a"}}`, `"questions" must be an array of question objects`},
		{"question is not an object", `{"questions":["a"]}`, `question 0: must be a JSON object`},
		{"id is not a string", `{"questions":[{"id":5,"prompt":"p","options":["x"]}]}`, `question 0: "id" must be a string`},
		{"options is not an array", `{"questions":[{"id":"a","prompt":"p","options":"x"}]}`, `question "a": "options" must be an array of strings`},
		{"option is not a string", `{"questions":[{"id":"a","prompt":"p","options":[1]}]}`, `question "a" option 0: "option" must be a string`},
		{"over-long multibyte prompt", `{"questions":[{"id":"a","prompt":"` + strings.Repeat("é", provider.MaxAskUserTextRunes+1) + `","options":["x"]}]}`, `question "a": "prompt" is longer than 200 characters (201 sent)`},
		{"over-long id padded to fit", `{"questions":[{"id":"` + atBound + ` ","prompt":"p","options":["x"]}]}`, `question 0: "id" is longer than 200 characters (201 sent)`},
		{"over-long prompt padded to fit", `{"questions":[{"id":"a","prompt":" ` + atBound + `","options":["x"]}]}`, `question "a": "prompt" is longer than 200 characters (201 sent)`},
		{"over-long option padded to fit", `{"questions":[{"id":"a","prompt":"p","options":["` + atBound + ` "]}]}`, `question "a" option 0: "option" is longer than 200 characters (201 sent)`},
		{"over-limit option and prompt at once", `{"questions":[{"id":"a","prompt":"` + longText + `","options":["` + longText + `"]}]}`, `question "a": "prompt" is longer than 200 characters (201 sent); question "a" option 0: "option" is longer than 200 characters (201 sent)`},
		{"over-long context", `{"context":"` + strings.Repeat("x", provider.MaxAskUserContextRunes+1) + `","questions":[{"id":"a","prompt":"p","options":["x"]}]}`, `"context" is longer than 2000 characters (2001 sent)`},
		{"over-long multibyte context", `{"context":"` + strings.Repeat("é", provider.MaxAskUserContextRunes+1) + `","questions":[{"id":"a","prompt":"p","options":["x"]}]}`, `"context" is longer than 2000 characters (2001 sent)`},
		{"blank context", `{"context":"  ","questions":[{"id":"a","prompt":"p","options":["x"]}]}`, `"context" has no text the form can display`},
		{"empty context", `{"context":"","questions":[{"id":"a","prompt":"p","options":["x"]}]}`, `"context" has no text the form can display`},
		{"context with a newline", `{"context":"why it matters\nand what it affects","questions":[{"id":"a","prompt":"p","options":["x"]}]}`, `"context" has no text the form can display`},
		{"context with a tab", `{"context":"why\tit matters","questions":[{"id":"a","prompt":"p","options":["x"]}]}`, `"context" has no text the form can display`},
		{"null context", `{"context":null,"questions":[{"id":"a","prompt":"p","options":["x"]}]}`, `"context" has no text the form can display`},
		{"context is not a string", `{"context":5,"questions":[{"id":"a","prompt":"p","options":["x"]}]}`, `"context" must be a string`},
		{"wrong-case context", `{"Context":"why","questions":[{"id":"a","prompt":"p","options":["x"]}]}`, `unknown fields: 1 (allowed: questions, context)`},
		{"malformed Unicode context", `{"context":"` + askUserEscapes(0xD800) + `","questions":[{"id":"a","prompt":"p","options":["x"]}]}`, `"context" carries malformed Unicode`},
		{"bad context does not hide a question fault", `{"context":"","questions":[{"id":"a","prompt":"","options":["x"]}]}`, `"context" has no text the form can display; question "a": "prompt" has no text the form can display`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := &recordingAuthorizer{decision: allow()}
			d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, auth)
			asker := &fakeQuestionAsker{}
			d.setAskUser(asker.ask)

			res, err := d.Dispatch(context.Background(), askUserCall(tc.args))

			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil (a bad payload is corrected in band)", err)
			}
			if !strings.Contains(res.Content, tc.want) {
				t.Errorf("content = %q, want it to mention %q", res.Content, tc.want)
			}
			if asker.callCount() != 0 {
				t.Error("an invalid payload mounted the question form")
			}
			if auth.callCount() != 0 {
				t.Error("an invalid payload reached the authorizer")
			}
		})
	}
}

func TestDecodeAskUserRequest_ArgumentErrorsLocateEveryViolation(t *testing.T) {
	optionText := "option-sentinel" + strings.Repeat("o", 209)
	promptText := "prompt-sentinel" + strings.Repeat("p", 241)
	idText := "id-sentinel" + strings.Repeat("i", 229)
	excessQuestions := make([]string, 0, provider.MaxAskUserQuestions+1)
	for i := 0; i < provider.MaxAskUserQuestions; i++ {
		excessQuestions = append(excessQuestions, fmt.Sprintf(`{"id":"q%d","prompt":"p","options":["a"]}`, i))
	}
	excessQuestions = append(excessQuestions, `{"id":"q5","prompt":"`+promptText+`","options":["yes"]}`)
	excessOptions := []string{`"` + optionText + `"`}
	for i := 1; i <= provider.MaxAskUserOptions; i++ {
		excessOptions = append(excessOptions, fmt.Sprintf(`"o%d"`, i))
	}
	trailingQuestions := make([]string, 0, provider.MaxAskUserQuestions+2)
	for i := 0; i <= provider.MaxAskUserQuestions; i++ {
		trailingQuestions = append(trailingQuestions, fmt.Sprintf(`{"id":"q%d","prompt":"p","options":["a"]}`, i))
	}
	trailingQuestions = append(trailingQuestions, `{"id":"q6","prompt":"`+promptText+`","options":["yes"]}`)
	trailingOptions := make([]string, 0, provider.MaxAskUserOptions+2)
	for i := 0; i <= provider.MaxAskUserOptions; i++ {
		trailingOptions = append(trailingOptions, fmt.Sprintf(`"o%d"`, i))
	}
	trailingOptions = append(trailingOptions, `"`+optionText+`"`)

	for _, tc := range []struct {
		name string
		args string
		want string
	}{
		{
			"over-limit option and prompt in different questions",
			`{"questions":[{"id":"q1","prompt":"pick one","options":["short","` + optionText + `"]},` +
				`{"id":"q4","prompt":"` + promptText + `","options":["yes"]}]}`,
			`invalid ask_user arguments: question "q1" option 1: "option" is longer than 200 characters (224 sent); ` +
				`question "q4": "prompt" is longer than 200 characters (256 sent)`,
		},
		{
			"an over-limit id falls back to the question index",
			`{"questions":[{"id":"` + idText + `","prompt":"` + promptText + `","options":["yes"]}]}`,
			`invalid ask_user arguments: question 0: "id" is longer than 200 characters (240 sent); ` +
				`question 0: "prompt" is longer than 200 characters (256 sent)`,
		},
		{
			"a duplicate id falls back to the question index",
			`{"questions":[{"id":"a","prompt":"p","options":["x"]},{"id":"a","prompt":"","options":["y"]}]}`,
			`invalid ask_user arguments: question 1: "id" duplicates the id of question 0; ` +
				`question 1: "prompt" has no text the form can display`,
		},
		{
			"unknown field, bad flag and repeated option in one question",
			`{"questions":[{"id":"a","prompt":"p","options":["x","x"],"multi_select":"yes","style":"grid"}]}`,
			`invalid ask_user arguments: question "a": unknown fields: 1 ` +
				`(allowed: id, prompt, options, multi_select, allow_custom); ` +
				`question "a": "multi_select" must be true or false; question "a" option 1: repeats option 0`,
		},
		{
			"an unknown root field does not hide a nested violation",
			`{"extra":true,"questions":[{"id":"a","prompt":"` + promptText + `","options":["yes"]}]}`,
			`invalid ask_user arguments: unknown fields: 1 (allowed: questions, context); ` +
				`question "a": "prompt" is longer than 200 characters (256 sent)`,
		},
		{
			"a failing question does not hide the questions after it",
			`{"questions":[{"id":"a","prompt":"","options":["x"]},{"id":"b","prompt":"p","options":[]}]}`,
			`invalid ask_user arguments: question "a": "prompt" has no text the form can display; ` +
				`question "b": "options" is empty`,
		},
		{
			"too many questions does not hide the excess question's own violation",
			`{"questions":[` + strings.Join(excessQuestions, ",") + `]}`,
			`invalid ask_user arguments: question 5: "questions" has 6 entries, at most 5 allowed; ` +
				`question "q5": "prompt" is longer than 200 characters (256 sent)`,
		},
		{
			"too many options does not hide an over-limit option label",
			`{"questions":[{"id":"a","prompt":"p","options":[` + strings.Join(excessOptions, ",") + `]}]}`,
			`invalid ask_user arguments: question "a" option 8: "options" has 9 entries, at most 8 allowed; ` +
				`question "a" option 0: "option" is longer than 200 characters (224 sent)`,
		},
		{
			"too many questions does not hide a violation past the first excess question",
			`{"questions":[` + strings.Join(trailingQuestions, ",") + `]}`,
			`invalid ask_user arguments: question 5: "questions" has 7 entries, at most 5 allowed; ` +
				`question "q6": "prompt" is longer than 200 characters (256 sent)`,
		},
		{
			"too many options does not hide a violation past the first excess option",
			`{"questions":[{"id":"a","prompt":"p","options":[` + strings.Join(trailingOptions, ",") + `]}]}`,
			`invalid ask_user arguments: question "a" option 8: "options" has 10 entries, at most 8 allowed; ` +
				`question "a" option 9: "option" is longer than 200 characters (224 sent)`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeAskUserRequest(tc.args)

			if err == nil {
				t.Fatal("decodeAskUserRequest error = nil, want a refusal")
			}
			if got := err.Error(); got != tc.want {
				t.Errorf("error = %q, want %q", got, tc.want)
			}
			if strings.Contains(err.Error(), "sentinel") {
				t.Errorf("error = %q, want no rejected text echoed back", err)
			}
			if strings.ContainsAny(err.Error(), "\r\n") {
				t.Errorf("error = %q, want one line", err)
			}
		})
	}
}

func TestProductionDispatcher_AskUserAcceptsTheAdvertisedMaxima(t *testing.T) {
	atBound := strings.Repeat("x", provider.MaxAskUserTextRunes)
	options := make([]string, 0, provider.MaxAskUserOptions)
	for i := 0; i < provider.MaxAskUserOptions; i++ {
		options = append(options, fmt.Sprintf(`"o%d"`, i))
	}
	options[0] = `"` + atBound + `"`
	questions := make([]string, 0, provider.MaxAskUserQuestions)
	for i := 0; i < provider.MaxAskUserQuestions; i++ {
		questions = append(questions, fmt.Sprintf(`{"id":"q%d","prompt":"p%d","options":[%s]}`, i, i, strings.Join(options, ",")))
	}
	args := `{"questions":[` + strings.Join(questions, ",") + `]}`

	asker := &fakeQuestionAsker{}
	d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
	d.setAskUser(asker.ask)

	if _, err := d.Dispatch(context.Background(), askUserCall(args)); err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}

	if asker.callCount() != 1 {
		t.Fatalf("form mounts = %d, want 1 (the advertised maxima are valid)", asker.callCount())
	}
	got := asker.req.Questions
	if len(got) != provider.MaxAskUserQuestions {
		t.Fatalf("decoded questions = %d, want %d", len(got), provider.MaxAskUserQuestions)
	}
	if len(got[0].Options) != provider.MaxAskUserOptions {
		t.Fatalf("decoded options = %d, want %d", len(got[0].Options), provider.MaxAskUserOptions)
	}
	if got[0].Options[0] != atBound {
		t.Errorf("a %d-rune option was altered or dropped", provider.MaxAskUserTextRunes)
	}
	if got[0].MultiSelect || got[0].AllowCustom {
		t.Error("omitted response-mode fields did not default to false")
	}
}

func TestProductionDispatcher_AskUserWithoutABoundFormIsAnUnknownTool(t *testing.T) {
	auth := &recordingAuthorizer{decision: allow()}
	d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, auth)

	res, err := d.Dispatch(context.Background(), askUserCall(askUserValidArgs))

	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if !strings.Contains(res.Content, "no_such_tool: "+provider.AskUserToolName) {
		t.Errorf("content = %q, want the ordinary unknown-tool refusal", res.Content)
	}
	if auth.callCount() != 0 {
		t.Errorf("authorizer calls = %d, want 0", auth.callCount())
	}
}

func TestProductionDispatcher_AskUserSeparatesFormFailureFromTurnCancellation(t *testing.T) {
	t.Run("form unavailable surfaces in band", func(t *testing.T) {
		d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
		d.setAskUser((&fakeQuestionAsker{err: errors.New("another overlay is already open")}).ask)

		res, err := d.Dispatch(context.Background(), askUserCall(askUserValidArgs))

		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil", err)
		}
		if !strings.Contains(res.Content, "could not be shown") {
			t.Errorf("content = %q, want an in-band explanation the model can act on", res.Content)
		}
	})
	t.Run("cancelled turn aborts the loop", func(t *testing.T) {
		d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
		d.setAskUser((&fakeQuestionAsker{err: context.Canceled}).ask)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		res, err := d.Dispatch(ctx, askUserCall(askUserValidArgs))

		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Dispatch error = %v, want context.Canceled", err)
		}
		if res.Content != "" {
			t.Errorf("content = %q, want empty for an aborted dispatch", res.Content)
		}
	})
	// The asker's error is a distinct sentinel here, so equality with context.Canceled
	// cannot make the assertion pass by accident: a form failure that races the turn's
	// cancellation must still be reported as the interruption it is.
	t.Run("a form failure racing cancellation reports the cancellation", func(t *testing.T) {
		formErr := errors.New("another overlay is already open")
		d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
		d.setAskUser((&fakeQuestionAsker{err: formErr}).ask)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		res, err := d.Dispatch(ctx, askUserCall(askUserValidArgs))

		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Dispatch error = %v, want context.Canceled", err)
		}
		if errors.Is(err, formErr) {
			t.Error("Dispatch returned the form's error; the turn loop would record a failed turn, not an interrupted one")
		}
		if res.Content != "" {
			t.Errorf("content = %q, want empty for an aborted dispatch", res.Content)
		}
	})
}

func TestRunHeadless_NeverAdvertisesOrOpensTheQuestionForm(t *testing.T) {
	var rounds [][]string
	client := toolThenContentClient(&rounds, provider.AskUserToolName, askUserValidArgs, "answered without asking")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("pick a storage backend", &stdout, &stderr)
	result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))

	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	for i, advertised := range rounds {
		if slices.Contains(advertised, provider.AskUserToolName) {
			t.Fatalf("headless round %d advertised %q: %v", i, provider.AskUserToolName, advertised)
		}
	}
	toolMsgs := messagesByRole(reloadStore(t, result.Session), "tool")
	if len(toolMsgs) != 1 {
		t.Fatalf("tool messages = %+v, want exactly one refusal", toolMsgs)
	}
	if got := toolMsgs[0].Content.Text(); !strings.Contains(got, "no_such_tool: "+provider.AskUserToolName) {
		t.Fatalf("headless ask_user result = %q, want the unknown-tool refusal", got)
	}
}
