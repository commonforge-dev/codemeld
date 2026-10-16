// Tests for the submit adapter: result-to-SubmitFunc accept/reject mapping plus
// the unknown-command and wrong-arity submit-boundary behavior.
// Reuses fakeHost / newFakeHost / events() from registry_test.go.
package tui

import (
	"errors"
	"testing"

	"codemeld.dev/codemeld/internal/sessions"
)

// promptRecorder is a PromptEntrypoint that records the inputs it received and
// returns a fixed accept/reject verdict.
func promptRecorder(accept bool, got *[]string) PromptEntrypoint {
	return func(input string, _ ...sessions.ContentPart) bool {
		*got = append(*got, input)
		return accept
	}
}

// singleCmdReg builds a one-command registry over h so a test can drive each
// StatusHandled mapping (success / retain / error) deterministically.
func singleCmdReg(t *testing.T, h HandlerFunc) *Registry {
	t.Helper()
	reg, err := NewRegistry([]Command{{Name: "do", Description: "x", ArgSig: ArgNone, Phase: PhaseOne, Handler: h}})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return reg
}

func TestNewSubmitFunc_PlainPrompt_AcceptedWhenEntrypointAccepts(t *testing.T) {
	var got []string
	host := newFakeHost()
	submit := NewSubmitFunc(BuildRegistry(nil), host, promptRecorder(true, &got))

	if !submit("just a prompt") {
		t.Fatal("plain prompt should be accepted when the entrypoint accepts it")
	}
	if len(got) != 1 || got[0] != "just a prompt" {
		t.Fatalf("entrypoint inputs = %v, want [just a prompt]", got)
	}
	if len(host.events()) != 0 {
		t.Fatalf("plain prompt must not append a slash_command event; got %d", len(host.events()))
	}
	if len(host.notices) != 0 {
		t.Fatalf("plain prompt must render no notice; got %v", host.notices)
	}
}

func TestNewSubmitFunc_PlainPrompt_RetainedWhenEntrypointRejects(t *testing.T) {
	var got []string
	host := newFakeHost()
	submit := NewSubmitFunc(BuildRegistry(nil), host, promptRecorder(false, &got))

	if submit("keep me") {
		t.Fatal("plain prompt must be retained (rejected) when the entrypoint rejects it")
	}
	if len(got) != 1 || got[0] != "keep me" {
		t.Fatalf("entrypoint inputs = %v, want [keep me]", got)
	}
}

func TestNewSubmitFunc_PlainPrompt_NilEntrypointRejects(t *testing.T) {
	host := newFakeHost()
	if NewSubmitFunc(BuildRegistry(nil), host, nil)("plain") {
		t.Fatal("a nil prompt entrypoint must reject every plain prompt")
	}
}

// TestNewSubmitFunc_AttachmentsReachOnlyPlainPrompts proves the image-attachment
// content parts a submission carries reach the plain-prompt entrypoint but are never
// forwarded to slash command dispatch — slash commands stay text-only.
func TestNewSubmitFunc_AttachmentsReachOnlyPlainPrompts(t *testing.T) {
	var gotParts [][]sessions.ContentPart
	prompt := PromptEntrypoint(func(_ string, imageParts ...sessions.ContentPart) bool {
		gotParts = append(gotParts, imageParts)
		return true
	})
	reg := singleCmdReg(t, func(CommandContext, []string) error { return nil })
	submit := NewSubmitFunc(reg, newFakeHost(), prompt)

	img := sessions.ContentPart{Type: "image_url", Raw: []byte(`{"type":"image_url","image_url":{"url":"data:image/png;base64,AA=="}}`)}

	// A plain prompt carries the image part through to the entrypoint.
	if !submit("look at this", img) {
		t.Fatal("plain prompt with an attachment should be accepted")
	}
	if len(gotParts) != 1 || len(gotParts[0]) != 1 || gotParts[0][0].Type != "image_url" {
		t.Fatalf("entrypoint image parts = %v, want exactly one image_url part", gotParts)
	}

	// A slash command never reaches the prompt entrypoint, so its attachments are dropped.
	if !submit("/do", img) {
		t.Fatal("/do should be handled")
	}
	if len(gotParts) != 1 {
		t.Fatalf("slash command forwarded attachments to the prompt entrypoint: %v", gotParts)
	}
}

func TestNewSubmitFunc_UnknownCommand_RetainsNoNoticeEventOrPrompt(t *testing.T) {
	var got []string
	host := newFakeHost()
	submit := NewSubmitFunc(BuildRegistry(nil), host, promptRecorder(true, &got))

	if submit("/bogus") {
		t.Fatal("/bogus must be rejected so the input is retained")
	}
	if len(got) != 0 {
		t.Fatalf("/bogus must not reach the model entrypoint; got %v", got)
	}
	want := "unknown command: /bogus — type /help to see available commands"
	if len(host.notices) != 1 || host.notices[0] != want {
		t.Fatalf("notices = %v, want exactly %q", host.notices, want)
	}
	if len(host.events()) != 0 {
		t.Fatalf("/bogus must append no slash_command event; got %d", len(host.events()))
	}
}

func TestNewSubmitFunc_WrongArity_RetainsNoEventOrPrompt(t *testing.T) {
	var got []string
	host := newFakeHost()
	submit := NewSubmitFunc(BuildRegistry(nil), host, promptRecorder(true, &got))

	if submit("/help extra") {
		t.Fatal("/help extra must be rejected (wrong arity)")
	}
	if len(got) != 0 {
		t.Fatalf("wrong-arity input must not reach the model entrypoint; got %v", got)
	}
	if len(host.notices) != 1 {
		t.Fatalf("wrong-arity must render exactly one notice; got %v", host.notices)
	}
	if len(host.events()) != 0 {
		t.Fatalf("wrong-arity must append no event; got %d", len(host.events()))
	}
}

func TestNewSubmitFunc_Handled_AcceptsUnlessRetainOrError(t *testing.T) {
	tests := []struct {
		name    string
		handler HandlerFunc
		want    bool
	}{
		{"success clears input", func(CommandContext, []string) error { return nil }, true},
		{"retain keeps input", func(ctx CommandContext, _ []string) error { ctx.RetainInput(); return nil }, false},
		{"handler error keeps input", func(CommandContext, []string) error { return errors.New("boom") }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			submit := NewSubmitFunc(singleCmdReg(t, tt.handler), newFakeHost(), nil)
			if got := submit("/do"); got != tt.want {
				t.Fatalf("submit(/do) = %v, want %v", got, tt.want)
			}
		})
	}
}
