// End-to-end coverage for the image-attach wiring contract: an image attached through the
// production submit path persists as a content-part user message and reaches the
// provider request as an image_url part, no fake substituted at the submit/persist seam.
package bootstrap

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// TestStartTUI_AttachedImageReachesProviderAndStore drives the real wired app: an
// image referenced through the production attach path is submitted through
// submitCurrent → the installed SubmitFunc → the prompt entrypoint → the pre-turn
// persister, then issued as a real provider turn against a stub client. It proves the
// user message persists as a sessions.PartsContent list carrying the image_url data
// URI and that the provider send path carries that part into the provider request body.
func TestStartTUI_AttachedImageReachesProviderAndStore(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var capturedReq provider.Request
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if req.Stream {
			capturedReq = req
		}
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	projectRoot := t.TempDir()
	// A minimal valid PNG (magic bytes are enough for the content sniff) inside the root.
	if err := os.WriteFile(filepath.Join(projectRoot, "diagram.png"), []byte("\x89PNG\r\n\x1a\nDATA"), 0o644); err != nil {
		t.Fatalf("write image: %v", err)
	}

	store := mkStore(t)
	result := &BootstrapResult{
		Home:        t.TempDir(),
		LaunchDir:   projectRoot,
		ProjectRoot: projectRoot,
		Session:     store,
		Model:       model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{
					"base_url": "https://api.openai.com/v1",
					"api_key":  "sk-test",
					"models":   []string{"gpt-5.5"},
				},
			},
		},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop")
	}

	accepted := ran.SubmitInput("look at this diagram.png")
	if !accepted {
		t.Fatal("submit with a typed image reference was rejected; the wired attach/persist path is broken")
	}

	turns.Wait() // let the turn goroutine finish writing the store before reading it

	if client.callCount() != 1 {
		t.Fatalf("provider client called %d times, want exactly 1 turn issued", client.callCount())
	}

	// The provider request carries the image as an image_url content part.
	userMsg := lastUserMessage(t, capturedReq.Messages)
	if !hasImageURLPart(userMsg.Parts) {
		t.Fatalf("provider request user message parts = %+v, want an image_url data: URI part", userMsg.Parts)
	}

	// The persisted record is a content-part user message with the data URI.
	m := lastStoredUserMessage(t, store.Records())
	if !m.Content.IsList() {
		t.Fatal("persisted user message is not a content-part list")
	}
	if !storedHasImageURL(m.Content.Parts()) {
		t.Fatalf("persisted parts = %+v, want an image_url data URI part", m.Content.Parts())
	}
}

// TestStartTUI_DeletedImageTokenSendsNoImagePart drives the real wired app: a clipboard image
// staged through the production CTRL-V path becomes an "[Image 1]" token, then the token is
// removed before submit (here by replacing the buffer with plain text, which drops the staged
// token). The issued provider turn must carry no image part — proving a removed image token
// stages nothing downstream, end to end through the real submit/persist path.
func TestStartTUI_DeletedImageTokenSendsNoImagePart(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var capturedReq provider.Request
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if !isTitleRequest(req) {
			capturedReq = req
		}
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	projectRoot := t.TempDir()
	store := mkStore(t)
	result := &BootstrapResult{
		Home:        t.TempDir(),
		LaunchDir:   projectRoot,
		ProjectRoot: projectRoot,
		Session:     store,
		Model:       model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{
					"base_url": "https://api.openai.com/v1",
					"api_key":  "sk-test",
					"models":   []string{"gpt-5.5"},
				},
			},
		},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop")
	}

	ran.SetClipboardReader(fakeClipboard{data: []byte("\x89PNG\r\n\x1a\nDATA")})
	if !ran.PressCtrlV() {
		t.Fatal("CTRL-V did not stage a pending clipboard attachment")
	}
	if got := ran.InputText(); got != "[Image 1]" {
		t.Fatalf("buffer after CTRL-V = %q, want the [Image 1] token", got)
	}
	// Replace the buffer with plain text, dropping the staged image token, then submit.
	if !ran.SubmitInput("no image here") {
		t.Fatal("submit of the token-free prompt was rejected")
	}

	turns.Wait()

	if client.callCount() != 2 {
		t.Fatalf("provider client called %d times, want 2 (one turn request plus one title request)", client.callCount())
	}
	userMsg := lastUserMessage(t, capturedReq.Messages)
	if hasImageURLPart(userMsg.Parts) {
		t.Fatalf("provider request carried an image part after the token was removed: %+v", userMsg.Parts)
	}
}

func lastUserMessage(t *testing.T, msgs []provider.Message) provider.Message {
	t.Helper()
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			return msgs[i]
		}
	}
	t.Fatal("no user message in the provider request")
	return provider.Message{}
}

func hasImageURLPart(parts []provider.ContentPart) bool {
	for _, p := range parts {
		if p.Type == "image_url" && strings.HasPrefix(p.ImageURL, "data:image/png;base64,") {
			return true
		}
	}
	return false
}

func lastStoredUserMessage(t *testing.T, recs []sessions.Record) sessions.Message {
	t.Helper()
	for i := len(recs) - 1; i >= 0; i-- {
		if m, ok := recs[i].(sessions.Message); ok && m.Role == "user" {
			return m
		}
	}
	t.Fatal("no user message in the session store")
	return sessions.Message{}
}

func storedHasImageURL(parts []sessions.ContentPart) bool {
	for _, p := range parts {
		if p.Type == "image_url" && strings.Contains(string(p.Raw), "data:image/png;base64,") {
			return true
		}
	}
	return false
}
