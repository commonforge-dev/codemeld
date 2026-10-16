// End-to-end coverage for the clipboard-image wiring contract: an image read off the OS clipboard
// through the production CTRL-V key path persists as a content-part user message and
// reaches the provider request as an image_url part. Only the OS
// clipboard — an external resource — is faked, at the production reader seam; the
// attach/submit/persist/send path under test is the real wired one.
package bootstrap

import (
	"context"
	"io"
	"sync"
	"testing"

	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/tui"
)

// fakeClipboard stands in for the OS image clipboard at the production reader seam,
// returning fixed PNG bytes so CTRL-V can run without a real clipboard or helper binary.
type fakeClipboard struct {
	data []byte
}

func (f fakeClipboard) ReadImage(context.Context) (string, []byte, bool, error) {
	return "image/png", f.data, true, nil
}

// TestStartTUI_ClipboardImageReachesProviderAndStore drives the real wired app: an
// image staged through the production CTRL-V clipboard path is submitted through
// submitCurrent → the installed SubmitFunc → the prompt entrypoint → the pre-turn
// persister, then issued as a real provider turn against a stub client. It proves the
// clipboard source reuses the image attachment pipeline end to end — the user message
// persists as a content-part list carrying the image_url data URI and the provider send
// path carries that part into the provider request body.
func TestStartTUI_ClipboardImageReachesProviderAndStore(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var capturedReq provider.Request
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		capturedReq = req
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

	// Inject the fake clipboard at the production reader seam, then drive the real
	// CTRL-V key handler followed by Enter — no fake at the attach/submit/persist seam.
	ran.SetClipboardReader(fakeClipboard{data: []byte("\x89PNG\r\n\x1a\nDATA")})
	if !ran.PressCtrlV() {
		t.Fatal("CTRL-V did not stage a pending clipboard attachment through the wired reader")
	}
	if !ran.SubmitCurrent() {
		t.Fatal("submit of the staged clipboard image was rejected; the wired attach/persist path is broken")
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
