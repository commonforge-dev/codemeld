// Integration tests for TR-TUI-10/11: ESC interrupts an in-flight streamed provider
// turn (durable stream_interrupted), and CTRL-C's double-empty clean exit / non-empty
// buffer clear — all driven through the production app StartTUI assembles against a
// no-network stub provider.
//
// Like the TR-TUI command integration tests, these live in package bootstrap because
// the production launch seams (StartTUI, swapRunApp/startCaptured, the goTurn and
// newTurnProviderClient seams, and the exitProcess seam) are package-private here; the
// pure ESC/CTRL-C TUI behavior (transcript interrupted marker, hint rendering, the
// fake-clock window) is already unit-pinned in internal/tui/key_esc_test.go and
// key_ctrlc_test.go, so these tests assert the production wiring and durable events.
package bootstrap

import (
	"bytes"
	"context"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
)

// TestTRTUI10_EscDuringStreamingInterruptsAndRecordsDurably pins TR-TUI-10: a plain
// prompt submitted through the wired app issues a cancellable streaming turn against a
// no-network stub provider; ESC through the app-level handler stops the in-flight
// stream via the ESC cancel path and records stream_interrupted{esc} durably on
// disk (the flush), carrying the retained partial-content char count. It
// fails if the prompt no longer routes through the turn controller, if ESC no longer
// cancels the live runner, or if the interruption is not flushed.
func TestTRTUI10_EscDuringStreamingInterruptsAndRecordsDurably(t *testing.T) {
	ctx := context.Background()

	// Join the background turn goroutine before reading the store, so the test never
	// races the turn's writes.
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	// Stub provider (no network): signal when the turn is issued, stream one delta,
	// then block until the request context is cancelled so ESC can interrupt a real
	// in-flight stream.
	entered := make(chan struct{})
	ready := make(chan struct{})
	client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
		close(entered)
		return provider.Response{Stream: blockingStream(ctx, contentChunk("Hi"), ready)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	result := &BootstrapResult{
		Home:      t.TempDir(),
		LaunchDir: "/launch",
		Session:   store,
		Model:     model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
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
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("hello") {
		t.Fatal("wired submit rejected a plain prompt; the prompt entrypoint is not wired to the turn controller")
	}

	<-entered // the turn was issued against the stub provider (no network)
	<-ready   // the runtime streamed and counted the first delta and is now blocked in-flight

	// ESC through the app-level handler: cancels the live runner, marks the partial
	// reply interrupted, and records + flushes stream_interrupted{esc}.
	app.HandleEsc()

	turns.Wait() // the blockingStream only unblocks on ctx cancel, so this returning proves the cancel propagated

	// Exactly one turn was issued, and the controller no longer reports an in-flight
	// turn: the stream was cancelled, not completed.
	if client.callCount() != 1 {
		t.Fatalf("provider client called %d times, want exactly 1 turn issued", client.callCount())
	}
	if _, inFlight := app.StreamCanceller().Cancel(); inFlight {
		t.Fatal("controller still reports an in-flight turn after ESC; the f90/g360 cancel path did not stop the stream")
	}

	// Production path: the streamed partial reply was rendered into the transcript of
	// the very app StartTUI assembled, and ESC sealed it with the interrupted marker.
	// Unlike the runner's retained counter and the durable event below — which only
	// prove bytes were counted and flushed — this fails if newTurnController stops
	// using the app as its stream surface or App.AppendStreamDelta stops mutating the
	// transcript, i.e. if the user would see no partial interrupted reply.
	if got := app.TranscriptText(); !strings.Contains(got, "Hi [interrupted]") {
		t.Fatalf("transcript = %q, want it to contain the interrupted partial reply %q", got, "Hi [interrupted]")
	}

	// stream_interrupted is durable on disk after the flush, with source esc
	// and the retained partial-content char count ("Hi" = 2 runes) — proving the partial
	// assistant content was retained at interrupt. The transcript interrupted marker
	// itself is unit-pinned in internal/tui/key_esc_test.go.
	disk := readSessionFile(t, store.Path())
	interrupts := diskStreamInterrupted(t, disk)
	if len(interrupts) != 1 {
		t.Fatalf("disk stream_interrupted events = %d, want 1 (durable after the req-400(d) flush)", len(interrupts))
	}
	if interrupts[0].Source != "esc" {
		t.Fatalf("stream_interrupted source = %q, want %q", interrupts[0].Source, "esc")
	}
	if interrupts[0].ContentChars != 2 {
		t.Fatalf("stream_interrupted content_chars = %d, want 2 (retained %q partial reply)", interrupts[0].ContentChars, "Hi")
	}

	// A cancelled turn emits no model_response: the reply was interrupted, not completed.
	if kinds := diskEventKinds(disk); slices.Contains(kinds, "model_response") {
		t.Fatalf("disk events = %v, want no model_response after an interrupted stream", kinds)
	}
	// The pre-turn user message is durable (persist-before-dispatch).
	if !diskHasUserMessage(disk, "hello") {
		t.Fatalf("session file %s missing the durable pre-turn user message", store.Path())
	}
}

// TestTRTUI11_DoubleCtrlCOnEmptyBufferExitsCleanly pins TR-TUI-11 part A: with an
// empty buffer, the first CTRL-C arms the exit window without exiting, and a second
// CTRL-C within the 1500ms window exits via the /exit clean-shutdown path — exit 0, the
// resume hint on stdout, and the canonical slash_command{exit, success}
// durable on disk after the flush. Two synchronous presses are inherently
// within the real-clock window; the window's outside-reset behavior is unit-pinned in
// internal/tui/key_ctrlc_test.go (TestCtrlC_OutsideWindow_ShowsHintAgainNotExit). It
// fails if CTRL-C no longer routes the double-empty exit through the production submit
// hook's clean-shutdown path.
func TestTRTUI11_DoubleCtrlCOnEmptyBufferExitsCleanly(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store}

	var stdout bytes.Buffer
	code := -1
	defer swapExitProcess(func(c int) { code = c })()

	app, restore := startCaptured(t, ctx, result, &stdout)
	defer restore()

	// First empty-buffer CTRL-C arms the exit window but does not exit.
	app.HandleCtrlC()
	if code != -1 {
		t.Fatalf("exit code = %d after a single empty CTRL-C, want no exit (window only armed)", code)
	}

	// Second empty-buffer CTRL-C within the window runs the clean-shutdown path.
	app.HandleCtrlC()
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (double-CTRL-C clean exit, req 445)", code)
	}
	if want := resumeHint(store.SessionID()); strings.TrimSpace(stdout.String()) != want {
		t.Fatalf("stdout = %q, want resume hint %q", stdout.String(), want)
	}

	// The exit is durable on disk before the process exits: the
	// slash_command appended before the flush is present, under the canonical name.
	disk := readSessionFile(t, store.Path())
	cmds := diskSlashCommands(t, disk)
	if len(cmds) != 1 || cmds[0].Name != "exit" || cmds[0].Outcome != "success" {
		t.Fatalf("disk slash_command = %+v, want one {exit, success}", cmds)
	}
	if len(cmds[0].Args) != 0 {
		t.Fatalf("exit slash_command args = %v, want empty", cmds[0].Args)
	}
}

// TestTRTUI11_CtrlCWithNonEmptyBufferClearsItAndDoesNotExit pins TR-TUI-11 part B: a
// CTRL-C over a non-empty input buffer clears the buffer and does not exit
// (step 2). It seeds and reads the buffer through the narrow SeedInput/InputText test
// seam — no existing cross-package seam can set the buffer without also submitting it.
// The buffer-clear branch is a pure UI action that records nothing and flushes nothing,
// so the assertions are the production-observable "no exit" (the exitProcess seam was
// not called) and an empty record stream.
func TestTRTUI11_CtrlCWithNonEmptyBufferClearsItAndDoesNotExit(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store}

	code := -1
	defer swapExitProcess(func(c int) { code = c })()

	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	app.SeedInput("a half-typed prompt")
	app.HandleCtrlC()

	if got := app.InputText(); got != "" {
		t.Fatalf("input buffer = %q after CTRL-C, want cleared (req 630 step 2)", got)
	}
	if code != -1 {
		t.Fatalf("exit code = %d, want no exit (CTRL-C over a non-empty buffer must clear, not exit)", code)
	}
	if cmds := slashCmds(t, store); len(cmds) != 0 {
		t.Fatalf("slash_command events = %+v, want none (the buffer-clear branch records nothing)", cmds)
	}
}
