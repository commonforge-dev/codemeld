// Tests for the production tui.ExitController (exitdeps.go) driven through
// the shared BuildRegistry builder: flush-success prints the resume hint and exits 0, the
// second-failure exits 1 with no hint, and SessionID reflects a live
// active-store swap.
package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// swapExitProcess overrides the os.Exit seam and returns a restore function.
func swapExitProcess(fn func(int)) func() {
	prev := exitProcess
	exitProcess = fn
	return func() { exitProcess = prev }
}

func TestExitController_FlushSuccess_PrintsHintExitsZero(t *testing.T) {
	store := mkStore(t)
	var buf bytes.Buffer
	code := -1
	defer swapExitProcess(func(c int) { code = c })()

	ctrl := exitController{activeStore: func() *sessions.Store { return store }, stop: func() {}, ctx: context.Background(), stdout: &buf}
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"exit": tui.NewExitHandler(ctrl)})
	host := &recordingHost{store: store}

	res := reg.DispatchSlashInput("/exit", host)
	if res.Status != tui.StatusHandled || res.Canonical != "exit" || res.Err != nil {
		t.Fatalf("dispatch result = %+v, want {handled, exit, no error}", res)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	want := tui.ResumeHint(store.SessionID())
	if got := strings.TrimSpace(buf.String()); got != want {
		t.Fatalf("stdout = %q, want resume hint %q", got, want)
	}
}

func TestExitController_SecondFlushFailure_ExitsOneNoHint(t *testing.T) {
	store := unwritableStore(t, "exit-fail", "/proj")
	var buf bytes.Buffer
	code := -1
	defer swapExitProcess(func(c int) { code = c })()

	ctrl := exitController{activeStore: func() *sessions.Store { return store }, stop: func() {}, ctx: context.Background(), stdout: &buf}
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"exit": tui.NewExitHandler(ctrl)})
	host := &recordingHost{store: store}

	res := reg.DispatchSlashInput("/exit", host)
	if res.Status != tui.StatusHandled || res.Err == nil {
		t.Fatalf("dispatch result = %+v, want handled with the flush error surfaced", res)
	}
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (req 400a second-failure)", code)
	}
	if buf.Len() != 0 {
		t.Fatalf("stdout = %q, want empty (resume hint suppressed on the failure path)", buf.String())
	}
}

func TestExitController_SessionID_ReflectsActiveStoreSwap(t *testing.T) {
	store1 := storeAt(t, filepath.Join(t.TempDir(), "s1.json"), "sess-one", "/proj")
	store2 := storeAt(t, filepath.Join(t.TempDir(), "s2.json"), "sess-two", "/proj")
	cur := store1
	ctrl := exitController{activeStore: func() *sessions.Store { return cur }, stop: func() {}, ctx: context.Background(), stdout: io.Discard}

	if got := ctrl.SessionID(); got != "sess-one" {
		t.Fatalf("SessionID() = %q, want sess-one", got)
	}
	cur = store2
	if got := ctrl.SessionID(); got != "sess-two" {
		t.Fatalf("SessionID() after swap = %q, want sess-two (read at call time)", got)
	}
}

type recordingTurnStopper struct {
	cancels       int
	waits         int
	waitedAfter   bool
	onWaitDrained func()
}

func (s *recordingTurnStopper) Cancel() (int, bool) {
	s.cancels++
	return 7, true
}

func (s *recordingTurnStopper) WaitTurnDrained() {
	s.waits++
	s.waitedAfter = s.cancels > 0
	if s.onWaitDrained != nil {
		s.onWaitDrained()
	}
}

func diskHasAssistantMessage(sess *sessions.Session, text string) bool {
	for _, r := range sess.Records {
		if m, ok := r.(sessions.Message); ok && m.Role == "assistant" && !m.Content.IsList() && m.Content.Text() == text {
			return true
		}
	}
	return false
}

func TestExitController_CancelsAndDrainsTheTurnBeforeTheFinalFlush(t *testing.T) {
	store := mkStore(t)
	var buf bytes.Buffer
	code := -1
	defer swapExitProcess(func(c int) { code = c })()

	const unwound = "recorded while the cancelled turn unwound"
	stopper := &recordingTurnStopper{onWaitDrained: func() {
		store.Append(sessions.Message{ID: "01890000-0000-7000-8000-0000000c0021", Role: "assistant", Content: sessions.TextContent(unwound), Timestamp: testStart})
	}}
	ctrl := exitController{activeStore: func() *sessions.Store { return store }, stop: func() {}, ctx: context.Background(), stdout: &buf, turn: stopper}
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"exit": tui.NewExitHandler(ctrl)})

	res := reg.DispatchSlashInput("/exit", &recordingHost{store: store})
	if res.Status != tui.StatusHandled || res.Err != nil {
		t.Fatalf("dispatch result = %+v, want {handled, no error}", res)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if stopper.cancels != 1 || stopper.waits != 1 {
		t.Fatalf("turn Cancel/WaitTurnDrained calls = %d/%d, want 1/1 — a clean exit must cancel the active turn and wait for it", stopper.cancels, stopper.waits)
	}
	if !stopper.waitedAfter {
		t.Fatal("WaitTurnDrained ran before Cancel; the exit path must cancel the turn first or the drain never returns")
	}
	if !diskHasAssistantMessage(readSessionFile(t, store.Path()), unwound) {
		t.Fatal("a record written while the cancelled turn unwound is missing from the flushed session; the drain must precede the clean-shutdown flush, not follow it")
	}
}

func TestStartTUI_ExitCancelsAndDrainsAnInFlightTurn(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	ready := make(chan struct{})
	release := make(chan struct{})
	var turnCtx atomic.Value
	client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
		turnCtx.Store(ctx)
		return provider.Response{Stream: gatedStream(ctx, contentChunk("Hi"), ready, release)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	var stdout bytes.Buffer
	code := -1
	defer swapExitProcess(func(c int) { code = c })()

	app, restore := startCaptured(t, ctx, indicatorTurnResult(t, store), &stdout)
	defer restore()

	if !app.SubmitInput("hello") {
		t.Fatal("wired submit rejected a plain prompt; the turn entrypoint is not wired")
	}
	<-ready

	exited := make(chan struct{})
	go func() {
		defer close(exited)
		app.SubmitInput("/exit")
	}()

	select {
	case <-exited:
		t.Fatal("/exit completed while the turn was still inside its provider stream; the exit path did not wait for the turn to drain")
	case <-time.After(200 * time.Millisecond):
	}

	tctx, _ := turnCtx.Load().(context.Context)
	if tctx == nil {
		t.Fatal("no turn context was captured; the stub provider client was never called")
	}
	if tctx.Err() == nil {
		t.Fatal("the per-turn context is still live after /exit; a child agent dispatched under it would not be cancelled")
	}

	close(release)
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("/exit never completed after the drained turn returned")
	}
	turns.Wait()

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
	if len(cmds) != 1 || cmds[0].Name != "exit" || cmds[0].Outcome != "success" {
		t.Fatalf("disk slash_command = %+v, want one {exit, success} after the drained exit", cmds)
	}
}

// The sibling test above drives /exit through SubmitInput on a test goroutine with no
// event loop running, so every transcript call the draining turn makes mutates
// directly. Production /exit arrives on the tview event-loop goroutine (a key handler
// through submitCurrent) and blocks it for the whole drain, while a turn cancelled
// mid-stream still has to surface its held partial and seal the stream — calls that
// marshal back onto that same loop. This drives the real loop and holds "{" unflushed
// (a whole-message text-tool-call candidate is withheld from the sink until the reply
// is proven ordinary prose), which is the only shape that defers those two calls until
// after the cancel.
func TestStartTUI_ExitFromTheEventLoopDrainsATurnHoldingUnflushedText(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	ready := make(chan struct{})
	release := make(chan struct{})
	client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
		return provider.Response{Stream: gatedStream(ctx, contentChunk("{"), ready, release)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	var stdout bytes.Buffer
	code := -1
	defer swapExitProcess(func(c int) { code = c })()

	screen := tcell.NewSimulationScreen("UTF-8")
	appC := make(chan *tui.App, 1)
	startC := make(chan error, 1)
	defer swapRunApp(func(a *tui.App) error {
		a.SetScreenFactoryForTest(func() (tcell.Screen, error) { return screen, nil })
		appC <- a
		return a.Run()
	})()
	go func() { startC <- StartTUI(ctx, indicatorTurnResult(t, store), &stdout) }()

	var app *tui.App
	select {
	case app = <-appC:
	case <-time.After(2 * time.Second):
		t.Fatal("StartTUI did not start the simulation event loop")
	}
	// /exit stops the loop itself, and tview's Run clears its screen unlocked once the
	// loop exits — a second Stop would race that read — so only stop an app a failed
	// assertion left running.
	t.Cleanup(func() {
		select {
		case err := <-startC:
			if err != nil {
				t.Errorf("StartTUI: %v", err)
			}
			return
		case <-time.After(2 * time.Second):
		}
		app.Stop()
		select {
		case err := <-startC:
			if err != nil {
				t.Errorf("StartTUI: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("StartTUI did not stop")
		}
	})

	if !submitOnEventLoop(t, app, "hello") {
		t.Fatal("wired submit rejected a plain prompt; the turn entrypoint is not wired")
	}
	<-ready

	exited := make(chan struct{})
	go func() {
		defer close(exited)
		app.RunOnEventLoopForTest(func() { app.SubmitInput("/exit") })
	}()

	select {
	case <-exited:
		t.Fatal("/exit completed while the turn was still inside its provider stream; the exit path did not wait for the turn to drain")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("/exit never completed: the drain blocked the event loop while the cancelled turn's held-partial flush and interrupt seal queued onto it")
	}
	turns.Wait()

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
	if len(cmds) != 1 || cmds[0].Name != "exit" || cmds[0].Outcome != "success" {
		t.Fatalf("disk slash_command = %+v, want one {exit, success} after the drained exit", cmds)
	}
}

func TestExitController_StopsDeliveryAfterTheTurnDrainsAndBeforeTheFinalFlush(t *testing.T) {
	for _, withTurn := range []bool{true, false} {
		t.Run(fmt.Sprintf("turn %v", withTurn), func(t *testing.T) {
			store := mkStore(t)
			var order []string
			ctrl := exitController{activeStore: func() *sessions.Store { return store }, stop: func() {}, ctx: context.Background(), stdout: io.Discard}
			if withTurn {
				ctrl.turn = &recordingTurnStopper{onWaitDrained: func() { order = append(order, "drained") }}
			}
			const drained = "recorded by the stop-and-drain hook"
			ctrl.stopDelivery = func() {
				order = append(order, "stop")
				store.Append(sessions.Message{ID: "01890000-0000-7000-8000-0000000c0022", Role: "assistant", Content: sessions.TextContent(drained), Timestamp: testStart})
			}

			if err := ctrl.FlushOnExit(); err != nil {
				t.Fatalf("FlushOnExit error: %v", err)
			}
			want := []string{"stop"}
			if withTurn {
				want = []string{"drained", "stop"}
			}
			if !slices.Equal(order, want) {
				t.Fatalf("order = %v, want %v", order, want)
			}
			if !diskHasAssistantMessage(readSessionFile(t, store.Path()), drained) {
				t.Fatal("a record the hook wrote is missing from the final flush")
			}
		})
	}
}

func TestStartTUI_ExitRecordsACapabilityChangeQueuedBehindADelivery(t *testing.T) {
	swapResolveExecutionCapability(t, constrainedLaunch)
	result, f := settingsFileLaunch(t)
	recorded := swapRecordedCapabilities(t)
	code := -1
	var atExit []events.ExecutionCapability
	defer swapExitProcess(func(c int) {
		code = c
		atExit = decodeDiskEvents[events.ExecutionCapability](t, readSessionFile(t, result.Session.Path()), events.KindExecutionCapability)
	})()

	started := make(chan string, 4)
	release := make(chan struct{})
	orig := deliverBlockedNotice
	t.Cleanup(func() { deliverBlockedNotice = orig })
	t.Cleanup(func() { close(release) })
	deliverBlockedNotice = func(*tui.App, string) {
		started <- "notice"
		<-release
	}

	screen := tcell.NewSimulationScreen("UTF-8")
	appC := make(chan *tui.App, 1)
	startC := make(chan error, 1)
	defer swapRunApp(func(a *tui.App) error {
		a.SetScreenFactoryForTest(func() (tcell.Screen, error) { return screen, nil })
		appC <- a
		return a.Run()
	})()
	go func() { startC <- StartTUI(context.Background(), result, io.Discard) }()
	var app *tui.App
	select {
	case app = <-appC:
	case <-time.After(5 * time.Second):
		t.Fatal("StartTUI did not start the simulation event loop")
	}
	returned := false
	t.Cleanup(func() {
		if !returned {
			app.Stop()
			<-startC
		}
	})

	requireRecordedCapability(t, recorded, enforce.Constrained)
	rewriteSettings(t, f.global, "blocked_paths: [\n")
	submitOnEventLoop(t, app, "/status")
	requireRecordedCapability(t, recorded, enforce.Refused)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the broken-file notice delivery never began")
	}

	f.editGlobal(t, "a")
	submitOnEventLoop(t, app, "/status")
	select {
	case got := <-recorded:
		t.Fatalf("recorded %+v while the delivery worker was held", got)
	default:
	}

	exited := make(chan struct{})
	go func() {
		defer close(exited)
		app.RunOnEventLoopForTest(func() { app.SubmitInput("/exit") })
	}()
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("/exit never completed: the stop-and-drain hook waited on the event loop it runs on")
	}
	select {
	case err := <-startC:
		returned = true
		if err != nil {
			t.Fatalf("StartTUI error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("StartTUI did not return after /exit; the deferred second stop must be a no-op")
	}
	if want := []events.ExecutionCapability{constrainedCapability, brokenCapability, constrainedCapability}; code != 0 || !reflect.DeepEqual(atExit, want) {
		t.Fatalf("exit code = %d, execution_capability on disk at process exit = %+v; want 0 and %+v", code, atExit, want)
	}
}
