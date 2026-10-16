// Tests for ESC priority: overlay dismissal, stream interruption, and non-empty
// input clearing.
package tui

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/gdamore/tcell/v2"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

type fakeStreamCanceller struct {
	retained int
	inFlight bool
	calls    int
}

func (f *fakeStreamCanceller) Cancel() (int, bool) {
	f.calls++
	return f.retained, f.inFlight
}

// fakeStreamReporter's Cancel clears the in-flight state so a later press sees the
// idempotent post-cancellation answer the real controller gives.
type fakeStreamReporter struct {
	fakeStreamCanceller
}

func (f *fakeStreamReporter) Cancel() (int, bool) {
	retained, inFlight := f.fakeStreamCanceller.Cancel()
	f.inFlight = false
	return retained, inFlight
}

func (f *fakeStreamReporter) StreamInFlight() bool { return f.inFlight }

func escGuardApp(t *testing.T, streaming bool) (*App, *sessions.Store, *fakeStreamReporter) {
	t.Helper()
	a := New(nil)
	store := escTestStore()
	a.SetActiveStore(store)
	canceller := &fakeStreamReporter{fakeStreamCanceller: fakeStreamCanceller{retained: 4, inFlight: streaming}}
	a.SetStreamCanceller(canceller)
	a.SetCommandFlush(func() error { return nil })
	if streaming {
		a.AppendStreamDelta("partial")
	}
	a.ShowStatus("status")
	return a, store, canceller
}

func escKey(a *App) { a.handleGlobalKey(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone)) }

// Both presses go through handleGlobalKey so this also pins that ESC itself does not
// clear the guard before HandleEsc consumes it.
func TestHandleEsc_StatusDismissOverActiveStreamDisarmsNextEsc(t *testing.T) {
	a, store, canceller := escGuardApp(t, true)

	escKey(a)

	if a.statusOpen {
		t.Fatal("status overlay still open after ESC")
	}
	if !a.escDisarmed {
		t.Fatal("dismissing /status over a live stream did not disarm the next ESC")
	}

	escKey(a)

	if got := a.NoticeText(); got != escInterruptHintText {
		t.Fatalf("notice = %q, want %q", got, escInterruptHintText)
	}
	if canceller.calls != 0 {
		t.Fatalf("canceller called %d times, want 0 (the disarmed ESC must not cancel)", canceller.calls)
	}
	if len(store.Records()) != 0 {
		t.Fatalf("records = %d, want 0 (no stream_interrupted for a disarmed ESC)", len(store.Records()))
	}
	if !a.transcript.streaming {
		t.Fatal("streamed reply sealed by the disarmed ESC")
	}
	if a.escDisarmed {
		t.Fatal("guard survived the ESC it disarmed; it is one-shot")
	}
}

func TestHandleEsc_EscAfterDisarmedPressInterruptsOnce(t *testing.T) {
	a, store, canceller := escGuardApp(t, true)

	escKey(a)
	escKey(a)
	escKey(a)

	if canceller.calls != 1 {
		t.Fatalf("canceller called %d times, want 1", canceller.calls)
	}
	interrupt := onlyStreamInterrupted(t, store)
	if interrupt.Source != "esc" || interrupt.ContentChars != 4 {
		t.Fatalf("stream_interrupted = %+v, want esc/4", interrupt)
	}
	if got := a.NoticeText(); got != "" {
		t.Fatalf("notice = %q, want cleared once the interrupt happened", got)
	}
}

func TestHandleEsc_IdleStatusDismissDoesNotDisarm(t *testing.T) {
	a, store, _ := escGuardApp(t, false)
	a.input.SetText("typed")

	a.HandleEsc()

	if a.escDisarmed {
		t.Fatal("dismissing /status with no stream in flight disarmed the next ESC")
	}
	if got := a.input.GetText(); got != "typed" {
		t.Fatalf("input after overlay ESC = %q, want preserved", got)
	}

	a.HandleEsc()

	if got := a.input.GetText(); got != "" {
		t.Fatalf("input = %q, want cleared by the adr-016 branch", got)
	}
	if len(store.Records()) != 0 {
		t.Fatalf("records = %d, want 0 with no stream in flight", len(store.Records()))
	}
	if got := a.NoticeText(); got != "" {
		t.Fatalf("notice = %q, want none", got)
	}
}

func TestHandleGlobalKey_NonEscKeyClearsEscGuard(t *testing.T) {
	a, store, canceller := escGuardApp(t, true)

	escKey(a)
	a.handleGlobalKey(tcell.NewEventKey(tcell.KeyRune, 'x', tcell.ModNone))

	if a.escDisarmed {
		t.Fatal("guard survived a non-ESC keystroke")
	}

	escKey(a)

	if canceller.calls != 1 {
		t.Fatalf("canceller called %d times, want 1 (a cleared guard must not swallow the ESC)", canceller.calls)
	}
	interrupt := onlyStreamInterrupted(t, store)
	if interrupt.Source != "esc" {
		t.Fatalf("stream_interrupted source = %q, want esc", interrupt.Source)
	}
	if got := a.NoticeText(); got != "" {
		t.Fatalf("notice = %q, want none", got)
	}
}

func TestHandleGlobalKey_CtrlLClearsEscGuard(t *testing.T) {
	a, store, canceller := escGuardApp(t, true)
	draws := 0
	a.draw = func() { draws++ }

	escKey(a)
	a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlL, 0, tcell.ModNone))

	if draws != 1 {
		t.Fatalf("draws = %d, want 1 (CTRL-L must still repaint)", draws)
	}
	if a.escDisarmed {
		t.Fatal("guard survived CTRL-L")
	}

	escKey(a)

	if canceller.calls != 1 {
		t.Fatalf("canceller called %d times, want 1 (a cleared guard must not swallow the ESC)", canceller.calls)
	}
	interrupt := onlyStreamInterrupted(t, store)
	if interrupt.Source != "esc" {
		t.Fatalf("stream_interrupted source = %q, want esc", interrupt.Source)
	}
}

func TestHandleEsc_OverlayDismissBeatsStreamAndDoesNotDisarm(t *testing.T) {
	for _, tc := range []struct {
		name   string
		open   func(*App)
		isOpen func(*App) bool
	}{
		{
			name:   "panel",
			open:   func(a *App) { a.ShowPanel("help") },
			isOpen: func(a *App) bool { return a.panelOpen },
		},
		{
			name: "effort picker",
			open: func(a *App) {
				a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: &effortApplierFake{}})
				a.openEffortPicker()
			},
			isOpen: func(a *App) bool { return a.effortPickerOpen },
		},
		{
			name: "model picker",
			open: func(a *App) {
				a.SetModelPickerDeps(ModelPickerDeps{Catalog: selectedModelCatalog(), Applier: &providerModelApplierFake{}})
				a.openModelPicker()
			},
			isOpen: func(a *App) bool { return a.modelPickerOpen },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, store, canceller := escGuardApp(t, true)
			a.dismissStatus()
			a.input.SetText("typed")
			tc.open(a)

			a.HandleEsc()

			if tc.isOpen(a) {
				t.Fatal("overlay still open after ESC; an open overlay owns ESC ahead of the stream")
			}
			if canceller.calls != 0 {
				t.Fatalf("canceller called %d times, want 0 (the overlay ESC must not cancel the turn)", canceller.calls)
			}
			if len(store.Records()) != 0 {
				t.Fatalf("records = %d, want 0 (no stream_interrupted for an overlay ESC)", len(store.Records()))
			}
			if !a.transcript.streaming {
				t.Fatal("streamed reply sealed by the overlay ESC")
			}
			if got := a.input.GetText(); got != "typed" {
				t.Fatalf("input after overlay ESC = %q, want preserved", got)
			}
			if a.escDisarmed {
				t.Fatal("dismissing a non-status overlay disarmed the next ESC")
			}

			a.HandleEsc()

			if canceller.calls != 1 {
				t.Fatalf("canceller called %d times, want 1 (the second ESC interrupts)", canceller.calls)
			}
			interrupt := onlyStreamInterrupted(t, store)
			if interrupt.Source != "esc" {
				t.Fatalf("stream_interrupted source = %q, want esc", interrupt.Source)
			}
		})
	}
}

// An overlay flag that skips the roster would silently lose both ESC and the
// cross-overlay guard, so the check walks the struct rather than a hand-kept list.
func TestOverlays_RosterCoversEveryOpenFlag(t *testing.T) {
	a := New(nil)
	roster := a.overlays()
	seen := make(map[string]bool, len(roster))
	for _, o := range roster {
		if seen[o.name] {
			t.Fatalf("overlay %q registered twice", o.name)
		}
		seen[o.name] = true
		if o.isOpen == nil {
			t.Fatalf("overlay %q has no isOpen predicate", o.name)
		}
	}

	fields := reflect.ValueOf(a).Elem()
	flags := 0
	for i := 0; i < fields.NumField(); i++ {
		field := fields.Type().Field(i)
		if field.Type.Kind() != reflect.Bool || !strings.HasSuffix(field.Name, "Open") {
			continue
		}
		flags++
		name := strings.TrimSuffix(field.Name, "Open")
		idx := slices.IndexFunc(roster, func(o overlay) bool { return o.name == name })
		if idx < 0 {
			t.Errorf("App.%s has no overlays() entry named %q; register it there instead of adding a branch", field.Name, name)
			continue
		}
		open := (*bool)(unsafe.Pointer(fields.Field(i).UnsafeAddr()))
		*open = true
		if !roster[idx].isOpen() {
			t.Errorf("overlays() entry %q reports closed while App.%s is true; its predicate reads the wrong flag", name, field.Name)
		}
		if !a.anyOverlayOpen() {
			t.Errorf("anyOverlayOpen() = false while App.%s is true", field.Name)
		}
		*open = false
	}
	if flags != len(roster) {
		t.Errorf("overlays() has %d entries for %d App overlay flags", len(roster), flags)
	}
}

// The resume picker registers open state only: handleGlobalKey hands its ESC to the
// focused list, so the roster walk must skip it rather than close it centrally.
func TestHandleEsc_NilDismissEntryIsSkipped(t *testing.T) {
	a, store, canceller := escGuardApp(t, true)
	a.dismissStatus()
	a.resumePickerOpen = true

	a.HandleEsc()

	if !a.resumePickerOpen {
		t.Fatal("roster walk centrally dismissed the resume picker; its entry has no dismiss func")
	}
	if canceller.calls != 1 {
		t.Fatalf("canceller called %d times, want 1 (a skipped entry falls through to the stream)", canceller.calls)
	}
	if interrupt := onlyStreamInterrupted(t, store); interrupt.Source != "esc" {
		t.Fatalf("stream_interrupted source = %q, want esc", interrupt.Source)
	}
}

func TestHandleEsc_StreamFirstMarksRecordsFlushesAndPreservesInput(t *testing.T) {
	a := New(nil)
	store := escTestStoreAtPath(filepath.Join(t.TempDir(), "session.json"))
	a.SetActiveStore(store)
	a.SetStreamCanceller(&fakeStreamCanceller{retained: 7, inFlight: true})
	a.SetCommandFlush(func() error {
		_, _, err := store.Flush(context.Background())
		return err
	})
	a.input.SetText("typed")
	a.AppendStreamDelta("partial")

	a.HandleEsc()

	if got := a.input.GetText(); got != "typed" {
		t.Fatalf("input = %q, want preserved", got)
	}
	if a.transcript.streaming || a.transcript.streamBuf != "" {
		t.Fatalf("stream buffer still open: streaming=%v buf=%q", a.transcript.streaming, a.transcript.streamBuf)
	}
	// The transcript stores the sealed line escaped (dynamic colors), so the
	// assertion reads the visible rendered text, where the interrupted marker shows
	// literally.
	if got, want := a.transcript.text(true), "partial [interrupted]"+visibleResponseLine; got != want {
		t.Fatalf("transcript = %q, want interrupted partial", got)
	}
	interrupt := onlyStreamInterrupted(t, store)
	if interrupt.Source != "esc" || interrupt.ContentChars != 7 {
		t.Fatalf("stream_interrupted = %+v, want esc/7", interrupt)
	}
	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("read flushed session: %v", err)
	}
	persisted, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("decode flushed session: %v", err)
	}
	interrupt = onlyStreamInterruptedRecord(t, persisted.Records)
	if interrupt.Source != "esc" || interrupt.ContentChars != 7 {
		t.Fatalf("persisted stream_interrupted = %+v, want esc/7", interrupt)
	}
}

func TestHandleEsc_RunningAppDoesNotQueueFromEventLoop(t *testing.T) {
	a := New(nil)
	store := escTestStore()
	a.SetActiveStore(store)
	a.SetStreamCanceller(&fakeStreamCanceller{retained: 5, inFlight: true})
	a.SetCommandFlush(func() error { return nil })
	a.AppendStreamDelta("partial")
	a.running.Store(true)
	defer a.running.Store(false)

	done := make(chan struct{})
	go func() {
		a.HandleEsc()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("HandleEsc blocked while running; event-loop ESC must not QueueUpdateDraw onto itself")
	}

	if a.transcript.streaming || a.transcript.streamBuf != "" {
		t.Fatalf("stream buffer still open: streaming=%v buf=%q", a.transcript.streaming, a.transcript.streamBuf)
	}
	interrupt := onlyStreamInterrupted(t, store)
	if interrupt.Source != "esc" || interrupt.ContentChars != 5 {
		t.Fatalf("stream_interrupted = %+v, want esc/5", interrupt)
	}
}

// TestHandleEsc_RunningAppSealsBufferedDeltasAndDropsStaleRender proves the direct
// event-loop interruption seals every buffered delta — not just the last rendered
// one — and invalidates the pending render, so the timer armed before the seal can
// neither re-render the sealed reply nor render the stream that follows it.
func TestHandleEsc_RunningAppSealsBufferedDeltasAndDropsStaleRender(t *testing.T) {
	a, stop := newRunningApp(t)
	defer stop()

	store := escTestStore()
	a.RunOnEventLoopForTest(func() {
		a.SetActiveStore(store)
		a.SetStreamCanceller(&fakeStreamCanceller{retained: 7, inFlight: true})
		a.SetCommandFlush(func() error { return nil })
	})

	timers := captureStreamRenderTimer(t, a)
	a.AppendStreamDelta("par")
	a.AppendStreamDelta("tial")
	stale := timers().fire

	a.RunOnEventLoopForTest(a.HandleEsc)

	sealed := "partial" + streamInterruptedMarker + visibleResponseLine
	if got := transcriptText(t, a); got != sealed {
		t.Fatalf("sealed transcript = %q, want %q", got, sealed)
	}
	if timers().pending {
		t.Fatal("ESC interruption left a pending stream render")
	}
	if interrupt := onlyStreamInterrupted(t, store); interrupt.Source != "esc" || interrupt.ContentChars != 7 {
		t.Fatalf("stream_interrupted = %+v, want esc/7", interrupt)
	}

	a.AppendStreamDelta("next reply")
	stale()

	if got := transcriptText(t, a); got != sealed {
		t.Fatalf("visible text after the stale timer = %q, want %q", got, sealed)
	}
}

func TestInterruptStream_AllowsNonEscSource(t *testing.T) {
	a := New(nil)
	store := escTestStore()
	a.SetActiveStore(store)
	a.SetStreamCanceller(&fakeStreamCanceller{retained: 3, inFlight: true})

	stopped, err := a.interruptStream("ctrl-c")
	if err != nil || !stopped {
		t.Fatalf("interruptStream stopped=%v err=%v, want stopped without error", stopped, err)
	}
	interrupt := onlyStreamInterrupted(t, store)
	if interrupt.Source != "ctrl-c" || interrupt.ContentChars != 3 {
		t.Fatalf("stream_interrupted = %+v, want ctrl-c/3", interrupt)
	}
}

// TestHandleEsc_OverlayDismissPreservesInput pins the overlay branch (the ESC order keeps
// it ahead of the clear): a single ESC over an open overlay dismisses it and leaves
// the typed buffer intact — it does not also clear.
func TestHandleEsc_OverlayDismissPreservesInput(t *testing.T) {
	a := New(nil)
	a.input.SetText("typed")
	a.ShowStatus("status")

	a.HandleEsc()

	if a.statusOpen {
		t.Fatal("status overlay still open after ESC")
	}
	if got := a.input.GetText(); got != "typed" {
		t.Fatalf("input after overlay ESC = %q, want preserved (a single ESC dismisses the overlay; it does not also clear)", got)
	}
}

// TestHandleEsc_ClearsNonEmptyInput pins the ESC clear branch: with no stream and no overlay, ESC
// clears a non-empty buffer and resets any armed CTRL-C exit window, mirroring
// HandleCtrlC step 2. A whitespace-only draft counts as non-empty, so it clears too.
func TestHandleEsc_ClearsNonEmptyInput(t *testing.T) {
	for _, tc := range []struct{ name, draft string }{
		{"typed text", "typed"},
		{"spaces only", "   "},
		{"tab only", "\t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			installFakeCtrlCClock(a)
			a.input.SetText(tc.draft)
			a.armCtrlCHint() // a prior empty CTRL-C left the exit window armed

			a.HandleEsc()

			if got := a.input.GetText(); got != "" {
				t.Fatalf("input = %q, want cleared (whitespace-only counts as non-empty)", got)
			}
			if a.ctrlCArmed || a.transcript.notice != "" {
				t.Fatalf("ESC clear did not reset the CTRL-C exit window: armed=%v notice=%q", a.ctrlCArmed, a.transcript.notice)
			}
		})
	}
}

// TestHandleEsc_EmptyBufferNoOp pins the ESC handler's lowest branch: ESC with no stream, no
// overlay, and an empty buffer is a pure no-op.
func TestHandleEsc_EmptyBufferNoOp(t *testing.T) {
	a := New(nil)

	a.HandleEsc()

	if got := a.input.GetText(); got != "" {
		t.Fatalf("input after empty-buffer ESC = %q, want empty (no-op)", got)
	}
}

func TestPromptUser_EscDismissesAsDefaultDeny(t *testing.T) {
	a := New(nil)
	a.input.SetText("typed")
	h := startPrompt(t, a, fullPromptRequest())

	h.key(tcell.KeyEscape)
	d := h.await()

	if d.Option != OptionDeny {
		t.Fatalf("Option = %d, want OptionDeny (%d)", d.Option, OptionDeny)
	}
	if want := defaultDenyPromptDecision().DenyEnvelope; d.DenyEnvelope != want {
		t.Fatalf("DenyEnvelope = %q, want default %q", d.DenyEnvelope, want)
	}
	if a.promptOpen || a.pages.HasPage(promptBasePage) {
		t.Fatal("prompt still open after ESC denial")
	}
	if got := a.input.GetText(); got != "typed" {
		t.Fatalf("input after prompt ESC = %q, want preserved", got)
	}
}

func TestPromptUser_ScopeChooserEscDismissesAsDefaultDeny(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, fullPromptRequest())

	h.down(2)
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopePage)

	h.key(tcell.KeyEscape)
	d := h.await()

	if d.Option != OptionDeny {
		t.Fatalf("Option = %d, want OptionDeny (%d)", d.Option, OptionDeny)
	}
	if want := defaultDenyPromptDecision().DenyEnvelope; d.DenyEnvelope != want {
		t.Fatalf("DenyEnvelope = %q, want default %q", d.DenyEnvelope, want)
	}
	if d.StoredSubject != "" {
		t.Fatalf("StoredSubject = %q, want empty (an abandoned scope choice creates no grant)", d.StoredSubject)
	}
	if a.promptOpen || a.pages.HasPage(promptBasePage) {
		t.Fatal("prompt still open after scope-chooser ESC denial")
	}
}

func TestInterruptStream_KeepsRecordInMemoryWhenFlushFails(t *testing.T) {
	a := New(nil)
	store := escTestStore()
	a.SetActiveStore(store)
	a.SetStreamCanceller(&fakeStreamCanceller{retained: 9, inFlight: true})
	flushErr := errors.New("flush failed")
	a.SetCommandFlush(func() error { return flushErr })

	stopped, err := a.interruptStream("esc")
	if !stopped || !errors.Is(err, flushErr) {
		t.Fatalf("interruptStream stopped=%v err=%v, want flush error", stopped, err)
	}
	interrupt := onlyStreamInterrupted(t, store)
	if interrupt.Source != "esc" || interrupt.ContentChars != 9 {
		t.Fatalf("stream_interrupted after flush failure = %+v, want esc/9", interrupt)
	}
}

func escTestStore() *sessions.Store {
	return escTestStoreAtPath("")
}

func escTestStoreAtPath(path string) *sessions.Store {
	started := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	return sessions.New(path, &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
			SchemaVersion: 1,
			Folder:        "/work",
			StartedAt:     started,
			UpdatedAt:     started,
		},
	})
}

func onlyStreamInterrupted(t *testing.T, store *sessions.Store) events.StreamInterrupted {
	t.Helper()
	return onlyStreamInterruptedRecord(t, store.Records())
}

func onlyStreamInterruptedRecord(t *testing.T, records []sessions.Record) events.StreamInterrupted {
	t.Helper()
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	ev, ok := records[0].(sessions.Event)
	if !ok {
		t.Fatalf("record type = %T, want sessions.Event", records[0])
	}
	if ev.Kind != events.KindStreamInterrupted {
		t.Fatalf("event kind = %q, want %q", ev.Kind, events.KindStreamInterrupted)
	}
	var payload events.StreamInterrupted
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		t.Fatalf("decode stream_interrupted: %v", err)
	}
	return payload
}
