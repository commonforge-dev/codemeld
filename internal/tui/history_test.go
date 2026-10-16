// Tests for the session input history: empty no-op, duplicate preservation,
// FIFO eviction, draft save/restore, cursor boundaries, snapshot, and wiring.
package tui

import (
	"strconv"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// TestHistory_UpEmptyIsNoOp covers TR-TUI-15: ↑ with an empty draft and empty
// history changes nothing and returns the draft unchanged.
func TestHistory_UpEmptyIsNoOp(t *testing.T) {
	h := NewHistory()
	if got := h.Up(""); got != "" {
		t.Fatalf("Up on empty history = %q, want %q", got, "")
	}
	if h.navigating() {
		t.Fatal("empty-history Up should not enter navigation")
	}
	if n := len(h.Snapshot()); n != 0 {
		t.Fatalf("empty-history Up changed buffer: len=%d", n)
	}
	// A non-empty draft is likewise returned unchanged on empty history.
	if got := h.Up("typed"); got != "typed" {
		t.Fatalf("Up on empty history = %q, want %q", got, "typed")
	}
}

func TestHistory_DuplicatesPreserved(t *testing.T) {
	h := NewHistory()
	h.Append("same")
	h.Append("same")
	h.Append("other")
	h.Append("same")
	want := []string{"same", "same", "other", "same"}
	got := h.Snapshot()
	if len(got) != len(want) {
		t.Fatalf("snapshot len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("snapshot[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestHistory_FIFOEvictionAtCap(t *testing.T) {
	h := NewHistory()
	total := defaultHistoryCap + 50
	for i := 0; i < total; i++ {
		h.Append("e" + strconv.Itoa(i))
	}
	snap := h.Snapshot()
	if len(snap) != defaultHistoryCap {
		t.Fatalf("snapshot len = %d, want %d", len(snap), defaultHistoryCap)
	}
	// The oldest 50 are gone; the survivors stay in submission order, newest last.
	if snap[0] != "e50" {
		t.Fatalf("oldest survivor = %q, want %q", snap[0], "e50")
	}
	if snap[len(snap)-1] != "e"+strconv.Itoa(total-1) {
		t.Fatalf("newest = %q, want %q", snap[len(snap)-1], "e"+strconv.Itoa(total-1))
	}
}

func TestHistory_DraftSaveAndRestore(t *testing.T) {
	h := NewHistory()
	h.Append("first")
	h.Append("second")

	// ↑ from the live line saves the draft and loads the newest entry.
	if got := h.Up("draft-in-progress"); got != "second" {
		t.Fatalf("first Up = %q, want %q", got, "second")
	}
	// ↑ again walks farther back.
	if got := h.Up("ignored"); got != "first" {
		t.Fatalf("second Up = %q, want %q", got, "first")
	}
	// ↓ walks forward to the newest entry.
	if got := h.Down(); got != "second" {
		t.Fatalf("Down = %q, want %q", got, "second")
	}
	// ↓ past the newest restores the originally saved draft.
	if got := h.Down(); got != "draft-in-progress" {
		t.Fatalf("Down to draft = %q, want %q", got, "draft-in-progress")
	}
	if h.navigating() {
		t.Fatal("restoring the draft should leave navigation")
	}
}

func TestHistory_CursorBoundaries(t *testing.T) {
	h := NewHistory()
	h.Append("a")
	h.Append("b")

	if got := h.Up("d"); got != "b" {
		t.Fatalf("Up = %q, want b", got)
	}
	if got := h.Up("d"); got != "a" {
		t.Fatalf("Up = %q, want a", got)
	}
	// Repeated ↑ at the oldest entry stays there.
	if got := h.Up("d"); got != "a" {
		t.Fatalf("Up at oldest = %q, want a", got)
	}
	// Walk back down to the draft.
	if got := h.Down(); got != "b" {
		t.Fatalf("Down = %q, want b", got)
	}
	if got := h.Down(); got != "d" {
		t.Fatalf("Down to draft = %q, want d", got)
	}
	// Repeated ↓ past the draft stays on the draft.
	if got := h.Down(); got != "d" {
		t.Fatalf("Down past draft = %q, want d", got)
	}
}

func TestHistory_AppendResetsNavigation(t *testing.T) {
	h := NewHistory()
	h.Append("one")
	h.Up("draft") // enter navigation on "one"
	if !h.navigating() {
		t.Fatal("expected navigation after Up")
	}
	h.Append("two")
	if h.navigating() {
		t.Fatal("Append should reset navigation to the live line")
	}
	// The next ↑ starts from the newest entry and re-saves the new draft.
	if got := h.Up("fresh"); got != "two" {
		t.Fatalf("Up after Append = %q, want two", got)
	}
	if got := h.Down(); got != "fresh" {
		t.Fatalf("Down to draft after Append = %q, want fresh", got)
	}
}

func TestHistory_SnapshotIsCopyInOrderAfterEviction(t *testing.T) {
	h := NewHistory()
	for i := 0; i < defaultHistoryCap+5; i++ {
		h.Append("v" + strconv.Itoa(i))
	}
	snap := h.Snapshot()
	// Mutating the returned slice must not affect stored history.
	snap[0] = "tampered"
	again := h.Snapshot()
	if again[0] == "tampered" {
		t.Fatal("Snapshot returned a view into internal storage, not a copy")
	}
	if again[0] != "v5" {
		t.Fatalf("post-eviction oldest = %q, want v5", again[0])
	}
}

func TestNew_StartsWithEmptyHistory(t *testing.T) {
	a := New(nil)
	if a.history == nil {
		t.Fatal("New did not initialize history")
	}
	if n := len(a.history.Snapshot()); n != 0 {
		t.Fatalf("fresh app history not empty: len=%d", n)
	}
}

// TestSubmitCurrent_AppendsBeforeDispatchOutcome proves history records both
// accepted and rejected submissions, in order, at the Enter boundary.
func TestSubmitCurrent_AppendsBeforeDispatchOutcome(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		var got []string
		a := New(recordingHook(true, &got))
		a.input.SetText("accept me")
		a.submitCurrent()
		snap := a.history.Snapshot()
		if len(snap) != 1 || snap[0] != "accept me" {
			t.Fatalf("history = %v, want [accept me]", snap)
		}
	})
	t.Run("rejected", func(t *testing.T) {
		var got []string
		a := New(recordingHook(false, &got))
		a.input.SetText("reject me")
		a.submitCurrent()
		snap := a.history.Snapshot()
		if len(snap) != 1 || snap[0] != "reject me" {
			t.Fatalf("rejected input not recorded: %v", snap)
		}
	})
	t.Run("whitespace ignored", func(t *testing.T) {
		var got []string
		a := New(recordingHook(true, &got))
		a.input.SetText("   ")
		a.submitCurrent()
		if n := len(a.history.Snapshot()); n != 0 {
			t.Fatalf("whitespace-only submission recorded: len=%d", n)
		}
	})
}

// TestHandleInputKey_NavigatesInputField proves the ↑/↓ binding drives the input
// field through the history store while the input area is focused. It sends the
// keys through the InputField's registered input handler (not handleInputKey
// directly), so removing the a.input.SetInputCapture(a.handleInputKey) wiring in
// New would make this test fail.
func TestHandleInputKey_NavigatesInputField(t *testing.T) {
	var got []string
	a := New(recordingHook(true, &got))

	a.input.SetText("alpha")
	a.submitCurrent()
	a.input.SetText("beta")
	a.submitCurrent()

	// Drive keys through the registered InputField input handler, which applies
	// the SetInputCapture wiring before the field's own handling.
	handler := a.input.InputHandler()
	noFocus := func(tview.Primitive) {}
	send := func(key tcell.Key) {
		handler(tcell.NewEventKey(key, 0, tcell.ModNone), noFocus)
	}

	a.input.SetText("draft")
	send(tcell.KeyUp)
	if txt := a.input.GetText(); txt != "beta" {
		t.Fatalf("after Up, field = %q, want beta", txt)
	}
	send(tcell.KeyUp)
	if txt := a.input.GetText(); txt != "alpha" {
		t.Fatalf("after second Up, field = %q, want alpha", txt)
	}

	send(tcell.KeyDown)
	if txt := a.input.GetText(); txt != "beta" {
		t.Fatalf("after Down, field = %q, want beta", txt)
	}
	send(tcell.KeyDown)
	if txt := a.input.GetText(); txt != "draft" {
		t.Fatalf("after Down to draft, field = %q, want draft", txt)
	}
}

// TestHandleInputKey_DownOnLiveLineLeavesText proves ↓ with no navigation
// underway does not clobber what the user is typing.
func TestHandleInputKey_DownOnLiveLineLeavesText(t *testing.T) {
	var got []string
	a := New(recordingHook(true, &got))
	a.input.SetText("typing")
	down := tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)
	a.handleInputKey(down)
	if txt := a.input.GetText(); txt != "typing" {
		t.Fatalf("Down on live line clobbered text: %q", txt)
	}
}

// TestHandleInputKey_OtherKeysFallThrough proves non-arrow keys are returned
// unchanged so normal typing reaches the input field.
func TestHandleInputKey_OtherKeysFallThrough(t *testing.T) {
	a := New(nil)
	ev := tcell.NewEventKey(tcell.KeyRune, 'x', tcell.ModNone)
	if got := a.handleInputKey(ev); got != ev {
		t.Fatal("non-arrow key should fall through to the input field")
	}
}
