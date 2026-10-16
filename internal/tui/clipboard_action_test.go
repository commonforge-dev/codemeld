// Action-level coverage for the CTRL-V clipboard-image binding: a successful read
// stages a pending attachment as a removable token through the pending-attachment model, every failure mode
// shows a friendly notice with no attachment and no panic, and the key routes only to the
// clipboard action — it does not submit, nor does any other global key (now including the
// retired CTRL-Y) reach the reader.
package tui

import (
	"context"
	"errors"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/sessions"
)

// fakeClipboardReader is the injected stand-in for the OS clipboard (an external
// resource), returning fixed results and counting calls so a test can prove which key
// reached it.
type fakeClipboardReader struct {
	mime  string
	data  []byte
	ok    bool
	err   error
	calls int
}

func (f *fakeClipboardReader) ReadImage(context.Context) (string, []byte, bool, error) {
	f.calls++
	return f.mime, f.data, f.ok, f.err
}

func pngBytes() []byte { return []byte("\x89PNG\r\n\x1a\nDATA") }

func TestCtrlV_AttachesClipboardImage(t *testing.T) {
	a := New(nil)
	a.SetClipboardReader(&fakeClipboardReader{mime: "image/png", data: pngBytes(), ok: true})

	if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlV, 0, tcell.ModNone)); ev != nil {
		t.Errorf("CTRL-V returned %v, want nil (consumed)", ev)
	}
	atts := a.input.imageAttachments()
	if len(atts) != 1 {
		t.Fatalf("pending attachments = %d, want 1", len(atts))
	}
	if atts[0].mime != "image/png" {
		t.Errorf("attachment mime = %q, want image/png", atts[0].mime)
	}
	// The clipboard image becomes an "[Image 1]" token in the buffer, not a bare notice.
	if got := a.input.GetText(); got != "[Image 1]" {
		t.Errorf("input buffer = %q, want %q (the clipboard image is a removable token)", got, "[Image 1]")
	}
	if got, want := atts[0].displayName(), "Image 1"; got != want {
		t.Errorf("attachment display name = %q, want %q", got, want)
	}
	if got := a.transcript.notice; got != attachedImageNotice(atts[0]) {
		t.Errorf("notice = %q, want the attached-image confirmation", got)
	}
}

func TestCtrlV_FriendlyNoticesOnFailure(t *testing.T) {
	cases := []struct {
		name   string
		reader *fakeClipboardReader
		notice string
	}{
		{"no helper", &fakeClipboardReader{err: errNoClipboardHelper}, noClipboardHelperNotice},
		{"no image", &fakeClipboardReader{ok: false}, "no image found in the clipboard"},
		{"timeout", &fakeClipboardReader{err: errClipboardTimeout}, "clipboard read timed out"},
		{"helper error", &fakeClipboardReader{err: errors.New("boom")}, "could not read an image from the clipboard"},
		{"not an image", &fakeClipboardReader{ok: true, data: []byte("plain text")}, imageAttachErrorNotice("clipboard image", errNotAnImage)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.SetClipboardReader(tc.reader)
			if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlV, 0, tcell.ModNone)); ev != nil {
				t.Errorf("CTRL-V returned %v, want nil (consumed)", ev)
			}
			if got := len(a.input.imageAttachments()); got != 0 {
				t.Fatalf("attachments = %d, want 0 on failure", got)
			}
			// A failed read inserts no token and consumes no "Image N" counter value.
			if got := a.input.GetText(); got != "" {
				t.Errorf("input buffer = %q, want empty on a failed clipboard read", got)
			}
			if got := a.transcript.notice; got != tc.notice {
				t.Errorf("notice = %q, want %q", got, tc.notice)
			}
		})
	}
}

// TestCtrlV_OnlyKeyThatReadsClipboard locks the binding's non-collision contract: no other
// global key reaches the clipboard reader — including the retired CTRL-Y, which is no
// longer bound to image paste — so Enter/chord submit, ESC-clear, shift+tab mode cycle, the
// global shortcuts, CTRL-Y, and the '@' picker trigger never paste an image, and CTRL-V
// itself reads exactly once. Bracketed paste is a separate path (the input field's
// PasteHandler, not handleGlobalKey), so it cannot reach here.
func TestCtrlV_OnlyKeyThatReadsClipboard(t *testing.T) {
	reader := &fakeClipboardReader{ok: false}
	a := New(nil)
	a.SetClipboardReader(reader)

	others := []tcell.Key{
		tcell.KeyEnter, tcell.KeyCR, tcell.KeyTab, tcell.KeyBacktab,
		tcell.KeyEscape, tcell.KeyCtrlE, tcell.KeyCtrlM, tcell.KeyCtrlR,
		tcell.KeyCtrlY, // CTRL-Y no longer reads the clipboard
	}
	for _, k := range others {
		a.handleGlobalKey(tcell.NewEventKey(k, 0, tcell.ModNone))
	}
	// The '@' file-picker trigger is a rune, not a special key.
	a.handleGlobalKey(tcell.NewEventKey(tcell.KeyRune, '@', tcell.ModNone))
	if reader.calls != 0 {
		t.Fatalf("clipboard reader called %d times by non-CTRL-V keys, want 0", reader.calls)
	}

	a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlV, 0, tcell.ModNone))
	if reader.calls != 1 {
		t.Fatalf("clipboard reader called %d times after CTRL-V, want exactly 1", reader.calls)
	}
}

// TestCtrlY_DoesNotReadClipboardOrStage is the focused regression: pressing the old
// CTRL-Y key neither reads the clipboard nor stages an attachment, so the rebind to CTRL-V
// fully retired the old binding rather than leaving it live alongside the new one.
func TestCtrlY_DoesNotReadClipboardOrStage(t *testing.T) {
	reader := &fakeClipboardReader{mime: "image/png", data: pngBytes(), ok: true}
	a := New(nil)
	a.SetClipboardReader(reader)

	a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlY, 0, tcell.ModNone))
	if reader.calls != 0 {
		t.Fatalf("CTRL-Y read the clipboard %d times, want 0 (f430 unbinds it)", reader.calls)
	}
	if n := len(a.input.imageAttachments()); n != 0 {
		t.Fatalf("CTRL-Y staged %d attachments, want 0", n)
	}
}

// TestCtrlY_DoesNotRedoInput drives CTRL-Y through the same fall-through the event loop
// uses — handleGlobalKey first, then route any returned (unconsumed) event into the input
// handler — and proves the prompt is unchanged. tview's TextArea binds KeyCtrlY to redo, so
// without the explicit CTRL-Y no-op case the returned event would restore an undone edit and
// mutate the prompt. The setup builds a live redo target (type, then undo) so the assertion
// is not vacuous.
func TestCtrlY_DoesNotRedoInput(t *testing.T) {
	a := New(nil)
	in := a.input
	noFocus := func(tview.Primitive) {}

	for _, r := range "hello" {
		in.InputHandler()(tcell.NewEventKey(tcell.KeyRune, r, tcell.ModNone), noFocus)
	}
	if got := in.GetText(); got != "hello" {
		t.Fatalf("setup: input = %q, want %q", got, "hello")
	}
	in.InputHandler()(tcell.NewEventKey(tcell.KeyCtrlZ, 0, tcell.ModNone), noFocus)
	afterUndo := in.GetText()
	if afterUndo == "hello" {
		t.Fatal("setup: undo did not change the buffer, so there is no redo target to test")
	}

	// Exactly the event-loop path: global handler, then the input handler for any leftover.
	if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlY, 0, tcell.ModNone)); ev != nil {
		in.InputHandler()(ev, noFocus)
	}
	if got := in.GetText(); got != afterUndo {
		t.Fatalf("CTRL-Y redid the undone edit via tview: input = %q, want %q unchanged (f430 no-op)", got, afterUndo)
	}
}

// TestCtrlV_DoesNotSubmit proves CTRL-V stages the attachment without submitting it — the
// submit hook fires only on the separate Enter path, so a staged clipboard image waits for
// the user to press Enter (matching the '@' picker).
func TestCtrlV_DoesNotSubmit(t *testing.T) {
	var submits int
	a := New(func(string, ...sessions.ContentPart) bool { submits++; return true })
	a.SetClipboardReader(&fakeClipboardReader{mime: "image/png", data: pngBytes(), ok: true})

	a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlV, 0, tcell.ModNone))
	if submits != 0 {
		t.Fatalf("submit hook fired %d times on CTRL-V, want 0 (CTRL-V stages, it does not submit)", submits)
	}
	if len(a.input.imageAttachments()) != 1 {
		t.Fatal("CTRL-V did not stage the pending attachment")
	}
	// Pressing Enter now submits the staged attachment as an image_url content part.
	if !a.SubmitCurrent() {
		t.Fatal("submit of the staged clipboard attachment was rejected")
	}
	if submits != 1 {
		t.Fatalf("submit hook fired %d times after Enter, want 1", submits)
	}
}
