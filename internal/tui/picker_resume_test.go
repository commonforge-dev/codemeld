// Tests for the production /resume picker overlay (Resolution — Option A):
// the continuation fires Selected/Index on Enter and a dismissal on ESC, the
// empty-folder overlay dismisses on any key, and the overlay registers in
// anyOverlayOpen — all driven through a tcell simulation screen so the real
// app-level focus + key handling is exercised without a terminal (mirroring the
// CTRL-M model picker's live-key test).
package tui

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/rivo/uniseg"

	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/sessions"
)

func resumePickerEntries() []ResumeEntry {
	return []ResumeEntry{
		{ID: "0190aaaa", Preview: "first prompt a"},
		{ID: "0190bbbb", Preview: "first prompt b"},
	}
}

// hasResumePicker reports, synchronously, whether the resume-picker page is
// currently mounted — the read runs on the event-loop goroutine and is delivered
// back over a channel so it never races the loop.
func hasResumePicker(a *App) bool {
	ch := make(chan bool, 1)
	a.app.QueueUpdate(func() { ch <- a.pages.HasPage(resumePickerPage) })
	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		return false
	}
}

func waitResumePicker(t *testing.T, a *App, want bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for hasResumePicker(a) != want {
		if time.Now().After(deadline) {
			a.app.Stop()
			t.Fatalf("resume picker page present=%v not reached within 2s", want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestResumePicker_EnterResolvesSelection pins the Option-A continuation: Present
// returns to the event loop immediately, and Down+Enter resolves onResult with the
// highlighted row — never blocking the loop.
func TestResumePicker_EnterResolvesSelection(t *testing.T) {
	a := New(nil)
	screen := tcell.NewSimulationScreen("UTF-8")
	a.app.SetScreen(screen)
	errc := make(chan error, 1)
	go func() { errc <- a.app.Run() }()

	resultc := make(chan PickerResult, 1)
	a.app.QueueUpdate(func() {
		a.openResumePicker(resumePickerEntries(), func(res PickerResult) { resultc <- res }, ResumeActions{})
	})
	waitResumePicker(t, a, true)
	if !a.anyOverlayOpen() {
		t.Error("anyOverlayOpen() = false while the resume picker is open")
	}

	screen.InjectKey(tcell.KeyDown, 0, tcell.ModNone)
	screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	waitResumePicker(t, a, false)

	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}
	select {
	case got := <-resultc:
		if !got.Selected || got.Index != 1 {
			t.Errorf("onResult = %+v, want Selected index 1", got)
		}
	default:
		t.Fatal("onResult was not invoked on Enter")
	}
}

// TestResumePicker_HeaderRowPresent pins the fixed column header: row 0 labels the
// session and time columns, both header cells are non-selectable and carry no entry
// reference, and the first entry sits at row resumeHeaderRows with its orig-index
// reference. If the header were dropped or made selectable, or entries were not offset,
// this fails.
func TestResumePicker_HeaderRowPresent(t *testing.T) {
	a := New(nil)
	a.openResumePicker(resumePickerEntries(), func(PickerResult) {}, ResumeActions{})

	tbl := a.resumePicker.table
	hdrLeft := tbl.GetCell(0, 0)
	hdrRight := tbl.GetCell(0, 1)
	if hdrLeft.Text != resumeHeaderSession {
		t.Errorf("header col 0 = %q, want %q", hdrLeft.Text, resumeHeaderSession)
	}
	if hdrRight.Text != resumeHeaderTimes {
		t.Errorf("header col 1 = %q, want %q", hdrRight.Text, resumeHeaderTimes)
	}
	if !hdrLeft.NotSelectable || !hdrRight.NotSelectable {
		t.Errorf("header cells selectable (col0=%v col1=%v), want both non-selectable", !hdrLeft.NotSelectable, !hdrRight.NotSelectable)
	}
	if _, ok := hdrLeft.GetReference().(int); ok {
		t.Error("header cell carries an entry reference; want none so it cannot resolve to a session")
	}
	if _, ok := tbl.GetCell(resumeHeaderRows, 0).GetReference().(int); !ok {
		t.Errorf("first entry row %d missing its orig-index reference", resumeHeaderRows)
	}
}

// simResumeRowText returns the concatenated rune text of one rendered row of a
// simulation screen, for asserting which row a primitive actually painted where.
func simResumeRowText(screen tcell.SimulationScreen, row int) string {
	cells, width, _ := screen.GetContents()
	var b strings.Builder
	for col := 0; col < width; col++ {
		for _, r := range cells[row*width+col].Runes {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TestResumePicker_HeaderStaysFixedWhenScrolled pins the SetFixed(resumeHeaderRows, 0)
// contract at the render boundary: with far more entries than fit the viewport and the
// selection driven to the last row, the table scrolls the body, yet the fixed header
// labels stay painted on the top rendered row. If table.SetFixed(resumeHeaderRows, 0)
// were removed from openResumePicker the header would scroll out of view and row 0 would
// show a mid-list entry instead, so this fails. It draws the real tview.Table (not a
// duplicated constant check) onto a constrained simulation screen.
func TestResumePicker_HeaderStaysFixedWhenScrolled(t *testing.T) {
	a := New(nil)
	entries := make([]ResumeEntry, 30)
	for i := range entries {
		entries[i] = ResumeEntry{ID: fmt.Sprintf("id-%02d", i), Preview: fmt.Sprintf("entry %02d", i)}
	}
	a.openResumePicker(entries, func(PickerResult) {}, ResumeActions{})

	tbl := a.resumePicker.table
	// Drive the cursor to the last entry so the body must scroll well past the header.
	tbl.Select(len(entries)-1+resumeHeaderRows, 0)

	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init: %v", err)
	}
	const width, height = 60, 10
	screen.SetSize(width, height)
	tbl.SetRect(0, 0, width, height)
	tbl.Draw(screen)
	screen.Show() // flush the back buffer so GetContents sees the painted cells.

	if top := simResumeRowText(screen, 0); !strings.Contains(top, resumeHeaderSession) {
		t.Errorf("top rendered row = %q, want the fixed header %q painted while scrolled to the last entry", top, resumeHeaderSession)
	}
}

// TestResumePicker_HighlightOffsetByHeader pins the row→entry mapping under the header:
// initial selection lands on the first entry (not the header), the highlighted entry
// tracks the cursor with the +1 offset, and the header row resolves to no entry. This
// would fail if any rename/delete path treated row 0 as an entry or were off by one.
func TestResumePicker_HighlightOffsetByHeader(t *testing.T) {
	a := New(nil)
	entries := []ResumeEntry{
		{ID: "id-a", Preview: "a"},
		{ID: "id-b", Preview: "b"},
	}
	a.openResumePicker(entries, func(PickerResult) {}, ResumeActions{})

	if row, _ := a.resumePicker.table.GetSelection(); row != resumeHeaderRows {
		t.Fatalf("initial selection row = %d, want %d (first entry, not the header)", row, resumeHeaderRows)
	}
	if e, ok := a.resumeHighlightedEntry(); !ok || e.ID != "id-a" {
		t.Errorf("highlighted entry = %+v ok=%v, want id-a", e, ok)
	}

	a.resumePicker.table.Select(resumeHeaderRows+1, 0)
	if e, ok := a.resumeHighlightedEntry(); !ok || e.ID != "id-b" {
		t.Errorf("highlighted entry after moving down = %+v ok=%v, want id-b", e, ok)
	}

	a.resumePicker.table.Select(0, 0)
	if e, ok := a.resumeHighlightedEntry(); ok {
		t.Errorf("header row resolved to entry %+v, want no entry under the header", e)
	}
}

// TestResumePicker_EscResolvesDismissal pins ESC: the continuation fires with
// Selected=false and the overlay tears down, restoring the input focus.
func TestResumePicker_EscResolvesDismissal(t *testing.T) {
	a := New(nil)
	screen := tcell.NewSimulationScreen("UTF-8")
	a.app.SetScreen(screen)
	errc := make(chan error, 1)
	go func() { errc <- a.app.Run() }()

	resultc := make(chan PickerResult, 1)
	a.app.QueueUpdate(func() {
		a.openResumePicker(resumePickerEntries(), func(res PickerResult) { resultc <- res }, ResumeActions{})
	})
	waitResumePicker(t, a, true)

	screen.InjectKey(tcell.KeyEscape, 0, tcell.ModNone)
	waitResumePicker(t, a, false)

	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}
	select {
	case got := <-resultc:
		if got.Selected {
			t.Errorf("onResult = %+v, want a dismissal (Selected=false)", got)
		}
	default:
		t.Fatal("onResult was not invoked on ESC")
	}
}

// TestResumePicker_EmptyDismissesOnAnyKey pins the empty-folder overlay:
// it shows the message and invokes onDismiss on any keypress.
func TestResumePicker_EmptyDismissesOnAnyKey(t *testing.T) {
	a := New(nil)
	screen := tcell.NewSimulationScreen("UTF-8")
	a.app.SetScreen(screen)
	errc := make(chan error, 1)
	go func() { errc <- a.app.Run() }()

	donec := make(chan struct{}, 1)
	a.app.QueueUpdate(func() {
		a.presentResumeEmpty(noResumableSessionsMsg, func() { donec <- struct{}{} })
	})
	waitResumePicker(t, a, true)

	screen.InjectKey(tcell.KeyRune, 'x', tcell.ModNone)
	waitResumePicker(t, a, false)

	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}
	select {
	case <-donec:
	default:
		t.Fatal("onDismiss was not invoked on a keypress")
	}
}

// TestResumeFooterHint pins the redesigned footer (DW): the one-row legend below the
// picker reads exactly "delete ctrl+d   rename ctrl+r".
func TestResumeFooterHint(t *testing.T) {
	if resumeFooterHint != "delete ctrl+d   rename ctrl+r" {
		t.Errorf("footer hint = %q, want %q", resumeFooterHint, "delete ctrl+d   rename ctrl+r")
	}
}

// TestResumePicker_RenameRefreshesRow drives the rename action seam: applying a typed
// title invokes actions.Rename and then re-lists, so the picker row shows the new title
// (overriding the preview). The persistence + lock-contention contract is covered by
// sessions.SetTitle's own tests; here the picker wiring is exercised with a fake action.
func TestResumePicker_RenameRefreshesRow(t *testing.T) {
	a := New(nil)
	entries := []ResumeEntry{{ID: "id-a", Preview: "first prompt a"}}
	var gotTitle string
	called := false
	actions := ResumeActions{
		Rename: func(_ ResumeEntry, title string) error {
			gotTitle, called = title, true
			return nil
		},
		ReList: func() ([]ResumeEntry, error) {
			// Model the persisted title being read back on refresh.
			return []ResumeEntry{{ID: "id-a", Preview: "first prompt a", Title: gotTitle}}, nil
		},
	}
	a.openResumePicker(entries, func(PickerResult) {}, actions)

	a.applyResumeRename(entries[0], "My Session")

	if !called || gotTitle != "My Session" {
		t.Fatalf("Rename action called=%v title=%q, want true / %q", called, gotTitle, "My Session")
	}
	if got := a.resumePicker.table.GetCell(resumeHeaderRows, 0).Text; got != "My Session" {
		t.Errorf("row title after rename = %q, want %q (title overrides preview)", got, "My Session")
	}
}

// TestResumePicker_RenameCancelDoesNotMutate pins the ESC-cancel path: ctrl+r mounts the
// rename overlay, and cancelling it removes the overlay without invoking Rename.
func TestResumePicker_RenameCancelDoesNotMutate(t *testing.T) {
	a := New(nil)
	entries := []ResumeEntry{{ID: "id-a", Preview: "p"}}
	called := false
	actions := ResumeActions{
		Rename: func(ResumeEntry, string) error { called = true; return nil },
		ReList: func() ([]ResumeEntry, error) { return entries, nil },
	}
	a.openResumePicker(entries, func(PickerResult) {}, actions)

	a.resumePickerKeys(tcell.NewEventKey(tcell.KeyCtrlR, 0, tcell.ModNone))
	if !a.pages.HasPage(resumeRenamePage) {
		t.Fatal("ctrl+r did not mount the rename overlay")
	}
	a.cancelResumeChild()
	if a.pages.HasPage(resumeRenamePage) {
		t.Error("rename overlay still mounted after cancel")
	}
	if called {
		t.Error("Rename ran on cancel, want no mutation")
	}
}

// TestResumePicker_DeleteRefreshesRows drives the delete action seam: deleting the
// highlighted row invokes actions.Delete and re-lists, so the row disappears while the
// picker stays open.
func TestResumePicker_DeleteRefreshesRows(t *testing.T) {
	a := New(nil)
	entries := []ResumeEntry{
		{ID: "id-a", Preview: "a"},
		{ID: "id-b", Preview: "b"},
	}
	deleted := ""
	actions := ResumeActions{
		Delete: func(e ResumeEntry) error { deleted = e.ID; return nil },
		ReList: func() ([]ResumeEntry, error) { return []ResumeEntry{{ID: "id-b", Preview: "b"}}, nil },
	}
	a.openResumePicker(entries, func(PickerResult) {}, actions)

	a.applyResumeDelete(entries[0])

	if deleted != "id-a" {
		t.Fatalf("Delete called for %q, want id-a", deleted)
	}
	if !a.resumePickerOpen {
		t.Fatal("picker closed after deleting one of two sessions")
	}
	if n := a.resumePicker.table.GetRowCount(); n != 1+resumeHeaderRows {
		t.Errorf("table row count = %d, want %d (header + 1 entry) after delete+refresh", n, 1+resumeHeaderRows)
	}
	if got := a.resumePicker.table.GetCell(resumeHeaderRows, 0).Text; got != "b" {
		t.Errorf("remaining row title = %q, want %q", got, "b")
	}
}

// TestResumePicker_DeleteConfirmationRequiredBeforeMutation pins that ctrl+d only opens
// the confirmation — the Delete action does not run until the user confirms.
func TestResumePicker_DeleteConfirmationRequiredBeforeMutation(t *testing.T) {
	a := New(nil)
	entries := []ResumeEntry{{ID: "id-a", Preview: "a"}}
	called := false
	actions := ResumeActions{
		Delete: func(ResumeEntry) error { called = true; return nil },
		ReList: func() ([]ResumeEntry, error) { return entries, nil },
	}
	a.openResumePicker(entries, func(PickerResult) {}, actions)

	a.resumePickerKeys(tcell.NewEventKey(tcell.KeyCtrlD, 0, tcell.ModNone))
	if !a.pages.HasPage(resumeDeletePage) {
		t.Fatal("ctrl+d did not mount the delete confirmation")
	}
	if called {
		t.Error("Delete ran before confirmation, want confirmation first")
	}
}

// TestResumePicker_RenameTargetsSelectedRowViaActionPath drives rename through the real
// row→entry seam: it selects the second data row (header + 1) and invokes showResumeRename
// — the same production entry point ctrl+r reaches — then submits a title through the focused
// input. It proves the action boundary maps the highlighted table row to the second session
// after the header offset: the prefilled title is the second row's, and Rename receives
// id-b. It would fail if showResumeRename used the unadjusted table row (→ no entry under the
// offset, no input) or hard-coded the first entry (→ id-a).
func TestResumePicker_RenameTargetsSelectedRowViaActionPath(t *testing.T) {
	a := New(nil)
	entries := []ResumeEntry{
		{ID: "id-a", Title: "alpha", Preview: "a"},
		{ID: "id-b", Title: "beta", Preview: "b"},
	}
	var gotID, gotTitle string
	actions := ResumeActions{
		Rename: func(e ResumeEntry, title string) error { gotID, gotTitle = e.ID, title; return nil },
		ReList: func() ([]ResumeEntry, error) { return entries, nil },
	}
	a.openResumePicker(entries, func(PickerResult) {}, actions)

	// Select the second data row, then open rename through the production seam.
	a.resumePicker.table.Select(resumeHeaderRows+1, 0)
	a.showResumeRename()

	field, ok := a.app.GetFocus().(*tview.InputField)
	if !ok {
		t.Fatal("showResumeRename did not focus the rename input for the selected row")
	}
	if field.GetText() != "beta" {
		t.Errorf("rename input prefilled with %q, want %q (the selected second row's title)", field.GetText(), "beta")
	}

	field.SetText("renamed")
	field.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})

	if gotID != "id-b" {
		t.Errorf("Rename received id %q, want id-b (the selected second row)", gotID)
	}
	if gotTitle != "renamed" {
		t.Errorf("Rename received title %q, want %q (submitted through the focused input)", gotTitle, "renamed")
	}
}

func TestResumePicker_NonUserSetRowFallsBackAndPrefillsEmpty(t *testing.T) {
	a := New(nil)
	entries := []ResumeEntry{
		{ID: "id-generated", Preview: "first prompt"},
		{ID: "id-untitled"},
		{ID: "id-named", Title: "My session", Preview: "another prompt"},
	}
	a.openResumePicker(entries, func(PickerResult) {}, ResumeActions{
		Rename: func(ResumeEntry, string) error { return nil },
		ReList: func() ([]ResumeEntry, error) { return entries, nil },
	})

	wantRows := []struct {
		row  int
		text string
	}{
		{resumeHeaderRows, "first prompt"},
		{resumeHeaderRows + 1, resumeUntitledLabel},
		{resumeHeaderRows + 2, "My session"},
	}
	for _, w := range wantRows {
		cell := a.resumePicker.table.GetCell(w.row, 0)
		if cell == nil {
			t.Fatalf("table row %d column 0 is missing", w.row)
		}
		if cell.Text != w.text {
			t.Errorf("table row %d = %q, want %q", w.row, cell.Text, w.text)
		}
	}

	prefill := func(t *testing.T, row int) string {
		t.Helper()
		a.resumePicker.table.Select(row, 0)
		a.showResumeRename()
		field, ok := a.app.GetFocus().(*tview.InputField)
		if !ok {
			t.Fatal("showResumeRename did not focus the rename input")
		}
		text := field.GetText()
		a.cancelResumeChild()
		return text
	}
	if got := prefill(t, resumeHeaderRows); got != "" {
		t.Errorf("rename prefill for the generated-title row = %q, want empty", got)
	}
	if got := prefill(t, resumeHeaderRows+2); got != "My session" {
		t.Errorf("rename prefill for the user-set row = %q, want %q", got, "My session")
	}
}

func TestResumePicker_RenameLabelNotYellow(t *testing.T) {
	a := New(nil)
	entries := []ResumeEntry{{ID: "id-a", Title: "alpha", Preview: "a"}}
	actions := ResumeActions{Rename: func(ResumeEntry, string) error { return nil }}
	a.openResumePicker(entries, func(PickerResult) {}, actions)

	a.resumePicker.table.Select(resumeHeaderRows, 0)
	a.showResumeRename()

	const label = "title "
	s := drawPrimitive(t, a.pages, 60, 12)
	cells, width, _ := s.GetContents()

	row, col := findCell(t, s, label)
	for c := col; c < col+len(label); c++ {
		fg, bg, _ := cells[row*width+c].Style.Decompose()
		if isYellow(fg) || isYellow(bg) {
			t.Errorf("rename label cell (%d,%d) uses fixed yellow (fg=%06X bg=%06X)", row, c, fg.Hex(), bg.Hex())
		}
	}
}

// TestResumePicker_DeleteTargetsSelectedRowViaActionPath drives delete through the real
// row→entry seam: it selects the second data row (header + 1) and invokes showResumeDelete
// — the same production entry point ctrl+d reaches — then confirms the modal. It proves the
// action boundary maps the highlighted table row to the second session after the header
// offset: Delete receives id-b. It would fail if showResumeDelete used the unadjusted table
// row (→ no entry under the offset, no confirmation) or hard-coded the first entry (→ id-a).
func TestResumePicker_DeleteTargetsSelectedRowViaActionPath(t *testing.T) {
	a := New(nil)
	entries := []ResumeEntry{
		{ID: "id-a", Title: "alpha", Preview: "a"},
		{ID: "id-b", Title: "beta", Preview: "b"},
	}
	deleted := ""
	actions := ResumeActions{
		Delete: func(e ResumeEntry) error { deleted = e.ID; return nil },
		ReList: func() ([]ResumeEntry, error) { return []ResumeEntry{{ID: "id-a", Title: "alpha", Preview: "a"}}, nil },
	}
	a.openResumePicker(entries, func(PickerResult) {}, actions)

	// Select the second data row, then open the delete confirmation through the seam.
	a.resumePicker.table.Select(resumeHeaderRows+1, 0)
	a.showResumeDelete()

	focus := a.app.GetFocus()
	if focus == nil {
		t.Fatal("showResumeDelete did not focus the confirmation for the selected row")
	}
	// The modal's default-focused button is "Delete"; Enter confirms it, mirroring the
	// production confirm keystroke.
	focus.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})

	if deleted != "id-b" {
		t.Errorf("Delete received id %q, want id-b (the selected second row)", deleted)
	}
}

// TestResumePicker_DeleteLastDismissesPicker pins the empty-after-refresh path: deleting
// the only remaining session closes the picker and resolves the continuation as a
// dismissal (the durable picker-open success already stands).
func TestResumePicker_DeleteLastDismissesPicker(t *testing.T) {
	a := New(nil)
	entries := []ResumeEntry{{ID: "id-a", Preview: "a"}}
	resultc := make(chan PickerResult, 1)
	actions := ResumeActions{
		Delete: func(ResumeEntry) error { return nil },
		ReList: func() ([]ResumeEntry, error) { return nil, nil },
	}
	a.openResumePicker(entries, func(r PickerResult) { resultc <- r }, actions)

	a.applyResumeDelete(entries[0])

	if a.resumePickerOpen {
		t.Error("picker still open after deleting the last session")
	}
	select {
	case r := <-resultc:
		if r.Selected {
			t.Errorf("onResult = %+v, want a dismissal after the list emptied", r)
		}
	default:
		t.Fatal("onResult not resolved after the list emptied")
	}
}

// TestResumeRowTitle covers the single-line title resolution (redesign): a
// stored title overrides the auto-derived preview, the preview is the fallback, an
// untitled/preview-less row reads as "New session", and an over-long value is rune-safely
// capped. The session id is never used as a fallback.
func TestResumeRowTitle(t *testing.T) {
	if resumeUntitledLabel != "New session" {
		t.Errorf("fallback label = %q, want %q", resumeUntitledLabel, "New session")
	}
	if got := resumeRowTitle(ResumeEntry{Title: "my title", Preview: "first prompt"}); got != "my title" {
		t.Errorf("title set: row title = %q, want the stored title to override the preview", got)
	}
	if got := resumeRowTitle(ResumeEntry{Preview: "first prompt"}); got != "first prompt" {
		t.Errorf("no title: row title = %q, want the preview fallback", got)
	}
	if got := resumeRowTitle(ResumeEntry{ID: "0190aaaa-bbbb"}); got != "New session" {
		t.Errorf("no title/preview: row title = %q, want %q (never the id)", got, "New session")
	}
}

// TestResumeRowTitle_MiddleTruncatesOverBudget pins the head + one ellipsis + tail shape
// that makes two long prompts sharing a prefix distinguishable: the trailing task id
// survives the cut, exactly one ellipsis appears, and the result fits the title budget.
func TestResumeRowTitle_MiddleTruncatesOverBudget(t *testing.T) {
	long := "please refactor the resume picker layout " + strings.Repeat("and tidy it ", 8) + "for task i870"

	got := resumeRowTitle(ResumeEntry{Preview: long})

	if uniseg.StringWidth(got) > resumeTitleCells {
		t.Errorf("row title %q = %d cells, want at most %d", got, uniseg.StringWidth(got), resumeTitleCells)
	}
	if n := strings.Count(got, "…"); n != 1 {
		t.Errorf("row title %q has %d ellipses, want exactly 1", got, n)
	}
	if !strings.HasPrefix(got, "please") {
		t.Errorf("row title %q dropped the head", got)
	}
	if !strings.Contains(got, "for task i870") {
		t.Errorf("row title %q dropped the distinguishing tail %q", got, "for task i870")
	}
}

// TestResumeRowTitle_ExactBudgetUnchanged pins the boundary: text that exactly fills the
// title budget is rendered verbatim, and one more cell forces the middle cut.
func TestResumeRowTitle_ExactBudgetUnchanged(t *testing.T) {
	exact := strings.Repeat("a", resumeTitleCells)
	if got := resumeRowTitle(ResumeEntry{Preview: exact}); got != exact {
		t.Errorf("exact-budget title = %q, want it unchanged", got)
	}
	if got := resumeRowTitle(ResumeEntry{Preview: exact + "b"}); !strings.Contains(got, "…") {
		t.Errorf("over-budget-by-one title = %q, want a middle ellipsis", got)
	}
}

// TestResumeRowTitle_GraphemeSafe pins that fitting cuts on grapheme clusters measured
// in terminal cells, not runes: for wide CJK, a multi-rune emoji ZWJ sequence, and
// combining marks, the retained head and tail must each end on a cluster boundary of the
// input, and the result must fit a budget a rune count would overshoot.
func TestResumeRowTitle_GraphemeSafe(t *testing.T) {
	cases := map[string]string{
		"cjk":       strings.Repeat("漢字", 60) + "for task i870",
		"emoji":     strings.Repeat("👨‍👩‍👧‍👦", 30) + "for task i870",
		"combining": strings.Repeat("e\u0301", 90) + "for task i870",
	}
	for name, text := range cases {
		got := resumeRowTitle(ResumeEntry{Preview: text})
		if w := uniseg.StringWidth(got); w > resumeTitleCells {
			t.Errorf("%s: row title %q = %d cells, want at most %d", name, got, w, resumeTitleCells)
		}
		head, tail, cut := strings.Cut(got, "…")
		if !cut {
			t.Fatalf("%s: row title %q was not truncated; the fixture is too short to exercise cutting", name, got)
		}
		if !strings.Contains(tail, "for task i870") {
			t.Errorf("%s: row title %q dropped the tail", name, got)
		}
		bounds := clusterBoundaries(text)
		if !bounds[len(head)] {
			t.Errorf("%s: head %q ends at byte %d, which is inside a grapheme cluster", name, head, len(head))
		}
		if !bounds[len(text)-len(tail)] {
			t.Errorf("%s: tail %q starts at byte %d, which is inside a grapheme cluster", name, tail, len(text)-len(tail))
		}
	}
}

// clusterBoundaries returns the byte offsets in s that fall between grapheme clusters,
// so a test can assert a cut never landed inside one.
func clusterBoundaries(s string) map[int]bool {
	bounds := map[int]bool{0: true}
	rest, state, off := s, -1, 0
	for rest != "" {
		cluster, next, _, st := uniseg.StepString(rest, state)
		off += len(cluster)
		bounds[off] = true
		rest, state = next, st
	}
	return bounds
}

// TestResumeCellBudgetsFitBorderedBody pins the layout arithmetic the rendered row
// depends on: the two named budgets plus tview's one-cell column gap must fit the 78
// inner cells an 80-column bordered body leaves. Raising either budget fails here rather
// than silently clipping the row at render time.
func TestResumeCellBudgetsFitBorderedBody(t *testing.T) {
	if resumeTitleCells+1+resumeTimeCells > resumeBodyInnerCells {
		t.Errorf("title %d + gap 1 + time %d exceeds the %d inner cells of an 80-column bordered body",
			resumeTitleCells, resumeTimeCells, resumeBodyInnerCells)
	}
	if resumeTitleCells < 1 || resumeTimeCells < 1 {
		t.Errorf("budgets must be positive, got title=%d time=%d", resumeTitleCells, resumeTimeCells)
	}
}

// TestResumePicker_RowRendersTitlePreviewAndNewSessionFallback pins the production
// table-render path (not just the resumeRowTitle helper): with a stored-title row, a
// preview-only row, and a no-title/no-preview row, column 0 must render the stored title,
// the preview, and "New session" respectively. If populateResumeTable stopped routing
// column 0 through resumeRowTitle, the empty entry's cell would no longer read "New session".
func TestResumePicker_RowRendersTitlePreviewAndNewSessionFallback(t *testing.T) {
	a := New(nil)
	entries := []ResumeEntry{
		{ID: "id-titled", Title: "my title", Preview: "first prompt"},
		{ID: "id-preview", Preview: "preview only"},
		{ID: "id-empty"},
	}
	a.openResumePicker(entries, func(PickerResult) {}, ResumeActions{})

	tbl := a.resumePicker.table
	cases := []struct {
		row  int
		want string
	}{
		{resumeHeaderRows, "my title"},
		{resumeHeaderRows + 1, "preview only"},
		{resumeHeaderRows + 2, resumeUntitledLabel},
	}
	for _, c := range cases {
		if got := tbl.GetCell(c.row, 0).Text; got != c.want {
			t.Errorf("column 0 at row %d = %q, want %q", c.row, got, c.want)
		}
	}
}

func TestResumePicker_RowShowsGeneratedTitleFromDisk(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	folder, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	started := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	prompt := sessions.Message{ID: ids.NewV7(), Role: "user", Content: sessions.TextContent("first prompt"), Timestamp: started}
	store, err := sessions.EnsureSession(home, folder, started, []sessions.Record{prompt})
	if err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	if _, _, err := store.FlushGeneratedTitle(context.Background(), "Auto title"); err != nil {
		t.Fatalf("flush generated title: %v", err)
	}

	list, skipped, err := sessions.ListResumable(home, cwd)
	if err != nil || len(skipped) != 0 || len(list) != 1 {
		t.Fatalf("ListResumable = %v, skipped %v, err %v; want the one session", list, skipped, err)
	}
	a := New(nil)
	a.openResumePicker([]ResumeEntry{{ID: list[0].ID, Title: list[0].Title, Preview: list[0].Preview}}, func(PickerResult) {}, ResumeActions{})
	if got := a.resumePicker.table.GetCell(resumeHeaderRows, 0).Text; got != "Auto title" {
		t.Errorf("row title = %q, want the generated title read from disk", got)
	}
}

func TestResumeRowTimesLocalTime(t *testing.T) {
	local := time.Local
	time.Local = time.FixedZone("UTC-4", -4*3600)
	t.Cleanup(func() { time.Local = local })

	started := time.Date(2026, 6, 1, 9, 30, 0, 0, time.UTC)
	updated := time.Date(2026, 6, 3, 14, 5, 0, 0, time.UTC)
	got := resumeRowTimes(ResumeEntry{StartedAt: started, UpdatedAt: updated}, updated.Add(4*time.Hour))
	if want := "Jun 01 05:30 · 4h ago"; got != want {
		t.Errorf("resumeRowTimes = %q, want %q", got, want)
	}
}

// TestResumeRowTimes pins the right-hand metadata: a compact month-day start stamp
// (no year, no "started"/"updated" labels) plus a relative update age, exposing NO
// session id — neither the full handle, its prefix, nor its last-8 suffix — and fitting
// the time-cell budget.
func TestResumeRowTimes(t *testing.T) {
	local := time.Local
	time.Local = time.UTC
	t.Cleanup(func() { time.Local = local })

	started := time.Date(2026, 6, 1, 9, 30, 0, 0, time.UTC)
	updated := time.Date(2026, 6, 3, 14, 5, 0, 0, time.UTC)
	now := updated.Add(4 * time.Hour)
	full := "0190aaaa-bbbb-cccc-dddd-eeeeeeee9999"

	got := resumeRowTimes(ResumeEntry{ID: full, StartedAt: started, UpdatedAt: updated, Preview: "hi"}, now)

	if want := "Jun 01 09:30"; !strings.Contains(got, want) {
		t.Errorf("row times %q omit the compact start stamp %q", got, want)
	}
	if strings.Contains(got, "2026") {
		t.Errorf("row times %q still spell out the year", got)
	}
	if strings.Contains(got, "started") || strings.Contains(got, "updated") {
		t.Errorf("row times %q still carry the old field labels", got)
	}
	if want := "4h ago"; !strings.Contains(got, want) {
		t.Errorf("row times %q omit the relative update age %q", got, want)
	}
	if w := uniseg.StringWidth(got); w > resumeTimeCells {
		t.Errorf("row times %q = %d cells, want at most %d", got, w, resumeTimeCells)
	}
	if strings.Contains(got, full) {
		t.Errorf("row times %q expose the full id; no id may appear on the row", got)
	}
	if strings.Contains(got, full[:8]) {
		t.Errorf("row times %q expose the id prefix %q; no id may appear on the row", got, full[:8])
	}
	if last8 := full[len(full)-8:]; strings.Contains(got, last8) {
		t.Errorf("row times %q expose the id last-8 %q; no id may appear on the row", got, last8)
	}
}

// TestResumeUpdatedAge walks every unit boundary of the relative age, including the
// clock-skew case where updated_at is ahead of now.
func TestResumeUpdatedAge(t *testing.T) {
	now := time.Date(2026, 6, 3, 14, 5, 0, 0, time.UTC)
	cases := []struct {
		name string
		age  time.Duration
		want string
	}{
		{"future", -2 * time.Hour, "just now"},
		{"zero", 0, "just now"},
		{"just under a minute", 59 * time.Second, "just now"},
		{"minute boundary", time.Minute, "1m ago"},
		{"minutes", 47 * time.Minute, "47m ago"},
		{"just under an hour", time.Hour - time.Second, "59m ago"},
		{"hour boundary", time.Hour, "1h ago"},
		{"hours", 4 * time.Hour, "4h ago"},
		{"just under a day", 24*time.Hour - time.Second, "23h ago"},
		{"day boundary", 24 * time.Hour, "1d ago"},
		{"days", 3 * 24 * time.Hour, "3d ago"},
		{"just under a year", 365*24*time.Hour - time.Second, "364d ago"},
		{"year boundary", 365 * 24 * time.Hour, "1y ago"},
		{"years", 3 * 365 * 24 * time.Hour, "3y ago"},
	}
	for _, c := range cases {
		if got := resumeUpdatedAge(now.Add(-c.age), now); got != c.want {
			t.Errorf("%s: age = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestResumeHeaderTimes_DescribesCompactStartAndRelativeAge pins that the fixed header
// labels the fields the row now carries and still fits the time-cell budget.
func TestResumeHeaderTimes_DescribesCompactStartAndRelativeAge(t *testing.T) {
	if !strings.Contains(resumeHeaderTimes, "Started") {
		t.Errorf("time header = %q, want it to name the start stamp", resumeHeaderTimes)
	}
	if !strings.Contains(resumeHeaderTimes, "age") {
		t.Errorf("time header = %q, want it to name the update as a relative age", resumeHeaderTimes)
	}
	if w := uniseg.StringWidth(resumeHeaderTimes); w > resumeTimeCells {
		t.Errorf("time header %q = %d cells, want at most %d", resumeHeaderTimes, w, resumeTimeCells)
	}
}

// TestResumePicker_RowRendersTimesAndHidesID closes the render-boundary gap: it
// populates the real picker table via openResumePicker and inspects the rendered cells,
// so the row contract is pinned where the user actually sees it — not only at the
// resumeRowTimes helper. Column 0 carries the title/preview, column 1 the compact start
// stamp and relative age, and no rendered cell exposes the session id (full handle,
// prefix, or last-8 suffix).
func TestResumePicker_RowRendersTimesAndHidesID(t *testing.T) {
	a := New(nil)
	started := time.Now().Add(-72 * time.Hour)
	updated := time.Now().Add(-4*time.Hour - 30*time.Minute)
	full := "0190aaaa-bbbb-cccc-dddd-eeeeeeee9999"
	entry := ResumeEntry{ID: full, StartedAt: started, UpdatedAt: updated, Preview: "first prompt a"}

	a.openResumePicker([]ResumeEntry{entry}, func(PickerResult) {}, ResumeActions{})

	left := a.resumePicker.table.GetCell(resumeHeaderRows, 0).Text
	right := a.resumePicker.table.GetCell(resumeHeaderRows, 1).Text

	if left != "first prompt a" {
		t.Errorf("column 0 = %q, want the preview %q", left, "first prompt a")
	}
	if want := started.Format(resumeRowTimeLayout); !strings.Contains(right, want) {
		t.Errorf("column 1 %q omits the compact start stamp %q", right, want)
	}
	if want := "4h ago"; !strings.Contains(right, want) {
		t.Errorf("column 1 %q omits the relative update age %q", right, want)
	}

	// The contract is "no id anywhere on the row", so scan both rendered cells.
	row := left + " " + right
	if strings.Contains(row, full) {
		t.Errorf("rendered row %q exposes the full id", row)
	}
	if strings.Contains(row, full[:8]) {
		t.Errorf("rendered row %q exposes the id prefix %q", row, full[:8])
	}
	if last8 := full[len(full)-8:]; strings.Contains(row, last8) {
		t.Errorf("rendered row %q exposes the id last-8 %q", row, last8)
	}
}

// TestResumePicker_BorderedBodyAt80ColumnsKeepsRowOnOneLine draws the real bordered body
// on an 80-column simulation screen with a wide-Unicode title. It proves the cell budgets
// (not rune counts) keep the entry row inside the border on a single line with its
// distinguishing tail and compact time cell still visible — a table-cell string check
// alone cannot see the border geometry or tview's own clipping.
func TestResumePicker_BorderedBodyAt80ColumnsKeepsRowOnOneLine(t *testing.T) {
	a := New(nil)
	started := time.Now().Add(-72 * time.Hour)
	updated := time.Now().Add(-4*time.Hour - 30*time.Minute)
	entry := ResumeEntry{
		ID:        "0190aaaa-bbbb-cccc-dddd-eeeeeeee9999",
		StartedAt: started,
		UpdatedAt: updated,
		Preview:   strings.Repeat("漢字", 40) + " for task i870",
	}
	a.openResumePicker([]ResumeEntry{entry}, func(PickerResult) {}, ResumeActions{})

	body := a.buildResumeBody(a.resumePicker.table)
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init: %v", err)
	}
	const width, height = 80, 8
	screen.SetSize(width, height)
	body.SetRect(0, 0, width, height)
	body.Draw(screen)
	screen.Show()

	entryRow := simResumeRowText(screen, 2)
	if !strings.Contains(entryRow, "for task i870") {
		t.Errorf("entry row = %q, want the distinguishing tail %q still visible at 80 columns", entryRow, "for task i870")
	}
	if !strings.Contains(entryRow, "4h ago") {
		t.Errorf("entry row = %q, want the relative update age still visible at 80 columns", entryRow)
	}
	if !strings.Contains(entryRow, started.Format(resumeRowTimeLayout)) {
		t.Errorf("entry row = %q, want the compact start stamp still visible at 80 columns", entryRow)
	}
	// The row must fit one line: the next line down is the footer hint, not row overflow.
	if next := simResumeRowText(screen, 3); strings.Contains(next, "漢") {
		t.Errorf("row wrapped onto the following line %q", next)
	}
}

// TestShowResumeDelete_NamesMiddleEllipsisedRow pins that the delete confirmation reuses
// the rendered display title: the bounded head/ellipsis/tail, never the untruncated
// preview and never the session id.
func TestShowResumeDelete_NamesMiddleEllipsisedRow(t *testing.T) {
	a := New(nil)
	full := "0190aaaa-bbbb-cccc-dddd-eeeeeeee9999"
	long := "please refactor the resume picker layout " + strings.Repeat("and tidy it ", 8) + "for task i870"
	a.openResumePicker(
		[]ResumeEntry{{ID: full, Preview: long}},
		func(PickerResult) {},
		ResumeActions{Delete: func(ResumeEntry) error { return nil }})

	a.showResumeDelete()

	name, prim := a.pages.GetFrontPage()
	if name != resumeDeletePage {
		t.Fatalf("front page = %q, want %q", name, resumeDeletePage)
	}
	// tview.Modal word-wraps to a third of the screen width, so draw it wide enough that
	// the whole prompt lands on one rendered line and Contains can see the title intact.
	text := screenText(drawPrimitive(t, prim, 400, 20))
	want := resumeRowTitle(ResumeEntry{Preview: long})
	if !strings.Contains(text, want) {
		t.Errorf("delete prompt %q omits the bounded display title %q", text, want)
	}
	if strings.Contains(text, long) {
		t.Errorf("delete prompt %q names the untruncated preview", text)
	}
	if strings.Contains(text, full[:8]) {
		t.Errorf("delete prompt %q exposes the session id", text)
	}
}

func TestResumePicker_DismissRemovesBothChildPagesBeforeRestoringFocus(t *testing.T) {
	a := New(nil)
	captured := tview.NewBox()
	a.app.SetFocus(captured)

	actions := ResumeActions{
		Rename: func(ResumeEntry, string) error { return nil },
		Delete: func(ResumeEntry) error { return nil },
	}
	a.openResumePicker(resumePickerEntries(), func(PickerResult) {}, actions)
	a.showResumeRename()
	a.showResumeDelete()
	if !a.pages.HasPage(resumeRenamePage) || !a.pages.HasPage(resumeDeletePage) {
		t.Fatal("rename/delete children not both mounted; the teardown ordering is untested")
	}

	a.dismissResumePicker()

	for _, page := range []string{resumeRenamePage, resumeDeletePage, resumePickerPage} {
		if a.pages.HasPage(page) {
			t.Errorf("page %q still mounted after dismissal", page)
		}
	}
	if a.app.GetFocus() != captured {
		t.Errorf("focus = %T, want the primitive captured at open", a.app.GetFocus())
	}
	if a.resumePickerOpen || a.resumePicker != nil || a.resumePickerPrev != nil {
		t.Error("per-open picker state not cleared by dismissal")
	}
}

func TestResumePicker_DismissWithoutOpenOverlayIsInert(t *testing.T) {
	a := New(nil)
	other := tview.NewBox()
	a.resumePickerPrev = tview.NewBox()
	a.app.SetFocus(other)

	a.dismissResumePicker()

	if a.app.GetFocus() != other {
		t.Errorf("focus = %T; a dismissal with no overlay open must be inert", a.app.GetFocus())
	}
}

func TestResumePicker_DismissWithNoCapturedFocusFallsBackToInput(t *testing.T) {
	a := New(nil)
	a.openResumePicker(resumePickerEntries(), func(PickerResult) {}, ResumeActions{})
	a.resumePickerPrev = nil

	a.dismissResumePicker()

	if a.app.GetFocus() != a.input {
		t.Errorf("focus = %T, want the input area when nothing was captured", a.app.GetFocus())
	}
}
