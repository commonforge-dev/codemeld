package tui

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type fakeBlockedPicker struct {
	host             *fakeHost
	presented        [][]BlockedRow
	relist           func() []BlockedRow
	flushesAtPresent int
}

type flushOrderHost struct {
	*fakeHost
	slashEvtAtFlush int
}

func (h *flushOrderHost) FlushActive() error {
	h.slashEvtAtFlush = len(h.events())
	return h.fakeHost.FlushActive()
}

func (p *fakeBlockedPicker) Present(rows []BlockedRow, _ func(BlockedRow) string, _ func(BlockedRow) string, _ func([]BlockedRow) string, relist func() []BlockedRow) {
	if p.host != nil {
		p.flushesAtPresent = p.host.flushes
	}
	p.presented = append(p.presented, rows)
	p.relist = relist
}

func newBlockedRegistry(t *testing.T, deps BlockedDeps) *Registry {
	t.Helper()
	r, err := NewRegistry([]Command{{
		Name:        "blocked",
		Description: "View the blocked paths",
		ArgSig:      ArgRestOptional,
		Phase:       PhaseOne,
		Handler:     NewBlockedHandler(deps),
	}})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

func TestBlockedHandler_FlushesSuccessBeforeOpening(t *testing.T) {
	host := &flushOrderHost{fakeHost: newFakeHost(), slashEvtAtFlush: -1}
	rows := []BlockedRow{
		{Kind: BlockedRowGlobal, Path: "/home/u/.ssh", Source: "/home/u/.codemeld/settings.yaml"},
		{Kind: BlockedRowFloor, Path: "/home/u/.codemeld"},
	}
	calls := 0
	picker := &fakeBlockedPicker{host: host.fakeHost}
	reg := newBlockedRegistry(t, BlockedDeps{Rows: func() []BlockedRow { calls++; return rows }, Picker: picker})

	res := reg.DispatchSlashInput("/blocked", host)
	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /blocked = %+v, want Handled/nil-err", res)
	}
	if len(picker.presented) != 1 {
		t.Fatalf("Present called %d times, want 1", len(picker.presented))
	}
	got := picker.presented[0]
	if len(got) != len(rows) || &got[0] != &rows[0] {
		t.Errorf("Present rows = %v, want the slice deps.Rows returned %v", got, rows)
	}
	if host.slashEvtAtFlush != 1 {
		t.Errorf("slash events at FlushActive = %d, want 1 (the success record is flushed)", host.slashEvtAtFlush)
	}
	if picker.flushesAtPresent != 1 {
		t.Errorf("flushes at Present = %d, want 1 (Present follows the flush)", picker.flushesAtPresent)
	}
	if evs := host.events(); len(evs) != 1 || decodeSlash(t, evs[0]).Outcome != "success" {
		t.Fatalf("slash_command events = %v, want one success", evs)
	}
	if picker.relist == nil {
		t.Fatal("handler passed no relist source")
	}
	picker.relist()
	if calls != 2 {
		t.Errorf("deps.Rows called %d times, want 2 (once to open, once through relist)", calls)
	}
}

func TestBlockedHandler_FlushFailureDoesNotPresent(t *testing.T) {
	host := newFlushErrHost(errors.New("flush failed"))
	picker := &fakeBlockedPicker{}
	deps := BlockedDeps{Rows: func() []BlockedRow { return []BlockedRow{{Kind: BlockedRowFloor, Path: "/x"}} }, Picker: picker}
	submit := NewSubmitFunc(newBlockedRegistry(t, deps), host, nil)

	if submit("/blocked") {
		t.Error("submit accepted /blocked on a flush failure; want reject")
	}
	if len(picker.presented) != 0 {
		t.Errorf("Present called %d times on a flush failure, want 0", len(picker.presented))
	}
}

func TestBlockedPicker_RendersEveryRowKindInOrder(t *testing.T) {
	a := New(nil)
	NewBlockedPicker(a).Present([]BlockedRow{
		{Kind: BlockedRowWarning, Text: "blocked_paths has 300 entries"},
		{Kind: BlockedRowGlobal, Path: "/home/u/.ssh", Source: "/home/u/.codemeld/settings.yaml"},
		{Kind: BlockedRowProject, Path: "/p/secrets", Source: "/p/.codemeld/settings.yaml"},
		{Kind: BlockedRowFloor, Path: "/home/u/.codemeld"},
		{Kind: BlockedRowGroup, Text: "Keys and passwords"},
		{Kind: BlockedRowMissing, Path: "~/.gnupg", Group: "Keys and passwords"},
	}, nil, nil, nil, nil)

	want := strings.Join([]string{
		"blocked_paths has 300 entries",
		"/home/u/.ssh  (/home/u/.codemeld/settings.yaml)",
		"/p/secrets  (edit /p/.codemeld/settings.yaml to change this entry)",
		"/home/u/.codemeld  (codemeld's own folder, always blocked)",
		"Recommended, not in your global settings:",
		"Keys and passwords",
		"  ~/.gnupg",
	}, "\n")
	if got := a.BlockedOverlayText(); got != want {
		t.Errorf("overlay text =\n%s\nwant\n%s", got, want)
	}
	wantRows := []int{0, 1, 2, 3, -1, 4, 5}
	bp := a.blockedPicker
	if bp.list.GetItemCount() != len(wantRows) {
		t.Fatalf("list items = %d, want %d", bp.list.GetItemCount(), len(wantRows))
	}
	for i, it := range bp.items {
		if it.row != wantRows[i] {
			t.Errorf("item %d backs row %d, want %d", i, it.row, wantRows[i])
		}
	}
}

func TestBlockedPicker_EscCloses(t *testing.T) {
	a := New(nil)
	a.app.SetFocus(a.input)
	a.openBlockedPicker([]BlockedRow{{Kind: BlockedRowFloor, Path: "/home/u/.codemeld"}})

	a.handleGlobalKey(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone))

	if a.blockedPickerOpen || a.pages.HasPage(blockedPickerPage) || a.BlockedOverlayText() != "" {
		t.Error("blocked overlay still open after ESC")
	}
	if a.app.GetFocus() != a.input {
		t.Error("focus not restored to the input after ESC")
	}
}

func TestBlockedPicker_PathIsCollapsedAndEscaped(t *testing.T) {
	a := New(nil)
	a.openBlockedPicker([]BlockedRow{{Kind: BlockedRowGlobal, Path: "/tmp/a\n[red]b\tc", Source: "/s\r[::b]"}})

	line := "/tmp/a [red]b c  (/s [::b])"
	if got := a.BlockedOverlayText(); got != line {
		t.Errorf("overlay text = %q, want %q", got, line)
	}
	main, _ := a.blockedPicker.list.GetItemText(0)
	if main != tview.Escape(line) || !strings.Contains(main, "[red[]") {
		t.Errorf("list item = %q, want escaped %q", main, tview.Escape(line))
	}
}

const (
	blockedItemWarning = iota
	blockedItemGlobal
	blockedItemProject
	blockedItemFloor
	blockedItemHeading
	blockedItemGroup
	blockedItemMissing
)

type blockedRecorder struct {
	rows     []BlockedRow
	removed  []BlockedRow
	added    []BlockedRow
	addedAll [][]BlockedRow
	message  string
}

func (r *blockedRecorder) take(row BlockedRow) {
	r.rows = slices.DeleteFunc(r.rows, func(have BlockedRow) bool { return have == row })
}

func openRecordedBlocked(a *App, withActions bool) *blockedRecorder {
	rec := &blockedRecorder{
		message: "blocked_paths updated",
		rows: []BlockedRow{
			{Kind: BlockedRowWarning, Text: "blocked_paths has 300 entries"},
			{Kind: BlockedRowGlobal, Path: "/home/u/.ssh", Source: "/home/u/.codemeld/global/settings.yaml", Occurrence: 1},
			{Kind: BlockedRowProject, Path: "/p/secrets", Source: "/p/.codemeld/settings.yaml"},
			{Kind: BlockedRowFloor, Path: "/home/u/.codemeld"},
			{Kind: BlockedRowGroup, Text: "Keys and passwords"},
			{Kind: BlockedRowMissing, Path: "~/.gnupg", Group: "Keys and passwords"},
		},
	}
	var remove, add func(BlockedRow) string
	var addAll func([]BlockedRow) string
	if withActions {
		remove = func(row BlockedRow) string { rec.removed = append(rec.removed, row); rec.take(row); return rec.message }
		add = func(row BlockedRow) string { rec.added = append(rec.added, row); rec.take(row); return rec.message }
		addAll = func(rows []BlockedRow) string {
			rec.addedAll = append(rec.addedAll, rows)
			for _, row := range rows {
				rec.take(row)
			}
			return rec.message
		}
	}
	NewBlockedPicker(a).Present(slices.Clone(rec.rows), remove, add, addAll, func() []BlockedRow { return slices.Clone(rec.rows) })
	return rec
}

func pressBlocked(t *testing.T, a *App, item int, key rune) {
	t.Helper()
	a.blockedPicker.list.SetCurrentItem(item)
	if ev := a.blockedPickerKeys(tcell.NewEventKey(tcell.KeyRune, key, tcell.ModNone)); ev != nil {
		t.Fatalf("%q reached the list, want it consumed", key)
	}
}

func blockedConfirm(t *testing.T, a *App) *tview.Modal {
	t.Helper()
	modal, ok := a.pages.GetPage(blockedConfirmPage).(*tview.Modal)
	if !ok {
		t.Fatal("no confirmation open")
	}
	return modal
}

func keyBlockedConfirm(t *testing.T, a *App, keys ...tcell.Key) {
	t.Helper()
	modal := blockedConfirm(t, a)
	for _, key := range keys {
		modal.InputHandler()(tcell.NewEventKey(key, 0, tcell.ModNone), func(p tview.Primitive) { a.app.SetFocus(p) })
	}
}

func blockedConfirmScreenText(t *testing.T, a *App) string {
	t.Helper()
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init: %v", err)
	}
	screen.SetSize(240, 30)
	modal := blockedConfirm(t, a)
	modal.SetRect(0, 0, 240, 30)
	modal.Draw(screen)
	screen.Show()
	cells, width, height := screen.GetContents()
	var b strings.Builder
	for row := 0; row < height; row++ {
		for col := 0; col < width; col++ {
			b.WriteString(string(cells[row*width+col].Runes))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func TestBlockedPicker_RemoveGlobalRowConfirmsThenRemovesAndRelists(t *testing.T) {
	a := New(nil)
	rec := openRecordedBlocked(a, true)
	global := rec.rows[1]

	pressBlocked(t, a, blockedItemGlobal, 'r')
	if text := blockedConfirmScreenText(t, a); !strings.Contains(text, "Remove /home/u/.ssh from /home/u/.codemeld/global/settings.yaml?") {
		t.Errorf("confirmation =\n%s\nwant it to name the path and its source", text)
	}
	keyBlockedConfirm(t, a, tcell.KeyRight, tcell.KeyEnter)
	if a.pages.HasPage(blockedConfirmPage) || len(rec.removed) != 0 || !a.blockedPickerOpen {
		t.Fatalf("Cancel: confirm open=%v removed=%v overlay open=%v; want closed, none, open", a.pages.HasPage(blockedConfirmPage), rec.removed, a.blockedPickerOpen)
	}

	pressBlocked(t, a, blockedItemGlobal, 'r')
	a.handleGlobalKey(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone))
	if a.pages.HasPage(blockedConfirmPage) || len(rec.removed) != 0 || !a.blockedPickerOpen {
		t.Fatalf("ESC: confirm open=%v removed=%v overlay open=%v; want closed, none, open", a.pages.HasPage(blockedConfirmPage), rec.removed, a.blockedPickerOpen)
	}
	if a.app.GetFocus() != a.blockedPicker.list {
		t.Error("focus not back on the list after ESC")
	}

	pressBlocked(t, a, blockedItemGlobal, 'r')
	keyBlockedConfirm(t, a, tcell.KeyEnter)
	if len(rec.removed) != 1 || rec.removed[0] != global {
		t.Fatalf("Remove called with %v, want once with %v", rec.removed, global)
	}
	if got := a.NoticeText(); got != rec.message {
		t.Errorf("notice = %q, want %q", got, rec.message)
	}
	if a.pages.HasPage(blockedConfirmPage) || strings.Contains(a.BlockedOverlayText(), global.Path) {
		t.Errorf("after confirm: confirm open=%v overlay=\n%s\nwant closed and the row relisted away", a.pages.HasPage(blockedConfirmPage), a.BlockedOverlayText())
	}
	if got := a.blockedPicker.list.GetCurrentItem(); got != blockedItemGlobal {
		t.Errorf("cursor = %d, want it kept at %d", got, blockedItemGlobal)
	}
	if a.app.GetFocus() != a.blockedPicker.list {
		t.Error("focus not back on the list after confirm")
	}
}

func TestBlockedPicker_AddMissingRowConfirmsThenAddsAndRelists(t *testing.T) {
	a := New(nil)
	rec := openRecordedBlocked(a, true)
	missing := rec.rows[5]

	pressBlocked(t, a, blockedItemMissing, 'a')
	if text := blockedConfirmScreenText(t, a); !strings.Contains(text, "Add ~/.gnupg to your global settings?") {
		t.Errorf("confirmation =\n%s\nwant it to name the path", text)
	}
	keyBlockedConfirm(t, a, tcell.KeyEnter)

	if len(rec.added) != 1 || rec.added[0] != missing {
		t.Fatalf("Add called with %v, want once with %v", rec.added, missing)
	}
	if strings.Contains(a.BlockedOverlayText(), missing.Path) {
		t.Errorf("overlay after add =\n%s\nwant the Missing row gone", a.BlockedOverlayText())
	}
	if got, want := a.blockedPicker.list.GetCurrentItem(), a.blockedPicker.list.GetItemCount()-1; got != want {
		t.Errorf("cursor = %d, want it clamped to the last item %d", got, want)
	}
	if a.NoticeText() != rec.message {
		t.Errorf("notice = %q, want %q", a.NoticeText(), rec.message)
	}
}

func TestBlockedPicker_EmptyMessageShowsNoNotice(t *testing.T) {
	a := New(nil)
	rec := openRecordedBlocked(a, true)
	rec.message = ""

	pressBlocked(t, a, blockedItemGlobal, 'r')
	keyBlockedConfirm(t, a, tcell.KeyEnter)
	if len(rec.removed) != 1 || a.NoticeText() != "" {
		t.Errorf("removed=%v notice=%q, want one removal and no notice", rec.removed, a.NoticeText())
	}
}

func TestBlockedPicker_ProjectRowNamesItsSourceWithoutConfirming(t *testing.T) {
	a := New(nil)
	rec := openRecordedBlocked(a, true)
	rec.rows[2].Source = "/p/.codemeld\n[red]settings.yaml"
	a.blockedPicker.setRows(slices.Clone(rec.rows))

	pressBlocked(t, a, blockedItemProject, 'r')
	if a.pages.HasPage(blockedConfirmPage) || len(rec.removed) != 0 {
		t.Fatal("r on a Project row opened a confirmation or removed something")
	}
	if got, want := a.NoticeText(), tview.Escape("edit /p/.codemeld [red]settings.yaml to change this entry"); got != want {
		t.Errorf("notice = %q, want the one-line %q", got, want)
	}
}

func TestBlockedPicker_KeysOnOtherRowsDoNothing(t *testing.T) {
	a := New(nil)
	rec := openRecordedBlocked(a, true)

	for _, item := range []int{blockedItemWarning, blockedItemFloor, blockedItemHeading, blockedItemGroup, blockedItemMissing} {
		pressBlocked(t, a, item, 'r')
	}
	for _, item := range []int{blockedItemWarning, blockedItemGlobal, blockedItemProject, blockedItemFloor, blockedItemHeading, blockedItemGroup} {
		pressBlocked(t, a, item, 'a')
	}
	if a.pages.HasPage(blockedConfirmPage) || len(rec.removed)+len(rec.added) != 0 || a.NoticeText() != "" {
		t.Errorf("confirm open=%v removed=%v added=%v notice=%q, want nothing", a.pages.HasPage(blockedConfirmPage), rec.removed, rec.added, a.NoticeText())
	}
}

func TestBlockedPicker_NilActionsMakeKeysInert(t *testing.T) {
	a := New(nil)
	openRecordedBlocked(a, false)

	for _, press := range []struct {
		item int
		key  rune
	}{{blockedItemGlobal, 'r'}, {blockedItemProject, 'r'}, {blockedItemMissing, 'a'}, {blockedItemGlobal, 'A'}} {
		pressBlocked(t, a, press.item, press.key)
		if a.pages.HasPage(blockedConfirmPage) || a.NoticeText() != "" {
			t.Errorf("%q on item %d with nil actions opened a confirmation or a notice", press.key, press.item)
		}
	}
}

func TestBlockedPicker_ConfirmationEscapesMarkup(t *testing.T) {
	a := New(nil)
	var removed []BlockedRow
	row := BlockedRow{Kind: BlockedRowGlobal, Path: "/tmp/[red]x\ty", Source: "/s/[::b]settings.yaml"}
	NewBlockedPicker(a).Present([]BlockedRow{row}, func(r BlockedRow) string { removed = append(removed, r); return "" }, nil, nil, nil)

	pressBlocked(t, a, 0, 'r')
	if text := blockedConfirmScreenText(t, a); !strings.Contains(text, "Remove /tmp/[red]x y from /s/[::b]settings.yaml?") {
		t.Errorf("confirmation =\n%s\nwant the markup shown literally on one line", text)
	}
	keyBlockedConfirm(t, a, tcell.KeyEnter)
	if len(removed) != 1 || removed[0] != row {
		t.Errorf("Remove called with %v, want once with the raw row %v", removed, row)
	}
}

func TestBlockedPicker_ForTestHooksGoThroughTheConfirmation(t *testing.T) {
	a := New(nil)
	rec := openRecordedBlocked(a, true)
	global, missing := rec.rows[1], rec.rows[5]

	if !a.RemoveBlockedPathForTest(global.Path) || !a.AddBlockedPathForTest(missing.Path) {
		t.Fatal("a hook found no row to act on")
	}
	if len(rec.removed) != 1 || rec.removed[0] != global || len(rec.added) != 1 || rec.added[0] != missing {
		t.Errorf("removed=%v added=%v, want one each with the typed rows", rec.removed, rec.added)
	}
	if a.RemoveBlockedPathForTest(rec.rows[1].Path) {
		t.Error("remove hook acted on a Project row")
	}
}

func TestBlockedPicker_FloorOnlyOpens(t *testing.T) {
	a := New(nil)
	a.openBlockedPicker([]BlockedRow{{Kind: BlockedRowFloor, Path: "/home/u/.codemeld"}})

	if !a.blockedPickerOpen || !a.pages.HasPage(blockedPickerPage) || a.app.GetFocus() != a.blockedPicker.list {
		t.Fatal("overlay did not open with only a Floor row")
	}
	if got, want := a.BlockedOverlayText(), "/home/u/.codemeld  (codemeld's own folder, always blocked)"; got != want {
		t.Errorf("overlay text = %q, want %q", got, want)
	}
}

func TestBlockedPicker_LocalRowRendersItsSourceAndConfirmsRemoval(t *testing.T) {
	a := New(nil)
	local := BlockedRow{Kind: BlockedRowLocal, Path: "/p/secrets", Source: "/p/.codemeld/settings.local.yaml"}
	var removed []BlockedRow
	rows := []BlockedRow{local}
	NewBlockedPicker(a).Present(slices.Clone(rows), func(row BlockedRow) string {
		removed = append(removed, row)
		return ""
	}, nil, nil, func() []BlockedRow { return nil })

	if got, want := a.BlockedOverlayText(), "/p/secrets  (/p/.codemeld/settings.local.yaml)"; got != want {
		t.Fatalf("overlay text = %q, want %q", got, want)
	}

	pressBlocked(t, a, 0, 'r')
	if text := blockedConfirmScreenText(t, a); !strings.Contains(text, "Remove /p/secrets from /p/.codemeld/settings.local.yaml?") {
		t.Fatalf("confirmation =\n%s\nwant it to name the path and the local file", text)
	}
	keyBlockedConfirm(t, a, tcell.KeyEnter)
	if len(removed) != 1 || removed[0] != local {
		t.Fatalf("Remove called with %v, want once with %v", removed, local)
	}
}

func TestBlockedPicker_SharedRowRendersItsSourceAndConfirmsRemoval(t *testing.T) {
	a := New(nil)
	shared := BlockedRow{Kind: BlockedRowShared, Path: "/p/secrets", Source: "/p/.codemeld/settings.yaml", Occurrence: 1}
	var removed []BlockedRow
	NewBlockedPicker(a).Present([]BlockedRow{shared}, func(row BlockedRow) string {
		removed = append(removed, row)
		return ""
	}, nil, nil, func() []BlockedRow { return nil })

	if got, want := a.BlockedOverlayText(), "/p/secrets  (/p/.codemeld/settings.yaml)"; got != want {
		t.Fatalf("overlay text = %q, want %q", got, want)
	}

	pressBlocked(t, a, 0, 'r')
	if text := blockedConfirmScreenText(t, a); !strings.Contains(text, "Remove /p/secrets from /p/.codemeld/settings.yaml?") {
		t.Fatalf("confirmation =\n%s\nwant it to name the path and the shared file", text)
	}
	keyBlockedConfirm(t, a, tcell.KeyRight, tcell.KeyEnter)
	if a.pages.HasPage(blockedConfirmPage) || len(removed) != 0 {
		t.Fatalf("Cancel: confirm open=%v removed=%v; want closed and none", a.pages.HasPage(blockedConfirmPage), removed)
	}

	pressBlocked(t, a, 0, 'r')
	keyBlockedConfirm(t, a, tcell.KeyEnter)
	if len(removed) != 1 || removed[0] != shared {
		t.Fatalf("Remove called with %v, want once with %v", removed, shared)
	}
}

type addPathRecorder struct {
	host          *fakeHost
	paths         []string
	dests         []BlockedDestination
	flushesAtCall int
	eventsAtCall  int
	message       string
}

func (r *addPathRecorder) add(path string, dest BlockedDestination) string {
	r.paths = append(r.paths, path)
	r.dests = append(r.dests, dest)
	r.flushesAtCall = r.host.flushes
	r.eventsAtCall = len(r.host.events())
	return r.message
}

func TestBlockedHandler_AddRecordsSuccessFlushesThenCallsTheHelper(t *testing.T) {
	for _, message := range []string{"~/my secrets is now blocked (added to /g)", "permissions: blocked_paths entry \"x\" must be absolute or start with ~/"} {
		host := &flushOrderHost{fakeHost: newFakeHost(), slashEvtAtFlush: -1}
		rec := &addPathRecorder{host: host.fakeHost, message: message}
		picker := &fakeBlockedPicker{}
		reg := newBlockedRegistry(t, BlockedDeps{Rows: func() []BlockedRow { return nil }, Picker: picker, AddPath: rec.add})

		res := reg.DispatchSlashInput("/blocked add ~/my secrets", host)
		if res.Status != StatusHandled || res.Err != nil || res.RetainInput {
			t.Fatalf("dispatch = %+v, want Handled/nil-err/no-retain", res)
		}
		if !slices.Equal(rec.paths, []string{"~/my secrets"}) || !slices.Equal(rec.dests, []BlockedDestination{BlockedGlobal}) {
			t.Fatalf("AddPath called with %q %q, want once with %q to the global file", rec.paths, rec.dests, "~/my secrets")
		}
		if rec.eventsAtCall != 1 || rec.flushesAtCall != 1 || host.slashEvtAtFlush != 1 {
			t.Errorf("events at call=%d flushes at call=%d events at flush=%d, want the success record appended and flushed before the helper", rec.eventsAtCall, rec.flushesAtCall, host.slashEvtAtFlush)
		}
		evs := host.events()
		if len(evs) != 1 {
			t.Fatalf("slash_command events = %d, want 1", len(evs))
		}
		if p := decodeSlash(t, evs[0]); p.Outcome != "success" || p.ErrorDetail != "" {
			t.Errorf("event = %+v, want success with empty errorDetail", p)
		}
		if !slices.Equal(host.notices, []string{message}) {
			t.Errorf("notices = %q, want only the helper message", host.notices)
		}
		if len(picker.presented) != 0 {
			t.Error("picker opened for /blocked add")
		}
	}
}

func TestBlockedHandler_AddFlushFailureSkipsTheHelper(t *testing.T) {
	host := newFlushErrHost(errors.New("flush failed"))
	called := false
	deps := BlockedDeps{Picker: &fakeBlockedPicker{}, AddPath: func(string, BlockedDestination) string { called = true; return "" }}
	if NewSubmitFunc(newBlockedRegistry(t, deps), host, nil)("/blocked add /etc/secrets") {
		t.Error("submit accepted /blocked add on a flush failure; want reject")
	}
	if called {
		t.Error("AddPath called after a flush failure")
	}
}

func TestBlockedHandler_OtherArgumentsShowUsage(t *testing.T) {
	for _, input := range []string{"/blocked foo", "/blocked add", "/blocked Add /etc/secrets", "/blocked remove /etc/secrets"} {
		t.Run(input, func(t *testing.T) {
			host := &flushOrderHost{fakeHost: newFakeHost(), slashEvtAtFlush: -1}
			picker := &fakeBlockedPicker{}
			called := false
			reg := newBlockedRegistry(t, BlockedDeps{Rows: func() []BlockedRow { return nil }, Picker: picker, AddPath: func(string, BlockedDestination) string { called = true; return "" }})

			res := reg.DispatchSlashInput(input, host)
			if res.Status != StatusHandled || res.Err != nil || !res.RetainInput {
				t.Fatalf("dispatch = %+v, want Handled/nil-err/retain", res)
			}
			if !slices.Equal(host.notices, []string{blockedUsage}) {
				t.Errorf("notices = %q, want only %q", host.notices, blockedUsage)
			}
			evs := host.events()
			if len(evs) != 1 {
				t.Fatalf("slash_command events = %d, want 1", len(evs))
			}
			if p := decodeSlash(t, evs[0]); p.Outcome != "error" || p.ErrorDetail != blockedUsage {
				t.Errorf("event = %+v, want error with the usage as errorDetail", p)
			}
			if host.slashEvtAtFlush != 1 || host.flushes != 1 {
				t.Errorf("events at flush=%d flushes=%d, want one flush after the append", host.slashEvtAtFlush, host.flushes)
			}
			if called || len(picker.presented) != 0 {
				t.Errorf("AddPath called=%v presented=%d, want neither", called, len(picker.presented))
			}
		})
	}
}

func TestBlockedPicker_AddAllConfirmsOnceWithTheDisplayedSnapshot(t *testing.T) {
	a := New(nil)
	rec := openRecordedBlocked(a, true)
	extra := BlockedRow{Kind: BlockedRowMissing, Path: "~/.aws", Group: "Cloud and cluster logins"}
	rec.rows = append(rec.rows, BlockedRow{Kind: BlockedRowGroup, Text: "Cloud and cluster logins"}, extra)
	a.blockedPicker.setRows(slices.Clone(rec.rows))
	snapshot := []BlockedRow{rec.rows[5], extra}

	pressBlocked(t, a, blockedItemWarning, 'A')
	if text := blockedConfirmScreenText(t, a); !strings.Contains(text, "Add all 2 missing recommended entries to your global settings?") {
		t.Errorf("confirmation =\n%s\nwant it to name the count", text)
	}
	keyBlockedConfirm(t, a, tcell.KeyRight, tcell.KeyEnter)
	if a.pages.HasPage(blockedConfirmPage) || len(rec.addedAll) != 0 {
		t.Fatalf("Cancel: confirm open=%v addedAll=%v, want closed and none", a.pages.HasPage(blockedConfirmPage), rec.addedAll)
	}

	pressBlocked(t, a, blockedItemWarning, 'A')
	a.blockedPicker.setRows(slices.Clone(rec.rows[:5]))
	keyBlockedConfirm(t, a, tcell.KeyEnter)
	if len(rec.addedAll) != 1 || !slices.Equal(rec.addedAll[0], snapshot) {
		t.Fatalf("AddAll called with %v, want once with %v", rec.addedAll, snapshot)
	}
	if text := a.BlockedOverlayText(); strings.Contains(text, "~/.gnupg") || strings.Contains(text, "~/.aws") {
		t.Errorf("overlay after add all =\n%s\nwant the Missing rows relisted away", text)
	}
	if a.NoticeText() != rec.message {
		t.Errorf("notice = %q, want %q", a.NoticeText(), rec.message)
	}
}

func TestBlockedPicker_AddAllWithNothingMissingOnlyNotices(t *testing.T) {
	a := New(nil)
	rec := openRecordedBlocked(a, true)
	rec.rows = rec.rows[:4]
	a.blockedPicker.setRows(slices.Clone(rec.rows))

	pressBlocked(t, a, 0, 'A')
	if a.pages.HasPage(blockedConfirmPage) || len(rec.addedAll) != 0 {
		t.Fatalf("confirm open=%v addedAll=%v, want neither", a.pages.HasPage(blockedConfirmPage), rec.addedAll)
	}
	if a.NoticeText() != blockedNothingMissing {
		t.Errorf("notice = %q, want %q", a.NoticeText(), blockedNothingMissing)
	}
}

func blockedDestModal(t *testing.T, a *App) *tview.Modal {
	t.Helper()
	modal, ok := a.pages.GetPage(blockedDestPage).(*tview.Modal)
	if !ok {
		t.Fatal("no destination page open")
	}
	return modal
}

func keyModal(a *App, modal *tview.Modal, keys ...tcell.Key) {
	for _, key := range keys {
		modal.InputHandler()(tcell.NewEventKey(key, 0, tcell.ModNone), func(p tview.Primitive) { a.app.SetFocus(p) })
	}
}

func modalScreenText(t *testing.T, modal *tview.Modal) string {
	t.Helper()
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init: %v", err)
	}
	screen.SetSize(240, 30)
	modal.SetRect(0, 0, 240, 30)
	modal.Draw(screen)
	screen.Show()
	cells, width, height := screen.GetContents()
	var b strings.Builder
	for row := 0; row < height; row++ {
		b.WriteString(rowText(cells, width, row))
		b.WriteString("\n")
	}
	return b.String()
}

func openBlockedDestination(t *testing.T, a *App, path string) *addPathRecorder {
	t.Helper()
	host := newFakeHost()
	rec := &addPathRecorder{host: host, message: "added"}
	reg := newBlockedRegistry(t, BlockedDeps{
		Picker:                     &fakeBlockedPicker{},
		AddPath:                    rec.add,
		ProjectDestinationsAllowed: true,
		Destinations:               NewBlockedDestinationPresenter(a),
	})
	if res := reg.DispatchSlashInput("/blocked add "+path, host); res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled/nil-err", res)
	}
	if evs := host.events(); len(evs) != 1 || host.flushes != 1 || decodeSlash(t, evs[0]).Outcome != "success" {
		t.Fatalf("events=%d flushes=%d, want one success record flushed", len(evs), host.flushes)
	}
	if len(rec.paths) != 0 || len(host.notices) != 0 {
		t.Fatalf("AddPath=%q notices=%q before a destination was chosen, want neither", rec.paths, host.notices)
	}
	return rec
}

func requireBlockedDestinationClosed(t *testing.T, a *App) {
	t.Helper()
	if a.blockedDestinationOpen || a.pages.HasPage(blockedDestPage) || a.blockedDestinationAdd != nil || a.blockedDestinationPrev != nil {
		t.Fatal("destination page state left behind after it closed")
	}
	if a.app.GetFocus() != a.input {
		t.Error("focus not restored to the input")
	}
}

func TestBlockedDestination_PageNamesThePathAndDefaultsToGlobal(t *testing.T) {
	a := New(nil)
	a.app.SetFocus(a.input)
	rec := openBlockedDestination(t, a, "~/my secrets")
	modal := blockedDestModal(t, a)

	text := strings.Join(strings.Fields(strings.ReplaceAll(modalScreenText(t, modal), "║", " ")), " ")
	for _, want := range []string{"~/my secrets", "applies to everyone who approves this repository", "Global", "Project (shared)", "Project (local)", "Cancel"} {
		if !strings.Contains(text, want) {
			t.Errorf("destination page =\n%s\nwant it to contain %q", text, want)
		}
	}
	if !a.anyOverlayOpen() {
		t.Error("destination page does not count as an overlay")
	}

	a.running.Store(true)
	keyModal(a, modal, tcell.KeyEnter)
	if !slices.Equal(rec.paths, []string{"~/my secrets"}) || !slices.Equal(rec.dests, []BlockedDestination{BlockedGlobal}) {
		t.Fatalf("AddPath = %q %q, want once to the global file", rec.paths, rec.dests)
	}
	if got := a.NoticeText(); got != rec.message {
		t.Errorf("notice = %q, want %q delivered directly on the event loop", got, rec.message)
	}
	requireBlockedDestinationClosed(t, a)
}

func TestBlockedDestination_EachButtonAddsOnceToItsDestination(t *testing.T) {
	for i, want := range []BlockedDestination{BlockedGlobal, BlockedProjectShared, BlockedProjectLocal} {
		t.Run(string(want), func(t *testing.T) {
			a := New(nil)
			a.app.SetFocus(a.input)
			rec := openBlockedDestination(t, a, "/etc/secrets")
			modal := blockedDestModal(t, a)
			for range i {
				keyModal(a, modal, tcell.KeyRight)
			}
			keyModal(a, modal, tcell.KeyEnter)
			keyModal(a, modal, tcell.KeyEnter)
			a.HandleEsc()
			a.answerBlockedDestination(i)

			if !slices.Equal(rec.dests, []BlockedDestination{want}) || !slices.Equal(rec.paths, []string{"/etc/secrets"}) {
				t.Fatalf("AddPath = %q %q, want exactly one call to %q", rec.paths, rec.dests, want)
			}
			requireBlockedDestinationClosed(t, a)
		})
	}
}

func TestBlockedDestination_CancelWritesNothing(t *testing.T) {
	for name, cancel := range map[string]func(*App, *tview.Modal){
		"button": func(a *App, m *tview.Modal) {
			keyModal(a, m, tcell.KeyRight, tcell.KeyRight, tcell.KeyRight, tcell.KeyEnter)
		},
		"app escape": func(a *App, _ *tview.Modal) { a.handleGlobalKey(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone)) },
	} {
		t.Run(name, func(t *testing.T) {
			a := New(nil)
			canceller := &fakeStreamReporter{fakeStreamCanceller{retained: 3, inFlight: true}}
			a.SetStreamCanceller(canceller)
			a.input.SetText("draft")
			a.app.SetFocus(a.input)
			rec := openBlockedDestination(t, a, "/etc/secrets")
			modal := blockedDestModal(t, a)

			cancel(a, modal)
			keyModal(a, modal, tcell.KeyEnter)
			a.answerBlockedDestination(0)

			if len(rec.paths) != 0 || a.NoticeText() != "" {
				t.Fatalf("AddPath=%q notice=%q after cancel, want neither", rec.paths, a.NoticeText())
			}
			if canceller.calls != 0 {
				t.Errorf("stream cancelled %d times, want the stream left running", canceller.calls)
			}
			if got := a.input.GetText(); got != "draft" {
				t.Errorf("input = %q, want the draft kept", got)
			}
			requireBlockedDestinationClosed(t, a)
		})
	}
}

func TestBlockedDestination_NeverStacksWithAnotherOverlay(t *testing.T) {
	a := New(nil)
	a.openBlockedPicker([]BlockedRow{{Kind: BlockedRowFloor, Path: "/home/u/.codemeld"}})
	called := false
	NewBlockedDestinationPresenter(a).PresentDestination("/etc/secrets", func(string, BlockedDestination) string { called = true; return "" })
	if a.blockedDestinationOpen || a.pages.HasPage(blockedDestPage) || called {
		t.Fatal("destination page opened over the blocked picker")
	}

	b := New(nil)
	openBlockedDestination(t, b, "/etc/secrets")
	b.OpenSecretPrompt(SecretPromptRequest{Label: "API key:", OnSubmit: func(string) {}})
	if b.secretPromptOpen || b.pages.HasPage(secretPromptPage) {
		t.Fatal("another overlay opened over the destination page")
	}
	if !b.blockedDestinationOpen {
		t.Fatal("destination page closed by another overlay's trigger")
	}
}

func TestBlockedDestination_PathRendersLiterallyAndReachesAddRaw(t *testing.T) {
	a := New(nil)
	raw := "/tmp/[red]x\ny\tz"
	var paths []string
	NewBlockedDestinationPresenter(a).PresentDestination(raw, func(path string, _ BlockedDestination) string {
		paths = append(paths, path)
		return ""
	})
	modal := blockedDestModal(t, a)

	if text := modalScreenText(t, modal); !strings.Contains(text, "/tmp/[red]x y z") {
		t.Errorf("destination page =\n%s\nwant the path shown literally on one line", text)
	}
	keyModal(a, modal, tcell.KeyEnter)
	if !slices.Equal(paths, []string{raw}) {
		t.Errorf("AddPath = %q, want the raw %q", paths, raw)
	}
}
