package tui

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var testSystemOneChoices = []SystemOneChoice{
	{Name: "openrouter:typesafe/jev-1.13", Provider: "openrouter", ModelID: "typesafe/jev-1.13"},
	{Name: "venice:jev-latest", Provider: "venice", ModelID: "jev-latest"},
	{Name: "openrouter:liquid/d1", Provider: "openrouter", ModelID: "liquid/d1"},
}

const (
	systemOneChoicesText = "choices: off, openrouter:typesafe/jev-1.13, venice:jev-latest, openrouter:liquid/d1"
	systemOneUsage       = "usage: /systemone <off|openrouter:typesafe/jev-1.13|venice:jev-latest|openrouter:liquid/d1>"
)

type fakeSystemOne struct {
	current string
	keys    map[string]bool
	setErr  error
	sets    []string
	status  string
}

func (f *fakeSystemOne) deps() SystemOneDeps {
	return SystemOneDeps{
		Current: func() string { return f.current },
		Set: func(name string) error {
			f.sets = append(f.sets, name)
			if f.setErr != nil {
				return f.setErr
			}
			f.current = name
			return nil
		},
		Choices: testSystemOneChoices,
		HasKey:  func(p string) bool { return f.keys[p] },
		Status:  func() string { return f.status },
	}
}

func runSystemOne(t *testing.T, f *fakeSystemOne, input string) (DispatchResult, *fakeHost) {
	t.Helper()
	reg := MustNewRegistry([]Command{
		{Name: "systemone", Description: "d", ArgSig: ArgOneOptional, Phase: PhaseTwo, Handler: NewSystemOneHandler(f.deps())},
	})
	host := newFakeHost()
	res := reg.DispatchSlashInput(input, host)
	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch %q = %+v", input, res)
	}
	return res, host
}

func assertSystemOneRecord(t *testing.T, host *fakeHost, outcome, detail string) {
	t.Helper()
	evs := host.events()
	if len(evs) != 1 || host.flushes != 1 {
		t.Fatalf("events = %d, flushes = %d; want one flushed record", len(evs), host.flushes)
	}
	if p := decodeSlash(t, evs[0]); p.Name != "systemone" || p.Outcome != outcome || p.ErrorDetail != detail {
		t.Errorf("record = %+v, want outcome %q detail %q", p, outcome, detail)
	}
}

func TestSystemOneHandler_Status(t *testing.T) {
	tests := []struct {
		name    string
		current string
		keys    map[string]bool
		status  string
		want    string
	}{
		{"off", "off", nil, "", "System One: off; applies only in Plan and Auto edits; " + systemOneChoicesText},
		{"openrouter with key", "openrouter:typesafe/jev-1.13", map[string]bool{"openrouter": true}, "",
			"System One: openrouter:typesafe/jev-1.13 (provider openrouter, model typesafe/jev-1.13); applies only in Plan and Auto edits; API key: configured; " + systemOneChoicesText},
		{"venice without key", "venice:jev-latest", map[string]bool{"openrouter": true}, "",
			"System One: venice:jev-latest (provider venice, model jev-latest); applies only in Plan and Auto edits; API key: none, run /connect venice; " + systemOneChoicesText},
		{"appended status line", "openrouter:liquid/d1", map[string]bool{"openrouter": true}, "System One check paused for this session: credits",
			"System One: openrouter:liquid/d1 (provider openrouter, model liquid/d1); applies only in Plan and Auto edits; API key: configured; " + systemOneChoicesText + "; System One check paused for this session: credits"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeSystemOne{current: tt.current, keys: tt.keys, status: tt.status}
			res, host := runSystemOne(t, f, "/systemone")
			if len(host.notices) != 1 || host.notices[0] != tt.want {
				t.Errorf("notices = %q\nwant %q", host.notices, tt.want)
			}
			if res.RetainInput || len(f.sets) != 0 {
				t.Errorf("RetainInput = %v, sets = %v; want neither", res.RetainInput, f.sets)
			}
			assertSystemOneRecord(t, host, "success", "")
		})
	}
}

func TestSystemOneHandler_Selections(t *testing.T) {
	for _, tc := range []struct{ arg, want string }{
		{"venice:jev-latest", "System One set to venice:jev-latest"},
		{"openrouter:liquid/d1", "System One set to openrouter:liquid/d1"},
		{"off", "System One turned off"},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			f := &fakeSystemOne{current: "openrouter:typesafe/jev-1.13", keys: map[string]bool{"openrouter": true, "venice": true}}
			res, host := runSystemOne(t, f, "/systemone "+tc.arg)
			if len(f.sets) != 1 || f.sets[0] != tc.arg {
				t.Errorf("sets = %v, want [%q]", f.sets, tc.arg)
			}
			if len(host.notices) != 1 || host.notices[0] != tc.want || res.RetainInput {
				t.Errorf("notices = %q, retain = %v; want %q", host.notices, res.RetainInput, tc.want)
			}
			assertSystemOneRecord(t, host, "success", "")
		})
	}
}

func TestSystemOneHandler_Refusals(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		keys map[string]bool
		want string
	}{
		{"absent provider", "openrouter:typesafe/jev-1.13", map[string]bool{"venice": true}, "System One: openrouter has no API key; run /connect openrouter"},
		{"empty key", "venice:jev-latest", map[string]bool{"venice": false}, "System One: venice has no API key; run /connect venice"},
		{"unknown name", "foo", map[string]bool{"openrouter": true}, systemOneUsage},
		{"bare provider", "openrouter", map[string]bool{"openrouter": true}, systemOneUsage},
		{"wrong case", "VENICE:jev-latest", map[string]bool{"venice": true}, systemOneUsage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeSystemOne{current: "off", keys: tt.keys}
			res, host := runSystemOne(t, f, "/systemone "+tt.arg)
			if len(f.sets) != 0 {
				t.Errorf("sets = %v, want none", f.sets)
			}
			if len(host.notices) != 1 || host.notices[0] != tt.want {
				t.Errorf("notices = %q, want %q", host.notices, tt.want)
			}
			if !res.RetainInput {
				t.Error("RetainInput = false on a refusal")
			}
			assertSystemOneRecord(t, host, "error", tt.want)
		})
	}
}

func TestSystemOneHandler_WriteFailure(t *testing.T) {
	f := &fakeSystemOne{current: "off", keys: map[string]bool{"venice": true}, setErr: errors.New("write_error: disk full")}
	res, host := runSystemOne(t, f, "/systemone venice:jev-latest")
	want := "couldn't change the System One setting: write_error: disk full"
	if len(host.notices) != 1 || host.notices[0] != want {
		t.Errorf("notices = %q, want %q", host.notices, want)
	}
	if !res.RetainInput {
		t.Error("RetainInput = false on a write failure")
	}
	assertSystemOneRecord(t, host, "error", want)

	_, host = runSystemOne(t, f, "/systemone")
	if len(host.notices) != 1 || host.notices[0] != "System One: off; applies only in Plan and Auto edits; "+systemOneChoicesText {
		t.Errorf("status after a failed write = %q, want the unchanged selection", host.notices)
	}
}

func TestSystemOneHandler_BareWithOpenerOpensPickerSilently(t *testing.T) {
	f := &fakeSystemOne{current: "off"}
	opened := 0
	deps := f.deps()
	deps.OpenPicker = func() { opened++ }
	reg := MustNewRegistry([]Command{
		{Name: "systemone", Description: "d", ArgSig: ArgOneOptional, Phase: PhaseTwo, Handler: NewSystemOneHandler(deps)},
	})
	host := newFakeHost()
	res := reg.DispatchSlashInput("/systemone", host)
	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch = %+v", res)
	}
	if opened != 1 {
		t.Fatalf("OpenPicker calls = %d, want 1", opened)
	}
	if len(host.notices) != 0 || res.RetainInput || len(host.events()) != 0 || host.flushes != 0 || len(f.sets) != 0 {
		t.Errorf("notices = %q, retain = %v, events = %d, flushes = %d, sets = %v; want none", host.notices, res.RetainInput, len(host.events()), host.flushes, f.sets)
	}
}

func openSystemOnePicker(t *testing.T, f *fakeSystemOne) (*App, *tview.List) {
	t.Helper()
	a := New(nil)
	a.SetSystemOneDeps(f.deps())
	a.OpenSystemOnePicker()
	if !a.SystemOnePickerOpen() {
		t.Fatal("System One picker did not open")
	}
	list, ok := a.app.GetFocus().(*tview.List)
	if !ok {
		t.Fatalf("focused primitive = %T, want the picker's *tview.List", a.app.GetFocus())
	}
	return a, list
}

func listRows(list *tview.List) []string {
	rows := make([]string, list.GetItemCount())
	for i := range rows {
		rows[i], _ = list.GetItemText(i)
	}
	return rows
}

func TestSystemOnePicker_RowsSelectionAndHeader(t *testing.T) {
	tests := []struct {
		name     string
		current  string
		keys     map[string]bool
		status   string
		rows     []string
		selected int
		header   string
	}{
		{"off", "off", map[string]bool{"openrouter": true, "venice": true}, "",
			[]string{"off", "openrouter:typesafe/jev-1.13", "venice:jev-latest", "openrouter:liquid/d1"}, 0,
			"System One: off; applies only in Plan and Auto edits"},
		{"model with key", "openrouter:liquid/d1", map[string]bool{"openrouter": true, "venice": true}, "",
			[]string{"off", "openrouter:typesafe/jev-1.13", "venice:jev-latest", "openrouter:liquid/d1"}, 3,
			"System One: openrouter:liquid/d1 (provider openrouter, model liquid/d1); applies only in Plan and Auto edits; API key: configured"},
		{"current without key", "venice:jev-latest", map[string]bool{"openrouter": true}, "",
			[]string{"off", "openrouter:typesafe/jev-1.13", "venice:jev-latest  no API key, run /connect venice", "openrouter:liquid/d1"}, 2,
			"System One: venice:jev-latest (provider venice, model jev-latest); applies only in Plan and Auto edits; API key: none, run /connect venice"},
		{"paused", "openrouter:typesafe/jev-1.13", map[string]bool{"openrouter": true}, "System One check paused for this session: credits",
			[]string{"off", "openrouter:typesafe/jev-1.13", "venice:jev-latest  no API key, run /connect venice", "openrouter:liquid/d1"}, 1,
			"System One: openrouter:typesafe/jev-1.13 (provider openrouter, model typesafe/jev-1.13); applies only in Plan and Auto edits; API key: configured; System One check paused for this session: credits"},
		{"paused while off", "off", nil, "System One check paused for this session: credits",
			[]string{"off", "openrouter:typesafe/jev-1.13  no API key, run /connect openrouter", "venice:jev-latest  no API key, run /connect venice", "openrouter:liquid/d1  no API key, run /connect openrouter"}, 0,
			"System One: off; applies only in Plan and Auto edits; System One check paused for this session: credits"},
		{"unmatched current", "openrouter:retired/x", map[string]bool{"openrouter": true, "venice": true}, "",
			[]string{"off", "openrouter:typesafe/jev-1.13", "venice:jev-latest", "openrouter:liquid/d1"}, 0,
			"System One: openrouter:retired/x; applies only in Plan and Auto edits"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeSystemOne{current: tt.current, keys: tt.keys, status: tt.status}
			a, list := openSystemOnePicker(t, f)
			if got := listRows(list); !slices.Equal(got, tt.rows) {
				t.Errorf("rows = %q\nwant %q", got, tt.rows)
			}
			if got := list.GetCurrentItem(); got != tt.selected {
				t.Errorf("selected row = %d, want %d", got, tt.selected)
			}
			if got := a.SystemOnePickerStatusText(); got != tt.header {
				t.Errorf("header = %q\nwant %q", got, tt.header)
			}
			if len(f.sets) != 0 || a.transcript.notice != "" {
				t.Errorf("sets = %v, notice = %q; opening must not write or notify", f.sets, a.transcript.notice)
			}
		})
	}
}

func drawnPickerText(t *testing.T, page tview.Primitive, width, height int) string {
	t.Helper()
	cells, w, h := drawPrimitive(t, page, width, height).GetContents()
	var b strings.Builder
	for row := 1; row < h-1; row++ {
		for col := 1; col < w-1; col++ {
			if r := cells[row*w+col].Runes; len(r) > 0 && r[0] != ' ' {
				b.WriteString(string(r))
			}
		}
	}
	return b.String()
}

func TestSystemOnePicker_WrappedHeaderStaysVisibleAcrossResize(t *testing.T) {
	f := &fakeSystemOne{current: "venice:jev-latest", status: "System One check paused for this session: out of credits on venice"}
	a, _ := openSystemOnePicker(t, f)
	page := a.pages.GetPage(systemOnePickerPage)
	want := "System One: venice:jev-latest (provider venice, model jev-latest); applies only in Plan and Auto edits; API key: none, run /connect venice; System One check paused for this session: out of credits on venice"
	for _, width := range []int{120, 28, 60} {
		got := drawnPickerText(t, page, width, 30)
		if !strings.Contains(got, strings.ReplaceAll(want, " ", "")+"off") {
			t.Errorf("width %d: drawn picker = %q\nwant the whole header %q followed by the off row", width, got, want)
		}
	}
}

func TestSystemOnePicker_RefusesToOpen(t *testing.T) {
	for _, tc := range []struct {
		name  string
		strip func(*SystemOneDeps)
	}{
		{"no Current", func(d *SystemOneDeps) { d.Current = nil }},
		{"no Set", func(d *SystemOneDeps) { d.Set = nil }},
		{"no HasKey", func(d *SystemOneDeps) { d.HasKey = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			deps := (&fakeSystemOne{current: "off"}).deps()
			tc.strip(&deps)
			a.SetSystemOneDeps(deps)
			a.OpenSystemOnePicker()
			if a.SystemOnePickerOpen() || a.pages.HasPage(systemOnePickerPage) {
				t.Error("picker opened with a required dependency missing")
			}
		})
	}

	t.Run("another overlay open", func(t *testing.T) {
		a := New(nil)
		a.SetSystemOneDeps((&fakeSystemOne{current: "off"}).deps())
		a.statusOpen = true
		a.OpenSystemOnePicker()
		if a.SystemOnePickerOpen() || a.pages.HasPage(systemOnePickerPage) {
			t.Error("picker opened over another overlay")
		}
	})

	t.Run("optional Status and Choices", func(t *testing.T) {
		a := New(nil)
		deps := (&fakeSystemOne{current: "off"}).deps()
		deps.Status, deps.Choices = nil, nil
		a.SetSystemOneDeps(deps)
		a.OpenSystemOnePicker()
		if !a.SystemOnePickerOpen() {
			t.Fatal("picker refused without the optional Status and Choices")
		}
		if got := listRows(a.app.GetFocus().(*tview.List)); !slices.Equal(got, []string{"off"}) {
			t.Errorf("rows = %q, want only off", got)
		}
	})
}

func TestSystemOnePicker_EscRestoresFocusWithoutWriting(t *testing.T) {
	f := &fakeSystemOne{current: "off"}
	a := New(nil)
	a.SetSystemOneDeps(f.deps())
	before := tview.NewBox()
	a.app.SetFocus(before)
	a.OpenSystemOnePicker()
	if !a.SystemOnePickerOpen() {
		t.Fatal("picker did not open")
	}
	a.HandleEsc()
	if a.SystemOnePickerOpen() || a.pages.HasPage(systemOnePickerPage) {
		t.Error("picker still mounted after Esc")
	}
	if a.app.GetFocus() != before {
		t.Errorf("focus = %T, want the primitive focused before the picker opened", a.app.GetFocus())
	}
	if len(f.sets) != 0 || a.transcript.notice != "" {
		t.Errorf("sets = %v, notice = %q; want neither", f.sets, a.transcript.notice)
	}
}

func pressPickerKeys(list *tview.List, keys ...tcell.Key) {
	for _, k := range keys {
		list.InputHandler()(tcell.NewEventKey(k, 0, tcell.ModNone), func(tview.Primitive) {})
	}
}

func TestSystemOnePicker_EnterConfirmsTheHighlightedRow(t *testing.T) {
	keys := map[string]bool{"openrouter": true, "venice": true}

	t.Run("different keyed model", func(t *testing.T) {
		f := &fakeSystemOne{current: "off", keys: keys}
		a, list := openSystemOnePicker(t, f)
		pressPickerKeys(list, tcell.KeyDown, tcell.KeyDown, tcell.KeyEnter)
		if !slices.Equal(f.sets, []string{"venice:jev-latest"}) || a.transcript.notice != "System One set to venice:jev-latest" {
			t.Errorf("sets = %v, notice = %q; want venice written and confirmed", f.sets, a.transcript.notice)
		}
		if a.SystemOnePickerOpen() {
			t.Error("picker still open after a confirmation")
		}
	})

	t.Run("current value", func(t *testing.T) {
		f := &fakeSystemOne{current: "openrouter:liquid/d1", keys: map[string]bool{"venice": true}}
		a, list := openSystemOnePicker(t, f)
		pressPickerKeys(list, tcell.KeyEnter)
		if len(f.sets) != 0 || a.transcript.notice != "" || a.SystemOnePickerOpen() {
			t.Errorf("sets = %v, notice = %q, open = %v; want a silent close", f.sets, a.transcript.notice, a.SystemOnePickerOpen())
		}
	})

	t.Run("unmatched current confirms off", func(t *testing.T) {
		f := &fakeSystemOne{current: "openrouter:retired/x", keys: keys}
		a, list := openSystemOnePicker(t, f)
		if len(f.sets) != 0 {
			t.Fatalf("opening wrote %v", f.sets)
		}
		pressPickerKeys(list, tcell.KeyEnter)
		if !slices.Equal(f.sets, []string{"off"}) || a.transcript.notice != "System One turned off" {
			t.Errorf("sets = %v, notice = %q; want off written and confirmed", f.sets, a.transcript.notice)
		}
	})

	t.Run("different model without key", func(t *testing.T) {
		f := &fakeSystemOne{current: "off", keys: map[string]bool{"venice": true}}
		a, list := openSystemOnePicker(t, f)
		pressPickerKeys(list, tcell.KeyDown, tcell.KeyEnter)
		if len(f.sets) != 0 || a.transcript.notice != "System One: openrouter has no API key; run /connect openrouter" || a.SystemOnePickerOpen() {
			t.Errorf("sets = %v, notice = %q, open = %v; want the no-key refusal and a closed picker", f.sets, a.transcript.notice, a.SystemOnePickerOpen())
		}
	})

	t.Run("failed write", func(t *testing.T) {
		f := &fakeSystemOne{current: "off", keys: keys, setErr: errors.New("write_error: disk full")}
		a, list := openSystemOnePicker(t, f)
		pressPickerKeys(list, tcell.KeyDown, tcell.KeyEnter)
		if a.transcript.notice != "couldn't change the System One setting: write_error: disk full" || a.SystemOnePickerOpen() || f.current != "off" {
			t.Errorf("notice = %q, open = %v, current = %q; want the failure notice, a closed picker and no change", a.transcript.notice, a.SystemOnePickerOpen(), f.current)
		}
	})
}

func TestSystemOnePicker_SelectRowForTestNeedsAnOpenPickerAndARow(t *testing.T) {
	f := &fakeSystemOne{current: "off", keys: map[string]bool{"venice": true}}
	a := New(nil)
	a.SetSystemOneDeps(f.deps())
	if a.SelectSystemOneRowForTest("venice:jev-latest") {
		t.Error("selected a row with the picker closed")
	}
	a.OpenSystemOnePicker()
	if a.SelectSystemOneRowForTest("venice:other") || !a.SystemOnePickerOpen() {
		t.Error("selected an absent row")
	}
	if !a.SelectSystemOneRowForTest("venice:jev-latest") || !slices.Equal(f.sets, []string{"venice:jev-latest"}) {
		t.Errorf("sets = %v, want the row confirmed", f.sets)
	}
}
