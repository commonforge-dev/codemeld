// Tests for the command registry: TR-TUI-3 validation fixtures plus dispatch
// tests for alias routing, unknown/wrong-arity rejection, bare exit, and
// canonical-name event recording via a fake command host.
package tui

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

// fakeHost is an in-memory CommandHost: it records rendered notices and backs
// AppendSlashCommand with a real but never-flushed session store so appended
// events can be read back without touching disk.
type fakeHost struct {
	store    *sessions.Store
	notices  []string
	panels   []string
	statuses []string
	flushes  int
}

func newFakeHost() *fakeHost {
	return &fakeHost{store: sessions.New("", &sessions.Session{})}
}

func (h *fakeHost) Notice(text string)       { h.notices = append(h.notices, text) }
func (h *fakeHost) ShowPanel(text string)    { h.panels = append(h.panels, text) }
func (h *fakeHost) ShowStatus(text string)   { h.statuses = append(h.statuses, text) }
func (h *fakeHost) Store() *sessions.Store   { return h.store }
func (h *fakeHost) events() []sessions.Event { return slashEvents(h.store) }

// FlushActive does not write to disk: fakeHost's store carries an empty path (its
// appended events are read back in memory), so the command-event flush hook the
// production app injects is absent here and dispatch durability is exercised in the
// bootstrap submit-boundary tests instead. It counts calls so ordering tests can
// assert a handler flushed before its next step (e.g. before opening an overlay).
func (h *fakeHost) FlushActive() error { h.flushes++; return nil }

// slashEvents returns every slash_command event currently in the store.
func slashEvents(store *sessions.Store) []sessions.Event {
	var out []sessions.Event
	for _, rec := range store.Records() {
		if ev, ok := rec.(sessions.Event); ok && ev.Kind == events.KindSlashCommand {
			out = append(out, ev)
		}
	}
	return out
}

func decodeSlash(t *testing.T, ev sessions.Event) events.SlashCommand {
	t.Helper()
	var p events.SlashCommand
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatalf("decode slash_command payload: %v", err)
	}
	return p
}

// nopHandler is a non-nil handler for validation fixtures, where dispatch (and
// thus the handler) never runs.
func nopHandler(CommandContext, []string) error { return nil }

func TestBuildRegistry_BuildsAndResolvesAliases(t *testing.T) {
	r := BuildRegistry(nil)
	if r == nil {
		t.Fatal("BuildRegistry(nil) returned nil")
	}
	// Real list passes validation (no panic in BuildRegistry, no error on re-validate).
	if _, err := NewRegistry(builtinCommands); err != nil {
		t.Fatalf("built-in list failed validation: %v", err)
	}

	if cmd, ok := r.resolve("new"); !ok || cmd.Name != "clear" {
		t.Fatalf("alias /new resolved to (%q, %v), want (clear, true)", cmd.Name, ok)
	}
	if cmd, ok := r.resolve("quit"); !ok || cmd.Name != "exit" {
		t.Fatalf("alias /quit resolved to (%q, %v), want (exit, true)", cmd.Name, ok)
	}
}

func TestCommands_ReturnsSourceOrder(t *testing.T) {
	got := BuildRegistry(nil).Commands()
	names := make([]string, len(got))
	for i, c := range got {
		names[i] = c.Name
	}
	want := []string{"help", "clear", "connect", "status", "context", "effort", "model", "mode", "resume", "settings", "blocked", "exit", "rename", "color", "fork", "compact"}
	if !equalStrings(names, want) {
		t.Fatalf("Commands() names = %v, want %v", names, want)
	}
}

func TestRegistry_PermissionsIsNotRegistered(t *testing.T) {
	r := BuildRegistry(nil)
	if cmd, ok := r.resolve("permissions"); ok {
		t.Fatalf("permissions resolved to %q, want no command or alias", cmd.Name)
	}
	if res := r.DispatchSlashInput("/permissions", newFakeHost()); res.Status != StatusUnknownCommand {
		t.Fatalf("dispatch /permissions status = %v, want StatusUnknownCommand", res.Status)
	}
	if cmd, ok := r.resolve("settings"); !ok || cmd.Name != "settings" || cmd.Description != "Show and change settings and stored permission grants" {
		t.Fatalf("settings resolved to (%+v, %v), want the settings command", cmd, ok)
	}
}

func TestRenderHelp_ListsBlocked(t *testing.T) {
	if out := RenderHelp(BuildRegistry(nil)); !strings.Contains(out, "/blocked") || !strings.Contains(out, "Show blocked paths and where each comes from; /blocked add <path> blocks another") {
		t.Fatalf("help output = %q, want /blocked with its description", out)
	}
}

// TestNewRegistry_Validation is the TR-TUI-3 detector: each violation class must
// fail registry construction, and the canonical good list must pass.
func TestNewRegistry_Validation(t *testing.T) {
	cmd := func(name string, aliases []string, sig ArgSignature, phase Phase) Command {
		return Command{Name: name, Aliases: aliases, ArgSig: sig, Phase: phase, Handler: nopHandler}
	}

	cases := []struct {
		name    string
		cmds    []Command
		wantErr bool
	}{
		{
			name: "valid",
			cmds: []Command{cmd("help", nil, ArgNone, PhaseOne), cmd("clear", []string{"new"}, ArgNone, PhaseTwo)},
		},
		{
			name:    "phase below range",
			cmds:    []Command{cmd("help", nil, ArgNone, Phase(0))},
			wantErr: true,
		},
		{
			name:    "phase above range",
			cmds:    []Command{cmd("help", nil, ArgNone, Phase(4))},
			wantErr: true,
		},
		{
			name:    "alias regex violation",
			cmds:    []Command{cmd("clear", []string{"New"}, ArgNone, PhaseOne)},
			wantErr: true,
		},
		{
			name:    "duplicate canonical name",
			cmds:    []Command{cmd("help", nil, ArgNone, PhaseOne), cmd("help", nil, ArgNone, PhaseOne)},
			wantErr: true,
		},
		{
			name:    "alias collides with a canonical name",
			cmds:    []Command{cmd("status", nil, ArgNone, PhaseOne), cmd("clear", []string{"status"}, ArgNone, PhaseOne)},
			wantErr: true,
		},
		{
			name:    "alias collides with another alias",
			cmds:    []Command{cmd("clear", []string{"new"}, ArgNone, PhaseOne), cmd("exit", []string{"new"}, ArgNone, PhaseOne)},
			wantErr: true,
		},
		{
			name:    "nil handler",
			cmds:    []Command{{Name: "help", ArgSig: ArgNone, Phase: PhaseOne, Handler: nil}},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRegistry(tc.cmds)
			if tc.wantErr && err == nil {
				t.Fatal("expected a validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestMustNewRegistry_PanicsOnInvalid(t *testing.T) {
	bad := []Command{{Name: "help", ArgSig: ArgNone, Phase: Phase(9), Handler: nopHandler}}
	assertPanics(t, func() { MustNewRegistry(bad) })
	assertNotPanics(t, func() { MustNewRegistry(builtinCommands) })
}

func TestArgSignature_Accepts(t *testing.T) {
	cases := []struct {
		sig  ArgSignature
		n    int
		want bool
	}{
		{ArgNone, 0, true}, {ArgNone, 1, false},
		{ArgOneRequired, 0, false}, {ArgOneRequired, 1, true}, {ArgOneRequired, 2, false},
		{ArgOneOptional, 0, true}, {ArgOneOptional, 1, true}, {ArgOneOptional, 2, false},
		{ArgRestRequired, 0, false}, {ArgRestRequired, 1, true}, {ArgRestRequired, 2, true},
		{ArgRestOptional, 0, true}, {ArgRestOptional, 1, true}, {ArgRestOptional, 3, true},
	}
	for _, tc := range cases {
		if got := tc.sig.accepts(tc.n); got != tc.want {
			t.Errorf("ArgSignature(%d).accepts(%d) = %v, want %v", tc.sig, tc.n, got, tc.want)
		}
	}
}

func TestDispatch_RestOptionalJoinsWords(t *testing.T) {
	var got [][]string
	r := MustNewRegistry([]Command{{Name: "blocked", Description: "d", ArgSig: ArgRestOptional, Phase: PhaseOne, Handler: func(_ CommandContext, args []string) error {
		got = append(got, args)
		return nil
	}}})
	for _, input := range []string{"/blocked", "/blocked add", "/blocked add  ~/a   b"} {
		if res := r.DispatchSlashInput(input, newFakeHost()); res.Status != StatusHandled {
			t.Fatalf("dispatch %q = %+v, want Handled", input, res)
		}
	}
	want := [][]string{nil, {"add"}, {"add ~/a b"}}
	if len(got) != len(want) {
		t.Fatalf("handler calls = %v, want %v", got, want)
	}
	for i := range want {
		if !equalStrings(got[i], want[i]) {
			t.Errorf("call %d args = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDispatch_AliasRecordsCanonicalName(t *testing.T) {
	host := newFakeHost()
	res := BuildRegistry(nil).DispatchSlashInput("/new", host)

	if res.Status != StatusHandled || res.Canonical != "clear" || res.Err != nil || res.RetainInput {
		t.Fatalf("dispatch /new = %+v, want Handled/clear/nil-err/no-retain", res)
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	p := decodeSlash(t, evs[0])
	if p.Name != "clear" {
		t.Errorf("event name = %q, want canonical %q (not the alias)", p.Name, "clear")
	}
	if p.Outcome != "success" {
		t.Errorf("event outcome = %q, want success", p.Outcome)
	}
	if len(p.Args) != 0 {
		t.Errorf("event args = %v, want empty", p.Args)
	}
}

func TestDispatch_ValidInvocationPassesArgs(t *testing.T) {
	host := newFakeHost()
	res := BuildRegistry(nil).DispatchSlashInput("/effort high", host)

	if res.Status != StatusHandled || res.Canonical != "effort" || res.Err != nil {
		t.Fatalf("dispatch /effort high = %+v, want Handled/effort/nil-err", res)
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	p := decodeSlash(t, evs[0])
	if p.Name != "effort" || !equalStrings(p.Args, []string{"high"}) || p.Outcome != "success" {
		t.Errorf("event = %+v, want name=effort args=[high] outcome=success", p)
	}
}

func TestDispatch_UnknownCommand(t *testing.T) {
	host := newFakeHost()
	res := BuildRegistry(nil).DispatchSlashInput("/bogus", host)

	if res.Status != StatusUnknownCommand {
		t.Fatalf("status = %v, want StatusUnknownCommand", res.Status)
	}
	if !res.RetainInput {
		t.Error("RetainInput = false, want true (req 560)")
	}
	want := "unknown command: /bogus — type /help to see available commands"
	if res.Notice != want {
		t.Errorf("notice = %q, want %q", res.Notice, want)
	}
	if len(host.notices) != 1 || host.notices[0] != want {
		t.Errorf("host notices = %v, want exactly [%q]", host.notices, want)
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("unknown command appended %d events, want 0 (req 570)", len(evs))
	}
}

func TestDispatch_WrongArity(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		canonical string
	}{
		{"none-with-arg", "/help extra", "help"},
		{"effort-too-many", "/effort a b", "effort"},
		{"model-too-many", "/model a b", "model"},
		{"color-missing", "/color", "color"},
		{"color-too-many", "/color red blue", "color"},
		{"fork-with-arg", "/fork now", "fork"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := newFakeHost()
			res := BuildRegistry(nil).DispatchSlashInput(tc.input, host)

			if res.Status != StatusWrongArity {
				t.Fatalf("status = %v, want StatusWrongArity", res.Status)
			}
			if res.Canonical != tc.canonical {
				t.Errorf("canonical = %q, want %q", res.Canonical, tc.canonical)
			}
			if !res.RetainInput {
				t.Error("RetainInput = false, want true (req 565)")
			}
			if !strings.Contains(res.Notice, "/"+tc.canonical) {
				t.Errorf("notice %q does not name the command /%s", res.Notice, tc.canonical)
			}
			if !strings.Contains(res.Notice, "got ") {
				t.Errorf("notice %q does not state the supplied count", res.Notice)
			}
			if evs := host.events(); len(evs) != 0 {
				t.Errorf("wrong-arity appended %d events, want 0 (req 570)", len(evs))
			}
		})
	}
}

func TestDispatch_BareExitMapsToExit(t *testing.T) {
	for _, in := range []string{"exit", "QUIT", "  quit  "} {
		t.Run(in, func(t *testing.T) {
			host := newFakeHost()
			res := BuildRegistry(nil).DispatchSlashInput(in, host)

			if res.Status != StatusHandled || res.Canonical != "exit" {
				t.Fatalf("dispatch %q = %+v, want Handled/exit (req 595)", in, res)
			}
			evs := host.events()
			if len(evs) != 1 {
				t.Fatalf("appended %d events, want 1", len(evs))
			}
			if name := decodeSlash(t, evs[0]).Name; name != "exit" {
				t.Errorf("event name = %q, want exit", name)
			}
		})
	}
}

func TestDispatch_NotASlashCommand(t *testing.T) {
	host := newFakeHost()
	res := BuildRegistry(nil).DispatchSlashInput("hello world", host)

	if res.Status != StatusNotASlashCommand {
		t.Fatalf("status = %v, want StatusNotASlashCommand", res.Status)
	}
	if res.RetainInput || res.Notice != "" {
		t.Errorf("res = %+v, want no retain and empty notice", res)
	}
	if len(host.notices) != 0 || len(host.events()) != 0 {
		t.Errorf("notices=%v events=%d, want none", host.notices, len(host.events()))
	}
}

// TestColorPaletteNames_MatchPalette pins the command's ordered choice list against
// the closed palette (colors.go) so the two cannot drift — a seventh palette entry or
// a renamed name fails here rather than silently dropping out of the /color error text.
func TestColorPaletteNames_MatchPalette(t *testing.T) {
	if len(colorPaletteNames) != len(inputAccentPalette) {
		t.Fatalf("colorPaletteNames has %d names, palette has %d", len(colorPaletteNames), len(inputAccentPalette))
	}
	for _, name := range colorPaletteNames {
		if _, ok := inputAccentPalette[name]; !ok {
			t.Errorf("colorPaletteNames lists %q which is not in inputAccentPalette", name)
		}
	}
}

// TestRenderHelp_IncludesColor confirms /color appears in the phase-2 help listing
// (buildPhase == PhaseTwo), the user-visible half of wiring the command.
func TestRenderHelp_IncludesColor(t *testing.T) {
	if out := RenderHelp(BuildRegistry(nil)); !strings.Contains(out, "/color") {
		t.Error("help output missing /color (a phase-2 command must be listed)")
	}
}

func TestRenderHelp_IncludesFork(t *testing.T) {
	if out := RenderHelp(BuildRegistry(nil)); !strings.Contains(out, "/fork") {
		t.Error("help output missing /fork (a phase-2 command must be listed)")
	}
}

func TestBuildRegistry_ForkReplacementDispatches(t *testing.T) {
	host := newFakeHost()
	var gotArgs []string
	calls := 0
	reg := BuildRegistry(map[string]HandlerFunc{
		"fork": func(ctx CommandContext, args []string) error {
			calls++
			gotArgs = args
			return ctx.AppendSlashCommand(OutcomeSuccess, "")
		},
	})

	res := reg.DispatchSlashInput("/fork", host)

	if res.Status != StatusHandled || res.Canonical != "fork" || res.Err != nil {
		t.Fatalf("dispatch /fork = %+v, want Handled/fork/nil-err", res)
	}
	if calls != 1 {
		t.Fatalf("fork replacement ran %d times, want 1 (BuildRegistry must rebind the placeholder)", calls)
	}
	if len(gotArgs) != 0 {
		t.Errorf("fork handler received args %v, want none (ArgNone)", gotArgs)
	}
	if evs := host.events(); len(evs) != 1 || decodeSlash(t, evs[0]).Name != "fork" {
		t.Errorf("appended events = %+v, want one fork slash_command", evs)
	}
}

func TestCompleteSlashName_IncludesFork(t *testing.T) {
	got := completeSlashName("/fo", 3, BuildRegistry(nil))
	if got.Action != tabReplace || got.Text != "/fork" {
		t.Fatalf("completeSlashName(%q) = %+v, want tabReplace to /fork", "/fo", got)
	}
}

func TestRenderHelp_IncludesCompact(t *testing.T) {
	out := RenderHelp(BuildRegistry(nil))
	if !strings.Contains(out, "/compact — Replace the conversation with a summary in a fresh child session") {
		t.Errorf("help output missing the shipped /compact row:\n%s", out)
	}
}

func TestCompact_IsPhaseTwoNoArgument(t *testing.T) {
	var compact Command
	for _, c := range BuildRegistry(nil).Commands() {
		if c.Name == "compact" {
			compact = c
		}
	}
	if compact.Name == "" {
		t.Fatal("/compact is not in the built-in registry")
	}
	if compact.Phase != PhaseTwo {
		t.Errorf("/compact phase = %d, want PhaseTwo (a phase-1 build must not list it)", compact.Phase)
	}
	if compact.ArgSig != ArgNone {
		t.Errorf("/compact arg signature = %d, want ArgNone", compact.ArgSig)
	}
	if len(compact.Aliases) != 0 {
		t.Errorf("/compact aliases = %v, want none", compact.Aliases)
	}
}

func TestCompleteSlashName_ResolvesCompactPrefix(t *testing.T) {
	reg := BuildRegistry(nil)
	if got := completeSlashName("/com", 4, reg); got.Action != tabReplace || got.Text != "/compact" {
		t.Fatalf("completeSlashName(%q) = %+v, want tabReplace to /compact", "/com", got)
	}
	if got := completeSlashName("/co", 3, reg); got.Action == tabReplace && got.Text == "/compact" {
		t.Fatalf("completeSlashName(%q) resolved to /compact; /co is ambiguous", "/co")
	}
	if got := completeSlashName("/zzz", 4, reg); got.Action == tabReplace {
		t.Fatalf("completeSlashName(%q) = %+v, want no replacement", "/zzz", got)
	}
}

func TestBuildRegistry_CompactReplacementDispatches(t *testing.T) {
	host := newFakeHost()
	calls := 0
	var gotArgs []string
	reg := BuildRegistry(map[string]HandlerFunc{
		"compact": func(ctx CommandContext, args []string) error {
			calls++
			gotArgs = args
			return ctx.AppendSlashCommand(OutcomeSuccess, "")
		},
	})

	res := reg.DispatchSlashInput("/compact", host)
	if res.Status != StatusHandled || res.Canonical != "compact" || res.Err != nil {
		t.Fatalf("dispatch /compact = %+v, want Handled/compact/nil-err", res)
	}
	if calls != 1 {
		t.Fatalf("compact replacement ran %d times, want 1 (BuildRegistry must rebind the placeholder)", calls)
	}
	if len(gotArgs) != 0 {
		t.Errorf("compact handler received args %v, want none (ArgNone)", gotArgs)
	}
	if evs := host.events(); len(evs) != 1 || decodeSlash(t, evs[0]).Name != "compact" {
		t.Fatalf("appended events = %+v, want one compact slash_command", evs)
	}

	res = reg.DispatchSlashInput("/compact now", host)
	if res.Status != StatusWrongArity || res.Canonical != "compact" || !res.RetainInput {
		t.Fatalf("dispatch %q = %+v, want WrongArity/compact with input retained", "/compact now", res)
	}
	if calls != 1 {
		t.Fatalf("compact handler ran %d times, want 1 (arity is rejected before the handler)", calls)
	}
	if evs := host.events(); len(evs) != 1 {
		t.Fatalf("appended events = %+v, want no event for the rejected arity", evs)
	}
}

// TestColorHandler_AppliesAllPaletteValues drives every palette name through the
// production dispatch path: the apply seam receives the resolved color, a success
// event is recorded, and the success is flushed before the visible accent change.
func TestColorHandler_AppliesAllPaletteValues(t *testing.T) {
	for _, name := range colorPaletteNames {
		t.Run(name, func(t *testing.T) {
			host := newFakeHost()
			var applied tcell.Color
			var appliedCount, flushesAtApply int
			reg := BuildRegistry(map[string]HandlerFunc{
				"color": NewColorHandler(ColorDeps{Apply: func(c tcell.Color) {
					applied = c
					appliedCount++
					flushesAtApply = host.flushes
				}}),
			})
			res := reg.DispatchSlashInput("/color "+name, host)

			if res.Status != StatusHandled || res.Canonical != "color" || res.Err != nil {
				t.Fatalf("dispatch /color %s = %+v, want Handled/color/nil-err", name, res)
			}
			if res.RetainInput {
				t.Error("success retained input, want cleared")
			}
			if appliedCount != 1 {
				t.Fatalf("Apply called %d times, want 1", appliedCount)
			}
			if want := inputAccentPalette[name]; applied != want {
				t.Errorf("applied color = %v, want %v", applied, want)
			}
			if flushesAtApply != 1 {
				t.Errorf("flushes before Apply = %d, want 1 (success must flush before the accent change)", flushesAtApply)
			}
			evs := host.events()
			if len(evs) != 1 {
				t.Fatalf("appended %d slash_command events, want 1", len(evs))
			}
			if p := decodeSlash(t, evs[0]); p.Name != "color" || p.Outcome != "success" ||
				!equalStrings(p.Args, []string{name}) || p.ErrorDetail != "" {
				t.Errorf("event = %+v, want name=color args=[%s] outcome=success no-error", p, name)
			}
		})
	}
}

// TestColorHandler_RejectsUnknownColorAndRetainsInput covers the bad-value path: a
// one-line notice naming the value and all six choices, retained input, a flushed
// error event, and no accent apply.
func TestColorHandler_RejectsUnknownColorAndRetainsInput(t *testing.T) {
	host := newFakeHost()
	applied := 0
	reg := BuildRegistry(map[string]HandlerFunc{
		"color": NewColorHandler(ColorDeps{Apply: func(tcell.Color) { applied++ }}),
	})
	res := reg.DispatchSlashInput("/color orange", host)

	if res.Status != StatusHandled || res.Canonical != "color" || res.Err != nil {
		t.Fatalf("dispatch /color orange = %+v, want Handled/color/nil-err", res)
	}
	if !res.RetainInput {
		t.Error("RetainInput = false, want true (a bad value keeps the typed input)")
	}
	if applied != 0 {
		t.Errorf("Apply called %d times on a bad value, want 0 (prior accent unchanged)", applied)
	}
	if host.flushes != 1 {
		t.Errorf("flushes = %d, want 1 (error event must be flushed)", host.flushes)
	}
	if len(host.notices) != 1 {
		t.Fatalf("notices = %v, want exactly one", host.notices)
	}
	notice := host.notices[0]
	if !strings.Contains(notice, "orange") {
		t.Errorf("notice %q does not name the supplied value", notice)
	}
	for _, name := range colorPaletteNames {
		if !strings.Contains(notice, name) {
			t.Errorf("notice %q does not list valid color %q", notice, name)
		}
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Name != "color" || p.Outcome != "error" ||
		p.ErrorDetail != notice || !equalStrings(p.Args, []string{"orange"}) {
		t.Errorf("event = %+v, want name=color args=[orange] outcome=error error_detail=notice", p)
	}
}

func assertPanics(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("expected a panic, got none")
		}
	}()
	fn()
}

func assertNotPanics(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("unexpected panic: %v", r)
		}
	}()
	fn()
}
