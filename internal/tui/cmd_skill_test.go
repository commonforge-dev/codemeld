package tui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/skills"
)

type skillFixture struct {
	t        *testing.T
	a        *App
	store    *sessions.Store
	reg      *Registry
	sent     []string
	plain    []string
	accept   bool
	hold     bool
	flushes  int
	flushErr error
}

func newSkillFixture(t *testing.T, loaded ...skills.Skill) *skillFixture {
	t.Helper()
	f := &skillFixture{t: t, a: New(nil), accept: true}
	f.store = queueTestStore(filepath.Join(t.TempDir(), "session.json"))
	f.a.SetActiveStore(f.store)
	f.a.SetCommandFlush(func() error {
		f.flushes++
		return f.flushErr
	})
	f.a.SetLiteralPrompt(func(text string, _ ...sessions.ContentPart) bool {
		if !f.accept {
			return false
		}
		if f.hold {
			f.a.EnqueuePrompt(text)
			return true
		}
		f.sent = append(f.sent, text)
		return true
	})
	cmds, _ := SkillCommands(loaded, SkillDeps{Submit: f.a.SubmitLiteral, ReplaceEcho: f.a.ReplaceNextEcho})
	f.reg = MustNewRegistry(append(BuildRegistry(nil).Commands(), cmds...))
	f.a.SetRegistry(f.reg)
	f.a.SetSubmit(NewSubmitFunc(f.reg, f.a, func(text string, _ ...sessions.ContentPart) bool {
		f.plain = append(f.plain, text)
		return true
	}))
	return f
}

func (f *skillFixture) slashCommands() []slashRecord {
	f.t.Helper()
	var out []slashRecord
	for _, ev := range slashEvents(f.store) {
		p := decodeSlash(f.t, ev)
		out = append(out, slashRecord{name: p.Name, args: strings.Join(p.Args, "|"), outcome: p.Outcome, detail: p.ErrorDetail})
	}
	return out
}

type slashRecord struct {
	name, args, outcome, detail string
}

func skillLoadEvents(records []sessions.Record) []sessions.Event {
	var out []sessions.Event
	for _, rec := range records {
		if ev, ok := rec.(sessions.Event); ok && ev.Kind == "skill_loaded" {
			out = append(out, ev)
		}
	}
	return out
}

func recordKinds(records []sessions.Record) []string {
	var out []string
	for _, rec := range records {
		if ev, ok := rec.(sessions.Event); ok {
			out = append(out, ev.Kind)
		}
	}
	return out
}

func skill(name, body string) skills.Skill {
	return skills.Skill{Name: name, Description: "Does " + name, Layer: skills.Project, Body: body, ModelInvocable: true}
}

func replayedUserText(text string) string {
	replay := New(nil)
	replay.ReplaySessionRecords([]sessions.Record{
		sessions.Message{ID: "u1", Role: "user", Content: sessions.TextContent(text), Timestamp: time.Date(2026, 7, 29, 9, 0, 0, 0, time.UTC)},
	})
	return replay.TranscriptText()
}

func TestExpandSkill(t *testing.T) {
	cases := []struct {
		name, body, args, want string
	}{
		{"repeated placeholders", "A $ARGUMENTS and B $ARGUMENTS", "x y", "A x y and B x y"},
		{"no arguments empties the placeholder", "run $ARGUMENTS now", "", "run  now"},
		{"no arguments and no placeholder adds nothing", "plain body", "", "plain body"},
		{"suffix only without a substitutable placeholder", "plain body", "fix it", "plain body\n\nARGUMENTS: fix it"},
		{"escaped placeholder keeps its backslash", `keep \$ARGUMENTS`, "x", "keep \\$ARGUMENTS\n\nARGUMENTS: x"},
		{"escaped dollar elsewhere", `cost \$5 for $ARGUMENTS`, "x", `cost \$5 for x`},
		{"indexed placeholder is preserved", "first $ARGUMENTS[0]", "x", "first $ARGUMENTS[0]\n\nARGUMENTS: x"},
		{"positional placeholders are preserved", "$0 and $1", "x", "$0 and $1\n\nARGUMENTS: x"},
		{"literal match swallows no identifier tail", "$ARGUMENTStail", "x", "xtail"},
		{"argument text is not expanded again", "say $ARGUMENTS", "$ARGUMENTS", "say $ARGUMENTS"},
		{"mixed indexed and plain", "$ARGUMENTS[1] $ARGUMENTS", "go", "$ARGUMENTS[1] go"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := expandSkill(tc.body, tc.args); got != tc.want {
				t.Fatalf("expandSkill(%q, %q) = %q, want %q", tc.body, tc.args, got, tc.want)
			}
		})
	}
}

func TestSkillCommand_SubmitsExpandedBodyAsUserTurn(t *testing.T) {
	f := newSkillFixture(t, skill("my-skill", "Please $ARGUMENTS carefully.\n"))

	if !f.a.SubmitInput("/my-skill   fix\tthe    tests  ") {
		t.Fatal("/my-skill with words was rejected; want a normal accepted turn")
	}

	if want := []string{"Please fix the tests carefully.\n"}; !slices.Equal(f.sent, want) {
		t.Fatalf("prompt callback got %q, want %q", f.sent, want)
	}
	if len(f.plain) != 0 {
		t.Fatalf("plain prompt path got %q, want nothing (the body goes through the prompt callback)", f.plain)
	}
	if want := []slashRecord{{name: "my-skill", args: "fix the tests", outcome: "success"}}; !slices.Equal(f.slashCommands(), want) {
		t.Fatalf("slash_command events = %+v, want %+v", f.slashCommands(), want)
	}
	if f.flushes != 1 {
		t.Fatalf("command flushes = %d, want 1", f.flushes)
	}
	if got := f.a.input.GetText(); got != "" {
		t.Fatalf("input = %q, want cleared after an accepted skill turn", got)
	}
	if got := f.a.history.Snapshot(); !slices.Equal(got, []string{"/my-skill   fix\tthe    tests"}) {
		t.Fatalf("history = %q, want the typed invocation", got)
	}
}

func TestSkillCommand_BareInvocationSendsEmptyArguments(t *testing.T) {
	f := newSkillFixture(t, skill("my-skill", "Review $ARGUMENTS the diff"))

	if !f.a.SubmitInput("/my-skill") {
		t.Fatal("bare /my-skill was rejected")
	}
	if want := []string{"Review  the diff"}; !slices.Equal(f.sent, want) {
		t.Fatalf("prompt callback got %q, want %q", f.sent, want)
	}
	if want := []slashRecord{{name: "my-skill", outcome: "success"}}; !slices.Equal(f.slashCommands(), want) {
		t.Fatalf("slash_command events = %+v, want %+v", f.slashCommands(), want)
	}
	if evs := slashEvents(f.store); len(decodeSlash(t, evs[0]).Args) != 0 {
		t.Fatalf("args = %q, want none", decodeSlash(t, evs[0]).Args)
	}
}

func TestSkillCommand_WhitespaceExpansionIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"empty body", ""},
		{"bare placeholder only", " $ARGUMENTS \n"},
	} {
		for _, held := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/held=%v", tc.name, held), func(t *testing.T) {
				f := newSkillFixture(t, skill("my-skill", tc.body))
				f.hold = held

				if f.a.SubmitInput("/my-skill") {
					t.Fatal("a whitespace-only expansion was accepted")
				}
				if len(f.sent) != 0 || len(f.a.queued) != 0 {
					t.Fatalf("sent %q, queued %d; want the prompt callback never reached", f.sent, len(f.a.queued))
				}
				if got := f.a.input.GetText(); got != "/my-skill" {
					t.Fatalf("input = %q, want the invocation retained", got)
				}
				if f.a.NoticeText() == "" {
					t.Fatal("no notice for a refused skill")
				}
				got := f.slashCommands()
				if len(got) != 1 || got[0].name != "my-skill" || got[0].outcome != "error" || got[0].detail == "" || strings.Contains(got[0].detail, "\n") {
					t.Fatalf("slash_command events = %+v, want one error with a one-line detail", got)
				}
				if f.flushes != 1 {
					t.Fatalf("command flushes = %d, want 1", f.flushes)
				}
				if got := skillLoadEvents(f.store.Records()); len(got) != 0 {
					t.Fatalf("skill_loaded events = %d, want none for an empty expansion", len(got))
				}
			})
		}
	}
}

func TestSkillCommand_RefusedSubmissionRetainsInputAndRecordsError(t *testing.T) {
	f := newSkillFixture(t, skill("my-skill", "Body $ARGUMENTS"))
	f.accept = false

	if f.a.SubmitInput("/my-skill go now") {
		t.Fatal("a refused prompt was reported accepted")
	}
	if got := f.a.input.GetText(); got != "/my-skill go now" {
		t.Fatalf("input = %q, want the invocation retained", got)
	}
	got := f.slashCommands()
	if len(got) != 1 || got[0] != (slashRecord{name: "my-skill", args: "go now", outcome: "error", detail: got[0].detail}) || got[0].detail == "" {
		t.Fatalf("slash_command events = %+v, want one error with joined args", got)
	}
	if f.a.NoticeText() == "" {
		t.Fatal("no notice for a refused skill")
	}
	if f.flushes != 1 {
		t.Fatalf("command flushes = %d, want 1", f.flushes)
	}
	if strings.Contains(f.a.TranscriptText(), "Body") {
		t.Fatalf("transcript = %q, want no echo of a refused body", f.a.TranscriptText())
	}
	if got := skillLoadEvents(f.store.Records()); len(got) != 0 {
		t.Fatalf("skill_loaded events = %d, want none for a refused submission", len(got))
	}

	f.a.input.SetText("")
	if !f.a.SubmitInput("ordinary words") {
		t.Fatal("plain prompt rejected")
	}
	if got := f.a.TranscriptText(); got != replayedUserText("ordinary words") {
		t.Fatalf("transcript after the next submit = %q, want only its own echo", got)
	}
}

func TestSkillCommand_ImmediateEchoMatchesResumeReplay(t *testing.T) {
	const body = "Line one $ARGUMENTS\n[red]line two[-]"
	f := newSkillFixture(t, skill("my-skill", body))
	f.a.Append("earlier output")
	before := f.a.TranscriptText()

	if !f.a.SubmitInput("/my-skill now") {
		t.Fatal("skill submit rejected")
	}

	live := f.a.TranscriptText()
	if !strings.HasPrefix(live, before) {
		t.Fatalf("transcript = %q, want the earlier output kept (no reset)", live)
	}
	if want := replayedUserText("Line one now\n[red]line two[-]"); !strings.HasSuffix(live, want) || strings.Contains(live, "/my-skill") {
		t.Fatalf("live transcript = %q, want it to end with the replay block %q and not echo the invocation", live, want)
	}

	if !f.a.SubmitInput("next prompt") {
		t.Fatal("plain prompt rejected")
	}
	if got := f.a.TranscriptText(); strings.Count(got, "Line one now") != 1 || !strings.HasSuffix(got, replayedUserText("next prompt")) {
		t.Fatalf("transcript = %q, want the next submit echoed as itself", got)
	}
}

func TestSkillCommand_QueuedAcceptanceEchoesOnceWhenDrained(t *testing.T) {
	f := newSkillFixture(t, skill("my-skill", "Queued $ARGUMENTS"))
	f.hold = true

	if !f.a.SubmitInput("/my-skill work") {
		t.Fatal("queued skill rejected")
	}
	if got := f.a.TranscriptText(); got != "" {
		t.Fatalf("transcript = %q, want no echo while the body is held", got)
	}
	if want := []slashRecord{{name: "my-skill", args: "work", outcome: "success"}}; !slices.Equal(f.slashCommands(), want) {
		t.Fatalf("slash_command events = %+v, want %+v", f.slashCommands(), want)
	}
	if f.flushes != 1 {
		t.Fatalf("command flushes = %d, want 1", f.flushes)
	}
	if got := skillLoadEvents(f.store.Records()); len(got) != 1 {
		t.Fatalf("skill_loaded events at queue acceptance = %d, want 1", len(got))
	}

	f.hold = false
	f.a.TurnEnded(turnOutcomeCompleted)
	if want := []string{"Queued work"}; !slices.Equal(f.sent, want) {
		t.Fatalf("drained %q, want %q", f.sent, want)
	}
	if got := skillLoadEvents(f.store.Records()); len(got) != 1 {
		t.Fatalf("skill_loaded events after drain = %d, want still 1", len(got))
	}
	if got := f.a.TranscriptText(); got != replayedUserText("Queued work") {
		t.Fatalf("transcript = %q, want exactly one echo of the drained body", got)
	}
}

func TestSkillCommand_AcceptedBodyStaysAcceptedWhenRecordFails(t *testing.T) {
	f := newSkillFixture(t, skill("my-skill", "Do $ARGUMENTS"))
	f.flushErr = errors.New("disk full")

	if !f.a.SubmitInput("/my-skill it") {
		t.Fatal("accepted body reported refused after its record flush failed")
	}
	if !slices.Equal(f.sent, []string{"Do it"}) {
		t.Fatalf("sent %q, want the body sent exactly once", f.sent)
	}
	if got := f.a.NoticeText(); !strings.Contains(got, "disk full") {
		t.Fatalf("notice = %q, want the record failure shown", got)
	}
	if got := f.a.input.GetText(); got != "" {
		t.Fatalf("input = %q, want cleared (not retained for retry)", got)
	}
	if got := f.a.TranscriptText(); !strings.HasPrefix(got, replayedUserText("Do it")+"\n") || strings.Count(got, "Do it") != 1 {
		t.Fatalf("transcript = %q, want the accepted echo kept", got)
	}
	if got := skillLoadEvents(f.store.Records()); len(got) != 1 {
		t.Fatalf("skill_loaded events = %d, want 1 appended before the failed flush", len(got))
	}

	t.Run("load append failure", func(t *testing.T) {
		f := newSkillFixture(t, skills.Skill{Name: "my-skill", Body: "Do $ARGUMENTS"})

		if !f.a.SubmitInput("/my-skill it") {
			t.Fatal("accepted body reported refused after its load record failed")
		}
		if !slices.Equal(f.sent, []string{"Do it"}) {
			t.Fatalf("sent %q, want the body sent exactly once", f.sent)
		}
		if got := f.a.NoticeText(); !strings.Contains(got, "skill load record could not be saved") {
			t.Fatalf("notice = %q, want the load record failure shown", got)
		}
		if got := f.a.input.GetText(); got != "" {
			t.Fatalf("input = %q, want cleared (not retained for retry)", got)
		}
		if want := []slashRecord{{name: "my-skill", args: "it", outcome: "success"}}; !slices.Equal(f.slashCommands(), want) {
			t.Fatalf("slash_command events = %+v, want %+v", f.slashCommands(), want)
		}
		if f.flushes != 1 {
			t.Fatalf("command flushes = %d, want 1", f.flushes)
		}
	})

	t.Run("append failure", func(t *testing.T) {
		var sent []string
		var echoed string
		cmds, _ := SkillCommands([]skills.Skill{skill("my-skill", "Do $ARGUMENTS")}, SkillDeps{
			Submit:      func(text string) bool { sent = append(sent, text); return true },
			ReplaceEcho: func(text string) { echoed = text },
		})
		ctx := &appendFailContext{fakeHost: *newFakeHost()}
		if err := cmds[0].Handler(ctx, []string{"it"}); err != nil {
			t.Fatalf("handler error = %v, want nil after an accepted body", err)
		}
		if ctx.retain || !slices.Equal(sent, []string{"Do it"}) || echoed != "Do it" {
			t.Fatalf("retain = %v, sent %q, echo %q; want accepted once with its echo", ctx.retain, sent, echoed)
		}
		if len(ctx.notices) != 1 || !strings.Contains(ctx.notices[0], "append refused") {
			t.Fatalf("notices = %q, want the append failure shown", ctx.notices)
		}
		if got := skillLoadEvents(ctx.store.Records()); len(got) != 1 {
			t.Fatalf("skill_loaded events = %d, want 1", len(got))
		}
		if ctx.flushes != 1 {
			t.Fatalf("flushes = %d, want the load record flushed after the command append failed", ctx.flushes)
		}
	})
}

type appendFailContext struct {
	fakeHost
	notices []string
	retain  bool
}

func (c *appendFailContext) Notice(text string) { c.notices = append(c.notices, text) }
func (c *appendFailContext) RetainInput()       { c.retain = true }
func (c *appendFailContext) Registry() *Registry {
	return nil
}
func (c *appendFailContext) AppendSlashCommand(Outcome, string) error {
	return errors.New("append refused")
}

func TestSkillCommands_RegistrationSurfaces(t *testing.T) {
	long := strings.Repeat("é", 1020) + "\x1b\n\tend"
	loaded := []skills.Skill{
		{Name: "zeta-skill", Description: "Line one\n  line\x07 two\t\x1b[31mred", Body: "z"},
		{Name: "7zip", Description: "Archive", Body: "a"},
		{Name: "alpha-skill", Description: long, Body: "a", ModelInvocable: false},
	}
	f := newSkillFixture(t, loaded...)

	var names []string
	for _, c := range f.reg.Commands() {
		names = append(names, c.Name)
	}
	builtins := []string{"help", "clear", "connect", "status", "context", "effort", "model", "mode", "resume", "settings", "blocked", "exit", "rename", "color", "fork", "compact", "systemone", "skills"}
	if want := append(slices.Clone(builtins), "zeta-skill", "alpha-skill"); !slices.Equal(names, want) {
		t.Fatalf("registry order = %q, want %q", names, want)
	}
	if got := slashNames(slashPickerCandidates(f.reg)); !slices.Equal(got, names) {
		t.Fatalf("picker order = %q, want registry order %q", got, names)
	}
	for _, c := range f.reg.Commands()[len(builtins):] {
		if c.Phase != PhaseTwo || c.ArgSig != ArgRestOptional || len(c.Aliases) != 0 {
			t.Fatalf("%s: phase %d argsig %d aliases %q, want PhaseTwo, rest-optional, none", c.Name, c.Phase, c.ArgSig, c.Aliases)
		}
		if strings.ContainsFunc(c.Description, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			t.Fatalf("%s description %q carries a control character", c.Name, c.Description)
		}
	}
	zeta, _ := f.reg.resolve("zeta-skill")
	if zeta.Description != "Line one line two [31mred" {
		t.Fatalf("zeta description = %q", zeta.Description)
	}
	alpha, _ := f.reg.resolve("alpha-skill")
	if n := len([]rune(alpha.Description)); n > 1024 || !strings.HasSuffix(alpha.Description, " end") {
		t.Fatalf("alpha description has %d code points (%q...), want the whole value within 1024", n, alpha.Description[:8])
	}

	help := RenderHelp(f.reg)
	if !strings.Contains(help, "  /zeta-skill — Line one line two [31mred\n") {
		t.Fatalf("help missing the one-line skill row:\n%s", help)
	}
	alphaAt, helpAt, zetaAt := strings.Index(help, "  /alpha-skill —"), strings.Index(help, "  /help —"), strings.Index(help, "  /zeta-skill —")
	if alphaAt < 0 || alphaAt >= helpAt || helpAt >= zetaAt {
		t.Fatalf("help is not alphabetical across skills and built-ins:\n%s", help)
	}
	if strings.Contains(help, "7zip") {
		t.Fatalf("help lists the unregistrable 7zip skill:\n%s", help)
	}

	if got := completeSlashName("/zet", 4, f.reg); got.Action != tabReplace || got.Text != "/zeta-skill " {
		t.Fatalf("Tab on /zet = %+v, want /zeta-skill with a trailing space", got)
	}
}

func TestSkillCommands_DigitLeadingNameWarnsInsteadOfRegistering(t *testing.T) {
	loaded := []skills.Skill{skill("7zip", "x"), skill("ok-skill", "y")}
	cmds, warnings := SkillCommands(loaded, SkillDeps{})
	if len(cmds) != 1 || cmds[0].Name != "ok-skill" {
		t.Fatalf("commands = %+v, want only ok-skill", cmds)
	}
	if want := []string{`skill "7zip" has no slash command: slash-command names must start with a lowercase letter`}; !slices.Equal(warnings, want) {
		t.Fatalf("warnings = %q, want %q", warnings, want)
	}
	if loaded[0].Name != "7zip" || len(loaded) != 2 {
		t.Fatalf("loaded list changed: %+v", loaded)
	}
}

func TestSkillCommand_PickerRunsBareOnceAndTabDoesNotSubmit(t *testing.T) {
	f := newSkillFixture(t, skill("zeta-skill", "Picked $ARGUMENTS"))

	f.a.input.SetText("/")
	field, ok := f.a.app.GetFocus().(*tview.InputField)
	if !f.a.slashPickerOpen || !ok {
		t.Fatal("slash picker did not open with a focused query field")
	}
	field.SetText("zet")
	field.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})

	if !slices.Equal(f.sent, []string{"Picked "}) {
		t.Fatalf("picker selection sent %q, want the bare skill once", f.sent)
	}
	if want := []slashRecord{{name: "zeta-skill", outcome: "success"}}; !slices.Equal(f.slashCommands(), want) {
		t.Fatalf("slash_command events = %+v, want %+v", f.slashCommands(), want)
	}

	f.sent = nil
	f.a.input.SetText("/zeta")
	f.a.input.InputHandler()(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone), func(tview.Primitive) {})
	if got := f.a.input.GetText(); got != "/zeta-skill " {
		t.Fatalf("input after Tab = %q, want the completed name with a trailing space", got)
	}
	if len(f.sent) != 0 || len(f.slashCommands()) != 1 {
		t.Fatalf("Tab submitted: sent %q, events %+v", f.sent, f.slashCommands())
	}
}

func TestSkillCommand_AcceptedUseWritesOneFlushedLoadRecord(t *testing.T) {
	const body = "Please $ARGUMENTS carefully.\n"
	f := newSkillFixture(t, skill("my-skill", body))
	var kindsAtFlush []string
	f.a.SetCommandFlush(func() error {
		f.flushes++
		kindsAtFlush = recordKinds(f.store.Records())
		_, _, err := f.store.Flush(context.Background())
		return err
	})

	if !f.a.SubmitInput("/my-skill tidy-widgets") {
		t.Fatal("/my-skill was rejected")
	}
	if f.flushes != 1 || !slices.Equal(kindsAtFlush, []string{"skill_loaded", "slash_command"}) {
		t.Fatalf("flushes = %d with kinds %q at flush, want one flush covering [skill_loaded slash_command]", f.flushes, kindsAtFlush)
	}

	session, _, err := sessions.OpenSession(f.store.Path())
	if err != nil {
		t.Fatalf("open flushed session: %v", err)
	}
	loads := skillLoadEvents(session.Records)
	if len(loads) != 1 {
		t.Fatalf("persisted skill_loaded events = %d, want 1", len(loads))
	}
	raw := loads[0].Payload
	if err := events.ValidatePayload("skill_loaded", raw); err != nil {
		t.Fatalf("persisted payload %s failed validation: %v", raw, err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("Please $ARGUMENTS carefully.\n"))
	want := map[string]any{
		"name":   "my-skill",
		"layer":  "project",
		"via":    "slash",
		"file":   "",
		"bytes":  float64(len("Please $ARGUMENTS carefully.\n")),
		"sha256": hex.EncodeToString(sum[:]),
	}
	if len(got) != len(want) {
		t.Fatalf("payload fields = %v, want exactly %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("payload %s = %v, want %v (payload %s)", k, got[k], v, raw)
		}
	}
	for _, leaked := range []string{"tidy-widgets", "carefully", "Please"} {
		if strings.Contains(string(raw), leaked) {
			t.Fatalf("payload %s carries skill text or arguments %q", raw, leaked)
		}
	}
}

func TestSkillCommand_LoadRecordFollowsActiveStoreSwap(t *testing.T) {
	f := newSkillFixture(t, skill("my-skill", "Do $ARGUMENTS"))
	if !f.a.SubmitInput("/my-skill first") {
		t.Fatal("/my-skill was rejected")
	}
	next := queueTestStore(filepath.Join(t.TempDir(), "next.json"))
	f.a.SetActiveStore(next)

	if !f.a.SubmitInput("/my-skill it") {
		t.Fatal("/my-skill was rejected after the store swap")
	}
	if got := skillLoadEvents(f.store.Records()); len(got) != 1 {
		t.Fatalf("old store skill_loaded events = %d, want only the pre-swap load", len(got))
	}
	if got := skillLoadEvents(next.Records()); len(got) != 1 {
		t.Fatalf("new store skill_loaded events = %d, want 1", len(got))
	}
}
