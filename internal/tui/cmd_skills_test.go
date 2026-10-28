package tui

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"codemeld.dev/codemeld/internal/skills"
)

func newSkillsPanelFixture(t *testing.T, view SkillsView, registered ...skills.Skill) *skillFixture {
	t.Helper()
	f := newSkillFixture(t)
	cmds, _ := SkillCommands(registered, SkillDeps{Submit: f.a.SubmitLiteral, ReplaceEcho: f.a.ReplaceNextEcho})
	f.reg = MustNewRegistry(append(BuildRegistry(map[string]HandlerFunc{"skills": NewSkillsHandler(view)}).Commands(), cmds...))
	f.a.SetRegistry(f.reg)
	f.a.SetSubmit(NewSubmitFunc(f.reg, f.a, nil))
	return f
}

func (f *skillFixture) openSkills() string {
	f.t.Helper()
	if !f.a.SubmitInput("/skills") {
		f.t.Fatal("/skills was rejected")
	}
	if !f.a.panelOpen {
		f.t.Fatal("/skills did not open the panel")
	}
	return f.a.panel.GetText(true)
}

func TestSkillsCommand_ShowsLoadedSkillsInlineAndEscKeepsInput(t *testing.T) {
	loaded := []skills.Skill{
		{Name: "deploy", Description: "Deploys [red]the app[-] to [::b]prod", Layer: skills.Project, Folder: "/p/.codemeld/skills/deploy", ModelInvocable: true},
		{Name: "notes", Description: "Takes notes", Layer: skills.Global, Folder: "/h/[blue]/.codemeld/skills/notes", ModelInvocable: true},
	}
	f := newSkillsPanelFixture(t, SkillsView{Loaded: loaded, GlobalRoot: "/h/.codemeld/skills", ProjectRoot: "/p/.codemeld/skills"}, loaded...)

	want := "Loaded\n" +
		"  deploy (project)\n" +
		"    Deploys [red]the app[-] to [::b]prod\n" +
		"    /p/.codemeld/skills/deploy/SKILL.md\n" +
		"  notes (global)\n" +
		"    Takes notes\n" +
		"    /h/[blue]/.codemeld/skills/notes/SKILL.md\n"
	if got := f.openSkills(); got != want {
		t.Fatalf("panel =\n%s\nwant\n%s", got, want)
	}
	if want := []slashRecord{{name: "skills", outcome: "success"}}; !slices.Equal(f.slashCommands(), want) {
		t.Fatalf("slash_command events = %+v, want %+v", f.slashCommands(), want)
	}

	f.a.input.SetText("draft")
	if f.a.handlePanelKey(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone)) != nil || f.a.panelOpen {
		t.Fatal("Esc did not close the skills panel")
	}
	if got := f.a.input.GetText(); got != "draft" {
		t.Fatalf("input = %q after Esc, want %q", got, "draft")
	}
}

func TestSkillsCommand_ShowsAReplacedGlobalSkillUnderNotLoaded(t *testing.T) {
	reason := "the project has its own skill with that name. To use both, rename the folder ~/.codemeld/skills/deploy and its name line."
	loaded := []skills.Skill{{Name: "deploy", Description: "Project deploy", Layer: skills.Project, Folder: "/p/.codemeld/skills/deploy", ModelInvocable: true}}
	f := newSkillsPanelFixture(t, SkillsView{
		Loaded:  loaded,
		Skipped: []SkippedSkill{{Path: "/h/.codemeld/skills/deploy", Reason: reason}},
	}, loaded...)

	want := "\nNot loaded\n  /h/.codemeld/skills/deploy\n    " + reason + "\n"
	if got := f.openSkills(); !strings.HasSuffix(got, want) || !strings.HasPrefix(got, "Loaded\n  deploy (project)\n") {
		t.Fatalf("panel =\n%s\nwant the project skill loaded and ending with\n%s", got, want)
	}
}

func TestSkillsCommand_EmptyStateNamesBothFolders(t *testing.T) {
	f := newSkillsPanelFixture(t, SkillsView{GlobalRoot: "/h/.codemeld/skills", ProjectRoot: "/p/.codemeld/skills"})

	want := "No skills are loaded. Skills live in ~/.codemeld/skills (every project) and .codemeld/skills (this project):\n" +
		"  /h/.codemeld/skills\n" +
		"  /p/.codemeld/skills\n"
	if got := f.openSkills(); got != want {
		t.Fatalf("panel =\n%s\nwant\n%s", got, want)
	}
}

func TestSkillsCommand_RootFailuresStayVisibleWhenNoSkillsLoaded(t *testing.T) {
	f := newSkillsPanelFixture(t, SkillsView{
		GlobalRoot:  "/h/.codemeld/skills",
		ProjectRoot: "/p/.codemeld/skills",
		Skipped: []SkippedSkill{
			{Path: "/h/.codemeld/skills", Reason: "the skills folder could not be read"},
			{Path: "/p/.codemeld/skills", Reason: "the skills folder was rejected"},
		},
	})

	got := f.openSkills()
	for _, part := range []string{
		"~/.codemeld/skills",
		"\nNot loaded\n  /h/.codemeld/skills\n    the skills folder could not be read\n  /p/.codemeld/skills\n    the skills folder was rejected\n",
	} {
		if !strings.Contains(got, part) {
			t.Fatalf("panel =\n%s\nwant it to contain %q", got, part)
		}
	}
}

func TestSkillsCommand_SlashCommandOnlyNeedsARegisteredCommand(t *testing.T) {
	manual := skills.Skill{Name: "manual", Description: "Manual only", Layer: skills.Project, Folder: "/p/.codemeld/skills/manual"}
	zip := skills.Skill{Name: "7zip", Description: "Zips", Layer: skills.Global, Folder: "/h/.codemeld/skills/7zip"}
	view := SkillsView{Loaded: []skills.Skill{manual, zip}}

	registered := newSkillsPanelFixture(t, view, manual, zip).openSkills()
	if want := "  manual (project)\n    Manual only\n    /p/.codemeld/skills/manual/SKILL.md\n    slash command only\n"; !strings.Contains(registered, want) {
		t.Fatalf("panel =\n%s\nwant\n%s", registered, want)
	}
	if want := "  7zip (global)\n    Zips\n    /h/.codemeld/skills/7zip/SKILL.md\n    cannot be started by the model or a slash command\n"; !strings.Contains(registered, want) {
		t.Fatalf("panel =\n%s\nwant\n%s", registered, want)
	}

	unregistered := newSkillsPanelFixture(t, view).openSkills()
	if strings.Contains(unregistered, "slash command only") || strings.Count(unregistered, "cannot be started by the model or a slash command") != 2 {
		t.Fatalf("panel without skill commands =\n%s\nwant neither skill labelled slash command only", unregistered)
	}
}

type orderingHost struct {
	*fakeHost
	steps []string
}

func (h *orderingHost) FlushActive() error {
	h.steps = append(h.steps, fmt.Sprintf("flush with %d events", len(h.events())))
	return nil
}

func (h *orderingHost) ShowPanel(string) { h.steps = append(h.steps, "panel") }

func TestSkillsHandler_AppendsAndFlushesBeforeOpeningThePanel(t *testing.T) {
	reg := BuildRegistry(map[string]HandlerFunc{"skills": NewSkillsHandler(SkillsView{})})
	host := &orderingHost{fakeHost: newFakeHost()}
	if res := reg.DispatchSlashInput("/skills", host); res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /skills = %+v, want handled without error", res)
	}
	if want := []string{"flush with 1 events", "panel"}; !slices.Equal(host.steps, want) {
		t.Fatalf("steps = %q, want %q", host.steps, want)
	}
	if p := decodeSlash(t, host.events()[0]); p.Name != "skills" || p.Outcome != "success" || len(p.Args) != 0 {
		t.Fatalf("event = %+v, want skills success with no args", p)
	}

	t.Run("append failure", func(t *testing.T) {
		ctx := &appendFailContext{}
		if err := NewSkillsHandler(SkillsView{})(ctx, nil); err == nil || err.Error() != "append refused" {
			t.Fatalf("handler error = %v, want the append error", err)
		}
		if len(ctx.panels) != 0 {
			t.Fatalf("panel opened %d times after a failed append, want 0", len(ctx.panels))
		}
	})

	t.Run("flush failure", func(t *testing.T) {
		host := newFlushErrHost(errors.New("disk full"))
		if NewSubmitFunc(reg, host, nil)("/skills") {
			t.Fatal("submit accepted /skills after a failed flush, want the input kept")
		}
		if len(host.panels) != 0 {
			t.Fatalf("panel opened %d times after a failed flush, want 0", len(host.panels))
		}
	})
}
