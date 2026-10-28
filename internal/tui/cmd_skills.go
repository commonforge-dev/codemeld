package tui

import (
	"path/filepath"
	"strings"

	"codemeld.dev/codemeld/internal/skills"
)

type SkillsView struct {
	Loaded      []skills.Skill
	Skipped     []SkippedSkill
	GlobalRoot  string
	ProjectRoot string
}

type SkippedSkill struct {
	Path   string
	Reason string
}

func NewSkillsHandler(view SkillsView) HandlerFunc {
	return func(ctx CommandContext, _ []string) error {
		if err := ctx.AppendSlashCommand(OutcomeSuccess, ""); err != nil {
			return err
		}
		if err := ctx.FlushActive(); err != nil {
			return err
		}
		ctx.ShowPanel(renderSkills(view, ctx.Registry()))
		return nil
	}
}

func renderSkills(view SkillsView, reg *Registry) string {
	var b strings.Builder
	if len(view.Loaded) == 0 {
		b.WriteString("No skills are loaded. Skills live in ~/.codemeld/skills (every project) and .codemeld/skills (this project):\n")
		b.WriteString("  " + view.GlobalRoot + "\n")
		b.WriteString("  " + view.ProjectRoot + "\n")
	} else {
		b.WriteString("Loaded\n")
		for _, s := range view.Loaded {
			b.WriteString("  " + s.Name + " (" + string(s.Layer) + ")\n")
			b.WriteString("    " + s.Description + "\n")
			b.WriteString("    " + filepath.Join(s.Folder, "SKILL.md") + "\n")
			if !s.ModelInvocable {
				if _, ok := reg.byName[s.Name]; ok {
					b.WriteString("    slash command only\n")
				} else {
					b.WriteString("    cannot be started by the model or a slash command\n")
				}
			}
		}
	}
	if len(view.Skipped) > 0 {
		b.WriteString("\nNot loaded\n")
		for _, s := range view.Skipped {
			b.WriteString("  " + s.Path + "\n")
			b.WriteString("    " + s.Reason + "\n")
		}
	}
	return b.String()
}
