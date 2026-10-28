package tui

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/skills"
)

type SkillDeps struct {
	Submit      func(text string) bool
	ReplaceEcho func(text string)
}

func SkillCommands(loaded []skills.Skill, deps SkillDeps) ([]Command, []string) {
	var cmds []Command
	var warnings []string
	for _, s := range loaded {
		if !namePattern.MatchString(s.Name) {
			warnings = append(warnings, fmt.Sprintf("skill %q has no slash command: slash-command names must start with a lowercase letter", s.Name))
			continue
		}
		cmds = append(cmds, Command{
			Name:        s.Name,
			Description: skillDescription(s.Description),
			ArgSig:      ArgRestOptional,
			Phase:       PhaseTwo,
			Handler:     newSkillHandler(s, deps),
		})
	}
	return cmds, warnings
}

func skillDescription(s string) string {
	return strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && !unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)), " ")
}

func newSkillHandler(s skills.Skill, deps SkillDeps) HandlerFunc {
	name, body := s.Name, s.Body
	sum := sha256.Sum256([]byte(body))
	load := events.SkillLoaded{
		Name:   name,
		Layer:  string(s.Layer),
		Via:    "slash",
		Bytes:  int64(len(body)),
		SHA256: hex.EncodeToString(sum[:]),
	}
	return func(ctx CommandContext, args []string) error {
		joined := ""
		if len(args) > 0 {
			joined = args[0]
		}
		message := expandSkill(body, joined)
		if strings.TrimSpace(message) == "" {
			return refuseSkill(ctx, fmt.Sprintf("/%s produced an empty message; nothing was sent", name))
		}
		if !deps.Submit(message) {
			return refuseSkill(ctx, fmt.Sprintf("/%s was not sent; your input was kept", name))
		}
		deps.ReplaceEcho(message)
		if err := events.AppendSkillLoaded(ctx.Store(), load); err != nil {
			ctx.Notice(fmt.Sprintf("/%s was sent, but its skill load record could not be saved: %v", name, err))
		}
		if err := ctx.AppendSlashCommand(OutcomeSuccess, ""); err != nil {
			ctx.Notice(fmt.Sprintf("/%s was sent, but its command record could not be saved: %v", name, err))
		}
		if err := ctx.FlushActive(); err != nil {
			ctx.Notice(fmt.Sprintf("/%s was sent, but its command record could not be saved: %v", name, err))
		}
		return nil
	}
}

func refuseSkill(ctx CommandContext, notice string) error {
	ctx.RetainInput()
	ctx.Notice(notice)
	if err := ctx.AppendSlashCommand(OutcomeError, notice); err != nil {
		return err
	}
	return ctx.FlushActive()
}

const argumentsPlaceholder = "$ARGUMENTS"

func expandSkill(body, args string) string {
	var b strings.Builder
	substituted := false
	for i := 0; i < len(body); {
		rest := body[i:]
		switch {
		case strings.HasPrefix(rest, `\$`):
			b.WriteString(`\$`)
			i += 2
		case strings.HasPrefix(rest, argumentsPlaceholder) && !strings.HasPrefix(rest[len(argumentsPlaceholder):], "["):
			b.WriteString(args)
			substituted = true
			i += len(argumentsPlaceholder)
		default:
			b.WriteByte(body[i])
			i++
		}
	}
	if !substituted && args != "" {
		b.WriteString("\n\nARGUMENTS: " + args)
	}
	return b.String()
}
