// Assembles the single synthetic system message sent on every provider request:
// the active mode's product-authored base prompt, the active model's special instructions,
// the environment block, the loaded skills list, and the loaded AGENTS.md instructions, in
// that fixed order.
// The per-mode base prompts are embedded markdown (shared core + one behavior block
// per mode); assembly reads only in-memory inputs and performs no I/O.
package agentinstr

import (
	_ "embed"
	"strings"
	"unicode"

	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/skills"
)

// The base prompt is a shared core fragment plus one mode-specific behavior block,
// authored as markdown and compiled into the binary via / go:embed. Each
// file embeds directly into a string; assembly trims the surrounding newlines so the
// section joins are exact regardless of an editor's trailing newline.
var (
	//go:embed baseprompts/shared.md
	sharedCore string
	//go:embed baseprompts/plan.md
	planBehavior string
	//go:embed baseprompts/build.md
	buildBehavior string
	//go:embed baseprompts/auto_edits.md
	autoEditsBehavior string
)

// sectionSeparator joins the non-empty top-level sections of the system message:
// exactly one blank line between them.
const sectionSeparator = "\n\n"

// BasePrompt returns the product-authored base system prompt for mode m: the shared
// core followed by the mode's behavior block, joined by a single blank line.
// An unrecognized mode falls back to Build's block — never an empty prompt — so
// the base section is always present. The base prompt is static per mode
// keeping the assembled prefix prompt-cache stable.
func BasePrompt(m mode.Mode) string {
	return joinSections(sharedCore, behaviorBlock(m))
}

// behaviorBlock selects the embedded behavior block for the active mode, defaulting
// to Build (the launch default) for any unrecognized value so BasePrompt never
// yields an empty result.
func behaviorBlock(m mode.Mode) string {
	switch m {
	case mode.Plan:
		return planBehavior
	case mode.AutoEdits:
		return autoEditsBehavior
	default:
		return buildBehavior
	}
}

// AssembleSystemMessage builds the single synthetic system message in the fixed order
// (1) active mode base prompt, (2) the active model's special instructions, (3)
// environment block, (4) the model-invocable loaded skills, (5) concatenated loaded
// AGENTS.md instructions, sections joined by
// a single blank line. The base prompt and environment block are always
// present, so the message is non-empty even with zero AGENTS.md files — superseding
// the earlier empty prompt for an empty set. The special-instructions section is present only
// for flagged models (provider + modelID match a modelSpecialInstructions entry); an
// unflagged model yields "" there, so its assembly is byte-identical to before. The
// AGENTS.md section reuses SystemPrompt's join semantics (newline-separated file
// content, skipped entries omitted); an empty section contributes nothing and leaves
// no dangling separator. provider and modelID are plain strings (the active
// Selection's provider id and model id) so this package stays free of an internal/model
// import. It reads only the in-memory inputs and makes no outbound calls.
func AssembleSystemMessage(m mode.Mode, provider, modelID string, env EnvironmentInputs, loaded []skills.Skill, entries []LoadEntry) string {
	return joinSections(BasePrompt(m), SpecialInstructions(provider, modelID), EnvironmentBlock(env), skillsSection(loaded), SystemPrompt(entries))
}

func skillsSection(loaded []skills.Skill) string {
	var b strings.Builder
	for _, s := range loaded {
		if !s.ModelInvocable {
			continue
		}
		if b.Len() == 0 {
			b.WriteString("Skills:\nWhen a request matches a skill's description, call the skill tool to load it.")
		}
		b.WriteString("\n- " + s.Name + ": " + oneLine(s.Description))
	}
	return b.String()
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && !unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)), " ")
}

// joinSections trims each section's surrounding newlines and joins the non-empty ones
// with a single blank line, so an empty section contributes nothing and no triple
// newline (dangling separator) can form between sections.
func joinSections(sections ...string) string {
	parts := make([]string, 0, len(sections))
	for _, s := range sections {
		if trimmed := strings.Trim(s, "\n"); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return strings.Join(parts, sectionSeparator)
}
