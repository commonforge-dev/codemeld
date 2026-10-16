// Per-model special instructions: a small library of named instruction
// blocks, each applied only to the models known to need it, inserted into the
// assembled system message between the base prompt and the environment block. The
// first block, latex-math, suppresses LaTeX math notation for models that default to
// it (IBM Granite via OpenRouter). Carrying these per-model — rather than in the shared
// base prompt for every model — keeps the prompt-cache prefix cost off models that
// never emit the quirk.
package agentinstr

import (
	_ "embed"
	"strings"
)

// The named instruction blocks are authored as markdown and compiled into the binary
// via //go:embed (one file, multiple H2-delimited blocks). The file is parsed once at
// package init into specialBlocks.
//
//go:embed baseprompts/special-instructions.md
var specialInstructionsRaw string

// specialBlockSeparator joins multiple blocks for one model: a single blank line, the
// same separator AssembleSystemMessage uses between top-level sections.
const specialBlockSeparator = "\n\n"

// specialBlocks maps each block's slug to its instruction text, parsed once from the
// embedded markdown file. The heading line is stripped and the body is newline-trimmed
// so a block joins exactly regardless of surrounding blank lines.
var specialBlocks = parseSpecialBlocks(specialInstructionsRaw)

// modelKey identifies a flagged model by the exact provider id and model id that
// ActiveState.Current reports (e.g. provider "openrouter", id
// "ibm-granite/granite-4.1-8b"). Configured OpenRouter model ids are preserved verbatim
// in the selectable catalog, so the configured id is the key.
type modelKey struct {
	provider string
	modelID  string
}

// modelSpecialInstructions is the list of flagged models: each maps to the ordered
// block names that model receives. A model absent from this map gets no special
// instructions. The granularity is intentionally per-block-per-model so a future quirk
// affecting a different model can be added as a new block plus map entry without
// leaking onto the models already listed. The block names referenced here must all
// exist in specialBlocks; that invariant is enforced by a test, not at runtime.
var modelSpecialInstructions = map[modelKey][]string{
	{provider: "openrouter", modelID: "ibm-granite/granite-4.1-8b"}: {"latex-math"},
}

// SpecialInstructions returns the special-instruction blocks for the active model,
// concatenated in the order listed for that model and joined by a single blank line, or
// "" when the model is not flagged. An empty result contributes nothing to the
// assembled system message via joinSections, so unflagged models assemble exactly as
// before. Block names listed for a model but missing from the parsed file are skipped
// here (a programming error caught by TestModelSpecialInstructions_BlocksExist, not a
// silent runtime failure).
func SpecialInstructions(provider, modelID string) string {
	names, ok := modelSpecialInstructions[modelKey{provider: provider, modelID: modelID}]
	if !ok {
		return ""
	}
	parts := make([]string, 0, len(names))
	for _, name := range names {
		if body, ok := specialBlocks[name]; ok && body != "" {
			parts = append(parts, body)
		}
	}
	return strings.Join(parts, specialBlockSeparator)
}

// parseSpecialBlocks splits the embedded markdown into named blocks: a line beginning
// "## " starts a new block whose name is the rest of that line (trimmed), and every
// following line until the next such heading (or EOF) is the block's body. Text before
// the first heading belongs to no block. Each body is newline-trimmed so it joins
// cleanly into the system message.
func parseSpecialBlocks(raw string) map[string]string {
	blocks := map[string]string{}
	var name string
	var body []string
	flush := func() {
		if name != "" {
			blocks[name] = strings.Trim(strings.Join(body, "\n"), "\n")
		}
	}
	for _, line := range strings.Split(raw, "\n") {
		if heading, ok := strings.CutPrefix(line, "## "); ok {
			flush()
			name = strings.TrimSpace(heading)
			body = nil
			continue
		}
		if name != "" {
			body = append(body, line)
		}
	}
	flush()
	return blocks
}
