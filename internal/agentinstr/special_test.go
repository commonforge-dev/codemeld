// Tests for the per-model special instructions: block parsing, flagged vs
// unflagged lookup, and the invariant that every block name referenced by the
// model→blocks map exists in the parsed file.
package agentinstr

import (
	"strings"
	"testing"
)

// The embedded file parses into named blocks: latex-math exists, its body carries the
// LaTeX-suppression guidance, and the leading file comment belongs to no block.
func TestParseSpecialBlocks_LatexMathPresent(t *testing.T) {
	body, ok := specialBlocks["latex-math"]
	if !ok {
		t.Fatal("specialBlocks missing the latex-math block")
	}
	for _, want := range []string{"Unicode", `\(`, `\frac`} {
		if !strings.Contains(body, want) {
			t.Errorf("latex-math block missing expected guidance %q\n--- body ---\n%s", want, body)
		}
	}
	if strings.HasPrefix(body, "<!--") || strings.Contains(body, "## latex-math") {
		t.Errorf("latex-math body leaked the file comment or its own heading:\n%s", body)
	}
}

// parseSpecialBlocks names a block from its "## " heading and gathers the lines until
// the next heading or EOF, dropping any preamble before the first heading.
func TestParseSpecialBlocks_HeadingDelimited(t *testing.T) {
	raw := "preamble line\n\n## alpha\nfirst\nsecond\n\n## beta\nonly\n"
	blocks := parseSpecialBlocks(raw)
	if got := len(blocks); got != 2 {
		t.Fatalf("parsed %d blocks, want 2 (preamble must not become a block)", got)
	}
	if got, want := blocks["alpha"], "first\nsecond"; got != want {
		t.Errorf("alpha body = %q, want %q", got, want)
	}
	if got, want := blocks["beta"], "only"; got != want {
		t.Errorf("beta body = %q, want %q", got, want)
	}
}

// SpecialInstructions returns the flagged model's block text and "" for an unflagged
// model; the flagged result is exactly the listed blocks joined.
func TestSpecialInstructions_FlaggedAndUnflagged(t *testing.T) {
	got := SpecialInstructions("openrouter", "ibm-granite/granite-4.1-8b")
	if got == "" {
		t.Fatal("SpecialInstructions returned empty for the flagged Granite key")
	}
	if got != specialBlocks["latex-math"] {
		t.Errorf("flagged Granite instructions = %q, want the latex-math block verbatim", got)
	}

	for _, unflagged := range []modelKey{
		{provider: "openai", modelID: "gpt-5.5"},
		{provider: "", modelID: ""},
		{provider: "openrouter", modelID: "z-ai/glm-5.1"},
		// Right id, wrong provider: the provider id disambiguates the key.
		{provider: "openai", modelID: "ibm-granite/granite-4.1-8b"},
	} {
		if s := SpecialInstructions(unflagged.provider, unflagged.modelID); s != "" {
			t.Errorf("SpecialInstructions(%q, %q) = %q, want empty (unflagged)", unflagged.provider, unflagged.modelID, s)
		}
	}
}

// Every block name listed in modelSpecialInstructions must resolve to a parsed block —
// an unknown name is a programming error this test catches rather than letting it drop
// silently at runtime.
func TestModelSpecialInstructions_BlocksExist(t *testing.T) {
	for key, names := range modelSpecialInstructions {
		for _, name := range names {
			if _, ok := specialBlocks[name]; !ok {
				t.Errorf("model %s/%s references block %q, which is not in the parsed special-instructions file", key.provider, key.modelID, name)
			}
		}
	}
}
