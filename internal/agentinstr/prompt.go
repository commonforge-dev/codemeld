// Assembles the loaded AGENTS.md instruction files into a single string
// preserving the discovery load order. This is the final AGENTS.md section of
// the full system message assembled by AssembleSystemMessage.
package agentinstr

import "strings"

// SystemPrompt assembles the loaded AGENTS.md entries into a single string by
// concatenating the Content of each loaded (non-skipped) entry in the slice order
// produced by LoadAgentInstructions — global before walked, in load_order.
// Skipped or unreadable entries (nil Content) contribute nothing, and empty input (or
// input with no loaded entries) yields an empty string. The entries' in-memory
// Content is used as-is; this never re-reads AGENTS.md from disk, matching what the
// launch loaded. It is the AGENTS.md section of AssembleSystemMessage; the inter-file
// newline join here is distinct from that function's blank-line section join.
func SystemPrompt(entries []LoadEntry) string {
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Skipped || len(e.Content) == 0 {
			continue
		}
		parts = append(parts, string(e.Content))
	}
	return strings.Join(parts, "\n")
}
