// Tests for SystemPrompt assembly: load order (global before walked), skip
// omission, and the empty cases.
package agentinstr

import "testing"

func TestSystemPrompt_AssemblesLoadedInOrderGlobalBeforeWalked(t *testing.T) {
	entries := []LoadEntry{
		{Layer: LayerGlobal, LoadOrder: 1, Content: []byte("global rules")},
		{Layer: LayerWalked, LoadOrder: 2, Content: []byte("root rules")},
		{Layer: LayerWalked, LoadOrder: 3, Content: []byte("project rules")},
	}
	got := SystemPrompt(entries)
	want := "global rules\nroot rules\nproject rules"
	if got != want {
		t.Fatalf("SystemPrompt() = %q, want %q", got, want)
	}
}

func TestSystemPrompt_OmitsSkippedEntries(t *testing.T) {
	entries := []LoadEntry{
		{Layer: LayerGlobal, LoadOrder: 1, Content: []byte("global rules")},
		{Layer: LayerWalked, LoadOrder: 2, Skipped: true, SkipReason: SkipSizeLimit},
		{Layer: LayerWalked, LoadOrder: 3, Skipped: true, SkipReason: SkipUnreadable},
		{Layer: LayerWalked, LoadOrder: 4, Content: []byte("project rules")},
	}
	got := SystemPrompt(entries)
	want := "global rules\nproject rules"
	if got != want {
		t.Fatalf("SystemPrompt() = %q, want %q (skipped entries contribute nothing)", got, want)
	}
}

func TestSystemPrompt_EmptyInputYieldsEmptyPrompt(t *testing.T) {
	if got := SystemPrompt(nil); got != "" {
		t.Fatalf("SystemPrompt(nil) = %q, want empty", got)
	}
	allSkipped := []LoadEntry{
		{Layer: LayerWalked, LoadOrder: 2, Skipped: true, SkipReason: SkipUnreadable},
	}
	if got := SystemPrompt(allSkipped); got != "" {
		t.Fatalf("SystemPrompt(all-skipped) = %q, want empty", got)
	}
}
