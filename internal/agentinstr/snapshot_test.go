// File-backed golden snapshot tests pinning each mode's assembled system message
// (base prompt + environment block) and the empty / with-AGENTS.md assemblies, so any
// wording change in a base prompt or the environment block surfaces as a reviewable
// fixture diff rather than a silent drift.
//
// This is a deliberately-gated change: see docs/gated-changes.md for how to regenerate
// these fixtures (CODEMELD_UPDATE_SNAPSHOTS=1) and why the regen step fails on purpose.
package agentinstr

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/skills"
)

// snapshotDir holds the committed golden fixtures, one per case below.
const snapshotDir = "testdata/snapshots"

// updateSnapshotsEnv is an explicit, off-by-default opt-in: setting it to a non-empty
// value rewrites the fixtures from the current assembly output (with the live GOOS
// written back as goosPlaceholder) and fails the run, so a regenerate is a deliberate
// reviewed step rather than something that happens silently in CI. Mirrors the
// file-backed snapshot style in internal/bootstrap (no implicit on-mismatch update).
const updateSnapshotsEnv = "CODEMELD_UPDATE_SNAPSHOTS"

// goosPlaceholder stands in for runtime.GOOS in the committed fixtures so the golden
// files stay identical across host operating systems; the live GOOS is substituted in
// at assert time. EnvironmentBlock reads runtime.GOOS directly (it is not a
// pinnable input), so this is the one environment-derived value the fixtures cannot
// hard-code — handled exactly like the <path> placeholder in the bootstrap first-run
// snapshot.
const goosPlaceholder = "<goos>"

// snapshotEnv is the fixed, deterministic environment input set for the golden
// fixtures: a pinned date, absolute working directory and project root, and a built-in
// VCS id. It calls no live clock, reads no process cwd, and runs no VCS detection, so
// the only environment-derived value in the assembled output is runtime.GOOS (handled
// via goosPlaceholder).
func snapshotEnv() EnvironmentInputs {
	return EnvironmentInputs{
		Now:         time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC),
		WorkingDir:  "/work/sample-project",
		ProjectRoot: "/work/sample-project",
		VCSName:     "git",
	}
}

func snapshotEnvWithRepoRoot() EnvironmentInputs {
	in := snapshotEnv()
	in.RepoRoot = "/work/sample-repo"
	return in
}

// sampleAgents is a two-file AGENTS.md load (global before walked) used by the
// with-AGENTS fixture to prove the instructions append as the final section.
func sampleAgents() []LoadEntry {
	return []LoadEntry{
		{Layer: LayerGlobal, LoadOrder: 1, Content: []byte("# Global instructions\n\nPrefer small, focused changes.")},
		{Layer: LayerWalked, LoadOrder: 2, Content: []byte("# Project instructions\n\nRun the linter before committing.")},
	}
}

// emptyAgents is a load record whose entries all contribute nothing (one skipped, one
// with empty content). It exercises the empty-AGENTS.md assembly path — base + env only
// with no dangling separator where the AGENTS.md section would have joined — using a
// non-nil slice rather than a bare nil.
func emptyAgents() []LoadEntry {
	return []LoadEntry{
		{Layer: LayerWalked, LoadOrder: 2, Skipped: true, SkipReason: SkipUnreadable},
		{Layer: LayerWalked, LoadOrder: 3, Content: nil},
	}
}

// snapshotCases pairs each committed fixture with the assembly that must reproduce it
// byte-for-byte. The first three pin one mode's base prompt + environment block each;
// the next two pin the empty-AGENTS.md and with-AGENTS.md assemblies (Build mode). The
// first five pass no model, so the special-instructions section is empty and they
// stay byte-identical to before; the last pins the flagged Granite assembly, whose
// special-instructions section is inserted between base prompt and environment block.
func snapshotCases() []struct {
	name string
	file string
	got  string
} {
	const graniteProvider, graniteID = "openrouter", "ibm-granite/granite-4.1-8b"
	return []struct {
		name string
		file string
		got  string
	}{
		{"plan mode", "plan.txt", AssembleSystemMessage(mode.Plan, "", "", snapshotEnv(), nil, nil)},
		{"build mode", "build.txt", AssembleSystemMessage(mode.Build, "", "", snapshotEnv(), nil, nil)},
		{"auto_edits mode", "auto_edits.txt", AssembleSystemMessage(mode.AutoEdits, "", "", snapshotEnv(), nil, nil)},
		{"base + env only (empty AGENTS.md)", "base_env_only.txt", AssembleSystemMessage(mode.Build, "", "", snapshotEnvWithRepoRoot(), nil, emptyAgents())},
		{"base + env + AGENTS.md", "with_agents.txt", AssembleSystemMessage(mode.Build, "", "", snapshotEnv(), nil, sampleAgents())},
		{"flagged model special instructions (Granite)", "special_latex.txt", AssembleSystemMessage(mode.Build, graniteProvider, graniteID, snapshotEnv(), nil, nil)},
		{"base + env + skills + AGENTS.md", "with_skills.txt", AssembleSystemMessage(mode.Build, "", "", snapshotEnv(), sampleSkills(), sampleAgents())},
	}
}

func sampleSkills() []skills.Skill {
	return []skills.Skill{
		{Name: "deploy", Description: "Deploy the service\n  to staging.", Body: "DEPLOY-BODY", ModelInvocable: true},
		{Name: "manual-only", Description: "Only run by hand.", ModelInvocable: false},
		{Name: "release-notes", Description: "Draft release notes.", ModelInvocable: true},
	}
}

// TestAssembledSystemMessage_GoldenSnapshots asserts each assembled system message
// matches its committed golden fixture byte-for-byte (after substituting the live GOOS
// for the placeholder), and that no case carries a dangling section separator. With
// updateSnapshotsEnv set it instead rewrites the fixtures and fails, making regeneration
// an explicit, reviewed action.
func TestAssembledSystemMessage_GoldenSnapshots(t *testing.T) {
	cases := snapshotCases()

	if os.Getenv(updateSnapshotsEnv) != "" {
		for _, tc := range cases {
			writeSnapshot(t, tc.file, tc.got)
		}
		t.Fatalf("regenerated %d golden fixtures because %s is set; unset it and re-run to assert",
			len(cases), updateSnapshotsEnv)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := strings.ReplaceAll(readSnapshot(t, tc.file), goosPlaceholder, runtime.GOOS)
			if tc.got != want {
				t.Fatalf("assembled message for %s differs from golden %s.\n%s",
					tc.name, filepath.Join(snapshotDir, tc.file), snapshotDiff(want, tc.got))
			}
			assertNoDanglingSeparator(t, tc.name, tc.got)
		})
	}
}

// assertNoDanglingSeparator fails if the assembled message contains a triple newline
// (an empty section that left a separator) or a trailing newline (sections join with a
// single blank line and the final section carries no trailing newline).
func assertNoDanglingSeparator(t *testing.T, name, got string) {
	t.Helper()
	if strings.Contains(got, "\n\n\n") {
		t.Errorf("%s: assembled message has a triple newline (dangling separator):\n%q", name, got)
	}
	if strings.HasSuffix(got, "\n") {
		t.Errorf("%s: assembled message ends with a newline; sections must join without a trailing separator", name)
	}
}

// writeSnapshot rewrites one fixture from assembly output, replacing the live GOOS with
// goosPlaceholder so the committed file is platform-independent. Used only by the
// updateSnapshotsEnv regenerate path.
func writeSnapshot(t *testing.T, file, got string) {
	t.Helper()
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		t.Fatalf("create snapshot dir %s: %v", snapshotDir, err)
	}
	body := strings.ReplaceAll(got, runtime.GOOS, goosPlaceholder)
	path := filepath.Join(snapshotDir, file)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write snapshot %s: %v", path, err)
	}
	t.Logf("wrote %s", path)
}

// readSnapshot loads a fixture from snapshotDir, failing loudly if it is missing or
// empty so a deleted/blank fixture cannot pass as an empty expectation.
func readSnapshot(t *testing.T, file string) string {
	t.Helper()
	path := filepath.Join(snapshotDir, file)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot %s: %v (regenerate with %s=1)", path, err, updateSnapshotsEnv)
	}
	if len(data) == 0 {
		t.Fatalf("snapshot %s is empty; an empty fixture would assert nothing", path)
	}
	return string(data)
}

// snapshotDiff renders a human-readable want/got comparison, locating the first
// differing line so a wording drift is obvious in test output rather than buried in two
// large blobs.
func snapshotDiff(want, got string) string {
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")

	n := len(wantLines)
	if len(gotLines) < n {
		n = len(gotLines)
	}
	firstDiff := -1
	for i := 0; i < n; i++ {
		if wantLines[i] != gotLines[i] {
			firstDiff = i
			break
		}
	}
	if firstDiff == -1 && len(wantLines) != len(gotLines) {
		firstDiff = n
	}

	var b strings.Builder
	if firstDiff >= 0 {
		b.WriteString("first difference at line ")
		b.WriteString(strconv.Itoa(firstDiff + 1))
		b.WriteString(":\n  want: ")
		b.WriteString(lineAt(wantLines, firstDiff))
		b.WriteString("\n  got:  ")
		b.WriteString(lineAt(gotLines, firstDiff))
		b.WriteString("\n")
	}
	b.WriteString("--- want ---\n")
	b.WriteString(want)
	b.WriteString("\n--- got ---\n")
	b.WriteString(got)
	return b.String()
}

func lineAt(lines []string, i int) string {
	if i < 0 || i >= len(lines) {
		return "<missing>"
	}
	return lines[i]
}
