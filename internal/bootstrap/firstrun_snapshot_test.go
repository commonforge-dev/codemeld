// File-backed snapshot test pinning the first-run canonical stdout message and
// generated settings bytes against the as-built first-run path.
package bootstrap

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/vcs/builtin"
)

// Snapshot fixtures. These hold the canonical stdout message and the
// canonical generated settings.yaml bytes (provider block, model block).
// They are the human-reviewable contract: regenerate them ONLY when
// the wording in changes, never to silence an accidental
// drift in the generator. A failure below means either the generator drifted or
// the changed — inspect the printed got/want diff and reconcile against
// before touching either side.
const (
	messageSnapshotPath  = "testdata/snapshots/first_run_message.txt"
	settingsSnapshotPath = "testdata/snapshots/first_run_settings.yaml"
)

// TestFirstRun_CanonicalMessageSnapshot drives the as-built first-run path
// (defaultRunFirstRun) against a tempdir HOME and asserts stdout begins with the
// canonical three-line message loaded from a file-backed snapshot, with
// stderr empty. The non-canonical "settings to review" tail is excluded
// from the snapshot and only sanity-checked separately, per the task contract.
func TestFirstRun_CanonicalMessageSnapshot(t *testing.T) {
	home := t.TempDir()

	var stdout, stderr bytes.Buffer
	ran, err := defaultRunFirstRun(home, &stdout, &stderr)
	if err != nil {
		t.Fatalf("defaultRunFirstRun: %v; stderr=%q", err, stderr.String())
	}
	if !ran {
		t.Fatalf("ran = false, want true when settings.yaml is absent")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty on a clean first run", stderr.String())
	}

	tmpl := readSnapshot(t, messageSnapshotPath)
	want := strings.ReplaceAll(tmpl, "<path>", SettingsPath(home))

	got := stdout.String()
	if !strings.HasPrefix(got, want) {
		t.Fatalf("stdout does not start with the canonical req-45 message snapshot.\n"+
			"Snapshot: %s\n%s", messageSnapshotPath,
			snapshotDiff(want, firstNBytes(got, len(want)+64)))
	}

	// tail is non-canonical and deliberately not part of the snapshot
	// only confirm it follows the canonical message, do not pin its wording.
	if tail := got[len(want):]; !strings.Contains(tail, "settings to review") {
		t.Errorf("expected the non-canonical req-50 'settings to review' section after the "+
			"canonical message, got tail: %q", tail)
	}
}

// TestFirstRun_GeneratedSettingsSnapshot reads the settings.yaml that the
// first-run path actually wrote to disk and compares its bytes to a file-backed
// snapshot, covering the provider block and model block
// byte-for-byte.
func TestFirstRun_GeneratedSettingsSnapshot(t *testing.T) {
	home := t.TempDir()

	var stdout, stderr bytes.Buffer
	if _, err := defaultRunFirstRun(home, &stdout, &stderr); err != nil {
		t.Fatalf("defaultRunFirstRun: %v; stderr=%q", err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty on a clean first run", stderr.String())
	}

	got, err := os.ReadFile(SettingsPath(home))
	if err != nil {
		t.Fatalf("read generated settings: %v", err)
	}

	want := []byte(readSnapshot(t, settingsSnapshotPath))
	if !bytes.Equal(got, want) {
		t.Fatalf("generated settings.yaml differs from snapshot %s.\n%s",
			settingsSnapshotPath, snapshotDiff(string(want), string(got)))
	}

	// Name the canonical blocks explicitly so a snapshot edit that drops one is
	// reported by block name, not just as an opaque byte mismatch.
	for _, blk := range []struct{ name, body string }{
		{"req-135 provider block", "# provider:\n#   openai:\n#     base_url: https://api.openai.com/v1"},
		{"req-515 model block", "# Manual edits to this key will be overwritten the next time you pick a model.\nmodel: {}\n"},
	} {
		if !bytes.Contains(want, []byte(blk.body)) {
			t.Errorf("snapshot %s is missing the %s; regenerate it from the PRD",
				settingsSnapshotPath, blk.name)
		}
	}

	// Same first-run invocation must have materialized the built-in VCS templates.
	// Asserting the on-disk bytes here ties the snapshot test to the
	// orchestration's RunMaterializeBuiltinTemplates call: dropping that step would
	// leave these files absent and fail the test, not silently pass.
	for _, name := range builtin.BuiltinNames() {
		wantTmpl, ok := builtin.BuiltinTemplate(name)
		if !ok {
			t.Fatalf("builtin.BuiltinTemplate(%q): not found", name)
		}
		gotTmpl, err := os.ReadFile(VCSTemplatePath(home, name))
		if err != nil {
			t.Fatalf("read materialized template %q: %v", name, err)
		}
		if !bytes.Equal(gotTmpl, wantTmpl) {
			t.Errorf("materialized template %q differs from builtin.BuiltinTemplate(%q)", name, name)
		}
	}
}

// This test pins the first-run guidance as
// named clauses through the orchestrated production entrypoint (defaultRunFirstRun),
// independently of the byte-snapshot tests above. Those snapshots assert byte-equality to
// fixtures, so a fixture regenerated without one of these clauses would still pass them;
// this test fails instead, keeping the three user-visible guarantees pinned at the
// real first-run path: the ChatGPT subscription login command reaches stdout, it needs no
// API key (so a subscriber is not pushed toward Platform billing), and the generated
// settings carry the plaintext-credential warning naming the global settings file that may
// hold ChatGPT session tokens.
func TestFirstRun_PRD02GuidanceNamedClauses(t *testing.T) {
	home := t.TempDir()

	var stdout, stderr bytes.Buffer
	ran, err := defaultRunFirstRun(home, &stdout, &stderr)
	if err != nil {
		t.Fatalf("defaultRunFirstRun: %v; stderr=%q", err, stderr.String())
	}
	if !ran {
		t.Fatal("ran = false, want true when settings.yaml is absent")
	}

	out := stdout.String()
	for _, want := range []string{"codemeld auth login openai-chatgpt", "no API key required"} {
		if !strings.Contains(out, want) {
			t.Errorf("first-run stdout missing PRD-02 clause %q\n--- stdout ---\n%s", want, out)
		}
	}

	settings, err := os.ReadFile(SettingsPath(home))
	if err != nil {
		t.Fatalf("read generated settings: %v", err)
	}
	for _, want := range []string{"plaintext", "~/.codemeld/global/settings.yaml"} {
		if !strings.Contains(string(settings), want) {
			t.Errorf("generated settings missing the PRD-02 plaintext-warning clause %q", want)
		}
	}
}

func TestFirstRun_WritesBlockedPathsOnlyOnFirstRun(t *testing.T) {
	t.Run("first run writes the block", func(t *testing.T) {
		home := t.TempDir()
		var stdout, stderr bytes.Buffer
		if ran, err := defaultRunFirstRun(home, &stdout, &stderr); err != nil || !ran {
			t.Fatalf("defaultRunFirstRun = %v, %v; want a first run; stderr=%q", ran, err, stderr.String())
		}
		got, err := os.ReadFile(SettingsPath(home))
		if err != nil {
			t.Fatalf("read generated settings: %v", err)
		}
		if !strings.Contains(string(got), "permissions: []\n\n"+renderBlockedPathsBlock()) {
			t.Fatalf("generated settings missing the blocked_paths block\n%s", got)
		}
	})

	t.Run("existing settings stay untouched", func(t *testing.T) {
		home := t.TempDir()
		const existing = "vcs:\n  priority: [hg, git, jj]\n"
		path := writeGlobalSettings(t, home, existing, 0o600)
		var stdout, stderr bytes.Buffer
		if ran, err := defaultRunFirstRun(home, &stdout, &stderr); err != nil || ran {
			t.Fatalf("defaultRunFirstRun = %v, %v; want no first run; stderr=%q", ran, err, stderr.String())
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != existing {
			t.Fatalf("settings = %q, %v; want the existing bytes unchanged", got, err)
		}
	})
}

// readSnapshot loads a snapshot fixture relative to the package's testdata dir,
// failing the test loudly if it is missing (a deleted fixture must not silently
// pass as an empty expectation).
func readSnapshot(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot %s: %v (fixtures live under internal/bootstrap/testdata/snapshots/)", path, err)
	}
	if len(data) == 0 {
		t.Fatalf("snapshot %s is empty; an empty fixture would assert nothing", path)
	}
	return string(data)
}

// snapshotDiff renders a human-readable want/got comparison, locating the first
// differing line so a wording drift is obvious in CI output rather than buried
// in two large blobs.
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
		b.WriteString(":\n")
		b.WriteString("  want: ")
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

func firstNBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
