// Integration tests for the YAML rewrite byte-preservation contract, driven through
// the production provider-aware model-picker apply path: newModelPickerDeps ->
// providerModelApplier.ApplyProviderModel -> pickerApply.applySelection ->
// model.PersistPickerSelection -> model.WriteActive / model.WriteLastUsed ->
// config.Persist -> config.RewriteKey. They assert the round-trip property on the
// real on-disk files each caller path writes — Testing Requirements "YAML
// rewrite contract tests", integration bullet (1) global model.last_used mirror and
// (2) project model.active. Exhaustive low-level writer-shape cases
// live in internal/config/rewrite_test.go; these belt-and-suspenders the user-action
// path with inline comments, an unknown top-level key, a block scalar, and the
// leading comment block above the rewritten key.
//
// They live in internal/bootstrap rather than internal/integration because the
// production picker apply deps (newModelPickerDeps) are package-private to bootstrap,
// following the precedent documented in tui_commands_test.go.
package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/tui"
)

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestYAMLRewrite_GlobalLastUsedMirror_PreservesUserBytes drives the picker's
// global mirror write (step 2) and asserts that only the model.last_used
// value changes in <home>/.codemeld/global/settings.yaml: the unknown top-level
// keys, the inline comment, the block scalar, the leading comment block above
// last_used, and the trailing key all survive byte-for-byte.
func TestYAMLRewrite_GlobalLastUsedMirror_PreservesUserBytes(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	projectRoot := t.TempDir()

	globalPath := filepath.Join(home, ".codemeld", "global", "settings.yaml")
	if err := os.MkdirAll(filepath.Dir(globalPath), 0o755); err != nil {
		t.Fatalf("mkdir global dir: %v", err)
	}
	original := "# global settings, hand-authored\n" +
		"editor: vim # preferred editor\n" +
		"notes: |\n" +
		"  keep this block\n" +
		"  scalar intact\n" +
		"model:\n" +
		"  # model.last_used is managed automatically by codemeld.\n" +
		"  last_used:\n" +
		"    provider: openai\n" +
		"    id: gpt-5.5\n" +
		"    effort: medium\n" +
		"trailing_unknown: bar\n"
	if err := os.WriteFile(globalPath, []byte(original), 0o600); err != nil {
		t.Fatalf("seed global settings: %v", err)
	}

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := providerCache(t, projectRoot)
	active := selectedState()

	deps := newModelPickerDeps(ctx, app, cache, active, nil, home, "/launch")
	if _, err := deps.Applier.ApplyProviderModel("openai", "gpt-5.5-pro", "high"); err != nil {
		t.Fatalf("ApplyProviderModel: %v", err)
	}

	got := readFileString(t, globalPath)
	want := strings.Replace(original,
		"    provider: openai\n    id: gpt-5.5\n    effort: medium",
		"    provider: openai\n    id: gpt-5.5-pro\n    effort: high", 1)
	if got != want {
		t.Fatalf("global model.last_used rewrite did not preserve user bytes.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestYAMLRewrite_ProjectModelActive_PreservesUserBytes drives the picker's
// per-project model.active write (step 1) and asserts that only the
// model.active value changes in <project_root>/.codemeld/settings.local.yaml: the unknown
// top-level keys, the inline comment, the block scalar, the leading comment block
// above active (retained, not regenerated), and the adjacent/trailing comments all
// survive byte-for-byte.
func TestYAMLRewrite_ProjectModelActive_PreservesUserBytes(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	projectRoot := t.TempDir()

	projPath := config.LocalSettingsPath(projectRoot)
	if err := os.MkdirAll(filepath.Dir(projPath), 0o755); err != nil {
		t.Fatalf("mkdir project dir: %v", err)
	}
	original := "# project settings, hand-authored\n" +
		"editor: vim # preferred editor\n" +
		"notes: |\n" +
		"  multi-line note\n" +
		"  second line\n" +
		"model:\n" +
		"  # model.active is managed automatically by codemeld.\n" +
		"  # Manual edits will be overwritten on the next pick.\n" +
		"  active:\n" +
		"    provider: openai\n" +
		"    id: gpt-5.5\n" +
		"    effort: medium\n" +
		"# trailing comment kept verbatim\n" +
		"trailing_unknown: bar\n"
	if err := os.WriteFile(projPath, []byte(original), 0o600); err != nil {
		t.Fatalf("seed project settings: %v", err)
	}

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := providerCache(t, projectRoot)
	active := selectedState()

	deps := newModelPickerDeps(ctx, app, cache, active, nil, home, "/launch")
	if _, err := deps.Applier.ApplyProviderModel("openai", "gpt-5.5-pro", "high"); err != nil {
		t.Fatalf("ApplyProviderModel: %v", err)
	}

	got := readFileString(t, projPath)
	want := strings.Replace(original,
		"    provider: openai\n    id: gpt-5.5\n    effort: medium",
		"    provider: openai\n    id: gpt-5.5-pro\n    effort: high", 1)
	if got != want {
		t.Fatalf("project model.active rewrite did not preserve user bytes.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}
