// Unit tests for RewriteKey: byte-preserving rewrite of codemeld-owned YAML keys.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
)

// modelSelection returns the canonical-ordered yaml.MapSlice for a
// model.active / model.last_used value used by these tests.
func modelSelection(provider, id, effort string) yaml.MapSlice {
	return yaml.MapSlice{
		{Key: "provider", Value: provider},
		{Key: "id", Value: id},
		{Key: "effort", Value: effort},
	}
}

func writeAt(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write seed file: %v", err)
	}
}

func readAt(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result file: %v", err)
	}
	return string(b)
}

// rewriteCase is one success-path RewriteKey scenario: seed input at a temp
// settings file, rewrite key with value, and require the zero-return success
// contract (nil error, empty write step, empty category) plus a byte-for-byte
// match of the resulting file against want. A case whose want equals input
// asserts the no-op identity path.
type rewriteCase struct {
	name  string
	input string
	key   string
	value any
	want  string
}

func (rc rewriteCase) run(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	writeAt(t, path, rc.input)

	step, cat, err := RewriteKey(path, rc.key, rc.value)
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}
	if got := readAt(t, path); got != rc.want {
		t.Fatalf("output mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, rc.want)
	}
}

// TestRewriteKey_ModelActive_RoundTrip exercises the byte-for-byte
// preservation invariant: an unknown user-authored top-level key, inline
// comments, a multi-line block scalar, and YAML anchors must all survive a
// model.active value rewrite untouched.
func TestRewriteKey_ModelActive_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	original := `# leading file comment
discovery:
  boundary: launch-dir-only # inline comment after value

description: |
  multi-line
  description text

defaults: &defaults
  timeout: 30
  retries: 3

worker:
  <<: *defaults
  name: alpha

experimental: 42

model:
  # active comment block above the active key
  # second line of comment
  # third line of comment
  active:
    provider: openai
    id: gpt-5.5
    effort: medium

permissions: []

trailing_unknown: bar
`
	writeAt(t, path, original)

	step, cat, err := RewriteKey(path, KeyModelActive, modelSelection("openrouter", "anthropic/claude-opus-4.7", "high"))
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero on success", step, cat)
	}

	got := readAt(t, path)

	want := strings.Replace(original,
		"  active:\n    provider: openai\n    id: gpt-5.5\n    effort: medium",
		"  active:\n    provider: openrouter\n    id: anthropic/claude-opus-4.7\n    effort: high",
		1)
	if got != want {
		t.Fatalf("round-trip mismatch.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRewriteKey_ModelActive_CommentBlockPreserved checks the comment
// block above model.active is preserved across a value replacement.
func TestRewriteKey_ModelActive_CommentBlockPreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	commented := `model:
  # model.active is managed automatically by codemeld.
  # It is rewritten whenever you pick a model in this project.
  # Manual edits to this key will be overwritten the next time you pick a model here.
  active:
    provider: openai
    id: gpt-5.5
    effort: medium
`
	writeAt(t, path, commented)

	step, cat, err := RewriteKey(path, KeyModelActive, modelSelection("openrouter", "z-ai/glm-5.1", "low"))
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}

	got := readAt(t, path)
	if !strings.Contains(got, "# model.active is managed automatically by codemeld.\n  # It is rewritten whenever you pick a model in this project.\n  # Manual edits to this key will be overwritten the next time you pick a model here.\n  active:") {
		t.Fatalf("comment block not preserved verbatim above active:\nfile is:\n%s", got)
	}
	if !strings.Contains(got, "provider: openrouter") {
		t.Fatalf("new provider not written; file is:\n%s", got)
	}
}

// TestRewriteKey_Permissions_AppendAndDedup exercises (a) appending a new
// entry at the tail and (b) the no-op behavior for a duplicate, with existing
// entries staying at their current indices.
func TestRewriteKey_Permissions_AppendAndDedup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	original := `# settings
permissions:
  - kind: direct
    subject: ls
    path_scope: "*"
    grant_kind: global
  - kind: direct
    subject: pwd
    path_scope: "*"
    grant_kind: global

other_key: keep
`
	writeAt(t, path, original)

	// Duplicate of the first existing entry: no-op success.
	dup := permissions.PermissionEntry{
		Kind:      "direct",
		Subject:   "ls",
		PathScope: "*",
		GrantKind: "global",
	}
	step, cat, err := RewriteKey(path, KeyPermissions, dup)
	if err != nil {
		t.Fatalf("RewriteKey(dup): %v", err)
	}
	if step != "" || cat != "" {
		t.Fatalf("dup append: step=%q cat=%q, want zero", step, cat)
	}
	if got := readAt(t, path); got != original {
		t.Fatalf("dup append changed the file:\n--- got ---\n%s\n--- want (original) ---\n%s", got, original)
	}

	// New entry appended at tail of the existing block; existing entries
	// stay at their current indices.
	added := permissions.PermissionEntry{
		Kind:      "direct",
		Subject:   "cat",
		PathScope: "*",
		GrantKind: "global",
	}
	step, cat, err = RewriteKey(path, KeyPermissions, added)
	if err != nil {
		t.Fatalf("RewriteKey(new): %v", err)
	}
	if step != "" || cat != "" {
		t.Fatalf("new append: step=%q cat=%q, want zero", step, cat)
	}

	want := `# settings
permissions:
  - kind: direct
    subject: ls
    path_scope: "*"
    grant_kind: global
  - kind: direct
    subject: pwd
    path_scope: "*"
    grant_kind: global
  - kind: direct
    subject: cat
    path_scope: "*"
    grant_kind: global

other_key: keep
`
	if got := readAt(t, path); got != want {
		t.Fatalf("append-at-tail mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRewriteKey_Permissions_HostEntryAppendDedupDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	pathGrant := `  - kind: tool
    subject: read_file
    path_scope: /home/u/proj
    grant_kind: folder
`
	original := "# settings\npermissions:\n" + pathGrant + "\nother_key: keep\n"
	writeAt(t, path, original)

	host := permissions.PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "docs.example.com", GrantKind: "project"}
	sibling := permissions.PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "api.example.com", GrantKind: "project"}
	otherTool := permissions.PermissionEntry{Kind: "tool", Subject: "web_search", HostScope: "docs.example.com", GrantKind: "project"}

	block := func(subject, host string) string {
		return "  - kind: tool\n    subject: " + subject + "\n    host_scope: " + host + "\n    grant_kind: project\n"
	}
	mustRewrite := func(what string, value any) {
		t.Helper()
		step, cat, err := RewriteKey(path, KeyPermissions, value)
		if err != nil {
			t.Fatalf("RewriteKey(%s): %v (step=%q cat=%q)", what, err, step, cat)
		}
		if step != "" || cat != "" {
			t.Fatalf("%s: step=%q cat=%q, want zero", what, step, cat)
		}
	}

	mustRewrite("append host", host)
	want := "# settings\npermissions:\n" + pathGrant + block("web_fetch", "docs.example.com") + "\nother_key: keep\n"
	if got := readAt(t, path); got != want {
		t.Fatalf("host append mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	mustRewrite("duplicate host", host)
	if got := readAt(t, path); got != want {
		t.Fatalf("duplicate host append changed the file:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	mustRewrite("sibling host", sibling)
	mustRewrite("other web tool", otherTool)
	want = "# settings\npermissions:\n" + pathGrant +
		block("web_fetch", "docs.example.com") +
		block("web_fetch", "api.example.com") +
		block("web_search", "docs.example.com") + "\nother_key: keep\n"
	if got := readAt(t, path); got != want {
		t.Fatalf("host identity mismatch (a sibling host and the other web tool are distinct entries):\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	mustRewrite("delete host", PermissionDelete(host.DedupKey()))
	want = "# settings\npermissions:\n" + pathGrant +
		block("web_fetch", "api.example.com") +
		block("web_search", "docs.example.com") + "\nother_key: keep\n"
	if got := readAt(t, path); got != want {
		t.Fatalf("host delete mismatch (only the exact host entry may be removed):\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRewriteKey_Permissions_EmptyFlowReplaced switches `permissions: []`
// into a block sequence with the new entry, preserving sibling keys.
func TestRewriteKey_Permissions_EmptyFlowReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	writeAt(t, path, "discovery:\n  boundary: launch-dir-only\n\npermissions: []\n\nmodel: {}\n")

	entry := permissions.PermissionEntry{
		Kind:      "direct",
		Subject:   "ls",
		PathScope: "/tmp",
		GrantKind: "folder",
	}
	step, cat, err := RewriteKey(path, KeyPermissions, entry)
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}

	got := readAt(t, path)
	want := "discovery:\n  boundary: launch-dir-only\n\npermissions:\n  - kind: direct\n    subject: ls\n    path_scope: /tmp\n    grant_kind: folder\n\nmodel: {}\n"
	if got != want {
		t.Fatalf("empty flow replacement mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRewriteKey_DisallowedKey rejects any key outside the codemeld-owned set
// as a defect, returning LoadStep with no category.
func TestRewriteKey_DisallowedKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	writeAt(t, path, "discovery:\n  boundary: launch-dir-only\n")
	originalBytes := readAt(t, path)

	step, cat, err := RewriteKey(path, "discovery", map[string]any{"boundary": "project-root"})
	if err == nil {
		t.Fatalf("RewriteKey(discovery): want error, got nil")
	}
	if step != fsutil.LoadStep {
		t.Fatalf("step = %q, want %q", step, fsutil.LoadStep)
	}
	if cat != "" {
		t.Fatalf("cat = %q, want zero for disallowed-key in-memory failure", cat)
	}
	if got := readAt(t, path); got != originalBytes {
		t.Fatalf("file changed despite rejected key write")
	}
}

// TestRewriteKey_AtomicWriteFailure_SyncFileSeam triggers a temp-file
// fsync failure via the fsutil seam and asserts the helper propagates the
// (step, cat) WriteAtomic returns. WriteStep + the seam's error category.
func TestRewriteKey_AtomicWriteFailure_SyncFileSeam(t *testing.T) {
	sentinel := errors.New("forced temp-file sync failure")
	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)

	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	step, cat, err := RewriteKey(path, KeyModelActive, modelSelection("openai", "gpt-5.5", "medium"))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel %v", err, sentinel)
	}
	if step != fsutil.WriteStep {
		t.Fatalf("step = %q, want %q", step, fsutil.WriteStep)
	}
	if cat != fserrors.IOError {
		t.Fatalf("cat = %q, want %q", cat, fserrors.IOError)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("target unexpectedly exists after sync failure: %v", statErr)
	}
}

// TestRewriteKey_AtomicWriteFailure_SyncDirSeam triggers a parent-directory
// fsync failure via the fsutil seam and asserts ParentSyncStep propagation.
func TestRewriteKey_AtomicWriteFailure_SyncDirSeam(t *testing.T) {
	sentinel := errors.New("forced parent-dir sync failure")
	restore := fsutil.SetSyncDirForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)

	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	step, cat, err := RewriteKey(path, KeyModelActive, modelSelection("openai", "gpt-5.5", "medium"))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel %v", err, sentinel)
	}
	if step != fsutil.ParentSyncStep {
		t.Fatalf("step = %q, want %q", step, fsutil.ParentSyncStep)
	}
	if cat != fserrors.IOError {
		t.Fatalf("cat = %q, want %q", cat, fserrors.IOError)
	}
}

// TestRewriteKey_AtomicWriteFailure_ReadOnlyParent triggers a WriteStep
// failure inside fsutil.WriteAtomic and asserts the (step, cat) propagation.
func TestRewriteKey_AtomicWriteFailure_ReadOnlyParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses mode bits; write failure unobservable")
	}
	parent := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(parent, 0o500); err != nil {
		t.Fatalf("mkdir read-only parent: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

	target := filepath.Join(parent, "settings.yaml")
	step, cat, err := RewriteKey(target, KeyModelActive, modelSelection("openai", "gpt-5.5", "medium"))
	if err == nil {
		t.Fatalf("RewriteKey: want error, got nil")
	}
	if step != fsutil.WriteStep {
		t.Fatalf("step = %q, want %q", step, fsutil.WriteStep)
	}
	if cat != fserrors.PermissionDenied {
		t.Fatalf("cat = %q, want %q", cat, fserrors.PermissionDenied)
	}
}

// TestRewriteKey_ParseFailure surfaces a malformed YAML file as LoadStep with
// an I/O-or-parse category; the on-disk file must remain unchanged.
func TestRewriteKey_ParseFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	malformed := "model: { active: { broken\n"
	writeAt(t, path, malformed)

	step, cat, err := RewriteKey(path, KeyModelActive, modelSelection("openai", "gpt-5.5", "medium"))
	if err == nil {
		t.Fatalf("RewriteKey: want error, got nil")
	}
	if step != fsutil.LoadStep {
		t.Fatalf("step = %q, want %q", step, fsutil.LoadStep)
	}
	if cat != fserrors.IOError {
		t.Fatalf("cat = %q, want %q", cat, fserrors.IOError)
	}
	if got := readAt(t, path); got != malformed {
		t.Fatalf("on-disk file changed despite parse failure:\n--- got ---\n%s\n--- want ---\n%s", got, malformed)
	}
}

// TestRewriteKey_SuccessfulWrite_ZeroReturns covers the success path on a
// fresh file: zero step, zero category, nil error.
func TestRewriteKey_SuccessfulWrite_ZeroReturns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	step, cat, err := RewriteKey(path, KeyModelActive, modelSelection("openai", "gpt-5.5", "medium"))
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" {
		t.Fatalf("step = %q, want empty on success", step)
	}
	if cat != "" {
		t.Fatalf("cat = %q, want empty on success", cat)
	}
	// File now contains the active key.
	got := readAt(t, path)
	if !strings.Contains(got, "active:") || !strings.Contains(got, "provider: openai") {
		t.Fatalf("expected file to contain new model.active value; got:\n%s", got)
	}
}

// TestRewriteKey_NoTempOrphanLeftBehind verifies that a successful rewrite
// leaves no .tmp- sibling file (which would prove the temp-name suffix rule).
// Combined with fsutil/atomic_test.go's TestTempName_NeverYamlOrJson, this
// covers the atomic-write protocol's "never ends in .yaml or .json" temp-name invariant for
// callers of RewriteKey.
func TestRewriteKey_NoTempOrphanLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	step, cat, err := RewriteKey(path, KeyModelLastUsed, modelSelection("openai", "gpt-5.5", "medium"))
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}

	entries, derr := os.ReadDir(dir)
	if derr != nil {
		t.Fatalf("ReadDir: %v", derr)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".yaml") && name != "settings.yaml" {
			t.Fatalf("found stray .yaml sibling: %q", name)
		}
		if strings.HasSuffix(name, ".json") {
			t.Fatalf("found stray .json sibling: %q", name)
		}
		if strings.Contains(name, ".tmp-") {
			t.Fatalf("temp orphan remains after successful write: %q", name)
		}
	}
}

// TestRewriteKey_ModelLastUsed_CreateFromAbsent covers the shared persistence
// function's create-file-if-absent rule for model.last_used: building a minimal file
// with the comment block above model:.
func TestRewriteKey_ModelLastUsed_CreateFromAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	step, cat, err := RewriteKey(path, KeyModelLastUsed, modelSelection("openai", "gpt-5.5", "medium"))
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}

	got := readAt(t, path)
	if !strings.HasPrefix(got, "# model.last_used is managed automatically by codemeld.\n") {
		t.Fatalf("missing req 515 comment block above model: in created file:\n%s", got)
	}
	if !strings.Contains(got, "model:\n  last_used:\n    provider: openai\n    id: gpt-5.5\n    effort: medium\n") {
		t.Fatalf("missing expected model.last_used body in created file:\n%s", got)
	}
}

// TestRewriteKey_ModelInsertAndReplace folds the model.active / model.last_used
// insert-and-replace fixtures into one
// table. Each case seeds an input file, rewrites the model key, and asserts the
// zero-return success contract plus byte-for-byte output — covering insertion
// into block and flow `model:` mappings, replacement inside a flow mapping, and
// preservation of unknown sibling subkeys, comment blocks, and
// non-target byte spans.
func TestRewriteKey_ModelInsertAndReplace(t *testing.T) {
	cases := []rewriteCase{
		{
			// group 45: first-rewrite — `model: {}` gains last_used:
			// without disturbing the leading comment block or sibling keys.
			name:  "last_used into empty flow model",
			key:   KeyModelLastUsed,
			value: modelSelection("openai", "gpt-5.5", "medium"),
			input: `# leading
discovery:
  boundary: launch-dir-only

# model.last_used is managed automatically by codemeld.
# It records the most recent model and effort you picked in any project,
# and is used as the default for folders you have not yet used with codemeld.
# Manual edits to this key will be overwritten the next time you pick a model.
model: {}

permissions: []
`,
			want: `# leading
discovery:
  boundary: launch-dir-only

# model.last_used is managed automatically by codemeld.
# It records the most recent model and effort you picked in any project,
# and is used as the default for folders you have not yet used with codemeld.
# Manual edits to this key will be overwritten the next time you pick a model.
model:
  last_used:
    provider: openai
    id: gpt-5.5
    effort: medium

permissions: []
`,
		},
		{
			// group 45: active appended after an existing last_used: in a block
			// model:, with the comment block above it.
			name:  "active into existing block model with last_used",
			key:   KeyModelActive,
			value: modelSelection("openrouter", "anthropic/claude-opus-4.7", "high"),
			input: `model:
  last_used:
    provider: openai
    id: gpt-5.5
    effort: medium
`,
			want: `model:
  last_used:
    provider: openai
    id: gpt-5.5
    effort: medium
  # This file holds this machine's own settings for this project; it is not shared with the team.
  # model.active is rewritten whenever you pick a model in this project.
  # Manual edits to this key will be overwritten the next time you pick a model here.
  active:
    provider: openrouter
    id: anthropic/claude-opus-4.7
    effort: high
`,
		},
		{
			// groups 35/38 [r5] replace: only the active value bytes change; a
			// non-owned single-quoted sibling under flow model: survives.
			name:  "active replaced in flow model preserving sibling",
			key:   KeyModelActive,
			value: modelSelection("openrouter", "anthropic/claude-opus-4.7", "high"),
			input: `discovery:
  boundary: launch-dir-only

model: {custom_key: 'hand-authored value', active: {provider: openai, id: gpt-5.5, effort: medium}}

other: keep
`,
			want: `discovery:
  boundary: launch-dir-only

model: {custom_key: 'hand-authored value', active: {provider: openrouter, id: anthropic/claude-opus-4.7, effort: high}}

other: keep
`,
		},
		{
			// groups 35/38 [r5] insert: flow model: with last_used (no active)
			// converts to block form (flow can not host the comments)
			// last_used keeps its inner flow value bytes, only its indent changes.
			name:  "active into flow model with last_used",
			key:   KeyModelActive,
			value: modelSelection("openrouter", "anthropic/claude-opus-4.7", "high"),
			input: `model: {last_used: {provider: openai, id: gpt-5.5, effort: medium}}
`,
			want: `model:
  last_used: {provider: openai, id: gpt-5.5, effort: medium}
  # This file holds this machine's own settings for this project; it is not shared with the team.
  # model.active is rewritten whenever you pick a model in this project.
  # Manual edits to this key will be overwritten the next time you pick a model here.
  active:
    provider: openrouter
    id: anthropic/claude-opus-4.7
    effort: high
`,
		},
		{
			// groups 35/38 [r5] insert: an unknown sibling's quoting and inner
			// formatting survive the flow→block conversion when active is added.
			name:  "active into flow model preserving unknown sibling",
			key:   KeyModelActive,
			value: modelSelection("openrouter", "anthropic/claude-opus-4.7", "high"),
			input: `model: {custom_key: 'hand-authored value'}
`,
			want: `model:
  custom_key: 'hand-authored value'
  # This file holds this machine's own settings for this project; it is not shared with the team.
  # model.active is rewritten whenever you pick a model in this project.
  # Manual edits to this key will be overwritten the next time you pick a model here.
  active:
    provider: openrouter
    id: anthropic/claude-opus-4.7
    effort: high
`,
		},
		{
			// groups 35/38: last_used carries no inline-comment requirement, so a
			// new flow entry is spliced before '}' and the flow style survives.
			name:  "last_used into flow model preserves flow",
			key:   KeyModelLastUsed,
			value: modelSelection("openai", "gpt-5.5", "medium"),
			input: `model: {custom_key: 'hand-authored value'}
`,
			want: `model: {custom_key: 'hand-authored value', last_used: {provider: openai, id: gpt-5.5, effort: medium}}
`,
		},
		{
			name:  "active into file without model",
			key:   KeyModelActive,
			value: modelSelection("openrouter", "anthropic/claude-opus-4.7", "high"),
			input: `other: keep
`,
			want: `other: keep
model:
  # This file holds this machine's own settings for this project; it is not shared with the team.
  # model.active is rewritten whenever you pick a model in this project.
  # Manual edits to this key will be overwritten the next time you pick a model here.
  active:
    provider: openrouter
    id: anthropic/claude-opus-4.7
    effort: high
`,
		},
		{
			name:  "active into empty flow model",
			key:   KeyModelActive,
			value: modelSelection("openrouter", "anthropic/claude-opus-4.7", "high"),
			input: `model: {}
other: keep
`,
			want: `model:
  # This file holds this machine's own settings for this project; it is not shared with the team.
  # model.active is rewritten whenever you pick a model in this project.
  # Manual edits to this key will be overwritten the next time you pick a model here.
  active:
    provider: openrouter
    id: anthropic/claude-opus-4.7
    effort: high
other: keep
`,
		},
		{
			name:  "active into null model",
			key:   KeyModelActive,
			value: modelSelection("openrouter", "anthropic/claude-opus-4.7", "high"),
			input: `model:
other: keep
`,
			want: `model:
  # This file holds this machine's own settings for this project; it is not shared with the team.
  # model.active is rewritten whenever you pick a model in this project.
  # Manual edits to this key will be overwritten the next time you pick a model here.
  active:
    provider: openrouter
    id: anthropic/claude-opus-4.7
    effort: high
other: keep
`,
		},
		{
			name:  "active into whitespace-only file",
			key:   KeyModelActive,
			value: modelSelection("openrouter", "anthropic/claude-opus-4.7", "high"),
			input: "  \n\n",
			want: `model:
  # This file holds this machine's own settings for this project; it is not shared with the team.
  # model.active is rewritten whenever you pick a model in this project.
  # Manual edits to this key will be overwritten the next time you pick a model here.
  active:
    provider: openrouter
    id: anthropic/claude-opus-4.7
    effort: high
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

// TestRewriteKey_FileAbsentReadError surfaces non-ErrNotExist read failures
// via LoadStep with the categorized errno (here PermissionDenied via a
// 0o000-mode file).
func TestRewriteKey_FileReadPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses mode bits; read failure unobservable")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	if err := os.WriteFile(path, []byte("model: {}\n"), 0o000); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	step, cat, err := RewriteKey(path, KeyModelActive, modelSelection("openai", "gpt-5.5", "medium"))
	if err == nil {
		t.Fatalf("RewriteKey: want error, got nil")
	}
	if step != fsutil.LoadStep {
		t.Fatalf("step = %q, want %q", step, fsutil.LoadStep)
	}
	if cat != fserrors.PermissionDenied {
		t.Fatalf("cat = %q, want %q", cat, fserrors.PermissionDenied)
	}
}

// TestRewriteKey_NotExistOnRead_TreatsAsAbsent confirms ErrNotExist is treated
// as the absent-file path (file created), not surfaced as a read error.
func TestRewriteKey_NotExistOnRead_TreatsAsAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.yaml")
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("precondition: path should not exist")
	}

	step, cat, err := RewriteKey(path, KeyPermissions, permissions.PermissionEntry{
		Kind: "direct", Subject: "ls", PathScope: "*", GrantKind: "global",
	})
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}
	got := readAt(t, path)
	want := "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: \"*\"\n    grant_kind: global\n"
	if got != want {
		t.Fatalf("absent-file create mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRewriteKey_Permissions_NonEmptyFlowPreserved covers a review
// issue: an existing non-empty flow-style permissions sequence must keep
// every existing byte (entries, ordering, quoting, inter-entry spacing) and
// only gain the new entry as a flow-form mapping spliced before the closing
// ']'.
func TestRewriteKey_Permissions_NonEmptyFlowPreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	// Non-canonical spacing inside the flow list lets this test fail loudly
	// if any earlier code path normalises entry bytes on its way out.
	original := `discovery:
  boundary: launch-dir-only

permissions: [   {kind: direct, subject: ls, path_scope: "*", grant_kind: global}  ,  {kind: direct, subject: pwd, path_scope: "*", grant_kind: global}   ]

other: keep
`
	writeAt(t, path, original)

	added := permissions.PermissionEntry{
		Kind:      "direct",
		Subject:   "cat",
		PathScope: "*",
		GrantKind: "global",
	}
	step, cat, err := RewriteKey(path, KeyPermissions, added)
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}

	want := `discovery:
  boundary: launch-dir-only

permissions: [   {kind: direct, subject: ls, path_scope: "*", grant_kind: global}  ,  {kind: direct, subject: pwd, path_scope: "*", grant_kind: global}   , {kind: direct, subject: cat, path_scope: "*", grant_kind: global}]

other: keep
`
	if got := readAt(t, path); got != want {
		t.Fatalf("non-empty-flow append mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	// Cross-check: every byte of the original before the closing ']' survives
	// verbatim in the output, proving no existing entry was rewritten.
	prefix := strings.TrimSuffix(original, "]\n\nother: keep\n")
	if got := readAt(t, path); !strings.HasPrefix(got, prefix) {
		t.Fatalf("original bytes before ']' were modified:\n--- got prefix ---\n%s\n--- want prefix ---\n%s", got[:len(prefix)], prefix)
	}
}

// authValue returns the canonical-ordered yaml.MapSlice for an
// auth.openai-chatgpt value used by these tests.
func authValue(access, refresh, expires, account string) yaml.MapSlice {
	return yaml.MapSlice{
		{Key: "access_token", Value: access},
		{Key: "refresh_token", Value: refresh},
		{Key: "expires_at", Value: expires},
		{Key: "account_id", Value: account},
	}
}

// TestRewriteKey_AuthChatGPT_CreateFromAbsent covers the shared persistence
// function's create-file-if-absent rule for auth.openai-chatgpt: an absent file
// gains a minimal auth: block with the single openai-chatgpt session and no
// managed comment.
func TestRewriteKey_AuthChatGPT_CreateFromAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	step, cat, err := RewriteKey(path, KeyAuthOpenAIChatGPT, authValue("at", "rt", "2099-01-02T03:04:05Z", "acct"))
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}

	got := readAt(t, path)
	want := "auth:\n  openai-chatgpt:\n    access_token: at\n    refresh_token: rt\n    expires_at: \"2099-01-02T03:04:05Z\"\n    account_id: acct\n"
	if got != want {
		t.Fatalf("create-from-absent mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRewriteKey_AuthChatGPT_AppendToExisting adds auth.openai-chatgpt to a file
// that has unrelated keys but no auth block, preserving every existing byte.
func TestRewriteKey_AuthChatGPT_AppendToExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	original := `discovery:
  boundary: launch-dir-only

permissions: []
`
	writeAt(t, path, original)

	step, cat, err := RewriteKey(path, KeyAuthOpenAIChatGPT, authValue("at", "rt", "2099-01-02T03:04:05Z", "acct"))
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}

	got := readAt(t, path)
	want := original + "auth:\n  openai-chatgpt:\n    access_token: at\n    refresh_token: rt\n    expires_at: \"2099-01-02T03:04:05Z\"\n    account_id: acct\n"
	if got != want {
		t.Fatalf("append mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRewriteKey_AuthChatGPT_ReplacePreservesSiblings replaces an existing
// session (a re-login / refresh) and proves the provider API key, model state,
// permissions, and comments survive byte-for-byte while only the four auth values
// change.
func TestRewriteKey_AuthChatGPT_ReplacePreservesSiblings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	const head = `# top comment
provider:
  openrouter:
    base_url: https://example.test
    api_key: sk-secret-key

`
	const tail = `
permissions:
  - kind: direct
    subject: ls
    path_scope: "*"
    grant_kind: global
`
	original := head + "auth:\n  openai-chatgpt:\n    access_token: old-at\n    refresh_token: old-rt\n    expires_at: \"2000-01-01T00:00:00Z\"\n    account_id: old-acct\n" + tail
	writeAt(t, path, original)

	step, cat, err := RewriteKey(path, KeyAuthOpenAIChatGPT, authValue("new-at", "new-rt", "2099-01-02T03:04:05Z", "new-acct"))
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}

	got := readAt(t, path)
	want := head + "auth:\n  openai-chatgpt:\n    access_token: new-at\n    refresh_token: new-rt\n    expires_at: \"2099-01-02T03:04:05Z\"\n    account_id: new-acct\n" + tail
	if got != want {
		t.Fatalf("replace mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRewriteKey_AuthChatGPT_Delete_RemovesOnlyAuth deletes the session from a
// file holding a provider API key, model state, permissions, and comments, and
// asserts only the auth: block is gone — every unrelated byte is preserved.
func TestRewriteKey_AuthChatGPT_Delete_RemovesOnlyAuth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	const kept = `# top comment
provider:
  openrouter:
    base_url: https://example.test
    api_key: sk-secret-key

model:
  active:
    provider: openai
    id: gpt-5.5
    effort: medium

`
	original := kept + "auth:\n  openai-chatgpt:\n    access_token: at\n    refresh_token: rt\n    expires_at: \"2099-01-02T03:04:05Z\"\n    account_id: acct\n\n" + `permissions:
  - kind: direct
    subject: ls
    path_scope: "*"
    grant_kind: global
`
	writeAt(t, path, original)

	step, cat, err := RewriteKey(path, KeyAuthOpenAIChatGPT, AuthDelete)
	if err != nil {
		t.Fatalf("RewriteKey delete: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}

	got := readAt(t, path)
	want := kept + `permissions:
  - kind: direct
    subject: ls
    path_scope: "*"
    grant_kind: global
`
	if got != want {
		t.Fatalf("delete mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	if strings.Contains(got, "openai-chatgpt") || strings.Contains(got, "access_token") {
		t.Fatalf("auth state still present after delete:\n%s", got)
	}
	if !strings.Contains(got, "api_key: sk-secret-key") {
		t.Fatalf("delete dropped the unrelated provider API key:\n%s", got)
	}
}

// TestRewriteKey_AuthChatGPT_Delete_AuthLastKey deletes a trailing auth: block and
// asserts the result ends in a single clean newline with no dangling blank line.
func TestRewriteKey_AuthChatGPT_Delete_AuthLastKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	original := "discovery:\n  boundary: launch-dir-only\n\nauth:\n  openai-chatgpt:\n    access_token: at\n    refresh_token: rt\n    expires_at: \"2099-01-02T03:04:05Z\"\n    account_id: acct\n"
	writeAt(t, path, original)

	step, cat, err := RewriteKey(path, KeyAuthOpenAIChatGPT, AuthDelete)
	if err != nil {
		t.Fatalf("RewriteKey delete: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}

	got := readAt(t, path)
	want := "discovery:\n  boundary: launch-dir-only\n"
	if got != want {
		t.Fatalf("delete-last-key mismatch:\n--- got ---\n%q\n--- want ---\n%q", got, want)
	}
}

// TestRewriteKey_AuthChatGPT_Delete_NoOpWhenAbsent covers the idempotent no-op
// paths: an absent file is not created, and a file with no session is untouched.
func TestRewriteKey_AuthChatGPT_Delete_NoOpWhenAbsent(t *testing.T) {
	t.Run("absent file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "settings.yaml")

		step, cat, err := RewriteKey(path, KeyAuthOpenAIChatGPT, AuthDelete)
		if err != nil || step != "" || cat != "" {
			t.Fatalf("delete absent = (%q, %q, %v), want zero", step, cat, err)
		}
		if _, statErr := os.Stat(path); !errors.Is(statErr, fs.ErrNotExist) {
			t.Fatalf("delete created a file for an absent session: %v", statErr)
		}
	})

	// group 14: existing-file no-op subcases — a delete against a file with no
	// openai-chatgpt session leaves every byte untouched (want == input).
	for _, tc := range []rewriteCase{
		{
			name:  "no auth block",
			key:   KeyAuthOpenAIChatGPT,
			value: AuthDelete,
			input: "discovery:\n  boundary: launch-dir-only\n\npermissions: []\n",
			want:  "discovery:\n  boundary: launch-dir-only\n\npermissions: []\n",
		},
		{
			name:  "empty auth mapping",
			key:   KeyAuthOpenAIChatGPT,
			value: AuthDelete,
			input: "auth: {}\n\npermissions: []\n",
			want:  "auth: {}\n\npermissions: []\n",
		},
	} {
		t.Run(tc.name, tc.run)
	}
}

// TestRewriteKey_AuthChatGPT_SetAtomicWriteFailure forces a temp-file fsync
// failure during an auth set and asserts the (step, cat) propagation with the
// on-disk file left absent (prior state unchanged).
func TestRewriteKey_AuthChatGPT_SetAtomicWriteFailure(t *testing.T) {
	sentinel := errors.New("forced temp-file sync failure")
	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)

	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	step, cat, err := RewriteKey(path, KeyAuthOpenAIChatGPT, authValue("at", "rt", "2099-01-02T03:04:05Z", "acct"))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel %v", err, sentinel)
	}
	if step != fsutil.WriteStep {
		t.Fatalf("step = %q, want %q", step, fsutil.WriteStep)
	}
	if cat != fserrors.IOError {
		t.Fatalf("cat = %q, want %q", cat, fserrors.IOError)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("target unexpectedly exists after sync failure: %v", statErr)
	}
}

// TestRewriteKey_PermissionsWrongPayloadType rejects newValue of the wrong
// Go type for the permissions key as a defect.
func TestRewriteKey_PermissionsWrongPayloadType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	step, cat, err := RewriteKey(path, KeyPermissions, "not an entry")
	if err == nil {
		t.Fatalf("RewriteKey: want error, got nil")
	}
	if step != fsutil.LoadStep {
		t.Fatalf("step = %q, want %q", step, fsutil.LoadStep)
	}
	if cat != "" {
		t.Fatalf("cat = %q, want zero for in-memory type-assertion failure", cat)
	}
}

// directGlobalKey builds the DedupKey of a direct global permission grant used by
// the permission-delete tests.
func directGlobalKey(subject string) permissions.DedupKey {
	return permissions.PermissionEntry{Kind: "direct", Subject: subject, PathScope: "*", GrantKind: "global"}.DedupKey()
}

// permDeleteBlockSeed is a three-entry block permissions list with a top comment,
// a per-entry head comment, and an unrelated sibling key. The delete tests use it
// to assert that removing one entry takes only that entry (and its own head
// comment) and preserves the others, their comments, the sibling key, and the
// blank separator before it.
const permDeleteBlockSeed = `# top comment
permissions:
  # ls entry
  - kind: direct
    subject: ls
    path_scope: "*"
    grant_kind: global
  # pwd entry
  - kind: direct
    subject: pwd
    path_scope: "*"
    grant_kind: global
  # cat entry
  - kind: direct
    subject: cat
    path_scope: "*"
    grant_kind: global

other_key: keep
`

// TestRewriteKey_PermissionDelete_BlockPositions removes the first, middle, and
// last entry of a block permissions list, reading the file back from disk each
// time to confirm durable removal of exactly the matched entry (and its own head
// comment) with every sibling entry, comment, key, and the blank separator intact.
func TestRewriteKey_PermissionDelete_BlockPositions(t *testing.T) {
	cases := []struct {
		name    string
		subject string
		want    string
	}{
		{
			name:    "first",
			subject: "ls",
			want: `# top comment
permissions:
  # pwd entry
  - kind: direct
    subject: pwd
    path_scope: "*"
    grant_kind: global
  # cat entry
  - kind: direct
    subject: cat
    path_scope: "*"
    grant_kind: global

other_key: keep
`,
		},
		{
			name:    "middle",
			subject: "pwd",
			want: `# top comment
permissions:
  # ls entry
  - kind: direct
    subject: ls
    path_scope: "*"
    grant_kind: global
  # cat entry
  - kind: direct
    subject: cat
    path_scope: "*"
    grant_kind: global

other_key: keep
`,
		},
		{
			name:    "last",
			subject: "cat",
			want: `# top comment
permissions:
  # ls entry
  - kind: direct
    subject: ls
    path_scope: "*"
    grant_kind: global
  # pwd entry
  - kind: direct
    subject: pwd
    path_scope: "*"
    grant_kind: global

other_key: keep
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "settings.yaml")
			writeAt(t, path, permDeleteBlockSeed)

			step, cat, err := RewriteKey(path, KeyPermissions, PermissionDelete(directGlobalKey(tc.subject)))
			if err != nil {
				t.Fatalf("RewriteKey delete %s: %v (step=%q cat=%q)", tc.subject, err, step, cat)
			}
			if step != "" || cat != "" {
				t.Fatalf("delete %s: step=%q cat=%q, want zero", tc.subject, step, cat)
			}
			if got := readAt(t, path); got != tc.want {
				t.Fatalf("delete %s mismatch:\n--- got ---\n%s\n--- want ---\n%s", tc.subject, got, tc.want)
			}
		})
	}
}

// TestRewriteKey_PermissionDelete_OnlyEntryDropsBlock removes the single entry of
// a permissions list and confirms the whole permissions: block is dropped (no
// stray `permissions: []`) while the unrelated model: block survives.
func TestRewriteKey_PermissionDelete_OnlyEntryDropsBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	writeAt(t, path, `model:
  active:
    provider: openai
    id: gpt-5.5
    effort: high

permissions:
  - kind: direct
    subject: ls
    path_scope: "*"
    grant_kind: global
`)

	step, cat, err := RewriteKey(path, KeyPermissions, PermissionDelete(directGlobalKey("ls")))
	if err != nil {
		t.Fatalf("RewriteKey delete only entry: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("delete only entry: step=%q cat=%q, want zero", step, cat)
	}

	want := `model:
  active:
    provider: openai
    id: gpt-5.5
    effort: high
`
	if got := readAt(t, path); got != want {
		t.Fatalf("only-entry delete mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRewriteKey_PermissionDelete_FlowPositions removes the first, middle, and
// last entry of a hand-authored flow permissions list with non-canonical spacing,
// confirming the non-target flow entries' bytes (spacing, quoting) and the sibling
// keys survive verbatim.
func TestRewriteKey_PermissionDelete_FlowPositions(t *testing.T) {
	seed := `discovery:
  boundary: launch-dir-only

permissions: [   {kind: direct, subject: ls, path_scope: "*", grant_kind: global}  ,  {kind: direct, subject: pwd, path_scope: "*", grant_kind: global}   , {kind: direct, subject: cat, path_scope: "*", grant_kind: global}]

other: keep
`
	cases := []struct {
		name    string
		subject string
		want    string
	}{
		{
			name:    "first",
			subject: "ls",
			want: `discovery:
  boundary: launch-dir-only

permissions: [   {kind: direct, subject: pwd, path_scope: "*", grant_kind: global}   , {kind: direct, subject: cat, path_scope: "*", grant_kind: global}]

other: keep
`,
		},
		{
			name:    "middle",
			subject: "pwd",
			want: `discovery:
  boundary: launch-dir-only

permissions: [   {kind: direct, subject: ls, path_scope: "*", grant_kind: global}   , {kind: direct, subject: cat, path_scope: "*", grant_kind: global}]

other: keep
`,
		},
		{
			name:    "last",
			subject: "cat",
			want: `discovery:
  boundary: launch-dir-only

permissions: [   {kind: direct, subject: ls, path_scope: "*", grant_kind: global}  ,  {kind: direct, subject: pwd, path_scope: "*", grant_kind: global}]

other: keep
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "settings.yaml")
			writeAt(t, path, seed)

			step, cat, err := RewriteKey(path, KeyPermissions, PermissionDelete(directGlobalKey(tc.subject)))
			if err != nil {
				t.Fatalf("RewriteKey flow delete %s: %v (step=%q cat=%q)", tc.subject, err, step, cat)
			}
			if step != "" || cat != "" {
				t.Fatalf("flow delete %s: step=%q cat=%q, want zero", tc.subject, step, cat)
			}
			if got := readAt(t, path); got != tc.want {
				t.Fatalf("flow delete %s mismatch:\n--- got ---\n%s\n--- want ---\n%s", tc.subject, got, tc.want)
			}
		})
	}
}

// TestRewriteKey_PermissionDelete_AbsentKeyNoOp asserts that deleting an entry not
// present in the list leaves the file byte-for-byte unchanged and writes nothing.
func TestRewriteKey_PermissionDelete_AbsentKeyNoOp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	seed := `permissions:
  - kind: direct
    subject: ls
    path_scope: "*"
    grant_kind: global
`
	writeAt(t, path, seed)

	step, cat, err := RewriteKey(path, KeyPermissions, PermissionDelete(directGlobalKey("pwd")))
	if err != nil {
		t.Fatalf("RewriteKey delete absent: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("delete absent: step=%q cat=%q, want zero", step, cat)
	}
	if got := readAt(t, path); got != seed {
		t.Fatalf("absent-key delete changed the file:\n--- got ---\n%s\n--- want (seed) ---\n%s", got, seed)
	}
}

// TestRewriteKey_PermissionDelete_AbsentFileNoOp asserts that deleting from a
// non-existent settings file is a clean no-op that creates no file.
func TestRewriteKey_PermissionDelete_AbsentFileNoOp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml") // absent

	step, cat, err := RewriteKey(path, KeyPermissions, PermissionDelete(directGlobalKey("ls")))
	if err != nil {
		t.Fatalf("RewriteKey delete absent file: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("delete absent file: step=%q cat=%q, want zero", step, cat)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("absent-file delete created a file, stat err = %v", statErr)
	}
}

func TestPersist_PermissionDeleteOp_ReportsRemovedUnderTheLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.yaml")
	writeAt(t, path, `permissions:
  - kind: direct
    subject: ls
    path_scope: "*"
    grant_kind: global
  - kind: direct
    subject: pwd
    path_scope: "*"
    grant_kind: global
`)
	remaining := `permissions:
  - kind: direct
    subject: pwd
    path_scope: "*"
    grant_kind: global
`

	op := &PermissionDeleteOp{Key: directGlobalKey("ls")}
	if reason, _, err := Persist(path, KeyPermissions, op); err != nil {
		t.Fatalf("Persist present entry = (%q, %v)", reason, err)
	}
	if !op.Removed {
		t.Fatal("Removed = false for an entry the locked re-read held")
	}
	if got := readAt(t, path); got != remaining {
		t.Fatalf("after delete:\n%s\nwant\n%s", got, remaining)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if reason, _, err := Persist(path, KeyPermissions, op); err != nil {
		t.Fatalf("Persist absent entry = (%q, %v)", reason, err)
	}
	if op.Removed {
		t.Fatal("Removed = true for an entry absent under the lock")
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAt(t, path); got != remaining || !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("absent-entry delete wrote the file: %q", got)
	}
}

func TestRewriteKey_NilPermissionDeleteOpIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.yaml")
	if _, _, err := RewriteKey(path, KeyPermissions, (*PermissionDeleteOp)(nil)); err == nil {
		t.Fatal("RewriteKey accepted a nil delete op")
	}
}

func providerEntryValue(baseURL, apiKey string) yaml.MapSlice {
	return yaml.MapSlice{
		{Key: "base_url", Value: baseURL},
		{Key: "api_key", Value: apiKey},
	}
}

// parseProviderEntry re-reads the file at path, parses it through the same
// provider.ParseProviders path a real load uses, and returns the entry named name
// (failing if the write did not produce a valid, present entry).
func parseProviderEntry(t *testing.T, path, name string) provider.ProviderEntry {
	t.Helper()
	var composed map[string]any
	if err := yaml.Unmarshal([]byte(readAt(t, path)), &composed); err != nil {
		t.Fatalf("unmarshal result file: %v", err)
	}
	entries, err := provider.ParseProviders(composed)
	if err != nil {
		t.Fatalf("ParseProviders: %v", err)
	}
	e, ok := entries[name]
	if !ok {
		t.Fatalf("provider %q absent after write; entries=%v", name, entries)
	}
	return e
}

// TestRewriteProviderEntry_CreateFromAbsence covers the create-file-if-absent path
// for a provider.<name> entry: an absent file is created at 0600 with the entry,
// and it round-trips through provider.ParseProviders with the default Bearer header.
func TestRewriteProviderEntry_CreateFromAbsence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	step, cat, err := RewriteKey(path, KeyProviderPrefix+"openrouter",
		providerEntryValue("https://openrouter.ai/api/v1", "sk-test-key"))
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}

	fi, serr := os.Stat(path)
	if serr != nil {
		t.Fatalf("stat created file: %v", serr)
	}
	if perm := fi.Mode().Perm(); perm != settingsFileMode.Perm() {
		t.Fatalf("mode = %o, want %o", perm, settingsFileMode.Perm())
	}

	if strings.Contains(readAt(t, path), "models") {
		t.Fatalf("written provider entry must not emit a models key:\n%s", readAt(t, path))
	}
	e := parseProviderEntry(t, path, "openrouter")
	if e.BaseURL != "https://openrouter.ai/api/v1" || e.APIKey != "sk-test-key" {
		t.Fatalf("entry = %+v, want base_url/api_key populated", e)
	}
	if e.AuthHeader == nil || e.AuthHeader.Name != "Authorization" {
		t.Fatalf("auth header = %+v, want default Authorization", e.AuthHeader)
	}
}

// TestRewriteProviderEntry_UpdatePreservesOthers updates one provider entry and
// asserts every non-target byte survives: the leading comment, an unknown key, a
// sibling provider entry, the auth session, model state, and permissions are
// byte-preserved, while only the target provider's fields change (including an
// optional auth_header round-trip).
func TestRewriteProviderEntry_UpdatePreservesOthers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	const head = `# top comment
discovery:
  boundary: launch-dir-only

provider:
  venice:
    base_url: https://old.example
    api_key: sk-old
`
	const siblingAndTail = `  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: sk-keep

auth:
  openai-chatgpt:
    access_token: at
    refresh_token: rt
    expires_at: "2099-01-02T03:04:05Z"
    account_id: acct

model:
  active:
    provider: openai
    id: gpt-5.5
    effort: medium

permissions:
  - kind: direct
    subject: ls
    path_scope: "*"
    grant_kind: global
`
	writeAt(t, path, head+siblingAndTail)

	val := providerEntryValue("https://new.example", "sk-new")
	val = append(val, yaml.MapItem{Key: "auth_header", Value: yaml.MapSlice{
		{Key: "name", Value: "X-API-Key"},
		{Key: "value", Value: "{api_key}"},
	}})

	step, cat, err := RewriteKey(path, KeyProviderPrefix+"venice", val)
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}

	got := readAt(t, path)
	// Every non-target span must survive byte-for-byte.
	for _, span := range []string{
		"# top comment\ndiscovery:\n  boundary: launch-dir-only\n",
		siblingAndTail,
	} {
		if !strings.Contains(got, span) {
			t.Fatalf("non-target span not preserved:\n--- want substring ---\n%s\n--- got ---\n%s", span, got)
		}
	}
	// The result must still be schema-valid.
	if verr := Validate([]byte(got), path); verr != nil {
		t.Fatalf("updated file failed schema validation: %v", verr)
	}

	// Target changed; sibling unchanged.
	if strings.Contains(readAt(t, path), "models") {
		t.Fatalf("rewritten provider entry must not emit a models key:\n%s", readAt(t, path))
	}
	venice := parseProviderEntry(t, path, "venice")
	if venice.BaseURL != "https://new.example" || venice.APIKey != "sk-new" {
		t.Fatalf("venice = %+v, want new base_url/api_key", venice)
	}
	if venice.AuthHeader == nil || venice.AuthHeader.Name != "X-API-Key" || venice.AuthHeader.Value != "{api_key}" {
		t.Fatalf("venice auth header = %+v, want X-API-Key/{api_key}", venice.AuthHeader)
	}
	openrouter := parseProviderEntry(t, path, "openrouter")
	if openrouter.APIKey != "sk-keep" || openrouter.BaseURL != "https://openrouter.ai/api/v1" {
		t.Fatalf("openrouter changed: %+v", openrouter)
	}
}

// TestRewriteProviderEntry_InsertSiblingPreservesExisting adds a new provider to an
// existing block provider: map and asserts the existing sibling survives
// byte-for-byte while both entries round-trip.
func TestRewriteProviderEntry_InsertSiblingPreservesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	const seed = `provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: sk-keep
`
	writeAt(t, path, seed)

	step, cat, err := RewriteKey(path, KeyProviderPrefix+"venice",
		providerEntryValue("https://venice.example", "sk-venice"))
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}

	got := readAt(t, path)
	if !strings.Contains(got, seed) {
		t.Fatalf("existing provider not preserved:\n--- want substring ---\n%s\n--- got ---\n%s", seed, got)
	}
	if verr := Validate([]byte(got), path); verr != nil {
		t.Fatalf("result failed schema validation: %v", verr)
	}
	if e := parseProviderEntry(t, path, "openrouter"); e.APIKey != "sk-keep" {
		t.Fatalf("openrouter changed: %+v", e)
	}
	if e := parseProviderEntry(t, path, "venice"); e.APIKey != "sk-venice" {
		t.Fatalf("venice = %+v, want sk-venice", e)
	}
}

// TestRewriteProviderEntry_ReplaceFlowStyleProvider updates a provider stored in a
// hand-authored flow-style provider: map (`provider: {name: {...}}`) and asserts the
// target's value is replaced while the result stays schema-valid and parses.
func TestRewriteProviderEntry_ReplaceFlowStyleProvider(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	const seed = "provider: {openrouter: {base_url: https://openrouter.ai/api/v1, api_key: sk-old}}\n"
	writeAt(t, path, seed)

	step, cat, err := RewriteKey(path, KeyProviderPrefix+"openrouter",
		providerEntryValue("https://openrouter.ai/api/v1", "sk-new"))
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}

	got := readAt(t, path)
	if verr := Validate([]byte(got), path); verr != nil {
		t.Fatalf("result failed schema validation: %v\n%s", verr, got)
	}
	e := parseProviderEntry(t, path, "openrouter")
	if e.APIKey != "sk-new" {
		t.Fatalf("openrouter = %+v, want sk-new", e)
	}
}

// TestRewriteProviderEntry_InsertIntoFlowStyleProvider inserts a new provider into a
// hand-authored flow-style provider: map and asserts the existing sibling's original
// flow bytes survive verbatim while both entries parse.
func TestRewriteProviderEntry_InsertIntoFlowStyleProvider(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	const sibling = "openrouter: {base_url: https://openrouter.ai/api/v1, api_key: sk-keep}"
	writeAt(t, path, "provider: {"+sibling+"}\n")

	step, cat, err := RewriteKey(path, KeyProviderPrefix+"venice",
		providerEntryValue("https://venice.example", "sk-venice"))
	if err != nil {
		t.Fatalf("RewriteKey: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want zero", step, cat)
	}

	got := readAt(t, path)
	if !strings.Contains(got, sibling) {
		t.Fatalf("sibling flow bytes not preserved:\n--- want substring ---\n%s\n--- got ---\n%s", sibling, got)
	}
	if verr := Validate([]byte(got), path); verr != nil {
		t.Fatalf("result failed schema validation: %v\n%s", verr, got)
	}
	if e := parseProviderEntry(t, path, "openrouter"); e.APIKey != "sk-keep" {
		t.Fatalf("openrouter changed: %+v", e)
	}
	if e := parseProviderEntry(t, path, "venice"); e.APIKey != "sk-venice" {
		t.Fatalf("venice = %+v, want sk-venice", e)
	}
}

// TestRewriteProviderEntry_ReservedRejected asserts that writing the reserved
// provider.openai-chatgpt id is refused with the distinct ErrReservedProviderID
// and creates no file.
func TestRewriteProviderEntry_ReservedRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	step, _, err := RewriteKey(path, KeyProviderPrefix+provider.ChatGPTProviderID,
		providerEntryValue("https://x.example", "sk-should-not-write"))
	if !errors.Is(err, ErrReservedProviderID) {
		t.Fatalf("err = %v, want ErrReservedProviderID", err)
	}
	if step != fsutil.LoadStep {
		t.Fatalf("step = %q, want %q", step, fsutil.LoadStep)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("reserved-id write created a file: %v", statErr)
	}
}

func TestRewriteProviderEntry_SchemaInvalidRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	const secret = "sk-should-not-leak-in-schema-error"
	bad := yaml.MapSlice{{Key: "api_key", Value: secret}}
	_, _, err := RewriteKey(path, KeyProviderPrefix+"venice", bad)
	if err == nil {
		t.Fatalf("RewriteKey: want schema-validation error, got nil")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("api key leaked in schema-validation error: %v", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("schema-invalid write created a file: %v", statErr)
	}
}

// TestRewriteProviderEntry_WriteFailureNoLeak forces a temp-file fsync failure via
// the fsutil seam and asserts the (step, cat) propagation, that no partial file is
// left behind, and that the api key value never appears in the error.
func TestRewriteProviderEntry_WriteFailureNoLeak(t *testing.T) {
	sentinel := errors.New("forced temp-file sync failure")
	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)

	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	const secret = "sk-must-not-leak-on-write-failure"
	step, cat, err := RewriteKey(path, KeyProviderPrefix+"venice",
		providerEntryValue("https://x.example", secret))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel %v", err, sentinel)
	}
	if step != fsutil.WriteStep {
		t.Fatalf("step = %q, want %q", step, fsutil.WriteStep)
	}
	if cat != fserrors.IOError {
		t.Fatalf("cat = %q, want %q", cat, fserrors.IOError)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("api key leaked in write-failure error: %v", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("target unexpectedly exists after write failure: %v", statErr)
	}
}

func preparedToggle(source []Favorite, target Favorite, want bool) *favoriteToggleValue {
	op := &favoriteToggleValue{target: target, want: want}
	op.source = source
	op.next = applyFavorite(source, target, want)
	op.prepared = true
	return op
}

func TestRewriteKey_ModelFavorites_Toggle(t *testing.T) {
	openaiGPT5 := Favorite{Provider: "openai", ID: "gpt-5"}
	anthropicOpus := Favorite{Provider: "anthropic", ID: "opus"}

	t.Run("creates the file when absent", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		step, cat, err := RewriteKey(target, keyModelFavorites, preparedToggle(nil, openaiGPT5, true))
		if err != nil {
			t.Fatalf("RewriteKey = (%q, %q, %v), want success", step, cat, err)
		}
		want := "model:\n  favorites:\n    - provider: openai\n      id: gpt-5\n"
		if got := readAt(t, target); got != want {
			t.Fatalf("created file =\n%q\nwant\n%q", got, want)
		}
	})

	t.Run("appends at the tail preserving order", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		writeAt(t, target, "model:\n  favorites:\n    - provider: openai\n      id: gpt-5\n")
		op := preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)
		if _, _, err := RewriteKey(target, keyModelFavorites, op); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		if got, want := favoritesOnDisk(t, target), []Favorite{openaiGPT5, anthropicOpus}; !slices.Equal(got, want) {
			t.Fatalf("favorites = %v, want %v", got, want)
		}
	})

	t.Run("removes every exact occurrence", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		writeAt(t, target, "model:\n  favorites:\n    - provider: openai\n      id: gpt-5\n    - provider: anthropic\n      id: opus\n    - provider: openai\n      id: gpt-5\n")
		source := []Favorite{openaiGPT5, anthropicOpus, openaiGPT5}
		if _, _, err := RewriteKey(target, keyModelFavorites, preparedToggle(source, openaiGPT5, false)); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		if got, want := favoritesOnDisk(t, target), []Favorite{anthropicOpus}; !slices.Equal(got, want) {
			t.Fatalf("favorites = %v, want %v", got, want)
		}
	})

	t.Run("last removal writes an empty flow list", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		writeAt(t, target, "model:\n  favorites:\n    - provider: openai\n      id: gpt-5\n")
		if _, _, err := RewriteKey(target, keyModelFavorites, preparedToggle([]Favorite{openaiGPT5}, openaiGPT5, false)); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		if !strings.Contains(got, "favorites: []") {
			t.Fatalf("emptied list =\n%q\nwant it to contain %q", got, "favorites: []")
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("emptied list failed schema validation: %v\n%s", err, got)
		}
		if favs := favoritesOnDisk(t, target); len(favs) != 0 {
			t.Fatalf("favorites = %v, want empty", favs)
		}
	})

	t.Run("last removal from a flow model map writes an empty flow list", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		writeAt(t, target, "model: {active: {provider: openai, id: gpt-5, effort: high}, favorites: [{provider: openai, id: gpt-5}]}\n")
		if _, _, err := RewriteKey(target, keyModelFavorites, preparedToggle([]Favorite{openaiGPT5}, openaiGPT5, false)); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		if !strings.Contains(got, "favorites: []") {
			t.Fatalf("emptied flow list =\n%q\nwant it to contain %q", got, "favorites: []")
		}
		if !strings.Contains(got, "active: {provider: openai, id: gpt-5, effort: high}") {
			t.Fatalf("splice dropped model.active:\n%s", got)
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("emptied flow list failed schema validation: %v\n%s", err, got)
		}
		if favs := favoritesOnDisk(t, target); len(favs) != 0 {
			t.Fatalf("favorites = %v, want empty", favs)
		}
	})

	t.Run("duplicate add writes nothing", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		before := "model:\n  favorites: [{provider: openai, id: gpt-5}]  # mine\n"
		writeAt(t, target, before)
		step, cat, err := RewriteKey(target, keyModelFavorites, preparedToggle([]Favorite{openaiGPT5}, openaiGPT5, true))
		if err != nil || step != "" || cat != "" {
			t.Fatalf("RewriteKey = (%q, %q, %v), want a clean no-op", step, cat, err)
		}
		if got := readAt(t, target); got != before {
			t.Fatalf("duplicate add rewrote bytes:\n%q\nwant\n%q", got, before)
		}
	})

	t.Run("absent remove writes nothing and creates no file", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		step, cat, err := RewriteKey(target, keyModelFavorites, preparedToggle(nil, openaiGPT5, false))
		if err != nil || step != "" || cat != "" {
			t.Fatalf("RewriteKey = (%q, %q, %v), want a clean no-op", step, cat, err)
		}
		if _, statErr := os.Stat(target); !errors.Is(statErr, fs.ErrNotExist) {
			t.Fatalf("absent remove created %s (stat err %v)", target, statErr)
		}
	})
}

func TestRewriteKey_ModelFavorites_PreservesUnrelatedContent(t *testing.T) {
	openaiGPT5 := Favorite{Provider: "openai", ID: "gpt-5"}
	anthropicOpus := Favorite{Provider: "anthropic", ID: "opus"}

	assertSpliceBounds := func(t *testing.T, got, prefix, suffix string) {
		t.Helper()
		if !strings.HasPrefix(got, prefix) {
			t.Fatalf("bytes before model.favorites changed:\n%q\nwant prefix\n%q", got, prefix)
		}
		if !strings.HasSuffix(got, suffix) {
			t.Fatalf("bytes after model.favorites changed:\n%q\nwant suffix\n%q", got, suffix)
		}
	}

	t.Run("block model map", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		prefix := "# top comment\nlogging:\n  retention_days: 7\nmodel:\n  # active is managed\n  active:\n    provider: openai\n    id: gpt-5\n    effort: high\n"
		suffix := "  last_used:\n    provider: anthropic\n    id: opus\n    effort: low\n"
		writeAt(t, target, prefix+"  favorites:\n    - provider: openai\n      id: gpt-5\n"+suffix)
		op := preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)
		if _, _, err := RewriteKey(target, keyModelFavorites, op); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		assertSpliceBounds(t, got, prefix, suffix)
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs, want := favoritesOnDisk(t, target), []Favorite{openaiGPT5, anthropicOpus}; !slices.Equal(favs, want) {
			t.Fatalf("favorites = %v, want %v", favs, want)
		}
	})

	t.Run("block model map with an inline comment on favorites", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		prefix := "model:\n  active:\n    provider: openai\n    id: gpt-5\n    effort: high\n  favorites: # keep this note\n"
		suffix := "  last_used:\n    provider: anthropic\n    id: opus\n    effort: low\n"
		writeAt(t, target, prefix+"    - provider: openai\n      id: gpt-5\n"+suffix)
		op := preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)
		if _, _, err := RewriteKey(target, keyModelFavorites, op); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		assertSpliceBounds(t, got, prefix, suffix)
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs, want := favoritesOnDisk(t, target), []Favorite{openaiGPT5, anthropicOpus}; !slices.Equal(favs, want) {
			t.Fatalf("favorites = %v, want %v", favs, want)
		}
	})

	t.Run("trailing comment after an inline empty favorites list survives an add", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		prefix := "model:\n  active:\n    provider: openai\n    id: gpt-5\n    effort: high\n"
		suffix := "  last_used:\n    provider: anthropic\n    id: opus\n    effort: low\n"
		writeAt(t, target, prefix+"  favorites: [] # keep this note\n"+suffix)
		if _, _, err := RewriteKey(target, keyModelFavorites, preparedToggle(nil, openaiGPT5, true)); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		assertSpliceBounds(t, got, prefix, suffix)
		want := prefix + "  favorites: # keep this note\n    - provider: openai\n      id: gpt-5\n" + suffix
		if got != want {
			t.Fatalf("trailing-comment rewrite =\n%q\nwant\n%q", got, want)
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs, want := favoritesOnDisk(t, target), []Favorite{openaiGPT5}; !slices.Equal(favs, want) {
			t.Fatalf("favorites = %v, want %v", favs, want)
		}
	})

	t.Run("inline comment on favorites survives a removal to empty", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		prefix := "model:\n  favorites: # keep this note\n"
		suffix := "logging:\n  retention_days: 7\n"
		writeAt(t, target, prefix+"    - provider: openai\n      id: gpt-5\n"+suffix)
		if _, _, err := RewriteKey(target, keyModelFavorites, preparedToggle([]Favorite{openaiGPT5}, openaiGPT5, false)); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		assertSpliceBounds(t, got, prefix, suffix)
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs := favoritesOnDisk(t, target); len(favs) != 0 {
			t.Fatalf("favorites = %v, want empty", favs)
		}
	})

	t.Run("flow model map with existing favorites", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		prefix := "# top comment\nmodel: {active: {provider: openai, id: gpt-5, effort: high}, favorites:"
		suffix := "}\nlogging:\n  retention_days: 7\n"
		writeAt(t, target, prefix+" [{provider: openai, id: gpt-5}]"+suffix)
		op := preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)
		if _, _, err := RewriteKey(target, keyModelFavorites, op); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		assertSpliceBounds(t, got, prefix, suffix)
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs, want := favoritesOnDisk(t, target), []Favorite{openaiGPT5, anthropicOpus}; !slices.Equal(favs, want) {
			t.Fatalf("favorites = %v, want %v", favs, want)
		}
	})

	t.Run("flow model map with a comment before a sibling", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		prefix := "model: {favorites:"
		suffix := ", # keep this note\n  active: {provider: openai, id: gpt-5, effort: high}}\nlogging:\n  retention_days: 7\n"
		writeAt(t, target, prefix+" [{provider: openai, id: gpt-5}]"+suffix)
		op := preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)
		if _, _, err := RewriteKey(target, keyModelFavorites, op); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		assertSpliceBounds(t, got, prefix, suffix)
		want := prefix + " [{provider: openai, id: gpt-5}, {provider: anthropic, id: opus}]" + suffix
		if got != want {
			t.Fatalf("flow comment rewrite =\n%q\nwant\n%q", got, want)
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs, want := favoritesOnDisk(t, target), []Favorite{openaiGPT5, anthropicOpus}; !slices.Equal(favs, want) {
			t.Fatalf("favorites = %v, want %v", favs, want)
		}
	})

	t.Run("flow model map with a comment before favorites", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		prefix := "model: {favorites: # keep this note\n  "
		suffix := ", active: {provider: openai, id: gpt-5, effort: high}}\nlogging:\n  retention_days: 7\n"
		source := prefix + "[{provider: openai, id: gpt-5}]" + suffix
		if err := Validate([]byte(source), target); err != nil {
			t.Fatalf("source failed schema validation: %v\n%s", err, source)
		}
		writeAt(t, target, source)
		op := preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)
		if _, _, err := RewriteKey(target, keyModelFavorites, op); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		assertSpliceBounds(t, got, prefix, suffix)
		want := prefix + "[{provider: openai, id: gpt-5}, {provider: anthropic, id: opus}]" + suffix
		if got != want {
			t.Fatalf("flow leading-comment rewrite =\n%q\nwant\n%q", got, want)
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
	})

	assertAliasResolves := func(t *testing.T, path string, want []Favorite) {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var raw struct {
			Model struct {
				Active []Favorite `yaml:"active"`
			} `yaml:"model"`
		}
		if err := yaml.Unmarshal(b, &raw); err != nil {
			t.Fatalf("decode %s: %v\n%s", path, err, b)
		}
		if !slices.Equal(raw.Model.Active, want) {
			t.Fatalf("model.active resolved to %v, want %v\n%s", raw.Model.Active, want, b)
		}
	}

	t.Run("block model map with an anchored favorites list aliased by a sibling", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		prefix := "model:\n  favorites:"
		suffix := "\n  active: *shared\n"
		source := prefix + " &shared\n    - provider: openai\n      id: gpt-5" + suffix
		if err := Validate([]byte(source), target); err != nil {
			t.Fatalf("source failed schema validation: %v\n%s", err, source)
		}
		writeAt(t, target, source)
		op := preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)
		if _, _, err := RewriteKey(target, keyModelFavorites, op); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		assertSpliceBounds(t, got, prefix, suffix)
		want := prefix + " &shared\n    - provider: openai\n      id: gpt-5\n    - provider: anthropic\n      id: opus" + suffix
		if got != want {
			t.Fatalf("anchored block rewrite =\n%q\nwant\n%q", got, want)
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs, want := favoritesOnDisk(t, target), []Favorite{openaiGPT5, anthropicOpus}; !slices.Equal(favs, want) {
			t.Fatalf("favorites = %v, want %v", favs, want)
		}
		assertAliasResolves(t, target, []Favorite{openaiGPT5, anthropicOpus})
	})

	t.Run("flow model map with an anchored favorites list aliased by a sibling", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		prefix := "model: {favorites:"
		suffix := ", active: *shared}\n"
		source := prefix + " &shared [{provider: openai, id: gpt-5}]" + suffix
		if err := Validate([]byte(source), target); err != nil {
			t.Fatalf("source failed schema validation: %v\n%s", err, source)
		}
		writeAt(t, target, source)
		op := preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)
		if _, _, err := RewriteKey(target, keyModelFavorites, op); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		assertSpliceBounds(t, got, prefix, suffix)
		want := prefix + " &shared [{provider: openai, id: gpt-5}, {provider: anthropic, id: opus}]" + suffix
		if got != want {
			t.Fatalf("anchored flow rewrite =\n%q\nwant\n%q", got, want)
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs, want := favoritesOnDisk(t, target), []Favorite{openaiGPT5, anthropicOpus}; !slices.Equal(favs, want) {
			t.Fatalf("favorites = %v, want %v", favs, want)
		}
		assertAliasResolves(t, target, []Favorite{openaiGPT5, anthropicOpus})
	})

	t.Run("block model map with an anchored favorite entry aliased by a sibling", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		prefix := "model:\n  favorites:\n"
		suffix := "  active: *shared\n"
		source := prefix + "    - &shared\n      provider: openai\n      id: gpt-5\n" + suffix
		if err := Validate([]byte(source), target); err != nil {
			t.Fatalf("source failed schema validation: %v\n%s", err, source)
		}
		writeAt(t, target, source)
		op := preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)
		if _, _, err := RewriteKey(target, keyModelFavorites, op); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		want := prefix + "    - &shared\n      provider: openai\n      id: gpt-5\n    - provider: anthropic\n      id: opus\n" + suffix
		if got != want {
			t.Fatalf("anchored favorite entry rewrite =\n%q\nwant\n%q", got, want)
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		var raw struct {
			Model struct {
				Active Favorite `yaml:"active"`
			} `yaml:"model"`
		}
		if err := yaml.Unmarshal([]byte(got), &raw); err != nil {
			t.Fatalf("decode result: %v\n%s", err, got)
		}
		if raw.Model.Active != openaiGPT5 {
			t.Fatalf("model.active resolved to %v, want %v\n%s", raw.Model.Active, openaiGPT5, got)
		}
	})

	t.Run("flow model map with an anchored favorite entry aliased by a sibling", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		source := "model: {favorites: [&shared {provider: openai, id: gpt-5}], active: *shared}\n"
		if err := Validate([]byte(source), target); err != nil {
			t.Fatalf("source failed schema validation: %v\n%s", err, source)
		}
		writeAt(t, target, source)
		op := preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)
		if _, _, err := RewriteKey(target, keyModelFavorites, op); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		want := "model: {favorites: [&shared {provider: openai, id: gpt-5}, {provider: anthropic, id: opus}], active: *shared}\n"
		if got != want {
			t.Fatalf("anchored flow favorite entry rewrite =\n%q\nwant\n%q", got, want)
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
	})

	for _, tc := range []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "block model map keeps a nested favorite anchor referenced by a sibling",
			source: "model:\n  favorites:\n    - provider: openai\n      id: &fav_id gpt-5\n  active:\n    provider: openai\n    id: *fav_id\n    effort: high\n",
			want:   "model:\n  favorites:\n    - provider: openai\n      id: &fav_id gpt-5\n    - provider: anthropic\n      id: opus\n  active:\n    provider: openai\n    id: *fav_id\n    effort: high\n",
		},
		{
			name:   "flow model map keeps a nested favorite anchor referenced by a sibling",
			source: "model: {favorites: [{provider: openai, id: &fav_id gpt-5}], active: {provider: openai, id: *fav_id, effort: high}}\n",
			want:   "model: {favorites: [{provider: openai, id: &fav_id gpt-5}, {provider: anthropic, id: opus}], active: {provider: openai, id: *fav_id, effort: high}}\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "settings.yaml")
			if err := Validate([]byte(tc.source), target); err != nil {
				t.Fatalf("source failed schema validation: %v\n%s", err, tc.source)
			}
			writeAt(t, target, tc.source)
			if _, _, err := RewriteKey(target, keyModelFavorites, preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)); err != nil {
				t.Fatalf("RewriteKey: %v", err)
			}
			got := readAt(t, target)
			if got != tc.want {
				t.Fatalf("nested anchored favorite rewrite =\n%q\nwant\n%q", got, tc.want)
			}
			if err := Validate([]byte(got), target); err != nil {
				t.Fatalf("result failed schema validation: %v\n%s", err, got)
			}
		})
	}

	for _, tc := range []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "block model map with anchored favorites list and entry aliased by a sibling",
			source: "model:\n  favorites: &list\n    - &entry\n      provider: openai\n      id: gpt-5\n  active: *entry\n",
			want:   "model:\n  favorites: &list\n    - &entry\n      provider: openai\n      id: gpt-5\n    - provider: anthropic\n      id: opus\n  active: *entry\n",
		},
		{
			name:   "flow model map with anchored favorites list and entry aliased by a sibling",
			source: "model: {favorites: &list [&entry {provider: openai, id: gpt-5}], active: *entry}\n",
			want:   "model: {favorites: &list [&entry {provider: openai, id: gpt-5}, {provider: anthropic, id: opus}], active: *entry}\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "settings.yaml")
			if err := Validate([]byte(tc.source), target); err != nil {
				t.Fatalf("source failed schema validation: %v\n%s", err, tc.source)
			}
			writeAt(t, target, tc.source)
			if _, _, err := RewriteKey(target, keyModelFavorites, preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)); err != nil {
				t.Fatalf("RewriteKey: %v", err)
			}
			got := readAt(t, target)
			if got != tc.want {
				t.Fatalf("wrapped anchored favorite entry rewrite =\n%q\nwant\n%q", got, tc.want)
			}
			if err := Validate([]byte(got), target); err != nil {
				t.Fatalf("result failed schema validation: %v\n%s", err, got)
			}
			var raw struct {
				Model struct {
					Active Favorite `yaml:"active"`
				} `yaml:"model"`
			}
			if err := yaml.Unmarshal([]byte(got), &raw); err != nil {
				t.Fatalf("decode result: %v\n%s", err, got)
			}
			if raw.Model.Active != openaiGPT5 {
				t.Fatalf("model.active resolved to %v, want %v\n%s", raw.Model.Active, openaiGPT5, got)
			}
		})
	}

	assertModelAliasResolves := func(t *testing.T, path string, want []Favorite) {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var raw struct {
			Ref struct {
				Favorites []Favorite `yaml:"favorites"`
			} `yaml:"x_anchor_ref"`
		}
		if err := yaml.Unmarshal(b, &raw); err != nil {
			t.Fatalf("decode %s: %v\n%s", path, err, b)
		}
		if !slices.Equal(raw.Ref.Favorites, want) {
			t.Fatalf("x_anchor_ref.favorites resolved to %v, want %v\n%s", raw.Ref.Favorites, want, b)
		}
	}

	t.Run("block model map anchored as a container aliased by a sibling", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		prefix := "model: &shared\n  favorites:"
		suffix := "\nx_anchor_ref: *shared\n"
		source := prefix + "\n    - provider: openai\n      id: gpt-5" + suffix
		if err := Validate([]byte(source), target); err != nil {
			t.Fatalf("source failed schema validation: %v\n%s", err, source)
		}
		writeAt(t, target, source)
		op := preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)
		if _, _, err := RewriteKey(target, keyModelFavorites, op); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		assertSpliceBounds(t, got, prefix, suffix)
		want := prefix + "\n    - provider: openai\n      id: gpt-5\n    - provider: anthropic\n      id: opus" + suffix
		if got != want {
			t.Fatalf("anchored block container rewrite =\n%q\nwant\n%q", got, want)
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs, want := favoritesOnDisk(t, target), []Favorite{openaiGPT5, anthropicOpus}; !slices.Equal(favs, want) {
			t.Fatalf("favorites = %v, want %v", favs, want)
		}
		assertModelAliasResolves(t, target, []Favorite{openaiGPT5, anthropicOpus})
	})

	t.Run("flow model map anchored as a container aliased by a sibling", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		prefix := "model: &shared {favorites:"
		suffix := "}\nx_anchor_ref: *shared\n"
		source := prefix + " [{provider: openai, id: gpt-5}]" + suffix
		if err := Validate([]byte(source), target); err != nil {
			t.Fatalf("source failed schema validation: %v\n%s", err, source)
		}
		writeAt(t, target, source)
		op := preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)
		if _, _, err := RewriteKey(target, keyModelFavorites, op); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		assertSpliceBounds(t, got, prefix, suffix)
		want := prefix + " [{provider: openai, id: gpt-5}, {provider: anthropic, id: opus}]" + suffix
		if got != want {
			t.Fatalf("anchored flow container rewrite =\n%q\nwant\n%q", got, want)
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs, want := favoritesOnDisk(t, target), []Favorite{openaiGPT5, anthropicOpus}; !slices.Equal(favs, want) {
			t.Fatalf("favorites = %v, want %v", favs, want)
		}
		assertModelAliasResolves(t, target, []Favorite{openaiGPT5, anthropicOpus})
	})

	t.Run("block model map with a tagged anchored favorites list aliased by a sibling", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		prefix := "model:\n  favorites:"
		suffix := "\n  active: *shared\n"
		source := prefix + " &shared !!seq\n    - provider: openai\n      id: gpt-5" + suffix
		if err := Validate([]byte(source), target); err != nil {
			t.Fatalf("source failed schema validation: %v\n%s", err, source)
		}
		writeAt(t, target, source)
		op := preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)
		if _, _, err := RewriteKey(target, keyModelFavorites, op); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		assertSpliceBounds(t, got, prefix, suffix)
		want := prefix + " &shared !!seq\n    - provider: openai\n      id: gpt-5\n    - provider: anthropic\n      id: opus" + suffix
		if got != want {
			t.Fatalf("tagged anchored block rewrite =\n%q\nwant\n%q", got, want)
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs, want := favoritesOnDisk(t, target), []Favorite{openaiGPT5, anthropicOpus}; !slices.Equal(favs, want) {
			t.Fatalf("favorites = %v, want %v", favs, want)
		}
		assertAliasResolves(t, target, []Favorite{openaiGPT5, anthropicOpus})
	})

	t.Run("flow model map with a tagged anchored favorites list aliased by a sibling", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		prefix := "model: {favorites:"
		suffix := ", active: *shared}\n"
		source := prefix + " &shared !!seq [{provider: openai, id: gpt-5}]" + suffix
		if err := Validate([]byte(source), target); err != nil {
			t.Fatalf("source failed schema validation: %v\n%s", err, source)
		}
		writeAt(t, target, source)
		op := preparedToggle([]Favorite{openaiGPT5}, anthropicOpus, true)
		if _, _, err := RewriteKey(target, keyModelFavorites, op); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		assertSpliceBounds(t, got, prefix, suffix)
		want := prefix + " &shared !!seq [{provider: openai, id: gpt-5}, {provider: anthropic, id: opus}]" + suffix
		if got != want {
			t.Fatalf("tagged anchored flow rewrite =\n%q\nwant\n%q", got, want)
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs, want := favoritesOnDisk(t, target), []Favorite{openaiGPT5, anthropicOpus}; !slices.Equal(favs, want) {
			t.Fatalf("favorites = %v, want %v", favs, want)
		}
		assertAliasResolves(t, target, []Favorite{openaiGPT5, anthropicOpus})
	})

	t.Run("empty flow model map stays flow style", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		writeAt(t, target, "# top comment\nmodel: {}\nlogging:\n  retention_days: 7\n")
		if _, _, err := RewriteKey(target, keyModelFavorites, preparedToggle(nil, openaiGPT5, true)); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		want := "# top comment\nmodel: {favorites: [{provider: openai, id: gpt-5}]}\nlogging:\n  retention_days: 7\n"
		if got != want {
			t.Fatalf("empty flow map rewrite =\n%q\nwant\n%q", got, want)
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs, want := favoritesOnDisk(t, target), []Favorite{openaiGPT5}; !slices.Equal(favs, want) {
			t.Fatalf("favorites = %v, want %v", favs, want)
		}
	})

	t.Run("flow model map without favorites", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		writeAt(t, target, "model: {last_used: {provider: anthropic, id: opus, effort: low}}\n")
		if _, _, err := RewriteKey(target, keyModelFavorites, preparedToggle(nil, openaiGPT5, true)); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		if !strings.Contains(got, "last_used: {provider: anthropic, id: opus, effort: low}") {
			t.Fatalf("splice dropped model.last_used:\n%s", got)
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs, want := favoritesOnDisk(t, target), []Favorite{openaiGPT5}; !slices.Equal(favs, want) {
			t.Fatalf("favorites = %v, want %v", favs, want)
		}
	})

	t.Run("model key absent", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		writeAt(t, target, "# keep me\nlogging:\n  retention_days: 7\n")
		if _, _, err := RewriteKey(target, keyModelFavorites, preparedToggle(nil, openaiGPT5, true)); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		if !strings.Contains(got, "# keep me") || !strings.Contains(got, "retention_days: 7") {
			t.Fatalf("splice dropped unrelated content:\n%s", got)
		}
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs, want := favoritesOnDisk(t, target), []Favorite{openaiGPT5}; !slices.Equal(favs, want) {
			t.Fatalf("favorites = %v, want %v", favs, want)
		}
	})

	t.Run("block removal orphaning a sibling alias is rejected", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		source := "model:\n  favorites:\n    - &shared\n      provider: openai\n      id: gpt-5\n  active: *shared\n"
		if err := Validate([]byte(source), target); err != nil {
			t.Fatalf("source failed schema validation: %v\n%s", err, source)
		}
		writeAt(t, target, source)
		_, _, err := RewriteKey(target, keyModelFavorites, preparedToggle([]Favorite{openaiGPT5}, openaiGPT5, false))
		if err == nil {
			t.Fatalf("removing an aliased anchored favorite should fail, got nil error")
		}
		if got := readAt(t, target); got != source {
			t.Fatalf("rejected removal rewrote bytes:\n%q\nwant\n%q", got, source)
		}
	})

	t.Run("flow removal orphaning a sibling alias is rejected", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		source := "model: {favorites: [&shared {provider: openai, id: gpt-5}], active: *shared}\n"
		if err := Validate([]byte(source), target); err != nil {
			t.Fatalf("source failed schema validation: %v\n%s", err, source)
		}
		writeAt(t, target, source)
		_, _, err := RewriteKey(target, keyModelFavorites, preparedToggle([]Favorite{openaiGPT5}, openaiGPT5, false))
		if err == nil {
			t.Fatalf("removing an aliased anchored favorite should fail, got nil error")
		}
		if got := readAt(t, target); got != source {
			t.Fatalf("rejected removal rewrote bytes:\n%q\nwant\n%q", got, source)
		}
	})

	t.Run("removing an unreferenced anchored favorite still succeeds", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "settings.yaml")
		source := "model:\n  favorites:\n    - &unused\n      provider: openai\n      id: gpt-5\n    - provider: anthropic\n      id: opus\n"
		if err := Validate([]byte(source), target); err != nil {
			t.Fatalf("source failed schema validation: %v\n%s", err, source)
		}
		writeAt(t, target, source)
		op := preparedToggle([]Favorite{openaiGPT5, anthropicOpus}, openaiGPT5, false)
		if _, _, err := RewriteKey(target, keyModelFavorites, op); err != nil {
			t.Fatalf("RewriteKey: %v", err)
		}
		got := readAt(t, target)
		if err := Validate([]byte(got), target); err != nil {
			t.Fatalf("result failed schema validation: %v\n%s", err, got)
		}
		if favs, want := favoritesOnDisk(t, target), []Favorite{anthropicOpus}; !slices.Equal(favs, want) {
			t.Fatalf("favorites = %v, want %v", favs, want)
		}
	})
}

func TestRewriteKey_ModelFavorites_RejectsInvalidPayload(t *testing.T) {
	before := "model:\n  favorites:\n    - provider: openai\n      id: gpt-5\n"
	cases := map[string]any{
		"wrong type":           modelSelection("openai", "gpt-5", "high"),
		"value not pointer":    favoriteToggleValue{target: Favorite{Provider: "openai", ID: "gpt-5"}, want: true, prepared: true},
		"unprepared":           &favoriteToggleValue{target: Favorite{Provider: "openai", ID: "gpt-5"}, want: true},
		"empty provider":       preparedToggle(nil, Favorite{Provider: "", ID: "gpt-5"}, true),
		"empty id":             preparedToggle(nil, Favorite{Provider: "openai", ID: ""}, true),
		"nil prepared pointer": (*favoriteToggleValue)(nil),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "settings.yaml")
			writeAt(t, target, before)
			step, _, err := RewriteKey(target, keyModelFavorites, payload)
			if err == nil {
				t.Fatalf("RewriteKey accepted payload %T", payload)
			}
			if step != fsutil.LoadStep {
				t.Fatalf("step = %q, want %q", step, fsutil.LoadStep)
			}
			if got := readAt(t, target); got != before {
				t.Fatalf("rejected payload changed bytes:\n%q\nwant\n%q", got, before)
			}
		})
	}
}

const attributionDoc = `# leading file comment
discovery:
  boundary: launch-dir-only # inline comment after value

# attribution is managed by hand today.
attribution: true # keep codemeld named on the dashboard

model:
  active:
    provider: openai
    id: gpt-5.5
    effort: medium

trailing_unknown: bar
`

func TestRewriteKey_Attribution_PreservesEveryOtherByte(t *testing.T) {
	for _, tc := range []rewriteCase{
		{
			name:  "true replaced by false in place",
			input: attributionDoc,
			key:   KeyAttribution,
			value: false,
			want:  strings.Replace(attributionDoc, "attribution: true #", "attribution: false #", 1),
		},
		{
			name:  "false replaced by true in place",
			input: strings.Replace(attributionDoc, "attribution: true #", "attribution: false #", 1),
			key:   KeyAttribution,
			value: true,
			want:  attributionDoc,
		},
		{
			name:  "same value rewrites identical bytes",
			input: attributionDoc,
			key:   KeyAttribution,
			value: true,
			want:  attributionDoc,
		},
		{
			name:  "absent key is appended",
			input: "discovery:\n  boundary: project # keep me\n",
			key:   KeyAttribution,
			value: false,
			want:  "discovery:\n  boundary: project # keep me\nattribution: false\n",
		},
		{
			name:  "absent file is created with only the key",
			input: "",
			key:   KeyAttribution,
			value: false,
			want:  "attribution: false\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.run(t) })
	}
}

func TestRewriteKey_Attribution_RejectsNonBoolPayloadAndValue(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		value any
	}{
		{"string payload", attributionDoc, "false"},
		{"nil payload", attributionDoc, nil},
		{"on-disk value is not a boolean", "attribution: maybe\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "settings.yaml")
			writeAt(t, target, tc.input)

			step, _, err := RewriteKey(target, KeyAttribution, tc.value)
			if err == nil {
				t.Fatalf("RewriteKey accepted %T", tc.value)
			}
			if step != fsutil.LoadStep {
				t.Fatalf("step = %q, want %q", step, fsutil.LoadStep)
			}
			if got := readAt(t, target); got != tc.input {
				t.Fatalf("rejected write changed bytes:\n%q\nwant\n%q", got, tc.input)
			}
		})
	}
}

func TestRewriteKey_SharedTempFolders_Shapes(t *testing.T) {
	for _, tc := range []rewriteCase{
		{
			name:  "absent file is created with only the key",
			input: "",
			value: "allow",
			want:  "confinement:\n  shared_temp_folders: allow\n",
		},
		{
			name:  "absent container is appended",
			input: "# top\nattribution: true # keep\n",
			value: "deny",
			want:  "# top\nattribution: true # keep\nconfinement:\n  shared_temp_folders: deny\n",
		},
		{
			name:  "block container gains the key after its siblings",
			input: "confinement:\n    program_lookup: strict # keep\nattribution: false\n",
			value: "allow",
			want:  "confinement:\n    program_lookup: strict # keep\n    shared_temp_folders: allow\nattribution: false\n",
		},
		{
			name:  "block value replaced in place",
			input: "confinement:\n  shared_temp_folders: deny # saved answer\n  program_lookup: strict\n",
			value: "allow",
			want:  "confinement:\n  shared_temp_folders: allow # saved answer\n  program_lookup: strict\n",
		},
		{
			name:  "null container becomes a block mapping",
			input: "confinement:\nattribution: true\n",
			value: "deny",
			want:  "confinement:\n  shared_temp_folders: deny\nattribution: true\n",
		},
		{
			name:  "empty flow container",
			input: "confinement: {}\nattribution: true\n",
			value: "allow",
			want:  "confinement: {shared_temp_folders: allow}\nattribution: true\n",
		},
		{
			name:  "flow container gains the key",
			input: "confinement: {program_lookup: strict}\n",
			value: "allow",
			want:  "confinement: {program_lookup: strict, shared_temp_folders: allow}\n",
		},
		{
			name:  "flow value replaced in place",
			input: "confinement: {shared_temp_folders: allow, program_lookup: strict}\n",
			value: "deny",
			want:  "confinement: {shared_temp_folders: deny, program_lookup: strict}\n",
		},
	} {
		tc.key = KeySharedTempFolders
		t.Run(tc.name, func(t *testing.T) { tc.run(t) })
	}
}

func TestRewriteKey_SharedTempFolders_AbsentContainerKeepsRootValid(t *testing.T) {
	for _, tc := range []rewriteCase{
		{
			name:  "flow root",
			input: "{attribution: true}\n",
			value: "allow",
			want:  "{attribution: true, confinement: {shared_temp_folders: allow}}\n",
		},
		{
			name:  "empty flow root",
			input: "{} # keep\n",
			value: "deny",
			want:  "{confinement: {shared_temp_folders: deny}} # keep\n",
		},
		{
			name:  "block root ending in a document-end marker",
			input: "attribution: true\n...\n# after\n",
			value: "allow",
			want:  "attribution: true\nconfinement:\n  shared_temp_folders: allow\n...\n# after\n",
		},
		{
			name:  "empty document ending in a document-end marker",
			input: "---\n...\n",
			value: "deny",
			want:  "---\nconfinement:\n  shared_temp_folders: deny\n...\n",
		},
	} {
		tc.key = KeySharedTempFolders
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t)
			raw, cat, err := ValidateGlobalSettingsBytes([]byte(tc.want), "settings.yaml")
			if err != nil {
				t.Fatalf("written settings do not validate: (%q, %v)", cat, err)
			}
			confinement, _ := raw["confinement"].(map[string]any)
			if got := confinement["shared_temp_folders"]; got != tc.value {
				t.Fatalf("confinement.shared_temp_folders = %v, want %v", got, tc.value)
			}
		})
	}
}

func TestRewriteKey_SharedTempFolders_RejectsBadPayloadAndShape(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		value any
	}{
		{"bool payload", "attribution: true\n", true},
		{"value outside the enum", "attribution: true\n", "ask"},
		{"container is a scalar", "confinement: strict\n", "allow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "settings.yaml")
			writeAt(t, target, tc.input)

			step, _, err := RewriteKey(target, KeySharedTempFolders, tc.value)
			if err == nil {
				t.Fatalf("RewriteKey accepted %v", tc.value)
			}
			if step != fsutil.LoadStep {
				t.Fatalf("step = %q, want %q", step, fsutil.LoadStep)
			}
			if got := readAt(t, target); got != tc.input {
				t.Fatalf("rejected write changed bytes:\n%q\nwant\n%q", got, tc.input)
			}
		})
	}
}

func TestRewriteKey_RetentionDays_Shapes(t *testing.T) {
	for _, tc := range []rewriteCase{
		{
			name:  "absent file is created with only the key",
			input: "",
			value: 14,
			want:  "sessions:\n  retention_days: 14\n",
		},
		{
			name:  "absent container is appended",
			input: "# top\nattribution: true # keep\n",
			value: 14,
			want:  "# top\nattribution: true # keep\nsessions:\n  retention_days: 14\n",
		},
		{
			name:  "null container becomes a block mapping",
			input: "sessions:\nattribution: true\n",
			value: 7,
			want:  "sessions:\n  retention_days: 7\nattribution: true\n",
		},
		{
			name:  "block container gains the key after its siblings",
			input: "sessions:\n    max_tool_output_bytes: 4096 # keep\nattribution: false\n",
			value: 60,
			want:  "sessions:\n    max_tool_output_bytes: 4096 # keep\n    retention_days: 60\nattribution: false\n",
		},
		{
			name:  "block value replaced in place",
			input: "# head\nsessions:\n  retention_days: 30 # days\n\n  max_tool_output_bytes: 4096\n",
			value: 14,
			want:  "# head\nsessions:\n  retention_days: 14 # days\n\n  max_tool_output_bytes: 4096\n",
		},
		{
			name:  "flow container gains the key",
			input: "sessions: {max_tool_output_bytes: 4096}\n",
			value: 14,
			want:  "sessions: {max_tool_output_bytes: 4096, retention_days: 14}\n",
		},
		{
			name:  "flow value replaced in place",
			input: "sessions: {retention_days: 30, max_tool_output_bytes: 4096}\n",
			value: 90,
			want:  "sessions: {retention_days: 90, max_tool_output_bytes: 4096}\n",
		},
	} {
		tc.key = KeyRetentionDays
		t.Run(tc.name, func(t *testing.T) { tc.run(t) })
	}
}

func TestRewriteKey_RetentionDays_NullContainerKeepsSurroundings(t *testing.T) {
	for _, tc := range []rewriteCase{
		{
			name:  "explicit block null with comment",
			input: "sessions: null # keep\nattribution: true\n",
			want:  "sessions: # keep\n  retention_days: 14\nattribution: true\n",
		},
		{
			name:  "tilde block null with comment",
			input: "sessions: ~ # keep\nattribution: true\n",
			want:  "sessions: # keep\n  retention_days: 14\nattribution: true\n",
		},
		{
			name:  "implicit block null with comment",
			input: "sessions: # keep\n\n# next\nattribution: true\n",
			want:  "sessions: # keep\n  retention_days: 14\n\n# next\nattribution: true\n",
		},
		{
			name:  "implicit block null before a key spelled like null",
			input: "sessions:\nnullable: 1\nattribution: true\n",
			want:  "sessions:\n  retention_days: 14\nnullable: 1\nattribution: true\n",
		},
		{
			name:  "explicit block null at end of file without newline",
			input: "attribution: true\nsessions: null",
			want:  "attribution: true\nsessions:\n  retention_days: 14",
		},
		{
			name:  "null inside a flow root with siblings around it",
			input: "{attribution: true, sessions: null, provider: {}}\n",
			want:  "{attribution: true, sessions: {retention_days: 14}, provider: {}}\n",
		},
		{
			name:  "null first in a flow root",
			input: "{sessions: null, attribution: true}\n",
			want:  "{sessions: {retention_days: 14}, attribution: true}\n",
		},
	} {
		tc.key = KeyRetentionDays
		tc.value = 14
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t)
			raw, cat, err := ValidateGlobalSettingsBytes([]byte(tc.want), "settings.yaml")
			if err != nil {
				t.Fatalf("written settings do not validate: (%q, %v)", cat, err)
			}
			sessions, _ := raw["sessions"].(map[string]any)
			if got := fmt.Sprint(sessions["retention_days"]); got != "14" {
				t.Fatalf("sessions.retention_days = %v, want 14", got)
			}
			if got := raw["attribution"]; got != true {
				t.Fatalf("attribution = %v, want true", got)
			}
		})
	}
}

func TestRewriteKey_RetentionDays_RejectsBadPayload(t *testing.T) {
	const seed = "sessions:\n  retention_days: 30\n"
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"string payload", "14"},
		{"uint64 payload", uint64(14)},
		{"float payload", 14.0},
		{"zero", 0},
		{"negative", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "settings.yaml")
			writeAt(t, target, seed)

			step, _, err := RewriteKey(target, KeyRetentionDays, tc.value)
			if err == nil {
				t.Fatalf("RewriteKey accepted %v", tc.value)
			}
			if step != fsutil.LoadStep {
				t.Fatalf("step = %q, want %q", step, fsutil.LoadStep)
			}
			if got := readAt(t, target); got != seed {
				t.Fatalf("rejected write changed bytes:\n%q\nwant\n%q", got, seed)
			}
		})
	}
}

func favoritesOnDisk(t *testing.T, path string) []Favorite {
	t.Helper()
	var raw map[string]any
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	favs, err := favoritesFromRaw(raw)
	if err != nil {
		t.Fatalf("favoritesFromRaw(%s): %v\n%s", path, err, b)
	}
	return favs
}

func TestRewriteKey_OpenRouterRouting_WritesOnlyTargetScalar(t *testing.T) {
	const head = "# top\nprovider:\n  openrouter:\n    base_url: https://openrouter.ai/api/v1\n    api_key: sk-x # key\n"
	const venice = "  venice:\n    base_url: https://api.venice.ai/api/v1\n    api_key: sk-v\n"
	const routing = "    # routing prefs\n    routing:\n      require_parameters: false\n      sort: latency # fast\n      max_price:\n        a/m: {prompt: 1}\n"
	for _, rc := range []rewriteCase{
		{
			name:  "block: missing routing is created under openrouter",
			input: head + venice,
			key:   KeyOpenRouterRoutingDataCollection, value: "deny",
			want: head + "    routing:\n      data_collection: deny\n" + venice,
		},
		{
			name:  "block: missing routing at end of file without newline",
			input: strings.TrimSuffix(head, "\n"),
			key:   KeyOpenRouterRoutingSort, value: "latency",
			want: head + "    routing:\n      sort: latency\n",
		},
		{
			name:  "block: new key appended after nested max_price",
			input: head + routing + venice,
			key:   KeyOpenRouterRoutingDataCollection, value: "allow",
			want: head + routing + "      data_collection: allow\n" + venice,
		},
		{
			name:  "block: sort replaced keeping its inline comment",
			input: head + routing + venice,
			key:   KeyOpenRouterRoutingSort, value: "throughput",
			want: head + strings.Replace(routing, "sort: latency # fast", "sort: throughput # fast", 1) + venice,
		},
		{
			name:  "block: default removes sort and keeps siblings and its inline comment",
			input: head + routing + venice,
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + strings.Replace(routing, "      sort: latency # fast\n", "      # fast\n", 1) + venice,
		},
		{
			name:  "block: default keeps comments before and inline on sort with a sibling",
			input: head + "    routing:\n      data_collection: allow\n      # sort choice\n      sort: latency # fast\n      require_parameters: true\n" + venice,
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + "    routing:\n      data_collection: allow\n      # sort choice\n      # fast\n      require_parameters: true\n" + venice,
		},
		{
			name:  "block: removing the final key removes routing",
			input: head + "    routing:\n      sort: latency\n" + venice,
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + venice,
		},
		{
			name:  "block: removing the final key keeps routing comments",
			input: head + "    routing:\n      # keep me\n      sort: latency # fast\n" + venice,
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + "      # keep me\n      # fast\n" + venice,
		},
		{
			name:  "block: removing the final key keeps a comment on the routing key",
			input: head + "    routing: # keep\n      sort: latency\n" + venice,
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + "      # keep\n" + venice,
		},
		{
			name:  "block: removing the final flow key keeps a comment after the routing value",
			input: head + "    routing: {sort: latency} # keep\n" + venice,
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + "      # keep\n" + venice,
		},
		{
			name:  "default without routing is a no-op",
			input: head + venice,
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + venice,
		},
		{
			name:  "default without sort is a no-op",
			input: head + "    routing:\n      data_collection: deny\n",
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + "    routing:\n      data_collection: deny\n",
		},
		{
			name:  "flow provider and openrouter: routing appended",
			input: "provider: {venice: {base_url: v, api_key: k}, openrouter: {base_url: u, api_key: k}} # c\n",
			key:   KeyOpenRouterRoutingSort, value: "latency",
			want: "provider: {venice: {base_url: v, api_key: k}, openrouter: {base_url: u, api_key: k, routing: {sort: latency}}} # c\n",
		},
		{
			name:  "flow openrouter: removing the only routing key removes routing",
			input: "provider: {openrouter: {base_url: u, api_key: k, routing: {sort: latency}}}\n",
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: "provider: {openrouter: {base_url: u, api_key: k}}\n",
		},
		{
			name:  "block openrouter with flow routing: scalar replaced",
			input: head + "    routing: {sort: latency, data_collection: allow} # r\n",
			key:   KeyOpenRouterRoutingDataCollection, value: "deny",
			want: head + "    routing: {sort: latency, data_collection: deny} # r\n",
		},
		{
			name:  "flow routing: first key removed",
			input: head + "    routing: {sort: latency, data_collection: allow}\n",
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + "    routing: {data_collection: allow}\n",
		},
		{
			name:  "flow routing: later key removed",
			input: head + "    routing: {data_collection: allow, sort: latency, require_parameters: true}\n",
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + "    routing: {data_collection: allow, require_parameters: true}\n",
		},
		{
			name:  "flow routing: only key removed drops the routing line",
			input: head + "    routing: {sort: latency}\n" + venice,
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + venice,
		},
		{
			name:  "empty flow routing gets its first key",
			input: head + "    routing: {}\n",
			key:   KeyOpenRouterRoutingSort, value: "throughput",
			want: head + "    routing: {sort: throughput}\n",
		},
		{
			name:  "block provider with flow openrouter: routing appended",
			input: "provider:\n  openrouter: {base_url: u, api_key: k}\n",
			key:   KeyOpenRouterRoutingDataCollection, value: "deny",
			want: "provider:\n  openrouter: {base_url: u, api_key: k, routing: {data_collection: deny}}\n",
		},
		{
			name:  "anchored tagged block provider mapping",
			input: "provider: &providers !!map\n  openrouter:\n    base_url: u\n    api_key: k\n",
			key:   KeyOpenRouterRoutingSort, value: "latency",
			want: "provider: &providers !!map\n  openrouter:\n    base_url: u\n    api_key: k\n    routing:\n      sort: latency\n",
		},
		{
			name:  "anchored tagged flow provider mapping",
			input: "provider: &providers !!map {openrouter: {base_url: u, api_key: k}}\n",
			key:   KeyOpenRouterRoutingDataCollection, value: "deny",
			want: "provider: &providers !!map {openrouter: {base_url: u, api_key: k, routing: {data_collection: deny}}}\n",
		},
		{
			name:  "anchored tagged flow provider keeps trailing nested sibling",
			input: "provider: &providers !!map {openrouter: {base_url: u, api_key: k, auth_header: {name: X-Key, value: \"{api_key}\"}}}\n",
			key:   KeyOpenRouterRoutingDataCollection, value: "deny",
			want: "provider: &providers !!map {openrouter: {base_url: u, api_key: k, auth_header: {name: X-Key, value: \"{api_key}\"}, routing: {data_collection: deny}}}\n",
		},
		{
			name:  "anchored tagged block openrouter mapping",
			input: "provider:\n  openrouter: &entry !!map\n    base_url: u\n    api_key: k\n",
			key:   KeyOpenRouterRoutingSort, value: "throughput",
			want: "provider:\n  openrouter: &entry !!map\n    base_url: u\n    api_key: k\n    routing:\n      sort: throughput\n",
		},
		{
			name:  "anchored tagged flow openrouter mapping",
			input: "provider:\n  openrouter: &entry !!map {base_url: u, api_key: k}\n",
			key:   KeyOpenRouterRoutingSort, value: "latency",
			want: "provider:\n  openrouter: &entry !!map {base_url: u, api_key: k, routing: {sort: latency}}\n",
		},
		{
			name:  "anchored tagged block routing mapping",
			input: head + "    routing: &route !!map\n      data_collection: deny\n",
			key:   KeyOpenRouterRoutingSort, value: "latency",
			want: head + "    routing: &route !!map\n      data_collection: deny\n      sort: latency\n",
		},
		{
			name:  "anchored tagged flow routing mapping",
			input: head + "    routing: &route !!map {data_collection: deny}\n",
			key:   KeyOpenRouterRoutingSort, value: "latency",
			want: head + "    routing: &route !!map {data_collection: deny, sort: latency}\n",
		},
		{
			name:  "new key follows trailing anchored max_price block",
			input: head + "    routing:\n      data_collection: deny\n      max_price: &prices !!map\n        a/m: {prompt: 1}\n" + venice,
			key:   KeyOpenRouterRoutingSort, value: "latency",
			want: head + "    routing:\n      data_collection: deny\n      max_price: &prices !!map\n        a/m: {prompt: 1}\n      sort: latency\n" + venice,
		},
		{
			name:  "anchored tagged routing scalar keeps its properties",
			input: head + "    routing:\n      sort: &choice !!str latency\n",
			key:   KeyOpenRouterRoutingSort, value: "throughput",
			want: head + "    routing:\n      sort: &choice !!str throughput\n",
		},
		{
			name:  "anchored tagged flow routing scalar keeps its properties",
			input: head + "    routing: &route !!map {sort: &choice !!str latency, data_collection: deny}\n",
			key:   KeyOpenRouterRoutingSort, value: "throughput",
			want: head + "    routing: &route !!map {sort: &choice !!str throughput, data_collection: deny}\n",
		},
		{
			name:  "default removes anchored tagged routing with its final key",
			input: head + "    routing: &route !!map\n      sort: latency\n" + venice,
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + venice,
		},
		{
			name:  "default removes anchored tagged flow routing with its final key",
			input: head + "    routing: &route !!map {sort: latency}\n" + venice,
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + venice,
		},
	} {
		t.Run(rc.name, func(t *testing.T) {
			if _, cat, err := ValidateGlobalSettingsBytes([]byte(rc.input), "settings.yaml"); cat != LoadOK || err != nil {
				t.Fatalf("source failed validation: %v %v", cat, err)
			}
			rc.run(t)
			if _, cat, err := ValidateGlobalSettingsBytes([]byte(rc.want), "settings.yaml"); cat != LoadOK || err != nil {
				t.Fatalf("result failed validation: %v %v", cat, err)
			}
		})
	}
}

func TestRewriteKey_OpenRouterRouting_RefusesAndLeavesFileUntouched(t *testing.T) {
	for _, tc := range []struct {
		name  string
		seed  string
		key   string
		value any
	}{
		{"no provider", "attribution: true\n", KeyOpenRouterRoutingSort, "latency"},
		{"no openrouter entry", "provider:\n  venice:\n    base_url: v\n    api_key: k\n", KeyOpenRouterRoutingDataCollection, "deny"},
		{"out-of-schema value", "provider:\n  openrouter:\n    base_url: u\n    api_key: k\n", KeyOpenRouterRoutingDataCollection, "maybe"},
		{"invalid existing sibling", "provider:\n  openrouter:\n    base_url: u\n    api_key: k\n    routing:\n      sort: bogus\n", KeyOpenRouterRoutingDataCollection, "deny"},
		{"non-string payload", "provider:\n  openrouter:\n    base_url: u\n    api_key: k\n", KeyOpenRouterRoutingSort, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.yaml")
			writeAt(t, path, tc.seed)
			step, _, err := RewriteKey(path, tc.key, tc.value)
			if err == nil || step != fsutil.LoadStep {
				t.Fatalf("RewriteKey = (%q, %v), want a LoadStep refusal", step, err)
			}
			if got := readAt(t, path); got != tc.seed {
				t.Fatalf("refused write changed the file:\n%s", got)
			}
		})
	}

	t.Run("absent file is not created", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "settings.yaml")
		if _, _, err := RewriteKey(path, KeyOpenRouterRoutingSort, "latency"); !errors.Is(err, errNoOpenRouterEntry) {
			t.Fatalf("err = %v, want errNoOpenRouterEntry", err)
		}
		if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("refused write created the file: %v", err)
		}
	})
}

func TestRewriteKey_OpenRouterMaxPrice(t *testing.T) {
	const id = "meta-llama/llama-3.3-70b:free"
	const q = `"` + id + `"`
	const head = "# top\nprovider:\n  openrouter:\n    base_url: https://openrouter.ai/api/v1\n    api_key: sk-x # key\n"
	const venice = "  venice:\n    base_url: https://api.venice.ai/api/v1\n    api_key: sk-v\n"
	const siblings = "    # routing prefs\n    routing:\n      sort: latency # fast\n      data_collection: deny\n"
	both := OpenRouterMaxPrice{Model: id, Price: provider.MaxPrice{Prompt: 1.5, Completion: 2, HasPrompt: true, HasCompletion: true}}
	promptOnly := OpenRouterMaxPrice{Model: id, Price: provider.MaxPrice{Prompt: 0.25, HasPrompt: true}}
	completionOnly := OpenRouterMaxPrice{Model: id, Price: provider.MaxPrice{Completion: 3, HasCompletion: true}}
	remove := OpenRouterMaxPrice{Model: id}
	for _, rc := range []rewriteCase{
		{
			name:  "block: set both creates routing and max_price",
			input: head + venice,
			value: both,
			want:  head + "    routing:\n      max_price:\n        " + q + ": {prompt: 1.5, completion: 2}\n" + venice,
		},
		{
			name:  "block: set one side appends max_price after routing siblings",
			input: head + siblings + venice,
			value: promptOnly,
			want:  head + siblings + "      max_price:\n        " + q + ": {prompt: 0.25}\n" + venice,
		},
		{
			name:  "block: new model joins another model's entry",
			input: head + siblings + "      max_price:\n        openai/gpt-4.1: {prompt: 1} # theirs\n" + venice,
			value: both,
			want:  head + siblings + "      max_price:\n        openai/gpt-4.1: {prompt: 1} # theirs\n        " + q + ": {prompt: 1.5, completion: 2}\n" + venice,
		},
		{
			name:  "block: set one side replaces the other side",
			input: head + siblings + "      max_price:\n        " + q + ": {prompt: 1}\n" + venice,
			value: completionOnly,
			want:  head + siblings + "      max_price:\n        " + q + ": {completion: 3}\n" + venice,
		},
		{
			name:  "block: set both on a block entry keeps its comments",
			input: head + siblings + "      max_price:\n        " + id + ": # mine\n          prompt: 1 # p\n          completion: 2\n" + venice,
			value: both,
			want:  head + siblings + "      max_price:\n        " + id + ": # mine\n          prompt: 1.5 # p\n          completion: 2\n" + venice,
		},
		{
			name:  "block: remove one model while another stays",
			input: head + siblings + "      max_price:\n        " + q + ": {prompt: 1}\n        openai/gpt-4.1: {prompt: 1} # theirs\n" + venice,
			value: remove,
			want:  head + siblings + "      max_price:\n        openai/gpt-4.1: {prompt: 1} # theirs\n" + venice,
		},
		{
			name:  "block: remove the last model keeps sibling routing keys",
			input: head + siblings + "      max_price:\n        " + q + ": {prompt: 1}\n" + venice,
			value: remove,
			want:  head + siblings + venice,
		},
		{
			name:  "block: remove the last model without siblings removes routing",
			input: head + "    routing:\n      max_price:\n        " + q + ": {prompt: 1, completion: 2}\n" + venice,
			value: remove,
			want:  head + venice,
		},
		{
			name:  "remove without an entry is a no-op",
			input: head + siblings + venice,
			value: remove,
			want:  head + siblings + venice,
		},
		{
			name:  "flow: set into routing without max_price",
			input: head + "    routing: {sort: latency} # r\n" + venice,
			value: both,
			want:  head + "    routing: {sort: latency, max_price: {" + q + ": {prompt: 1.5, completion: 2}}} # r\n" + venice,
		},
		{
			name:  "flow: set replaces the existing entry",
			input: head + "    routing: {sort: latency, max_price: {" + q + ": {prompt: 1}}}\n" + venice,
			value: both,
			want:  head + "    routing: {sort: latency, max_price: {" + q + ": {prompt: 1.5, completion: 2}}}\n" + venice,
		},
		{
			name:  "flow: remove one model while another stays",
			input: head + "    routing: {sort: latency, max_price: {openai/gpt-4.1: {prompt: 1}, " + q + ": {completion: 2}}}\n" + venice,
			value: remove,
			want:  head + "    routing: {sort: latency, max_price: {openai/gpt-4.1: {prompt: 1}}}\n" + venice,
		},
		{
			name:  "flow: remove the first of several models keeps comments inside its value",
			input: head + "    routing:\n      max_price: {" + q + ": { # keep this pricing note\n        prompt: 1}, \"other/model\": {prompt: 2}}\n" + venice,
			value: remove,
			want:  head + "    routing:\n      max_price: { # keep this pricing note\n        \"other/model\": {prompt: 2}}\n" + venice,
		},
		{
			name:  "flow: remove a middle model keeps comments inside its value",
			input: head + "    routing:\n      max_price: {\"a/b.c\": {prompt: 1}, " + q + ": {prompt: 2, # p\n        completion: 3}, \"d/e:free\": {prompt: 4}}\n" + venice,
			value: remove,
			want:  head + "    routing:\n      max_price: {\"a/b.c\": {prompt: 1} # p\n        , \"d/e:free\": {prompt: 4}}\n" + venice,
		},
		{
			name:  "flow: remove the last of several models keeps comments inside its value",
			input: head + "    routing:\n      max_price: {\"other/model\": {prompt: 2}, " + q + ": { # keep\n        completion: 1}}\n" + venice,
			value: remove,
			want:  head + "    routing:\n      max_price: {\"other/model\": {prompt: 2} # keep\n        }\n" + venice,
		},
		{
			name:  "flow: remove the first model with an unmatched brace in its nested comment",
			input: head + "    routing:\n      max_price: {" + q + ": { # keep }\n        prompt: 1}, \"other/model\": {prompt: 2}}\n" + venice,
			value: remove,
			want:  head + "    routing:\n      max_price: { # keep }\n        \"other/model\": {prompt: 2}}\n" + venice,
		},
		{
			name:  "flow: remove a middle model with an unmatched bracket in its nested comment",
			input: head + "    routing:\n      max_price: {\"a/b.c\": {prompt: 1}, " + q + ": {prompt: 2, # p ]\n        completion: 3}, \"d/e:free\": {prompt: 4}}\n" + venice,
			value: remove,
			want:  head + "    routing:\n      max_price: {\"a/b.c\": {prompt: 1} # p ]\n        , \"d/e:free\": {prompt: 4}}\n" + venice,
		},
		{
			name:  "flow: remove the last model with an unmatched quote in its nested comment",
			input: head + "    routing:\n      max_price: {\"other/model\": {prompt: 2}, " + q + ": { # it's \"\n        completion: 1}}\n" + venice,
			value: remove,
			want:  head + "    routing:\n      max_price: {\"other/model\": {prompt: 2} # it's \"\n        }\n" + venice,
		},
		{
			name:  "flow: remove the last model keeps sibling routing keys",
			input: head + "    routing: {sort: latency, max_price: {" + q + ": {prompt: 1}}} # r\n" + venice,
			value: remove,
			want:  head + "    routing: {sort: latency} # r\n" + venice,
		},
		{
			name:  "flow: remove the last model without siblings removes routing",
			input: head + "    routing: {max_price: {" + q + ": {prompt: 1}}}\n" + venice,
			value: remove,
			want:  head + venice,
		},
		{
			name:  "flow: remove the last model keeps a comment inside max_price",
			input: head + "    routing: {sort: latency, max_price: {" + q + ": {prompt: 1} # keep\n      }}\n" + venice,
			value: remove,
			want:  head + "    routing: {sort: latency  # keep\n}\n" + venice,
		},
		{
			name:  "flow openrouter: set creates routing",
			input: "provider: {openrouter: {base_url: u, api_key: k}}\n",
			value: promptOnly,
			want:  "provider: {openrouter: {base_url: u, api_key: k, routing: {max_price: {" + q + ": {prompt: 0.25}}}}}\n",
		},
		{
			name:  "flow openrouter: remove the last model removes routing",
			input: "provider: {openrouter: {base_url: u, api_key: k, routing: {max_price: {" + q + ": {prompt: 1}}}}}\n",
			value: remove,
			want:  "provider: {openrouter: {base_url: u, api_key: k}}\n",
		},
	} {
		rc.key = KeyOpenRouterRoutingMaxPrice
		t.Run(rc.name, func(t *testing.T) {
			if _, cat, err := ValidateGlobalSettingsBytes([]byte(rc.input), "settings.yaml"); cat != LoadOK || err != nil {
				t.Fatalf("source failed validation: %v %v", cat, err)
			}
			rc.run(t)
			if _, cat, err := ValidateGlobalSettingsBytes([]byte(rc.want), "settings.yaml"); cat != LoadOK || err != nil {
				t.Fatalf("result failed validation: %v %v", cat, err)
			}
		})
	}
}

func TestRewriteKey_OpenRouterMaxPrice_RefusesAndLeavesFileUntouched(t *testing.T) {
	const seed = "provider:\n  openrouter:\n    base_url: u\n    api_key: k\n"
	price := provider.MaxPrice{Prompt: 1, HasPrompt: true}
	for _, tc := range []struct {
		name  string
		seed  string
		value any
	}{
		{"no openrouter entry", "provider:\n  venice:\n    base_url: v\n    api_key: k\n", OpenRouterMaxPrice{Model: "a/m", Price: price}},
		{"empty model id", seed, OpenRouterMaxPrice{Price: price}},
		{"wrong payload type", seed, price},
		{"negative value", seed, OpenRouterMaxPrice{Model: "a/m", Price: provider.MaxPrice{Prompt: -1, HasPrompt: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.yaml")
			writeAt(t, path, tc.seed)
			step, _, err := RewriteKey(path, KeyOpenRouterRoutingMaxPrice, tc.value)
			if err == nil || step != fsutil.LoadStep {
				t.Fatalf("RewriteKey = (%q, %v), want a LoadStep refusal", step, err)
			}
			if got := readAt(t, path); got != tc.seed {
				t.Fatalf("refused write changed the file:\n%s", got)
			}
		})
	}
}

func TestRewriteKey_OpenRouterRouting_BlockScalarTargets(t *testing.T) {
	const head = "provider:\n  openrouter:\n    base_url: u\n    api_key: k\n    routing:\n"
	const venice = "  venice:\n    base_url: v\n    api_key: k\n"
	for _, tc := range []struct {
		rewriteCase
		wantRouting map[string]any
	}{
		{rewriteCase{
			name:  "literal strip data_collection replaced",
			input: head + "      data_collection: |-\n        deny\n      sort: latency\n" + venice,
			key:   KeyOpenRouterRoutingDataCollection, value: "allow",
			want: head + "      data_collection: allow\n      sort: latency\n" + venice,
		}, map[string]any{"data_collection": "allow", "sort": "latency"}},
		{rewriteCase{
			name:  "folded strip data_collection with header comment replaced at end of entry",
			input: head + "      require_parameters: true\n      data_collection: >- # privacy\n        deny\n" + venice,
			key:   KeyOpenRouterRoutingDataCollection, value: "allow",
			want: head + "      require_parameters: true\n      data_collection: allow # privacy\n" + venice,
		}, map[string]any{"data_collection": "allow", "require_parameters": true}},
		{rewriteCase{
			name:  "literal clip sort replaced keeping the trailing blank line",
			input: head + "      sort: |\n        latency\n\n      require_parameters: true\n",
			key:   KeyOpenRouterRoutingSort, value: "throughput",
			want: head + "      sort: throughput\n\n      require_parameters: true\n",
		}, map[string]any{"sort": "throughput", "require_parameters": true}},
		{rewriteCase{
			name:  "folded keep sort with indentation indicator replaced",
			input: head + "      sort: >2+\n        latency\n      data_collection: deny\n",
			key:   KeyOpenRouterRoutingSort, value: "latency",
			want: head + "      sort: latency\n      data_collection: deny\n",
		}, map[string]any{"sort": "latency", "data_collection": "deny"}},
		{rewriteCase{
			name:  "default removes a literal strip sort and keeps siblings",
			input: head + "      sort: |-\n        latency\n      data_collection: deny\n" + venice,
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + "      data_collection: deny\n" + venice,
		}, map[string]any{"data_collection": "deny"}},
		{rewriteCase{
			name:  "default removes a folded strip sort that was the only routing key",
			input: head + "      sort: >-\n        latency\n" + venice,
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: "provider:\n  openrouter:\n    base_url: u\n    api_key: k\n" + venice,
		}, nil},
		{rewriteCase{
			name:  "new sort inserted after a trailing literal data_collection",
			input: head + "      data_collection: |-\n        deny\n" + venice,
			key:   KeyOpenRouterRoutingSort, value: "latency",
			want: head + "      data_collection: |-\n        deny\n      sort: latency\n" + venice,
		}, map[string]any{"data_collection": "deny", "sort": "latency"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t)
			raw, cat, err := ValidateGlobalSettingsBytes([]byte(tc.want), "settings.yaml")
			if cat != LoadOK || err != nil {
				t.Fatalf("result failed validation: %v %v", cat, err)
			}
			entry, _ := raw["provider"].(map[string]any)["openrouter"].(map[string]any)
			routing, _ := entry["routing"].(map[string]any)
			if !maps.Equal(routing, tc.wantRouting) {
				t.Fatalf("routing = %#v, want %#v", routing, tc.wantRouting)
			}
		})
	}
}

func TestRewriteKey_OpenRouterRouting_FlowSeparatorsAndComments(t *testing.T) {
	const head = "provider:\n  openrouter:\n    base_url: u\n    api_key: k\n"
	for _, tc := range []struct {
		rewriteCase
		wantRouting map[string]any
	}{
		{rewriteCase{
			name:  "insert into flow routing with a trailing comma",
			input: head + "    routing: {data_collection: deny,}\n",
			key:   KeyOpenRouterRoutingSort, value: "latency",
			want: head + "    routing: {data_collection: deny, sort: latency}\n",
		}, map[string]any{"data_collection": "deny", "sort": "latency"}},
		{rewriteCase{
			name:  "insert into flow routing with a trailing comma and space",
			input: head + "    routing: {data_collection: deny, }\n",
			key:   KeyOpenRouterRoutingSort, value: "latency",
			want: head + "    routing: {data_collection: deny, sort: latency}\n",
		}, map[string]any{"data_collection": "deny", "sort": "latency"}},
		{rewriteCase{
			name:  "insert routing into flow openrouter with a trailing comma",
			input: "provider: {openrouter: {base_url: u, api_key: k,}}\n",
			key:   KeyOpenRouterRoutingDataCollection, value: "deny",
			want: "provider: {openrouter: {base_url: u, api_key: k, routing: {data_collection: deny}}}\n",
		}, map[string]any{"data_collection": "deny"}},
		{rewriteCase{
			name:  "remove the only sort and keep its flow comment",
			input: "provider: {openrouter: {base_url: u, api_key: k, routing: {# keep me\n      sort: latency}}}\n",
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: "provider: {openrouter: {base_url: u, api_key: k # keep me\n}}\n",
		}, nil},
		{rewriteCase{
			name:  "remove later sort keeps the prior sibling's comment",
			input: head + "    routing: {data_collection: allow # keep\n      , sort: latency}\n",
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + "    routing: {data_collection: allow # keep\n      }\n",
		}, map[string]any{"data_collection": "allow"}},
		{rewriteCase{
			name:  "remove later sort keeps a comment after the separator",
			input: head + "    routing: {data_collection: allow, # keep\n      sort: latency}\n",
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + "    routing: {data_collection: allow # keep\n      }\n",
		}, map[string]any{"data_collection": "allow"}},
		{rewriteCase{
			name:  "remove first sort keeps a comment between entries",
			input: head + "    routing: {sort: latency, # keep\n      data_collection: allow}\n",
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + "    routing: { # keep\n      data_collection: allow}\n",
		}, map[string]any{"data_collection": "allow"}},
		{rewriteCase{
			name:  "remove first sort keeps the next sibling's comment",
			input: head + "    routing: {sort: latency,\n      data_collection: allow # keep\n      }\n",
			key:   KeyOpenRouterRoutingSort, value: "default",
			want: head + "    routing: {data_collection: allow # keep\n      }\n",
		}, map[string]any{"data_collection": "allow"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t)
			raw, cat, err := ValidateGlobalSettingsBytes([]byte(tc.want), "settings.yaml")
			if cat != LoadOK || err != nil {
				t.Fatalf("result failed validation: %v %v", cat, err)
			}
			entry, _ := raw["provider"].(map[string]any)["openrouter"].(map[string]any)
			routing, _ := entry["routing"].(map[string]any)
			if !maps.Equal(routing, tc.wantRouting) {
				t.Fatalf("routing = %#v, want %#v", routing, tc.wantRouting)
			}
		})
	}
}

func TestRewriteProviderEntry_OpenRouterMergesConnectionFields(t *testing.T) {
	const tail = "    # header\n    auth_header: {name: X-Key, value: \"{api_key}\"}\n    routing:\n      # keep\n      require_parameters: false\n      max_price: {a/m: {prompt: 1}}\n"
	for _, rc := range []rewriteCase{
		{
			name:  "block entry keeps auth_header and routing",
			input: "provider:\n  openrouter:\n    base_url: https://old.example # url\n    api_key: \"sk-old\"\n" + tail + "  venice:\n    base_url: v\n    api_key: k\n",
			key:   KeyProviderPrefix + "openrouter", value: providerEntryValue("https://openrouter.ai/api/v1", "sk-new"),
			want: "provider:\n  openrouter:\n    base_url: https://openrouter.ai/api/v1 # url\n    api_key: sk-new\n" + tail + "  venice:\n    base_url: v\n    api_key: k\n",
		},
		{
			name:  "flow entry keeps routing",
			input: "provider: {openrouter: {base_url: u, api_key: sk-old, routing: {sort: latency}}}\n",
			key:   KeyProviderPrefix + "openrouter", value: providerEntryValue("u", "sk-new"),
			want: "provider: {openrouter: {base_url: u, api_key: sk-new, routing: {sort: latency}}}\n",
		},
		{
			name:  "absent openrouter entry is created whole",
			input: "provider:\n  venice:\n    base_url: v\n    api_key: k\n",
			key:   KeyProviderPrefix + "openrouter", value: providerEntryValue("u", "sk-new"),
			want: "provider:\n  venice:\n    base_url: v\n    api_key: k\n  openrouter:\n    base_url: u\n    api_key: sk-new\n",
		},
	} {
		t.Run(rc.name, rc.run)
	}

	t.Run("invalid merged candidate is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "settings.yaml")
		const seed = "provider:\n  openrouter:\n    base_url: u\n    api_key: sk-old\n    routing: {sort: bogus}\n"
		writeAt(t, path, seed)
		step, _, err := RewriteKey(path, KeyProviderPrefix+"openrouter", providerEntryValue("u", "sk-new"))
		if err == nil || step != fsutil.LoadStep || strings.Contains(err.Error(), "sk-new") {
			t.Fatalf("RewriteKey = (%q, %v), want a key-free LoadStep refusal", step, err)
		}
		if got := readAt(t, path); got != seed {
			t.Fatalf("refused write changed the file:\n%s", got)
		}
	})
}
