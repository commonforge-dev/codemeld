package filetools

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"codemeld.dev/codemeld/internal/tools"
)

// fileCountTestCap is the tool-output byte cap used in tests, matching tree/glob/grep's test cap so
// truncation behavior is exercised under the same budget.
const fileCountTestCap = 65536

// newFileCountToolIn builds a file_count tool whose project root and relative-path base are root, with a
// separate home anchor (a throwaway temp dir so a real ~/.codemeld/global/codemeldignore cannot leak in),
// mirroring tree_test's newTreeToolIn.
func newFileCountToolIn(t *testing.T, root string) *FileCountTool {
	t.Helper()
	return NewFileCountTool(t.TempDir(), root, root, fileCountTestCap)
}

// invokeFileCount runs the tool's full standalone path (ResolveTarget then count) and returns the result.
func invokeFileCount(t *testing.T, tool *FileCountTool, args map[string]any) (tools.Result, error) {
	t.Helper()
	return tool.Invoke(context.Background(), args)
}

// fileCountLines splits a successful file_count result's stdout into its lines (trailing newline dropped),
// asserting a zero exit so a rejection is not silently read as empty output.
func fileCountLines(t *testing.T, res tools.Result) []string {
	t.Helper()
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d (stderr=%q), want 0", res.ExitCode, res.Stderr)
	}
	out := strings.TrimSuffix(string(res.Stdout), "\n")
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

// wantLines runs args and asserts the result's stdout lines equal want exactly.
func wantLines(t *testing.T, tool *FileCountTool, args map[string]any, want []string) {
	t.Helper()
	res, err := invokeFileCount(t, tool, args)
	if err != nil {
		t.Fatalf("Invoke(%v) error = %v", args, err)
	}
	if got := fileCountLines(t, res); !reflect.DeepEqual(got, want) {
		t.Fatalf("result(%v) = %v, want %v", args, got, want)
	}
}

// TestFileCountTool_Advertise pins the tool's metadata: name file_count, ReadOnly, a closed schema with no
// required fields, the public include_dotfiles flag, and no include_hidden alias.
func TestFileCountTool_Advertise(t *testing.T) {
	tool := newFileCountToolIn(t, t.TempDir())
	if tool.Name() != "file_count" {
		t.Fatalf("Name() = %q, want %q", tool.Name(), "file_count")
	}
	if tool.SubjectKind() != "tool" {
		t.Fatalf("SubjectKind() = %q, want %q", tool.SubjectKind(), "tool")
	}
	md := tool.Advertise()
	if !md.ReadOnly {
		t.Fatal("Advertise().ReadOnly = false, want true")
	}
	params := md.Parameters
	if params["additionalProperties"] != false {
		t.Fatalf("additionalProperties = %v, want false (closed schema)", params["additionalProperties"])
	}
	if req, ok := params["required"].([]string); !ok || len(req) != 0 {
		t.Fatalf("required = %v, want empty (every argument optional)", params["required"])
	}
	props, ok := params["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties is %T, want map[string]any", params["properties"])
	}
	for _, key := range []string{"path", "kinds", "include_globs", "exclude_globs", "group_by", "include_dotfiles", "include_ignored", "limit"} {
		if _, ok := props[key]; !ok {
			t.Fatalf("schema is missing property %q", key)
		}
	}
	if _, ok := props["include_hidden"]; ok {
		t.Fatal("schema advertises include_hidden; the public flag must be include_dotfiles only")
	}
	gb, _ := props["group_by"].(map[string]any)
	enum, _ := gb["enum"].([]string)
	for _, mode := range []string{"extension", "top_dir", "dir", "depth", "stem"} {
		if !containsStr(enum, mode) {
			t.Fatalf("group_by enum %v is missing %q", enum, mode)
		}
	}
	if !strings.Contains(md.Description, "stem") {
		t.Fatalf("description must advertise stem grouping; got %q", md.Description)
	}
	assertFileCountGuidance(t, md, props)
}

// containsStr reports whether want is in list.
func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// assertFileCountGuidance pins the advertising guidance without matching the full description text:
// the tool must (1) tell models to prefer file_count over shell/Python for expressible counting requests,
// (2) state that kinds/include_globs/exclude_globs are JSON arrays, and (3) carry a prefix-folder image count
// with thumbnail exclusion. Substring checks so minor copy edits do not break unrelated assertions.
func assertFileCountGuidance(t *testing.T, md tools.Metadata, props map[string]any) {
	t.Helper()
	desc := md.Description
	lower := strings.ToLower(desc)
	if !strings.Contains(lower, "prefer") || !strings.Contains(lower, "shell") || !strings.Contains(lower, "python") {
		t.Fatalf("description must prefer file_count over shell/Python; got %q", desc)
	}
	if !strings.Contains(lower, "json array") {
		t.Fatalf("description must say kinds/include_globs/exclude_globs are JSON arrays; got %q", desc)
	}
	if !strings.Contains(desc, "kinds [\"file\"]") {
		t.Fatalf("description must tie kinds to JSON-array guidance with a valid example like kinds [\"file\"]; got %q", desc)
	}
	if !strings.Contains(lower, "thumbnail") || !strings.Contains(desc, "th_*") {
		t.Fatalf("description must include a prefix-folder image count with thumbnail exclusion; got %q", desc)
	}
	for _, key := range []string{"include_globs", "exclude_globs"} {
		prop, _ := props[key].(map[string]any)
		pd, _ := prop["description"].(string)
		if !strings.Contains(strings.ToLower(pd), "json array") {
			t.Fatalf("%s description must state it is a JSON array; got %q", key, pd)
		}
	}
}

// TestFileCountTool_FlatKindTotals pins the flat (no group_by) total under each kinds selection: the default
// counts regular files only; dir/symlink kinds count their own type; a multi-kind set sums them. A symlink to
// a directory is counted as a leaf and never descended.
func TestFileCountTool_FlatKindTotals(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.go"), "package x\n")
	writeFile(t, filepath.Join(root, "b.txt"), "text\n")
	mkdirAll(t, filepath.Join(root, "sub"))
	writeFile(t, filepath.Join(root, "sub", "c.go"), "package x\n")
	if err := os.Symlink(filepath.Join(root, "sub"), filepath.Join(root, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newFileCountToolIn(t, root)

	wantLines(t, tool, map[string]any{}, []string{"total: 3"})                                         // a.go, b.txt, sub/c.go
	wantLines(t, tool, map[string]any{"kinds": []any{"dir"}}, []string{"total: 1"})                    // sub
	wantLines(t, tool, map[string]any{"kinds": []any{"symlink"}}, []string{"total: 1"})                // link (not followed)
	wantLines(t, tool, map[string]any{"kinds": []any{"file", "dir", "symlink"}}, []string{"total: 5"}) // 3 files + sub + link
}

// TestFileCountTool_OtherKindCount pins the advertised "other" kind: a special filesystem entry (a FIFO) is
// counted only under kinds:["other"], so a fixture of a regular file, a directory, and a FIFO reports total 1.
// Skipped only when the platform cannot create a FIFO.
func TestFileCountTool_OtherKindCount(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.go"), "package x\n")
	mkdirAll(t, filepath.Join(root, "sub"))
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0o644); err != nil {
		t.Skipf("Mkfifo unsupported on this platform: %v", err)
	}
	tool := newFileCountToolIn(t, root)

	wantLines(t, tool, map[string]any{"kinds": []any{"other"}}, []string{"total: 1"}) // the FIFO only
}

// TestFileCountTool_IncludeExcludeGlobs pins that include_globs keeps only matching entries, exclude_globs
// drops matching entries, and the two compose (include then exclude).
func TestFileCountTool_IncludeExcludeGlobs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "keep.go"), "package x\n")
	writeFile(t, filepath.Join(root, "skip.go"), "package x\n")
	writeFile(t, filepath.Join(root, "note.txt"), "text\n")
	tool := newFileCountToolIn(t, root)

	wantLines(t, tool, map[string]any{"include_globs": []any{"*.go"}}, []string{"total: 2"})    // keep.go, skip.go
	wantLines(t, tool, map[string]any{"exclude_globs": []any{"skip.go"}}, []string{"total: 2"}) // keep.go, note.txt
	wantLines(t, tool, map[string]any{"include_globs": []any{"*.go"}, "exclude_globs": []any{"skip.go"}}, []string{"total: 1"})
}

// TestFileCountTool_RecursiveGlobs pins the advertised recursive ** matching for include_globs/exclude_globs,
// applied to each entry's path relative to the counted directory: a root-only "*.go" never crosses a slash so
// it sees one file, while "**/*.go" reaches nested files at any depth, and "**/skip.go" drops a nested match.
func TestFileCountTool_RecursiveGlobs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "top.go"), "package x\n")
	mkdirAll(t, filepath.Join(root, "sub"))
	writeFile(t, filepath.Join(root, "sub", "deep.go"), "package x\n")
	writeFile(t, filepath.Join(root, "sub", "skip.go"), "package x\n")
	tool := newFileCountToolIn(t, root)

	wantLines(t, tool, map[string]any{"include_globs": []any{"*.go"}}, []string{"total: 1"})       // top.go only
	wantLines(t, tool, map[string]any{"include_globs": []any{"**/*.go"}}, []string{"total: 3"})    // top.go, sub/deep.go, sub/skip.go
	wantLines(t, tool, map[string]any{"exclude_globs": []any{"**/skip.go"}}, []string{"total: 2"}) // drops nested sub/skip.go
}

// TestFileCountTool_GroupByExtension pins extension grouping, including the "(none)" no-extension key and the
// "(dir)" directory marker, and the descending-count-then-ascending-key ordering.
func TestFileCountTool_GroupByExtension(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.go"), "package x\n")
	writeFile(t, filepath.Join(root, "b.go"), "package x\n")
	writeFile(t, filepath.Join(root, "c.txt"), "text\n")
	writeFile(t, filepath.Join(root, "README"), "readme\n")
	mkdirAll(t, filepath.Join(root, "sub"))
	writeFile(t, filepath.Join(root, "sub", "d.go"), "package x\n")
	tool := newFileCountToolIn(t, root)

	wantLines(t, tool, map[string]any{"group_by": "extension"},
		[]string{"total: 5", ".go: 3", "(none): 1", ".txt: 1"})
	wantLines(t, tool, map[string]any{"group_by": "extension", "kinds": []any{"file", "dir"}},
		[]string{"total: 6", ".go: 3", "(dir): 1", "(none): 1", ".txt: 1"})
}

// TestFileCountTool_GroupByTopDir pins top-level-directory grouping, with "(root)" for direct children.
func TestFileCountTool_GroupByTopDir(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "top.go"), "package x\n")
	mkdirAll(t, filepath.Join(root, "src"))
	writeFile(t, filepath.Join(root, "src", "a.go"), "package x\n")
	writeFile(t, filepath.Join(root, "src", "b.go"), "package x\n")
	mkdirAll(t, filepath.Join(root, "pkg"))
	writeFile(t, filepath.Join(root, "pkg", "c.go"), "package x\n")
	tool := newFileCountToolIn(t, root)

	wantLines(t, tool, map[string]any{"group_by": "top_dir"},
		[]string{"total: 4", "src: 2", "(root): 1", "pkg: 1"})
}

// TestFileCountTool_GroupByParentDirAndDepth pins parent-directory grouping ("(root)" for direct children)
// and depth grouping (entries directly under the counted directory are depth 1) over the same nested fixture.
func TestFileCountTool_GroupByParentDirAndDepth(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "x.go"), "package x\n")
	mkdirAll(t, filepath.Join(root, "a", "b"))
	writeFile(t, filepath.Join(root, "a", "y.go"), "package x\n")
	writeFile(t, filepath.Join(root, "a", "b", "z.go"), "package x\n")
	tool := newFileCountToolIn(t, root)

	wantLines(t, tool, map[string]any{"group_by": "dir"},
		[]string{"total: 3", "(root): 1", "a: 1", "a/b: 1"})
	wantLines(t, tool, map[string]any{"group_by": "depth"},
		[]string{"total: 3", "1: 1", "2: 1", "3: 1"})
}

// TestFileCountTool_GroupByStem pins stem grouping: files sharing a basename across formats (including a
// nested one) collapse to one key, files with no extension keep their basename, an all-extension basename
// like ".env" keeps its original final segment (empty-trim fallback), and non-file entries counted via kinds
// use their final path segment unchanged (no extension trimming). Ordering stays count-descending then
// key-ascending.
func TestFileCountTool_GroupByStem(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "cat.png"), "img\n")
	writeFile(t, filepath.Join(root, "cat.webp"), "img\n")
	writeFile(t, filepath.Join(root, "dog.png"), "img\n")
	writeFile(t, filepath.Join(root, "README"), "readme\n")
	writeFile(t, filepath.Join(root, ".env"), "SECRET=1\n")
	mkdirAll(t, filepath.Join(root, "nested"))
	writeFile(t, filepath.Join(root, "nested", "cat.json"), "{}\n")
	mkdirAll(t, filepath.Join(root, "photos.bak"))
	if err := os.Symlink(filepath.Join(root, "cat.png"), filepath.Join(root, "asset.link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newFileCountToolIn(t, root)

	// Files only (dotfiles skipped): cat.png/cat.webp/nested/cat.json fold under "cat"; README keeps its basename.
	wantLines(t, tool, map[string]any{"group_by": "stem"},
		[]string{"total: 5", "cat: 3", "README: 1", "dog: 1"})

	// Empty-trim fallback: ".env" trims to "" so its original final segment is kept as the group key.
	wantLines(t, tool, map[string]any{"group_by": "stem", "include_dotfiles": true},
		[]string{"total: 6", "cat: 3", ".env: 1", "README: 1", "dog: 1"})

	// Non-file entries use the final path segment unchanged: "photos.bak" is not trimmed to "photos".
	wantLines(t, tool, map[string]any{"group_by": "stem", "kinds": []any{"dir"}},
		[]string{"total: 2", "nested: 1", "photos.bak: 1"})

	// Symlink entries also keep their dotted final segment: "asset.link" is not trimmed to "asset".
	wantLines(t, tool, map[string]any{"group_by": "stem", "kinds": []any{"symlink"}},
		[]string{"total: 1", "asset.link: 1"})

	// "other" entries (a FIFO) likewise keep their dotted final segment: "pipe.dat" is not trimmed to "pipe".
	if err := syscall.Mkfifo(filepath.Join(root, "pipe.dat"), 0o644); err != nil {
		t.Logf("Mkfifo unsupported on this platform, skipping other-kind stem assertion: %v", err)
	} else {
		wantLines(t, tool, map[string]any{"group_by": "stem", "kinds": []any{"other"}},
			[]string{"total: 1", "pipe.dat: 1"})
	}
}

// TestFileCountTool_GroupLimitTruncation pins that limit caps the visible groups, folds the remainder into
// "other", reports truncation metadata, and keeps the visible counts plus other equal to the total.
func TestFileCountTool_GroupLimitTruncation(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.go", "b.txt", "c.md", "d.json"} {
		writeFile(t, filepath.Join(root, name), "x\n")
	}
	tool := newFileCountToolIn(t, root)

	res, err := invokeFileCount(t, tool, map[string]any{"group_by": "extension", "limit": 2})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	got := fileCountLines(t, res)
	want := []string{"total: 4", ".go: 1", ".json: 1", "other: 2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("limit:2 = %v, want %v", got, want)
	}
	meta := parseMeta(t, res.Stderr)
	if !meta.Truncated || meta.TruncationReason != TruncationReasonLimit {
		t.Fatalf("meta = %+v, want truncated with reason limit", meta)
	}
}

// TestFileCountTool_Dotfiles pins that hidden (dot-prefixed) entries are skipped by default and counted when
// include_dotfiles is set.
func TestFileCountTool_Dotfiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "visible.go"), "package x\n")
	writeFile(t, filepath.Join(root, ".hidden.go"), "package x\n")
	tool := newFileCountToolIn(t, root)

	wantLines(t, tool, map[string]any{}, []string{"total: 1"})
	wantLines(t, tool, map[string]any{"include_dotfiles": true}, []string{"total: 2"})
}

// TestFileCountTool_CodemeldignoreFiltering pins that a codemeldignore-matched entry is skipped by default
// and counted when include_ignored is set.
func TestFileCountTool_CodemeldignoreFiltering(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "keep.go"), "package x\n")
	writeFile(t, filepath.Join(root, "drop.go"), "package x\n")
	mkdirAll(t, filepath.Join(root, ".codemeld"))
	writeFile(t, ProjectCodemeldignorePath(root), "drop.go\n")
	tool := newFileCountToolIn(t, root)

	wantLines(t, tool, map[string]any{}, []string{"total: 1"})
	wantLines(t, tool, map[string]any{"include_ignored": true}, []string{"total: 2"})
}

// TestFileCountTool_EmptyDirectory pins that an empty directory is a success reporting total 0, not an error.
func TestFileCountTool_EmptyDirectory(t *testing.T) {
	root := t.TempDir()
	tool := newFileCountToolIn(t, root)

	res, err := invokeFileCount(t, tool, map[string]any{})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	if got := fileCountLines(t, res); !reflect.DeepEqual(got, []string{"total: 0"}) {
		t.Fatalf("empty dir = %v, want [total: 0]", got)
	}
	if meta := parseMeta(t, res.Stderr); meta.Truncated {
		t.Fatal("meta.Truncated = true for a non-truncated count, want false")
	}
}

// TestFileCountTool_ExplicitRootEqualsDefault pins that every spelling of the project root yields the same
// result as an omitted path.
func TestFileCountTool_ExplicitRootEqualsDefault(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.go"), "package x\n")
	writeFile(t, filepath.Join(root, "b.go"), "package x\n")
	tool := newFileCountToolIn(t, root)

	assertExplicitRootEqualsDefault(t, func(a map[string]any) (tools.Result, error) { return invokeFileCount(t, tool, a) }, fileCountLines, root, nil)
}

// TestFileCountTool_ArgumentValidation pins in-band rejection of unknown args (including the include_hidden
// alias), wrong-type/out-of-range numerics, malformed kinds/group_by, and malformed/wrong-type glob lists.
func TestFileCountTool_ArgumentValidation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.go"), "package x\n")
	tool := newFileCountToolIn(t, root)

	assertArgRejections(t, func(a map[string]any) (tools.Result, error) { return invokeFileCount(t, tool, a) }, []argRejectionCase{
		{"unknown arg", map[string]any{"bogus": 1}, "unexpected argument"},
		{"include_hidden rejected", map[string]any{"include_hidden": true}, "unexpected argument"},
		{"path wrong type", map[string]any{"path": 5}, "must be a string"},
		{"limit zero", map[string]any{"limit": 0}, "limit must be >= 1"},
		{"limit over max", map[string]any{"limit": FileCountMaxLimit + 1}, "maximum of " + strconv.Itoa(FileCountMaxLimit)},
		{"limit wrong type", map[string]any{"limit": "ten"}, "must be an integer"},
		{"limit fractional", map[string]any{"limit": 1.5}, "must be an integer"},
		{"include_dotfiles wrong type", map[string]any{"include_dotfiles": "yes"}, "must be a boolean"},
		{"include_ignored wrong type", map[string]any{"include_ignored": 1}, "must be a boolean"},
		{"group_by unrecognized", map[string]any{"group_by": "size"}, "stem"},
		{"group_by wrong type", map[string]any{"group_by": 7}, "must be a string"},
		{"kinds wrong type", map[string]any{"kinds": "file"}, "must be an array of strings"},
		{"kinds empty", map[string]any{"kinds": []any{}}, "at least one kind"},
		{"kinds member wrong type", map[string]any{"kinds": []any{1}}, "must be a string"},
		{"kinds bad value", map[string]any{"kinds": []any{"folder"}}, "must be one of"},
		{"include_globs wrong type", map[string]any{"include_globs": "*.go"}, "must be an array of strings"},
		{"include_globs member wrong type", map[string]any{"include_globs": []any{1}}, "must be a string"},
		{"include_globs malformed", map[string]any{"include_globs": []any{"["}}, "malformed glob pattern"},
		{"include_globs empty member", map[string]any{"include_globs": []any{""}}, "empty pattern"},
		{"exclude_globs wrong type", map[string]any{"exclude_globs": "*.go"}, "must be an array of strings"},
		{"exclude_globs member wrong type", map[string]any{"exclude_globs": []any{1}}, "must be a string"},
		{"exclude_globs malformed", map[string]any{"exclude_globs": []any{"["}}, "malformed glob pattern"},
		{"exclude_globs empty member", map[string]any{"exclude_globs": []any{""}}, "empty pattern"},
	})
}

// TestFileCountTool_ContainmentRejections pins that a path escaping the root (an in-root symlink to outside,
// an absolute outside path, ../ traversal) is rejected fail-closed with no out-of-root content leaked.
func TestFileCountTool_ContainmentRejections(t *testing.T) {
	root := t.TempDir()
	outsideDir := t.TempDir()
	writeFile(t, filepath.Join(outsideDir, "secret.go"), "package secret\n")
	if err := os.Symlink(outsideDir, filepath.Join(root, "escape")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newFileCountToolIn(t, root)

	assertContainmentRejections(t, func(p string) (tools.Result, error) { return invokeFileCount(t, tool, map[string]any{"path": p}) },
		"secret", []pathCase{
			{"symlink escape dir", "escape"},
			{"absolute outside", outsideDir},
			{"dotdot traversal", "../" + filepath.Base(outsideDir)},
		})
}

// TestFileCountTool_DirectorySymlinkPathRejected pins that, as a recursive tool, file_count refuses a
// directory-symlink `path` fail-closed before any walk so a count cannot be redirected through it.
func TestFileCountTool_DirectorySymlinkPathRejected(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "realdir"))
	writeFile(t, filepath.Join(root, "realdir", "a.go"), "package realdir\n")
	if err := os.Symlink(filepath.Join(root, "realdir"), filepath.Join(root, "linkdir")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newFileCountToolIn(t, root)

	res, err := invokeFileCount(t, tool, map[string]any{"path": "linkdir"})
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil (in-band rejection)", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("ExitCode = 0, want a fail-closed rejection of a directory-symlink path (stdout=%q)", res.Stdout)
	}
	if !strings.Contains(string(res.Stderr), "symlink") {
		t.Fatalf("Stderr = %q, want it to name the symlink rejection", res.Stderr)
	}
}

// TestFileCountTool_StandaloneExternalReadRefused pins that the standalone (non-dispatch) path refuses an
// explicit out-of-project directory in-band, since only the dispatch path can obtain approval.
func TestFileCountTool_StandaloneExternalReadRefused(t *testing.T) {
	root := t.TempDir()
	outsideDir := t.TempDir()
	writeFile(t, filepath.Join(outsideDir, "secret.go"), "package secret\n")
	tool := newFileCountToolIn(t, root)

	res, err := invokeFileCount(t, tool, map[string]any{"path": outsideDir})
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil (in-band refusal)", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("ExitCode = 0, want a dispatch-only refusal (stdout=%q)", res.Stdout)
	}
	if !strings.Contains(string(res.Stderr), "dispatch") {
		t.Fatalf("Stderr = %q, want it to name the dispatch-only refusal", res.Stderr)
	}
	if strings.Contains(string(res.Stdout), "secret") {
		t.Fatalf("Stdout leaked out-of-root content: %q", res.Stdout)
	}
}

// TestFileCountTool_ResolvedRootSwappedToSymlinkRejected pins the reuse-at-invoke revalidation: if the
// authorized directory is swapped for a symlink to an outside directory between resolution and invocation,
// file_count rejects the now-symlink root in-band rather than letting Walk follow it out of the project.
func TestFileCountTool_ResolvedRootSwappedToSymlinkRejected(t *testing.T) {
	assertResolvedRootSwapRejected(t, func(root string) readNavTool { return newFileCountToolIn(t, root) }, nil, "package secret\n")
}
