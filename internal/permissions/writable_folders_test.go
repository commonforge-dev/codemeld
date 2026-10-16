package permissions

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

type writableFixture struct {
	root, home, project string
}

func newWritableFixture(t *testing.T) writableFixture {
	t.Helper()
	root := blockedTempDir(t)
	f := writableFixture{root: root, home: filepath.Join(root, "home"), project: filepath.Join(root, "project")}
	mkdirs(t,
		filepath.Join(f.home, "w"),
		filepath.Join(f.home, ".codemeld", "x"),
		filepath.Join(f.project, "src"),
		filepath.Join(f.project, ".codemeld", "sub"),
		filepath.Join(f.project, ".codemeldx"),
	)
	if err := os.WriteFile(filepath.Join(root, "file"), nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	for link, target := range map[string]string{
		"to-project-codemeld": filepath.Join(f.project, ".codemeld"),
		"to-w":                filepath.Join(f.home, "w"),
	} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	return f
}

func assertWritableNotices(t *testing.T, notices []string, want []string) {
	t.Helper()
	if len(notices) != len(want) {
		t.Fatalf("notices = %q, want %d containing %q", notices, len(want), want)
	}
	for i, notice := range notices {
		if !strings.HasPrefix(notice, "writable_folders: entry ") {
			t.Fatalf("notice %q lacks the writable_folders entry prefix", notice)
		}
		if !strings.Contains(notice, want[i]) {
			t.Fatalf("notice %q missing %q", notice, want[i])
		}
	}
}

func TestParseWritableFolders_Entries(t *testing.T) {
	f := newWritableFixture(t)
	homeFloor := "codemeld's protected home folder"
	projectFloor := "project's protected codemeld folder"
	impact := ": confined Auto commands and in-process edits may write under the home directory, except protected and blocked paths"
	fsRoot := filepath.VolumeName(f.root) + string(filepath.Separator)
	backslash := struct {
		folders []string
		notices []string
	}{nil, []string{`"~\\w": must be an absolute path or start with ~/`}}
	if runtime.GOOS == "windows" {
		backslash.folders, backslash.notices = []string{filepath.Join(f.home, "w")}, nil
	}

	tests := []struct {
		name    string
		entries []any
		folders []string
		notices []string
	}{
		{"tilde expands under the supplied home", []any{"~/w"}, []string{filepath.Join(f.home, "w")}, nil},
		{"relative", []any{"rel/path"}, nil, []string{`"rel/path": must be an absolute path`}},
		{"other user's home", []any{"~user/x"}, nil, []string{`"~user/x": must be an absolute path`}},
		{"filesystem root", []any{fsRoot}, nil, []string{fmt.Sprintf("%q: the filesystem root", fsRoot)}},
		{"missing", []any{filepath.Join(f.root, "missing")}, nil, []string{"does not exist"}},
		{"regular file", []any{filepath.Join(f.root, "file")}, nil, []string{"not a directory"}},
		{"home floor", []any{"~/.codemeld"}, nil, []string{`"~/.codemeld": inside ` + homeFloor}},
		{"inside home floor", []any{"~/.codemeld/x"}, nil, []string{`"~/.codemeld/x": inside ` + homeFloor}},
		{"home", []any{f.home}, []string{f.home}, []string{fmt.Sprintf("%q", f.home) + impact}},
		{"home's parent", []any{f.root}, []string{f.root}, []string{fmt.Sprintf("%q", f.root) + impact}},
		{"project floor", []any{filepath.Join(f.project, ".codemeld")}, nil, []string{projectFloor}},
		{"inside project floor", []any{filepath.Join(f.project, ".codemeld", "sub")}, nil, []string{projectFloor}},
		{"symlink to project floor", []any{filepath.Join(f.root, "to-project-codemeld")}, nil, []string{`to-project-codemeld": inside the ` + projectFloor}},
		{"project subfolder", []any{filepath.Join(f.project, "src")}, []string{filepath.Join(f.project, "src")}, nil},
		{"floor-prefixed sibling", []any{filepath.Join(f.project, ".codemeldx")}, []string{filepath.Join(f.project, ".codemeldx")}, nil},
		{"two spellings collapse to the first", []any{filepath.Join(f.home, "w"), filepath.Join(f.root, "to-w"), "~/w"}, []string{filepath.Join(f.home, "w")}, nil},
		{"backslash tilde", []any{`~\w`}, backslash.folders, backslash.notices},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			folders, notices, err := ParseWritableFolders(tt.entries, f.home, f.project)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if !slices.Equal(folders, tt.folders) {
				t.Fatalf("folders = %q, want %q", folders, tt.folders)
			}
			assertWritableNotices(t, notices, tt.notices)
		})
	}
}

func TestParseWritableFolders_RootRejectedWhenHomeIsBelowIt(t *testing.T) {
	root := filepath.VolumeName(os.TempDir()) + string(filepath.Separator)
	for _, entry := range []string{root, "~/.."} {
		folders, notices, err := ParseWritableFolders([]any{entry}, filepath.Join(root, "h"), filepath.Join(root, "p"))
		if err != nil || folders != nil {
			t.Fatalf("%q: folders = %q, err = %v; want a rejection", entry, folders, err)
		}
		assertWritableNotices(t, notices, []string{"the filesystem root"})
	}
}

func TestParseWritableFolders_EmptyAndMalformed(t *testing.T) {
	for _, raw := range []any{nil, []any{}} {
		folders, notices, err := ParseWritableFolders(raw, "/h", "/p")
		if folders != nil || notices != nil || err != nil {
			t.Fatalf("%#v: folders = %q, notices = %q, err = %v; want nothing", raw, folders, notices, err)
		}
	}
	for _, raw := range []any{"/data/x", []any{"/data/x", 3}} {
		if _, _, err := ParseWritableFolders(raw, "/h", "/p"); err == nil {
			t.Fatalf("%#v: err = nil, want a shape error", raw)
		}
	}
}

func TestParseWritableFolders_CaseRule(t *testing.T) {
	f := newWritableFixture(t)
	work, upperWork := filepath.Join(f.root, "work"), filepath.Join(f.root, "Work")
	upperFloor := filepath.Join(f.project, ".CODEMELD")
	mkdirs(t, work)
	_, err := os.Stat(upperWork)
	caseSensitive := err != nil
	if caseSensitive {
		mkdirs(t, upperWork, upperFloor)
	}
	firstResolved, err := filepath.EvalSymlinks(upperWork)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}

	folders, notices, _ := parseWritableFolders([]any{upperFloor}, f.home, f.project, true)
	if folders != nil {
		t.Fatalf("folding: folders = %q, want the floor case variant rejected", folders)
	}
	assertWritableNotices(t, notices, []string{"project's protected codemeld folder"})
	folders, _, _ = parseWritableFolders([]any{upperWork, work}, f.home, f.project, true)
	if !slices.Equal(folders, []string{firstResolved}) {
		t.Fatalf("folding: folders = %q, want the first spelling %q only", folders, firstResolved)
	}

	if !caseSensitive {
		return
	}
	folders, notices, _ = parseWritableFolders([]any{upperFloor}, f.home, f.project, false)
	if !slices.Equal(folders, []string{upperFloor}) || notices != nil {
		t.Fatalf("exact: folders = %q, notices = %q; want the case variant accepted", folders, notices)
	}
	folders, _, _ = parseWritableFolders([]any{upperWork, work}, f.home, f.project, false)
	if !slices.Equal(folders, []string{upperWork, work}) {
		t.Fatalf("exact: folders = %q, want both case variants", folders)
	}
}
