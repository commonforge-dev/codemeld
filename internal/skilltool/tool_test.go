package skilltool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/skills"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/vcs"
)

const limit = 4096

func realDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return dir
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
}

func globalRoot(home string) string { return filepath.Join(home, ".codemeld", "skills") }

func projectRoot(project string) string { return filepath.Join(project, ".codemeld", "skills") }

func writeSkill(t *testing.T, root, name, body string, disabled bool) string {
	t.Helper()
	folder := filepath.Join(root, name)
	header := "---\nname: " + name + "\ndescription: does " + name + "\n"
	if disabled {
		header += "disable-model-invocation: true\n"
	}
	write(t, filepath.Join(folder, "SKILL.md"), header+"---\n"+body)
	return folder
}

func load(t *testing.T, home, project string) []skills.Skill {
	t.Helper()
	set := skills.Load(home, project, nil, limit)
	if len(set.Skipped) > 0 {
		t.Fatalf("skills.Load skipped %+v", set.Skipped)
	}
	return set.Loaded
}

func invoke(t *testing.T, tool *Tool, args map[string]any) tools.Result {
	t.Helper()
	res, err := tool.Invoke(context.Background(), args)
	if err != nil {
		t.Fatalf("Invoke(%v) error = %v, want nil", args, err)
	}
	return res
}

func wantFailed(t *testing.T, res tools.Result, contains string) {
	t.Helper()
	if res.ExitCode != 1 || len(res.Stdout) != 0 || !strings.Contains(string(res.Stderr), contains) {
		t.Fatalf("result = exit %d stdout %q stderr %q, want a failed result naming %q", res.ExitCode, res.Stdout, res.Stderr, contains)
	}
}

func readOK(t *testing.T, tool *Tool, name, file, want string) {
	t.Helper()
	res := invoke(t, tool, map[string]any{"name": name, "file": file})
	if res.ExitCode != 0 || string(res.Stdout) != want {
		t.Fatalf("read %s = exit %d stdout %q stderr %q, want %q", file, res.ExitCode, res.Stdout, res.Stderr, want)
	}
}

func wantRefusal(t *testing.T, tool *Tool, name, file, entry, source string) {
	t.Helper()
	res, err := tool.Invoke(context.Background(), map[string]any{"name": name, "file": file})
	var refusal *securitystate.Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("read %s = (%+v, %v), want a blocked-path refusal", file, res, err)
	}
	if refusal.Source != "blocked_path" || refusal.Entry != entry || refusal.EntrySource != source || refusal.Subject != "skill" {
		t.Fatalf("refusal = %+v, want blocked_path for entry %s from %s", refusal, entry, source)
	}
}

func body(t *testing.T, tool *Tool, name string) string {
	t.Helper()
	res := invoke(t, tool, map[string]any{"name": name})
	if res.ExitCode != 0 {
		t.Fatalf("body of %s = exit %d stderr %q, want success", name, res.ExitCode, res.Stderr)
	}
	return string(res.Stdout)
}

func header(folder, text string) string {
	return "Skill folder: " + folder + "\nRelative paths in this skill are relative to that folder.\n\n" + text + "\n\n"
}

func TestBodyFolderAndRecursiveFileList(t *testing.T) {
	home, project := realDir(t), realDir(t)
	folder := writeSkill(t, globalRoot(home), "deploy", "Run scripts/run.sh.\n", false)
	write(t, filepath.Join(folder, "scripts", "run.sh"), "echo hi\n")
	write(t, filepath.Join(folder, "b.md"), "b")
	write(t, filepath.Join(folder, "a", "deep", "SKILL.md"), "nested")
	if err := os.MkdirAll(filepath.Join(folder, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(folder, "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}
	tool := New(load(t, home, project), limit, home, project, permissions.NewBlockedPaths(home, nil), nil)

	want := header(folder, "Run scripts/run.sh.") +
		"Other files in the skill folder (read one with the file argument):\n- a/deep/SKILL.md\n- b.md\n- scripts/run.sh\n"
	if got := body(t, tool, "deploy"); got != want {
		t.Fatalf("body =\n%s\nwant\n%s", got, want)
	}
}

func TestAbsoluteInRootFolderLinkIsReadable(t *testing.T) {
	home, project := realDir(t), realDir(t)
	target := writeSkill(t, filepath.Join(globalRoot(home), "vault"), "linked", "body\n", false)
	write(t, filepath.Join(target, "f.txt"), "F")
	folder := filepath.Join(globalRoot(home), "linked")
	symlink(t, target, folder)
	tool := New(load(t, home, project), limit, home, project, permissions.NewBlockedPaths(home, nil), nil)

	readOK(t, tool, "linked", "f.txt", "F")
	want := header(folder, "body") + "Other files in the skill folder (read one with the file argument):\n- f.txt\n"
	if got := body(t, tool, "linked"); got != want {
		t.Fatalf("body =\n%s\nwant\n%s", got, want)
	}
}

func TestDisabledSkillRefusesBodyButReadsFiles(t *testing.T) {
	home, project := realDir(t), realDir(t)
	folder := writeSkill(t, globalRoot(home), "release", "secret steps\n", true)
	write(t, filepath.Join(folder, "notes.txt"), "notes")
	tool := New(load(t, home, project), limit, home, project, permissions.NewBlockedPaths(home, nil), nil)

	res := invoke(t, tool, map[string]any{"name": "release"})
	wantFailed(t, res, "/release in the TUI")
	if text := string(res.Stderr); !strings.Contains(text, "not available in codemeld run") || strings.Contains(text, "secret steps") || strings.Contains(text, "notes.txt") || strings.Contains(text, folder) {
		t.Fatalf("refusal %q must say slash commands are TUI-only and carry no body, folder or file list", text)
	}
	readOK(t, tool, "release", "notes.txt", "notes")
}

func TestFileListStopsAt200Sorted(t *testing.T) {
	home, project := realDir(t), realDir(t)
	folder := writeSkill(t, globalRoot(home), "many", "body\n", false)
	for i := range 205 {
		write(t, filepath.Join(folder, fmt.Sprintf("f%03d", 204-i)), "x")
	}
	tool := New(load(t, home, project), limit, home, project, permissions.NewBlockedPaths(home, nil), nil)

	var list strings.Builder
	for i := range 200 {
		fmt.Fprintf(&list, "- f%03d\n", i)
	}
	want := header(folder, "body") + "Other files in the skill folder (read one with the file argument):\n" + list.String() + "5 more files not listed.\n"
	if got := body(t, tool, "many"); got != want {
		t.Fatalf("body =\n%s\nwant\n%s", got, want)
	}
}

func TestFileListOmitsBlockedEscapingAndCycles(t *testing.T) {
	home, project, outside := realDir(t), realDir(t), realDir(t)
	folder := writeSkill(t, globalRoot(home), "tidy", "body\n", false)
	write(t, filepath.Join(folder, "keep.txt"), "k")
	write(t, filepath.Join(folder, "secret", "key.txt"), "SECRET")
	symlink(t, filepath.Join(folder, "secret", "key.txt"), filepath.Join(folder, "alias.txt"))
	write(t, filepath.Join(outside, "out.txt"), "OUT")
	symlink(t, filepath.Join(outside, "out.txt"), filepath.Join(folder, "out.txt"))
	symlink(t, "..", filepath.Join(folder, "sub", "loop"))
	write(t, filepath.Join(folder, "sub", "inner.txt"), "i")
	blocked := permissions.NewBlockedPaths(home, []permissions.BlockedEntry{{Path: filepath.Join(folder, "secret"), Source: "/settings.yaml"}})
	tool := New(load(t, home, project), limit, home, project, blocked, nil)

	want := header(folder, "body") +
		"Other files in the skill folder (read one with the file argument):\n- keep.txt\n- sub/inner.txt\n" +
		"Left out: 2 blocked by blocked_paths, 1 unreadable or leading outside the skill folder, 1 folder links that loop back.\n"
	done := make(chan string, 1)
	go func() { done <- body(t, tool, "tidy") }()
	select {
	case got := <-done:
		if got != want {
			t.Fatalf("body =\n%s\nwant\n%s", got, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("enumeration did not terminate on a folder link cycle")
	}
}

func TestUnavailableListReturnsCachedBody(t *testing.T) {
	cases := []struct {
		name    string
		blocked func(home, project, folder string) *permissions.BlockedPaths
		mutate  func(t *testing.T, home string)
		note    string
	}{
		{name: "nil snapshot", blocked: func(string, string, string) *permissions.BlockedPaths { return nil }, note: listUnknownMessage},
		{
			name: "blocked folder",
			blocked: func(home, _, folder string) *permissions.BlockedPaths {
				return permissions.NewBlockedPaths(home, []permissions.BlockedEntry{{Path: folder, Source: "/s.yaml"}})
			},
			note: "the skill folder is blocked by a blocked_paths entry",
		},
		{
			name: "degraded outside the project",
			blocked: func(home, project, _ string) *permissions.BlockedPaths {
				return permissions.NewLiveBlockedPaths(home, project, nil, func() permissions.BlockedReload {
					return permissions.BlockedReload{Problems: map[string]string{"/s.yaml": "is broken"}}
				})
			},
			note: listBrokenMessage,
		},
		{
			name:    "folder swapped outside the skills root",
			blocked: func(home, _, _ string) *permissions.BlockedPaths { return permissions.NewBlockedPaths(home, nil) },
			mutate: func(t *testing.T, home string) {
				folder := filepath.Join(globalRoot(home), "cached")
				if err := os.RemoveAll(folder); err != nil {
					t.Fatal(err)
				}
				outside := realDir(t)
				write(t, filepath.Join(outside, "leak.txt"), "LEAK")
				symlink(t, outside, folder)
			},
			note: "is missing or leads outside",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, project := realDir(t), realDir(t)
			folder := writeSkill(t, globalRoot(home), "cached", "cached body\n", false)
			write(t, filepath.Join(folder, "live.txt"), "LIVE")
			tool := New(load(t, home, project), limit, home, project, tc.blocked(home, project, folder), nil)
			if tc.mutate != nil {
				tc.mutate(t, home)
			}
			got := body(t, tool, "cached")
			if !strings.HasPrefix(got, header(folder, "cached body")+"File list unavailable: ") || !strings.Contains(got, tc.note) || strings.Contains(got, "live.txt") || strings.Contains(got, "leak.txt") {
				t.Fatalf("body =\n%s\nwant the cached body with the note %q and no live names", got, tc.note)
			}
		})
	}
}

func TestAdversarialFileArguments(t *testing.T) {
	home, project, outside := realDir(t), realDir(t), realDir(t)
	folder := writeSkill(t, globalRoot(home), "safe", "body\n", false)
	write(t, filepath.Join(globalRoot(home), "x"), "SIBLING")
	write(t, filepath.Join(home, ".codemeld", "settings.yaml"), "STATE")
	write(t, filepath.Join(outside, "out.txt"), "OUTSIDE")
	symlink(t, filepath.Join(outside, "out.txt"), filepath.Join(folder, "out"))
	symlink(t, filepath.Join(home, ".codemeld", "settings.yaml"), filepath.Join(folder, "state"))
	write(t, filepath.Join(folder, "secret.txt"), "BLOCKED")
	symlink(t, filepath.Join(folder, "secret.txt"), filepath.Join(folder, "to-blocked"))
	if err := syscall.Mkfifo(filepath.Join(folder, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(folder, "big"), strings.Repeat("B", 65))
	blocked := permissions.NewBlockedPaths(home, []permissions.BlockedEntry{{Path: filepath.Join(folder, "secret.txt"), Source: "/s.yaml"}})
	tool := New(load(t, home, project), 64, home, project, blocked, nil)

	for _, file := range []string{"../x", "/etc/passwd", "a/../../x", "out", "state", "to-blocked", "secret.txt", "fifo", "big", "%2e%2e/x", "..%2fx", `..\x`, "."} {
		t.Run(file, func(t *testing.T) {
			done := make(chan struct{})
			var res tools.Result
			var err error
			go func() {
				defer close(done)
				res, err = tool.Invoke(context.Background(), map[string]any{"name": "safe", "file": file})
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("read did not return")
			}
			var refusal *securitystate.Refusal
			if errors.As(err, &refusal) {
				return
			}
			if err != nil || res.ExitCode != 1 || len(res.Stdout) != 0 {
				t.Fatalf("read %q = (exit %d stdout %q, %v), want a refusal", file, res.ExitCode, res.Stdout, err)
			}
		})
	}
	wantRefusal(t, tool, "safe", "to-blocked", filepath.Join(folder, "secret.txt"), "/s.yaml")
	wantFailed(t, invoke(t, tool, map[string]any{"name": "safe", "file": "big"}), "over the 64-byte limit")
}

func TestReplacementBetweenStatAndOpenIsRefused(t *testing.T) {
	home, project := realDir(t), realDir(t)
	folder := writeSkill(t, globalRoot(home), "race", "body\n", false)
	target := filepath.Join(folder, "data.txt")
	write(t, target, "data")
	tool := New(load(t, home, project), limit, home, project, permissions.NewBlockedPaths(home, nil), nil)

	t.Run("fifo", func(t *testing.T) {
		defer swap(&openFile, func(r *os.Root, name string, flag int, perm os.FileMode) (*os.File, error) {
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(target, 0o644); err != nil {
				t.Fatal(err)
			}
			return r.OpenFile(name, flag, perm)
		})()
		done := make(chan tools.Result, 1)
		go func() { done <- invoke(t, tool, map[string]any{"name": "race", "file": "data.txt"}) }()
		select {
		case res := <-done:
			wantFailed(t, res, "is not a regular file")
		case <-time.After(10 * time.Second):
			t.Fatal("FIFO read stalled without a writer")
		}
	})

	t.Run("growing", func(t *testing.T) {
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		write(t, target, "data")
		original := readLimited
		defer swap(&readLimited, func(f *os.File, n int64) ([]byte, error) {
			write(t, target, "data plus more")
			return original(f, n)
		})()
		wantFailed(t, invoke(t, tool, map[string]any{"name": "race", "file": "data.txt"}), "changed while it was being read")
	})
}

func TestListingFolderReplacedByFIFOIsOmitted(t *testing.T) {
	home, project := realDir(t), realDir(t)
	folder := writeSkill(t, globalRoot(home), "race", "body\n", false)
	write(t, filepath.Join(folder, "keep.txt"), "k")
	write(t, filepath.Join(folder, "sub", "inner.txt"), "i")
	tool := New(load(t, home, project), limit, home, project, permissions.NewBlockedPaths(home, nil), nil)
	defer swap(&openFile, func(r *os.Root, name string, flag int, perm os.FileMode) (*os.File, error) {
		if name == "sub" {
			if err := os.RemoveAll(filepath.Join(folder, "sub")); err != nil {
				t.Error(err)
			}
			if err := syscall.Mkfifo(filepath.Join(folder, "sub"), 0o644); err != nil {
				t.Error(err)
			}
		}
		return r.OpenFile(name, flag, perm)
	})()

	want := header(folder, "body") +
		"Other files in the skill folder (read one with the file argument):\n- keep.txt\n" +
		"Left out: 1 unreadable or leading outside the skill folder.\n"
	done := make(chan string, 1)
	go func() { done <- body(t, tool, "race") }()
	select {
	case got := <-done:
		if got != want {
			t.Fatalf("body =\n%s\nwant\n%s", got, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("enumeration stalled on a FIFO without a writer")
	}
}

func TestListingUnreadableFolderIsNotEmpty(t *testing.T) {
	home, project := realDir(t), realDir(t)
	folder := writeSkill(t, globalRoot(home), "plain", "body\n", false)
	tool := New(load(t, home, project), limit, home, project, permissions.NewBlockedPaths(home, nil), nil)

	if got, want := body(t, tool, "plain"), header(folder, "body")+"The skill folder has no other files.\n"; got != want {
		t.Fatalf("empty folder body =\n%s\nwant\n%s", got, want)
	}
	defer swap(&openFile, func(r *os.Root, name string, flag int, perm os.FileMode) (*os.File, error) {
		if name == "." {
			return nil, syscall.EACCES
		}
		return r.OpenFile(name, flag, perm)
	})()
	if got, want := body(t, tool, "plain"), header(folder, "body")+"File list unavailable: the skill folder could not be read.\n"; got != want {
		t.Fatalf("unreadable folder body =\n%s\nwant\n%s", got, want)
	}
}

func swap[T any](p *T, v T) func() {
	old := *p
	*p = v
	return func() { *p = old }
}

type liveList struct {
	mu       sync.Mutex
	entries  []permissions.BlockedEntry
	problems map[string]string
}

func (l *liveList) set(entries []permissions.BlockedEntry, problems map[string]string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries, l.problems = entries, problems
}

func (l *liveList) reload() permissions.BlockedReload {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.problems) > 0 {
		return permissions.BlockedReload{Problems: l.problems}
	}
	return permissions.BlockedReload{Changed: true, Entries: l.entries}
}

func TestConfiguredBlocksFollowTheLiveList(t *testing.T) {
	home, project := realDir(t), realDir(t)
	folder := writeSkill(t, globalRoot(home), "live", "body\n", false)
	write(t, filepath.Join(folder, "scripts", "run.sh"), "run")
	write(t, filepath.Join(folder, "open.txt"), "open")
	list := &liveList{}
	tool := New(load(t, home, project), limit, home, project, permissions.NewLiveBlockedPaths(home, project, nil, list.reload), nil)
	scripts := filepath.Join(folder, "scripts")
	listed := header(folder, "body") + "Other files in the skill folder (read one with the file argument):\n- open.txt\n- scripts/run.sh\n"

	readOK(t, tool, "live", "scripts/run.sh", "run")
	if got := body(t, tool, "live"); got != listed {
		t.Fatalf("unblocked body =\n%s\nwant\n%s", got, listed)
	}

	list.set([]permissions.BlockedEntry{{Path: scripts, Source: "/g.yaml"}}, nil)
	wantRefusal(t, tool, "live", "scripts/run.sh", scripts, "/g.yaml")
	readOK(t, tool, "live", "open.txt", "open")
	want := header(folder, "body") + "Other files in the skill folder (read one with the file argument):\n- open.txt\nLeft out: 1 blocked by blocked_paths.\n"
	if got := body(t, tool, "live"); got != want {
		t.Fatalf("blocked body =\n%s\nwant\n%s", got, want)
	}

	list.set(nil, nil)
	readOK(t, tool, "live", "scripts/run.sh", "run")
	if got := body(t, tool, "live"); got != listed {
		t.Fatalf("unblocked-again body =\n%s\nwant\n%s", got, listed)
	}
}

func TestDegradedListRefusesOutsideProjectAndKeepsLastValidBlocks(t *testing.T) {
	project := realDir(t)
	home := filepath.Join(project, "home")
	outside := realDir(t)
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := writeSkill(t, globalRoot(home), "inside", "in\n", false)
	write(t, filepath.Join(inside, "a.txt"), "A")
	redirected := filepath.Join(outside, "skills")
	symlink(t, redirected, projectRoot(project))
	far := writeSkill(t, redirected, "far", "far\n", false)
	write(t, filepath.Join(far, "f.txt"), "F")
	write(t, filepath.Join(far, "kept-secret.txt"), "S")

	otherHome := realDir(t)
	global := writeSkill(t, globalRoot(otherHome), "global", "g\n", false)
	write(t, filepath.Join(global, "g.txt"), "G")

	secret := filepath.Join(far, "kept-secret.txt")
	list := &liveList{entries: []permissions.BlockedEntry{{Path: secret, Source: "/g.yaml"}}}
	homeTool := New(load(t, home, project), limit, home, project, permissions.NewLiveBlockedPaths(home, project, nil, list.reload), nil)
	otherTool := New(load(t, otherHome, realDir(t)), limit, otherHome, project, permissions.NewLiveBlockedPaths(otherHome, project, nil, list.reload), nil)

	healthy := func() {
		readOK(t, otherTool, "global", "g.txt", "G")
		readOK(t, homeTool, "far", "f.txt", "F")
		readOK(t, homeTool, "inside", "a.txt", "A")
		wantRefusal(t, homeTool, "far", "kept-secret.txt", secret, "/g.yaml")
	}
	healthy()

	list.set(list.entries, map[string]string{"/g.yaml": "is broken"})
	wantFailed(t, invoke(t, otherTool, map[string]any{"name": "global", "file": "g.txt"}), listBrokenMessage)
	wantFailed(t, invoke(t, homeTool, map[string]any{"name": "far", "file": "f.txt"}), listBrokenMessage)
	wantRefusal(t, homeTool, "far", "kept-secret.txt", secret, "/g.yaml")
	readOK(t, homeTool, "inside", "a.txt", "A")
	if got := body(t, otherTool, "global"); !strings.Contains(got, "File list unavailable: "+listBrokenMessage) || strings.Contains(got, "g.txt") {
		t.Fatalf("degraded body = %q, want the cached body with the broken-list note", got)
	}

	list.set(list.entries, nil)
	healthy()

	nilTool := New(load(t, otherHome, realDir(t)), limit, otherHome, project, nil, nil)
	wantFailed(t, invoke(t, nilTool, map[string]any{"name": "global", "file": "g.txt"}), listUnknownMessage)
}

func TestSwappedRootsAndFoldersAreRefused(t *testing.T) {
	setup := func(t *testing.T) (string, string, *Tool) {
		home, project := realDir(t), realDir(t)
		folder := writeSkill(t, projectRoot(project), "proj", "body\n", false)
		write(t, filepath.Join(folder, "f.txt"), "F")
		return home, project, New(load(t, home, project), limit, home, project, permissions.NewBlockedPaths(home, nil), nil)
	}
	replaceWithStateCopy := func(t *testing.T, dir string, state string) {
		t.Helper()
		if err := os.Rename(dir, dir+".old"); err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(state, "proj", "f.txt"), "STATE")
		write(t, filepath.Join(state, "f.txt"), "STATE")
		symlink(t, state, dir)
	}
	assertRefused := func(t *testing.T, tool *Tool) {
		t.Helper()
		res := invoke(t, tool, map[string]any{"name": "proj", "file": "f.txt"})
		if res.ExitCode != 1 || strings.Contains(string(res.Stdout), "STATE") {
			t.Fatalf("read = exit %d stdout %q, want a refusal before reading", res.ExitCode, res.Stdout)
		}
		if got := body(t, tool, "proj"); !strings.Contains(got, "File list unavailable: ") || strings.Contains(got, "f.txt") {
			t.Fatalf("body = %q, want no live list", got)
		}
	}

	t.Run("root fails RootAllowed", func(t *testing.T) {
		home, project, tool := setup(t)
		replaceWithStateCopy(t, projectRoot(project), filepath.Join(home, ".codemeld", "sessions"))
		assertRefused(t, tool)
	})
	t.Run("folder redirected outside its root", func(t *testing.T) {
		_, project, tool := setup(t)
		replaceWithStateCopy(t, filepath.Join(projectRoot(project), "proj"), realDir(t))
		assertRefused(t, tool)
	})
	t.Run("root replaced before acquisition", func(t *testing.T) {
		_, project, tool := setup(t)
		root := projectRoot(project)
		original := openRoot
		defer swap(&openRoot, func(name string) (*os.Root, error) {
			if err := os.Rename(root, root+".old"); err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(root, "proj", "f.txt"), "STATE")
			return original(name)
		})()
		res := invoke(t, tool, map[string]any{"name": "proj", "file": "f.txt"})
		wantFailed(t, res, "changed while it was being opened")
	})
	t.Run("folder replaced before acquisition", func(t *testing.T) {
		_, project, tool := setup(t)
		folder := filepath.Join(projectRoot(project), "proj")
		original := openFolder
		defer swap(&openFolder, func(r *os.Root, name string) (*os.Root, error) {
			if err := os.Rename(folder, folder+".old"); err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(folder, "f.txt"), "STATE")
			return original(r, name)
		})()
		res := invoke(t, tool, map[string]any{"name": "proj", "file": "f.txt"})
		wantFailed(t, res, "changed while it was being opened")
	})
}

func TestBodyIsTheStartupSnapshotAndFilesAreLive(t *testing.T) {
	home, project := realDir(t), realDir(t)
	folder := writeSkill(t, globalRoot(home), "snap", "original body\n", false)
	write(t, filepath.Join(folder, "extra.txt"), "first")
	tool := New(load(t, home, project), limit, home, project, permissions.NewBlockedPaths(home, nil), nil)

	write(t, filepath.Join(folder, "SKILL.md"), "---\nname: snap\ndescription: d\n---\nedited body\n")
	if got := body(t, tool, "snap"); !strings.Contains(got, "original body") || strings.Contains(got, "edited body") {
		t.Fatalf("body = %q, want the startup body", got)
	}
	readOK(t, tool, "snap", "extra.txt", "first")
	write(t, filepath.Join(folder, "extra.txt"), "second")
	readOK(t, tool, "snap", "extra.txt", "second")
}

func TestUnknownNameAndInvalidArguments(t *testing.T) {
	home, project := realDir(t), realDir(t)
	writeSkill(t, globalRoot(home), "visible", "v\n", false)
	writeSkill(t, globalRoot(home), "hidden", "h\n", true)
	tool := New(load(t, home, project), limit, home, project, permissions.NewBlockedPaths(home, nil), nil)

	res := invoke(t, tool, map[string]any{"name": "nope"})
	wantFailed(t, res, `no skill named "nope"; available skills: visible`)
	if strings.Contains(string(res.Stderr), "hidden") {
		t.Fatalf("unknown-name message %q discloses a slash-only skill", res.Stderr)
	}
	wantFailed(t, invoke(t, New(nil, limit, home, project, nil, nil), map[string]any{"name": "nope"}), `no skill named "nope" is available`)

	for _, args := range []map[string]any{
		{},
		{"name": 3},
		{"name": ""},
		{"name": "visible", "file": 7},
		{"name": "visible", "path": "x"},
	} {
		wantFailed(t, invoke(t, tool, args), "argument")
	}
}

func digest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func skillLoads(t *testing.T, store *sessions.Store) []events.SkillLoaded {
	t.Helper()
	var out []events.SkillLoaded
	for _, r := range store.Records() {
		ev, ok := r.(sessions.Event)
		if !ok || ev.Kind != "skill_loaded" {
			continue
		}
		if err := events.ValidatePayload(ev.Kind, ev.Payload); err != nil {
			t.Fatalf("skill_loaded payload %s: %v", ev.Payload, err)
		}
		var p events.SkillLoaded
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("decode skill_loaded: %v", err)
		}
		out = append(out, p)
	}
	return out
}

func TestLoadsRecordTheReadBytesNotTheSkillText(t *testing.T) {
	home, project := realDir(t), realDir(t)
	const skillBody, script = "Run scripts/run.sh.\n", "echo hi\n"
	folder := writeSkill(t, projectRoot(project), "deploy", skillBody, false)
	write(t, filepath.Join(folder, "scripts", "run.sh"), script)
	store := sessions.NewMemoryOnly()
	tool := New(load(t, home, project), limit, home, project, permissions.NewBlockedPaths(home, nil), func() *sessions.Store { return store })

	if got := body(t, tool, "deploy"); !strings.Contains(got, "- scripts/run.sh") {
		t.Fatalf("body = %q, want the file list", got)
	}
	child := ids.NewV7()
	res, err := tool.Invoke(vcs.WithChildInvocationID(context.Background(), child), map[string]any{"name": "deploy", "file": "./scripts//run.sh"})
	if err != nil || string(res.Stdout) != script {
		t.Fatalf("file read = (%+v, %v), want the script", res, err)
	}

	want := []events.SkillLoaded{
		{Name: "deploy", Layer: "project", Via: "tool", Bytes: int64(len(skillBody)), SHA256: digest(skillBody)},
		{Name: "deploy", Layer: "project", Via: "tool", File: "scripts/run.sh", Bytes: int64(len(script)), SHA256: digest(script), ChildInvocationID: child},
	}
	if got := skillLoads(t, store); !reflect.DeepEqual(got, want) {
		t.Fatalf("skill_loaded = %+v, want %+v", got, want)
	}
	for _, r := range store.Records() {
		if ev, ok := r.(sessions.Event); ok && (strings.Contains(string(ev.Payload), "Run scripts") || strings.Contains(string(ev.Payload), "echo hi")) {
			t.Fatalf("record %s carries skill text", ev.Payload)
		}
	}
}

func TestFailedReadsRecordNothing(t *testing.T) {
	home, project := realDir(t), realDir(t)
	folder := writeSkill(t, globalRoot(home), "safe", "body\n", false)
	writeSkill(t, globalRoot(home), "off", "off body\n", true)
	write(t, filepath.Join(folder, "secret.txt"), "BLOCKED")
	write(t, filepath.Join(folder, "big"), strings.Repeat("B", 65))
	blocked := permissions.NewBlockedPaths(home, []permissions.BlockedEntry{{Path: filepath.Join(folder, "secret.txt"), Source: "/s.yaml"}})
	store := sessions.NewMemoryOnly()
	tool := New(load(t, home, project), 64, home, project, blocked, func() *sessions.Store { return store })

	for _, args := range []map[string]any{
		{"name": "nope"},
		{"name": 3},
		{"name": "off"},
		{"name": "safe", "file": "../x"},
		{"name": "safe", "file": "missing.txt"},
		{"name": "safe", "file": "secret.txt"},
		{"name": "safe", "file": "big"},
	} {
		res, err := tool.Invoke(context.Background(), args)
		if err == nil && res.ExitCode != 1 {
			t.Fatalf("Invoke(%v) = %+v, want a failed or refused read", args, res)
		}
	}
	if got := skillLoads(t, store); len(got) != 0 {
		t.Fatalf("skill_loaded = %+v, want none for failed reads", got)
	}
}
