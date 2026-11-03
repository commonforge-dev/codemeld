package permissions

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"
)

func TestHistoryStores(t *testing.T) {
	type fixture struct{ root, other string }
	mkdir := func(t *testing.T, path string) {
		t.Helper()
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(t *testing.T, path, content string) {
		t.Helper()
		mkdir(t, filepath.Dir(path))
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gitFile := func(t *testing.T, f fixture, content string) { write(t, filepath.Join(f.root, ".git"), content) }
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, f fixture)
		want    func(f fixture) []string
		wantErr bool
	}{
		{name: "no marker", want: func(fixture) []string { return nil }},
		{name: "git folder", setup: func(t *testing.T, f fixture) { mkdir(t, filepath.Join(f.root, ".git")) },
			want: func(f fixture) []string { return []string{filepath.Join(f.root, ".git")} }},
		{name: "symlinked git folder", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.other, "store"))
			if err := os.Symlink(filepath.Join(f.other, "store"), filepath.Join(f.root, ".git")); err != nil {
				t.Fatal(err)
			}
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".git"), filepath.Join(f.other, "store")}
		}},
		{name: "git folder with commondir", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.other, "main.git"))
			write(t, filepath.Join(f.root, ".git", "commondir"), filepath.Join(f.other, "main.git")+"\n")
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".git"), filepath.Join(f.other, "main.git")}
		}},
		{name: "symlinked git folder with relative commondir", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.other, "main.git"))
			write(t, filepath.Join(f.other, "wt", "commondir"), "../main.git\n")
			if err := os.Symlink(filepath.Join(f.other, "wt"), filepath.Join(f.root, ".git")); err != nil {
				t.Fatal(err)
			}
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".git"), filepath.Join(f.other, "wt"), filepath.Join(f.other, "main.git")}
		}},
		{name: "absolute gitdir without commondir", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.other, "gd"))
			gitFile(t, f, "gitdir: "+filepath.Join(f.other, "gd")+"\n")
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".git"), filepath.Join(f.other, "gd")}
		}},
		{name: "relative gitdir", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.root, "sub", "gd"))
			gitFile(t, f, "gitdir: sub/gd")
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".git"), filepath.Join(f.root, "sub", "gd")}
		}},
		{name: "worktree with commondir", setup: func(t *testing.T, f fixture) {
			write(t, filepath.Join(f.other, "main", ".git", "worktrees", "wt", "commondir"), "../..\n")
			gitFile(t, f, "gitdir: "+filepath.Join(f.other, "main", ".git", "worktrees", "wt")+"\n")
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".git"), filepath.Join(f.other, "main", ".git", "worktrees", "wt"), filepath.Join(f.other, "main", ".git")}
		}},
		{name: "gitdir through a selector symlink", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.root, "stores", "a"))
			mkdir(t, filepath.Join(f.root, "links"))
			if err := os.Symlink("../stores/a", filepath.Join(f.root, "links", "current")); err != nil {
				t.Fatal(err)
			}
			gitFile(t, f, "gitdir: links/current\n")
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".git"), filepath.Join(f.root, "links", "current"), filepath.Join(f.root, "stores", "a")}
		}},
		{name: "symlink chain through a symlinked git folder", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.other, "store"))
			for link, target := range map[string]string{"one": filepath.Join(f.other, "two"), "two": "store"} {
				if err := os.Symlink(target, filepath.Join(f.other, link)); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(filepath.Join(f.other, "one"), filepath.Join(f.root, ".git")); err != nil {
				t.Fatal(err)
			}
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".git"), filepath.Join(f.other, "one"), filepath.Join(f.other, "two"), filepath.Join(f.other, "store")}
		}},
		{name: "commondir through a symlinked pointer and a selector symlink", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.other, "gd"))
			mkdir(t, filepath.Join(f.other, "main"))
			write(t, filepath.Join(f.other, "pointers", "commondir"), "../sel\n")
			if err := os.Symlink(filepath.Join(f.other, "pointers", "commondir"), filepath.Join(f.other, "gd", "commondir")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("main", filepath.Join(f.other, "sel")); err != nil {
				t.Fatal(err)
			}
			gitFile(t, f, "gitdir: "+filepath.Join(f.other, "gd"))
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".git"), filepath.Join(f.other, "gd"), filepath.Join(f.other, "gd", "commondir"),
				filepath.Join(f.other, "pointers", "commondir"), filepath.Join(f.other, "sel"), filepath.Join(f.other, "main")}
		}},
		{name: "sharedpath through a selector symlink", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.other, "src", ".hg"))
			if err := os.Symlink(filepath.Join(f.other, "src"), filepath.Join(f.other, "sel")); err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(f.root, ".hg", "sharedpath"), filepath.Join(f.other, "sel", ".hg"))
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".hg"), filepath.Join(f.other, "sel"), filepath.Join(f.other, "src", ".hg")}
		}},
		{name: "relative gitdir through a selector symlink then dot-dot", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.other, "selected"))
			mkdir(t, filepath.Join(f.other, "store"))
			mkdir(t, filepath.Join(f.root, "links", "store"))
			if err := os.Symlink(filepath.Join(f.other, "selected"), filepath.Join(f.root, "links", "current")); err != nil {
				t.Fatal(err)
			}
			gitFile(t, f, "gitdir: links/current/../store\n")
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".git"), filepath.Join(f.root, "links", "current"), filepath.Join(f.other, "store")}
		}},
		{name: "absolute gitdir through a selector symlink then dot-dot", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.other, "selected"))
			mkdir(t, filepath.Join(f.other, "store"))
			mkdir(t, filepath.Join(f.root, "links", "store"))
			if err := os.Symlink(filepath.Join(f.other, "selected"), filepath.Join(f.root, "links", "current")); err != nil {
				t.Fatal(err)
			}
			gitFile(t, f, "gitdir: "+filepath.Join(f.root, "links", "current")+"/../store\n")
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".git"), filepath.Join(f.root, "links", "current"), filepath.Join(f.other, "store")}
		}},
		{name: "commondir through a selector symlink then dot-dot", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.other, "selected"))
			mkdir(t, filepath.Join(f.other, "main"))
			mkdir(t, filepath.Join(f.other, "gd", "main"))
			if err := os.Symlink(filepath.Join(f.other, "selected"), filepath.Join(f.other, "gd", "current")); err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(f.other, "gd", "commondir"), "current/../main\n")
			gitFile(t, f, "gitdir: "+filepath.Join(f.other, "gd"))
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".git"), filepath.Join(f.other, "gd"), filepath.Join(f.other, "gd", "current"), filepath.Join(f.other, "main")}
		}},
		{name: "sharedpath through a selector symlink then dot-dot", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.other, "selected"))
			mkdir(t, filepath.Join(f.other, "src", ".hg"))
			mkdir(t, filepath.Join(f.root, "links", "src", ".hg"))
			if err := os.Symlink(filepath.Join(f.other, "selected"), filepath.Join(f.root, "links", "current")); err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(f.root, ".hg", "sharedpath"), filepath.Join(f.root, "links", "current")+"/../src/.hg")
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".hg"), filepath.Join(f.root, "links", "current"), filepath.Join(f.other, "src", ".hg")}
		}},
		{name: "gitdir through a folder then dot-dot", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.root, "sub"))
			mkdir(t, filepath.Join(f.root, "gd"))
			gitFile(t, f, "gitdir: sub/../gd")
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".git"), filepath.Join(f.root, "gd")}
		}},
		{name: "gitdir through a regular file then dot-dot", wantErr: true, setup: func(t *testing.T, f fixture) {
			write(t, filepath.Join(f.root, "plainfile"), "")
			mkdir(t, filepath.Join(f.root, "store"))
			gitFile(t, f, "gitdir: plainfile/../store")
		}},
		{name: "gitdir selector symlink through a regular file then dot-dot", wantErr: true, setup: func(t *testing.T, f fixture) {
			write(t, filepath.Join(f.root, "plainfile"), "")
			mkdir(t, filepath.Join(f.root, "store"))
			if err := os.Symlink("plainfile/../store", filepath.Join(f.root, "selector")); err != nil {
				t.Fatal(err)
			}
			gitFile(t, f, "gitdir: selector")
		}},
		{name: "hg folder", setup: func(t *testing.T, f fixture) { mkdir(t, filepath.Join(f.root, ".hg")) },
			want: func(f fixture) []string { return []string{filepath.Join(f.root, ".hg")} }},
		{name: "hg share absolute", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.other, "src", ".hg"))
			write(t, filepath.Join(f.root, ".hg", "sharedpath"), filepath.Join(f.other, "src", ".hg"))
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".hg"), filepath.Join(f.other, "src", ".hg")}
		}},
		{name: "hg share relative to the hg folder", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.root, "src", ".hg"))
			write(t, filepath.Join(f.root, ".hg", "sharedpath"), "../src/.hg\n")
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".hg"), filepath.Join(f.root, "src", ".hg")}
		}},
		{name: "git and hg", setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.root, ".git"))
			mkdir(t, filepath.Join(f.root, ".hg"))
		}, want: func(f fixture) []string {
			return []string{filepath.Join(f.root, ".git"), filepath.Join(f.root, ".hg")}
		}},
		{name: "unreadable pointer file", wantErr: true, setup: func(t *testing.T, f fixture) {
			if os.Geteuid() == 0 {
				t.Skip("root ignores file permissions")
			}
			mkdir(t, filepath.Join(f.other, "gd"))
			gitFile(t, f, "gitdir: "+filepath.Join(f.other, "gd"))
			if err := os.Chmod(filepath.Join(f.root, ".git"), 0); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "dangling git symlink", wantErr: true, setup: func(t *testing.T, f fixture) {
			if err := os.Symlink(filepath.Join(f.other, "missing"), filepath.Join(f.root, ".git")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "missing gitdir inside the root", wantErr: true, setup: func(t *testing.T, f fixture) { gitFile(t, f, "gitdir: missing") }},
		{name: "missing gitdir outside the root", wantErr: true, setup: func(t *testing.T, f fixture) {
			gitFile(t, f, "gitdir: "+filepath.Join(f.other, "missing"))
		}},
		{name: "missing commondir target", wantErr: true, setup: func(t *testing.T, f fixture) {
			write(t, filepath.Join(f.other, "gd", "commondir"), "../missing")
			gitFile(t, f, "gitdir: "+filepath.Join(f.other, "gd"))
		}},
		{name: "git folder with missing commondir target", wantErr: true, setup: func(t *testing.T, f fixture) {
			write(t, filepath.Join(f.root, ".git", "commondir"), filepath.Join(f.other, "missing"))
		}},
		{name: "git folder with empty commondir", wantErr: true, setup: func(t *testing.T, f fixture) {
			write(t, filepath.Join(f.root, ".git", "commondir"), "\n")
		}},
		{name: "git folder with dangling commondir symlink", wantErr: true, setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.root, ".git"))
			if err := os.Symlink(filepath.Join(f.other, "missing"), filepath.Join(f.root, ".git", "commondir")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlinked git folder with commondir fifo", wantErr: true, setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.other, "wt"))
			if err := syscall.Mkfifo(filepath.Join(f.other, "wt", "commondir"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(f.other, "wt"), filepath.Join(f.root, ".git")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "missing sharedpath target", wantErr: true, setup: func(t *testing.T, f fixture) {
			write(t, filepath.Join(f.root, ".hg", "sharedpath"), filepath.Join(f.other, "missing"))
		}},
		{name: "empty git file", wantErr: true, setup: func(t *testing.T, f fixture) { gitFile(t, f, "") }},
		{name: "git file without the gitdir prefix", wantErr: true, setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.root, "gd"))
			gitFile(t, f, "gd\n")
		}},
		{name: "empty gitdir", wantErr: true, setup: func(t *testing.T, f fixture) { gitFile(t, f, "gitdir: \n") }},
		{name: "empty commondir", wantErr: true, setup: func(t *testing.T, f fixture) {
			write(t, filepath.Join(f.other, "gd", "commondir"), "\n")
			gitFile(t, f, "gitdir: "+filepath.Join(f.other, "gd"))
		}},
		{name: "empty sharedpath", wantErr: true, setup: func(t *testing.T, f fixture) {
			write(t, filepath.Join(f.root, ".hg", "sharedpath"), "")
		}},
		{name: "git fifo", wantErr: true, setup: func(t *testing.T, f fixture) {
			if err := syscall.Mkfifo(filepath.Join(f.root, ".git"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "dangling commondir symlink", wantErr: true, setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.other, "gd"))
			if err := os.Symlink(filepath.Join(f.other, "missing"), filepath.Join(f.other, "gd", "commondir")); err != nil {
				t.Fatal(err)
			}
			gitFile(t, f, "gitdir: "+filepath.Join(f.other, "gd"))
		}},
		{name: "dangling sharedpath symlink", wantErr: true, setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.root, ".hg"))
			if err := os.Symlink(filepath.Join(f.other, "missing"), filepath.Join(f.root, ".hg", "sharedpath")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "commondir fifo", wantErr: true, setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.other, "gd"))
			if err := syscall.Mkfifo(filepath.Join(f.other, "gd", "commondir"), 0o600); err != nil {
				t.Fatal(err)
			}
			gitFile(t, f, "gitdir: "+filepath.Join(f.other, "gd"))
		}},
		{name: "sharedpath fifo", wantErr: true, setup: func(t *testing.T, f fixture) {
			mkdir(t, filepath.Join(f.root, ".hg"))
			if err := syscall.Mkfifo(filepath.Join(f.root, ".hg", "sharedpath"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hg file", wantErr: true, setup: func(t *testing.T, f fixture) { write(t, filepath.Join(f.root, ".hg"), "") }},
		{name: "gitdir is a file", wantErr: true, setup: func(t *testing.T, f fixture) {
			write(t, filepath.Join(f.other, "gd"), "")
			gitFile(t, f, "gitdir: "+filepath.Join(f.other, "gd"))
		}},
		{name: "commondir target is a file", wantErr: true, setup: func(t *testing.T, f fixture) {
			write(t, filepath.Join(f.other, "gd", "commondir"), "../file")
			write(t, filepath.Join(f.other, "file"), "")
			gitFile(t, f, "gitdir: "+filepath.Join(f.other, "gd"))
		}},
		{name: "sharedpath target is a file", wantErr: true, setup: func(t *testing.T, f fixture) {
			write(t, filepath.Join(f.other, "file"), "")
			write(t, filepath.Join(f.root, ".hg", "sharedpath"), filepath.Join(f.other, "file"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var f fixture
			for _, dir := range []*string{&f.root, &f.other} {
				resolved, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				*dir = resolved
			}
			if tc.setup != nil {
				tc.setup(t, f)
			}
			type result struct {
				stores []string
				err    error
			}
			done := make(chan result, 1)
			go func() {
				stores, err := HistoryStores(f.root)
				done <- result{stores, err}
			}()
			var got []string
			var err error
			select {
			case r := <-done:
				got, err = r.stores, r.err
			case <-time.After(10 * time.Second):
				t.Fatal("HistoryStores still blocked after 10s; want it to return promptly")
			}
			if tc.wantErr {
				if err == nil {
					t.Fatalf("HistoryStores = %q, nil; want an error", got)
				}
				return
			}
			if err != nil || !slices.Equal(got, tc.want(f)) {
				t.Fatalf("HistoryStores = %q, %v; want %q", got, err, tc.want(f))
			}
		})
	}
}
