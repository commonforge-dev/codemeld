package permissions

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func blockedTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return dir
}

func mkdirs(t *testing.T, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll(%q): %v", dir, err)
		}
	}
}

func TestBlockedPaths_Matching(t *testing.T) {
	home := blockedTempDir(t)
	outside := blockedTempDir(t)
	ssh := filepath.Join(home, ".ssh")
	realData := filepath.Join(outside, "real-data")
	mkdirs(t, filepath.Join(ssh, "child"), realData)
	if err := os.Symlink(ssh, filepath.Join(outside, "ssh-link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := os.Symlink(filepath.Join(ssh, "child"), filepath.Join(outside, "child-link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	sep := string(filepath.Separator)
	dataLink := filepath.Join(home, "data-link")
	if err := os.Symlink(realData, dataLink); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	entries := []BlockedEntry{
		{Path: ssh, Source: "/global/settings.yaml"},
		{Path: dataLink, Source: "/global/settings.yaml"},
	}
	exact := newBlockedPaths(home, entries, false)

	cases := []struct {
		name    string
		target  string
		blocked bool
		entry   string
	}{
		{"file inside entry", filepath.Join(ssh, "id_rsa"), true, ssh},
		{"entry itself", ssh, true, ssh},
		{"sibling sharing a prefix", filepath.Join(home, ".sshx"), false, ""},
		{"missing target under entry", filepath.Join(ssh, "newkey"), true, ssh},
		{"symlink outside home into entry", filepath.Join(outside, "ssh-link", "id_rsa"), true, ssh},
		{"parent of a symlink into entry", filepath.Join(outside, "child-link") + sep + ".." + sep + "id_rsa", true, ssh},
		{"path under the folder a symlinked entry points to", filepath.Join(realData, "file"), true, dataLink},
		{"floor", filepath.Join(home, ".codemeld", "global", "settings.yaml"), true, filepath.Join(home, ".codemeld")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entry, ok := exact.Blocking(c.target)
			if ok != c.blocked || entry.Path != c.entry {
				t.Fatalf("Blocking(%q) = %+v, %v; want entry %q, %v", c.target, entry, ok, c.entry, c.blocked)
			}
		})
	}
}

func TestBlockedPaths_FloorWithoutEntries(t *testing.T) {
	home := blockedTempDir(t)
	entry, ok := NewBlockedPaths(home, nil).Blocking(filepath.Join(home, ".codemeld", "global", "settings.yaml"))
	if !ok || !entry.Floor() || entry.Path != filepath.Join(home, ".codemeld") {
		t.Fatalf("Blocking = %+v, %v; want the floor", entry, ok)
	}
}

func TestBlockedPaths_EntryAppliesOnceCreated(t *testing.T) {
	home := blockedTempDir(t)
	elsewhere := blockedTempDir(t)
	missing := filepath.Join(home, "later")
	blocked := newBlockedPaths(home, []BlockedEntry{{Path: missing, Source: "s"}}, false)
	link := filepath.Join(elsewhere, "link")
	if err := os.Symlink(missing, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	target := filepath.Join(link, "file")

	if _, ok := blocked.Blocking(target); ok {
		t.Fatalf("Blocking(%q) before the entry exists = true, want false", target)
	}
	mkdirs(t, missing)
	if entry, ok := blocked.Blocking(target); !ok || entry.Path != missing {
		t.Fatalf("Blocking(%q) after the entry exists = %+v, %v; want the entry", target, entry, ok)
	}
}

func TestBlockedPaths_LetterCase(t *testing.T) {
	home := blockedTempDir(t)
	entries := []BlockedEntry{{Path: filepath.Join(home, ".ssh"), Source: "s"}}
	target := filepath.Join(home, ".SSH", "id_rsa")

	if _, ok := newBlockedPaths(home, entries, true).Blocking(target); !ok {
		t.Fatalf("case-insensitive Blocking(%q) = false, want true", target)
	}
	if _, ok := newBlockedPaths(home, entries, false).Blocking(target); ok {
		t.Fatalf("exact Blocking(%q) = true, want false", target)
	}
}

func TestBlockedPaths_UnresolvableTargetComparedAsWritten(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	home := blockedTempDir(t)
	outside := blockedTempDir(t)
	ssh := filepath.Join(home, ".ssh")
	locked := filepath.Join(outside, "locked")
	mkdirs(t, ssh, filepath.Join(locked, "inner"))
	if err := os.Symlink(outside, filepath.Join(ssh, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	target := filepath.Join(ssh, "link", "locked", "inner", "key")

	if forms := blockedForms(target); len(forms) != 1 || forms[0] != target {
		t.Fatalf("blockedForms(%q) = %v, want only the written form", target, forms)
	}
	if _, ok := newBlockedPaths(home, []BlockedEntry{{Path: ssh, Source: "s"}}, false).Blocking(target); !ok {
		t.Fatalf("Blocking(%q) = false, want the written form blocked", target)
	}
}

func TestBlockedPaths_BlockedWithin(t *testing.T) {
	home := blockedTempDir(t)
	ssh := filepath.Join(home, ".ssh")
	blocked := newBlockedPaths(home, []BlockedEntry{{Path: ssh, Source: "s"}}, false)

	if entry, ok := blocked.BlockedWithin(home); !ok || entry.Path != ssh {
		t.Fatalf("BlockedWithin(home) = %+v, %v; want the ~/.ssh entry", entry, ok)
	}
	sub := filepath.Join(ssh, "sub")
	if entry, ok := blocked.BlockedWithin(sub); ok {
		t.Fatalf("BlockedWithin(%q) = %+v, want nothing", sub, entry)
	}
	if _, ok := blocked.Blocking(sub); !ok {
		t.Fatalf("Blocking(%q) = false, want true", sub)
	}
}

func TestBlockedPaths_WindowsDrivePrefixes(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("drive prefixes are Windows path syntax")
	}
	home := blockedTempDir(t)
	ssh := filepath.Join(home, ".ssh")
	mkdirs(t, ssh)
	blocked := NewBlockedPaths(home, []BlockedEntry{{Path: ssh, Source: "s"}})
	floorOnly := NewBlockedPaths(home, nil)

	for _, prefix := range []string{`\\?\`, `\\.\`, `\??\`} {
		if entry, ok := blocked.Blocking(prefix + filepath.Join(ssh, "id_rsa")); !ok || entry.Path != ssh {
			t.Fatalf("Blocking(%s…id_rsa) = %+v, %v; want the ~/.ssh entry", prefix, entry, ok)
		}
		if entry, ok := blocked.Blocking(prefix + filepath.Join(home, ".codemeld", "global", "settings.yaml")); !ok || !entry.Floor() {
			t.Fatalf("Blocking(%s…settings.yaml) = %+v, %v; want the floor", prefix, entry, ok)
		}
		if entry, ok := blocked.BlockedWithin(prefix + home); !ok || entry.Path != ssh {
			t.Fatalf("BlockedWithin(%s home) = %+v, %v; want the ~/.ssh entry", prefix, entry, ok)
		}
		if entry, ok := floorOnly.BlockedWithin(prefix + home); !ok || !entry.Floor() {
			t.Fatalf("floor-only BlockedWithin(%s home) = %+v, %v; want the floor", prefix, entry, ok)
		}
	}
}

func TestBlockedPaths_EntryOrder(t *testing.T) {
	home := blockedTempDir(t)
	ssh := filepath.Join(home, ".ssh")
	keys := filepath.Join(ssh, "keys")
	target := filepath.Join(keys, "id_rsa")

	for _, order := range [][2]string{{ssh, keys}, {keys, ssh}} {
		blocked := newBlockedPaths(home, []BlockedEntry{{Path: order[0], Source: "s"}, {Path: order[1], Source: "s"}}, false)
		if entry, ok := blocked.Blocking(target); !ok || entry.Path != order[0] {
			t.Fatalf("entries %v: Blocking(%q) = %+v, %v; want the first entry", order, target, entry, ok)
		}
		if entry, ok := blocked.BlockedWithin(home); !ok || entry.Path != order[0] {
			t.Fatalf("entries %v: BlockedWithin(home) = %+v, %v; want the first entry", order, entry, ok)
		}
	}

	settings := filepath.Join(home, ".codemeld", "global", "settings.yaml")
	if entry, ok := newBlockedPaths(home, []BlockedEntry{{Path: home, Source: "s"}}, false).Blocking(settings); !ok || !entry.Floor() {
		t.Fatalf("Blocking(%q) with a home entry = %+v, %v; want the floor", settings, entry, ok)
	}
}

func TestBlockedPaths_NilReceiver(t *testing.T) {
	var blocked *BlockedPaths
	if _, ok := blocked.Blocking("/home/u/.codemeld"); ok {
		t.Fatal("nil Blocking = true, want false")
	}
	if _, ok := blocked.BlockedWithin("/"); ok {
		t.Fatal("nil BlockedWithin = true, want false")
	}
	if found, err := blocked.InRepository("/"); found != nil || err != nil {
		t.Fatalf("nil InRepository = %+v, %v; want nothing", found, err)
	}
}

func TestBlockedPaths_InRepository(t *testing.T) {
	home := blockedTempDir(t)
	base := blockedTempDir(t)
	root := filepath.Join(base, "repo")
	secrets := filepath.Join(root, "secrets")
	outside := filepath.Join(base, "outside")
	vault := filepath.Join(base, "vault")
	cased := filepath.Join(base, "Cased")
	upper := filepath.Join(base, "upper")
	mkdirs(t, secrets, outside, filepath.Join(vault, "repo"), cased, filepath.Join(upper, "Secrets"), filepath.Join(home, ".ssh"))
	link := filepath.Join(base, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "out-link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	floor := BlockedEntry{Path: filepath.Join(home, ".codemeld")}
	ssh := BlockedEntry{Path: filepath.Join(home, ".ssh"), Source: "s"}

	cases := []struct {
		name  string
		root  string
		entry string
		fold  bool
		want  []RepositoryEntry
	}{
		{"entry equal to the root", root, root, false, []RepositoryEntry{{Entry: BlockedEntry{Path: root, Source: "s"}, Candidates: []string{root}}}},
		{"nested entry", root, secrets, false, []RepositoryEntry{{Entry: BlockedEntry{Path: secrets, Source: "s"}, Candidates: []string{secrets}}}},
		{"root inside the entry", filepath.Join(vault, "repo"), vault, false, []RepositoryEntry{{Entry: BlockedEntry{Path: vault, Source: "s"}, Candidates: []string{filepath.Join(vault, "repo")}}}},
		{"entry through a symlinked parent", root, filepath.Join(link, "secrets"), false, []RepositoryEntry{{Entry: BlockedEntry{Path: filepath.Join(link, "secrets"), Source: "s"}, Candidates: []string{secrets}}}},
		{"entry inside the root only through case folding", cased, filepath.Join(base, "cased", "secrets"), true, []RepositoryEntry{{Entry: BlockedEntry{Path: filepath.Join(base, "cased", "secrets"), Source: "s"}, Candidates: []string{cased}}}},
		{"on-disk spelling differing only by case with folding", upper, filepath.Join(upper, "secrets"), true, []RepositoryEntry{{Entry: BlockedEntry{Path: filepath.Join(upper, "secrets"), Source: "s"}, Candidates: []string{upper}}}},
		{"on-disk spelling differing only by case without folding", upper, filepath.Join(upper, "secrets"), false, []RepositoryEntry{{Entry: BlockedEntry{Path: filepath.Join(upper, "secrets"), Source: "s"}, Candidates: []string{filepath.Join(upper, "secrets")}}}},
		{"exact on-disk spelling with folding", root, secrets, true, []RepositoryEntry{{Entry: BlockedEntry{Path: secrets, Source: "s"}, Candidates: []string{secrets}}}},
		{"missing entry with folding", root, filepath.Join(root, "missing"), true, []RepositoryEntry{{Entry: BlockedEntry{Path: filepath.Join(root, "missing"), Source: "s"}, Candidates: []string{filepath.Join(root, "missing")}}}},
		{"sibling sharing the root's prefix", root, root + "-secrets", false, nil},
		{"entry under a sibling sharing the root's prefix", root, filepath.Join(root+"x", "secrets"), false, nil},
		{"entry outside the root", root, ssh.Path, false, nil},
		{"entry reached through a symlink inside the root", root, filepath.Join(outside, "secrets"), false, nil},
		{"case-folded entry without folding", cased, filepath.Join(base, "cased", "secrets"), false, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			found, err := newBlockedPaths(home, []BlockedEntry{{Path: c.entry, Source: "s"}}, c.fold).InRepository(c.root)
			if err != nil {
				t.Fatalf("InRepository(%q): %v", c.root, err)
			}
			if !reflect.DeepEqual(found, c.want) {
				t.Fatalf("InRepository(%q) = %+v, want %+v", c.root, found, c.want)
			}
		})
	}

	t.Run("floor when the root is the home folder", func(t *testing.T) {
		found, err := newBlockedPaths(home, []BlockedEntry{ssh}, false).InRepository(home)
		want := []RepositoryEntry{{Entry: ssh, Candidates: []string{ssh.Path}}, {Entry: floor, Candidates: []string{floor.Path}}}
		if err != nil || !reflect.DeepEqual(found, want) {
			t.Fatalf("InRepository(home) = %+v, %v; want %+v", found, err, want)
		}
	})

	t.Run("unreadable folder below the root with folding", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses directory permissions")
		}
		repo := filepath.Join(base, "locked-repo")
		locked := filepath.Join(repo, "locked")
		mkdirs(t, locked)
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
		entry := BlockedEntry{Path: filepath.Join(locked, "k"), Source: "s"}
		found, err := newBlockedPaths(home, []BlockedEntry{entry}, true).InRepository(repo)
		want := []RepositoryEntry{{Entry: entry, Candidates: []string{repo}}}
		if err != nil || !reflect.DeepEqual(found, want) {
			t.Fatalf("InRepository(%q) = %+v, %v; want %+v", repo, found, err, want)
		}
	})

	t.Run("unresolvable root", func(t *testing.T) {
		if _, err := newBlockedPaths(home, []BlockedEntry{ssh}, false).InRepository(filepath.Join(base, "missing")); err == nil {
			t.Fatal("InRepository(missing root) = nil error, want the resolution error")
		}
	})
}

type stubReload struct {
	mu    sync.Mutex
	calls int
	next  *BlockedReload
}

func (s *stubReload) set(entries ...BlockedEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next = &BlockedReload{Changed: true, Entries: entries}
}

func (s *stubReload) reload() BlockedReload {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.next == nil {
		return BlockedReload{}
	}
	r := *s.next
	s.next = nil
	return r
}

func (s *stubReload) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestBlockedPaths_LiveListFollowsReload(t *testing.T) {
	home := blockedTempDir(t)
	ssh := BlockedEntry{Path: filepath.Join(home, ".ssh"), Source: "s"}
	target := filepath.Join(ssh.Path, "id_rsa")
	stub := &stubReload{}
	live := NewLiveBlockedPaths(home, "", nil, stub.reload)

	if _, ok := live.Blocking(target); ok {
		t.Fatalf("Blocking(%q) before the entry is added = true, want false", target)
	}
	stub.set(ssh)
	if entry, ok := live.Blocking(target); !ok || entry != ssh {
		t.Fatalf("Blocking(%q) after the entry is added = %+v, %v; want %+v", target, entry, ok, ssh)
	}
	stub.set()
	if entry, ok := live.Blocking(target); ok {
		t.Fatalf("Blocking(%q) after the entry is removed = %+v, want nothing", target, entry)
	}
}

func TestBlockedPaths_CurrentKeepsItsEntries(t *testing.T) {
	home := blockedTempDir(t)
	ssh := BlockedEntry{Path: filepath.Join(home, ".ssh"), Source: "s"}
	target := filepath.Join(ssh.Path, "id_rsa")
	stub := &stubReload{}
	live := NewLiveBlockedPaths(home, "", []BlockedEntry{ssh}, stub.reload)

	current := live.Current()
	if stub.count() != 1 {
		t.Fatalf("Current called reload %d times, want 1", stub.count())
	}
	stub.set()
	if _, ok := live.Blocking(target); ok {
		t.Fatalf("live Blocking(%q) after the removal = true, want false", target)
	}
	calls := stub.count()
	if entry, ok := current.Blocking(target); !ok || entry != ssh {
		t.Fatalf("copy Blocking(%q) = %+v, %v; want %+v", target, entry, ok, ssh)
	}
	if got := current.Entries(); len(got) != 2 || got[0] != ssh {
		t.Fatalf("copy Entries = %+v, want %+v and the floor", got, ssh)
	}
	if stub.count() != calls {
		t.Fatalf("queries on the copy called reload %d times, want none", stub.count()-calls)
	}
	var none *BlockedPaths
	if none.Current() != nil {
		t.Fatal("nil Current() is not nil")
	}
	if NewBlockedPaths(home, []BlockedEntry{ssh}).reload != nil {
		t.Fatal("NewBlockedPaths holds a re-read function")
	}
}

func TestBlockedPaths_ConcurrentQueriesDuringSwaps(t *testing.T) {
	home := blockedTempDir(t)
	ssh := BlockedEntry{Path: filepath.Join(home, ".ssh"), Source: "s"}
	var mu sync.Mutex
	flip := false
	live := NewLiveBlockedPaths(home, "", nil, func() BlockedReload {
		mu.Lock()
		defer mu.Unlock()
		flip = !flip
		if flip {
			return BlockedReload{Changed: true, Entries: []BlockedEntry{ssh}}
		}
		return BlockedReload{Changed: true}
	})

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				live.Blocking(filepath.Join(ssh.Path, "id_rsa"))
				live.BlockedWithin(home)
				_ = live.Entries()
				_, _ = live.InRepository(home)
				live.Current().Blocking(ssh.Path)
			}
		}()
	}
	wg.Wait()
}

func problemNotice(file, reason string) string {
	return "blocked_paths: " + file + " " + reason + "; reads outside the project will ask until it is fixed"
}

func TestBlockedPaths_ProblemNotices(t *testing.T) {
	home := blockedTempDir(t)
	var next map[string]string
	live := NewLiveBlockedPaths(home, "", nil, func() BlockedReload { return BlockedReload{Problems: next} })
	var lines []string
	check := func(problems map[string]string, want ...string) {
		t.Helper()
		next, lines = problems, nil
		live.Entries()
		if !slices.Equal(lines, want) {
			t.Fatalf("after problems %v: notices = %q, want %q", problems, lines, want)
		}
		if live.Degraded() != (len(problems) > 0) {
			t.Fatalf("after problems %v: Degraded = %v", problems, live.Degraded())
		}
	}
	const a, b, c = "/a/settings.yaml", "/b/settings.yaml", "/c\nd/settings.yaml"

	next = map[string]string{b: "is not valid YAML"}
	live.Entries()
	live.SetNotice(func(line string) { lines = append(lines, line) })
	check(map[string]string{b: "is not valid YAML"}, problemNotice(b, "is not valid YAML"))
	check(map[string]string{b: "is not valid YAML"})
	check(map[string]string{b: "doesn't match the settings schema", a: "is missing"},
		problemNotice(a, "is missing"), problemNotice(b, "doesn't match the settings schema"))
	check(map[string]string{a: "is missing", c: "can't be read"}, fixedNotice(b), problemNotice("/c d/settings.yaml", "can't be read"))
	check(nil, fixedNotice(a), fixedNotice("/c d/settings.yaml"))
	check(nil)
}

func fixedNotice(file string) string {
	return "blocked_paths: " + file + " can be read again"
}

func TestBlockedPaths_CurrentKeepsTheDegradedStateAndRoot(t *testing.T) {
	home := blockedTempDir(t)
	problems := map[string]string{"/g/settings.yaml": "is missing"}
	var next map[string]string
	live := NewLiveBlockedPaths(home, "/project", nil, func() BlockedReload { return BlockedReload{Problems: next} })

	next = problems
	broken := live.Current()
	next = nil
	fixed := live.Current()
	if !broken.Degraded() || fixed.Degraded() || live.Degraded() {
		t.Fatalf("Degraded broken, fixed, live = %v, %v, %v; want true, false, false", broken.Degraded(), fixed.Degraded(), live.Degraded())
	}
	next = problems
	live.Entries()
	if !live.Degraded() || fixed.Degraded() {
		t.Fatalf("Degraded live, fixed = %v, %v; want the copy unchanged by a later problem", live.Degraded(), fixed.Degraded())
	}
	if live.ProjectRoot() != "/project" || fixed.ProjectRoot() != "/project" {
		t.Fatalf("ProjectRoot live, copy = %q, %q; want /project", live.ProjectRoot(), fixed.ProjectRoot())
	}

	var none *BlockedPaths
	none.SetNotice(func(string) {})
	if none.Degraded() || none.ProjectRoot() != "" || !none.OutsideProject(home) {
		t.Fatal("nil list: want not degraded, no project root and every path outside")
	}
}

func TestBlockedPaths_ConcurrentNoticesDuringFailingReloads(t *testing.T) {
	home := blockedTempDir(t)
	ssh := BlockedEntry{Path: filepath.Join(home, ".ssh"), Source: "s"}
	var mu sync.Mutex
	failing := false
	live := NewLiveBlockedPaths(home, home, nil, func() BlockedReload {
		mu.Lock()
		defer mu.Unlock()
		failing = !failing
		if failing {
			return BlockedReload{Changed: true, Entries: []BlockedEntry{ssh}, Problems: map[string]string{"/g/settings.yaml": "is not valid YAML"}}
		}
		return BlockedReload{Changed: true}
	})

	var lineMu sync.Mutex
	lines := 0
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				live.SetNotice(func(string) {
					lineMu.Lock()
					lines++
					lineMu.Unlock()
				})
				live.Blocking(filepath.Join(ssh.Path, "id_rsa"))
				_ = live.Degraded()
				_ = live.Current().Degraded()
				_ = live.OutsideProject(ssh.Path)
			}
		}()
	}
	wg.Wait()
}

func TestBlockedPaths_CurrentCopiesOneReload(t *testing.T) {
	home := blockedTempDir(t)
	broken := BlockedEntry{Path: filepath.Join(home, "broken"), Source: "s"}
	fixed := BlockedEntry{Path: filepath.Join(home, "fixed"), Source: "s"}
	failing := false
	live := NewLiveBlockedPaths(home, "", nil, func() BlockedReload {
		failing = !failing
		if failing {
			return BlockedReload{Changed: true, Entries: []BlockedEntry{broken}, Problems: map[string]string{"/g/settings.yaml": "is not valid YAML"}}
		}
		return BlockedReload{Changed: true, Entries: []BlockedEntry{fixed}}
	})

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 500 {
				c := live.Current()
				if entry := c.Entries()[0]; (entry == broken) != c.Degraded() {
					t.Errorf("copy holds %+v with Degraded %v; want the entries and degraded state of one reload", entry, c.Degraded())
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
}

func TestBlockedPaths_OutsideProject(t *testing.T) {
	base := blockedTempDir(t)
	project := filepath.Join(base, "project")
	outside := filepath.Join(base, "outside")
	mkdirs(t, project, outside)
	if err := os.Symlink(outside, filepath.Join(project, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	rootLink := filepath.Join(base, "project-link")
	if err := os.Symlink(project, rootLink); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	sep := string(filepath.Separator)
	noReload := func() BlockedReload { return BlockedReload{} }

	cases := []struct {
		name    string
		root    string
		path    string
		outside bool
	}{
		{"a file in the project", project, filepath.Join(project, "a.txt"), false},
		{"the project root itself", project, project, false},
		{"a path through a symlinked project root", rootLink, filepath.Join(rootLink, "a.txt"), false},
		{"a sibling folder", project, filepath.Join(base, "sibling", "a.txt"), true},
		{"a step out of the project", project, project + sep + ".." + sep + "x", true},
		{"a symlink inside the project that points outside", project, filepath.Join(project, "link", "secret"), true},
		{"an empty project root", "", filepath.Join(project, "a.txt"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NewLiveBlockedPaths(base, c.root, nil, noReload).OutsideProject(c.path); got != c.outside {
				t.Fatalf("OutsideProject(%q) with root %q = %v, want %v", c.path, c.root, got, c.outside)
			}
		})
	}

	t.Run("letter case", func(t *testing.T) {
		target := filepath.Join(base, "PROJECT", "a")
		for _, fold := range []bool{true, false} {
			b := newBlockedPaths(base, nil, fold)
			b.projectRoot = project
			if got := b.OutsideProject(target); got == fold {
				t.Fatalf("fold=%v: OutsideProject(%q) = %v, want %v", fold, target, got, !fold)
			}
		}
	})

	t.Run("a path that cannot be resolved", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses directory permissions")
		}
		locked := filepath.Join(project, "locked")
		mkdirs(t, filepath.Join(locked, "inner"))
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
		target := filepath.Join(locked, "inner", "x")
		if !NewLiveBlockedPaths(base, project, nil, noReload).OutsideProject(target) {
			t.Fatalf("OutsideProject(%q) = false, want an unresolvable path counted as outside", target)
		}
	})
}

func TestExpandBlockedEntry(t *testing.T) {
	home := t.TempDir()
	sep := string(filepath.Separator)
	valid := map[string]string{
		"~":   home,
		"~/x": filepath.Join(home, "x"),
		home + sep + "a" + sep + "." + sep + "b" + sep + ".." + sep + "c": filepath.Join(home, "a", "c"),
	}
	if runtime.GOOS == "windows" {
		valid[`~\x`] = filepath.Join(home, "x")
		valid[`~\`] = home
	}
	for raw, want := range valid {
		got, err := ExpandBlockedEntry(home, raw)
		if err != nil || got != want {
			t.Fatalf("ExpandBlockedEntry(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"~user/x", "x/y", "./x", ""} {
		_, err := ExpandBlockedEntry(home, raw)
		if err == nil {
			t.Fatalf("ExpandBlockedEntry(%q) = nil error, want a rejection", raw)
		}
		if raw != "" && !strings.Contains(err.Error(), raw) {
			t.Fatalf("ExpandBlockedEntry(%q) error %q does not name the entry", raw, err)
		}
	}
}

func TestBlockedPaths_Forms(t *testing.T) {
	home := blockedTempDir(t)
	realDir := filepath.Join(home, "realDir")
	link := filepath.Join(home, "link")
	mkdirs(t, realDir)
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	floor := filepath.Join(home, ".codemeld")
	missing := filepath.Join(home, "missing", "x")
	cases := []struct {
		name    string
		entries []string
		want    []string
	}{
		{"floor only", nil, []string{floor}},
		{"symlinked entry", []string{link}, []string{link, realDir, floor}},
		{"missing entry", []string{missing}, []string{missing, floor}},
		{"missing entry beneath a symlinked parent", []string{filepath.Join(link, "gone")}, []string{filepath.Join(link, "gone"), filepath.Join(realDir, "gone"), floor}},
		{"duplicate dropped", []string{link, realDir, link}, []string{link, realDir, floor}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var entries []BlockedEntry
			for _, e := range c.entries {
				entries = append(entries, BlockedEntry{Path: e, Source: "/global/settings.yaml"})
			}
			if got := NewBlockedPaths(home, entries).Forms(); !reflect.DeepEqual(got, c.want) {
				t.Errorf("Forms() = %q, want %q", got, c.want)
			}
		})
	}
}

type transitionQueue struct {
	mu     sync.Mutex
	queued []bool
}

func (q *transitionQueue) enqueue(degraded bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.queued = append(q.queued, degraded)
}

func (q *transitionQueue) take() []bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.queued
	q.queued = nil
	return out
}

func TestBlockedPaths_DegradedChangeRunsOncePerChange(t *testing.T) {
	home := blockedTempDir(t)
	var next map[string]string
	live := NewLiveBlockedPaths(home, "", nil, func() BlockedReload { return BlockedReload{Problems: next} })
	q := &transitionQueue{}
	live.SetOnDegradedChange(q.enqueue)

	for _, step := range []struct {
		problems map[string]string
		want     []bool
	}{
		{nil, nil},
		{map[string]string{"/g/settings.yaml": "is not valid YAML"}, []bool{true}},
		{map[string]string{"/g/settings.yaml": "is not valid YAML"}, nil},
		{map[string]string{"/g/settings.yaml": "doesn't match the settings schema", "/p/settings.yaml": "is missing"}, nil},
		{nil, []bool{false}},
		{nil, nil},
	} {
		next = step.problems
		live.Entries()
		_ = live.Current()
		if got := q.take(); !slices.Equal(got, step.want) {
			t.Fatalf("after problems %v: transitions = %v, want %v", step.problems, got, step.want)
		}
	}

	next = map[string]string{"/g/settings.yaml": "is missing"}
	copied := live.Current()
	if got := q.take(); !slices.Equal(got, []bool{true}) {
		t.Fatalf("transitions = %v, want [true]", got)
	}
	copied.Entries()
	if got := q.take(); got != nil || copied.onDegraded.Load() != nil {
		t.Fatalf("a Current copy carries the callback (transitions %v)", got)
	}

	live.SetOnDegradedChange(nil)
	next = nil
	live.Entries()
	if got := q.take(); got != nil || live.Degraded() {
		t.Fatalf("after removal: transitions = %v, Degraded = %v; want none and false", got, live.Degraded())
	}
	var none *BlockedPaths
	none.SetOnDegradedChange(q.enqueue)
}

func TestBlockedPaths_ConcurrentDegradedChangesStayOrdered(t *testing.T) {
	home := blockedTempDir(t)
	ssh := BlockedEntry{Path: filepath.Join(home, ".ssh"), Source: "s"}
	var mu sync.Mutex
	reloads := 0
	live := NewLiveBlockedPaths(home, home, nil, func() BlockedReload {
		mu.Lock()
		defer mu.Unlock()
		reloads++
		if reloads%2 == 1 {
			return BlockedReload{Changed: true, Entries: []BlockedEntry{ssh}, Problems: map[string]string{"/g/settings.yaml": "is not valid YAML"}}
		}
		return BlockedReload{Changed: true}
	})
	q := &transitionQueue{}
	first := func(degraded bool) { q.enqueue(degraded) }
	second := func(degraded bool) { q.enqueue(degraded) }
	live.SetOnDegradedChange(first)

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				if i%2 == 0 {
					live.SetOnDegradedChange(second)
				} else {
					live.SetOnDegradedChange(first)
				}
				live.Blocking(filepath.Join(ssh.Path, "id_rsa"))
				_ = live.Degraded()
				_ = live.Current().Degraded()
				_ = live.OutsideProject(ssh.Path)
			}
		}()
	}
	wg.Wait()

	got := q.take()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != reloads {
		t.Fatalf("transitions = %d, want one per reload (%d), since every reload flips the state", len(got), reloads)
	}
	for i, degraded := range got {
		if degraded != (i%2 == 0) {
			t.Fatalf("transition %d = %v; want strictly alternating values starting with true", i, degraded)
		}
	}
}

func TestBlockedPaths_DelayedDeliveryKeepsTransitionsThroughRemoval(t *testing.T) {
	home := blockedTempDir(t)
	var mu sync.Mutex
	var next map[string]string
	var gate chan struct{}
	entered := make(chan struct{}, 1)
	live := NewLiveBlockedPaths(home, "", nil, func() BlockedReload {
		mu.Lock()
		problems, wait := next, gate
		mu.Unlock()
		if wait != nil {
			entered <- struct{}{}
			<-wait
		}
		return BlockedReload{Problems: problems}
	})
	set := func(problems map[string]string, wait chan struct{}) {
		mu.Lock()
		next, gate = problems, wait
		mu.Unlock()
	}
	queue := make(chan bool, 8)
	live.SetOnDegradedChange(func(degraded bool) { queue <- degraded })

	release := make(chan struct{})
	delivered := make(chan []bool, 1)
	go func() {
		<-release
		var got []bool
		for len(queue) > 0 {
			got = append(got, <-queue)
		}
		delivered <- got
	}()

	set(map[string]string{"/g/settings.yaml": "is not valid YAML"}, nil)
	live.Entries()
	set(nil, nil)
	live.Entries()

	wait := make(chan struct{})
	set(map[string]string{"/g/settings.yaml": "is missing"}, wait)
	queried := make(chan struct{})
	go func() {
		live.Entries()
		close(queried)
	}()
	<-entered
	removed := make(chan struct{})
	go func() {
		live.SetOnDegradedChange(nil)
		close(removed)
	}()
	select {
	case <-removed:
		t.Fatal("removal returned while a refresh that loaded the callback was still running")
	case <-time.After(20 * time.Millisecond):
	}
	close(wait)
	for _, done := range []chan struct{}{queried, removed} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("a query or the removal deadlocked behind the undelivered queue")
		}
	}

	set(nil, nil)
	finished := make(chan struct{})
	go func() {
		live.Entries()
		_ = live.Current()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("a query after removal blocked")
	}

	close(release)
	select {
	case got := <-delivered:
		if !slices.Equal(got, []bool{true, false, true}) {
			t.Fatalf("delivered = %v, want [true false true] in order with nothing lost or added after removal", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the delayed delivery never ran")
	}
}
