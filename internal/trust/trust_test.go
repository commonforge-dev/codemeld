package trust

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/locks"
	"codemeld.dev/codemeld/internal/sessions"
)

func canonical(t *testing.T, path string) string {
	t.Helper()
	root, err := sessions.CanonicalizeFolder(path)
	if err != nil {
		t.Fatalf("canonicalize %s: %v", path, err)
	}
	return root
}

func storeText(version int, roots ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "version: %d\nprojects:\n", version)
	for _, root := range roots {
		fmt.Fprintf(&b, "- %s\n", root)
	}
	return b.String()
}

func seedStoreBytes(t *testing.T, home, data string) {
	t.Helper()
	path := StorePath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir store dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write store: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod store: %v", err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func readStoreFile(t *testing.T, home string) Store {
	t.Helper()
	var store Store
	if err := yaml.Unmarshal([]byte(mustRead(t, StorePath(home))), &store); err != nil {
		t.Fatalf("decode store: %v", err)
	}
	return store
}

func mustRecord(t *testing.T, home, root string) {
	t.Helper()
	if err := Record(home, root); err != nil {
		t.Fatalf("Record(%s): %v", root, err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s -> %s: %v", link, target, err)
	}
}

type pathState struct {
	kind   fs.FileMode
	perm   fs.FileMode
	target string
	data   string
	mtime  time.Time
}

func snapshot(t *testing.T, path string) pathState {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	state := pathState{kind: info.Mode().Type(), perm: info.Mode().Perm(), mtime: info.ModTime()}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		if state.target, err = os.Readlink(path); err != nil {
			t.Fatalf("readlink %s: %v", path, err)
		}
	case info.Mode().IsRegular():
		state.data = mustRead(t, path)
	}
	return state
}

func assertLookup(t *testing.T, home, root string, want Decision) {
	t.Helper()
	if got := Lookup(home, root); got != want {
		t.Fatalf("Lookup(%s) = %#v, want %#v", root, got, want)
	}
}

func TestLookup_MissingStoreIsNoRecord(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	assertLookup(t, home, root, Decision{Reason: ReasonNoRecord, Root: canonical(t, root)})
	if _, err := os.Lstat(filepath.Dir(StorePath(home))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stat global dir = %v, want Lookup to create nothing", err)
	}
}

func TestLookup_UnresolvableRoot(t *testing.T) {
	home := t.TempDir()
	for _, root := range []string{"", filepath.Join(t.TempDir(), "missing")} {
		assertLookup(t, home, root, Decision{Reason: ReasonUnresolvedRoot})
	}
}

func TestLookup_IsExactMatch(t *testing.T) {
	parent := canonical(t, t.TempDir())
	child := filepath.Join(parent, "c")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatalf("mkdir child: %v", err)
	}

	parentHome := t.TempDir()
	mustRecord(t, parentHome, parent)
	assertLookup(t, parentHome, parent, Decision{Trusted: true, Reason: ReasonTrusted, Root: parent})
	assertLookup(t, parentHome, child, Decision{Reason: ReasonNoRecord, Root: child})

	childHome := t.TempDir()
	mustRecord(t, childHome, child)
	assertLookup(t, childHome, child, Decision{Trusted: true, Reason: ReasonTrusted, Root: child})
	assertLookup(t, childHome, parent, Decision{Reason: ReasonNoRecord, Root: parent})
}

func TestRecord_StoresTheCanonicalRootOfASymlinkAlias(t *testing.T) {
	home, real := t.TempDir(), canonical(t, t.TempDir())
	alias := filepath.Join(t.TempDir(), "link")
	symlink(t, real, alias)

	mustRecord(t, home, alias)

	if got := readStoreFile(t, home).Projects; !slices.Equal(got, []string{real}) {
		t.Fatalf("stored projects = %v, want only the resolved root %s", got, real)
	}
	for _, spelling := range []string{alias, real, real + string(filepath.Separator), filepath.Join(real, "x", "..")} {
		assertLookup(t, home, spelling, Decision{Trusted: true, Reason: ReasonTrusted, Root: real})
	}
}

func TestRecord_ExistingRootLeavesStoreUntouched(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	mustRecord(t, home, root)
	past := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(StorePath(home), past, past); err != nil {
		t.Fatalf("chtimes store: %v", err)
	}
	before := snapshot(t, StorePath(home))

	mustRecord(t, home, root)

	if after := snapshot(t, StorePath(home)); after != before {
		t.Fatalf("store changed on a repeat approval:\n got=%#v\nwant=%#v", after, before)
	}
}

func TestRecord_CreatesGlobalDirAndStore(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	mustRecord(t, home, root)

	info, err := os.Lstat(StorePath(home))
	if err != nil {
		t.Fatalf("stat store: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != storePerm {
		t.Fatalf("store = %v, want a regular file at 0600", info.Mode())
	}
	assertLookup(t, home, root, Decision{Trusted: true, Reason: ReasonTrusted, Root: canonical(t, root)})
}

func TestRecord_WritesVersionedSequenceByAtomicReplaceAt0600(t *testing.T) {
	home, first, second := t.TempDir(), canonical(t, t.TempDir()), canonical(t, t.TempDir())
	mustRecord(t, home, first)
	firstInfo, err := os.Stat(StorePath(home))
	if err != nil {
		t.Fatalf("stat store: %v", err)
	}
	mustRecord(t, home, second)

	secondInfo, err := os.Stat(StorePath(home))
	if err != nil {
		t.Fatalf("stat store: %v", err)
	}
	if perm := secondInfo.Mode().Perm(); perm != storePerm {
		t.Fatalf("store perm = %04o, want 0600", perm)
	}
	if os.SameFile(firstInfo, secondInfo) {
		t.Fatal("second Record rewrote the store in place, want a new file renamed over it")
	}

	raw := mustRead(t, StorePath(home))
	if !strings.HasPrefix(raw, "version: 1\n") {
		t.Fatalf("store = %q, want it to open with `version: 1`", raw)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("decode store: %v", err)
	}
	if len(doc) != 2 || fmt.Sprint(doc["version"]) != "1" {
		t.Fatalf("store = %#v, want exactly version and projects keys", doc)
	}
	seq, ok := doc["projects"].([]any)
	if !ok || len(seq) != 2 || seq[0] != first || seq[1] != second {
		t.Fatalf("projects = %#v, want the sequence [%s %s]", doc["projects"], first, second)
	}

	entries, err := os.ReadDir(filepath.Dir(StorePath(home)))
	if err != nil {
		t.Fatalf("read global dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := []string{"approved-projects.yaml", "approved-projects.yaml" + lockSuffix}
	if !slices.Equal(names, want) {
		t.Fatalf("global dir holds %v, want %v and no temp residue", names, want)
	}
}

func TestRecord_UnresolvableRootWritesNothing(t *testing.T) {
	home := t.TempDir()
	for _, root := range []string{"", filepath.Join(t.TempDir(), "missing")} {
		if err := Record(home, root); err == nil {
			t.Fatalf("Record(%q) succeeded", root)
		}
	}
	if _, err := os.Lstat(filepath.Join(home, ".codemeld")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stat .codemeld = %v, want nothing written", err)
	}
}

func TestStore_EmptyProjectsIsAnEmptyList(t *testing.T) {
	for name, text := range map[string]string{
		"projects missing": "version: 1\n",
		"projects empty":   "version: 1\nprojects:\n",
		"projects null":    "version: 1\nprojects: null\n",
		"projects []":      "version: 1\nprojects: []\n",
	} {
		t.Run(name, func(t *testing.T) {
			home, root := t.TempDir(), canonical(t, t.TempDir())
			seedStoreBytes(t, home, text)

			assertLookup(t, home, root, Decision{Reason: ReasonNoRecord, Root: root})
			mustRecord(t, home, root)
			if got := readStoreFile(t, home).Projects; !slices.Equal(got, []string{root}) {
				t.Fatalf("stored projects = %v, want [%s]", got, root)
			}
		})
	}
}

func TestStore_DeadRootStaysReadableAndIsPreserved(t *testing.T) {
	home, root := t.TempDir(), canonical(t, t.TempDir())
	dead := filepath.Join(canonical(t, t.TempDir()), "gone")
	seedStoreBytes(t, home, storeText(Version, dead))

	assertLookup(t, home, root, Decision{Reason: ReasonNoRecord, Root: root})
	mustRecord(t, home, root)
	if got := readStoreFile(t, home).Projects; !slices.Equal(got, []string{dead, root}) {
		t.Fatalf("stored projects = %v, want [%s %s]", got, dead, root)
	}
}

func TestStore_UnreadableApprovesNothingAndIsNeverOverwritten(t *testing.T) {
	type setup func(t *testing.T, home, root string)
	perm := func(p fs.FileMode) setup {
		return func(t *testing.T, home, root string) {
			seedStoreBytes(t, home, storeText(Version, root))
			if err := os.Chmod(StorePath(home), p); err != nil {
				t.Fatalf("chmod store: %v", err)
			}
		}
	}
	text := func(f func(t *testing.T, root string) string) setup {
		return func(t *testing.T, home, root string) { seedStoreBytes(t, home, f(t, root)) }
	}

	cases := []struct {
		name  string
		setup setup
	}{
		{"symlink to a valid store", func(t *testing.T, home, root string) {
			decoy := t.TempDir()
			mustRecord(t, decoy, root)
			if err := os.MkdirAll(filepath.Dir(StorePath(home)), 0o755); err != nil {
				t.Fatalf("mkdir store dir: %v", err)
			}
			symlink(t, StorePath(decoy), StorePath(home))
		}},
		{"dangling symlink", func(t *testing.T, home, _ string) {
			if err := os.MkdirAll(filepath.Dir(StorePath(home)), 0o755); err != nil {
				t.Fatalf("mkdir store dir: %v", err)
			}
			symlink(t, filepath.Join(home, "absent.yaml"), StorePath(home))
		}},
		{"directory", func(t *testing.T, home, _ string) {
			if err := os.MkdirAll(StorePath(home), 0o700); err != nil {
				t.Fatalf("mkdir store path: %v", err)
			}
		}},
		{"fifo", func(t *testing.T, home, _ string) {
			if err := os.MkdirAll(filepath.Dir(StorePath(home)), 0o755); err != nil {
				t.Fatalf("mkdir store dir: %v", err)
			}
			if err := syscall.Mkfifo(StorePath(home), 0o600); err != nil {
				t.Fatalf("mkfifo store: %v", err)
			}
		}},
		{"perm 0640", perm(0o640)},
		{"perm 0644", perm(0o644)},
		{"perm 0604", perm(0o604)},
		{"perm 0400", perm(0o400)},
		{"perm 0700", perm(0o700)},
		{"yaml parse failure", text(func(*testing.T, string) string { return "\tnot: [yaml\n" })},
		{"truncated", text(func(_ *testing.T, root string) string { return "version: 1\nprojects: [" + root })},
		{"empty file", text(func(*testing.T, string) string { return "" })},
		{"projects is a mapping", text(func(_ *testing.T, root string) string {
			return "version: 1\nprojects:\n  " + root + ": yes\n"
		})},
		{"unknown version", text(func(_ *testing.T, root string) string { return storeText(Version+1, root) })},
		{"zero version", text(func(_ *testing.T, root string) string { return storeText(0, root) })},
		{"missing version", text(func(_ *testing.T, root string) string { return "projects:\n- " + root + "\n" })},
		{"duplicate root", text(func(_ *testing.T, root string) string { return storeText(Version, root, root) })},
		{"relative root", text(func(_ *testing.T, root string) string { return storeText(Version, root, "relative/root") })},
		{"empty root", text(func(_ *testing.T, root string) string { return storeText(Version, root, `""`) })},
		{"uncleaned root", text(func(_ *testing.T, root string) string { return storeText(Version, root, "/x/../y") })},
		{"trailing separator", text(func(t *testing.T, root string) string {
			return storeText(Version, root, canonical(t, t.TempDir())+"/")
		})},
		{"symlink spelling of an existing dir", text(func(t *testing.T, root string) string {
			alias := filepath.Join(t.TempDir(), "alias")
			symlink(t, canonical(t, t.TempDir()), alias)
			return storeText(Version, root, alias)
		})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, root, other := t.TempDir(), canonical(t, t.TempDir()), t.TempDir()
			tc.setup(t, home, root)
			before := snapshot(t, StorePath(home))

			assertLookup(t, home, root, Decision{Reason: ReasonUnreadable, Root: root})
			for _, r := range []string{other, root} {
				if err := Record(home, r); err == nil {
					t.Fatalf("Record(%s) succeeded against an unreadable store", r)
				}
			}
			if after := snapshot(t, StorePath(home)); after != before {
				t.Fatalf("store path changed:\n got=%#v\nwant=%#v", after, before)
			}
		})
	}
}

func TestLookup_StoreSwappedForSymlinkBeforeOpenIsUnreadable(t *testing.T) {
	home, decoy, root := t.TempDir(), t.TempDir(), canonical(t, t.TempDir())
	mustRecord(t, home, root)
	mustRecord(t, decoy, root)

	original := openStore
	openStore = func(path string) (*os.File, error) {
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove store before open: %v", err)
		}
		symlink(t, StorePath(decoy), path)
		return original(path)
	}
	t.Cleanup(func() { openStore = original })

	assertLookup(t, home, root, Decision{Reason: ReasonUnreadable, Root: root})
}

func TestRecord_ReadsAndWritesUnderTheSidecarLock(t *testing.T) {
	home, mine, theirs := t.TempDir(), canonical(t, t.TempDir()), canonical(t, t.TempDir())
	if err := os.MkdirAll(filepath.Dir(StorePath(home)), 0o755); err != nil {
		t.Fatalf("mkdir store dir: %v", err)
	}
	release, reason, err := locks.Acquire(StorePath(home)+lockSuffix, lockTimeout)
	if reason != locks.ReasonNone {
		t.Fatalf("hold sidecar lock: %v (%s)", err, reason)
	}

	done := make(chan error, 1)
	go func() { done <- Record(home, mine) }()

	select {
	case err := <-done:
		release()
		t.Fatalf("Record returned %v while another holder owned the sidecar lock", err)
	case <-time.After(300 * time.Millisecond):
	}
	seedStoreBytes(t, home, storeText(Version, theirs))
	release()

	if err := <-done; err != nil {
		t.Fatalf("Record after release: %v", err)
	}
	if got := readStoreFile(t, home).Projects; !slices.Equal(got, []string{theirs, mine}) {
		t.Fatalf("stored projects = %v, want the write made under the lock kept and %s appended", got, mine)
	}
}

func TestRecord_FailsWhileTheSidecarLockIsHeld(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	mustRecord(t, home, t.TempDir())
	before := mustRead(t, StorePath(home))

	release, reason, err := locks.Acquire(StorePath(home)+lockSuffix, lockTimeout)
	if reason != locks.ReasonNone {
		t.Fatalf("hold sidecar lock: %v (%s)", err, reason)
	}
	defer release()

	if err := Record(home, root); err == nil {
		t.Fatal("Record succeeded while another holder owned the sidecar lock")
	}
	if after := mustRead(t, StorePath(home)); after != before {
		t.Fatalf("store bytes changed:\n got=%q\nwant=%q", after, before)
	}
}

func TestRecord_ConcurrentApprovalsAllSurvive(t *testing.T) {
	home := t.TempDir()
	roots := make([]string, 8)
	for i := range roots {
		roots[i] = canonical(t, t.TempDir())
	}

	var wg sync.WaitGroup
	errs := make([]error, len(roots))
	for i, root := range roots {
		wg.Go(func() { errs[i] = Record(home, root) })
	}
	wg.Wait()

	for i, root := range roots {
		if errs[i] != nil {
			t.Fatalf("Record(%s): %v", root, errs[i])
		}
		assertLookup(t, home, root, Decision{Trusted: true, Reason: ReasonTrusted, Root: root})
	}
	if got := readStoreFile(t, home).Projects; len(got) != len(roots) {
		t.Fatalf("stored projects = %v, want %d distinct roots", got, len(roots))
	}
}

func TestRecord_PublicationFailures(t *testing.T) {
	sentinel := errors.New("sync failed")

	t.Run("write failure leaves prior bytes", func(t *testing.T) {
		home, root := t.TempDir(), t.TempDir()
		mustRecord(t, home, t.TempDir())
		before := mustRead(t, StorePath(home))

		restore := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
		defer restore()
		if err := Record(home, root); err == nil {
			t.Fatal("Record succeeded despite a write failure")
		}
		if after := mustRead(t, StorePath(home)); after != before {
			t.Fatalf("store bytes changed:\n got=%q\nwant=%q", after, before)
		}
	})

	t.Run("parent sync failure errors but leaves a complete store", func(t *testing.T) {
		home, root := t.TempDir(), canonical(t, t.TempDir())

		restore := fsutil.SetSyncDirForTest(func(*os.File) error { return sentinel })
		defer restore()
		if err := Record(home, root); err == nil {
			t.Fatal("Record reported success despite an unsynced parent directory")
		}
		restore()

		assertLookup(t, home, root, Decision{Trusted: true, Reason: ReasonTrusted, Root: root})
	})
}

func TestStore_LegacyTrustFileIsNeitherReadNorModified(t *testing.T) {
	home, listed, other := t.TempDir(), canonical(t, t.TempDir()), canonical(t, t.TempDir())
	legacy := filepath.Join(filepath.Dir(StorePath(home)), "trust.yaml")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o755); err != nil {
		t.Fatalf("mkdir global dir: %v", err)
	}
	if err := os.WriteFile(legacy, []byte(storeText(Version, listed)), 0o600); err != nil {
		t.Fatalf("write trust.yaml: %v", err)
	}
	past := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(legacy, past, past); err != nil {
		t.Fatalf("chtimes trust.yaml: %v", err)
	}
	before := snapshot(t, legacy)

	assertLookup(t, home, listed, Decision{Reason: ReasonNoRecord, Root: listed})
	mustRecord(t, home, other)
	assertLookup(t, home, listed, Decision{Reason: ReasonNoRecord, Root: listed})
	assertLookup(t, home, other, Decision{Trusted: true, Reason: ReasonTrusted, Root: other})

	if after := snapshot(t, legacy); after != before {
		t.Fatalf("trust.yaml changed:\n got=%#v\nwant=%#v", after, before)
	}
	if got := readStoreFile(t, home).Projects; !slices.Equal(got, []string{other}) {
		t.Fatalf("stored projects = %v, want only [%s]", got, other)
	}
}
