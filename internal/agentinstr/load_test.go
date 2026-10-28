// Tests for AGENTS.md discovery (global + farthest-first walk, dedup, load_order,
// size/unreadable skips, unreadable-directory continuation) and the event replay
// helper's field preservation.
package agentinstr

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/sessions"
)

// fakeFile describes a stat/read result for one path in the fake filesystem.
type fakeFile struct {
	size    int64
	content []byte
	statErr error // forces a non-not-exist stat failure when set
	readErr error // forces a readFile failure when set
}

// fakeFS installs in-memory stat/readFile/readDir seams so the walk is fully
// deterministic and never touches the real filesystem above the test inputs.
type fakeFS struct {
	files          map[string]fakeFile
	unreadableDirs map[string]bool
}

func (f *fakeFS) install(t *testing.T) {
	t.Helper()
	origStat, origLstat, origRead, origDir := stat, lstat, readFile, readDir
	t.Cleanup(func() { stat, lstat, readFile, readDir = origStat, origLstat, origRead, origDir })

	stat = func(path string) (os.FileInfo, error) {
		fl, ok := f.files[path]
		if !ok {
			return nil, &os.PathError{Op: "stat", Path: path, Err: syscall.ENOENT}
		}
		if fl.statErr != nil {
			return nil, &os.PathError{Op: "stat", Path: path, Err: fl.statErr}
		}
		return fakeInfo{name: filepath.Base(path), size: fl.size}, nil
	}
	lstat = stat
	readFile = func(path string, _ int) ([]byte, error) {
		fl, ok := f.files[path]
		if !ok {
			return nil, &os.PathError{Op: "open", Path: path, Err: syscall.ENOENT}
		}
		if fl.readErr != nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: fl.readErr}
		}
		return fl.content, nil
	}
	readDir = func(dir string) ([]os.DirEntry, error) {
		if f.unreadableDirs[dir] {
			return nil, &os.PathError{Op: "open", Path: dir, Err: syscall.EACCES}
		}
		return nil, nil
	}
}

// fakeInfo is a minimal os.FileInfo exposing the size and name the loader reads.
type fakeInfo struct {
	name string
	size int64
}

func (fi fakeInfo) Name() string       { return fi.name }
func (fi fakeInfo) Size() int64        { return fi.size }
func (fi fakeInfo) Mode() os.FileMode  { return 0o644 }
func (fi fakeInfo) ModTime() time.Time { return time.Time{} }
func (fi fakeInfo) IsDir() bool        { return false }
func (fi fakeInfo) Sys() any           { return nil }

// loaded returns a present, readable file of the given content.
func loaded(content string) fakeFile {
	return fakeFile{size: int64(len(content)), content: []byte(content)}
}

func load(t *testing.T, home, launchDir string, maxBytes int) []LoadEntry {
	t.Helper()
	got, err := LoadAgentInstructions(home, launchDir, maxBytes, Selection{})
	if err != nil {
		t.Fatalf("LoadAgentInstructions() error = %v", err)
	}
	return got
}

func wantEntry(t *testing.T, e LoadEntry, path, layer string, order int) {
	t.Helper()
	if e.Path != path {
		t.Errorf("Path = %q, want %q", e.Path, path)
	}
	if e.Layer != layer {
		t.Errorf("%s: Layer = %q, want %q", path, e.Layer, layer)
	}
	if e.LoadOrder != order {
		t.Errorf("%s: LoadOrder = %d, want %d", path, e.LoadOrder, order)
	}
}

func TestLoadAgentInstructions_GlobalAndWalkedMerged(t *testing.T) {
	const home = "/home/u"
	globalPath := filepath.Join(home, ".codemeld", "global", "AGENTS.md")
	fs := &fakeFS{files: map[string]fakeFile{
		globalPath:               loaded("global"),
		"/home/AGENTS.md":        loaded("home"),
		"/home/u/proj/AGENTS.md": loaded("proj"),
	}}
	fs.install(t)

	got := load(t, home, "/home/u/proj", 65536)
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(got), got)
	}
	// Global first (order 1), then farthest-first walk: /home before /home/u/proj.
	wantEntry(t, got[0], globalPath, LayerGlobal, 1)
	wantEntry(t, got[1], "/home/AGENTS.md", LayerWalked, 2)
	wantEntry(t, got[2], "/home/u/proj/AGENTS.md", LayerWalked, 3)
	if string(got[2].Content) != "proj" {
		t.Errorf("walked content = %q, want %q", got[2].Content, "proj")
	}
	for _, e := range got {
		if e.Skipped {
			t.Errorf("%s unexpectedly skipped: %+v", e.Path, e)
		}
	}
}

func TestLoadAgentInstructions_GlobalAbsentSilent(t *testing.T) {
	const home = "/home/u"
	fs := &fakeFS{files: map[string]fakeFile{
		"/home/u/proj/AGENTS.md": loaded("proj"),
	}}
	fs.install(t)

	got := load(t, home, "/home/u/proj", 65536)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(got), got)
	}
	// Global absent yields no entry, and the first walked entry still starts at 2.
	wantEntry(t, got[0], "/home/u/proj/AGENTS.md", LayerWalked, 2)
}

func TestLoadAgentInstructions_OversizeSkipsSizeLimit(t *testing.T) {
	const home = "/home/u"
	fs := &fakeFS{files: map[string]fakeFile{
		"/home/u/proj/AGENTS.md": {size: 11, content: []byte("01234567890")},
	}}
	fs.install(t)

	got := load(t, home, "/home/u/proj", 10) // cap 10 < size 11
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(got), got)
	}
	e := got[0]
	if !e.Skipped || e.SkipReason != SkipSizeLimit {
		t.Fatalf("Skipped=%v SkipReason=%q, want true/size_limit", e.Skipped, e.SkipReason)
	}
	if e.Content != nil {
		t.Errorf("Content = %q, want nil on size skip", e.Content)
	}
	if e.ErrorCategory != "" || e.ErrorDetail != "" {
		t.Errorf("size skip carried error fields: cat=%q detail=%q", e.ErrorCategory, e.ErrorDetail)
	}
}

func TestLoadAgentInstructions_SizeAtCapAllowed(t *testing.T) {
	const home = "/home/u"
	fs := &fakeFS{files: map[string]fakeFile{
		"/home/u/proj/AGENTS.md": {size: 10, content: []byte("0123456789")},
	}}
	fs.install(t)

	got := load(t, home, "/home/u/proj", 10) // size == cap is allowed
	if len(got) != 1 || got[0].Skipped {
		t.Fatalf("size-at-cap should load, got %+v", got)
	}
}

func TestLoadAgentInstructions_UnreadableFileSkips(t *testing.T) {
	const home = "/home/u"
	t.Run("read fails", func(t *testing.T) {
		fs := &fakeFS{files: map[string]fakeFile{
			"/home/u/proj/AGENTS.md": {size: 5, readErr: syscall.EACCES},
		}}
		fs.install(t)

		got := load(t, home, "/home/u/proj", 65536)
		if len(got) != 1 {
			t.Fatalf("got %d entries, want 1: %+v", len(got), got)
		}
		e := got[0]
		if !e.Skipped || e.SkipReason != SkipUnreadable {
			t.Fatalf("Skipped=%v SkipReason=%q, want true/unreadable", e.Skipped, e.SkipReason)
		}
		if e.ErrorCategory != fserrors.PermissionDenied {
			t.Errorf("ErrorCategory = %q, want %q", e.ErrorCategory, fserrors.PermissionDenied)
		}
		if e.ErrorDetail == "" {
			t.Error("ErrorDetail is empty on unreadable skip")
		}
	})

	t.Run("stat fails", func(t *testing.T) {
		fs := &fakeFS{files: map[string]fakeFile{
			"/home/u/proj/AGENTS.md": {statErr: syscall.EIO},
		}}
		fs.install(t)

		got := load(t, home, "/home/u/proj", 65536)
		if len(got) != 1 {
			t.Fatalf("got %d entries, want 1: %+v", len(got), got)
		}
		e := got[0]
		if !e.Skipped || e.SkipReason != SkipUnreadable {
			t.Fatalf("Skipped=%v SkipReason=%q, want true/unreadable", e.Skipped, e.SkipReason)
		}
		if e.ErrorCategory != fserrors.IOError {
			t.Errorf("ErrorCategory = %q, want %q", e.ErrorCategory, fserrors.IOError)
		}
	})
}

func TestLoadAgentInstructions_DedupGlobalAndWalked(t *testing.T) {
	const home = "/home/u"
	globalPath := filepath.Join(home, ".codemeld", "global", "AGENTS.md")
	fs := &fakeFS{files: map[string]fakeFile{
		globalPath: loaded("global"),
	}}
	fs.install(t)

	// Launch inside the global directory, so the walk's candidate for that
	// directory is exactly the global path.
	got := load(t, home, filepath.Join(home, ".codemeld", "global"), 65536)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 (loaded once via global): %+v", len(got), got)
	}
	wantEntry(t, got[0], globalPath, LayerGlobal, 1)
}

func TestLoadAgentInstructions_WalkReachesRootRegardlessOfBoundary(t *testing.T) {
	// The loader never consults discovery.boundary: it always walks to the
	// filesystem root. A file at the farthest ancestor (root) must be found from
	// a deep launch directory and ordered first in the walk.
	const home = "/home/u"
	fs := &fakeFS{files: map[string]fakeFile{
		"/AGENTS.md": loaded("root"),
	}}
	fs.install(t)

	got := load(t, home, "/home/u/proj/deep/nested", 65536)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(got), got)
	}
	wantEntry(t, got[0], "/AGENTS.md", LayerWalked, 2)
}

func TestLoadAgentInstructions_UnreadableDirectorySkippedAndWalkContinues(t *testing.T) {
	const home = "/home/u"
	fs := &fakeFS{
		files: map[string]fakeFile{
			"/home/AGENTS.md":        loaded("home"),
			"/home/u/proj/AGENTS.md": loaded("proj"),
			"/home/u/AGENTS.md":      loaded("should-never-be-listed"),
		},
		// /home/u is unreadable: its AGENTS.md must not appear, but the walk must
		// continue past it to /home/u/proj.
		unreadableDirs: map[string]bool{"/home/u": true},
	}
	fs.install(t)

	got := load(t, home, "/home/u/proj", 65536)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	wantEntry(t, got[0], "/home/AGENTS.md", LayerWalked, 2)
	wantEntry(t, got[1], "/home/u/proj/AGENTS.md", LayerWalked, 3)
	for _, e := range got {
		if e.Path == "/home/u/AGENTS.md" {
			t.Errorf("unreadable directory produced a file entry: %+v", e)
		}
	}
}

func TestLoadAgentInstructions_NoHomeSkipsGlobal(t *testing.T) {
	fs := &fakeFS{files: map[string]fakeFile{
		"/home/u/proj/AGENTS.md": loaded("proj"),
	}}
	fs.install(t)

	got := load(t, "", "/home/u/proj", 65536)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(got), got)
	}
	wantEntry(t, got[0], "/home/u/proj/AGENTS.md", LayerWalked, 2)
}

// newStore builds an empty in-memory session store for replay assertions.
func newStore(t *testing.T) *sessions.Store {
	t.Helper()
	return sessions.New("unused-in-tests", &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
			Folder:        "/home/u/proj",
			StartedAt:     time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC),
			UpdatedAt:     time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC),
			SchemaVersion: 1,
		},
	})
}

func TestReplay_EmitsLoadedAndSkippedWithPreservedFields(t *testing.T) {
	entries := []LoadEntry{
		{Path: "/home/u/.codemeld/global/AGENTS.md", Layer: LayerGlobal, LoadOrder: 1, Content: []byte("g")},
		{Path: "/home/AGENTS.md", Layer: LayerWalked, LoadOrder: 2, Content: []byte("h")},
		{Path: "/home/u/big/AGENTS.md", Layer: LayerWalked, LoadOrder: 3, Skipped: true, SkipReason: SkipSizeLimit},
		{
			Path: "/home/u/proj/AGENTS.md", Layer: LayerWalked, LoadOrder: 4,
			Skipped: true, SkipReason: SkipUnreadable,
			ErrorCategory: fserrors.PermissionDenied, ErrorDetail: "open AGENTS.md: permission denied",
		},
	}
	store := newStore(t)
	if err := Replay(store, entries); err != nil {
		t.Fatalf("Replay() error = %v", err)
	}

	recs := store.Records()
	if len(recs) != len(entries) {
		t.Fatalf("store has %d records, want %d", len(recs), len(entries))
	}
	for i, rec := range recs {
		ev, ok := rec.(sessions.Event)
		if !ok {
			t.Fatalf("record %d is %T, want sessions.Event", i, rec)
		}
		if ev.Kind != events.KindAgentInstructionsLoaded {
			t.Errorf("record %d kind = %q, want %q", i, ev.Kind, events.KindAgentInstructionsLoaded)
		}
		// The reloaded bytes must satisfy the events load-time validator.
		if err := events.ValidatePayload(ev.Kind, ev.Payload); err != nil {
			t.Fatalf("record %d ValidatePayload() error = %v", i, err)
		}
		var got events.AgentInstructionsLoaded
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("record %d unmarshal payload: %v", i, err)
		}
		src := entries[i]
		if got.Path != src.Path || got.Layer != src.Layer || got.LoadOrder != int64(src.LoadOrder) {
			t.Errorf("record %d = %+v, want path/layer/order %q/%q/%d", i, got, src.Path, src.Layer, src.LoadOrder)
		}
		wantReason := ""
		if src.Skipped {
			wantReason = src.SkipReason
		}
		if got.SkipReason != wantReason {
			t.Errorf("record %d SkipReason = %q, want %q", i, got.SkipReason, wantReason)
		}
		if src.SkipReason == SkipUnreadable {
			if got.ErrorCategory != string(src.ErrorCategory) || got.ErrorDetail != src.ErrorDetail {
				t.Errorf("record %d error fields = %q/%q, want %q/%q", i, got.ErrorCategory, got.ErrorDetail, src.ErrorCategory, src.ErrorDetail)
			}
		} else if got.ErrorCategory != "" || got.ErrorDetail != "" {
			t.Errorf("record %d carried error fields on non-unreadable: %q/%q", i, got.ErrorCategory, got.ErrorDetail)
		}
	}
}

func TestReplay_PropagatesAppendError(t *testing.T) {
	// A walked entry with load_order 1 is rejected by the events validator
	// (walked must be >= 2), so Replay must surface that error.
	bad := []LoadEntry{{Path: "/home/u/proj/AGENTS.md", Layer: LayerWalked, LoadOrder: 1, Content: []byte("x")}}
	if err := Replay(newStore(t), bad); err == nil {
		t.Fatal("Replay() with an invalid entry did not error")
	}
}

func findByPath(t *testing.T, entries []LoadEntry, path string) LoadEntry {
	t.Helper()
	for _, e := range entries {
		if e.Path == path {
			return e
		}
	}
	t.Fatalf("no entry for %s in %+v", path, entries)
	return LoadEntry{}
}

// A candidate whose opened target is not a regular file must terminate as an unreadable
// skip: the walk may neither block in open(2) nor stream an unbounded source.
func TestLoadAgentInstructions_NonRegularCandidateIsABoundedUnreadableSkip(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{"fifo", func(t *testing.T, path string) {
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatalf("mkfifo: %v", err)
			}
		}},
		{"symlink to a directory", func(t *testing.T, path string) {
			if err := os.Symlink(t.TempDir(), path); err != nil {
				t.Fatalf("symlink: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			launchDir := t.TempDir()
			path := filepath.Join(launchDir, FileName)
			tc.setup(t, path)

			reads := 0
			restore := readLimited
			t.Cleanup(func() { readLimited = restore })
			readLimited = func(f *os.File, limit int64) ([]byte, error) {
				reads++
				return restore(f, limit)
			}

			type result struct {
				entries []LoadEntry
				err     error
			}
			done := make(chan result, 1)
			go func() {
				entries, err := LoadAgentInstructions("", launchDir, 1<<20, Selection{})
				done <- result{entries, err}
			}()

			select {
			case got := <-done:
				if got.err != nil {
					t.Fatalf("LoadAgentInstructions: %v", got.err)
				}
				entry := findByPath(t, got.entries, path)
				if !entry.Skipped || entry.SkipReason != SkipUnreadable {
					t.Fatalf("entry = %+v, want an %q skip", entry, SkipUnreadable)
				}
				if reads != 0 {
					t.Fatalf("readLimited called %d times, want a non-regular target rejected before any read", reads)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the walk blocked on a non-regular candidate instead of skipping it")
			}
		})
	}
}

func TestLoadAgentInstructions_UnstableLengthIsAnUnreadableSkip(t *testing.T) {
	for _, tc := range []struct {
		name string
		read func(*os.File, int64) ([]byte, error)
	}{
		{"short read", func(*os.File, int64) ([]byte, error) { return []byte("x"), nil }},
		{"overlong read", func(_ *os.File, limit int64) ([]byte, error) { return make([]byte, limit), nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			launchDir := t.TempDir()
			path := filepath.Join(launchDir, FileName)
			if err := os.WriteFile(path, []byte("# repo instructions\n"), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			restore := readLimited
			t.Cleanup(func() { readLimited = restore })
			readLimited = tc.read

			entry := findByPath(t, load(t, "", launchDir, 1<<20), path)
			if !entry.Skipped || entry.SkipReason != SkipUnreadable {
				t.Fatalf("entry = %+v, want an %q skip", entry, SkipUnreadable)
			}
		})
	}
}

// A candidate that grows past the cap between the first stat and the open must stay a
// size_limit skip: the opened target's own snapshot is what bounds the read.
func TestLoadAgentInstructions_OverCapAfterOpenIsASizeLimitSkip(t *testing.T) {
	launchDir := t.TempDir()
	path := filepath.Join(launchDir, FileName)
	if err := os.WriteFile(path, make([]byte, 64), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	origStat := stat
	t.Cleanup(func() { stat = origStat })
	stat = func(p string) (os.FileInfo, error) {
		info, err := origStat(p)
		if err != nil || p != path {
			return info, err
		}
		return fakeInfo{name: filepath.Base(p), size: 1}, nil
	}

	reads := 0
	restore := readLimited
	t.Cleanup(func() { readLimited = restore })
	readLimited = func(f *os.File, limit int64) ([]byte, error) {
		reads++
		return restore(f, limit)
	}

	entry := findByPath(t, load(t, "", launchDir, 8), path)
	if !entry.Skipped || entry.SkipReason != SkipSizeLimit {
		t.Fatalf("entry = %+v, want a %q skip", entry, SkipSizeLimit)
	}
	if reads != 0 {
		t.Fatalf("readLimited called %d times, want an over-cap target rejected before any read", reads)
	}
}

// A dangling AGENTS.md symlink is located but unresolvable, so it is an unreadable skip
// rather than an absent candidate the filter never sees.
func TestLoadAgentInstructions_DanglingSymlinkIsAnUnreadableSkip(t *testing.T) {
	launchDir := t.TempDir()
	path := filepath.Join(launchDir, FileName)
	if err := os.Symlink(filepath.Join(launchDir, "missing-target"), path); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	reads := 0
	restore := readLimited
	t.Cleanup(func() { readLimited = restore })
	readLimited = func(f *os.File, limit int64) ([]byte, error) {
		reads++
		return restore(f, limit)
	}

	entry := findByPath(t, load(t, "", launchDir, 1<<20), path)
	if !entry.Skipped || entry.SkipReason != SkipUnreadable {
		t.Fatalf("entry = %+v, want an %q skip", entry, SkipUnreadable)
	}
	if reads != 0 {
		t.Fatalf("readLimited called %d times, want an unresolvable candidate rejected before any read", reads)
	}
}

func TestLoadAgentInstructions_RegularCandidateStillLoadsThroughTheBoundedReader(t *testing.T) {
	launchDir := t.TempDir()
	path := filepath.Join(launchDir, FileName)
	const content = "# repo instructions\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	entry := findByPath(t, load(t, "", launchDir, 1<<20), path)
	if entry.Skipped || string(entry.Content) != content {
		t.Fatalf("entry = %+v, want the file loaded with its exact bytes", entry)
	}
}

func forbidIO(t *testing.T) {
	t.Helper()
	origStat, origLstat, origRead, origDir, origOpen := stat, lstat, readFile, readDir, openCandidate
	t.Cleanup(func() {
		stat, lstat, readFile, readDir, openCandidate = origStat, origLstat, origRead, origDir, origOpen
	})
	fail := func(path string) error {
		t.Errorf("unexpected filesystem access to %s", path)
		return &os.PathError{Op: "forbidden", Path: path, Err: syscall.EPERM}
	}
	stat = func(p string) (os.FileInfo, error) { return nil, fail(p) }
	lstat = stat
	readFile = func(p string, _ int) ([]byte, error) { return nil, fail(p) }
	readDir = func(p string) ([]os.DirEntry, error) { return nil, fail(p) }
	openCandidate = func(p string) (*os.File, error) { return nil, fail(p) }
}

func loadSel(t *testing.T, home, launchDir string, maxBytes int, sel Selection) []LoadEntry {
	t.Helper()
	got, err := LoadAgentInstructions(home, launchDir, maxBytes, sel)
	if err != nil {
		t.Fatalf("LoadAgentInstructions(%+v) error = %v", sel, err)
	}
	return got
}

func TestLoadAgentInstructions_InvalidSelectionErrorsBeforeAnyIO(t *testing.T) {
	for name, sel := range map[string]Selection{
		"unknown mode":           {Mode: SelectionMode(99)},
		"negative mode":          {Mode: SelectionMode(-1), Path: "/abs/AGENTS.md"},
		"explicit empty path":    {Mode: ExplicitFile},
		"explicit relative path": {Mode: ExplicitFile, Path: "rel/AGENTS.md"},
	} {
		t.Run(name, func(t *testing.T) {
			forbidIO(t)
			got, err := LoadAgentInstructions("/home/u", "/home/u/proj", 65536, sel)
			if err == nil || got != nil {
				t.Fatalf("got %+v, %v; want nil entries and an error", got, err)
			}
		})
	}
}

func TestLoadAgentInstructions_DiscoverNoneReadsNothing(t *testing.T) {
	forbidIO(t)
	if got := loadSel(t, "/home/u", "/home/u/proj", 65536, Selection{Mode: DiscoverNone, Path: "ignored"}); len(got) != 0 {
		t.Fatalf("got %+v, want no entries", got)
	}
}

func TestLoadAgentInstructions_DiscoverAllIgnoresPath(t *testing.T) {
	const home = "/home/u"
	globalPath := filepath.Join(home, ".codemeld", "global", "AGENTS.md")
	fs := &fakeFS{files: map[string]fakeFile{
		globalPath:               loaded("global"),
		"/home/u/proj/AGENTS.md": loaded("proj"),
	}}
	fs.install(t)

	got := loadSel(t, home, "/home/u/proj", 65536, Selection{Mode: DiscoverAll, Path: "not/absolute"})
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	wantEntry(t, got[0], globalPath, LayerGlobal, 1)
	wantEntry(t, got[1], "/home/u/proj/AGENTS.md", LayerWalked, 2)
}

func TestLoadAgentInstructions_DiscoverAllButLaunchDirDropsOnlyTheLaunchFile(t *testing.T) {
	const home = "/home/u"
	globalPath := filepath.Join(home, ".codemeld", "global", "AGENTS.md")
	fs := &fakeFS{files: map[string]fakeFile{
		globalPath:               loaded("global"),
		"/home/u/AGENTS.md":      loaded("same"),
		"/home/u/proj/AGENTS.md": loaded("same"),
	}}
	fs.install(t)

	got := loadSel(t, home, "/home/u/proj", 65536, Selection{Mode: DiscoverAllButLaunchDir, Path: "not/absolute"})
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	wantEntry(t, got[0], globalPath, LayerGlobal, 1)
	wantEntry(t, got[1], "/home/u/AGENTS.md", LayerWalked, 2)
}

func TestLoadAgentInstructions_DiscoverAllButLaunchDirKeepsGlobalWhenLaunchedThere(t *testing.T) {
	const home = "/home/u"
	globalDir := filepath.Join(home, ".codemeld", "global")
	globalPath := filepath.Join(globalDir, "AGENTS.md")
	fs := &fakeFS{files: map[string]fakeFile{globalPath: loaded("global")}}
	fs.install(t)

	got := loadSel(t, home, globalDir, 65536, Selection{Mode: DiscoverAllButLaunchDir})
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(got), got)
	}
	wantEntry(t, got[0], globalPath, LayerGlobal, 1)
}

func TestLoadAgentInstructions_ExplicitFileReplacesDiscovery(t *testing.T) {
	const home = "/home/u"
	globalPath := filepath.Join(home, ".codemeld", "global", "AGENTS.md")
	fs := &fakeFS{files: map[string]fakeFile{
		globalPath:               loaded("global"),
		"/home/u/proj/AGENTS.md": loaded("proj"),
		"/elsewhere/custom.md":   loaded("custom"),
		"/elsewhere/big.md":      {size: 11, content: []byte("01234567890")},
		"/elsewhere/denied.md":   {size: 5, readErr: syscall.EACCES},
		"/elsewhere/broken.md":   {statErr: syscall.EIO},
	}}
	fs.install(t)
	explicit := func(p string) []LoadEntry {
		return loadSel(t, home, "/home/u/proj", 10, Selection{Mode: ExplicitFile, Path: p})
	}

	t.Run("loaded and cleaned", func(t *testing.T) {
		got := explicit("/elsewhere/sub/../custom.md")
		if len(got) != 1 {
			t.Fatalf("got %d entries, want 1: %+v", len(got), got)
		}
		wantEntry(t, got[0], "/elsewhere/custom.md", LayerWalked, 2)
		if got[0].Skipped || string(got[0].Content) != "custom" {
			t.Fatalf("entry = %+v, want loaded verbatim", got[0])
		}
	})
	t.Run("global path is recorded as walked", func(t *testing.T) {
		got := explicit(globalPath)
		if len(got) != 1 {
			t.Fatalf("got %d entries, want 1: %+v", len(got), got)
		}
		wantEntry(t, got[0], globalPath, LayerWalked, 2)
	})
	t.Run("missing is silently absent", func(t *testing.T) {
		if got := explicit("/elsewhere/missing.md"); len(got) != 0 {
			t.Fatalf("got %+v, want no entries", got)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		got := explicit("/elsewhere/big.md")
		if len(got) != 1 {
			t.Fatalf("got %d entries, want 1: %+v", len(got), got)
		}
		wantEntry(t, got[0], "/elsewhere/big.md", LayerWalked, 2)
		if !got[0].Skipped || got[0].SkipReason != SkipSizeLimit || got[0].ErrorCategory != "" || got[0].ErrorDetail != "" {
			t.Fatalf("entry = %+v, want a bare size_limit skip", got[0])
		}
	})
	for name, tc := range map[string]struct {
		path string
		cat  fserrors.Category
	}{
		"unreadable on read": {"/elsewhere/denied.md", fserrors.PermissionDenied},
		"unreadable on stat": {"/elsewhere/broken.md", fserrors.IOError},
	} {
		t.Run(name, func(t *testing.T) {
			got := explicit(tc.path)
			if len(got) != 1 {
				t.Fatalf("got %d entries, want 1: %+v", len(got), got)
			}
			wantEntry(t, got[0], tc.path, LayerWalked, 2)
			if !got[0].Skipped || got[0].SkipReason != SkipUnreadable || got[0].ErrorCategory != tc.cat || got[0].ErrorDetail == "" {
				t.Fatalf("entry = %+v, want an unreadable skip with category %q and detail", got[0], tc.cat)
			}
		})
	}
}

func TestLoadAgentInstructions_ExplicitFileKeepsSymlinkAndNonRegularSemantics(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.md")
	if err := os.WriteFile(target, []byte("linked"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	link := filepath.Join(dir, "link.md")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	fifo := filepath.Join(dir, "fifo.md")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	got := loadSel(t, "", dir, 1<<20, Selection{Mode: ExplicitFile, Path: link})
	if len(got) != 1 || got[0].Path != link || got[0].Skipped || string(got[0].Content) != "linked" {
		t.Fatalf("got %+v, want the symlink path loaded unresolved", got)
	}

	for name, path := range map[string]string{"fifo": fifo, "directory": t.TempDir()} {
		t.Run(name, func(t *testing.T) {
			done := make(chan []LoadEntry, 1)
			go func() {
				entries, _ := LoadAgentInstructions("", dir, 1<<20, Selection{Mode: ExplicitFile, Path: path})
				done <- entries
			}()
			select {
			case got := <-done:
				if len(got) != 1 || got[0].Path != path || got[0].Layer != LayerWalked || got[0].LoadOrder != 2 ||
					!got[0].Skipped || got[0].SkipReason != SkipUnreadable {
					t.Fatalf("got %+v, want one walked/order-2 unreadable skip", got)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("explicit non-regular candidate blocked the load")
			}
		})
	}
}
