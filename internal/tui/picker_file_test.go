// Tests for the '@' file-reference picker: single-'@'-at-boundary trigger detection
// and paste suppression, '@query' token boundary parsing, contiguous substring matching,
// codemeldignore filtering through the injected Walk seam with directory trailing
// slashes, inline token replacement on select, literal-'@' preservation on ESC/no-match, the
// one-overlay-at-a-time guard, and focus restore — the pure helpers directly, the overlay
// behavior through App methods, and the live query field's SetChangedFunc/SetInputCapture wiring
// driven through the focused widget, mirroring picker_effort_test.go.
package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/filetools"
)

func TestDetectAtTrigger(t *testing.T) {
	cases := []struct {
		name   string
		prev   string
		cur    string
		wantAt int
		wantOK bool
	}{
		{"into empty buffer", "", "@", 0, true},
		{"after a space", "foo ", "foo @", 4, true},
		{"after a newline", "a\n", "a\n@", 2, true},
		{"after a tab", "x\t", "x\t@", 2, true},
		{"after a word is not a boundary", "foo", "foo@", 0, false},
		{"single letter then @", "a", "a@", 0, false},
		{"mid-word insertion", "ab", "a@b", 0, false},
		{"second @ adjacent is not a boundary", "@", "@@", 0, false},
		{"non-ascii word char before @", "café", "café@", 0, false},
		{"non-ascii space before @ triggers", "é ", "é @", len("é "), true},
		// A bracketed paste arrives as a multi-rune change, so it never triggers — even
		// when the pasted text contains (or is) an '@' run.
		{"paste of @text", "", "@foo", 0, false},
		{"paste containing @", "x", "x @foo", 0, false},
		{"deletion", "@", "", 0, false},
		{"same-length replacement", "abc", "abd", 0, false},
		{"insert non-@ rune", "foo ", "foo a", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			at, ok := detectAtTrigger(tc.prev, tc.cur)
			if ok != tc.wantOK || (ok && at != tc.wantAt) {
				t.Errorf("detectAtTrigger(%q, %q) = (%d, %v), want (%d, %v)", tc.prev, tc.cur, at, ok, tc.wantAt, tc.wantOK)
			}
		})
	}
}

func TestFileRefTokenEnd(t *testing.T) {
	cases := []struct {
		name   string
		text   string
		atByte int
		want   int
	}{
		{"lone @", "@", 0, 1},
		{"@ plus run to end", "@foo", 0, 4},
		{"@ run stops at space", "@foo bar", 0, 4},
		{"@ mid buffer", "hello @foo", 6, 10},
		{"@ mid buffer stops at space", "hello @foo world", 6, 10},
		{"out of range offset returned unchanged", "abc", 5, 5},
		{"non-ascii run", "@résumé x", 0, len("@résumé")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fileRefTokenEnd(tc.text, tc.atByte); got != tc.want {
				t.Errorf("fileRefTokenEnd(%q, %d) = %d, want %d", tc.text, tc.atByte, got, tc.want)
			}
		})
	}
}

func TestFileRefSearch_CompleteCorpusAndBound(t *testing.T) {
	t.Run("unique match after more than 2000 nonmatches", func(t *testing.T) {
		root := t.TempDir()
		home := t.TempDir()
		for i := range 2100 {
			writeFile(t, filepath.Join(root, fmt.Sprintf("filler-%05d.txt", i)), "f")
		}
		writeFile(t, filepath.Join(root, "zz-unique-target.go"), "package z")

		got, err := collectFileRefSearch(t, context.Background(), root, home, "unique-target")
		if err != nil {
			t.Fatalf("searchFileRefs: %v", err)
		}
		if !slices.Equal(got, []string{"zz-unique-target.go"}) {
			t.Fatalf("got %v, want [zz-unique-target.go]; the producer must search the whole tree, not a prefix", got)
		}
	})

	t.Run("emits at most 50 matches in walker order", func(t *testing.T) {
		root := t.TempDir()
		home := t.TempDir()
		for i := range 60 {
			writeFile(t, filepath.Join(root, fmt.Sprintf("hit-%02d.txt", i)), "h")
		}

		got, err := collectFileRefSearch(t, context.Background(), root, home, "hit-")
		if err != nil {
			t.Fatalf("searchFileRefs: %v", err)
		}
		if len(got) != 50 {
			t.Fatalf("emitted %d matches, want 50", len(got))
		}
		want := make([]string, 50)
		for i := range want {
			want[i] = fmt.Sprintf("hit-%02d.txt", i)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("traversal continues past the bound to a later entry", func(t *testing.T) {
		root := t.TempDir()
		home := t.TempDir()
		for i := range 60 {
			writeFile(t, filepath.Join(root, fmt.Sprintf("hit-%02d.txt", i)), "h")
		}
		sentinel := filepath.Join(root, "zz-unreadable")
		if err := os.Mkdir(sentinel, 0o000); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(sentinel, 0o755) })

		got, err := collectFileRefSearch(t, context.Background(), root, home, "hit-")
		if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("err = %v, want the unreadable later directory's permission error; the producer stopped traversing at the bound", err)
		}
		if len(got) != 50 {
			t.Fatalf("emitted %d matches, want 50", len(got))
		}
	})
}

func TestFileRefSearch_MatchingAndDirectories(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	writeFile(t, filepath.Join(root, "Main.go"), "package x")
	writeFile(t, filepath.Join(root, "sub", "child.go"), "package y")
	writeFile(t, filepath.Join(root, "notes.md"), "n")

	cases := []struct {
		name  string
		query string
		want  []string
	}{
		{"empty query lists everything in walker order", "", []string{"Main.go", "notes.md", "sub/", "sub/child.go"}},
		{"case insensitive", "MAIN.GO", []string{"Main.go"}},
		{"directory keeps its trailing slash", "sub", []string{"sub/", "sub/child.go"}},
		{"matches the trailing slash itself", "sub/c", []string{"sub/child.go"}},
		{"contiguous only", "mngo", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := collectFileRefSearch(t, context.Background(), root, home, tc.query)
			if err != nil {
				t.Fatalf("searchFileRefs: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFileRefSearch_FiltersAndErrors(t *testing.T) {
	t.Run("hidden and ignored paths never reach the producer", func(t *testing.T) {
		root := t.TempDir()
		home := t.TempDir()
		writeFile(t, filepath.Join(root, "keep.txt"), "k")
		writeFile(t, filepath.Join(root, "ignored.txt"), "i")
		writeFile(t, filepath.Join(root, "build.log"), "l")
		writeFile(t, filepath.Join(root, "node_modules", "dep.js"), "x")
		writeFile(t, filepath.Join(root, ".hidden", "secret.txt"), "s")
		writeFile(t, filetools.ProjectCodemeldignorePath(root), "ignored.txt\nnode_modules\n")
		writeFile(t, filetools.GlobalCodemeldignorePath(home), "**/*.log\n")

		got, err := collectFileRefSearch(t, context.Background(), root, home, "")
		if err != nil {
			t.Fatalf("searchFileRefs: %v", err)
		}
		if !slices.Equal(got, []string{"keep.txt"}) {
			t.Fatalf("got %v, want [keep.txt]", got)
		}
	})

	t.Run("matcher construction failure returns before any result", func(t *testing.T) {
		root := t.TempDir()
		home := t.TempDir()
		writeFile(t, filepath.Join(root, "main.go"), "package x")
		writeFile(t, filetools.ProjectCodemeldignorePath(root), "[unterminated\n")

		got, err := collectFileRefSearch(t, context.Background(), root, home, "main")
		if err == nil {
			t.Fatal("expected a matcher error; the producer must never emit unfiltered results")
		}
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, context.Canceled) {
			t.Fatalf("matcher error %v is not distinguishable from a read or cancellation error", err)
		}
		if len(got) != 0 {
			t.Fatalf("emitted %v, want no results on a matcher failure", got)
		}
	})

	t.Run("traversal failure is a distinct error with no results", func(t *testing.T) {
		home := t.TempDir()
		root := filepath.Join(t.TempDir(), "missing")

		got, err := collectFileRefSearch(t, context.Background(), root, home, "")
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("err = %v, want a read error wrapping os.ErrNotExist", err)
		}
		if len(got) != 0 {
			t.Fatalf("emitted %v, want no results on a traversal failure", got)
		}
	})
}

func TestFileRefSearch_Cancellation(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	for _, name := range []string{"hit-a.txt", "hit-b.txt", "hit-c.txt"} {
		writeFile(t, filepath.Join(root, name), "h")
	}

	ctx := &cancelAfterChecksCtx{Context: context.Background(), left: 6}
	got, err := collectFileRefSearch(t, ctx, root, home, "hit-")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled rather than a successful completion", err)
	}
	if len(got) != 0 {
		t.Fatalf("emitted %v, want no rows from a cancelled search", got)
	}
}

type cancelAfterChecksCtx struct {
	context.Context
	left int
}

func (c *cancelAfterChecksCtx) Err() error {
	if c.left == 0 {
		return context.Canceled
	}
	c.left--
	return nil
}

func TestRankFileRefMatches(t *testing.T) {
	cases := []struct {
		name  string
		query string
		paths []string
		want  []string
	}{
		{
			name:  "exact, prefix, last segment, then any substring",
			query: "dir1",
			paths: []string{"zdir1.txt", "a/dir1.go", "dir10/", "dir1/"},
			want:  []string{"dir1/", "dir10/", "a/dir1.go", "zdir1.txt"},
		},
		{
			name:  "exact match ignores case and a folder's trailing slash",
			query: "data",
			paths: []string{"cache/Data/", "Data/"},
			want:  []string{"Data/", "cache/Data/"},
		},
		{
			name:  "shallower first within a rank, walk order at equal depth",
			query: "x",
			paths: []string{"a/b/x.go", "b/x.go", "a/x.go"},
			want:  []string{"b/x.go", "a/x.go", "a/b/x.go"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := slices.Clone(tc.paths)
			rankFileRefMatches(got, tc.query)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFileRefSearch_Ranking(t *testing.T) {
	t.Run("the best 50 are emitted even when deeper matches come first in walk order", func(t *testing.T) {
		root := t.TempDir()
		home := t.TempDir()
		for i := range 60 {
			if err := os.MkdirAll(filepath.Join(root, "a", fmt.Sprintf("%02d", i), "data"), 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
		}
		for _, dir := range []string{filepath.Join(root, "b", "data"), filepath.Join(root, "data")} {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
		}

		got, err := collectFileRefSearch(t, context.Background(), root, home, "data/")
		if err != nil {
			t.Fatalf("searchFileRefs: %v", err)
		}
		want := []string{"data/", "b/data/"}
		for i := range 48 {
			want = append(want, fmt.Sprintf("a/%02d/data/", i))
		}
		if !slices.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("a walk error emits the ranked matches collected before it", func(t *testing.T) {
		root := t.TempDir()
		home := t.TempDir()
		writeFile(t, filepath.Join(root, "a", "dir1.go"), "a")
		writeFile(t, filepath.Join(root, "dir1.txt"), "d")
		unreadable := filepath.Join(root, "zz-unreadable")
		writeFile(t, filepath.Join(unreadable, "dir1.go"), "z")
		if err := os.Chmod(unreadable, 0o000); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(unreadable, 0o755) })

		got, err := collectFileRefSearch(t, context.Background(), root, home, "dir1")
		if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("err = %v, want the unreadable directory's permission error", err)
		}
		if want := []string{"dir1.txt", "a/dir1.go"}; !slices.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
}

func collectFileRefSearch(t *testing.T, ctx context.Context, root, home, query string) ([]string, error) {
	t.Helper()
	var got []string
	err := searchFileRefs(ctx, root, home, query, func(path string) { got = append(got, path) })
	return got, err
}

// writeFile writes content to path under a test, creating parent directories.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

// withFileRefSources installs a fake project root and home so the '@' trigger is live, and
// returns the project root. The project root holds the files passed in rel (relative paths).
func withFileRefSources(t *testing.T, a *App, rel ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, r := range rel {
		writeFile(t, filepath.Join(root, filepath.FromSlash(r)), "x")
	}
	a.statusLineState = &statusStateFake{projectRoot: root}
	a.SetHome(t.TempDir())
	return root
}

func TestFilePicker_TriggerOpensWithSources(t *testing.T) {
	a := New(nil)
	withFileRefSources(t, a, "main.go", "sub/child.go")

	a.input.SetText("@") // fires the change hook: single '@' at the buffer start

	if !a.FilePickerOpen() {
		t.Fatal("FilePickerOpen() = false; typing '@' at a word boundary must open the picker")
	}
	if !a.pages.HasPage(filePickerPage) {
		t.Error("file picker page not mounted")
	}
	if a.filePicker == nil {
		t.Fatal("picker opened without a live session")
	}
	if len(a.filePicker.shown) != 0 {
		t.Errorf("picker opened with %d selectable rows, want 0 (guidance only, no walk)", len(a.filePicker.shown))
	}
	if got := fileRefListText(a.filePicker); got != fileRefIdleGuidance {
		t.Errorf("picker list = %q, want the idle guidance %q", got, fileRefIdleGuidance)
	}
	if got := a.input.GetText(); got != "@" {
		t.Errorf("input = %q, want %q (the trigger never consumes the '@')", got, "@")
	}
}

func TestFilePicker_InertWithoutSources(t *testing.T) {
	a := New(nil) // no StatusState, no home installed (unit-test construction)

	a.input.SetText("@")

	if a.filePickerOpen {
		t.Error("picker opened with no production sources installed; the trigger must be inert")
	}
	if got := a.input.GetText(); got != "@" {
		t.Errorf("input = %q, want %q (typed '@' left untouched)", got, "@")
	}
}

func TestFilePicker_PasteDoesNotOpen(t *testing.T) {
	a := New(nil)
	withFileRefSources(t, a, "main.go")

	a.input.SetText("@foo bar") // a multi-rune change (bracketed paste), not a single '@'

	if a.filePickerOpen {
		t.Error("picker opened on a multi-rune paste containing '@'; only a single typed '@' may open it")
	}
}

// TestFilePicker_LongPasteCollapsesWithoutOpening proves the long-paste collapse path keeps the
// paste-suppression guard: a long bracketed paste whose lines contain '@' collapses to the placeholder
// (which has no '@') through the paste-suppressed change hook, so the file-reference
// picker never opens. It drives the production PasteHandler closure directly.
func TestFilePicker_LongPasteCollapsesWithoutOpening(t *testing.T) {
	a := New(nil)
	withFileRefSources(t, a, "main.go") // sources installed: a *typed* '@' would open the picker

	pasteInto(a.input, "@a\n@b\n@c\n@d\n@e\n@f")

	if got := a.input.GetText(); got != "[Pasted 6 lines — paste again to expand]" {
		t.Fatalf("visible buffer after long paste = %q, want placeholder", got)
	}
	if a.filePickerOpen {
		t.Error("file picker opened on a long paste containing '@'; a paste must never open it")
	}
}

// TestFilePicker_BracketedPasteOfAtDoesNotOpen drives the real bracketed-paste path the TUI
// uses (EventPaste start marker, the pasted rune, EventPaste end marker) for a paste of exactly
// '@'. A lone pasted '@' inserts the same one byte as a typed '@', so only the paste marker
// tells them apart: the picker must stay closed and the '@' must land in the buffer literally.
// This covers the production PasteHandler path that the SetText-based multi-rune
// TestFilePicker_PasteDoesNotOpen does not exercise; it mirrors
// TestRun_BracketedPasteInsertsWithoutSubmitting's delivery.
func TestFilePicker_BracketedPasteOfAtDoesNotOpen(t *testing.T) {
	a := New(nil)
	withFileRefSources(t, a, "main.go") // sources installed: a *typed* '@' would open the picker

	drawn := make(chan struct{}, 16)
	a.app.SetAfterDrawFunc(func(tcell.Screen) {
		select {
		case drawn <- struct{}{}:
		default:
		}
	})
	a.app.SetScreen(tcell.NewSimulationScreen("UTF-8"))

	errc := make(chan error, 1)
	go func() { errc <- a.app.Run() }()

	// Wait for the initial draw so the input is focused and the loop is live.
	select {
	case <-drawn:
	case <-time.After(2 * time.Second):
		a.app.Stop()
		t.Fatal("app did not draw within 2s")
	}

	a.app.QueueEvent(tcell.NewEventPaste(true))
	a.app.QueueEvent(tcell.NewEventKey(tcell.KeyRune, '@', tcell.ModNone))
	a.app.QueueEvent(tcell.NewEventPaste(false))

	// The end marker triggers the PasteHandler insert and a redraw; poll until the '@' lands.
	deadline := time.After(2 * time.Second)
	for inputTextSync(a) != "@" {
		select {
		case <-drawn:
		case <-deadline:
			got := inputTextSync(a)
			a.app.Stop()
			t.Fatalf("pasted '@' not inserted within 2s; buffer = %q, want %q", got, "@")
		}
	}

	open := filePickerOpenSync(a)
	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}
	if open {
		t.Error("file picker opened on a bracketed paste of '@'; a paste must never open it")
	}
}

// filePickerOpenSync reads filePickerOpen on the event-loop goroutine so a running-app test can
// check it without racing the loop, mirroring inputTextSync.
func filePickerOpenSync(a *App) bool {
	var open bool
	a.app.QueueUpdate(func() { open = a.filePickerOpen })
	return open
}

func TestFilePicker_NoOpWhileOverlayOpen(t *testing.T) {
	a := New(nil)
	withFileRefSources(t, a, "main.go")
	a.statusOpen = true // another overlay holds the screen

	a.openFilePicker(0)

	if a.filePickerOpen {
		t.Error("filePickerOpen = true; the '@' trigger must be a no-op while another overlay is open")
	}
	if a.pages.HasPage(filePickerPage) {
		t.Error("file picker page mounted while another overlay is open")
	}
}

func confirmFileRefThroughField(t *testing.T, a *App) {
	t.Helper()
	a.app.QueueUpdate(func() {
		field, ok := a.app.GetFocus().(*tview.InputField)
		if !ok {
			t.Errorf("focused widget = %T, want the query *tview.InputField", a.app.GetFocus())
			return
		}
		field.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})
	})
	waitFileRefState(t, a, func() bool { return !a.filePickerOpen })
}

func TestFilePicker_SelectInsertsStreamedToken(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		query   string
		want    []string
		token   string
	}{
		{
			name:    "directory row keeps its trailing slash",
			fixture: "sub/child.go",
			query:   "sub",
			want:    []string{"sub/", "sub/child.go"},
			token:   "@sub/",
		},
		{
			name:  "file row has no trailing slash",
			query: "main",
			want:  []string{"main.go"},
			token: "@main.go",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := startRunningFilePicker(t)
			if tc.fixture != "" {
				writeFile(t, filepath.Join(a.statusLineState.ProjectRoot(), filepath.FromSlash(tc.fixture)), "x")
			}

			startFileRefSearchThroughField(t, a, tc.query, nil)
			waitFileRefState(t, a, func() bool {
				return a.filePicker != nil && a.filePicker.searchCancel == nil && slices.Equal(a.filePicker.shown, tc.want)
			})
			confirmFileRefThroughField(t, a)

			a.app.QueueUpdate(func() {
				if got := a.input.GetText(); got != tc.token {
					t.Errorf("input = %q, want %q (the settled row becomes the token verbatim)", got, tc.token)
				}
				if a.filePickerOpen || a.pages.HasPage(filePickerPage) {
					t.Error("picker still open after a selection")
				}
				if a.app.GetFocus() != a.input {
					t.Error("focus not restored to the input after selection")
				}
			})
		})
	}
}

func TestFilePicker_SelectImageDecision(t *testing.T) {
	cases := []struct {
		name       string
		fixture    string
		content    string
		query      string
		wantInput  string
		wantAttach bool
		wantNotice bool
	}{
		{
			name:       "supported image attaches as a removable token",
			fixture:    "diagram.png",
			content:    pngMagic + "data",
			query:      "diagram",
			wantInput:  "[diagram.png]",
			wantAttach: true,
			wantNotice: true,
		},
		{
			name:      "non-image inlines as plain text",
			fixture:   "notes.txt",
			content:   "n",
			query:     "notes",
			wantInput: "@notes.txt",
		},
		{
			name:      "image extension with non-image bytes inlines as plain text",
			fixture:   "broken.png",
			content:   "definitely not a png",
			query:     "broken",
			wantInput: "@broken.png",
		},
		{
			name:       "oversize image notices and drops the token",
			fixture:    "big.png",
			content:    pngMagic + strings.Repeat("\x00", maxImageBytes+1-len(pngMagic)),
			query:      "big",
			wantInput:  "",
			wantNotice: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := startRunningFilePicker(t)
			writeFile(t, filepath.Join(a.statusLineState.ProjectRoot(), tc.fixture), tc.content)

			startFileRefSearchThroughField(t, a, tc.query, nil)
			waitFileRefState(t, a, func() bool {
				return a.filePicker != nil && a.filePicker.searchCancel == nil && slices.Equal(a.filePicker.shown, []string{tc.fixture})
			})
			confirmFileRefThroughField(t, a)

			a.app.QueueUpdate(func() {
				if got := a.input.GetText(); got != tc.wantInput {
					t.Errorf("input = %q, want %q", got, tc.wantInput)
				}
				atts := a.input.imageAttachments()
				switch {
				case !tc.wantAttach:
					if len(atts) != 0 {
						t.Errorf("attachments = %d, want 0", len(atts))
					}
				case len(atts) != 1:
					t.Errorf("attachments = %d, want 1", len(atts))
				default:
					if atts[0].mime != "image/png" {
						t.Errorf("attachment mime = %q, want image/png", atts[0].mime)
					}
					a.input.Replace(0, len(tc.wantInput), "")
					if n := len(a.input.imageAttachments()); n != 0 {
						t.Errorf("attachments after deleting the token = %d, want 0 (the token is removable)", n)
					}
				}
				if hasNotice := a.transcript.notice != ""; hasNotice != tc.wantNotice {
					t.Errorf("notice present = %v (%q), want %v", hasNotice, a.transcript.notice, tc.wantNotice)
				}
				if a.filePickerOpen || a.pages.HasPage(filePickerPage) {
					t.Error("picker still open after a selection")
				}
			})
		})
	}
}

func assertNoSelectableConfirm(t *testing.T, a *App, sess *filePickerSession, genBefore uint64, want string) {
	t.Helper()
	got := a.input.GetText()
	if got != want {
		t.Errorf("input = %q, want the literal %q", got, want)
	}
	for _, placeholder := range []string{fileRefIdleGuidance, fileRefSearchingRow, fileRefFailedRow, fileRefNoMatchRow} {
		if strings.Contains(got, placeholder) {
			t.Errorf("input = %q contains the placeholder %q; a placeholder row must never confirm as a path", got, placeholder)
		}
	}
	if sess.searchGeneration <= genBefore {
		t.Errorf("generation = %d, want > %d (Enter with no candidate must revoke the search)", sess.searchGeneration, genBefore)
	}
	if a.filePickerOpen || a.pages.HasPage(filePickerPage) {
		t.Error("picker still open after Enter with no selectable row")
	}
}

func TestFilePicker_EnterWithNoSelectableRow(t *testing.T) {
	t.Run("pending search placeholder", func(t *testing.T) {
		a := New(nil)
		withFileRefSources(t, a, "main.go")
		field := focusedPickerField(t, a)
		timers := collectFileRefTimers(a)
		sess := a.filePicker

		field.SetText("mai")
		if got := fileRefListText(sess); got != fileRefSearchingRow {
			t.Fatalf("list = %q, want %q while the search is pending", got, fileRefSearchingRow)
		}
		if len(*timers) != 1 {
			t.Fatalf("scheduled %d timers, want 1 (the owning debounce timer must be pending)", len(*timers))
		}
		gen := sess.searchGeneration

		field.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})

		assertNoSelectableConfirm(t, a, sess, gen, "@mai")
	})

	t.Run("failed search placeholder", func(t *testing.T) {
		a := startRunningFilePicker(t)
		startFileRefSearchThroughField(t, a, "mai", func(_ context.Context, _ string, _ func(path string)) error {
			return errors.New("bad codemeldignore pattern")
		})
		waitFileRefState(t, a, func() bool {
			return a.filePicker != nil && a.filePicker.searchCancel == nil && fileRefListText(a.filePicker) == fileRefFailedRow
		})

		a.app.QueueUpdate(func() {
			sess := a.filePicker
			if sess == nil {
				t.Error("failed search dismissed the picker; a search must never close it")
				return
			}
			gen := sess.searchGeneration
			field, ok := a.app.GetFocus().(*tview.InputField)
			if !ok {
				t.Errorf("focused widget = %T, want the query *tview.InputField", a.app.GetFocus())
				return
			}
			field.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})
			assertNoSelectableConfirm(t, a, sess, gen, "@mai")
		})
	})
}

func TestFilePicker_EscLeavesAtQueryLiteral(t *testing.T) {
	cases := []struct {
		name    string
		dismiss func(a *App, field *tview.InputField)
	}{
		{
			name: "field ESC capture",
			dismiss: func(_ *App, field *tview.InputField) {
				field.InputHandler()(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone), func(tview.Primitive) {})
			},
		},
		{
			name:    "central HandleEsc",
			dismiss: func(a *App, _ *tview.InputField) { a.HandleEsc() },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			withFileRefSources(t, a, "main.go")
			collectFileRefTimers(a)

			a.input.SetText("foo ")
			a.input.SetText("foo @")
			if !a.filePickerOpen || a.filePicker.atByte != 4 {
				t.Fatalf("picker not open at byte 4 (open=%v)", a.filePickerOpen)
			}
			field, ok := a.app.GetFocus().(*tview.InputField)
			if !ok {
				t.Fatalf("focused widget = %T, want the query *tview.InputField", a.app.GetFocus())
			}
			sess := a.filePicker

			field.SetText("bar")
			if sess.query != "bar" {
				t.Fatalf("sess.query = %q, want %q (the field's change hook owns the query)", sess.query, "bar")
			}
			gen := sess.searchGeneration

			tc.dismiss(a, field)

			if got := a.input.GetText(); got != "foo @bar" {
				t.Errorf("input = %q, want %q (ESC leaves the '@'+query literal at the trigger offset)", got, "foo @bar")
			}
			if a.filePickerOpen || a.pages.HasPage(filePickerPage) {
				t.Error("picker still open after ESC")
			}
			if sess.searchGeneration <= gen {
				t.Errorf("generation = %d, want > %d (ESC must revoke the pending search)", sess.searchGeneration, gen)
			}
			if a.app.GetFocus() != a.input {
				t.Error("focus not restored to the input after ESC")
			}
		})
	}
}

func TestFilePicker_QueryClearsToGuidanceAndRevokes(t *testing.T) {
	a := New(nil)
	withFileRefSources(t, a, "main.go")
	field := focusedPickerField(t, a)
	timers := collectFileRefTimers(a)
	sess := a.filePicker

	field.SetText("ma")
	if got := fileRefListText(sess); got != fileRefSearchingRow {
		t.Fatalf("list = %q, want %q while a search is pending", got, fileRefSearchingRow)
	}
	if len(sess.shown) != 0 {
		t.Fatalf("shown = %v, want no selectable rows while searching", sess.shown)
	}
	if len(*timers) != 1 {
		t.Fatalf("scheduled %d timers, want 1 for a non-empty query", len(*timers))
	}
	genPending := sess.searchGeneration

	field.SetText("")
	if got := fileRefListText(sess); got != fileRefIdleGuidance {
		t.Errorf("list = %q, want the restored idle guidance %q", got, fileRefIdleGuidance)
	}
	if sess.searchGeneration == genPending {
		t.Error("clearing the query did not advance the generation; a pending search stays owned")
	}
	if !a.filePickerOpen {
		t.Error("clearing the query closed the picker; it must stay open showing guidance")
	}
}

// focusedPickerField opens the picker via a typed '@' and returns the live query field that
// holds focus, type-asserting it to *tview.InputField. This proves the widget buildFilePicker
// focuses is the one whose SetChangedFunc/SetInputCapture the wiring tests then drive — the
// piece the handler-level tests (which call onFileRefQueryChanged/confirmFileRef directly) skip.
func focusedPickerField(t *testing.T, a *App) *tview.InputField {
	t.Helper()
	a.input.SetText("@")
	if !a.filePickerOpen {
		t.Fatal("picker did not open on a typed '@'")
	}
	field, ok := a.app.GetFocus().(*tview.InputField)
	if !ok {
		t.Fatalf("focused widget = %T, want *tview.InputField (the query field must hold focus)", a.app.GetFocus())
	}
	return field
}

func TestFilePicker_FieldChangeSchedulesThroughWiring(t *testing.T) {
	a := New(nil)
	withFileRefSources(t, a, "main.go", "sub/child.go")
	field := focusedPickerField(t, a)
	timers := collectFileRefTimers(a)

	field.SetText("main")

	sess := a.filePicker
	if sess == nil {
		t.Fatal("picker closed on a query typed into the field")
	}
	if sess.query != "main" {
		t.Errorf("sess.query = %q, want %q (the field's change hook must update the live query)", sess.query, "main")
	}
	if got := fileRefListText(sess); got != fileRefSearchingRow {
		t.Errorf("list = %q, want %q (the field change must clear rows to searching)", got, fileRefSearchingRow)
	}
	if len(*timers) != 1 {
		t.Errorf("scheduled %d timers, want 1 (the field change must reach the debounce scheduler)", len(*timers))
	}
}

func openFilePickerWithRows(t *testing.T, a *App, query string, rows ...string) (*tview.InputField, *filePickerSession) {
	t.Helper()
	collectFileRefTimers(a)
	field := focusedPickerField(t, a)
	sess := a.filePicker
	if query != "" {
		field.SetText(query)
	}
	showFileRefRows(a, sess, rows...)
	return field, sess
}

func TestFilePicker_FieldArrowsMoveSelectionClamped(t *testing.T) {
	a := New(nil)
	withFileRefSources(t, a, "main.go")
	field, sess := openFilePickerWithRows(t, a, "", "a.go", "b.go", "c.go")

	press := func(key tcell.Key) {
		field.InputHandler()(tcell.NewEventKey(key, 0, tcell.ModNone), func(tview.Primitive) {})
	}

	press(tcell.KeyUp)
	if got := sess.list.GetCurrentItem(); got != 0 {
		t.Errorf("Up on the first candidate = %d, want 0 (clamped, no wraparound to the last)", got)
	}
	press(tcell.KeyDown)
	press(tcell.KeyDown)
	if got := sess.list.GetCurrentItem(); got != 2 {
		t.Errorf("two Downs = %d, want 2 (↑/↓ from the field drive the list)", got)
	}
	press(tcell.KeyDown)
	if got := sess.list.GetCurrentItem(); got != 2 {
		t.Errorf("Down on the last candidate = %d, want 2 (clamped, no wraparound to the first)", got)
	}
	press(tcell.KeyUp)
	if got := sess.list.GetCurrentItem(); got != 1 {
		t.Errorf("Up = %d, want 1", got)
	}
}

func TestFilePicker_ListSelectConfirmsHighlighted(t *testing.T) {
	a := New(nil)
	withFileRefSources(t, a, "main.go")
	_, sess := openFilePickerWithRows(t, a, "", "a.go", "b.go")
	sess.list.SetCurrentItem(1)

	sess.list.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})

	if got := a.input.GetText(); got != "@b.go" {
		t.Errorf("input = %q, want %q (list selection confirms the highlighted candidate)", got, "@b.go")
	}
	if a.filePickerOpen || a.pages.HasPage(filePickerPage) {
		t.Error("picker still mounted after a list selection")
	}
}

func TestFilePicker_RepeatedDismissIsHarmless(t *testing.T) {
	a := New(nil)
	withFileRefSources(t, a, "main.go")
	openFilePickerWithRows(t, a, "bar", "a.go")

	a.dismissFilePicker(true)
	text := a.input.GetText()
	if text != "@bar" {
		t.Fatalf("input after the first dismissal = %q, want %q", text, "@bar")
	}
	if a.filePickerPrev != nil {
		t.Fatal("prior focus not cleared by the first dismissal; a second would restore stale focus")
	}
	elsewhere := tview.NewBox()
	a.app.SetFocus(elsewhere)

	a.dismissFilePicker(true)

	if got := a.input.GetText(); got != text {
		t.Errorf("input after a second dismissal = %q, want the first close's %q (dismissal is idempotent)", got, text)
	}
	if a.app.GetFocus() != elsewhere {
		t.Errorf("focus after a second dismissal = %T, want it left where it was", a.app.GetFocus())
	}
	if a.filePickerOpen || a.pages.HasPage(filePickerPage) {
		t.Error("picker re-mounted by a second dismissal")
	}
	if a.filePicker != nil {
		t.Error("a second dismissal revived the session")
	}
}

func TestFilePicker_ConfirmWithInvalidCandidateLeavesLiteral(t *testing.T) {
	cases := []struct {
		name    string
		corrupt func(sess *filePickerSession)
	}{
		{
			name:    "no selectable rows",
			corrupt: func(sess *filePickerSession) { sess.shown = nil },
		},
		{
			name: "current item past the shown rows",
			corrupt: func(sess *filePickerSession) {
				sess.list.SetCurrentItem(2)
				sess.shown = sess.shown[:1]
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			withFileRefSources(t, a, "main.go")
			_, sess := openFilePickerWithRows(t, a, "mai", "a.go", "b.go", "c.go")
			gen := sess.searchGeneration
			tc.corrupt(sess)

			a.confirmFileRef()

			assertNoSelectableConfirm(t, a, sess, gen, "@mai")
			if strings.Contains(a.input.GetText(), ".go") {
				t.Errorf("input = %q, want no candidate path inserted for an invalid index", a.input.GetText())
			}
		})
	}
}

func TestFilePicker_ConfirmWithInvalidTriggerOffsetMakesNoReplacement(t *testing.T) {
	cases := []struct {
		name   string
		atByte int
	}{
		{name: "negative offset", atByte: -1},
		{name: "offset at the end of the buffer", atByte: len("@")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			withFileRefSources(t, a, "main.go")
			_, sess := openFilePickerWithRows(t, a, "", "a.go")
			sess.atByte = tc.atByte

			a.confirmFileRef()

			if got := a.input.GetText(); got != "@" {
				t.Errorf("input = %q, want it unchanged at %q (an out-of-range trigger offset replaces nothing)", got, "@")
			}
			if a.filePickerOpen || a.pages.HasPage(filePickerPage) {
				t.Error("picker still mounted after a confirm with an invalid trigger offset")
			}
		})
	}
}

func TestFileRefDebounceDelay_CountsRunes(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  time.Duration
		ok    bool
	}{
		{name: "empty is not schedulable", query: "", want: 0, ok: false},
		{name: "one ascii rune", query: "a", want: 400 * time.Millisecond, ok: true},
		{name: "one multibyte rune", query: "é", want: 400 * time.Millisecond, ok: true},
		{name: "two ascii runes", query: "ab", want: 250 * time.Millisecond, ok: true},
		{name: "two multibyte runes", query: "éè", want: 250 * time.Millisecond, ok: true},
		{name: "many runes", query: "internal/tui", want: 250 * time.Millisecond, ok: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := fileRefDebounceDelay(tc.query)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("fileRefDebounceDelay(%q) = %v, %v; want %v, %v", tc.query, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func collectFileRefTimers(a *App) *[]func() {
	timers := &[]func(){}
	a.afterFunc = func(_ time.Duration, f func()) { *timers = append(*timers, f) }
	return timers
}

func TestFileRefSearchSchedule_ObsoleteTimerCannotStart(t *testing.T) {
	a := New(nil)
	withFileRefSources(t, a, "main.go")
	timers := collectFileRefTimers(a)
	a.input.SetText("@")
	sess := a.filePicker
	if sess == nil {
		t.Fatal("picker did not open")
	}

	started := 0
	start := func(uint64) { started++ }
	if !a.scheduleFileRefSearch(sess, "m", start) {
		t.Fatal("first schedule refused a one-rune query")
	}
	if !a.scheduleFileRefSearch(sess, "ma", start) {
		t.Fatal("replacement schedule refused a two-rune query")
	}
	if len(*timers) != 2 {
		t.Fatalf("collected %d timers, want 2", len(*timers))
	}

	(*timers)[0]()
	if started != 0 {
		t.Fatalf("obsolete timer started %d searches, want 0", started)
	}

	(*timers)[1]()
	if started != 1 {
		t.Fatalf("current timer started %d searches, want 1", started)
	}
}

func TestFileRefSearchSchedule_RejectsReplacedSession(t *testing.T) {
	a := New(nil)
	withFileRefSources(t, a, "main.go")
	timers := collectFileRefTimers(a)
	a.input.SetText("@")
	sess := a.filePicker
	if sess == nil {
		t.Fatal("picker did not open")
	}

	started := 0
	if !a.scheduleFileRefSearch(sess, "ma", func(uint64) { started++ }) {
		t.Fatal("schedule refused a two-rune query")
	}
	a.filePicker = &filePickerSession{}

	(*timers)[0]()

	if started != 0 {
		t.Fatalf("callback for a replaced session started %d searches, want 0", started)
	}
}

func TestFileRefSearchInvalidate_RevokesBeforeCancel(t *testing.T) {
	a := New(nil)
	sess := &filePickerSession{searchGeneration: 7}
	a.invalidateFileRefSearch(sess)
	before := sess.searchGeneration
	var genAtCancel uint64
	var cancelled bool
	sess.searchCancel = func() {
		cancelled = true
		genAtCancel = sess.searchGeneration
	}

	a.invalidateFileRefSearch(sess)

	if !cancelled {
		t.Fatal("prior cancel handle was not invoked")
	}
	if genAtCancel != before+1 {
		t.Errorf("generation at cancel = %d, want %d (ownership must advance before cancel runs)", genAtCancel, before+1)
	}
	if sess.searchCancel != nil {
		t.Error("searchCancel not cleared; a revoked worker still looks owned")
	}
	if a.ownsFileRefSearch(sess, before) {
		t.Error("the revoked generation still owns the search")
	}
}

func showFileRefRows(a *App, sess *filePickerSession, rows ...string) {
	for _, r := range rows {
		a.applyFileRefSearchRow(sess, sess.searchGeneration, r)
	}
}

func fileRefListText(sess *filePickerSession) string {
	var rows []string
	for i := 0; i < sess.list.GetItemCount(); i++ {
		main, _ := sess.list.GetItemText(i)
		rows = append(rows, main)
	}
	return strings.Join(rows, "\n")
}

func waitFileRefShown(t *testing.T, a *App, pred func(rows []string) bool) []string {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		var rows []string
		a.app.QueueUpdate(func() {
			if a.filePicker != nil {
				rows = append([]string(nil), a.filePicker.shown...)
			}
		})
		if pred(rows) {
			return rows
		}
		select {
		case <-deadline:
			a.app.Stop()
			t.Fatal("file picker shown rows did not reach the expected state within 2s")
			return nil
		default:
		}
	}
}

func waitFileRefState(t *testing.T, a *App, pred func() bool) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		var done bool
		a.app.QueueUpdate(func() { done = pred() })
		if done {
			return
		}
		select {
		case <-deadline:
			a.app.Stop()
			t.Fatal("file picker did not reach the expected state within 2s")
		case <-time.After(time.Millisecond):
		}
	}
}

func startFileRefSearchThroughField(t *testing.T, a *App, query string, search fileRefSearchFunc) {
	t.Helper()
	var timers []func()
	a.afterFunc = func(_ time.Duration, f func()) { timers = append(timers, f) }
	a.app.QueueUpdate(func() {
		a.input.SetText("@")
		sess := a.filePicker
		if search != nil {
			sess.search = search
		}
		field := a.app.GetFocus().(*tview.InputField)
		field.SetText(query)
	})
	if len(timers) != 1 {
		t.Fatalf("scheduled %d timers, want 1", len(timers))
	}
	timers[0]()
}

func startRunningFilePicker(t *testing.T) *App {
	t.Helper()
	a := New(nil)
	withFileRefSources(t, a, "main.go")
	screen := tcell.NewSimulationScreen("UTF-8")
	a.newScreen = func() (tcell.Screen, error) { return screen, nil }
	errC := make(chan error, 1)
	go func() { errC <- a.Run() }()
	waitLoopRunning(t, a)
	t.Cleanup(func() {
		a.app.Stop()
		if err := <-errC; err != nil {
			t.Errorf("app.Run returned error: %v", err)
		}
	})
	return a
}

func TestFilePicker_OpensGuidanceWithoutWalk(t *testing.T) {
	a := New(nil)
	withFileRefSources(t, a, "main.go")
	timers := collectFileRefTimers(a)

	a.input.SetText("@")

	sess := a.filePicker
	if sess == nil {
		t.Fatal("typing '@' did not open the picker")
	}
	if _, ok := a.app.GetFocus().(*tview.InputField); !ok {
		t.Errorf("focused widget = %T, want the query *tview.InputField", a.app.GetFocus())
	}
	if got := fileRefListText(sess); got != fileRefIdleGuidance {
		t.Errorf("list = %q, want exactly the idle guidance %q", got, fileRefIdleGuidance)
	}
	if len(sess.shown) != 0 {
		t.Errorf("shown = %v, want no selectable rows at open", sess.shown)
	}
	if len(*timers) != 0 {
		t.Errorf("scheduled %d timers at open, want 0 (no walk until a query settles)", len(*timers))
	}
}

func TestFilePicker_LiveScheduleAndRunningLoop(t *testing.T) {
	a := New(nil)
	withFileRefSources(t, a, "main.go")
	screen := tcell.NewSimulationScreen("UTF-8")
	a.newScreen = func() (tcell.Screen, error) { return screen, nil }

	type timer struct {
		delay time.Duration
		fire  func()
	}
	var timers []timer
	a.afterFunc = func(delay time.Duration, f func()) { timers = append(timers, timer{delay: delay, fire: f}) }

	release := make(chan struct{})
	started := make(chan struct{}, 4)
	emitted := make(chan struct{}, 1)
	controlled := func(_ context.Context, _ string, emit func(path string)) error {
		started <- struct{}{}
		emit("hit-1.go")
		emitted <- struct{}{}
		<-release
		return nil
	}

	errc := make(chan error, 1)
	go func() { errc <- a.Run() }()
	waitLoopRunning(t, a)

	a.app.QueueUpdate(func() {
		a.input.SetText("@")
		sess := a.filePicker
		sess.search = controlled
		field := a.app.GetFocus().(*tview.InputField)
		field.SetText("m")
		field.SetText("ma")
	})

	var obsolete, current timer
	a.app.QueueUpdate(func() {
		if len(timers) == 2 {
			obsolete, current = timers[0], timers[1]
		}
	})
	if obsolete.fire == nil || current.fire == nil {
		a.app.Stop()
		t.Fatalf("did not capture both debounce timers (got %d)", len(timers))
	}
	if obsolete.delay != fileRefDebounceFirstRune {
		a.app.Stop()
		t.Fatalf("one-rune delay = %v, want %v", obsolete.delay, fileRefDebounceFirstRune)
	}
	if current.delay != fileRefDebounceMoreRunes {
		a.app.Stop()
		t.Fatalf("multi-rune delay = %v, want %v", current.delay, fileRefDebounceMoreRunes)
	}

	obsolete.fire()
	current.fire()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		a.app.Stop()
		close(release)
		t.Fatal("owning timer did not start the worker within 2s")
	}
	<-emitted

	probe := make(chan struct{})
	go func() { a.app.QueueUpdate(func() {}); close(probe) }()
	select {
	case <-probe:
	case <-time.After(2 * time.Second):
		a.app.Stop()
		close(release)
		t.Fatal("event loop unresponsive while the search worker was blocked")
	}

	select {
	case <-started:
		a.app.Stop()
		close(release)
		t.Fatal("a second worker started; the obsolete timer was not rejected")
	default:
	}

	close(release)
	shown := waitFileRefShown(t, a, func(rows []string) bool { return len(rows) == 1 })
	if !slices.Equal(shown, []string{"hit-1.go"}) {
		a.app.Stop()
		t.Fatalf("shown = %v, want [hit-1.go]", shown)
	}

	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}
}

func TestFilePicker_StreamsRowsBeforeFinal(t *testing.T) {
	t.Run("rows render in walker order and survive final handling", func(t *testing.T) {
		a := startRunningFilePicker(t)
		release := make(chan struct{})
		emitted := make(chan struct{}, 1)
		paths := []string{"a.go", "b.go", "c.go"}
		startFileRefSearchThroughField(t, a, "a", func(_ context.Context, _ string, emit func(path string)) error {
			for _, path := range paths {
				emit(path)
			}
			emitted <- struct{}{}
			<-release
			return nil
		})
		select {
		case <-emitted:
		case <-time.After(2 * time.Second):
			t.Fatal("worker did not finish its synchronous emits")
		}
		shown := waitFileRefShown(t, a, func(rows []string) bool { return slices.Equal(rows, paths) })
		if !slices.Equal(shown, paths) {
			t.Fatalf("shown = %v, want %v before worker final", shown, paths)
		}

		close(release)
		waitFileRefState(t, a, func() bool { return a.filePicker != nil && a.filePicker.searchCancel == nil })
		sess := a.filePicker
		if !slices.Equal(sess.shown, paths) {
			t.Errorf("shown = %v after final, want the rows retained (final must not overtake rows)", sess.shown)
		}
		if !a.filePickerOpen {
			t.Error("a nonzero-row success closed the picker; rows must stay selectable")
		}
	})

	t.Run("no more than 50 rows are selectable", func(t *testing.T) {
		a := New(nil)
		withFileRefSources(t, a, "main.go")
		a.input.SetText("@")
		sess := a.filePicker
		gen := sess.searchGeneration
		a.renderFileRefPlaceholder(sess, fileRefSearchingRow)

		var many []string
		for i := 0; i < 60; i++ {
			many = append(many, fmt.Sprintf("hit-%02d.go", i))
		}
		for _, p := range many {
			a.applyFileRefSearchRow(sess, gen, p)
		}
		if len(sess.shown) != fileRefSearchLimit {
			t.Fatalf("shown %d rows, want the %d-row bound", len(sess.shown), fileRefSearchLimit)
		}
		if !slices.Equal(sess.shown, many[:fileRefSearchLimit]) {
			t.Fatalf("shown = %v, want the first %d in walker order", sess.shown, fileRefSearchLimit)
		}
	})

	t.Run("the bound production seam searches the whole tree past 2000 nonmatches", func(t *testing.T) {
		a := startRunningFilePicker(t)
		root := a.statusLineState.ProjectRoot()
		for i := 0; i < 2100; i++ {
			writeFile(t, filepath.Join(root, fmt.Sprintf("filler-%05d.txt", i)), "f")
		}
		writeFile(t, filepath.Join(root, "zz-unique-target.go"), "package z")

		startFileRefSearchThroughField(t, a, "unique-target", nil)
		waitFileRefState(t, a, func() bool {
			return a.filePicker != nil && a.filePicker.searchCancel == nil && slices.Equal(a.filePicker.shown, []string{"zz-unique-target.go"})
		})
		a.app.QueueUpdate(func() {
			field := a.app.GetFocus().(*tview.InputField)
			field.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})
		})
		waitFileRefState(t, a, func() bool { return !a.filePickerOpen })
		if got := a.input.GetText(); got != "@zz-unique-target.go" {
			t.Fatalf("input = %q, want %q", got, "@zz-unique-target.go")
		}
	})
}

func TestFilePicker_SuccessFinal(t *testing.T) {
	t.Run("zero rows keep the picker open with no matches", func(t *testing.T) {
		a := startRunningFilePicker(t)
		startFileRefSearchThroughField(t, a, "zzznope", func(_ context.Context, _ string, _ func(path string)) error {
			return nil
		})
		waitFileRefState(t, a, func() bool {
			return a.filePicker != nil && a.filePicker.searchCancel == nil && fileRefListText(a.filePicker) == fileRefNoMatchRow
		})

		a.app.QueueUpdate(func() {
			if !a.filePickerOpen {
				t.Error("a zero-row success dismissed the picker")
			}
			if len(a.filePicker.shown) != 0 {
				t.Errorf("shown = %v, want none (the no-matches row is not selectable)", a.filePicker.shown)
			}
		})
	})

	t.Run("Backspace after zero rows searches again and its rows replace no matches", func(t *testing.T) {
		a := startRunningFilePicker(t)
		search := func(_ context.Context, query string, emit func(path string)) error {
			if query == "file" {
				emit("file1")
				emit("file2")
			}
			return nil
		}
		startFileRefSearchThroughField(t, a, "files", search)
		waitFileRefState(t, a, func() bool {
			return a.filePicker != nil && a.filePicker.searchCancel == nil && fileRefListText(a.filePicker) == fileRefNoMatchRow
		})

		var timers []func()
		a.app.QueueUpdate(func() {
			a.afterFunc = func(_ time.Duration, f func()) { timers = append(timers, f) }
			field := a.app.GetFocus().(*tview.InputField)
			field.InputHandler()(tcell.NewEventKey(tcell.KeyBackspace2, 0, tcell.ModNone), func(tview.Primitive) {})
		})
		if len(timers) != 1 {
			t.Fatalf("scheduled %d timers after Backspace, want 1 (the edit must start a new search)", len(timers))
		}
		timers[0]()

		waitFileRefState(t, a, func() bool {
			return a.filePicker != nil && a.filePicker.searchCancel == nil && slices.Equal(a.filePicker.shown, []string{"file1", "file2"})
		})
		a.app.QueueUpdate(func() {
			if got := fileRefListText(a.filePicker); got != "file1\nfile2" {
				t.Errorf("list = %q, want the new rows replacing %q", got, fileRefNoMatchRow)
			}
		})
	})

	for _, key := range []tcell.Key{tcell.KeyEnter, tcell.KeyEscape} {
		t.Run(tcell.KeyNames[key]+" on no matches closes leaving the @query literal", func(t *testing.T) {
			a := startRunningFilePicker(t)
			startFileRefSearchThroughField(t, a, "zzznope", func(_ context.Context, _ string, _ func(path string)) error {
				return nil
			})
			waitFileRefState(t, a, func() bool {
				return a.filePicker != nil && a.filePicker.searchCancel == nil && fileRefListText(a.filePicker) == fileRefNoMatchRow
			})

			a.app.QueueUpdate(func() {
				sess := a.filePicker
				gen := sess.searchGeneration
				field := a.app.GetFocus().(*tview.InputField)
				field.InputHandler()(tcell.NewEventKey(key, 0, tcell.ModNone), func(tview.Primitive) {})
				assertNoSelectableConfirm(t, a, sess, gen, "@zzznope")
			})
		})
	}

	t.Run("nonzero rows stay open and selectable", func(t *testing.T) {
		a := startRunningFilePicker(t)
		startFileRefSearchThroughField(t, a, "main", func(_ context.Context, _ string, emit func(path string)) error {
			emit("main.go")
			return nil
		})
		waitFileRefState(t, a, func() bool {
			return a.filePicker != nil && a.filePicker.searchCancel == nil && slices.Equal(a.filePicker.shown, []string{"main.go"})
		})
		sess := a.filePicker

		if !a.filePickerOpen {
			t.Error("a nonzero-row success dismissed the picker")
		}
		if !slices.Equal(sess.shown, []string{"main.go"}) {
			t.Errorf("shown = %v, want the emitted rows retained", sess.shown)
		}
	})
}

func TestFilePicker_ErrorFinal(t *testing.T) {
	t.Run("error with no rows shows a notice and the search-failed placeholder", func(t *testing.T) {
		a := startRunningFilePicker(t)
		startFileRefSearchThroughField(t, a, "bad", func(_ context.Context, _ string, _ func(path string)) error {
			return errors.New("bad codemeldignore pattern")
		})
		waitFileRefState(t, a, func() bool {
			return a.transcript.notice == "bad codemeldignore pattern"
		})
		sess := a.filePicker

		if a.transcript.notice == "" {
			t.Error("an active search error left no notice")
		}
		if got := fileRefListText(sess); got != fileRefFailedRow {
			t.Errorf("list = %q, want %q with zero rows", got, fileRefFailedRow)
		}
		if len(sess.shown) != 0 {
			t.Errorf("shown = %v, want none (the failed placeholder is not selectable)", sess.shown)
		}
		if !a.filePickerOpen {
			t.Error("an error dismissed the picker; a search must never close it")
		}
	})

	t.Run("error after rows keeps the rows and shows no failed placeholder", func(t *testing.T) {
		a := startRunningFilePicker(t)
		startFileRefSearchThroughField(t, a, "main", func(_ context.Context, _ string, emit func(path string)) error {
			emit("main.go")
			return errors.New("unreadable directory")
		})
		waitFileRefState(t, a, func() bool {
			return a.transcript.notice == "unreadable directory"
		})
		sess := a.filePicker

		if a.transcript.notice == "" {
			t.Error("a late search error left no notice")
		}
		if got := fileRefListText(sess); got != "main.go" {
			t.Errorf("list = %q, want the earlier rows retained (never search failed)", got)
		}
		if !slices.Equal(sess.shown, []string{"main.go"}) {
			t.Errorf("shown = %v, want the earlier rows retained", sess.shown)
		}
	})

	t.Run("context.Canceled is silent", func(t *testing.T) {
		a := New(nil)
		withFileRefSources(t, a, "main.go")
		a.input.SetText("@")
		sess := a.filePicker
		gen := sess.searchGeneration
		a.renderFileRefPlaceholder(sess, fileRefSearchingRow)

		a.applyFileRefSearchFinal(sess, gen, context.Canceled)

		if a.transcript.notice != "" {
			t.Errorf("cancellation surfaced a notice %q, want silence", a.transcript.notice)
		}
		if got := fileRefListText(sess); got != fileRefSearchingRow {
			t.Errorf("list = %q, want the pending row untouched by cancellation", got)
		}
		if !a.filePickerOpen {
			t.Error("cancellation dismissed the picker; it is lifecycle control, not a result")
		}
	})
}

func TestFilePicker_RevocationRejectsStaleEffects(t *testing.T) {
	t.Run("canceled workers cannot revive revoked pickers", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			action string
		}{
			{name: "replacement", action: "replace"},
			{name: "clear", action: "clear"},
			{name: "ESC", action: "escape"},
			{name: "confirmation", action: "confirm"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				a := startRunningFilePicker(t)
				started := make(chan struct{}, 1)
				stale := make(chan struct{}, 1)
				search := func(ctx context.Context, _ string, emit func(path string)) error {
					if tc.action == "confirm" {
						emit("main.go")
					}
					started <- struct{}{}
					<-ctx.Done()
					emit("stale.go")
					stale <- struct{}{}
					return errors.New("stale worker error")
				}
				startFileRefSearchThroughField(t, a, "main", search)
				select {
				case <-started:
				case <-time.After(2 * time.Second):
					t.Fatal("worker did not start")
				}

				a.app.QueueUpdate(func() {
					field := a.app.GetFocus().(*tview.InputField)
					switch tc.action {
					case "replace":
						field.SetText("next")
					case "clear":
						field.SetText("")
					case "escape":
						a.HandleEsc()
					case "confirm":
						field.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})
					}
				})
				select {
				case <-stale:
				case <-time.After(2 * time.Second):
					t.Fatal("canceled worker did not emit its stale callback")
				}
				a.app.QueueUpdate(func() {})

				a.app.QueueUpdate(func() {
					switch tc.action {
					case "replace":
						if a.filePicker == nil || a.filePicker.query != "next" || fileRefListText(a.filePicker) != fileRefSearchingRow {
							t.Errorf("replacement picker state changed after stale callbacks")
						}
					case "clear":
						if a.filePicker == nil || len(a.filePicker.shown) != 0 || fileRefListText(a.filePicker) != fileRefIdleGuidance {
							t.Errorf("cleared picker state changed after stale callbacks")
						}
					case "escape":
						if a.filePickerOpen || a.input.GetText() != "@main" {
							t.Errorf("ESC state changed after stale callbacks")
						}
					case "confirm":
						if a.filePickerOpen || a.input.GetText() != "@main.go" {
							t.Errorf("confirmation state changed after stale callbacks")
						}
					}
					if a.transcript.notice != "" {
						t.Errorf("stale worker error surfaced notice %q", a.transcript.notice)
					}
				})
			})
		}
	})

	t.Run("stale row and final callbacks are no-ops", func(t *testing.T) {
		a := New(nil)
		withFileRefSources(t, a, "main.go")
		a.input.SetText("@")
		sess := a.filePicker
		staleGen := sess.searchGeneration
		a.renderFileRefPlaceholder(sess, fileRefSearchingRow)
		a.invalidateFileRefSearch(sess)

		a.applyFileRefSearchRow(sess, staleGen, "leak.go")
		if len(sess.shown) != 0 {
			t.Errorf("a stale row mutated the live list: %v", sess.shown)
		}

		a.applyFileRefSearchFinal(sess, staleGen, nil)
		if !a.filePickerOpen {
			t.Error("a stale nil final dismissed the live picker")
		}
		a.applyFileRefSearchFinal(sess, staleGen, errors.New("stale error"))
		if a.transcript.notice != "" {
			t.Errorf("a stale error final surfaced a notice %q", a.transcript.notice)
		}
		if got := fileRefListText(sess); got != fileRefSearchingRow {
			t.Errorf("a stale final changed the list to %q", got)
		}
	})

	t.Run("ESC revokes ownership before cancel", func(t *testing.T) {
		a := New(nil)
		withFileRefSources(t, a, "main.go")
		a.input.SetText("@")
		sess := a.filePicker
		a.invalidateFileRefSearch(sess)
		before := sess.searchGeneration
		var cancelled bool
		var genAtCancel uint64
		sess.searchCancel = func() { cancelled = true; genAtCancel = sess.searchGeneration }

		a.HandleEsc()

		if !cancelled {
			t.Fatal("ESC did not cancel the in-flight search")
		}
		if genAtCancel != before+1 {
			t.Errorf("generation at cancel = %d, want %d (ownership advances before cancel)", genAtCancel, before+1)
		}
		if a.filePickerOpen {
			t.Error("ESC left the picker open")
		}
	})

	t.Run("confirm revokes ownership before cancel", func(t *testing.T) {
		a := New(nil)
		withFileRefSources(t, a, "main.go")
		a.input.SetText("@")
		sess := a.filePicker
		a.invalidateFileRefSearch(sess)
		showFileRefRows(a, sess, "main.go")
		before := sess.searchGeneration
		var cancelled bool
		var genAtCancel uint64
		sess.searchCancel = func() { cancelled = true; genAtCancel = sess.searchGeneration }

		a.confirmFileRef()

		if !cancelled {
			t.Fatal("confirm did not cancel the in-flight search")
		}
		if genAtCancel != before+1 {
			t.Errorf("generation at cancel = %d, want %d", genAtCancel, before+1)
		}
		if got := a.input.GetText(); got != "@main.go" {
			t.Errorf("input = %q, want the confirmed token %q", got, "@main.go")
		}
	})

	t.Run("replacement and clear revoke ownership before cancel", func(t *testing.T) {
		a := New(nil)
		withFileRefSources(t, a, "main.go")
		timers := collectFileRefTimers(a)
		a.input.SetText("@")
		sess := a.filePicker

		a.invalidateFileRefSearch(sess)
		before := sess.searchGeneration
		var replaced bool
		var replacedGen uint64
		sess.searchCancel = func() { replaced = true; replacedGen = sess.searchGeneration }
		a.onFileRefQueryChanged(sess, "mai")
		if !replaced {
			t.Fatal("a replacement query did not cancel the prior search")
		}
		if replacedGen != before+1 {
			t.Errorf("generation at replacement cancel = %d, want %d", replacedGen, before+1)
		}

		var cleared bool
		sess.searchCancel = func() { cleared = true }
		a.onFileRefQueryChanged(sess, "")
		if !cleared {
			t.Fatal("clearing the query did not cancel the pending search")
		}
		_ = timers
	})
}
