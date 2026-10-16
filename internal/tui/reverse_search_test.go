// Tests for the CTRL-R history reverse-search overlay.
package tui

import (
	"testing"

	"github.com/gdamore/tcell/v2"
)

func ctrlR(a *App) *tcell.EventKey { return tcell.NewEventKey(tcell.KeyCtrlR, 0, tcell.ModNone) }

func TestMostRecentMatch(t *testing.T) {
	hist := []string{"git status", "ls -la", "git commit", "make build"}
	cases := []struct {
		name      string
		history   []string
		query     string
		wantMatch string
		wantOK    bool
	}{
		{"empty query matches newest", hist, "", "make build", true},
		{"most recent containing substring", hist, "git", "git commit", true},
		{"only-older match", hist, "status", "git status", true},
		{"no match", hist, "zzz", "", false},
		{"empty history", nil, "anything", "", false},
		{"empty history empty query", []string{}, "", "", false},
		{"exact substring not case folded", hist, "GIT", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := mostRecentMatch(tc.history, tc.query)
			if got != tc.wantMatch || ok != tc.wantOK {
				t.Fatalf("mostRecentMatch(%q) = (%q, %v), want (%q, %v)", tc.query, got, ok, tc.wantMatch, tc.wantOK)
			}
		})
	}
}

func TestReverseSearchSession_SetQueryTracksMatch(t *testing.T) {
	s := newReverseSearchSession([]string{"alpha one", "beta two", "alpha three"})
	if !s.matched || s.match != "alpha three" {
		t.Fatalf("initial match = (%q, %v), want newest entry", s.match, s.matched)
	}
	s.setQuery("beta")
	if !s.matched || s.match != "beta two" {
		t.Fatalf("after %q match = (%q, %v), want beta two", "beta", s.match, s.matched)
	}
	s.setQuery("alpha")
	if !s.matched || s.match != "alpha three" {
		t.Fatalf("after %q match = (%q, %v), want most-recent alpha", "alpha", s.match, s.matched)
	}
	s.setQuery("nope")
	if s.matched || s.match != "" {
		t.Fatalf("after no-match query match = (%q, %v), want cleared", s.match, s.matched)
	}
	if got := renderReverseSearchMatch(s); got != reverseSearchNoMatch {
		t.Fatalf("no-match render = %q, want %q", got, reverseSearchNoMatch)
	}
}

// TR-TUI-16: CTRL-R with empty history shows the hint, opens no overlay, and the
// hint clears on the next keystroke.
func TestOpenReverseSearch_EmptyHistoryShowsHintNoOverlayClearsOnNextKey(t *testing.T) {
	a := New(nil)

	if got := a.handleGlobalKey(ctrlR(a)); got != nil {
		t.Fatalf("CTRL-R returned %v, want nil (consumed)", got)
	}
	if a.reverseSearchOpen {
		t.Fatal("overlay opened on empty history; req 650 forbids opening")
	}
	if a.pages.HasPage(reverseSearchPage) {
		t.Fatal("reverse-search page mounted on empty history")
	}
	if got := a.transcript.notice; got != reverseSearchEmptyHint {
		t.Fatalf("notice = %q, want %q", got, reverseSearchEmptyHint)
	}

	// Next keystroke clears the hint.
	a.handleGlobalKey(tcell.NewEventKey(tcell.KeyRune, 'a', tcell.ModNone))
	if got := a.transcript.notice; got != "" {
		t.Fatalf("notice after next keystroke = %q, want cleared", got)
	}
}

func TestOpenReverseSearch_NoOpWhileAnotherOverlayOpen(t *testing.T) {
	a := New(nil)
	a.history.Append("git status")
	a.ShowStatus("status snapshot")

	if got := a.handleGlobalKey(ctrlR(a)); got != nil {
		t.Fatalf("CTRL-R returned %v, want nil (consumed even when inert)", got)
	}
	if a.reverseSearchOpen {
		t.Fatal("reverse-search opened over an existing overlay; req 600 forbids it")
	}
	if !a.statusOpen {
		t.Fatal("existing status overlay was disturbed by CTRL-R")
	}
}

func TestOpenReverseSearch_OpensWithMostRecentMatch(t *testing.T) {
	a := New(nil)
	a.history.Append("git status")
	a.history.Append("make build")

	a.handleGlobalKey(ctrlR(a))

	if !a.reverseSearchOpen {
		t.Fatal("CTRL-R did not open the overlay with non-empty history")
	}
	if !a.pages.HasPage(reverseSearchPage) {
		t.Fatal("reverse-search page not mounted")
	}
	if a.reverseSearch == nil || a.reverseSearch.match != "make build" {
		t.Fatalf("initial match = %+v, want most-recent entry", a.reverseSearch)
	}
}

func TestReverseSearchFieldKeys_UpDownConsumedKeepMatch(t *testing.T) {
	a := New(nil)
	a.history.Append("git status")
	a.history.Append("make build")
	a.openReverseSearch()

	for _, k := range []tcell.Key{tcell.KeyUp, tcell.KeyDown} {
		if got := a.reverseSearchFieldKeys(tcell.NewEventKey(k, 0, tcell.ModNone)); got != nil {
			t.Fatalf("field key %v returned %v, want nil (consumed)", k, got)
		}
	}
	if !a.reverseSearchOpen {
		t.Fatal("overlay closed by ↑/↓; phase 1 keeps the single match selected")
	}
	if a.reverseSearch.match != "make build" {
		t.Fatalf("match after ↑/↓ = %q, want unchanged most-recent", a.reverseSearch.match)
	}
}

func TestAcceptReverseSearch_NoMatchIsNoOp(t *testing.T) {
	a := New(nil)
	a.history.Append("git status")
	a.input.SetText("draft")
	a.openReverseSearch()
	a.reverseSearch.setQuery("zzz") // no entry contains this

	a.reverseSearchFieldKeys(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone))

	if !a.reverseSearchOpen {
		t.Fatal("Enter on no-match dismissed the overlay; it must be a no-op")
	}
	if got := a.input.GetText(); got != "draft" {
		t.Fatalf("buffer after no-match Enter = %q, want preserved draft", got)
	}
}

func TestAcceptReverseSearch_AcceptsMatchIntoBuffer(t *testing.T) {
	a := New(nil)
	a.history.Append("git status")
	a.history.Append("make build")
	a.input.SetText("partial")
	a.openReverseSearch()
	a.reverseSearch.setQuery("git")

	a.reverseSearchFieldKeys(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone))

	if a.reverseSearchOpen {
		t.Fatal("overlay still open after accepting a match")
	}
	if got := a.input.GetText(); got != "git status" {
		t.Fatalf("buffer after accept = %q, want accepted match", got)
	}
}

func TestReverseSearch_EscDismissesPreservesBuffer(t *testing.T) {
	a := New(nil)
	a.history.Append("git status")
	a.input.SetText("draft")
	a.openReverseSearch()

	// ESC routes through the central ESC priority path.
	a.HandleEsc()

	if a.reverseSearchOpen {
		t.Fatal("overlay still open after ESC")
	}
	if a.pages.HasPage(reverseSearchPage) {
		t.Fatal("reverse-search page still mounted after ESC")
	}
	if got := a.input.GetText(); got != "draft" {
		t.Fatalf("buffer after ESC = %q, want preserved draft", got)
	}
}

func TestReverseSearch_LabelNotYellow(t *testing.T) {
	a := New(nil)
	a.history.Append("git status")
	a.history.Append("make build")
	a.openReverseSearch()

	s := drawPrimitive(t, a.pages, 60, 12)
	cells, width, _ := s.GetContents()

	row, col := findCell(t, s, reverseSearchLabel)
	for c := col; c < col+len(reverseSearchLabel); c++ {
		fg, bg, _ := cells[row*width+c].Style.Decompose()
		if isYellow(fg) || isYellow(bg) {
			t.Errorf("reverse-search label cell (%d,%d) uses fixed yellow (fg=%06X bg=%06X)", row, c, fg.Hex(), bg.Hex())
		}
	}
}

func TestReverseSearchFieldKeys_EscDismissesPreservesBuffer(t *testing.T) {
	a := New(nil)
	a.history.Append("git status")
	a.input.SetText("draft")
	a.openReverseSearch()

	if got := a.reverseSearchFieldKeys(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone)); got != nil {
		t.Fatalf("field ESC returned %v, want nil (consumed)", got)
	}
	if a.reverseSearchOpen {
		t.Fatal("overlay still open after field-level ESC")
	}
	if got := a.input.GetText(); got != "draft" {
		t.Fatalf("buffer after field ESC = %q, want preserved draft", got)
	}
}
