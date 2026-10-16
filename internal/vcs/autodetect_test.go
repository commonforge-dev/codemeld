// Tests for AutoDetect: boundary modes, innermost match, same-level ties, built-in override exclusion, custom templates, and unreadable-directory handling.
package vcs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// mkMarker creates dir/name as a directory so DetectInDir's lstat probe finds it.
func mkMarker(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
		t.Fatalf("mkdir marker %s/%s: %v", dir, name, err)
	}
}

func mkDirs(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

// setReadDir overrides the readDir seam so unreadable directories can be forced deterministically.
func setReadDir(t *testing.T, fn func(string) ([]os.DirEntry, error)) {
	t.Helper()
	orig := readDir
	t.Cleanup(func() { readDir = orig })
	readDir = fn
}

// customTemplate builds a minimal user template carrying only the detect marker AutoDetect consults.
func customTemplate(name, marker string) *Template {
	return &Template{Name: name, Detect: &DetectSpec{Marker: marker}, Actions: map[string]ActionSpec{}, Source: "test"}
}

func wantMatches(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("matches = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("matches[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestAutoDetect_MarkerAtCWD(t *testing.T) {
	cwd := t.TempDir()
	mkMarker(t, cwd, ".git")

	matches, depth, warnings, err := AutoDetect(cwd, "project-root", cwd, nil)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	wantMatches(t, matches, []string{"git"})
	if depth != 0 {
		t.Fatalf("depth = %d, want 0", depth)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
}

func TestAutoDetect_MarkerNLevelsUp(t *testing.T) {
	base := t.TempDir()
	mkMarker(t, base, ".git")
	cwd := filepath.Join(base, "a", "b", "c")
	mkDirs(t, cwd)

	matches, depth, _, err := AutoDetect(cwd, "project-root", base, nil)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	wantMatches(t, matches, []string{"git"})
	if depth != 3 {
		t.Fatalf("depth = %d, want 3", depth)
	}
}

func TestAutoDetect_TiedMarkersSameLevel(t *testing.T) {
	cwd := t.TempDir()
	mkMarker(t, cwd, ".git")
	mkMarker(t, cwd, ".hg")

	matches, depth, _, err := AutoDetect(cwd, "project-root", cwd, nil)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	// Built-ins are returned in canonical order so vcs.priority tie-breaking sees a stable candidate set.
	wantMatches(t, matches, []string{"git", "hg"})
	if depth != 0 {
		t.Fatalf("depth = %d, want 0", depth)
	}
}

func TestAutoDetect_NoMarkerFound(t *testing.T) {
	base := t.TempDir()
	cwd := filepath.Join(base, "a", "b")
	mkDirs(t, cwd)

	matches, depth, warnings, err := AutoDetect(cwd, "project-root", base, nil)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(matches) != 0 {
		t.Fatalf("matches = %v, want empty", matches)
	}
	if depth != -1 {
		t.Fatalf("depth = %d, want -1", depth)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
}

func TestAutoDetect_BuiltinNameOverrideUsesBuiltinDetect(t *testing.T) {
	// A user template named "git" must not add a second detector: the built-in .git marker is
	// authoritative during auto-detection, and the override's own marker is ignored.
	templates := map[string]*Template{"git": customTemplate("git", ".override-marker")}

	t.Run("matches built-in marker once", func(t *testing.T) {
		cwd := t.TempDir()
		mkMarker(t, cwd, ".git")

		matches, depth, _, err := AutoDetect(cwd, "project-root", cwd, templates)
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		wantMatches(t, matches, []string{"git"}) // exactly once, not twice
		if depth != 0 {
			t.Fatalf("depth = %d, want 0", depth)
		}
	})

	t.Run("override marker is not used", func(t *testing.T) {
		cwd := t.TempDir()
		mkMarker(t, cwd, ".override-marker") // present, but the override's detect must be ignored

		matches, depth, _, err := AutoDetect(cwd, "project-root", cwd, templates)
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if len(matches) != 0 {
			t.Fatalf("matches = %v, want empty (override marker must not be probed)", matches)
		}
		if depth != -1 {
			t.Fatalf("depth = %d, want -1", depth)
		}
	})
}

func TestAutoDetect_CustomTemplateParticipates(t *testing.T) {
	cwd := t.TempDir()
	mkMarker(t, cwd, ".fossil")
	templates := map[string]*Template{"fossil": customTemplate("fossil", ".fossil")}

	matches, depth, _, err := AutoDetect(cwd, "project-root", cwd, templates)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	wantMatches(t, matches, []string{"fossil"})
	if depth != 0 {
		t.Fatalf("depth = %d, want 0", depth)
	}
}

func TestAutoDetect_DetectorOrdering(t *testing.T) {
	// Built-ins first in canonical order, then non-built-in templates sorted by name.
	cwd := t.TempDir()
	mkMarker(t, cwd, ".git")
	mkMarker(t, cwd, ".aaa")
	mkMarker(t, cwd, ".fossil")
	templates := map[string]*Template{
		"fossil": customTemplate("fossil", ".fossil"),
		"aaa":    customTemplate("aaa", ".aaa"),
	}

	matches, _, _, err := AutoDetect(cwd, "project-root", cwd, templates)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	wantMatches(t, matches, []string{"git", "aaa", "fossil"})
}

func TestAutoDetect_LaunchDirOnly(t *testing.T) {
	t.Run("marker present", func(t *testing.T) {
		cwd := t.TempDir()
		mkMarker(t, cwd, ".hg")

		matches, depth, _, err := AutoDetect(cwd, "launch-dir-only", "", nil)
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		wantMatches(t, matches, []string{"hg"})
		if depth != 0 {
			t.Fatalf("depth = %d, want 0", depth)
		}
	})

	t.Run("does not walk to ancestor marker", func(t *testing.T) {
		base := t.TempDir()
		mkMarker(t, base, ".git") // ancestor marker that must NOT be seen
		cwd := filepath.Join(base, "sub")
		mkDirs(t, cwd)

		matches, depth, _, err := AutoDetect(cwd, "launch-dir-only", base, nil)
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if len(matches) != 0 {
			t.Fatalf("matches = %v, want empty (launch-dir-only must not walk)", matches)
		}
		if depth != -1 {
			t.Fatalf("depth = %d, want -1", depth)
		}
	})
}

func TestAutoDetect_UnsupportedBoundary(t *testing.T) {
	cwd := t.TempDir()
	mkMarker(t, cwd, ".git")
	setReadDir(t, func(p string) ([]os.DirEntry, error) {
		t.Fatalf("readDir(%q) called: unsupported boundary must not walk", p)
		return nil, nil
	})

	for _, mode := range []string{"", "typo", "Project-Root"} {
		t.Run(mode, func(t *testing.T) {
			matches, depth, warnings, err := AutoDetect(cwd, mode, cwd, nil)
			if err == nil {
				t.Fatalf("err = nil, want error for unsupported boundary %q", mode)
			}
			if matches != nil || depth != -1 || warnings != nil {
				t.Fatalf("matches/depth/warnings = %v/%d/%v, want nil/-1/nil", matches, depth, warnings)
			}
		})
	}
}

func TestAutoDetect_UnreadableDirWarnsAndContinues(t *testing.T) {
	base := t.TempDir()
	mkMarker(t, base, ".git")
	mid := filepath.Join(base, "mid")
	cwd := filepath.Join(mid, "leaf")
	mkDirs(t, cwd)

	setReadDir(t, func(p string) ([]os.DirEntry, error) {
		if p == mid {
			return nil, &os.PathError{Op: "open", Path: p, Err: syscall.EACCES}
		}
		return os.ReadDir(p)
	})

	matches, depth, warnings, err := AutoDetect(cwd, "project-root", base, nil)
	if err != nil {
		t.Fatalf("err = %v, want nil (walk must continue past unreadable dir)", err)
	}
	wantMatches(t, matches, []string{"git"})
	if depth != 2 {
		t.Fatalf("depth = %d, want 2 (leaf=0, mid=1, base=2)", depth)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly one", warnings)
	}
	w := warnings[0]
	if !strings.Contains(w, mid) {
		t.Fatalf("warning %q does not name skipped directory %q", w, mid)
	}
	if !strings.Contains(w, "errno") || !strings.Contains(w, "permission denied") {
		t.Fatalf("warning %q missing OS error code", w)
	}
	if strings.Contains(w, "\n") {
		t.Fatalf("warning is not single-line: %q", w)
	}
}

func TestAutoDetect_UnreadableBoundaryStops(t *testing.T) {
	// The project root itself is unreadable: it is probed (and skipped with a warning), then the
	// walk stops because the boundary has been reached rather than continuing upward.
	base := t.TempDir()
	cwd := filepath.Join(base, "leaf")
	mkDirs(t, cwd)
	rootAbs, _ := filepath.Abs(base)

	setReadDir(t, func(p string) ([]os.DirEntry, error) {
		if p == rootAbs {
			return nil, &os.PathError{Op: "open", Path: p, Err: syscall.EACCES}
		}
		return os.ReadDir(p)
	})

	matches, depth, warnings, err := AutoDetect(cwd, "project-root", base, nil)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(matches) != 0 || depth != -1 {
		t.Fatalf("matches/depth = %v/%d, want empty/-1", matches, depth)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly one for the skipped boundary dir", warnings)
	}
}

func TestAutoDetect_UnreadableAnchorProjectRoot(t *testing.T) {
	// The walk anchor (cwd) itself is unreadable: AutoDetect must fail before the walk and must not
	// probe or select an ancestor marker (walk-anchor exception).
	base := t.TempDir()
	mkMarker(t, base, ".git") // ancestor marker that must NOT be selected
	cwd := filepath.Join(base, "leaf")
	mkDirs(t, cwd)
	cwdAbs, _ := filepath.Abs(cwd)

	setReadDir(t, func(p string) ([]os.DirEntry, error) {
		if p == cwdAbs {
			return nil, &os.PathError{Op: "open", Path: p, Err: syscall.EACCES}
		}
		t.Fatalf("readDir(%q) called: unreadable anchor must not probe parents", p)
		return nil, nil
	})

	matches, depth, warnings, err := AutoDetect(cwd, "project-root", base, nil)
	if err == nil {
		t.Fatalf("err = nil, want error for unreadable walk anchor")
	}
	var are *AnchorReadError
	if !errors.As(err, &are) {
		t.Fatalf("err = %v, want *AnchorReadError", err)
	}
	if are.Operation != "read-walk-anchor" {
		t.Fatalf("operation = %q, want read-walk-anchor", are.Operation)
	}
	if are.Anchor != cwdAbs {
		t.Fatalf("anchor = %q, want %q", are.Anchor, cwdAbs)
	}
	if matches != nil || depth != -1 || warnings != nil {
		t.Fatalf("matches/depth/warnings = %v/%d/%v, want nil/-1/nil", matches, depth, warnings)
	}
}

func TestAutoDetect_UnreadableAnchorLaunchDirOnly(t *testing.T) {
	// In launch-dir-only mode the sole probed level is the anchor; an unreadable anchor fails rather
	// than returning a success-with-warning (walk-anchor exception).
	cwd := t.TempDir()
	cwdAbs, _ := filepath.Abs(cwd)

	setReadDir(t, func(p string) ([]os.DirEntry, error) {
		if p == cwdAbs {
			return nil, &os.PathError{Op: "open", Path: p, Err: syscall.EACCES}
		}
		t.Fatalf("readDir(%q) called: launch-dir-only must probe only the anchor", p)
		return nil, nil
	})

	matches, depth, warnings, err := AutoDetect(cwd, "launch-dir-only", "", nil)
	if err == nil {
		t.Fatalf("err = nil, want error for unreadable walk anchor")
	}
	var are *AnchorReadError
	if !errors.As(err, &are) {
		t.Fatalf("err = %v, want *AnchorReadError", err)
	}
	if are.Operation != "read-walk-anchor" {
		t.Fatalf("operation = %q, want read-walk-anchor", are.Operation)
	}
	if are.Anchor != cwdAbs {
		t.Fatalf("anchor = %q, want %q", are.Anchor, cwdAbs)
	}
	if matches != nil || depth != -1 || warnings != nil {
		t.Fatalf("matches/depth/warnings = %v/%d/%v, want nil/-1/nil", matches, depth, warnings)
	}
}

func TestAutoDetect_CwdOutsideProjectRoot(t *testing.T) {
	base := t.TempDir()
	cwd := filepath.Join(base, "here")
	projectRoot := filepath.Join(base, "elsewhere") // sibling, not an ancestor of cwd
	mkDirs(t, cwd)
	mkDirs(t, projectRoot)
	setReadDir(t, func(p string) ([]os.DirEntry, error) {
		t.Fatalf("readDir(%q) called: out-of-bounds cwd must error before walking", p)
		return nil, nil
	})

	matches, depth, warnings, err := AutoDetect(cwd, "project-root", projectRoot, nil)
	if err == nil {
		t.Fatalf("err = nil, want error for cwd outside project root")
	}
	if matches != nil || depth != -1 || warnings != nil {
		t.Fatalf("matches/depth/warnings = %v/%d/%v, want nil/-1/nil", matches, depth, warnings)
	}
}
