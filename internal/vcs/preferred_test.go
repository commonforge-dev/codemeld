// Tests for ValidatePreferred (cross-reference) and RunPreferred (single-detector boundary-aware walk).
package vcs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestValidatePreferred_EmptyDisables(t *testing.T) {
	if err := ValidatePreferred("", nil, nil, "global/settings.yaml"); err != nil {
		t.Fatalf("empty name: err = %v, want nil", err)
	}
}

func TestValidatePreferred_BuiltinAlwaysAccepted(t *testing.T) {
	builtins := []string{"git", "hg", "jj"}
	for _, name := range builtins {
		// No user templates loaded at all: a built-in name must still be accepted (set (a)).
		if err := ValidatePreferred(name, builtins, nil, "global/settings.yaml"); err != nil {
			t.Fatalf("built-in %q: err = %v, want nil", name, err)
		}
	}
}

func TestValidatePreferred_UserDefinedAcceptedOnceLoaded(t *testing.T) {
	if err := ValidatePreferred("fossil", []string{"git", "hg", "jj"}, []string{"fossil"}, "project/.codemeld/settings.yaml"); err != nil {
		t.Fatalf("loaded user template: err = %v, want nil", err)
	}
}

func TestValidatePreferred_UnknownRejected(t *testing.T) {
	src := "project/.codemeld/settings.yaml"
	err := ValidatePreferred("svn", []string{"git", "hg", "jj"}, []string{"fossil"}, src)
	if err == nil {
		t.Fatalf("unknown name: err = nil, want validation error")
	}
	msg := err.Error()
	for _, want := range []string{src, "vcs.preferred", `"svn"`, "schema validation failed"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}
}

func TestRunPreferred_MatchAtCWD(t *testing.T) {
	cwd := t.TempDir()
	mkMarker(t, cwd, ".hg")

	got, err := RunPreferred("hg", cwd, "project-root", cwd, "global/settings.yaml", builtinMarkers, nil)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != absClean(cwd) {
		t.Fatalf("matchedDir = %q, want %q", got, absClean(cwd))
	}
}

// Only the named detect runs: a directory with .git but preferred hg must not fall back to git.
func TestRunPreferred_SkipsPriorityNoFallback(t *testing.T) {
	cwd := t.TempDir()
	mkMarker(t, cwd, ".git")

	_, err := RunPreferred("hg", cwd, "project-root", cwd, "global/settings.yaml", builtinMarkers, nil)
	if err == nil {
		t.Fatalf("preferred hg over a git-only dir: err = nil, want no-match error")
	}
	if !strings.Contains(err.Error(), "vcs.preferred 'hg'") {
		t.Fatalf("error %q missing no-match text for hg", err.Error())
	}
}

// With both markers present, the named one selects the dir regardless of vcs.priority order.
func TestRunPreferred_BothMarkersNamedWins(t *testing.T) {
	cwd := t.TempDir()
	mkMarker(t, cwd, ".git")
	mkMarker(t, cwd, ".hg")

	got, err := RunPreferred("hg", cwd, "project-root", cwd, "global/settings.yaml", builtinMarkers, nil)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != absClean(cwd) {
		t.Fatalf("matchedDir = %q, want %q", got, absClean(cwd))
	}
}

func TestRunPreferred_DetectFailsEverywhere(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "a", "b")
	mkDirs(t, cwd)
	src := "project/.codemeld/settings.yaml"

	_, err := RunPreferred("git", cwd, "project-root", root, src, builtinMarkers, nil)
	if err == nil {
		t.Fatalf("no marker anywhere: err = nil, want detect-fails-everywhere error")
	}
	want := "codemeld: vcs.preferred 'git' (from " + src + "): no matching repo found; remove the override, change it, or launch in a directory where the named VCS is present"
	if err.Error() != want {
		t.Fatalf("error = %q\nwant      %q", err.Error(), want)
	}
}

func TestRunPreferred_InnermostMatchWins(t *testing.T) {
	root := t.TempDir()
	mid := filepath.Join(root, "a")
	cwd := filepath.Join(mid, "b")
	mkDirs(t, cwd)
	mkMarker(t, root, ".git")
	mkMarker(t, mid, ".git")

	got, err := RunPreferred("git", cwd, "project-root", root, "global/settings.yaml", builtinMarkers, nil)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != absClean(mid) {
		t.Fatalf("matchedDir = %q, want innermost %q", got, absClean(mid))
	}
}

func TestRunPreferred_LaunchDirOnly_ParentIgnored(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "a")
	mkDirs(t, cwd)
	mkMarker(t, root, ".git") // only the parent carries the marker

	_, err := RunPreferred("git", cwd, "launch-dir-only", root, "global/settings.yaml", builtinMarkers, nil)
	if err == nil {
		t.Fatalf("launch-dir-only with marker only at parent: err = nil, want no-match error")
	}
	if !strings.Contains(err.Error(), "no matching repo found") {
		t.Fatalf("error %q is not the no-match error", err.Error())
	}
}

func TestRunPreferred_LaunchDirOnly_Match(t *testing.T) {
	cwd := t.TempDir()
	mkMarker(t, cwd, ".git")

	got, err := RunPreferred("git", cwd, "launch-dir-only", "", "global/settings.yaml", builtinMarkers, nil)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != absClean(cwd) {
		t.Fatalf("matchedDir = %q, want %q", got, absClean(cwd))
	}
}

func TestRunPreferred_UnsupportedBoundary(t *testing.T) {
	cwd := t.TempDir()
	_, err := RunPreferred("git", cwd, "whole-disk", cwd, "global/settings.yaml", builtinMarkers, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported VCS auto-detect boundary") {
		t.Fatalf("err = %v, want unsupported-boundary error", err)
	}
}

func TestRunPreferred_CWDOutsideProjectRoot(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir() // a sibling temp dir, not under root
	_, err := RunPreferred("git", other, "project-root", root, "global/settings.yaml", builtinMarkers, nil)
	if err == nil || !strings.Contains(err.Error(), "is not within project root") {
		t.Fatalf("err = %v, want cwd-outside-root error", err)
	}
}

// In project-root mode an unreadable walk anchor (cwd) is fatal: RunPreferred must return an
// *AnchorReadError before probing or selecting an ancestor marker, and must not walk to a parent
// (walk-anchor exception), mirroring AutoDetect.
func TestRunPreferred_UnreadableAnchorProjectRoot(t *testing.T) {
	base := t.TempDir()
	mkMarker(t, base, ".git") // ancestor marker that must NOT be selected
	cwd := filepath.Join(base, "leaf")
	mkDirs(t, cwd)
	cwdAbs := absClean(cwd)

	setReadDir(t, func(p string) ([]os.DirEntry, error) {
		if p == cwdAbs {
			return nil, &os.PathError{Op: "open", Path: p, Err: syscall.EACCES}
		}
		t.Fatalf("readDir(%q) called: unreadable anchor must not probe parents", p)
		return nil, nil
	})

	got, err := RunPreferred("git", cwd, "project-root", base, "global/settings.yaml", builtinMarkers, nil)
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
	if got != "" {
		t.Fatalf("matchedDir = %q, want empty on anchor read failure", got)
	}
}

// In launch-dir-only mode the sole probed level is the anchor; an unreadable anchor is fatal
// (*AnchorReadError) rather than a no-match error, and no other directory is probed.
func TestRunPreferred_UnreadableAnchorLaunchDirOnly(t *testing.T) {
	cwd := t.TempDir()
	cwdAbs := absClean(cwd)

	setReadDir(t, func(p string) ([]os.DirEntry, error) {
		if p == cwdAbs {
			return nil, &os.PathError{Op: "open", Path: p, Err: syscall.EACCES}
		}
		t.Fatalf("readDir(%q) called: launch-dir-only must probe only the anchor", p)
		return nil, nil
	})

	got, err := RunPreferred("git", cwd, "launch-dir-only", "", "global/settings.yaml", builtinMarkers, nil)
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
	if got != "" {
		t.Fatalf("matchedDir = %q, want empty on anchor read failure", got)
	}
}

// A non-built-in preferred name probes its loaded template's detect marker.
func TestRunPreferred_CustomTemplateMarker(t *testing.T) {
	cwd := t.TempDir()
	mkMarker(t, cwd, ".fslckout")
	templates := map[string]*Template{"fossil": customTemplate("fossil", ".fslckout")}

	got, err := RunPreferred("fossil", cwd, "project-root", cwd, "global/settings.yaml", builtinMarkers, templates)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != absClean(cwd) {
		t.Fatalf("matchedDir = %q, want %q", got, absClean(cwd))
	}
}

// A built-in-name override probes the built-in marker, ignoring the override file's detect block.
func TestRunPreferred_BuiltinOverrideUsesBuiltinMarker(t *testing.T) {
	cwd := t.TempDir()
	mkMarker(t, cwd, ".git") // the real built-in marker
	// Override template claims a different marker that is NOT present on disk.
	templates := map[string]*Template{"git": customTemplate("git", ".not-here")}

	got, err := RunPreferred("git", cwd, "project-root", cwd, "global/settings.yaml", builtinMarkers, templates)
	if err != nil {
		t.Fatalf("built-in override should match via built-in marker: err = %v", err)
	}
	if got != absClean(cwd) {
		t.Fatalf("matchedDir = %q, want %q", got, absClean(cwd))
	}

	// Conversely, when only the override's bogus marker exists, the built-in name must not match.
	cwd2 := t.TempDir()
	mkMarker(t, cwd2, ".not-here")
	if _, err := RunPreferred("git", cwd2, "project-root", cwd2, "global/settings.yaml", builtinMarkers, templates); err == nil {
		t.Fatalf("override marker must be ignored: err = nil, want no-match error")
	}
}
