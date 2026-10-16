// Tests for project discovery: both boundary modes, innermost project-root selection, ~/.codemeld/ carve-out, and unreadable-directory paths.
package config

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"codemeld.dev/codemeld/internal/fserrors"
)

func mkMarker(t *testing.T, dir string) string {
	t.Helper()
	cm := filepath.Join(dir, ".codemeld")
	if err := os.MkdirAll(cm, 0o755); err != nil {
		t.Fatalf("mkdir marker dir: %v", err)
	}
	p := filepath.Join(cm, "settings.yaml")
	if err := os.WriteFile(p, []byte("discovery:\n  boundary: project-root\n"), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	return p
}

func mkDirs(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

// setHome overrides the userHomeDir seam so the carve-out is deterministic and the real home cannot accidentally match a temp ancestor.
func setHome(t *testing.T, home string) {
	t.Helper()
	orig := userHomeDir
	t.Cleanup(func() { userHomeDir = orig })
	userHomeDir = func() (string, error) { return home, nil }
}

func setReadDir(t *testing.T, fn func(string) ([]os.DirEntry, error)) {
	t.Helper()
	orig := readDir
	t.Cleanup(func() { readDir = orig })
	readDir = fn
}

func wantLayers(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("layers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("layers[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLocateProjectRoot_LaunchDirOnly(t *testing.T) {
	t.Run("marker present", func(t *testing.T) {
		cwd := t.TempDir()
		marker := mkMarker(t, cwd)

		root, layers, warnings, err := LocateProjectRoot(cwd, "launch-dir-only")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if root != cwd {
			t.Fatalf("root = %q, want %q", root, cwd)
		}
		wantLayers(t, layers, []string{marker})
		if len(warnings) != 0 {
			t.Fatalf("warnings = %v, want none", warnings)
		}
	})

	t.Run("marker absent", func(t *testing.T) {
		cwd := t.TempDir()

		root, layers, _, err := LocateProjectRoot(cwd, "launch-dir-only")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if root != cwd {
			t.Fatalf("root = %q, want %q", root, cwd)
		}
		if len(layers) != 0 {
			t.Fatalf("layers = %v, want none", layers)
		}
	})

	// launch-dir-only does not walk, so an unreadable anchor is irrelevant: only the launch-dir marker is consulted.
	t.Run("does not walk on unreadable anchor", func(t *testing.T) {
		cwd := t.TempDir()
		setReadDir(t, func(string) ([]os.DirEntry, error) {
			return nil, &os.PathError{Op: "open", Path: cwd, Err: syscall.EACCES}
		})
		root, layers, _, err := LocateProjectRoot(cwd, "launch-dir-only")
		if err != nil {
			t.Fatalf("err = %v, want nil (launch-dir-only must not read directories)", err)
		}
		if root != cwd || len(layers) != 0 {
			t.Fatalf("root = %q layers = %v, want %q and none", root, layers, cwd)
		}
	})
}

// An unsupported boundary mode must error and never fall through to the upward
// walk (which could inherit an ancestor marker); readDir is wired to fail if the
// walk is ever entered.
func TestLocateProjectRoot_InvalidMode(t *testing.T) {
	for _, mode := range []string{"", "typo", "Project-Root"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			setHome(t, filepath.Join(base, "no-such-home"))
			mkMarker(t, base) // ancestor marker that must NOT be selected
			cwd := filepath.Join(base, "a", "b")
			mkDirs(t, cwd)
			setReadDir(t, func(p string) ([]os.DirEntry, error) {
				t.Fatalf("readDir(%q) called: invalid mode must not walk upward", p)
				return nil, nil
			})

			anchor, _ := filepath.Abs(cwd)
			root, layers, warnings, err := LocateProjectRoot(cwd, mode)
			if err == nil {
				t.Fatalf("err = nil, want error for unsupported mode %q", mode)
			}
			if root != anchor || layers != nil || warnings != nil {
				t.Fatalf("root/layers/warnings = %q/%v/%v, want anchor/nil/nil", root, layers, warnings)
			}
		})
	}
}

func TestLocateProjectRoot_MarkerAtCWD(t *testing.T) {
	cwd := t.TempDir()
	setHome(t, filepath.Join(cwd, "no-such-home"))
	marker := mkMarker(t, cwd)

	root, layers, warnings, err := LocateProjectRoot(cwd, "project-root")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if root != cwd {
		t.Fatalf("root = %q, want %q", root, cwd)
	}
	wantLayers(t, layers, []string{marker})
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
}

func TestLocateProjectRoot_MarkerNLevelsUp(t *testing.T) {
	base := t.TempDir()
	setHome(t, filepath.Join(base, "no-such-home"))
	marker := mkMarker(t, base)
	cwd := filepath.Join(base, "a", "b", "c")
	mkDirs(t, cwd)

	root, layers, _, err := LocateProjectRoot(cwd, "project-root")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if root != base {
		t.Fatalf("root = %q, want %q", root, base)
	}
	wantLayers(t, layers, []string{marker})
}

func TestLocateProjectRoot_InnermostWins(t *testing.T) {
	base := t.TempDir()
	setHome(t, filepath.Join(base, "no-such-home"))
	mkMarker(t, base)
	inner := filepath.Join(base, "a")
	mkDirs(t, inner)
	innerMarker := mkMarker(t, inner)
	cwd := filepath.Join(inner, "b")
	mkDirs(t, cwd)

	root, layers, _, err := LocateProjectRoot(cwd, "project-root")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if root != inner {
		t.Fatalf("root = %q, want innermost %q", root, inner)
	}
	wantLayers(t, layers, []string{innerMarker})
}

func TestLocateProjectRoot_NoMarkerFallsBackToCWD(t *testing.T) {
	base := t.TempDir()
	setHome(t, filepath.Join(base, "no-such-home"))
	cwd := filepath.Join(base, "a", "b")
	mkDirs(t, cwd)

	root, layers, _, err := LocateProjectRoot(cwd, "project-root")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if root != cwd {
		t.Fatalf("root = %q, want fallback %q", root, cwd)
	}
	if len(layers) != 0 {
		t.Fatalf("layers = %v, want none", layers)
	}
}

// A stray settings.yaml directly under the home directory's .codemeld/ must never be matched as a project root.
func TestLocateProjectRoot_HomeCodemeldExcluded(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	mkMarker(t, home) // home/.codemeld/settings.yaml
	cwd := filepath.Join(home, "proj", "sub")
	mkDirs(t, cwd)

	root, layers, _, err := LocateProjectRoot(cwd, "project-root")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if root != cwd {
		t.Fatalf("root = %q, want fallback %q (home must be excluded)", root, cwd)
	}
	if len(layers) != 0 {
		t.Fatalf("layers = %v, want none (home marker must be ignored)", layers)
	}
}

func symlinkAlias(t *testing.T, target string) string {
	t.Helper()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(alias)
	if err != nil {
		t.Fatalf("EvalSymlinks(alias): %v", err)
	}
	if resolved == alias {
		t.Skipf("symlink alias %q did not differ from its resolved target", alias)
	}
	return alias
}

func TestLocateProjectRoot_LaunchDirOnlyThroughAlias(t *testing.T) {
	real := t.TempDir()
	marker := mkMarker(t, real)
	alias := symlinkAlias(t, real)

	root, layers, _, err := LocateProjectRoot(alias, "launch-dir-only")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if root != real {
		t.Fatalf("root = %q, want canonical %q (not alias %q)", root, real, alias)
	}
	wantLayers(t, layers, []string{marker})
}

func TestLocateProjectRoot_ProjectRootWalkThroughAlias(t *testing.T) {
	base := t.TempDir()
	setHome(t, filepath.Join(base, "no-such-home"))
	marker := mkMarker(t, base)
	realLeaf := filepath.Join(base, "a", "b")
	mkDirs(t, realLeaf)
	alias := symlinkAlias(t, realLeaf)

	root, layers, _, err := LocateProjectRoot(alias, "project-root")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if root != base {
		t.Fatalf("root = %q, want real marked ancestor %q (not via alias %q)", root, base, alias)
	}
	wantLayers(t, layers, []string{marker})
}

func TestLocateProjectRoot_ProjectRootFallbackThroughAlias(t *testing.T) {
	base := t.TempDir()
	setHome(t, filepath.Join(base, "no-such-home"))
	realLeaf := filepath.Join(base, "x", "y")
	mkDirs(t, realLeaf)
	alias := symlinkAlias(t, realLeaf)

	root, layers, _, err := LocateProjectRoot(alias, "project-root")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if root != realLeaf {
		t.Fatalf("root = %q, want canonical fallback %q (not alias %q)", root, realLeaf, alias)
	}
	if len(layers) != 0 {
		t.Fatalf("layers = %v, want none", layers)
	}
}

func TestLocateProjectRoot_HomeThroughAliasStillExcluded(t *testing.T) {
	realHome := t.TempDir()
	mkMarker(t, realHome)
	setHome(t, symlinkAlias(t, realHome))
	cwd := filepath.Join(realHome, "proj", "sub")
	mkDirs(t, cwd)

	root, layers, _, err := LocateProjectRoot(cwd, "project-root")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if root != cwd {
		t.Fatalf("root = %q, want fallback %q (home reached through an alias must still be excluded)", root, cwd)
	}
	if len(layers) != 0 {
		t.Fatalf("layers = %v, want none (home marker must be ignored even via an alias)", layers)
	}
}

func TestLocateProjectRoot_AnchorUnreadable(t *testing.T) {
	cwd := t.TempDir()
	setHome(t, filepath.Join(cwd, "no-such-home"))
	anchor, _ := filepath.Abs(cwd)
	setReadDir(t, func(p string) ([]os.DirEntry, error) {
		if p == anchor {
			return nil, &os.PathError{Op: "open", Path: p, Err: syscall.EACCES}
		}
		return os.ReadDir(p)
	})

	root, layers, warnings, err := LocateProjectRoot(cwd, "project-root")
	if err == nil {
		t.Fatalf("err = nil, want *AnchorReadError")
	}
	var are *AnchorReadError
	if !errors.As(err, &are) {
		t.Fatalf("err = %T, want *AnchorReadError", err)
	}
	if are.Operation != "read-walk-anchor" {
		t.Fatalf("Operation = %q, want read-walk-anchor", are.Operation)
	}
	if are.Anchor != anchor {
		t.Fatalf("Anchor = %q, want %q", are.Anchor, anchor)
	}
	if are.Category != fserrors.PermissionDenied {
		t.Fatalf("Category = %q, want %q", are.Category, fserrors.PermissionDenied)
	}
	if root != anchor || layers != nil || warnings != nil {
		t.Fatalf("root/layers/warnings = %q/%v/%v, want anchor/nil/nil", root, layers, warnings)
	}

	line := fserrors.FormatOpFail(are.Operation, are.Anchor, are.Category)
	want := "codemeld: read-walk-anchor failed: " + anchor + ": permission_denied"
	if line != want {
		t.Fatalf("OP_FAIL line = %q, want %q", line, want)
	}
}

func TestLocateProjectRoot_NonAnchorUnreadableWarnsAndContinues(t *testing.T) {
	base := t.TempDir()
	setHome(t, filepath.Join(base, "no-such-home"))
	proj := filepath.Join(base, "proj")
	mkDirs(t, proj)
	projMarker := mkMarker(t, proj)
	mid := filepath.Join(proj, "mid")
	cwd := filepath.Join(mid, "leaf")
	mkDirs(t, cwd)

	setReadDir(t, func(p string) ([]os.DirEntry, error) {
		if p == mid {
			return nil, &os.PathError{Op: "open", Path: p, Err: syscall.EACCES}
		}
		return os.ReadDir(p)
	})

	root, layers, warnings, err := LocateProjectRoot(cwd, "project-root")
	if err != nil {
		t.Fatalf("err = %v, want nil (walk must continue past unreadable dir)", err)
	}
	if root != proj {
		t.Fatalf("root = %q, want %q", root, proj)
	}
	wantLayers(t, layers, []string{projMarker})
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

func setStatMarker(t *testing.T, fn func(string) (os.FileInfo, error)) {
	t.Helper()
	orig := statMarker
	t.Cleanup(func() { statMarker = orig })
	statMarker = fn
}

// Falling back past an unclassifiable candidate would hand the trust gate a directory with no
// covered settings at all, which reads as "nothing to withhold" rather than as a failure.
func TestLocateProjectRoot_InvalidCandidateMarkerStopsTheWalk(t *testing.T) {
	t.Run("unreadable candidate marker", func(t *testing.T) {
		base := t.TempDir()
		setHome(t, filepath.Join(base, "nowhere"))
		project := filepath.Join(base, "project")
		cwd := filepath.Join(project, "nested")
		mkDirs(t, cwd)
		ancestorMarker := mkMarker(t, base)
		candidate := filepath.Join(project, markerRelPath)

		setStatMarker(t, func(path string) (os.FileInfo, error) {
			if path == candidate {
				return nil, &os.PathError{Op: "stat", Path: path, Err: syscall.EACCES}
			}
			return os.Stat(path)
		})

		root, layers, _, err := LocateProjectRoot(cwd, "project-root")
		if err != nil {
			t.Fatalf("LocateProjectRoot error: %v", err)
		}
		if root != project {
			t.Fatalf("root = %q, want the unreadable candidate's directory %q, not a fallback", root, project)
		}
		wantLayers(t, layers, []string{candidate})
		if slices.Contains(layers, ancestorMarker) {
			t.Fatalf("layers = %v, want the walk stopped before the readable ancestor marker", layers)
		}
	})

	t.Run("resolved marker target is not a regular file", func(t *testing.T) {
		base := t.TempDir()
		setHome(t, filepath.Join(base, "nowhere"))
		project := filepath.Join(base, "project")
		cwd := filepath.Join(project, "nested")
		mkDirs(t, cwd)
		mkMarker(t, base)
		candidate := filepath.Join(project, markerRelPath)
		mkDirs(t, filepath.Dir(candidate))
		if err := os.Symlink(t.TempDir(), candidate); err != nil {
			t.Fatalf("symlink marker to a directory: %v", err)
		}

		root, layers, _, err := LocateProjectRoot(cwd, "project-root")
		if err != nil {
			t.Fatalf("LocateProjectRoot error: %v", err)
		}
		if root != project {
			t.Fatalf("root = %q, want the non-regular candidate's directory %q, not a fallback", root, project)
		}
		wantLayers(t, layers, []string{candidate})
	})

	t.Run("a path component above the marker is not a directory", func(t *testing.T) {
		base := t.TempDir()
		setHome(t, filepath.Join(base, "nowhere"))
		project := filepath.Join(base, "project")
		cwd := filepath.Join(project, "nested")
		mkDirs(t, cwd)
		ancestorMarker := mkMarker(t, base)
		if err := os.WriteFile(filepath.Join(project, ".codemeld"), []byte("not a directory\n"), 0o600); err != nil {
			t.Fatalf("write .codemeld as a file: %v", err)
		}
		candidate := filepath.Join(project, markerRelPath)

		root, layers, _, err := LocateProjectRoot(cwd, "project-root")
		if err != nil {
			t.Fatalf("LocateProjectRoot error: %v", err)
		}
		if root != project {
			t.Fatalf("root = %q, want the non-directory candidate's directory %q, not a fallback", root, project)
		}
		wantLayers(t, layers, []string{candidate})
		if slices.Contains(layers, ancestorMarker) {
			t.Fatalf("layers = %v, want the walk stopped before the readable ancestor marker", layers)
		}
	})
}
