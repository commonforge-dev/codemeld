// Unit tests for the shared read-target resolver and symlink-policy predicates: project-root-relative
// resolution (stable across process cwd), required vs optional/default path modes, adversarial out-of-root
// rejection before any read, in-root tilde expansion, directory/file scope, and the directory-symlink /
// list-classification / read-regular-file predicates.
package filetools

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readOpts is the read tool's mode: a path is required.
var readOpts = ReadTargetOptions{RequirePath: true, Kind: "read"}

// dirOpts mirrors the directory-oriented tools (grep/glob/list/tree): an omitted path defaults to root.
var dirOpts = ReadTargetOptions{RequirePath: false, Kind: "list"}

// recursiveOpts mirrors the recursive tools (grep/glob/tree): an omitted path defaults to root and a
// final-component directory symlink is rejected fail-closed before descent.
var recursiveOpts = ReadTargetOptions{RequirePath: false, Kind: "grep", RejectDirectorySymlink: true}

// The *ExtOpts variants mirror the dispatch read tools' real options, which set AllowExternal so an
// EXPLICIT absolute/~ path outside the project root becomes a promptable external read instead of a
// pre-authorization rejection. Every other structural rejection still applies.
var (
	readExtOpts      = ReadTargetOptions{RequirePath: true, Kind: "read", AllowExternal: true}
	dirExtOpts       = ReadTargetOptions{RequirePath: false, Kind: "list", AllowExternal: true}
	recursiveExtOpts = ReadTargetOptions{RequirePath: false, Kind: "grep", RejectDirectorySymlink: true, AllowExternal: true}
)

func symlink(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Fatalf("Symlink(%q -> %q): %v", newname, oldname, err)
	}
}

// TestResolveReadTarget_RelativeResolvesAgainstProjectRoot pins Done-when 1: a relative path resolves
// against the project root, not the process cwd. The tool is built with a process cwd that holds a decoy
// file of the same relative name; resolution must reach the project-root copy regardless.
func TestResolveReadTarget_RelativeResolvesAgainstProjectRoot(t *testing.T) {
	root := eval(t, t.TempDir())
	otherCWD := eval(t, t.TempDir())
	home := t.TempDir()

	writeFile(t, filepath.Join(root, "shared.txt"), "ROOT")
	writeFile(t, filepath.Join(otherCWD, "shared.txt"), "CWD")

	target, scope, err := ResolveReadTarget(home, otherCWD, root, map[string]any{"path": "shared.txt"}, readOpts)
	if err != nil {
		t.Fatalf("ResolveReadTarget error = %v, want nil", err)
	}
	want := filepath.Join(root, "shared.txt")
	if target != want {
		t.Fatalf("target = %q, want %q (resolved against project root, not process cwd %q)", target, want, otherCWD)
	}
	if scope != root {
		t.Fatalf("scope = %q, want %q (the file's enclosing directory)", scope, root)
	}
	if got := readFile(t, target); got != "ROOT" {
		t.Fatalf("resolved target content = %q, want ROOT (the process-cwd decoy must not win)", got)
	}
}

// TestResolveReadTarget_OptionalDefaultAndRequired pins Done-when 1: an omitted optional path defaults to
// the project root, while read mode requires a non-empty path.
func TestResolveReadTarget_OptionalDefaultAndRequired(t *testing.T) {
	root := eval(t, t.TempDir())
	home := t.TempDir()

	t.Run("optional omitted defaults to root", func(t *testing.T) {
		target, scope, err := ResolveReadTarget(home, root, root, map[string]any{}, dirOpts)
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		if target != root || scope != root {
			t.Fatalf("target=%q scope=%q, want both %q", target, scope, root)
		}
	})

	t.Run("optional blank defaults to root", func(t *testing.T) {
		target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": "   "}, dirOpts)
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		if target != root || scope != root {
			t.Fatalf("target=%q scope=%q, want both %q", target, scope, root)
		}
	})

	t.Run("read mode requires a path", func(t *testing.T) {
		for _, args := range []map[string]any{{}, {"path": ""}, {"path": "   "}} {
			_, _, err := ResolveReadTarget(home, root, root, args, readOpts)
			var te *TargetError
			if !errors.As(err, &te) {
				t.Fatalf("ResolveReadTarget(%v) error = %v, want *TargetError", args, err)
			}
		}
	})
}

// TestResolveReadTarget_AdversarialRejectTable pins Done-when 2: ../ traversal, an absolute-outside path,
// a symlink whose target escapes the root, and a ~user form are each rejected with a *TargetError and
// return no usable target, so no read can occur against an out-of-root path.
func TestResolveReadTarget_AdversarialRejectTable(t *testing.T) {
	root := eval(t, t.TempDir())
	home := t.TempDir()
	outsideDir := eval(t, t.TempDir())
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	writeFile(t, outsideFile, "TOP SECRET")

	// In-project symlinks whose destinations are outside the root.
	symlink(t, outsideDir, filepath.Join(root, "linkdir"))
	symlink(t, outsideFile, filepath.Join(root, "linkfile"))

	cases := []struct {
		name string
		path any
	}{
		{"dot-dot traversal", "../escape.txt"},
		{"nested dot-dot traversal", "a/../../escape.txt"},
		{"absolute outside file", outsideFile},
		{"absolute outside dir", outsideDir},
		{"symlink escape to dir", "linkdir"},
		{"symlink escape to file", "linkfile"},
		{"tilde user form", "~bob/secret.txt"},
		{"non-string path", 42},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": tc.path}, readOpts)
			var te *TargetError
			if !errors.As(err, &te) {
				t.Fatalf("error = %v, want *TargetError", err)
			}
			if target != "" || scope != "" {
				t.Fatalf("returned target=%q scope=%q on rejection, want both empty (no readable target)", target, scope)
			}
		})
	}
}

// TestResolveReadTarget_ExternalExplicitPathResolvesWhenAllowed pins the external-read producer contract: with
// AllowExternal set, an EXPLICIT absolute or ~ path outside the project root resolves to a concrete
// out-of-root target and scope (so dispatch can prompt) instead of being rejected, and the scope is the
// target's real symlink-resolved location so a grant anchors on the truth, never a symlink alias.
func TestResolveReadTarget_ExternalExplicitPathResolvesWhenAllowed(t *testing.T) {
	root := eval(t, t.TempDir())
	home := t.TempDir() // outside root, so "~" names an explicit external directory
	outsideDir := eval(t, t.TempDir())
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	writeFile(t, outsideFile, "EXTERNAL")

	t.Run("absolute outside file resolves to external target and scope", func(t *testing.T) {
		target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": outsideFile}, readExtOpts)
		if err != nil {
			t.Fatalf("error = %v, want nil (an explicit external path is promptable, not rejected)", err)
		}
		if target != outsideFile {
			t.Fatalf("target = %q, want %q", target, outsideFile)
		}
		if scope != outsideDir {
			t.Fatalf("scope = %q, want %q (the external file's enclosing dir)", scope, outsideDir)
		}
		if !isExternalReadScope(scope, root) {
			t.Fatalf("isExternalReadScope(%q, %q) = false, want true", scope, root)
		}
	})

	t.Run("absolute outside dir resolves to itself for recursive tools", func(t *testing.T) {
		target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": outsideDir}, recursiveExtOpts)
		if err != nil {
			t.Fatalf("error = %v, want nil (a real external directory is a valid promptable recursive target)", err)
		}
		if target != outsideDir || scope != outsideDir {
			t.Fatalf("target=%q scope=%q, want both %q", target, scope, outsideDir)
		}
	})

	t.Run("tilde-home outside the project resolves as external", func(t *testing.T) {
		realHome := eval(t, home)
		target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": "~"}, dirExtOpts)
		if err != nil {
			t.Fatalf("error = %v, want nil (~ outside the project is an explicit external path)", err)
		}
		if target != realHome || scope != realHome {
			t.Fatalf("target=%q scope=%q, want both %q", target, scope, realHome)
		}
	})

	t.Run("non-existent external target returns the anchored path", func(t *testing.T) {
		missing := filepath.Join(outsideDir, "missing.txt")
		target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": missing}, readExtOpts)
		if err != nil {
			t.Fatalf("error = %v, want nil (resolution does not require existence)", err)
		}
		if target != missing || scope != outsideDir {
			t.Fatalf("target=%q scope=%q, want %q and %q", target, scope, missing, outsideDir)
		}
	})

	t.Run("external explicit symlink resolves to its real location, not the alias", func(t *testing.T) {
		otherDir := eval(t, t.TempDir())
		otherFile := filepath.Join(otherDir, "real.txt")
		writeFile(t, otherFile, "REAL")
		alias := filepath.Join(outsideDir, "alias")
		symlink(t, otherFile, alias)

		target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": alias}, readExtOpts)
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		if target != otherFile {
			t.Fatalf("target = %q, want %q (followed to the real file)", target, otherFile)
		}
		if scope != otherDir {
			t.Fatalf("scope = %q, want %q (the real file's dir, so a grant cannot widen to the alias's dir)", scope, otherDir)
		}
	})
}

// TestResolveReadTarget_AllowExternalStillRejectsEscapes pins the fail-closed boundary: even with
// AllowExternal set, the only widening is an EXPLICIT absolute/~ external path. A relative ".." traversal,
// an in-root path whose final symlink escapes the root, a ~user form, a non-string path, and a
// directory-symlink root for the recursive tools (in-root or external) all stay *TargetError rejections
// with no usable target, so AllowExternal can never smuggle an implicit escape past the resolver.
func TestResolveReadTarget_AllowExternalStillRejectsEscapes(t *testing.T) {
	root := eval(t, t.TempDir())
	home := t.TempDir() // outside root
	outsideDir := eval(t, t.TempDir())
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	writeFile(t, outsideFile, "SECRET")
	symlink(t, outsideDir, filepath.Join(root, "linkdir"))
	symlink(t, outsideFile, filepath.Join(root, "linkfile"))

	// An explicit external directory symlink that points at another external directory: a recursive tool
	// must still refuse to follow a directory symlink as its root, even out-of-project.
	extReal := eval(t, t.TempDir())
	extLinkParent := eval(t, t.TempDir())
	extDLink := filepath.Join(extLinkParent, "dlink")
	symlink(t, extReal, extDLink)

	cases := []struct {
		name string
		path any
		opts ReadTargetOptions
	}{
		{"relative dotdot traversal", "../escape.txt", readExtOpts},
		{"nested relative dotdot traversal", "a/../../escape.txt", readExtOpts},
		{"in-root symlink escape to file", "linkfile", readExtOpts},
		{"in-root symlink escape to dir", "linkdir", dirExtOpts},
		{"in-root directory symlink for recursive", "linkdir", recursiveExtOpts},
		{"external directory symlink root for recursive", extDLink, recursiveExtOpts},
		{"tilde user form", "~bob/secret.txt", readExtOpts},
		{"non-string path", 42, readExtOpts},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": tc.path}, tc.opts)
			var te *TargetError
			if !errors.As(err, &te) {
				t.Fatalf("error = %v, want *TargetError (AllowExternal must not relax this escape)", err)
			}
			if target != "" || scope != "" {
				t.Fatalf("returned target=%q scope=%q on rejection, want both empty", target, scope)
			}
		})
	}
}

// TestResolveReadTarget_FailureSurfacesInBand pins Done-when 4: a rejection is a *TargetError (never a
// turn-aborting Go error) that converts to a non-zero-exit, stderr-bearing tool result via failResult.
func TestResolveReadTarget_FailureSurfacesInBand(t *testing.T) {
	root := eval(t, t.TempDir())
	home := t.TempDir()

	_, _, err := ResolveReadTarget(home, root, root, map[string]any{"path": "../escape.txt"}, readOpts)
	var te *TargetError
	if !errors.As(err, &te) {
		t.Fatalf("error = %v, want *TargetError", err)
	}
	res := failResult(err.Error())
	if res.ExitCode == 0 {
		t.Fatalf("failResult ExitCode = 0, want non-zero (in-band failure)")
	}
	if !strings.Contains(string(res.Stderr), "read target rejected") {
		t.Fatalf("stderr = %q, want it to name the rejected read target", res.Stderr)
	}
}

// TestResolveReadTarget_TildeInRoot pins Done-when 4: ~ expands for an in-root path. Home is placed inside
// the project so "~/f.txt" resolves to an in-project file and is accepted.
func TestResolveReadTarget_TildeInRoot(t *testing.T) {
	root := eval(t, t.TempDir())
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatalf("Mkdir home: %v", err)
	}
	want := filepath.Join(home, "f.txt")
	writeFile(t, want, "HI")

	target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": "~/f.txt"}, readOpts)
	if err != nil {
		t.Fatalf("ResolveReadTarget(~/f.txt) error = %v, want nil", err)
	}
	if target != want {
		t.Fatalf("target = %q, want %q", target, want)
	}
	if scope != home {
		t.Fatalf("scope = %q, want %q", scope, home)
	}
}

// TestResolveReadTarget_DirectoryAndFileScope asserts both the returned target and the path scope so a
// later tool cannot authorize one path and read another (Architecture Review risk): a directory target
// scopes to itself; a file target scopes to its enclosing directory.
func TestResolveReadTarget_DirectoryAndFileScope(t *testing.T) {
	root := eval(t, t.TempDir())
	home := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	file := filepath.Join(sub, "f.txt")
	writeFile(t, file, "X")

	t.Run("directory target scopes to itself", func(t *testing.T) {
		target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": "sub"}, dirOpts)
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		if target != sub || scope != sub {
			t.Fatalf("target=%q scope=%q, want both %q", target, scope, sub)
		}
	})

	t.Run("file target scopes to parent", func(t *testing.T) {
		target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": "sub/f.txt"}, readOpts)
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		if target != file {
			t.Fatalf("target = %q, want %q", target, file)
		}
		if scope != sub {
			t.Fatalf("scope = %q, want %q (enclosing dir)", scope, sub)
		}
	})
}

// TestResolveReadTarget_FollowsInRootSymlink: a final-component symlink that stays inside the root is
// followed to its real target (so the returned path is the real in-project node), the complement of the
// symlink-escape rejections. The recursive tools (RejectDirectorySymlink) are the exception: they accept
// a real directory but refuse a directory symlink fail-closed before descent.
func TestResolveReadTarget_FollowsInRootSymlink(t *testing.T) {
	root := eval(t, t.TempDir())
	home := t.TempDir()

	realDir := filepath.Join(root, "realdir")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	realFile := filepath.Join(root, "real.txt")
	writeFile(t, realFile, "DATA")
	symlink(t, realDir, filepath.Join(root, "dlink"))
	symlink(t, realFile, filepath.Join(root, "flink"))

	t.Run("symlink to in-root dir is followed for list", func(t *testing.T) {
		target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": "dlink"}, dirOpts)
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		if target != realDir || scope != realDir {
			t.Fatalf("target=%q scope=%q, want both %q", target, scope, realDir)
		}
	})

	t.Run("real dir accepted for recursive tools", func(t *testing.T) {
		target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": "realdir"}, recursiveOpts)
		if err != nil {
			t.Fatalf("error = %v, want nil (a real directory is a valid recursive target)", err)
		}
		if target != realDir || scope != realDir {
			t.Fatalf("target=%q scope=%q, want both %q", target, scope, realDir)
		}
	})

	t.Run("symlink to in-root dir rejected for recursive tools", func(t *testing.T) {
		target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": "dlink"}, recursiveOpts)
		var te *TargetError
		if !errors.As(err, &te) {
			t.Fatalf("error = %v, want *TargetError (recursive tools must not follow a directory symlink, req 35)", err)
		}
		if target != "" || scope != "" {
			t.Fatalf("returned target=%q scope=%q on rejection, want both empty", target, scope)
		}
	})

	t.Run("symlink to in-root file", func(t *testing.T) {
		target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": "flink"}, readOpts)
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		if target != realFile {
			t.Fatalf("target = %q, want %q", target, realFile)
		}
		if scope != root {
			t.Fatalf("scope = %q, want %q", scope, root)
		}
	})
}

// TestResolveReadTarget_NonExistentTargetIsContained: a non-existent in-root target is returned as the
// anchored path (contained, scope = enclosing dir) so the calling tool reports a normal not-found rather
// than this resolver aborting the turn.
func TestResolveReadTarget_NonExistentTargetIsContained(t *testing.T) {
	root := eval(t, t.TempDir())
	home := t.TempDir()

	target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": "missing.txt"}, readOpts)
	if err != nil {
		t.Fatalf("error = %v, want nil (resolution does not require existence)", err)
	}
	if want := filepath.Join(root, "missing.txt"); target != want {
		t.Fatalf("target = %q, want %q", target, want)
	}
	if scope != root {
		t.Fatalf("scope = %q, want %q", scope, root)
	}
}

// TestResolveReadTarget_SymlinkedProjectRoot pins the symlinked-root regression: when the project root
// passed in is itself a symlink (production roots are absolute and cleaned but not symlink-resolved), a
// boundary-valid in-root path must still resolve, because the resolver normalizes the root to the same
// symlink-resolved form used for candidate parents. A symlink that escapes the (resolved) root must still
// reject.
func TestResolveReadTarget_SymlinkedProjectRoot(t *testing.T) {
	realRoot := eval(t, t.TempDir())
	home := t.TempDir()
	// A symlink whose destination is the real project root; passed in unresolved as projectRoot.
	linkRoot := filepath.Join(t.TempDir(), "proj-link")
	symlink(t, realRoot, linkRoot)

	writeFile(t, filepath.Join(realRoot, "file.txt"), "ROOT-FILE")
	outsideDir := eval(t, t.TempDir())
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	writeFile(t, outsideFile, "TOP SECRET")
	symlink(t, outsideFile, filepath.Join(realRoot, "escape"))

	t.Run("in-root path resolves under a symlinked root", func(t *testing.T) {
		target, scope, err := ResolveReadTarget(home, linkRoot, linkRoot, map[string]any{"path": "file.txt"}, readOpts)
		if err != nil {
			t.Fatalf("ResolveReadTarget error = %v, want nil (in-root file under a symlinked root)", err)
		}
		if want := filepath.Join(realRoot, "file.txt"); target != want {
			t.Fatalf("target = %q, want %q (resolved to the real root)", target, want)
		}
		if scope != realRoot {
			t.Fatalf("scope = %q, want %q", scope, realRoot)
		}
		if got := readFile(t, target); got != "ROOT-FILE" {
			t.Fatalf("resolved target content = %q, want ROOT-FILE", got)
		}
	})

	t.Run("symlink escape still rejects under a symlinked root", func(t *testing.T) {
		target, scope, err := ResolveReadTarget(home, linkRoot, linkRoot, map[string]any{"path": "escape"}, readOpts)
		var te *TargetError
		if !errors.As(err, &te) {
			t.Fatalf("error = %v, want *TargetError (symlink escape must reject)", err)
		}
		if target != "" || scope != "" {
			t.Fatalf("returned target=%q scope=%q on rejection, want both empty", target, scope)
		}
	})
}

// rootForm is one way of writing a path that denotes the project root, with a label for subtests. Shared
// by the resolver-level and tool-level explicit-root regression tests.
type rootForm struct {
	name string
	path string
}

// rootPathForms returns the explicit-root path spellings the resolver must accept: the absolute root, "." and
// "./", and the absolute root with a trailing separator — all of which denote the project root itself.
func rootPathForms(root string) []rootForm {
	return []rootForm{
		{"absolute", root},
		{"dot", "."},
		{"dot-slash", "./"},
		{"trailing-slash", root + string(filepath.Separator)},
	}
}

// TestResolveReadTarget_ExplicitRootAccepted pins that a present, non-blank path that denotes the project
// root resolves to (root, root) — the same result an omitted path returns — for both the plain
// directory-oriented tools and the recursive tools (where the real root is not a directory symlink, so the
// RejectDirectorySymlink rule does not apply to it).
func TestResolveReadTarget_ExplicitRootAccepted(t *testing.T) {
	root := eval(t, t.TempDir())
	home := t.TempDir()

	for _, opts := range []ReadTargetOptions{dirOpts, recursiveOpts} {
		opts := opts
		t.Run(opts.Kind, func(t *testing.T) {
			for _, f := range rootPathForms(root) {
				f := f
				t.Run(f.name, func(t *testing.T) {
					target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": f.path}, opts)
					if err != nil {
						t.Fatalf("ResolveReadTarget(path=%q) error = %v, want nil", f.path, err)
					}
					if target != root || scope != root {
						t.Fatalf("path=%q: target=%q scope=%q, want both %q", f.path, target, scope, root)
					}
				})
			}
		})
	}
}

// TestResolveReadTarget_ExplicitRootUnderSymlinkedRoot pins that a path that canonicalizes to the
// project root itself is accepted even for the recursive tools, including when the project root passed in
// is an unresolved symlink and the same symlinked form is given as path — it resolves to the real root.
func TestResolveReadTarget_ExplicitRootUnderSymlinkedRoot(t *testing.T) {
	realRoot := eval(t, t.TempDir())
	home := t.TempDir()
	linkRoot := filepath.Join(t.TempDir(), "proj-link")
	symlink(t, realRoot, linkRoot)

	for _, opts := range []ReadTargetOptions{dirOpts, recursiveOpts} {
		opts := opts
		t.Run(opts.Kind, func(t *testing.T) {
			target, scope, err := ResolveReadTarget(home, linkRoot, linkRoot, map[string]any{"path": linkRoot}, opts)
			if err != nil {
				t.Fatalf("ResolveReadTarget(path=symlinked root) error = %v, want nil", err)
			}
			if target != realRoot || scope != realRoot {
				t.Fatalf("target=%q scope=%q, want both %q (the real root)", target, scope, realRoot)
			}
		})
	}
}

// TestResolveReadTarget_ExplicitRootNegative pins that the root short-circuit is exact-root-only: the
// root's parent and a ../ escape are still rejected, a directory symlink pointing at a non-root in-root
// directory is still refused by the recursive tools (it canonicalizes elsewhere, not to root), and an
// out-of-root symlink whose target IS the project root is rejected fail-closed instead of
// being short-circuited as the root: its parent lies outside the root, so it must fail parent containment.
func TestResolveReadTarget_ExplicitRootNegative(t *testing.T) {
	root := eval(t, t.TempDir())
	home := t.TempDir()
	realDir := filepath.Join(root, "realdir")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	symlink(t, realDir, filepath.Join(root, "dlink"))

	// An out-of-root symlink aliasing the project root: outside/link-to-root -> root.
	outside := eval(t, t.TempDir())
	outsideRootAlias := filepath.Join(outside, "link-to-root")
	symlink(t, root, outsideRootAlias)

	cases := []struct {
		name string
		path string
		opts ReadTargetOptions
	}{
		{"root parent absolute", filepath.Dir(root), dirOpts},
		{"dot-dot escape", "..", dirOpts},
		{"dot-dot alias cleaning back to root", filepath.Join("..", filepath.Base(root)), dirOpts},
		{"non-root dir symlink for recursive tools", "dlink", recursiveOpts},
		{"out-of-root symlink alias to root", outsideRootAlias, dirOpts},
		{"out-of-root symlink alias to root for recursive tools", outsideRootAlias, recursiveOpts},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			target, scope, err := ResolveReadTarget(home, root, root, map[string]any{"path": tc.path}, tc.opts)
			var te *TargetError
			if !errors.As(err, &te) {
				t.Fatalf("ResolveReadTarget(path=%q) error = %v, want *TargetError", tc.path, err)
			}
			if target != "" || scope != "" {
				t.Fatalf("path=%q: returned target=%q scope=%q on rejection, want both empty", tc.path, target, scope)
			}
		})
	}
}

// TestIsDirectorySymlink pins Done-when 3: directory-symlink no-follow detection used by recursive tools.
func TestIsDirectorySymlink(t *testing.T) {
	root := eval(t, t.TempDir())
	dir := filepath.Join(root, "dir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	file := filepath.Join(root, "f.txt")
	writeFile(t, file, "X")
	dlink := filepath.Join(root, "dlink")
	symlink(t, dir, dlink)
	flink := filepath.Join(root, "flink")
	symlink(t, file, flink)
	dangling := filepath.Join(root, "dangling")
	symlink(t, filepath.Join(root, "nowhere"), dangling)

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"real directory", dir, false},
		{"regular file", file, false},
		{"symlink to dir", dlink, true},
		{"symlink to file", flink, false},
		{"dangling symlink", dangling, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := IsDirectorySymlink(tc.path)
			if err != nil {
				t.Fatalf("IsDirectorySymlink error = %v, want nil", err)
			}
			if got != tc.want {
				t.Fatalf("IsDirectorySymlink(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestClassifyEntry pins Done-when 3: list classifies entries by their own type without following a
// symlink, so a symlink (to a file or a dir) is reported as EntrySymlink.
func TestClassifyEntry(t *testing.T) {
	root := eval(t, t.TempDir())
	dir := filepath.Join(root, "dir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	file := filepath.Join(root, "f.txt")
	writeFile(t, file, "X")
	flink := filepath.Join(root, "flink")
	symlink(t, file, flink)
	dlink := filepath.Join(root, "dlink")
	symlink(t, dir, dlink)

	cases := []struct {
		name string
		path string
		want EntryKind
	}{
		{"regular file", file, EntryFile},
		{"directory", dir, EntryDir},
		{"symlink to file", flink, EntrySymlink},
		{"symlink to dir", dlink, EntrySymlink},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ClassifyEntry(tc.path)
			if err != nil {
				t.Fatalf("ClassifyEntry error = %v, want nil", err)
			}
			if got != tc.want {
				t.Fatalf("ClassifyEntry(%s) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

// TestResolveReadFile pins Done-when 3: the read tool follows a symlink only to a regular file inside the
// root; a directory, a symlink-to-dir, a symlink-escape, and a missing target are all refused.
func TestResolveReadFile(t *testing.T) {
	root := eval(t, t.TempDir())
	outsideDir := eval(t, t.TempDir())
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	writeFile(t, outsideFile, "SECRET")

	file := filepath.Join(root, "f.txt")
	writeFile(t, file, "DATA")
	dir := filepath.Join(root, "dir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	flink := filepath.Join(root, "flink")
	symlink(t, file, flink)
	dlink := filepath.Join(root, "dlink")
	symlink(t, dir, dlink)
	escape := filepath.Join(root, "escape")
	symlink(t, outsideFile, escape)

	t.Run("regular file", func(t *testing.T) {
		real, ok, reason := ResolveReadFile(file, root)
		if !ok {
			t.Fatalf("ok = false (%q), want true", reason)
		}
		if real != file {
			t.Fatalf("real = %q, want %q", real, file)
		}
	})

	t.Run("symlink to in-root regular file is followed", func(t *testing.T) {
		real, ok, reason := ResolveReadFile(flink, root)
		if !ok {
			t.Fatalf("ok = false (%q), want true", reason)
		}
		if real != file {
			t.Fatalf("real = %q, want %q (followed to the real file)", real, file)
		}
	})

	for _, tc := range []struct {
		name string
		path string
	}{
		{"directory", dir},
		{"symlink to dir", dlink},
		{"symlink escape", escape},
		{"missing", filepath.Join(root, "missing.txt")},
	} {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			real, ok, reason := ResolveReadFile(tc.path, root)
			if ok {
				t.Fatalf("ok = true, want false for %s", tc.name)
			}
			if real != "" {
				t.Fatalf("real = %q, want empty on refusal", real)
			}
			if reason == "" {
				t.Fatalf("reason empty, want a non-empty rejection reason for %s", tc.name)
			}
		})
	}
}
