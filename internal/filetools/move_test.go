// Unit tests for the built-in move tool: metadata/classification, pre-authorization two-endpoint
// resolution (in-scope, missing/symlink source, existing destination of every form, missing parents,
// same resolved endpoint, traversal, ~user, bad args), supported ~ home-anchor expansion and in/out-of-root
// ".." traversal for both endpoints, independent out-of-root classification of each endpoint (including a
// source or destination parent reached through an in-project symlink to outside), standalone refusal of
// either out-of-root endpoint, and the pre-resolved no-overwrite move of a file and a directory. The tool
// stays unregistered: these tests exercise it directly, never through dispatch or a registry.
package filetools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// newMoveToolIn builds a move tool whose project root and relative-path base are root, with a separate
// home anchor, so relative endpoints land inside the project and ~ expansion is exercised independently —
// mirroring newCreateToolIn and newToolIn.
func newMoveToolIn(t *testing.T, root string) *MoveTool {
	t.Helper()
	return NewMoveTool(t.TempDir(), root, root)
}

func TestMoveTool_AdvertiseMetadata(t *testing.T) {
	tool := newMoveToolIn(t, t.TempDir())

	if tool.Name() != "move" {
		t.Fatalf("Name() = %q, want move", tool.Name())
	}
	if tool.SubjectKind() != "tool" {
		t.Fatalf("SubjectKind() = %q, want tool", tool.SubjectKind())
	}

	md := tool.Advertise()
	if md.ReadOnly {
		t.Fatal("Advertise().ReadOnly = true, want false (the move tool is mutating)")
	}
	if strings.TrimSpace(md.Description) == "" {
		t.Fatal("Advertise().Description is empty, want a one-line description")
	}
	if md.Parameters["type"] != "object" {
		t.Fatalf("Parameters.type = %v, want object", md.Parameters["type"])
	}
	if md.Parameters["additionalProperties"] != false {
		t.Fatalf("Parameters.additionalProperties = %v, want false", md.Parameters["additionalProperties"])
	}
	required, ok := md.Parameters["required"].([]string)
	if !ok || !reflect.DeepEqual(required, []string{"source", "destination"}) {
		t.Fatalf("Parameters.required = %v, want [source destination]", md.Parameters["required"])
	}
	props, ok := md.Parameters["properties"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters.properties type = %T, want map[string]any", md.Parameters["properties"])
	}
	// Both endpoints must advertise the out-of-root contract: in-project paths move normally, an out-of-root
	// endpoint is permitted via the permission prompt rather than forbidden. Guard against either
	// description regressing to a flat "within the project" requirement, which would contradict dispatch
	// prompting (instead of hard-denying) for an out-of-root endpoint.
	for _, key := range []string{"source", "destination"} {
		prop, ok := props[key].(map[string]any)
		if !ok {
			t.Fatalf("Parameters.properties[%s] type = %T, want map[string]any", key, props[key])
		}
		desc, _ := prop["description"].(string)
		if strings.Contains(desc, "within the project") {
			t.Fatalf("%s description still claims endpoints are %q; out-of-root moves are prompt-gated, not forbidden: %q", key, "within the project", desc)
		}
		for _, want := range []string{"outside the project", "permission prompt"} {
			if !strings.Contains(desc, want) {
				t.Fatalf("%s description = %q, want it to mention %q (out-of-root prompt approval)", key, desc, want)
			}
		}
	}
}

// TestMoveTool_ResolveEndpointsInScope proves a fully in-root move resolves both endpoints to their real
// paths and parent scopes, neither flagged out-of-root.
func TestMoveTool_ResolveEndpointsInScope(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMoveToolIn(t, root)

	writeFile(t, filepath.Join(root, "a.txt"), "A\n")

	resolved, err := tool.ResolveEndpoints(map[string]any{"source": "a.txt", "destination": "b.txt"})
	if err != nil {
		t.Fatalf("ResolveEndpoints error = %v, want nil", err)
	}
	if resolved.Source != filepath.Join(root, "a.txt") {
		t.Fatalf("Source = %q, want %q", resolved.Source, filepath.Join(root, "a.txt"))
	}
	if resolved.Destination != filepath.Join(root, "b.txt") {
		t.Fatalf("Destination = %q, want %q", resolved.Destination, filepath.Join(root, "b.txt"))
	}
	if resolved.SourceScope != root || resolved.DestinationScope != root {
		t.Fatalf("scopes = (%q, %q), want both %q", resolved.SourceScope, resolved.DestinationScope, root)
	}
	if resolved.SourceOutOfRoot || resolved.DestinationOutOfRoot {
		t.Fatalf("out-of-root flags = (%v, %v), want both false", resolved.SourceOutOfRoot, resolved.DestinationOutOfRoot)
	}
}

// TestMoveTool_NegativeResolutionTable is the adversarial negative table: every structurally invalid move
// is rejected with a *TargetError before authorization, and nothing on disk changes. Existing entries are
// asserted byte/-kind identical and no destination is created.
func TestMoveTool_NegativeResolutionTable(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMoveToolIn(t, root)

	srcFile := filepath.Join(root, "src.txt")
	writeFile(t, srcFile, "SOURCE\n")
	existingFile := filepath.Join(root, "exists.txt")
	writeFile(t, existingFile, "ORIGINAL\n")
	existingDir := filepath.Join(root, "subdir")
	if err := os.Mkdir(existingDir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	// Symlink to the source: a final source symlink must be refused (move relocates the real entry, not a
	// link to it), not followed.
	srcLink := filepath.Join(root, "srclink")
	if err := os.Symlink(srcFile, srcLink); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	// Dangling symlink: exists as a symlink even though its destination does not, so it is an existing
	// destination form move must refuse before any rename.
	danglingLink := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(root, "nowhere"), danglingLink); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	cases := []struct {
		name string
		args map[string]any
	}{
		{"missing source entry", map[string]any{"source": "ghost.txt", "destination": "dst.txt"}},
		{"source is a symlink", map[string]any{"source": "srclink", "destination": "dst.txt"}},
		{"source parent missing", map[string]any{"source": "no/such/src.txt", "destination": "dst.txt"}},
		{"destination is an existing file", map[string]any{"source": "src.txt", "destination": "exists.txt"}},
		{"destination is an existing directory", map[string]any{"source": "src.txt", "destination": "subdir"}},
		{"destination is an existing dangling symlink", map[string]any{"source": "src.txt", "destination": "dangling"}},
		{"destination parent missing", map[string]any{"source": "src.txt", "destination": "no/such/dst.txt"}},
		{"same resolved endpoint", map[string]any{"source": "src.txt", "destination": "src.txt"}},
		{"unsupported ~user source", map[string]any{"source": "~nobody/x", "destination": "dst.txt"}},
		{"unsupported ~user destination", map[string]any{"source": "src.txt", "destination": "~nobody/x"}},
		{"empty source", map[string]any{"source": "", "destination": "dst.txt"}},
		{"empty destination", map[string]any{"source": "src.txt", "destination": ""}},
		{"missing source argument", map[string]any{"destination": "dst.txt"}},
		{"missing destination argument", map[string]any{"source": "src.txt"}},
		{"non-string source argument", map[string]any{"source": 42, "destination": "dst.txt"}},
		{"non-string destination argument", map[string]any{"source": "src.txt", "destination": 42}},
		{"unknown argument", map[string]any{"source": "src.txt", "destination": "dst.txt", "extra": "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tool.ResolveEndpoints(tc.args)
			var te *TargetError
			if !errors.As(err, &te) {
				t.Fatalf("ResolveEndpoints error = %v, want *TargetError", err)
			}
		})
	}

	// Nothing the table touched may have changed, and no destination may have been created.
	if got := readFile(t, srcFile); got != "SOURCE\n" {
		t.Fatalf("source file = %q, want unchanged SOURCE", got)
	}
	if got := readFile(t, existingFile); got != "ORIGINAL\n" {
		t.Fatalf("existing file = %q, want unchanged ORIGINAL", got)
	}
	if info, err := os.Stat(existingDir); err != nil || !info.IsDir() {
		t.Fatalf("existing dir changed: info=%v err=%v", info, err)
	}
	if fi, err := os.Lstat(danglingLink); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("existing symlink changed: mode=%v err=%v", fi.Mode(), err)
	}
	if _, err := os.Lstat(filepath.Join(root, "dst.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a destination was created by a rejected move: %v", err)
	}
}

// TestMoveTool_ResolveEndpointsOutOfRoot pins out-of-root prompting for both endpoints independently: an
// out-of-root endpoint is not a hard *TargetError but resolves (promptable) to its real out-of-root parent
// folder as the path scope and is flagged out-of-root, including a parent reached through an in-project
// symlink. The in-root endpoint in each pair stays in-root. A pre-resolved move into the authorized
// out-of-root folder then succeeds, proving the resolved endpoints are reused at invoke time.
func TestMoveTool_ResolveEndpointsOutOfRoot(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMoveToolIn(t, root)
	outsideDir := eval(t, t.TempDir())

	t.Run("out-of-root destination absolute", func(t *testing.T) {
		src := filepath.Join(root, "moveme.txt")
		writeFile(t, src, "OUT\n")
		dst := filepath.Join(outsideDir, "moved.txt")

		resolved, err := tool.ResolveEndpoints(map[string]any{"source": src, "destination": dst})
		if err != nil {
			t.Fatalf("ResolveEndpoints error = %v, want nil (promptable)", err)
		}
		if resolved.SourceOutOfRoot {
			t.Fatal("SourceOutOfRoot = true, want false for an in-root source")
		}
		if !resolved.DestinationOutOfRoot {
			t.Fatal("DestinationOutOfRoot = false, want true")
		}
		if resolved.DestinationScope != outsideDir {
			t.Fatalf("DestinationScope = %q, want the real out-of-root folder %q", resolved.DestinationScope, outsideDir)
		}
		if !tool.OutOfRootScope(resolved.DestinationScope) {
			t.Fatalf("OutOfRootScope(%q) = false, want true", resolved.DestinationScope)
		}

		res, err := tool.InvokeWithResolvedMove(context.Background(), resolved)
		if err != nil {
			t.Fatalf("InvokeWithResolvedMove error = %v, want nil", err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
		}
		if got := readFile(t, dst); got != "OUT\n" {
			t.Fatalf("out-of-root destination = %q, want OUT", got)
		}
		if _, statErr := os.Lstat(src); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("source still present after move: %v", statErr)
		}
	})

	t.Run("out-of-root source absolute", func(t *testing.T) {
		src := filepath.Join(outsideDir, "from-outside.txt")
		writeFile(t, src, "IN\n")

		resolved, err := tool.ResolveEndpoints(map[string]any{"source": src, "destination": "landed.txt"})
		if err != nil {
			t.Fatalf("ResolveEndpoints error = %v, want nil (promptable)", err)
		}
		if !resolved.SourceOutOfRoot {
			t.Fatal("SourceOutOfRoot = false, want true")
		}
		if resolved.DestinationOutOfRoot {
			t.Fatal("DestinationOutOfRoot = true, want false for an in-root destination")
		}
		if resolved.SourceScope != outsideDir {
			t.Fatalf("SourceScope = %q, want the real out-of-root folder %q", resolved.SourceScope, outsideDir)
		}
	})

	t.Run("destination parent reached through an in-project symlink to outside", func(t *testing.T) {
		escapeLink := filepath.Join(root, "escape")
		if err := os.Symlink(outsideDir, escapeLink); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		writeFile(t, filepath.Join(root, "viasym.txt"), "S\n")

		resolved, err := tool.ResolveEndpoints(map[string]any{"source": "viasym.txt", "destination": "escape/child.txt"})
		if err != nil {
			t.Fatalf("ResolveEndpoints error = %v, want nil (promptable)", err)
		}
		if resolved.Destination != filepath.Join(outsideDir, "child.txt") {
			t.Fatalf("Destination = %q, want the real path %q", resolved.Destination, filepath.Join(outsideDir, "child.txt"))
		}
		if !resolved.DestinationOutOfRoot {
			t.Fatal("DestinationOutOfRoot on symlink parent = false, want true")
		}
	})

	t.Run("source parent reached through an in-project symlink to outside", func(t *testing.T) {
		// Mirror of the destination symlink-escape case for the source endpoint: a real file living outside
		// the root, reached through an in-project symlink parent, must resolve (promptable) to its real
		// out-of-root path and folder, with the source flagged out-of-root and the in-root destination left
		// in-root — so the source-side parent symlink resolution is pinned, not just the destination's.
		writeFile(t, filepath.Join(outsideDir, "fromsymparent.txt"), "S\n")
		srcLink := filepath.Join(root, "srcescape")
		if err := os.Symlink(outsideDir, srcLink); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		resolved, err := tool.ResolveEndpoints(map[string]any{"source": "srcescape/fromsymparent.txt", "destination": "pulled-in.txt"})
		if err != nil {
			t.Fatalf("ResolveEndpoints error = %v, want nil (promptable)", err)
		}
		if resolved.Source != filepath.Join(outsideDir, "fromsymparent.txt") {
			t.Fatalf("Source = %q, want the real path %q", resolved.Source, filepath.Join(outsideDir, "fromsymparent.txt"))
		}
		if resolved.SourceScope != outsideDir {
			t.Fatalf("SourceScope = %q, want the real out-of-root folder %q", resolved.SourceScope, outsideDir)
		}
		if !resolved.SourceOutOfRoot {
			t.Fatal("SourceOutOfRoot on symlink parent = false, want true")
		}
		if resolved.DestinationOutOfRoot {
			t.Fatal("DestinationOutOfRoot = true, want false for an in-root destination")
		}
	})
}

// TestMoveTool_ResolveEndpointsTildeAndTraversal pins the supported home-anchor (~) expansion and ".."
// traversal branches of the shared resolver for both move endpoints — the resolver matrix the negative
// table's ~user/structural rows do not reach. A "~" anchored inside the project resolves under the home
// anchor and stays in-root; "~/.." expands relative to home first and then traverses, landing out-of-root
// when home sits outside the project; a relative ".." that stays inside the base resolves in-root, while one
// that escapes the base resolves (promptable) to its real out-of-root parent. Each case asserts the
// resolved endpoint, its scope, and the out-of-root flag, so a regression in ~ expansion or ".." handling
// in resolveAnchoredTarget fails here.
func TestMoveTool_ResolveEndpointsTildeAndTraversal(t *testing.T) {
	t.Run("supported ~ endpoints resolve under the home anchor (in-root)", func(t *testing.T) {
		root := eval(t, t.TempDir())
		home := filepath.Join(root, "home")
		if err := os.Mkdir(home, 0o755); err != nil {
			t.Fatalf("Mkdir home: %v", err)
		}
		tool := NewMoveTool(home, root, root)
		writeFile(t, filepath.Join(home, "fromhome.txt"), "H\n")

		resolved, err := tool.ResolveEndpoints(map[string]any{"source": "~/fromhome.txt", "destination": "~/landed.txt"})
		if err != nil {
			t.Fatalf("ResolveEndpoints error = %v, want nil", err)
		}
		if resolved.Source != filepath.Join(home, "fromhome.txt") {
			t.Fatalf("Source = %q, want %q (expanded under the home anchor)", resolved.Source, filepath.Join(home, "fromhome.txt"))
		}
		if resolved.Destination != filepath.Join(home, "landed.txt") {
			t.Fatalf("Destination = %q, want %q (expanded under the home anchor)", resolved.Destination, filepath.Join(home, "landed.txt"))
		}
		if resolved.SourceScope != home || resolved.DestinationScope != home {
			t.Fatalf("scopes = (%q, %q), want both %q", resolved.SourceScope, resolved.DestinationScope, home)
		}
		if resolved.SourceOutOfRoot || resolved.DestinationOutOfRoot {
			t.Fatalf("out-of-root flags = (%v, %v), want both false for a home anchor inside the project", resolved.SourceOutOfRoot, resolved.DestinationOutOfRoot)
		}
	})

	t.Run("~/.. expands relative to home then traverses out-of-root", func(t *testing.T) {
		root := eval(t, t.TempDir())
		outsideHomeRoot := eval(t, t.TempDir())
		outsideHome := filepath.Join(outsideHomeRoot, "home")
		if err := os.Mkdir(outsideHome, 0o755); err != nil {
			t.Fatalf("Mkdir outside home: %v", err)
		}
		tool := NewMoveTool(outsideHome, root, root)
		writeFile(t, filepath.Join(root, "src.txt"), "S\n")

		// "~/../moved.txt" expands relative to home to <outsideHomeRoot>/moved.txt, so ".." traverses out of
		// the home anchor; that out-of-root destination is promptable, resolving to the real
		// out-of-root folder rather than a project-local basename.
		wantDst := filepath.Join(outsideHomeRoot, "moved.txt")
		resolved, err := tool.ResolveEndpoints(map[string]any{"source": "src.txt", "destination": "~/../moved.txt"})
		if err != nil {
			t.Fatalf("ResolveEndpoints error = %v, want nil (out-of-root promptable)", err)
		}
		if resolved.Destination != wantDst {
			t.Fatalf("Destination = %q, want %q (expanded relative to home, then traversed)", resolved.Destination, wantDst)
		}
		if resolved.DestinationScope != outsideHomeRoot {
			t.Fatalf("DestinationScope = %q, want %q", resolved.DestinationScope, outsideHomeRoot)
		}
		if !resolved.DestinationOutOfRoot || !tool.OutOfRootScope(resolved.DestinationScope) {
			t.Fatalf("destination out-of-root = (%v, %v), want both true", resolved.DestinationOutOfRoot, tool.OutOfRootScope(resolved.DestinationScope))
		}
		if resolved.SourceOutOfRoot {
			t.Fatal("SourceOutOfRoot = true, want false for an in-root source")
		}
	})

	t.Run("source ~/.. expands relative to home then traverses out-of-root", func(t *testing.T) {
		root := eval(t, t.TempDir())
		outsideHomeRoot := eval(t, t.TempDir())
		outsideHome := filepath.Join(outsideHomeRoot, "home")
		if err := os.Mkdir(outsideHome, 0o755); err != nil {
			t.Fatalf("Mkdir outside home: %v", err)
		}
		tool := NewMoveTool(outsideHome, root, root)
		wantSrc := filepath.Join(outsideHomeRoot, "from-outside-home.txt")
		writeFile(t, wantSrc, "S\n")

		resolved, err := tool.ResolveEndpoints(map[string]any{"source": "~/../from-outside-home.txt", "destination": "pulled-in.txt"})
		if err != nil {
			t.Fatalf("ResolveEndpoints error = %v, want nil (out-of-root promptable)", err)
		}
		if resolved.Source != wantSrc {
			t.Fatalf("Source = %q, want %q (expanded relative to home, then traversed)", resolved.Source, wantSrc)
		}
		if resolved.SourceScope != outsideHomeRoot {
			t.Fatalf("SourceScope = %q, want %q", resolved.SourceScope, outsideHomeRoot)
		}
		if !resolved.SourceOutOfRoot || !tool.OutOfRootScope(resolved.SourceScope) {
			t.Fatalf("source out-of-root = (%v, %v), want both true", resolved.SourceOutOfRoot, tool.OutOfRootScope(resolved.SourceScope))
		}
		if resolved.DestinationOutOfRoot {
			t.Fatal("DestinationOutOfRoot = true, want false for an in-root destination")
		}
	})

	t.Run("in-root .. collapses lexically and stays in-root", func(t *testing.T) {
		root := eval(t, t.TempDir())
		tool := newMoveToolIn(t, root)
		sub := filepath.Join(root, "sub")
		if err := os.Mkdir(sub, 0o755); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		writeFile(t, filepath.Join(sub, "inner.txt"), "I\n")

		// "sub/../moved.txt" cleans lexically to "moved.txt" under the base, so it stays in-root.
		resolved, err := tool.ResolveEndpoints(map[string]any{"source": "sub/inner.txt", "destination": "sub/../moved.txt"})
		if err != nil {
			t.Fatalf("ResolveEndpoints error = %v, want nil", err)
		}
		if resolved.Source != filepath.Join(sub, "inner.txt") {
			t.Fatalf("Source = %q, want %q", resolved.Source, filepath.Join(sub, "inner.txt"))
		}
		if resolved.Destination != filepath.Join(root, "moved.txt") {
			t.Fatalf("Destination = %q, want %q (\"..\" collapsed lexically to the base)", resolved.Destination, filepath.Join(root, "moved.txt"))
		}
		if resolved.DestinationScope != root {
			t.Fatalf("DestinationScope = %q, want %q", resolved.DestinationScope, root)
		}
		if resolved.SourceOutOfRoot || resolved.DestinationOutOfRoot {
			t.Fatalf("out-of-root flags = (%v, %v), want both false", resolved.SourceOutOfRoot, resolved.DestinationOutOfRoot)
		}
	})

	t.Run("source in-root .. collapses lexically and stays in-root", func(t *testing.T) {
		root := eval(t, t.TempDir())
		tool := newMoveToolIn(t, root)
		sub := filepath.Join(root, "sub")
		if err := os.Mkdir(sub, 0o755); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		wantSrc := filepath.Join(root, "src.txt")
		writeFile(t, wantSrc, "S\n")

		resolved, err := tool.ResolveEndpoints(map[string]any{"source": "sub/../src.txt", "destination": "moved.txt"})
		if err != nil {
			t.Fatalf("ResolveEndpoints error = %v, want nil", err)
		}
		if resolved.Source != wantSrc {
			t.Fatalf("Source = %q, want %q (\"..\" collapsed lexically to the base)", resolved.Source, wantSrc)
		}
		if resolved.SourceScope != root {
			t.Fatalf("SourceScope = %q, want %q", resolved.SourceScope, root)
		}
		if resolved.SourceOutOfRoot || resolved.DestinationOutOfRoot {
			t.Fatalf("out-of-root flags = (%v, %v), want both false", resolved.SourceOutOfRoot, resolved.DestinationOutOfRoot)
		}
	})

	t.Run("relative .. escaping the base resolves out-of-root", func(t *testing.T) {
		root := eval(t, t.TempDir())
		tool := newMoveToolIn(t, root)
		writeFile(t, filepath.Join(root, "leaving.txt"), "L\n")
		parentOfRoot := filepath.Dir(root)

		// "../escaped.txt" resolves against the base (root) to <parent-of-root>/escaped.txt — outside the
		// project — so it is a promptable out-of-root destination anchored on the real parent folder.
		wantDst := filepath.Join(parentOfRoot, "escaped.txt")
		resolved, err := tool.ResolveEndpoints(map[string]any{"source": "leaving.txt", "destination": "../escaped.txt"})
		if err != nil {
			t.Fatalf("ResolveEndpoints error = %v, want nil (out-of-root promptable)", err)
		}
		if resolved.Destination != wantDst {
			t.Fatalf("Destination = %q, want %q", resolved.Destination, wantDst)
		}
		if resolved.DestinationScope != parentOfRoot {
			t.Fatalf("DestinationScope = %q, want %q", resolved.DestinationScope, parentOfRoot)
		}
		if !resolved.DestinationOutOfRoot || !tool.OutOfRootScope(resolved.DestinationScope) {
			t.Fatalf("destination out-of-root = (%v, %v), want both true", resolved.DestinationOutOfRoot, tool.OutOfRootScope(resolved.DestinationScope))
		}
		if resolved.SourceOutOfRoot {
			t.Fatal("SourceOutOfRoot = true, want false for an in-root source")
		}
	})

	t.Run("source relative .. escaping the base resolves out-of-root", func(t *testing.T) {
		root := eval(t, t.TempDir())
		tool := newMoveToolIn(t, root)
		parentOfRoot := filepath.Dir(root)

		wantSrc := filepath.Join(parentOfRoot, "escaped-source.txt")
		writeFile(t, wantSrc, "S\n")
		resolved, err := tool.ResolveEndpoints(map[string]any{"source": "../escaped-source.txt", "destination": "pulled-in.txt"})
		if err != nil {
			t.Fatalf("ResolveEndpoints error = %v, want nil (out-of-root promptable)", err)
		}
		if resolved.Source != wantSrc {
			t.Fatalf("Source = %q, want %q", resolved.Source, wantSrc)
		}
		if resolved.SourceScope != parentOfRoot {
			t.Fatalf("SourceScope = %q, want %q", resolved.SourceScope, parentOfRoot)
		}
		if !resolved.SourceOutOfRoot || !tool.OutOfRootScope(resolved.SourceScope) {
			t.Fatalf("source out-of-root = (%v, %v), want both true", resolved.SourceOutOfRoot, tool.OutOfRootScope(resolved.SourceScope))
		}
		if resolved.DestinationOutOfRoot {
			t.Fatal("DestinationOutOfRoot = true, want false for an in-root destination")
		}
	})
}

// TestMoveTool_InvokeStandaloneRejectsOutOfRoot pins the out-of-root boundary on the standalone Invoke path:
// it has no authorizer, so a move with an out-of-root source OR destination — direct absolute or reached
// through an in-root parent symlink — must fail in-band and move nothing. Only dispatch can authorize an
// out-of-root endpoint through the approval prompt.
func TestMoveTool_InvokeStandaloneRejectsOutOfRoot(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMoveToolIn(t, root)
	outsideDir := eval(t, t.TempDir())

	t.Run("out-of-root destination", func(t *testing.T) {
		src := filepath.Join(root, "stay.txt")
		writeFile(t, src, "x")
		dst := filepath.Join(outsideDir, "escaped.txt")

		res, err := tool.Invoke(context.Background(), map[string]any{"source": src, "destination": dst})
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil (the refusal is in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for an out-of-root destination")
		}
		if !strings.Contains(string(res.Stderr), "outside the project root") {
			t.Fatalf("stderr = %q, want it to name the out-of-root refusal", res.Stderr)
		}
		if _, statErr := os.Lstat(dst); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("entry moved outside the project root: %v", statErr)
		}
		if got := readFile(t, src); got != "x" {
			t.Fatalf("source = %q, want unchanged x (no mutation)", got)
		}
	})

	t.Run("out-of-root source", func(t *testing.T) {
		src := filepath.Join(outsideDir, "outsider.txt")
		writeFile(t, src, "y")

		res, err := tool.Invoke(context.Background(), map[string]any{"source": src, "destination": "pulled-in.txt"})
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil (the refusal is in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for an out-of-root source")
		}
		if !strings.Contains(string(res.Stderr), "outside the project root") {
			t.Fatalf("stderr = %q, want it to name the out-of-root refusal", res.Stderr)
		}
		if _, statErr := os.Lstat(filepath.Join(root, "pulled-in.txt")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("entry moved in from outside the project root: %v", statErr)
		}
		if got := readFile(t, src); got != "y" {
			t.Fatalf("source = %q, want unchanged y (no mutation)", got)
		}
	})

	t.Run("destination parent symlink-escapes the root", func(t *testing.T) {
		escapeLink := filepath.Join(root, "out")
		if err := os.Symlink(outsideDir, escapeLink); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		src := filepath.Join(root, "local.txt")
		writeFile(t, src, "z")

		res, err := tool.Invoke(context.Background(), map[string]any{"source": "local.txt", "destination": "out/sneaky.txt"})
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil (the refusal is in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for a symlink-escaped destination")
		}
		if _, statErr := os.Lstat(filepath.Join(outsideDir, "sneaky.txt")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("entry moved outside the project root via symlink escape: %v", statErr)
		}
		if got := readFile(t, src); got != "z" {
			t.Fatalf("source = %q, want unchanged z (no mutation)", got)
		}
	})
}

// TestMoveTool_InvokeMovesFile proves the fully in-root standalone path renames an existing file with the
// no-overwrite helper: the destination holds the source bytes and the source is gone.
func TestMoveTool_InvokeMovesFile(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMoveToolIn(t, root)
	writeFile(t, filepath.Join(root, "a.txt"), "CONTENT\n")

	res, err := tool.Invoke(context.Background(), map[string]any{"source": "a.txt", "destination": "b.txt"})
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if got := readFile(t, filepath.Join(root, "b.txt")); got != "CONTENT\n" {
		t.Fatalf("destination = %q, want CONTENT", got)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "a.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("source still present after move: %v", statErr)
	}
}

// TestMoveTool_InvokeWithResolvedMoveMovesDirectory proves the pre-resolved invocation path moves a
// directory through the no-overwrite helper using the resolved endpoints without re-resolving the lexical
// arguments: the directory and its contents land at the resolved destination and the source is gone.
func TestMoveTool_InvokeWithResolvedMoveMovesDirectory(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMoveToolIn(t, root)

	srcDir := filepath.Join(root, "d")
	if err := os.Mkdir(srcDir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	writeFile(t, filepath.Join(srcDir, "inner.txt"), "NESTED\n")

	resolved, err := tool.ResolveEndpoints(map[string]any{"source": "d", "destination": "d2"})
	if err != nil {
		t.Fatalf("ResolveEndpoints error = %v, want nil", err)
	}
	if resolved.Source != srcDir || resolved.Destination != filepath.Join(root, "d2") {
		t.Fatalf("resolved endpoints = (%q, %q), want (%q, %q)", resolved.Source, resolved.Destination, srcDir, filepath.Join(root, "d2"))
	}

	res, err := tool.InvokeWithResolvedMove(context.Background(), resolved)
	if err != nil {
		t.Fatalf("InvokeWithResolvedMove error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if info, err := os.Stat(filepath.Join(root, "d2")); err != nil || !info.IsDir() {
		t.Fatalf("destination dir missing or not a dir: info=%v err=%v", info, err)
	}
	if got := readFile(t, filepath.Join(root, "d2", "inner.txt")); got != "NESTED\n" {
		t.Fatalf("moved dir content = %q, want NESTED", got)
	}
	if _, statErr := os.Lstat(srcDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("source dir still present after move: %v", statErr)
	}
}

func TestMoveTool_ReportsAJournalledMoveAroundTheRename(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMoveToolIn(t, root)
	src := filepath.Join(root, "a.txt")
	dst := filepath.Join(root, "b.txt")
	writeFile(t, src, "A\n")
	journal := newFakeJournal(dst)

	res, err := tool.InvokeWithResolvedMove(WithWriteJournal(context.Background(), journal), ResolvedMove{Source: src, Destination: dst})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("move = %+v, %v; want success", res, err)
	}
	want := []string{"begin_move:" + src + ">" + dst, "resolve_move:" + src + ">" + dst}
	if !reflect.DeepEqual(journal.events, want) {
		t.Fatalf("journal events = %v, want %v from a journal covering only the destination", journal.events, want)
	}
	if got := readFile(t, dst); got != "A\n" {
		t.Fatalf("destination = %q, want the moved bytes", got)
	}
}

func TestMoveTool_AJournalRefusalLeavesBothEndpoints(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMoveToolIn(t, root)
	src := filepath.Join(root, "a.txt")
	dst := filepath.Join(root, "b.txt")
	writeFile(t, src, "A\n")
	journal := newFakeJournal(src)
	journal.beginMoveErr = errors.New("not a declared move pair")

	res, err := tool.InvokeWithResolvedMove(WithWriteJournal(context.Background(), journal), ResolvedMove{Source: src, Destination: dst})
	if err != nil {
		t.Fatalf("move error = %v, want an in-band refusal", err)
	}
	if res.ExitCode == 0 || !strings.Contains(string(res.Stderr), "not a declared move pair") {
		t.Fatalf("move = %+v, want the journal's refusal reported", res)
	}
	if got := readFile(t, src); got != "A\n" {
		t.Fatalf("source = %q, want it left in place", got)
	}
	if _, statErr := os.Lstat(dst); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("destination exists after a refused move: %v", statErr)
	}
}
