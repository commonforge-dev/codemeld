// Unit tests for marker validation and single-directory marker detection.
package vcs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/vcs/builtin"
)

func TestValidateMarker(t *testing.T) {
	cases := []struct {
		name    string
		marker  string
		wantErr bool
	}{
		{"empty", "", true},
		{"slash", "a/b", true},
		{"backslash", `a\b`, true},
		{"nul", "a\x00b", true},
		{"dot", ".", true},
		{"dotdot", "..", true},
		{"leading space", " .git", true},
		{"trailing space", ".git ", true},
		{"leading tab", "\t.git", true},
		{"trailing newline", ".git\n", true},
		{"too long", strings.Repeat("a", 256), true},
		{"git", ".git", false},
		{"hg", ".hg", false},
		{"jj", ".jj", false},
		{"custom", "my-vcs-root", false},
		{"dotfile not dotdot", "...", false},
		{"max length", strings.Repeat("a", 255), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateMarker(tc.marker)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateMarker(%q) = nil, want error", tc.marker)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateMarker(%q) = %v, want nil", tc.marker, err)
			}
		})
	}
}

func TestDetectInDir_RegularFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".hg"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write marker file: %v", err)
	}
	got, err := DetectInDir(dir, ".hg")
	if err != nil {
		t.Fatalf("DetectInDir error: %v", err)
	}
	if !got {
		t.Fatalf("DetectInDir = false, want true for regular-file marker")
	}
}

func TestDetectInDir_Directory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir marker dir: %v", err)
	}
	got, err := DetectInDir(dir, ".git")
	if err != nil {
		t.Fatalf("DetectInDir error: %v", err)
	}
	if !got {
		t.Fatalf("DetectInDir = false, want true for directory marker")
	}
}

func TestDetectInDir_Symlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("mkdir symlink target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, ".git")); err != nil {
		t.Fatalf("symlink marker: %v", err)
	}
	got, err := DetectInDir(dir, ".git")
	if err != nil {
		t.Fatalf("DetectInDir error: %v", err)
	}
	if !got {
		t.Fatalf("DetectInDir = false, want true for symlink marker (lstat must not follow)")
	}
}

func TestDetectInDir_DanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "missing-target"), filepath.Join(dir, ".git")); err != nil {
		t.Fatalf("symlink marker: %v", err)
	}
	got, err := DetectInDir(dir, ".git")
	if err != nil {
		t.Fatalf("DetectInDir error: %v", err)
	}
	if !got {
		t.Fatalf("DetectInDir = false, want true: lstat sees the dangling link itself")
	}
}

func TestDetectInDir_Absent(t *testing.T) {
	dir := t.TempDir()
	got, err := DetectInDir(dir, ".git")
	if err != nil {
		t.Fatalf("DetectInDir error: %v", err)
	}
	if got {
		t.Fatalf("DetectInDir = true, want false when marker absent")
	}
}

func TestDetectInDir_InvalidMarker(t *testing.T) {
	got, err := DetectInDir(t.TempDir(), "a/b")
	if err == nil {
		t.Fatalf("DetectInDir with invalid marker = nil error, want validation error")
	}
	if got {
		t.Fatalf("DetectInDir = true on invalid marker, want false")
	}
}

func TestDetectInDir_PermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; permission failure is unobservable")
	}
	parent := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(parent, 0o000); err != nil {
		t.Fatalf("mkdir locked parent: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

	got, err := DetectInDir(parent, ".git")
	if err == nil {
		t.Fatalf("DetectInDir in unreadable dir = nil error, want EACCES")
	}
	if got {
		t.Fatalf("DetectInDir = true on error, want false")
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("EACCES misreported as not-exist: %v", err)
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("err does not wrap a permission error: %v", err)
	}
}

// builtinMarkers must stay aligned with the embedded built-in templates.
func TestBuiltinMarkers_AlignWithTemplates(t *testing.T) {
	names := builtin.BuiltinNames()
	if len(names) != len(builtinMarkers) {
		t.Fatalf("builtinMarkers has %d entries, built-in names has %d", len(builtinMarkers), len(names))
	}
	for _, name := range names {
		marker, ok := builtinMarkers[name]
		if !ok {
			t.Errorf("built-in %q has no marker in builtinMarkers", name)
			continue
		}
		if err := ValidateMarker(marker); err != nil {
			t.Errorf("built-in %q marker %q fails validation: %v", name, marker, err)
		}
	}
}
