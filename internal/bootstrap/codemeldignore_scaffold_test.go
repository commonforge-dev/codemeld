// Tests for the global (first-run) and project codemeldignore scaffolding: create-when-absent,
// never-overwrite, and the first-run integration.
package bootstrap

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"codemeld.dev/codemeld/internal/filetools"
)

func TestScaffoldProjectCodemeldignore_CreatesWhenAbsent(t *testing.T) {
	root := t.TempDir()
	var stderr bytes.Buffer

	if err := ScaffoldProjectCodemeldignore(root, &stderr); err != nil {
		t.Fatalf("ScaffoldProjectCodemeldignore: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	path := filetools.ProjectCodemeldignorePath(root)
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected scaffolded file at %q: %v", path, err)
	}
	if string(got) != codemeldignoreTemplate {
		t.Fatalf("scaffolded content does not match the template:\n%s", got)
	}
	// The commented template must parse to zero patterns (every line is a comment).
	m, err := filetools.LoadCodemeldignoreMatcher(root, t.TempDir())
	if err != nil {
		t.Fatalf("LoadCodemeldignoreMatcher over the scaffolded file: %v", err)
	}
	if m != nil {
		t.Fatalf("commented template parsed to a non-nil matcher: %+v", m)
	}
}

func TestScaffoldProjectCodemeldignore_NeverOverwrites(t *testing.T) {
	root := t.TempDir()
	path := filetools.ProjectCodemeldignorePath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	const existing = "build\n"
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stderr bytes.Buffer
	if err := ScaffoldProjectCodemeldignore(root, &stderr); err != nil {
		t.Fatalf("ScaffoldProjectCodemeldignore: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read existing file: %v", err)
	}
	if string(got) != existing {
		t.Fatalf("existing codemeldignore was overwritten: got %q, want %q", got, existing)
	}
}

func TestScaffoldProjectCodemeldignore_EmptyRootIsNoOp(t *testing.T) {
	var stderr bytes.Buffer
	if err := ScaffoldProjectCodemeldignore("", &stderr); err != nil {
		t.Fatalf("ScaffoldProjectCodemeldignore(\"\"): %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty for an empty root", stderr.String())
	}
}

func TestFirstRun_ScaffoldsGlobalCodemeldignore(t *testing.T) {
	home := t.TempDir()
	var stdout, stderr bytes.Buffer

	ran, err := defaultRunFirstRun(home, &stdout, &stderr)
	if err != nil {
		t.Fatalf("defaultRunFirstRun: %v; stderr=%q", err, stderr.String())
	}
	if !ran {
		t.Fatal("ran = false, want true on a clean first run")
	}
	path := filetools.GlobalCodemeldignorePath(home)
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected global codemeldignore at %q: %v", path, err)
	}
	if string(got) != codemeldignoreTemplate {
		t.Fatalf("global codemeldignore content does not match the template:\n%s", got)
	}
}
