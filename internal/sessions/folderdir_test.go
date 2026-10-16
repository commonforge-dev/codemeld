// Unit tests for per-folder session subdirectory derivation and the folder-file policy.
package sessions

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFolderDirName_FixedHashes(t *testing.T) {
	cases := []struct {
		folder string
		want   string
	}{
		{"/home/u/proj", "9c09f8055a26c27736ddcc04b4e693af-proj"},
		{"/", "8a5edab282632443219e051e4ade2d1d-root"},
	}
	for _, tc := range cases {
		if got := FolderDirName(tc.folder); got != tc.want {
			t.Errorf("FolderDirName(%q) = %q, want %q", tc.folder, got, tc.want)
		}
	}
}

func TestSanitizeBasename(t *testing.T) {
	long := strings.Repeat("a", 40)
	cases := []struct {
		name   string
		folder string
		want   string
	}{
		{"plain", "/home/u/proj", "proj"},
		{"allowed punctuation kept", "/x/my.proj-v2_final", "my.proj-v2_final"},
		{"special chars replaced", "/x/my project!@#", "my_project___"},
		{"unicode rune replaced", "/x/café", "caf_"},
		{"length cap at 32", "/x/" + long, strings.Repeat("a", 32)},
		{"root", "/", "root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeBasename(tc.folder); got != tc.want {
				t.Errorf("sanitizeBasename(%q) = %q, want %q", tc.folder, got, tc.want)
			}
		})
	}
}

func TestCanonicalizeFolder_SymlinkAndNormalization(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	// EvalSymlinks may itself canonicalize the temp root (e.g. /var -> /private/var
	// on macOS), so derive the expected value from the resolved target.
	want, err := CanonicalizeFolder(target)
	if err != nil {
		t.Fatalf("CanonicalizeFolder(target): %v", err)
	}

	// A symlinked path with a trailing slash and a "." segment must normalize to
	// the resolved target.
	got, err := CanonicalizeFolder(link + "/./")
	if err != nil {
		t.Fatalf("CanonicalizeFolder(link): %v", err)
	}
	if got != want {
		t.Errorf("CanonicalizeFolder(symlink) = %q, want %q", got, want)
	}
}

func TestEnsureFolderDir_CreatesAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	const folder = "/home/u/proj"

	subdir, err := EnsureFolderDir(home, folder)
	if err != nil {
		t.Fatalf("EnsureFolderDir: %v", err)
	}
	wantSubdir := filepath.Join(SessionRoot(home), FolderDirName(folder))
	if subdir != wantSubdir {
		t.Fatalf("subdir = %q, want %q", subdir, wantSubdir)
	}
	info, statErr := os.Stat(subdir)
	if statErr != nil || !info.IsDir() {
		t.Fatalf("subdir not created as directory: %v", statErr)
	}

	folderPath := filepath.Join(subdir, folderFileName)
	wantBytes := []byte(folder + "\n")
	got, readErr := os.ReadFile(folderPath)
	if readErr != nil {
		t.Fatalf("read folder file: %v", readErr)
	}
	if !bytes.Equal(got, wantBytes) {
		t.Fatalf("folder file = %q, want %q", got, wantBytes)
	}

	// Second call observes the existing file and leaves byte-equal contents.
	if _, err := EnsureFolderDir(home, folder); err != nil {
		t.Fatalf("second EnsureFolderDir: %v", err)
	}
	got2, readErr := os.ReadFile(folderPath)
	if readErr != nil {
		t.Fatalf("re-read folder file: %v", readErr)
	}
	if !bytes.Equal(got2, wantBytes) {
		t.Fatalf("folder file after second call = %q, want %q", got2, wantBytes)
	}
}

func TestEnsureFolderDir_AcceptsLFAndUnterminated(t *testing.T) {
	const folder = "/home/u/proj"
	for _, content := range []string{folder, folder + "\n"} {
		home := t.TempDir()
		subdir := filepath.Join(SessionRoot(home), FolderDirName(folder))
		if err := os.MkdirAll(subdir, 0o755); err != nil {
			t.Fatalf("seed subdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(subdir, folderFileName), []byte(content), 0o644); err != nil {
			t.Fatalf("seed folder file: %v", err)
		}
		// Recorded folder equals the launch folder regardless of trailing LF:
		// no collision, no error.
		if _, err := EnsureFolderDir(home, folder); err != nil {
			t.Fatalf("EnsureFolderDir with recorded %q: %v", content, err)
		}
	}
}

func TestEnsureFolderDir_EmptyAfterTrimRewrites(t *testing.T) {
	home := t.TempDir()
	const folder = "/home/u/proj"
	subdir := filepath.Join(SessionRoot(home), FolderDirName(folder))
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("seed subdir: %v", err)
	}
	folderPath := filepath.Join(subdir, folderFileName)
	// Whitespace-only is "no recorded folder": the normal write path runs, no
	// collision check.
	if err := os.WriteFile(folderPath, []byte("  \n\t"), 0o644); err != nil {
		t.Fatalf("seed empty folder file: %v", err)
	}
	if _, err := EnsureFolderDir(home, folder); err != nil {
		t.Fatalf("EnsureFolderDir over empty file: %v", err)
	}
	got, err := os.ReadFile(folderPath)
	if err != nil {
		t.Fatalf("read folder file: %v", err)
	}
	if want := folder + "\n"; string(got) != want {
		t.Fatalf("folder file = %q, want %q", got, want)
	}
}
