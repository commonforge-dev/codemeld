// Unit tests for built-in VCS template materialization.
package bootstrap

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/vcs"
	"codemeld.dev/codemeld/internal/vcs/builtin"
)

func seedFirstRunDirs(t *testing.T, home string) {
	t.Helper()
	if path, cat, err := EnsureFirstRunDirs(home); err != nil {
		t.Fatalf("seed first-run dirs: %v (path=%q cat=%q)", err, path, cat)
	}
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatalf("stat %q for inode: %v", path, err)
	}
	return st.Ino
}

func TestVCSTemplatePaths(t *testing.T) {
	home := "/some/home"
	if got, want := VCSTemplateDir(home), "/some/home/.codemeld/global/vcs"; got != want {
		t.Fatalf("VCSTemplateDir = %q, want %q", got, want)
	}
	if got, want := VCSTemplatePath(home, "git"), "/some/home/.codemeld/global/vcs/git.yaml"; got != want {
		t.Fatalf("VCSTemplatePath = %q, want %q", got, want)
	}
}

func TestMaterializeBuiltinTemplates_Fresh_WritesAllWithBytesAndMode(t *testing.T) {
	home := t.TempDir()
	seedFirstRunDirs(t, home)

	path, cat, err := MaterializeBuiltinTemplates(home)
	if err != nil {
		t.Fatalf("MaterializeBuiltinTemplates: %v (path=%q cat=%q)", err, path, cat)
	}
	if path != "" || cat != "" {
		t.Fatalf("path=%q cat=%q on success, want both empty", path, cat)
	}

	for _, name := range builtin.BuiltinNames() {
		target := VCSTemplatePath(home, name)
		got, readErr := os.ReadFile(target)
		if readErr != nil {
			t.Fatalf("read materialized %q: %v", target, readErr)
		}
		want, ok := builtin.BuiltinTemplate(name)
		if !ok {
			t.Fatalf("builtin.BuiltinTemplate(%q) not ok", name)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("template %q bytes differ from embedded source", name)
		}
		info, statErr := os.Stat(target)
		if statErr != nil {
			t.Fatalf("stat %q: %v", target, statErr)
		}
		if mode := info.Mode().Perm(); mode != 0o644 {
			t.Fatalf("template %q mode = %v, want 0644", name, mode)
		}
	}
}

func TestMaterializeBuiltinTemplates_SecondInvocation_NoRematerialization(t *testing.T) {
	home := t.TempDir()
	seedFirstRunDirs(t, home)

	if path, cat, err := MaterializeBuiltinTemplates(home); err != nil {
		t.Fatalf("first materialize: %v (path=%q cat=%q)", err, path, cat)
	}

	// Capture inodes; an idempotent second run must not rewrite (WriteAtomic
	// renames a fresh temp file into place, which would change the inode).
	before := make(map[string]uint64)
	for _, name := range builtin.BuiltinNames() {
		before[name] = inodeOf(t, VCSTemplatePath(home, name))
	}

	if path, cat, err := MaterializeBuiltinTemplates(home); err != nil {
		t.Fatalf("second materialize: %v (path=%q cat=%q)", err, path, cat)
	}

	for _, name := range builtin.BuiltinNames() {
		if after := inodeOf(t, VCSTemplatePath(home, name)); after != before[name] {
			t.Fatalf("template %q inode changed (%d -> %d): it was re-materialized", name, before[name], after)
		}
	}
}

func TestMaterializeBuiltinTemplates_PreservesUserEditedTemplate(t *testing.T) {
	home := t.TempDir()
	seedFirstRunDirs(t, home)

	// Simulate a user-edited git.yaml present before first materialization.
	const sentinel = "# user edited git template\nmarkers: [.git]\n"
	gitPath := VCSTemplatePath(home, "git")
	if err := os.WriteFile(gitPath, []byte(sentinel), 0o644); err != nil {
		t.Fatalf("seed user-edited git.yaml: %v", err)
	}

	if path, cat, err := MaterializeBuiltinTemplates(home); err != nil {
		t.Fatalf("MaterializeBuiltinTemplates: %v (path=%q cat=%q)", err, path, cat)
	}

	got, err := os.ReadFile(gitPath)
	if err != nil {
		t.Fatalf("read git.yaml: %v", err)
	}
	if string(got) != sentinel {
		t.Fatalf("user-edited git.yaml was overwritten (req 60)\n--- got ---\n%s\n--- want ---\n%s", got, sentinel)
	}

	// The other missing templates must still be materialized from the embedded source.
	for _, name := range []string{"hg", "jj"} {
		target := VCSTemplatePath(home, name)
		got, readErr := os.ReadFile(target)
		if readErr != nil {
			t.Fatalf("read %q: %v", target, readErr)
		}
		want, _ := builtin.BuiltinTemplate(name)
		if !bytes.Equal(got, want) {
			t.Fatalf("template %q not materialized from embedded source", name)
		}
	}
}

func TestMaterializeBuiltinTemplates_WriteFailure_PropagatesCategory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; permission failure is unobservable")
	}
	home := t.TempDir()
	seedFirstRunDirs(t, home)

	// Make the vcs dir read-only so WriteAtomic's temp-file create fails.
	vcsDir := VCSTemplateDir(home)
	if err := os.Chmod(vcsDir, 0o500); err != nil {
		t.Fatalf("chmod vcs dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(vcsDir, 0o755) })

	path, cat, err := MaterializeBuiltinTemplates(home)
	if err == nil {
		t.Fatalf("MaterializeBuiltinTemplates into read-only dir succeeded, want failure")
	}
	if want := VCSTemplatePath(home, "git"); path != want {
		t.Fatalf("failed path = %q, want %q (first template in order)", path, want)
	}
	if cat != fserrors.PermissionDenied {
		t.Fatalf("cat = %q, want %q", cat, fserrors.PermissionDenied)
	}
}

func TestRunMaterializeBuiltinTemplates_Success_NoOutputExit0(t *testing.T) {
	home := t.TempDir()
	seedFirstRunDirs(t, home)

	var stderr bytes.Buffer
	code := RunMaterializeBuiltinTemplates(home, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty on success", stderr.String())
	}
}

func TestRunMaterializeBuiltinTemplates_Failure_EmitsExactOpFailExit1(t *testing.T) {
	home := t.TempDir()
	// Create the parent tree but make the vcs path a regular file, not a dir, so
	// the first template's os.Stat hits ENOTDIR (io_error) deterministically,
	// independent of the test process's uid.
	global := filepath.Join(home, ".codemeld", "global")
	if err := os.MkdirAll(global, 0o755); err != nil {
		t.Fatalf("seed global dir: %v", err)
	}
	if err := os.WriteFile(VCSTemplateDir(home), []byte("x"), 0o644); err != nil {
		t.Fatalf("seed file at vcs dir path: %v", err)
	}

	var stderr bytes.Buffer
	code := RunMaterializeBuiltinTemplates(home, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	wantLine := "codemeld: write-vcs-template failed: " + VCSTemplatePath(home, "git") + ": " + string(fserrors.IOError) + "\n"
	if stderr.String() != wantLine {
		t.Fatalf("stderr mismatch\n--- got ---\n%q\n--- want ---\n%q", stderr.String(), wantLine)
	}
	if strings.Count(stderr.String(), "\n") != 1 {
		t.Errorf("stderr must be exactly one line, got: %q", stderr.String())
	}
}

const olderGitTemplate = "# an earlier codemeld git template\ndetect:\n  marker: .git\n"

func swapEarlierGit(t *testing.T, old string) {
	t.Helper()
	prev := isEarlierBuiltin
	isEarlierBuiltin = func(name string, b []byte) bool { return name == "git" && string(b) == old }
	t.Cleanup(func() { isEarlierBuiltin = prev })
}

func swapWriteAtomic(t *testing.T, w func(string, []byte, os.FileMode) (fsutil.AtomicWriteStep, fserrors.Category, error)) {
	t.Helper()
	prev := writeAtomic
	writeAtomic = w
	t.Cleanup(func() { writeAtomic = prev })
}

func seedFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("seed %q: %v", path, err)
	}
}

func readString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return string(b)
}

func TestMaterializeBuiltinTemplates_EarlierVersionReplacedAndLoadsAsReference(t *testing.T) {
	home := t.TempDir()
	seedFirstRunDirs(t, home)
	swapEarlierGit(t, olderGitTemplate)
	gitPath := VCSTemplatePath(home, "git")
	seedFile(t, gitPath, olderGitTemplate)

	if path, cat, err := MaterializeBuiltinTemplates(home); err != nil {
		t.Fatalf("MaterializeBuiltinTemplates: %v (path=%q cat=%q)", err, path, cat)
	}

	want, _ := builtin.BuiltinTemplate("git")
	if got := readString(t, gitPath); got != string(want) {
		t.Fatalf("git.yaml = %q, want the current embedded bytes", got)
	}
	templates, err := vcs.LoadTemplates(VCSTemplateDir(home))
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	if tmpl := templates["git"]; tmpl == nil || !tmpl.BuiltinReferenceCopy {
		t.Fatalf("git template = %#v, want a byte-identical reference copy", tmpl)
	}
}

func TestMaterializeBuiltinTemplates_EditedCopyOfEarlierVersionUntouched(t *testing.T) {
	home := t.TempDir()
	seedFirstRunDirs(t, home)
	swapEarlierGit(t, olderGitTemplate)
	gitPath := VCSTemplatePath(home, "git")
	edited := olderGitTemplate + "# my note\n"
	seedFile(t, gitPath, edited)

	if path, cat, err := MaterializeBuiltinTemplates(home); err != nil {
		t.Fatalf("MaterializeBuiltinTemplates: %v (path=%q cat=%q)", err, path, cat)
	}
	if got := readString(t, gitPath); got != edited {
		t.Fatalf("git.yaml = %q, want the edited bytes unchanged", got)
	}
}

func TestMaterializeBuiltinTemplates_CurrentCopyNotRewritten(t *testing.T) {
	home := t.TempDir()
	seedFirstRunDirs(t, home)
	swapEarlierGit(t, olderGitTemplate)
	gitPath := VCSTemplatePath(home, "git")
	current, _ := builtin.BuiltinTemplate("git")
	seedFile(t, gitPath, string(current))
	past := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(gitPath, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	if path, cat, err := MaterializeBuiltinTemplates(home); err != nil {
		t.Fatalf("MaterializeBuiltinTemplates: %v (path=%q cat=%q)", err, path, cat)
	}
	info, err := os.Stat(gitPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.ModTime().Equal(past) {
		t.Fatalf("git.yaml mtime = %v, want %v (not rewritten)", info.ModTime(), past)
	}
}

func TestMaterializeBuiltinTemplates_RefreshReadFailureReportsAndPreserves(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; permission failure is unobservable")
	}
	home := t.TempDir()
	seedFirstRunDirs(t, home)
	swapEarlierGit(t, olderGitTemplate)
	gitPath := VCSTemplatePath(home, "git")
	seedFile(t, gitPath, olderGitTemplate)
	if err := os.Chmod(gitPath, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(gitPath, 0o644) })

	path, cat, err := MaterializeBuiltinTemplates(home)
	if err == nil || path != gitPath || cat != fserrors.PermissionDenied {
		t.Fatalf("MaterializeBuiltinTemplates = (%q, %q, %v), want (%q, %q, error)", path, cat, err, gitPath, fserrors.PermissionDenied)
	}
	if err := os.Chmod(gitPath, 0o644); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	if got := readString(t, gitPath); got != olderGitTemplate {
		t.Fatalf("git.yaml = %q, want the existing bytes preserved", got)
	}
}

func TestMaterializeBuiltinTemplates_RefreshPrePublicationWriteFailurePreserves(t *testing.T) {
	home := t.TempDir()
	seedFirstRunDirs(t, home)
	swapEarlierGit(t, olderGitTemplate)
	gitPath := VCSTemplatePath(home, "git")
	seedFile(t, gitPath, olderGitTemplate)
	swapWriteAtomic(t, func(string, []byte, os.FileMode) (fsutil.AtomicWriteStep, fserrors.Category, error) {
		return fsutil.WriteStep, fserrors.NoSpace, syscall.ENOSPC
	})

	path, cat, err := MaterializeBuiltinTemplates(home)
	if err == nil || path != gitPath || cat != fserrors.NoSpace {
		t.Fatalf("MaterializeBuiltinTemplates = (%q, %q, %v), want (%q, %q, error)", path, cat, err, gitPath, fserrors.NoSpace)
	}
	if got := readString(t, gitPath); got != olderGitTemplate {
		t.Fatalf("git.yaml = %q, want the existing bytes preserved", got)
	}
}

func TestMaterializeBuiltinTemplates_RefreshPostPublicationSyncFailureReports(t *testing.T) {
	home := t.TempDir()
	seedFirstRunDirs(t, home)
	swapEarlierGit(t, olderGitTemplate)
	gitPath := VCSTemplatePath(home, "git")
	seedFile(t, gitPath, olderGitTemplate)
	syncErr := errors.New("parent fsync failed")
	swapWriteAtomic(t, func(p string, d []byte, m os.FileMode) (fsutil.AtomicWriteStep, fserrors.Category, error) {
		if step, c, err := fsutil.WriteAtomic(p, d, m); err != nil {
			return step, c, err
		}
		return fsutil.ParentSyncStep, fserrors.IOError, syncErr
	})

	path, cat, err := MaterializeBuiltinTemplates(home)
	if !errors.Is(err, syncErr) || path != gitPath || cat != fserrors.IOError {
		t.Fatalf("MaterializeBuiltinTemplates = (%q, %q, %v), want (%q, %q, %v)", path, cat, err, gitPath, fserrors.IOError, syncErr)
	}
	want, _ := builtin.BuiltinTemplate("git")
	if got := readString(t, gitPath); got != string(want) {
		t.Fatalf("git.yaml = %q, want the current embedded bytes installed", got)
	}
}
