package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/enforce"
)

func skipUnlessLinuxTempDirs(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("session temp folders are created only on linux")
	}
}

func newOwnedTempDir(t *testing.T) *sessionTempDir {
	t.Helper()
	dir, err := newSessionTempDir()
	if err != nil {
		t.Fatalf("newSessionTempDir: %v", err)
	}
	t.Cleanup(dir.close)
	return dir
}

func setHook(t *testing.T, hook *func(string), fn func(string)) {
	t.Helper()
	prev := *hook
	*hook = fn
	t.Cleanup(func() { *hook = prev })
}

func mkdirMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

type keptTarget struct {
	dir, file string
}

func newKeptTarget(t *testing.T, dir string) keptTarget {
	t.Helper()
	mkdirMode(t, dir, 0o700)
	k := keptTarget{dir: dir, file: filepath.Join(dir, "keep")}
	mustWrite(t, k.file, "keep")
	mkdirMode(t, filepath.Join(dir, "sub"), 0o500)
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
		_ = os.Chmod(filepath.Join(dir, "sub"), 0o700)
	})
	return k
}

func (k keptTarget) requireUnchanged(t *testing.T) {
	t.Helper()
	for path, want := range map[string]os.FileMode{k.dir: 0o750, filepath.Join(k.dir, "sub"): 0o500} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != want {
			t.Fatalf("%s: info %v, err %v; want a folder with mode %v", path, info, err, want)
		}
	}
	if data, err := os.ReadFile(k.file); err != nil || string(data) != "keep" {
		t.Fatalf("%s = %q, %v; want it unchanged", k.file, data, err)
	}
}

func requireGone(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s still present (err %v), want it removed", path, err)
	}
}

func TestNewSessionTempDir_CreatesPrivateFolderNamedForThisProcess(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	tmp := canonicalTempDir(t)
	t.Setenv("TMPDIR", tmp)

	first := newOwnedTempDir(t)
	if got := filepath.Dir(first.path); got != tmp {
		t.Fatalf("folder %q is in %q, want %q", first.path, got, tmp)
	}
	wantPrefix := fmt.Sprintf("codemeld-confine-%d-", os.Getpid())
	if name := filepath.Base(first.path); !strings.HasPrefix(name, wantPrefix) || name == wantPrefix {
		t.Fatalf("folder name %q, want %q followed by a suffix", name, wantPrefix)
	}
	info, err := os.Stat(first.path)
	if err != nil {
		t.Fatalf("stat %q: %v", first.path, err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("folder %q has mode %v, want a directory with 0700", first.path, info.Mode())
	}

	if second := newOwnedTempDir(t); second.path == first.path {
		t.Fatalf("two calls both returned %q", first.path)
	}
}

func TestNewSessionTempDir_StoresTheResolvedFolderUnderASymlinkedTMPDIR(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	target := canonicalTempDir(t)
	alias := filepath.Join(canonicalTempDir(t), "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", alias)

	first := newOwnedTempDir(t)
	conf := &confinement{tmpDir: first.path}
	conf.own(first)
	replacement, rollback, err := conf.prepareReplacement()
	if err != nil {
		t.Fatalf("prepareReplacement: %v", err)
	}
	for _, dir := range []string{first.path, replacement} {
		if got := filepath.Dir(dir); got != target {
			t.Fatalf("folder %q is in %q, want the resolved %q", dir, got, target)
		}
		mustWrite(t, filepath.Join(dir, "f"), "x")
	}
	if err := rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if err := conf.cleanupAll(); err != nil {
		t.Fatalf("cleanupAll: %v", err)
	}
	requireGone(t, first.path)
	requireGone(t, replacement)
}

func finishedProcessPID(t *testing.T) int {
	t.Helper()
	finished := exec.Command(os.Args[0], "-test.run=^$")
	if err := finished.Run(); err != nil {
		t.Fatalf("run a short-lived process: %v", err)
	}
	return finished.ProcessState.Pid()
}

func sessionTempRecords() string {
	return filepath.Join(os.Getenv("HOME"), ".codemeld", "confine-tmp")
}

func readRecordFields(t *testing.T, record string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil {
		t.Fatalf("record %s = %q: %v", record, data, err)
	}
	return fields
}

func writeRecordFields(t *testing.T, record string, fields map[string]any) {
	t.Helper()
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, record, string(data))
}

func recordedTempDir(t *testing.T, name string) (path, record string) {
	t.Helper()
	dir := newOwnedTempDir(t)
	if err := dir.recordFailure(); err != nil {
		t.Fatalf("record failure: %v", err)
	}
	path = filepath.Join(filepath.Dir(dir.path), name)
	if err := os.Rename(dir.path, path); err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(sessionTempRecords(), filepath.Base(dir.path))
	fields := readRecordFields(t, created)
	fields["path"] = path
	record = filepath.Join(sessionTempRecords(), name)
	writeRecordFields(t, record, fields)
	if err := os.Remove(created); err != nil {
		t.Fatal(err)
	}
	dir.close()
	return path, record
}

func requirePresent(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("%q was removed: %v", path, err)
		}
	}
}

func TestRemoveStaleSessionTempDirs_RemovesOnlyFinishedProcessFolders(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("HOME", t.TempDir())
	deadPID := finishedProcessPID(t)

	running := exec.Command("sleep", "60")
	if err := running.Start(); err != nil {
		t.Fatalf("start a long-running process: %v", err)
	}
	t.Cleanup(func() {
		_ = running.Process.Kill()
		_ = running.Wait()
	})

	stale, staleRecord := recordedTempDir(t, fmt.Sprintf("codemeld-confine-%d-stale", deadPID))
	cache := filepath.Join(stale, "gocache")
	mkdirMode(t, cache, 0o700)
	mustWrite(t, filepath.Join(cache, "entry"), "x")
	if err := os.Chmod(cache, 0); err != nil {
		t.Fatal(err)
	}

	var kept []string
	for _, name := range []string{
		fmt.Sprintf("codemeld-confine-%d-self", os.Getpid()),
		fmt.Sprintf("codemeld-confine-%d-live", running.Process.Pid),
		"codemeld-confine-abc-x",
		"codemeld-confine-007-x",
		fmt.Sprintf("codemeld-confine-0%d-x", deadPID),
		fmt.Sprintf("codemeld-confine-+%d-x", deadPID),
		fmt.Sprintf("codemeld-confine-%d-x", int64(deadPID)+1<<32),
	} {
		path, record := recordedTempDir(t, name)
		kept = append(kept, path, record)
	}

	if err := removeStaleSessionTempDirs(); err != nil {
		t.Fatalf("removeStaleSessionTempDirs: %v", err)
	}

	requireGone(t, stale)
	requireGone(t, staleRecord)
	requirePresent(t, kept...)
}

func TestRemoveStaleSessionTempDirs_AFolderWithoutARecordIsKept(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("HOME", t.TempDir())
	mkdirMode(t, sessionTempRecords(), 0o700)
	unrecorded := filepath.Join(tmp, fmt.Sprintf("codemeld-confine-%d-x", finishedProcessPID(t)))
	mkdirMode(t, unrecorded, 0o700)
	mustWrite(t, filepath.Join(unrecorded, "keep"), "keep")

	if err := removeStaleSessionTempDirs(); err != nil {
		t.Fatalf("removeStaleSessionTempDirs: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(unrecorded, "keep")); err != nil || string(data) != "keep" {
		t.Fatalf("unrecorded folder's file = %q, %v; want it kept", data, err)
	}
}

func TestRemoveStaleSessionTempDirs_ARecordWhoseFolderIsGoneIsDropped(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	path, record := recordedTempDir(t, fmt.Sprintf("codemeld-confine-%d-x", finishedProcessPID(t)))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	if err := removeStaleSessionTempDirs(); err != nil {
		t.Fatalf("removeStaleSessionTempDirs: %v", err)
	}
	requireGone(t, record)
}

func TestRemoveStaleSessionTempDirs_ADifferentEntryAtARecordedPathIsKeptAndReported(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	for _, replacement := range []string{"directory", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			t.Setenv("HOME", t.TempDir())
			path, record := recordedTempDir(t, fmt.Sprintf("codemeld-confine-%d-x", finishedProcessPID(t)))
			if err := os.Rename(path, path+".moved"); err != nil {
				t.Fatal(err)
			}
			kept := newKeptTarget(t, filepath.Join(t.TempDir(), "other"))
			if replacement == "directory" {
				if err := os.Rename(kept.dir, path); err != nil {
					t.Fatal(err)
				}
				kept.dir, kept.file = path, filepath.Join(path, "keep")
			} else if err := os.Symlink(kept.dir, path); err != nil {
				t.Fatal(err)
			}

			err := removeStaleSessionTempDirs()
			if err == nil || !strings.Contains(err.Error(), path) {
				t.Fatalf("removeStaleSessionTempDirs = %v, want an error naming %s", err, path)
			}
			kept.requireUnchanged(t)
			requireGone(t, record)
		})
	}
}

func TestRemoveStaleSessionTempDirs_AReusedInodeWithADifferentBirthTimeIsKept(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	path, record := recordedTempDir(t, fmt.Sprintf("codemeld-confine-%d-x", finishedProcessPID(t)))
	mustWrite(t, filepath.Join(path, "keep"), "keep")
	fields := readRecordFields(t, record)
	btime, ok := fields["btime_ns"].(json.Number)
	if !ok {
		t.Skip("the temp filesystem reports no birth time")
	}
	ns, err := btime.Int64()
	if err != nil {
		t.Fatal(err)
	}
	fields["btime_ns"] = ns - 1
	writeRecordFields(t, record, fields)

	if err := removeStaleSessionTempDirs(); err == nil {
		t.Fatal("removeStaleSessionTempDirs = nil, want the mismatch reported")
	}
	if data, err := os.ReadFile(filepath.Join(path, "keep")); err != nil || string(data) != "keep" {
		t.Fatalf("file in the reused folder = %q, %v; want it kept", data, err)
	}
}

func TestRemoveStaleSessionTempDirs_ARecordWithoutABirthTimeKeepsTheFolderAndIsDropped(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	path, record := recordedTempDir(t, fmt.Sprintf("codemeld-confine-%d-x", finishedProcessPID(t)))
	fields := readRecordFields(t, record)
	delete(fields, "btime_ns")
	writeRecordFields(t, record, fields)

	if err := removeStaleSessionTempDirs(); err == nil {
		t.Fatal("removeStaleSessionTempDirs = nil, want the unprovable folder reported")
	}
	requirePresent(t, path)
	requireGone(t, record)
}

func TestRemoveStaleSessionTempDirs_AMalformedRecordKeepsTheFolderAndRecord(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	pid := finishedProcessPID(t)
	without := func(field string) func(string, map[string]any) string {
		return func(_ string, f map[string]any) string {
			delete(f, field)
			b, _ := json.Marshal(f)
			return string(b)
		}
	}
	null := func(field string) func(string, map[string]any) string {
		return func(_ string, f map[string]any) string {
			f[field] = nil
			b, _ := json.Marshal(f)
			return string(b)
		}
	}
	for name, content := range map[string]func(valid string, fields map[string]any) string{
		"truncated":         func(string, map[string]any) string { return "{" },
		"trailing bytes":    func(v string, _ map[string]any) string { return v + "\n{" },
		"trailing brace":    func(v string, _ map[string]any) string { return v + "}" },
		"second JSON value": func(v string, _ map[string]any) string { return v + "\n" + v },
		"missing dev":       without("dev"),
		"missing ino":       without("ino"),
		"missing path":      without("path"),
		"null dev":          null("dev"),
		"null ino":          null("ino"),
		"null path":         null("path"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			t.Setenv("HOME", t.TempDir())
			path, record := recordedTempDir(t, fmt.Sprintf("codemeld-confine-%d-x", pid))
			sentinel := filepath.Join(path, "sentinel")
			mustWrite(t, sentinel, "x")
			valid, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			mustWrite(t, record, content(string(valid), readRecordFields(t, record)))

			if err := removeStaleSessionTempDirs(); err == nil {
				t.Fatal("removeStaleSessionTempDirs = nil, want the malformed record reported")
			}
			requirePresent(t, path, record, sentinel)
		})
	}
	t.Run("trailing whitespace is accepted", func(t *testing.T) {
		t.Setenv("TMPDIR", t.TempDir())
		t.Setenv("HOME", t.TempDir())
		path, record := recordedTempDir(t, fmt.Sprintf("codemeld-confine-%d-x", pid))
		valid, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(t, record, string(valid)+" \n\t\n")

		if err := removeStaleSessionTempDirs(); err != nil {
			t.Fatalf("removeStaleSessionTempDirs: %v", err)
		}
		requireGone(t, path)
		requireGone(t, record)
	})
}

func TestRemoveStaleSessionTempDirs_AnotherCleanerRemovingTheFolderFirstIsNotAnError(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	for name, hook := range map[string]*func(string){"during traversal": &duringSessionTempDirCleanup, "before the final unlink": &beforeSessionTempDirUnlink} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			t.Setenv("HOME", t.TempDir())
			path, record := recordedTempDir(t, fmt.Sprintf("codemeld-confine-%d-x", finishedProcessPID(t)))
			mkdirMode(t, filepath.Join(path, "sub"), 0o700)
			mustWrite(t, filepath.Join(path, "f"), "x")
			fired := false
			setHook(t, hook, func(dir string) {
				if dir != path || fired {
					return
				}
				fired = true
				if err := os.RemoveAll(path); err != nil {
					t.Errorf("remove: %v", err)
				}
			})

			if err := removeStaleSessionTempDirs(); err != nil {
				t.Fatalf("removeStaleSessionTempDirs: %v", err)
			}
			if !fired {
				t.Fatal("the other cleaner's hook did not fire")
			}
			requireGone(t, record)
		})
	}
}

func TestRemoveStaleSessionTempDirs_AFIFORecordIsReportedWithoutBlocking(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	path, record := recordedTempDir(t, fmt.Sprintf("codemeld-confine-%d-x", finishedProcessPID(t)))
	sentinel := filepath.Join(path, "sentinel")
	mustWrite(t, sentinel, "x")
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(record, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- removeStaleSessionTempDirs() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("removeStaleSessionTempDirs = nil, want the FIFO record reported")
		}
	case <-time.After(10 * time.Second):
		if w, err := os.OpenFile(record, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = w.Close()
		}
		t.Fatal("removeStaleSessionTempDirs blocked opening a FIFO record")
	}
	requirePresent(t, path, record, sentinel)
}

func TestRemoveStaleSessionTempDirs_ARecordAnotherCleanerRemovedAfterTheScanIsNotAnError(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	t.Setenv("HOME", t.TempDir())
	pid := finishedProcessPID(t)
	type recorded struct{ path, record string }
	byParent := map[string]recorded{}
	for _, suffix := range []string{"a", "b"} {
		t.Setenv("TMPDIR", t.TempDir())
		path, record := recordedTempDir(t, fmt.Sprintf("codemeld-confine-%d-%s", pid, suffix))
		byParent[filepath.Dir(path)] = recorded{path, record}
	}
	unrelated := filepath.Join(sessionTempRecords(), "unrelated")
	mustWrite(t, unrelated, "x")
	fired := false
	setHook(t, &afterStaleScanParentOpen, func(parent string) {
		if fired {
			return
		}
		fired = true
		for p, other := range byParent {
			if p == parent {
				continue
			}
			if err := os.RemoveAll(other.path); err != nil {
				t.Error(err)
			}
			if err := os.Remove(other.record); err != nil {
				t.Error(err)
			}
		}
	})

	if err := removeStaleSessionTempDirs(); err != nil {
		t.Fatalf("removeStaleSessionTempDirs: %v", err)
	}
	if !fired {
		t.Fatal("the other cleaner's hook did not fire")
	}
	for _, r := range byParent {
		requireGone(t, r.path)
		requireGone(t, r.record)
	}
	requirePresent(t, unrelated)
}

func TestSessionTempRecords_AnUnsafeRecordsFolderIsNeitherWrittenNorTrusted(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	for _, unsafe := range []string{"symlink", "mode 0755"} {
		t.Run(unsafe, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			t.Setenv("HOME", t.TempDir())
			stale, record := recordedTempDir(t, fmt.Sprintf("codemeld-confine-%d-x", finishedProcessPID(t)))
			records := sessionTempRecords()
			target := records
			if unsafe == "symlink" {
				target = filepath.Join(t.TempDir(), "elsewhere")
				if err := os.Rename(records, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, records); err != nil {
					t.Fatal(err)
				}
				record = filepath.Join(target, filepath.Base(record))
			} else if err := os.Chmod(records, 0o755); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadDir(target)
			if err != nil {
				t.Fatal(err)
			}

			dir, err := newSessionTempDir()
			if err != nil {
				t.Fatalf("newSessionTempDir: %v", err)
			}
			t.Cleanup(dir.close)
			if dir.recordFailure() == nil {
				t.Fatal("record failure = nil, want the unsafe records folder reported")
			}
			requirePresent(t, dir.path)
			if err := removeStaleSessionTempDirs(); err == nil {
				t.Fatal("removeStaleSessionTempDirs = nil, want the unsafe records folder reported")
			}
			requirePresent(t, stale, record)
			after, err := os.ReadDir(target)
			if err != nil {
				t.Fatal(err)
			}
			if len(after) != len(before) || len(after) != 1 || after[0].Name() != before[0].Name() {
				t.Fatalf("records folder holds %v, want only %v", after, before)
			}
			if info, err := os.Stat(target); err != nil || (unsafe == "mode 0755" && info.Mode().Perm() != 0o755) {
				t.Fatalf("records folder %s: %v, %v; want it left as it was", target, info, err)
			}
		})
	}
}

func TestStartExecutionCapability_AFailedRecordKeepsTheFolderAndShowsOneNotice(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	if os.Geteuid() == 0 {
		t.Skip("root can create a folder in a read-only parent")
	}
	t.Setenv("TMPDIR", t.TempDir())
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkdirMode(t, filepath.Join(home, ".codemeld"), 0o500)
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(home, ".codemeld"), 0o700) })

	var notices bytes.Buffer
	dir, err := startExecutionCapability(enforce.Resolution{SelfTestPassed: true}, stderrNoticeRenderer{w: &notices})
	if err != nil || dir == nil {
		t.Fatalf("startExecutionCapability = (%v, %v), want a folder and no error", dir, err)
	}
	t.Cleanup(dir.close)
	requirePresent(t, dir.path)
	requireGone(t, filepath.Join(sessionTempRecords(), filepath.Base(dir.path)))
	got := notices.String()
	if strings.Count(got, "\n") != 1 || !strings.Contains(got, "left behind") || !strings.Contains(got, dir.path) {
		t.Fatalf("notices = %q, want one notice that a crash would leave %s behind", got, dir.path)
	}
}

func TestNewSessionTempDir_RecordsTheFolderBeforeReturning(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	dir := newOwnedTempDir(t)
	fields := readRecordFields(t, filepath.Join(sessionTempRecords(), filepath.Base(dir.path)))
	info, err := os.Stat(dir.path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	if fields["path"] != dir.path || fields["dev"] != json.Number(fmt.Sprint(st.Dev)) || fields["ino"] != json.Number(fmt.Sprint(st.Ino)) {
		t.Fatalf("record = %v, want path %s, dev %d, ino %d", fields, dir.path, st.Dev, st.Ino)
	}
}

func TestSessionTempDir_AFailedRemovalKeepsTheRecord(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	if os.Geteuid() == 0 {
		t.Skip("root can remove a folder from a read-only parent")
	}
	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	t.Setenv("HOME", t.TempDir())
	dir := newOwnedTempDir(t)
	record := filepath.Join(sessionTempRecords(), filepath.Base(dir.path))
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	err := dir.remove()
	_ = os.Chmod(parent, 0o700)
	if err == nil {
		t.Fatal("remove from a read-only parent = nil, want an error")
	}
	requirePresent(t, dir.path, record)
}

func TestSessionTempDir_RemovalAndReleaseDropTheRecord(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	record := func(path string) string { return filepath.Join(sessionTempRecords(), filepath.Base(path)) }

	dir := newOwnedTempDir(t)
	requirePresent(t, record(dir.path))
	if err := dir.removeAndRelease(); err != nil {
		t.Fatalf("removeAndRelease: %v", err)
	}
	requireGone(t, dir.path)
	requireGone(t, record(dir.path))

	first := newOwnedTempDir(t)
	conf := &confinement{tmpDir: first.path}
	conf.own(first)
	replacement, _, err := conf.prepareReplacement()
	if err != nil {
		t.Fatalf("prepareReplacement: %v", err)
	}
	conf.commitReplacement(replacement)
	if warning := conf.takeCleanupWarning(); warning != "" {
		t.Fatalf("cleanup warning %q", warning)
	}
	requireGone(t, first.path)
	requireGone(t, record(first.path))
	requirePresent(t, replacement, record(replacement))
	if err := conf.cleanupAll(); err != nil {
		t.Fatalf("cleanupAll: %v", err)
	}
}

func TestRemoveStaleSessionTempDirs_AParentSwapAfterTheScanOpensCannotRedirectIt(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	base, outside := canonicalTempDir(t), canonicalTempDir(t)
	tmp := filepath.Join(base, "tmp")
	mkdirMode(t, tmp, 0o700)
	t.Setenv("TMPDIR", tmp)
	t.Setenv("HOME", t.TempDir())
	name := fmt.Sprintf("codemeld-confine-%d-stale", finishedProcessPID(t))
	recordedTempDir(t, name)
	mkdirMode(t, filepath.Join(tmp, name, "cache"), 0)
	kept := newKeptTarget(t, filepath.Join(outside, name))
	setHook(t, &afterStaleScanParentOpen, func(string) {
		if err := os.Rename(tmp, tmp+".moved"); err != nil {
			t.Errorf("rename: %v", err)
		}
		if err := os.Symlink(outside, tmp); err != nil {
			t.Errorf("symlink: %v", err)
		}
	})

	if err := removeStaleSessionTempDirs(); err != nil {
		t.Fatalf("removeStaleSessionTempDirs: %v", err)
	}
	requireGone(t, filepath.Join(tmp+".moved", name))
	kept.requireUnchanged(t)
}

func TestRemoveStaleSessionTempDirs_ASwappedCandidateIsLeftAndReportedAtStartup(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	tmp, outside := canonicalTempDir(t), canonicalTempDir(t)
	t.Setenv("TMPDIR", tmp)
	t.Setenv("HOME", t.TempDir())
	stale, _ := recordedTempDir(t, fmt.Sprintf("codemeld-confine-%d-stale", finishedProcessPID(t)))
	sub := filepath.Join(stale, "sub")
	mkdirMode(t, sub, 0)
	kept := newKeptTarget(t, filepath.Join(outside, "target"))
	setHook(t, &duringSessionTempDirCleanup, func(dir string) {
		if dir != sub {
			return
		}
		if err := os.Rename(sub, sub+".moved"); err != nil {
			t.Errorf("rename: %v", err)
		}
		if err := os.Symlink(kept.dir, sub); err != nil {
			t.Errorf("symlink: %v", err)
		}
	})

	var notices bytes.Buffer
	if _, err := startExecutionCapability(enforce.Resolution{}, stderrNoticeRenderer{w: &notices}); err != nil {
		t.Fatalf("startExecutionCapability: %v", err)
	}
	if got := notices.String(); !strings.HasPrefix(got, "codemeld: could not remove a leftover confinement temp folder: ") || !strings.Contains(got, sub) {
		t.Fatalf("notice = %q, want the leftover-folder warning naming %s", got, sub)
	}
	if target, err := os.Readlink(sub); err != nil || target != kept.dir {
		t.Fatalf("readlink %s = %q, %v; want the substituted link left in place", sub, target, err)
	}
	kept.requireUnchanged(t)
}

func TestSignalMeansGone(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"process done", os.ErrProcessDone, true},
		{"wrapped process done", fmt.Errorf("signal: %w", os.ErrProcessDone), true},
		{"nil", nil, false},
		{"permission denied", syscall.EPERM, false},
		{"unrelated", errors.New("boom"), false},
	}
	for _, tc := range cases {
		if got := signalMeansGone(tc.err); got != tc.want {
			t.Errorf("%s: signalMeansGone(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

func TestSessionTempDirPID(t *testing.T) {
	cases := []struct {
		name    string
		wantPID int
		wantOK  bool
	}{
		{"codemeld-confine-1234-x", 1234, true},
		{"codemeld-confine-0-x", 0, false},
		{"codemeld-confine-+1234-x", 0, false},
		{"codemeld-confine--1234-x", 0, false},
		{"codemeld-confine-01234-x", 0, false},
		{"codemeld-confine-1234-", 0, false},
		{"codemeld-confine-4294968530-x", 0, false},
	}
	for _, tc := range cases {
		pid, ok := sessionTempDirPID(tc.name)
		if ok != tc.wantOK || (ok && pid != tc.wantPID) {
			t.Errorf("sessionTempDirPID(%q) = (%d, %v), want (%d, %v)", tc.name, pid, ok, tc.wantPID, tc.wantOK)
		}
	}
}

func TestNewSessionTempDir_IsPrivateUnderOwnerMaskingUmasks(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	for _, umask := range []int{0o277, 0o477, 0o777} {
		t.Run(fmt.Sprintf("%04o", umask), func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			prev := syscall.Umask(umask)
			t.Cleanup(func() { syscall.Umask(prev) })

			dir, err := newSessionTempDir()
			syscall.Umask(prev)
			if err != nil {
				t.Fatalf("newSessionTempDir: %v", err)
			}
			t.Cleanup(dir.close)
			info, err := os.Stat(dir.path)
			if err != nil {
				t.Fatalf("stat %q: %v", dir.path, err)
			}
			if info.Mode().Perm() != 0o700 {
				t.Fatalf("folder %q has mode %v, want 0700", dir.path, info.Mode().Perm())
			}
		})
	}
}

func TestNewSessionTempDir_RelativeTMPDIRYieldsAnAbsolutePathInTheResolvedParent(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	base := canonicalTempDir(t)
	mkdirMode(t, filepath.Join(base, "rel"), 0o700)
	t.Chdir(base)
	t.Setenv("TMPDIR", "rel")

	dir := newOwnedTempDir(t)
	if !filepath.IsAbs(dir.path) {
		t.Fatalf("folder %q is not absolute", dir.path)
	}
	if got, want := filepath.Dir(dir.path), filepath.Join(base, "rel"); got != want {
		t.Fatalf("folder %q is in %q, want %q", dir.path, got, want)
	}
}

func TestSessionTempDir_RelativeTMPDIRThenAWorkingDirectoryChangeCannotRedirectCleanup(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	launch, later, outside := canonicalTempDir(t), canonicalTempDir(t), canonicalTempDir(t)
	mkdirMode(t, filepath.Join(launch, "rel"), 0o700)
	t.Chdir(launch)
	t.Setenv("TMPDIR", "rel")
	dir := newOwnedTempDir(t)
	name := filepath.Base(dir.path)
	if err := os.Rename(filepath.Join(launch, "rel"), filepath.Join(launch, "rel.moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(launch, "rel")); err != nil {
		t.Fatal(err)
	}
	kept := newKeptTarget(t, filepath.Join(outside, name))
	mkdirMode(t, filepath.Join(later, "rel", name), 0o700)
	decoy := newKeptTarget(t, filepath.Join(later, "rel", name, "decoy"))
	t.Chdir(later)

	if err := dir.removeAndRelease(); err != nil {
		t.Fatalf("removeAndRelease: %v", err)
	}
	requireGone(t, filepath.Join(launch, "rel.moved", name))
	kept.requireUnchanged(t)
	decoy.requireUnchanged(t)
}

func TestNewSessionTempDir_UnresolvableParentFailsBeforeCreation(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	base := canonicalTempDir(t)
	t.Setenv("TMPDIR", filepath.Join(base, "missing"))

	dir, err := newSessionTempDir()
	if err == nil || dir != nil {
		t.Fatalf("newSessionTempDir = (%v, %v), want only an error", dir, err)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%q holds %d entries after the failure, want none", base, len(entries))
	}
}

type swappedTempDir struct {
	created   string
	original  string
	kept      keptTarget
	parentDir string
}

func swapSessionTempDirAt(t *testing.T, seam *func(string), replaceWith func(created string, s *swappedTempDir) error) *swappedTempDir {
	t.Helper()
	s := &swappedTempDir{parentDir: canonicalTempDir(t)}
	t.Setenv("TMPDIR", s.parentDir)
	s.kept = newKeptTarget(t, filepath.Join(canonicalTempDir(t), "outside"))
	setHook(t, seam, func(created string) {
		s.created = created
		s.original = created + ".original"
		if err := os.Rename(created, s.original); err != nil {
			t.Errorf("rename %q: %v", created, err)
			return
		}
		if err := replaceWith(created, s); err != nil {
			t.Errorf("replace %q: %v", created, err)
		}
	})
	t.Cleanup(func() {
		if s.original != "" {
			_ = os.Chmod(s.original, 0o700)
			_ = os.RemoveAll(s.original)
		}
	})
	return s
}

func symlinkToOutside(created string, s *swappedTempDir) error {
	return os.Symlink(s.kept.dir, created)
}

func (s *swappedTempDir) requireLinkKept(t *testing.T) {
	t.Helper()
	if target, err := os.Readlink(s.created); err != nil || target != s.kept.dir {
		t.Fatalf("readlink %s = %q, %v; want the substituted link left in place", s.created, target, err)
	}
}

func TestNewSessionTempDir_SwapBeforeTheModeOpenFailsSafely(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	s := swapSessionTempDirAt(t, &beforeSessionTempDirChmod, symlinkToOutside)

	dir, err := newSessionTempDir()
	if err == nil || dir != nil {
		t.Fatalf("newSessionTempDir = (%v, %v), want only an error after the swap", dir, err)
	}
	if s.created == "" {
		t.Fatal("the seam before the mode open was not called")
	}
	s.kept.requireUnchanged(t)
	s.requireLinkKept(t)
}

func TestNewSessionTempDir_RealDirectorySwapBeforeTheFirstOpenIsLeftUntouched(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	s := swapSessionTempDirAt(t, &beforeSessionTempDirChmod, func(created string, _ *swappedTempDir) error {
		if err := os.Mkdir(created, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(created, "planted"), []byte("planted"), 0o600); err != nil {
			return err
		}
		return os.Chmod(created, 0o550)
	})
	t.Cleanup(func() { _ = os.Chmod(s.created, 0o700) })

	dir, err := newSessionTempDir()
	if err == nil || dir != nil {
		t.Fatalf("newSessionTempDir = (%v, %v), want only an error after the swap", dir, err)
	}
	info, err := os.Lstat(s.created)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o550 {
		t.Fatalf("replacement %s: info %v, err %v; want the planted folder with its mode 0550", s.created, info, err)
	}
	if data, err := os.ReadFile(filepath.Join(s.created, "planted")); err != nil || string(data) != "planted" {
		t.Fatalf("planted file = %q, %v; want it unchanged", data, err)
	}
}

func TestNewSessionTempDir_AParentSwapDuringCreationFailsAndRollsBackThroughTheHandles(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	base, outside := canonicalTempDir(t), canonicalTempDir(t)
	tmp := filepath.Join(base, "tmp")
	mkdirMode(t, tmp, 0o700)
	t.Setenv("TMPDIR", tmp)
	var kept keptTarget
	var created string
	setHook(t, &beforeSessionTempDirChmod, func(path string) {
		created = path
		if err := os.Rename(tmp, tmp+".moved"); err != nil {
			t.Errorf("rename: %v", err)
		}
		if err := os.Symlink(outside, tmp); err != nil {
			t.Errorf("symlink: %v", err)
		}
		kept = newKeptTarget(t, filepath.Join(outside, filepath.Base(path)))
	})

	dir, err := newSessionTempDir()
	if err == nil || dir != nil {
		t.Fatalf("newSessionTempDir = (%v, %v), want only an error", dir, err)
	}
	requireGone(t, filepath.Join(tmp+".moved", filepath.Base(created)))
	kept.requireUnchanged(t)
}

func TestNewSessionTempDir_SwapAfterCreationLeavesTheLinkAndReportsTheCleanupFailure(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	s := swapSessionTempDirAt(t, &afterSessionTempDirChmod, symlinkToOutside)

	dir := newOwnedTempDir(t)
	if dir.path != s.created || filepath.Dir(dir.path) != s.parentDir {
		t.Fatalf("newSessionTempDir = %q, want the created path %q in %q", dir.path, s.created, s.parentDir)
	}
	s.kept.requireUnchanged(t)

	if err := dir.removeAndRelease(); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("removeAndRelease = %v, want the replacement reported", err)
	}
	s.requireLinkKept(t)
	s.kept.requireUnchanged(t)
}

func TestSessionTempDir_AnAncestorSwapBeforeCleanupCannotRedirectIt(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	base, outside := canonicalTempDir(t), canonicalTempDir(t)
	ancestor := filepath.Join(base, "a")
	t.Setenv("TMPDIR", filepath.Join(ancestor, "tmp"))
	mkdirMode(t, filepath.Join(ancestor, "tmp"), 0o700)
	dir := newOwnedTempDir(t)
	mkdirMode(t, filepath.Join(dir.path, "cache"), 0)
	name := filepath.Base(dir.path)
	if err := os.Rename(ancestor, ancestor+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, ancestor); err != nil {
		t.Fatal(err)
	}
	kept := newKeptTarget(t, filepath.Join(outside, "tmp", name))

	if err := dir.removeAndRelease(); err != nil {
		t.Fatalf("removeAndRelease: %v", err)
	}
	requireGone(t, filepath.Join(ancestor+".moved", "tmp", name))
	kept.requireUnchanged(t)
}

func TestSessionTempDir_UnreadableDescendantsAreRemoved(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	t.Setenv("TMPDIR", t.TempDir())
	dir := newOwnedTempDir(t)
	deep := filepath.Join(dir.path, "a", "b")
	mkdirMode(t, deep, 0o700)
	mustWrite(t, filepath.Join(deep, "f"), "x")
	if err := os.Symlink("/", filepath.Join(deep, "root")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{deep, filepath.Dir(deep), dir.path} {
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
	}

	if err := dir.removeAndRelease(); err != nil {
		t.Fatalf("removeAndRelease: %v", err)
	}
	requireGone(t, dir.path)
}

func TestSessionTempDir_ASwapDuringPermissionRecoveryIsNeitherFollowedNorChanged(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	for _, replacement := range []string{"symlink", "real directory"} {
		t.Run(replacement, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			dir := newOwnedTempDir(t)
			sub := filepath.Join(dir.path, "sub")
			mkdirMode(t, sub, 0o700)
			mustWrite(t, filepath.Join(sub, "f"), "x")
			if err := os.Chmod(sub, 0); err != nil {
				t.Fatal(err)
			}
			kept := newKeptTarget(t, filepath.Join(canonicalTempDir(t), "outside"))
			swapped := 0
			setHook(t, &duringSessionTempDirCleanup, func(path string) {
				if path != sub || swapped > 0 {
					return
				}
				swapped++
				if err := os.Rename(sub, sub+".moved"); err != nil {
					t.Errorf("rename: %v", err)
				}
				if replacement == "symlink" {
					if err := os.Symlink(kept.dir, sub); err != nil {
						t.Errorf("symlink: %v", err)
					}
					return
				}
				if err := os.Rename(kept.dir, sub); err != nil {
					t.Errorf("move the outside folder in: %v", err)
				}
				kept.dir, kept.file = sub, filepath.Join(sub, "keep")
			})

			err := dir.remove()
			if err == nil || !strings.Contains(err.Error(), sub) {
				t.Fatalf("remove = %v, want an error naming %s", err, sub)
			}
			if swapped != 1 {
				t.Fatalf("swaps = %d, want the hook to fire once", swapped)
			}
			kept.requireUnchanged(t)
		})
	}
}

func TestSessionTempDir_AnEmptyRealDirectorySwappedInBeforeTheFinalUnlinkIsKept(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	t.Setenv("TMPDIR", t.TempDir())
	dir := newOwnedTempDir(t)
	setHook(t, &beforeSessionTempDirUnlink, func(path string) {
		if path != dir.path {
			return
		}
		if err := os.Rename(dir.path, dir.path+".moved"); err != nil {
			t.Errorf("rename: %v", err)
		}
		if err := os.Mkdir(dir.path, 0o750); err != nil {
			t.Errorf("mkdir: %v", err)
		}
	})

	if err := dir.remove(); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("remove = %v, want the replacement reported", err)
	}
	if info, err := os.Lstat(dir.path); err != nil || !info.IsDir() || info.Mode().Perm() != 0o750 {
		t.Fatalf("replacement %s: info %v, err %v; want it kept with mode 0750", dir.path, info, err)
	}
}

func openFDsAt(t *testing.T, paths ...string) []string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var fds []string
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err == nil && slices.Contains(paths, strings.TrimSuffix(target, " (deleted)")) {
			fds = append(fds, e.Name())
		}
	}
	return fds
}

func TestSessionTempDir_HandlesAreCloseOnExecAndReleasedAfterAFailedThenRetriedCleanup(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	if os.Geteuid() == 0 {
		t.Skip("root can remove a folder from a read-only parent")
	}
	parent := canonicalTempDir(t)
	t.Setenv("TMPDIR", parent)
	dir := newOwnedTempDir(t)
	fds := openFDsAt(t, parent, dir.path)
	if len(fds) != 2 {
		t.Fatalf("open handles on %s and its folder = %v, want two", parent, fds)
	}
	for _, fd := range fds {
		info, err := os.ReadFile(filepath.Join("/proc/self/fdinfo", fd))
		if err != nil {
			t.Fatal(err)
		}
		var flags int
		for line := range strings.Lines(string(info)) {
			if rest, ok := strings.CutPrefix(line, "flags:"); ok {
				_, _ = fmt.Sscanf(strings.TrimSpace(rest), "%o", &flags)
			}
		}
		if flags&syscall.O_CLOEXEC == 0 {
			t.Fatalf("handle %s flags %o, want close-on-exec", fd, flags)
		}
	}

	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	err := dir.remove()
	_ = os.Chmod(parent, 0o700)
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("remove from a read-only parent = %v, want a permission error", err)
	}
	if got := openFDsAt(t, parent, dir.path); !slices.Equal(got, fds) {
		t.Fatalf("handles after the failed cleanup = %v, want %v kept for the retry", got, fds)
	}

	if err := dir.remove(); err != nil {
		t.Fatalf("retry: %v", err)
	}
	requireGone(t, dir.path)
	if got := openFDsAt(t, parent, dir.path); len(got) != 0 {
		t.Fatalf("handles after the retry = %v, want none", got)
	}
}

type failedRollback struct {
	*ancestorSwap
	parent, created string
	cleanups        int
}

func failCreationRollback(t *testing.T) *failedRollback {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root can remove a folder from a read-only parent")
	}
	f := &failedRollback{ancestorSwap: newAncestorSwap(t)}
	f.parent = filepath.Join(f.ancestor+".moved", "tmp")
	t.Cleanup(func() { _ = os.Chmod(f.parent, 0o700) })
	setHook(t, &beforeSessionTempDirChmod, func(path string) {
		f.created = path
		f.swap(t)
		if err := os.Chmod(f.parent, 0o500); err != nil {
			t.Errorf("chmod: %v", err)
		}
	})
	setHook(t, &duringSessionTempDirCleanup, func(path string) {
		if path != f.created {
			return
		}
		if f.cleanups++; f.cleanups == 2 {
			if err := os.Chmod(f.parent, 0o700); err != nil {
				t.Errorf("chmod: %v", err)
			}
		}
	})
	return f
}

func (f *failedRollback) held() string {
	return filepath.Join(f.parent, filepath.Base(f.created))
}

func (f *failedRollback) requireCreationAndRollbackErrors(t *testing.T, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "does not resolve to the folder codemeld created") || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("error = %v, want both the creation mismatch and the failed rollback", err)
	}
}

func (f *failedRollback) requireRetriedAndReleased(t *testing.T) {
	t.Helper()
	if f.cleanups != 2 {
		t.Fatalf("cleanup attempts on %s = %d, want the rollback and one exit retry", f.created, f.cleanups)
	}
	f.requireHeld(t, []string{f.created}, nil)
	if got := openFDsAt(t, f.parent, f.held()); len(got) != 0 {
		t.Fatalf("handles after the exit retry = %v, want none", got)
	}
}

func TestNewSessionTempDir_AFailedCreationRollbackHandsBackTheHeldOwner(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	f := failCreationRollback(t)

	dir, err := newSessionTempDir()
	f.requireCreationAndRollbackErrors(t, err)
	if dir == nil || dir.path != f.created {
		t.Fatalf("owner = %v, want the held folder %s returned for the exit retry", dir, f.created)
	}
	if got := openFDsAt(t, f.parent, f.held()); len(got) != 2 {
		t.Fatalf("handles after the failed rollback = %v, want the parent and folder kept", got)
	}

	if err := dir.removeAndRelease(); err != nil {
		t.Fatalf("exit retry: %v", err)
	}
	f.requireRetriedAndReleased(t)
}

func TestConfinement_AFailedReplacementRollbackIsRetriedAtExit(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	conf := injectedTempDir(t)
	launch := conf.tmpDir
	f := failCreationRollback(t)

	folder, rollback, err := conf.prepareReplacement()
	f.requireCreationAndRollbackErrors(t, err)
	if folder != "" || rollback() != nil || conf.tmpDir != launch {
		t.Fatalf("prepareReplacement folder = %q, tmpDir = %q; want no replacement and %q kept", folder, conf.tmpDir, launch)
	}
	if got := retainedTempDirs(conf); !slices.Equal(got, []string{f.created}) {
		t.Fatalf("retained = %v, want the failed replacement %s kept for the exit retry", got, f.created)
	}

	if err := conf.cleanupAll(); err != nil {
		t.Fatalf("cleanupAll: %v", err)
	}
	f.requireRetriedAndReleased(t)
	requireGone(t, launch)
}
