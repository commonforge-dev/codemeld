// Integration tests proving concurrent permission-grant persistence through
// config.Persist serializes correctly: in-process goroutines, the deterministic
// sidecar-exclusion-after-inode-replacement regression, and a
// cross-process variant via the test binary.
package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/locks"
	"codemeld.dev/codemeld/internal/permissions"
)

// Subprocess-helper env keys re-exec this test binary as a controllable child
// that performs exactly one config.Persist append, so the gofrs/flock path is
// exercised across real OS processes (mirrors the os.Executable pattern in
// internal/locks/flock_test.go and internal/runner/runner_test.go).
const (
	persistChildModeEnv = "CODEMELD_T20_PERSIST_CHILD"
	persistChildTarget  = "CODEMELD_T20_TARGET"
	persistChildSubject = "CODEMELD_T20_SUBJECT"
	persistChildScope   = "CODEMELD_T20_SCOPE"
)

// TestMain runs the cross-process persist worker when the helper env is set;
// otherwise it runs the package's tests normally.
func TestMain(m *testing.M) {
	if os.Getenv(persistChildModeEnv) == "1" {
		runPersistChild()
	}
	os.Exit(m.Run())
}

// runPersistChild is the cross-process worker: one config.Persist append against
// the shared settings file named by the environment, then exit. It exits nonzero
// with a diagnostic on any non-ReasonNone outcome so a parent-side failure is
// legible rather than surfacing as a mysterious missing entry (task step 4).
// Reached only in a re-exec'd child.
func runPersistChild() {
	target := os.Getenv(persistChildTarget)
	entry := folderEntry(os.Getenv(persistChildSubject), os.Getenv(persistChildScope))
	reason, cat, err := config.Persist(target, config.KeyPermissions, entry)
	if reason != config.ReasonNone || err != nil {
		fmt.Fprintf(os.Stderr, "persist child %q: reason=%q cat=%q err=%v\n", entry.Subject, reason, cat, err)
		os.Exit(3)
	}
	os.Exit(0)
}

// folderEntry builds a direct folder-grant permission entry. Distinct subjects
// give distinct DedupKeys, so every writer's append is a new entry rather than a
// dedup no-op.
func folderEntry(subject, scope string) permissions.PermissionEntry {
	return permissions.PermissionEntry{Kind: "direct", Subject: subject, PathScope: scope, GrantKind: "folder"}
}

// userPrefix is the leading comment block plus an unknown user-authored
// top-level key that every write must preserve byte-for-byte. The root settings
// schema sets no top-level additionalProperties:false, so an unknown key
// validates (schemas/settings.schema.json).
const userPrefix = "# user-authored settings; keep these bytes exactly\n" +
	"# second comment line\n" +
	"custom_top_key: kept-verbatim\n"

// seedSettings writes a settings file with userPrefix followed by an initial
// permission entry, creating the parent .codemeld directory. The seed stands in
// for a hand-authored file: it is written directly (not via Persist) because
// Persist only emits codemeld-owned keys.
func seedSettings(t *testing.T, target string) {
	t.Helper()
	seed := userPrefix +
		"permissions:\n" +
		"  - kind: direct\n" +
		"    subject: seed\n" +
		"    path_scope: /work\n" +
		"    grant_kind: folder\n"
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("mkdir settings dir: %v", err)
	}
	if err := os.WriteFile(target, []byte(seed), 0o600); err != nil {
		t.Fatalf("write seed settings: %v", err)
	}
}

// readFile returns the file contents or fails the test.
func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// assertSubjectsPresent fails if any subject's entry is missing from content,
// catching a lost update. Subjects are alphanumeric, so they marshal as an
// unquoted `subject: <value>` line.
func assertSubjectsPresent(t *testing.T, content string, subjects ...string) {
	t.Helper()
	for _, s := range subjects {
		if !strings.Contains(content, "subject: "+s) {
			t.Fatalf("settings file missing entry subject %q (lost update?):\n%s", s, content)
		}
	}
}

// assertNoTempOrphans fails if the settings directory holds a temp orphan (a
// name containing ".tmp-") or a stray discovery-suffixed sibling (".json", or
// ".yaml" other than settings.yaml). settings.yaml.lock is allowed: it is the
// sidecar lock file, never an atomic-rename target. Mirrors
// fsutil.WriteAtomic's temp-name contract and the loader's discovery suffixes.
func assertNoTempOrphans(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir settings dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.Contains(name, ".tmp-"):
			t.Fatalf("temp orphan left in settings dir: %q", name)
		case strings.HasSuffix(name, ".json"):
			t.Fatalf("stray .json discovery file: %q", name)
		case strings.HasSuffix(name, ".yaml") && name != "settings.yaml":
			t.Fatalf("stray .yaml discovery file: %q", name)
		}
	}
}

// TestConcurrentPersist_GoroutineWriters_NoLostUpdate spawns four goroutines
// (>=3 per task) each appending a distinct permission via config.Persist to one
// shared settings file. The sidecar advisory lock must serialize the
// read-modify-write cycles so every append survives, the user-authored comment
// and unknown key stay byte-for-byte, and no temp orphan is left behind (task
// steps 2 and 5; Done-when 1, 3, 4).
func TestConcurrentPersist_GoroutineWriters_NoLostUpdate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".codemeld")
	target := filepath.Join(dir, "settings.yaml")
	seedSettings(t, target)

	subjects := []string{"alpha", "bravo", "charlie", "delta"}
	var wg sync.WaitGroup
	reasons := make([]config.PersistReason, len(subjects))
	errs := make([]error, len(subjects))
	for i, s := range subjects {
		wg.Add(1)
		go func(i int, s string) {
			defer wg.Done()
			reasons[i], _, errs[i] = config.Persist(target, config.KeyPermissions, folderEntry(s, "/work"))
		}(i, s)
	}
	wg.Wait()

	for i, s := range subjects {
		if errs[i] != nil || reasons[i] != config.ReasonNone {
			t.Fatalf("writer %q = (%q, %v), want (none, nil)", s, reasons[i], errs[i])
		}
	}

	content := readFile(t, target)
	assertSubjectsPresent(t, content, append([]string{"seed"}, subjects...)...)
	if !strings.HasPrefix(content, userPrefix) {
		t.Fatalf("user-authored comment/key prefix not preserved byte-for-byte:\nwant prefix:\n%q\ngot:\n%q", userPrefix, content)
	}
	assertNoTempOrphans(t, dir)
}

// lateResult carries the late writer's outcome back over a channel so the main
// goroutine never reads it without a happens-before edge (race-clean).
type lateResult struct {
	reason config.PersistReason
	err    error
}

// TestConcurrentPersist_SidecarExclusionAfterInodeReplace is the sidecar-lock
// regression guard at the integration black-box level (task step 3; Done-when 2).
// It forces the three-inode interleaving a two-writer test cannot reach: a holder
// keeps the sidecar lock across a peer's *completed* atomic rename (an inode
// replacement via config.RewriteKey), and a late config.Persist arrival must
// still be excluded until the holder releases. If Persist regressed to locking
// the renamed-over settings file instead of the sidecar, the late writer would
// take an uncontended lock on the fresh inode and finish at once, firing the
// negative assertion below.
func TestConcurrentPersist_SidecarExclusionAfterInodeReplace(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".codemeld")
	target := filepath.Join(dir, "settings.yaml")

	// (1) Seed via the real chokepoint so the settings inode exists and has been
	// rename-replaced once.
	if reason, _, err := config.Persist(target, config.KeyPermissions, folderEntry("alpha", "/work")); err != nil || reason != config.ReasonNone {
		t.Fatalf("seed Persist(alpha) = (%q, %v), want (none, nil)", reason, err)
	}

	// (2) Hold the sidecar lock on the exact path Persist locks (target+".lock")
	// and, while held, complete a RewriteKey append that renames a fresh inode
	// over the settings file. The lock rides the stable sidecar inode, untouched
	// by the rename.
	release, lockReason, lockErr := locks.Acquire(target+".lock", 2*time.Second)
	if lockErr != nil || lockReason != locks.ReasonNone {
		t.Fatalf("hold sidecar lock = (%q, %v), want (none, nil)", lockReason, lockErr)
	}
	if step, cat, err := config.RewriteKey(target, config.KeyPermissions, folderEntry("bravo", "/work")); err != nil {
		release()
		t.Fatalf("RewriteKey(bravo) under held lock = (step=%q cat=%q, %v), want nil err", step, cat, err)
	}

	// (3) A late Persist arrival must block on the held sidecar lock.
	done := make(chan lateResult, 1)
	go func() {
		r, _, e := config.Persist(target, config.KeyPermissions, folderEntry("charlie", "/work"))
		done <- lateResult{reason: r, err: e}
	}()

	// Negative assertion: with the holder still holding the sidecar lock, the late
	// writer cannot finish. The 200ms window is far under Persist's 2s lock
	// timeout, so after release the late writer still has ample budget to acquire.
	select {
	case res := <-done:
		release()
		t.Fatalf("late Persist finished while sidecar lock held (reason=%q err=%v): mutual exclusion broken", res.reason, res.err)
	case <-time.After(200 * time.Millisecond):
	}

	// Release: the late writer must now acquire, re-read (seeing alpha+bravo),
	// append charlie, and succeed.
	release()
	select {
	case res := <-done:
		if res.err != nil || res.reason != config.ReasonNone {
			t.Fatalf("late Persist(charlie) after release = (%q, %v), want (none, nil)", res.reason, res.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("late Persist never finished after the sidecar lock was released")
	}

	content := readFile(t, target)
	assertSubjectsPresent(t, content, "alpha", "bravo", "charlie")
	assertNoTempOrphans(t, dir)
}

// TestConcurrentPersist_SeparateProcesses re-execs this test binary as four child
// processes (>=3 per task), each calling config.Persist against one shared
// settings file, proving the gofrs/flock path serializes writes across real OS
// processes — coverage goroutines alone cannot give (task step 4; Done-when 1, 3,
// 4).
func TestConcurrentPersist_SeparateProcesses(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	dir := filepath.Join(t.TempDir(), ".codemeld")
	target := filepath.Join(dir, "settings.yaml")
	seedSettings(t, target)

	subjects := []string{"proc0", "proc1", "proc2", "proc3"}
	cmds := make([]*exec.Cmd, len(subjects))
	stderrs := make([]*strings.Builder, len(subjects))
	for i, s := range subjects {
		cmd := exec.Command(exe, "-test.run=^$")
		cmd.Env = append(os.Environ(),
			persistChildModeEnv+"=1",
			persistChildTarget+"="+target,
			persistChildSubject+"="+s,
			persistChildScope+"=/work",
		)
		var eb strings.Builder
		cmd.Stderr = &eb
		stderrs[i] = &eb
		cmds[i] = cmd
	}

	// Start every child before waiting on any, so their lock acquisitions actually
	// contend rather than running one-at-a-time.
	for i, cmd := range cmds {
		if startErr := cmd.Start(); startErr != nil {
			t.Fatalf("start child %q: %v", subjects[i], startErr)
		}
	}
	for i, cmd := range cmds {
		if waitErr := cmd.Wait(); waitErr != nil {
			t.Fatalf("child %q failed: %v\nstderr: %s", subjects[i], waitErr, stderrs[i].String())
		}
	}

	content := readFile(t, target)
	assertSubjectsPresent(t, content, append([]string{"seed"}, subjects...)...)
	if !strings.HasPrefix(content, userPrefix) {
		t.Fatalf("user-authored prefix not preserved across cross-process writes:\nwant prefix:\n%q\ngot:\n%q", userPrefix, content)
	}
	assertNoTempOrphans(t, dir)
}
