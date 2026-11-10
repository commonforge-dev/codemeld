//go:build linux && (amd64 || arm64)

package bootstrap

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/netproxy"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/vcs"
)

func TestConfinedRunner_AutoProjectSymlinkExclusionsThroughTheRealHelper(t *testing.T) {
	if _, err := runner.ResolveOnPath("sh", runner.FixedPATH); err != nil {
		t.Fatalf("sh absent from %s: %v", runner.FixedPATH, err)
	}
	// The helper's read walk lists every directory above the blocked home, so fixtures avoid the churning shared temp folder.
	created, err := os.MkdirTemp("/var/tmp", "codemeld-symlinks-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(created) })
	base, err := filepath.EvalSymlinks(created)
	if err != nil {
		t.Fatal(err)
	}
	home, project, outside, tmpDir := filepath.Join(base, "home"), filepath.Join(base, "project"), filepath.Join(base, "outside"), filepath.Join(base, "tmp")
	codemeld, allowed := filepath.Join(project, ".codemeld"), filepath.Join(project, "allowed")
	for _, dir := range []string{filepath.Join(home, ".codemeld", "global"), outside, tmpDir, codemeld, allowed} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(home, ".codemeld", "global", "settings.yaml"): "",
		filepath.Join(outside, "file.txt"):                          "outside",
		filepath.Join(codemeld, "file.txt"):                         "codemeld",
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	links := []struct{ link, target string }{
		{filepath.Join(base, "alias"), outside},
		{filepath.Join(project, "out-dir"), outside},
		{filepath.Join(project, "out-rel"), "../outside"},
		{filepath.Join(project, "out-file"), filepath.Join(outside, "file.txt")},
		{filepath.Join(project, "out-chain"), filepath.Join(base, "alias")},
		{filepath.Join(project, "chain"), "out-rel"},
		{filepath.Join(project, "cm-dir"), codemeld},
		{filepath.Join(project, "cm-rel"), ".codemeld"},
		{filepath.Join(project, "cm-file"), ".codemeld/file.txt"},
		{filepath.Join(project, "cm-chain"), "cm-rel"},
	}
	for _, l := range links {
		if err := os.Symlink(l.target, l.link); err != nil {
			t.Fatal(err)
		}
	}

	bin := filepath.Join(t.TempDir(), "codemeld")
	buildCtx, cancelBuild := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancelBuild()
	build := exec.CommandContext(buildCtx, "go", "build", "-o", bin, "codemeld.dev/codemeld/cmd/codemeld")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cgo-free codemeld: %v\n%s", err, out)
	}
	abi, abiErr := llsys.LandlockGetABIVersion()
	t.Logf("landlock ABI probe: %d, %v", abi, abiErr)
	resolution := enforce.Resolve(enforce.ResolveInput{Home: home, HelperExecutable: bin})
	if !resolution.SelfTestPassed {
		for _, primitive := range []string{"codemeld confinement: landlock: landlock ABI", "codemeld confinement: seccomp:"} {
			if strings.Contains(resolution.Reason, primitive) {
				t.Skipf("host lacks a confinement primitive: %s", resolution.Reason)
			}
		}
		t.Fatalf("self-test through %s refused: %+v", bin, resolution)
	}

	cache, err := config.NewCache(map[string]any{"confinement": map[string]any{"program_lookup": "strict"}}, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	conf := withSessionProxy(t, launchConfinement(resolution, tmpDir, mode.NewActiveState(mode.AutoEdits, mode.SourceDefault), cache, home,
		securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, nil)}, nil))
	forward := &helperForwardingRunner{bin: bin}
	confined := &confinedRunner{inner: forward, conf: conf, cap: 4096}
	write := func(t *testing.T, target string) runner.RunResult {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := confined.Exec(ctx, runner.RunSpec{
			InvocationID: ids.NewV7(),
			Argv:         []string{"sh", "-c", `if printf t450 > "$1"; then echo wrote; else echo denied; fi`, "sh", target},
			Cwd:          project,
		})
		if err != nil {
			t.Fatalf("confined write to %s: %v", target, err)
		}
		if ctx.Err() != nil {
			t.Fatalf("confined write to %s: %v; result %+v", target, ctx.Err(), res)
		}
		return res
	}
	observed := func(path string) string {
		b, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			return "<absent>"
		}
		if err != nil {
			return "<" + err.Error() + ">"
		}
		return string(b)
	}

	for _, tc := range []struct{ name, target, real string }{
		{"allowed absolute", filepath.Join(allowed, "abs.txt"), filepath.Join(allowed, "abs.txt")},
		{"allowed relative", "allowed/rel.txt", filepath.Join(allowed, "rel.txt")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := write(t, tc.target)
			if got := observed(tc.real); string(res.Stdout) != "wrote\n" || got != "t450" {
				t.Fatalf("child = %q/%q exit %d, parent reads %s = %q; want a write", res.Stdout, res.Stderr, res.ExitCode, tc.real, got)
			}
		})
	}

	if len(forward.specs) == 0 || !slices.Equal(forward.specs[0].Argv[:2], []string{"/proc/self/exe", enforce.HelperCommand}) {
		t.Fatalf("inner runs = %+v, want the helper invocation", forward.specs)
	}
	policy, err := enforce.ReadPolicyFrame(bytes.NewReader(forward.specs[0].Stdin))
	if err != nil {
		t.Fatal(err)
	}
	if policy.Mode != string(mode.AutoEdits) || !slices.Equal(policy.WriteRoots, []string{allowed}) || policy.TmpDir != tmpDir {
		t.Fatalf("policy frame = %+v, want auto_edits writing only %s and %s", policy, allowed, tmpDir)
	}

	for _, tc := range []struct{ name, entry, real string }{
		{"outside directory link", "out-dir/", outside},
		{"outside relative-target link", "out-rel/", outside},
		{"outside file link", "out-file", filepath.Join(outside, "file.txt")},
		{"outside chained alias", "out-chain/", outside},
		{"project link chained to outside", "chain/", outside},
		{"codemeld directory link", "cm-dir/", codemeld},
		{"codemeld relative-target link", "cm-rel/", codemeld},
		{"codemeld file link", "cm-file", filepath.Join(codemeld, "file.txt")},
		{"codemeld chained alias", "cm-chain/", codemeld},
	} {
		for _, form := range []string{"absolute", "relative"} {
			t.Run(tc.name+"/"+form, func(t *testing.T) {
				target, real := tc.entry, tc.real
				if name, isDir := strings.CutSuffix(tc.entry, "/"); isDir {
					leaf := name + "-" + form + ".txt"
					target, real = filepath.Join(name, leaf), filepath.Join(tc.real, leaf)
				}
				if form == "absolute" {
					target = filepath.Join(project, target)
				}
				before := observed(real)
				res := write(t, target)
				after := observed(real)
				if string(res.Stdout) != "denied\n" || after != before || !strings.Contains(string(res.Stderr), "Permission denied") {
					t.Fatalf("write to %s: child = %q/%q exit %d, parent reads %s = %q (was %q); want a denial leaving it unchanged",
						target, res.Stdout, res.Stderr, res.ExitCode, real, after, before)
				}
			})
		}
	}
}

func liveRealHelperConfinement(t *testing.T, home, project, tmpDir, yaml string) *confinement {
	t.Helper()
	writeProjectSettings(t, project, yaml)
	cache, err := config.NewCache(map[string]any{"confinement": map[string]any{"program_lookup": "strict"}}, project,
		[]string{SettingsPath(home), projectSettingsPath(project)}, home)
	if err != nil {
		t.Fatal(err)
	}
	resolution := resolveExecutionCapability(enforce.ResolveInput{Home: home})
	return withSessionProxy(t, launchConfinement(resolution, tmpDir, mode.NewActiveState(mode.AutoEdits, mode.SourceDefault), cache, home,
		securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, nil)}, nil))
}

func TestConfinedRunner_AutoWritableFolderFollowsTheLiveSettingsThroughTheRealHelper(t *testing.T) {
	home, project, bin := realConfinementHost(t)
	if _, err := runner.ResolveOnPath("sh", runner.FixedPATH); err != nil {
		t.Fatalf("sh absent from %s: %v", runner.FixedPATH, err)
	}
	base := filepath.Dir(project)
	writable, sibling, tmpDir := filepath.Join(base, "writable"), filepath.Join(base, "sibling"), filepath.Join(base, "tmp")
	for _, dir := range []string{writable, sibling, tmpDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	conf := liveRealHelperConfinement(t, home, project, tmpDir, writableFoldersYAML(writable))
	settings := projectSettingsPath(project)
	confined := &confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 4096}
	n := 0
	write := func(t *testing.T, dir string) (runner.RunResult, string) {
		t.Helper()
		n++
		target := filepath.Join(dir, "f"+strconv.Itoa(n))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := confined.Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(), Argv: []string{"sh", "-c", "echo hi > " + target}, Cwd: project})
		if err != nil || ctx.Err() != nil {
			t.Fatalf("confined write to %s: %v, %v; result %+v", target, err, ctx.Err(), res)
		}
		return res, target
	}
	allowed := func(t *testing.T, label, dir string) {
		t.Helper()
		if res, target := write(t, dir); res.ExitCode != 0 {
			t.Fatalf("%s: write into %s: exit %d stderr %q, want 0", label, dir, res.ExitCode, res.Stderr)
		} else if b, err := os.ReadFile(target); err != nil || string(b) != "hi\n" {
			t.Fatalf("%s: %s = %q, %v; want the written line", label, target, b, err)
		}
	}
	denied := func(t *testing.T, label, dir string) {
		t.Helper()
		res, target := write(t, dir)
		if _, err := os.Lstat(target); res.ExitCode == 0 || !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s: write into %s: exit %d stderr %q, stat %v; want a failure leaving %s absent", label, dir, res.ExitCode, res.Stderr, err, target)
		}
	}

	allowed(t, "declared at launch", writable)
	denied(t, "never declared", sibling)
	rewriteSettings(t, settings, writableFoldersYAML(writable, sibling))
	allowed(t, "added mid-session", sibling)
	rewriteSettings(t, settings, writableFoldersYAML(sibling))
	denied(t, "removed mid-session", writable)
	allowed(t, "still declared", sibling)
	rewriteSettings(t, settings, "writable_folders: [\n")
	denied(t, "malformed settings", sibling)
	rewriteSettings(t, settings, writableFoldersYAML(sibling))
	allowed(t, "restored settings", sibling)
	if err := os.Remove(settings); err != nil {
		t.Fatal(err)
	}
	denied(t, "failed settings read", sibling)
	writeProjectSettings(t, project, writableFoldersYAML(sibling))
	allowed(t, "settings readable again", sibling)
}

func TestConfinedRunner_ARunningCommandKeepsItsPolicyThroughTheRealHelper(t *testing.T) {
	home, project, bin := realConfinementHost(t)
	if _, err := runner.ResolveOnPath("sh", runner.FixedPATH); err != nil {
		t.Fatalf("sh absent from %s: %v", runner.FixedPATH, err)
	}
	base := filepath.Dir(project)
	writable, tmpDir := filepath.Join(base, "writable"), filepath.Join(base, "tmp")
	for _, dir := range []string{writable, tmpDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	ready, proceed := filepath.Join(tmpDir, "ready"), filepath.Join(tmpDir, "proceed")
	for _, fifo := range []string{ready, proceed} {
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	conf := liveRealHelperConfinement(t, home, project, tmpDir, writableFoldersYAML(writable))
	confined := &confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 4096}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	run := func(script string, args ...string) runner.RunResult {
		res, err := confined.Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(), Argv: append([]string{"sh", "-c", script, "sh"}, args...), Cwd: project})
		if err != nil || ctx.Err() != nil {
			t.Errorf("confined %q %q: %v, %v; result %+v", script, args, err, ctx.Err(), res)
		}
		return res
	}
	early, late := filepath.Join(writable, "early"), filepath.Join(writable, "late")
	running := make(chan runner.RunResult, 1)
	go func() {
		running <- run(`printf r > "$1" && read -r _ < "$2" && printf x > "$3"`, ready, proceed, early)
	}()
	signal := make(chan string, 1)
	go func() {
		b, _ := os.ReadFile(ready)
		signal <- string(b)
	}()
	select {
	case got := <-signal:
		if got != "r" {
			t.Fatalf("readiness signal = %q, want the running command's handshake", got)
		}
	case res := <-running:
		t.Fatalf("the running command exited before its handshake: exit %d stderr %q", res.ExitCode, res.Stderr)
	}

	rewriteSettings(t, projectSettingsPath(project), writableFoldersYAML())
	if res := run(`printf x > "$1"`, late); res.ExitCode == 0 {
		t.Fatalf("a command started after the removal wrote %s: exit 0, want a failure", late)
	}
	if err := os.WriteFile(proceed, []byte("go\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := <-running; res.ExitCode != 0 {
		t.Fatalf("the command running before the removal: exit %d stderr %q, want its original policy to allow the write", res.ExitCode, res.Stderr)
	}
	if b, err := os.ReadFile(early); err != nil || string(b) != "x" {
		t.Fatalf("%s = %q, %v; want the running command's write", early, b, err)
	}
	if _, err := os.Lstat(late); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stat %s = %v, want it absent", late, err)
	}
}

func TestConfinedRunner_AutoNestedWriteRootsThroughTheRealHelper(t *testing.T) {
	home, project, bin := realConfinementHost(t)
	if _, err := runner.ResolveOnPath("sh", runner.FixedPATH); err != nil {
		t.Fatalf("sh absent from %s: %v", runner.FixedPATH, err)
	}
	base, err := filepath.EvalSymlinks(filepath.Dir(project))
	if err != nil {
		t.Fatal(err)
	}
	shared, outside, declared := filepath.Join(base, "shared"), filepath.Join(base, "outside"), filepath.Join(base, "declared")
	inShared := filepath.Join(shared, "declared")
	for _, dir := range []string{inShared, outside, declared} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "keep"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(shared, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", alias)
	owned, err := newSessionTempDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owned.close)
	private := owned.path
	if filepath.Dir(private) != shared {
		t.Fatalf("private temp folder %q, want it stored resolved inside %q", private, shared)
	}
	conf := liveRealHelperConfinement(t, home, project, private, writableFoldersYAML(declared, inShared, shared))
	confined := &confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 4096}
	run := func(t *testing.T, script string, args ...string) runner.RunResult {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := confined.Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(), Argv: append([]string{"sh", "-c", script, "sh"}, args...), Cwd: project})
		if err != nil || ctx.Err() != nil {
			t.Fatalf("confined %q %q: %v, %v; result %+v", script, args, err, ctx.Err(), res)
		}
		return res
	}
	const write = `printf x > "$1/f"`
	const swap = `mv "$1" "$1.moved" && ln -s "$2" "$1"`
	outsideNames := func() []string {
		entries, err := os.ReadDir(outside)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		return names
	}

	for _, dir := range []string{private, inShared, declared} {
		if res := run(t, write, dir); res.ExitCode != 0 {
			t.Fatalf("write into %s: exit %d stderr %q, want 0", dir, res.ExitCode, res.Stderr)
		}
	}
	if err := os.RemoveAll(declared); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(declared, 0o700); err != nil {
		t.Fatal(err)
	}
	if res := run(t, write, declared); res.ExitCode != 0 {
		t.Fatalf("write into the re-created %s: exit %d stderr %q, want 0", declared, res.ExitCode, res.Stderr)
	}

	swapThenWrite := func(dirs ...string) {
		for _, dir := range dirs {
			if res := run(t, swap, dir, outside); res.ExitCode != 0 {
				t.Fatalf("swap %s for a symlink: exit %d stderr %q, want 0", dir, res.ExitCode, res.Stderr)
			}
			res := run(t, write, dir)
			if got := outsideNames(); res.ExitCode == 0 || !slices.Equal(got, []string{"keep"}) {
				t.Fatalf("write through the swapped %s: exit %d stderr %q, outside holds %q; want a failure leaving it unchanged", dir, res.ExitCode, res.Stderr, got)
			}
		}
	}
	swapThenWrite(private, inShared)

	projectTmp := filepath.Join(project, "tmp")
	if err := os.Mkdir(projectTmp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", projectTmp)
	inProject, err := newSessionTempDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inProject.close)
	confined = &confinedRunner{inner: &helperForwardingRunner{bin: bin}, cap: 4096,
		conf: liveRealHelperConfinement(t, home, project, inProject.path, writableFoldersYAML(declared))}
	swapThenWrite(inProject.path)
	if b, err := os.ReadFile(filepath.Join(outside, "keep")); err != nil || string(b) != "outside" {
		t.Fatalf("outside/keep = %q, %v; want it unchanged", b, err)
	}
}

func TestConfinedRunner_PrivateTempFolderBeneathDevShmCannotBeReplacedThroughTheRealHelper(t *testing.T) {
	home, project, bin := realConfinementHost(t)
	if _, err := runner.ResolveOnPath("sh", runner.FixedPATH); err != nil {
		t.Fatalf("sh absent from %s: %v", runner.FixedPATH, err)
	}
	shm, err := os.MkdirTemp("/dev/shm", "codemeld-shm-")
	if err != nil {
		t.Skipf("no writable /dev/shm: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shm) })
	t.Setenv("TMPDIR", shm)
	owned, err := newSessionTempDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owned.removeAndRelease() })
	private := owned.path
	before, err := os.Lstat(private)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(project), "outside")
	if err := os.MkdirAll(filepath.Join(outside, filepath.Base(private)), 0o700); err != nil {
		t.Fatal(err)
	}
	conf := liveRealHelperConfinement(t, home, project, private, writableFoldersYAML("/dev/shm"))
	confined := &confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 4096}
	run := func(t *testing.T, script string, args ...string) runner.RunResult {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := confined.Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(), Argv: append([]string{"sh", "-c", script, "sh"}, args...), Cwd: project})
		if err != nil || ctx.Err() != nil {
			t.Fatalf("confined %q %q: %v, %v; result %+v", script, args, err, ctx.Err(), res)
		}
		return res
	}

	forward := confined.inner.(*helperForwardingRunner)
	if res := run(t, `printf x > "$1/f"`, private); res.ExitCode != 0 {
		t.Fatalf("write into %s: exit %d stderr %q, want 0", private, res.ExitCode, res.Stderr)
	}
	policy, err := enforce.ReadPolicyFrame(bytes.NewReader(forward.specs[len(forward.specs)-1].Stdin))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(policy.WriteRoots, "/dev/shm") || policy.TmpDir != private {
		t.Fatalf("policy = %+v, want /dev/shm declared and the private folder as tmp_dir", policy)
	}
	for _, tc := range []struct{ name, script string }{
		{"write beside the private folder", `printf x > "$1/f"`},
		{"rename the private folder away", `mv "$2" "$2.moved"`},
		{"remove the private folder", `rm -f "$2/f" && rmdir "$2"`},
		{"plant a link beside it", `ln -s "$3" "$1/link"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if res := run(t, tc.script, shm, private, outside); res.ExitCode == 0 {
				t.Fatalf("%s: exit 0 stderr %q, want a refusal", tc.script, res.Stderr)
			}
		})
	}
	after, err := os.Lstat(private)
	if err != nil || !after.IsDir() || !os.SameFile(before, after) {
		t.Fatalf("private folder after the attempts: %v, %v; want the same folder in place", after, err)
	}
	if entries, err := os.ReadDir(shm); err != nil || len(entries) != 1 {
		t.Fatalf("%s holds %v, %v; want only the private folder", shm, entries, err)
	}
	if res := run(t, `printf y > "$1/g"`, private); res.ExitCode != 0 {
		t.Fatalf("a later write into %s: exit %d stderr %q, want 0", private, res.ExitCode, res.Stderr)
	}
	if b, err := os.ReadFile(filepath.Join(private, "g")); err != nil || string(b) != "y" {
		t.Fatalf("%s/g = %q, %v; want the later write in the private folder", private, b, err)
	}
	if entries, err := os.ReadDir(filepath.Join(outside, filepath.Base(private))); err != nil || len(entries) != 0 {
		t.Fatalf("outside target holds %v, %v; want it empty", entries, err)
	}
}

func TestConfinedRunner_SavedAllowLaunchWritesOnlyThePrivateTempFolderThroughTheRealHelper(t *testing.T) {
	home, project, bin := realConfinementHost(t)
	base, err := filepath.EvalSymlinks(filepath.Dir(project))
	if err != nil {
		t.Fatal(err)
	}
	launchTmp := filepath.Join(base, "launchtmp")
	if err := os.Mkdir(launchTmp, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(launchTmp, "keep")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", launchTmp)
	writeGlobalSettings(t, home, "confinement:\n  shared_temp_folders: allow\n", 0o600)

	inspected := false
	runConfinedLaunch(t, confinedLaunchResult(t, home, project, savedGlobalConfig(t, home)), func(conf *confinement) {
		confined := &confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 4096}
		run := func(target string) runner.RunResult {
			t.Helper()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			res, err := confined.Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(), Argv: []string{"sh", "-c", `printf x > "$1"`, "sh", target}, Cwd: project})
			if err != nil || ctx.Err() != nil {
				t.Fatalf("confined write to %s: %v, %v; result %+v", target, err, ctx.Err(), res)
			}
			return res
		}

		if res := run(victim); res.ExitCode == 0 {
			t.Fatalf("write to %s under the launch TMPDIR: exit 0, want a failure", victim)
		}
		if b, err := os.ReadFile(victim); err != nil || string(b) != "keep" {
			t.Fatalf("%s = %q, %v; want it unchanged", victim, b, err)
		}
		inside := filepath.Join(conf.tmpDir, "f")
		if res := run(inside); res.ExitCode != 0 {
			t.Fatalf("write inside the private temp folder: exit %d stderr %q, want 0", res.ExitCode, res.Stderr)
		}
		if b, err := os.ReadFile(inside); err != nil || string(b) != "x" {
			t.Fatalf("%s = %q, %v; want the written byte", inside, b, err)
		}
		inspected = true
	})
	if !inspected {
		t.Fatal("the launch confinement was never inspected")
	}
}

func TestConfinedRunner_GitRunsWithABlockedGlobalConfigThroughTheRealHelper(t *testing.T) {
	if _, err := runner.ResolveOnPath("git", runner.FixedPATH); err != nil {
		t.Skipf("git absent from %s: %v", runner.FixedPATH, err)
	}
	home, project, bin := realConfinementHost(t)
	gitconfig := filepath.Join(home, ".gitconfig")
	const fixture = "[user]\n\tname = codemeld fixture\n"
	if err := os.WriteFile(gitconfig, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(gitconfig); err != nil || string(b) != fixture {
		t.Fatalf("unconfined read of %s = %q, %v; want the fixture", gitconfig, b, err)
	}
	repo, tmpDir := filepath.Join(project, "repo"), filepath.Join(filepath.Dir(project), "tmp")
	for _, dir := range []string{repo, tmpDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var entries []permissions.BlockedEntry
	for _, raw := range []string{"~/.gitconfig", "~/.config/git/config"} {
		path, err := permissions.ExpandBlockedEntry(home, raw)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, permissions.BlockedEntry{Path: path, Source: SettingsPath(home)})
	}
	cache, err := config.NewCache(map[string]any{"confinement": map[string]any{"program_lookup": "strict"}}, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	conf := withSessionProxy(t, launchConfinement(resolveExecutionCapability(enforce.ResolveInput{Home: home}), tmpDir,
		mode.NewActiveState(mode.AutoEdits, mode.SourceDefault), cache, home, securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, entries)}, nil))
	confined := &confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 4096}
	run := func(script string) runner.RunResult {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := confined.Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(), Argv: []string{"sh", "-c", script}, Cwd: repo})
		if err != nil || ctx.Err() != nil {
			t.Fatalf("confined %q: %v, %v; result %+v", script, err, ctx.Err(), res)
		}
		return res
	}

	if res := run(`cat "$HOME/.gitconfig"`); res.ExitCode == 0 || !strings.Contains(string(res.Stderr), "Permission denied") {
		t.Fatalf("confined read of the fixture: exit %d stdout %q stderr %q; want a denial", res.ExitCode, res.Stdout, res.Stderr)
	}
	if res := run(`git init -q && git status`); res.ExitCode != 0 {
		t.Fatalf("confined git init and status: exit %d stderr %q; want 0", res.ExitCode, res.Stderr)
	}
	if res := run(`unset GIT_CONFIG_GLOBAL; git status`); res.ExitCode == 0 || !strings.Contains(string(res.Stderr), gitconfig) {
		t.Fatalf("confined git status without the override: exit %d stderr %q; want a failure reading %s", res.ExitCode, res.Stderr, gitconfig)
	}
}

func TestConfinedRunner_HelperNeverRunsAnInfocmpPlantedOnTheFriendlyLookupPath(t *testing.T) {
	home, project, bin := realConfinementHost(t)
	base := filepath.Dir(project)
	tools, tmpDir := filepath.Join(project, "tools"), filepath.Join(base, "tmp")
	for _, dir := range []string{tools, tmpDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(base, "infocmp-ran")
	stub := filepath.Join(tools, "infocmp")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nprintf ran > '"+marker+"'\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(stub, "-1", "dumb").Run(); err == nil {
		t.Fatal("unconfined stub exited 0, want its non-zero exit")
	}
	if b, err := os.ReadFile(marker); err != nil || string(b) != "ran" {
		t.Fatalf("unconfined stub marker = %q, %v; want the fixture to write it", b, err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+runner.FixedPATH)
	cache, err := config.NewCache(map[string]any{}, project, nil)
	if err != nil {
		t.Fatal(err)
	}

	owned, err := newSessionTempDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owned.removeAndRelease() })

	for _, tc := range []struct {
		mode   mode.Mode
		tmpDir string
	}{{mode.Plan, owned.path}, {mode.AutoEdits, tmpDir}} {
		t.Run(string(tc.mode), func(t *testing.T) {
			conf := launchConfinement(resolveExecutionCapability(enforce.ResolveInput{Home: home}), tc.tmpDir,
				mode.NewActiveState(tc.mode, mode.SourceDefault), cache, home, securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, nil)}, nil)
			conf.own(owned)
			if first, _, _ := strings.Cut(conf.lookupPath, string(os.PathListSeparator)); first != tools {
				t.Fatalf("lookup path = %q, want %s first", conf.lookupPath, tools)
			}
			confined := &confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 4096}
			run := func(argv ...string) runner.RunResult {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				res, err := confined.Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(), Argv: argv, Cwd: project})
				if err != nil || ctx.Err() != nil {
					t.Fatalf("confined %q: %v, %v; result %+v", argv, err, ctx.Err(), res)
				}
				return res
			}

			if res := run("sh", "-c", `printf %s "$TERM"`); res.ExitCode != 0 || string(res.Stdout) != "dumb" {
				t.Fatalf("confined TERM print: exit %d stdout %q stderr %q; want 0 and dumb", res.ExitCode, res.Stdout, res.Stderr)
			}
			res := run("env")
			var terms []string
			for line := range strings.Lines(string(res.Stdout)) {
				if strings.HasPrefix(line, "TERM=") {
					terms = append(terms, line)
				}
			}
			if res.ExitCode != 0 || !slices.Equal(terms, []string{"TERM=dumb\n"}) {
				t.Fatalf("confined env: exit %d TERM entries %q stderr %q; want exactly TERM=dumb", res.ExitCode, terms, res.Stderr)
			}
			if _, err := os.Stat(marker); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("stat %s = %v; want the planted infocmp never run", marker, err)
			}
		})
	}
}

func TestConfinedRunner_HelperRunsNoProgramFromTheLookupPathBeforeConfinement(t *testing.T) {
	origPATH := os.Getenv("PATH")
	home, project, bin := realConfinementHost(t)
	base := filepath.Dir(project)
	canary, markers, tmpDir := filepath.Join(base, "canary"), filepath.Join(base, "markers"), filepath.Join(base, "tmp")
	for _, dir := range []string{canary, markers, tmpDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fake := filepath.Join(base, "canary-fake")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n: > '"+markers+"'/\"${0##*/}\"\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	names := lookupPathExecutables(origPATH + string(os.PathListSeparator) + runner.FixedPATH)
	names["infocmp"] = true
	other := ""
	for name := range names {
		if err := os.Symlink(fake, filepath.Join(canary, name)); err != nil {
			t.Fatal(err)
		}
		if name != "infocmp" {
			other = name
		}
	}
	if other == "" {
		t.Fatal("no executable found on PATH or runner.FixedPATH besides the infocmp canary")
	}
	readMarkers := func() []string {
		t.Helper()
		entries, err := os.ReadDir(markers)
		if err != nil {
			t.Fatalf("read marker folder: %v", err)
		}
		var got []string
		for _, e := range entries {
			got = append(got, e.Name())
		}
		return got
	}

	for _, name := range []string{"infocmp", other} {
		_ = exec.Command(filepath.Join(canary, name)).Run()
	}
	if got := readMarkers(); !slices.Equal(got, slices.Sorted(slices.Values([]string{"infocmp", other}))) {
		t.Fatalf("unconfined canary markers = %q; want infocmp and %s", got, other)
	}
	clearMarkers := func(names []string) {
		t.Helper()
		for _, name := range names {
			if err := os.Remove(filepath.Join(markers, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	clearMarkers([]string{"infocmp", other})

	t.Setenv("PATH", canary+string(os.PathListSeparator)+origPATH)
	cache, err := config.NewCache(map[string]any{}, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := newSessionTempDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owned.removeAndRelease() })

	for _, tc := range []struct {
		mode   mode.Mode
		tmpDir string
	}{{mode.Plan, owned.path}, {mode.AutoEdits, tmpDir}} {
		t.Run(string(tc.mode), func(t *testing.T) {
			conf := launchConfinement(resolveExecutionCapability(enforce.ResolveInput{Home: home}), tc.tmpDir,
				mode.NewActiveState(tc.mode, mode.SourceDefault), cache, home, securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, nil)}, nil)
			conf.own(owned)
			if first, _, _ := strings.Cut(conf.lookupPath, string(os.PathListSeparator)); first != canary {
				t.Fatalf("lookup path = %q, want %s first", conf.lookupPath, canary)
			}
			confined := &confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 4096}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			res, err := confined.Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(), Argv: []string{"/bin/sh", "-c", `printf %s "$TERM"`}, Cwd: project})
			if got := readMarkers(); len(got) > 0 {
				t.Errorf("programs run from the lookup PATH before confinement: %q", got)
				clearMarkers(got)
			}
			if err != nil || ctx.Err() != nil || res.ExitCode != 0 || string(res.Stdout) != "dumb" {
				t.Fatalf("confined TERM print: %v, %v; exit %d stdout %q stderr %q; want 0 and dumb", err, ctx.Err(), res.ExitCode, res.Stdout, res.Stderr)
			}
		})
	}
}

func lookupPathExecutables(path string) map[string]bool {
	names := map[string]bool{}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			dir = "."
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if info, err := os.Stat(filepath.Join(dir, e.Name())); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
				names[e.Name()] = true
			}
		}
	}
	return names
}

func TestLookupPathExecutables_EmptyComponentScansTheCurrentDirectory(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "codemeld-cwd-only-program"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	for _, path := range []string{"/usr/bin::/bin", ":/usr/bin", "/usr/bin:"} {
		if !lookupPathExecutables(path)["codemeld-cwd-only-program"] {
			t.Errorf("PATH %q: current-directory executable missing from the inventory", path)
		}
	}
}

const planTempReplacedNote ="codemeld: the session's private temp folder was moved or replaced since codemeld created it; " +
	"Plan commands run without it. Restart codemeld to get a new one."

func planRealHelperRunner(t *testing.T, home, project, bin string, cache *config.Cache) (*confinedRunner, *sessionTempDir) {
	t.Helper()
	owned, err := newSessionTempDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owned.removeAndRelease() })
	conf := launchConfinement(resolveExecutionCapability(enforce.ResolveInput{Home: home}), owned.path,
		mode.NewActiveState(mode.Plan, mode.SourceDefault), cache, home, securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, nil)}, nil)
	conf.own(owned)
	return &confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 64 * 1024}, owned
}

func runConfined(t *testing.T, ctx context.Context, r *confinedRunner, spec runner.RunSpec) runner.RunResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	spec.InvocationID = ids.NewV7()
	res, err := r.Exec(ctx, spec)
	if err != nil || ctx.Err() != nil {
		t.Fatalf("confined %q: %v, %v; result %+v", spec.Argv, err, ctx.Err(), res)
	}
	return res
}

func TestConfinedRunner_PlanWritesOnlyThePrivateTempFolderAndBuildsGoThroughTheRealHelper(t *testing.T) {
	hostGo, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no Go toolchain on the launch PATH: %v", err)
	}
	out, err := exec.Command(hostGo, "env", "GOROOT").Output()
	if err != nil {
		t.Fatalf("%s env GOROOT: %v", hostGo, err)
	}
	goBin := filepath.Join(strings.TrimSpace(string(out)), "bin")
	if _, err := os.Stat(filepath.Join(goBin, "go")); err != nil {
		t.Fatalf("toolchain behind %s: %v", hostGo, err)
	}
	home, project, bin := realConfinementHost(t)
	if _, err := runner.ResolveOnPath("sh", runner.FixedPATH); err != nil {
		t.Fatalf("sh absent from %s: %v", runner.FixedPATH, err)
	}
	lib := filepath.Join(project, "lib")
	if err := os.Mkdir(lib, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := map[string]string{
		filepath.Join(lib, "go.mod"):       "module example.com/lib\n\ngo 1.21\n",
		filepath.Join(lib, "lib.go"):       "package lib\n\nfunc Add(a, b int) int { return a + b }\n",
		filepath.Join(lib, "lib_test.go"):  "package lib\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) {\n\tif Add(2, 3) != 5 {\n\t\tt.Fatal(\"Add(2, 3) != 5\")\n\t}\n}\n",
		filepath.Join(project, "keep.txt"): "keep",
	}
	for path, content := range fixture {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outsideProbe := filepath.Join("/tmp", "codemeld-plan-probe-"+strconv.Itoa(os.Getpid()))
	if _, err := os.Lstat(outsideProbe); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("fixture: %s must be absent, stat = %v", outsideProbe, err)
	}
	t.Setenv("PATH", goBin+string(os.PathListSeparator)+runner.FixedPATH)
	cache, err := config.NewCache(map[string]any{}, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	confined, owned := planRealHelperRunner(t, home, project, bin, cache)
	write := func(target string) runner.RunResult {
		return runConfined(t, context.Background(), confined, runner.RunSpec{Argv: []string{"sh", "-c", `printf x > "$1"`, "sh", target}, Cwd: project})
	}

	inside := filepath.Join(owned.path, "f")
	if res := write(inside); res.ExitCode != 0 {
		t.Fatalf("write inside the private temp folder: exit %d stderr %q, want 0", res.ExitCode, res.Stderr)
	}
	if b, err := os.ReadFile(inside); err != nil || string(b) != "x" {
		t.Fatalf("%s = %q, %v; want the written byte", inside, b, err)
	}
	for _, target := range []string{filepath.Join(project, "keep.txt"), filepath.Join(project, "new.txt"), outsideProbe} {
		if res := write(target); res.ExitCode == 0 {
			t.Fatalf("write to %s: exit 0, want a failure", target)
		}
	}
	if b, err := os.ReadFile(filepath.Join(project, "keep.txt")); err != nil || string(b) != "keep" {
		t.Fatalf("keep.txt = %q, %v; want it unchanged", b, err)
	}
	for _, absent := range []string{filepath.Join(project, "new.txt"), outsideProbe} {
		if _, err := os.Lstat(absent); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("stat %s = %v, want it absent", absent, err)
		}
	}

	res := runConfined(t, context.Background(), confined, runner.RunSpec{
		Argv:        []string{"sh", "-c", "go build ./... && go test ./..."},
		Cwd:         lib,
		Assignments: []string{"GOTOOLCHAIN=local", "GOPROXY=off", "GOFLAGS=-mod=readonly"},
	})
	if res.ExitCode != 0 || !strings.HasPrefix(string(res.Stdout), "ok") || !strings.Contains(string(res.Stdout), "example.com/lib") {
		t.Fatalf("confined go build and go test: exit %d stdout %q stderr %q; want 0", res.ExitCode, res.Stdout, res.Stderr)
	}
	entries, err := os.ReadDir(lib)
	if err != nil || len(entries) != 3 {
		t.Fatalf("%s holds %v, %v; want only the three fixture files", lib, entries, err)
	}
	for path, content := range fixture {
		if b, err := os.ReadFile(path); err != nil || string(b) != content {
			t.Fatalf("%s = %q, %v; want it unchanged", path, b, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(home, "go")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stat %s/go = %v, want no module cache", home, err)
	}
}

func TestConfinedRunner_PlanRefusesAReplacedPrivateTempFolderThroughTheRealHelper(t *testing.T) {
	home, project, bin := realConfinementHost(t)
	if _, err := runner.ResolveOnPath("sh", runner.FixedPATH); err != nil {
		t.Fatalf("sh absent from %s: %v", runner.FixedPATH, err)
	}
	projectTmp, outside := filepath.Join(project, "tmp"), filepath.Join(filepath.Dir(project), "outside")
	for _, dir := range []string{projectTmp, outside} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TMPDIR", projectTmp)
	cache, err := config.NewCache(map[string]any{"confinement": map[string]any{"program_lookup": "strict"}}, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	confined, owned := planRealHelperRunner(t, home, project, bin, cache)
	private := owned.path
	if filepath.Dir(private) != projectTmp {
		t.Fatalf("private temp folder %q, want it inside the project's %s", private, projectTmp)
	}
	plan := func(script string) runner.RunResult {
		return runConfined(t, context.Background(), confined, runner.RunSpec{Argv: []string{"sh", "-c", script, "sh", private}, Cwd: project})
	}
	auto := func(script string) {
		ctx := vcs.WithConfinementMode(context.Background(), string(mode.AutoEdits))
		res := runConfined(t, ctx, confined, runner.RunSpec{Argv: []string{"sh", "-c", script, "sh", private, outside}, Cwd: project})
		if res.ExitCode != 0 {
			t.Fatalf("auto %q: exit %d stderr %q, want 0", script, res.ExitCode, res.Stderr)
		}
	}

	if res := plan(`printf x > "$TMPDIR/a"`); res.ExitCode != 0 || strings.Contains(string(res.Stderr), planTempReplacedNote) {
		t.Fatalf("plan write into the unchanged folder: exit %d stderr %q, want 0 and no replacement note", res.ExitCode, res.Stderr)
	}
	if b, err := os.ReadFile(filepath.Join(private, "a")); err != nil || string(b) != "x" {
		t.Fatalf("%s/a = %q, %v; want the plan write", private, b, err)
	}

	for _, tc := range []struct{ name, replace string }{
		{"symlink to an outside folder", `mv "$1" "$1.moved" && ln -s "$2" "$1"`},
		{"different folder under the same name", `rm -rf "$1" && mkdir "$1"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auto(tc.replace)
			res := plan(`printf x > "$1/f"`)
			if res.ExitCode == 0 || !strings.Contains(string(res.Stderr), planTempReplacedNote) {
				t.Fatalf("plan write through the replaced folder: exit %d stderr %q, want a failure and the replacement note", res.ExitCode, res.Stderr)
			}
			if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
				t.Fatalf("%s holds %v, %v; want it empty", outside, entries, err)
			}
			if _, err := os.Lstat(filepath.Join(private, "f")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("stat %s/f = %v, want it absent", private, err)
			}
		})
	}
}

func TestConfinedRunner_HistoryStoresStayReadOnlyThroughTheRealHelper(t *testing.T) {
	home, project, bin := realConfinementHost(t)
	if _, err := runner.ResolveOnPath("sh", runner.FixedPATH); err != nil {
		t.Fatalf("sh absent from %s: %v", runner.FixedPATH, err)
	}
	base, err := filepath.EvalSymlinks(filepath.Dir(project))
	if err != nil {
		t.Fatal(err)
	}
	project = filepath.Join(base, "project")
	worktree, stores, tmpDir := filepath.Join(base, "wt"), filepath.Join(base, "stores"), filepath.Join(base, "tmp")
	store, gitdir := filepath.Join(project, ".git"), filepath.Join(stores, "wtgit")
	for _, dir := range []string{store, filepath.Join(project, "src"), filepath.Join(worktree, "sub"), gitdir, filepath.Join(stores, "other"), tmpDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	pointer := filepath.Join(worktree, ".git")
	files := map[string]string{filepath.Join(store, "HEAD"): "head", filepath.Join(gitdir, "HEAD"): "wthead", pointer: "gitdir: " + gitdir + "\n"}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	selected, linked := filepath.Join(stores, "selected"), filepath.Join(base, "linked")
	selector := filepath.Join(linked, "links", "current")
	for _, dir := range []string{selected, filepath.Join(stores, "unselected"), filepath.Join(linked, "links"), filepath.Join(linked, "sub")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(selected, selector); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(linked, ".git"), []byte("gitdir: links/current\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dotdot, dotStore := filepath.Join(base, "dotdot"), filepath.Join(stores, "dotstore")
	dotSelector := filepath.Join(dotdot, "links", "current")
	for _, dir := range []string{dotStore, filepath.Join(dotdot, "links", "dotstore"), filepath.Join(dotdot, "sub")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(selected, dotSelector); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dotdot, ".git"), []byte("gitdir: links/current/../dotstore\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := liveRealHelperConfinement(t, home, project, tmpDir, writableFoldersYAML(worktree, stores, linked, dotdot))
	run := func(t *testing.T, storesWritable bool, script string, args ...string) runner.RunResult {
		t.Helper()
		confined := &confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 4096, storesWritable: storesWritable}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := confined.Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(), Argv: append([]string{"sh", "-c", script, "sh"}, args...), Cwd: project})
		if err != nil || ctx.Err() != nil {
			t.Fatalf("confined %q %q: %v, %v; result %+v", script, args, err, ctx.Err(), res)
		}
		return res
	}
	unchanged := func(t *testing.T) {
		t.Helper()
		for path, content := range files {
			if b, err := os.ReadFile(path); err != nil || string(b) != content {
				t.Fatalf("%s = %q, %v; want %q", path, b, err, content)
			}
		}
		for _, path := range []string{filepath.Join(store, "new"), filepath.Join(gitdir, "new"), filepath.Join(worktree, "moved")} {
			if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("stat %s = %v, want it absent", path, err)
			}
		}
	}

	for _, tc := range []struct{ name, script, target string }{
		{"create in the project store", `printf x > "$1/new"`, store},
		{"modify the project store", `printf x > "$1/HEAD"`, store},
		{"create in the worktree gitdir", `printf x > "$1/new"`, gitdir},
		{"modify the worktree gitdir", `printf x > "$1/HEAD"`, gitdir},
		{"overwrite the pointer file", `printf 'gitdir: /elsewhere\n' > "$1"`, pointer},
		{"delete the pointer file", `rm -f "$1"`, pointer},
		{"rename the pointer file", `mv "$1" "$(dirname "$1")/moved"`, pointer},
		{"repoint the pointer file", `printf 'gitdir: /elsewhere\n' > "$TMPDIR/p" && mv -f "$TMPDIR/p" "$1"`, pointer},
		{"create in the store a dot-dot selector reaches", `printf x > "$1/new"`, dotStore},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if res := run(t, false, tc.script, tc.target); res.ExitCode == 0 {
				t.Fatalf("%s: exit 0 stderr %q, want a refusal", tc.script, res.Stderr)
			}
			unchanged(t)
		})
	}
	for _, tc := range []struct{ name, script string }{
		{"replace the store selector", `ln -sfn "$2" "$1"`},
		{"rename over the store selector", `ln -s "$2" "$TMPDIR/sel" && mv -fT "$TMPDIR/sel" "$1"`},
		{"delete the store selector", `rm -f "$1"`},
	} {
		for _, link := range []string{selector, dotSelector} {
			t.Run(tc.name+" "+filepath.Base(filepath.Dir(filepath.Dir(link))), func(t *testing.T) {
				if res := run(t, false, tc.script, link, filepath.Join(stores, "unselected")); res.ExitCode == 0 {
					t.Fatalf("%s: exit 0 stderr %q, want a refusal", tc.script, res.Stderr)
				}
				if target, err := os.Readlink(link); err != nil || target != selected {
					t.Fatalf("readlink %s = %q, %v; want %q", link, target, err, selected)
				}
			})
		}
	}
	if _, err := os.Lstat(filepath.Join(dotStore, "new")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stat %s/new = %v, want it absent", dotStore, err)
	}
	for _, dir := range []string{filepath.Join(project, "src"), filepath.Join(worktree, "sub"), filepath.Join(stores, "other"), filepath.Join(linked, "sub"),
		filepath.Join(dotdot, "sub"), filepath.Join(dotdot, "links", "dotstore")} {
		if res := run(t, false, `printf x > "$1/f"`, dir); res.ExitCode != 0 {
			t.Fatalf("write into %s: exit %d stderr %q, want 0", dir, res.ExitCode, res.Stderr)
		}
	}
	for _, dir := range []string{store, gitdir} {
		if res := run(t, true, `printf x > "$1/vcs"`, dir); res.ExitCode != 0 {
			t.Fatalf("vcs runner write into %s: exit %d stderr %q, want 0", dir, res.ExitCode, res.Stderr)
		}
		if b, err := os.ReadFile(filepath.Join(dir, "vcs")); err != nil || string(b) != "x" {
			t.Fatalf("%s/vcs = %q, %v; want the vcs runner's write", dir, b, err)
		}
	}
}

func TestConfinedRunner_ExternalGitStoresStayReadOnlyThroughTheRealHelper(t *testing.T) {
	mkdir := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(t *testing.T, path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, project, base string) (store, writable string)
	}{
		{"pointer to a store whose hooks folder is writable", func(t *testing.T, project, base string) (string, string) {
			store := filepath.Join(base, "main.git")
			mkdir(t, filepath.Join(store, "hooks"))
			write(t, filepath.Join(project, ".git"), "gitdir: "+store+"\n")
			return store, filepath.Join(store, "hooks")
		}},
		{"git folder whose commondir names a store in a writable folder", func(t *testing.T, project, base string) (string, string) {
			store := filepath.Join(base, "stores", "common")
			mkdir(t, filepath.Join(store, "hooks"))
			mkdir(t, filepath.Join(project, ".git"))
			write(t, filepath.Join(project, ".git", "commondir"), store+"\n")
			return store, filepath.Join(base, "stores")
		}},
		{"symlinked git folder whose commondir names a store in a writable folder", func(t *testing.T, project, base string) (string, string) {
			store := filepath.Join(base, "stores", "common")
			mkdir(t, filepath.Join(store, "hooks"))
			mkdir(t, filepath.Join(base, "wt"))
			write(t, filepath.Join(base, "wt", "commondir"), "../stores/common\n")
			if err := os.Symlink(filepath.Join(base, "wt"), filepath.Join(project, ".git")); err != nil {
				t.Fatal(err)
			}
			return store, filepath.Join(base, "stores")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, project, bin := realConfinementHost(t)
			if _, err := runner.ResolveOnPath("sh", runner.FixedPATH); err != nil {
				t.Fatalf("sh absent from %s: %v", runner.FixedPATH, err)
			}
			base, err := filepath.EvalSymlinks(filepath.Dir(project))
			if err != nil {
				t.Fatal(err)
			}
			project = filepath.Join(base, "project")
			free, tmpDir := filepath.Join(base, "free"), filepath.Join(base, "tmp")
			for _, dir := range []string{project, free, tmpDir} {
				mkdir(t, dir)
			}
			store, writable := tc.setup(t, project, base)
			hook := filepath.Join(store, "hooks", "pre-commit")
			write(t, hook, "orig")
			conf := liveRealHelperConfinement(t, home, project, tmpDir, writableFoldersYAML(writable, free))
			p, err := conf.policy(conf.mode(), conf.tmpDir, conf.blocked.Current(), false)
			if err != nil || !slices.Contains(p.NoWritePaths, store) {
				t.Fatalf("policy no-write paths = %q, %v; want %s among them", p.NoWritePaths, err, store)
			}
			run := func(t *testing.T, storesWritable bool, script string, args ...string) runner.RunResult {
				t.Helper()
				confined := &confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 4096, storesWritable: storesWritable}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				res, err := confined.Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(), Argv: append([]string{"sh", "-c", script, "sh"}, args...), Cwd: project})
				if err != nil || ctx.Err() != nil {
					t.Fatalf("confined %q %q: %v, %v; result %+v", script, args, err, ctx.Err(), res)
				}
				return res
			}
			for _, script := range []string{`printf x > "$1/hooks/new"`, `printf x > "$1/hooks/pre-commit"`} {
				if res := run(t, false, script, store); res.ExitCode == 0 {
					t.Fatalf("%s: exit 0 stderr %q, want a refusal", script, res.Stderr)
				}
			}
			if b, err := os.ReadFile(hook); err != nil || string(b) != "orig" {
				t.Fatalf("%s = %q, %v; want it unchanged", hook, b, err)
			}
			if _, err := os.Lstat(filepath.Join(store, "hooks", "new")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("stat %s/hooks/new = %v, want it absent", store, err)
			}
			if res := run(t, false, `printf x > "$1/f"`, free); res.ExitCode != 0 {
				t.Fatalf("write into %s: exit %d stderr %q, want 0", free, res.ExitCode, res.Stderr)
			}
			if res := run(t, true, `printf x > "$1/hooks/vcs"`, store); res.ExitCode != 0 {
				t.Fatalf("vcs runner write into %s/hooks: exit %d stderr %q, want 0", store, res.ExitCode, res.Stderr)
			}
		})
	}
}

func TestConfinedRunner_StatusWorksWithReadOnlyStoresThroughTheRealHelper(t *testing.T) {
	home, project, bin := realConfinementHost(t)
	base, err := filepath.EvalSymlinks(filepath.Dir(project))
	if err != nil {
		t.Fatal(err)
	}
	project = filepath.Join(base, "project")
	tmpDir := filepath.Join(base, "tmp")
	if err := os.Mkdir(tmpDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		program, store string
		setup          [][]string
		status         []string
		want           string
	}{
		{"git", ".git", [][]string{{"git", "init", "-q"}, {"git", "add", "f"}, {"git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "init"}},
			[]string{"git", "status", "--porcelain"}, " M f\n"},
		{"hg", ".hg", [][]string{{"hg", "init"}, {"hg", "add", "-q", "f"}, {"hg", "commit", "-q", "-u", "t", "-m", "init"}},
			[]string{"hg", "status"}, "M f\n"},
	} {
		t.Run(tc.program, func(t *testing.T) {
			if _, err := runner.ResolveOnPath(tc.program, runner.FixedPATH); err != nil {
				t.Skipf("%s absent from %s: %v", tc.program, runner.FixedPATH, err)
			}
			repo := filepath.Join(base, tc.program+"repo")
			if err := os.Mkdir(repo, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(repo, "f"), []byte("one\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, argv := range tc.setup {
				cmd := exec.Command(argv[0], argv[1:]...)
				cmd.Dir = repo
				cmd.Env = append(os.Environ(), "HOME="+home, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "HGRCPATH=", "HGPLAIN=1")
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%q: %v\n%s", argv, err, out)
				}
			}
			if err := os.WriteFile(filepath.Join(repo, "f"), []byte("two\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			forward := &helperForwardingRunner{bin: bin}
			confined := &confinedRunner{inner: forward, cap: 4096,
				conf: liveRealHelperConfinement(t, home, project, tmpDir, writableFoldersYAML(repo))}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			res, err := confined.Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(), Argv: tc.status, Cwd: repo})
			if err != nil || ctx.Err() != nil {
				t.Fatalf("confined %q: %v, %v; result %+v", tc.status, err, ctx.Err(), res)
			}
			policy, err := enforce.ReadPolicyFrame(bytes.NewReader(forward.specs[0].Stdin))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(policy.NoWritePaths, filepath.Join(repo, tc.store)) {
				t.Fatalf("no-write paths = %q, want %s read-only", policy.NoWritePaths, filepath.Join(repo, tc.store))
			}
			if res.ExitCode != 0 || string(res.Stdout) != tc.want {
				t.Fatalf("confined %q: exit %d stdout %q stderr %q; want 0 and %q", tc.status, res.ExitCode, res.Stdout, res.Stderr, tc.want)
			}
		})
	}
}

func TestRunHeadless_ConfinedShellExpandsPathnamePatternsThroughTheRealHelper(t *testing.T) {
	home, project, bin := realConfinementHost(t)
	if _, err := runner.ResolveOnPath("sh", runner.FixedPATH); err != nil {
		t.Fatalf("sh absent from %s: %v", runner.FixedPATH, err)
	}
	if err := os.Mkdir(filepath.Join(project, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"a.md": "x1\n", "b.md": "x2\n"} {
		if err := os.WriteFile(filepath.Join(project, "dir", name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	matches := []string{"dir/a.md:1:x1", "dir/b.md:1:x2"}
	for _, m := range []mode.Mode{mode.Plan, mode.AutoEdits} {
		for _, tc := range []struct {
			command string
			matched bool
		}{
			{"grep -n x dir/*.md", true},
			{"grep -n x dir/?.md", true},
			{"grep -n x dir/[ab].md", true},
			{"ls | grep -n x dir/*.md", true},
			{"ls; grep -n x dir/*.md", true},
			{"true && grep -n x dir/*.md", true},
			{"false || grep -n x dir/*.md", true},
			{"false && grep -n x dir/*.md", false},
			{"true || grep -n x dir/*.md", false},
		} {
			t.Run(string(m)+"/"+tc.command, func(t *testing.T) {
				run := &helperForwardingRunner{bin: bin}
				result := headlessResult(t, project, mode.NewActiveState(m, mode.SourceDefault))
				result.Home, result.ConfigLayerPaths = home, []string{SettingsPath(home)}
				result.Config["confinement"] = map[string]any{"program_lookup": "strict"}
				runHeadlessShell(t, result, run, tc.command)

				if len(run.specs) != 1 || !slices.Equal(run.specs[0].Argv[3:], []string{"-c", tc.command}) {
					t.Fatalf("inner runs = %+v, want one sh -c %q through the helper", run.specs, tc.command)
				}
				ends := decodeDiskEvents[events.ToolExecEnd](t, readSessionFile(t, result.Session.Path()), events.KindToolExecEnd)
				if len(ends) != 1 {
					t.Fatalf("tool_exec_end = %+v, want one", ends)
				}
				for _, match := range matches {
					if strings.Contains(ends[0].Stdout, match) != tc.matched {
						t.Fatalf("stdout = %q, stderr = %q; want %q present = %v", ends[0].Stdout, ends[0].Stderr, match, tc.matched)
					}
				}
			})
		}
	}
}

func setupDescriptors(t *testing.T, pid string) map[string]string {
	t.Helper()
	dir := filepath.Join("/proc", pid, "fd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]string{}
	for _, e := range entries {
		if target, err := os.Readlink(filepath.Join(dir, e.Name())); err == nil {
			held[e.Name()] = target
		}
	}
	return held
}

func heldSetupEnds(t *testing.T, baseline map[string]bool) []string {
	t.Helper()
	var extra []string
	for _, target := range setupDescriptors(t, "self") {
		if (strings.HasPrefix(target, "socket:") || strings.Contains(target, "seccomp")) && !baseline[target] {
			extra = append(extra, target)
		}
	}
	return extra
}

func setupBaseline(t *testing.T) map[string]bool {
	t.Helper()
	baseline := map[string]bool{}
	for _, target := range setupDescriptors(t, "self") {
		baseline[target] = true
	}
	return baseline
}

func brokerConfinement(t *testing.T) (conf *confinement, project, writable, bin string) {
	t.Helper()
	conf, project, writable, bin = unstartedBrokerConfinement(t)
	startedSessionProxy(t, conf)
	return conf, project, writable, bin
}

func unstartedBrokerConfinement(t *testing.T) (conf *confinement, project, writable, bin string) {
	t.Helper()
	home, project, bin := realConfinementHost(t)
	if _, err := runner.ResolveOnPath("sh", runner.FixedPATH); err != nil {
		t.Fatalf("sh absent from %s: %v", runner.FixedPATH, err)
	}
	base := filepath.Dir(project)
	writable, tmpDir := filepath.Join(base, "writable"), filepath.Join(base, "tmp")
	for _, dir := range []string{writable, tmpDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	conf = liveRealHelperConfinement(t, home, project, tmpDir, writableFoldersYAML(writable))
	conf.broker = enforce.BrokerSlice
	return conf, project, writable, bin
}

func startedSessionProxy(t *testing.T, conf *confinement) netip.AddrPort {
	t.Helper()
	withSessionProxy(t, conf)
	endpoint, err := conf.proxy.start()
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}

func swapRelease(t *testing.T, release func(*os.File) error) {
	t.Helper()
	old := releaseHelper
	releaseHelper = release
	t.Cleanup(func() { releaseHelper = old })
}

func helperChildren(t *testing.T) []string {
	t.Helper()
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	var pids []string
	for _, task := range tasks {
		b, _ := os.ReadFile(filepath.Join("/proc/self/task", task.Name(), "children"))
		for _, pid := range strings.Fields(string(b)) {
			cmdline, _ := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
			if slices.Contains(strings.Split(string(cmdline), "\x00"), enforce.HelperCommand) {
				pids = append(pids, pid)
			}
		}
	}
	return pids
}

const listOwnDescriptors = `for f in /proc/$$/fd/*; do readlink "$f" || :; done`

func TestConfinedRunner_BrokerLaunchHoldsTheTargetUntilReleaseThroughTheRealHelper(t *testing.T) {
	conf, project, writable, bin := brokerConfinement(t)
	reached, gate := make(chan struct{}, 2), make(chan struct{})
	openGate := sync.OnceFunc(func() { close(gate) })
	t.Cleanup(openGate)
	swapRelease(t, func(f *os.File) error {
		reached <- struct{}{}
		<-gate
		return enforce.ReleaseHelper(f)
	})
	forward := &helperForwardingRunner{bin: bin}
	confined := &confinedRunner{inner: forward, conf: conf, cap: 4096}
	baseline := setupBaseline(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	finish := filepath.Join(writable, "finish")
	script := `cat > /dev/null; ` + listOwnDescriptors + ` > "$1.tmp" && mv "$1.tmp" "$1"; while [ ! -e "$2" ]; do sleep 0.05; done`
	markers := []string{filepath.Join(writable, "a"), filepath.Join(writable, "b")}
	type outcome struct {
		res runner.RunResult
		err error
	}
	done := make(chan outcome, len(markers))
	for i, marker := range markers {
		var stdin []byte
		if i == 0 {
			stdin = bytes.Repeat([]byte("x"), 1<<20)
		}
		go func() {
			res, err := confined.Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(), Argv: []string{"sh", "-c", script, "sh", marker, finish},
				Cwd: project, Stdin: stdin})
			done <- outcome{res, err}
		}()
	}
	for range markers {
		select {
		case <-reached:
		case got := <-done:
			t.Fatalf("launch returned before reaching release: %v, exit %d stderr %q", got.err, got.res.ExitCode, got.res.Stderr)
		case <-ctx.Done():
			t.Fatal("no launch reached release")
		}
	}

	for _, marker := range markers {
		if _, err := os.Lstat(marker); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("target ran before release: stat %s = %v", marker, err)
		}
	}
	helpers := helperChildren(t)
	if len(helpers) != len(markers) {
		t.Fatalf("helper processes = %v, want %d", helpers, len(markers))
	}
	for _, pid := range helpers {
		fds := setupDescriptors(t, pid)
		for fd, target := range fds {
			n, _ := strconv.Atoi(fd)
			runtimeOwned := target == "anon_inode:[eventpoll]" || target == "anon_inode:[eventfd]" ||
				strings.HasPrefix(target, "/sys/fs/cgroup/") && strings.HasSuffix(target, "/cpu.max")
			if fd == "3" && !strings.HasPrefix(target, "socket:") || n > 3 && !runtimeOwned || strings.Contains(target, "seccomp") {
				t.Errorf("helper %s fd %s = %q; want only stdin, stdout, stderr and the setup channel at 3, no listener", pid, fd, target)
			}
		}
		if _, ok := fds["3"]; !ok {
			t.Errorf("helper %s has no setup channel at fd 3: %v", pid, fds)
		}
	}
	unrelated, err := runner.DirectExecRunner{}.Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(), Argv: []string{"/bin/sh", "-c", listOwnDescriptors}})
	if err != nil || unrelated.ExitCode != 0 {
		t.Fatalf("unrelated child: %v, exit %d", err, unrelated.ExitCode)
	}
	if out := string(unrelated.Stdout); strings.Contains(out, "socket:") || strings.Contains(out, "seccomp") {
		t.Errorf("unrelated child inherited a setup descriptor:\n%s", out)
	}

	openGate()
	for _, marker := range markers {
		var listing []byte
		for ctx.Err() == nil {
			if listing, err = os.ReadFile(marker); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("target never wrote %s after release: %v", marker, err)
		}
		if strings.Contains(string(listing), "socket:") || strings.Contains(string(listing), "seccomp") {
			t.Errorf("target %s holds a setup descriptor:\n%s", marker, listing)
		}
	}
	for _, target := range heldSetupEnds(t, baseline) {
		if strings.HasPrefix(target, "socket:") {
			t.Errorf("codemeld still holds setup channel %s while the target runs", target)
		}
	}
	if err := os.WriteFile(finish, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for range markers {
		got := <-done
		if got.err != nil || got.res.ExitCode != 0 {
			t.Errorf("broker launch: %v, exit %d stderr %q", got.err, got.res.ExitCode, got.res.Stderr)
		}
	}
	if extra := heldSetupEnds(t, baseline); len(extra) != 0 {
		t.Errorf("after the targets exited codemeld still holds %v", extra)
	}
}

func TestConfinedRunner_BrokerEarlyCloseStopsTheBrokerWhileTheTargetRunsThroughTheRealHelper(t *testing.T) {
	conf, project, writable, bin := brokerConfinement(t)
	forward := &helperForwardingRunner{bin: bin}
	confined := &confinedRunner{inner: forward, conf: conf, cap: 4096}
	baseline := setupBaseline(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	marker, finish := filepath.Join(writable, "running"), filepath.Join(writable, "finish")
	type outcome struct {
		res runner.RunResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := confined.Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(),
			Argv: []string{"sh", "-c", `: > "$1"; while [ ! -e "$2" ]; do sleep 0.05; done`, "sh", marker, finish}, Cwd: project})
		done <- outcome{res, err}
	}()
	for ctx.Err() == nil {
		if _, err := os.Lstat(marker); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("target never ran")
	}
	forward.mu.Lock()
	forward.specs[0].Helper.Close()
	forward.mu.Unlock()
	if extra := heldSetupEnds(t, baseline); len(extra) != 0 {
		t.Errorf("Close returned while codemeld still holds %v", extra)
	}
	if err := os.WriteFile(finish, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := <-done; got.err != nil || got.res.ExitCode != 0 {
		t.Errorf("broker launch: %v, exit %d stderr %q", got.err, got.res.ExitCode, got.res.Stderr)
	}
}

func TestConfinedRunner_BrokerHandoffFailureLeavesNothingOpenThroughTheRealHelper(t *testing.T) {
	refused := errors.New("handoff refused")
	cases := map[string]func(t *testing.T){
		"listener receipt": func(t *testing.T) {
			old := receiveListener
			receiveListener = func(*os.File, time.Duration) (*os.File, error) { return nil, refused }
			t.Cleanup(func() { receiveListener = old })
			swapRelease(t, func(*os.File) error { t.Error("release reached after a failed listener receipt"); return refused })
		},
		"release": func(t *testing.T) {
			swapRelease(t, func(*os.File) error { return refused })
		},
	}
	for name, inject := range cases {
		t.Run(name, func(t *testing.T) {
			conf, project, writable, bin := brokerConfinement(t)
			inject(t)
			forward := &helperForwardingRunner{bin: bin}
			confined := &confinedRunner{inner: forward, conf: conf, cap: 4096}
			baseline := setupBaseline(t)
			marker := filepath.Join(writable, "ran")
			done := make(chan error, 1)
			go func() {
				_, err := confined.Exec(context.Background(), runner.RunSpec{InvocationID: ids.NewV7(),
					Argv: []string{"sh", "-c", `echo ran > "$1"`, "sh", marker}, Cwd: project})
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, refused) {
					t.Fatalf("err = %v, want the handoff failure", err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("launch did not return after the handoff failed")
			}
			if _, err := os.Lstat(marker); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("target ran without release: stat %s = %v", marker, err)
			}
			if helpers := helperChildren(t); len(helpers) != 0 {
				t.Errorf("helper processes left unreaped: %v", helpers)
			}
			if extra := heldSetupEnds(t, baseline); len(extra) != 0 {
				t.Errorf("codemeld still holds %v", extra)
			}
			requireOwnerRetired(t, conf, forward.specs[0].Helper)
		})
	}
}

func TestConfinedRunner_BrokerWrapperRefusalClosesTheHelperChannel(t *testing.T) {
	refused := errors.New("inner refused")
	wrappers := map[string]func(*confinement, *confineInner, runner.RunSpec) error{
		"confinedRunner": func(conf *confinement, inner *confineInner, spec runner.RunSpec) error {
			_, err := (&confinedRunner{inner: inner, conf: conf, cap: 4096}).Exec(context.Background(), spec)
			return err
		},
		"confinedShellRunner": func(conf *confinement, inner *confineInner, spec runner.RunSpec) error {
			_, err := shellAdapter(conf, inner).Exec(context.Background(), spec)
			return err
		},
	}
	for name, run := range wrappers {
		t.Run(name, func(t *testing.T) {
			conf := &confinement{constrained: true, mode: fixedMode(string(mode.AutoEdits)), lookupPath: programDir(t, "sh"), tmpDir: t.TempDir(),
				projectRoot: t.TempDir(), blocked: testBlocked(t), broker: enforce.BrokerSlice}
			startedSessionProxy(t, conf)
			inner := &confineInner{err: refused}
			baseline := setupBaseline(t)
			err := run(conf, inner, runner.RunSpec{InvocationID: ids.NewV7(), Argv: []string{"sh", "-c", "true"}, Cwd: t.TempDir()})
			if !errors.Is(err, refused) || len(inner.bounded) != 1 || inner.bounded[0].Helper == nil {
				t.Fatalf("err = %v, inner saw %d specs; want the refusal of one broker-mode spec", err, len(inner.bounded))
			}
			if extra := heldSetupEnds(t, baseline); len(extra) != 0 {
				t.Errorf("codemeld still holds %v after the inner refusal", extra)
			}
			requireOwnerRetired(t, conf, inner.bounded[0].Helper)
		})
	}
}

func requireOwnerRetired(t *testing.T, conf *confinement, helper runner.HelperLaunch) {
	t.Helper()
	l := helper.(*brokerLaunch)
	if l.owner == nil || l.owner.Register(netip.MustParseAddrPort("127.0.0.1:65000")) == nil {
		t.Error("the call's proxy owner still accepts registrations after the launch ended")
	}
	if conf.proxy.running() == nil {
		t.Error("ending the call stopped the session proxy")
	}
}

func TestBrokerLaunch_OwnerCleanupIsIdempotentAndKeepsTheSessionProxy(t *testing.T) {
	conf := &confinement{broker: enforce.BrokerSlice}
	var spec runner.RunSpec
	if err := conf.attachBroker(&spec, enforce.BrokerSlice); err == nil || spec.Helper != nil {
		t.Fatalf("attachBroker without a session proxy = %v, helper %v; want a refusal", err, spec.Helper)
	}
	endpoint := startedSessionProxy(t, conf)
	server := conf.proxy.running()
	if err := conf.attachBroker(&spec, enforce.BrokerSlice); err != nil {
		t.Fatal(err)
	}
	l := spec.Helper.(*brokerLaunch)
	used, fresh := netip.MustParseAddrPort("127.0.0.1:65001"), netip.MustParseAddrPort("127.0.0.1:65002")
	if err := l.owner.Register(used); err != nil {
		t.Fatal(err)
	}
	l.Close()
	l.Close()
	requireOwnerRetired(t, conf, l)
	next := server.NewOwner(nil)
	defer next.Close()
	if err := next.Register(used); err == nil {
		t.Error("a retired call's endpoint registered a new owner")
	}
	if err := next.Register(fresh); err != nil {
		t.Errorf("fresh endpoint after the call ended: %v", err)
	}
	if conf.proxy.running() != server {
		t.Error("the session proxy changed after the call ended")
	}
	c, err := net.DialTimeout("tcp", endpoint.String(), time.Second)
	if err != nil {
		t.Fatalf("the session proxy stopped accepting after the call ended: %v", err)
	}
	_ = c.Close()
}

func TestBrokerLaunch_BothSetupEndsAreCloseOnExec(t *testing.T) {
	var spec runner.RunSpec
	if err := (&confinement{}).attachBroker(&spec, enforce.BrokerFull); err != nil {
		t.Fatal(err)
	}
	defer spec.Helper.Close()
	l := spec.Helper.(*brokerLaunch)
	for name, f := range map[string]*os.File{"codemeld end": l.own, "helper end": l.helper} {
		rc, err := f.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var flags int
		var ferr error
		if err := rc.Control(func(fd uintptr) { flags, ferr = unix.FcntlInt(fd, unix.F_GETFD, 0) }); err != nil || ferr != nil {
			t.Fatal(err, ferr)
		}
		if flags&unix.FD_CLOEXEC == 0 {
			t.Errorf("%s flags %#x, want FD_CLOEXEC", name, flags)
		}
	}
}

type proxyStarts struct {
	mu    sync.Mutex
	addrs []string
}

func (p *proxyStarts) record(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.addrs = append(p.addrs, addr)
}

func (p *proxyStarts) list() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.addrs)
}

func swapProxyStart(t *testing.T, before func() error) *proxyStarts {
	t.Helper()
	starts := &proxyStarts{}
	real := startSessionProxy
	startSessionProxy = func(allow []string) (*netproxy.Server, string, error) {
		if before != nil {
			if err := before(); err != nil {
				starts.record("")
				return nil, "", err
			}
		}
		server, addr, err := real(allow)
		starts.record(addr)
		return server, addr, err
	}
	t.Cleanup(func() { startSessionProxy = real })
	return starts
}

func requireProxyClosed(t *testing.T, addr string) {
	t.Helper()
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = c.Close()
		t.Fatalf("the session proxy at %s still accepts connections", addr)
	}
}

var conflictingProxyEnv = []string{"HTTPS_PROXY=http://inherited:1", "https_proxy=http://inherited:1", "NO_PROXY=example.com",
	"ALL_PROXY=socks5://inherited:1", "all_proxy=socks5://inherited:1"}

func requireProxyRouteEnv(t *testing.T, env []string, proxyURL string) {
	t.Helper()
	for name, want := range map[string]string{"HTTPS_PROXY": proxyURL, "HTTP_PROXY": proxyURL, "https_proxy": proxyURL, "http_proxy": proxyURL,
		"NO_PROXY": "localhost,127.0.0.1,::1", "no_proxy": "localhost,127.0.0.1,::1"} {
		if got := envNamed(env, name); !slices.Equal(got, []string{name + "=" + want}) {
			t.Errorf("%s entries = %q, want exactly %s=%s", name, got, name, want)
		}
	}
	for _, name := range []string{"ALL_PROXY", "all_proxy"} {
		if got := envNamed(env, name); len(got) != 0 {
			t.Errorf("%s entries = %q, want none", name, got)
		}
	}
}

func requireInheritedProxyEnv(t *testing.T, env []string) {
	t.Helper()
	for _, e := range conflictingProxyEnv {
		name, _, _ := strings.Cut(e, "=")
		if got := envNamed(env, name); !slices.Equal(got, []string{e}) {
			t.Errorf("%s entries = %q, want the inherited %s unchanged", name, got, e)
		}
	}
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "no_proxy"} {
		if got := envNamed(env, name); len(got) != 0 {
			t.Errorf("%s entries = %q, want none", name, got)
		}
	}
}

func proxyRouteConfinement(t *testing.T, resolution enforce.Resolution, m mode.Mode, programs ...string) (*confinement, string) {
	t.Helper()
	home, project := canonicalTempDir(t), canonicalTempDir(t)
	cache, err := config.NewCache(map[string]any{}, project, nil, home)
	if err != nil {
		t.Fatal(err)
	}
	conf := withSessionTemp(t, launchConfinement(resolution, "", mode.NewActiveState(m, mode.SourceDefault), cache, home,
		securitystate.Policy{Blocked: testBlocked(t)}, slices.Clone(conflictingProxyEnv)))
	t.Cleanup(conf.proxy.stop)
	conf.lookupPath = programDir(t, programs...)
	return conf, project
}

var slicePassed = enforce.Resolution{Capability: enforce.Constrained, SelfTestPassed: true, SliceSelfTestPassed: true}

func TestLaunchConfinement_SandboxedPlanAndAutoEditsTakeTheProxyRoute(t *testing.T) {
	filtered := slicePassed
	filtered.SliceSelfTestPassed = false
	for _, tc := range []struct {
		name       string
		m          mode.Mode
		resolution enforce.Resolution
		argv       []string
		authority  string
		proxy      bool
	}{
		{"plan", mode.Plan, slicePassed, []string{"mytool"}, "", true},
		{"plan network command", mode.Plan, slicePassed, []string{"curl", "https://example.com/"}, enforce.NetworkAccessAuthority, true},
		{"plan no-socket fallback", mode.Plan, filtered, []string{"curl", "https://example.com/"}, enforce.NetworkAccessAuthority, false},
		{"build", mode.Build, slicePassed, []string{"mytool"}, "", false},
		{"network command", mode.AutoEdits, slicePassed, []string{"curl", "https://example.com/"}, enforce.NetworkAccessAuthority, true},
		{"file deletion", mode.AutoEdits, slicePassed, []string{"rm", "x"}, "file deletion", true},
		{"no-socket fallback", mode.AutoEdits, filtered, []string{"curl", "https://example.com/"}, enforce.NetworkAccessAuthority, false},
		{"unrecognized command", mode.AutoEdits, slicePassed, []string{"mytool"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			starts := swapProxyStart(t, nil)
			conf, project := proxyRouteConfinement(t, tc.resolution, tc.m, "mytool", "curl", "rm")
			authority, _ := permissions.ExceptionalAuthority(tc.argv)
			if authority != tc.authority {
				t.Fatalf("authority = %q, want %q", authority, tc.authority)
			}
			inner := &confineInner{}
			spec := confinedSpec(project, tc.argv...)
			spec.ExceptionalAuthority = authority
			if _, err := (&confinedRunner{inner: inner, conf: conf, cap: 4096}).Exec(context.Background(), spec); err != nil {
				t.Fatal(err)
			}
			if tc.m == mode.Build {
				if len(inner.execs) != 1 || len(inner.bounded) != 0 || inner.execs[0].Helper != nil || len(inner.execs[0].Env) != 0 {
					t.Fatalf("build: inner saw %+v, want one unchanged unconfined spec", inner.execs)
				}
			} else {
				if len(inner.bounded) != 1 {
					t.Fatalf("inner saw %d confined specs", len(inner.bounded))
				}
				got := inner.bounded[0]
				policy, _ := decodeFrame(t, got.Stdin)
				if (policy.Broker == enforce.BrokerSlice) != tc.proxy || (got.Helper != nil) != tc.proxy || policy.ExceptionalAuthority != "" {
					t.Errorf("broker %q, helper channel %v, authority %q; want the proxy route %v and no authority", policy.Broker, got.Helper != nil, policy.ExceptionalAuthority, tc.proxy)
				}
				if tc.proxy {
					addrs := starts.list()
					if len(addrs) != 1 || !strings.HasPrefix(addrs[0], "127.0.0.1:") {
						t.Fatalf("proxy starts = %q, want one loopback proxy", addrs)
					}
					requireProxyRouteEnv(t, got.Env, "http://"+addrs[0])
				} else {
					requireInheritedProxyEnv(t, got.Env)
				}
			}
			if !tc.proxy && len(starts.list()) != 0 {
				t.Errorf("proxy starts = %q, want none off the proxy route", starts.list())
			}
		})
	}
}

func TestConfinedRunner_ProxyRouteRefusesCommandProxyAssignments(t *testing.T) {
	swapProxyStart(t, nil)
	for _, assignment := range []string{"HTTPS_PROXY=http://evil:1", "NO_PROXY=*", "ALL_PROXY=socks5://evil:1"} {
		conf, project := proxyRouteConfinement(t, slicePassed, mode.AutoEdits, "mytool")
		inner := &confineInner{}
		spec := confinedSpec(project, "mytool")
		spec.Assignments = []string{assignment}
		_, err := (&confinedRunner{inner: inner, conf: conf, cap: 4096}).Exec(context.Background(), spec)
		if envErr := (*runner.EnvAssignmentError)(nil); !errors.As(err, &envErr) || inner.calls() != 0 {
			t.Errorf("%s: err = %v, inner saw %d calls; want the assignment refused before launch", assignment, err, inner.calls())
		}
	}
}

func TestConfinedRunner_DispatcherCopiesShareOneSessionProxy(t *testing.T) {
	reached, gate := make(chan struct{}, 1), make(chan struct{})
	starts := swapProxyStart(t, func() error {
		reached <- struct{}{}
		<-gate
		return nil
	})
	conf, project := proxyRouteConfinement(t, slicePassed, mode.AutoEdits, "mytool")
	child := *conf
	inners := []*confineInner{{}, {}}
	done := make(chan error, 2)
	for i, c := range []*confinement{conf, &child} {
		go func() {
			_, err := (&confinedRunner{inner: inners[i], conf: c, cap: 4096}).Exec(context.Background(), confinedSpec(project, "mytool"))
			done <- err
		}()
	}
	<-reached
	time.Sleep(50 * time.Millisecond)
	close(gate)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	again := &confineInner{}
	if _, err := (&confinedRunner{inner: again, conf: &child, cap: 4096}).Exec(context.Background(), confinedSpec(project, "mytool")); err != nil {
		t.Fatal(err)
	}
	addrs := starts.list()
	if len(addrs) != 1 {
		t.Fatalf("proxy starts = %q, want exactly one for the session", addrs)
	}
	for _, inner := range append(inners, again) {
		if len(inner.bounded) != 1 || !slices.Equal(envNamed(inner.bounded[0].Env, "HTTP_PROXY"), []string{"HTTP_PROXY=http://" + addrs[0]}) {
			t.Fatalf("specs = %+v, want each run pointed at the one session proxy %s", inner.bounded, addrs[0])
		}
	}

	if err := conf.cleanupAll(); err != nil {
		t.Fatal(err)
	}
	requireProxyClosed(t, addrs[0])
	late := &confineInner{}
	if _, err := (&confinedRunner{inner: late, conf: &child, cap: 4096}).Exec(context.Background(), confinedSpec(project, "mytool")); err == nil || late.calls() != 0 {
		t.Fatalf("run after cleanup: err = %v, inner saw %d calls; want a refusal before launch", err, late.calls())
	}
	if n := len(starts.list()); n != 1 {
		t.Fatalf("proxy starts = %d after cleanup, want still 1", n)
	}
}

func TestSessionProxy_CleanupWithoutTempFoldersStopsTheRunningProxy(t *testing.T) {
	starts := swapProxyStart(t, nil)
	conf := &confinement{}
	conf.own(nil)
	if conf.owned != nil {
		t.Fatal("own(nil) created temp-folder ownership")
	}
	endpoint, err := conf.proxy.start()
	if err != nil {
		t.Fatal(err)
	}
	if again, err := conf.proxy.start(); err != nil || again != endpoint {
		t.Fatalf("second start = %v, %v; want the running %v", again, err, endpoint)
	}
	if err := conf.cleanupAll(); err != nil {
		t.Fatal(err)
	}
	requireProxyClosed(t, endpoint.String())
	if _, err := conf.proxy.start(); !errors.Is(err, errSessionProxyStopped) || len(starts.list()) != 1 {
		t.Fatalf("start after cleanup = %v with %d starts; want the stopped refusal and no new start", err, len(starts.list()))
	}
}

func TestSessionProxy_CleanupRacingABlockedFirstStartJoinsIt(t *testing.T) {
	for _, first := range []string{"parent", "child copy"} {
		t.Run(first, func(t *testing.T) {
			reached, gate := make(chan struct{}, 1), make(chan struct{})
			starts := swapProxyStart(t, func() error {
				reached <- struct{}{}
				<-gate
				return nil
			})
			conf := &confinement{}
			conf.own(nil)
			child := *conf
			starter, waiter := conf, &child
			if first == "child copy" {
				starter, waiter = waiter, starter
			}
			results := make(chan error, 2)
			start := func(c *confinement) {
				_, err := c.proxy.start()
				results <- err
			}
			go start(starter)
			<-reached
			go start(waiter)
			cleaned := make(chan error, 1)
			go func() { cleaned <- conf.cleanupAll() }()
			select {
			case err := <-cleaned:
				t.Fatalf("cleanup returned %v while the first start was still running", err)
			case <-time.After(50 * time.Millisecond):
			}
			close(gate)
			if err := <-cleaned; err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := <-results; !errors.Is(err, errSessionProxyStopped) {
					t.Errorf("start racing cleanup = %v, want the stopped refusal", err)
				}
			}
			addrs := starts.list()
			if len(addrs) != 1 {
				t.Fatalf("proxy starts = %q, want one", addrs)
			}
			requireProxyClosed(t, addrs[0])
			if conf.decide(netip.MustParseAddrPort(addrs[0])) {
				t.Error("the decider admits the stopped proxy's endpoint")
			}
			if _, err := child.proxy.start(); !errors.Is(err, errSessionProxyStopped) || len(starts.list()) != 1 {
				t.Errorf("start after cleanup = %v with %d starts; want the stopped refusal and no new start", err, len(starts.list()))
			}
		})
	}
}

func TestSessionProxy_CleanupRefusesHelperStartupThatRacesIt(t *testing.T) {
	conf := &confinement{}
	startedSessionProxy(t, conf)
	var spec runner.RunSpec
	if err := conf.attachBroker(&spec, enforce.BrokerSlice); err != nil {
		t.Fatal(err)
	}
	defer spec.Helper.Close()
	conf.proxy.stop()
	if err := spec.Helper.Started(); !errors.Is(err, errSessionProxyStopped) {
		t.Errorf("helper startup after cleanup = %v, want the stopped refusal", err)
	}
	var later runner.RunSpec
	if err := conf.attachBroker(&later, enforce.BrokerFull); !errors.Is(err, errSessionProxyStopped) || later.Helper != nil {
		t.Errorf("broker launch after cleanup = %v, helper %v; want the stopped refusal", err, later.Helper)
	}
}

func TestSessionProxy_CleanupHoldsTheListenerUntilAnAdmittedConnectEndsThroughTheRealHelper(t *testing.T) {
	conf, project, _, bin := unstartedBrokerConfinement(t)
	endpoint := startedSessionProxy(t, conf)
	admitted, resume := make(chan struct{}), make(chan struct{})
	resumeOnce := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(resumeOnce)
	admits, pause := conf.decide, sync.OnceFunc(func() { close(admitted); <-resume })
	conf.decide = func(dest netip.AddrPort) bool {
		ok := admits(dest)
		if ok {
			pause()
		}
		return ok
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ran := make(chan struct{})
	go func() {
		defer close(ran)
		_, _ = (&confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 4096}).Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(),
			Argv: []string{os.Args[0], "-test.run=^TestConfinedConnectChild$", "--", endpoint.String()}, Cwd: project})
	}()
	select {
	case <-admitted:
	case <-ctx.Done():
		t.Fatal("the child's connect to the proxy endpoint was never admitted")
	}
	cleaned := make(chan struct{})
	go func() {
		defer close(cleaned)
		_ = conf.cleanupAll()
	}()
	for admits(endpoint) {
		time.Sleep(5 * time.Millisecond)
	}
	if ln, err := net.Listen("tcp4", endpoint.String()); err == nil {
		_ = ln.Close()
		t.Fatal("the proxy endpoint could be rebound while an admitted connect was still pending")
	}
	select {
	case <-cleaned:
		t.Fatal("cleanup returned while an admitted connect was still pending")
	default:
	}
	resumeOnce()
	select {
	case <-cleaned:
	case <-ctx.Done():
		t.Fatal("cleanup never returned after the admitted connect ended")
	}
	requireProxyClosed(t, endpoint.String())
	<-ran
}

func TestConfinedRunner_ProxyStartFailureLaunchesNothing(t *testing.T) {
	refused := errors.New("proxy refused")
	starts := swapProxyStart(t, func() error { return refused })
	conf, project := proxyRouteConfinement(t, slicePassed, mode.AutoEdits, "mytool")
	for range 2 {
		inner := &confineInner{}
		if _, err := (&confinedRunner{inner: inner, conf: conf, cap: 4096}).Exec(context.Background(), confinedSpec(project, "mytool")); !errors.Is(err, refused) || inner.calls() != 0 {
			t.Fatalf("err = %v, inner saw %d calls; want the proxy failure and no launch", err, inner.calls())
		}
	}
	if n := len(starts.list()); n != 1 {
		t.Errorf("proxy starts = %d, want the one failed start shared by later runs", n)
	}
}

func TestConfinedConnectChild(t *testing.T) {
	i := slices.Index(os.Args, "--")
	if i < 0 || i+1 >= len(os.Args) {
		t.Skip("runs only as a confined child")
	}
	switch os.Args[i+1] {
	case "env":
		for _, e := range os.Environ() {
			fmt.Println(e)
		}
		return
	case "hold":
		holdProxyConnection(os.Args[i+2], os.Args[i+3], os.Args[i+4], os.Args[i+5])
		return
	case "short":
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if err != nil {
			fmt.Printf("socket %d\n", err)
			return
		}
		defer func() { _ = unix.Close(fd) }()
		addr := [3]byte{}
		_, _, e := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&addr[0])), uintptr(len(addr)))
		fmt.Printf("connect %d\n", e)
		return
	case "unix":
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			fmt.Printf("socket %d\n", err)
			return
		}
		_ = unix.Close(fd)
		fmt.Println("socket created")
		return
	case "get":
		host := "example.com"
		if len(os.Args) > i+2 {
			host = os.Args[i+2]
		}
		resp, err := http.Get("http://" + host + "/")
		if err != nil {
			fmt.Printf("get %v\n", err)
			return
		}
		_ = resp.Body.Close()
		fmt.Printf("status %d refused %q\n", resp.StatusCode, resp.Header.Get("X-Proxy-Refused"))
		return
	}
	dest := netip.MustParseAddrPort(os.Args[i+1])
	family := unix.AF_INET
	if dest.Addr().Is4In6() {
		family = unix.AF_INET6
	}
	fd, err := unix.Socket(family, unix.SOCK_STREAM, 0)
	if err != nil {
		fmt.Printf("socket %d\n", err)
		return
	}
	defer func() { _ = unix.Close(fd) }()
	var sa unix.Sockaddr = &unix.SockaddrInet4{Port: int(dest.Port()), Addr: dest.Addr().As4()}
	if family == unix.AF_INET6 {
		sa = &unix.SockaddrInet6{Port: int(dest.Port()), Addr: dest.Addr().As16()}
	}
	if err := unix.Connect(fd, sa); err != nil {
		fmt.Printf("connect %d\n", err)
		return
	}
	fmt.Println("connected")
}

func holdProxyConnection(marker, gate, result, target string) {
	report := func(msg string) {
		_ = os.WriteFile(result+".tmp", []byte(msg), 0o600)
		_ = os.Rename(result+".tmp", result)
	}
	c, err := net.Dial("tcp", strings.TrimPrefix(os.Getenv("HTTP_PROXY"), "http://"))
	if err != nil {
		report("dial " + err.Error())
		return
	}
	defer func() { _ = c.Close() }()
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		report("marker " + err.Error())
		return
	}
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(gate); err == nil {
			break
		}
	}
	_, werr := fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, rerr := bufio.NewReader(c).ReadString('\n')
	report(fmt.Sprintf("write %v read %q err %v", werr, line, rerr))
}

func waitForFile(t *testing.T, ctx context.Context, path string) []byte {
	t.Helper()
	for ctx.Err() == nil {
		if b, err := os.ReadFile(path); err == nil {
			return b
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", path)
	return nil
}

func TestConfinedRunner_ProxyConnectionsEndWithTheirCommandThroughTheRealHelper(t *testing.T) {
	conf, project, writable, bin := brokerConfinement(t)
	server := conf.proxy.running()
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	var dialed atomic.Int32
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			dialed.Add(1)
			_ = c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const script = `"$0" -test.run='^TestConfinedConnectChild$' -- hold "$1" "$2" "$3" "$4" </dev/null >/dev/null 2>&1 &
while [ ! -e "$5" ]; do sleep 0.05; done`
	file := func(name string) string { return filepath.Join(writable, name) }
	run := func(c *confinement, n, until string) (runner.RunResult, error) {
		return (&confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: c, cap: 4096}).Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(),
			Argv: []string{"sh", "-c", script, os.Args[0], file("connected" + n), file("gate" + n), file("result" + n), upstream.Addr().String(), until},
			Cwd:  project})
	}

	child := *conf
	overlapping := make(chan error, 1)
	go func() {
		res, err := run(&child, "2", file("finish2"))
		if err == nil && res.ExitCode != 0 {
			err = fmt.Errorf("exit %d stderr %q", res.ExitCode, res.Stderr)
		}
		overlapping <- err
	}()
	waitForFile(t, ctx, file("connected2"))
	if res, err := run(conf, "1", file("connected1")); err != nil || res.ExitCode != 0 {
		t.Fatalf("background-child call: %v, exit %d stderr %q", err, res.ExitCode, res.Stderr)
	}
	for _, n := range []string{"1", "2"} {
		if err := os.WriteFile(file("gate"+n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := string(waitForFile(t, ctx, file("result1"))); !strings.Contains(got, `read ""`) || strings.Contains(got, "timeout") {
		t.Errorf("background child after its call ended: %s; want its proxy connection closed unanswered", got)
	}
	if got := string(waitForFile(t, ctx, file("result2"))); !strings.Contains(got, `read "HTTP/1.1 403 `) {
		t.Errorf("overlapping call's child: %s; want its connection still served", got)
	}
	if r := server.Refusals(); len(r) != 1 {
		t.Errorf("refusals %+v, want only the overlapping call's request parsed", r)
	}
	if err := os.WriteFile(file("finish2"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-overlapping; err != nil {
		t.Fatalf("overlapping call: %v", err)
	}

	res, err := (&confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 1 << 16}).Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(),
		Argv: []string{os.Args[0], "-test.run=^TestConfinedConnectChild$", "--", "get"}, Cwd: project})
	if err != nil || !strings.HasPrefix(string(res.Stdout), "status 403 ") {
		t.Fatalf("later call: %v, stdout %q stderr %q; want a request served by the same session proxy", err, res.Stdout, res.Stderr)
	}
	if r := server.Refusals(); len(r) != 2 || conf.proxy.running() != server {
		t.Errorf("refusals %+v; want the later call's request handled by the same session proxy", r)
	}
	if n := dialed.Load(); n != 0 {
		t.Errorf("the fixture upstream was dialed %d times", n)
	}
}

func TestConfinedRunner_ProxyAskerFromTheConfinementThroughTheRealHelper(t *testing.T) {
	conf, project, writable, bin := unstartedBrokerConfinement(t)
	file := func(name string) string { return filepath.Join(writable, name) }
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var mu sync.Mutex
	var asked []string
	conf.proxyAsker = func(askCtx context.Context, host, port string, _ func() bool, _ func(netproxy.Decision) bool) (netproxy.Decision, error) {
		mu.Lock()
		asked = append(asked, net.JoinHostPort(host, port))
		first := len(asked) == 1
		mu.Unlock()
		if !first {
			return netproxy.DecisionDeny, nil
		}
		if err := os.WriteFile(file("asked"), nil, 0o600); err != nil {
			return netproxy.DecisionDeny, err
		}
		select {
		case <-askCtx.Done():
		case <-ctx.Done():
		}
		return netproxy.DecisionSession, nil
	}
	if err := os.WriteFile(file("gate"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const script = `"$0" -test.run='^TestConfinedConnectChild$' -- hold "$1" "$2" "$3" "$4" </dev/null >/dev/null 2>&1 &
while [ ! -e "$5" ]; do sleep 0.05; done`
	res, err := (&confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 4096}).Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(),
		Argv: []string{"sh", "-c", script, os.Args[0], file("connected"), file("gate"), file("result"), "example.com", file("asked")},
		Cwd:  project})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("call that ends while asked: %v, exit %d stderr %q", err, res.ExitCode, res.Stderr)
	}
	if got := string(waitForFile(t, ctx, file("result"))); strings.Contains(got, "timeout") {
		t.Errorf("background child after its call ended: %s; want its proxy connection closed", got)
	}
	server := conf.proxy.running()
	if r := server.Refusals(); len(r) != 1 || r[0] != (netproxy.Refusal{Host: "example.com", Port: "80", Reason: "not approved (command ended)"}) {
		t.Fatalf("refusals %+v, want the ended call's request refused not approved (command ended)", r)
	}

	res, err = (&confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 1 << 16}).Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(),
		Argv: []string{os.Args[0], "-test.run=^TestConfinedConnectChild$", "--", "get"}, Cwd: project})
	if err != nil || firstLine(string(res.Stdout)) != `status 403 refused "not approved (denied)"` {
		t.Fatalf("later call: %v, stdout %q stderr %q; want the confinement's asker asked again and denying", err, res.Stdout, res.Stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(asked, []string{"example.com:80", "example.com:80"}) {
		t.Fatalf("asked %q; want the ended call's late answer to store no approval", asked)
	}
}

func TestConfinedRunner_ProxyRouteRefusalsStayWithTheirCallThroughTheRealHelper(t *testing.T) {
	conf, project, writable, bin := brokerConfinement(t)
	file := func(name string) string { return filepath.Join(writable, name) }
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	other, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	otherPort := strconv.Itoa(other.Addr().(*net.TCPAddr).Port)
	const script = `for step in "$@"; do
case "$step" in
wait:*) : > "${step#wait:}.ready"; while [ ! -e "${step#wait:}" ]; do sleep 0.05; done ;;
*) "$0" -test.run='^TestConfinedConnectChild$' -- $step >/dev/null ;;
esac
done`
	run := func(c *confinement, steps ...string) []netproxy.Refusal {
		forward := &helperForwardingRunner{bin: bin}
		res, err := (&confinedRunner{inner: forward, conf: c, cap: 1 << 16}).Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(),
			Argv: append([]string{"sh", "-c", script, os.Args[0]}, steps...), Cwd: project})
		if err != nil || res.ExitCode != 0 {
			t.Errorf("call %q: %v, exit %d stderr %q", steps, err, res.ExitCode, res.Stderr)
			return nil
		}
		forward.mu.Lock()
		helper := forward.specs[0].Helper
		forward.mu.Unlock()
		h, ok := helper.(interface{ refusals() []netproxy.Refusal })
		if !ok {
			t.Errorf("call %q: helper %T has no refusal accessor", steps, helper)
			return nil
		}
		got := h.refusals()
		if len(got) > 0 {
			h.refusals()[0].Host = "changed"
		}
		helper.Close()
		if again := h.refusals(); !slices.Equal(again, got) {
			t.Errorf("call %q: a repeated read after a second Close returned %+v, first %+v", steps, again, got)
		}
		return got
	}
	noOne := func(host string) netproxy.Refusal {
		return netproxy.Refusal{Host: host, Port: "80", Reason: "not approved (no one to ask)"}
	}
	direct := func(host string) netproxy.Refusal {
		return netproxy.Refusal{Host: host, Port: otherPort, Reason: "direct connection not allowed (use the proxy)"}
	}
	notTCP := netproxy.Refusal{Reason: "not a TCP connect"}
	check := func(what string, got, want []netproxy.Refusal) {
		t.Helper()
		if !slices.Equal(got, want) {
			t.Errorf("%s refusals:\n got %+v\nwant %+v", what, got, want)
		}
	}

	check("first sequential call", run(conf, "get a.test", "127.0.0.1:"+otherPort, "short"),
		[]netproxy.Refusal{noOne("a.test"), direct("127.0.0.1"), notTCP})
	check("second sequential call", run(conf, "get b.test", "1.1.1.1:"+otherPort),
		[]netproxy.Refusal{noOne("b.test"), direct("1.1.1.1")})

	child := *conf
	overlapping := make(chan []netproxy.Refusal, 1)
	go func() {
		overlapping <- run(&child, "get c.test", "127.0.0.1:"+otherPort, "wait:"+file("gate"), "get c2.test")
	}()
	waitForFile(t, ctx, file("gate.ready"))
	check("call inside the overlap", run(conf, "get d.test", "1.1.1.1:"+otherPort),
		[]netproxy.Refusal{noOne("d.test"), direct("1.1.1.1")})
	if err := os.WriteFile(file("gate"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	check("overlapping call", <-overlapping,
		[]netproxy.Refusal{noOne("c.test"), noOne("c2.test"), direct("127.0.0.1")})
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func TestConfinedRunner_SliceResultStaysWithItsSessionThroughTheRealHelper(t *testing.T) {
	home, project, bin := realConfinementHost(t)
	resolution := resolveExecutionCapability(enforce.ResolveInput{Home: home})
	if !resolution.SliceSelfTestPassed {
		t.Skip("unverified: the slice self-test did not pass on this host")
	}
	starts := swapProxyStart(t, nil)
	base := filepath.Dir(project)
	sliced := liveRealHelperConfinement(t, home, project, filepath.Join(base, "tmp-sliced"), writableFoldersYAML())
	failed := resolution
	failed.SliceSelfTestPassed = false
	swapResolveExecutionCapability(t, failed)
	filtered := liveRealHelperConfinement(t, home, project, filepath.Join(base, "tmp-filtered"), writableFoldersYAML())
	for _, conf := range []*confinement{sliced, filtered} {
		if err := os.MkdirAll(conf.tmpDir, 0o700); err != nil {
			t.Fatal(err)
		}
		conf.inherited = slices.Clone(conflictingProxyEnv)
	}

	other, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := other.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	run := func(conf *confinement, arg string) (string, runner.RunSpec) {
		t.Helper()
		forward := &helperForwardingRunner{bin: bin}
		res, err := (&confinedRunner{inner: forward, conf: conf, cap: 1 << 16}).Exec(ctx, runner.RunSpec{InvocationID: ids.NewV7(),
			Argv: []string{os.Args[0], "-test.run=^TestConfinedConnectChild$", "--", arg}, Cwd: project})
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("confined child %s: %v, exit %d stderr %q", arg, err, res.ExitCode, res.Stderr)
		}
		spec := forward.specs[0]
		if (spec.Helper != nil) != (conf == sliced) || spec.Argv[1] != enforce.HelperCommand {
			t.Errorf("sliced %v: helper channel %v, argv %q", conf == sliced, spec.Helper != nil, spec.Argv)
		}
		return string(res.Stdout), spec
	}

	out, _ := run(sliced, "env")
	env := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	proxyURL, _ := strings.CutPrefix(slices.Concat(envNamed(env, "HTTP_PROXY"), []string{""})[0], "HTTP_PROXY=")
	port, ok := strings.CutPrefix(proxyURL, "http://127.0.0.1:")
	if _, err := strconv.ParseUint(port, 10, 16); !ok || err != nil {
		t.Fatalf("HTTP_PROXY = %q, want http://127.0.0.1:<port>", proxyURL)
	}
	requireProxyRouteEnv(t, env, proxyURL)
	out, _ = run(filtered, "env")
	requireInheritedProxyEnv(t, strings.Split(strings.TrimSuffix(out, "\n"), "\n"))

	connected, refused := "connected", fmt.Sprintf("connect %d", syscall.EPERM)
	for _, tc := range []struct {
		conf *confinement
		dest string
		want string
	}{
		{sliced, "127.0.0.1:" + port, connected},
		{sliced, "[::ffff:127.0.0.1]:" + port, connected},
		{sliced, other.Addr().String(), refused},
		{sliced, "1.1.1.1:" + port, refused},
		{filtered, "127.0.0.1:" + port, fmt.Sprintf("socket %d", syscall.EPERM)},
		{filtered, other.Addr().String(), fmt.Sprintf("socket %d", syscall.EPERM)},
	} {
		if got, _ := run(tc.conf, tc.dest); firstLine(got) != tc.want {
			t.Errorf("sliced %v to %s: child printed %q, want first line %q", tc.conf == sliced, tc.dest, got, tc.want)
		}
	}
	if got, _ := run(sliced, "get"); firstLine(got) != `status 403 refused "not approved (no one to ask)"` {
		t.Errorf("request through the session proxy printed %q, want a 403 no-one-to-ask refusal", got)
	}
	if n := accepted.Load(); n != 0 {
		t.Errorf("the other loopback listener accepted %d connections from confined children", n)
	}
	if addrs := starts.list(); len(addrs) != 1 || addrs[0] != "127.0.0.1:"+port {
		t.Errorf("proxy starts = %q, want the one session proxy at 127.0.0.1:%s", addrs, port)
	}
}

func TestConfinedRunner_ProxyRouteFailureNoteNamesItsRefusalsThroughTheRealHelper(t *testing.T) {
	conf, project, writable, bin := brokerConfinement(t)
	server := conf.proxy.running()
	file := func(name string) string { return filepath.Join(writable, name) }
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	other, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	otherAddr := other.Addr().String()
	const script = `for step in "$@"; do
case "$step" in
wait:*) : > "${step#wait:}.ready"; while [ ! -e "${step#wait:}" ]; do sleep 0.05; done ;;
quiet:*) "$0" -test.run='^TestConfinedConnectChild$' -- ${step#quiet:} >/dev/null 2>&1 ;;
*) "$0" -test.run='^TestConfinedConnectChild$' -- $step ;;
esac
done
exit 1`
	spec := func(steps ...string) runner.RunSpec {
		return runner.RunSpec{InvocationID: ids.NewV7(), Argv: append([]string{"sh", "-c", script, os.Args[0]}, steps...), Cwd: project}
	}
	run := func(c *confinement, steps ...string) runner.RunResult {
		res, err := (&confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: c, cap: 1 << 16}).Exec(ctx, spec(steps...))
		if err != nil || res.ExitCode != 1 {
			t.Errorf("call %q: %v, exit %d stderr %q", steps, err, res.ExitCode, res.Stderr)
		}
		return res
	}
	noOne := func(host string) string { return refusedLine(host+":80", "not approved (no one to ask)") }
	note := func(lines ...string) string { return strings.Join(lines, "\n") + "\n" + confinedFailureNote }
	check := func(what string, res runner.RunResult, want string) {
		t.Helper()
		if string(res.Stderr) != want {
			t.Errorf("%s stderr:\n got %q\nwant %q", what, res.Stderr, want)
		}
	}

	first := run(conf, "quiet:get a.test", otherAddr)
	check("first call", first, note(noOne("a.test"), refusedLine(otherAddr, "direct connection not allowed (use the proxy)")))
	if want := fmt.Sprintf("connect %d", syscall.EPERM); firstLine(string(first.Stdout)) != want {
		t.Errorf("first call stdout = %q, want the direct connect refused %q", first.Stdout, want)
	}
	check("sequential call after a refusal", run(conf, "quiet:get b.test"), note(noOne("b.test")))

	child := *conf
	overlapping := make(chan runner.RunResult, 1)
	go func() { overlapping <- run(&child, "quiet:get c.test", "wait:"+file("gate")) }()
	waitForFile(t, ctx, file("gate.ready"))
	check("call inside the overlap", run(conf, "quiet:get d.test"), note(noOne("d.test")))
	if err := os.WriteFile(file("gate"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	check("overlapping call", <-overlapping, note(noOne("c.test")))

	store := mkStore(t)
	shell := &shellEventRunner{inner: &helperForwardingRunner{bin: bin}, active: func() *sessions.Store { return store }, cap: 1 << 16}
	res, err := execNoted(&confinedShellRunner{events: shell, conf: conf}, spec("quiet:get e.test"))
	if err != nil {
		t.Fatal(err)
	}
	check("shell call in a session", res, note(noOne("e.test")))
	if ends := decodeStoreEvents[events.ToolExecEnd](t, reloadStore(t, store), events.KindToolExecEnd); len(ends) != 1 || ends[0].Stderr != string(res.Stderr) {
		t.Errorf("tool_exec_end = %+v, want the returned stderr %q", ends, res.Stderr)
	}
	if conf.proxy.running() != server {
		t.Error("the session proxy changed; want the one proxy kept across every call")
	}
}

func TestConfinedRunner_SandboxedNetworkCommandTakesTheProxyRouteThroughTheRealHelper(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T) (*confinement, string, string){
		"auto_edits": func(t *testing.T) (*confinement, string, string) {
			conf, project, _, bin := brokerConfinement(t)
			return conf, project, bin
		},
		"plan": func(t *testing.T) (*confinement, string, string) {
			home, project, bin := realConfinementHost(t)
			cache, err := config.NewCache(map[string]any{"confinement": map[string]any{"program_lookup": "strict"}}, project, nil)
			if err != nil {
				t.Fatal(err)
			}
			confined, _ := planRealHelperRunner(t, home, project, bin, cache)
			confined.conf.broker = enforce.BrokerSlice
			startedSessionProxy(t, confined.conf)
			return confined.conf, project, bin
		},
	} {
		t.Run(name, func(t *testing.T) {
			conf, project, bin := setup(t)
			other, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = other.Close() }()
			otherAddr := other.Addr().String()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			run := func(arg string, cap int) runner.RunResult {
				t.Helper()
				spec := runner.RunSpec{InvocationID: ids.NewV7(), Cwd: project, ExceptionalAuthority: enforce.NetworkAccessAuthority,
					Argv: []string{"sh", "-c", `"$0" -test.run='^TestConfinedConnectChild$' -- "$1"; exit 1`, os.Args[0], arg}}
				res, err := (&confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: cap}).Exec(ctx, spec)
				if err != nil || res.ExitCode != 1 {
					t.Fatalf("child %s: %v, exit %d stderr %q", arg, err, res.ExitCode, res.Stderr)
				}
				return res
			}
			eperm := func(call string) string { return fmt.Sprintf("%s %d", call, syscall.EPERM) }

			direct := run(otherAddr, 4096)
			if firstLine(string(direct.Stdout)) != eperm("connect") {
				t.Errorf("direct connect stdout = %q, want %q", direct.Stdout, eperm("connect"))
			}
			if want := refusedLine(otherAddr, "direct connection not allowed (use the proxy)") + "\n" + confinedFailureNote; string(direct.Stderr) != want {
				t.Errorf("direct connect stderr:\n got %q\nwant %q", direct.Stderr, want)
			}

			fits := len("\n"+confinedFailureNote) + len(wantProxyRouteNote) + 1
			for cap, want := range map[int]string{fits: wantProxyRouteNote + "\n" + confinedFailureNote, fits - 1: confinedFailureNote} {
				res := run("unix", cap)
				if firstLine(string(res.Stdout)) != eperm("socket") {
					t.Errorf("cap %d: unix socket stdout = %q, want %q", cap, res.Stdout, eperm("socket"))
				}
				if string(res.Stderr) != want {
					t.Errorf("cap %d: unix socket stderr:\n got %q\nwant %q", cap, res.Stderr, want)
				}
			}
		})
	}
}

func TestLaunchConfinement_OnlyTheProxyRouteAddsRefusalLines(t *testing.T) {
	filtered := slicePassed
	filtered.SliceSelfTestPassed = false
	record := []netproxy.Refusal{{Host: "a.test", Port: "80", Reason: "not approved (no one to ask)"}}
	generic := "boom\n" + confinedFailureNote
	refused := "boom\n" + refusedLine("a.test:80", "not approved (no one to ask)") + "\n" + confinedFailureNote
	for _, tc := range []struct {
		name       string
		m          mode.Mode
		resolution enforce.Resolution
		argv       []string
		want       string
	}{
		{"plan", mode.Plan, slicePassed, []string{"mytool"}, refused},
		{"build", mode.Build, slicePassed, []string{"mytool"}, "boom"},
		{"network command", mode.AutoEdits, slicePassed, []string{"curl", "https://example.com/"}, refused},
		{"no-socket fallback", mode.AutoEdits, filtered, []string{"mytool"}, generic},
		{"proxy route", mode.AutoEdits, slicePassed, []string{"mytool"}, refused},
	} {
		authority, _ := permissions.ExceptionalAuthority(tc.argv)
		adapters := map[string]func(*confinement, runner.RunSpec) (runner.RunResult, error){
			"vcs": func(c *confinement, spec runner.RunSpec) (runner.RunResult, error) {
				return (&confinedRunner{inner: &confineInner{exitCode: 1, stderr: []byte("boom")}, conf: c, cap: 4096}).Exec(context.Background(), spec)
			},
			"bash": func(c *confinement, spec runner.RunSpec) (runner.RunResult, error) {
				return execNoted(&confinedShellRunner{events: &shellEventRunner{inner: &confineInner{exitCode: 1, stderr: []byte("boom")}, cap: 4096}, conf: c}, spec)
			},
		}
		for name, exec := range adapters {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				swapProxyStart(t, nil)
				reads := swapInvocationRefusals(t, record)
				conf, project := proxyRouteConfinement(t, tc.resolution, tc.m, "mytool", "curl")
				spec := confinedSpec(project, tc.argv...)
				spec.ExceptionalAuthority = authority
				res, err := exec(conf, spec)
				if err != nil {
					t.Fatal(err)
				}
				if string(res.Stderr) != tc.want {
					t.Fatalf("stderr = %q, want %q", res.Stderr, tc.want)
				}
				if wantReads := map[bool]int{true: 1}[tc.want == refused]; reads.count() != wantReads {
					t.Fatalf("refusals read %d times, want %d", reads.count(), wantReads)
				}
			})
		}
	}
}
