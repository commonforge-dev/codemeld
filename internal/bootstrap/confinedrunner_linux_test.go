//go:build linux && (amd64 || arm64)

package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/securitystate"
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
	conf := launchConfinement(resolution, tmpDir, mode.NewActiveState(mode.AutoEdits, mode.SourceDefault), cache, home,
		securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, nil)}, nil)
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
	return launchConfinement(resolution, tmpDir, mode.NewActiveState(mode.AutoEdits, mode.SourceDefault), cache, home,
		securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, nil)}, nil)
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
	conf := launchConfinement(resolveExecutionCapability(enforce.ResolveInput{Home: home}), tmpDir,
		mode.NewActiveState(mode.AutoEdits, mode.SourceDefault), cache, home, securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, entries)}, nil)
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

const planTempReplacedNote = "codemeld: the session's private temp folder was moved or replaced since codemeld created it; " +
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
			p, err := conf.policy(conf.mode(), conf.tmpDir, "", conf.blocked.Current(), false)
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
