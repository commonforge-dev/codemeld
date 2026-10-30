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
	private, err := newSessionTempDir()
	if err != nil {
		t.Fatal(err)
	}
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

	for _, dir := range []string{private, inShared} {
		if res := run(t, swap, dir, outside); res.ExitCode != 0 {
			t.Fatalf("swap %s for a symlink: exit %d stderr %q, want 0", dir, res.ExitCode, res.Stderr)
		}
		res := run(t, write, dir)
		if got := outsideNames(); res.ExitCode == 0 || !slices.Equal(got, []string{"keep"}) {
			t.Fatalf("write through the swapped %s: exit %d stderr %q, outside holds %q; want a failure leaving it unchanged", dir, res.ExitCode, res.Stderr, got)
		}
	}
	if b, err := os.ReadFile(filepath.Join(outside, "keep")); err != nil || string(b) != "outside" {
		t.Fatalf("outside/keep = %q, %v; want it unchanged", b, err)
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

	for _, tc := range []struct {
		mode   mode.Mode
		tmpDir string
	}{{mode.Plan, ""}, {mode.AutoEdits, tmpDir}} {
		t.Run(string(tc.mode), func(t *testing.T) {
			conf := launchConfinement(resolveExecutionCapability(enforce.ResolveInput{Home: home}), tc.tmpDir,
				mode.NewActiveState(tc.mode, mode.SourceDefault), cache, home, securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, nil)}, nil)
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
