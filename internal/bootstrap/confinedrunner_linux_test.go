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
	"strings"
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
		securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, nil)})
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
