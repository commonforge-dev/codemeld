// Tests for the read-only `codemeld config check` command.
package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/bootstrap"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/trust"
)

func stubConfigEnv(t *testing.T, home, cwd string) {
	t.Helper()
	prevHome, prevGetwd := resolveHome, osGetwd
	resolveHome = func() (string, error) { return home, nil }
	osGetwd = func() (string, error) { return cwd, nil }
	t.Cleanup(func() { resolveHome, osGetwd = prevHome, prevGetwd })
}

func writeProjectSettings(t *testing.T, root, body string) string {
	t.Helper()
	dir := filepath.Join(root, ".codemeld")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	path := filepath.Join(dir, "settings.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write project settings: %v", err)
	}
	return path
}

func canonicalDir(t *testing.T, dir string) string {
	t.Helper()
	root, err := sessions.CanonicalizeFolder(dir)
	if err != nil {
		t.Fatalf("canonicalize %s: %v", dir, err)
	}
	return root
}

func trustProject(t *testing.T, home, root string) {
	t.Helper()
	if err := trust.Record(home, root); err != nil {
		t.Fatalf("record trust: %v", err)
	}
}

func runConfig(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), append([]string{"codemeld"}, args...), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func mustContain(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func mustNotContain(t *testing.T, out string, unwants ...string) {
	t.Helper()
	for _, unwant := range unwants {
		if strings.Contains(out, unwant) {
			t.Fatalf("output unexpectedly contains %q:\n%s", unwant, out)
		}
	}
}

func TestConfigCheck_NoArgumentReportsBothLaunchLayers(t *testing.T) {
	t.Run("no project settings file is not a failure", func(t *testing.T) {
		home, project := t.TempDir(), t.TempDir()
		writeGlobalSettings(t, home, "agent:\n  max_concurrency: 2\n")
		stubConfigEnv(t, home, project)

		code, stdout, stderr := runConfig(t, "config", "check")
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr)
		}
		mustContain(t, stdout,
			bootstrap.SettingsPath(home)+" (global layer rules): ok",
			filepath.Join(canonicalDir(t, project), ".codemeld", "settings.yaml")+" (project layer rules): not present",
		)
	})

	t.Run("a trusted project settings file is validated", func(t *testing.T) {
		home, project := t.TempDir(), t.TempDir()
		writeGlobalSettings(t, home, "agent:\n  max_concurrency: 2\n")
		marker := writeProjectSettings(t, project, "mode:\n  default: plan\n")
		trustProject(t, home, project)
		stubConfigEnv(t, home, project)

		code, stdout, stderr := runConfig(t, "config", "check")
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr)
		}
		mustContain(t, stdout, bootstrap.SettingsPath(home)+" (global layer rules): ok")
		mustContain(t, stdout, canonicalMarker(t, marker)+" (project layer rules): ok")
	})
}

// canonicalMarker renders the project marker path the way discovery reports it, so an
// assertion survives a temporary directory that lives behind a symlink.
func canonicalMarker(t *testing.T, marker string) string {
	t.Helper()
	return filepath.Join(canonicalDir(t, filepath.Dir(filepath.Dir(marker))), ".codemeld", "settings.yaml")
}

func TestConfigCheck_AbsentGlobalSettingsIsReportedNotGenerated(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	stubConfigEnv(t, home, project)

	code, stdout, stderr := runConfig(t, "config", "check")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr)
	}
	mustContain(t, stdout, bootstrap.SettingsPath(home)+" (global layer rules): not present")
	if _, err := os.Stat(bootstrap.SettingsPath(home)); !os.IsNotExist(err) {
		t.Fatalf("global settings stat err = %v, want the file to still be absent", err)
	}
}

func TestConfigCheck_HonorsTheProjectRootDiscoveryBoundary(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	writeGlobalSettings(t, home, "discovery:\n  boundary: project-root\n")
	marker := writeProjectSettings(t, project, "mode:\n  default: plan\n")
	nested := filepath.Join(project, "a", "b")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	stubConfigEnv(t, home, nested)

	code, stdout, stderr := runConfig(t, "config", "check")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr)
	}
	mustContain(t, stdout, canonicalMarker(t, marker)+" (project layer rules): present, not approved")
}

func TestConfigCheck_PathArgumentChecksOnlyThatFile(t *testing.T) {
	home, project, other := t.TempDir(), t.TempDir(), t.TempDir()
	writeGlobalSettings(t, home, "agent:\n  max_concurrency: 2\n")
	// A broken layer in the working directory proves no project discovery ran.
	writeProjectSettings(t, project, "mode:\n  default: plan\nmode:\n  default: build\n")
	named := writeProjectSettings(t, other, "mode:\n  default: build\n")
	stubConfigEnv(t, home, project)

	t.Run("a project-shaped path applies the project layer's rules", func(t *testing.T) {
		code, stdout, stderr := runConfig(t, "config", "check", named)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr)
		}
		if got := strings.Count(strings.TrimSpace(stdout), "\n"); got != 0 {
			t.Fatalf("stdout has %d extra lines, want exactly one layer line:\n%s", got, stdout)
		}
		mustContain(t, stdout, named+" (project layer rules): ok")
		mustNotContain(t, stdout, project)
	})

	t.Run("the global settings path applies the global layer's rules", func(t *testing.T) {
		code, stdout, stderr := runConfig(t, "config", "check", bootstrap.SettingsPath(home))
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr)
		}
		mustContain(t, stdout, bootstrap.SettingsPath(home)+" (global layer rules): ok")
		mustNotContain(t, stdout, project)
	})

	t.Run("a relative path is reported absolute", func(t *testing.T) {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		if err := os.Chdir(other); err != nil {
			t.Fatalf("chdir: %v", err)
		}
		t.Cleanup(func() { _ = os.Chdir(cwd) })

		code, stdout, stderr := runConfig(t, "config", "check", filepath.Join(".codemeld", "settings.yaml"))
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr)
		}
		mustContain(t, stdout, filepath.Join(other, ".codemeld", "settings.yaml")+" (project layer rules): ok")
	})
}

func TestConfigCheck_LayerRulesAreChosenByPath(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	writeGlobalSettings(t, home, "sessions:\n  retention_days: 30\n")
	projectOnly := writeProjectSettings(t, project, "declared_commands:\n  - go build\n")
	stubConfigEnv(t, home, project)

	code, stdout, _ := runConfig(t, "config", "check", projectOnly)
	if code != 0 {
		t.Fatalf("project-only keys under project rules: exit = %d, want 0:\n%s", code, stdout)
	}

	// sessions.retention_days is global-only, so the same bytes fail under project rules.
	code, stdout, _ = runConfig(t, "config", "check", bootstrap.SettingsPath(home))
	if code != 0 {
		t.Fatalf("global-only keys under global rules: exit = %d, want 0:\n%s", code, stdout)
	}
	globalCopy := writeProjectSettings(t, t.TempDir(), "sessions:\n  retention_days: 30\n")
	code, stdout, _ = runConfig(t, "config", "check", globalCopy)
	if code == 0 {
		t.Fatalf("global-only keys under project rules: exit = 0, want non-zero:\n%s", stdout)
	}
	mustContain(t, stdout, "(project layer rules): failed to load", "sessions.retention_days")
}

func TestConfigCheck_DuplicateMappingKeyFailsWithTheLoadFailureMessage(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	writeGlobalSettings(t, home, "agent:\n  max_concurrency: 2\n")
	broken := writeProjectSettings(t, project, "mode:\n  default: plan\n  default: build\n")
	stubConfigEnv(t, home, project)

	code, stdout, stderr := runConfig(t, "config", "check", broken)
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero (stdout=%q stderr=%q)", stdout, stderr)
	}
	mustContain(t, stdout,
		broken+" (project layer rules): failed to load",
		"codemeld: "+broken+": is not valid YAML; codemeld would not start with this file in place.",
		`what happened: the key "default" is set twice in the same block, at line 2 and again at line 3`,
		`to fix: delete one of the two "default" lines, either line 2 or line 3`,
	)
}

func TestConfigCheck_UntrustedProjectLayerIsNamedAndStaysUntrusted(t *testing.T) {
	setUp := func(t *testing.T, body string) (home, project, marker string) {
		t.Helper()
		home, project = t.TempDir(), t.TempDir()
		writeGlobalSettings(t, home, "agent:\n  max_concurrency: 2\n")
		marker = canonicalMarker(t, writeProjectSettings(t, project, body))
		stubConfigEnv(t, home, project)
		return home, project, marker
	}
	stillUntrusted := func(t *testing.T, home, project string) {
		t.Helper()
		if decision := trust.Lookup(home, canonicalDir(t, project)); decision.Trusted {
			t.Fatalf("checking the layer trusted the project: %#v", decision)
		}
		if _, err := os.Stat(trust.StorePath(home)); !os.IsNotExist(err) {
			t.Fatalf("trust store stat err = %v, want no store written by a check", err)
		}
	}

	t.Run("a valid layer is named rather than loaded", func(t *testing.T) {
		home, project, marker := setUp(t, "mode:\n  default: plan\n")

		code, stdout, stderr := runConfig(t, "config", "check")
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr)
		}
		mustContain(t, stdout,
			marker+" (project layer rules): present, not approved",
			"approve the project",
			"codemeld config check "+marker,
		)
		mustNotContain(t, stdout, marker+" (project layer rules): ok")
		stillUntrusted(t, home, project)
	})

	t.Run("a malformed layer is not parsed", func(t *testing.T) {
		home, project, marker := setUp(t, "mode:\n  default: plan\n  default: build\n")

		code, stdout, stderr := runConfig(t, "config", "check")
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr)
		}
		mustContain(t, stdout, marker+" (project layer rules): present, not approved")
		mustNotContain(t, stdout+stderr, "is not valid YAML", "set twice")
		stillUntrusted(t, home, project)
	})

	t.Run("naming the file parses it without trusting the project", func(t *testing.T) {
		home, project, marker := setUp(t, "mode:\n  default: plan\n")

		code, stdout, stderr := runConfig(t, "config", "check", marker)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr)
		}
		mustContain(t, stdout, marker+" (project layer rules): ok")
		stillUntrusted(t, home, project)
	})
}

func TestConfigCheck_LeavesTheApprovalStoreByteIdentical(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	writeGlobalSettings(t, home, "agent:\n  max_concurrency: 2\n")
	writeProjectSettings(t, project, "mode:\n  default: plan\n")
	trustProject(t, home, project)
	writeProjectSettings(t, project, "mode:\n  default: build\n")
	before, err := os.ReadFile(trust.StorePath(home))
	if err != nil {
		t.Fatalf("read trust store: %v", err)
	}
	stubConfigEnv(t, home, project)

	code, stdout, stderr := runConfig(t, "config", "check")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr)
	}
	mustContain(t, stdout, "(project layer rules): ok")

	after, err := os.ReadFile(trust.StorePath(home))
	if err != nil {
		t.Fatalf("re-read trust store: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("trust store changed:\nbefore=%s\nafter=%s", before, after)
	}
}

func treeSnapshot(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return rerr
		}
		digest := ""
		if info.Mode().IsRegular() {
			data, derr := os.ReadFile(path)
			if derr != nil {
				return derr
			}
			sum := sha256.Sum256(data)
			digest = hex.EncodeToString(sum[:])
		}
		lines = append(lines, fmt.Sprintf("%s %s %s", rel, info.Mode(), digest))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// makeReadOnly registers its restore after t.TempDir registered its own removal, so the
// modes are back before the directory is torn down.
func makeReadOnly(t *testing.T, dir string) {
	t.Helper()
	var restore []func()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		mode := info.Mode().Perm()
		restore = append(restore, func() { _ = os.Chmod(path, mode) })
		return os.Chmod(path, mode&^0o222)
	})
	t.Cleanup(func() {
		for _, fn := range restore {
			fn()
		}
	})
	if err != nil {
		t.Fatalf("chmod tree %s: %v", dir, err)
	}
}

func TestConfigCheck_WritesNothing(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	writeGlobalSettings(t, home, "agent:\n  max_concurrency: 2\n")
	writeProjectSettings(t, project, "mode:\n  default: plan\n")
	trustProject(t, home, project)
	makeReadOnly(t, home)
	makeReadOnly(t, project)
	homeBefore, projectBefore := treeSnapshot(t, home), treeSnapshot(t, project)
	stubConfigEnv(t, home, project)

	for _, args := range [][]string{
		{"config", "check"},
		{"config", "check", filepath.Join(project, ".codemeld", "settings.yaml")},
		{"config", "check", bootstrap.SettingsPath(home)},
	} {
		code, stdout, stderr := runConfig(t, args...)
		if code != 0 {
			t.Fatalf("%v: exit = %d, want 0 (stdout=%q stderr=%q)", args, code, stdout, stderr)
		}
	}
	if got := treeSnapshot(t, home); got != homeBefore {
		t.Fatalf("home tree changed:\nbefore:\n%s\nafter:\n%s", homeBefore, got)
	}
	if got := treeSnapshot(t, project); got != projectBefore {
		t.Fatalf("project tree changed:\nbefore:\n%s\nafter:\n%s", projectBefore, got)
	}
}

// The schema failure is chosen so its message quotes the offending value: that is what makes
// the absence of the auth values evidence rather than an accident of this validator's wording.
func TestConfigCheck_NeverPrintsAuthValues(t *testing.T) {
	const (
		accessToken  = "CHECKED-ACCESS-SECRET"
		refreshToken = "CHECKED-REFRESH-SECRET"
		badHash      = "NOT-A-VALID-SHA256-HASH"
	)
	home, project := t.TempDir(), t.TempDir()
	writeGlobalSettings(t, home, "auth:\n  openai-chatgpt:\n    access_token: "+accessToken+"\n"+
		"    refresh_token: "+refreshToken+"\n"+
		"permissions:\n  - kind: literal\n    subject: sh -c\n    path_scope: /srv/app\n"+
		"    grant_kind: folder\n    argument_hash: "+badHash+"\n")
	stubConfigEnv(t, home, project)

	for _, args := range [][]string{{"config", "check"}, {"config", "check", bootstrap.SettingsPath(home)}} {
		code, stdout, stderr := runConfig(t, args...)
		if code == 0 {
			t.Fatalf("%v: exit = 0, want non-zero (stdout=%q)", args, stdout)
		}
		mustContain(t, stdout, "(global layer rules): failed to load", "does not match the settings schema", badHash)
		mustNotContain(t, stdout+stderr, accessToken, refreshToken)
	}
}

func TestConfigCheck_SymlinkedSettingsFileIsRefusedByTheHardenedReader(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	writeGlobalSettings(t, home, "agent:\n  max_concurrency: 2\n")
	target := filepath.Join(t.TempDir(), "elsewhere.yaml")
	if err := os.WriteFile(target, []byte("mode:\n  default: plan\n"), 0o600); err != nil {
		t.Fatalf("write link target: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(project, ".codemeld"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	marker := filepath.Join(project, ".codemeld", "settings.yaml")
	if err := os.Symlink(target, marker); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	stubConfigEnv(t, home, project)

	code, stdout, stderr := runConfig(t, "config", "check", marker)
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero (stdout=%q stderr=%q)", stdout, stderr)
	}
	mustContain(t, stdout,
		marker+" (project layer rules): failed to load",
		"could not be read",
		"settings file could not be read safely",
	)
	mustNotContain(t, stdout+stderr, target)
}

func TestConfigCheck_HomeAndWorkingDirectoryFailuresExitOne(t *testing.T) {
	t.Run("home resolution", func(t *testing.T) {
		stubConfigEnv(t, t.TempDir(), t.TempDir())
		resolveHome = func() (string, error) { return "", errors.New("$HOME unset") }

		code, stdout, stderr := runConfig(t, "config", "check")
		if code != 1 {
			t.Fatalf("exit = %d, want 1 (stderr=%q)", code, stderr)
		}
		mustContain(t, stderr, "cannot resolve home directory")
		if stdout != "" {
			t.Fatalf("stdout non-empty on error: %q", stdout)
		}
	})

	t.Run("working directory", func(t *testing.T) {
		home := t.TempDir()
		writeGlobalSettings(t, home, "agent:\n  max_concurrency: 2\n")
		stubConfigEnv(t, home, t.TempDir())
		osGetwd = func() (string, error) { return "", errors.New("cwd removed") }

		code, stdout, stderr := runConfig(t, "config", "check")
		if code != 1 {
			t.Fatalf("exit = %d, want 1 (stderr=%q)", code, stderr)
		}
		mustContain(t, stderr, "cannot determine working directory: cwd removed")
		if stdout != "" {
			t.Fatalf("stdout non-empty on error: %q", stdout)
		}
	})
}

func TestConfigCheck_UsageErrors(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	writeGlobalSettings(t, home, "agent:\n  max_concurrency: 2\n")
	stubConfigEnv(t, home, project)

	runUsageErrorCases(t, []usageErrorCase{
		{"config without subcommand", []string{"codemeld", "config"}, "config requires a subcommand; use 'codemeld config check'"},
		{"unknown config subcommand", []string{"codemeld", "config", "bogus"}, `unknown config subcommand "bogus"`},
		{"two paths", []string{"codemeld", "config", "check", "a.yaml", "b.yaml"}, "config check accepts at most one settings file path; got 2"},
	})

	authCode, _, _ := runConfig(t, "auth")
	configCode, stdout, _ := runConfig(t, "config")
	if configCode != authCode {
		t.Fatalf("config exit = %d, auth exit = %d, want the same usage-error code", configCode, authCode)
	}
	if stdout != "" {
		t.Fatalf("stdout non-empty on usage error: %q", stdout)
	}
}
