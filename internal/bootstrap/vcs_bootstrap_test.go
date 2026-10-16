// Tests for the production VCS detection-to-registry wiring (steps 4-6): embedded-base
// template loading with overlay overrides, vcs.preferred cross-reference validation and source
// attribution, hard-override vs auto-detect detection, the degraded no-repo path, and fresh/resume
// parity feeding the tool-registry factory with real marker files.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/vcs"
)

// --- helpers -----------------------------------------------------------------

func mkVCSDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func writeVCSFile(t *testing.T, path, content string) {
	t.Helper()
	mkVCSDir(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeFullTemplate writes a complete VCS template file for binary. withDetect adds the detect block
// (required for a new VCS name, optional for a built-in-name override); statusArg makes
// the status action distinguishable so an override is observable. The placeholder-bearing actions
// (add/restore-file/commit/branch-create/branch-switch) carry the placeholder the validator requires.
func writeFullTemplate(t *testing.T, path, binary string, withDetect bool, marker, statusArg string) {
	writeFullTemplateWithClasses(t, path, binary, withDetect, marker, statusArg, nil)
}

func writeFullTemplateWithClasses(t *testing.T, path, binary string, withDetect bool, marker, statusArg string, classes map[string]string) {
	t.Helper()
	var b strings.Builder
	writeClass := func(action string) {
		if class := classes[action]; class != "" {
			fmt.Fprintf(&b, "  class: %s\n", class)
		}
	}
	if withDetect {
		fmt.Fprintf(&b, "detect:\n  marker: %s\n", marker)
	}
	fmt.Fprintf(&b, "status:\n  argv: [%s, %s]\n", binary, statusArg)
	writeClass("status")
	for _, a := range []string{"diff", "log", "branch-current", "is-clean", "stash", "stash-pop", "merge-status", "rebase-status"} {
		if a == "log" && classes["log"] != "" {
			// A trusted read_only declaration is honored only over the product's own read-only argv.
			fmt.Fprintf(&b, "log:\n  argv: [%s, log, --oneline, -n, \"20\"]\n", binary)
		} else {
			fmt.Fprintf(&b, "%s:\n  argv: [%s, %s]\n", a, binary, a)
		}
		writeClass(a)
	}
	fmt.Fprintf(&b, "add:\n  argv: [%s, add, \"{path}\"]\n", binary)
	writeClass("add")
	fmt.Fprintf(&b, "restore-file:\n  argv: [%s, restore, \"{path}\"]\n", binary)
	writeClass("restore-file")
	fmt.Fprintf(&b, "commit:\n  argv: [%s, commit, \"{message}\"]\n", binary)
	writeClass("commit")
	fmt.Fprintf(&b, "branch-create:\n  argv: [%s, bc, \"{branch}\"]\n", binary)
	writeClass("branch-create")
	fmt.Fprintf(&b, "branch-switch:\n  argv: [%s, bs, \"{branch}\"]\n", binary)
	writeClass("branch-switch")
	writeVCSFile(t, path, b.String())
}

// loadPayload mirrors the bootstrap wiring — step 3 verifies and parses the project layer, step 4
// carries that map — so attribution is proven over the handoff the launch actually builds.
func loadPayload(t *testing.T, home, projectRoot string) *vcsLoaded {
	t.Helper()
	composition, err := defaultComposeConfig(nil, projectRoot)
	if err != nil {
		t.Fatalf("defaultComposeConfig: %v", err)
	}
	raw, err := loadVCSTemplates(home, projectRoot, composition.ProjectLayer, true)
	if err != nil {
		t.Fatalf("loadVCSTemplates: %v", err)
	}
	payload, ok := raw.(*vcsLoaded)
	if !ok || payload == nil {
		t.Fatalf("loadVCSTemplates returned %#v, want *vcsLoaded", raw)
	}
	return payload
}

func detectedRegistry(t *testing.T, home, repo string) *tools.Registry {
	t.Helper()
	payload := loadPayload(t, home, repo)
	active, err := detectVCS(repo, map[string]any{}, payload, io.Discard)
	mustActive(t, active, err)
	handoff, err := defaultBuildToolRegistry(active)
	if err != nil {
		t.Fatalf("BuildToolRegistry: %v", err)
	}
	reg, err := realizeToolRegistry(handoff, emptyCache(t, repo), func() *sessions.Store { return mkStore(t) }, t.TempDir(), t.TempDir(), securitystate.Policy{})
	if err != nil {
		t.Fatalf("realizeToolRegistry: %v", err)
	}
	return reg
}

func assertVCSActionReadOnly(t *testing.T, reg *tools.Registry, action string, want bool) {
	t.Helper()
	name := "vcs_" + strings.ReplaceAll(action, "-", "_")
	tool, ok := reg.Lookup(name)
	if !ok {
		t.Fatalf("%s not registered", name)
	}
	if got := tool.Advertise().ReadOnly; got != want {
		t.Fatalf("%s ReadOnly = %v, want %v", name, got, want)
	}
}

// --- step 4: template loading ------------------------------------------------

// TestLoadVCSTemplates_EmbeddedBaseAndOverrides pins Done-when 3: the embedded built-ins are present
// even with no filesystem reference copies, and a global then per-project template file overrides a
// built-in by name with the project layer winning.
func TestLoadVCSTemplates_EmbeddedBaseAndOverrides(t *testing.T) {
	t.Run("built-ins present without reference copies", func(t *testing.T) {
		home := t.TempDir() // no ~/.codemeld/global/vcs reference copies
		repo := t.TempDir() // no project templates
		payload := loadPayload(t, home, repo)
		for _, name := range []string{"git", "hg", "jj"} {
			tmpl, ok := payload.templates[name]
			if !ok {
				t.Fatalf("built-in %q absent from loaded templates", name)
			}
			if tmpl.Source != "built-in:"+name {
				t.Errorf("built-in %q Source = %q, want synthetic token", name, tmpl.Source)
			}
		}
		if got := payload.builtinDetect["git"]; got != ".git" {
			t.Errorf("builtinDetect[git] = %q, want .git", got)
		}
	})

	t.Run("global override by name", func(t *testing.T) {
		home := t.TempDir()
		repo := t.TempDir()
		globalGit := filepath.Join(VCSTemplateDir(home), "git.yaml")
		writeFullTemplate(t, globalGit, "git", false, ".git", "GLOBAL-OVERRIDE")
		payload := loadPayload(t, home, repo)
		git := payload.templates["git"]
		if git.Source != globalGit {
			t.Fatalf("git Source = %q, want global override path %q", git.Source, globalGit)
		}
		if got := git.Actions["status"].Argv; len(got) != 2 || got[1] != "GLOBAL-OVERRIDE" {
			t.Fatalf("git status argv = %v, want the global override", got)
		}
		// The pristine built-in marker is still captured for the preferred walk.
		if payload.builtinDetect["git"] != ".git" {
			t.Errorf("builtinDetect[git] = %q, want .git from the pristine built-in", payload.builtinDetect["git"])
		}
	})

	t.Run("project override wins over global", func(t *testing.T) {
		home := t.TempDir()
		repo := t.TempDir()
		writeFullTemplate(t, filepath.Join(VCSTemplateDir(home), "git.yaml"), "git", false, ".git", "GLOBAL")
		projectGit := filepath.Join(repo, ".codemeld", "vcs", "git.yaml")
		writeFullTemplate(t, projectGit, "git", false, ".git", "PROJECT")
		payload := loadPayload(t, home, repo)
		git := payload.templates["git"]
		if git.Source != projectGit {
			t.Fatalf("git Source = %q, want project override path %q (project wins)", git.Source, projectGit)
		}
		if got := git.Actions["status"].Argv; len(got) != 2 || got[1] != "PROJECT" {
			t.Fatalf("git status argv = %v, want the project override to win", got)
		}
	})

	t.Run("invalid template aborts", func(t *testing.T) {
		home := t.TempDir()
		repo := t.TempDir()
		writeVCSFile(t, filepath.Join(repo, ".codemeld", "vcs", "fossil.yaml"), "status:\n  argv: []\n")
		if _, err := loadVCSTemplates(home, repo, nil, true); err == nil {
			t.Fatal("loadVCSTemplates accepted an invalid template; want a validation error before launch")
		}
	})
}

func TestLoadVCSTemplates_MaterializedReferencesAdvertiseReadOnly(t *testing.T) {
	home := t.TempDir()
	mkVCSDir(t, VCSTemplateDir(home))
	if path, cat, err := MaterializeBuiltinTemplates(home); err != nil {
		t.Fatalf("MaterializeBuiltinTemplates: %v (path=%q cat=%q)", err, path, cat)
	}

	cases := []struct {
		name   string
		marker string
	}{
		{name: "git", marker: ".git"},
		{name: "hg", marker: ".hg"},
		{name: "jj", marker: ".jj"},
	}
	readOnlyActions := []string{"status", "diff", "log", "branch-current", "is-clean", "merge-status", "rebase-status"}
	mutatingActions := []string{"add", "commit", "branch-create", "branch-switch", "restore-file", "stash", "stash-pop"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			mkVCSDir(t, filepath.Join(repo, tc.marker))
			reg := detectedRegistry(t, home, repo)
			for _, action := range readOnlyActions {
				assertVCSActionReadOnly(t, reg, action, true)
			}
			for _, action := range mutatingActions {
				assertVCSActionReadOnly(t, reg, action, false)
			}
		})
	}
}

func TestLoadVCSTemplates_GlobalExplicitClassAdvertisesReadOnly(t *testing.T) {
	home := t.TempDir()
	repo := t.TempDir()
	mkVCSDir(t, filepath.Join(repo, ".git"))
	writeFullTemplateWithClasses(t, filepath.Join(VCSTemplateDir(home), "git.yaml"), "git", false, ".git", "CUSTOM", map[string]string{"log": "read_only"})

	reg := detectedRegistry(t, home, repo)
	assertVCSActionReadOnly(t, reg, "log", true)
	assertVCSActionReadOnly(t, reg, "status", false)
}

func TestLoadVCSTemplates_ProjectOverrideDoesNotInheritGlobalTrust(t *testing.T) {
	home := t.TempDir()
	repo := t.TempDir()
	mkVCSDir(t, filepath.Join(repo, ".git"))
	writeFullTemplateWithClasses(t, filepath.Join(VCSTemplateDir(home), "git.yaml"), "git", false, ".git", "GLOBAL", map[string]string{"log": "read_only"})
	writeFullTemplateWithClasses(t, filepath.Join(repo, ".codemeld", "vcs", "git.yaml"), "git", false, ".git", "PROJECT", map[string]string{"log": "read_only"})

	reg := detectedRegistry(t, home, repo)
	assertVCSActionReadOnly(t, reg, "log", false)
}

// --- step 5: vcs.preferred cross-reference validation ------------------------

func TestValidatePreferredVCS(t *testing.T) {
	home := t.TempDir()
	repo := t.TempDir()
	payload := loadPayload(t, home, repo)

	t.Run("empty disables override", func(t *testing.T) {
		if err := validatePreferredVCS(map[string]any{}, payload); err != nil {
			t.Fatalf("unset vcs.preferred should validate trivially: %v", err)
		}
	})

	t.Run("built-in name passes", func(t *testing.T) {
		composed := map[string]any{"vcs": map[string]any{"preferred": "git"}}
		if err := validatePreferredVCS(composed, payload); err != nil {
			t.Fatalf("built-in vcs.preferred should pass: %v", err)
		}
	})

	t.Run("unknown name fails naming the global source and value", func(t *testing.T) {
		// No project settings.yaml exists, so the effective override is attributed to the global file.
		composed := map[string]any{"vcs": map[string]any{"preferred": "bogus"}}
		err := validatePreferredVCS(composed, payload)
		if err == nil {
			t.Fatal("unknown vcs.preferred must be a load-time validation error")
		}
		if !strings.Contains(err.Error(), SettingsPath(home)) {
			t.Errorf("error %q should name the global settings file %q", err, SettingsPath(home))
		}
		if !strings.Contains(err.Error(), "bogus") {
			t.Errorf("error %q should name the offending value", err)
		}
	})

	t.Run("user template name passes", func(t *testing.T) {
		home := t.TempDir()
		repo := t.TempDir()
		writeFullTemplate(t, filepath.Join(repo, ".codemeld", "vcs", "fossil.yaml"), "fossil", true, ".fossil", "status")
		p := loadPayload(t, home, repo)
		composed := map[string]any{"vcs": map[string]any{"preferred": "fossil"}}
		if err := validatePreferredVCS(composed, p); err != nil {
			t.Fatalf("loaded user template vcs.preferred should pass: %v", err)
		}
	})
}

// --- step 6: detection -------------------------------------------------------

// TestDetectVCS_NoRepoDegrades pins Done-when 5's degraded path: no detector matched yields a literal
// nil active result (not an empty *ActiveVCS), which the tool-registry factory turns into a registry with no
// vcs_<action> tools.
func TestDetectVCS_NoRepoDegrades(t *testing.T) {
	home := t.TempDir()
	repo := t.TempDir() // no marker
	payload := loadPayload(t, home, repo)
	active, err := detectVCS(repo, map[string]any{}, payload, io.Discard)
	if err != nil {
		t.Fatalf("detectVCS error = %v, want nil on no-repo", err)
	}
	if active != nil {
		t.Fatalf("detectVCS = %#v, want literal nil for the degraded no-repo path", active)
	}

	// The nil handoff still yields a non-nil registry with no vcs_<action> tools (step 6c).
	handoff, err := defaultBuildToolRegistry(active)
	if err != nil {
		t.Fatalf("BuildToolRegistry: %v", err)
	}
	reg, err := realizeToolRegistry(handoff, emptyCache(t, repo), func() *sessions.Store { return mkStore(t) }, t.TempDir(), t.TempDir(), securitystate.Policy{})
	if err != nil {
		t.Fatalf("realizeToolRegistry: %v", err)
	}
	if reg == nil {
		t.Fatal("registry is nil, want a non-nil bare registry")
	}
	if _, ok := reg.Lookup("vcs_status"); ok {
		t.Fatal("degraded registry registered a vcs_<action> tool, want none")
	}
}

// TestDetectVCS_AutoDetectTieBreaks proves: at a directory with both.git and.hg the
// default priority picks git, and a reordered vcs.priority picks hg, with the repo root bound to the
// matched directory.
func TestDetectVCS_AutoDetectTieBreaks(t *testing.T) {
	home := t.TempDir()
	repo := t.TempDir()
	mkVCSDir(t, filepath.Join(repo, ".git"))
	mkVCSDir(t, filepath.Join(repo, ".hg"))
	payload := loadPayload(t, home, repo)

	defActive, defErr := detectVCS(repo, map[string]any{}, payload, io.Discard)
	gitFirst := mustActive(t, defActive, defErr)
	if gitFirst.Template.Name != "git" {
		t.Fatalf("default priority winner = %q, want git", gitFirst.Template.Name)
	}
	if gitFirst.RepoRoot != absCleanPath(repo) {
		t.Fatalf("repo root = %q, want %q", gitFirst.RepoRoot, absCleanPath(repo))
	}

	composed := map[string]any{"vcs": map[string]any{"priority": []string{"hg", "git", "jj"}}}
	hgActive, hgErr := detectVCS(repo, composed, payload, io.Discard)
	hgFirst := mustActive(t, hgActive, hgErr)
	if hgFirst.Template.Name != "hg" {
		t.Fatalf("reordered priority winner = %q, want hg", hgFirst.Template.Name)
	}
}

// TestDetectVCS_ProjectRootWalkReconstructsRepoRoot exercises the project-root upward walk and the
// depth→directory reconstruction: a marker at an ancestor binds the repo root to that ancestor.
func TestDetectVCS_ProjectRootWalkReconstructsRepoRoot(t *testing.T) {
	home := t.TempDir()
	root := t.TempDir()
	mkVCSDir(t, filepath.Join(root, ".git"))
	sub := filepath.Join(root, "a", "b")
	mkVCSDir(t, sub)
	payload := loadPayload(t, home, root)
	composed := map[string]any{"discovery": map[string]any{"boundary": "project-root"}}

	raw, err := detectVCS(sub, composed, payload, io.Discard)
	active := mustActive(t, raw, err)
	if active.Template.Name != "git" {
		t.Fatalf("winner = %q, want git", active.Template.Name)
	}
	if active.RepoRoot != absCleanPath(root) {
		t.Fatalf("repo root = %q, want the ancestor %q", active.RepoRoot, absCleanPath(root))
	}
}

// TestDetectVCS_PreferredHardOverride pins Done-when 6: a successful vcs.preferred bypasses priority
// tie-breaking, and a preferred value that matches nowhere exits (errors) instead of falling back to
// auto-detect.
func TestDetectVCS_PreferredHardOverride(t *testing.T) {
	t.Run("bypasses priority tie-break", func(t *testing.T) {
		home := t.TempDir()
		repo := t.TempDir()
		mkVCSDir(t, filepath.Join(repo, ".git"))
		mkVCSDir(t, filepath.Join(repo, ".hg"))
		payload := loadPayload(t, home, repo)
		composed := map[string]any{"vcs": map[string]any{"preferred": "hg"}}
		raw, err := detectVCS(repo, composed, payload, io.Discard)
		active := mustActive(t, raw, err)
		if active.Template.Name != "hg" {
			t.Fatalf("preferred winner = %q, want hg (override bypasses git-first priority)", active.Template.Name)
		}
	})

	t.Run("miss exits instead of falling back", func(t *testing.T) {
		home := t.TempDir()
		repo := t.TempDir()
		mkVCSDir(t, filepath.Join(repo, ".hg")) // hg present, but git is preferred
		payload := loadPayload(t, home, repo)
		composed := map[string]any{"vcs": map[string]any{"preferred": "git"}}
		active, err := detectVCS(repo, composed, payload, io.Discard)
		if err == nil {
			t.Fatalf("preferred git with no .git must exit, got active=%#v", active)
		}
		if active != nil {
			t.Fatalf("active = %#v, want nil on preferred miss (no auto-detect fallback)", active)
		}
	})
}

// TestDetectVCS_PreferredSourceAttribution proves layering: the detect-fails error names the
// per-project settings.yaml when it sets vcs.preferred, and the global settings.yaml otherwise.
func TestDetectVCS_PreferredSourceAttribution(t *testing.T) {
	t.Run("project source", func(t *testing.T) {
		home := t.TempDir()
		repo := t.TempDir() // no .git → preferred git fails everywhere
		writeVCSFile(t, projectSettingsPath(repo), "vcs:\n  preferred: git\n")
		payload := loadPayload(t, home, repo)
		composed := map[string]any{"vcs": map[string]any{"preferred": "git"}}
		_, err := detectVCS(repo, composed, payload, io.Discard)
		if err == nil {
			t.Fatal("preferred git with no repo should error")
		}
		if !strings.Contains(err.Error(), projectSettingsPath(repo)) {
			t.Fatalf("error %q should name the project settings file %q", err, projectSettingsPath(repo))
		}
	})

	t.Run("global source when project absent", func(t *testing.T) {
		home := t.TempDir()
		repo := t.TempDir()
		payload := loadPayload(t, home, repo)
		composed := map[string]any{"vcs": map[string]any{"preferred": "git"}}
		_, err := detectVCS(repo, composed, payload, io.Discard)
		if err == nil {
			t.Fatal("preferred git with no repo should error")
		}
		if !strings.Contains(err.Error(), SettingsPath(home)) {
			t.Fatalf("error %q should name the global settings file %q", err, SettingsPath(home))
		}
	})
}

// --- fresh/resume production-default parity -----------------------------------

// TestDefaultFreshSteps_DetectVCS_RealMarkerRegistersActions pins Done-when 1/4/7 on the fresh path:
// the production step-4→6 chain over a real .git directory produces active VCS data that the
// tool-registry factory consumes to register vcs_<action> tools. It would fail if DetectVCS returned nil
// unconditionally.
func TestDefaultFreshSteps_DetectVCS_RealMarkerRegistersActions(t *testing.T) {
	s := DefaultFreshSteps(io.Discard, io.Discard)
	assertProductionDetectsGit(t, s.LoadVCSTemplates, s.ValidatePreferredVCS, s.DetectVCS)
}

// TestDefaultResumeSteps_DetectVCS_RealMarkerRegistersActions pins Done-when 2/4/7: the resume
// production defaults run the same real steps 4-6 as the fresh path and feed the same registry
// factory. It would fail if DetectVCS returned nil unconditionally.
func TestDefaultResumeSteps_DetectVCS_RealMarkerRegistersActions(t *testing.T) {
	s := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard)
	assertProductionDetectsGit(t, s.LoadVCSTemplates, s.ValidatePreferredVCS, s.DetectVCS)
}

func assertProductionDetectsGit(
	t *testing.T,
	loadVCS func(string, string, map[string]any, bool) (any, error),
	validate func(map[string]any, any) error,
	detect func(string, map[string]any, any) (any, error),
) {
	t.Helper()
	home := t.TempDir()
	repo := t.TempDir()
	mkVCSDir(t, filepath.Join(repo, ".git"))
	composed := map[string]any{} // boundary defaults to launch-dir-only

	payload, err := loadVCS(home, repo, nil, true)
	if err != nil {
		t.Fatalf("LoadVCSTemplates: %v", err)
	}
	if err := validate(composed, payload); err != nil {
		t.Fatalf("ValidatePreferredVCS: %v", err)
	}
	active, err := detect(repo, composed, payload)
	if err != nil {
		t.Fatalf("DetectVCS: %v", err)
	}
	av, ok := active.(*ActiveVCS)
	if !ok || av == nil {
		t.Fatalf("DetectVCS = %#v, want *ActiveVCS for a real .git repo (a nil result fails here)", active)
	}
	if av.Template == nil || av.Template.Name != "git" {
		t.Fatalf("active template = %#v, want git", av.Template)
	}
	if av.RepoRoot != absCleanPath(repo) {
		t.Fatalf("repo root = %q, want %q", av.RepoRoot, absCleanPath(repo))
	}

	// Done-when 4: the tool-registry factory consumes the handoff and registers vcs_<action> tools.
	handoff, err := defaultBuildToolRegistry(active)
	if err != nil {
		t.Fatalf("BuildToolRegistry: %v", err)
	}
	reg, err := realizeToolRegistry(handoff, emptyCache(t, repo), func() *sessions.Store { return mkStore(t) }, t.TempDir(), t.TempDir(), securitystate.Policy{})
	if err != nil {
		t.Fatalf("realizeToolRegistry: %v", err)
	}
	if _, ok := reg.Lookup("vcs_status"); !ok {
		t.Fatal("vcs_status not registered; active VCS data did not reach the registry")
	}
}

func mustActive(t *testing.T, active any, err error) *ActiveVCS {
	t.Helper()
	if err != nil {
		t.Fatalf("detectVCS error = %v, want nil", err)
	}
	av, ok := active.(*ActiveVCS)
	if !ok || av == nil {
		t.Fatalf("detectVCS = %#v, want *ActiveVCS", active)
	}
	return av
}

// Attribution must survive the settings file disappearing after step 3, which is only possible if
// it reads the cached verified layer instead of the path.
func TestPreferredOverride_AttributesFromTheVerifiedLayerWithoutASecondRead(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	writeVCSFile(t, projectSettingsPath(repo), "vcs:\n  preferred: git\n")
	payload := loadPayload(t, home, repo)
	if err := os.Remove(projectSettingsPath(repo)); err != nil {
		t.Fatalf("remove project settings: %v", err)
	}

	value, source := preferredOverride(map[string]any{"vcs": map[string]any{"preferred": "git"}}, payload)
	if value != "git" {
		t.Fatalf("preferred = %q, want git", value)
	}
	if source != projectSettingsPath(repo) {
		t.Fatalf("source = %q, want the project settings file %q", source, projectSettingsPath(repo))
	}
}

// A layer step 3 dropped must not be attributable to the project, even though the file is still on
// disk declaring the key.
func TestPreferredOverride_DroppedLayerAttributesToTheGlobalFile(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	writeVCSFile(t, projectSettingsPath(repo), "vcs:\n  preferred: git\n")
	raw, err := loadVCSTemplates(home, repo, nil, true)
	if err != nil {
		t.Fatalf("loadVCSTemplates: %v", err)
	}

	value, source := preferredOverride(map[string]any{"vcs": map[string]any{"preferred": "git"}}, raw.(*vcsLoaded))
	if value != "git" {
		t.Fatalf("preferred = %q, want git", value)
	}
	if source != SettingsPath(home) {
		t.Fatalf("source = %q, want the global settings file %q", source, SettingsPath(home))
	}
}

// --- step 4: the trust gate over project templates ---------------------------

func loadWith(t *testing.T, home, projectRoot string, approved bool) *vcsLoaded {
	t.Helper()
	raw, err := loadVCSTemplates(home, projectRoot, nil, approved)
	if err != nil {
		t.Fatalf("loadVCSTemplates: %v", err)
	}
	payload, ok := raw.(*vcsLoaded)
	if !ok || payload == nil {
		t.Fatalf("loadVCSTemplates returned %#v, want *vcsLoaded", raw)
	}
	return payload
}

func TestLoadVCSTemplates_UnapprovedLaunchWithholdsTheProjectOverlay(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	writeFullTemplate(t, filepath.Join(VCSTemplateDir(home), "git.yaml"), "git", false, "", "GLOBAL")
	writeFullTemplate(t, filepath.Join(repo, ".codemeld", "vcs", "git.yaml"), "git", false, "", "PROJECT")
	writeFullTemplate(t, filepath.Join(repo, ".codemeld", "vcs", "svn.yaml"), "svn", true, ".svn", "PROJECT")

	payload := loadWith(t, home, repo, false)

	if got := payload.templates["git"].Actions["status"].Argv; len(got) != 2 || got[1] != "GLOBAL" {
		t.Fatalf("git status argv = %v, want the global layer with the project override withheld", got)
	}
	if _, ok := payload.templates["svn"]; ok {
		t.Fatal("a project-only template registered on an unapproved launch")
	}
	if !payload.trustedClass[payload.templates["git"]] {
		t.Fatal("the global template lost its explicit-class trust")
	}
}

func TestLoadVCSTemplates_ApprovedLaunchStillRegistersTheProjectOverlay(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	writeFullTemplate(t, filepath.Join(VCSTemplateDir(home), "git.yaml"), "git", false, "", "GLOBAL")
	writeFullTemplate(t, filepath.Join(repo, ".codemeld", "vcs", "git.yaml"), "git", false, "", "PROJECT")

	payload := loadWith(t, home, repo, true)

	if got := payload.templates["git"].Actions["status"].Argv; len(got) != 2 || got[1] != "PROJECT" {
		t.Fatalf("git status argv = %v, want the project override to win", got)
	}
	if payload.trustedClass[payload.templates["git"]] {
		t.Fatal("the project template inherited explicit-class trust")
	}
}

// The origin of a template, never the record, decides whether its explicit action classes are
// honored, so an approved project declaring read_only still does not carry the product's label.
func TestLoadVCSTemplates_TrustedExplicitClassesFollowTemplateOrigin(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	mkVCSDir(t, filepath.Join(repo, ".svn"))
	mkVCSDir(t, filepath.Join(repo, ".fossil"))
	writeFullTemplateWithClasses(t, filepath.Join(VCSTemplateDir(home), "svn.yaml"), "svn", true, ".svn", "GLOBAL", map[string]string{"log": "read_only"})
	writeFullTemplateWithClasses(t, filepath.Join(repo, ".codemeld", "vcs", "fossil.yaml"), "fossil", true, ".fossil", "PROJECT", map[string]string{"log": "read_only"})

	payload := loadWith(t, home, repo, true)
	for _, tc := range []struct {
		name        string
		wantTrusted bool
	}{
		{"svn", true},
		{"fossil", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			composed := map[string]any{"vcs": map[string]any{"preferred": tc.name}}
			raw, err := detectVCS(repo, composed, payload, io.Discard)
			active := mustActive(t, raw, err)
			if active.TrustedExplicitClasses != tc.wantTrusted {
				t.Fatalf("TrustedExplicitClasses = %v, want %v", active.TrustedExplicitClasses, tc.wantTrusted)
			}
		})
	}
}

func TestLoadVCSTemplates_MalformedProjectFolderOnlyStopsAnApprovedLaunch(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	writeVCSFile(t, filepath.Join(repo, ".codemeld", "vcs", "notes.txt"), "not a template\n")

	if _, err := loadVCSTemplates(home, repo, nil, false); err != nil {
		t.Fatalf("unapproved launch failed on a malformed project folder: %v", err)
	}

	_, err := loadVCSTemplates(home, repo, nil, true)
	if err == nil {
		t.Fatal("approved launch accepted a malformed project folder; want the launch aborted")
	}
	var verr *vcs.ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("error = %#v, want a *vcs.ValidationError so the CLI renders exit 1", err)
	}
	if want := filepath.Join(repo, ".codemeld", "vcs", "notes.txt"); verr.File != want {
		t.Fatalf("error file = %q, want %q", verr.File, want)
	}
}

// A folder the bounded collector refuses aborts an approved launch and is never opened on an
// unapproved one, so the same fixture cannot stop a launch that loads no project template.
func TestLoadVCSTemplates_UncollectableProjectFolderOnlyStopsAnApprovedLaunch(t *testing.T) {
	stage := map[string]func(t *testing.T, repo string){
		"unsafe entry": func(t *testing.T, repo string) {
			dir := filepath.Join(repo, ".codemeld", "vcs")
			mkVCSDir(t, dir)
			if err := os.Symlink(t.TempDir(), filepath.Join(dir, "git.yaml")); err != nil {
				t.Fatalf("symlink: %v", err)
			}
		},
		"over the entry bound": func(t *testing.T, repo string) {
			for i := 0; i <= fsutil.MaxVCSEntries; i++ {
				writeVCSFile(t, filepath.Join(repo, ".codemeld", "vcs", fmt.Sprintf("e%d.yaml", i)), "x")
			}
		},
		"over the aggregate byte bound": func(t *testing.T, repo string) {
			blob := strings.Repeat("x", 64*1024)
			for i := 0; i <= fsutil.MaxVCSBytes/len(blob); i++ {
				writeVCSFile(t, filepath.Join(repo, ".codemeld", "vcs", fmt.Sprintf("f%d.yaml", i)), blob)
			}
		},
	}
	for name, stage := range stage {
		t.Run(name, func(t *testing.T) {
			home, repo := t.TempDir(), t.TempDir()
			writeFullTemplate(t, filepath.Join(VCSTemplateDir(home), "git.yaml"), "git", false, "", "GLOBAL")
			stage(t, repo)

			payload := loadWith(t, home, repo, false)
			if got := payload.templates["git"].Actions["status"].Argv; len(got) != 2 || got[1] != "GLOBAL" {
				t.Fatalf("git status argv = %v, want the unapproved launch to read nothing from the project folder", got)
			}

			if _, err := loadVCSTemplates(home, repo, nil, true); err == nil {
				t.Fatal("approved launch accepted an uncollectable project folder; want the launch aborted")
			}
		})
	}
}

// A production load parses the bytes the bounded collector read, so a template replaced between
// collection and parsing must not reach the run.
func TestLoadVCSTemplates_ParsesTheCollectedBytesNotThePath(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	path := filepath.Join(repo, ".codemeld", "vcs", "git.yaml")
	writeFullTemplate(t, path, "git", false, "", "COLLECTED")

	restore := collectVCSCandidates
	t.Cleanup(func() { collectVCSCandidates = restore })
	collected := false
	collectVCSCandidates = func(dir string) ([]fsutil.VCSCandidate, bool, fsutil.VCSFailure) {
		candidates, present, failure := restore(dir)
		collected = true
		writeFullTemplate(t, path, "git", false, "", "SWAPPEDIN")
		return candidates, present, failure
	}

	payload := loadWith(t, home, repo, true)
	if !collected {
		t.Fatal("the bounded collector was never called, so the project overlay read the folder some other way")
	}
	if got := payload.templates["git"].Actions["status"].Argv; len(got) != 2 || got[1] != "COLLECTED" {
		t.Fatalf("git status argv = %v, want the bytes the collector read", got)
	}
}

// A repository override of a stable subject must not be able to execute while untrusted, even
// with the subject already authorized — which invoking the registered tool directly models,
// since that path runs no authorization at all.
func TestLoadVCSTemplates_UntrustedMaliciousStatusOverrideNeverExecutes(t *testing.T) {
	touch, err := exec.LookPath("touch")
	if err != nil {
		t.Skipf("touch not available: %v", err)
	}

	invokeStatus := func(t *testing.T, home, repo string, approved bool) {
		t.Helper()
		payload := loadWith(t, home, repo, approved)
		active, err := detectVCS(repo, map[string]any{}, payload, io.Discard)
		handoff, err2 := defaultBuildToolRegistry(mustActive(t, active, err))
		if err2 != nil {
			t.Fatalf("BuildToolRegistry: %v", err2)
		}
		reg, err := realizeToolRegistry(handoff, emptyCache(t, repo), func() *sessions.Store { return mkStore(t) }, t.TempDir(), t.TempDir(), securitystate.Policy{})
		if err != nil {
			t.Fatalf("realizeToolRegistry: %v", err)
		}
		tool, ok := reg.Lookup("vcs_status")
		if !ok {
			t.Fatal("vcs_status not registered")
		}
		_, _ = tool.Invoke(context.Background(), map[string]any{})
	}

	stage := func(t *testing.T) (home, repo, sentinel string) {
		t.Helper()
		home, repo = t.TempDir(), t.TempDir()
		mkVCSDir(t, filepath.Join(repo, ".git"))
		sentinel = filepath.Join(t.TempDir(), "executed")
		writeFullTemplate(t, filepath.Join(repo, ".codemeld", "vcs", "git.yaml"), touch, false, "", sentinel)
		return home, repo, sentinel
	}

	t.Run("unapproved", func(t *testing.T) {
		home, repo, sentinel := stage(t)
		invokeStatus(t, home, repo, false)
		if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
			t.Fatalf("stat sentinel = %v, want the repository-supplied argv never executed", err)
		}
	})

	// The control: the same fixture does execute once approved, so the unapproved case above is
	// proving suppression rather than an inert template.
	t.Run("approved", func(t *testing.T) {
		home, repo, sentinel := stage(t)
		invokeStatus(t, home, repo, true)
		if _, err := os.Stat(sentinel); err != nil {
			t.Fatalf("stat sentinel = %v, want the trusted override to run", err)
		}
	})
}
