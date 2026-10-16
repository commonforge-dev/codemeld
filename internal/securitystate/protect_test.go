// Tests for the protected-state policy and the typed refusal it produces.
package securitystate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/permissions"
)

// The project settings file is written and the global one deliberately left absent, so every case
// below runs against one existing and one not-yet-created identity.
type fixture struct {
	policy      Policy
	projectRoot string
	home        string
	project     string
	global      string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	projectRoot := t.TempDir()
	home := t.TempDir()
	project := filepath.Join(projectRoot, ".codemeld", "settings.yaml")
	global := filepath.Join(home, ".codemeld", "global", "settings.yaml")
	mkdirAll(t, filepath.Dir(project))
	mkdirAll(t, filepath.Dir(global))
	writeFile(t, project, "permissions: []\n")
	return fixture{
		policy:      Policy{SettingsPaths: []string{project, global}},
		projectRoot: projectRoot,
		home:        home,
		project:     project,
		global:      global,
	}
}

func mkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", dir, err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink(%q -> %q): %v", link, target, err)
	}
}

func mustEval(t *testing.T, path string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", path, err)
	}
	return real
}

func TestPolicy_RefusesConfiguredNamesAndSidecars(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name string
		raw  string
	}{
		{"project absolute", f.project},
		{"project relative", ".codemeld/settings.yaml"},
		{"project dot-dot", "sub/../.codemeld/settings.yaml"},
		{"project dot-slash", "./.codemeld/settings.yaml"},
		{"project sidecar", f.project + ".lock"},
		{"global absolute", f.global},
		{"global tilde", "~/.codemeld/global/settings.yaml"},
		{"global sidecar", f.global + ".lock"},
		{"global sidecar tilde", "~/.codemeld/global/settings.yaml.lock"},
	}
	for _, tool := range []string{"edit", "create", "delete", "mkdir"} {
		for _, c := range cases {
			t.Run(tool+"/"+c.name, func(t *testing.T) {
				args := map[string]any{"path": c.raw}
				if got := f.policy.RefuseNominal(tool, args, f.home, f.projectRoot); got == nil {
					t.Fatalf("RefuseNominal(%s, %q) = nil, want a protected-state refusal", tool, c.raw)
				}
			})
		}
	}
}

// Only the configured identities are protected: a settings-shaped file elsewhere in the project is
// not, and neither is any operation outside the covered set.
func TestPolicy_LeavesUnprotectedPathsAlone(t *testing.T) {
	f := newFixture(t)
	nested := filepath.Join(f.projectRoot, "vendor", "dep", ".codemeld")
	mkdirAll(t, nested)
	writeFile(t, filepath.Join(nested, "settings.yaml"), "x: 1\n")

	t.Run("paths", func(t *testing.T) {
		for _, raw := range []string{
			"vendor/dep/.codemeld/settings.yaml",
			".codemeld/settings.yml",
			".codemeld/settings.yaml.bak",
			".codemeld/settings",
			"notes.md",
			".codemeld",
		} {
			args := map[string]any{"path": raw}
			if got := f.policy.RefuseNominal("edit", args, f.home, f.projectRoot); got != nil {
				t.Fatalf("RefuseNominal(edit, %q) = %+v, want nil", raw, got)
			}
		}
	})

	t.Run("uncovered tools", func(t *testing.T) {
		args := map[string]any{"path": f.project}
		for _, tool := range []string{"read", "grep", "glob", "list", "tree", "bash", "vcs_commit"} {
			if got := f.policy.RefuseNominal(tool, args, f.home, f.projectRoot); got != nil {
				t.Fatalf("RefuseNominal(%s) = %+v, want nil (only the mutating file tools are covered)", tool, got)
			}
			if got := f.policy.RefuseResolved(tool, f.project); got != nil {
				t.Fatalf("RefuseResolved(%s) = %+v, want nil", tool, got)
			}
		}
	})

	t.Run("zero policy", func(t *testing.T) {
		var empty Policy
		args := map[string]any{"path": f.project}
		if got := empty.RefuseNominal("edit", args, f.home, f.projectRoot); got != nil {
			t.Fatalf("zero Policy refused %+v, want nil", got)
		}
		if got := empty.RefuseResolved("edit", f.project); got != nil {
			t.Fatalf("zero Policy refused a resolved endpoint %+v, want nil", got)
		}
	})
}

func TestPolicy_RefusesSymlinkAliases(t *testing.T) {
	f := newFixture(t)
	parentLink := filepath.Join(f.projectRoot, "cfg")
	symlink(t, filepath.Join(f.projectRoot, ".codemeld"), parentLink)
	finalLink := filepath.Join(f.projectRoot, "notes.yaml")
	symlink(t, f.project, finalLink)

	t.Run("parent symlink nominal", func(t *testing.T) {
		args := map[string]any{"path": "cfg/settings.yaml"}
		if got := f.policy.RefuseNominal("edit", args, f.home, f.projectRoot); got == nil {
			t.Fatal("RefuseNominal through a symlinked parent = nil, want a refusal")
		}
	})
	t.Run("final component symlink nominal", func(t *testing.T) {
		args := map[string]any{"path": "notes.yaml"}
		if got := f.policy.RefuseNominal("edit", args, f.home, f.projectRoot); got == nil {
			t.Fatal("RefuseNominal on a symlink to the settings file = nil, want a refusal")
		}
	})
	t.Run("final component symlink resolved", func(t *testing.T) {
		if got := f.policy.RefuseResolved("delete", finalLink); got == nil {
			t.Fatal("RefuseResolved on a symlink to the settings file = nil, want a refusal")
		}
	})
	t.Run("resolved real path", func(t *testing.T) {
		if got := f.policy.RefuseResolved("edit", mustEval(t, f.project)); got == nil {
			t.Fatal("RefuseResolved on the real settings path = nil, want a refusal")
		}
	})
	t.Run("resolved unprotected", func(t *testing.T) {
		if got := f.policy.RefuseResolved("edit", filepath.Join(f.projectRoot, "main.go")); got != nil {
			t.Fatalf("RefuseResolved on an ordinary file = %+v, want nil", got)
		}
	})
}

func TestPolicy_RefusalShape(t *testing.T) {
	f := newFixture(t)
	got := f.policy.RefuseNominal("edit", map[string]any{"path": ".codemeld/settings.yaml"}, f.home, f.projectRoot)
	if got == nil {
		t.Fatal("RefuseNominal = nil, want a refusal")
	}
	if got.SubjectKind != "tool" {
		t.Errorf("SubjectKind = %q, want tool", got.SubjectKind)
	}
	if got.Subject != "edit" {
		t.Errorf("Subject = %q, want edit", got.Subject)
	}
	wantScope := mustEval(t, filepath.Dir(f.project))
	if got.PathScope != wantScope {
		t.Errorf("PathScope = %q, want the endpoint parent %q", got.PathScope, wantScope)
	}
	if !filepath.IsAbs(got.PathScope) {
		t.Errorf("PathScope = %q, want an absolute path", got.PathScope)
	}
	if got.Envelope != permissions.BuildGuardDenyEnvelope() {
		t.Errorf("Envelope = %q, want the fixed guard envelope", got.Envelope)
	}
	if got.Error() == "" {
		t.Error("Error() = empty, want a typed protected-state message")
	}
}

func TestPolicy_MoveEndpointsAndContainingAncestors(t *testing.T) {
	f := newFixture(t)
	sibling := filepath.Join(f.projectRoot, ".codemeld-backup")
	mkdirAll(t, sibling)

	refusals := []struct {
		name        string
		source      string
		destination string
	}{
		{"protected source", f.project, filepath.Join(f.projectRoot, "copy.yaml")},
		{"protected destination", filepath.Join(f.projectRoot, "copy.yaml"), f.project},
		{"sidecar destination", filepath.Join(f.projectRoot, "copy.yaml"), f.project + ".lock"},
		{"global destination", filepath.Join(f.projectRoot, "copy.yaml"), f.global},
		{"containing codemeld dir", filepath.Join(f.projectRoot, ".codemeld"), filepath.Join(f.projectRoot, "old")},
		{"containing project root", f.projectRoot, filepath.Join(f.projectRoot, "..", "moved")},
		{"containing home codemeld", "~/.codemeld", filepath.Join(f.home, "old")},
	}
	for _, c := range refusals {
		t.Run(c.name, func(t *testing.T) {
			args := map[string]any{"source": c.source, "destination": c.destination}
			got := f.policy.RefuseNominal("move", args, f.home, f.projectRoot)
			if got == nil {
				t.Fatalf("RefuseNominal(move, %q -> %q) = nil, want a refusal", c.source, c.destination)
			}
			if got.Subject != "move" {
				t.Fatalf("Subject = %q, want move", got.Subject)
			}
		})
	}

	t.Run("unprotected move", func(t *testing.T) {
		args := map[string]any{"source": sibling, "destination": filepath.Join(f.projectRoot, "renamed")}
		if got := f.policy.RefuseNominal("move", args, f.home, f.projectRoot); got != nil {
			t.Fatalf("RefuseNominal on a sibling of .codemeld = %+v, want nil", got)
		}
	})

	t.Run("source first", func(t *testing.T) {
		args := map[string]any{"source": f.project, "destination": f.global}
		got := f.policy.RefuseNominal("move", args, f.home, f.projectRoot)
		if got == nil {
			t.Fatal("RefuseNominal with two protected endpoints = nil, want a refusal")
		}
		wantScope := mustEval(t, filepath.Dir(f.project))
		if got.PathScope != wantScope {
			t.Fatalf("PathScope = %q, want the source parent %q", got.PathScope, wantScope)
		}
	})

	t.Run("resolved endpoints", func(t *testing.T) {
		if got := f.policy.RefuseResolved("move", filepath.Join(f.projectRoot, "copy.yaml"), mustEval(t, f.project)); got == nil {
			t.Fatal("RefuseResolved(move) on a resolved protected destination = nil, want a refusal")
		}
		if got := f.policy.RefuseResolved("move", mustEval(t, filepath.Dir(f.project)), filepath.Join(f.projectRoot, "old")); got == nil {
			t.Fatal("RefuseResolved(move) on a resolved containing directory = nil, want a refusal")
		}
		if got := f.policy.RefuseResolved("move", sibling, filepath.Join(f.projectRoot, "renamed")); got != nil {
			t.Fatalf("RefuseResolved(move) on unprotected endpoints = %+v, want nil", got)
		}
	})

	t.Run("containment is move-only", func(t *testing.T) {
		args := map[string]any{"path": filepath.Join(f.projectRoot, ".codemeld")}
		for _, tool := range []string{"edit", "create", "delete", "mkdir"} {
			if got := f.policy.RefuseNominal(tool, args, f.home, f.projectRoot); got != nil {
				t.Fatalf("RefuseNominal(%s) on the containing directory = %+v, want nil", tool, got)
			}
		}
	})
}

// A structurally broken call is left to the operation's own resolver rather than converted into a
// protected-state refusal.
func TestPolicy_MalformedArgumentsAreNotRefusals(t *testing.T) {
	f := newFixture(t)
	for _, args := range []map[string]any{
		{},
		{"path": ""},
		{"path": 42},
		{"path": "~nobody/.codemeld/settings.yaml"},
		{"source": f.project},
	} {
		if got := f.policy.RefuseNominal("edit", args, f.home, f.projectRoot); got != nil {
			t.Fatalf("RefuseNominal(%v) = %+v, want nil", args, got)
		}
	}
	if got := f.policy.RefuseResolved("edit", ""); got != nil {
		t.Fatalf("RefuseResolved on an empty endpoint = %+v, want nil", got)
	}
}

func TestPolicy_ProtectedInFindsConfiguredIdentitiesAndSidecars(t *testing.T) {
	f := newFixture(t)
	writeFile(t, f.project+".lock", "")

	got, err := f.policy.ProtectedIn(f.projectRoot)
	if err != nil {
		t.Fatalf("ProtectedIn: %v", err)
	}
	for _, want := range []string{f.project, f.project + ".lock"} {
		if !contains(got, want) {
			t.Fatalf("ProtectedIn = %v, missing %q", got, want)
		}
	}
	if contains(got, f.global) {
		t.Fatalf("ProtectedIn = %v, includes the global settings file that lies outside the repository", got)
	}
}

func TestPolicy_ProtectedInMatchesSymlinkAndHardlinkAliases(t *testing.T) {
	f := newFixture(t)
	link := filepath.Join(f.projectRoot, "alias.yaml")
	if err := os.Symlink(f.project, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	hard := filepath.Join(f.projectRoot, "nested", "hardlink.yaml")
	mkdirAll(t, filepath.Dir(hard))
	if err := os.Link(f.project, hard); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}
	aliasPolicy := Policy{SettingsPaths: []string{link}}

	got, err := f.policy.ProtectedIn(f.projectRoot)
	if err != nil {
		t.Fatalf("ProtectedIn: %v", err)
	}
	if !contains(got, hard) {
		t.Fatalf("ProtectedIn = %v, missing the hardlink alias %q", got, hard)
	}

	viaLink, err := aliasPolicy.ProtectedIn(f.projectRoot)
	if err != nil {
		t.Fatalf("ProtectedIn(symlinked identity): %v", err)
	}
	for _, want := range []string{link, f.project, hard} {
		if !contains(viaLink, want) {
			t.Fatalf("ProtectedIn(symlinked identity) = %v, missing %q", viaLink, want)
		}
	}
}

func TestPolicy_ProtectedInFailsClosedOnAnUnreadableTree(t *testing.T) {
	f := newFixture(t)
	sealed := filepath.Join(f.projectRoot, "sealed")
	mkdirAll(t, sealed)
	if err := os.Chmod(sealed, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(sealed, 0o755) })
	if _, err := os.ReadDir(sealed); err == nil {
		t.Skip("directory permissions are not enforced for this user")
	}

	if _, err := f.policy.ProtectedIn(f.projectRoot); err == nil {
		t.Fatal("ProtectedIn = nil error; a tree it cannot enumerate must not report a partial set")
	}
}

func TestPolicy_ProtectedInIsEmptyWithoutAPolicyOrRoot(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name   string
		policy Policy
		root   string
	}{
		{"no configured settings paths", Policy{}, f.projectRoot},
		{"no root", f.policy, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.policy.ProtectedIn(tc.root)
			if err != nil || len(got) != 0 {
				t.Fatalf("ProtectedIn = %v, %v, want no identities and no error", got, err)
			}
		})
	}
}

func TestPolicy_RefusesBlockedPaths(t *testing.T) {
	f := newFixture(t)
	home := mustEval(t, f.home)
	project := mustEval(t, f.projectRoot)
	ssh := filepath.Join(home, ".ssh")
	secrets := filepath.Join(project, "secrets")
	mkdirAll(t, ssh)
	mkdirAll(t, secrets)
	writeFile(t, filepath.Join(ssh, "id_rsa"), "key\n")
	writeFile(t, filepath.Join(secrets, "token"), "TOKEN\n")
	const globalSource, projectSource = "/cfg/global/settings.yaml", "/cfg/project/settings.yaml"
	policy := Policy{Blocked: permissions.NewBlockedPaths(home, []permissions.BlockedEntry{
		{Path: ssh, Source: globalSource},
		{Path: secrets, Source: projectSource},
	})}
	nominal := func(tool, raw string) *Refusal {
		return policy.RefuseNominal(tool, map[string]any{"path": raw}, home, project)
	}
	floor := filepath.Join(home, ".codemeld")

	cases := []struct {
		name   string
		tool   string
		got    *Refusal
		scope  string
		entry  string
		reason string
	}{
		{"read nominal", "read", nominal("read", "~/.ssh/id_rsa"), ssh, ssh, "~/.ssh/id_rsa is blocked by your blocked_paths entry ~/.ssh"},
		{"read resolved", "read", policy.RefuseResolved("read", filepath.Join(ssh, "id_rsa")), ssh, ssh, "~/.ssh/id_rsa is blocked by your blocked_paths entry ~/.ssh"},
		{"grep nominal", "grep", nominal("grep", "~/.ssh"), ssh, ssh, "~/.ssh is blocked by your blocked_paths entry ~/.ssh"},
		{"grep resolved", "grep", policy.RefuseResolved("grep", ssh), ssh, ssh, "~/.ssh is blocked by your blocked_paths entry ~/.ssh"},
		{"tree nominal", "tree", nominal("tree", "~/.ssh"), ssh, ssh, "~/.ssh is blocked by your blocked_paths entry ~/.ssh"},
		{"tree resolved", "tree", policy.RefuseResolved("tree", ssh), ssh, ssh, "~/.ssh is blocked by your blocked_paths entry ~/.ssh"},
		{"edit inside", "edit", policy.RefuseResolved("edit", filepath.Join(secrets, "token")), secrets, secrets, ""},
		{"create missing inside", "create", policy.RefuseResolved("create", filepath.Join(secrets, "new")), secrets, secrets, ""},
		{"create nominal absolute", "create", nominal("create", filepath.Join(secrets, "new")), secrets, secrets, ""},
		{"mkdir inside", "mkdir", policy.RefuseResolved("mkdir", filepath.Join(secrets, "sub")), secrets, secrets, ""},
		{"delete inside", "delete", policy.RefuseResolved("delete", filepath.Join(secrets, "token")), secrets, secrets, ""},
		{"delete containing", "delete", policy.RefuseResolved("delete", project), filepath.Dir(project), secrets, ""},
		{"move source containing", "move", policy.RefuseResolved("move", project, filepath.Join(project, "..", "moved")), filepath.Dir(project), secrets, ""},
		{"move destination containing", "move", policy.RefuseResolved("move", filepath.Join(project, "notes"), project), filepath.Dir(project), secrets, ""},
		{"floor", "read", policy.RefuseResolved("read", filepath.Join(floor, "global", "settings.yaml")), filepath.Join(floor, "global"), floor, "~/.codemeld/global/settings.yaml is inside codemeld's protected folder ~/.codemeld"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got == nil {
				t.Fatal("refusal = nil, want a blocked-path refusal")
			}
			if c.got.Source != "blocked_path" || c.got.SubjectKind != "tool" || c.got.Subject != c.tool {
				t.Fatalf("refusal = %+v, want source blocked_path and subject tool/%s", c.got, c.tool)
			}
			if c.got.PathScope != c.scope || c.got.Entry != c.entry {
				t.Fatalf("PathScope, Entry = %q, %q; want %q, %q", c.got.PathScope, c.got.Entry, c.scope, c.entry)
			}
			if !permissions.IsModeDenyEnvelope(c.got.Envelope) {
				t.Fatalf("Envelope = %q, want a recoverable guard envelope", c.got.Envelope)
			}
			if strings.Contains(c.got.Envelope, globalSource) || strings.Contains(c.got.Envelope, projectSource) {
				t.Fatalf("Envelope = %q names a settings file", c.got.Envelope)
			}
			if c.reason != "" && !strings.Contains(c.got.Envelope, c.reason) {
				t.Fatalf("Envelope = %q, want reason %q", c.got.Envelope, c.reason)
			}
		})
	}

	t.Run("entry source and floor", func(t *testing.T) {
		if got := policy.RefuseResolved("read", filepath.Join(ssh, "id_rsa")); got == nil || got.EntrySource != globalSource {
			t.Fatalf("refusal = %+v, want EntrySource %q", got, globalSource)
		}
		if got := policy.RefuseResolved("read", filepath.Join(floor, "x")); got == nil || got.EntrySource != "" {
			t.Fatalf("floor refusal = %+v, want an empty EntrySource", got)
		}
	})

	t.Run("not refused", func(t *testing.T) {
		for name, got := range map[string]*Refusal{
			"sibling read nominal":  nominal("read", "~/.sshx/a"),
			"sibling read resolved": policy.RefuseResolved("read", filepath.Join(home, ".sshx", "a")),
			"grep at home nominal":  nominal("grep", "~"),
			"grep at home resolved": policy.RefuseResolved("grep", home),
			"relative nominal":      nominal("read", "secrets/token"),
		} {
			if got != nil {
				t.Fatalf("%s = %+v, want nil", name, got)
			}
		}
	})

	t.Run("home display", func(t *testing.T) {
		upperHome := strings.ToUpper(home)
		for _, c := range []struct {
			path string
			fold bool
			want string
		}{
			{home, false, "~"},
			{filepath.Join(ssh, "id_rsa"), false, "~/.ssh/id_rsa"},
			{filepath.Join(upperHome, ".ssh", "id_rsa"), true, "~/.ssh/id_rsa"},
			{filepath.Join(upperHome, ".ssh", "id_rsa"), false, filepath.Join(upperHome, ".ssh", "id_rsa")},
			{filepath.Join(home+"x", ".ssh"), true, filepath.Join(home+"x", ".ssh")},
		} {
			if got := underHome(home, c.path, c.fold); got != c.want {
				t.Fatalf("underHome(%q, fold=%v) = %q, want %q", c.path, c.fold, got, c.want)
			}
		}
	})

	t.Run("symlinked home display", func(t *testing.T) {
		physical := mustEval(t, t.TempDir())
		linkedHome := filepath.Join(mustEval(t, t.TempDir()), "home")
		symlink(t, physical, linkedHome)
		mkdirAll(t, filepath.Join(physical, ".ssh"))
		linked := Policy{Blocked: permissions.NewBlockedPaths(linkedHome, []permissions.BlockedEntry{
			{Path: filepath.Join(linkedHome, ".ssh"), Source: globalSource},
		})}
		got := linked.RefuseResolved("read", filepath.Join(physical, ".ssh", "id_rsa"))
		if want := "~/.ssh/id_rsa is blocked by your blocked_paths entry ~/.ssh"; got == nil || !strings.Contains(got.Envelope, want) {
			t.Fatalf("refusal = %+v, want reason %q", got, want)
		}
	})
}

func TestPolicy_RefuseShell(t *testing.T) {
	f := newFixture(t)
	home := mustEval(t, f.home)
	project := mustEval(t, f.projectRoot)
	ssh := filepath.Join(home, ".ssh")
	mkdirAll(t, filepath.Join(ssh, "a"))
	symlink(t, ssh, filepath.Join(project, "keys"))
	symlink(t, filepath.Join(ssh, "a"), filepath.Join(project, "sub"))
	const source = "/cfg/global/settings.yaml"
	policy := Policy{Blocked: permissions.NewBlockedPaths(home, []permissions.BlockedEntry{{Path: ssh, Source: source}})}
	refuse := func(folder string, argv ...string) *Refusal {
		return policy.RefuseShell("direct", strings.Join(argv, " "), folder, permissions.ShellPathCandidates(argv, folder, home))
	}
	floor := filepath.Join(home, ".codemeld")

	cases := []struct {
		name   string
		argv   []string
		folder string
		entry  string
		reason string
	}{
		{"cat ~/.ssh/k", []string{"cat", filepath.Join(ssh, "k")}, project, ssh, "~/.ssh/k is blocked by your blocked_paths entry ~/.ssh"},
		{"cat -- ~/.ssh/k", []string{"cat", "--", filepath.Join(ssh, "k")}, project, ssh, ""},
		{"cat ~/tmp/../.ssh/k", []string{"cat", home + "/tmp/../.ssh/k"}, project, ssh, ""},
		{"--x=<home>/.ssh/k", []string{"grep", "--x=" + filepath.Join(ssh, "k")}, project, ssh, ""},
		{"--x=~/.ssh/k", []string{"grep", "--x=~/.ssh/k"}, project, ssh, ""},
		{"project symlink into ~/.ssh", []string{"cat", "keys/k"}, project, ssh, ""},
		{"sub/../k where sub links to ~/.ssh/a", []string{"cat", "sub/../k"}, project, ssh, ""},
		{"floor", []string{"cat", filepath.Join(floor, "global", "settings.yaml")}, project, floor, "~/.codemeld/global/settings.yaml is inside codemeld's protected folder ~/.codemeld"},
		{"run folder inside ~/.ssh", []string{"ls"}, filepath.Join(ssh, "a"), ssh, "~/.ssh/a is blocked by your blocked_paths entry ~/.ssh"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := refuse(c.folder, c.argv...)
			if got == nil {
				t.Fatal("refusal = nil, want a blocked-path refusal")
			}
			if got.Source != "blocked_path" || got.SubjectKind != "direct" || got.Subject != strings.Join(c.argv, " ") || got.PathScope != c.folder {
				t.Fatalf("refusal = %+v, want blocked_path direct/%q in %q", got, strings.Join(c.argv, " "), c.folder)
			}
			wantSource := source
			if c.entry == floor {
				wantSource = ""
			}
			if got.Entry != c.entry || got.EntrySource != wantSource {
				t.Fatalf("Entry, EntrySource = %q, %q; want %q, %q", got.Entry, got.EntrySource, c.entry, wantSource)
			}
			if !permissions.IsModeDenyEnvelope(got.Envelope) {
				t.Fatalf("Envelope = %q, want a recoverable guard envelope", got.Envelope)
			}
			if c.reason != "" && !strings.Contains(got.Envelope, c.reason) {
				t.Fatalf("Envelope = %q, want reason %q", got.Envelope, c.reason)
			}
		})
	}

	t.Run("a cleaning join would miss the link", func(t *testing.T) {
		if got := policy.RefuseShell("direct", "cat sub/../k", project, []string{filepath.Join(project, "sub/../k")}); got != nil {
			t.Fatalf("refusal = %+v, want nil for the cleaned %q", got, filepath.Join(project, "sub/../k"))
		}
	})

	t.Run("not refused", func(t *testing.T) {
		for name, got := range map[string]*Refusal{
			"~/.sshx/k":                            refuse(project, "cat", filepath.Join(home, ".sshx", "k")),
			"~/.ss":                                refuse(project, "cat", filepath.Join(home, ".ss")),
			"quoted '~/.ssh/k' runs as a relative": refuse(project, "cat", "~/.ssh/k"),
			`escaped \~/.ssh/k runs as a relative`: refuse(home, "cat", "~/.ssh/k"),
			"--x= with an empty value":             refuse(project, "grep", "--x="),
			"-/abs/blocked with no =":              refuse(project, "grep", "-"+filepath.Join(ssh, "k")),
			"ls ~":                                 refuse(project, "ls", home),
			"nil Blocked":                          Policy{}.RefuseShell("direct", "cat", ssh, []string{filepath.Join(ssh, "k")}),
		} {
			if got != nil {
				t.Fatalf("%s = %+v, want nil", name, got)
			}
		}
	})
}

func TestPolicy_RefuseVCS(t *testing.T) {
	f := newFixture(t)

	if refusal := f.policy.RefuseVCS("vcs_restore_file", f.projectRoot, false); refusal != nil {
		t.Fatalf("RefuseVCS(risky=false) = %+v, want no refusal", refusal)
	}
	if refusal := (Policy{}).RefuseVCS("vcs_restore_file", f.projectRoot, true); refusal != nil {
		t.Fatalf("RefuseVCS(unguarded policy) = %+v, want no refusal", refusal)
	}
	refusal := f.policy.RefuseVCS("vcs_restore_file", f.projectRoot, true)
	if refusal == nil {
		t.Fatal("RefuseVCS(risky) = nil, want the guard refusal")
	}
	if refusal.SubjectKind != "tool" || refusal.Subject != "vcs_restore_file" {
		t.Fatalf("refusal subject = %q/%q, want tool/vcs_restore_file", refusal.SubjectKind, refusal.Subject)
	}
	if refusal.PathScope != f.projectRoot {
		t.Fatalf("refusal PathScope = %q, want the action's execution directory %q", refusal.PathScope, f.projectRoot)
	}
	if refusal.Envelope != permissions.BuildGuardDenyEnvelope() {
		t.Fatalf("refusal envelope = %q, want the fixed guard envelope", refusal.Envelope)
	}
}

func TestPolicy_RefuseBlockedVCS(t *testing.T) {
	f := newFixture(t)
	home := mustEval(t, f.home)
	project := mustEval(t, f.projectRoot)
	ssh := filepath.Join(home, ".ssh")
	secrets := filepath.Join(project, "secrets")
	keys := filepath.Join(project, "keys")
	floor := filepath.Join(home, ".codemeld")
	const source = "/cfg/global/settings.yaml"
	policy := Policy{Blocked: permissions.NewBlockedPaths(home, []permissions.BlockedEntry{
		{Path: ssh, Source: source},
		{Path: secrets, Source: source},
		{Path: keys, Source: source},
	})}
	queried := func(root string) func(func(string) ([]string, error)) bool {
		return func(protectedIn func(string) ([]string, error)) bool {
			candidates, err := protectedIn(root)
			return err != nil || len(candidates) > 0
		}
	}

	t.Run("first risky entry", func(t *testing.T) {
		got := policy.RefuseBlockedVCS("vcs_restore_file", project, queried(project))
		if got == nil {
			t.Fatal("refusal = nil, want a blocked-path refusal")
		}
		if got.Source != "blocked_path" || got.SubjectKind != "tool" || got.Subject != "vcs_restore_file" || got.PathScope != project {
			t.Fatalf("refusal = %+v, want blocked_path tool/vcs_restore_file in %q", got, project)
		}
		if got.Entry != secrets || got.EntrySource != source {
			t.Fatalf("Entry, EntrySource = %q, %q; want %q, %q", got.Entry, got.EntrySource, secrets, source)
		}
		if want := project + " is blocked by your blocked_paths entry " + secrets; !permissions.IsModeDenyEnvelope(got.Envelope) || !strings.Contains(got.Envelope, want) {
			t.Fatalf("Envelope = %q, want a recoverable guard envelope with reason %q", got.Envelope, want)
		}
	})

	t.Run("floor", func(t *testing.T) {
		got := Policy{Blocked: permissions.NewBlockedPaths(home, nil)}.RefuseBlockedVCS("vcs_stash", home, queried(home))
		if got == nil || got.Entry != floor || got.EntrySource != "" || got.PathScope != home {
			t.Fatalf("refusal = %+v, want the floor %q in %q", got, floor, home)
		}
		if want := "~ is inside codemeld's protected folder ~/.codemeld"; !strings.Contains(got.Envelope, want) {
			t.Fatalf("Envelope = %q, want reason %q", got.Envelope, want)
		}
	})

	t.Run("callback error with risk", func(t *testing.T) {
		got := policy.RefuseBlockedVCS("vcs_branch_switch", project, queried(filepath.Join(project, "missing")))
		if got == nil || got.Source != "blocked_path" || got.Entry != ssh {
			t.Fatalf("refusal = %+v, want a blocked-path refusal naming the first entry %q", got, ssh)
		}
	})

	t.Run("not refused", func(t *testing.T) {
		for name, got := range map[string]*Refusal{
			"verdict without the callback": policy.RefuseBlockedVCS("vcs_status", project, func(func(string) ([]string, error)) bool { return true }),
			"no risk":                      policy.RefuseBlockedVCS("vcs_restore_file", project, func(in func(string) ([]string, error)) bool { _, _ = in(project); return false }),
			"nil Blocked":                  Policy{}.RefuseBlockedVCS("vcs_restore_file", project, queried(project)),
		} {
			if got != nil {
				t.Fatalf("%s = %+v, want nil", name, got)
			}
		}
	})
}

func contains(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

func guardedArgs(tool, endpoint string) map[string]any {
	if tool == filetools.MoveToolName {
		return map[string]any{"source": endpoint, "destination": endpoint + ".moved"}
	}
	return map[string]any{"path": endpoint}
}

func TestPolicy_RefusesTheLocalSettingsFileForEveryGuardedTool(t *testing.T) {
	f := newFixture(t)
	local := config.LocalSettingsPath(f.projectRoot)
	writeFile(t, local, "permissions: []\n")
	policy := Policy{SettingsPaths: []string{f.project, local, f.global}}

	targets := map[string]string{
		"local file":    local,
		"local sidecar": local + ".lock",
	}
	for tool := range guardedTools {
		for name, target := range targets {
			t.Run(tool+"/"+name, func(t *testing.T) {
				got := policy.RefuseNominal(tool, guardedArgs(tool, target), f.home, f.projectRoot)
				if got == nil {
					t.Fatalf("RefuseNominal(%s, %q) = nil, want a protected-state refusal", tool, target)
				}
				if got.Envelope != permissions.BuildGuardDenyEnvelope() {
					t.Errorf("Envelope = %q, want the fixed guard envelope", got.Envelope)
				}
				if got.Source != sourceProtectedState {
					t.Errorf("Source = %q, want %q", got.Source, sourceProtectedState)
				}
			})
		}
	}

	t.Run("move/containing directory", func(t *testing.T) {
		args := map[string]any{"source": filepath.Dir(local), "destination": filepath.Join(f.projectRoot, "old")}
		got := policy.RefuseNominal(filetools.MoveToolName, args, f.home, f.projectRoot)
		if got == nil {
			t.Fatal("moving the directory holding the local settings file was not refused")
		}
		if got.Envelope != permissions.BuildGuardDenyEnvelope() || got.Source != sourceProtectedState {
			t.Fatalf("refusal = %+v, want the guard envelope and %q", got, sourceProtectedState)
		}
	})

	t.Run("read-only tools reach the file", func(t *testing.T) {
		for tool := range blockedTools {
			if guardedTools[tool] {
				continue
			}
			if got := policy.RefuseNominal(tool, map[string]any{"path": local}, f.home, f.projectRoot); got != nil {
				t.Errorf("RefuseNominal(%s, local settings) = %+v, want nil", tool, got)
			}
		}
	})
}
