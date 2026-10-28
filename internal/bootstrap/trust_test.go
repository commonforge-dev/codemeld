package bootstrap

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/trust"
)

const approvePrompt = "Trust this folder?"

func writeProjectSettings(t *testing.T, root, content string) {
	t.Helper()
	path := projectSettingsPath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir project settings parent: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write project settings: %v", err)
	}
}

func trustProject(t *testing.T, content string) string {
	t.Helper()
	root := t.TempDir()
	writeProjectSettings(t, root, content)
	return root
}

func trustStore(t *testing.T, home string) trust.Store {
	t.Helper()
	data, err := os.ReadFile(trust.StorePath(home))
	if err != nil {
		t.Fatalf("read trust store: %v", err)
	}
	var store trust.Store
	if err := yaml.Unmarshal(data, &store); err != nil {
		t.Fatalf("decode trust store: %v", err)
	}
	return store
}

func trustStoreAbsent(t *testing.T, home string) {
	t.Helper()
	if _, err := os.Stat(trust.StorePath(home)); !os.IsNotExist(err) {
		t.Fatalf("stat trust store = %v, want no record written", err)
	}
}

func approveRoot(t *testing.T, home, root string) {
	t.Helper()
	if err := trust.Record(home, root); err != nil {
		t.Fatalf("trust.Record: %v", err)
	}
}

func countNotices(stderr string) int {
	return strings.Count(stderr, "codemeld: unapproved project ")
}

func mustCanonical(t *testing.T, path string) string {
	t.Helper()
	canonical, err := sessions.CanonicalizeFolder(path)
	if err != nil {
		t.Fatalf("canonicalize %s: %v", path, err)
	}
	return canonical
}

func TestGateTrust_TerminalAnswers(t *testing.T) {
	cases := []struct {
		name     string
		answer   string
		approved bool
	}{
		{"eof", "", false},
		{"empty line", "\n", false},
		{"malformed", "yes please\n", false},
		{"explicit no", "n\n", false},
		{"retired always answer", "a\n", false},
		{"short yes", "y\n", true},
		{"spelled yes", " YES \n", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			root := trustProject(t, "model: {}\n")
			var stderr strings.Builder

			decision := gateTrust(home, root, root, strings.NewReader(tc.answer), &stderr, true)

			if !strings.Contains(stderr.String(), approvePrompt) || !strings.Contains(stderr.String(), "[y/N]") {
				t.Fatalf("stderr = %q, want the two-way approval prompt", stderr.String())
			}
			if !strings.Contains(stderr.String(), "Do you trust "+root+"?") {
				t.Fatalf("prompt = %q, want it to ask about the project root", stderr.String())
			}
			if strings.Contains(stderr.String(), agentinstr.FileName) || strings.Contains(stderr.String(), " 0 ") {
				t.Fatalf("stderr = %q, want no instruction file mention and no zero count", stderr.String())
			}
			if decision.Trusted != tc.approved {
				t.Fatalf("decision = %#v, want approved=%v", decision, tc.approved)
			}

			var next strings.Builder
			nextDecision := gateTrust(home, root, root, strings.NewReader(""), &next, true)

			if !tc.approved {
				if countNotices(stderr.String()) != 1 {
					t.Fatalf("stderr = %q, want exactly one ignored-settings notice", stderr.String())
				}
				trustStoreAbsent(t, home)
				if nextDecision.Trusted || !strings.Contains(next.String(), approvePrompt) {
					t.Fatalf("next launch decision = %#v, stderr = %q, want it asked again", nextDecision, next.String())
				}
				return
			}

			if countNotices(stderr.String()) != 0 {
				t.Fatalf("stderr = %q, want no notice on an approved launch", stderr.String())
			}
			if got := trustStore(t, home).Projects; !slices.Equal(got, []string{mustCanonical(t, root)}) {
				t.Fatalf("stored projects = %v, want exactly the canonical root", got)
			}
			if !nextDecision.Trusted || nextDecision.Reason != trust.ReasonTrusted || next.Len() != 0 {
				t.Fatalf("next launch decision = %#v, stderr = %q, want a silent approved launch", nextDecision, next.String())
			}
		})
	}
}

func TestGateTrust_NonInteractiveLaunchNeverPromptsAndDegrades(t *testing.T) {
	home := t.TempDir()
	root := trustProject(t, "model: {}\n")
	var stderr strings.Builder

	decision := gateTrust(home, root, root, strings.NewReader("y\n"), &stderr, false)

	if decision.Trusted {
		t.Fatalf("decision = %#v, want an unapproved launch", decision)
	}
	if strings.Contains(stderr.String(), approvePrompt) {
		t.Fatalf("stderr = %q, want no prompt without a terminal", stderr.String())
	}
	if countNotices(stderr.String()) != 1 {
		t.Fatalf("stderr = %q, want exactly one ignored-settings notice", stderr.String())
	}
	trustStoreAbsent(t, home)
}

func TestInteractiveTrustGate_PipedStdinIsNotATerminal(t *testing.T) {
	home := t.TempDir()
	root := trustProject(t, "model: {}\n")
	var stderr strings.Builder

	decision := interactiveTrustGate(strings.NewReader("y\n"), &stderr)(home, root, root)

	if decision.Trusted {
		t.Fatalf("decision = %#v, want unapproved when stdin is not a terminal", decision)
	}
	if countNotices(stderr.String()) != 1 {
		t.Fatalf("stderr = %q, want exactly one ignored-settings notice", stderr.String())
	}
}

func TestGateTrust_NothingGatedIsNeverAsked(t *testing.T) {
	home := t.TempDir()
	root := t.TempDir()
	var stderr strings.Builder

	decision := gateTrust(home, root, root, strings.NewReader("y\n"), &stderr, true)

	if !decision.Trusted || decision.Reason != trust.ReasonNothingCovered {
		t.Fatalf("decision = %#v, want the nothing-to-gate outcome", decision)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want nothing printed", stderr.String())
	}
	trustStoreAbsent(t, home)

	writeProjectSettings(t, root, "model: {}\n")
	var second strings.Builder
	gateTrust(home, root, root, strings.NewReader("\n"), &second, true)
	if !strings.Contains(second.String(), approvePrompt) {
		t.Fatalf("stderr = %q, want the prompt once a gated file exists", second.String())
	}
}

func TestGateTrust_UnreadableStoreWithNothingGatedIsNotAsked(t *testing.T) {
	home := t.TempDir()
	root := t.TempDir()
	storePath := trust.StorePath(home)
	if err := os.MkdirAll(filepath.Dir(storePath), 0o755); err != nil {
		t.Fatalf("mkdir store dir: %v", err)
	}
	if err := os.WriteFile(storePath, []byte("\tnot: [yaml\n"), 0o600); err != nil {
		t.Fatalf("write malformed store: %v", err)
	}
	var stderr strings.Builder

	decision := gateTrust(home, root, root, strings.NewReader("y\n"), &stderr, true)

	if decision.Trusted || decision.Reason != trust.ReasonUnreadable {
		t.Fatalf("decision = %#v, want unapproved %q", decision, trust.ReasonUnreadable)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want nothing printed", stderr.String())
	}
}

func TestGateTrust_ApprovedRootStaysApprovedAcrossEditsAndRemoval(t *testing.T) {
	home := t.TempDir()
	above := t.TempDir()
	root := mkdirAll(t, filepath.Join(above, "repo"))
	writeProjectSettings(t, root, "model: {}\n")
	writeGlobalAgents(t, home, "# global\n")
	writeAgentsFile(t, above, "# above the root\n")
	writeAgentsFile(t, root, "# repo\n")

	if decision := gateTrust(home, root, root, strings.NewReader("y\n"), &strings.Builder{}, true); !decision.Trusted {
		t.Fatalf("setup decision = %#v, want the project approved", decision)
	}

	writeAgentsFile(t, above, "# above the root, edited\n")
	writeGlobalAgents(t, home, "# global, edited\n")
	writeAgentsFile(t, root, "# repo, steered\n")
	writeProjectSettings(t, root, "model: {active: x}\n")
	writeProjectTemplate(t, root, "git.yaml", "status:\n  argv: [git, status]\n")
	var stderr strings.Builder
	if decision := gateTrust(home, root, root, strings.NewReader("\n"), &stderr, true); !decision.Trusted || decision.Reason != trust.ReasonTrusted {
		t.Fatalf("decision = %#v, want edits to leave the root approved", decision)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want a silent approved launch", stderr.String())
	}

	if err := os.RemoveAll(filepath.Join(root, ".codemeld")); err != nil {
		t.Fatalf("remove project config dir: %v", err)
	}
	if decision := gateTrust(home, root, root, strings.NewReader("\n"), &stderr, true); !decision.Trusted || decision.Reason != trust.ReasonTrusted {
		t.Fatalf("decision = %#v, want a listed root with nothing present still approved", decision)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want a silent approved launch", stderr.String())
	}
}

func TestGateTrust_IndeterminatePresenceFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		path  func(root string) string
		stage func(t *testing.T, root string)
	}{
		{"settings path is a directory", projectSettingsPath, func(t *testing.T, root string) {
			mkdirAll(t, projectSettingsPath(root))
		}},
		{"local settings path is a symlink", config.LocalSettingsPath, func(t *testing.T, root string) {
			mkdirAll(t, filepath.Join(root, ".codemeld"))
			target := filepath.Join(t.TempDir(), "local.yaml")
			if err := os.WriteFile(target, []byte("model: {}\n"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := os.Symlink(target, config.LocalSettingsPath(root)); err != nil {
				t.Fatalf("symlink: %v", err)
			}
		}},
		{"vcs folder is a symlink", projectVCSTemplateDir, func(t *testing.T, root string) {
			mkdirAll(t, filepath.Join(root, ".codemeld"))
			if err := os.Symlink(t.TempDir(), projectVCSTemplateDir(root)); err != nil {
				t.Fatalf("symlink: %v", err)
			}
		}},
		{"vcs folder is a regular file", projectVCSTemplateDir, func(t *testing.T, root string) {
			mkdirAll(t, filepath.Join(root, ".codemeld"))
			if err := os.WriteFile(projectVCSTemplateDir(root), []byte("x"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			root := t.TempDir()
			tc.stage(t, root)
			var stderr strings.Builder

			decision := gateTrust(home, root, root, strings.NewReader("y\n"), &stderr, true)

			if decision.Trusted || decision.Reason != trust.ReasonUnreadable {
				t.Fatalf("decision = %#v, want unapproved %q", decision, trust.ReasonUnreadable)
			}
			if strings.Contains(stderr.String(), approvePrompt) {
				t.Fatalf("stderr = %q, want no prompt when presence could not be determined", stderr.String())
			}
			notice := noticeLine(t, stderr.String())
			if want := tc.path(root); !strings.Contains(notice, want) {
				t.Fatalf("notice = %q, want it to name %q", notice, want)
			}
			if strings.Contains(notice, "(") {
				t.Fatalf("notice = %q, want no parenthesised reason", notice)
			}
			trustStoreAbsent(t, home)
		})
	}
}

func TestGateTrust_RecordFailureLeavesTheLaunchUnapprovedAndSaysSo(t *testing.T) {
	home := t.TempDir()
	root := trustProject(t, "model: {}\n")
	storePath := trust.StorePath(home)
	if err := os.MkdirAll(filepath.Dir(storePath), 0o755); err != nil {
		t.Fatalf("mkdir store dir: %v", err)
	}
	malformed := []byte("\tnot: [yaml\n")
	if err := os.WriteFile(storePath, malformed, 0o600); err != nil {
		t.Fatalf("write malformed store: %v", err)
	}
	var stderr strings.Builder

	decision := gateTrust(home, root, root, strings.NewReader("y\n"), &stderr, true)

	if decision.Trusted {
		t.Fatalf("decision = %#v, want an unapproved launch", decision)
	}
	if !strings.Contains(stderr.String(), approvePrompt) {
		t.Fatalf("stderr = %q, want the prompt despite the unreadable store", stderr.String())
	}
	if !strings.Contains(stderr.String(), "could not record approval") {
		t.Fatalf("stderr = %q, want the failed append reported", stderr.String())
	}
	if countNotices(stderr.String()) != 1 {
		t.Fatalf("stderr = %q, want exactly one ignored-settings notice", stderr.String())
	}
	after, err := os.ReadFile(storePath)
	if err != nil || string(after) != string(malformed) {
		t.Fatalf("store bytes = %q (err %v), want the prior bytes untouched", after, err)
	}
}

func TestHeadlessTrustGate_HonorsTheListAndNeverAppends(t *testing.T) {
	for _, listed := range []bool{true, false} {
		t.Run(fmt.Sprintf("listed=%v", listed), func(t *testing.T) {
			home := t.TempDir()
			root := trustProject(t, "model: {}\n")
			if listed {
				approveRoot(t, home, root)
			} else {
				approveRoot(t, home, t.TempDir())
			}
			before, err := os.ReadFile(trust.StorePath(home))
			if err != nil {
				t.Fatalf("read store: %v", err)
			}

			var stderr strings.Builder
			decision := headlessTrustGate(&stderr)(home, root, root)

			if decision.Trusted != listed {
				t.Fatalf("decision = %#v, want approved = %v", decision, listed)
			}
			if strings.Contains(stderr.String(), approvePrompt) {
				t.Fatalf("stderr = %q, want no prompt on a headless run", stderr.String())
			}
			if wantNotices := map[bool]int{true: 0, false: 1}[listed]; countNotices(stderr.String()) != wantNotices {
				t.Fatalf("stderr = %q, want %d ignored-settings notices", stderr.String(), wantNotices)
			}
			after, err := os.ReadFile(trust.StorePath(home))
			if err != nil || string(after) != string(before) {
				t.Fatalf("store bytes = %q (err %v), want them untouched", after, err)
			}
		})
	}
}

func TestHeadlessTrustGate_NoStoreStaysUnapprovedAndWritesNoStore(t *testing.T) {
	home := t.TempDir()
	root := trustProject(t, "model: {}\n")
	writeAgentsFile(t, root, "# repo instructions\n")

	var stderr strings.Builder
	decision := headlessTrustGate(&stderr)(home, root, root)

	if decision.Trusted || decision.Reason != trust.ReasonNoRecord {
		t.Fatalf("decision = %#v, want a root with no answer withheld", decision)
	}
	if countNotices(stderr.String()) != 1 {
		t.Fatalf("stderr = %q, want exactly one ignored-settings notice", stderr.String())
	}
	if !strings.Contains(stderr.String(), projectSettingsPath(root)) {
		t.Fatalf("notice = %q, want the ignored settings file named", stderr.String())
	}
	if strings.Contains(stderr.String(), agentinstr.FileName) {
		t.Fatalf("notice = %q, want no mention of instruction files at all", stderr.String())
	}
	trustStoreAbsent(t, home)
}

func TestHeadlessTrustGate_NothingGatedIsSilent(t *testing.T) {
	home := t.TempDir()
	var stderr strings.Builder
	launchDir := t.TempDir()
	decision := headlessTrustGate(&stderr)(home, launchDir, launchDir)
	if !decision.Trusted || decision.Reason != trust.ReasonNothingCovered {
		t.Fatalf("decision = %#v, want the nothing-to-gate outcome", decision)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want no ignored-settings notice when nothing is withheld", stderr.String())
	}
	trustStoreAbsent(t, home)
}

func TestGateTrust_UnresolvableRootIsNeverPrompted(t *testing.T) {
	home := t.TempDir()
	missing := filepath.Join(t.TempDir(), "gone")
	var stderr strings.Builder

	decision := gateTrust(home, missing, missing, strings.NewReader("y\n"), &stderr, true)

	if decision.Trusted {
		t.Fatalf("decision = %#v, want an unapproved launch", decision)
	}
	if strings.Contains(stderr.String(), approvePrompt) {
		t.Fatalf("stderr = %q, want no prompt for a root no answer could be filed under", stderr.String())
	}
	trustStoreAbsent(t, home)
}

func TestGateTrust_LegacyTrustRecordIsNeitherReadNorModified(t *testing.T) {
	home := t.TempDir()
	root := trustProject(t, "model: {}\n")
	legacy := filepath.Join(filepath.Dir(trust.StorePath(home)), "trust.yaml")
	mkdirAll(t, filepath.Dir(legacy))
	legacyBytes := []byte(fmt.Sprintf("version: 1\nprojects:\n  %s:\n    mode: always\n", mustCanonical(t, root)))
	if err := os.WriteFile(legacy, legacyBytes, 0o600); err != nil {
		t.Fatalf("write legacy record: %v", err)
	}
	legacyInfo, err := os.Stat(legacy)
	if err != nil {
		t.Fatalf("stat legacy record: %v", err)
	}

	var headless strings.Builder
	if decision := headlessTrustGate(&headless)(home, root, root); decision.Trusted {
		t.Fatalf("headless decision = %#v, want the legacy record ignored", decision)
	}
	var stderr strings.Builder
	if decision := gateTrust(home, root, root, strings.NewReader("y\n"), &stderr, true); !decision.Trusted {
		t.Fatalf("decision = %#v, want the answered launch approved", decision)
	}

	after, err := os.ReadFile(legacy)
	if err != nil || string(after) != string(legacyBytes) {
		t.Fatalf("legacy bytes = %q (err %v), want them untouched", after, err)
	}
	afterInfo, err := os.Stat(legacy)
	if err != nil || !afterInfo.ModTime().Equal(legacyInfo.ModTime()) {
		t.Fatalf("legacy mtime = %v (err %v), want %v", afterInfo.ModTime(), err, legacyInfo.ModTime())
	}
}

func mkdirAll(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	return dir
}

func TestGateTrust_InstructionOnlyProjectIsNotGated(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	writeAgentsFile(t, root, "# repo instructions\n")
	var stderr strings.Builder

	decision := gateTrust(home, root, root, strings.NewReader("\n"), &stderr, true)

	if !decision.Trusted || decision.Reason != trust.ReasonNothingCovered {
		t.Fatalf("decision = %#v, want a project holding only AGENTS.md to have nothing to gate", decision)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want nothing printed", stderr.String())
	}
	trustStoreAbsent(t, home)
}

func TestHeadlessFreshSteps_InstructionDiscoveryIsIndependentOfTheTrustDecision(t *testing.T) {
	for _, tc := range []struct {
		name    string
		record  bool
		trusted bool
		notices int
	}{
		{name: "no record", trusted: false, notices: 1},
		{name: "listed root", record: true, trusted: true, notices: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAgentsFixture(t)
			writeProjectSettings(t, f.root, "model: {}\n")
			if tc.record {
				approveRoot(t, f.home, f.root)
			}
			store := storeAt(t, filepath.Join(t.TempDir(), "session.json"),
				"01890000-0000-7000-8000-000000002513", f.root)

			var stderr strings.Builder
			steps := HeadlessFreshSteps(&stderr, nil, "")
			decision := steps.GateTrust(f.home, f.root, f.launch)
			if decision.Trusted != tc.trusted {
				t.Fatalf("decision = %#v, want trusted = %v", decision, tc.trusted)
			}

			entries, err := steps.LoadAgentInstructions(context.Background(), store, f.home, f.launch, nil, f.root, nil, agentinstr.Selection{})
			if err != nil {
				t.Fatalf("LoadAgentInstructions: %v", err)
			}
			for _, path := range f.repoFiles() {
				findLoadEntry(t, entries, path)
			}
			durable := map[string]bool{}
			for _, rec := range diskAgentInstr(t, readSessionFile(t, store.Path())) {
				durable[rec.Path] = true
			}
			for _, path := range f.repoFiles() {
				if !durable[path] {
					t.Fatalf("durable records = %v, want the repository's %s among them", durable, path)
				}
			}
			if countNotices(stderr.String()) != tc.notices {
				t.Fatalf("stderr = %q, want %d ignored-settings notices", stderr.String(), tc.notices)
			}
		})
	}
}

func writeProjectTemplate(t *testing.T, root, name, content string) {
	t.Helper()
	dir := projectVCSTemplateDir(root)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir project vcs dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write project template: %v", err)
	}
}

func writeLocalProjectSettings(t *testing.T, root, content string) {
	t.Helper()
	path := config.LocalSettingsPath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir project settings parent: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write local project settings: %v", err)
	}
}

func TestAskTrust_PromptMatchesThePresentGatedInputs(t *testing.T) {
	settingsOnly := "This folder has its own codemeld settings, which can let commands run and files be changed without asking you.\n" +
		"If you say no, codemeld still runs but ignores those settings.\n"
	vcsOnly := "This folder has its own version-control commands for codemeld, which can let commands run without asking you.\n" +
		"If you say no, codemeld still runs but ignores those commands.\n"
	both := "This folder has its own codemeld settings and version-control commands, which can let commands run and files be changed without asking you.\n" +
		"If you say no, codemeld still runs but ignores those settings and commands.\n"
	cases := []struct {
		name               string
		shared, local, vcs bool
		body               string
	}{
		{"shared settings only", true, false, false, settingsOnly},
		{"local settings only", false, true, false, settingsOnly},
		{"vcs only", false, false, true, vcsOnly},
		{"all three", true, true, true, both},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.shared {
				writeProjectSettings(t, root, "model: {}\n")
			}
			if tc.local {
				writeLocalProjectSettings(t, root, "model: {}\n")
			}
			if tc.vcs {
				mkdirAll(t, projectVCSTemplateDir(root))
			}
			present, determinate := presentGatedPaths(root)
			if !determinate {
				t.Fatalf("presentGatedPaths(%s) is indeterminate", root)
			}

			var stderr strings.Builder
			askTrust(strings.NewReader("n\n"), &stderr, root, present)

			want := "Do you trust " + root + "?\n" + tc.body + "Trust this folder? [y/N] "
			if stderr.String() != want {
				t.Fatalf("prompt = %q, want %q", stderr.String(), want)
			}
		})
	}
}

func TestNoticeUntrustedProject_NamesEveryWithheldInputWithoutACount(t *testing.T) {
	for _, tc := range []struct {
		name      string
		templates int
	}{
		{"template folder present", 2},
		{"template folder absent", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			root := trustProject(t, "model: {}\n")
			for i := range tc.templates {
				writeProjectTemplate(t, root, fmt.Sprintf("v%d.yaml", i), "status:\n  argv: [hg, status]\n")
			}

			var stderr strings.Builder
			gateTrust(home, root, root, strings.NewReader("n\n"), &stderr, true)
			notice := noticeLine(t, stderr.String())

			if countNotices(stderr.String()) != 1 {
				t.Fatalf("stderr = %q, want exactly one degraded-launch notice", stderr.String())
			}
			if !strings.Contains(notice, projectSettingsPath(root)) {
				t.Fatalf("notice = %q, want it to name %q", notice, projectSettingsPath(root))
			}
			if named := strings.Contains(notice, projectVCSTemplateDir(root)); named != (tc.templates > 0) {
				t.Fatalf("notice = %q, names the VCS folder = %v, want %v", notice, named, tc.templates > 0)
			}
			if strings.ContainsAny(notice, "0123456789") && strings.Contains(notice, " 2 ") {
				t.Fatalf("notice = %q, want no file count", notice)
			}
			if strings.Contains(notice, "(") {
				t.Fatalf("notice = %q, want no parenthesised reason", notice)
			}
		})
	}
}

func TestWithheldInputs_NamesOnlyGatedPathsThatAreThere(t *testing.T) {
	root := t.TempDir()
	if got := withheldInputs(root, false); got != nil {
		t.Fatalf("WithheldInputs = %#v, want nothing while every gated path is absent", got)
	}
	if err := os.MkdirAll(projectSettingsPath(root), 0o755); err != nil {
		t.Fatalf("mkdir non-regular settings path: %v", err)
	}
	assertWithheldSummary(t, withheldInputs(root, false), root)
	writeProjectTemplate(t, root, "git.yaml", "status:\n  argv: [git, status]\n")
	if err := os.WriteFile(config.LocalSettingsPath(root), []byte("model: {}\n"), 0o600); err != nil {
		t.Fatalf("write local settings: %v", err)
	}
	want := []WithheldInput{
		{Category: WithheldSettings, Path: projectSettingsPath(root)},
		{Category: WithheldSettings, Path: config.LocalSettingsPath(root)},
		{Category: WithheldVCSTemplates, Path: projectVCSTemplateDir(root)},
	}
	if got := withheldInputs(root, false); !slices.Equal(got, want) {
		t.Fatalf("WithheldInputs = %#v, want %#v", got, want)
	}
	if got := withheldInputs(root, true); got != nil {
		t.Fatalf("WithheldInputs = %#v, want nothing withheld on an approved launch", got)
	}
}

// The notice follows the prompt on the same line, since the prompt deliberately ends without a
// newline, so it is located by prefix rather than by splitting lines.
func noticeLine(t *testing.T, stderr string) string {
	t.Helper()
	at := strings.Index(stderr, "codemeld: unapproved project ")
	if at < 0 {
		t.Fatalf("stderr = %q, want a degraded-launch notice", stderr)
	}
	return strings.SplitN(stderr[at:], "\n", 2)[0]
}

func TestHeadlessTrustGate_ListDecidesWhetherProjectTemplatesAreAdmitted(t *testing.T) {
	cases := []struct {
		name    string
		record  bool
		trusted bool
	}{
		{"listed root admits", true, true},
		{"unlisted root withholds", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			root := trustProject(t, "model: {}\n")
			writeFullTemplate(t, filepath.Join(projectVCSTemplateDir(root), "git.yaml"), "git", false, "", "PROJECT")
			if tc.record {
				approveRoot(t, home, root)
			}

			var stderr strings.Builder
			decision := headlessTrustGate(&stderr)(home, root, root)
			if decision.Trusted != tc.trusted {
				t.Fatalf("decision = %#v, want trusted = %v", decision, tc.trusted)
			}
			if strings.Contains(stderr.String(), approvePrompt) {
				t.Fatalf("stderr = %q, want no headless prompt", stderr.String())
			}
			if !tc.record {
				trustStoreAbsent(t, home)
			}

			payload := loadWith(t, t.TempDir(), root, decision.Trusted)
			argv := payload.templates["git"].Actions["status"].Argv
			gotOverride := len(argv) == 2 && argv[1] == "PROJECT"
			if gotOverride != tc.trusted {
				t.Fatalf("git status argv = %v, want the project override admitted = %v", argv, tc.trusted)
			}
		})
	}
}

func TestProtectedStatePolicy_RefusesTheLocalSettingsFile(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	local := config.LocalSettingsPath(project)
	seedProtectedSettings(t, local)

	policy := mustProtectedStatePolicy(t, home, project, nil)
	got := policy.RefuseNominal(filetools.EditToolName, map[string]any{"path": local}, home, project)
	if got == nil {
		t.Fatalf("edit on %q was not refused as protected state", local)
	}
	if got.Envelope != permissions.BuildGuardDenyEnvelope() {
		t.Errorf("Envelope = %q, want the fixed guard envelope", got.Envelope)
	}
	if got.Source != "protected_state" {
		t.Errorf("Source = %q, want protected_state", got.Source)
	}
}
