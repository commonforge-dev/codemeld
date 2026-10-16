// Tests for the embedded built-in VCS templates: byte snapshots, action/placeholder shape, and the accessors.
package builtin

import (
	"testing"

	"github.com/goccy/go-yaml"
)

// requiredActions is the full set of actions every template must define.
var requiredActions = []string{
	"detect", "status", "diff", "add", "commit", "log",
	"branch-current", "branch-create", "branch-switch", "restore-file",
	"is-clean", "stash", "stash-pop", "merge-status", "rebase-status",
}

// placeholderActions maps each action to the one placeholder it must carry;
// any action absent here must contain no placeholder at all.
var placeholderActions = map[string]string{
	"add":           "{path}",
	"restore-file":  "{path}",
	"commit":        "{message}",
	"branch-create": "{branch}",
	"branch-switch": "{branch}",
}

var allPlaceholders = []string{"{path}", "{message}", "{branch}"}

var expectedMarkers = map[string]string{
	"git": ".git",
	"hg":  ".hg",
	"jj":  ".jj",
}

func TestBuiltinNames_CanonicalOrder(t *testing.T) {
	got := BuiltinNames()
	want := []string{"git", "hg", "jj"}
	if len(got) != len(want) {
		t.Fatalf("BuiltinNames() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("BuiltinNames()[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestBuiltinNames_ReturnsFreshSlice(t *testing.T) {
	first := BuiltinNames()
	first[0] = "mutated"
	if second := BuiltinNames(); second[0] != "git" {
		t.Fatalf("BuiltinNames() shares backing array; second call returned %v", second)
	}
}

func TestBuiltinTemplate_UnknownNameNotOK(t *testing.T) {
	for _, name := range []string{"", "svn", "Git", "git.yaml", "../git", "fossil"} {
		if data, ok := BuiltinTemplate(name); ok || data != nil {
			t.Errorf("BuiltinTemplate(%q) = (%q, %v), want (nil, false)", name, data, ok)
		}
	}
}

func TestBuiltinTemplate_ReturnsFreshCopy(t *testing.T) {
	a, ok := BuiltinTemplate("git")
	if !ok {
		t.Fatal("BuiltinTemplate(git) not ok")
	}
	a[0] = 0
	b, _ := BuiltinTemplate("git")
	if b[0] == 0 {
		t.Fatal("BuiltinTemplate returns slice aliasing embedded bytes; mutation leaked")
	}
}

func TestBuiltinTemplates_ParseAsYAML(t *testing.T) {
	for _, name := range BuiltinNames() {
		data, ok := BuiltinTemplate(name)
		if !ok {
			t.Fatalf("BuiltinTemplate(%q) not ok", name)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Errorf("%s.yaml does not parse as a YAML map: %v", name, err)
		}
	}
}

func TestBuiltinTemplates_AllRequiredActionsPresent(t *testing.T) {
	for _, name := range BuiltinNames() {
		doc := mustParse(t, name)
		if len(doc) != len(requiredActions) {
			t.Errorf("%s.yaml has %d top-level keys, want exactly %d", name, len(doc), len(requiredActions))
		}
		for _, action := range requiredActions {
			if _, present := doc[action]; !present {
				t.Errorf("%s.yaml missing required action %q", name, action)
			}
		}
	}
}

func TestBuiltinTemplates_DetectMarkerOnly(t *testing.T) {
	for _, name := range BuiltinNames() {
		doc := mustParse(t, name)
		detect, ok := doc["detect"].(map[string]any)
		if !ok {
			t.Errorf("%s.yaml: detect is not a map", name)
			continue
		}
		if len(detect) != 1 {
			t.Errorf("%s.yaml: detect has %d keys, want only 'marker'", name, len(detect))
		}
		marker, ok := detect["marker"].(string)
		if !ok {
			t.Errorf("%s.yaml: detect.marker is not a string", name)
			continue
		}
		if marker != expectedMarkers[name] {
			t.Errorf("%s.yaml: detect.marker = %q, want %q", name, marker, expectedMarkers[name])
		}
	}
}

func TestBuiltinTemplates_ActionBodyShapeAndPlaceholders(t *testing.T) {
	for _, name := range BuiltinNames() {
		doc := mustParse(t, name)
		for _, action := range requiredActions {
			if action == "detect" {
				continue
			}
			body, ok := doc[action].(map[string]any)
			if !ok {
				t.Errorf("%s.yaml: action %q is not a map", name, action)
				continue
			}
			for key := range body {
				if key != "argv" && key != "cwd" {
					t.Errorf("%s.yaml: action %q has disallowed key %q (only argv/cwd permitted)", name, action, key)
				}
			}
			rawArgv, ok := body["argv"]
			if !ok {
				t.Errorf("%s.yaml: action %q missing required argv", name, action)
				continue
			}
			argv, ok := rawArgv.([]any)
			if !ok || len(argv) == 0 {
				t.Errorf("%s.yaml: action %q argv must be a non-empty list, got %T", name, action, rawArgv)
				continue
			}
			joined := ""
			for _, elem := range argv {
				s, ok := elem.(string)
				if !ok {
					t.Errorf("%s.yaml: action %q argv has non-string element %v (%T)", name, action, elem, elem)
					continue
				}
				joined += s + "\x00"
			}

			want, wantsPlaceholder := placeholderActions[action]
			for _, ph := range allPlaceholders {
				present := contains(joined, ph)
				switch {
				case wantsPlaceholder && ph == want && !present:
					t.Errorf("%s.yaml: action %q must contain placeholder %s but does not", name, action, ph)
				case present && (!wantsPlaceholder || ph != want):
					t.Errorf("%s.yaml: action %q contains placeholder %s it must not accept", name, action, ph)
				}
			}
		}
	}
}

func mustParse(t *testing.T, name string) map[string]any {
	t.Helper()
	data, ok := BuiltinTemplate(name)
	if !ok {
		t.Fatalf("BuiltinTemplate(%q) not ok", name)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("%s.yaml parse: %v", name, err)
	}
	return doc
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// Each constant below is an independent copy of the corresponding embedded
// template. Drift between the .yaml file and this literal fails the snapshot
// test and must be reviewed, since these are the exact bytes users see on disk.

const expectedGit = `# codemeld built-in VCS template: git.
#
# Materialized to ~/.codemeld/global/vcs/git.yaml on first run as a complete,
# copy-and-modify reference. Each top-level key is one VCS action. 'detect' uses
# a single 'marker' key; every other action uses 'argv' (run directly, with no
# shell) and an optional 'cwd'. The placeholders {path}, {message}, and {branch}
# are substituted before the command runs.

detect:
  marker: .git

status:
  argv: [git, status, --short]

diff:
  argv: [git, diff]

add:
  argv: [git, add, "{path}"]

commit:
  argv: [git, commit, -m, "{message}"]

log:
  argv: [git, log, --oneline, -n, "20"]

branch-current:
  argv: [git, branch, --show-current]

branch-create:
  argv: [git, branch, "{branch}"]

branch-switch:
  argv: [git, switch, "{branch}"]

restore-file:
  argv: [git, restore, "{path}"]

is-clean:
  argv: [git, status, --porcelain]

stash:
  argv: [git, stash, push]

stash-pop:
  argv: [git, stash, pop]

# Probe-only: report whether a merge is in progress; never start/continue/abort.
merge-status:
  argv: [git, rev-parse, --verify, --quiet, MERGE_HEAD]

# Probe-only: report whether a rebase is in progress; never start/continue/abort.
rebase-status:
  argv: [git, rev-parse, --verify, --quiet, REBASE_HEAD]
`

const expectedHg = `# codemeld built-in VCS template: hg (Mercurial).
#
# Materialized to ~/.codemeld/global/vcs/hg.yaml on first run as a complete,
# copy-and-modify reference. Each top-level key is one VCS action. 'detect' uses
# a single 'marker' key; every other action uses 'argv' (run directly, with no
# shell) and an optional 'cwd'. The placeholders {path}, {message}, and {branch}
# are substituted before the command runs.

detect:
  marker: .hg

status:
  argv: [hg, status]

diff:
  argv: [hg, diff]

add:
  argv: [hg, add, "{path}"]

commit:
  argv: [hg, commit, -m, "{message}"]

log:
  argv: [hg, log, --limit, "20"]

branch-current:
  argv: [hg, branch]

branch-create:
  argv: [hg, branch, "{branch}"]

branch-switch:
  argv: [hg, update, "{branch}"]

restore-file:
  argv: [hg, revert, "{path}"]

is-clean:
  argv: [hg, status]

stash:
  argv: [hg, shelve]

stash-pop:
  argv: [hg, unshelve]

# Probe-only: list unresolved merge files; never start/continue/abort a merge.
merge-status:
  argv: [hg, resolve, --list]

# Probe-only: report interrupted operations such as an in-progress rebase.
rebase-status:
  argv: [hg, summary]
`

const expectedJj = `# codemeld built-in VCS template: jj (Jujutsu).
#
# Materialized to ~/.codemeld/global/vcs/jj.yaml on first run as a complete,
# copy-and-modify reference. Each top-level key is one VCS action. 'detect' uses
# a single 'marker' key; every other action uses 'argv' (run directly, with no
# shell) and an optional 'cwd'. The placeholders {path}, {message}, and {branch}
# are substituted before the command runs.
#
# Jujutsu's model differs from git/hg: the working copy is always a commit and
# branches are "bookmarks". The actions below map onto the nearest jj concept;
# a few (stash/stash-pop) have no direct equivalent and report state instead.
# Edit this file to match your workflow.

detect:
  marker: .jj

status:
  argv: [jj, status]

diff:
  argv: [jj, diff]

add:
  argv: [jj, file, track, "{path}"]

commit:
  argv: [jj, commit, -m, "{message}"]

log:
  argv: [jj, log, --limit, "20"]

branch-current:
  argv: [jj, bookmark, list]

branch-create:
  argv: [jj, bookmark, create, "{branch}"]

branch-switch:
  argv: [jj, edit, "{branch}"]

restore-file:
  argv: [jj, restore, "{path}"]

is-clean:
  argv: [jj, diff, --stat]

# No stash in jj: the working copy is already a commit. Reports state instead.
stash:
  argv: [jj, status]

# No stash-pop in jj. Reports state instead; edit if your workflow needs one.
stash-pop:
  argv: [jj, status]

# Probe-only: conflicts are recorded in commits; jj status reports them.
merge-status:
  argv: [jj, status]

# Probe-only: jj has no interrupted-rebase state; jj status reports it.
rebase-status:
  argv: [jj, status]
`

func TestBuiltinTemplates_ByteSnapshot(t *testing.T) {
	cases := map[string]string{"git": expectedGit, "hg": expectedHg, "jj": expectedJj}
	for name, want := range cases {
		data, ok := BuiltinTemplate(name)
		if !ok {
			t.Fatalf("BuiltinTemplate(%q) not ok", name)
		}
		if got := string(data); got != want {
			t.Errorf("%s.yaml byte snapshot drift\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
		}
	}
}
