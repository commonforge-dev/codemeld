package securitystate

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/locks"
)

const baseGlobal = `provider:
  acme:
    base_url: https://api.acme.test
    api_key: global-key
`

func seedLayer(t *testing.T, kind LayerKind, path, content string) LayerSnapshot {
	t.Helper()
	mkdirAll(t, filepath.Dir(path))
	writeFile(t, path, content)
	raw, cat, err := validate(kind, []byte(content), path)
	if cat != config.LoadOK {
		t.Fatalf("fixture must validate as a %s layer: %v", kind, err)
	}
	return LayerSnapshot{Kind: kind, Path: path, Present: true, Raw: raw}
}

func globalPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "global", "settings.yaml")
}

// rewrite replaces a layer's content after the baseline was taken, standing in for an edit
// made outside codemeld's own writers.
func rewrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("rewrite %s: %v", path, err)
	}
}

func only(t *testing.T, results []Result) Result {
	t.Helper()
	if len(results) != 1 {
		t.Fatalf("results = %#v, want exactly one", results)
	}
	return results[0]
}

func checkpointAfter(t *testing.T, kind LayerKind, before, after string) Result {
	t.Helper()
	path := globalPath(t)
	m := NewMonitor([]LayerSnapshot{seedLayer(t, kind, path, before)})
	rewrite(t, path, after)
	return only(t, m.Checkpoint())
}

func TestMonitor_UsesTheProductionSidecarLockTimeout(t *testing.T) {
	m := NewMonitor([]LayerSnapshot{seedLayer(t, LayerGlobal, globalPath(t), baseGlobal)})
	if m.lockTimeout != 2*time.Second {
		t.Fatalf("lockTimeout = %v, want the 2s protocol every protected writer uses", m.lockTimeout)
	}
}

func TestMonitor_UnchangedLayersProduceNoDrift(t *testing.T) {
	global := seedLayer(t, LayerGlobal, globalPath(t), baseGlobal)
	project := seedLayer(t, LayerProject, filepath.Join(t.TempDir(), ".codemeld", "settings.yaml"),
		"permissions:\n  - kind: direct\n    subject: ls\n    path_scope: /home/u\n    grant_kind: folder\n")

	if results := NewMonitor([]LayerSnapshot{global, project}).Checkpoint(); len(results) != 0 {
		t.Fatalf("results = %#v, want none for unchanged layers", results)
	}
}

func TestMonitor_AdmittedAbsentProjectLayerIsCleanThenComparedOnCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".codemeld", "settings.yaml")
	mkdirAll(t, filepath.Dir(path))
	m := NewMonitor([]LayerSnapshot{{Kind: LayerProject, Path: path}})

	if results := m.Checkpoint(); len(results) != 0 {
		t.Fatalf("results = %#v, want none while the admitted path is still absent", results)
	}

	writeFile(t, path, "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: /home/u\n    grant_kind: folder\n")
	result := only(t, m.Checkpoint())
	if !slices.Equal(result.Labels, []Label{LabelAdded}) || !slices.Equal(result.Sections, []Section{SectionPermissions}) {
		t.Fatalf("result = %#v, want the created file compared semantically", result)
	}
}

func TestMonitor_IgnoredLayerIsNeverOpenedOrLocked(t *testing.T) {
	ignored := filepath.Join(t.TempDir(), ".codemeld", "settings.yaml")
	mkdirAll(t, filepath.Dir(ignored))
	writeFile(t, ignored, "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: /home/u\n    grant_kind: folder\n")

	globalFile := globalPath(t)
	m := NewMonitor([]LayerSnapshot{
		seedLayer(t, LayerGlobal, globalFile, baseGlobal),
		{Kind: LayerProject, Path: ignored, Ignored: true},
	})
	rewrite(t, globalFile, strings.Replace(baseGlobal, "global-key", "rotated", 1))

	result := only(t, m.Checkpoint())
	if result.Kind != LayerGlobal {
		t.Fatalf("result = %#v, want only the admitted global layer", result)
	}
	if _, err := os.Stat(ignored + lockSuffix); !os.IsNotExist(err) {
		t.Fatalf("stat ignored sidecar = %v, want the ignored layer never locked", err)
	}
}

func TestMonitor_BothLayersReturnSeparateOrderedResults(t *testing.T) {
	globalFile := globalPath(t)
	projectFile := filepath.Join(t.TempDir(), ".codemeld", "settings.yaml")
	m := NewMonitor([]LayerSnapshot{
		seedLayer(t, LayerGlobal, globalFile, baseGlobal),
		seedLayer(t, LayerProject, projectFile, "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: /home/u\n    grant_kind: folder\n"),
	})
	rewrite(t, globalFile, strings.Replace(baseGlobal, "global-key", "rotated", 1))
	rewrite(t, projectFile, "permissions:\n  - kind: direct\n    subject: cat\n    path_scope: /home/u\n    grant_kind: folder\n")

	results := m.Checkpoint()
	if len(results) != 2 {
		t.Fatalf("results = %#v, want one per affected layer", results)
	}
	if results[0].Kind != LayerGlobal || results[0].Path != globalFile {
		t.Fatalf("results[0] = %#v, want the global layer first", results[0])
	}
	if results[1].Kind != LayerProject || results[1].Path != projectFile {
		t.Fatalf("results[1] = %#v, want the project layer second", results[1])
	}
}

func TestMonitor_PermissionCorrespondence(t *testing.T) {
	const one = "  - kind: direct\n    subject: ls\n    path_scope: /home/u\n    grant_kind: folder\n"
	const two = "  - kind: direct\n    subject: cat\n    path_scope: /home/u\n    grant_kind: folder\n"
	const rescoped = "  - kind: direct\n    subject: ls\n    path_scope: /home/other\n    grant_kind: folder\n"
	list := func(entries ...string) string { return "permissions:\n" + strings.Join(entries, "") }

	tests := []struct {
		name          string
		before, after string
		want          []Label
	}{
		{"addition", list(one), list(one, two), []Label{LabelAdded}},
		{"removal", list(one, two), list(one), []Label{LabelRemoved}},
		{"reorder", list(one, two), list(two, one), []Label{LabelChanged}},
		{
			name:   "authorization-bearing field replacement",
			before: list(one),
			after:  list(rescoped),
			want:   []Label{LabelAdded, LabelRemoved},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkpointAfter(t, LayerGlobal, tt.before, tt.after)
			if !slices.Equal(result.Labels, tt.want) {
				t.Fatalf("labels = %v, want %v", result.Labels, tt.want)
			}
			if !slices.Equal(result.Sections, []Section{SectionPermissions}) {
				t.Fatalf("sections = %v, want only %q", result.Sections, SectionPermissions)
			}
		})
	}
}

func TestMonitor_ProtectedSectionsAndSecretContainment(t *testing.T) {
	const before = `auth:
  openai-chatgpt:
    access_token: at-1
    refresh_token: rt-1
    expires_at: "2030-01-01T00:00:00Z"
    account_id: acct-1
provider:
  acme:
    base_url: https://api.acme.test
    api_key: acme-key
    auth_header:
      name: X-Acme
      value: header-secret
web_research:
  api_key: exa-key
`
	tests := []struct {
		name     string
		after    string
		sections []Section
		labels   []Label
	}{
		{
			name:     "auth record change",
			after:    strings.Replace(before, "at-1", "at-2", 1),
			sections: []Section{SectionAuth},
			labels:   []Label{LabelChanged},
		},
		{
			name:     "provider destination change",
			after:    strings.Replace(before, "https://api.acme.test", "https://api.evil.test", 1),
			sections: []Section{SectionProviderDestination},
			labels:   []Label{LabelChanged},
		},
		{
			name:     "provider credential change",
			after:    strings.Replace(before, "acme-key", "rotated-key", 1),
			sections: []Section{SectionProviderCredential},
			labels:   []Label{LabelChanged},
		},
		{
			name:     "auth header name change",
			after:    strings.Replace(before, "X-Acme", "X-Other", 1),
			sections: []Section{SectionProviderAuthHeader},
			labels:   []Label{LabelChanged},
		},
		{
			name:     "auth header value change",
			after:    strings.Replace(before, "header-secret", "other-secret", 1),
			sections: []Section{SectionProviderAuthHeader},
			labels:   []Label{LabelChanged},
		},
		{
			name:     "web research credential change",
			after:    strings.Replace(before, "exa-key", "rotated-exa", 1),
			sections: []Section{SectionWebResearchCredential},
			labels:   []Label{LabelChanged},
		},
		{
			name:     "provider rename",
			after:    strings.Replace(before, "  acme:", "  acme-renamed:", 1),
			sections: []Section{SectionProviderDestination, SectionProviderCredential, SectionProviderAuthHeader},
			labels:   []Label{LabelAdded, LabelRemoved},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkpointAfter(t, LayerGlobal, before, tt.after)
			if !slices.Equal(result.Sections, tt.sections) {
				t.Fatalf("sections = %v, want %v", result.Sections, tt.sections)
			}
			if !slices.Equal(result.Labels, tt.labels) {
				t.Fatalf("labels = %v, want %v", result.Labels, tt.labels)
			}
			assertNoSecrets(t, result)
		})
	}
}

// A declared command runs in Auto posture with no prompt, so editing the list on disk changes
// what is authorized exactly as editing a grant does.
func TestMonitor_DeclaredCommandDrift(t *testing.T) {
	const before = `declared_commands:
  - prep-open-tasks.sh --only
  - sed -n
`
	tests := []struct {
		name   string
		after  string
		labels []Label
	}{
		{
			name:   "entry added",
			after:  before + "  - ./dira\n",
			labels: []Label{LabelAdded},
		},
		{
			name:   "entry removed",
			after:  strings.Replace(before, "  - sed -n\n", "", 1),
			labels: []Label{LabelRemoved},
		},
		{
			name:   "entry widened to cover more invocations",
			after:  strings.Replace(before, "prep-open-tasks.sh --only", "prep-open-tasks.sh", 1),
			labels: []Label{LabelAdded, LabelRemoved},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkpointAfter(t, LayerProject, before, tt.after)
			if !slices.Equal(result.Sections, []Section{SectionDeclaredCommands}) {
				t.Fatalf("sections = %v, want only %q", result.Sections, SectionDeclaredCommands)
			}
			if !slices.Equal(result.Labels, tt.labels) {
				t.Fatalf("labels = %v, want %v", result.Labels, tt.labels)
			}
		})
	}
}

func TestMonitor_DeclaredCommandReorderIsNotDrift(t *testing.T) {
	const before = `declared_commands:
  - prep-open-tasks.sh --only
  - sed -n
`
	const after = `declared_commands:
  - sed -n
  - prep-open-tasks.sh --only
`
	path := globalPath(t)
	m := NewMonitor([]LayerSnapshot{seedLayer(t, LayerProject, path, before)})
	rewrite(t, path, after)

	if results := m.Checkpoint(); len(results) != 0 {
		t.Fatalf("results = %#v, want none: every declared entry is tried, so their order authorizes nothing", results)
	}
}

func TestMonitor_BlockedPathDrift(t *testing.T) {
	const before = `blocked_paths:
  - "~/.ssh"
  - /data/secrets
`
	tests := []struct {
		name   string
		after  string
		labels []Label
	}{
		{
			name:   "entry added",
			after:  before + "  - \"~/.docker/config.json\"\n",
			labels: []Label{LabelAdded},
		},
		{
			name:   "entry removed",
			after:  strings.Replace(before, "  - /data/secrets\n", "", 1),
			labels: []Label{LabelRemoved},
		},
		{
			name:   "entry changed",
			after:  strings.Replace(before, "/data/secrets", "/data/secrets/keys", 1),
			labels: []Label{LabelAdded, LabelRemoved},
		},
	}
	for _, kind := range []LayerKind{LayerProject, LayerGlobal} {
		for _, tt := range tests {
			t.Run(string(kind)+" "+tt.name, func(t *testing.T) {
				result := checkpointAfter(t, kind, before, tt.after)
				if !slices.Equal(result.Sections, []Section{SectionBlockedPaths}) {
					t.Fatalf("sections = %v, want only %q", result.Sections, SectionBlockedPaths)
				}
				if !slices.Equal(result.Labels, tt.labels) {
					t.Fatalf("labels = %v, want %v", result.Labels, tt.labels)
				}
			})
		}
	}
}

func TestMonitor_BlockedPathReorderIsNotDrift(t *testing.T) {
	const before = `blocked_paths:
  - "~/.ssh"
  - /data/secrets
`
	const after = `blocked_paths:
  - /data/secrets
  - "~/.ssh"
`
	for _, kind := range []LayerKind{LayerProject, LayerGlobal} {
		t.Run(string(kind), func(t *testing.T) {
			path := globalPath(t)
			m := NewMonitor([]LayerSnapshot{seedLayer(t, kind, path, before)})
			rewrite(t, path, after)

			if results := m.Checkpoint(); len(results) != 0 {
				t.Fatalf("results = %#v, want none: every blocked path applies, so their order blocks nothing more", results)
			}
		})
	}
}

func TestMonitor_WritableFolderDrift(t *testing.T) {
	const before = `writable_folders:
  - /data/build
  - "~/scratch"
`
	tests := []struct {
		name   string
		after  string
		labels []Label
	}{
		{
			name:   "entry added",
			after:  before + "  - /data/cache\n",
			labels: []Label{LabelAdded},
		},
		{
			name:   "entry removed",
			after:  strings.Replace(before, "  - /data/build\n", "", 1),
			labels: []Label{LabelRemoved},
		},
		{
			name:   "entry replaced with a wider folder",
			after:  strings.Replace(before, "/data/build", "/data", 1),
			labels: []Label{LabelAdded, LabelRemoved},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkpointAfter(t, LayerProject, before, tt.after)
			if !slices.Equal(result.Sections, []Section{SectionWritableFolders}) {
				t.Fatalf("sections = %v, want only %q", result.Sections, SectionWritableFolders)
			}
			if !slices.Equal(result.Labels, tt.labels) {
				t.Fatalf("labels = %v, want %v", result.Labels, tt.labels)
			}
		})
	}
}

func TestMonitor_WritableFolderReorderIsNotDrift(t *testing.T) {
	const before = `writable_folders:
  - /data/build
  - "~/scratch"
`
	const after = `writable_folders:
  - "~/scratch"
  - /data/build
`
	path := globalPath(t)
	m := NewMonitor([]LayerSnapshot{seedLayer(t, LayerProject, path, before)})
	rewrite(t, path, after)

	if results := m.Checkpoint(); len(results) != 0 {
		t.Fatalf("results = %#v, want none: every writable folder applies, so their order authorizes nothing", results)
	}
}

// The result is the record an investigator reads, so nothing that names the account, the
// vendor, or any credential may reach it.
func assertNoSecrets(t *testing.T, result Result) {
	t.Helper()
	rendered := string(result.Kind) + " " + result.Path + " " + string(result.Reason)
	for _, section := range result.Sections {
		rendered += " " + string(section)
	}
	for _, label := range result.Labels {
		rendered += " " + string(label)
	}
	for _, secret := range []string{"acme", "at-1", "at-2", "rt-1", "acct-1", "header-secret", "exa-key", "rotated", "api.acme.test", "X-Acme"} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("result %q exposes %q", rendered, secret)
		}
	}
}

func TestMonitor_WebResearchDriftKeysOnlyOnTheAPIKey(t *testing.T) {
	const bare = "agent:\n  max_concurrency: 2\n"
	const enabled = bare + "web_research:\n  enabled: true\n"
	const disabled = bare + "web_research:\n  enabled: false\n"
	const emptyKey = bare + "web_research:\n  enabled: false\n  api_key: \"\"\n"

	quiet := []struct{ name, before, after string }{
		{"block appears with no api_key", bare, enabled},
		{"block disappears with no api_key", enabled, bare},
		{"enabled toggled", disabled, enabled},
	}
	for _, tt := range quiet {
		t.Run(tt.name, func(t *testing.T) {
			path := globalPath(t)
			m := NewMonitor([]LayerSnapshot{seedLayer(t, LayerGlobal, path, tt.before)})
			rewrite(t, path, tt.after)
			if results := m.Checkpoint(); len(results) != 0 {
				t.Fatalf("results = %#v, want none for a web_research change that touches no api_key", results)
			}
		})
	}

	protected := []struct {
		name, before, after string
		want                Label
	}{
		{"absent to empty api_key", disabled, emptyKey, LabelAdded},
		{"empty api_key to absent", emptyKey, disabled, LabelRemoved},
		{"no block to empty api_key", bare, emptyKey, LabelAdded},
	}
	for _, tt := range protected {
		t.Run(tt.name, func(t *testing.T) {
			result := checkpointAfter(t, LayerGlobal, tt.before, tt.after)
			if !slices.Equal(result.Labels, []Label{tt.want}) {
				t.Fatalf("labels = %v, want %v", result.Labels, []Label{tt.want})
			}
			if !slices.Equal(result.Sections, []Section{SectionWebResearchCredential}) {
				t.Fatalf("sections = %v, want only %q", result.Sections, SectionWebResearchCredential)
			}
		})
	}
}

func TestMonitor_OneEditAcrossSeveralSectionsKeepsFixedOrder(t *testing.T) {
	const before = `permissions:
  - kind: direct
    subject: ls
    path_scope: /home/u
    grant_kind: folder
provider:
  acme:
    base_url: https://api.acme.test
    api_key: acme-key
web_research:
  api_key: exa-key
`
	const after = `permissions:
  - kind: direct
    subject: ls
    path_scope: /home/u
    grant_kind: folder
  - kind: direct
    subject: cat
    path_scope: /home/u
    grant_kind: folder
provider:
  acme:
    base_url: https://api.acme.test
    api_key: rotated
`
	result := checkpointAfter(t, LayerGlobal, before, after)
	wantSections := []Section{SectionPermissions, SectionProviderCredential, SectionWebResearchCredential}
	if !slices.Equal(result.Sections, wantSections) {
		t.Fatalf("sections = %v, want %v", result.Sections, wantSections)
	}
	if !slices.Equal(result.Labels, []Label{LabelAdded, LabelRemoved, LabelChanged}) {
		t.Fatalf("labels = %v, want every observed label in fixed order", result.Labels)
	}
}

func TestMonitor_SourceLayerViolationsAreMalformedAlone(t *testing.T) {
	const validGlobal = "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: /home/u\n    grant_kind: folder\n"

	tests := []struct {
		name  string
		kind  LayerKind
		after string
	}{
		{"invalid yaml", LayerGlobal, "provider: [\n"},
		{"schema violation", LayerGlobal, "agent:\n  max_concurrency: \"many\"\n"},
		{
			name:  "global host grant",
			kind:  LayerGlobal,
			after: "permissions:\n  - kind: tool\n    subject: web_search\n    host_scope: example.com\n    grant_kind: project\n",
		},
		{
			name:  "schema-valid authorization-invalid global permission",
			kind:  LayerGlobal,
			after: "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: relative/dir\n    grant_kind: folder\n",
		},
		{
			name:  "schema-valid authorization-invalid project permission",
			kind:  LayerProject,
			after: "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: relative/dir\n    grant_kind: folder\n",
		},
		{"project global-only key", LayerProject, "web_research:\n  api_key: leaked\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkpointAfter(t, tt.kind, validGlobal, tt.after)
			if !slices.Equal(result.Labels, []Label{LabelMalformed}) {
				t.Fatalf("labels = %v, want only %q", result.Labels, LabelMalformed)
			}
			if len(result.Sections) != 0 {
				t.Fatalf("sections = %v, want none for a file that was never compared", result.Sections)
			}
		})
	}
}

func TestMonitor_DeletedBaselineReturnsMissingAlone(t *testing.T) {
	path := globalPath(t)
	m := NewMonitor([]LayerSnapshot{seedLayer(t, LayerGlobal, path, baseGlobal)})
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove settings: %v", err)
	}

	result := only(t, m.Checkpoint())
	if !slices.Equal(result.Labels, []Label{LabelMissing}) {
		t.Fatalf("labels = %v, want only %q", result.Labels, LabelMissing)
	}
	if len(result.Sections) != 0 {
		t.Fatalf("sections = %v, want none for an absent file", result.Sections)
	}
}

func TestMonitor_UnsafeTargetsAreUnreadableAlone(t *testing.T) {
	tests := []struct {
		name    string
		replace func(t *testing.T, path string)
	}{
		{
			name: "final component symlink",
			replace: func(t *testing.T, path string) {
				target := filepath.Join(filepath.Dir(path), "elsewhere.yaml")
				writeFile(t, target, baseGlobal)
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove settings: %v", err)
				}
				symlink(t, target, path)
			},
		},
		{
			name: "non-regular target",
			replace: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove settings: %v", err)
				}
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatalf("mkfifo: %v", err)
				}
			},
		},
		{
			name: "oversized file",
			replace: func(t *testing.T, path string) {
				rewrite(t, path, "# "+strings.Repeat("x", 64*1024)+"\n")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := globalPath(t)
			m := NewMonitor([]LayerSnapshot{seedLayer(t, LayerGlobal, path, baseGlobal)})
			tt.replace(t, path)

			done := make(chan []Result, 1)
			go func() { done <- m.Checkpoint() }()
			select {
			case results := <-done:
				result := only(t, results)
				if !slices.Equal(result.Labels, []Label{LabelUnreadable}) {
					t.Fatalf("labels = %v, want only %q", result.Labels, LabelUnreadable)
				}
				if len(result.Sections) != 0 {
					t.Fatalf("sections = %v, want none", result.Sections)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("checkpoint blocked instead of classifying the target")
			}
		})
	}
}

func TestMonitor_HeldSidecarLockReturnsTypedUnavailable(t *testing.T) {
	path := globalPath(t)
	m := NewMonitor([]LayerSnapshot{seedLayer(t, LayerGlobal, path, baseGlobal)})
	m.lockTimeout = 50 * time.Millisecond
	rewrite(t, path, strings.Replace(baseGlobal, "global-key", "rotated", 1))

	release, reason, err := locks.Acquire(path+lockSuffix, time.Second)
	if reason != locks.ReasonNone {
		t.Fatalf("seed lock: reason = %q, err = %v", reason, err)
	}
	defer release()

	result := only(t, m.Checkpoint())
	if !result.Unavailable || result.Reason != locks.ReasonLockTimeout {
		t.Fatalf("result = %#v, want a typed unavailable timeout", result)
	}
	if len(result.Labels) != 0 || len(result.Sections) != 0 {
		t.Fatalf("result = %#v, want no labels or sections for an uninspected layer", result)
	}
}

func publishedGlobal(t *testing.T, path string) (string, Projection) {
	t.Helper()
	published := strings.Replace(baseGlobal, "global-key", "published-key", 1)
	raw, cat, err := validate(LayerGlobal, []byte(published), path)
	if cat != config.LoadOK {
		t.Fatalf("publication fixture must validate: %v", err)
	}
	return published, Project(raw)
}

func TestMonitor_PublicationCannotLandInsideACheckpoint(t *testing.T) {
	path := globalPath(t)
	layer := seedLayer(t, LayerGlobal, path, baseGlobal)
	m := NewMonitor([]LayerSnapshot{layer})
	published, next := publishedGlobal(t, path)

	landed := make(chan struct{})
	advanced := false
	landedDuringRead := false
	restore := readSettings
	t.Cleanup(func() { readSettings = restore })
	readSettings = func(p string) ([]byte, bool, bool) {
		go func() {
			defer close(landed)
			release, reason, err := locks.Acquire(p+lockSuffix, 10*time.Second)
			if reason != locks.ReasonNone {
				t.Errorf("publisher lock: reason = %q, err = %v", reason, err)
				return
			}
			defer release()
			if err := os.WriteFile(p, []byte(published), 0o600); err != nil {
				t.Errorf("publish: %v", err)
				return
			}
			advanced = m.AdvanceBaseline(p, Project(layer.Raw), next)
		}()
		select {
		case <-landed:
			landedDuringRead = true
		case <-time.After(200 * time.Millisecond):
		}
		return restore(p)
	}

	if results := m.Checkpoint(); len(results) != 0 {
		t.Fatalf("results = %#v, want none: the checkpoint must compare one consistent file and baseline", results)
	}
	if landedDuringRead {
		t.Fatal("a publication landed while the checkpoint was reading the layer")
	}
	select {
	case <-landed:
	case <-time.After(10 * time.Second):
		t.Fatal("publication never completed after the checkpoint released the layer")
	}
	if !advanced {
		t.Fatal("AdvanceBaseline refused the publication that waited for the checkpoint")
	}

	readSettings = restore
	if results := m.Checkpoint(); len(results) != 0 {
		t.Fatalf("results = %#v, want none once the publication advanced the baseline", results)
	}
}

func TestMonitor_CheckpointAndPublishingWriterRunConcurrently(t *testing.T) {
	path := globalPath(t)
	layer := seedLayer(t, LayerGlobal, path, baseGlobal)
	m := NewMonitor([]LayerSnapshot{layer})
	published, next := publishedGlobal(t, path)

	release, reason, err := locks.Acquire(path+lockSuffix, time.Second)
	if reason != locks.ReasonNone {
		t.Fatalf("seed lock: reason = %q, err = %v", reason, err)
	}
	release = sync.OnceFunc(release)
	defer release()

	reached := make(chan struct{})
	restore := acquireLock
	t.Cleanup(func() { acquireLock = restore })
	acquireLock = func(p string, timeout time.Duration) (func(), locks.LockReason, error) {
		close(reached)
		return restore(p, timeout)
	}

	checkpoint := make(chan []Result, 1)
	go func() { checkpoint <- m.Checkpoint() }()
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("checkpoint never reached the sidecar lock")
	}

	rewrite(t, path, published)
	advance := make(chan bool, 1)
	go func() { advance <- m.AdvanceBaseline(path, Project(layer.Raw), next) }()
	select {
	case ok := <-advance:
		if !ok {
			t.Fatal("AdvanceBaseline refused a prior matching the retained baseline")
		}
	case <-time.After(m.lockTimeout / 2):
		t.Fatal("AdvanceBaseline under the sidecar lock blocked behind a waiting checkpoint")
	}
	release()

	select {
	case results := <-checkpoint:
		if len(results) != 0 {
			t.Fatalf("results = %#v, want none: the checkpoint should wait out the publication and see the advanced baseline", results)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("checkpoint never completed")
	}
}

func TestMonitor_BaselineAdvancesOnlyFromAMatchingPrior(t *testing.T) {
	path := globalPath(t)
	layer := seedLayer(t, LayerGlobal, path, baseGlobal)
	m := NewMonitor([]LayerSnapshot{layer})

	published, next := publishedGlobal(t, path)

	stale := Project(map[string]any{"web_research": map[string]any{"api_key": "never-was-the-baseline"}})
	if m.AdvanceBaseline(path, stale, next) {
		t.Fatal("AdvanceBaseline accepted a prior that does not match the retained baseline")
	}

	rewrite(t, path, published)
	if result := only(t, m.Checkpoint()); !slices.Equal(result.Labels, []Label{LabelChanged}) {
		t.Fatalf("result = %#v, want the publication reported as drift before the baseline advances", result)
	}

	if !m.AdvanceBaseline(path, Project(layer.Raw), next) {
		t.Fatal("AdvanceBaseline refused a prior matching the retained baseline")
	}
	if results := m.Checkpoint(); len(results) != 0 {
		t.Fatalf("results = %#v, want none once the confirmed publication advanced the baseline", results)
	}
}

// Detection is read-only: a checkpoint over a drifted layer must leave the live
// authorization and configuration view exactly as the launch composed it.
func TestMonitor_CheckpointLeavesTheRuntimeCacheUntouched(t *testing.T) {
	path := globalPath(t)
	composed := map[string]any{
		"permissions": []any{map[string]any{
			"kind": "direct", "subject": "ls", "path_scope": "/home/u", "grant_kind": "folder",
		}},
		"provider": map[string]any{"acme": map[string]any{
			"base_url": "https://api.acme.test", "api_key": "global-key",
		}},
	}
	cache, err := config.NewCache(composed, "", []string{path})
	if err != nil {
		t.Fatalf("build cache: %v", err)
	}
	before := cache.Permissions()
	beforeProvider, _ := cache.Provider("acme")
	beforeKey := beforeProvider.APIKey

	m := NewMonitor([]LayerSnapshot{seedLayer(t, LayerGlobal, path, baseGlobal)})
	rewrite(t, path, "permissions:\n  - kind: direct\n    subject: rm\n    path_scope: /\n    grant_kind: global\n")
	if results := m.Checkpoint(); len(results) == 0 {
		t.Fatal("checkpoint reported no drift for a rewritten layer")
	}

	if !slices.Equal(cache.Permissions(), before) {
		t.Fatalf("permissions = %v, want the pre-checkpoint view %v", cache.Permissions(), before)
	}
	if after, _ := cache.Provider("acme"); after.APIKey != beforeKey || after.BaseURL != beforeProvider.BaseURL {
		t.Fatalf("provider = %#v, want the pre-checkpoint view %#v", after, beforeProvider)
	}
}

const baseLocal = `permissions:
  - kind: direct
    subject: ls
    path_scope: /home/u
    grant_kind: folder
`

func localSettingsPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), ".codemeld", "settings.local.yaml")
}

func TestMonitor_LocalLayerPermissionDrift(t *testing.T) {
	const ls = "  - kind: direct\n    subject: ls\n    path_scope: /home/u\n    grant_kind: folder\n"
	const cat = "  - kind: direct\n    subject: cat\n    path_scope: /home/u\n    grant_kind: folder\n"
	list := func(entries ...string) string { return "permissions:\n" + strings.Join(entries, "") }

	tests := []struct {
		name          string
		before, after string
		label         Label
	}{
		{"added", list(ls), list(ls, cat), LabelAdded},
		{"removed", list(ls, cat), list(ls), LabelRemoved},
		{"changed", list(ls, cat), list(cat, ls), LabelChanged},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := localSettingsPath(t)
			m := NewMonitor([]LayerSnapshot{seedLayer(t, LayerLocal, path, tt.before)})
			rewrite(t, path, tt.after)

			result := only(t, m.Checkpoint())
			if result.Kind != LayerKind("local") || result.Path != path {
				t.Fatalf("result = %#v, want kind %q and path %q", result, LayerKind("local"), path)
			}
			if !slices.Equal(result.Sections, []Section{SectionPermissions}) {
				t.Fatalf("sections = %v, want only %q", result.Sections, SectionPermissions)
			}
			if !slices.Equal(result.Labels, []Label{tt.label}) {
				t.Fatalf("labels = %v, want only %q", result.Labels, tt.label)
			}
		})
	}
}

func TestMonitor_LocalLayerAllowListViolationIsMalformedAlone(t *testing.T) {
	path := localSettingsPath(t)
	m := NewMonitor([]LayerSnapshot{seedLayer(t, LayerLocal, path, baseLocal)})
	rewrite(t, path, baseLocal+"agent:\n  max_concurrency: 2\n")

	result := only(t, m.Checkpoint())
	if !slices.Equal(result.Labels, []Label{LabelMalformed}) {
		t.Fatalf("labels = %v, want only %q", result.Labels, LabelMalformed)
	}
	if len(result.Sections) != 0 {
		t.Fatalf("sections = %v, want none for a file that was never compared", result.Sections)
	}
}

func TestMonitor_UnchangedAndAbsentLocalLayersProduceNoDrift(t *testing.T) {
	unchanged := seedLayer(t, LayerLocal, localSettingsPath(t), baseLocal)
	absent := localSettingsPath(t)
	mkdirAll(t, filepath.Dir(absent))

	m := NewMonitor([]LayerSnapshot{unchanged, {Kind: LayerLocal, Path: absent}})
	if results := m.Checkpoint(); len(results) != 0 {
		t.Fatalf("results = %#v, want none for an unchanged and an admitted-absent local layer", results)
	}
}
