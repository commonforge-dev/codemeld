// Table tests for config layer composition (95): nearest-wins map
// merge, list replacement, permissions concat/dedup, inheritance
// unknown-key passthrough, nil layers, and input immutability.
package config

import (
	"reflect"
	"testing"

	"codemeld.dev/codemeld/internal/permissions"
)

func TestCompose_BlockedPathsCombineGlobalFirst(t *testing.T) {
	global := map[string]any{"blocked_paths": []any{"~/.ssh"}}
	project := map[string]any{"blocked_paths": []any{"/data/x"}}
	cases := []struct {
		name            string
		global, project map[string]any
		want            []any
	}{
		{"both layers", global, project, []any{"~/.ssh", "/data/x"}},
		{"global only", global, nil, []any{"~/.ssh"}},
		{"project only", nil, project, []any{"/data/x"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Compose(c.global, c.project)
			if err != nil {
				t.Fatalf("Compose: %v", err)
			}
			if !reflect.DeepEqual(got["blocked_paths"], c.want) {
				t.Fatalf("blocked_paths = %#v, want %#v", got["blocked_paths"], c.want)
			}
		})
	}
	got, err := Compose(map[string]any{}, map[string]any{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if _, ok := got["blocked_paths"]; ok {
		t.Fatalf("blocked_paths = %#v, want the key absent when no layer sets it", got["blocked_paths"])
	}
}

func perm(kind, subject, pathScope, grantKind string) map[string]any {
	return map[string]any{
		"kind":       kind,
		"subject":    subject,
		"path_scope": pathScope,
		"grant_kind": grantKind,
	}
}

func hostPerm(subject, hostScope string) map[string]any {
	return map[string]any{
		"kind":       "tool",
		"subject":    subject,
		"host_scope": hostScope,
		"grant_kind": "project",
	}
}

func TestCompose(t *testing.T) {
	tests := []struct {
		name    string
		global  map[string]any
		project map[string]any
		want    map[string]any
	}{
		{
			name:    "nil layers compose to empty",
			global:  nil,
			project: nil,
			want:    map[string]any{},
		},
		{
			name:    "nearest-wins on discovery.boundary",
			global:  map[string]any{"discovery": map[string]any{"boundary": "launch-dir-only"}},
			project: map[string]any{"discovery": map[string]any{"boundary": "project-root"}},
			want:    map[string]any{"discovery": map[string]any{"boundary": "project-root"}},
		},
		{
			name:    "map subkeys merge, inherited subkey kept",
			global:  map[string]any{"vcs": map[string]any{"preferred": "git", "priority": []any{"git", "hg"}}},
			project: map[string]any{"vcs": map[string]any{"priority": []any{"hg"}}},
			// preferred inherited from global; priority list replaced wholesale.
			want: map[string]any{"vcs": map[string]any{"preferred": "git", "priority": []any{"hg"}}},
		},
		{
			name:    "list replace on vcs.priority (no concat)",
			global:  map[string]any{"vcs": map[string]any{"priority": []any{"git", "hg", "jj"}}},
			project: map[string]any{"vcs": map[string]any{"priority": []any{"jj"}}},
			want:    map[string]any{"vcs": map[string]any{"priority": []any{"jj"}}},
		},
		{
			name:    "single-layer key merges as-is (req 95)",
			global:  map[string]any{"agent": map[string]any{"max_concurrency": 4}},
			project: map[string]any{"model": map[string]any{"active": "gpt-5.5"}},
			want: map[string]any{
				"agent": map[string]any{"max_concurrency": 4},
				"model": map[string]any{"active": "gpt-5.5"},
			},
		},
		{
			name:    "model.active and last_used both preserved raw",
			global:  map[string]any{"model": map[string]any{"last_used": "gpt-5.0"}},
			project: map[string]any{"model": map[string]any{"active": "gpt-5.5"}},
			want:    map[string]any{"model": map[string]any{"active": "gpt-5.5", "last_used": "gpt-5.0"}},
		},
		{
			name:    "global mode.default preserved through empty project mode object",
			global:  map[string]any{"mode": map[string]any{"default": "auto_edits"}},
			project: map[string]any{"mode": map[string]any{}},
			// mode is subkey-merged, so an empty project mode object cannot erase the
			// configured global default (would fall back to build otherwise).
			want: map[string]any{"mode": map[string]any{"default": "auto_edits"}},
		},
		{
			name:    "project mode.default overrides global mode.default",
			global:  map[string]any{"mode": map[string]any{"default": "auto_edits"}},
			project: map[string]any{"mode": map[string]any{"default": "plan"}},
			want:    map[string]any{"mode": map[string]any{"default": "plan"}},
		},
		{
			name: "provider merges one level by name; entry replaced wholesale",
			global: map[string]any{"provider": map[string]any{
				"openai":     map[string]any{"base_url": "https://a", "api_key": "g", "models": []any{"x"}},
				"openrouter": map[string]any{"base_url": "https://or", "api_key": "k", "models": []any{"y"}},
			}},
			project: map[string]any{"provider": map[string]any{
				"openai": map[string]any{"base_url": "https://b", "api_key": "p", "models": []any{"z"}},
			}},
			want: map[string]any{"provider": map[string]any{
				"openai":     map[string]any{"base_url": "https://b", "api_key": "p", "models": []any{"z"}},
				"openrouter": map[string]any{"base_url": "https://or", "api_key": "k", "models": []any{"y"}},
			}},
		},
		{
			name: "permissions concat-merge with dedup, first occurrence kept",
			global: map[string]any{"permissions": []any{
				perm("direct", "ls", "/home/u", "folder"),
				perm("tool", "Read", "*", "global"),
			}},
			project: map[string]any{"permissions": []any{
				perm("direct", "ls", "/home/u", "folder"), // duplicate of global[0]
				perm("direct", "rm", "/home/u", "folder"), // new
			}},
			want: map[string]any{"permissions": []any{
				perm("direct", "ls", "/home/u", "folder"),
				perm("tool", "Read", "*", "global"),
				perm("direct", "rm", "/home/u", "folder"),
			}},
		},
		{
			name:   "host entries collapse only on identical canonical host identity",
			global: map[string]any{},
			project: map[string]any{"permissions": []any{
				hostPerm("web_search", "example.com"),
				hostPerm("web_search", "EXAMPLE.com."),
				hostPerm("web_search", "example.com"),
			}},
			want: map[string]any{"permissions": []any{
				hostPerm("web_search", "example.com"),
			}},
		},
		{
			name: "host entries differing by tool or host stay distinct",
			global: map[string]any{"permissions": []any{
				perm("tool", "Read", "*", "global"),
			}},
			project: map[string]any{"permissions": []any{
				hostPerm("web_search", "example.com"),
				hostPerm("web_fetch", "example.com"),
				hostPerm("web_search", "example.org"),
			}},
			want: map[string]any{"permissions": []any{
				perm("tool", "Read", "*", "global"),
				hostPerm("web_search", "example.com"),
				hostPerm("web_fetch", "example.com"),
				hostPerm("web_search", "example.org"),
			}},
		},
		{
			name:   "hosts that do not canonicalize keep their raw identity",
			global: map[string]any{},
			project: map[string]any{"permissions": []any{
				hostPerm("web_search", "not a host"),
				hostPerm("web_search", "not a host"),
				hostPerm("web_search", "also not a host"),
			}},
			want: map[string]any{"permissions": []any{
				hostPerm("web_search", "not a host"),
				hostPerm("web_search", "also not a host"),
			}},
		},
		{
			name: "duplicate host entry across layers keeps the first",
			global: map[string]any{"permissions": []any{
				hostPerm("web_search", "example.com"),
			}},
			project: map[string]any{"permissions": []any{
				hostPerm("web_search", "example.com"),
			}},
			want: map[string]any{"permissions": []any{
				hostPerm("web_search", "example.com"),
			}},
		},
		{
			name: "path entries keep their existing dedup identity (regression)",
			global: map[string]any{"permissions": []any{
				perm("tool", "Read", "*", "global"),
				perm("direct", "ls", "/home/u", "folder"),
			}},
			project: map[string]any{"permissions": []any{
				perm("tool", "Read", "*", "global"),
				perm("direct", "ls", "/home/u", "folder"),
				perm("direct", "ls", "/home/u/x", "folder"),
				perm("tool", "Write", "*", "global"),
			}},
			want: map[string]any{"permissions": []any{
				perm("tool", "Read", "*", "global"),
				perm("direct", "ls", "/home/u", "folder"),
				perm("direct", "ls", "/home/u/x", "folder"),
				perm("tool", "Write", "*", "global"),
			}},
		},
		{
			name: "empty project permissions does not revoke global grants (req 90a)",
			global: map[string]any{"permissions": []any{
				perm("direct", "ls", "/home/u", "folder"),
			}},
			project: map[string]any{"permissions": []any{}},
			want: map[string]any{"permissions": []any{
				perm("direct", "ls", "/home/u", "folder"),
			}},
		},
		{
			name:    "empty project permissions with no global key omits permissions (req 90a)",
			global:  map[string]any{},
			project: map[string]any{"permissions": []any{}},
			want:    map[string]any{},
		},
		{
			name:    "empty global permissions list is preserved",
			global:  map[string]any{"permissions": []any{}},
			project: map[string]any{},
			want:    map[string]any{"permissions": []any{}},
		},
		{
			name:    "unknown future top-level key passes through unchanged",
			global:  map[string]any{"future_feature": map[string]any{"deep": []any{"a", "b"}}},
			project: map[string]any{},
			want:    map[string]any{"future_feature": map[string]any{"deep": []any{"a", "b"}}},
		},
		{
			name:    "unknown future key in both layers prefers project value wholesale",
			global:  map[string]any{"future_feature": map[string]any{"a": 1, "b": 2}},
			project: map[string]any{"future_feature": map[string]any{"a": 9}},
			// Not a merge-by-key known map: project value wins as a whole, so "b" is dropped.
			want: map[string]any{"future_feature": map[string]any{"a": 9}},
		},
		{
			name:    "declared_commands copied from the project layer alone (adr-047)",
			global:  nil,
			project: map[string]any{"declared_commands": []any{"prep-open-tasks.sh --only"}},
			want:    map[string]any{"declared_commands": []any{"prep-open-tasks.sh --only"}},
		},
		{
			name:    "declared_commands absent when the project layer withholds it",
			global:  nil,
			project: map[string]any{},
			want:    map[string]any{},
		},
		{
			name:    "declared_commands in the global layer alone is dropped (adr-047)",
			global:  map[string]any{"declared_commands": []any{"prep-open-tasks.sh --only"}},
			project: nil,
			want:    map[string]any{},
		},
		{
			name:    "global declared_commands never merge with the project list",
			global:  map[string]any{"declared_commands": []any{"rm -rf"}},
			project: map[string]any{"declared_commands": []any{"prep-open-tasks.sh --only"}},
			want:    map[string]any{"declared_commands": []any{"prep-open-tasks.sh --only"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Compose(tt.global, tt.project)
			if err != nil {
				t.Fatalf("Compose() error = %v, want nil", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Compose() =\n  %#v\nwant\n  %#v", got, tt.want)
			}
		})
	}
}

func TestCompose_DoesNotMutateOrAliasInputs(t *testing.T) {
	globalPerm := perm("direct", "ls", "/home/u", "folder")
	global := map[string]any{
		"vcs":         map[string]any{"priority": []any{"git", "hg"}},
		"permissions": []any{globalPerm},
	}
	project := map[string]any{
		"vcs": map[string]any{"priority": []any{"jj"}},
	}

	got, err := Compose(global, project)
	if err != nil {
		t.Fatalf("Compose() error = %v", err)
	}

	// Mutating the composed output must not reach back into the inputs.
	gotVCS := got["vcs"].(map[string]any)
	gotVCS["priority"].([]any)[0] = "MUTATED"
	got["permissions"].([]any)[0].(map[string]any)["subject"] = "MUTATED"

	if global["vcs"].(map[string]any)["priority"].([]any)[0] != "git" {
		t.Fatalf("Compose mutated/aliased global vcs.priority: %#v", global["vcs"])
	}
	if globalPerm["subject"] != "ls" {
		t.Fatalf("Compose mutated/aliased global permission entry: %#v", globalPerm)
	}

	// Inputs unchanged in length too.
	if len(global) != 2 || len(project) != 1 {
		t.Fatalf("Compose changed input map sizes: global=%d project=%d", len(global), len(project))
	}
}

func TestCompose_MalformedPermissions(t *testing.T) {
	tests := []struct {
		name    string
		global  map[string]any
		project map[string]any
	}{
		{
			name:   "permissions value is not a list",
			global: map[string]any{"permissions": map[string]any{"kind": "direct"}},
		},
		{
			name:   "permissions value is nil",
			global: map[string]any{"permissions": nil},
		},
		{
			name:   "entry is not a mapping",
			global: map[string]any{"permissions": []any{"not-a-map"}},
		},
		{
			name:   "entry missing a tuple field",
			global: map[string]any{"permissions": []any{map[string]any{"kind": "direct", "subject": "ls", "path_scope": "/x"}}},
		},
		{
			name:   "host entry missing grant_kind",
			global: map[string]any{"permissions": []any{map[string]any{"kind": "tool", "subject": "web_search", "host_scope": "example.com"}}},
		},
		{
			name:   "host_scope is not a string",
			global: map[string]any{"permissions": []any{map[string]any{"kind": "tool", "subject": "web_search", "host_scope": 7, "grant_kind": "project"}}},
		},
		{
			name:   "tuple field is not a string",
			global: map[string]any{"permissions": []any{map[string]any{"kind": "direct", "subject": "ls", "path_scope": "/x", "grant_kind": 7}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Compose(tt.global, tt.project); err == nil {
				t.Fatalf("Compose() error = nil, want a malformed-permissions error")
			}
		})
	}
}

func permEntry(subject, scope, grantKind string) map[string]any {
	return map[string]any{"kind": "direct", "subject": subject, "path_scope": scope, "grant_kind": grantKind}
}

func TestCompose_ThreeLayerPrecedence(t *testing.T) {
	global := map[string]any{"attribution": true, "only_global": "g"}
	project := map[string]any{"attribution": false, "only_project": "p"}
	local := map[string]any{"attribution": true, "only_local": "l"}

	got, err := Compose(global, project, local)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	for key, want := range map[string]any{
		"attribution":  true,
		"only_global":  "g",
		"only_project": "p",
		"only_local":   "l",
	} {
		if got[key] != want {
			t.Fatalf("%s = %#v, want %#v", key, got[key], want)
		}
	}

	noLocal, err := Compose(global, project)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if noLocal["attribution"] != false {
		t.Fatalf("attribution = %#v, want the project value when no local layer is passed", noLocal["attribution"])
	}
	if _, ok := noLocal["only_local"]; ok {
		t.Fatalf("composed = %#v, want no local key when no local layer is passed", noLocal)
	}
}

func TestCompose_SubkeyMergeAcrossThreeLayers(t *testing.T) {
	required := []string{"discovery", "agent", "agent_instructions", "sessions", "vcs", "model", "mode", "provider"}

	if len(composeMergeMapKeys) != len(required) {
		t.Fatalf("composeMergeMapKeys = %#v, want exactly the %d required keys %v", composeMergeMapKeys, len(required), required)
	}
	for _, key := range required {
		if !composeMergeMapKeys[key] {
			t.Fatalf("composeMergeMapKeys is missing required key %q: %#v", key, composeMergeMapKeys)
		}
	}

	for _, key := range required {
		t.Run(key, func(t *testing.T) {
			global := map[string]any{key: map[string]any{"g": "from-global", "shared": "global"}}
			project := map[string]any{key: map[string]any{"p": "from-project", "shared": "project"}}
			local := map[string]any{key: map[string]any{"l": "from-local", "shared": "local"}}

			got, err := Compose(global, project, local)
			if err != nil {
				t.Fatalf("Compose: %v", err)
			}
			want := map[string]any{"g": "from-global", "p": "from-project", "l": "from-local", "shared": "local"}
			if !reflect.DeepEqual(got[key], want) {
				t.Fatalf("%s = %#v, want %#v", key, got[key], want)
			}
		})
	}
}

func TestCompose_PermissionsConcatenateGlobalProjectLocal(t *testing.T) {
	g := permEntry("g", "/g", "folder")
	p := permEntry("p", "/p", "folder")
	l := permEntry("l", "/l", "folder")

	got, err := Compose(
		map[string]any{"permissions": []any{g}},
		map[string]any{"permissions": []any{p}},
		map[string]any{"permissions": []any{l}},
	)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if !reflect.DeepEqual(got["permissions"], []any{g, p, l}) {
		t.Fatalf("permissions = %#v, want global, project, local", got["permissions"])
	}
}

func TestCompose_PermissionsDedupKeepsTheFarthestCopy(t *testing.T) {
	shared := permEntry("ls", "/proj", "folder")
	other := permEntry("cat", "/proj", "folder")

	cases := []struct {
		name                   string
		global, project, local map[string]any
		want                   []any
	}{
		{
			name:    "project and local",
			global:  map[string]any{},
			project: map[string]any{"permissions": []any{other, shared}},
			local:   map[string]any{"permissions": []any{shared}},
			want:    []any{other, shared},
		},
		{
			name:    "all three",
			global:  map[string]any{"permissions": []any{shared}},
			project: map[string]any{"permissions": []any{shared}},
			local:   map[string]any{"permissions": []any{shared, other}},
			want:    []any{shared, other},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Compose(c.global, c.project, c.local)
			if err != nil {
				t.Fatalf("Compose: %v", err)
			}
			if !reflect.DeepEqual(got["permissions"], c.want) {
				t.Fatalf("permissions = %#v, want %#v", got["permissions"], c.want)
			}
		})
	}
}

func TestCompose_EmptyLocalPermissionsListIsAbsent(t *testing.T) {
	g := permEntry("g", "/g", "folder")
	got, err := Compose(map[string]any{"permissions": []any{g}}, nil, map[string]any{"permissions": []any{}})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if !reflect.DeepEqual(got["permissions"], []any{g}) {
		t.Fatalf("permissions = %#v, want the global grant untouched", got["permissions"])
	}

	onlyEmpty, err := Compose(nil, nil, map[string]any{"permissions": []any{}})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if _, ok := onlyEmpty["permissions"]; ok {
		t.Fatalf("permissions = %#v, want the key omitted", onlyEmpty["permissions"])
	}
}

func TestCompose_BlockedPathsAppendTheLocalLayerLast(t *testing.T) {
	cases := []struct {
		name                   string
		global, project, local map[string]any
		want                   []any
	}{
		{
			name:    "all three layers",
			global:  map[string]any{"blocked_paths": []any{"~/.ssh"}},
			project: map[string]any{"blocked_paths": []any{"/data/x"}},
			local:   map[string]any{"blocked_paths": []any{"/data/y"}},
			want:    []any{"~/.ssh", "/data/x", "/data/y"},
		},
		{
			name:  "local only",
			local: map[string]any{"blocked_paths": []any{"/data/y"}},
			want:  []any{"/data/y"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Compose(c.global, c.project, c.local)
			if err != nil {
				t.Fatalf("Compose: %v", err)
			}
			if !reflect.DeepEqual(got["blocked_paths"], c.want) {
				t.Fatalf("blocked_paths = %#v, want %#v", got["blocked_paths"], c.want)
			}
		})
	}
}

func TestCompose_DeclaredCommandsStayProjectOnly(t *testing.T) {
	got, err := Compose(
		map[string]any{declaredCommandsKey: []any{"global-cmd"}},
		map[string]any{declaredCommandsKey: []any{"project-cmd"}},
		map[string]any{declaredCommandsKey: []any{"local-cmd"}},
	)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if !reflect.DeepEqual(got[declaredCommandsKey], []any{"project-cmd"}) {
		t.Fatalf("%s = %#v, want the project list only", declaredCommandsKey, got[declaredCommandsKey])
	}

	noProject, err := Compose(map[string]any{declaredCommandsKey: []any{"global-cmd"}}, nil, map[string]any{declaredCommandsKey: []any{"local-cmd"}})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if _, ok := noProject[declaredCommandsKey]; ok {
		t.Fatalf("%s = %#v, want both the global and local lists dropped", declaredCommandsKey, noProject[declaredCommandsKey])
	}
}

func TestCompose_WritableFoldersStayProjectOnly(t *testing.T) {
	got, err := Compose(
		map[string]any{writableFoldersKey: []any{"/global"}},
		map[string]any{writableFoldersKey: []any{"/project"}},
	)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if !reflect.DeepEqual(got[writableFoldersKey], []any{"/project"}) {
		t.Fatalf("%s = %#v, want the project list only", writableFoldersKey, got[writableFoldersKey])
	}

	noProject, err := Compose(map[string]any{writableFoldersKey: []any{"/global"}}, nil)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if _, ok := noProject[writableFoldersKey]; ok {
		t.Fatalf("%s = %#v, want the global list dropped", writableFoldersKey, noProject[writableFoldersKey])
	}
}

func TestLayerPermissions_StampsTheLayerItWasReadAs(t *testing.T) {
	raw := map[string]any{"permissions": []any{
		permEntry("ls", "/proj", "folder"),
		map[string]any{"kind": "tool", "subject": "web_fetch", "host_scope": "example.test", "grant_kind": "project"},
	}}
	for _, kind := range []permissions.LayerKind{permissions.LayerLocal, permissions.LayerProject, permissions.LayerGlobal} {
		t.Run(string(kind), func(t *testing.T) {
			entries, err := LayerPermissions(raw, kind)
			if err != nil {
				t.Fatalf("LayerPermissions: %v", err)
			}
			if len(entries) != 2 {
				t.Fatalf("entries = %#v, want both parsed", entries)
			}
			for _, e := range entries {
				if e.Layer != kind {
					t.Fatalf("entry %+v carries layer %q, want %q", e, e.Layer, kind)
				}
			}
		})
	}
}

func TestLayerPermissions_EmptyAndMalformed(t *testing.T) {
	entries, err := LayerPermissions(map[string]any{}, permissions.LayerLocal)
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries = %#v, err = %v; want no entries and no error", entries, err)
	}
	if _, err := LayerPermissions(map[string]any{"permissions": []any{permEntry("ls", "relative", "folder")}}, permissions.LayerLocal); err == nil {
		t.Fatalf("err = nil, want ParseEntry's rejection")
	}
	if _, err := LayerPermissions(map[string]any{"permissions": "not-a-list"}, permissions.LayerLocal); err == nil {
		t.Fatalf("err = nil, want a rejection of a non-list permissions value")
	}
}
