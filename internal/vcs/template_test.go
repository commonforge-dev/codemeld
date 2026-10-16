// Table tests for VCS template loading and validation failures.
package vcs

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/vcs/builtin"
)

// defaultBodies returns a complete, valid set of action bodies for a new-name ("svn") template.
func defaultBodies() map[string]string {
	return map[string]string{
		"detect":         "detect:\n  marker: .svn\n",
		"status":         "status:\n  argv: [svn, status]\n",
		"diff":           "diff:\n  argv: [svn, diff]\n",
		"add":            "add:\n  argv: [svn, add, \"{path}\"]\n",
		"commit":         "commit:\n  argv: [svn, commit, -m, \"{message}\"]\n",
		"log":            "log:\n  argv: [svn, log]\n",
		"branch-current": "branch-current:\n  argv: [svn, info]\n",
		"branch-create":  "branch-create:\n  argv: [svn, copy, \"{branch}\"]\n",
		"branch-switch":  "branch-switch:\n  argv: [svn, switch, \"{branch}\"]\n",
		"restore-file":   "restore-file:\n  argv: [svn, revert, \"{path}\"]\n",
		"is-clean":       "is-clean:\n  argv: [svn, status]\n",
		"stash":          "stash:\n  argv: [svn, shelve]\n",
		"stash-pop":      "stash-pop:\n  argv: [svn, unshelve]\n",
		"merge-status":   "merge-status:\n  argv: [svn, status]\n",
		"rebase-status":  "rebase-status:\n  argv: [svn, status]\n",
	}
}

// buildTemplate assembles template YAML in canonical action order, applying body overrides and omitting named actions.
func buildTemplate(override map[string]string, omit ...string) string {
	bodies := defaultBodies()
	maps.Copy(bodies, override)
	var sb strings.Builder
	for _, action := range requiredActions {
		if slices.Contains(omit, action) {
			continue
		}
		sb.WriteString(bodies[action])
		sb.WriteString("\n")
	}
	return sb.String()
}

// loadOne writes a single template file into a fresh temp dir and loads that directory.
func loadOne(t *testing.T, basename, content string) (map[string]*Template, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, basename), []byte(content), 0o600); err != nil {
		t.Fatalf("seed template: %v", err)
	}
	return LoadTemplates(dir)
}

func TestLoadTemplates_ValidNewName(t *testing.T) {
	got, err := loadOne(t, "svn.yaml", buildTemplate(nil))
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	tmpl, ok := got["svn"]
	if !ok {
		t.Fatalf("template %q not loaded; got keys %v", "svn", keys(got))
	}
	if tmpl.Detect == nil || tmpl.Detect.Marker != ".svn" {
		t.Errorf("Detect = %+v, want marker .svn", tmpl.Detect)
	}
	if len(tmpl.Actions) != len(requiredActions)-1 {
		t.Errorf("loaded %d non-detect actions, want %d", len(tmpl.Actions), len(requiredActions)-1)
	}
	add, ok := tmpl.Actions["add"]
	if !ok {
		t.Fatal("add action missing")
	}
	if want := []string{"svn", "add", "{path}"}; !slices.Equal(add.Argv, want) {
		t.Errorf("add.Argv = %v, want %v", add.Argv, want)
	}
	if add.Cwd != "" {
		t.Errorf("add.Cwd = %q, want empty (omitted)", add.Cwd)
	}
	if !strings.HasSuffix(tmpl.Source, "svn.yaml") {
		t.Errorf("Source = %q, want suffix svn.yaml", tmpl.Source)
	}
}

func TestLoadTemplates_BuiltinOverrideMayOmitDetect(t *testing.T) {
	got, err := loadOne(t, "git.yaml", buildTemplate(nil, "detect"))
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	tmpl, ok := got["git"]
	if !ok {
		t.Fatalf("override %q not loaded", "git")
	}
	if tmpl.Detect != nil {
		t.Errorf("Detect = %+v, want nil for omitted detect", tmpl.Detect)
	}
}

func TestLoadTemplates_CwdPreserved(t *testing.T) {
	override := map[string]string{"status": "status:\n  argv: [svn, status]\n  cwd: sub/dir\n"}
	got, err := loadOne(t, "svn.yaml", buildTemplate(override))
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	if cwd := got["svn"].Actions["status"].Cwd; cwd != "sub/dir" {
		t.Errorf("status.Cwd = %q, want sub/dir", cwd)
	}
}

func TestLoadTemplates_MissingDirIsEmpty(t *testing.T) {
	got, err := LoadTemplates(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("missing dir should not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("missing dir returned %d templates, want 0", len(got))
	}
}

func TestLoadTemplates_DuplicateNameSameSource(t *testing.T) {
	a := filepath.Join(t.TempDir(), "git.yaml")
	b := filepath.Join(t.TempDir(), "git.yaml")
	content := buildTemplate(nil, "detect")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	_, err := loadTemplatePaths([]string{a, b})
	if err == nil {
		t.Fatal("expected duplicate-name error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, a) || !strings.Contains(msg, b) {
		t.Errorf("error must name both files; got %q", msg)
	}
}

func TestLoadTemplates_ValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		basename string
		content  string
		wantPart string
	}{
		{
			name:     "new name missing required action",
			basename: "svn.yaml",
			content:  buildTemplate(nil, "status"),
			wantPart: "missing required actions: status",
		},
		{
			name:     "new name missing detect",
			basename: "svn.yaml",
			content:  buildTemplate(nil, "detect"),
			wantPart: "missing required actions: detect",
		},
		{
			name:     "override missing non-detect action",
			basename: "git.yaml",
			content:  buildTemplate(nil, "detect", "commit"),
			wantPart: "missing required actions: commit",
		},
		{
			name:     "unknown top-level key",
			basename: "svn.yaml",
			content:  buildTemplate(nil) + "bogus:\n  argv: [x]\n",
			wantPart: `unknown top-level key "bogus"`,
		},
		{
			name:     "forbidden wrapping key",
			basename: "svn.yaml",
			content:  "name: thing\n" + buildTemplate(nil),
			wantPart: `forbidden top-level wrapping key "name"`,
		},
		{
			name:     "bad filename regex",
			basename: "Git.yaml",
			content:  buildTemplate(nil, "detect"),
			wantPart: "filename does not match",
		},
		{
			name:     "detect not a map",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"detect": "detect: hello\n"}),
			wantPart: "detect action body must be a map",
		},
		{
			name:     "detect missing marker",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"detect": "detect: {}\n"}),
			wantPart: "missing the required key marker",
		},
		{
			name:     "detect unknown subkey",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"detect": "detect:\n  marker: .svn\n  extra: y\n"}),
			wantPart: `detect action has unknown key "extra"`,
		},
		{
			name:     "marker non-string",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"detect": "detect:\n  marker: 123\n"}),
			wantPart: "detect.marker must be a string",
		},
		{
			name:     "marker empty",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"detect": "detect:\n  marker: \"\"\n"}),
			wantPart: "must be a non-empty string",
		},
		{
			name:     "marker contains slash",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"detect": "detect:\n  marker: a/b\n"}),
			wantPart: "must not contain",
		},
		{
			name:     "marker is dotdot",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"detect": "detect:\n  marker: \"..\"\n"}),
			wantPart: "must not be '.' or '..'",
		},
		{
			name:     "marker too long",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"detect": "detect:\n  marker: " + strings.Repeat("a", 256) + "\n"}),
			wantPart: "exceeds 255",
		},
		{
			name:     "marker leading whitespace",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"detect": "detect:\n  marker: \" .svn\"\n"}),
			wantPart: "leading or trailing ASCII whitespace",
		},
		{
			name:     "action body not a map",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"status": "status: hello\n"}),
			wantPart: `action "status" body must be a map`,
		},
		{
			name:     "action missing argv",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"status": "status:\n  cwd: sub\n"}),
			wantPart: `action "status" is missing the required key argv`,
		},
		{
			name:     "argv not a list",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"status": "status:\n  argv: hello\n"}),
			wantPart: "argv must be a list of strings",
		},
		{
			name:     "argv empty",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"status": "status:\n  argv: []\n"}),
			wantPart: "argv must be a non-empty list",
		},
		{
			name:     "argv non-string element",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"status": "status:\n  argv: [svn, 5]\n"}),
			wantPart: "argv element 1 is not a string",
		},
		{
			name:     "action unknown key",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"status": "status:\n  argv: [svn, status]\n  env: x\n"}),
			wantPart: `action "status" has unknown key "env"`,
		},
		{
			name:     "cwd empty string",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"status": "status:\n  argv: [svn, status]\n  cwd: \"\"\n"}),
			wantPart: "cwd must not be empty",
		},
		{
			name:     "cwd non-string",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"status": "status:\n  argv: [svn, status]\n  cwd: 5\n"}),
			wantPart: "cwd must be a string",
		},
		{
			name:     "class unknown value",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"status": "status:\n  argv: [svn, status]\n  class: readonly\n"}),
			wantPart: `action "status" has unknown class "readonly"`,
		},
		{
			name:     "class non-string",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"status": "status:\n  argv: [svn, status]\n  class: 5\n"}),
			wantPart: `action "status" class must be a string`,
		},
		{
			name:     "unknown placeholder",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"status": "status:\n  argv: [svn, \"{bogus}\"]\n"}),
			wantPart: "unknown placeholder {bogus}",
		},
		{
			name:     "placeholder in action that rejects it",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"status": "status:\n  argv: [svn, \"{path}\"]\n"}),
			wantPart: "uses placeholder {path} it does not accept",
		},
		{
			name:     "placeholder-accepting action missing placeholder",
			basename: "svn.yaml",
			content:  buildTemplate(map[string]string{"add": "add:\n  argv: [svn, add]\n"}),
			wantPart: "must contain its placeholder {path}",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadOne(t, tc.basename, tc.content)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantPart)
			}
			if !strings.Contains(err.Error(), tc.wantPart) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantPart)
			}
		})
	}
}

func TestLoadTemplates_ActionClassValidation(t *testing.T) {
	override := map[string]string{
		"status": "status:\n  argv: [svn, status]\n  class: read_only\n",
		"commit": "commit:\n  argv: [svn, commit, -m, \"{message}\"]\n  class: mutating\n",
	}
	got, err := loadOne(t, "svn.yaml", buildTemplate(override))
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	tmpl := got["svn"]
	if c := tmpl.Actions["status"].Class; c != ClassReadOnly {
		t.Errorf("status.Class = %q, want %q", c, ClassReadOnly)
	}
	if c := tmpl.Actions["commit"].Class; c != ClassMutating {
		t.Errorf("commit.Class = %q, want %q", c, ClassMutating)
	}
	// An action that omits class stays ClassUnset, distinct from an explicit mutating declaration.
	if c := tmpl.Actions["diff"].Class; c != ClassUnset {
		t.Errorf("diff.Class = %q, want ClassUnset (absent)", c)
	}
}

func TestLoadTemplates_UnchangedReferenceCopyProvenance(t *testing.T) {
	for _, name := range builtin.BuiltinNames() {
		ref, ok := builtin.BuiltinTemplate(name)
		if !ok {
			t.Fatalf("built-in %q not found", name)
		}
		got, err := loadOne(t, name+".yaml", string(ref))
		if err != nil {
			t.Fatalf("LoadTemplates(%s): %v", name, err)
		}
		if !got[name].BuiltinReferenceCopy {
			t.Errorf("byte-identical %s copy: BuiltinReferenceCopy = false, want true", name)
		}
	}
}

func TestLoadTemplates_ChangedCopyIsNotReferenceProvenance(t *testing.T) {
	ref, ok := builtin.BuiltinTemplate("git")
	if !ok {
		t.Fatal("built-in git not found")
	}
	// Append a YAML comment: bytes differ but the template still parses and stays a valid git override.
	changed := string(ref) + "\n# local edit\n"
	got, err := loadOne(t, "git.yaml", changed)
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	if got["git"].BuiltinReferenceCopy {
		t.Error("changed git copy: BuiltinReferenceCopy = true, want false")
	}
}

func keys(m map[string]*Template) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestLoadBuiltinTemplates proves the embedded built-ins parse into complete *Template values from
// the binary alone (no filesystem reference copy), each with the detect marker from builtinMarkers,
// every non-detect action present, and a non-empty synthetic Source. This is the base map bootstrap
// step 4 starts from set (a).
func TestLoadBuiltinTemplates(t *testing.T) {
	m, err := LoadBuiltinTemplates()
	if err != nil {
		t.Fatalf("LoadBuiltinTemplates: %v", err)
	}
	if len(m) != len(builtinMarkers) {
		t.Fatalf("loaded %d built-ins, want %d", len(m), len(builtinMarkers))
	}
	for name, marker := range builtinMarkers {
		tmpl, ok := m[name]
		if !ok {
			t.Fatalf("built-in %q absent from loaded map", name)
		}
		if tmpl.Detect == nil || tmpl.Detect.Marker != marker {
			t.Errorf("built-in %q detect = %v, want marker %q", name, tmpl.Detect, marker)
		}
		if tmpl.Source == "" {
			t.Errorf("built-in %q has empty Source", name)
		}
		for _, action := range requiredActions {
			if action == "detect" {
				continue
			}
			if _, ok := tmpl.Actions[action]; !ok {
				t.Errorf("built-in %q missing action %q", name, action)
			}
		}
	}
}

func TestLoadTemplateFiles_MatchesThePathLoader(t *testing.T) {
	dir := t.TempDir()
	content := buildTemplate(nil)
	path := filepath.Join(dir, "svn.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("seed template: %v", err)
	}

	fromPath, err := LoadTemplates(dir)
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	fromBytes, err := LoadTemplateFiles([]TemplateFile{{Path: path, Bytes: []byte(content)}})
	if err != nil {
		t.Fatalf("LoadTemplateFiles: %v", err)
	}
	if !slices.Equal(keys(fromPath), keys(fromBytes)) {
		t.Fatalf("names = %v, want %v", keys(fromBytes), keys(fromPath))
	}
	want, got := fromPath["svn"], fromBytes["svn"]
	if got.Source != want.Source || got.Name != want.Name || got.Detect.Marker != want.Detect.Marker {
		t.Fatalf("template = %+v, want %+v", got, want)
	}
	if !slices.Equal(got.Actions["status"].Argv, want.Actions["status"].Argv) {
		t.Fatalf("status argv = %v, want %v", got.Actions["status"].Argv, want.Actions["status"].Argv)
	}
}

func TestLoadTemplateFiles_AppliesTheFilenameAndDuplicateRules(t *testing.T) {
	content := buildTemplate(nil, "detect")

	_, err := LoadTemplateFiles([]TemplateFile{{Path: filepath.Join("/p/.codemeld/vcs", "notes.txt"), Bytes: []byte(content)}})
	if err == nil || !strings.Contains(err.Error(), filenamePattern) {
		t.Fatalf("error = %v, want the filename rule applied to bytes too", err)
	}

	a := filepath.Join("/p/.codemeld/vcs", "git.yaml")
	b := filepath.Join("/q/.codemeld/vcs", "git.yaml")
	_, err = LoadTemplateFiles([]TemplateFile{{Path: a, Bytes: []byte(content)}, {Path: b, Bytes: []byte(content)}})
	if err == nil || !strings.Contains(err.Error(), a) || !strings.Contains(err.Error(), b) {
		t.Fatalf("error = %v, want a duplicate-name error naming both sources", err)
	}
}

func TestLoadTemplateFiles_ReportsValidationFailuresAgainstTheGivenPath(t *testing.T) {
	path := filepath.Join("/p/.codemeld/vcs", "svn.yaml")
	_, err := LoadTemplateFiles([]TemplateFile{{Path: path, Bytes: []byte("status:\n  argv: []\n")}})
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("error = %v, want the failure attributed to %s", err, path)
	}
}

func TestLoadTemplates_DuplicateKeyCarriesTheSharedFixAndFileAttribution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "svn.yaml")
	if err := os.WriteFile(path, []byte("detect:\n  marker: .svn\n  marker: .svn\n"), 0o600); err != nil {
		t.Fatalf("seed template: %v", err)
	}

	_, err := LoadTemplates(dir)
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("err = %v, want a *ValidationError", err)
	}
	if verr.File != path {
		t.Fatalf("ValidationError.File = %q, want %q", verr.File, path)
	}
	msg := verr.Error()
	if !strings.HasPrefix(msg, path+": is not valid YAML; codemeld did not start.\n") {
		t.Fatalf("message %q does not name the file, the failure and the consequence", msg)
	}
	for _, part := range []string{
		`the key "marker" is set twice in the same block, at line 2 and again at line 3`,
		`to fix: delete one of the two "marker" lines, either line 2 or line 3`,
	} {
		if !strings.Contains(msg, part) {
			t.Fatalf("message %q missing %q", msg, part)
		}
	}
	if strings.Contains(msg, "yaml_parse_error") {
		t.Fatalf("message %q leaks the internal category token", msg)
	}
}
