// Tests for the settings.yaml loader: load-failure classification and the global-file plaintext-key mode warning.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/testsupport"
)

func writeFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod seed file: %v", err)
	}
	return path
}

func TestLoadYAML(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantCat     LoadFailure
		expectNodes bool
		stderrParts []string
	}{
		{
			name:        "clean file",
			content:     "agent:\n  max_concurrency: 4\n",
			wantCat:     LoadOK,
			expectNodes: true,
		},
		{
			name:    "empty file",
			content: "",
			wantCat: LoadOK,
		},
		{
			name:    "whitespace and comment only",
			content: "\n  \n# just a comment\n",
			wantCat: LoadOK,
		},
		{
			name:        "malformed YAML",
			content:     "agent: { max_concurrency: 4\n",
			wantCat:     YAMLParseError,
			stderrParts: []string{"codemeld: ", "is not valid YAML", "codemeld did not start"},
		},
		{
			name:        "wrong-type schema failure",
			content:     "agent:\n  max_concurrency: \"three\"\n",
			wantCat:     SchemaValidationError,
			stderrParts: []string{"codemeld: ", "schema validation failed at", "agent.max_concurrency"},
		},
		{
			name:        "root sequence",
			content:     "[]\n",
			wantCat:     SchemaValidationError,
			stderrParts: []string{"codemeld: ", "schema validation failed at (root)"},
		},
		{
			name:        "root scalar",
			content:     "\"x\"\n",
			wantCat:     SchemaValidationError,
			stderrParts: []string{"codemeld: ", "schema validation failed at (root)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeFile(t, tt.content, 0o600)
			doc, raw, cat, err := LoadYAML(path)

			if cat != tt.wantCat {
				t.Fatalf("cat = %q, want %q (err=%v)", cat, tt.wantCat, err)
			}

			if tt.wantCat == LoadOK {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				if doc == nil {
					t.Fatalf("doc = nil on success path")
				}
				if tt.expectNodes && len(doc.Docs) == 0 {
					t.Fatalf("doc has no nodes on success path: %#v", doc)
				}
				if raw == nil {
					t.Fatalf("raw = nil, want non-nil decoded map")
				}
				return
			}

			if err == nil {
				t.Fatalf("err = nil, want a load error for category %q", cat)
			}
			line := FormatLoadError(path, cat, err, LaunchAborted)
			for _, part := range tt.stderrParts {
				if !strings.Contains(line, part) {
					t.Fatalf("stderr line %q missing %q", line, part)
				}
			}
		})
	}
}

func TestFormatLoadError_SchemaShape(t *testing.T) {
	path := writeFile(t, "agent:\n  max_concurrency: \"three\"\n", 0o600)
	_, _, cat, err := LoadYAML(path)
	if cat != SchemaValidationError {
		t.Fatalf("cat = %q, want %q", cat, SchemaValidationError)
	}
	msg := FormatLoadError(path, cat, err, LaunchAborted)
	wantPrefix := "codemeld: " + path + ": does not match the settings schema; codemeld did not start.\n"
	if !strings.HasPrefix(msg, wantPrefix) {
		t.Fatalf("schema message %q does not start with %q", msg, wantPrefix)
	}
	if !strings.Contains(msg, "\n  what happened: schema validation failed at agent.max_concurrency: ") {
		t.Fatalf("schema message %q does not carry the validator detail without the path", msg)
	}
	if n := strings.Count(msg, path); n != 1 {
		t.Fatalf("schema message %q names the path %d times, want 1", msg, n)
	}
	if !strings.Contains(msg, "\n  to fix: ") {
		t.Fatalf("schema message %q has no fix line", msg)
	}
}

func TestLoadYAML_Unreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; EACCES unobservable")
	}
	path := writeFile(t, "agent:\n  max_concurrency: 1\n", 0o000)
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	_, _, cat, err := LoadYAML(path)
	if cat != UnreadableFile {
		t.Fatalf("cat = %q, want %q", cat, UnreadableFile)
	}
	if err == nil {
		t.Fatalf("err = nil, want a read error")
	}
	msg := FormatLoadError(path, cat, err, LaunchAborted)
	wantPrefix := "codemeld: " + path + ": could not be read; codemeld did not start.\n"
	if !strings.HasPrefix(msg, wantPrefix) {
		t.Fatalf("unreadable message %q does not start with %q", msg, wantPrefix)
	}
	if !strings.Contains(msg, "\n  to fix: ") {
		t.Fatalf("unreadable message %q has no fix line", msg)
	}
}

func TestWarnIfBroaderThan0600_Broader(t *testing.T) {
	path := writeFile(t, "x: 1\n", 0o644)

	out := testsupport.CaptureStderr(t, func() { WarnIfBroaderThan0600(path) })
	want := "codemeld: " + path + ": file mode 0644 is broader than 0600; API keys and ChatGPT session tokens are stored in plaintext\n"
	if out != want {
		t.Fatalf("stderr = %q, want %q", out, want)
	}
	if n := strings.Count(out, "broader than 0600"); n != 1 {
		t.Fatalf("warning emitted %d times, want exactly 1", n)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode changed to %v; WarnIfBroaderThan0600 must not chmod", info.Mode().Perm())
	}
}

// The warning must fire once for a broad-mode global file whose bytes still validate, since
// the bounded byte seam itself never opens the file or inspects its mode.
func TestWarnIfBroaderThan0600_BroaderWarnsAndBytesValidate(t *testing.T) {
	content := "agent:\n  max_concurrency: 2\n"
	path := writeFile(t, content, 0o644)

	out := testsupport.CaptureStderr(t, func() { WarnIfBroaderThan0600(path) })
	want := "codemeld: " + path + ": file mode 0644 is broader than 0600; API keys and ChatGPT session tokens are stored in plaintext\n"
	if out != want {
		t.Fatalf("stderr = %q, want %q", out, want)
	}

	raw, cat, err := ValidateGlobalSettingsBytes([]byte(content), path)
	if cat != LoadOK || err != nil {
		t.Fatalf("cat = %q, err = %v; want LoadOK and nil", cat, err)
	}
	if raw == nil {
		t.Fatalf("raw = nil, want the decoded map")
	}
}

// A settings path that is a symbolic link is rejected rather than followed, so the warning
// must not report a mode read from whatever the link names.
func TestWarnIfBroaderThan0600_SymlinkNoTargetDerivedWarning(t *testing.T) {
	target := writeFile(t, "x: 1\n", 0o666)
	link := filepath.Join(t.TempDir(), "settings.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	out := testsupport.CaptureStderr(t, func() { WarnIfBroaderThan0600(link) })
	if out != "" {
		t.Fatalf("stderr = %q, want empty for a symlinked settings path", out)
	}
}

// stores plaintext ChatGPT session tokens alongside provider API keys in
// the same global settings file, so the broader-permission warning must name
// both kinds of credential, not API keys alone. This pins
// the wording so it cannot silently regress to the API-key-only phrasing.
func TestWarnIfBroaderThan0600_NamesChatGPTSessionTokens(t *testing.T) {
	path := writeFile(t, "x: 1\n", 0o640)
	out := testsupport.CaptureStderr(t, func() { WarnIfBroaderThan0600(path) })
	for _, part := range []string{"API keys", "ChatGPT session tokens", "plaintext"} {
		if !strings.Contains(out, part) {
			t.Fatalf("warning %q missing %q", out, part)
		}
	}
}

const globalHostGrantYAML = `permissions:
  - kind: tool
    subject: web_search
    host_scope: example.com
    grant_kind: project
`

func TestValidateGlobalSettingsBytes_RejectsHostGrant(t *testing.T) {
	path := writeFile(t, globalHostGrantYAML, 0o600)

	if _, _, cat, err := LoadYAML(path); cat != LoadOK || err != nil {
		t.Fatalf("LoadYAML cat = %q, err = %v; fixture must be schema-valid", cat, err)
	}

	raw, cat, err := ValidateGlobalSettingsBytes([]byte(globalHostGrantYAML), path)
	if cat != SchemaValidationError {
		t.Fatalf("cat = %q, want %q", cat, SchemaValidationError)
	}
	if err == nil {
		t.Fatalf("err = nil, want a host-grant rejection")
	}
	if raw != nil {
		t.Fatalf("rejected load returned raw=%v, want nil", raw)
	}
	msg := FormatLoadError(path, cat, err, LaunchAborted)
	for _, part := range []string{"codemeld: " + path + ": does not match the settings schema", "schema validation failed at permissions.0: ", ".codemeld/settings.yaml"} {
		if !strings.Contains(msg, part) {
			t.Fatalf("stderr message %q missing %q", msg, part)
		}
	}
}

const globalDeclaredCommandsYAML = "declared_commands:\n  - \"prep-open-tasks.sh --only\"\n"

func TestValidateGlobalSettingsBytes_RejectsDeclaredCommands(t *testing.T) {
	path := writeFile(t, globalDeclaredCommandsYAML, 0o600)

	if _, _, cat, err := LoadYAML(path); cat != LoadOK || err != nil {
		t.Fatalf("LoadYAML cat = %q, err = %v; fixture must be schema-valid", cat, err)
	}

	raw, cat, err := ValidateGlobalSettingsBytes([]byte(globalDeclaredCommandsYAML), path)
	if cat != SchemaValidationError {
		t.Fatalf("cat = %q, want %q", cat, SchemaValidationError)
	}
	if err == nil {
		t.Fatalf("err = nil, want a declared_commands rejection")
	}
	if raw != nil {
		t.Fatalf("rejected load returned raw=%v, want nil", raw)
	}
	msg := FormatLoadError(path, cat, err, LaunchAborted)
	for _, part := range []string{"codemeld: " + path + ": does not match the settings schema", "schema validation failed at declared_commands: ", ".codemeld/settings.yaml"} {
		if !strings.Contains(msg, part) {
			t.Fatalf("stderr message %q missing %q", msg, part)
		}
	}
}

func TestValidateProjectSettingsBytes_KeepsDeclaredCommands(t *testing.T) {
	path := writeFile(t, globalDeclaredCommandsYAML, 0o600)

	raw, cat, err := ValidateProjectSettingsBytes([]byte(globalDeclaredCommandsYAML), path)
	if cat != LoadOK || err != nil {
		t.Fatalf("cat = %q, err = %v; want LoadOK and nil in the project layer", cat, err)
	}
	if raw == nil || raw["declared_commands"] == nil {
		t.Fatalf("raw = %v, want declared_commands preserved", raw)
	}
}

func TestValidateGlobalSettingsBytes_RejectsWritableFolders(t *testing.T) {
	for _, content := range []string{
		"writable_folders: []\n",
		"writable_folders: [\"/data/x\"]\n",
	} {
		t.Run(content, func(t *testing.T) {
			path := writeFile(t, content, 0o600)
			raw, cat, err := ValidateGlobalSettingsBytes([]byte(content), path)
			if cat != SchemaValidationError {
				t.Fatalf("cat = %q, want %q", cat, SchemaValidationError)
			}
			if err == nil || raw != nil {
				t.Fatalf("raw = %v, err = %v; want a writable_folders rejection", raw, err)
			}
			if !strings.Contains(err.Error(), globalWritableFoldersDetail) {
				t.Fatalf("error %q missing %q", err.Error(), globalWritableFoldersDetail)
			}
		})
	}
}

func TestValidateProjectSettingsBytes_AcceptsWritableFoldersShape(t *testing.T) {
	for _, content := range []string{
		"writable_folders: [\"/data/x\", \"~/y\"]\n",
		"writable_folders: [\"/data/x\", \"rel/path\", \"~user/x\", \"/\", \"~/.codemeld\"]\n",
	} {
		t.Run(content, func(t *testing.T) {
			path := writeFile(t, content, 0o600)
			raw, cat, err := ValidateProjectSettingsBytes([]byte(content), path)
			if cat != LoadOK || err != nil {
				t.Fatalf("cat = %q, err = %v; want LoadOK and nil", cat, err)
			}
			if _, ok := raw["writable_folders"]; !ok {
				t.Fatalf("raw = %v, want writable_folders preserved", raw)
			}
		})
	}
}

func TestValidateProjectSettingsBytes_RejectsMisshapedWritableFolders(t *testing.T) {
	for _, content := range []string{
		"writable_folders: \"/data/x\"\n",
		"writable_folders: [3]\n",
	} {
		t.Run(content, func(t *testing.T) {
			path := writeFile(t, content, 0o600)
			raw, cat, err := ValidateProjectSettingsBytes([]byte(content), path)
			if cat != SchemaValidationError {
				t.Fatalf("cat = %q, want %q", cat, SchemaValidationError)
			}
			if err == nil || raw != nil {
				t.Fatalf("raw = %v, err = %v; want a rejection", raw, err)
			}
			if !strings.Contains(err.Error(), "writable_folders") {
				t.Fatalf("error %q missing writable_folders", err.Error())
			}
		})
	}
}

var settingsLayerValidators = []struct {
	name     string
	validate func([]byte, string) (map[string]any, LoadFailure, error)
}{
	{"global", ValidateGlobalSettingsBytes},
	{"project", ValidateProjectSettingsBytes},
}

func TestValidateSettingsBytes_AcceptsBlockedPathsInBothLayers(t *testing.T) {
	for _, layer := range settingsLayerValidators {
		for _, content := range []string{
			"blocked_paths: [\"~/.ssh\", \"/data/secrets\", \"~/.docker/config.json\"]\n",
			"blocked_paths: []\n",
		} {
			t.Run(layer.name+" "+content, func(t *testing.T) {
				path := writeFile(t, content, 0o600)
				raw, cat, err := layer.validate([]byte(content), path)
				if cat != LoadOK || err != nil {
					t.Fatalf("cat = %q, err = %v; want LoadOK and nil", cat, err)
				}
				if _, ok := raw["blocked_paths"]; !ok {
					t.Fatalf("raw = %v, want blocked_paths preserved", raw)
				}
			})
		}
	}
}

func TestValidateSettingsBytes_RejectsMisshapedBlockedPathsInBothLayers(t *testing.T) {
	for _, layer := range settingsLayerValidators {
		for _, content := range []string{
			"blocked_paths: [\"secrets\"]\n",
			"blocked_paths: [\"./x\"]\n",
			"blocked_paths: [\"~user/x\"]\n",
			"blocked_paths: [\"\"]\n",
			"blocked_paths: [3]\n",
			"blocked_paths: \"/data/secrets\"\n",
		} {
			t.Run(layer.name+" "+content, func(t *testing.T) {
				path := writeFile(t, content, 0o600)
				raw, cat, err := layer.validate([]byte(content), path)
				if cat != SchemaValidationError {
					t.Fatalf("cat = %q, want %q", cat, SchemaValidationError)
				}
				if err == nil || raw != nil {
					t.Fatalf("raw = %v, err = nil; want a rejection", raw)
				}
				for _, part := range []string{path, "blocked_paths"} {
					if !strings.Contains(err.Error(), part) {
						t.Fatalf("error %q missing %q", err.Error(), part)
					}
				}
			})
		}
	}
}

func TestValidateGlobalSettingsBytes_KeepsNonHostPermissions(t *testing.T) {
	const content = "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: /home/u\n    grant_kind: folder\n"
	path := writeFile(t, content, 0o600)

	raw, cat, err := ValidateGlobalSettingsBytes([]byte(content), path)
	if cat != LoadOK || err != nil {
		t.Fatalf("cat = %q, err = %v; want LoadOK and nil", cat, err)
	}
	if raw == nil {
		t.Fatalf("raw = nil, want the decoded map")
	}
}

func TestValidateGlobalSettingsBytes_AcceptsLegacyConfinementKey(t *testing.T) {
	const content = "confinement:\n  shared_temp_folders: allow\n"
	path := writeFile(t, content, 0o600)

	if _, _, cat, err := LoadYAML(path); cat != LoadOK || err != nil {
		t.Fatalf("LoadYAML cat = %q, err = %v; want LoadOK and nil", cat, err)
	}
	raw, cat, err := ValidateGlobalSettingsBytes([]byte(content), path)
	if cat != LoadOK || err != nil || raw == nil {
		t.Fatalf("cat = %q, err = %v, raw = %v; want LoadOK and the decoded map", cat, err, raw)
	}
}

// A schema-valid entry ParseEntry refuses must be rejected at its own layer. Composition can
// drop such an entry behind an equivalent one from another layer, so a check that runs only
// over the composed list lets the invalid source layer through.
func TestValidatePermissionEntries_RejectsSchemaValidAuthorizationInvalid(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "unparseable host",
			content: "permissions:\n  - kind: tool\n    subject: web_search\n    host_scope: \"not a host\"\n    grant_kind: project\n",
		},
		{
			name:    "relative path scope",
			content: "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: relative/dir\n    grant_kind: folder\n",
		},
		{
			name:    "mismatched literal argument hash",
			content: "permissions:\n  - kind: literal\n    subject: ls -la\n    path_scope: /home/u\n    grant_kind: folder\n    argument_hash: \"" + strings.Repeat("a", 64) + "\"\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeFile(t, tt.content, 0o600)
			if _, _, cat, err := LoadYAML(path); cat != LoadOK || err != nil {
				t.Fatalf("LoadYAML cat = %q, err = %v; fixture must be schema-valid", cat, err)
			}
			for name, validate := range map[string]func([]byte, string) (map[string]any, LoadFailure, error){
				"global":  ValidateGlobalSettingsBytes,
				"project": ValidateProjectSettingsBytes,
			} {
				raw, cat, err := validate([]byte(tt.content), path)
				if cat != SchemaValidationError || err == nil || raw != nil {
					t.Fatalf("%s: cat = %q, err = %v, raw = %v; want a rejection", name, cat, err, raw)
				}
			}
		})
	}
}

func TestValidateProjectSettingsBytes_RejectsGlobalOnlyKey(t *testing.T) {
	const content = "web_research:\n  api_key: secret\n"
	path := writeFile(t, content, 0o600)

	raw, cat, err := ValidateProjectSettingsBytes([]byte(content), path)
	if cat != SchemaValidationError || err == nil || raw != nil {
		t.Fatalf("cat = %q, err = %v, raw = %v; want a global-only rejection", cat, err, raw)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("error %q leaks the credential value", err)
	}
}

func TestValidateProjectSettingsBytes_RejectsConfinementKeys(t *testing.T) {
	for _, tc := range []struct {
		content string
		wantKey string
	}{
		{"confinement:\n  program_lookup: strict\n", "confinement.program_lookup"},
		{"confinement:\n  shared_temp_folders: allow\n", "confinement.shared_temp_folders"},
		{"confinement:\n  shared_temp_folders: deny\n  program_lookup: friendly\n", "confinement.program_lookup"},
		{"confinement:\n  program_lookup: strict\nattribution: true\n", "attribution"},
	} {
		t.Run(tc.wantKey, func(t *testing.T) {
			path := writeFile(t, tc.content, 0o600)
			raw, cat, err := ValidateProjectSettingsBytes([]byte(tc.content), path)
			if cat != SchemaValidationError || err == nil || raw != nil {
				t.Fatalf("cat = %q, err = %v, raw = %v; want a global-only rejection", cat, err, raw)
			}
			if want := "schema validation failed at " + tc.wantKey + ": " + globalOnlyDetail; !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not contain %q", err, want)
			}
		})
	}
}

func TestCopyLayer_SharesNoStructure(t *testing.T) {
	original := map[string]any{"provider": map[string]any{"p": map[string]any{"api_key": "k"}}}
	copied := CopyLayer(original)
	original["provider"].(map[string]any)["p"].(map[string]any)["api_key"] = "rotated"

	got := copied["provider"].(map[string]any)["p"].(map[string]any)["api_key"]
	if got != "k" {
		t.Fatalf("copied api_key = %v, want the value captured at copy time", got)
	}
}

func TestWarnIfBroaderThan0600_Exactly0600(t *testing.T) {
	path := writeFile(t, "x: 1\n", 0o600)
	out := testsupport.CaptureStderr(t, func() { WarnIfBroaderThan0600(path) })
	if out != "" {
		t.Fatalf("stderr = %q, want empty for mode 0600", out)
	}
}

func TestWarnIfBroaderThan0600_Missing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	out := testsupport.CaptureStderr(t, func() { WarnIfBroaderThan0600(path) })
	if out != "" {
		t.Fatalf("stderr = %q, want empty for missing file", out)
	}
}

func TestWarnIfBroaderThan0600_WindowsSuppressed(t *testing.T) {
	orig := isWindows
	t.Cleanup(func() { isWindows = orig })
	isWindows = true

	path := writeFile(t, "x: 1\n", 0o644)
	out := testsupport.CaptureStderr(t, func() { WarnIfBroaderThan0600(path) })
	if out != "" {
		t.Fatalf("stderr = %q, want empty when isWindows=true", out)
	}
}

func TestLoadYAMLBytes_MatchesTheFileEntryPoint(t *testing.T) {
	contents := []struct {
		name    string
		content string
		want    LoadFailure
	}{
		{"clean file", "agent:\n  max_concurrency: 4\n", LoadOK},
		{"empty file", "", LoadOK},
		{"whitespace and comment only", "\n  \n# just a comment\n", LoadOK},
		{"malformed YAML", "agent: { max_concurrency: 4\n", YAMLParseError},
		{"wrong-type schema failure", "agent:\n  max_concurrency: \"three\"\n", SchemaValidationError},
		{"root sequence", "[]\n", SchemaValidationError},
		{"root scalar", "\"x\"\n", SchemaValidationError},
	}
	for _, tt := range contents {
		t.Run(tt.name, func(t *testing.T) {
			path := writeFile(t, tt.content, 0o600)
			wantDoc, wantRaw, wantCat, wantErr := LoadYAML(path)
			doc, raw, cat, err := LoadYAMLBytes([]byte(tt.content), path)

			if wantCat != tt.want {
				t.Fatalf("LoadYAML cat = %q, want %q (err=%v)", wantCat, tt.want, wantErr)
			}
			if cat != tt.want {
				t.Fatalf("cat = %q, want %q (err=%v)", cat, tt.want, err)
			}
			if (err == nil) != (wantErr == nil) {
				t.Fatalf("err = %v, want the file loader's %v", err, wantErr)
			}
			if !reflect.DeepEqual(raw, wantRaw) {
				t.Fatalf("raw = %#v, want the file loader's %#v", raw, wantRaw)
			}
			if (doc == nil) != (wantDoc == nil) {
				t.Fatalf("doc = %#v, want the file loader's %#v", doc, wantDoc)
			}
			if tt.want == LoadOK {
				return
			}
			if got, want := FormatLoadError(path, cat, err, LaunchAborted), FormatLoadError(path, wantCat, wantErr, LaunchAborted); got != want {
				t.Fatalf("diagnostic = %q, want the file loader's %q", got, want)
			}
		})
	}
}

// The bytes entry point must classify and diagnose against a path it never opens, since its
// caller has already read — and checked — the content it is handed.
func TestLoadYAMLBytes_NamesThePathWithoutReadingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-created.yaml")

	if _, raw, cat, err := LoadYAMLBytes([]byte("agent:\n  max_concurrency: 4\n"), path); cat != LoadOK {
		t.Fatalf("cat = %q (err=%v), want %q for valid bytes under an absent path", cat, err, LoadOK)
	} else if agent, _ := raw["agent"].(map[string]any); fmt.Sprint(agent["max_concurrency"]) != "4" {
		t.Fatalf("raw = %#v, want the supplied bytes decoded", raw)
	}

	_, _, cat, err := LoadYAMLBytes([]byte("agent:\n  max_concurrency: \"three\"\n"), path)
	if cat != SchemaValidationError {
		t.Fatalf("cat = %q, want %q", cat, SchemaValidationError)
	}
	if !strings.Contains(FormatLoadError(path, cat, err, LaunchAborted), path) {
		t.Fatalf("diagnostic %q does not name the source path %q", FormatLoadError(path, cat, err, LaunchAborted), path)
	}
}

const duplicateInEntryYAML = `permissions:
  - kind: tool
    subject: web_search
    grant_kind: session
  - kind: literal
    subject: "prdtasks-locked.sh create :*"
    path_scope: /home/u
    grant_kind: folder
    grant_kind: folder
`

func TestFormatLoadError_DuplicateKeyInAListEntry(t *testing.T) {
	path := writeFile(t, duplicateInEntryYAML, 0o600)
	_, _, cat, err := LoadYAML(path)
	if cat != YAMLParseError {
		t.Fatalf("cat = %q, want %q (err=%v)", cat, YAMLParseError, err)
	}

	msg := FormatLoadError(path, cat, err, LaunchAborted)
	wantPrefix := "codemeld: " + path + ": is not valid YAML; codemeld did not start.\n"
	if !strings.HasPrefix(msg, wantPrefix) {
		t.Fatalf("message %q does not start with %q", msg, wantPrefix)
	}
	for _, part := range []string{
		`the key "grant_kind" is set twice in the same block, at line 8 and again at line 9`,
		`the entry whose subject is "prdtasks-locked.sh create :*"`,
		`to fix: delete one of the two "grant_kind" lines, either line 8 or line 9`,
	} {
		if !strings.Contains(msg, part) {
			t.Fatalf("message %q missing %q", msg, part)
		}
	}
}

func TestFormatLoadError_DuplicateKeyOutsideAnEntryOmitsTheSubjectClause(t *testing.T) {
	path := writeFile(t, "agent:\n  max_concurrency: 1\n  max_concurrency: 2\n", 0o600)
	_, _, cat, err := LoadYAML(path)
	if cat != YAMLParseError {
		t.Fatalf("cat = %q, want %q (err=%v)", cat, YAMLParseError, err)
	}

	msg := FormatLoadError(path, cat, err, LaunchAborted)
	if !strings.Contains(msg, `the key "max_concurrency" is set twice in the same block, at line 2 and again at line 3`) {
		t.Fatalf("message %q does not name the duplicated key and both lines", msg)
	}
	if strings.Contains(msg, "subject") {
		t.Fatalf("message %q names an entry subject the file does not have", msg)
	}
}

func TestFormatLoadError_NonDuplicateParseErrorsKeepTheParserDetail(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantPart string
	}{
		{"tab indentation", "agent:\n\tmax_concurrency: 1\n", "cannot start any token"},
		{"unclosed quote", "agent:\n  mode: \"unclosed\n", "quote"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeFile(t, tt.content, 0o600)
			_, _, cat, err := LoadYAML(path)
			if cat != YAMLParseError {
				t.Fatalf("cat = %q, want %q (err=%v)", cat, YAMLParseError, err)
			}

			msg := FormatLoadError(path, cat, err, LaunchAborted)
			if !strings.HasPrefix(msg, "codemeld: "+path+": is not valid YAML; codemeld did not start.\n") {
				t.Fatalf("message %q does not carry the shared frame", msg)
			}
			if !strings.Contains(msg, "\n  what happened: ") || !strings.Contains(strings.ToLower(msg), tt.wantPart) {
				t.Fatalf("message %q does not report the parser's own detail about %s", msg, tt.wantPart)
			}
			if !strings.Contains(msg, "\n  to fix: correct the YAML at the position reported above, then start codemeld again") {
				t.Fatalf("message %q has no generic fix line", msg)
			}
			if strings.Contains(msg, "set twice") {
				t.Fatalf("message %q claims a duplicate key that is not there", msg)
			}
		})
	}
}

func TestFormatLoadError_NeverPrintsTheCategoryToken(t *testing.T) {
	path := writeFile(t, "x: 1\n", 0o600)
	for _, cat := range []LoadFailure{UnreadableFile, YAMLParseError, SchemaValidationError} {
		t.Run(string(cat), func(t *testing.T) {
			msg := FormatLoadError(path, cat, fmt.Errorf("%s: underlying detail", path), LaunchAborted)
			for _, token := range []string{string(UnreadableFile), string(YAMLParseError), string(SchemaValidationError)} {
				if strings.Contains(msg, token) {
					t.Fatalf("message %q leaks the internal category token %q", msg, token)
				}
			}
			if !strings.Contains(msg, "codemeld did not start") {
				t.Fatalf("message %q does not state the consequence", msg)
			}
		})
	}
}

func TestFormatYAMLParseFailure_CarriesTheSameHintWithoutAPath(t *testing.T) {
	src := []byte(duplicateInEntryYAML)
	_, _, _, err := LoadYAMLBytes(src, "unused.yaml")
	if err == nil {
		t.Fatal("err = nil, want a parse failure for a duplicate key")
	}

	body := FormatYAMLParseFailure(src, errors.Unwrap(err), LaunchAborted)
	if strings.HasPrefix(body, "codemeld: ") {
		t.Fatalf("body %q carries an attribution its caller supplies", body)
	}
	for _, part := range []string{
		"is not valid YAML; codemeld did not start.",
		`the key "grant_kind" is set twice in the same block, at line 8 and again at line 9`,
		`to fix: delete one of the two "grant_kind" lines`,
	} {
		if !strings.Contains(body, part) {
			t.Fatalf("body %q missing %q", body, part)
		}
	}
}

func TestFormatLoadError_DuplicateKeyNamesAnEntryThatCarriesNameInsteadOfSubject(t *testing.T) {
	path := writeFile(t, "declared_commands:\n  - name: build\n    argv: [make]\n    argv: [make]\n", 0o600)
	_, _, cat, err := LoadYAML(path)
	if cat != YAMLParseError {
		t.Fatalf("cat = %q, want %q (err=%v)", cat, YAMLParseError, err)
	}

	msg := FormatLoadError(path, cat, err, LaunchAborted)
	if !strings.Contains(msg, `the block is the entry whose name is "build"`) {
		t.Fatalf("message %q does not name the entry by its name key", msg)
	}
}

// The local layer must report the same category and message shape as the project layer for
// every rule the two share, so a rejection renders identically wherever it came from.
func TestValidateLocalSettingsBytes_ParityWithTheProjectLayer(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"global-only key", "web_research:\n  api_key: secret\n"},
		{"unparseable permission entry", "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: relative/dir\n    grant_kind: folder\n"},
		{"misshapen blocked_paths", "blocked_paths: [\"secrets\"]\n"},
		{"malformed YAML", "model:\n  active: [\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeFile(t, tt.content, 0o600)
			localRaw, localCat, localErr := ValidateLocalSettingsBytes([]byte(tt.content), path)
			projectRaw, projectCat, projectErr := ValidateProjectSettingsBytes([]byte(tt.content), path)
			if localCat != projectCat || localCat == LoadOK {
				t.Fatalf("local cat = %q, project cat = %q; want the same non-OK category", localCat, projectCat)
			}
			if localRaw != nil || projectRaw != nil {
				t.Fatalf("local raw = %v, project raw = %v; want both nil", localRaw, projectRaw)
			}
			if localErr == nil || projectErr == nil || localErr.Error() != projectErr.Error() {
				t.Fatalf("local err = %v, project err = %v; want the same message", localErr, projectErr)
			}
			if localCat == SchemaValidationError && !strings.Contains(localErr.Error(), path) {
				t.Fatalf("error %q missing the file path", localErr)
			}
		})
	}
}

func TestValidateLocalSettingsBytes_AcceptsWhatTheProjectLayerAlsoAccepts(t *testing.T) {
	const content = "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: /home/u\n    grant_kind: folder\nblocked_paths: [\"~/.ssh\"]\n"
	path := writeFile(t, content, 0o600)
	if _, cat, err := ValidateLocalSettingsBytes([]byte(content), path); cat != LoadOK || err != nil {
		t.Fatalf("local cat = %q, err = %v; want LoadOK and nil", cat, err)
	}
	if _, cat, err := ValidateProjectSettingsBytes([]byte(content), path); cat != LoadOK || err != nil {
		t.Fatalf("project cat = %q, err = %v; want LoadOK and nil", cat, err)
	}
}
