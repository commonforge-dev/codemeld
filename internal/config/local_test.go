// Tests for the local settings layer: path derivation, the write helper's modes and lock, and the allow-list.
package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/locks"
	"codemeld.dev/codemeld/internal/permissions"
)

func TestLocalSettingsPath_DerivesFromTheResolvedProjectRoot(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	project := t.TempDir()
	mkMarker(t, project)
	sub := filepath.Join(project, "a", "b")
	mkDirs(t, sub)

	for _, mode := range []string{"launch-dir-only", "project-root"} {
		t.Run(mode, func(t *testing.T) {
			cwd := sub
			if mode == "launch-dir-only" {
				cwd = project
			}
			root, _, _, err := LocateProjectRoot(cwd, mode)
			if err != nil {
				t.Fatalf("LocateProjectRoot: %v", err)
			}
			want := filepath.Join(root, ".codemeld", "settings.local.yaml")
			if got := LocalSettingsPath(root); got != want {
				t.Fatalf("LocalSettingsPath = %q, want %q", got, want)
			}
			if got := LocalSettingsLockPath(root); got != want+".lock" {
				t.Fatalf("LocalSettingsLockPath = %q, want %q", got, want+".lock")
			}
		})
	}
}

func TestLocalSettingsPath_EmptyRoot(t *testing.T) {
	if got := LocalSettingsPath(""); got != "" {
		t.Fatalf("LocalSettingsPath(\"\") = %q, want empty", got)
	}
	if got := LocalSettingsLockPath(""); got != "" {
		t.Fatalf("LocalSettingsLockPath(\"\") = %q, want empty", got)
	}
}

// controlDirMode is the mode MkdirAll(0755) produces under this process's umask, so the
// assertion on the directory codemeld creates does not depend on the runner's umask.
func controlDirMode(t *testing.T) os.FileMode {
	t.Helper()
	control := filepath.Join(t.TempDir(), "control")
	if err := os.MkdirAll(control, 0o755); err != nil {
		t.Fatalf("mkdir control: %v", err)
	}
	info, err := os.Stat(control)
	if err != nil {
		t.Fatalf("stat control: %v", err)
	}
	return info.Mode().Perm()
}

func TestPersistLocal_CreatesTheDirectoryAndFileWithTheSharedModes(t *testing.T) {
	project := t.TempDir()

	created, reason, _, err := PersistLocal(project, KeyPermissions, folderEntry("ls", project))
	if reason != ReasonNone || err != nil {
		t.Fatalf("reason = %q, err = %v; want a clean write", reason, err)
	}
	if !created {
		t.Fatalf("created = false, want true for the write that made the file")
	}

	dir, err := os.Stat(filepath.Join(project, ".codemeld"))
	if err != nil {
		t.Fatalf("stat .codemeld: %v", err)
	}
	if got, want := dir.Mode().Perm(), controlDirMode(t); got != want {
		t.Fatalf("directory mode = %o, want %o", got, want)
	}
	file, err := os.Stat(LocalSettingsPath(project))
	if err != nil {
		t.Fatalf("stat local settings: %v", err)
	}
	if got := file.Mode().Perm(); got != settingsFileMode.Perm() {
		t.Fatalf("file mode = %o, want %o", got, settingsFileMode.Perm())
	}
}

func TestPersistLocal_LeavesBroaderExistingModesAlone(t *testing.T) {
	project := t.TempDir()
	dir := filepath.Join(project, ".codemeld")
	mkDirs(t, dir)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	path := LocalSettingsPath(project)
	if err := os.WriteFile(path, []byte("permissions: []\n"), 0o644); err != nil {
		t.Fatalf("seed local settings: %v", err)
	}

	created, reason, _, err := PersistLocal(project, KeyPermissions, folderEntry("ls", project))
	if reason != ReasonNone || err != nil {
		t.Fatalf("reason = %q, err = %v; want a clean write", reason, err)
	}
	if created {
		t.Fatalf("created = true, want false for a write to an existing file")
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := di.Mode().Perm(); got != 0o777 {
		t.Fatalf("directory mode = %o, want 0777 left alone", got)
	}
	// The atomic replace publishes a new inode at the shared settings mode; the write neither
	// refused the broader file nor chmod'd anything.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if got := fi.Mode().Perm(); got != settingsFileMode.Perm() {
		t.Fatalf("file mode = %o, want %o", got, settingsFileMode.Perm())
	}
}

func TestPersistLocal_LockTimeoutLeavesTheFileUntouched(t *testing.T) {
	project := t.TempDir()
	mkDirs(t, filepath.Join(project, ".codemeld"))
	path := LocalSettingsPath(project)
	const seeded = "permissions: []\n"
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed local settings: %v", err)
	}

	var locked string
	setAcquireLock(t, func(p string, _ time.Duration) (func(), locks.LockReason, error) {
		locked = p
		return func() {}, locks.ReasonLockTimeout, errors.New("forced timeout")
	})
	failIfMergeCalled(t)

	created, reason, _, err := PersistLocal(project, KeyPermissions, folderEntry("ls", project))
	if reason != ReasonLockTimeout || err == nil {
		t.Fatalf("reason = %q, err = %v; want a lock timeout", reason, err)
	}
	if created {
		t.Fatalf("created = true, want false when the write never ran")
	}
	if locked != LocalSettingsLockPath(project) {
		t.Fatalf("locked = %q, want the sidecar %q", locked, LocalSettingsLockPath(project))
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != seeded {
		t.Fatalf("file = %q, err = %v; want the seeded bytes unchanged", data, err)
	}
}

func TestPersistLocal_ModelActiveRoundTrips(t *testing.T) {
	project := t.TempDir()
	active := map[string]any{"provider": "openai", "id": "gpt-x", "effort": "high"}

	if _, reason, _, err := PersistLocal(project, KeyModelActive, active); reason != ReasonNone || err != nil {
		t.Fatalf("reason = %q, err = %v; want a clean write", reason, err)
	}

	path := LocalSettingsPath(project)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read local settings: %v", err)
	}
	if !strings.Contains(string(data), "id: gpt-x") {
		t.Fatalf("on-disk bytes %q must name the field id", data)
	}
	raw, cat, verr := ValidateLocalSettingsBytes(data, path)
	if cat != LoadOK || verr != nil {
		t.Fatalf("cat = %q, err = %v; want the written file to validate", cat, verr)
	}
	model, ok := raw["model"].(map[string]any)
	if !ok {
		t.Fatalf("raw = %v, want a model map", raw)
	}
	got, ok := model["active"].(map[string]any)
	if !ok || got["provider"] != "openai" || got["id"] != "gpt-x" || got["effort"] != "high" {
		t.Fatalf("model.active = %v, want the written selection", model["active"])
	}
}

func TestValidateLocalSettingsBytes_AcceptsTheAllowedShape(t *testing.T) {
	for name, content := range map[string]string{
		"empty document": "",
		"comment only":   "# nothing here\n",
		"all three keys": "model:\n  active:\n    provider: openai\n    id: gpt-x\n" +
			"permissions:\n  - kind: direct\n    subject: ls\n    path_scope: /home/u\n    grant_kind: folder\n" +
			"blocked_paths: [\"~/.ssh\"]\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.local.yaml")
			raw, cat, err := ValidateLocalSettingsBytes([]byte(content), path)
			if cat != LoadOK || err != nil {
				t.Fatalf("cat = %q, err = %v; want LoadOK and nil", cat, err)
			}
			if raw == nil {
				t.Fatalf("raw = nil, want a decoded (possibly empty) layer")
			}
		})
	}
}

func TestValidateLocalSettingsBytes_RejectsKeysOutsideTheAllowList(t *testing.T) {
	tests := []struct {
		name    string
		content string
		key     string
	}{
		{"declared_commands", "declared_commands: [\"ls\"]\n", "declared_commands"},
		{"readable_folders", "readable_folders: [\"/data\"]\n", "readable_folders"},
		{"writable_folders", "writable_folders: [\"/data\"]\n", "writable_folders"},
		{"discovery.boundary", "discovery:\n  boundary: project-root\n", "discovery.boundary"},
		{"sessions.retention_days", "sessions:\n  retention_days: 30\n", "sessions.retention_days"},
		{"sessions.max_tool_output_bytes", "sessions:\n  max_tool_output_bytes: 4096\n", "sessions.max_tool_output_bytes"},
		{"provider", "provider:\n  openai:\n    base_url: https://example.test\n    api_key: k\n", "provider.openai.api_key"},
		{"auth", "auth:\n  openai-chatgpt:\n    access_token: t\n", "auth.openai-chatgpt"},
		{"model.favorites", "model:\n  favorites:\n    - provider: openai\n      id: gpt-x\n", "model.favorites"},
		{"web_research", "web_research:\n  api_key: k\n", "web_research.api_key"},
		{"attribution", "attribution: true\n", "attribution"},
		{"unknown top-level key", "surprise: 1\n", "surprise"},
		{"case-differing key", "Model:\n  active: x\n", "Model"},
		{"whitespace-padded key", "\" model \":\n  active: x\n", " model "},
		{"permission-shaped top-level key", "grant_kind: folder\n", "grant_kind"},
		{"model.last_used", "model:\n  last_used:\n    provider: openai\n    id: gpt-x\n", "model.last_used"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.local.yaml")
			raw, cat, err := ValidateLocalSettingsBytes([]byte(tt.content), path)
			if cat != SchemaValidationError || err == nil || raw != nil {
				t.Fatalf("cat = %q, err = %v, raw = %v; want a rejection", cat, err, raw)
			}
			for _, part := range []string{path, tt.key} {
				if !strings.Contains(err.Error(), part) {
					t.Fatalf("error %q missing %q", err, part)
				}
			}
		})
	}
}

// An unknown model subkey is refused by the shared schema before the local allow-list runs, so
// the message names model rather than the dotted subkey.
func TestValidateLocalSettingsBytes_RejectsUnknownModelSubkey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.local.yaml")
	raw, cat, err := ValidateLocalSettingsBytes([]byte("model:\n  surprise: 1\n"), path)
	if cat != SchemaValidationError || err == nil || raw != nil {
		t.Fatalf("cat = %q, err = %v, raw = %v; want a rejection", cat, err, raw)
	}
	if !strings.Contains(err.Error(), "model") || !strings.Contains(err.Error(), path) {
		t.Fatalf("error %q must name the file and the model key", err)
	}
}

func TestValidateLocalSettingsBytes_GlobalOnlyKeysKeepTheirRemediation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.local.yaml")
	_, _, err := ValidateLocalSettingsBytes([]byte("attribution: true\n"), path)
	if err == nil || !strings.Contains(err.Error(), globalOnlyDetail) {
		t.Fatalf("error = %v, want the global-only remediation", err)
	}

	_, _, err = ValidateLocalSettingsBytes([]byte("declared_commands: [\"ls\"]\n"), path)
	if err == nil || !strings.Contains(err.Error(), localKeyDetail) {
		t.Fatalf("error = %v, want the project-settings remediation", err)
	}
}

func TestValidateLocalSettingsBytes_GrantKinds(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantFail string
	}{
		{
			name:    "folder path grant",
			content: "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: /home/u\n    grant_kind: folder\n",
		},
		{
			name:    "project host grant",
			content: "permissions:\n  - kind: tool\n    subject: web_fetch\n    host_scope: example.test\n    grant_kind: project\n",
		},
		{
			name:     "global grant",
			content:  "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: \"*\"\n    grant_kind: global\n",
			wantFail: "permissions.0",
		},
		{
			name:     "wildcard path scope",
			content:  "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: \"*\"\n    grant_kind: folder\n",
			wantFail: "permissions.0",
		},
		{
			name:     "unparseable entry",
			content:  "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: relative/dir\n    grant_kind: folder\n",
			wantFail: "permissions.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.local.yaml")
			raw, cat, err := ValidateLocalSettingsBytes([]byte(tt.content), path)
			if tt.wantFail == "" {
				if cat != LoadOK || err != nil || raw == nil {
					t.Fatalf("cat = %q, err = %v; want the entry accepted", cat, err)
				}
				return
			}
			if cat != SchemaValidationError || err == nil {
				t.Fatalf("cat = %q, err = %v; want a rejection", cat, err)
			}
			for _, part := range []string{path, tt.wantFail} {
				if !strings.Contains(err.Error(), part) {
					t.Fatalf("error %q missing %q", err, part)
				}
			}
		})
	}
}

// An entry ParseEntry refuses must keep ParseEntry's own message rather than being re-reported
// by the local grant-kind rule.
func TestValidateLocalSettingsBytes_KeepsParseEntryMessages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.local.yaml")
	_, _, err := ValidateLocalSettingsBytes([]byte("permissions:\n  - kind: direct\n    subject: ls\n    path_scope: relative/dir\n    grant_kind: folder\n"), path)
	if err == nil || !strings.Contains(err.Error(), "must be \"*\" or a cleaned absolute path") {
		t.Fatalf("error = %v, want ParseEntry's path_scope message", err)
	}
	_, _, err = ValidateLocalSettingsBytes([]byte("permissions:\n  - kind: direct\n    subject: ls\n    path_scope: \"*\"\n    grant_kind: global\n"), path)
	if err == nil || !strings.Contains(err.Error(), localGlobalGrantDetail) {
		t.Fatalf("error = %v, want the local layer's machine-wide-grant rejection", err)
	}
}

func TestValidateLocalSettingsBytes_MatchesProjectCategoryOnMalformedYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.local.yaml")
	const broken = "model:\n  active: [\n"
	_, localCat, localErr := ValidateLocalSettingsBytes([]byte(broken), path)
	_, projectCat, projectErr := ValidateProjectSettingsBytes([]byte(broken), path)
	if localCat != projectCat || localCat == LoadOK {
		t.Fatalf("local cat = %q, project cat = %q; want the same non-OK category", localCat, projectCat)
	}
	if localErr == nil || projectErr == nil {
		t.Fatalf("local err = %v, project err = %v; want both to fail", localErr, projectErr)
	}
}

func TestPersistLocal_CreatedOnlyOnTheWriteThatMadeTheFile(t *testing.T) {
	project := t.TempDir()
	entry := func(subject string) permissions.PermissionEntry { return folderEntry(subject, project) }

	for i, subject := range []string{"ls", "cat", "echo"} {
		created, reason, _, err := PersistLocal(project, KeyPermissions, entry(subject))
		if reason != ReasonNone || err != nil {
			t.Fatalf("write %d: reason = %q, err = %v", i, reason, err)
		}
		if want := i == 0; created != want {
			t.Fatalf("write %d: created = %v, want %v", i, created, want)
		}
	}
	data, err := os.ReadFile(LocalSettingsPath(project))
	if err != nil {
		t.Fatalf("read local settings: %v", err)
	}
	if strings.Contains(string(data), "created") {
		t.Fatalf("on-disk bytes %q must not store a creation flag", data)
	}
}

func TestPersistLocal_AbsentFileNoOpRemovalIsNotACreation(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		payload any
	}{
		{"permission removal", KeyPermissions, PermissionDelete(folderEntry("ls", "/work").DedupKey())},
		{"blocked path removal", blockedPathsKey, BlockedPathRemove("/home/u", "/home/u/.ssh", 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project := t.TempDir()
			created, reason, _, err := PersistLocal(project, tt.key, tt.payload)
			if reason != ReasonNone || err != nil {
				t.Fatalf("reason = %q, err = %v; want a clean no-op", reason, err)
			}
			if created {
				t.Fatalf("created = true, want false when the removal published nothing")
			}
			if _, statErr := os.Stat(LocalSettingsPath(project)); !errors.Is(statErr, fs.ErrNotExist) {
				t.Fatalf("stat err = %v, want the target still absent", statErr)
			}
		})
	}
}
