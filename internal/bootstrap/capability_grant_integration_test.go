// Production-path integration tests for capability grants: approving one member tool through the
// real authorizer/prompt-gate/persist path stores a folded capability subject, after which a sibling
// member tool at the same scope is auto-matched with no second prompt.
package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/tui"
)

func TestProductionAuthorizer_WriteTreeGrantFoldsCreateEditMkdir(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	sub := filepath.Join(project, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "a.go"), []byte("package a\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	prompts := 0
	var lastCapability string
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		prompts++
		lastCapability = req.CapabilityStoredSubject
		return tui.PromptDecision{Option: tui.OptionAllowFolder, StoredSubject: req.CapabilityStoredSubject}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, project), permissions.NewTurnCache(), newPromptGateBuilder(show), home, project, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewEditTool(home, project, project)); err != nil {
		t.Fatalf("Register edit: %v", err)
	}
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, project, project)); err != nil {
		t.Fatalf("Register create: %v", err)
	}
	if err := reg.Register(tools.BuiltinSource, filetools.NewMkdirTool(home, project, project)); err != nil {
		t.Fatalf("Register mkdir: %v", err)
	}

	if _, derr := dispatch.DispatchTool(context.Background(), filetools.EditToolName,
		map[string]any{"path": "sub/a.go", "old_text": "package a", "new_text": "package b"}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(edit) err = %v, want nil (folder-approved edit)", derr)
	}
	if prompts != 1 {
		t.Fatalf("prompts after edit = %d, want 1", prompts)
	}
	if lastCapability != permissions.CapabilityWriteTree {
		t.Fatalf("prompt CapabilityStoredSubject = %q, want %q (dispatch must carry the write_tree fold to the prompt)", lastCapability, permissions.CapabilityWriteTree)
	}

	folderSettings := config.LocalSettingsPath(project)
	entry := findGrant(t, readPersistedPermissions(t, folderSettings, project), permissions.CapabilityWriteTree)
	if entry.Kind != "tool" || entry.GrantKind != "folder" || entry.PathScope != sub {
		t.Fatalf("persisted entry = %+v, want kind tool / grant_kind folder / path_scope %q", entry, sub)
	}

	auth.resetTurnCache()

	if _, derr := dispatch.DispatchTool(context.Background(), filetools.CreateToolName,
		map[string]any{"path": "sub/b.go", "content": "x"}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(create) err = %v, want nil (folded by the write_tree grant)", derr)
	}
	if _, derr := dispatch.DispatchTool(context.Background(), filetools.MkdirToolName,
		map[string]any{"path": "sub/nested"}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(mkdir) err = %v, want nil (folded by the write_tree grant)", derr)
	}
	if prompts != 1 {
		t.Fatalf("prompts after a sibling create+mkdir = %d, want 1 (write_tree folds create+edit+mkdir; no re-prompt)", prompts)
	}
	if _, statErr := os.Stat(filepath.Join(sub, "b.go")); statErr != nil {
		t.Fatalf("create did not produce a file: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(sub, "nested")); statErr != nil {
		t.Fatalf("mkdir did not produce a directory: %v", statErr)
	}
}

func TestProductionAuthorizer_WriteTreeSessionGrantFoldsMembersWithoutPersisting(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	sub := filepath.Join(project, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "a.go"), []byte("package a\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	prompts := 0
	var lastCapability string
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		prompts++
		lastCapability = req.CapabilityStoredSubject
		return tui.PromptDecision{Option: tui.OptionAllowSession, StoredSubject: req.CapabilityStoredSubject}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, project), permissions.NewTurnCache(), newPromptGateBuilder(show), home, project, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewEditTool(home, project, project)); err != nil {
		t.Fatalf("Register edit: %v", err)
	}
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, project, project)); err != nil {
		t.Fatalf("Register create: %v", err)
	}
	if err := reg.Register(tools.BuiltinSource, filetools.NewMkdirTool(home, project, project)); err != nil {
		t.Fatalf("Register mkdir: %v", err)
	}

	if _, derr := dispatch.DispatchTool(context.Background(), filetools.EditToolName,
		map[string]any{"path": "sub/a.go", "old_text": "package a", "new_text": "package b"}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(edit) err = %v, want nil (session-approved edit)", derr)
	}
	if prompts != 1 {
		t.Fatalf("prompts after edit = %d, want 1", prompts)
	}
	if lastCapability != permissions.CapabilityWriteTree {
		t.Fatalf("prompt CapabilityStoredSubject = %q, want %q (dispatch must carry the write_tree fold to the prompt)", lastCapability, permissions.CapabilityWriteTree)
	}

	folderSettings := config.LocalSettingsPath(project)
	if _, statErr := os.Stat(folderSettings); !os.IsNotExist(statErr) {
		t.Fatalf("os.Stat(folderSettings) after session approval err = %v, want IsNotExist (a session grant must not persist a settings file)", statErr)
	}

	auth.resetTurnCache()

	if _, derr := dispatch.DispatchTool(context.Background(), filetools.CreateToolName,
		map[string]any{"path": "sub/b.go", "content": "x"}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(create) err = %v, want nil (folded by the write_tree session grant)", derr)
	}
	if _, derr := dispatch.DispatchTool(context.Background(), filetools.MkdirToolName,
		map[string]any{"path": "sub/nested"}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(mkdir) err = %v, want nil (folded by the write_tree session grant)", derr)
	}
	if prompts != 1 {
		t.Fatalf("prompts after a sibling create+mkdir = %d, want 1 (the write_tree session grant folds create+edit+mkdir; no re-prompt)", prompts)
	}
	if _, statErr := os.Stat(filepath.Join(sub, "b.go")); statErr != nil {
		t.Fatalf("create did not produce a file: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(sub, "nested")); statErr != nil {
		t.Fatalf("mkdir did not produce a directory: %v", statErr)
	}
	if _, statErr := os.Stat(folderSettings); !os.IsNotExist(statErr) {
		t.Fatalf("os.Stat(folderSettings) after folded siblings err = %v, want IsNotExist (session grants persist nothing)", statErr)
	}
}

func TestProductionAuthorizer_LegacyWriteGrantRefusesMkdir(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	sub := filepath.Join(project, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	folderSettings := config.LocalSettingsPath(project)
	if err := os.MkdirAll(filepath.Dir(folderSettings), 0o755); err != nil {
		t.Fatalf("MkdirAll .codemeld: %v", err)
	}
	seed := fmt.Sprintf("permissions:\n  - kind: tool\n    subject: %s\n    path_scope: %s\n    grant_kind: folder\n", permissions.CapabilityWrite, sub)
	if err := os.WriteFile(folderSettings, []byte(seed), 0o644); err != nil {
		t.Fatalf("WriteFile seed settings: %v", err)
	}
	_, raw, cat, err := config.LoadYAML(folderSettings)
	if err != nil || cat != config.LoadOK {
		t.Fatalf("LoadYAML(seed) cat=%v err=%v, want a readable seeded settings file", cat, err)
	}
	cache, err := config.NewCache(raw, project, nil)
	if err != nil {
		t.Fatalf("NewCache(seed): %v", err)
	}
	seeded := findGrant(t, cache.Permissions(), permissions.CapabilityWrite)
	if seeded.Kind != "tool" || seeded.GrantKind != "folder" || seeded.PathScope != sub {
		t.Fatalf("seeded legacy grant = %+v, want kind tool / grant_kind folder / path_scope %q", seeded, sub)
	}

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	prompts := 0
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		prompts++
		return tui.PromptDecision{Option: tui.OptionAllowFolder, StoredSubject: req.CapabilityStoredSubject}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(show), home, project, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, project, project)); err != nil {
		t.Fatalf("Register create: %v", err)
	}
	if err := reg.Register(tools.BuiltinSource, filetools.NewMkdirTool(home, project, project)); err != nil {
		t.Fatalf("Register mkdir: %v", err)
	}

	if _, derr := dispatch.DispatchTool(context.Background(), filetools.CreateToolName,
		map[string]any{"path": "sub/a.go", "content": "x"}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(create) err = %v, want nil (legacy write folds create)", derr)
	}
	if prompts != 0 {
		t.Fatalf("prompts after create = %d, want 0 (the legacy write grant folds create)", prompts)
	}

	if _, derr := dispatch.DispatchTool(context.Background(), filetools.MkdirToolName,
		map[string]any{"path": "sub/nested"}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(mkdir) err = %v, want nil (prompt approved), got %v", derr, derr)
	}
	if prompts != 1 {
		t.Fatalf("prompts after mkdir = %d, want 1 (a legacy write grant must not fold mkdir)", prompts)
	}

	after := readPersistedPermissions(t, folderSettings, project)
	legacy := findGrant(t, after, permissions.CapabilityWrite)
	if legacy.Kind != "tool" || legacy.GrantKind != "folder" || legacy.PathScope != sub {
		t.Fatalf("legacy write grant after mkdir upgrade = %+v, want it unchanged (kind tool / folder / %q)", legacy, sub)
	}
	upgrade := findGrant(t, after, permissions.CapabilityWriteTree)
	if upgrade.Kind != "tool" || upgrade.GrantKind != "folder" || upgrade.PathScope != sub {
		t.Fatalf("upgrade write_tree grant = %+v, want kind tool / grant_kind folder / path_scope %q", upgrade, sub)
	}

	auth.resetTurnCache()
	if _, derr := dispatch.DispatchTool(context.Background(), filetools.MkdirToolName,
		map[string]any{"path": "sub/nested2"}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(second mkdir) err = %v, want nil (folded by the new write_tree grant)", derr)
	}
	if prompts != 1 {
		t.Fatalf("prompts after second mkdir = %d, want 1 (the write_tree upgrade folds mkdir; no re-prompt)", prompts)
	}
}

// TestProductionAuthorizer_ReadCapabilityGrantFoldsReadFamily drives the capability read side end to end:
// approving "allow in this folder" for an explicit out-of-project grep persists a folder grant whose
// subject is the "read*" capability scoped to that out-of-project folder; later list, glob, and file_count
// at the same scope are different concrete subjects the capability folds, so each is auto-matched with no further
// prompt. An out-of-project read is used so the request reaches the prompt in Build mode (an in-project
// read auto-allows and never creates a grant).
func TestProductionAuthorizer_ReadCapabilityGrantFoldsReadFamily(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	ext, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(ext): %v", err)
	}
	if err := os.WriteFile(filepath.Join(ext, "canary.txt"), []byte("external-canary\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	prompts := 0
	var lastCapability string
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		prompts++
		lastCapability = req.CapabilityStoredSubject
		return tui.PromptDecision{Option: tui.OptionAllowFolder, StoredSubject: req.CapabilityStoredSubject}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, project), permissions.NewTurnCache(), newPromptGateBuilder(show), home, project, mode.NewActiveState(mode.Build, mode.SourceDefault))

	const cap = 65536
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewGrepTool(home, project, project, cap)); err != nil {
		t.Fatalf("Register grep: %v", err)
	}
	if err := reg.Register(tools.BuiltinSource, filetools.NewListTool(home, project, project, cap)); err != nil {
		t.Fatalf("Register list: %v", err)
	}
	if err := reg.Register(tools.BuiltinSource, filetools.NewGlobTool(home, project, project, cap)); err != nil {
		t.Fatalf("Register glob: %v", err)
	}
	if err := reg.Register(tools.BuiltinSource, filetools.NewFileCountTool(home, project, project, cap)); err != nil {
		t.Fatalf("Register file_count: %v", err)
	}

	if _, derr := dispatch.DispatchTool(context.Background(), filetools.GrepToolName,
		map[string]any{"pattern": "external-canary", "path": ext}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(grep) err = %v, want nil (folder-approved external read)", derr)
	}
	if prompts != 1 {
		t.Fatalf("prompts after grep = %d, want 1", prompts)
	}
	if lastCapability != permissions.CapabilityRead {
		t.Fatalf("prompt CapabilityStoredSubject = %q, want %q (dispatch must carry the read* fold to the prompt)", lastCapability, permissions.CapabilityRead)
	}

	folderSettings := config.LocalSettingsPath(project)
	entry := findGrant(t, readPersistedPermissions(t, folderSettings, project), permissions.CapabilityRead)
	if entry.Kind != "tool" || entry.GrantKind != "folder" || entry.PathScope != ext {
		t.Fatalf("persisted entry = %+v, want kind tool / grant_kind folder / path_scope %q (the out-of-project read folder)", entry, ext)
	}

	// Reset the turn cache so the sibling reads must rely on the persistent capability grant.
	auth.resetTurnCache()

	if _, derr := dispatch.DispatchTool(context.Background(), filetools.ListToolName,
		map[string]any{"path": ext}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(list) err = %v, want nil (folded by read*)", derr)
	}
	if _, derr := dispatch.DispatchTool(context.Background(), filetools.GlobToolName,
		map[string]any{"pattern": "*.txt", "path": ext}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(glob) err = %v, want nil (folded by read*)", derr)
	}
	if _, derr := dispatch.DispatchTool(context.Background(), filetools.FileCountToolName,
		map[string]any{"path": ext}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(file_count) err = %v, want nil (folded by read*)", derr)
	}
	if prompts != 1 {
		t.Fatalf("prompts after list+glob+file_count = %d, want 1 (read* folds the read/search family incl. file_count; no re-prompt)", prompts)
	}
}

// The terminal is fed a single "4": the sibling reads that follow have no answer left on stdin, so
// they can only succeed by matching the persisted read* capability.
func TestHeadlessAuthorizer_ReadCapabilityGrantFoldsReadFamily(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	ext, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(ext): %v", err)
	}
	if err := os.WriteFile(filepath.Join(ext, "canary.txt"), []byte("external-canary\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := mkStore(t)
	var prompted bytes.Buffer
	terminal := newTerminalPrompter(strings.NewReader("4\n"), &prompted)
	auth := newHeadlessAuthorizer(emptyCache(t, project), func() *sessions.Store { return store },
		mode.NewActiveState(mode.Build, mode.SourceDefault), terminal, stderrNoticeRenderer{w: &bytes.Buffer{}})

	const cap = 65536
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewReadTool(home, project, project, cap)); err != nil {
		t.Fatalf("Register read: %v", err)
	}
	if err := reg.Register(tools.BuiltinSource, filetools.NewGrepTool(home, project, project, cap)); err != nil {
		t.Fatalf("Register grep: %v", err)
	}
	if err := reg.Register(tools.BuiltinSource, filetools.NewListTool(home, project, project, cap)); err != nil {
		t.Fatalf("Register list: %v", err)
	}
	if err := reg.Register(tools.BuiltinSource, filetools.NewFileCountTool(home, project, project, cap)); err != nil {
		t.Fatalf("Register file_count: %v", err)
	}

	if _, derr := dispatch.DispatchTool(context.Background(), filetools.ReadToolName,
		map[string]any{"path": filepath.Join(ext, "canary.txt")}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(read) err = %v, want nil (the terminal answered 4)", derr)
	}
	if n := strings.Count(prompted.String(), "approval required"); n != 1 {
		t.Fatalf("terminal rendered %d prompts for the external read, want 1:\n%s", n, prompted.String())
	}
	if sentence := tui.CapabilityCoverageSentence(permissions.CapabilityRead); !strings.Contains(prompted.String(), sentence) {
		t.Fatalf("the headless prompt did not disclose what the grant covers (%q):\n%s", sentence, prompted.String())
	}

	folderSettings := config.LocalSettingsPath(project)
	entry := findGrant(t, readPersistedPermissions(t, folderSettings, project), permissions.CapabilityRead)
	if entry.Kind != "tool" || entry.GrantKind != "folder" || entry.PathScope != ext {
		t.Fatalf("persisted entry = %+v, want kind tool / grant_kind folder / path_scope %q (the out-of-project read folder)", entry, ext)
	}

	auth.grants.ResetTurnCache()

	if _, derr := dispatch.DispatchTool(context.Background(), filetools.GrepToolName,
		map[string]any{"pattern": "external-canary", "path": ext}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(grep) err = %v, want nil (folded by read*)", derr)
	}
	if _, derr := dispatch.DispatchTool(context.Background(), filetools.ListToolName,
		map[string]any{"path": ext}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(list) err = %v, want nil (folded by read*)", derr)
	}
	if _, derr := dispatch.DispatchTool(context.Background(), filetools.FileCountToolName,
		map[string]any{"path": ext}, home, project, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(file_count) err = %v, want nil (folded by read*)", derr)
	}
	if n := strings.Count(prompted.String(), "approval required"); n != 1 {
		t.Fatalf("terminal rendered %d prompts, want 1 (read* folds grep+list+file_count; no re-prompt):\n%s", n, prompted.String())
	}
}
