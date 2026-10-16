package bootstrap

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/locks"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/turn"
)

func mustProtectedStatePolicy(t *testing.T, home, projectRoot string, layers []securitystate.LayerSnapshot) securitystate.Policy {
	t.Helper()
	policy, err := protectedStatePolicy(home, projectRoot, layers)
	if err != nil {
		t.Fatalf("protectedStatePolicy: %v", err)
	}
	return policy
}

func TestBlockedPathsFromLayers(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	globalPath := SettingsPath(home)
	projectPath := projectSettingsPath(t.TempDir())
	layers := func(projectIgnored bool) []securitystate.LayerSnapshot {
		return []securitystate.LayerSnapshot{
			{Kind: securitystate.LayerGlobal, Path: globalPath, Present: true, Raw: map[string]any{"blocked_paths": []any{"~/.ssh"}}},
			{Kind: securitystate.LayerProject, Path: projectPath, Present: true, Ignored: projectIgnored, Raw: map[string]any{"blocked_paths": []any{outside}}},
		}
	}

	t.Run("both layers with sources", func(t *testing.T) {
		blocked, err := blockedPathsFromLayers(home, "", layers(false))
		if err != nil {
			t.Fatalf("blockedPathsFromLayers: %v", err)
		}
		for target, source := range map[string]string{
			filepath.Join(home, ".ssh", "id_rsa"): globalPath,
			filepath.Join(outside, "file"):        projectPath,
		} {
			if entry, ok := blocked.Blocking(target); !ok || entry.Source != source {
				t.Fatalf("Blocking(%q) = %+v, %v; want an entry from %q", target, entry, ok, source)
			}
		}
	})

	t.Run("ignored project layer", func(t *testing.T) {
		blocked, err := blockedPathsFromLayers(home, "", layers(true))
		if err != nil {
			t.Fatalf("blockedPathsFromLayers: %v", err)
		}
		if entry, ok := blocked.Blocking(filepath.Join(outside, "file")); ok {
			t.Fatalf("Blocking = %+v, want the ignored project layer to contribute nothing", entry)
		}
	})

	t.Run("no layers keeps the floor", func(t *testing.T) {
		blocked, err := blockedPathsFromLayers(home, "", nil)
		if err != nil {
			t.Fatalf("blockedPathsFromLayers: %v", err)
		}
		if entry, ok := blocked.Blocking(filepath.Join(home, ".codemeld", "global", "settings.yaml")); !ok || !entry.Floor() {
			t.Fatalf("Blocking = %+v, %v; want the ~/.codemeld floor", entry, ok)
		}
	})

	t.Run("bad entry names the file and the entry", func(t *testing.T) {
		bad := []securitystate.LayerSnapshot{{Kind: securitystate.LayerGlobal, Path: globalPath, Present: true, Raw: map[string]any{"blocked_paths": []any{"relative/dir"}}}}
		_, err := blockedPathsFromLayers(home, "", bad)
		if err == nil || !strings.Contains(err.Error(), globalPath) || !strings.Contains(err.Error(), "relative/dir") {
			t.Fatalf("error = %v, want one naming %q and the entry", err, globalPath)
		}
	})
}

const blockedSecret = "TOKEN-7f3a9c"

func seedBlockedSecret(t *testing.T, root string) string {
	t.Helper()
	folder := filepath.Join(root, "vault")
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", folder, err)
	}
	file := filepath.Join(folder, "token.txt")
	if err := os.WriteFile(file, []byte(blockedSecret), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", file, err)
	}
	return file
}

func blockedGlobalLayers(t *testing.T, home, projectRoot string, folders ...string) []securitystate.LayerSnapshot {
	t.Helper()
	writeGlobalSettings(t, home, blockedYAML(folders...), 0o600)
	global, err := defaultLoadGlobalSettings(home)
	if err != nil {
		t.Fatalf("defaultLoadGlobalSettings: %v", err)
	}
	return settingsLayerSnapshots(home, projectRoot, global, true, ConfigComposition{})
}

func requestRecordingClient(toolName, args string) (*stubTurnClient, func() string) {
	inner := toolThenContentClient(nil, toolName, args, guardRecoveryAnswer)
	var mu sync.Mutex
	var sent strings.Builder
	client := &stubTurnClient{fn: func(ctx context.Context, req provider.Request) (provider.Response, error) {
		mu.Lock()
		sent.WriteString(requestText(req))
		mu.Unlock()
		return inner.fn(ctx, req)
	}}
	return client, func() string {
		mu.Lock()
		defer mu.Unlock()
		return sent.String()
	}
}

func toolArgs(t *testing.T, args map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal tool arguments: %v", err)
	}
	return string(raw)
}

func blockedPathDenial(tool, folder, source string) events.PermissionMatched {
	return events.PermissionMatched{SubjectKind: "tool", Subject: tool, PathScope: folder, Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: folder, BlockedEntrySource: source}
}

func TestDelegateBinding_ChildReadOfAGloballyBlockedFileCarriesItsInvocationID(t *testing.T) {
	cache, home, project, active, modeActive := delegateFixture(t)
	store := mkStore(t)
	file := seedBlockedSecret(t, project)
	reg := delegateRegistry(t, cache, home, project, active, modeActive)
	guard := mustProtectedStatePolicy(t, home, cache.ProjectRoot(), blockedGlobalLayers(t, home, project, filepath.Dir(file)))
	deps := delegateTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, guard)

	child := ids.NewV7()
	calls := []turn.AssembledToolCall{structuredCall("c1", filetools.ReadToolName, map[string]any{"path": file})}
	unit := deps.NewDispatcher(permissions.ModeContext{
		Mode:              string(mode.Build),
		ChildAgent:        true,
		ChildInvocationID: child,
	}).Plan(calls, 1).Units[0]
	if unit.PreRun != nil {
		if err := unit.PreRun(context.Background()); err != nil {
			t.Fatalf("PreRun error = %v", err)
		}
	}
	res, err := unit.Run(context.Background())
	if err != nil || !res.Denied || strings.Contains(res.Content, blockedSecret) {
		t.Fatalf("child read = %+v, %v; want a denial that carries none of the file", res, err)
	}

	want := blockedPathDenial(filetools.ReadToolName, filepath.Dir(file), SettingsPath(home))
	want.ChildInvocationID = child
	if matched := decodePermissionMatched(t, reloadStore(t, store)); len(matched) != 1 || matched[0] != want {
		t.Fatalf("permission_matched = %#v, want exactly one %#v", matched, want)
	}
}

func blockedYAML(paths ...string) string {
	if len(paths) == 0 {
		return "blocked_paths: []\n"
	}
	return "blocked_paths:\n  - " + strings.Join(paths, "\n  - ") + "\n"
}

func bumpSettings(path, content string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return err
	}
	later := info.ModTime().Add(time.Second)
	return os.Chtimes(path, later, later)
}

func rewriteSettings(t *testing.T, path, content string) {
	t.Helper()
	if err := bumpSettings(path, content); err != nil {
		t.Fatalf("rewrite %s: %v", path, err)
	}
}

type rereadFixture struct {
	home, project, outside, global, projectFile, localFile string
}

func newRereadFixture(t *testing.T) rereadFixture {
	t.Helper()
	f := rereadFixture{home: declaredScopeDir(t), project: declaredScopeDir(t), outside: declaredScopeDir(t)}
	f.global = SettingsPath(f.home)
	f.projectFile = projectSettingsPath(f.project)
	f.localFile = config.LocalSettingsPath(f.project)
	return f
}

func (f rereadFixture) paths(names []string) []string {
	out := make([]string, len(names))
	for i, name := range names {
		out[i] = filepath.Join(f.outside, name)
	}
	return out
}

func (f rereadFixture) fromGlobal(names ...string) []permissions.BlockedEntry {
	return f.entries(f.global, names)
}

func (f rereadFixture) fromProject(names ...string) []permissions.BlockedEntry {
	return f.entries(f.projectFile, names)
}

func (f rereadFixture) entries(source string, names []string) []permissions.BlockedEntry {
	var out []permissions.BlockedEntry
	for _, path := range f.paths(names) {
		out = append(out, permissions.BlockedEntry{Path: path, Source: source})
	}
	return out
}

func (f rereadFixture) writeGlobal(t *testing.T, names ...string) {
	t.Helper()
	writeGlobalSettings(t, f.home, blockedYAML(f.paths(names)...), 0o600)
}

func (f rereadFixture) writeProject(t *testing.T, names ...string) {
	t.Helper()
	writeProjectSettings(t, f.project, blockedYAML(f.paths(names)...))
}

func (f rereadFixture) fromLocal(names ...string) []permissions.BlockedEntry {
	return f.entries(f.localFile, names)
}

func (f rereadFixture) writeLocal(t *testing.T, names ...string) {
	t.Helper()
	writeLocalProjectSettings(t, f.project, blockedYAML(f.paths(names)...))
}

func (f rereadFixture) editLocal(t *testing.T, names ...string) {
	t.Helper()
	rewriteSettings(t, f.localFile, blockedYAML(f.paths(names)...))
}

func (f rereadFixture) editGlobal(t *testing.T, names ...string) {
	t.Helper()
	rewriteSettings(t, f.global, blockedYAML(f.paths(names)...))
}

func (f rereadFixture) editProject(t *testing.T, names ...string) {
	t.Helper()
	rewriteSettings(t, f.projectFile, blockedYAML(f.paths(names)...))
}

func (f rereadFixture) trust(t *testing.T) {
	t.Helper()
	approveRoot(t, f.home, f.project)
}

func (f rereadFixture) layers(t *testing.T, projectTrusted bool) []securitystate.LayerSnapshot {
	t.Helper()
	global, err := defaultLoadGlobalSettings(f.home)
	if err != nil {
		t.Fatalf("defaultLoadGlobalSettings: %v", err)
	}
	var composition ConfigComposition
	if data, err := os.ReadFile(f.projectFile); err == nil {
		raw, _, err := config.ValidateProjectSettingsBytes(data, f.projectFile)
		if err != nil {
			t.Fatalf("ValidateProjectSettingsBytes: %v", err)
		}
		composition.ProjectLayer, composition.ProjectPresent = raw, true
	}
	if data, err := os.ReadFile(f.localFile); err == nil {
		raw, _, err := config.ValidateLocalSettingsBytes(data, f.localFile)
		if err != nil {
			t.Fatalf("ValidateLocalSettingsBytes: %v", err)
		}
		composition.LocalLayer, composition.LocalPresent = raw, true
	}
	return settingsLayerSnapshots(f.home, f.project, global, projectTrusted, composition)
}

func (f rereadFixture) blocked(t *testing.T, projectTrusted bool) *permissions.BlockedPaths {
	t.Helper()
	return mustProtectedStatePolicy(t, f.home, f.project, f.layers(t, projectTrusted)).Blocked
}

func requireBlockedEntries(t *testing.T, blocked *permissions.BlockedPaths, want ...[]permissions.BlockedEntry) {
	t.Helper()
	wanted := slices.Concat(want...)
	got := blocked.Entries()
	if len(got) == 0 || !got[len(got)-1].Floor() || !slices.Equal(got[:len(got)-1], wanted) {
		t.Fatalf("Entries = %+v, want %+v then the floor", got, wanted)
	}
}

func TestBlockedPathsReread_GlobalEditBeforeTheFirstCheck(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t, "a")
	layers := f.layers(t, true)
	f.editGlobal(t, "a", "b")

	requireBlockedEntries(t, mustProtectedStatePolicy(t, f.home, f.project, layers).Blocked, f.fromGlobal("a", "b"))
}

func TestBlockedPathsReread_AdditionsAndRemovals(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t, "g1")
	f.writeProject(t, "p1")
	f.trust(t)
	blocked := f.blocked(t, true)
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromProject("p1"))

	f.editProject(t, "p1", "p2")
	f.editGlobal(t, "g1", "g2")
	requireBlockedEntries(t, blocked, f.fromGlobal("g1", "g2"), f.fromProject("p1", "p2"))

	f.editGlobal(t, "g2")
	f.editProject(t, "p2")
	requireBlockedEntries(t, blocked, f.fromGlobal("g2"), f.fromProject("p2"))
	if _, ok := blocked.Blocking(filepath.Join(f.outside, "g1", "k")); ok {
		t.Fatal("a removed global item is still refused")
	}
	if entry, ok := blocked.Blocking(filepath.Join(f.outside, "p2", "k")); !ok || entry != f.fromProject("p2")[0] {
		t.Fatalf("Blocking(p2/k) = %+v, %v; want the project item", entry, ok)
	}
}

func TestBlockedPathsReread_SameSizeRewrites(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t, "a")
	blocked := f.blocked(t, true)
	requireBlockedEntries(t, blocked, f.fromGlobal("a"))

	f.editGlobal(t, "b")
	requireBlockedEntries(t, blocked, f.fromGlobal("b"))

	info, err := os.Lstat(f.global)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	replacement := f.global + ".new"
	if err := os.WriteFile(replacement, []byte(blockedYAML(f.paths([]string{"c"})...)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chtimes(replacement, info.ModTime(), info.ModTime()); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	if err := os.Rename(replacement, f.global); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if after, err := os.Lstat(f.global); err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		t.Fatalf("replacement stat = %v, %v; want the original size and modification time", after, err)
	}
	requireBlockedEntries(t, blocked, f.fromGlobal("c"))
}

func TestBlockedPathsReread_BrokenGlobalFileKeepsTheLastValidEntries(t *testing.T) {
	cases := map[string]func(t *testing.T, f rereadFixture){
		"invalid YAML": func(t *testing.T, f rereadFixture) { rewriteSettings(t, f.global, "blocked_paths: [\n") },
		"invalid item": func(t *testing.T, f rereadFixture) { rewriteSettings(t, f.global, blockedYAML("relative/dir")) },
		"deleted": func(t *testing.T, f rereadFixture) {
			if err := os.Remove(f.global); err != nil {
				t.Fatalf("Remove: %v", err)
			}
		},
	}
	for name, breakFile := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRereadFixture(t)
			f.writeGlobal(t, "a")
			blocked := f.blocked(t, true)
			requireBlockedEntries(t, blocked, f.fromGlobal("a"))

			breakFile(t, f)
			requireBlockedEntries(t, blocked, f.fromGlobal("a"))

			f.writeGlobal(t, "b", "c")
			requireBlockedEntries(t, blocked, f.fromGlobal("b", "c"))
		})
	}
}

func TestBlockedPathsReread_HeldProjectLockDefersTheChange(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t)
	f.writeProject(t, "p1")
	f.trust(t)
	blocked := f.blocked(t, true)
	requireBlockedEntries(t, blocked, f.fromProject("p1"))

	release, reason, err := locks.TryAcquire(f.projectFile + ".lock")
	if release == nil {
		t.Fatalf("TryAcquire = %q, %v; want the lock", reason, err)
	}
	f.editProject(t, "p1", "p2")
	requireBlockedEntries(t, blocked, f.fromProject("p1"))

	release()
	requireBlockedEntries(t, blocked, f.fromProject("p1", "p2"))
}

func TestBlockedPathsReread_IgnoredProjectLayerContributesNothing(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t)
	f.writeProject(t, "p1")
	blocked := f.blocked(t, false)
	requireBlockedEntries(t, blocked)

	f.editProject(t, "p2")
	f.trust(t)
	requireBlockedEntries(t, blocked)
}

type settingsRound struct {
	edit func() error
	call declaredToolCall
}

func settingsEdit(path, content string) func() error {
	return func() error { return bumpSettings(path, content) }
}

func settingsEditingClient(t *testing.T, rounds ...settingsRound) *stubTurnClient {
	calls := make([]declaredToolCall, len(rounds))
	for i, r := range rounds {
		calls[i] = r.call
	}
	inner := declaredScopeClient(calls...)
	var round int32
	return &stubTurnClient{fn: func(ctx context.Context, req provider.Request) (provider.Response, error) {
		if i := int(atomic.AddInt32(&round, 1)) - 1; i < len(rounds) && rounds[i].edit != nil {
			if err := rounds[i].edit(); err != nil {
				t.Errorf("edit settings before round %d: %v", i+1, err)
			}
		}
		return inner.fn(ctx, req)
	}}
}

func readCall(t *testing.T, path string) declaredToolCall {
	return declaredToolCall{name: filetools.ReadToolName, args: toolArgs(t, map[string]any{"path": path})}
}

func midRunBlockedClient(t *testing.T, settings, file string) *stubTurnClient {
	read := readCall(t, file)
	return settingsEditingClient(t,
		settingsRound{call: read},
		settingsRound{edit: settingsEdit(settings, blockedYAML(filepath.Dir(file))), call: read},
		settingsRound{edit: settingsEdit(settings, blockedYAML()), call: read},
	)
}

func problemNotice(file, reason string) string {
	return "blocked_paths: " + file + " " + reason + "; reads outside the project will ask until it is fixed"
}

func fixedNotice(file string) string {
	return "blocked_paths: " + file + " can be read again"
}

func recordNotices(blocked *permissions.BlockedPaths) func() []string {
	var mu sync.Mutex
	var lines []string
	blocked.SetNotice(func(line string) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, line)
	})
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		taken := lines
		lines = nil
		return taken
	}
}

func requireDegraded(t *testing.T, blocked *permissions.BlockedPaths, notices func() []string, degraded bool, want ...string) {
	t.Helper()
	if blocked.Degraded() != degraded {
		t.Fatalf("Degraded = %v, want %v", blocked.Degraded(), degraded)
	}
	if got := notices(); !slices.Equal(got, want) {
		t.Fatalf("notices = %q, want %q", got, want)
	}
}

func TestBlockedPathsReread_ProblemsNameTheFileAndReason(t *testing.T) {
	cases := []struct {
		name      string
		reason    string
		breakFile func(t *testing.T, f rereadFixture)
	}{
		{"invalid YAML", "is not valid YAML", func(t *testing.T, f rereadFixture) { rewriteSettings(t, f.global, "blocked_paths: [\n") }},
		{"relative item", "doesn't match the settings schema", func(t *testing.T, f rereadFixture) { rewriteSettings(t, f.global, blockedYAML("relative/dir")) }},
		{"item the platform rejects", "has an invalid blocked_paths item", func(t *testing.T, f rereadFixture) {
			item := "C:/x"
			if runtime.GOOS == "windows" {
				item = "/x"
			}
			rewriteSettings(t, f.global, blockedYAML(item))
		}},
		{"unreadable file", "can't be read", func(t *testing.T, f rereadFixture) {
			if os.Geteuid() == 0 {
				t.Skip("root reads a mode 000 file")
			}
			info, err := os.Lstat(f.global)
			if err != nil {
				t.Fatalf("Lstat: %v", err)
			}
			if err := os.Chmod(f.global, 0o000); err != nil {
				t.Fatalf("Chmod: %v", err)
			}
			t.Cleanup(func() { _ = os.Chmod(f.global, 0o600) })
			later := info.ModTime().Add(time.Second)
			if err := os.Chtimes(f.global, later, later); err != nil {
				t.Fatalf("Chtimes: %v", err)
			}
		}},
		{"deleted global file", "is missing", func(t *testing.T, f rereadFixture) {
			if err := os.Remove(f.global); err != nil {
				t.Fatalf("Remove: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRereadFixture(t)
			f.writeGlobal(t, "a")
			blocked := f.blocked(t, true)
			notices := recordNotices(blocked)
			requireBlockedEntries(t, blocked, f.fromGlobal("a"))
			requireDegraded(t, blocked, notices, false)

			tc.breakFile(t, f)
			requireBlockedEntries(t, blocked, f.fromGlobal("a"))
			requireDegraded(t, blocked, notices, true, problemNotice(f.global, tc.reason))
			if _, ok := blocked.Blocking(filepath.Join(f.outside, "a", "k")); !ok {
				t.Fatal("the last valid entry is no longer refused")
			}
		})
	}
}

func TestBlockedPathsReread_HeldProjectLockIsNotAProblemUntilItIsReleased(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t)
	f.writeProject(t, "p1")
	blocked := f.blocked(t, true)
	notices := recordNotices(blocked)
	requireBlockedEntries(t, blocked, f.fromProject("p1"))

	release, reason, err := locks.TryAcquire(f.projectFile + ".lock")
	if release == nil {
		t.Fatalf("TryAcquire = %q, %v; want the lock", reason, err)
	}
	rewriteSettings(t, f.projectFile, "blocked_paths: [\n")
	requireBlockedEntries(t, blocked, f.fromProject("p1"))
	requireDegraded(t, blocked, notices, false)

	release()
	requireBlockedEntries(t, blocked, f.fromProject("p1"))
	requireDegraded(t, blocked, notices, true, problemNotice(f.projectFile, "is not valid YAML"))
}

func TestBlockedPathsReread_EachFileLeavesProblemsOnItsOwn(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t, "g1")
	f.writeProject(t, "p1")
	f.trust(t)
	blocked := f.blocked(t, true)
	notices := recordNotices(blocked)
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromProject("p1"))

	rewriteSettings(t, f.global, "blocked_paths: [\n")
	rewriteSettings(t, f.projectFile, "blocked_paths: [\n")
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromProject("p1"))
	files := slices.Sorted(slices.Values([]string{f.global, f.projectFile}))
	requireDegraded(t, blocked, notices, true, problemNotice(files[0], "is not valid YAML"), problemNotice(files[1], "is not valid YAML"))

	f.editProject(t, "p2")
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromProject("p2"))
	requireDegraded(t, blocked, notices, true, fixedNotice(f.projectFile))

	f.editGlobal(t, "g2")
	requireBlockedEntries(t, blocked, f.fromGlobal("g2"), f.fromProject("p2"))
	requireDegraded(t, blocked, notices, false, fixedNotice(f.global))
}

func TestBlockedPathsReread_DegradedCheckRereadsWithoutAStatChange(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t)
	blocked := f.blocked(t, true)
	requireBlockedEntries(t, blocked)

	const broken, valid = "blocked_paths: [\n\n", "blocked_paths: []\n"
	rewriteSettings(t, f.global, broken)
	requireBlockedEntries(t, blocked)
	if !blocked.Degraded() {
		t.Fatal("Degraded = false after breaking the global file")
	}

	info, err := os.Lstat(f.global)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if err := os.WriteFile(f.global, []byte(valid), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chtimes(f.global, info.ModTime(), info.ModTime()); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	if after, err := os.Lstat(f.global); err != nil || !sameSettingsStat(info, nil, after, nil) {
		t.Fatalf("fixed file stat = %v, %v; want it unchanged", after, err)
	}
	requireBlockedEntries(t, blocked)
	if blocked.Degraded() {
		t.Fatal("Degraded = true after the file was fixed without a stat change")
	}
}

func requireMidRunBlockedReads(t *testing.T, client *stubTurnClient, store *sessions.Store, file, source string) {
	t.Helper()
	if client.callCount() != 4 {
		t.Fatalf("provider calls = %d, want 4 (three reads and a final answer)", client.callCount())
	}
	results := messagesByRole(store, "tool")
	if len(results) != 3 {
		t.Fatalf("tool messages = %d, want 3", len(results))
	}
	for i, allowed := range []bool{true, false, true} {
		if got := results[i].Content.Text(); strings.Contains(got, blockedSecret) != allowed {
			t.Fatalf("read %d = %q, want allowed=%v", i+1, got, allowed)
		}
	}
	want := blockedPathDenial(filetools.ReadToolName, filepath.Dir(file), source)
	var refused []events.PermissionMatched
	for _, m := range decodePermissionMatched(t, store) {
		if m.OutcomeSource == "blocked_path" {
			refused = append(refused, m)
		}
	}
	if len(refused) != 1 || refused[0] != want {
		t.Fatalf("blocked_path records = %#v, want exactly one %#v", refused, want)
	}
}

func TestBlockedPaths_ProjectScopeFilesContributeOnlyToAnApprovedProject(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t, "g1")
	f.writeProject(t, "p1")
	f.writeLocal(t, "l1")
	f.trust(t)

	t.Run("approved", func(t *testing.T) {
		requireBlockedEntries(t, f.blocked(t, true), f.fromGlobal("g1"), f.fromProject("p1"), f.fromLocal("l1"))

		entries, err := blockedEntriesFromLayers(f.home, f.layers(t, true))
		want := slices.Concat(f.fromGlobal("g1"), f.fromProject("p1"), f.fromLocal("l1"))
		if err != nil || !slices.Equal(entries, want) {
			t.Fatalf("blockedEntriesFromLayers = %+v, %v; want %+v", entries, err, want)
		}
	})

	t.Run("unapproved", func(t *testing.T) {
		requireBlockedEntries(t, f.blocked(t, false), f.fromGlobal("g1"))

		entries, err := blockedEntriesFromLayers(f.home, f.layers(t, false))
		if err != nil || !slices.Equal(entries, f.fromGlobal("g1")) {
			t.Fatalf("blockedEntriesFromLayers = %+v, %v; want the global layer's entry alone", entries, err)
		}

		ignored := f.layers(t, true)
		for i := range ignored {
			if ignored[i].Kind == securitystate.LayerGlobal {
				continue
			}
			if !ignored[i].Present {
				t.Fatalf("layer %+v, want a content-bearing project-scope snapshot to mark ignored", ignored[i])
			}
			ignored[i].Ignored = true
		}
		entries, err = blockedEntriesFromLayers(f.home, ignored)
		if err != nil || !slices.Equal(entries, f.fromGlobal("g1")) {
			t.Fatalf("blockedEntriesFromLayers over ignored content-bearing layers = %+v, %v; want the global layer's entry alone", entries, err)
		}
	})
}

func TestBlockedPathsReread_UnapprovedProjectEditsChangeNoEntry(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t, "g1")
	f.writeProject(t, "p1")
	f.writeLocal(t, "l1")
	blocked := f.blocked(t, false)
	notices := recordNotices(blocked)
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"))

	f.editProject(t, "p1", "p2")
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"))

	f.editLocal(t, "l1", "l2")
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"))

	rewriteSettings(t, f.projectFile, "blocked_paths: [\n")
	rewriteSettings(t, f.localFile, "blocked_paths: [\n")
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"))
	requireDegraded(t, blocked, notices, false)

	f.editGlobal(t, "g1", "g2")
	requireBlockedEntries(t, blocked, f.fromGlobal("g1", "g2"))
}

func TestBlockedPaths_DriftBaselineCoversProjectScopeFilesOnlyWhenApproved(t *testing.T) {
	cases := map[string]struct {
		approved bool
		want     []securitystate.LayerKind
	}{
		"unapproved": {},
		"approved":   {approved: true, want: []securitystate.LayerKind{securitystate.LayerProject, securitystate.LayerLocal}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRereadFixture(t)
			f.writeGlobal(t, "g1")
			f.writeProject(t, "p1")
			f.writeLocal(t, "l1")
			monitor := securitystate.NewMonitor(f.layers(t, tc.approved))

			grant := "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: " + f.outside + "\n    grant_kind: folder\n"
			rewriteSettings(t, f.projectFile, blockedYAML(f.paths([]string{"p1"})...)+grant)
			rewriteSettings(t, f.localFile, blockedYAML(f.paths([]string{"l1"})...)+grant)

			got := monitor.Checkpoint()
			if len(got) != len(tc.want) {
				t.Fatalf("Checkpoint = %+v, want %d result(s) for %v", got, len(tc.want), tc.want)
			}
			paths := map[securitystate.LayerKind]string{securitystate.LayerProject: f.projectFile, securitystate.LayerLocal: f.localFile}
			for i, kind := range tc.want {
				if got[i].Kind != kind || got[i].Path != paths[kind] || !slices.Contains(got[i].Sections, securitystate.SectionPermissions) {
					t.Fatalf("Checkpoint[%d] = %+v, want the %s layer at %q reporting %q", i, got[i], kind, paths[kind], securitystate.SectionPermissions)
				}
			}
		})
	}
}
func TestBlockedPathsReread_LocalEditIsValidatedAsTheLocalLayer(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t, "g1")
	f.writeProject(t, "p1")
	f.writeLocal(t, "l1")
	f.trust(t)
	blocked := f.blocked(t, true)
	notices := recordNotices(blocked)
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromProject("p1"), f.fromLocal("l1"))

	f.editLocal(t, "l1", "l2")
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromProject("p1"), f.fromLocal("l1", "l2"))
	requireDegraded(t, blocked, notices, false)

	f.editLocal(t, "l2")
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromProject("p1"), f.fromLocal("l2"))
	if entry, ok := blocked.Blocking(filepath.Join(f.paths([]string{"l1"})[0], "k")); ok {
		t.Fatalf("Blocking = %+v, want the removed local entry to refuse nothing", entry)
	}
	if _, ok := blocked.Blocking(filepath.Join(f.paths([]string{"l2"})[0], "k")); !ok {
		t.Fatal("Blocking = false, want the retained local entry still refused")
	}
	requireDegraded(t, blocked, notices, false)

	rewriteSettings(t, f.localFile, blockedYAML(f.paths([]string{"l3"})...)+"agent:\n  max_concurrency: 2\n")
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromProject("p1"))
	requireDegraded(t, blocked, notices, true, problemNotice(f.localFile, "doesn't match the settings schema"))
}

func TestBlockedPathsReread_HeldLocalLockChangesNothingUntilItIsReleased(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t, "g1")
	f.writeProject(t, "p1")
	f.writeLocal(t, "l1")
	blocked := f.blocked(t, true)
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromProject("p1"), f.fromLocal("l1"))

	release, reason, err := locks.TryAcquire(f.localFile + ".lock")
	if release == nil {
		t.Fatalf("TryAcquire = %q, %v; want the lock", reason, err)
	}
	f.editLocal(t, "l1", "l2")
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromProject("p1"), f.fromLocal("l1"))

	release()
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromProject("p1"), f.fromLocal("l1", "l2"))
}

func TestBlockedPathsReread_BrokenLocalFileKeepsTheLastValidEntries(t *testing.T) {
	cases := map[string]func(t *testing.T, f rereadFixture){
		"invalid YAML": func(t *testing.T, f rereadFixture) { rewriteSettings(t, f.localFile, "blocked_paths: [\n") },
		"invalid item": func(t *testing.T, f rereadFixture) {
			item := "C:/x"
			if runtime.GOOS == "windows" {
				item = "/x"
			}
			rewriteSettings(t, f.localFile, blockedYAML(item))
		},
	}
	for name, breakFile := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRereadFixture(t)
			f.writeGlobal(t, "g1")
			f.writeLocal(t, "l1")
			f.trust(t)
			blocked := f.blocked(t, true)
			requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromLocal("l1"))

			breakFile(t, f)
			requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromLocal("l1"))
			if !blocked.Degraded() {
				t.Fatal("Degraded = false after breaking the local file")
			}

			f.editLocal(t, "l2", "l3")
			requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromLocal("l2", "l3"))
		})
	}
}

func TestBlockedPathsReread_UnreadableLocalFileKeepsTheLastValidEntriesAndReportsAProblem(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 000 file")
	}
	f := newRereadFixture(t)
	f.writeGlobal(t, "g1")
	f.writeLocal(t, "l1")
	blocked := f.blocked(t, true)
	notices := recordNotices(blocked)
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromLocal("l1"))

	info, err := os.Lstat(f.localFile)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if err := os.Chmod(f.localFile, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.localFile, 0o600) })
	later := info.ModTime().Add(time.Second)
	if err := os.Chtimes(f.localFile, later, later); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromLocal("l1"))
	requireDegraded(t, blocked, notices, true, problemNotice(f.localFile, "can't be read"))
	if _, ok := blocked.Blocking(filepath.Join(f.paths([]string{"l1"})[0], "k")); !ok {
		t.Fatal("Entries from the last valid list stay refused.")
	}
}

func TestBlockedPathsFromLayers_UnknownLayerKindIsNeitherReadNorWatched(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t, "g1")
	f.writeLocal(t, "l1")
	f.trust(t)

	global := f.layers(t, true)[0]
	unknown := securitystate.LayerSnapshot{
		Kind:    securitystate.LayerKind("future"),
		Path:    f.localFile,
		Present: true,
		Raw:     map[string]any{"blocked_paths": []any{f.paths([]string{"l1"})[0]}},
	}
	layers := []securitystate.LayerSnapshot{global, unknown}

	blocked, err := blockedPathsFromLayers(f.home, f.project, layers)
	if err != nil {
		t.Fatalf("blockedPathsFromLayers: %v", err)
	}
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"))

	f.editLocal(t, "l1", "l2")
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"))

	entries, err := blockedEntriesFromLayers(f.home, layers)
	if err != nil || !slices.Equal(entries, f.fromGlobal("g1")) {
		t.Fatalf("blockedEntriesFromLayers = %+v, %v; want only the global layer's entry", entries, err)
	}
}

func TestBlockedPathsReread_DeletedLocalFileDropsOnlyItsEntries(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t, "g1")
	f.writeProject(t, "p1")
	f.writeLocal(t, "l1")
	f.trust(t)
	blocked := f.blocked(t, true)
	notices := recordNotices(blocked)
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromProject("p1"), f.fromLocal("l1"))

	if err := os.Remove(f.localFile); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromProject("p1"))
	requireBlockedEntries(t, blocked, f.fromGlobal("g1"), f.fromProject("p1"))
	requireDegraded(t, blocked, notices, false)
}
