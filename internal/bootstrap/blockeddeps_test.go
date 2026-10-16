package bootstrap

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/locks"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/trust"
	"codemeld.dev/codemeld/internal/tui"
)

func seedBlockedSettings(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func liveGlobalBlocked(t *testing.T, home string) *permissions.BlockedPaths {
	t.Helper()
	global := SettingsPath(home)
	raw, _, err := config.ValidateGlobalSettingsBytes([]byte(mustReadFile(t, global)), global)
	if err != nil {
		t.Fatalf("ValidateGlobalSettingsBytes: %v", err)
	}
	blocked, err := blockedPathsFromLayers(home, "", []securitystate.LayerSnapshot{{Kind: securitystate.LayerGlobal, Path: global, Present: true, Raw: raw}})
	if err != nil {
		t.Fatalf("blockedPathsFromLayers: %v", err)
	}
	return blocked
}

func controlCharHome(t *testing.T) string {
	t.Helper()
	home := filepath.Join(declaredScopeDir(t), "ho\nme\tdir")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	return home
}

func TestRemoveAndAddBlockedEntry_ChangeTheFileAndTheLiveList(t *testing.T) {
	home := declaredScopeDir(t)
	global := SettingsPath(home)
	original := "blocked_paths:\n  # Keys and passwords\n  - \"~/.ssh\"\n"
	seedBlockedSettings(t, global, original)
	blocked := liveGlobalBlocked(t, home)
	ssh := filepath.Join(home, ".ssh")
	key := filepath.Join(ssh, "id_rsa")
	if _, ok := blocked.Current().Blocking(key); !ok {
		t.Fatalf("Blocking(%q) before removal = false, want true", key)
	}

	if msg := removeBlockedEntry(blocked, home, tui.BlockedRow{Kind: tui.BlockedRowGlobal, Path: ssh, Source: global}); msg != "" {
		t.Fatalf("removeBlockedEntry = %q, want no message", msg)
	}
	if got, want := mustReadFile(t, global), "blocked_paths: []\n  # Keys and passwords\n"; got != want {
		t.Fatalf("file after removal = %q, want %q", got, want)
	}
	if entry, ok := blocked.Current().Blocking(key); ok {
		t.Fatalf("Blocking(%q) after removal = %+v, want not blocked", key, entry)
	}
	if !missingRow(blockedRows(blocked, home, global), "~/.ssh") {
		t.Fatalf("rows after removal do not offer ~/.ssh")
	}

	if msg := addRecommendedEntry(home, tui.BlockedRow{Kind: tui.BlockedRowMissing, Path: "~/.ssh", Group: "Keys and passwords"}); msg != "" {
		t.Fatalf("addRecommendedEntry = %q, want no message", msg)
	}
	if got := mustReadFile(t, global); got != original {
		t.Fatalf("file after add = %q, want %q", got, original)
	}
	if entry, ok := blocked.Current().Blocking(key); !ok || entry.Source != global {
		t.Fatalf("Blocking(%q) after add = %+v, %v; want an entry from %q", key, entry, ok, global)
	}
}

func TestRemoveBlockedEntry_StillBlockedMessages(t *testing.T) {
	t.Run("another spelling of the same path", func(t *testing.T) {
		home := declaredScopeDir(t)
		global := SettingsPath(home)
		ssh := filepath.Join(home, ".ssh")
		seedBlockedSettings(t, global, fmt.Sprintf("blocked_paths:\n  - \"~/.ssh\"\n  - %q\n", ssh))
		blocked := liveGlobalBlocked(t, home)

		msg := removeBlockedEntry(blocked, home, tui.BlockedRow{Kind: tui.BlockedRowGlobal, Path: ssh, Source: global})
		if want := fmt.Sprintf("%s is still blocked by the blocked_paths entry %s in %s", ssh, ssh, global); msg != want {
			t.Fatalf("message = %q, want %q", msg, want)
		}
		if got, want := mustReadFile(t, global), fmt.Sprintf("blocked_paths:\n  - %q\n", ssh); got != want {
			t.Fatalf("file = %q, want %q", got, want)
		}
	})

	t.Run("an entry inside codemeld's own folder", func(t *testing.T) {
		home := declaredScopeDir(t)
		global := SettingsPath(home)
		seedBlockedSettings(t, global, "blocked_paths:\n  - \"~/.codemeld/cache\"\n")
		blocked := liveGlobalBlocked(t, home)
		cache := filepath.Join(home, ".codemeld", "cache")

		msg := removeBlockedEntry(blocked, home, tui.BlockedRow{Kind: tui.BlockedRowGlobal, Path: cache, Source: global})
		if want := fmt.Sprintf("%s is still blocked: it is inside codemeld's own folder %s", cache, filepath.Join(home, ".codemeld")); msg != want {
			t.Fatalf("message = %q, want %q", msg, want)
		}
		if strings.Contains(msg, global) {
			t.Fatalf("message = %q, want no source file", msg)
		}
		if got, want := mustReadFile(t, global), "blocked_paths: []\n"; got != want {
			t.Fatalf("file = %q, want %q", got, want)
		}
	})
}

func TestBlockedEntryFunctions_WrongRowWritesNothing(t *testing.T) {
	home := controlCharHome(t)
	global := SettingsPath(home)
	project := projectSettingsPath(declaredScopeDir(t))
	body := "blocked_paths:\n  - \"~/.ssh\"\n"
	seedBlockedSettings(t, global, body)
	seedBlockedSettings(t, project, body)
	blocked := liveGlobalBlocked(t, home)
	ssh := filepath.Join(home, ".ssh")
	removeWant := "only entries in " + fserrors.CollapseControls(global) + " can be removed here"

	cases := []struct {
		name string
		call func() string
		want string
	}{
		{"project row to remove", func() string {
			return removeBlockedEntry(blocked, home, tui.BlockedRow{Kind: tui.BlockedRowProject, Path: ssh, Source: project})
		}, removeWant},
		{"global kind from another file to remove", func() string {
			return removeBlockedEntry(blocked, home, tui.BlockedRow{Kind: tui.BlockedRowGlobal, Path: ssh, Source: project})
		}, removeWant},
		{"global row to add", func() string {
			return addRecommendedEntry(home, tui.BlockedRow{Kind: tui.BlockedRowGlobal, Path: ssh, Source: global})
		}, "only recommended entries can be added here"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			globalInfo, projectInfo := mustStat(t, global), mustStat(t, project)
			if msg := tc.call(); msg != tc.want {
				t.Fatalf("message = %q, want %q", msg, tc.want)
			}
			for path, before := range map[string]os.FileInfo{global: globalInfo, project: projectInfo} {
				if got := mustReadFile(t, path); got != body {
					t.Fatalf("%s = %q, want unchanged %q", path, got, body)
				}
				if after := mustStat(t, path); !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
					t.Fatalf("%s was rewritten", path)
				}
			}
		})
	}
}

func TestBlockedEntryFunctions_WriteFailureNamesOnlyTheReason(t *testing.T) {
	home := controlCharHome(t)
	global := SettingsPath(home)
	project := projectSettingsPath(declaredScopeDir(t))
	body := "blocked_paths:\n  - \"~/.ssh\"\n"
	seedBlockedSettings(t, global, body)
	seedBlockedSettings(t, project, body)
	blocked := liveGlobalBlocked(t, home)
	sentinel := errors.New("forced blocked sync failure")
	t.Cleanup(fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel }))
	want := "couldn't update " + fserrors.CollapseControls(global) + ": " + string(config.ReasonWriteError)

	for name, call := range map[string]func() string{
		"remove": func() string {
			return removeBlockedEntry(blocked, home, tui.BlockedRow{Kind: tui.BlockedRowGlobal, Path: filepath.Join(home, ".ssh"), Source: global})
		},
		"add": func() string {
			return addRecommendedEntry(home, tui.BlockedRow{Kind: tui.BlockedRowMissing, Path: "~/.gnupg", Group: "Keys and passwords"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			msg := call()
			if msg != want {
				t.Fatalf("message = %q, want %q", msg, want)
			}
			if strings.ContainsAny(msg, "\n\r\t") || strings.Contains(msg, sentinel.Error()) || strings.Contains(msg, string(fserrors.IOError)) {
				t.Fatalf("message = %q, want only the reason token on one line", msg)
			}
			for _, path := range []string{global, project} {
				if got := mustReadFile(t, path); got != body {
					t.Fatalf("%s = %q, want unchanged %q", path, got, body)
				}
			}
		})
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	return info
}

func missingRow(rows []tui.BlockedRow, path string) bool {
	return slices.ContainsFunc(rows, func(r tui.BlockedRow) bool { return r.Kind == tui.BlockedRowMissing && r.Path == path })
}

func rowsOfKind(rows []tui.BlockedRow, kinds ...tui.BlockedRowKind) []tui.BlockedRow {
	return slices.DeleteFunc(slices.Clone(rows), func(r tui.BlockedRow) bool { return !slices.Contains(kinds, r.Kind) })
}

func TestBlockedRowsFrom(t *testing.T) {
	home := declaredScopeDir(t)
	global := SettingsPath(home)
	project := filepath.Join(declaredScopeDir(t), ".codemeld", "settings.yaml")
	floor := filepath.Join(home, ".codemeld")
	g := func(path string) permissions.BlockedEntry {
		return permissions.BlockedEntry{Path: path, Source: global}
	}
	p := func(path string) permissions.BlockedEntry {
		return permissions.BlockedEntry{Path: path, Source: project}
	}
	ssh := filepath.Join(home, ".ssh")

	cases := []struct {
		name     string
		entries  []permissions.BlockedEntry
		foldCase bool
		check    func(t *testing.T, rows []tui.BlockedRow)
	}{
		{
			name:    "global and project entries in list order",
			entries: []permissions.BlockedEntry{g("/opt/a"), p("/opt/b"), g("/opt/c")},
			check: func(t *testing.T, rows []tui.BlockedRow) {
				want := []tui.BlockedRow{
					{Kind: tui.BlockedRowGlobal, Path: "/opt/a", Source: global},
					{Kind: tui.BlockedRowProject, Path: "/opt/b", Source: project},
					{Kind: tui.BlockedRowGlobal, Path: "/opt/c", Source: global},
				}
				if got := rowsOfKind(rows, tui.BlockedRowGlobal, tui.BlockedRowProject); !slices.Equal(got, want) {
					t.Fatalf("entry rows = %+v, want %+v", got, want)
				}
			},
		},
		{
			name:    "tilde and absolute spellings count occurrences",
			entries: []permissions.BlockedEntry{g(mustExpandBlocked(t, home, "~/.ssh")), g(ssh)},
			check: func(t *testing.T, rows []tui.BlockedRow) {
				got := rowsOfKind(rows, tui.BlockedRowGlobal)
				if len(got) != 2 || got[0].Occurrence != 0 || got[1].Occurrence != 1 || got[0].Path != ssh || got[1].Path != ssh {
					t.Fatalf("global rows = %+v, want %s at occurrence 0 and 1", got, ssh)
				}
			},
		},
		{
			name:    "floor follows the entries",
			entries: []permissions.BlockedEntry{g("/opt/a"), p("/opt/b")},
			check: func(t *testing.T, rows []tui.BlockedRow) {
				if len(rows) < 3 || rows[2] != (tui.BlockedRow{Kind: tui.BlockedRowFloor, Path: floor}) {
					t.Fatalf("rows = %+v, want the floor %s right after both entries", rows, floor)
				}
			},
		},
		{
			name:    "an /etc entry puts its warning first",
			entries: []permissions.BlockedEntry{g("/opt/a"), g("/etc")},
			check: func(t *testing.T, rows []tui.BlockedRow) {
				if rows[0].Kind != tui.BlockedRowWarning || !strings.Contains(rows[0].Text, "/etc") {
					t.Fatalf("first row = %+v, want the /etc warning", rows[0])
				}
				if len(rowsOfKind(rows, tui.BlockedRowWarning)) != 1 || rows[1].Path != "/opt/a" {
					t.Fatalf("rows = %+v, want one warning then the entries", rows)
				}
			},
		},
		{
			name: "no entries lists every recommended path under its group",
			check: func(t *testing.T, rows []tui.BlockedRow) {
				want := []tui.BlockedRow{{Kind: tui.BlockedRowFloor, Path: floor}}
				for _, group := range recommendedBlockedPaths {
					want = append(want, tui.BlockedRow{Kind: tui.BlockedRowGroup, Text: group.heading})
					for _, path := range group.paths {
						want = append(want, tui.BlockedRow{Kind: tui.BlockedRowMissing, Path: path, Group: group.heading})
					}
				}
				if !slices.Equal(rows, want) {
					t.Fatalf("rows = %+v, want %+v", rows, want)
				}
			},
		},
		{
			name:    "a global ~/.ssh entry makes ~/.ssh present",
			entries: []permissions.BlockedEntry{g(ssh)},
			check: func(t *testing.T, rows []tui.BlockedRow) {
				if missingRow(rows, "~/.ssh") || !missingRow(rows, "~/.gnupg") {
					t.Fatalf("rows = %+v, want ~/.ssh present and ~/.gnupg missing", rows)
				}
			},
		},
		{
			name:    "a global home entry covers every recommended path",
			entries: []permissions.BlockedEntry{g(home)},
			check: func(t *testing.T, rows []tui.BlockedRow) {
				if got := rowsOfKind(rows, tui.BlockedRowGroup, tui.BlockedRowMissing); len(got) != 0 {
					t.Fatalf("group and missing rows = %+v, want none", got)
				}
			},
		},
		{
			name:    "~/.ssh only in the project file stays missing",
			entries: []permissions.BlockedEntry{p(ssh)},
			check: func(t *testing.T, rows []tui.BlockedRow) {
				if !missingRow(rows, "~/.ssh") {
					t.Fatalf("rows = %+v, want ~/.ssh missing", rows)
				}
			},
		},
		{
			name:     "with case folding ~/.SSH covers ~/.ssh",
			entries:  []permissions.BlockedEntry{g(filepath.Join(home, ".SSH"))},
			foldCase: true,
			check: func(t *testing.T, rows []tui.BlockedRow) {
				if missingRow(rows, "~/.ssh") {
					t.Fatalf("rows = %+v, want ~/.ssh present", rows)
				}
			},
		},
		{
			name:    "without case folding ~/.SSH leaves ~/.ssh missing",
			entries: []permissions.BlockedEntry{g(filepath.Join(home, ".SSH"))},
			check: func(t *testing.T, rows []tui.BlockedRow) {
				if !missingRow(rows, "~/.ssh") {
					t.Fatalf("rows = %+v, want ~/.ssh missing", rows)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries := permissions.NewBlockedPaths(home, tc.entries).Entries()
			tc.check(t, blockedRowsFrom(entries, home, global, "", "", tc.foldCase))
		})
	}
}

func mustExpandBlocked(t *testing.T, home, raw string) string {
	t.Helper()
	path, err := permissions.ExpandBlockedEntry(home, raw)
	if err != nil {
		t.Fatalf("ExpandBlockedEntry(%q): %v", raw, err)
	}
	return path
}

func TestBlockedRows_ReadsTheListNowInForce(t *testing.T) {
	home := declaredScopeDir(t)
	global := SettingsPath(home)
	now := []permissions.BlockedEntry{{Path: "/opt/a", Source: global}}
	blocked := permissions.NewLiveBlockedPaths(home, "", nil, func() permissions.BlockedReload {
		return permissions.BlockedReload{Changed: true, Entries: now}
	})

	got := rowsOfKind(blockedRows(blocked, home, global), tui.BlockedRowGlobal, tui.BlockedRowFloor)
	want := []tui.BlockedRow{
		{Kind: tui.BlockedRowGlobal, Path: "/opt/a", Source: global},
		{Kind: tui.BlockedRowFloor, Path: filepath.Join(home, ".codemeld")},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("rows = %+v, want %+v", got, want)
	}
}

type localBlockedFixture struct {
	home, project, global, local, shared string
}

func newLocalBlockedFixture(t *testing.T, globalBody, localBody, sharedBody string) localBlockedFixture {
	t.Helper()
	f := localBlockedFixture{home: declaredScopeDir(t), project: mustCanonical(t, declaredScopeDir(t))}
	f.global = SettingsPath(f.home)
	f.local = config.LocalSettingsPath(f.project)
	f.shared = projectSettingsPath(f.project)
	seedBlockedSettings(t, f.global, globalBody)
	if localBody != "" {
		seedBlockedSettings(t, f.local, localBody)
	}
	if sharedBody != "" {
		seedBlockedSettings(t, f.shared, sharedBody)
	}
	if err := trust.Record(f.home, f.project); err != nil {
		t.Fatalf("trust.Record: %v", err)
	}
	return f
}

func (f localBlockedFixture) live(t *testing.T) *permissions.BlockedPaths {
	t.Helper()
	layers := []securitystate.LayerSnapshot{{
		Kind: securitystate.LayerGlobal, Path: f.global, Present: true,
		Raw: mustValidateLayer(t, f.global, config.ValidateGlobalSettingsBytes),
	}}
	project := securitystate.LayerSnapshot{Kind: securitystate.LayerProject, Path: f.shared}
	if _, err := os.Stat(f.shared); err == nil {
		project.Present = true
		project.Raw = mustValidateLayer(t, f.shared, config.ValidateProjectSettingsBytes)
	}
	local := securitystate.LayerSnapshot{Kind: securitystate.LayerLocal, Path: f.local}
	if _, err := os.Stat(f.local); err == nil {
		local.Present = true
		local.Raw = mustValidateLayer(t, f.local, config.ValidateLocalSettingsBytes)
	}
	layers = append(layers, project, local)
	blocked, err := blockedPathsFromLayers(f.home, f.project, layers)
	if err != nil {
		t.Fatalf("blockedPathsFromLayers: %v", err)
	}
	return blocked
}

func mustValidateLayer(t *testing.T, path string, validate func([]byte, string) (map[string]any, config.LoadFailure, error)) map[string]any {
	t.Helper()
	raw, _, err := validate([]byte(mustReadFile(t, path)), path)
	if err != nil {
		t.Fatalf("validate %s: %v", path, err)
	}
	return raw
}

func TestBlockedRowsFrom_LocalAndSharedEntriesCarryTheirOwnKindAndOccurrence(t *testing.T) {
	home := declaredScopeDir(t)
	global := SettingsPath(home)
	root := declaredScopeDir(t)
	local := config.LocalSettingsPath(root)
	shared := projectSettingsPath(root)
	other := projectSettingsPath(declaredScopeDir(t))
	secrets := filepath.Join(declaredScopeDir(t), "secrets")

	entries := []permissions.BlockedEntry{
		{Path: secrets, Source: global},
		{Path: secrets, Source: local},
		{Path: secrets, Source: local},
		{Path: secrets, Source: shared},
		{Path: secrets, Source: shared},
		{Path: secrets, Source: other},
	}
	rows := blockedRowsFrom(entries, home, global, local, shared, false)

	want := []tui.BlockedRow{
		{Kind: tui.BlockedRowGlobal, Path: secrets, Source: global, Occurrence: 0},
		{Kind: tui.BlockedRowLocal, Path: secrets, Source: local, Occurrence: 0},
		{Kind: tui.BlockedRowLocal, Path: secrets, Source: local, Occurrence: 1},
		{Kind: tui.BlockedRowShared, Path: secrets, Source: shared, Occurrence: 0},
		{Kind: tui.BlockedRowShared, Path: secrets, Source: shared, Occurrence: 1},
		{Kind: tui.BlockedRowProject, Path: secrets, Source: other},
	}
	if got := rows[:len(want)]; !slices.Equal(got, want) {
		t.Fatalf("rows = %+v, want %+v (Occurrence counts within each file)", got, want)
	}
}

func TestRemoveBlockedEntry_LocalRowChangesOnlyTheLocalFile(t *testing.T) {
	keep := "/etc/secrets-keep"
	drop := "/etc/secrets-drop"
	f := newLocalBlockedFixture(t,
		"blocked_paths: []\n",
		fmt.Sprintf("blocked_paths:\n  - %q\n  - %q\n", drop, keep),
		"blocked_paths: []\n")
	blocked := f.live(t)
	globalBefore, sharedBefore := mustReadFile(t, f.global), mustReadFile(t, f.shared)

	row := tui.BlockedRow{Kind: tui.BlockedRowLocal, Path: drop, Source: f.local}
	if msg := removeBlockedEntry(blocked, f.home, row); msg != "" {
		t.Fatalf("removeBlockedEntry = %q, want no message once the path is no longer blocked", msg)
	}
	if got, want := mustReadFile(t, f.local), fmt.Sprintf("blocked_paths:\n  - %q\n", keep); got != want {
		t.Fatalf("local file = %q, want %q", got, want)
	}
	if got := mustReadFile(t, f.global); got != globalBefore {
		t.Fatalf("global file = %q, want it byte-identical %q", got, globalBefore)
	}
	if got := mustReadFile(t, f.shared); got != sharedBefore {
		t.Fatalf("shared project file = %q, want it byte-identical %q", got, sharedBefore)
	}
	if entry, ok := blocked.Current().Blocking(filepath.Join(drop, "x")); ok {
		t.Fatalf("Blocking(%q) after removal = %+v, want not blocked", drop, entry)
	}
}

func TestRemoveBlockedEntry_LocalRowStillBlockedMessages(t *testing.T) {
	t.Run("another layer still blocks it", func(t *testing.T) {
		shared := "/etc/shared-too"
		f := newLocalBlockedFixture(t,
			"blocked_paths: []\n",
			fmt.Sprintf("blocked_paths:\n  - %q\n", shared),
			fmt.Sprintf("blocked_paths:\n  - %q\n", shared))
		blocked := f.live(t)

		row := tui.BlockedRow{Kind: tui.BlockedRowLocal, Path: shared, Source: f.local}
		msg := removeBlockedEntry(blocked, f.home, row)
		want := fmt.Sprintf("%s is still blocked by the blocked_paths entry %s in %s", shared, shared, f.shared)
		if msg != want {
			t.Fatalf("message = %q, want %q", msg, want)
		}
	})

	t.Run("inside codemeld's own folder", func(t *testing.T) {
		f := newLocalBlockedFixture(t, "blocked_paths: []\n", "blocked_paths:\n  - \"~/.codemeld/cache\"\n", "")
		blocked := f.live(t)
		cache := filepath.Join(f.home, ".codemeld", "cache")

		row := tui.BlockedRow{Kind: tui.BlockedRowLocal, Path: cache, Source: f.local}
		msg := removeBlockedEntry(blocked, f.home, row)
		want := fmt.Sprintf("%s is still blocked: it is inside codemeld's own folder %s", cache, filepath.Join(f.home, ".codemeld"))
		if msg != want {
			t.Fatalf("message = %q, want %q", msg, want)
		}
	})
}

func TestRemoveBlockedEntry_WrongLocalOrSharedRowWritesNothing(t *testing.T) {
	entry := "/etc/secrets"
	body := fmt.Sprintf("blocked_paths:\n  - %q\n", entry)
	f := newLocalBlockedFixture(t, body, body, body)
	blocked := f.live(t)
	want := "only entries in " + fserrors.CollapseControls(f.global) + ", " + fserrors.CollapseControls(f.local) + " and " + fserrors.CollapseControls(f.shared) + " can be removed here"

	rows := map[string]tui.BlockedRow{
		"local kind naming the global file":   {Kind: tui.BlockedRowLocal, Path: entry, Source: f.global},
		"local kind naming the shared file":   {Kind: tui.BlockedRowLocal, Path: entry, Source: f.shared},
		"global kind naming the local file":   {Kind: tui.BlockedRowGlobal, Path: entry, Source: f.local},
		"global kind naming the shared file":  {Kind: tui.BlockedRowGlobal, Path: entry, Source: f.shared},
		"shared kind naming the global file":  {Kind: tui.BlockedRowShared, Path: entry, Source: f.global},
		"shared kind naming the local file":   {Kind: tui.BlockedRowShared, Path: entry, Source: f.local},
		"shared kind naming another project":  {Kind: tui.BlockedRowShared, Path: entry, Source: projectSettingsPath(declaredScopeDir(t))},
		"project kind naming the shared file": {Kind: tui.BlockedRowProject, Path: entry, Source: f.shared},
		"floor row":                           {Kind: tui.BlockedRowFloor, Path: filepath.Join(f.home, ".codemeld")},
		"warning row":                         {Kind: tui.BlockedRowWarning, Text: "blocked_paths has 300 entries"},
		"group row":                           {Kind: tui.BlockedRowGroup, Text: "Keys and passwords"},
		"recommended row passed to removal":   {Kind: tui.BlockedRowMissing, Path: "~/.gnupg", Group: "Keys and passwords"},
	}
	for name, row := range rows {
		t.Run(name, func(t *testing.T) {
			if msg := removeBlockedEntry(blocked, f.home, row); msg != want {
				t.Fatalf("message = %q, want %q", msg, want)
			}
			for _, path := range []string{f.global, f.local, f.shared} {
				if got := mustReadFile(t, path); got != body {
					t.Fatalf("%s = %q, want unchanged %q", path, got, body)
				}
			}
		})
	}
}

func TestRemoveBlockedEntry_ProjectRowInARootlessRunWritesNothing(t *testing.T) {
	home := declaredScopeDir(t)
	global := SettingsPath(home)
	body := "blocked_paths:\n  - \"/etc/secrets\"\n"
	seedBlockedSettings(t, global, body)
	blocked := liveGlobalBlocked(t, home)
	cwd := declaredScopeDir(t)
	t.Chdir(cwd)
	relShared := filepath.Join(".codemeld", "settings.yaml")
	want := "only entries in " + fserrors.CollapseControls(global) + " can be removed here"

	for name, row := range map[string]tui.BlockedRow{
		"local row":                 {Kind: tui.BlockedRowLocal, Path: "/etc/secrets", Source: "/nowhere/.codemeld/settings.local.yaml"},
		"shared row":                {Kind: tui.BlockedRowShared, Path: "/etc/secrets", Source: "/nowhere/.codemeld/settings.yaml"},
		"shared row, relative file": {Kind: tui.BlockedRowShared, Path: "/etc/secrets", Source: relShared},
	} {
		t.Run(name, func(t *testing.T) {
			if msg := removeBlockedEntry(blocked, home, row); msg != want {
				t.Fatalf("message = %q, want %q", msg, want)
			}
			if got := mustReadFile(t, global); got != body {
				t.Fatalf("global file = %q, want unchanged %q", got, body)
			}
			requireAbsent(t, filepath.Join(cwd, ".codemeld"))
		})
	}
}

func TestBlockedRows_RootlessRunClassifiesNoRowAsShared(t *testing.T) {
	home := declaredScopeDir(t)
	global := SettingsPath(home)
	relShared := filepath.Join(".codemeld", "settings.yaml")
	now := []permissions.BlockedEntry{{Path: "/opt/a", Source: relShared}}
	blocked := permissions.NewLiveBlockedPaths(home, "", nil, func() permissions.BlockedReload {
		return permissions.BlockedReload{Changed: true, Entries: now}
	})

	rows := blockedRows(blocked, home, global)
	if got := rowsOfKind(rows, tui.BlockedRowShared); len(got) != 0 {
		t.Fatalf("shared rows = %+v, want none in a rootless run", got)
	}
	if !slices.Contains(rows, tui.BlockedRow{Kind: tui.BlockedRowProject, Path: "/opt/a", Source: relShared}) {
		t.Fatalf("rows = %+v, want /opt/a as a read-only project row", rows)
	}
}

func TestRemoveBlockedEntry_SharedRowChangesOnlyTheSharedFile(t *testing.T) {
	keep := "/etc/secrets-keep"
	drop := "/etc/secrets-drop"
	globalBody := fmt.Sprintf("blocked_paths:\n  - %q\n", "/etc/global-only")
	localBody := fmt.Sprintf("blocked_paths:\n  - %q\n", "/etc/local-only")
	f := newLocalBlockedFixture(t, globalBody, localBody,
		fmt.Sprintf("blocked_paths:\n  - %q\n  - %q\n  - %q\n", drop, keep, drop))
	blocked := f.live(t)
	globalInfo, localInfo := mustStat(t, f.global), mustStat(t, f.local)

	var second tui.BlockedRow
	for _, row := range blockedRows(blocked, f.home, f.global) {
		if row.Kind == tui.BlockedRowShared && row.Path == drop && row.Occurrence == 1 {
			second = row
		}
	}
	if second.Source != f.shared {
		t.Fatalf("no second shared row for %s from %s", drop, f.shared)
	}
	msg := removeBlockedEntry(blocked, f.home, second)
	if want := fmt.Sprintf("%s is still blocked by the blocked_paths entry %s in %s", drop, drop, f.shared); msg != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
	if got := blockedItemsIn(t, f.shared); !slices.Equal(got, []string{drop, keep}) {
		t.Fatalf("shared blocked_paths = %q, want [%s %s]", got, drop, keep)
	}
	assertUnchanged(t, f.global, globalBody, globalInfo)
	assertUnchanged(t, f.local, localBody, localInfo)

	first := tui.BlockedRow{Kind: tui.BlockedRowShared, Path: drop, Source: f.shared}
	if msg := removeBlockedEntry(blocked, f.home, first); msg != "" {
		t.Fatalf("removeBlockedEntry = %q, want no message once the path is no longer blocked", msg)
	}
	if got := blockedItemsIn(t, f.shared); !slices.Equal(got, []string{keep}) {
		t.Fatalf("shared blocked_paths = %q, want [%s]", got, keep)
	}
	if entry, ok := blocked.Current().Blocking(filepath.Join(drop, "x")); ok {
		t.Fatalf("Blocking(%q) after removal = %+v, want not blocked", drop, entry)
	}
	if _, ok := blocked.Current().Blocking(filepath.Join(keep, "x")); !ok {
		t.Fatalf("Blocking(%q) after removal = false, want still blocked", keep)
	}
}

func TestRemoveBlockedEntry_SharedRowStillBlockedByAnotherFile(t *testing.T) {
	entry := "/etc/both"
	body := fmt.Sprintf("blocked_paths:\n  - %q\n", entry)
	f := newLocalBlockedFixture(t, "blocked_paths: []\n", body, body)
	blocked := f.live(t)

	msg := removeBlockedEntry(blocked, f.home, tui.BlockedRow{Kind: tui.BlockedRowShared, Path: entry, Source: f.shared})
	if want := fmt.Sprintf("%s is still blocked by the blocked_paths entry %s in %s", entry, entry, f.local); msg != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
	if got := blockedItemsIn(t, f.shared); len(got) != 0 {
		t.Fatalf("shared blocked_paths = %q, want empty", got)
	}
}

func TestRemoveBlockedEntry_RefusalNamesTheSharedFileEvenWhenAbsent(t *testing.T) {
	f := newLocalBlockedFixture(t, "blocked_paths: []\n", "blocked_paths: []\n", "")
	blocked := f.live(t)
	want := "only entries in " + fserrors.CollapseControls(f.global) + ", " + fserrors.CollapseControls(f.local) + " and " + fserrors.CollapseControls(f.shared) + " can be removed here"

	row := tui.BlockedRow{Kind: tui.BlockedRowProject, Path: "/etc/secrets", Source: f.shared}
	if msg := removeBlockedEntry(blocked, f.home, row); msg != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
	requireAbsent(t, f.shared)
}

func TestRemoveBlockedEntry_FailedLocalWriteNamesOnlyTheReason(t *testing.T) {
	entry := "/etc/secrets"
	body := fmt.Sprintf("blocked_paths:\n  - %q\n", entry)
	f := newLocalBlockedFixture(t, "blocked_paths: []\n", body, "")
	blocked := f.live(t)
	sentinel := errors.New("forced blocked sync failure")
	t.Cleanup(fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel }))

	row := tui.BlockedRow{Kind: tui.BlockedRowLocal, Path: entry, Source: f.local}
	msg := removeBlockedEntry(blocked, f.home, row)
	want := "couldn't update " + fserrors.CollapseControls(f.local) + ": " + string(config.ReasonWriteError)
	if msg != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
	if strings.Contains(msg, sentinel.Error()) {
		t.Fatalf("message = %q, want only the reason token", msg)
	}
	if got := mustReadFile(t, f.local); got != body {
		t.Fatalf("local file = %q, want unchanged %q", got, body)
	}
}

func TestRemoveBlockedEntry_GlobalRemovalCreatesNoTrustRecord(t *testing.T) {
	home := declaredScopeDir(t)
	global := SettingsPath(home)
	seedBlockedSettings(t, global, "blocked_paths:\n  - \"/etc/secrets\"\n")
	blocked := liveGlobalBlocked(t, home)

	row := tui.BlockedRow{Kind: tui.BlockedRowGlobal, Path: "/etc/secrets", Source: global}
	if msg := removeBlockedEntry(blocked, home, row); msg != "" {
		t.Fatalf("removeBlockedEntry = %q, want no message", msg)
	}
	if _, err := os.Stat(trust.StorePath(home)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat trust store = %v, want no record written by a global removal", err)
	}
}

func globalBlockedItems(t *testing.T, home string) []string {
	t.Helper()
	global := SettingsPath(home)
	raw, _, err := config.ValidateGlobalSettingsBytes([]byte(mustReadFile(t, global)), global)
	if err != nil {
		t.Fatalf("ValidateGlobalSettingsBytes: %v", err)
	}
	items, _ := raw["blocked_paths"].([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, _ := item.(string)
		out = append(out, s)
	}
	return out
}

func assertUnchanged(t *testing.T, path, body string, before os.FileInfo) {
	t.Helper()
	if got := mustReadFile(t, path); got != body {
		t.Fatalf("%s = %q, want unchanged %q", path, got, body)
	}
	if after := mustStat(t, path); !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("%s was rewritten", path)
	}
}

func TestAddUserEntry_AppendsKeepingCommentsAndBlocksAtOnce(t *testing.T) {
	home := declaredScopeDir(t)
	global := SettingsPath(home)
	seedBlockedSettings(t, global, "# my settings\nblocked_paths:\n  # Keys and passwords\n  - \"~/.ssh\"\n  # my own entries\n  - \"/opt/a\"\n")
	blocked := liveGlobalBlocked(t, home)
	target := filepath.Join(home, "secrets", "notes.txt")
	if _, ok := blocked.Current().Blocking(target); ok {
		t.Fatalf("Blocking(%q) before add = true, want false", target)
	}

	msg := addUserEntry(blocked, home, "~/secrets", tui.BlockedGlobal, false, "")
	if want := "~/secrets is now blocked (added to " + global + ")"; msg != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
	if got, want := mustReadFile(t, global), "# my settings\nblocked_paths:\n  # Keys and passwords\n  - \"~/.ssh\"\n  # my own entries\n  - \"/opt/a\"\n  - \"~/secrets\"\n"; got != want {
		t.Fatalf("file = %q, want %q", got, want)
	}
	if entry, ok := blocked.Current().Blocking(target); !ok || entry.Source != global {
		t.Fatalf("Blocking(%q) after add = %+v, %v; want an entry from %q", target, entry, ok, global)
	}
}

func TestAddUserEntry_RefusalsWriteNothing(t *testing.T) {
	sharedEntry := "/etc/shared-secrets"
	body := "# keep\nblocked_paths:\n  - \"~/.ssh\"\n"
	f := newLocalBlockedFixture(t, body, "", fmt.Sprintf("blocked_paths:\n  - %q\n", sharedEntry))
	blocked := f.live(t)
	ssh := filepath.Join(f.home, ".ssh")

	cases := []struct{ raw, want string }{
		{"~/.ssh/id_rsa", fmt.Sprintf("~/.ssh/id_rsa is already blocked by the blocked_paths entry %s in %s", ssh, f.global)},
		{sharedEntry + "/x", fmt.Sprintf("%s/x is already blocked by the blocked_paths entry %s in %s", sharedEntry, sharedEntry, f.shared)},
		{"~/.codemeld/cache", fmt.Sprintf("~/.codemeld/cache is already blocked: it is inside codemeld's own folder %s", filepath.Join(f.home, ".codemeld"))},
		{"secrets", `permissions: blocked_paths entry "secrets" must be absolute or start with ~/`},
		{"", "permissions: blocked_paths entry is empty"},
	}
	sharedBody := mustReadFile(t, f.shared)
	for _, dest := range []tui.BlockedDestination{tui.BlockedGlobal, tui.BlockedProjectShared, tui.BlockedProjectLocal} {
		for _, tc := range cases {
			t.Run(string(dest)+"/"+tc.raw, func(t *testing.T) {
				before, sharedBefore := mustStat(t, f.global), mustStat(t, f.shared)
				if msg := addUserEntry(blocked, f.home, tc.raw, dest, true, "project-root"); msg != tc.want {
					t.Fatalf("message = %q, want %q", msg, tc.want)
				}
				assertUnchanged(t, f.global, body, before)
				assertUnchanged(t, f.shared, sharedBody, sharedBefore)
				requireAbsent(t, f.local)
			})
		}
	}
}

func TestAddUserEntry_BroadEntryWarns(t *testing.T) {
	home := declaredScopeDir(t)
	global := SettingsPath(home)
	seedBlockedSettings(t, global, "blocked_paths: []\n")
	blocked := liveGlobalBlocked(t, home)

	msg := addUserEntry(blocked, home, "~", tui.BlockedGlobal, false, "")
	want := fmt.Sprintf("~ is now blocked (added to %s); warning: blocked_paths entry %s in %s covers your home folder (%s); programs need these to start, so most commands will fail", global, home, global, home)
	if msg != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
	if got := globalBlockedItems(t, home); !slices.Equal(got, []string{"~"}) {
		t.Fatalf("blocked_paths = %q, want [~]", got)
	}
}

func recommendedMissingRows() []tui.BlockedRow {
	var rows []tui.BlockedRow
	for _, group := range recommendedBlockedPaths {
		for _, path := range group.paths {
			rows = append(rows, tui.BlockedRow{Kind: tui.BlockedRowMissing, Path: path, Group: group.heading})
		}
	}
	return rows
}

func TestAddAllRecommended_WritesEveryEntryWithoutAList(t *testing.T) {
	home := declaredScopeDir(t)
	global := SettingsPath(home)
	seedBlockedSettings(t, global, "# my settings\n")
	rows := recommendedMissingRows()

	msg := addAllRecommended(home, rows)
	if want := fmt.Sprintf("processed %d recommended entries in %s (already-present entries left unchanged)", len(rows), global); msg != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
	var want []string
	for _, row := range rows {
		want = append(want, row.Path)
	}
	if got := globalBlockedItems(t, home); !slices.Equal(got, want) {
		t.Fatalf("blocked_paths = %q, want %q", got, want)
	}
	if !strings.HasPrefix(mustReadFile(t, global), "# my settings\n") {
		t.Fatalf("file = %q, want the comment kept", mustReadFile(t, global))
	}
}

func TestAddAllRecommended_InsertsUnderExistingHeadings(t *testing.T) {
	home := declaredScopeDir(t)
	global := SettingsPath(home)
	seedBlockedSettings(t, global, "blocked_paths:\n  # Keys and passwords\n  - \"~/.ssh\"\n  # Cloud and cluster logins\n  - \"~/.aws\"\n")
	rows := []tui.BlockedRow{
		{Kind: tui.BlockedRowMissing, Path: "~/.gnupg", Group: "Keys and passwords"},
		{Kind: tui.BlockedRowMissing, Path: "~/.kube", Group: "Cloud and cluster logins"},
	}

	if msg := addAllRecommended(home, rows); !strings.HasPrefix(msg, "processed 2 recommended entries") {
		t.Fatalf("message = %q, want 2 processed", msg)
	}
	want := "blocked_paths:\n  # Keys and passwords\n  - \"~/.ssh\"\n  - \"~/.gnupg\"\n  # Cloud and cluster logins\n  - \"~/.aws\"\n  - \"~/.kube\"\n"
	if got := mustReadFile(t, global); got != want {
		t.Fatalf("file = %q, want %q", got, want)
	}
}

func TestAddAllRecommended_ConcurrentDuplicateStaysSingle(t *testing.T) {
	home := declaredScopeDir(t)
	global := SettingsPath(home)
	seedBlockedSettings(t, global, "blocked_paths:\n  - \"~/.gnupg\"\n")
	rows := []tui.BlockedRow{
		{Kind: tui.BlockedRowMissing, Path: "~/.ssh", Group: "Keys and passwords"},
		{Kind: tui.BlockedRowMissing, Path: "~/.gnupg", Group: "Keys and passwords"},
		{Kind: tui.BlockedRowMissing, Path: "~/.aws", Group: "Cloud and cluster logins"},
	}

	msg := addAllRecommended(home, rows)
	if want := fmt.Sprintf("processed 3 recommended entries in %s (already-present entries left unchanged)", global); msg != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
	if got, want := globalBlockedItems(t, home), []string{"~/.gnupg", "~/.ssh", "~/.aws"}; !slices.Equal(got, want) {
		t.Fatalf("blocked_paths = %q, want %q", got, want)
	}
}

func TestAddAllRecommended_StopsAtTheFirstFailure(t *testing.T) {
	home := declaredScopeDir(t)
	global := SettingsPath(home)
	seedBlockedSettings(t, global, "blocked_paths: []\n")
	rows := []tui.BlockedRow{
		{Kind: tui.BlockedRowMissing, Path: "~/.ssh", Group: "Keys and passwords"},
		{Kind: tui.BlockedRowMissing, Path: "secrets", Group: "Keys and passwords"},
		{Kind: tui.BlockedRowMissing, Path: "~/.aws", Group: "Cloud and cluster logins"},
	}

	msg := addAllRecommended(home, rows)
	if want := "processed 1 of 3; stopped at secrets: couldn't update " + global + ": " + string(config.ReasonRereadParseError); msg != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
	if got := globalBlockedItems(t, home); !slices.Equal(got, []string{"~/.ssh"}) {
		t.Fatalf("blocked_paths = %q, want only ~/.ssh", got)
	}
}

func requireAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Lstat(%q) = %v, want the file absent", path, err)
	}
}

const blockedUnrelatedKey = "model:\n  active:\n    provider: openai\n    id: gpt-5\n"

func (f localBlockedFixture) target(dest tui.BlockedDestination) string {
	switch dest {
	case tui.BlockedProjectShared:
		return f.shared
	case tui.BlockedProjectLocal:
		return f.local
	}
	return f.global
}

func blockedItemsIn(t *testing.T, path string) []string {
	t.Helper()
	_, raw, _, err := config.LoadYAMLBytes([]byte(mustReadFile(t, path)), path)
	if err != nil {
		t.Fatalf("LoadYAMLBytes(%s): %v", path, err)
	}
	items, _ := raw["blocked_paths"].([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, _ := item.(string)
		out = append(out, s)
	}
	return out
}

var blockedDestinations = []tui.BlockedDestination{tui.BlockedGlobal, tui.BlockedProjectShared, tui.BlockedProjectLocal}

func TestAddUserEntry_EachDestinationWritesOnlyItsFileAndBlocksAtOnce(t *testing.T) {
	wantKind := map[tui.BlockedDestination]tui.BlockedRowKind{
		tui.BlockedGlobal:        tui.BlockedRowGlobal,
		tui.BlockedProjectShared: tui.BlockedRowShared,
		tui.BlockedProjectLocal:  tui.BlockedRowLocal,
	}
	for _, dest := range blockedDestinations {
		t.Run(string(dest), func(t *testing.T) {
			body := "blocked_paths: []\n"
			f := newLocalBlockedFixture(t, body, body, body)
			blocked := f.live(t)
			entry := "/etc/" + string(dest)
			target := f.target(dest)
			before := map[string]os.FileInfo{}
			for _, path := range []string{f.global, f.shared, f.local} {
				before[path] = mustStat(t, path)
			}

			msg := addUserEntry(blocked, f.home, entry, dest, true, "project-root")
			if want := entry + " is now blocked (added to " + target + ")"; msg != want {
				t.Fatalf("message = %q, want %q", msg, want)
			}
			if got := blockedItemsIn(t, target); !slices.Equal(got, []string{entry}) {
				t.Fatalf("%s blocked_paths = %q, want [%s]", target, got, entry)
			}
			for path, info := range before {
				if path != target {
					assertUnchanged(t, path, body, info)
				}
			}
			if got, ok := blocked.Current().Blocking(filepath.Join(entry, "x")); !ok || got.Source != target {
				t.Fatalf("Blocking after add = %+v, %v; want an entry from %s", got, ok, target)
			}
			rows := blockedRows(blocked, f.home, f.global)
			if !slices.Contains(rows, tui.BlockedRow{Kind: wantKind[dest], Path: entry, Source: target}) {
				t.Fatalf("rows = %+v, want %s listed from %s", rows, entry, target)
			}
		})
	}
}

func TestAddUserEntry_ProjectDestinationsNeedTheLaunchGate(t *testing.T) {
	f := newLocalBlockedFixture(t, "blocked_paths: []\n", "", "")
	admitted := f.live(t)
	rootless := liveGlobalBlocked(t, f.home)
	before := mustStat(t, f.global)

	cases := []struct {
		name    string
		blocked *permissions.BlockedPaths
		dest    tui.BlockedDestination
		allowed bool
		want    string
	}{
		{"shared, gate closed", admitted, tui.BlockedProjectShared, false, blockedProjectUnavailable},
		{"local, gate closed", admitted, tui.BlockedProjectLocal, false, blockedProjectUnavailable},
		{"shared, no root", rootless, tui.BlockedProjectShared, true, blockedProjectUnavailable},
		{"local, no root", rootless, tui.BlockedProjectLocal, true, blockedProjectUnavailable},
		{"unknown", admitted, tui.BlockedDestination("elsewhere"), true, blockedUnknownDestination},
		{"empty", admitted, tui.BlockedDestination(""), true, blockedUnknownDestination},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if msg := addUserEntry(tc.blocked, f.home, "/etc/secrets", tc.dest, tc.allowed, "project-root"); msg != tc.want {
				t.Fatalf("message = %q, want %q", msg, tc.want)
			}
			assertUnchanged(t, f.global, "blocked_paths: []\n", before)
			requireAbsent(t, f.shared)
			requireAbsent(t, f.local)
		})
	}
	if blockedProjectUnavailable != "refused: project settings are not available for this launch (no approved project root); nothing written" ||
		blockedUnknownDestination != "refused: unknown /blocked destination; nothing written" {
		t.Fatalf("refusal texts changed: %q / %q", blockedProjectUnavailable, blockedUnknownDestination)
	}
}

func TestAddUserEntry_FirstSharedCreationNamesTheMarker(t *testing.T) {
	for boundary, render := range map[string]func(string) string{
		"project-root":         tui.RenderProjectRootMarkerNotice,
		discoveryLaunchDirOnly: tui.RenderCrossModeMarkerNotice,
	} {
		t.Run(boundary, func(t *testing.T) {
			f := newLocalBlockedFixture(t, "blocked_paths: []\n", "", "")
			blocked := f.live(t)

			msg := addUserEntry(blocked, f.home, "/etc/a", tui.BlockedProjectShared, true, boundary)
			want := "/etc/a is now blocked (added to " + f.shared + ")\n" + render(permissions.BoundPromptFact(f.shared))
			if msg != want {
				t.Fatalf("message = %q, want %q", msg, want)
			}
			if msg := addUserEntry(blocked, f.home, "/etc/b", tui.BlockedProjectShared, true, boundary); msg != "/etc/b is now blocked (added to "+f.shared+")" {
				t.Fatalf("second add = %q, want no creation notice for an existing file", msg)
			}
			requireAbsent(t, f.local)
		})
	}
}

func TestAddUserEntry_FirstLocalCreationNamesTheIgnoreNotice(t *testing.T) {
	f := newLocalBlockedFixture(t, "blocked_paths: []\n", "", "")
	blocked := f.live(t)

	msg := addUserEntry(blocked, f.home, "/etc/a", tui.BlockedProjectLocal, true, "project-root")
	want := "/etc/a is now blocked (added to " + f.local + ")\n" + tui.RenderLocalSettingsIgnoreNotice(f.local, config.LocalSettingsLockPath(f.project))
	if msg != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
	if !strings.Contains(msg, "settings.local.yaml ") || !strings.Contains(msg, "settings.local.yaml.lock") {
		t.Fatalf("message = %q, want it to name settings.local.yaml and settings.local.yaml.lock", msg)
	}
	if msg := addUserEntry(blocked, f.home, "/etc/b", tui.BlockedProjectLocal, true, "project-root"); msg != "/etc/b is now blocked (added to "+f.local+")" {
		t.Fatalf("second add = %q, want no creation notice for an existing file", msg)
	}
	requireAbsent(t, f.shared)
}

func TestAddUserEntry_FailureBeforePublicationChangesNothing(t *testing.T) {
	for _, dest := range blockedDestinations {
		for _, seeded := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/seeded=%v", dest, seeded), func(t *testing.T) {
				body := ""
				if seeded {
					body = "blocked_paths: []\n"
				}
				f := newLocalBlockedFixture(t, "blocked_paths: []\n", body, body)
				blocked := f.live(t)
				target := f.target(dest)
				t.Cleanup(fsutil.SetSyncFileForTest(func(*os.File) error { return errors.New("forced sync failure") }))

				msg := addUserEntry(blocked, f.home, "/etc/a", dest, true, "project-root")
				if want := "couldn't update " + target + ": " + string(config.ReasonWriteError); msg != want {
					t.Fatalf("message = %q, want %q", msg, want)
				}
				if dest == tui.BlockedGlobal || seeded {
					if got := blockedItemsIn(t, target); len(got) != 0 {
						t.Fatalf("%s blocked_paths = %q, want unchanged", target, got)
					}
				} else {
					requireAbsent(t, target)
				}
				if entry, ok := blocked.Current().Blocking("/etc/a"); ok {
					t.Fatalf("Blocking after a failed add = %+v, want not in force", entry)
				}
			})
		}
	}
}

func TestAddUserEntry_ParentSyncFailureAfterPublicationReportsFailure(t *testing.T) {
	for _, dest := range blockedDestinations {
		t.Run(string(dest), func(t *testing.T) {
			f := newLocalBlockedFixture(t, "blocked_paths: []\n", "", "")
			if err := os.MkdirAll(filepath.Dir(f.shared), 0o700); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			blocked := f.live(t)
			target := f.target(dest)
			t.Cleanup(fsutil.SetSyncDirForTest(func(*os.File) error { return errors.New("forced parent sync failure") }))

			msg := addUserEntry(blocked, f.home, "/etc/a", dest, true, "project-root")
			if want := "couldn't update " + target + ": " + string(config.ReasonParentDirError); msg != want {
				t.Fatalf("message = %q, want %q with no success or creation notice", msg, want)
			}
			if got := blockedItemsIn(t, target); !slices.Equal(got, []string{"/etc/a"}) {
				t.Fatalf("%s blocked_paths = %q, want the published entry on disk", target, got)
			}
			if entry, ok := blocked.Current().Blocking("/etc/a"); !ok || entry.Source != target {
				t.Fatalf("Blocking after the published add = %+v, %v; want it enforced from %s", entry, ok, target)
			}
		})
	}
}

func TestAddUserEntry_LockFailureWritesNothing(t *testing.T) {
	for _, dest := range []tui.BlockedDestination{tui.BlockedProjectShared, tui.BlockedProjectLocal} {
		t.Run(string(dest), func(t *testing.T) {
			f := newLocalBlockedFixture(t, "blocked_paths: []\n", blockedUnrelatedKey, blockedUnrelatedKey)
			blocked := f.live(t)
			target := f.target(dest)
			if err := os.Mkdir(target+".lock", 0o700); err != nil {
				t.Fatalf("Mkdir: %v", err)
			}
			before := mustStat(t, target)

			msg := addUserEntry(blocked, f.home, "/etc/a", dest, true, "project-root")
			if want := "couldn't update " + target + ": " + string(config.ReasonLockAcquireError); msg != want {
				t.Fatalf("message = %q, want %q", msg, want)
			}
			assertUnchanged(t, target, blockedUnrelatedKey, before)
		})
	}
}

func folderContents(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	out := map[string]string{}
	for _, entry := range entries {
		out[entry.Name()] = mustReadFile(t, filepath.Join(dir, entry.Name()))
	}
	return out
}

func TestBlockedWrites_SymlinkedProjectFolderLeavesTheGlobalFolderUntouched(t *testing.T) {
	entry := "/etc/secrets"
	globalBody := fmt.Sprintf("blocked_paths:\n  - %q\n", entry)
	cases := []struct {
		name   string
		dest   tui.BlockedDestination
		remove bool
	}{
		{"add shared", tui.BlockedProjectShared, false},
		{"add local", tui.BlockedProjectLocal, false},
		{"remove shared", tui.BlockedProjectShared, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLocalBlockedFixture(t, globalBody, "", "")
			globalDir := filepath.Dir(f.global)
			if err := os.Symlink(globalDir, filepath.Join(f.project, ".codemeld")); err != nil {
				t.Fatalf("Symlink: %v", err)
			}
			blocked := f.live(t)
			// The live-list reread creates its own lock sidecars by pathname; settle them so only the write is measured.
			blocked.Current()
			before, info := folderContents(t, globalDir), mustStat(t, f.global)

			var msg string
			if tc.remove {
				row := tui.BlockedRow{Kind: tui.BlockedRowShared, Path: entry, Source: f.shared}
				if rows := blockedRows(blocked, f.home, f.global); !slices.Contains(rows, row) {
					t.Fatalf("rows = %+v, want a removable shared row for %s", rows, entry)
				}
				msg = removeBlockedEntry(blocked, f.home, row)
			} else {
				msg = addUserEntry(blocked, f.home, "/etc/a", tc.dest, true, "project-root")
			}
			if want := "couldn't update " + fserrors.CollapseControls(f.target(tc.dest)) + ": " + string(config.ReasonParentDirError); msg != want {
				t.Fatalf("message = %q, want %q with no success notice", msg, want)
			}
			assertUnchanged(t, f.global, globalBody, info)
			if after := folderContents(t, globalDir); !maps.Equal(after, before) {
				t.Fatalf("global folder = %q, want unchanged %q", after, before)
			}
		})
	}
}

func TestAddUserEntry_ConcurrentProjectWritersKeepEveryPath(t *testing.T) {
	for _, dest := range []tui.BlockedDestination{tui.BlockedProjectShared, tui.BlockedProjectLocal} {
		t.Run(string(dest), func(t *testing.T) {
			f := newLocalBlockedFixture(t, "blocked_paths: []\n", blockedUnrelatedKey, blockedUnrelatedKey)
			blocked := f.live(t)
			target := f.target(dest)

			published := make(chan struct{})
			release := make(chan struct{})
			var holding atomic.Bool
			t.Cleanup(fsutil.SetSyncDirForTest(func(dir *os.File) error {
				if holding.CompareAndSwap(false, true) {
					close(published)
					<-release
				}
				return dir.Sync()
			}))

			msgs := make([]string, 3)
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				msgs[0] = addUserEntry(blocked, f.home, "/etc/a", dest, true, "project-root")
			}()
			<-published

			if got := blockedItemsIn(t, target); !slices.Equal(got, []string{"/etc/a"}) {
				t.Fatalf("holder published %q, want [/etc/a] before the late writers start", got)
			}
			if held, _, _ := locks.TryAcquire(target + ".lock"); held != nil {
				held()
				t.Fatal("sidecar lock free while the holder is still inside Persist")
			}
			if _, ok := blocked.Current().Blocking("/etc/a"); ok {
				t.Fatal("live check read the settings file while its writer held the sidecar")
			}

			var dup string
			for i, path := range []string{"/etc/b", "/etc/c"} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					msgs[i+1] = addUserEntry(blocked, f.home, path, dest, true, "project-root")
				}()
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, dup = persistUserEntry(f.home, f.project, "/etc/a", dest, "project-root")
			}()
			close(release)
			wg.Wait()

			for i, path := range []string{"/etc/a", "/etc/b", "/etc/c"} {
				if want := path + " is now blocked (added to " + target + ")"; msgs[i] != want {
					t.Errorf("writer %s = %q, want %q", path, msgs[i], want)
				}
			}
			if dup != "" {
				t.Errorf("duplicate add = %q, want success", dup)
			}
			got := blockedItemsIn(t, target)
			slices.Sort(got)
			if !slices.Equal(got, []string{"/etc/a", "/etc/b", "/etc/c"}) {
				t.Fatalf("%s blocked_paths = %q, want each path once", target, got)
			}
			if body := mustReadFile(t, target); !strings.HasPrefix(body, blockedUnrelatedKey) {
				t.Fatalf("%s = %q, want the unrelated key kept", target, body)
			}
			for _, path := range []string{"/etc/a", "/etc/b", "/etc/c"} {
				if entry, ok := blocked.Current().Blocking(path); !ok || entry.Source != target {
					t.Errorf("Blocking(%s) after release = %+v, %v; want it enforced from %s", path, entry, ok, target)
				}
			}
		})
	}
}
