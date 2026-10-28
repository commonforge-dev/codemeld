package tui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
)

type fakePermissionLister struct{ entries []permissions.PermissionEntry }

func (l *fakePermissionLister) List() []permissions.PermissionEntry { return l.entries }

// fakeSettingsPicker records what it was shown without opening a real overlay. To pin
// crash-safe ordering it snapshots, at Present time, the host's flush count and recorded
// slash_command count — both must already be 1 when the overlay opens.
type fakeSettingsPicker struct {
	host              *fakeHost
	presented         [][]PermissionRow
	deps              SettingsDeps
	flushesAtPresent  int
	slashEvtAtPresent int
}

func (p *fakeSettingsPicker) Present(rows []PermissionRow, deps SettingsDeps) {
	if p.host != nil {
		p.flushesAtPresent = p.host.flushes
		p.slashEvtAtPresent = len(p.host.events())
	}
	p.presented = append(p.presented, rows)
	p.deps = deps
}

func openEntryPicker(a *App, entries []permissions.PermissionEntry, revoke func(permissions.PermissionEntry), relist func() []permissions.PermissionEntry) {
	var deps SettingsDeps
	if revoke != nil {
		deps.Revoke = func(row PermissionRow) { revoke(row.Entry) }
	}
	if relist != nil {
		deps.Rows = func() []PermissionRow { return unlayeredPermissionRows(relist()) }
	}
	a.openSettingsPicker(unlayeredPermissionRows(entries), deps, SessionSettings{})
}

func highlightedEntry(a *App) (permissions.PermissionEntry, bool) {
	row, ok := a.settingsHighlightedRow()
	return row.Entry, ok
}

func newSettingsRegistry(t *testing.T, deps SettingsDeps) *Registry {
	t.Helper()
	r, err := NewRegistry([]Command{
		{
			Name:        "settings",
			Description: "Show and change settings and stored permission grants",
			ArgSig:      ArgNone,
			Phase:       PhaseOne,
			Handler:     NewSettingsHandler(deps),
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

// TestSettingsHandler_FlushesSuccessBeforeOpening pins the crash-safe ordering: the
// picker-open slash_command{success} is recorded and flushed before the overlay opens.
func TestSettingsHandler_FlushesSuccessBeforeOpening(t *testing.T) {
	host := newFakeHost()
	lister := &fakePermissionLister{entries: []permissions.PermissionEntry{
		{Kind: "tool", Subject: permissions.CapabilityWrite, PathScope: "*", GrantKind: "global"},
	}}
	picker := &fakeSettingsPicker{host: host}
	revoked := 0
	deps := SettingsDeps{Lister: lister, Picker: picker, Revoke: func(PermissionRow) { revoked++ }}
	reg := newSettingsRegistry(t, deps)

	res := reg.DispatchSlashInput("/settings", host)
	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /settings = %+v, want Handled/nil-err", res)
	}
	if len(picker.presented) != 1 || len(picker.presented[0]) != 1 {
		t.Fatalf("picker presented %v, want one call with the one grant", picker.presented)
	}
	// The handler forwards the injected revoke seam (not a fake/double) to the overlay.
	if picker.deps.Revoke == nil {
		t.Fatal("handler did not forward the revoke action to the picker")
	}
	picker.deps.Revoke(PermissionRow{})
	if revoked != 1 {
		t.Errorf("forwarded revoke invoked deps.Revoke %d times, want 1", revoked)
	}
	if evs := host.events(); len(evs) != 1 || decodeSlash(t, evs[0]).Outcome != "success" {
		t.Fatalf("slash_command events = %v, want one success", evs)
	}
	// The ordering assertion: both were already recorded when the overlay opened, so moving
	// Present() above FlushActive/AppendSlashCommand in the handler fails this test.
	if picker.flushesAtPresent != 1 {
		t.Errorf("flushes at Present time = %d, want 1 (success flushed before opening)", picker.flushesAtPresent)
	}
	if picker.slashEvtAtPresent != 1 {
		t.Errorf("slash_command events at Present time = %d, want 1 (success recorded before opening)", picker.slashEvtAtPresent)
	}
}

func TestRenderPermissionEntry(t *testing.T) {
	cases := []struct {
		name string
		e    permissions.PermissionEntry
		want string
	}{
		{
			name: "capability write, global",
			e:    permissions.PermissionEntry{Kind: "tool", Subject: permissions.CapabilityWrite, PathScope: "*", GrantKind: "global"},
			want: "allow writing (create + edit) — globally",
		},
		{
			name: "capability write_tree, folder",
			e:    permissions.PermissionEntry{Kind: "tool", Subject: permissions.CapabilityWriteTree, PathScope: "/home/me/project", GrantKind: "folder"},
			want: "allow creating and editing files and folders (create + edit + mkdir) — in /home/me/project",
		},
		{
			name: "capability read, folder",
			e:    permissions.PermissionEntry{Kind: "tool", Subject: permissions.CapabilityRead, PathScope: "/home/me/project", GrantKind: "folder"},
			want: "allow reading/searching (read + grep + glob + list + tree + file_count) — in /home/me/project",
		},
		{
			name: "legacy concrete tool subject",
			e:    permissions.PermissionEntry{Kind: "tool", Subject: "grep", PathScope: "*", GrantKind: "global"},
			want: "allow the grep tool — globally",
		},
		{
			name: "literal command, folder",
			e:    permissions.PermissionEntry{Kind: "literal", Subject: "npm test", PathScope: "/srv/app", GrantKind: "folder"},
			want: "run npm test — in /srv/app",
		},
		{
			name: "direct command, global",
			e:    permissions.PermissionEntry{Kind: "direct", Subject: "ls", PathScope: "*", GrantKind: "global"},
			want: "run ls — globally",
		},
		{
			name: "project host, web_fetch",
			e:    permissions.PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "example.com", GrantKind: "project"},
			want: "allow the web_fetch tool — example.com",
		},
		{
			name: "project host, web_search",
			e:    permissions.PermissionEntry{Kind: "tool", Subject: "web_search", HostScope: "docs.example.org", GrantKind: "project"},
			want: "allow the web_search tool — docs.example.org",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderPermissionEntry(tc.e); got != tc.want {
				t.Errorf("renderPermissionEntry() = %q, want %q", got, tc.want)
			}
		})
	}
}

// permissionsFixture is a mix of global and folder grants, legacy and capability subjects.
func permissionsFixture() []permissions.PermissionEntry {
	return []permissions.PermissionEntry{
		{Kind: "tool", Subject: permissions.CapabilityWrite, PathScope: "*", GrantKind: "global"},
		{Kind: "tool", Subject: "grep", PathScope: "*", GrantKind: "global"},
		{Kind: "tool", Subject: permissions.CapabilityRead, PathScope: "/home/me/project", GrantKind: "folder"},
		{Kind: "literal", Subject: "npm test", PathScope: "/home/me/project", GrantKind: "folder"},
	}
}

func permissionsHostFixture() []permissions.PermissionEntry {
	return append(permissionsFixture(),
		permissions.PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "example.com", GrantKind: "project"},
		permissions.PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "docs.example.org", GrantKind: "project"},
		permissions.PermissionEntry{Kind: "tool", Subject: "web_search", HostScope: "example.com", GrantKind: "project"},
	)
}

func listItems(l interface{ GetItemCount() int }, get func(int) string) []string {
	out := make([]string, l.GetItemCount())
	for i := range out {
		out[i] = get(i)
	}
	return out
}

func TestSettingsTabBar_DrawsEveryTabAsItsOwnChip(t *testing.T) {
	labels := []string{"commands / tool grants", "folders", "project hosts", "openrouter", "settings"}
	for active := range permTabCount {
		chips := make([]string, len(labels))
		for i, label := range labels {
			chips[i] = "[" + chromeOnFillText + ":" + statusSegmentBody1 + ":]" + label + "[-:-:-]"
			if i == active {
				chips[i] = "[" + chromeOnFillText + ":" + accentTealHex + ":b]" + label + "[-:-:-]"
			}
		}
		if got, want := settingsTabBar(active), strings.Join(chips, " │ "); got != want {
			t.Errorf("tab bar with tab %d active = %q, want %q", active, got, want)
		}
	}
}

func TestSettingsTabBar_FitsOneRowOfAnEightyColumnOverlay(t *testing.T) {
	plain := strings.Join([]string{permTabGlobal, permTabFolders, permTabHosts, permTabOpenRouter, permTabSettings}, " │ ")
	for active := range permTabCount {
		if got := tview.TaggedStringWidth(settingsTabBar(active)); got != 72 {
			t.Errorf("tab bar width with tab %d active = %d cells, want 72", active, got)
		}
	}

	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatal(err)
	}
	screen.SetSize(80, 24)
	a := New(nil)
	openEntryPicker(a, permissionsFixture(), nil, nil)
	for active := range permTabCount {
		a.settingsPicker.activeTab = active
		a.renderSettingsTab()
		a.pages.SetRect(0, 0, 80, 24)
		a.pages.Draw(screen)
		screen.Show()
		rows := screenRows(screen)
		if !strings.Contains(rows[1], plain) {
			t.Errorf("tab %d active: tab bar row = %q, want all five tabs %q unclipped", active, rows[1], plain)
		}
		if strings.Contains(rows[2], permTabSettings) {
			t.Errorf("tab %d active: row below the tab bar = %q, want no wrapped tab text", active, rows[2])
		}
	}
}

func TestSettingsPicker_TabsListReadably(t *testing.T) {
	a := New(nil)
	openEntryPicker(a, permissionsFixture(), nil, nil)

	pp := a.settingsPicker
	if pp == nil {
		t.Fatal("settingsPicker nil after open")
	}
	if !a.anyOverlayOpen() {
		t.Error("anyOverlayOpen() = false while the permissions overlay is open")
	}

	get := func(i int) string { s, _ := pp.list.GetItemText(i); return s }

	// Global tab: the two globally-scoped grants, capability and legacy, both readable.
	globalRows := listItems(pp.list, get)
	wantGlobal := []string{
		"allow the grep tool — globally",
		"allow writing (create + edit) — globally",
	}
	if len(globalRows) != len(wantGlobal) {
		t.Fatalf("global tab rows = %v, want %v", globalRows, wantGlobal)
	}
	for i, w := range wantGlobal {
		if globalRows[i] != w {
			t.Errorf("global row %d = %q, want %q", i, globalRows[i], w)
		}
	}

	// Switch to the folders tab and check its two folder-scoped grants.
	a.stepSettingsTab(1)
	if pp.activeTab != permTabIndexFolders {
		t.Fatalf("activeTab = %d after toggle, want %d", pp.activeTab, permTabIndexFolders)
	}
	folderRows := listItems(pp.list, get)
	wantFolders := []string{
		"allow reading/searching (read + grep + glob + list + tree + file_count) — in /home/me/project",
		"run npm test — in /home/me/project",
	}
	if len(folderRows) != len(wantFolders) {
		t.Fatalf("folders tab rows = %v, want %v", folderRows, wantFolders)
	}
	for i, w := range wantFolders {
		if folderRows[i] != w {
			t.Errorf("folder row %d = %q, want %q", i, folderRows[i], w)
		}
	}
}

func permissionsRowsOnTab(a *App) []string {
	pp := a.settingsPicker
	return listItems(pp.list, func(i int) string { s, _ := pp.list.GetItemText(i); return s })
}

func TestSettingsPicker_HostTabListsToolAndHost(t *testing.T) {
	a := New(nil)
	openEntryPicker(a, permissionsHostFixture(), nil, nil)
	pp := a.settingsPicker

	wantGlobal := []string{
		"allow the grep tool — globally",
		"allow writing (create + edit) — globally",
	}
	wantFolders := []string{
		"allow reading/searching (read + grep + glob + list + tree + file_count) — in /home/me/project",
		"run npm test — in /home/me/project",
	}
	wantHosts := []string{
		"allow the web_fetch tool — docs.example.org",
		"allow the web_fetch tool — example.com",
		"allow the web_search tool — example.com",
	}

	for _, tc := range []struct {
		tab  int
		want []string
	}{
		{tab: 0, want: wantGlobal},
		{tab: permTabIndexFolders, want: wantFolders},
		{tab: permTabIndexHosts, want: wantHosts},
	} {
		if pp.activeTab != tc.tab {
			t.Fatalf("activeTab = %d, want %d", pp.activeTab, tc.tab)
		}
		got := permissionsRowsOnTab(a)
		if len(got) != len(tc.want) {
			t.Fatalf("tab %d rows = %v, want %v", tc.tab, got, tc.want)
		}
		for i, w := range tc.want {
			if got[i] != w {
				t.Errorf("tab %d row %d = %q, want %q", tc.tab, i, got[i], w)
			}
		}
		a.stepSettingsTab(1)
	}
	if pp.activeTab != permTabIndexOpenRouter {
		t.Fatalf("activeTab after the grant tabs = %d, want the openrouter tab %d", pp.activeTab, permTabIndexOpenRouter)
	}
	a.stepSettingsTab(1)
	if pp.activeTab != permTabIndexSettings {
		t.Fatalf("activeTab after the openrouter tab = %d, want the settings tab %d", pp.activeTab, permTabIndexSettings)
	}
	a.stepSettingsTab(1)
	if pp.activeTab != 0 {
		t.Errorf("activeTab after cycling all tabs = %d, want 0", pp.activeTab)
	}

	for _, row := range wantHosts {
		for _, banned := range []string{"globally", " in /", "*", "create + edit", "folder"} {
			if strings.Contains(row, banned) {
				t.Errorf("host row %q contains path/capability text %q", row, banned)
			}
		}
	}
}

func permissionsUnorderedFixture() []permissions.PermissionEntry {
	return []permissions.PermissionEntry{
		{Kind: "literal", Subject: "apt update", PathScope: "*", GrantKind: "global"},
		{Kind: "tool", Subject: "grep", PathScope: "*", GrantKind: "global"},
		{Kind: "literal", Subject: "zsh lint", PathScope: "*", GrantKind: "global"},
		{Kind: "literal", Subject: "make build", PathScope: "/home/me/alpha", GrantKind: "folder"},
		{Kind: "tool", Subject: "grep", PathScope: "/home/me/zeta", GrantKind: "folder"},
		{Kind: "literal", Subject: "Make test", PathScope: "/home/me/beta", GrantKind: "folder"},
		{Kind: "tool", Subject: "web_fetch", HostScope: "alpha.example.com", GrantKind: "project"},
		{Kind: "tool", Subject: "web_search", HostScope: "zeta.example.com", GrantKind: "project"},
		{Kind: "tool", Subject: "web_fetch", HostScope: "zulu.example.com", GrantKind: "project"},
	}
}

func wantUnorderedRowsByTab() [][]string {
	return [][]string{
		{
			"allow the grep tool — globally",
			"run apt update — globally",
			"run zsh lint — globally",
		},
		{
			"allow the grep tool — in /home/me/zeta",
			"run make build — in /home/me/alpha",
			"run Make test — in /home/me/beta",
		},
		{
			"allow the web_fetch tool — alpha.example.com",
			"allow the web_fetch tool — zulu.example.com",
			"allow the web_search tool — zeta.example.com",
		},
	}
}

func assertRows(t *testing.T, a *App, tab int, want []string) {
	t.Helper()
	got := permissionsRowsOnTab(a)
	if len(got) != len(want) {
		t.Fatalf("tab %d rows = %v, want %v", tab, got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("tab %d row %d = %q, want %q", tab, i, got[i], w)
		}
	}
}

func TestSettingsPicker_TabsAreAlphabetical(t *testing.T) {
	a := New(nil)
	openEntryPicker(a, permissionsUnorderedFixture(), nil, nil)

	for tab, want := range wantUnorderedRowsByTab() {
		if a.settingsPicker.activeTab != tab {
			t.Fatalf("activeTab = %d, want %d", a.settingsPicker.activeTab, tab)
		}
		assertRows(t, a, tab, want)
		a.stepSettingsTab(1)
	}
}

func TestSettingsPicker_SortedRevokeKeepsRowIdentity(t *testing.T) {
	a := New(nil)
	grants := permissionsUnorderedFixture()
	revoke, relist, calls := removingRevoke(&grants)
	openEntryPicker(a, relist(), revoke, relist)

	a.stepSettingsTab(1)
	a.stepSettingsTab(1)
	a.settingsPicker.list.SetCurrentItem(1)
	entry, ok := highlightedEntry(a)
	if !ok {
		t.Fatal("no highlighted grant on the hosts tab")
	}
	if entry.Subject != "web_fetch" || entry.HostScope != "zulu.example.com" {
		t.Fatalf("highlighted host grant = %+v, want web_fetch/zulu.example.com", entry)
	}
	a.applySettingsRevoke(PermissionRow{Entry: entry})

	if len(*calls) != 1 || (*calls)[0].DedupKey() != entry.DedupKey() {
		t.Fatalf("revoke calls = %+v, want one for the highlighted host grant %+v", *calls, entry)
	}
	assertRows(t, a, permTabIndexHosts, []string{
		"allow the web_fetch tool — alpha.example.com",
		"allow the web_search tool — zeta.example.com",
	})
	a.stepSettingsTab(1)
	a.stepSettingsTab(1)
	a.stepSettingsTab(1)
	assertRows(t, a, 0, wantUnorderedRowsByTab()[0])
	a.stepSettingsTab(1)
	assertRows(t, a, permTabIndexFolders, wantUnorderedRowsByTab()[1])
}

func TestSplitPermissionGrants_EqualRowsKeepSourceOrder(t *testing.T) {
	first := permissions.PermissionEntry{Kind: "literal", Subject: "npm test", PathScope: "*", GrantKind: "global", ArgumentHash: "aaa"}
	second := first
	second.ArgumentHash = "bbb"
	global, _, _ := splitPermissionGrants(unlayeredPermissionRows([]permissions.PermissionEntry{first, second}))
	if len(global) != 2 {
		t.Fatalf("global grants = %+v, want both entries", global)
	}
	if global[0].Entry.ArgumentHash != first.ArgumentHash || global[1].Entry.ArgumentHash != second.ArgumentHash {
		t.Errorf("equal-row order = %q,%q, want %q,%q", global[0].Entry.ArgumentHash, global[1].Entry.ArgumentHash, first.ArgumentHash, second.ArgumentHash)
	}
}

func TestSettingsPicker_EmptyHostTabIsPlaceholderAndInert(t *testing.T) {
	a := New(nil)
	fixture := permissionsFixture()
	calls := 0
	openEntryPicker(a, fixture, func(permissions.PermissionEntry) { calls++ }, func() []permissions.PermissionEntry { return fixture })

	a.stepSettingsTab(1)
	a.stepSettingsTab(1)
	if a.settingsPicker.activeTab != permTabIndexHosts {
		t.Fatalf("activeTab = %d, want the hosts tab %d", a.settingsPicker.activeTab, permTabIndexHosts)
	}
	if rows := permissionsRowsOnTab(a); len(rows) != 1 || rows[0] != settingsEmptyRow {
		t.Fatalf("empty hosts tab rows = %v, want just %q", rows, settingsEmptyRow)
	}
	if _, ok := highlightedEntry(a); ok {
		t.Error("placeholder row on the empty hosts tab backs a grant, want none")
	}
	a.showSettingsDelete()
	if a.pages.HasPage(settingsDeletePage) {
		t.Error("revoke confirm shown for the empty hosts tab placeholder")
	}
	if calls != 0 {
		t.Errorf("revoke seam called %d times on an empty hosts tab, want 0", calls)
	}
}

func TestSettingsPicker_RevokeHostRemovesOnlyThatEntry(t *testing.T) {
	a := New(nil)
	grants := permissionsHostFixture()
	revoke, relist, calls := removingRevoke(&grants)
	openEntryPicker(a, relist(), revoke, relist)

	a.stepSettingsTab(1)
	a.stepSettingsTab(1)
	a.settingsPicker.list.SetCurrentItem(0)
	entry, ok := highlightedEntry(a)
	if !ok {
		t.Fatal("no highlighted grant on the hosts tab")
	}
	if entry.Subject != "web_fetch" || entry.HostScope != "docs.example.org" {
		t.Fatalf("highlighted host grant = %+v, want web_fetch/docs.example.org", entry)
	}
	a.applySettingsRevoke(PermissionRow{Entry: entry})

	if len(*calls) != 1 || (*calls)[0].DedupKey() != entry.DedupKey() {
		t.Fatalf("revoke calls = %+v, want one for the highlighted host grant %+v", *calls, entry)
	}
	wantHosts := []string{
		"allow the web_fetch tool — example.com",
		"allow the web_search tool — example.com",
	}
	got := permissionsRowsOnTab(a)
	if len(got) != len(wantHosts) {
		t.Fatalf("hosts rows after revoke = %v, want %v", got, wantHosts)
	}
	for i, w := range wantHosts {
		if got[i] != w {
			t.Errorf("hosts row %d after revoke = %q, want %q", i, got[i], w)
		}
	}
	a.stepSettingsTab(1)
	a.stepSettingsTab(1)
	a.stepSettingsTab(1)
	if rows := permissionsRowsOnTab(a); len(rows) != 2 {
		t.Errorf("global rows after a host revoke = %v, want both path grants kept", rows)
	}
	a.stepSettingsTab(1)
	if rows := permissionsRowsOnTab(a); len(rows) != 2 {
		t.Errorf("folder rows after a host revoke = %v, want both path grants kept", rows)
	}
}

func TestSettingsPicker_HostRevokeSkipKeepsRow(t *testing.T) {
	a := New(nil)
	fixture := permissionsHostFixture()
	calls := 0
	openEntryPicker(a, fixture, func(permissions.PermissionEntry) { calls++ }, func() []permissions.PermissionEntry { return fixture })

	a.stepSettingsTab(1)
	a.stepSettingsTab(1)
	entry, _ := highlightedEntry(a)
	a.applySettingsRevoke(PermissionRow{Entry: entry})

	if calls != 1 {
		t.Fatalf("revoke seam called %d times, want 1", calls)
	}
	if rows := permissionsRowsOnTab(a); len(rows) != 3 {
		t.Fatalf("hosts rows after a skipped revoke = %v, want all three kept", rows)
	}
}

func TestSettingsPicker_TabKeysNavigateBothDirections(t *testing.T) {
	a := New(nil)
	openEntryPicker(a, permissionsUnorderedFixture(), nil, nil)

	for _, tc := range []struct {
		key  tcell.Key
		want int
	}{
		{key: tcell.KeyTab, want: permTabIndexFolders},
		{key: tcell.KeyRight, want: permTabIndexHosts},
		{key: tcell.KeyRight, want: permTabIndexOpenRouter},
		{key: tcell.KeyTab, want: permTabIndexSettings},
		{key: tcell.KeyRight, want: 0},
		{key: tcell.KeyLeft, want: permTabIndexSettings},
		{key: tcell.KeyLeft, want: permTabIndexOpenRouter},
		{key: tcell.KeyLeft, want: permTabIndexHosts},
		{key: tcell.KeyLeft, want: permTabIndexFolders},
		{key: tcell.KeyLeft, want: 0},
	} {
		if ev := a.settingsPickerKeys(tcell.NewEventKey(tc.key, 0, tcell.ModNone)); ev != nil {
			t.Fatalf("key %v reached the list, want it consumed by the picker", tc.key)
		}
		if got := a.settingsPicker.activeTab; got != tc.want {
			t.Fatalf("activeTab after %v = %d, want %d", tc.key, got, tc.want)
		}
		switch tc.want {
		case permTabIndexOpenRouter:
			assertRows(t, a, tc.want, []string{"attribution   on", "data collection   allow", "sort   default", maxPriceDisabledRow})
			continue
		case permTabIndexSettings:
			assertRows(t, a, tc.want, []string{retentionDefaultRow})
			continue
		}
		assertRows(t, a, tc.want, wantUnorderedRowsByTab()[tc.want])
	}
}

func TestSettingsPicker_RevokeKeepsNearestSelection(t *testing.T) {
	for _, tc := range []struct {
		name       string
		tab        int
		start      int
		wantCursor int
		wantRow    string
	}{
		{name: "global middle", tab: 0, start: 1, wantCursor: 0, wantRow: "allow the grep tool — globally"},
		{name: "global first", tab: 0, start: 0, wantCursor: 0, wantRow: "run apt update — globally"},
		{name: "global last", tab: 0, start: 2, wantCursor: 1, wantRow: "run apt update — globally"},
		{name: "folders middle", tab: permTabIndexFolders, start: 1, wantCursor: 0, wantRow: "allow the grep tool — in /home/me/zeta"},
		{name: "hosts first", tab: permTabIndexHosts, start: 0, wantCursor: 0, wantRow: "allow the web_fetch tool — zulu.example.com"},
		{name: "hosts last", tab: permTabIndexHosts, start: 2, wantCursor: 1, wantRow: "allow the web_fetch tool — zulu.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			grants := permissionsUnorderedFixture()
			revoke, relist, calls := removingRevoke(&grants)
			openEntryPicker(a, relist(), revoke, relist)
			for i := 0; i < tc.tab; i++ {
				a.stepSettingsTab(1)
			}
			pp := a.settingsPicker
			pp.list.SetCurrentItem(tc.start)
			entry, ok := highlightedEntry(a)
			if !ok {
				t.Fatalf("no highlighted grant at row %d on tab %d", tc.start, tc.tab)
			}

			a.applySettingsRevoke(PermissionRow{Entry: entry})

			if len(*calls) != 1 || (*calls)[0].DedupKey() != entry.DedupKey() {
				t.Fatalf("revoke calls = %+v, want one for %+v", *calls, entry)
			}
			if got := pp.list.GetCurrentItem(); got != tc.wantCursor {
				t.Fatalf("cursor after revoke = %d, want %d (rows %v)", got, tc.wantCursor, permissionsRowsOnTab(a))
			}
			selected, ok := highlightedEntry(a)
			if !ok {
				t.Fatal("no highlighted grant after revoke")
			}
			if got := renderPermissionEntry(selected); got != tc.wantRow {
				t.Errorf("highlighted grant after revoke = %q, want %q", got, tc.wantRow)
			}
			if row, _ := pp.list.GetItemText(pp.list.GetCurrentItem()); row != tc.wantRow {
				t.Errorf("row under the cursor = %q, want %q (highlighted entry must match the rendered row)", row, tc.wantRow)
			}
		})
	}
}

func TestSettingsPicker_RevokeOnlyRowLeavesInertPlaceholder(t *testing.T) {
	a := New(nil)
	grants := []permissions.PermissionEntry{{Kind: "literal", Subject: "apt update", PathScope: "*", GrantKind: "global"}}
	revoke, relist, calls := removingRevoke(&grants)
	openEntryPicker(a, relist(), revoke, relist)

	entry, ok := highlightedEntry(a)
	if !ok {
		t.Fatal("no highlighted grant on the one-row global tab")
	}
	a.applySettingsRevoke(PermissionRow{Entry: entry})

	if rows := permissionsRowsOnTab(a); len(rows) != 1 || rows[0] != settingsEmptyRow {
		t.Fatalf("rows after revoking the only grant = %v, want just %q", rows, settingsEmptyRow)
	}
	if _, ok := highlightedEntry(a); ok {
		t.Error("placeholder backs a grant after the only row was revoked, want none")
	}
	if a.RevokeHighlightedPermissionForTest() {
		t.Error("placeholder row was revocable, want the revoke refused")
	}
	a.showSettingsDelete()
	if a.pages.HasPage(settingsDeletePage) {
		t.Error("revoke confirm shown for the placeholder row")
	}
	if len(*calls) != 1 {
		t.Errorf("revoke seam called %d times, want 1", len(*calls))
	}
}

func TestSettingsPicker_SkippedRevokeKeepsSelection(t *testing.T) {
	a := New(nil)
	fixture := permissionsUnorderedFixture()
	calls := 0
	openEntryPicker(a, fixture, func(permissions.PermissionEntry) { calls++ }, func() []permissions.PermissionEntry { return fixture })

	pp := a.settingsPicker
	pp.list.SetCurrentItem(2)
	entry, _ := highlightedEntry(a)
	a.applySettingsRevoke(PermissionRow{Entry: entry})

	if calls != 1 {
		t.Fatalf("revoke seam called %d times, want 1", calls)
	}
	if got := pp.list.GetCurrentItem(); got != 2 {
		t.Errorf("cursor after a skipped revoke = %d, want 2 (unchanged)", got)
	}
	selected, ok := highlightedEntry(a)
	if !ok || selected.DedupKey() != entry.DedupKey() {
		t.Errorf("highlighted grant after a skipped revoke = %+v (ok=%v), want %+v", selected, ok, entry)
	}
	if rows := permissionsRowsOnTab(a); len(rows) != 3 {
		t.Errorf("rows after a skipped revoke = %v, want all three kept", rows)
	}
	if a.app.GetFocus() != pp.list {
		t.Error("focus left the permissions list after a skipped revoke")
	}
}

// TestSettingsPicker_NoStyleTagParsing confirms the list does not parse tview style tags,
// so grant subjects/paths containing literal "[tag]" text render exactly as granted.
func TestSettingsPicker_NoStyleTagParsing(t *testing.T) {
	a := New(nil)
	openEntryPicker(a, permissionsFixture(), nil, nil)

	pp := a.settingsPicker
	if pp == nil {
		t.Fatal("settingsPicker nil after open")
	}
	if main, secondary := pp.list.GetUseStyleTags(); main || secondary {
		t.Errorf("GetUseStyleTags() = (%v, %v), want (false, false)", main, secondary)
	}
}

func TestSettingsPicker_BorderTitleIsSettings(t *testing.T) {
	a := New(nil)
	openEntryPicker(a, permissionsFixture(), nil, nil)

	bg, ok := a.pages.GetPage(settingsPickerPage).(*overlayBackground)
	if !ok {
		t.Fatalf("page %q = %T, want *overlayBackground", settingsPickerPage, a.pages.GetPage(settingsPickerPage))
	}
	flex, ok := bg.inner.(*tview.Flex)
	if !ok {
		t.Fatalf("overlay inner = %T, want *tview.Flex", bg.inner)
	}
	if got := flex.GetTitle(); got != " settings " {
		t.Errorf("border title = %q, want %q", got, " settings ")
	}
}

// TestSettingsPicker_EmptyTabShowsPlaceholder confirms a tab with no grants renders the
// placeholder rather than an empty list.
func TestSettingsPicker_EmptyTabShowsPlaceholder(t *testing.T) {
	a := New(nil)
	openEntryPicker(a, nil, nil, nil)
	pp := a.settingsPicker
	if got := pp.list.GetItemCount(); got != 1 {
		t.Fatalf("empty global tab item count = %d, want 1 placeholder", got)
	}
	if s, _ := pp.list.GetItemText(0); s != settingsEmptyRow {
		t.Errorf("placeholder = %q, want %q", s, settingsEmptyRow)
	}
}

// TestSettingsPicker_EscDismissesAndRestoresFocus drives the real app-level ESC capture:
// ESC dismisses the overlay through the central path and returns focus to the input.
func TestSettingsPicker_EscDismissesAndRestoresFocus(t *testing.T) {
	a := New(nil)

	screen := tcell.NewSimulationScreen("UTF-8")
	a.app.SetScreen(screen)
	errc := make(chan error, 1)
	go func() { errc <- a.app.Run() }()

	hasPicker := func() bool {
		open := false
		a.app.QueueUpdate(func() { open = a.pages.HasPage(settingsPickerPage) })
		return open
	}
	waitPicker := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for hasPicker() != want {
			if time.Now().After(deadline) {
				a.app.Stop()
				t.Fatalf("permissions picker page present=%v not reached within 2s", want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	// Focus the input first so the restore target is deterministic, then open the overlay.
	a.app.QueueUpdate(func() {
		a.app.SetFocus(a.input)
		openEntryPicker(a, permissionsFixture(), nil, nil)
	})
	waitPicker(true)

	screen.InjectKey(tcell.KeyEscape, 0, tcell.ModNone)
	waitPicker(false)

	focusInput := make(chan bool, 1)
	a.app.QueueUpdate(func() { focusInput <- a.app.GetFocus() == a.input && !a.anyOverlayOpen() })
	if !<-focusInput {
		a.app.Stop()
		t.Fatal("after ESC: focus not restored to input or overlay still open")
	}

	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}
}

// TestSettingsPicker_RevokeSkipNoticeNoDeadlockOnEventLoop guards the deadlock the
// /settings revoke path is wired to avoid. The confirm's Revoke button runs
// applySettingsRevoke on the tview event-loop goroutine; the revoke seam surfaces its
// skip/failure notice from inside that call. If the seam renders through a background sink
// (NoticeFromBackground → QueueUpdateDraw), the loop blocks waiting on itself and the confirm
// hangs. Production passes the app's on-loop-safe Notice sink instead. This drives the seam's
// skip arm on a live loop and fails via the watchdog if the revoke hangs; it also asserts the
// notice is visible, the row is kept (a skip removes nothing), and focus returns to the list.
func TestSettingsPicker_RevokeSkipNoticeNoDeadlockOnEventLoop(t *testing.T) {
	a := New(nil)
	fixture := permissionsFixture()
	// The list shows the active (global) tab; a skip removes nothing, so its row count is unchanged.
	globalGrants, _, _ := splitPermissionGrants(unlayeredPermissionRows(fixture))
	wantRows := len(globalGrants)
	skipText := RenderRevokeSkipNotice("/home/me/project/.codemeld/settings.yaml", PermissionRow{})
	// Model production RevokeGrant(entry, app)'s skip arm: surface the notice through the
	// on-loop Notice sink and remove nothing (relist unchanged), so the row is kept.
	revoke := func(permissions.PermissionEntry) { a.Notice(skipText) }
	relist := func() []permissions.PermissionEntry { return fixture }

	screen := tcell.NewSimulationScreen("UTF-8")
	a.app.SetScreen(screen)
	errc := make(chan error, 1)
	go func() { errc <- a.app.Run() }()

	opened := make(chan struct{})
	a.app.QueueUpdate(func() {
		a.app.SetFocus(a.input)
		openEntryPicker(a, fixture, revoke, relist)
		close(opened)
	})
	select {
	case <-opened:
	case <-time.After(2 * time.Second):
		a.app.Stop()
		t.Fatal("overlay did not open within 2s")
	}

	type outcome struct {
		notice      string
		rows        int
		focusOnList bool
	}
	// Run the revoke on the loop goroutine, exactly as the confirm's Revoke button does. A
	// deadlocked notice sink never sends on done, so the watchdog fails fast and clearly.
	done := make(chan outcome, 1)
	a.app.QueueUpdate(func() {
		entry, _ := highlightedEntry(a)
		a.applySettingsRevoke(PermissionRow{Entry: entry})
		done <- outcome{
			notice:      a.TranscriptText(),
			rows:        a.settingsPicker.list.GetItemCount(),
			focusOnList: a.app.GetFocus() == a.settingsPicker.list,
		}
	})
	select {
	case out := <-done:
		if !strings.Contains(out.notice, "can't revoke — no matching grant in") {
			t.Errorf("skip notice not surfaced; transcript = %q", out.notice)
		}
		if out.rows != wantRows {
			t.Errorf("rows after a skipped revoke = %d, want %d (nothing removed)", out.rows, wantRows)
		}
		if !out.focusOnList {
			t.Error("focus did not return to the permissions list after revoke")
		}
	case <-time.After(2 * time.Second):
		a.app.Stop()
		t.Fatal("revoke on the event loop hung — the /settings notice sink is not event-loop safe")
	}

	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}
}

// removingRevoke returns a revoke func that drops the entry from the shared grants slice
// (modeling the seam removing it from the live source) and records the calls, plus a relist
// closure over the same slice.
func removingRevoke(grants *[]permissions.PermissionEntry) (func(permissions.PermissionEntry), func() []permissions.PermissionEntry, *[]permissions.PermissionEntry) {
	var calls []permissions.PermissionEntry
	revoke := func(e permissions.PermissionEntry) {
		calls = append(calls, e)
		var next []permissions.PermissionEntry
		for _, g := range *grants {
			if g.DedupKey() != e.DedupKey() {
				next = append(next, g)
			}
		}
		*grants = next
	}
	relist := func() []permissions.PermissionEntry { return *grants }
	return revoke, relist, &calls
}

func globalRows(t *testing.T, a *App) []string {
	t.Helper()
	pp := a.settingsPicker
	get := func(i int) string { s, _ := pp.list.GetItemText(i); return s }
	return listItems(pp.list, get)
}

// TestSettingsPicker_RevokeRefreshesFromLiveList confirms a confirmed revoke calls the
// seam with the highlighted grant and rebuilds the rows from the live list, so the removed
// grant's row disappears while unrelated grants remain.
func TestSettingsPicker_RevokeRefreshesFromLiveList(t *testing.T) {
	a := New(nil)
	grants := permissionsFixture()
	revoke, relist, calls := removingRevoke(&grants)
	openEntryPicker(a, relist(), revoke, relist)

	entry, ok := highlightedEntry(a)
	if !ok {
		t.Fatal("no highlighted grant on the global tab")
	}
	a.applySettingsRevoke(PermissionRow{Entry: entry})

	if len(*calls) != 1 || (*calls)[0].DedupKey() != entry.DedupKey() {
		t.Fatalf("revoke calls = %+v, want one for the highlighted grant %+v", *calls, entry)
	}
	rows := globalRows(t, a)
	if len(rows) != 1 || rows[0] != "allow writing (create + edit) — globally" {
		t.Errorf("global rows after revoke = %v, want just the surviving writing grant", rows)
	}
}

// TestSettingsPicker_RevokeSkipKeepsRow models a seam skip (composed-only/non-writable):
// the seam removes nothing from the live list, so after refresh the row is still present.
func TestSettingsPicker_RevokeSkipKeepsRow(t *testing.T) {
	a := New(nil)
	fixture := permissionsFixture()
	calls := 0
	revoke := func(permissions.PermissionEntry) { calls++ } // seam skips: live list unchanged
	relist := func() []permissions.PermissionEntry { return fixture }
	openEntryPicker(a, fixture, revoke, relist)

	entry, _ := highlightedEntry(a)
	a.applySettingsRevoke(PermissionRow{Entry: entry})

	if calls != 1 {
		t.Fatalf("revoke seam called %d times, want 1", calls)
	}
	if rows := globalRows(t, a); len(rows) != 2 {
		t.Fatalf("global rows after a skipped revoke = %v, want both kept", rows)
	}
}

// TestSettingsPicker_RevokeCancelNoWrite confirms opening the confirm and cancelling it
// performs no revoke, removes no row, and leaves the overlay itself open.
func TestSettingsPicker_RevokeCancelNoWrite(t *testing.T) {
	a := New(nil)
	calls := 0
	revoke := func(permissions.PermissionEntry) { calls++ }
	fixture := permissionsFixture()
	relist := func() []permissions.PermissionEntry { return fixture }
	openEntryPicker(a, fixture, revoke, relist)

	a.showSettingsDelete()
	if !a.pages.HasPage(settingsDeletePage) {
		t.Fatal("revoke confirm not shown after showSettingsDelete")
	}
	a.cancelSettingsDelete()

	if a.pages.HasPage(settingsDeletePage) {
		t.Error("revoke confirm still present after cancel")
	}
	if calls != 0 {
		t.Errorf("cancel performed %d revokes, want 0", calls)
	}
	if !a.settingsPickerOpen {
		t.Error("cancel dismissed the whole overlay, want only the confirm cancelled")
	}
	if n := a.settingsPicker.list.GetItemCount(); n != 2 {
		t.Errorf("rows after cancel = %d, want 2 (nothing removed)", n)
	}
}

func TestSettingsPicker_NoRevokeSeamIsInert(t *testing.T) {
	a := New(nil)
	openEntryPicker(a, permissionsFixture(), nil, nil)
	a.showSettingsDelete()
	if a.pages.HasPage(settingsDeletePage) {
		t.Error("revoke confirm shown with no revoke seam wired, want the overlay read-only")
	}
}

// TestSettingsPicker_DeleteConfirmOwnsEsc drives the real app-level ESC capture: r opens
// the confirm, the first ESC cancels only the confirm (the overlay stays open), and the
// second ESC dismisses the overlay and restores input focus — no revoke fires on either ESC.
func TestSettingsPicker_DeleteConfirmOwnsEsc(t *testing.T) {
	a := New(nil)
	calls := 0
	revoke := func(permissions.PermissionEntry) { calls++ }
	fixture := permissionsFixture()
	relist := func() []permissions.PermissionEntry { return fixture }

	screen := tcell.NewSimulationScreen("UTF-8")
	a.app.SetScreen(screen)
	errc := make(chan error, 1)
	go func() { errc <- a.app.Run() }()

	hasPage := func(name string) bool {
		open := false
		a.app.QueueUpdate(func() { open = a.pages.HasPage(name) })
		return open
	}
	waitPage := func(name string, want bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for hasPage(name) != want {
			if time.Now().After(deadline) {
				a.app.Stop()
				t.Fatalf("page %q present=%v not reached within 2s", name, want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	a.app.QueueUpdate(func() {
		a.app.SetFocus(a.input)
		openEntryPicker(a, fixture, revoke, relist)
	})
	waitPage(settingsPickerPage, true)

	screen.InjectKey(tcell.KeyRune, 'r', tcell.ModNone)
	waitPage(settingsDeletePage, true)

	// First ESC: cancels only the confirm; the overlay is still up.
	screen.InjectKey(tcell.KeyEscape, 0, tcell.ModNone)
	waitPage(settingsDeletePage, false)
	if !hasPage(settingsPickerPage) {
		a.app.Stop()
		t.Fatal("first ESC dismissed the whole overlay, want only the confirm cancelled")
	}

	// Second ESC: dismisses the overlay and restores input focus.
	screen.InjectKey(tcell.KeyEscape, 0, tcell.ModNone)
	waitPage(settingsPickerPage, false)

	done := make(chan bool, 1)
	a.app.QueueUpdate(func() { done <- a.app.GetFocus() == a.input && calls == 0 })
	if !<-done {
		a.app.Stop()
		t.Fatal("after ESC-ESC: focus not restored to input, or a revoke fired")
	}
	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}
}

// TestSettingsPicker_RevokeConfirmButtonRevokes drives the real key path end to end: r
// opens the confirm, Enter activates the default Revoke button, the seam is called for the
// highlighted grant, and its row is gone after the refresh.
func TestSettingsPicker_RevokeConfirmButtonRevokes(t *testing.T) {
	a := New(nil)
	grants := permissionsFixture()
	revoke, relist, calls := removingRevoke(&grants)

	screen := tcell.NewSimulationScreen("UTF-8")
	a.app.SetScreen(screen)
	errc := make(chan error, 1)
	go func() { errc <- a.app.Run() }()

	hasPage := func(name string) bool {
		open := false
		a.app.QueueUpdate(func() { open = a.pages.HasPage(name) })
		return open
	}
	waitPage := func(name string, want bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for hasPage(name) != want {
			if time.Now().After(deadline) {
				a.app.Stop()
				t.Fatalf("page %q present=%v not reached within 2s", name, want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	a.app.QueueUpdate(func() {
		a.app.SetFocus(a.input)
		openEntryPicker(a, relist(), revoke, relist)
	})
	waitPage(settingsPickerPage, true)

	screen.InjectKey(tcell.KeyRune, 'r', tcell.ModNone)
	waitPage(settingsDeletePage, true)
	// Enter activates the focused (first) button, "Revoke".
	screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	waitPage(settingsDeletePage, false)

	done := make(chan bool, 1)
	a.app.QueueUpdate(func() {
		removed := true
		for i := 0; i < a.settingsPicker.list.GetItemCount(); i++ {
			if s, _ := a.settingsPicker.list.GetItemText(i); strings.Contains(s, "grep") {
				removed = false
			}
		}
		done <- len(*calls) == 1 && removed
	})
	if !<-done {
		a.app.Stop()
		t.Fatalf("Revoke button did not call the seam once and remove the row (calls=%v)", *calls)
	}
	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}
}

// TestSettingsPicker_RevokeConfirmArrowSelectsCancel pins the arrow→button key routing that
// makes the confirmation navigable in a real terminal: the modal opens focused on the default
// "Revoke", → moves the selection to "Cancel", and Enter then activates Cancel — so no revoke
// fires, the highlighted row stays, and the overlay remains open. Without permissionsDeleteKeys
// the arrow is inert, Enter would activate Revoke, and this fails. (The reverse-video highlight
// itself is a visual property left to the required real-terminal gate.)
func TestSettingsPicker_RevokeConfirmArrowSelectsCancel(t *testing.T) {
	a := New(nil)
	grants := permissionsFixture()
	revoke, relist, calls := removingRevoke(&grants)

	screen := tcell.NewSimulationScreen("UTF-8")
	a.app.SetScreen(screen)
	errc := make(chan error, 1)
	go func() { errc <- a.app.Run() }()

	hasPage := func(name string) bool {
		open := false
		a.app.QueueUpdate(func() { open = a.pages.HasPage(name) })
		return open
	}
	waitPage := func(name string, want bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for hasPage(name) != want {
			if time.Now().After(deadline) {
				a.app.Stop()
				t.Fatalf("page %q present=%v not reached within 2s", name, want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	a.app.QueueUpdate(func() {
		a.app.SetFocus(a.input)
		openEntryPicker(a, relist(), revoke, relist)
	})
	waitPage(settingsPickerPage, true)

	screen.InjectKey(tcell.KeyRune, 'r', tcell.ModNone)
	waitPage(settingsDeletePage, true)
	// → moves the selection from Revoke to Cancel; Enter then activates the now-focused Cancel.
	screen.InjectKey(tcell.KeyRight, 0, tcell.ModNone)
	screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	waitPage(settingsDeletePage, false)

	done := make(chan bool, 1)
	a.app.QueueUpdate(func() {
		done <- len(*calls) == 0 && a.settingsPickerOpen && a.settingsPicker.list.GetItemCount() == 2
	})
	if !<-done {
		a.app.Stop()
		t.Fatalf("arrow did not move selection to Cancel: revoke fired or overlay/rows changed (calls=%v)", *calls)
	}
	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}
}

func TestSettingsPicker_DismissRemovesConfirmChildBeforeRestoringFocus(t *testing.T) {
	a := New(nil)
	captured := tview.NewBox()
	a.app.SetFocus(captured)

	grants := permissionsFixture()
	revoke, relist, _ := removingRevoke(&grants)
	openEntryPicker(a, relist(), revoke, relist)
	a.showSettingsDelete()
	if !a.pages.HasPage(settingsDeletePage) {
		t.Fatal("revoke confirmation not mounted; the teardown ordering is untested")
	}

	a.dismissSettingsPicker()

	if a.pages.HasPage(settingsDeletePage) {
		t.Error("revoke confirmation still mounted after dismissal")
	}
	if a.pages.HasPage(settingsPickerPage) {
		t.Error("permissions overlay still mounted after dismissal")
	}
	if a.app.GetFocus() != captured {
		t.Errorf("focus = %T, want the primitive captured at open", a.app.GetFocus())
	}
	if a.settingsPickerOpen || a.settingsPicker != nil || a.settingsPickerPrev != nil {
		t.Error("per-open picker state not cleared by dismissal")
	}

	other := tview.NewBox()
	a.app.SetFocus(other)
	a.dismissSettingsPicker()
	if a.app.GetFocus() != other {
		t.Errorf("repeated dismissal moved focus to %T; it must be inert", a.app.GetFocus())
	}
}

func TestSettingsPicker_DismissWithNoCapturedFocusFallsBackToInput(t *testing.T) {
	a := New(nil)
	openEntryPicker(a, permissionsFixture(), nil, nil)
	a.settingsPickerPrev = nil

	a.dismissSettingsPicker()

	if a.app.GetFocus() != a.input {
		t.Errorf("focus = %T, want the input area when nothing was captured", a.app.GetFocus())
	}
}

type fakeOpenRouterSettings struct {
	on                          bool
	dc, sort                    string
	activeProvider, activeModel string
	prices                      map[string]provider.MaxPrice
	err                         error
	wrote                       []string
	estimate                    func(model, sortMode string, fetched func()) (provider.OpenRouterEstimate, bool)
}

const (
	maxPriceDisabledRow = "max price   active model is not an OpenRouter model"
	retentionDefaultRow = "session retention (days)   default"
)

func maxPriceWrite(model string, p provider.MaxPrice) string {
	return fmt.Sprintf("max_price[%s]=%+v", model, p)
}

func (f *fakeOpenRouterSettings) record(write string, apply func()) error {
	f.wrote = append(f.wrote, write)
	if f.err != nil {
		return f.err
	}
	apply()
	return nil
}

func (f *fakeOpenRouterSettings) seam() OpenRouterSettings {
	return OpenRouterSettings{
		Attribution: func() bool { return f.on },
		SetAttribution: func(v bool) error {
			return f.record(fmt.Sprintf("attribution=%t", v), func() { f.on = v })
		},
		DataCollection: func() string { return f.dc },
		SetDataCollection: func(v string) error {
			return f.record("data_collection="+v, func() { f.dc = v })
		},
		Sort: func() string { return f.sort },
		SetSort: func(v string) error {
			return f.record("sort="+v, func() { f.sort = v })
		},
		MaxPrice: func(model string) (provider.MaxPrice, bool) {
			p, ok := f.prices[model]
			return p, ok
		},
		SetMaxPrice: func(model string, p provider.MaxPrice) error {
			return f.record(maxPriceWrite(model, p), func() {
				if !p.HasPrompt && !p.HasCompletion {
					delete(f.prices, model)
					return
				}
				if f.prices == nil {
					f.prices = map[string]provider.MaxPrice{}
				}
				f.prices[model] = p
			})
		},
		ActiveModel:  func() (string, string) { return f.activeProvider, f.activeModel },
		SortEstimate: f.estimate,
	}
}

func openSettingsTab(a *App, f *fakeOpenRouterSettings) {
	if f != nil {
		a.openRouterSettings = f.seam()
	}
	openEntryPicker(a, permissionsFixture(), nil, nil)
	a.settingsPicker.activeTab = permTabIndexOpenRouter
	a.renderSettingsTab()
}

func pressEnter(t *testing.T, a *App) {
	t.Helper()
	if ev := a.settingsPickerKeys(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)); ev != nil {
		t.Fatal("Enter reached the list, want it consumed by the settings tab")
	}
}

func pressEnterOnRow(t *testing.T, a *App, row int) {
	t.Helper()
	a.settingsPicker.list.SetCurrentItem(row)
	pressEnter(t, a)
	if got := a.settingsPicker.list.GetCurrentItem(); got != row {
		t.Fatalf("cursor after Enter on row %d = %d, want it to stay on the acted row", row, got)
	}
}

func TestSettingsPicker_SettingsTabShowsLiveValues(t *testing.T) {
	for _, tc := range []struct {
		fake fakeOpenRouterSettings
		want []string
	}{
		{
			fake: fakeOpenRouterSettings{on: true, dc: "allow", sort: "default"},
			want: []string{"attribution   on", "data collection   allow", "sort   default", maxPriceDisabledRow},
		},
		{
			fake: fakeOpenRouterSettings{on: false, dc: "deny", sort: "latency"},
			want: []string{"attribution   off", "data collection   deny", "sort   latency", maxPriceDisabledRow},
		},
	} {
		a := New(nil)
		openSettingsTab(a, &tc.fake)
		assertRows(t, a, permTabIndexOpenRouter, tc.want)
	}
}

func TestSettingsPicker_SettingsTabWithoutSeamShowsDefaultsAndIsInert(t *testing.T) {
	a := New(nil)
	openSettingsTab(a, nil)
	want := []string{"attribution   on", "data collection   allow", "sort   default", maxPriceDisabledRow}
	assertRows(t, a, permTabIndexOpenRouter, want)

	for row := range want {
		pressEnterOnRow(t, a, row)
	}
	assertRows(t, a, permTabIndexOpenRouter, want)
	if a.NoticeText() != "" {
		t.Errorf("notice = %q, want none for an inert toggle", a.NoticeText())
	}
}

func TestSettingsPicker_EnterActsOnlyOnHighlightedRow(t *testing.T) {
	for row, want := range []string{"attribution=false", "data_collection=deny", "sort=throughput"} {
		a := New(nil)
		f := &fakeOpenRouterSettings{on: true, dc: "allow", sort: "default"}
		openSettingsTab(a, f)
		pressEnterOnRow(t, a, row)
		if len(f.wrote) != 1 || f.wrote[0] != want {
			t.Errorf("Enter on row %d wrote %v, want only %q", row, f.wrote, want)
		}
	}
}

func TestSettingsPicker_EnterTogglesAttributionThroughTheSeam(t *testing.T) {
	a := New(nil)
	f := &fakeOpenRouterSettings{on: true, dc: "allow", sort: "default"}
	openSettingsTab(a, f)

	pressEnter(t, a)
	if rows := permissionsRowsOnTab(a); rows[0] != "attribution   off" {
		t.Errorf("row after opting out = %q, want it off", rows[0])
	}
	if a.NoticeText() != "" {
		t.Errorf("notice = %q, want none on a successful toggle", a.NoticeText())
	}

	pressEnter(t, a)
	if rows := permissionsRowsOnTab(a); rows[0] != "attribution   on" {
		t.Errorf("row after opting back in = %q, want it on", rows[0])
	}
	if want := []string{"attribution=false", "attribution=true"}; !slices.Equal(f.wrote, want) {
		t.Fatalf("writes = %v, want %v", f.wrote, want)
	}

	for _, tab := range []int{0, permTabIndexFolders, permTabIndexHosts} {
		a.settingsPicker.activeTab = tab
		a.renderSettingsTab()
		if ev := a.settingsPickerKeys(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)); ev == nil {
			t.Errorf("Enter consumed on grant tab %d, want it to reach the list", tab)
		}
	}
	if len(f.wrote) != 2 {
		t.Errorf("writes = %v, want Enter on a grant tab to write nothing", f.wrote)
	}
}

func TestSettingsPicker_DataCollectionFlipsAndWritesExplicitAllow(t *testing.T) {
	a := New(nil)
	f := &fakeOpenRouterSettings{on: true, dc: "allow", sort: "default"}
	openSettingsTab(a, f)

	for _, want := range []string{"deny", "allow"} {
		pressEnterOnRow(t, a, settingsRowDataCollection)
		if rows := permissionsRowsOnTab(a); rows[settingsRowDataCollection] != "data collection   "+want {
			t.Errorf("data collection row = %q, want %q", rows[settingsRowDataCollection], want)
		}
	}
	if want := []string{"data_collection=deny", "data_collection=allow"}; !slices.Equal(f.wrote, want) {
		t.Fatalf("writes = %v, want %v", f.wrote, want)
	}
}

func TestSettingsPicker_SortCyclesBackToDefault(t *testing.T) {
	a := New(nil)
	f := &fakeOpenRouterSettings{on: true, dc: "allow", sort: "default"}
	openSettingsTab(a, f)

	for _, want := range []struct{ row, help string }{
		{"throughput", sortHelpThroughput},
		{"best value", sortHelpBestValue},
		{"default", sortHelpDefault},
	} {
		pressEnterOnRow(t, a, settingsRowSort)
		if rows := permissionsRowsOnTab(a); rows[settingsRowSort] != "sort   "+want.row {
			t.Errorf("sort row = %q, want %q", rows[settingsRowSort], want.row)
		}
		if got := permissionsHelp(a); got != want.help {
			t.Errorf("help after Enter to %s = %q, want %q", want.row, got, want.help)
		}
	}
	if want := []string{"sort=throughput", "sort=best_value", "sort=default"}; !slices.Equal(f.wrote, want) {
		t.Fatalf("writes = %v, want %v", f.wrote, want)
	}
}

const (
	sortHelpDefault    = "OpenRouter's normal routing: healthy providers, cheaper ones picked more often"
	sortHelpThroughput = "Fastest providers first, whatever the price"
	sortHelpBestValue  = "Fastest at typical speed or better, within 20% of the cheapest at that speed"
	sortHelpOther      = "Set in the settings file; Enter switches to default"
)

func permissionsHelp(a *App) string {
	return a.settingsPicker.help.GetText(false)
}

func TestSettingsPicker_SortRowShowsEachModeWithItsHelp(t *testing.T) {
	for _, tc := range []struct{ stored, row, help string }{
		{"default", "default", sortHelpDefault},
		{"throughput", "throughput", sortHelpThroughput},
		{"best_value", "best value", sortHelpBestValue},
		{"latency", "latency", sortHelpOther},
	} {
		a := New(nil)
		openSettingsTab(a, &fakeOpenRouterSettings{on: true, dc: "allow", sort: tc.stored})
		a.settingsPicker.list.SetCurrentItem(settingsRowSort)
		if rows := permissionsRowsOnTab(a); rows[settingsRowSort] != "sort   "+tc.row {
			t.Errorf("stored %s: sort row = %q, want %q", tc.stored, rows[settingsRowSort], tc.row)
		}
		if got := permissionsHelp(a); got != tc.help {
			t.Errorf("stored %s: help = %q, want %q", tc.stored, got, tc.help)
		}
	}
}

func TestSettingsPicker_HandSetLatencySortEnterGoesToDefault(t *testing.T) {
	a := New(nil)
	f := &fakeOpenRouterSettings{on: true, dc: "allow", sort: "latency"}
	openSettingsTab(a, f)

	pressEnterOnRow(t, a, settingsRowSort)

	if rows := permissionsRowsOnTab(a); rows[settingsRowSort] != "sort   default" {
		t.Errorf("sort row = %q, want default", rows[settingsRowSort])
	}
	if got := permissionsHelp(a); got != sortHelpDefault {
		t.Errorf("help = %q, want %q", got, sortHelpDefault)
	}
	if want := []string{"sort=default"}; !slices.Equal(f.wrote, want) {
		t.Fatalf("writes = %v, want %v", f.wrote, want)
	}
}

func TestSettingsPicker_HelpOnlyOnTheOpenRouterAndSettingsTabs(t *testing.T) {
	a := New(nil)
	a.openRouterSettings = (&fakeOpenRouterSettings{on: true, dc: "allow", sort: "throughput"}).seam()
	openEntryPicker(a, permissionsUnorderedFixture(), nil, nil)
	moveCursor := func(key tcell.Key) {
		a.settingsPicker.list.InputHandler()(tcell.NewEventKey(key, 0, tcell.ModNone), func(tview.Primitive) {})
	}
	want := func(tab, row int) string {
		if id, ok := settingsRowID(tab, row); ok {
			return rowHelpWant(id, sortHelpThroughput)
		}
		return ""
	}

	for tab := range permTabCount {
		if got := a.settingsPicker.activeTab; got != tab {
			t.Fatalf("activeTab = %d, want %d", got, tab)
		}
		for _, key := range []tcell.Key{tcell.KeyDown, tcell.KeyDown, tcell.KeyDown, tcell.KeyUp} {
			moveCursor(key)
			row := a.settingsPicker.list.GetCurrentItem()
			if got, w := permissionsHelp(a), want(tab, row); got != w {
				t.Errorf("help on tab %d row %d = %q, want %q", tab, row, got, w)
			}
		}
		if tab == permTabIndexOpenRouter && a.settingsPicker.list.GetCurrentItem() != settingsRowSort {
			t.Fatalf("openrouter cursor = %d, want the walk to end on the sort row", a.settingsPicker.list.GetCurrentItem())
		}
		a.settingsPickerKeys(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone))
		next := a.settingsPicker.activeTab
		if got, w := permissionsHelp(a), want(next, a.settingsPicker.list.GetCurrentItem()); got != w {
			t.Errorf("help after switching from tab %d to %d = %q, want %q", tab, next, got, w)
		}
	}
}

const (
	helpAttribution    = "Identify codemeld to OpenRouter on chat requests (app URL, name, categories)"
	helpDataCollection = "allow: may use providers that store or train on prompts; deny: avoid them"
	helpMaxPrice       = "Input/output price caps per M tokens for OpenRouter models; empty: no cap"
	helpRetention      = "Idle days before auto-deletion; pruning runs at a fresh launch, not on resume"
)

func rowHelpWant(id int, sortText string) string {
	return map[int]string{
		settingsRowAttribution:    helpAttribution,
		settingsRowDataCollection: helpDataCollection,
		settingsRowSort:           sortText,
		settingsRowMaxPrice:       helpMaxPrice,
		settingsRowRetention:      helpRetention,
	}[id]
}

var sortHelpVariants = []struct{ stored, help string }{
	{"default", sortHelpDefault},
	{"throughput", sortHelpThroughput},
	{"best_value", sortHelpBestValue},
	{"latency", sortHelpOther},
}

func openSettingsPickerOnTab(a *App, sort string, tab int) {
	NewSettingsPicker(a, (&fakeOpenRouterSettings{on: true, dc: "allow", sort: sort}).seam(), (&fakeRetention{days: 30}).seam()).
		Present(unlayeredPermissionRows(permissionsFixture()), SettingsDeps{})
	a.settingsPicker.activeTab = tab
	a.renderSettingsTab()
}

func TestSettingsPicker_EveryListedSettingsRowHasHelp(t *testing.T) {
	for _, tab := range []int{permTabIndexOpenRouter, permTabIndexSettings} {
		a := New(nil)
		openSettingsPickerOnTab(a, "default", tab)
		n := a.settingsPicker.list.GetItemCount()
		if n == 0 {
			t.Fatalf("tab %d lists no rows", tab)
		}
		for i := range n {
			a.settingsPicker.list.SetCurrentItem(i)
			a.updateRowHelp(i)
			if got := permissionsHelp(a); got == "" {
				t.Errorf("tab %d row %d: help is empty", tab, i)
			}
		}
	}
}

func TestSettingsPicker_RowHelpWording(t *testing.T) {
	type place struct{ tab, row int }
	type helpCase struct {
		sort string
		at   place
		want string
	}
	cases := []helpCase{
		{"default", place{permTabIndexOpenRouter, 0}, helpAttribution},
		{"default", place{permTabIndexOpenRouter, 1}, helpDataCollection},
		{"default", place{permTabIndexOpenRouter, 3}, helpMaxPrice},
		{"default", place{permTabIndexSettings, 0}, helpRetention},
	}
	for _, v := range sortHelpVariants {
		cases = append(cases, helpCase{v.stored, place{permTabIndexOpenRouter, 2}, v.help})
	}
	shown := map[place]string{}
	for _, tc := range cases {
		a := New(nil)
		openSettingsPickerOnTab(a, tc.sort, tc.at.tab)
		a.settingsPicker.list.SetCurrentItem(tc.at.row)
		a.updateRowHelp(tc.at.row)
		got := permissionsHelp(a)
		if got != tc.want {
			t.Errorf("sort %s, tab %d row %d: help = %q, want %q", tc.sort, tc.at.tab, tc.at.row, got, tc.want)
		}
		shown[tc.at] = got
	}
	if or, st := shown[place{permTabIndexOpenRouter, 0}], shown[place{permTabIndexSettings, 0}]; or == st {
		t.Errorf("openrouter row 0 and settings row 0 both show help %q, want each its own", or)
	}
}

func TestSettingsPicker_MaxPriceHelpIsTheSameWithOrWithoutAnOpenRouterModel(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*App)
	}{
		{"active openrouter model", func(a *App) {
			a.openRouterSettings = maxPriceSettings(nil).seam()
		}},
		{"no active model seam", func(a *App) {
			a.openRouterSettings = maxPriceSettings(nil).seam()
			a.openRouterSettings.ActiveModel = nil
		}},
		{"empty active model", func(a *App) {
			a.openRouterSettings = (&fakeOpenRouterSettings{on: true, dc: "allow", sort: "default"}).seam()
		}},
		{"non-openrouter provider", func(a *App) {
			a.openRouterSettings = (&fakeOpenRouterSettings{on: true, dc: "allow", sort: "default", activeProvider: "anthropic", activeModel: "claude"}).seam()
		}},
	} {
		a := New(nil)
		tc.setup(a)
		openEntryPicker(a, permissionsFixture(), nil, nil)
		a.settingsPicker.activeTab = permTabIndexOpenRouter
		a.renderSettingsTab()
		_, i := settingsRowPlace(settingsRowMaxPrice)
		a.settingsPicker.list.SetCurrentItem(i)
		a.updateRowHelp(i)
		if got := permissionsHelp(a); got != helpMaxPrice {
			t.Errorf("%s: max price help = %q, want %q", tc.name, got, helpMaxPrice)
		}
	}
}

func TestSettingsPicker_RowHelpFitsTheHelpRowOfAnEightyColumnOverlay(t *testing.T) {
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatal(err)
	}
	screen.SetSize(80, 24)
	check := func(sort string, id int, want string) {
		t.Helper()
		tab, i := settingsRowPlace(id)
		a := New(nil)
		openSettingsPickerOnTab(a, sort, tab)
		a.settingsPicker.list.SetCurrentItem(i)
		a.updateRowHelp(i)
		a.pages.SetRect(0, 0, 80, 24)
		a.pages.Draw(screen)
		screen.Show()
		rows := screenRows(screen)
		help := []rune(rows[21])
		if got := strings.TrimRight(string(help[1:79]), " "); got != want {
			t.Errorf("sort %s, row %d: help row = %q, want the whole help %q", sort, id, string(help), want)
		}
	}
	for _, id := range []int{settingsRowAttribution, settingsRowDataCollection, settingsRowMaxPrice, settingsRowRetention} {
		check("default", id, rowHelpWant(id, ""))
	}
	for _, v := range sortHelpVariants {
		check(v.stored, settingsRowSort, v.help)
	}
}

func TestSettingsPicker_FailedSettingWriteKeepsRowsAndNotifies(t *testing.T) {
	stored := []string{"attribution   on", "data collection   allow", "sort   default", maxPriceDisabledRow}
	for row, label := range []string{"attribution", "data collection", "sort"} {
		a := New(nil)
		f := &fakeOpenRouterSettings{on: true, dc: "allow", sort: "default", err: errors.New("write_error: no\nspace left")}
		openSettingsTab(a, f)

		pressEnterOnRow(t, a, row)

		if len(f.wrote) != 1 {
			t.Fatalf("row %d writes = %v, want exactly one attempt", row, f.wrote)
		}
		assertRows(t, a, permTabIndexOpenRouter, stored)
		if want := "couldn't change the openrouter " + label + " setting: write_error: no space left"; a.NoticeText() != want {
			t.Errorf("notice = %q, want %q", a.NoticeText(), want)
		}
	}
}

func TestSettingsPicker_RevokeAndShareKeysAreInertOnNonGrantTabs(t *testing.T) {
	for _, tab := range []int{permTabIndexOpenRouter, permTabIndexSettings} {
		for _, key := range []rune{'r', 's'} {
			var revoked, shared []PermissionRow
			a := New(nil)
			a.openRouterSettings = (&fakeOpenRouterSettings{on: true, dc: "allow", sort: "default"}).seam()
			a.openSettingsPicker(layeredRowsFixture(), SettingsDeps{
				Rows:     layeredRowsFixture,
				Revoke:   func(row PermissionRow) { revoked = append(revoked, row) },
				Share:    func(row PermissionRow) ShareResult { shared = append(shared, row); return ShareResult{} },
				Approved: true,
			}, SessionSettings{})
			a.settingsPicker.activeTab = tab
			a.renderSettingsTab()

			if ev := a.settingsPickerKeys(tcell.NewEventKey(tcell.KeyRune, key, tcell.ModNone)); ev != nil {
				t.Fatalf("tab %d: %c reached the list, want the picker to consume it", tab, key)
			}
			if a.pages.HasPage(settingsDeletePage) {
				t.Errorf("tab %d: %c opened a confirmation", tab, key)
			}
			if len(revoked) != 0 || len(shared) != 0 {
				t.Errorf("tab %d: %c called revoke %v / share %v", tab, key, revoked, shared)
			}
		}
	}
}

const maxPriceModelID = "meta-llama/llama-3.3-70b-instruct:free"

func maxPriceSettings(prices map[string]provider.MaxPrice) *fakeOpenRouterSettings {
	return &fakeOpenRouterSettings{on: true, dc: "allow", sort: "default", activeProvider: "openrouter", activeModel: maxPriceModelID, prices: prices}
}

func openMaxPriceEditor(t *testing.T, a *App) *maxPriceEditor {
	t.Helper()
	pressEnterOnRow(t, a, settingsRowMaxPrice)
	if !a.pages.HasPage(settingsDeletePage) || a.settingsPicker.maxPrice == nil {
		t.Fatal("Enter on the max price row opened no editor")
	}
	return a.settingsPicker.maxPrice
}

func sendFieldKey(a *App, field *tview.InputField, key tcell.Key) {
	field.InputHandler()(tcell.NewEventKey(key, 0, tcell.ModNone), func(p tview.Primitive) { a.app.SetFocus(p) })
}

func maxPriceRow(t *testing.T, a *App) string {
	t.Helper()
	return permissionsRowsOnTab(a)[settingsRowMaxPrice]
}

func TestSettingsPicker_MaxPriceRowShowsActiveModelCaps(t *testing.T) {
	const label = "max price (" + maxPriceModelID + ")   "
	for _, tc := range []struct {
		name   string
		prices map[string]provider.MaxPrice
		want   string
	}{
		{"both caps", map[string]provider.MaxPrice{maxPriceModelID: {Prompt: 1.5, Completion: 2, HasPrompt: true, HasCompletion: true}}, label + "input $1.5 / output $2 per M tokens"},
		{"prompt cap only", map[string]provider.MaxPrice{maxPriceModelID: {Prompt: 0.25, HasPrompt: true}}, label + "input $0.25 / output none per M tokens"},
		{"completion cap only", map[string]provider.MaxPrice{maxPriceModelID: {Completion: 0.0000001, HasCompletion: true}}, label + "input none / output $0.0000001 per M tokens"},
		{"no caps", map[string]provider.MaxPrice{"openai/gpt-4.1": {Prompt: 1, HasPrompt: true}}, label + "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			openSettingsTab(a, maxPriceSettings(tc.prices))
			if got := maxPriceRow(t, a); got != tc.want {
				t.Errorf("max price row = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSettingsPicker_MaxPriceRowIsInertWithoutAnOpenRouterModel(t *testing.T) {
	for _, tc := range []struct {
		name, provider, model string
	}{
		{"another provider", "venice", "llama-3.3-70b"},
		{"no selection", "", ""},
		{"empty provider id", "", maxPriceModelID},
		{"empty model id", "openrouter", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			f := maxPriceSettings(map[string]provider.MaxPrice{maxPriceModelID: {Prompt: 1, HasPrompt: true}})
			f.activeProvider, f.activeModel = tc.provider, tc.model
			openSettingsTab(a, f)
			if got := maxPriceRow(t, a); got != maxPriceDisabledRow {
				t.Errorf("max price row = %q, want %q", got, maxPriceDisabledRow)
			}
			pressEnterOnRow(t, a, settingsRowMaxPrice)
			if a.pages.HasPage(settingsDeletePage) {
				t.Error("Enter opened the max price editor for a non-OpenRouter model")
			}
			if len(f.wrote) != 0 {
				t.Errorf("writes = %v, want none", f.wrote)
			}
		})
	}
}

func TestSettingsPicker_MaxPriceEditorSubmitWritesParsedValues(t *testing.T) {
	a := New(nil)
	f := maxPriceSettings(map[string]provider.MaxPrice{maxPriceModelID: {Prompt: 1, HasPrompt: true}})
	openSettingsTab(a, f)

	ed := openMaxPriceEditor(t, a)
	if ed.prompt.GetLabel() != "input  $ " || ed.completion.GetLabel() != "output $ " {
		t.Fatalf("editor labels = %q/%q, want %q/%q", ed.prompt.GetLabel(), ed.completion.GetLabel(), "input  $ ", "output $ ")
	}
	if ed.prompt.GetText() != "1" || ed.completion.GetText() != "" {
		t.Fatalf("editor fields = %q/%q, want the current values 1 and empty", ed.prompt.GetText(), ed.completion.GetText())
	}
	if a.app.GetFocus() != ed.prompt {
		t.Fatalf("focus = %T, want the prompt field", a.app.GetFocus())
	}
	for _, step := range []struct {
		key  tcell.Key
		from *tview.InputField
		want *tview.InputField
	}{
		{tcell.KeyTab, ed.prompt, ed.completion},
		{tcell.KeyUp, ed.completion, ed.prompt},
		{tcell.KeyDown, ed.prompt, ed.completion},
	} {
		sendFieldKey(a, step.from, step.key)
		if a.app.GetFocus() != step.want {
			t.Fatalf("focus after key %v = %T, want the other field", step.key, a.app.GetFocus())
		}
	}

	ed.prompt.SetText(" 0.5 ")
	ed.completion.SetText("2")
	sendFieldKey(a, ed.completion, tcell.KeyEnter)

	want := provider.MaxPrice{Prompt: 0.5, Completion: 2, HasPrompt: true, HasCompletion: true}
	if !slices.Equal(f.wrote, []string{maxPriceWrite(maxPriceModelID, want)}) {
		t.Fatalf("writes = %v, want one write of %+v", f.wrote, want)
	}
	if a.pages.HasPage(settingsDeletePage) || !a.pages.HasPage(settingsPickerPage) {
		t.Fatal("submit did not close only the editor")
	}
	if a.app.GetFocus() != a.settingsPicker.list || a.settingsPicker.list.GetCurrentItem() != settingsRowMaxPrice {
		t.Fatal("submit did not return focus to the max price row")
	}
	if got, wantRow := maxPriceRow(t, a), "max price ("+maxPriceModelID+")   input $0.5 / output $2 per M tokens"; got != wantRow {
		t.Errorf("max price row = %q, want %q", got, wantRow)
	}
	if a.NoticeText() != "" {
		t.Errorf("notice = %q, want none on a successful write", a.NoticeText())
	}
}

func TestSettingsPicker_MaxPriceEditorBothEmptyRemovesTheCap(t *testing.T) {
	a := New(nil)
	f := maxPriceSettings(map[string]provider.MaxPrice{maxPriceModelID: {Prompt: 1, Completion: 2, HasPrompt: true, HasCompletion: true}})
	openSettingsTab(a, f)

	ed := openMaxPriceEditor(t, a)
	ed.prompt.SetText("")
	ed.completion.SetText("  ")
	sendFieldKey(a, ed.prompt, tcell.KeyEnter)

	if !slices.Equal(f.wrote, []string{maxPriceWrite(maxPriceModelID, provider.MaxPrice{})}) {
		t.Fatalf("writes = %v, want one removal", f.wrote)
	}
	if got, want := maxPriceRow(t, a), "max price ("+maxPriceModelID+")   none"; got != want {
		t.Errorf("max price row = %q, want %q", got, want)
	}
}

func TestSettingsPicker_MaxPriceEditorRejectsInvalidInput(t *testing.T) {
	stored := "max price (" + maxPriceModelID + ")   input $1 / output none per M tokens"
	for _, tc := range []struct{ prompt, completion, notice string }{
		{"abc", "", `couldn't change the openrouter max price setting: input "abc" is not a number of at least 0`},
		{"1", "-0.5", `couldn't change the openrouter max price setting: output "-0.5" is not a number of at least 0`},
		{"NaN", "", `couldn't change the openrouter max price setting: input "NaN" is not a number of at least 0`},
		{"1", "+Inf", `couldn't change the openrouter max price setting: output "+Inf" is not a number of at least 0`},
	} {
		a := New(nil)
		f := maxPriceSettings(map[string]provider.MaxPrice{maxPriceModelID: {Prompt: 1, HasPrompt: true}})
		openSettingsTab(a, f)

		ed := openMaxPriceEditor(t, a)
		ed.prompt.SetText(tc.prompt)
		ed.completion.SetText(tc.completion)
		sendFieldKey(a, ed.prompt, tcell.KeyEnter)

		if len(f.wrote) != 0 {
			t.Errorf("%q/%q writes = %v, want none", tc.prompt, tc.completion, f.wrote)
		}
		if a.NoticeText() != tc.notice {
			t.Errorf("notice = %q, want %q", a.NoticeText(), tc.notice)
		}
		if got := maxPriceRow(t, a); got != stored {
			t.Errorf("max price row = %q, want the stored %q", got, stored)
		}
	}
}

func TestSettingsPicker_MaxPriceFailedWriteKeepsStoredRowAndNotifies(t *testing.T) {
	a := New(nil)
	f := maxPriceSettings(nil)
	f.err = errors.New("write_error: no\nspace left")
	openSettingsTab(a, f)

	ed := openMaxPriceEditor(t, a)
	ed.prompt.SetText("3")
	sendFieldKey(a, ed.prompt, tcell.KeyEnter)

	if len(f.wrote) != 1 {
		t.Fatalf("writes = %v, want exactly one attempt", f.wrote)
	}
	if got, want := maxPriceRow(t, a), "max price ("+maxPriceModelID+")   none"; got != want {
		t.Errorf("max price row = %q, want the stored %q", got, want)
	}
	if want := "couldn't change the openrouter max price setting: write_error: no space left"; a.NoticeText() != want {
		t.Errorf("notice = %q, want %q", a.NoticeText(), want)
	}
}

func TestSettingsPicker_EscClosesOnlyTheMaxPriceEditor(t *testing.T) {
	a := New(nil)
	f := maxPriceSettings(nil)
	openSettingsTab(a, f)

	ed := openMaxPriceEditor(t, a)
	ed.prompt.SetText("9")
	if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone)); ev != nil {
		t.Fatal("ESC was not consumed by the global key handler")
	}

	if a.pages.HasPage(settingsDeletePage) {
		t.Fatal("ESC left the max price editor open")
	}
	if !a.settingsPickerOpen || !a.pages.HasPage(settingsPickerPage) {
		t.Fatal("ESC closed the permissions picker, want only the editor closed")
	}
	if a.app.GetFocus() != a.settingsPicker.list {
		t.Errorf("focus = %T, want the settings list", a.app.GetFocus())
	}
	if len(f.wrote) != 0 {
		t.Errorf("writes = %v, want none after ESC", f.wrote)
	}
	if got := maxPriceRow(t, a); got != "max price ("+maxPriceModelID+")   none" {
		t.Errorf("max price row = %q, want it unchanged", got)
	}
}

func settingsEditorTitle(t *testing.T, a *App) string {
	t.Helper()
	page, ok := a.pages.GetPage(settingsDeletePage).(*tview.Flex)
	if !ok {
		t.Fatal("no editor open")
	}
	return page.GetItem(1).(*tview.Flex).GetItem(1).(*tview.Flex).GetTitle()
}

func TestSettingsPicker_ShortRowLabelsKeepEditorTitles(t *testing.T) {
	a := New(nil)
	openSettingsTab(a, maxPriceSettings(nil))
	openMaxPriceEditor(t, a)
	if got, want := settingsEditorTitle(t, a), " openrouter max price per M tokens ("+maxPriceModelID+") "; got != want {
		t.Errorf("max price editor title = %q, want %q", got, want)
	}

	b := New(nil)
	openRetentionTab(t, b, &fakeRetention{days: 30})
	pressEnterOnRow(t, b, 0)
	if got, want := settingsEditorTitle(t, b), " session retention (days) "; got != want {
		t.Errorf("retention editor title = %q, want %q", got, want)
	}
}

type fakeRetention struct {
	days  int
	err   error
	wrote []int
}

func (f *fakeRetention) seam() SessionSettings {
	return SessionSettings{
		RetentionDays: func() int { return f.days },
		SetRetentionDays: func(days int) error {
			f.wrote = append(f.wrote, days)
			if f.err != nil {
				return f.err
			}
			f.days = days
			return nil
		},
	}
}

func openRetentionTab(t *testing.T, a *App, f *fakeRetention) {
	t.Helper()
	NewSettingsPicker(a, OpenRouterSettings{}, f.seam()).Present(unlayeredPermissionRows(permissionsFixture()), SettingsDeps{})
	a.stepSettingsTab(-1)
	if a.settingsPicker.activeTab != permTabIndexSettings {
		t.Fatalf("active tab = %d, want the settings tab", a.settingsPicker.activeTab)
	}
}

func retentionRow(a *App) string {
	return permissionsRowsOnTab(a)[0]
}

func submitRetentionEditor(t *testing.T, a *App, text string) {
	t.Helper()
	pressEnterOnRow(t, a, 0)
	field := a.settingsPicker.retention
	if !a.pages.HasPage(settingsDeletePage) || field == nil || a.app.GetFocus() != field {
		t.Fatal("Enter on the retention row opened no focused editor")
	}
	field.SetText(text)
	sendFieldKey(a, field, tcell.KeyEnter)
}

func answerRetentionConfirm(t *testing.T, a *App, key tcell.Key) {
	t.Helper()
	modal, ok := a.pages.GetPage(settingsDeletePage).(*tview.Modal)
	if !ok {
		t.Fatal("no confirmation open")
	}
	modal.InputHandler()(tcell.NewEventKey(key, 0, tcell.ModNone), func(p tview.Primitive) { a.app.SetFocus(p) })
}

func TestSettingsPicker_SettingsTabListsOnlyRetention(t *testing.T) {
	a := New(nil)
	openRetentionTab(t, a, &fakeRetention{days: 30})
	assertRows(t, a, permTabIndexSettings, []string{"session retention (days)   30"})
}

func TestSettingsPicker_EnterOnRetentionNeverTogglesAttribution(t *testing.T) {
	a := New(nil)
	or := &fakeOpenRouterSettings{on: true, dc: "allow", sort: "default"}
	f := &fakeRetention{days: 30}
	NewSettingsPicker(a, or.seam(), f.seam()).Present(unlayeredPermissionRows(permissionsFixture()), SettingsDeps{})
	a.stepSettingsTab(-1)

	pressEnterOnRow(t, a, 0)
	if !a.pages.HasPage(settingsDeletePage) || a.settingsPicker.retention == nil {
		t.Fatal("Enter on the retention row opened no retention editor")
	}
	if len(or.wrote) != 0 || len(f.wrote) != 0 {
		t.Errorf("Enter on the retention row wrote %v / %v, want nothing before submit", or.wrote, f.wrote)
	}
	a.cancelSettingsDelete()
	submitRetentionEditor(t, a, "45")
	if len(or.wrote) != 0 || !slices.Equal(f.wrote, []int{45}) {
		t.Errorf("writes = %v / %v, want only retention 45", or.wrote, f.wrote)
	}
	assertRows(t, a, permTabIndexSettings, []string{"session retention (days)   45"})
}

func TestSettingsPicker_RetentionEditorRaisesWithoutConfirm(t *testing.T) {
	for _, text := range []string{"45", " 30 "} {
		a := New(nil)
		f := &fakeRetention{days: 30}
		openRetentionTab(t, a, f)

		pressEnterOnRow(t, a, 0)
		if got := a.settingsPicker.retention.GetText(); got != "30" {
			t.Fatalf("editor text = %q, want the current value", got)
		}
		a.cancelSettingsDelete()
		submitRetentionEditor(t, a, text)

		want := strings.TrimSpace(text)
		if len(f.wrote) != 1 || strconv.Itoa(f.wrote[0]) != want {
			t.Fatalf("%q writes = %v, want one write of %s", text, f.wrote, want)
		}
		if a.pages.HasPage(settingsDeletePage) {
			t.Fatalf("%q left a page open, want no confirmation when not lowering", text)
		}
		if got := retentionRow(a); got != "session retention (days)   "+want {
			t.Errorf("retention row = %q, want %s", got, want)
		}
		if a.app.GetFocus() != a.settingsPicker.list || a.settingsPicker.list.GetCurrentItem() != 0 {
			t.Error("submit did not return focus to the retention row")
		}
		if a.NoticeText() != "" {
			t.Errorf("notice = %q, want none", a.NoticeText())
		}
	}
}

func TestSettingsPicker_RetentionEditorRejectsInvalidInput(t *testing.T) {
	for _, text := range []string{"abc", "0", "-1", "", "1.5", "9223372036854775808"} {
		a := New(nil)
		f := &fakeRetention{days: 30}
		openRetentionTab(t, a, f)

		submitRetentionEditor(t, a, text)

		if len(f.wrote) != 0 {
			t.Errorf("%q writes = %v, want none", text, f.wrote)
		}
		if a.pages.HasPage(settingsDeletePage) {
			t.Errorf("%q left a page open", text)
		}
		if want := fmt.Sprintf("couldn't change the session retention (days) setting: %q is not a whole number of at least 1", text); a.NoticeText() != want {
			t.Errorf("notice = %q, want %q", a.NoticeText(), want)
		}
		if got := retentionRow(a); got != "session retention (days)   30" {
			t.Errorf("retention row = %q, want it unchanged", got)
		}
	}
}

func TestSettingsPicker_RetentionLoweringAsksFirst(t *testing.T) {
	a := New(nil)
	f := &fakeRetention{days: 30}
	openRetentionTab(t, a, f)

	submitRetentionEditor(t, a, "14")
	if len(f.wrote) != 0 {
		t.Fatalf("writes before confirmation = %v, want none", f.wrote)
	}
	answerRetentionConfirm(t, a, tcell.KeyEscape)
	if len(f.wrote) != 0 || a.pages.HasPage(settingsDeletePage) {
		t.Fatalf("cancel wrote %v or left the confirmation open", f.wrote)
	}
	if got := retentionRow(a); got != "session retention (days)   30" {
		t.Errorf("retention row after cancel = %q, want it unchanged", got)
	}
	if a.app.GetFocus() != a.settingsPicker.list {
		t.Error("cancel did not refocus the settings list")
	}

	submitRetentionEditor(t, a, "14")
	answerRetentionConfirm(t, a, tcell.KeyEnter)
	if !slices.Equal(f.wrote, []int{14}) {
		t.Fatalf("writes after confirming = %v, want [14]", f.wrote)
	}
	if a.pages.HasPage(settingsDeletePage) {
		t.Fatal("confirming left the confirmation open")
	}
	if got := retentionRow(a); got != "session retention (days)   14" {
		t.Errorf("retention row after confirming = %q, want 14", got)
	}
	if a.app.GetFocus() != a.settingsPicker.list || a.settingsPicker.list.GetCurrentItem() != 0 {
		t.Error("confirming did not return focus to the retention row")
	}
}

func TestRetentionConfirmText(t *testing.T) {
	want := "Sessions not updated in the last 14 days become eligible for automatic deletion at the next fresh interactive launch. Resuming a session does not start pruning."
	if got := retentionConfirmText(14); got != want {
		t.Errorf("retentionConfirmText(14) = %q, want %q", got, want)
	}
}

func TestSettingsPicker_RetentionFailedWriteKeepsRowAndNotifies(t *testing.T) {
	a := New(nil)
	f := &fakeRetention{days: 30, err: errors.New("write_error: no\nspace left")}
	openRetentionTab(t, a, f)

	submitRetentionEditor(t, a, "60")

	if !slices.Equal(f.wrote, []int{60}) {
		t.Fatalf("writes = %v, want exactly one attempt", f.wrote)
	}
	if got := retentionRow(a); got != "session retention (days)   30" {
		t.Errorf("retention row = %q, want the getter's value", got)
	}
	if want := "couldn't change the session retention (days) setting: write_error: no space left"; a.NoticeText() != want {
		t.Errorf("notice = %q, want %q", a.NoticeText(), want)
	}
}

func TestSettingsFooterHint_NamesTheToggleKey(t *testing.T) {
	for _, want := range []string{"tab switch", "revoke r", "toggle enter", "esc close"} {
		if !strings.Contains(settingsFooterHint, want) {
			t.Errorf("footer hint = %q, want it to mention %q", settingsFooterHint, want)
		}
	}
}

const (
	shareLocalPath   = "/proj/.codemeld/settings.local.yaml"
	shareProjectPath = "/proj/.codemeld/settings.yaml"
	shareGlobalPath  = "/home/me/.codemeld/global/settings.yaml"
)

var (
	shareFolderGrant  = permissions.PermissionEntry{Kind: "tool", Subject: permissions.CapabilityRead, PathScope: "/proj", GrantKind: "folder"}
	shareHostGrant    = permissions.PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "docs.example.com", GrantKind: "project"}
	shareGlobalGrant  = permissions.PermissionEntry{Kind: "tool", Subject: "grep", PathScope: "*", GrantKind: "global"}
	shareSessionGrant = permissions.PermissionEntry{Kind: "literal", Subject: "npm test", PathScope: "/proj", GrantKind: "session"}

	localFolderRow   = PermissionRow{Entry: shareFolderGrant, Layer: permissions.LayerLocal, Path: shareLocalPath}
	projectFolderRow = PermissionRow{Entry: shareFolderGrant, Layer: permissions.LayerProject, Path: shareProjectPath}
	localHostRow     = PermissionRow{Entry: shareHostGrant, Layer: permissions.LayerLocal, Path: shareLocalPath}
	globalRow        = PermissionRow{Entry: shareGlobalGrant, Layer: permissions.LayerGlobal, Path: shareGlobalPath}
	sessionRow       = PermissionRow{Entry: shareSessionGrant}
)

func layeredRowsFixture() []PermissionRow {
	return []PermissionRow{localFolderRow, projectFolderRow, localHostRow, globalRow, sessionRow}
}

func selectPermissionRow(t *testing.T, a *App, row PermissionRow) {
	t.Helper()
	if !a.SelectPermissionForTest(row.Entry) {
		t.Fatalf("no tab lists %+v", row.Entry)
	}
	for i, r := range a.settingsPicker.activeRows() {
		if samePermissionRow(r, row) {
			a.settingsPicker.list.SetCurrentItem(i)
			return
		}
	}
	t.Fatalf("row %+v not listed", row)
}

func TestSettingsPicker_RowsShowLayerKindAndPath(t *testing.T) {
	a := New(nil)
	var revoked []PermissionRow
	a.openSettingsPicker(layeredRowsFixture(), SettingsDeps{
		Rows:   layeredRowsFixture,
		Revoke: func(row PermissionRow) { revoked = append(revoked, row) },
	}, SessionSettings{})

	read := "allow reading/searching (read + grep + glob + list + tree + file_count) — in /proj"
	for _, tc := range []struct {
		tab  int
		want []string
	}{
		{tab: 0, want: []string{"allow the grep tool — globally — " + shareGlobalPath + " [global]"}},
		{tab: permTabIndexFolders, want: []string{
			read + " — " + shareLocalPath + " [local]",
			read + " — " + shareProjectPath + " [project]",
			"run npm test — in /proj",
		}},
		{tab: permTabIndexHosts, want: []string{"allow the web_fetch tool — docs.example.com — " + shareLocalPath + " [local]"}},
	} {
		a.settingsPicker.activeTab = tc.tab
		a.renderSettingsTab()
		assertRows(t, a, tc.tab, tc.want)
	}

	selectPermissionRow(t, a, sessionRow)
	a.applySettingsRevoke(sessionRow)
	if len(revoked) != 1 || revoked[0] != sessionRow {
		t.Fatalf("revoked %+v, want the unlayered session row %+v", revoked, sessionRow)
	}
}

func TestSettingsPicker_ShareOfferedOnlyOnApprovedLocalRow(t *testing.T) {
	share := func(PermissionRow) ShareResult { return ShareResult{} }
	for _, tc := range []struct {
		name     string
		rows     []PermissionRow
		tab      int
		selected *PermissionRow
		approved bool
		share    func(PermissionRow) ShareResult
		offered  bool
	}{
		{name: "approved local folder row", rows: layeredRowsFixture(), selected: &localFolderRow, approved: true, share: share, offered: true},
		{name: "approved local host row", rows: layeredRowsFixture(), selected: &localHostRow, approved: true, share: share, offered: true},
		{name: "project row", rows: layeredRowsFixture(), selected: &projectFolderRow, approved: true, share: share},
		{name: "global row", rows: layeredRowsFixture(), selected: &globalRow, approved: true, share: share},
		{name: "unlayered session row", rows: layeredRowsFixture(), selected: &sessionRow, approved: true, share: share},
		{name: "empty tab placeholder", rows: []PermissionRow{localFolderRow}, tab: permTabIndexHosts, approved: true, share: share},
		{name: "openrouter tab", rows: layeredRowsFixture(), tab: permTabIndexOpenRouter, approved: true, share: share},
		{name: "settings tab", rows: layeredRowsFixture(), tab: permTabIndexSettings, approved: true, share: share},
		{name: "local row without an explicit approval", rows: layeredRowsFixture(), selected: &localFolderRow, share: share},
		{name: "local row with no share seam", rows: layeredRowsFixture(), selected: &localFolderRow, approved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sharedFile := filepath.Join(t.TempDir(), "settings.yaml")
			const seed = "permissions: []\n"
			if err := os.WriteFile(sharedFile, []byte(seed), 0o600); err != nil {
				t.Fatal(err)
			}
			var shared []PermissionRow
			var seam func(PermissionRow) ShareResult
			if tc.share != nil {
				seam = func(row PermissionRow) ShareResult {
					shared = append(shared, row)
					if err := os.WriteFile(sharedFile, []byte("permissions: [shared]\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					return tc.share(row)
				}
			}
			a := New(nil)
			a.openSettingsPicker(tc.rows, SettingsDeps{
				Rows: func() []PermissionRow { return tc.rows }, Share: seam, Approved: tc.approved, Boundary: "project-root",
			}, SessionSettings{})
			if tc.selected != nil {
				selectPermissionRow(t, a, *tc.selected)
			} else {
				a.settingsPicker.activeTab = tc.tab
				a.renderSettingsTab()
			}

			wantHint := settingsFooterHint
			if tc.offered {
				wantHint = settingsShareFooterHint
			}
			if got := a.settingsPicker.footer.GetText(false); got != wantHint {
				t.Fatalf("footer = %q, want %q", got, wantHint)
			}

			if ev := a.settingsPickerKeys(tcell.NewEventKey(tcell.KeyRune, 's', tcell.ModNone)); ev != nil {
				t.Fatal("s reached the list, want the picker to consume it")
			}
			if got := a.pages.HasPage(settingsDeletePage); got != tc.offered {
				t.Fatalf("share confirmation shown = %v, want %v", got, tc.offered)
			}
			a.cancelSettingsDelete()
			if len(shared) != 0 {
				t.Fatalf("share seam called %+v before any confirmation", shared)
			}
			if got, err := os.ReadFile(sharedFile); err != nil || string(got) != seed {
				t.Fatalf("settings.yaml = %q (err %v), want it unchanged", got, err)
			}
		})
	}
}

func TestSettingsPicker_FooterFollowsTheCursor(t *testing.T) {
	a := New(nil)
	a.openSettingsPicker(layeredRowsFixture(), SettingsDeps{
		Share: func(PermissionRow) ShareResult { return ShareResult{} }, Approved: true,
	}, SessionSettings{})
	a.stepSettingsTab(1)
	footer := a.settingsPicker.footer
	for _, tc := range []struct {
		row  int
		want string
	}{
		{row: 1, want: settingsFooterHint},
		{row: 0, want: settingsShareFooterHint},
		{row: 2, want: settingsFooterHint},
	} {
		a.settingsPicker.list.SetCurrentItem(tc.row)
		if got := footer.GetText(false); got != tc.want {
			t.Errorf("footer on folder row %d = %q, want %q", tc.row, got, tc.want)
		}
	}
}

func TestShareConfirmText(t *testing.T) {
	const everyone = "Everyone who approves this repository receives it."
	const outside = "That folder is outside this project."
	inside := permissions.PermissionEntry{Kind: "literal", Subject: "npm test", PathScope: "/proj/web", GrantKind: "folder"}
	far := permissions.PermissionEntry{Kind: "literal", Subject: "npm test", PathScope: "/srv/other", GrantKind: "folder"}
	tagged := permissions.PermissionEntry{Kind: "literal", Subject: "npm test", PathScope: "/proj/[red]x", GrantKind: "folder"}
	long := "/proj/" + strings.Repeat("a", 130)
	longOne := permissions.PermissionEntry{Kind: "literal", Subject: "npm test", PathScope: long + "/one", GrantKind: "folder"}
	longTwo := permissions.PermissionEntry{Kind: "literal", Subject: "npm test", PathScope: long + "/two", GrantKind: "folder"}
	longHost := strings.Repeat("h", 130) + ".example.com"
	hostOne := permissions.PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: longHost + ".one", GrantKind: "project"}
	hostTwo := permissions.PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: longHost + ".two", GrantKind: "project"}
	newline := permissions.PermissionEntry{Kind: "literal", Subject: "npm test", PathScope: "/proj/a\nb", GrantKind: "folder"}
	for _, tc := range []struct {
		name    string
		entry   permissions.PermissionEntry
		root    string
		want    []string
		notWant []string
	}{
		{name: "folder inside the project", entry: inside, root: "/proj", want: []string{"run npm test — in /proj/web", "It covers the folder /proj/web.", everyone}, notWant: []string{outside, "network"}},
		{name: "folder outside the project", entry: far, root: "/proj", want: []string{"It covers the folder /srv/other. " + outside, everyone}},
		{name: "folder with no known project root", entry: inside, root: "", want: []string{outside}},
		{name: "host grant", entry: shareHostGrant, root: "/proj", want: []string{"It authorizes network access to docs.example.com.", everyone}, notWant: []string{"covers the folder", outside}},
		{name: "style tags stay literal", entry: tagged, root: "/proj", want: []string{"It covers the folder /proj/[red[]x."}},
		{name: "long folder path one", entry: longOne, root: "/proj", want: []string{"It covers the folder " + long + "/one."}, notWant: []string{"…"}},
		{name: "long folder path two", entry: longTwo, root: "/proj", want: []string{"It covers the folder " + long + "/two."}, notWant: []string{"…"}},
		{name: "long host one", entry: hostOne, root: "/proj", want: []string{"It authorizes network access to " + longHost + ".one."}, notWant: []string{"…"}},
		{name: "long host two", entry: hostTwo, root: "/proj", want: []string{"It authorizes network access to " + longHost + ".two."}, notWant: []string{"…"}},
		{name: "control runes are escaped", entry: newline, root: "/proj", want: []string{`It covers the folder /proj/a\x0Ab.`}, notWant: []string{"/proj/a\nb"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := shareConfirmText(tc.entry, tc.root)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("confirmation = %q, want it to contain %q", got, w)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(got, w) {
					t.Errorf("confirmation = %q, want no %q", got, w)
				}
			}
		})
	}
}

func TestSettingsPicker_ShareConfirmCancelWritesNothingAndConfirmShares(t *testing.T) {
	dir := t.TempDir()
	localFile, sharedFile := filepath.Join(dir, "settings.local.yaml"), filepath.Join(dir, "settings.yaml")
	for _, f := range []string{localFile, sharedFile} {
		if err := os.WriteFile(f, []byte("permissions: []\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := func() string {
		l, _ := os.ReadFile(localFile)
		s, _ := os.ReadFile(sharedFile)
		return string(l) + "|" + string(s)
	}
	before := snapshot()
	var shared []PermissionRow
	deps := SettingsDeps{
		Rows: layeredRowsFixture,
		Share: func(row PermissionRow) ShareResult {
			shared = append(shared, row)
			if err := os.WriteFile(sharedFile, []byte("permissions: [shared]\n"), 0o600); err != nil {
				t.Error(err)
			}
			return ShareResult{SharedPath: sharedFile, LocalPath: localFile}
		},
		Approved: true,
	}

	a := New(nil)
	screen := tcell.NewSimulationScreen("UTF-8")
	a.app.SetScreen(screen)
	errc := make(chan error, 1)
	go func() { errc <- a.app.Run() }()
	onLoop := func(fn func()) {
		done := make(chan struct{})
		a.app.QueueUpdate(func() { fn(); close(done) })
		<-done
	}
	waitPage := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			var open bool
			onLoop(func() { open = a.pages.HasPage(settingsDeletePage) })
			if open == want {
				return
			}
			if time.Now().After(deadline) {
				a.app.Stop()
				t.Fatalf("confirmation present=%v not reached within 2s", want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	onLoop(func() {
		a.openSettingsPicker(layeredRowsFixture(), deps, SessionSettings{})
		selectPermissionRow(t, a, localFolderRow)
	})
	screen.InjectKey(tcell.KeyRune, 's', tcell.ModNone)
	waitPage(true)
	var confirm string
	var sharedBeforeConfirm int
	onLoop(func() {
		if modal, ok := a.pages.GetPage(settingsDeletePage).(*tview.Modal); ok {
			confirm = strings.Join(strings.Fields(strings.ReplaceAll(modalScreenText(t, modal), "║", " ")), " ")
		}
		sharedBeforeConfirm = len(shared)
	})
	for _, want := range []string{"It covers the folder /proj.", "Everyone who approves this repository receives it."} {
		if !strings.Contains(confirm, want) || sharedBeforeConfirm != 0 || snapshot() != before {
			a.app.Stop()
			t.Fatalf("confirmation = %q with %d share calls, files changed %v; want %q shown before any write", confirm, sharedBeforeConfirm, snapshot() != before, want)
		}
	}
	screen.InjectKey(tcell.KeyRight, 0, tcell.ModNone)
	screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	waitPage(false)
	var stillOpen bool
	onLoop(func() { stillOpen = a.settingsPickerOpen })
	if len(shared) != 0 || snapshot() != before || !stillOpen {
		a.app.Stop()
		t.Fatalf("Cancel: shared %+v, files changed %v, overlay open %v; want nothing written and the overlay kept", shared, snapshot() != before, stillOpen)
	}

	screen.InjectKey(tcell.KeyRune, 's', tcell.ModNone)
	waitPage(true)
	screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	waitPage(false)
	var got []PermissionRow
	onLoop(func() { got = shared })
	if len(got) != 1 || got[0] != localFolderRow {
		a.app.Stop()
		t.Fatalf("Share: seam calls %+v, want one for the selected local row", got)
	}
	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}
}

func TestSettingsPicker_ShareOutcomeNotices(t *testing.T) {
	marker := permissions.BoundPromptFact(shareProjectPath)
	localFailure := RenderShareLocalRemovalFailedNotice(shareProjectPath, shareLocalPath, "read-only file system", false)
	read := "allow reading/searching (read + grep + glob + list + tree + file_count) — in /proj"
	localLabel := read + " — " + shareLocalPath + " [local]"
	projectLabel := read + " — " + shareProjectPath + " [project]"
	paths := ShareResult{SharedPath: shareProjectPath, LocalPath: shareLocalPath}
	with := func(mod func(*ShareResult)) ShareResult { r := paths; mod(&r); return r }
	both := []PermissionRow{localFolderRow, projectFolderRow}
	for _, tc := range []struct {
		name       string
		res        ShareResult
		boundary   string
		after      []PermissionRow
		wantNotice string
		wantRows   []string
	}{
		{name: "clean share into an existing file", res: paths, boundary: "launch-dir-only", after: []PermissionRow{projectFolderRow}, wantRows: []string{projectLabel}},
		{name: "refused", res: ShareResult{Refused: true}, wantNotice: RenderShareRefusedNotice(), wantRows: []string{localLabel}},
		{
			name: "shared write failed", res: with(func(r *ShareResult) { r.SharedErr = errors.New("permission denied") }),
			wantNotice: RenderShareFailedNotice(shareProjectPath, "permission denied"), wantRows: []string{localLabel},
		},
		{
			name: "local removal failed after the shared write", res: with(func(r *ShareResult) { r.LocalErr = errors.New("read-only file system") }),
			after: both, wantNotice: localFailure, wantRows: []string{localLabel, projectLabel},
		},
		{
			name: "local removal failed after a skipped shared write",
			res: with(func(r *ShareResult) {
				r.SharedSkipped = true
				r.LocalErr = errors.New("read-only file system")
			}),
			after: both, wantNotice: RenderShareLocalRemovalFailedNotice(shareProjectPath, shareLocalPath, "read-only file system", true),
			wantRows: []string{localLabel, projectLabel},
		},
		{
			name: "created under launch-dir-only", res: with(func(r *ShareResult) { r.SharedCreated = true }), boundary: "launch-dir-only",
			after: []PermissionRow{projectFolderRow}, wantNotice: RenderCrossModeMarkerNotice(marker), wantRows: []string{projectLabel},
		},
		{
			name: "created under project-root", res: with(func(r *ShareResult) { r.SharedCreated = true }), boundary: "project-root",
			after: []PermissionRow{projectFolderRow}, wantNotice: RenderProjectRootMarkerNotice(marker), wantRows: []string{projectLabel},
		},
		{
			name: "created and local removal failed",
			res: with(func(r *ShareResult) {
				r.SharedCreated = true
				r.LocalErr = errors.New("read-only file system")
			}),
			boundary: "project-root", after: both,
			wantNotice: RenderProjectRootMarkerNotice(marker) + "\n" + localFailure, wantRows: []string{localLabel, projectLabel},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := []PermissionRow{localFolderRow}
			var shared []PermissionRow
			a := New(nil)
			a.openSettingsPicker(current, SettingsDeps{
				Rows: func() []PermissionRow { return current },
				Share: func(row PermissionRow) ShareResult {
					shared = append(shared, row)
					if tc.after != nil {
						current = tc.after
					}
					return tc.res
				},
				Approved: true,
				Boundary: tc.boundary,
			}, SessionSettings{})
			a.stepSettingsTab(1)

			a.applySettingsShare(localFolderRow)

			if len(shared) != 1 || shared[0] != localFolderRow {
				t.Fatalf("share seam calls %+v, want one for the local row", shared)
			}
			if got := a.NoticeText(); got != tc.wantNotice {
				t.Errorf("notice = %q\nwant     %q", got, tc.wantNotice)
			}
			assertRows(t, a, permTabIndexFolders, tc.wantRows)
		})
	}
}

func TestSettingsPicker_ShareRetryClearsEarlierFailureNotice(t *testing.T) {
	read := "allow reading/searching (read + grep + glob + list + tree + file_count) — in /proj"
	current := []PermissionRow{localFolderRow}
	results := []ShareResult{
		{SharedPath: shareProjectPath, LocalPath: shareLocalPath, LocalErr: errors.New("read-only file system")},
		{SharedPath: shareProjectPath, LocalPath: shareLocalPath, SharedSkipped: true},
	}
	afters := [][]PermissionRow{{localFolderRow, projectFolderRow}, {projectFolderRow}}
	calls := 0
	a := New(nil)
	a.openSettingsPicker(current, SettingsDeps{
		Rows: func() []PermissionRow { return current },
		Share: func(PermissionRow) ShareResult {
			res := results[calls]
			current = afters[calls]
			calls++
			return res
		},
		Approved: true,
	}, SessionSettings{})
	a.stepSettingsTab(1)

	a.applySettingsShare(localFolderRow)
	if want := RenderShareLocalRemovalFailedNotice(shareProjectPath, shareLocalPath, "read-only file system", false); a.NoticeText() != want {
		t.Fatalf("after failed share notice = %q, want %q", a.NoticeText(), want)
	}

	a.applySettingsShare(localFolderRow)
	if got := a.NoticeText(); got != "" {
		t.Errorf("after successful retry notice = %q, want it cleared", got)
	}
	assertRows(t, a, permTabIndexFolders, []string{read + " — " + shareProjectPath + " [project]"})
}

func TestRevokeConfirmText(t *testing.T) {
	text, action := revokeConfirmText(projectFolderRow)
	for _, w := range []string{"Remove this shared grant?", "It is removed from " + shareProjectPath + " for everyone who pulls the repository."} {
		if !strings.Contains(text, w) {
			t.Errorf("project confirmation = %q, want it to contain %q", text, w)
		}
	}
	if action != "Remove" {
		t.Errorf("project confirmation action = %q, want Remove", action)
	}
	for _, row := range []PermissionRow{localFolderRow, globalRow, sessionRow} {
		text, action := revokeConfirmText(row)
		if want := "Revoke this grant?\n\n" + tview.Escape(renderPermissionRow(row)); text != want || action != "Revoke" {
			t.Errorf("confirmation for %+v = (%q, %q), want (%q, Revoke)", row, text, action, want)
		}
	}
}

func TestSettingsPicker_ProjectRowRevokeCancelKeepsFileAndRow(t *testing.T) {
	sharedFile := filepath.Join(t.TempDir(), "settings.yaml")
	const content = "# team\npermissions:\n  - kind: tool\n    subject: read\n"
	if err := os.WriteFile(sharedFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	row := PermissionRow{Entry: shareFolderGrant, Layer: permissions.LayerProject, Path: sharedFile}
	rows := []PermissionRow{localFolderRow, row}
	var revoked []PermissionRow
	a := New(nil)
	a.openSettingsPicker(rows, SettingsDeps{
		Rows: func() []PermissionRow { return rows },
		Revoke: func(r PermissionRow) {
			revoked = append(revoked, r)
			rows = rows[:1]
		},
	}, SessionSettings{})
	selectPermissionRow(t, a, row)

	if ev := a.settingsPickerKeys(tcell.NewEventKey(tcell.KeyRune, 'r', tcell.ModNone)); ev != nil {
		t.Fatal("r reached the list, want the picker to consume it")
	}
	if !a.pages.HasPage(settingsDeletePage) {
		t.Fatal("r did not open the confirmation on a project row")
	}
	a.cancelSettingsDelete()

	if got, err := os.ReadFile(sharedFile); err != nil || string(got) != content {
		t.Fatalf("shared file after cancel = %q, %v; want it byte-identical", got, err)
	}
	if len(revoked) != 0 {
		t.Fatalf("cancel revoked %+v", revoked)
	}
	read := "allow reading/searching (read + grep + glob + list + tree + file_count) — in /proj"
	assertRows(t, a, permTabIndexFolders, []string{read + " — " + shareLocalPath + " [local]", read + " — " + sharedFile + " [project]"})

	a.applySettingsRevoke(row)
	if len(revoked) != 1 || revoked[0] != row {
		t.Fatalf("revoked %+v, want the project row", revoked)
	}
	assertRows(t, a, permTabIndexFolders, []string{read + " — " + shareLocalPath + " [local]"})
}

type fakeSortEstimates struct {
	ready   map[string]provider.OpenRouterEstimate
	calls   []string
	fetched []func()
}

func (f *fakeSortEstimates) estimate(model, sortMode string, fetched func()) (provider.OpenRouterEstimate, bool) {
	f.calls = append(f.calls, model+" "+sortMode)
	est, ok := f.ready[model+" "+sortMode]
	if !ok {
		f.fetched = append(f.fetched, fetched)
	}
	return est, ok
}

func estimateSettings(sortMode string, est *fakeSortEstimates) *fakeOpenRouterSettings {
	f := maxPriceSettings(nil)
	f.sort = sortMode
	f.estimate = est.estimate
	return f
}

func sortRow(a *App) string {
	return permissionsRowsOnTab(a)[settingsRowSort]
}

func TestSettingsPicker_SortRowShowsEstimateForEachMode(t *testing.T) {
	for _, tc := range []struct {
		stored string
		est    provider.OpenRouterEstimate
		want   string
	}{
		{"default", provider.OpenRouterEstimate{PromptPerM: 0.04, CompletionPerM: 0.15, Discount: 0.8}, "sort   default (about $0.04 / $0.15 per M, 80% off)"},
		{"throughput", provider.OpenRouterEstimate{PromptPerM: 1, CompletionPerM: 2.5}, "sort   throughput (about $1 / $2.5 per M)"},
		{"best_value", provider.OpenRouterEstimate{PromptPerM: 0.1, CompletionPerM: 0.32}, "sort   best value (about $0.1 / $0.32 per M)"},
	} {
		est := &fakeSortEstimates{ready: map[string]provider.OpenRouterEstimate{maxPriceModelID + " " + tc.stored: tc.est}}
		a := New(nil)
		openSettingsTab(a, estimateSettings(tc.stored, est))
		if got := sortRow(a); got != tc.want {
			t.Errorf("stored %s: sort row = %q, want %q", tc.stored, got, tc.want)
		}
	}
}

func TestRenderSortEstimate(t *testing.T) {
	for _, tc := range []struct {
		est  provider.OpenRouterEstimate
		want string
	}{
		{provider.OpenRouterEstimate{PromptPerM: 0.1, CompletionPerM: 0.12345}, "about $0.1 / $0.1235 per M"},
		{provider.OpenRouterEstimate{PromptPerM: 1.5, CompletionPerM: 20}, "about $1.5 / $20 per M"},
		{provider.OpenRouterEstimate{PromptPerM: 0.00004, CompletionPerM: 0.10001}, "about $0 / $0.1 per M"},
		{provider.OpenRouterEstimate{PromptPerM: 1, CompletionPerM: 2, Discount: 0.8}, "about $1 / $2 per M, 80% off"},
		{provider.OpenRouterEstimate{PromptPerM: 1, CompletionPerM: 2, Discount: 0.125}, "about $1 / $2 per M, 13% off"},
		{provider.OpenRouterEstimate{PromptPerM: 1, CompletionPerM: 2, Discount: 0.3333}, "about $1 / $2 per M, 33% off"},
		{provider.OpenRouterEstimate{PromptPerM: 1, CompletionPerM: 2, Discount: 0.005}, "about $1 / $2 per M, 1% off"},
		{provider.OpenRouterEstimate{PromptPerM: 1, CompletionPerM: 2, Discount: 0.004}, "about $1 / $2 per M, 0% off"},
		{provider.OpenRouterEstimate{PromptPerM: 1, CompletionPerM: 2, Discount: 0.145}, "about $1 / $2 per M, 15% off"},
		{provider.OpenRouterEstimate{PromptPerM: 1, CompletionPerM: 2, Discount: 0.14499}, "about $1 / $2 per M, 14% off"},
		{provider.OpenRouterEstimate{PromptPerM: 1, CompletionPerM: 2, Discount: 0.14501}, "about $1 / $2 per M, 15% off"},
	} {
		if got := renderSortEstimate(tc.est); got != tc.want {
			t.Errorf("renderSortEstimate(%+v) = %q, want %q", tc.est, got, tc.want)
		}
	}
}

func TestSettingsPicker_SortRowWithoutEstimateShowsModeAlone(t *testing.T) {
	ready := map[string]provider.OpenRouterEstimate{maxPriceModelID + " default": {PromptPerM: 1, CompletionPerM: 2}}
	for _, tc := range []struct {
		name, provider, model string
		wantCalls             int
	}{
		{"another provider", "venice", maxPriceModelID, 0},
		{"no selection", "", "", 0},
		{"missing data", "openrouter", "other/model", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			est := &fakeSortEstimates{ready: ready}
			f := estimateSettings("default", est)
			f.activeProvider, f.activeModel = tc.provider, tc.model
			a := New(nil)
			openSettingsTab(a, f)
			if got := sortRow(a); got != "sort   default" {
				t.Errorf("sort row = %q, want the mode alone", got)
			}
			if len(est.calls) != tc.wantCalls {
				t.Errorf("estimate calls = %v, want %d", est.calls, tc.wantCalls)
			}
		})
	}
}

func TestSettingsPicker_FetchedEstimateRedrawsTheOpenSettingsTab(t *testing.T) {
	est := &fakeSortEstimates{}
	a := New(nil)
	openSettingsTab(a, estimateSettings("best_value", est))
	a.settingsPicker.list.SetCurrentItem(settingsRowMaxPrice)
	if got := sortRow(a); got != "sort   best value" {
		t.Fatalf("sort row before the fetch = %q", got)
	}
	if len(est.fetched) != 1 {
		t.Fatalf("estimate requests with a pending fetch = %d, want 1", len(est.fetched))
	}

	est.ready = map[string]provider.OpenRouterEstimate{maxPriceModelID + " best_value": {PromptPerM: 0.1, CompletionPerM: 0.32}}
	est.fetched[0]()
	if got := sortRow(a); got != "sort   best value (about $0.1 / $0.32 per M)" {
		t.Fatalf("sort row after the fetch = %q", got)
	}
	if got := a.settingsPicker.list.GetCurrentItem(); got != settingsRowMaxPrice {
		t.Errorf("cursor after the redraw = %d, want it unchanged", got)
	}
}

func TestSettingsPicker_FetchedEstimateIgnoresASwitchedModel(t *testing.T) {
	est := &fakeSortEstimates{}
	f := estimateSettings("default", est)
	a := New(nil)
	openSettingsTab(a, f)

	f.activeModel = "other/model"
	est.ready = map[string]provider.OpenRouterEstimate{
		maxPriceModelID + " default": {PromptPerM: 9, CompletionPerM: 9},
		"other/model default":        {PromptPerM: 1, CompletionPerM: 1},
	}
	calls := len(est.calls)
	est.fetched[0]()
	if got := sortRow(a); got != "sort   default" {
		t.Errorf("sort row after the previous model's fetch = %q, want the mode alone", got)
	}
	if len(est.calls) != calls {
		t.Errorf("estimate calls after a switched-model completion = %v, want none added", est.calls[calls:])
	}
}

func TestSettingsPicker_FetchedEstimateAfterCloseOrTabChangeIsInert(t *testing.T) {
	for name, leave := range map[string]func(a *App){
		"closed":    func(a *App) { a.dismissSettingsPicker() },
		"other tab": func(a *App) { a.stepSettingsTab(1) },
	} {
		t.Run(name, func(t *testing.T) {
			est := &fakeSortEstimates{}
			a := New(nil)
			openSettingsTab(a, estimateSettings("default", est))
			leave(a)
			est.ready = map[string]provider.OpenRouterEstimate{maxPriceModelID + " default": {PromptPerM: 1, CompletionPerM: 1}}
			calls := len(est.calls)
			est.fetched[0]()
			if len(est.calls) != calls {
				t.Errorf("estimate calls after leaving the tab = %v, want none added", est.calls[calls:])
			}
			if a.settingsPicker != nil {
				assertRows(t, a, permTabIndexSettings, []string{retentionDefaultRow})
			}
		})
	}
}

func TestSettingsPicker_SettingsTabBuildsNoEstimate(t *testing.T) {
	est := &fakeSortEstimates{}
	a := New(nil)
	a.openRouterSettings = estimateSettings("default", est).seam()
	openEntryPicker(a, permissionsFixture(), nil, nil)
	a.settingsPicker.activeTab = permTabIndexSettings
	a.renderSettingsTab()
	if len(est.calls) != 0 {
		t.Errorf("estimate calls rendering the settings tab = %v, want none", est.calls)
	}
}

func TestSettingsPicker_EnterOnSortRowChangesTheEstimate(t *testing.T) {
	est := &fakeSortEstimates{ready: map[string]provider.OpenRouterEstimate{
		maxPriceModelID + " default":    {PromptPerM: 0.1, CompletionPerM: 0.2},
		maxPriceModelID + " throughput": {PromptPerM: 3, CompletionPerM: 4},
		maxPriceModelID + " best_value": {PromptPerM: 0.5, CompletionPerM: 0.6, Discount: 0.1},
	}}
	a := New(nil)
	openSettingsTab(a, estimateSettings("default", est))
	for _, want := range []string{
		"throughput (about $3 / $4 per M)",
		"best value (about $0.5 / $0.6 per M, 10% off)",
		"default (about $0.1 / $0.2 per M)",
	} {
		pressEnterOnRow(t, a, settingsRowSort)
		if got := sortRow(a); got != "sort   "+want {
			t.Errorf("sort row = %q, want %q", got, "sort   "+want)
		}
	}
}
