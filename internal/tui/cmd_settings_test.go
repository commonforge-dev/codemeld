package tui

import (
	"errors"
	"reflect"
	"testing"

	"codemeld.dev/codemeld/internal/permissions"
)

func TestSettingsHandler_NilRowsFallsBackToUnlayeredListerRows(t *testing.T) {
	grant := permissions.PermissionEntry{Kind: "direct", Subject: "ls", PathScope: "*", GrantKind: "global", Layer: permissions.LayerGlobal}
	lister := &fakePermissionLister{entries: []permissions.PermissionEntry{grant}}
	picker := &fakeSettingsPicker{}
	reg := newSettingsRegistry(t, SettingsDeps{Lister: lister, Picker: picker})

	if res := reg.DispatchSlashInput("/settings", newFakeHost()); res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /settings = %+v, want Handled/nil-err", res)
	}
	want := []PermissionRow{{Entry: grant}}
	if !reflect.DeepEqual(picker.presented, [][]PermissionRow{want}) {
		t.Fatalf("presented %+v, want one unlayered row per lister entry whatever Entry.Layer says", picker.presented)
	}
	if picker.deps.Revoke != nil || picker.deps.Share != nil {
		t.Fatal("nil Revoke and Share seams must leave the overlay read-only")
	}
	if got := picker.deps.Rows(); !reflect.DeepEqual(got, want) {
		t.Fatalf("relist = %+v, want the lister's entries as unlayered rows", got)
	}
}

func TestSettingsHandler_PresentsLayeredRowsAndPassesSeamsThrough(t *testing.T) {
	grant := permissions.PermissionEntry{
		Kind: "tool", Subject: "read_file", PathScope: "/p", GrantKind: "folder", Layer: permissions.LayerLocal,
	}
	lister := &fakePermissionLister{entries: []permissions.PermissionEntry{grant}}
	picker := &fakeSettingsPicker{}
	var revoked, shared []PermissionRow
	layered := []PermissionRow{{Entry: grant, Layer: permissions.LayerLocal, Path: "/p/.codemeld/settings.local.yaml"}}
	reg := newSettingsRegistry(t, SettingsDeps{
		Lister:   lister,
		Picker:   picker,
		Rows:     func() []PermissionRow { return layered },
		Revoke:   func(row PermissionRow) { revoked = append(revoked, row) },
		Share:    func(row PermissionRow) ShareResult { shared = append(shared, row); return ShareResult{} },
		Approved: true,
		Boundary: "project-root",
	})

	if res := reg.DispatchSlashInput("/settings", newFakeHost()); res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /settings = %+v, want Handled/nil-err", res)
	}
	if !reflect.DeepEqual(picker.presented, [][]PermissionRow{layered}) {
		t.Fatalf("presented %+v, want the layered rows", picker.presented)
	}
	if !picker.deps.Approved || picker.deps.Boundary != "project-root" {
		t.Fatalf("picker deps Approved=%v Boundary=%q, want the handler's run-fixed inputs", picker.deps.Approved, picker.deps.Boundary)
	}
	picker.deps.Revoke(layered[0])
	picker.deps.Share(layered[0])
	if !reflect.DeepEqual(revoked, layered) || !reflect.DeepEqual(shared, layered) {
		t.Fatalf("revoked %+v shared %+v, want the layered row passed through unchanged", revoked, shared)
	}
}

func newSettingsAndOpenRouterRegistry(deps SettingsDeps) *Registry {
	return BuildRegistry(map[string]HandlerFunc{
		"settings":   NewSettingsHandler(deps),
		"openrouter": NewOpenRouterHandler(deps),
	})
}

func TestOpenRouterAndSettingsHandlers_RequestTheirTabAfterFlushingTheirOwnEvent(t *testing.T) {
	for _, tc := range []struct {
		command string
		tab     int
	}{
		{"openrouter", permTabIndexOpenRouter},
		{"settings", 0},
	} {
		t.Run(tc.command, func(t *testing.T) {
			host := newFakeHost()
			picker := &fakeSettingsPicker{host: host}
			reg := newSettingsAndOpenRouterRegistry(SettingsDeps{Lister: &fakePermissionLister{}, Picker: picker})

			if res := reg.DispatchSlashInput("/"+tc.command, host); res.Status != StatusHandled || res.Err != nil || res.Canonical != tc.command {
				t.Fatalf("dispatch /%s = %+v, want Handled/nil-err/%s", tc.command, res, tc.command)
			}
			if len(picker.presented) != 1 || picker.deps.tab != tc.tab {
				t.Fatalf("presented %d times with tab %d, want once with tab %d", len(picker.presented), picker.deps.tab, tc.tab)
			}
			evs := host.events()
			if len(evs) != 1 {
				t.Fatalf("slash_command events = %v, want one", evs)
			}
			if ev := decodeSlash(t, evs[0]); ev.Name != tc.command || ev.Outcome != "success" {
				t.Fatalf("slash_command = %+v, want %s success", ev, tc.command)
			}
			if picker.slashEvtAtPresent != 1 || picker.flushesAtPresent != 1 {
				t.Fatalf("at Present: events %d flushes %d, want 1 and 1", picker.slashEvtAtPresent, picker.flushesAtPresent)
			}
		})
	}
}

func TestOpenRouterAndSettingsHandlers_DoNotPresentWhenAppendOrFlushFails(t *testing.T) {
	for _, command := range []string{"openrouter", "settings"} {
		t.Run(command+" append", func(t *testing.T) {
			picker := &fakeSettingsPicker{}
			cmd, _ := newSettingsAndOpenRouterRegistry(SettingsDeps{Lister: &fakePermissionLister{}, Picker: picker}).resolve(command)
			if err := cmd.Handler(&appendFailContext{}, nil); err == nil {
				t.Fatal("handler returned nil on an append failure")
			}
			if len(picker.presented) != 0 {
				t.Fatal("picker presented after an append failure")
			}
		})
		t.Run(command+" flush", func(t *testing.T) {
			picker := &fakeSettingsPicker{}
			flushErr := errors.New("flush failed")
			reg := newSettingsAndOpenRouterRegistry(SettingsDeps{Lister: &fakePermissionLister{}, Picker: picker})
			if res := reg.DispatchSlashInput("/"+command, newFlushErrHost(flushErr)); !errors.Is(res.Err, flushErr) {
				t.Fatalf("dispatch err = %v, want the flush error", res.Err)
			}
			if len(picker.presented) != 0 {
				t.Fatal("picker presented after a flush failure")
			}
		})
	}
}

func TestOpenRouterHandler_RejectsAnArgumentBeforeRunning(t *testing.T) {
	host := newFakeHost()
	picker := &fakeSettingsPicker{}
	res := newSettingsAndOpenRouterRegistry(SettingsDeps{Lister: &fakePermissionLister{}, Picker: picker}).DispatchSlashInput("/openrouter extra", host)

	if res.Status != StatusWrongArity || res.Canonical != "openrouter" || !res.RetainInput {
		t.Fatalf("dispatch = %+v, want WrongArity for openrouter with input retained", res)
	}
	if len(picker.presented) != 0 || len(host.events()) != 0 {
		t.Fatalf("presented %d, events %d; want neither", len(picker.presented), len(host.events()))
	}
}
