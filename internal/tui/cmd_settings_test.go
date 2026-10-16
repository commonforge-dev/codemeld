package tui

import (
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
