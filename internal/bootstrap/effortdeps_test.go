// Tests for the production tui.EffortApplier (effortdeps.go) driven end-to-end
// through the shared BuildRegistry builder over a real model.ActiveState and the real
// config persistence chokepoint: clean flow, active-write failure (degraded), and
// silent mirror failure, with the ordering and source transition.
package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/tui"
)

func TestEffortApplier_CleanFlow_ChangeWriteMirrorSourcePicker(t *testing.T) {
	ctx := context.Background()
	projectRoot := t.TempDir()
	home := t.TempDir()
	store := storeAt(t, filepath.Join(t.TempDir(), "s.json"), "id-clean", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)
	active := selectedState() // openai/gpt-5.5/medium, source resume

	effortDeps := newEffortDeps(ctx, app, providerCache(t, projectRoot), active, home)
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"effort": tui.NewEffortHandler(effortDeps)})
	host := &recordingHost{store: store}

	res := reg.DispatchSlashInput("/effort high", host)
	if res.Status != tui.StatusHandled || res.Canonical != "effort" || res.Err != nil {
		t.Fatalf("dispatch result = %+v, want {handled, effort, no error}", res)
	}

	changed := decodeModelChanged(t, store)
	if len(changed) != 1 {
		t.Fatalf("model_changed events = %d, want 1", len(changed))
	}
	if mc := changed[0]; mc.NewProvider != "openai" || mc.NewModelID != "gpt-5.5" || mc.NewEffort != "high" ||
		mc.PriorProvider != "openai" || mc.PriorModelID != "gpt-5.5" || mc.PriorEffort != "medium" {
		t.Fatalf("model_changed = %+v, want new openai/gpt-5.5/high, prior openai/gpt-5.5/medium (only effort differs)", changed[0])
	}
	if n := len(kindEvents(t, store, events.KindModelPersistFailed)); n != 0 {
		t.Fatalf("model_persist_failed = %d, want 0 on the clean path", n)
	}
	if n := len(kindEvents(t, store, events.KindModelGlobalMirrorFailed)); n != 0 {
		t.Fatalf("model_global_mirror_failed = %d, want 0 on the clean path", n)
	}
	// The transaction flushes the session at the durability
	// point, so the session file on disk — not just the in-memory store — must
	// carry both the handler's slash_command and PersistPickerSelection's
	// model_changed before the settings writes count as a clean apply. Fails if the
	// registry dispatch adapter path appends those records but bypasses the session flush.
	assertFileContains(t, store.Path(), "slash_command")
	assertFileContains(t, store.Path(), "model_changed")
	assertFileContains(t, config.LocalSettingsPath(projectRoot), "high")
	if _, err := os.Stat(filepath.Join(projectRoot, ".codemeld", "settings.yaml")); !os.IsNotExist(err) {
		t.Fatalf("shared settings.yaml must stay absent; stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".codemeld", "global", "settings.yaml")); err != nil {
		t.Fatalf("model.last_used mirror not written: %v", err)
	}
	if _, src, _ := active.Current(); src != model.SourcePicker {
		t.Fatalf("active source = %q, want picker", src)
	}
}

func TestEffortApplier_ActiveWriteFailure_DegradesSkipsMirror(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	// A regular file as the project root makes <root>/.codemeld uncreatable, so the
	// per-project model.active write fails deterministically (parent_dir_error).
	projectRoot := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(projectRoot, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := storeAt(t, filepath.Join(t.TempDir(), "s.json"), "id-deg", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)
	active := selectedState()

	effortDeps := newEffortDeps(ctx, app, providerCache(t, projectRoot), active, home)
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"effort": tui.NewEffortHandler(effortDeps)})
	host := &recordingHost{store: store}

	res := reg.DispatchSlashInput("/effort high", host)
	if res.Status != tui.StatusHandled || res.Err != nil {
		t.Fatalf("dispatch result = %+v, want handled with no error (a persistence degrade is not a dispatch error)", res)
	}

	kinds := eventKinds(store.Records())
	ci, pi := slices.Index(kinds, events.KindModelChanged), slices.Index(kinds, events.KindModelPersistFailed)
	if ci < 0 || pi < 0 || ci > pi {
		t.Fatalf("event kinds = %v, want model_changed before model_persist_failed", kinds)
	}
	if n := len(kindEvents(t, store, events.KindModelGlobalMirrorFailed)); n != 0 {
		t.Fatalf("model_global_mirror_failed = %d, want 0 (mirror skipped when the active write fails)", n)
	}
	if _, err := os.Stat(filepath.Join(home, ".codemeld", "global", "settings.yaml")); !os.IsNotExist(err) {
		t.Fatalf("model.last_used mirror must be absent on active-write failure; stat err = %v", err)
	}
	if _, src, _ := active.Current(); src != model.SourcePickerDegraded {
		t.Fatalf("active source = %q, want picker_degraded", src)
	}
}

// TestSubmitBoundary_EffortRejectEventIsDurableOnDisk pins that an
// /effort validation rejection appends slash_command{outcome:error} and must flush
// it so the recorded error is durable on disk, not left in memory
// until some unrelated later flush. Validation rejects before the apply
// transaction, so the reject path is the only flush boundary. It fails if
// rejectEffort's FlushActive call is removed — the store is then never flushed and
// the file is absent / missing the error record.
func TestSubmitBoundary_EffortRejectEventIsDurableOnDisk(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	app.SetCommandFlush(newCommandFlush(ctx, app))

	effortDeps := newEffortDeps(ctx, app, providerCache(t, t.TempDir()), selectedState(), t.TempDir())
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"effort": tui.NewEffortHandler(effortDeps)})

	if tui.NewSubmitFunc(reg, app, nil)("/effort turbo") {
		t.Fatal("/effort turbo must be rejected (retain), not accepted")
	}
	assertFileContains(t, store.Path(), "slash_command")
	assertFileContains(t, store.Path(), "unsupported effort turbo")
}

// TestSubmitBoundary_EffortCancelledFlushRejectsAndPersistsNothing pins the
// production EffortApplier: when the session flush
// inside PersistPickerSelection fails without a write reason (here a cancelled run
// context, which Store.Flush reports as ("", ReasonNone, ctx.Err()) before any
// write), the apply must stop before writing model.active / model.last_used and
// before the picker source transition, surfacing the error so the submit is
// rejected and the typed input retained for a retry. The store path is writable, so
// cancellation is the only reason the flush fails. It fails if persist.go ignores a
// ReasonNone flush failure and proceeds to the settings writes and ApplyUserSelection.
func TestSubmitBoundary_EffortCancelledFlushRejectsAndPersistsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	projectRoot := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	app.SetCommandFlush(newCommandFlush(ctx, app))
	active := selectedState() // openai/gpt-5.5/medium, source resume

	effortDeps := newEffortDeps(ctx, app, providerCache(t, projectRoot), active, home)
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"effort": tui.NewEffortHandler(effortDeps)})

	if tui.NewSubmitFunc(reg, app, nil)("/effort high") {
		t.Fatal("/effort high on a cancelled run context must be rejected (retain), not accepted")
	}
	if _, err := os.Stat(filepath.Join(projectRoot, ".codemeld", "settings.yaml")); !os.IsNotExist(err) {
		t.Fatalf("model.active must be absent after a non-write flush failure; stat err = %v", err)
	}
	if _, err := os.Stat(config.LocalSettingsPath(projectRoot)); !os.IsNotExist(err) {
		t.Fatalf("local model.active must be absent after a non-write flush failure; stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".codemeld", "global", "settings.yaml")); !os.IsNotExist(err) {
		t.Fatalf("model.last_used must be absent after a non-write flush failure; stat err = %v", err)
	}
	if _, err := os.Stat(store.Path()); !os.IsNotExist(err) {
		t.Fatalf("session file must be absent after a cancelled flush; stat err = %v", err)
	}
	if _, src, _ := active.Current(); src != model.SourceResume {
		t.Fatalf("active source = %q, want resume (no picker transition on a non-write flush failure)", src)
	}
}

func TestEffortApplier_MirrorFailure_SilentNotDegraded(t *testing.T) {
	ctx := context.Background()
	projectRoot := t.TempDir()
	// A regular file as home makes the global mirror target uncreatable while the
	// per-project write still succeeds.
	home := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(home, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := storeAt(t, filepath.Join(t.TempDir(), "s.json"), "id-mirror", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)
	active := selectedState()

	effortDeps := newEffortDeps(ctx, app, providerCache(t, projectRoot), active, home)
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"effort": tui.NewEffortHandler(effortDeps)})
	host := &recordingHost{store: store}

	if res := reg.DispatchSlashInput("/effort high", host); res.Err != nil {
		t.Fatalf("dispatch error = %v, want nil (a mirror failure is silent)", res.Err)
	}
	if n := len(kindEvents(t, store, events.KindModelGlobalMirrorFailed)); n != 1 {
		t.Fatalf("model_global_mirror_failed = %d, want 1", n)
	}
	if n := len(kindEvents(t, store, events.KindModelPersistFailed)); n != 0 {
		t.Fatalf("model_persist_failed = %d, want 0 (the active write succeeded)", n)
	}
	assertFileContains(t, config.LocalSettingsPath(projectRoot), "high")
	if _, err := os.Stat(filepath.Join(projectRoot, ".codemeld", "settings.yaml")); !os.IsNotExist(err) {
		t.Fatalf("shared settings.yaml must stay absent; stat err = %v", err)
	}
	if _, src, _ := active.Current(); src != model.SourcePicker {
		t.Fatalf("active source = %q, want picker (a mirror failure does not degrade)", src)
	}
}
