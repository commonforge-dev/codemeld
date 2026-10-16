// Tests for model-selection persistence: path/key selection and ordered YAML
// shape, model_changed prior-field behavior, the lock_timeout canonical detail,
// and the picker-selection write flow's degraded, silent-mirror, and
// flush-failure routing paths.
package model

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// recordingUI captures the one-line notices the picker flow renders, so tests can
// assert which failures surface to the user and which stay silent.
type recordingUI struct{ notices []string }

func (r *recordingUI) Notice(text string) { r.notices = append(r.notices, text) }

// newFlushStore returns a store with a valid session that flushes to path, so
// tests can exercise the real flush boundary.
func newFlushStore(path string) *sessions.Store {
	return sessions.New(path, &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
			Folder:        "/home/u/proj",
			StartedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			UpdatedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			SchemaVersion: 1,
		},
	})
}

// setPersist swaps the config.Persist seam for the duration of a test.
func setPersist(t *testing.T, fn func(string, string, any) (config.PersistReason, fserrors.Category, error)) {
	t.Helper()
	orig := persist
	persist = fn
	t.Cleanup(func() { persist = orig })
}

func setPersistLocal(t *testing.T, fn func(string, string, any) (bool, config.PersistReason, fserrors.Category, error)) {
	t.Helper()
	orig := persistLocal
	persistLocal = fn
	t.Cleanup(func() { persistLocal = orig })
}

func sampleSelection() Selection {
	return Selection{Provider: "openai", ID: "gpt-5", Effort: "high"}
}

func TestSelectionYAML_ProviderIDEffortOrder(t *testing.T) {
	out, err := yaml.Marshal(selectionYAML(sampleSelection()))
	if err != nil {
		t.Fatalf("marshal selection: %v", err)
	}
	got := string(out)
	pi := strings.Index(got, "provider")
	ii := strings.Index(got, "id")
	ei := strings.Index(got, "effort")
	if pi < 0 || ii < 0 || ei < 0 {
		t.Fatalf("missing a key in %q", got)
	}
	if pi >= ii || ii >= ei {
		t.Fatalf("keys not in provider, id, effort order: %q", got)
	}
	if strings.Contains(got, "model_id") {
		t.Fatalf("on-disk field must be id, not model_id: %q", got)
	}
}

func TestWriteActive_CleanSucceedsWritesCommentBlockAndMapping(t *testing.T) {
	root := t.TempDir()
	path, created, reason, errCat, err := WriteActive(root, sampleSelection())
	if err != nil || reason != config.ReasonNone || errCat != "" {
		t.Fatalf("WriteActive() = (reason=%q, cat=%q, err=%v), want clean success", reason, errCat, err)
	}
	if !created {
		t.Fatal("created = false, want true for a write that made the local file")
	}
	want := config.LocalSettingsPath(root)
	if path != want {
		t.Fatalf("target path = %q, want %q", path, want)
	}
	if _, serr := os.Stat(filepath.Join(root, ".codemeld", "settings.yaml")); !os.IsNotExist(serr) {
		t.Fatalf("shared settings.yaml must stay absent; stat err = %v", serr)
	}
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("read settings file: %v", rerr)
	}
	body := string(data)
	wantHead := "model:\n" +
		"  # This file holds this machine's own settings for this project; it is not shared with the team.\n" +
		"  # model.active is rewritten whenever you pick a model in this project.\n" +
		"  # Manual edits to this key will be overwritten the next time you pick a model here.\n" +
		"  active:\n"
	if !strings.HasPrefix(body, wantHead) {
		t.Fatalf("settings file does not start with the model.active comment block:\n--- got ---\n%s\n--- want prefix ---\n%s", body, wantHead)
	}
	if _, cat, verr := config.ValidateLocalSettingsBytes(data, path); verr != nil || cat != config.LoadOK {
		t.Fatalf("ValidateLocalSettingsBytes() = (cat=%v, err=%v), want LoadOK", cat, verr)
	}
	for _, sub := range []string{"provider: openai", "id: gpt-5", "effort: high"} {
		if !strings.Contains(body, sub) {
			t.Fatalf("settings file missing %q:\n%s", sub, body)
		}
	}

	var doc map[string]any
	if uerr := yaml.Unmarshal(data, &doc); uerr != nil {
		t.Fatalf("parse local settings: %v", uerr)
	}
	if len(doc) != 1 || doc["model"] == nil {
		t.Fatalf("local settings top-level keys = %+v, want model only", doc)
	}
	sub, ok := doc["model"].(map[string]any)
	if !ok || len(sub) != 1 || sub["active"] == nil {
		t.Fatalf("model subkeys = %+v, want active only", doc["model"])
	}

	_, created, _, _, err = WriteActive(root, sampleSelection())
	if err != nil {
		t.Fatalf("second WriteActive() error = %v", err)
	}
	if created {
		t.Fatal("created = true on a second write, want false (the file already existed)")
	}
}

func TestWriteLastUsed_CleanSucceedsResolvesGlobalPath(t *testing.T) {
	home := t.TempDir()
	path, reason, errCat, err := WriteLastUsed(home, sampleSelection())
	if err != nil || reason != config.ReasonNone || errCat != "" {
		t.Fatalf("WriteLastUsed() = (reason=%q, cat=%q, err=%v), want clean success", reason, errCat, err)
	}
	want := filepath.Join(home, ".codemeld", "global", "settings.yaml")
	if path != want {
		t.Fatalf("target path = %q, want %q", path, want)
	}
	if _, serr := os.Stat(path); serr != nil {
		t.Fatalf("global settings file not written: %v", serr)
	}
}

func TestEmitModelChanged_NoPriorOmitsAllPriorFields(t *testing.T) {
	store := newTurnStore()
	if err := EmitModelChanged(store, sampleSelection(), nil); err != nil {
		t.Fatalf("EmitModelChanged() error = %v", err)
	}
	evs := kindEvents(t, store, events.KindModelChanged)
	if len(evs) != 1 {
		t.Fatalf("model_changed events = %d, want 1", len(evs))
	}
	mc := decodePayload[events.ModelChanged](t, evs[0])
	if mc.NewProvider != "openai" || mc.NewModelID != "gpt-5" || mc.NewEffort != "high" {
		t.Fatalf("new fields = %+v, want openai/gpt-5/high", mc)
	}
	if mc.PriorProvider != "" || mc.PriorModelID != "" || mc.PriorEffort != "" {
		t.Fatalf("prior fields = %+v, want all empty when no prior", mc)
	}
}

func TestEmitModelChanged_WithPriorEmitsAllPriorFields(t *testing.T) {
	store := newTurnStore()
	prior := Selection{Provider: "openrouter", ID: "claude", Effort: "low"}
	if err := EmitModelChanged(store, sampleSelection(), &prior); err != nil {
		t.Fatalf("EmitModelChanged() error = %v", err)
	}
	mc := decodePayload[events.ModelChanged](t, kindEvents(t, store, events.KindModelChanged)[0])
	if mc.PriorProvider != "openrouter" || mc.PriorModelID != "claude" || mc.PriorEffort != "low" {
		t.Fatalf("prior fields = %+v, want openrouter/claude/low", mc)
	}
}

func TestEmitModelPersistFailed_LockTimeoutCanonicalDetail(t *testing.T) {
	store := newTurnStore()
	// config.Persist surfaces the raw context-deadline error for lock_timeout, but
	// the event must carry the canonical detail and omit error_category.
	err := EmitModelPersistFailed(store, "/p/.codemeld/settings.yaml", sampleSelection(),
		config.ReasonLockTimeout, "", errors.New("context deadline exceeded"))
	if err != nil {
		t.Fatalf("EmitModelPersistFailed() error = %v", err)
	}
	mpf := decodePayload[events.ModelPersistFailed](t, kindEvents(t, store, events.KindModelPersistFailed)[0])
	if mpf.ErrorDetail != lockTimeoutDetail {
		t.Fatalf("error_detail = %q, want %q", mpf.ErrorDetail, lockTimeoutDetail)
	}
	if mpf.ErrorCategory != "" {
		t.Fatalf("error_category = %q, want empty for lock_timeout", mpf.ErrorCategory)
	}
}

func TestPersistPickerSelection_CleanFlow(t *testing.T) {
	projectRoot := t.TempDir()
	home := t.TempDir()
	sessionPath := filepath.Join(t.TempDir(), "session.json")
	store := newFlushStore(sessionPath)
	ui := &recordingUI{}

	res, err := PersistPickerSelection(context.Background(), store, ui, sampleSelection(), nil, projectRoot, home)
	if err != nil {
		t.Fatalf("PersistPickerSelection() error = %v", err)
	}
	if res.Degraded {
		t.Fatalf("result degraded on a clean flow, want not degraded")
	}
	if len(ui.notices) != 1 || !strings.Contains(ui.notices[0], config.LocalSettingsPath(projectRoot)) {
		t.Fatalf("notices on a clean first pick = %v, want the local-settings ignore notice", ui.notices)
	}
	if !strings.Contains(ui.notices[0], config.LocalSettingsLockPath(projectRoot)) {
		t.Fatalf("ignore notice = %q, want it to name the .lock sidecar", ui.notices[0])
	}

	// model_changed is the first record (emitted before the flush and before the
	// settings write), and no persist-failure events were appended.
	recs := store.Records()
	if len(recs) == 0 {
		t.Fatal("no records appended")
	}
	if first, ok := recs[0].(sessions.Event); !ok || first.Kind != events.KindModelChanged {
		t.Fatalf("first record = %+v, want a model_changed event", recs[0])
	}
	if got := kindEvents(t, store, events.KindModelPersistFailed); len(got) != 0 {
		t.Fatalf("model_persist_failed events = %d, want 0", len(got))
	}

	// The flush durably wrote model_changed before the settings write, and both
	// settings files exist.
	sessData, rerr := os.ReadFile(sessionPath)
	if rerr != nil {
		t.Fatalf("read session file: %v", rerr)
	}
	if !strings.Contains(string(sessData), events.KindModelChanged) {
		t.Fatalf("flushed session file missing model_changed:\n%s", sessData)
	}
	if _, serr := os.Stat(config.LocalSettingsPath(projectRoot)); serr != nil {
		t.Fatalf("model.active not written to the local settings file: %v", serr)
	}
	if _, serr := os.Stat(filepath.Join(projectRoot, ".codemeld", "settings.yaml")); !os.IsNotExist(serr) {
		t.Fatalf("shared settings.yaml must stay absent; stat err = %v", serr)
	}
	if _, serr := os.Stat(filepath.Join(home, ".codemeld", "global", "settings.yaml")); serr != nil {
		t.Fatalf("model.last_used not written: %v", serr)
	}

	ui.notices = nil
	if _, err := PersistPickerSelection(context.Background(), store, ui, sampleSelection(), nil, projectRoot, home); err != nil {
		t.Fatalf("second PersistPickerSelection() error = %v", err)
	}
	if len(ui.notices) != 0 {
		t.Fatalf("notices on a second pick = %v, want none (the local file already existed)", ui.notices)
	}
}

func TestPersistPickerSelection_SharedProjectSettingsUntouched(t *testing.T) {
	projectRoot := t.TempDir()
	home := t.TempDir()
	shared := filepath.Join(projectRoot, ".codemeld", "settings.yaml")
	if err := os.MkdirAll(filepath.Dir(shared), 0o755); err != nil {
		t.Fatal(err)
	}
	original := "model:\n  active:\n    provider: openrouter\n    id: pre-split\n    effort: low\n"
	if err := os.WriteFile(shared, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	beforeStat, err := os.Stat(shared)
	if err != nil {
		t.Fatal(err)
	}

	store := newFlushStore(filepath.Join(t.TempDir(), "session.json"))
	ui := &recordingUI{}
	if _, err := PersistPickerSelection(context.Background(), store, ui, sampleSelection(), nil, projectRoot, home); err != nil {
		t.Fatalf("PersistPickerSelection() error = %v", err)
	}

	after, err := os.ReadFile(shared)
	if err != nil {
		t.Fatalf("read shared settings: %v", err)
	}
	if string(after) != original {
		t.Fatalf("shared settings.yaml changed:\n--- got ---\n%s\n--- want ---\n%s", after, original)
	}
	afterStat, err := os.Stat(shared)
	if err != nil {
		t.Fatal(err)
	}
	if !afterStat.ModTime().Equal(beforeStat.ModTime()) {
		t.Fatalf("shared settings.yaml mtime changed: %v -> %v", beforeStat.ModTime(), afterStat.ModTime())
	}
	if got := readPersistedEffort(t, config.LocalSettingsPath(projectRoot), config.KeyModelActive); got != "high" {
		t.Fatalf("local model.active effort = %q, want high", got)
	}
}

func TestPersistPickerSelection_ExistingLocalFileEmitsNoNotice(t *testing.T) {
	projectRoot := t.TempDir()
	home := t.TempDir()
	localPath := config.LocalSettingsPath(projectRoot)
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPath, []byte("model: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	store := newFlushStore(filepath.Join(t.TempDir(), "session.json"))
	ui := &recordingUI{}
	if _, err := PersistPickerSelection(context.Background(), store, ui, sampleSelection(), nil, projectRoot, home); err != nil {
		t.Fatalf("PersistPickerSelection() error = %v", err)
	}
	if len(ui.notices) != 0 {
		t.Fatalf("notices = %v, want none for a project whose local file already existed", ui.notices)
	}
}

func TestPersistPickerSelection_LockTimeoutDegradesNamingLocalPath(t *testing.T) {
	projectRoot := t.TempDir()
	setPersistLocal(t, func(string, string, any) (bool, config.PersistReason, fserrors.Category, error) {
		return false, config.ReasonLockTimeout, "", errors.New("context deadline exceeded")
	})
	store := newFlushStore(filepath.Join(t.TempDir(), "session.json"))
	ui := &recordingUI{}

	res, err := PersistPickerSelection(context.Background(), store, ui, sampleSelection(), nil, projectRoot, t.TempDir())
	if err != nil {
		t.Fatalf("PersistPickerSelection() error = %v", err)
	}
	if !res.Degraded {
		t.Fatal("result not degraded after a lock_timeout active write, want degraded")
	}
	evs := kindEvents(t, store, events.KindModelPersistFailed)
	if len(evs) != 1 {
		t.Fatalf("model_persist_failed events = %d, want 1", len(evs))
	}
	mpf := decodePayload[events.ModelPersistFailed](t, evs[0])
	if mpf.TargetPath != config.LocalSettingsPath(projectRoot) {
		t.Fatalf("target_path = %q, want %q", mpf.TargetPath, config.LocalSettingsPath(projectRoot))
	}
	if mpf.Provider != "openai" || mpf.ModelID != "gpt-5" || mpf.Effort != "high" {
		t.Fatalf("selection fields = %+v, want openai/gpt-5/high", mpf)
	}
	if mpf.Reason != string(config.ReasonLockTimeout) || mpf.ErrorDetail != lockTimeoutDetail {
		t.Fatalf("reason/detail = (%q, %q), want (lock_timeout, %q)", mpf.Reason, mpf.ErrorDetail, lockTimeoutDetail)
	}
	if len(ui.notices) != 1 || !strings.Contains(ui.notices[0], config.LocalSettingsPath(projectRoot)) {
		t.Fatalf("notices = %v, want one failure notice naming the local path", ui.notices)
	}
}

func readPersistedEffort(t *testing.T, path, key string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var cur any = doc
	for _, segment := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%s: %q is not a mapping in:\n%s", path, key, data)
		}
		cur = m[segment]
	}
	effort, ok := cur.(map[string]any)["effort"]
	if !ok {
		t.Fatalf("%s: %s carries no effort in:\n%s", path, key, data)
	}
	return effort.(string)
}

func TestWriteSelection_PersistsEffortTokenVerbatim(t *testing.T) {
	for _, effort := range []string{EffortNoReasoning, EffortDefault} {
		t.Run(effort, func(t *testing.T) {
			sel := Selection{Provider: "openai", ID: "gpt-5", Effort: effort}
			activePath, _, reason, errCat, err := WriteActive(t.TempDir(), sel)
			if err != nil || reason != config.ReasonNone || errCat != "" {
				t.Fatalf("WriteActive() = (reason=%q, cat=%q, err=%v), want clean success", reason, errCat, err)
			}
			if got := readPersistedEffort(t, activePath, config.KeyModelActive); got != effort {
				t.Fatalf("model.active effort = %q, want %q verbatim", got, effort)
			}
			lastUsedPath, reason, errCat, err := WriteLastUsed(t.TempDir(), sel)
			if err != nil || reason != config.ReasonNone || errCat != "" {
				t.Fatalf("WriteLastUsed() = (reason=%q, cat=%q, err=%v), want clean success", reason, errCat, err)
			}
			if got := readPersistedEffort(t, lastUsedPath, config.KeyModelLastUsed); got != effort {
				t.Fatalf("model.last_used effort = %q, want %q verbatim", got, effort)
			}
		})
	}
}

func TestPersistPickerSelection_PersistsAdvertisedDefaultVerbatim(t *testing.T) {
	projectRoot := t.TempDir()
	home := t.TempDir()
	store := newFlushStore(filepath.Join(t.TempDir(), "session.json"))
	sel := Selection{Provider: "openai", ID: "gpt-5", Effort: EffortDefault}

	res, err := PersistPickerSelection(context.Background(), store, &recordingUI{}, sel, nil, projectRoot, home)
	if err != nil {
		t.Fatalf("PersistPickerSelection() error = %v", err)
	}
	if res.Degraded {
		t.Fatal("result degraded on a clean flow, want not degraded")
	}
	activePath := config.LocalSettingsPath(projectRoot)
	if got := readPersistedEffort(t, activePath, config.KeyModelActive); got != EffortDefault {
		t.Fatalf("model.active effort = %q, want %q verbatim", got, EffortDefault)
	}
	lastUsedPath := filepath.Join(home, ".codemeld", "global", "settings.yaml")
	if got := readPersistedEffort(t, lastUsedPath, config.KeyModelLastUsed); got != EffortDefault {
		t.Fatalf("model.last_used effort = %q, want %q verbatim", got, EffortDefault)
	}
}

func TestPersistPickerSelection_ActiveWriteFailureDegrades(t *testing.T) {
	setPersistLocal(t, func(string, string, any) (bool, config.PersistReason, fserrors.Category, error) {
		return false, config.ReasonWriteError, fserrors.PermissionDenied, errors.New("boom")
	})
	store := newFlushStore(filepath.Join(t.TempDir(), "session.json"))
	ui := &recordingUI{}

	res, err := PersistPickerSelection(context.Background(), store, ui, sampleSelection(), nil, t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatalf("PersistPickerSelection() error = %v", err)
	}
	if !res.Degraded {
		t.Fatalf("result not degraded after model.active failure, want degraded")
	}
	if got := kindEvents(t, store, events.KindModelPersistFailed); len(got) != 1 {
		t.Fatalf("model_persist_failed events = %d, want 1", len(got))
	}
	// The flow returns before the mirror, so no global mirror failure is recorded.
	if got := kindEvents(t, store, events.KindModelGlobalMirrorFailed); len(got) != 0 {
		t.Fatalf("model_global_mirror_failed events = %d, want 0 when active write fails first", len(got))
	}
	if len(ui.notices) != 1 {
		t.Fatalf("notices = %v, want exactly one persist-failure notice", ui.notices)
	}
}

func TestPersistPickerSelection_MirrorFailureIsSilent(t *testing.T) {
	// model.active succeeds; only the global model.last_used mirror fails.
	setPersistLocal(t, func(string, string, any) (bool, config.PersistReason, fserrors.Category, error) {
		return false, config.ReasonNone, "", nil
	})
	setPersist(t, func(string, string, any) (config.PersistReason, fserrors.Category, error) {
		return config.ReasonWriteError, fserrors.PermissionDenied, errors.New("mirror boom")
	})
	store := newFlushStore(filepath.Join(t.TempDir(), "session.json"))
	ui := &recordingUI{}

	res, err := PersistPickerSelection(context.Background(), store, ui, sampleSelection(), nil, t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatalf("PersistPickerSelection() error = %v", err)
	}
	if res.Degraded {
		t.Fatalf("result degraded on a mirror-only failure, want not degraded")
	}
	if got := kindEvents(t, store, events.KindModelGlobalMirrorFailed); len(got) != 1 {
		t.Fatalf("model_global_mirror_failed events = %d, want 1", len(got))
	}
	if got := kindEvents(t, store, events.KindModelPersistFailed); len(got) != 0 {
		t.Fatalf("model_persist_failed events = %d, want 0 on a clean active write", len(got))
	}
	// The mirror failure is silent: no user-facing notice.
	if len(ui.notices) != 0 {
		t.Fatalf("notices on a silent mirror failure = %v, want none", ui.notices)
	}
}

func TestPersistPickerSelection_FlushFailureRoutedThroughG250(t *testing.T) {
	projectRoot := t.TempDir()
	home := t.TempDir()
	// A missing parent directory makes the session flush fail with parent_dir_error.
	sessionPath := filepath.Join(t.TempDir(), "no-such-subdir", "session.json")
	store := newFlushStore(sessionPath)
	ui := tui.New(nil)

	res, err := PersistPickerSelection(context.Background(), store, ui, sampleSelection(), nil, projectRoot, home)
	if err != nil {
		t.Fatalf("PersistPickerSelection() error = %v", err)
	}
	if res.Degraded {
		t.Fatalf("result degraded, want not degraded (only the flush failed)")
	}
	// model_changed precedes the flush; the write-failure protocol appends session_write_failed after.
	if first, ok := store.Records()[0].(sessions.Event); !ok || first.Kind != events.KindModelChanged {
		t.Fatalf("first record = %+v, want model_changed", store.Records()[0])
	}
	if got := kindEvents(t, store, events.KindSessionWriteFailed); len(got) != 1 {
		t.Fatalf("session_write_failed events = %d, want 1 (flush failure routed through g250)", len(got))
	}
	// Both messages have to survive in the production sink, which keeps one notice.
	notice := ui.NoticeText()
	for _, sub := range []string{
		sessionPath,
		string(sessions.ReasonParentDirError),
		config.LocalSettingsPath(projectRoot),
		config.LocalSettingsLockPath(projectRoot),
	} {
		if !strings.Contains(notice, sub) {
			t.Fatalf("App notice = %q, want it to name %q", notice, sub)
		}
	}
	// The sequence still proceeds to the settings write after routing the failure.
	if _, serr := os.Stat(config.LocalSettingsPath(projectRoot)); serr != nil {
		t.Fatalf("model.active not written after flush failure: %v", serr)
	}
}
