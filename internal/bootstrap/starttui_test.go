// Tests for the production step-8 launch: StartTUI assembly + run, the
// DefaultFreshSteps wiring (real, not a no-op), and the submit-boundary
// reachability of the production registry's /new, /status, and plain-prompt paths.
// Shared test helpers for the bootstrap dependency tests live here.
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/goccy/go-yaml"
	"github.com/openai/openai-go/v3"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/trust"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/turn"
	"codemeld.dev/codemeld/internal/vcs"
)

var testStart = time.Date(2026, 5, 28, 9, 0, 0, 0, time.UTC)

// storeAt builds a real session store with valid metadata at path.
func storeAt(t *testing.T, path, id, folder string) *sessions.Store {
	t.Helper()
	return sessions.New(path, &sessions.Session{Metadata: sessions.Metadata{
		ID:            id,
		Folder:        folder,
		StartedAt:     testStart,
		UpdatedAt:     testStart,
		SchemaVersion: sessions.CurrentSchemaVersion,
	}})
}

// mkStore is a writable default store (a temp path so Flush succeeds).
func mkStore(t *testing.T) *sessions.Store {
	t.Helper()
	return storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-000000000001", "/proj")
}

// titledStore is a writable store that already carries a title, so the first-turn
// auto-title hook returns before it generates one: a test that reads the session file
// the production turn wrote then has no later rewrite racing its assertion.
func titledStore(t *testing.T) *sessions.Store {
	t.Helper()
	store := mkStore(t)
	if _, _, err := store.FlushTitle(context.Background(), "ask user"); err != nil {
		t.Fatalf("seed title: %v", err)
	}
	return store
}

// unwritableStore is a store whose session path sits under a regular file, so
// every Flush fails deterministically with a real write reason (and a valid,
// non-empty target path for the session_write_failed event).
func unwritableStore(t *testing.T, id, folder string) *sessions.Store {
	t.Helper()
	base := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(base, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	return storeAt(t, filepath.Join(base, "session.json"), id, folder)
}

// recordingHost is a tui.CommandHost backed by a real store; it records the
// notices, panels, and status overlays dispatch rendered.
type recordingHost struct {
	store    *sessions.Store
	notices  []string
	panels   []string
	statuses []string
}

func (h *recordingHost) Notice(text string)     { h.notices = append(h.notices, text) }
func (h *recordingHost) ShowPanel(text string)  { h.panels = append(h.panels, text) }
func (h *recordingHost) ShowStatus(text string) { h.statuses = append(h.statuses, text) }
func (h *recordingHost) Store() *sessions.Store { return h.store }

// FlushActive is a no-op so the in-memory dispatch-reachability tests stay
// disk-free; the production command-event flush hook (newCommandFlush) and its
// on-disk durability are covered directly by the submit-boundary tests.
func (h *recordingHost) FlushActive() error { return nil }

// flushHookHost is a recordingHost whose FlushActive runs a wired flush hook
// (the production newCommandFlush) instead of the no-op, so a dispatch test can
// both observe the overlay/notice side effects and exercise the real
// command-event flush — e.g. proving a cancelled-context flush fails the handler
// before it opens its overlay.
type flushHookHost struct {
	recordingHost
	flush func() error
}

func (h *flushHookHost) FlushActive() error { return h.flush() }

// noopClear is a non-nil placeholder /clear handler for registries whose /clear
// path the test does not exercise (registry construction rejects a nil handler).
func noopClear(tui.CommandContext, []string) error { return nil }

func eventKinds(recs []sessions.Record) []string {
	var out []string
	for _, r := range recs {
		if ev, ok := r.(sessions.Event); ok {
			out = append(out, ev.Kind)
		}
	}
	return out
}

func kindEvents(t *testing.T, store *sessions.Store, kind string) []sessions.Event {
	t.Helper()
	var out []sessions.Event
	for _, r := range store.Records() {
		if ev, ok := r.(sessions.Event); ok && ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

func slashCmds(t *testing.T, store *sessions.Store) []events.SlashCommand {
	t.Helper()
	return decodeStoreEvents[events.SlashCommand](t, store, events.KindSlashCommand)
}

func decodeModelChanged(t *testing.T, store *sessions.Store) []events.ModelChanged {
	t.Helper()
	return decodeStoreEvents[events.ModelChanged](t, store, events.KindModelChanged)
}

func decodeInteractionMode(t *testing.T, store *sessions.Store) []events.InteractionMode {
	t.Helper()
	return decodeStoreEvents[events.InteractionMode](t, store, events.KindInteractionMode)
}

// selectedState is a run-scoped active state seeded with an openai/gpt-5.5/medium
// selection sourced from a resume, so an apply can be observed transitioning the
// source to picker / picker_degraded.
func selectedState() *model.ActiveState {
	return model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: "medium"}, model.SourceResume)
}

// selectedModeState is a run-scoped active mode seeded with Plan + user_command, so
// a /clear carry-forward emission records that originating source rather than a
// launch default — mirroring selectedState for the interaction-mode capability.
func selectedModeState() *mode.ActiveState {
	return mode.NewActiveState(mode.Plan, mode.SourceUserCommand)
}

// seedOpenAIDiscovered writes the given OpenAI configured-provider model ids into the
// models.yaml store beside globalSettingsPath, via the real store writer — the production
// read path config.NewCache derives a configured provider's selectable models from.
func seedOpenAIDiscovered(t *testing.T, globalSettingsPath string, ids ...string) {
	t.Helper()
	seedOpenAIDiscoveredWithEfforts(t, globalSettingsPath, []string{"medium", "high"}, ids...)
}

func seedOpenAIDiscoveredWithEfforts(t *testing.T, globalSettingsPath string, efforts []string, ids ...string) {
	t.Helper()
	models := make([]config.DiscoveredModel, len(ids))
	for i, id := range ids {
		options := make([]any, len(efforts))
		for j, effort := range efforts {
			options[j] = effort
		}
		models[i] = config.DiscoveredModel{ID: id, Capabilities: map[string]any{
			"supportsReasoningEffort": true,
			"reasoningEffortOptions":  options,
		}}
	}
	seedOpenAIDiscoveredModels(t, globalSettingsPath, models)
}

func seedOpenAIDiscoveredModels(t *testing.T, globalSettingsPath string, models []config.DiscoveredModel) {
	t.Helper()
	if err := config.UpdateDiscoveredModelsProvider(
		config.DiscoveredModelsPath(globalSettingsPath), "openai",
		config.DiscoveredProvider{Models: models},
	); err != nil {
		t.Fatalf("seed discovered openai models: %v", err)
	}
}

// providerCache builds a composed-config cache whose openai provider has the two
// catalog models the model/effort tests select against, seeded through the real
// discovered-model store beside a temporary global settings path.
func providerCache(t *testing.T, projectRoot string) *config.Cache {
	t.Helper()
	globalSettings := SettingsPath(t.TempDir())
	seedOpenAIDiscoveredWithEfforts(t, globalSettings, []string{"medium", "high", "xhigh"}, "gpt-5.5", "gpt-5.5-pro")
	composed := map[string]any{
		"provider": map[string]any{
			"openai": map[string]any{
				"base_url": "https://api.openai.com/v1",
				"api_key":  "sk-test",
			},
		},
	}
	cache, err := config.NewCache(composed, projectRoot, []string{globalSettings})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	return cache
}

func assertFileContains(t *testing.T, path, sub string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(data), sub) {
		t.Fatalf("%s does not contain %q; contents:\n%s", path, sub, data)
	}
}

func assertFileLacks(t *testing.T, path, sub string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if strings.Contains(string(data), sub) {
		t.Fatalf("%s unexpectedly contains %q; contents:\n%s", path, sub, data)
	}
}

func userMessageCount(store *sessions.Store) int {
	n := 0
	for _, r := range store.Records() {
		if m, ok := r.(sessions.Message); ok && m.Role == "user" {
			n++
		}
	}
	return n
}

// swapRunApp overrides the runApp seam and returns a restore function.
func swapRunApp(fn func(*tui.App) error) func() {
	prev := runApp
	runApp = fn
	return func() { runApp = prev }
}

func TestStartTUI_NilSession_ReturnsError(t *testing.T) {
	if err := StartTUI(context.Background(), &BootstrapResult{}, io.Discard); err == nil {
		t.Fatal("StartTUI must error when the result carries no active session")
	}
}

func TestStartTUI_BuildsAppAndRunsEventLoop(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	if ran.ActiveStore() != store {
		t.Fatal("StartTUI did not install the bootstrap session as the active store")
	}
}

func TestStartTUI_RenamePersistsUserNameAndShowsBadge(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	if _, _, err := store.FlushTitle(context.Background(), "Earlier name"); err != nil {
		t.Fatalf("seed an already-named session: %v", err)
	}
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	if got := ran.SessionBadgeText(); !strings.Contains(got, "Earlier name") {
		t.Errorf("badge = %q, want it for a session already named when the run started", got)
	}

	if !ran.SubmitInput("/rename My session") {
		t.Fatal("installed submit rejected a /rename whose write succeeds")
	}
	badge := ran.SessionBadgeText()
	if !strings.Contains(badge, "My session") {
		t.Errorf("badge = %q, want the persistent session name after /rename", badge)
	}
	if strings.Contains(badge, "Earlier name") {
		t.Errorf("badge = %q, still shows the pre-rename name", badge)
	}

	sess, _, oerr := sessions.OpenSession(store.Path())
	if oerr != nil {
		t.Fatalf("reopen the session file: %v", oerr)
	}
	if sess.Metadata.Title != "My session" || sess.Metadata.TitleSource != sessions.TitleSourceUser {
		t.Errorf("persisted (title, source) = (%q, %q), want (%q, %q)", sess.Metadata.Title, sess.Metadata.TitleSource, "My session", sessions.TitleSourceUser)
	}
	if !sess.Metadata.UpdatedAt.Equal(testStart) {
		t.Errorf("updated_at = %s after /rename, want it unchanged at %s", sess.Metadata.UpdatedAt, testStart)
	}
}

func TestStartTUI_RenameWriteFailureKeepsProtocolAndShowsNoBadge(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	sessionDir := filepath.Join(t.TempDir(), "sessions")
	if err := os.Mkdir(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store := storeAt(t, filepath.Join(sessionDir, "session.json"), "01890000-0000-7000-8000-000000000009", "/proj")
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	if err := os.RemoveAll(sessionDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sessionDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if ran.SubmitInput("/rename My session") {
		t.Fatal("installed submit accepted a /rename whose atomic write failed")
	}
	if got := len(kindEvents(t, store, events.KindSessionWriteFailed)); got != 1 {
		t.Fatalf("session_write_failed events = %d, want 1 (the write-failure protocol must still run)", got)
	}
	notice := ran.NoticeText()
	if !strings.Contains(notice, "session log unwritable") {
		t.Errorf("notice = %q, want the session-write-failure notice retained", notice)
	}
	if strings.Contains(notice, "Renamed session") {
		t.Errorf("notice = %q, want no rename confirmation past a failed durability boundary", notice)
	}
	if got := ran.SessionBadgeText(); strings.Contains(got, "My session") {
		t.Errorf("badge = %q, want no session-name badge after a failed rename write", got)
	}
}

// TestStartTUI_InstalledSubmitDispatchesThroughBuiltApp pins the installed submit wiring:
// it drives input through the submit hook StartTUI actually installs on the app
// it builds (app.SubmitInput → submitCurrent → the SetSubmit hook), not a
// hand-assembled NewSubmitFunc. It proves both arms of that hook are connected:
//   - a plain prompt reaches the production prompt entrypoint and persists the
//     user message durably (the PromptEntrypoint arg);
//   - a /effort with no model selected reaches the real effort handler through
//     the registry, which records slash_command{effort, error} and flushes it
//     via the command-flush hook StartTUI installed (the Registry arg).
//
// It fails if StartTUI no longer calls app.SetSubmit(tui.NewSubmitFunc(...)):
// a.submit is then nil, submitCurrent is a no-op, the prompt is rejected, and no
// slash_command record is appended.
func TestStartTUI_InstalledSubmitDispatchesThroughBuiltApp(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}

	if !ran.SubmitInput("hello there") {
		t.Fatal("installed submit rejected a plain prompt; StartTUI's submit hook is not wired")
	}
	if got := userMessageCount(store); got != 1 {
		t.Fatalf("persisted user messages = %d, want 1 (installed submit must route plain prompts through the production prompt entrypoint)", got)
	}

	if ran.SubmitInput("/effort high") {
		t.Fatal("/effort with no model selected must be rejected (retain) through the installed submit")
	}
	cmds := slashCmds(t, store)
	if len(cmds) != 1 || cmds[0].Name != "effort" || cmds[0].Outcome != "error" {
		t.Fatalf("slash_command events = %+v, want one {effort, error} dispatched through the installed submit", cmds)
	}
}

// TestStartTUI_BareEffortAndModelOpenPickerThroughInstalledSubmit pins the
// production wiring: a bare /effort and a bare /model dispatched through the
// installed submit open their pickers via the wired EffortDeps/ModelDeps.OpenPicker
// (app.OpenEffortPicker / app.OpenModelPicker) and record no slash_command —
// matching the CTRL-E/CTRL-M key paths. It fails if newEffortDeps/newModelDeps stop
// setting OpenPicker, leaving a bare invocation inert in the real app.
func TestStartTUI_BareEffortAndModelOpenPickerThroughInstalledSubmit(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store, Model: selectedState()}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}

	// Bare /effort opens the effort picker (a model is selected) and clears the input.
	if !ran.SubmitInput("/effort") {
		t.Fatal("installed submit rejected bare /effort; OpenPicker is not wired in newEffortDeps")
	}
	if !ran.EffortPickerOpen() {
		t.Fatal("bare /effort did not open the effort picker through the installed submit")
	}
	// Dismiss so the model picker is not blocked by an open overlay.
	ran.HandleEsc()
	if ran.EffortPickerOpen() {
		t.Fatal("ESC did not dismiss the effort picker")
	}

	// Bare /model opens the model picker and clears the input.
	if !ran.SubmitInput("/model") {
		t.Fatal("installed submit rejected bare /model; OpenPicker is not wired in newModelDeps")
	}
	if !ran.ModelPickerOpen() {
		t.Fatal("bare /model did not open the model picker through the installed submit")
	}

	// Neither bare invocation recorded a slash_command (parity with CTRL-E/CTRL-M).
	if cmds := slashCmds(t, store); len(cmds) != 0 {
		t.Fatalf("bare /effort and /model recorded %+v slash_command events, want none", cmds)
	}
}

// TestStartTUI_InstallsPickerDepsForControlKey pins the effort picker (effort/CTRL-E)
// and the model picker (model/CTRL-M): StartTUI must install the picker deps it builds on the App
// itself (app.SetEffortDeps / app.SetModelPickerDeps), not only hand them to the
// /effort and /model registries. With a model selected, the control key then opens the
// picker through the assembled app. Each row fails if StartTUI omits the matching setter
// — the deps stay nil, the open call returns before mounting the overlay, and the
// control-key press reports the picker never opened.
func TestStartTUI_InstallsPickerDepsForControlKey(t *testing.T) {
	cases := []struct {
		name    string
		press   func(*tui.App) bool
		unwired string
	}{
		{
			name:    "effort picker for CTRL-E",
			press:   (*tui.App).PressCtrlE,
			unwired: "CTRL-E did not open the effort picker; StartTUI left App.effortDeps unwired (missing SetEffortDeps)",
		},
		{
			name:    "model picker for CTRL-M",
			press:   (*tui.App).PressCtrlM,
			unwired: "CTRL-M did not open the model picker; StartTUI left App.modelPickerDeps unwired (missing SetModelPickerDeps)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ran *tui.App
			defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

			store := mkStore(t)
			result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store, Model: selectedState()}
			if err := StartTUI(context.Background(), result, io.Discard); err != nil {
				t.Fatalf("StartTUI error: %v", err)
			}
			if ran == nil {
				t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
			}
			if !tc.press(ran) {
				t.Fatal(tc.unwired)
			}
		})
	}
}

// TestStartTUI_FileRefPickerOpensThroughAssembledApp pins the production wiring:
// StartTUI must pass BootstrapResult.Home to the app (app.SetHome) and the picker must
// read the project root from the installed StatusState, so typing '@' at a word boundary
// in the assembled app's input opens the '@' file-reference picker. It drives the real
// change hook through the captured app (SeedInput → the TextArea change func StartTUI's New
// installs) over a real project root. It fails if StartTUI omits SetHome — home stays empty,
// openFilePicker returns before mounting, and FilePickerOpen reports the picker never opened.
func TestStartTUI_FileRefPickerOpensThroughAssembledApp(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	projectRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectRoot, "main.go"), []byte("package x"), 0o644); err != nil {
		t.Fatalf("seed project file: %v", err)
	}
	store := mkStore(t)
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: projectRoot, ProjectRoot: projectRoot, Session: store}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}

	ran.SeedInput("@") // a single '@' at the buffer start, through the assembled app's change hook
	if !ran.FilePickerOpen() {
		t.Fatal("typing '@' did not open the file-reference picker through the assembled app; StartTUI left the picker's home/project-root sources unwired (missing SetHome)")
	}
}

// TestStartTUI_PickerRequiredLaunchOpensModelPicker pins the picker-required launch: a path-4
// launch outcome (BootstrapResult.ModelPickerRequired) opens the provider-aware model
// picker after StartTUI installs the model-picker deps, so the run does not start model-less.
// It fails if StartTUI stops routing the launch flag through OpenModelPicker.
func TestStartTUI_PickerRequiredLaunchOpensModelPicker(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	result := &BootstrapResult{
		Home:                t.TempDir(),
		LaunchDir:           "/launch",
		Session:             store,
		Model:               model.NewActiveState(nil, ""),
		ModelPickerRequired: true,
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	if !ran.ModelPickerOpen() {
		t.Fatal("ModelPickerRequired launch did not open the model picker; StartTUI's path-4 picker routing is unwired")
	}
}

// TestStartTUI_SelectedLaunchDoesNotForcePickerOpen pins the contrast: a normal
// selected-state launch (ModelPickerRequired false) does not force the picker open.
func TestStartTUI_SelectedLaunchDoesNotForcePickerOpen(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store, Model: selectedState()}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	if ran.ModelPickerOpen() {
		t.Fatal("a selected-state launch forced the model picker open; only ModelPickerRequired should")
	}
}

// TestStartTUI_InstallsRegistryForTabCompletion pins tab completion: StartTUI
// must install the production command registry on the App itself
// (app.SetRegistry), not only hand it to the submit adapter. Tab name-completion
// then matches the live command set through the assembled app: "/stat"
// completes to "/status". It fails if StartTUI omits SetRegistry — App.registry
// stays nil, completeName no-ops, and PressTab returns the buffer unchanged.
func TestStartTUI_InstallsRegistryForTabCompletion(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}

	if text, _ := ran.PressTab("/stat"); text != "/status" {
		t.Fatalf("Tab on %q completed to %q, want %q; StartTUI left App.registry unwired (missing SetRegistry)", "/stat", text, "/status")
	}
}

// The overlay reads its rows from result.SettingsLayers, not from the cache's
// ConfigLayerPaths, which never carries the local layer.
func TestStartTUI_SettingsLayersReachStatusOverlay(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	globalPath := "/home/u/.codemeld/global/settings.yaml"
	projectPath := "/proj/.codemeld/settings.yaml"
	localPath := "/proj/.codemeld/settings.local.yaml"
	result := &BootstrapResult{
		Home:             "/home/u",
		LaunchDir:        "/proj",
		ProjectRoot:      "/proj",
		Session:          store,
		Model:            selectedState(),
		ConfigLayerPaths: []string{globalPath, projectPath},
		SettingsLayers: []securitystate.LayerSnapshot{
			{Kind: securitystate.LayerGlobal, Path: globalPath, Present: true},
			{Kind: securitystate.LayerProject, Path: projectPath, Present: true},
			{Kind: securitystate.LayerLocal, Path: localPath, Present: true},
		},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}

	if !ran.SubmitInput("/status") {
		t.Fatal("/status should be accepted through StartTUI's installed submit hook")
	}
	overlay := ran.StatusText()
	want := "Config layer sources:\n  " + globalPath + " [global]\n  " + projectPath + " [project]\n  " + localPath + " [local]\n"
	if !strings.Contains(overlay, want) {
		t.Errorf("status overlay missing %q\n--- overlay ---\n%s", want, overlay)
	}
}

func TestStatusLayers_ProjectsOnlyLoadedLayersByKind(t *testing.T) {
	global := securitystate.LayerSnapshot{Kind: securitystate.LayerGlobal, Path: "/h/.codemeld/global/settings.yaml", Present: true}
	for _, tc := range []struct {
		name   string
		layers []securitystate.LayerSnapshot
		want   []tui.StatusLayer
	}{
		{
			name:   "global only",
			layers: []securitystate.LayerSnapshot{global, {Kind: securitystate.LayerProject, Path: "/p/.codemeld/settings.yaml"}, {Kind: securitystate.LayerLocal, Path: "/p/.codemeld/settings.local.yaml"}},
			want:   []tui.StatusLayer{{Kind: "global", Path: global.Path}},
		},
		{
			name:   "global and local without shared",
			layers: []securitystate.LayerSnapshot{global, {Kind: securitystate.LayerProject, Path: "/p/.codemeld/settings.yaml"}, {Kind: securitystate.LayerLocal, Path: "/p/.codemeld/settings.local.yaml", Present: true}},
			want:   []tui.StatusLayer{{Kind: "global", Path: global.Path}, {Kind: "local", Path: "/p/.codemeld/settings.local.yaml"}},
		},
		{
			name:   "ignored layers are left out",
			layers: []securitystate.LayerSnapshot{global, {Kind: securitystate.LayerProject, Path: "/p/.codemeld/settings.yaml", Present: true, Ignored: true}, {Kind: securitystate.LayerLocal, Path: "/p/.codemeld/settings.local.yaml", Present: true, Ignored: true}},
			want:   []tui.StatusLayer{{Kind: "global", Path: global.Path}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := statusLayers(tc.layers); !slices.Equal(got, tc.want) {
				t.Fatalf("statusLayers() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestStartTUI_RendersLaunchBannerFirstForSelectedLaunch pins the launch banner: a
// selected-state launch renders the two banner lines (name+version, then the
// provider·model·effort·dir metadata subtitle) as the transcript's first content through
// the real StartTUI assembly, sourced from the same statusState /status reads. It
// fails if StartTUI stops rendering the banner, reorders it after other transcript
// content, or drifts the version off the hard-coded value.
func TestStartTUI_RendersLaunchBannerFirstForSelectedLaunch(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store, Model: selectedState()}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	if got := ran.TranscriptText(); !bannerHasHead(got, "openai · gpt-5.5 · medium effort", "/launch", codemeldVersion) {
		t.Fatalf("transcript does not start with the launch banner\n--- got ---\n%s", got)
	}
}

// bannerHasHead reports whether the visible transcript got opens with the launch
// banner: the teal-filled name bar (◆ codemeld … <version>) on the first line, then the
// given selection and launch-dir text on the metadata subtitle line beneath it. It tolerates
// the bar's width padding (which depends on the terminal width at append time, fixed to 80
// under `go test`) by matching on substrings rather than the exact padded string.
func bannerHasHead(got, selection, launchDir, version string) bool {
	return strings.HasPrefix(got, "◆ codemeld") &&
		strings.Contains(got, version) &&
		strings.Contains(got, selection) &&
		strings.Contains(got, launchDir)
}

// resumeStoreWithHistory builds a store whose loaded record stream already holds a
// prior user/assistant exchange, standing in for a cold-start resumed session.
func resumeStoreWithHistory(t *testing.T) *sessions.Store {
	t.Helper()
	return sessions.New(filepath.Join(t.TempDir(), "session.json"), &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            "01890000-0000-7000-8000-0000000000aa",
			Folder:        "/proj",
			StartedAt:     testStart,
			UpdatedAt:     testStart,
			SchemaVersion: sessions.CurrentSchemaVersion,
		},
		Records: []sessions.Record{
			sessions.Message{Role: "user", Content: sessions.TextContent("prior question")},
			sessions.Message{Role: "assistant", Content: sessions.TextContent("prior answer")},
		},
	})
}

// TestStartTUI_ColdResumeReplaysPriorTranscriptAfterBanner pins cold-start resume replay: a
// cold-start resume launch (ResumeReplay set) re-renders the loaded session's prior
// conversation into the transcript, after the launch banner and before the event loop
// runs, so the user does not resume into an empty-looking pane.
func TestStartTUI_ColdResumeReplaysPriorTranscriptAfterBanner(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := resumeStoreWithHistory(t)
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store, Model: selectedState(), ResumeReplay: true}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	got := ran.TranscriptText()
	if !bannerHasHead(got, "openai · gpt-5.5 · medium effort", "/launch", codemeldVersion) {
		t.Fatalf("resumed transcript must still open with the banner\n--- got ---\n%s", got)
	}
	wantReplay := "▌ prior question\n\nprior answer"
	if !strings.Contains(got, wantReplay) {
		t.Fatalf("resumed transcript missing replayed history %q\n--- got ---\n%s", wantReplay, got)
	}
	// The banner precedes the replayed history.
	if strings.Index(got, "▌ prior question") <= strings.Index(got, "◆ codemeld") {
		t.Errorf("replayed history must come after the banner\n--- got ---\n%s", got)
	}
}

// TestStartTUI_FreshLaunchDoesNotReplay is the contrast: with ResumeReplay false the
// loaded records are not re-rendered, so fresh-launch transcript behavior (banner only)
// is unchanged even if the session somehow carries records.
func TestStartTUI_FreshLaunchDoesNotReplay(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := resumeStoreWithHistory(t)
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store, Model: selectedState()}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	if got := ran.TranscriptText(); strings.Contains(got, "prior question") || strings.Contains(got, "prior answer") {
		t.Fatalf("fresh launch must not replay loaded records\n--- got ---\n%s", got)
	}
}

// TestBannerLines_NameLineCarriesFilledBar pins the name bar: the banner's name line is the
// teal-filled chrome bar (LaunchBannerBar) — bold white text on the teal background (the
// "[fg:bg:b]…[-:-:-]" fill tag) carrying "◆ codemeld" and the dynamic version — rather than
// the prior plain bold name. The version is sourced from status.Version(), never hardcoded.
func TestBannerLines_NameLineCarriesFilledBar(t *testing.T) {
	app := tui.New(nil)
	status := newStatusState(app, providerCache(t, t.TempDir()), selectedState(), &BootstrapResult{LaunchDir: "/launch"}, enforce.Resolution{})
	got := bannerLines(status)[0]
	for _, want := range []string{"[#ffffff:#1f9e8f:b]", "◆ codemeld", codemeldVersion, "[-:-:-]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("banner name line = %q, want it to contain %q (teal-filled bar)", got, want)
		}
	}
}

// TestStartTUI_BannerEscapesBracketedRuntimeValues pins bracket escaping: a
// launch directory (or model/provider) whose text contains a "[tag]"-like sequence renders
// the literal brackets in the transcript rather than being parsed as tview markup. The banner
// is appended through the raw AppendStyled seam, so without tview.Escape in bannerLines a path
// like /tmp/[red]work would drop its "[red]" — the assertion fails if that escaping is removed.
func TestStartTUI_BannerEscapesBracketedRuntimeValues(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/tmp/[red]work", Session: store, Model: selectedState()}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	if got := ran.TranscriptText(); !strings.Contains(got, "/tmp/[red]work") {
		t.Fatalf("launch banner dropped bracketed path (markup parsed instead of escaped)\n--- got ---\n%s", got)
	}
}

// TestStartTUI_BannerNoModelSelectedFallback pins the no-model fallback: a launch with
// no model determined renders the defined "no model selected" fallback on the
// selection line rather than blank/garbage, still as the transcript's first lines.
func TestStartTUI_BannerNoModelSelectedFallback(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store, Model: model.NewActiveState(nil, "")}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	if got := ran.TranscriptText(); !bannerHasHead(got, "no model selected", "/launch", codemeldVersion) {
		t.Fatalf("no-model launch banner wrong\n--- got ---\n%s", got)
	}
}

// TestStartTUI_ClearWipesTranscriptAndReRendersBanner pins the transcript reset: /new driven through
// the submit hook StartTUI installs wipes the prior conversation from the visible
// transcript and re-renders the launch banner for the fresh session, with no leftover
// "> /new" echo. It reads the rendered transcript of the app StartTUI built (not the
// store pointer), so it fails if the swap happens but the visible pane is left
// holding old content, the banner is not re-rendered, or the accepted command echoes
// onto the cleared pane.
func TestStartTUI_ClearWipesTranscriptAndReRendersBanner(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000001f0", t.TempDir())
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store, Model: selectedState()}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}

	const selection = "openai · gpt-5.5 · medium effort"
	// Seed prior conversation on top of the launch banner StartTUI already rendered,
	// so the assertion proves old content is gone — not just that the pane is short.
	const priorMarker = "PRIOR-CONVERSATION-MARKER"
	ran.Append(priorMarker)
	if pre := ran.TranscriptText(); !bannerHasHead(pre, selection, "/launch", codemeldVersion) || !strings.Contains(pre, priorMarker) {
		t.Fatalf("precondition: transcript should hold the banner then prior content:\n%s", pre)
	}

	if !ran.SubmitInput("/new") {
		t.Fatal("/new should be accepted through StartTUI's installed submit hook")
	}

	got := strings.TrimRight(ran.TranscriptText(), "\n")
	// The pane is reset to exactly the re-rendered banner: its head is present, and the
	// prior conversation and the command echo are gone (banner head matched by
	// substring since the bar is width-padded).
	if !bannerHasHead(got, selection, "/launch", codemeldVersion) {
		t.Fatalf("after /new, transcript = %q, want the re-rendered banner", got)
	}
	if strings.Contains(got, priorMarker) {
		t.Error("prior conversation survived /clear; the visible transcript was not reset")
	}
	if strings.Contains(got, "/new") || strings.Contains(got, "/clear") {
		t.Errorf("the /new command echoed into the fresh transcript:\n%s", got)
	}
}

// TestStartTUI_StatusLineSeededAndLiveUpdatesOnModelApply pins the status-line footer: StartTUI seeds
// the persistent status-line footer from the same statusState /status and the launch
// banner read, and a real /model apply driven through the installed submit path
// live-updates that footer — read back from the app StartTUI built, not an
// in-memory-only snapshot. It fails if StartTUI stops installing the status state
// (SetStatusLineState) or if the model deps no longer carry the footer-refresh
// callback (App.RefreshStatusLine), leaving the footer stuck on the launch selection.
func TestStartTUI_StatusLineSeededAndLiveUpdatesOnModelApply(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	home := t.TempDir()
	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5", "gpt-5.5-pro")
	result := &BootstrapResult{
		Home:        home,
		LaunchDir:   "/launch",
		ProjectRoot: t.TempDir(),
		Session:     store,
		Model:       selectedState(), // openai/gpt-5.5/medium
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{
					"base_url": "https://api.openai.com/v1",
					"api_key":  "sk-test",
				},
			},
		},
		ConfigLayerPaths: []string{SettingsPath(home)},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}

	// Seeded footer reflects the launch selection (gpt-5.5), not yet gpt-5.5-pro.
	seeded := ran.StatusLineText()
	if !strings.Contains(seeded, "gpt-5.5") || strings.Contains(seeded, "gpt-5.5-pro") {
		t.Fatalf("seeded status line = %q, want it to show the launch model gpt-5.5", seeded)
	}

	// Drive a real /model apply through the installed submit hook; the footer must
	// live-update to the new model.
	if !ran.SubmitInput("/model gpt-5.5-pro") {
		t.Fatal("/model gpt-5.5-pro should be accepted through StartTUI's installed submit hook")
	}
	if got := ran.StatusLineText(); !strings.Contains(got, "gpt-5.5-pro") {
		t.Fatalf("status line after /model apply = %q, want it to reflect gpt-5.5-pro (footer did not live-update)", got)
	}
}

// TestStartTUI_ChatGPTProviderReflectedAndModelStaysOnIt pins the ChatGPT provider id through the full
// production StartTUI assembly: a run launched with the built-in openai-chatgpt provider
// active seeds the status-line footer with the stable provider id (never "OpenAI
// ChatGPT"), and a /model gpt-5.4 dispatched through the installed submit hook
// validates against the openai-chatgpt built-in allowlist (selectable catalog wiring), stays on
// openai-chatgpt — never switching to the configured openai provider despite similar
// model ids — and live-updates the footer, still showing the id.
func TestStartTUI_ChatGPTProviderReflectedAndModelStaysOnIt(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	home := t.TempDir()
	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5", "gpt-5.5-pro")
	result := &BootstrapResult{
		Home:        home,
		LaunchDir:   "/launch",
		ProjectRoot: t.TempDir(),
		Session:     store,
		Model:       model.NewActiveState(&model.Selection{Provider: "openai-chatgpt", ID: "gpt-5.5", Effort: "medium"}, model.SourceResume),
		// A configured openai provider with the same model id proves /model does not
		// cross over to it; openai-chatgpt itself is built-in and needs no settings entry.
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{
					"base_url": "https://api.openai.com/v1",
					"api_key":  "sk-test",
				},
			},
		},
		ConfigLayerPaths: []string{SettingsPath(home)},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}

	seeded := ran.StatusLineText()
	if !strings.Contains(seeded, "openai-chatgpt") || strings.Contains(seeded, "OpenAI ChatGPT") {
		t.Fatalf("seeded status line = %q, want the stable id openai-chatgpt (not the display name)", seeded)
	}

	if !ran.SubmitInput("/model gpt-5.4") {
		t.Fatal("/model gpt-5.4 should be accepted (openai-chatgpt's built-in allowlist includes it)")
	}
	got := ran.StatusLineText()
	if !strings.Contains(got, "gpt-5.4") {
		t.Fatalf("status line after /model = %q, want it to reflect gpt-5.4", got)
	}
	if !strings.Contains(got, "openai-chatgpt") || strings.Contains(got, "OpenAI ChatGPT") {
		t.Fatalf("status line after /model = %q, want it to stay on the openai-chatgpt id (no switch to openai, no display name)", got)
	}
}

// TestStartTUI_ModeHintSeededAndUpdatesOnModeSwitch pins the mode-hint row: StartTUI seeds the
// persistent mode-hint row from the active interaction mode, and a /mode switch driven
// through the installed submit path updates that row via the shared Notify seam without
// appending the confirmation to the session transcript — all read back from the app
// StartTUI built. It fails if StartTUI stops seeding the row (RefreshModeHint) or if
// newModeDeps no longer points Notify at the row refresh, leaving the hint stuck on the
// launch mode or routed back into the transcript.
func TestStartTUI_ModeHintSeededAndUpdatesOnModeSwitch(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	result := &BootstrapResult{
		Home:      t.TempDir(),
		LaunchDir: "/launch",
		Session:   store,
		Model:     selectedState(),
		Mode:      mode.NewActiveState(mode.Build, mode.SourceDefault),
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}

	// Seeded bar reflects the launch mode (build) before any switch, as the "• build" pill.
	if got := ran.ModeHintText(); !strings.Contains(got, "• build") {
		t.Fatalf("seeded mode pill = %q, want it to show the launch mode build", got)
	}

	// Drive /mode auto-edits through the installed submit hook; the bar's pill must update
	// to the new mode through the shared Notify seam.
	if !ran.SubmitInput("/mode auto-edits") {
		t.Fatal("/mode auto-edits should be accepted through StartTUI's installed submit hook")
	}
	got := ran.ModeHintText()
	if !strings.Contains(got, "• auto-edits") {
		t.Fatalf("mode pill after /mode = %q, want it to reflect auto-edits (bar did not update)", got)
	}
	if strings.Contains(got, "• build") {
		t.Fatalf("mode pill after /mode = %q, still shows the stale build mode", got)
	}
	// The switch confirmation must not reach the transcript — only the command
	// echo does. The mode indicator belongs to the bottom bar's pill, not the transcript.
	if tr := ran.TranscriptText(); strings.Contains(tr, "• auto-edits") || strings.Contains(tr, "mode on (shift+tab to cycle)") {
		t.Fatalf("mode switch confirmation appeared in the transcript; it must only update the bar:\n%s", tr)
	}
}

// newInteractiveAuthorizer is the one interactive assembly both a fresh launch and a resume
// reach through StartTUI, so a prompt built by either carries the launch's trust decision
// rather than the struct's trusted zero value.
func TestNewInteractiveAuthorizer_CarriesTrustDecisionToBothPromptKinds(t *testing.T) {
	cases := []struct {
		name    string
		result  *BootstrapResult
		trusted bool
	}{
		{"fresh untrusted", &BootstrapResult{BackgroundPrune: true, TrustDecision: trust.Decision{Reason: trust.ReasonNoRecord, Root: "/proj"}}, false},
		{"resume untrusted", &BootstrapResult{ResumeReplay: true, TrustDecision: trust.Decision{Reason: trust.ReasonUnreadable, Root: "/proj"}}, false},
		{"fresh trusted", &BootstrapResult{BackgroundPrune: true, TrustDecision: trust.Decision{Trusted: true, Reason: trust.ReasonTrusted, Root: "/proj"}}, true},
		{"resume trusted by vacuity", &BootstrapResult{ResumeReplay: true, TrustDecision: trust.Decision{Trusted: true, Reason: trust.ReasonNothingCovered, Root: "/proj"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := tui.New(nil)
			auth := newInteractiveAuthorizer(app, emptyCache(t, "/proj"), tc.result, mode.NewActiveState(mode.Build, mode.SourceDefault))
			display := auth.buildPromptDisplay(dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: "rm x"}, "/proj")
			if display.ProjectUntrusted == tc.trusted {
				t.Fatalf("display ProjectUntrusted = %v for a trusted=%v launch", display.ProjectUntrusted, tc.trusted)
			}
			folder, err := buildPromptRequest(permissions.MatchRequest{Kind: matchKindDirect, Subject: "rm x", PathScope: "/proj"}, display, permissions.ScopeEscalation{})
			if err != nil {
				t.Fatalf("buildPromptRequest: %v", err)
			}
			host, err := buildPromptRequest(permissions.MatchRequest{Kind: matchKindHost, Subject: "web_fetch", Host: "example.com"}, display, permissions.ScopeEscalation{})
			if err != nil {
				t.Fatalf("buildPromptRequest (host): %v", err)
			}
			if folder.ProjectUntrusted == tc.trusted || host.ProjectUntrusted == tc.trusted {
				t.Fatalf("folder/host prompt ProjectUntrusted = %v/%v for a trusted=%v launch",
					folder.ProjectUntrusted, host.ProjectUntrusted, tc.trusted)
			}
		})
	}
}

func TestDefaultFreshSteps_StartTUI_IsRealNotNoOp(t *testing.T) {
	var ran bool
	defer swapRunApp(func(*tui.App) error { ran = true; return nil })()

	steps := DefaultFreshSteps(io.Discard, io.Discard)
	result := &BootstrapResult{Home: t.TempDir(), Session: mkStore(t)}
	if err := steps.StartTUI(context.Background(), result); err != nil {
		t.Fatalf("DefaultFreshSteps.StartTUI error: %v", err)
	}
	if !ran {
		t.Fatal("DefaultFreshSteps.StartTUI is still a no-op stub; it did not run the event loop")
	}
}

func TestStartTUI_ColdResumeLockReleasedOnNew(t *testing.T) {
	ctx := context.Background()
	store := storeAt(t, filepath.Join(t.TempDir(), "resumed.json"), "01890000-0000-7000-8000-000000000441", t.TempDir())
	var releases int
	var ran bool
	defer swapRunApp(func(app *tui.App) error {
		ran = true
		if releases != 0 {
			t.Fatalf("resume lock released before the TUI left the resumed session: %d", releases)
		}
		if !app.SubmitInput("/new") {
			t.Fatal("/new should be accepted")
		}
		if releases != 1 {
			t.Fatalf("resume lock releases after /new = %d, want 1", releases)
		}
		return nil
	})()

	result := &BootstrapResult{
		Home:              t.TempDir(),
		Session:           store,
		Model:             selectedState(),
		ResumeLockRelease: func() { releases++ },
	}
	if err := StartTUI(ctx, result, io.Discard); err != nil {
		t.Fatalf("StartTUI: %v", err)
	}
	if !ran {
		t.Fatal("runApp did not run")
	}
	if releases != 1 {
		t.Fatalf("resume lock releases after StartTUI return = %d, want still 1", releases)
	}
}

func TestStartTUI_ForkThroughInstalledSubmitSwitchesToDurableChild(t *testing.T) {
	const (
		parentID = "01890000-0000-7000-8000-0000000f0001"
		userID   = "01890000-0000-7000-8000-0000000f0002"
		asstID   = "01890000-0000-7000-8000-0000000f0003"
		lateID   = "01890000-0000-7000-8000-0000000f0004"
	)
	ctx := context.Background()
	home := t.TempDir()
	folder := t.TempDir()
	parentPath := filepath.Join(t.TempDir(), "parent.json")
	parent := sessions.New(parentPath, &sessions.Session{Metadata: sessions.Metadata{
		ID:            parentID,
		Folder:        folder,
		Title:         "Refactor plan",
		StartedAt:     testStart,
		UpdatedAt:     testStart,
		SchemaVersion: sessions.CurrentSchemaVersion,
	}})
	parent.Append(sessions.Message{ID: userID, Role: "user", Content: sessions.TextContent("plan the work"), Timestamp: testStart})
	parent.Append(sessions.Message{ID: asstID, Role: "assistant", Content: sessions.TextContent("here is the plan"), Timestamp: testStart})

	active := selectedState()
	modeActive := selectedModeState()
	var releases int

	var ran *tui.App
	defer swapRunApp(func(app *tui.App) error {
		ran = app
		if releases != 0 {
			t.Fatalf("resume lock released before /fork: %d", releases)
		}
		if !app.SubmitInput("/fork") {
			t.Fatal("/fork should be accepted through StartTUI's installed submit hook")
		}
		if releases != 1 {
			t.Fatalf("resume lock releases after /fork = %d, want 1 (released after activation)", releases)
		}
		return nil
	})()

	result := &BootstrapResult{
		Home:              home,
		LaunchDir:         "/launch",
		Session:           parent,
		Model:             active,
		Mode:              modeActive,
		ResumeLockRelease: func() { releases++ },
	}
	if err := StartTUI(ctx, result, io.Discard); err != nil {
		t.Fatalf("StartTUI: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}

	child := ran.ActiveStore()
	if child == parent {
		t.Fatal("active store still the parent after /fork; the child was not activated")
	}
	childID := child.SessionID()
	if childID == parentID {
		t.Fatal("child reused the parent session id")
	}

	got := strings.TrimRight(ran.TranscriptText(), "\n")
	if !bannerHasHead(got, "openai · gpt-5.5 · medium effort", "/launch", codemeldVersion) {
		t.Fatalf("after /fork, transcript does not open with the re-rendered banner:\n%s", got)
	}
	if !strings.Contains(got, "plan the work") || !strings.Contains(got, "here is the plan") {
		t.Fatalf("child transcript missing replayed history:\n%s", got)
	}
	if strings.Contains(got, "/fork") {
		t.Errorf("the /fork command echoed into the child transcript:\n%s", got)
	}

	if sel, src, ok := active.Current(); !ok || sel.Provider != "openai" || sel.ID != "gpt-5.5" || src != model.SourceResume {
		t.Fatalf("run-scoped model changed after /fork = %+v src=%v ok=%v", sel, src, ok)
	}
	if m, _ := modeActive.Current(); m != mode.Plan {
		t.Fatalf("run-scoped mode changed after /fork = %v, want plan", m)
	}

	parentDisk, _, err := sessions.OpenSession(parentPath)
	if err != nil {
		t.Fatalf("open parent from disk: %v", err)
	}
	capability, ok := parentDisk.Records[2].(sessions.Event)
	if !ok || capability.Kind != events.KindExecutionCapability {
		t.Fatalf("parent record after the conversation = %#v, want the launch execution_capability", parentDisk.Records[2])
	}
	forkPoint := capability.ID
	slashIdx, forkedIdx, childRef := -1, -1, ""
	for i, rec := range parentDisk.Records {
		ev, ok := rec.(sessions.Event)
		if !ok {
			continue
		}
		switch ev.Kind {
		case events.KindSlashCommand:
			var sc events.SlashCommand
			if err := json.Unmarshal(ev.Payload, &sc); err != nil {
				t.Fatalf("decode parent slash_command: %v", err)
			}
			if sc.Name != "fork" || sc.Outcome != "success" || sc.ErrorDetail != "" {
				t.Fatalf("parent slash_command = %+v, want fork success", sc)
			}
			slashIdx = i
		case events.KindSessionForked:
			var sf events.SessionForked
			if err := json.Unmarshal(ev.Payload, &sf); err != nil {
				t.Fatalf("decode session_forked: %v", err)
			}
			forkedIdx, childRef = i, sf.ToSessionID
		}
	}
	if slashIdx < 0 || forkedIdx != slashIdx+1 {
		t.Fatalf("parent disk record order: slash_command idx=%d, session_forked idx=%d, want success immediately before marker", slashIdx, forkedIdx)
	}
	if childRef != childID {
		t.Fatalf("session_forked to_session_id = %q, want the activated child %q", childRef, childID)
	}

	childDisk, _, err := sessions.OpenSession(child.Path())
	if err != nil {
		t.Fatalf("open child from disk: %v", err)
	}
	if childDisk.Metadata.Title != "Refactor plan (forked)" {
		t.Fatalf("child title = %q, want %q", childDisk.Metadata.Title, "Refactor plan (forked)")
	}
	if fo := childDisk.Metadata.ForkedFrom; fo == nil || fo.SessionID != parentID || fo.RecordID != forkPoint {
		t.Fatalf("child forked_from = %+v, want session_id=%s record_id=%s (the last parent record before /fork)", fo, parentID, forkPoint)
	}
	first, ok := childDisk.Records[0].(sessions.Message)
	if !ok || first.ID != userID || first.Role != "user" || first.ParentID != forkPoint {
		t.Fatalf("child record[0] = %#v, want the user message stamped with parent record %s", childDisk.Records[0], forkPoint)
	}
	if second, ok := childDisk.Records[1].(sessions.Message); !ok || second.ID != asstID || second.Role != "assistant" {
		t.Fatalf("child record[1] = %#v, want the assistant message", childDisk.Records[1])
	}
	msgs := 0
	for _, r := range childDisk.Records {
		if _, ok := r.(sessions.Message); ok {
			msgs++
		}
	}
	if msgs != 2 {
		t.Fatalf("child carried %d messages, want exactly the 2 continuation messages (parent events excluded)", msgs)
	}
	if !slices.Contains(eventKinds(childDisk.Records), events.KindLaunchBegan) {
		t.Fatalf("child missing its own launch_began event; kinds = %v", eventKinds(childDisk.Records))
	}

	before := len(parent.Records())
	parent.Append(sessions.Message{ID: lateID, Role: "user", Content: sessions.TextContent("late"), Timestamp: testStart})
	if len(parent.Records()) != before {
		t.Fatal("parent still accepts appends after /fork sealed it in-process")
	}
	if _, _, err := sessions.OpenSession(parentPath); err != nil {
		t.Fatalf("parent no longer loadable after /fork: %v", err)
	}
}

type countingScreen struct {
	tcell.SimulationScreen
	shows atomic.Int32
}

func (s *countingScreen) Show() {
	s.shows.Add(1)
	s.SimulationScreen.Show()
}

func runLiveApp(t *testing.T, screen tcell.Screen, drive func(app *tui.App)) func() {
	t.Helper()
	return swapRunApp(func(app *tui.App) error {
		app.SetScreenFactoryForTest(func() (tcell.Screen, error) { return screen, nil })
		errc := make(chan error, 1)
		go func() { errc <- app.Run() }()
		onEventLoop(t, app, func() {})
		drive(app)
		app.Stop()
		return <-errc
	})
}

func onEventLoop(t *testing.T, app *tui.App, fn func()) {
	t.Helper()
	done := make(chan struct{})
	app.RunOnEventLoopForTest(func() { defer close(done); fn() })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		app.Stop()
		t.Fatal("the event loop did not run a queued update within 5s")
	}
}

func submitOnEventLoop(t *testing.T, app *tui.App, input string) bool {
	t.Helper()
	var accepted bool
	onEventLoop(t, app, func() { accepted = app.SubmitInput(input) })
	return accepted
}

func waitForStoreSwitch(t *testing.T, app *tui.App, prior *sessions.Store) *sessions.Store {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := app.ActiveStore(); got != prior {
			return got
		}
		time.Sleep(2 * time.Millisecond)
	}
	app.Stop()
	t.Fatal("the active store never switched to the compacted child within 5s")
	return nil
}

func TestStartTUI_CompactThroughInstalledSubmitCreatesOwnedSummaryChild(t *testing.T) {
	const (
		parentID = "01890000-0000-7000-8000-0000000c0001"
		userID   = "01890000-0000-7000-8000-0000000c0002"
		asstID   = "01890000-0000-7000-8000-0000000c0003"
	)
	home := t.TempDir()
	folder := t.TempDir()
	parentPath := filepath.Join(t.TempDir(), "parent.json")
	parent := sessions.New(parentPath, &sessions.Session{Metadata: sessions.Metadata{
		ID:            parentID,
		Folder:        folder,
		Title:         "Refactor plan",
		StartedAt:     testStart,
		UpdatedAt:     testStart,
		SchemaVersion: sessions.CurrentSchemaVersion,
	}})
	parent.Append(sessions.Message{ID: userID, Role: "user", Content: sessions.TextContent("plan the work"), Timestamp: testStart})
	parent.Append(sessions.Message{ID: asstID, Role: "assistant", Content: sessions.TextContent("here is the plan"), Timestamp: testStart})

	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	screen := &countingScreen{SimulationScreen: tcell.NewSimulationScreen("UTF-8")}
	entered := make(chan int32, 1)
	release := make(chan struct{})
	var calls, foreignProviders atomic.Int32
	var summaryReq, childReq provider.Request
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if calls.Add(1) == 1 {
			summaryReq = req
			entered <- screen.shows.Load()
			<-release
			return provider.Response{Completion: &openai.ChatCompletion{
				Choices: []openai.ChatCompletionChoice{{Message: openai.ChatCompletionMessage{Content: "the plan, summarized"}}},
			}}, nil
		}
		if isTitleRequest(req) {
			return titleCompletion(""), nil
		}
		childReq = req
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(cfg provider.ClientConfig) provider.Client {
		if cfg.Name != "openai" {
			foreignProviders.Add(1)
		}
		return client
	})()

	var appRef atomic.Pointer[tui.App]
	var storeAtRelease atomic.Pointer[sessions.Store]
	var releases atomic.Int32
	var child *sessions.Store
	var childDisk *sessions.Session

	defer runLiveApp(t, screen, func(app *tui.App) {
		appRef.Store(app)
		var accepted bool
		var drawsAtDispatch int32
		onEventLoop(t, app, func() {
			drawsAtDispatch = screen.shows.Load()
			accepted = app.SubmitInput("/compact")
		})
		if !accepted {
			t.Fatal("/compact was rejected by the installed submit hook")
		}
		if drawsBeforeWork := <-entered; drawsBeforeWork <= drawsAtDispatch {
			t.Fatalf("paints before the summary request = %d, at dispatch = %d; /compact must paint before it backgrounds provider work", drawsBeforeWork, drawsAtDispatch)
		}
		for _, in := range []string{"keep typing", "/fork", "/clear", "/compact"} {
			if submitOnEventLoop(t, app, in) {
				t.Fatalf("%q was accepted while compaction held the submit lease", in)
			}
			if got := app.NoticeText(); !strings.Contains(got, "compaction is running") {
				t.Fatalf("notice after retaining %q = %q, want the compaction-in-progress line", in, got)
			}
		}
		if got := client.callCount(); got != 1 {
			t.Fatalf("provider calls during compaction = %d, want 1 (a retained submission must not dispatch)", got)
		}
		if app.ActiveStore() != parent {
			t.Fatal("the active store changed before the summary completed")
		}
		close(release)

		child = waitForStoreSwitch(t, app, parent)
		var err error
		if childDisk, _, err = sessions.OpenSession(child.Path()); err != nil {
			t.Fatalf("open the compacted child from disk: %v", err)
		}
		if !submitOnEventLoop(t, app, "continue") {
			t.Fatal("a prompt was rejected after compaction released the submit lease")
		}
		turns.Wait()
	})()

	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")
	active, modeActive := selectedState(), selectedModeState()
	result := &BootstrapResult{
		Home:      home,
		LaunchDir: "/launch",
		Session:   parent,
		Model:     active,
		Mode:      modeActive,
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{"base_url": "https://api.openai.com/v1", "api_key": "sk-test"},
			},
		},
		ConfigLayerPaths: []string{SettingsPath(home)},
		ResumeLockRelease: func() {
			releases.Add(1)
			if a := appRef.Load(); a != nil {
				storeAtRelease.Store(a.ActiveStore())
			}
		},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI: %v", err)
	}

	if summaryReq.Model != "gpt-5.5" || summaryReq.Stream {
		t.Fatalf("summary request = model %q stream %v, want gpt-5.5 non-streaming", summaryReq.Model, summaryReq.Stream)
	}
	if n := len(summaryReq.Messages); n == 0 || summaryReq.Messages[0].Role != "system" {
		t.Fatalf("summary request messages = %+v, want a leading system instruction", summaryReq.Messages)
	}
	if foreignProviders.Load() != 0 {
		t.Fatalf("%d clients were built for a provider other than the selected openai; compaction must not fall back", foreignProviders.Load())
	}

	if releases.Load() != 1 {
		t.Fatalf("source ownership releases = %d, want exactly 1", releases.Load())
	}
	if storeAtRelease.Load() != child {
		t.Fatal("the parent's ownership was released before the prepared child became the active store")
	}
	childID := child.SessionID()
	if childID == parentID {
		t.Fatal("the compacted child reused the parent session id")
	}

	parentDisk, _, err := sessions.OpenSession(parentPath)
	if err != nil {
		t.Fatalf("open parent from disk: %v", err)
	}
	recs := parentDisk.Records
	if len(recs) < 2 {
		t.Fatalf("parent records = %d, want the compaction success and marker tail", len(recs))
	}
	forked, ok := recs[len(recs)-1].(sessions.Event)
	if !ok || forked.Kind != events.KindSessionForked {
		t.Fatalf("last parent record = %#v, want the session_forked marker", recs[len(recs)-1])
	}
	var sf events.SessionForked
	if err := json.Unmarshal(forked.Payload, &sf); err != nil {
		t.Fatalf("decode session_forked: %v", err)
	}
	if sf.ToSessionID != childID {
		t.Fatalf("session_forked to_session_id = %q, want the activated child %q", sf.ToSessionID, childID)
	}
	success, ok := recs[len(recs)-2].(sessions.Event)
	if !ok || success.Kind != events.KindSlashCommand {
		t.Fatalf("record before session_forked = %#v, want the compact slash_command", recs[len(recs)-2])
	}
	var sc events.SlashCommand
	if err := json.Unmarshal(success.Payload, &sc); err != nil {
		t.Fatalf("decode parent slash_command: %v", err)
	}
	if sc.Name != "compact" || sc.Outcome != "success" || sc.ErrorDetail != "" {
		t.Fatalf("terminal parent slash_command = %+v, want compact success immediately before session_forked", sc)
	}

	if childDisk.Metadata.Title != "Refactor plan (compacted)" {
		t.Fatalf("child title = %q, want %q", childDisk.Metadata.Title, "Refactor plan (compacted)")
	}
	capability, ok := recs[2].(sessions.Event)
	if !ok || capability.Kind != events.KindExecutionCapability {
		t.Fatalf("parent record after the conversation = %#v, want the launch execution_capability", recs[2])
	}
	if fo := childDisk.Metadata.ForkedFrom; fo == nil || fo.SessionID != parentID || fo.RecordID != capability.ID {
		t.Fatalf("child forked_from = %+v, want session_id=%s record_id=%s (the last parent record before compaction)", fo, parentID, capability.ID)
	}
	summary, ok := childDisk.Records[0].(sessions.Compaction)
	if !ok {
		t.Fatalf("child record[0] = %#v, want a compaction record", childDisk.Records[0])
	}
	if summary.Summary != "the plan, summarized" || summary.Provider != "openai" || summary.ModelID != "gpt-5.5" {
		t.Fatalf("child compaction = %+v, want the generated summary stamped with the active provider/model", summary)
	}
	if summary.ParentID != capability.ID {
		t.Fatalf("child compaction parent_id = %q, want the fork-point record %q", summary.ParentID, capability.ID)
	}
	for _, rec := range childDisk.Records {
		if msg, isMsg := rec.(sessions.Message); isMsg {
			t.Fatalf("the compacted child carried a parent message %#v; it must start from the summary alone", msg)
		}
	}
	if !slices.Contains(eventKinds(childDisk.Records), events.KindLaunchBegan) {
		t.Fatalf("child missing its own launch_began event; kinds = %v", eventKinds(childDisk.Records))
	}

	if sel, src, ok := active.Current(); !ok || sel.Provider != "openai" || sel.ID != "gpt-5.5" || src != model.SourceResume {
		t.Fatalf("run-scoped model changed across compaction = %+v src=%v ok=%v", sel, src, ok)
	}
	if m, _ := modeActive.Current(); m != mode.Plan {
		t.Fatalf("run-scoped mode changed across compaction = %v, want plan", m)
	}
	roles := make([]string, len(childReq.Messages))
	var joined strings.Builder
	for i, m := range childReq.Messages {
		roles[i] = m.Role
		joined.WriteString(m.Content)
		joined.WriteString("\n")
	}
	if !slices.Equal(roles, []string{"system", "user", "user"}) {
		t.Fatalf("next request roles = %v, want the assembled instructions, the compaction context, and the child prompt", roles)
	}
	if !strings.Contains(joined.String(), "the plan, summarized") || !strings.Contains(joined.String(), "continue") {
		t.Fatalf("next request lost the compaction context or the child prompt:\n%s", joined.String())
	}
	for _, parentOnly := range []string{"plan the work", "here is the plan"} {
		if strings.Contains(joined.String(), parentOnly) {
			t.Fatalf("next request replayed the parent-only message %q; the child must carry the summary alone", parentOnly)
		}
	}
}

func TestStartTUI_CompactWithArgumentsRejectedBeforeProviderWork(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		t.Error("a wrong-arity /compact reached the provider")
		return provider.Response{}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	home := t.TempDir()
	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")
	if err := StartTUI(context.Background(), &BootstrapResult{
		Home:      home,
		LaunchDir: "/launch",
		Session:   store,
		Model:     selectedState(),
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{"base_url": "https://api.openai.com/v1", "api_key": "sk-test"},
			},
		},
		ConfigLayerPaths: []string{SettingsPath(home)},
	}, io.Discard); err != nil {
		t.Fatalf("StartTUI: %v", err)
	}

	if ran.SubmitInput("/compact now") {
		t.Fatal("/compact with an argument was accepted; the arity gate must retain the input")
	}
	if got := client.callCount(); got != 0 {
		t.Fatalf("provider calls = %d, want 0 (arity is rejected before any provider work)", got)
	}
	if got := slashCmds(t, store); len(got) != 0 {
		t.Fatalf("appended slash_command events = %+v, want none for a wrong-arity invocation", got)
	}
}

func TestStartTUI_CompactSelectedProviderFailureLeavesParentActive(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
		t.Error("compaction built a configured-provider client for an openai-chatgpt selection")
		return nil
	})()

	home := t.TempDir()
	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")
	store := storeAt(t, filepath.Join(t.TempDir(), "parent.json"), "01890000-0000-7000-8000-0000000c0011", t.TempDir())
	store.Append(sessions.Message{ID: "01890000-0000-7000-8000-0000000c0012", Role: "user", Content: sessions.TextContent("plan the work"), Timestamp: testStart})
	if err := StartTUI(context.Background(), &BootstrapResult{
		Home:      home,
		LaunchDir: "/launch",
		Session:   store,
		Model:     model.NewActiveState(&model.Selection{Provider: "openai-chatgpt", ID: "gpt-5.5", Effort: "medium"}, model.SourceResume),
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{"base_url": "https://api.openai.com/v1", "api_key": "sk-test"},
			},
		},
		ConfigLayerPaths: []string{SettingsPath(home)},
	}, io.Discard); err != nil {
		t.Fatalf("StartTUI: %v", err)
	}

	if !ran.SubmitInput("/compact") {
		t.Fatal("/compact was not admitted through the installed submit hook")
	}
	if got := ran.NoticeText(); !strings.Contains(got, "compaction failed") {
		t.Fatalf("notice after a failed compaction = %q, want a compaction-failed line", got)
	}
	if ran.ActiveStore() != store {
		t.Fatal("a failed compaction switched sessions")
	}
	cmds := slashCmds(t, store)
	if len(cmds) != 1 || cmds[0].Name != "compact" || cmds[0].Outcome != "error" || cmds[0].ErrorDetail == "" {
		t.Fatalf("parent slash_command events = %+v, want one compact error with a detail", cmds)
	}
	if got := len(kindEvents(t, store, events.KindSessionForked)); got != 0 {
		t.Fatalf("session_forked events = %d, want 0 (a failed compaction must not seal the parent)", got)
	}
	before := len(store.Records())
	store.Append(sessions.Message{ID: "01890000-0000-7000-8000-0000000c0013", Role: "user", Content: sessions.TextContent("late"), Timestamp: testStart})
	if len(store.Records()) == before {
		t.Fatal("the parent was sealed by a failed compaction; it must stay active and appendable")
	}
}

// TestSubmitBoundary_NewRoutesToRealClearHandlerAndSwapsStore proves /new reaches
// the production NewClearHandler (not the recordHandler placeholder): the canonical
// name "clear" is recorded, the App's active-session reference moves to the fresh
// store, the AGENTS.md record is replayed onto it, and the prior store is closed.
func TestSubmitBoundary_NewRoutesToRealClearHandlerAndSwapsStore(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	folder := t.TempDir()
	priorStore := storeAt(t, filepath.Join(t.TempDir(), "prior.json"), "prior-id", folder)
	app := tui.New(nil)
	app.SetActiveStore(priorStore)

	entries := []agentinstr.LoadEntry{{Path: "/p/AGENTS.md", Layer: agentinstr.LayerWalked, LoadOrder: 2}}
	result := &BootstrapResult{Home: home, Session: priorStore, AgentInstructions: entries}
	clearDeps := newClearDeps(ctx, app, result, selectedState(), selectedModeState(), &resumeLockHolder{}, fixedRecorder(injectedResolution), nil)

	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"clear": tui.NewClearHandler(clearDeps)})
	submit := tui.NewSubmitFunc(reg, app, nil)

	if !submit("/new") {
		t.Fatal("/new should be accepted (handled, no retain)")
	}
	fresh := app.ActiveStore()
	if fresh == priorStore {
		t.Fatal("active-session reference not swapped to the fresh store after /new")
	}

	cmds := slashCmds(t, priorStore)
	if len(cmds) != 1 || cmds[0].Name != "clear" || cmds[0].Outcome != "success" {
		t.Fatalf("prior slash_command events = %+v, want one {clear, success} (canonical, not the typed /new)", cmds)
	}
	if kinds := eventKinds(fresh.Records()); !slices.Equal(kinds, []string{events.KindLaunchBegan, events.KindExecutionCapability, events.KindAgentInstructionsLoaded, events.KindInteractionMode}) {
		t.Fatalf("fresh session kinds = %v, want [launch_began execution_capability agent_instructions_loaded interaction_mode]", kinds)
	}
	im := decodeInteractionMode(t, fresh)
	if len(im) != 1 || im[0].Mode != "plan" || im[0].Source != "user_command" || im[0].Trigger != "clear" {
		t.Fatalf("fresh interaction_mode = %+v, want one {plan, user_command, clear} (carried-forward source)", im)
	}

	before := len(priorStore.Records())
	priorStore.Append(sessions.Message{ID: "late", Role: "user", Content: sessions.TextContent("late"), Timestamp: testStart})
	if len(priorStore.Records()) != before {
		t.Fatal("prior store still accepts appends after /new closed it")
	}
}

// TestSubmitBoundary_NewRefusesSwitchOnCancelledFlushContext pins the swap
// refusal: when the run context is already cancelled, /clear's pre-switch flush of
// the prior session performs no write and returns a non-write error (empty
// category). The handler must then refuse the swap and leave the active-session
// reference on the prior store — closing it and switching to a fresh session
// would drop the prior session's final records before they were made durable.
// The prior store is writable, so the only reason the flush fails is the
// cancelled context, not an atomic-write error.
func TestSubmitBoundary_NewRefusesSwitchOnCancelledFlushContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	folder := t.TempDir()
	priorStore := storeAt(t, filepath.Join(t.TempDir(), "prior.json"), "prior-id", folder)
	app := tui.New(nil)
	app.SetActiveStore(priorStore)

	result := &BootstrapResult{Home: t.TempDir(), Session: priorStore}
	clearDeps := newClearDeps(ctx, app, result, selectedState(), selectedModeState(), &resumeLockHolder{}, fixedRecorder(injectedResolution), nil)

	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"clear": tui.NewClearHandler(clearDeps)})
	submit := tui.NewSubmitFunc(reg, app, nil)

	if submit("/new") {
		t.Fatal("/new must be rejected (retain) when the pre-switch flush fails on a cancelled context")
	}
	if app.ActiveStore() != priorStore {
		t.Fatal("active-session reference changed after a refused /new switch")
	}
	// The refused switch never closed the prior store, so it still accepts appends.
	before := len(priorStore.Records())
	priorStore.Append(sessions.Message{ID: "after", Role: "user", Content: sessions.TextContent("after"), Timestamp: testStart})
	if len(priorStore.Records()) != before+1 {
		t.Fatal("prior store was closed despite the refused switch")
	}
}

// TestSubmitBoundary_StatusReachableThroughProductionRegistry proves /status
// dispatches to NewStatusHandler (not recordHandler) through the same production
// assembly helper StartTUI uses.
func TestSubmitBoundary_StatusReachableThroughProductionRegistry(t *testing.T) {
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	status := newStatusState(app, providerCache(t, t.TempDir()), selectedState(), &BootstrapResult{LaunchDir: "/launch"}, enforce.Resolution{})
	host := &recordingHost{store: store}

	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"status": tui.NewStatusHandler(status)})
	submit := tui.NewSubmitFunc(reg, host, nil)

	if !submit("/status") {
		t.Fatal("/status should be accepted")
	}
	if len(host.statuses) != 1 {
		t.Fatalf("status overlay opened %d times, want 1 (NewStatusHandler must run)", len(host.statuses))
	}
	cmds := slashCmds(t, store)
	if len(cmds) != 1 || cmds[0].Name != "status" || cmds[0].Outcome != "success" {
		t.Fatalf("slash_command events = %+v, want one {status, success}", cmds)
	}
}

// TestSubmitBoundary_StatusEventIsDurableOnDisk pins: dispatching
// /status through the production submit path with the real command-event flush
// hook installed must make the slash_command record durable on disk, not leave it
// only in memory until some unrelated later flush. It fails if /status's
// FlushActive call is removed — the store is then never flushed and the file is
// absent.
func TestSubmitBoundary_StatusEventIsDurableOnDisk(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	app.SetCommandFlush(newCommandFlush(ctx, app))
	status := newStatusState(app, providerCache(t, t.TempDir()), selectedState(), &BootstrapResult{LaunchDir: "/launch"}, enforce.Resolution{})

	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"status": tui.NewStatusHandler(status)})
	if !tui.NewSubmitFunc(reg, app, nil)("/status") {
		t.Fatal("/status should be accepted")
	}

	assertFileContains(t, store.Path(), "slash_command")
	assertFileContains(t, store.Path(), `"status"`)
}

// TestSubmitBoundary_StatusRetainsOnCancelledFlushContext pins status retention:
// when the run context is already cancelled, the command-event flush hook
// attempts no write and returns the cancellation error (reason ReasonNone, empty
// category). newCommandFlush must surface that error rather than reporting
// success, so /status fails at its durability boundary before opening
// the overlay: submit returns false (the input is retained) and the slash_command
// record stays in memory for a later flush to retry rather than being treated as
// durable. It fails if newCommandFlush reports nil for a never-attempted flush.
func TestSubmitBoundary_StatusRetainsOnCancelledFlushContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	host := &flushHookHost{recordingHost: recordingHost{store: store}, flush: newCommandFlush(ctx, app)}
	status := newStatusState(app, providerCache(t, t.TempDir()), selectedState(), &BootstrapResult{LaunchDir: "/launch"}, enforce.Resolution{})

	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"status": tui.NewStatusHandler(status)})
	if tui.NewSubmitFunc(reg, host, nil)("/status") {
		t.Fatal("/status must be rejected (retain) when the command-event flush fails on a cancelled context")
	}
	if len(host.statuses) != 0 {
		t.Fatalf("status overlay opened %d times, want 0 (flush must fail before ShowStatus)", len(host.statuses))
	}
	// The cancelled context means no write was attempted, so the file is absent —
	// but the record is not lost: it remains in memory for a later flush to retry.
	if _, err := os.Stat(store.Path()); !os.IsNotExist(err) {
		t.Fatalf("os.Stat(%s) err = %v, want not-exist (a cancelled context attempts no write)", store.Path(), err)
	}
	if cmds := slashCmds(t, store); len(cmds) != 1 || cmds[0].Name != "status" {
		t.Fatalf("in-memory slash_command events = %+v, want one {status} retained for retry", cmds)
	}
}

// TestCommandFlush_WriteFailureRecordsAndContinues pins for the
// command-event flush hook: an atomic-write failure on the active store records
// session_write_failed (carrying the records forward) and returns nil so the
// command that triggered the flush is not aborted.
func TestCommandFlush_WriteFailureRecordsAndContinues(t *testing.T) {
	store := unwritableStore(t, "flush-fail-id", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)

	if err := newCommandFlush(context.Background(), app)(); err != nil {
		t.Fatalf("command flush should swallow a handled per-turn write failure, got %v", err)
	}
	if got := len(kindEvents(t, store, events.KindSessionWriteFailed)); got != 1 {
		t.Fatalf("session_write_failed events = %d, want 1 (req 400a)", got)
	}
}

// TestRefreshRecordFlush_WriteFailureRecordsAndReturnsError pins the stricter
// durability contract for CTRL-R model refresh history: it must report the
// atomic-write error to the picker even though it also records session_write_failed
// and leaves the refresh record in memory for a later retry. A normal command flush
// intentionally returns nil after the same handled failure.
func TestRefreshRecordFlush_WriteFailureRecordsAndReturnsError(t *testing.T) {
	store := unwritableStore(t, "refresh-flush-fail-id", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)

	if err := newRefreshRecordFlush(context.Background(), app)(store); err == nil {
		t.Fatal("refresh-record flush swallowed an atomic-write failure; the picker would claim an undurable refresh was recorded")
	}
	if got := len(kindEvents(t, store, events.KindSessionWriteFailed)); got != 1 {
		t.Fatalf("session_write_failed events = %d, want 1 (the write-failure protocol must still run)", got)
	}
}

func TestForkDeps_StrictFlushPreservesWriteError(t *testing.T) {
	store := unwritableStore(t, "01890000-0000-7000-8000-0000000f00f1", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)

	deps := newForkDeps(context.Background(), app, t.TempDir(), &resumeLockHolder{}, &turnController{}, statusState{}, fixedRecorder(injectedResolution), nil)
	if err := deps.FlushParent(store); err == nil {
		t.Fatal("strict fork flush swallowed an atomic-write failure; a handled newCommandFlush would return nil and let the fork proceed past an unwritten parent")
	}
	if got := len(kindEvents(t, store, events.KindSessionWriteFailed)); got != 1 {
		t.Fatalf("session_write_failed events = %d, want 1 (strict flush still reports the failure)", got)
	}
}

func TestPromptEntrypoint_PersistsUserInputThroughG255(t *testing.T) {
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	// No model is selected, so the controller's dispatch issues no turn; this test
	// pins only the persist-before-dispatch arm of the entrypoint.
	ctl := newTurnController(context.Background(), app, providerCache(t, t.TempDir()), model.NewActiveState(nil, ""), nil, nil)
	if !newPromptEntrypoint(context.Background(), app, ctl)("hello there") {
		t.Fatal("prompt entrypoint should accept and persist when the pre-turn flush succeeds")
	}
	if got := userMessageCount(store); got != 1 {
		t.Fatalf("persisted user messages = %d, want 1 (g255 pre-turn persistence)", got)
	}
}

func TestPromptEntrypoint_RejectsWhenPersistenceFails(t *testing.T) {
	// A store whose flush always fails blocks the pre-turn durability gate.
	store := unwritableStore(t, "no-flush-id", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)

	ctl := newTurnController(context.Background(), app, providerCache(t, t.TempDir()), model.NewActiveState(nil, ""), nil, nil)
	if newPromptEntrypoint(context.Background(), app, ctl)("hello") {
		t.Fatal("prompt entrypoint must reject (retain) when pre-turn persistence fails")
	}
}

// TestStartTUI_WiredSubmitIssuesCancellableStreamingTurn pins the wired streaming turn:
// a plain prompt submitted through the wired app persists the user message
// (persist-before-dispatch), issues a real provider turn against an injected stub
// client with no outbound network, streams deltas (retained chars > 0), and is
// cancellable through the canceller StartTUI installs via App.SetStreamCanceller.
// It fails if StartTUI no longer routes the prompt entrypoint through the turn
// controller, or no longer installs the controller as the stream canceller.
func TestStartTUI_WiredSubmitIssuesCancellableStreamingTurn(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	// Run the turn on a goroutine the test can join, so it never reads the session
	// store while the background turn is still writing to it.
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	// Stub provider client (no network): signal when the turn is issued, stream one
	// delta, then block until the request context is cancelled so the test can
	// observe a cancellable in-flight turn.
	entered := make(chan struct{})
	ready := make(chan struct{})
	client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
		close(entered)
		return provider.Response{Stream: blockingStream(ctx, contentChunk("Hi"), ready)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	home := t.TempDir()
	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")
	result := &BootstrapResult{
		Home:      home,
		LaunchDir: "/launch",
		Session:   store,
		Model:     model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{
					"base_url": "https://api.openai.com/v1",
					"api_key":  "sk-test",
				},
			},
		},
		ConfigLayerPaths: []string{SettingsPath(home)},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}

	if !ran.SubmitInput("hello") {
		t.Fatal("wired submit rejected a plain prompt; the prompt entrypoint is not wired to the turn controller")
	}

	<-entered // the turn was issued: the stub provider client was called
	<-ready   // the runtime consumed the first delta (retained > 0) and is now blocked in-flight

	retained, inFlight := ran.StreamCanceller().Cancel()
	if !inFlight {
		t.Fatal("installed stream canceller reports no in-flight turn; App.SetStreamCanceller is not wired to the live runner")
	}
	if retained == 0 {
		t.Fatal("no streamed deltas retained before cancel; AppendStreamDelta was not wired as the runtime sink")
	}

	turns.Wait() // let the cancelled turn's goroutine finish before reading the store

	if client.callCount() != 1 {
		t.Fatalf("provider client called %d times, want exactly 1 turn issued", client.callCount())
	}
	if got := userMessageCount(store); got != 1 {
		t.Fatalf("persisted user messages = %d, want 1 (persist-before-dispatch)", got)
	}
}

func TestStartTUI_BusyPlainPromptJoinsRunningTurn(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	entered := make(chan struct{})
	release := make(chan struct{})
	var streamed atomic.Int32
	var joinedReq provider.Request
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if isTitleRequest(req) {
			return titleCompletion("Joined prompt session"), nil
		}
		switch streamed.Add(1) {
		case 1:
			close(entered)
			<-release
			return provider.Response{Stream: newStream(contentChunk("first answer"), finishChunk("stop"))}, nil
		case 2:
			joinedReq = req
		}
		return provider.Response{Stream: newStream(contentChunk("second answer"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	projectRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectRoot, "diagram.png"), []byte("\x89PNG\r\n\x1a\nDATA"), 0o644); err != nil {
		t.Fatalf("write image: %v", err)
	}
	store := mkStore(t)
	result := indicatorTurnResult(t, store)
	result.LaunchDir, result.ProjectRoot = projectRoot, projectRoot

	var waiting, final string
	defer runLiveApp(t, tcell.NewSimulationScreen("UTF-8"), func(app *tui.App) {
		if !submitOnEventLoop(t, app, "first prompt") {
			t.Fatal("wired submit rejected a plain prompt; the turn entrypoint is not wired")
		}
		<-entered
		var accepted bool
		onEventLoop(t, app, func() {
			accepted = app.SubmitInput("look at this diagram.png")
			waiting = app.TranscriptText()
		})
		if !accepted {
			t.Fatal("busy plain prompt was rejected")
		}
		close(release)
		turns.Wait()
		onEventLoop(t, app, func() { final = app.TranscriptText() })
	})()

	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}

	if strings.Contains(waiting, "look at this") {
		t.Fatalf("transcript while waiting = %q, want no echo before the turn adds the message", waiting)
	}
	if got := streamed.Load(); got != 2 {
		t.Fatalf("streamed provider requests = %d, want 2 (the joined message rides the running turn, not a new one)", got)
	}
	msgs := joinedReq.Messages
	if len(msgs) < 2 || msgs[len(msgs)-2].Role != "assistant" || msgs[len(msgs)-2].Content != "first answer" {
		t.Fatalf("next request messages = %+v, want the first answer followed by the joined message", msgs)
	}
	if joined := msgs[len(msgs)-1]; joined.Role != "user" || !hasImageURLPart(joined.Parts) {
		t.Fatalf("joined message = %+v, want a user message carrying the image part", joined)
	}
	if got := userMessageCount(store); got != 2 {
		t.Fatalf("persisted user messages = %d, want 2", got)
	}
	if got := strings.Count(final, "look at this"); got != 1 {
		t.Fatalf("transcript has %d echoes of the joined message, want 1:\n%s", got, final)
	}
	first, joined, second := strings.Index(final, "first answer"), strings.Index(final, "look at this"), strings.Index(final, "second answer")
	if first < 0 || joined < first || second < joined {
		t.Fatalf("transcript = %q, want first answer, joined message, second answer in order", final)
	}
}

func TestStartTUI_CompletedTurnDispatchesUnsentPrompt(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	entered := make(chan struct{})
	release := make(chan struct{})
	var streamed atomic.Int32
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if isTitleRequest(req) {
			return titleCompletion("Unsent prompt session"), nil
		}
		if streamed.Add(1) == 1 {
			close(entered)
			<-release
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"go test ./..."}`)))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("second"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()
	terminal := &fakeTurnDispatcher{results: map[string]turn.ToolResult{"call_1": {Content: "done", Terminal: true}}}
	defer swapToolLoop(func(d turn.Deps, _ turn.ToolDispatcher, n int) *turn.ToolLoop {
		return turn.NewToolLoop(d, terminal, n)
	})()

	store := mkStore(t)
	var final string
	defer runLiveApp(t, tcell.NewSimulationScreen("UTF-8"), func(app *tui.App) {
		if !submitOnEventLoop(t, app, "first prompt") {
			t.Fatal("wired submit rejected a plain prompt; the turn entrypoint is not wired")
		}
		<-entered
		if !submitOnEventLoop(t, app, "unsent prompt") {
			t.Fatal("busy plain prompt was rejected")
		}
		close(release)
		turns.Wait()
		onEventLoop(t, app, func() { final = app.TranscriptText() })
	})()

	if err := StartTUI(context.Background(), indicatorTurnResult(t, store), io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}

	if got := streamed.Load(); got != 2 {
		t.Fatalf("streamed provider requests = %d, want 2 (the unsent prompt dispatches once as the next turn)", got)
	}
	if got := userMessageCount(store); got != 2 {
		t.Fatalf("persisted user messages = %d, want 2 (the unsent prompt persists through the normal pre-turn path)", got)
	}
	if !diskHasUserMessage(readSessionFile(t, store.Path()), "unsent prompt") {
		t.Fatal("the dispatched unsent prompt never reached the flushed session")
	}
	if got := strings.Count(final, "unsent prompt"); got != 1 {
		t.Fatalf("transcript has %d echoes of the unsent prompt, want 1:\n%s", got, final)
	}
}

func TestPromptEntrypoint_LoopClosingBetweenSubmitsKeepsSubmitOrder(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	firstEntered, firstRelease := make(chan struct{}), make(chan struct{})
	nextEntered, nextRelease := make(chan struct{}), make(chan struct{})
	var streamed atomic.Int32
	client := &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		switch streamed.Add(1) {
		case 1:
			close(firstEntered)
			<-firstRelease
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"go test ./..."}`)))}, nil
		case 2:
			close(nextEntered)
			<-nextRelease
		}
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	ctx := context.Background()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	ctl := newTurnController(ctx, app, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setToolDispatcher(&fakeTurnDispatcher{results: map[string]turn.ToolResult{"call_1": {Content: "done", Terminal: true}}})
	loopClosed, handOff := make(chan struct{}), make(chan struct{})
	var firstEnd sync.Once
	ctl.setUnsentHook(func(store *sessions.Store, unsent []turn.PendingUserMessage, outcome string) func() {
		firstEnd.Do(func() {
			close(loopClosed)
			<-handOff
		})
		return app.UserMessagesUnsent(store, len(unsent), 0, outcome)
	})
	entry := newPromptEntrypoint(ctx, app, ctl)
	app.SetSubmit(func(input string, parts ...sessions.ContentPart) bool { return entry(input, parts...) })
	app.SetScreenFactoryForTest(func() (tcell.Screen, error) { return tcell.NewSimulationScreen("UTF-8"), nil })
	errc := make(chan error, 1)
	go func() { errc <- app.Run() }()
	onEventLoop(t, app, func() {})

	transcriptOf := func() string {
		var text string
		onEventLoop(t, app, func() { text = app.TranscriptText() })
		return text
	}
	submit := func(input string) {
		t.Helper()
		if !submitOnEventLoop(t, app, input) {
			t.Fatalf("submit %q was rejected", input)
		}
	}

	submit("first prompt")
	<-firstEntered
	submit("extra A")
	if got := transcriptOf(); strings.Contains(got, "extra A") {
		t.Fatalf("transcript = %q, want no echo for the message the running turn accepted", got)
	}
	close(firstRelease)
	<-loopClosed
	submit("extra B")
	close(handOff)
	<-nextEntered
	submit("extra C")
	close(nextRelease)
	turns.Wait()
	final := transcriptOf()
	app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app run: %v", err)
	}

	if got := streamed.Load(); got != 4 {
		t.Fatalf("streamed provider requests = %d, want 4 (the first turn plus one turn per extra message)", got)
	}
	var users []string
	for _, rec := range store.Records() {
		if m, ok := rec.(sessions.Message); ok && m.Role == "user" {
			users = append(users, m.Content.Text())
		}
	}
	if want := []string{"first prompt", "extra A", "extra B", "extra C"}; !slices.Equal(users, want) {
		t.Fatalf("persisted user messages = %q, want %q (submit order, each once)", users, want)
	}
	a, b, c := strings.Index(final, "extra A"), strings.Index(final, "extra B"), strings.Index(final, "extra C")
	if a < 0 || b < a || c < b {
		t.Fatalf("transcript = %q, want the extra messages echoed in submit order", final)
	}
	for _, s := range []string{"extra A", "extra B", "extra C"} {
		if got := strings.Count(final, s); got != 1 {
			t.Fatalf("transcript has %d echoes of %q, want 1:\n%s", got, s, final)
		}
	}
}

func TestPromptEntrypoint_NoTurnStartsBeforeEarlierTurnEnds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		unsent bool
		fork   bool
		want   []string
	}{
		{name: "completed with an unsent message", unsent: true, want: []string{"first prompt", "handed off", "second prompt"}},
		{name: "completed with zero unsent", want: []string{"first prompt", "second prompt"}},
		{name: "fork refused while the end is pending", fork: true, want: []string{"first prompt", "second prompt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var turns sync.WaitGroup
			defer swapGoTurn(waitableGoTurn(&turns))()

			firstEntered, firstRelease, lastEntered := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var streamed atomic.Int32
			client := &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
				n := streamed.Add(1)
				if n == int32(len(tc.want)) {
					close(lastEntered)
				}
				if n == 1 {
					close(firstEntered)
					<-firstRelease
					if tc.unsent {
						return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"go test ./..."}`)))}, nil
					}
				}
				return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			ctx := context.Background()
			store := mkStore(t)
			app := tui.New(nil)
			app.SetActiveStore(store)
			ctl := newTurnController(ctx, app, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
			ctl.setToolDispatcher(&fakeTurnDispatcher{results: map[string]turn.ToolResult{"call_1": {Content: "done", Terminal: true}}})
			firstEnding, releaseFirstEnd := make(chan struct{}), make(chan struct{})
			var holdFirst sync.Once
			ctl.setUnsentHook(func(store *sessions.Store, unsent []turn.PendingUserMessage, outcome string) func() {
				end := app.UserMessagesUnsent(store, len(unsent), 0, outcome)
				held := false
				holdFirst.Do(func() { held = true })
				if !held {
					return end
				}
				return func() {
					close(firstEnding)
					<-releaseFirstEnd
					end()
				}
			})
			reg := tui.BuildRegistry(map[string]tui.HandlerFunc{
				"fork": tui.NewForkHandler(newForkDeps(ctx, app, t.TempDir(), &resumeLockHolder{}, ctl, statusState{}, fixedRecorder(injectedResolution), nil)),
			})
			app.SetSubmit(tui.NewSubmitFunc(reg, app, newPromptEntrypoint(ctx, app, ctl)))
			app.SetScreenFactoryForTest(func() (tcell.Screen, error) { return tcell.NewSimulationScreen("UTF-8"), nil })
			errc := make(chan error, 1)
			go func() { errc <- app.Run() }()
			onEventLoop(t, app, func() {})

			submit := func(input string) {
				t.Helper()
				if !submitOnEventLoop(t, app, input) {
					t.Fatalf("submit %q was rejected", input)
				}
			}

			submit("first prompt")
			<-firstEntered
			if tc.unsent {
				submit("handed off")
			}
			close(firstRelease)
			<-firstEnding
			if tc.fork {
				submitOnEventLoop(t, app, "/fork")
				var notice string
				onEventLoop(t, app, func() { notice = app.NoticeText() })
				if notice != "fork unavailable while a turn is active" {
					t.Fatalf("notice after /fork = %q, want the refusal while the earlier turn's end is pending", notice)
				}
			}
			submit("second prompt")
			if ctl.busy() {
				t.Fatal("a submit while the earlier turn's end was pending started a new turn")
			}
			close(releaseFirstEnd)
			<-lastEntered
			turns.Wait()
			var final string
			onEventLoop(t, app, func() { final = app.TranscriptText() })
			app.Stop()
			if err := <-errc; err != nil {
				t.Fatalf("app run: %v", err)
			}

			if got := streamed.Load(); got != int32(len(tc.want)) {
				t.Fatalf("streamed provider requests = %d, want %d (one turn per message, none started early)", got, len(tc.want))
			}
			if app.ActiveStore() != store {
				t.Fatal("the active store changed; /fork must be refused while the earlier turn's end is pending")
			}
			var users []string
			for _, rec := range store.Records() {
				if m, ok := rec.(sessions.Message); ok && m.Role == "user" {
					users = append(users, m.Content.Text())
				}
			}
			if !slices.Equal(users, tc.want) {
				t.Fatalf("persisted user messages = %q, want %q (submit order, each once)", users, tc.want)
			}
			for _, s := range tc.want[1:] {
				if got := strings.Count(final, s); got != 1 {
					t.Fatalf("transcript has %d echoes of %q, want 1:\n%s", got, s, final)
				}
			}
		})
	}
}

type gatedToolDispatcher struct {
	entered, release chan struct{}
	terminal         bool
}

func (d gatedToolDispatcher) Plan(calls []turn.AssembledToolCall, _ int) turn.ToolPlan {
	plan := turn.ToolPlan{Units: make([]turn.PlannedToolCall, len(calls))}
	for i, call := range calls {
		plan.Units[i] = turn.PlannedToolCall{
			Call: call,
			Run:  func(ctx context.Context) (turn.ToolResult, error) { return d.Dispatch(ctx, call) },
		}
	}
	return plan
}

func (d gatedToolDispatcher) Dispatch(context.Context, turn.AssembledToolCall) (turn.ToolResult, error) {
	close(d.entered)
	<-d.release
	return turn.ToolResult{Content: "ok", Terminal: d.terminal}, nil
}

func midTurnSwitchResult(t *testing.T, command string) (*BootstrapResult, *sessions.Store, func()) {
	t.Helper()
	home, folder := t.TempDir(), t.TempDir()
	canon, err := sessions.CanonicalizeFolder(folder)
	if err != nil {
		t.Fatalf("canonicalize folder: %v", err)
	}
	prior, err := sessions.EnsureSession(home, canon, testStart, nil)
	if err != nil {
		t.Fatalf("ensure prior session: %v", err)
	}
	target, err := sessions.EnsureSession(home, canon, testStart, []sessions.Record{
		sessions.Message{ID: ids.NewV7(), Role: "user", Content: sessions.TextContent("resumed question"), Timestamp: testStart},
	})
	if err != nil {
		t.Fatalf("ensure resume target: %v", err)
	}
	mustFlush(t, prior)
	mustFlush(t, target)
	result := indicatorTurnResult(t, prior)
	result.Home, result.LaunchDir = home, folder
	if command != "/resume" {
		return result, prior, func() {}
	}
	build := newResumeDeps
	return result, prior, swapNewResumeDeps(func(c context.Context, app *tui.App, r *BootstrapResult, lock *resumeLockHolder, cache *config.Cache, active *model.ActiveState, recorder *capabilityRecorder, conf *confinement) tui.ResumeDeps {
		deps := build(c, app, r, lock, cache, active, recorder, conf)
		deps.Picker = &selectingResumePicker{selectID: target.SessionID()}
		return deps
	})
}

func simScreenText(screen tcell.SimulationScreen) string {
	cells, width, height := screen.GetContents()
	var b strings.Builder
	for row := range height {
		for col := range width {
			b.WriteString(string(cells[row*width+col].Runes))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func TestStartTUI_MessageAddedWhileSwitchWaitsForDrainDoesNotDeadlock(t *testing.T) {
	for _, command := range []string{"/clear", "/resume"} {
		t.Run(command[1:], func(t *testing.T) {
			var turns sync.WaitGroup
			defer swapGoTurn(waitableGoTurn(&turns))()

			var streamed atomic.Int32
			client := &stubTurnClient{fn: func(ctx context.Context, req provider.Request) (provider.Response, error) {
				if isTitleRequest(req) {
					return titleCompletion("Switch session"), nil
				}
				if streamed.Add(1) == 1 {
					return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"go test ./..."}`)))}, nil
				}
				<-ctx.Done()
				return provider.Response{}, ctx.Err()
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()
			tool := gatedToolDispatcher{entered: make(chan struct{}), release: make(chan struct{})}
			defer swapToolLoop(func(d turn.Deps, _ turn.ToolDispatcher, n int) *turn.ToolLoop {
				return turn.NewToolLoop(d, tool, n)
			})()

			result, prior, restore := midTurnSwitchResult(t, command)
			defer restore()
			screen := tcell.NewSimulationScreen("UTF-8")
			var active *sessions.Store
			var final, rendered string
			defer runLiveApp(t, screen, func(app *tui.App) {
				if !submitOnEventLoop(t, app, "first prompt") {
					t.Fatal("wired submit rejected a plain prompt")
				}
				<-tool.entered
				if !submitOnEventLoop(t, app, "extra message") {
					t.Fatal("busy plain prompt was rejected")
				}
				held, start, cmdDone := make(chan struct{}), make(chan struct{}), make(chan bool, 1)
				go app.RunOnEventLoopForTest(func() {
					close(held)
					<-start
					cmdDone <- app.SubmitInput(command)
				})
				<-held
				close(tool.release)
				deadline := time.Now().Add(5 * time.Second)
				for !slices.ContainsFunc(prior.Records(), func(r sessions.Record) bool {
					m, ok := r.(sessions.Message)
					return ok && m.Role == "user" && m.Content.Text() == "extra message"
				}) {
					if time.Now().After(deadline) {
						t.Fatal("the running turn never committed the accepted message")
					}
					time.Sleep(2 * time.Millisecond)
				}
				close(start)
				select {
				case ok := <-cmdDone:
					if !ok {
						t.Fatalf("%s was rejected", command)
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("%s never returned: the turn blocked reporting the added message while the command waited for it to drain", command)
				}
				var notice string
				onEventLoop(t, app, func() { active, notice = app.ActiveStore(), app.NoticeText() })
				if active == prior {
					t.Fatalf("%s did not switch away from the prior session; notice = %q", command, notice)
				}
				turns.Wait()
				onEventLoop(t, app, func() {})
				onEventLoop(t, app, func() { final, rendered = app.TranscriptText(), simScreenText(screen) })
			})()

			if err := StartTUI(context.Background(), result, io.Discard); err != nil {
				t.Fatalf("StartTUI error: %v", err)
			}

			if strings.Contains(final, "extra message") {
				t.Fatalf("new transcript = %q, want no echo of a message the prior session's turn added", final)
			}
			if strings.Contains(rendered, "sending: ") || strings.Contains(rendered, "queued: ") {
				t.Fatalf("rendered screen still shows a queue row:\n%s", rendered)
			}
			if got := decodeStoreEvents[events.QueuedPromptDiscarded](t, prior, events.KindQueuedPromptDiscarded); len(got) != 0 {
				t.Fatalf("prior discard events = %+v, want none for a message the turn added", got)
			}
		})
	}
}

func TestStartTUI_SwitchDuringTurnRecordsUnsentMessageInPriorSession(t *testing.T) {
	for _, command := range []string{"/clear", "/resume"} {
		t.Run(command[1:], func(t *testing.T) {
			var turns sync.WaitGroup
			defer swapGoTurn(waitableGoTurn(&turns))()

			ready := make(chan struct{})
			client := &stubTurnClient{fn: func(ctx context.Context, req provider.Request) (provider.Response, error) {
				if isTitleRequest(req) {
					return titleCompletion("Switch session"), nil
				}
				return provider.Response{Stream: blockingStream(ctx, contentChunk("Hi"), ready)}, nil
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			result, prior, restore := midTurnSwitchResult(t, command)
			defer restore()
			screen := tcell.NewSimulationScreen("UTF-8")
			var active *sessions.Store
			var waiting, final, rendered string
			defer runLiveApp(t, screen, func(app *tui.App) {
				if !submitOnEventLoop(t, app, "first prompt") {
					t.Fatal("wired submit rejected a plain prompt")
				}
				<-ready
				if !submitOnEventLoop(t, app, "extra message") {
					t.Fatal("busy plain prompt was rejected")
				}
				onEventLoop(t, app, func() {})
				onEventLoop(t, app, func() { waiting = simScreenText(screen) })
				if !submitOnEventLoop(t, app, command) {
					t.Fatalf("%s was rejected", command)
				}
				turns.Wait()
				onEventLoop(t, app, func() {})
				onEventLoop(t, app, func() {
					active, final, rendered = app.ActiveStore(), app.TranscriptText(), simScreenText(screen)
				})
			})()

			if err := StartTUI(context.Background(), result, io.Discard); err != nil {
				t.Fatalf("StartTUI error: %v", err)
			}

			if !strings.Contains(waiting, "sending: extra message") {
				t.Fatalf("rendered screen before %s:\n%s\nwant the message waiting as a sending row", command, waiting)
			}
			if active == prior {
				t.Fatalf("%s did not switch away from the prior session", command)
			}
			want := []events.QueuedPromptDiscarded{{Text: "extra message", Reason: "interrupted"}}
			if got := decodeDiskEvents[events.QueuedPromptDiscarded](t, readSessionFile(t, prior.Path()), events.KindQueuedPromptDiscarded); !slices.Equal(got, want) {
				t.Fatalf("prior session discard events on disk = %+v, want %+v", got, want)
			}
			if got := decodeStoreEvents[events.QueuedPromptDiscarded](t, active, events.KindQueuedPromptDiscarded); len(got) != 0 {
				t.Fatalf("switched-to session discard events = %+v, want none", got)
			}
			if strings.Contains(final, "not sent:") || strings.Contains(final, "extra message") {
				t.Fatalf("new transcript = %q, want no trace of the prior turn's unsent message", final)
			}
			if strings.Contains(rendered, "sending: ") || strings.Contains(rendered, "queued: ") {
				t.Fatalf("rendered screen still shows a queue row:\n%s", rendered)
			}
		})
	}
}

type unsentHook = func(*sessions.Store, []turn.PendingUserMessage, string) func()

func wrapStartTUIUnsentHook(wrap func(ctl *turnController, next unsentHook) unsentHook) func() {
	build := newResumeDeps
	return swapNewResumeDeps(func(c context.Context, app *tui.App, r *BootstrapResult, lock *resumeLockHolder, cache *config.Cache, active *model.ActiveState, recorder *capabilityRecorder, conf *confinement) tui.ResumeDeps {
		ctl := app.StreamCanceller().(*turnController)
		ctl.setUnsentHook(wrap(ctl, ctl.onUnsent))
		return build(c, app, r, lock, cache, active, recorder, conf)
	})
}

func switchWhileEventLoopHeld(t *testing.T, app *tui.App, command string, whileHeld func()) {
	t.Helper()
	held, start, cmdDone := make(chan struct{}), make(chan struct{}), make(chan bool, 1)
	go app.RunOnEventLoopForTest(func() {
		close(held)
		<-start
		cmdDone <- app.SubmitInput(command)
	})
	<-held
	whileHeld()
	close(start)
	select {
	case ok := <-cmdDone:
		if !ok {
			t.Fatalf("%s was rejected", command)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s never returned", command)
	}
}

func assertHeldMessagesStayInPriorSession(t *testing.T, prior, active *sessions.Store, final, rendered string, want []events.QueuedPromptDiscarded, texts ...string) {
	t.Helper()
	if active == prior {
		t.Fatal("the command did not switch away from the prior session")
	}
	if got := decodeDiskEvents[events.QueuedPromptDiscarded](t, readSessionFile(t, prior.Path()), events.KindQueuedPromptDiscarded); !slices.Equal(got, want) {
		t.Fatalf("prior session discard events on disk = %+v, want %+v", got, want)
	}
	if got := decodeStoreEvents[events.QueuedPromptDiscarded](t, active, events.KindQueuedPromptDiscarded); len(got) != 0 {
		t.Fatalf("switched-to session discard events = %+v, want none", got)
	}
	for _, text := range texts {
		for _, rec := range active.Records() {
			if m, ok := rec.(sessions.Message); ok && m.Content.Text() == text {
				t.Fatalf("switched-to session recorded the prior session's message %q", text)
			}
		}
		if strings.Contains(final, text) {
			t.Fatalf("new transcript = %q, want no trace of %q", final, text)
		}
	}
	if strings.Contains(final, "not sent:") {
		t.Fatalf("new transcript = %q, want no not-sent line", final)
	}
	if strings.Contains(rendered, "sending: ") || strings.Contains(rendered, "queued: ") {
		t.Fatalf("rendered screen still shows a queue row:\n%s", rendered)
	}
}

func TestStartTUI_SwitchBeforeCompletedTurnEndsDiscardsUnsentMessageInPriorSession(t *testing.T) {
	for _, command := range []string{"/clear", "/resume"} {
		t.Run(command[1:], func(t *testing.T) {
			var turns sync.WaitGroup
			defer swapGoTurn(waitableGoTurn(&turns))()

			var streamed atomic.Int32
			client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
				if isTitleRequest(req) {
					return titleCompletion("Switch session"), nil
				}
				if streamed.Add(1) == 1 {
					return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"go test ./..."}`)))}, nil
				}
				return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()
			tool := gatedToolDispatcher{entered: make(chan struct{}), release: make(chan struct{}), terminal: true}
			defer swapToolLoop(func(d turn.Deps, _ turn.ToolDispatcher, n int) *turn.ToolLoop {
				return turn.NewToolLoop(d, tool, n)
			})()

			result, prior, restore := midTurnSwitchResult(t, command)
			defer restore()
			ended, proceed := make(chan struct{}), make(chan struct{})
			var endOnce sync.Once
			defer wrapStartTUIUnsentHook(func(_ *turnController, next unsentHook) unsentHook {
				return func(store *sessions.Store, msgs []turn.PendingUserMessage, outcome string) func() {
					end := next(store, msgs, outcome)
					endOnce.Do(func() {
						close(ended)
						<-proceed
					})
					return end
				}
			})()
			screen := tcell.NewSimulationScreen("UTF-8")
			var active *sessions.Store
			var final, rendered string
			defer runLiveApp(t, screen, func(app *tui.App) {
				if !submitOnEventLoop(t, app, "first prompt") {
					t.Fatal("wired submit rejected a plain prompt")
				}
				<-tool.entered
				if !submitOnEventLoop(t, app, "extra message") {
					t.Fatal("busy plain prompt was rejected")
				}
				close(tool.release)
				select {
				case <-ended:
				case <-time.After(5 * time.Second):
					t.Fatal("the turn never completed")
				}
				switchWhileEventLoopHeld(t, app, command, func() { close(proceed) })
				turns.Wait()
				onEventLoop(t, app, func() {})
				onEventLoop(t, app, func() {
					active, final, rendered = app.ActiveStore(), app.TranscriptText(), simScreenText(screen)
				})
			})()

			if err := StartTUI(context.Background(), result, io.Discard); err != nil {
				t.Fatalf("StartTUI error: %v", err)
			}

			if got := streamed.Load(); got != 1 {
				t.Fatalf("streamed provider requests = %d, want 1 (the unsent message is not dispatched after the switch)", got)
			}
			want := []events.QueuedPromptDiscarded{{Text: "extra message", Reason: "interrupted"}}
			assertHeldMessagesStayInPriorSession(t, prior, active, final, rendered, want, "extra message")
		})
	}
}

func TestStartTUI_SwitchBeforeInterruptedTurnEndsDiscardsAcceptedAndFallbackMessages(t *testing.T) {
	for _, command := range []string{"/clear", "/resume"} {
		t.Run(command[1:], func(t *testing.T) {
			var turns sync.WaitGroup
			defer swapGoTurn(waitableGoTurn(&turns))()

			ready := make(chan struct{})
			var streamed atomic.Int32
			client := &stubTurnClient{fn: func(ctx context.Context, req provider.Request) (provider.Response, error) {
				if isTitleRequest(req) {
					return titleCompletion("Switch session"), nil
				}
				streamed.Add(1)
				return provider.Response{Stream: blockingStream(ctx, contentChunk("Hi"), ready)}, nil
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			result, prior, restore := midTurnSwitchResult(t, command)
			defer restore()
			var ctl *turnController
			loopClosed, handOff := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer wrapStartTUIUnsentHook(func(c *turnController, next unsentHook) unsentHook {
				ctl = c
				return func(store *sessions.Store, msgs []turn.PendingUserMessage, outcome string) func() {
					once.Do(func() {
						close(loopClosed)
						<-handOff
					})
					return next(store, msgs, outcome)
				}
			})()

			screen := tcell.NewSimulationScreen("UTF-8")
			var active *sessions.Store
			var final, rendered string
			defer runLiveApp(t, screen, func(app *tui.App) {
				if !submitOnEventLoop(t, app, "first prompt") {
					t.Fatal("wired submit rejected a plain prompt")
				}
				<-ready
				if !submitOnEventLoop(t, app, "message A") {
					t.Fatal("busy plain prompt was rejected")
				}
				ctl.Cancel()
				<-loopClosed
				if !submitOnEventLoop(t, app, "message B") {
					t.Fatal("submit after the loop closed was rejected")
				}
				switchWhileEventLoopHeld(t, app, command, func() { close(handOff) })
				turns.Wait()
				onEventLoop(t, app, func() {})
				onEventLoop(t, app, func() {
					active, final, rendered = app.ActiveStore(), app.TranscriptText(), simScreenText(screen)
				})
			})()

			if err := StartTUI(context.Background(), result, io.Discard); err != nil {
				t.Fatalf("StartTUI error: %v", err)
			}

			if got := streamed.Load(); got != 1 {
				t.Fatalf("streamed provider requests = %d, want 1 (neither held message is dispatched)", got)
			}
			want := []events.QueuedPromptDiscarded{
				{Text: "message A", Reason: "interrupted"},
				{Text: "message B", Reason: "interrupted"},
			}
			assertHeldMessagesStayInPriorSession(t, prior, active, final, rendered, want, "message A", "message B")
		})
	}
}

func TestStartTUI_MessageAddedAfterTurnEndedStaysInPriorSession(t *testing.T) {
	for _, command := range []string{"/clear", "/resume"} {
		t.Run(command[1:], func(t *testing.T) {
			var turns sync.WaitGroup
			defer swapGoTurn(waitableGoTurn(&turns))()

			var streamed atomic.Int32
			client := &stubTurnClient{fn: func(ctx context.Context, req provider.Request) (provider.Response, error) {
				if isTitleRequest(req) {
					return titleCompletion("Switch session"), nil
				}
				if streamed.Add(1) == 1 {
					return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"go test ./..."}`)))}, nil
				}
				<-ctx.Done()
				return provider.Response{}, ctx.Err()
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()
			tool := gatedToolDispatcher{entered: make(chan struct{}), release: make(chan struct{})}
			delay, delivered := make(chan struct{}), make(chan struct{})
			defer swapToolLoop(func(d turn.Deps, _ turn.ToolDispatcher, n int) *turn.ToolLoop {
				added := d.OnUserMessageAdded
				d.OnUserMessageAdded = func(text string, parts []sessions.ContentPart) {
					go func() {
						<-delay
						added(text, parts)
						close(delivered)
					}()
				}
				return turn.NewToolLoop(d, tool, n)
			})()

			result, prior, restore := midTurnSwitchResult(t, command)
			defer restore()
			screen := tcell.NewSimulationScreen("UTF-8")
			var active *sessions.Store
			var final, rendered string
			defer runLiveApp(t, screen, func(app *tui.App) {
				if !submitOnEventLoop(t, app, "first prompt") {
					t.Fatal("wired submit rejected a plain prompt")
				}
				<-tool.entered
				if !submitOnEventLoop(t, app, "extra message") {
					t.Fatal("busy plain prompt was rejected")
				}
				close(tool.release)
				deadline := time.Now().Add(5 * time.Second)
				for streamed.Load() < 2 {
					if time.Now().After(deadline) {
						t.Fatal("the running turn never sent the accepted message")
					}
					time.Sleep(2 * time.Millisecond)
				}
				if !submitOnEventLoop(t, app, command) {
					t.Fatalf("%s was rejected", command)
				}
				turns.Wait()
				onEventLoop(t, app, func() {})
				close(delay)
				<-delivered
				onEventLoop(t, app, func() {})
				onEventLoop(t, app, func() {
					active, final, rendered = app.ActiveStore(), app.TranscriptText(), simScreenText(screen)
				})
			})()

			if err := StartTUI(context.Background(), result, io.Discard); err != nil {
				t.Fatalf("StartTUI error: %v", err)
			}

			if got := streamed.Load(); got != 2 {
				t.Fatalf("streamed provider requests = %d, want 2 (the added message is not dispatched again)", got)
			}
			var users []string
			for _, rec := range readSessionFile(t, prior.Path()).Records {
				if m, ok := rec.(sessions.Message); ok && m.Role == "user" {
					users = append(users, m.Content.Text())
				}
			}
			if want := []string{"first prompt", "extra message"}; !slices.Equal(users, want) {
				t.Fatalf("prior session user messages = %q, want %q", users, want)
			}
			assertHeldMessagesStayInPriorSession(t, prior, active, final, rendered, nil, "extra message")
		})
	}
}

// TestStartTUI_WiredSubmitAssemblesBaseEnvAgentsInOrder pins system-message assembly: a prompt submitted
// through the app StartTUI assembles leads its provider request with the single
// synthetic system message StartTUI assembles per dispatch — the active mode's base
// prompt, the environment block, and the loaded AGENTS.md text, in that order.
// It fails if StartTUI reverts to the static AGENTS-only prompt: the base
// prompt and environment block would be absent.
func TestStartTUI_WiredSubmitAssemblesBaseEnvAgentsInOrder(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var firstSystem string
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if !isTitleRequest(req) && len(req.Messages) > 0 && req.Messages[0].Role == "system" {
			firstSystem = req.Messages[0].Content
		}
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	const agentsMarker = "AGENTS-MARKER-XYZ"
	home := t.TempDir()
	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")
	result := &BootstrapResult{
		Home:        home,
		LaunchDir:   "/launch",
		ProjectRoot: "/launch/proj",
		Session:     store,
		Model:       model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Mode:        mode.NewActiveState(mode.Build, mode.SourceDefault),
		AgentInstructions: []agentinstr.LoadEntry{
			{Path: "/launch/proj/AGENTS.md", Layer: agentinstr.LayerWalked, LoadOrder: 2, Content: []byte(agentsMarker)},
		},
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{
					"base_url": "https://api.openai.com/v1",
					"api_key":  "sk-test",
				},
			},
		},
		ConfigLayerPaths: []string{SettingsPath(home)},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}

	if !ran.SubmitInput("hello") {
		t.Fatal("wired submit rejected a plain prompt; the prompt entrypoint is not wired")
	}
	turns.Wait()

	if firstSystem == "" {
		t.Fatal("provider request carried no system message; StartTUI did not assemble the base+env+AGENTS prompt")
	}
	idxBase := strings.Index(firstSystem, "Build mode")
	idxEnv := strings.Index(firstSystem, "Environment:")
	idxAgents := strings.Index(firstSystem, agentsMarker)
	if idxBase < 0 || idxEnv < 0 || idxAgents < 0 {
		t.Fatalf("system message missing a section (base=%d env=%d agents=%d):\n%s", idxBase, idxEnv, idxAgents, firstSystem)
	}
	if idxBase >= idxEnv || idxEnv >= idxAgents {
		t.Fatalf("system message sections out of order (base=%d env=%d agents=%d):\n%s", idxBase, idxEnv, idxAgents, firstSystem)
	}
	if !strings.Contains(firstSystem, "Project: proj") {
		t.Fatalf("env block missing the project name (basename of ProjectRoot):\n%s", firstSystem)
	}
}

// TestStartTUI_WiredSubmitDispatchesToolCallThroughProductionDispatcher pins the
// production dispatcher binding: a prompt submitted through the app StartTUI built, answered
// by a provider tool-call response, must route through the production tool
// dispatcher StartTUI binds onto the turn controller (starttui.go's
// turnCtl.setToolDispatcher over the realized registry). The fake provider returns
// a structured call to an unknown tool, which the production dispatcher refuses
// in-band as no_such_tool without prompting (DispatchTool rejects an unregistered
// name before authorizing); the tool-call loop records that tool result and re-issues to a
// final answer.
//
// The other StartTUI submit tests only drive plain prompts, so removing the
// setToolDispatcher handoff would leave the controller's dispatcher nil and go
// uncaught until a real model emitted a tool call. This test exercises that handoff
// directly: with the dispatcher unbound the tool-call round cannot be serviced, so
// no tool result is recorded and the loop never re-issues to its final answer.
func TestStartTUI_WiredSubmitDispatchesToolCallThroughProductionDispatcher(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	// Run the agentic turn on a goroutine the test can join before reading the store.
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	// Round 1 returns a tool call to an unknown structured tool; round 2 returns the
	// final answer once the loop has recorded the no_such_tool result and re-issued.
	var round int32
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "read_file", `{"path":"/x"}`)))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	home := t.TempDir()
	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")
	result := &BootstrapResult{
		Home:      home,
		LaunchDir: "/launch",
		Session:   store,
		Model:     model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{
					"base_url": "https://api.openai.com/v1",
					"api_key":  "sk-test",
				},
			},
		},
		ConfigLayerPaths: []string{SettingsPath(home)},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}

	if !ran.SubmitInput("read a file") {
		t.Fatal("wired submit rejected a plain prompt; the prompt entrypoint is not wired to the turn controller")
	}
	turns.Wait()

	toolMsgs := messagesByRole(store, "tool")
	if len(toolMsgs) != 1 {
		t.Fatalf("tool result messages = %d, want 1 (StartTUI's bound dispatcher must service the tool-call round; an unbound dispatcher records none)", len(toolMsgs))
	}
	if got := toolMsgs[0].Content.Text(); !strings.Contains(got, "no_such_tool: read_file") {
		t.Fatalf("tool result content = %q, want a no_such_tool result from the realized-registry-backed production dispatcher", got)
	}
	if toolMsgs[0].ToolCallID != "call_1" {
		t.Fatalf("tool result tool_call_id = %q, want call_1 (the dispatcher's result correlated to the model's call)", toolMsgs[0].ToolCallID)
	}
	asst := messagesByRole(store, "assistant")
	if len(asst) == 0 || asst[len(asst)-1].Content.Text() != "done" {
		t.Fatalf("final assistant message = %+v, want the loop to re-issue to %q after the dispatched tool result", asst, "done")
	}
	if client.callCount() != 3 {
		t.Fatalf("provider calls = %d, want 3 (one tool-call round through the dispatcher, one final round, one title request)", client.callCount())
	}
}

// advTestTool is a minimal registry tool with controllable name, description, schema,
// and read-only class for the advertised-set assembly tests.
type advTestTool struct {
	name     string
	desc     string
	params   map[string]any
	readOnly bool
}

func (t advTestTool) Name() string        { return t.name }
func (t advTestTool) SubjectKind() string { return "tool" }
func (t advTestTool) Advertise() tools.Metadata {
	return tools.Metadata{Description: t.desc, Parameters: t.params, ReadOnly: t.readOnly}
}
func (t advTestTool) Invoke(context.Context, map[string]any) (tools.Result, error) {
	return tools.Result{}, nil
}

func advRegistry(t *testing.T) *tools.Registry {
	t.Helper()
	reg := tools.NewRegistry()
	for _, tool := range []advTestTool{
		{name: "vcs_status", desc: "show", params: map[string]any{"type": "object"}, readOnly: true},
		{name: "vcs_commit", desc: "commit", params: map[string]any{"type": "object"}, readOnly: false},
	} {
		if err := reg.Register(tools.BuiltinSource, tool); err != nil {
			t.Fatalf("register %s: %v", tool.name, err)
		}
	}
	return reg
}

// toolNames projects an advertised set onto its names in order.
func toolNames(defs []provider.ToolDefinition) []string {
	names := make([]string, len(defs))
	for i, d := range defs {
		names[i] = d.Name
	}
	return names
}

// Build advertises every registry tool plus the product-authored bash and
// suggest_followup, sorted by name; the read-only classification does not filter anything
// in Build.
func TestAdvertisedTools_BuildAdvertisesAllPlusBashSorted(t *testing.T) {
	got := toolNames(advertisedTools(advRegistry(t), mode.Build))
	want := []string{"bash", "suggest_followup", "vcs_commit", "vcs_status"}
	if !slices.Equal(got, want) {
		t.Fatalf("Build advertised %v, want %v (all registry tools + bash + suggest_followup, name-sorted)", got, want)
	}
}

// Auto edits advertises the same full set as Build.
func TestAdvertisedTools_AutoEditsAdvertisesAll(t *testing.T) {
	got := toolNames(advertisedTools(advRegistry(t), mode.AutoEdits))
	want := []string{"bash", "suggest_followup", "vcs_commit", "vcs_status"}
	if !slices.Equal(got, want) {
		t.Fatalf("Auto edits advertised %v, want %v", got, want)
	}
}

// Plan advertises only read-only registry tools but still
// advertises bash and suggest_followup: bash's read/write intent is per-invocation and
// suggest_followup is never destructive, so neither is filtered at advertise time.
func TestAdvertisedTools_PlanFiltersToReadOnlyButKeepsBash(t *testing.T) {
	got := toolNames(advertisedTools(advRegistry(t), mode.Plan))
	want := []string{"bash", "suggest_followup", "vcs_status"} // vcs_commit (mutating) filtered out
	if !slices.Equal(got, want) {
		t.Fatalf("Plan advertised %v, want %v (read-only registry tools + bash + suggest_followup)", got, want)
	}
}

// bash and suggest_followup are advertised even when the registry is empty — they carry
// no registry entry, so their definitions are product-authored and always present.
func TestAdvertisedTools_BashWithoutRegistryEntry(t *testing.T) {
	got := toolNames(advertisedTools(tools.NewRegistry(), mode.Plan))
	if !slices.Equal(got, []string{"bash", "suggest_followup"}) {
		t.Fatalf("empty-registry advertised %v, want [bash suggest_followup]", got)
	}
}

// The product-authored bash definition's name matches the pinned dispatch name, so a
// model tool call learned from the advertisement routes to the shell path.
func TestBashToolDefinition_MatchesDispatchName(t *testing.T) {
	if provider.BashToolDefinition().Name != bashToolName {
		t.Fatalf("bash advertised name = %q, want the dispatch name %q", provider.BashToolDefinition().Name, bashToolName)
	}
}

// TestContextState_UsesActiveSelectionAndRecords pins the /context production adapter
// to the live run state: it reads the active provider/model from model.ActiveState and
// the session token records from the app's active store (live, not a startup copy), so
// BuildContextSnapshot sums the current totals and flags an anomalous turn. No provider
// or catalog exposes a context-window size yet, so ContextWindow stays 0 (unknown).
func TestContextState_UsesActiveSelectionAndRecords(t *testing.T) {
	app := tui.New(nil)
	cs := newContextState(app, selectedState())

	// Before any store is active: selection is still readable, records are empty, and
	// the window is unknown.
	if p, m := cs.Selection(); p != "openai" || m != "gpt-5.5" {
		t.Fatalf("Selection = %q/%q, want openai/gpt-5.5", p, m)
	}
	if recs := cs.Records(); recs != nil {
		t.Errorf("Records with no active store = %v, want nil", recs)
	}
	if w := cs.ContextWindow(); w != 0 {
		t.Errorf("ContextWindow = %d, want 0 (no window source landed)", w)
	}

	// Attach a live store with two completed turns, the second reporting missing usage;
	// /context reads it live through the active store.
	store := mkStore(t)
	if err := model.EmitModelResponse(store, "openai", "gpt-5.5", 100, 40, nil, false, nil, ""); err != nil {
		t.Fatalf("seed model_response: %v", err)
	}
	if err := model.EmitModelResponse(store, "openai", "gpt-5.5", 30, 10, nil, false, []string{"usage_missing"}, ""); err != nil {
		t.Fatalf("seed anomalous model_response: %v", err)
	}
	app.SetActiveStore(store)

	snap := tui.BuildContextSnapshot(cs)
	if snap.Provider != "openai" || snap.ModelID != "gpt-5.5" {
		t.Errorf("snapshot selection = %q/%q, want openai/gpt-5.5", snap.Provider, snap.ModelID)
	}
	if snap.InputTokens != 130 || snap.OutputTokens != 50 {
		t.Errorf("snapshot totals = %d input/%d output, want 130/50", snap.InputTokens, snap.OutputTokens)
	}
	if !snap.Incomplete {
		t.Errorf("snapshot Incomplete = false, want true (a turn reported usage_missing)")
	}
	if snap.Window != 0 {
		t.Errorf("snapshot Window = %d, want 0 (unknown)", snap.Window)
	}
}

// TestStartTUI_ContextDispatchOpensPanel pins the production /context wiring: StartTUI must
// bind "context" to tui.NewContextHandler(contextSt) in its registry rather than leave it on
// the default recordHandler. Driven through the assembled app's installed submit hook,
// /context opens a panel; ESC then dismisses that panel and leaves the user's draft intact.
// If StartTUI stops replacing "context" (falling back to recordHandler), no panel opens and
// ESC clears the draft instead — failing this test.
func TestStartTUI_ContextDispatchOpensPanel(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store, Model: selectedState()}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}

	if !ran.SubmitInput("/context") {
		t.Fatal("/context should be accepted through StartTUI's installed submit hook")
	}
	// A panel is open only when /context is wired to the real handler. Prove it through the
	// ESC seam: an open panel absorbs ESC (dismiss) and keeps the draft; recordHandler opens
	// nothing, so the same ESC clears the draft.
	ran.SeedInput("draft")
	ran.HandleEsc()
	if got := ran.InputText(); got != "draft" {
		t.Fatalf("after /context, ESC cleared the draft (got %q); /context fell back to recordHandler instead of NewContextHandler", got)
	}
}

// The per-turn system-prompt assembler reads the active model on every call, so
// a /model switch changes the special-instructions section on the next turn rather than
// being frozen at construction. A flagged Granite selection carries the latex-math
// block; switching to an unflagged model drops it on the next assembly.
func TestSystemPromptAssembler_ReadsActiveModelPerCall(t *testing.T) {
	result := &BootstrapResult{LaunchDir: "/launch", ProjectRoot: "/launch"}
	modeActive := mode.NewActiveState(mode.Build, mode.SourceDefault)
	active := model.NewActiveState(&model.Selection{Provider: "openrouter", ID: "ibm-granite/granite-4.1-8b", Effort: model.EffortDefault}, model.SourceProject)
	assemble := newSystemPromptAssembler(result, modeActive, active)

	special := agentinstr.SpecialInstructions("openrouter", "ibm-granite/granite-4.1-8b")
	if special == "" {
		t.Fatal("test precondition: Granite must be a flagged model")
	}
	if got := assemble(); !strings.Contains(got, special) {
		t.Fatalf("flagged Granite turn did not carry the special instructions:\n%s", got)
	}

	// A /model switch to an unflagged model drops the special section on the next turn.
	active.ApplyUserSelection(model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, false)
	if got := assemble(); strings.Contains(got, special) {
		t.Fatalf("after switching to an unflagged model the special instructions still appear:\n%s", got)
	}
}

func TestSystemPromptAssembler_CarriesDetectedRepoRoot(t *testing.T) {
	result := &BootstrapResult{
		LaunchDir:   "/repos/codemeld/p1/internal",
		ProjectRoot: "/repos/codemeld/p1",
		VCSTemplate: &ActiveVCS{Template: &vcs.Template{Name: "hg"}, RepoRoot: "/repos/codemeld"},
	}
	assemble := newSystemPromptAssembler(result, mode.NewActiveState(mode.Build, mode.SourceDefault), model.NewActiveState(nil, ""))

	got := assemble()
	if !strings.Contains(got, "- Repository root: /repos/codemeld\n- Version control: Mercurial") {
		t.Fatalf("assembled system message did not carry the detected repository root:\n%s", got)
	}
}

func TestSystemPromptAssembler_NoVCSOmitsRepoRoot(t *testing.T) {
	cases := []struct {
		name      string
		vcs       any
		wantNoVCS bool
	}{
		{name: "nil handoff", vcs: nil, wantNoVCS: true},
		{name: "mistyped handoff", vcs: &vcs.Template{Name: "hg"}, wantNoVCS: true},
		{name: "typed nil handoff", vcs: (*ActiveVCS)(nil), wantNoVCS: true},
		{name: "template-less handoff", vcs: &ActiveVCS{RepoRoot: "/repos/codemeld"}, wantNoVCS: true},
		{name: "empty root", vcs: &ActiveVCS{Template: &vcs.Template{Name: "hg"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := &BootstrapResult{LaunchDir: "/launch", ProjectRoot: "/launch", VCSTemplate: tc.vcs}
			assemble := newSystemPromptAssembler(result, mode.NewActiveState(mode.Build, mode.SourceDefault), model.NewActiveState(nil, ""))

			got := assemble()
			if strings.Contains(got, "Repository root") {
				t.Fatalf("assembly emitted a repository-root line:\n%s", got)
			}
			if tc.wantNoVCS && !strings.Contains(got, "- Version control: no version control detected") {
				t.Fatalf("assembly lost the explicit no-VCS text:\n%s", got)
			}
		})
	}
}

func TestNewModelPickerDeps_BindsFavoritesAndPreservesExistingFields(t *testing.T) {
	home := t.TempDir()
	cache, err := config.NewCache(map[string]any{}, t.TempDir(), []string{SettingsPath(home)})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	deps := newModelPickerDeps(context.Background(), tui.New(nil), cache, selectedState(), nil, home, "/launch")

	if deps.Catalog == nil || deps.Applier == nil || deps.Refresh == nil || deps.RefreshCatalog == nil {
		t.Fatalf("factory dropped an existing capability: Catalog=%v Applier=%v Refresh non-nil=%v RefreshCatalog non-nil=%v",
			deps.Catalog, deps.Applier, deps.Refresh != nil, deps.RefreshCatalog != nil)
	}
	if deps.Favorites == nil || deps.ToggleFavorite == nil {
		t.Fatalf("factory left favorite callbacks unbound: Favorites non-nil=%v ToggleFavorite non-nil=%v",
			deps.Favorites != nil, deps.ToggleFavorite != nil)
	}

	if got := deps.Favorites(); got != nil {
		t.Fatalf("Favorites() before any toggle = %+v, want nil", got)
	}
	added, err := deps.ToggleFavorite("openai-chatgpt", "gpt-5.5")
	if err != nil {
		t.Fatalf("ToggleFavorite error: %v", err)
	}
	want := []tui.ModelFavorite{{Provider: "openai-chatgpt", ModelID: "gpt-5.5"}}
	if !slices.Equal(added, want) {
		t.Fatalf("ToggleFavorite = %+v, want %+v", added, want)
	}
	if live := deps.Favorites(); !slices.Equal(live, want) {
		t.Fatalf("Favorites() after toggle = %+v, want %+v (cache-backed snapshot)", live, want)
	}
	assertFileContains(t, SettingsPath(home), "provider: openai-chatgpt")
	assertFileContains(t, SettingsPath(home), "id: gpt-5.5")
}

func diskFavorites(t *testing.T, path string) []config.Favorite {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Model struct {
			Favorites []struct {
				Provider string `yaml:"provider"`
				ID       string `yaml:"id"`
			} `yaml:"favorites"`
		} `yaml:"model"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	out := make([]config.Favorite, 0, len(doc.Model.Favorites))
	for _, f := range doc.Model.Favorites {
		out = append(out, config.Favorite{Provider: f.Provider, ID: f.ID})
	}
	return out
}

func TestStartTUI_ModelFavoriteTogglePersistsAndRefreshesLivePicker(t *testing.T) {
	home := t.TempDir()
	projectRoot := t.TempDir()
	globalSettings := SettingsPath(home)
	projectSettings := filepath.Join(projectRoot, ".codemeld", "settings.yaml")
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        "/launch",
		ProjectRoot:      projectRoot,
		Session:          mkStore(t),
		Model:            model.NewActiveState(&model.Selection{Provider: "openai-chatgpt", ID: "gpt-5.5", Effort: "medium"}, model.SourceResume),
		ConfigLayerPaths: []string{globalSettings, projectSettings},
	}

	screen := tcell.NewSimulationScreen("UTF-8")
	screen.SetSize(120, 60)
	appC := make(chan *tui.App, 1)
	startC := make(chan error, 1)
	defer swapRunApp(func(a *tui.App) error {
		a.SetScreenFactoryForTest(func() (tcell.Screen, error) { return screen, nil })
		appC <- a
		return a.Run()
	})()
	go func() { startC <- StartTUI(context.Background(), result, io.Discard) }()

	var app *tui.App
	select {
	case app = <-appC:
	case <-time.After(2 * time.Second):
		t.Fatal("StartTUI did not start the simulation event loop")
	}
	t.Cleanup(func() {
		app.Stop()
		select {
		case err := <-startC:
			if err != nil {
				t.Errorf("StartTUI: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("StartTUI did not stop")
		}
	})

	var opened bool
	app.RunOnEventLoopForTest(func() { opened = app.PressCtrlM() })
	if !opened {
		t.Fatal("CTRL-M did not open the model picker; StartTUI left App.modelPickerDeps unwired")
	}
	// tview resets the simulation screen size during Init.
	app.RunOnEventLoopForTest(func() { screen.SetSize(120, 60) })
	if _, err := os.Stat(globalSettings); !os.IsNotExist(err) {
		t.Fatalf("global settings stat err = %v, want not-exist before the toggle", err)
	}

	screen.InjectKey(tcell.KeyCtrlF, 0, tcell.ModNone)

	wantPair := []config.Favorite{{Provider: "openai-chatgpt", ID: "gpt-5.5"}}
	deadline := time.Now().Add(3 * time.Second)
	for !slices.Equal(diskFavorites(t, globalSettings), wantPair) {
		if time.Now().After(deadline) {
			t.Fatalf("global settings favorites = %+v, want exactly %+v after one CTRL-F", diskFavorites(t, globalSettings), wantPair)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := os.Stat(projectSettings); !os.IsNotExist(err) {
		t.Fatalf("project settings stat err = %v, want not-exist (favorite writes target ConfigLayerPaths[0] only)", err)
	}

	renderedScreen := func() string {
		var rendered string
		app.RunOnEventLoopForTest(func() {
			cells, width, height := screen.GetContents()
			var b strings.Builder
			for row := 0; row < height; row++ {
				for col := 0; col < width; col++ {
					b.WriteString(string(cells[row*width+col].Runes))
				}
				b.WriteByte('\n')
			}
			rendered = b.String()
		})
		return rendered
	}
	const favoriteAlias = "OpenAI ChatGPT · gpt-5.5"
	deadline = time.Now().Add(3 * time.Second)
	for {
		if got := renderedScreen(); strings.Contains(got, "Favorites") && strings.Contains(got, favoriteAlias) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("mounted picker never rendered the favorite alias %q\n--- rendered ---\n%s", favoriteAlias, renderedScreen())
		}
		time.Sleep(5 * time.Millisecond)
	}

	var stillOpen bool
	app.RunOnEventLoopForTest(func() { stillOpen = app.ModelPickerOpen() })
	if !stillOpen {
		t.Fatal("model picker closed across the CTRL-F toggle; the live refresh must keep it mounted")
	}
}

func TestNewInteractiveToolAdvertiser_AddsAskUserOnlyToTheLiveSet(t *testing.T) {
	base := newToolAdvertiser(advRegistry(t), mode.NewActiveState(mode.Build, mode.SourceDefault))

	headless := toolNames(base())
	if slices.Contains(headless, provider.AskUserToolName) {
		t.Fatalf("the shared base advertiser offers %q; a headless turn has no form to open", provider.AskUserToolName)
	}
	if want := []string{"bash", "suggest_followup", "vcs_commit", "vcs_status"}; !slices.Equal(headless, want) {
		t.Fatalf("base advertised %v, want %v unchanged by the live wrapper", headless, want)
	}

	live := newInteractiveToolAdvertiser(base)()
	want := []string{"ask_user", "bash", "suggest_followup", "vcs_commit", "vcs_status"}
	if !slices.Equal(toolNames(live), want) {
		t.Fatalf("live advertised %v, want %v (name-sorted with the question form added)", toolNames(live), want)
	}
	assertAskUserDefinition(t, live)
	if got := toolNames(base()); slices.Contains(got, provider.AskUserToolName) {
		t.Fatalf("wrapping mutated the base set: %v", got)
	}
}

// assertAskUserDefinition holds the wrapper to the whole advertised contract rather than to
// the name: registering the name with an empty description and no parameter schema would
// leave every name-based assertion green while a live turn advertised a tool the model has
// no way to call correctly.
func assertAskUserDefinition(t *testing.T, defs []provider.ToolDefinition) {
	t.Helper()
	want := provider.AskUserToolDefinition()
	at := slices.IndexFunc(defs, func(d provider.ToolDefinition) bool { return d.Name == provider.AskUserToolName })
	if at < 0 {
		t.Fatalf("advertised tools = %v, want %q among them", toolNames(defs), provider.AskUserToolName)
	}
	if got := defs[at]; got.Description != want.Description || !reflect.DeepEqual(got.Parameters, want.Parameters) {
		t.Fatalf("advertised %s definition =\n%+v\nwant\n%+v", provider.AskUserToolName, got, want)
	}
}

const (
	askUserQuestionsArgs = `{"questions":[` +
		`{"id":"storage","prompt":"Where should sessions be stored?","options":[{"label":"Local disk","description":"Kept on this machine"},{"label":"Object store"}]},` +
		`{"id":"name","prompt":"What should it be called?","context":"The name is the command users type.","options":[{"label":"run"},{"label":"go"}],"allow_custom":true}]}`
	askUserFinalAnswer = "stored on the object store"
)

type askUserTurn struct {
	app          *tui.App
	store        *sessions.Store
	advertised   []provider.ToolDefinition
	continuation []provider.Message
	settle       func()
}

func startAskUserTurn(t *testing.T) *askUserTurn {
	t.Helper()
	turn := &askUserTurn{}
	var ran *tui.App
	t.Cleanup(swapRunApp(func(a *tui.App) error { ran = a; return nil }))
	var turns sync.WaitGroup
	release := make(chan struct{})
	t.Cleanup(swapGoTurn(func(fn func()) {
		turns.Add(1)
		go func() {
			defer turns.Done()
			<-release
			fn()
		}()
	}))

	var round int32
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		switch atomic.AddInt32(&round, 1) {
		case 1:
			turn.advertised = req.Tools
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", provider.AskUserToolName, askUserQuestionsArgs)))}, nil
		case 2:
			turn.continuation = req.Messages
			return provider.Response{Stream: newStream(contentChunk(askUserFinalAnswer), finishChunk("stop"))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("title"), finishChunk("stop"))}, nil
	}}
	t.Cleanup(swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client }))

	turn.store = titledStore(t)
	home := t.TempDir()
	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")
	result := &BootstrapResult{
		Home:      home,
		LaunchDir: "/launch",
		Session:   turn.store,
		Model:     model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{"base_url": "https://api.openai.com/v1", "api_key": "sk-test"},
			},
		},
		ConfigLayerPaths: []string{SettingsPath(home)},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	if !ran.SubmitInput("where should sessions live?") {
		t.Fatal("wired submit rejected a plain prompt")
	}
	close(release)
	if !ran.AwaitQuestionFormForTest(5 * time.Second) {
		t.Fatal("the ask_user call did not mount the question form through the production dispatcher")
	}
	turn.app, turn.settle = ran, turns.Wait
	return turn
}

// durable reads the session file the production turn wrote, without flushing it first:
// a test-side flush would write the very records the assertion calls durable.
func (a *askUserTurn) durable(t *testing.T) *sessions.Store {
	t.Helper()
	return sessions.New(a.store.Path(), readSessionFile(t, a.store.Path()))
}

func (a *askUserTurn) assertContinuedWith(t *testing.T, result string) {
	t.Helper()
	var carried bool
	for _, m := range a.continuation {
		if m.Role == "tool" && m.Content == result && m.ToolCallID == "call_1" {
			carried = true
		}
	}
	if !carried {
		t.Fatalf("the next provider round did not carry %s under tool_call_id call_1: %+v", result, a.continuation)
	}
	asst := messagesByRole(a.durable(t), "assistant")
	if len(asst) == 0 || asst[len(asst)-1].Content.Text() != askUserFinalAnswer {
		t.Fatalf("final assistant message = %+v, want the turn to continue to its answer", asst)
	}
}

func TestStartTUI_AskUserToolCallMountsTheFormAndPersistsTheSubmittedAnswers(t *testing.T) {
	turn := startAskUserTurn(t)

	if !turn.app.AnswerQuestionForTest(0, 1) {
		t.Fatal("could not choose the second option of the first question")
	}
	if !turn.app.AnswerQuestionCustomForTest(1, "codemeld ask") {
		t.Fatal("could not enter a custom answer for the second question")
	}
	turn.app.SubmitQuestionFormForTest()
	turn.settle()

	assertAskUserDefinition(t, turn.advertised)
	if turn.app.QuestionFormOpen() {
		t.Error("the question form outlived its submission")
	}

	durable := turn.durable(t)
	toolMsgs := messagesByRole(durable, "tool")
	if len(toolMsgs) != 1 {
		t.Fatalf("durable tool messages = %d, want 1 (the question call is dispatched and persisted, not intercepted)", len(toolMsgs))
	}
	if toolMsgs[0].ToolCallID != "call_1" {
		t.Fatalf("tool result tool_call_id = %q, want call_1", toolMsgs[0].ToolCallID)
	}
	want := `{"answers":[` +
		`{"id":"storage","prompt":"Where should sessions be stored?","selected":["Object store"]},` +
		`{"id":"name","prompt":"What should it be called?","selected":[],"custom":"codemeld ask"}]}`
	if got := toolMsgs[0].Content.Text(); got != want {
		t.Fatalf("persisted tool result =\n%s\nwant\n%s", got, want)
	}
	turn.assertContinuedWith(t, want)
	var recordedCall bool
	for _, m := range messagesByRole(durable, "assistant") {
		for _, tc := range m.ToolCalls {
			if strings.Contains(string(tc.Raw), provider.AskUserToolName) {
				recordedCall = true
			}
		}
	}
	if !recordedCall {
		t.Fatal("the assistant tool_calls record does not carry the ask_user call; it was intercepted rather than dispatched")
	}
}

// TestStartTUI_AskUserFormClosesWhenTheTurnIsCancelled is the assembled half of the
// context-propagation contract: cancelling the turn while the form is mounted has to reach
// the form the production dispatcher opened, not just the dispatcher that opened it.
func TestStartTUI_AskUserFormClosesWhenTheTurnIsCancelled(t *testing.T) {
	turn := startAskUserTurn(t)

	turn.app.HandleCtrlC()
	turn.settle()

	if turn.app.QuestionFormOpen() {
		t.Error("the mounted question form outlived the cancelled turn")
	}
	if msgs := messagesByRole(turn.durable(t), "tool"); len(msgs) != 0 {
		t.Errorf("durable tool messages = %+v, want none: an interrupted turn answers nothing", msgs)
	}
}

func TestStartTUI_AskUserDismissalContinuesTheSameTurn(t *testing.T) {
	turn := startAskUserTurn(t)

	turn.app.HandleEsc()
	turn.settle()

	if turn.app.QuestionFormOpen() {
		t.Error("the dismissed question form is still open")
	}
	want := `{"answers":[],"cancelled":true}`
	toolMsgs := messagesByRole(turn.durable(t), "tool")
	if len(toolMsgs) != 1 || toolMsgs[0].Content.Text() != want {
		t.Fatalf("durable tool messages = %+v, want one %s result", toolMsgs, want)
	}
	if toolMsgs[0].ToolCallID != "call_1" {
		t.Fatalf("cancelled tool result tool_call_id = %q, want call_1", toolMsgs[0].ToolCallID)
	}
	turn.assertContinuedWith(t, want)
}

const (
	askUserFirstContext  = "Sessions are replayed on /resume, so where they live decides what survives a restart."
	askUserSecondContext = "An object store is a remote blob service; local disk keeps everything on this machine."
	askUserExplanation   = "It is a remote blob service."
	askUserNameContext   = "The name is the command users type."
	askUserClarification = "what is an object store?"
	askUserContextArgs   = `{"questions":[` +
		`{"id":"storage","prompt":"Where should sessions be stored?","context":"` + askUserFirstContext + `","options":[{"label":"Local disk"},{"label":"Object store"}]}]}`
	askUserSecondArgs = `{"questions":[` +
		`{"id":"storage","prompt":"Where should sessions be stored?","context":"` + askUserSecondContext + `",` +
		`"options":[{"label":"Local disk","description":"Kept on this machine"},{"label":"Object store","description":"A remote blob service"}]},` +
		`{"id":"name","prompt":"What should it be called?","context":"` + askUserNameContext + `","options":[{"label":"run"},{"label":"go"}],"allow_custom":true}]}`
)

func TestStartTUI_AskUserContextClarificationAndRecordSurviveTheWholeTurn(t *testing.T) {
	var ran *tui.App
	t.Cleanup(swapRunApp(func(a *tui.App) error { ran = a; return nil }))
	var turns sync.WaitGroup
	release := make(chan struct{})
	t.Cleanup(swapGoTurn(func(fn func()) {
		turns.Add(1)
		go func() {
			defer turns.Done()
			<-release
			fn()
		}()
	}))

	var round int32
	var clarificationRound []provider.Message
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		switch atomic.AddInt32(&round, 1) {
		case 1:
			return provider.Response{Stream: newStream(
				contentChunk("I need to know where sessions go."),
				toolCallsChunk(toolFrag(0, "call_1", provider.AskUserToolName, askUserContextArgs)),
			)}, nil
		case 2:
			clarificationRound = req.Messages
			return provider.Response{Stream: newStream(
				contentChunk(askUserExplanation),
				toolCallsChunk(toolFrag(0, "call_2", provider.AskUserToolName, askUserSecondArgs)),
			)}, nil
		case 3:
			return provider.Response{Stream: newStream(contentChunk(askUserFinalAnswer), finishChunk("stop"))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("title"), finishChunk("stop"))}, nil
	}}
	t.Cleanup(swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client }))

	store := titledStore(t)
	home := t.TempDir()
	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")
	result := &BootstrapResult{
		Home:      home,
		LaunchDir: "/launch",
		Session:   store,
		Model:     model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{"base_url": "https://api.openai.com/v1", "api_key": "sk-test"},
			},
		},
		ConfigLayerPaths: []string{SettingsPath(home)},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if !ran.SubmitInput("where should sessions live?") {
		t.Fatal("wired submit rejected a plain prompt")
	}
	close(release)

	if !ran.AwaitQuestionFormForTest(5 * time.Second) {
		t.Fatal("the ask_user call did not mount the question form through the production dispatcher")
	}
	if got := ran.QuestionContextForTest(); got != askUserFirstContext {
		t.Fatalf("first form context = %q, want %q shown above the question", got, askUserFirstContext)
	}
	if !ran.AskClarificationForTest(askUserClarification) {
		t.Fatal("could not reach the clarification action on the mounted form")
	}
	ran.SubmitQuestionFormForTest()

	if !ran.AwaitQuestionFormForTest(5 * time.Second) {
		t.Fatal("the clarification did not continue the turn to a second ask_user call")
	}
	if got := ran.QuestionContextForTest(); got != askUserSecondContext {
		t.Fatalf("second form context = %q, want the model's explanation restated as %q", got, askUserSecondContext)
	}
	if !ran.AnswerQuestionForTest(0, 1) {
		t.Fatal("could not choose the second option of the first question")
	}
	if !ran.AnswerQuestionCustomForTest(1, "codemeld ask") {
		t.Fatal("could not enter a custom answer for the second question")
	}
	if got := ran.QuestionContextForTest(); got != askUserNameContext {
		t.Fatalf("second question's context = %q, want only its own %q", got, askUserNameContext)
	}
	ran.SubmitQuestionFormForTest()
	turns.Wait()

	durable := sessions.New(store.Path(), readSessionFile(t, store.Path()))
	toolMsgs := messagesByRole(durable, "tool")
	wantClarification := `{"clarification":"` + askUserClarification + `"}`
	wantAnswers := `{"answers":[` +
		`{"id":"storage","prompt":"Where should sessions be stored?","selected":["Object store"]},` +
		`{"id":"name","prompt":"What should it be called?","selected":[],"custom":"codemeld ask"}]}`
	if len(toolMsgs) != 2 {
		t.Fatalf("durable tool messages = %d, want the clarification and the answer", len(toolMsgs))
	}
	if toolMsgs[0].ToolCallID != "call_1" || toolMsgs[0].Content.Text() != wantClarification {
		t.Fatalf("first tool result = %+v, want %s under call_1", toolMsgs[0], wantClarification)
	}
	if toolMsgs[1].ToolCallID != "call_2" || toolMsgs[1].Content.Text() != wantAnswers {
		t.Fatalf("second tool result = %+v, want %s under call_2", toolMsgs[1], wantAnswers)
	}
	var carried bool
	for _, m := range clarificationRound {
		if m.Role == "tool" && m.ToolCallID == "call_1" && m.Content == wantClarification {
			carried = true
		}
	}
	if !carried {
		t.Fatalf("the round after the clarification did not carry it under call_1: %+v", clarificationRound)
	}
	if asst := messagesByRole(durable, "assistant"); len(asst) == 0 || asst[len(asst)-1].Content.Text() != askUserFinalAnswer {
		t.Fatalf("final assistant message = %+v, want the turn to continue to its answer", asst)
	}

	wantLive := "I need to know where sessions go." + responseCopyLine + "\n\n" +
		"Asked for clarification (ask_user):\n  " + askUserClarification + "\n\n" +
		askUserExplanation + responseCopyLine + "\n\n" +
		"Answered (ask_user):\n" +
		"  Where should sessions be stored? — Object store\n" +
		"  What should it be called? — codemeld ask"
	live := ran.TranscriptText()
	if !strings.Contains(live, wantLive) {
		t.Fatalf("live transcript =\n%q\nwant it to carry\n%q", live, wantLive)
	}
	withoutHeadings := strings.ReplaceAll(live, "("+provider.AskUserToolName+"):", "")
	if strings.Contains(withoutHeadings, provider.AskUserToolName) {
		t.Errorf("live transcript = %q, still prints a generic ask_user activity line beside the named records", live)
	}

	replayed := tui.New(nil)
	replayed.ReplaySessionRecords(durable.Records())
	got := replayed.TranscriptText()
	if !strings.Contains(got, wantLive) {
		t.Fatalf("replayed transcript =\n%q\nwant it to carry the same records as live\n%q", got, wantLive)
	}
	if strings.Contains(strings.ReplaceAll(got, "("+provider.AskUserToolName+"):", ""), provider.AskUserToolName) {
		t.Errorf("replayed transcript = %q, prints a generic ask_user activity line beside the named records", got)
	}
}

// The TUI seals each assistant reply with this control; it is restated here because the
// package under test cannot reach the tui package's own constant.
const responseCopyLine = "\n  [Copy response]"

const guardRecoveryAnswer = "I cannot edit that file; run /settings to manage grants."

// The edit names a settings file by absolute path while the launch directory is a different tree,
// so only a policy built from the configured project root and home can protect either target.
func TestStartTUI_ProtectedSettingsMutationIsRefusedAndTheTurnReIssues(t *testing.T) {
	cases := []struct {
		name   string
		target func(project, home string) string
	}{
		{name: "project settings", target: func(project, _ string) string { return projectSettingsPath(project) }},
		{name: "global settings", target: func(_, home string) string { return SettingsPath(home) }},
		{name: "trust record", target: func(_, home string) string { return trust.StorePath(home) }},
		{name: "trust record lock sidecar", target: func(_, home string) string { return trust.StorePath(home) + ".lock" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ran *tui.App
			defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()
			var turns sync.WaitGroup
			defer swapGoTurn(waitableGoTurn(&turns))()

			project, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatalf("EvalSymlinks: %v", err)
			}
			launch, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatalf("EvalSymlinks: %v", err)
			}
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatalf("EvalSymlinks: %v", err)
			}
			projectSettings := projectSettingsPath(project)
			globalSettings := SettingsPath(home)
			trustRecord := trust.StorePath(home)
			trustLock := trustRecord + ".lock"
			seedProtectedSettings(t, projectSettings)
			seedProtectedSettings(t, globalSettings)
			seedProtectedSettings(t, trustRecord)
			seedProtectedSettings(t, trustLock)
			target := tc.target(project, home)

			client := toolThenContentClient(nil, filetools.EditToolName, removeGrantsArgs(t, target), guardRecoveryAnswer)
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			store := titledStore(t)
			seedOpenAIDiscovered(t, globalSettings, "gpt-5.5")
			result := &BootstrapResult{
				Home:        home,
				LaunchDir:   launch,
				ProjectRoot: project,
				Session:     store,
				Model:       model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
				Config: map[string]any{
					"provider": map[string]any{
						"openai": map[string]any{
							"base_url": "https://api.openai.com/v1",
							"api_key":  "sk-test",
						},
					},
				},
				ConfigLayerPaths: []string{globalSettings},
				ToolRegistry:     &toolRegistryFactory{active: nil},
			}
			if err := StartTUI(context.Background(), result, io.Discard); err != nil {
				t.Fatalf("StartTUI error: %v", err)
			}
			if ran == nil {
				t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
			}
			if !ran.SubmitInput("clear my grants") {
				t.Fatal("wired submit rejected a plain prompt")
			}
			turns.Wait()

			for _, path := range []string{projectSettings, globalSettings, trustRecord, trustLock} {
				if got := mustReadFile(t, path); got != sevenGrantSettings {
					t.Fatalf("protected file %q = %q, want its bytes untouched by the interactive turn", path, got)
				}
			}
			if client.callCount() != 2 {
				t.Fatalf("provider calls = %d, want 2 (a guard denial re-issues rather than halting the turn)", client.callCount())
			}

			durable := sessions.New(store.Path(), readSessionFile(t, store.Path()))
			matched := decodePermissionMatched(t, durable)
			want := events.PermissionMatched{
				SubjectKind:   "tool",
				Subject:       filetools.EditToolName,
				PathScope:     filepath.Dir(target),
				Outcome:       "deny",
				OutcomeSource: "protected_state",
			}
			if len(matched) != 1 || matched[0] != want {
				t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
			}
			toolMsgs := messagesByRole(durable, "tool")
			if len(toolMsgs) != 1 || toolMsgs[0].Content.Text() != permissions.BuildGuardDenyEnvelope() {
				t.Fatalf("durable tool messages = %+v, want the one guard deny envelope", toolMsgs)
			}
			asst := messagesByRole(durable, "assistant")
			if len(asst) == 0 || asst[len(asst)-1].Content.Text() != guardRecoveryAnswer {
				t.Fatalf("final assistant message = %+v, want the model's recovery reply %q", asst, guardRecoveryAnswer)
			}
		})
	}
}

func TestStartTUI_BlockedPathIsRefusedAndTheTurnReIssues(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args func(file string) map[string]any
		want func(t *testing.T, file, project, source string) events.PermissionMatched
	}{
		{name: "read", tool: filetools.ReadToolName, args: func(file string) map[string]any {
			return map[string]any{"path": file}
		}},
		{name: "edit", tool: filetools.EditToolName, args: func(file string) map[string]any {
			return map[string]any{"path": file, "old_text": "TOKEN", "new_text": "SPENT"}
		}},
		{name: "bash", tool: bashToolName, args: func(file string) map[string]any {
			return map[string]any{"command": "cat " + file}
		}, want: func(t *testing.T, file, project, source string) events.PermissionMatched {
			requestSubject, err := permissions.DirectRequestSubject([]string{"cat", file}, nil, false)
			if err != nil {
				t.Fatalf("DirectRequestSubject: %v", err)
			}
			return events.PermissionMatched{SubjectKind: "direct", Subject: "cat " + file, PathScope: project, Outcome: "deny", OutcomeSource: "blocked_path", DirectRequestSubject: requestSubject, BlockedEntry: filepath.Dir(file), BlockedEntrySource: source}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ran *tui.App
			defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()
			var turns sync.WaitGroup
			defer swapGoTurn(waitableGoTurn(&turns))()

			project, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatalf("EvalSymlinks: %v", err)
			}
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatalf("EvalSymlinks: %v", err)
			}
			file := seedBlockedSecret(t, project)
			globalSettings := SettingsPath(home)
			layers := blockedGlobalLayers(t, home, project, filepath.Dir(file))
			seedOpenAIDiscovered(t, globalSettings, "gpt-5.5")

			client, sent := requestRecordingClient(tc.tool, toolArgs(t, tc.args(file)))
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			store := titledStore(t)
			result := &BootstrapResult{
				Home:             home,
				LaunchDir:        project,
				ProjectRoot:      project,
				Session:          store,
				Model:            model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
				Config:           headlessProviderConfig(),
				ConfigLayerPaths: []string{globalSettings},
				SettingsLayers:   layers,
				ToolRegistry:     &toolRegistryFactory{active: nil},
			}
			if err := StartTUI(context.Background(), result, io.Discard); err != nil {
				t.Fatalf("StartTUI error: %v", err)
			}
			if ran == nil {
				t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
			}
			if !ran.SubmitInput("show me the token") {
				t.Fatal("wired submit rejected a plain prompt")
			}
			turns.Wait()

			if got := mustReadFile(t, file); got != blockedSecret {
				t.Fatalf("blocked file = %q, want its bytes untouched", got)
			}
			if client.callCount() != 2 {
				t.Fatalf("provider calls = %d, want 2 (a blocked-path denial re-issues rather than halting the turn)", client.callCount())
			}
			if strings.Contains(sent(), blockedSecret) {
				t.Fatal("a model request carried the blocked file's content")
			}
			if strings.Contains(sent(), globalSettings) {
				t.Fatal("a model request carried the settings file path")
			}
			if n := strings.Count(ran.TranscriptText(), blockedSourceLine(filepath.Dir(file), globalSettings)); n != 1 {
				t.Fatalf("transcript = %q carries the source line %d times, want once", ran.TranscriptText(), n)
			}
			durable := sessions.New(store.Path(), readSessionFile(t, store.Path()))
			want := blockedPathDenial(tc.tool, filepath.Dir(file), globalSettings)
			if tc.want != nil {
				want = tc.want(t, file, project, globalSettings)
			}
			if matched := decodePermissionMatched(t, durable); len(matched) != 1 || matched[0] != want {
				t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
			}
		})
	}
}

func TestStartTUI_BlockedPathAddedMidRunIsRefusedAtTheNextRead(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	project := declaredScopeDir(t)
	home := declaredScopeDir(t)
	file := seedBlockedSecret(t, project)
	globalSettings := SettingsPath(home)
	layers := blockedGlobalLayers(t, home, project)
	seedOpenAIDiscovered(t, globalSettings, "gpt-5.5")

	client := midRunBlockedClient(t, globalSettings, file)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := titledStore(t)
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        project,
		ProjectRoot:      project,
		Session:          store,
		Model:            model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config:           headlessProviderConfig(),
		ConfigLayerPaths: []string{globalSettings},
		SettingsLayers:   layers,
		ToolRegistry:     &toolRegistryFactory{active: nil},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	if !ran.SubmitInput("show me the token") {
		t.Fatal("wired submit rejected a plain prompt")
	}
	turns.Wait()

	requireMidRunBlockedReads(t, client, reloadStore(t, store), file, globalSettings)
}

func swapBlockedNoticeDelivery(t *testing.T) <-chan string {
	t.Helper()
	delivered := make(chan string, 16)
	orig := deliverBlockedNotice
	t.Cleanup(func() { deliverBlockedNotice = orig })
	deliverBlockedNotice = func(app *tui.App, line string) {
		app.NoticeFromBackground(line)
		delivered <- line
	}
	return delivered
}

func requireDelivered(t *testing.T, delivered <-chan string, want string) {
	t.Helper()
	select {
	case got := <-delivered:
		if got != want {
			t.Fatalf("delivered notice = %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("notice %q was never delivered", want)
	}
}

func TestQueueBlockedNotices_ReturnsAtOnceFromTheEventLoop(t *testing.T) {
	delivered := swapBlockedNoticeDelivery(t)
	screen := tcell.NewSimulationScreen("UTF-8")
	app := tui.New(nil)
	app.SetScreenFactoryForTest(func() (tcell.Screen, error) { return screen, nil })
	runC := make(chan error, 1)
	go func() { runC <- app.Run() }()
	t.Cleanup(func() {
		app.Stop()
		select {
		case <-runC:
		case <-time.After(2 * time.Second):
			t.Error("the app did not stop")
		}
	})

	var problems map[string]string
	blocked := permissions.NewLiveBlockedPaths(t.TempDir(), "", nil, func() permissions.BlockedReload {
		return permissions.BlockedReload{Problems: problems}
	})
	t.Cleanup(queueBlockedNotices(app, blocked, nil))

	returned := make(chan struct{})
	go func() {
		app.RunOnEventLoopForTest(func() {
			problems = map[string]string{"/g/settings.yaml": "is not valid YAML"}
			blocked.Entries()
		})
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("a notice sent from inside an event-loop callback blocked the loop")
	}
	line := problemNotice("/g/settings.yaml", "is not valid YAML")
	requireDelivered(t, delivered, line)
	app.RunOnEventLoopForTest(func() {})
	if got := app.NoticeText(); got != line {
		t.Fatalf("notice line = %q, want %q", got, line)
	}
}

func TestQueueBlockedNotices_StopEndsTheDrainAfterTheAppStops(t *testing.T) {
	started := make(chan string, 1)
	release := make(chan struct{})
	returned := make(chan struct{})
	orig := deliverBlockedNotice
	t.Cleanup(func() { deliverBlockedNotice = orig })
	deliverBlockedNotice = func(app *tui.App, line string) {
		started <- line
		<-release
		app.NoticeFromBackground(line)
		close(returned)
	}
	screen := tcell.NewSimulationScreen("UTF-8")
	app := tui.New(nil)
	app.SetScreenFactoryForTest(func() (tcell.Screen, error) { return screen, nil })
	runC := make(chan error, 1)
	go func() { runC <- app.Run() }()
	app.RunOnEventLoopForTest(func() {})

	var problems map[string]string
	blocked := permissions.NewLiveBlockedPaths(t.TempDir(), "", nil, func() permissions.BlockedReload {
		return permissions.BlockedReload{Problems: problems}
	})
	stop := queueBlockedNotices(app, blocked, nil)
	problems = map[string]string{"/g/settings.yaml": "is not valid YAML"}
	blocked.Entries()
	line := problemNotice("/g/settings.yaml", "is not valid YAML")
	select {
	case got := <-started:
		if got != line {
			t.Fatalf("delivery began with %q, want %q", got, line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the delivery never began")
	}

	app.BeginShutdown()
	app.Stop()
	select {
	case <-runC:
	case <-time.After(5 * time.Second):
		t.Fatal("the app did not stop")
	}

	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the drain goroutine did not finish after the app stopped")
	}

	close(release)
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("a delivery begun before the stop stayed blocked behind the stopped event loop")
	}
	if got := app.NoticeText(); got != "" {
		t.Fatalf("notice line after the stop = %q, want none", got)
	}
}

func TestQueueBlockedNotices_DeliversThroughTheHookReadWhenTheQueueStarts(t *testing.T) {
	entered := make(chan string, 1)
	release := make(chan struct{})
	finished := make(chan struct{})
	replaced := make(chan string, 1)
	orig := deliverBlockedNotice
	deliverBlockedNotice = func(_ *tui.App, line string) {
		defer close(finished)
		entered <- line
		<-release
	}
	var problems map[string]string
	blocked := permissions.NewLiveBlockedPaths(t.TempDir(), "", nil, func() permissions.BlockedReload {
		return permissions.BlockedReload{Problems: problems}
	})
	stop := queueBlockedNotices(tui.New(nil), blocked, nil)
	hookEntered := false
	var releaseOnce sync.Once
	releaseHook := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(func() {
		stop()
		releaseHook()
		if hookEntered {
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Error("the released hook never finished")
			}
		}
		deliverBlockedNotice = orig
	})
	deliverBlockedNotice = func(_ *tui.App, line string) { replaced <- line }

	problems = map[string]string{"/g/settings.yaml": "is not valid YAML"}
	blocked.Entries()
	line := problemNotice("/g/settings.yaml", "is not valid YAML")
	select {
	case got := <-entered:
		hookEntered = true
		if got != line {
			t.Fatalf("captured hook received %q, want %q", got, line)
		}
	case got := <-replaced:
		t.Fatalf("the hook swapped in after the queue started received %q", got)
	case <-time.After(5 * time.Second):
		t.Fatal("the notice was never delivered")
	}

	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop waited for a delivery blocked inside the hook")
	}

	releaseHook()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the released hook never finished")
	}
	select {
	case got := <-replaced:
		t.Fatalf("the hook swapped in after the queue started received %q", got)
	default:
	}
}

func TestQueueBlockedNotices_DeliveryThatSeesTheStopSkipsTheHook(t *testing.T) {
	called := make(chan string, 1)
	spawned := make(chan struct{}, 1)
	release := make(chan struct{})
	ran := make(chan struct{})
	origDeliver, origSpawn := deliverBlockedNotice, spawnBlockedDelivery
	deliverBlockedNotice = func(_ *tui.App, line string) { called <- line }
	spawnBlockedDelivery = func(f func()) {
		spawned <- struct{}{}
		go func() {
			defer close(ran)
			<-release
			f()
		}()
	}
	var problems map[string]string
	blocked := permissions.NewLiveBlockedPaths(t.TempDir(), "", nil, func() permissions.BlockedReload {
		return permissions.BlockedReload{Problems: problems}
	})
	stop := queueBlockedNotices(tui.New(nil), blocked, nil)
	wasSpawned := false
	var releaseOnce sync.Once
	releaseDelivery := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(func() {
		stop()
		releaseDelivery()
		if wasSpawned {
			select {
			case <-ran:
			case <-time.After(5 * time.Second):
				t.Error("the released delivery never finished")
			}
		}
		deliverBlockedNotice, spawnBlockedDelivery = origDeliver, origSpawn
	})

	problems = map[string]string{"/g/settings.yaml": "is not valid YAML"}
	blocked.Entries()
	select {
	case <-spawned:
		wasSpawned = true
	case <-time.After(5 * time.Second):
		t.Fatal("the delivery was never spawned")
	}

	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop waited for a delivery that had not started")
	}

	releaseDelivery()
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("the released delivery never finished")
	}
	select {
	case got := <-called:
		t.Fatalf("a delivery released after stop called the hook with %q", got)
	default:
	}
}

func TestStartTUI_BrokenGlobalSettingsMakeOutsideShellReadsAsk(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()
	delivered := swapBlockedNoticeDelivery(t)

	project := declaredScopeDir(t)
	home := declaredScopeDir(t)
	file := seedBlockedSecret(t, declaredScopeDir(t))
	globalSettings := SettingsPath(home)
	layers := blockedGlobalLayers(t, home, project, filepath.Dir(file))
	seedOpenAIDiscovered(t, globalSettings, "gpt-5.5")
	_, first, second := headlessExternalReads(t)
	bash := func(command string) declaredToolCall {
		return declaredToolCall{name: bashToolName, args: toolArgs(t, map[string]any{"command": command})}
	}
	client := settingsEditingClient(t,
		settingsRound{edit: settingsEdit(globalSettings, "blocked_paths: [\n"), call: bash("cat " + first)},
		settingsRound{call: bash("cat " + file)},
		settingsRound{edit: settingsEdit(globalSettings, blockedYAML(filepath.Dir(file))), call: bash("cat " + second)},
	)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := titledStore(t)
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        project,
		ProjectRoot:      project,
		Session:          store,
		Model:            model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config:           headlessProviderConfig(),
		ConfigLayerPaths: []string{globalSettings},
		SettingsLayers:   layers,
		ToolRegistry:     &toolRegistryFactory{active: nil},
	}

	screen := tcell.NewSimulationScreen("UTF-8")
	screen.SetSize(120, 60)
	appC := make(chan *tui.App, 1)
	startC := make(chan error, 1)
	defer swapRunApp(func(a *tui.App) error {
		a.SetScreenFactoryForTest(func() (tcell.Screen, error) { return screen, nil })
		appC <- a
		return a.Run()
	})()
	go func() { startC <- StartTUI(context.Background(), result, io.Discard) }()

	var app *tui.App
	select {
	case app = <-appC:
	case <-time.After(2 * time.Second):
		t.Fatal("StartTUI did not start the simulation event loop")
	}
	t.Cleanup(func() {
		app.Stop()
		select {
		case err := <-startC:
			if err != nil {
				t.Errorf("StartTUI: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("StartTUI did not stop")
		}
	})
	app.RunOnEventLoopForTest(func() { screen.SetSize(120, 60) })

	var submitted bool
	app.RunOnEventLoopForTest(func() { submitted = app.SubmitInput("read the files") })
	if !submitted {
		t.Fatal("wired submit rejected a plain prompt")
	}

	requireDelivered(t, delivered, problemNotice(globalSettings, "is not valid YAML"))
	rendered := func() string {
		var text string
		app.RunOnEventLoopForTest(func() {
			cells, width, height := screen.GetContents()
			var b strings.Builder
			for row := 0; row < height; row++ {
				for col := 0; col < width; col++ {
					b.WriteString(string(cells[row*width+col].Runes))
				}
				b.WriteByte('\n')
			}
			text = b.String()
		})
		return text
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(rendered(), "allow this [o]nce") {
		if time.Now().After(deadline) {
			t.Fatalf("the permission prompt never opened\n--- rendered ---\n%s", rendered())
		}
		time.Sleep(5 * time.Millisecond)
	}

	screen.InjectKey(tcell.KeyRune, 'o', tcell.ModNone)
	done := make(chan struct{})
	go func() { turns.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("the turn did not finish after the allow-once answer\n--- rendered ---\n%s", rendered())
	}
	requireDelivered(t, delivered, fixedNotice(globalSettings))

	durable := sessions.New(store.Path(), readSessionFile(t, store.Path()))
	if shown := decodeStoreEvents[events.PermissionPromptShown](t, durable, events.KindPermissionPromptShown); len(shown) != 1 {
		t.Fatalf("permission_prompt_shown events = %+v, want only the outside read made while the file was broken", shown)
	}
	results := messagesByRole(durable, "tool")
	if len(results) != 3 || !strings.Contains(results[0].Content.Text(), "OUTSIDE A") ||
		strings.Contains(results[1].Content.Text(), blockedSecret) || !strings.Contains(results[2].Content.Text(), "OUTSIDE B") {
		t.Fatalf("tool messages = %+v, want both outside reads answered and the blocked read refused", results)
	}
	var refused []events.PermissionMatched
	for _, m := range decodePermissionMatched(t, durable) {
		if m.OutcomeSource == "blocked_path" {
			refused = append(refused, m)
		}
	}
	if len(refused) != 1 || refused[0].Subject != "cat "+file {
		t.Fatalf("blocked_path records = %#v, want one for %q", refused, "cat "+file)
	}
}

func TestStartTUI_ShellCommandAboveABlockedPathPromptsOnceAndRunsAfterAllowOnce(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	file := seedBlockedSecret(t, project)
	globalSettings := SettingsPath(home)
	layers := blockedGlobalLayers(t, home, project, filepath.Dir(file))
	seedOpenAIDiscovered(t, globalSettings, "gpt-5.5")
	const marker = "home-listing-marker"
	if err := os.WriteFile(filepath.Join(home, marker), nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	client, sent := requestRecordingClient(bashToolName, toolArgs(t, map[string]any{"command": "ls " + home}))
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := titledStore(t)
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        project,
		ProjectRoot:      project,
		Session:          store,
		Model:            model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config:           headlessProviderConfig(),
		ConfigLayerPaths: []string{globalSettings},
		SettingsLayers:   layers,
		ToolRegistry:     &toolRegistryFactory{active: nil},
	}

	screen := tcell.NewSimulationScreen("UTF-8")
	screen.SetSize(120, 60)
	appC := make(chan *tui.App, 1)
	startC := make(chan error, 1)
	defer swapRunApp(func(a *tui.App) error {
		a.SetScreenFactoryForTest(func() (tcell.Screen, error) { return screen, nil })
		appC <- a
		return a.Run()
	})()
	go func() { startC <- StartTUI(context.Background(), result, io.Discard) }()

	var app *tui.App
	select {
	case app = <-appC:
	case <-time.After(2 * time.Second):
		t.Fatal("StartTUI did not start the simulation event loop")
	}
	t.Cleanup(func() {
		app.Stop()
		select {
		case err := <-startC:
			if err != nil {
				t.Errorf("StartTUI: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("StartTUI did not stop")
		}
	})
	app.RunOnEventLoopForTest(func() { screen.SetSize(120, 60) })

	var submitted bool
	app.RunOnEventLoopForTest(func() { submitted = app.SubmitInput("list my home folder") })
	if !submitted {
		t.Fatal("wired submit rejected a plain prompt")
	}

	rendered := func() string {
		var text string
		app.RunOnEventLoopForTest(func() {
			cells, width, height := screen.GetContents()
			var b strings.Builder
			for row := 0; row < height; row++ {
				for col := 0; col < width; col++ {
					b.WriteString(string(cells[row*width+col].Runes))
				}
				b.WriteByte('\n')
			}
			text = b.String()
		})
		return text
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(rendered(), "allow this [o]nce") {
		if time.Now().After(deadline) {
			t.Fatalf("the permission prompt never opened\n--- rendered ---\n%s", rendered())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if strings.Contains(sent(), marker) {
		t.Fatal("the home listing reached the model before the prompt was answered")
	}

	screen.InjectKey(tcell.KeyRune, 'o', tcell.ModNone)
	done := make(chan struct{})
	go func() { turns.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the turn did not finish after the allow-once answer")
	}

	if !strings.Contains(sent(), marker) {
		t.Fatal("the approved ls did not run: its home listing never reached the model")
	}
	durable := sessions.New(store.Path(), readSessionFile(t, store.Path()))
	if shown := decodeStoreEvents[events.PermissionPromptShown](t, durable, events.KindPermissionPromptShown); len(shown) != 1 {
		t.Fatalf("permission_prompt_shown events = %+v, want exactly one", shown)
	}
	for _, matched := range decodePermissionMatched(t, durable) {
		if matched.OutcomeSource == "mode_auto" {
			t.Fatalf("permission_matched = %+v, want no mode_auto allow for the asking command", matched)
		}
	}
}

func TestStartTUI_InvalidBlockedPathsEntryStopsTheLaunch(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	project := t.TempDir()
	home := t.TempDir()
	globalSettings := SettingsPath(home)
	entry := "vault/x"
	layers := blockedGlobalLayers(t, home, project, "~/vault")
	layers[0].Raw["blocked_paths"] = []any{entry}
	seedOpenAIDiscovered(t, globalSettings, "gpt-5.5")

	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        project,
		ProjectRoot:      project,
		Session:          titledStore(t),
		Model:            model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config:           headlessProviderConfig(),
		ConfigLayerPaths: []string{globalSettings},
		SettingsLayers:   layers,
		ToolRegistry:     &toolRegistryFactory{active: nil},
	}
	err := StartTUI(context.Background(), result, io.Discard)
	if err == nil || ran != nil {
		t.Fatalf("StartTUI error = %v, event loop ran = %v; want a failed launch that never runs the app", err, ran != nil)
	}
	for _, want := range []string{"bootstrap: StartTUI build blocked paths:", globalSettings, fmt.Sprintf("%q", entry)} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("StartTUI error = %q, want it to contain %q", err, want)
		}
	}
}

func TestStartTUI_BigBlockedPathsEntryWarnsAfterTheBanner(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry string
		warns bool
	}{
		{"system folder", "/etc", true},
		{"ssh folder", "~/.ssh", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ran *tui.App
			defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

			home := t.TempDir()
			result := &BootstrapResult{
				Home:           home,
				LaunchDir:      "/launch",
				Session:        mkStore(t),
				Model:          selectedState(),
				SettingsLayers: blockedGlobalLayers(t, home, t.TempDir(), tc.entry),
			}
			if err := StartTUI(context.Background(), result, io.Discard); err != nil || ran == nil {
				t.Fatalf("StartTUI error = %v, event loop ran = %v; want a launch", err, ran != nil)
			}

			got := ran.TranscriptText()
			if !bannerHasHead(got, "openai · gpt-5.5 · medium effort", "/launch", codemeldVersion) {
				t.Fatalf("transcript does not start with the launch banner\n--- got ---\n%s", got)
			}
			warning := "warning: blocked_paths entry /etc in " + SettingsPath(home) + " covers /etc; programs need these to start, so most commands will fail"
			if tc.warns && strings.Count(got, warning) != 1 {
				t.Fatalf("transcript shows the warning %d times, want once\n--- got ---\n%s", strings.Count(got, warning), got)
			}
			if !tc.warns && strings.Contains(got, "warning: blocked_paths") {
				t.Fatalf("transcript shows a blocked_paths warning, want none\n--- got ---\n%s", got)
			}
		})
	}
}

const (
	toolLessModelID = "tencent/hy-mt2-30b-a3b"
	toolfulModelID  = "openai/gpt-5.5"
)

func toolGateModels() []config.DiscoveredModel {
	return []config.DiscoveredModel{
		{ID: toolLessModelID, Capabilities: map[string]any{"supportedParameters": []any{"max_tokens", "top_p"}}},
		{ID: toolfulModelID, Capabilities: map[string]any{"supportedParameters": []any{"max_tokens", "tools"}}},
	}
}

func seedOpenRouterDiscoveredModels(t *testing.T, globalSettingsPath string, models []config.DiscoveredModel) {
	t.Helper()
	if err := config.UpdateDiscoveredModelsProvider(
		config.DiscoveredModelsPath(globalSettingsPath), "openrouter",
		config.DiscoveredProvider{Models: models},
	); err != nil {
		t.Fatalf("seed discovered openrouter models: %v", err)
	}
}

func openRouterToolCache(t *testing.T, models []config.DiscoveredModel) (*config.Cache, string) {
	t.Helper()
	globalSettings := SettingsPath(t.TempDir())
	seedOpenRouterDiscoveredModels(t, globalSettings, models)
	composed := map[string]any{"provider": map[string]any{
		"openrouter": map[string]any{"base_url": "https://openrouter.ai/api/v1", "api_key": "sk-or-test"},
	}}
	cache, err := config.NewCache(composed, t.TempDir(), []string{globalSettings})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	return cache, globalSettings
}

func toolGateSelection(id string) model.Selection {
	return model.Selection{Provider: "openrouter", ID: id, Effort: model.EffortDefault}
}

func toolGateActive(id string) *model.ActiveState {
	sel := toolGateSelection(id)
	return model.NewActiveState(&sel, model.SourceProject)
}

func interactiveGatedAdvertiser(t *testing.T, cache *config.Cache, active *model.ActiveState) func() []provider.ToolDefinition {
	t.Helper()
	return newCapabilityGatedToolAdvertiser(
		newInteractiveToolAdvertiser(newToolAdvertiser(advRegistry(t), mode.NewActiveState(mode.Build, mode.SourceDefault))),
		cache, active)
}

func TestNewCapabilityGatedToolAdvertiser_SuppressesTheWholeInteractiveSet(t *testing.T) {
	cache, _ := openRouterToolCache(t, toolGateModels())
	active := toolGateActive(toolfulModelID)
	gated := interactiveGatedAdvertiser(t, cache, active)

	want := []string{"ask_user", "bash", "suggest_followup", "vcs_commit", "vcs_status"}
	if got := toolNames(gated()); !slices.Equal(got, want) {
		t.Fatalf("supported model advertised %v, want %v", got, want)
	}
	assertAskUserDefinition(t, gated())

	active.ApplyUserSelection(toolGateSelection(toolLessModelID), false)
	if got := gated(); len(got) != 0 {
		t.Fatalf("tool-less model advertised %v, want nothing — ask_user must not survive the gate", toolNames(got))
	}
}

func TestNewCapabilityGatedToolAdvertiser_ReadsSelectionAndCatalogPerCall(t *testing.T) {
	cache, globalSettings := openRouterToolCache(t, toolGateModels())
	active := toolGateActive(toolfulModelID)
	gated := interactiveGatedAdvertiser(t, cache, active)

	if len(gated()) == 0 {
		t.Fatal("the capable launch selection advertised nothing")
	}
	active.ApplyUserSelection(toolGateSelection(toolLessModelID), false)
	if got := gated(); len(got) != 0 {
		t.Fatalf("after switching to a tool-less model the next turn advertised %v, want nothing", toolNames(got))
	}
	active.ApplyUserSelection(toolGateSelection(toolfulModelID), false)
	if len(gated()) == 0 {
		t.Fatal("switching back to a capable model did not restore the advertised set")
	}

	seedOpenRouterDiscoveredModels(t, globalSettings, []config.DiscoveredModel{
		{ID: toolfulModelID, Capabilities: map[string]any{"supportedParametersEmpty": true}},
	})
	if len(gated()) == 0 {
		t.Fatal("the rewritten store took effect before ReloadDiscoveredCatalog")
	}

	cache.ReloadDiscoveredCatalog()

	if got := gated(); len(got) != 0 {
		t.Fatalf("after a discovery reload the selected model advertised %v, want nothing", toolNames(got))
	}
}

func TestTurnController_ToolLessModelDispatchesWithoutTools(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var gotTools []provider.ToolDefinition
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		gotTools = req.Tools
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	cache, _ := openRouterToolCache(t, toolGateModels())
	for _, tc := range []struct {
		name      string
		modelID   string
		wantTools []string
	}{
		{"tool-less", toolLessModelID, nil},
		{"capable", toolfulModelID, []string{"ask_user", "bash", "suggest_followup", "vcs_commit", "vcs_status"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotTools = nil
			active := turnSelection("openrouter", tc.modelID, model.EffortDefault)
			ctl := newTurnController(context.Background(), &recordingSurface{}, cache, active, nil, nil)
			ctl.setToolAdvertiser(interactiveGatedAdvertiser(t, cache, active))

			if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
				t.Fatalf("dispatch error = %v", err)
			}
			turns.Wait()

			if got := toolNames(gotTools); !slices.Equal(got, tc.wantTools) {
				t.Fatalf("request advertised %v, want %v", got, tc.wantTools)
			}
		})
	}
}

func TestNewCapabilityGatedToolAdvertiser_GatesVeniceFunctionCallingModels(t *testing.T) {
	globalSettings := SettingsPath(t.TempDir())
	if err := config.UpdateDiscoveredModelsProvider(
		config.DiscoveredModelsPath(globalSettings), "venice",
		config.DiscoveredProvider{Models: []config.DiscoveredModel{
			{ID: "venice-translate", Capabilities: map[string]any{"supportsFunctionCalling": false}},
			{ID: "venice-uncensored", Capabilities: map[string]any{"supportsFunctionCalling": true}},
			{ID: "venice-legacy"},
		}},
	); err != nil {
		t.Fatalf("seed discovered venice models: %v", err)
	}
	cache, err := config.NewCache(map[string]any{"provider": map[string]any{
		"venice": map[string]any{"base_url": "https://api.venice.ai/api/v1", "api_key": "vk-test"},
	}}, t.TempDir(), []string{globalSettings})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}

	veniceSelection := func(id string) model.Selection {
		return model.Selection{Provider: "venice", ID: id, Effort: model.EffortDefault}
	}
	sel := veniceSelection("venice-translate")
	active := model.NewActiveState(&sel, model.SourceProject)
	gated := interactiveGatedAdvertiser(t, cache, active)

	if got := gated(); len(got) != 0 {
		t.Fatalf("a supportsFunctionCalling:false model advertised %v, want nothing", toolNames(got))
	}
	for _, id := range []string{"venice-uncensored", "venice-legacy"} {
		active.ApplyUserSelection(veniceSelection(id), false)
		if len(gated()) == 0 {
			t.Errorf("%s advertised nothing, want the full mode-filtered set", id)
		}
	}
}

func TestStartTUI_ToolLessModelSubmitsATurnWithoutTools(t *testing.T) {
	for _, tc := range []struct {
		name    string
		modelID string
		capable bool
	}{
		{"tool-less", toolLessModelID, false},
		{"capable", toolfulModelID, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var turns sync.WaitGroup
			defer swapGoTurn(waitableGoTurn(&turns))()

			// The title hook issues its own tool-less request after the turn, so
			// only the first round answers what the turn advertised.
			var mu sync.Mutex
			var first []provider.ToolDefinition
			var captured bool
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
				return &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
					mu.Lock()
					if !captured {
						captured, first = true, req.Tools
					}
					mu.Unlock()
					return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
				}}
			})()

			var ran *tui.App
			defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

			home, dir := t.TempDir(), t.TempDir()
			settings := SettingsPath(home)
			seedOpenRouterDiscoveredModels(t, settings, toolGateModels())
			result := &BootstrapResult{
				Home:             home,
				LaunchDir:        dir,
				ProjectRoot:      dir,
				Session:          mkStore(t),
				Model:            toolGateActive(tc.modelID),
				ToolRegistry:     &toolRegistryFactory{active: nil},
				ConfigLayerPaths: []string{settings},
				Config: map[string]any{"provider": map[string]any{
					"openrouter": map[string]any{"base_url": "https://openrouter.ai/api/v1", "api_key": "sk-or-test"},
				}},
			}
			if err := StartTUI(context.Background(), result, io.Discard); err != nil {
				t.Fatalf("StartTUI error: %v", err)
			}
			if ran == nil {
				t.Fatal("StartTUI did not run the event loop")
			}
			if !ran.SubmitInput("hello there") {
				t.Fatal("the wired submit rejected a plain prompt")
			}
			turns.Wait()

			mu.Lock()
			names, sawRound := toolNames(first), captured
			mu.Unlock()
			if !sawRound {
				t.Fatal("the submitted prompt issued no provider round")
			}
			if !tc.capable {
				if len(names) != 0 {
					t.Fatalf("the wired launch advertised %v for a tool-less model, want nothing", names)
				}
				return
			}
			for _, want := range []string{"ask_user", "bash"} {
				if !slices.Contains(names, want) {
					t.Fatalf("the wired launch advertised %v, want %q retained for a capable model", names, want)
				}
			}
		})
	}
}

// The interactive dispatcher is built with the run's protected-state policy; this proves that policy
// reaches VCS dispatch too, against a real repository whose committed settings differ from the
// approved bytes on disk.
func TestStartTUI_ProtectedSettingsVCSMutationIsRefusedAndTheTurnReIssues(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	seedGitRepo(t, project)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	projectSettings := projectSettingsPath(project)
	globalSettings := SettingsPath(home)
	seedProtectedSettings(t, projectSettings)
	seedProtectedSettings(t, globalSettings)

	client := toolThenContentClient(nil, "vcs_restore_file", `{"path":".codemeld/settings.yaml"}`, guardRecoveryAnswer)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := titledStore(t)
	seedOpenAIDiscovered(t, globalSettings, "gpt-5.5")
	result := &BootstrapResult{
		Home:        home,
		LaunchDir:   project,
		ProjectRoot: project,
		Session:     store,
		Model:       model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{
					"base_url": "https://api.openai.com/v1",
					"api_key":  "sk-test",
				},
			},
		},
		ConfigLayerPaths: []string{globalSettings},
		ToolRegistry:     &toolRegistryFactory{active: activeBuiltinVCS(t, "git", project)},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	if !ran.SubmitInput("discard my policy changes") {
		t.Fatal("wired submit rejected a plain prompt")
	}
	turns.Wait()

	if got := mustReadFile(t, projectSettings); got != sevenGrantSettings {
		t.Fatalf("project settings = %q, want the seven grants untouched by the restore", got)
	}
	durable := sessions.New(store.Path(), readSessionFile(t, store.Path()))
	matched := decodePermissionMatched(t, durable)
	want := events.PermissionMatched{
		SubjectKind:   "tool",
		Subject:       "vcs_restore_file",
		PathScope:     project,
		Outcome:       "deny",
		OutcomeSource: "protected_state",
	}
	if len(matched) != 1 || matched[0] != want {
		t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
	}
	toolMsgs := messagesByRole(durable, "tool")
	if len(toolMsgs) != 1 || toolMsgs[0].Content.Text() != permissions.BuildGuardDenyEnvelope() {
		t.Fatalf("durable tool messages = %+v, want the one guard deny envelope", toolMsgs)
	}
}

func TestStartTUI_BlockedEntryVCSRestoreIsRefusedAndTheTurnReIssues(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	seedBlockedGitRepo(t, project)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	secrets := filepath.Join(project, "secrets")
	globalSettings := SettingsPath(home)
	layers := blockedGlobalLayers(t, home, project, secrets)
	seedOpenAIDiscovered(t, globalSettings, "gpt-5.5")

	client := toolThenContentClient(nil, "vcs_restore_file", `{"path":"secrets/k"}`, guardRecoveryAnswer)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := titledStore(t)
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        project,
		ProjectRoot:      project,
		Session:          store,
		Model:            model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config:           headlessProviderConfig(),
		ConfigLayerPaths: []string{globalSettings},
		SettingsLayers:   layers,
		ToolRegistry:     &toolRegistryFactory{active: activeBuiltinVCS(t, "git", project)},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	if !ran.SubmitInput("discard my secret changes") {
		t.Fatal("wired submit rejected a plain prompt")
	}
	turns.Wait()

	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (a blocked-path denial re-issues rather than halting the turn)", client.callCount())
	}
	if got := mustReadFile(t, filepath.Join(secrets, "k")); got != modifiedSecret {
		t.Fatalf("blocked file = %q, want its modified bytes %q", got, modifiedSecret)
	}
	durable := sessions.New(store.Path(), readSessionFile(t, store.Path()))
	want := events.PermissionMatched{SubjectKind: "tool", Subject: "vcs_restore_file", PathScope: project, Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: secrets, BlockedEntrySource: globalSettings}
	if matched := decodePermissionMatched(t, durable); len(matched) != 1 || matched[0] != want {
		t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
	}
}

// Both dispatchers bind this policy, so refusing every spelling here covers both.
func TestProtectedStatePolicy_RefusesApprovalStoreAliases(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	project := t.TempDir()
	record := trust.StorePath(home)
	seedProtectedSettings(t, record)
	seedProtectedSettings(t, record+".lock")

	aliasDir := t.TempDir()
	alias := filepath.Join(aliasDir, "approved-projects.yaml")
	lockAlias := filepath.Join(aliasDir, "approved-projects.yaml.lock")
	if err := os.Symlink(record+".lock", lockAlias); err != nil {
		t.Fatalf("symlink lock: %v", err)
	}
	if err := os.Symlink(record, alias); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	globalDir := filepath.Dir(record)
	relBase := filepath.Dir(globalDir)

	policy := mustProtectedStatePolicy(t, home, project, nil)
	targets := map[string]string{
		"absolute record": record,
		"lock sidecar":    record + ".lock",
		"relative record": "global/approved-projects.yaml",
		"dotdot record":   filepath.Join(globalDir, "..", "global", "approved-projects.yaml"),
		"symlink alias":   alias,
		"lock alias":      lockAlias,
	}
	tools := []string{
		filetools.EditToolName, filetools.CreateToolName,
		filetools.DeleteToolName, filetools.MkdirToolName, filetools.MoveToolName,
	}

	for name, target := range targets {
		for _, tool := range tools {
			t.Run(name+"/"+tool, func(t *testing.T) {
				args := map[string]any{"path": target}
				if tool == filetools.MoveToolName {
					args = map[string]any{"source": target, "destination": filepath.Join(project, "stolen.yaml")}
				}
				if policy.RefuseNominal(tool, args, home, relBase) == nil {
					t.Fatalf("%s on %q was not refused as protected state", tool, target)
				}
			})
		}
	}

	if policy.RefuseNominal(filetools.EditToolName, map[string]any{"path": filepath.Join(project, "notes.md")}, home, project) != nil {
		t.Fatal("an ordinary project file was refused as protected state")
	}
}

// degradedTrustFixture returns the project root, with both settings files, plus the
// withheld summary the production helper derives from it, so a test drives the same value
// a real degraded launch would carry rather than a hand-written one.
func degradedTrustFixture(t *testing.T, vcsTemplates int) (string, []WithheldInput) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".codemeld"), 0o755); err != nil {
		t.Fatalf("create project config dir: %v", err)
	}
	for _, path := range []string{projectSettingsPath(root), config.LocalSettingsPath(root)} {
		if err := os.WriteFile(path, []byte("model: gpt-5.5\n"), 0o600); err != nil {
			t.Fatalf("write project settings: %v", err)
		}
	}
	if vcsTemplates > 0 {
		if err := os.MkdirAll(filepath.Join(root, ".codemeld", "vcs"), 0o755); err != nil {
			t.Fatalf("create vcs template dir: %v", err)
		}
		for i := range vcsTemplates {
			name := fmt.Sprintf("vcs%d.yaml", i)
			if err := os.WriteFile(filepath.Join(root, ".codemeld", "vcs", name), []byte("name: hg\n"), 0o600); err != nil {
				t.Fatalf("write vcs template %s: %v", name, err)
			}
		}
	}
	return root, withheldInputs(root, false)
}

func degradedResult(t *testing.T, root string, withheld []WithheldInput) *BootstrapResult {
	t.Helper()
	return &BootstrapResult{
		Home:           t.TempDir(),
		LaunchDir:      root,
		ProjectRoot:    root,
		Session:        mkStore(t),
		Model:          selectedState(),
		TrustDecision:  trust.Decision{Reason: trust.ReasonNoRecord, Root: root},
		WithheldInputs: withheld,
	}
}

func statusOverlay(t *testing.T, result *BootstrapResult) string {
	t.Helper()
	app, restore := startCaptured(t, context.Background(), result, io.Discard)
	t.Cleanup(restore)
	if !app.SubmitInput("/status") {
		t.Fatal("/status rejected through the production StartTUI submit path")
	}
	overlay := app.StatusText()
	if overlay == "" {
		t.Fatal("/status overlay is empty; StartTUI's app did not render the status snapshot")
	}
	return overlay
}

// This fails if newStatusState stops forwarding the approval handoff, or if the overlay
// re-derives the state from disk instead of reporting the launch the user is in.
func TestStartTUI_DegradedApprovalDisclosureReachesStatusOverlay(t *testing.T) {
	root, withheld := degradedTrustFixture(t, 1)
	app, restore := startCaptured(t, context.Background(), degradedResult(t, root, withheld), io.Discard)
	defer restore()

	if !app.SubmitInput("/status") {
		t.Fatal("/status rejected through the production StartTUI submit path")
	}
	overlay := app.StatusText()
	want := "Project approval: not approved — ignoring project settings " + projectSettingsPath(root) +
		" and project settings " + config.LocalSettingsPath(root) +
		" and VCS command templates " + projectVCSTemplateDir(root) + "\n"
	if !strings.Contains(overlay, want) {
		t.Errorf("status overlay missing %q\n--- overlay ---\n%s", want, overlay)
	}

	if err := os.RemoveAll(filepath.Join(root, ".codemeld")); err != nil {
		t.Fatalf("remove covered project inputs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "AGENTS.md"), []byte("project instructions\n"), 0o600); err != nil {
		t.Fatalf("write project instructions: %v", err)
	}
	if !app.SubmitInput("/status") {
		t.Fatal("/status rejected on the second open")
	}
	if again := app.StatusText(); again != overlay {
		t.Errorf("the disclosure followed a mid-session change to the covered files\n--- launch ---\n%s\n--- after change ---\n%s", overlay, again)
	}
}

func TestStartTUI_DegradedApprovalDisclosureNamesOnlyPresentInputs(t *testing.T) {
	root, _ := degradedTrustFixture(t, 0)
	if err := os.Remove(projectSettingsPath(root)); err != nil {
		t.Fatalf("remove shared settings: %v", err)
	}

	overlay := statusOverlay(t, degradedResult(t, root, withheldInputs(root, false)))

	if want := "Project approval: not approved — ignoring project settings " + config.LocalSettingsPath(root) + "\n"; !strings.Contains(overlay, want) {
		t.Errorf("status overlay missing %q\n--- overlay ---\n%s", want, overlay)
	}
	for _, absent := range []string{projectSettingsPath(root), projectVCSTemplateDir(root)} {
		if strings.Contains(overlay, absent) {
			t.Errorf("status overlay names absent input %q\n--- overlay ---\n%s", absent, overlay)
		}
	}
}

func TestStartTUI_DegradedApprovalDisclosureNamesTheVCSFolderOnce(t *testing.T) {
	root, withheld := degradedTrustFixture(t, 3)

	overlay := statusOverlay(t, degradedResult(t, root, withheld))

	if got := strings.Count(overlay, projectVCSTemplateDir(root)); got != 1 {
		t.Errorf("status overlay names the VCS folder %d times, want once\n--- overlay ---\n%s", got, overlay)
	}
}

func TestStartTUI_DegradedApprovalDisclosureNamesUninspectableVCSFolder(t *testing.T) {
	root, _ := degradedTrustFixture(t, 0)
	if err := os.Symlink(t.TempDir(), projectVCSTemplateDir(root)); err != nil {
		t.Fatalf("symlink vcs folder: %v", err)
	}
	if _, determinate := presentGatedPaths(root); determinate {
		t.Fatal("the fixture folder was inspectable, want an indeterminate presence check")
	}
	result := degradedResult(t, root, withheldInputs(root, false))
	result.TrustDecision.Reason = trust.ReasonUnreadable

	overlay := statusOverlay(t, result)

	if want := "VCS command templates " + projectVCSTemplateDir(root); !strings.Contains(overlay, want) {
		t.Errorf("status overlay missing %q\n--- overlay ---\n%s", want, overlay)
	}
}

func TestStartTUI_ApprovalStatesReachStatusOverlay(t *testing.T) {
	for _, tc := range []struct {
		name     string
		decision trust.Decision
		want     string
	}{
		{"listed root", trust.Decision{Trusted: true, Reason: trust.ReasonTrusted, Root: "/proj"}, "Project approval: approved\n"},
		{"nothing covered", trust.Decision{Trusted: true, Reason: trust.ReasonNothingCovered, Root: "/proj"}, "Project approval: nothing to approve\n"},
		{"unresolved root", trust.Decision{Reason: trust.ReasonUnresolvedRoot}, "Project approval: not approved\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			overlay := statusOverlay(t, &BootstrapResult{
				Home:          t.TempDir(),
				LaunchDir:     "/proj",
				ProjectRoot:   "/proj",
				Session:       mkStore(t),
				Model:         selectedState(),
				TrustDecision: tc.decision,
			})
			if !strings.Contains(overlay, tc.want) {
				t.Errorf("status overlay missing %q\n--- overlay ---\n%s", tc.want, overlay)
			}
			if strings.Contains(overlay, "trusted") || strings.Contains(overlay, "ignoring") {
				t.Errorf("status overlay carries trust or withheld wording\n--- overlay ---\n%s", overlay)
			}
		})
	}
}

// /status and the launch notice are two renderings of one run-fixed summary, so this
// fails if /status grows its own idea of which inputs are covered.
func TestStartTUI_StatusApprovalDisclosureAgreesWithLaunchNotice(t *testing.T) {
	for _, tc := range []struct {
		name         string
		vcsTemplates int
	}{
		{name: "settings and vcs templates", vcsTemplates: 1},
		{name: "settings only", vcsTemplates: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, withheld := degradedTrustFixture(t, tc.vcsTemplates)
			result := degradedResult(t, root, withheld)

			var notice strings.Builder
			noticeUntrustedProject(&notice, root, result.WithheldInputs)
			if notice.Len() == 0 {
				t.Fatal("fixture produced no launch notice; the agreement check would be vacuous")
			}

			overlay := statusOverlay(t, result)

			for _, path := range []string{projectSettingsPath(root), config.LocalSettingsPath(root), projectVCSTemplateDir(root)} {
				inNotice := strings.Contains(notice.String(), path)
				inOverlay := strings.Contains(overlay, path)
				if inNotice != inOverlay {
					t.Errorf("%s: launch notice names it = %v, /status names it = %v\n--- notice ---\n%s\n--- overlay ---\n%s",
						path, inNotice, inOverlay, notice.String(), overlay)
				}
			}
		})
	}
}

func captureSettingsDeps(t *testing.T) *tui.SettingsDeps {
	t.Helper()
	var captured tui.SettingsDeps
	production := newSettingsDeps
	newSettingsDeps = func(app *tui.App, cache *config.Cache, active *model.ActiveState, authorizer *productionAuthorizer) tui.SettingsDeps {
		captured = production(app, cache, active, authorizer)
		return captured
	}
	t.Cleanup(func() { newSettingsDeps = production })
	return &captured
}

func loadedLayer(t *testing.T, kind securitystate.LayerKind, path string) securitystate.LayerSnapshot {
	t.Helper()
	_, raw, cat, err := config.LoadYAML(path)
	if err != nil || cat != config.LoadOK {
		t.Fatalf("LoadYAML(%q) cat=%v err=%v", path, cat, err)
	}
	return securitystate.LayerSnapshot{Kind: kind, Path: path, Present: true, Raw: raw}
}

func layered(e permissions.PermissionEntry, kind permissions.LayerKind) permissions.PermissionEntry {
	e.Layer = kind
	return e
}

func TestStartTUI_PermissionsRowsSkipIgnoredLayers(t *testing.T) {
	root := mustCanonical(t, t.TempDir())
	home := t.TempDir()
	global := permissions.PermissionEntry{Kind: "tool", Subject: "grep", PathScope: "*", GrantKind: "global"}
	seedGrantFile(t, SettingsPath(home), global)
	seedGrantFile(t, projectSettingsPath(root), folderGrant(root, "read_file"))
	seedGrantFile(t, config.LocalSettingsPath(root), folderGrant(root, "list_files"))
	project := loadedLayer(t, securitystate.LayerProject, projectSettingsPath(root))
	project.Ignored = true
	local := loadedLayer(t, securitystate.LayerLocal, config.LocalSettingsPath(root))
	local.Ignored = true
	deps := captureSettingsDeps(t)
	result := &BootstrapResult{
		Home: home, LaunchDir: root, ProjectRoot: root, Session: mkStore(t),
		TrustDecision:  trust.Decision{Reason: trust.ReasonNoRecord, Root: root},
		SettingsLayers: []securitystate.LayerSnapshot{loadedLayer(t, securitystate.LayerGlobal, SettingsPath(home)), project, local},
	}
	_, restore := startCaptured(t, context.Background(), result, io.Discard)
	defer restore()

	want := []tui.PermissionRow{{Entry: layered(global, permissions.LayerGlobal), Layer: permissions.LayerGlobal, Path: SettingsPath(home)}}
	if got := deps.Rows(); !reflect.DeepEqual(got, want) {
		t.Fatalf("launch rows = %+v, want only the global layer's %+v", got, want)
	}
}

func TestStartTUI_SettingsDepsBindLiveRowsRevokeAndShare(t *testing.T) {
	root := mustCanonical(t, t.TempDir())
	home := t.TempDir()
	host := projectHostGrant("web_fetch", "docs.example.com")
	shared, kept := folderGrant(root, "read_file"), folderGrant(root, "list_files")
	seedGrantFile(t, projectSettingsPath(root), host)
	seedGrantFile(t, config.LocalSettingsPath(root), shared)
	seedGrantFile(t, config.LocalSettingsPath(root), kept)
	deps := captureSettingsDeps(t)
	result := &BootstrapResult{
		Home: home, LaunchDir: root, ProjectRoot: root, Session: mkStore(t),
		TrustDecision: trust.Decision{Trusted: true, Reason: trust.ReasonTrusted, Root: root},
		SettingsLayers: []securitystate.LayerSnapshot{
			{Kind: securitystate.LayerGlobal, Path: SettingsPath(home), Present: true, Raw: map[string]any{}},
			loadedLayer(t, securitystate.LayerProject, projectSettingsPath(root)),
			loadedLayer(t, securitystate.LayerLocal, config.LocalSettingsPath(root)),
		},
	}
	_, restore := startCaptured(t, context.Background(), result, io.Discard)
	defer restore()

	hostRow := projectRow(root, layered(host, permissions.LayerProject))
	sharedRow := localRow(root, layered(shared, permissions.LayerLocal))
	keptRow := localRow(root, layered(kept, permissions.LayerLocal))
	if got, want := deps.Rows(), []tui.PermissionRow{hostRow, sharedRow, keptRow}; !reflect.DeepEqual(got, want) {
		t.Fatalf("launch rows = %+v\nwant %+v", got, want)
	}

	res := deps.Share(sharedRow)
	if want := (tui.ShareResult{SharedPath: projectSettingsPath(root), LocalPath: config.LocalSettingsPath(root)}); res != want {
		t.Fatalf("Share = %+v, want %+v", res, want)
	}
	requireFileGrants(t, projectSettingsPath(root), root, host, shared)
	requireFileGrants(t, config.LocalSettingsPath(root), root, kept)
	sharedAsProject := projectRow(root, sharedRow.Entry)
	if got, want := deps.Rows(), []tui.PermissionRow{hostRow, keptRow, sharedAsProject}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rows after share = %+v\nwant %+v", got, want)
	}

	deps.Revoke(keptRow)
	requireFileGrants(t, config.LocalSettingsPath(root), root)
	if got, want := deps.Rows(), []tui.PermissionRow{hostRow, sharedAsProject}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rows after revoke = %+v\nwant %+v", got, want)
	}
}

func TestStartTUI_SettingsDepsCarryExplicitApprovalAndBoundary(t *testing.T) {
	for _, tc := range []struct {
		name     string
		decision trust.Decision
		boundary string
		approved bool
	}{
		{name: "explicitly approved root", decision: trust.Decision{Trusted: true, Reason: trust.ReasonTrusted, Root: "/proj"}, boundary: "project-root", approved: true},
		{name: "nothing to gate is not an approval", decision: trust.Decision{Trusted: true, Reason: trust.ReasonNothingCovered, Root: "/proj"}, boundary: "launch-dir-only"},
		{name: "unapproved root", decision: trust.Decision{Reason: trust.ReasonNoRecord, Root: "/proj"}, boundary: "project-root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps := captureSettingsDeps(t)
			result := &BootstrapResult{
				Home: t.TempDir(), LaunchDir: "/proj", ProjectRoot: "/proj", Session: mkStore(t),
				TrustDecision: tc.decision,
				Config:        map[string]any{"discovery": map[string]any{"boundary": tc.boundary}},
			}
			_, restore := startCaptured(t, context.Background(), result, io.Discard)
			defer restore()

			if deps.Approved != tc.approved {
				t.Errorf("SettingsDeps.Approved = %v, want %v for %+v", deps.Approved, tc.approved, tc.decision)
			}
			if deps.Boundary != tc.boundary {
				t.Errorf("SettingsDeps.Boundary = %q, want %q", deps.Boundary, tc.boundary)
			}
		})
	}
}

func TestStartTUI_MalformedLayerPermissionsFailTheLaunch(t *testing.T) {
	home := t.TempDir()
	result := &BootstrapResult{
		Home: home, LaunchDir: "/launch", Session: mkStore(t),
		SettingsLayers: []securitystate.LayerSnapshot{{
			Kind: securitystate.LayerGlobal, Path: SettingsPath(home), Present: true,
			Raw: map[string]any{"permissions": []any{"not a mapping"}},
		}},
	}
	defer swapRunApp(func(*tui.App) error { return nil })()
	if err := StartTUI(context.Background(), result, io.Discard); err == nil || !strings.Contains(err.Error(), "permission rows") {
		t.Fatalf("StartTUI error = %v, want the permission-row build to refuse an unparseable layer", err)
	}
}

var injectedResolution = enforce.Resolution{
	Capability: enforce.Refused,
	Reason:     "test: injected refusal",
	Legs:       []enforce.Leg{{Name: "test-write", Observed: "denied"}, {Name: "test-read", Observed: "held_by_host"}},
}

var injectedCapability = events.ExecutionCapability{
	Capability: "refused",
	Reason:     "test: injected refusal",
	Legs:       []events.ExecutionCapabilityLeg{{Name: "test-write", Observed: "denied"}, {Name: "test-read", Observed: "held_by_host"}},
}

func swapResolveExecutionCapability(t *testing.T, resolution enforce.Resolution) *int {
	t.Helper()
	calls := new(int)
	prev := resolveExecutionCapability
	resolveExecutionCapability = func(enforce.ResolveInput) enforce.Resolution {
		*calls++
		return resolution
	}
	t.Cleanup(func() { resolveExecutionCapability = prev })
	return calls
}

func finishedPID(t *testing.T) int {
	t.Helper()
	finished := exec.Command(os.Args[0], "-test.run=^$")
	if err := finished.Run(); err != nil {
		t.Fatalf("run finished process: %v", err)
	}
	return finished.ProcessState.Pid()
}

func TestStartTUI_RecordsTheInjectedCapabilityOnceAfterLaunchBegan(t *testing.T) {
	calls := swapResolveExecutionCapability(t, injectedResolution)
	store := mkStore(t)
	if _, err := events.Append(store, events.LaunchBegan{Source: "fresh"}); err != nil {
		t.Fatal(err)
	}
	var disk *sessions.Session
	defer swapRunApp(func(*tui.App) error { disk = readSessionFile(t, store.Path()); return nil })()

	if err := StartTUI(context.Background(), &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store}, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("Resolve calls = %d, want 1", *calls)
	}
	kinds := eventKinds(disk.Records)
	began, capability := slices.Index(kinds, events.KindLaunchBegan), slices.Index(kinds, events.KindExecutionCapability)
	if began < 0 || capability <= began {
		t.Fatalf("event kinds on disk = %v, want execution_capability after launch_began", kinds)
	}
	caps := decodeDiskEvents[events.ExecutionCapability](t, disk, events.KindExecutionCapability)
	if len(caps) != 1 || !reflect.DeepEqual(caps[0], injectedCapability) {
		t.Fatalf("execution_capability on disk = %+v, want exactly %+v", caps, injectedCapability)
	}
}

func TestStartTUI_StatusShowsTheLaunchCapability(t *testing.T) {
	swapResolveExecutionCapability(t, injectedResolution)
	app, restore := startCaptured(t, context.Background(), &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: mkStore(t)}, io.Discard)
	defer restore()

	if got := app.StatusLineText(); !strings.HasSuffix(strings.TrimSpace(got), "sandbox: unavailable") {
		t.Errorf("status line = %q, want it to end with the sandbox: unavailable pill", got)
	}
	if !app.SubmitInput("/status") {
		t.Fatal("/status should be accepted")
	}
	if overlay := app.StatusText(); !strings.Contains(overlay, "\n"+injectedSandboxLine+"\n") {
		t.Errorf("status overlay missing the launch capability\n--- overlay ---\n%s", overlay)
	}
}

func TestStartTUI_ResumeAppendsOneNewCapability(t *testing.T) {
	calls := swapResolveExecutionCapability(t, injectedResolution)
	path := filepath.Join(t.TempDir(), "session.json")
	prior := storeAt(t, path, "01890000-0000-7000-8000-0000000000ab", "/proj")
	earlier := events.ExecutionCapability{Capability: "refused", Reason: "earlier launch"}
	for _, p := range []events.EventPayload{events.LaunchBegan{Source: "fresh"}, earlier} {
		if _, err := events.Append(prior, p); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := prior.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	resumed := sessions.New(path, readSessionFile(t, path))
	if _, err := events.Append(resumed, events.LaunchBegan{Source: "resume"}); err != nil {
		t.Fatal(err)
	}
	defer swapRunApp(func(*tui.App) error { return nil })()

	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: resumed, ResumeReplay: true}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	caps := decodeDiskEvents[events.ExecutionCapability](t, readSessionFile(t, path), events.KindExecutionCapability)
	if *calls != 1 || len(caps) != 2 || !reflect.DeepEqual(caps[0], earlier) || !reflect.DeepEqual(caps[1], injectedCapability) {
		t.Fatalf("Resolve calls = %d, capabilities = %+v, want one call and the injected one appended after %+v", *calls, caps, earlier)
	}
}

func TestStartTUI_CapabilityFlushFailureRunsTheWriteFailureProtocolAndAborts(t *testing.T) {
	swapResolveExecutionCapability(t, injectedResolution)
	ran := false
	defer swapRunApp(func(*tui.App) error { ran = true; return nil })()

	store := unwritableStore(t, "01890000-0000-7000-8000-0000000000ac", "/proj")
	err := StartTUI(context.Background(), &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store}, io.Discard)
	if err == nil || ran {
		t.Fatalf("StartTUI error = %v, ran = %v; want the launch aborted", err, ran)
	}
	if got := len(kindEvents(t, store, events.KindSessionWriteFailed)); got != 1 {
		t.Fatalf("session_write_failed events = %d, want 1", got)
	}
}

func TestStartTUI_SessionTempFolderFollowsTheSelfTest(t *testing.T) {
	for _, passed := range []bool{true, false} {
		t.Run(fmt.Sprintf("self-test passed %v", passed), func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			stale := filepath.Join(tmp, fmt.Sprintf("codemeld-confine-%d-x", finishedPID(t)))
			if runtime.GOOS == "linux" {
				if err := os.Mkdir(stale, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			resolution := injectedResolution
			resolution.SelfTestPassed = passed
			swapResolveExecutionCapability(t, resolution)
			own := filepath.Join(tmp, fmt.Sprintf("codemeld-confine-%d-*", os.Getpid()))
			var during []string
			var perm fs.FileMode
			defer swapRunApp(func(*tui.App) error {
				during, _ = filepath.Glob(own)
				if len(during) == 1 {
					if info, err := os.Stat(during[0]); err == nil && info.IsDir() {
						perm = info.Mode().Perm()
					}
				}
				return nil
			})()

			if err := StartTUI(context.Background(), &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: mkStore(t)}, io.Discard); err != nil {
				t.Fatalf("StartTUI error: %v", err)
			}
			if passed && (len(during) != 1 || perm != 0o700) {
				t.Fatalf("temp folders during launch = %v (perm %v), want one 0700 folder", during, perm)
			}
			if !passed && len(during) != 0 {
				t.Fatalf("temp folders during launch = %v, want none", during)
			}
			if after, _ := filepath.Glob(own); len(after) != 0 {
				t.Fatalf("temp folders after launch = %v, want none", after)
			}
			if _, err := os.Stat(stale); runtime.GOOS == "linux" && !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("stale folder stat = %v, want it removed", err)
			}
		})
	}
}

func TestStartTUI_RemovesSessionTempFolderWithUnreadableDescendant(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the confined temp folder is written only on Linux")
	}
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	resolution := injectedResolution
	resolution.SelfTestPassed = true
	swapResolveExecutionCapability(t, resolution)
	own := filepath.Join(tmp, fmt.Sprintf("codemeld-confine-%d-*", os.Getpid()))
	var setupErr error
	defer swapRunApp(func(*tui.App) error {
		during, _ := filepath.Glob(own)
		if len(during) != 1 {
			setupErr = fmt.Errorf("temp folders during launch = %v, want one", during)
			return nil
		}
		locked := filepath.Join(during[0], "a", "b")
		if setupErr = os.MkdirAll(locked, 0o700); setupErr != nil {
			return nil
		}
		if setupErr = os.WriteFile(filepath.Join(locked, "f"), []byte("x"), 0o600); setupErr != nil {
			return nil
		}
		setupErr = os.Chmod(filepath.Join(during[0], "a"), 0)
		return nil
	})()

	if err := StartTUI(context.Background(), &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: mkStore(t)}, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	if after, _ := filepath.Glob(own); len(after) != 0 {
		t.Fatalf("temp folders after launch = %v, want none", after)
	}
}

func TestStartTUI_LaunchConfinementIsSharedWithTheVCSRunners(t *testing.T) {
	calls := swapResolveExecutionCapability(t, enforce.Resolution{
		Capability:     enforce.Constrained,
		Legs:           []enforce.Leg{{Name: "test-write", Observed: "denied"}},
		SelfTestPassed: true,
	})
	project := t.TempDir()
	result := headlessResult(t, project, mode.NewActiveState(mode.Plan, mode.SourceDefault))
	result.ToolRegistry = &toolRegistryFactory{active: &ActiveVCS{Template: productVettedGitTemplate(t), RepoRoot: project}}
	inner := &confineInner{}
	prev := newVCSActionRunner
	newVCSActionRunner = func() runner.Runner { return inner }
	t.Cleanup(func() { newVCSActionRunner = prev })
	launchPath := t.TempDir()
	t.Setenv("PATH", launchPath)

	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if isTitleRequest(req) {
			return titleCompletion("Confinement session"), nil
		}
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()
	var d *productionToolDispatcher
	defer swapToolLoop(func(deps turn.Deps, disp turn.ToolDispatcher, n int) *turn.ToolLoop {
		d, _ = disp.(*productionToolDispatcher)
		return turn.NewToolLoop(deps, disp, n)
	})()
	defer runLiveApp(t, tcell.NewSimulationScreen("UTF-8"), func(app *tui.App) {
		if !submitOnEventLoop(t, app, "hi") {
			t.Fatal("wired submit rejected a plain prompt")
		}
		turns.Wait()
	})()

	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if d == nil || d.confinement == nil {
		t.Fatalf("dispatcher = %+v; want the production dispatcher with a launch confinement", d)
	}
	conf := d.confinement
	if *calls != 1 {
		t.Fatalf("Resolve calls = %d, want 1", *calls)
	}
	if !conf.constrained || conf.home != result.Home || conf.projectRoot != project || conf.lookupPath != launchPath || conf.mode() != string(mode.Plan) {
		t.Fatalf("confinement = %+v, want constrained with the launch home, project root, PATH and mode", *conf)
	}
	if conf.blocked == nil || conf.blocked != d.guard.Blocked {
		t.Fatalf("blocked = %p, want the launch guard's %p", conf.blocked, d.guard.Blocked)
	}

	conf.lookupPath = programDir(t, "git")
	if _, err := d.Dispatch(context.Background(), structuredCall("c1", "vcs_status", map[string]any{})); err != nil {
		t.Fatalf("Dispatch error = %v", err)
	}
	if len(inner.bounded) != 1 {
		t.Fatalf("vcs runs = %+v, want one confined run", inner.bounded)
	}
	got := inner.bounded[0]
	if len(got.Argv) < 3 || got.Argv[0] != "/proc/self/exe" || got.Argv[1] != enforce.HelperCommand || got.Argv[2] != filepath.Join(conf.lookupPath, "git") {
		t.Fatalf("vcs argv = %q, want the helper prefix and git from the shared confinement's lookup path", got.Argv)
	}
	if policy, _ := decodeFrame(t, got.Stdin); policy.Mode != string(mode.Plan) {
		t.Fatalf("policy = %+v, want the plan launch mode", policy)
	}
}

func TestStartTUI_TempFolderFailureAbortsWithoutRecordingCapability(t *testing.T) {
	store := mkStore(t)
	home := t.TempDir()
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	resolution := injectedResolution
	resolution.SelfTestPassed = true
	swapResolveExecutionCapability(t, resolution)
	ran := false
	defer swapRunApp(func(*tui.App) error { ran = true; return nil })()

	err := StartTUI(context.Background(), &BootstrapResult{Home: home, LaunchDir: "/launch", Session: store}, io.Discard)
	if !errors.Is(err, fs.ErrNotExist) || ran {
		t.Fatalf("StartTUI error = %v, ran = %v; want the temp folder error and no launch", err, ran)
	}
	if got := kindEvents(t, store, events.KindExecutionCapability); len(got) != 0 {
		t.Fatalf("execution_capability events = %d, want none", len(got))
	}
}

func TestStartTUI_SwitchesReuseTheLaunchCapabilityAndCleanUpEveryFolder(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can remove a folder from a read-only parent")
	}
	launchTmp, switchTmp := t.TempDir(), t.TempDir()
	t.Setenv("TMPDIR", launchTmp)
	resolution := injectedResolution
	resolution.SelfTestPassed = true
	calls := swapResolveExecutionCapability(t, resolution)
	result, _, restore := midTurnSwitchResult(t, "/resume")
	defer restore()
	var retried []string
	var stepErr error
	defer swapRunApp(func(app *tui.App) error {
		retried, _ = filepath.Glob(filepath.Join(launchTmp, sessionTempDirPrefix+"*"))
		t.Setenv("TMPDIR", switchTmp)
		if stepErr = os.Chmod(launchTmp, 0o500); stepErr != nil {
			return nil
		}
		cleared := app.SubmitInput("/new")
		if stepErr = os.Chmod(launchTmp, 0o700); stepErr != nil {
			return nil
		}
		if !cleared || !strings.HasPrefix(app.NoticeText(), "can't remove private temp folder ") {
			stepErr = fmt.Errorf("/new accepted = %v, notice = %q; want the cleanup warning", cleared, app.NoticeText())
			return nil
		}
		fresh := app.ActiveStore()
		if !app.SubmitInput("/resume") || app.ActiveStore() == fresh {
			stepErr = errors.New("/resume did not switch away from the /new session")
		}
		return nil
	})()

	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if stepErr != nil {
		t.Fatal(stepErr)
	}
	if *calls != 1 {
		t.Fatalf("Resolve calls = %d, want 1 across /clear and /resume", *calls)
	}
	if len(retried) != 1 {
		t.Fatalf("launch temp folders = %v, want one", retried)
	}
	for _, dir := range []string{launchTmp, switchTmp} {
		if left, _ := filepath.Glob(filepath.Join(dir, sessionTempDirPrefix+"*")); len(left) != 0 {
			t.Fatalf("temp folders left in %s = %v, want none", dir, left)
		}
	}
}

func TestStartTUI_CompactPreparedButNeverDeliveredIsDiscardedOnExit(t *testing.T) {
	launchTmp := t.TempDir()
	t.Setenv("TMPDIR", launchTmp)
	resolution := injectedResolution
	resolution.SelfTestPassed = true
	swapResolveExecutionCapability(t, resolution)
	result, prior, restore := midTurnSwitchResult(t, "/compact")
	defer restore()
	prior.Append(sessions.Message{ID: ids.NewV7(), Role: "user", Content: sessions.TextContent("plan the work"), Timestamp: testStart})
	mustFlush(t, prior)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
		return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{Completion: &openai.ChatCompletion{
				Choices: []openai.ChatCompletionChoice{{Message: openai.ChatCompletionMessage{Content: "the plan, summarized"}}},
			}}, nil
		}}
	})()

	var appRef atomic.Pointer[tui.App]
	var childPath atomic.Value
	latched := make(chan struct{})
	orig := recordExecutionCapability
	recordExecutionCapability = func(ctx context.Context, store *sessions.Store, resolution enforce.Resolution, notices tui.NoticeRenderer) error {
		err := orig(ctx, store, resolution, notices)
		if store != prior {
			childPath.Store(store.Path())
			appRef.Load().BeginShutdown()
			close(latched)
		}
		return err
	}
	t.Cleanup(func() { recordExecutionCapability = orig })

	var stepErr error
	defer runLiveApp(t, tcell.NewSimulationScreen("UTF-8"), func(app *tui.App) {
		appRef.Store(app)
		if !submitOnEventLoop(t, app, "/compact") {
			stepErr = errors.New("/compact was not accepted")
			return
		}
		select {
		case <-latched:
		case <-time.After(5 * time.Second):
			stepErr = errors.New("/compact never wrote the child capability")
		}
	})()

	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if stepErr != nil {
		t.Fatal(stepErr)
	}
	path, _ := childPath.Load().(string)
	deadline := time.Now().Add(5 * time.Second)
	for {
		left, _ := filepath.Glob(filepath.Join(launchTmp, sessionTempDirPrefix+"*"))
		if len(left) == 0 && !resumeLockHeld(t, path) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after exit: temp folders %v, child lock held %v; want none and released", left, resumeLockHeld(t, path))
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestCompactLease_EndWaitsForAnActivationInProgress(t *testing.T) {
	var discarded atomic.Int32
	child := preparedChild{
		release:  func() { discarded.Add(1) },
		rollback: func() error { discarded.Add(1); return nil },
	}
	lease := &compactLease{}
	if !lease.hold(child) {
		t.Fatal("hold refused before end")
	}
	started, finish, activated := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		lease.activate(func(preparedChild) {
			close(started)
			<-finish
		})
		close(activated)
	}()
	<-started
	ended := make(chan error, 1)
	go func() { ended <- lease.end() }()
	select {
	case <-ended:
		t.Fatal("end returned while activation was still running")
	case <-time.After(20 * time.Millisecond):
	}
	close(finish)
	<-activated
	if err := <-ended; err != nil {
		t.Fatalf("end error: %v", err)
	}
	if n := discarded.Load(); n != 0 {
		t.Fatalf("activated child was discarded (%d calls), want it left to the exit cleanup", n)
	}

	late := &compactLease{}
	late.hold(child)
	if err := late.end(); err != nil {
		t.Fatalf("end error: %v", err)
	}
	late.activate(func(preparedChild) { t.Fatal("activation ran after end discarded the child") })
	if n := discarded.Load(); n != 2 {
		t.Fatalf("discard calls after end = %d, want rollback and release", n)
	}
}

func TestCompactLease_HoldAfterEndReportsTheRollbackError(t *testing.T) {
	sentinel := errors.New("rollback failed")
	var reported []error
	orig := reportLateCompactDiscard
	reportLateCompactDiscard = func(err error) { reported = append(reported, err) }
	t.Cleanup(func() { reportLateCompactDiscard = orig })

	var order []string
	child := preparedChild{
		rollback: func() error { order = append(order, "rollback"); return sentinel },
		release:  func() { order = append(order, "release") },
	}
	lease := &compactLease{}
	if err := lease.end(); err != nil {
		t.Fatalf("end error: %v", err)
	}
	if lease.hold(child) {
		t.Fatal("hold accepted a child after end")
	}
	lease.activate(func(preparedChild) { t.Fatal("activation ran for a child prepared after end") })
	if !slices.Equal(order, []string{"rollback", "release"}) {
		t.Fatalf("discard order = %v, want rollback then release", order)
	}
	if len(reported) != 1 || !errors.Is(reported[0], sentinel) {
		t.Fatalf("reported = %v, want the rollback error once", reported)
	}
}

func TestStartTUI_ForkAndCompactReuseTheLaunchCapabilityAndCleanUpTheirFolders(t *testing.T) {
	launchTmp := t.TempDir()
	t.Setenv("TMPDIR", launchTmp)
	resolution := injectedResolution
	resolution.SelfTestPassed = true
	calls := swapResolveExecutionCapability(t, resolution)
	result, prior, restore := midTurnSwitchResult(t, "/fork")
	defer restore()
	prior.Append(sessions.Message{ID: ids.NewV7(), Role: "user", Content: sessions.TextContent("plan the work"), Timestamp: testStart})
	mustFlush(t, prior)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
		return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{Completion: &openai.ChatCompletion{
				Choices: []openai.ChatCompletionChoice{{Message: openai.ChatCompletionMessage{Content: "the plan, summarized"}}},
			}}, nil
		}}
	})()
	folders := func() []string {
		left, _ := filepath.Glob(filepath.Join(launchTmp, sessionTempDirPrefix+"*"))
		return left
	}
	var seen []string
	var stepErr error
	defer swapRunApp(func(app *tui.App) error {
		seen = append(seen, folders()...)
		for _, command := range []string{"/fork", "/compact"} {
			before := app.ActiveStore()
			if !app.SubmitInput(command) || app.ActiveStore() == before {
				stepErr = fmt.Errorf("%s did not switch sessions; notice %q", command, app.NoticeText())
				return nil
			}
			now := folders()
			if len(now) != 1 || slices.Contains(seen, now[0]) {
				stepErr = fmt.Errorf("temp folders after %s = %v, want one new folder (seen %v)", command, now, seen)
				return nil
			}
			seen = append(seen, now[0])
		}
		return nil
	})()

	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if stepErr != nil {
		t.Fatal(stepErr)
	}
	if *calls != 1 {
		t.Fatalf("Resolve calls = %d, want 1 across /fork and /compact", *calls)
	}
	if len(seen) != 3 {
		t.Fatalf("temp folders seen = %v, want the launch folder and one per switch", seen)
	}
	if left := folders(); len(left) != 0 {
		t.Fatalf("temp folders left = %v, want none", left)
	}
}

func fixedRecorder(launch enforce.Resolution) *capabilityRecorder {
	return &capabilityRecorder{launch: launch}
}

var constrainedLaunch = enforce.Resolution{
	Capability:     enforce.Constrained,
	Legs:           []enforce.Leg{{Name: "test-write", Observed: "denied"}},
	SelfTestPassed: true,
}

var (
	constrainedCapability = events.ExecutionCapability{Capability: "constrained", Legs: []events.ExecutionCapabilityLeg{{Name: "test-write", Observed: "denied"}}}
	brokenCapability      = events.ExecutionCapability{Capability: "refused", Reason: "settings file is broken", Legs: []events.ExecutionCapabilityLeg{{Name: "test-write", Observed: "denied"}}}
)

const (
	sandboxOnLine       = "Sandbox: on — commands run with OS-enforced filesystem and process-access restrictions"
	sandboxOffLine      = "Sandbox: off — build mode runs commands outside the sandbox"
	brokenSandboxLine   = "Sandbox: unavailable (settings file is broken) — automatic command authorization is unavailable"
	injectedSandboxLine = "Sandbox: unavailable (test: injected refusal) — automatic command authorization is unavailable"
)

func TestStatusState_SandboxPillAndOverlayFollowCapabilityAndMode(t *testing.T) {
	broken := liveExecutionCapability(constrainedLaunch, true)
	for _, tc := range []struct {
		name       string
		resolution enforce.Resolution
		modeKey    string
		pill       string
		overlay    string
	}{
		{"passed plan", constrainedLaunch, "plan", "sandbox: on", sandboxOnLine},
		{"passed auto_edits", constrainedLaunch, "auto_edits", "sandbox: on", sandboxOnLine + "; fewer permission prompts"},
		{"passed build", constrainedLaunch, "build", "sandbox: off", sandboxOffLine},
		{"refused plan", injectedResolution, "plan", "sandbox: unavailable", injectedSandboxLine},
		{"refused auto_edits", injectedResolution, "auto_edits", "sandbox: unavailable", injectedSandboxLine},
		{"refused build", injectedResolution, "build", "sandbox: unavailable", injectedSandboxLine},
		{"broken plan", broken, "plan", "sandbox: unavailable", brokenSandboxLine},
		{"broken auto_edits", broken, "auto_edits", "sandbox: unavailable", brokenSandboxLine},
		{"broken build", broken, "build", "sandbox: unavailable", brokenSandboxLine},
		{"empty capability", enforce.Resolution{}, "plan", "sandbox: unavailable", "Sandbox: unavailable — automatic command authorization is unavailable"},
		{"unknown mode", constrainedLaunch, "turbo", "sandbox: unavailable", "Sandbox: unavailable — automatic command authorization is unavailable"},
	} {
		app := tui.New(nil)
		status := newStatusState(app, providerCache(t, t.TempDir()), selectedState(), &BootstrapResult{LaunchDir: "/launch"}, tc.resolution)
		app.SetStatusLineState(status)
		app.RefreshModeHint(tc.modeKey)
		if got := strings.TrimSpace(app.StatusLineText()); !strings.HasSuffix(got, tc.pill) {
			t.Errorf("%s: status line = %q, want it to end with %q", tc.name, got, tc.pill)
		}
		overlay := tui.RenderStatus(tui.BuildStatusSnapshot(status))
		if !strings.Contains(overlay, "\n"+tc.overlay+"\n") {
			t.Errorf("%s: overlay missing %q\n--- overlay ---\n%s", tc.name, tc.overlay, overlay)
		}
		if tc.pill == "sandbox: unavailable" && strings.Contains(overlay, "outside the sandbox") {
			t.Errorf("%s: unavailable overlay claims unconfined execution\n--- overlay ---\n%s", tc.name, overlay)
		}
	}
}

func TestStartTUI_SandboxPillFollowsModeSwitch(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	swapResolveExecutionCapability(t, constrainedLaunch)
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()
	result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: mkStore(t), Model: selectedState(), Mode: mode.NewActiveState(mode.Build, mode.SourceDefault)}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if got := strings.TrimSpace(ran.StatusLineText()); !strings.HasSuffix(got, "sandbox: off") {
		t.Fatalf("launch status line = %q, want the sandbox: off pill in build mode", got)
	}
	ran.RefreshModeHint(string(mode.AutoEdits))
	if got := strings.TrimSpace(ran.StatusLineText()); !strings.HasSuffix(got, "sandbox: on") {
		t.Fatalf("status line after switching to auto-edits = %q, want the sandbox: on pill", got)
	}
}

func settingsFileLaunch(t *testing.T) (*BootstrapResult, rereadFixture) {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	f := newRereadFixture(t)
	f.writeGlobal(t, "a")
	return &BootstrapResult{Home: f.home, LaunchDir: f.project, ProjectRoot: f.project, Session: mkStore(t), SettingsLayers: f.layers(t, true)}, f
}

func swapRecordedCapabilities(t *testing.T) <-chan enforce.Resolution {
	t.Helper()
	recorded := make(chan enforce.Resolution, 8)
	orig := recordExecutionCapability
	recordExecutionCapability = func(ctx context.Context, store *sessions.Store, resolution enforce.Resolution, notices tui.NoticeRenderer) error {
		err := orig(ctx, store, resolution, notices)
		recorded <- resolution
		return err
	}
	t.Cleanup(func() { recordExecutionCapability = orig })
	return recorded
}

func requireRecordedCapability(t *testing.T, recorded <-chan enforce.Resolution, want enforce.Capability) {
	t.Helper()
	select {
	case got := <-recorded:
		if got.Capability != want {
			t.Fatalf("recorded capability = %+v, want %s", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no %s capability was recorded within 5s", want)
	}
}

func waitForStatusLine(t *testing.T, app *tui.App, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var got string
		onEventLoop(t, app, func() { got = app.StatusLineText() })
		if strings.HasSuffix(strings.TrimSpace(got), want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("status line = %q, want it to end with %q", got, want)
		}
	}
}

func requireDiskCapabilities(t *testing.T, store *sessions.Store, want ...events.ExecutionCapability) {
	t.Helper()
	caps := decodeDiskEvents[events.ExecutionCapability](t, readSessionFile(t, store.Path()), events.KindExecutionCapability)
	if !reflect.DeepEqual(caps, want) {
		t.Fatalf("execution_capability on disk = %+v, want %+v", caps, want)
	}
}

func TestStartTUI_BrokenSettingsFileRefusesAndRecordsUntilFixed(t *testing.T) {
	swapResolveExecutionCapability(t, constrainedLaunch)
	result, f := settingsFileLaunch(t)
	recorded := swapRecordedCapabilities(t)

	defer runLiveApp(t, tcell.NewSimulationScreen("UTF-8"), func(app *tui.App) {
		requireRecordedCapability(t, recorded, enforce.Constrained)
		waitForStatusLine(t, app, "sandbox: off")

		rewriteSettings(t, f.global, "blocked_paths: [\n")
		var overlay string
		onEventLoop(t, app, func() {
			app.SubmitInput("/status")
			overlay = app.StatusText()
		})
		if !strings.Contains(overlay, "\n"+brokenSandboxLine+"\n") {
			t.Fatalf("/status while broken is missing the refusal\n--- overlay ---\n%s", overlay)
		}
		requireRecordedCapability(t, recorded, enforce.Refused)
		waitForStatusLine(t, app, "sandbox: unavailable")
		requireDiskCapabilities(t, result.Session, constrainedCapability, brokenCapability)

		f.editGlobal(t, "a")
		onEventLoop(t, app, func() { app.SubmitInput("/blocked") })
		requireRecordedCapability(t, recorded, enforce.Constrained)
		waitForStatusLine(t, app, "sandbox: off")
	})()

	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	requireDiskCapabilities(t, result.Session, constrainedCapability, brokenCapability, constrainedCapability)
}

func TestStartTUI_RefusedLaunchKeepsItsReasonWhileTheSettingsFileIsBroken(t *testing.T) {
	swapResolveExecutionCapability(t, injectedResolution)
	result, f := settingsFileLaunch(t)
	var stepErr error
	defer swapRunApp(func(app *tui.App) error {
		for _, edit := range []func(){
			func() { rewriteSettings(t, f.global, "blocked_paths: [\n") },
			func() { f.editGlobal(t, "a") },
		} {
			edit()
			app.SubmitInput("/blocked")
			app.SubmitInput("/status")
			if got := app.StatusLineText(); !strings.HasSuffix(strings.TrimSpace(got), "sandbox: unavailable") {
				stepErr = fmt.Errorf("status line = %q, want the sandbox: unavailable pill", got)
				return nil
			}
			if overlay := app.StatusText(); !strings.Contains(overlay, "\n"+injectedSandboxLine+"\n") {
				stepErr = fmt.Errorf("/status lost the launch reason\n--- overlay ---\n%s", overlay)
				return nil
			}
		}
		return nil
	})()

	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if stepErr != nil {
		t.Fatal(stepErr)
	}
	requireDiskCapabilities(t, result.Session, injectedCapability)
}

func TestStartTUI_SettingsFileBrokenBeforeTheFirstRecordStartsRefused(t *testing.T) {
	swapResolveExecutionCapability(t, constrainedLaunch)
	result, f := settingsFileLaunch(t)
	rewriteSettings(t, f.global, "blocked_paths: [\n")

	app, restore := startCaptured(t, context.Background(), result, io.Discard)
	defer restore()

	requireDiskCapabilities(t, result.Session, brokenCapability)
	if got := app.StatusLineText(); !strings.HasSuffix(strings.TrimSpace(got), "sandbox: unavailable") {
		t.Fatalf("status line = %q, want the sandbox: unavailable pill", got)
	}
	app.SubmitInput("/status")
	if overlay := app.StatusText(); !strings.Contains(overlay, "\n"+brokenSandboxLine+"\n") {
		t.Fatalf("/status is missing the refusal\n--- overlay ---\n%s", overlay)
	}
}

func TestStartTUI_SessionStaysOwnedUntilTheDeliveryWorkerRecords(t *testing.T) {
	runFailed := errors.New("test: run failed")
	for _, runErr := range []error{nil, runFailed} {
		t.Run(fmt.Sprint(runErr), func(t *testing.T) {
			swapResolveExecutionCapability(t, constrainedLaunch)
			result, f := settingsFileLaunch(t)
			var released, releasedBeforeWrite atomic.Bool
			result.ResumeLockRelease = func() { released.Store(true) }
			liveBlocked := captureLiveBlocked(t)
			hold := newRecordHold(t)
			orig := recordExecutionCapability
			recordExecutionCapability = func(ctx context.Context, store *sessions.Store, resolution enforce.Resolution, notices tui.NoticeRenderer) error {
				if resolution.Capability == enforce.Refused {
					hold.block()
					releasedBeforeWrite.Store(released.Load())
				}
				return orig(ctx, store, resolution, notices)
			}
			t.Cleanup(func() { recordExecutionCapability = orig })

			defer swapRunApp(func(app *tui.App) error {
				app.SetScreenFactoryForTest(func() (tcell.Screen, error) { return tcell.NewSimulationScreen("UTF-8"), nil })
				errc := make(chan error, 1)
				go func() { errc <- app.Run() }()
				onEventLoop(t, app, func() {})
				setSettingsBroken(t, f, true)
				refreshWithin(t, liveBlocked())
				hold.waitEntered(t)
				time.AfterFunc(100*time.Millisecond, hold.open)
				app.Stop()
				if err := <-errc; err != nil {
					return err
				}
				return runErr
			})()

			if err := StartTUI(context.Background(), result, io.Discard); !errors.Is(err, runErr) {
				t.Fatalf("StartTUI error = %v, want %v", err, runErr)
			}
			if releasedBeforeWrite.Load() {
				t.Fatal("the session lock was released before the delivery worker recorded the transition")
			}
			requireDiskCapabilities(t, result.Session, constrainedCapability, brokenCapability)
			if !released.Load() {
				t.Fatal("the session lock was not released after StartTUI returned")
			}
		})
	}
}

func liveSettingsRecorder(t *testing.T, launch enforce.Resolution) (*capabilityRecorder, rereadFixture) {
	t.Helper()
	f := newRereadFixture(t)
	f.writeGlobal(t, "a")
	return &capabilityRecorder{launch: launch, blocked: f.blocked(t, true)}, f
}

func setSettingsBroken(t *testing.T, f rereadFixture, broken bool) {
	t.Helper()
	if broken {
		rewriteSettings(t, f.global, "blocked_paths: [\n")
		return
	}
	f.editGlobal(t, "a")
}

func capabilityFor(broken bool) events.ExecutionCapability {
	if broken {
		return brokenCapability
	}
	return constrainedCapability
}

func refreshWithin(t *testing.T, blocked *permissions.BlockedPaths) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		blocked.Current()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a blocked-list refresh did not finish within 5s")
	}
}

type storedCapability struct {
	store      *sessions.Store
	resolution enforce.Resolution
}

func watchCapabilityRecords(t *testing.T, after func(store *sessions.Store)) <-chan storedCapability {
	t.Helper()
	records := make(chan storedCapability, 32)
	orig := recordExecutionCapability
	recordExecutionCapability = func(ctx context.Context, store *sessions.Store, resolution enforce.Resolution, notices tui.NoticeRenderer) error {
		err := orig(ctx, store, resolution, notices)
		records <- storedCapability{store: store, resolution: resolution}
		after(store)
		return err
	}
	t.Cleanup(func() { recordExecutionCapability = orig })
	return records
}

func nextCapabilityRecord(t *testing.T, records <-chan storedCapability, match func(storedCapability) bool) storedCapability {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case got := <-records:
			if match(got) {
				return got
			}
		case <-timeout:
			t.Fatal("no matching execution_capability record within 5s")
		}
	}
}

type recordHold struct {
	held    atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func newRecordHold(t *testing.T) *recordHold {
	h := &recordHold{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(h.open)
	return h
}

func (h *recordHold) block() {
	if !h.held.CompareAndSwap(false, true) {
		return
	}
	close(h.entered)
	select {
	case <-h.release:
	case <-time.After(10 * time.Second):
	}
}

func (h *recordHold) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-h.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no execution_capability record reached the hold within 5s")
	}
}

func (h *recordHold) open() {
	select {
	case <-h.release:
	default:
		close(h.release)
	}
}

func waitForMutexWaitIn(t *testing.T, function string) {
	t.Helper()
	waiting := regexp.MustCompile(`sync\.\(\*Mutex\)\.Lock\(.*\n[^\n]*\n[^\n]*\(\*capabilityRecorder\)\.` + function + `\(`)
	buf := make([]byte, 1<<20)
	deadline := time.Now().Add(5 * time.Second)
	for !waiting.Match(buf[:runtime.Stack(buf, true)]) {
		if time.Now().After(deadline) {
			t.Fatalf("no goroutine waited on the recording mutex in capabilityRecorder.%s within 5s", function)
		}
		time.Sleep(time.Millisecond)
	}
}

func runLiveDelivery(t *testing.T, app *tui.App, recorder *capabilityRecorder) {
	t.Helper()
	orig := deliverBlockedNotice
	deliverBlockedNotice = func(*tui.App, string) {}
	stop := queueBlockedNotices(app, recorder.blocked, func(degraded bool, notices tui.NoticeRenderer) {
		recorder.deliver(context.Background(), app, degraded, notices)
	})
	t.Cleanup(func() {
		stop()
		deliverBlockedNotice = orig
	})
}

func receiveWithin[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not finish within 5s", what)
		var zero T
		return zero
	}
}

func captureLiveBlocked(t *testing.T) func() *permissions.BlockedPaths {
	t.Helper()
	var blocked atomic.Pointer[permissions.BlockedPaths]
	production := newSettingsDeps
	newSettingsDeps = func(app *tui.App, cache *config.Cache, active *model.ActiveState, a *productionAuthorizer) tui.SettingsDeps {
		blocked.Store(a.blocked)
		return production(app, cache, active, a)
	}
	t.Cleanup(func() { newSettingsDeps = production })
	return blocked.Load
}

func TestStartTUI_DeliveryWaitingOnTheClearSwitchRecordsIntoTheFreshSession(t *testing.T) {
	swapResolveExecutionCapability(t, constrainedLaunch)
	result, f := settingsFileLaunch(t)
	liveBlocked := captureLiveBlocked(t)
	hold := newRecordHold(t)
	records := watchCapabilityRecords(t, func(store *sessions.Store) {
		if store != result.Session {
			hold.block()
		}
	})
	var fresh *sessions.Store

	defer runLiveApp(t, tcell.NewSimulationScreen("UTF-8"), func(app *tui.App) {
		nextCapabilityRecord(t, records, func(r storedCapability) bool { return r.store == result.Session })
		go app.RunOnEventLoopForTest(func() { app.SubmitInput("/clear") })
		hold.waitEntered(t)
		fresh = nextCapabilityRecord(t, records, func(r storedCapability) bool { return r.store != result.Session }).store
		setSettingsBroken(t, f, true)
		refreshWithin(t, liveBlocked())
		waitForMutexWaitIn(t, "deliver")
		hold.open()

		delivered := nextCapabilityRecord(t, records, func(storedCapability) bool { return true })
		if delivered.store != fresh || delivered.resolution.Capability != enforce.Refused {
			t.Fatalf("delivery recorded %s into %p, want refused into the fresh session %p", delivered.resolution.Capability, delivered.store, fresh)
		}
		onEventLoop(t, app, func() {
			if app.ActiveStore() != fresh {
				t.Errorf("active store = %p, want the fresh session %p", app.ActiveStore(), fresh)
			}
		})
	})()

	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	requireDiskCapabilities(t, fresh, constrainedCapability, brokenCapability)
}

func TestStartTUI_ClearSwitchRefreshesBeforeWaitingOnTheRecordingMutex(t *testing.T) {
	swapResolveExecutionCapability(t, constrainedLaunch)
	result, f := settingsFileLaunch(t)
	liveBlocked := captureLiveBlocked(t)
	hold := newRecordHold(t)
	var armed atomic.Bool
	records := watchCapabilityRecords(t, func(store *sessions.Store) {
		if armed.Load() && store == result.Session {
			hold.block()
		}
	})
	var fresh *sessions.Store

	defer runLiveApp(t, tcell.NewSimulationScreen("UTF-8"), func(app *tui.App) {
		nextCapabilityRecord(t, records, func(r storedCapability) bool { return r.store == result.Session })
		blocked := liveBlocked()
		armed.Store(true)
		setSettingsBroken(t, f, true)
		refreshWithin(t, blocked)
		hold.waitEntered(t)

		setSettingsBroken(t, f, false)
		go app.RunOnEventLoopForTest(func() { app.SubmitInput("/clear") })
		waitForMutexWaitIn(t, "activate")
		if blocked.Degraded() {
			t.Error("the switch waits on the recording mutex before refreshing the repaired settings file")
		}
		refreshWithin(t, blocked)
		hold.open()

		fresh = nextCapabilityRecord(t, records, func(r storedCapability) bool { return r.store != result.Session }).store
		onEventLoop(t, app, func() {
			if app.ActiveStore() != fresh {
				t.Errorf("active store = %p, want the fresh session %p", app.ActiveStore(), fresh)
			}
		})
	})()

	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	requireDiskCapabilities(t, result.Session, constrainedCapability, brokenCapability)
	requireDiskCapabilities(t, fresh, constrainedCapability, constrainedCapability)
}

const childOriginRecordID = "01890000-0000-7000-8000-0000000f0001"

// childStore is a written child session (metadata.forked_from present) carrying the derived title
// a fork or compaction gives it; records[0] must carry childOriginRecordID as its parent_id.
func childStore(t *testing.T, title string, records ...sessions.Record) *sessions.Store {
	t.Helper()
	store := sessions.New(filepath.Join(t.TempDir(), "child.json"), &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            "01890000-0000-7000-8000-0000000f0002",
			Folder:        "/proj",
			Title:         title,
			TitleSource:   sessions.TitleSourceGenerated,
			StartedAt:     testStart,
			UpdatedAt:     testStart,
			SchemaVersion: sessions.CurrentSchemaVersion,
			ForkedFrom:    &sessions.ForkOrigin{SessionID: "01890000-0000-7000-8000-0000000f0003", RecordID: childOriginRecordID},
		},
		Records: records,
	})
	mustFlush(t, store)
	return store
}

func TestFirstTurnTitleInputs_Eligibility(t *testing.T) {
	user := func(text string) sessions.Message {
		return sessions.Message{Role: "user", Content: sessions.TextContent(text), Timestamp: testStart}
	}
	answer := sessions.Message{Role: "assistant", Content: sessions.TextContent("a plan"), Timestamp: testStart}
	plain := func(t *testing.T, records ...sessions.Record) *sessions.Store {
		store := mkStore(t)
		for _, r := range records {
			store.Append(r)
		}
		return store
	}
	forkedUser := user("plan the work")
	forkedUser.ParentID = childOriginRecordID

	cases := []struct {
		name  string
		store func(t *testing.T) *sessions.Store
		ok    bool
	}{
		{"one plain-text user record", func(t *testing.T) *sessions.Store { return plain(t, user("help me refactor login"), answer) }, true},
		{"one plain-text user record under a generated fallback title", func(t *testing.T) *sessions.Store {
			store := plain(t, user("help me refactor login"), answer)
			mustFlush(t, store)
			if _, _, err := store.FlushGeneratedTitle(context.Background(), "help me refactor login"); err != nil {
				t.Fatalf("seed fallback title: %v", err)
			}
			return store
		}, true},
		{"whitespace-only text", func(t *testing.T) *sessions.Store { return plain(t, user(" \t\n"), answer) }, false},
		{"content parts", func(t *testing.T) *sessions.Store {
			parts := []sessions.ContentPart{{Type: "text", Raw: []byte(`{"type":"text","text":"look"}`)}}
			return plain(t, sessions.Message{Role: "user", Content: sessions.PartsContent(parts), Timestamp: testStart}, answer)
		}, false},
		{"multiple user records", func(t *testing.T) *sessions.Store {
			return plain(t, user("help me refactor login"), answer, user("and add tests"), answer)
		}, false},
		{"fork child", func(t *testing.T) *sessions.Store {
			return childStore(t, "Refactor plan (forked)", forkedUser, answer)
		}, false},
		{"summary-only compact child with one new user record", func(t *testing.T) *sessions.Store {
			return childStore(t, "Refactor plan (compacted)",
				sessions.Compaction{ID: "01890000-0000-7000-8000-0000000f0004", Summary: "the plan, summarized", Provider: "openai", ModelID: "gpt-5.5", Timestamp: testStart, ParentID: childOriginRecordID},
				user("now add tests"), answer)
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			firstUser, firstAssistant, ok := firstTurnTitleInputs(tc.store(t))
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && (firstUser != "help me refactor login" || firstAssistant != "a plan") {
				t.Fatalf("inputs = (%q, %q), want the opening exchange", firstUser, firstAssistant)
			}
		})
	}
}

func TestStartTUI_BlockedAddWithoutAnAdmittedProjectWritesGlobal(t *testing.T) {
	for _, withRoot := range []bool{false, true} {
		t.Run(fmt.Sprintf("root=%v", withRoot), func(t *testing.T) {
			home := t.TempDir()
			root := mustCanonical(t, t.TempDir())
			result := &BootstrapResult{
				Home: home, LaunchDir: root, Session: mkStore(t),
				TrustDecision: trust.Decision{Reason: trust.ReasonNoRecord, Root: root},
			}
			if withRoot {
				result.ProjectRoot = root
			}
			result.SettingsLayers = settingsLayerSnapshots(home, result.ProjectRoot, map[string]any{}, false, ConfigComposition{})
			app, restore := startCaptured(t, context.Background(), result, io.Discard)
			defer restore()

			if !app.SubmitInput("/blocked add /etc/secrets") {
				t.Fatal("/blocked add rejected")
			}
			if app.ChooseBlockedDestinationForTest(tui.BlockedGlobal) {
				t.Fatal("destination page opened without an admitted project root")
			}
			global := SettingsPath(home)
			if got, want := app.NoticeText(), "/etc/secrets is now blocked (added to "+global+")"; got != want {
				t.Fatalf("notice = %q, want %q", got, want)
			}
			if got := blockedItemsIn(t, global); !slices.Equal(got, []string{"/etc/secrets"}) {
				t.Fatalf("global blocked_paths = %q, want [/etc/secrets]", got)
			}
			requireAbsent(t, projectSettingsPath(root))
			requireAbsent(t, config.LocalSettingsPath(root))
		})
	}
}

func TestStartTUI_BlockedAddInAnAdmittedProjectWithNoSettingsFilesOffersProjectDestinations(t *testing.T) {
	home := t.TempDir()
	root := mustCanonical(t, t.TempDir())
	liveBlocked := captureLiveBlocked(t)
	app, _ := startRunningOnScreen(t, &BootstrapResult{
		Home: home, LaunchDir: root, ProjectRoot: root, Session: mkStore(t),
		TrustDecision:  trust.Decision{Trusted: true, Reason: trust.ReasonNothingCovered, Root: root},
		Config:         map[string]any{"discovery": map[string]any{"boundary": "project-root"}},
		SettingsLayers: settingsLayerSnapshots(home, root, map[string]any{}, true, ConfigComposition{}),
	})
	shared := projectSettingsPath(root)

	var opened bool
	var notice string
	onEventLoop(t, app, func() {
		app.SubmitInput("/blocked add /etc/secrets")
		opened = app.ChooseBlockedDestinationForTest(tui.BlockedProjectShared)
		notice = app.NoticeText()
	})
	if !opened {
		t.Fatal("no destination page for an admitted project with absent settings files")
	}
	if want := "/etc/secrets is now blocked (added to " + shared + ")\n" + tui.RenderProjectRootMarkerNotice(permissions.BoundPromptFact(shared)); notice != want {
		t.Fatalf("notice = %q, want %q", notice, want)
	}
	if got := blockedItemsIn(t, shared); !slices.Equal(got, []string{"/etc/secrets"}) {
		t.Fatalf("shared blocked_paths = %q, want [/etc/secrets]", got)
	}
	requireAbsent(t, config.LocalSettingsPath(root))
	if entry, ok := liveBlocked().Current().Blocking("/etc/secrets"); !ok || entry.Source != shared {
		t.Fatalf("live Blocking = %+v, %v; want it enforced from %s", entry, ok, shared)
	}
	var overlay string
	onEventLoop(t, app, func() {
		app.SubmitInput("/blocked")
		overlay = app.BlockedOverlayText()
	})
	if want := "/etc/secrets  (" + shared + ")"; !strings.Contains(overlay, want) {
		t.Fatalf("/blocked =\n%s\nwant the row %q", overlay, want)
	}
}

func swapLaunchStdio(t *testing.T, input string, terminal bool) (*os.File, func() string) {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "stdin")
	if err := os.WriteFile(in, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	stdin, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	prevStdin, prevStderr, prevTerminal := os.Stdin, os.Stderr, stdinIsTerminal
	os.Stdin, os.Stderr, stdinIsTerminal = stdin, stderr, func(io.Reader) bool { return terminal }
	t.Cleanup(func() {
		os.Stdin, os.Stderr, stdinIsTerminal = prevStdin, prevStderr, prevTerminal
		_ = stdin.Close()
		_ = stderr.Close()
	})
	return stdin, func() string {
		data, err := os.ReadFile(stderr.Name())
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
}

func requireStdinUnread(t *testing.T, stdin *os.File) {
	t.Helper()
	if offset, err := stdin.Seek(0, io.SeekCurrent); err != nil || offset != 0 {
		t.Fatalf("stdin offset = %d (%v), want nothing read", offset, err)
	}
}

func settingsBytes(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func savedGlobalConfig(t *testing.T, home string) map[string]any {
	t.Helper()
	global, err := defaultLoadGlobalSettings(home)
	if err != nil {
		t.Fatalf("defaultLoadGlobalSettings: %v", err)
	}
	composition, err := defaultComposeConfig(global, "")
	if err != nil {
		t.Fatalf("defaultComposeConfig: %v", err)
	}
	return composition.Config
}

func confinedLaunchResult(t *testing.T, home, project string, composed map[string]any) *BootstrapResult {
	t.Helper()
	return &BootstrapResult{Home: home, LaunchDir: project, ProjectRoot: project, Session: mkStore(t), Config: composed,
		ConfigLayerPaths: []string{SettingsPath(home)}, Mode: mode.NewActiveState(mode.AutoEdits, mode.SourceDefault)}
}

func runConfinedLaunch(t *testing.T, result *BootstrapResult, inspect func(*confinement)) {
	t.Helper()
	var conf *confinement
	build := newResumeDeps
	defer swapNewResumeDeps(func(c context.Context, app *tui.App, r *BootstrapResult, lock *resumeLockHolder, cache *config.Cache, active *model.ActiveState, recorder *capabilityRecorder, launched *confinement) tui.ResumeDeps {
		conf = launched
		return build(c, app, r, lock, cache, active, recorder, launched)
	})()
	defer swapRunApp(func(*tui.App) error {
		if conf == nil {
			return errors.New("the event loop ran before the launch confinement was built")
		}
		inspect(conf)
		return nil
	})()
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
}

func TestStartTUI_ConstrainedLaunchAsksNoTempQuestionAndGrantsOnlyThePrivateFolder(t *testing.T) {
	swapResolveExecutionCapability(t, constrainedLaunch)
	for _, tc := range []struct {
		name, saved string
	}{
		{"absent", ""},
		{"saved allow", "confinement:\n  shared_temp_folders: allow\n"},
		{"saved deny", "confinement:\n  shared_temp_folders: deny\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, project, launchTmp := canonicalTempDir(t), canonicalTempDir(t), canonicalTempDir(t)
			t.Setenv("TMPDIR", launchTmp)
			composed := map[string]any{}
			if tc.saved != "" {
				writeGlobalSettings(t, home, tc.saved, 0o600)
				composed = savedGlobalConfig(t, home)
			}
			stdin, stderr := swapLaunchStdio(t, "yes\n", true)

			inspected := false
			runConfinedLaunch(t, confinedLaunchResult(t, home, project, composed), func(conf *confinement) {
				requirePrivateTempOnly(t, conf, project, launchTmp)
				inspected = true
			})

			if !inspected {
				t.Fatal("the launch confinement was never inspected")
			}
			if got := stderr(); strings.Contains(got, "Allow the shared temp folders?") {
				t.Fatalf("stderr = %q, want no shared temp question", got)
			}
			requireStdinUnread(t, stdin)
			if got := settingsBytes(t, SettingsPath(home)); got != tc.saved {
				t.Fatalf("global settings = %q, want %q unchanged", got, tc.saved)
			}
		})
	}
}
