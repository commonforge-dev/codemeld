// Integration tests for TR-TUI-5/6/7: /clear+/new session switch, the four
// /exit forms' clean-shutdown path, and /effort+/model validation/persistence,
// all driven through the production submit path StartTUI assembles.
//
// This suite's prep names internal/integration/tui_commands_test.go as the target file,
// but its Architecture Review and Research both direct: when the wiring exposes only
// package-private driving hooks, use the owning package's test seam rather than
// weakening production visibility for the test. As built, the only way to drive
// the real production wiring (StartTUI's registry-backed submit adapter, the
// production /clear/effort/model/exit deps, the command-event flush hook, and the
// exit-code seam) is via internal/bootstrap's package-private runApp and
// exitProcess seams and the unexported new*Deps builders. So these black-box TUI
// integration tests live in package bootstrap, reusing the swapRunApp/SubmitInput
// driver established by starttui_test.go, instead of an internal/integration
// package that could only re-implement the deps as fakes.
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/trust"
	"codemeld.dev/codemeld/internal/tui"
)

// startCaptured runs StartTUI with the runApp seam swapped so the real event
// loop never blocks, returning the *tui.App StartTUI built and installed its
// production submit adapter on. The returned restore closure must be deferred.
// SubmitInput on the returned app exercises the same accept/clear contract Enter
// drives, against the genuine production registry + submit adapter.
func startCaptured(t *testing.T, ctx context.Context, result *BootstrapResult, stdout io.Writer) (*tui.App, func()) {
	t.Helper()
	var app *tui.App
	restore := swapRunApp(func(a *tui.App) error { app = a; return nil })
	if err := StartTUI(ctx, result, stdout); err != nil {
		restore()
		t.Fatalf("StartTUI error: %v", err)
	}
	if app == nil {
		restore()
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	return app, restore
}

// readSessionFile reads path back from disk and parses it through the real
// sessions codec, so an assertion sees the flushed/durable record stream rather
// than the in-memory store object (TR-TUI-5/6 Done-when 2).
func readSessionFile(t *testing.T, path string) *sessions.Session {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read session file %s: %v", path, err)
	}
	sess, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal session file %s: %v", path, err)
	}
	return sess
}

// diskSlashCommands returns the slash_command payloads in a disk-read record
// stream, decoded through the real event payload type.
func diskSlashCommands(t *testing.T, sess *sessions.Session) []events.SlashCommand {
	t.Helper()
	return decodeDiskEvents[events.SlashCommand](t, sess, events.KindSlashCommand)
}

// diskStreamInterrupted returns the stream_interrupted payloads in a disk-read
// record stream, decoded through the real event payload type.
func diskStreamInterrupted(t *testing.T, sess *sessions.Session) []events.StreamInterrupted {
	t.Helper()
	return decodeDiskEvents[events.StreamInterrupted](t, sess, events.KindStreamInterrupted)
}

// diskModelRecoveryFailed returns the model_recovery_failed payloads in a disk-read
// record stream, decoded through the real event payload type.
func diskModelRecoveryFailed(t *testing.T, sess *sessions.Session) []events.ModelRecoveryFailed {
	t.Helper()
	return decodeDiskEvents[events.ModelRecoveryFailed](t, sess, events.KindModelRecoveryFailed)
}

// diskHasUserMessage reports whether the disk-read record stream contains a user
// message with the given text content.
func diskHasUserMessage(sess *sessions.Session, text string) bool {
	for _, r := range sess.Records {
		if m, ok := r.(sessions.Message); ok && m.Role == "user" && !m.Content.IsList() && m.Content.Text() == text {
			return true
		}
	}
	return false
}

// diskEventKinds returns the event kinds, in order, of a disk-read record stream.
func diskEventKinds(sess *sessions.Session) []string {
	var out []string
	for _, r := range sess.Records {
		if ev, ok := r.(sessions.Event); ok {
			out = append(out, ev.Kind)
		}
	}
	return out
}

// firstLaunchBeganSource decodes the first launch_began payload's source, or ""
// when the stream has none.
func firstLaunchBeganSource(t *testing.T, sess *sessions.Session) string {
	t.Helper()
	for _, r := range sess.Records {
		ev, ok := r.(sessions.Event)
		if !ok || ev.Kind != events.KindLaunchBegan {
			continue
		}
		var p events.LaunchBegan
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("decode launch_began from disk: %v", err)
		}
		return p.Source
	}
	return ""
}

// modelTestConfig is a composed-config map exposing the openai provider
// credentials and project-root discovery boundary for the /model and /effort
// tests. Callers pair this map with a seeded discovered-model store
// (seedOpenAIDiscovered) so the configured selectable IDs derive from the
// store rather than a settings models list.
func modelTestConfig() map[string]any {
	return map[string]any{
		"discovery": map[string]any{"boundary": "project-root"},
		"provider": map[string]any{
			"openai": map[string]any{
				"base_url": "https://api.openai.com/v1",
				"api_key":  "sk-test",
			},
		},
	}
}

// TestTRTUI5_ClearAndNew_SwitchSessionDurablyOnDisk covers TR-TUI-5 for both the
// /clear and /new spellings: a plain prompt is run, then the alias ends the
// session and opens a fresh one. It reads the prior session JSON back from disk
// (Done-when 2) and asserts the prior file holds the pre-switch user message and
// the canonical slash_command{clear, success} (never the typed /new), that the
// fresh session has a new, valid UUIDv7 distinct from the prior id, and that the
// fresh session begins on disk with launch_began{source:"fresh"}.
func TestTRTUI5_ClearAndNew_SwitchSessionDurablyOnDisk(t *testing.T) {
	for _, alias := range []string{"/clear", "/new"} {
		t.Run(alias, func(t *testing.T) {
			ctx := context.Background()
			prior := mkStore(t)
			result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: prior}
			app, restore := startCaptured(t, ctx, result, io.Discard)
			defer restore()

			if !app.SubmitInput("hello there") {
				t.Fatal("plain prompt rejected; production prompt entrypoint not wired")
			}
			if !app.SubmitInput(alias) {
				t.Fatalf("%s rejected; it should switch sessions and be accepted", alias)
			}

			fresh := app.ActiveStore()
			if fresh == prior {
				t.Fatalf("%s did not swap the active session", alias)
			}
			priorID, freshID := prior.SessionID(), fresh.SessionID()
			if priorID == freshID {
				t.Fatalf("fresh session reused the prior id %q", freshID)
			}
			if !ids.IsValidV7(freshID) {
				t.Fatalf("fresh session id %q is not a valid UUIDv7", freshID)
			}

			// Prior session, read back from disk: the pre-switch prompt and the
			// canonical slash_command{clear} must both be flushed before the new
			// session opened, not just held in memory.
			priorDisk := readSessionFile(t, prior.Path())
			if !diskHasUserMessage(priorDisk, "hello there") {
				t.Fatalf("prior session file %s missing the pre-switch user message", prior.Path())
			}
			cmds := diskSlashCommands(t, priorDisk)
			if len(cmds) != 1 || cmds[0].Name != "clear" || cmds[0].Outcome != "success" {
				t.Fatalf("prior disk slash_command = %+v, want one {clear, success} (canonical, not %q)", cmds, alias)
			}
			if len(cmds[0].Args) != 0 {
				t.Fatalf("clear slash_command args = %v, want empty", cmds[0].Args)
			}

			// Fresh session, read back from disk: it must begin with the
			// launch_began{source:"fresh"} the production SessionSwapper appended.
			freshDisk := readSessionFile(t, fresh.Path())
			if got := firstLaunchBeganSource(t, freshDisk); got != "fresh" {
				t.Fatalf("fresh session first launch_began source = %q, want %q", got, "fresh")
			}
			if kinds := diskEventKinds(freshDisk); len(kinds) == 0 || kinds[0] != events.KindLaunchBegan {
				t.Fatalf("fresh session disk kinds = %v, want to begin with launch_began", kinds)
			}

			// The prior store was sealed by the swap, so a late append is dropped
			// — the in-memory stream stops growing.
			before := len(prior.Records())
			prior.Append(sessions.Message{ID: freshID, Role: "user", Content: sessions.TextContent("late"), Timestamp: testStart})
			if len(prior.Records()) != before {
				t.Fatal("prior store still accepted an append after the session switch")
			}
		})
	}
}

// TestTRTUI6_ExitForms_CleanShutdownDurableExitZeroHint covers TR-TUI-6 for all
// four spellings (/exit, /quit, bare exit, bare quit): each runs the same
// clean-shutdown path, records the canonical slash_command{exit, success} which
// is durable on disk after the flush, exits 0, and prints the
// resume hint to stdout. The os.Exit seam is swapped so the path can be observed
// without terminating the test binary.
func TestTRTUI6_ExitForms_CleanShutdownDurableExitZeroHint(t *testing.T) {
	for _, form := range []string{"/exit", "/quit", "exit", "quit"} {
		t.Run(form, func(t *testing.T) {
			ctx := context.Background()
			store := mkStore(t)
			result := &BootstrapResult{Home: t.TempDir(), LaunchDir: "/launch", Session: store}

			var stdout bytes.Buffer
			code := -1
			defer swapExitProcess(func(c int) { code = c })()

			app, restore := startCaptured(t, ctx, result, &stdout)
			defer restore()

			if !app.SubmitInput(form) {
				t.Fatalf("%q should run the clean-shutdown path and be accepted", form)
			}
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (req 445 clean exit)", code)
			}
			if want := resumeHint(store.SessionID()); strings.TrimSpace(stdout.String()) != want {
				t.Fatalf("stdout = %q, want resume hint %q", stdout.String(), want)
			}

			// The session must be durable on disk before the process exits:
			// the slash_command{exit} appended before the flush is present
			// in the file, under the canonical name for every spelling.
			disk := readSessionFile(t, store.Path())
			cmds := diskSlashCommands(t, disk)
			if len(cmds) != 1 || cmds[0].Name != "exit" || cmds[0].Outcome != "success" {
				t.Fatalf("disk slash_command = %+v, want one {exit, success} for %q", cmds, form)
			}
			if len(cmds[0].Args) != 0 {
				t.Fatalf("exit slash_command args = %v, want empty", cmds[0].Args)
			}
		})
	}
}

// TestF600_PermissionsCommand_OpensOverlayWithComposedCacheGrants covers the
// production wiring: submitting /settings through StartTUI's real submit adapter must
// open the permissions overlay listing the grants the production lister sources from the
// config cache StartTUI composed — not just record the slash command. It fails if
// StartTUI drops the "settings" handler replacement (dispatch would fall to the
// builtin placeholder and never open the overlay) or if the lister stops reading the
// composed cache's grants.
func TestF600_PermissionsCommand_OpensOverlayWithComposedCacheGrants(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	home := t.TempDir()
	cfg := map[string]any{
		"permissions": []any{
			map[string]any{"kind": "direct", "subject": "ls", "path_scope": "*", "grant_kind": "global"},
		},
	}
	result := &BootstrapResult{
		Home:           home,
		LaunchDir:      "/launch",
		Config:         cfg,
		SettingsLayers: []securitystate.LayerSnapshot{{Kind: securitystate.LayerGlobal, Path: SettingsPath(home), Present: true, Raw: cfg}},
		Session:        store,
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("/settings") {
		t.Fatal("/settings rejected; the production registry did not bind the handler")
	}

	overlay := app.SettingsOverlayText()
	if overlay == "" {
		t.Fatal("/settings did not open the overlay; StartTUI's production replacement of the placeholder handler is missing")
	}
	if !strings.Contains(overlay, "run ls") {
		t.Fatalf("permissions overlay = %q, want it to list the composed cache grant (\"run ls ...\")", overlay)
	}
}

func TestOpenRouterCommand_OpensSettingsOnOpenRouterTabThroughProductionWiring(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	cfg := map[string]any{
		"permissions": []any{
			map[string]any{"kind": "direct", "subject": "ls", "path_scope": "*", "grant_kind": "global"},
		},
	}
	result := &BootstrapResult{
		Home:           home,
		LaunchDir:      "/launch",
		Config:         cfg,
		SettingsLayers: []securitystate.LayerSnapshot{{Kind: securitystate.LayerGlobal, Path: SettingsPath(home), Present: true, Raw: cfg}},
		Session:        mkStore(t),
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("/openrouter") {
		t.Fatalf("/openrouter rejected; notice %q", app.NoticeText())
	}
	if app.SettingsOverlayText() == "" || app.SortRowForTest() == "" {
		t.Fatalf("/openrouter overlay %q sort row %q, want the overlay open on the OpenRouter tab", app.SettingsOverlayText(), app.SortRowForTest())
	}
	app.HandleEsc()
	if app.SettingsOverlayText() != "" {
		t.Fatal("ESC left the /openrouter overlay open")
	}

	if !app.SubmitInput("/settings") {
		t.Fatalf("/settings rejected; notice %q", app.NoticeText())
	}
	if !strings.Contains(app.SettingsOverlayText(), "run ls") || app.SortRowForTest() != "" {
		t.Fatalf("/settings overlay %q sort row %q, want the overlay open on its first tab", app.SettingsOverlayText(), app.SortRowForTest())
	}
}

// TestF1210_PermissionsSettingsTab_TogglesAttributionThroughRealWiring drives the settings
// tab's toggle through the genuine StartTUI wiring — the real cache-backed callbacks, no
// fake — and proves the write lands in the global settings file (byte-preserving) and in
// the session. The returned row is rendered from the same Cache.Attribution() accessor
// buildTurnClient snapshots, so an unchanged row would mean the session never saw the write.
func TestF1210_PermissionsSettingsTab_TogglesAttributionThroughRealWiring(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	home := t.TempDir()
	global := SettingsPath(home)
	const seed = "# hand-written global settings\nagent:\n  max_concurrency: 4 # keep me\n"
	if err := os.MkdirAll(filepath.Dir(global), 0o700); err != nil {
		t.Fatalf("create global settings dir: %v", err)
	}
	if err := os.WriteFile(global, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed global settings: %v", err)
	}

	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        "/launch",
		Config:           map[string]any{"agent": map[string]any{"max_concurrency": 4}},
		ConfigLayerPaths: []string{global},
		Session:          store,
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("/settings") {
		t.Fatal("/settings rejected; the production registry did not bind the handler")
	}

	if row := app.ToggleAttributionForTest(); row != "attribution   off" {
		t.Fatalf("settings row after the toggle = %q, want it off in the live session", row)
	}
	if notice := app.NoticeText(); notice != "" {
		t.Fatalf("notice = %q, want none on a successful toggle", notice)
	}

	got, err := os.ReadFile(global)
	if err != nil {
		t.Fatalf("read global settings: %v", err)
	}
	if want := seed + "attribution: false\n"; string(got) != want {
		t.Fatalf("global settings =\n%q\nwant\n%q", got, want)
	}

	if row := app.ToggleAttributionForTest(); row != "attribution   on" {
		t.Fatalf("settings row after toggling back = %q, want it on", row)
	}
	got, err = os.ReadFile(global)
	if err != nil {
		t.Fatalf("read global settings: %v", err)
	}
	if want := seed + "attribution: true\n"; string(got) != want {
		t.Fatalf("global settings after toggling back =\n%q\nwant\n%q", got, want)
	}
}

// TestF1210_PermissionsSettingsTab_FailedWriteKeepsSessionAndDisk proves the
// no-optimistic-update rule survives the real wiring, not just the picker's own seam: a
// write that fails inside the locked writer must leave the file, the session accessor, and
// the displayed row alone, and report the failure as a notice.
func TestF1210_PermissionsSettingsTab_FailedWriteKeepsSessionAndDisk(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	home := t.TempDir()
	global := SettingsPath(home)
	const seed = "attribution: true # keep me\n"
	if err := os.MkdirAll(filepath.Dir(global), 0o700); err != nil {
		t.Fatalf("create global settings dir: %v", err)
	}
	if err := os.WriteFile(global, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed global settings: %v", err)
	}

	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        "/launch",
		Config:           map[string]any{"attribution": true},
		ConfigLayerPaths: []string{global},
		Session:          store,
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("/settings") {
		t.Fatal("/settings rejected; the production registry did not bind the handler")
	}

	sentinel := errors.New("forced temp-file sync failure")
	restoreSync := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
	row := app.ToggleAttributionForTest()
	restoreSync()

	if row != "attribution   on" {
		t.Errorf("settings row after a failed write = %q, want the unchanged on-disk value", row)
	}
	if notice := app.NoticeText(); !strings.Contains(notice, "couldn't change the openrouter attribution setting") {
		t.Errorf("notice = %q, want the toggle-failure notice", notice)
	}
	got, err := os.ReadFile(global)
	if err != nil {
		t.Fatalf("read global settings: %v", err)
	}
	if string(got) != seed {
		t.Errorf("failed write changed bytes:\n%q\nwant\n%q", got, seed)
	}
}

const openRouterSettingsSeed = "provider:\n  openrouter:\n    base_url: https://openrouter.ai/api/v1\n    api_key: or-key\n"

const systemOneKeysSeed = "provider:\n  openrouter:\n    base_url: https://openrouter.ai/api/v1\n    api_key: or-key\n  venice:\n    base_url: https://api.venice.ai/api/v1\n    api_key: v-key\n"

func startSystemOneTUI(t *testing.T, seed string) (*tui.App, string, *sessions.Store) {
	t.Helper()
	home := t.TempDir()
	global := writeGlobalSettings(t, home, seed, 0o600)
	_, raw, _, err := config.LoadYAML(global)
	if err != nil {
		t.Fatalf("load seeded settings: %v", err)
	}
	composed, err := config.Compose(raw, nil)
	if err != nil {
		t.Fatalf("config.Compose: %v", err)
	}
	store := mkStore(t)
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        "/launch",
		Config:           composed,
		ConfigLayerPaths: []string{global},
		Session:          store,
	}
	app, restore := startCaptured(t, context.Background(), result, io.Discard)
	t.Cleanup(restore)
	return app, global, store
}

func systemOneOnDisk(t *testing.T, global string) any {
	t.Helper()
	_, raw, cat, err := config.LoadYAML(global)
	if err != nil {
		t.Fatalf("config.LoadYAML = (%q, %v)", cat, err)
	}
	return raw[config.KeySystemOne]
}

func TestSystemOneCommand_WritesGlobalFileAndShowsEachChange(t *testing.T) {
	app, global, store := startSystemOneTUI(t, systemOneKeysSeed)

	app.SubmitInput("/systemone")
	if got := app.SystemOnePickerStatusText(); !strings.HasPrefix(got, "System One: off; ") {
		t.Fatalf("status = %q, want the off state", got)
	}
	app.HandleEsc()
	for _, step := range []struct{ name, confirm, status string }{
		{"venice:jev-latest", "System One set to venice:jev-latest", "System One: venice:jev-latest (provider venice, model jev-latest); "},
		{"openrouter:liquid/d1", "System One set to openrouter:liquid/d1", "System One: openrouter:liquid/d1 (provider openrouter, model liquid/d1); "},
		{"off", "System One turned off", "System One: off; "},
	} {
		if !app.SubmitInput("/systemone " + step.name) {
			t.Fatalf("/systemone %s retained input; notice %q", step.name, app.NoticeText())
		}
		if got := app.NoticeText(); got != step.confirm {
			t.Fatalf("notice = %q, want %q", got, step.confirm)
		}
		if got := systemOneOnDisk(t, global); got != step.name {
			t.Fatalf("system_one on disk = %#v, want %q", got, step.name)
		}
		app.SubmitInput("/systemone")
		if got := app.SystemOnePickerStatusText(); !strings.HasPrefix(got, step.status) {
			t.Fatalf("status after %s = %q, want prefix %q", step.name, got, step.status)
		}
		app.HandleEsc()
	}

	before := readFileString(t, global)
	if app.SubmitInput("/systemone foo") {
		t.Fatal("/systemone foo accepted")
	}
	usage := "usage: /systemone <off|openrouter:typesafe/jev-1.13|venice:jev-latest|openrouter:liquid/d1>"
	if got := app.NoticeText(); got != usage {
		t.Fatalf("notice = %q, want %q", got, usage)
	}
	if after := readFileString(t, global); after != before {
		t.Fatalf("refusal changed the global file:\n%q\nwant\n%q", after, before)
	}

	var records []events.SlashCommand
	for _, c := range diskSlashCommands(t, readSessionFile(t, store.Path())) {
		if c.Name == "systemone" {
			records = append(records, c)
		}
	}
	if len(records) != 4 {
		t.Fatalf("systemone records = %+v, want 4", records)
	}
	if ok := records[0]; ok.Outcome != "success" || ok.ErrorDetail != "" {
		t.Errorf("selection record = %+v, want success with no detail", ok)
	}
	if bad := records[3]; bad.Outcome != "error" || bad.ErrorDetail != usage {
		t.Errorf("refusal record = %+v, want error with the usage notice", bad)
	}
}

func TestSystemOneCommand_RefusesMissingKeyWithoutWriting(t *testing.T) {
	const seed = "provider:\n  venice:\n    base_url: https://api.venice.ai/api/v1\n    api_key: v-key\n"
	app, global, _ := startSystemOneTUI(t, seed)
	if app.SubmitInput("/systemone openrouter:typesafe/jev-1.13") {
		t.Fatal("selection without a key accepted")
	}
	if got, want := app.NoticeText(), "System One: openrouter has no API key; run /connect openrouter"; got != want {
		t.Fatalf("notice = %q, want %q", got, want)
	}
	if got := app.InputText(); got != "/systemone openrouter:typesafe/jev-1.13" {
		t.Errorf("input = %q, want it retained", got)
	}
	if got := readFileString(t, global); got != seed {
		t.Fatalf("refusal changed the global file:\n%q\nwant\n%q", got, seed)
	}
}

func TestSystemOneCommand_FailedWritesKeepTheSessionSelection(t *testing.T) {
	t.Run("pre-publication failure", func(t *testing.T) {
		app, global, _ := startSystemOneTUI(t, systemOneKeysSeed)
		sentinel := errors.New("forced temp-file sync failure")
		restoreSync := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
		accepted := app.SubmitInput("/systemone venice:jev-latest")
		restoreSync()
		if accepted || app.InputText() != "/systemone venice:jev-latest" {
			t.Fatalf("accepted = %v, input = %q; want the input retained", accepted, app.InputText())
		}
		if got := app.NoticeText(); !strings.HasPrefix(got, "couldn't change the System One setting: ") {
			t.Fatalf("notice = %q, want the setting-failure notice", got)
		}
		if got := readFileString(t, global); got != systemOneKeysSeed {
			t.Fatalf("failed write changed the global file:\n%q", got)
		}
		app.SubmitInput("/systemone")
		if got := app.SystemOnePickerStatusText(); !strings.HasPrefix(got, "System One: off; ") {
			t.Fatalf("status = %q, want the unchanged off selection", got)
		}
		app.HandleEsc()
	})

	t.Run("directory sync failure after rename", func(t *testing.T) {
		app, global, store := startSystemOneTUI(t, systemOneKeysSeed)
		sentinel := errors.New("forced parent dir sync failure")
		restoreSync := fsutil.SetSyncDirForTest(func(*os.File) error { return sentinel })
		accepted := app.SubmitInput("/systemone venice:jev-latest")
		restoreSync()
		if accepted || app.InputText() != "/systemone venice:jev-latest" {
			t.Fatalf("accepted = %v, input = %q; want the input retained", accepted, app.InputText())
		}
		want := "couldn't change the System One setting: " + systemOneParentDirReason
		if got := app.NoticeText(); got != want {
			t.Fatalf("notice = %q, want %q", got, want)
		}
		if got := systemOneOnDisk(t, global); got != "venice:jev-latest" {
			t.Fatalf("system_one on disk = %#v, want the already-published value", got)
		}
		cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
		if last := cmds[len(cmds)-1]; last.Name != "systemone" || last.Outcome != "error" || last.ErrorDetail != want {
			t.Fatalf("last record = %+v, want the failure as an error", last)
		}
		app.SubmitInput("/systemone")
		if got := app.SystemOnePickerStatusText(); !strings.HasPrefix(got, "System One: off; ") {
			t.Fatalf("status = %q, want the unchanged live selection", got)
		}
		app.HandleEsc()
	})
}

func TestSystemOneCommand_MalformedSettingsFailureHidesSettingsSource(t *testing.T) {
	const credential = "sk-or-FAKE-b63-credential-7f3a"
	for _, tc := range []struct{ name, body string }{
		{"parse error", "provider:\n  openrouter:\n    base_url: https://openrouter.ai/api/v1\n    api_key: \"" + credential + "\n"},
		{"schema error", "provider:\n  openrouter:\n    base_url: https://openrouter.ai/api/v1\n    api_key: [" + credential + "]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, global, store := startSystemOneTUI(t, systemOneKeysSeed)
			if !app.SubmitInput("/systemone venice:jev-latest") {
				t.Fatalf("valid selection retained; notice %q", app.NoticeText())
			}
			if err := os.WriteFile(global, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write malformed settings: %v", err)
			}
			if app.SubmitInput("/systemone off") {
				t.Fatal("/systemone off accepted against malformed settings")
			}
			if got := app.InputText(); got != "/systemone off" {
				t.Errorf("input = %q, want it retained", got)
			}
			notice := app.NoticeText()
			if notice == "System One turned off" || !strings.HasPrefix(notice, "couldn't change the System One setting: ") {
				t.Fatalf("notice = %q, want the setting-failure notice", notice)
			}
			if strings.Contains(notice, credential) {
				t.Fatalf("notice leaks the settings source: %q", notice)
			}
			if strings.Contains(readFileString(t, store.Path()), credential) {
				t.Fatal("session file holds the settings source")
			}
			cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
			if last := cmds[len(cmds)-1]; last.Name != "systemone" || last.Outcome != "error" || last.ErrorDetail != notice {
				t.Fatalf("last record = %+v, want the failure notice as an error", last)
			}
			app.SubmitInput("/systemone")
			if got := app.SystemOnePickerStatusText(); !strings.HasPrefix(got, "System One: venice:jev-latest ") {
				t.Fatalf("status = %q, want the unchanged live selection", got)
			}
			app.HandleEsc()
		})
	}
}

func pickSystemOne(t *testing.T, app *tui.App, name string) {
	t.Helper()
	if !app.SubmitInput("/systemone") || !app.SystemOnePickerOpen() {
		t.Fatal("bare /systemone did not open the picker")
	}
	if !app.SelectSystemOneRowForTest(name) {
		t.Fatalf("picker has no %q row", name)
	}
	if app.SystemOnePickerOpen() {
		t.Fatalf("picker still open after choosing %q", name)
	}
}

func TestSystemOnePicker_ChoicesPersistToTheGlobalFile(t *testing.T) {
	app, global, _ := startSystemOneTUI(t, systemOneKeysSeed)

	pickSystemOne(t, app, "venice:jev-latest")
	if got := app.NoticeText(); got != "System One set to venice:jev-latest" {
		t.Fatalf("notice = %q, want the set confirmation", got)
	}
	if got := systemOneOnDisk(t, global); got != "venice:jev-latest" {
		t.Fatalf("system_one on disk = %#v, want venice:jev-latest", got)
	}

	app.SubmitInput("/systemone")
	if got := app.SystemOnePickerStatusText(); !strings.HasPrefix(got, "System One: venice:jev-latest (provider venice, model jev-latest); ") {
		t.Fatalf("reopened header = %q, want the new selection", got)
	}
	app.HandleEsc()

	pickSystemOne(t, app, "off")
	if got := app.NoticeText(); got != "System One turned off" {
		t.Fatalf("notice = %q, want the off confirmation", got)
	}
	if got := systemOneOnDisk(t, global); got != "off" {
		t.Fatalf("system_one on disk = %#v, want off", got)
	}

	before, seq := readFileString(t, global), app.NoticeSeq()
	pickSystemOne(t, app, "off")
	if !app.SubmitInput("/systemone") {
		t.Fatal("bare /systemone rejected")
	}
	app.HandleEsc()
	if app.SystemOnePickerOpen() {
		t.Fatal("Esc did not close the picker")
	}
	if after := readFileString(t, global); after != before || app.NoticeSeq() != seq {
		t.Fatalf("current choice or Esc wrote or notified: file changed = %v, notices %d -> %d", after != before, seq, app.NoticeSeq())
	}
}

func TestSystemOnePicker_CurrentChoiceWithoutKeyClosesSilently(t *testing.T) {
	const seed = "provider:\n  venice:\n    base_url: https://api.venice.ai/api/v1\n    api_key: v-key\nsystem_one: openrouter:typesafe/jev-1.13\n"
	app, global, _ := startSystemOneTUI(t, seed)
	seq := app.NoticeSeq()
	pickSystemOne(t, app, "openrouter:typesafe/jev-1.13")
	if got := readFileString(t, global); got != seed || app.NoticeSeq() != seq {
		t.Fatalf("choosing the current no-key value wrote or notified: file %q, notice %q", got, app.NoticeText())
	}
}

func TestSystemOnePicker_RefusalsWriteNothing(t *testing.T) {
	t.Run("different model without key", func(t *testing.T) {
		const seed = "provider:\n  venice:\n    base_url: https://api.venice.ai/api/v1\n    api_key: v-key\n"
		app, global, _ := startSystemOneTUI(t, seed)
		pickSystemOne(t, app, "openrouter:liquid/d1")
		if got, want := app.NoticeText(), "System One: openrouter has no API key; run /connect openrouter"; got != want {
			t.Fatalf("notice = %q, want %q", got, want)
		}
		if got := readFileString(t, global); got != seed {
			t.Fatalf("refusal changed the global file:\n%q", got)
		}
	})

	t.Run("failed write", func(t *testing.T) {
		app, global, _ := startSystemOneTUI(t, systemOneKeysSeed)
		restoreSync := fsutil.SetSyncFileForTest(func(*os.File) error { return errors.New("forced temp-file sync failure") })
		pickSystemOne(t, app, "venice:jev-latest")
		restoreSync()
		if got := app.NoticeText(); !strings.HasPrefix(got, "couldn't change the System One setting: ") || strings.Contains(got, "forced temp-file sync failure") {
			t.Fatalf("notice = %q, want the sanitized setting-failure notice", got)
		}
		if got := readFileString(t, global); got != systemOneKeysSeed {
			t.Fatalf("failed write changed the global file:\n%q", got)
		}
		app.SubmitInput("/systemone")
		if got := app.SystemOnePickerStatusText(); !strings.HasPrefix(got, "System One: off; ") {
			t.Fatalf("status = %q, want the unchanged off selection", got)
		}
		app.HandleEsc()
	})
}

func TestF1730_SettingsRetentionPersistsOnlyAcceptedWrites(t *testing.T) {
	const seed = "# hand-written\nsessions:\n  retention_days: 30 # keep\n"
	app, cache, global := startPermissionsSettingsTUI(t, seed)
	readGlobal := func() string {
		t.Helper()
		b, err := os.ReadFile(global)
		if err != nil {
			t.Fatalf("read global settings: %v", err)
		}
		return string(b)
	}
	withDays := func(days string) string {
		return "# hand-written\nsessions:\n  retention_days: " + days + " # keep\n"
	}

	for _, step := range []struct {
		text    string
		confirm bool
		days    int
	}{
		{"45", false, 45},
		{"14", false, 45},
		{"14", true, 14},
	} {
		row := app.SetRetentionForTest(step.text, step.confirm)
		if want := fmt.Sprintf("session retention (days)   %d", step.days); row != want {
			t.Fatalf("SetRetentionForTest(%q, %t) row = %q, want %q", step.text, step.confirm, row, want)
		}
		if got := cache.RetentionDays(); got != step.days {
			t.Fatalf("cache.RetentionDays() = %d, want %d", got, step.days)
		}
		if got, want := readGlobal(), withDays(fmt.Sprint(step.days)); got != want {
			t.Fatalf("global settings after %q/%t =\n%q\nwant\n%q", step.text, step.confirm, got, want)
		}
		if notice := app.NoticeText(); notice != "" {
			t.Fatalf("notice = %q, want none", notice)
		}
	}

	_, raw, cat, err := config.LoadYAML(global)
	if err != nil {
		t.Fatalf("config.LoadYAML = (%q, %v)", cat, err)
	}
	if got := resumeRetentionDays(raw); got != 14 {
		t.Fatalf("resumeRetentionDays(reloaded global) = %d, want 14", got)
	}
}

func startPermissionsSettingsTUI(t *testing.T, seed string) (*tui.App, *config.Cache, string) {
	t.Helper()
	return startPermissionsSettingsTUIWithModel(t, seed, nil)
}

func startPermissionsSettingsTUIWithModel(t *testing.T, seed string, sel *model.Selection) (*tui.App, *config.Cache, string) {
	t.Helper()
	return startPermissionsSettingsTUIWithDiscovered(t, seed, sel, nil)
}

func startPermissionsSettingsTUIWithDiscovered(t *testing.T, seed string, sel *model.Selection, openRouterIDs []string) (*tui.App, *config.Cache, string) {
	t.Helper()
	home := t.TempDir()
	global := writeGlobalSettings(t, home, seed, 0o600)
	if len(openRouterIDs) > 0 {
		var discovered []config.DiscoveredModel
		for _, id := range openRouterIDs {
			discovered = append(discovered, config.DiscoveredModel{ID: id})
		}
		if err := config.UpdateDiscoveredModelsProvider(config.DiscoveredModelsPath(global), "openrouter", config.DiscoveredProvider{Models: discovered}); err != nil {
			t.Fatalf("seed discovered openrouter models: %v", err)
		}
	}
	_, raw, _, err := config.LoadYAML(global)
	if err != nil {
		t.Fatalf("load seeded settings: %v", err)
	}
	composed, err := config.Compose(raw, nil)
	if err != nil {
		t.Fatalf("config.Compose: %v", err)
	}
	var cache *config.Cache
	production := newSettingsDeps
	newSettingsDeps = func(app *tui.App, c *config.Cache, active *model.ActiveState, authorizer *productionAuthorizer) tui.SettingsDeps {
		cache = c
		return production(app, c, active, authorizer)
	}
	t.Cleanup(func() { newSettingsDeps = production })

	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        "/launch",
		Config:           composed,
		ConfigLayerPaths: []string{global},
		Session:          mkStore(t),
		Model:            model.NewActiveState(sel, model.SourceProject),
	}
	app, restore := startCaptured(t, context.Background(), result, io.Discard)
	t.Cleanup(restore)
	if cache == nil {
		t.Fatal("StartTUI built no config cache through the permissions-deps seam")
	}
	settleOpenRouterEndpoints(t, cache, openRouterIDs...)
	if !app.SubmitInput("/settings") {
		t.Fatal("/settings rejected; the production registry did not bind the handler")
	}
	return app, cache, global
}

func fakeOpenRouterTurnServer(t *testing.T) (baseURL string, providerObject func(*config.Cache) map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var chatBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/models/m/endpoints":
			_, _ = io.WriteString(w, `{"data":{"endpoints":[
				{"provider_name":"a","tag":"a","pricing":{"prompt":"0.0000001","completion":"0.0000002"},"throughput_last_30m":{"p50":20}},
				{"provider_name":"b","tag":"b/fp8","pricing":{"prompt":"0.0000001","completion":"0.0000002"},"throughput_last_30m":{"p50":90}},
				{"provider_name":"c","tag":"c","pricing":{"prompt":"0.0000001","completion":"0.0000002"},"throughput_last_30m":{"p50":50}}
			]}}`)
		case "/api/v1/chat/completions":
			raw, _ := io.ReadAll(r.Body)
			mu.Lock()
			chatBody = raw
			mu.Unlock()
			_, _ = io.WriteString(w, `{"id":"c1","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/api/v1", func(cache *config.Cache) map[string]any {
		t.Helper()
		prevStore := openRouterEndpoints
		openRouterEndpoints = &provider.OpenRouterEndpointStore{HTTPClient: srv.Client()}
		defer func() { openRouterEndpoints = prevStore }()
		defer swapTurnProviderClient(func(cfg provider.ClientConfig) provider.Client {
			cfg.HTTPClient = srv.Client()
			return provider.NewClient(cfg)
		})()
		client, ok := buildTurnClient("openrouter", provider.AuthKindConfigured, cache, nil, "")
		if !ok {
			t.Fatalf("buildTurnClient(openrouter) ok = false, want a client")
		}
		if _, err := client.ChatCompletion(context.Background(), provider.Request{
			Model:    "m",
			Messages: []provider.Message{{Role: "user", Content: "hi"}},
		}); err != nil {
			t.Fatalf("ChatCompletion() error = %v, want nil", err)
		}
		mu.Lock()
		defer mu.Unlock()
		var body struct {
			Provider map[string]any `json:"provider"`
		}
		if err := json.Unmarshal(chatBody, &body); err != nil {
			t.Fatalf("decode request body: %v\nbody = %s", err, chatBody)
		}
		return body.Provider
	}
}

func reloadedOpenRouterSort(t *testing.T, settings string) string {
	t.Helper()
	data, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	_, raw, _, err := config.LoadYAMLBytes(data, settings)
	if err != nil {
		t.Fatalf("LoadYAMLBytes: %v\n%s", err, data)
	}
	fresh, err := config.NewCache(raw, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	return fresh.OpenRouterSort()
}

func TestF1570_PermissionsSettingsTab_RoutingRowsWriteGlobalFileAndReachRequests(t *testing.T) {
	baseURL, providerObject := fakeOpenRouterTurnServer(t)
	app, cache, global := startPermissionsSettingsTUI(t, "provider:\n  openrouter:\n    base_url: "+baseURL+"\n    api_key: or-key\n")

	if got := providerObject(cache); len(got) != 0 {
		t.Fatalf("request provider object before any change = %#v, want none", got)
	}
	for _, step := range []struct {
		act     func() string
		row     string
		routing map[string]any
		sort    string
		request map[string]any
	}{
		{app.ToggleDataCollectionForTest, "data collection   deny", map[string]any{"data_collection": "deny"}, "default", nil},
		{app.ToggleDataCollectionForTest, "data collection   allow", map[string]any{"data_collection": "allow"}, "default", nil},
		{app.StepSortForTest, "sort   throughput", map[string]any{"data_collection": "allow", "sort": "throughput"}, "throughput", nil},
		{
			app.StepSortForTest, "sort   best value", map[string]any{"data_collection": "allow", "sort": "best_value"}, "best_value",
			map[string]any{"data_collection": "allow", "order": []any{"b/fp8"}},
		},
		{app.StepSortForTest, "sort   default", map[string]any{"data_collection": "allow"}, "default", nil},
	} {
		if row := step.act(); row != step.row {
			t.Fatalf("settings row = %q, want %q", row, step.row)
		}
		if notice := app.NoticeText(); notice != "" {
			t.Fatalf("notice after %q = %q, want none", step.row, notice)
		}
		if got := persistedProviderEntry(t, global, "openrouter")["routing"]; !reflect.DeepEqual(got, step.routing) {
			t.Fatalf("persisted routing after %q = %#v, want %#v", step.row, got, step.routing)
		}
		if got := reloadedOpenRouterSort(t, global); got != step.sort {
			t.Fatalf("reloaded sort after %q = %q, want %q", step.row, got, step.sort)
		}
		want := step.request
		if want == nil {
			want = step.routing
		}
		if got := providerObject(cache); !reflect.DeepEqual(got, want) {
			t.Fatalf("next request provider object after %q = %#v, want %#v", step.row, got, want)
		}
	}
}

func TestF1570_PermissionsSettingsTab_RoutingRowsWithoutOpenRouterChangeNothing(t *testing.T) {
	const seed = "agent:\n  max_concurrency: 4 # keep me\n"
	app, cache, global := startPermissionsSettingsTUI(t, seed)

	for _, tc := range []struct {
		act    func() string
		row    string
		notice string
	}{
		{app.ToggleDataCollectionForTest, "data collection   allow", "couldn't change the openrouter data collection setting: config: provider.openrouter.routing.data_collection needs a configured provider.openrouter entry"},
		{app.StepSortForTest, "sort   default", "couldn't change the openrouter sort setting: config: provider.openrouter.routing.sort needs a configured provider.openrouter entry"},
	} {
		if row := tc.act(); row != tc.row {
			t.Errorf("settings row = %q, want the unchanged default %q", row, tc.row)
		}
		if notice := app.NoticeText(); notice != tc.notice {
			t.Errorf("notice = %q, want %q", notice, tc.notice)
		}
	}
	if got, err := os.ReadFile(global); err != nil || string(got) != seed {
		t.Errorf("global settings = %q (err %v), want %q", got, err, seed)
	}
	if _, ok := cache.Provider("openrouter"); ok {
		t.Error("cache gained an openrouter entry")
	}
	if dc, st := cache.OpenRouterDataCollection(), cache.OpenRouterSort(); dc != "allow" || st != "default" {
		t.Errorf("cache routing = %q/%q, want allow/default", dc, st)
	}
}

func TestF1570_PermissionsSettingsTab_FailedRoutingWriteKeepsDiskCacheAndRequests(t *testing.T) {
	const seed = openRouterSettingsSeed + "    routing:\n      data_collection: deny # keep me\n      sort: latency\n"
	app, cache, global := startPermissionsSettingsTUI(t, seed)
	stored := map[string]any{"data_collection": "deny", "sort": "latency"}

	for _, tc := range []struct {
		act    func() string
		row    string
		notice string
	}{
		{app.ToggleDataCollectionForTest, "data collection   deny", "couldn't change the openrouter data collection setting: "},
		{app.StepSortForTest, "sort   latency", "couldn't change the openrouter sort setting: "},
	} {
		restoreSync := fsutil.SetSyncFileForTest(func(*os.File) error { return errors.New("forced temp-file sync failure") })
		row := tc.act()
		restoreSync()

		if row != tc.row {
			t.Errorf("settings row after a failed write = %q, want the stored %q", row, tc.row)
		}
		if notice := app.NoticeText(); !strings.HasPrefix(notice, tc.notice) {
			t.Errorf("notice = %q, want it to start with %q", notice, tc.notice)
		}
		if got, err := os.ReadFile(global); err != nil || string(got) != seed {
			t.Errorf("global settings = %q (err %v), want %q", got, err, seed)
		}
		if dc, st := cache.OpenRouterDataCollection(), cache.OpenRouterSort(); dc != "deny" || st != "latency" {
			t.Errorf("cache routing = %q/%q, want deny/latency", dc, st)
		}
		if got := openRouterRequestProviderObject(t, cache); !reflect.DeepEqual(got, stored) {
			t.Errorf("next request provider object = %#v, want %#v", got, stored)
		}
	}
}

type refusingTransport struct{}

func (refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no network in this test")
}

func settleOpenRouterEndpoints(t *testing.T, cache *config.Cache, models ...string) {
	t.Helper()
	prev := openRouterEndpoints
	openRouterEndpoints = &provider.OpenRouterEndpointStore{HTTPClient: &http.Client{Transport: refusingTransport{}}}
	t.Cleanup(func() { openRouterEndpoints = prev })
	entry, _ := cache.Provider("openrouter")
	name, value := entry.ResolveAuthHeader()
	for _, model := range models {
		openRouterEndpoints.BestValueTag(context.Background(), entry, name, value, model, "", nil)
	}
}

const openRouterModelsHeader = "model | input $/M | output $/M | quantizations"

func TestF1630_PermissionsSettingsTab_MaxPriceReachesNextTurnClientConfig(t *testing.T) {
	app, cache, global := startPermissionsSettingsTUIWithDiscovered(t, openRouterSettingsSeed, &model.Selection{Provider: "openrouter", ID: "m", Effort: model.EffortDefault}, []string{"other/model", "m"})
	settleOpenRouterEndpoints(t, cache, "m")

	if rows := app.OpenRouterModelsForTest(); !slices.Equal(rows, []string{openRouterModelsHeader, "(no models configured)"}) {
		t.Fatalf("table rows before any cap = %q", rows)
	}
	for _, step := range []struct {
		prompt, completion string
		rows               []string
		persisted          map[string]any
		request            map[string]any
	}{
		{
			"0.5", "2", []string{openRouterModelsHeader, "m | $0.5 | $2 | none"},
			map[string]any{"prompt": 0.5, "completion": uint64(2)}, map[string]any{"prompt": 0.5, "completion": 2.0},
		},
		{
			"1", "", []string{openRouterModelsHeader, "m | $1 | none | none"},
			map[string]any{"prompt": uint64(1)}, map[string]any{"prompt": 1.0},
		},
	} {
		if !app.SaveOpenRouterModelCapsForTest("m", step.prompt, step.completion) {
			t.Fatalf("saving %s/%s did not reach the price editor", step.prompt, step.completion)
		}
		if notice := app.NoticeText(); notice != "" {
			t.Fatalf("notice = %q, want none", notice)
		}
		if rows := app.OpenRouterModelsForTest(); !slices.Equal(rows, step.rows) {
			t.Fatalf("table rows = %q, want %q", rows, step.rows)
		}
		if row := app.OpenRouterModelsCountRowForTest(); row != "models: 1 configured" {
			t.Fatalf("models row = %q", row)
		}
		wantPersisted := map[string]any{"max_price": map[string]any{"m": step.persisted}}
		if got := persistedProviderEntry(t, global, "openrouter")["routing"]; !reflect.DeepEqual(got, wantPersisted) {
			t.Fatalf("persisted routing = %#v, want %#v", got, wantPersisted)
		}
		if got := openRouterRequestProviderObject(t, cache)["max_price"]; !reflect.DeepEqual(got, step.request) {
			t.Fatalf("next request max_price = %#v, want %#v", got, step.request)
		}
	}

	if !app.RemoveOpenRouterModelForTest("m") {
		t.Fatal("removing m did not reach the confirmation")
	}
	if rows := app.OpenRouterModelsForTest(); !slices.Equal(rows, []string{openRouterModelsHeader, "(no models configured)"}) {
		t.Fatalf("table rows after removal = %q", rows)
	}
	if row := app.OpenRouterModelsCountRowForTest(); row != "models: 0 configured" {
		t.Fatalf("models row after removal = %q", row)
	}
	if _, ok := persistedProviderEntry(t, global, "openrouter")["routing"]; ok {
		t.Fatal("removing the only cap left a routing entry on disk")
	}
	if got, ok := openRouterRequestProviderObject(t, cache)["max_price"]; ok {
		t.Fatalf("next request max_price after removal = %#v, want none", got)
	}
}

func TestF1930_OpenRouterModelsDialog_QuantizationsPersistThroughProductionDeps(t *testing.T) {
	const seed = openRouterSettingsSeed + "    routing:\n      # keep me\n      max_price:\n        keep/caps: {prompt: 7}\n      quantizations:\n        keep/quant: {levels: [int8], mode: preferred}\n"
	app, cache, global := startPermissionsSettingsTUIWithDiscovered(t, seed, nil, []string{"m"})
	keepCaps := map[string]any{"keep/caps": map[string]any{"prompt": uint64(7)}}
	keepQuant := map[string]any{"levels": []any{"int8"}, "mode": "preferred"}
	routing := func() map[string]any {
		t.Helper()
		r, _ := persistedProviderEntry(t, global, "openrouter")["routing"].(map[string]any)
		return r
	}

	if !app.SaveOpenRouterModelForTest("m", "", "", "fp8 fp4", true) {
		t.Fatal("adding m did not reach the dialog")
	}
	if notice := app.NoticeText(); notice != "" {
		t.Fatalf("notice = %q, want none", notice)
	}
	want := map[string]any{
		"max_price":     keepCaps,
		"quantizations": map[string]any{"keep/quant": keepQuant, "m": map[string]any{"levels": []any{"fp8", "fp4"}, "mode": "required"}},
	}
	if got := routing(); !reflect.DeepEqual(got, want) {
		t.Fatalf("persisted routing = %#v, want %#v", got, want)
	}
	wantCache := []config.OpenRouterQuantization{
		{Model: "keep/quant", Quantization: provider.Quantization{Levels: []string{"int8"}, Mode: "preferred"}},
		{Model: "m", Quantization: provider.Quantization{Levels: []string{"fp8", "fp4"}, Mode: "required"}},
	}
	if got := cache.OpenRouterQuantizations(); !reflect.DeepEqual(got, wantCache) {
		t.Fatalf("cached quantizations = %+v, want %+v", got, wantCache)
	}
	rows := []string{openRouterModelsHeader, "keep/caps | $7 | none | none", "keep/quant | none | none | int8 (preferred)", "m | none | none | fp8 fp4 (required)"}
	if got := app.OpenRouterModelsForTest(); !slices.Equal(got, rows) {
		t.Fatalf("table rows = %q, want %q", got, rows)
	}
	if row := app.OpenRouterModelsCountRowForTest(); row != "models: 3 configured" {
		t.Fatalf("models row = %q", row)
	}

	if !app.SaveOpenRouterModelForTest("m", "1", "", "", false) {
		t.Fatal("editing m did not reach the dialog")
	}
	want = map[string]any{
		"max_price":     map[string]any{"keep/caps": map[string]any{"prompt": uint64(7)}, "m": map[string]any{"prompt": uint64(1)}},
		"quantizations": map[string]any{"keep/quant": keepQuant},
	}
	if got := routing(); !reflect.DeepEqual(got, want) {
		t.Fatalf("persisted routing after clearing the levels = %#v, want %#v", got, want)
	}
	if data, _ := os.ReadFile(global); !strings.Contains(string(data), "# keep me") {
		t.Fatalf("saving dropped a routing comment:\n%s", data)
	}

	if !app.SaveOpenRouterModelForTest("m", "1", "", "bf16", false) {
		t.Fatal("re-editing m did not reach the dialog")
	}
	if !app.RemoveOpenRouterModelForTest("m") {
		t.Fatal("removing m did not reach the confirmation")
	}
	want = map[string]any{"max_price": keepCaps, "quantizations": map[string]any{"keep/quant": keepQuant}}
	if got := routing(); !reflect.DeepEqual(got, want) {
		t.Fatalf("persisted routing after remove = %#v, want %#v", got, want)
	}
	if got := cache.OpenRouterQuantizations(); !reflect.DeepEqual(got, wantCache[:1]) {
		t.Fatalf("cached quantizations after remove = %+v", got)
	}
}

func TestF1930_OpenRouterModelsDialog_ExternalQuantizationsSurviveButStayOutOfTheSession(t *testing.T) {
	const seed = openRouterSettingsSeed + "    routing:\n      quantizations:\n        a/one: {levels: [fp8], mode: preferred}\n"
	app, cache, global := startPermissionsSettingsTUIWithDiscovered(t, seed, nil, []string{"m"})
	if err := os.WriteFile(global, []byte(seed+"        b/two: {levels: [fp4, unknown], mode: required}\n"), 0o600); err != nil {
		t.Fatalf("external settings edit: %v", err)
	}

	if !app.SaveOpenRouterModelForTest("m", "", "", "bf16", false) {
		t.Fatal("adding m did not reach the dialog")
	}
	want := map[string]any{
		"a/one": map[string]any{"levels": []any{"fp8"}, "mode": "preferred"},
		"b/two": map[string]any{"levels": []any{"fp4", "unknown"}, "mode": "required"},
		"m":     map[string]any{"levels": []any{"bf16"}, "mode": "preferred"},
	}
	routing, _ := persistedProviderEntry(t, global, "openrouter")["routing"].(map[string]any)
	if got := routing["quantizations"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("persisted quantizations = %#v, want %#v", got, want)
	}
	for _, q := range cache.OpenRouterQuantizations() {
		if q.Model == "b/two" {
			t.Fatal("the external entry reached the session cache")
		}
	}
	rows := []string{openRouterModelsHeader, "a/one | none | none | fp8 (preferred)", "m | none | none | bf16 (preferred)"}
	if got := app.OpenRouterModelsForTest(); !slices.Equal(got, rows) {
		t.Fatalf("table rows = %q, want %q", got, rows)
	}
	if row := app.OpenRouterModelsCountRowForTest(); row != "models: 2 configured" {
		t.Fatalf("models row = %q", row)
	}
}

func TestF1920_OpenRouterModelsTable_ListsLaunchCapsAndIgnoresExternalEdits(t *testing.T) {
	const capsSeed = openRouterSettingsSeed + "    routing:\n      max_price:\n        a/one:\n          prompt: 1\n"
	app, _, global := startPermissionsSettingsTUIWithDiscovered(t, capsSeed, nil, []string{"m"})

	if rows := app.OpenRouterModelsForTest(); !slices.Equal(rows, []string{openRouterModelsHeader, "a/one | $1 | none | none"}) {
		t.Fatalf("table rows at launch = %q", rows)
	}
	external := capsSeed + "        b/two:\n          completion: 5\n"
	if err := os.WriteFile(global, []byte(external), 0o600); err != nil {
		t.Fatalf("external settings edit: %v", err)
	}
	if !app.SaveOpenRouterModelCapsForTest("m", "2", "") {
		t.Fatal("adding m did not reach the price editor")
	}
	if notice := app.NoticeText(); notice != "" {
		t.Fatalf("notice = %q, want none", notice)
	}
	if rows := app.OpenRouterModelsForTest(); !slices.Equal(rows, []string{openRouterModelsHeader, "a/one | $1 | none | none", "m | $2 | none | none"}) {
		t.Fatalf("table rows after an external edit and an in-process add = %q", rows)
	}
	if row := app.OpenRouterModelsCountRowForTest(); row != "models: 2 configured" {
		t.Fatalf("models row = %q", row)
	}
}

// TestF495_PermissionsRevoke_RemovesFromDiskAndLiveSession is the revoke wiring/terminal test
// (minus the human real-terminal gate): it drives the production /settings overlay's revoke
// through the genuine StartTUI wiring — the real authorizer.RevokeGrant seam, no fake/double —
// and proves a confirmed revoke removes the grant from the correct settings file (read back
// from disk) and from the live session (the overlay, sourced from the live grants, drops it).
func TestF495_PermissionsRevoke_RemovesFromDiskAndLiveSession(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	home := t.TempDir()
	globalTarget := SettingsPath(home)
	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: "*", GrantKind: "global"}

	// Seed the grant both on disk (the revoke target the seam re-reads and deletes) and in the
	// composed cache (so the overlay lists it and the live match uses it) — the same identity.
	seedGrantFile(t, globalTarget, entry)
	result := &BootstrapResult{
		Home:      home,
		LaunchDir: "/launch",
		Config: map[string]any{
			"permissions": []any{
				map[string]any{"kind": "tool", "subject": "read_file", "path_scope": "*", "grant_kind": "global"},
			},
		},
		SettingsLayers: []securitystate.LayerSnapshot{loadedLayer(t, securitystate.LayerGlobal, globalTarget)},
		Session:        store,
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("/settings") {
		t.Fatal("/settings rejected; the production registry did not bind the handler")
	}
	if overlay := app.SettingsOverlayText(); !strings.Contains(overlay, "allow the read_file tool") {
		t.Fatalf("overlay before revoke = %q, want it to list the seeded global grant", overlay)
	}
	if present, _ := targetHasGrant(globalTarget, home, entry.DedupKey()); !present {
		t.Fatal("precondition: seeded grant should be on disk before revoke")
	}

	if !app.RevokeHighlightedPermissionForTest() {
		t.Fatal("no highlighted grant to revoke through the production overlay")
	}

	// Disk: the global settings file no longer carries the grant.
	if present, _ := targetHasGrant(globalTarget, home, entry.DedupKey()); present {
		t.Errorf("grant still on disk after revoke, want removed from %q", globalTarget)
	}
	// Live session: the overlay, sourced from the live grants table, no longer lists it.
	if overlay := app.SettingsOverlayText(); strings.Contains(overlay, "read_file") {
		t.Errorf("overlay after revoke = %q, want the revoked grant gone from the live session", overlay)
	}
	// Session file, read back from disk: exactly one revocation naming the removed grant, so a
	// later reader can tell this deletion from an ordinary edit of the same YAML.
	assertDiskRevocations(t, store.Path(), entry)
	if notice := app.NoticeText(); notice != "" {
		t.Errorf("notice = %q, want none on a recorded revoke", notice)
	}
}

// assertDiskRevocations reloads the session file and asserts it carries exactly one
// permission_revoke_requested per want, in order, each naming its grant's stored identity.
func assertDiskRevocations(t *testing.T, sessionPath string, want ...permissions.PermissionEntry) {
	t.Helper()
	got := decodeDiskEvents[events.PermissionRevokeRequested](t, readSessionFile(t, sessionPath), events.KindPermissionRevokeRequested)
	if len(got) != len(want) {
		t.Fatalf("durable permission_revoke_requested events = %d (%+v), want %d", len(got), got, len(want))
	}
	for i, entry := range want {
		if expect := wantRevokeEvent(entry); got[i] != expect {
			t.Errorf("durable revocation %d = %+v, want the removed grant's identity %+v", i+1, got[i], expect)
		}
	}
}

func TestPermissionsRevoke_SessionGrantIsDurableWithoutTouchingSettings(t *testing.T) {
	ctx := context.Background()
	project := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)

	var live *syncGrants
	production := newSettingsDeps
	newSettingsDeps = func(app *tui.App, cache *config.Cache, active *model.ActiveState, authorizer *productionAuthorizer) tui.SettingsDeps {
		live = authorizer.grants
		return production(app, cache, active, authorizer)
	}
	defer func() { newSettingsDeps = production }()

	result := &BootstrapResult{Home: home, LaunchDir: project, ProjectRoot: project, Session: store}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()
	if live == nil {
		t.Fatal("StartTUI built no grant table through the permissions-deps seam")
	}

	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: project, GrantKind: "session"}
	live.AppendPermission(entry)
	if !app.SubmitInput("/settings") {
		t.Fatal("/settings rejected; the production registry did not bind the handler")
	}
	if !app.SelectPermissionForTest(entry) {
		t.Fatal("session grant was not selectable in the production permissions picker")
	}
	if !app.RevokeHighlightedPermissionForTest() {
		t.Fatal("session grant was not revoked through the production permissions picker")
	}
	if overlay := app.SettingsOverlayText(); strings.Contains(overlay, "read_file") {
		t.Errorf("overlay after revoke = %q, want the session grant gone", overlay)
	}
	assertDiskRevocations(t, store.Path(), entry)
	mustNotExist(t, filepath.Join(project, ".codemeld", "settings.yaml"), "a session revoke must not write the project settings file")
	mustNotExist(t, SettingsPath(home), "a session revoke must not write the global settings file")
	if notice := app.NoticeText(); notice != "" {
		t.Errorf("notice = %q, want none on a recorded session revoke", notice)
	}
}

// TestPermissionsRevoke_HandledSessionWriteFailureKeepsOneQueuedEvent drives the production
// registry and breaks the session path between opening /settings and confirming the revoke. The
// /settings handler already flushed its slash_command, so the revoke's flush takes the store's
// JSONL append path and fails there for real — the write-failure protocol the command flush hook
// owns then reports it and returns nil.
//
// What must hold: the settings deletion and the live removal stand (a revoked grant must never keep
// authorizing), exactly the existing session-write-failure notice appears, and the one appended
// revocation stays queued rather than being duplicated or dropped — so an independently successful
// later flush carries that same single record.
func TestPermissionsRevoke_HandledSessionWriteFailureKeepsOneQueuedEvent(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	home := t.TempDir()
	globalTarget := SettingsPath(home)
	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: "*", GrantKind: "global"}

	seedGrantFile(t, globalTarget, entry)
	result := &BootstrapResult{
		Home:      home,
		LaunchDir: "/launch",
		Config: map[string]any{
			"permissions": []any{
				map[string]any{"kind": "tool", "subject": "read_file", "path_scope": "*", "grant_kind": "global"},
			},
		},
		SettingsLayers: []securitystate.LayerSnapshot{loadedLayer(t, securitystate.LayerGlobal, globalTarget)},
		Session:        store,
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("/settings") {
		t.Fatal("/settings rejected; the production registry did not bind the handler")
	}
	// The handler's own flush already created the file and made its slash_command durable, so the
	// revoke's flush appends to it. A directory at that path fails the store's O_WRONLY|O_APPEND
	// open with EISDIR for every user including root, unlike a mode-bit failure root bypasses, so
	// this case runs under the same gate everywhere. The flushed file is moved aside intact rather
	// than discarded, so the "nothing reached disk" assertion reads the real artifact.
	if _, err := os.Stat(store.Path()); err != nil {
		t.Fatalf("precondition: /settings should have flushed the session file: %v", err)
	}
	aside := store.Path() + ".aside"
	if err := os.Rename(store.Path(), aside); err != nil {
		t.Fatalf("move the flushed session file aside: %v", err)
	}
	if err := os.Mkdir(store.Path(), 0o700); err != nil {
		t.Fatalf("put a directory at the session path: %v", err)
	}

	if !app.RevokeHighlightedPermissionForTest() {
		t.Fatal("no highlighted grant to revoke through the production overlay")
	}

	if present, _ := targetHasGrant(globalTarget, home, entry.DedupKey()); present {
		t.Errorf("grant still on disk after a failed session write, want the settings delete kept")
	}
	if overlay := app.SettingsOverlayText(); strings.Contains(overlay, "read_file") {
		t.Errorf("overlay after revoke = %q, want the revoked grant gone despite the write failure", overlay)
	}
	// The notice area holds the latest notice, so a revoke-specific one added on top of the handled
	// write failure would show here instead.
	if notice := app.NoticeText(); !strings.HasPrefix(notice, "session log unwritable — ") {
		t.Fatalf("notice = %q, want exactly the existing session-write-failure notice", notice)
	}

	// The record is queued, not durable: nothing reached the session file while the append failed.
	assertDiskRevocations(t, aside)
	if got := countPermissionEvents(store, events.KindPermissionRevokeRequested); got != 1 {
		t.Fatalf("queued permission_revoke_requested events = %d, want exactly 1 (no duplicate)", got)
	}

	// An independently successful later flush carries that same one record.
	if err := os.Remove(store.Path()); err != nil {
		t.Fatalf("remove the blocking directory: %v", err)
	}
	if err := os.Rename(aside, store.Path()); err != nil {
		t.Fatalf("restore the session file: %v", err)
	}
	if _, _, err := store.Flush(ctx); err != nil {
		t.Fatalf("later flush: %v", err)
	}
	assertDiskRevocations(t, store.Path(), entry)
}

// resumeHint mirrors tui.ResumeHint without importing it for one string, matching
// the cmd_exit.go constant; kept local so a wording drift fails this test too.
func resumeHint(sessionID string) string {
	return "to resume this session run: codemeld --resume " + sessionID
}

// TestTRTUI7_EffortValid_AppliesAndPersists covers the /effort success path: a
// supported level records slash_command{effort, success}, emits model_changed,
// writes model.active to the project settings file, and transitions the
// run's next-turn source to picker (the change applies on the next turn).
func TestTRTUI7_EffortValid_AppliesAndPersists(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	active := selectedState() // openai/gpt-5.5/medium, sourced from a resume
	projectRoot := t.TempDir()
	home := t.TempDir()
	seedOpenAIDiscoveredWithEfforts(t, SettingsPath(home), []string{"medium", "high", "xhigh"}, "gpt-5.5", "gpt-5.5-pro")
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        "/launch",
		ProjectRoot:      projectRoot,
		Config:           modelTestConfig(),
		ConfigLayerPaths: []string{SettingsPath(home)},
		Model:            active,
		Session:          store,
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	// Seeded footer reflects the launch effort (medium), not yet high; this pins the
	// production /effort apply path's footer refresh so dropping Refresh:
	// app.RefreshStatusLine from newEffortDeps leaves the footer stale and fails here.
	seeded := app.StatusLineText()
	if !strings.Contains(seeded, "medium") || strings.Contains(seeded, "high") {
		t.Fatalf("seeded status line = %q, want it to show the launch effort medium", seeded)
	}

	if !app.SubmitInput("/effort high") {
		t.Fatal("/effort high (a supported level) should be accepted")
	}

	cmds := slashCmds(t, store)
	if len(cmds) != 1 || cmds[0].Name != "effort" || cmds[0].Outcome != "success" {
		t.Fatalf("slash_command events = %+v, want one {effort, success}", cmds)
	}
	changed := decodeModelChanged(t, store)
	if len(changed) != 1 || changed[0].NewEffort != "high" || changed[0].NewModelID != "gpt-5.5" {
		t.Fatalf("model_changed = %+v, want one with new_effort high on gpt-5.5", changed)
	}
	sel, src, ok := active.Current()
	if !ok || sel.Effort != "high" || src != model.SourcePicker {
		t.Fatalf("active state = (%+v, %q, %v), want effort high / source picker", sel, src, ok)
	}
	// the supported level is persisted to model.active on disk.
	target := config.LocalSettingsPath(projectRoot)
	assertFileContains(t, target, "gpt-5.5")
	assertFileContains(t, target, "high")
	// The persistent footer live-updates to the new effort after the apply path runs.
	if got := app.StatusLineText(); !strings.Contains(got, "high") {
		t.Fatalf("status line after /effort apply = %q, want it to reflect effort high (footer did not live-update)", got)
	}
}

// TestTRTUI7_ModelValid_AppliesPersistsAndFallsBackEffort covers the /model
// success path: a supported id records slash_command{model, success}, falls the
// effort back to the new model's default when the current one is unsupported,
// emits model_changed, and triggers a real model.active write to the project
// settings file plus the model.last_used global mirror.
func TestTRTUI7_ModelValid_AppliesPersistsAndFallsBackEffort(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	active := model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: "low"}, model.SourceResume)
	projectRoot := t.TempDir()
	home := t.TempDir()
	seedOpenAIDiscoveredWithEfforts(t, SettingsPath(home), []string{"medium", "high", "xhigh"}, "gpt-5.5", "gpt-5.5-pro")
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        "/launch",
		ProjectRoot:      projectRoot,
		Config:           modelTestConfig(),
		ConfigLayerPaths: []string{SettingsPath(home)},
		Model:            active,
		Session:          store,
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	// gpt-5.5-pro supports {medium, high, xhigh}, so the current "low" falls back
	// to "medium" (effort-on-success rule).
	if !app.SubmitInput("/model gpt-5.5-pro") {
		t.Fatal("/model gpt-5.5-pro (in the active provider allowlist) should be accepted")
	}

	cmds := slashCmds(t, store)
	if len(cmds) != 1 || cmds[0].Name != "model" || cmds[0].Outcome != "success" {
		t.Fatalf("slash_command events = %+v, want one {model, success}", cmds)
	}
	changed := decodeModelChanged(t, store)
	if len(changed) != 1 || changed[0].NewModelID != "gpt-5.5-pro" || changed[0].NewEffort != "medium" {
		t.Fatalf("model_changed = %+v, want one with new_model_id gpt-5.5-pro / new_effort medium", changed)
	}
	sel, src, ok := active.Current()
	if !ok || sel.ID != "gpt-5.5-pro" || sel.Effort != "medium" || src != model.SourcePicker {
		t.Fatalf("active state = (%+v, %q, %v), want gpt-5.5-pro / medium / picker", sel, src, ok)
	}
	// step 1: per-project model.active write.
	activePath := config.LocalSettingsPath(projectRoot)
	assertFileContains(t, activePath, "gpt-5.5-pro")
	assertFileContains(t, activePath, "medium")
	// step 2: global model.last_used mirror, written only after the active
	// write succeeds.
	assertFileContains(t, filepath.Join(home, ".codemeld", "global", "settings.yaml"), "gpt-5.5-pro")
}

// TestTRTUI7_RejectUnsupported_ExactErrorAndErrorEvent is the negative table
// required by Done-when 3: /effort with an unsupported level and /model with an
// unknown id each retain the typed input, render the exact error text
// emit slash_command{outcome:error} carrying that same text as error_detail, run
// no apply (no model_changed), and write no model.active file.
func TestTRTUI7_RejectUnsupported_ExactErrorAndErrorEvent(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		cmdName string
		wantErr string
	}{
		{
			name:    "effort unsupported level",
			input:   "/effort wrong",
			cmdName: "effort",
			wantErr: "unsupported effort wrong; supported efforts: medium, high, xhigh",
		},
		{
			name:    "model unknown id",
			input:   "/model gpt-9",
			cmdName: "model",
			// active provider openai's allowlist, in declaration order.
			wantErr: "unsupported model gpt-9; supported models: gpt-5.5, gpt-5.5-pro",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := mkStore(t)
			active := selectedState()
			projectRoot := t.TempDir()
			home := t.TempDir()
			seedOpenAIDiscoveredWithEfforts(t, SettingsPath(home), []string{"medium", "high", "xhigh"}, "gpt-5.5", "gpt-5.5-pro")
			result := &BootstrapResult{
				Home:             home,
				LaunchDir:        "/launch",
				ProjectRoot:      projectRoot,
				Config:           modelTestConfig(),
				ConfigLayerPaths: []string{SettingsPath(home)},
				Model:            active,
				Session:          store,
			}
			app, restore := startCaptured(t, ctx, result, io.Discard)
			defer restore()

			before, _, _ := active.Current()
			if app.SubmitInput(tc.input) {
				t.Fatalf("%q must be rejected (input retained), not accepted", tc.input)
			}

			cmds := slashCmds(t, store)
			if len(cmds) != 1 || cmds[0].Name != tc.cmdName || cmds[0].Outcome != "error" {
				t.Fatalf("slash_command events = %+v, want one {%s, error}", cmds, tc.cmdName)
			}
			if cmds[0].ErrorDetail != tc.wantErr {
				t.Fatalf("slash_command error_detail = %q, want exact req-575 text %q", cmds[0].ErrorDetail, tc.wantErr)
			}
			if changed := decodeModelChanged(t, store); len(changed) != 0 {
				t.Fatalf("model_changed events = %+v, want none on a rejected value", changed)
			}
			if after, _, _ := active.Current(); after != before {
				t.Fatalf("active selection changed on a rejected value: before %+v, after %+v", before, after)
			}
			if _, err := os.Stat(filepath.Join(projectRoot, ".codemeld", "settings.yaml")); !os.IsNotExist(err) {
				t.Fatalf("model.active settings file stat err = %v, want not-exist (no write on rejection)", err)
			}
		})
	}
}

func TestConnectCommand_ProductionWiring_OpenAIRetainsEveryDiscoveredModel(t *testing.T) {
	const prov = "openai"
	formerlyUnusable := []string{"text-embedding-3-large", "some-unknown-model"}
	discovered := append([]string{"gpt-5.5", "gpt-5.5-pro"}, formerlyUnusable...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer sk-entered-at-the-prompt" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		var data []any
		for _, id := range discovered {
			data = append(data, map[string]any{"id": id})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer srv.Close()
	defer swapConnectDiscover(func(ctx context.Context, cfg provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		cfg.Entry.BaseURL = srv.URL
		return provider.DiscoverAPIKeyModels(ctx, cfg)
	})()

	ctx := context.Background()
	store := mkStore(t)
	home := t.TempDir()
	settings := SettingsPath(home)
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        "/launch",
		Session:          store,
		ConfigLayerPaths: []string{settings},
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	pickerHas := func(providerID, modelID string) bool {
		for _, row := range app.ModelPickerRows() {
			if row.Provider == providerID && row.ModelID == modelID {
				return true
			}
		}
		return false
	}
	if pickerHas(prov, discovered[0]) {
		t.Fatalf("live picker already offered %s/%s before /connect", prov, discovered[0])
	}

	if !app.SubmitInput("/connect " + prov) {
		t.Fatalf("/connect %s rejected; the production connect handler is not wired", prov)
	}
	if !app.SecretPromptOpen() {
		t.Fatalf("/connect %s did not open the masked API-key prompt", prov)
	}
	app.SubmitSecretPromptForTest("sk-entered-at-the-prompt")

	cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
	if len(cmds) != 1 || cmds[0].Name != "connect" || cmds[0].Outcome != "success" || cmds[0].ErrorDetail != "" {
		t.Fatalf("disk slash_command events = %+v, want one {connect, success}", cmds)
	}

	data, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("read written settings: %v", err)
	}
	var composed map[string]any
	if err := yaml.Unmarshal(data, &composed); err != nil {
		t.Fatalf("unmarshal written settings: %v", err)
	}
	entries, err := provider.ParseProviders(composed)
	if err != nil {
		t.Fatalf("ParseProviders on the written settings: %v", err)
	}
	entry, ok := entries[prov]
	if !ok {
		t.Fatalf("provider %q absent after connect; entries=%v", prov, entries)
	}
	if entry.BaseURL != "https://api.openai.com/v1" {
		t.Errorf("base_url = %q, want the real Platform endpoint", entry.BaseURL)
	}
	if entry.APIKey != "sk-entered-at-the-prompt" {
		t.Errorf("api_key = %q, want the entered key persisted", entry.APIKey)
	}
	provMap, ok := composed["provider"].(map[string]any)[prov].(map[string]any)
	if !ok {
		t.Fatalf("provider %q missing from persisted settings mapping", prov)
	}
	if _, hasModels := provMap["models"]; hasModels {
		t.Errorf("persisted settings %q has a models key = %v, want none so models.yaml supplies the discovered ids", prov, provMap["models"])
	}

	mstore, err := config.ReadDiscoveredModels(config.DiscoveredModelsPath(settings))
	if err != nil {
		t.Fatalf("read models.yaml: %v", err)
	}
	var gotIDs []string
	for _, m := range mstore.Providers[prov].Models {
		gotIDs = append(gotIDs, m.ID)
	}
	if !slices.Equal(gotIDs, discovered) {
		t.Fatalf("models.yaml %s ids = %v, want every sanitized discovered id %v", prov, gotIDs, discovered)
	}

	for _, id := range discovered {
		if !pickerHas(prov, id) {
			t.Errorf("live picker lacks discovered %s/%s after /connect: %+v", prov, id, app.ModelPickerRows())
		}
	}

	tr := app.TranscriptText()
	if !strings.Contains(tr, "connected provider "+prov) {
		t.Errorf("transcript = %q, want a connected-provider notice", tr)
	}
	if strings.Contains(tr, "add its api_key in global settings") {
		t.Errorf("transcript tells the user to add an api_key after %s persisted it: %q", prov, tr)
	}
	for _, leak := range []string{"sk-", formerlyUnusable[0], formerlyUnusable[1]} {
		if strings.Contains(tr, leak) {
			t.Errorf("transcript leaked %q: %q", leak, tr)
		}
	}
}

func TestConnectCommand_ProductionWiring_OpenAIRefusesZeroUsable(t *testing.T) {
	const prov = "openai"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{
			{"id": ""},
			{"id": "some unknown model"},
		}})
	}))
	defer srv.Close()
	defer swapConnectDiscover(func(ctx context.Context, cfg provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		cfg.Entry.BaseURL = srv.URL
		return provider.DiscoverAPIKeyModels(ctx, cfg)
	})()

	ctx := context.Background()
	store := mkStore(t)
	home := t.TempDir()
	settings := SettingsPath(home)
	modelsPath := config.DiscoveredModelsPath(settings)

	if _, _, err := config.Persist(settings, config.KeyProviderPrefix+prov, yaml.MapSlice{
		{Key: "base_url", Value: "https://api.openai.com/v1"},
		{Key: "api_key", Value: "sk-prior-valid-key"},
	}); err != nil {
		t.Fatalf("seed prior settings: %v", err)
	}
	if err := config.UpdateDiscoveredModelsProvider(modelsPath, prov, config.DiscoveredProvider{
		Source: "seed",
		Models: []config.DiscoveredModel{{ID: "gpt-5.5"}},
	}); err != nil {
		t.Fatalf("seed prior models.yaml: %v", err)
	}
	priorModels, err := os.ReadFile(modelsPath)
	if err != nil {
		t.Fatalf("read seeded models.yaml: %v", err)
	}
	priorSettings, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("read seeded settings: %v", err)
	}
	var seedComposed map[string]any
	if err := yaml.Unmarshal(priorSettings, &seedComposed); err != nil {
		t.Fatalf("unmarshal seeded settings: %v", err)
	}

	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        "/launch",
		Session:          store,
		Config:           seedComposed,
		ConfigLayerPaths: []string{settings},
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	pickerHas := func(providerID, modelID string) bool {
		for _, row := range app.ModelPickerRows() {
			if row.Provider == providerID && row.ModelID == modelID {
				return true
			}
		}
		return false
	}
	if !pickerHas(prov, "gpt-5.5") {
		t.Fatalf("seeded %s/gpt-5.5 not offered before the zero-usable refusal; the prior cache was not loaded", prov)
	}

	if !app.SubmitInput("/connect " + prov) {
		t.Fatalf("/connect %s rejected; the production connect handler is not wired", prov)
	}
	if !app.SecretPromptOpen() {
		t.Fatalf("/connect %s did not open the masked API-key prompt", prov)
	}
	app.SubmitSecretPromptForTest("sk-entered-at-the-prompt")

	afterSettings, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("read settings after zero-usable refusal: %v", err)
	}
	if !slices.Equal(afterSettings, priorSettings) {
		t.Fatalf("settings changed after a zero-usable response:\nprior:\n%s\nafter:\n%s", priorSettings, afterSettings)
	}
	afterModels, err := os.ReadFile(modelsPath)
	if err != nil {
		t.Fatalf("read models.yaml after zero-usable refusal: %v", err)
	}
	if !slices.Equal(afterModels, priorModels) {
		t.Fatalf("models.yaml changed after a zero-usable response:\nprior:\n%s\nafter:\n%s", priorModels, afterModels)
	}
	cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
	if len(cmds) != 1 || cmds[0].Name != "connect" || cmds[0].Outcome != "error" {
		t.Fatalf("disk slash_command events = %+v, want one {connect, error}", cmds)
	}
	if !pickerHas(prov, "gpt-5.5") {
		t.Errorf("live picker dropped seeded %s/gpt-5.5 after a zero-usable response: %+v", prov, app.ModelPickerRows())
	}
	tr := app.TranscriptText()
	if strings.Contains(tr, "connected provider") {
		t.Errorf("transcript claims a connection on a zero-usable response: %q", tr)
	}
	if !strings.Contains(tr, "no usable models") {
		t.Errorf("transcript = %q, want the zero-usable refusal notice", tr)
	}
	if strings.Contains(tr, "sk-") {
		t.Errorf("transcript leaked a secret-shaped token: %q", tr)
	}
}

func TestConnectCommand_ProductionWiring_OpenAIFailedRefreshKeepsPriorCache(t *testing.T) {
	const prov = "openai"
	ctx := context.Background()
	store := mkStore(t)
	home := t.TempDir()
	settings := SettingsPath(home)
	modelsPath := config.DiscoveredModelsPath(settings)

	if _, _, err := config.Persist(settings, config.KeyProviderPrefix+prov, yaml.MapSlice{
		{Key: "base_url", Value: "https://api.openai.com/v1"},
		{Key: "api_key", Value: "sk-prior-valid-key"},
	}); err != nil {
		t.Fatalf("seed prior settings: %v", err)
	}
	if err := config.UpdateDiscoveredModelsProvider(modelsPath, prov, config.DiscoveredProvider{
		Source: "seed",
		Models: []config.DiscoveredModel{{ID: "gpt-5.5"}},
	}); err != nil {
		t.Fatalf("seed prior models.yaml: %v", err)
	}
	priorModels, err := os.ReadFile(modelsPath)
	if err != nil {
		t.Fatalf("read seeded models.yaml: %v", err)
	}
	seedData, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("read seeded settings: %v", err)
	}
	var seedComposed map[string]any
	if err := yaml.Unmarshal(seedData, &seedComposed); err != nil {
		t.Fatalf("unmarshal seeded settings: %v", err)
	}

	defer swapConnectDiscover(func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		return nil, errors.New("provider openai model discovery: HTTP 503")
	})()

	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        "/launch",
		Session:          store,
		Config:           seedComposed,
		ConfigLayerPaths: []string{settings},
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	pickerHas := func(providerID, modelID string) bool {
		for _, row := range app.ModelPickerRows() {
			if row.Provider == providerID && row.ModelID == modelID {
				return true
			}
		}
		return false
	}
	if !pickerHas(prov, "gpt-5.5") {
		t.Fatalf("seeded %s/gpt-5.5 not offered before the failed refresh; the prior cache was not loaded", prov)
	}

	if !app.SubmitInput("/connect " + prov) {
		t.Fatalf("/connect %s not handled; the production connect handler is not wired", prov)
	}
	if !app.SecretPromptOpen() {
		t.Fatalf("/connect %s did not open the masked API-key prompt", prov)
	}
	app.SubmitSecretPromptForTest("sk-new-key-that-fails")

	afterModels, err := os.ReadFile(modelsPath)
	if err != nil {
		t.Fatalf("read models.yaml after failed refresh: %v", err)
	}
	if !slices.Equal(afterModels, priorModels) {
		t.Fatalf("models.yaml changed after a failed refresh:\nprior:\n%s\nafter:\n%s", priorModels, afterModels)
	}
	if !pickerHas(prov, "gpt-5.5") {
		t.Errorf("live picker dropped seeded %s/gpt-5.5 after a failed refresh: %+v", prov, app.ModelPickerRows())
	}
	data, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if !slices.Equal(data, seedData) {
		t.Fatalf("settings changed after a failed refresh:\nprior:\n%s\nafter:\n%s", seedData, data)
	}
	var composed map[string]any
	if err := yaml.Unmarshal(data, &composed); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	cache, err := config.NewCache(composed, home, []string{settings})
	if err != nil {
		t.Fatalf("config.NewCache over seeded settings + store: %v", err)
	}
	if got := cache.SelectableCatalog().SupportedEffort(prov, "gpt-5.5"); len(got) == 0 {
		t.Errorf("fresh offline catalog does not expose %s/gpt-5.5 after a failed refresh", prov)
	}

	tr := app.TranscriptText()
	if strings.Contains(tr, "connected provider") {
		t.Errorf("transcript claims a connection on a failed refresh: %q", tr)
	}
	if strings.Contains(tr, "sk-") {
		t.Errorf("transcript leaked a secret-shaped token: %q", tr)
	}
	cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
	if len(cmds) != 1 || cmds[0].Name != "connect" || cmds[0].Outcome != "error" {
		t.Fatalf("disk slash_command events = %+v, want one {connect, error}", cmds)
	}
	if strings.Contains(cmds[0].ErrorDetail, "sk-") {
		t.Errorf("connect error_detail = %q, must carry no secret", cmds[0].ErrorDetail)
	}
}

// App state must be accessed through RunOnEventLoopForTest to keep it on the event-loop goroutine.
func startRunning(t *testing.T, result *BootstrapResult) *tui.App {
	t.Helper()
	app, _ := startRunningOnScreen(t, result)
	return app
}

func startRunningOnScreen(t *testing.T, result *BootstrapResult) (*tui.App, tcell.SimulationScreen) {
	t.Helper()
	screen := tcell.NewSimulationScreen("UTF-8")
	screen.SetSize(120, 40)
	appC := make(chan *tui.App, 1)
	startC := make(chan error, 1)
	restore := swapRunApp(func(app *tui.App) error {
		app.SetScreenFactoryForTest(func() (tcell.Screen, error) { return screen, nil })
		appC <- app
		return app.Run()
	})
	go func() { startC <- StartTUI(context.Background(), result, io.Discard) }()

	var app *tui.App
	select {
	case app = <-appC:
	case <-time.After(2 * time.Second):
		restore()
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
		restore()
	})
	return app, screen
}

func TestBlocked_ListsTheLiveGlobalEntriesOnTheEventLoop(t *testing.T) {
	home := declaredScopeDir(t)
	settings := SettingsPath(home)
	first, second, third := filepath.Join(home, "one"), filepath.Join(home, "two"), filepath.Join(home, "three")
	layers := blockedGlobalLayers(t, home, "", first, second)
	app := startRunning(t, &BootstrapResult{
		Home:             home,
		LaunchDir:        "/launch",
		Session:          mkStore(t),
		ConfigLayerPaths: []string{settings},
		SettingsLayers:   layers,
	})

	onLoop := func(what string, fn func()) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			app.RunOnEventLoopForTest(fn)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not finish on the event loop", what)
		}
	}
	openBlocked := func() string {
		t.Helper()
		var accepted bool
		var overlay string
		onLoop("/blocked", func() {
			accepted = app.SubmitInput("/blocked")
			overlay = app.BlockedOverlayText()
		})
		if !accepted {
			t.Fatal("/blocked rejected; the production registry did not bind the handler")
		}
		onLoop("closing /blocked", app.HandleEsc)
		return overlay
	}
	before, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}

	overlay := openBlocked()
	for _, path := range []string{first, second} {
		if want := path + "  (" + settings + ")"; !strings.Contains(overlay, want) {
			t.Errorf("overlay = %q, want the line %q", overlay, want)
		}
	}
	if strings.Contains(overlay, third) {
		t.Errorf("overlay = %q, lists %s before it was added", overlay, third)
	}
	after, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("opening /blocked changed %s:\nbefore:\n%s\nafter:\n%s", settings, before, after)
	}

	rewriteSettings(t, settings, blockedYAML(first, second, third))
	if overlay := openBlocked(); !strings.Contains(overlay, third+"  ("+settings+")") {
		t.Errorf("overlay after adding %s = %q, want it listed from %s", third, overlay, settings)
	}
}

func TestBlocked_RemoveAndAddChangeTheGlobalFileAndTheNextRead(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	home := declaredScopeDir(t)
	settings := writeGlobalSettings(t, home, string(GeneratedSettingsBytes()), 0o600)
	global, err := defaultLoadGlobalSettings(home)
	if err != nil {
		t.Fatalf("defaultLoadGlobalSettings: %v", err)
	}
	seedOpenAIDiscovered(t, settings, "gpt-5.5")
	ssh := filepath.Join(home, ".ssh")
	secret := filepath.Join(ssh, "id_rsa")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(secret, []byte(blockedSecret), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	read := readCall(t, secret)
	var round int32
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if i := atomic.AddInt32(&round, 1); i%2 == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, fmt.Sprintf("call_%d", i), read.name, read.args)))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := titledStore(t)
	app := startRunning(t, &BootstrapResult{
		Home:             home,
		LaunchDir:        home,
		ProjectRoot:      home,
		Session:          store,
		Model:            model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config:           headlessProviderConfig(),
		ConfigLayerPaths: []string{settings},
		SettingsLayers:   settingsLayerSnapshots(home, home, global, true, ConfigComposition{}),
		ToolRegistry:     &toolRegistryFactory{active: nil},
	})

	onLoop := func(what string, fn func()) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			app.RunOnEventLoopForTest(fn)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not finish on the event loop", what)
		}
	}
	onlyASlashCommandAdded := func(what string, before int) {
		t.Helper()
		added := store.Records()[before:]
		if len(added) != 1 {
			t.Fatalf("%s added %d session records (%+v), want only the slash_command", what, len(added), added)
		}
		if ev, ok := added[0].(sessions.Event); !ok || ev.Kind != events.KindSlashCommand {
			t.Fatalf("%s added %+v, want only the slash_command", what, added[0])
		}
	}
	throughBlocked := func(what string, act func() bool) {
		t.Helper()
		before := len(store.Records())
		var accepted, acted bool
		var notice string
		onLoop(what, func() {
			accepted = app.SubmitInput("/blocked")
			acted = act()
			notice = app.NoticeText()
			app.HandleEsc()
		})
		if !accepted || !acted {
			t.Fatalf("%s: /blocked accepted=%v, row acted on=%v", what, accepted, acted)
		}
		if notice != "" {
			t.Errorf("%s: notice = %q, want none", what, notice)
		}
		onlyASlashCommandAdded(what, before)
	}
	readSecret := func(what string) string {
		t.Helper()
		before := len(messagesByRole(store, "tool"))
		var accepted bool
		onLoop(what, func() { accepted = app.SubmitInput("read the key") })
		if !accepted {
			t.Fatalf("%s: prompt rejected", what)
		}
		done := make(chan struct{})
		go func() {
			turns.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: the turn did not finish", what)
		}
		results := messagesByRole(store, "tool")
		if len(results) != before+1 {
			t.Fatalf("%s: tool messages = %d, want %d", what, len(results), before+1)
		}
		return results[before].Content.Text()
	}
	keysSection := func() string {
		t.Helper()
		data, err := os.ReadFile(settings)
		if err != nil {
			t.Fatalf("read settings: %v", err)
		}
		text := string(data)
		start := strings.Index(text, "  # Keys and passwords\n")
		if start < 0 {
			t.Fatalf("settings lost the # Keys and passwords heading:\n%s", text)
		}
		section := text[start+1:]
		if end := strings.Index(section, "\n  # "); end >= 0 {
			section = section[:end]
		}
		return section
	}
	refusals := func() []events.PermissionMatched {
		t.Helper()
		var refused []events.PermissionMatched
		for _, m := range decodePermissionMatched(t, store) {
			if m.OutcomeSource == "blocked_path" {
				refused = append(refused, m)
			}
		}
		return refused
	}

	if !strings.Contains(keysSection(), `- "~/.ssh"`) {
		t.Fatalf("precondition: generated settings do not block ~/.ssh under # Keys and passwords:\n%s", keysSection())
	}

	throughBlocked("removing ~/.ssh", func() bool { return app.RemoveBlockedPathForTest(ssh) })
	data, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if strings.Contains(string(data), `"~/.ssh"`) {
		t.Errorf("settings still list ~/.ssh after the removal:\n%s", data)
	}
	if got := readSecret("read after removal"); !strings.Contains(got, blockedSecret) {
		t.Errorf("read after removal = %q, want the file content", got)
	}
	if refused := refusals(); len(refused) != 0 {
		t.Errorf("blocked_path records after removal = %#v, want none", refused)
	}

	throughBlocked("adding ~/.ssh", func() bool { return app.AddBlockedPathForTest("~/.ssh") })
	if !strings.Contains(keysSection(), `- "~/.ssh"`) {
		t.Errorf("settings do not list ~/.ssh under # Keys and passwords after the add:\n%s", keysSection())
	}
	if got := readSecret("read after add"); strings.Contains(got, blockedSecret) {
		t.Errorf("read after add = %q, want a refusal", got)
	}
	want := blockedPathDenial(filetools.ReadToolName, ssh, settings)
	if refused := refusals(); len(refused) != 1 || refused[0] != want {
		t.Errorf("blocked_path records = %#v, want exactly one %#v", refused, want)
	}
}

func TestModelPicker_RefreshProductionWiring(t *testing.T) {
	const prov = "openrouter"
	stale := time.Now().Add(-4 * 24 * time.Hour).UTC().Format(time.RFC3339)

	seedStale := func(t *testing.T, modelsPath string) {
		if err := config.UpdateDiscoveredModelsProvider(modelsPath, prov, config.DiscoveredProvider{
			RefreshedAt: stale,
			Models:      []config.DiscoveredModel{{ID: "openrouter-old"}},
		}); err != nil {
			t.Fatalf("seed stale models.yaml: %v", err)
		}
	}
	pickerHas := func(app *tui.App, providerID, modelID string) bool {
		var found bool
		app.RunOnEventLoopForTest(func() {
			for _, row := range app.ModelPickerRows() {
				if row.Provider == providerID && row.ModelID == modelID {
					found = true
					return
				}
			}
		})
		return found
	}
	pickerStatus := func(app *tui.App) string {
		var text string
		app.RunOnEventLoopForTest(func() { text = app.ModelPickerStatusText() })
		return text
	}

	t.Run("stale provider auto-refreshes live rows", func(t *testing.T) {
		var hits atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if r.URL.Path != "/models" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "openrouter-new"}}})
		}))
		defer srv.Close()

		home := t.TempDir()
		settings := SettingsPath(home)
		modelsPath := config.DiscoveredModelsPath(settings)
		seedStale(t, modelsPath)

		app := startRunning(t, &BootstrapResult{
			Home:             home,
			LaunchDir:        "/launch",
			Session:          mkStore(t),
			Config:           map[string]any{"provider": map[string]any{prov: map[string]any{"base_url": srv.URL, "api_key": "or-key"}}},
			ConfigLayerPaths: []string{settings},
		})

		if !pickerHas(app, prov, "openrouter-old") {
			t.Fatalf("seeded %s/openrouter-old not offered before refresh; prior cache not loaded", prov)
		}
		var opened bool
		app.RunOnEventLoopForTest(func() { opened = app.PressCtrlM() })
		if !opened {
			t.Fatalf("CTRL-M did not open the model picker")
		}

		deadline := time.Now().Add(3 * time.Second)
		for !pickerHas(app, prov, "openrouter-new") {
			if time.Now().After(deadline) {
				t.Fatalf("live picker never showed the refreshed openrouter-new")
			}
			time.Sleep(5 * time.Millisecond)
		}
		if pickerHas(app, prov, "openrouter-old") {
			t.Errorf("refreshed picker still offers the stale openrouter-old")
		}
		var open bool
		app.RunOnEventLoopForTest(func() { open = app.ModelPickerOpen() })
		if !open {
			t.Errorf("picker closed during the background refresh; it must stay open")
		}
		if hits.Load() == 0 {
			t.Errorf("provider /models endpoint never hit; the real refresher did not run")
		}
		mstore, err := config.ReadDiscoveredModels(modelsPath)
		if err != nil {
			t.Fatalf("read models.yaml after refresh: %v", err)
		}
		var gotIDs []string
		for _, m := range mstore.Providers[prov].Models {
			gotIDs = append(gotIDs, m.ID)
		}
		if !slices.Equal(gotIDs, []string{"openrouter-new"}) {
			t.Errorf("models.yaml %s ids = %v, want [openrouter-new]", prov, gotIDs)
		}
	})

	t.Run("failed refresh keeps prior rows and leaks no key", func(t *testing.T) {
		var hits atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		home := t.TempDir()
		settings := SettingsPath(home)
		modelsPath := config.DiscoveredModelsPath(settings)
		seedStale(t, modelsPath)
		priorModels, err := os.ReadFile(modelsPath)
		if err != nil {
			t.Fatalf("read seeded models.yaml: %v", err)
		}

		app := startRunning(t, &BootstrapResult{
			Home:             home,
			LaunchDir:        "/launch",
			Session:          mkStore(t),
			Config:           map[string]any{"provider": map[string]any{prov: map[string]any{"base_url": srv.URL, "api_key": "or-secret-key"}}},
			ConfigLayerPaths: []string{settings},
		})

		if !pickerHas(app, prov, "openrouter-old") {
			t.Fatalf("seeded %s/openrouter-old not offered before refresh", prov)
		}
		var opened bool
		app.RunOnEventLoopForTest(func() { opened = app.PressCtrlM() })
		if !opened {
			t.Fatalf("CTRL-M did not open the model picker")
		}

		deadline := time.Now().Add(3 * time.Second)
		var status string
		for {
			status = pickerStatus(app)
			if strings.Contains(status, "could not refresh") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("picker failure status never appeared; last status = %q", status)
			}
			time.Sleep(5 * time.Millisecond)
		}
		wantStatus := "could not refresh " + prov + " models"
		if status != wantStatus {
			t.Errorf("picker failure status = %q, want %q", status, wantStatus)
		}
		if strings.Contains(status, "\n") {
			t.Errorf("picker failure status spans multiple lines: %q", status)
		}
		if strings.Contains(status, "or-secret-key") {
			t.Errorf("picker failure status %q leaked the configured api key", status)
		}
		if hits.Load() == 0 {
			t.Errorf("provider /models endpoint never hit; the refresher did not run")
		}
		if !pickerHas(app, prov, "openrouter-old") {
			t.Errorf("failed refresh dropped the prior %s/openrouter-old", prov)
		}
		if pickerHas(app, prov, "openrouter-new") {
			t.Errorf("failed refresh surfaced a new model; want prior rows only")
		}
		afterModels, err := os.ReadFile(modelsPath)
		if err != nil {
			t.Fatalf("read models.yaml after failed refresh: %v", err)
		}
		if !slices.Equal(afterModels, priorModels) {
			t.Fatalf("models.yaml changed after a failed refresh:\nprior:\n%s\nafter:\n%s", priorModels, afterModels)
		}
		if strings.Contains(string(afterModels), "or-secret-key") {
			t.Errorf("models.yaml leaked the configured api key")
		}
	})

	t.Run("missing-cache provider refreshes on open", func(t *testing.T) {
		var hits atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if r.URL.Path != "/models" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "openrouter-fresh"}}})
		}))
		defer srv.Close()

		home := t.TempDir()
		settings := SettingsPath(home)
		modelsPath := config.DiscoveredModelsPath(settings)

		app := startRunning(t, &BootstrapResult{
			Home:             home,
			LaunchDir:        "/launch",
			Session:          mkStore(t),
			Config:           map[string]any{"provider": map[string]any{prov: map[string]any{"base_url": srv.URL, "api_key": "or-key"}}},
			ConfigLayerPaths: []string{settings},
		})

		var opened bool
		app.RunOnEventLoopForTest(func() { opened = app.PressCtrlM() })
		if !opened {
			t.Fatalf("CTRL-M did not open the model picker")
		}

		deadline := time.Now().Add(3 * time.Second)
		for !pickerHas(app, prov, "openrouter-fresh") {
			if time.Now().After(deadline) {
				t.Fatalf("live picker never showed the discovered openrouter-fresh for a missing-cache provider")
			}
			time.Sleep(5 * time.Millisecond)
		}
		if hits.Load() == 0 {
			t.Errorf("provider /models endpoint never hit; the missing-cache refresher did not run")
		}
		var open bool
		app.RunOnEventLoopForTest(func() { open = app.ModelPickerOpen() })
		if !open {
			t.Errorf("picker closed during the background refresh; it must stay open")
		}
		mstore, err := config.ReadDiscoveredModels(modelsPath)
		if err != nil {
			t.Fatalf("read models.yaml after refresh: %v", err)
		}
		var gotIDs []string
		for _, m := range mstore.Providers[prov].Models {
			gotIDs = append(gotIDs, m.ID)
		}
		if !slices.Equal(gotIDs, []string{"openrouter-fresh"}) {
			t.Errorf("models.yaml %s ids = %v, want [openrouter-fresh]", prov, gotIDs)
		}
	})
}

// swapConnectDiscover replaces the /connect key-validation seam for a test and returns
// a restore closure to defer.
func swapConnectDiscover(f func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error)) func() {
	prev := connectDiscoverModels
	connectDiscoverModels = f
	return func() { connectDiscoverModels = prev }
}

func openRouterRoutingCache(t *testing.T, home, settingsYAML string) (*config.Cache, string) {
	t.Helper()
	settings := writeGlobalSettings(t, home, settingsYAML, 0o600)
	_, raw, _, err := config.LoadYAML(settings)
	if err != nil {
		t.Fatalf("load seeded settings: %v", err)
	}
	composed, err := config.Compose(raw, nil)
	if err != nil {
		t.Fatalf("config.Compose: %v", err)
	}
	cache, err := config.NewCache(composed, home, []string{settings})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	return cache, settings
}

func reconnectProvider(t *testing.T, home string, cache *config.Cache, id string) {
	t.Helper()
	defer swapConnectDiscover(func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		return []provider.DiscoveredConfiguredModel{{ID: id + "-model"}}, nil
	})()
	var connectErr error
	newConnectDeps(tui.New(nil), home, cache).Connect(id, "sk-reconnected", func(err error) { connectErr = err })
	if connectErr != nil {
		t.Fatalf("Connect(%s) error = %v, want nil", id, connectErr)
	}
}

func persistedProviderEntry(t *testing.T, settings, id string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if _, _, err := config.ValidateGlobalSettingsBytes(data, settings); err != nil {
		t.Fatalf("persisted settings fail validation: %v\n%s", err, data)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	entry, ok := doc["provider"].(map[string]any)[id].(map[string]any)
	if !ok {
		t.Fatalf("provider.%s missing from persisted settings:\n%s", id, data)
	}
	return entry
}

func TestConnectDeps_OpenRouterReconnectPreservesRouting(t *testing.T) {
	cases := []struct {
		name        string
		routingYAML string
		want        provider.Routing
		wantOnDisk  map[string]any
		wantRequest map[string]any
	}{
		{
			name:        "full routing block",
			routingYAML: "    routing:\n      sort: throughput\n      data_collection: deny\n      require_parameters: true\n",
			want:        provider.Routing{Sort: "throughput", DataCollection: "deny", RequireParameters: true},
			wantOnDisk:  map[string]any{"sort": "throughput", "data_collection": "deny", "require_parameters": true},
			wantRequest: map[string]any{"sort": "throughput", "data_collection": "deny", "require_parameters": true},
		},
		{
			name:        "partial routing block",
			routingYAML: "    routing:\n      data_collection: allow\n      require_parameters: false\n",
			want:        provider.Routing{DataCollection: "allow"},
			wantOnDisk:  map[string]any{"data_collection": "allow", "require_parameters": false},
			wantRequest: map[string]any{"data_collection": "allow"},
		},
		{
			name:        "max_price map",
			routingYAML: "    routing:\n      sort: throughput\n      max_price:\n        z/model: { completion: 2 }\n        m: { completion: 1.5, prompt: 0 }\n",
			want: provider.Routing{Sort: "throughput", MaxPrice: map[string]provider.MaxPrice{
				"m":       {Prompt: 0, Completion: 1.5, HasPrompt: true, HasCompletion: true},
				"z/model": {Completion: 2, HasCompletion: true},
			}},
			wantOnDisk: map[string]any{"sort": "throughput", "max_price": map[string]any{
				"m":       map[string]any{"prompt": uint64(0), "completion": 1.5},
				"z/model": map[string]any{"completion": uint64(2)},
			}},
			wantRequest: map[string]any{"sort": "throughput", "max_price": map[string]any{"prompt": float64(0), "completion": 1.5}},
		},
		{
			name:        "empty max_price map",
			routingYAML: "    routing:\n      sort: latency\n      max_price: {}\n",
			want:        provider.Routing{Sort: "latency"},
			wantOnDisk:  map[string]any{"sort": "latency", "max_price": map[string]any{}},
			wantRequest: map[string]any{"sort": "latency"},
		},
		{
			name: "no routing block",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			seed := "provider:\n  openrouter:\n    base_url: https://openrouter.ai/api/v1\n    api_key: sk-prior\n" + tc.routingYAML
			cache, settings := openRouterRoutingCache(t, home, seed)

			reconnectProvider(t, home, cache, "openrouter")

			if got, _ := os.ReadFile(settings); string(got) != strings.Replace(seed, "sk-prior", "sk-reconnected", 1) {
				t.Fatalf("reconnect changed more than the api key:\n%s", got)
			}
			entry := persistedProviderEntry(t, settings, "openrouter")
			gotOnDisk, hasRouting := entry["routing"]
			if tc.wantOnDisk == nil {
				if hasRouting {
					t.Fatalf("persisted routing = %v, want no routing key when none was configured", gotOnDisk)
				}
			} else if !reflect.DeepEqual(gotOnDisk, tc.wantOnDisk) {
				t.Fatalf("persisted routing = %#v, want exactly %#v", gotOnDisk, tc.wantOnDisk)
			}

			live, ok := cache.Provider("openrouter")
			if !ok || live.APIKey != "sk-reconnected" || !reflect.DeepEqual(live.Routing, tc.want) {
				t.Fatalf("live cache entry = %+v (ok=%v), want api key sk-reconnected and routing %+v", live, ok, tc.want)
			}
			if got := openRouterRequestProviderObject(t, cache); !reflect.DeepEqual(got, tc.wantRequest) {
				t.Fatalf("next request provider object = %#v, want %#v", got, tc.wantRequest)
			}
		})
	}
}

func TestConnectDeps_OpenRouterReconnectKeepsDiskRoutingAndSessionRouting(t *testing.T) {
	home := t.TempDir()
	cache, settings := openRouterRoutingCache(t, home, "provider:\n  openrouter:\n    base_url: https://openrouter.ai/api/v1\n    api_key: sk-prior\n    auth_header:\n      name: X-Key\n      value: \"{api_key}\"\n    routing:\n      sort: latency\n")
	const edited = "# edited after startup\nprovider:\n  openrouter:\n    base_url: https://openrouter.ai/api/v1\n    api_key: sk-prior # old key\n    # header note\n    auth_header: {name: X-Other, value: \"{api_key}\"}\n    routing:\n      # privacy\n      data_collection: deny\n      require_parameters: false\n"
	writeGlobalSettings(t, home, edited, 0o600)

	reconnectProvider(t, home, cache, "openrouter")

	if got, _ := os.ReadFile(settings); string(got) != strings.Replace(edited, "sk-prior", "sk-reconnected", 1) {
		t.Fatalf("persisted settings = %q, want the edited file with only the api key replaced", got)
	}
	live, _ := cache.Provider("openrouter")
	if !reflect.DeepEqual(live.Routing, provider.Routing{Sort: "latency"}) {
		t.Fatalf("live routing = %+v, want the session's routing", live.Routing)
	}
	if live.AuthHeader == nil || live.AuthHeader.Name != "X-Key" || live.APIKey != "sk-reconnected" {
		t.Fatalf("live entry = %+v, want the session auth header and the new key", live)
	}
	if got := openRouterRequestProviderObject(t, cache); !reflect.DeepEqual(got, map[string]any{"sort": "latency"}) {
		t.Fatalf("next request provider object = %#v, want the session routing", got)
	}
}

func TestConnectDeps_NonOpenRouterReconnectReplacesEntry(t *testing.T) {
	home := t.TempDir()
	cache, settings := openRouterRoutingCache(t, home, "provider:\n  venice:\n    base_url: https://api.venice.ai/api/v1\n    api_key: sk-prior\n    auth_header:\n      name: X-Key\n      value: \"{api_key}\"\n")

	reconnectProvider(t, home, cache, "venice")

	entry := persistedProviderEntry(t, settings, "venice")
	if want := map[string]any{"base_url": "https://api.venice.ai/api/v1", "api_key": "sk-reconnected"}; !reflect.DeepEqual(entry, want) {
		t.Fatalf("persisted venice entry = %#v, want the whole-entry replacement %#v", entry, want)
	}
	if live, _ := cache.Provider("venice"); live.AuthHeader != nil || live.APIKey != "sk-reconnected" {
		t.Fatalf("live venice entry = %+v, want only the new connection fields", live)
	}
}

func capabilityMapEqual(got, want map[string]any) bool {
	if len(got) != len(want) {
		return false
	}
	for k, wv := range want {
		gv, ok := got[k]
		if !ok || fmt.Sprint(gv) != fmt.Sprint(wv) {
			return false
		}
	}
	return true
}

// TestConnectCommand_ProductionWiring_DiscoverySuccess drives /connect venice and
// /connect openrouter through the real StartTUI submit path against a fake /models
// endpoint. A successful connect validates the entered key by discovery, persists
// base_url + the real api key to global settings with NO discovered models list, writes
// the sanitized discovered ids to the system-owned models.yaml store, records a durable
// slash_command{connect, success}, and makes the discovered ids selectable in the running
// picker without a restart — all read back from disk.
func TestConnectCommand_ProductionWiring_DiscoverySuccess(t *testing.T) {
	for _, prov := range []struct {
		id, baseURL     string
		efforts         []string
		supportedParams []string
		wantEfforts     []string
	}{
		{"venice", "https://api.venice.ai/api/v1", []string{"low", "medium", "high", "max"}, nil, []string{"low", "medium", "high", "max"}},
		{"openrouter", "https://openrouter.ai/api/v1", nil, []string{"reasoning", "tools"}, []string{provider.EffortNoReasoning}},
	} {
		t.Run(prov.id, func(t *testing.T) {
			discovered := []string{prov.id + "-model-a", prov.id + "-model-b"}
			// Fake /models endpoint: the real discovery call runs against it, so the test
			// exercises URL-building and the HTTP path, not a stubbed result.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/models" {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				if got := r.Header.Get("Authorization"); got != "Bearer sk-entered-at-the-prompt" {
					http.Error(w, "bad auth", http.StatusUnauthorized)
					return
				}
				model0 := map[string]any{
					"id":       discovered[0],
					"created":  1700000000,
					"owned_by": "acme",
					"api_key":  "sk-should-not-persist",
				}
				if prov.efforts != nil {
					model0["model_spec"] = map[string]any{"capabilities": map[string]any{
						"supportsReasoningEffort": true,
						"reasoningEffortOptions":  prov.efforts,
						"defaultReasoningEffort":  "medium",
						"supportsTools":           true,
						"secret_token":            "sk-nope",
					}}
				}
				switch prov.id {
				case "venice":
					caps := model0["model_spec"].(map[string]any)["capabilities"].(map[string]any)
					caps["supportsVision"] = true
					caps["supportsMultipleImages"] = true
					caps["maxImages"] = 3
					caps["supportsFunctionCalling"] = true
				case "openrouter":
					model0["architecture"] = map[string]any{
						"input_modalities": []any{"text", "image"},
						"tokenizer":        "GPT",
					}
					if prov.supportedParams != nil {
						model0["supported_parameters"] = prov.supportedParams
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": []any{model0, map[string]any{"id": discovered[1]}},
				})
			}))
			defer srv.Close()
			var app *tui.App
			var progressAtDiscover string
			// Point discovery at the fake endpoint while leaving the real base_url (the
			// value persisted to settings) intact.
			defer swapConnectDiscover(func(ctx context.Context, cfg provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
				if cfg.ProviderName != prov.id {
					return nil, fmt.Errorf("test discovery provider = %q, want %q", cfg.ProviderName, prov.id)
				}
				if cfg.Entry.BaseURL != prov.baseURL {
					return nil, fmt.Errorf("test discovery base_url = %q, want %q", cfg.Entry.BaseURL, prov.baseURL)
				}
				if cfg.Entry.APIKey != "sk-entered-at-the-prompt" {
					return nil, fmt.Errorf("test discovery api key = %q, want entered key", cfg.Entry.APIKey)
				}
				if app != nil {
					progressAtDiscover = app.TranscriptText()
				}
				cfg.Entry.BaseURL = srv.URL
				return provider.DiscoverAPIKeyModels(ctx, cfg)
			})()

			ctx := context.Background()
			store := mkStore(t)
			home := t.TempDir()
			// ConfigLayerPaths[0] is the global settings file in production, and the
			// cache derives its models.yaml path from it — set it so the live picker
			// refresh reads the store /connect writes beside the settings file.
			result := &BootstrapResult{
				Home:             home,
				LaunchDir:        "/launch",
				Session:          store,
				ConfigLayerPaths: []string{SettingsPath(home)},
			}
			var restore func()
			app, restore = startCaptured(t, ctx, result, io.Discard)
			defer restore()

			pickerHas := func(providerID, modelID string) bool {
				for _, row := range app.ModelPickerRows() {
					if row.Provider == providerID && row.ModelID == modelID {
						return true
					}
				}
				return false
			}
			if pickerHas(prov.id, discovered[0]) {
				t.Fatalf("live picker already offered %s/%s before /connect", prov.id, discovered[0])
			}

			if !app.SubmitInput("/connect " + prov.id) {
				t.Fatalf("/connect %s rejected; the production connect handler is not wired", prov.id)
			}
			if !app.SecretPromptOpen() {
				t.Fatalf("/connect %s did not open the masked API-key prompt", prov.id)
			}
			app.SubmitSecretPromptForTest("sk-entered-at-the-prompt")

			// Durable slash_command{connect, success}, read back from disk.
			cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
			if len(cmds) != 1 || cmds[0].Name != "connect" || cmds[0].Outcome != "success" || cmds[0].ErrorDetail != "" {
				t.Fatalf("disk slash_command events = %+v, want one {connect, success}", cmds)
			}

			// Settings: base_url + the entered api key, and NO discovered models list.
			settings := SettingsPath(home)
			data, err := os.ReadFile(settings)
			if err != nil {
				t.Fatalf("read written settings: %v", err)
			}
			var composed map[string]any
			if err := yaml.Unmarshal(data, &composed); err != nil {
				t.Fatalf("unmarshal written settings: %v", err)
			}
			entries, err := provider.ParseProviders(composed)
			if err != nil {
				t.Fatalf("ParseProviders on the written settings: %v", err)
			}
			entry, ok := entries[prov.id]
			if !ok {
				t.Fatalf("provider %q absent after connect; entries=%v", prov.id, entries)
			}
			if entry.BaseURL != prov.baseURL {
				t.Errorf("base_url = %q, want the real %q (not the fake endpoint)", entry.BaseURL, prov.baseURL)
			}
			if entry.APIKey != "sk-entered-at-the-prompt" {
				t.Errorf("api_key = %q, want the entered key persisted", entry.APIKey)
			}
			provMap, ok := composed["provider"].(map[string]any)[prov.id].(map[string]any)
			if !ok {
				t.Fatalf("provider %q missing from persisted settings mapping", prov.id)
			}
			if _, hasModels := provMap["models"]; hasModels {
				t.Errorf("persisted settings %q has a models key = %v; /connect must omit it so models.yaml supplies discovered ids", prov.id, provMap["models"])
			}

			// models.yaml: exactly the discovered ids, read back from disk.
			mstore, err := config.ReadDiscoveredModels(config.DiscoveredModelsPath(settings))
			if err != nil {
				t.Fatalf("read models.yaml: %v", err)
			}
			var gotIDs []string
			for _, m := range mstore.Providers[prov.id].Models {
				gotIDs = append(gotIDs, m.ID)
			}
			if !slices.Equal(gotIDs, discovered) {
				t.Errorf("models.yaml %s ids = %v, want discovered %v", prov.id, gotIDs, discovered)
			}

			wantMods := map[string][]string{"venice": {"image"}, "openrouter": {"text", "image"}}
			wantCaps := map[string]map[string]any{
				"venice": {
					"supportsReasoningEffort": true,
					"reasoningEffortOptions":  []any{"low", "medium", "high", "max"},
					"defaultReasoningEffort":  "medium",
					"supportsMultipleImages":  true,
					"maxImages":               3,
					"supportsFunctionCalling": true,
				},
				"openrouter": {"supportedParameters": []any{"reasoning", "tools"}},
			}
			firstModel := mstore.Providers[prov.id].Models[0]
			if !slices.Equal(firstModel.InputModalities, wantMods[prov.id]) {
				t.Errorf("models.yaml %s %s input_modalities = %v, want %v", prov.id, firstModel.ID, firstModel.InputModalities, wantMods[prov.id])
			}
			if !capabilityMapEqual(firstModel.Capabilities, wantCaps[prov.id]) {
				t.Errorf("models.yaml %s %s capabilities = %v, want exactly %v (unmodeled/secret-shaped provider fields must not persist)", prov.id, firstModel.ID, firstModel.Capabilities, wantCaps[prov.id])
			}

			if prov.efforts != nil {
				if s, _ := firstModel.Capabilities["supportsReasoningEffort"].(bool); !s {
					t.Errorf("models.yaml %s %s capabilities = %v, want supportsReasoningEffort true persisted", prov.id, firstModel.ID, firstModel.Capabilities)
				}
			}
			cache, err := config.NewCache(composed, home, []string{settings})
			if err != nil {
				t.Fatalf("config.NewCache over written settings: %v", err)
			}
			if got := cache.SelectableCatalog().SupportedEffort(prov.id, discovered[0]); !slices.Equal(got, prov.wantEfforts) {
				t.Errorf("live cache SupportedEffort(%s, %s) = %v, want %v", prov.id, discovered[0], got, prov.wantEfforts)
			}

			wantChecking := "checking the " + prov.id + " API key by loading its models"
			if !strings.Contains(progressAtDiscover, wantChecking) {
				t.Errorf("progress before /models = %q, want %q model-loading progress for %s", progressAtDiscover, wantChecking, prov.id)
			}
			tr := app.TranscriptText()
			if !strings.Contains(tr, "connected provider "+prov.id) {
				t.Errorf("transcript = %q, want a connected-provider notice", tr)
			}
			if !strings.Contains(tr, "the API key validated and discovered models are ready to use") {
				t.Errorf("transcript = %q, want success copy confirming the key validated and models are ready", tr)
			}
			if strings.Contains(app.TranscriptText(), "add its api_key in global settings") {
				t.Errorf("transcript tells the user to add an api_key after %s persisted it: %q", prov.id, app.TranscriptText())
			}
			if strings.Contains(app.TranscriptText(), "sk-") {
				t.Errorf("transcript leaked a secret-shaped token: %q", app.TranscriptText())
			}

			// The running picker offers the discovered ids now, refreshed from the same
			// models.yaml just written — not left stale until a restart.
			if !pickerHas(prov.id, discovered[0]) {
				t.Errorf("live picker lacks %s/%s after /connect: %+v", prov.id, discovered[0], app.ModelPickerRows())
			}
		})
	}
}

func TestConnectCommand_ProductionWiring_VeniceProgressDrawsBeforeDiscovery(t *testing.T) {
	const key = "sk-entered-at-the-prompt"
	started := make(chan struct{})
	release := make(chan struct{})
	defer swapConnectDiscover(func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		close(started)
		<-release
		return []provider.DiscoveredConfiguredModel{{ID: "venice-model-a"}}, nil
	})()

	store := mkStore(t)
	home := t.TempDir()
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        "/launch",
		Session:          store,
		ConfigLayerPaths: []string{SettingsPath(home)},
	}
	screen := tcell.NewSimulationScreen("UTF-8")
	screen.SetSize(120, 40)
	appC := make(chan *tui.App, 1)
	startC := make(chan error, 1)
	defer swapRunApp(func(app *tui.App) error {
		app.SetScreenFactoryForTest(func() (tcell.Screen, error) { return screen, nil })
		appC <- app
		return app.Run()
	})()
	go func() { startC <- StartTUI(context.Background(), result, io.Discard) }()

	var app *tui.App
	select {
	case app = <-appC:
	case <-time.After(2 * time.Second):
		t.Fatal("StartTUI did not start the simulation event loop")
	}
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
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

	submitted := make(chan bool, 1)
	go func() {
		app.RunOnEventLoopForTest(func() {
			if !app.SubmitInput("/connect venice") || !app.SecretPromptOpen() {
				submitted <- false
				return
			}
			app.SubmitSecretPromptForTest(key)
			submitted <- true
		})
	}()
	select {
	case ok := <-submitted:
		if !ok {
			t.Fatal("production /connect did not open the Venice API-key prompt")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("production /connect did not submit on the event loop")
	}

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("Venice discovery did not start")
	}
	cells, width, height := screen.GetContents()
	var rendered strings.Builder
	for row := 0; row < height; row++ {
		for col := 0; col < width; col++ {
			rendered.WriteString(string(cells[row*width+col].Runes))
		}
		rendered.WriteByte('\n')
	}
	if got := rendered.String(); !strings.Contains(got, "checking the venice API key by loading its models") {
		t.Fatalf("rendered progress = %q, want Venice model-loading notice", got)
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		var transcript string
		app.RunOnEventLoopForTest(func() { transcript = app.TranscriptText() })
		if strings.Contains(transcript, "connected provider venice; the API key validated and discovered models are ready to use") {
			if strings.Contains(transcript, key) {
				t.Fatalf("transcript leaked the API key: %q", transcript)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("transcript = %q, want Venice success after discovery completes", transcript)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
	if len(cmds) != 1 || cmds[0].Name != "connect" || cmds[0].Outcome != "success" {
		t.Fatalf("disk slash_command events = %+v, want one {connect, success}", cmds)
	}
}

// TestConnectCommand_ProductionWiring_DiscoveryFailure drives /connect venice with a
// key the endpoint rejects: the connection is refused before any durable write, so
// settings and models.yaml are never created, the live catalog is not mutated, a durable
// slash_command{connect, error} is recorded, and the secret-free notice leaks no key.
func TestConnectCommand_ProductionWiring_DiscoveryFailure(t *testing.T) {
	for _, prov := range []string{"venice", "openrouter"} {
		t.Run(prov, func(t *testing.T) {
			var app *tui.App
			var progressAtDiscover string
			defer swapConnectDiscover(func(ctx context.Context, cfg provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
				if app != nil {
					progressAtDiscover = app.TranscriptText()
				}
				return nil, errors.New("provider " + prov + " model discovery: HTTP 401")
			})()

			ctx := context.Background()
			store := mkStore(t)
			home := t.TempDir()
			result := &BootstrapResult{
				Home:             home,
				LaunchDir:        "/launch",
				Session:          store,
				ConfigLayerPaths: []string{SettingsPath(home)},
			}
			var restore func()
			app, restore = startCaptured(t, ctx, result, io.Discard)
			defer restore()

			if !app.SubmitInput("/connect " + prov) {
				t.Fatalf("/connect %s rejected; the production connect handler is not wired", prov)
			}
			if !app.SecretPromptOpen() {
				t.Fatalf("/connect %s did not open the masked API-key prompt", prov)
			}
			app.SubmitSecretPromptForTest("sk-rejected-key")

			if _, err := os.Stat(SettingsPath(home)); !os.IsNotExist(err) {
				t.Fatalf("settings stat err = %v, want not-exist (no write on validation failure)", err)
			}
			if _, err := os.Stat(config.DiscoveredModelsPath(SettingsPath(home))); !os.IsNotExist(err) {
				t.Fatalf("models.yaml stat err = %v, want not-exist (no store write on validation failure)", err)
			}
			cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
			if len(cmds) != 1 || cmds[0].Name != "connect" || cmds[0].Outcome != "error" {
				t.Fatalf("disk slash_command events = %+v, want one {connect, error}", cmds)
			}
			for _, row := range app.ModelPickerRows() {
				if row.Provider == prov {
					t.Errorf("%s became selectable after a failed validation: %+v", prov, row)
				}
			}
			if strings.Contains(app.TranscriptText(), "sk-") {
				t.Errorf("transcript leaked a secret-shaped token: %q", app.TranscriptText())
			}
			if strings.Contains(app.TranscriptText(), "connected provider") {
				t.Errorf("transcript claims a connection on a failed validation")
			}
			wantChecking := "checking the " + prov + " API key by loading its models"
			if !strings.Contains(progressAtDiscover, wantChecking) {
				t.Errorf("progress before /models = %q, want %q before the rejection", progressAtDiscover, wantChecking)
			}
		})
	}
}

// TestConnectCommand_ProductionWiring_BarePickerSelection drives a bare /connect through
// the real StartTUI submit path: it opens the production provider picker, records no
// slash_command and writes no settings until a row is selected, then selection enters
// the same masked-key direct connect flow as /connect <provider>.
func TestConnectCommand_ProductionWiring_BarePickerSelection(t *testing.T) {
	defer swapConnectDiscover(func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		return []provider.DiscoveredConfiguredModel{{ID: "gpt-5.5"}}, nil
	})()
	ctx := context.Background()
	store := mkStore(t)
	home := t.TempDir()
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        "/launch",
		Session:          store,
		ConfigLayerPaths: []string{SettingsPath(home)},
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("/connect") {
		t.Fatal("bare /connect should be accepted after opening the picker")
	}

	if app.SecretPromptOpen() {
		t.Fatal("bare /connect opened the masked prompt before a provider was selected")
	}
	if !app.ConnectPickerOpen() {
		t.Fatal("bare /connect did not open the provider picker")
	}
	rows := app.ConnectPickerRows()
	if len(rows) != 3 {
		t.Fatalf("connect picker rows = %+v, want three production providers", rows)
	}
	for i, id := range []string{"openai", "openrouter", "venice"} {
		if rows[i].ID != id || rows[i].Label != id {
			t.Fatalf("connect picker rows = %+v, want stable id/label order openai, openrouter, venice", rows)
		}
	}
	// The production handler ran (not the wrong-arity branch), but opening the picker
	// itself is not a connection and must not render the old interim guidance.
	tr := app.TranscriptText()
	if strings.Contains(tr, "takes at most one argument") {
		t.Fatalf("transcript = %q, shows the wrong-arity error; bare /connect must reach the handler", tr)
	}
	if strings.Contains(tr, "choose one") {
		t.Fatalf("transcript = %q, still renders interim provider guidance instead of opening the picker", tr)
	}
	if evs := slashCmds(t, store); len(evs) != 0 {
		t.Errorf("recorded %d slash_command events before picker selection, want 0", len(evs))
	}
	if _, err := os.Stat(SettingsPath(home)); !os.IsNotExist(err) {
		t.Fatalf("global settings stat err = %v, want not-exist before picker selection", err)
	}

	if !app.SelectConnectProviderForTest("openai") {
		t.Fatal("test could not select openai from the connect picker")
	}
	if app.ConnectPickerOpen() {
		t.Fatal("connect picker stayed open after provider selection")
	}
	if !app.SecretPromptOpen() {
		t.Fatal("provider selection did not enter the masked direct connect flow")
	}
	app.SubmitSecretPromptForTest("sk-entered-through-picker")

	cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
	if len(cmds) != 1 || cmds[0].Name != "connect" || cmds[0].Outcome != "success" || !slices.Equal(cmds[0].Args, []string{"openai"}) {
		t.Fatalf("disk slash_command events = %+v, want one {connect [openai], success}", cmds)
	}
	settings := SettingsPath(home)
	assertFileContains(t, settings, "provider:")
	assertFileContains(t, settings, "openai:")
	assertFileContains(t, settings, "sk-entered-through-picker")
	if tr := app.TranscriptText(); !strings.Contains(tr, "connected provider openai") || strings.Contains(tr, "sk-entered-through-picker") {
		t.Fatalf("transcript = %q, want connected-provider notice without leaking key", tr)
	}
}

// TestConnectCommand_ProductionWiring_ReservedRejected drives the reserved
// browser-login provider through the real submit path: it is rejected before any
// deps call, the input is retained, a durable slash_command{connect, error} carries
// the `codemeld auth login openai-chatgpt` guidance, and no provider entry is
// written for it.
func TestConnectCommand_ProductionWiring_ReservedRejected(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	home := t.TempDir()
	result := &BootstrapResult{Home: home, LaunchDir: "/launch", Session: store}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if app.SubmitInput("/connect openai-chatgpt") {
		t.Fatal("/connect openai-chatgpt accepted; the reserved browser-login provider must be rejected with retained input")
	}

	cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
	if len(cmds) != 1 || cmds[0].Name != "connect" || cmds[0].Outcome != "error" {
		t.Fatalf("disk slash_command events = %+v, want one {connect, error}", cmds)
	}
	if !strings.Contains(cmds[0].ErrorDetail, "auth login openai-chatgpt") {
		t.Errorf("error_detail = %q, want browser-login guidance", cmds[0].ErrorDetail)
	}
	if _, err := os.Stat(SettingsPath(home)); !os.IsNotExist(err) {
		t.Fatalf("global settings stat err = %v, want not-exist (no provider.openai-chatgpt write)", err)
	}
}

// TestConnectCommand_ProductionWiring_UnknownRejected drives an unknown provider id
// through the real submit path: rejected with retained input, a durable
// slash_command{connect, error} that echoes neither the typed id nor a secret, and
// no settings write.
func TestConnectCommand_ProductionWiring_UnknownRejected(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	home := t.TempDir()
	result := &BootstrapResult{Home: home, LaunchDir: "/launch", Session: store}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if app.SubmitInput("/connect bogus") {
		t.Fatal("/connect bogus accepted; an unknown provider must be rejected with retained input")
	}

	cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
	if len(cmds) != 1 || cmds[0].Name != "connect" || cmds[0].Outcome != "error" || len(cmds[0].Args) != 0 {
		t.Fatalf("disk slash_command events = %+v, want one {connect, error} with no args", cmds)
	}
	if strings.Contains(cmds[0].ErrorDetail, "bogus") {
		t.Errorf("error_detail = %q, must not echo the typed id", cmds[0].ErrorDetail)
	}
	if _, err := os.Stat(SettingsPath(home)); !os.IsNotExist(err) {
		t.Fatalf("global settings stat err = %v, want not-exist (no write on unknown rejection)", err)
	}
}

// TestConnectCommand_ProductionWiring_PromptCancel drives /connect openai through the
// real submit path, then dismisses the masked prompt with ESC: no provider entry is
// written, no slash_command is recorded (no false success or error), and the user sees
// the static cancellation notice. A cancelled prompt claims no connection.
func TestConnectCommand_ProductionWiring_PromptCancel(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	home := t.TempDir()
	result := &BootstrapResult{Home: home, LaunchDir: "/launch", Session: store}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("/connect openai") {
		t.Fatal("/connect openai not handled; the production connect handler is not wired")
	}
	if !app.SecretPromptOpen() {
		t.Fatal("/connect openai did not open the masked API-key prompt")
	}

	app.HandleEsc() // dismiss the prompt without submitting a key

	if app.SecretPromptOpen() {
		t.Fatal("masked prompt still open after ESC cancel")
	}
	if _, err := os.Stat(SettingsPath(home)); !os.IsNotExist(err) {
		t.Fatalf("settings written on a cancelled prompt (stat err %v), want none", err)
	}
	if cmds := slashCmds(t, store); len(cmds) != 0 {
		t.Fatalf("recorded %d slash_command events on cancel, want 0 (no false success or error)", len(cmds))
	}
	if tr := app.TranscriptText(); !strings.Contains(tr, "cancelled") {
		t.Errorf("transcript = %q, want a cancellation notice", tr)
	}
	if strings.Contains(app.TranscriptText(), "connected provider") {
		t.Errorf("transcript claims a connection on a cancelled prompt")
	}
}

func TestConnectCommand_ProductionWiring_PersistFailure(t *testing.T) {
	defer swapConnectDiscover(func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		return []provider.DiscoveredConfiguredModel{{ID: "gpt-5.5"}}, nil
	})()
	ctx := context.Background()
	store := mkStore(t)
	home := t.TempDir()
	blocker := filepath.Join(home, ".codemeld")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := &BootstrapResult{Home: home, LaunchDir: "/launch", Session: store}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	// The command is handled (the prompt/connect seam completes on the event loop); the
	// forced write failure is surfaced as a recorded error event, asserted below, not by
	// retaining the input.
	if !app.SubmitInput("/connect openai") {
		t.Fatal("/connect openai not handled; the production connect handler is not wired")
	}
	if !app.SecretPromptOpen() {
		t.Fatal("/connect openai did not open the masked API-key prompt")
	}
	// Submitting the masked key drives finishConnect, whose forced write fails closed.
	app.SubmitSecretPromptForTest("sk-entered-at-the-prompt")

	// The write failed closed: the seeded regular file is unchanged and no global
	// settings file was created under it.
	if data, err := os.ReadFile(blocker); err != nil || string(data) != "x" {
		t.Fatalf("blocker file = %q (err %v), want unchanged \"x\" (write must fail closed)", data, err)
	}
	// Any stat error proves no settings file exists: not-exist, or not-a-directory
	// because the path traverses the seeded regular-file blocker.
	if _, err := os.Stat(SettingsPath(home)); err == nil {
		t.Fatal("global settings file exists, want none (write failed closed)")
	}
	// A failed connect records durable, secret-free error evidence — exactly one
	// slash_command{connect, error}, no success — read back from disk.
	cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
	connectEvents := 0
	for _, c := range cmds {
		if c.Name != "connect" {
			continue
		}
		connectEvents++
		if c.Outcome != "error" {
			t.Fatalf("slash_command{connect} outcome = %q, want error on a failed write: %+v", c.Outcome, c)
		}
		if c.ErrorDetail == "" {
			t.Errorf("connect error event has empty error_detail, want durable evidence: %+v", c)
		}
		if strings.Contains(c.ErrorDetail, "sk-") {
			t.Errorf("connect error_detail = %q, must carry no secret", c.ErrorDetail)
		}
	}
	if connectEvents != 1 {
		t.Fatalf("recorded %d connect events, want exactly 1 error event: %+v", connectEvents, cmds)
	}

	// Force a later session flush: no pending connect success may exist that a
	// subsequent flush could turn durable, so nothing false appears after re-flushing.
	if _, _, err := store.Flush(ctx); err != nil {
		t.Fatalf("later flush: %v", err)
	}
	for _, c := range diskSlashCommands(t, readSessionFile(t, store.Path())) {
		if c.Name == "connect" && c.Outcome == "success" {
			t.Fatalf("a later flush persisted a false slash_command{connect, success}: %+v", c)
		}
	}

	tr := app.TranscriptText()
	if !strings.Contains(tr, "nothing was saved") {
		t.Errorf("transcript = %q, want a secret-free store-failure notice", tr)
	}
	if strings.Contains(tr, "connected provider") {
		t.Errorf("transcript = %q, must not claim a connected provider on failure", tr)
	}
	if strings.Contains(tr, "sk-") {
		t.Errorf("transcript leaked a secret-shaped token: %q", tr)
	}
}

// TestConnectCommand_ProductionWiring_DiscoveryPersistFailure drives /connect venice
// where discovery and the models.yaml store write both succeed but the later settings
// write fails: the connect must undo the store write so both settings.yaml and
// models.yaml are left as they were, the live catalog is not mutated, and a durable
// slash_command{connect, error} — not a false success — is recorded.
func TestConnectCommand_ProductionWiring_DiscoveryPersistFailure(t *testing.T) {
	const prov = "venice"
	discovered := []string{"venice-model-a", "venice-model-b"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]string{{"id": discovered[0]}, {"id": discovered[1]}},
		})
	}))
	defer srv.Close()
	defer swapConnectDiscover(func(ctx context.Context, cfg provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		cfg.Entry.BaseURL = srv.URL
		return provider.DiscoverAPIKeyModels(ctx, cfg)
	})()

	ctx := context.Background()
	store := mkStore(t)
	home := t.TempDir()
	settings := SettingsPath(home)
	modelsPath := config.DiscoveredModelsPath(settings)
	if err := config.UpdateDiscoveredModelsProvider(modelsPath, "openrouter", config.DiscoveredProvider{
		Source: "seed",
		Models: []config.DiscoveredModel{{ID: "openrouter-existing"}},
	}); err != nil {
		t.Fatalf("seed existing models.yaml: %v", err)
	}
	priorModels, err := os.ReadFile(modelsPath)
	if err != nil {
		t.Fatalf("read seeded models.yaml: %v", err)
	}
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        "/launch",
		Session:          store,
		ConfigLayerPaths: []string{settings},
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	// Plant a directory at the settings.yaml path after startup (so the initial config
	// load still reads a normal absent file). The sibling models.yaml stays writable, so
	// discovery and the store write succeed and only the settings write fails — hitting a
	// directory where its re-read expects a file — which exercises the fail-closed undo.
	if err := os.MkdirAll(settings, 0o755); err != nil {
		t.Fatal(err)
	}

	if !app.SubmitInput("/connect " + prov) {
		t.Fatalf("/connect %s not handled; the production connect handler is not wired", prov)
	}
	if !app.SecretPromptOpen() {
		t.Fatalf("/connect %s did not open the masked API-key prompt", prov)
	}
	app.SubmitSecretPromptForTest("sk-entered-at-the-prompt")

	// The store write was rolled back exactly: the existing models.yaml bytes and the
	// unrelated OpenRouter row must survive, with no orphaned Venice entry.
	afterModels, err := os.ReadFile(modelsPath)
	if err != nil {
		t.Fatalf("read models.yaml after rollback: %v", err)
	}
	if !slices.Equal(afterModels, priorModels) {
		t.Fatalf("models.yaml after rollback differs from prior bytes:\nprior:\n%s\nafter:\n%s", priorModels, afterModels)
	}
	mstore, err := config.ReadDiscoveredModels(modelsPath)
	if err != nil {
		t.Fatalf("read rolled-back models.yaml: %v", err)
	}
	if _, ok := mstore.Providers[prov]; ok {
		t.Fatalf("rolled-back models.yaml still contains failed %s entry: %+v", prov, mstore.Providers)
	}
	if got := mstore.Providers["openrouter"].Models[0].ID; got != "openrouter-existing" {
		t.Fatalf("openrouter row = %q, want preserved openrouter-existing", got)
	}
	// The settings path is still the planted directory — the failed write clobbered nothing.
	if info, err := os.Stat(settings); err != nil || !info.IsDir() {
		t.Fatalf("settings path info = %v (err %v), want the unchanged directory", info, err)
	}

	// Exactly one durable, secret-free slash_command{connect, error}, no success.
	cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
	connectEvents := 0
	for _, c := range cmds {
		if c.Name != "connect" {
			continue
		}
		connectEvents++
		if c.Outcome != "error" {
			t.Fatalf("slash_command{connect} outcome = %q, want error on a failed write: %+v", c.Outcome, c)
		}
		if strings.Contains(c.ErrorDetail, "sk-") {
			t.Errorf("connect error_detail = %q, must carry no secret", c.ErrorDetail)
		}
	}
	if connectEvents != 1 {
		t.Fatalf("recorded %d connect events, want exactly 1 error event: %+v", connectEvents, cmds)
	}

	// The live catalog was not mutated: the discovered ids are not offered after failure.
	for _, row := range app.ModelPickerRows() {
		if row.Provider == prov {
			t.Errorf("%s became selectable after a failed settings write: %+v", prov, row)
		}
	}

	// A secret-free persist-failure notice is shown; no false connection, no leaked key.
	tr := app.TranscriptText()
	if !strings.Contains(tr, "failed to persist") {
		t.Errorf("transcript = %q, want a persist-failure notice", tr)
	}
	if strings.Contains(tr, "connected provider") {
		t.Errorf("transcript = %q, must not claim a connected provider on failure", tr)
	}
	if strings.Contains(tr, "sk-") {
		t.Errorf("transcript leaked a secret-shaped token: %q", tr)
	}
}

// TestConnectCommand_ProductionWiring_DiscoveryStoreFailure drives /connect venice when
// discovery succeeds but the models.yaml store write cannot complete: a directory is
// planted at the discovered-models path, so connectDiscovered's store-write step fails
// before any settings persistence. The failure must leave settings.yaml uncreated and the
// planted store target untouched, mutate no live catalog rows, record exactly one durable
// slash_command{connect, error}, and leak neither the entered key nor a success notice.
func TestConnectCommand_ProductionWiring_DiscoveryStoreFailure(t *testing.T) {
	const prov = "venice"
	discovered := []string{"venice-model-a", "venice-model-b"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]string{{"id": discovered[0]}, {"id": discovered[1]}},
		})
	}))
	defer srv.Close()
	defer swapConnectDiscover(func(ctx context.Context, cfg provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		cfg.Entry.BaseURL = srv.URL
		return provider.DiscoverAPIKeyModels(ctx, cfg)
	})()

	ctx := context.Background()
	store := mkStore(t)
	home := t.TempDir()
	settings := SettingsPath(home)
	modelsPath := config.DiscoveredModelsPath(settings)
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        "/launch",
		Session:          store,
		ConfigLayerPaths: []string{settings},
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	// Plant a directory at the discovered-models path after startup: discovery still
	// succeeds, but the store-write step cannot treat a directory as models.yaml, so it
	// fails before the settings write — exercising the store-write-failure branch that
	// leaves both files as they were.
	if err := os.MkdirAll(modelsPath, 0o755); err != nil {
		t.Fatal(err)
	}

	if !app.SubmitInput("/connect " + prov) {
		t.Fatalf("/connect %s not handled; the production connect handler is not wired", prov)
	}
	if !app.SecretPromptOpen() {
		t.Fatalf("/connect %s did not open the masked API-key prompt", prov)
	}
	app.SubmitSecretPromptForTest("sk-entered-at-the-prompt")

	// Settings was never written: a store-write failure must not persist a provider entry.
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Fatalf("settings stat err = %v, want not-exist (no settings write after a store failure)", err)
	}
	// The planted store target is untouched — not replaced with discovered YAML.
	if info, err := os.Stat(modelsPath); err != nil || !info.IsDir() {
		t.Fatalf("models.yaml path info = %v (err %v), want the unchanged planted directory", info, err)
	}

	// Exactly one durable, secret-free slash_command{connect, error}, no success.
	cmds := diskSlashCommands(t, readSessionFile(t, store.Path()))
	connectEvents := 0
	for _, c := range cmds {
		if c.Name != "connect" {
			continue
		}
		connectEvents++
		if c.Outcome != "error" {
			t.Fatalf("slash_command{connect} outcome = %q, want error on a failed store write: %+v", c.Outcome, c)
		}
		if strings.Contains(c.ErrorDetail, "sk-") {
			t.Errorf("connect error_detail = %q, must carry no secret", c.ErrorDetail)
		}
	}
	if connectEvents != 1 {
		t.Fatalf("recorded %d connect events, want exactly 1 error event: %+v", connectEvents, cmds)
	}

	// The live catalog was not mutated: the discovered ids are not offered after failure.
	for _, row := range app.ModelPickerRows() {
		if row.Provider == prov {
			t.Errorf("%s became selectable after a failed store write: %+v", prov, row)
		}
	}

	// No false connection and no leaked key in the secret-free failure notice.
	tr := app.TranscriptText()
	if strings.Contains(tr, "connected provider") {
		t.Errorf("transcript = %q, must not claim a connected provider on a store-write failure", tr)
	}
	if strings.Contains(tr, "sk-") {
		t.Errorf("transcript leaked a secret-shaped token: %q", tr)
	}
}

func TestBlocked_ListsLocalEntriesWithTheLocalFile(t *testing.T) {
	home := declaredScopeDir(t)
	project := mustCanonical(t, declaredScopeDir(t))
	settings := SettingsPath(home)
	local := config.LocalSettingsPath(project)
	globalPath, localPath := filepath.Join(home, "one"), filepath.Join(home, "two")

	layers := blockedGlobalLayers(t, home, project, globalPath)
	seedBlockedSettings(t, local, blockedYAML(localPath))
	layers = append(layers, securitystate.LayerSnapshot{
		Kind: securitystate.LayerLocal, Path: local, Present: true,
		Raw: mustValidateLayer(t, local, config.ValidateLocalSettingsBytes),
	})
	if err := trust.Record(home, project); err != nil {
		t.Fatalf("trust.Record: %v", err)
	}

	app := startRunning(t, &BootstrapResult{
		Home:             home,
		LaunchDir:        project,
		ProjectRoot:      project,
		Session:          mkStore(t),
		ConfigLayerPaths: []string{settings},
		SettingsLayers:   layers,
	})

	done := make(chan struct{})
	var accepted bool
	var overlay string
	go func() {
		app.RunOnEventLoopForTest(func() {
			accepted = app.SubmitInput("/blocked")
			overlay = app.BlockedOverlayText()
			app.HandleEsc()
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("/blocked did not finish on the event loop")
	}
	if !accepted {
		t.Fatal("/blocked rejected; the production registry did not bind the handler")
	}

	if want := localPath + "  (" + local + ")"; !strings.Contains(overlay, want) {
		t.Fatalf("overlay = %q, want the local entry listed as %q", overlay, want)
	}
	if want := globalPath + "  (" + settings + ")"; !strings.Contains(overlay, want) {
		t.Fatalf("overlay = %q, want the global entry still listed as %q", overlay, want)
	}
}

func TestBlocked_RemovingALocalRowWritesTheLocalFile(t *testing.T) {
	home := declaredScopeDir(t)
	project := mustCanonical(t, declaredScopeDir(t))
	settings := SettingsPath(home)
	local := config.LocalSettingsPath(project)
	secrets := declaredScopeDir(t)
	drop, keep := filepath.Join(secrets, "drop"), filepath.Join(secrets, "keep")

	layers := blockedGlobalLayers(t, home, project)
	seedBlockedSettings(t, local, blockedYAML(drop, keep))
	layers = append(layers, securitystate.LayerSnapshot{
		Kind: securitystate.LayerLocal, Path: local, Present: true,
		Raw: mustValidateLayer(t, local, config.ValidateLocalSettingsBytes),
	})
	storeUnchanged := approvedRootsUnchanged(t, home, project)
	decision := trust.Lookup(home, project)
	if !decision.Trusted {
		t.Fatalf("trust gate = %#v, want the recorded project admitted", decision)
	}
	globalBefore := mustReadFile(t, settings)

	app, screen := startRunningOnScreen(t, &BootstrapResult{
		Home:             home,
		LaunchDir:        project,
		ProjectRoot:      project,
		Session:          mkStore(t),
		ConfigLayerPaths: []string{settings},
		SettingsLayers:   layers,
		TrustDecision:    decision,
	})

	var accepted bool
	var overlay string
	app.RunOnEventLoopForTest(func() {
		accepted = app.SubmitInput("/blocked")
		overlay = app.BlockedOverlayText()
	})
	if !accepted {
		t.Fatal("/blocked rejected; the production registry did not bind the handler")
	}
	if first, want := strings.SplitN(overlay, "\n", 2)[0], drop+"  ("+local+")"; first != want {
		t.Fatalf("first row = %q, want the local entry %q, which the picker opens highlighted", first, want)
	}

	screen.InjectKey(tcell.KeyRune, 'r', tcell.ModNone)
	screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)

	removed := func() bool {
		body := mustReadFile(t, local)
		return !strings.Contains(body, drop) && strings.Contains(body, keep)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !removed() {
		if time.Now().After(deadline) {
			t.Fatalf("local file = %q, want %s removed and %s kept by the /blocked removal", mustReadFile(t, local), drop, keep)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := mustReadFile(t, settings); got != globalBefore {
		t.Fatalf("global settings = %q, want it byte-identical %q", got, globalBefore)
	}
	mustNotExist(t, projectSettingsPath(project), "a local /blocked removal must not create the shared settings file")
	storeUnchanged()
}

func startLayeredSettingsTUI(t *testing.T, root, home string, kinds ...securitystate.LayerKind) (*tui.App, tcell.SimulationScreen) {
	t.Helper()
	paths := map[securitystate.LayerKind]string{securitystate.LayerProject: projectSettingsPath(root), securitystate.LayerLocal: config.LocalSettingsPath(root)}
	layers := []securitystate.LayerSnapshot{{Kind: securitystate.LayerGlobal, Path: SettingsPath(home), Present: true, Raw: map[string]any{}}}
	for _, kind := range kinds {
		layers = append(layers, loadedLayer(t, kind, paths[kind]))
	}
	decision := trust.Lookup(home, root)
	if !decision.Trusted || decision.Reason != trust.ReasonTrusted {
		t.Fatalf("trust gate = %#v, want the listed root admitted", decision)
	}
	return startRunningOnScreen(t, &BootstrapResult{
		Home: home, LaunchDir: root, ProjectRoot: root, Session: mkStore(t),
		Config:         map[string]any{"discovery": map[string]any{"boundary": "project-root"}},
		SettingsLayers: layers,
		TrustDecision:  decision,
	})
}

func TestSettingsShare_MovesOneLocalEntryToANewSharedFile(t *testing.T) {
	root := mustCanonical(t, t.TempDir())
	home := t.TempDir()
	first, shared, host := folderGrant(root, "read_file"), folderGrant(root, "list_files"), projectHostGrant("web_fetch", "docs.example.com")
	for _, e := range []permissions.PermissionEntry{first, shared, host} {
		seedGrantFile(t, config.LocalSettingsPath(root), e)
	}
	storeUnchanged := approvedRootsUnchanged(t, home, root)
	app, screen := startLayeredSettingsTUI(t, root, home, securitystate.LayerLocal)

	var selected bool
	app.RunOnEventLoopForTest(func() {
		selected = app.SubmitInput("/settings") && app.SelectPermissionForTest(shared)
	})
	if !selected {
		t.Fatal("the local grant was not selectable in the production /settings overlay")
	}
	screen.InjectKey(tcell.KeyRune, 's', tcell.ModNone)
	screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(projectSettingsPath(root)); err == nil && !strings.Contains(mustReadFile(t, config.LocalSettingsPath(root)), "list_files") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("share did not finish: local file = %q", mustReadFile(t, config.LocalSettingsPath(root)))
		}
		time.Sleep(5 * time.Millisecond)
	}

	requireFileGrants(t, projectSettingsPath(root), root, shared)
	requireFileGrants(t, config.LocalSettingsPath(root), root, first, host)
	var notice string
	app.RunOnEventLoopForTest(func() { notice = app.NoticeText() })
	if want := tui.RenderProjectRootMarkerNotice(permissions.BoundPromptFact(projectSettingsPath(root))); notice != want {
		t.Fatalf("notice = %q, want the project-root marker notice %q", notice, want)
	}
	storeUnchanged()
}

func TestSettingsSharedDelete_RemovesOneSharedEntry(t *testing.T) {
	root := mustCanonical(t, t.TempDir())
	home := t.TempDir()
	other, removed, host := folderGrant(root, "list_files"), folderGrant(root, "read_file"), projectHostGrant("web_fetch", "docs.example.com")
	for _, e := range []permissions.PermissionEntry{other, removed, host} {
		seedGrantFile(t, projectSettingsPath(root), e)
	}
	seedGrantFile(t, config.LocalSettingsPath(root), folderGrant(root, "grep"))
	localBefore := mustReadFile(t, config.LocalSettingsPath(root))
	storeUnchanged := approvedRootsUnchanged(t, home, root)
	app, _ := startLayeredSettingsTUI(t, root, home, securitystate.LayerProject, securitystate.LayerLocal)

	var selected, revoked bool
	app.RunOnEventLoopForTest(func() {
		selected = app.SubmitInput("/settings") && app.SelectPermissionForTest(removed)
		revoked = selected && app.RevokeHighlightedPermissionForTest()
	})
	if !selected || !revoked {
		t.Fatalf("selected %v, revoked %v; want the shared grant removed through the production /settings overlay", selected, revoked)
	}

	requireFileGrants(t, projectSettingsPath(root), root, other, host)
	if got := mustReadFile(t, config.LocalSettingsPath(root)); got != localBefore {
		t.Fatalf("local settings = %q, want it byte-identical %q", got, localBefore)
	}
	storeUnchanged()
}

type estimateServer struct {
	srv     *httptest.Server
	mu      sync.Mutex
	seen    []string
	entered chan struct{}
	release chan struct{}
}

func newEndpointsBodyServer(t *testing.T, body func(model string) (string, bool)) *estimateServer {
	t.Helper()
	s := &estimateServer{}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen = append(s.seen, r.URL.Path+" "+r.Header.Get("Authorization"))
		entered, release := s.entered, s.release
		s.mu.Unlock()
		if entered != nil {
			entered <- struct{}{}
			<-release
		}
		b, ok := body(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/models/"), "/endpoints"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, b)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *estimateServer) block() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entered, s.release = make(chan struct{}, 1), make(chan struct{})
}

func (s *estimateServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.seen)
}

func guardedEstimateClient(allow ...*estimateServer) (*http.Client, *atomic.Int64) {
	allowed := map[string]bool{}
	for _, s := range allow {
		allowed[s.srv.Listener.Addr().String()] = true
	}
	transport := allow[0].srv.Client().Transport.(*http.Transport).Clone()
	realDial := (&net.Dialer{}).DialContext
	var rejected atomic.Int64
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !allowed[addr] {
			rejected.Add(1)
			return nil, fmt.Errorf("rejected dial to %q", addr)
		}
		return realDial(ctx, network, addr)
	}
	return &http.Client{Transport: transport}, &rejected
}

type estimateTUI struct {
	t      *testing.T
	app    *tui.App
	screen tcell.SimulationScreen
	cache  *config.Cache
}

func startEstimateTUI(t *testing.T, baseURL string, sel *model.Selection, store *provider.OpenRouterEndpointStore, routing map[string]any, layers ...string) *estimateTUI {
	t.Helper()
	prevStore := openRouterEndpoints
	openRouterEndpoints = store
	t.Cleanup(func() { openRouterEndpoints = prevStore })
	h := &estimateTUI{t: t}
	production := newSettingsDeps
	newSettingsDeps = func(app *tui.App, c *config.Cache, active *model.ActiveState, authorizer *productionAuthorizer) tui.SettingsDeps {
		h.cache = c
		return production(app, c, active, authorizer)
	}
	t.Cleanup(func() { newSettingsDeps = production })
	openrouter := map[string]any{"base_url": baseURL, "api_key": "or-key"}
	if routing != nil {
		openrouter["routing"] = routing
	}
	h.app, h.screen = startRunningOnScreen(t, &BootstrapResult{
		Home:             t.TempDir(),
		LaunchDir:        "/launch",
		ConfigLayerPaths: layers,
		Session:          mkStore(t),
		Model:            model.NewActiveState(sel, model.SourceProject),
		Config: map[string]any{"provider": map[string]any{
			"openrouter": openrouter,
			"openai":     map[string]any{"base_url": baseURL, "api_key": "sk-test", "models": []string{"gpt-5.5"}},
		}},
	})
	h.reopen()
	return h
}

func (h *estimateTUI) onLoop(fn func()) {
	h.t.Helper()
	done := make(chan struct{})
	go func() {
		h.app.RunOnEventLoopForTest(fn)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		h.t.Fatal("event-loop call did not finish")
	}
}

func (h *estimateTUI) reopen() {
	h.t.Helper()
	var ok bool
	h.onLoop(func() { ok = h.app.SubmitInput("/settings") })
	if !ok {
		h.t.Fatal("/settings rejected")
	}
}

func (h *estimateTUI) showSettings() string {
	h.t.Helper()
	var row string
	h.onLoop(func() {
		if !h.app.ShowOpenRouterTabForTest() {
			h.t.Error("permissions overlay is not open")
		}
		row = h.app.SortRowForTest()
	})
	return row
}

func (h *estimateTUI) awaitSortRow(want string) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var got string
		h.onLoop(func() { got = h.app.SortRowForTest() })
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("sort row = %q, want %q", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func openRouterModel(id string) *model.Selection {
	return &model.Selection{Provider: "openrouter", ID: id, Effort: model.EffortDefault}
}

func TestF1950_OpenRouterTabAndModelsTableMakeNoEndpointsRequest(t *testing.T) {
	srv := newEndpointsBodyServer(t, func(string) (string, bool) { return `{"data":{"endpoints":[]}}`, true })
	client, rejected := guardedEstimateClient(srv)
	h := startEstimateTUI(t, srv.srv.URL+"/api/v1", openRouterModel("m"), &provider.OpenRouterEndpointStore{HTTPClient: client}, map[string]any{
		"sort":      "best_value",
		"max_price": map[string]any{"q/one": map[string]any{"prompt": 1}},
	})
	expectNone := func(when string) {
		t.Helper()
		time.Sleep(50 * time.Millisecond)
		if got := srv.requests(); len(got) != 0 || rejected.Load() != 0 {
			t.Fatalf("endpoint requests %s = %v, rejected dials = %d; want none", when, got, rejected.Load())
		}
	}
	expectNone("at startup")

	if row := h.showSettings(); row != "sort   best value" {
		t.Fatalf("sort row = %q, want the mode alone", row)
	}
	expectNone("after opening the OpenRouter tab")

	h.screen.InjectKey(tcell.KeyEscape, 0, tcell.ModNone)
	h.awaitSortRow("")
	h.reopen()
	if row := h.showSettings(); row != "sort   best value" {
		t.Fatalf("sort row on the reopened tab = %q, want the mode alone", row)
	}
	expectNone("after reopening the OpenRouter tab")

	var rows []string
	h.onLoop(func() { rows = h.app.OpenRouterModelsForTest() })
	if len(rows) != 2 {
		t.Fatalf("table rows = %q, want the header and q/one", rows)
	}
	expectNone("after opening the models table")
}

func TestSettingsTabEstimate_BestValueRequestPickHonorsIgnoredProviders(t *testing.T) {
	var mu sync.Mutex
	var chatBody []byte
	var endpointRequests atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/models/m/endpoints":
			endpointRequests.Add(1)
			_, _ = io.WriteString(w, `{"data":{"endpoints":[
				{"provider_name":"Slow","tag":"slow","pricing":{"prompt":"0.0000001","completion":"0.0000001"},"throughput_last_30m":{"p50":20}},
				{"provider_name":"Wafer","tag":"wafer/nvfp4","pricing":{"prompt":"0.00000028","completion":"0.00000028"},"throughput_last_30m":{"p50":90}},
				{"provider_name":"Relace","tag":"relace","pricing":{"prompt":"0.00000025","completion":"0.00000025"},"throughput_last_30m":{"p50":60}}
			]}}`)
		case "/api/v1/chat/completions":
			raw, _ := io.ReadAll(r.Body)
			mu.Lock()
			chatBody = raw
			mu.Unlock()
			_, _ = io.WriteString(w, `{"id":"c1","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	h := startEstimateTUI(t, srv.URL+"/api/v1", openRouterModel("m"), &provider.OpenRouterEndpointStore{HTTPClient: srv.Client()}, map[string]any{"sort": "best_value"})
	if row := h.showSettings(); row != "sort   best value" {
		t.Fatalf("sort row = %q, want the mode alone", row)
	}
	time.Sleep(50 * time.Millisecond)
	if n := endpointRequests.Load(); n != 0 {
		t.Fatalf("endpoint requests before the chat request = %d, want none", n)
	}

	defer swapTurnProviderClient(func(cfg provider.ClientConfig) provider.Client {
		cfg.HTTPClient = srv.Client()
		return provider.NewClient(cfg)
	})()
	client, ok := buildTurnClient("openrouter", provider.AuthKindConfigured, h.cache, nil, "")
	if !ok {
		t.Fatal("buildTurnClient(openrouter) ok = false, want a client")
	}
	if _, err := client.ChatCompletion(context.Background(), provider.Request{
		Model:            "m",
		Messages:         []provider.Message{{Role: "user", Content: "hi"}},
		IgnoredProviders: []string{"wafer"},
	}); err != nil {
		t.Fatalf("ChatCompletion() error = %v, want nil", err)
	}
	mu.Lock()
	defer mu.Unlock()
	var body struct {
		Provider map[string]any `json:"provider"`
	}
	if err := json.Unmarshal(chatBody, &body); err != nil {
		t.Fatalf("decode request body: %v\nbody = %s", err, chatBody)
	}
	if want := map[string]any{"order": []any{"relace"}, "ignore": []any{"wafer"}}; !reflect.DeepEqual(body.Provider, want) {
		t.Fatalf("request provider object = %#v, want %#v", body.Provider, want)
	}
	if n := endpointRequests.Load(); n != 1 {
		t.Fatalf("endpoint requests after the chat request = %d, want 1", n)
	}
}

func (h *estimateTUI) awaitOfferedLevels(want string) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var got string
		h.onLoop(func() { got = h.app.OpenRouterOfferedLevelsForTest() })
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("offered line = %q, want %q", got, want)
		}
	}
}

func TestF1940_OpenRouterModelsDialog_OfferedLevelsThroughProductionDepsAndStore(t *testing.T) {
	const hosts = `{"data":{"endpoints":[
		{"provider_name":"a","quantization":"fp8","pricing":{"prompt":"0.0000001","completion":"0.0000002"}},
		{"provider_name":"b","quantization":"fp8","pricing":{"prompt":"n/a","completion":"0.0000002"}},
		{"provider_name":"c","quantization":"nvfp4","pricing":{"prompt":"0.0000003","completion":"0.0000004"}},
		{"provider_name":"d","pricing":{"prompt":"0.0000003","completion":"0.0000004"}}
	]}}`
	srv := newEndpointsBodyServer(t, func(model string) (string, bool) {
		return hosts, model == "q/one" || model == "q/three"
	})
	client, rejected := guardedEstimateClient(srv)
	global := writeGlobalSettings(t, t.TempDir(), "provider:\n  openrouter:\n    base_url: "+srv.srv.URL+"/api/v1\n    api_key: or-key\n", 0o600)
	h := startEstimateTUI(t, srv.srv.URL+"/api/v1", openRouterModel("m"), &provider.OpenRouterEndpointStore{HTTPClient: client}, map[string]any{
		"max_price": map[string]any{
			"q/one":   map[string]any{"prompt": 1},
			"q/two":   map[string]any{"prompt": 2},
			"q/three": map[string]any{"prompt": 3},
		},
	}, global)
	expectRequests := func(when string, want ...string) {
		t.Helper()
		var models []string
		for _, r := range srv.requests() {
			models = append(models, strings.TrimSuffix(strings.TrimPrefix(r, "/api/v1/models/"), "/endpoints Bearer or-key"))
		}
		if !slices.Equal(models, want) {
			t.Fatalf("endpoint requests %s = %v, want %v", when, models, want)
		}
	}

	if row := h.showSettings(); row != "sort   default" {
		t.Fatalf("sort row = %q, want the mode alone", row)
	}
	var rows []string
	h.onLoop(func() { rows = h.app.OpenRouterModelsForTest() })
	if len(rows) != 4 {
		t.Fatalf("table rows = %q, want the three configured models", rows)
	}
	time.Sleep(50 * time.Millisecond)
	expectRequests("after opening the tab and the table")

	edit := func(model string) {
		t.Helper()
		var opened bool
		h.onLoop(func() { opened = h.app.EditOpenRouterModelForTest(model) })
		if !opened {
			t.Fatalf("%s dialog did not open", model)
		}
		h.awaitOfferedLevels("  checking providers\u2026")
	}

	srv.block()
	edit("q/one")
	<-srv.entered
	close(srv.release)
	h.awaitOfferedLevels("  providers per level: fp8 2, nvfp4 1, unspecified 1")
	expectRequests("after editing q/one", "q/one")

	srv.block()
	edit("q/two")
	<-srv.entered
	var drafted bool
	h.onLoop(func() { drafted = h.app.DraftOpenRouterModelCapsForTest("q/two", "5", "") })
	if !drafted {
		t.Fatal("drafting q/two caps did not reach the open dialog")
	}
	close(srv.release)
	h.awaitOfferedLevels("  provider list unavailable")
	expectRequests("after the failed lookup", "q/one", "q/two")

	var saved bool
	h.onLoop(func() { saved = h.app.SubmitOpenRouterModelEditorForTest("q/two") })
	if !saved {
		t.Fatal("the q/two dialog that received the failed lookup was no longer open to save")
	}
	var notice string
	h.onLoop(func() { notice = h.app.NoticeText() })
	if notice != "" {
		t.Fatalf("notice after saving with no host list = %q, want none", notice)
	}
	if got, _ := h.cache.OpenRouterMaxPrice("q/two"); got != (provider.MaxPrice{Prompt: 5, HasPrompt: true}) {
		t.Fatalf("q/two caps after saving = %+v, want prompt 5", got)
	}
	if got, want := persistedProviderEntry(t, global, "openrouter")["routing"], map[string]any{"max_price": map[string]any{"q/two": map[string]any{"prompt": uint64(5)}}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("persisted routing = %#v, want %#v", got, want)
	}
	expectRequests("after the failed lookup and the save", "q/one", "q/two")
	if n := rejected.Load(); n != 0 {
		t.Fatalf("rejected dials = %d, want none", n)
	}
}
