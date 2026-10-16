// Integration test for TR-TUI-8: the /status overlay opens within 200ms through
// the production StartTUI submit path and renders every item from the
// in-memory launch snapshot, with the only open-time disk write being the
// by-design slash_command flush (TR-TUI-8).
//
// This test lives in package bootstrap (not
// internal/integration): the production launch driver (StartTUI's runApp seam,
// the registry-backed submit adapter, newStatusState) and the
// startCaptured/SubmitInput/StatusText fixtures are package-private to bootstrap,
// matching the landed TUI integration precedent in tui_commands_test.go.
package bootstrap

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// TestTRTUI8_StatusOverlay_OpensFastWithAllItemsThroughProductionPath drives
// /status through the production StartTUI submit path against a session with a
// loaded AGENTS.md record and one completed turn, then asserts: the overlay opens
// within 200ms (Done-when 1), all 11 items are present and correctly
// populated in order including the global-first/project-last config layer sources
// (Done-when 2), and the production path renders from in-memory snapshot state
// while the sole open-time disk write is the by-design slash_command flush, read
// back from disk (Done-when 3). TestNewStatusHandler_NoDiskIOAtOpen owns the
// hit-counter proof that BuildStatusSnapshot itself reads no disk.
func TestTRTUI8_StatusOverlay_OpensFastWithAllItemsThroughProductionPath(t *testing.T) {
	ctx := context.Background()

	// mkStore: a writable temp-path store so /status's FlushActive succeeds. Its
	// metadata fixes the session id and started_at the overlay reports
	// (items 2-3): id 01890000-...0001, started_at testStart (2026-05-28T09:00:00Z).
	store := mkStore(t)

	// Seed one completed turn (model_turn + model_response) so the token-usage and
	// attestability items (item 11) aggregate real in-memory records. A nil
	// anomaly list keeps the session fully attestable.
	if err := model.EmitModelTurn(store, "openai", "gpt-5.5", "medium", model.SourceResume); err != nil {
		t.Fatalf("seed model_turn: %v", err)
	}
	if err := model.EmitModelResponse(store, "openai", "gpt-5.5", 120, 340, nil, false, nil, ""); err != nil {
		t.Fatalf("seed model_response: %v", err)
	}

	// Distinct launch dir and project root so items 4 and 5 are independently
	// checkable and the "(same as launch dir)" suffix must stay absent.
	const (
		launchDir   = "/work/launchdir"
		projectRoot = "/work/project"
		globalCfg   = "/home/dev/.codemeld/global/settings.yaml"
		projectCfg  = "/work/project/.codemeld/settings.yaml"
		localCfg    = "/work/project/.codemeld/settings.local.yaml"
	)
	agents := []agentinstr.LoadEntry{
		{Path: "/home/dev/.codemeld/global/AGENTS.md", Layer: agentinstr.LayerGlobal, LoadOrder: 1},
		{Path: "/work/project/AGENTS.md", Layer: agentinstr.LayerWalked, LoadOrder: 2},
	}

	// The bootstrap launch snapshot the launch steps hand to StartTUI: they own the session +
	// active model and, from step 2, ConfigLayerPaths (global-first/project-last).
	result := &BootstrapResult{
		Home:             "/home/dev",
		LaunchDir:        launchDir,
		ProjectRoot:      projectRoot,
		ConfigLayerPaths: []string{globalCfg, projectCfg},
		SettingsLayers: []securitystate.LayerSnapshot{
			{Kind: securitystate.LayerGlobal, Path: globalCfg, Present: true},
			{Kind: securitystate.LayerProject, Path: projectCfg, Present: true},
			{Kind: securitystate.LayerLocal, Path: localCfg, Present: true},
		},
		Model:             selectedState(), // openai/gpt-5.5/medium
		Session:           store,
		AgentInstructions: agents,
	}

	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	// Done-when 1: time from before the keystroke through to the rendered overlay
	// text being readable must be <=200ms (TR-TUI-8). The fixture is local and
	// deterministic so the window is not dominated by disk or provider work.
	start := time.Now()
	if !app.SubmitInput("/status") {
		t.Fatal("/status rejected through the production StartTUI submit path")
	}
	overlay := app.StatusText()
	elapsed := time.Since(start)
	if overlay == "" {
		t.Fatal("/status overlay is empty; the production path did not render the snapshot")
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("/status overlay opened in %v, want <=200ms (req TR-TUI-8)", elapsed)
	}

	// Done-when 2: all 11 items, present and correctly populated from the
	// production snapshot, in the fixed order. Each item's substring index must be
	// strictly increasing.
	wantInOrder := []string{
		// 1. codemeld version — read from the codemeldVersion source the banner and
		// /status share, bumped by hand on each release, so this test never owns
		// a second copy of the release literal.
		"codemeld " + codemeldVersion,
		// 2. session id (UUIDv7, from the session metadata).
		"Session: " + store.SessionID(),
		// 3. session start timestamp — testStart rendered RFC 3339, ms precision.
		"Started: 2026-05-28T09:00:00.000Z",
		// 4. launch directory.
		"Launch dir: " + launchDir,
		// 5. project root (distinct from the launch dir here).
		"Project root: " + projectRoot,
		// 6-8. active provider / model id / effort.
		"Provider: openai",
		"Model: gpt-5.5",
		"Effort: medium",
		// 9. loaded AGENTS.md files — path, layer, load order, in load order.
		"AGENTS.md files:",
		"/home/dev/.codemeld/global/AGENTS.md [global, load_order=1]",
		"/work/project/AGENTS.md [walked, load_order=2]",
		// 10. config layer sources — global, project, local.
		"Config layer sources:",
		globalCfg + " [global]",
		projectCfg + " [project]",
		localCfg + " [local]",
		// 11. token usage totals. There is no always-on attestability
		// indicator: this fully attestable session ends at the token-usage line.
		"Token usage: 120 input, 340 output",
	}
	last := -1
	for _, want := range wantInOrder {
		idx := strings.Index(overlay, want)
		if idx < 0 {
			t.Fatalf("status overlay missing item %q\n--- overlay ---\n%s", want, overlay)
		}
		if idx <= last {
			t.Fatalf("status overlay item %q at %d is out of req-585 order (previous item ended at %d)\n--- overlay ---\n%s", want, idx, last, overlay)
		}
		last = idx
	}

	// item 5: launch dir and project root differ, so the matching suffix
	// must not appear.
	if strings.Contains(overlay, "(same as launch dir)") {
		t.Errorf("project root line carries the (same as launch dir) suffix when launch dir %q != project root %q\n--- overlay ---\n%s", launchDir, projectRoot, overlay)
	}

	// A fully attestable session shows no superseded attestability line and
	// no incomplete-counts line — the overlay ends at the token-usage line.
	if strings.Contains(overlay, "Attestability:") {
		t.Errorf("overlay renders a superseded Attestability line\n--- overlay ---\n%s", overlay)
	}
	if strings.Contains(overlay, "Token counts:") {
		t.Errorf("fully attestable overlay renders an incomplete-counts line\n--- overlay ---\n%s", overlay)
	}

	// Done-when 3: the one allowed open-time disk write is the by-design
	// slash_command flush — read it back from disk. The config-source lines and the
	// AGENTS.md/selection items above prove the in-memory cache, result, and active
	// state were read, since no session file on disk carries those. The session
	// id/start/token items are NOT claimed here as in-memory-sourced: /status
	// flushes the session before snapshotting (cmd_status.go FlushActive →
	// BuildStatusSnapshot), so a statusState that reread the just-flushed file would
	// render the same values and still pass this assertion. That the production
	// statusState sources the session id, start timestamp, and records from the
	// in-memory store (not the file) is pinned separately by
	// TestTRTUI8_StatusStateSourcesSessionFromMemoryNotDisk.
	disk := readSessionFile(t, store.Path())
	cmds := diskSlashCommands(t, disk)
	if len(cmds) != 1 || cmds[0].Name != "status" || cmds[0].Outcome != "success" {
		t.Fatalf("disk slash_command = %+v, want one {status, success} flushed by /status", cmds)
	}
}

// TestTRTUI8_StatusStateSourcesSessionFromMemoryNotDisk pins in-memory session sourcing at the
// production source boundary the submit-path test cannot isolate: the production
// statusState must read the session id, start timestamp, and record stream from the
// active in-memory store, never from the session file. The submit-path test above
// flushes the session before snapshotting (cmd_status.go), so a regression that read
// those fields back from store.Path() would render identical values there and pass.
// Here the in-memory store and the on-disk file at the same path are seeded with
// deliberately different ids, start timestamps, and token totals, and the snapshot is
// built directly through newStatusState + BuildStatusSnapshot with no /status dispatch
// and no flush, so the on-disk values stay divergent. The assertions match the
// in-memory values, so a statusState that read from store.Path() would render the disk
// values and fail.
func TestTRTUI8_StatusStateSourcesSessionFromMemoryNotDisk(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "session.json")

	// On-disk session: a one-off store flushed once through the real codec, carrying
	// a different id/start and a model_response with different token totals than the
	// in-memory store below. This is the file a disk-reading regression would pick up.
	diskStore := sessions.New(path, &sessions.Session{Metadata: sessions.Metadata{
		ID:            "01890000-0000-7000-8000-0000000000d1",
		Folder:        "/proj",
		StartedAt:     time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:     time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		SchemaVersion: sessions.CurrentSchemaVersion,
	}})
	if err := model.EmitModelResponse(diskStore, "openai", "gpt-5.5", 999, 888, nil, false, nil, ""); err != nil {
		t.Fatalf("seed disk model_response: %v", err)
	}
	if _, _, err := diskStore.Flush(ctx); err != nil {
		t.Fatalf("flush disk session: %v", err)
	}

	// In-memory store at the same path, never flushed, so the divergent disk file
	// stays in place: id 01890000-...00a1, started_at testStart, tokens 120/340.
	inMem := sessions.New(path, &sessions.Session{Metadata: sessions.Metadata{
		ID:            "01890000-0000-7000-8000-0000000000a1",
		Folder:        "/proj",
		StartedAt:     testStart,
		UpdatedAt:     testStart,
		SchemaVersion: sessions.CurrentSchemaVersion,
	}})
	if err := model.EmitModelResponse(inMem, "openai", "gpt-5.5", 120, 340, nil, false, nil, ""); err != nil {
		t.Fatalf("seed in-memory model_response: %v", err)
	}

	app := tui.New(nil)
	app.SetActiveStore(inMem)
	status := newStatusState(app, providerCache(t, t.TempDir()), selectedState(), &BootstrapResult{LaunchDir: "/launch"}, enforce.Resolution{})

	// Build the snapshot directly: no /status dispatch, so no pre-snapshot flush
	// re-stamps the file with the in-memory state.
	snap := tui.BuildStatusSnapshot(status)

	if snap.SessionID != inMem.SessionID() {
		t.Errorf("snapshot session id = %q, want in-memory %q (not the disk id %q)", snap.SessionID, inMem.SessionID(), "01890000-0000-7000-8000-0000000000d1")
	}
	if !snap.StartedAt.Equal(testStart) {
		t.Errorf("snapshot start = %v, want in-memory %v (not the disk start 2020-01-01)", snap.StartedAt, testStart)
	}
	if snap.InputTokens != 120 || snap.OutputTokens != 340 {
		t.Errorf("snapshot tokens = %d input / %d output, want in-memory 120/340 (not the disk 999/888)", snap.InputTokens, snap.OutputTokens)
	}
}

func TestStatusOverlay_WebResearchStateComesFromBootstrappedConfig(t *testing.T) {
	const sentinelKey = "exa-secret-do-not-render"
	for _, tc := range []struct {
		name     string
		composed map[string]any
		onDisk   string
		want     string
		absent   string
	}{
		{
			name:     "disabled in memory, enabled on disk",
			composed: map[string]any{"enabled": false},
			onDisk:   "web_research:\n  enabled: true\n  api_key: \"" + sentinelKey + "\"\n",
			want:     "web research: off",
			absent:   "web research: on",
		},
		{
			name:     "enabled with key in memory, disabled on disk",
			composed: map[string]any{"enabled": true, "api_key": sentinelKey},
			onDisk:   "web_research:\n  enabled: false\n",
			want:     "web research: on — mcp.exa.ai",
			absent:   "web research: off",
		},
		{
			name:     "enabled without key in memory, disabled on disk",
			composed: map[string]any{"enabled": true},
			onDisk:   "web_research:\n  enabled: false\n",
			want:     "web research: on — mcp.exa.ai",
			absent:   "web research: off",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			layerPath := filepath.Join(t.TempDir(), "settings.yaml")
			if err := os.WriteFile(layerPath, []byte(tc.onDisk), 0o600); err != nil {
				t.Fatalf("write divergent settings layer: %v", err)
			}

			result := &BootstrapResult{
				Home:             "/home/dev",
				LaunchDir:        "/work/launchdir",
				ProjectRoot:      "/work/project",
				ConfigLayerPaths: []string{layerPath},
				Config:           map[string]any{"web_research": tc.composed},
				Model:            selectedState(),
				Session:          mkStore(t),
			}

			app, restore := startCaptured(t, ctx, result, io.Discard)
			defer restore()

			if !app.SubmitInput("/status") {
				t.Fatal("/status rejected through the production StartTUI submit path")
			}
			overlay := app.StatusText()
			if !strings.Contains(overlay, tc.want) {
				t.Fatalf("status overlay missing %q\n--- overlay ---\n%s", tc.want, overlay)
			}
			if strings.Contains(overlay, tc.absent) {
				t.Errorf("status overlay carries %q\n--- overlay ---\n%s", tc.absent, overlay)
			}
			if strings.Contains(overlay, sentinelKey) {
				t.Errorf("status overlay discloses the configured Exa key\n--- overlay ---\n%s", overlay)
			}
		})
	}
}

// TestStatusOverlay_KeepsChatGPTProviderId pins the provider id: when the active selection's
// provider is the built-in openai-chatgpt, the /status overlay renders the stable
// provider id, never the "OpenAI ChatGPT" display name — display names belong only to
// picker group headers. It builds the snapshot directly through the production
// newStatusState + BuildStatusSnapshot, then renders it.
func TestStatusOverlay_KeepsChatGPTProviderId(t *testing.T) {
	app := tui.New(nil)
	app.SetActiveStore(mkStore(t))
	active := model.NewActiveState(&model.Selection{Provider: "openai-chatgpt", ID: "gpt-5.5", Effort: "medium"}, model.SourceResume)

	status := newStatusState(app, providerCache(t, t.TempDir()), active, &BootstrapResult{LaunchDir: "/launch"}, enforce.Resolution{})
	overlay := tui.RenderStatus(tui.BuildStatusSnapshot(status))

	if !strings.Contains(overlay, "Provider: openai-chatgpt") {
		t.Errorf("status overlay = %q, want it to show Provider: openai-chatgpt (the stable id)", overlay)
	}
	if strings.Contains(overlay, "OpenAI ChatGPT") {
		t.Errorf("status overlay = %q, want it to not substitute the display name", overlay)
	}
}
