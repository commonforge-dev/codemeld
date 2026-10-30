// Tests for the /status overlay: snapshot ordering
// token aggregation, attestability, no-disk-at-open behavior driven through
// an injected StatusState fake, plus the dispatch + ESC-dismiss path.
package tui

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/trust"
)

// statusStateFake is a recording StatusState used by every cmd_status test.
// Each accessor ticks a hit counter so tests can prove the snapshot reads
// only in-memory state and never paths through a method that would touch
// disk ("single snapshot... no disk I/O at open").
type statusStateFake struct {
	version       string
	launchDir     string
	projectRoot   string
	layers        []StatusLayer
	provider      string
	modelID       string
	effort        string
	agents        []agentinstr.LoadEntry
	sessionID     string
	startedAt     time.Time
	records       []sessions.Record
	webEnabled    bool
	webKey        string
	approval      ApprovalDisclosure
	sandbox       string
	reason        string
	modeKey       string
	approvalHits  int
	capHits       int
	webHits       int
	versionHits   int
	launchHits    int
	projectHits   int
	layerHits     int
	selectionHits int
	agentsHits    int
	sessionIDHits int
	startedAtHits int
	recordsHits   int
}

func (s *statusStateFake) Version() string {
	s.versionHits++
	return s.version
}

func (s *statusStateFake) LaunchDir() string {
	s.launchHits++
	return s.launchDir
}

func (s *statusStateFake) ProjectRoot() string {
	s.projectHits++
	return s.projectRoot
}

// Layers hands back the stored rows without copying them, so a test that mutates the
// fake's slice afterwards exercises BuildStatusSnapshot's own freeze.
func (s *statusStateFake) Layers() []StatusLayer {
	s.layerHits++
	return s.layers
}

func (s *statusStateFake) Selection() (string, string, string) {
	s.selectionHits++
	return s.provider, s.modelID, s.effort
}

func (s *statusStateFake) AgentInstructions() []agentinstr.LoadEntry {
	s.agentsHits++
	out := make([]agentinstr.LoadEntry, len(s.agents))
	copy(out, s.agents)
	return out
}

// Approval hands back the stored disclosure without copying it, so a test that mutates
// the fake's slice afterwards exercises BuildStatusSnapshot's own freeze rather than
// a defensive copy the fake made for it.
func (s *statusStateFake) Approval() ApprovalDisclosure {
	s.approvalHits++
	return s.approval
}

func (s *statusStateFake) SandboxStatus() (string, string, string) {
	s.capHits++
	return s.sandbox, s.reason, s.modeKey
}

func (s *statusStateFake) SessionID() string {
	s.sessionIDHits++
	return s.sessionID
}

func (s *statusStateFake) SessionStartedAt() time.Time {
	s.startedAtHits++
	return s.startedAt
}

func (s *statusStateFake) WebResearch() bool {
	s.webHits++
	return s.webEnabled
}

func (s *statusStateFake) Records() []sessions.Record {
	s.recordsHits++
	out := make([]sessions.Record, len(s.records))
	copy(out, s.records)
	return out
}

// fixtureState returns a populated statusStateFake that satisfies TR-TUI-8's
// "session with at least one AGENTS.md loaded and at least one completed
// turn" precondition.
func fixtureState() *statusStateFake {
	started, _ := time.Parse(time.RFC3339, "2026-05-28T10:00:00Z")
	return &statusStateFake{
		version:     "0.1.0-test",
		launchDir:   "/work/codemeld",
		projectRoot: "/work/codemeld",
		layers: []StatusLayer{
			{Kind: "global", Path: "/home/dev/.codemeld/global/settings.yaml"},
			{Kind: "project", Path: "/work/codemeld/.codemeld/settings.yaml"},
			{Kind: "local", Path: "/work/codemeld/.codemeld/settings.local.yaml"},
		},
		provider: "openai",
		modelID:  "gpt-4",
		effort:   "medium",
		agents: []agentinstr.LoadEntry{
			{Path: "/home/dev/.codemeld/global/AGENTS.md", Layer: "global", LoadOrder: 1},
			{Path: "/work/codemeld/AGENTS.md", Layer: "walked", LoadOrder: 2},
		},
		sessionID: "01890000-0000-7000-8000-000000000001",
		startedAt: started,
		approval:  ApprovalDisclosure{Approved: true, Reason: trust.ReasonTrusted},
		records: []sessions.Record{
			modelResponseRecord(t0, "openai", "gpt-4", 100, 250, nil),
		},
	}
}

var t0 = mustParseTime("2026-05-28T10:00:01Z")

func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// modelResponseRecord builds a sessions.Event carrying a valid model_response
// payload, mirroring the on-disk shape Append would produce.
func modelResponseRecord(ts time.Time, provider, modelID string, input, output int64, anomaly []string) sessions.Event {
	p := events.ModelResponse{
		Provider:     provider,
		ModelID:      modelID,
		InputTokens:  input,
		OutputTokens: output,
		Anomaly:      append([]string(nil), anomaly...),
	}
	if p.Anomaly == nil {
		p.Anomaly = []string{}
	}
	data, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	return sessions.Event{
		ID:        ids.NewV7(),
		Kind:      events.KindModelResponse,
		Timestamp: ts,
		Payload:   data,
	}
}

// visibleStatusText renders RenderStatus's markup through a dynamic-color
// TextView (matching the production a.status surface) and returns the
// visible text: bold [::b]Title[::-] section tags are stripped to their styling
// and escaped bracket labels are unescaped back to [global]/[project]. Tests
// assert against this so they pin what the user actually sees, not the raw tags.
func visibleStatusText(snap StatusSnapshot) string {
	tv := tview.NewTextView()
	tv.SetDynamicColors(true)
	tv.SetText(RenderStatus(snap))
	return tv.GetText(true)
}

func TestRenderStatus_RendersAllElevenItemsInOrder(t *testing.T) {
	snap := BuildStatusSnapshot(fixtureState())
	raw := RenderStatus(snap)
	out := visibleStatusText(snap)

	// Section titles are emitted as bold tview markup, so the raw render
	// carries the tags but the visible text shows the bare title (the dynamic-color
	// TextView renders them as styling, not literal [::b]...[::-] text).
	for _, title := range []string{"Session", "Location", "Model", "Context", "Usage"} {
		if !strings.Contains(raw, "[::b]"+title+"[::-]") {
			t.Errorf("raw render missing bold markup for section %q:\n%s", title, raw)
		}
	}
	if strings.Contains(out, "[::b]") || strings.Contains(out, "[::-]") {
		t.Errorf("visible status text still shows literal bold tags; markup did not render as styling:\n%s", out)
	}

	// A blank line separates each section from the previous one (the first
	// section, Session, opens the output so it has none before it).
	for _, title := range []string{"Location", "Model", "Context", "Usage"} {
		if !strings.Contains(out, "\n\n"+title+"\n") {
			t.Errorf("section %q is not preceded by a blank line:\n%s", title, out)
		}
	}

	// The fixed 11-item order is preserved within the grouped layout
	// each item — and the section title that introduces its group — appears at a
	// strictly increasing position in the visible text.
	prefixes := []string{
		"Session\n",                             // section title
		"codemeld 0.1.0-test",                   // 1
		"Session: 01890000-0000-7000-8000-",     // 2
		"Started: 2026-05-28T10:00:00.000Z",     // 3
		"Location\n",                            // section title
		"Launch dir: /work/codemeld",            // 4
		"Project root: /work/codemeld (same as", // 5 with suffix
		"Model\n",                               // section title
		"Provider: openai",                      // 6
		"Model: gpt-4",                          // 7
		"Effort: medium",                        // 8
		"Context\n",                             // section title
		"AGENTS.md files:",                      // 9 header
		"Config layer sources:",                 // 10 header
		"Usage\n",                               // section title
		"Token usage: 100 input, 250 output",    // 11 totals
	}
	last := -1
	for _, p := range prefixes {
		idx := strings.Index(out, p)
		if idx < 0 {
			t.Fatalf("status overlay missing item %q\n--- output ---\n%s", p, out)
		}
		if idx <= last {
			t.Fatalf("status overlay item %q appeared at %d, but a later item already appeared at %d (req 585 ordering)\n--- output ---\n%s", p, idx, last, out)
		}
		last = idx
	}

	// A fully attestable session (the fixture) shows no attestability line
	// and no incomplete-counts line — the overlay ends at the Token usage line.
	if strings.Contains(out, "Attestability:") {
		t.Errorf("fully attestable overlay still renders a superseded Attestability line:\n%s", out)
	}
	if strings.Contains(out, "Token counts:") {
		t.Errorf("fully attestable overlay renders an incomplete-counts line:\n%s", out)
	}

	// Each AGENTS.md and config-layer line must appear under its header, in
	// load-order/farthest-first order, with the bracket labels rendered literally.
	agentsHdr := strings.Index(out, "AGENTS.md files:")
	cfgHdr := strings.Index(out, "Config layer sources:")
	if got := strings.Index(out, "/home/dev/.codemeld/global/AGENTS.md [global, load_order=1]"); got < agentsHdr || got > cfgHdr {
		t.Errorf("global AGENTS.md line at %d, want between AGENTS.md header (%d) and config header (%d)", got, agentsHdr, cfgHdr)
	}
	if got := strings.Index(out, "/work/codemeld/AGENTS.md [walked, load_order=2]"); got < agentsHdr || got > cfgHdr {
		t.Errorf("walked AGENTS.md line at %d, want between AGENTS.md header (%d) and config header (%d)", got, agentsHdr, cfgHdr)
	}
	globalCfg := strings.Index(out, "/home/dev/.codemeld/global/settings.yaml [global]")
	projectCfg := strings.Index(out, "/work/codemeld/.codemeld/settings.yaml [project]")
	localCfg := strings.Index(out, "/work/codemeld/.codemeld/settings.local.yaml [local]")
	if globalCfg < cfgHdr {
		t.Errorf("global config layer line at %d, want after config header (%d)", globalCfg, cfgHdr)
	}
	if globalCfg >= projectCfg || projectCfg >= localCfg {
		t.Errorf("config layer order: global=%d project=%d local=%d, want global, project, local", globalCfg, projectCfg, localCfg)
	}
}

// TestRenderStatus_EscapesBracketDataInDynamicColorView pins the
// output-encoding contract: runtime status data containing [tag]-like sequences
// must survive rendering through the dynamic-color status TextView literally,
// instead of being swallowed as tview color markup. Without escaping in
// RenderStatus, values like "/tmp/[red]work" lose their bracket sequence.
func TestRenderStatus_EscapesBracketDataInDynamicColorView(t *testing.T) {
	state := fixtureState()
	state.launchDir = "/tmp/[red]work"
	state.projectRoot = "/tmp/[::b]root[::-]"
	state.modelID = "gpt-[yellow]"
	state.provider = "open[blue]ai"
	state.effort = "med[green]ium"
	state.version = "0.1.0-[white]"
	state.sessionID = "01890000-[u]-7000"
	state.agents = []agentinstr.LoadEntry{
		{Path: "/work/[blue]/AGENTS.md", Layer: "global", LoadOrder: 1},
	}
	state.layers = []StatusLayer{{Kind: "[blue]", Path: "/home/[red]/settings.yaml"}}

	out := visibleStatusText(BuildStatusSnapshot(state))

	for _, literal := range []string{
		"/tmp/[red]work",
		"/tmp/[::b]root[::-]",
		"gpt-[yellow]",
		"open[blue]ai",
		"med[green]ium",
		"0.1.0-[white]",
		"01890000-[u]-7000",
		"/work/[blue]/AGENTS.md",
		"/home/[red]/settings.yaml [[blue]]",
	} {
		if !strings.Contains(out, literal) {
			t.Errorf("visible status text dropped literal bracket data %q (parsed as markup):\n%s", literal, out)
		}
	}
}

func TestRenderStatus_EscapesControlCharactersInRuntimePaths(t *testing.T) {
	render := func(name string) string {
		state := fixtureState()
		state.launchDir = "/l/" + name
		state.projectRoot = "/r/" + name
		state.approval = ApprovalDisclosure{Reason: trust.ReasonNoRecord, Withheld: []string{
			"project settings /r/" + name + "/.codemeld/settings.yaml",
		}}
		return RenderStatus(BuildStatusSnapshot(state))
	}
	raw := render("x\x1b\x1b[2Jy\rz\nProject approval: approved\u009b")
	escaped := `x\x1B\x1B[2Jy\x0Dz\x0AProject approval: approved\u009B`

	for _, line := range []string{
		"\nLaunch dir: /l/" + escaped + "\n",
		"\nProject root: /r/" + escaped + "\n",
		"\nProject approval: not approved — ignoring project settings /r/" + escaped + "/.codemeld/settings.yaml\n",
	} {
		if !strings.Contains(raw, line) {
			t.Errorf("status render missing %q:\n%s", line, raw)
		}
	}
	if strings.ContainsAny(raw, "\x1b\r\u009b") {
		t.Errorf("status render carries a raw control from a runtime value: %q", raw)
	}
	if got, want := strings.Count(raw, "\n"), strings.Count(render("plain"), "\n"); got != want {
		t.Errorf("status render has %d lines, want %d as for an ordinary folder name:\n%s", got, want, raw)
	}

	tv := tview.NewTextView()
	tv.SetDynamicColors(true)
	tv.SetText(raw)
	visible := tv.GetText(true)
	if n := strings.Count("\n"+visible, "\nProject approval:"); n != 1 {
		t.Errorf("visible status shows %d approval rows, want 1:\n%s", n, visible)
	}
	if !strings.Contains(visible, "Launch dir: /l/"+escaped+"\n") {
		t.Errorf("visible status lost the escaped launch dir:\n%s", visible)
	}
}

func TestRenderStatus_WebResearchLineReflectsInMemoryState(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		key     string
		want    string
		absent  []string
	}{
		{
			name:   "disabled",
			want:   "web research: off",
			absent: []string{"mcp.exa.ai", "web research: on"},
		},
		{
			name:    "enabled with key",
			enabled: true,
			key:     "exa-key-value",
			want:    "web research: on — mcp.exa.ai",
			absent:  []string{"web research: off", "requires an Exa API key"},
		},
		{
			name:    "enabled without key",
			enabled: true,
			want:    "web research: on — mcp.exa.ai",
			absent:  []string{"web research: off", "requires an Exa API key"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := fixtureState()
			state.webEnabled = tc.enabled
			state.webKey = tc.key

			out := visibleStatusText(BuildStatusSnapshot(state))
			if !strings.Contains(out, tc.want) {
				t.Errorf("status overlay missing web-research line %q:\n%s", tc.want, out)
			}
			for _, absent := range tc.absent {
				if strings.Contains(out, absent) {
					t.Errorf("status overlay carries %q for the %s state:\n%s", absent, tc.name, out)
				}
			}
			if state.webHits != 1 {
				t.Errorf("WebResearch read %d times, want exactly 1 (snapshot-at-open)", state.webHits)
			}
		})
	}
}

func TestRenderStatus_WebResearchNeverDisclosesAPIKey(t *testing.T) {
	const sentinel = "exa-secret-do-not-render"
	for _, enabled := range []bool{false, true} {
		state := fixtureState()
		state.webEnabled = enabled
		state.webKey = sentinel

		snap := BuildStatusSnapshot(state)
		if strings.Contains(RenderStatus(snap), sentinel) {
			t.Fatalf("rendered /status overlay discloses the configured Exa key (enabled=%v)", enabled)
		}
		if strings.Contains(RenderStatusLine(state), sentinel) {
			t.Fatalf("persistent status line discloses the configured Exa key (enabled=%v)", enabled)
		}
	}
}

func TestBuildStatusSnapshot_ProjectMatchesLaunchSuffix(t *testing.T) {
	state := fixtureState()
	state.projectRoot = state.launchDir
	if got := RenderStatus(BuildStatusSnapshot(state)); !strings.Contains(got, "Project root: /work/codemeld (same as launch dir)") {
		t.Errorf("project root line missing the (same as launch dir) suffix:\n%s", got)
	}

	state.projectRoot = "/work"
	if got := RenderStatus(BuildStatusSnapshot(state)); strings.Contains(got, "(same as launch dir)") {
		t.Errorf("project root line carries the (same as launch dir) suffix when paths differ:\n%s", got)
	}
}

func TestBuildStatusSnapshot_SumsTokenUsageAcrossModelResponses(t *testing.T) {
	state := fixtureState()
	state.records = []sessions.Record{
		modelResponseRecord(t0, "openai", "gpt-4", 100, 200, nil),
		modelResponseRecord(t0.Add(time.Second), "openai", "gpt-4", 50, 75, nil),
		// A non-model_response record must not affect the totals.
		sessions.Event{ID: ids.NewV7(), Kind: events.KindSlashCommand, Timestamp: t0, Payload: []byte(`{"name":"status","args":[],"outcome":"success"}`)},
		modelResponseRecord(t0.Add(2*time.Second), "openai", "gpt-4", 7, 11, nil),
	}
	snap := BuildStatusSnapshot(state)
	if snap.InputTokens != 157 {
		t.Errorf("InputTokens = %d, want 157 (100+50+7)", snap.InputTokens)
	}
	if snap.OutputTokens != 286 {
		t.Errorf("OutputTokens = %d, want 286 (200+75+11)", snap.OutputTokens)
	}
}

func TestBuildStatusSnapshot_AttestabilityFlipsOnUsageMissingAnomaly(t *testing.T) {
	state := fixtureState()
	state.records = []sessions.Record{
		modelResponseRecord(t0, "openai", "gpt-4", 100, 200, nil),
	}
	fullySnap := BuildStatusSnapshot(state)
	if !fullySnap.FullyAttestable {
		t.Error("FullyAttestable = false when no anomaly present, want true")
	}
	// A fully attestable session renders no incomplete-counts line.
	if out := RenderStatus(fullySnap); strings.Contains(out, "Token counts:") {
		t.Errorf("fully attestable overlay renders an incomplete-counts line:\n%s", out)
	}
	state.records = []sessions.Record{
		modelResponseRecord(t0, "openai", "gpt-4", 100, 200, nil),
		modelResponseRecord(t0.Add(time.Second), "openai", "gpt-4", 0, 0, []string{"usage_missing"}),
	}
	snap := BuildStatusSnapshot(state)
	if snap.FullyAttestable {
		t.Error("FullyAttestable = true when usage_missing anomaly present, want false")
	}
	// A not-fully-attestable session renders exactly one incomplete-counts
	// line and no superseded Attestability line.
	out := RenderStatus(snap)
	if !strings.Contains(out, "Token counts: incomplete (some turns did not report usage)") {
		t.Errorf("overlay does not render the incomplete-counts line for a usage_missing anomaly:\n%s", out)
	}
	if strings.Contains(out, "Attestability:") {
		t.Errorf("overlay still renders the superseded Attestability line:\n%s", out)
	}
}

func TestBuildStatusSnapshot_EmptyLayersAndAgents(t *testing.T) {
	state := fixtureState()
	state.layers = nil
	state.agents = nil
	out := RenderStatus(BuildStatusSnapshot(state))
	// Headers still render so the 11-item order is preserved even on a fresh
	// session with no AGENTS.md and a single global-only layer absent.
	if !strings.Contains(out, "AGENTS.md files:\n  (none)") {
		t.Errorf("empty AGENTS.md section missing the (none) placeholder:\n%s", out)
	}
	if !strings.Contains(out, "Config layer sources:\n  (none)") {
		t.Errorf("empty config layer section missing the (none) placeholder:\n%s", out)
	}
}

// TestRenderStatus_SkippedAgentInstructionsAreFilteredOut pins item 9
// against the "loaded" wording: an oversize or unreadable AGENTS.md candidate
// from agentinstr.LoadEntry must not appear in the overlay's loaded list, and a
// section with only skipped entries renders (none) so the 11-item order holds.
func TestRenderStatus_SkippedAgentInstructionsAreFilteredOut(t *testing.T) {
	state := fixtureState()
	state.agents = []agentinstr.LoadEntry{
		{Path: "/home/dev/.codemeld/global/AGENTS.md", Layer: agentinstr.LayerGlobal, LoadOrder: 1},
		{Path: "/work/codemeld/AGENTS.md", Layer: agentinstr.LayerWalked, LoadOrder: 2, Skipped: true, SkipReason: agentinstr.SkipSizeLimit},
	}
	out := RenderStatus(BuildStatusSnapshot(state))
	if !strings.Contains(out, "/home/dev/.codemeld/global/AGENTS.md [global, load_order=1]") {
		t.Errorf("loaded global AGENTS.md missing from overlay:\n%s", out)
	}
	if strings.Contains(out, "/work/codemeld/AGENTS.md") {
		t.Errorf("skipped AGENTS.md was rendered as a loaded file:\n%s", out)
	}
	if strings.Contains(out, "size_limit") {
		t.Errorf("overlay leaks the skip reason in the loaded-files section:\n%s", out)
	}

	state.agents = []agentinstr.LoadEntry{
		{Path: "/work/codemeld/AGENTS.md", Layer: agentinstr.LayerWalked, LoadOrder: 2, Skipped: true, SkipReason: agentinstr.SkipSizeLimit},
	}
	out = RenderStatus(BuildStatusSnapshot(state))
	if !strings.Contains(out, "AGENTS.md files:\n  (none)") {
		t.Errorf("section with only skipped entries does not render the (none) placeholder:\n%s", out)
	}
}

func TestNewStatusHandler_DispatchAppendsSuccessEventAndOpensOverlay(t *testing.T) {
	host := newFakeHost()
	state := fixtureState()
	reg, err := NewRegistry([]Command{
		{Name: "status", Description: "Open the session status overlay", ArgSig: ArgNone, Phase: PhaseOne, Handler: NewStatusHandler(state)},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	res := reg.DispatchSlashInput("/status", host)
	if res.Status != StatusHandled || res.Canonical != "status" || res.Err != nil {
		t.Fatalf("dispatch /status = %+v, want Handled/status/nil-err", res)
	}

	// The handler must append exactly one slash_command success event with the
	// canonical name and an empty args list.
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	p := decodeSlash(t, evs[0])
	if p.Name != "status" || p.Outcome != "success" || len(p.Args) != 0 {
		t.Errorf("event = %+v, want name=status args=[] outcome=success", p)
	}

	// The overlay must open via ShowStatus (not ShowPanel), so /status renders
	// on the accent-bordered status surface rather than the /help panel.
	if len(host.statuses) != 1 {
		t.Fatalf("ShowStatus called %d times, want 1", len(host.statuses))
	}
	if len(host.panels) != 0 {
		t.Errorf("ShowPanel called %d times, want 0 (status uses its own surface)", len(host.panels))
	}
	for _, want := range []string{"codemeld 0.1.0-test", "Session:", "Token usage:"} {
		if !strings.Contains(host.statuses[0], want) {
			t.Errorf("status overlay text missing %q\n--- overlay ---\n%s", want, host.statuses[0])
		}
	}
}

func TestNewStatusHandler_NoDiskIOAtOpen(t *testing.T) {
	// item 11: the snapshot is built from in-memory state with no
	// disk read. The store carries an empty path on purpose — the snapshot build
	// must never flush or read it directly (an atomic write rejects ""), so a
	// passing dispatch proves the snapshot did no disk I/O of its own. The
	// slash_command flush is a separate, host-delegated step
	// (ctx.FlushActive), a no-op against fakeHost; its on-disk durability is
	// covered by the bootstrap submit-boundary tests.
	host := &fakeHost{store: sessions.New("", &sessions.Session{})}
	state := fixtureState()
	reg, err := NewRegistry([]Command{
		{Name: "status", Description: "Open the session status overlay", ArgSig: ArgNone, Phase: PhaseOne, Handler: NewStatusHandler(state)},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	res := reg.DispatchSlashInput("/status", host)
	if res.Err != nil {
		t.Fatalf("dispatch /status err = %v, want nil (no disk I/O should fire)", res.Err)
	}
	if state.recordsHits != 1 || state.agentsHits != 1 || state.layerHits != 1 || state.webHits != 1 {
		t.Errorf("snapshot did not read each state source exactly once: records=%d agents=%d layers=%d web_research=%d", state.recordsHits, state.agentsHits, state.layerHits, state.webHits)
	}
}

// statusOrderHost records the order in which the command-event flush and the
// overlay open fire, so a test can prove the appended slash_command is flushed
// durable before the overlay opens — never the reverse.
type statusOrderHost struct {
	*fakeHost
	order []string
}

func (h *statusOrderHost) FlushActive() error {
	h.order = append(h.order, "flush")
	return h.fakeHost.FlushActive()
}

func (h *statusOrderHost) ShowStatus(text string) {
	h.order = append(h.order, "show")
	h.fakeHost.ShowStatus(text)
}

// TestNewStatusHandler_FlushesBeforeOpeningOverlay pins the flush boundary: the
// handler appends the slash_command, flushes it durable via FlushActive, and only
// then opens the overlay. A de-abstraction that dropped the flush or moved it after
// ShowStatus would open the overlay over a still-in-memory slash_command record.
func TestNewStatusHandler_FlushesBeforeOpeningOverlay(t *testing.T) {
	host := &statusOrderHost{fakeHost: newFakeHost()}
	state := fixtureState()
	reg, err := NewRegistry([]Command{
		{Name: "status", Description: "Open the session status overlay", ArgSig: ArgNone, Phase: PhaseOne, Handler: NewStatusHandler(state)},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	res := reg.DispatchSlashInput("/status", host)
	if res.Err != nil {
		t.Fatalf("dispatch /status err = %v, want nil", res.Err)
	}
	if host.flushes != 1 {
		t.Errorf("FlushActive called %d times, want 1 (the appended slash_command must be flushed durable)", host.flushes)
	}
	if len(host.statuses) != 1 {
		t.Fatalf("ShowStatus called %d times, want 1", len(host.statuses))
	}
	if len(host.order) != 2 || host.order[0] != "flush" || host.order[1] != "show" {
		t.Errorf("operation order = %v, want [flush show] (flush must be durable before the overlay opens)", host.order)
	}
}

func TestApp_ShowStatusBlocksInput(t *testing.T) {
	a := New(nil)
	a.ShowStatus("status body")
	if !a.statusOpen {
		t.Fatal("status overlay did not open (open flag false)")
	}
	if got := a.status.GetText(true); !strings.Contains(got, "status body") {
		t.Errorf("status overlay text = %q, want it to contain %q", got, "status body")
	}
	if a.app.GetFocus() != a.status {
		t.Error("focus is not on the status overlay while open; input is not blocked")
	}
}

// TestApp_StatusOverlayDrawsNoChrome pins the chromeless overlay: the /status overlay draws no
// chrome of its own — no top or bottom horizontal rule and no box border. The
// input area's own bottom rule is the only separator above the snapshot (a second
// rule one row below it read as a redundant separator bar), so the snapshot text
// occupies the overlay's top row with no rule/corner/vertical runes anywhere.
// Drawn synchronously via drawPrimitive so the geometry is deterministic.
func TestApp_StatusOverlayDrawsNoChrome(t *testing.T) {
	a := New(nil)
	a.status.SetText("STATUS BODY LINE")
	screen := drawPrimitive(t, a.status, 30, 3)

	cells, width, height := screen.GetContents()
	bodyRow := -1
	for row := 0; row < height; row++ {
		for col := 0; col < width; col++ {
			runes := cells[row*width+col].Runes
			if len(runes) == 0 {
				continue
			}
			switch runes[0] {
			case tcell.RuneHLine,
				tcell.RuneVLine,
				tcell.RuneULCorner, tcell.RuneURCorner,
				tcell.RuneLLCorner, tcell.RuneLRCorner:
				t.Fatalf("status overlay drew a rule/border rune %q at row %d col %d; want no chrome of its own (f345)", string(runes[0]), row, col)
			default:
				if bodyRow < 0 && runes[0] == 'S' {
					bodyRow = row
				}
			}
		}
	}
	if bodyRow != 0 {
		t.Fatalf("status body on row %d, want it on the top row (0) with no rule above it", bodyRow)
	}
}

func TestApp_StatusEscDismissesAndRetainsInput(t *testing.T) {
	a := New(nil)
	a.input.SetText("draft text")
	a.ShowStatus("status body")

	if got := a.handleStatusKey(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone)); got != nil {
		t.Error("ESC was not consumed by the status overlay")
	}
	if a.statusOpen {
		t.Error("statusOpen = true after ESC")
	}
	if a.app.GetFocus() != a.input {
		t.Error("focus did not return to the input area after dismiss")
	}
	if txt := a.input.GetText(); txt != "draft text" {
		t.Errorf("input buffer = %q after ESC, want it retained as %q", txt, "draft text")
	}
}

func TestApp_StatusNonEscKeyDoesNotReachInput(t *testing.T) {
	a := New(nil)
	a.ShowStatus("status body")

	ev := tcell.NewEventKey(tcell.KeyRune, 'a', tcell.ModNone)
	if got := a.handleStatusKey(ev); got != ev {
		t.Error("non-ESC key was not passed through to the status overlay")
	}
	if !a.statusOpen {
		t.Error("status overlay dismissed by a non-ESC key (req 580 blocks input keystrokes)")
	}
}

// TestApp_StatusArrowKeysAreConsumed pins the /status overlay's "no auto-refresh" against
// the static snapshot: the arrow keys must not scroll the text view or close
// the overlay, so handleStatusKey consumes them and the overlay stays open.
func TestApp_StatusArrowKeysAreConsumed(t *testing.T) {
	cases := []struct {
		name string
		key  tcell.Key
	}{
		{"up", tcell.KeyUp},
		{"down", tcell.KeyDown},
		{"left", tcell.KeyLeft},
		{"right", tcell.KeyRight},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.ShowStatus("status body")

			ev := tcell.NewEventKey(tc.key, 0, tcell.ModNone)
			if got := a.handleStatusKey(ev); got != nil {
				t.Errorf("arrow key %v was not consumed by the status overlay", tc.key)
			}
			if !a.statusOpen {
				t.Errorf("arrow key %v dismissed the status overlay", tc.key)
			}
		})
	}
}

// TestApp_StatusPanelIsBelowInputInRootLayout pins the /status overlay's "temporary panel
// below the input area" as restyled into a borderless panel: the status text
// view must be a child of the root flex immediately after the input row and before the
// merged bottom bar row (statusBarRow: segments + mode pill + shift+tab hint), so the
// overlay sits directly under the input and pushes the bar down while open — not
// registered as a full-screen Pages overlay.
func TestApp_StatusPanelIsBelowInputInRootLayout(t *testing.T) {
	a := New(nil)

	count := a.root.GetItemCount()
	if count < 3 {
		t.Fatalf("root flex has %d items, want at least 3 (transcript, input, status)", count)
	}
	inputIdx, statusIdx, statusBarIdx := -1, -1, -1
	for i := 0; i < count; i++ {
		switch a.root.GetItem(i) {
		case a.input:
			inputIdx = i
		case a.status:
			statusIdx = i
		case a.statusBarRow:
			statusBarIdx = i
		}
	}
	if inputIdx < 0 {
		t.Fatal("input area is not a child of the root flex")
	}
	if statusIdx < 0 {
		t.Fatal("status panel is not a child of the root flex; req 580 requires it below the input area, not as a separate Pages page")
	}
	if statusIdx != inputIdx+1 {
		t.Errorf("status panel at index %d, want immediately after input (index %d) so its top rule joins the input's bottom rule", statusIdx, inputIdx)
	}
	// The merged bottom bar must follow the overlay, so the overlay pushes the bar down
	// while open.
	if statusBarIdx <= statusIdx {
		t.Errorf("bottom bar at index %d, want after the status overlay (index %d)", statusBarIdx, statusIdx)
	}
	// And it must not also be registered as a full-screen Pages page.
	if a.pages.HasPage("status") {
		t.Error("status is registered as a Pages page; req 580 requires it as a below-input panel in the root layout instead")
	}
}

// TestBuildRegistry_StatusDispatchesToHandler pins the production
// dispatch wiring: /status goes through NewStatusHandler — not recordHandler —
// so a single slash_command success event is appended and the overlay opens via
// ShowStatus.
func TestBuildRegistry_StatusDispatchesToHandler(t *testing.T) {
	host := newFakeHost()
	state := fixtureState()
	// Only /status is bound to its real handler; every other command keeps the
	// recordHandler placeholder, so a passing dispatch proves /status is wired.
	reg := BuildRegistry(map[string]HandlerFunc{"status": NewStatusHandler(state)})

	res := reg.DispatchSlashInput("/status", host)
	if res.Status != StatusHandled || res.Canonical != "status" || res.Err != nil {
		t.Fatalf("dispatch /status = %+v, want Handled/status/nil-err", res)
	}

	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	p := decodeSlash(t, evs[0])
	if p.Name != "status" || p.Outcome != "success" || len(p.Args) != 0 {
		t.Errorf("event = %+v, want name=status args=[] outcome=success", p)
	}

	if len(host.statuses) != 1 {
		t.Fatalf("ShowStatus called %d times via the production registry, want 1 (recordHandler would call 0)", len(host.statuses))
	}
	if len(host.panels) != 0 {
		t.Errorf("ShowPanel called %d times, want 0 (status uses its own surface)", len(host.panels))
	}
	for _, want := range []string{"codemeld 0.1.0-test", "Session:", "Token usage:"} {
		if !strings.Contains(host.statuses[0], want) {
			t.Errorf("status overlay text missing %q\n--- overlay ---\n%s", want, host.statuses[0])
		}
	}
}

// TestApp_StatusEscDismissesBeforeInFlightCancel pins the /status ESC ordering: while /status is
// open, ESC dismisses the modal ahead of any in-flight stream, so the underlying work is never
// cancelled and no stream_interrupted is recorded. /status is the one exception to the
// stream-first ESC priority in HandleEsc.
func TestApp_StatusEscDismissesBeforeInFlightCancel(t *testing.T) {
	a := New(nil)
	a.SetActiveStore(escTestStore())
	fc := &fakeStreamCanceller{retained: 7, inFlight: true}
	a.SetStreamCanceller(fc)
	a.input.SetText("draft text")
	a.ShowStatus("status body")

	a.HandleEsc()

	if a.statusOpen {
		t.Error("statusOpen = true after ESC; /status must dismiss before stream cancellation")
	}
	if fc.calls != 0 {
		t.Errorf("stream canceller called %d times; ESC on an open /status must not cancel in-flight work", fc.calls)
	}
	for _, k := range eventKinds(a.ActiveStore().Records()) {
		if k == events.KindStreamInterrupted {
			t.Error("stream_interrupted recorded; ESC on an open /status must not interrupt the stream")
		}
	}
	if txt := a.input.GetText(); txt != "draft text" {
		t.Errorf("input buffer = %q after ESC, want it retained as %q", txt, "draft text")
	}
}

const statusBody = "[::b]Model[::-]\nProvider: openai\nLayer: /home/dev/settings.yaml [global[]"

func statusReverseText(h *layoutHarness) string {
	h.t.Helper()
	var out string
	done := make(chan struct{})
	h.a.app.QueueUpdate(func() {
		defer close(done)
		_, sy, _, sh := h.a.status.GetRect()
		cells, width, height := h.screen.GetContents()
		for row := sy; row < sy+sh && row < height; row++ {
			for col := 0; col < width; col++ {
				c := cells[row*width+col]
				if _, _, attr := c.Style.Decompose(); attr&tcell.AttrReverse != 0 && len(c.Runes) > 0 {
					out += string(c.Runes)
				}
			}
		}
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		h.a.app.Stop()
		h.t.Fatal("status highlight read did not complete within 2s")
	}
	return out
}

func TestApp_StatusDragSelectsAndCopiesVisibleText(t *testing.T) {
	h := newLayoutHarness(t, 80, 24)
	defer h.stop()

	var captured []string
	h.runDraw(func() {
		h.a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
		h.a.ShowStatus(statusBody)
	})

	var sx, sy int
	h.runDraw(func() { sx, sy, _, _ = h.a.status.GetRect() })
	valueY := sy + 1
	h.injectMouse(sx+10, valueY, tcell.Button1)
	h.injectMouse(sx+16, valueY, tcell.Button1)

	if rev := statusReverseText(h); rev != "openai" {
		t.Fatalf("mid-drag highlight = %q, want %q", rev, "openai")
	}

	h.injectMouse(sx+16, valueY, tcell.ButtonNone)

	var (
		got     []string
		open    bool
		focused tview.Primitive
		body    string
	)
	h.runDraw(func() {
		got = append([]string(nil), captured...)
		open = h.a.statusOpen
		focused = h.a.app.GetFocus()
		body = h.a.status.GetText(true)
	})
	if want := osc52Sequence("openai"); len(got) != 1 || got[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one %q", got, want)
	}
	if !open {
		t.Error("statusOpen = false after a selection drag; the modal must stay open")
	}
	if focused != h.a.status {
		t.Error("focus left the /status modal after a selection drag")
	}
	if !strings.Contains(body, "Provider: openai") {
		t.Errorf("status snapshot text = %q, want the frozen snapshot unchanged by the drag", body)
	}
	if rev := statusReverseText(h); rev != "" {
		t.Fatalf("post-release highlight = %q, want it cleared", rev)
	}

	h.injectMouse(sx+2, valueY, tcell.Button1)
	h.injectMouse(sx+2, valueY, tcell.ButtonNone)
	h.runDraw(func() { got = append([]string(nil), captured...) })
	if len(got) != 1 {
		t.Fatalf("osc52 sink = %q after an empty press/release, want still exactly one copy", got)
	}
}

func TestApp_StatusSelectionMapsVisibleTextNotMarkup(t *testing.T) {
	const width, height = 40, 8
	body := "[::b]Model[::-]\nLayer: /dev/settings.yaml [global[]\nSession: alpha beta gamma delta epsilon zeta"

	drag := func(t *testing.T, x1, y1, x2, y2 int) (string, string) {
		t.Helper()
		a := New(nil)
		var captured []string
		a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
		a.ShowStatus(body)
		drawPrimitive(t, a.status, width, height)

		a.handleAppMouse(tcell.NewEventMouse(x1, y1, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
		a.handleAppMouse(tcell.NewEventMouse(x2, y2, tcell.Button1, tcell.ModNone), tview.MouseMove)
		highlight := reverseText(t, a.status, width, height)
		a.handleAppMouse(nil, tview.MouseLeftUp)
		if len(captured) != 1 {
			t.Fatalf("osc52 sink = %q, want exactly one copy", captured)
		}
		return captured[0], highlight
	}

	t.Run("escaped bracket data copies as the visible literal", func(t *testing.T) {
		got, highlight := drag(t, 26, 1, 34, 1)
		if want := osc52Sequence("[global]"); got != want {
			t.Fatalf("osc52 sink = %q, want %q (the escaped [global[] must copy as its visible literal)", got, want)
		}
		if highlight != "[global]" {
			t.Fatalf("mid-drag highlight = %q, want %q", highlight, "[global]")
		}
	})

	t.Run("selection continues across a wrapped row", func(t *testing.T) {
		want := "alpha beta gamma delta epsilon zeta"
		got, highlight := drag(t, 9, 2, 4, 3)
		if got != osc52Sequence(want) {
			t.Fatalf("osc52 sink = %q, want %q (the drag must follow the wrapped continuation row)", got, osc52Sequence(want))
		}
		if highlight != want {
			t.Fatalf("mid-drag highlight = %q, want %q", highlight, want)
		}
	})

	t.Run("a title-row drag copies no style markup", func(t *testing.T) {
		got, _ := drag(t, 0, 0, 5, 0)
		if want := osc52Sequence("Model"); got != want {
			t.Fatalf("osc52 sink = %q, want %q (the [::b] title tags must not be copied)", got, want)
		}
	})
}

func TestRenderStatus_SessionLineCarriesEscapedCopyControl(t *testing.T) {
	state := fixtureState()
	snap := BuildStatusSnapshot(state)
	raw := RenderStatus(snap)
	out := visibleStatusText(snap)

	if want := "Session: " + state.sessionID + " [click to copy]\n"; !strings.Contains(out, want) {
		t.Errorf("visible status text missing %q:\n%s", want, out)
	}
	if n := strings.Count(out, "[click to copy]"); n != 1 {
		t.Errorf("visible status text carries %d copy controls, want exactly 1:\n%s", n, out)
	}
	// The two halves split opposite ways: an escaped style tag draws literally, an
	// unescaped label is swallowed by the dynamic-color view and never drawn.
	if want := "[#1f9e8f::u][click to copy[]" + defaultTag + "[::U]"; !strings.Contains(raw, want) {
		t.Errorf("raw render missing %q:\n%s", want, raw)
	}
}

// TestApp_StatusCopyControlUnderlineStopsAtTheControl draws the panel and reads applied
// cell styles: the underline must not reach the Started: line that follows the session line.
func TestApp_StatusCopyControlUnderlineStopsAtTheControl(t *testing.T) {
	state := fixtureState()
	a := New(nil)
	a.SetStatusLineState(state)
	a.ShowStatus(RenderStatus(BuildStatusSnapshot(state)))

	screen := drawPrimitive(t, a.status, 80, 30)
	if got := underlinedText(screen); got != statusCopyControl {
		t.Errorf("underlined cells spell %q, want exactly the control %q", got, statusCopyControl)
	}
}

// TestApp_StatusCopyControlHitTestFollowsWrappedText clicks every cell of the drawn panel
// and reads back the glyphs of the cells that copied, so the activating region is pinned to
// exactly the drawn control. Width 20 pushes that control onto a wrapped continuation row
// and width 5 splits it across two, both of which a cell-rect hit test would address wrong.
func TestApp_StatusCopyControlHitTestFollowsWrappedText(t *testing.T) {
	for _, width := range []int{80, 20, 5} {
		t.Run(fmt.Sprintf("width=%d", width), func(t *testing.T) {
			const height = 30
			state := fixtureState()
			a := New(nil)
			a.SetStatusLineState(state)
			var captured []string
			a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
			a.ShowStatus(RenderStatus(BuildStatusSnapshot(state)))
			screen := drawPrimitive(t, a.status, width, height)
			cells, _, _ := screen.GetContents()
			a.afterFunc = func(time.Duration, func()) {}

			var hits strings.Builder
			for y := 0; y < height; y++ {
				for x := 0; x < width; x++ {
					captured = captured[:0]
					a.handleAppMouse(tcell.NewEventMouse(x, y, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
					a.handleAppMouse(nil, tview.MouseLeftUp)
					if len(captured) == 0 {
						continue
					}
					if want := osc52Sequence(state.sessionID); len(captured) != 1 || captured[0] != want {
						t.Fatalf("cell (%d,%d) emitted %q, want exactly one %q", x, y, captured, want)
					}
					hits.WriteString(string(cells[y*width+x].Runes))
				}
			}
			if got := hits.String(); got != statusCopyControl {
				t.Errorf("the cells that copy the session id spell %q, want exactly %q", got, statusCopyControl)
			}
		})
	}
}

func TestApp_StatusCopyControlNeedsPressAndReleaseOnIt(t *testing.T) {
	const width, height = 80, 30
	state := fixtureState()
	ctlX := len(statusSessionPrefix) + len(state.sessionID) + 1
	const ctlY = 2

	open := func(t *testing.T) (*App, *[]string) {
		t.Helper()
		a := New(nil)
		a.SetStatusLineState(state)
		captured := new([]string)
		a.input.osc52 = func(seq string) error { *captured = append(*captured, seq); return nil }
		a.ShowStatus(RenderStatus(BuildStatusSnapshot(state)))
		drawPrimitive(t, a.status, width, height)
		return a, captured
	}

	t.Run("a press on the control released elsewhere stays a selection", func(t *testing.T) {
		a, captured := open(t)
		a.handleAppMouse(tcell.NewEventMouse(ctlX, ctlY, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
		a.handleAppMouse(tcell.NewEventMouse(10, ctlY, tcell.Button1, tcell.ModNone), tview.MouseMove)
		a.handleAppMouse(nil, tview.MouseLeftUp)

		want := osc52Sequence(state.sessionID[1:] + " ")
		if len(*captured) != 1 || (*captured)[0] != want {
			t.Fatalf("osc52 sink = %q, want exactly one %q (the dragged visible text, not the session id)", *captured, want)
		}
		if got := a.NoticeText(); got != "" {
			t.Errorf("notice = %q after a drag off the control, want none", got)
		}
	})

	t.Run("a drag across the control copies the visible line", func(t *testing.T) {
		a, captured := open(t)
		a.handleAppMouse(tcell.NewEventMouse(0, ctlY, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
		a.handleAppMouse(tcell.NewEventMouse(ctlX+len(statusCopyControl), ctlY, tcell.Button1, tcell.ModNone), tview.MouseMove)
		a.handleAppMouse(nil, tview.MouseLeftUp)

		want := osc52Sequence(statusSessionPrefix + state.sessionID + " " + statusCopyControl)
		if len(*captured) != 1 || (*captured)[0] != want {
			t.Fatalf("osc52 sink = %q, want exactly one %q (a selection that includes the control copies its visible text)", *captured, want)
		}
		if got := a.NoticeText(); got != "" {
			t.Errorf("notice = %q after a selection drag, want none", got)
		}
	})

	t.Run("a press on the id released on the control stays a selection", func(t *testing.T) {
		a, captured := open(t)
		a.handleAppMouse(tcell.NewEventMouse(len(statusSessionPrefix), ctlY, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
		a.handleAppMouse(tcell.NewEventMouse(ctlX, ctlY, tcell.Button1, tcell.ModNone), tview.MouseMove)
		a.handleAppMouse(nil, tview.MouseLeftUp)

		want := osc52Sequence(state.sessionID + " ")
		if len(*captured) != 1 || (*captured)[0] != want {
			t.Fatalf("osc52 sink = %q, want exactly one %q (the dragged visible text, not the session id)", *captured, want)
		}
		if got := a.NoticeText(); got != "" {
			t.Errorf("notice = %q after a drag onto the control, want none", got)
		}
	})

	t.Run("a press outside the panel released on the control copies nothing", func(t *testing.T) {
		a, captured := open(t)
		a.handleAppMouse(tcell.NewEventMouse(5, height+5, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
		a.handleAppMouse(tcell.NewEventMouse(ctlX, ctlY, tcell.Button1, tcell.ModNone), tview.MouseLeftUp)

		if len(*captured) != 0 {
			t.Fatalf("osc52 sink = %q after a press outside the panel, want no copy", *captured)
		}
		if got := a.NoticeText(); got != "" {
			t.Errorf("notice = %q after a press outside the panel, want none", got)
		}
	})

	t.Run("no state installed arms nothing", func(t *testing.T) {
		a := New(nil)
		var captured []string
		a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
		a.ShowStatus(RenderStatus(BuildStatusSnapshot(state)))
		drawPrimitive(t, a.status, width, height)

		a.handleAppMouse(tcell.NewEventMouse(ctlX, ctlY, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
		a.handleAppMouse(nil, tview.MouseLeftUp)

		if len(captured) != 0 {
			t.Fatalf("osc52 sink = %q with no StatusState installed, want no copy", captured)
		}
		if got := a.NoticeText(); got != "" {
			t.Errorf("notice = %q with no StatusState installed, want none", got)
		}
	})

	t.Run("a dismissed overlay leaves no armed control", func(t *testing.T) {
		a, captured := open(t)
		a.dismissStatus()
		if len(a.statusRegions.all) != 0 {
			t.Fatalf("copy control still armed after dismiss: %+v", a.statusRegions.all)
		}
		a.ShowStatus("plain panel with no session line")
		drawPrimitive(t, a.status, width, height)
		a.handleAppMouse(tcell.NewEventMouse(ctlX, ctlY, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
		a.handleAppMouse(nil, tview.MouseLeftUp)
		if len(*captured) != 0 {
			t.Fatalf("osc52 sink = %q after reopening on a snapshot with no control, want no copy", *captured)
		}
	})
}

// TestApp_StatusCopyControlClickCopiesSessionIDThroughDispatch uses the real App as the
// command host and gives it the one StatusState the handler snapshots, matching how
// bootstrap wires both, so the click is answered by the same object the overlay rendered.
func TestApp_StatusCopyControlClickCopiesSessionIDThroughDispatch(t *testing.T) {
	h := newLayoutHarness(t, 80, 50)
	defer h.stop()

	state := fixtureState()
	var captured []string
	h.runDraw(func() {
		h.a.afterFunc = func(time.Duration, func()) {}
		h.a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
		h.a.SetActiveStore(escTestStore())
		h.a.SetStatusLineState(state)
		reg := BuildRegistry(map[string]HandlerFunc{"status": NewStatusHandler(state)})
		if res := reg.DispatchSlashInput("/status", h.a); res.Status != StatusHandled || res.Err != nil {
			t.Errorf("dispatch /status = %+v, want Handled with no error", res)
		}
	})

	var sx, sy int
	h.runDraw(func() { sx, sy, _, _ = h.a.status.GetRect() })
	ctlX := sx + len(statusSessionPrefix) + len(state.sessionID) + 1
	ctlY := sy + 2

	h.injectMouse(ctlX, ctlY, tcell.Button1)
	h.injectMouse(ctlX, ctlY, tcell.ButtonNone)

	var (
		got     []string
		last    string
		notice  string
		open    bool
		focused tview.Primitive
		body    string
		kinds   []string
	)
	h.runDraw(func() {
		got = append([]string(nil), captured...)
		last = h.a.input.lastCopied
		notice = h.a.NoticeText()
		open = h.a.statusOpen
		focused = h.a.app.GetFocus()
		body = h.a.status.GetText(true)
		kinds = eventKinds(h.a.ActiveStore().Records())
	})

	if want := osc52Sequence(state.sessionID); len(got) != 1 || got[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one %q", got, want)
	}
	if last != state.sessionID {
		t.Errorf("lastCopied = %q, want the exact session id %q", last, state.sessionID)
	}
	if notice != statusCopyNotice {
		t.Errorf("notice = %q, want %q", notice, statusCopyNotice)
	}
	if !open {
		t.Error("statusOpen = false after the copy click; the overlay must stay open")
	}
	if focused != h.a.status {
		t.Error("focus left the /status modal after the copy click")
	}
	if want := statusSessionPrefix + state.sessionID + " " + statusCopyControl; !strings.Contains(body, want) {
		t.Errorf("status snapshot text = %q, want the frozen snapshot to still carry %q", body, want)
	}
	if len(kinds) != 1 || kinds[0] != events.KindSlashCommand {
		t.Errorf("session records = %v, want only the dispatched slash_command (the click writes none)", kinds)
	}
}

func TestApp_StatusSelectionClearedOnCloseAndReopen(t *testing.T) {
	const width, height = 40, 6
	a := New(nil)
	a.input.osc52 = func(string) error { return nil }
	a.ShowStatus(statusBody)
	drawPrimitive(t, a.status, width, height)

	a.handleAppMouse(tcell.NewEventMouse(10, 1, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
	a.handleAppMouse(tcell.NewEventMouse(16, 1, tcell.Button1, tcell.ModNone), tview.MouseMove)
	if rev := reverseText(t, a.status, width, height); rev != "openai" {
		t.Fatalf("mid-drag highlight = %q, want %q", rev, "openai")
	}

	a.handleStatusKey(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone))
	if a.status.selecting {
		t.Error("the drag is still active after the modal closed under it")
	}

	a.ShowStatus(statusBody)
	a.handleAppMouse(tcell.NewEventMouse(30, 1, tcell.Button1, tcell.ModNone), tview.MouseMove)
	if rev := reverseText(t, a.status, width, height); rev != "" {
		t.Fatalf("reopened snapshot shows highlight %q, want none carried over from the abandoned drag", rev)
	}

	a.handleAppMouse(tcell.NewEventMouse(10, 1, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
	a.handleAppMouse(tcell.NewEventMouse(16, 1, tcell.Button1, tcell.ModNone), tview.MouseMove)
	a.ShowStatus(statusBody)
	if rev := reverseText(t, a.status, width, height); rev != "" {
		t.Fatalf("new snapshot shows highlight %q, want the previous range dropped", rev)
	}
}

func TestApp_StatusSelectionSurvivesInFlightRedraw(t *testing.T) {
	h := newLayoutHarness(t, 80, 24)
	defer h.stop()

	fc := &fakeStreamCanceller{retained: 7, inFlight: true}
	var captured []string
	h.runDraw(func() {
		h.a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
		h.a.SetActiveStore(escTestStore())
		h.a.SetStreamCanceller(fc)
		for i := 0; i < 40; i++ {
			h.a.Append(fmt.Sprintf("conversation line %d", i))
		}
		h.a.ShowStatus(statusBody)
	})

	var sx, sy int
	h.runDraw(func() { sx, sy, _, _ = h.a.status.GetRect() })
	valueY := sy + 1
	h.injectMouse(sx+10, valueY, tcell.Button1)
	h.injectMouse(sx+16, valueY, tcell.Button1)

	h.runDraw(func() { h.a.AppendStreamDelta("streamed reply while the drag is held") })

	var (
		afterY int
		body   string
	)
	h.runDraw(func() {
		_, afterY, _, _ = h.a.status.GetRect()
		body = h.a.status.GetText(true)
	})
	if afterY != sy {
		t.Fatalf("status panel moved from row %d to %d during the repaint; the drag coordinates no longer address it", sy, afterY)
	}
	if body != "Model\nProvider: openai\nLayer: /home/dev/settings.yaml [global]" {
		t.Errorf("status snapshot text = %q; the panel must stay a frozen snapshot while the stream runs", body)
	}
	if rev := statusReverseText(h); rev != "openai" {
		t.Fatalf("highlight after the stream repaint = %q, want it to survive as %q", rev, "openai")
	}

	h.injectMouse(sx+16, valueY, tcell.ButtonNone)

	var (
		got     []string
		open    bool
		focused tview.Primitive
		calls   int
		kinds   []string
	)
	h.runDraw(func() {
		got = append([]string(nil), captured...)
		open = h.a.statusOpen
		focused = h.a.app.GetFocus()
		calls = fc.calls
		kinds = eventKinds(h.a.ActiveStore().Records())
	})
	if want := osc52Sequence("openai"); len(got) != 1 || got[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one %q", got, want)
	}
	if !open {
		t.Error("statusOpen = false; a selection drag must not close the modal")
	}
	if focused != h.a.status {
		t.Error("focus left the /status modal during a drag over an in-flight response")
	}
	if calls != 0 {
		t.Errorf("stream canceller called %d times; selecting status text must not touch the response", calls)
	}
	for _, k := range kinds {
		if k == events.KindStreamInterrupted {
			t.Error("stream_interrupted recorded; selecting status text must not interrupt the stream")
		}
	}
}

// TestApp_StatusClickAboveThenEscDoesNotCancelInFlightWork drives the reported click-then-ESC path
// through the real event loop: with in-flight work and /status open, a left click above the
// below-input status panel must keep focus on the modal (the app-level mouse shield), and the
// following ESC must dismiss /status without cancelling the stream.
func TestApp_StatusClickAboveThenEscDoesNotCancelInFlightWork(t *testing.T) {
	h := newLayoutHarness(t, 80, 24)
	defer h.stop()

	fc := &fakeStreamCanceller{retained: 7, inFlight: true}
	h.runDraw(func() {
		h.a.SetActiveStore(escTestStore())
		h.a.SetStreamCanceller(fc)
		h.a.input.SetText("draft text")
		h.a.ShowStatus("status body")
	})

	// Row 0 is the transcript region, well above the below-input status panel. The shield
	// consumes the click (no visible change), so drive it with injectMouseQuiet, whose
	// follow-up resize forces the draw a plain injectMouse would wait on forever.
	h.injectMouseQuiet(1, 0, tcell.Button1)
	h.injectMouseQuiet(1, 0, tcell.ButtonNone)
	var (
		focused   tview.Primitive
		selecting bool
	)
	h.runDraw(func() {
		focused = h.a.app.GetFocus()
		selecting = h.a.status.selecting
	})
	if focused != h.a.status {
		t.Fatal("focus left the /status modal after a background click above the panel")
	}
	if selecting {
		t.Error("a background click above the panel started a status selection")
	}

	// ESC routes through the real app-level key capture (handleGlobalKey -> HandleEsc). Drive
	// it on the event-loop goroutine and read state in the same step, so the assertions are
	// serialized with the handler instead of racing tview's separate event/update channels.
	// HandleEsc must dismiss the modal ahead of any stream cancellation.
	var (
		open  bool
		calls int
		draft string
		kinds []string
	)
	h.runDraw(func() {
		h.a.handleGlobalKey(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone))
		open = h.a.statusOpen
		calls = fc.calls
		draft = h.a.input.GetText()
		kinds = eventKinds(h.a.ActiveStore().Records())
	})
	if open {
		t.Error("statusOpen = true after ESC; the modal must dismiss")
	}
	if calls != 0 {
		t.Errorf("stream canceller called %d times; click-above-then-ESC must not cancel in-flight work", calls)
	}
	if draft != "draft text" {
		t.Errorf("input buffer = %q after ESC, want it retained", draft)
	}
	for _, k := range kinds {
		if k == events.KindStreamInterrupted {
			t.Error("stream_interrupted recorded; click-above-then-ESC must not interrupt the stream")
		}
	}
}

func TestRenderStatus_LabelsLayersByKindNotPositionOrName(t *testing.T) {
	state := fixtureState()
	state.layers = []StatusLayer{
		{Kind: "local", Path: "/work/codemeld/.codemeld/my-machine.yaml"},
		{Kind: "global", Path: "/home/dev/.codemeld/global/settings.yaml"},
	}

	out := visibleStatusText(BuildStatusSnapshot(state))

	for _, want := range []string{
		"  /work/codemeld/.codemeld/my-machine.yaml [local]\n",
		"  /home/dev/.codemeld/global/settings.yaml [global]\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status overlay missing layer row %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "[project]") {
		t.Errorf("status overlay invented a [project] label:\n%s", out)
	}
}

func TestBuildStatusSnapshot_FreezesLayersAtOpen(t *testing.T) {
	state := fixtureState()
	snap := BuildStatusSnapshot(state)
	before := visibleStatusText(snap)

	state.layers[0].Kind = "project"

	if got := visibleStatusText(snap); got != before {
		t.Errorf("the built snapshot followed a later layer change:\n--- before ---\n%s\n--- after ---\n%s", before, got)
	}
}

// A degraded session is otherwise indistinguishable from a normal one once the launch
// notice has scrolled away, so /status must keep naming every withheld input in one line.
func TestRenderStatus_UnapprovedNamesEveryWithheldInput(t *testing.T) {
	state := fixtureState()
	state.approval = ApprovalDisclosure{Reason: trust.ReasonNoRecord, Withheld: []string{
		"project settings /work/codemeld/.codemeld/settings.yaml",
		"project settings /work/codemeld/.codemeld/settings.local.yaml",
		"VCS command templates /work/codemeld/.codemeld/vcs",
	}}

	out := visibleStatusText(BuildStatusSnapshot(state))

	want := "Project approval: not approved — ignoring project settings /work/codemeld/.codemeld/settings.yaml" +
		" and project settings /work/codemeld/.codemeld/settings.local.yaml" +
		" and VCS command templates /work/codemeld/.codemeld/vcs\n"
	if !strings.Contains(out, want) {
		t.Errorf("degraded status overlay missing %q:\n%s", want, out)
	}
	// An unapproved project still loads its AGENTS.md files, listed a few lines above.
	if !strings.Contains(out, "/work/codemeld/AGENTS.md") {
		t.Errorf("degraded status overlay dropped the project AGENTS.md the gate does not cover:\n%s", out)
	}
}

func TestRenderStatus_ApprovalLine(t *testing.T) {
	for _, tc := range []struct {
		name     string
		approval ApprovalDisclosure
		want     string
	}{
		{"listed root", ApprovalDisclosure{Approved: true, Reason: trust.ReasonTrusted}, "Project approval: approved\n"},
		{"nothing covered", ApprovalDisclosure{Approved: true, Reason: trust.ReasonNothingCovered}, "Project approval: nothing to approve\n"},
		{"no record, nothing withheld", ApprovalDisclosure{Reason: trust.ReasonNoRecord}, "Project approval: not approved\n"},
		{"unreadable store", ApprovalDisclosure{Reason: trust.ReasonUnreadable}, "Project approval: not approved\n"},
		{"unresolved root", ApprovalDisclosure{Reason: trust.ReasonUnresolvedRoot}, "Project approval: not approved\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := fixtureState()
			state.approval = tc.approval

			out := visibleStatusText(BuildStatusSnapshot(state))

			if !strings.Contains(out, tc.want) {
				t.Errorf("status overlay missing %q:\n%s", tc.want, out)
			}
			if strings.Count(out, "Project approval:") != 1 {
				t.Errorf("status overlay has more than one approval line:\n%s", out)
			}
			for _, absent := range []string{"trusted", "ignoring", "withheld", "on_change", "always"} {
				if strings.Contains(out, absent) {
					t.Errorf("status overlay carries %q:\n%s", absent, out)
				}
			}
		})
	}
}

// The overlay must keep showing the launch the user is in, so neither the state's later
// value nor the slice it handed over can move an already-built snapshot.
func TestBuildStatusSnapshot_FreezesApprovalDisclosureAtOpen(t *testing.T) {
	state := fixtureState()
	state.approval = ApprovalDisclosure{Reason: trust.ReasonNoRecord, Withheld: []string{"project settings /p/.codemeld/settings.yaml"}}

	snap := BuildStatusSnapshot(state)
	before := visibleStatusText(snap)

	state.approval.Withheld[0] = "changed"
	state.approval = ApprovalDisclosure{Approved: true, Reason: trust.ReasonTrusted}

	if got := visibleStatusText(snap); got != before {
		t.Errorf("the built snapshot followed a later approval change:\n--- before ---\n%s\n--- after ---\n%s", before, got)
	}
	if state.approvalHits != 1 {
		t.Errorf("Approval read %d times, want exactly 1 (snapshot-at-open)", state.approvalHits)
	}
}

func TestRenderStatus_EscapesApprovalDisclosureBrackets(t *testing.T) {
	state := fixtureState()
	state.approval = ApprovalDisclosure{Reason: trust.ReasonNoRecord, Withheld: []string{"project settings /p/[red]/settings.yaml"}}

	if out := visibleStatusText(BuildStatusSnapshot(state)); !strings.Contains(out, "project settings /p/[red]/settings.yaml") {
		t.Errorf("visible status text dropped the bracketed withheld path (parsed as markup):\n%s", out)
	}
}

func TestBuildStatusSnapshot_CopiesSandboxStatusOnce(t *testing.T) {
	state := fixtureState()
	state.sandbox, state.reason, state.modeKey = "unavailable", "linux: not yet supported", "plan"
	snap := BuildStatusSnapshot(state)
	if state.capHits != 1 {
		t.Errorf("SandboxStatus read %d times, want exactly 1 (snapshot-at-open)", state.capHits)
	}
	state.sandbox, state.reason, state.modeKey = "on", "", "auto_edits"
	if snap.SandboxState != "unavailable" || snap.SandboxReason != "linux: not yet supported" || snap.SandboxMode != "plan" {
		t.Errorf("snapshot sandbox = %q (%q) mode %q, want unavailable (linux: not yet supported) mode plan", snap.SandboxState, snap.SandboxReason, snap.SandboxMode)
	}
	if out := visibleStatusText(snap); !strings.Contains(out, "\nSandbox: unavailable (linux: not yet supported) — automatic command authorization is unavailable\n") {
		t.Errorf("frozen snapshot did not render the captured sandbox line:\n%s", out)
	}
}

func TestRenderStatus_SandboxLineFollowsStarted(t *testing.T) {
	const (
		onLine          = "Sandbox: on — commands run with OS-enforced filesystem and process-access restrictions"
		unavailableTail = " — automatic command authorization is unavailable"
	)
	for _, tc := range []struct{ sandbox, reason, modeKey, want string }{
		{"on", "", "plan", onLine},
		{"on", "", "auto_edits", onLine + "; fewer permission prompts"},
		{"off", "", "build", "Sandbox: off — build mode runs commands outside the sandbox"},
		{"unavailable", "linux: not yet supported", "plan", "Sandbox: unavailable (linux: not yet supported)" + unavailableTail},
		{"unavailable", "settings file is broken", "plan", "Sandbox: unavailable (settings file is broken)" + unavailableTail},
		{"unavailable", "settings file is broken", "auto_edits", "Sandbox: unavailable (settings file is broken)" + unavailableTail},
		{"unavailable", "settings file is broken", "build", "Sandbox: unavailable (settings file is broken)" + unavailableTail},
		{"unavailable", "", "plan", "Sandbox: unavailable" + unavailableTail},
		{"unavailable", "[red]x", "plan", "Sandbox: unavailable ([red]x)" + unavailableTail},
	} {
		state := fixtureState()
		state.sandbox, state.reason, state.modeKey = tc.sandbox, tc.reason, tc.modeKey
		out := visibleStatusText(BuildStatusSnapshot(state))
		if !strings.Contains(out, "Started: 2026-05-28T10:00:00.000Z\n"+tc.want+"\n") {
			t.Errorf("want %q on the line right after Started:\n--- output ---\n%s", tc.want, out)
		}
		if tc.sandbox == "unavailable" && strings.Contains(out, "outside the sandbox") {
			t.Errorf("%s/%s: unavailable overlay claims unconfined execution:\n%s", tc.reason, tc.modeKey, out)
		}
	}
}
