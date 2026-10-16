// End-to-end integration tests for the agent-modes system: the assembled
// system message, mode-filtered tool advertising, mode permission posture, the
// /mode switch, and /clear mode carry-forward — all driven through the production
// wiring StartTUI assembles and the production turn controller / dispatcher /
// authorizer trio, with event and record assertions read back from the durable
// session-record store on disk.
//
// This suite's prep names internal/integration/modes_test.go, but its Architecture Review
// directs these tests to package bootstrap: the only way to drive the real headless
// production seams (StartTUI's submit adapter via swapRunApp/SubmitInput, the
// provider-request capture via swapTurnProviderClient, the background-turn join via
// swapGoTurn, and the production newProductionToolDispatcher/newProductionAuthorizer
// constructors) without exporting new seams solely for test placement is from inside
// internal/bootstrap. So these black-box integration tests live beside the owning
// production wiring (Step 9), reusing the helpers established by tui_commands_test.go,
// turndeps_test.go, tooldispatch_test.go, and authdeps_test.go.
//
// As-built note for Step 5 (Auto edits out-of-root edit): the prep wording says
// Auto edits "prompts for ... out-of-scope edit targets". The
// structured edit tool no longer refuses an out-of-project target in-band — it resolves
// to the real out-of-root file and routes to authorization. Auto edits does not
// auto-approve an out-of-root write (isInScopeFileTool stays project-root-bound), so it
// falls through to the prompt exactly as the prep wording names. The scenario-5 test below
// pins the real production observable: a raw-shell call prompts as Build, and an out-of-root
// edit prompts (the production gate is invoked) rather than being auto-approved or refused
// in-band.
package bootstrap

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	cmdrunner "codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/tui"
)

// reloadStore flushes the store and reloads it from its session file, so a later
// assertion sees the durable on-disk record stream rather than the in-memory store.
func reloadStore(t *testing.T, store *sessions.Store) *sessions.Store {
	t.Helper()
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("flush session: %v", err)
	}
	return sessions.New(store.Path(), readSessionFile(t, store.Path()))
}

// decodePermissionMatched decodes every permission_matched payload in a store's record
// stream, in order, through the real event payload type (mirrors decodeInteractionMode).
func decodePermissionMatched(t *testing.T, store *sessions.Store) []events.PermissionMatched {
	t.Helper()
	return decodeStoreEvents[events.PermissionMatched](t, store, events.KindPermissionMatched)
}

// modesProviderConfig is the composed-config map exposing the openai provider with the
// gpt-5.5 model the integration turns dispatch against, so a StartTUI-assembled cache
// resolves the provider and the turn controller issues a (stubbed) request.
func modesProviderConfig() map[string]any {
	return map[string]any{
		"provider": map[string]any{
			"openai": map[string]any{
				"base_url": "https://api.openai.com/v1",
				"api_key":  "sk-test",
				"models":   []string{"gpt-5.5"},
			},
		},
	}
}

// TestModesIntegration_CapturedRequestCarriesSystemMessageAndModeFilteredTools covers
// integration scenario 1: a prompt submitted through the production StartTUI submit
// path produces a captured provider request whose single leading system message is the
// system-message assembly in the fixed order (base prompt → environment block → AGENTS.md) and
// whose advertised tool set is the mode-filtered set for the active mode. Driving
// it through StartTUI exercises the real newSystemPromptAssembler + newToolAdvertiser +
// realized registry, not a unit-level stand-in.
func TestModesIntegration_CapturedRequestCarriesSystemMessageAndModeFilteredTools(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var gotReq provider.Request
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if !isTitleRequest(req) {
			gotReq = req
		}
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	projectRoot := t.TempDir()
	result := &BootstrapResult{
		Home:        t.TempDir(),
		LaunchDir:   projectRoot,
		ProjectRoot: projectRoot,
		Session:     mkStore(t),
		Model:       selectedState(), // openai/gpt-5.5
		Config:      modesProviderConfig(),
		Mode:        mode.NewActiveState(mode.Build, mode.SourceDefault),
		// A real factory so StartTUI realizes the built-in edit + create tools (always
		// registered, even with no VCS), giving Build a non-trivial advertised set.
		ToolRegistry:      &toolRegistryFactory{active: nil},
		AgentInstructions: []agentinstr.LoadEntry{{Path: filepath.Join(projectRoot, "AGENTS.md"), Layer: agentinstr.LayerWalked, LoadOrder: 2, Content: []byte("be terse from AGENTS")}},
	}

	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("investigate this") {
		t.Fatal("plain prompt rejected; the production submit/turn entrypoint is not wired")
	}
	turns.Wait()

	if len(gotReq.Messages) == 0 || gotReq.Messages[0].Role != "system" {
		t.Fatalf("first request message = %+v, want a leading system message", gotReq.Messages)
	}
	systemCount := 0
	for _, m := range gotReq.Messages {
		if m.Role == "system" {
			systemCount++
		}
	}
	if systemCount != 1 {
		t.Fatalf("request carried %d system messages, want exactly 1 (the single synthetic system message)", systemCount)
	}

	// Fixed assembly order: base prompt (Build) → environment block → AGENTS.md.
	sys := gotReq.Messages[0].Content
	base := strings.Index(sys, "Build mode")
	env := strings.Index(sys, "Environment:")
	agents := strings.Index(sys, "be terse from AGENTS")
	if base < 0 || env < 0 || agents < 0 {
		t.Fatalf("system message missing a section (base=%d env=%d agents=%d):\n%s", base, env, agents, sys)
	}
	if base >= env || env >= agents {
		t.Fatalf("system message sections out of order (base=%d env=%d agents=%d): want base < env < AGENTS\n%s", base, env, agents, sys)
	}

	got := toolNames(gotReq.Tools)
	want := []string{"ask_user", "bash", "create", "delegate", "delete", "edit", "file_count", "glob", "grep", "list", "mkdir", "move", "read", "read_image", "suggest_followup", "tree", "web_fetch", "web_search"}
	if !slices.Equal(got, want) {
		t.Fatalf("advertised tools on the captured request = %v, want %v (mode-filtered set for Build)", got, want)
	}
}

// TestModesIntegration_FlaggedModelRequestCarriesSpecialInstructions covers per-model special instructions: a
// configured OpenRouter Granite selection threaded through StartTUI's per-turn assembler
// makes the captured provider request's single system message carry that model's
// special-instructions block, inserted between the base prompt and the environment
// block. Driving it through StartTUI (not the agentinstr lookup alone) pins the
// production wiring — active model → newSystemPromptAssembler → the real request.
func TestModesIntegration_FlaggedModelRequestCarriesSpecialInstructions(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var gotReq provider.Request
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if !isTitleRequest(req) {
			gotReq = req
		}
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	projectRoot := t.TempDir()
	result := &BootstrapResult{
		Home:        t.TempDir(),
		LaunchDir:   projectRoot,
		ProjectRoot: projectRoot,
		Session:     mkStore(t),
		Model: model.NewActiveState(&model.Selection{
			Provider: "openrouter", ID: "ibm-granite/granite-4.1-8b", Effort: model.EffortDefault,
		}, model.SourceProject),
		Config: map[string]any{
			"provider": map[string]any{
				"openrouter": map[string]any{
					"base_url": "https://openrouter.ai/api/v1",
					"api_key":  "sk-test",
					"models":   []string{"ibm-granite/granite-4.1-8b"},
				},
			},
		},
		Mode:         mode.NewActiveState(mode.Build, mode.SourceDefault),
		ToolRegistry: &toolRegistryFactory{active: nil},
	}

	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("explain 5 x 2") {
		t.Fatal("plain prompt rejected; the production submit/turn entrypoint is not wired")
	}
	turns.Wait()

	if len(gotReq.Messages) == 0 || gotReq.Messages[0].Role != "system" {
		t.Fatalf("first request message = %+v, want a leading system message", gotReq.Messages)
	}
	sys := gotReq.Messages[0].Content
	special := agentinstr.SpecialInstructions("openrouter", "ibm-granite/granite-4.1-8b")
	if special == "" {
		t.Fatal("test precondition: Granite must be a flagged model")
	}
	if !strings.Contains(sys, special) {
		t.Fatalf("captured request system message did not carry the flagged model's special instructions\n--- want substring ---\n%s\n--- system message ---\n%s", special, sys)
	}

	// Order: base prompt → special instructions → environment block.
	base := strings.Index(sys, "Build mode")
	spec := strings.Index(sys, special)
	env := strings.Index(sys, "Environment:")
	if base < 0 || base >= spec || spec >= env {
		t.Fatalf("special instructions not ordered base < special < env (base=%d special=%d env=%d):\n%s", base, spec, env, sys)
	}
}

// TestModesIntegration_PlanDeniesMutatingCallEndToEnd covers scenario 2: in Plan, a
// mutating tool call the model issues is denied without prompting, the denial round-trips
// to the model as a denied_by:"mode" envelope, and the durable record stream carries a
// single permission_matched{outcome:"deny", outcome_source:"mode_auto"} with no grant
// fields. It runs the real loop → production dispatcher → production authorizer → mode
// posture; the prompt gate fails the test if it is ever reached (Plan never prompts).
func TestModesIntegration_PlanDeniesMutatingCallEndToEnd(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := toolThenContentClient(nil, "bash", `{"command":"rm notes.txt"}`, "understood")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := providerCache(t, cwd)

	gateCalls := 0
	gate := func(tui.PromptRequest) (tui.PromptDecision, error) {
		gateCalls++
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(gate), home, cwd, mode.NewActiveState(mode.Plan, mode.SourceConfig))

	run := &fakeDispatchRunner{}
	ctl := newTurnController(ctx, &recordingSurface{}, cache, turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, auth)
	ctl.setToolDispatcher(newProductionToolDispatcher(tools.NewRegistry(), run, auth, home, cwd, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if gateCalls != 0 {
		t.Fatalf("prompt gate invoked %d times, want 0 (Plan denies without prompting)", gateCalls)
	}
	if run.callCount() != 0 {
		t.Fatalf("runner Exec calls = %d, want 0 (a Plan-denied mutating command must not execute)", run.callCount())
	}

	reloaded := reloadStore(t, store)
	toolMsgs := messagesByRole(reloaded, "tool")
	if len(toolMsgs) != 1 {
		t.Fatalf("durable tool messages = %d, want 1 (the deny envelope)", len(toolMsgs))
	}
	if got := toolMsgs[0].Content.Text(); !strings.Contains(got, `"denied_by":"mode"`) {
		t.Fatalf("deny envelope = %q, want a denied_by:\"mode\" policy denial (not a user denial)", got)
	}

	matched := decodePermissionMatched(t, reloaded)
	if len(matched) != 1 {
		t.Fatalf("durable permission_matched events = %d, want exactly 1 (the mode deny)", len(matched))
	}
	m := matched[0]
	if m.Outcome != "deny" || m.OutcomeSource != "mode_auto" {
		t.Fatalf("permission_matched = %#v, want outcome deny / outcome_source mode_auto", m)
	}
	if m.GrantKind != "" || m.GrantPathScope != "" {
		t.Fatalf("mode_auto deny carried grant fields: %#v", m)
	}
}

// TestModesIntegration_PlanRunsReadOnlyCallEndToEnd covers scenario 3: in Plan, a
// read-only call (an allowlisted read-only shell command) is auto-allowed without
// prompting, the command runs, and the durable record stream carries the matching
// permission_matched{outcome:"once", outcome_source:"mode_auto"} with no grant fields.
func TestModesIntegration_PlanRunsReadOnlyCallEndToEnd(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := toolThenContentClient(nil, "bash", `{"command":"ls"}`, "done")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := providerCache(t, cwd)

	gateCalls := 0
	gate := func(tui.PromptRequest) (tui.PromptDecision, error) {
		gateCalls++
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(gate), home, cwd, mode.NewActiveState(mode.Plan, mode.SourceConfig))

	run := &fakeDispatchRunner{result: cmdrunner.RunResult{Stdout: []byte("file1\n")}}
	ctl := newTurnController(ctx, &recordingSurface{}, cache, turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, auth)
	ctl.setToolDispatcher(newProductionToolDispatcher(tools.NewRegistry(), run, auth, home, cwd, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if gateCalls != 0 {
		t.Fatalf("prompt gate invoked %d times, want 0 (Plan auto-allows read-only without prompting)", gateCalls)
	}
	if run.callCount() != 1 {
		t.Fatalf("runner Exec calls = %d, want 1 (the read-only command runs after the mode auto-allow)", run.callCount())
	}

	reloaded := reloadStore(t, store)
	toolMsgs := messagesByRole(reloaded, "tool")
	if len(toolMsgs) != 1 || toolMsgs[0].Content.Text() != "file1" {
		t.Fatalf("durable tool messages = %+v, want one carrying the read-only command output", toolMsgs)
	}
	matched := decodePermissionMatched(t, reloaded)
	if len(matched) != 1 {
		t.Fatalf("durable permission_matched events = %d, want exactly 1 (the mode allow)", len(matched))
	}
	m := matched[0]
	if m.Outcome != "once" || m.OutcomeSource != "mode_auto" {
		t.Fatalf("permission_matched = %#v, want outcome once / outcome_source mode_auto", m)
	}
	if m.GrantKind != "" || m.GrantPathScope != "" {
		t.Fatalf("mode_auto allow carried grant fields: %#v", m)
	}

	// Grant-store read back: a Plan read-only mode-auto approval appends no
	// session/folder/global grant, mirroring the Auto edits approval assertion
	// (Done-when 3). This is the same cache bound into newProductionAuthorizer, so a
	// regression that appended a grant while still emitting the same event fails here.
	if got := len(cache.Permissions()); got != 0 {
		t.Fatalf("grant table holds %d entries, want 0 (a mode-auto approval creates no grant)", got)
	}
}

// TestModesIntegration_AutoEditsApprovesInScopeEditWithoutGrant covers scenario 4: in
// Auto edits, an in-scope structured edit (target within the project root) is
// auto-approved without prompting, the file is modified through the real edit tool, the
// durable record carries permission_matched{outcome:"once", outcome_source:"mode_auto",
// subject:"edit"} with the resolved containing directory as path_scope and no grant
// fields, and the grant table read back proves the mode-auto approval appended no grant.
func TestModesIntegration_AutoEditsApprovesInScopeEditWithoutGrant(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	file := filepath.Join(project, "main.go")
	if err := os.WriteFile(file, []byte("package OLD\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	client := toolThenContentClient(nil, filetools.EditToolName, `{"path":"main.go","old_text":"OLD","new_text":"NEW"}`, "edited")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := providerCache(t, project)

	gateCalls := 0
	gate := func(tui.PromptRequest) (tui.PromptDecision, error) {
		gateCalls++
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(gate), home, project, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewEditTool(home, project, project)); err != nil {
		t.Fatalf("Register edit tool: %v", err)
	}
	ctl := newTurnController(ctx, &recordingSurface{}, cache, turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, auth)
	ctl.setToolDispatcher(newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if gateCalls != 0 {
		t.Fatalf("prompt gate invoked %d times, want 0 (Auto edits auto-approves an in-scope edit)", gateCalls)
	}
	if got := mustReadFile(t, file); got != "package NEW\n" {
		t.Fatalf("edited file = %q, want %q (the edit applied through the real production path)", got, "package NEW\n")
	}

	reloaded := reloadStore(t, store)
	matched := decodePermissionMatched(t, reloaded)
	if len(matched) != 1 {
		t.Fatalf("durable permission_matched events = %d, want exactly 1 (the mode-auto edit approval)", len(matched))
	}
	want := events.PermissionMatched{
		SubjectKind:   "tool",
		Subject:       filetools.EditToolName,
		PathScope:     project, // resolved containing directory of project/main.go
		Outcome:       "once",
		OutcomeSource: "mode_auto",
	}
	if matched[0] != want {
		t.Fatalf("permission_matched = %#v, want %#v (mode_auto edit approval, no grant fields)", matched[0], want)
	}

	// Grant-store read back: a mode-auto approval appends no session/folder/global grant.
	if got := len(cache.Permissions()); got != 0 {
		t.Fatalf("grant table holds %d entries, want 0 (a mode-auto approval creates no grant)", got)
	}
}

func TestModesIntegration_AutoEditsApprovesAliasedRootEditWithoutPrompt(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	project := t.TempDir()
	alias := filepath.Join(t.TempDir(), "proj-alias")
	if err := os.Symlink(project, alias); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if resolved, err := filepath.EvalSymlinks(alias); err != nil || resolved == alias {
		t.Skipf("symlink alias did not differ from its resolved target: resolved=%q err=%v", resolved, err)
	}

	home := t.TempDir()
	file := filepath.Join(project, "main.go")
	if err := os.WriteFile(file, []byte("package OLD\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	root, _, _, err := config.LocateProjectRoot(alias, "launch-dir-only")
	if err != nil {
		t.Fatalf("LocateProjectRoot: %v", err)
	}
	if root != project {
		t.Fatalf("discovered root = %q, want canonical %q (not alias %q)", root, project, alias)
	}

	client := toolThenContentClient(nil, filetools.EditToolName, `{"path":"main.go","old_text":"OLD","new_text":"NEW"}`, "edited")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := providerCache(t, root)

	gateCalls := 0
	gate := func(tui.PromptRequest) (tui.PromptDecision, error) {
		gateCalls++
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(gate), home, alias, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewEditTool(home, alias, root)); err != nil {
		t.Fatalf("Register edit tool: %v", err)
	}
	ctl := newTurnController(ctx, &recordingSurface{}, cache, turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, auth)
	ctl.setToolDispatcher(newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, alias, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if gateCalls != 0 {
		t.Fatalf("prompt gate invoked %d times, want 0 (Auto edits auto-approves an in-scope edit reached through a root alias)", gateCalls)
	}
	if got := mustReadFile(t, file); got != "package NEW\n" {
		t.Fatalf("edited file = %q, want %q (the edit applied through the real production path)", got, "package NEW\n")
	}

	reloaded := reloadStore(t, store)
	matched := decodePermissionMatched(t, reloaded)
	if len(matched) != 1 {
		t.Fatalf("durable permission_matched events = %d, want exactly 1 (the mode-auto edit approval)", len(matched))
	}
	want := events.PermissionMatched{
		SubjectKind:   "tool",
		Subject:       filetools.EditToolName,
		PathScope:     project,
		Outcome:       "once",
		OutcomeSource: "mode_auto",
	}
	if matched[0] != want {
		t.Fatalf("permission_matched = %#v, want %#v (mode_auto edit approval through the root alias, no grant fields)", matched[0], want)
	}

	if got := len(cache.Permissions()); got != 0 {
		t.Fatalf("grant table holds %d entries, want 0 (a mode-auto approval creates no grant)", got)
	}
}

func TestModesIntegration_AutoEditsApprovesInScopeMkdirWithoutGrant(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	target := filepath.Join(project, "newdir")

	client := toolThenContentClient(nil, filetools.MkdirToolName, `{"path":"newdir"}`, "made")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := providerCache(t, project)

	gateCalls := 0
	gate := func(tui.PromptRequest) (tui.PromptDecision, error) {
		gateCalls++
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(gate), home, project, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewMkdirTool(home, project, project)); err != nil {
		t.Fatalf("Register mkdir tool: %v", err)
	}
	ctl := newTurnController(ctx, &recordingSurface{}, cache, turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, auth)
	ctl.setToolDispatcher(newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if gateCalls != 0 {
		t.Fatalf("prompt gate invoked %d times, want 0 (Auto edits auto-approves an in-scope mkdir)", gateCalls)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat created directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("created target = %v, want a directory (mkdir applied through the real production path)", info.Mode())
	}

	reloaded := reloadStore(t, store)
	matched := decodePermissionMatched(t, reloaded)
	if len(matched) != 1 {
		t.Fatalf("durable permission_matched events = %d, want exactly 1 (the mode-auto mkdir approval)", len(matched))
	}
	want := events.PermissionMatched{
		SubjectKind:   "tool",
		Subject:       filetools.MkdirToolName,
		PathScope:     project,
		Outcome:       "once",
		OutcomeSource: "mode_auto",
	}
	if matched[0] != want {
		t.Fatalf("permission_matched = %#v, want %#v (mode_auto mkdir approval, no grant fields)", matched[0], want)
	}

	if got := len(cache.Permissions()); got != 0 {
		t.Fatalf("grant table holds %d entries, want 0 (a mode-auto approval creates no grant)", got)
	}
}

func TestModesIntegration_AutoEditsApprovesNestedInScopeCreateWithoutGrant(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	target := filepath.Join(project, "docs", "guide.go")

	client := toolThenContentClient(nil, filetools.CreateToolName, `{"path":"docs/guide.go","content":"package docs\n"}`, "made")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := providerCache(t, project)

	gateCalls := 0
	gate := func(tui.PromptRequest) (tui.PromptDecision, error) {
		gateCalls++
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(gate), home, project, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, project, project)); err != nil {
		t.Fatalf("Register create tool: %v", err)
	}
	ctl := newTurnController(ctx, &recordingSurface{}, cache, turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, auth)
	ctl.setToolDispatcher(newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if gateCalls != 0 {
		t.Fatalf("prompt gate invoked %d times, want 0 (Auto edits auto-approves an in-scope nested create)", gateCalls)
	}
	if got := mustReadFile(t, target); got != "package docs\n" {
		t.Fatalf("created file = %q, want %q (the nested create applied through the real production path)", got, "package docs\n")
	}
	if info, statErr := os.Stat(filepath.Join(project, "docs")); statErr != nil || !info.IsDir() {
		t.Fatalf("missing parent directory not created by the nested create: info=%v err=%v", info, statErr)
	}

	reloaded := reloadStore(t, store)
	matched := decodePermissionMatched(t, reloaded)
	if len(matched) != 1 {
		t.Fatalf("durable permission_matched events = %d, want exactly 1 (the mode-auto nested create approval)", len(matched))
	}
	want := events.PermissionMatched{
		SubjectKind:   "tool",
		Subject:       filetools.CreateToolName,
		PathScope:     project,
		Outcome:       "once",
		OutcomeSource: "mode_auto",
	}
	if matched[0] != want {
		t.Fatalf("permission_matched = %#v, want %#v (mode_auto create approval, no grant fields)", matched[0], want)
	}

	if got := len(cache.Permissions()); got != 0 {
		t.Fatalf("grant table holds %d entries, want 0 (a mode-auto approval creates no grant)", got)
	}
}

// TestModesIntegration_AutoEditsPromptsShellAndOutOfRootEdit covers scenario 5.
// Sub-test "shell prompts as build": a raw-shell call in Auto edits falls through to
// Build behavior and prompts (the production gate is invoked) before running. Sub-test
// "out-of-root edit prompts under auto edits": an edit whose target escapes
// the project root is no longer refused in-band; Auto edits does not auto-approve it
// (isInScopeFileTool stays project-root-bound), so it routes to the prompt — the gate is
// invoked once and, when allowed, the out-of-project file is edited. See the file header.
func TestModesIntegration_AutoEditsPromptsShellAndOutOfRootEdit(t *testing.T) {
	t.Run("shell prompts as build", func(t *testing.T) {
		ctx := context.Background()
		var turns sync.WaitGroup
		defer swapGoTurn(waitableGoTurn(&turns))()

		client := toolThenContentClient(nil, "bash", `{"command":"make build"}`, "ran")
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		cwd := t.TempDir()
		home := t.TempDir()
		store := mkStore(t)
		app := tui.New(nil)
		app.SetActiveStore(store)
		cache := providerCache(t, cwd)

		gateCalls := 0
		gate := func(tui.PromptRequest) (tui.PromptDecision, error) {
			gateCalls++
			return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
		}
		auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(gate), home, cwd, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))

		run := &fakeDispatchRunner{result: cmdrunner.RunResult{Stdout: []byte("built\n")}}
		ctl := newTurnController(ctx, &recordingSurface{}, cache, turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, auth)
		ctl.setToolDispatcher(newProductionToolDispatcher(tools.NewRegistry(), run, auth, home, cwd, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

		if err := ctl.dispatch(store, time.Time{}); err != nil {
			t.Fatalf("dispatch error = %v", err)
		}
		turns.Wait()

		if gateCalls != 1 {
			t.Fatalf("prompt gate invoked %d times, want 1 (Auto edits prompts for a shell command as in Build)", gateCalls)
		}
		if run.callCount() != 1 {
			t.Fatalf("runner Exec calls = %d, want 1 (the shell command runs once the prompt allows it)", run.callCount())
		}
	})

	t.Run("out-of-root edit prompts under auto edits", func(t *testing.T) {
		ctx := context.Background()
		var turns sync.WaitGroup
		defer swapGoTurn(waitableGoTurn(&turns))()

		project, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		home := t.TempDir()
		outside, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks(outside): %v", err)
		}
		target := filepath.Join(outside, "secret.txt")
		if err := os.WriteFile(target, []byte("untouched\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		args := `{"path":"` + target + `","old_text":"untouched","new_text":"changed"}`
		client := toolThenContentClient(nil, filetools.EditToolName, args, "adjusted")
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		store := mkStore(t)
		app := tui.New(nil)
		app.SetActiveStore(store)
		cache := providerCache(t, project)

		gateCalls := 0
		var gotReq tui.PromptRequest
		gate := func(req tui.PromptRequest) (tui.PromptDecision, error) {
			gateCalls++
			gotReq = req
			return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
		}
		auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(gate), home, project, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))

		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, filetools.NewEditTool(home, project, project)); err != nil {
			t.Fatalf("Register edit tool: %v", err)
		}
		ctl := newTurnController(ctx, &recordingSurface{}, cache, turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, auth)
		ctl.setToolDispatcher(newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

		if err := ctl.dispatch(store, time.Time{}); err != nil {
			t.Fatalf("dispatch error = %v", err)
		}
		turns.Wait()

		// Auto edits does not auto-approve the out-of-root edit; it prompts exactly once, and the
		// prompt carries the out-of-root folder signal anchored on the real out-of-root folder.
		if gateCalls != 1 {
			t.Fatalf("prompt gate invoked %d times, want 1 (Auto edits prompts for an out-of-root edit, not auto-approve or in-band reject)", gateCalls)
		}
		if !gotReq.OutOfRootFileWrite || gotReq.RunFolder != outside {
			t.Fatalf("prompt = {OutOfRootFileWrite:%v RunFolder:%q}, want {true %q}", gotReq.OutOfRootFileWrite, gotReq.RunFolder, outside)
		}
		reloaded := reloadStore(t, store)
		toolMsgs := messagesByRole(reloaded, "tool")
		if len(toolMsgs) != 1 || !strings.Contains(toolMsgs[0].Content.Text(), "edited ") {
			t.Fatalf("durable tool messages = %+v, want one applied-edit result (allow-once approved the out-of-root edit)", toolMsgs)
		}
		if got := mustReadFile(t, target); got != "changed\n" {
			t.Fatalf("out-of-project file = %q, want the approved edit %q", got, "changed\n")
		}
	})
}

// TestModesIntegration_ModeSwitchChangesAuthorizationAndAdvertisedTools covers scenario
// 6: a mid-session /mode switch — driven through the production submitted-command path
// (app.SubmitInput("/mode plan") → the real tui.NewModeHandler bound to newModeDeps over
// the shared run-scoped mode state, the exact wiring StartTUI installs) — changes
// both the advertised tool set and subsequent authorization. Two turns share one mode
// state, one production authorizer, one advertiser, and one dispatcher. In Build the
// mutating shell call prompts and runs; after the submitted /mode plan switches to Plan
// the same call is denied without prompting, and the advertised set drops the mutating
// tool while keeping the read-only one and bash. Each turn's continuation round preserves
// its own advertised set. Routing the switch through the real /mode
// command (rather than poking ApplyUserCommand directly) is what proves the submitted
// command re-points the run-scoped mode the authorizer and advertiser read.
func TestModesIntegration_ModeSwitchChangesAuthorizationAndAdvertisedTools(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var perRound [][]string
	var round int32
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		perRound = append(perRound, toolNames(req.Tools))
		// Odd rounds (the initial round of each turn) issue the mutating shell call;
		// even rounds (continuation) answer with content.
		if atomic.AddInt32(&round, 1)%2 == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"rm build.log"}`)))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := providerCache(t, cwd)
	modeActive := mode.NewActiveState(mode.Build, mode.SourceDefault)

	gateCalls := 0
	gate := func(tui.PromptRequest) (tui.PromptDecision, error) {
		gateCalls++
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(gate), home, cwd, modeActive)

	run := &fakeDispatchRunner{result: cmdrunner.RunResult{Stdout: []byte("ok\n")}}
	ctl := newTurnController(ctx, &recordingSurface{}, cache, turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, auth)
	ctl.setToolAdvertiser(newToolAdvertiser(advRegistry(t), modeActive))
	ctl.setToolDispatcher(newProductionToolDispatcher(advRegistry(t), run, auth, home, cwd, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

	// Turn 1: Build — the mutating call prompts and runs.
	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("Build dispatch error = %v", err)
	}
	turns.Wait()
	if gateCalls != 1 {
		t.Fatalf("after the Build turn the gate was invoked %d times, want 1 (Build prompts for the mutating shell call)", gateCalls)
	}
	if run.callCount() != 1 {
		t.Fatalf("after the Build turn runner Exec calls = %d, want 1 (the allowed call ran)", run.callCount())
	}

	// The /mode switch, driven through the production submitted-command path. A
	// registry carrying the real tui.NewModeHandler bound to newModeDeps over the
	// shared modeActive is dispatched via the app's submit adapter — the same
	// NewModeHandler(newModeDeps(...)) wiring StartTUI installs (starttui.go modeDeps +
	// BuildRegistry). Submitting "/mode plan" proves the submitted command,
	// not a direct ApplyUserCommand poke, re-points the authorizer's posture and the
	// advertiser's mode-filtered set the next turn reads.
	modeReg := tui.BuildRegistry(map[string]tui.HandlerFunc{
		"mode": tui.NewModeHandler(newModeDeps(ctx, app, modeActive)),
	})
	app.SetSubmit(tui.NewSubmitFunc(modeReg, app, nil))
	if !app.SubmitInput("/mode plan") {
		t.Fatal("/mode plan rejected through the production submitted-command path; the /mode command is not wired to the shared run-scoped mode state")
	}

	// Turn 2: Plan — the same call is denied without prompting.
	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("Plan dispatch error = %v", err)
	}
	turns.Wait()
	if gateCalls != 1 {
		t.Fatalf("after the Plan turn the gate was invoked %d times total, want still 1 (Plan denies without prompting)", gateCalls)
	}
	if run.callCount() != 1 {
		t.Fatalf("after the Plan turn runner Exec calls = %d, want still 1 (the Plan-denied call must not run)", run.callCount())
	}

	// Provider rounds: Build's allowed call runs and continues, so Build has two rounds
	// advertising the full set. Plan denies the same call but mode-policy denials are
	// recoverable, so Plan also has a denied tool-call round and a continuation answer
	// round that both drop the mutating tool while keeping the read-only one and bash.
	if len(perRound) != 4 {
		t.Fatalf("provider rounds = %d, want 4 (Build's two rounds + Plan's denied round + Plan's continuation)", len(perRound))
	}
	buildSet := []string{"bash", "suggest_followup", "vcs_commit", "vcs_status"}
	planSet := []string{"bash", "suggest_followup", "vcs_status"}
	for i := 0; i < 2; i++ {
		if !slices.Equal(perRound[i], buildSet) {
			t.Fatalf("Build round %d advertised %v, want %v", i, perRound[i], buildSet)
		}
	}
	for i := 2; i < 4; i++ {
		if !slices.Equal(perRound[i], planSet) {
			t.Fatalf("Plan round %d advertised %v, want %v (the switch filtered the mutating tool)", i, perRound[i], planSet)
		}
		if slices.Contains(perRound[i], "vcs_commit") {
			t.Fatalf("Plan round %d still advertised the mutating vcs_commit after the /mode switch", i)
		}
	}

	// The Plan denial is durable as a denied_by:"mode" tool message.
	reloaded := reloadStore(t, store)
	var sawModeDeny bool
	for _, msg := range messagesByRole(reloaded, "tool") {
		if strings.Contains(msg.Content.Text(), `"denied_by":"mode"`) {
			sawModeDeny = true
		}
	}
	if !sawModeDeny {
		t.Fatal("no denied_by:\"mode\" tool message after the switch to Plan; the switch did not change authorization")
	}
}

func TestModesIntegration_ActiveTurnModeSwitchAppliesToLaterAuthorization(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	fileA := filepath.Join(project, "a.go")
	fileB := filepath.Join(project, "b.go")
	if err := os.WriteFile(fileA, []byte("package OLD_A\n"), 0o644); err != nil {
		t.Fatalf("WriteFile a.go: %v", err)
	}
	if err := os.WriteFile(fileB, []byte("package OLD_B\n"), 0o644); err != nil {
		t.Fatalf("WriteFile b.go: %v", err)
	}

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := providerCache(t, project)
	modeActive := mode.NewActiveState(mode.Build, mode.SourceDefault)

	modeReg := tui.BuildRegistry(map[string]tui.HandlerFunc{
		"mode": tui.NewModeHandler(newModeDeps(ctx, app, modeActive)),
	})
	app.SetSubmit(tui.NewSubmitFunc(modeReg, app, nil))

	argsA := `{"path":"a.go","old_text":"OLD_A","new_text":"NEW_A"}`
	argsB := `{"path":"b.go","old_text":"OLD_B","new_text":"NEW_B"}`
	var round int32
	var switchOK atomic.Bool
	client := &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		switch atomic.AddInt32(&round, 1) {
		case 1:
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", filetools.EditToolName, argsA)))}, nil
		case 2:
			switchOK.Store(app.SubmitInput("/mode auto-edits"))
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_2", filetools.EditToolName, argsB)))}, nil
		default:
			return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
		}
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	gateCalls := 0
	gate := func(tui.PromptRequest) (tui.PromptDecision, error) {
		gateCalls++
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(gate), home, project, modeActive)

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewEditTool(home, project, project)); err != nil {
		t.Fatalf("Register edit tool: %v", err)
	}
	ctl := newTurnController(ctx, &recordingSurface{}, cache, turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, auth)
	ctl.setToolDispatcher(newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if !switchOK.Load() {
		t.Fatal("/mode auto-edits rejected mid-turn through the production submitted-command path")
	}
	if gateCalls != 1 {
		t.Fatalf("prompt gate invoked %d times, want 1 (only the Build a.go edit prompts; the b.go edit after the mid-turn switch must not)", gateCalls)
	}
	if got := mustReadFile(t, fileA); got != "package NEW_A\n" {
		t.Fatalf("a.go = %q, want %q (the Build edit applied)", got, "package NEW_A\n")
	}
	if got := mustReadFile(t, fileB); got != "package NEW_B\n" {
		t.Fatalf("b.go = %q, want %q (the post-switch Auto edits edit applied)", got, "package NEW_B\n")
	}

	reloaded := reloadStore(t, store)
	var modeAuto []events.PermissionMatched
	for _, m := range decodePermissionMatched(t, reloaded) {
		if m.OutcomeSource == "mode_auto" {
			modeAuto = append(modeAuto, m)
		}
	}
	if len(modeAuto) != 1 {
		t.Fatalf("mode_auto permission_matched events = %d, want exactly 1 (the b.go edit auto-approved after the switch)", len(modeAuto))
	}
	want := events.PermissionMatched{
		SubjectKind:   "tool",
		Subject:       filetools.EditToolName,
		PathScope:     project,
		Outcome:       "once",
		OutcomeSource: "mode_auto",
	}
	if modeAuto[0] != want {
		t.Fatalf("mode_auto permission_matched = %#v, want %#v (the later in-project edit, no grant fields)", modeAuto[0], want)
	}

	var sawSwitch bool
	for _, im := range decodeInteractionMode(t, reloaded) {
		if im.Mode == "auto_edits" && im.Trigger == "user_command" {
			sawSwitch = true
		}
	}
	if !sawSwitch {
		t.Fatal("no interaction_mode{mode:auto_edits, trigger:user_command} recorded; the switch did not go through the production /mode command")
	}
}

// TestModesIntegration_ClearCarriesModeIntoFreshSession covers scenario 7: a /clear
// issued through the production submit path carries the active mode forward into the
// fresh session and records interaction_mode{trigger:"clear"} there, read back from the
// fresh session's durable record stream. The active mode (Plan, originally from a /mode
// switch) carries forward with its original source rather than resetting to a launch
// default.
func TestModesIntegration_ClearCarriesModeIntoFreshSession(t *testing.T) {
	ctx := context.Background()
	prior := mkStore(t)
	result := &BootstrapResult{
		Home:        t.TempDir(),
		LaunchDir:   "/launch",
		ProjectRoot: "/launch",
		Session:     prior,
		Mode:        mode.NewActiveState(mode.Plan, mode.SourceUserCommand),
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("/clear") {
		t.Fatal("/clear rejected; it should switch sessions and be accepted")
	}

	fresh := app.ActiveStore()
	if fresh == prior {
		t.Fatal("/clear did not swap the active session")
	}

	// The fresh session's durable record stream carries the carried-forward mode under
	// trigger "clear" with the source it originally came from.
	freshDisk := readSessionFile(t, fresh.Path())
	im := diskInteractionMode(t, freshDisk)
	if len(im) != 1 {
		t.Fatalf("fresh session interaction_mode events = %+v, want exactly one (the /clear carry-forward)", im)
	}
	if im[0].Mode != "plan" || im[0].Source != "user_command" || im[0].Trigger != "clear" {
		t.Fatalf("fresh session interaction_mode = %+v, want {plan, user_command, clear}", im[0])
	}
}

// TestModesIntegration_FreshSessionToolCallRoundTripsWithAdvertisedTools covers scenario
// 8: a fresh-session tool call round-trips end-to-end (the model issues a tool call, the
// loop dispatches it, records the result, and re-issues to a final answer),
// now with the tool set advertised up front on every provider round. It pins
// that both the initial and the continuation round carry the same advertised
// set, and the round-trip records read back from disk.
func TestModesIntegration_FreshSessionToolCallRoundTripsWithAdvertisedTools(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var perRound [][]string
	client := toolThenContentClient(&perRound, "bash", `{"command":"echo hi"}`, "done")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	cwd := t.TempDir()
	store := mkStore(t) // a fresh session
	run := &fakeDispatchRunner{result: cmdrunner.RunResult{Stdout: []byte("hi\n")}}
	auth := &recordingAuthorizer{decision: allow()}
	ctl := newTurnController(ctx, &recordingSurface{}, providerCache(t, cwd), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setToolAdvertiser(newToolAdvertiser(advRegistry(t), mode.NewActiveState(mode.Build, mode.SourceDefault)))
	ctl.setToolDispatcher(newProductionToolDispatcher(tools.NewRegistry(), run, auth, t.TempDir(), cwd, func() *sessions.Store { return store }, 65536, securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	// Up-front advertised tools on both the initial and the continuation round (Done-when 4).
	if len(perRound) != 2 {
		t.Fatalf("provider rounds = %d, want 2 (tool-call round + continuation round)", len(perRound))
	}
	want := []string{"bash", "suggest_followup", "vcs_commit", "vcs_status"}
	for i, got := range perRound {
		if !slices.Equal(got, want) {
			t.Fatalf("round %d advertised %v, want %v (the same set on every round)", i, got, want)
		}
	}

	// The tool call round-trips: the result and the final answer are durable on disk.
	reloaded := reloadStore(t, store)
	toolMsgs := messagesByRole(reloaded, "tool")
	if len(toolMsgs) != 1 || toolMsgs[0].Content.Text() != "hi" || toolMsgs[0].ToolCallID != "call_1" {
		t.Fatalf("durable tool messages = %+v, want one {content hi, tool_call_id call_1}", toolMsgs)
	}
	asst := messagesByRole(reloaded, "assistant")
	if len(asst) == 0 || asst[len(asst)-1].Content.Text() != "done" {
		t.Fatalf("final assistant message = %+v, want the loop to re-issue to %q", asst, "done")
	}
}
