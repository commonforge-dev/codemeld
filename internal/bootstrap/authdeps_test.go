// Tests for the production permission-authorizer assembly (authdeps.go): a structured-tool
// authorization driven end-to-end through DispatchTool, the wired productionAuthorizer, a real
// grant table/turn cache, and the gated prompt (fake terminal) — asserting the prompt sees the
// full name+args call while matching on the bare registered name, that the in-memory grant
// short-circuits a repeat without re-prompting, and that the permission_* events read back from the
// active store; plus concurrent authorizations serializing at the shared gate with race-free shared
// grant-table access.
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/trust"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/turn"
	"codemeld.dev/codemeld/internal/vcs"
)

// TestBuildPromptDisplay_CarriesDispatchShellContext pins the production dispatch->bootstrap carry:
// productionAuthorizer.buildPromptDisplay (the seam Authorize uses to build the bootstrap prompt
// display) must copy dispatch's display-only shell scope/pipeline context onto the bootstrap display
// while preserving the run-scoped fields. If the applyShellContext call is dropped from that seam this
// test fails, unlike the direct applyShellContext unit test in promptgate_test.go.
func TestBuildPromptDisplay_CarriesDispatchShellContext(t *testing.T) {
	a := &productionAuthorizer{display: promptDisplayData{
		projectRoot:             "/work/proj",
		launchDir:               "/work/proj/sub",
		boundary:                "boundary",
		folderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
		wouldCreateSettingsFile: true,
	}}
	disp := dispatch.PromptDisplay{
		Action:       dispatch.ActionRunCommand,
		Subject:      "grep x",
		Pipeline:     "cat file | grep x",
		WholeCommand: true,
	}
	got := a.buildPromptDisplay(disp, "/work/proj/dir")

	if got.Pipeline != disp.Pipeline {
		t.Errorf("Pipeline = %q, want %q", got.Pipeline, disp.Pipeline)
	}
	if got.WholeCommand != disp.WholeCommand {
		t.Errorf("WholeCommand = %v, want %v", got.WholeCommand, disp.WholeCommand)
	}
	// run-scoped fields still resolved from the authorizer's display data and the request path scope.
	if got.ProjectRoot != "/work/proj" || got.FolderSettingsPath != "/work/proj/.codemeld/settings.yaml" {
		t.Errorf("run-scoped fields not preserved: %#v", got)
	}
	if got.FolderCoverage != "/work/proj/dir and its descendants" {
		t.Errorf("FolderCoverage = %q, want %q", got.FolderCoverage, "/work/proj/dir and its descendants")
	}
	if !got.WouldCreateSettingsFile {
		t.Error("WouldCreateSettingsFile not preserved")
	}
}

func TestBuildPromptDisplay_CarriesRunTrustDecision(t *testing.T) {
	for _, untrusted := range []bool{false, true} {
		a := &productionAuthorizer{display: promptDisplayData{projectRoot: "/work/proj", projectUntrusted: untrusted}}
		got := a.buildPromptDisplay(dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: "rm x"}, "/work/proj")
		if got.ProjectUntrusted != untrusted {
			t.Fatalf("ProjectUntrusted = %v, want %v", got.ProjectUntrusted, untrusted)
		}
		req, err := buildPromptRequest(permissions.MatchRequest{Kind: matchKindDirect, Subject: "rm x", PathScope: "/work/proj"}, got, permissions.ScopeEscalation{})
		if err != nil {
			t.Fatalf("buildPromptRequest: %v", err)
		}
		if req.ProjectUntrusted != untrusted {
			t.Fatalf("prompt request ProjectUntrusted = %v, want %v", req.ProjectUntrusted, untrusted)
		}
	}
}

// The production seam must also carry dispatch's display-only requested target, or a prompted
// structured tool reaches the prompt with no target for the summary to name.
func TestBuildPromptDisplay_CarriesRequestedTarget(t *testing.T) {
	a := &productionAuthorizer{display: promptDisplayData{projectRoot: "/work/proj"}}
	got := a.buildPromptDisplay(dispatch.PromptDisplay{
		Action:          dispatch.ActionRunTool,
		Subject:         "read",
		RequestedTarget: "/outside/a.txt",
		Body:            `read({"path":"/outside/a.txt"})`,
	}, "/outside")
	if got.RequestedTarget != "/outside/a.txt" {
		t.Fatalf("RequestedTarget = %q, want the dispatch lexical path", got.RequestedTarget)
	}
	summary := promptSummaryFor(permissions.MatchRequest{Kind: matchKindTool, Subject: "read"}, got, nil)
	if len(summary.Targets) != 1 || summary.Targets[0] != "/outside/a.txt" {
		t.Fatalf("summary targets = %#v, want the carried lexical path", summary.Targets)
	}
}

// authTestTool is a minimal structured tool with no distinct execution directory, so DispatchTool
// authorizes it against the process cwd and invokes it once authorized. readOnly drives its
// Advertise().ReadOnly classification, which DispatchTool maps onto the mode context's operation class.
type authTestTool struct {
	name     string
	readOnly bool
	invoked  *bool
}

func (t authTestTool) Name() string              { return t.name }
func (t authTestTool) SubjectKind() string       { return "tool" }
func (t authTestTool) Advertise() tools.Metadata { return tools.Metadata{ReadOnly: t.readOnly} }
func (t authTestTool) Invoke(context.Context, map[string]any) (tools.Result, error) {
	if t.invoked != nil {
		*t.invoked = true
	}
	return tools.Result{}, nil
}

// emptyCache builds a real config.Cache (the grant table) with no preconfigured grants, anchored at
// projectRoot, for driving the authorizer against a real matching table.
func emptyCache(t *testing.T, projectRoot string) *config.Cache {
	t.Helper()
	c, err := config.NewCache(map[string]any{}, projectRoot, nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	return c
}

// permissionEventKinds returns the kinds of every permission_* event in the store's stream, in order.
func permissionEventKinds(store *sessions.Store) []string {
	var kinds []string
	for _, rec := range store.Records() {
		if ev, ok := rec.(sessions.Event); ok {
			kinds = append(kinds, ev.Kind)
		}
	}
	return kinds
}

// firstEvent returns the first event of kind in the store, failing if none exists.
func firstEvent(t *testing.T, store *sessions.Store, kind string) sessions.Event {
	t.Helper()
	for _, rec := range store.Records() {
		if ev, ok := rec.(sessions.Event); ok && ev.Kind == kind {
			return ev
		}
	}
	t.Fatalf("no %s event in store stream", kind)
	return sessions.Event{}
}

// TestProductionAuthorizer_StructuredToolEndToEnd drives a structured-tool authorization the whole
// way through DispatchTool → the wired productionAuthorizer → the permissions orchestrator → the gated
// prompt (a fake terminal). It asserts the prompt sees the full structured-tool call including args
// while the matching subject stays the bare registered name, that the session grant the prompt
// creates short-circuits a second identical call without re-prompting, and reads the emitted
// permission_* events back from the active session store.
func TestProductionAuthorizer_StructuredToolEndToEnd(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	var (
		shown  int
		gotReq tui.PromptRequest
	)
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		gotReq = req
		return tui.PromptDecision{Option: tui.OptionAllowSession}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, authTestTool{name: "read_file"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	args := map[string]any{"path": "/proj/main.go"}

	// First call: no grant, no cache hit, so the user is prompted and grants a session permission.
	if _, err := dispatch.DispatchTool(context.Background(), "read_file", args, home, cwd, reg, auth); err != nil {
		t.Fatalf("DispatchTool (first): %v", err)
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times, want exactly 1", shown)
	}
	// An unmapped tool shows the generic "Run tool" action over the registered name, with the
	// full call as the verbatim body; the matching subject (asserted via the event log below) stays the
	// bare name so grants/events are unaffected.
	if gotReq.Action != dispatch.ActionRunTool {
		t.Errorf("prompt Action = %q, want %q (other-tool action header)", gotReq.Action, dispatch.ActionRunTool)
	}
	if gotReq.Subject != "read_file" {
		t.Errorf("prompt display Subject = %q, want the registered tool name read_file", gotReq.Subject)
	}
	if want := `read_file({"path":"/proj/main.go"})`; gotReq.Body != want {
		t.Errorf("prompt Body = %q, want the full structured-tool call %q", gotReq.Body, want)
	}
	if gotReq.Kind != tui.SubjectStructuredTool {
		t.Errorf("prompt Kind = %q, want %q", gotReq.Kind, tui.SubjectStructuredTool)
	}

	// Second identical call: the in-memory session grant must authorize it without prompting.
	if _, err := dispatch.DispatchTool(context.Background(), "read_file", args, home, cwd, reg, auth); err != nil {
		t.Fatalf("DispatchTool (second): %v", err)
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times after a session grant, want still 1 (the grant must short-circuit)", shown)
	}

	// Read the emitted permission_* events back from the active store (not just fake-emit calls).
	kinds := permissionEventKinds(store)
	for _, want := range []string{events.KindPermissionPromptShown, events.KindPermissionDecision, events.KindPermissionMatched} {
		if !slices.Contains(kinds, want) {
			t.Errorf("permission event stream %v missing %q", kinds, want)
		}
	}

	var shownPayload events.PermissionPromptShown
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionPromptShown).Payload, &shownPayload); err != nil {
		t.Fatalf("unmarshal permission_prompt_shown: %v", err)
	}
	if shownPayload.SubjectKind != "tool" || shownPayload.Subject != "read_file" {
		t.Errorf("permission_prompt_shown = %#v, want tool/read_file (matching subject, not the args call)", shownPayload)
	}

	var decision events.PermissionDecision
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionDecision).Payload, &decision); err != nil {
		t.Fatalf("unmarshal permission_decision: %v", err)
	}
	if decision.Outcome != "granted" || decision.GrantKind != "session" {
		t.Errorf("permission_decision = %#v, want granted/session", decision)
	}

	var matched events.PermissionMatched
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionMatched).Payload, &matched); err != nil {
		t.Fatalf("unmarshal permission_matched: %v", err)
	}
	if matched.OutcomeSource != "grant" || matched.Outcome != "session_grant" || matched.Subject != "read_file" {
		t.Errorf("permission_matched = %#v, want grant/session_grant/read_file (the in-memory grant authorized the repeat)", matched)
	}
}

// TestProductionAuthorizer_CreatePromptShowsFileAndContent is the terminal production test this task
// owns (Wiring contract): a real `create` call in Build mode is driven through DispatchTool → the
// wired productionAuthorizer → the orchestrator → the gated prompt (a fake terminal), and the prompt the user
// sees carries the human-readable create display: action "Create file", the filename the
// model produced, and the file content verbatim — not the JSON call. It proves the
// dispatch→display→tui contract is wired through the *real* create tool, not only set in a tui unit
// test; the matching subject stays "create" in the event log (asserted below). It fails if DispatchTool
// stops building the file display, if the authorizer stops carrying Action/Subject/Body, or if the
// prompt stops receiving them.
func TestProductionAuthorizer_CreatePromptShowsFileAndContent(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	var gotReq tui.PromptRequest
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		gotReq = req
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	content := "1. Alberta\n2. British Columbia\n"
	args := map[string]any{"path": "provinces.md", "content": content}
	if _, err := dispatch.DispatchTool(context.Background(), filetools.CreateToolName, args, home, cwd, reg, auth); err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}

	if gotReq.Action != dispatch.ActionCreateFile {
		t.Errorf("prompt Action = %q, want %q", gotReq.Action, dispatch.ActionCreateFile)
	}
	if gotReq.Subject != "provinces.md" {
		t.Errorf("prompt Subject = %q, want the filename the model produced (provinces.md)", gotReq.Subject)
	}
	if gotReq.Body != content {
		t.Errorf("prompt Body = %q, want the file content verbatim %q", gotReq.Body, content)
	}

	// The matching subject (no longer shown on the prompt) stays the bare registered name in the event log.
	var shownPayload events.PermissionPromptShown
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionPromptShown).Payload, &shownPayload); err != nil {
		t.Fatalf("unmarshal permission_prompt_shown: %v", err)
	}
	if shownPayload.Subject != filetools.CreateToolName || shownPayload.SubjectKind != "tool" {
		t.Errorf("permission_prompt_shown = %#v, want tool/create (matching subject preserved in the event log)", shownPayload)
	}
}

func TestProductionAuthorizer_BuildPromptsBeforeNestedCreate(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	target := filepath.Join(cwd, "docs", "guide.md")

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	shown := 0
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		if _, statErr := os.Lstat(filepath.Join(cwd, "docs")); !errors.Is(statErr, fs.ErrNotExist) {
			t.Fatalf("missing parent %q exists at prompt time: %v (creation must not precede authorization)", filepath.Join(cwd, "docs"), statErr)
		}
		return tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope("")}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	args := map[string]any{"path": target, "content": "NEW"}
	_, derr := dispatch.DispatchTool(context.Background(), filetools.CreateToolName, args, home, cwd, reg, auth)
	var de *dispatch.DeniedError
	if !errors.As(derr, &de) {
		t.Fatalf("DispatchTool err = %v, want a *dispatch.DeniedError (Build prompts, then is denied)", derr)
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times, want 1 (Build prompts for a nested create; it does not auto-approve)", shown)
	}
	for _, p := range []string{target, filepath.Join(cwd, "docs")} {
		if _, statErr := os.Lstat(p); !errors.Is(statErr, fs.ErrNotExist) {
			t.Fatalf("denied Build nested create produced %q: %v", p, statErr)
		}
	}
}

// TestProductionAuthorizer_DeletePromptShowsFile proves delete's production wiring: a real `delete` call in
// Build mode is driven through DispatchTool → the wired productionAuthorizer → the gated prompt (a fake
// terminal), and the prompt the user sees carries the delete display: action "Delete file" and
// the filename the model produced, with no body (the irreversible removal of the named path is the whole
// approval). The matching subject stays "delete" in the event log. It proves the dispatch→display→tui
// contract is wired through the *real* delete tool, and — with no grant — that a delete reaches the prompt
// rather than being auto-approved. It fails if DispatchTool stops building the delete display, if the
// authorizer stops carrying Action/Subject/Body, or if the prompt stops receiving them.
func TestProductionAuthorizer_DeletePromptShowsFile(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	// The delete target must exist for pre-authorization resolution to succeed (delete is must-exist).
	if err := os.WriteFile(filepath.Join(cwd, "doomed.txt"), []byte("bye\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	var gotReq tui.PromptRequest
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		gotReq = req
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewDeleteTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := dispatch.DispatchTool(context.Background(), filetools.DeleteToolName, map[string]any{"path": "doomed.txt"}, home, cwd, reg, auth); err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}

	if gotReq.Action != dispatch.ActionDeleteFile {
		t.Errorf("prompt Action = %q, want %q", gotReq.Action, dispatch.ActionDeleteFile)
	}
	if gotReq.Subject != "doomed.txt" {
		t.Errorf("prompt Subject = %q, want the filename the model produced (doomed.txt)", gotReq.Subject)
	}
	if gotReq.Body != "" {
		t.Errorf("prompt Body = %q, want empty (a delete shows no payload)", gotReq.Body)
	}

	var shownPayload events.PermissionPromptShown
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionPromptShown).Payload, &shownPayload); err != nil {
		t.Fatalf("unmarshal permission_prompt_shown: %v", err)
	}
	if shownPayload.Subject != filetools.DeleteToolName || shownPayload.SubjectKind != "tool" {
		t.Errorf("permission_prompt_shown = %#v, want tool/delete (matching subject preserved in the event log)", shownPayload)
	}
}

// TestProductionAuthorizer_DeleteAllowOncePromptsEachTarget is the regression guard: an allow-once
// delete of one file must not authorize a second delete of a *different* file in the same parent during
// the same turn. It drives two real delete tools through DispatchTool → the wired productionAuthorizer →
// a real shared TurnCache, approving each with OptionAllowOnce. The turn-cache key is
// (subject_kind, subject, path_scope) and omits the target filename, so before the fix the second
// delete hit the cached "delete" decision and ran with no prompt; now each concrete delete reaches its
// own prompt. It fails if a delete's allow-once outcome is recorded in the turn cache again.
func TestProductionAuthorizer_DeleteAllowOncePromptsEachTarget(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	// Two sibling files in the same parent directory: their delete requests share kind/subject/path scope.
	aPath := filepath.Join(cwd, "a.txt")
	bPath := filepath.Join(cwd, "b.txt")
	for _, p := range []string{aPath, bPath} {
		if werr := os.WriteFile(p, []byte("bye\n"), 0o644); werr != nil {
			t.Fatalf("WriteFile %s: %v", p, werr)
		}
	}
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	shown := 0
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	// One authorizer and one TurnCache shared across both deletes models a single turn (the cache is not
	// Reset between them), so a leaked allow-once would short-circuit the second delete.
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewDeleteTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// First delete: no grant, no cache hit → one prompt, file removed.
	if _, err := dispatch.DispatchTool(context.Background(), filetools.DeleteToolName, map[string]any{"path": "a.txt"}, home, cwd, reg, auth); err != nil {
		t.Fatalf("DispatchTool (a.txt): %v", err)
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times after first delete, want 1", shown)
	}
	if _, serr := os.Stat(aPath); !os.IsNotExist(serr) {
		t.Fatalf("a.txt stat err = %v, want not-exist (the allow-once delete should have removed it)", serr)
	}

	// Second delete of a *different* file in the same parent, same turn: must prompt again, not ride the
	// first delete's cached decision.
	if _, err := dispatch.DispatchTool(context.Background(), filetools.DeleteToolName, map[string]any{"path": "b.txt"}, home, cwd, reg, auth); err != nil {
		t.Fatalf("DispatchTool (b.txt): %v", err)
	}
	if shown != 2 {
		t.Fatalf("prompt shown %d times after second delete, want 2 (each delete needs its own approval; a cached allow-once would bypass b.txt)", shown)
	}
	if _, serr := os.Stat(bPath); !os.IsNotExist(serr) {
		t.Fatalf("b.txt stat err = %v, want not-exist (removed only after its own prompt)", serr)
	}
}

// TestProductionAuthorizer_MoveAllowOncePromptsEachPair is the regression guard: an allow-once move
// of one source/destination pair must not authorize a *different* move in the same parent during the same
// turn. It drives two real moves through DispatchTool → the wired productionAuthorizer → a real shared
// TurnCache, approving each with OptionAllowOnce. The turn-cache key is (subject_kind, subject, path_scope)
// and omits the resolved endpoints, so before the fix the second move hit the cached "move" decision and
// ran with no prompt — a target-blind grant for a source+destination mutation. Now each concrete move
// reaches its own prompt showing its own endpoints. It fails if a move's allow-once outcome is recorded in
// the turn cache again.
func TestProductionAuthorizer_MoveAllowOncePromptsEachPair(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	// Two distinct sources in the same parent directory: their move requests share kind/subject/path scope,
	// so a leaked allow-once would let the second ride the first's decision.
	aPath := filepath.Join(cwd, "a.txt")
	cPath := filepath.Join(cwd, "c.txt")
	for _, p := range []string{aPath, cPath} {
		if werr := os.WriteFile(p, []byte("body\n"), 0o644); werr != nil {
			t.Fatalf("WriteFile %s: %v", p, werr)
		}
	}
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	var subjects []string
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		subjects = append(subjects, req.Subject)
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	// One authorizer and one TurnCache shared across both moves models a single turn (the cache is not
	// Reset between them), so a leaked allow-once would short-circuit the second move.
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewMoveTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// First move: no grant, no cache hit → one prompt over its own endpoints, rename runs.
	if _, derr := dispatch.DispatchTool(context.Background(), filetools.MoveToolName,
		map[string]any{"source": "a.txt", "destination": "b.txt"}, home, cwd, reg, auth); derr != nil {
		t.Fatalf("DispatchTool (a.txt -> b.txt): %v", derr)
	}
	if len(subjects) != 1 {
		t.Fatalf("prompt shown %d times after first move, want 1", len(subjects))
	}
	if _, serr := os.Stat(aPath); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("a.txt stat err = %v, want not-exist (the allow-once move should have renamed it)", serr)
	}

	// Second move of a *different* pair in the same parent, same turn: must prompt again over its own
	// endpoints, not ride the first move's cached decision.
	if _, derr := dispatch.DispatchTool(context.Background(), filetools.MoveToolName,
		map[string]any{"source": "c.txt", "destination": "d.txt"}, home, cwd, reg, auth); derr != nil {
		t.Fatalf("DispatchTool (c.txt -> d.txt): %v", derr)
	}
	if len(subjects) != 2 {
		t.Fatalf("prompt shown %d times after second move, want 2 (each move needs its own approval; a cached allow-once would bypass c.txt -> d.txt)", len(subjects))
	}
	// The second prompt showed its own endpoints, proving it was a fresh decision and not a reused one.
	if subjects[1] != "c.txt -> d.txt" {
		t.Fatalf("second prompt Subject = %q, want \"c.txt -> d.txt\" (its own endpoints, not the first move's)", subjects[1])
	}
	if _, serr := os.Stat(cPath); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("c.txt stat err = %v, want not-exist (renamed only after its own prompt)", serr)
	}
	if data, rerr := os.ReadFile(filepath.Join(cwd, "d.txt")); rerr != nil || string(data) != "body\n" {
		t.Fatalf("destination d.txt = %q (err %v), want the moved content", string(data), rerr)
	}
}

// TestProductionAuthorizer_MoveDenyDoesNotSuppressNextPair pins the deny side of the move fix: denying one
// move's source/destination pair must not short-circuit (and silently suppress the prompt for) a different
// same-scope move in the same turn. It drives two real moves through one shared production authorizer and
// TurnCache: the first is denied (DispatchTool returns a *DeniedError and nothing is moved), the second —
// a distinct pair in the same parent — must still reach its own prompt and, on approval, run. It fails if a
// denied move's outcome is recorded in the turn cache, which would deny or suppress the second move.
func TestProductionAuthorizer_MoveDenyDoesNotSuppressNextPair(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	aPath := filepath.Join(cwd, "a.txt")
	cPath := filepath.Join(cwd, "c.txt")
	for _, p := range []string{aPath, cPath} {
		if werr := os.WriteFile(p, []byte("body\n"), 0o644); werr != nil {
			t.Fatalf("WriteFile %s: %v", p, werr)
		}
	}
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	// Deny the first move; allow the second once. Both share the (tool, move, cwd) cache key.
	var subjects []string
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		subjects = append(subjects, req.Subject)
		if len(subjects) == 1 {
			return tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope("")}, nil
		}
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewMoveTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// First move: denied → DeniedError, one prompt, nothing moved.
	_, derr := dispatch.DispatchTool(context.Background(), filetools.MoveToolName,
		map[string]any{"source": "a.txt", "destination": "b.txt"}, home, cwd, reg, auth)
	var de *dispatch.DeniedError
	if !errors.As(derr, &de) {
		t.Fatalf("DispatchTool (a.txt -> b.txt) err = %v, want a *dispatch.DeniedError", derr)
	}
	if len(subjects) != 1 {
		t.Fatalf("prompt shown %d times after first move, want 1", len(subjects))
	}
	if _, serr := os.Stat(aPath); serr != nil {
		t.Fatalf("a.txt stat err = %v, want it still present (the denied move must not run)", serr)
	}

	// Second move of a *different* pair in the same parent, same turn: the denied first decision must not be
	// cached, so this prompts again and, approved, runs.
	if _, derr := dispatch.DispatchTool(context.Background(), filetools.MoveToolName,
		map[string]any{"source": "c.txt", "destination": "d.txt"}, home, cwd, reg, auth); derr != nil {
		t.Fatalf("DispatchTool (c.txt -> d.txt): %v", derr)
	}
	if len(subjects) != 2 {
		t.Fatalf("prompt shown %d times after second move, want 2 (a denied first move must not suppress the second's prompt)", len(subjects))
	}
	if subjects[1] != "c.txt -> d.txt" {
		t.Fatalf("second prompt Subject = %q, want \"c.txt -> d.txt\"", subjects[1])
	}
	if _, serr := os.Stat(cPath); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("c.txt stat err = %v, want not-exist (renamed after its own prompt)", serr)
	}
	if data, rerr := os.ReadFile(filepath.Join(cwd, "d.txt")); rerr != nil || string(data) != "body\n" {
		t.Fatalf("destination d.txt = %q (err %v), want the moved content", string(data), rerr)
	}
}

// TestProductionAuthorizer_PlanDeniesMutatingEndToEnd drives a mutating structured-tool call through
// the real production path — DispatchTool → the wired productionAuthorizer reading a Plan-mode
// ActiveState → the permissions mode posture — and proves the seam this task owns is wired, not stubbed:
// Plan denies the call without prompting, returns a denied_by:"mode" envelope, never invokes the tool,
// and records a single permission_matched{outcome_source: "mode_auto", outcome: "deny"} read back from
// the real session store (the modes integration suite re-proves this end-to-end at the provider level).
func TestProductionAuthorizer_PlanDeniesMutatingEndToEnd(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	shown := 0
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		return tui.PromptDecision{}, errors.New("Plan must not prompt")
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Plan, mode.SourceConfig))

	invoked := false
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, authTestTool{name: "edit_file", invoked: &invoked}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, err := dispatch.DispatchTool(context.Background(), "edit_file", map[string]any{"path": "/proj/x.go"}, home, cwd, reg, auth)
	var denied *dispatch.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("DispatchTool err = %v, want a *dispatch.DeniedError (Plan denies a mutating tool)", err)
	}
	if invoked {
		t.Fatal("a denied tool must not be invoked")
	}
	if shown != 0 {
		t.Fatalf("prompt shown %d times, want 0 (Plan never prompts)", shown)
	}
	var env struct {
		DeniedBy string `json:"denied_by"`
		Reason   string `json:"reason"`
	}
	if uerr := json.Unmarshal([]byte(denied.Envelope), &env); uerr != nil {
		t.Fatalf("deny envelope is not clean JSON: %v", uerr)
	}
	if env.DeniedBy != "mode" {
		t.Fatalf("denied_by = %q, want \"mode\" (a policy denial must not look like a user denial)", env.DeniedBy)
	}

	// Only the mode_auto deny event is recorded — no prompt_shown, no decision, no grant match.
	if kinds := permissionEventKinds(store); !slices.Equal(kinds, []string{events.KindPermissionMatched}) {
		t.Fatalf("permission event stream = %v, want exactly [permission_matched]", kinds)
	}
	var matched events.PermissionMatched
	if uerr := json.Unmarshal(firstEvent(t, store, events.KindPermissionMatched).Payload, &matched); uerr != nil {
		t.Fatalf("unmarshal permission_matched: %v", uerr)
	}
	if matched.OutcomeSource != "mode_auto" || matched.Outcome != "deny" {
		t.Fatalf("permission_matched = %#v, want mode_auto/deny", matched)
	}
	if matched.GrantKind != "" || matched.GrantPathScope != "" {
		t.Fatalf("mode_auto deny carried grant fields: %#v", matched)
	}
	if matched.Subject != "edit_file" {
		t.Fatalf("permission_matched subject = %q, want edit_file", matched.Subject)
	}
}

// TestProductionAuthorizer_PlanAllowsReadOnlyEndToEnd is the allow counterpart: a read-only tool in
// Plan mode is auto-approved without prompting, the tool is invoked, and a permission_matched{
// outcome_source: "mode_auto", outcome: "once"} is recorded — proving the wired Plan posture allows
// read-only investigation as well as denying mutations.
func TestProductionAuthorizer_PlanAllowsReadOnlyEndToEnd(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	shown := 0
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		return tui.PromptDecision{}, errors.New("Plan must not prompt")
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Plan, mode.SourceConfig))

	invoked := false
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, authTestTool{name: "read_file", readOnly: true, invoked: &invoked}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := dispatch.DispatchTool(context.Background(), "read_file", map[string]any{"path": "/proj/x.go"}, home, cwd, reg, auth); err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	if !invoked {
		t.Fatal("a read-only tool auto-allowed in Plan must be invoked")
	}
	if shown != 0 {
		t.Fatalf("prompt shown %d times, want 0 (Plan never prompts)", shown)
	}
	if kinds := permissionEventKinds(store); !slices.Equal(kinds, []string{events.KindPermissionMatched}) {
		t.Fatalf("permission event stream = %v, want exactly [permission_matched]", kinds)
	}
	var matched events.PermissionMatched
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionMatched).Payload, &matched); err != nil {
		t.Fatalf("unmarshal permission_matched: %v", err)
	}
	if matched.OutcomeSource != "mode_auto" || matched.Outcome != "once" {
		t.Fatalf("permission_matched = %#v, want mode_auto/once", matched)
	}
	if matched.GrantKind != "" || matched.GrantPathScope != "" {
		t.Fatalf("mode_auto allow carried grant fields: %#v", matched)
	}
}

func TestProductionAuthorizer_WebToolNeverAutoAllowedEndToEnd(t *testing.T) {
	modes := []struct {
		name  string
		state *mode.ActiveState
	}{
		{"build", mode.NewActiveState(mode.Build, mode.SourceDefault)},
		{"auto_edits", mode.NewActiveState(mode.AutoEdits, mode.SourceConfig)},
		{"plan", mode.NewActiveState(mode.Plan, mode.SourceConfig)},
	}
	for _, name := range []string{webSearchToolName, webFetchToolName} {
		for _, m := range modes {
			for _, readOnly := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/read_only=%v", name, m.name, readOnly), func(t *testing.T) {
					cwd := t.TempDir()
					home := t.TempDir()
					store := mkStore(t)
					app := tui.New(nil)
					app.SetActiveStore(store)

					shown := 0
					show := func(tui.PromptRequest) (tui.PromptDecision, error) {
						shown++
						return tui.PromptDecision{Option: tui.OptionDeny}, nil
					}
					auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, m.state)

					invoked := false
					reg := tools.NewRegistry()
					if err := reg.Register(tools.BuiltinSource, authTestTool{name: name, readOnly: readOnly, invoked: &invoked}); err != nil {
						t.Fatalf("Register: %v", err)
					}

					_, err := dispatch.DispatchTool(context.Background(), name, map[string]any{"query": "codemeld"}, home, cwd, reg, auth)
					var denied *dispatch.DeniedError
					if !errors.As(err, &denied) {
						t.Fatalf("DispatchTool err = %v, want a *dispatch.DeniedError", err)
					}
					if shown != 1 {
						t.Fatalf("prompt shown %d times in %s, want exactly 1 (no mode posture may resolve a web call)", shown, m.name)
					}
					if invoked {
						t.Fatal("a denied web tool must not be invoked — no socket may open")
					}
					var env struct {
						DeniedBy string `json:"denied_by"`
					}
					if uerr := json.Unmarshal([]byte(denied.Envelope), &env); uerr != nil {
						t.Fatalf("deny envelope is not clean JSON: %v", uerr)
					}
					if env.DeniedBy != "user" {
						t.Fatalf("denied_by = %q, want \"user\" (the denial comes from the prompt, not a mode policy)", env.DeniedBy)
					}
					if kinds := permissionEventKinds(store); !slices.Equal(kinds, []string{events.KindPermissionPromptShown, events.KindPermissionDecision}) {
						t.Fatalf("permission event stream = %v in %s, want [permission_prompt_shown permission_decision]", kinds, m.name)
					}
				})
			}
		}
	}
}

func TestProductionAuthorizer_WebToolApprovedInvokesEndToEnd(t *testing.T) {
	for _, name := range []string{webSearchToolName, webFetchToolName} {
		t.Run(name, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			store := mkStore(t)
			app := tui.New(nil)
			app.SetActiveStore(store)

			shown := 0
			show := func(tui.PromptRequest) (tui.PromptDecision, error) {
				shown++
				return tui.PromptDecision{Option: tui.OptionAllowSession}, nil
			}
			auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Plan, mode.SourceConfig))

			invoked := false
			reg := tools.NewRegistry()
			if err := reg.Register(tools.BuiltinSource, authTestTool{name: name, invoked: &invoked}); err != nil {
				t.Fatalf("Register: %v", err)
			}

			if _, err := dispatch.DispatchTool(context.Background(), name, map[string]any{"query": "codemeld"}, home, cwd, reg, auth); err != nil {
				t.Fatalf("DispatchTool: %v", err)
			}
			if shown != 1 {
				t.Fatalf("prompt shown %d times, want exactly 1", shown)
			}
			if !invoked {
				t.Fatal("an approved web tool must be invoked")
			}

			invoked = false
			if _, err := dispatch.DispatchTool(context.Background(), name, map[string]any{"query": "codemeld"}, home, cwd, reg, auth); err != nil {
				t.Fatalf("DispatchTool (second): %v", err)
			}
			if shown != 1 {
				t.Fatalf("prompt shown %d times, want the grant to short-circuit the repeat", shown)
			}
			if !invoked {
				t.Fatal("a granted web tool must be invoked")
			}
		})
	}
}

// TestProductionAuthorizer_PlanDeniesRawShellEndToEnd proves Plan's mutating-deny posture for a
// mutating raw-shell command end to end: `git push` is a mutating VCS subcommand (not one of the
// read-only carve-out subcommands), so it classifies mutating and Plan denies it without
// prompting, driven through the real DispatchShell → wired productionAuthorizer → orchestrator path. The
// command never executes and the deny carries denied_by:"mode".
func TestProductionAuthorizer_PlanDeniesRawShellEndToEnd(t *testing.T) {
	prependFixturePrograms(t, "git")
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	shown := 0
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		return tui.PromptDecision{}, errors.New("Plan must not prompt")
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Plan, mode.SourceConfig))

	run := &fakeDispatchRunner{}
	// `git push` mutates — it is not one of the read-only carve-out subcommands, so it
	// classifies mutating and Plan denies it without prompting.
	_, err := dispatch.DispatchShell(context.Background(), "git push", home, cwd, auth, run)
	var denied *dispatch.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("DispatchShell err = %v, want a *dispatch.DeniedError (Plan denies non-allowlisted raw shell)", err)
	}
	if run.callCount() != 0 {
		t.Fatalf("runner Exec calls = %d, want 0 (a denied shell command must not execute)", run.callCount())
	}
	if shown != 0 {
		t.Fatalf("prompt shown %d times, want 0 (Plan never prompts)", shown)
	}
	var env struct {
		DeniedBy string `json:"denied_by"`
	}
	if uerr := json.Unmarshal([]byte(denied.Envelope), &env); uerr != nil {
		t.Fatalf("deny envelope is not clean JSON: %v", uerr)
	}
	if env.DeniedBy != "mode" {
		t.Fatalf("denied_by = %q, want \"mode\"", env.DeniedBy)
	}
	var matched events.PermissionMatched
	if uerr := json.Unmarshal(firstEvent(t, store, events.KindPermissionMatched).Payload, &matched); uerr != nil {
		t.Fatalf("unmarshal permission_matched: %v", uerr)
	}
	if matched.OutcomeSource != "mode_auto" || matched.Outcome != "deny" || matched.SubjectKind != "direct" {
		t.Fatalf("permission_matched = %#v, want mode_auto/deny on a direct subject", matched)
	}
}

func declaredCommandCache(t *testing.T, projectRoot string, entries ...string) *config.Cache {
	t.Helper()
	items := make([]any, len(entries))
	for i, e := range entries {
		items[i] = e
	}
	c, err := config.NewCache(map[string]any{"declared_commands": items}, projectRoot, nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	return c
}

func TestProductionAuthorizer_AutoDeclaredCommandEndToEnd(t *testing.T) {
	prependFixturePrograms(t, "git")
	t.Run("declared prefix covers the changing argument without prompting", func(t *testing.T) {
		cwd := t.TempDir()
		home := t.TempDir()
		store := mkStore(t)
		app := tui.New(nil)
		app.SetActiveStore(store)

		shown := 0
		show := func(tui.PromptRequest) (tui.PromptDecision, error) {
			shown++
			return tui.PromptDecision{}, errors.New("a declared command must not prompt")
		}
		cache := declaredCommandCache(t, cwd, "git push")
		auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))

		run := &fakeDispatchRunner{}
		for _, cmd := range []string{"git push origin main", "git push origin release"} {
			if _, err := dispatch.DispatchShell(context.Background(), cmd, home, cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell(%q): %v", cmd, err)
			}
		}
		if shown != 0 {
			t.Fatalf("prompt shown %d times, want 0", shown)
		}
		if run.callCount() != 2 {
			t.Fatalf("runner Exec calls = %d, want 2", run.callCount())
		}
		if kinds := permissionEventKinds(store); !slices.Equal(kinds, []string{events.KindPermissionMatched, events.KindPermissionMatched}) {
			t.Fatalf("permission event stream = %v, want two permission_matched records and nothing else", kinds)
		}
		var matched events.PermissionMatched
		if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionMatched).Payload, &matched); err != nil {
			t.Fatalf("unmarshal permission_matched: %v", err)
		}
		want := events.PermissionMatched{
			SubjectKind:          "direct",
			Subject:              "git push origin main",
			PathScope:            cwd,
			Outcome:              "once",
			OutcomeSource:        "declared_command",
			DirectRequestSubject: "git push origin main",
		}
		if matched != want {
			t.Fatalf("permission_matched = %#v, want %#v", matched, want)
		}
		if got := len(cache.Permissions()); got != 0 {
			t.Fatalf("grant table holds %d entries, want 0", got)
		}
	})

	t.Run("an undeclared command still prompts", func(t *testing.T) {
		cwd := t.TempDir()
		home := t.TempDir()
		store := mkStore(t)
		app := tui.New(nil)
		app.SetActiveStore(store)

		shown := 0
		show := func(tui.PromptRequest) (tui.PromptDecision, error) {
			shown++
			return tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope("")}, nil
		}
		auth := newProductionAuthorizer(app, declaredCommandCache(t, cwd, "git push"), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))

		run := &fakeDispatchRunner{}
		_, err := dispatch.DispatchShell(context.Background(), "git fetch origin", home, cwd, auth, run)
		var denied *dispatch.DeniedError
		if !errors.As(err, &denied) {
			t.Fatalf("DispatchShell err = %v, want a *dispatch.DeniedError", err)
		}
		if shown != 1 {
			t.Fatalf("prompt shown %d times, want 1", shown)
		}
		if run.callCount() != 0 {
			t.Fatalf("runner Exec calls = %d, want 0", run.callCount())
		}
	})
}

// TestProductionAuthorizer_AutoEditsApprovesInProjectCreateEndToEnd is the terminal production test
// (Wiring contract): an in-project `create` call in Auto edits is auto-approved through the *real*
// production path — DispatchTool resolving the create tool's target before authorization, the wired
// productionAuthorizer overlaying mode.AutoEdits and the project root, and the mode posture — without
// prompting. It proves the whole chain is bound, not stubbed: the real filetools create tool runs and
// writes the file, no prompt is shown, and a single permission_matched{outcome_source:"mode_auto",
// outcome:"once", subject_kind:"tool", subject:"create"} with the resolved containing directory as
// path_scope and no grant fields is read back from the real session store. It fails if DispatchTool stops
// carrying the resolved create target, if the authorizer stops overlaying AutoEdits/ProjectRoot, if a
// mode-auto create starts prompting, or if the persisted event shape changes.
func TestProductionAuthorizer_AutoEditsApprovesInProjectCreateEndToEnd(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	target := filepath.Join(cwd, "sub", "new.go")

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	shown := 0
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		return tui.PromptDecision{}, errors.New("Auto edits must not prompt for an in-project create")
	}
	cache := emptyCache(t, cwd)
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	args := map[string]any{"path": target, "content": "package main\n"}
	if _, err := dispatch.DispatchTool(context.Background(), filetools.CreateToolName, args, home, cwd, reg, auth); err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	if shown != 0 {
		t.Fatalf("prompt shown %d times, want 0 (Auto edits auto-approves an in-project nested create)", shown)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read created file: %v", err)
	}
	if string(got) != "package main\n" {
		t.Fatalf("created file content = %q, want the dispatched content", got)
	}
	if info, statErr := os.Stat(filepath.Join(cwd, "sub")); statErr != nil || !info.IsDir() {
		t.Fatalf("missing parent directory not created by the nested create: info=%v err=%v", info, statErr)
	}

	if kinds := permissionEventKinds(store); !slices.Equal(kinds, []string{events.KindPermissionMatched}) {
		t.Fatalf("permission event stream = %v, want exactly [permission_matched] (mode-auto: no prompt_shown, no decision)", kinds)
	}
	var matched events.PermissionMatched
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionMatched).Payload, &matched); err != nil {
		t.Fatalf("unmarshal permission_matched: %v", err)
	}
	want := events.PermissionMatched{
		SubjectKind:   "tool",
		Subject:       filetools.CreateToolName,
		PathScope:     cwd,
		Outcome:       "once",
		OutcomeSource: "mode_auto",
	}
	if matched != want {
		t.Fatalf("permission_matched = %#v, want %#v (mode_auto create approval with the deepest-existing-ancestor path_scope and no grant fields)", matched, want)
	}

	if got := len(cache.Permissions()); got != 0 {
		t.Fatalf("grant table holds %d entries, want 0 (a mode-auto approval creates no grant)", got)
	}
}

// TestProductionAuthorizer_AutoEditsCreateOutOfProjectPromptsWithFolderOption pins the production
// out-of-root create behavior: an out-of-project create is no longer rejected
// in-band before authorization, and Auto edits does not auto-approve it (isInScopeFileTool stays
// project-root-bound). It routes through the real authorizer to the approval prompt, which carries the
// out-of-root folder-grant signal and offers the folder option anchored on the real out-of-root folder
// (its grant file would still live in the project). With the prompt denied, no file is created and the
// default posture (no grant ⇒ out-of-root write denied) holds — only the mechanism moved from a hard deny
// to a prompt.
func TestProductionAuthorizer_AutoEditsCreateOutOfProjectPromptsWithFolderOption(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(outside): %v", err)
	}
	target := filepath.Join(outside, "nested", "x.go")

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	var gotReq tui.PromptRequest
	shown := 0
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		gotReq = req
		return tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope("")}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	args := map[string]any{"path": target, "content": "x"}
	_, derr := dispatch.DispatchTool(context.Background(), filetools.CreateToolName, args, home, cwd, reg, auth)
	var de *dispatch.DeniedError
	if !errors.As(derr, &de) {
		t.Fatalf("DispatchTool err = %v, want a *dispatch.DeniedError (out-of-project create prompts, then is denied)", derr)
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times, want 1 (Auto edits prompts for an out-of-project create; it does not auto-approve or reject in-band)", shown)
	}
	// The prompt carries the out-of-root signal and offers the folder option anchored on the real
	// out-of-root folder.
	if !gotReq.OutOfRootFileWrite {
		t.Fatalf("prompt OutOfRootFileWrite = false, want true for an out-of-project create")
	}
	if tui.OmitFolderOption(gotReq.RunFolder, gotReq.ProjectRoot, gotReq.OutOfRootFileWrite, gotReq.ProjectUntrusted).Hidden() {
		t.Fatalf("folder option omitted for an out-of-project create; want it offered (adr-017 option A)")
	}
	if gotReq.RunFolder != outside {
		t.Fatalf("prompt RunFolder = %q, want the real out-of-root folder %q (the deepest existing ancestor)", gotReq.RunFolder, outside)
	}
	// The denied prompt is recorded (prompt_shown + decision), proving authorization was reached.
	if kinds := permissionEventKinds(store); len(kinds) == 0 {
		t.Fatalf("permission event stream = %v, want the prompt/decision events (authorization is reached for an out-of-root create)", kinds)
	}
	if _, statErr := os.Stat(target); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("out-of-project target stat = %v, want it not to exist (denied, no file created)", statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(outside, "nested")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("out-of-project parent stat = %v, want it not to exist (denied, no external parent created)", statErr)
	}
}

func TestProductionAuthorizer_AutoEditsApprovesInProjectMkdirEndToEnd(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	containing := filepath.Join(cwd, "sub")
	if err := os.MkdirAll(containing, 0o755); err != nil {
		t.Fatalf("mkdir containing: %v", err)
	}
	target := filepath.Join(containing, "newdir")

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	shown := 0
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		return tui.PromptDecision{}, errors.New("Auto edits must not prompt for an in-project mkdir")
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewMkdirTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	args := map[string]any{"path": target}
	if _, err := dispatch.DispatchTool(context.Background(), filetools.MkdirToolName, args, home, cwd, reg, auth); err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	if shown != 0 {
		t.Fatalf("prompt shown %d times, want 0 (Auto edits auto-approves an in-project mkdir)", shown)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat created directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("created target = %v, want a directory", info.Mode())
	}

	if kinds := permissionEventKinds(store); !slices.Equal(kinds, []string{events.KindPermissionMatched}) {
		t.Fatalf("permission event stream = %v, want exactly [permission_matched] (mode-auto: no prompt_shown, no decision)", kinds)
	}
	var matched events.PermissionMatched
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionMatched).Payload, &matched); err != nil {
		t.Fatalf("unmarshal permission_matched: %v", err)
	}
	want := events.PermissionMatched{
		SubjectKind:   "tool",
		Subject:       filetools.MkdirToolName,
		PathScope:     containing,
		Outcome:       "once",
		OutcomeSource: "mode_auto",
	}
	if matched != want {
		t.Fatalf("permission_matched = %#v, want %#v (mode_auto mkdir approval with the ancestor path_scope and no grant fields)", matched, want)
	}
}

func TestProductionAuthorizer_AutoEditsMkdirOutOfProjectPrompts(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(outside): %v", err)
	}
	target := filepath.Join(outside, "newdir")

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	var gotReq tui.PromptRequest
	shown := 0
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		gotReq = req
		return tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope("")}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewMkdirTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	args := map[string]any{"path": target}
	_, derr := dispatch.DispatchTool(context.Background(), filetools.MkdirToolName, args, home, cwd, reg, auth)
	var de *dispatch.DeniedError
	if !errors.As(derr, &de) {
		t.Fatalf("DispatchTool err = %v, want a *dispatch.DeniedError (out-of-project mkdir prompts, then is denied)", derr)
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times, want 1 (Auto edits prompts for an out-of-project mkdir; it does not auto-approve)", shown)
	}
	if !gotReq.OutOfRootFileWrite {
		t.Fatalf("prompt OutOfRootFileWrite = false, want true for an out-of-project mkdir")
	}
	if _, statErr := os.Stat(target); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("out-of-project target stat = %v, want it not to exist (denied, no directory created)", statErr)
	}
}

// TestProductionAuthorizer_OutOfRootSessionGrantSkipsRepromptAndSiblingPrompts pins this behavior end to end:
// approving "allow for this session" for an out-of-root create persists an in-memory grant
// scoped to that out-of-root folder; a later create in the same folder matches the grant and does not
// re-prompt (Auto edits, like Build, honors a pre-existing covering grant), while a create in a *sibling*
// out-of-root folder is a distinct scope the grant does not cover, so it prompts again. The turn cache is
// reset between attempts so the no-re-prompt result is the persistent session grant, not the per-turn cache.
func TestProductionAuthorizer_OutOfRootSessionGrantSkipsRepromptAndSiblingPrompts(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	approved, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(approved): %v", err)
	}
	sibling, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(sibling): %v", err)
	}

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	prompts := 0
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		prompts++
		return tui.PromptDecision{Option: tui.OptionAllowSession}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	mustCreate := func(path string) {
		t.Helper()
		if _, derr := dispatch.DispatchTool(context.Background(), filetools.CreateToolName,
			map[string]any{"path": path, "content": "x"}, home, cwd, reg, auth); derr != nil {
			t.Fatalf("DispatchTool(%q) err = %v, want nil (authorized)", path, derr)
		}
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("create %q did not produce a file: %v", path, statErr)
		}
	}

	// First create in the approved out-of-root folder prompts once; approving session grants the folder.
	mustCreate(filepath.Join(approved, "a.go"))
	if prompts != 1 {
		t.Fatalf("prompts after first create = %d, want 1", prompts)
	}

	// Reset the turn cache so the next attempt must rely on the persistent session grant, not the cache.
	auth.resetTurnCache()
	mustCreate(filepath.Join(approved, "b.go"))
	if prompts != 1 {
		t.Fatalf("prompts after a second create in the approved folder = %d, want 1 (the session grant covers the folder and its descendants; no re-prompt)", prompts)
	}

	// A sibling out-of-root folder is a distinct scope the grant does not cover, so it prompts again.
	auth.resetTurnCache()
	mustCreate(filepath.Join(sibling, "c.go"))
	if prompts != 2 {
		t.Fatalf("prompts after a create in a sibling out-of-root folder = %d, want 2 (a distinct out-of-root folder prompts separately)", prompts)
	}
}

// TestProductionAuthorizer_OutOfRootFolderGrantDeniesSymlinkEscape pins the folder-approval boundary that an
// approved out-of-root folder grant must not be widened by symlink traversal: after approving a create in
// the real folder `approved` (session grant), a later create whose path is lexically *under* `approved` but
// whose parent symlink-resolves to a different out-of-root folder (`escaped`) is a distinct scope the grant
// does not cover, so it must prompt again — and when that prompt denies, nothing is written into the symlink
// target. Grant matching keys on the resolved real parent (ResolveTarget resolves the parent symlink to its
// real directory, resolve.go), so this fails if matching ever used the lexical approved folder instead of
// the resolved real parent. The turn cache is reset before the second attempt so the re-prompt is the grant
// table's verdict, not a per-turn cache miss.
func TestProductionAuthorizer_OutOfRootFolderGrantDeniesSymlinkEscape(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	approved, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(approved): %v", err)
	}
	escaped, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(escaped): %v", err)
	}

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	// The prompt grants the session on the first (real-folder) create, then flips to deny so the second
	// create — if it reaches the prompt at all instead of riding the grant — is rejected.
	prompts := 0
	decision := tui.PromptDecision{Option: tui.OptionAllowSession}
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		prompts++
		return decision, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Approve a create in the real out-of-root folder; the session grant is scoped to `approved`.
	if _, derr := dispatch.DispatchTool(context.Background(), filetools.CreateToolName,
		map[string]any{"path": filepath.Join(approved, "a.go"), "content": "x"}, home, cwd, reg, auth); derr != nil {
		t.Fatalf("DispatchTool(approved create) err = %v, want nil (session-approved out-of-root create)", derr)
	}
	if prompts != 1 {
		t.Fatalf("prompts after the approved-folder create = %d, want 1", prompts)
	}

	// Plant a symlink inside the approved folder that points at the separate `escaped` folder, then request a
	// create whose path is lexically under `approved` but whose parent resolves to `escaped`.
	if err := os.Symlink(escaped, filepath.Join(approved, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	decision = tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope("")}
	auth.resetTurnCache()

	target := filepath.Join(approved, "link", "new.go") // resolved real parent is escaped, not approved
	_, derr := dispatch.DispatchTool(context.Background(), filetools.CreateToolName,
		map[string]any{"path": target, "content": "x"}, home, cwd, reg, auth)
	var de *dispatch.DeniedError
	if !errors.As(derr, &de) {
		t.Fatalf("DispatchTool(symlink create) err = %v, want a *dispatch.DeniedError (the grant must not cover the symlink-resolved folder, so it prompts and is denied)", derr)
	}
	if prompts != 2 {
		t.Fatalf("prompts after the symlink-escape create = %d, want 2 (the resolved parent %q is outside the granted folder %q, so the grant must not match and it must prompt again)", prompts, escaped, approved)
	}
	if _, statErr := os.Stat(filepath.Join(escaped, "new.go")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("symlink-target file stat = %v, want it not to exist (denied, so no file is written into the escape folder)", statErr)
	}
}

// countPermissionEvents returns how many permission_* events of kind are in the store's stream.
func countPermissionEvents(store *sessions.Store, kind string) int {
	n := 0
	for _, k := range permissionEventKinds(store) {
		if k == kind {
			n++
		}
	}
	return n
}

// TestProductionAuthorizer_GlobalGrantTargetsGlobalSettingsAndDegrades drives a global grant choice
// end-to-end through productionAuthorizer.Authorize and forces the global settings persist to fail
// (its parent directory is seeded as a regular file, so config.Persist returns parent_dir_error). It
// pins the task-owned persistGrant closure's global branch: the write target must be the global
// settings file SettingsPath(home) — not the project folder settings file — and the request path must
// be passed through so a failed global persist degrades to a session grant scoped to that path. The
// single permission_persist_failed event proves both: its target_path is the global settings file and
// its degraded_to_path_scope is the request path (production folder/global
// target selection + degradation handoff through newProductionAuthorizer).
func TestProductionAuthorizer_GlobalGrantTargetsGlobalSettingsAndDegrades(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	// Force the global persist to fail by making the global settings file's parent directory
	// (<home>/.codemeld/global) a regular file, so EnsureDir hits ENOTDIR (parent_dir_error).
	globalParent := filepath.Dir(SettingsPath(home))
	if err := os.MkdirAll(filepath.Dir(globalParent), 0o755); err != nil {
		t.Fatalf("seed global parent dir: %v", err)
	}
	if err := os.WriteFile(globalParent, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed global parent file: %v", err)
	}

	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{Option: tui.OptionAllowGlobal}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	req := permissions.MatchRequest{Kind: "tool", Subject: "read_file", PathScope: cwd}
	d, err := auth.Authorize(context.Background(), req, dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: "read_file"}, permissions.ModeContext{})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if d.PersistErr == nil {
		t.Fatalf("Decision.PersistErr = nil, want the surfaced global persist failure")
	}

	var p events.PermissionPersistFailed
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionPersistFailed).Payload, &p); err != nil {
		t.Fatalf("unmarshal permission_persist_failed: %v", err)
	}
	if p.GrantKind != "global" {
		t.Errorf("event grant_kind = %q, want global", p.GrantKind)
	}
	if want := SettingsPath(home); p.TargetPath != want {
		t.Errorf("event target_path = %q, want the global settings file %q (persistGrant must select the global target)", p.TargetPath, want)
	}
	if p.DegradedToPathScope != cwd {
		t.Errorf("event degraded_to_path_scope = %q, want the request path %q (persistGrant must pass req.PathScope)", p.DegradedToPathScope, cwd)
	}
	if got := countPermissionEvents(store, events.KindPermissionPersistFailed); got != 1 {
		t.Fatalf("permission_persist_failed events = %d, want exactly 1", got)
	}
}

// TestProductionAuthorizer_FolderGrantTargetsFolderSettings drives a folder grant choice through
// productionAuthorizer.Authorize and forces the folder settings persist to fail (the
// <project_root>/.codemeld parent is seeded as a regular file). It pins the persistGrant closure's
// default (folder) branch: the write target must be <project_root>/.codemeld/settings.yaml, and a
// folder grant carries no degraded_to_path_scope because its scope is unchanged. Paired with the
// global test this protects both arms of the grant-kind target selection.
func TestProductionAuthorizer_FolderGrantTargetsFolderSettings(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	// Force the folder persist to fail by making <project_root>/.codemeld a regular file.
	if err := os.WriteFile(filepath.Join(cwd, ".codemeld"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed folder parent file: %v", err)
	}
	folderTarget := config.LocalSettingsPath(cwd)

	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{Option: tui.OptionAllowFolder}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	req := permissions.MatchRequest{Kind: "tool", Subject: "read_file", PathScope: cwd}
	if _, err := auth.Authorize(context.Background(), req, dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: "read_file"}, permissions.ModeContext{}); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	var p events.PermissionPersistFailed
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionPersistFailed).Payload, &p); err != nil {
		t.Fatalf("unmarshal permission_persist_failed: %v", err)
	}
	if p.GrantKind != "folder" {
		t.Errorf("event grant_kind = %q, want folder", p.GrantKind)
	}
	if p.TargetPath != folderTarget {
		t.Errorf("event target_path = %q, want the folder settings file %q (persistGrant must select the folder target)", p.TargetPath, folderTarget)
	}
	if p.DegradedToPathScope != "" {
		t.Errorf("event degraded_to_path_scope = %q, want absent for a folder grant", p.DegradedToPathScope)
	}
}

// readPersistedPermissions loads the on-disk settings file at path through the same config view the
// runtime uses and returns its typed permission entries, so a test can assert the exact grant_kind and
// path_scope a grant durably wrote — not merely that the file changed. projectRoot anchors the cache as
// production does.
func readPersistedPermissions(t *testing.T, path, projectRoot string) []permissions.PermissionEntry {
	t.Helper()
	_, raw, cat, err := config.LoadYAML(path)
	if err != nil || cat != config.LoadOK {
		t.Fatalf("LoadYAML(%q) cat=%v err=%v, want a readable settings file (a grant should have created it)", path, cat, err)
	}
	cache, err := config.NewCache(raw, projectRoot, nil)
	if err != nil {
		t.Fatalf("NewCache from %q: %v", path, err)
	}
	return cache.Permissions()
}

// findGrant returns the single persisted entry for subject (a registered tool name), failing if it is
// missing or duplicated so each readback assertion pins exactly one durable grant.
func findGrant(t *testing.T, entries []permissions.PermissionEntry, subject string) permissions.PermissionEntry {
	t.Helper()
	var found []permissions.PermissionEntry
	for _, e := range entries {
		if e.Subject == subject {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("persisted permission entries for subject %q = %d (%+v), want exactly 1", subject, len(found), entries)
	}
	return found[0]
}

// TestProductionAuthorizer_OutOfRootFolderGrantPersistsToProjectSettings closes the readback gap on
// the folder arm: approving "allow in this folder" for an out-of-root create must write a *durable* folder
// grant to <project_root>/.codemeld/settings.yaml whose path_scope is the real out-of-root folder (not
// "*", not the project root). It drives the real create tool through DispatchTool, approves
// OptionAllowFolder, then reads the project settings file back from disk and asserts the stored entry — so
// a regression that stops writing the grant, writes it to the wrong file, or stores the wrong path_scope
// fails here even when the in-memory session grant still works.
func TestProductionAuthorizer_OutOfRootFolderGrantPersistsToProjectSettings(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(outside): %v", err)
	}
	target := filepath.Join(outside, "new.go")

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{Option: tui.OptionAllowFolder}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, derr := dispatch.DispatchTool(context.Background(), filetools.CreateToolName,
		map[string]any{"path": target, "content": "x"}, home, cwd, reg, auth); derr != nil {
		t.Fatalf("DispatchTool err = %v, want nil (folder-approved out-of-root create)", derr)
	}
	if _, statErr := os.Stat(target); statErr != nil {
		t.Fatalf("folder-approved create did not produce a file: %v", statErr)
	}

	folderSettings := config.LocalSettingsPath(cwd)
	entry := findGrant(t, readPersistedPermissions(t, folderSettings, cwd), filetools.CreateToolName)
	if entry.Kind != "tool" {
		t.Errorf("persisted kind = %q, want tool", entry.Kind)
	}
	if entry.GrantKind != "folder" {
		t.Errorf("persisted grant_kind = %q, want folder", entry.GrantKind)
	}
	if entry.PathScope != outside {
		t.Errorf("persisted path_scope = %q, want the real out-of-root folder %q", entry.PathScope, outside)
	}
}

// TestProductionAuthorizer_OutOfRootGlobalGrantPersistsToGlobalSettings is the global counterpart:
// approving "allow globally" for an out-of-root create must write a durable global grant to
// <home>/.codemeld/global/settings.yaml with path_scope "*" — not the folder settings file, not a folder
// path_scope. It reads the real global settings file back and asserts the entry, so a regression in the
// global write target or stored scope fails here.
func TestProductionAuthorizer_OutOfRootGlobalGrantPersistsToGlobalSettings(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(outside): %v", err)
	}
	target := filepath.Join(outside, "new.go")

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{Option: tui.OptionAllowGlobal}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, derr := dispatch.DispatchTool(context.Background(), filetools.CreateToolName,
		map[string]any{"path": target, "content": "x"}, home, cwd, reg, auth); derr != nil {
		t.Fatalf("DispatchTool err = %v, want nil (global-approved out-of-root create)", derr)
	}
	if _, statErr := os.Stat(target); statErr != nil {
		t.Fatalf("global-approved create did not produce a file: %v", statErr)
	}

	for _, path := range []string{projectSettingsPath(cwd), config.LocalSettingsPath(cwd)} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, fs.ErrNotExist) {
			t.Fatalf("%s stat = %v, want absent (a global grant must not write a project-scope file)", path, statErr)
		}
	}
	entry := findGrant(t, readPersistedPermissions(t, SettingsPath(home), cwd), filetools.CreateToolName)
	if entry.Kind != "tool" {
		t.Errorf("persisted kind = %q, want tool", entry.Kind)
	}
	if entry.GrantKind != "global" {
		t.Errorf("persisted grant_kind = %q, want global", entry.GrantKind)
	}
	if entry.PathScope != "*" {
		t.Errorf("persisted path_scope = %q, want \"*\" for a global grant", entry.PathScope)
	}
}

// TestProductionAuthorizer_MovePromptShowsEndpoints drives a real same-directory `move` through
// DispatchTool → the wired productionAuthorizer → the gated prompt (a fake terminal), proving the
// move multi-scope dispatch seam carries its human-readable display through the *real*
// production path: the prompt shows action "Move" over "source -> destination" with no body, the source
// and destination share one resolved scope so the user is prompted once, and on approval the rename
// runs. The matching subject stays "move" in the event log. It fails if dispatch stops building the move
// display, if the authorizer stops carrying Action/Subject/Body, or if a same-directory rename starts
// prompting twice.
func TestProductionAuthorizer_MovePromptShowsEndpoints(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "a.txt"), []byte("body\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	shown := 0
	var gotReq tui.PromptRequest
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		gotReq = req
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewMoveTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, derr := dispatch.DispatchTool(context.Background(), filetools.MoveToolName,
		map[string]any{"source": "a.txt", "destination": "b.txt"}, home, cwd, reg, auth); derr != nil {
		t.Fatalf("DispatchTool: %v", derr)
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times, want 1 (a same-directory rename shares one resolved scope)", shown)
	}
	if gotReq.Action != dispatch.ActionMoveFile {
		t.Errorf("prompt Action = %q, want %q", gotReq.Action, dispatch.ActionMoveFile)
	}
	if gotReq.Subject != "a.txt -> b.txt" {
		t.Errorf("prompt Subject = %q, want the lexical endpoints \"a.txt -> b.txt\"", gotReq.Subject)
	}
	if gotReq.Body != "" {
		t.Errorf("prompt Body = %q, want empty (a move shows no payload)", gotReq.Body)
	}
	// The approved move actually ran: the source is gone and the destination holds its content.
	if _, statErr := os.Stat(filepath.Join(cwd, "a.txt")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("source a.txt stat = %v, want it gone after the approved move", statErr)
	}
	if data, rerr := os.ReadFile(filepath.Join(cwd, "b.txt")); rerr != nil || string(data) != "body\n" {
		t.Errorf("destination b.txt = %q (err %v), want the moved content", string(data), rerr)
	}

	var shownPayload events.PermissionPromptShown
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionPromptShown).Payload, &shownPayload); err != nil {
		t.Fatalf("unmarshal permission_prompt_shown: %v", err)
	}
	if shownPayload.Subject != filetools.MoveToolName || shownPayload.SubjectKind != "tool" {
		t.Errorf("permission_prompt_shown = %#v, want tool/move (matching subject preserved in the event log)", shownPayload)
	}
}

// TestProductionAuthorizer_MoveOutOfRootEndpointPromptCarriesFolderSignal pins the production out-of-root
// carry-through for a move with an in-project source and an out-of-project destination (reached through an
// in-project symlink). It drives the real move tool through DispatchTool → the wired productionAuthorizer
// → the gated prompt: the in-root source scope is authorized first with no out-of-root signal, then the
// out-of-root destination scope prompts with OutOfRootFileWrite set and the folder option offered anchored
// on the real out-of-root folder. With that endpoint denied, DispatchTool returns a
// *DeniedError and nothing is moved — the all-authorize-before-invoke cutoff holds end to end. It fails if
// the authorizer stops carrying the per-endpoint out-of-root signal or if a denied endpoint lets the move
// run.
func TestProductionAuthorizer_MoveOutOfRootEndpointPromptCarriesFolderSignal(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(outside): %v", err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "a.txt"), []byte("body\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(cwd, "escape")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	// Grant the in-root source scope; deny the out-of-root destination scope. Capture every prompt so the
	// per-endpoint signals can be asserted.
	var reqs []tui.PromptRequest
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		reqs = append(reqs, req)
		if req.OutOfRootFileWrite {
			return tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope("")}, nil
		}
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewMoveTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, derr := dispatch.DispatchTool(context.Background(), filetools.MoveToolName,
		map[string]any{"source": "a.txt", "destination": "escape/b.txt"}, home, cwd, reg, auth)
	var de *dispatch.DeniedError
	if !errors.As(derr, &de) {
		t.Fatalf("DispatchTool err = %v, want a *dispatch.DeniedError (the out-of-root destination is denied)", derr)
	}
	if len(reqs) != 2 {
		t.Fatalf("prompts shown = %d, want 2 (an in-root source scope and a distinct out-of-root destination scope)", len(reqs))
	}
	// Source first, in-root: no out-of-root signal.
	if reqs[0].OutOfRootFileWrite {
		t.Errorf("source prompt OutOfRootFileWrite = true, want false (the source is in-project)")
	}
	// Destination second, out-of-root: signal set, folder option offered on the real out-of-root folder.
	dst := reqs[1]
	if !dst.OutOfRootFileWrite {
		t.Errorf("destination prompt OutOfRootFileWrite = false, want true (the destination is out-of-project)")
	}
	if dst.RunFolder != outside {
		t.Errorf("destination prompt RunFolder = %q, want the real out-of-root folder %q", dst.RunFolder, outside)
	}
	if tui.OmitFolderOption(dst.RunFolder, dst.ProjectRoot, dst.OutOfRootFileWrite, dst.ProjectUntrusted).Hidden() {
		t.Errorf("folder option omitted for the out-of-root destination; want it offered (adr-017 option A)")
	}
	// Nothing moved: the source remains and no file was written into the escape folder.
	if _, statErr := os.Stat(filepath.Join(cwd, "a.txt")); statErr != nil {
		t.Errorf("source a.txt stat = %v, want it still present (the denied move must not run)", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "b.txt")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("destination file stat = %v, want it absent (denied, so no file is written into the escape folder)", statErr)
	}
}

// TestProductionAuthorizer_ConcurrentAuthorizationsSerializeAtGate fires N authorizations through one
// shared productionAuthorizer concurrently and proves: (1) only one permission prompt is ever on
// screen at a time — the shared prompt gate serializes them — and (2) every distinct session
// grant lands in the shared grant table with no lost or corrupted append, exercised under -race so a
// concurrent map/slice access through the syncGrants wrapper would fail.
func TestProductionAuthorizer_ConcurrentAuthorizationsSerializeAtGate(t *testing.T) {
	const n = 6
	cwd := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := emptyCache(t, cwd)

	var (
		mu        sync.Mutex
		active    int
		maxActive int
	)
	entered := make(chan struct{})
	proceed := make(chan struct{})
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		entered <- struct{}{}
		<-proceed
		mu.Lock()
		active--
		mu.Unlock()
		return tui.PromptDecision{Option: tui.OptionAllowSession}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(show), t.TempDir(), cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Distinct subjects so none matches a prior grant; each must prompt and serialize.
			req := permissions.MatchRequest{Kind: "tool", Subject: fmt.Sprintf("tool%d", i), PathScope: cwd}
			_, _ = auth.Authorize(context.Background(), req, dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: fmt.Sprintf("tool%d", i)}, permissions.ModeContext{})
		}()
	}

	// Release prompts one at a time, asserting exactly one is ever active.
	for i := 0; i < n; i++ {
		<-entered
		mu.Lock()
		got := active
		mu.Unlock()
		if got != 1 {
			t.Fatalf("prompt %d: %d concurrent prompts on screen, want exactly 1 (the gate must serialize)", i, got)
		}
		proceed <- struct{}{}
	}
	wg.Wait()

	if maxActive != 1 {
		t.Fatalf("peak concurrent prompts = %d, want 1", maxActive)
	}
	// Every authorization appended its own session grant through the mutex-guarded table.
	if got := len(cache.Permissions()); got != n {
		t.Fatalf("grant table holds %d entries, want %d (each concurrent authorization appended one session grant)", got, n)
	}
}

// waitForPromptShown blocks until store holds at least n permission_prompt_shown events or timeout
// elapses, polling the mutex-guarded record stream (safe alongside the concurrent emitters). It is
// the same-key concurrency test's synchronization point: a second permission_prompt_shown is the
// observable proof that a second authorization reached the prompt path past the grant/cache check.
func waitForPromptShown(store *sessions.Store, n int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for {
		count := 0
		for _, k := range permissionEventKinds(store) {
			if k == events.KindPermissionPromptShown {
				count++
			}
		}
		if count >= n || time.Now().After(deadline) {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// TestProductionAuthorizer_ConcurrentIdenticalRequestsPromptOnce drives two concurrent authorizations
// of the *exact same* permissions.MatchRequest through one shared productionAuthorizer. The first is
// held at the prompt while the second races in; without the in-flight serialization the second misses
// the grant/cache (neither recorded yet) and queues a duplicate prompt for the now-authorized subject.
// The fix parks the second on the per-identity in-flight lock until the first records its session
// grant, so the second resolves by matching that grant — exactly one prompt is shown and exactly one
// grant is recorded (safe shared grant-table/cache behavior across workers).
func TestProductionAuthorizer_ConcurrentIdenticalRequestsPromptOnce(t *testing.T) {
	cwd := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := emptyCache(t, cwd)

	var shownMu sync.Mutex
	shown := 0
	entered := make(chan struct{}, 2)
	proceed := make(chan struct{})
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shownMu.Lock()
		shown++
		shownMu.Unlock()
		entered <- struct{}{}
		<-proceed
		return tui.PromptDecision{Option: tui.OptionAllowSession}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(show), t.TempDir(), cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	req := permissions.MatchRequest{Kind: "tool", Subject: "read_file", PathScope: cwd}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = auth.Authorize(context.Background(), req, dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: "read_file"}, permissions.ModeContext{})
	}()
	<-entered // first authorization is at the prompt, holding the gate and the in-flight lock.

	go func() {
		defer wg.Done()
		_, _ = auth.Authorize(context.Background(), req, dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: "read_file"}, permissions.ModeContext{})
	}()

	// Without the fix the second authorization passes the grant/cache check and emits its own
	// permission_prompt_shown just before blocking on the gate; we release the first only once that
	// second event appears so the duplicate prompt is provably reached. With the fix the second parks
	// on the in-flight lock before any lookup, so no second permission_prompt_shown is ever emitted and
	// this wait times out — which is the expected pass path.
	waitForPromptShown(store, 2, time.Second)

	close(proceed) // first prompt grants a session permission and records it.
	wg.Wait()

	shownMu.Lock()
	got := shown
	shownMu.Unlock()
	if got != 1 {
		t.Fatalf("prompt shown %d times for two concurrent identical requests, want exactly 1 (the second must resolve from the first's recorded grant, not re-prompt)", got)
	}
	if n := len(cache.Permissions()); n != 1 {
		t.Fatalf("grant table holds %d entries, want 1 (the duplicate request must not record a second grant)", n)
	}
}

// TestProductionAuthorizer_ConcurrentIdenticalBatchesPromptOnce is the batched-path analogue of the
// identical-request test above: two concurrent AuthorizeBatch calls for the *same* pipeline stage race
// through one shared productionAuthorizer. The batched path binds no per-stage prompt of its own — it
// resolves each stage without prompting first — so without acquireBatchInflight the second batch misses
// the grant and cache (neither recorded yet) and queues a duplicate command-level prompt behind the
// first. Holding the stage's in-flight lock across permissions.AuthorizeBatch parks the second batch
// until the first records its session grant, so the second resolves by matching it: exactly one prompt
// is shown and exactly one grant is recorded. It fails if the batch in-flight acquisition is removed or
// moved to after resolution begins.
func TestProductionAuthorizer_ConcurrentIdenticalBatchesPromptOnce(t *testing.T) {
	cwd := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := emptyCache(t, cwd)

	var shownMu sync.Mutex
	shown := 0
	entered := make(chan struct{}, 2)
	proceed := make(chan struct{})
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shownMu.Lock()
		shown++
		shownMu.Unlock()
		entered <- struct{}{}
		<-proceed
		return tui.PromptDecision{Option: tui.OptionAllowSession}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(show), t.TempDir(), cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reqs := []dispatch.BatchAuthRequest{{
		Req:     permissions.MatchRequest{Kind: "direct", Subject: "rm", SubjectTokens: []string{"rm"}, PathScope: cwd},
		Display: dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: "rm"},
	}}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = auth.AuthorizeBatch(context.Background(), reqs)
	}()
	<-entered // first batch is at the command-level prompt, holding the gate and the stage in-flight lock.

	go func() {
		defer wg.Done()
		_, _ = auth.AuthorizeBatch(context.Background(), reqs)
	}()

	// Without the fix the second batch resolves past the grant/cache miss and emits its own
	// permission_prompt_shown before blocking on the gate; wait for that second event so a duplicate
	// prompt is provably reached. With the fix the second batch parks on the stage in-flight lock before
	// any resolution, so no second permission_prompt_shown is emitted and this wait times out (the pass
	// path).
	waitForPromptShown(store, 2, time.Second)

	close(proceed) // first batch grants a session permission for the stage and records it.
	wg.Wait()

	shownMu.Lock()
	got := shown
	shownMu.Unlock()
	if got != 1 {
		t.Fatalf("prompt shown %d times for two concurrent identical batches, want exactly 1 (the second must resolve from the first's recorded grant, not re-prompt)", got)
	}
	if n := len(cache.Permissions()); n != 1 {
		t.Fatalf("grant table holds %d entries, want 1 (the duplicate batch must not record a second grant)", n)
	}
}

// recordingNotices captures the one-line notices RevokeGrant surfaces so a test can assert the
// skip/failure path fired (and the happy path stayed silent) without driving the tview event loop.
type recordingNotices struct {
	mu    sync.Mutex
	texts []string
}

func (r *recordingNotices) Notice(text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.texts = append(r.texts, text)
}

// revokeAuthorizer builds a productionAuthorizer anchored at cwd/home with grants pre-seeded in the
// live in-memory table and a prompt gate that fails if ever reached (a revoke must never prompt). It
// returns the authorizer, the backing cache for assertions, the active session store a recorded
// revocation lands in, and a notice recorder the caller passes to RevokeGrant as its notice sink
// (RevokeGrant renders through the caller-supplied sink, which in production is the event-loop-safe
// *tui.App).
func revokeAuthorizer(t *testing.T, cwd, home string, grants ...permissions.PermissionEntry) (*productionAuthorizer, *config.Cache, *sessions.Store, *recordingNotices) {
	t.Helper()
	cache := emptyCache(t, cwd)
	for _, g := range grants {
		cache.AppendPermission(g)
	}
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{}, errors.New("revoke must not prompt")
	}
	app := tui.New(nil)
	store := mkStore(t)
	app.SetActiveStore(store)
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))
	return auth, cache, store, &recordingNotices{}
}

// revokeEvents returns the permission_revoke_requested payloads the store holds, decoded through the
// real payload type.
func revokeEvents(t *testing.T, store *sessions.Store) []events.PermissionRevokeRequested {
	t.Helper()
	var out []events.PermissionRevokeRequested
	for _, rec := range store.Records() {
		ev, ok := rec.(sessions.Event)
		if !ok || ev.Kind != events.KindPermissionRevokeRequested {
			continue
		}
		var p events.PermissionRevokeRequested
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("decode permission_revoke_requested: %v", err)
		}
		out = append(out, p)
	}
	return out
}

// wantRevokeEvent is the payload a revoke of entry must record: the stored grant's own identity
// under the closed /permissions source.
func wantRevokeEvent(entry permissions.PermissionEntry) events.PermissionRevokeRequested {
	return events.PermissionRevokeRequested{
		EntryKind: entry.Kind, Subject: entry.Subject, PathScope: entry.PathScope, HostScope: entry.HostScope,
		GrantKind: entry.GrantKind, ArgumentHash: entry.ArgumentHash, Source: events.RevokeSourcePermissionsUI,
	}
}

// assertOneRevokeEvent pins that exactly one revocation was recorded and that it names entry.
func assertOneRevokeEvent(t *testing.T, store *sessions.Store, entry permissions.PermissionEntry) {
	t.Helper()
	got := revokeEvents(t, store)
	if len(got) != 1 {
		t.Fatalf("permission_revoke_requested events = %d, want exactly 1", len(got))
	}
	if want := wantRevokeEvent(entry); got[0] != want {
		t.Fatalf("recorded revocation = %+v, want the removed grant's identity %+v", got[0], want)
	}
}

// assertNoRevokeEvent pins the paths that revoked nothing: they must leave no evidence that a grant
// was removed.
func assertNoRevokeEvent(t *testing.T, store *sessions.Store) {
	t.Helper()
	if got := revokeEvents(t, store); len(got) != 0 {
		t.Fatalf("permission_revoke_requested events = %d (%+v), want 0 — nothing was revoked", len(got), got)
	}
}

// seedGrantFile writes entry into the settings file at target through the production persist
// chokepoint, so the on-disk format is exactly what a revoke reads back and deletes.
func seedGrantFile(t *testing.T, target string, entry permissions.PermissionEntry) {
	t.Helper()
	if _, _, err := config.Persist(target, config.KeyPermissions, entry); err != nil {
		t.Fatalf("seed grant into %q: %v", target, err)
	}
}

// cacheHasGrant reports whether the live table still holds the grant identified by key.
func cacheHasGrant(c *config.Cache, key permissions.DedupKey) bool {
	for _, e := range c.Permissions() {
		if e.DedupKey() == key {
			return true
		}
	}
	return false
}

func mustNotExist(t *testing.T, path, why string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stat %q = %v, want it absent (%s)", path, err, why)
	}
}

func gatedInteractiveAuthorizer(t *testing.T, home, project string) (*productionAuthorizer, *sessions.Store) {
	t.Helper()
	decision := trust.Lookup(home, project)
	return interactiveAuthorizerFor(t, &BootstrapResult{
		Home: home, LaunchDir: project, ProjectRoot: project,
		TrustDecision: decision,
	})
}

func interactiveAuthorizerFor(t *testing.T, result *BootstrapResult) (*productionAuthorizer, *sessions.Store) {
	t.Helper()
	app := tui.New(nil)
	store := mkStore(t)
	app.SetActiveStore(store)
	return newInteractiveAuthorizer(app, emptyCache(t, result.ProjectRoot), result, mode.NewActiveState(mode.Build, mode.SourceDefault)), store
}

func recordedProject(t *testing.T, home string) string {
	t.Helper()
	project := mustCanonical(t, trustProject(t, "model: {}\n"))
	approveRoot(t, home, project)
	return project
}

func readTrustStoreBytes(t *testing.T, home string) string {
	t.Helper()
	data, err := os.ReadFile(trust.StorePath(home))
	if err != nil {
		t.Fatalf("read trust store: %v", err)
	}
	return string(data)
}

func TestInteractiveAuthorizer_OnlyATrustedProjectTargetRefreshes(t *testing.T) {
	t.Run("global grant", func(t *testing.T) {
		home := t.TempDir()
		project := recordedProject(t, home)
		auth, store := gatedInteractiveAuthorizer(t, home, project)
		before := readTrustStoreBytes(t, home)

		entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: "*", GrantKind: "global"}
		if _, err := auth.persistGrant(store, project)(entry); err != nil {
			t.Fatalf("persistGrant: %v", err)
		}
		if _, err := os.Stat(SettingsPath(home)); err != nil {
			t.Fatalf("global settings not written: %v", err)
		}
		if after := readTrustStoreBytes(t, home); after != before {
			t.Fatalf("a global grant rewrote the trust record:\n got=%q\nwant=%q", after, before)
		}
	})

	t.Run("untrusted decision", func(t *testing.T) {
		home := t.TempDir()
		project := mustCanonical(t, trustProject(t, "model: {}\n"))
		approveRoot(t, home, project)
		auth, store := interactiveAuthorizerFor(t, &BootstrapResult{
			Home: home, LaunchDir: project, ProjectRoot: project,
			TrustDecision: trust.Decision{Reason: trust.ReasonNoRecord, Root: project},
		})
		before := readTrustStoreBytes(t, home)

		entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: project, GrantKind: "folder"}
		if _, err := auth.persistGrant(store, project)(entry); err != nil {
			t.Fatalf("persistGrant: %v", err)
		}
		if after := readTrustStoreBytes(t, home); after != before {
			t.Fatalf("an untrusted run rewrote the trust record:\n got=%q\nwant=%q", after, before)
		}
	})
}

func TestInteractiveAuthorizer_FolderGrantWritesOnlyTheLocalSettingsFile(t *testing.T) {
	home := t.TempDir()
	project := mustCanonical(t, t.TempDir())
	auth, store := gatedInteractiveAuthorizer(t, home, project)

	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: project, GrantKind: "folder"}
	if _, err := auth.persistGrant(store, project)(entry); err != nil {
		t.Fatalf("persistGrant: %v", err)
	}
	if _, err := os.Stat(config.LocalSettingsPath(project)); err != nil {
		t.Fatalf("local settings not created: %v", err)
	}
	mustNotExist(t, projectSettingsPath(project), "a grant write must not create the shared project settings file")
}

func TestInteractiveAuthorizer_ShellPromptsCarryShellSubjectKind(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    tui.SubjectKind
	}{
		{"rm x", tui.SubjectDirectCommand},
		{"echo hi > out.txt", tui.SubjectLiteralCommand},
	} {
		t.Run(tc.command, func(t *testing.T) {
			home := t.TempDir()
			project := mustCanonical(t, t.TempDir())
			auth, _ := interactiveAuthorizerFor(t, &BootstrapResult{Home: home, LaunchDir: project, ProjectRoot: project})
			var kinds []tui.SubjectKind
			auth.prompts = newPromptGateBuilder(func(req tui.PromptRequest) (tui.PromptDecision, error) {
				kinds = append(kinds, req.Kind)
				return tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope("")}, nil
			})
			_, _ = dispatch.DispatchShell(context.Background(), tc.command, home, project, auth, &fakeDispatchRunner{})
			if len(kinds) != 1 || kinds[0] != tc.want {
				t.Fatalf("prompted kinds = %v, want [%s]", kinds, tc.want)
			}
		})
	}
}

// TestProductionAuthorizer_RevokeFolderGrantRemovesFromFolderFile pins the folder arm of the revoke
// seam: a folder grant seeded in <project>/.codemeld/settings.yaml and in the live table is removed
// from both by RevokeGrant, while the global settings file is never touched and no notice fires.
func TestProductionAuthorizer_RevokeFolderGrantRemovesFromFolderFile(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	folderTarget := config.LocalSettingsPath(cwd)
	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: cwd, GrantKind: "folder"}
	key := entry.DedupKey()

	seedGrantFile(t, folderTarget, entry)
	auth, cache, store, notices := revokeAuthorizer(t, cwd, home, entry)
	if present, _ := targetHasGrant(folderTarget, cwd, key); !present {
		t.Fatalf("precondition: folder grant should be on disk before revoke")
	}

	auth.RevokeGrant(entry, notices)

	if present, _ := targetHasGrant(folderTarget, cwd, key); present {
		t.Errorf("folder grant still on disk after revoke, want removed from %q", folderTarget)
	}
	if got := mustReadFile(t, folderTarget); got != "" {
		t.Errorf("folder settings file = %q, want the empty document a revoke of its only grant leaves", got)
	}
	if cacheHasGrant(cache, key) {
		t.Errorf("folder grant still in the live table after revoke, want removed")
	}
	mustNotExist(t, SettingsPath(home), "a folder revoke must not touch the global settings file")
	mustNotExist(t, projectSettingsPath(cwd), "a folder revoke must not touch the shared project settings file")
	if len(notices.texts) != 0 {
		t.Errorf("revoke fired notices %v, want none on the happy path", notices.texts)
	}
	assertOneRevokeEvent(t, store, entry)
}

// TestProductionAuthorizer_RevokeGlobalGrantRemovesFromGlobalFile is the global counterpart: a global
// grant seeded in <home>/.codemeld/global/settings.yaml is removed from disk and memory, the project
// settings file is never touched, and no notice fires.
func TestProductionAuthorizer_RevokeGlobalGrantRemovesFromGlobalFile(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	globalTarget := SettingsPath(home)
	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: "*", GrantKind: "global"}
	key := entry.DedupKey()

	seedGrantFile(t, globalTarget, entry)
	auth, cache, store, notices := revokeAuthorizer(t, cwd, home, entry)
	if present, _ := targetHasGrant(globalTarget, cwd, key); !present {
		t.Fatalf("precondition: global grant should be on disk before revoke")
	}

	auth.RevokeGrant(entry, notices)

	if present, _ := targetHasGrant(globalTarget, cwd, key); present {
		t.Errorf("global grant still on disk after revoke, want removed from %q", globalTarget)
	}
	if got := mustReadFile(t, globalTarget); got != "" {
		t.Errorf("global settings file = %q, want the empty document a revoke of its only grant leaves", got)
	}
	if cacheHasGrant(cache, key) {
		t.Errorf("global grant still in the live table after revoke, want removed")
	}
	mustNotExist(t, filepath.Join(cwd, ".codemeld", "settings.yaml"), "a global revoke must not touch the project settings file")
	if len(notices.texts) != 0 {
		t.Errorf("revoke fired notices %v, want none on the happy path", notices.texts)
	}
	assertOneRevokeEvent(t, store, entry)
}

// TestProductionAuthorizer_RevokeSessionGrantMemoryOnly pins the session arm: a session grant lives
// only in memory, so RevokeGrant drops it from the table and writes no settings file at all — while
// still recording the revocation, which is the only durable trace such a revoke can leave.
func TestProductionAuthorizer_RevokeSessionGrantMemoryOnly(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: cwd, GrantKind: "session"}
	key := entry.DedupKey()

	auth, cache, store, notices := revokeAuthorizer(t, cwd, home, entry)
	if !cacheHasGrant(cache, key) {
		t.Fatalf("precondition: session grant should be in the live table before revoke")
	}

	auth.RevokeGrant(entry, notices)

	if cacheHasGrant(cache, key) {
		t.Errorf("session grant still in the live table after revoke, want removed")
	}
	mustNotExist(t, filepath.Join(cwd, ".codemeld", "settings.yaml"), "a session revoke must not write the project settings file")
	mustNotExist(t, SettingsPath(home), "a session revoke must not write the global settings file")
	if len(notices.texts) != 0 {
		t.Errorf("revoke fired notices %v, want none for a session-only removal", notices.texts)
	}
	assertOneRevokeEvent(t, store, entry)
}

// TestProductionAuthorizer_RevokeSessionGrantDuplicateRequestRecordsOnce pins the true-removal gate:
// the second revoke of the same session grant removes nothing, so it must record nothing. Without
// the gate a repeated request would manufacture a second revocation of a grant that was already gone.
func TestProductionAuthorizer_RevokeSessionGrantDuplicateRequestRecordsOnce(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: cwd, GrantKind: "session"}
	other := permissions.PermissionEntry{Kind: "tool", Subject: "list_dir", PathScope: cwd, GrantKind: "session"}

	auth, cache, store, notices := revokeAuthorizer(t, cwd, home, entry, other)

	auth.RevokeGrant(entry, notices)
	auth.RevokeGrant(entry, notices)

	assertOneRevokeEvent(t, store, entry)
	if !cacheHasGrant(cache, other.DedupKey()) {
		t.Errorf("the unrelated session grant was dropped, want only the revoked identity removed")
	}
	if len(notices.texts) != 0 {
		t.Errorf("revoke fired notices %v, want none — a duplicate request is silent", notices.texts)
	}
}

// TestProductionAuthorizer_RevokeStaleSessionGrantRecordsNothing pins the other half of that gate: a
// grant the live table never held is a stale request, so it removes nothing and records nothing.
func TestProductionAuthorizer_RevokeStaleSessionGrantRecordsNothing(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	held := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: cwd, GrantKind: "session"}
	stale := permissions.PermissionEntry{Kind: "tool", Subject: "delete_file", PathScope: cwd, GrantKind: "session"}

	auth, cache, store, notices := revokeAuthorizer(t, cwd, home, held)

	auth.RevokeGrant(stale, notices)

	assertNoRevokeEvent(t, store)
	if !cacheHasGrant(cache, held.DedupKey()) {
		t.Errorf("a stale revoke dropped an unrelated live grant, want the table untouched")
	}
	if len(notices.texts) != 0 {
		t.Errorf("revoke fired notices %v, want none for a stale request", notices.texts)
	}
}

// TestProductionAuthorizer_RevokeLiteralGrantRecordsItsArgumentHash pins the literal identity form
// through the production seam: the recorded hash is the stored grant's own, so a reader can match
// the revocation to the exact pinned command rather than to any subject that merely looks like it.
func TestProductionAuthorizer_RevokeLiteralGrantRecordsItsArgumentHash(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	folderTarget := config.LocalSettingsPath(cwd)
	// A subject already in canonical literal form, so the entry read back from the settings file
	// keeps the identity the event has to name.
	subject := "git status"
	entry := permissions.PermissionEntry{
		Kind: "literal", Subject: subject, PathScope: cwd, GrantKind: "folder",
		ArgumentHash: permissions.ComputeArgumentHash(subject),
	}

	seedGrantFile(t, folderTarget, entry)
	auth, _, store, notices := revokeAuthorizer(t, cwd, home, entry)
	if present, _ := targetHasGrant(folderTarget, cwd, entry.DedupKey()); !present {
		t.Fatalf("precondition: literal grant should be on disk before revoke")
	}

	auth.RevokeGrant(entry, notices)

	assertOneRevokeEvent(t, store, entry)
	if len(notices.texts) != 0 {
		t.Errorf("revoke fired notices %v, want none on the happy path", notices.texts)
	}
}

// TestProductionAuthorizer_RevokeRecordingFailureKeepsTheGrantRemoved pins the ordering the task
// accepts: the settings delete and the live removal have already happened when recording is
// attempted, so a rejected append leaves the grant gone, queues no event, and reports the failure as
// a recording failure — never as a revoke failure, which would wrongly imply the grant survived.
func TestProductionAuthorizer_RevokeRecordingFailureKeepsTheGrantRemoved(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	folderTarget := config.LocalSettingsPath(cwd)
	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: cwd, GrantKind: "folder"}

	seedGrantFile(t, folderTarget, entry)
	auth, cache, store, notices := revokeAuthorizer(t, cwd, home, entry)
	// No active session to append to: events.Append rejects before queueing, the same shape a
	// payload rejection takes, so the revoke's recording fails while the deletion has already landed.
	auth.activeStore = func() *sessions.Store { return nil }

	auth.RevokeGrant(entry, notices)

	if present, _ := targetHasGrant(folderTarget, cwd, entry.DedupKey()); present {
		t.Errorf("grant still on disk after a failed recording, want the settings delete kept")
	}
	if cacheHasGrant(cache, entry.DedupKey()) {
		t.Errorf("revoked grant is still authorizing after a failed recording, want it removed")
	}
	assertNoRevokeEvent(t, store)
	// The prefix is the assertion: "revoke failed" would tell the user the grant survived, which it
	// did not.
	if len(notices.texts) != 1 || !strings.HasPrefix(notices.texts[0], "revoke not recorded — ") {
		t.Fatalf("revoke notices = %v, want exactly one recording-failure notice", notices.texts)
	}
}

// TestProductionAuthorizer_RevokeNonWriteFlushFailureKeepsOneQueuedEvent pins the other flush arm: a
// failure the write-failure protocol does not own is returned to the caller, so the revoke reports it
// once and leaves the single appended record queued in memory. Nothing is rolled back and nothing is
// re-appended, so a later successful flush carries that same one event.
func TestProductionAuthorizer_RevokeNonWriteFlushFailureKeepsOneQueuedEvent(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: cwd, GrantKind: "session"}

	auth, cache, store, notices := revokeAuthorizer(t, cwd, home, entry)
	auth.flush = func() error { return errors.New("context canceled") }

	auth.RevokeGrant(entry, notices)

	if cacheHasGrant(cache, entry.DedupKey()) {
		t.Errorf("revoked grant is still authorizing after a flush failure, want it removed")
	}
	assertOneRevokeEvent(t, store, entry)
	if len(notices.texts) != 1 || !strings.HasPrefix(notices.texts[0], "revoke not recorded — ") {
		t.Fatalf("revoke notices = %v, want exactly one recording-failure notice", notices.texts)
	}

	// The queued record is what a later independently successful flush would carry: one event, no
	// duplicate written by the failure path.
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("later flush: %v", err)
	}
	assertOneRevokeEvent(t, store, entry)
}

// TestProductionAuthorizer_RevokeAbsentOnTargetSkips pins the composed-only/wrong-layer guard: a grant
// that matches in memory but is absent from its writable target file is reported and skipped — the
// live grant is left intact and no file is created (DeleteGrant would silently no-op there, which
// would otherwise drop a grant still set in another layer).
func TestProductionAuthorizer_RevokeAbsentOnTargetSkips(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	folderTarget := config.LocalSettingsPath(cwd)
	// In the live table only; the project settings file is never seeded.
	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: cwd, GrantKind: "folder"}
	key := entry.DedupKey()

	auth, cache, store, notices := revokeAuthorizer(t, cwd, home, entry)

	auth.RevokeGrant(entry, notices)

	if !cacheHasGrant(cache, key) {
		t.Errorf("live grant was dropped on an absent-on-target revoke, want it kept until removed at its source")
	}
	mustNotExist(t, folderTarget, "an absent-on-target revoke must not create the settings file")
	if want := tui.RenderRevokeSkipNotice(folderTarget, tui.PermissionRow{}); len(notices.texts) != 1 || notices.texts[0] != want {
		t.Errorf("revoke notices = %v, want exactly [%q]", notices.texts, want)
	}
	assertNoRevokeEvent(t, store)
}

// TestProductionAuthorizer_RevokePersistFailureKeepsGrant pins the non-writable arm: the grant is
// present on disk (so the preflight passes) but the settings write fails, so RevokeGrant reports a
// failure notice and leaves the live grant in place, keeping memory and disk consistent.
func TestProductionAuthorizer_RevokePersistFailureKeepsGrant(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions, so the write cannot be forced to fail")
	}
	cwd := t.TempDir()
	home := t.TempDir()
	folderDir := filepath.Join(cwd, ".codemeld")
	folderTarget := filepath.Join(folderDir, "settings.local.yaml")
	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: cwd, GrantKind: "folder"}
	key := entry.DedupKey()

	seedGrantFile(t, folderTarget, entry)
	// Make the settings directory read-only so the atomic temp-write/rename inside DeleteGrant fails,
	// while the preflight read of the existing file still succeeds. Restore perms so TempDir cleanup works.
	if err := os.Chmod(folderDir, 0o500); err != nil {
		t.Fatalf("chmod settings dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(folderDir, 0o700) })

	auth, cache, store, notices := revokeAuthorizer(t, cwd, home, entry)

	auth.RevokeGrant(entry, notices)

	if !cacheHasGrant(cache, key) {
		t.Errorf("live grant was dropped after a failed settings write, want it kept (memory must follow disk)")
	}
	if len(notices.texts) != 1 || !strings.HasPrefix(notices.texts[0], "revoke failed — ") {
		t.Errorf("revoke notices = %v, want exactly one revoke-failed notice", notices.texts)
	}
	assertNoRevokeEvent(t, store)
}

// TestProductionAuthorizer_RevokeUninspectableTargetKeepsGrant pins the inspect-failure arm: the
// selected settings file exists but is malformed YAML, so the preflight cannot tell whether it holds
// the grant. RevokeGrant must report a revoke failure (not a composed-layer skip) and keep the live
// grant, so a grant that may still be on disk is not silently dropped from memory.
func TestProductionAuthorizer_RevokeUninspectableTargetKeepsGrant(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	folderDir := filepath.Join(cwd, ".codemeld")
	folderTarget := filepath.Join(folderDir, "settings.local.yaml")
	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: cwd, GrantKind: "folder"}
	key := entry.DedupKey()

	if err := os.MkdirAll(folderDir, 0o700); err != nil {
		t.Fatalf("mkdir settings dir: %v", err)
	}
	// Malformed YAML: LoadYAML fails to parse, so the target cannot be inspected. This must be
	// distinguished from an absent file (which is a legitimate composed-only skip).
	if err := os.WriteFile(folderTarget, []byte("permissions: ["), 0o600); err != nil {
		t.Fatalf("write malformed settings file: %v", err)
	}

	auth, cache, store, notices := revokeAuthorizer(t, cwd, home, entry)

	auth.RevokeGrant(entry, notices)

	if !cacheHasGrant(cache, key) {
		t.Errorf("live grant was dropped when its target could not be inspected, want it kept")
	}
	skip := tui.RenderRevokeSkipNotice(folderTarget, tui.PermissionRow{})
	if len(notices.texts) != 1 || !strings.HasPrefix(notices.texts[0], "revoke failed — ") || notices.texts[0] == skip {
		t.Errorf("revoke notices = %v, want exactly one revoke-failed notice (not the composed-layer skip)", notices.texts)
	}
	assertNoRevokeEvent(t, store)
}

func projectHostGrant(subject, host string) permissions.PermissionEntry {
	return permissions.PermissionEntry{Kind: "tool", Subject: subject, HostScope: host, GrantKind: "project"}
}

func TestProductionAuthorizer_ProjectHostGrantPersistsToProjectSettings(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{}, errors.New("persisting a grant must not prompt")
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	entry := projectHostGrant("web_fetch", "docs.example.com")
	got, err := auth.persistGrant(store, "")(entry)
	if err != nil {
		t.Fatalf("persistGrant project host: %v", err)
	}
	if got != entry {
		t.Fatalf("effective entry = %+v, want the approved grant %+v unchanged on a clean persist", got, entry)
	}

	projectTarget := config.LocalSettingsPath(cwd)
	if persisted := findGrant(t, readPersistedPermissions(t, projectTarget, cwd), "web_fetch"); persisted != entry {
		t.Errorf("entry read back from %q = %+v, want %+v", projectTarget, persisted, entry)
	}
	mustNotExist(t, SettingsPath(home), "a project host grant must never be written to the global settings file")
	if n := countPermissionEvents(store, events.KindPermissionPersistFailed); n != 0 {
		t.Errorf("permission_persist_failed events = %d, want 0 on a clean persist", n)
	}
}

func TestProductionAuthorizer_ProjectHostGrantFailureDegradesToSessionHost(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	if err := os.WriteFile(filepath.Join(cwd, ".codemeld"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed project settings parent as a file: %v", err)
	}
	projectTarget := config.LocalSettingsPath(cwd)

	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{}, errors.New("persisting a grant must not prompt")
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	entry := projectHostGrant("web_search", "mcp.exa.ai")
	got, err := auth.persistGrant(store, "")(entry)
	if err == nil {
		t.Fatalf("persistGrant error = nil, want the surfaced project host persist failure")
	}
	want := permissions.PermissionEntry{Kind: "tool", Subject: "web_search", HostScope: "mcp.exa.ai", GrantKind: "session"}
	if got != want {
		t.Fatalf("degraded entry = %+v, want %+v (same tool and host, session lifetime)", got, want)
	}

	var p events.PermissionPersistFailed
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionPersistFailed).Payload, &p); err != nil {
		t.Fatalf("unmarshal permission_persist_failed: %v", err)
	}
	if p.SubjectKind != "host" || p.GrantKind != "project" || p.HostScope != "mcp.exa.ai" {
		t.Errorf("event subject_kind/grant_kind/host_scope = %q/%q/%q, want host/project/mcp.exa.ai", p.SubjectKind, p.GrantKind, p.HostScope)
	}
	if p.DegradedToPathScope != "" {
		t.Errorf("event degraded_to_path_scope = %q, want absent for a host grant", p.DegradedToPathScope)
	}
	if p.TargetPath != projectTarget {
		t.Errorf("event target_path = %q, want the project settings file %q", p.TargetPath, projectTarget)
	}
	if n := countPermissionEvents(store, events.KindPermissionPersistFailed); n != 1 {
		t.Errorf("permission_persist_failed events = %d, want exactly 1 (the write is never retried)", n)
	}
	mustNotExist(t, SettingsPath(home), "a failed project host persist must not fall back to the global settings file")
}

func TestProductionAuthorizer_RevokeProjectHostGrantRemovesOnlyExactEntry(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	projectTarget := config.LocalSettingsPath(cwd)

	target := projectHostGrant("web_fetch", "docs.example.com")
	survivors := []permissions.PermissionEntry{
		projectHostGrant("web_fetch", "api.example.com"),
		projectHostGrant("web_search", "docs.example.com"),
		{Kind: "tool", Subject: "read_file", PathScope: cwd, GrantKind: "folder"},
	}
	for _, e := range append([]permissions.PermissionEntry{target}, survivors...) {
		seedGrantFile(t, projectTarget, e)
	}
	auth, cache, store, notices := revokeAuthorizer(t, cwd, home, append([]permissions.PermissionEntry{target}, survivors...)...)
	if present, _ := targetHasGrant(projectTarget, cwd, target.DedupKey()); !present {
		t.Fatalf("precondition: project host grant should be on disk before revoke")
	}

	auth.RevokeGrant(target, notices)

	if present, _ := targetHasGrant(projectTarget, cwd, target.DedupKey()); present {
		t.Errorf("project host grant still on disk after revoke, want removed from %q", projectTarget)
	}
	if cacheHasGrant(cache, target.DedupKey()) {
		t.Errorf("project host grant still in the live table after revoke, want removed")
	}
	for _, e := range survivors {
		if present, _ := targetHasGrant(projectTarget, cwd, e.DedupKey()); !present {
			t.Errorf("%+v was removed from %q, want only the exact revoked host entry deleted", e, projectTarget)
		}
		if !cacheHasGrant(cache, e.DedupKey()) {
			t.Errorf("%+v was dropped from the live table, want only the exact revoked host entry removed", e)
		}
	}
	mustNotExist(t, SettingsPath(home), "a project host revoke must not touch the global settings file")
	if len(notices.texts) != 0 {
		t.Errorf("revoke fired notices %v, want none on the happy path", notices.texts)
	}
	assertOneRevokeEvent(t, store, target)
}

func TestProductionAuthorizer_RevokeProjectHostAbsentOnTargetSkips(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	projectTarget := config.LocalSettingsPath(cwd)
	entry := projectHostGrant("web_fetch", "docs.example.com")

	auth, cache, store, notices := revokeAuthorizer(t, cwd, home, entry)

	auth.RevokeGrant(entry, notices)

	if !cacheHasGrant(cache, entry.DedupKey()) {
		t.Errorf("live host grant was dropped on an absent-on-target revoke, want it kept until removed at its source")
	}
	mustNotExist(t, projectTarget, "an absent-on-target host revoke must not create the project settings file")
	if want := tui.RenderRevokeSkipNotice(projectTarget, tui.PermissionRow{}); len(notices.texts) != 1 || notices.texts[0] != want {
		t.Errorf("revoke notices = %v, want exactly [%q]", notices.texts, want)
	}
	assertNoRevokeEvent(t, store)
}

func TestProductionAuthorizer_RevokeProjectHostUninspectableTargetKeepsGrant(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	projectDir := filepath.Join(cwd, ".codemeld")
	projectTarget := filepath.Join(projectDir, "settings.local.yaml")
	entry := projectHostGrant("web_fetch", "docs.example.com")

	if err := os.MkdirAll(projectDir, 0o700); err != nil {
		t.Fatalf("mkdir settings dir: %v", err)
	}
	if err := os.WriteFile(projectTarget, []byte("permissions: ["), 0o600); err != nil {
		t.Fatalf("write malformed settings file: %v", err)
	}

	auth, cache, store, notices := revokeAuthorizer(t, cwd, home, entry)

	auth.RevokeGrant(entry, notices)

	if !cacheHasGrant(cache, entry.DedupKey()) {
		t.Errorf("live host grant was dropped when its target could not be inspected, want it kept")
	}
	skip := tui.RenderRevokeSkipNotice(projectTarget, tui.PermissionRow{})
	if len(notices.texts) != 1 || !strings.HasPrefix(notices.texts[0], "revoke failed — ") || notices.texts[0] == skip {
		t.Errorf("revoke notices = %v, want exactly one revoke-failed notice (not the composed-layer skip)", notices.texts)
	}
	assertNoRevokeEvent(t, store)
}

// TestNewTurnController_HoldsAuthorizer confirms StartTUI's turn-wiring seam stores the production
// authorizer on the controller, where the tool-call loop consumes it.
func TestNewTurnController_HoldsAuthorizer(t *testing.T) {
	app := tui.New(nil)
	app.SetActiveStore(mkStore(t))
	cwd := t.TempDir()
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}), t.TempDir(), cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	var sink dispatch.Authorizer = auth
	ctl := newTurnController(context.Background(), &recordingSurface{}, emptyCache(t, cwd), turnSelection("openai", "gpt-5.5", "default"), nil, sink)
	if ctl.authorizer != sink {
		t.Fatalf("turnController.authorizer = %v, want the authorizer StartTUI handed it", ctl.authorizer)
	}
}

func TestProductionAuthorizer_ModeSwitchImmediatelyChangesSingleAndBatchAuthorization(t *testing.T) {
	t.Run("single path reads the post-switch mode", func(t *testing.T) {
		cwd, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		home := t.TempDir()
		containing := filepath.Join(cwd, "sub")
		if err := os.MkdirAll(containing, 0o755); err != nil {
			t.Fatalf("mkdir containing: %v", err)
		}
		target := filepath.Join(containing, "new.go")

		store := mkStore(t)
		app := tui.New(nil)
		app.SetActiveStore(store)

		shown := 0
		show := func(tui.PromptRequest) (tui.PromptDecision, error) {
			shown++
			return tui.PromptDecision{}, errors.New("must not prompt: Auto edits auto-approves the in-project create")
		}
		modeActive := mode.NewActiveState(mode.Build, mode.SourceDefault)
		auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, modeActive)

		modeActive.ApplyUserCommand(mode.AutoEdits)

		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, cwd, cwd)); err != nil {
			t.Fatalf("Register: %v", err)
		}
		if _, err := dispatch.DispatchTool(context.Background(), filetools.CreateToolName,
			map[string]any{"path": target, "content": "package main\n"}, home, cwd, reg, auth); err != nil {
			t.Fatalf("DispatchTool: %v", err)
		}
		if shown != 0 {
			t.Fatalf("prompt shown %d times, want 0 (the post-switch Auto edits mode must auto-approve the in-project create)", shown)
		}
		if _, statErr := os.Stat(target); statErr != nil {
			t.Fatalf("create did not produce a file: %v", statErr)
		}
		if kinds := permissionEventKinds(store); !slices.Equal(kinds, []string{events.KindPermissionMatched}) {
			t.Fatalf("permission event stream = %v, want exactly [permission_matched] (mode-auto: no prompt_shown, no decision)", kinds)
		}
		var matched events.PermissionMatched
		if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionMatched).Payload, &matched); err != nil {
			t.Fatalf("unmarshal permission_matched: %v", err)
		}
		want := events.PermissionMatched{
			SubjectKind:   "tool",
			Subject:       filetools.CreateToolName,
			PathScope:     containing,
			Outcome:       "once",
			OutcomeSource: "mode_auto",
		}
		if matched != want {
			t.Fatalf("permission_matched = %#v, want %#v (the switch to Auto edits took effect for this single check)", matched, want)
		}
	})

	t.Run("batch path reads the post-switch mode", func(t *testing.T) {
		cwd := t.TempDir()
		home := t.TempDir()
		store := mkStore(t)
		app := tui.New(nil)
		app.SetActiveStore(store)

		shown := 0
		show := func(tui.PromptRequest) (tui.PromptDecision, error) {
			shown++
			return tui.PromptDecision{}, errors.New("must not prompt: Plan denies the mutating stage without prompting")
		}
		modeActive := mode.NewActiveState(mode.Build, mode.SourceDefault)
		auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, modeActive)

		modeActive.ApplyUserCommand(mode.Plan)

		run := &fakeDispatchRunner{}
		_, err := dispatch.DispatchShell(context.Background(), "echo hi | tee out.txt", home, cwd, auth, run)
		var denied *dispatch.DeniedError
		if !errors.As(err, &denied) {
			t.Fatalf("DispatchShell err = %v, want a *dispatch.DeniedError (Plan denies the mutating pipeline stage)", err)
		}
		if shown != 0 {
			t.Fatalf("prompt shown %d times, want 0 (the post-switch Plan mode denies the mutating stage without prompting)", shown)
		}
		if run.callCount() != 0 {
			t.Fatalf("runner Exec calls = %d, want 0 (a Plan-denied pipeline must not execute any stage)", run.callCount())
		}
		var sawModeDeny bool
		for _, rec := range store.Records() {
			ev, ok := rec.(sessions.Event)
			if !ok || ev.Kind != events.KindPermissionMatched {
				continue
			}
			var m events.PermissionMatched
			if err := json.Unmarshal(ev.Payload, &m); err != nil {
				t.Fatalf("unmarshal permission_matched: %v", err)
			}
			if m.OutcomeSource == "mode_auto" && m.Outcome == "deny" && m.SubjectKind == "direct" {
				sawModeDeny = true
			}
		}
		if !sawModeDeny {
			t.Fatal("no mode_auto/deny permission_matched on a direct stage; the batch seam did not consume the post-switch Plan mode")
		}
	})

	t.Run("single path reads the mode after setup", func(t *testing.T) {
		cwd := t.TempDir()
		home := t.TempDir()
		store := mkStore(t)
		app := tui.New(nil)
		app.SetActiveStore(store)

		shown := 0
		show := func(tui.PromptRequest) (tui.PromptDecision, error) {
			shown++
			return tui.PromptDecision{}, errors.New("must not prompt: Plan denies the create")
		}
		modeActive := mode.NewActiveState(mode.Build, mode.SourceDefault)
		auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, modeActive)
		entered := make(chan struct{})
		release := make(chan struct{})
		auth.activeStore = func() *sessions.Store {
			close(entered)
			<-release
			return store
		}

		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, cwd, cwd)); err != nil {
			t.Fatalf("Register: %v", err)
		}
		target := filepath.Join(cwd, "new.go")
		done := make(chan error, 1)
		go func() {
			_, err := dispatch.DispatchTool(context.Background(), filetools.CreateToolName,
				map[string]any{"path": target, "content": "package main\n"}, home, cwd, reg, auth)
			done <- err
		}()

		<-entered
		modeActive.ApplyUserCommand(mode.Plan)
		close(release)
		err := <-done
		var denied *dispatch.DeniedError
		if !errors.As(err, &denied) {
			t.Fatalf("DispatchTool err = %v, want a *dispatch.DeniedError", err)
		}
		if shown != 0 {
			t.Fatalf("prompt shown %d times, want 0", shown)
		}
		if _, statErr := os.Stat(target); !errors.Is(statErr, fs.ErrNotExist) {
			t.Fatalf("create target stat error = %v, want not exist", statErr)
		}
	})

	t.Run("batch path reads the mode after setup", func(t *testing.T) {
		cwd := t.TempDir()
		home := t.TempDir()
		store := mkStore(t)
		app := tui.New(nil)
		app.SetActiveStore(store)

		shown := 0
		show := func(tui.PromptRequest) (tui.PromptDecision, error) {
			shown++
			return tui.PromptDecision{}, errors.New("must not prompt: Plan denies the mutating pipeline stage")
		}
		modeActive := mode.NewActiveState(mode.Build, mode.SourceDefault)
		auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, modeActive)
		entered := make(chan struct{})
		release := make(chan struct{})
		auth.activeStore = func() *sessions.Store {
			close(entered)
			<-release
			return store
		}

		run := &fakeDispatchRunner{}
		done := make(chan error, 1)
		go func() {
			_, err := dispatch.DispatchShell(context.Background(), "echo hi | tee out.txt", home, cwd, auth, run)
			done <- err
		}()

		<-entered
		modeActive.ApplyUserCommand(mode.Plan)
		close(release)
		err := <-done
		var denied *dispatch.DeniedError
		if !errors.As(err, &denied) {
			t.Fatalf("DispatchShell err = %v, want a *dispatch.DeniedError", err)
		}
		if shown != 0 {
			t.Fatalf("prompt shown %d times, want 0", shown)
		}
		if run.callCount() != 0 {
			t.Fatalf("runner Exec calls = %d, want 0", run.callCount())
		}
	})
}

func TestProductionAuthorizer_ModeSwitchDoesNotReauthorizeShownPrompt(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	target := filepath.Join(cwd, "new.go")

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	shown := 0
	entered := make(chan struct{})
	release := make(chan struct{})
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		entered <- struct{}{}
		<-release
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	modeActive := mode.NewActiveState(mode.Build, mode.SourceDefault)
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, modeActive)

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, cwd, cwd)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	var derr error
	done := make(chan struct{})
	go func() {
		_, derr = dispatch.DispatchTool(context.Background(), filetools.CreateToolName,
			map[string]any{"path": target, "content": "x"}, home, cwd, reg, auth)
		close(done)
	}()

	<-entered
	modeActive.ApplyUserCommand(mode.Plan)
	close(release)
	<-done

	if derr != nil {
		t.Fatalf("DispatchTool err = %v, want nil (the shown prompt's allow-once must stand after the switch)", derr)
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times, want exactly 1 (a mode switch must not re-prompt a request already shown)", shown)
	}
	if _, statErr := os.Stat(target); statErr != nil {
		t.Fatalf("create did not produce a file: %v (the allow-once decision must have applied)", statErr)
	}
	if got := countPermissionEvents(store, events.KindPermissionPromptShown); got != 1 {
		t.Fatalf("permission_prompt_shown events = %d, want exactly 1 (the shown prompt is not re-shown or re-evaluated)", got)
	}
}

var directChainCases = []struct {
	name    string
	command string
	calls   int
}{
	{"direct call", `prdtasks create g "First task"`, 1},
	{"&& chain", `prdtasks create g "First task" && prdtasks create f "Second task"`, 2},
	{"; chain", `prdtasks create g "First task" ; prdtasks create f "Second task"`, 2},
}

func prependFixturePrograms(t *testing.T, names ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("WriteFile(%q): %v", path, err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestProductionAuthorizer_SessionDirectGrantCoversSafeChains(t *testing.T) {
	prependFixturePrograms(t, "prdtasks")
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	cache := emptyCache(t, cwd)
	cache.AppendPermission(permissions.PermissionEntry{
		Kind: "direct", Subject: "prdtasks create :*", PathScope: cwd, GrantKind: "session",
	})

	shown := 0
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		return tui.PromptDecision{}, errors.New("the session grant must authorize every stage without prompting")
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	for _, tc := range directChainCases {
		t.Run(tc.name, func(t *testing.T) {
			auth.resetTurnCache()
			run := &fakeDispatchRunner{}
			if _, derr := dispatch.DispatchShell(context.Background(), tc.command, home, cwd, auth, run); derr != nil {
				t.Fatalf("DispatchShell(%q) = %v, want the session grant to authorize it", tc.command, derr)
			}
			if run.callCount() != tc.calls {
				t.Fatalf("runner Exec calls = %d, want %d (each authorized stage runs directly)", run.callCount(), tc.calls)
			}
			if shown != 0 {
				t.Fatalf("prompt shown %d times, want 0 (the direct grant covers every stage)", shown)
			}
		})
	}

	auth.resetTurnCache()
	run := &fakeDispatchRunner{}
	_, err = dispatch.DispatchShell(context.Background(), `prdtasks create g "First task" && prdtasks archive g`, home, cwd, auth, run)
	if err == nil {
		t.Fatalf("DispatchShell = nil, want a refusal: `prdtasks archive g` is outside the granted subject")
	}
	if run.callCount() != 0 {
		t.Fatalf("runner Exec calls = %d, want 0 (a non-matching stage prevents every stage from executing)", run.callCount())
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times, want 1 (only the uncovered stage reaches the prompt)", shown)
	}
}

func TestProductionAuthorizer_FolderDirectGrantCoversSafeChains(t *testing.T) {
	prependFixturePrograms(t, "prdtasks")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	cwd := filepath.Join(root, "proj")
	descendant := filepath.Join(cwd, "sub")
	sibling := filepath.Join(root, "other")
	for _, dir := range []string{cwd, descendant, sibling} {
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			t.Fatalf("MkdirAll(%q): %v", dir, mkErr)
		}
	}
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	seedGrantFile(t, projectSettingsPath(cwd), permissions.PermissionEntry{
		Kind: "direct", Subject: "prdtasks create :*", PathScope: cwd, GrantKind: "folder",
	})
	composition, err := defaultComposeConfig(nil, cwd)
	if err != nil {
		t.Fatalf("defaultComposeConfig: %v", err)
	}
	cache, err := config.NewCache(composition.Config, cwd, []string{projectSettingsPath(cwd)})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}

	shown := 0
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		return tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope("")}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	for _, scope := range []struct {
		label string
		dir   string
	}{{"grant scope", cwd}, {"descendant scope", descendant}} {
		for _, tc := range directChainCases {
			t.Run(scope.label+"/"+tc.name, func(t *testing.T) {
				auth.resetTurnCache()
				run := &fakeDispatchRunner{}
				if _, derr := dispatch.DispatchShell(context.Background(), tc.command, home, scope.dir, auth, run); derr != nil {
					t.Fatalf("DispatchShell(%q) in %s = %v, want the persisted folder grant to authorize it", tc.command, scope.label, derr)
				}
				if run.callCount() != tc.calls {
					t.Fatalf("runner Exec calls = %d, want %d (each authorized stage runs directly)", run.callCount(), tc.calls)
				}
				if shown != 0 {
					t.Fatalf("prompt shown %d times, want 0 (the folder grant covers the scope and its descendants)", shown)
				}
			})
		}
	}

	for _, escape := range []struct {
		label string
		dir   string
	}{{"sibling", sibling}, {"ancestor", root}} {
		t.Run("scope escape/"+escape.label, func(t *testing.T) {
			before := shown
			auth.resetTurnCache()
			run := &fakeDispatchRunner{}
			_, derr := dispatch.DispatchShell(context.Background(), directChainCases[1].command, home, escape.dir, auth, run)
			var denied *dispatch.DeniedError
			if !errors.As(derr, &denied) {
				t.Fatalf("DispatchShell in the %s scope = %v, want a *dispatch.DeniedError (the folder grant does not reach it)", escape.label, derr)
			}
			if run.callCount() != 0 {
				t.Fatalf("runner Exec calls = %d, want 0 (a denied stage prevents every stage from executing)", run.callCount())
			}
			if shown == before {
				t.Fatalf("prompt shown %d times, want more than %d (an out-of-scope stage must reach the prompt)", shown, before)
			}
		})
	}
}

func reloadedAuthorizer(t *testing.T, app *tui.App, home, cwd, why string) *productionAuthorizer {
	t.Helper()
	composition, err := defaultComposeConfig(nil, cwd)
	if err != nil {
		t.Fatalf("defaultComposeConfig: %v", err)
	}
	cache, err := config.NewCache(composition.Config, cwd, []string{projectSettingsPath(cwd)})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{}, errors.New(why)
	}
	return newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))
}

func wantSingleStagePrompt(t *testing.T, req tui.PromptRequest) {
	t.Helper()
	if len(req.BatchedStages) != 0 {
		t.Fatalf("prompt BatchedStages = %v, want none (one unresolved stage renders the ordinary prompt with its scope chooser)", req.BatchedStages)
	}
}

func TestProductionAuthorizer_DirectPromptScopePersistsAndReloads(t *testing.T) {
	prependFixturePrograms(t, "prdtasks")
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	shown := 0
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		wantSingleStagePrompt(t, req)
		return tui.PromptDecision{Option: tui.OptionAllowFolder, StoredSubject: "prdtasks create :*"}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	run := &fakeDispatchRunner{}
	if _, derr := dispatch.DispatchShell(context.Background(), `prdtasks create g "First task"`, home, cwd, auth, run); derr != nil {
		t.Fatalf("DispatchShell = %v, want the folder approval to authorize it", derr)
	}
	if shown != 1 || run.callCount() != 1 {
		t.Fatalf("prompt shown %d times and runner Exec calls = %d, want 1 and 1", shown, run.callCount())
	}

	entry := findGrant(t, readPersistedPermissions(t, config.LocalSettingsPath(cwd), cwd), "prdtasks create :*")
	if entry.Kind != "direct" || entry.GrantKind != "folder" || entry.PathScope != cwd {
		t.Fatalf("persisted entry = %+v, want a direct folder grant scoped to %q", entry, cwd)
	}

	reloaded := reloadedAuthorizer(t, app, home, cwd, "the reloaded folder grant must authorize a later create without prompting")
	later := &fakeDispatchRunner{}
	if _, derr := dispatch.DispatchShell(context.Background(), `prdtasks create f "Second task"`, home, cwd, reloaded, later); derr != nil {
		t.Fatalf("DispatchShell after reload = %v, want the persisted %q scope to cover a differently-argued create", derr, "prdtasks create :*")
	}
	if later.callCount() != 1 {
		t.Fatalf("runner Exec calls after reload = %d, want 1", later.callCount())
	}

	reloaded.resetTurnCache()
	outside := &fakeDispatchRunner{}
	if _, derr := dispatch.DispatchShell(context.Background(), `prdtasks archive g`, home, cwd, reloaded, outside); derr == nil {
		t.Fatalf("DispatchShell(`prdtasks archive g`) = nil, want a refusal: the stored scope covers only `prdtasks create`")
	}
	if outside.callCount() != 0 {
		t.Fatalf("runner Exec calls for the uncovered command = %d, want 0", outside.callCount())
	}
}

func TestProductionAuthorizer_ChainPromptScopePersistsAfterGrantedStage(t *testing.T) {
	prependFixturePrograms(t, "prdtasks")
	for _, tc := range []struct {
		name    string
		command string
	}{
		{"&& chain", `prdtasks archive g && prdtasks create g "First task"`},
		{"; chain", `prdtasks archive g ; prdtasks create g "First task"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatalf("EvalSymlinks: %v", err)
			}
			home := t.TempDir()
			store := mkStore(t)
			app := tui.New(nil)
			app.SetActiveStore(store)

			seedGrantFile(t, projectSettingsPath(cwd), permissions.PermissionEntry{
				Kind: "direct", Subject: "prdtasks archive :*", PathScope: cwd, GrantKind: "folder",
			})
			composition, err := defaultComposeConfig(nil, cwd)
			if err != nil {
				t.Fatalf("defaultComposeConfig: %v", err)
			}
			cache, err := config.NewCache(composition.Config, cwd, []string{projectSettingsPath(cwd)})
			if err != nil {
				t.Fatalf("config.NewCache: %v", err)
			}

			shown := 0
			show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
				shown++
				wantSingleStagePrompt(t, req)
				return tui.PromptDecision{Option: tui.OptionAllowFolder, StoredSubject: "prdtasks create :*"}, nil
			}
			auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

			run := &fakeDispatchRunner{}
			if _, derr := dispatch.DispatchShell(context.Background(), tc.command, home, cwd, auth, run); derr != nil {
				t.Fatalf("DispatchShell(%q) = %v, want the granted stage plus the approved stage to run", tc.command, derr)
			}
			if shown != 1 || run.callCount() != 2 {
				t.Fatalf("prompt shown %d times and runner Exec calls = %d, want 1 and 2", shown, run.callCount())
			}

			persisted := readPersistedPermissions(t, config.LocalSettingsPath(cwd), cwd)
			entry := findGrant(t, persisted, "prdtasks create :*")
			if entry.Kind != "direct" || entry.GrantKind != "folder" || entry.PathScope != cwd {
				t.Fatalf("persisted entry = %+v, want a direct folder grant scoped to %q", entry, cwd)
			}
			if len(persisted) != 1 {
				t.Fatalf("persisted entries = %+v, want only the approved stage's scope", persisted)
			}
			findGrant(t, readPersistedPermissions(t, projectSettingsPath(cwd), cwd), "prdtasks archive :*")

			reloaded := reloadedAuthorizer(t, app, home, cwd, "the reloaded folder grant must authorize a later create without prompting")
			later := &fakeDispatchRunner{}
			if _, derr := dispatch.DispatchShell(context.Background(), `prdtasks create f "Second task"`, home, cwd, reloaded, later); derr != nil {
				t.Fatalf("DispatchShell after reload = %v, want the chain stage's stored scope to cover a differently-argued create", derr)
			}
			if later.callCount() != 1 {
				t.Fatalf("runner Exec calls after reload = %d, want 1", later.callCount())
			}
		})
	}
}

func TestProductionAuthorizer_HostPromptProjectGrantWritesProjectSettings(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	var shown tui.PromptRequest
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		shown = req
		return tui.PromptDecision{Option: tui.OptionAllowProject}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	req := permissions.MatchRequest{Kind: "host", Subject: "web_fetch", Host: "docs.example.com"}
	const hostRequest = "http://docs.example.com/guide?q=a+b"
	disp := dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: "web_fetch", HostRequest: hostRequest, DirectHTTPFallback: true}
	decision, err := auth.Authorize(context.Background(), req, disp, permissions.ModeContext{NetworkEgress: true})
	if err != nil {
		t.Fatalf("Authorize host request: %v", err)
	}
	if decision.PersistErr != nil {
		t.Fatalf("persisting the project host grant failed: %v", decision.PersistErr)
	}

	if shown.Kind != tui.SubjectHost {
		t.Fatalf("prompt kind = %q, want the host form (%q)", shown.Kind, tui.SubjectHost)
	}
	if shown.HostTool != "web_fetch" || shown.Host != "docs.example.com" {
		t.Errorf("prompt showed tool %q host %q, want web_fetch / docs.example.com", shown.HostTool, shown.Host)
	}
	if shown.HostRequest != hostRequest || !shown.DirectHTTPFallback {
		t.Errorf("prompt showed request %q fallback %t, want %q / true", shown.HostRequest, shown.DirectHTTPFallback, hostRequest)
	}
	if shown.RunFolder != "" || shown.ProjectRoot != "" || shown.FolderSettingsPath != "" || shown.CapabilityStoredSubject != "" {
		t.Errorf("host prompt carried path-scope display data: %#v", shown)
	}

	want := permissions.PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "docs.example.com", GrantKind: "project"}
	if decision.Grant == nil || *decision.Grant != want {
		t.Fatalf("decision grant = %+v, want %+v", decision.Grant, want)
	}

	projectTarget := config.LocalSettingsPath(cwd)
	persisted := findGrant(t, readPersistedPermissions(t, projectTarget, cwd), "web_fetch")
	if persisted != want {
		t.Errorf("entry read back from %q = %+v, want %+v", projectTarget, persisted, want)
	}
	if persisted.PathScope != "" {
		t.Errorf("persisted host grant carries path scope %q, want none", persisted.PathScope)
	}
	mustNotExist(t, SettingsPath(home), "an allow-in-this-project host approval must never reach the global settings file")
	if n := countPermissionEvents(store, events.KindPermissionPersistFailed); n != 0 {
		t.Errorf("permission_persist_failed events = %d, want 0 on a clean persist", n)
	}
}

func TestProductionAuthorizer_HostFreshConfirmationTakesNoGrant(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	var shown []tui.PromptRequest
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		shown = append(shown, req)
		if req.FreshConfirmation {
			return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
		}
		return tui.PromptDecision{Option: tui.OptionAllowProject}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	granted := permissions.MatchRequest{Kind: "host", Subject: "web_fetch", Host: "docs.example.com"}
	if _, err := auth.Authorize(context.Background(), granted, dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: "web_fetch"}, permissions.ModeContext{NetworkEgress: true}); err != nil {
		t.Fatalf("Authorize host request: %v", err)
	}

	fresh := permissions.MatchRequest{Kind: "host", Subject: "web_fetch", Host: "docs.example.com", FreshConfirmation: true}
	for i := 0; i < 2; i++ {
		d, err := auth.Authorize(context.Background(), fresh, dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: "web_fetch"}, permissions.ModeContext{NetworkEgress: true})
		if err != nil {
			t.Fatalf("Authorize fresh confirmation %d: %v", i, err)
		}
		if d.Grant != nil {
			t.Fatalf("fresh confirmation %d created grant %+v, want none", i, *d.Grant)
		}
	}

	if len(shown) != 3 {
		t.Fatalf("prompts shown = %d, want 3 (the project grant, then both fresh confirmations)", len(shown))
	}
	for i, req := range shown[1:] {
		if !req.FreshConfirmation {
			t.Errorf("fresh confirmation prompt %d did not carry the marker: %#v", i, req)
		}
	}
	if entries := readPersistedPermissions(t, config.LocalSettingsPath(cwd), cwd); len(entries) != 1 {
		t.Errorf("persisted entries = %d (%+v), want only the one project host grant", len(entries), entries)
	}
}

func promptShownPayloads(t *testing.T, store *sessions.Store) []events.PermissionPromptShown {
	t.Helper()
	var out []events.PermissionPromptShown
	for _, rec := range store.Records() {
		ev, ok := rec.(sessions.Event)
		if !ok || ev.Kind != events.KindPermissionPromptShown {
			continue
		}
		var p events.PermissionPromptShown
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("unmarshal permission_prompt_shown: %v", err)
		}
		out = append(out, p)
	}
	return out
}

func wantDirectTokens(t *testing.T, p events.PermissionPromptShown, want []string) {
	t.Helper()
	if p.DirectTokens == nil {
		t.Fatalf("permission_prompt_shown %#v carries no direct_tokens", p)
	}
	if !slices.Equal(*p.DirectTokens, want) {
		t.Fatalf("direct_tokens = %q, want %q", *p.DirectTokens, want)
	}
}

func TestProductionAuthorizer_DirectShellPersistsCanonicalTokens(t *testing.T) {
	prependFixturePrograms(t, "git")
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	shown := 0
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))
	run := &fakeDispatchRunner{}

	if _, err := dispatch.DispatchShell(context.Background(), `git commit -m "First task"`, home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times, want 1", shown)
	}
	if run.callCount() != 1 {
		t.Fatalf("runner Exec calls = %d, want 1 (an approved command still executes)", run.callCount())
	}

	prompts := promptShownPayloads(t, store)
	if len(prompts) != 1 {
		t.Fatalf("persisted %d permission_prompt_shown events, want 1", len(prompts))
	}
	if prompts[0].SubjectKind != "direct" || prompts[0].Subject != "git commit -m First task" {
		t.Fatalf("persisted prompt = %#v, want the direct flattened subject", prompts[0])
	}
	wantDirectTokens(t, prompts[0], []string{"git", "commit", "-m", "First task"})
}

func TestProductionAuthorizer_DirectPipelinePersistsPerStageTokens(t *testing.T) {
	prependFixturePrograms(t, "git")
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	shown := 0
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))
	run := &fakeDispatchRunner{}

	if _, err := dispatch.DispatchShell(context.Background(), `git commit -m "First task" | git push origin "feature branch"`, home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times, want 1 command-level prompt for the pipeline", shown)
	}
	if run.callCount() != 2 {
		t.Fatalf("runner Exec calls = %d, want 2 (both stages run after one approval)", run.callCount())
	}

	prompts := promptShownPayloads(t, store)
	if len(prompts) != 2 {
		t.Fatalf("persisted %d permission_prompt_shown events, want 2", len(prompts))
	}
	wantDirectTokens(t, prompts[0], []string{"git", "commit", "-m", "First task"})
	wantDirectTokens(t, prompts[1], []string{"git", "push", "origin", "feature branch"})
}

func decisionPayloads(t *testing.T, store *sessions.Store) []events.PermissionDecision {
	t.Helper()
	var out []events.PermissionDecision
	for _, rec := range store.Records() {
		ev, ok := rec.(sessions.Event)
		if !ok || ev.Kind != events.KindPermissionDecision {
			continue
		}
		var p events.PermissionDecision
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("unmarshal permission_decision: %v", err)
		}
		out = append(out, p)
	}
	return out
}

func TestProductionAuthorizer_DirectBatchPersistsPerStageEnvIdentities(t *testing.T) {
	prependFixturePrograms(t, "myprog", "otherprog")
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	shown := 0
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		return tui.PromptDecision{Option: tui.OptionAllowSession}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))
	run := &fakeDispatchRunner{}

	if _, err := dispatch.DispatchShell(context.Background(), `FOO=a myprog -n 1 x | BAR=b otherprog -m "two words"`, home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times, want 1 command-level prompt for the batch", shown)
	}

	stages := []struct {
		tokens      []string
		assignments []string
	}{
		{tokens: []string{"myprog", "-n", "1", "x"}, assignments: []string{"FOO=a"}},
		{tokens: []string{"otherprog", "-m", "two words"}, assignments: []string{"BAR=b"}},
	}

	prompts := promptShownPayloads(t, store)
	decisions := decisionPayloads(t, store)
	if len(prompts) != len(stages) || len(decisions) != len(stages) {
		t.Fatalf("persisted %d prompts and %d decisions, want %d of each", len(prompts), len(decisions), len(stages))
	}

	for i, stage := range stages {
		wantSubject := strings.Join(stage.tokens, " ")
		wantCommand := permissions.ExactSubject(stage.tokens[0], stage.tokens[1:])
		wantRequest, err := permissions.DirectRequestSubject(stage.tokens, stage.assignments, false)
		if err != nil {
			t.Fatalf("DirectRequestSubject(%q): %v", stage.tokens, err)
		}

		prompt := prompts[i]
		wantDirectTokens(t, prompt, stage.tokens)
		if prompt.Subject != wantSubject {
			t.Fatalf("stage %d prompt subject = %q, want %q", i, prompt.Subject, wantSubject)
		}
		if prompt.DirectCommandSubject != wantCommand || prompt.DirectRequestSubject != wantRequest {
			t.Fatalf("stage %d prompt identities = %q/%q, want %q/%q",
				i, prompt.DirectCommandSubject, prompt.DirectRequestSubject, wantCommand, wantRequest)
		}

		decision := decisions[i]
		if decision.Subject != wantSubject {
			t.Fatalf("stage %d decision subject = %q, want %q", i, decision.Subject, wantSubject)
		}
		if decision.DirectCommandSubject != wantCommand || decision.DirectRequestSubject != wantRequest {
			t.Fatalf("stage %d decision identities = %q/%q, want %q/%q",
				i, decision.DirectCommandSubject, decision.DirectRequestSubject, wantCommand, wantRequest)
		}
		got, _, ok := permissions.DecodeDirectRequestSubject(decision.GrantSubject, wantCommand)
		if !ok || !slices.Equal(got, stage.assignments) {
			t.Fatalf("stage %d stored grant subject %q carries assignments %q, want %q",
				i, decision.GrantSubject, got, stage.assignments)
		}
	}
}

func TestProductionAuthorizer_SingleAuthorizeCarriesDirectTokens(t *testing.T) {
	cwd := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), t.TempDir(), cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	tokens := []string{"git", "commit", "-m", "First task"}
	req := permissions.MatchRequest{Kind: "direct", Subject: strings.Join(tokens, " "), SubjectTokens: tokens, PathScope: cwd}
	disp := dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: `git commit -m "First task"`}
	if _, err := auth.Authorize(context.Background(), req, disp, permissions.ModeContext{Class: permissions.ClassMutating}); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	prompts := promptShownPayloads(t, store)
	if len(prompts) != 1 {
		t.Fatalf("persisted %d permission_prompt_shown events, want 1", len(prompts))
	}
	wantDirectTokens(t, prompts[0], tokens)
}

func TestProductionAuthorizer_NonDirectPromptsOmitDirectTokens(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))
	run := &fakeDispatchRunner{}

	if _, err := dispatch.DispatchShell(context.Background(), `git log > out.txt`, home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell (literal route): %v", err)
	}

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, authTestTool{name: "read_file"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := dispatch.DispatchTool(context.Background(), "read_file", map[string]any{"path": "/proj/main.go"}, home, cwd, reg, auth); err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}

	prompts := promptShownPayloads(t, store)
	if len(prompts) != 2 {
		t.Fatalf("persisted %d permission_prompt_shown events, want 2", len(prompts))
	}
	for _, p := range prompts {
		if p.SubjectKind == "direct" {
			t.Fatalf("expected no direct subject kind in this test, got %#v", p)
		}
		if p.DirectTokens != nil {
			t.Fatalf("%s prompt persisted direct_tokens %q, want none", p.SubjectKind, *p.DirectTokens)
		}
	}
}

func TestProductionAuthorizer_DirectEnvIdentityEndToEnd(t *testing.T) {
	prependFixturePrograms(t, "myprog")
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	shown := 0
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		return tui.PromptDecision{Option: tui.OptionAllowSession}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))
	run := &fakeDispatchRunner{}

	if _, err := dispatch.DispatchShell(context.Background(), "FOO=bar myprog -n 1 x", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times, want 1", shown)
	}

	wantCommand := permissions.ExactSubject("myprog", []string{"-n", "1", "x"})
	wantRequest, err := permissions.DirectRequestSubject([]string{"myprog", "-n", "1", "x"}, []string{"FOO=bar"}, false)
	if err != nil {
		t.Fatalf("DirectRequestSubject: %v", err)
	}

	var prompt events.PermissionPromptShown
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionPromptShown).Payload, &prompt); err != nil {
		t.Fatalf("unmarshal permission_prompt_shown: %v", err)
	}
	if prompt.Subject != "myprog -n 1 x" || prompt.DirectTokens == nil || strings.Join(*prompt.DirectTokens, " ") != prompt.Subject {
		t.Fatalf("permission_prompt_shown = %#v, want the joined command subject and tokens", prompt)
	}
	if prompt.DirectCommandSubject != wantCommand || prompt.DirectRequestSubject != wantRequest {
		t.Fatalf("prompt identities = %q/%q, want %q/%q", prompt.DirectCommandSubject, prompt.DirectRequestSubject, wantCommand, wantRequest)
	}

	var decision events.PermissionDecision
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionDecision).Payload, &decision); err != nil {
		t.Fatalf("unmarshal permission_decision: %v", err)
	}
	if decision.Subject != "myprog -n 1 x" || decision.DirectCommandSubject != wantCommand || decision.DirectRequestSubject != wantRequest {
		t.Fatalf("permission_decision = %#v, want the joined subject and the request identities", decision)
	}
	if got, _, ok := permissions.DecodeDirectRequestSubject(decision.GrantSubject, wantCommand); !ok || !slices.Equal(got, []string{"FOO=bar"}) {
		t.Fatalf("stored grant subject %q does not carry the request's assignments", decision.GrantSubject)
	}

	if _, err := dispatch.DispatchShell(context.Background(), "myprog -n 1 x", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell (bare): %v", err)
	}
	if shown != 2 {
		t.Fatalf("prompt shown %d times, want 2 (the assignment grant must not cover the bare command)", shown)
	}

	if _, err := dispatch.DispatchShell(context.Background(), "FOO=bar myprog -n 1 x", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell (repeat): %v", err)
	}
	if shown != 2 {
		t.Fatalf("prompt shown %d times, want still 2 (the grant must authorize its own request)", shown)
	}
	var matched events.PermissionMatched
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionMatched).Payload, &matched); err != nil {
		t.Fatalf("unmarshal permission_matched: %v", err)
	}
	if matched.Subject != "myprog -n 1 x" || matched.DirectRequestSubject != wantRequest {
		t.Fatalf("permission_matched = %#v, want the joined subject and the request identity", matched)
	}
}

// The in-flight key mirrors the turn cache's identity, so it must isolate the same variants.
func TestInflightKeyOf_IsolatesAssignmentVariants(t *testing.T) {
	tokens := []string{"hg", "status"}
	bareSubject, err := permissions.DirectRequestSubject(tokens, nil, false)
	if err != nil {
		t.Fatalf("DirectRequestSubject: %v", err)
	}
	envSubject, err := permissions.DirectRequestSubject(tokens, []string{"LD_PRELOAD=/x/evil.so"}, false)
	if err != nil {
		t.Fatalf("DirectRequestSubject: %v", err)
	}
	bare := permissions.MatchRequest{Kind: "direct", Subject: bareSubject, SubjectTokens: tokens, PathScope: "/proj"}
	env := permissions.MatchRequest{
		Kind: "direct", Subject: envSubject, SubjectTokens: tokens,
		Assignments: []string{"LD_PRELOAD=/x/evil.so"}, PathScope: "/proj",
	}
	if inflightKeyOf(bare) == inflightKeyOf(env) {
		t.Fatalf("the bare and assignment-bearing requests share the in-flight key %+v", inflightKeyOf(bare))
	}
}

// One choice authorizes every stage, so the batched summary must describe the whole batch: the
// stage count plus the union of the stages' effects and targets, and the unknown fallback for the
// entire batch as soon as one stage cannot be classified.
func TestBuildBatchPromptRequest_SummaryCoversEveryStage(t *testing.T) {
	batch := func(stages ...string) tui.PromptRequest {
		t.Helper()
		prompts := make([]permissions.BatchPromptRequest, len(stages))
		displays := make([]PromptDisplay, len(stages))
		for i, stage := range stages {
			prompts[i] = permissions.BatchPromptRequest{
				Req:   permissions.MatchRequest{Kind: "direct", Subject: stage, PathScope: "/work"},
				Index: i,
			}
			displays[i] = PromptDisplay{Action: "Run command", Subject: stage}
		}
		pr, err := buildBatchPromptRequest(prompts, displays, nil)
		if err != nil {
			t.Fatalf("buildBatchPromptRequest: %v", err)
		}
		return pr
	}

	known := batch("cp a b", "touch c", "mkdir d")
	if known.Summary.Unknown {
		t.Fatalf("batch of classified stages fell back to unknown: %#v", known.Summary)
	}
	if known.Summary.StageCount != 3 {
		t.Fatalf("stage count = %d, want 3", known.Summary.StageCount)
	}
	if !reflect.DeepEqual(known.Summary.Targets, []string{"b", "c", "d"}) {
		t.Fatalf("batch targets = %#v, want every stage's target in stage order", known.Summary.Targets)
	}
	rows := strings.Join(known.Summary.DisplayRows(), "\n")
	if !strings.Contains(rows, "(3 stages)") || !strings.Contains(rows, "effect: runs a command, writes") {
		t.Fatalf("batch shape row does not describe the whole batch:\n%s", rows)
	}
	if !strings.Contains(known.Summary.Sentence, "all 3 pipeline stages") {
		t.Fatalf("batch sentence describes only the representative stage: %q", known.Summary.Sentence)
	}

	overCap := batch("cp a b", "touch c d", "mkdir e f", "rm g h")
	if overCap.Summary.StageCount != 4 {
		t.Fatalf("stage count = %d, want 4", overCap.Summary.StageCount)
	}
	wantTargets := []string{"b", "c", "d", "e", "f", "g", "h"}
	if !reflect.DeepEqual(overCap.Summary.Targets, wantTargets) {
		t.Fatalf("batch targets = %#v, want %#v — the cap is a rendering bound, not a collection bound", overCap.Summary.Targets, wantTargets)
	}
	capped := overCap.Summary.DisplayRows()
	if n := strings.Count(strings.Join(capped, "\n"), "Requested target: "); n != 6 {
		t.Fatalf("rendered %d target rows, want the six-row cap:\n%s", n, strings.Join(capped, "\n"))
	}
	if !strings.Contains(strings.Join(capped, "\n"), "… plus 1 more requested targets") {
		t.Fatalf("over-cap batch does not report its omitted-target count:\n%s", strings.Join(capped, "\n"))
	}

	mixed := batch("cp a b", "psql -c 'select 1'")
	if !mixed.Summary.Unknown || len(mixed.Summary.Targets) != 0 {
		t.Fatalf("one unclassifiable stage did not force the whole batch unknown: %#v", mixed.Summary)
	}
	if mixed.Summary.Lines != 2 {
		t.Fatalf("batch shape must still count the stage list: %#v", mixed.Summary)
	}

	// A representative stage that classifies on its own must not lend its summary to a batch
	// whose other stage does not.
	solo := batch("cp a b")
	if solo.Summary.Unknown || !reflect.DeepEqual(solo.Summary.Targets, []string{"b"}) {
		t.Fatalf("single-stage batch lost its ordinary summary: %#v", solo.Summary)
	}
	if solo.Summary.StageCount != 0 {
		t.Fatalf("single-stage batch reported a stage count of %d, want the ordinary single-request summary", solo.Summary.StageCount)
	}
}

func independentPrompts(t *testing.T, calls ...[2]string) ([]permissions.BatchPromptRequest, []PromptDisplay, []string) {
	t.Helper()
	prompts := make([]permissions.BatchPromptRequest, len(calls))
	displays := make([]PromptDisplay, len(calls))
	targets := make([]string, len(calls))
	for i, c := range calls {
		prompts[i] = permissions.BatchPromptRequest{
			Req:   permissions.MatchRequest{Kind: "tool", Subject: c[0], PathScope: filepath.Dir(c[1])},
			Index: i,
		}
		displays[i] = PromptDisplay{
			Action:         "Run tool",
			Subject:        c[0],
			Body:           fmt.Sprintf("%s({%q:%q})", c[0], "path", c[1]),
			ProjectRoot:    "/work",
			FolderCoverage: filepath.Dir(c[1]) + " and its descendants",
		}
		targets[i] = c[1]
	}
	return prompts, displays, targets
}

func TestBuildIndependentPromptRequest_MergedQuestionShowsEveryMembersCall(t *testing.T) {
	prompts, displays, targets := independentPrompts(t,
		[2]string{"read", "/work/notes/a.md"},
		[2]string{"read", "/work/notes/b.md"},
		[2]string{"read", "/work/notes/c.md"},
	)
	for i := range displays {
		displays[i].GrantStoredSubject = permissions.CapabilityRead
	}
	questions := independentQuestions(prompts, displays)
	if !reflect.DeepEqual(questions, [][]int{{0, 1, 2}}) {
		t.Fatalf("questions = %#v, want the three same-decision reads merged into one", questions)
	}

	pr, err := buildIndependentPromptRequest(prompts, displays, targets, questions[0])
	if err != nil {
		t.Fatalf("buildIndependentPromptRequest: %v", err)
	}
	for _, d := range displays {
		if !strings.Contains(pr.Body, d.Body) {
			t.Fatalf("merged question hid a member's call %q\n--- body ---\n%s", d.Body, pr.Body)
		}
	}
	if lines := strings.Split(pr.Body, "\n"); len(lines) != len(displays) {
		t.Fatalf("body lines = %#v, want one per member call", lines)
	}
	if pr.Subject != "" {
		t.Fatalf("merged question kept a representative subject %q; the member list already shows it", pr.Subject)
	}
	if !reflect.DeepEqual(pr.Summary.Targets, targets) {
		t.Fatalf("summary targets = %#v, want this question's own prepared targets %#v", pr.Summary.Targets, targets)
	}
	if pr.CapabilityStoredSubject != permissions.CapabilityRead {
		t.Fatalf("capability = %q, want the shared %q stated once", pr.CapabilityStoredSubject, permissions.CapabilityRead)
	}
	if pr.FolderCoverage != "/work/notes and its descendants" {
		t.Fatalf("folder coverage = %q, want the one scope every member shares", pr.FolderCoverage)
	}
	if len(pr.BatchedStages) != 0 || len(pr.BatchedEscalations) != 0 {
		t.Fatalf("merged question populated pipeline-batch fields: %#v %#v", pr.BatchedStages, pr.BatchedEscalations)
	}
	if _, err := buildIndependentPromptRequest(prompts, displays, targets, []int{len(prompts)}); err == nil {
		t.Fatal("an out-of-range member built a prompt; it must fail rather than decide the wrong call")
	}
	if _, err := buildIndependentPromptRequest(prompts, displays, targets, nil); err == nil {
		t.Fatal("an empty question built a prompt; it decides nothing")
	}
}

func TestBuildIndependentPromptRequest_SingleMemberRendersTheOrdinaryPrompt(t *testing.T) {
	prompts, displays, targets := independentPrompts(t, [2]string{"read", "/work/main.go"})
	displays[0].GrantStoredSubject = permissions.CapabilityRead

	pr, err := buildIndependentPromptRequest(prompts, displays, targets, []int{0})
	if err != nil {
		t.Fatalf("buildIndependentPromptRequest: %v", err)
	}
	if len(pr.BatchedStages) != 0 {
		t.Fatalf("a lone unresolved call rendered group chrome: %#v", pr)
	}
	if pr.Subject != "read" || pr.Body != displays[0].Body {
		t.Fatalf("subject = %q body = %q, want the ordinary single-call prompt", pr.Subject, pr.Body)
	}
	if pr.CapabilityStoredSubject != permissions.CapabilityRead {
		t.Fatalf("capability = %q, want the call's own %q", pr.CapabilityStoredSubject, permissions.CapabilityRead)
	}
}

// The requested target is the lexical path the call was written with; authorization is applied to
// the prepared target it resolved to, so that is what the question must name.
func TestBuildIndependentPromptRequest_LoneQuestionSummarizesItsPreparedTarget(t *testing.T) {
	prompts, displays, targets := independentPrompts(t, [2]string{"read", "/work/main.go"})
	displays[0].RequestedTarget = "../elsewhere/main.go"

	pr, err := buildIndependentPromptRequest(prompts, displays, targets, []int{0})
	if err != nil {
		t.Fatalf("buildIndependentPromptRequest: %v", err)
	}
	if !reflect.DeepEqual(pr.Summary.Targets, targets) {
		t.Fatalf("summary targets = %#v, want the prepared target %#v the authorization applies to", pr.Summary.Targets, targets)
	}
	if slices.Contains(pr.Summary.Targets, displays[0].RequestedTarget) {
		t.Fatalf("summary named the requested target %q, which is not what was authorized", displays[0].RequestedTarget)
	}
}

// Members that all carry the same broader-scope warning are still one decision, so they merge and
// the question carries that one warning for all of them.
func TestBuildIndependentPromptRequest_MergesMembersSharingOneEscalation(t *testing.T) {
	prompts, displays, targets := independentPrompts(t,
		[2]string{"read", "/work/sub/x.go"},
		[2]string{"read", "/work/sub/y.go"},
	)
	for i := range prompts {
		prompts[i].Escalation = permissions.ScopeEscalation{NarrowerScope: "/work/sub/deep"}
		displays[i].GrantStoredSubject = permissions.CapabilityRead
	}

	questions := independentQuestions(prompts, displays)
	if !reflect.DeepEqual(questions, [][]int{{0, 1}}) {
		t.Fatalf("questions = %#v, want the two equally escalating reads merged into one", questions)
	}
	pr, err := buildIndependentPromptRequest(prompts, displays, targets, questions[0])
	if err != nil {
		t.Fatalf("buildIndependentPromptRequest: %v", err)
	}
	if pr.ScopeEscalationNarrower != "/work/sub/deep" {
		t.Fatalf("escalation = %q, want the one narrower scope every member shares", pr.ScopeEscalationNarrower)
	}
	if pr.CapabilityStoredSubject != permissions.CapabilityRead {
		t.Fatalf("capability = %q, want the shared %q stated once", pr.CapabilityStoredSubject, permissions.CapabilityRead)
	}
	if len(pr.BatchedEscalations) != 0 {
		t.Fatalf("merged question populated pipeline escalations: %#v", pr.BatchedEscalations)
	}
	if !reflect.DeepEqual(pr.Summary.Targets, targets) {
		t.Fatalf("summary targets = %#v, want both members' prepared targets %#v", pr.Summary.Targets, targets)
	}
}

// A question states one scope-escalation warning, so it may only hold members that all carry it.
func TestBuildIndependentPromptRequest_KeepsTheQuestionsOwnEscalation(t *testing.T) {
	prompts, displays, targets := independentPrompts(t,
		[2]string{"read", "/work/sub/x.go"},
		[2]string{"read", "/work/sub/y.go"},
	)
	prompts[1].Escalation = permissions.ScopeEscalation{NarrowerScope: "/work/sub/deep"}

	questions := independentQuestions(prompts, displays)
	if !reflect.DeepEqual(questions, [][]int{{0}, {1}}) {
		t.Fatalf("questions = %#v, want the escalating call kept out of the non-escalating one", questions)
	}
	escalating, err := buildIndependentPromptRequest(prompts, displays, targets, questions[1])
	if err != nil {
		t.Fatalf("buildIndependentPromptRequest: %v", err)
	}
	if escalating.ScopeEscalationNarrower != "/work/sub/deep" {
		t.Fatalf("escalation = %q, want the question's own narrower scope", escalating.ScopeEscalationNarrower)
	}
	plain, err := buildIndependentPromptRequest(prompts, displays, targets, questions[0])
	if err != nil {
		t.Fatalf("buildIndependentPromptRequest: %v", err)
	}
	if plain.ScopeEscalationNarrower != "" {
		t.Fatalf("escalation = %q, want none — a sibling's warning must not travel", plain.ScopeEscalationNarrower)
	}
}

func TestIndependentQuestions_EveryDistinctEffectSplitsTheQuestion(t *testing.T) {
	base := func(index int) (permissions.BatchPromptRequest, PromptDisplay) {
		return permissions.BatchPromptRequest{
			Req:   permissions.MatchRequest{Kind: "tool", Subject: "read", PathScope: "/work"},
			Index: index,
		}, PromptDisplay{Action: "Run tool", GrantStoredSubject: permissions.CapabilityRead}
	}
	cases := []struct {
		name  string
		apply func(*permissions.BatchPromptRequest, *PromptDisplay)
	}{
		{"kind", func(p *permissions.BatchPromptRequest, _ *PromptDisplay) { p.Req.Kind = "literal" }},
		{"subject", func(p *permissions.BatchPromptRequest, _ *PromptDisplay) { p.Req.Subject = "grep" }},
		{"path scope", func(p *permissions.BatchPromptRequest, _ *PromptDisplay) { p.Req.PathScope = "/other" }},
		{"host", func(p *permissions.BatchPromptRequest, _ *PromptDisplay) { p.Req.Host = "example.test" }},
		{"clear environment", func(p *permissions.BatchPromptRequest, _ *PromptDisplay) { p.Req.ClearEnvironment = true }},
		{"scope escalation", func(p *permissions.BatchPromptRequest, _ *PromptDisplay) { p.Escalation.NarrowerScope = "/work/sub" }},
		{"action", func(_ *permissions.BatchPromptRequest, d *PromptDisplay) { d.Action = "Edit file" }},
		{"stored grant capability", func(_ *permissions.BatchPromptRequest, d *PromptDisplay) { d.GrantStoredSubject = "" }},
		{"out-of-root write", func(_ *permissions.BatchPromptRequest, d *PromptDisplay) { d.OutOfRootFileWrite = true }},
		{"out-of-root read scope", func(_ *permissions.BatchPromptRequest, d *PromptDisplay) { d.OutOfRootReadScope = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, firstDisplay := base(0)
			second, secondDisplay := base(1)
			tc.apply(&second, &secondDisplay)
			got := independentQuestions([]permissions.BatchPromptRequest{first, second}, []PromptDisplay{firstDisplay, secondDisplay})
			if !reflect.DeepEqual(got, [][]int{{0}, {1}}) {
				t.Fatalf("questions = %#v, want two — a difference in %s is an effect one screen cannot state", got, tc.name)
			}
		})
	}

	first, firstDisplay := base(0)
	second, secondDisplay := base(1)
	if got := independentQuestions([]permissions.BatchPromptRequest{first, second}, []PromptDisplay{firstDisplay, secondDisplay}); !reflect.DeepEqual(got, [][]int{{0, 1}}) {
		t.Fatalf("questions = %#v, want equal calls merged into one", got)
	}
}

// Subject tokens and assignments are part of what a grant authorizes and no question compares them;
// a host call's prompt shows neither a member list nor a body. Each is asked on its own even against
// an otherwise identical call.
func TestIndependentQuestions_TokensAssignmentsAndHostsNeverMerge(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*permissions.MatchRequest)
	}{
		{"subject tokens", func(r *permissions.MatchRequest) { r.SubjectTokens = []string{"ls", "-l"} }},
		{"assignments", func(r *permissions.MatchRequest) { r.Assignments = []string{"A=1"} }},
		{"host", func(r *permissions.MatchRequest) { r.Kind = matchKindHost; r.Host = "example.test" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prompts := make([]permissions.BatchPromptRequest, 2)
			displays := make([]PromptDisplay, 2)
			for i := range prompts {
				req := permissions.MatchRequest{Kind: "direct", Subject: "ls -l", PathScope: "/work"}
				tc.apply(&req)
				prompts[i] = permissions.BatchPromptRequest{Req: req, Index: i}
				displays[i] = PromptDisplay{Action: "Run command"}
			}
			if got := independentQuestions(prompts, displays); !reflect.DeepEqual(got, [][]int{{0}, {1}}) {
				t.Fatalf("questions = %#v, want each call asked on its own", got)
			}
		})
	}
}

func TestIndependentQuestions_KeepsTheCallsOriginalOrder(t *testing.T) {
	prompts, displays, _ := independentPrompts(t,
		[2]string{"read", "/work/a.md"},
		[2]string{"grep", "/work/b.md"},
		[2]string{"read", "/work/c.md"},
	)
	if got := independentQuestions(prompts, displays); !reflect.DeepEqual(got, [][]int{{0, 2}, {1}}) {
		t.Fatalf("questions = %#v, want the reads merged and every question in first-member order", got)
	}
}

func TestBuildIndependentPrompt_FansOneDecisionOutToEveryMember(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	app := tui.New(nil)
	app.SetActiveStore(mkStore(t))

	prompts, displays, targets := independentPrompts(t,
		[2]string{"read", "/work/notes/a.md"},
		[2]string{"read", "/work/notes/b.md"},
		[2]string{"grep", "/work/notes/c.md"},
	)
	for i := range displays {
		displays[i].GrantStoredSubject = permissions.CapabilityRead
	}
	displays[2].GrantStoredSubject = ""

	var shown []tui.PromptRequest
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		shown = append(shown, req)
		if len(shown) == 2 {
			return tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope("")}, nil
		}
		return tui.PromptDecision{Option: tui.OptionAllowSession}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	outcomes, err := auth.buildIndependentPrompt(displays, targets)(context.Background(), prompts)
	if err != nil {
		t.Fatalf("independent prompt: %v", err)
	}
	if len(shown) != 2 {
		t.Fatalf("screens shown = %d, want one per question", len(shown))
	}
	if len(outcomes) != len(prompts) {
		t.Fatalf("outcomes = %d, want one per original call (%d)", len(outcomes), len(prompts))
	}
	for _, i := range []int{0, 1} {
		if outcomes[i].Choice != permissions.PromptAllowSession {
			t.Fatalf("member %d choice = %v, want the merged question's allow", i, outcomes[i].Choice)
		}
		if outcomes[i].StoredSubject != permissions.CapabilityRead {
			t.Fatalf("member %d stored subject = %q, want its own display capability %q", i, outcomes[i].StoredSubject, permissions.CapabilityRead)
		}
	}
	if outcomes[2].Choice != permissions.PromptDeny || outcomes[2].DenyEnvelope == "" {
		t.Fatalf("sibling question outcome = %+v, want its own deny", outcomes[2])
	}
	for i, req := range shown {
		if req.ApprovalIndex != i+1 || req.ApprovalTotal != 2 {
			t.Fatalf("screen %d position = %d of %d, want %d of 2", i, req.ApprovalIndex, req.ApprovalTotal, i+1)
		}
	}
	if strings.Contains(shown[0].Body, displays[2].Body) {
		t.Fatalf("a question showed a call it does not decide\n--- body ---\n%s", shown[0].Body)
	}
}

// The bridge owes the orchestrator one outcome per original call, so a decision count that does not
// match the question count must fail rather than resolve a call by an answer never given for it.
func TestBuildIndependentPrompt_RejectsAMismatchedDecisionCount(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	app := tui.New(nil)
	app.SetActiveStore(mkStore(t))

	prompts, displays, targets := independentPrompts(t,
		[2]string{"read", "/work/notes/a.md"},
		[2]string{"read", "/work/notes/b.md"},
	)
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(nil), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))
	auth.prompts.showIndependent = func([]tui.PromptRequest) ([]tui.PromptDecision, error) {
		return nil, nil
	}

	if _, err := auth.buildIndependentPrompt(displays, targets)(context.Background(), prompts); err == nil {
		t.Fatal("a short decision vector was accepted; no call may be resolved by an answer that was never given")
	}
}

func TestProductionAuthorizer_IndependentGroupAsksOnceForOneSharedDecision(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	var shown []tui.PromptRequest
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		shown = append(shown, req)
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	read := func(name string) dispatch.IndependentAuthRequest {
		path := filepath.Join(cwd, name)
		return dispatch.IndependentAuthRequest{
			Req:            permissions.MatchRequest{Kind: "tool", Subject: "read", PathScope: cwd},
			Display:        dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: "read", Body: fmt.Sprintf("read({%q:%q})", "path", path)},
			ModeCtx:        permissions.ModeContext{Class: permissions.ClassReadOnly, ToolName: "read", ExternalRead: true},
			PreparedTarget: path,
		}
	}
	reqs := []dispatch.IndependentAuthRequest{read("a.md"), read("b.md"), read("c.md"), read("d.md"), read("e.md")}

	decisions, err := auth.AuthorizeIndependent(context.Background(), reqs)
	if err != nil {
		t.Fatalf("AuthorizeIndependent: %v", err)
	}
	if len(shown) != 1 {
		t.Fatalf("prompt asked %d times, want once — every call is the same decision", len(shown))
	}
	if shown[0].ApprovalIndex != 0 || shown[0].ApprovalTotal != 0 {
		t.Fatalf("approval position = %d of %d, want none — a lone question shows no counter", shown[0].ApprovalIndex, shown[0].ApprovalTotal)
	}
	for _, r := range reqs {
		if !strings.Contains(shown[0].Body, r.Display.Body) {
			t.Fatalf("the one screen hid the call %q\n--- body ---\n%s", r.Display.Body, shown[0].Body)
		}
	}
	if len(shown[0].Summary.Targets) != len(reqs) {
		t.Fatalf("summary targets = %#v, want every member's prepared target", shown[0].Summary.Targets)
	}
	if len(decisions) != len(reqs) {
		t.Fatalf("decisions = %d, want one per call (%d)", len(decisions), len(reqs))
	}
	for i, d := range decisions {
		if d.DenyEnvelope != "" {
			t.Fatalf("decision[%d] = %+v, want the shared allow applied to every member", i, d)
		}
	}
	recorded := decodeStoreEvents[events.PermissionDecision](t, reloadStore(t, store), events.KindPermissionDecision)
	if len(recorded) != len(reqs) {
		t.Fatalf("recorded decisions = %d, want one per member call (%d)", len(recorded), len(reqs))
	}
}

func TestProductionAuthorizer_IndependentCallsThatDifferAreAskedSeparately(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	var shown []tui.PromptRequest
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		shown = append(shown, req)
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reqs := []dispatch.IndependentAuthRequest{
		{
			Req:            permissions.MatchRequest{Kind: "tool", Subject: "read", PathScope: cwd},
			Display:        dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: "read", Body: "read({\"path\":\"main.go\"})"},
			ModeCtx:        permissions.ModeContext{Class: permissions.ClassReadOnly, ToolName: "read", ExternalRead: true},
			PreparedTarget: filepath.Join(cwd, "main.go"),
		},
		{
			Req:            permissions.MatchRequest{Kind: "tool", Subject: "vcs_status", PathScope: cwd},
			Display:        dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: "vcs_status", Body: "vcs_status({})"},
			ModeCtx:        permissions.ModeContext{Class: permissions.ClassReadOnly, ToolName: "vcs_status", ExternalRead: true},
			PreparedTarget: cwd,
		},
	}

	decisions, err := auth.AuthorizeIndependent(context.Background(), reqs)
	if err != nil {
		t.Fatalf("AuthorizeIndependent: %v", err)
	}
	if len(shown) != 2 {
		t.Fatalf("prompt asked %d times, want one question per distinct decision", len(shown))
	}
	if len(decisions) != 2 || decisions[0].DenyEnvelope != "" || decisions[1].DenyEnvelope != "" {
		t.Fatalf("decisions = %+v, want one allow per call", decisions)
	}
	for i, req := range shown {
		if req.ApprovalIndex != i+1 || req.ApprovalTotal != 2 {
			t.Fatalf("screen %d position = %d of %d, want %d of 2", i, req.ApprovalIndex, req.ApprovalTotal, i+1)
		}
		other := reqs[1-i].Display.Body
		if strings.Contains(req.Body, other) || slices.Contains(req.Summary.Targets, reqs[1-i].PreparedTarget) {
			t.Fatalf("screen %d named the call it is not deciding\n--- request ---\n%#v", i, req)
		}
	}
}

func TestProductionAuthorizer_IndependentGroupDeniesOnlyItsOwnCall(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	turnCache := permissions.NewTurnCache()
	denied := permissions.MatchRequest{Kind: "tool", Subject: "grep", PathScope: cwd}
	turnCache.Record(denied, "deny")

	shown := 0
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), turnCache, newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	independent := func(subject string) dispatch.IndependentAuthRequest {
		return dispatch.IndependentAuthRequest{
			Req:            permissions.MatchRequest{Kind: "tool", Subject: subject, PathScope: cwd},
			Display:        dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: subject},
			ModeCtx:        permissions.ModeContext{Class: permissions.ClassReadOnly, ToolName: subject, ExternalRead: true},
			PreparedTarget: cwd,
		}
	}
	decisions, err := auth.AuthorizeIndependent(context.Background(), []dispatch.IndependentAuthRequest{
		independent("grep"), independent("read"),
	})
	if err != nil {
		t.Fatalf("AuthorizeIndependent: %v", err)
	}
	if decisions[0].DenyEnvelope == "" {
		t.Fatalf("first decision = %+v, want the cached deny with its own envelope", decisions[0])
	}
	if decisions[1].DenyEnvelope != "" {
		t.Fatalf("second decision = %+v, want it authorized despite the sibling denial", decisions[1])
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times, want 1 (only the unresolved call needed one)", shown)
	}
}

// A global grant that cannot be persisted degrades to a session grant over the requesting call's
// own path. The group shares no path scope, so binding persistence to the first call would degrade
// a later call's grant onto a directory it never asked for.
func TestProductionAuthorizer_IndependentPersistFailureDegradesToItsOwnPath(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	other := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	// A directory at the global settings path makes every global persist fail.
	if err := os.MkdirAll(SettingsPath(home), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{Option: tui.OptionAllowGlobal}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	independent := func(subject, scope string) dispatch.IndependentAuthRequest {
		return dispatch.IndependentAuthRequest{
			Req:            permissions.MatchRequest{Kind: "tool", Subject: subject, PathScope: scope},
			Display:        dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: subject},
			ModeCtx:        permissions.ModeContext{Class: permissions.ClassReadOnly, ToolName: subject, ExternalRead: true},
			PreparedTarget: scope,
		}
	}
	decisions, err := auth.AuthorizeIndependent(context.Background(), []dispatch.IndependentAuthRequest{
		independent("read", cwd), independent("grep", other),
	})
	if err != nil {
		t.Fatalf("AuthorizeIndependent: %v", err)
	}
	for i, want := range []string{cwd, other} {
		d := decisions[i]
		if d.PersistErr == nil {
			t.Fatalf("decision[%d] = %+v, want the forced persist failure", i, d)
		}
		if d.Grant == nil || d.Grant.PathScope != want {
			t.Fatalf("decision[%d] degraded grant = %+v, want it scoped to its own request path %q", i, d.Grant, want)
		}
	}
}

// The members are separate calls, not stages of one command, so the summary must not borrow the
// pipeline framing that a batched prompt uses.
func TestBuildIndependentPromptRequest_SummaryDescribesOnlyItsOwnQuestion(t *testing.T) {
	prompts, displays, targets := independentPrompts(t,
		[2]string{"read", "/work/notes/a.md"},
		[2]string{"read", "/work/notes/b.md"},
	)

	pr, err := buildIndependentPromptRequest(prompts, displays, targets, []int{0, 1})
	if err != nil {
		t.Fatalf("buildIndependentPromptRequest: %v", err)
	}
	if strings.Contains(pr.Summary.Sentence, "pipeline") {
		t.Fatalf("summary sentence = %q, want no pipeline framing for independent tool calls", pr.Summary.Sentence)
	}
	if strings.Contains(pr.Summary.Sentence, "applies to call") {
		t.Fatalf("summary sentence = %q, want no per-call disclaimer — the screen decides one question", pr.Summary.Sentence)
	}
	if pr.Summary.StageCount != 0 {
		t.Fatalf("summary stage count = %d, want 0 (these are not stages of one command)", pr.Summary.StageCount)
	}
	if !reflect.DeepEqual(pr.Summary.Targets, targets) {
		t.Fatalf("summary targets = %#v, want each member's prepared target %#v", pr.Summary.Targets, targets)
	}
	rows := strings.Join(pr.Summary.DisplayRows(), "\n")
	if strings.Contains(rows, "stages)") {
		t.Fatalf("summary shape row framed the question as pipeline stages:\n%s", rows)
	}
}

func TestProductionAuthorizer_PermanentApprovalWritesTheLocalSettingsFile(t *testing.T) {
	cwd := mustCanonical(t, t.TempDir())
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	hgignore := filepath.Join(cwd, ".hgignore")
	gitignore := filepath.Join(cwd, ".gitignore")
	seedIgnoreFile(t, hgignore, "syntax: glob\n")
	seedIgnoreFile(t, gitignore, "*.tmp\n")

	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{Option: tui.OptionAllowFolder}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))
	notices := &recordingNotices{}
	auth.notices = notices

	req := permissions.MatchRequest{Kind: "tool", Subject: "read_file", PathScope: cwd}
	if _, err := auth.Authorize(context.Background(), req, dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: "read_file"}, permissions.ModeContext{}); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	entry := findGrant(t, readPersistedPermissions(t, config.LocalSettingsPath(cwd), cwd), "read_file")
	if entry.GrantKind != "folder" || entry.PathScope != cwd {
		t.Fatalf("persisted entry = %+v, want a folder grant scoped to %q", entry, cwd)
	}
	if got, want := mustReadFile(t, config.LocalSettingsPath(cwd)), fmt.Sprintf("permissions:\n  - kind: tool\n    subject: read_file\n    path_scope: %s\n    grant_kind: folder\n", cwd); got != want {
		t.Fatalf("local settings file = %q, want the fixed bytes %q", got, want)
	}
	mustNotExist(t, projectSettingsPath(cwd), "a permanent approval must not create the shared project settings file")
	if got := readIgnoreFile(t, hgignore); got != "syntax: glob\n" {
		t.Fatalf(".hgignore = %q, want it byte-identical — codemeld never edits an ignore file", got)
	}
	if got := readIgnoreFile(t, gitignore); got != "*.tmp\n" {
		t.Fatalf(".gitignore = %q, want it byte-identical — codemeld never edits an ignore file", got)
	}

	want := tui.RenderLocalSettingsIgnoreNotice(config.LocalSettingsPath(cwd), config.LocalSettingsLockPath(cwd))
	if len(notices.texts) != 1 || notices.texts[0] != want {
		t.Fatalf("notices = %v, want exactly the ignore notice %q", notices.texts, want)
	}

	second := permissions.PermissionEntry{Kind: "tool", Subject: "list_files", PathScope: cwd, GrantKind: "folder"}
	if _, err := auth.persistGrant(store, cwd)(second); err != nil {
		t.Fatalf("second persistGrant: %v", err)
	}
	if len(notices.texts) != 1 {
		t.Fatalf("notices after a second permanent approval = %v, want the ignore notice emitted once per project", notices.texts)
	}
}

func TestProductionAuthorizer_ExistingLocalSettingsFileAnnouncesNothing(t *testing.T) {
	cwd := mustCanonical(t, t.TempDir())
	home := t.TempDir()
	store := mkStore(t)
	auth, _ := interactiveAuthorizerFor(t, &BootstrapResult{Home: home, LaunchDir: cwd, ProjectRoot: cwd})
	notices := &recordingNotices{}
	auth.notices = notices
	seedGrantFile(t, config.LocalSettingsPath(cwd), permissions.PermissionEntry{
		Kind: "tool", Subject: "list_files", PathScope: cwd, GrantKind: "folder",
	})

	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: cwd, GrantKind: "folder"}
	if _, err := auth.persistGrant(store, cwd)(entry); err != nil {
		t.Fatalf("persistGrant: %v", err)
	}
	if len(notices.texts) != 0 {
		t.Fatalf("notices = %v, want none — the local file already existed", notices.texts)
	}
}

func TestProductionAuthorizer_FailedLocalWriteAnnouncesNothing(t *testing.T) {
	cwd := mustCanonical(t, t.TempDir())
	home := t.TempDir()
	store := mkStore(t)
	seedIgnoreFile(t, filepath.Join(cwd, ".codemeld"), "x")
	auth, _ := interactiveAuthorizerFor(t, &BootstrapResult{Home: home, LaunchDir: cwd, ProjectRoot: cwd})
	notices := &recordingNotices{}
	auth.notices = notices

	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: cwd, GrantKind: "folder"}
	if _, err := auth.persistGrant(store, cwd)(entry); err == nil {
		t.Fatal("persistGrant err = nil, want the seeded .codemeld file to fail the write")
	}
	for _, text := range notices.texts {
		if strings.Contains(text, "ignore file") {
			t.Fatalf("notices = %v, want no ignore notice for a write that created nothing", notices.texts)
		}
	}
}

func TestProductionAuthorizer_RepeatedLocalCreationAnnouncesOnce(t *testing.T) {
	cwd := mustCanonical(t, t.TempDir())
	home := t.TempDir()
	store := mkStore(t)
	auth, _ := interactiveAuthorizerFor(t, &BootstrapResult{Home: home, LaunchDir: cwd, ProjectRoot: cwd})
	notices := &recordingNotices{}
	auth.notices = notices
	local := config.LocalSettingsPath(cwd)

	persist := auth.persistGrant(store, cwd)
	for _, subject := range []string{"read_file", "list_files"} {
		entry := permissions.PermissionEntry{Kind: "tool", Subject: subject, PathScope: cwd, GrantKind: "folder"}
		if _, err := persist(entry); err != nil {
			t.Fatalf("persistGrant %s: %v", subject, err)
		}
		if _, err := os.Stat(local); err != nil {
			t.Fatalf("the %s grant did not create %q: %v", subject, local, err)
		}
		if err := os.Remove(local); err != nil {
			t.Fatalf("remove %q between writes: %v", local, err)
		}
	}

	want := tui.RenderLocalSettingsIgnoreNotice(local, config.LocalSettingsLockPath(cwd))
	if len(notices.texts) != 1 || notices.texts[0] != want {
		t.Fatalf("notices after two writes that each created the local file = %v, want exactly one ignore notice %q", notices.texts, want)
	}
}

func TestProductionAuthorizer_ConcurrentLocalCreationAnnouncesOnce(t *testing.T) {
	cwd := mustCanonical(t, t.TempDir())
	home := t.TempDir()
	auth, _ := interactiveAuthorizerFor(t, &BootstrapResult{Home: home, LaunchDir: cwd, ProjectRoot: cwd})
	notices := &recordingNotices{}
	auth.notices = notices

	var start, done sync.WaitGroup
	start.Add(1)
	for range 8 {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			auth.announceLocalSettings()
		}()
	}
	start.Done()
	done.Wait()

	want := tui.RenderLocalSettingsIgnoreNotice(config.LocalSettingsPath(cwd), config.LocalSettingsLockPath(cwd))
	if len(notices.texts) != 1 || notices.texts[0] != want {
		t.Fatalf("notices from 8 concurrent created reports = %v, want exactly one ignore notice %q", notices.texts, want)
	}
}

func TestProductionAuthorizer_LocalGrantLeavesSharedProjectSettingsByteIdentical(t *testing.T) {
	cwd := mustCanonical(t, t.TempDir())
	home := t.TempDir()
	store := mkStore(t)
	shared := seedSharedProjectSettings(t, cwd, permissions.PermissionEntry{
		Kind: "tool", Subject: "list_files", PathScope: cwd, GrantKind: "folder",
	})
	auth, _ := interactiveAuthorizerFor(t, &BootstrapResult{Home: home, LaunchDir: cwd, ProjectRoot: cwd})

	folder := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: cwd, GrantKind: "folder"}
	host := projectHostGrant("web_fetch", "docs.example.com")
	for _, entry := range []permissions.PermissionEntry{folder, host} {
		if _, err := auth.persistGrant(store, cwd)(entry); err != nil {
			t.Fatalf("persistGrant %+v: %v", entry, err)
		}
		requireSharedProjectSettingsUnchanged(t, cwd, shared, "a local grant write")
	}

	localTarget := config.LocalSettingsPath(cwd)
	entries := readPersistedPermissions(t, localTarget, cwd)
	if len(entries) != 2 {
		t.Fatalf("%q holds %+v, want exactly the two local grants (the shared file's grant must not be copied in)", localTarget, entries)
	}
	if got := findGrant(t, entries, "read_file"); got != folder {
		t.Fatalf("folder grant read back from %q = %+v, want %+v", localTarget, got, folder)
	}
	if got := findGrant(t, entries, "web_fetch"); got != host {
		t.Fatalf("project host grant read back from %q = %+v, want %+v", localTarget, got, host)
	}
}

func TestProductionAuthorizer_RevokeLeavesSharedProjectSettingsByteIdentical(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(root string) permissions.PermissionEntry
	}{
		{"folder grant", func(root string) permissions.PermissionEntry {
			return permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: root, GrantKind: "folder"}
		}},
		{"project host grant", func(string) permissions.PermissionEntry {
			return projectHostGrant("web_fetch", "docs.example.com")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := mustCanonical(t, t.TempDir())
			home := t.TempDir()
			entry := tc.build(cwd)
			localTarget := config.LocalSettingsPath(cwd)

			seedGrantFile(t, localTarget, entry)
			shared := seedSharedProjectSettings(t, cwd, entry)
			auth, cache, store, notices := revokeAuthorizer(t, cwd, home, entry)

			auth.RevokeGrant(entry, notices)

			if present, _ := targetHasGrant(localTarget, cwd, entry.DedupKey()); present {
				t.Errorf("grant still in %q after revoke, want it removed from the local file", localTarget)
			}
			if cacheHasGrant(cache, entry.DedupKey()) {
				t.Errorf("grant still in the live table after revoke, want removed")
			}
			requireSharedProjectSettingsUnchanged(t, cwd, shared, "a local revoke")
			if len(notices.texts) != 0 {
				t.Errorf("revoke fired notices %v, want none on the happy path", notices.texts)
			}
			assertOneRevokeEvent(t, store, entry)
		})
	}
}

func seedSharedProjectSettings(t *testing.T, projectRoot string, entry permissions.PermissionEntry) string {
	t.Helper()
	target := projectSettingsPath(projectRoot)
	seedGrantFile(t, target, entry)
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read seeded %q: %v", target, err)
	}
	marked := "# committed by the team\n" + string(data)
	if err := os.WriteFile(target, []byte(marked), 0o600); err != nil {
		t.Fatalf("write seeded %q: %v", target, err)
	}
	return marked
}

func requireSharedProjectSettingsUnchanged(t *testing.T, projectRoot, want, after string) {
	t.Helper()
	target := projectSettingsPath(projectRoot)
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read %q after %s: %v", target, after, err)
	}
	if string(got) != want {
		t.Fatalf("%q is not byte-identical after %s:\n got=%q\nwant=%q", target, after, got, want)
	}
}

func seedIgnoreFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readIgnoreFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func shareAuthorizer(t *testing.T, trusted bool, reason trust.Reason) (auth *productionAuthorizer, root, home string, store *sessions.Store) {
	t.Helper()
	root = mustCanonical(t, t.TempDir())
	home = t.TempDir()
	auth, store = interactiveAuthorizerFor(t, &BootstrapResult{
		Home: home, LaunchDir: root, ProjectRoot: root,
		TrustDecision: trust.Decision{Trusted: trusted, Reason: reason, Root: root},
	})
	return auth, root, home, store
}

func approvedShareAuthorizer(t *testing.T) (*productionAuthorizer, string, string, *sessions.Store) {
	t.Helper()
	return shareAuthorizer(t, true, trust.ReasonTrusted)
}

func folderGrant(root, subject string) permissions.PermissionEntry {
	return permissions.PermissionEntry{Kind: "tool", Subject: subject, PathScope: root, GrantKind: "folder"}
}

func seedLocalGrant(t *testing.T, auth *productionAuthorizer, root string, entry permissions.PermissionEntry) {
	t.Helper()
	seedGrantFile(t, config.LocalSettingsPath(root), entry)
	auth.grants.AppendPermission(entry)
}

func localRow(root string, e permissions.PermissionEntry) tui.PermissionRow {
	return tui.PermissionRow{Entry: e, Layer: permissions.LayerLocal, Path: config.LocalSettingsPath(root)}
}

func projectRow(root string, e permissions.PermissionEntry) tui.PermissionRow {
	return tui.PermissionRow{Entry: e, Layer: permissions.LayerProject, Path: projectSettingsPath(root)}
}

func requireRows(t *testing.T, auth *productionAuthorizer, want ...tui.PermissionRow) {
	t.Helper()
	if got := auth.grants.LayeredPermissions(); len(got)+len(want) > 0 && !reflect.DeepEqual(got, want) {
		t.Fatalf("management rows = %+v\nwant %+v", got, want)
	}
}

func requireFileGrants(t *testing.T, path, root string, want ...permissions.PermissionEntry) {
	t.Helper()
	var got []permissions.PermissionEntry
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		got = readPersistedPermissions(t, path, root)
	}
	if len(got) != len(want) || (len(want) > 0 && !reflect.DeepEqual(got, want)) {
		t.Fatalf("%s holds %+v, want %+v", path, got, want)
	}
}

func approvedRootsUnchanged(t *testing.T, home, root string) func() {
	t.Helper()
	if err := trust.Record(home, root); err != nil {
		t.Fatalf("trust.Record: %v", err)
	}
	path := trust.StorePath(home)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat approved-roots store: %v", err)
	}
	data := mustReadFile(t, path)
	return func() {
		t.Helper()
		after, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat approved-roots store after share: %v", err)
		}
		if got := mustReadFile(t, path); got != data || !after.ModTime().Equal(before.ModTime()) {
			t.Fatalf("approved-roots store changed across a share: bytes %q -> %q, mtime %v -> %v", data, got, before.ModTime(), after.ModTime())
		}
	}
}

func TestShareGrant_MovesTheLocalEntryToTheSharedFile(t *testing.T) {
	auth, root, home, _ := approvedShareAuthorizer(t)
	storeUnchanged := approvedRootsUnchanged(t, home, root)
	shared, other := folderGrant(root, "read_file"), folderGrant(root, "list_files")
	seedLocalGrant(t, auth, root, shared)
	seedLocalGrant(t, auth, root, other)

	res := auth.ShareGrant(localRow(root, shared))

	want := tui.ShareResult{SharedPath: projectSettingsPath(root), LocalPath: config.LocalSettingsPath(root), SharedCreated: true}
	if res != want {
		t.Fatalf("ShareGrant = %+v, want %+v", res, want)
	}
	requireFileGrants(t, projectSettingsPath(root), root, shared)
	requireFileGrants(t, config.LocalSettingsPath(root), root, other)
	if !cacheHasGrant(auth.grants.cache, shared.DedupKey()) {
		t.Fatal("the shared grant stopped authorizing after a share")
	}
	requireRows(t, auth, localRow(root, other), projectRow(root, shared))
	storeUnchanged()
}

func TestShareGrant_SharedCopyAlreadyPresentSkipsTheSharedWrite(t *testing.T) {
	auth, root, home, _ := approvedShareAuthorizer(t)
	storeUnchanged := approvedRootsUnchanged(t, home, root)
	entry := folderGrant(root, "read_file")
	seedLocalGrant(t, auth, root, entry)
	sharedBytes := seedSharedProjectSettings(t, root, entry)
	auth.grants.addRow(projectRow(root, entry))

	res := auth.ShareGrant(localRow(root, entry))

	want := tui.ShareResult{SharedPath: projectSettingsPath(root), LocalPath: config.LocalSettingsPath(root), SharedSkipped: true}
	if res != want {
		t.Fatalf("ShareGrant = %+v, want %+v", res, want)
	}
	requireSharedProjectSettingsUnchanged(t, root, sharedBytes, "a skipped share")
	requireFileGrants(t, config.LocalSettingsPath(root), root)
	requireRows(t, auth, projectRow(root, entry))
	if !cacheHasGrant(auth.grants.cache, entry.DedupKey()) {
		t.Fatal("the grant stopped authorizing after a skipped share")
	}
	storeUnchanged()
}

func TestShareGrant_FailedSharedWriteLeavesBothFilesAndTheGrant(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions, so the write cannot be forced to fail")
	}
	auth, root, home, _ := approvedShareAuthorizer(t)
	storeUnchanged := approvedRootsUnchanged(t, home, root)
	entry := folderGrant(root, "read_file")
	seedLocalGrant(t, auth, root, entry)
	seedGrantFile(t, projectSettingsPath(root), folderGrant(root, "list_files"))
	sharedBefore := mustReadFile(t, projectSettingsPath(root))
	localBefore := mustReadFile(t, config.LocalSettingsPath(root))
	dir := filepath.Join(root, ".codemeld")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod settings dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	res := auth.ShareGrant(localRow(root, entry))

	if res.SharedErr == nil || res.SharedErr.Error() == "" || res.Refused || res.SharedSkipped || res.SharedCreated || res.LocalErr != nil {
		t.Fatalf("ShareGrant = %+v, want only a shared-write failure with its reason", res)
	}
	if res.SharedPath != projectSettingsPath(root) || res.LocalPath != config.LocalSettingsPath(root) {
		t.Fatalf("ShareGrant paths = %q/%q, want both settings files", res.SharedPath, res.LocalPath)
	}
	if got := mustReadFile(t, projectSettingsPath(root)); got != sharedBefore {
		t.Fatalf("shared file changed by a failed share: %q", got)
	}
	if got := mustReadFile(t, config.LocalSettingsPath(root)); got != localBefore {
		t.Fatalf("local file changed by a failed share: %q", got)
	}
	if !cacheHasGrant(auth.grants.cache, entry.DedupKey()) {
		t.Fatal("the grant stopped authorizing after a failed share")
	}
	requireRows(t, auth, localRow(root, entry))
	storeUnchanged()
}

func TestShareGrant_FailedLocalRemovalLeavesBothCopiesAndARerunFinishes(t *testing.T) {
	auth, root, home, _ := approvedShareAuthorizer(t)
	storeUnchanged := approvedRootsUnchanged(t, home, root)
	entry := folderGrant(root, "read_file")
	seedLocalGrant(t, auth, root, entry)
	lock := config.LocalSettingsLockPath(root)
	if err := os.Remove(lock); err != nil {
		t.Fatalf("remove local lock: %v", err)
	}
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatalf("block the local lock with a directory: %v", err)
	}

	res := auth.ShareGrant(localRow(root, entry))

	if res.LocalErr == nil || res.SharedErr != nil || res.Refused || res.SharedSkipped || !res.SharedCreated {
		t.Fatalf("ShareGrant = %+v, want a created shared copy and a local-removal failure", res)
	}
	if res.SharedPath != projectSettingsPath(root) || res.LocalPath != config.LocalSettingsPath(root) {
		t.Fatalf("ShareGrant paths = %q/%q, want both settings files", res.SharedPath, res.LocalPath)
	}
	requireFileGrants(t, projectSettingsPath(root), root, entry)
	requireFileGrants(t, config.LocalSettingsPath(root), root, entry)
	if !cacheHasGrant(auth.grants.cache, entry.DedupKey()) {
		t.Fatal("the grant stopped authorizing after a half-done share")
	}
	requireRows(t, auth, localRow(root, entry), projectRow(root, entry))
	sharedAfterFirst := mustReadFile(t, projectSettingsPath(root))

	if err := os.Remove(lock); err != nil {
		t.Fatalf("unblock the local lock: %v", err)
	}
	res = auth.ShareGrant(localRow(root, entry))

	want := tui.ShareResult{SharedPath: projectSettingsPath(root), LocalPath: config.LocalSettingsPath(root), SharedSkipped: true}
	if res != want {
		t.Fatalf("re-run ShareGrant = %+v, want %+v", res, want)
	}
	if got := mustReadFile(t, projectSettingsPath(root)); got != sharedAfterFirst {
		t.Fatalf("re-run rewrote the shared file: %q -> %q", sharedAfterFirst, got)
	}
	requireFileGrants(t, config.LocalSettingsPath(root), root)
	requireRows(t, auth, projectRow(root, entry))
	if !cacheHasGrant(auth.grants.cache, entry.DedupKey()) {
		t.Fatal("the grant stopped authorizing after the re-run")
	}
	storeUnchanged()
}

func TestShareGrant_RefusesWithoutWriting(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trusted bool
		reason  trust.Reason
		row     func(root, home string, e permissions.PermissionEntry) tui.PermissionRow
	}{
		{"project row", true, trust.ReasonTrusted, func(root, _ string, e permissions.PermissionEntry) tui.PermissionRow {
			return projectRow(root, e)
		}},
		{"global row", true, trust.ReasonTrusted, func(_, home string, e permissions.PermissionEntry) tui.PermissionRow {
			return tui.PermissionRow{Entry: e, Layer: permissions.LayerGlobal, Path: SettingsPath(home)}
		}},
		{"session row", true, trust.ReasonTrusted, func(_, _ string, e permissions.PermissionEntry) tui.PermissionRow {
			return tui.PermissionRow{Entry: e}
		}},
		{"explicitly unapproved", false, trust.ReasonNoRecord, func(root, _ string, e permissions.PermissionEntry) tui.PermissionRow {
			return localRow(root, e)
		}},
		{"nothing covered", true, trust.ReasonNothingCovered, func(root, _ string, e permissions.PermissionEntry) tui.PermissionRow {
			return localRow(root, e)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth, root, home, _ := shareAuthorizer(t, tc.trusted, tc.reason)
			entry := folderGrant(root, "read_file")
			seedLocalGrant(t, auth, root, entry)
			seedGrantFile(t, projectSettingsPath(root), folderGrant(root, "list_files"))
			sharedBefore := mustReadFile(t, projectSettingsPath(root))
			localBefore := mustReadFile(t, config.LocalSettingsPath(root))

			if res := auth.ShareGrant(tc.row(root, home, entry)); res != (tui.ShareResult{Refused: true}) {
				t.Fatalf("ShareGrant = %+v, want a bare refusal", res)
			}
			if got := mustReadFile(t, projectSettingsPath(root)); got != sharedBefore {
				t.Fatalf("refused share changed the shared file: %q", got)
			}
			if got := mustReadFile(t, config.LocalSettingsPath(root)); got != localBefore {
				t.Fatalf("refused share changed the local file: %q", got)
			}
			requireRows(t, auth, localRow(root, entry))
		})
	}
}

func TestRevokeRow_DeletesOnlyTheRowsOwnFile(t *testing.T) {
	auth, root, home, store := approvedShareAuthorizer(t)
	entry := folderGrant(root, "read_file")
	seedLocalGrant(t, auth, root, entry)
	sharedBytes := seedSharedProjectSettings(t, root, entry)
	auth.grants.addRow(projectRow(root, entry))
	notices := &recordingNotices{}

	auth.RevokeRow(localRow(root, entry), notices)

	requireFileGrants(t, config.LocalSettingsPath(root), root)
	requireSharedProjectSettingsUnchanged(t, root, sharedBytes, "a local-row revoke")
	if !cacheHasGrant(auth.grants.cache, entry.DedupKey()) {
		t.Fatal("the grant stopped authorizing while its shared copy remains")
	}
	requireRows(t, auth, projectRow(root, entry))
	assertOneRevokeEvent(t, store, entry)

	auth.RevokeRow(projectRow(root, entry), notices)

	requireFileGrants(t, projectSettingsPath(root), root)
	if got := mustReadFile(t, projectSettingsPath(root)); !strings.HasPrefix(got, "# committed by the team\n") {
		t.Fatalf("shared file lost its unrelated content: %q", got)
	}
	if cacheHasGrant(auth.grants.cache, entry.DedupKey()) {
		t.Fatal("the grant kept authorizing after its last copy was removed from the shared file")
	}
	requireRows(t, auth)
	if got := revokeEvents(t, store); len(got) != 2 || got[1] != wantRevokeEvent(entry) {
		t.Fatalf("revoke events = %+v, want a second one for %+v", got, entry)
	}

	global := permissions.PermissionEntry{Kind: "tool", Subject: "list_files", PathScope: "*", GrantKind: "global"}
	seedGrantFile(t, SettingsPath(home), global)
	auth.grants.AppendPermission(global)
	auth.RevokeRow(tui.PermissionRow{Entry: global, Layer: permissions.LayerGlobal, Path: SettingsPath(home)}, notices)

	requireFileGrants(t, SettingsPath(home), root)
	if cacheHasGrant(auth.grants.cache, global.DedupKey()) {
		t.Fatal("the global grant kept authorizing after its only copy was revoked")
	}
	requireRows(t, auth)
	if len(notices.texts) != 0 {
		t.Fatalf("revoke notices = %v, want none", notices.texts)
	}
}

func TestRevokeRow_UnlayeredRowRevokesTheSessionGrant(t *testing.T) {
	auth, root, _, store := approvedShareAuthorizer(t)
	entry := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: root, GrantKind: "session"}
	auth.grants.AppendPermission(entry)
	requireRows(t, auth, tui.PermissionRow{Entry: entry})

	auth.RevokeRow(tui.PermissionRow{Entry: entry}, &recordingNotices{})

	if cacheHasGrant(auth.grants.cache, entry.DedupKey()) {
		t.Fatal("the session grant kept authorizing after its revoke")
	}
	requireRows(t, auth)
	assertOneRevokeEvent(t, store, entry)
}

func seedProjectGrant(t *testing.T, auth *productionAuthorizer, root string, entry permissions.PermissionEntry) {
	t.Helper()
	seedGrantFile(t, projectSettingsPath(root), entry)
	auth.grants.cache.AppendPermission(entry)
	auth.grants.addRow(projectRow(root, entry))
}

func TestRevokeRow_ProjectRowRemovesOnlyThatEntryFromTheSharedFile(t *testing.T) {
	auth, root, home, store := approvedShareAuthorizer(t)
	storeUnchanged := approvedRootsUnchanged(t, home, root)
	entry, other, host := folderGrant(root, "read_file"), folderGrant(root, "list_files"), projectHostGrant("web_fetch", "docs.example.com")
	for _, e := range []permissions.PermissionEntry{other, entry, host} {
		seedProjectGrant(t, auth, root, e)
	}
	notices := &recordingNotices{}

	auth.RevokeRow(projectRow(root, entry), notices)

	requireFileGrants(t, projectSettingsPath(root), root, other, host)
	if cacheHasGrant(auth.grants.cache, entry.DedupKey()) {
		t.Fatal("the removed shared grant kept authorizing")
	}
	for _, e := range []permissions.PermissionEntry{other, host} {
		if !cacheHasGrant(auth.grants.cache, e.DedupKey()) {
			t.Fatalf("%+v stopped authorizing", e)
		}
	}
	requireRows(t, auth, projectRow(root, other), projectRow(root, host))
	if len(notices.texts) != 0 {
		t.Fatalf("revoke notices = %v, want none", notices.texts)
	}
	assertOneRevokeEvent(t, store, entry)
	storeUnchanged()
}

func TestRevokeRow_ProjectRowWithALocalCopyKeepsTheGrant(t *testing.T) {
	auth, root, _, store := approvedShareAuthorizer(t)
	entry := folderGrant(root, "read_file")
	seedLocalGrant(t, auth, root, entry)
	seedProjectGrant(t, auth, root, entry)

	auth.RevokeRow(projectRow(root, entry), &recordingNotices{})

	requireFileGrants(t, projectSettingsPath(root), root)
	requireFileGrants(t, config.LocalSettingsPath(root), root, entry)
	if !cacheHasGrant(auth.grants.cache, entry.DedupKey()) {
		t.Fatal("the grant stopped authorizing while its local copy remains")
	}
	requireRows(t, auth, localRow(root, entry))
	assertOneRevokeEvent(t, store, entry)
}

func TestRevokeRow_ProjectEntryAbsentFromTheSharedFileSkips(t *testing.T) {
	for _, tc := range []struct {
		name      string
		withLocal bool
	}{
		{"another layer holds it", true},
		{"another writer removed it", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth, root, _, store := approvedShareAuthorizer(t)
			entry := folderGrant(root, "read_file")
			var wantRows []tui.PermissionRow
			holding := tui.PermissionRow{}
			if tc.withLocal {
				seedLocalGrant(t, auth, root, entry)
				holding = localRow(root, entry)
				wantRows = append(wantRows, holding)
			}
			sharedBytes := seedSharedProjectSettings(t, root, folderGrant(root, "list_files"))
			auth.grants.cache.AppendPermission(entry)
			auth.grants.addRow(projectRow(root, entry))
			wantRows = append(wantRows, projectRow(root, entry))
			notices := &recordingNotices{}

			auth.RevokeRow(projectRow(root, entry), notices)

			requireSharedProjectSettingsUnchanged(t, root, sharedBytes, "a skipped project-row revoke")
			if want := tui.RenderRevokeSkipNotice(projectSettingsPath(root), holding); len(notices.texts) != 1 || notices.texts[0] != want {
				t.Fatalf("revoke notices = %v, want exactly [%q]", notices.texts, want)
			}
			if !cacheHasGrant(auth.grants.cache, entry.DedupKey()) {
				t.Fatal("a skipped revoke dropped the live grant")
			}
			requireRows(t, auth, wantRows...)
			assertNoRevokeEvent(t, store)
		})
	}
}

func TestRevokeRow_ProjectEntryRemovedBeforeTheLockSkips(t *testing.T) {
	auth, root, _, store := approvedShareAuthorizer(t)
	entry := folderGrant(root, "read_file")
	seedProjectGrant(t, auth, root, entry)
	path := projectSettingsPath(root)
	var afterOtherWriter string
	ran := false
	beforeRevokeRowPersist = func() {
		ran = true
		if _, _, err := config.Persist(path, config.KeyPermissions, config.PermissionDelete(entry.DedupKey())); err != nil {
			t.Errorf("other writer: %v", err)
		}
		afterOtherWriter = mustReadFile(t, path)
	}
	t.Cleanup(func() { beforeRevokeRowPersist = nil })
	notices := &recordingNotices{}

	auth.RevokeRow(projectRow(root, entry), notices)

	if !ran {
		t.Fatal("the hook between the preflight and the locked delete never ran")
	}
	if got := mustReadFile(t, path); got != afterOtherWriter {
		t.Fatalf("the delete wrote after another writer removed the entry: %q -> %q", afterOtherWriter, got)
	}
	if want := tui.RenderRevokeSkipNotice(path, tui.PermissionRow{}); len(notices.texts) != 1 || notices.texts[0] != want {
		t.Fatalf("revoke notices = %v, want exactly [%q]", notices.texts, want)
	}
	if !cacheHasGrant(auth.grants.cache, entry.DedupKey()) {
		t.Fatal("a locked no-op dropped the live grant")
	}
	requireRows(t, auth, projectRow(root, entry))
	assertNoRevokeEvent(t, store)
}

func TestRevokeRow_UninspectableSharedFileFailsAndKeepsTheGrant(t *testing.T) {
	for _, tc := range []struct {
		name       string
		content    string
		unreadable bool
	}{
		{"unparseable", "permissions: [", false},
		{"schema-invalid", "permissions: 7\n", false},
		{"unreadable", "permissions: []\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unreadable && os.Geteuid() == 0 {
				t.Skip("root reads any file")
			}
			auth, root, _, store := approvedShareAuthorizer(t)
			entry := folderGrant(root, "read_file")
			auth.grants.cache.AppendPermission(entry)
			auth.grants.addRow(projectRow(root, entry))
			path := projectSettingsPath(root)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.unreadable {
				if err := os.Chmod(path, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
			}
			_, inspectErr := targetHasGrant(path, root, entry.DedupKey())
			if inspectErr == nil {
				t.Fatalf("precondition: %q should not be inspectable", tc.content)
			}
			notices := &recordingNotices{}

			auth.RevokeRow(projectRow(root, entry), notices)

			if tc.unreadable {
				_ = os.Chmod(path, 0o600)
			}
			if got := mustReadFile(t, path); got != tc.content {
				t.Fatalf("shared file changed: %q", got)
			}
			if want := tui.RenderRevokeFailedNotice(path, inspectErr.Error()); len(notices.texts) != 1 || notices.texts[0] != want {
				t.Fatalf("revoke notices = %v, want exactly [%q]", notices.texts, want)
			}
			if !cacheHasGrant(auth.grants.cache, entry.DedupKey()) {
				t.Fatal("a failed revoke dropped the live grant")
			}
			requireRows(t, auth, projectRow(root, entry))
			assertNoRevokeEvent(t, store)
		})
	}
}

func TestProductionAuthorizer_MidRunApprovalsAppearAsLiveRows(t *testing.T) {
	cwd := mustCanonical(t, t.TempDir())
	home := t.TempDir()
	globalParent := filepath.Dir(SettingsPath(home))
	if err := os.MkdirAll(filepath.Dir(globalParent), 0o755); err != nil {
		t.Fatalf("seed global parent dir: %v", err)
	}
	if err := os.WriteFile(globalParent, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed global parent file: %v", err)
	}
	app := tui.New(nil)
	app.SetActiveStore(mkStore(t))
	var option tui.PromptOption
	show := func(tui.PromptRequest) (tui.PromptDecision, error) { return tui.PromptDecision{Option: option}, nil }
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))
	auth.notices = &recordingNotices{}

	for _, step := range []struct {
		option  tui.PromptOption
		subject string
	}{
		{tui.OptionAllowFolder, "read_file"},
		{tui.OptionAllowSession, "list_files"},
		{tui.OptionAllowGlobal, "grep"},
	} {
		option = step.option
		req := permissions.MatchRequest{Kind: "tool", Subject: step.subject, PathScope: cwd}
		if _, err := auth.Authorize(context.Background(), req, dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: step.subject}, permissions.ModeContext{}); err != nil {
			t.Fatalf("Authorize %s: %v", step.subject, err)
		}
	}

	effective := auth.grants.Permissions()
	if len(effective) != 3 || effective[1].GrantKind != "session" || effective[2].GrantKind != "session" {
		t.Fatalf("effective grants = %+v, want a folder grant, a session grant and a degraded session grant", effective)
	}
	if persisted := findGrant(t, readPersistedPermissions(t, config.LocalSettingsPath(cwd), cwd), "read_file"); persisted != effective[0] {
		t.Fatalf("local file holds %+v, want the approved grant %+v", persisted, effective[0])
	}
	requireRows(t, auth, localRow(cwd, effective[0]), tui.PermissionRow{Entry: effective[1]}, tui.PermissionRow{Entry: effective[2]})
}

func TestStartTUI_AuthorizerCarriesTheSelfTestResultAtEverySite(t *testing.T) {
	for _, tc := range selfTestCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			swapResolveExecutionCapability(t, tc.resolution)
			var auth *productionAuthorizer
			production := newSettingsDeps
			newSettingsDeps = func(app *tui.App, cache *config.Cache, active *model.ActiveState, a *productionAuthorizer) tui.SettingsDeps {
				auth = a
				return production(app, cache, active, a)
			}
			t.Cleanup(func() { newSettingsDeps = production })
			project := t.TempDir()
			_, restore := startCaptured(t, context.Background(), headlessResult(t, project, mode.NewActiveState(mode.Plan, mode.SourceDefault)), io.Discard)
			restore()
			if auth == nil || auth.executionConstrained != tc.want || auth.blocked == nil {
				t.Fatalf("authorizer = %+v, want executionConstrained %v and the live blocked list", auth, tc.want)
			}

			ctx := context.Background()
			req := permissions.MatchRequest{Kind: "direct", Subject: "touch x", SubjectTokens: []string{"touch", "x"}, PathScope: project}
			modeCtx := permissions.ModeContext{Class: permissions.ClassMutating}
			single, err := auth.Authorize(ctx, req, dispatch.PromptDisplay{}, modeCtx)
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			batch, err := auth.AuthorizeBatch(ctx, []dispatch.BatchAuthRequest{{Req: req, ModeCtx: modeCtx}})
			if err != nil || len(batch) != 1 {
				t.Fatalf("AuthorizeBatch = %+v, %v", batch, err)
			}
			independent, err := auth.AuthorizeIndependent(ctx, []dispatch.IndependentAuthRequest{{Req: req, ModeCtx: modeCtx}})
			if err != nil || len(independent) != 1 {
				t.Fatalf("AuthorizeIndependent = %+v, %v", independent, err)
			}
			for site, dec := range map[string]permissions.Decision{"Authorize": single, "AuthorizeBatch": batch[0], "AuthorizeIndependent": independent[0]} {
				if allowed := dec.Outcome == "once" && dec.DenyEnvelope == ""; allowed != tc.want {
					t.Errorf("%s decision = %+v, want confined allow %v", site, dec, tc.want)
				}
			}
			confined := 0
			for _, m := range decodeStoreEvents[events.PermissionMatched](t, auth.activeStore(), events.KindPermissionMatched) {
				if m.OutcomeSource == permissions.OutcomeSourceConfined {
					confined++
				}
			}
			want := 0
			if tc.want {
				want = 3
			}
			if confined != want {
				t.Fatalf("confined matches = %d, want %d", confined, want)
			}
		})
	}
}

func exceptionalTestAuthorizer(t *testing.T, m mode.Mode, constrained bool) (auth *productionAuthorizer, shown *[]tui.PromptRequest, home, cwd string) {
	t.Helper()
	prependFixturePrograms(t, "curl")
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home = t.TempDir()
	auth, shown = exceptionalAuthorizerAt(t, m, constrained, home, cwd)
	return auth, shown, home, cwd
}

func exceptionalAuthorizerAt(t *testing.T, m mode.Mode, constrained bool, home, cwd string) (*productionAuthorizer, *[]tui.PromptRequest) {
	t.Helper()
	app := tui.New(nil)
	app.SetActiveStore(mkStore(t))
	shown := &[]tui.PromptRequest{}
	show := func(pr tui.PromptRequest) (tui.PromptDecision, error) {
		*shown = append(*shown, pr)
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, mode.NewActiveState(m, mode.SourceUserCommand))
	auth.executionConstrained = constrained
	return auth, shown
}

var authorizerSites = map[string]func(*productionAuthorizer, dispatch.BatchAuthRequest) (permissions.Decision, error){
	"Authorize": func(a *productionAuthorizer, r dispatch.BatchAuthRequest) (permissions.Decision, error) {
		return a.Authorize(context.Background(), r.Req, r.Display, r.ModeCtx)
	},
	"AuthorizeBatch": func(a *productionAuthorizer, r dispatch.BatchAuthRequest) (permissions.Decision, error) {
		decs, err := a.AuthorizeBatch(context.Background(), []dispatch.BatchAuthRequest{r})
		if err != nil || len(decs) != 1 {
			return permissions.Decision{}, fmt.Errorf("AuthorizeBatch = %+v, %w", decs, err)
		}
		return decs[0], nil
	},
	"AuthorizeIndependent": func(a *productionAuthorizer, r dispatch.BatchAuthRequest) (permissions.Decision, error) {
		decs, err := a.AuthorizeIndependent(context.Background(), []dispatch.IndependentAuthRequest{{Req: r.Req, Display: r.Display, ModeCtx: r.ModeCtx}})
		if err != nil || len(decs) != 1 {
			return permissions.Decision{}, fmt.Errorf("AuthorizeIndependent = %+v, %w", decs, err)
		}
		return decs[0], nil
	},
}

func directShellAuthRequest(command, scope string) dispatch.BatchAuthRequest {
	tokens := strings.Fields(command)
	return dispatch.BatchAuthRequest{
		Req:     permissions.MatchRequest{Kind: "direct", Subject: command, SubjectTokens: tokens, PathScope: scope},
		Display: dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: command},
		ModeCtx: permissions.ModeContext{Class: permissions.ClassMutating, Stages: []permissions.StageNormalization{{Tokens: tokens, Source: command}}},
	}
}

func TestProductionAuthorizer_BrokenSettingsAsksBeforeConstrainedShellUntilFixed(t *testing.T) {
	for site, call := range authorizerSites {
		for _, m := range []mode.Mode{mode.Plan, mode.AutoEdits} {
			t.Run(site+"/"+string(m), func(t *testing.T) {
				f := newRereadFixture(t)
				f.writeGlobal(t, "a")
				auth, shown, _, cwd := exceptionalTestAuthorizer(t, m, true)
				auth.blocked = f.blocked(t, true)
				req := directShellAuthRequest("touch x", cwd)
				step := func(state string, wantPrompts int) {
					t.Helper()
					dec, err := call(auth, req)
					if err != nil || dec.Outcome != "once" {
						t.Fatalf("%s: decision = %+v, %v; want an allow", state, dec, err)
					}
					if len(*shown) != wantPrompts {
						t.Fatalf("%s: prompts = %d, want %d", state, len(*shown), wantPrompts)
					}
				}
				step("valid", 0)
				rewriteSettings(t, f.global, "blocked_paths: [\n")
				step("broken", 1)
				step("still broken", 2)
				f.editGlobal(t, "a")
				step("fixed", 2)
			})
		}
	}
}

func TestProductionAuthorizer_BrokenSettingsLeavesUnconstrainedShellUnchanged(t *testing.T) {
	for site, call := range authorizerSites {
		t.Run(site, func(t *testing.T) {
			f := newRereadFixture(t)
			f.writeGlobal(t, "a")
			blocked := f.blocked(t, true)
			rewriteSettings(t, f.global, "blocked_paths: [\n")
			for _, tc := range []struct {
				m        mode.Mode
				command  string
				outcome  string
				readOnly bool
			}{
				{mode.Plan, "touch x", "deny", false},
				{mode.Plan, "ls", "once", true},
				{mode.AutoEdits, "ls", "once", true},
			} {
				auth, shown, _, cwd := exceptionalTestAuthorizer(t, tc.m, false)
				auth.blocked = blocked
				dec, err := call(auth, directShellAuthRequest(tc.command, cwd))
				if err != nil || dec.Outcome != tc.outcome || dec.ReadOnlyAuto != tc.readOnly || len(*shown) != 0 {
					t.Fatalf("%s %q = %+v, %v with %d prompts; want %s without a prompt", tc.m, tc.command, dec, err, len(*shown), tc.outcome)
				}
				if !auth.blocked.Current().Degraded() || auth.settingsBroken() {
					t.Fatalf("settingsBroken = %v for an unconstrained run over a degraded list", auth.settingsBroken())
				}
			}
		})
	}
	auth, _, _, _ := exceptionalTestAuthorizer(t, mode.Plan, true)
	if auth.settingsBroken() {
		t.Fatal("a nil blocked list reads as broken settings")
	}
}

func TestProductionAuthorizer_ExceptionalShellPromptNamesTheAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, command, authority string
		check                    func(tui.PromptRequest) bool
	}{
		{"direct network", "curl https://example.com", "network access", func(pr tui.PromptRequest) bool {
			return pr.Subject == "curl https://example.com" && pr.Pipeline == "" && !pr.WholeCommand
		}},
		{"direct deletion", "rm -f out.txt", "file deletion", func(pr tui.PromptRequest) bool {
			return pr.Subject == "rm -f out.txt" && pr.Pipeline == ""
		}},
		{"pipeline with a later exceptional stage", "sort data.txt | curl -d @- https://example.com", "network access", func(pr tui.PromptRequest) bool {
			return pr.Subject == "curl -d @- https://example.com" && pr.Pipeline == "sort data.txt | curl -d @- https://example.com" && pr.BatchedStages == nil
		}},
		{"literal network", "sh -c 'curl https://example.com'", "network access", func(pr tui.PromptRequest) bool {
			return pr.Subject == "sh -c 'curl https://example.com'" && pr.WholeCommand
		}},
		{"literal deletion", "sh -c 'rm -f out.txt'", "file deletion", func(pr tui.PromptRequest) bool {
			return pr.Subject == "sh -c 'rm -f out.txt'" && pr.WholeCommand
		}},
		{"staged deletion then network", "rm -f out.txt && curl https://example.com", "network access", func(pr tui.PromptRequest) bool {
			return pr.Subject == "" && slices.Equal(pr.BatchedStages, []string{"rm -f out.txt", "curl https://example.com"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, home, cwd := exceptionalTestAuthorizer(t, mode.Build, false)
			prompted := func(m mode.Mode, constrained bool, runs int) tui.PromptRequest {
				t.Helper()
				auth, shown := exceptionalAuthorizerAt(t, m, constrained, home, cwd)
				for range runs {
					if _, err := dispatch.DispatchShell(context.Background(), tc.command, home, cwd, auth, &fakeDispatchRunner{}); err != nil {
						t.Fatalf("DispatchShell(%s, constrained %v): %v", m, constrained, err)
					}
				}
				if len(*shown) != runs {
					t.Fatalf("%s constrained %v showed %d prompts for %d runs, want one each", m, constrained, len(*shown), runs)
				}
				if grants := auth.grants.Permissions(); len(grants) != 0 {
					t.Fatalf("allow once stored grants %+v", grants)
				}
				return (*shown)[0]
			}
			marked := prompted(mode.AutoEdits, true, 2)
			if marked.Action != "Allow "+tc.authority || marked.ExceptionalAuthority != tc.authority || marked.Body != "" || !tc.check(marked) {
				t.Fatalf("prompt = %+v, want %q over the complete command", marked, "Allow "+tc.authority)
			}
			for _, posture := range []struct {
				m           mode.Mode
				constrained bool
			}{{mode.AutoEdits, false}, {mode.Build, true}, {mode.Build, false}} {
				ordinary := prompted(posture.m, posture.constrained, 1)
				if ordinary.Action != dispatch.ActionRunCommand || ordinary.ExceptionalAuthority != "" {
					t.Fatalf("%s constrained %v prompt = %+v, want today's action", posture.m, posture.constrained, ordinary)
				}
				ordinary.Action, ordinary.ExceptionalAuthority = marked.Action, marked.ExceptionalAuthority
				if !reflect.DeepEqual(ordinary, marked) {
					t.Fatalf("marked prompt %+v differs from the %s prompt %+v beyond its header", marked, posture.m, ordinary)
				}
			}
		})
	}
}

func TestProductionAuthorizer_ExceptionalHeaderReadsTheOverlaidMode(t *testing.T) {
	auth, shown, _, cwd := exceptionalTestAuthorizer(t, mode.AutoEdits, true)
	stage := func(source string) dispatch.BatchAuthRequest {
		tokens := strings.Fields(source)
		return dispatch.BatchAuthRequest{
			Req:     permissions.MatchRequest{Kind: "direct", Subject: source, SubjectTokens: tokens, PathScope: cwd},
			Display: dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: source},
			ModeCtx: permissions.ModeContext{Class: permissions.ClassMutating, Stages: []permissions.StageNormalization{{Tokens: tokens, Source: source}}},
		}
	}
	single := stage("curl https://example.com")
	if _, err := auth.Authorize(context.Background(), single.Req, single.Display, single.ModeCtx); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if _, err := auth.AuthorizeBatch(context.Background(), []dispatch.BatchAuthRequest{stage("rm -f a"), stage("curl https://example.com/b")}); err != nil {
		t.Fatalf("AuthorizeBatch: %v", err)
	}
	if len(*shown) != 2 {
		t.Fatalf("prompts = %d, want 2", len(*shown))
	}
	for i, pr := range *shown {
		if pr.Action != "Allow network access" || pr.ExceptionalAuthority != "network access" {
			t.Fatalf("prompt %d = %+v, want the network authority from the overlaid mode", i, pr)
		}
	}
}

func TestProductionAuthorizer_IndependentKeepsTheExceptionalMarker(t *testing.T) {
	auth, shown, _, cwd := exceptionalTestAuthorizer(t, mode.AutoEdits, true)
	literal := dispatch.IndependentAuthRequest{
		Req:     permissions.MatchRequest{Kind: "literal", Subject: "sh -c 'curl https://example.com'", PathScope: cwd},
		Display: dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: "sh -c 'curl https://example.com'", WholeCommand: true},
		ModeCtx: permissions.ModeContext{Class: permissions.ClassMutating},
	}
	if _, err := auth.AuthorizeIndependent(context.Background(), []dispatch.IndependentAuthRequest{literal}); err != nil {
		t.Fatalf("AuthorizeIndependent: %v", err)
	}
	if len(*shown) != 1 || (*shown)[0].ExceptionalAuthority != "network access" || (*shown)[0].Action != "Allow network access" {
		t.Fatalf("prompts = %+v, want one naming network access", *shown)
	}

	prompts := []permissions.BatchPromptRequest{
		{Req: permissions.MatchRequest{Kind: "literal", Subject: "x"}, Index: 0},
		{Req: permissions.MatchRequest{Kind: "literal", Subject: "x"}, Index: 1},
	}
	displays := []PromptDisplay{{Action: "Allow network access", ExceptionalAuthority: "network access"}, {Action: "Allow network access"}}
	if got := independentQuestions(prompts, displays); len(got) != 2 {
		t.Fatalf("questions = %v, want members with differing markers kept apart", got)
	}
}

func TestProductionAuthorizer_ExceptionalLeavesHostAndPlanAlone(t *testing.T) {
	auth, shown, home, cwd := exceptionalTestAuthorizer(t, mode.AutoEdits, true)
	if _, err := auth.Authorize(context.Background(), hostRequest("web_fetch", "example.com"), dispatch.PromptDisplay{HostRequest: "https://example.com"}, permissions.ModeContext{}); err != nil {
		t.Fatalf("Authorize host: %v", err)
	}
	if len(*shown) != 1 || (*shown)[0].Kind != tui.SubjectHost || (*shown)[0].ExceptionalAuthority != "" {
		t.Fatalf("host prompts = %+v, want one unmarked host prompt", *shown)
	}

	auth.modeActive = mode.NewActiveState(mode.Plan, mode.SourceDefault)
	if _, err := dispatch.DispatchShell(context.Background(), "curl https://example.com", home, cwd, auth, &fakeDispatchRunner{}); err != nil {
		t.Fatalf("DispatchShell plan: %v", err)
	}
	if len(*shown) != 1 {
		t.Fatalf("plan prompted %+v, want no exceptional prompt", (*shown)[1:])
	}
}

type modeSwitchCase struct {
	start, switched mode.Mode
	pinned          bool
}

func (c modeSwitchCase) name() string {
	pin := "unpinned"
	if c.pinned {
		pin = string(c.start) + " pin"
	}
	return pin + ", live " + string(c.start) + " to " + string(c.switched)
}

func (c modeSwitchCase) ctx() context.Context {
	if c.pinned {
		return vcs.WithConfinementMode(context.Background(), string(c.start))
	}
	return context.Background()
}

func (c modeSwitchCase) decidingMode() mode.Mode {
	if c.pinned {
		return c.start
	}
	return c.switched
}

var modeSwitchCases = []modeSwitchCase{
	{mode.Plan, mode.Build, true},
	{mode.AutoEdits, mode.Build, true},
	{mode.Build, mode.Plan, true},
	{mode.Build, mode.AutoEdits, true},
	{mode.Plan, mode.Build, false},
	{mode.Build, mode.Plan, false},
}

func TestProductionAuthorizer_EntryPinOutlivesASwitchBeforeAuthorization(t *testing.T) {
	sites := map[string]func(context.Context, *productionAuthorizer, dispatch.BatchAuthRequest) (permissions.Decision, error){
		"Authorize": func(ctx context.Context, a *productionAuthorizer, r dispatch.BatchAuthRequest) (permissions.Decision, error) {
			return a.Authorize(ctx, r.Req, r.Display, r.ModeCtx)
		},
		"AuthorizeBatch": func(ctx context.Context, a *productionAuthorizer, r dispatch.BatchAuthRequest) (permissions.Decision, error) {
			decs, err := a.AuthorizeBatch(ctx, []dispatch.BatchAuthRequest{r})
			if err != nil || len(decs) != 1 {
				return permissions.Decision{}, fmt.Errorf("AuthorizeBatch = %+v, %w", decs, err)
			}
			return decs[0], nil
		},
		"AuthorizeIndependent": func(ctx context.Context, a *productionAuthorizer, r dispatch.BatchAuthRequest) (permissions.Decision, error) {
			decs, err := a.AuthorizeIndependent(ctx, []dispatch.IndependentAuthRequest{{Req: r.Req, Display: r.Display, ModeCtx: r.ModeCtx}})
			if err != nil || len(decs) != 1 {
				return permissions.Decision{}, fmt.Errorf("AuthorizeIndependent = %+v, %w", decs, err)
			}
			return decs[0], nil
		},
	}
	for site, call := range sites {
		for _, tc := range modeSwitchCases {
			t.Run(site+"/"+tc.name(), func(t *testing.T) {
				auth, shown, _, cwd := exceptionalTestAuthorizer(t, tc.start, true)
				auth.modeActive.ApplyUserCommand(tc.switched)
				dec, err := call(tc.ctx(), auth, directShellAuthRequest("touch x", cwd))
				if err != nil || dec.Outcome != "once" {
					t.Fatalf("decision = %+v, %v; want an allow", dec, err)
				}
				wantPrompts := 0
				if tc.decidingMode() == mode.Build {
					wantPrompts = 1
				}
				if len(*shown) != wantPrompts {
					t.Fatalf("prompts = %d, want %d — the mutation must be decided under %q", len(*shown), wantPrompts, tc.decidingMode())
				}
			})
		}
	}
}

var failedSelfTest = enforce.Resolution{Capability: enforce.Refused, Reason: "test: no self-test"}

func writableFoldersYAML(folders ...string) string {
	if len(folders) == 0 {
		return "writable_folders: []\n"
	}
	return "writable_folders:\n  - " + strings.Join(folders, "\n  - ") + "\n"
}

type writableLaunch struct {
	home, project, folder, target string
	decision                      trust.Decision
	composition                   ConfigComposition
	layers                        []securitystate.LayerSnapshot
	layerPaths                    []string
}

func gateWritableLaunch(t *testing.T, home, project string, approved bool, projectYAML func(folder string) string) writableLaunch {
	t.Helper()
	l := writableLaunch{home: home, project: project, folder: declaredScopeDir(t)}
	l.target = filepath.Join(l.folder, "notes.txt")
	writeGlobalSettings(t, home, blockedYAML(), 0o600)
	writeProjectSettings(t, project, projectYAML(l.folder))
	if approved {
		approveRoot(t, home, project)
	}
	l.decision = headlessTrustGate(io.Discard)(home, project, project)
	global, err := defaultLoadGlobalSettings(home)
	if err != nil {
		t.Fatalf("defaultLoadGlobalSettings: %v", err)
	}
	composeRoot := project
	l.layerPaths = []string{SettingsPath(home), projectSettingsPath(project)}
	if !vcsTemplatesApproved(l.decision) {
		composeRoot = ""
		l.layerPaths = l.layerPaths[:1]
	}
	if l.composition, err = defaultComposeConfig(global, composeRoot); err != nil {
		t.Fatalf("defaultComposeConfig: %v", err)
	}
	l.layers = settingsLayerSnapshots(home, project, global, l.decision.Trusted, l.composition)
	return l
}

func declaringWritableFolder(folder string) string { return writableFoldersYAML(folder) }

func requireUnapprovedLaunchWithholdsFolders(t *testing.T, l writableLaunch, cache *config.Cache) {
	t.Helper()
	if l.decision.Trusted || l.decision.Reason != trust.ReasonNoRecord {
		t.Fatalf("trust decision = %+v, want untrusted with %q", l.decision, trust.ReasonNoRecord)
	}
	if l.composition.ProjectPresent || l.composition.ProjectLayer != nil {
		t.Fatalf("composition = %+v, want the project layer withheld", l.composition)
	}
	if _, ok := l.composition.Config["writable_folders"]; ok {
		t.Fatalf("composed config = %+v, want no writable_folders", l.composition.Config)
	}
	if folders := cache.WritableFolders(); len(folders) != 0 {
		t.Fatalf("cache writable folders = %v, want none", folders)
	}
}

type writableHarness struct {
	auth       *productionAuthorizer
	dispatcher *productionToolDispatcher
	store      *sessions.Store
	cache      *config.Cache
	prompts    int
	answer     bool
}

func newWritableHarness(t *testing.T, l writableLaunch, resolution enforce.Resolution) *writableHarness {
	t.Helper()
	cache, err := config.NewCache(l.composition.Config, l.project, l.layerPaths, l.home)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	guard := mustProtectedStatePolicy(t, l.home, l.project, l.layers)
	h := &writableHarness{store: mkStore(t), cache: cache}
	app := tui.New(nil)
	app.SetActiveStore(h.store)
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		h.prompts++
		if !h.answer {
			return tui.PromptDecision{}, errors.New("no prompt expected")
		}
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	h.auth = newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(show), l.home, l.project, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))
	h.auth.executionConstrained = resolution.SelfTestPassed
	h.auth.blocked = guard.Blocked
	active := func() *sessions.Store { return h.store }
	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, active, l.home, l.project, guard)
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}
	h.dispatcher = newProductionToolDispatcher(reg, &fakeDispatchRunner{}, h.auth, l.home, l.project, active, cache.MaxToolOutputBytes(), guard)
	return h
}

func (h *writableHarness) edit(t *testing.T, target string, wantPrompts int) {
	t.Helper()
	if err := os.WriteFile(target, []byte("old\n"), 0o600); err != nil {
		t.Fatalf("seed %s: %v", target, err)
	}
	h.answer = wantPrompts > 0
	before := h.prompts
	call := turn.AssembledToolCall{ID: "c1", Name: filetools.EditToolName, Arguments: toolArgs(t, map[string]any{"path": target, "old_text": "old", "new_text": "new"})}
	res, err := h.dispatcher.Dispatch(context.Background(), call)
	if err != nil || res.Denied || res.WriteTarget != target {
		t.Fatalf("Dispatch(edit) = %+v, %v; want a successful edit of %s", res, err, target)
	}
	if got := mustReadFile(t, target); got != "new\n" {
		t.Fatalf("%s = %q, want the edit applied", target, got)
	}
	if got := h.prompts - before; got != wantPrompts {
		t.Fatalf("prompts = %d, want %d", got, wantPrompts)
	}
}

func (h *writableHarness) modeAutoAllows(t *testing.T) []events.PermissionMatched {
	t.Helper()
	var out []events.PermissionMatched
	for _, m := range decodePermissionMatched(t, reloadStore(t, h.store)) {
		if m.OutcomeSource == "mode_auto" {
			out = append(out, m)
		}
	}
	return out
}

func writableEditRequest(l writableLaunch) dispatch.BatchAuthRequest {
	return dispatch.BatchAuthRequest{
		Req:     permissions.MatchRequest{Kind: "tool", Subject: filetools.EditToolName, PathScope: l.folder},
		Display: dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: filetools.EditToolName},
		ModeCtx: permissions.ModeContext{Class: permissions.ClassMutating, ToolName: filetools.EditToolName, TargetPath: l.target},
	}
}

func TestProductionAuthorizer_WritableFolderEditIsAutoAllowedUnderAConstrainedLaunch(t *testing.T) {
	l := gateWritableLaunch(t, declaredScopeDir(t), declaredScopeDir(t), true, declaringWritableFolder)
	h := newWritableHarness(t, l, constrainedLaunch)
	if got := h.cache.WritableFolders(); !slices.Equal(got, []string{l.folder}) {
		t.Fatalf("cache writable folders = %v, want [%s]", got, l.folder)
	}

	h.edit(t, l.target, 0)

	want := events.PermissionMatched{SubjectKind: "tool", Subject: filetools.EditToolName, PathScope: l.folder, Outcome: "once", OutcomeSource: "mode_auto"}
	if matched := decodePermissionMatched(t, reloadStore(t, h.store)); len(matched) != 1 || matched[0] != want {
		t.Fatalf("permission_matched on disk = %+v, want exactly %+v", matched, want)
	}
}

func TestProductionAuthorizer_WritableFolderEditPromptsWithoutAPassedSelfTest(t *testing.T) {
	l := gateWritableLaunch(t, declaredScopeDir(t), declaredScopeDir(t), true, declaringWritableFolder)
	h := newWritableHarness(t, l, failedSelfTest)

	h.edit(t, l.target, 1)

	if allows := h.modeAutoAllows(t); len(allows) != 0 {
		t.Fatalf("mode_auto matches = %+v, want none", allows)
	}
}

func TestProductionAuthorizer_WritableFolderEditFollowsBrokenSettingsUntilFixed(t *testing.T) {
	l := gateWritableLaunch(t, declaredScopeDir(t), declaredScopeDir(t), true, declaringWritableFolder)
	h := newWritableHarness(t, l, constrainedLaunch)
	global := SettingsPath(l.home)

	h.edit(t, l.target, 0)
	if n := len(h.modeAutoAllows(t)); n != 1 {
		t.Fatalf("mode_auto matches after the valid edit = %d, want 1", n)
	}

	rewriteSettings(t, global, "blocked_paths: [\n")
	live := liveExecutionCapability(constrainedLaunch, h.auth.blocked.Current().Degraded())
	if live.Capability != enforce.Refused || live.Reason != "settings file is broken" {
		t.Fatalf("displayed capability = %+v, want refused with %q", live, "settings file is broken")
	}
	if len(h.auth.writableFolders) == 0 {
		t.Fatal("the cached writable-folder snapshot is empty")
	}
	h.edit(t, l.target, 1)
	if n := len(h.modeAutoAllows(t)); n != 1 {
		t.Fatalf("mode_auto matches after the broken edit = %d, want still 1", n)
	}

	rewriteSettings(t, global, blockedYAML())
	h.edit(t, l.target, 0)
	if n := len(h.modeAutoAllows(t)); n != 2 {
		t.Fatalf("mode_auto matches after the fix = %d, want 2", n)
	}
}

func TestProductionAuthorizer_WritableFolderOverlayAtTheBatchSeams(t *testing.T) {
	for _, site := range []string{"AuthorizeBatch", "AuthorizeIndependent"} {
		t.Run(site, func(t *testing.T) {
			l := gateWritableLaunch(t, declaredScopeDir(t), declaredScopeDir(t), true, declaringWritableFolder)
			h := newWritableHarness(t, l, constrainedLaunch)
			global := SettingsPath(l.home)
			step := func(state string, wantPrompts int, wantAllows int) {
				t.Helper()
				h.answer = wantPrompts > 0
				before := h.prompts
				dec, err := authorizerSites[site](h.auth, writableEditRequest(l))
				if err != nil || dec.Outcome != "once" {
					t.Fatalf("%s: decision = %+v, %v; want an allow", state, dec, err)
				}
				if got := h.prompts - before; got != wantPrompts {
					t.Fatalf("%s: prompts = %d, want %d", state, got, wantPrompts)
				}
				if n := len(h.modeAutoAllows(t)); n != wantAllows {
					t.Fatalf("%s: mode_auto matches = %d, want %d", state, n, wantAllows)
				}
			}
			step("valid", 0, 1)
			rewriteSettings(t, global, "blocked_paths: [\n")
			step("broken", 1, 1)
			rewriteSettings(t, global, blockedYAML())
			step("fixed", 0, 2)
		})
	}
}

func TestProductionAuthorizer_AbsentOrEmptyWritableFoldersKeepTheOutOfRootPrompt(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml func(string) string
	}{
		{"absent", func(string) string { return blockedYAML() }},
		{"empty", func(string) string { return writableFoldersYAML() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := gateWritableLaunch(t, declaredScopeDir(t), declaredScopeDir(t), true, tc.yaml)
			h := newWritableHarness(t, l, constrainedLaunch)
			if !l.decision.Trusted || len(h.cache.WritableFolders()) != 0 || len(h.auth.writableFolders) != 0 {
				t.Fatalf("decision = %+v, cache folders = %v, authorizer folders = %v; want a trusted project with none", l.decision, h.cache.WritableFolders(), h.auth.writableFolders)
			}

			h.edit(t, l.target, 1)
			for site, call := range authorizerSites {
				h.auth.resetTurnCache()
				h.answer = true
				before := h.prompts
				if dec, err := call(h.auth, writableEditRequest(l)); err != nil || dec.Outcome != "once" || h.prompts-before != 1 {
					t.Fatalf("%s = %+v, %v with %d prompts; want one prompt", site, dec, err, h.prompts-before)
				}
			}
			if allows := h.modeAutoAllows(t); len(allows) != 0 {
				t.Fatalf("mode_auto matches = %+v, want none", allows)
			}
		})
	}
}

func TestProductionAuthorizer_UnapprovedProjectWritableFoldersHaveNoEffect(t *testing.T) {
	l := gateWritableLaunch(t, declaredScopeDir(t), declaredScopeDir(t), false, declaringWritableFolder)
	h := newWritableHarness(t, l, constrainedLaunch)
	requireUnapprovedLaunchWithholdsFolders(t, l, h.cache)

	h.edit(t, l.target, 1)

	if allows := h.modeAutoAllows(t); len(allows) != 0 {
		t.Fatalf("mode_auto matches = %+v, want none", allows)
	}
}
