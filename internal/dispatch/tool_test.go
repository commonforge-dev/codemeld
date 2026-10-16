// Unit tests for DispatchTool: registry-miss handling, authorized/denied invocation, exact tool
// MatchRequest fields, and vcs_<action> routing including effective-cwd path scope and the VCS
// launch-failure cwd errors, using fake tools/authorizer and real registered ActionTools.
package dispatch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/permissions"
	cmdrunner "codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/vcs"
)

// fakeTool is a structured tool with no distinct execution directory: dispatch authorizes it against
// the process cwd. It records whether Invoke ran and the args it received, and returns a canned result.
type fakeTool struct {
	name     string
	result   tools.Result
	readOnly bool
	invoked  bool
	gotArgs  map[string]any
}

var _ tools.Tool = (*fakeTool)(nil)

func (f *fakeTool) Name() string              { return f.name }
func (f *fakeTool) SubjectKind() string       { return "tool" }
func (f *fakeTool) Advertise() tools.Metadata { return tools.Metadata{ReadOnly: f.readOnly} }

func (f *fakeTool) Invoke(_ context.Context, args map[string]any) (tools.Result, error) {
	f.invoked = true
	f.gotArgs = args
	return f.result, nil
}

// fakeTargetTool is a structured tool whose target is resolved before authorization (the edit-tool
// shape): it stands in for the targetScopedTool/resolvedTargetInvoker seams so the dispatch ordering
// (resolve → authorize the resolved scope → invoke with the resolved target) is testable without the
// real edit tool. It records the target it was invoked with so a test can prove the authorized target,
// not a re-resolved one, reaches invocation.
type fakeTargetTool struct {
	name          string
	target        string
	scope         string
	resolveErr    error
	result        tools.Result
	invoked       bool
	invokedTarget string
}

var (
	_ tools.Tool = (*fakeTargetTool)(nil)
)

func (f *fakeTargetTool) Name() string              { return f.name }
func (f *fakeTargetTool) SubjectKind() string       { return "tool" }
func (f *fakeTargetTool) Advertise() tools.Metadata { return tools.Metadata{} }

func (f *fakeTargetTool) ResolveTarget(map[string]any) (string, string, error) {
	if f.resolveErr != nil {
		return "", "", f.resolveErr
	}
	return f.target, f.scope, nil
}

func (f *fakeTargetTool) InvokeWithResolvedTarget(_ context.Context, _ map[string]any, resolvedTarget string) (tools.Result, error) {
	f.invoked = true
	f.invokedTarget = resolvedTarget
	return f.result, nil
}

// Invoke is the Tool-interface fallback; dispatch routes a resolvedTargetInvoker through
// InvokeWithResolvedTarget, so reaching this in a target-scoped test is itself a failure.
func (f *fakeTargetTool) Invoke(context.Context, map[string]any) (tools.Result, error) {
	f.invoked = true
	return f.result, nil
}

// fakeDelegateTool stands in for the real delegate tool so the dispatch ordering (prepare →
// authorize the candidate → invoke from it) is testable without starting a child agent. It records
// what invocation received so a test can prove no second resolution of the raw declaration ran.
type fakeDelegateTool struct {
	name            string
	instruction     string
	declared        map[string]bool
	remove          map[string]bool
	moves           map[permissions.MovePair]bool
	targets         []string
	prepareErr      error
	result          tools.Result
	invoked         bool
	invokedArgs     bool
	invokedInstr    string
	invokedDeclared map[string]bool
	invokedRemove   map[string]bool
	invokedMoves    map[permissions.MovePair]bool
}

var _ tools.Tool = (*fakeDelegateTool)(nil)

func (f *fakeDelegateTool) Name() string              { return f.name }
func (f *fakeDelegateTool) SubjectKind() string       { return "tool" }
func (f *fakeDelegateTool) Advertise() tools.Metadata { return tools.Metadata{} }

func (f *fakeDelegateTool) PrepareDelegate(map[string]any) (string, map[string]bool, map[string]bool, map[permissions.MovePair]bool, []string, error) {
	if f.prepareErr != nil {
		return "", nil, nil, nil, nil, f.prepareErr
	}
	return f.instruction, f.declared, f.remove, f.moves, f.targets, nil
}

func (f *fakeDelegateTool) InvokeWithPreparedDelegate(_ context.Context, instruction string, declared, remove map[string]bool, moves map[permissions.MovePair]bool) (tools.Result, error) {
	f.invoked = true
	f.invokedInstr = instruction
	f.invokedDeclared = declared
	f.invokedRemove = remove
	f.invokedMoves = moves
	return f.result, nil
}

// Invoke is the Tool-interface fallback; dispatch routes a preparedDelegateTool through
// InvokeWithPreparedDelegate, so reaching this would be a second resolution of the raw arguments.
func (f *fakeDelegateTool) Invoke(context.Context, map[string]any) (tools.Result, error) {
	f.invoked, f.invokedArgs = true, true
	return f.result, nil
}

// fakeMoveTool is a multi-scope (move-shaped) structured tool: it resolves two endpoints before
// authorization (a canned filetools.ResolvedMove) and is invoked with the resolved pair, standing in for
// the real move tool so the dispatch multi-scope ordering (resolve → authorize each unique scope → invoke
// with the resolved endpoints) is testable without the real move tool. It records the resolved value it
// was invoked with so a test can prove invocation reused the authorized resolution rather than
// re-resolving from arguments.
type fakeMoveTool struct {
	name            string
	resolved        filetools.ResolvedMove
	resolveErr      error
	result          tools.Result
	invoked         bool
	invokedResolved filetools.ResolvedMove
}

var _ tools.Tool = (*fakeMoveTool)(nil)

func (f *fakeMoveTool) Name() string              { return f.name }
func (f *fakeMoveTool) SubjectKind() string       { return "tool" }
func (f *fakeMoveTool) Advertise() tools.Metadata { return tools.Metadata{} }

func (f *fakeMoveTool) ResolveEndpoints(map[string]any) (filetools.ResolvedMove, error) {
	if f.resolveErr != nil {
		return filetools.ResolvedMove{}, f.resolveErr
	}
	return f.resolved, nil
}

func (f *fakeMoveTool) InvokeWithResolvedMove(_ context.Context, resolved filetools.ResolvedMove) (tools.Result, error) {
	f.invoked = true
	f.invokedResolved = resolved
	return f.result, nil
}

// Invoke is the Tool-interface fallback; dispatch routes a multiScopeFileTool through
// InvokeWithResolvedMove, so reaching this in a move test is itself a failure.
func (f *fakeMoveTool) Invoke(context.Context, map[string]any) (tools.Result, error) {
	f.invoked = true
	return f.result, nil
}

// denyScopeAuthorizer grants every authorization except one denied path scope. A move's source and
// destination authorizations share the bare "move" subject, so the shared fakeAuthorizer (keyed on
// subject) cannot grant one endpoint and deny the other; this authorizer keys on req.PathScope instead so
// a destination-denial test can grant the source scope and deny the destination scope. It records each
// request in order so the test can assert the source-then-destination ordering and non-invocation.
type denyScopeAuthorizer struct {
	denyScope string
	envelope  string
	requests  []permissions.MatchRequest
}

func (a *denyScopeAuthorizer) Authorize(_ context.Context, req permissions.MatchRequest, _ PromptDisplay, _ permissions.ModeContext) (permissions.Decision, error) {
	a.requests = append(a.requests, req)
	if req.PathScope == a.denyScope {
		return denyDecision(a.envelope), nil
	}
	return grantDecision(), nil
}

// fakeCmdRunner is a runner.Runner stub for building real vcs.ActionTools without launching
// processes: it mints a fixed invocation id, counts Exec calls, records the spec, and returns a
// preset RunResult.
type fakeCmdRunner struct {
	id      string
	result  cmdrunner.RunResult
	calls   int
	gotSpec cmdrunner.RunSpec
}

var _ cmdrunner.Runner = (*fakeCmdRunner)(nil)

func (f *fakeCmdRunner) NewInvocationID() string { return f.id }

func (f *fakeCmdRunner) Exec(_ context.Context, spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
	f.calls++
	f.gotSpec = spec
	res := f.result
	if res.InvocationID == "" {
		res.InvocationID = spec.InvocationID
	}
	return res, nil
}

func noopEmit(events.EventPayload) error { return nil }

// registerGitStatus registers a single git "status" action under vcs_status in reg via the real
// RegisterActions, so dispatch routes through a genuine *vcs.ActionTool. The output cap is the
// sessions.max_tool_output_bytes parameter; these dispatch tests use a generous cap that never
// truncates so they assert routing/cwd behavior, not truncation.
func registerGitStatus(t *testing.T, reg *tools.Registry, repoRoot string, status vcs.ActionSpec, run cmdrunner.Runner, emit vcs.EventAppender) {
	t.Helper()
	tmpl := &vcs.Template{
		Name:    "git",
		Source:  "/etc/codemeld/vcs/git.yaml",
		Detect:  &vcs.DetectSpec{Marker: ".git"},
		Actions: map[string]vcs.ActionSpec{"status": status},
	}
	if err := vcs.RegisterActions(reg, tmpl, repoRoot, run, emit, 65536); err != nil {
		t.Fatalf("RegisterActions: %v", err)
	}
}

func TestDispatchTool_BuiltinAuthorizedInvokes(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	wantScope := mustEval(t, cwd)

	ft := &fakeTool{name: "read_file", result: tools.Result{ExitCode: 0, Stdout: []byte("contents")}}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"read_file": {decision: grantDecision()},
	}}
	args := map[string]any{"path": "x.go"}

	res, err := DispatchTool(context.Background(), "read_file", args, home, cwd, reg, auth)
	if err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	if !ft.invoked {
		t.Fatal("tool was not invoked after authorization granted")
	}
	if !reflect.DeepEqual(ft.gotArgs, args) {
		t.Fatalf("Invoke args = %v, want %v (args passed straight through)", ft.gotArgs, args)
	}
	if string(res.Stdout) != "contents" || res.ExitCode != 0 {
		t.Fatalf("result = %+v, want stdout contents exit 0", res)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1", len(auth.requests))
	}
	got := auth.requests[0]
	if got.Kind != "tool" || got.Subject != "read_file" {
		t.Fatalf("MatchRequest kind/subject = %q/%q, want tool/read_file", got.Kind, got.Subject)
	}
	// the mode context carries the tool name and the single read-only class.
	mc := auth.modeCtxs[0]
	if mc.ToolName != "read_file" {
		t.Fatalf("mode context ToolName = %q, want read_file", mc.ToolName)
	}
	if mc.Class != permissions.ClassMutating {
		t.Fatalf("mode context Class = %q, want mutating (fakeTool defaults to non-read-only)", mc.Class)
	}
	if got.SubjectTokens != nil {
		t.Fatalf("SubjectTokens = %v, want nil for a tool subject", got.SubjectTokens)
	}
	if got.PathScope != wantScope {
		t.Fatalf("PathScope = %q, want %q (process cwd for a default tool)", got.PathScope, wantScope)
	}
}

// TestDispatchTool_ModeContextReadOnlyClass proves a tool advertised read-only
// (Advertise().ReadOnly) is carried into the mode context as the read_only operation class — the
// single classification Plan posture and tool advertising share.
func TestDispatchTool_ModeContextReadOnlyClass(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()

	ft := &fakeTool{name: "list_dir", readOnly: true}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{"list_dir": {decision: grantDecision()}}}

	if _, err := DispatchTool(context.Background(), "list_dir", nil, home, cwd, reg, auth); err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	mc := auth.modeCtxs[0]
	if mc.Class != permissions.ClassReadOnly {
		t.Fatalf("mode context Class = %q, want read_only for a read-only tool", mc.Class)
	}
	if mc.ToolName != "list_dir" {
		t.Fatalf("mode context ToolName = %q, want list_dir", mc.ToolName)
	}
}

// TestDispatchTool_OtherToolPromptDisplayCarriesFullCall proves an unmapped structured tool's
// authorization shows the generic "Run tool" action over the bare registered name, with the full
// name+args call as the verbatim body, while the matching subject stays the bare
// registered tool name (matching must ignore args). The action header never leaks the bare tool token;
// a tool invoked with no arguments is the only case where the body equals the subject.
func TestDispatchTool_OtherToolPromptDisplayCarriesFullCall(t *testing.T) {
	cases := []struct {
		name     string
		args     map[string]any
		wantBody string
	}{
		{"with args shows full call", map[string]any{"path": "x.go"}, `read_file({"path":"x.go"})`},
		{"sorted multi-arg call is deterministic", map[string]any{"b": "2", "a": "1"}, `read_file({"a":"1","b":"2"})`},
		{"no args is the bare name", nil, "read_file"},
		{"empty args is the bare name", map[string]any{}, "read_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			cwd := t.TempDir()
			ft := &fakeTool{name: "read_file"}
			reg := tools.NewRegistry()
			if err := reg.Register(tools.BuiltinSource, ft); err != nil {
				t.Fatalf("Register: %v", err)
			}
			auth := &fakeAuthorizer{bySubject: map[string]authBehavior{"read_file": {decision: grantDecision()}}}

			if _, err := DispatchTool(context.Background(), "read_file", tc.args, home, cwd, reg, auth); err != nil {
				t.Fatalf("DispatchTool: %v", err)
			}
			if len(auth.displays) != 1 {
				t.Fatalf("authorize calls = %d, want 1", len(auth.displays))
			}
			want := PromptDisplay{Action: ActionRunTool, Subject: "read_file", Body: tc.wantBody}
			if got := auth.displays[0]; got != want {
				t.Fatalf("prompt display = %+v, want %+v", got, want)
			}
			if got := auth.displays[0].Action; got == "read_file" {
				t.Fatalf("action header leaked the bare tool token %q", got)
			}
			if got := auth.requests[0].Subject; got != "read_file" {
				t.Fatalf("matching subject = %q, want the bare registered name read_file (matching must ignore args)", got)
			}
		})
	}
}

// TestDispatchTool_FileToolPromptDisplayShowsFileAndContent proves the create/edit/delete file tools show
// a plain action over the affected filename and the verbatim payload, not the JSON call: create
// shows "Create file" + the path + the file content exactly as decoded (no injected line numbers); edit
// shows "Edit file" + the path + the pre-authorization unified patch; delete shows "Delete file" + the path with no body
// (the irreversible removal of the named path is the whole approval) and — unlike create/edit — folds to
// no capability, so a delete approval never rides a "write" grant. The matching subject stays the bare
// registered name so grants/events are unaffected. fakeTools registered under the tool names exercise the
// name→display mapping in isolation; the production end-to-end create prompt is pinned in
// internal/bootstrap (authdeps_test.go).
func TestDispatchTool_FileToolPromptDisplayShowsFileAndContent(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()

	t.Run("create shows the filename and verbatim content", func(t *testing.T) {
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, &fakeTool{name: filetools.CreateToolName}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.CreateToolName: {decision: grantDecision()}}}
		content := "1. Alberta\n2. British Columbia\n"
		args := map[string]any{"path": "provinces.md", "content": content}

		if _, err := DispatchTool(context.Background(), filetools.CreateToolName, args, home, cwd, reg, auth); err != nil {
			t.Fatalf("DispatchTool: %v", err)
		}
		want := PromptDisplay{Action: ActionCreateFile, Subject: "provinces.md", RequestedTarget: "provinces.md", Body: content, GrantStoredSubject: permissions.CapabilityWriteTree}
		if got := auth.displays[0]; got != want {
			t.Fatalf("create prompt display = %+v, want %+v", got, want)
		}
		if got := auth.requests[0].Subject; got != filetools.CreateToolName {
			t.Fatalf("matching subject = %q, want the bare registered name %q", got, filetools.CreateToolName)
		}
	})

	t.Run("edit shows the filename and the pre-authorization unified patch", func(t *testing.T) {
		project := mustEval(t, t.TempDir())
		target := filepath.Join(project, "main.go")
		if err := os.WriteFile(target, []byte("package main\n\nfunc main() {\n\tfoo()\n}\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, filetools.NewEditTool(home, project, project)); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.EditToolName: {decision: grantDecision()}}}
		args := map[string]any{"path": "main.go", "old_text": "foo()", "new_text": "bar()"}

		if _, err := DispatchTool(context.Background(), filetools.EditToolName, args, home, project, reg, auth); err != nil {
			t.Fatalf("DispatchTool: %v", err)
		}
		got := auth.displays[0]
		if got.Action != ActionEditFile || got.Subject != "main.go" || got.GrantStoredSubject != permissions.CapabilityWriteTree {
			t.Fatalf("edit prompt display = %+v, want the edit action over main.go folded to %q", got, permissions.CapabilityWriteTree)
		}
		for _, want := range []string{"--- " + target + "\n", "+++ " + target + "\n", "@@", "-\tfoo()\n", "+\tbar()\n", " func main() {\n"} {
			if !strings.Contains(got.Body, want) {
				t.Fatalf("edit prompt body missing %q\n--- got ---\n%s", want, got.Body)
			}
		}
		if strings.Contains(got.Body, "Replace:") || strings.Contains(got.Body, "With:") {
			t.Fatalf("edit prompt body still carries the old Replace/With snippet\n--- got ---\n%s", got.Body)
		}
	})

	t.Run("a failed preview refuses in-band without prompting or writing", func(t *testing.T) {
		project := mustEval(t, t.TempDir())
		target := filepath.Join(project, "main.go")
		const original = "package main\n\nfunc main() {\n\tfoo()\n\tfoo()\n}\n"
		if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, filetools.NewEditTool(home, project, project)); err != nil {
			t.Fatalf("Register: %v", err)
		}

		cases := []struct {
			name string
			args map[string]any
			want string
		}{
			{"ambiguous", map[string]any{"path": "main.go", "old_text": "foo()", "new_text": "bar()"}, "matches 2 times"},
			{"stale", map[string]any{"path": "main.go", "old_text": "absent()", "new_text": "bar()"}, "was not found in the file"},
			{"unchanged", map[string]any{"path": "main.go", "old_text": "foo()", "new_text": "foo()"}, "there is no change to apply"},
			{"empty old_text", map[string]any{"path": "main.go", "old_text": "", "new_text": "bar()"}, "old_text must be non-empty"},
			{"malformed new_text", map[string]any{"path": "main.go", "old_text": "foo()", "new_text": 7}, "new_text"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.EditToolName: {decision: grantDecision()}}}
				res, err := DispatchTool(context.Background(), filetools.EditToolName, tc.args, home, project, reg, auth)
				if err != nil {
					t.Fatalf("DispatchTool error = %v, want the in-band refusal result the model sees", err)
				}
				if res.ExitCode == 0 || !strings.Contains(string(res.Stderr)+string(res.Stdout), tc.want) {
					t.Fatalf("result = %+v, want a non-zero-exit refusal mentioning %q", res, tc.want)
				}
				if len(auth.requests) != 0 {
					t.Fatalf("authorize calls = %d, want 0 (a preview failure must not prompt or create a grant)", len(auth.requests))
				}
				if data, rerr := os.ReadFile(target); rerr != nil || string(data) != original {
					t.Fatalf("target = %q (err %v), want byte-identical %q (preview must never write)", string(data), rerr, original)
				}
			})
		}
	})

	t.Run("delete shows the filename with no body and no capability folding", func(t *testing.T) {
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, &fakeTool{name: filetools.DeleteToolName}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.DeleteToolName: {decision: grantDecision()}}}
		args := map[string]any{"path": "doomed.txt"}

		if _, err := DispatchTool(context.Background(), filetools.DeleteToolName, args, home, cwd, reg, auth); err != nil {
			t.Fatalf("DispatchTool: %v", err)
		}
		// Empty GrantStoredSubject: delete is not a write-capability member, so a delete approval stores a
		// concrete "delete" grant, never the folded "write" subject that authorizes create/edit. This is the
		// delete-tool guardrail that a delete never rides a create/edit grant.
		want := PromptDisplay{Action: ActionDeleteFile, Subject: "doomed.txt", RequestedTarget: "doomed.txt", Body: "", GrantStoredSubject: ""}
		if got := auth.displays[0]; got != want {
			t.Fatalf("delete prompt display = %+v, want %+v", got, want)
		}
		if got := auth.requests[0].Subject; got != filetools.DeleteToolName {
			t.Fatalf("matching subject = %q, want the bare registered name %q", got, filetools.DeleteToolName)
		}
	})
}

func TestDispatchTool_DeniedDoesNotInvoke(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	env := permissions.BuildDenyEnvelope("nope")

	ft := &fakeTool{name: "write_file"}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"write_file": {decision: denyDecision(env), prompts: true},
	}}

	_, err := DispatchTool(context.Background(), "write_file", nil, home, cwd, reg, auth)
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want *DeniedError", err)
	}
	if de.Envelope != env {
		t.Fatalf("DeniedError.Envelope = %q, want %q", de.Envelope, env)
	}
	if ft.invoked {
		t.Fatal("denied tool must not be invoked")
	}
}

func TestDispatchTool_UnknownReturnsNoSuchToolWithoutPrompting(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	reg := tools.NewRegistry()
	// Empty bySubject with nil fallback: any Authorize call errors, so a stray prompt is caught too.
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{}}

	_, err := DispatchTool(context.Background(), "vcs_status", nil, home, cwd, reg, auth)
	var nst *NoSuchToolError
	if !errors.As(err, &nst) {
		t.Fatalf("error = %v, want *NoSuchToolError", err)
	}
	if nst.Name != "vcs_status" {
		t.Fatalf("NoSuchToolError.Name = %q, want vcs_status", nst.Name)
	}
	if len(auth.requests) != 0 {
		t.Fatalf("authorize calls = %d, want 0 (unknown tool, incl. no-active-VCS miss, must not prompt)", len(auth.requests))
	}
}

func TestDispatchTool_VCSActionRoutesThroughRegisteredTool(t *testing.T) {
	home := t.TempDir()
	processCWD := t.TempDir()
	repo := t.TempDir()
	wantScope := mustEval(t, repo)

	run := &fakeCmdRunner{id: "inv-1", result: cmdrunner.RunResult{ExitCode: 0, Stdout: []byte("on branch main")}}
	reg := tools.NewRegistry()
	registerGitStatus(t, reg, repo, vcs.ActionSpec{Argv: []string{"git", "status"}}, run, noopEmit)

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"vcs_status": {decision: grantDecision()},
	}}

	res, err := DispatchTool(context.Background(), "vcs_status", nil, home, processCWD, reg, auth)
	if err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	if run.calls != 1 {
		t.Fatalf("runner Exec calls = %d, want 1 (dispatch must route into the registered g225-backed tool)", run.calls)
	}
	if run.gotSpec.Cwd != wantScope {
		t.Fatalf("runner cwd = %q, want %q (action effective cwd)", run.gotSpec.Cwd, wantScope)
	}
	if string(res.Stdout) != "on branch main" || res.ExitCode != 0 {
		t.Fatalf("result = %+v, want stdout 'on branch main' exit 0", res)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1", len(auth.requests))
	}
	got := auth.requests[0]
	if got.Kind != "tool" || got.Subject != "vcs_status" || got.SubjectTokens != nil {
		t.Fatalf("MatchRequest = %+v, want tool/vcs_status/no tokens", got)
	}
	if got.PathScope != wantScope {
		t.Fatalf("PathScope = %q, want %q (action effective cwd, not process cwd %q)", got.PathScope, wantScope, processCWD)
	}
}

func TestDispatchTool_VCSActionUsesAuthorizedCWDWhenSymlinkChanges(t *testing.T) {
	home := t.TempDir()
	processCWD := t.TempDir()
	repo := t.TempDir()
	allowedA := mkdir(t, filepath.Join(repo, "allowed-a"))
	allowedB := mkdir(t, filepath.Join(repo, "allowed-b"))
	link := filepath.Join(repo, "work")
	if err := os.Symlink(allowedA, link); err != nil {
		t.Fatalf("Symlink(%q -> %q): %v", link, allowedA, err)
	}
	wantScope := mustEval(t, link)
	changedScope := mustEval(t, allowedB)

	run := &fakeCmdRunner{id: "inv-1", result: cmdrunner.RunResult{ExitCode: 0}}
	reg := tools.NewRegistry()
	registerGitStatus(t, reg, repo, vcs.ActionSpec{Argv: []string{"git", "status"}, Cwd: "work"}, run, noopEmit)

	mutated := false
	auth := &fakeAuthorizer{
		bySubject: map[string]authBehavior{
			"vcs_status": {decision: grantDecision()},
		},
		onAuthorize: func(req permissions.MatchRequest) {
			if req.Subject != "vcs_status" {
				return
			}
			if err := os.Remove(link); err != nil {
				t.Fatalf("Remove(%q): %v", link, err)
			}
			if err := os.Symlink(allowedB, link); err != nil {
				t.Fatalf("Symlink(%q -> %q): %v", link, allowedB, err)
			}
			mutated = true
		},
	}

	_, err := DispatchTool(context.Background(), "vcs_status", nil, home, processCWD, reg, auth)
	if err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	if len(auth.requests) != 1 || auth.requests[0].PathScope != wantScope {
		t.Fatalf("authorized path scope = %v, want original symlink target %q", auth.requests, wantScope)
	}
	if !mutated {
		t.Fatal("test did not mutate symlink between authorization and invocation")
	}
	if run.calls != 1 {
		t.Fatalf("runner Exec calls = %d, want 1", run.calls)
	}
	if run.gotSpec.Cwd != wantScope {
		t.Fatalf("runner cwd = %q, want authorized cwd %q, not mutated cwd %q", run.gotSpec.Cwd, wantScope, changedScope)
	}
}

func TestDispatchTool_VCSCWDEscapeAuthorizesCarriedScopeAndInvokes(t *testing.T) {
	home := t.TempDir()
	processCWD := t.TempDir()
	repo := t.TempDir()
	outside := t.TempDir()
	wantScope := mustEval(t, outside)

	var emitCalls int
	emit := func(events.EventPayload) error { emitCalls++; return nil }
	run := &fakeCmdRunner{id: "inv-1"}
	reg := tools.NewRegistry()
	registerGitStatus(t, reg, repo, vcs.ActionSpec{Argv: []string{"git", "status"}, Cwd: outside}, run, emit)

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"vcs_status": {decision: grantDecision()},
	}}

	res, err := DispatchTool(context.Background(), "vcs_status", nil, home, processCWD, reg, auth)
	if err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	if len(auth.requests) != 1 || auth.requests[0].PathScope != wantScope {
		t.Fatalf("authorize path scope = %v, want carried escape scope %q (CWDEscapeError.ResolvedCwd)", auth.requests, wantScope)
	}
	if run.calls != 0 {
		t.Fatalf("runner Exec calls = %d, want 0 (cwd escape fails before exec)", run.calls)
	}
	if res.ExitCode != -1 || !strings.Contains(string(res.Stderr), "cwd escapes repo root") {
		t.Fatalf("result = %+v, want g225 cwd-escape launch-failure surface preserved", res)
	}
	if emitCalls != 2 {
		t.Fatalf("emit calls = %d, want 2 (g225 paired tool_exec_start/end preserved)", emitCalls)
	}
}

func TestDispatchTool_VCSRepoRootGoneAuthorizesCarriedScopeAndInvokes(t *testing.T) {
	home := t.TempDir()
	processCWD := t.TempDir()
	repo := t.TempDir()

	var emitCalls int
	emit := func(events.EventPayload) error { emitCalls++; return nil }
	run := &fakeCmdRunner{id: "inv-1"}
	reg := tools.NewRegistry()
	registerGitStatus(t, reg, repo, vcs.ActionSpec{Argv: []string{"git", "status"}}, run, emit)

	// The active repo root vanishes after the tool was bound ("active repo root binding").
	if err := os.RemoveAll(repo); err != nil {
		t.Fatalf("RemoveAll(repo): %v", err)
	}
	wantScope := filepath.Clean(repo)

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"vcs_status": {decision: grantDecision()},
	}}

	res, err := DispatchTool(context.Background(), "vcs_status", nil, home, processCWD, reg, auth)
	if err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	if len(auth.requests) != 1 || auth.requests[0].PathScope != wantScope {
		t.Fatalf("authorize path scope = %v, want carried would-be cwd %q (RepoRootResolveError.PathScope)", auth.requests, wantScope)
	}
	if run.calls != 0 {
		t.Fatalf("runner Exec calls = %d, want 0 (repo-root disappearance fails before exec)", run.calls)
	}
	if res.ExitCode != -1 || !strings.Contains(string(res.Stderr), "launch failed") {
		t.Fatalf("result = %+v, want g225 repo-root launch-failure surface preserved", res)
	}
	if emitCalls != 2 {
		t.Fatalf("emit calls = %d, want 2 (g225 paired events preserved)", emitCalls)
	}
}

func TestDispatchTool_VCSEffectiveCWDErrorWithoutScopeReturnsBeforePrompting(t *testing.T) {
	home := t.TempDir()
	processCWD := t.TempDir()
	repo := t.TempDir()
	// An explicit cwd target that does not exist while the repo root still resolves: ResolveActionCWD
	// returns a plain wrapped error carrying no concrete path scope (a VCS dispatcher error).
	missingCwd := filepath.Join(repo, "gone")

	run := &fakeCmdRunner{id: "inv-1"}
	reg := tools.NewRegistry()
	registerGitStatus(t, reg, repo, vcs.ActionSpec{Argv: []string{"git", "status"}, Cwd: missingCwd}, run, noopEmit)

	// Any Authorize call errors, so a stray prompt is caught.
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{}}

	_, err := DispatchTool(context.Background(), "vcs_status", nil, home, processCWD, reg, auth)
	if err == nil {
		t.Fatal("want an effective-cwd resolution error")
	}
	var de *DeniedError
	var nst *NoSuchToolError
	if errors.As(err, &de) || errors.As(err, &nst) {
		t.Fatalf("error must surface directly, got %v", err)
	}
	var escErr *vcs.CWDEscapeError
	var rootErr *vcs.RepoRootResolveError
	if errors.As(err, &escErr) || errors.As(err, &rootErr) {
		t.Fatalf("a no-scope effective-cwd error must not be a carried-scope error type, got %v", err)
	}
	if len(auth.requests) != 0 {
		t.Fatalf("authorize calls = %d, want 0 (no concrete scope returns before prompting)", len(auth.requests))
	}
	if run.calls != 0 {
		t.Fatalf("runner Exec calls = %d, want 0", run.calls)
	}
}

// TestDispatchTool_TargetScopedResolvesBeforeAuthorizeAndInvokes proves the edit-tool dispatch shape
// the target is resolved before authorization, the resolved parent is the authorized path
// scope, the resolved target rides in the mode-auth context, and invocation reuses that exact resolved
// target rather than re-resolving from arguments (so a symlink change cannot land the write elsewhere).
func TestDispatchTool_TargetScopedResolvesBeforeAuthorizeAndInvokes(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	target := filepath.Join(cwd, "sub", "file.go")
	scope := filepath.Join(cwd, "sub")

	ft := &fakeTargetTool{name: "edit", target: target, scope: scope, result: tools.Result{ExitCode: 0, Stdout: []byte("edited")}}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{"edit": {decision: grantDecision()}}}

	res, err := DispatchTool(context.Background(), "edit", map[string]any{"path": "sub/file.go"}, home, cwd, reg, auth)
	if err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	if string(res.Stdout) != "edited" {
		t.Fatalf("result stdout = %q, want edited", res.Stdout)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1", len(auth.requests))
	}
	if got := auth.requests[0].PathScope; got != scope {
		t.Fatalf("authorized PathScope = %q, want the resolved parent %q", got, scope)
	}
	mc := auth.modeCtxs[0]
	if mc.TargetPath != target {
		t.Fatalf("mode context TargetPath = %q, want the resolved target %q", mc.TargetPath, target)
	}
	if mc.ToolName != "edit" || mc.Class != permissions.ClassMutating {
		t.Fatalf("mode context = %+v, want ToolName edit / mutating", mc)
	}
	if !ft.invoked || ft.invokedTarget != target {
		t.Fatalf("invoked=%v invokedTarget=%q, want invoked with the resolved target %q", ft.invoked, ft.invokedTarget, target)
	}
}

// TestDispatchTool_TargetScopedOutOfScopeReturnsBeforePrompting proves an out-of-scope edit target
// (resolution failure) surfaces before any authorization prompt and the tool is never invoked.
func TestDispatchTool_TargetScopedOutOfScopeReturnsBeforePrompting(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	wantErr := errors.New("edit target rejected: outside the project root")

	ft := &fakeTargetTool{name: "edit", resolveErr: wantErr}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Empty bySubject with nil fallback: any Authorize call errors, catching a stray prompt.
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{}}

	_, err := DispatchTool(context.Background(), "edit", map[string]any{"path": "../escape.go"}, home, cwd, reg, auth)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want the resolution error surfaced directly", err)
	}
	if len(auth.requests) != 0 {
		t.Fatalf("authorize calls = %d, want 0 (an out-of-scope target must not prompt)", len(auth.requests))
	}
	if ft.invoked {
		t.Fatal("out-of-scope target must not invoke the tool")
	}
}

// TestDispatchTool_SymlinkEscapeEditTargetPromptsForRealFolder pins out-of-root folder approval: an edit
// whose target escapes the project root *through an in-project symlink* is no longer a pre-authorization
// *filetools.TargetError. It resolves to the real out-of-root file and routes to authorization (the
// approval prompt) anchored on the real out-of-root folder, with the out-of-root folder-grant signal
// set. With no grant the authorizer denies it, so the tool is never invoked and no write reaches the
// escaping target — the default posture (no grant ⇒ out-of-root write denied) holds; only the
// mechanism moved from a hard deny to a prompt. The path scope is the *real* out-of-root folder, never
// the in-project lexical path, so a grant can never be widened to authorize a write whose real parent
// differs.
func TestDispatchTool_SymlinkEscapeEditTargetPromptsForRealFolder(t *testing.T) {
	home := t.TempDir()
	project := mustEval(t, t.TempDir())

	// A real directory outside the project, holding a file, and an in-project symlink pointing at it,
	// so the path "<project>/escape/secret.txt" looks in-project but resolves outside the root.
	outside := mustEval(t, t.TempDir())
	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("untouched\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(project, "escape")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewEditTool(home, project, project)); err != nil {
		t.Fatalf("Register edit tool: %v", err)
	}
	env := permissions.BuildDenyEnvelope("nope")
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		filetools.EditToolName: {decision: denyDecision(env), prompts: true},
	}}

	_, err := DispatchTool(context.Background(), filetools.EditToolName, map[string]any{
		"path": "escape/secret.txt", "old_text": "untouched", "new_text": "changed",
	}, home, project, reg, auth)

	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("DispatchTool error = %v, want *DeniedError (out-of-root edit prompts, then is denied with no grant)", err)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1 (an out-of-root edit routes through authorization, not a hard deny)", len(auth.requests))
	}
	if got := auth.requests[0].PathScope; got != outside {
		t.Fatalf("authorized PathScope = %q, want the real out-of-root folder %q (never the in-project lexical path)", got, outside)
	}
	if !auth.displays[0].OutOfRootFileWrite {
		t.Fatalf("display.OutOfRootFileWrite = false, want true (an out-of-root edit raises the folder-grant signal)")
	}
	if data, rerr := os.ReadFile(outsideFile); rerr != nil || string(data) != "untouched\n" {
		t.Fatalf("out-of-project file = %q (err %v), want untouched (denied, no write through the escaping symlink)", string(data), rerr)
	}
}

// TestDispatchTool_InRootEditDoesNotRaiseOutOfRootSignal proves the out-of-root folder-grant signal stays
// false for an in-root edit, so an in-root write never broadens the folder option beyond its normal rule.
func TestDispatchTool_InRootEditDoesNotRaiseOutOfRootSignal(t *testing.T) {
	home := t.TempDir()
	project := mustEval(t, t.TempDir())
	file := filepath.Join(project, "main.go")
	if err := os.WriteFile(file, []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewEditTool(home, project, project)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.EditToolName: {decision: grantDecision()}}}
	if _, err := DispatchTool(context.Background(), filetools.EditToolName, map[string]any{
		"path": "main.go", "old_text": "main", "new_text": "x",
	}, home, project, reg, auth); err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	if auth.displays[0].OutOfRootFileWrite {
		t.Fatalf("display.OutOfRootFileWrite = true for an in-root edit, want false")
	}
}

func TestDispatchTool_GrantedEditStillWritesAfterPreview(t *testing.T) {
	home := t.TempDir()
	project := mustEval(t, t.TempDir())
	target := filepath.Join(project, "main.go")
	const original = "package main\n\nfunc main() {\n\tfoo()\n}\n"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewEditTool(home, project, project)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	args := map[string]any{"path": "main.go", "old_text": "foo()", "new_text": "bar()"}

	var atDecision string
	auth := &fakeAuthorizer{
		bySubject: map[string]authBehavior{filetools.EditToolName: {decision: grantDecision()}},
		onAuthorize: func(permissions.MatchRequest) {
			data, err := os.ReadFile(target)
			if err != nil {
				t.Errorf("ReadFile during authorization: %v", err)
			}
			atDecision = string(data)
		},
	}
	res, err := DispatchTool(context.Background(), filetools.EditToolName, args, home, project, reg, auth)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("DispatchTool = (%+v, %v), want a successful edit", res, err)
	}
	if atDecision != original {
		t.Fatalf("file at the authorization decision = %q, want the unmodified %q", atDecision, original)
	}
	if got, want := readTarget(t, target), "package main\n\nfunc main() {\n\tbar()\n}\n"; got != want {
		t.Fatalf("file after a granted edit = %q, want %q", got, want)
	}
}

func readTarget(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	return string(data)
}

// TestDispatchTool_TargetScopedDeniedNotInvoked proves a denied edit is not invoked even after its
// target resolves: resolution happens before authorization, but a deny still blocks the write.
func TestDispatchTool_TargetScopedDeniedNotInvoked(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	env := permissions.BuildDenyEnvelope("nope")

	ft := &fakeTargetTool{name: "edit", target: filepath.Join(cwd, "f.go"), scope: cwd}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{"edit": {decision: denyDecision(env), prompts: true}}}

	_, err := DispatchTool(context.Background(), "edit", map[string]any{"path": "f.go"}, home, cwd, reg, auth)
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want *DeniedError", err)
	}
	if ft.invoked {
		t.Fatal("denied edit must not be invoked")
	}
}

// TestDispatchTool_ExternalReadPromptsAndCarriesSignals pins the external-read dispatch wiring for the six
// read-only navigation tools: an EXPLICIT out-of-project path resolves (rather than failing before
// authorization), reaches the authorizer against the real external scope with modeCtx.ExternalRead set
// (so the read-only auto-allow is bypassed and the request prompts) and display.OutOfRootReadScope set
// (so the prompt offers the folder option for that external read) while the write signal stays false.
// Approval then invokes the tool.
func TestDispatchTool_ExternalReadPromptsAndCarriesSignals(t *testing.T) {
	home := t.TempDir()
	project := mustEval(t, t.TempDir())
	ext := mustEval(t, t.TempDir())
	if err := os.WriteFile(filepath.Join(ext, "a.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	const cap = 65536

	cases := []struct {
		name string
		tool tools.Tool
		args map[string]any
	}{
		{filetools.ReadToolName, filetools.NewReadTool(home, project, project, cap), map[string]any{"path": filepath.Join(ext, "a.txt")}},
		{filetools.GlobToolName, filetools.NewGlobTool(home, project, project, cap), map[string]any{"pattern": "**/*.txt", "path": ext}},
		{filetools.GrepToolName, filetools.NewGrepTool(home, project, project, cap), map[string]any{"pattern": "hello", "path": ext}},
		{filetools.ListToolName, filetools.NewListTool(home, project, project, cap), map[string]any{"path": ext}},
		{filetools.TreeToolName, filetools.NewTreeTool(home, project, project, cap), map[string]any{"path": ext}},
		{filetools.FileCountToolName, filetools.NewFileCountTool(home, project, project, cap), map[string]any{"path": ext}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			reg := tools.NewRegistry()
			if err := reg.Register(tools.BuiltinSource, tc.tool); err != nil {
				t.Fatalf("Register: %v", err)
			}
			auth := &fakeAuthorizer{bySubject: map[string]authBehavior{tc.name: {decision: grantDecision()}}}
			if _, err := DispatchTool(context.Background(), tc.name, tc.args, home, project, reg, auth); err != nil {
				t.Fatalf("DispatchTool: %v", err)
			}
			if len(auth.requests) != 1 {
				t.Fatalf("authorize calls = %d, want 1 (an explicit external read prompts, not a pre-auth refusal)", len(auth.requests))
			}
			if got := auth.requests[0].PathScope; got != ext {
				t.Fatalf("PathScope = %q, want the real external dir %q", got, ext)
			}
			if !auth.modeCtxs[0].ExternalRead {
				t.Fatalf("modeCtx.ExternalRead = false, want true (external read bypasses the read-only auto-allow)")
			}
			if !auth.displays[0].OutOfRootReadScope {
				t.Fatalf("display.OutOfRootReadScope = false, want true (external read re-enables the folder option)")
			}
			if auth.displays[0].OutOfRootFileWrite {
				t.Fatalf("display.OutOfRootFileWrite = true, want false (a read never raises the write signal)")
			}
			if got, want := auth.displays[0].RequestedTarget, tc.args["path"].(string); got != want {
				t.Fatalf("display.RequestedTarget = %q, want the lexical path argument %q", got, want)
			}
		})
	}
}

// TestDispatchTool_InProjectReadRaisesNoExternalSignal proves the external-read signals stay false for
// an in-project read, so an in-project read keeps its existing no-prompt auto-allow path and never
// broadens the prompt.
func TestDispatchTool_InProjectReadRaisesNoExternalSignal(t *testing.T) {
	home := t.TempDir()
	project := mustEval(t, t.TempDir())
	if err := os.WriteFile(filepath.Join(project, "a.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewReadTool(home, project, project, 65536)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.ReadToolName: {decision: grantDecision()}}}
	if _, err := DispatchTool(context.Background(), filetools.ReadToolName, map[string]any{"path": "a.txt"}, home, project, reg, auth); err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	if auth.modeCtxs[0].ExternalRead {
		t.Fatalf("modeCtx.ExternalRead = true for an in-project read, want false")
	}
	if auth.displays[0].OutOfRootReadScope {
		t.Fatalf("display.OutOfRootReadScope = true for an in-project read, want false")
	}
}

func TestPrepareTool_BlockedListSetsOpenReadForOutsideReads(t *testing.T) {
	home := t.TempDir()
	project := mustEval(t, t.TempDir())
	ext := mustEval(t, t.TempDir())
	for _, f := range []string{filepath.Join(project, "a.txt"), filepath.Join(ext, "a.txt")} {
		if err := os.WriteFile(f, []byte("hi\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	reg := tools.NewRegistry()
	for _, tool := range []tools.Tool{
		filetools.NewReadTool(home, project, project, 65536),
		filetools.NewReadImageTool(home, project, project, 65536),
		filetools.NewListTool(home, project, project, 65536),
	} {
		if err := reg.Register(tools.BuiltinSource, tool); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	guard := securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, nil)}

	cases := []struct {
		name     string
		tool     string
		args     map[string]any
		wantOpen bool
	}{
		{"read outside", filetools.ReadToolName, map[string]any{"path": filepath.Join(ext, "a.txt")}, true},
		{"read_image outside", filetools.ReadImageToolName, map[string]any{"path": filepath.Join(ext, "a.txt")}, true},
		{"list outside", filetools.ListToolName, map[string]any{"path": ext}, true},
		{"read in project", filetools.ReadToolName, map[string]any{"path": "a.txt"}, false},
		{"list in project", filetools.ListToolName, map[string]any{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareTool(context.Background(), tc.tool, tc.args, home, project, reg, guard)
			if err != nil {
				t.Fatalf("PrepareTool: %v", err)
			}
			mc := prepared.IndependentRequest().ModeCtx
			if mc.OpenRead != tc.wantOpen || mc.ExternalRead {
				t.Fatalf("OpenRead = %v, ExternalRead = %v; want OpenRead %v and ExternalRead false", mc.OpenRead, mc.ExternalRead, tc.wantOpen)
			}
			if prepared.ExternalRead() != tc.wantOpen {
				t.Fatalf("PreparedTool.ExternalRead() = %v, want %v", prepared.ExternalRead(), tc.wantOpen)
			}
		})
	}
}

func TestPrepareTool_NetworkEgressMarkerOnWebToolsOnly(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()

	cases := []struct {
		name     string
		readOnly bool
		want     bool
	}{
		{webSearchToolName, false, true},
		{webFetchToolName, false, true},
		{webSearchToolName + "_x", false, false},
		{"read_file", true, false},
		{"vcs_status", true, false},
		{"edit", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := tools.NewRegistry()
			if err := reg.Register(tools.BuiltinSource, &fakeTool{name: tc.name, readOnly: tc.readOnly}); err != nil {
				t.Fatalf("Register: %v", err)
			}
			prepared, err := PrepareTool(context.Background(), tc.name, map[string]any{"query": "x"}, home, cwd, reg)
			if err != nil {
				t.Fatalf("PrepareTool: %v", err)
			}
			if got := prepared.modeCtx.NetworkEgress; got != tc.want {
				t.Fatalf("modeCtx.NetworkEgress = %v for %q, want %v", got, tc.name, tc.want)
			}
		})
	}

	t.Run("read-only web tool still carries the marker", func(t *testing.T) {
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, &fakeTool{name: webFetchToolName, readOnly: true}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		prepared, err := PrepareTool(context.Background(), webFetchToolName, map[string]any{"url": "https://example.com"}, home, cwd, reg)
		if err != nil {
			t.Fatalf("PrepareTool: %v", err)
		}
		if !prepared.modeCtx.NetworkEgress {
			t.Fatal("modeCtx.NetworkEgress = false for a read-only-advertised web_fetch, want true")
		}
	})

	t.Run("unknown web-shaped name never reaches preparation", func(t *testing.T) {
		reg := tools.NewRegistry()
		_, err := PrepareTool(context.Background(), webSearchToolName, map[string]any{"query": "x"}, home, cwd, reg)
		var noSuch *NoSuchToolError
		if !errors.As(err, &noSuch) {
			t.Fatalf("PrepareTool(unregistered %q) err = %v, want *NoSuchToolError", webSearchToolName, err)
		}
	})
}

func TestDispatchTool_WebToolAuthorizationGatesInvocation(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	env := permissions.BuildDenyEnvelope("no web research")

	for _, name := range []string{webSearchToolName, webFetchToolName} {
		t.Run(name+" denied", func(t *testing.T) {
			ft := &fakeTool{name: name}
			reg := tools.NewRegistry()
			if err := reg.Register(tools.BuiltinSource, ft); err != nil {
				t.Fatalf("Register: %v", err)
			}
			auth := &fakeAuthorizer{bySubject: map[string]authBehavior{name: {decision: denyDecision(env), prompts: true}}}

			_, err := DispatchTool(context.Background(), name, map[string]any{"query": "x"}, home, cwd, reg, auth)
			var de *DeniedError
			if !errors.As(err, &de) {
				t.Fatalf("error = %v, want *DeniedError", err)
			}
			if de.Envelope != env {
				t.Fatalf("deny envelope = %q, want the authorizer's bounded envelope %q", de.Envelope, env)
			}
			if ft.invoked {
				t.Fatal("a denied web tool must not be invoked — no socket may open")
			}
			if !auth.modeCtxs[0].NetworkEgress {
				t.Fatal("modeCtx.NetworkEgress = false at the authorizer, want true")
			}
		})

		t.Run(name+" authorized", func(t *testing.T) {
			ft := &fakeTool{name: name}
			reg := tools.NewRegistry()
			if err := reg.Register(tools.BuiltinSource, ft); err != nil {
				t.Fatalf("Register: %v", err)
			}
			auth := &fakeAuthorizer{bySubject: map[string]authBehavior{name: {decision: grantDecision()}}}

			if _, err := DispatchTool(context.Background(), name, map[string]any{"query": "x"}, home, cwd, reg, auth); err != nil {
				t.Fatalf("DispatchTool: %v", err)
			}
			if !ft.invoked {
				t.Fatal("an authorized web tool must be invoked")
			}
			if len(auth.requests) != 1 {
				t.Fatalf("authorize calls = %d, want 1", len(auth.requests))
			}
			if got := auth.requests[0].Subject; got != name {
				t.Fatalf("matching subject = %q, want the registered name %q", got, name)
			}
		})
	}
}

func TestDispatchTool_GrantStoredSubjectFoldsCapability(t *testing.T) {
	t.Run("create folds to write_tree", func(t *testing.T) {
		home := t.TempDir()
		cwd := t.TempDir()
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, &fakeTool{name: filetools.CreateToolName}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.CreateToolName: {decision: grantDecision()}}}
		if _, err := DispatchTool(context.Background(), filetools.CreateToolName, map[string]any{"path": "a.go", "content": "x"}, home, cwd, reg, auth); err != nil {
			t.Fatalf("DispatchTool: %v", err)
		}
		if got := auth.displays[0].GrantStoredSubject; got != permissions.CapabilityWriteTree {
			t.Fatalf("GrantStoredSubject = %q, want %q", got, permissions.CapabilityWriteTree)
		}
		if got := auth.requests[0].Subject; got != filetools.CreateToolName {
			t.Fatalf("matching subject = %q, want the concrete tool name %q", got, filetools.CreateToolName)
		}
	})

	t.Run("edit folds to write_tree", func(t *testing.T) {
		home := t.TempDir()
		cwd := t.TempDir()
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, &fakeTool{name: filetools.EditToolName}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.EditToolName: {decision: grantDecision()}}}
		if _, err := DispatchTool(context.Background(), filetools.EditToolName, map[string]any{"path": "a.go", "old_text": "x", "new_text": "y"}, home, cwd, reg, auth); err != nil {
			t.Fatalf("DispatchTool: %v", err)
		}
		if got := auth.displays[0].GrantStoredSubject; got != permissions.CapabilityWriteTree {
			t.Fatalf("GrantStoredSubject = %q, want %q", got, permissions.CapabilityWriteTree)
		}
	})

	t.Run("mkdir folds to write_tree", func(t *testing.T) {
		home := t.TempDir()
		cwd := t.TempDir()
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, &fakeTool{name: filetools.MkdirToolName}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.MkdirToolName: {decision: grantDecision()}}}
		if _, err := DispatchTool(context.Background(), filetools.MkdirToolName, map[string]any{"path": "build/cache"}, home, cwd, reg, auth); err != nil {
			t.Fatalf("DispatchTool: %v", err)
		}
		if got := auth.displays[0].GrantStoredSubject; got != permissions.CapabilityWriteTree {
			t.Fatalf("GrantStoredSubject = %q, want %q (mkdir folds to the write_tree successor)", got, permissions.CapabilityWriteTree)
		}
		if got := auth.requests[0].Subject; got != filetools.MkdirToolName {
			t.Fatalf("matching subject = %q, want the concrete tool name %q", got, filetools.MkdirToolName)
		}
	})

	t.Run("external read folds to read*", func(t *testing.T) {
		home := t.TempDir()
		project := mustEval(t, t.TempDir())
		ext := mustEval(t, t.TempDir())
		if err := os.WriteFile(filepath.Join(ext, "a.txt"), []byte("hello\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, filetools.NewGrepTool(home, project, project, 65536)); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.GrepToolName: {decision: grantDecision()}}}
		if _, err := DispatchTool(context.Background(), filetools.GrepToolName, map[string]any{"pattern": "hello", "path": ext}, home, project, reg, auth); err != nil {
			t.Fatalf("DispatchTool: %v", err)
		}
		if got := auth.displays[0].GrantStoredSubject; got != permissions.CapabilityRead {
			t.Fatalf("GrantStoredSubject = %q, want %q", got, permissions.CapabilityRead)
		}
		if got := auth.requests[0].Subject; got != filetools.GrepToolName {
			t.Fatalf("matching subject = %q, want the concrete tool name %q", got, filetools.GrepToolName)
		}
	})

	t.Run("in-project read carries no stored subject", func(t *testing.T) {
		home := t.TempDir()
		project := mustEval(t, t.TempDir())
		if err := os.WriteFile(filepath.Join(project, "a.txt"), []byte("hi\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, filetools.NewReadTool(home, project, project, 65536)); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.ReadToolName: {decision: grantDecision()}}}
		if _, err := DispatchTool(context.Background(), filetools.ReadToolName, map[string]any{"path": "a.txt"}, home, project, reg, auth); err != nil {
			t.Fatalf("DispatchTool: %v", err)
		}
		if got := auth.displays[0].GrantStoredSubject; got != "" {
			t.Fatalf("GrantStoredSubject = %q, want empty (an in-project read never creates a grant)", got)
		}
	})

	t.Run("unrelated tool carries no stored subject", func(t *testing.T) {
		home := t.TempDir()
		cwd := t.TempDir()
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, &fakeTool{name: "read_file"}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{"read_file": {decision: grantDecision()}}}
		if _, err := DispatchTool(context.Background(), "read_file", map[string]any{"path": "x"}, home, cwd, reg, auth); err != nil {
			t.Fatalf("DispatchTool: %v", err)
		}
		if got := auth.displays[0].GrantStoredSubject; got != "" {
			t.Fatalf("GrantStoredSubject = %q, want empty (read_file maps to no capability)", got)
		}
	})
}

// TestDispatchTool_ExternalReadDeniedNotInvoked proves a denied external read is not invoked even though its
// target resolved before authorization: the deny envelope surfaces and the file content is not read.
func TestDispatchTool_ExternalReadDeniedNotInvoked(t *testing.T) {
	home := t.TempDir()
	project := mustEval(t, t.TempDir())
	ext := mustEval(t, t.TempDir())
	if err := os.WriteFile(filepath.Join(ext, "a.txt"), []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewReadTool(home, project, project, 65536)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	env := permissions.BuildDenyEnvelope("nope")
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		filetools.ReadToolName: {decision: denyDecision(env), prompts: true},
	}}
	res, err := DispatchTool(context.Background(), filetools.ReadToolName, map[string]any{"path": filepath.Join(ext, "a.txt")}, home, project, reg, auth)
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want *DeniedError (denied external read)", err)
	}
	if strings.Contains(string(res.Stdout), "secret") {
		t.Fatalf("denied external read leaked content: %q", res.Stdout)
	}
}

// TestDispatchTool_MkdirPromptDisplayShowsDirectory proves the mkdir tool shows a distinct "Create
// directory" action over the target directory path with no body — never the generic "Run tool"
// fallback, a read label, or the bare tool token, any of which would make a mutating directory creation
// look like an ordinary structured call.
func TestDispatchTool_MkdirPromptDisplayShowsDirectory(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, &fakeTool{name: filetools.MkdirToolName}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.MkdirToolName: {decision: grantDecision()}}}
	args := map[string]any{"path": "build/cache"}

	if _, err := DispatchTool(context.Background(), filetools.MkdirToolName, args, home, cwd, reg, auth); err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	want := PromptDisplay{Action: ActionCreateDirectory, Subject: "build/cache", RequestedTarget: "build/cache", Body: "", GrantStoredSubject: permissions.CapabilityWriteTree}
	if got := auth.displays[0]; got != want {
		t.Fatalf("mkdir prompt display = %+v, want %+v", got, want)
	}
	if got := auth.displays[0].Action; got == filetools.MkdirToolName || got == ActionRunTool {
		t.Fatalf("mkdir action header = %q, want the distinct directory-create action, not the bare token or Run tool", got)
	}
	if got := auth.requests[0].Subject; got != filetools.MkdirToolName {
		t.Fatalf("matching subject = %q, want the bare registered name %q", got, filetools.MkdirToolName)
	}
}

// TestDispatchTool_MkdirTargetScopedInRootCreatesAndNoSignal pins the real mkdir tool through the
// target-scoped dispatch seam for an in-project directory: dispatch resolves the deepest-existing ancestor
// as the authorized path scope, carries the resolved target directory in the mode-auth context.
func TestDispatchTool_MkdirTargetScopedInRootCreatesAndNoSignal(t *testing.T) {
	home := t.TempDir()
	project := mustEval(t, t.TempDir())
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewMkdirTool(home, project, project)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.MkdirToolName: {decision: grantDecision()}}}

	if _, err := DispatchTool(context.Background(), filetools.MkdirToolName, map[string]any{"path": "newdir"}, home, project, reg, auth); err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1", len(auth.requests))
	}
	if got := auth.requests[0].PathScope; got != project {
		t.Fatalf("authorized PathScope = %q, want the resolved existing ancestor %q", got, project)
	}
	wantTarget := filepath.Join(project, "newdir")
	if got := auth.modeCtxs[0].TargetPath; got != wantTarget {
		t.Fatalf("mode context TargetPath = %q, want the resolved target dir %q", got, wantTarget)
	}
	if mc := auth.modeCtxs[0]; mc.ToolName != filetools.MkdirToolName || mc.Class != permissions.ClassMutating {
		t.Fatalf("mode context = %+v, want ToolName mkdir / mutating", mc)
	}
	if auth.displays[0].OutOfRootFileWrite {
		t.Fatalf("display.OutOfRootFileWrite = true for an in-root mkdir, want false")
	}
	if got := auth.displays[0].GrantStoredSubject; got != permissions.CapabilityWriteTree {
		t.Fatalf("GrantStoredSubject = %q, want %q (mkdir folds to the write_tree successor)", got, permissions.CapabilityWriteTree)
	}
	fi, statErr := os.Stat(wantTarget)
	if statErr != nil || !fi.IsDir() {
		t.Fatalf("created dir %q: stat err %v isDir %v, want an existing directory", wantTarget, statErr, fi != nil && fi.IsDir())
	}
}

// TestDispatchTool_MkdirOutOfRootPromptsForRealFolderAndDeniedNotCreated pins out-of-root folder
// approval for mkdir: a target whose deepest-existing ancestor escapes the project root *through an
// in-project symlink* is not a pre-authorization rejection — it resolves to the real out-of-root
// folder, routes to the approval prompt anchored on that real folder with the out-of-root folder-grant
// signal set, and with no grant is denied so no directory is created outside the root. The authorized
// path scope is the real external folder, never the in-project lexical path, mirroring the edit-tool
// out-of-root posture.
func TestDispatchTool_MkdirOutOfRootPromptsForRealFolderAndDeniedNotCreated(t *testing.T) {
	home := t.TempDir()
	project := mustEval(t, t.TempDir())
	outside := mustEval(t, t.TempDir())
	if err := os.Symlink(outside, filepath.Join(project, "escape")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewMkdirTool(home, project, project)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	env := permissions.BuildDenyEnvelope("nope")
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		filetools.MkdirToolName: {decision: denyDecision(env), prompts: true},
	}}

	_, err := DispatchTool(context.Background(), filetools.MkdirToolName, map[string]any{"path": "escape/newdir"}, home, project, reg, auth)
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want *DeniedError (an out-of-root mkdir prompts, then is denied with no grant)", err)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1 (an out-of-root mkdir routes through authorization, not a hard deny)", len(auth.requests))
	}
	if got := auth.requests[0].PathScope; got != outside {
		t.Fatalf("authorized PathScope = %q, want the real out-of-root folder %q (never the in-project lexical path)", got, outside)
	}
	if !auth.displays[0].OutOfRootFileWrite {
		t.Fatalf("display.OutOfRootFileWrite = false, want true (an out-of-root mkdir raises the folder-grant signal)")
	}
	created := filepath.Join(outside, "newdir")
	if _, statErr := os.Stat(created); !os.IsNotExist(statErr) {
		t.Fatalf("directory at %q exists despite deny (stat err %v), want no directory created", created, statErr)
	}
}

// TestDispatchTool_MoveSameScopeAuthorizesOnceAndInvokes proves the move multi-scope dispatch shape for a
// same-directory rename: the source and destination resolve to the same parent scope, so dispatch
// authorizes it once (not twice for the same folder), shows the "Move source -> destination" display over
// the lexical endpoints with the bare "move" matching subject and no folded capability, and — once
// granted — invokes the tool with the exact pair resolved before authorization.
func TestDispatchTool_MoveSameScopeAuthorizesOnceAndInvokes(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	resolved := filetools.ResolvedMove{
		Source: "/proj/sub/a.txt", SourceScope: "/proj/sub",
		Destination: "/proj/sub/b.txt", DestinationScope: "/proj/sub",
	}
	ft := &fakeMoveTool{name: filetools.MoveToolName, resolved: resolved, result: tools.Result{ExitCode: 0, Stdout: []byte("moved")}}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.MoveToolName: {decision: grantDecision()}}}

	res, err := DispatchTool(context.Background(), filetools.MoveToolName, map[string]any{"source": "a.txt", "destination": "b.txt"}, home, cwd, reg, auth)
	if err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	if string(res.Stdout) != "moved" {
		t.Fatalf("result stdout = %q, want moved", res.Stdout)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1 (a same-directory rename authorizes its one shared scope once)", len(auth.requests))
	}
	if got := auth.requests[0]; got.Kind != "tool" || got.Subject != filetools.MoveToolName || got.PathScope != "/proj/sub" {
		t.Fatalf("MatchRequest = %+v, want tool/move at the shared resolved scope /proj/sub", got)
	}
	want := PromptDisplay{Action: ActionMoveFile, Subject: "a.txt -> b.txt", RequestedTarget: "a.txt -> b.txt", Body: ""}
	if got := auth.displays[0]; got != want {
		t.Fatalf("move prompt display = %+v, want %+v (Move over the lexical endpoints, no body, no capability folding)", got, want)
	}
	if mc := auth.modeCtxs[0]; mc.ToolName != filetools.MoveToolName || mc.Class != permissions.ClassMutating || mc.TargetPath != "" {
		t.Fatalf("mode context = %+v, want move/mutating with no TargetPath (a move carries its endpoint pair, never a half-target)", mc)
	}
	if mc := auth.modeCtxs[0]; mc.MoveSource != resolved.Source || mc.MoveDestination != resolved.Destination {
		t.Fatalf("mode context endpoints = %q -> %q, want the resolved pair %q -> %q", mc.MoveSource, mc.MoveDestination, resolved.Source, resolved.Destination)
	}
	if !ft.invoked || ft.invokedResolved != resolved {
		t.Fatalf("invoked=%v invokedResolved=%+v, want invoked with the resolved pair %+v", ft.invoked, ft.invokedResolved, resolved)
	}
}

// TestDispatchTool_MoveTwoScopesAuthorizeIndependentlyAndInvoke proves a move across two different
// directories authorizes each resolved scope independently — source first, then destination — before
// invoking, and the invocation reuses the same resolved pair. Both authorizations carry the bare "move"
// subject and the same "source -> destination" display.
func TestDispatchTool_MoveTwoScopesAuthorizeIndependentlyAndInvoke(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	resolved := filetools.ResolvedMove{
		Source: "/proj/src/a.txt", SourceScope: "/proj/src",
		Destination: "/proj/dst/a.txt", DestinationScope: "/proj/dst",
	}
	ft := &fakeMoveTool{name: filetools.MoveToolName, resolved: resolved, result: tools.Result{ExitCode: 0}}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.MoveToolName: {decision: grantDecision()}}}

	if _, err := DispatchTool(context.Background(), filetools.MoveToolName, map[string]any{"source": "src/a.txt", "destination": "dst/a.txt"}, home, cwd, reg, auth); err != nil {
		t.Fatalf("DispatchTool: %v", err)
	}
	if len(auth.requests) != 2 {
		t.Fatalf("authorize calls = %d, want 2 (distinct source and destination scopes authorize independently)", len(auth.requests))
	}
	if got := auth.requests[0].PathScope; got != "/proj/src" {
		t.Fatalf("first authorized scope = %q, want the source scope /proj/src (source is authorized first)", got)
	}
	if got := auth.requests[1].PathScope; got != "/proj/dst" {
		t.Fatalf("second authorized scope = %q, want the destination scope /proj/dst", got)
	}
	for i, d := range auth.displays {
		if d.Subject != "src/a.txt -> dst/a.txt" || d.Action != ActionMoveFile {
			t.Fatalf("display[%d] = %+v, want the Move action over both endpoints on every scope prompt", i, d)
		}
	}
	for i, mc := range auth.modeCtxs {
		if mc.MoveSource != resolved.Source || mc.MoveDestination != resolved.Destination || mc.TargetPath != "" {
			t.Fatalf("mode context[%d] endpoints = %q -> %q (TargetPath %q), want the same resolved pair %q -> %q on every scope",
				i, mc.MoveSource, mc.MoveDestination, mc.TargetPath, resolved.Source, resolved.Destination)
		}
	}
	if !ft.invoked || ft.invokedResolved != resolved {
		t.Fatalf("invoked=%v invokedResolved=%+v, want invoked with the resolved pair %+v after both scopes granted", ft.invoked, ft.invokedResolved, resolved)
	}
}

// TestDispatchTool_MoveSourceDenialDoesNotInvokeOrAuthorizeDestination proves a denied source endpoint
// returns before the move runs and before the destination is ever authorized: dispatch authorizes the
// source first, and on its denial returns the *DeniedError without prompting the destination scope or
// invoking the tool — no partial mutation.
func TestDispatchTool_MoveSourceDenialDoesNotInvokeOrAuthorizeDestination(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	env := permissions.BuildDenyEnvelope("nope")
	resolved := filetools.ResolvedMove{
		Source: "/proj/src/a.txt", SourceScope: "/proj/src",
		Destination: "/proj/dst/a.txt", DestinationScope: "/proj/dst",
	}
	ft := &fakeMoveTool{name: filetools.MoveToolName, resolved: resolved}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.MoveToolName: {decision: denyDecision(env), prompts: true}}}

	_, err := DispatchTool(context.Background(), filetools.MoveToolName, map[string]any{"source": "src/a.txt", "destination": "dst/a.txt"}, home, cwd, reg, auth)
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want *DeniedError", err)
	}
	if de.Envelope != env {
		t.Fatalf("DeniedError.Envelope = %q, want %q", de.Envelope, env)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1 (a denied source must return before the destination is authorized)", len(auth.requests))
	}
	if ft.invoked {
		t.Fatal("a move with a denied source must not be invoked")
	}
}

// TestDispatchTool_MoveDestinationDenialDoesNotInvoke proves that approving the source does not let the
// move run when the destination is denied: dispatch authorizes both scopes (source granted, destination
// denied) and returns the *DeniedError without invoking — an approved source endpoint never authorizes the
// mutation on its own.
func TestDispatchTool_MoveDestinationDenialDoesNotInvoke(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	env := permissions.BuildDenyEnvelope("nope")
	resolved := filetools.ResolvedMove{
		Source: "/proj/src/a.txt", SourceScope: "/proj/src",
		Destination: "/proj/dst/a.txt", DestinationScope: "/proj/dst",
	}
	ft := &fakeMoveTool{name: filetools.MoveToolName, resolved: resolved}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Grant every scope except the destination, which is denied — the source share of the move authorizes,
	// the destination does not.
	auth := &denyScopeAuthorizer{denyScope: "/proj/dst", envelope: env}

	_, err := DispatchTool(context.Background(), filetools.MoveToolName, map[string]any{"source": "src/a.txt", "destination": "dst/a.txt"}, home, cwd, reg, auth)
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want *DeniedError (a denied destination blocks the move)", err)
	}
	if len(auth.requests) != 2 {
		t.Fatalf("authorize calls = %d, want 2 (source granted, then destination denied)", len(auth.requests))
	}
	if auth.requests[0].PathScope != "/proj/src" || auth.requests[1].PathScope != "/proj/dst" {
		t.Fatalf("authorized scopes = %q then %q, want source /proj/src then destination /proj/dst", auth.requests[0].PathScope, auth.requests[1].PathScope)
	}
	if ft.invoked {
		t.Fatal("a move with a denied destination must not be invoked, even though the source was approved")
	}
}

// TestDispatchTool_MoveOutOfRootEndpointsRaiseFolderSignalPerScope proves the out-of-root
// folder-grant signal is raised per endpoint: an in-root source paired with an out-of-root destination
// raises the write signal only on the destination scope's prompt, the read signal is never raised (a move
// is a write, not an external read), and the reverse pairing raises it only on the source.
func TestDispatchTool_MoveOutOfRootEndpointsRaiseFolderSignalPerScope(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()

	t.Run("out-of-root destination raises the signal only on the destination", func(t *testing.T) {
		resolved := filetools.ResolvedMove{
			Source: "/proj/src/a.txt", SourceScope: "/proj/src", SourceOutOfRoot: false,
			Destination: "/outside/a.txt", DestinationScope: "/outside", DestinationOutOfRoot: true,
		}
		ft := &fakeMoveTool{name: filetools.MoveToolName, resolved: resolved}
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, ft); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.MoveToolName: {decision: grantDecision()}}}
		if _, err := DispatchTool(context.Background(), filetools.MoveToolName, map[string]any{"source": "src/a.txt", "destination": "../outside/a.txt"}, home, cwd, reg, auth); err != nil {
			t.Fatalf("DispatchTool: %v", err)
		}
		if auth.displays[0].OutOfRootFileWrite {
			t.Fatalf("source prompt OutOfRootFileWrite = true for an in-root source, want false")
		}
		if !auth.displays[1].OutOfRootFileWrite {
			t.Fatalf("destination prompt OutOfRootFileWrite = false for an out-of-root destination, want true")
		}
		for i, d := range auth.displays {
			if d.OutOfRootReadScope {
				t.Fatalf("display[%d].OutOfRootReadScope = true, want false (a move is a write, never an external read)", i)
			}
		}
	})

	t.Run("out-of-root source raises the signal only on the source", func(t *testing.T) {
		resolved := filetools.ResolvedMove{
			Source: "/outside/a.txt", SourceScope: "/outside", SourceOutOfRoot: true,
			Destination: "/proj/dst/a.txt", DestinationScope: "/proj/dst", DestinationOutOfRoot: false,
		}
		ft := &fakeMoveTool{name: filetools.MoveToolName, resolved: resolved}
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, ft); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.MoveToolName: {decision: grantDecision()}}}
		if _, err := DispatchTool(context.Background(), filetools.MoveToolName, map[string]any{"source": "../outside/a.txt", "destination": "dst/a.txt"}, home, cwd, reg, auth); err != nil {
			t.Fatalf("DispatchTool: %v", err)
		}
		if !auth.displays[0].OutOfRootFileWrite {
			t.Fatalf("source prompt OutOfRootFileWrite = false for an out-of-root source, want true")
		}
		if auth.displays[1].OutOfRootFileWrite {
			t.Fatalf("destination prompt OutOfRootFileWrite = true for an in-root destination, want false")
		}
	})
}

func TestPrepareTool_ResolvesWithoutAuthorizingOrInvoking(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	target := filepath.Join(cwd, "sub", "file.go")
	scope := filepath.Join(cwd, "sub")

	ft := &fakeTargetTool{name: "edit", target: target, scope: scope}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}

	prepared, err := PrepareTool(context.Background(), "edit", map[string]any{"path": "sub/file.go"}, home, cwd, reg)
	if err != nil {
		t.Fatalf("PrepareTool: %v", err)
	}
	if prepared.Name() != "edit" {
		t.Fatalf("prepared Name = %q, want the exact registered name %q", prepared.Name(), "edit")
	}
	if prepared.Scope() != scope {
		t.Fatalf("prepared Scope = %q, want the resolved scope %q", prepared.Scope(), scope)
	}
	if ft.invoked {
		t.Fatal("PrepareTool invoked the tool, want resolution only")
	}
}

func TestPrepareTool_RefusesUnknownAndUnresolvableBeforePreparing(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()

	t.Run("unknown name", func(t *testing.T) {
		_, err := PrepareTool(context.Background(), "nope", nil, home, cwd, tools.NewRegistry())
		var noSuch *NoSuchToolError
		if !errors.As(err, &noSuch) || noSuch.Name != "nope" {
			t.Fatalf("error = %v, want *NoSuchToolError for nope", err)
		}
	})

	t.Run("unresolvable target", func(t *testing.T) {
		wantErr := errors.New("edit target rejected: outside the project root")
		ft := &fakeTargetTool{name: "edit", resolveErr: wantErr}
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, ft); err != nil {
			t.Fatalf("Register: %v", err)
		}
		_, err := PrepareTool(context.Background(), "edit", map[string]any{"path": "../escape.go"}, home, cwd, reg)
		if !errors.Is(err, wantErr) {
			t.Fatalf("error = %v, want the resolution error surfaced directly", err)
		}
		if ft.invoked {
			t.Fatal("failed preparation must not invoke the tool")
		}
	})
}

func TestDispatchPreparedTool_ReusesResolvedTargetAfterSwap(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	target := filepath.Join(cwd, "sub", "file.go")
	scope := filepath.Join(cwd, "sub")

	ft := &fakeTargetTool{name: "edit", target: target, scope: scope, result: tools.Result{Stdout: []byte("edited")}}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	prepared, err := PrepareTool(context.Background(), "edit", map[string]any{"path": "sub/file.go"}, home, cwd, reg)
	if err != nil {
		t.Fatalf("PrepareTool: %v", err)
	}

	swapped := filepath.Join(cwd, "elsewhere", "file.go")
	ft.target = swapped
	ft.scope = filepath.Join(cwd, "elsewhere")

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{"edit": {decision: grantDecision()}}}
	res, err := DispatchPreparedTool(context.Background(), prepared, auth)
	if err != nil {
		t.Fatalf("DispatchPreparedTool: %v", err)
	}
	if string(res.Stdout) != "edited" {
		t.Fatalf("result stdout = %q, want edited", res.Stdout)
	}
	if len(auth.requests) != 1 || auth.requests[0].PathScope != scope {
		t.Fatalf("authorized PathScope = %+v, want the prepared scope %q", auth.requests, scope)
	}
	if auth.modeCtxs[0].TargetPath != target {
		t.Fatalf("mode context TargetPath = %q, want the prepared target %q", auth.modeCtxs[0].TargetPath, target)
	}
	if ft.invokedTarget != target {
		t.Fatalf("invoked target = %q, want the prepared target %q (never a re-resolved one)", ft.invokedTarget, target)
	}
}

func TestDispatchPreparedTool_DeniedNotInvoked(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	env := permissions.BuildDenyEnvelope("nope")

	ft := &fakeTargetTool{name: "edit", target: filepath.Join(cwd, "f.go"), scope: cwd}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	prepared, err := PrepareTool(context.Background(), "edit", map[string]any{"path": "f.go"}, home, cwd, reg)
	if err != nil {
		t.Fatalf("PrepareTool: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{"edit": {decision: denyDecision(env), prompts: true}}}
	_, err = DispatchPreparedTool(context.Background(), prepared, auth)
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want *DeniedError", err)
	}
	if ft.invoked {
		t.Fatal("denied prepared call must not be invoked")
	}
}

func TestDispatchPreparedTool_UnpreparedCallRefusedBeforeAuthorizing(t *testing.T) {
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{}}
	if _, err := DispatchPreparedTool(context.Background(), PreparedTool{}, auth); err == nil {
		t.Fatal("DispatchPreparedTool(zero value) = nil error, want a refusal")
	}
	if len(auth.requests) != 0 {
		t.Fatalf("authorize calls = %d, want 0 (an unprepared call must not prompt)", len(auth.requests))
	}
}

func delegateArgs() map[string]any {
	return map[string]any{"instructions": "do it", "files": []any{"a.txt"}}
}

func TestPrepareTool_DelegateCandidateReachesAuthorizationWithoutStartingAChild(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	declared := map[string]bool{filepath.Join(cwd, "a.txt"): true}

	fd := &fakeDelegateTool{name: "delegate", instruction: "do it", declared: declared}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, fd); err != nil {
		t.Fatalf("Register: %v", err)
	}

	prepared, err := PrepareTool(context.Background(), "delegate", delegateArgs(), home, cwd, reg)
	if err != nil {
		t.Fatalf("PrepareTool: %v", err)
	}
	if fd.invoked {
		t.Fatal("PrepareTool started the child, want preparation only")
	}
	_, _, modeCtx := prepared.authorizationInputs()
	if !reflect.DeepEqual(modeCtx.DelegateWrite, declared) {
		t.Fatalf("mode context DelegateWrite = %v, want the canonical candidate %v", modeCtx.DelegateWrite, declared)
	}
	if prepared.Scope() != cwd {
		t.Fatalf("prepared Scope = %q, want the process cwd %q", prepared.Scope(), cwd)
	}
}

// A declaration that does not resolve is carried on the prepared call rather than returned, so the
// caller can let a ceiling answer first — dispatch does not know whether one is judging the call. The
// candidate stays empty either way (an unresolvable declaration is an unbounded child, not a subset
// of anything) and no child starts on any of the three paths out.
func TestPrepareTool_MalformedDelegateCarriesItsRefusalWithNoCandidate(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	wantErr := errors.New(`delegate: argument "files" must name at least one path the child may write`)
	malformed := map[string]any{"instructions": "do it"}

	fd := &fakeDelegateTool{name: "delegate", prepareErr: wantErr}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, fd); err != nil {
		t.Fatalf("Register: %v", err)
	}

	prepared, err := PrepareTool(context.Background(), "delegate", malformed, home, cwd, reg)
	if err != nil {
		t.Fatalf("PrepareTool error = %v, want the refusal carried on the prepared call", err)
	}
	if !errors.Is(prepared.DelegateRefusal(), wantErr) {
		t.Fatalf("DelegateRefusal = %v, want the tool's own refusal", prepared.DelegateRefusal())
	}
	_, _, modeCtx := prepared.authorizationInputs()
	if len(modeCtx.DelegateWrite) != 0 {
		t.Fatalf("mode context DelegateWrite = %v, want an empty candidate for a ceiling to refuse", modeCtx.DelegateWrite)
	}
	if fd.invoked {
		t.Fatal("preparation started the child")
	}

	t.Run("a ceiling denial answers ahead of the refusal", func(t *testing.T) {
		_, err := InvokeDecided(context.Background(), prepared, denyDecision(permissions.BuildDenyEnvelope("out of ceiling")))
		var de *DeniedError
		if !errors.As(err, &de) {
			t.Fatalf("error = %v, want *DeniedError", err)
		}
		if fd.invoked {
			t.Fatal("a denied delegate call must not start a child")
		}
	})

	t.Run("an authorized call surfaces the refusal and starts nothing", func(t *testing.T) {
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{"delegate": {decision: grantDecision()}}}
		_, err := DispatchTool(context.Background(), "delegate", malformed, home, cwd, reg, auth)
		if !errors.Is(err, wantErr) {
			t.Fatalf("error = %v, want the preparation refusal surfaced", err)
		}
		if fd.invoked {
			t.Fatal("failed preparation must not start a child")
		}
	})
}

// A filesystem ancestor or symlink swap that would make the raw declaration re-resolve elsewhere
// must not reach invocation.
func TestInvokeDecided_DelegateStartsTheChildFromThePreparedDeclaration(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	declared := map[string]bool{filepath.Join(cwd, "a.txt"): true}

	fd := &fakeDelegateTool{name: "delegate", instruction: "do it", declared: declared, result: tools.Result{Stdout: []byte("child ran")}}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, fd); err != nil {
		t.Fatalf("Register: %v", err)
	}
	prepared, err := PrepareTool(context.Background(), "delegate", delegateArgs(), home, cwd, reg)
	if err != nil {
		t.Fatalf("PrepareTool: %v", err)
	}

	fd.instruction = "do something else"
	fd.declared = map[string]bool{filepath.Join(cwd, "elsewhere", "a.txt"): true}

	res, err := InvokeDecided(context.Background(), prepared, grantDecision())
	if err != nil {
		t.Fatalf("InvokeDecided: %v", err)
	}
	if string(res.Stdout) != "child ran" {
		t.Fatalf("result stdout = %q, want child ran", res.Stdout)
	}
	if fd.invokedArgs {
		t.Fatal("delegate was invoked from its raw arguments, want the prepared declaration")
	}
	if fd.invokedInstr != "do it" {
		t.Fatalf("invoked instruction = %q, want the prepared %q", fd.invokedInstr, "do it")
	}
	if !reflect.DeepEqual(fd.invokedDeclared, declared) {
		t.Fatalf("invoked declaration = %v, want the prepared %v (never a re-resolved one)", fd.invokedDeclared, declared)
	}
}

// Maps and slices are reference types, so an authorizer that writes to the declaration it is asked
// to judge would otherwise decide what the child is built from and how it is scheduled.
func TestPrepareTool_DelegateDeclarationSurvivesAMutatingAuthorizer(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	leaf := filepath.Join(cwd, "a.txt")
	widened := filepath.Join(cwd, "widened.txt")
	declared := map[string]bool{leaf: true}
	targets := []string{leaf, filepath.Join(cwd, "missing")}

	fd := &fakeDelegateTool{name: "delegate", instruction: "do it", declared: declared, targets: targets}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, fd); err != nil {
		t.Fatalf("Register: %v", err)
	}
	prepared, err := PrepareTool(context.Background(), "delegate", delegateArgs(), home, cwd, reg)
	if err != nil {
		t.Fatalf("PrepareTool: %v", err)
	}

	// The tool's own map and slice are no longer the prepared call's.
	declared[widened] = true
	targets[0] = widened

	req := prepared.IndependentRequest()
	req.ModeCtx.DelegateWrite[widened] = true
	delete(req.ModeCtx.DelegateWrite, leaf)

	seen := prepared.DelegateSchedulerTargets()
	seen[0] = widened

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{"delegate": {decision: grantDecision()}}}
	auth.onAuthorize = func(permissions.MatchRequest) {
		auth.modeCtxs[len(auth.modeCtxs)-1].DelegateWrite[widened] = true
	}
	if _, err := DispatchPreparedTool(context.Background(), prepared, auth); err != nil {
		t.Fatalf("DispatchPreparedTool: %v", err)
	}

	want := map[string]bool{leaf: true}
	if !reflect.DeepEqual(fd.invokedDeclared, want) {
		t.Fatalf("invoked declaration = %v, want the prepared leaves %v", fd.invokedDeclared, want)
	}
	wantTargets := []string{leaf, filepath.Join(cwd, "missing")}
	if !slices.Equal(prepared.DelegateSchedulerTargets(), wantTargets) {
		t.Fatalf("scheduler targets = %v, want %v", prepared.DelegateSchedulerTargets(), wantTargets)
	}
	if !reflect.DeepEqual(prepared.DelegateDeclaredWrite(), want) {
		t.Fatalf("declared write = %v, want %v", prepared.DelegateDeclaredWrite(), want)
	}
	if !prepared.DelegatePrepared() {
		t.Fatal("a resolved declaration reports no prepared delegate")
	}
}

func TestInvokeDecided_DeniedDelegateStartsNoChild(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()

	fd := &fakeDelegateTool{name: "delegate", instruction: "do it", declared: map[string]bool{filepath.Join(cwd, "a.txt"): true}}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, fd); err != nil {
		t.Fatalf("Register: %v", err)
	}
	prepared, err := PrepareTool(context.Background(), "delegate", delegateArgs(), home, cwd, reg)
	if err != nil {
		t.Fatalf("PrepareTool: %v", err)
	}

	_, err = InvokeDecided(context.Background(), prepared, denyDecision(permissions.BuildDenyEnvelope("out of ceiling")))
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want *DeniedError", err)
	}
	if fd.invoked {
		t.Fatal("a denied delegate call must not start a child")
	}
}

func TestPrepareTool_DelegateDeleteDeclarationSurvivesAMutatingAuthorizer(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	write := map[string]bool{filepath.Join(cwd, "a.txt"): true}
	old := filepath.Join(cwd, "old.txt")
	widened := filepath.Join(cwd, "widened.txt")
	remove := map[string]bool{old: true}

	fd := &fakeDelegateTool{name: "delegate", instruction: "do it", declared: write, remove: remove}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, fd); err != nil {
		t.Fatalf("Register: %v", err)
	}
	prepared, err := PrepareTool(context.Background(), "delegate", delegateArgs(), home, cwd, reg)
	if err != nil {
		t.Fatalf("PrepareTool: %v", err)
	}
	remove[widened] = true

	want := map[string]bool{old: true}
	_, _, modeCtx := prepared.authorizationInputs()
	if !reflect.DeepEqual(modeCtx.DelegateDelete, want) {
		t.Fatalf("mode context DelegateDelete = %v, want the canonical delete candidate %v", modeCtx.DelegateDelete, want)
	}
	modeCtx.DelegateDelete[widened] = true

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{"delegate": {decision: grantDecision()}}}
	auth.onAuthorize = func(permissions.MatchRequest) {
		auth.modeCtxs[len(auth.modeCtxs)-1].DelegateDelete[widened] = true
	}
	if _, err := DispatchPreparedTool(context.Background(), prepared, auth); err != nil {
		t.Fatalf("DispatchPreparedTool: %v", err)
	}
	if !reflect.DeepEqual(fd.invokedRemove, want) {
		t.Fatalf("invoked delete declaration = %v, want the prepared %v", fd.invokedRemove, want)
	}
	if !reflect.DeepEqual(fd.invokedDeclared, map[string]bool{filepath.Join(cwd, "a.txt"): true}) {
		t.Fatalf("invoked write declaration = %v, want the prepared write set", fd.invokedDeclared)
	}
}

func TestPrepareTool_DelegateDeleteFormKeepsOmittedApartFromSuppliedEmpty(t *testing.T) {
	for _, tc := range []struct {
		name    string
		remove  map[string]bool
		wantNil bool
	}{
		{"omitted", nil, true},
		{"supplied empty", map[string]bool{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			cwd := t.TempDir()
			fd := &fakeDelegateTool{name: "delegate", instruction: "do it", declared: map[string]bool{filepath.Join(cwd, "a.txt"): true}, remove: tc.remove}
			reg := tools.NewRegistry()
			if err := reg.Register(tools.BuiltinSource, fd); err != nil {
				t.Fatalf("Register: %v", err)
			}
			prepared, err := PrepareTool(context.Background(), "delegate", delegateArgs(), home, cwd, reg)
			if err != nil {
				t.Fatalf("PrepareTool: %v", err)
			}
			_, _, modeCtx := prepared.authorizationInputs()
			if got := modeCtx.DelegateDelete == nil; got != tc.wantNil || len(modeCtx.DelegateDelete) != 0 {
				t.Fatalf("mode context DelegateDelete = %#v, want nil=%v and empty", modeCtx.DelegateDelete, tc.wantNil)
			}
			if _, err := InvokeDecided(context.Background(), prepared, grantDecision()); err != nil {
				t.Fatalf("InvokeDecided: %v", err)
			}
			if got := fd.invokedRemove == nil; got != tc.wantNil {
				t.Fatalf("invoked delete declaration = %#v, want nil=%v", fd.invokedRemove, tc.wantNil)
			}
		})
	}
}

func TestPrepareTool_ReadContainmentVerdicts(t *testing.T) {
	home := t.TempDir()
	project := mustEval(t, t.TempDir())
	outside := mustEval(t, t.TempDir())
	if err := os.WriteFile(filepath.Join(project, "in.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "out.txt"), []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(project, "escape")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewReadTool(home, project, project, 65536)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	cases := []struct {
		name         string
		path         string
		wantExternal bool
		wantScope    string
	}{
		{"in project", "in.txt", false, project},
		{"explicit external path", filepath.Join(outside, "out.txt"), true, outside},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareTool(context.Background(), filetools.ReadToolName, map[string]any{"path": tc.path}, home, project, reg)
			if err != nil {
				t.Fatalf("PrepareTool: %v", err)
			}
			if prepared.ExternalRead() != tc.wantExternal {
				t.Fatalf("ExternalRead = %v, want %v for %q", prepared.ExternalRead(), tc.wantExternal, tc.path)
			}
			if prepared.Scope() != tc.wantScope {
				t.Fatalf("Scope = %q, want the real resolved folder %q", prepared.Scope(), tc.wantScope)
			}
		})
	}

	t.Run("symlink escape fails preparation", func(t *testing.T) {
		if _, err := PrepareTool(context.Background(), filetools.ReadToolName, map[string]any{"path": "escape/out.txt"}, home, project, reg); err == nil {
			t.Fatal("PrepareTool(symlink escape) = nil error, want the read tool's out-of-root refusal")
		}
	})
}

type guardFixture struct {
	policy      securitystate.Policy
	home        string
	projectRoot string
	settings    string
}

func newGuardFixture(t *testing.T) guardFixture {
	t.Helper()
	home := t.TempDir()
	projectRoot := t.TempDir()
	settings := filepath.Join(projectRoot, ".codemeld", "settings.yaml")
	global := filepath.Join(home, ".codemeld", "global", "settings.yaml")
	for _, dir := range []string{filepath.Dir(settings), filepath.Dir(global)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll(%q): %v", dir, err)
		}
	}
	if err := os.WriteFile(settings, []byte("permissions: []\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", settings, err)
	}
	return guardFixture{
		policy:      securitystate.Policy{SettingsPaths: []string{settings, global}},
		home:        home,
		projectRoot: projectRoot,
		settings:    settings,
	}
}

func asRefusal(t *testing.T, err error) *securitystate.Refusal {
	t.Helper()
	var refusal *securitystate.Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("error = %v (%T), want a typed protected-state refusal", err, err)
	}
	return refusal
}

// The registered tool is wired to fail resolution, so reaching its resolver at all would surface a
// different error than the refusal these cases expect.
func TestPrepareTool_GuardRefusesNominalEndpointBeforeResolving(t *testing.T) {
	f := newGuardFixture(t)
	paths := []struct {
		name string
		raw  string
	}{
		{"absolute", f.settings},
		{"relative", ".codemeld/settings.yaml"},
		{"dot-dot", "sub/../.codemeld/settings.yaml"},
		{"sidecar", ".codemeld/settings.yaml.lock"},
		{"absent global", "~/.codemeld/global/settings.yaml"},
	}
	for _, name := range []string{filetools.EditToolName, filetools.CreateToolName, filetools.DeleteToolName, filetools.MkdirToolName} {
		for _, p := range paths {
			t.Run(name+"/"+p.name, func(t *testing.T) {
				ft := &fakeTargetTool{name: name, resolveErr: errors.New("resolver must not run")}
				reg := tools.NewRegistry()
				if err := reg.Register(tools.BuiltinSource, ft); err != nil {
					t.Fatalf("Register: %v", err)
				}
				auth := &fakeAuthorizer{}

				_, err := DispatchTool(context.Background(), name, map[string]any{"path": p.raw}, f.home, f.projectRoot, reg, auth, f.policy)
				refusal := asRefusal(t, err)
				if refusal.Subject != name || refusal.SubjectKind != "tool" {
					t.Fatalf("refusal subject = %q/%q, want %q/tool", refusal.SubjectKind, refusal.Subject, name)
				}
				if refusal.Envelope != permissions.BuildGuardDenyEnvelope() {
					t.Fatalf("refusal envelope = %q, want the fixed guard envelope", refusal.Envelope)
				}
				if len(auth.requests) != 0 {
					t.Fatalf("authorize calls = %d, want 0 (the guard runs before authorization)", len(auth.requests))
				}
				if ft.invoked {
					t.Fatal("tool was invoked after a protected-state refusal")
				}
			})
		}
	}
}

// An endpoint whose lexical spelling is innocuous but whose resolved target is a protected identity
// is refused over the exact path invocation would have reused.
func TestPrepareTool_GuardRefusesResolvedAliasAfterResolution(t *testing.T) {
	f := newGuardFixture(t)
	real, err := filepath.EvalSymlinks(f.settings)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	ft := &fakeTargetTool{name: filetools.EditToolName, target: real, scope: filepath.Dir(real)}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &fakeAuthorizer{}

	_, err = DispatchTool(context.Background(), filetools.EditToolName, map[string]any{"path": "notes.txt"}, f.home, f.projectRoot, reg, auth, f.policy)
	refusal := asRefusal(t, err)
	if refusal.PathScope != filepath.Dir(real) {
		t.Fatalf("refusal PathScope = %q, want the resolved endpoint parent %q", refusal.PathScope, filepath.Dir(real))
	}
	if len(auth.requests) != 0 {
		t.Fatalf("authorize calls = %d, want 0", len(auth.requests))
	}
	if ft.invoked {
		t.Fatal("tool was invoked after a protected-state refusal")
	}
}

func TestPrepareTool_GuardRefusesMoveEndpoints(t *testing.T) {
	f := newGuardFixture(t)

	t.Run("nominal endpoints", func(t *testing.T) {
		cases := []struct {
			name        string
			source      string
			destination string
		}{
			{"source", f.settings, filepath.Join(f.projectRoot, "copy.yaml")},
			{"destination", filepath.Join(f.projectRoot, "copy.yaml"), f.settings},
			{"sidecar destination", filepath.Join(f.projectRoot, "copy.yaml"), f.settings + ".lock"},
			{"containing directory", filepath.Join(f.projectRoot, ".codemeld"), filepath.Join(f.projectRoot, "old")},
			{"project root", f.projectRoot, filepath.Join(f.projectRoot, "..", "moved")},
			{"home codemeld", "~/.codemeld", filepath.Join(f.home, "old")},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				mt := &fakeMoveTool{name: filetools.MoveToolName, resolveErr: errors.New("resolver must not run")}
				reg := tools.NewRegistry()
				if err := reg.Register(tools.BuiltinSource, mt); err != nil {
					t.Fatalf("Register: %v", err)
				}
				auth := &fakeAuthorizer{}
				args := map[string]any{"source": c.source, "destination": c.destination}

				_, err := DispatchTool(context.Background(), filetools.MoveToolName, args, f.home, f.projectRoot, reg, auth, f.policy)
				refusal := asRefusal(t, err)
				if refusal.Subject != filetools.MoveToolName {
					t.Fatalf("refusal Subject = %q, want move", refusal.Subject)
				}
				if len(auth.requests) != 0 || mt.invoked {
					t.Fatalf("authorize calls = %d, invoked = %v, want 0/false", len(auth.requests), mt.invoked)
				}
			})
		}
	})

	t.Run("resolved endpoints", func(t *testing.T) {
		real, err := filepath.EvalSymlinks(f.settings)
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		mt := &fakeMoveTool{name: filetools.MoveToolName, resolved: filetools.ResolvedMove{
			Source:           filepath.Join(f.projectRoot, "copy.yaml"),
			SourceScope:      f.projectRoot,
			Destination:      real,
			DestinationScope: filepath.Dir(real),
		}}
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, mt); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &fakeAuthorizer{}
		args := map[string]any{"source": "copy.yaml", "destination": "notes.yaml"}

		_, err = DispatchTool(context.Background(), filetools.MoveToolName, args, f.home, f.projectRoot, reg, auth, f.policy)
		refusal := asRefusal(t, err)
		if refusal.PathScope != filepath.Dir(real) {
			t.Fatalf("refusal PathScope = %q, want the resolved destination parent %q", refusal.PathScope, filepath.Dir(real))
		}
		if len(auth.requests) != 0 || mt.invoked {
			t.Fatalf("authorize calls = %d, invoked = %v, want 0/false", len(auth.requests), mt.invoked)
		}
	})
}

// A configured guard changes nothing for an ordinary target, and an ordinary resolution failure
// still surfaces as itself rather than as a protected-state refusal.
func TestDispatchTool_GuardLeavesUnprotectedCallsUnchanged(t *testing.T) {
	f := newGuardFixture(t)

	t.Run("authorized edit invokes", func(t *testing.T) {
		target := filepath.Join(f.projectRoot, "src", "main.go")
		ft := &fakeTargetTool{name: filetools.EditToolName, target: target, scope: filepath.Dir(target), result: tools.Result{Stdout: []byte("edited")}}
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, ft); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.EditToolName: {decision: grantDecision()}}}

		res, err := DispatchTool(context.Background(), filetools.EditToolName, map[string]any{"path": "src/main.go"}, f.home, f.projectRoot, reg, auth, f.policy)
		if err != nil {
			t.Fatalf("DispatchTool: %v", err)
		}
		if string(res.Stdout) != "edited" || !ft.invoked || ft.invokedTarget != target {
			t.Fatalf("stdout=%q invoked=%v target=%q, want the ordinary edit to run", res.Stdout, ft.invoked, ft.invokedTarget)
		}
		if len(auth.requests) != 1 {
			t.Fatalf("authorize calls = %d, want 1", len(auth.requests))
		}
	})

	t.Run("move both endpoints authorized", func(t *testing.T) {
		mt := &fakeMoveTool{name: filetools.MoveToolName, resolved: filetools.ResolvedMove{
			Source:           filepath.Join(f.projectRoot, "a.txt"),
			SourceScope:      f.projectRoot,
			Destination:      filepath.Join(f.projectRoot, "b.txt"),
			DestinationScope: f.projectRoot,
		}, result: tools.Result{Stdout: []byte("moved")}}
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, mt); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.MoveToolName: {decision: grantDecision()}}}

		res, err := DispatchTool(context.Background(), filetools.MoveToolName, map[string]any{"source": "a.txt", "destination": "b.txt"}, f.home, f.projectRoot, reg, auth, f.policy)
		if err != nil {
			t.Fatalf("DispatchTool: %v", err)
		}
		if string(res.Stdout) != "moved" || !mt.invoked {
			t.Fatalf("stdout=%q invoked=%v, want the ordinary move to run", res.Stdout, mt.invoked)
		}
	})

	t.Run("ordinary preparation errors stay distinct", func(t *testing.T) {
		wantErr := errors.New("edit target rejected: no safe parent")
		ft := &fakeTargetTool{name: filetools.EditToolName, resolveErr: wantErr}
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, ft); err != nil {
			t.Fatalf("Register: %v", err)
		}

		_, err := PrepareTool(context.Background(), filetools.EditToolName, map[string]any{"path": "src/main.go"}, f.home, f.projectRoot, reg, f.policy)
		if !errors.Is(err, wantErr) {
			t.Fatalf("PrepareTool error = %v, want the tool's own resolution error", err)
		}
		var refusal *securitystate.Refusal
		if errors.As(err, &refusal) {
			t.Fatal("an ordinary resolution error was reported as a protected-state refusal")
		}

		_, err = PrepareTool(context.Background(), "nope", map[string]any{"path": f.settings}, f.home, f.projectRoot, reg, f.policy)
		var noSuch *NoSuchToolError
		if !errors.As(err, &noSuch) {
			t.Fatalf("PrepareTool(unknown) error = %v, want *NoSuchToolError", err)
		}
	})

	t.Run("read of the settings file is not guarded", func(t *testing.T) {
		ft := &fakeTargetTool{name: filetools.ReadToolName, target: f.settings, scope: filepath.Dir(f.settings), result: tools.Result{Stdout: []byte("contents")}}
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, ft); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{filetools.ReadToolName: {decision: grantDecision()}}}

		if _, err := DispatchTool(context.Background(), filetools.ReadToolName, map[string]any{"path": f.settings}, f.home, f.projectRoot, reg, auth, f.policy); err != nil {
			t.Fatalf("DispatchTool(read) = %v, want the read to pass the guard", err)
		}
		if !ft.invoked {
			t.Fatal("read tool was not invoked; reads are deliberately outside the guard")
		}
	})
}

// registerBuiltinVCS registers every action of a real built-in template, so these cases route
// through a genuine *vcs.ActionTool rather than a stand-in that could satisfy the guard seam without
// carrying the production classification.
func registerBuiltinVCS(t *testing.T, reg *tools.Registry, name, repoRoot string, run cmdrunner.Runner, emit vcs.EventAppender) {
	t.Helper()
	tmpls, err := vcs.LoadBuiltinTemplates()
	if err != nil {
		t.Fatalf("LoadBuiltinTemplates: %v", err)
	}
	tmpl, ok := tmpls[name]
	if !ok {
		t.Fatalf("built-in template %q not loaded", name)
	}
	if err := vcs.RegisterActions(reg, tmpl, repoRoot, run, emit, 65536); err != nil {
		t.Fatalf("RegisterActions: %v", err)
	}
}

func countingEmit(n *int) vcs.EventAppender {
	return func(events.EventPayload) error {
		*n++
		return nil
	}
}

// A VCS action that could reach protected state is refused before authorization, so no mode posture,
// grant, cache entry, declared scope, or prompt outcome can let it run.
func TestDispatchTool_GuardRefusesVCSActionBeforeAuthorizing(t *testing.T) {
	f := newGuardFixture(t)
	wantScope := mustEval(t, f.projectRoot)
	actions := []struct {
		subject string
		args    map[string]any
		result  cmdrunner.RunResult
	}{
		{"vcs_restore_file", map[string]any{"path": ".codemeld/settings.yaml"}, cmdrunner.RunResult{}},
		{"vcs_stash", nil, cmdrunner.RunResult{ExitCode: 1}},
		{"vcs_branch_switch", map[string]any{"branch": "other"}, cmdrunner.RunResult{}},
		{"vcs_stash_pop", nil, cmdrunner.RunResult{}},
	}
	postures := []struct {
		name string
		auth authBehavior
	}{
		{"an authorizer that would grant", authBehavior{decision: grantDecision()}},
		{"an authorizer that would allow once", authBehavior{decision: permissions.Decision{Outcome: "once"}, prompts: true}},
		{"an authorizer that would deny", authBehavior{decision: denyDecision("denied")}},
	}
	for _, action := range actions {
		for _, posture := range postures {
			t.Run(action.subject+"/"+posture.name, func(t *testing.T) {
				emitted := 0
				run := &fakeCmdRunner{id: "0198f0ab-cdef-7000-8000-000000000001", result: action.result}
				reg := tools.NewRegistry()
				registerBuiltinVCS(t, reg, "git", f.projectRoot, run, countingEmit(&emitted))
				auth := &fakeAuthorizer{fallback: &posture.auth}

				_, err := DispatchTool(context.Background(), action.subject, action.args, f.home, f.projectRoot, reg, auth, f.policy)
				refusal := asRefusal(t, err)
				if refusal.SubjectKind != "tool" || refusal.Subject != action.subject {
					t.Fatalf("refusal subject = %q/%q, want tool/%s", refusal.SubjectKind, refusal.Subject, action.subject)
				}
				if refusal.PathScope != wantScope {
					t.Fatalf("refusal PathScope = %q, want the resolved execution cwd %q", refusal.PathScope, wantScope)
				}
				if len(auth.requests) != 0 {
					t.Fatalf("authorize calls = %d, want the refusal to precede authorization", len(auth.requests))
				}
				if emitted != 0 {
					t.Fatalf("tool-execution events = %d, want none; the action must not launch", emitted)
				}
			})
		}
	}
}

// The guard narrows nothing else: reads, staging, and committing approved bytes stay dispatchable.
func TestDispatchTool_GuardLeavesUsableVCSActionsAlone(t *testing.T) {
	f := newGuardFixture(t)
	cases := []struct {
		subject string
		args    map[string]any
	}{
		{"vcs_status", nil},
		{"vcs_add", map[string]any{"path": ".codemeld/settings.yaml"}},
		{"vcs_commit", map[string]any{"message": "track approved policy"}},
		{"vcs_restore_file", map[string]any{"path": "src/main.go"}},
	}
	for _, tc := range cases {
		t.Run(tc.subject, func(t *testing.T) {
			emitted := 0
			run := &fakeCmdRunner{id: "0198f0ab-cdef-7000-8000-000000000002"}
			reg := tools.NewRegistry()
			registerBuiltinVCS(t, reg, "git", f.projectRoot, run, countingEmit(&emitted))
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}

			if _, err := DispatchTool(context.Background(), tc.subject, tc.args, f.home, f.projectRoot, reg, auth, f.policy); err != nil {
				t.Fatalf("DispatchTool(%s) = %v, want the action to run", tc.subject, err)
			}
			if len(auth.requests) != 1 || run.calls != 1 || emitted != 2 {
				t.Fatalf("authorize=%d exec=%d events=%d, want one authorization, one execution, and its paired events", len(auth.requests), run.calls, emitted)
			}
		})
	}
}

// A dispatcher given no policy is deliberately unguarded, so the guard cannot change behavior for a
// caller that never configured protected state.
func TestDispatchTool_UnguardedDispatchStillRunsVCSActions(t *testing.T) {
	f := newGuardFixture(t)
	emitted := 0
	run := &fakeCmdRunner{id: "0198f0ab-cdef-7000-8000-000000000003"}
	reg := tools.NewRegistry()
	registerBuiltinVCS(t, reg, "git", f.projectRoot, run, countingEmit(&emitted))
	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}

	if _, err := DispatchTool(context.Background(), "vcs_restore_file", map[string]any{"path": "x"}, f.home, f.projectRoot, reg, auth); err != nil {
		t.Fatalf("DispatchTool = %v, want the unguarded action to run", err)
	}
	if run.calls != 1 || emitted != 2 {
		t.Fatalf("exec=%d events=%d, want the action to run once with its paired events", run.calls, emitted)
	}
}

// A custom VCS template's argv is unconstrained, so no project template action survives the guard.
func TestDispatchTool_GuardRefusesCustomVCSTemplateActions(t *testing.T) {
	f := newGuardFixture(t)
	emitted := 0
	run := &fakeCmdRunner{id: "0198f0ab-cdef-7000-8000-000000000004"}
	reg := tools.NewRegistry()
	tmpl := &vcs.Template{
		Name:   "git",
		Source: filepath.Join(f.projectRoot, ".codemeld", "vcs", "git.yaml"),
		Detect: &vcs.DetectSpec{Marker: ".git"},
		Actions: map[string]vcs.ActionSpec{
			"status": {Argv: []string{"git", "checkout", "--", ".codemeld/settings.yaml"}, Class: vcs.ClassReadOnly},
		},
	}
	if err := vcs.RegisterActions(reg, tmpl, f.projectRoot, run, countingEmit(&emitted), 65536); err != nil {
		t.Fatalf("RegisterActions: %v", err)
	}
	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}

	_, err := DispatchTool(context.Background(), "vcs_status", nil, f.home, f.projectRoot, reg, auth, f.policy)
	refusal := asRefusal(t, err)
	if refusal.Subject != "vcs_status" {
		t.Fatalf("refusal subject = %q, want vcs_status", refusal.Subject)
	}
	if len(auth.requests) != 0 || run.calls != 0 || emitted != 0 {
		t.Fatalf("authorize=%d exec=%d events=%d, want the refusal to precede all of them", len(auth.requests), run.calls, emitted)
	}
}

// The refusal is scoped to the directory the action would have executed in, resolved through the
// same symlink handling authorization uses.
func TestDispatchTool_GuardRefusalScopeIsTheResolvedActionCWD(t *testing.T) {
	f := newGuardFixture(t)
	link := filepath.Join(t.TempDir(), "repo-link")
	if err := os.Symlink(f.projectRoot, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	emitted := 0
	run := &fakeCmdRunner{id: "0198f0ab-cdef-7000-8000-000000000005"}
	reg := tools.NewRegistry()
	registerBuiltinVCS(t, reg, "git", link, run, countingEmit(&emitted))
	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}

	_, err := DispatchTool(context.Background(), "vcs_restore_file", map[string]any{"path": ".codemeld/settings.yaml"}, f.home, f.projectRoot, reg, auth, f.policy)
	refusal := asRefusal(t, err)
	if refusal.PathScope != mustEval(t, f.projectRoot) {
		t.Fatalf("refusal PathScope = %q, want the resolved repo root %q", refusal.PathScope, mustEval(t, f.projectRoot))
	}
	if emitted != 0 {
		t.Fatalf("tool-execution events = %d, want none", emitted)
	}
}

type scriptedCmdRunner struct {
	results map[string]cmdrunner.RunResult
	calls   int
}

var _ cmdrunner.Runner = (*scriptedCmdRunner)(nil)

func (s *scriptedCmdRunner) NewInvocationID() string { return "0198f0ab-cdef-7000-8000-000000000006" }

func (s *scriptedCmdRunner) Exec(_ context.Context, spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
	s.calls++
	res := s.results[strings.Join(spec.Argv, " ")]
	res.InvocationID = spec.InvocationID
	return res, nil
}

const (
	blockedEntrySource = "/cfg/global/settings.yaml"
	headSHA            = "0123456789abcdef0123456789abcdef01234567"
	baseSHA            = "89abcdef0123456789abcdef0123456789abcdef"
)

func blockedOnlyPolicy(home, entry string) securitystate.Policy {
	return securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, []permissions.BlockedEntry{{Path: entry, Source: blockedEntrySource}})}
}

func liveBlockedPolicy(home string, entries []permissions.BlockedEntry, switchAt int, next []permissions.BlockedEntry) (securitystate.Policy, func() int) {
	calls := 0
	blocked := permissions.NewLiveBlockedPaths(home, "", entries, func() permissions.BlockedReload {
		calls++
		if switchAt == 0 || calls < switchAt {
			return permissions.BlockedReload{}
		}
		return permissions.BlockedReload{Changed: true, Entries: next}
	})
	return securitystate.Policy{Blocked: blocked}, func() int { return calls }
}

func TestPrepareTool_DegradedListAsksForOutsideReads(t *testing.T) {
	home := t.TempDir()
	project := mustEval(t, t.TempDir())
	ext := mustEval(t, t.TempDir())
	secrets := mkdir(t, filepath.Join(ext, "secrets"))
	for _, f := range []string{filepath.Join(project, "a.txt"), filepath.Join(ext, "a.txt"), filepath.Join(secrets, "k")} {
		if err := os.WriteFile(f, []byte("hi\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewReadTool(home, project, project, 65536)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	degraded := securitystate.Policy{Blocked: permissions.NewLiveBlockedPaths(home, project, []permissions.BlockedEntry{{Path: secrets, Source: blockedEntrySource}}, func() permissions.BlockedReload {
		return permissions.BlockedReload{Problems: map[string]string{blockedEntrySource: "is not valid YAML"}}
	})}

	for _, tc := range []struct {
		name             string
		path             string
		open, externally bool
	}{
		{"read outside", filepath.Join(ext, "a.txt"), false, true},
		{"read in project", "a.txt", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareTool(context.Background(), filetools.ReadToolName, map[string]any{"path": tc.path}, home, project, reg, degraded)
			if err != nil {
				t.Fatalf("PrepareTool: %v", err)
			}
			if mc := prepared.IndependentRequest().ModeCtx; mc.OpenRead != tc.open || mc.ExternalRead != tc.externally {
				t.Fatalf("OpenRead = %v, ExternalRead = %v; want %v, %v", mc.OpenRead, mc.ExternalRead, tc.open, tc.externally)
			}
		})
	}

	t.Run("blocked target", func(t *testing.T) {
		auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
		_, err := DispatchTool(context.Background(), filetools.ReadToolName, map[string]any{"path": filepath.Join(secrets, "k")}, home, project, reg, auth, degraded)
		if refusal := asRefusal(t, err); refusal.Source != "blocked_path" || refusal.Entry != secrets {
			t.Fatalf("refusal = %+v, want blocked_path for %q", refusal, secrets)
		}
		if len(auth.requests) != 0 {
			t.Fatalf("authorize calls = %d, want the refusal before any", len(auth.requests))
		}
	})
}

func TestPrepareTool_OneBlockedListPerCall(t *testing.T) {
	f := newGuardFixture(t)
	secrets := filepath.Join(f.projectRoot, "secrets")
	entry := permissions.BlockedEntry{Path: secrets, Source: blockedEntrySource}
	moveInto := func(t *testing.T) *tools.Registry {
		t.Helper()
		reg := tools.NewRegistry()
		mt := &fakeMoveTool{name: filetools.MoveToolName, resolved: filetools.ResolvedMove{
			Source:           filepath.Join(f.projectRoot, "a.txt"),
			SourceScope:      f.projectRoot,
			Destination:      filepath.Join(secrets, "a.txt"),
			DestinationScope: secrets,
		}}
		if err := reg.Register(tools.BuiltinSource, mt); err != nil {
			t.Fatalf("Register: %v", err)
		}
		return reg
	}
	moveArgs := map[string]any{"source": "a.txt", "destination": "secrets/a.txt"}

	t.Run("a move with two endpoints reloads once", func(t *testing.T) {
		policy, calls := liveBlockedPolicy(f.home, nil, 0, nil)
		if _, err := PrepareTool(context.Background(), filetools.MoveToolName, moveArgs, f.home, f.projectRoot, moveInto(t), policy); err != nil {
			t.Fatalf("PrepareTool: %v", err)
		}
		if calls() != 1 {
			t.Fatalf("reload calls = %d, want 1", calls())
		}
	})

	t.Run("a VCS rewrite in a repository holding two entries reloads once", func(t *testing.T) {
		reg := tools.NewRegistry()
		run := &scriptedCmdRunner{results: map[string]cmdrunner.RunResult{"git rev-parse --verify --quiet other^{commit}": {Stdout: []byte(headSHA + "\n")}}}
		registerBuiltinVCS(t, reg, "git", f.projectRoot, run, countingEmit(new(int)))
		entries := []permissions.BlockedEntry{entry, {Path: filepath.Join(f.projectRoot, "keys"), Source: blockedEntrySource}}
		policy, calls := liveBlockedPolicy(f.home, entries, 0, nil)
		if _, err := PrepareTool(context.Background(), "vcs_branch_switch", map[string]any{"branch": "other"}, f.home, f.projectRoot, reg, policy); err != nil {
			t.Fatalf("PrepareTool: %v", err)
		}
		if calls() != 1 {
			t.Fatalf("reload calls = %d, want 1", calls())
		}
	})

	t.Run("a removal from the second reload on does not reach the call", func(t *testing.T) {
		policy, _ := liveBlockedPolicy(f.home, []permissions.BlockedEntry{entry}, 2, nil)
		_, err := PrepareTool(context.Background(), filetools.MoveToolName, moveArgs, f.home, f.projectRoot, moveInto(t), policy)
		if refusal := asRefusal(t, err); refusal.Source != "blocked_path" || refusal.Entry != secrets {
			t.Fatalf("refusal = %+v, want blocked_path for %q", refusal, secrets)
		}
	})
}

func TestDispatchTool_BlockedEntryRefusesVCSRewriteBeforeAuthorizing(t *testing.T) {
	f := newGuardFixture(t)
	wantScope := mustEval(t, f.projectRoot)
	secrets := filepath.Join(f.projectRoot, "secrets")
	resolves := func(rev, sha string) map[string]cmdrunner.RunResult {
		return map[string]cmdrunner.RunResult{"git rev-parse --verify --quiet " + rev: {Stdout: []byte(sha + "\n")}}
	}
	differs := cmdrunner.RunResult{ExitCode: 1}
	switchDiffers := resolves("other^{commit}", headSHA)
	switchDiffers["git --literal-pathspecs diff --quiet --no-ext-diff "+headSHA+" -- secrets"] = differs
	popDiffers := resolves("refs/stash", headSHA)
	popDiffers["git rev-parse --verify --quiet refs/stash^1"] = cmdrunner.RunResult{Stdout: []byte(baseSHA + "\n")}
	popDiffers["git --literal-pathspecs diff --quiet --no-ext-diff "+baseSHA+" "+headSHA+" -- secrets"] = differs

	cases := []struct {
		name    string
		entry   string
		subject string
		args    map[string]any
		results map[string]cmdrunner.RunResult
	}{
		{"restore of a path under the entry", secrets, "vcs_restore_file", map[string]any{"path": "secrets/k"}, nil},
		{"restore of the whole tree", secrets, "vcs_restore_file", map[string]any{"path": "."}, nil},
		{"stash with changes under the entry", secrets, "vcs_stash", nil, map[string]cmdrunner.RunResult{"git --literal-pathspecs diff --quiet --no-ext-diff -- secrets": differs}},
		{"branch switch to a revision differing under the entry", secrets, "vcs_branch_switch", map[string]any{"branch": "other"}, switchDiffers},
		{"stash pop", secrets, "vcs_stash_pop", nil, popDiffers},
		{"an entry equal to the root", f.projectRoot, "vcs_restore_file", map[string]any{"path": "src/main.go"}, nil},
		{"a repository inside the entry", filepath.Dir(f.projectRoot), "vcs_branch_switch", map[string]any{"branch": "other"}, resolves("other^{commit}", headSHA)},
		{"a failing query", secrets, "vcs_restore_file", map[string]any{"path": "secrets/k"}, map[string]cmdrunner.RunResult{"git --literal-pathspecs ls-files --error-unmatch -- secrets": {ExitCode: 128}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			emitted := 0
			run := &scriptedCmdRunner{results: tc.results}
			reg := tools.NewRegistry()
			registerBuiltinVCS(t, reg, "git", f.projectRoot, run, countingEmit(&emitted))
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}

			_, err := DispatchTool(context.Background(), tc.subject, tc.args, f.home, f.projectRoot, reg, auth, blockedOnlyPolicy(f.home, tc.entry))
			refusal := asRefusal(t, err)
			if refusal.Source != "blocked_path" || refusal.SubjectKind != "tool" || refusal.Subject != tc.subject || refusal.PathScope != wantScope {
				t.Fatalf("refusal = %+v, want blocked_path tool/%s in %q", refusal, tc.subject, wantScope)
			}
			if refusal.Entry != tc.entry || refusal.EntrySource != blockedEntrySource {
				t.Fatalf("Entry, EntrySource = %q, %q; want %q, %q", refusal.Entry, refusal.EntrySource, tc.entry, blockedEntrySource)
			}
			if len(auth.requests) != 0 || emitted != 0 {
				t.Fatalf("authorize=%d events=%d, want the refusal to precede authorization and launch", len(auth.requests), emitted)
			}
		})
	}

	t.Run("protected_state takes precedence", func(t *testing.T) {
		emitted := 0
		run := &scriptedCmdRunner{}
		reg := tools.NewRegistry()
		registerBuiltinVCS(t, reg, "git", f.projectRoot, run, countingEmit(&emitted))
		auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
		policy := f.policy
		policy.Blocked = blockedOnlyPolicy(f.home, secrets).Blocked

		_, err := DispatchTool(context.Background(), "vcs_restore_file", map[string]any{"path": "."}, f.home, f.projectRoot, reg, auth, policy)
		if refusal := asRefusal(t, err); refusal.Source != "protected_state" {
			t.Fatalf("refusal source = %q, want protected_state", refusal.Source)
		}
		if len(auth.requests) != 0 || emitted != 0 {
			t.Fatalf("authorize=%d events=%d, want neither", len(auth.requests), emitted)
		}
	})
}

func TestDispatchTool_BlockedEntryLeavesOtherVCSActionsAlone(t *testing.T) {
	f := newGuardFixture(t)
	secrets := filepath.Join(f.projectRoot, "secrets")
	resolved := map[string]cmdrunner.RunResult{"git rev-parse --verify --quiet other^{commit}": {Stdout: []byte(headSHA + "\n")}}
	cases := []struct {
		name    string
		subject string
		args    map[string]any
		results map[string]cmdrunner.RunResult
	}{
		{"restore of a path outside the entry", "vcs_restore_file", map[string]any{"path": "src/main.go"}, nil},
		{"branch switch with no difference under the entry", "vcs_branch_switch", map[string]any{"branch": "other"}, resolved},
		{"status", "vcs_status", nil, nil},
		{"diff", "vcs_diff", nil, nil},
		{"log", "vcs_log", nil, nil},
		{"add", "vcs_add", map[string]any{"path": "secrets/k"}, nil},
		{"commit", "vcs_commit", map[string]any{"message": "m"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			emitted := 0
			run := &scriptedCmdRunner{results: tc.results}
			reg := tools.NewRegistry()
			registerBuiltinVCS(t, reg, "git", f.projectRoot, run, countingEmit(&emitted))
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}

			if _, err := DispatchTool(context.Background(), tc.subject, tc.args, f.home, f.projectRoot, reg, auth, blockedOnlyPolicy(f.home, secrets)); err != nil {
				t.Fatalf("DispatchTool(%s) = %v, want the action to run", tc.subject, err)
			}
			if len(auth.requests) != 1 || emitted != 2 {
				t.Fatalf("authorize=%d events=%d, want one authorization and the action's paired events", len(auth.requests), emitted)
			}
		})
	}

	t.Run("no entry inside the repository runs no query", func(t *testing.T) {
		emitted := 0
		run := &scriptedCmdRunner{results: resolved}
		reg := tools.NewRegistry()
		registerBuiltinVCS(t, reg, "git", f.projectRoot, run, countingEmit(&emitted))
		auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}

		if _, err := DispatchTool(context.Background(), "vcs_branch_switch", map[string]any{"branch": "other"}, f.home, f.projectRoot, reg, auth, blockedOnlyPolicy(f.home, filepath.Join(f.home, ".ssh"))); err != nil {
			t.Fatalf("DispatchTool = %v, want the action to run", err)
		}
		if run.calls != 1 || emitted != 2 {
			t.Fatalf("exec=%d events=%d, want only the action itself to run", run.calls, emitted)
		}
	})
}

func TestToolPromptDisplay_CarriesLexicalRequestedTarget(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args map[string]any
		want string
	}{
		{"create", filetools.CreateToolName, map[string]any{"path": "a.md", "content": "x"}, "a.md"},
		{"edit", filetools.EditToolName, map[string]any{"path": "a.md"}, "a.md"},
		{"delete", filetools.DeleteToolName, map[string]any{"path": "a.md"}, "a.md"},
		{"mkdir", filetools.MkdirToolName, map[string]any{"path": "build/cache"}, "build/cache"},
		{"move", filetools.MoveToolName, map[string]any{"source": "a", "destination": "b"}, "a -> b"},
		{"read", filetools.ReadToolName, map[string]any{"path": "/outside/a.txt"}, "/outside/a.txt"},
		{"glob", filetools.GlobToolName, map[string]any{"pattern": "**/*.go", "path": "/outside"}, "/outside"},
		{"grep", filetools.GrepToolName, map[string]any{"pattern": "x", "path": "/outside"}, "/outside"},
		{"list", filetools.ListToolName, map[string]any{"path": "/outside"}, "/outside"},
		{"tree", filetools.TreeToolName, map[string]any{"path": "/outside"}, "/outside"},
		{"file_count", filetools.FileCountToolName, map[string]any{"path": "/outside"}, "/outside"},
		{"glob without a path", filetools.GlobToolName, map[string]any{"pattern": "**/*.go"}, ""},
		{"read with a non-string path", filetools.ReadToolName, map[string]any{"path": 7}, ""},
		{"unrelated tool", "vcs_status", map[string]any{"path": "/outside"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := toolPromptDisplay(tc.tool, tc.args, "")
			if got.RequestedTarget != tc.want {
				t.Fatalf("RequestedTarget = %q, want %q", got.RequestedTarget, tc.want)
			}
		})
	}
}

// The generic prompt Subject stays the registered tool name, so the requested target
// has to ride its own carrier rather than being read back out of the rendered JSON.
func TestToolPromptDisplay_RequestedTargetIsSeparateFromSubject(t *testing.T) {
	got := toolPromptDisplay(filetools.ReadToolName, map[string]any{"path": "/outside/a.txt"}, "")
	if got.Subject != filetools.ReadToolName {
		t.Fatalf("Subject = %q, want the registered tool name", got.Subject)
	}
	if got.RequestedTarget != "/outside/a.txt" {
		t.Fatalf("RequestedTarget = %q, want the lexical path argument", got.RequestedTarget)
	}
}

func TestIndependentRequest_MatchesWhatDispatchWouldAuthorize(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	target := filepath.Join(cwd, "sub", "file.go")
	scope := filepath.Join(cwd, "sub")

	ft := &fakeTargetTool{name: "edit", target: target, scope: scope, result: tools.Result{Stdout: []byte("edited")}}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	prepared, err := PrepareTool(context.Background(), "edit", map[string]any{"path": "sub/file.go"}, home, cwd, reg)
	if err != nil {
		t.Fatalf("PrepareTool: %v", err)
	}

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{"edit": {decision: grantDecision()}}}
	if _, err := DispatchPreparedTool(context.Background(), prepared, auth); err != nil {
		t.Fatalf("DispatchPreparedTool: %v", err)
	}

	independent := prepared.IndependentRequest()
	if !reflect.DeepEqual(independent.Req, auth.requests[0]) {
		t.Fatalf("IndependentRequest.Req = %+v, want the request DispatchPreparedTool authorized %+v", independent.Req, auth.requests[0])
	}
	if !reflect.DeepEqual(independent.Display, auth.displays[0]) {
		t.Fatalf("IndependentRequest.Display = %+v, want %+v", independent.Display, auth.displays[0])
	}
	if !reflect.DeepEqual(independent.ModeCtx, auth.modeCtxs[0]) {
		t.Fatalf("IndependentRequest.ModeCtx = %+v, want %+v", independent.ModeCtx, auth.modeCtxs[0])
	}
	if independent.PreparedTarget != target {
		t.Fatalf("IndependentRequest.PreparedTarget = %q, want the resolved target %q", independent.PreparedTarget, target)
	}
}

func TestPreparedTarget_FallsBackToTheResolvedScope(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, &fakeTool{name: "vcs_status", readOnly: true}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	prepared, err := PrepareTool(context.Background(), "vcs_status", nil, home, cwd, reg)
	if err != nil {
		t.Fatalf("PrepareTool: %v", err)
	}
	if prepared.PreparedTarget() != prepared.Scope() {
		t.Fatalf("PreparedTarget = %q, want the resolved scope %q for a tool with no file target", prepared.PreparedTarget(), prepared.Scope())
	}
}

func TestInvokeDecided_RunsOnItsOwnApprovalOnly(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	env := permissions.BuildDenyEnvelope("nope")

	newPrepared := func(t *testing.T) (*fakeTargetTool, PreparedTool) {
		t.Helper()
		ft := &fakeTargetTool{name: "edit", target: filepath.Join(cwd, "f.go"), scope: cwd, result: tools.Result{Stdout: []byte("edited")}}
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, ft); err != nil {
			t.Fatalf("Register: %v", err)
		}
		prepared, err := PrepareTool(context.Background(), "edit", map[string]any{"path": "f.go"}, home, cwd, reg)
		if err != nil {
			t.Fatalf("PrepareTool: %v", err)
		}
		return ft, prepared
	}

	t.Run("denied", func(t *testing.T) {
		ft, prepared := newPrepared(t)
		_, err := InvokeDecided(context.Background(), prepared, denyDecision(env))
		var de *DeniedError
		if !errors.As(err, &de) {
			t.Fatalf("error = %v, want *DeniedError", err)
		}
		if de.Envelope != env {
			t.Fatalf("envelope = %q, want this call's own envelope %q", de.Envelope, env)
		}
		if ft.invoked {
			t.Fatal("a denied member of an authorization group must not be invoked")
		}
	})

	t.Run("approved", func(t *testing.T) {
		ft, prepared := newPrepared(t)
		res, err := InvokeDecided(context.Background(), prepared, grantDecision())
		if err != nil {
			t.Fatalf("InvokeDecided: %v", err)
		}
		if string(res.Stdout) != "edited" || ft.invokedTarget != prepared.PreparedTarget() {
			t.Fatalf("invoked target = %q with stdout %q, want the prepared target %q", ft.invokedTarget, res.Stdout, prepared.PreparedTarget())
		}
	})

	t.Run("unprepared", func(t *testing.T) {
		if _, err := InvokeDecided(context.Background(), PreparedTool{}, grantDecision()); err == nil {
			t.Fatal("InvokeDecided(zero value) = nil error, want a refusal")
		}
	})
}

// The replacement directory holds a byte-identical target, so every path-based check still passes and a
// refusal can only come from the identity captured before the prompt.
func prepareScopeSwapEdit(t *testing.T) (PreparedTool, string, string) {
	t.Helper()
	home := t.TempDir()
	project := mustEval(t, t.TempDir())
	scope := filepath.Join(project, "pkg")
	if err := os.Mkdir(scope, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	target := filepath.Join(scope, "main.go")
	const original = "package pkg\n\nfunc run() {\n\tfoo()\n}\n"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewEditTool(home, project, project)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	args := map[string]any{"path": "pkg/main.go", "old_text": "foo()", "new_text": "bar()"}
	prepared, err := PrepareTool(context.Background(), filetools.EditToolName, args, home, project, reg)
	if err != nil {
		t.Fatalf("PrepareTool: %v", err)
	}

	if err := os.RemoveAll(scope); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := os.Mkdir(scope, 0o755); err != nil {
		t.Fatalf("Mkdir(replacement): %v", err)
	}
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatalf("WriteFile(replacement target): %v", err)
	}
	return prepared, target, original
}

func TestInvokeDecided_EditRefusesAScopeReplacedWhileThePromptWasOpen(t *testing.T) {
	prepared, target, original := prepareScopeSwapEdit(t)

	res, err := InvokeDecided(context.Background(), prepared, grantDecision())
	if err != nil {
		t.Fatalf("InvokeDecided: %v, want the refusal in-band", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("result = %+v, want a non-zero refusal", res)
	}
	if got := string(res.Stderr); !strings.Contains(got, "authorized directory was replaced while the request was pending") {
		t.Fatalf("stderr = %q, want the pending-replacement refusal (not a missing-target or changed-content failure)", got)
	}
	if got := readTarget(t, target); got != original {
		t.Fatalf("target = %q, want byte-identical %q (nothing written)", got, original)
	}
}

func TestInvokeDecided_EditWithoutACapturedScopeIdentityRefuses(t *testing.T) {
	prepared, target, original := prepareScopeSwapEdit(t)
	prepared.scopeIdentity = filetools.ScopeIdentity{}

	res, err := InvokeDecided(context.Background(), prepared, grantDecision())
	if err != nil {
		t.Fatalf("InvokeDecided: %v, want the refusal in-band", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("result = %+v, want a non-zero refusal for an absent identity", res)
	}
	if got := readTarget(t, target); got != original {
		t.Fatalf("target = %q, want byte-identical %q (nothing written)", got, original)
	}
}

func TestInvokeDecided_CreateRefusesAScopeReplacedWhileThePromptWasOpen(t *testing.T) {
	home := t.TempDir()
	project := mustEval(t, t.TempDir())
	scope := filepath.Join(project, "pkg")
	if err := os.Mkdir(scope, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	target := filepath.Join(scope, "new.go")

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, project, project)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	args := map[string]any{"path": "pkg/new.go", "content": "package pkg\n"}
	prepared, err := PrepareTool(context.Background(), filetools.CreateToolName, args, home, project, reg)
	if err != nil {
		t.Fatalf("PrepareTool: %v", err)
	}

	if err := os.RemoveAll(scope); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := os.Mkdir(scope, 0o755); err != nil {
		t.Fatalf("Mkdir(replacement): %v", err)
	}

	res, err := InvokeDecided(context.Background(), prepared, grantDecision())
	if err != nil {
		t.Fatalf("InvokeDecided: %v, want the refusal in-band", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("result = %+v, want a non-zero refusal", res)
	}
	if got := string(res.Stderr); !strings.Contains(got, "authorized directory was replaced while the request was pending") {
		t.Fatalf("stderr = %q, want the pending-replacement refusal", got)
	}
	if _, serr := os.Lstat(target); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("Lstat(target) = %v, want the file never created in the replacement directory", serr)
	}
}

// The comparison is against the authorized scope, never the deepest ancestor existing at invocation.
func TestInvokeDecided_CreateStillRunsWhenOnlyAnIntermediateDirectoryAppeared(t *testing.T) {
	home := t.TempDir()
	project := mustEval(t, t.TempDir())
	target := filepath.Join(project, "a", "b", "new.go")

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, project, project)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	args := map[string]any{"path": "a/b/new.go", "content": "package b\n"}
	prepared, err := PrepareTool(context.Background(), filetools.CreateToolName, args, home, project, reg)
	if err != nil {
		t.Fatalf("PrepareTool: %v", err)
	}
	if prepared.Scope() != project {
		t.Fatalf("prepared Scope = %q, want the deepest existing ancestor %q", prepared.Scope(), project)
	}
	if err := os.Mkdir(filepath.Join(project, "a"), 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	res, err := InvokeDecided(context.Background(), prepared, grantDecision())
	if err != nil {
		t.Fatalf("InvokeDecided: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("result = %+v, stderr = %q, want a successful create", res, res.Stderr)
	}
	if got, want := readTarget(t, target), "package b\n"; got != want {
		t.Fatalf("file = %q, want %q", got, want)
	}
}

func TestInvokeDecided_OnlyMutatingFileToolsCarryTheAuthorizedScope(t *testing.T) {
	home := t.TempDir()
	project := mustEval(t, t.TempDir())

	mutating := []tools.Tool{
		filetools.NewEditTool(home, project, project),
		filetools.NewCreateTool(home, project, project),
		filetools.NewMkdirTool(home, project, project),
		filetools.NewDeleteTool(home, project, project),
	}
	for _, tool := range mutating {
		if _, ok := tool.(authorizedScopeInvoker); !ok {
			t.Fatalf("%s does not implement authorizedScopeInvoker, so dispatch would invoke it without the authorized directory's identity", tool.Name())
		}
	}

	readOnly := []tools.Tool{
		filetools.NewReadTool(home, project, project, 4096),
		filetools.NewGrepTool(home, project, project, 4096),
		filetools.NewGlobTool(home, project, project, 4096),
		filetools.NewListTool(home, project, project, 4096),
		filetools.NewTreeTool(home, project, project, 4096),
		filetools.NewFileCountTool(home, project, project, 4096),
		filetools.NewReadImageTool(home, project, project, 4096),
	}
	for _, tool := range readOnly {
		if _, ok := tool.(authorizedScopeInvoker); ok {
			t.Fatalf("%s implements authorizedScopeInvoker, want the read-only tools left on the unchanged resolved-target seam", tool.Name())
		}
		if _, ok := tool.(resolvedTargetInvoker); !ok {
			t.Fatalf("%s no longer implements resolvedTargetInvoker", tool.Name())
		}
	}
}

func TestPrepareTool_DelegateMovePairsSurviveAMutatingCaller(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	pair := permissions.MovePair{Source: filepath.Join(cwd, "a.txt"), Destination: filepath.Join(cwd, "b.txt")}
	widened := permissions.MovePair{Source: filepath.Join(cwd, "a.txt"), Destination: filepath.Join(cwd, "elsewhere.txt")}
	moves := map[permissions.MovePair]bool{pair: true}

	fd := &fakeDelegateTool{name: "delegate", instruction: "do it", moves: moves}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, fd); err != nil {
		t.Fatalf("Register: %v", err)
	}
	prepared, err := PrepareTool(context.Background(), "delegate", delegateArgs(), home, cwd, reg)
	if err != nil {
		t.Fatalf("PrepareTool: %v", err)
	}
	moves[widened] = true

	want := map[permissions.MovePair]bool{pair: true}
	_, _, modeCtx := prepared.authorizationInputs()
	if !reflect.DeepEqual(modeCtx.DelegateMoves, want) {
		t.Fatalf("mode context DelegateMoves = %v, want the canonical move candidate %v", modeCtx.DelegateMoves, want)
	}
	modeCtx.DelegateMoves[widened] = true

	if _, err := InvokeDecided(context.Background(), prepared, grantDecision()); err != nil {
		t.Fatalf("InvokeDecided: %v", err)
	}
	if !reflect.DeepEqual(fd.invokedMoves, want) {
		t.Fatalf("invoked move declaration = %v, want the prepared %v", fd.invokedMoves, want)
	}
}

func TestPrepareTool_DelegateMoveFormKeepsOmittedApartFromSuppliedEmpty(t *testing.T) {
	for _, tc := range []struct {
		name    string
		moves   map[permissions.MovePair]bool
		wantNil bool
	}{
		{"omitted", nil, true},
		{"supplied empty", map[permissions.MovePair]bool{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			cwd := t.TempDir()
			fd := &fakeDelegateTool{name: "delegate", instruction: "do it", declared: map[string]bool{filepath.Join(cwd, "a.txt"): true}, moves: tc.moves}
			reg := tools.NewRegistry()
			if err := reg.Register(tools.BuiltinSource, fd); err != nil {
				t.Fatalf("Register: %v", err)
			}
			prepared, err := PrepareTool(context.Background(), "delegate", delegateArgs(), home, cwd, reg)
			if err != nil {
				t.Fatalf("PrepareTool: %v", err)
			}
			_, _, modeCtx := prepared.authorizationInputs()
			if got := modeCtx.DelegateMoves == nil; got != tc.wantNil || len(modeCtx.DelegateMoves) != 0 {
				t.Fatalf("mode context DelegateMoves = %#v, want nil=%v and empty", modeCtx.DelegateMoves, tc.wantNil)
			}
			if _, err := InvokeDecided(context.Background(), prepared, grantDecision()); err != nil {
				t.Fatalf("InvokeDecided: %v", err)
			}
			if got := fd.invokedMoves == nil; got != tc.wantNil {
				t.Fatalf("invoked move declaration = %#v, want nil=%v", fd.invokedMoves, tc.wantNil)
			}
		})
	}
}

func TestInvokeDecided_CancelledAfterApprovalDoesNotInvoke(t *testing.T) {
	cwd := t.TempDir()
	ft := &fakeTargetTool{name: "edit", target: filepath.Join(cwd, "f.go"), scope: cwd, result: tools.Result{Stdout: []byte("edited")}}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	prepared, err := PrepareTool(context.Background(), "edit", map[string]any{"path": "f.go"}, t.TempDir(), cwd, reg)
	if err != nil {
		t.Fatalf("PrepareTool: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := InvokeDecided(ctx, prepared, grantDecision()); !errors.Is(err, context.Canceled) {
		t.Fatalf("InvokeDecided error = %v, want context.Canceled", err)
	}
	if ft.invoked {
		t.Fatal("the approved tool ran after cancellation")
	}
}

func TestDispatchTool_MoveCancelledDuringAuthorizationDoesNotInvoke(t *testing.T) {
	resolved := filetools.ResolvedMove{
		Source: "/proj/src/a.txt", SourceScope: "/proj/src",
		Destination: "/proj/dst/a.txt", DestinationScope: "/proj/dst",
	}
	ft := &fakeMoveTool{name: filetools.MoveToolName, resolved: resolved}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, ft); err != nil {
		t.Fatalf("Register: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth := &fakeAuthorizer{
		bySubject:   map[string]authBehavior{filetools.MoveToolName: {decision: grantDecision()}},
		onAuthorize: func(permissions.MatchRequest) { cancel() },
	}

	_, err := DispatchTool(ctx, filetools.MoveToolName, map[string]any{"source": "src/a.txt", "destination": "dst/a.txt"}, t.TempDir(), t.TempDir(), reg, auth)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DispatchTool error = %v, want context.Canceled", err)
	}
	if len(auth.requests) != 2 {
		t.Fatalf("authorize calls = %d, want both scopes authorized before the check", len(auth.requests))
	}
	if ft.invoked {
		t.Fatal("the move ran after cancellation")
	}
}
