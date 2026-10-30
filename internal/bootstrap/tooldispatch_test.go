// Tests for production tool-call dispatch wiring: the deferred tool-registry
// factory (degraded no-VCS path, VCS action registration, output-cap propagation,
// fresh/resume parity) and the turn.ToolDispatcher binding (bash -> DispatchShell,
// structured -> DispatchTool) including denial, unknown-tool, malformed-argument
// in-band handling, the result formatter, and controller-level loop/concurrency wiring.
package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/agent"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	cmdrunner "codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/skills"
	"codemeld.dev/codemeld/internal/subagenttool"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/turn"
	"codemeld.dev/codemeld/internal/vcs"
	"codemeld.dev/codemeld/internal/webresearch"
	"codemeld.dev/codemeld/internal/webresearch/exa"
)

// --- dispatch fakes ----------------------------------------------------------

// fakeDispatchRunner is a dispatch.Runner stub: it records Exec invocations and returns a
// canned result, so shell-dispatch routing is testable without launching a real process.
type fakeDispatchRunner struct {
	result cmdrunner.RunResult
	err    error
	calls  int32
}

func (f *fakeDispatchRunner) NewInvocationID() string { return ids.NewV7() }

func (f *fakeDispatchRunner) Exec(context.Context, cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
	atomic.AddInt32(&f.calls, 1)
	return f.result, f.err
}

func (f *fakeDispatchRunner) callCount() int { return int(atomic.LoadInt32(&f.calls)) }

// recordingAuthorizer is a dispatch.Authorizer stub returning a fixed decision/error and
// counting calls, so allow/deny/no-prompt paths are testable without the production gate.
type recordingAuthorizer struct {
	decision permissions.Decision
	err      error
	calls    int32
	mu       sync.Mutex
	modeCtxs []permissions.ModeContext
}

func (a *recordingAuthorizer) Authorize(_ context.Context, _ permissions.MatchRequest, _ dispatch.PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error) {
	atomic.AddInt32(&a.calls, 1)
	a.mu.Lock()
	a.modeCtxs = append(a.modeCtxs, modeCtx)
	a.mu.Unlock()
	return a.decision, a.err
}

func (a *recordingAuthorizer) callCount() int { return int(atomic.LoadInt32(&a.calls)) }

// lastModeCtx returns the mode-authorization context of the most recent Authorize call.
func (a *recordingAuthorizer) lastModeCtx(t *testing.T) permissions.ModeContext {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.modeCtxs) == 0 {
		t.Fatal("no Authorize call recorded")
	}
	return a.modeCtxs[len(a.modeCtxs)-1]
}

// stubStructuredTool is a tools.Tool stub for structured-dispatch tests.
type stubStructuredTool struct {
	name   string
	result tools.Result
	err    error
	calls  int32
}

func (t *stubStructuredTool) Name() string              { return t.name }
func (t *stubStructuredTool) SubjectKind() string       { return "tool" }
func (t *stubStructuredTool) Advertise() tools.Metadata { return tools.Metadata{} }
func (t *stubStructuredTool) Invoke(context.Context, map[string]any) (tools.Result, error) {
	atomic.AddInt32(&t.calls, 1)
	return t.result, t.err
}

func (t *stubStructuredTool) callCount() int { return int(atomic.LoadInt32(&t.calls)) }

// dispatcherFor builds a production dispatcher over the given collaborators with real
// (existing) temp dirs for home/process cwd, which path-scope resolution requires.
func dispatcherFor(t *testing.T, reg *tools.Registry, run dispatch.Runner, auth dispatch.Authorizer) *productionToolDispatcher {
	t.Helper()
	store := mkStore(t)
	return newProductionToolDispatcher(reg, run, auth, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 65536, securitystate.Policy{})
}

func bashCall(id, command string) turn.AssembledToolCall {
	raw, _ := json.Marshal(map[string]string{"command": command})
	return turn.AssembledToolCall{ID: id, Name: "bash", Arguments: string(raw)}
}

func structuredCall(id, name string, args map[string]any) turn.AssembledToolCall {
	raw, _ := json.Marshal(args)
	return turn.AssembledToolCall{ID: id, Name: name, Arguments: string(raw)}
}

func allow() permissions.Decision { return permissions.Decision{Outcome: "allow_once"} }
func deny(env string) permissions.Decision {
	return permissions.Decision{Outcome: "deny", DenyEnvelope: env}
}

// --- dispatcher: bash routing -----------------------------------------------

func TestProductionDispatcher_BashRoutesToShellAndRunsAuthorized(t *testing.T) {
	run := &fakeDispatchRunner{result: cmdrunner.RunResult{Stdout: []byte("hi\n")}}
	auth := &recordingAuthorizer{decision: allow()}
	d := dispatcherFor(t, tools.NewRegistry(), run, auth)

	res, err := d.Dispatch(context.Background(), bashCall("c1", "echo hi"))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if res.Content != "hi" {
		t.Fatalf("content = %q, want %q (captured stdout)", res.Content, "hi")
	}
	if auth.callCount() != 1 {
		t.Fatalf("authorizer calls = %d, want 1 (bash routes through the authorizer)", auth.callCount())
	}
	if run.callCount() != 1 {
		t.Fatalf("runner Exec calls = %d, want 1 (authorized bash runs through DispatchShell)", run.callCount())
	}
}

func TestProductionDispatcher_BashDeniedReturnsEnvelopeWithoutExecuting(t *testing.T) {
	run := &fakeDispatchRunner{}
	auth := &recordingAuthorizer{decision: deny("DENY-ENV")}
	d := dispatcherFor(t, tools.NewRegistry(), run, auth)

	res, err := d.Dispatch(context.Background(), bashCall("c1", "rm -rf /"))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil (a denial is an in-band result)", err)
	}
	if res.Content != "DENY-ENV" {
		t.Fatalf("content = %q, want the deny envelope %q", res.Content, "DENY-ENV")
	}
	if !res.Denied {
		t.Fatal("res.Denied = false, want true so the loop routes the envelope through DeliverDeny")
	}
	if run.callCount() != 0 {
		t.Fatalf("runner Exec calls = %d, want 0 (a denied command must not execute)", run.callCount())
	}
}

func TestProductionDispatcher_UnsupportedShellConstructSurfacedWithoutPrompt(t *testing.T) {
	// Bare simple compounds route to the literal path; use still-unsupported constructs to exercise
	// the in-band refusal.
	cases := map[string]string{
		"command substitution": "echo $(whoami)",
		"backtick":             "echo `whoami`",
		"bare newline":         "echo hi\nls",
	}
	for name, command := range cases {
		t.Run(name, func(t *testing.T) {
			run := &fakeDispatchRunner{}
			auth := &recordingAuthorizer{decision: allow()}
			d := dispatcherFor(t, tools.NewRegistry(), run, auth)

			res, err := d.Dispatch(context.Background(), bashCall("c1", command))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil (a rejected construct surfaces in-band)", err)
			}
			if res.Denied {
				t.Fatalf("Denied = true, want false")
			}
			if !strings.Contains(res.Content, "unsupported_shell_construct") {
				t.Fatalf("content = %q, want it to report the unsupported construct", res.Content)
			}
			if auth.callCount() != 0 {
				t.Fatalf("authorizer calls = %d, want 0 (a rejected construct is refused before prompting)", auth.callCount())
			}
			if run.callCount() != 0 {
				t.Fatalf("runner Exec calls = %d, want 0", run.callCount())
			}
		})
	}
}

func TestProductionDispatcher_PlanSerializesIneligibleCall(t *testing.T) {
	d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
	plan := d.Plan([]turn.AssembledToolCall{bashCall("c1", "echo hi")}, 3)
	if len(plan.Units) != 1 {
		t.Fatalf("plan units = %d, want 1 per call", len(plan.Units))
	}
	targets := plan.Units[0].Targets
	if len(targets) != 1 || targets[0] != productionToolDispatchTarget {
		t.Fatalf("Plan targets = %v, want the conservative production serialization target", targets)
	}
}

func TestProductionDispatcher_BashEmitsToolExecEventsAndCapsModelOutput(t *testing.T) {
	store := mkStore(t)
	run := &fakeDispatchRunner{result: cmdrunner.RunResult{Stdout: []byte(strings.Repeat("A", 12))}}
	d := newProductionToolDispatcher(tools.NewRegistry(), run, &recordingAuthorizer{decision: allow()}, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 4, securitystate.Policy{})

	res, err := d.Dispatch(context.Background(), bashCall("c1", "echo hi"))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if res.Content != "AAAA" {
		t.Fatalf("tool result content = %q, want capped model output %q", res.Content, "AAAA")
	}
	starts := kindEvents(t, store, events.KindToolExecStart)
	ends := kindEvents(t, store, events.KindToolExecEnd)
	if len(starts) != 1 || len(ends) != 1 {
		t.Fatalf("tool_exec events = %d start/%d end, want 1/1", len(starts), len(ends))
	}
	var end events.ToolExecEnd
	if err := json.Unmarshal(ends[0].Payload, &end); err != nil {
		t.Fatalf("decode tool_exec_end: %v", err)
	}
	if !end.Truncated || end.Stdout != "AAAA" || end.OriginalBytes == nil || end.OriginalBytes.Stdout != 12 {
		t.Fatalf("tool_exec_end = %+v, want capped stdout with original byte count", end)
	}
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("flush session: %v", err)
	}
	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("read persisted session: %v", err)
	}
	reloaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("reload persisted session: %v", err)
	}
	reloadedStore := sessions.New(store.Path(), reloaded)
	if got := len(kindEvents(t, reloadedStore, events.KindToolExecEnd)); got != 1 {
		t.Fatalf("persisted tool_exec_end events = %d, want 1", got)
	}
}

func TestProductionDispatcher_MalformedBashCommandSurfacesInBandWithoutExecuting(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	cases := []struct {
		name       string
		command    string
		wantReason string
	}{
		{"unterminated single quote", "echo 'x", "unterminated single quote"},
		{"unterminated double quote", `git "log`, "unterminated double quote"},
		{"dangling trailing backslash", `echo x\`, "dangling backslash"},
		{"empty remainder after cd prefix", "cd /tmp && ", "empty command after cd prefix"},
		{"empty pipeline stage", "ls | | wc", "empty pipeline stage"},
		{"unresolvable cd hint", "cd " + missing + " && git status", missing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := mkStore(t)
			run := &fakeDispatchRunner{}
			auth := &recordingAuthorizer{decision: allow()}
			d := newProductionToolDispatcher(tools.NewRegistry(), run, auth, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 65536, securitystate.Policy{})

			res, err := d.Dispatch(context.Background(), bashCall("c1", tc.command))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil (a malformed command surfaces in-band)", err)
			}
			if res.Denied {
				t.Fatalf("Denied = true, want false (a malformed command is not a permission denial)")
			}
			if !strings.Contains(res.Content, tc.wantReason) {
				t.Fatalf("content = %q, want it to carry the underlying reason %q", res.Content, tc.wantReason)
			}
			if auth.callCount() != 0 {
				t.Fatalf("authorizer calls = %d, want 0 (reclassifying the refusal must not authorize anything)", auth.callCount())
			}
			if run.callCount() != 0 {
				t.Fatalf("runner Exec calls = %d, want 0", run.callCount())
			}
			reloaded := reloadStore(t, store)
			if n := len(kindEvents(t, reloaded, events.KindToolExecStart)); n != 0 {
				t.Fatalf("tool_exec_start events = %d, want 0 (nothing ran)", n)
			}
			if n := len(kindEvents(t, reloaded, events.KindToolExecEnd)); n != 0 {
				t.Fatalf("tool_exec_end events = %d, want 0 (nothing ran)", n)
			}
			if matched := decodePermissionMatched(t, reloaded); len(matched) != 0 {
				t.Fatalf("permission_matched events = %#v, want none (no authorization was attempted)", matched)
			}
		})
	}
}

// A whitespace-only command never reaches DispatchShell: decodeBashCommand rejects it first, so it
// proves the older in-band rejection still holds rather than the malformed-command path.
func TestProductionDispatcher_WhitespaceOnlyBashCommandRejectedByArgumentDecode(t *testing.T) {
	run := &fakeDispatchRunner{}
	auth := &recordingAuthorizer{decision: allow()}
	d := dispatcherFor(t, tools.NewRegistry(), run, auth)

	res, err := d.Dispatch(context.Background(), bashCall("c1", "   "))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if res.Denied {
		t.Fatalf("Denied = true, want false")
	}
	if !strings.Contains(res.Content, "invalid bash arguments") {
		t.Fatalf("content = %q, want the argument-decode rejection", res.Content)
	}
	if auth.callCount() != 0 || run.callCount() != 0 {
		t.Fatalf("authorizer calls = %d, runner calls = %d, want 0/0", auth.callCount(), run.callCount())
	}
}

func TestProductionDispatcher_ShellInfrastructureFailuresStillAbortTheLoop(t *testing.T) {
	t.Run("hintless scope resolution failure", func(t *testing.T) {
		run := &fakeDispatchRunner{}
		auth := &recordingAuthorizer{decision: allow()}
		store := mkStore(t)
		missing := filepath.Join(t.TempDir(), "does-not-exist")
		d := newProductionToolDispatcher(tools.NewRegistry(), run, auth, t.TempDir(), missing, func() *sessions.Store { return store }, 65536, securitystate.Policy{})

		res, err := d.Dispatch(context.Background(), bashCall("c1", "git status"))
		if err == nil {
			t.Fatal("Dispatch error = nil, want a dispatch failure for an unresolvable process cwd")
		}
		var malformed *dispatch.MalformedCommandError
		if errors.As(err, &malformed) {
			t.Fatalf("error = %v, want it left unclassified so the turn still records dispatch_failed", err)
		}
		if res.Content != "" {
			t.Fatalf("content = %q, want empty on an internal failure", res.Content)
		}
	})

	t.Run("runner exec failure", func(t *testing.T) {
		boom := errors.New("runner boom")
		run := &fakeDispatchRunner{err: boom}
		auth := &recordingAuthorizer{decision: allow()}
		d := dispatcherFor(t, tools.NewRegistry(), run, auth)

		res, err := d.Dispatch(context.Background(), bashCall("c1", "git status"))
		if !errors.Is(err, boom) {
			t.Fatalf("Dispatch error = %v, want the runner failure propagated", err)
		}
		var malformed *dispatch.MalformedCommandError
		if errors.As(err, &malformed) {
			t.Fatalf("error = %v, want a runner failure left unclassified", err)
		}
		if res.Content != "" {
			t.Fatalf("content = %q, want empty on an internal failure", res.Content)
		}
	})
}

// --- dispatcher: structured routing -----------------------------------------

func TestProductionDispatcher_UnknownStructuredToolSurfacesNoSuchToolWithoutPrompt(t *testing.T) {
	auth := &recordingAuthorizer{decision: allow()}
	d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, auth)

	res, err := d.Dispatch(context.Background(), structuredCall("c1", "read_file", map[string]any{"path": "/x"}))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil (an unknown tool surfaces in-band)", err)
	}
	if !strings.Contains(res.Content, "no_such_tool: read_file") {
		t.Fatalf("content = %q, want a no_such_tool result", res.Content)
	}
	if auth.callCount() != 0 {
		t.Fatalf("authorizer calls = %d, want 0 (an unknown structured tool must not prompt)", auth.callCount())
	}
}

func TestProductionDispatcher_StructuredToolRunsAuthorized(t *testing.T) {
	reg := tools.NewRegistry()
	tool := &stubStructuredTool{name: "do_thing", result: tools.Result{Stdout: []byte("out\n")}}
	if err := reg.Register("src", tool); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &recordingAuthorizer{decision: allow()}
	d := dispatcherFor(t, reg, &fakeDispatchRunner{}, auth)

	res, err := d.Dispatch(context.Background(), structuredCall("c1", "do_thing", map[string]any{}))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if res.Content != "out" {
		t.Fatalf("content = %q, want %q (captured tool stdout)", res.Content, "out")
	}
	if tool.callCount() != 1 {
		t.Fatalf("tool Invoke calls = %d, want 1", tool.callCount())
	}
	if auth.callCount() != 1 {
		t.Fatalf("authorizer calls = %d, want 1 (a structured tool routes through the authorizer)", auth.callCount())
	}
}

// TestProductionDispatcher_PassesModeContext proves the production dispatcher's bash and structured
// routes carry the mode-authorization context the authorizer (and the permission-prompt posture) need:
// a bash call is classified mutating with no tool name; a structured call carries its registered name
// and its read-only class.
func TestProductionDispatcher_PassesModeContext(t *testing.T) {
	t.Run("bash is mutating with no tool name", func(t *testing.T) {
		auth := &recordingAuthorizer{decision: allow()}
		d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, auth)

		if _, err := d.Dispatch(context.Background(), bashCall("c1", "echo hi")); err != nil {
			t.Fatalf("Dispatch: %v", err)
		}
		mc := auth.lastModeCtx(t)
		if mc.Class != permissions.ClassMutating {
			t.Fatalf("bash Class = %q, want mutating", mc.Class)
		}
		if mc.ToolName != "" {
			t.Fatalf("bash ToolName = %q, want empty (raw shell has no tool name)", mc.ToolName)
		}
	})

	t.Run("structured tool carries its name and class", func(t *testing.T) {
		reg := tools.NewRegistry()
		if err := reg.Register("src", &stubStructuredTool{name: "do_thing"}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &recordingAuthorizer{decision: allow()}
		d := dispatcherFor(t, reg, &fakeDispatchRunner{}, auth)

		if _, err := d.Dispatch(context.Background(), structuredCall("c1", "do_thing", map[string]any{"path": "x"})); err != nil {
			t.Fatalf("Dispatch: %v", err)
		}
		mc := auth.lastModeCtx(t)
		if mc.ToolName != "do_thing" {
			t.Fatalf("structured ToolName = %q, want do_thing", mc.ToolName)
		}
		if mc.Class != permissions.ClassMutating {
			t.Fatalf("structured Class = %q, want mutating (stub advertises non-read-only)", mc.Class)
		}
	})
}

func TestProductionDispatcher_StructuredToolDeniedNotInvoked(t *testing.T) {
	reg := tools.NewRegistry()
	tool := &stubStructuredTool{name: "do_thing", result: tools.Result{Stdout: []byte("out\n")}}
	if err := reg.Register("src", tool); err != nil {
		t.Fatalf("Register: %v", err)
	}
	d := dispatcherFor(t, reg, &fakeDispatchRunner{}, &recordingAuthorizer{decision: deny("STRUCT-DENY")})

	res, err := d.Dispatch(context.Background(), structuredCall("c1", "do_thing", map[string]any{}))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil (a denial is in-band)", err)
	}
	if res.Content != "STRUCT-DENY" {
		t.Fatalf("content = %q, want the deny envelope", res.Content)
	}
	if !res.Denied {
		t.Fatal("res.Denied = false, want true so the loop routes the envelope through DeliverDeny")
	}
	if tool.callCount() != 0 {
		t.Fatalf("tool Invoke calls = %d, want 0 (a denied tool must not run)", tool.callCount())
	}
}

func TestProductionDispatcher_MalformedStructuredArgsNoPromptNoInvoke(t *testing.T) {
	reg := tools.NewRegistry()
	tool := &stubStructuredTool{name: "do_thing"}
	if err := reg.Register("src", tool); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &recordingAuthorizer{decision: allow()}
	d := dispatcherFor(t, reg, &fakeDispatchRunner{}, auth)

	res, err := d.Dispatch(context.Background(), turn.AssembledToolCall{ID: "c1", Name: "do_thing", Arguments: "{bad json"})
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil (malformed args surface in-band)", err)
	}
	if !strings.Contains(res.Content, "invalid tool arguments") {
		t.Fatalf("content = %q, want an invalid-arguments result", res.Content)
	}
	if auth.callCount() != 0 || tool.callCount() != 0 {
		t.Fatalf("authorizer/tool calls = %d/%d, want 0/0 (malformed args must not prompt or run)", auth.callCount(), tool.callCount())
	}
}

func TestProductionDispatcher_InternalErrorAbortsLoop(t *testing.T) {
	reg := tools.NewRegistry()
	if err := reg.Register("src", &stubStructuredTool{name: "do_thing"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	boom := errors.New("authorizer boom")
	d := dispatcherFor(t, reg, &fakeDispatchRunner{}, &recordingAuthorizer{err: boom})

	res, err := d.Dispatch(context.Background(), structuredCall("c1", "do_thing", map[string]any{}))
	if !errors.Is(err, boom) {
		t.Fatalf("Dispatch error = %v, want the internal error propagated (aborts the loop)", err)
	}
	if res.Content != "" {
		t.Fatalf("content = %q, want empty on an internal failure", res.Content)
	}
}

// --- result formatter --------------------------------------------------------

func TestFormatToolResult(t *testing.T) {
	cases := []struct {
		name          string
		res           tools.Result
		preserveNewln bool
		want          string
	}{
		{"stdout only", tools.Result{Stdout: []byte("hello\n")}, false, "hello"},
		{"stderr only", tools.Result{Stderr: []byte("oops\n")}, false, "oops"},
		{"both streams", tools.Result{Stdout: []byte("out"), Stderr: []byte("err")}, false, "out\nstderr:\nerr"},
		{"non-zero exit", tools.Result{Stdout: []byte("partial"), ExitCode: 2}, false, "partial\nexit status 2"},
		{"empty", tools.Result{}, false, "(no output)"},
		// preserveStdoutNewlines keeps read's verbatim trailing bytes; stderr metadata is still trimmed.
		{"preserve single trailing newline", tools.Result{Stdout: []byte("package main\n")}, true, "package main\n"},
		{"preserve multiple trailing newlines", tools.Result{Stdout: []byte("a\n\n")}, true, "a\n\n"},
		{"preserve newline-only stdout", tools.Result{Stdout: []byte("\n\n")}, true, "\n\n"},
		{"preserve does not touch stderr", tools.Result{Stdout: []byte("x\n"), Stderr: []byte("meta\n")}, true, "x\n\nstderr:\nmeta"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatToolResult(tc.res, 65536, tc.preserveNewln); got != tc.want {
				t.Fatalf("formatToolResult = %q, want %q", got, tc.want)
			}
		})
	}
	if got := formatToolResult(tools.Result{Stdout: []byte("abcdef")}, 3, false); got != "abc" {
		t.Fatalf("formatToolResult capped stdout = %q, want %q", got, "abc")
	}
}

// --- registry factory --------------------------------------------------------

func TestDefaultBuildToolRegistry_YieldsNonNilFactory(t *testing.T) {
	handoff, err := defaultBuildToolRegistry(nil)
	if err != nil {
		t.Fatalf("defaultBuildToolRegistry error = %v, want nil", err)
	}
	if _, ok := handoff.(*toolRegistryFactory); !ok {
		t.Fatalf("handoff type = %T, want *toolRegistryFactory", handoff)
	}
}

func TestRealizeToolRegistry_DegradedYieldsNonNilEmptyRegistry(t *testing.T) {
	cache := emptyCache(t, t.TempDir())
	store := mkStore(t)
	storeFn := func() *sessions.Store { return store }

	degraded := []struct {
		name   string
		active any
	}{
		{"no detection result", nil},
		{"nil template", &ActiveVCS{Template: nil, RepoRoot: "/repo"}},
		{"empty repo root", &ActiveVCS{Template: &vcs.Template{Name: "git"}, RepoRoot: ""}},
	}
	for _, tc := range degraded {
		t.Run(tc.name, func(t *testing.T) {
			reg, err := (&toolRegistryFactory{active: tc.active}).realize(cache, storeFn, t.TempDir(), t.TempDir(), securitystate.Policy{})
			if err != nil {
				t.Fatalf("realize error = %v, want nil (degraded VCS data must not fail launch)", err)
			}
			if reg == nil {
				t.Fatal("realize returned a nil registry, want a non-nil bare registry")
			}
			if _, ok := reg.Lookup("vcs_status"); ok {
				t.Fatal("degraded registry registered a vcs_<action> tool, want none")
			}
		})
	}

	// A non-factory handoff (a degraded launch, or an unexpected type) still yields a
	// non-nil registry so the dispatcher always has one to look up against.
	for _, handoff := range []any{nil, "not a factory"} {
		reg, err := realizeToolRegistry(handoff, cache, storeFn, t.TempDir(), t.TempDir(), securitystate.Policy{})
		if err != nil || reg == nil {
			t.Fatalf("realizeToolRegistry(%v) = (%v, %v), want a non-nil registry and no error", handoff, reg, err)
		}
	}
}

func TestRealizeToolRegistry_RegistersVCSActionsWhenActive(t *testing.T) {
	tmpl := &vcs.Template{
		Name:    "git",
		Source:  "/etc/codemeld/vcs/git.yaml",
		Actions: map[string]vcs.ActionSpec{"status": {Argv: []string{"git", "status"}}},
	}
	factory := &toolRegistryFactory{active: &ActiveVCS{Template: tmpl, RepoRoot: t.TempDir()}}

	reg, err := factory.realize(emptyCache(t, t.TempDir()), func() *sessions.Store { return mkStore(t) }, t.TempDir(), t.TempDir(), securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize error = %v, want nil", err)
	}
	if _, ok := reg.Lookup("vcs_status"); !ok {
		t.Fatal("active VCS data did not register vcs_status into the registry")
	}
}

// TestRealizeToolRegistry_RegistersBuiltinTools pins that the production tool-registry
// factory registers every built-in file tool for every launch (even with no active VCS),
// each with the expected classification: edit and create are mutating;
// read, glob, grep, and tree are read-only. Folds the former per-tool registration tests
// into one table keyed by tool name + read-only/mutating classification.
func TestRealizeToolRegistry_RegistersBuiltinTools(t *testing.T) {
	cases := []struct {
		name     string
		toolName string
		readOnly bool
	}{
		{name: "edit", toolName: filetools.EditToolName, readOnly: false},
		{name: "create", toolName: filetools.CreateToolName, readOnly: false},
		{name: "delete", toolName: filetools.DeleteToolName, readOnly: false},
		{name: "mkdir", toolName: filetools.MkdirToolName, readOnly: false},
		{name: "move", toolName: filetools.MoveToolName, readOnly: false},
		{name: "read", toolName: filetools.ReadToolName, readOnly: true},
		{name: "glob", toolName: filetools.GlobToolName, readOnly: true},
		{name: "grep", toolName: filetools.GrepToolName, readOnly: true},
		{name: "tree", toolName: filetools.TreeToolName, readOnly: true},
		{name: "file_count", toolName: filetools.FileCountToolName, readOnly: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			factory := &toolRegistryFactory{active: nil} // no VCS detected
			reg, err := factory.realize(emptyCache(t, t.TempDir()), func() *sessions.Store { return mkStore(t) }, t.TempDir(), t.TempDir(), securitystate.Policy{})
			if err != nil {
				t.Fatalf("realize error = %v, want nil", err)
			}
			tool, ok := reg.Lookup(tc.toolName)
			if !ok {
				t.Fatalf("%s tool not registered into the realized registry", tc.name)
			}
			if got := tool.Advertise().ReadOnly; got != tc.readOnly {
				if tc.readOnly {
					t.Fatalf("%s tool advertised mutating, want read-only", tc.name)
				}
				t.Fatalf("%s tool advertised read-only, want mutating", tc.name)
			}
		})
	}
}

func swapSearchBackend(f func(exa.Config) webresearch.SearchBackend) func() {
	prev := newSearchBackend
	newSearchBackend = f
	return func() { newSearchBackend = prev }
}

type stubSearchBackend struct {
	candidates []webresearch.Candidate
	err        error
	observe    func() []string
	mu         sync.Mutex
	queries    []string
	seenHosts  [][]string
}

func (b *stubSearchBackend) Search(_ context.Context, query string) ([]webresearch.Candidate, error) {
	b.mu.Lock()
	b.queries = append(b.queries, query)
	if b.observe != nil {
		b.seenHosts = append(b.seenHosts, b.observe())
	}
	b.mu.Unlock()
	if b.err != nil {
		return nil, b.err
	}
	return b.candidates, nil
}

func (b *stubSearchBackend) calls() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.queries...)
}

func (b *stubSearchBackend) hostsAtSearch() [][]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([][]string(nil), b.seenHosts...)
}

func webResearchRegistry(t *testing.T, settings map[string]any) *tools.Registry {
	return webResearchRegistryWith(t, settings, &stubSearchBackend{}, nil)
}

func webResearchRegistryWith(t *testing.T, settings map[string]any, backend webresearch.SearchBackend, capture *exa.Config) *tools.Registry {
	t.Helper()
	defer swapSearchBackend(func(cfg exa.Config) webresearch.SearchBackend {
		if capture != nil {
			*capture = cfg
		}
		return backend
	})()
	composed := map[string]any{}
	if settings != nil {
		composed["web_research"] = settings
	}
	cache, err := config.NewCache(composed, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	tmpl := &vcs.Template{
		Name:    "git",
		Source:  "/etc/codemeld/vcs/git.yaml",
		Actions: map[string]vcs.ActionSpec{"status": {Argv: []string{"git", "status"}}},
	}
	factory := &toolRegistryFactory{active: &ActiveVCS{Template: tmpl, RepoRoot: t.TempDir()}}
	reg, err := factory.realize(cache, func() *sessions.Store { return mkStore(t) }, t.TempDir(), t.TempDir(), securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize error = %v, want nil", err)
	}
	return reg
}

func webToolMetadataJSON(t *testing.T, reg *tools.Registry, name string) string {
	t.Helper()
	tool, ok := reg.Lookup(name)
	if !ok {
		t.Fatalf("%s not registered into the realized registry", name)
	}
	encoded, err := json.Marshal(tool.Advertise())
	if err != nil {
		t.Fatalf("marshal %s metadata: %v", name, err)
	}
	return string(encoded)
}

func TestRealizeToolRegistry_WebResearchDisabledRegistersNeitherWebTool(t *testing.T) {
	reg := webResearchRegistry(t, map[string]any{"enabled": false})
	advertised := toolNames(advertisedTools(reg, mode.Build))
	for _, name := range []string{webSearchToolName, webFetchToolName} {
		if _, ok := reg.Lookup(name); ok {
			t.Fatalf("%s registered while web research is explicitly disabled", name)
		}
		if slices.Contains(advertised, name) {
			t.Fatalf("%s advertised while web research is explicitly disabled: %v", name, advertised)
		}
	}
}

func TestRealizeToolRegistry_AbsentWebResearchBlockRegistersBothWebTools(t *testing.T) {
	reg := webResearchRegistry(t, nil)
	advertised := toolNames(advertisedTools(reg, mode.Build))
	for _, name := range []string{webSearchToolName, webFetchToolName} {
		if _, ok := reg.Lookup(name); !ok {
			t.Fatalf("%s not registered with no web_research block", name)
		}
		if !slices.Contains(advertised, name) {
			t.Fatalf("%s not advertised with no web_research block: %v", name, advertised)
		}
	}
}

func TestRealizeToolRegistry_WebResearchLeavesExistingRegistrationsIntact(t *testing.T) {
	for _, tc := range []struct {
		name     string
		settings map[string]any
	}{
		{"disabled", map[string]any{"enabled": false}},
		{"enabled", map[string]any{"enabled": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := webResearchRegistry(t, tc.settings)
			existing := []string{
				filetools.EditToolName, filetools.CreateToolName, filetools.DeleteToolName,
				filetools.MkdirToolName, filetools.MoveToolName, filetools.ReadToolName,
				filetools.GlobToolName, filetools.GrepToolName, filetools.ListToolName,
				filetools.TreeToolName, filetools.FileCountToolName, "vcs_status",
			}
			for _, name := range existing {
				tool, ok := reg.Lookup(name)
				if !ok {
					t.Fatalf("%s missing from the realized registry", name)
				}
				if _, isWeb := tool.(*webResearchTool); isWeb {
					t.Fatalf("%s was replaced by a web research tool", name)
				}
			}
		})
	}
}

func TestRealizeToolRegistry_WebResearchEnabledRegistersExactSchemas(t *testing.T) {
	reg := webResearchRegistry(t, map[string]any{"enabled": true})
	advertised := toolNames(advertisedTools(reg, mode.Build))
	for _, tc := range []struct {
		toolName string
		param    string
	}{
		{webSearchToolName, "query"},
		{webFetchToolName, "url"},
	} {
		t.Run(tc.toolName, func(t *testing.T) {
			tool, ok := reg.Lookup(tc.toolName)
			if !ok {
				t.Fatalf("%s not registered while web research is enabled", tc.toolName)
			}
			if !slices.Contains(advertised, tc.toolName) {
				t.Fatalf("%s not advertised: %v", tc.toolName, advertised)
			}
			md := tool.Advertise()
			if md.Description == "" {
				t.Fatalf("%s advertised an empty description", tc.toolName)
			}
			props, _ := md.Parameters["properties"].(map[string]any)
			param, _ := props[tc.param].(map[string]any)
			paramDesc, _ := param["description"].(string)
			if paramDesc == "" {
				t.Fatalf("%s.%s advertised an empty description: %v", tc.toolName, tc.param, md.Parameters)
			}
			want := map[string]any{
				"type": "object",
				"properties": map[string]any{
					tc.param: map[string]any{"type": "string", "description": paramDesc},
				},
				"required":             []string{tc.param},
				"additionalProperties": false,
			}
			if !reflect.DeepEqual(md.Parameters, want) {
				t.Fatalf("%s parameters = %#v, want %#v", tc.toolName, md.Parameters, want)
			}
		})
	}
}

// The advertised web_search description is the only place the candidate-first research loop is
// stated to the model, so it is pinned as a contract rather than left as prose.
func TestRealizeToolRegistry_WebSearchGuidanceRequiresSelectiveResearch(t *testing.T) {
	reg := webResearchRegistry(t, map[string]any{"enabled": true})
	tool, ok := reg.Lookup(webSearchToolName)
	if !ok {
		t.Fatalf("%s not registered while web research is enabled", webSearchToolName)
	}
	description := strings.ToLower(tool.Advertise().Description)

	for _, tc := range []struct {
		requirement string
		phrases     []string
	}{
		{"one targeted search at a time", []string{"one targeted search at a time"}},
		{"reviewing the candidates before searching again", []string{"read the candidates it returns before running another"}},
		{"an explicit selective web_fetch", []string{"call web_fetch on only the one or two candidate addresses"}},
		{"stopping once the evidence is sufficient", []string{"stop searching and fetching as soon as you have enough evidence"}},
		{"that a candidate carries no page content", []string{"it does not read any of them"}},
		{"that reading a candidate is separately approved", []string{"the user approves separately"}},
	} {
		found := false
		for _, phrase := range tc.phrases {
			if strings.Contains(description, phrase) {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s description does not require %s: %q", webSearchToolName, tc.requirement, description)
		}
	}
	for _, forbidden := range []string{"automatically", "fetches the results", "reads the results", "returns the page"} {
		if strings.Contains(description, forbidden) {
			t.Fatalf("%s description implies automatic result-host fetching (%q): %q", webSearchToolName, forbidden, description)
		}
	}

	fetchTool, ok := reg.Lookup(webFetchToolName)
	if !ok {
		t.Fatalf("%s not registered while web research is enabled", webFetchToolName)
	}
	if !strings.Contains(strings.ToLower(fetchTool.Advertise().Description), "web_search") {
		t.Fatalf("%s description does not point at a web_search result as a valid address: %q", webFetchToolName, fetchTool.Advertise().Description)
	}
}

func TestRealizeToolRegistry_WebResearchAPIKeyNeverAltersOrLeaksIntoRegistration(t *testing.T) {
	const sentinel = "do-not-disclose-this-key"
	keyless := webResearchRegistry(t, map[string]any{"enabled": true})
	variants := map[string]*tools.Registry{
		"empty key":      webResearchRegistry(t, map[string]any{"enabled": true, "api_key": ""}),
		"configured key": webResearchRegistry(t, map[string]any{"enabled": true, "api_key": sentinel, "max_results": 3, "timeout_seconds": 5}),
	}
	for _, name := range []string{webSearchToolName, webFetchToolName} {
		want := webToolMetadataJSON(t, keyless, name)
		for label, reg := range variants {
			got := webToolMetadataJSON(t, reg, name)
			if got != want {
				t.Fatalf("%s metadata with %s = %s, want the keyless metadata %s", name, label, got, want)
			}
			if strings.Contains(got, sentinel) {
				t.Fatalf("%s metadata with %s disclosed the configured key: %s", name, label, got)
			}
		}
	}
}

func TestRealizeToolRegistry_WebToolsCarryMutatingClassification(t *testing.T) {
	reg := webResearchRegistry(t, map[string]any{"enabled": true})
	build := toolNames(advertisedTools(reg, mode.Build))
	filtered := toolNames(advertisedTools(reg, mode.Plan))
	for _, name := range []string{webSearchToolName, webFetchToolName} {
		tool, ok := reg.Lookup(name)
		if !ok {
			t.Fatalf("%s not registered while web research is enabled", name)
		}
		if tool.Advertise().ReadOnly {
			t.Fatalf("%s advertised read-only, want mutating", name)
		}
		if !slices.Contains(build, name) {
			t.Fatalf("%s missing from the unfiltered advertised set: %v", name, build)
		}
		if slices.Contains(filtered, name) {
			t.Fatalf("%s survived the read-only advertised filter: %v", name, filtered)
		}
	}
	if !slices.Contains(filtered, filetools.ReadToolName) {
		t.Fatalf("read-only filter dropped %s as well: %v", filetools.ReadToolName, filtered)
	}
}

func TestProductionDispatcher_MalformedWebToolArgsStayDecoderErrors(t *testing.T) {
	reg := webResearchRegistry(t, map[string]any{"enabled": true})
	auth := &recordingAuthorizer{decision: allow()}
	d := dispatcherFor(t, reg, &fakeDispatchRunner{}, auth)

	res, err := d.Dispatch(context.Background(), turn.AssembledToolCall{ID: "c1", Name: webSearchToolName, Arguments: "{not json"})
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if !strings.Contains(res.Content, "invalid tool arguments") {
		t.Fatalf("content = %q, want the in-band decoder error", res.Content)
	}
	if auth.callCount() != 0 {
		t.Fatalf("authorizer calls = %d, want 0", auth.callCount())
	}
}

type recordingTransport struct {
	mu       sync.Mutex
	requests []string
	respond  func(*http.Request) (*http.Response, error)
}

func (t *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.requests = append(t.requests, r.URL.String())
	t.mu.Unlock()
	return t.respond(r)
}

func (t *recordingTransport) sent() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.requests...)
}

func (t *recordingTransport) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.requests)
}

func scriptedTransport(routes map[string]*http.Response) *recordingTransport {
	tr := &recordingTransport{}
	tr.respond = func(r *http.Request) (*http.Response, error) {
		bare := *r.URL
		bare.User = nil
		resp, ok := routes[bare.String()]
		if !ok {
			return nil, errors.New("no route")
		}
		return resp, nil
	}
	return tr
}

type hostAuthSpy struct {
	transport *recordingTransport
	denied    map[string]string
	mu        sync.Mutex
	reqs      []permissions.MatchRequest
	displays  []dispatch.PromptDisplay
	modeCtxs  []permissions.ModeContext
	dials     []int
	err       error
}

func (s *hostAuthSpy) Authorize(_ context.Context, req permissions.MatchRequest, disp dispatch.PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error) {
	sent := s.transport.count()
	s.mu.Lock()
	s.reqs = append(s.reqs, req)
	s.displays = append(s.displays, disp)
	s.modeCtxs = append(s.modeCtxs, modeCtx)
	s.dials = append(s.dials, sent)
	s.mu.Unlock()
	if s.err != nil {
		return permissions.Decision{}, s.err
	}
	if env, ok := s.denied[req.Host]; ok {
		return deny(env), nil
	}
	return allow(), nil
}

func (s *hostAuthSpy) hosts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.reqs {
		out = append(out, r.Host)
	}
	return out
}

func webFetchCall(url string) turn.AssembledToolCall {
	return structuredCall("c1", webFetchToolName, map[string]any{"url": url})
}

func decodeFetchResult(t *testing.T, content string, outputCap int) map[string]any {
	t.Helper()
	if len(content) > outputCap {
		t.Fatalf("fetch result is %d bytes, want <= the %d-byte output cap: %s", len(content), outputCap, content)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(content), &decoded); err != nil {
		t.Fatalf("fetch result is not valid JSON (%v): %s", err, content)
	}
	for key := range decoded {
		switch key {
		case "outcome", "content", "final_url":
		default:
			t.Fatalf("fetch result carries unexpected field %q: %s", key, content)
		}
	}
	if _, ok := decoded["outcome"].(string); !ok {
		t.Fatalf("fetch result has no outcome: %s", content)
	}
	return decoded
}

func webSearchDispatcherWith(t *testing.T, auth dispatch.Authorizer, tr http.RoundTripper, outputCap int, backend webresearch.SearchBackend, settings map[string]any) *productionToolDispatcher {
	t.Helper()
	store := mkStore(t)
	d := newProductionToolDispatcher(webResearchRegistryWith(t, settings, backend, nil), &fakeDispatchRunner{}, auth, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, outputCap, securitystate.Policy{})

	d.setWebFetch(config.WebResearchSettings{Enabled: true, TimeoutSeconds: 5})
	if d.fetchClient == nil {
		t.Fatal("setWebFetch left the fetch client nil; search has no source transport")
	}
	d.fetchClient.Transport = tr
	return d
}

func webSearchCall(query string) turn.AssembledToolCall {
	return structuredCall("c1", webSearchToolName, map[string]any{"query": query})
}

func searchCandidates(urls ...string) []webresearch.Candidate {
	var out []webresearch.Candidate
	for _, u := range urls {
		out = append(out, webresearch.Candidate{Title: "title of " + u, URL: u, Snippet: "snippet"})
	}
	return out
}

// decodeSearchResults pins the model-visible search schema: candidate metadata and an omitted
// count, with no field that would carry fetched page content.
func decodeSearchResults(t *testing.T, content string, outputCap int) ([]map[string]any, int) {
	t.Helper()
	if len(content) > outputCap {
		t.Fatalf("search result is %d bytes, want <= the %d-byte output cap: %s", len(content), outputCap, content)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(content), &decoded); err != nil {
		t.Fatalf("search result is not valid JSON (%v): %s", err, content)
	}
	for key := range decoded {
		switch key {
		case "candidates", "omitted":
		default:
			t.Fatalf("search result carries unexpected field %q: %s", key, content)
		}
	}
	raw, ok := decoded["candidates"].([]any)
	if !ok {
		t.Fatalf("search result has no candidates array: %s", content)
	}
	var candidates []map[string]any
	for _, item := range raw {
		candidate, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("candidate is not an object: %s", content)
		}
		for key := range candidate {
			switch key {
			case "title", "url", "snippet", "published_date":
			default:
				t.Fatalf("candidate carries unexpected field %q: %s", key, content)
			}
		}
		if _, ok := candidate["url"].(string); !ok {
			t.Fatalf("candidate has no url: %s", content)
		}
		candidates = append(candidates, candidate)
	}
	omitted, _ := decoded["omitted"].(float64)
	return candidates, int(omitted)
}

func candidateURLs(candidates []map[string]any) []string {
	var out []string
	for _, candidate := range candidates {
		url, _ := candidate["url"].(string)
		out = append(out, url)
	}
	return out
}

func TestRealizeToolRegistry_SearchBackendKeyedAndKeylessDifferOnlyByTheKey(t *testing.T) {
	const sentinel = "do-not-disclose-this-key"
	settings := func(extra map[string]any) map[string]any {
		s := map[string]any{"enabled": true, "max_results": 3, "timeout_seconds": 5}
		for k, v := range extra {
			s[k] = v
		}
		return s
	}
	var keyless, keyed exa.Config
	webResearchRegistryWith(t, settings(nil), &stubSearchBackend{}, &keyless)
	webResearchRegistryWith(t, settings(map[string]any{"api_key": sentinel}), &stubSearchBackend{}, &keyed)

	if keyless.APIKey != "" {
		t.Fatalf("keyless adapter key = %q, want empty", keyless.APIKey)
	}
	if keyed.APIKey != sentinel {
		t.Fatalf("keyed adapter key = %q, want the configured key", keyed.APIKey)
	}
	if keyless.MaxResults != 3 || keyless.Timeout != 5*time.Second {
		t.Fatalf("adapter results/timeout = %d/%v, want the configured 3/5s", keyless.MaxResults, keyless.Timeout)
	}
	if keyless.MaxOutputBytes <= 0 {
		t.Fatalf("adapter output cap = %d, want the configured tool-output cap", keyless.MaxOutputBytes)
	}
	if keyed.MaxResults != keyless.MaxResults || keyed.Timeout != keyless.Timeout || keyed.MaxOutputBytes != keyless.MaxOutputBytes {
		t.Fatalf("keyed adapter config = %+v, want the keyless config %+v apart from the key", keyed, keyless)
	}
	if keyed.HTTPClient == nil || keyless.HTTPClient == nil || keyed.HTTPClient.Timeout != keyless.HTTPClient.Timeout {
		t.Fatalf("keyed adapter client = %+v, want the same bounded client as the keyless one %+v", keyed.HTTPClient, keyless.HTTPClient)
	}

	tr := scriptedTransport(map[string]*http.Response{})
	auth := &hostAuthSpy{transport: tr}
	backend := &stubSearchBackend{candidates: searchCandidates("https://one.example/a")}
	d := webSearchDispatcherWith(t, auth, tr, 65536, backend, settings(map[string]any{"api_key": sentinel}))

	res, err := d.Dispatch(context.Background(), webSearchCall("codemeld"))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if strings.Contains(res.Content, sentinel) {
		t.Fatalf("search result disclosed the configured key: %s", res.Content)
	}
	if candidates, _ := decodeSearchResults(t, res.Content, 65536); !reflect.DeepEqual(candidateURLs(candidates), []string{"https://one.example/a"}) {
		t.Fatalf("keyed search candidates = %v, want the same candidate path as a keyless search", candidates)
	}
	for i, req := range auth.reqs {
		if strings.Contains(req.Host, sentinel) || strings.Contains(req.Subject, sentinel) || strings.Contains(auth.displays[i].HostRequest, sentinel) {
			t.Fatalf("authorization %d disclosed the configured key: %+v %+v", i, req, auth.displays[i])
		}
	}
}

// TestProductionDispatcher_DeleteToolEndToEndRemovesFileOnlyAfterGrant pins the delete tool on the
// production dispatcher: a real delete-tool call round-trips through the production dispatcher's
// authorization seam and execution path with no shell involved. Without an explicit grant (a denying
// authorizer) the file survives and the model gets the deny; with an
// explicit grant the file is removed through the real dispatch path, with the resolved target carried in
// the mode-authorization context.
func TestProductionDispatcher_DeleteToolEndToEndRemovesFileOnlyAfterGrant(t *testing.T) {
	setup := func(t *testing.T, decision permissions.Decision) (*recordingAuthorizer, string, turn.ToolResult) {
		t.Helper()
		project, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		file := filepath.Join(project, "doomed.txt")
		if err := os.WriteFile(file, []byte("bye\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, filetools.NewDeleteTool(t.TempDir(), project, project)); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &recordingAuthorizer{decision: decision}
		store := mkStore(t)
		d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, t.TempDir(), project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})
		res, derr := d.Dispatch(context.Background(), structuredCall("c1", "delete", map[string]any{"path": "doomed.txt"}))
		if derr != nil {
			t.Fatalf("Dispatch error = %v, want nil", derr)
		}
		return auth, file, res
	}

	t.Run("no grant leaves the file in place", func(t *testing.T) {
		auth, file, res := setup(t, deny(permissions.BuildDenyEnvelope("nope")))
		if auth.callCount() != 1 {
			t.Fatalf("authorizer calls = %d, want 1 (the delete routes through Authorize)", auth.callCount())
		}
		if !res.Denied {
			t.Fatalf("res.Denied = false, want true (no grant ⇒ delete denied); content=%q", res.Content)
		}
		if _, statErr := os.Stat(file); statErr != nil {
			t.Fatalf("file removed despite a denied delete: %v", statErr)
		}
	})

	t.Run("explicit grant removes the file through real dispatch", func(t *testing.T) {
		auth, file, res := setup(t, allow())
		if auth.callCount() != 1 {
			t.Fatalf("authorizer calls = %d, want 1 (the delete routes through Authorize)", auth.callCount())
		}
		if res.Denied {
			t.Fatalf("res.Denied = true, want an authorized delete; content=%q", res.Content)
		}
		if _, statErr := os.Stat(file); !os.IsNotExist(statErr) {
			t.Fatalf("file still present after an approved delete: %v", statErr)
		}
		if mc := auth.lastModeCtx(t); mc.TargetPath != file {
			t.Fatalf("mode context TargetPath = %q, want the resolved target %q", mc.TargetPath, file)
		}
	})
}

func TestRealizeToolRegistry_DeleteDescriptionStatesTheConditionalAllowance(t *testing.T) {
	reg, err := (&toolRegistryFactory{active: nil}).realize(emptyCache(t, t.TempDir()), func() *sessions.Store { return mkStore(t) }, t.TempDir(), t.TempDir(), securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize: %v", err)
	}
	tool, ok := reg.Lookup(filetools.DeleteToolName)
	if !ok {
		t.Fatal("delete not registered")
	}
	md := tool.Advertise()
	if !strings.Contains(md.Description, "irreversible and may need approval first") {
		t.Fatalf("delete description = %q, want it to say deletion may need approval", md.Description)
	}
	for _, stale := range []string{"always requires", "never auto-approved"} {
		if strings.Contains(md.Description, stale) {
			t.Fatalf("delete description = %q, still claims %q", md.Description, stale)
		}
	}
	path, _ := md.Parameters["properties"].(map[string]any)["path"].(map[string]any)["description"].(string)
	if !strings.Contains(path, "outside the project and every writable folder is allowed only after you approve it") {
		t.Fatalf("delete path description = %q, want the outside-both-scopes approval rule", path)
	}
}

func TestProductionDispatcher_ConstrainedAutoEditsDeleteRunsWithoutAsking(t *testing.T) {
	l := gateWritableLaunch(t, declaredScopeDir(t), declaredScopeDir(t), true, declaringWritableFolder)
	h := newWritableHarness(t, l, constrainedLaunch)
	outside := declaredScopeDir(t)
	projectFile := filepath.Join(l.project, "doomed.txt")
	link := filepath.Join(l.project, "link.txt")
	referent := filepath.Join(outside, "referent.txt")
	victim := filepath.Join(outside, "victim.txt")
	for _, path := range []string{projectFile, l.target, referent, victim} {
		if err := os.WriteFile(path, []byte("keep\n"), 0o600); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
	}
	if err := os.Symlink(referent, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(l.project, "outlink")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	for i, path := range []string{projectFile, l.target, link} {
		res, err := h.dispatcher.Dispatch(context.Background(), structuredCall(fmt.Sprintf("d%d", i), filetools.DeleteToolName, map[string]any{"path": path}))
		if err != nil || res.Denied {
			t.Fatalf("Dispatch(delete %s) = %+v, %v; want it removed", path, res, err)
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("%s still present after the delete: %v", path, err)
		}
	}
	if h.prompts != 0 {
		t.Fatalf("prompts = %d, want none for in-scope deletes", h.prompts)
	}
	if got := mustReadFile(t, referent); got != "keep\n" {
		t.Fatalf("link referent = %q, want it untouched", got)
	}
	allows := h.modeAutoAllows(t)
	if len(allows) != 3 {
		t.Fatalf("mode_auto matches = %+v, want 3", allows)
	}
	for _, m := range allows {
		if m.Subject != filetools.DeleteToolName || m.Outcome != "once" {
			t.Fatalf("mode_auto match = %+v, want a delete allowed once", m)
		}
	}

	h.deny = true
	res, err := h.dispatcher.Dispatch(context.Background(), structuredCall("d3", filetools.DeleteToolName, map[string]any{"path": filepath.Join(l.project, "outlink", "victim.txt")}))
	if err != nil || !res.Denied {
		t.Fatalf("Dispatch(delete through outlink) = %+v, %v; want it refused at the prompt", res, err)
	}
	if h.prompts != 1 {
		t.Fatalf("prompts = %d, want the outside delete to ask once", h.prompts)
	}
	if got := mustReadFile(t, victim); got != "keep\n" {
		t.Fatalf("outside target = %q, want it intact", got)
	}
}

// TestProductionDispatcher_MkdirToolEndToEndCreatesDirectoryUnderFolderGrant drives the production
// dispatcher over the *realized* production registry and the *real* production authorizer: a mkdir call —
// registered only through toolRegistryFactory.realize, never hand-registered — round-trips through the
// production dispatch + authorization seam and creates the (nested) directory with no shell involved. Build
// mode never auto-allows mkdir, so it reaches the gated prompt; approving a concrete mkdir *folder* grant
// authorizes the create, the prompt carries the distinct "Create directory" action over the target path
// (not a generic tool run), and the granted folder both short-circuits a later in-folder mkdir without
// re-prompting and persists durably to the folder settings file. It fails if realize stops registering
// mkdir (production dispatch then cannot find it), if the directory-create display regresses, or if a
// concrete mkdir folder grant stops matching or persisting.
func TestProductionDispatcher_MkdirToolEndToEndCreatesDirectoryUnderFolderGrant(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	wantTarget := filepath.Join(project, "build", "cache")

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
		return tui.PromptDecision{Option: tui.OptionAllowFolder}, nil
	}
	cache := emptyCache(t, project)
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(show), home, project, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, func() *sessions.Store { return store }, home, project, securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}
	run := &fakeDispatchRunner{}
	d := newProductionToolDispatcher(reg, run, auth, home, project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})

	// First create: no grant yet, so mkdir prompts; approving the folder grant creates build/cache through
	// the real dispatch path.
	res, derr := d.Dispatch(context.Background(), structuredCall("c1", filetools.MkdirToolName, map[string]any{"path": "build/cache"}))
	if derr != nil {
		t.Fatalf("Dispatch error = %v, want nil", derr)
	}
	if res.Denied {
		t.Fatalf("res.Denied = true, want an authorized mkdir; content=%q", res.Content)
	}
	if fi, statErr := os.Stat(wantTarget); statErr != nil || !fi.IsDir() {
		t.Fatalf("created dir %q: stat err %v isDir %v, want an existing directory (created through the real dispatch path)", wantTarget, statErr, fi != nil && fi.IsDir())
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times, want 1 (Build mode never auto-allows mkdir; it must reach the prompt)", shown)
	}
	if gotReq.Action != dispatch.ActionCreateDirectory {
		t.Fatalf("prompt action = %q, want the distinct directory-create label %q", gotReq.Action, dispatch.ActionCreateDirectory)
	}
	if gotReq.Subject != "build/cache" {
		t.Fatalf("prompt subject = %q, want the mkdir target path carried into the display (build/cache)", gotReq.Subject)
	}

	// Second create in the same granted folder: the concrete mkdir folder grant must authorize it without
	// re-prompting (its deepest-existing ancestor is the granted project folder).
	res2, derr2 := d.Dispatch(context.Background(), structuredCall("c2", filetools.MkdirToolName, map[string]any{"path": "data/logs"}))
	if derr2 != nil {
		t.Fatalf("Dispatch (second) error = %v, want nil", derr2)
	}
	if res2.Denied {
		t.Fatalf("second mkdir res.Denied = true, want the folder grant to authorize it; content=%q", res2.Content)
	}
	if fi, statErr := os.Stat(filepath.Join(project, "data", "logs")); statErr != nil || !fi.IsDir() {
		t.Fatalf("second created dir: stat err %v isDir %v, want an existing directory", statErr, fi != nil && fi.IsDir())
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times across two mkdir calls, want 1 (the folder grant must short-circuit the second)", shown)
	}
	if run.callCount() != 0 {
		t.Fatalf("runner Exec calls = %d, want 0 (mkdir creates the directory directly, never shells out)", run.callCount())
	}

	// The grant the prompt created is a durable mkdir *folder* grant scoped to the resolved existing-ancestor
	// folder (the project root), persisted to the folder settings file — not a one-shot allow.
	entry := findGrant(t, readPersistedPermissions(t, config.LocalSettingsPath(project), project), filetools.MkdirToolName)
	if entry.GrantKind != "folder" {
		t.Fatalf("persisted grant_kind = %q, want folder", entry.GrantKind)
	}
	if entry.PathScope != project {
		t.Fatalf("persisted path_scope = %q, want the resolved existing-ancestor folder %q", entry.PathScope, project)
	}
}

func TestProductionDispatcher_MoveToolEndToEndMovesFileUnderFolderGrant(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	source := filepath.Join(project, "old.txt")
	destination := filepath.Join(project, "new.txt")
	if err := os.WriteFile(source, []byte("keep me\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

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
		return tui.PromptDecision{Option: tui.OptionAllowFolder}, nil
	}
	cache := emptyCache(t, project)
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(show), home, project, mode.NewActiveState(mode.Build, mode.SourceDefault))

	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, func() *sessions.Store { return store }, home, project, securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}
	run := &fakeDispatchRunner{}
	d := newProductionToolDispatcher(reg, run, auth, home, project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})

	res, derr := d.Dispatch(context.Background(), structuredCall("c1", filetools.MoveToolName, map[string]any{
		"source": "old.txt", "destination": "new.txt",
	}))
	if derr != nil {
		t.Fatalf("Dispatch error = %v, want nil", derr)
	}
	if res.Denied {
		t.Fatalf("res.Denied = true, want an authorized move; content=%q", res.Content)
	}
	if got := mustReadFile(t, destination); got != "keep me\n" {
		t.Fatalf("destination = %q, want %q (the move applied through the real dispatch path with content preserved)", got, "keep me\n")
	}
	if _, statErr := os.Stat(source); !os.IsNotExist(statErr) {
		t.Fatalf("source still present after an approved move: %v", statErr)
	}
	if shown != 1 {
		t.Fatalf("prompt shown %d times, want 1 (Build mode auto-approves nothing and both endpoints share the project folder, so one grant covers it)", shown)
	}
	if gotReq.Action != dispatch.ActionMoveFile {
		t.Fatalf("prompt action = %q, want the distinct move label %q", gotReq.Action, dispatch.ActionMoveFile)
	}
	if gotReq.Subject != "old.txt -> new.txt" {
		t.Fatalf("prompt subject = %q, want both endpoints carried into the display (old.txt -> new.txt)", gotReq.Subject)
	}
	if run.callCount() != 0 {
		t.Fatalf("runner Exec calls = %d, want 0 (move renames the file directly, never shells out)", run.callCount())
	}

	// The grant the prompt created is a durable move *folder* grant whose subject stays the concrete
	// "move" name — move folds under no capability, so an existing write grant cannot authorize it.
	entry := findGrant(t, readPersistedPermissions(t, config.LocalSettingsPath(project), project), filetools.MoveToolName)
	if entry.GrantKind != "folder" {
		t.Fatalf("persisted grant_kind = %q, want folder", entry.GrantKind)
	}
	if entry.Subject != filetools.MoveToolName {
		t.Fatalf("persisted grant subject = %q, want the concrete %q (move never folds under the write capability)", entry.Subject, filetools.MoveToolName)
	}
	if entry.PathScope != project {
		t.Fatalf("persisted path_scope = %q, want the resolved endpoint folder %q", entry.PathScope, project)
	}
}

func TestProductionDispatcher_MoveToolAutoEditsInProjectNeedsNoPrompt(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	source := filepath.Join(project, "sub", "old.txt")
	destination := filepath.Join(project, "new.txt")
	if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(source, []byte("keep me\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		t.Errorf("prompt shown for an all-in-project Auto edits move: %+v", req)
		return tui.PromptDecision{Option: tui.OptionDeny}, nil
	}
	cache := emptyCache(t, project)
	turnCache := permissions.NewTurnCache()
	auth := newProductionAuthorizer(app, cache, turnCache, newPromptGateBuilder(show), home, project, mode.NewActiveState(mode.AutoEdits, mode.SourceDefault))

	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, func() *sessions.Store { return store }, home, project, securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})

	res, derr := d.Dispatch(context.Background(), structuredCall("c1", filetools.MoveToolName, map[string]any{
		"source": "sub/old.txt", "destination": "new.txt",
	}))
	if derr != nil {
		t.Fatalf("Dispatch error = %v, want nil", derr)
	}
	if res.Denied {
		t.Fatalf("res.Denied = true, want an Auto edits mode-auto move; content=%q", res.Content)
	}
	if got := mustReadFile(t, destination); got != "keep me\n" {
		t.Fatalf("destination = %q, want %q (the move applied through the real dispatch path)", got, "keep me\n")
	}
	if _, statErr := os.Stat(source); !os.IsNotExist(statErr) {
		t.Fatalf("source still present after the move: %v", statErr)
	}

	matched := decodePermissionMatched(t, reloadStore(t, store))
	if len(matched) != 2 {
		t.Fatalf("durable permission_matched events = %d, want 2 (one mode_auto per resolved move scope)", len(matched))
	}
	for _, m := range matched {
		if m.Outcome != "once" || m.OutcomeSource != "mode_auto" {
			t.Fatalf("permission_matched = %#v, want outcome once / outcome_source mode_auto", m)
		}
		if m.GrantKind != "" || m.GrantPathScope != "" {
			t.Fatalf("mode_auto move event carried grant fields: %#v", m)
		}
		if m.SubjectKind != "tool" || m.Subject != filetools.MoveToolName {
			t.Fatalf("permission_matched subject = %s/%s, want tool/%s", m.SubjectKind, m.Subject, filetools.MoveToolName)
		}
	}
	if got := len(cache.Permissions()); got != 0 {
		t.Fatalf("grant table holds %d entries, want 0 (a mode-auto move creates no grant)", got)
	}
	for _, scope := range []string{filepath.Dir(source), project} {
		req := permissions.MatchRequest{Kind: "tool", Subject: filetools.MoveToolName, PathScope: scope}
		if _, hit := turnCache.Lookup(req); hit {
			t.Fatalf("a mode-auto move wrote a turn-cache entry for scope %q", scope)
		}
	}
	if _, statErr := os.Stat(filepath.Join(project, ".codemeld", "settings.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("a mode-auto move persisted settings (stat err %v), want no persisted grant", statErr)
	}
}

func TestProductionDispatcher_MoveToolAutoEditsOutOfRootDeniedNotMoved(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(project, "escape")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	source := filepath.Join(project, "old.txt")
	if err := os.WriteFile(source, []byte("keep me\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	var shown int
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		shown++
		return tui.PromptDecision{Option: tui.OptionDeny}, nil
	}
	cache := emptyCache(t, project)
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(show), home, project, mode.NewActiveState(mode.AutoEdits, mode.SourceDefault))

	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, func() *sessions.Store { return store }, home, project, securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})

	res, derr := d.Dispatch(context.Background(), structuredCall("c1", filetools.MoveToolName, map[string]any{
		"source": "old.txt", "destination": "escape/new.txt",
	}))
	if derr != nil {
		t.Fatalf("Dispatch error = %v, want nil", derr)
	}
	if !res.Denied {
		t.Fatalf("res.Denied = false, want a denial; an out-of-root destination is never mode-auto approved (content=%q)", res.Content)
	}
	if shown == 0 {
		t.Fatal("prompt never shown, want the out-of-root move to reach the explicit authorization path")
	}
	if got := mustReadFile(t, source); got != "keep me\n" {
		t.Fatalf("source = %q, want it untouched after the denial", got)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "new.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("a denied move wrote outside the project root (stat err %v)", statErr)
	}
	for _, m := range decodePermissionMatched(t, reloadStore(t, store)) {
		if m.OutcomeSource == "mode_auto" {
			t.Fatalf("out-of-root move produced a mode_auto event: %#v", m)
		}
	}
}

// TestProductionDispatcher_EditToolEndToEndModifiesFile pins Done-when 5: a real edit-tool call
// round-trips through the production dispatcher's authorization seam and execution path and modifies
// the file, with the resolved target carried in the mode-authorization context.
func TestProductionDispatcher_EditToolEndToEndModifiesFile(t *testing.T) {
	project := t.TempDir()
	file := filepath.Join(project, "main.go")
	if err := os.WriteFile(file, []byte("package OLD\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	wantTarget, err := filepath.EvalSymlinks(file)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewEditTool(t.TempDir(), project, project)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &recordingAuthorizer{decision: allow()}
	store := mkStore(t)
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, t.TempDir(), project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})

	res, derr := d.Dispatch(context.Background(), structuredCall("c1", "edit", map[string]any{
		"path": "main.go", "old_text": "OLD", "new_text": "NEW",
	}))
	if derr != nil {
		t.Fatalf("Dispatch error = %v, want nil", derr)
	}
	if res.Denied {
		t.Fatalf("res.Denied = true, want an authorized edit; content=%q", res.Content)
	}
	if got := mustReadFile(t, file); got != "package NEW\n" {
		t.Fatalf("file = %q, want %q (the edit applied through the real dispatch path)", got, "package NEW\n")
	}
	if auth.callCount() != 1 {
		t.Fatalf("authorizer calls = %d, want 1 (the edit routes through Authorize)", auth.callCount())
	}
	if mc := auth.lastModeCtx(t); mc.TargetPath != wantTarget {
		t.Fatalf("mode context TargetPath = %q, want the resolved target %q", mc.TargetPath, wantTarget)
	}
}

// TestProductionDispatcher_EditToolOutOfRootRoutesThroughAuthorization pins folder approval end to end on the
// production dispatcher: an out-of-project edit target is no longer refused in-band before authorization;
// it routes through Authorize (the approval prompt) anchored on the resolved real out-of-root file. With
// no grant (a denying authorizer) the out-of-project file is left untouched and the model gets the deny;
// with an approving authorizer the edit applies to that out-of-project file.
func TestProductionDispatcher_EditToolOutOfRootRoutesThroughAuthorization(t *testing.T) {
	setup := func(t *testing.T, decision permissions.Decision) (*recordingAuthorizer, string, turn.ToolResult) {
		t.Helper()
		project := t.TempDir()
		outside := filepath.Join(t.TempDir(), "secret.txt")
		if err := os.WriteFile(outside, []byte("untouched\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, filetools.NewEditTool(t.TempDir(), project, project)); err != nil {
			t.Fatalf("Register: %v", err)
		}
		auth := &recordingAuthorizer{decision: decision}
		store := mkStore(t)
		d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, t.TempDir(), project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})
		res, err := d.Dispatch(context.Background(), structuredCall("c1", "edit", map[string]any{
			"path": outside, "old_text": "untouched", "new_text": "changed",
		}))
		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil", err)
		}
		return auth, outside, res
	}

	t.Run("deny leaves the out-of-project file untouched", func(t *testing.T) {
		auth, outside, res := setup(t, deny(permissions.BuildDenyEnvelope("nope")))
		if auth.callCount() != 1 {
			t.Fatalf("authorizer calls = %d, want 1 (an out-of-root edit prompts, not an in-band reject)", auth.callCount())
		}
		if !res.Denied {
			t.Fatalf("res.Denied = false, want true (no grant ⇒ out-of-root write denied); content=%q", res.Content)
		}
		if got := mustReadFile(t, outside); got != "untouched\n" {
			t.Fatalf("out-of-project file = %q, want untouched", got)
		}
	})

	t.Run("approval applies the edit to the out-of-project file", func(t *testing.T) {
		auth, outside, res := setup(t, allow())
		if auth.callCount() != 1 {
			t.Fatalf("authorizer calls = %d, want 1", auth.callCount())
		}
		if res.Denied {
			t.Fatalf("res.Denied = true, want an authorized out-of-root edit; content=%q", res.Content)
		}
		if got := mustReadFile(t, outside); got != "changed\n" {
			t.Fatalf("out-of-project file = %q, want the applied edit %q", got, "changed\n")
		}
	})
}

func TestProductionDispatcher_EditDisplayPatchOnlySurvivesASuccessfulWrite(t *testing.T) {
	const original = "alpha\nBETA\ngamma\n"
	const outputCap = 65536

	setup := func(t *testing.T, decision permissions.Decision, authErr error) (*productionToolDispatcher, string) {
		t.Helper()
		project, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		if err := os.WriteFile(filepath.Join(project, "doc.txt"), []byte(original), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		reg := tools.NewRegistry()
		for _, tool := range []tools.Tool{
			filetools.NewEditTool(t.TempDir(), project, project),
			filetools.NewCreateTool(t.TempDir(), project, project),
		} {
			if err := reg.Register(tools.BuiltinSource, tool); err != nil {
				t.Fatalf("Register: %v", err)
			}
		}
		store := mkStore(t)
		auth := &recordingAuthorizer{decision: decision, err: authErr}
		runner := &fakeDispatchRunner{result: cmdrunner.RunResult{Stdout: []byte("shell out\n")}}
		d := newProductionToolDispatcher(reg, runner, auth, t.TempDir(), project, func() *sessions.Store { return store }, outputCap, securitystate.Policy{})
		return d, project
	}
	editArgs := func(oldText, newText string) map[string]any {
		return map[string]any{"path": "doc.txt", "old_text": oldText, "new_text": newText}
	}

	t.Run("successful edit carries the approved patch beside unchanged content", func(t *testing.T) {
		d, project := setup(t, allow(), nil)
		file := filepath.Join(project, "doc.txt")
		args := editArgs("BETA", "DELTA")

		wantPatch, refusal := filetools.NewEditTool(t.TempDir(), project, project).Preview(file, args)
		if refusal != nil {
			t.Fatalf("Preview refusal = %+v, want the pre-authorization patch", *refusal)
		}

		res, err := d.Dispatch(context.Background(), structuredCall("c1", "edit", args))
		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil", err)
		}
		if res.DisplayPatch != wantPatch {
			t.Fatalf("DisplayPatch =\n%s\n--- want the pre-authorization patch ---\n%s", res.DisplayPatch, wantPatch)
		}
		wantContent := formatToolResult(tools.Result{Stdout: []byte("edited " + file + " (replaced 1 occurrence)\n")}, outputCap, false)
		if res.Content != wantContent {
			t.Fatalf("Content = %q, want the unchanged formatter output %q", res.Content, wantContent)
		}
		if strings.Contains(res.Content, "@@") {
			t.Fatalf("Content = %q leaked the patch into model-facing output", res.Content)
		}
		if got := mustReadFile(t, file); got != "alpha\nDELTA\ngamma\n" {
			t.Fatalf("file = %q, want the applied edit", got)
		}
	})

	t.Run("refused edit carries no patch", func(t *testing.T) {
		d, project := setup(t, allow(), nil)
		for _, tc := range []struct {
			name string
			args map[string]any
		}{
			{"stale", editArgs("ABSENT", "x")},
			{"ambiguous", editArgs("a", "x")},
			{"unchanged", editArgs("BETA", "BETA")},
		} {
			t.Run(tc.name, func(t *testing.T) {
				res, err := d.Dispatch(context.Background(), structuredCall("c1", "edit", tc.args))
				if err != nil {
					t.Fatalf("Dispatch error = %v, want nil (a refusal is in-band)", err)
				}
				if res.DisplayPatch != "" {
					t.Fatalf("DisplayPatch = %q, want empty for a refused edit", res.DisplayPatch)
				}
				if got := mustReadFile(t, filepath.Join(project, "doc.txt")); got != original {
					t.Fatalf("file = %q, want byte-identical %q", got, original)
				}
			})
		}
	})

	t.Run("malformed arguments carry no patch", func(t *testing.T) {
		d, _ := setup(t, allow(), nil)
		res, err := d.Dispatch(context.Background(), turn.AssembledToolCall{ID: "c1", Name: "edit", Arguments: "{not json"})
		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil (malformed arguments are in-band)", err)
		}
		if res.DisplayPatch != "" {
			t.Fatalf("DisplayPatch = %q, want empty for malformed arguments", res.DisplayPatch)
		}
	})

	t.Run("rejected target carries no patch", func(t *testing.T) {
		d, _ := setup(t, allow(), nil)
		res, err := d.Dispatch(context.Background(), structuredCall("c1", "edit", map[string]any{
			"path": "missing.txt", "old_text": "BETA", "new_text": "DELTA",
		}))
		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil (a rejected target is in-band)", err)
		}
		if res.DisplayPatch != "" {
			t.Fatalf("DisplayPatch = %q, want empty for a rejected target", res.DisplayPatch)
		}
		if !strings.Contains(res.Content, "edit target rejected") {
			t.Fatalf("Content = %q, want the in-band target refusal", res.Content)
		}
	})

	t.Run("failed write carries no patch", func(t *testing.T) {
		d, project := setup(t, allow(), nil)
		restore := fsutil.SetSyncFileForTest(func(*os.File) error { return errors.New("forced sync failure") })
		defer restore()

		res, err := d.Dispatch(context.Background(), structuredCall("c1", "edit", editArgs("BETA", "DELTA")))
		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil (a write failure is in-band)", err)
		}
		if res.DisplayPatch != "" {
			t.Fatalf("DisplayPatch = %q, want empty when the atomic write fails", res.DisplayPatch)
		}
		if got := mustReadFile(t, filepath.Join(project, "doc.txt")); got != original {
			t.Fatalf("file = %q, want byte-identical %q after a failed write", got, original)
		}
	})

	t.Run("denied edit carries no patch", func(t *testing.T) {
		d, project := setup(t, deny(permissions.BuildDenyEnvelope("nope")), nil)
		res, err := d.Dispatch(context.Background(), structuredCall("c1", "edit", editArgs("BETA", "DELTA")))
		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil (a denial is in-band)", err)
		}
		if !res.Denied {
			t.Fatalf("res.Denied = false, want true; content=%q", res.Content)
		}
		if res.DisplayPatch != "" {
			t.Fatalf("DisplayPatch = %q, want empty in a deny envelope result", res.DisplayPatch)
		}
		if got := mustReadFile(t, filepath.Join(project, "doc.txt")); got != original {
			t.Fatalf("file = %q, want byte-identical %q after a denial", got, original)
		}
	})

	t.Run("cancellation and dispatcher errors carry no patch", func(t *testing.T) {
		for name, authErr := range map[string]error{
			"cancelled":        context.Canceled,
			"internal failure": errors.New("authorizer exploded"),
		} {
			t.Run(name, func(t *testing.T) {
				d, _ := setup(t, allow(), authErr)
				res, err := d.Dispatch(context.Background(), structuredCall("c1", "edit", editArgs("BETA", "DELTA")))
				if !errors.Is(err, authErr) {
					t.Fatalf("Dispatch error = %v, want %v (an internal failure aborts the loop)", err, authErr)
				}
				if res.DisplayPatch != "" {
					t.Fatalf("DisplayPatch = %q, want empty for an aborted dispatch", res.DisplayPatch)
				}
			})
		}
	})

	t.Run("non-edit results carry no patch", func(t *testing.T) {
		d, project := setup(t, allow(), nil)

		created, err := d.Dispatch(context.Background(), structuredCall("c1", "create", map[string]any{
			"path": "new.txt", "content": "hello\n",
		}))
		if err != nil {
			t.Fatalf("create Dispatch error = %v, want nil", err)
		}
		if created.DisplayPatch != "" {
			t.Fatalf("create DisplayPatch = %q, want empty", created.DisplayPatch)
		}
		if got := mustReadFile(t, filepath.Join(project, "new.txt")); got != "hello\n" {
			t.Fatalf("created file = %q, want %q", got, "hello\n")
		}

		shell, err := d.Dispatch(context.Background(), turn.AssembledToolCall{ID: "c2", Name: "bash", Arguments: `{"command":"echo hi"}`})
		if err != nil {
			t.Fatalf("bash Dispatch error = %v, want nil", err)
		}
		if shell.DisplayPatch != "" {
			t.Fatalf("bash DisplayPatch = %q, want empty", shell.DisplayPatch)
		}
		if shell.Content != "shell out" {
			t.Fatalf("bash Content = %q, want the unchanged formatted output %q", shell.Content, "shell out")
		}
	})
}

// TestProductionDispatcher_CreateToolEndToEndCreatesFile pins Done-when 5: a real create-tool
// call round-trips through the production dispatcher's authorization seam and execution path and creates
// the file, with the resolved target carried in the mode-authorization context.
func TestProductionDispatcher_CreateToolEndToEndCreatesFile(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	file := filepath.Join(project, "new.go")
	wantTarget := filepath.Join(project, "new.go")

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(t.TempDir(), project, project)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &recordingAuthorizer{decision: allow()}
	store := mkStore(t)
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, t.TempDir(), project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})

	res, derr := d.Dispatch(context.Background(), structuredCall("c1", "create", map[string]any{
		"path": "new.go", "content": "package main\n",
	}))
	if derr != nil {
		t.Fatalf("Dispatch error = %v, want nil", derr)
	}
	if res.Denied {
		t.Fatalf("res.Denied = true, want an authorized create; content=%q", res.Content)
	}
	if got := mustReadFile(t, file); got != "package main\n" {
		t.Fatalf("file = %q, want %q (the create applied through the real dispatch path)", got, "package main\n")
	}
	if auth.callCount() != 1 {
		t.Fatalf("authorizer calls = %d, want 1 (the create routes through Authorize)", auth.callCount())
	}
	if mc := auth.lastModeCtx(t); mc.TargetPath != wantTarget {
		t.Fatalf("mode context TargetPath = %q, want the resolved target %q", mc.TargetPath, wantTarget)
	}
}

// TestProductionDispatcher_CreateToolExistingTargetSurfacesInBand pins the create-only contract end to
// end: a target that already exists is refused before authorization and surfaces in-band (not aborting
// the turn), and the existing file is left untouched.
func TestProductionDispatcher_CreateToolExistingTargetSurfacesInBand(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	file := filepath.Join(project, "exists.go")
	if err := os.WriteFile(file, []byte("package OLD\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(t.TempDir(), project, project)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &recordingAuthorizer{decision: allow()}
	store := mkStore(t)
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, t.TempDir(), project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})

	res, derr := d.Dispatch(context.Background(), structuredCall("c1", "create", map[string]any{
		"path": "exists.go", "content": "package NEW\n",
	}))
	if derr != nil {
		t.Fatalf("Dispatch error = %v, want nil (an existing target is in-band, not a turn abort)", derr)
	}
	if !strings.Contains(res.Content, "create target rejected") {
		t.Fatalf("content = %q, want an existing-target rejection message", res.Content)
	}
	if auth.callCount() != 0 {
		t.Fatalf("authorizer calls = %d, want 0 (an existing target is refused before prompting)", auth.callCount())
	}
	if got := mustReadFile(t, file); got != "package OLD\n" {
		t.Fatalf("existing file = %q, want untouched", got)
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	return string(b)
}

// TestProductionDispatcher_ReadToolEndToEndReturnsContent pins Done-when 5: a real read-tool call
// round-trips through the production dispatcher's authorization seam and returns the file content
// verbatim, with the resolved target carried in the mode-authorization context. read is read-only, so the
// recording authorizer (which the production binding wraps with the auto-allow posture) still sees the
// call but the model receives the file content rather than a denial.
func TestProductionDispatcher_ReadToolEndToEndReturnsContent(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	file := filepath.Join(project, "main.go")
	if err := os.WriteFile(file, []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, filetools.NewReadTool(t.TempDir(), project, project, 65536)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &recordingAuthorizer{decision: allow()}
	store := mkStore(t)
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, t.TempDir(), project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})

	res, derr := d.Dispatch(context.Background(), structuredCall("c1", "read", map[string]any{"path": "main.go"}))
	if derr != nil {
		t.Fatalf("Dispatch error = %v, want nil", derr)
	}
	if res.Denied {
		t.Fatalf("res.Denied = true, want an authorized read; content=%q", res.Content)
	}
	if !strings.Contains(res.Content, "package main") {
		t.Fatalf("content = %q, want the verbatim file content", res.Content)
	}
	if auth.callCount() != 1 {
		t.Fatalf("authorizer calls = %d, want 1 (the read routes through Authorize)", auth.callCount())
	}
	if mc := auth.lastModeCtx(t); mc.TargetPath != file {
		t.Fatalf("mode context TargetPath = %q, want the resolved target %q", mc.TargetPath, file)
	}
	if mc := auth.lastModeCtx(t); mc.Class != permissions.ClassReadOnly {
		t.Fatalf("mode context Class = %v, want read_only (read is read-only, req 20)", mc.Class)
	}
}

// TestProductionDispatcher_ReadPreservesTrailingNewlines pins the read tool's exact-text contract
// through the production dispatch path: read's stdout is verbatim file content, so a file ending in
// one or more newline bytes must reach the model with those bytes intact — the formatter's
// trailing-newline trim (correct for shell/command output) must not apply to read. Guards against the
// regression where "package main\n" was delivered as "package main".
func TestProductionDispatcher_ReadPreservesTrailingNewlines(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"single trailing newline", "package main\n"},
		{"multiple trailing newlines", "line one\nline two\n\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatalf("EvalSymlinks: %v", err)
			}
			file := filepath.Join(project, "main.go")
			if err := os.WriteFile(file, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			reg := tools.NewRegistry()
			if err := reg.Register(tools.BuiltinSource, filetools.NewReadTool(t.TempDir(), project, project, 65536)); err != nil {
				t.Fatalf("Register: %v", err)
			}
			store := mkStore(t)
			d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()}, t.TempDir(), project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})

			res, derr := d.Dispatch(context.Background(), structuredCall("c1", "read", map[string]any{"path": "main.go"}))
			if derr != nil {
				t.Fatalf("Dispatch error = %v, want nil", derr)
			}
			if res.Denied {
				t.Fatalf("res.Denied = true, want an authorized read; content=%q", res.Content)
			}
			// read carries its truncation metadata in a trailing "stderr:" segment, so the verbatim
			// file content is everything before it. That stdout segment must equal the file bytes
			// exactly — trailing newlines and all — which the buggy trim path corrupted.
			stdoutSegment, _, ok := strings.Cut(res.Content, "\nstderr:\n")
			if !ok {
				t.Fatalf("content = %q, want a trailing stderr metadata segment", res.Content)
			}
			if stdoutSegment != tc.content {
				t.Fatalf("read content segment = %q, want the verbatim file bytes %q", stdoutSegment, tc.content)
			}
		})
	}
}

// TestProductionDispatcher_ReadToolOutOfProjectPromptsThenReads pins the prompt contract for read at the
// production dispatch seam: an EXPLICIT out-of-project read target is no longer refused before
// authorization — it reaches the authorizer as a promptable external read (modeCtx.ExternalRead set), so
// approval reads the out-of-project file and a denial blocks it with the standard denial result, leaking
// no content. This supersedes the earlier "refused before prompting" behavior.
func TestProductionDispatcher_ReadToolOutOfProjectPromptsThenReads(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	outsideDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	outside := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outside, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	newDispatcher := func(auth dispatch.Authorizer) *productionToolDispatcher {
		reg := tools.NewRegistry()
		if err := reg.Register(tools.BuiltinSource, filetools.NewReadTool(t.TempDir(), project, project, 65536)); err != nil {
			t.Fatalf("Register: %v", err)
		}
		store := mkStore(t)
		return newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, t.TempDir(), project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})
	}

	t.Run("approved reaches the prompt then reads", func(t *testing.T) {
		auth := &recordingAuthorizer{decision: allow()}
		res, derr := newDispatcher(auth).Dispatch(context.Background(), structuredCall("c1", "read", map[string]any{"path": outside}))
		if derr != nil {
			t.Fatalf("Dispatch error = %v, want nil", derr)
		}
		if res.Denied {
			t.Fatalf("res.Denied = true, want an approved external read; content=%q", res.Content)
		}
		if auth.callCount() != 1 {
			t.Fatalf("authorizer calls = %d, want 1 (an explicit out-of-project read now prompts, not a pre-auth refusal)", auth.callCount())
		}
		if mc := auth.lastModeCtx(t); !mc.ExternalRead {
			t.Fatalf("modeCtx.ExternalRead = false, want true (an out-of-project read bypasses the read-only auto-allow)")
		}
		if !strings.Contains(res.Content, "secret") {
			t.Fatalf("content = %q, want the approved out-of-project file content", res.Content)
		}
	})

	t.Run("denied blocks the read and leaks nothing", func(t *testing.T) {
		auth := &recordingAuthorizer{decision: deny("DENY-ENV")}
		res, derr := newDispatcher(auth).Dispatch(context.Background(), structuredCall("c1", "read", map[string]any{"path": outside}))
		if derr != nil {
			t.Fatalf("Dispatch error = %v, want nil (a denied read is in-band, not a turn abort)", derr)
		}
		if !res.Denied {
			t.Fatalf("res.Denied = false, want a denied external read; content=%q", res.Content)
		}
		if strings.Contains(res.Content, "secret") {
			t.Fatalf("content = %q, leaked out-of-root file content on denial", res.Content)
		}
		if auth.callCount() != 1 {
			t.Fatalf("authorizer calls = %d, want 1", auth.callCount())
		}
	})
}

// TestRealizeToolRegistry_CapPropagatesToVCSActions pins Done-when 6: the factory threads
// Cache.MaxToolOutputBytes() into vcs.RegisterActions, so a registered action's persisted
// tool_exec_end output is truncated at the configured cap. The 512-byte output truncated to the
// 256-byte minimum cap fails if the default (65536) cap were used instead of the configured one.
func TestRealizeToolRegistry_CapPropagatesToVCSActions(t *testing.T) {
	const cap = 256
	const outLen = 512
	tmpl := &vcs.Template{
		Name:    "git",
		Source:  "/etc/codemeld/vcs/git.yaml",
		Actions: map[string]vcs.ActionSpec{"status": {Argv: []string{"printf", "%s", strings.Repeat("A", outLen)}}},
	}
	factory := &toolRegistryFactory{active: &ActiveVCS{Template: tmpl, RepoRoot: t.TempDir()}}

	cache, err := config.NewCache(map[string]any{
		"sessions": map[string]any{"max_tool_output_bytes": cap},
	}, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	store := mkStore(t)

	reg, err := factory.realize(cache, func() *sessions.Store { return store }, t.TempDir(), t.TempDir(), securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize error = %v", err)
	}
	tool, ok := reg.Lookup("vcs_status")
	if !ok {
		t.Fatal("vcs_status not registered")
	}
	if _, err := tool.Invoke(context.Background(), map[string]any{}); err != nil {
		t.Fatalf("Invoke vcs_status: %v", err)
	}

	ends := kindEvents(t, store, events.KindToolExecEnd)
	if len(ends) != 1 {
		t.Fatalf("tool_exec_end events = %d, want 1", len(ends))
	}
	var end events.ToolExecEnd
	if err := json.Unmarshal(ends[0].Payload, &end); err != nil {
		t.Fatalf("decode tool_exec_end: %v", err)
	}
	if !end.Truncated {
		t.Fatal("tool_exec_end not truncated; the configured cap did not reach VCS action registration")
	}
	if len(end.Stdout) != cap {
		t.Fatalf("persisted stdout = %d bytes, want %d (the configured cap)", len(end.Stdout), cap)
	}
	if end.OriginalBytes == nil || end.OriginalBytes.Stdout != outLen {
		t.Fatalf("original_bytes.stdout = %v, want %d", end.OriginalBytes, outLen)
	}
}

// TestBuildToolRegistry_FreshAndResumeParity pins Done-when 2: the resume bootstrap wires the
// same non-nil registry factory default as fresh launch.
func TestBuildToolRegistry_FreshAndResumeParity(t *testing.T) {
	fresh, err := DefaultFreshSteps(io.Discard, io.Discard).BuildToolRegistry(nil)
	if err != nil {
		t.Fatalf("fresh BuildToolRegistry error = %v", err)
	}
	resume, err := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard).BuildToolRegistry(nil)
	if err != nil {
		t.Fatalf("resume BuildToolRegistry error = %v", err)
	}
	if _, ok := fresh.(*toolRegistryFactory); !ok {
		t.Fatalf("fresh handoff type = %T, want *toolRegistryFactory", fresh)
	}
	if _, ok := resume.(*toolRegistryFactory); !ok {
		t.Fatalf("resume handoff type = %T, want *toolRegistryFactory (resume must mirror fresh)", resume)
	}
}

// --- controller-level loop + concurrency wiring ------------------------------

// toolFrag renders one streamed tool_calls fragment for a chunk delta (mirrors the
// turn-test fixture); args is the raw JSON arguments string, escaped into the chunk.
func toolFrag(index int, id, name, args string) string {
	return fmt.Sprintf(`{"index":%d,"id":%q,"type":"function","function":{"name":%q,"arguments":%q}}`, index, id, name, args)
}

// toolCallsChunk builds a streamed chunk whose delta carries the given tool_calls fragments
// and finish_reason "tool_calls".
func toolCallsChunk(frags ...string) []byte {
	return []byte(fmt.Sprintf(
		`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[%s]},"finish_reason":"tool_calls"}]}`,
		strings.Join(frags, ",")))
}

func messagesByRole(store *sessions.Store, role string) []sessions.Message {
	var out []sessions.Message
	for _, r := range store.Records() {
		if m, ok := r.(sessions.Message); ok && m.Role == role {
			out = append(out, m)
		}
	}
	return out
}

// TestTurnController_ToolCallTurnRoutesThroughLoopAndDispatcher pins Done-when 1/3 at the
// controller level: a tool-call response is handled by turn.NewToolLoop, routed through the
// bound production dispatcher (bash -> DispatchShell), its result persisted, and the loop re-issued
// to a final answer. A bare turn.New would not iterate, so no tool result would be recorded
// and the provider would be called only once.
func TestTurnController_ToolCallTurnRoutesThroughLoopAndDispatcher(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var round int32
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"echo hi"}`)))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	run := &fakeDispatchRunner{result: cmdrunner.RunResult{Stdout: []byte("hi\n")}}
	auth := &recordingAuthorizer{decision: allow()}
	ctl := newTurnController(context.Background(), &recordingSurface{}, providerCache(t, t.TempDir()),
		turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setToolDispatcher(newProductionToolDispatcher(tools.NewRegistry(), run, auth, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 65536, securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	toolMsgs := messagesByRole(store, "tool")
	if len(toolMsgs) != 1 {
		t.Fatalf("tool result messages = %d, want 1 (the loop dispatched and recorded the bash result)", len(toolMsgs))
	}
	if got := toolMsgs[0].Content.Text(); got != "hi" {
		t.Fatalf("tool result content = %q, want %q", got, "hi")
	}
	if toolMsgs[0].ToolCallID != "call_1" {
		t.Fatalf("tool result tool_call_id = %q, want call_1", toolMsgs[0].ToolCallID)
	}
	if run.callCount() != 1 || auth.callCount() != 1 {
		t.Fatalf("runner/authorizer calls = %d/%d, want 1/1", run.callCount(), auth.callCount())
	}
	asst := messagesByRole(store, "assistant")
	if len(asst) == 0 || asst[len(asst)-1].Content.Text() != "done" {
		t.Fatalf("final assistant message = %+v, want the loop to re-issue to %q", asst, "done")
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (one tool-call round, one final round)", client.callCount())
	}
}

func TestTurnController_MalformedBashCallCompletesTheRoundInBand(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var round int32
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"echo 'x"}`)))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	run := &fakeDispatchRunner{}
	auth := &recordingAuthorizer{decision: allow()}
	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()),
		turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setToolDispatcher(newProductionToolDispatcher(tools.NewRegistry(), run, auth, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 65536, securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	reloaded := reloadStore(t, store)
	asst := messagesByRole(reloaded, "assistant")
	if len(asst) == 0 || len(asst[0].ToolCalls) != 1 || asst[0].ToolCalls[0].ID != "call_1" {
		t.Fatalf("assistant messages = %+v, want the tool-call record persisted", asst)
	}
	toolMsgs := messagesByRole(reloaded, "tool")
	if len(toolMsgs) != 1 {
		t.Fatalf("tool result messages = %d, want 1 (the refusal is recorded as the tool result)", len(toolMsgs))
	}
	if got := toolMsgs[0].Content.Text(); !strings.Contains(got, "unterminated single quote") {
		t.Fatalf("tool result content = %q, want the underlying reason", got)
	}
	if toolMsgs[0].ToolCallID != "call_1" {
		t.Fatalf("tool result tool_call_id = %q, want call_1", toolMsgs[0].ToolCallID)
	}
	if asst[len(asst)-1].Content.Text() != "done" {
		t.Fatalf("final assistant message = %+v, want the loop to re-issue to %q", asst, "done")
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (one malformed tool-call round, one final round)", client.callCount())
	}
	if run.callCount() != 0 || auth.callCount() != 0 {
		t.Fatalf("runner/authorizer calls = %d/%d, want 0/0", run.callCount(), auth.callCount())
	}
	terminals := decodeStoreEvents[events.TurnTerminal](t, reloaded, events.KindTurnTerminal)
	if len(terminals) == 0 {
		t.Fatal("turn_terminal events = 0, want the round recorded")
	}
	for _, term := range terminals {
		if term.Outcome != events.TurnOutcomeCompleted {
			t.Fatalf("turn_terminal = %#v, want every outcome %q", term, events.TurnOutcomeCompleted)
		}
	}
	if committed := surface.committedList(); len(committed) != 0 {
		t.Fatalf("committed error lines = %v, want none (no turn-recovery line for an in-band refusal)", committed)
	}
}

// TestTurnController_ToolActivityWiredToSurface pins the tool-activity wiring contract at the
// controller level: turn.Deps.OnToolActivity is wired to surface.AppendToolActivity, so a
// tool-call round's about-to-run calls are surfaced inline (in assembled order) before
// dispatch. Two calls in one round must arrive as a single activity round, matching
// turn.ToolActivityLines.
func TestTurnController_ToolActivityWiredToSurface(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var round int32
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(
				toolFrag(0, "call_1", "bash", `{"command":"go build ./..."}`),
				toolFrag(1, "call_2", "bash", `{"command":"gofmt -w ."}`),
			))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	run := &fakeDispatchRunner{result: cmdrunner.RunResult{Stdout: []byte("ok\n")}}
	auth := &recordingAuthorizer{decision: allow()}
	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()),
		turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setToolDispatcher(newProductionToolDispatcher(tools.NewRegistry(), run, auth, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 65536, securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	rounds := surface.activityRounds()
	if len(rounds) != 1 {
		t.Fatalf("activity rounds = %d, want 1 (one tool-call round)", len(rounds))
	}
	want := turn.ToolActivityLines([]turn.AssembledToolCall{
		{ID: "call_1", Name: "bash", Arguments: `{"command":"go build ./..."}`},
		{ID: "call_2", Name: "bash", Arguments: `{"command":"gofmt -w ."}`},
	})
	if strings.Join(rounds[0], "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("activity lines = %v, want %v (wired to surface.AppendToolActivity, assembled order)", rounds[0], want)
	}
}

// barrierDispatcher releases only once n calls are dispatching concurrently, so a turn
// completes its tool-call round iff the loop ran at least n calls in parallel. A call that
// waits past the timeout returns an error (aborting the scheduler) instead of hanging.
type barrierDispatcher struct {
	n       int32
	count   atomic.Int32
	release chan struct{}
}

func newBarrierDispatcher(n int32) *barrierDispatcher {
	return &barrierDispatcher{n: n, release: make(chan struct{})}
}

func (b *barrierDispatcher) Plan(calls []turn.AssembledToolCall, _ int) turn.ToolPlan {
	return planThrough(calls, b.Dispatch)
}

func (b *barrierDispatcher) Dispatch(context.Context, turn.AssembledToolCall) (turn.ToolResult, error) {
	if b.count.Add(1) == b.n {
		close(b.release)
	}
	select {
	case <-b.release:
		return turn.ToolResult{Content: "ok"}, nil
	case <-time.After(2 * time.Second):
		return turn.ToolResult{}, fmt.Errorf("concurrency barrier timed out: only %d of %d calls ran concurrently", b.count.Load(), b.n)
	}
}

type cancelObservedDispatcher struct {
	entered chan struct{}
	done    chan struct{}
	once    sync.Once
}

func newCancelObservedDispatcher() *cancelObservedDispatcher {
	return &cancelObservedDispatcher{entered: make(chan struct{}), done: make(chan struct{})}
}

func (d *cancelObservedDispatcher) Plan(calls []turn.AssembledToolCall, _ int) turn.ToolPlan {
	return planThrough(calls, d.Dispatch)
}

func planThrough(calls []turn.AssembledToolCall, dispatch func(context.Context, turn.AssembledToolCall) (turn.ToolResult, error)) turn.ToolPlan {
	plan := turn.ToolPlan{Units: make([]turn.PlannedToolCall, len(calls))}
	for i, call := range calls {
		plan.Units[i] = turn.PlannedToolCall{
			Call: call,
			Run:  func(ctx context.Context) (turn.ToolResult, error) { return dispatch(ctx, call) },
		}
	}
	return plan
}

func (d *cancelObservedDispatcher) Dispatch(ctx context.Context, _ turn.AssembledToolCall) (turn.ToolResult, error) {
	d.once.Do(func() { close(d.entered) })
	<-ctx.Done()
	close(d.done)
	return turn.ToolResult{}, ctx.Err()
}

func TestTurnController_CancelDuringToolDispatchStopsTurnWithoutReportingStream(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var round int32
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"sleep"}`)))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("unreached"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	dispatcher := newCancelObservedDispatcher()
	ctl := newTurnController(context.Background(), &recordingSurface{}, providerCache(t, t.TempDir()),
		turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setToolDispatcher(dispatcher)

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	<-dispatcher.entered

	retained, inFlight := ctl.Cancel()
	if inFlight || retained != 0 {
		t.Fatalf("Cancel during tool dispatch = (%d, %v), want (0, false) so TUI does not emit stream_interrupted", retained, inFlight)
	}
	select {
	case <-dispatcher.done:
	case <-time.After(2 * time.Second):
		t.Fatal("tool dispatch did not observe turn cancellation")
	}
	turns.Wait()

	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (cancel during tool dispatch must not re-issue the turn)", client.callCount())
	}
	if got := len(messagesByRole(store, "tool")); got != 0 {
		t.Fatalf("tool result messages = %d, want 0 after cancelled dispatch", got)
	}
}

func TestTurnController_ResetsPermissionTurnCachePerSubmittedToolTurn(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var providerCalls int32
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&providerCalls, 1)%2 == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"rm hi"}`)))}, nil
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
	var prompts int
	authorizer := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(func(tui.PromptRequest) (tui.PromptDecision, error) {
		prompts++
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	ctl := newTurnController(context.Background(), &recordingSurface{}, cache,
		turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, authorizer)
	ctl.setToolDispatcher(newProductionToolDispatcher(tools.NewRegistry(), &fakeDispatchRunner{}, authorizer, home, cwd, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

	for i := 0; i < 2; i++ {
		if err := ctl.dispatch(store, time.Time{}); err != nil {
			t.Fatalf("dispatch %d error = %v", i+1, err)
		}
		turns.Wait()
	}

	if prompts != 2 {
		t.Fatalf("prompts = %d, want 2 (allow-once must be reset between submitted turns)", prompts)
	}
	if providerCalls != 4 {
		t.Fatalf("provider calls = %d, want 4 (two tool-call rounds plus two final answers)", providerCalls)
	}
}

// TestTurnController_PassesConfiguredConcurrencyToLoop pins Done-when 4: the controller
// threads Cache.AgentMaxConcurrency() into the tool-call scheduler loop. With max_concurrency 2 and
// two independent tool calls, both reach the barrier and the round completes; a regression
// that dropped or under-counted the configured value (e.g. passing 0 or 1) would leave the
// barrier unmet, abort the round, and record no tool results.
func TestTurnController_PassesConfiguredConcurrencyToLoop(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var round int32
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(
				toolFrag(0, "call_1", "bash", `{"command":"echo a"}`),
				toolFrag(1, "call_2", "bash", `{"command":"echo b"}`),
			))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	cache, err := config.NewCache(map[string]any{
		"provider": map[string]any{"openai": map[string]any{
			"base_url": "https://api.openai.com/v1", "api_key": "sk-test", "models": []string{"gpt-5.5"},
		}},
		"agent": map[string]any{"max_concurrency": 2},
	}, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	ctl := newTurnController(context.Background(), &recordingSurface{}, cache,
		turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setToolDispatcher(newBarrierDispatcher(2))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if got := len(messagesByRole(store, "tool")); got != 2 {
		t.Fatalf("tool result messages = %d, want 2 (both calls ran concurrently → configured max_concurrency reached the loop)", got)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (the concurrent round completed and the loop re-issued)", client.callCount())
	}
}

// TestTurnController_DeniedToolCallPersistsDenyEnvelope pins Done-when 1/2 on the production
// path: a denied bash tool call drives the real loop -> production dispatcher -> shared authorizer
// (deny prompt) -> permissions.DeliverDeny, and the deny envelope is persisted to disk as a
// role:"tool" message keyed to the assistant's tool_call_id — with no fake at the DeliverDeny
// seam. The typed reason is normalized (trimmed, capped) by the real BuildDenyEnvelope; an empty
// reason yields the §Reserved Values default text. The denied command never executes.
func TestTurnController_DeniedToolCallPersistsDenyEnvelope(t *testing.T) {
	cases := []struct {
		name         string
		reason       string
		wantEnvelope string
	}{
		{
			name:         "typed reason trimmed",
			reason:       "  too risky for this repo  ",
			wantEnvelope: `{"denied_by":"user","reason":"too risky for this repo"}`,
		},
		{
			name:         "empty reason defaults",
			reason:       "",
			wantEnvelope: `{"denied_by":"user","reason":"user denied this tool call without a reason"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var turns sync.WaitGroup
			defer swapGoTurn(waitableGoTurn(&turns))()

			var round int32
			client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
				if atomic.AddInt32(&round, 1) == 1 {
					return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"rm -rf /"}`)))}, nil
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

			// The prompt fake mirrors prompt_deny.go's finalizeDeny: it builds the envelope with the
			// real permissions.BuildDenyEnvelope from the user's raw reason text, so normalization runs
			// in the production builder rather than the test, and DeliverDeny is never faked.
			authorizer := newProductionAuthorizer(app, cache, permissions.NewTurnCache(),
				newPromptGateBuilder(func(tui.PromptRequest) (tui.PromptDecision, error) {
					return tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope(tc.reason)}, nil
				}), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

			run := &fakeDispatchRunner{}
			ctl := newTurnController(context.Background(), &recordingSurface{}, cache,
				turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, authorizer)
			ctl.setToolDispatcher(newProductionToolDispatcher(tools.NewRegistry(), run, authorizer, home, cwd, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

			if err := ctl.dispatch(store, time.Time{}); err != nil {
				t.Fatalf("dispatch error = %v", err)
			}
			turns.Wait()

			if run.callCount() != 0 {
				t.Fatalf("runner Exec calls = %d, want 0 (a denied command must not execute)", run.callCount())
			}

			// Disk readback: flush, reload from the session file, and inspect the reloaded records so
			// the assertion proves durable persistence, not just an in-memory append.
			if _, _, err := store.Flush(context.Background()); err != nil {
				t.Fatalf("flush session: %v", err)
			}
			data, err := os.ReadFile(store.Path())
			if err != nil {
				t.Fatalf("read persisted session: %v", err)
			}
			reloaded, err := sessions.Unmarshal(data)
			if err != nil {
				t.Fatalf("reload persisted session: %v", err)
			}
			reloadedStore := sessions.New(store.Path(), reloaded)

			toolMsgs := messagesByRole(reloadedStore, "tool")
			if len(toolMsgs) != 1 {
				t.Fatalf("persisted tool messages = %d, want 1 (the denied call's deny envelope)", len(toolMsgs))
			}
			if got := toolMsgs[0].Content.Text(); got != tc.wantEnvelope {
				t.Fatalf("persisted deny envelope = %q, want %q", got, tc.wantEnvelope)
			}

			// The deny envelope must be keyed to the assistant tool call it answers. The tool-call
			// assistant message is appended before the deny result, so it is the first assistant record.
			asst := messagesByRole(reloadedStore, "assistant")
			if len(asst) == 0 || len(asst[0].ToolCalls) != 1 {
				t.Fatalf("assistant tool-call message = %+v, want one carrying a single tool call", asst)
			}
			if toolMsgs[0].ToolCallID != asst[0].ToolCalls[0].ID {
				t.Fatalf("deny envelope tool_call_id = %q, want it keyed to the assistant tool call %q",
					toolMsgs[0].ToolCallID, asst[0].ToolCalls[0].ID)
			}
		})
	}
}

// TestTurnController_TextToolCallDeniedPersistsDenyEnvelope pins text tool-call denial on the
// production path: a tool call the model emits as assistant TEXT (a bare JSON object,
// finishing as "stop" rather than "tool_calls") is parsed by turn.go and routed through the
// SAME real loop -> production dispatcher -> shared authorizer (deny prompt) ->
// permissions.DeliverDeny as a native call. A denied parsed call therefore obeys the current
// mode's auto/ask rules with no extra gate and persists the deny envelope to disk as a
// role:"tool" message keyed to the assistant's tool_call_id — read back from the session file,
// not just an in-memory assertion — and the denied command never executes, exactly as a denied
// structured call does (compare TestTurnController_DeniedToolCallPersistsDenyEnvelope).
func TestTurnController_TextToolCallDeniedPersistsDenyEnvelope(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	const textCall = `{"name":"bash","arguments":{"command":"rm -rf /"}}`
	var round int32
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			// The tool call arrives as assistant content with a non-tool_calls finish reason —
			// the exact shape a small/open model produces (docs/ibm-model-issues.md).
			return provider.Response{Stream: newStream(contentChunk(textCall), finishChunk("stop"))}, nil
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

	// The deny is built by the real permissions.BuildDenyEnvelope in the prompt fake, so DeliverDeny
	// is never faked — the parsed text call traverses the production deny path unchanged.
	authorizer := newProductionAuthorizer(app, cache, permissions.NewTurnCache(),
		newPromptGateBuilder(func(tui.PromptRequest) (tui.PromptDecision, error) {
			return tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope("text-form call, still denied")}, nil
		}), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	run := &fakeDispatchRunner{}
	ctl := newTurnController(context.Background(), &recordingSurface{}, cache,
		turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, authorizer)
	ctl.setToolDispatcher(newProductionToolDispatcher(tools.NewRegistry(), run, authorizer, home, cwd, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if run.callCount() != 0 {
		t.Fatalf("runner Exec calls = %d, want 0 (a denied command must not execute)", run.callCount())
	}

	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("flush session: %v", err)
	}
	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("read persisted session: %v", err)
	}
	reloaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("reload persisted session: %v", err)
	}
	reloadedStore := sessions.New(store.Path(), reloaded)

	toolMsgs := messagesByRole(reloadedStore, "tool")
	if len(toolMsgs) != 1 {
		t.Fatalf("persisted tool messages = %d, want 1 (the denied text call's deny envelope)", len(toolMsgs))
	}
	const wantEnvelope = `{"denied_by":"user","reason":"text-form call, still denied"}`
	if got := toolMsgs[0].Content.Text(); got != wantEnvelope {
		t.Fatalf("persisted deny envelope = %q, want %q", got, wantEnvelope)
	}

	// The raw JSON must not be committed as assistant text; the assistant record is a tool-call
	// record (empty text + one tool call) keyed to the deny result.
	asst := messagesByRole(reloadedStore, "assistant")
	if len(asst) == 0 || len(asst[0].ToolCalls) != 1 {
		t.Fatalf("assistant tool-call message = %+v, want one carrying a single tool call", asst)
	}
	if text := asst[0].Content.Text(); strings.Contains(text, `"name"`) || strings.Contains(text, `"arguments"`) {
		t.Fatalf("assistant message committed the raw tool-call JSON blob: %q", text)
	}
	if toolMsgs[0].ToolCallID != asst[0].ToolCalls[0].ID {
		t.Fatalf("deny envelope tool_call_id = %q, want it keyed to the assistant tool call %q",
			toolMsgs[0].ToolCallID, asst[0].ToolCalls[0].ID)
	}
}

// TestTurnController_DeniedToolCallSkipsTitleGeneration pins the post-denial halt: a permission
// denial returns nil from the turn loop (an in-band refusal, not a failure) but halts the
// attempt with no final assistant answer, so the interactive first-turn title hook must NOT
// fire a follow-up provider request. turnController.run gates onTurnComplete on
// !loop.Denied(); with the title hook wired exactly as StartTUI wires it, a denied first turn
// calls the provider exactly once — the turn — never a second title request. Removing the
// run guard makes onTurnComplete fire, firstTurnTitleInputs accepts the single-user-message
// turn even with no assistant answer, and GenerateTitle issues that extra request — caught
// here as both an unexpected title request and a call count of two.
func TestTurnController_DeniedToolCallSkipsTitleGeneration(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if isTitleRequest(req) {
			t.Errorf("unexpected title request after a denial")
			return titleCompletion("should not be generated"), nil
		}
		// Round 1 is a tool call the prompt gate denies; the denial stops the turn, so no
		// second streamed round is ever issued.
		return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"rm -rf /"}`)))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	// A single user message makes this a titleable first turn, so without the run guard the
	// title hook would issue a provider request — exactly the regression being pinned.
	store.Append(sessions.Message{Role: "user", Content: sessions.TextContent("run the command"), Timestamp: testStart})
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := providerCache(t, cwd)

	authorizer := newProductionAuthorizer(app, cache, permissions.NewTurnCache(),
		newPromptGateBuilder(func(tui.PromptRequest) (tui.PromptDecision, error) {
			return tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope("out of scope")}, nil
		}), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	run := &fakeDispatchRunner{}
	ctl := newTurnController(context.Background(), &recordingSurface{}, cache,
		turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, authorizer)
	ctl.setToolDispatcher(newProductionToolDispatcher(tools.NewRegistry(), run, authorizer, home, cwd, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))
	// Wire the interactive first-turn title hook exactly as StartTUI does.
	ctl.setTurnCompleteHook(newTitleOnComplete(app, func(providerID, modelID string) []string {
		return cache.SelectableCatalog().SupportedEffort(providerID, modelID)
	}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if got := client.callCount(); got != 1 {
		t.Fatalf("provider calls = %d, want 1 (a denial must not trigger a follow-up title request)", got)
	}
	if run.callCount() != 0 {
		t.Fatalf("runner Exec calls = %d, want 0 (a denied command must not execute)", run.callCount())
	}
}

func planHarness(t *testing.T) (readToolsHarness, string, string) {
	t.Helper()
	project := readToolsProject(t)
	home := t.TempDir()
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("CANARY\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(project, "escape")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	return newReadToolsHarness(t, project, home, mode.Build, emptyCache(t, project)), project, outside
}

func sixReadCalls() []turn.AssembledToolCall {
	return []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "main.go"}),
		structuredCall("c2", filetools.GlobToolName, map[string]any{"pattern": "**/*.go"}),
		structuredCall("c3", filetools.GrepToolName, map[string]any{"pattern": "func"}),
		structuredCall("c4", filetools.ListToolName, map[string]any{"path": "."}),
		structuredCall("c5", filetools.TreeToolName, map[string]any{"path": "."}),
		structuredCall("c6", filetools.FileCountToolName, map[string]any{"path": "."}),
	}
}

// shape spells one character per call: 'e' for an overlappable prepared read, 'd' for a valid
// delegate scheduled on its own prepared targets, 'x' for an excluded serial barrier. The expected
// dependency graph follows from the shape alone, so a partition is asserted whole rather than unit
// by unit.
func assertPartitionedPlan(t *testing.T, plan turn.ToolPlan, calls []turn.AssembledToolCall, shape string) {
	t.Helper()
	assertPlanAnswersCalls(t, plan, calls)
	if len(shape) != len(plan.Units) {
		t.Fatalf("shape %q covers %d units, want %d", shape, len(shape), len(plan.Units))
	}
	var segment []string
	var delegated []string
	barrier := ""
	kind := byte(0)
	fence := func(extra []string) []string {
		var deps []string
		if barrier != "" {
			deps = append(deps, barrier)
		}
		return append(deps, extra...)
	}
	for i, unit := range plan.Units {
		if shape[i] != kind {
			switch shape[i] {
			case 'e':
				segment = nil
			case 'd':
				delegated = nil
			}
			kind = shape[i]
		}
		switch shape[i] {
		case 'e':
			if len(unit.Targets) != 0 {
				t.Fatalf("unit %d (%s) targets = %v, want none on an overlappable read", i, calls[i].Name, unit.Targets)
			}
			if !unit.ContinueOnError {
				t.Fatalf("unit %d (%s) ContinueOnError = false, want true so a concurrent sibling still drains", i, calls[i].Name)
			}
			// An overlappable read carries a pre-run only when it belongs to an authorization
			// group, and that guard waits for the group's approval, never for a sibling read's
			// failure — only the 'x' barrier and 'd' delegate below carry the eligible-failure guard.
			wantDeps := fence(delegated)
			if !slices.Equal(unit.Deps, wantDeps) {
				t.Fatalf("unit %d (%s) deps = %v, want %v (an eligible segment waits for the barrier and delegates before it)", i, calls[i].Name, unit.Deps, wantDeps)
			}
			segment = append(segment, calls[i].ID)
		case 'd':
			if slices.Contains(unit.Targets, productionToolDispatchTarget) {
				t.Fatalf("unit %d (%s) targets = %v, want the child's own targets, not the synthetic one that would serialize disjoint children", i, calls[i].Name, unit.Targets)
			}
			if len(unit.Targets) == 0 {
				t.Fatalf("unit %d (%s) carries no targets, want the child's prepared write set", i, calls[i].Name)
			}
			if unit.ContinueOnError {
				t.Fatalf("unit %d (%s) ContinueOnError = true, want false so a failed child stops later calls", i, calls[i].Name)
			}
			if unit.PreRun == nil {
				t.Fatalf("unit %d (%s) has no pre-run guard, want the eligible-failure guard before a child starts", i, calls[i].Name)
			}
			wantDeps := fence(segment)
			if !slices.Equal(unit.Deps, wantDeps) {
				t.Fatalf("unit %d (%s) deps = %v, want %v (a delegate waits for the read segment and barrier before it)", i, calls[i].Name, unit.Deps, wantDeps)
			}
			delegated = append(delegated, calls[i].ID)
		case 'x':
			if len(unit.Targets) != 1 || unit.Targets[0] != productionToolDispatchTarget {
				t.Fatalf("unit %d (%s) targets = %v, want the synthetic serialization target on an excluded barrier", i, calls[i].Name, unit.Targets)
			}
			if unit.ContinueOnError {
				t.Fatalf("unit %d (%s) ContinueOnError = true, want false so an excluded failure stops later calls", i, calls[i].Name)
			}
			if unit.PreRun == nil {
				t.Fatalf("unit %d (%s) has no pre-run guard, want the eligible-failure guard on an excluded barrier", i, calls[i].Name)
			}
			wantDeps := append(slices.Clone(segment), delegated...)
			if !slices.Equal(unit.Deps, wantDeps) {
				t.Fatalf("unit %d (%s) deps = %v, want %v (a barrier waits for the eligible segment and delegates before it)", i, calls[i].Name, unit.Deps, wantDeps)
			}
			barrier, segment, delegated, kind = calls[i].ID, nil, nil, 'x'
		default:
			t.Fatalf("shape %q has unknown character %q", shape, shape[i])
		}
	}
}

func assertSerialTargets(t *testing.T, plan turn.ToolPlan, calls []turn.AssembledToolCall) {
	t.Helper()
	assertPartitionedPlan(t, plan, calls, strings.Repeat("x", len(calls)))
}

func assertOverlappableUnits(t *testing.T, plan turn.ToolPlan, calls []turn.AssembledToolCall) {
	t.Helper()
	assertPartitionedPlan(t, plan, calls, strings.Repeat("e", len(calls)))
}

func assertPlanAnswersCalls(t *testing.T, plan turn.ToolPlan, calls []turn.AssembledToolCall) {
	t.Helper()
	if len(plan.Units) != len(calls) {
		t.Fatalf("plan units = %d, want one per call (%d)", len(plan.Units), len(calls))
	}
	for i, unit := range plan.Units {
		if unit.Call.ID != calls[i].ID || unit.Call.Name != calls[i].Name {
			t.Fatalf("unit %d answers %q/%q, want %q/%q", i, unit.Call.ID, unit.Call.Name, calls[i].ID, calls[i].Name)
		}
		if unit.Run == nil {
			t.Fatalf("unit %d has no run", i)
		}
	}
}

func TestProductionDispatcher_PlanClassifiesOnlyProjectConfinedReads(t *testing.T) {
	h, _, outside := planHarness(t)
	outsideFile := filepath.Join(outside, "secret.txt")

	t.Run("six in-project reads", func(t *testing.T) {
		calls := sixReadCalls()
		assertOverlappableUnits(t, h.dispatcher.Plan(calls, 3), calls)
	})

	negatives := []struct {
		name  string
		calls []turn.AssembledToolCall
		shape string
	}{
		{"read_image is not an allowlisted read", []turn.AssembledToolCall{
			structuredCall("c1", filetools.ReadImageToolName, map[string]any{"path": "logo.png"})}, "x"},
		{"shell", []turn.AssembledToolCall{bashCall("c1", "cat main.go")}, "x"},
		{"near-miss name", []turn.AssembledToolCall{
			structuredCall("c1", "read_file", map[string]any{"path": "main.go"})}, "x"},
		{"name differing only in case", []turn.AssembledToolCall{
			structuredCall("c1", "Read", map[string]any{"path": "main.go"})}, "x"},
		{"prose naming a read", []turn.AssembledToolCall{
			structuredCall("c1", "read the file main.go", map[string]any{"path": "main.go"})}, "x"},
		{"vcs action", []turn.AssembledToolCall{
			structuredCall("c1", "vcs_status", map[string]any{})}, "x"},
		{"mutating edit", []turn.AssembledToolCall{
			structuredCall("c1", filetools.EditToolName, map[string]any{"path": "main.go", "old_text": "a", "new_text": "b"})}, "x"},
		{"mutating delete", []turn.AssembledToolCall{
			structuredCall("c1", filetools.DeleteToolName, map[string]any{"path": "main.go"})}, "x"},
		{"unknown argument", []turn.AssembledToolCall{
			structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "main.go", "depth": 2})}, "x"},
		{"wrong argument type", []turn.AssembledToolCall{
			structuredCall("c1", filetools.GrepToolName, map[string]any{"pattern": 5})}, "x"},
		{"malformed arguments", []turn.AssembledToolCall{
			{ID: "c1", Name: filetools.ReadToolName, Arguments: `{"path":`}}, "x"},
		{"explicit external target", []turn.AssembledToolCall{
			structuredCall("c1", filetools.ReadToolName, map[string]any{"path": outsideFile})}, "x"},
		{"parent-directory escape", []turn.AssembledToolCall{
			structuredCall("c1", filetools.ListToolName, map[string]any{"path": filepath.Join("..", filepath.Base(outside))})}, "x"},
		{"symlink escape", []turn.AssembledToolCall{
			structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "escape/secret.txt"})}, "x"},
		{"one shell sibling after a clean read batch", append(sixReadCalls(), bashCall("c7", "rm -rf /")), "eeeeeex"},
		{"one external read sibling after a clean read batch", append(sixReadCalls(),
			structuredCall("c7", filetools.ReadToolName, map[string]any{"path": outsideFile})), "eeeeeex"},
		{"one shell sibling before a clean read batch", append([]turn.AssembledToolCall{bashCall("c0", "rm -rf /")}, sixReadCalls()...), "xeeeeee"},
		{"one external read sibling amid a clean read batch", slices.Insert(sixReadCalls(), 3,
			structuredCall("c7", filetools.ReadToolName, map[string]any{"path": outsideFile})), "eeexeee"},
	}
	for _, tc := range negatives {
		t.Run(tc.name, func(t *testing.T) {
			assertPartitionedPlan(t, h.dispatcher.Plan(tc.calls, 3), tc.calls, tc.shape)
		})
	}
}

// Timeout lets serialized fixtures finish; hold makes durable intervals measurable.
type overlapProbe struct {
	mu      sync.Mutex
	live    int
	peak    int
	want    int
	closed  bool
	release chan struct{}
	timeout time.Duration
	hold    time.Duration
}

func newOverlapProbe(want int, timeout time.Duration) *overlapProbe {
	return newHoldingProbe(want, timeout, 0)
}

func newHoldingProbe(want int, timeout, hold time.Duration) *overlapProbe {
	return &overlapProbe{want: want, release: make(chan struct{}), timeout: timeout, hold: hold}
}

func (p *overlapProbe) enter() {
	p.mu.Lock()
	p.live++
	if p.live > p.peak {
		p.peak = p.live
	}
	reached := p.live >= p.want && !p.closed
	if reached {
		p.closed = true
	}
	p.mu.Unlock()
	if reached {
		close(p.release)
	}
	select {
	case <-p.release:
	case <-time.After(p.timeout):
	}
	if p.hold > 0 {
		time.Sleep(p.hold)
	}
}

func (p *overlapProbe) exit() {
	p.mu.Lock()
	p.live--
	p.mu.Unlock()
}

func (p *overlapProbe) peakLive() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peak
}

// overlapProbeUnit runs one planned unit the way ToolLoop.onToolCalls does — the PreRun guard
// before Run, and a continuing unit's error withheld from the scheduler — so a scheduled plan is
// exercised under the contract production actually runs it under.
type overlapProbeUnit struct {
	unit  turn.PlannedToolCall
	probe *overlapProbe
	run   *planRun
	// hold keeps the unit live after its work returns, so a lifetime the scheduler allowed to
	// overlap is long enough to observe overlapping rather than merely being permitted to.
	hold time.Duration
}

func (u *overlapProbeUnit) ID() string        { return u.unit.Call.ID }
func (u *overlapProbeUnit) Deps() []string    { return u.unit.Deps }
func (u *overlapProbeUnit) Targets() []string { return u.unit.Targets }

func (u *overlapProbeUnit) Run(ctx context.Context) error {
	if u.unit.PreRun != nil {
		if err := u.unit.PreRun(ctx); err != nil {
			return err
		}
	}
	if u.probe != nil {
		u.probe.enter()
		defer u.probe.exit()
	}
	u.run.executed(u.unit.Call.ID)
	started := time.Now()
	_, err := u.unit.Run(ctx)
	time.Sleep(u.hold)
	u.run.span(u.unit.Call.ID, started, time.Now())
	if err != nil && u.unit.ContinueOnError {
		u.run.failed(err)
		return nil
	}
	return err
}

type planRun struct {
	mu    sync.Mutex
	ran   []string
	errs  []error
	spans map[string][2]time.Time
}

func (r *planRun) executed(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ran = append(r.ran, id)
}

func (r *planRun) span(id string, started, ended time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.spans == nil {
		r.spans = map[string][2]time.Time{}
	}
	r.spans[id] = [2]time.Time{started, ended}
}

func (r *planRun) overlapped(a, b string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	x, ranA := r.spans[a]
	y, ranB := r.spans[b]
	return ranA && ranB && x[0].Before(y[1]) && y[0].Before(x[1])
}

func (r *planRun) failed(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, err)
}

func (r *planRun) ids() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.ran)
}

func schedulePlan(plan turn.ToolPlan, maxConcurrency int, probe *overlapProbe) (*planRun, error) {
	return schedulePlanHeld(plan, maxConcurrency, probe, 0)
}

// schedulePlanHeld reports which units actually overlapped, read out of the scheduled run rather
// than out of the plan's shape.
func schedulePlanHeld(plan turn.ToolPlan, maxConcurrency int, probe *overlapProbe, hold time.Duration) (*planRun, error) {
	run := &planRun{}
	work := make([]agent.WorkUnit, len(plan.Units))
	for i := range plan.Units {
		work[i] = &overlapProbeUnit{unit: plan.Units[i], probe: probe, run: run, hold: hold}
	}
	err := agent.Schedule(context.Background(), work, maxConcurrency)
	if err == nil && len(run.errs) > 0 {
		err = run.errs[0]
	}
	return run, err
}

func scheduleWithProbe(t *testing.T, plan turn.ToolPlan, maxConcurrency, want int, timeout time.Duration) *overlapProbe {
	t.Helper()
	probe := newOverlapProbe(want, timeout)
	if _, err := schedulePlan(plan, maxConcurrency, probe); err != nil {
		t.Fatalf("Schedule: %v", err)
	}
	return probe
}

func TestProductionDispatcher_EligibleBatchOverlapsUpToTheConfiguredCap(t *testing.T) {
	for _, cap := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("cap %d", cap), func(t *testing.T) {
			h, _, _ := planHarness(t)
			calls := sixReadCalls()
			plan := h.dispatcher.Plan(calls, cap)
			assertOverlappableUnits(t, plan, calls)
			timeout := 2 * time.Second
			if cap == 1 {
				timeout = 20 * time.Millisecond
			}
			probe := scheduleWithProbe(t, plan, cap, cap, timeout)
			if got := probe.peakLive(); got != cap {
				t.Fatalf("peak concurrent production reads = %d, want exactly the configured %d", got, cap)
			}
			for _, start := range decodeStoreEvents[events.StructuredReadStart](t, h.store, events.KindStructuredReadStart) {
				if int(start.ConfiguredConcurrency) != cap {
					t.Fatalf("structured_read_start configured_concurrency = %d, want the configured %d", start.ConfiguredConcurrency, cap)
				}
			}
		})
	}
}

func TestProductionDispatcher_WhollyExcludedBatchStaysSerialWithoutEvidence(t *testing.T) {
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("CANARY\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	excluded := []turn.AssembledToolCall{
		bashCall("c1", "echo hi"),
		structuredCall("c2", filetools.ReadImageToolName, map[string]any{"path": "logo.png"}),
		structuredCall("c3", "read_file", map[string]any{"path": "main.go"}),
		{ID: "c4", Name: filetools.ReadToolName, Arguments: `{"path":`},
		structuredCall("c5", filetools.ReadToolName, map[string]any{"path": filepath.Join(outside, "secret.txt")}),
	}

	h, _, _ := planHarness(t)
	plan := h.dispatcher.Plan(excluded, 6)
	assertSerialTargets(t, plan, excluded)
	probe := scheduleWithProbe(t, plan, 6, 2, 20*time.Millisecond)
	if got := probe.peakLive(); got != 1 {
		t.Fatalf("peak concurrency of a wholly excluded batch = %d, want 1", got)
	}
	if n := len(kindEvents(t, h.store, events.KindStructuredReadStart)); n != 0 {
		t.Fatalf("structured_read_start events = %d, want 0 (a serialized batch records no read evidence)", n)
	}
	if n := len(kindEvents(t, h.store, events.KindStructuredReadEnd)); n != 0 {
		t.Fatalf("structured_read_end events = %d, want 0", n)
	}
}

func TestProductionDispatcher_MixedBatchOverlapsOnlyItsEligibleSegments(t *testing.T) {
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("CANARY\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cases := []struct {
		name    string
		sibling turn.AssembledToolCall
	}{
		{"shell", bashCall("c7", "echo hi")},
		{"read_image", structuredCall("c7", filetools.ReadImageToolName, map[string]any{"path": "logo.png"})},
		{"unknown tool", structuredCall("c7", "read_file", map[string]any{"path": "main.go"})},
		{"malformed arguments", turn.AssembledToolCall{ID: "c7", Name: filetools.ReadToolName, Arguments: `{"path":`}},
		{"external read", structuredCall("c7", filetools.ReadToolName, map[string]any{"path": filepath.Join(outside, "secret.txt")})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := planHarness(t)
			calls := append(sixReadCalls(), tc.sibling)
			plan := h.dispatcher.Plan(calls, 6)
			assertPartitionedPlan(t, plan, calls, "eeeeeex")
			probe := scheduleWithProbe(t, plan, 6, 6, 2*time.Second)
			if got := probe.peakLive(); got != 6 {
				t.Fatalf("peak concurrency beside a %s sibling = %d, want the six eligible reads to overlap", tc.name, got)
			}
			starts := decodeStoreEvents[events.StructuredReadStart](t, reloadStore(t, h.store), events.KindStructuredReadStart)
			if len(starts) != 6 {
				t.Fatalf("structured_read_start events = %d, want 6 (only the %s sibling is excluded)", len(starts), tc.name)
			}
		})
	}
}

func TestProductionDispatcher_PlanRecordsOneRefusalPerRejectedCall(t *testing.T) {
	_, _, outside := planHarness(t)
	cases := []struct {
		name       string
		sibling    turn.AssembledToolCall
		wantTool   string
		wantReason string
	}{
		{"not allowlisted", structuredCall("c7", filetools.ReadImageToolName, map[string]any{"path": "logo.png"}),
			filetools.ReadImageToolName, structuredReadRefusalNotAllowlisted},
		{"unknown tool", structuredCall("c7", "read_file", map[string]any{"path": "main.go"}),
			"read_file", structuredReadRefusalNotAllowlisted},
		{"shell", bashCall("c7", "echo hi"), bashToolName, structuredReadRefusalNotAllowlisted},
		{"malformed arguments", turn.AssembledToolCall{ID: "c7", Name: filetools.ReadToolName, Arguments: `{"path":`},
			filetools.ReadToolName, structuredReadRefusalArgsInvalid},
		{"unknown argument", structuredCall("c7", filetools.ReadToolName, map[string]any{"path": "main.go", "depth": 2}),
			filetools.ReadToolName, structuredReadRefusalArgsInvalid},
		{"wrong argument type", structuredCall("c7", filetools.GrepToolName, map[string]any{"pattern": 5}),
			filetools.GrepToolName, structuredReadRefusalArgsInvalid},
		{"symlink escape", structuredCall("c7", filetools.ReadToolName, map[string]any{"path": "escape/secret.txt"}),
			filetools.ReadToolName, structuredReadRefusalPrepareFailed},
		{"explicit external target", structuredCall("c7", filetools.ReadToolName, map[string]any{"path": filepath.Join(outside, "secret.txt")}),
			filetools.ReadToolName, structuredReadRefusalOutOfProject},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := planHarness(t)
			calls := append(sixReadCalls(), tc.sibling)
			assertPartitionedPlan(t, h.dispatcher.Plan(calls, 3), calls, "eeeeeex")

			refusals := decodeStoreEvents[events.StructuredReadRefused](t, reloadStore(t, h.store), events.KindStructuredReadRefused)
			if len(refusals) != 1 {
				t.Fatalf("structured_read_refused events = %d, want exactly 1 (only the %s call is refused)", len(refusals), tc.name)
			}
			if refusals[0].ToolName != tc.wantTool {
				t.Errorf("tool_name = %q, want the refused call's exact name %q", refusals[0].ToolName, tc.wantTool)
			}
			if refusals[0].Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", refusals[0].Reason, tc.wantReason)
			}
			if int(refusals[0].BatchSize) != len(calls) {
				t.Errorf("batch_size = %d, want the assembled batch size %d", refusals[0].BatchSize, len(calls))
			}
			if n := len(kindEvents(t, h.store, events.KindStructuredReadStart)); n != 0 {
				t.Fatalf("structured_read_start events = %d, want 0 (planning admits nothing on its own)", n)
			}
		})
	}
}

func TestProductionDispatcher_PlanRecordsEveryRefusedCallInABatch(t *testing.T) {
	h, _, outside := planHarness(t)
	calls := []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadImageToolName, map[string]any{"path": "logo.png"}),
		structuredCall("c2", filetools.ReadToolName, map[string]any{"path": "main.go"}),
		structuredCall("c3", filetools.ReadToolName, map[string]any{"path": filepath.Join(outside, "secret.txt")}),
	}
	assertPartitionedPlan(t, h.dispatcher.Plan(calls, 3), calls, "xex")

	refusals := decodeStoreEvents[events.StructuredReadRefused](t, reloadStore(t, h.store), events.KindStructuredReadRefused)
	if len(refusals) != 2 {
		t.Fatalf("structured_read_refused events = %d, want 2 (classification must not stop at the first rejection)", len(refusals))
	}
	want := []events.StructuredReadRefused{
		{ToolName: filetools.ReadImageToolName, Reason: structuredReadRefusalNotAllowlisted, BatchSize: 3},
		{ToolName: filetools.ReadToolName, Reason: structuredReadRefusalOutOfProject, BatchSize: 3},
	}
	if !reflect.DeepEqual(refusals, want) {
		t.Fatalf("refusals = %+v, want %+v", refusals, want)
	}
}

func TestProductionDispatcher_EligibleBatchRecordsNoRefusal(t *testing.T) {
	h, _, _ := planHarness(t)
	calls := sixReadCalls()
	plan := h.dispatcher.Plan(calls, 3)
	assertOverlappableUnits(t, plan, calls)
	for _, unit := range plan.Units {
		if _, err := unit.Run(context.Background()); err != nil {
			t.Fatalf("prepared run error = %v, want nil", err)
		}
	}

	reloaded := reloadStore(t, h.store)
	if n := len(kindEvents(t, reloaded, events.KindStructuredReadRefused)); n != 0 {
		t.Fatalf("structured_read_refused events = %d, want 0 for an all-eligible batch", n)
	}
	starts := kindEvents(t, reloaded, events.KindStructuredReadStart)
	ends := kindEvents(t, reloaded, events.KindStructuredReadEnd)
	if len(starts) != len(calls) || len(ends) != len(calls) {
		t.Fatalf("durable structured_read events = %d start/%d end, want %d/%d", len(starts), len(ends), len(calls), len(calls))
	}
}

func TestProductionDispatcher_PreparedRunEmitsDurablePairedEvidence(t *testing.T) {
	h, project, _ := planHarness(t)
	calls := []turn.AssembledToolCall{structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "main.go"})}
	plan := h.dispatcher.Plan(calls, 2)
	assertOverlappableUnits(t, plan, calls)
	res, err := plan.Units[0].Run(context.Background())
	if err != nil {
		t.Fatalf("prepared run error = %v, want nil", err)
	}
	if !strings.HasPrefix(res.Content, "package main") {
		t.Fatalf("prepared read content = %q, want the file's verbatim content", res.Content)
	}

	reloaded := reloadStore(t, h.store)
	starts := decodeStoreEvents[events.StructuredReadStart](t, reloaded, events.KindStructuredReadStart)
	ends := decodeStoreEvents[events.StructuredReadEnd](t, reloaded, events.KindStructuredReadEnd)
	if len(starts) != 1 || len(ends) != 1 {
		t.Fatalf("durable structured_read events = %d start/%d end, want 1/1", len(starts), len(ends))
	}
	if !ids.IsValidV7(starts[0].InvocationID) || starts[0].InvocationID != ends[0].InvocationID {
		t.Fatalf("invocation ids = %q/%q, want one shared UUIDv7", starts[0].InvocationID, ends[0].InvocationID)
	}
	if starts[0].ToolName != filetools.ReadToolName || ends[0].ToolName != filetools.ReadToolName {
		t.Fatalf("tool names = %q/%q, want %q on both records", starts[0].ToolName, ends[0].ToolName, filetools.ReadToolName)
	}
	if starts[0].PathScope != project {
		t.Fatalf("path_scope = %q, want the scope preparation resolved (%q)", starts[0].PathScope, project)
	}
	if starts[0].ConfiguredConcurrency != 2 {
		t.Fatalf("configured_concurrency = %d, want the planned 2", starts[0].ConfiguredConcurrency)
	}
	if ends[0].Outcome != structuredReadOutcomeSuccess || ends[0].DurationMs < 0 {
		t.Fatalf("end record = %+v, want a success with a non-negative duration", ends[0])
	}
	kinds := eventKinds(reloaded.Records())
	if si, ei := slices.Index(kinds, events.KindStructuredReadStart), slices.Index(kinds, events.KindStructuredReadEnd); si > ei {
		t.Fatalf("record order = %v, want the start appended before its end", kinds)
	}
}

// Authorize by resolved target because sibling reads share a path scope.
type denyingAuthorizer struct {
	denyTarget string
	err        error
	calls      int32
}

func (a *denyingAuthorizer) Authorize(_ context.Context, _ permissions.MatchRequest, _ dispatch.PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error) {
	atomic.AddInt32(&a.calls, 1)
	if modeCtx.TargetPath != a.denyTarget {
		return allow(), nil
	}
	if a.err != nil {
		return permissions.Decision{}, a.err
	}
	return deny(`{"denied_by":"user","reason":"blocked"}`), nil
}

func TestProductionDispatcher_PreparedRunOutcomes(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		authErr error
		want    string
	}{
		{"success", "main.go", nil, structuredReadOutcomeSuccess},
		{"tool failure", "missing.go", nil, structuredReadOutcomeToolFailure},
		{"denial", "main.go", nil, structuredReadOutcomeDenied},
		{"cancellation", "main.go", context.Canceled, structuredReadOutcomeCancelled},
		{"internal failure", "main.go", errors.New("prompt surface failed"), structuredReadOutcomeInternalFailure},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project := readToolsProject(t)
			if err := os.WriteFile(filepath.Join(project, "sibling.go"), []byte("package sibling\n"), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			home := t.TempDir()
			reg, err := (&toolRegistryFactory{active: nil}).realize(emptyCache(t, project), func() *sessions.Store { return nil }, home, project, securitystate.Policy{})
			if err != nil {
				t.Fatalf("realize production registry: %v", err)
			}
			store := mkStore(t)
			auth := &denyingAuthorizer{err: tc.authErr}
			if tc.want != structuredReadOutcomeSuccess && tc.want != structuredReadOutcomeToolFailure {
				auth.denyTarget = filepath.Join(project, tc.path)
			}
			d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})

			calls := []turn.AssembledToolCall{
				structuredCall("c1", filetools.ReadToolName, map[string]any{"path": tc.path}),
				structuredCall("c2", filetools.ReadToolName, map[string]any{"path": "sibling.go"}),
			}
			plan := d.Plan(calls, 2)
			assertOverlappableUnits(t, plan, calls)
			subject, serr := plan.Units[0].Run(context.Background())
			sibling, sierr := plan.Units[1].Run(context.Background())

			switch tc.want {
			case structuredReadOutcomeCancelled, structuredReadOutcomeInternalFailure:
				if serr == nil {
					t.Fatal("prepared run error = nil, want the internal failure returned to abort the turn")
				}
			default:
				if serr != nil {
					t.Fatalf("prepared run error = %v, want nil (this outcome surfaces in band)", serr)
				}
			}
			if tc.want == structuredReadOutcomeDenied && !subject.Denied {
				t.Fatalf("subject result = %+v, want the deny envelope marked denied", subject)
			}
			if sierr != nil || !strings.HasPrefix(sibling.Content, "package sibling") {
				t.Fatalf("sibling result = (%+v, %v), want its own successful read", sibling, sierr)
			}

			starts := decodeStoreEvents[events.StructuredReadStart](t, reloadStore(t, store), events.KindStructuredReadStart)
			ends := decodeStoreEvents[events.StructuredReadEnd](t, reloadStore(t, store), events.KindStructuredReadEnd)
			if len(starts) != 2 || len(ends) != 2 {
				t.Fatalf("structured_read events = %d start/%d end, want 2/2 (no dangling start)", len(starts), len(ends))
			}
			if ends[0].Outcome != tc.want {
				t.Fatalf("subject outcome = %q, want %q", ends[0].Outcome, tc.want)
			}
			if ends[1].Outcome != structuredReadOutcomeSuccess {
				t.Fatalf("sibling outcome = %q, want the sibling unaffected", ends[1].Outcome)
			}
			if starts[0].InvocationID == starts[1].InvocationID {
				t.Fatal("both invocations share one id, want one UUIDv7 per invocation")
			}
		})
	}
}

func TestProductionDispatcher_EvidenceStartFailureSkipsInvocation(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	home := t.TempDir()
	tool := &countingReadTool{ReadTool: filetools.NewReadTool(home, project, project, 65536)}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, tool); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &recordingAuthorizer{decision: allow()}
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return nil }, 65536, securitystate.Policy{})

	calls := []turn.AssembledToolCall{structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "main.go"})}
	plan := d.Plan(calls, 2)
	assertOverlappableUnits(t, plan, calls)
	if _, err := plan.Units[0].Run(context.Background()); err == nil {
		t.Fatal("prepared run error = nil, want the unrecordable read refused")
	}
	if auth.callCount() != 0 {
		t.Fatalf("authorizer calls = %d, want 0 (the read must not run without its start record)", auth.callCount())
	}
}

func TestProductionDispatcher_PreparedRunMatchesOrdinaryDispatch(t *testing.T) {
	h, _, _ := planHarness(t)
	calls := sixReadCalls()
	plan := h.dispatcher.Plan(calls, 3)
	assertOverlappableUnits(t, plan, calls)
	for i, call := range calls {
		t.Run(call.Name, func(t *testing.T) {
			prepared, err := plan.Units[i].Run(context.Background())
			if err != nil {
				t.Fatalf("prepared run error = %v, want nil", err)
			}
			ordinary, err := h.dispatcher.Dispatch(context.Background(), call)
			if err != nil {
				t.Fatalf("ordinary dispatch error = %v, want nil", err)
			}
			if prepared != ordinary {
				t.Fatalf("prepared result = %+v, want the ordinary dispatch result %+v", prepared, ordinary)
			}
			if prepared.Content == "" {
				t.Fatal("prepared result content is empty, want the tool's real output")
			}
		})
	}
	if *h.gateCalls != 0 {
		t.Fatalf("prompt gate calls = %d, want 0 (in-project reads auto-allow in Build)", *h.gateCalls)
	}
}

func TestProductionDispatcher_PreparedRunFailsClosedOnSwappedTarget(t *testing.T) {
	h, project, outside := planHarness(t)
	target := filepath.Join(project, "swapped.txt")
	if err := os.WriteFile(target, []byte("in project\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	calls := []turn.AssembledToolCall{structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "swapped.txt"})}
	plan := h.dispatcher.Plan(calls, 3)
	assertOverlappableUnits(t, plan, calls)

	if err := os.Remove(target); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), target); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	// The scheduler runs the pre-run first, so the swap is re-checked on the path production
	// actually takes: a call whose target no longer prepares leaves its authorization group and
	// falls back to the per-call re-check rather than executing on a stale preparation.
	if err := plan.Units[0].PreRun(context.Background()); err != nil {
		t.Fatalf("pre-run error = %v, want the swapped call to simply leave its group", err)
	}
	res, err := plan.Units[0].Run(context.Background())
	if err == nil {
		t.Fatalf("prepared run error = nil, want the re-check to fail closed (content %q)", res.Content)
	}
	if strings.Contains(res.Content, "CANARY") {
		t.Fatalf("prepared read leaked out-of-project content: %q", res.Content)
	}
	reloaded := reloadStore(t, h.store)
	if n := len(kindEvents(t, reloaded, events.KindStructuredReadRefused)); n != 0 {
		t.Fatalf("structured_read_refused events = %d, want 0 (refusal is a planning record, and planning admitted this call)", n)
	}
	if n := len(kindEvents(t, reloaded, events.KindStructuredReadStart)); n != 0 {
		t.Fatalf("structured_read_start events = %d, want 0 (a failed re-check never dispatches)", n)
	}
}

type countingReadTool struct {
	*filetools.ReadTool
	resolves int32
}

func (t *countingReadTool) ResolveTarget(args map[string]any) (string, string, error) {
	atomic.AddInt32(&t.resolves, 1)
	return t.ReadTool.ResolveTarget(args)
}

func (t *countingReadTool) resolveCount() int { return int(atomic.LoadInt32(&t.resolves)) }

func TestProductionDispatcher_PreparedRunResolvesAgainAtDispatch(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	home := t.TempDir()
	tool := &countingReadTool{ReadTool: filetools.NewReadTool(home, project, project, 65536)}
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, tool); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &recordingAuthorizer{decision: allow()}
	store := mkStore(t)
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})

	calls := []turn.AssembledToolCall{structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "main.go"})}
	plan := d.Plan(calls, 3)
	assertOverlappableUnits(t, plan, calls)
	if got := tool.resolveCount(); got != 1 {
		t.Fatalf("resolutions after planning = %d, want 1", got)
	}
	if auth.callCount() != 0 {
		t.Fatalf("authorizer calls after planning = %d, want 0 (preparation never authorizes)", auth.callCount())
	}

	res, rerr := plan.Units[0].Run(context.Background())
	if rerr != nil {
		t.Fatalf("prepared run error = %v, want nil", rerr)
	}
	if !strings.HasPrefix(res.Content, "package main\n") {
		t.Fatalf("prepared read content = %q, want the file's verbatim content first", res.Content)
	}
	if got := tool.resolveCount(); got != 2 {
		t.Fatalf("resolutions after running = %d, want 2 (the run discards the plan-time resolution, which a barrier may have invalidated)", got)
	}
	if auth.callCount() != 1 {
		t.Fatalf("authorizer calls after running = %d, want 1", auth.callCount())
	}
	if mc := auth.lastModeCtx(t); mc.TargetPath != filepath.Join(project, "main.go") {
		t.Fatalf("mode context TargetPath = %q, want the prepared target", mc.TargetPath)
	}
}

func TestPhase1ReadToolNames_HoldsExactlyTheSixReads(t *testing.T) {
	want := []string{
		filetools.ReadToolName, filetools.GlobToolName, filetools.GrepToolName,
		filetools.ListToolName, filetools.TreeToolName, filetools.FileCountToolName,
	}
	if len(phase1ReadToolNames) != len(want) {
		t.Fatalf("allowlist holds %d names, want exactly %d", len(phase1ReadToolNames), len(want))
	}
	for _, name := range want {
		if _, ok := phase1ReadToolNames[name]; !ok {
			t.Fatalf("allowlist is missing %q", name)
		}
	}
	for _, name := range []string{filetools.ReadImageToolName, filetools.EditToolName, filetools.CreateToolName,
		filetools.DeleteToolName, filetools.MkdirToolName, filetools.MoveToolName, bashToolName} {
		if _, ok := phase1ReadToolNames[name]; ok {
			t.Fatalf("allowlist holds %q, want only the six read tools", name)
		}
	}
}

type scopelessReadTool struct {
	*filetools.ReadTool
}

func (t *scopelessReadTool) ResolveTarget(map[string]any) (string, string, error) { return "", "", nil }

func TestProductionDispatcher_PlanRejectsScopelessResolution(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, &scopelessReadTool{ReadTool: filetools.NewReadTool(home, project, project, 65536)}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	store := mkStore(t)
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()}, home, project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})

	calls := []turn.AssembledToolCall{structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "main.go"})}
	plan := d.Plan(calls, 3)
	assertSerialTargets(t, plan, calls)

	refusals := decodeStoreEvents[events.StructuredReadRefused](t, reloadStore(t, store), events.KindStructuredReadRefused)
	want := []events.StructuredReadRefused{{ToolName: filetools.ReadToolName, Reason: structuredReadRefusalScopeUnresolved, BatchSize: 1}}
	if !reflect.DeepEqual(refusals, want) {
		t.Fatalf("refusals = %+v, want %+v (an unresolved scope is not an external read)", refusals, want)
	}
}

type fakeQuestionAsker struct {
	mu    sync.Mutex
	calls int
	req   tui.QuestionRequest
	res   tui.QuestionResult
	err   error
}

func (f *fakeQuestionAsker) ask(_ context.Context, req tui.QuestionRequest) (tui.QuestionResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.req = req
	return f.res, f.err
}

func (f *fakeQuestionAsker) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func askUserCall(args string) turn.AssembledToolCall {
	return turn.AssembledToolCall{ID: "q1", Name: provider.AskUserToolName, Arguments: args}
}

const askUserValidArgs = `{"questions":[` +
	`{"id":"storage","prompt":"Where should sessions be stored?","context":"Sessions are replayed on /resume.\nWhere they live decides what survives a restart.",` +
	`"options":[{"label":"Local disk","description":"Fast, lost with the machine"},{"label":"Object store"}]},` +
	`{"id":"targets","prompt":"Which platforms?","options":[{"label":"Linux"},{"label":"macOS"}],"multi_select":true,"allow_custom":true}]}`

func TestProductionDispatcher_AskUserPlansAsAnOrdinarySerialCall(t *testing.T) {
	d := dispatcherFor(t, tools.NewRegistry(), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()})
	d.setAskUser((&fakeQuestionAsker{}).ask)

	calls := []turn.AssembledToolCall{askUserCall(askUserValidArgs)}
	plan := d.Plan(calls, 3)

	assertSerialTargets(t, plan, calls)
}

// The seven approved folder grants a recorded session lost to two ordinary edit calls.
const sevenGrantSettings = `permissions:
  - subject: prdtasks
    path_scope: /proj
    grant_kind: folder
  - subject: rg
    path_scope: /proj
    grant_kind: folder
  - subject: edit
    path_scope: /proj/internal
    grant_kind: folder
  - subject: create
    path_scope: /proj/internal
    grant_kind: folder
  - subject: mkdir
    path_scope: /proj/docs
    grant_kind: folder
  - subject: move
    path_scope: /proj/docs
    grant_kind: folder
  - subject: delete
    path_scope: /proj/tmp
    grant_kind: folder
`

const clearedGrantSettings = "permissions: []\n"

// guardedRun wires the realized production registry and the run's two configured settings
// identities, so a refusal it produces is the production guard's rather than a fixture's.
type guardedRun struct {
	project    string
	settings   string
	global     string
	auth       *recordingAuthorizer
	run        *fakeDispatchRunner
	dispatcher *productionToolDispatcher
}

func newGuardedRun(t *testing.T, active func() *sessions.Store) guardedRun {
	t.Helper()
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return newGuardedRunIn(t, active, project, nil)
}

func newGuardedRunIn(t *testing.T, active func() *sessions.Store, project string, av *ActiveVCS, blocked ...string) guardedRun {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	settings := projectSettingsPath(project)
	global := SettingsPath(home)
	seedProtectedSettings(t, settings)
	seedProtectedSettings(t, global)
	cache := emptyCache(t, project)
	reg, err := (&toolRegistryFactory{active: av}).realize(cache, active, home, project, securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}
	auth := &recordingAuthorizer{decision: allow()}
	run := &fakeDispatchRunner{}
	policy := securitystate.Policy{
		SettingsPaths: []string{projectSettingsPath(cache.ProjectRoot()), SettingsPath(home)},
	}
	if len(blocked) > 0 {
		entries := make([]permissions.BlockedEntry, len(blocked))
		for i, rel := range blocked {
			entries[i] = permissions.BlockedEntry{Path: filepath.Join(project, rel), Source: global}
		}
		policy.Blocked = permissions.NewBlockedPaths(home, entries)
	}
	return guardedRun{
		project:    project,
		settings:   settings,
		global:     global,
		auth:       auth,
		run:        run,
		dispatcher: newProductionToolDispatcher(reg, run, auth, home, project, active, 65536, policy),
	}
}

// Changed bytes or an appeared sidecar is what a refusal that arrived after the tool ran looks like.
func (g guardedRun) assertProtectedStateIntact(t *testing.T) {
	t.Helper()
	for _, path := range []string{g.settings, g.global} {
		if got := mustReadFile(t, path); got != sevenGrantSettings {
			t.Fatalf("settings file %q = %q, want the seven grants untouched", path, got)
		}
		if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
			t.Fatalf("sidecar %q stat err = %v, want it never created", path+".lock", err)
		}
	}
}

func removeGrants(path string) map[string]any {
	return map[string]any{"path": path, "old_text": sevenGrantSettings, "new_text": clearedGrantSettings}
}

func removeGrantsArgs(t *testing.T, path string) string {
	t.Helper()
	raw, err := json.Marshal(removeGrants(path))
	if err != nil {
		t.Fatalf("marshal grant-removal arguments: %v", err)
	}
	return string(raw)
}

func seedProtectedSettings(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(sevenGrantSettings), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func TestProductionDispatcher_GuardRefusesProtectedMutationBeforeInvocation(t *testing.T) {
	cases := []struct {
		name  string
		tool  string
		args  func(g guardedRun) map[string]any
		scope func(g guardedRun) string
	}{
		{
			name:  "seven-grant removal through the project settings file",
			tool:  filetools.EditToolName,
			args:  func(guardedRun) map[string]any { return removeGrants(".codemeld/settings.yaml") },
			scope: func(g guardedRun) string { return filepath.Dir(g.settings) },
		},
		{
			name:  "seven-grant removal through the global settings file",
			tool:  filetools.EditToolName,
			args:  func(g guardedRun) map[string]any { return removeGrants(g.global) },
			scope: func(g guardedRun) string { return filepath.Dir(g.global) },
		},
		{
			name: "project sidecar delete",
			tool: filetools.DeleteToolName,
			args: func(guardedRun) map[string]any {
				return map[string]any{"path": ".codemeld/settings.yaml.lock"}
			},
			scope: func(g guardedRun) string { return filepath.Dir(g.settings) },
		},
		{
			name: "global sidecar create through ~",
			tool: filetools.CreateToolName,
			args: func(guardedRun) map[string]any {
				return map[string]any{"path": "~/.codemeld/global/settings.yaml.lock", "content": "held\n"}
			},
			scope: func(g guardedRun) string { return filepath.Dir(g.global) },
		},
		{
			name: "project sidecar mkdir",
			tool: filetools.MkdirToolName,
			args: func(guardedRun) map[string]any {
				return map[string]any{"path": ".codemeld/settings.yaml.lock"}
			},
			scope: func(g guardedRun) string { return filepath.Dir(g.settings) },
		},
		{
			name: "move whose source is the project settings file",
			tool: filetools.MoveToolName,
			args: func(guardedRun) map[string]any {
				return map[string]any{"source": ".codemeld/settings.yaml", "destination": "spare.yaml"}
			},
			scope: func(g guardedRun) string { return filepath.Dir(g.settings) },
		},
		{
			name: "move whose destination is the global settings file",
			tool: filetools.MoveToolName,
			args: func(g guardedRun) map[string]any {
				return map[string]any{"source": "spare.yaml", "destination": g.global}
			},
			scope: func(g guardedRun) string { return filepath.Dir(g.global) },
		},
		{
			name: "move carrying away the directory that holds the project settings file",
			tool: filetools.MoveToolName,
			args: func(guardedRun) map[string]any {
				return map[string]any{"source": ".codemeld", "destination": "stash"}
			},
			scope: func(g guardedRun) string { return g.project },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := mkStore(t)
			g := newGuardedRun(t, func() *sessions.Store { return store })

			res, err := g.dispatcher.Dispatch(context.Background(), structuredCall("c1", tc.tool, tc.args(g)))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil (a guard refusal is an in-band denial)", err)
			}
			if !res.Denied {
				t.Fatalf("res.Denied = false, want the protected mutation refused; content=%q", res.Content)
			}
			if res.Content != permissions.BuildGuardDenyEnvelope() {
				t.Fatalf("res.Content = %q, want the fixed guard deny envelope %q", res.Content, permissions.BuildGuardDenyEnvelope())
			}
			if g.auth.callCount() != 0 {
				t.Fatalf("authorizer calls = %d, want 0 (the guard refuses before authorization)", g.auth.callCount())
			}
			g.assertProtectedStateIntact(t)

			matched := decodePermissionMatched(t, reloadStore(t, store))
			want := events.PermissionMatched{
				SubjectKind:   "tool",
				Subject:       tc.tool,
				PathScope:     tc.scope(g),
				Outcome:       "deny",
				OutcomeSource: "protected_state",
			}
			if len(matched) != 1 || matched[0] != want {
				t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
			}
		})
	}
}

func TestProductionDispatcher_GuardEventAppendFailureFailsClosed(t *testing.T) {
	g := newGuardedRun(t, func() *sessions.Store { return nil })

	res, err := g.dispatcher.Dispatch(context.Background(), structuredCall("c1", filetools.EditToolName, removeGrants(".codemeld/settings.yaml")))
	if err == nil {
		t.Fatalf("Dispatch error = nil (res=%+v), want the unrecordable guard refusal returned as an internal failure", res)
	}
	if res.Denied || res.Content != "" {
		t.Fatalf("res = %+v, want the empty result an internal failure carries", res)
	}
	if g.auth.callCount() != 0 {
		t.Fatalf("authorizer calls = %d, want 0", g.auth.callCount())
	}
	g.assertProtectedStateIntact(t)
}

func TestProductionDispatcher_OrdinaryPreparationErrorIsNotAGuardRefusal(t *testing.T) {
	store := mkStore(t)
	g := newGuardedRun(t, func() *sessions.Store { return store })

	res, err := g.dispatcher.Dispatch(context.Background(), structuredCall("c1", filetools.EditToolName,
		map[string]any{"path": "absent.go", "old_text": "OLD", "new_text": "NEW"}))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil (a bad target surfaces in band)", err)
	}
	if res.Denied || res.Content == "" || res.Content == permissions.BuildGuardDenyEnvelope() {
		t.Fatalf("res = %+v, want the tool's own in-band target refusal, not the guard envelope", res)
	}
	if matched := decodePermissionMatched(t, reloadStore(t, store)); len(matched) != 0 {
		t.Fatalf("permission_matched events = %#v, want none (an ordinary preparation error records no guard evidence)", matched)
	}
}

func TestProductionDispatcher_GuardLeavesUnprotectedMutationUnchanged(t *testing.T) {
	store := mkStore(t)
	g := newGuardedRun(t, func() *sessions.Store { return store })
	file := filepath.Join(g.project, "main.go")
	if err := os.WriteFile(file, []byte("package OLD\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	res, err := g.dispatcher.Dispatch(context.Background(), structuredCall("c1", filetools.EditToolName,
		map[string]any{"path": "main.go", "old_text": "OLD", "new_text": "NEW"}))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if res.Denied {
		t.Fatalf("res.Denied = true, want an authorized ordinary edit; content=%q", res.Content)
	}
	if g.auth.callCount() != 1 {
		t.Fatalf("authorizer calls = %d, want 1 (an unprotected target keeps its ordinary authorization)", g.auth.callCount())
	}
	if got := mustReadFile(t, file); got != "package NEW\n" {
		t.Fatalf("edited file = %q, want %q", got, "package NEW\n")
	}
	g.assertProtectedStateIntact(t)
	if matched := decodePermissionMatched(t, reloadStore(t, store)); len(matched) != 0 {
		t.Fatalf("permission_matched events = %#v, want none from the guard for an unprotected target", matched)
	}
}

// Reads are outside the settings guard's scope, so a settings read keeps its structured-read route.
func TestProductionDispatcher_GuardLeavesStructuredReadRouteUnchanged(t *testing.T) {
	t.Run("in-project settings read stays an eligible prepared read", func(t *testing.T) {
		store := mkStore(t)
		g := newGuardedRun(t, func() *sessions.Store { return store })

		calls := []turn.AssembledToolCall{structuredCall("c1", filetools.ReadToolName, map[string]any{"path": ".codemeld/settings.yaml"})}
		plan := g.dispatcher.Plan(calls, 2)
		assertOverlappableUnits(t, plan, calls)
		res, err := plan.Units[0].Run(context.Background())
		if err != nil {
			t.Fatalf("prepared run error = %v, want nil", err)
		}
		if res.Denied || !strings.Contains(res.Content, "permissions:") {
			t.Fatalf("res = %+v, want the settings file's contents read back", res)
		}
		if matched := decodePermissionMatched(t, reloadStore(t, store)); len(matched) != 0 {
			t.Fatalf("permission_matched events = %#v, want none (a read emits no guard evidence)", matched)
		}
	})

	t.Run("global settings read stays its external-read result", func(t *testing.T) {
		store := mkStore(t)
		g := newGuardedRun(t, func() *sessions.Store { return store })

		calls := []turn.AssembledToolCall{structuredCall("c1", filetools.ReadToolName, map[string]any{"path": g.global})}
		plan := g.dispatcher.Plan(calls, 2)
		assertSerialTargets(t, plan, calls)
		refusals := decodeStoreEvents[events.StructuredReadRefused](t, store, events.KindStructuredReadRefused)
		if len(refusals) != 1 || refusals[0].Reason != structuredReadRefusalOutOfProject {
			t.Fatalf("structured_read_refused = %#v, want one %q refusal", refusals, structuredReadRefusalOutOfProject)
		}
		res, err := plan.Units[0].Run(context.Background())
		if err != nil {
			t.Fatalf("dispatch error = %v, want nil", err)
		}
		if res.Denied || !strings.Contains(res.Content, "permissions:") {
			t.Fatalf("res = %+v, want the ordinary approved external read, not a guard refusal", res)
		}
		if g.auth.callCount() != 1 {
			t.Fatalf("authorizer calls = %d, want 1 (an external read still prompts)", g.auth.callCount())
		}
		if matched := decodePermissionMatched(t, reloadStore(t, store)); len(matched) != 0 {
			t.Fatalf("permission_matched events = %#v, want none from the guard", matched)
		}
	})
}

func blockedSourceLine(entry, source string) string {
	return "Blocked by the blocked_paths entry " + entry + " in " + source
}

func TestProductionDispatcher_BlockedPathRefusesReadBeforeInvocation(t *testing.T) {
	setup := func(t *testing.T, store *sessions.Store, project bool) (guardedRun, string, string) {
		t.Helper()
		g := newGuardedRun(t, func() *sessions.Store { return store })
		secrets := filepath.Join(g.project, "secrets")
		if err := os.MkdirAll(secrets, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(secrets, "token.txt"), []byte("TOKEN\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := os.WriteFile(filepath.Join(g.project, "notes.txt"), []byte("NOTES\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		source := g.global
		if project {
			source = g.settings
		}
		g.dispatcher.guard.Blocked = permissions.NewBlockedPaths(g.dispatcher.home, []permissions.BlockedEntry{{Path: secrets, Source: source}})
		return g, secrets, source
	}
	assertRefused := func(t *testing.T, g guardedRun, store *sessions.Store, secrets, source string, res turn.ToolResult) {
		t.Helper()
		if !res.Denied || !permissions.IsModeDenyEnvelope(res.Content) {
			t.Fatalf("res = %+v, want a recoverable guard denial", res)
		}
		if strings.Contains(res.Content, "TOKEN") {
			t.Fatalf("res.Content = %q carries the blocked file's content", res.Content)
		}
		if want := permissions.BuildBlockedPathDenyEnvelope(filepath.Join(secrets, "token.txt"), secrets, false); res.Content != want || strings.Contains(res.Content, source) {
			t.Fatalf("res.Content = %q, want exactly %q with no settings path", res.Content, want)
		}
		if want := blockedSourceLine(secrets, source); res.Notice != want {
			t.Fatalf("res.Notice = %q, want %q", res.Notice, want)
		}
		g.auth.mu.Lock()
		for _, modeCtx := range g.auth.modeCtxs {
			if strings.HasPrefix(modeCtx.TargetPath, secrets) {
				t.Errorf("authorizer saw blocked target %q, want the call refused before authorization", modeCtx.TargetPath)
			}
		}
		g.auth.mu.Unlock()
		matched := decodePermissionMatched(t, reloadStore(t, store))
		want := events.PermissionMatched{SubjectKind: "tool", Subject: filetools.ReadToolName, PathScope: secrets, Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: secrets, BlockedEntrySource: source}
		if len(matched) != 1 || matched[0] != want {
			t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
		}
	}

	for _, tc := range []struct {
		name    string
		project bool
	}{
		{name: "dispatch"},
		{name: "dispatch from a trusted project entry", project: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := mkStore(t)
			g, secrets, source := setup(t, store, tc.project)

			res, err := g.dispatcher.Dispatch(context.Background(), structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "secrets/token.txt"}))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil (a blocked-path refusal is an in-band denial)", err)
			}
			assertRefused(t, g, store, secrets, source, res)
			if g.auth.callCount() != 0 {
				t.Fatalf("authorizer calls = %d, want 0", g.auth.callCount())
			}
		})
	}

	t.Run("concurrent read segment", func(t *testing.T) {
		store := mkStore(t)
		g, secrets, source := setup(t, store, false)
		calls := []turn.AssembledToolCall{
			structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "notes.txt"}),
			structuredCall("c2", filetools.ReadToolName, map[string]any{"path": "secrets/token.txt"}),
		}

		plan := g.dispatcher.Plan(calls, 2)
		results := make([]turn.ToolResult, len(plan.Units))
		for i, unit := range plan.Units {
			if unit.PreRun != nil {
				if err := unit.PreRun(context.Background()); err != nil {
					t.Fatalf("unit %d PreRun error = %v", i, err)
				}
			}
			res, err := unit.Run(context.Background())
			if err != nil {
				t.Fatalf("unit %d Run error = %v", i, err)
			}
			results[i] = res
		}
		if results[0].Denied || !strings.Contains(results[0].Content, "NOTES") {
			t.Fatalf("unblocked read = %+v, want its content", results[0])
		}
		assertRefused(t, g, store, secrets, source, results[1])
	})

	t.Run("floor", func(t *testing.T) {
		store := mkStore(t)
		g, _, _ := setup(t, store, false)
		floor := filepath.Join(g.dispatcher.home, ".codemeld")
		target := filepath.Join(floor, "x")
		if err := os.WriteFile(target, []byte("TOKEN\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		res, err := g.dispatcher.Dispatch(context.Background(), structuredCall("c1", filetools.ReadToolName, map[string]any{"path": target}))
		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil", err)
		}
		if !res.Denied || strings.Contains(res.Content, "TOKEN") {
			t.Fatalf("res = %+v, want a denial that carries none of the file", res)
		}
		if res.Notice != "" {
			t.Fatalf("res.Notice = %q, want none for a floor refusal", res.Notice)
		}
		reloaded := reloadStore(t, store)
		want := events.PermissionMatched{SubjectKind: "tool", Subject: filetools.ReadToolName, PathScope: floor, Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: floor}
		if matched := decodePermissionMatched(t, reloaded); len(matched) != 1 || matched[0] != want {
			t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
		}
		for _, rec := range reloaded.Records() {
			if ev, ok := rec.(sessions.Event); ok && ev.Kind == events.KindPermissionMatched && strings.Contains(string(ev.Payload), `"blocked_entry_source"`) {
				t.Fatalf("floor refusal payload %s carries blocked_entry_source", ev.Payload)
			}
		}
	})

	t.Run("protected state", func(t *testing.T) {
		store := mkStore(t)
		g, _, _ := setup(t, store, false)

		res, err := g.dispatcher.Dispatch(context.Background(), structuredCall("c1", filetools.EditToolName, removeGrants(g.global)))
		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil", err)
		}
		if !res.Denied || res.Content != permissions.BuildGuardDenyEnvelope() || res.Notice != "" {
			t.Fatalf("res = %+v, want the guard deny envelope with no notice", res)
		}
	})
}

func TestProductionDispatcher_BlockedPathRefusesShellReadBeforeInvocation(t *testing.T) {
	setup := func(t *testing.T, store *sessions.Store, project bool) (guardedRun, string, string) {
		t.Helper()
		g := newGuardedRun(t, func() *sessions.Store { return store })
		secrets := filepath.Join(g.project, "secrets")
		if err := os.MkdirAll(secrets, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(secrets, "token.txt"), []byte("TOKEN\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		source := g.global
		if project {
			source = g.settings
		}
		g.dispatcher.guard.Blocked = permissions.NewBlockedPaths(g.dispatcher.home, []permissions.BlockedEntry{{Path: secrets, Source: source}})
		return g, secrets, source
	}
	direct := func(t *testing.T, scope string, tokens ...string) events.PermissionMatched {
		t.Helper()
		requestSubject, err := permissions.DirectRequestSubject(tokens, nil, false)
		if err != nil {
			t.Fatalf("DirectRequestSubject: %v", err)
		}
		return events.PermissionMatched{SubjectKind: "direct", Subject: strings.Join(tokens, " "), PathScope: scope, DirectRequestSubject: requestSubject}
	}
	readToken := func(t *testing.T, project, secrets string) (string, events.PermissionMatched) {
		token := filepath.Join(secrets, "token.txt")
		return "cat " + token, direct(t, project, "cat", token)
	}

	for _, tc := range []struct {
		name    string
		child   bool
		project bool
		build   func(t *testing.T, project, secrets string) (string, events.PermissionMatched)
	}{
		{name: "direct read", build: readToken},
		{name: "direct read from a trusted project entry", project: true, build: readToken},
		{name: "run folder", build: func(t *testing.T, project, secrets string) (string, events.PermissionMatched) {
			return "cd " + secrets + " && ls", direct(t, secrets, "ls")
		}},
		{name: "staged read", build: func(t *testing.T, project, secrets string) (string, events.PermissionMatched) {
			token := filepath.Join(secrets, "token.txt")
			return "ls && cat " + token, direct(t, project, "cat", token)
		}},
		{name: "literal read", build: func(t *testing.T, project, secrets string) (string, events.PermissionMatched) {
			command := "cat " + filepath.Join(secrets, "token.txt") + " 2>/dev/null"
			canonical, err := permissions.CanonicalLiteralForm(command)
			if err != nil {
				t.Fatalf("CanonicalLiteralForm: %v", err)
			}
			return command, events.PermissionMatched{SubjectKind: "literal", Subject: canonical, PathScope: project, ArgumentHash: permissions.ComputeArgumentHash(canonical)}
		}},
		{name: "child dispatcher", child: true, build: readToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := mkStore(t)
			g, secrets, source := setup(t, store, tc.project)
			command, want := tc.build(t, g.project, secrets)
			want.Outcome, want.OutcomeSource, want.BlockedEntry, want.BlockedEntrySource = "deny", "blocked_path", secrets, source
			if tc.child {
				want.ChildInvocationID = ids.NewV7()
				g.dispatcher.childInvocationID = want.ChildInvocationID
			}

			res, err := g.dispatcher.Dispatch(context.Background(), bashCall("c1", command))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil (a blocked-path refusal is an in-band denial)", err)
			}
			if !res.Denied || !permissions.IsModeDenyEnvelope(res.Content) || strings.Contains(res.Content, "TOKEN") {
				t.Fatalf("res = %+v, want a recoverable guard denial that carries none of the file", res)
			}
			target := filepath.Join(secrets, "token.txt")
			if want.PathScope == secrets {
				target = secrets
			}
			if wantContent := permissions.BuildBlockedPathDenyEnvelope(target, secrets, false); res.Content != wantContent || strings.Contains(res.Content, source) {
				t.Fatalf("res.Content = %q, want exactly %q with no settings path", res.Content, wantContent)
			}
			if wantNotice := blockedSourceLine(secrets, source); res.Notice != wantNotice {
				t.Fatalf("res.Notice = %q, want %q", res.Notice, wantNotice)
			}
			if g.auth.callCount() != 0 || g.run.callCount() != 0 {
				t.Fatalf("authorizer calls = %d, runner calls = %d, want 0/0", g.auth.callCount(), g.run.callCount())
			}
			if matched := decodePermissionMatched(t, reloadStore(t, store)); len(matched) != 1 || matched[0] != want {
				t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
			}
		})
	}

	t.Run("mutating command naming the blocked path", func(t *testing.T) {
		store := mkStore(t)
		g, secrets, _ := setup(t, store, false)

		res, err := g.dispatcher.Dispatch(context.Background(), bashCall("c1", "rm "+filepath.Join(secrets, "token.txt")))
		if err != nil || res.Denied {
			t.Fatalf("res = %+v, err = %v; want the approved command to run", res, err)
		}
		if g.auth.callCount() != 1 || g.run.callCount() != 1 {
			t.Fatalf("authorizer calls = %d, runner calls = %d, want 1/1", g.auth.callCount(), g.run.callCount())
		}
		if matched := decodePermissionMatched(t, reloadStore(t, store)); len(matched) != 0 {
			t.Fatalf("permission_matched events = %#v, want none from the guard", matched)
		}
	})
}

func TestProductionDispatcher_ShellCommandAboveABlockedPathAsks(t *testing.T) {
	for _, approve := range []bool{true, false} {
		t.Run(fmt.Sprintf("prompts once, approve=%v", approve), func(t *testing.T) {
			store := mkStore(t)
			g := newGuardedRun(t, func() *sessions.Store { return store })
			secrets := filepath.Join(g.project, "secrets")
			if err := os.MkdirAll(secrets, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			g.dispatcher.guard.Blocked = permissions.NewBlockedPaths(g.dispatcher.home, []permissions.BlockedEntry{{Path: secrets, Source: g.global}})
			gateCalls := 0
			gate := func(tui.PromptRequest) (tui.PromptDecision, error) {
				gateCalls++
				if approve {
					return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
				}
				return tui.PromptDecision{Option: tui.OptionDeny}, nil
			}
			app := tui.New(nil)
			app.SetActiveStore(store)
			g.dispatcher.authorizer = newProductionAuthorizer(app, emptyCache(t, g.project), permissions.NewTurnCache(), newPromptGateBuilder(gate), g.dispatcher.home, g.project, mode.NewActiveState(mode.Build, mode.SourceConfig))

			res, err := g.dispatcher.Dispatch(context.Background(), bashCall("c1", "ls "+g.dispatcher.home))
			if err != nil {
				t.Fatalf("Dispatch error = %v", err)
			}
			wantRuns := 0
			if approve {
				wantRuns = 1
			}
			if gateCalls != 1 || g.run.callCount() != wantRuns || res.Denied == approve {
				t.Fatalf("prompts = %d, runner calls = %d, denied = %v; want 1 prompt, %d runs, denied = %v", gateCalls, g.run.callCount(), res.Denied, wantRuns, !approve)
			}
			for _, matched := range decodePermissionMatched(t, reloadStore(t, store)) {
				if matched.OutcomeSource == "mode_auto" {
					t.Fatalf("permission_matched = %+v, want no mode_auto allow", matched)
				}
			}
		})
	}

	t.Run("a child dispatcher denies without running", func(t *testing.T) {
		cache, home, project, active, modeActive := generalAgentFixture(t)
		const marker = "home-listing-marker"
		if err := os.WriteFile(filepath.Join(home, marker), nil, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		file := seedBlockedSecret(t, project)
		store := mkStore(t)
		reg := generalAgentRegistry(t, cache, home, project, active, modeActive)
		guard := mustProtectedStatePolicy(t, home, cache.ProjectRoot(), blockedGlobalLayers(t, home, project, filepath.Dir(file)))
		deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, guard)
		child := deps.NewDispatcher(permissions.ModeContext{Mode: string(mode.Build)})

		res, err := child.Dispatch(context.Background(), bashCall("c1", "ls "+home))
		if err != nil {
			t.Fatalf("Dispatch error = %v", err)
		}
		if !res.Denied || strings.Contains(res.Content, marker) {
			t.Fatalf("res = %+v, want a denial carrying no home listing", res)
		}
		reloaded := reloadStore(t, store)
		if execs := decodeStoreEvents[events.ToolExecStart](t, reloaded, events.KindToolExecStart); len(execs) != 0 {
			t.Fatalf("tool_exec_start events = %+v, want none: the command must not run", execs)
		}
		for _, matched := range decodePermissionMatched(t, reloaded) {
			if matched.OutcomeSource == "mode_auto" {
				t.Fatalf("permission_matched = %+v, want no mode_auto allow", matched)
			}
		}
	})
}

func TestRealizeToolRegistry_WalkToolsLeaveOutBlockedEntries(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	secrets := filepath.Join(project, "secrets")
	if err := os.MkdirAll(secrets, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	for path, content := range map[string]string{
		filepath.Join(secrets, "token.txt"): "TOKEN\n",
		filepath.Join(project, "notes.txt"): "nothing here\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	registry := func(guard securitystate.Policy) *tools.Registry {
		reg, err := realizeToolRegistry(&toolRegistryFactory{}, emptyCache(t, project), func() *sessions.Store { return mkStore(t) }, home, project, guard)
		if err != nil {
			t.Fatalf("realizeToolRegistry: %v", err)
		}
		return reg
	}
	blocked := registry(securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, []permissions.BlockedEntry{{Path: secrets, Source: SettingsPath(home)}})})
	unblocked := registry(securitystate.Policy{})

	for name, args := range map[string]map[string]any{
		filetools.GlobToolName:      {"pattern": "**", "include_ignored": true},
		filetools.TreeToolName:      {"include_ignored": true},
		filetools.ListToolName:      {"include_ignored": true},
		filetools.GrepToolName:      {"pattern": "TOKEN", "include_ignored": true},
		filetools.FileCountToolName: {"include_ignored": true},
	} {
		t.Run(name, func(t *testing.T) {
			invoke := func(reg *tools.Registry) tools.Result {
				tool, ok := reg.Lookup(name)
				if !ok {
					t.Fatalf("%s not registered", name)
				}
				res, err := tool.Invoke(context.Background(), args)
				if err != nil {
					t.Fatalf("Invoke(%s): %v", name, err)
				}
				return res
			}
			got, baseline := invoke(blocked), invoke(unblocked)
			if string(got.Stdout) == string(baseline.Stdout) {
				t.Fatalf("stdout = %q with and without the blocked entry, want the entry left out", got.Stdout)
			}
			if strings.Contains(string(got.Stdout), "secrets") || strings.Contains(string(got.Stdout), "TOKEN") {
				t.Fatalf("stdout = %q, want nothing from the blocked folder", got.Stdout)
			}
			if !strings.Contains(string(got.Stderr), "left out (blocked): secrets\n") {
				t.Fatalf("stderr = %q, want the left-out line", got.Stderr)
			}
			if strings.Contains(string(baseline.Stderr), "left out") {
				t.Fatalf("unblocked stderr = %q, want no left-out line", baseline.Stderr)
			}
		})
	}
}

// Dropping the policy from otherwise identical wiring reproduces the incident, so the refusal above
// is the forwarded policy's doing and not something else in the path.
func TestProductionDispatcher_WithoutTheForwardedPolicyTheGrantRemovalSucceeds(t *testing.T) {
	store := mkStore(t)
	g := newGuardedRun(t, func() *sessions.Store { return store })
	g.dispatcher.guard = securitystate.Policy{}

	res, err := g.dispatcher.Dispatch(context.Background(), structuredCall("c1", filetools.EditToolName, removeGrants(".codemeld/settings.yaml")))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if res.Denied {
		t.Fatalf("res.Denied = true, want the unguarded edit to go through; content=%q", res.Content)
	}
	if got := mustReadFile(t, g.settings); got != clearedGrantSettings {
		t.Fatalf("settings file = %q, want the grants removed %q — the zero policy must protect nothing", got, clearedGrantSettings)
	}
}

// Raw shell is a declared residual: a command naming a protected file keeps dispatching as it does
// today rather than picking up the guard.
func TestProductionDispatcher_GuardLeavesRawShellUnchanged(t *testing.T) {
	store := mkStore(t)
	g := newGuardedRun(t, func() *sessions.Store { return store })

	res, err := g.dispatcher.Dispatch(context.Background(), bashCall("c1", "rm .codemeld/settings.yaml"))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if res.Denied {
		t.Fatalf("res.Denied = true, want raw shell outside the guard; content=%q", res.Content)
	}
	if g.auth.callCount() != 1 || g.run.callCount() != 1 {
		t.Fatalf("authorizer calls = %d, runner calls = %d, want 1/1 (raw shell keeps its ordinary route)", g.auth.callCount(), g.run.callCount())
	}
	if matched := decodePermissionMatched(t, reloadStore(t, store)); len(matched) != 0 {
		t.Fatalf("permission_matched events = %#v, want none from the guard for a shell command", matched)
	}
}

func requireVCSBinary(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not available: %v", name, err)
	}
}

func runInRepo(t *testing.T, dir string, argv ...string) {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v in %s: %v\n%s", argv, dir, err, out)
	}
}

// The repositories below commit the cleared-grant bytes and leave the seven grants uncommitted, so a
// guard that failed would be visible as a real restore replacing them.
func seedGitRepo(t *testing.T, project string) {
	t.Helper()
	requireVCSBinary(t, "git")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "gitconfig"))
	t.Setenv("GIT_CONFIG_SYSTEM", filepath.Join(t.TempDir(), "gitsystem"))
	t.Setenv("GIT_AUTHOR_NAME", "codemeld")
	t.Setenv("GIT_AUTHOR_EMAIL", "codemeld@example.test")
	t.Setenv("GIT_COMMITTER_NAME", "codemeld")
	t.Setenv("GIT_COMMITTER_EMAIL", "codemeld@example.test")
	runInRepo(t, project, "git", "init", "-b", "main")
	seedTrackedSettings(t, project)
	runInRepo(t, project, "git", "add", ".codemeld/settings.yaml")
	runInRepo(t, project, "git", "commit", "-m", "track policy")
}

func seedHgRepo(t *testing.T, project string) {
	t.Helper()
	requireVCSBinary(t, "hg")
	t.Setenv("HGRCPATH", filepath.Join(t.TempDir(), "hgrc"))
	t.Setenv("HGUSER", "codemeld <codemeld@example.test>")
	runInRepo(t, project, "hg", "init")
	seedTrackedSettings(t, project)
	runInRepo(t, project, "hg", "add", ".codemeld/settings.yaml")
	runInRepo(t, project, "hg", "commit", "-m", "track policy")
}

func seedJJRepo(t *testing.T, project string) {
	t.Helper()
	requireVCSBinary(t, "jj")
	config := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(config, []byte("[user]\nname = \"codemeld\"\nemail = \"codemeld@example.test\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("JJ_CONFIG", config)
	runInRepo(t, project, "jj", "git", "init")
	seedTrackedSettings(t, project)
}

func seedTrackedSettings(t *testing.T, project string) {
	t.Helper()
	path := projectSettingsPath(project)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(clearedGrantSettings), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func activeBuiltinVCS(t *testing.T, name, project string) *ActiveVCS {
	t.Helper()
	tmpls, err := vcs.LoadBuiltinTemplates()
	if err != nil {
		t.Fatalf("LoadBuiltinTemplates: %v", err)
	}
	tmpl, ok := tmpls[name]
	if !ok {
		t.Fatalf("built-in template %q not loaded", name)
	}
	return &ActiveVCS{Template: tmpl, RepoRoot: project}
}

// The whole production path runs here: the realized registry's real *vcs.ActionTool, the production
// dispatcher, and the real git/hg/jj binaries behind DirectExecRunner.
func TestProductionDispatcher_GuardRefusesRealVCSActionsAndPreservesSettings(t *testing.T) {
	cases := []struct {
		name    string
		vcsName string
		seed    func(*testing.T, string)
		refused []string
		allowed []struct {
			tool string
			args map[string]any
		}
	}{
		{
			name: "git", vcsName: "git", seed: seedGitRepo,
			refused: []string{"vcs_restore_file", "vcs_stash"},
			allowed: []struct {
				tool string
				args map[string]any
			}{
				{"vcs_status", nil},
				{"vcs_add", map[string]any{"path": ".codemeld/settings.yaml"}},
				{"vcs_commit", map[string]any{"message": "track approved policy"}},
			},
		},
		{
			name: "hg", vcsName: "hg", seed: seedHgRepo,
			refused: []string{"vcs_restore_file", "vcs_stash", "vcs_stash_pop"},
			allowed: []struct {
				tool string
				args map[string]any
			}{
				{"vcs_status", nil},
				{"vcs_add", map[string]any{"path": ".codemeld/settings.yaml"}},
				{"vcs_commit", map[string]any{"message": "track approved policy"}},
			},
		},
		{
			name: "jj", vcsName: "jj", seed: seedJJRepo,
			refused: []string{"vcs_restore_file"},
			allowed: []struct {
				tool string
				args map[string]any
			}{
				{"vcs_status", nil},
				{"vcs_stash", nil},
				{"vcs_stash_pop", nil},
				{"vcs_commit", map[string]any{"message": "track approved policy"}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, tool := range tc.refused {
				t.Run("refused/"+tool, func(t *testing.T) {
					store := mkStore(t)
					project, g := newGuardedVCSRun(t, store, tc.vcsName, tc.seed)

					res, err := g.dispatcher.Dispatch(context.Background(), structuredCall("c1", tool, map[string]any{"path": ".codemeld/settings.yaml", "branch": "main"}))
					if err != nil {
						t.Fatalf("Dispatch error = %v, want nil (a guard refusal is an in-band denial)", err)
					}
					if !res.Denied || res.Content != permissions.BuildGuardDenyEnvelope() {
						t.Fatalf("res = %+v, want the fixed guard deny envelope", res)
					}
					if g.auth.callCount() != 0 {
						t.Fatalf("authorizer calls = %d, want 0 (the guard refuses before authorization)", g.auth.callCount())
					}
					g.assertProtectedStateIntact(t)

					matched := decodePermissionMatched(t, reloadStore(t, store))
					want := events.PermissionMatched{
						SubjectKind:   "tool",
						Subject:       tool,
						PathScope:     project,
						Outcome:       "deny",
						OutcomeSource: "protected_state",
					}
					if len(matched) != 1 || matched[0] != want {
						t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
					}
					if execs := decodeStoreEvents[events.ToolExecStart](t, reloadStore(t, store), events.KindToolExecStart); len(execs) != 0 {
						t.Fatalf("tool_exec_start events = %#v, want none; the action must not launch", execs)
					}
				})
			}
			for _, allowed := range tc.allowed {
				t.Run("allowed/"+allowed.tool, func(t *testing.T) {
					store := mkStore(t)
					_, g := newGuardedVCSRun(t, store, tc.vcsName, tc.seed)

					res, err := g.dispatcher.Dispatch(context.Background(), structuredCall("c1", allowed.tool, allowed.args))
					if err != nil {
						t.Fatalf("Dispatch error = %v, want nil", err)
					}
					if res.Denied {
						t.Fatalf("res = %+v, want %s to stay available under the guard", res, allowed.tool)
					}
					if g.auth.callCount() != 1 {
						t.Fatalf("authorizer calls = %d, want 1", g.auth.callCount())
					}
					g.assertProtectedStateIntact(t)
					if matched := decodePermissionMatched(t, reloadStore(t, store)); len(matched) != 0 {
						t.Fatalf("durable permission_matched = %#v, want no guard evidence", matched)
					}
				})
			}
		})
	}
}

func newGuardedVCSRun(t *testing.T, store *sessions.Store, vcsName string, seed func(*testing.T, string), blocked ...string) (string, guardedRun) {
	t.Helper()
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	seed(t, project)
	return project, newGuardedRunIn(t, func() *sessions.Store { return store }, project, activeBuiltinVCS(t, vcsName, project), blocked...)
}

const (
	committedSecret = "k-committed\n"
	modifiedSecret  = "k-modified\n"
)

func writeSecret(t *testing.T, project, content string) {
	t.Helper()
	path := filepath.Join(project, "secrets", "k")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func seedBlockedGitRepo(t *testing.T, project string) {
	t.Helper()
	seedGitRepo(t, project)
	seedProtectedSettings(t, projectSettingsPath(project))
	writeSecret(t, project, committedSecret)
	runInRepo(t, project, "git", "add", ".codemeld/settings.yaml", "secrets/k")
	runInRepo(t, project, "git", "commit", "-m", "track secret")
	writeSecret(t, project, "k-stashed\n")
	runInRepo(t, project, "git", "stash", "push")
	writeSecret(t, project, modifiedSecret)
}

func seedBlockedHgRepo(t *testing.T, project string) {
	t.Helper()
	seedHgRepo(t, project)
	seedProtectedSettings(t, projectSettingsPath(project))
	writeSecret(t, project, committedSecret)
	runInRepo(t, project, "hg", "add", "secrets/k")
	runInRepo(t, project, "hg", "commit", "-m", "track secret")
	writeSecret(t, project, modifiedSecret)
}

func seedBlockedJJRepo(t *testing.T, project string) {
	t.Helper()
	seedJJRepo(t, project)
	seedProtectedSettings(t, projectSettingsPath(project))
	writeSecret(t, project, committedSecret)
	runInRepo(t, project, "jj", "commit", "-m", "track secret")
	writeSecret(t, project, modifiedSecret)
}

func TestProductionDispatcher_BlockedEntryRefusesRealVCSRewritesAndLeavesDiffAlone(t *testing.T) {
	cases := []struct {
		vcsName string
		seed    func(*testing.T, string)
		branch  string
		refused map[string]string
	}{
		{"git", seedBlockedGitRepo, "main", map[string]string{
			"vcs_restore_file": "blocked_path", "vcs_branch_switch": "blocked_path", "vcs_stash": "blocked_path", "vcs_stash_pop": "blocked_path",
		}},
		{"hg", seedBlockedHgRepo, ".", map[string]string{
			"vcs_restore_file": "blocked_path", "vcs_branch_switch": "blocked_path", "vcs_stash": "blocked_path", "vcs_stash_pop": "protected_state",
		}},
		{"jj", seedBlockedJJRepo, "@-", map[string]string{
			"vcs_restore_file": "blocked_path", "vcs_branch_switch": "blocked_path",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.vcsName, func(t *testing.T) {
			for tool, source := range tc.refused {
				t.Run("refused/"+tool, func(t *testing.T) {
					store := mkStore(t)
					project, g := newGuardedVCSRun(t, store, tc.vcsName, tc.seed, "secrets")
					secrets := filepath.Join(project, "secrets")

					res, err := g.dispatcher.Dispatch(context.Background(), structuredCall("c1", tool, map[string]any{"path": "secrets/k", "branch": tc.branch}))
					if err != nil {
						t.Fatalf("Dispatch error = %v, want nil (a refusal is an in-band denial)", err)
					}
					want := events.PermissionMatched{SubjectKind: "tool", Subject: tool, PathScope: project, Outcome: "deny", OutcomeSource: source}
					envelope := permissions.BuildGuardDenyEnvelope()
					if source == "blocked_path" {
						want.BlockedEntry, want.BlockedEntrySource = secrets, g.global
						envelope = permissions.BuildBlockedPathDenyEnvelope(project, secrets, false)
					}
					if !res.Denied || res.Content != envelope {
						t.Fatalf("res = %+v, want the %s deny envelope %q", res, source, envelope)
					}
					if g.auth.callCount() != 0 {
						t.Fatalf("authorizer calls = %d, want 0", g.auth.callCount())
					}
					if got := mustReadFile(t, filepath.Join(secrets, "k")); got != modifiedSecret {
						t.Fatalf("blocked file = %q, want its modified bytes %q", got, modifiedSecret)
					}
					g.assertProtectedStateIntact(t)

					if matched := decodePermissionMatched(t, reloadStore(t, store)); len(matched) != 1 || matched[0] != want {
						t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
					}
					if execs := decodeStoreEvents[events.ToolExecStart](t, reloadStore(t, store), events.KindToolExecStart); len(execs) != 0 {
						t.Fatalf("tool_exec_start events = %#v, want none; the action must not launch", execs)
					}
				})
			}
			t.Run("allowed/vcs_diff", func(t *testing.T) {
				store := mkStore(t)
				_, g := newGuardedVCSRun(t, store, tc.vcsName, tc.seed, "secrets")

				res, err := g.dispatcher.Dispatch(context.Background(), structuredCall("c1", "vcs_diff", nil))
				if err != nil {
					t.Fatalf("Dispatch error = %v, want nil", err)
				}
				if res.Denied || !strings.Contains(res.Content, strings.TrimSpace(modifiedSecret)) {
					t.Fatalf("res = %+v, want the diff to run and show the blocked file's change", res)
				}
				if g.auth.callCount() != 1 {
					t.Fatalf("authorizer calls = %d, want 1", g.auth.callCount())
				}
				if matched := decodePermissionMatched(t, reloadStore(t, store)); len(matched) != 0 {
					t.Fatalf("durable permission_matched = %#v, want none", matched)
				}
			})
		})
	}
}

// orderedFailureAuthorizer fails two named targets with distinct errors and holds one of them until
// the other has already failed, so a test pins which concurrent failure reaches the plan's latch
// first without depending on scheduling luck.
type orderedFailureAuthorizer struct {
	errs    map[string]error
	waitFor map[string]chan struct{}
	signal  map[string]chan struct{}
}

func (a *orderedFailureAuthorizer) Authorize(_ context.Context, _ permissions.MatchRequest, _ dispatch.PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error) {
	err, failing := a.errs[modeCtx.TargetPath]
	if !failing {
		return allow(), nil
	}
	if wait, ok := a.waitFor[modeCtx.TargetPath]; ok {
		<-wait
	}
	if signal, ok := a.signal[modeCtx.TargetPath]; ok {
		close(signal)
	}
	return permissions.Decision{}, err
}

func TestProductionDispatcher_LatchSurfacesTheLowestIndexEligibleFailure(t *testing.T) {
	first, second := errors.New("first read failed"), errors.New("second read failed")
	for _, tc := range []struct{ name, fails, waits string }{
		{"lower index fails first", "a.go", "b.go"},
		{"higher index fails first", "b.go", "a.go"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project := readToolsProject(t)
			home := t.TempDir()
			for _, name := range []string{"a.go", "b.go"} {
				if err := os.WriteFile(filepath.Join(project, name), []byte("package p\n"), 0o644); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
			}
			reg, err := (&toolRegistryFactory{active: nil}).realize(emptyCache(t, project), func() *sessions.Store { return nil }, home, project, securitystate.Policy{})
			if err != nil {
				t.Fatalf("realize production registry: %v", err)
			}
			failed := make(chan struct{})
			auth := &orderedFailureAuthorizer{
				errs:    map[string]error{filepath.Join(project, "a.go"): first, filepath.Join(project, "b.go"): second},
				signal:  map[string]chan struct{}{filepath.Join(project, tc.fails): failed},
				waitFor: map[string]chan struct{}{filepath.Join(project, tc.waits): failed},
			}
			store := mkStore(t)
			d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})

			calls := []turn.AssembledToolCall{
				structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "a.go"}),
				structuredCall("c2", filetools.ReadToolName, map[string]any{"path": "b.go"}),
				bashCall("c3", "echo hi"),
			}
			plan := d.Plan(calls, 3)
			assertPartitionedPlan(t, plan, calls, "eex")

			run, serr := schedulePlan(plan, 3, nil)
			if !errors.Is(serr, first) {
				t.Fatalf("surfaced error = %v, want the lowest model-call-index failure %v regardless of completion order", serr, first)
			}
			if want := []string{"c1", "c2"}; !slices.Equal(sortedIDs(run.ids()), want) {
				t.Fatalf("executed = %v, want the failing segment to drain and the barrier to stay unexecuted", run.ids())
			}
		})
	}
}

func sortedIDs(ids []string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return out
}

func newOpenReadHarness(t *testing.T, project, home string, m mode.Mode, entries []permissions.BlockedEntry) readToolsHarness {
	t.Helper()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	gateCalls := 0
	gate := func(tui.PromptRequest) (tui.PromptDecision, error) {
		gateCalls++
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	cache := emptyCache(t, project)
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(gate), home, project, mode.NewActiveState(m, mode.SourceConfig))
	policy := securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, entries)}
	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, func() *sessions.Store { return store }, home, project, policy)
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), policy)
	return readToolsHarness{dispatcher: d, cache: cache, store: store, gateCalls: &gateCalls}
}

var openReadModes = []struct {
	name string
	m    mode.Mode
}{{"build", mode.Build}, {"auto_edits", mode.AutoEdits}, {"plan", mode.Plan}}

func TestProductionDispatcher_OpenReadReadsExplicitOutsideTargetsWithoutPrompt(t *testing.T) {
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "ext.txt"), []byte("external-canary\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "ext.png"), pngBytes, 0o644); err != nil {
		t.Fatalf("WriteFile png: %v", err)
	}
	cases := []struct {
		tool string
		args map[string]any
		want string
	}{
		{filetools.ReadToolName, map[string]any{"path": filepath.Join(outside, "ext.txt")}, "external-canary"},
		{filetools.ReadImageToolName, map[string]any{"path": filepath.Join(outside, "ext.png")}, "image/png"},
		{filetools.GrepToolName, map[string]any{"pattern": "external-canary", "path": outside}, "ext.txt"},
		{filetools.ListToolName, map[string]any{"path": outside}, "ext.txt"},
	}
	for _, md := range openReadModes {
		for _, tc := range cases {
			t.Run(md.name+"/"+tc.tool, func(t *testing.T) {
				project := readToolsProject(t)
				home := t.TempDir()
				h := newOpenReadHarness(t, project, home, md.m, nil)

				res, derr := h.dispatcher.Dispatch(context.Background(), structuredCall("c1", tc.tool, tc.args))
				if derr != nil {
					t.Fatalf("Dispatch error = %v, want nil", derr)
				}
				if res.Denied || !strings.Contains(res.Content, tc.want) {
					t.Fatalf("res = %+v, want the outside target's content %q", res, tc.want)
				}
				if *h.gateCalls != 0 {
					t.Fatalf("prompt gate calls = %d, want 0", *h.gateCalls)
				}
				matched := decodePermissionMatched(t, reloadStore(t, h.store))
				want := events.PermissionMatched{SubjectKind: "tool", Subject: tc.tool, PathScope: outside, Outcome: "once", OutcomeSource: "open_read"}
				if len(matched) != 1 || matched[0] != want {
					t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
				}
				if grants := h.cache.Permissions(); len(grants) != 0 {
					t.Fatalf("grant table = %#v, want no grant", grants)
				}
				for _, dir := range []string{filepath.Join(project, ".codemeld"), filepath.Join(home, ".codemeld")} {
					if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("settings folder %s exists (err=%v), want no grant written", dir, err)
					}
				}
			})
		}
	}
}

func TestProductionDispatcher_OpenReadEscapesStayClosed(t *testing.T) {
	const (
		failsBeforeAuth = "fails"
		refusedBlocked  = "blocked"
		walksOutside    = "walks"
	)
	fixture := func(t *testing.T) (project, home, outside string) {
		t.Helper()
		project = readToolsProject(t)
		var err error
		if home, err = filepath.EvalSymlinks(t.TempDir()); err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		if outside, err = filepath.EvalSymlinks(t.TempDir()); err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		if filepath.Dir(project) != filepath.Dir(outside) || filepath.Dir(home) != filepath.Dir(outside) {
			t.Fatalf("project %s, home %s and outside %s must share a parent", project, home, outside)
		}
		for path, content := range map[string]string{
			filepath.Join(outside, "a.txt"):                             "OUTSIDE-A\n",
			filepath.Join(outside, "img.png"):                           string(pngBytes),
			filepath.Join(outside, "pub.txt"):                           "PUBLIC-NEEDLE\n",
			filepath.Join(outside, "secret", "key.txt"):                 "BLOCKED-NEEDLE\n",
			filepath.Join(outside, "x", "keep.txt"):                     "x\n",
			filepath.Join(home, ".ssh", "id_rsa"):                       "PRIVATE-KEY\n",
			filepath.Join(home, ".codemeld", "global", "settings.yaml"): "SETTINGS-SECRET\n",
		} {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
		}
		for link, target := range map[string]string{
			filepath.Join(project, "link.txt"): filepath.Join(outside, "a.txt"),
			filepath.Join(project, "linkdir"):  outside,
			filepath.Join(project, "link.png"): filepath.Join(outside, "img.png"),
			filepath.Join(outside, "link"):     filepath.Join(home, ".ssh", "id_rsa"),
		} {
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlink unsupported: %v", err)
			}
		}
		return project, home, outside
	}
	path := func(p string) map[string]any { return map[string]any{"path": p} }
	rows := []struct {
		name   string
		tool   string
		args   func(project, home, outside string) map[string]any
		expect string
		marker string
	}{
		{"relative climb out", filetools.ReadToolName, func(_, _, o string) map[string]any {
			return path(filepath.Join("..", filepath.Base(o), "a.txt"))
		}, failsBeforeAuth, "OUTSIDE-A"},
		{"in-project file symlink out", filetools.ReadToolName, func(_, _, _ string) map[string]any { return path("link.txt") }, failsBeforeAuth, "OUTSIDE-A"},
		{"in-project folder symlink out", filetools.ReadToolName, func(_, _, _ string) map[string]any { return path(filepath.Join("linkdir", "a.txt")) }, failsBeforeAuth, "OUTSIDE-A"},
		{"other user home", filetools.ReadToolName, func(_, _, _ string) map[string]any { return path("~nobody/x") }, failsBeforeAuth, "PRIVATE-KEY"},
		{"root key", filetools.ReadToolName, func(_, _, _ string) map[string]any { return path("~root/.ssh/id_rsa") }, failsBeforeAuth, "PRIVATE-KEY"},
		{"blocked home key", filetools.ReadToolName, func(_, _, _ string) map[string]any { return path("~/.ssh/id_rsa") }, refusedBlocked, "PRIVATE-KEY"},
		{"dot-dot into blocked folder", filetools.ReadToolName, func(_, h, o string) map[string]any {
			return path(strings.Join([]string{o, "x", "..", "..", filepath.Base(h), ".ssh", "id_rsa"}, string(filepath.Separator)))
		}, refusedBlocked, "PRIVATE-KEY"},
		{"outside symlink into blocked folder", filetools.ReadToolName, func(_, _, o string) map[string]any { return path(filepath.Join(o, "link")) }, refusedBlocked, "PRIVATE-KEY"},
		{"codemeld floor", filetools.ReadToolName, func(_, h, _ string) map[string]any {
			return path(filepath.Join(h, ".codemeld", "global", "settings.yaml"))
		}, refusedBlocked, "SETTINGS-SECRET"},
		{"grep outside folder with blocked entry", filetools.GrepToolName, func(_, _, o string) map[string]any {
			return map[string]any{"pattern": "NEEDLE", "path": o}
		}, walksOutside, "BLOCKED-NEEDLE"},
		{"in-project image symlink out", filetools.ReadImageToolName, func(_, _, _ string) map[string]any { return path("link.png") }, failsBeforeAuth, "visual input"},
	}
	for _, md := range openReadModes {
		for _, row := range rows {
			t.Run(md.name+"/"+row.name, func(t *testing.T) {
				project, home, outside := fixture(t)
				h := newOpenReadHarness(t, project, home, md.m, []permissions.BlockedEntry{
					{Path: filepath.Join(home, ".ssh"), Source: SettingsPath(home)},
					{Path: filepath.Join(outside, "secret"), Source: SettingsPath(home)},
				})

				res, derr := h.dispatcher.Dispatch(context.Background(), structuredCall("c1", row.tool, row.args(project, home, outside)))
				if derr != nil {
					t.Fatalf("Dispatch error = %v, want an in-band result", derr)
				}
				if strings.Contains(res.Content, row.marker) {
					t.Fatalf("res.Content = %q carries %q", res.Content, row.marker)
				}
				if *h.gateCalls != 0 {
					t.Fatalf("prompt gate calls = %d, want 0", *h.gateCalls)
				}
				matched := decodePermissionMatched(t, reloadStore(t, h.store))
				counts := map[string]int{}
				for _, m := range matched {
					counts[m.OutcomeSource]++
				}
				switch row.expect {
				case failsBeforeAuth:
					if len(matched) != 0 {
						t.Fatalf("res = %+v, permission_matched = %#v; want a failure before authorization", res, matched)
					}
				case refusedBlocked:
					if !res.Denied || counts["blocked_path"] != 1 || len(matched) != 1 {
						t.Fatalf("res = %+v, permission_matched = %#v; want one blocked_path refusal", res, matched)
					}
				case walksOutside:
					if res.Denied || !strings.Contains(res.Content, "PUBLIC-NEEDLE") || counts["open_read"] != 1 || len(matched) != 1 {
						t.Fatalf("res = %+v, permission_matched = %#v; want the outside walk without the blocked entry", res, matched)
					}
				}
			})
		}
	}
}

// --- authorization groups ----------------------------------------------------

// groupHarness is the production dispatch path with a recording prompt: the realized production
// registry, the production authorizer (which carries the independent-authorization seam), and the
// turn cache the scenario seeds to produce an already-resolved sibling.
type groupHarness struct {
	dispatcher *productionToolDispatcher
	registry   *tools.Registry
	store      *sessions.Store
	turnCache  *permissions.TurnCache
	project    string
	prompts    *[]tui.PromptRequest
}

func newGroupHarness(t *testing.T, decide func(tui.PromptRequest) (tui.PromptDecision, error)) groupHarness {
	t.Helper()
	return newGroupHarnessIn(t, readToolsProject(t), decide, nil)
}

func newGroupHarnessIn(t *testing.T, project string, decide func(tui.PromptRequest) (tui.PromptDecision, error), av *ActiveVCS) groupHarness {
	t.Helper()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	var prompts []tui.PromptRequest
	gate := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		prompts = append(prompts, req)
		if decide != nil {
			return decide(req)
		}
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	cache := emptyCache(t, project)
	turnCache := permissions.NewTurnCache()
	auth := newProductionAuthorizer(app, cache, turnCache, newPromptGateBuilder(gate), home, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
	reg, err := (&toolRegistryFactory{active: av}).realize(cache, func() *sessions.Store { return store }, home, project, securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{})
	return groupHarness{dispatcher: d, registry: reg, store: store, turnCache: turnCache, project: project, prompts: &prompts}
}

// assertGroupPromptedEachCall proves one authorization group reached the prompt surface as a walk of
// approval questions: one screen per want entry, each numbered in order and naming only the target it
// decides. Calls in distinct folders are distinct decisions, so they stay distinct questions.
func assertGroupPromptedEachCall(t *testing.T, shown []tui.PromptRequest, want []string) {
	t.Helper()
	if len(shown) != len(want) {
		t.Fatalf("prompt requests = %d, want one per distinct approval question (%d)", len(shown), len(want))
	}
	total := 0
	if len(want) > 1 {
		total = len(want)
	}
	for i, req := range shown {
		if len(req.BatchedStages) != 0 {
			t.Fatalf("request %d rendered pipeline-batch chrome: %#v", i, req.BatchedStages)
		}
		if total > 0 && (req.ApprovalIndex != i+1 || req.ApprovalTotal != total) {
			t.Fatalf("request %d is approval %d of %d, want %d of %d", i, req.ApprovalIndex, req.ApprovalTotal, i+1, total)
		}
		if !slices.Contains(req.Summary.Targets, want[i]) && !strings.Contains(req.Body, want[i]) {
			t.Fatalf("request %d does not name the call it decides (%q): %#v", i, want[i], req)
		}
		for j, other := range want {
			if j == i {
				continue
			}
			if slices.Contains(req.Summary.Targets, other) || strings.Contains(req.Body, other) {
				t.Fatalf("request %d names call %q, which it is not deciding", i, other)
			}
		}
	}
}

func externalReadDir(t *testing.T, name, content string) (dir, path string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return dir, path
}

// A group is assembled from authorization eligibility alone, so it spans members the scheduler
// still runs serially: the in-project read overlaps, while the image read and both external reads
// keep their synthetic serial target — and all four are approved on one prompt.
func TestProductionDispatcher_AuthGroupSpansSerialExecutionTargets(t *testing.T) {
	h := newGroupHarness(t, nil)
	_, firstExternal := externalReadDir(t, "notes.txt", "OUTSIDE ONE\n")
	_, secondExternal := externalReadDir(t, "other.txt", "OUTSIDE TWO\n")

	calls := []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "main.go"}),
		structuredCall("c2", filetools.ReadImageToolName, map[string]any{"path": "logo.png"}),
		structuredCall("c3", filetools.ReadToolName, map[string]any{"path": firstExternal}),
		structuredCall("c4", filetools.ReadToolName, map[string]any{"path": secondExternal}),
	}
	plan := h.dispatcher.Plan(calls, 4)
	assertPartitionedPlan(t, plan, calls, "exxx")

	run, err := schedulePlan(plan, 4, nil)
	if err != nil {
		t.Fatalf("Schedule: %v", err)
	}
	if len(run.ran) != len(calls) {
		t.Fatalf("executed %v, want every group member to run", run.ran)
	}
	want := []string{firstExternal, secondExternal}
	assertGroupPromptedEachCall(t, *h.prompts, want)

	// One question per distinct scope, and each call keeps its own audit decision at its own scope.
	decisions := decodeStoreEvents[events.PermissionDecision](t, reloadStore(t, h.store), events.KindPermissionDecision)
	var scopes []string
	for _, d := range decisions {
		if d.Subject != filetools.ReadToolName {
			continue
		}
		scopes = append(scopes, d.PathScope)
	}
	wantScopes := []string{filepath.Dir(firstExternal), filepath.Dir(secondExternal)}
	if !reflect.DeepEqual(scopes, wantScopes) {
		t.Fatalf("recorded decision scopes = %v, want one per approved call at its own scope %v", scopes, wantScopes)
	}
}

// A read's authorization scope is the enclosing folder, so five reads of five files in one folder are
// the same tool at the same scope with the same stored grant — one decision on the production path.
func TestProductionDispatcher_SameFolderReadsShareOneApproval(t *testing.T) {
	h := newGroupHarness(t, nil)
	dir, first := externalReadDir(t, "one.txt", "ONE\n")
	paths := []string{first}
	calls := []turn.AssembledToolCall{structuredCall("c0", filetools.ReadToolName, map[string]any{"path": first})}
	for i, name := range []string{"two.txt", "three.txt", "four.txt", "five.txt"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(strings.ToUpper(name)+"\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		paths = append(paths, path)
		calls = append(calls, structuredCall(fmt.Sprintf("c%d", i+1), filetools.ReadToolName, map[string]any{"path": path}))
	}

	run, err := schedulePlan(h.dispatcher.Plan(calls, len(calls)), len(calls), nil)
	if err != nil {
		t.Fatalf("Schedule: %v", err)
	}
	if len(run.ran) != len(calls) {
		t.Fatalf("executed %v, want every member to run on the one approval", run.ran)
	}
	if len(*h.prompts) != 1 {
		t.Fatalf("prompts shown = %d, want one — every call is the same decision", len(*h.prompts))
	}
	shown := (*h.prompts)[0]
	if shown.ApprovalIndex != 0 || shown.ApprovalTotal != 0 {
		t.Fatalf("lone question rendered an approval counter: %d of %d", shown.ApprovalIndex, shown.ApprovalTotal)
	}
	for _, path := range paths {
		if !strings.Contains(shown.Body, path) {
			t.Fatalf("the one screen hid the call reading %q\n--- body ---\n%s", path, shown.Body)
		}
	}
	decisions := decodeStoreEvents[events.PermissionDecision](t, reloadStore(t, h.store), events.KindPermissionDecision)
	reads := 0
	for _, d := range decisions {
		if d.Subject == filetools.ReadToolName && d.PathScope == dir {
			reads++
		}
	}
	if reads != len(calls) {
		t.Fatalf("recorded read decisions = %d, want one per member call (%d)", reads, len(calls))
	}
}

// The production prompt bridge blocks in a TUI call that does not watch the dispatch context, so a
// cancellation that lands while the group prompt is open is only visible once the decision returns.
func TestProductionDispatcher_CancelWhileTheGroupPromptIsOpenRunsNoMember(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newGroupHarness(t, func(tui.PromptRequest) (tui.PromptDecision, error) {
		cancel()
		return tui.PromptDecision{Option: tui.OptionAllowSession}, nil
	})
	_, first := externalReadDir(t, "one.txt", "ONE\n")
	_, second := externalReadDir(t, "two.txt", "TWO\n")

	calls := []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadToolName, map[string]any{"path": first}),
		structuredCall("c2", filetools.ReadToolName, map[string]any{"path": second}),
	}
	plan := h.dispatcher.Plan(calls, 2)
	for i, unit := range plan.Units {
		if unit.PreRun == nil {
			t.Fatalf("unit %d has no group pre-run, so nothing gates its execution", i)
		}
		if err := unit.PreRun(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("unit %d pre-run = %v, want context.Canceled so the scheduler runs no member", i, err)
		}
	}
	if len(*h.prompts) != 2 {
		t.Fatalf("prompt requests = %d, want one per distinct question on the one cancelled group", len(*h.prompts))
	}
	decisions := decodeStoreEvents[events.PermissionDecision](t, reloadStore(t, h.store), events.KindPermissionDecision)
	if len(decisions) != 0 {
		t.Fatalf("recorded decisions = %+v, want none — a cancelled group stores no decision and no grant", decisions)
	}
}

// The real *vcs.ActionTool, registered from the built-in git template, is authorized inside a group
// with two external reads while keeping its serial execution target. It does not
// appear on the prompt itself: a read-only action that is not an explicit external read auto-allows
// in every mode (internal/permissions/orchestrate.go:583), and PrepareTool raises ExternalRead only
// for a target-scoped tool (internal/dispatch/tool.go:322), which a VCS action is not. What its
// membership buys is that it does not split the group — the reads on either side of it still share
// one approval.
func TestProductionDispatcher_RealReadOnlyVCSActionSharesTheGroupAndStaysSerial(t *testing.T) {
	project := readToolsProject(t)
	seedGitRepo(t, project)
	h := newGroupHarnessIn(t, project, nil, activeBuiltinVCS(t, "git", project))
	_, firstExternal := externalReadDir(t, "notes.txt", "OUTSIDE ONE\n")
	_, secondExternal := externalReadDir(t, "other.txt", "OUTSIDE TWO\n")

	calls := []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadToolName, map[string]any{"path": firstExternal}),
		structuredCall("c2", "vcs_status", map[string]any{}),
		structuredCall("c3", filetools.ReadToolName, map[string]any{"path": secondExternal}),
	}
	// A vcs action carrying a parameter is not an admitted read-only action, so it never joins a group.
	malformed := append(slices.Clone(calls), structuredCall("c4", "vcs_status", map[string]any{"branch": "main"}))
	groups := h.dispatcher.assembleAuthGroups(malformed)
	if groups[0] == nil || groups[0] != groups[1] || groups[1] != groups[2] {
		t.Fatalf("the real vcs action split the authorization group its neighbouring reads share")
	}
	if groups[3] != nil {
		t.Fatalf("a vcs action carrying a parameter joined an authorization group")
	}

	plan := h.dispatcher.Plan(calls, 3)
	assertPartitionedPlan(t, plan, calls, "xxx")
	run, err := schedulePlan(plan, 3, nil)
	if err != nil {
		t.Fatalf("Schedule: %v", err)
	}
	if want := []string{"c1", "c2", "c3"}; !slices.Equal(run.ids(), want) {
		t.Fatalf("executed %v, want %v — the group decision precedes execution and model order still governs it", run.ids(), want)
	}
	want := []string{firstExternal, secondExternal}
	assertGroupPromptedEachCall(t, *h.prompts, want)
}

func TestProductionDispatcher_NonEligibleCallEndsTheAuthGroup(t *testing.T) {
	h := newGroupHarness(t, nil)
	_, first := externalReadDir(t, "one.txt", "ONE\n")
	_, second := externalReadDir(t, "two.txt", "TWO\n")

	calls := []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadToolName, map[string]any{"path": first}),
		bashCall("c2", "echo hi"),
		structuredCall("c3", filetools.ReadToolName, map[string]any{"path": second}),
	}
	plan := h.dispatcher.Plan(calls, 3)
	if _, err := schedulePlan(plan, 3, nil); err != nil {
		t.Fatalf("Schedule: %v", err)
	}
	// The shell call is not authorization-eligible, so the reads on either side of it cannot
	// share one approval.
	if len(*h.prompts) != 2 {
		t.Fatalf("prompts shown = %d, want one per read (the shell barrier ends the group between them)", len(*h.prompts))
	}
	for _, shown := range *h.prompts {
		if shown.ApprovalTotal != 0 {
			t.Fatalf("a lone call rendered an approval counter: %d of %d", shown.ApprovalIndex, shown.ApprovalTotal)
		}
	}
}

func TestProductionDispatcher_DeniedGroupMemberDoesNotBlockItsSiblings(t *testing.T) {
	h := newGroupHarness(t, nil)
	deniedDir, deniedPath := externalReadDir(t, "denied.txt", "DENIED\n")
	_, allowedPath := externalReadDir(t, "allowed.txt", "ALLOWED\n")
	h.turnCache.Record(permissions.MatchRequest{Kind: matchKindTool, Subject: filetools.ReadToolName, PathScope: deniedDir}, "deny")

	calls := []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadToolName, map[string]any{"path": deniedPath}),
		structuredCall("c2", filetools.ReadToolName, map[string]any{"path": allowedPath}),
	}
	if groups := h.dispatcher.assembleAuthGroups(calls); groups[0] == nil || groups[0] != groups[1] {
		t.Fatalf("calls did not share one authorization group, so the mixed outcome would not come from one approval")
	}
	plan := h.dispatcher.Plan(calls, 2)
	results := make([]turn.ToolResult, len(plan.Units))
	for i, unit := range plan.Units {
		if err := unit.PreRun(context.Background()); err != nil {
			t.Fatalf("unit %d pre-run: %v", i, err)
		}
		res, err := unit.Run(context.Background())
		if err != nil {
			t.Fatalf("unit %d run: %v", i, err)
		}
		results[i] = res
	}
	if !results[0].Denied || results[0].Content == "" {
		t.Fatalf("denied member = %+v, want its own deny envelope in band", results[0])
	}
	if strings.Contains(results[0].Content, "DENIED") {
		t.Fatalf("denied member returned file content: %q", results[0].Content)
	}
	if results[1].Denied || !strings.Contains(results[1].Content, "ALLOWED") {
		t.Fatalf("approved sibling = %+v, want it to have run", results[1])
	}
}

// The interactive bridge itself must be able to return a mixed outcome. A decision vector injected
// below the prompt cannot prove that: the allow and the deny here are made on the production group
// prompt, one per listed call, and each call carries only its own result.
func TestProductionDispatcher_GroupPromptAllowsOneCallAndDeniesTheOther(t *testing.T) {
	var deniedPath string
	h := newGroupHarness(t, func(req tui.PromptRequest) (tui.PromptDecision, error) {
		if slices.Contains(req.Summary.Targets, deniedPath) {
			return tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope("")}, nil
		}
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	})
	_, allowedPath := externalReadDir(t, "allowed.txt", "ALLOWED\n")
	_, deniedPath = externalReadDir(t, "denied.txt", "REFUSED\n")

	calls := []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadToolName, map[string]any{"path": allowedPath}),
		structuredCall("c2", filetools.ReadToolName, map[string]any{"path": deniedPath}),
	}
	if groups := h.dispatcher.assembleAuthGroups(calls); groups[0] == nil || groups[0] != groups[1] {
		t.Fatal("calls did not share one authorization group, so the mixed outcome would not come from one prompt")
	}
	plan := h.dispatcher.Plan(calls, 2)
	results := make([]turn.ToolResult, len(plan.Units))
	for i, unit := range plan.Units {
		if err := unit.PreRun(context.Background()); err != nil {
			t.Fatalf("unit %d pre-run: %v", i, err)
		}
		res, err := unit.Run(context.Background())
		if err != nil {
			t.Fatalf("unit %d run: %v", i, err)
		}
		results[i] = res
	}
	assertGroupPromptedEachCall(t, *h.prompts, []string{allowedPath, deniedPath})
	if results[0].Denied || !strings.Contains(results[0].Content, "ALLOWED") {
		t.Fatalf("allowed call = %+v, want it to have run on its own approval", results[0])
	}
	if !results[1].Denied {
		t.Fatalf("denied call = %+v, want its own deny envelope — the sibling's allow must not carry it", results[1])
	}
	if strings.Contains(results[1].Content, "REFUSED") {
		t.Fatalf("denied call returned file content: %q", results[1].Content)
	}
}

// A member that validated at plan time can lose its preparation before the group authorizes: a
// predecessor barrier runs in between and can move what its path resolves to. The dangling symlink
// stands in for that effect. Such a member is a runtime group boundary, so the eligible calls on
// either side of it are authorized separately and it keeps only its ordinary per-call path.
func TestProductionDispatcher_FailedRePreparationSplitsTheGroup(t *testing.T) {
	h := newGroupHarness(t, nil)
	_, first := externalReadDir(t, "one.txt", "ONE\n")
	_, second := externalReadDir(t, "two.txt", "TWO\n")
	middleDir, middleTarget := externalReadDir(t, "middle.txt", "MIDDLE\n")
	link := filepath.Join(middleDir, "link.txt")
	if err := os.Symlink(middleTarget, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	calls := []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadToolName, map[string]any{"path": first}),
		structuredCall("c2", filetools.ReadToolName, map[string]any{"path": link}),
		structuredCall("c3", filetools.ReadToolName, map[string]any{"path": second}),
	}
	groups := h.dispatcher.assembleAuthGroups(calls)
	if groups[0] == nil || groups[0] != groups[1] || groups[1] != groups[2] {
		t.Fatal("plan-time grouping did not admit all three calls, so a runtime split has nothing to prove")
	}
	plan := h.dispatcher.Plan(calls, 3)

	if err := os.Remove(middleTarget); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	for i, unit := range plan.Units {
		if err := unit.PreRun(context.Background()); err != nil {
			t.Fatalf("unit %d pre-run: %v", i, err)
		}
	}
	if len(*h.prompts) != 2 {
		t.Fatalf("prompt requests = %d, want one per surviving call — each side of the broken member is its own group", len(*h.prompts))
	}
	for i, shown := range *h.prompts {
		if shown.ApprovalTotal != 0 {
			t.Fatalf("prompt %d was asked as part of a walk across the member that lost its preparation", i)
		}
	}
	// It carries no group decision either, so Plan routes it to its ordinary per-call dispatch.
	if groups[1].member("c2") != nil {
		t.Fatal("the member that lost its preparation still holds a group decision")
	}
}

func TestProductionDispatcher_GroupPromptFailureRunsNothing(t *testing.T) {
	boom := errors.New("prompt transport failed")
	h := newGroupHarness(t, func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{}, boom
	})
	_, first := externalReadDir(t, "one.txt", "ONE\n")
	_, second := externalReadDir(t, "two.txt", "TWO\n")

	calls := []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadToolName, map[string]any{"path": first}),
		structuredCall("c2", filetools.ReadToolName, map[string]any{"path": second}),
	}
	plan := h.dispatcher.Plan(calls, 2)
	run, err := schedulePlan(plan, 2, nil)
	if !errors.Is(err, boom) {
		t.Fatalf("Schedule error = %v, want the prompt failure", err)
	}
	if len(run.ran) != 0 {
		t.Fatalf("executed %v, want no group member to run after a failed prompt", run.ran)
	}
}

func TestProductionDispatcher_CancelledGroupRunsNothing(t *testing.T) {
	h := newGroupHarness(t, nil)
	_, first := externalReadDir(t, "one.txt", "ONE\n")
	_, second := externalReadDir(t, "two.txt", "TWO\n")

	calls := []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadToolName, map[string]any{"path": first}),
		structuredCall("c2", filetools.ReadToolName, map[string]any{"path": second}),
	}
	plan := h.dispatcher.Plan(calls, 2)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i, unit := range plan.Units {
		if err := unit.PreRun(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("unit %d pre-run error = %v, want context.Canceled", i, err)
		}
	}
	if len(*h.prompts) != 0 {
		t.Fatalf("prompts shown = %d, want none for a cancelled group", len(*h.prompts))
	}
}

// classifiedFixture advertises exactly the metadata a case needs, so admission to a group can be
// attributed to the read-only bit or the credential classification on its own.
type classifiedFixture struct {
	name string
	meta tools.Metadata
}

func (f *classifiedFixture) Name() string              { return f.name }
func (f *classifiedFixture) SubjectKind() string       { return "tool" }
func (f *classifiedFixture) Advertise() tools.Metadata { return f.meta }
func (f *classifiedFixture) Invoke(context.Context, map[string]any) (tools.Result, error) {
	return tools.Result{}, nil
}

func TestProductionDispatcher_AuthGroupEligibilityRequiresEveryProof(t *testing.T) {
	project := readToolsProject(t)
	h := newGroupHarnessIn(t, project, nil, activeBuiltinVCS(t, "git", project))
	if err := os.WriteFile(filepath.Join(h.project, "credential-named.txt"), []byte("token=abc\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, external := externalReadDir(t, "notes.txt", "OUTSIDE\n")

	// A credential-handling read-only tool and a noncredential mutating one prove that neither
	// half of the classification can admit a call on its own.
	if err := h.registry.Register("test-credential-fixture", &classifiedFixture{name: "credentialReadFixture", meta: tools.Metadata{ReadOnly: true}}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// A credential-handling action registered from a project template under the vcs_<action>
	// spelling passes the argument validator, so only its metadata keeps it out.
	if err := h.registry.Register("test-credential-fixture", &classifiedFixture{name: "vcs_credential_read", meta: tools.Metadata{ReadOnly: true}}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := h.registry.Register("test-credential-fixture", &classifiedFixture{name: "noncredentialMutatingFixture", meta: tools.Metadata{Noncredential: true}}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	cases := []struct {
		name string
		call turn.AssembledToolCall
		want bool
	}{
		{"ordinary read of a credential-named file", structuredCall("c", filetools.ReadToolName, map[string]any{"path": "credential-named.txt"}), true},
		{"explicit external read", structuredCall("c", filetools.ReadToolName, map[string]any{"path": external}), true},
		{"image read", structuredCall("c", filetools.ReadImageToolName, map[string]any{"path": "logo.png"}), true},
		{"read-only vcs action", structuredCall("c", "vcs_status", map[string]any{}), true},
		{"credential-handling operation", structuredCall("c", "credentialReadFixture", map[string]any{}), false},
		{"credential-handling read-only vcs action", structuredCall("c", "vcs_credential_read", map[string]any{}), false},
		{"noncredential mutating operation", structuredCall("c", "noncredentialMutatingFixture", map[string]any{}), false},
		{"unknown tool", structuredCall("c", "read_file", map[string]any{"path": "main.go"}), false},
		{"shell", bashCall("c", "echo hi"), false},
		{"write tool", structuredCall("c", filetools.EditToolName, map[string]any{"path": "main.go"}), false},
		{"web search", structuredCall("c", webSearchToolName, map[string]any{"query": "x"}), false},
		{"web fetch", structuredCall("c", webFetchToolName, map[string]any{"url": "https://example.com"}), false},
		{"malformed json arguments", turn.AssembledToolCall{ID: "c", Name: filetools.ReadToolName, Arguments: `{"path":`}, false},
		{"read with limit 0", structuredCall("c", filetools.ReadToolName, map[string]any{"path": "main.go", "limit": 0}), false},
		{"malformed glob pattern", structuredCall("c", filetools.GlobToolName, map[string]any{"pattern": "[a-"}), false},
		{"invalid grep expression", structuredCall("c", filetools.GrepToolName, map[string]any{"pattern": "("}), false},
		{"unknown read_image argument", structuredCall("c", filetools.ReadImageToolName, map[string]any{"path": "logo.png", "limit": 1}), false},
		{"blank read_image path", structuredCall("c", filetools.ReadImageToolName, map[string]any{"path": " "}), false},
		{"vcs action carrying a parameter", structuredCall("c", "vcs_status", map[string]any{"branch": "main"}), false},
		{"missing target", structuredCall("c", filetools.ReadToolName, map[string]any{"path": "nope.txt"}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			groups := h.dispatcher.assembleAuthGroups([]turn.AssembledToolCall{tc.call})
			if got := groups[0] != nil; got != tc.want {
				t.Fatalf("grouped = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRealizeRegistry_OnlyProductClassifiedReadOperationsAdvertiseNoncredential(t *testing.T) {
	project := readToolsProject(t)
	home := t.TempDir()
	store := mkStore(t)
	cache := emptyCache(t, project)
	reg, err := (&toolRegistryFactory{active: activeBuiltinVCS(t, "git", project)}).realize(cache, func() *sessions.Store { return store }, home, project, securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize: %v", err)
	}
	classification := func(name string) tools.Metadata {
		tool, ok := reg.Lookup(name)
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		return tool.Advertise()
	}
	for _, name := range []string{
		filetools.ReadToolName, filetools.GlobToolName, filetools.GrepToolName,
		filetools.ListToolName, filetools.TreeToolName, filetools.FileCountToolName,
		filetools.ReadImageToolName, "vcs_status", "vcs_diff", "vcs_log",
	} {
		if !classification(name).Noncredential {
			t.Errorf("%s does not advertise non-credential-handling, so it can never join an authorization group", name)
		}
	}
	for _, name := range []string{
		filetools.EditToolName, filetools.CreateToolName, filetools.DeleteToolName,
		filetools.MkdirToolName, filetools.MoveToolName, "vcs_commit", "vcs_add",
	} {
		if classification(name).Noncredential {
			t.Errorf("mutating tool %s advertises non-credential-handling", name)
		}
	}
}

// swappingImageTool captures its target, then replaces the file at the same path. A dispatcher that
// captured the image a second time would report bytes that no longer match the result it returned.
type swappingImageTool struct {
	project     string
	replacement []byte
}

func (t *swappingImageTool) Name() string        { return filetools.ReadImageToolName }
func (t *swappingImageTool) SubjectKind() string { return "tool" }
func (t *swappingImageTool) Advertise() tools.Metadata {
	return tools.Metadata{ReadOnly: true}
}

func (t *swappingImageTool) ResolveTarget(args map[string]any) (string, string, error) {
	path, _ := args["path"].(string)
	target := filepath.Join(t.project, path)
	return target, filepath.Dir(target), nil
}

func (t *swappingImageTool) Invoke(ctx context.Context, args map[string]any) (tools.Result, error) {
	target, _, err := t.ResolveTarget(args)
	if err != nil {
		return tools.Result{}, err
	}
	return t.InvokeWithResolvedTarget(ctx, args, target)
}

func (t *swappingImageTool) InvokeWithResolvedTarget(_ context.Context, _ map[string]any, target string) (tools.Result, error) {
	captured, err := os.ReadFile(target)
	if err != nil {
		return tools.Result{}, err
	}
	if err := os.WriteFile(target, t.replacement, 0o644); err != nil {
		return tools.Result{}, err
	}
	return tools.Result{
		Stdout:            []byte(fmt.Sprintf("read logo.png (image/png, %d bytes)", len(captured))),
		ModelContextImage: "data:image/png;base64," + base64.StdEncoding.EncodeToString(captured),
	}, nil
}

func TestProductionDispatcher_ImageContextComesFromTheAuthorizedCapture(t *testing.T) {
	h := newGroupHarness(t, nil)
	replacement := append(append([]byte{}, pngBytes...), []byte("REPLACED")...)
	if err := h.registry.Register("test-swapping-image", &swappingImageTool{project: h.project, replacement: replacement}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	res, err := h.dispatcher.Dispatch(context.Background(), structuredCall("c1", filetools.ReadImageToolName, map[string]any{"path": "logo.png"}))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	encoded, ok := strings.CutPrefix(res.ModelContextImage, "data:image/png;base64,")
	if !ok {
		t.Fatalf("ModelContextImage = %q, want a png data URI", res.ModelContextImage)
	}
	decoded, derr := base64.StdEncoding.DecodeString(encoded)
	if derr != nil {
		t.Fatalf("data URI payload = %v, want valid base64", derr)
	}
	if !bytes.Equal(decoded, pngBytes) {
		t.Fatalf("model context carried %d bytes, want the %d bytes the tool captured before the path was replaced", len(decoded), len(pngBytes))
	}
	if !strings.Contains(res.Content, fmt.Sprintf("%d bytes", len(pngBytes))) {
		t.Fatalf("result notice = %q, want it to describe the same capture", res.Content)
	}
	onDisk, rerr := os.ReadFile(filepath.Join(h.project, "logo.png"))
	if rerr != nil {
		t.Fatalf("ReadFile: %v", rerr)
	}
	if bytes.Equal(onDisk, pngBytes) {
		t.Fatal("the fixture did not replace the image, so a second read could not be detected")
	}
}

func TestHeadlessAuthorization_FormsNoAuthGroups(t *testing.T) {
	var authorizer any = &headlessAuthorizer{}
	if _, ok := authorizer.(dispatch.IndependentAuthorizer); ok {
		t.Fatal("the headless authorizer exposes the independent-group seam; headless must stay per-call sequential")
	}

	project := readToolsProject(t)
	home := t.TempDir()
	store := mkStore(t)
	cache := emptyCache(t, project)
	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, func() *sessions.Store { return store }, home, project, securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize: %v", err)
	}
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, &recordingAuthorizer{}, home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{})

	calls := sixReadCalls()
	for i, group := range d.assembleAuthGroups(calls) {
		if group != nil {
			t.Fatalf("call %d joined an authorization group under an authorizer with no independent seam", i)
		}
	}
	for i, unit := range d.Plan(calls, 6).Units {
		if unit.PreRun != nil {
			t.Fatalf("unit %d gained a group pre-run without an independent authorizer", i)
		}
	}
}

func TestProductionDispatcher_OnlyReadImageReachesTheModelContext(t *testing.T) {
	h := newGroupHarness(t, nil)
	// A tool other than read_image cannot put pixels in front of the model, however it fills its
	// own result.
	smuggler := renamedImageTool{swappingImageTool: &swappingImageTool{project: h.project, replacement: pngBytes}}
	if err := h.registry.Register("test-image-smuggler", smuggler); err != nil {
		t.Fatalf("Register: %v", err)
	}
	res, err := h.dispatcher.Dispatch(context.Background(), structuredCall("c1", "smuggler", map[string]any{"path": "logo.png"}))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if res.ModelContextImage != "" {
		t.Fatalf("ModelContextImage = %q, want none for a tool that is not read_image", res.ModelContextImage)
	}
}

type renamedImageTool struct{ *swappingImageTool }

func (renamedImageTool) Name() string { return "smuggler" }

// --- delegate registration ---------------------------------------------------

func generalAgentFixture(t *testing.T) (*config.Cache, string, string, *model.ActiveState, *mode.ActiveState) {
	t.Helper()
	project := readToolsProject(t)
	home := t.TempDir()
	globalSettings := SettingsPath(home)
	// The two models carry different effort menus, so a snapshot that kept the launch
	// model's catalog lookup cannot pass the post-change assertion.
	seedOpenAIDiscoveredModels(t, globalSettings, []config.DiscoveredModel{
		discoveredWithEfforts("gpt-5.5", "medium", "high"),
		discoveredWithEfforts("gpt-6", "low", "xhigh"),
	})
	cache, err := config.NewCache(headlessProviderConfig(), project, []string{globalSettings})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	active := model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: "high"}, model.SourceProject)
	return cache, home, project, active, mode.NewActiveState(mode.Build, mode.SourceDefault)
}

func discoveredWithEfforts(id string, efforts ...string) config.DiscoveredModel {
	options := make([]any, len(efforts))
	for i, e := range efforts {
		options[i] = e
	}
	return config.DiscoveredModel{ID: id, Capabilities: map[string]any{
		"supportsReasoningEffort": true,
		"reasoningEffortOptions":  options,
	}}
}

// publishParentTurn stands in for one dispatch: it publishes the run-scoped model and mode as
// they read right now, under a prompt naming both, so a snapshot frozen by this publication is
// distinguishable from one frozen by any other.
func publishParentTurn(h *parentTurnHolder, active *model.ActiveState, modeActive *mode.ActiveState) {
	sel, source, _ := active.Current()
	m, _ := modeActive.Current()
	h.publish(sel, source, string(m), "prompt for "+string(m)+"/"+sel.ID)
}

// generalAgentTestBinding binds a holder that has already published the states as they read now,
// so every test that only needs a resolvable parent has one.
func generalAgentTestBinding(active *model.ActiveState, modeActive *mode.ActiveState) generalAgentBinding {
	parent := &parentTurnHolder{}
	publishParentTurn(parent, active, modeActive)
	return generalAgentBinding{parent: parent, notices: &recordingNotices{}}
}

func generalAgentRegistry(t *testing.T, cache *config.Cache, home, project string, active *model.ActiveState, modeActive *mode.ActiveState) *tools.Registry {
	t.Helper()
	store := mkStore(t)
	reg, err := realizeToolRegistry(&toolRegistryFactory{active: nil}, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil),
		generalAgentTestBinding(active, modeActive))
	if err != nil {
		t.Fatalf("realizeToolRegistry: %v", err)
	}
	return reg
}

// TestRealizeToolRegistry_GeneralAgentNeedsItsParentBinding pins that delegate is registered only
// where a parent exists to inherit, and is advertised as mutating yet still offered in Plan.
func TestRealizeToolRegistry_GeneralAgentNeedsItsParentBinding(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)

	reg := generalAgentRegistry(t, cache, home, project, active, modeActive)
	tool, ok := reg.Lookup(subagenttool.ToolName)
	if !ok {
		t.Fatal("a bound registry does not carry the delegate tool")
	}
	if meta := tool.Advertise(); meta.ReadOnly || meta.Noncredential {
		t.Fatalf("delegate metadata = %+v, want neither read-only nor noncredential", meta)
	}

	bare, err := realizeToolRegistry(&toolRegistryFactory{active: nil}, cache, func() *sessions.Store { return mkStore(t) }, home, project, securitystate.Policy{})
	if err != nil {
		t.Fatalf("realizeToolRegistry: %v", err)
	}
	if _, ok := bare.Lookup(subagenttool.ToolName); ok {
		t.Fatal("an unbound registry registered delegate, want none")
	}

	if got := toolNames(advertisedTools(reg, mode.Plan)); !slices.Contains(got, subagenttool.ToolName) {
		t.Fatalf("Plan advertised %v, want general_agent included for its read-only form", got)
	}
	if got := toolNames(advertisedTools(reg, mode.Build)); !slices.Contains(got, subagenttool.ToolName) {
		t.Fatalf("Build advertised %v, want general_agent included", got)
	}
}

// productVettedGitTemplate is the embedded built-in git template narrowed to the three actions
// these tests exercise. The argv has to stay the product's own: an action that keeps the built-in
// read-only classification while running argv of its own is refused by the protected-state guard
// before authorization, so a controlled result comes from the command runner instead.
func productVettedGitTemplate(t *testing.T) *vcs.Template {
	t.Helper()
	builtins, err := vcs.LoadBuiltinTemplates()
	if err != nil {
		t.Fatalf("LoadBuiltinTemplates: %v", err)
	}
	git, ok := builtins["git"]
	if !ok {
		t.Fatal("the embedded built-in templates carry no git entry")
	}
	actions := make(map[string]vcs.ActionSpec, 3)
	for _, name := range []string{"status", "diff", "commit"} {
		action, ok := git.Actions[name]
		if !ok {
			t.Fatalf("the built-in git template has no %q action", name)
		}
		actions[name] = action
	}
	return &vcs.Template{Name: git.Name, Source: git.Source, Actions: actions}
}

// stubVCSActionRunner points the registered vcs_<action> tools at a runner returning fact on
// stdout, so an admitted action produces a child-only observable without launching git.
func stubVCSActionRunner(t *testing.T, fact string) {
	t.Helper()
	prev := newVCSActionRunner
	newVCSActionRunner = func() cmdrunner.Runner {
		return &fakeDispatchRunner{result: cmdrunner.RunResult{Stdout: []byte(fact)}}
	}
	t.Cleanup(func() { newVCSActionRunner = prev })
}

func generalAgentVCSRegistry(t *testing.T, cache *config.Cache, home, project string, active *model.ActiveState, modeActive *mode.ActiveState, store *sessions.Store, repoRoot, fact string) *tools.Registry {
	t.Helper()
	stubVCSActionRunner(t, fact)
	factory := &toolRegistryFactory{active: &ActiveVCS{Template: productVettedGitTemplate(t), RepoRoot: repoRoot}}
	reg, err := realizeToolRegistry(factory, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil),
		generalAgentTestBinding(active, modeActive))
	if err != nil {
		t.Fatalf("realizeToolRegistry: %v", err)
	}
	return reg
}

func registeredMetadata(t *testing.T, registered []tools.Tool, name string) tools.Metadata {
	t.Helper()
	for _, tool := range registered {
		if tool.Name() == name {
			return tool.Advertise()
		}
	}
	t.Fatalf("%s is absent from the snapshot's realized registry", name)
	return tools.Metadata{}
}

// TestGeneralAgentBinding_SnapshotCarriesTheRealizedRegistry proves the production binding hands the
// child selection the live registry entries and their realized metadata — the only thing that can
// separate a read-only VCS action from a mutating one — rather than provider definitions.
func TestGeneralAgentBinding_SnapshotCarriesTheRealizedRegistry(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	store := mkStore(t)
	reg := generalAgentVCSRegistry(t, cache, home, project, active, modeActive, store, project, "irrelevant")
	deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))

	snap, ok := deps.Snapshot(t.Context())
	if !ok {
		t.Fatal("Snapshot reported no resolvable parent, want the seeded openai selection")
	}
	var got []string
	for _, tool := range snap.Registered {
		got = append(got, tool.Name())
	}
	var want []string
	for _, tool := range reg.List() {
		want = append(want, tool.Name())
	}
	if !slices.Equal(got, want) {
		t.Fatalf("snapshot registry = %v, want the live registry %v", got, want)
	}
	if meta := registeredMetadata(t, snap.Registered, "vcs_status"); !meta.ReadOnly || !meta.Noncredential {
		t.Fatalf("vcs_status metadata = %+v, want both flags set on a product-vetted read-only action", meta)
	}
	if meta := registeredMetadata(t, snap.Registered, "vcs_commit"); meta.ReadOnly || meta.Noncredential {
		t.Fatalf("vcs_commit metadata = %+v, want neither flag set on a mutating action", meta)
	}
}

// TestGeneralAgentBinding_ChildVCSCallKeepsInheritedModeAndResolvedCwd runs child VCS calls on the
// dispatcher the production binding builds. The read-only action is authorized on the shared path
// with the inherited mode and its resolved repo cwd; the mutating action of the same template
// reaches that same path and is refused there, because the child has no approver of its own and
// Build never auto-allows a mutation.
func TestGeneralAgentBinding_ChildVCSCallKeepsInheritedModeAndResolvedCwd(t *testing.T) {
	const fact = "CHILD-VCS-FACT-4711"
	for _, tc := range []struct {
		name    string
		subject string
		args    map[string]any
		allowed bool
	}{
		{"read-only action", "vcs_status", map[string]any{}, true},
		{"mutating action", "vcs_commit", map[string]any{"message": "take the repo"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, home, project, active, modeActive := generalAgentFixture(t)
			store := mkStore(t)
			repoRoot := project
			reg := generalAgentVCSRegistry(t, cache, home, project, active, modeActive, store, repoRoot, fact)
			deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))

			d := deps.NewDispatcher(permissions.ModeContext{
				Mode:          string(mode.Build),
				DeclaredWrite: map[string]bool{filepath.Join(project, "out.txt"): true},
			})
			res, err := d.Dispatch(context.Background(), structuredCall("c1", tc.subject, tc.args))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}

			reloaded := reloadStore(t, store)
			execs := decodeStoreEvents[events.ToolExecStart](t, reloaded, events.KindToolExecStart)
			if !tc.allowed {
				if !res.Denied {
					t.Fatalf("result = %+v, want a denial — a mutation has no mode auto-allow and the child has no approver", res)
				}
				if len(execs) != 0 {
					t.Fatalf("tool_exec_start events = %+v, want none — a denied action must not run", execs)
				}
				decided := decodeStoreEvents[events.PermissionDecision](t, reloaded, events.KindPermissionDecision)
				if len(decided) != 1 || decided[0].Subject != tc.subject || decided[0].PathScope != repoRoot {
					t.Fatalf("permission_decision events = %+v, want one denial for %s scoped to %s", decided, tc.subject, repoRoot)
				}
				return
			}
			matched := decodePermissionMatched(t, reloaded)
			if len(matched) != 1 {
				t.Fatalf("permission_matched events = %+v, want exactly one for the child's VCS call", matched)
			}
			if matched[0].Subject != tc.subject || matched[0].PathScope != repoRoot {
				t.Fatalf("permission_matched = %#v, want subject %s scoped to the resolved repo root %s", matched[0], tc.subject, repoRoot)
			}
			if matched[0].Outcome != "once" || matched[0].OutcomeSource != "mode_auto" {
				t.Fatalf("permission_matched = %#v, want the inherited mode to auto-allow the read-only action with no prompt", matched[0])
			}
			if res.Denied || !strings.Contains(res.Content, fact) {
				t.Fatalf("result = %+v, want the action's own output %q", res, fact)
			}
			if len(execs) != 1 || execs[0].Subject != tc.subject || execs[0].PathScope != repoRoot {
				t.Fatalf("tool_exec_start events = %+v, want one %s execution in the resolved repo root", execs, tc.subject)
			}
		})
	}
}

// TestGeneralAgentBinding_ChildVCSActionCarriesItsInvocationID covers the one admitted tool whose
// tool_exec_* records are written by the shared registry's own event appender rather than by the
// child dispatcher: the appender is bound once, before any child exists, so only the call can carry
// the attribution.
func TestGeneralAgentBinding_ChildVCSActionCarriesItsInvocationID(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	store := mkStore(t)
	reg := generalAgentVCSRegistry(t, cache, home, project, active, modeActive, store, project, "CHILD-VCS-FACT-8123")
	deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))

	first, second := ids.NewV7(), ids.NewV7()
	for _, child := range []string{first, second} {
		d := deps.NewDispatcher(permissions.ModeContext{
			Mode:              string(mode.Build),
			ChildAgent:        true,
			ChildInvocationID: child,
		})
		res, err := d.Dispatch(context.Background(), structuredCall("c1", "vcs_status", map[string]any{}))
		if err != nil {
			t.Fatalf("child Dispatch error = %v, want nil", err)
		}
		if res.Denied {
			t.Fatalf("child result = %+v, want the inherited mode to admit the read-only action", res)
		}
	}
	parent := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()},
		home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(),
		mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
	if res, err := parent.Dispatch(context.Background(), structuredCall("c1", "vcs_status", map[string]any{})); err != nil || res.Denied {
		t.Fatalf("parent Dispatch = %+v, err = %v, want the same action admitted", res, err)
	}

	reloaded := reloadStore(t, store)
	starts := decodeStoreEvents[events.ToolExecStart](t, reloaded, events.KindToolExecStart)
	ends := decodeStoreEvents[events.ToolExecEnd](t, reloaded, events.KindToolExecEnd)
	if len(starts) != 3 || len(ends) != 3 {
		t.Fatalf("tool_exec events = %d start/%d end, want 3/3", len(starts), len(ends))
	}
	want := []string{first, second, ""}
	for i, id := range want {
		if starts[i].Subject != "vcs_status" || ends[i].Subject != "vcs_status" {
			t.Fatalf("tool_exec %d subject = %q/%q, want vcs_status", i, starts[i].Subject, ends[i].Subject)
		}
		if starts[i].ChildInvocationID != id {
			t.Errorf("tool_exec_start %d child_invocation_id = %q, want %q", i, starts[i].ChildInvocationID, id)
		}
		if ends[i].ChildInvocationID != id {
			t.Errorf("tool_exec_end %d child_invocation_id = %q, want %q", i, ends[i].ChildInvocationID, id)
		}
	}
	if starts[0].ChildInvocationID == starts[1].ChildInvocationID {
		t.Fatal("two disjoint children shared one child_invocation_id, so their VCS records are indistinguishable")
	}
}

// TestGeneralAgentBinding_ChildStructuredReadCarriesItsInvocationID covers the read tools a child is
// permitted: they are recorded as structured_read_* rather than tool_exec_*, so this is the only
// place their attribution can live.
func TestGeneralAgentBinding_ChildStructuredReadCarriesItsInvocationID(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	store := mkStore(t)
	reg := generalAgentRegistry(t, cache, home, project, active, modeActive)
	deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))

	runRead := func(d turn.ToolDispatcher) {
		t.Helper()
		calls := []turn.AssembledToolCall{structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "main.go"})}
		plan := d.Plan(calls, 1)
		if _, err := plan.Units[0].Run(context.Background()); err != nil {
			t.Fatalf("structured read error = %v, want nil", err)
		}
	}

	first, second := ids.NewV7(), ids.NewV7()
	for _, child := range []string{first, second} {
		runRead(deps.NewDispatcher(permissions.ModeContext{
			Mode:              string(mode.Build),
			ChildAgent:        true,
			ChildInvocationID: child,
		}))
	}
	runRead(newProductionToolDispatcher(reg, &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()},
		home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(),
		mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil)))

	reloaded := reloadStore(t, store)
	starts := decodeStoreEvents[events.StructuredReadStart](t, reloaded, events.KindStructuredReadStart)
	ends := decodeStoreEvents[events.StructuredReadEnd](t, reloaded, events.KindStructuredReadEnd)
	if len(starts) != 3 || len(ends) != 3 {
		t.Fatalf("structured_read events = %d start/%d end, want 3/3", len(starts), len(ends))
	}
	for i, id := range []string{first, second, ""} {
		if starts[i].ChildInvocationID != id {
			t.Errorf("structured_read_start %d child_invocation_id = %q, want %q", i, starts[i].ChildInvocationID, id)
		}
		if ends[i].ChildInvocationID != id {
			t.Errorf("structured_read_end %d child_invocation_id = %q, want %q", i, ends[i].ChildInvocationID, id)
		}
	}
	if starts[0].ChildInvocationID == starts[1].ChildInvocationID {
		t.Fatal("two disjoint children shared one child_invocation_id, so their read records are indistinguishable")
	}
}

// TestGeneralAgentBinding_ChildStructuredReadRefusalCarriesItsInvocationID covers the planning-time
// refusal record, which is child activity the parent's own refusals must stay distinguishable from.
func TestGeneralAgentBinding_ChildStructuredReadRefusalCarriesItsInvocationID(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	store := mkStore(t)
	reg := generalAgentRegistry(t, cache, home, project, active, modeActive)
	deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))

	child := ids.NewV7()
	outOfProject := filepath.Join(t.TempDir(), "elsewhere.go")
	calls := []turn.AssembledToolCall{structuredCall("c1", filetools.ReadToolName, map[string]any{"path": outOfProject})}
	deps.NewDispatcher(permissions.ModeContext{
		Mode:              string(mode.Build),
		ChildAgent:        true,
		ChildInvocationID: child,
	}).Plan(calls, 1)

	refusals := decodeStoreEvents[events.StructuredReadRefused](t, reloadStore(t, store), events.KindStructuredReadRefused)
	if len(refusals) != 1 {
		t.Fatalf("structured_read_refused events = %+v, want exactly one", refusals)
	}
	if refusals[0].ChildInvocationID != child {
		t.Errorf("structured_read_refused child_invocation_id = %q, want %q", refusals[0].ChildInvocationID, child)
	}
}

// TestProductionDispatcher_ReadOnlyVCSIsAlwaysASerialBarrier proves an admitted read-only VCS
// action stays outside the concurrent project-confined read segment and fences the reads around it.
func TestProductionDispatcher_ReadOnlyVCSIsAlwaysASerialBarrier(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	store := mkStore(t)
	reg := generalAgentVCSRegistry(t, cache, home, project, active, modeActive, store, project, "fact")
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()},
		home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{})

	calls := []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "main.go"}),
		structuredCall("c2", "vcs_status", map[string]any{}),
		structuredCall("c3", filetools.ReadToolName, map[string]any{"path": "main.go"}),
	}
	assertPartitionedPlan(t, d.Plan(calls, 3), calls, "exe")
}

// --- delegate scheduling -----------------------------------------------------

// generalAgentProbe stands in for the parent a child inherits and hands back no dispatcher, so a
// scheduled delegate reaches the child-start boundary carrying its ceiling and stops there without a
// provider round.
type generalAgentProbe struct {
	mu       sync.Mutex
	starts   int
	declared []map[string]bool
}

func (p *generalAgentProbe) snapshot(context.Context) (subagenttool.Snapshot, bool) {
	p.mu.Lock()
	p.starts++
	p.mu.Unlock()
	return subagenttool.Snapshot{Mode: string(mode.Build)}, true
}

func (p *generalAgentProbe) newDispatcher(modeCtx permissions.ModeContext) turn.ToolDispatcher {
	p.mu.Lock()
	p.declared = append(p.declared, modeCtx.DeclaredWrite)
	p.mu.Unlock()
	return nil
}

func (p *generalAgentProbe) started() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.starts
}

func (p *generalAgentProbe) ceilings() []map[string]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.declared)
}

func generalAgentProbeDispatcher(t *testing.T) (*productionToolDispatcher, *generalAgentProbe, string) {
	t.Helper()
	project := readToolsProject(t)
	home := t.TempDir()
	cache := emptyCache(t, project)
	store := mkStore(t)
	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, func() *sessions.Store { return store }, home, project, securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}
	probe := &generalAgentProbe{}
	tool := subagenttool.New(subagenttool.Deps{
		Home:          home,
		LaunchDir:     project,
		ProjectRoot:   project,
		Snapshot:      probe.snapshot,
		NewDispatcher: probe.newDispatcher,
		Store:         func() *sessions.Store { return store },
	})
	if err := reg.Register(tools.BuiltinSource, tool); err != nil {
		t.Fatalf("Register general_agent: %v", err)
	}
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()},
		home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{})
	return d, probe, project
}

func plannedGeneralAgentCall(id string, files ...string) turn.AssembledToolCall {
	list := make([]any, len(files))
	for i, f := range files {
		list[i] = f
	}
	return structuredCall(id, subagenttool.ToolName, map[string]any{"instructions": "do it", "files": list})
}

const generalAgentHold = 30 * time.Millisecond

func TestProductionDispatcher_GeneralAgentIsFencedFromEveryReadSegment(t *testing.T) {
	d, probe, project := generalAgentProbeDispatcher(t)

	calls := []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "main.go"}),
		plannedGeneralAgentCall("c2", "out.txt"),
		structuredCall("c3", filetools.ReadToolName, map[string]any{"path": "main.go"}),
	}
	plan := d.Plan(calls, 3)
	assertPartitionedPlan(t, plan, calls, "ede")
	if want := []string{filepath.Join(project, "out.txt")}; !slices.Equal(plan.Units[1].Targets, want) {
		t.Fatalf("delegate targets = %v, want the canonical declared leaf %v", plan.Units[1].Targets, want)
	}

	run, err := schedulePlanHeld(plan, 3, nil, generalAgentHold)
	if err != nil {
		t.Fatalf("Schedule: %v", err)
	}
	if run.overlapped("c1", "c2") || run.overlapped("c2", "c3") {
		t.Fatalf("a delegate overlapped an adjacent read segment; execution order %v", run.ids())
	}
	if probe.started() != 1 {
		t.Fatalf("children started = %d, want 1", probe.started())
	}
}

func TestProductionDispatcher_DisjointGeneralAgentsOverlapUnderTheConfiguredCap(t *testing.T) {
	for _, tc := range []struct {
		name        string
		concurrency int
		wantOverlap bool
	}{
		{"cap 2 overlaps", 2, true},
		{"cap 1 serializes", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, probe, _ := generalAgentProbeDispatcher(t)
			calls := []turn.AssembledToolCall{plannedGeneralAgentCall("c1", "a.txt"), plannedGeneralAgentCall("c2", "b.txt")}
			plan := d.Plan(calls, tc.concurrency)
			assertPartitionedPlan(t, plan, calls, "dd")

			run, err := schedulePlanHeld(plan, tc.concurrency, nil, generalAgentHold)
			if err != nil {
				t.Fatalf("Schedule: %v", err)
			}
			if got := run.overlapped("c1", "c2"); got != tc.wantOverlap {
				t.Fatalf("delegates overlapped = %v, want %v at concurrency %d", got, tc.wantOverlap, tc.concurrency)
			}
			if probe.started() != 2 {
				t.Fatalf("children started = %d, want 2", probe.started())
			}
		})
	}
}

func TestProductionDispatcher_ConflictingGeneralAgentsRunInModelOrder(t *testing.T) {
	for _, tc := range []struct{ name, first, second string }{
		{"equal leaves", "notes.txt", "notes.txt"},
		{"ancestor and descendant", "dir", "dir/notes.txt"},
		{"casing variants of one entry", "Notes.txt", "notes.TXT"},
		{"leaf-disjoint creates sharing a missing parent", "shared/a.txt", "shared/b.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, probe, _ := generalAgentProbeDispatcher(t)
			calls := []turn.AssembledToolCall{plannedGeneralAgentCall("c1", tc.first), plannedGeneralAgentCall("c2", tc.second)}
			plan := d.Plan(calls, 2)
			assertPartitionedPlan(t, plan, calls, "dd")

			run, err := schedulePlanHeld(plan, 2, nil, generalAgentHold)
			if err != nil {
				t.Fatalf("Schedule: %v", err)
			}
			if run.overlapped("c1", "c2") {
				t.Fatalf("children declaring %q and %q overlapped", tc.first, tc.second)
			}
			if want := []string{"c1", "c2"}; !slices.Equal(run.ids(), want) {
				t.Fatalf("execution order = %v, want the model-call order %v", run.ids(), want)
			}
			if probe.started() != 2 {
				t.Fatalf("children started = %d, want 2", probe.started())
			}
		})
	}
}

// bash is included because the declared ceiling bounds file tools, not the shell, so ordering a
// delegate against it cannot come from comparing paths.
func TestProductionDispatcher_GeneralAgentIsOrderedAgainstAdjacentExcludedWork(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sibling turn.AssembledToolCall
	}{
		{"structured write", structuredCall("c2", filetools.CreateToolName, map[string]any{"path": "written.txt", "content": "x"})},
		{"bash", bashCall("c2", "echo hi")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, _ := generalAgentProbeDispatcher(t)
			calls := []turn.AssembledToolCall{plannedGeneralAgentCall("c1", "declared.txt"), tc.sibling, plannedGeneralAgentCall("c3", "other.txt")}
			plan := d.Plan(calls, 3)
			assertPartitionedPlan(t, plan, calls, "dxd")

			run, err := schedulePlanHeld(plan, 3, nil, generalAgentHold)
			if err != nil {
				t.Fatalf("Schedule: %v", err)
			}
			if run.overlapped("c1", "c2") || run.overlapped("c2", "c3") {
				t.Fatalf("a delegate overlapped the adjacent excluded call; execution order %v", run.ids())
			}
			if want := []string{"c1", "c2", "c3"}; !slices.Equal(run.ids(), want) {
				t.Fatalf("execution order = %v, want %v", run.ids(), want)
			}
		})
	}
}

func TestProductionDispatcher_BarriersFenceGeneralAgentsWithoutSerializingThem(t *testing.T) {
	d, _, _ := generalAgentProbeDispatcher(t)
	calls := []turn.AssembledToolCall{
		bashCall("c1", "echo before"),
		plannedGeneralAgentCall("c2", "a.txt"),
		plannedGeneralAgentCall("c3", "b.txt"),
		bashCall("c4", "echo after"),
	}
	plan := d.Plan(calls, 4)
	assertPartitionedPlan(t, plan, calls, "xddx")

	run, err := schedulePlanHeld(plan, 4, nil, generalAgentHold)
	if err != nil {
		t.Fatalf("Schedule: %v", err)
	}
	if !run.overlapped("c2", "c3") {
		t.Fatalf("disjoint delegates between two barriers did not overlap; order %v", run.ids())
	}
	for _, barrier := range []string{"c1", "c4"} {
		for _, child := range []string{"c2", "c3"} {
			if run.overlapped(barrier, child) {
				t.Fatalf("delegate %s overlapped the barrier %s", child, barrier)
			}
		}
	}
}

func TestProductionDispatcher_ReadsFenceGeneralAgentsWithoutSerializingThem(t *testing.T) {
	d, probe, _ := generalAgentProbeDispatcher(t)
	calls := []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "main.go"}),
		structuredCall("c2", filetools.ListToolName, map[string]any{"path": "."}),
		plannedGeneralAgentCall("c3", "a.txt"),
		plannedGeneralAgentCall("c4", "b.txt"),
	}
	plan := d.Plan(calls, 4)
	assertPartitionedPlan(t, plan, calls, "eedd")

	run, err := schedulePlanHeld(plan, 4, nil, generalAgentHold)
	if err != nil {
		t.Fatalf("Schedule: %v", err)
	}
	for _, read := range []string{"c1", "c2"} {
		for _, child := range []string{"c3", "c4"} {
			if run.overlapped(read, child) {
				t.Fatalf("delegate %s overlapped the read %s before it", child, read)
			}
		}
	}
	if !run.overlapped("c3", "c4") {
		t.Fatalf("disjoint delegates did not overlap after the read segment; order %v", run.ids())
	}
	if probe.started() != 2 {
		t.Fatalf("children started = %d, want 2", probe.started())
	}
}

// ContinueOnError lets a failed read satisfy the dependency, so the delegate's own pre-run has to
// consult the recorded failure before it authorizes or starts anything.
func TestProductionDispatcher_FailedReadStartsNoGeneralAgent(t *testing.T) {
	for _, tc := range []struct {
		name          string
		reads         []string
		fails         string
		generalAgents []string
	}{
		{"one read, one delegate", []string{"a.go"}, "a.go", []string{"x.txt"}},
		{"one of two reads fails, two disjoint delegates", []string{"a.go", "b.go"}, "b.go", []string{"x.txt", "y.txt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project := readToolsProject(t)
			home := t.TempDir()
			cache := emptyCache(t, project)
			store := mkStore(t)
			for _, name := range tc.reads {
				if err := os.WriteFile(filepath.Join(project, name), []byte("package p\n"), 0o644); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
			}
			reg, err := (&toolRegistryFactory{active: nil}).realize(cache, func() *sessions.Store { return store }, home, project, securitystate.Policy{})
			if err != nil {
				t.Fatalf("realize production registry: %v", err)
			}
			probe := &generalAgentProbe{}
			if rerr := reg.Register(tools.BuiltinSource, subagenttool.New(subagenttool.Deps{
				Home: home, LaunchDir: project, ProjectRoot: project,
				Snapshot:      probe.snapshot,
				NewDispatcher: probe.newDispatcher,
				Store:         func() *sessions.Store { return store },
			})); rerr != nil {
				t.Fatalf("Register general_agent: %v", rerr)
			}
			readFailed := errors.New("read authorization failed")
			auth := &orderedFailureAuthorizer{errs: map[string]error{filepath.Join(project, tc.fails): readFailed}}
			d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project,
				func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{})

			var calls []turn.AssembledToolCall
			for i, name := range tc.reads {
				calls = append(calls, structuredCall(fmt.Sprintf("r%d", i), filetools.ReadToolName, map[string]any{"path": name}))
			}
			for i, file := range tc.generalAgents {
				calls = append(calls, plannedGeneralAgentCall(fmt.Sprintf("d%d", i), file))
			}
			plan := d.Plan(calls, len(calls))
			assertPartitionedPlan(t, plan, calls, strings.Repeat("e", len(tc.reads))+strings.Repeat("d", len(tc.generalAgents)))

			run, serr := schedulePlanHeld(plan, len(calls), nil, 0)
			if !errors.Is(serr, readFailed) {
				t.Fatalf("Schedule error = %v, want the recorded read failure %v", serr, readFailed)
			}
			if probe.started() != 0 {
				t.Fatalf("children started = %d, want 0 after a failed eligible read", probe.started())
			}
			for i := range tc.generalAgents {
				if id := fmt.Sprintf("d%d", i); slices.Contains(run.ids(), id) {
					t.Fatalf("delegate %s ran after a failed read; executed %v", id, run.ids())
				}
			}
		})
	}
}

// An invalid declaration is never a disjoint target set that could let two children overlap.
func TestProductionDispatcher_InvalidGeneralAgentStaysASerialBarrier(t *testing.T) {
	for _, tc := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"null file list", map[string]any{"instructions": "do it", "files": nil}, "must be an array"},
		{"absolute path", map[string]any{"instructions": "do it", "files": []any{"/etc/passwd"}}, "must be relative"},
		{"out of project", map[string]any{"instructions": "do it", "files": []any{"../escaped.txt"}}, "outside the project"},
		{"malformed argument", map[string]any{"instructions": "do it", "files": "out.txt"}, "must be an array"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, probe, _ := generalAgentProbeDispatcher(t)
			calls := []turn.AssembledToolCall{structuredCall("c1", subagenttool.ToolName, tc.args)}
			plan := d.Plan(calls, 2)
			assertPartitionedPlan(t, plan, calls, "x")

			res, err := plan.Units[0].Run(context.Background())
			if err != nil {
				t.Fatalf("Run error = %v, want the refusal in band", err)
			}
			if !strings.Contains(res.Content, tc.want) {
				t.Fatalf("content = %q, want it to name %q", res.Content, tc.want)
			}
			if probe.started() != 0 {
				t.Fatalf("children started = %d, want 0 for an invalid declaration", probe.started())
			}
		})
	}
}

// Between planning and execution the declared path's missing parent appears as a symlink out of the
// project. The launch check resolves the planned canonical target, sees it moved, and refuses
// before any authorization, so no child starts with a ceiling other than the planned one.
func TestProductionDispatcher_GeneralAgentPlanIsNotReresolvedBeforeTheChildStarts(t *testing.T) {
	d, probe, project := generalAgentProbeDispatcher(t)
	calls := []turn.AssembledToolCall{plannedGeneralAgentCall("c1", "link/a.txt")}
	plan := d.Plan(calls, 2)

	planned := []string{filepath.Join(project, "link"), filepath.Join(project, "link", "a.txt")}
	if !slices.Equal(plan.Units[0].Targets, planned) {
		t.Fatalf("delegate targets = %v, want the leaf plus its missing parent %v", plan.Units[0].Targets, planned)
	}

	elsewhere, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(project, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	res, err := plan.Units[0].Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(res.Content, "no longer resolves") {
		t.Fatalf("result = %q, want the launch refused on the moved declaration", res.Content)
	}
	if probe.started() != 0 || len(probe.ceilings()) != 0 {
		t.Fatalf("children started = %d with ceilings %v, want none", probe.started(), probe.ceilings())
	}
	if auth := d.authorizer.(*recordingAuthorizer); auth.callCount() != 0 {
		t.Fatalf("authorizations = %d, want none before the drift refusal", auth.callCount())
	}
	if !slices.Equal(plan.Units[0].Targets, planned) {
		t.Fatalf("delegate targets = %v after the parent appeared, want the planned %v", plan.Units[0].Targets, planned)
	}
}

func declarationArgs(write, remove []string) map[string]any {
	args := map[string]any{"instructions": "do it"}
	if write != nil {
		args["files"] = stringsAsAny(write)
	}
	if remove != nil {
		args["files_delete"] = stringsAsAny(remove)
	}
	return args
}

func stringsAsAny(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

func TestProductionDispatcher_DeleteDeclarationsOrderGeneralAgents(t *testing.T) {
	t.Run("both forms are one deduplicated target set", func(t *testing.T) {
		d, _, project := generalAgentProbeDispatcher(t)
		calls := []turn.AssembledToolCall{structuredCall("c1", subagenttool.ToolName, declarationArgs([]string{"both.txt"}, []string{"both.txt", "gone.txt"}))}
		plan := d.Plan(calls, 2)
		assertPartitionedPlan(t, plan, calls, "d")
		want := []string{filepath.Join(project, "both.txt"), filepath.Join(project, "gone.txt")}
		if !slices.Equal(plan.Units[0].Targets, want) {
			t.Fatalf("delegate targets = %v, want %v", plan.Units[0].Targets, want)
		}
	})

	for _, tc := range []struct {
		name          string
		first, second map[string]any
		wantOverlap   bool
	}{
		{"delete and delete of one path serialize", declarationArgs(nil, []string{"notes.txt"}), declarationArgs(nil, []string{"notes.txt"}), false},
		{"delete and write of one path serialize", declarationArgs(nil, []string{"notes.txt"}), declarationArgs([]string{"notes.txt"}, nil), false},
		{"a directory delete and a write beneath it serialize", declarationArgs(nil, []string{"dir"}), declarationArgs([]string{"dir/notes.txt"}, nil), false},
		{"disjoint write and delete sets overlap", declarationArgs([]string{"a.txt"}, []string{"old-a.txt"}), declarationArgs([]string{"b.txt"}, []string{"old-b.txt"}), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, probe, _ := generalAgentProbeDispatcher(t)
			calls := []turn.AssembledToolCall{
				structuredCall("c1", subagenttool.ToolName, tc.first),
				structuredCall("c2", subagenttool.ToolName, tc.second),
			}
			plan := d.Plan(calls, 2)
			assertPartitionedPlan(t, plan, calls, "dd")

			run, err := schedulePlanHeld(plan, 2, nil, generalAgentHold)
			if err != nil {
				t.Fatalf("Schedule: %v", err)
			}
			if got := run.overlapped("c1", "c2"); got != tc.wantOverlap {
				t.Fatalf("delegates overlapped = %v, want %v", got, tc.wantOverlap)
			}
			if want := []string{"c1", "c2"}; !tc.wantOverlap && !slices.Equal(run.ids(), want) {
				t.Fatalf("execution order = %v, want the model-call order %v", run.ids(), want)
			}
			if probe.started() != 2 {
				t.Fatalf("children started = %d, want 2", probe.started())
			}
		})
	}
}

func TestGeneralAgentBinding_SnapshotsThePublishedParentTurn(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	reg := generalAgentRegistry(t, cache, home, project, active, modeActive)
	store := mkStore(t)
	parent := &parentTurnHolder{}
	deps := generalAgentBinding{parent: parent, notices: &recordingNotices{}}.deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))

	if _, ok := parent.current(); ok {
		t.Fatal("an unread holder reported a parent, want the zero value withheld")
	}
	if _, ok := deps.Snapshot(t.Context()); ok {
		t.Fatal("Snapshot resolved a parent before any turn published one, want no child started")
	}

	publishParentTurn(parent, active, modeActive)
	active.ApplyUserSelection(model.Selection{Provider: "openai", ID: "gpt-6", Effort: "xhigh"}, false)
	modeActive.ApplyUserCommand(mode.AutoEdits)

	frozen, ok := deps.Snapshot(t.Context())
	if !ok {
		t.Fatal("Snapshot reported no resolvable parent after a turn published one")
	}
	if frozen.Model.ID != "gpt-5.5" || frozen.Model.Effort != "high" {
		t.Fatalf("snapshot model = %+v, want the published turn's model and effort", frozen.Model)
	}
	if frozen.ModelSource != model.SourceProject {
		t.Fatalf("snapshot model source = %q, want the published turn's source", frozen.ModelSource)
	}
	if frozen.Mode != string(mode.Build) {
		t.Fatalf("snapshot mode = %q, want the published turn's mode", frozen.Mode)
	}
	if frozen.SystemPrompt != "prompt for build/gpt-5.5" {
		t.Fatalf("snapshot prompt = %q, want the prompt the published turn assembled", frozen.SystemPrompt)
	}
	if got := frozen.SupportedEffort("openai", "gpt-5.5"); !slices.Equal(got, []string{"medium", "high"}) {
		t.Fatalf("supported effort = %v, want the catalog's menu for the published model", got)
	}
	if !slices.Contains(toolNames(frozen.Tools), subagenttool.ToolName) {
		t.Fatalf("snapshot tools = %v, want the parent's advertised surface", toolNames(frozen.Tools))
	}

	pinned, ok := deps.Snapshot(vcs.WithConfinementMode(t.Context(), string(mode.Plan)))
	if !ok {
		t.Fatal("Snapshot reported no resolvable parent for a pinned call")
	}
	if pinned.Mode != string(mode.Plan) || slices.Contains(toolNames(pinned.Tools), filetools.CreateToolName) {
		t.Fatalf("pinned snapshot mode = %q, tools %v; want the call's plan pin and its read-only surface", pinned.Mode, toolNames(pinned.Tools))
	}
	if pinned.Model != frozen.Model || pinned.ModelSource != frozen.ModelSource || pinned.SystemPrompt != frozen.SystemPrompt {
		t.Fatalf("pinned snapshot = %+v, want the published turn's model, source and prompt", pinned)
	}

	publishParentTurn(parent, active, modeActive)
	next, ok := deps.Snapshot(t.Context())
	if !ok {
		t.Fatal("Snapshot reported no resolvable parent after the next turn published")
	}
	if next.Model.ID != "gpt-6" || next.Model.Effort != "xhigh" || next.Mode != string(mode.AutoEdits) {
		t.Fatalf("next snapshot = %+v, want the model, effort, and mode the next turn published", next)
	}
	if next.SystemPrompt != "prompt for auto_edits/gpt-6" {
		t.Fatalf("next snapshot prompt = %q, want the prompt the next turn assembled", next.SystemPrompt)
	}
	if got := next.SupportedEffort("openai", "gpt-6"); !slices.Equal(got, []string{"low", "xhigh"}) {
		t.Fatalf("supported effort = %v, want the catalog's menu for the newly published model", got)
	}
}

func TestTurnController_DispatchPublishesTheParentTurnForGeneralAgent(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("Hi"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	cache, home, project, active, modeActive := generalAgentFixture(t)
	reg := generalAgentRegistry(t, cache, home, project, active, modeActive)
	store := mkStore(t)
	parent := &parentTurnHolder{}
	deps := generalAgentBinding{parent: parent, notices: &recordingNotices{}}.deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))

	if _, ok := deps.Snapshot(t.Context()); ok {
		t.Fatal("a delegate call before the first dispatch resolved a parent, want none")
	}

	ctl := newTurnController(context.Background(), &recordingSurface{}, cache, active, func() string {
		m, _ := modeActive.Current()
		sel, _, _ := active.Current()
		return "prompt for " + string(m) + "/" + sel.ID
	}, nil)
	ctl.setGeneralAgentParent(parent)
	ctl.setDevDebug(false, func() string {
		m, _ := modeActive.Current()
		return string(m)
	}, nil)
	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	active.ApplyUserSelection(model.Selection{Provider: "openai", ID: "gpt-6", Effort: "xhigh"}, false)
	modeActive.ApplyUserCommand(mode.AutoEdits)

	snap, ok := deps.Snapshot(t.Context())
	if !ok {
		t.Fatal("a delegate call in the dispatched turn resolved no parent, want the dispatched turn")
	}
	if snap.Model.ID != "gpt-5.5" || snap.Model.Effort != "high" || snap.ModelSource != model.SourceProject {
		t.Fatalf("child model = %+v (source %q), want the dispatched turn's selection", snap.Model, snap.ModelSource)
	}
	if snap.Mode != string(mode.Build) {
		t.Fatalf("child mode = %q, want the dispatched turn's mode", snap.Mode)
	}
	if snap.SystemPrompt != "prompt for build/gpt-5.5" {
		t.Fatalf("child prompt = %q, want the prompt the dispatched turn assembled", snap.SystemPrompt)
	}

	pinned, ok := deps.Snapshot(vcs.WithConfinementMode(t.Context(), string(mode.AutoEdits)))
	if !ok {
		t.Fatal("a pinned delegate call in the dispatched turn resolved no parent")
	}
	if pinned.Mode != string(mode.AutoEdits) || pinned.Model != snap.Model || pinned.SystemPrompt != snap.SystemPrompt {
		t.Fatalf("pinned child = mode %q, model %+v, prompt %q; want the call's pin with the dispatched turn's model and prompt", pinned.Mode, pinned.Model, pinned.SystemPrompt)
	}
}

// TestRunHeadlessTurn_PublishesTheParentTurnItRuns proves the headless path publishes the very
// model, source, mode, and system prompt its own turn.Deps carry, so a headless child cannot
// inherit values read or assembled a second time.
func TestRunHeadlessTurn_PublishesTheParentTurnItRuns(t *testing.T) {
	var sent provider.Request
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		sent = req
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	cache, home, _, active, _ := generalAgentFixture(t)
	parent := &parentTurnHolder{}
	var stdout, stderr strings.Builder
	err := runHeadlessTurn(context.Background(), mkStore(t), cache, active, newHeadlessSurface(&stdout, &stderr), nil,
		func() string { return "assembled once" }, func() []provider.ToolDefinition { return nil },
		home, time.Time{}, false, string(mode.AutoEdits), parent)
	if err != nil {
		t.Fatalf("runHeadlessTurn error = %v, want nil", err)
	}

	published, ok := parent.current()
	if !ok {
		t.Fatal("the headless turn published no parent, so a headless delegate call starts no child")
	}
	if published.model.ID != sent.Model || published.model.Effort != sent.Effort {
		t.Fatalf("published model = %+v, want the model and effort the turn requested (%q/%q)", published.model, sent.Model, sent.Effort)
	}
	if len(sent.Messages) == 0 || sent.Messages[0].Role != "system" {
		t.Fatalf("turn request messages = %+v, want a leading system message to compare the published prompt against", sent.Messages)
	}
	if published.systemPrompt != sent.Messages[0].Content {
		t.Fatalf("published prompt = %q, want the system message the turn sent (%q)", published.systemPrompt, sent.Messages[0].Content)
	}
	if published.mode != string(mode.AutoEdits) || published.modelSource != model.SourceProject {
		t.Fatalf("published mode/source = %q/%q, want the mode and source the turn ran under", published.mode, published.modelSource)
	}
}

func childCeilingFixture(t *testing.T, declarations ...string) (turn.ToolDispatcher, *sessions.Store, string, string, map[string]bool) {
	t.Helper()
	d, store, home, project, declared, _ := childScopesFixture(t, declarations, nil)
	return d, store, home, project, declared
}

func childScopesFixture(t *testing.T, write, remove []string) (turn.ToolDispatcher, *sessions.Store, string, string, map[string]bool, map[string]bool) {
	t.Helper()
	cache, home, project, active, modeActive := generalAgentFixture(t)
	if err := os.MkdirAll(filepath.Join(project, "work"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	for _, name := range []string{filepath.Join("work", "notes.txt"), "linked.txt"} {
		if err := os.WriteFile(filepath.Join(project, name), []byte("body\n"), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
	}
	if err := os.Symlink(filepath.Join(project, "linked.txt"), filepath.Join(project, "link.txt")); err != nil {
		t.Fatalf("Symlink link.txt: %v", err)
	}
	if err := os.Symlink(filepath.Join(project, "work"), filepath.Join(project, "worklink")); err != nil {
		t.Fatalf("Symlink worklink: %v", err)
	}
	declared, removable, err := filetools.ResolveDeclaredScopes(home, project, write, remove)
	if err != nil {
		t.Fatalf("ResolveDeclaredScopes: %v", err)
	}
	if remove != nil && removable == nil {
		removable = map[string]bool{}
	}
	store := mkStore(t)
	reg := generalAgentRegistry(t, cache, home, project, active, modeActive)
	deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
	return deps.NewDispatcher(permissions.ModeContext{
		Mode:           string(mode.Build),
		ChildAgent:     true,
		DeclaredWrite:  declared,
		DeclaredDelete: removable,
	}), store, home, project, declared, removable
}

func sameFilesystemObject(a, b string) bool {
	ai, aerr := os.Lstat(a)
	if aerr != nil {
		return false
	}
	bi, berr := os.Lstat(b)
	if berr != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

func decodeDenyEnvelope(t *testing.T, envelope string) (deniedBy, reason string) {
	t.Helper()
	var wire struct {
		DeniedBy string `json:"denied_by"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(envelope), &wire); err != nil {
		t.Fatalf("deny envelope %q is not valid JSON: %v", envelope, err)
	}
	return wire.DeniedBy, wire.Reason
}

func assertChildScopeDenial(t *testing.T, store *sessions.Store, before int, res turn.ToolResult) string {
	t.Helper()
	return assertChildScopeDenialBy(t, store, before, res, "unattended")
}

func assertChildScopeDenialBy(t *testing.T, store *sessions.Store, before int, res turn.ToolResult, wantDeniedBy string) string {
	t.Helper()
	if !res.Denied {
		t.Fatalf("result = %+v, want a declared-scope denial", res)
	}
	matched := decodePermissionMatched(t, store)
	if len(matched) != before+1 {
		t.Fatalf("permission_matched events = %d, want exactly one more than %d", len(matched), before)
	}
	ev := matched[len(matched)-1]
	if ev.OutcomeSource != permissions.OutcomeSourceDeclaredScope || ev.Outcome != "deny" {
		t.Fatalf("permission_matched = %#v, want declared_scope/deny", ev)
	}
	if ev.GrantKind != "" || ev.GrantPathScope != "" {
		t.Fatalf("permission_matched = %#v, want no grant fields on a declaration refusal", ev)
	}
	deniedBy, reason := decodeDenyEnvelope(t, res.Content)
	if deniedBy != wantDeniedBy {
		t.Fatalf("denied_by = %q, want %q", deniedBy, wantDeniedBy)
	}
	if !strings.Contains(reason, "child agent") {
		t.Fatalf("reason %q does not identify the child's own declaration", reason)
	}
	return reason
}

func TestProductionDispatcher_WebSearchRefusalCarriesTheWrapUpMarker(t *testing.T) {
	dir := t.TempDir()
	store := mkStore(t)
	auth := newHeadlessAuthorizer(emptyCache(t, dir), func() *sessions.Store { return store },
		mode.NewActiveState(mode.Build, mode.SourceDefault), nil, &recordingNotices{})
	backend := &stubSearchBackend{}
	d := webSearchDispatcherWith(t, auth, nil, 65536, backend, map[string]any{"enabled": true})

	for i := 1; i <= maxRefusalsPerCall; i++ {
		res, err := d.Dispatch(context.Background(), webSearchCall(fmt.Sprintf("query %d", i)))
		if err != nil || !res.Denied {
			t.Fatalf("search %d = %+v, %v, want a refusal", i, res, err)
		}
		if res.WrapUp != (i == maxRefusalsPerCall) {
			t.Fatalf("search %d WrapUp = %v, want it only on refusal %d", i, res.WrapUp, maxRefusalsPerCall)
		}
	}
	if len(backend.queries) != 0 {
		t.Fatalf("backend searched %v, want nothing after refusals", backend.queries)
	}
}

func TestChildCeiling_PathContainmentBypassAttemptsAllDeny(t *testing.T) {
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	tests := []struct {
		name       string
		tool       string
		args       func(outside string) map[string]any
		wantTarget func(project, outside string) string
		// caseVariantOf names the declared path this row respells. Whether the respelling is a
		// distinct canonical target depends on the volume, so such a row resolves through the
		// production create resolver and is skipped where the two spellings are one file.
		caseVariantOf string
	}{
		{
			name: "a traversal out of a declared path",
			tool: filetools.CreateToolName,
			args: func(string) map[string]any {
				return map[string]any{"path": "work/../escaped.txt", "content": "x"}
			},
			wantTarget: func(project, _ string) string { return filepath.Join(project, "escaped.txt") },
		},
		{
			name: "a symlink whose target is undeclared",
			tool: filetools.EditToolName,
			args: func(string) map[string]any {
				return map[string]any{"path": "link.txt", "old_text": "body", "new_text": "taken"}
			},
			wantTarget: func(project, _ string) string { return filepath.Join(project, "linked.txt") },
		},
		{
			name: "a differently-normalized spelling",
			tool: filetools.CreateToolName,
			args: func(string) map[string]any {
				return map[string]any{"path": "./work/./sibling.txt", "content": "x"}
			},
			wantTarget: func(project, _ string) string { return filepath.Join(project, "work", "sibling.txt") },
		},
		{
			name: "an absolute path outside the project root",
			tool: filetools.CreateToolName,
			args: func(outside string) map[string]any {
				return map[string]any{"path": filepath.Join(outside, "beyond.txt"), "content": "x"}
			},
			wantTarget: func(_, outside string) string { return filepath.Join(outside, "beyond.txt") },
		},
		{
			name: "a trailing-slash spelling",
			tool: filetools.CreateToolName,
			args: func(string) map[string]any {
				return map[string]any{"path": "work/trailing.txt/", "content": "x"}
			},
			wantTarget: func(project, _ string) string { return filepath.Join(project, "work", "trailing.txt") },
		},
		{
			name: "a case-variant spelling",
			tool: filetools.CreateToolName,
			args: func(string) map[string]any {
				return map[string]any{"path": "work/NOTES.txt", "content": "x"}
			},
			wantTarget:    func(project, _ string) string { return filepath.Join(project, "work", "NOTES.txt") },
			caseVariantOf: filepath.Join("work", "notes.txt"),
		},
	}

	d, store, home, project, declared := childCeilingFixture(t, filepath.Join("work", "notes.txt"))
	seen := map[string]bool{}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := tc.args(outside)
			target := tc.wantTarget(project, outside)
			if tc.caseVariantOf != "" {
				spelled := filepath.Join(project, args["path"].(string))
				if sameFilesystemObject(spelled, filepath.Join(project, tc.caseVariantOf)) {
					t.Skipf("%s and %s are one file on this case-insensitive volume, so the spelling has no distinct canonical target to deny", args["path"], tc.caseVariantOf)
				}
				resolved, _, rerr := filetools.NewCreateTool(home, project, project).ResolveTarget(args)
				if rerr != nil {
					t.Fatalf("ResolveTarget(%v) = %v, want the production canonical target", args["path"], rerr)
				}
				if resolved != target {
					t.Fatalf("production canonical target = %s, want %s", resolved, target)
				}
			}
			if declared[target] {
				t.Fatalf("row target %s is inside the declaration, so the row proves nothing", target)
			}
			if seen[target] {
				t.Fatalf("row target %s repeats an earlier row's canonical target", target)
			}
			seen[target] = true

			before := len(decodePermissionMatched(t, store))
			res, derr := d.Dispatch(context.Background(), structuredCall(fmt.Sprintf("bypass-%d", i), tc.tool, args))
			if derr != nil {
				t.Fatalf("Dispatch error = %v, want nil", derr)
			}
			if res.WrapUp {
				t.Fatalf("refusal of distinct target %s carries WrapUp, want different calls to have no limit", target)
			}
			assertChildScopeDenialBy(t, store, before, res, "unattended")
			if tc.tool == filetools.CreateToolName {
				if _, statErr := os.Lstat(target); statErr == nil {
					t.Fatalf("%s exists after a refused call", target)
				}
			}
		})
	}
	if body, err := os.ReadFile(filepath.Join(project, "linked.txt")); err != nil || string(body) != "body\n" {
		t.Fatalf("linked.txt = %q (err %v), want the refused edit to have changed nothing", body, err)
	}
}

func TestChildCeiling_CanonicalEquivalentSpellingsAreAdmitted(t *testing.T) {
	tests := []struct {
		spelling string
		absolute bool
	}{
		{spelling: "work/new.txt"},
		{spelling: "./work/new.txt"},
		{spelling: "work/./new.txt"},
		{spelling: "work/../work/new.txt"},
		{spelling: "work/new.txt/"},
		{spelling: "worklink/new.txt"},
		{spelling: "work/new.txt", absolute: true},
	}
	for i, tc := range tests {
		name := tc.spelling
		if tc.absolute {
			name = "absolute " + name
		}
		t.Run(name, func(t *testing.T) {
			d, store, _, project, declared := childCeilingFixture(t, filepath.Join("work", "new.txt"))
			target := filepath.Join(project, "work", "new.txt")
			if !declared[target] {
				t.Fatalf("declaration %v does not name %s", declared, target)
			}
			path := tc.spelling
			if tc.absolute {
				path = filepath.Join(project, tc.spelling)
			}

			res, err := d.Dispatch(context.Background(), structuredCall(fmt.Sprintf("same-%d", i),
				filetools.CreateToolName, map[string]any{"path": path, "content": "x"}))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}
			if res.Denied {
				t.Fatalf("result = %+v, want the declaration to admit a canonical-equivalent spelling", res)
			}
			matched := decodePermissionMatched(t, store)
			if len(matched) != 1 {
				t.Fatalf("permission_matched events = %+v, want exactly one", matched)
			}
			if matched[0].OutcomeSource != permissions.OutcomeSourceDeclaredScope || matched[0].Outcome != "once" {
				t.Fatalf("permission_matched = %#v, want declared_scope/once", matched[0])
			}
			if _, statErr := os.Stat(target); statErr != nil {
				t.Fatalf("declared target %s was not written: %v", target, statErr)
			}
		})
	}
}

func TestChildCeiling_MkdirMoveAndDeleteNameTheMissingChildForm(t *testing.T) {
	tests := []struct {
		name string
		call turn.AssembledToolCall
		form string
	}{
		{
			name: "delete",
			call: structuredCall("d1", filetools.DeleteToolName, map[string]any{"path": "work/notes.txt"}),
			form: "this general_agent call did not supply files_delete",
		},
		{
			name: "mkdir",
			call: structuredCall("d2", filetools.MkdirToolName, map[string]any{"path": "work/sub"}),
			form: "this general_agent call did not supply files_mkdir",
		},
		{
			name: "move",
			call: structuredCall("d3", filetools.MoveToolName, map[string]any{"source": "work/notes.txt", "destination": "work/renamed.txt"}),
			form: "this general_agent call did not supply files_move",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, store, _, project, _ := childCeilingFixture(t, filepath.Join("work", "notes.txt"))

			res, err := d.Dispatch(context.Background(), tc.call)
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}
			reason := assertChildScopeDenial(t, store, 0, res)
			if !strings.Contains(reason, tc.form) {
				t.Fatalf("reason %q does not name the missing child form %q", reason, tc.form)
			}
			for _, forbidden := range []string{"--files-authorized", "not available to a child agent", "unavailable", "forbidden"} {
				if strings.Contains(reason, forbidden) {
					t.Fatalf("reason %q contains %q; a child refusal names only the missing declaration form", reason, forbidden)
				}
			}
			if _, statErr := os.Stat(filepath.Join(project, "work", "notes.txt")); statErr != nil {
				t.Fatalf("the declared write path was mutated by a refused call: %v", statErr)
			}
		})
	}
}

func TestChildCeiling_NestedGeneralAgentIsDecidedBeforeTheGrandchildStarts(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	declared, _, err := filetools.ResolveDeclaredScopes(home, project, []string{"a.txt", "b.txt"}, nil)
	if err != nil {
		t.Fatalf("ResolveDeclaredScopes: %v", err)
	}
	tests := []struct {
		name       string
		files      []string
		wantDenied bool
	}{
		{name: "a subset starts the grandchild", files: []string{"a.txt"}},
		{name: "a broader declaration is refused", files: []string{"a.txt", "c.txt"}, wantDenied: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nested, _, rerr := filetools.ResolveDeclaredScopes(home, project, tc.files, nil)
			if rerr != nil {
				t.Fatalf("ResolveDeclaredScopes: %v", rerr)
			}
			stub := &stubStructuredTool{name: subagenttool.ToolName, result: tools.Result{Stdout: []byte("grandchild ran\n")}}
			reg := tools.NewRegistry()
			if regErr := reg.Register(tools.BuiltinSource, stub); regErr != nil {
				t.Fatalf("Register: %v", regErr)
			}
			store := mkStore(t)
			deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
			d := deps.NewDispatcher(permissions.ModeContext{
				Mode:              string(mode.Build),
				ChildAgent:        true,
				DeclaredWrite:     declared,
				GeneralAgentWrite: nested,
			})

			files := make([]any, len(tc.files))
			for i, f := range tc.files {
				files[i] = f
			}
			res, derr := d.Dispatch(context.Background(), structuredCall("n1", subagenttool.ToolName,
				map[string]any{"instructions": "do it", "files": files}))
			if derr != nil {
				t.Fatalf("Dispatch error = %v, want nil", derr)
			}
			if res.Denied != tc.wantDenied {
				t.Fatalf("result = %+v, want denied=%v", res, tc.wantDenied)
			}
			wantCalls := 1
			if tc.wantDenied {
				wantCalls = 0
			}
			if stub.callCount() != wantCalls {
				t.Fatalf("delegate invocations = %d, want %d", stub.callCount(), wantCalls)
			}
			matched := decodePermissionMatched(t, store)
			if len(matched) != 1 || matched[0].OutcomeSource != permissions.OutcomeSourceDeclaredScope {
				t.Fatalf("permission_matched = %+v, want exactly one declared_scope decision", matched)
			}
			if !tc.wantDenied {
				return
			}
			deniedBy, reason := decodeDenyEnvelope(t, res.Content)
			if deniedBy != "unattended" {
				t.Fatalf("denied_by = %q, want unattended — a child has no approver", deniedBy)
			}
			if !strings.Contains(reason, "nested general_agent call") {
				t.Fatalf("reason %q does not name the nested-declaration rule", reason)
			}
		})
	}
}

// TestChildCeiling_AnUnresolvableNestedGeneralAgentDeniesThroughDeclaredScope pins the child-ceiling contract on
// the production path: a nested call whose declaration does not validate still reaches authorization,
// carrying no candidate, and is denied by declared scope before any grandchild starts. Handing the
// child the delegate tool's own corrective instead would answer a ceiling question outside the
// authorizer and leave no permission_matched record of the refusal. The top-level case below is the
// counterpart — no ceiling is judging it, so it stays a corrective.
func TestChildCeiling_AnUnresolvableNestedGeneralAgentDeniesThroughDeclaredScope(t *testing.T) {
	tests := []struct {
		name string
		args map[string]any
	}{
		{"a null file list", map[string]any{"instructions": "do it", "files": nil}},
		{"an empty path entry", map[string]any{"instructions": "do it", "files": []any{""}}},
		{"an absolute path", map[string]any{"instructions": "do it", "files": []any{"/etc/passwd"}}},
		{"a path outside the project", map[string]any{"instructions": "do it", "files": []any{"../escape.txt"}}},
		{"an unknown argument", map[string]any{"instructions": "do it", "files": []any{"a.txt"}, "model": "sonnet"}},
	}
	for _, tc := range tests {
		for _, inherited := range []struct {
			name     string
			write    []string
			resolved bool
		}{
			{"no inherited candidate", nil, false},
			{"an inherited resolved empty candidate", nil, true},
			{"an inherited resolved candidate", []string{"a.txt"}, true},
		} {
			t.Run(tc.name+"/"+inherited.name, func(t *testing.T) {
				cache, home, project, active, modeActive := generalAgentFixture(t)
				declared, _, rerr := filetools.ResolveDeclaredScopes(home, project, []string{"a.txt", "b.txt"}, nil)
				if rerr != nil {
					t.Fatalf("ResolveDeclaredScopes: %v", rerr)
				}
				reg := generalAgentRegistry(t, cache, home, project, active, modeActive)
				store := mkStore(t)
				deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
				inheritedWrite, _, ierr := filetools.ResolveDeclaredScopes(home, project, inherited.write, nil)
				if ierr != nil {
					t.Fatalf("ResolveDeclaredScopes: %v", ierr)
				}
				d := deps.NewDispatcher(permissions.ModeContext{
					Mode:                 string(mode.Build),
					ChildAgent:           true,
					DeclaredWrite:        declared,
					GeneralAgentWrite:    inheritedWrite,
					GeneralAgentResolved: inherited.resolved,
				})

				res, derr := d.Dispatch(context.Background(), structuredCall("n1", subagenttool.ToolName, tc.args))
				if derr != nil {
					t.Fatalf("Dispatch error = %v, want nil", derr)
				}
				if !res.Denied {
					t.Fatalf("result = %+v, want a declared-scope denial rather than the tool's corrective", res)
				}
				matched := decodePermissionMatched(t, store)
				if len(matched) != 1 || matched[0].OutcomeSource != permissions.OutcomeSourceDeclaredScope {
					t.Fatalf("permission_matched = %+v, want exactly one declared_scope decision", matched)
				}
				deniedBy, reason := decodeDenyEnvelope(t, res.Content)
				if deniedBy != "unattended" {
					t.Fatalf("denied_by = %q, want unattended — a child has no approver", deniedBy)
				}
				if !strings.Contains(reason, "nested general_agent call") {
					t.Fatalf("reason %q does not name the nested-declaration rule", reason)
				}
			})
		}
	}
}

func TestChildCeiling_WriteAndDeleteDeclarationsAreAsymmetric(t *testing.T) {
	notes := filepath.Join("work", "notes.txt")
	fresh := filepath.Join("work", "fresh.txt")
	deleteNotes := structuredCall("a1", filetools.DeleteToolName, map[string]any{"path": notes})
	editNotes := structuredCall("a1", filetools.EditToolName, map[string]any{"path": notes, "old_text": "body", "new_text": "edited"})
	createFresh := structuredCall("a1", filetools.CreateToolName, map[string]any{"path": fresh, "content": "x"})
	tests := []struct {
		name          string
		write, remove []string
		call          turn.AssembledToolCall
		wantDenied    bool
		wantNotes     string
	}{
		{name: "a write-declared path cannot be deleted", write: []string{notes}, call: deleteNotes, wantDenied: true, wantNotes: "body\n"},
		{name: "a delete-declared path cannot be edited", remove: []string{notes}, call: editNotes, wantDenied: true, wantNotes: "body\n"},
		{name: "a delete-declared path cannot be created", remove: []string{fresh}, call: createFresh, wantDenied: true, wantNotes: "body\n"},
		{name: "a delete-declared path deletes", remove: []string{notes}, call: deleteNotes},
		{name: "a path in both lists edits", write: []string{notes}, remove: []string{notes}, call: editNotes, wantNotes: "edited\n"},
		{name: "a path in both lists deletes", write: []string{notes}, remove: []string{notes}, call: deleteNotes},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, store, _, project, _, _ := childScopesFixture(t, tc.write, tc.remove)

			res, err := d.Dispatch(context.Background(), tc.call)
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}
			if tc.wantDenied {
				assertChildScopeDenial(t, store, 0, res)
			} else {
				if res.Denied {
					t.Fatalf("result = %+v, want the declaration to authorize the call", res)
				}
				matched := decodePermissionMatched(t, store)
				if len(matched) != 1 || matched[0].OutcomeSource != permissions.OutcomeSourceDeclaredScope || matched[0].Outcome != "once" {
					t.Fatalf("permission_matched = %+v, want exactly one declared_scope/once", matched)
				}
			}
			body, rerr := os.ReadFile(filepath.Join(project, notes))
			if rerr != nil && !os.IsNotExist(rerr) {
				t.Fatalf("ReadFile: %v", rerr)
			}
			if string(body) != tc.wantNotes {
				t.Fatalf("%s = %q, want %q", notes, body, tc.wantNotes)
			}
			if _, statErr := os.Lstat(filepath.Join(project, fresh)); statErr == nil {
				t.Fatalf("%s exists, want no create authorized by a delete declaration", fresh)
			}
		})
	}
}

func TestChildCeiling_DeletesTheDeclaredPathAndRefusesAnUndeclaredOneInOneRun(t *testing.T) {
	notes := filepath.Join("work", "notes.txt")
	d, store, _, project, _, _ := childScopesFixture(t, nil, []string{notes})

	res, err := d.Dispatch(context.Background(), structuredCall("d1", filetools.DeleteToolName, map[string]any{"path": notes}))
	if err != nil || res.Denied {
		t.Fatalf("declared delete = %+v, %v; want it authorized", res, err)
	}
	if _, statErr := os.Lstat(filepath.Join(project, notes)); !os.IsNotExist(statErr) {
		t.Fatalf("%s still exists (err=%v), want the declared delete done", notes, statErr)
	}

	res, err = d.Dispatch(context.Background(), structuredCall("d2", filetools.DeleteToolName, map[string]any{"path": "linked.txt"}))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	assertChildScopeDenial(t, store, 1, res)
	if _, statErr := os.Lstat(filepath.Join(project, "linked.txt")); statErr != nil {
		t.Fatalf("the undeclared linked.txt was touched: %v", statErr)
	}
}

func TestChildCeiling_DeleteRefusalNamesTheFilesDeleteForm(t *testing.T) {
	notes := filepath.Join("work", "notes.txt")
	tests := []struct {
		name   string
		remove []string
		form   string
	}{
		{"files_delete omitted", nil, "this general_agent call did not supply files_delete"},
		{"files_delete supplied empty", []string{}, "this general_agent call supplied an empty files_delete"},
		{"files_delete missing the target", []string{"linked.txt"}, "this general_agent call's files_delete does not list this target"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, store, _, project, _, _ := childScopesFixture(t, []string{notes}, tc.remove)

			res, err := d.Dispatch(context.Background(), structuredCall("d1", filetools.DeleteToolName, map[string]any{"path": notes}))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}
			reason := assertChildScopeDenial(t, store, 0, res)
			at := -1
			for _, want := range []string{"a child agent may touch only the paths its general_agent call declared", tc.form, "cannot widen while the child runs", "target="} {
				idx := strings.Index(reason, want)
				if idx <= at {
					t.Fatalf("reason %q is missing %q or has it out of order", reason, want)
				}
				at = idx
			}
			if !strings.HasSuffix(reason, filepath.Join(project, notes)+`"`) {
				t.Fatalf("reason %q does not end with the canonical target", reason)
			}
			if strings.Contains(reason, "--files-authorized") {
				t.Fatalf("reason %q names a CLI flag; a child refusal names the delegate argument", reason)
			}
			if _, statErr := os.Stat(filepath.Join(project, notes)); statErr != nil {
				t.Fatalf("the refused target was removed: %v", statErr)
			}
		})
	}
}

func TestChildCeiling_DeleteAliasesOfTheDeclaredTargetDeleteAndBypassesDeny(t *testing.T) {
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	beyond := filepath.Join(outside, "beyond.txt")
	if err := os.WriteFile(beyond, []byte("outside\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	notes := filepath.Join("work", "notes.txt")
	spelled := func(path string) func(string) string { return func(string) string { return path } }
	tests := []struct {
		name          string
		declared      string
		path          func(project string) string
		deleted       string
		kept          []string
		caseVariantOf string
	}{
		{name: "the declared spelling", declared: notes, path: spelled("work/notes.txt"), deleted: notes},
		{name: "a normalized spelling", declared: notes, path: spelled("./work/./notes.txt"), deleted: notes},
		{name: "a traversal back to the declared target", declared: notes, path: spelled("work/../work/notes.txt"), deleted: notes},
		{name: "a trailing-separator spelling", declared: notes, path: spelled("work/notes.txt/"), deleted: notes},
		{name: "an in-project parent symlink", declared: notes, path: spelled("worklink/notes.txt"), deleted: notes},
		{name: "the absolute path", declared: notes, path: func(project string) string { return filepath.Join(project, notes) }, deleted: notes},
		{name: "a declared final-component symlink deletes the link itself", declared: "link.txt", path: spelled("link.txt"), deleted: "link.txt", kept: []string{"linked.txt"}},
		{name: "a traversal to another target", declared: notes, path: spelled("work/../linked.txt"), kept: []string{notes, "linked.txt"}},
		{name: "the file behind a declared symlink", declared: "link.txt", path: spelled("linked.txt"), kept: []string{"link.txt", "linked.txt"}},
		{name: "an absolute path outside the project", declared: notes, path: spelled(beyond), kept: []string{notes}},
		{name: "a case-variant spelling", declared: notes, path: spelled("work/NOTES.txt"), kept: []string{notes, filepath.Join("work", "NOTES.txt")}, caseVariantOf: notes},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, store, home, project, _, removable := childScopesFixture(t, nil, []string{tc.declared})
			if tc.caseVariantOf != "" {
				variant := filepath.Join(project, "work", "NOTES.txt")
				if sameFilesystemObject(variant, filepath.Join(project, tc.caseVariantOf)) {
					t.Skipf("%s is the declared file on this case-insensitive volume, so the spelling has no distinct target", variant)
				}
				if werr := os.WriteFile(variant, []byte("variant\n"), 0o644); werr != nil {
					t.Fatalf("WriteFile: %v", werr)
				}
			}
			args := map[string]any{"path": tc.path(project)}
			target, _, rerr := filetools.NewDeleteTool(home, project, project).ResolveTarget(args)
			if rerr != nil {
				t.Fatalf("ResolveTarget(%v) = %v, want a production canonical target", args["path"], rerr)
			}
			if removable[target] != (tc.deleted != "") {
				t.Fatalf("canonical target %s declared=%v, so the row does not exercise what it names", target, removable[target])
			}

			res, derr := d.Dispatch(context.Background(), structuredCall(fmt.Sprintf("alias-%d", i), filetools.DeleteToolName, args))
			if derr != nil {
				t.Fatalf("Dispatch error = %v, want nil", derr)
			}
			if tc.deleted == "" {
				assertChildScopeDenial(t, store, 0, res)
			} else {
				if res.Denied {
					t.Fatalf("result = %+v, want the canonical alias admitted", res)
				}
				matched := decodePermissionMatched(t, store)
				if len(matched) != 1 || matched[0].OutcomeSource != permissions.OutcomeSourceDeclaredScope || matched[0].Outcome != "once" {
					t.Fatalf("permission_matched = %+v, want exactly one declared_scope/once", matched)
				}
				if _, statErr := os.Lstat(filepath.Join(project, tc.deleted)); !os.IsNotExist(statErr) {
					t.Fatalf("%s still exists (err=%v), want it deleted", tc.deleted, statErr)
				}
			}
			for _, rel := range tc.kept {
				if _, statErr := os.Lstat(filepath.Join(project, rel)); statErr != nil {
					t.Fatalf("%s was mutated by the call: %v", rel, statErr)
				}
			}
			if _, statErr := os.Stat(beyond); statErr != nil {
				t.Fatalf("the out-of-project file was mutated: %v", statErr)
			}
		})
	}
}

func TestChildCeiling_NestedGeneralAgentDeleteFormStaysWithinItsImmediateParent(t *testing.T) {
	tests := []struct {
		name         string
		parentWrite  []string
		parentDelete []string
		nested       map[string]any
		wantDenied   bool
	}{
		{"a delete subset starts the grandchild", []string{"a.txt"}, []string{"old.txt"}, declarationArgs(nil, []string{"old.txt"}), false},
		{"a delete outside the parent's delete list is refused", []string{"a.txt"}, []string{"old.txt"}, declarationArgs(nil, []string{"other.txt"}), true},
		{"a parent write path admits no grandchild delete of it", []string{"a.txt"}, nil, declarationArgs(nil, []string{"a.txt"}), true},
		{"an omitted grandchild delete list fits an absent parent list", []string{"a.txt"}, nil, declarationArgs([]string{"a.txt"}, nil), false},
		{"a supplied empty grandchild delete list fits an absent parent list", []string{"a.txt"}, nil, declarationArgs([]string{"a.txt"}, []string{}), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cache, home, project, active, modeActive := generalAgentFixture(t)
			write, remove, err := filetools.ResolveDeclaredScopes(home, project, tc.parentWrite, tc.parentDelete)
			if err != nil {
				t.Fatalf("ResolveDeclaredScopes: %v", err)
			}
			store := mkStore(t)
			probe := &generalAgentProbe{}
			reg := tools.NewRegistry()
			if rerr := reg.Register(tools.BuiltinSource, subagenttool.New(subagenttool.Deps{
				Home: home, LaunchDir: project, ProjectRoot: project,
				Snapshot:      probe.snapshot,
				NewDispatcher: probe.newDispatcher,
				Store:         func() *sessions.Store { return store },
			})); rerr != nil {
				t.Fatalf("Register general_agent: %v", rerr)
			}
			deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
			d := deps.NewDispatcher(permissions.ModeContext{
				Mode:           string(mode.Build),
				ChildAgent:     true,
				DeclaredWrite:  write,
				DeclaredDelete: remove,
			})

			res, derr := d.Dispatch(context.Background(), structuredCall("n1", subagenttool.ToolName, tc.nested))
			if derr != nil {
				t.Fatalf("Dispatch error = %v, want nil", derr)
			}
			if res.Denied != tc.wantDenied {
				t.Fatalf("result = %+v, want denied=%v", res, tc.wantDenied)
			}
			matched := decodePermissionMatched(t, store)
			if len(matched) != 1 || matched[0].OutcomeSource != permissions.OutcomeSourceDeclaredScope {
				t.Fatalf("permission_matched = %+v, want exactly one declared_scope decision", matched)
			}
			wantStarts := 1
			if tc.wantDenied {
				wantStarts = 0
			}
			if probe.started() != wantStarts {
				t.Fatalf("grandchild starts = %d, want %d", probe.started(), wantStarts)
			}
			if !tc.wantDenied {
				return
			}
			if _, reason := decodeDenyEnvelope(t, res.Content); !strings.Contains(reason, "nested general_agent call may declare in files_delete") {
				t.Fatalf("reason %q does not name the nested delete-declaration rule", reason)
			}
		})
	}
}

func TestProductionDispatcher_MalformedTopLevelGeneralAgentStaysInBand(t *testing.T) {
	tests := []struct {
		name string
		args map[string]any
		want string
	}{
		{"a null file list", map[string]any{"instructions": "do it", "files": nil}, "must be an array of strings"},
		{"an empty path entry", map[string]any{"instructions": "do it", "files": []any{""}}, "must not be empty"},
		{"an absolute path", map[string]any{"instructions": "do it", "files": []any{"/etc/passwd"}}, "must be relative"},
		{"a home-relative path", map[string]any{"instructions": "do it", "files": []any{"~/secrets.txt"}}, "must not be home-relative"},
		{"a path outside the project", map[string]any{"instructions": "do it", "files": []any{"../escape.txt"}}, "outside the project"},
		{"an unknown argument", map[string]any{"instructions": "do it", "files": []any{"a.txt"}, "model": "sonnet"}, `unexpected argument "model"`},
		{"an empty instruction", map[string]any{"instructions": "   ", "files": []any{"a.txt"}}, "must not be empty"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cache, home, project, active, modeActive := generalAgentFixture(t)
			reg := generalAgentRegistry(t, cache, home, project, active, modeActive)
			store := mkStore(t)
			auth := &recordingAuthorizer{decision: allow()}
			d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project,
				func() *sessions.Store { return store }, 65536, securitystate.Policy{})

			res, err := d.Dispatch(context.Background(), structuredCall("c1", subagenttool.ToolName, tc.args))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil so the turn continues", err)
			}
			if res.Denied {
				t.Fatalf("result = %+v, want a corrective tool result rather than a denial", res)
			}
			if !strings.Contains(res.Content, subagenttool.ToolName+": ") || !strings.Contains(res.Content, tc.want) {
				t.Fatalf("content = %q, want the tool's own corrective naming %q", res.Content, tc.want)
			}
			if auth.callCount() != 0 {
				t.Fatalf("authorize calls = %d, want 0 — a call that never prepared is not a permission question", auth.callCount())
			}
			if matched := decodePermissionMatched(t, store); len(matched) != 0 {
				t.Fatalf("permission_matched = %+v, want none", matched)
			}
		})
	}
}

func TestProductionDispatcher_TopLevelGeneralAgentCandidateReachesAuthorization(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	reg := generalAgentRegistry(t, cache, home, project, active, modeActive)
	store := mkStore(t)
	auth := &recordingAuthorizer{decision: permissions.Decision{Outcome: "deny", DenyEnvelope: permissions.BuildDenyEnvelope("no")}}
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project,
		func() *sessions.Store { return store }, 65536, securitystate.Policy{})

	res, err := d.Dispatch(context.Background(), structuredCall("c1", subagenttool.ToolName,
		map[string]any{"instructions": "do it", "files": []any{"a.txt", filepath.Join("dir", "b.txt")}}))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if !res.Denied {
		t.Fatalf("result = %+v, want the denial delivered in band", res)
	}
	want := map[string]bool{
		filepath.Join(project, "a.txt"):        true,
		filepath.Join(project, "dir", "b.txt"): true,
	}
	mc := auth.lastModeCtx(t)
	if !reflect.DeepEqual(mc.GeneralAgentWrite, want) {
		t.Fatalf("GeneralAgentWrite = %v, want the canonical candidate %v", mc.GeneralAgentWrite, want)
	}
	if mc.ChildAgent {
		t.Fatal("ChildAgent = true, want a top-level call judged against the run's own ceiling")
	}
}

func writeDispatcher(t *testing.T, auth dispatch.Authorizer) (*productionToolDispatcher, string) {
	t.Helper()
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()
	reg := tools.NewRegistry()
	for _, tool := range []tools.Tool{
		filetools.NewEditTool(home, project, project),
		filetools.NewCreateTool(home, project, project),
		filetools.NewDeleteTool(home, project, project),
		filetools.NewReadTool(home, project, project, 65536),
	} {
		if err := reg.Register(tools.BuiltinSource, tool); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	store := mkStore(t)
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, 65536, securitystate.Policy{})
	return d, project
}

func TestProductionDispatcher_WriteTargetNamesTheAuthorizedEditAndCreateTarget(t *testing.T) {
	auth := &recordingAuthorizer{decision: allow()}
	d, project := writeDispatcher(t, auth)
	if err := os.WriteFile(filepath.Join(project, "main.go"), []byte("package OLD\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	edited, derr := d.Dispatch(context.Background(), structuredCall("c1", filetools.EditToolName, map[string]any{
		"path": "main.go", "old_text": "OLD", "new_text": "NEW",
	}))
	if derr != nil {
		t.Fatalf("Dispatch(edit) error = %v, want nil", derr)
	}
	if want := filepath.Join(project, "main.go"); edited.WriteTarget != want {
		t.Fatalf("edit WriteTarget = %q, want the resolved target %q", edited.WriteTarget, want)
	}
	if edited.WriteTarget != auth.lastModeCtx(t).TargetPath {
		t.Fatalf("edit WriteTarget = %q, want the exact path authorization decided on (%q)", edited.WriteTarget, auth.lastModeCtx(t).TargetPath)
	}

	created, derr := d.Dispatch(context.Background(), structuredCall("c2", filetools.CreateToolName, map[string]any{
		"path": "sub/new.go", "content": "package new\n",
	}))
	if derr != nil {
		t.Fatalf("Dispatch(create) error = %v, want nil", derr)
	}
	if want := filepath.Join(project, "sub", "new.go"); created.WriteTarget != want {
		t.Fatalf("create WriteTarget = %q, want the resolved target %q", created.WriteTarget, want)
	}
}

func TestProductionDispatcher_WriteTargetAbsentUnlessTheWriteSucceeded(t *testing.T) {
	boom := errors.New("authorizer boom")
	cases := []struct {
		name         string
		auth         dispatch.Authorizer
		call         turn.AssembledToolCall
		wantErr      bool
		wantDenied   bool
		wantContains string
	}{
		{
			name:         "denied edit",
			auth:         &recordingAuthorizer{decision: deny(permissions.BuildDenyEnvelope("nope"))},
			call:         structuredCall("c1", filetools.EditToolName, map[string]any{"path": "main.go", "old_text": "OLD", "new_text": "NEW"}),
			wantDenied:   true,
			wantContains: "denied_by",
		},
		{
			name:    "authorizer failure",
			auth:    &recordingAuthorizer{err: boom},
			call:    structuredCall("c1", filetools.EditToolName, map[string]any{"path": "main.go", "old_text": "OLD", "new_text": "NEW"}),
			wantErr: true,
		},
		{
			name:         "authorized edit that changes nothing",
			auth:         &recordingAuthorizer{decision: allow()},
			call:         structuredCall("c1", filetools.EditToolName, map[string]any{"path": "main.go", "old_text": "ABSENT", "new_text": "NEW"}),
			wantContains: "exit status 1",
		},
		{
			name:         "create refused before prompting",
			auth:         &recordingAuthorizer{decision: allow()},
			call:         structuredCall("c1", filetools.CreateToolName, map[string]any{"path": "main.go", "content": "x"}),
			wantContains: "create target rejected",
		},
		{
			name:         "successful read",
			auth:         &recordingAuthorizer{decision: allow()},
			call:         structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "main.go"}),
			wantContains: "package OLD",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, project := writeDispatcher(t, tc.auth)
			file := filepath.Join(project, "main.go")
			if err := os.WriteFile(file, []byte("package OLD\n"), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			res, derr := d.Dispatch(context.Background(), tc.call)
			if tc.wantErr != (derr != nil) {
				t.Fatalf("Dispatch error = %v, want error: %v", derr, tc.wantErr)
			}
			if res.WriteTarget != "" {
				t.Fatalf("WriteTarget = %q, want empty: no successful write happened", res.WriteTarget)
			}
			if res.Denied != tc.wantDenied {
				t.Fatalf("res.Denied = %v, want %v; content=%q", res.Denied, tc.wantDenied, res.Content)
			}
			if !strings.Contains(res.Content, tc.wantContains) {
				t.Fatalf("content = %q, want it to contain %q", res.Content, tc.wantContains)
			}
			if got := mustReadFile(t, file); got != "package OLD\n" {
				t.Fatalf("main.go = %q, want it unchanged", got)
			}
		})
	}
}

func TestProductionDispatcher_DeleteTargetNamesTheAuthorizedDeleteApartFromWrites(t *testing.T) {
	auth := &recordingAuthorizer{decision: allow()}
	d, project := writeDispatcher(t, auth)
	file := filepath.Join(project, "old.go")
	if err := os.WriteFile(file, []byte("package old\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	created, derr := d.Dispatch(context.Background(), structuredCall("c1", filetools.CreateToolName, map[string]any{
		"path": "new.go", "content": "package new\n",
	}))
	if derr != nil {
		t.Fatalf("Dispatch(create) error = %v, want nil", derr)
	}
	if created.WriteTarget == "" || created.DeleteTarget != "" {
		t.Fatalf("create WriteTarget/DeleteTarget = %q/%q, want only a write target", created.WriteTarget, created.DeleteTarget)
	}

	deleted, derr := d.Dispatch(context.Background(), structuredCall("c2", filetools.DeleteToolName, map[string]any{"path": "old.go"}))
	if derr != nil {
		t.Fatalf("Dispatch(delete) error = %v, want nil", derr)
	}
	if deleted.DeleteTarget != file || deleted.WriteTarget != "" {
		t.Fatalf("delete WriteTarget/DeleteTarget = %q/%q, want only the delete target %q", deleted.WriteTarget, deleted.DeleteTarget, file)
	}
	if deleted.DeleteTarget != auth.lastModeCtx(t).TargetPath {
		t.Fatalf("delete DeleteTarget = %q, want the exact path authorization decided on (%q)", deleted.DeleteTarget, auth.lastModeCtx(t).TargetPath)
	}
	if _, statErr := os.Lstat(file); !os.IsNotExist(statErr) {
		t.Fatalf("old.go still exists (err=%v), want it deleted", statErr)
	}

	again, derr := d.Dispatch(context.Background(), structuredCall("c3", filetools.DeleteToolName, map[string]any{"path": "old.go"}))
	if derr != nil {
		t.Fatalf("Dispatch(delete again) error = %v, want nil", derr)
	}
	if again.DeleteTarget != "" {
		t.Fatalf("DeleteTarget = %q, want empty: nothing was deleted", again.DeleteTarget)
	}

	denied, project2 := writeDispatcher(t, &recordingAuthorizer{decision: deny(permissions.BuildDenyEnvelope("nope"))})
	kept := filepath.Join(project2, "kept.go")
	if err := os.WriteFile(kept, []byte("package kept\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	refused, derr := denied.Dispatch(context.Background(), structuredCall("c4", filetools.DeleteToolName, map[string]any{"path": "kept.go"}))
	if derr != nil {
		t.Fatalf("Dispatch(denied delete) error = %v, want nil", derr)
	}
	if !refused.Denied || refused.DeleteTarget != "" {
		t.Fatalf("denied delete = %+v, want a denial with no delete target", refused)
	}
	if _, statErr := os.Lstat(kept); statErr != nil {
		t.Fatalf("kept.go was removed by a denied delete: %v", statErr)
	}
}

func TestGeneralAgentBinding_AChildDeleteReachesTheSessionAndBothChildBlocks(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	root, err := filepath.EvalSymlinks(project)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	target := filepath.Join(root, "old.txt")
	if err := os.WriteFile(target, []byte("OLD\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var round int32
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", filetools.DeleteToolName, `{"path":"old.txt"}`)))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("removed it"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	turnStore := func() *sessions.Store { return store }
	parent := &parentTurnHolder{}
	publishParentTurn(parent, active, modeActive)
	live := tui.New(nil)
	reg, err := realizeToolRegistry(&toolRegistryFactory{active: nil}, cache, turnStore, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil), generalAgentBinding{parent: parent, notices: live})
	if err != nil {
		t.Fatalf("realizeToolRegistry: %v", err)
	}
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()}, home, project, turnStore, cache.MaxToolOutputBytes(), securitystate.Policy{})

	res, derr := d.Dispatch(context.Background(), structuredCall("d1", subagenttool.ToolName, map[string]any{
		"instructions": "remove the old file", "files_delete": []any{"old.txt"},
	}))
	if derr != nil || res.Denied {
		t.Fatalf("Dispatch(general_agent) = %+v, %v; want the child to run", res, derr)
	}
	if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
		t.Fatalf("old.txt still exists (err=%v); result=%q", statErr, res.Content)
	}

	reloaded := reloadStore(t, store)
	starts := decodeStoreEvents[events.ChildAgentStart](t, reloaded, events.KindChildAgentStart)
	ends := decodeStoreEvents[events.ChildAgentEnd](t, reloaded, events.KindChildAgentEnd)
	if len(starts) != 1 || len(ends) != 1 {
		t.Fatalf("child lifecycle records = %d start / %d end, want 1/1", len(starts), len(ends))
	}
	if len(starts[0].DeclaredPaths) != 0 || !slices.Equal(starts[0].DeclaredDeletePaths, []string{target}) {
		t.Fatalf("start declared_paths/declared_delete_paths = %v / %v, want none / [%s]", starts[0].DeclaredPaths, starts[0].DeclaredDeletePaths, target)
	}
	if ends[0].Reason != events.ChildAgentReasonCompleted || len(ends[0].WrittenPaths) != 0 || !slices.Equal(ends[0].DeletedPaths, []string{target}) {
		t.Fatalf("end = %+v, want a completed child with no writes and deleted_paths [%s]", ends[0], target)
	}

	replayed := tui.New(nil)
	replayed.ReplaySessionRecords(reloaded.Records())
	for name, app := range map[string]*tui.App{"live": live, "replayed": replayed} {
		text := app.TranscriptText()
		for _, want := range []string{"may delete:", "deleted 1 file(s), none undone:", "    " + target} {
			if !strings.Contains(text, want) {
				t.Errorf("%s child block = %q, want it to contain %q", name, text, want)
			}
		}
		for _, unwanted := range []string{"may write:", "changed no files"} {
			if strings.Contains(text, unwanted) {
				t.Errorf("%s child block = %q, want no %q for a delete-only child", name, text, unwanted)
			}
		}
	}
}

func TestGeneralAgentBinding_AChildMoveReachesTheSessionAndBothChildBlocks(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	root, err := filepath.EvalSymlinks(project)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	source := filepath.Join(root, "old.txt")
	destination := filepath.Join(root, "new.txt")
	if err := os.WriteFile(source, []byte("OLD\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var round int32
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", filetools.MoveToolName, `{"source":"old.txt","destination":"new.txt"}`)))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("renamed it"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	turnStore := func() *sessions.Store { return store }
	parent := &parentTurnHolder{}
	publishParentTurn(parent, active, modeActive)
	live := tui.New(nil)
	reg, err := realizeToolRegistry(&toolRegistryFactory{active: nil}, cache, turnStore, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil), generalAgentBinding{parent: parent, notices: live})
	if err != nil {
		t.Fatalf("realizeToolRegistry: %v", err)
	}
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()}, home, project, turnStore, cache.MaxToolOutputBytes(), securitystate.Policy{})

	res, derr := d.Dispatch(context.Background(), structuredCall("d1", subagenttool.ToolName, map[string]any{
		"instructions": "rename the old file", "files_move": []any{map[string]any{"source": "old.txt", "destination": "new.txt"}},
	}))
	if derr != nil || res.Denied {
		t.Fatalf("Dispatch(general_agent) = %+v, %v; want the child to run", res, derr)
	}
	if _, statErr := os.Lstat(source); !os.IsNotExist(statErr) {
		t.Fatalf("old.txt still exists (err=%v); result=%q", statErr, res.Content)
	}
	if got := mustReadFile(t, destination); got != "OLD\n" {
		t.Fatalf("new.txt = %q, want the moved file", got)
	}

	reloaded := reloadStore(t, store)
	starts := decodeStoreEvents[events.ChildAgentStart](t, reloaded, events.KindChildAgentStart)
	ends := decodeStoreEvents[events.ChildAgentEnd](t, reloaded, events.KindChildAgentEnd)
	if len(starts) != 1 || len(ends) != 1 {
		t.Fatalf("child lifecycle records = %d start / %d end, want 1/1", len(starts), len(ends))
	}
	wantPairs := []events.ChildMovePair{{Source: source, Destination: destination}}
	if len(starts[0].DeclaredPaths) != 0 || len(starts[0].DeclaredDeletePaths) != 0 || !slices.Equal(starts[0].DeclaredMovePairs, wantPairs) {
		t.Fatalf("start declared_paths/declared_delete_paths/declared_move_pairs = %v / %v / %v, want none / none / %v", starts[0].DeclaredPaths, starts[0].DeclaredDeletePaths, starts[0].DeclaredMovePairs, wantPairs)
	}
	if ends[0].Reason != events.ChildAgentReasonCompleted || len(ends[0].WrittenPaths) != 0 || len(ends[0].DeletedPaths) != 0 || !slices.Equal(ends[0].MovedPairs, wantPairs) {
		t.Fatalf("end = %+v, want a completed child with no writes or deletes and moved_pairs %v", ends[0], wantPairs)
	}

	replayed := tui.New(nil)
	replayed.ReplaySessionRecords(reloaded.Records())
	for name, app := range map[string]*tui.App{"live": live, "replayed": replayed} {
		text := app.TranscriptText()
		for _, want := range []string{"may move:", "moved 1 file(s), none undone:", "    " + source + " -> " + destination} {
			if !strings.Contains(text, want) {
				t.Errorf("%s child block = %q, want it to contain %q", name, text, want)
			}
		}
		for _, unwanted := range []string{"may write:", "may delete:", "changed no files"} {
			if strings.Contains(text, unwanted) {
				t.Errorf("%s child block = %q, want no %q for a move-only child", name, text, unwanted)
			}
		}
	}
}

type ctxObservingTool struct{ name string }

func (t *ctxObservingTool) Name() string              { return t.name }
func (t *ctxObservingTool) SubjectKind() string       { return "tool" }
func (t *ctxObservingTool) Advertise() tools.Metadata { return tools.Metadata{} }
func (t *ctxObservingTool) Invoke(ctx context.Context, _ map[string]any) (tools.Result, error) {
	if err := ctx.Err(); err != nil {
		return tools.Result{}, err
	}
	return tools.Result{Stdout: []byte("ran\n")}, nil
}

func TestProductionDispatcher_CancelledContextStopsToolsBeforeInvocation(t *testing.T) {
	auth := &recordingAuthorizer{decision: allow()}
	d, project := writeDispatcher(t, auth)
	file := filepath.Join(project, "main.go")
	if err := os.WriteFile(file, []byte("package OLD\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, derr := d.Dispatch(ctx, structuredCall("c1", filetools.EditToolName, map[string]any{
		"path": "main.go", "old_text": "OLD", "new_text": "NEW",
	}))
	if !errors.Is(derr, context.Canceled) {
		t.Fatalf("Dispatch(edit) error = %v, want cancellation before invocation", derr)
	}
	if got := mustReadFile(t, file); got != "package OLD\n" {
		t.Fatalf("main.go = %q, want the write not to start", got)
	}
	entries, err := os.ReadDir(project)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("project holds %d entries, want only the published file: %v", len(entries), entries)
	}

	reg := tools.NewRegistry()
	if err := reg.Register(tools.BuiltinSource, &ctxObservingTool{name: "do_thing"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	other := dispatcherFor(t, reg, &fakeDispatchRunner{}, auth)
	if _, derr := other.Dispatch(ctx, structuredCall("c2", "do_thing", map[string]any{})); !errors.Is(derr, context.Canceled) {
		t.Fatalf("Dispatch(do_thing) error = %v, want the parent cancellation to reach an ordinary tool", derr)
	}
}

func TestGeneralAgentBinding_ChildDispatcherAttributesItsToolExecEvents(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	store := mkStore(t)
	reg, err := realizeToolRegistry(&toolRegistryFactory{active: nil}, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil),
		generalAgentTestBinding(active, modeActive))
	if err != nil {
		t.Fatalf("realizeToolRegistry: %v", err)
	}
	binding := generalAgentTestBinding(active, modeActive)
	deps := binding.deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
	if deps.Store == nil || deps.Store() != store {
		t.Fatal("delegate deps carry no accessor for the run's turn store, so no child record could reach the parent session")
	}

	first, second := ids.NewV7(), ids.NewV7()
	for _, child := range []string{first, second, ""} {
		disp := deps.NewDispatcher(permissions.ModeContext{
			Mode:              string(mode.Build),
			ChildAgent:        child != "",
			ChildInvocationID: child,
			DeclaredWrite:     map[string]bool{filepath.Join(project, "main.go"): true},
		})
		prod, ok := disp.(*productionToolDispatcher)
		if !ok {
			t.Fatalf("NewDispatcher returned %T, want *productionToolDispatcher", disp)
		}
		prod.runner = &fakeDispatchRunner{}
		prod.authorizer = &recordingAuthorizer{decision: allow()}
		if _, err := prod.Dispatch(context.Background(), bashCall("c1", "echo hi")); err != nil {
			t.Fatalf("Dispatch error = %v, want nil", err)
		}
	}

	reloaded := reloadStore(t, store)
	starts := decodeStoreEvents[events.ToolExecStart](t, reloaded, events.KindToolExecStart)
	ends := decodeStoreEvents[events.ToolExecEnd](t, reloaded, events.KindToolExecEnd)
	if len(starts) != 3 || len(ends) != 3 {
		t.Fatalf("tool_exec events = %d start/%d end, want 3/3", len(starts), len(ends))
	}
	want := []string{first, second, ""}
	for i, id := range want {
		if starts[i].ChildInvocationID != id {
			t.Errorf("tool_exec_start %d child_invocation_id = %q, want %q", i, starts[i].ChildInvocationID, id)
		}
		if ends[i].ChildInvocationID != id {
			t.Errorf("tool_exec_end %d child_invocation_id = %q, want %q", i, ends[i].ChildInvocationID, id)
		}
	}
	if starts[0].ChildInvocationID == starts[1].ChildInvocationID {
		t.Fatal("two disjoint children shared one child_invocation_id, so their records are indistinguishable")
	}
}

func TestHeadlessAuthorizer_AttributesAChildsPermissionEvents(t *testing.T) {
	cache, _, project, _, modeActive := generalAgentFixture(t)
	store := mkStore(t)
	child := ids.NewV7()
	target := filepath.Join(project, "main.go")

	for _, id := range []string{child, ""} {
		auth := newHeadlessAuthorizer(cache, func() *sessions.Store { return store }, modeActive, nil, &recordingNotices{})
		auth.childAgent = id != ""
		auth.childInvocationID = id
		auth.declaredWrite = map[string]bool{target: true}
		req := permissions.MatchRequest{Kind: "tool", Subject: filetools.EditToolName, PathScope: target}
		disp := dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: filetools.EditToolName}
		if _, err := auth.Authorize(context.Background(), req, disp, permissions.ModeContext{
			Class:      permissions.ClassMutating,
			ToolName:   filetools.EditToolName,
			TargetPath: target,
		}); err != nil {
			t.Fatalf("Authorize error = %v, want nil", err)
		}
	}

	matched := decodeStoreEvents[events.PermissionMatched](t, reloadStore(t, store), events.KindPermissionMatched)
	if len(matched) != 2 {
		t.Fatalf("permission_matched events = %d, want 2", len(matched))
	}
	if matched[0].ChildInvocationID != child {
		t.Errorf("child permission_matched child_invocation_id = %q, want %q", matched[0].ChildInvocationID, child)
	}
	if matched[1].ChildInvocationID != "" {
		t.Errorf("parent permission_matched child_invocation_id = %q, want it omitted", matched[1].ChildInvocationID)
	}
}

// The live child-agent surface is discovered on the notice renderer the binding already
// holds, so the TUI site needs no extra wiring: the app implements the sink and receives it,
// while the headless stderr renderer does not and leaves the delegate exactly as it was.
func TestGeneralAgentBinding_ActivitySinkComesFromTheNoticeRenderer(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	reg := generalAgentRegistry(t, cache, home, project, active, modeActive)
	store := mkStore(t)
	parent := &parentTurnHolder{}
	turnStore := func() *sessions.Store { return store }

	app := tui.New(nil)
	withApp := generalAgentBinding{parent: parent, notices: app}.deps(reg, cache, turnStore, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
	if sink, ok := withApp.Activity.(*tui.App); !ok || sink != app {
		t.Fatalf("activity sink = %#v, want the app that already renders this run's notices", withApp.Activity)
	}

	headless := generalAgentBinding{parent: parent, notices: stderrNoticeRenderer{w: io.Discard}}.deps(reg, cache, turnStore, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
	if headless.Activity != nil {
		t.Fatalf("activity sink = %#v, want none: the headless renderer implements no live surface", headless.Activity)
	}
}

func seedChildMoveProject(t *testing.T, project string) {
	t.Helper()
	for _, dir := range []string{"work", "other"} {
		if err := os.MkdirAll(filepath.Join(project, dir), 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", dir, err)
		}
	}
	for _, name := range []string{filepath.Join("work", "notes.txt"), filepath.Join("work", "sibling.txt"), filepath.Join("other", "notes.txt"), "linked.txt", "second.txt"} {
		if err := os.WriteFile(filepath.Join(project, name), []byte("body\n"), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
	}
	for link, target := range map[string]string{"link.txt": "linked.txt", "worklink": "work", "otherlink": "other"} {
		if err := os.Symlink(filepath.Join(project, target), filepath.Join(project, link)); err != nil {
			t.Fatalf("Symlink %s: %v", link, err)
		}
	}
}

func resolveMovePairs(t *testing.T, home, project string, pairs ...[2]string) map[permissions.MovePair]bool {
	t.Helper()
	mover := filetools.NewMoveTool(home, project, project)
	moves := make(map[permissions.MovePair]bool, len(pairs))
	for _, pair := range pairs {
		resolved, err := mover.ResolveEndpoints(map[string]any{"source": pair[0], "destination": pair[1]})
		if err != nil {
			t.Fatalf("ResolveEndpoints(%v): %v", pair, err)
		}
		moves[permissions.MovePair{Source: resolved.Source, Destination: resolved.Destination}] = true
	}
	return moves
}

func childMovesFixture(t *testing.T, pairs ...[2]string) (turn.ToolDispatcher, *sessions.Store, string, string, map[permissions.MovePair]bool) {
	t.Helper()
	cache, home, project, active, modeActive := generalAgentFixture(t)
	seedChildMoveProject(t, project)
	moves := resolveMovePairs(t, home, project, pairs...)
	store := mkStore(t)
	reg := generalAgentRegistry(t, cache, home, project, active, modeActive)
	deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
	return deps.NewDispatcher(permissions.ModeContext{
		Mode:          string(mode.Build),
		ChildAgent:    true,
		DeclaredMoves: moves,
	}), store, home, project, moves
}

func moveCall(id, source, destination string) turn.AssembledToolCall {
	return structuredCall(id, filetools.MoveToolName, map[string]any{"source": source, "destination": destination})
}

func TestChildCeiling_MovesADeclaredPairAndRefusesEndpointsFromTwoPairs(t *testing.T) {
	d, store, _, project, _ := childMovesFixture(t, [2]string{"work/notes.txt", "work/renamed.txt"}, [2]string{"second.txt", "work/second.txt"})

	res, err := d.Dispatch(context.Background(), moveCall("m1", "work/notes.txt", "work/second.txt"))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	reason := assertChildScopeDenial(t, store, 0, res)
	if !strings.Contains(reason, "files_move does not declare this source and destination as one pair") {
		t.Fatalf("reason %q does not name the undeclared pair", reason)
	}
	if _, statErr := os.Lstat(filepath.Join(project, "work", "second.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("work/second.txt exists (err=%v) after a refused move", statErr)
	}

	res, err = d.Dispatch(context.Background(), moveCall("m2", "work/notes.txt", "work/renamed.txt"))
	if err != nil || res.Denied {
		t.Fatalf("declared move = %+v, %v; want it authorized", res, err)
	}
	matched := decodePermissionMatched(t, store)
	if len(matched) != 2 || matched[1].OutcomeSource != permissions.OutcomeSourceDeclaredScope || matched[1].Outcome != "once" {
		t.Fatalf("permission_matched = %+v, want the refusal then one declared_scope/once", matched)
	}
	if body, rerr := os.ReadFile(filepath.Join(project, "work", "renamed.txt")); rerr != nil || string(body) != "body\n" {
		t.Fatalf("work/renamed.txt = %q (err=%v), want the moved file", body, rerr)
	}
	if _, statErr := os.Lstat(filepath.Join(project, "work", "notes.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("work/notes.txt still exists (err=%v), want it moved", statErr)
	}
}

func TestChildCeiling_AMovePairGrantsNoWriteOnItsDestinationAndNoDeleteOfItsSource(t *testing.T) {
	declared := [2]string{"work/notes.txt", "work/renamed.txt"}

	t.Run("no write on the destination", func(t *testing.T) {
		d, store, _, project, _ := childMovesFixture(t, declared)
		res, err := d.Dispatch(context.Background(), structuredCall("w1", filetools.CreateToolName, map[string]any{"path": "work/renamed.txt", "content": "x"}))
		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil", err)
		}
		assertChildScopeDenial(t, store, 0, res)
		if _, statErr := os.Lstat(filepath.Join(project, "work", "renamed.txt")); !os.IsNotExist(statErr) {
			t.Fatalf("work/renamed.txt exists (err=%v), want no write authorized by a move pair", statErr)
		}
	})

	t.Run("no delete of the source", func(t *testing.T) {
		d, store, _, project, _ := childMovesFixture(t, declared)
		res, err := d.Dispatch(context.Background(), structuredCall("r1", filetools.DeleteToolName, map[string]any{"path": "work/notes.txt"}))
		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil", err)
		}
		assertChildScopeDenial(t, store, 0, res)
		if _, statErr := os.Lstat(filepath.Join(project, "work", "notes.txt")); statErr != nil {
			t.Fatalf("work/notes.txt was removed (err=%v), want no delete authorized by a move pair", statErr)
		}
	})
}

func TestChildCeiling_MoveBypassAttemptsDenyOnBothEndpoints(t *testing.T) {
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	beyond := filepath.Join(outside, "beyond.txt")
	if err := os.WriteFile(beyond, []byte("outside\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	declared := [2]string{"work/notes.txt", "work/renamed.txt"}
	tests := []struct {
		name                string
		source, destination string
		caseVariant         bool
	}{
		{name: "source: a traversal to another file", source: "work/../linked.txt", destination: "work/renamed.txt"},
		{name: "destination: a traversal to another path", source: "work/notes.txt", destination: "work/../renamed.txt"},
		{name: "source: a parent symlink to another directory", source: "otherlink/notes.txt", destination: "work/renamed.txt"},
		{name: "destination: a parent symlink to another directory", source: "work/notes.txt", destination: "otherlink/renamed.txt"},
		{name: "source: a differently-normalized spelling of another file", source: "./work/./sibling.txt", destination: "work/renamed.txt"},
		{name: "destination: a differently-normalized spelling of another path", source: "work/notes.txt", destination: "./work/./elsewhere.txt"},
		{name: "source: an absolute path outside the project root", source: beyond, destination: "work/renamed.txt"},
		{name: "destination: an absolute path outside the project root", source: "work/notes.txt", destination: filepath.Join(outside, "new.txt")},
		{name: "source: a trailing-slash spelling of another file", source: "work/sibling.txt/", destination: "work/renamed.txt"},
		{name: "destination: a trailing-slash spelling of another path", source: "work/notes.txt", destination: "work/trailing.txt/"},
		{name: "source: a case-variant spelling", source: "work/NOTES.txt", destination: "work/renamed.txt", caseVariant: true},
		{name: "destination: a case-variant spelling", source: "work/notes.txt", destination: "work/RENAMED.txt", caseVariant: true},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, store, home, project, moves := childMovesFixture(t, declared)
			if tc.caseVariant {
				variant := filepath.Join(project, "work", "NOTES.txt")
				if _, serr := os.Lstat(variant); serr == nil {
					t.Skip("this volume is case-insensitive, so a case variant names the declared path itself")
				}
				if werr := os.WriteFile(variant, []byte("variant\n"), 0o644); werr != nil {
					t.Fatalf("WriteFile: %v", werr)
				}
			}
			resolved, rerr := filetools.NewMoveTool(home, project, project).ResolveEndpoints(map[string]any{"source": tc.source, "destination": tc.destination})
			if rerr != nil {
				t.Fatalf("ResolveEndpoints = %v, want the row to reach authorization", rerr)
			}
			if moves[permissions.MovePair{Source: resolved.Source, Destination: resolved.Destination}] {
				t.Fatalf("row resolves to the declared pair %s -> %s, so it proves nothing", resolved.Source, resolved.Destination)
			}

			res, derr := d.Dispatch(context.Background(), moveCall(fmt.Sprintf("bypass-%d", i), tc.source, tc.destination))
			if derr != nil {
				t.Fatalf("Dispatch error = %v, want nil", derr)
			}
			assertChildScopeDenial(t, store, 0, res)
			if _, statErr := os.Lstat(resolved.Source); statErr != nil {
				t.Fatalf("source %s was moved by a refused call: %v", resolved.Source, statErr)
			}
			if _, statErr := os.Lstat(resolved.Destination); !os.IsNotExist(statErr) {
				t.Fatalf("destination %s exists after a refused call (err=%v)", resolved.Destination, statErr)
			}
		})
	}

	t.Run("a canonical alias of both declared endpoints moves", func(t *testing.T) {
		d, store, _, project, _ := childMovesFixture(t, declared)
		res, err := d.Dispatch(context.Background(), moveCall("alias", "worklink/notes.txt", filepath.Join(project, "work", "renamed.txt")+"/"))
		if err != nil || res.Denied {
			t.Fatalf("aliased declared move = %+v, %v; want it authorized", res, err)
		}
		if matched := decodePermissionMatched(t, store); len(matched) != 1 || matched[0].OutcomeSource != permissions.OutcomeSourceDeclaredScope || matched[0].Outcome != "once" {
			t.Fatalf("permission_matched = %+v, want exactly one declared_scope/once", matched)
		}
		if _, statErr := os.Lstat(filepath.Join(project, "work", "renamed.txt")); statErr != nil {
			t.Fatalf("work/renamed.txt was not moved into place: %v", statErr)
		}
	})
}

func TestChildCeiling_NestedGeneralAgentMovePairsMatchOnlyAsWholePairs(t *testing.T) {
	renamed := [2]string{"work/notes.txt", "work/renamed.txt"}
	second := [2]string{"second.txt", "work/second.txt"}
	tests := []struct {
		name        string
		parentWrite []string
		parent      [][2]string
		nested      [2]string
		wantDenied  bool
	}{
		{name: "a declared pair starts the grandchild", parent: [][2]string{renamed, second}, nested: renamed},
		{name: "endpoints recombined from two parent pairs are refused", parent: [][2]string{renamed, second}, nested: [2]string{"work/notes.txt", "work/second.txt"}, wantDenied: true},
		{name: "a parent with no move pairs admits none", parentWrite: []string{"work/renamed.txt"}, nested: renamed, wantDenied: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cache, home, project, active, modeActive := generalAgentFixture(t)
			seedChildMoveProject(t, project)
			write, _, err := filetools.ResolveDeclaredScopes(home, project, tc.parentWrite, nil)
			if err != nil {
				t.Fatalf("ResolveDeclaredScopes: %v", err)
			}
			store := mkStore(t)
			probe := &generalAgentProbe{}
			reg := tools.NewRegistry()
			if rerr := reg.Register(tools.BuiltinSource, subagenttool.New(subagenttool.Deps{
				Home: home, LaunchDir: project, ProjectRoot: project,
				Snapshot:      probe.snapshot,
				NewDispatcher: probe.newDispatcher,
				Store:         func() *sessions.Store { return store },
			})); rerr != nil {
				t.Fatalf("Register general_agent: %v", rerr)
			}
			deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
			d := deps.NewDispatcher(permissions.ModeContext{
				Mode:          string(mode.Build),
				ChildAgent:    true,
				DeclaredWrite: write,
				DeclaredMoves: resolveMovePairs(t, home, project, tc.parent...),
			})

			args := map[string]any{"instructions": "do it", "files_move": []any{map[string]any{"source": tc.nested[0], "destination": tc.nested[1]}}}
			res, derr := d.Dispatch(context.Background(), structuredCall("n1", subagenttool.ToolName, args))
			if derr != nil {
				t.Fatalf("Dispatch error = %v, want nil", derr)
			}
			if res.Denied != tc.wantDenied {
				t.Fatalf("result = %+v, want denied=%v", res, tc.wantDenied)
			}
			if matched := decodePermissionMatched(t, store); len(matched) != 1 || matched[0].OutcomeSource != permissions.OutcomeSourceDeclaredScope {
				t.Fatalf("permission_matched = %+v, want exactly one declared_scope decision", matched)
			}
			wantStarts := 1
			if tc.wantDenied {
				wantStarts = 0
			}
			if probe.started() != wantStarts {
				t.Fatalf("grandchild starts = %d, want %d", probe.started(), wantStarts)
			}
			if !tc.wantDenied {
				return
			}
			if _, reason := decodeDenyEnvelope(t, res.Content); !strings.Contains(reason, "nested general_agent call may declare in files_move only whole move pairs") {
				t.Fatalf("reason %q does not name the nested move-pair rule", reason)
			}
		})
	}
}

func TestProductionDispatcher_ConfinedBashRefusalIsInBand(t *testing.T) {
	onlyHere := programDir(t, "zzconfinedprobe")
	t.Setenv("PATH", onlyHere+string(os.PathListSeparator)+os.Getenv("PATH"))
	lsDir := programDir(t, "ls")
	for _, tc := range []struct{ command, want string }{
		{"PATH=" + lsDir + " ls", "PATH"},
		{"zzconfinedprobe", "zzconfinedprobe"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			run := &fakeDispatchRunner{}
			d := dispatcherFor(t, tools.NewRegistry(), run, &recordingAuthorizer{decision: allow()})
			d.confinement = &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), blocked: testBlocked(t)}

			res, err := d.Dispatch(context.Background(), bashCall("c1", tc.command))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want an in-band refusal", err)
			}
			if !strings.Contains(res.Content, tc.want) || !strings.Contains(res.Content, "before starting any process") {
				t.Fatalf("content = %q, want it to name %s and say nothing was started", res.Content, tc.want)
			}
			if run.callCount() != 0 {
				t.Fatalf("runner calls = %d, want 0", run.callCount())
			}
			if n := len(kindEvents(t, d.active(), events.KindToolExecStart)) + len(kindEvents(t, d.active(), events.KindToolExecEnd)); n != 0 {
				t.Fatalf("tool_exec records = %d, want 0", n)
			}
		})
	}
}

func confinedVCSRegistry(t *testing.T, conf *confinement, inner *confineInner) (*tools.Registry, generalAgentBinding, *config.Cache, string, string, *sessions.Store) {
	t.Helper()
	cache, home, project, active, modeActive := generalAgentFixture(t)
	store := mkStore(t)
	prev := newVCSActionRunner
	newVCSActionRunner = func() cmdrunner.Runner { return inner }
	t.Cleanup(func() { newVCSActionRunner = prev })
	binding := generalAgentTestBinding(active, modeActive)
	binding.confinement = conf
	factory := &toolRegistryFactory{active: &ActiveVCS{Template: productVettedGitTemplate(t), RepoRoot: project}}
	reg, err := realizeToolRegistry(factory, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil), binding)
	if err != nil {
		t.Fatalf("realizeToolRegistry: %v", err)
	}
	return reg, binding, cache, home, project, store
}

func TestProductionDispatcher_ConfinedVCSSharesTheRealizedConfinement(t *testing.T) {
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: t.TempDir(), blocked: testBlocked(t)}
	inner := &confineInner{}
	reg, _, cache, home, project, store := confinedVCSRegistry(t, conf, inner)
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()}, home, project,
		func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
	d.confinement = conf

	res, err := d.Dispatch(context.Background(), structuredCall("c1", "vcs_status", map[string]any{}))
	if err != nil {
		t.Fatalf("Dispatch error = %v", err)
	}
	if !strings.Contains(res.Content, `"git"`) || !strings.Contains(res.Content, "before starting any process") || inner.calls() != 0 {
		t.Fatalf("content = %q, inner calls = %d, want the lookup refusal in-band and nothing run", res.Content, inner.calls())
	}
	reloaded := reloadStore(t, store)
	if s, e := len(kindEvents(t, reloaded, events.KindToolExecStart)), len(kindEvents(t, reloaded, events.KindToolExecEnd)); s != 1 || e != 1 {
		t.Fatalf("tool_exec records = %d start/%d end, want one pair", s, e)
	}

	conf.lookupPath = programDir(t, "git")
	if _, err := d.Dispatch(context.Background(), structuredCall("c2", "vcs_status", map[string]any{})); err != nil {
		t.Fatalf("Dispatch error = %v", err)
	}
	if len(inner.bounded) != 1 || len(inner.execs) != 0 || inner.boundedCap != cache.MaxToolOutputBytes() {
		t.Fatalf("bounded/exec = %d/%d at cap %d, want one bounded run at the output cap", len(inner.bounded), len(inner.execs), inner.boundedCap)
	}
	got := inner.bounded[0]
	want, err := cmdrunner.FixedEnvironment(conf.blocked.Home(), got.Cwd, "", conf.lookupPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Env, helperLaunchEnv(t, want)) {
		t.Fatalf("vcs env = %v, want the fixed environment %v", got.Env, want)
	}
	wantHelperArgv(t, got.Argv, filepath.Join(conf.lookupPath, "git"), "status", "--short")
	if policy, _ := decodeFrame(t, got.Stdin); policy.Mode != string(mode.Plan) {
		t.Fatalf("vcs policy = %+v, want plan", policy)
	}
}

func TestGeneralAgentBinding_ChildConfinementUsesItsFrozenMode(t *testing.T) {
	lookup := t.TempDir()
	for name, body := range map[string]string{"ls": "#!/bin/sh\necho CONFINED-LS\n", "git": "#!/bin/sh\n"} {
		if err := os.WriteFile(filepath.Join(lookup, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	launch := string(mode.Build)
	conf := &confinement{constrained: true, mode: func() string { return launch }, home: "/launch-home", lookupPath: lookup,
		projectRoot: "/launch-project", blocked: permissions.NewBlockedPaths("/launch-home", nil), tmpDir: "/launch-tmp"}
	inner := &confineInner{}
	childInner := &confineInner{}
	prevChild := newChildToolRunner
	newChildToolRunner = func() cmdrunner.Runner { return childInner }
	t.Cleanup(func() { newChildToolRunner = prevChild })
	reg, binding, cache, home, project, store := confinedVCSRegistry(t, conf, inner)
	deps := binding.deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))

	child, ok := deps.NewDispatcher(permissions.ModeContext{Mode: string(mode.Plan)}).(*productionToolDispatcher)
	if !ok {
		t.Fatal("NewDispatcher did not return a production dispatcher")
	}
	if child.confinement == nil || child.confinement == conf {
		t.Fatalf("child confinement = %p, want a copy of %p", child.confinement, conf)
	}
	copied := *child.confinement
	copied.mode, conf.mode = nil, nil
	if !reflect.DeepEqual(copied, *conf) {
		t.Fatalf("child confinement = %+v, want the parent's values %+v", copied, *conf)
	}
	conf.mode = func() string { return launch }
	if got := child.confinement.mode(); got != string(mode.Plan) {
		t.Fatalf("child mode = %q, want the frozen plan", got)
	}

	res, err := child.Dispatch(context.Background(), structuredCall("c1", "vcs_status", map[string]any{}))
	if err != nil || res.Denied {
		t.Fatalf("child vcs Dispatch = %+v, err = %v", res, err)
	}
	if len(inner.bounded) != 1 || inner.bounded[0].Env == nil {
		t.Fatalf("child vcs runs bounded/exec = %d/%d, want one confined run in the frozen plan mode", len(inner.bounded), len(inner.execs))
	}

	if _, err := child.Dispatch(context.Background(), bashCall("c2", "ls")); err != nil {
		t.Fatalf("child bash Dispatch error = %v", err)
	}
	if len(childInner.bounded) != 1 || len(childInner.execs) != 0 {
		t.Fatalf("child bash runs bounded/exec = %d/%d, want one recorded confined run", len(childInner.bounded), len(childInner.execs))
	}
	wantHelperArgv(t, childInner.bounded[0].Argv, filepath.Join(lookup, "ls"))
	if policy, _ := decodeFrame(t, childInner.bounded[0].Stdin); policy.Mode != string(mode.Plan) {
		t.Fatalf("child policy = %+v, want the frozen plan mode", policy)
	}
}

func TestGeneralAgentBinding_AChildWithoutConfinementKeepsItsOwnMode(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	store := mkStore(t)
	deps := generalAgentTestBinding(active, modeActive).deps(tools.NewRegistry(), cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
	child, ok := deps.NewDispatcher(permissions.ModeContext{Mode: string(mode.Plan), ChildAgent: true}).(*productionToolDispatcher)
	if !ok || child.confinement != nil {
		t.Fatalf("NewDispatcher = %+v, want an unconfined production dispatcher", child)
	}
	ctx := vcs.WithConfinementMode(context.Background(), string(mode.Build))
	if got, ok := vcs.ConfinementMode(child.pinMode(ctx)); !ok || got != string(mode.Plan) {
		t.Fatalf("child call mode = %q (pinned %v), want its inherited plan over the caller's build", got, ok)
	}
}

type childModeRound struct {
	before func()
	chunks [][]byte
}

type childModeHarness struct {
	d          *productionToolDispatcher
	modeActive *mode.ActiveState
	cache      *config.Cache
	home       string
	store      *sessions.Store
	script     []childModeRound
	advertised [][]string
	ran        []string
}

func newChildModeHarness(t *testing.T, published mode.Mode, wiring string) *childModeHarness {
	t.Helper()
	cache, home, project, active, _ := generalAgentFixture(t)
	h := &childModeHarness{modeActive: mode.NewActiveState(published, mode.SourceUserCommand), cache: cache, home: home, store: mkStore(t)}
	turnStore := func() *sessions.Store { return h.store }
	inner := &confineInner{
		onBounded: func(spec cmdrunner.RunSpec) {
			policy, _ := decodeFrame(t, spec.Stdin)
			h.ran = append(h.ran, policy.Mode)
		},
		onExec: func(cmdrunner.RunSpec) { h.ran = append(h.ran, "unconfined") },
	}
	prevVCS := newVCSActionRunner
	newVCSActionRunner = func() cmdrunner.Runner { return inner }
	t.Cleanup(func() { newVCSActionRunner = prevVCS })
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		h.advertised = append(h.advertised, toolNames(req.Tools))
		next := childModeRound{chunks: [][]byte{contentChunk("done"), finishChunk("stop")}}
		if len(h.script) > 0 {
			next, h.script = h.script[0], h.script[1:]
		}
		if next.before != nil {
			next.before()
		}
		return provider.Response{Stream: newStream(next.chunks...)}, nil
	}}
	t.Cleanup(swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client }))

	var top, bound *confinement
	live := func() *confinement {
		return &confinement{constrained: true, mode: liveMode(h.modeActive), lookupPath: programDir(t, "git"), blocked: testBlocked(t), tmpDir: t.TempDir(), projectRoot: project}
	}
	switch wiring {
	case "shared":
		top = live()
		bound = top
	case "unbound":
		top = live()
	case "readerless":
		top = &confinement{constrained: true, blocked: testBlocked(t)}
		bound = top
	case "none":
	default:
		t.Fatalf("unknown wiring %q", wiring)
	}
	parent := &parentTurnHolder{}
	publishParentTurn(parent, active, h.modeActive)
	guard := mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil)
	factory := &toolRegistryFactory{active: &ActiveVCS{Template: productVettedGitTemplate(t), RepoRoot: project}}
	reg, err := realizeToolRegistry(factory, cache, turnStore, home, project, guard, generalAgentBinding{parent: parent, notices: &recordingNotices{}, confinement: bound})
	if err != nil {
		t.Fatalf("realizeToolRegistry: %v", err)
	}
	auth := newHeadlessAuthorizer(cache, turnStore, h.modeActive, nil, &recordingNotices{})
	auth.executionConstrained = top != nil
	auth.blocked = guard.Blocked
	h.d = newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, turnStore, cache.MaxToolOutputBytes(), guard)
	h.d.confinement = top
	return h
}

func (h *childModeHarness) saveBuildGrant(t *testing.T) {
	t.Helper()
	entry := permissions.PermissionEntry{Kind: "tool", Subject: filetools.CreateToolName, PathScope: h.cache.ProjectRoot(), GrantKind: "folder"}
	seedGrantFile(t, SettingsPath(h.home), entry)
	h.cache.AppendPermission(entry)
}

func (h *childModeHarness) call(t *testing.T, scheduled bool, call turn.AssembledToolCall, from, to mode.Mode) turn.ToolResult {
	t.Helper()
	h.modeActive.ApplyUserCommand(from)
	run := func(ctx context.Context) (turn.ToolResult, error) { return h.d.Dispatch(ctx, call) }
	if scheduled {
		unit := h.d.Plan([]turn.AssembledToolCall{call}, 1).Units[0]
		if slices.Equal(unit.Targets, []string{productionToolDispatchTarget}) {
			t.Fatal("the general_agent call was planned as a serial barrier, want a prepared general_agent unit")
		}
		run = func(ctx context.Context) (turn.ToolResult, error) {
			if err := unit.PreRun(ctx); err != nil {
				return turn.ToolResult{}, err
			}
			return unit.Run(ctx)
		}
	}
	h.modeActive.ApplyUserCommand(to)
	res, err := run(context.Background())
	if err != nil {
		t.Fatalf("general_agent call error = %v", err)
	}
	return res
}

func (h *childModeHarness) childStarts(t *testing.T) int {
	t.Helper()
	return len(decodeStoreEvents[events.ChildAgentStart](t, h.store, events.KindChildAgentStart))
}

func (h *childModeHarness) nestedDenialSources(t *testing.T) []string {
	t.Helper()
	var sources []string
	for _, m := range decodePermissionMatched(t, h.store) {
		if m.Subject == subagenttool.ToolName && m.ChildInvocationID != "" && m.Outcome == "deny" {
			sources = append(sources, m.OutcomeSource)
		}
	}
	return sources
}

func childVCSRound() childModeRound {
	return childModeRound{chunks: [][]byte{toolCallsChunk(toolFrag(0, "v1", "vcs_status", `{}`))}}
}

func nestedWriterRound() childModeRound {
	return childModeRound{chunks: [][]byte{toolCallsChunk(toolFrag(0, "n1", subagenttool.ToolName, `{"instructions":"write","files":["nested.txt"]}`))}}
}

func nestedReaderRound(before func()) childModeRound {
	return childModeRound{before: before, chunks: [][]byte{toolCallsChunk(toolFrag(0, "n2", subagenttool.ToolName, `{"instructions":"look deeper"}`))}}
}

func nestedDenialSource(m mode.Mode) string {
	if m == mode.Plan {
		return "mode_auto"
	}
	return "declared_scope"
}

func readOnlyGeneralAgentCall(id string) turn.AssembledToolCall {
	return structuredCall(id, subagenttool.ToolName, map[string]any{"instructions": "look"})
}

func TestGeneralAgentBinding_ChildRunsUnderTheModeItsCallWasPinnedTo(t *testing.T) {
	for _, tc := range []struct{ from, to mode.Mode }{
		{mode.Build, mode.Plan},
		{mode.Plan, mode.Build},
		{mode.Build, mode.AutoEdits},
		{mode.Build, mode.Build},
		{mode.Plan, mode.Plan},
	} {
		for _, scheduled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_to_%s/scheduled=%v", tc.from, tc.to, scheduled), func(t *testing.T) {
				h := newChildModeHarness(t, tc.from, "shared")
				h.saveBuildGrant(t)

				h.script = []childModeRound{childVCSRound(), nestedWriterRound()}
				if res := h.call(t, scheduled, readOnlyGeneralAgentCall("g1"), tc.from, tc.to); res.Denied {
					t.Fatalf("read-only general_agent = %+v, want a started child", res)
				}
				if h.childStarts(t) != 1 {
					t.Fatalf("children started = %d, want 1", h.childStarts(t))
				}
				if want := []string{ranAs(tc.to)}; !slices.Equal(h.ran, want) {
					t.Fatalf("child vcs runs = %v, want %v", h.ran, want)
				}
				if got, want := h.nestedDenialSources(t), []string{nestedDenialSource(tc.to)}; !slices.Equal(got, want) {
					t.Fatalf("child authorizer denial sources = %v, want %v", got, want)
				}
				if len(h.advertised) == 0 || slices.Contains(h.advertised[0], filetools.CreateToolName) || !slices.Contains(h.advertised[0], "vcs_status") {
					t.Fatalf("read-only child advertised %v, want vcs_status and no create", h.advertised)
				}

				h.advertised = nil
				res := h.call(t, scheduled, structuredCall("g2", subagenttool.ToolName, map[string]any{"instructions": "write it", "files": []any{"out.txt"}}), tc.from, tc.to)
				if tc.to == mode.Plan {
					if !res.Denied || h.childStarts(t) != 1 || len(h.advertised) != 0 {
						t.Fatalf("mutating general_agent under plan = %+v, children %d, provider rounds %d; want a refusal before any child starts", res, h.childStarts(t), len(h.advertised))
					}
					return
				}
				if res.Denied || h.childStarts(t) != 2 {
					t.Fatalf("mutating general_agent under %s = %+v, children %d; want the saved grant to start a child", tc.to, res, h.childStarts(t))
				}
				if len(h.advertised) != 1 || !slices.Contains(h.advertised[0], filetools.CreateToolName) {
					t.Fatalf("writing child advertised %v, want create offered under %s", h.advertised, tc.to)
				}
			})
		}
	}
}

type switchAfterAuthorizer struct {
	dispatch.Authorizer
	after func()
}

func (a switchAfterAuthorizer) Authorize(ctx context.Context, req permissions.MatchRequest, disp dispatch.PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error) {
	dec, err := a.Authorizer.Authorize(ctx, req, disp, modeCtx)
	a.after()
	return dec, err
}

func TestGeneralAgentBinding_ASwitchAfterThePinDoesNotMoveTheChild(t *testing.T) {
	for _, tc := range []struct{ pinned, later mode.Mode }{
		{mode.Plan, mode.Build},
		{mode.Build, mode.Plan},
	} {
		for _, scheduled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_then_%s/scheduled=%v", tc.pinned, tc.later, scheduled), func(t *testing.T) {
				h := newChildModeHarness(t, tc.later, "shared")
				h.d.authorizer = switchAfterAuthorizer{Authorizer: h.d.authorizer, after: func() { h.modeActive.ApplyUserCommand(tc.later) }}

				h.script = []childModeRound{childVCSRound(), nestedWriterRound()}
				if res := h.call(t, scheduled, readOnlyGeneralAgentCall("g1"), tc.later, tc.pinned); res.Denied {
					t.Fatalf("general_agent = %+v, want a started child", res)
				}
				if want := []string{ranAs(tc.pinned)}; !slices.Equal(h.ran, want) {
					t.Fatalf("child vcs runs = %v, want %v", h.ran, want)
				}
				if got, want := h.nestedDenialSources(t), []string{nestedDenialSource(tc.pinned)}; !slices.Equal(got, want) {
					t.Fatalf("child authorizer denial sources = %v, want %v", got, want)
				}
			})
		}
	}
}

func TestGeneralAgentBinding_APlanChildAndItsGrandchildStayPlan(t *testing.T) {
	for _, wiring := range []string{"shared", "unbound"} {
		for _, scheduled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/scheduled=%v", wiring, scheduled), func(t *testing.T) {
				h := newChildModeHarness(t, mode.Build, wiring)
				toBuild := func() { h.modeActive.ApplyUserCommand(mode.Build) }
				done := childModeRound{chunks: [][]byte{contentChunk("done"), finishChunk("stop")}}
				if wiring == "shared" {
					h.script = []childModeRound{childVCSRound(), nestedReaderRound(toBuild), childVCSRound(), nestedWriterRound(), done, nestedWriterRound()}
				} else {
					h.script = []childModeRound{nestedReaderRound(toBuild), nestedWriterRound(), done, nestedWriterRound()}
				}

				if res := h.call(t, scheduled, readOnlyGeneralAgentCall("g1"), mode.Build, mode.Plan); res.Denied {
					t.Fatalf("general_agent = %+v, want a started child", res)
				}
				if m, _ := h.modeActive.Current(); m != mode.Build {
					t.Fatalf("top-level mode = %s, want the switch back to build to have happened mid-child", m)
				}
				if h.childStarts(t) != 2 {
					t.Fatalf("children started = %d, want the child and its grandchild", h.childStarts(t))
				}
				if got := h.nestedDenialSources(t); !slices.Equal(got, []string{"mode_auto", "mode_auto"}) {
					t.Fatalf("child and grandchild denial sources = %v, want both under plan", got)
				}
				for i, names := range h.advertised {
					if slices.Contains(names, filetools.CreateToolName) || !slices.Contains(names, subagenttool.ToolName) {
						t.Fatalf("round %d advertised %v, want the read-only plan surface", i, names)
					}
				}
				if wiring == "shared" && !slices.Equal(h.ran, []string{"plan", "plan"}) {
					t.Fatalf("child and grandchild vcs runs = %v, want both confined under plan", h.ran)
				}
			})
		}
	}
}

func TestGeneralAgentBinding_AnUnpinnedCallFallsBackToThePublishedMode(t *testing.T) {
	for _, wiring := range []string{"none", "readerless"} {
		for _, scheduled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/scheduled=%v", wiring, scheduled), func(t *testing.T) {
				h := newChildModeHarness(t, mode.Build, wiring)
				h.modeActive.ApplyUserCommand(mode.Plan)
				if pinned, ok := vcs.ConfinementMode(h.d.pinMode(context.Background())); ok {
					t.Fatalf("pinMode invented mode %q with no mode reader", pinned)
				}

				h.script = []childModeRound{childVCSRound(), nestedWriterRound()}
				if res := h.call(t, scheduled, readOnlyGeneralAgentCall("g1"), mode.Build, mode.Plan); res.Denied {
					t.Fatalf("general_agent = %+v, want a started child", res)
				}
				if h.childStarts(t) != 1 {
					t.Fatalf("children started = %d, want 1", h.childStarts(t))
				}
				if !slices.Equal(h.ran, []string{"unconfined"}) {
					t.Fatalf("child vcs runs = %v, want the read-only action auto-allowed and run unconfined under build", h.ran)
				}
				if got := h.nestedDenialSources(t); !slices.Equal(got, []string{"declared_scope"}) {
					t.Fatalf("child authorizer denial sources = %v, want the published build mode", got)
				}
			})
		}
	}
}

func TestGeneralAgentBinding_ChildAuthorizerCarriesTheLaunchSelfTest(t *testing.T) {
	launches := map[string]func(t *testing.T) *confinement{
		"headless": func(t *testing.T) *confinement {
			d, _ := runHeadlessCapturingDispatcher(t, headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Plan, mode.SourceDefault)))
			return d.confinement
		},
		"tui": func(t *testing.T) *confinement {
			var conf *confinement
			production := newResumeDeps
			newResumeDeps = func(ctx context.Context, app *tui.App, result *BootstrapResult, lock *resumeLockHolder, cache *config.Cache, active *model.ActiveState, recorder *capabilityRecorder, c *confinement) tui.ResumeDeps {
				conf = c
				return production(ctx, app, result, lock, cache, active, recorder, c)
			}
			defer func() { newResumeDeps = production }()
			_, restore := startCaptured(t, context.Background(), headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Plan, mode.SourceDefault)), io.Discard)
			restore()
			return conf
		},
	}
	child := func(t *testing.T, conf *confinement, inherited bool) (*headlessAuthorizer, *productionToolDispatcher) {
		t.Helper()
		cache, home, project, active, modeActive := generalAgentFixture(t)
		store := mkStore(t)
		binding := generalAgentTestBinding(active, modeActive)
		binding.confinement = conf
		deps := binding.deps(tools.NewRegistry(), cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
		d, ok := deps.NewDispatcher(permissions.ModeContext{Mode: string(mode.Plan), ExecutionConstrained: inherited}).(*productionToolDispatcher)
		if !ok {
			t.Fatal("NewDispatcher did not return a production dispatcher")
		}
		move, ok := d.authorizer.(childMoveAuthorizer)
		if !ok {
			t.Fatalf("child authorizer = %T, want childMoveAuthorizer", d.authorizer)
		}
		auth, ok := move.Authorizer.(*headlessAuthorizer)
		if !ok {
			t.Fatalf("child authorizer = %T, want *headlessAuthorizer", move.Authorizer)
		}
		return auth, d
	}
	for launch, confinementOf := range launches {
		for _, tc := range selfTestCases {
			t.Run(launch+"/"+tc.name, func(t *testing.T) {
				t.Setenv("TMPDIR", t.TempDir())
				swapResolveExecutionCapability(t, tc.resolution)
				conf := confinementOf(t)
				if conf == nil {
					t.Fatal("the launch built no confinement")
				}
				auth, d := child(t, conf, !tc.want)
				if auth.executionConstrained != tc.want || d.confinement == nil || d.confinement.constrained != tc.want {
					t.Fatalf("child authorizer constrained = %v, runner confinement = %+v; want both %v", auth.executionConstrained, d.confinement, tc.want)
				}
			})
		}
	}
	if auth, _ := child(t, nil, true); auth.executionConstrained {
		t.Fatal("a child with no launch confinement was marked constrained")
	}
}

func TestGeneralAgentBinding_ChildFailsClosedOnConstrainedShellWhileSettingsAreBroken(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t, "a")
	guard := mustProtectedStatePolicy(t, f.home, f.project, f.layers(t, true))
	store := mkStore(t)
	binding := generalAgentBinding{parent: &parentTurnHolder{}, notices: &recordingNotices{}, confinement: &confinement{constrained: true}}
	deps := binding.deps(tools.NewRegistry(), emptyCache(t, f.project), func() *sessions.Store { return store }, f.home, f.project, guard)
	d, ok := deps.NewDispatcher(permissions.ModeContext{Mode: string(mode.Plan)}).(*productionToolDispatcher)
	if !ok {
		t.Fatal("NewDispatcher did not return a production dispatcher")
	}
	move, _ := d.authorizer.(childMoveAuthorizer)
	if auth, _ := move.Authorizer.(*headlessAuthorizer); auth == nil || auth.blocked != guard.Blocked {
		t.Fatalf("child authorizer = %+v, want the parent's live blocked list %p", move.Authorizer, guard.Blocked)
	}

	req := directShellAuthRequest("touch x", f.project)
	step := func(state, outcome string) {
		t.Helper()
		dec, err := d.authorizer.Authorize(context.Background(), req.Req, req.Display, req.ModeCtx)
		if err != nil || dec.Outcome != outcome {
			t.Fatalf("%s: decision = %+v, %v; want %s", state, dec, err, outcome)
		}
	}
	step("valid", "once")
	rewriteSettings(t, f.global, "blocked_paths: [\n")
	step("broken", "deny")
	f.editGlobal(t, "a")
	step("fixed", "once")
}

type pinnedVCSHarness struct {
	d     *productionToolDispatcher
	spy   *pinSpyAuthorizer
	inner *confineInner
	ran   *[]string
}

func newPinnedVCSHarness(t *testing.T, active *mode.ActiveState) pinnedVCSHarness {
	t.Helper()
	inner := &confineInner{}
	conf := &confinement{constrained: true, mode: liveMode(active), lookupPath: programDir(t, "git"), blocked: testBlocked(t), tmpDir: t.TempDir()}
	reg, _, cache, home, project, store := confinedVCSRegistry(t, conf, inner)
	conf.projectRoot = project
	app := tui.New(nil)
	app.SetActiveStore(store)
	allowAll := func(tui.PromptRequest) (tui.PromptDecision, error) { return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil }
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(allowAll), home, project, active)
	auth.executionConstrained = true
	spy := &pinSpyAuthorizer{productionAuthorizer: auth}
	guard := mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil)
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, spy, home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), guard)
	d.confinement = conf
	ran := &[]string{}
	inner.onBounded = func(spec cmdrunner.RunSpec) {
		policy, _ := decodeFrame(t, spec.Stdin)
		*ran = append(*ran, policy.Mode)
	}
	inner.onExec = func(cmdrunner.RunSpec) { *ran = append(*ran, "unconfined") }
	return pinnedVCSHarness{d: d, spy: spy, inner: inner, ran: ran}
}

func ranAs(m mode.Mode) string {
	if m == mode.Build {
		return "unconfined"
	}
	return string(m)
}

func authorizedVCSUnit(t *testing.T, d *productionToolDispatcher, id string) turn.PlannedToolCall {
	t.Helper()
	calls := []turn.AssembledToolCall{structuredCall(id, "vcs_status", map[string]any{})}
	if groups := d.assembleAuthGroups(calls); groups[0] == nil {
		t.Fatal("the read-only vcs action formed no authorization group")
	}
	unit := d.Plan(calls, 1).Units[0]
	if err := unit.PreRun(context.Background()); err != nil {
		t.Fatalf("group pre-run: %v", err)
	}
	return unit
}

func TestProductionDispatcher_GroupedVCSMemberKeepsTheGroupMode(t *testing.T) {
	for _, tc := range []struct{ captured, switched mode.Mode }{
		{mode.Plan, mode.Build},
		{mode.AutoEdits, mode.Build},
		{mode.Build, mode.Plan},
		{mode.Build, mode.AutoEdits},
	} {
		t.Run(string(tc.captured)+"_to_"+string(tc.switched), func(t *testing.T) {
			active := mode.NewActiveState(tc.captured, mode.SourceUserCommand)
			h := newPinnedVCSHarness(t, active)

			member := authorizedVCSUnit(t, h.d, "c1")
			active.ApplyUserCommand(tc.switched)
			if _, err := member.Run(context.Background()); err != nil {
				t.Fatalf("member run: %v", err)
			}
			if _, err := h.d.Dispatch(context.Background(), structuredCall("c2", "vcs_status", map[string]any{})); err != nil {
				t.Fatalf("ungrouped Dispatch: %v", err)
			}
			later := authorizedVCSUnit(t, h.d, "c3")
			if _, err := later.Run(context.Background()); err != nil {
				t.Fatalf("later member run: %v", err)
			}

			want := []string{ranAs(tc.captured), ranAs(tc.switched), ranAs(tc.switched)}
			if !slices.Equal(*h.ran, want) {
				t.Fatalf("runs = %v, want the member under its group's mode, then later calls under the new mode %v", *h.ran, want)
			}
			if pins := h.spy.recorded(); !slices.Equal(pins, []string{string(tc.captured), string(tc.switched), string(tc.switched)}) {
				t.Fatalf("authorization pins = %v", pins)
			}
		})
	}
}

func splitVCSGroup(t *testing.T, d *productionToolDispatcher) *authGroup {
	t.Helper()
	dir, target := externalReadDir(t, "middle.txt", "MIDDLE\n")
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	calls := []turn.AssembledToolCall{
		structuredCall("c1", "vcs_status", map[string]any{}),
		structuredCall("c2", filetools.ReadToolName, map[string]any{"path": link}),
		structuredCall("c3", "vcs_status", map[string]any{}),
	}
	groups := d.assembleAuthGroups(calls)
	if groups[0] == nil || groups[0] != groups[1] || groups[1] != groups[2] {
		t.Fatal("plan-time grouping did not admit all three calls")
	}
	if err := os.Remove(target); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	return groups[0]
}

func TestProductionDispatcher_EachAuthorizationSegmentCapturesItsOwnMode(t *testing.T) {
	for _, tc := range []struct{ first, second mode.Mode }{
		{mode.Plan, mode.Build},
		{mode.Build, mode.AutoEdits},
	} {
		t.Run(string(tc.first)+"_then_"+string(tc.second), func(t *testing.T) {
			active := mode.NewActiveState(tc.first, mode.SourceUserCommand)
			h := newPinnedVCSHarness(t, active)
			group := splitVCSGroup(t, h.d)
			h.spy.after = func(context.Context) { active.ApplyUserCommand(tc.second) }

			if err := authorizeGroup(context.Background(), group); err != nil {
				t.Fatalf("authorizeGroup: %v", err)
			}
			if pins := h.spy.recorded(); !slices.Equal(pins, []string{string(tc.first), string(tc.second)}) {
				t.Fatalf("segment authorization pins = %v, want %q then %q", pins, tc.first, tc.second)
			}
			first, second := group.member("c1"), group.member("c3")
			if first == nil || second == nil || group.member("c2") != nil {
				t.Fatalf("members c1/c2/c3 = %v/%v/%v, want both vcs calls decided and the broken read left out", first, group.member("c2"), second)
			}
			if !first.pinned || first.mode != string(tc.first) || !second.pinned || second.mode != string(tc.second) {
				t.Fatalf("member pins = %+v / %+v, want %q and %q", first, second, tc.first, tc.second)
			}
			for _, m := range []*groupMember{first, second} {
				if _, err := h.d.dispatchDecided(context.Background(), m, false, 1); err != nil {
					t.Fatalf("dispatchDecided: %v", err)
				}
			}
			if want := []string{ranAs(tc.first), ranAs(tc.second)}; !slices.Equal(*h.ran, want) {
				t.Fatalf("runs = %v, want each segment's members under its own captured mode %v", *h.ran, want)
			}
		})
	}
}

func TestProductionDispatcher_FailedSegmentPublishesNoMemberOrMode(t *testing.T) {
	boom := errors.New("authorization failed")
	for _, tc := range []struct {
		name string
		arm  func(h pinnedVCSHarness, cancel context.CancelFunc)
		want error
	}{
		{"cancelled after the first segment", func(h pinnedVCSHarness, cancel context.CancelFunc) {
			h.spy.after = func(context.Context) { cancel() }
		}, context.Canceled},
		{"second segment errors", func(h pinnedVCSHarness, _ context.CancelFunc) {
			calls := 0
			h.spy.before = func(context.Context) error {
				calls++
				if calls == 2 {
					return boom
				}
				return nil
			}
		}, boom},
	} {
		t.Run(tc.name, func(t *testing.T) {
			active := mode.NewActiveState(mode.Plan, mode.SourceUserCommand)
			h := newPinnedVCSHarness(t, active)
			group := splitVCSGroup(t, h.d)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tc.arm(h, cancel)

			if err := authorizeGroup(ctx, group); !errors.Is(err, tc.want) {
				t.Fatalf("authorizeGroup = %v, want %v", err, tc.want)
			}
			if err := authorizeGroup(context.Background(), group); !errors.Is(err, tc.want) {
				t.Fatalf("second authorizeGroup = %v, want the once-published %v", err, tc.want)
			}
			if pins := h.spy.recorded(); len(pins) != 2 {
				t.Fatalf("authorization calls = %v, want the two segments of the one resolution only", pins)
			}
			if group.members != nil || group.member("c1") != nil || group.member("c3") != nil {
				t.Fatalf("members = %v, want none published after a failed resolution", group.members)
			}
			if h.inner.calls() != 0 {
				t.Fatalf("runner calls = %d, want no member executed", h.inner.calls())
			}
		})
	}
}

func TestProductionDispatcher_ConcurrentCallsKeepTheirOwnMode(t *testing.T) {
	for _, captured := range []mode.Mode{mode.Plan, mode.AutoEdits} {
		t.Run(string(captured), func(t *testing.T) {
			active := mode.NewActiveState(captured, mode.SourceUserCommand)
			h := newPinShellHarness(t, active, nil, "ls", "head")
			held, release := make(chan struct{}), make(chan struct{})
			var authorizations atomic.Int32
			h.spy.before = func(context.Context) error {
				if authorizations.Add(1) == 1 {
					close(held)
					<-release
				}
				return nil
			}

			done := make(chan error, 1)
			go func() {
				_, err := h.d.Dispatch(context.Background(), bashCall("a", "ls"))
				done <- err
			}()
			<-held
			active.ApplyUserCommand(mode.Build)
			if _, err := h.d.Dispatch(context.Background(), bashCall("b", "head")); err != nil {
				t.Fatalf("call B: %v", err)
			}
			if len(h.inner.execs) != 1 || len(h.inner.bounded) != 0 {
				t.Fatalf("after B bounded/exec = %d/%d, want B's one unconfined Build run", len(h.inner.bounded), len(h.inner.execs))
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatalf("call A: %v", err)
			}

			if len(h.inner.bounded) != 1 || len(h.inner.execs) != 1 {
				t.Fatalf("bounded/exec = %d/%d, want A confined and B unconfined", len(h.inner.bounded), len(h.inner.execs))
			}
			wantHelperArgv(t, h.inner.bounded[0].Argv, filepath.Join(h.d.confinement.lookupPath, "ls"))
			if policy, _ := decodeFrame(t, h.inner.bounded[0].Stdin); policy.Mode != string(captured) {
				t.Fatalf("A policy mode = %q, want its captured %q", policy.Mode, captured)
			}
			if filepath.Base(h.inner.execs[0].Argv[0]) != "head" {
				t.Fatalf("unconfined run = %q, want B's head", h.inner.execs[0].Argv)
			}
			if pins := h.spy.recorded(); !slices.Equal(pins, []string{string(captured), string(mode.Build)}) {
				t.Fatalf("authorization pins = %v, want A under %q and B under build", pins, captured)
			}
		})
	}
}

func TestProductionDispatcher_EntryPinRespectsExistingPinsAndMissingModeSources(t *testing.T) {
	plan := string(mode.Plan)
	for _, tc := range []struct {
		name                 string
		arrange              func(d *productionToolDispatcher) context.Context
		want                 string
		wantExecs, wantBound int
	}{
		{"nil confinement", func(d *productionToolDispatcher) context.Context {
			d.confinement = nil
			return context.Background()
		}, unpinnedCall, 1, 0},
		{"nil mode callback", func(d *productionToolDispatcher) context.Context {
			d.confinement.mode = nil
			return context.Background()
		}, unpinnedCall, 0, 0},
		{"existing context pin", func(*productionToolDispatcher) context.Context {
			return vcs.WithConfinementMode(context.Background(), plan)
		}, plan, 0, 1},
		{"child fixed mode", func(d *productionToolDispatcher) context.Context {
			d.childMode = &plan
			return context.Background()
		}, plan, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			active := mode.NewActiveState(mode.Build, mode.SourceUserCommand)
			h := newPinShellHarness(t, active, nil, "ls")
			ctx := tc.arrange(h.d)

			_, _ = h.d.Dispatch(ctx, bashCall("c1", "ls"))
			if pins := h.spy.recorded(); !slices.Equal(pins, []string{tc.want}) {
				t.Fatalf("authorization pins = %v, want [%s]", pins, tc.want)
			}
			if len(h.inner.execs) != tc.wantExecs || len(h.inner.bounded) != tc.wantBound {
				t.Fatalf("exec/bounded = %d/%d, want %d/%d", len(h.inner.execs), len(h.inner.bounded), tc.wantExecs, tc.wantBound)
			}
		})
	}
}

func childDirsFixture(t *testing.T, write []string, dirs ...string) (turn.ToolDispatcher, *sessions.Store, string, string, map[string]bool) {
	t.Helper()
	cache, home, project, active, modeActive := generalAgentFixture(t)
	seedChildMoveProject(t, project)
	declared, _, err := filetools.ResolveDeclaredScopes(home, project, write, nil)
	if err != nil {
		t.Fatalf("ResolveDeclaredScopes: %v", err)
	}
	mkdir := filetools.NewMkdirTool(home, project, project)
	var declaredDirs map[string]bool
	for _, dir := range dirs {
		target, _, rerr := mkdir.ResolveTarget(map[string]any{"path": dir})
		if rerr != nil {
			t.Fatalf("ResolveTarget(%s): %v", dir, rerr)
		}
		if declaredDirs == nil {
			declaredDirs = map[string]bool{}
		}
		declaredDirs[target] = true
	}
	store := mkStore(t)
	reg := generalAgentRegistry(t, cache, home, project, active, modeActive)
	deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
	return deps.NewDispatcher(permissions.ModeContext{
		Mode:          string(mode.Build),
		ChildAgent:    true,
		DeclaredWrite: declared,
		DeclaredDirs:  declaredDirs,
	}), store, home, project, declaredDirs
}

func TestChildCeiling_MkdirAdmitsEverySpellingOfTheExactDeclaredDirectory(t *testing.T) {
	tests := []struct {
		spelling string
		absolute bool
	}{
		{spelling: "work/new/sub"},
		{spelling: "work/new/sub/"},
		{spelling: "./work/./new/sub"},
		{spelling: "work/../work/new/sub"},
		{spelling: "work/new/../new/sub"},
		{spelling: "worklink/new/sub"},
		{spelling: "work/new/sub", absolute: true},
		{spelling: "work/new/sub/", absolute: true},
	}
	for i, tc := range tests {
		name := tc.spelling
		if tc.absolute {
			name = "absolute " + name
		}
		t.Run(name, func(t *testing.T) {
			d, store, _, project, dirs := childDirsFixture(t, nil, filepath.Join("work", "new", "sub"))
			target := filepath.Join(project, "work", "new", "sub")
			if !dirs[target] {
				t.Fatalf("declaration %v does not name %s", dirs, target)
			}
			path := tc.spelling
			if tc.absolute {
				path = project + "/" + tc.spelling
			}

			res, err := d.Dispatch(context.Background(), structuredCall(fmt.Sprintf("mk-%d", i), filetools.MkdirToolName, map[string]any{"path": path}))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}
			if res.Denied {
				t.Fatalf("result = %+v, want the declaration to admit a canonical-equivalent spelling", res)
			}
			matched := decodePermissionMatched(t, store)
			if len(matched) != 1 || matched[0].OutcomeSource != permissions.OutcomeSourceDeclaredScope || matched[0].Outcome != "once" {
				t.Fatalf("permission_matched = %+v, want exactly one declared_scope/once", matched)
			}
			if info, statErr := os.Stat(target); statErr != nil || !info.IsDir() {
				t.Fatalf("declared directory %s was not created: %v", target, statErr)
			}
		})
	}
}

func TestChildCeiling_MkdirBypassAttemptsAllDeny(t *testing.T) {
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	d, store, home, project, dirs := childDirsFixture(t, []string{filepath.Join("work", "notes.txt")}, filepath.Join("work", "new", "sub"))
	if err := os.Symlink(outside, filepath.Join(project, "outlink")); err != nil {
		t.Fatalf("Symlink outlink: %v", err)
	}
	tests := []struct {
		name        string
		path        string
		want        string
		caseVariant bool
	}{
		{name: "a traversal to another directory", path: "work/new/../other-sub", want: filepath.Join(project, "work", "other-sub")},
		{name: "a symlink alias resolving elsewhere", path: "otherlink/new/sub", want: filepath.Join(project, "other", "new", "sub")},
		{name: "a symlink alias resolving out of the project", path: "outlink/new/sub", want: filepath.Join(outside, "new", "sub")},
		{name: "the missing parent the declared mkdir would create", path: "./work/./new/", want: filepath.Join(project, "work", "new")},
		{name: "a directory below the declared one", path: "work/new/sub/deeper", want: filepath.Join(project, "work", "new", "sub", "deeper")},
		{name: "an absolute path outside the project root", path: filepath.Join(outside, "beyond"), want: filepath.Join(outside, "beyond")},
		{name: "a home-relative path outside the project root", path: "~/beyond", want: filepath.Join(home, "beyond")},
		{name: "a case-variant spelling", path: "WORK/new/sub", want: filepath.Join(project, "WORK", "new", "sub"), caseVariant: true},
	}
	seen := map[string]bool{}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.caseVariant && sameFilesystemObject(filepath.Join(project, "WORK"), filepath.Join(project, "work")) {
				t.Skip("this volume is case-insensitive, so a case variant names the declared directory itself")
			}
			resolved, _, rerr := filetools.NewMkdirTool(home, project, project).ResolveTarget(map[string]any{"path": tc.path})
			if rerr != nil {
				t.Fatalf("ResolveTarget(%s) = %v, want the row to reach authorization", tc.path, rerr)
			}
			if resolved != tc.want {
				t.Fatalf("production canonical target = %s, want %s", resolved, tc.want)
			}
			if dirs[resolved] || seen[resolved] {
				t.Fatalf("row target %s is declared or repeats an earlier row, so the row proves nothing", resolved)
			}
			seen[resolved] = true

			before := len(decodePermissionMatched(t, store))
			res, derr := d.Dispatch(context.Background(), structuredCall(fmt.Sprintf("mkdir-bypass-%d", i), filetools.MkdirToolName, map[string]any{"path": tc.path}))
			if derr != nil {
				t.Fatalf("Dispatch error = %v, want nil", derr)
			}
			assertChildScopeDenialBy(t, store, before, res, "unattended")
			if _, statErr := os.Lstat(resolved); !os.IsNotExist(statErr) {
				t.Fatalf("%s exists after a refused call (err=%v)", resolved, statErr)
			}
		})
	}
	if _, statErr := os.Lstat(filepath.Join(project, "work", "new")); !os.IsNotExist(statErr) {
		t.Fatalf("work/new exists after only refused calls (err=%v)", statErr)
	}
}

func TestChildCeiling_ADeclaredWriteStillCreatesItsMissingParentsWithoutADirectoryDeclaration(t *testing.T) {
	d, store, _, project, dirs := childDirsFixture(t, []string{filepath.Join("fresh", "deep", "new.txt")})
	if len(dirs) != 0 {
		t.Fatalf("directory declaration = %v, want none", dirs)
	}
	res, err := d.Dispatch(context.Background(), structuredCall("c1", filetools.CreateToolName, map[string]any{"path": "fresh/deep/new.txt", "content": "x"}))
	if err != nil || res.Denied {
		t.Fatalf("declared create = %+v, %v; want it authorized", res, err)
	}
	if matched := decodePermissionMatched(t, store); len(matched) != 1 || matched[0].OutcomeSource != permissions.OutcomeSourceDeclaredScope || matched[0].Outcome != "once" {
		t.Fatalf("permission_matched = %+v, want exactly one declared_scope/once", matched)
	}
	if body, rerr := os.ReadFile(filepath.Join(project, "fresh", "deep", "new.txt")); rerr != nil || string(body) != "x" {
		t.Fatalf("fresh/deep/new.txt = %q (err=%v), want the declared file created with its parents", body, rerr)
	}

	res, err = d.Dispatch(context.Background(), structuredCall("c2", filetools.MkdirToolName, map[string]any{"path": "fresh/other"}))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	reason := assertChildScopeDenial(t, store, 1, res)
	if !strings.Contains(reason, "this general_agent call did not supply files_mkdir") {
		t.Fatalf("reason %q does not name the absent directory declaration", reason)
	}
}

func plannedGeneralAgentArgsCall(id string, args map[string]any) turn.AssembledToolCall {
	args["instructions"] = "do it"
	return structuredCall(id, subagenttool.ToolName, args)
}

func TestProductionDispatcher_GeneralAgentDirectoriesOrderLikeEveryOtherForm(t *testing.T) {
	for _, tc := range []struct {
		name          string
		first, second map[string]any
		wantOverlap   bool
	}{
		{"equal directories",
			map[string]any{"files": []any{"one.txt"}, "files_mkdir": []any{"made"}},
			map[string]any{"files": []any{"two.txt"}, "files_mkdir": []any{"made"}}, false},
		{"a directory and a write below it",
			map[string]any{"files": []any{"one.txt"}, "files_mkdir": []any{"made"}},
			map[string]any{"files": []any{"made/notes.txt"}}, false},
		{"a directory and a delete of it",
			map[string]any{"files": []any{"one.txt"}, "files_mkdir": []any{"made"}},
			map[string]any{"files_delete": []any{"made"}}, false},
		{"a directory and a move onto it",
			map[string]any{"files": []any{"one.txt"}, "files_mkdir": []any{"made"}},
			map[string]any{"files_move": []any{map[string]any{"source": "main.go", "destination": "made"}}}, false},
		{"sibling directories sharing a missing parent",
			map[string]any{"files": []any{"one.txt"}, "files_mkdir": []any{"x/y"}},
			map[string]any{"files": []any{"two.txt"}, "files_mkdir": []any{"x/z"}}, false},
		{"disjoint directories",
			map[string]any{"files": []any{"one.txt"}, "files_mkdir": []any{"p"}},
			map[string]any{"files": []any{"two.txt"}, "files_mkdir": []any{"q"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, probe, _ := generalAgentProbeDispatcher(t)
			calls := []turn.AssembledToolCall{plannedGeneralAgentArgsCall("c1", tc.first), plannedGeneralAgentArgsCall("c2", tc.second)}
			plan := d.Plan(calls, 2)
			assertPartitionedPlan(t, plan, calls, "dd")

			run, err := schedulePlanHeld(plan, 2, nil, generalAgentHold)
			if err != nil {
				t.Fatalf("Schedule: %v", err)
			}
			if got := run.overlapped("c1", "c2"); got != tc.wantOverlap {
				t.Fatalf("delegates overlapped = %v, want %v; execution order %v", got, tc.wantOverlap, run.ids())
			}
			if want := []string{"c1", "c2"}; !tc.wantOverlap && !slices.Equal(run.ids(), want) {
				t.Fatalf("execution order = %v, want the model-call order %v", run.ids(), want)
			}
			if probe.started() != 2 {
				t.Fatalf("children started = %d, want 2", probe.started())
			}
		})
	}
}

// --- top-level delegate launch authorization ---------------------------------

type launchPrompts struct {
	mu       sync.Mutex
	requests []tui.PromptRequest
	active   int
	overlap  bool
	hold     time.Duration
	answer   func(i int) tui.PromptOption
}

func (p *launchPrompts) show(req tui.PromptRequest) (tui.PromptDecision, error) {
	p.mu.Lock()
	i := len(p.requests)
	p.requests = append(p.requests, req)
	p.active++
	if p.active > 1 {
		p.overlap = true
	}
	p.mu.Unlock()
	time.Sleep(p.hold)
	p.mu.Lock()
	p.active--
	p.mu.Unlock()
	option := tui.OptionAllowOnce
	if p.answer != nil {
		option = p.answer(i)
	}
	return tui.PromptDecision{Option: option, StoredSubject: req.CapabilityStoredSubject}, nil
}

func (p *launchPrompts) shown() []tui.PromptRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.requests)
}

type launchFixture struct {
	d       *productionToolDispatcher
	auth    *productionAuthorizer
	turn    *permissions.TurnCache
	probe   *generalAgentProbe
	prompts *launchPrompts
	store   *sessions.Store
	project string
	home    string
}

type launchOptions struct {
	mode   mode.Mode
	grants func(project string) []any
	layers func(project string) []securitystate.LayerSnapshot
	answer func(i int) tui.PromptOption
	hold   time.Duration
}

func newLaunchFixture(t *testing.T, opts launchOptions) *launchFixture {
	t.Helper()
	project := readToolsProject(t)
	home := t.TempDir()
	cfg := map[string]any{}
	if opts.grants != nil {
		cfg["permissions"] = opts.grants(project)
	}
	cache, err := config.NewCache(cfg, project, nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	m := opts.mode
	if m == "" {
		m = mode.Build
	}
	var layers []securitystate.LayerSnapshot
	if opts.layers != nil {
		layers = opts.layers(project)
	}
	guard := mustProtectedStatePolicy(t, home, project, layers)
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	prompts := &launchPrompts{answer: opts.answer, hold: opts.hold}
	turnCache := permissions.NewTurnCache()
	auth := newProductionAuthorizer(app, cache, turnCache, newPromptGateBuilder(prompts.show), home, project, mode.NewActiveState(m, mode.SourceDefault))
	activeStore := func() *sessions.Store { return store }
	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, activeStore, home, project, guard)
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}
	probe := &generalAgentProbe{}
	if err := reg.Register(tools.BuiltinSource, subagenttool.New(subagenttool.Deps{
		Home:          home,
		LaunchDir:     project,
		ProjectRoot:   project,
		Snapshot:      probe.snapshot,
		NewDispatcher: probe.newDispatcher,
		Store:         activeStore,
	})); err != nil {
		t.Fatalf("Register general_agent: %v", err)
	}
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, activeStore, 65536, guard)
	return &launchFixture{d: d, auth: auth, turn: turnCache, probe: probe, prompts: prompts, store: store, project: project, home: home}
}

func (f *launchFixture) seed(t *testing.T, rel ...string) {
	t.Helper()
	for _, r := range rel {
		path := filepath.Join(f.project, r)
		dir := filepath.Dir(path)
		if strings.HasSuffix(r, "/") {
			dir = path
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if strings.HasSuffix(r, "/") {
			continue
		}
		if err := os.WriteFile(path, []byte("body\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
}

func (f *launchFixture) launch(t *testing.T, args map[string]any) turn.ToolResult {
	t.Helper()
	args["instructions"] = "do it"
	res, err := f.d.Dispatch(context.Background(), structuredCall("c1", subagenttool.ToolName, args))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	return res
}

type launchPrompt struct {
	action, subject, scope string
}

func (f *launchFixture) launchPromptsShown(t *testing.T) []launchPrompt {
	t.Helper()
	shown := f.prompts.shown()
	recorded := decodeStoreEvents[events.PermissionPromptShown](t, f.store, events.KindPermissionPromptShown)
	if len(shown) != len(recorded) {
		t.Fatalf("prompt surface showed %d prompts, event store recorded %d", len(shown), len(recorded))
	}
	out := make([]launchPrompt, len(shown))
	for i, req := range shown {
		if recorded[i].Subject == subagenttool.ToolName || req.Action == dispatch.ActionRunTool {
			t.Fatalf("prompt %+v / %+v asks about the tool general_agent", req, recorded[i])
		}
		out[i] = launchPrompt{action: req.Action, subject: req.Subject, scope: recorded[i].PathScope}
	}
	for _, m := range decodePermissionMatched(t, f.store) {
		if m.Subject == subagenttool.ToolName {
			t.Fatalf("permission_matched %+v decided the tool general_agent", m)
		}
	}
	return out
}

func pathList(values ...string) []any { return stringsAsAny(values) }

func movePair(source, destination string) map[string]any {
	return map[string]any{"source": source, "destination": destination}
}

func TestProductionDispatcher_TopLevelGeneralAgentLaunchAuthorizesEachDeclaredOperation(t *testing.T) {
	folderGrant := func(subject, scope string) map[string]any {
		return map[string]any{"kind": "tool", "subject": subject, "path_scope": scope, "grant_kind": "folder"}
	}
	type row struct {
		name        string
		mode        mode.Mode
		seed        []string
		grants      func(project string) []any
		args        map[string]any
		answer      func(i int) tui.PromptOption
		wantPrompts func(project string) []launchPrompt
		wantStart   bool
	}
	p := filepath.Join
	rows := []row{
		{
			name:      "an edit already allowed by a grant",
			seed:      []string{"a.txt"},
			grants:    func(project string) []any { return []any{folderGrant("edit", project)} },
			args:      map[string]any{"files": pathList("a.txt")},
			wantStart: true,
		},
		{
			name:      "an edit already allowed by Auto edits",
			mode:      mode.AutoEdits,
			seed:      []string{"a.txt"},
			args:      map[string]any{"files": pathList("a.txt")},
			wantStart: true,
		},
		{
			name: "a create, delete, move, and mkdir already allowed",
			seed: []string{"old.txt", "src.txt"},
			grants: func(project string) []any {
				return []any{folderGrant("create", project), folderGrant("delete", project), folderGrant("move", project), folderGrant("mkdir", project)}
			},
			args: map[string]any{
				"files": pathList("new.txt"), "files_delete": pathList("old.txt"),
				"files_move": []any{movePair("src.txt", "dst.txt")}, "files_mkdir": pathList("made"),
			},
			wantStart: true,
		},
		{
			name:   "one uncovered declared path",
			seed:   []string{"a.txt"},
			grants: func(project string) []any { return []any{folderGrant("edit", project)} },
			args:   map[string]any{"files": pathList("a.txt", "new.txt")},
			wantPrompts: func(project string) []launchPrompt {
				return []launchPrompt{{dispatch.ActionCreateFile, p(project, "new.txt"), project}}
			},
			wantStart: true,
		},
		{
			name:   "a read grant does not cover a declared write",
			grants: func(project string) []any { return []any{folderGrant("read", project)} },
			args:   map[string]any{"files": pathList("new.txt")},
			wantPrompts: func(project string) []launchPrompt {
				return []launchPrompt{{dispatch.ActionCreateFile, p(project, "new.txt"), project}}
			},
			wantStart: true,
		},
		{
			name: "a write grant does not cover a declared delete",
			seed: []string{"old.txt"},
			grants: func(project string) []any {
				return []any{folderGrant(permissions.CapabilityWriteTree, project)}
			},
			args: map[string]any{"files": pathList("new.txt"), "files_delete": pathList("old.txt")},
			wantPrompts: func(project string) []launchPrompt {
				return []launchPrompt{{dispatch.ActionDeleteFile, p(project, "old.txt"), project}}
			},
			wantStart: true,
		},
		{
			name: "a delegate grant does not cover uncovered operations",
			grants: func(string) []any {
				return []any{map[string]any{"kind": "tool", "subject": "general_agent", "path_scope": "*", "grant_kind": "global"}}
			},
			args:   map[string]any{"files": pathList("new.txt")},
			answer: func(int) tui.PromptOption { return tui.OptionDeny },
			wantPrompts: func(project string) []launchPrompt {
				return []launchPrompt{{dispatch.ActionCreateFile, p(project, "new.txt"), project}}
			},
		},
		{
			name: "uncovered operations prompt in form and path order",
			seed: []string{"w1/", "w2/", "d1/x.txt", "d2/y.txt", "mv/a.txt", "mv2/", "k1/", "k2/"},
			args: map[string]any{
				"files_mkdir":  pathList("k2/new", "k1/new"),
				"files_move":   []any{movePair("mv/a.txt", "mv2/a.txt")},
				"files_delete": pathList("d2/y.txt", "d1/x.txt"),
				"files":        pathList("w2/b.txt", "w1/a.txt"),
			},
			wantPrompts: func(project string) []launchPrompt {
				move := p(project, "mv", "a.txt") + " -> " + p(project, "mv2", "a.txt")
				return []launchPrompt{
					{dispatch.ActionCreateFile, p(project, "w1", "a.txt"), p(project, "w1")},
					{dispatch.ActionCreateFile, p(project, "w2", "b.txt"), p(project, "w2")},
					{dispatch.ActionDeleteFile, p(project, "d1", "x.txt"), p(project, "d1")},
					{dispatch.ActionDeleteFile, p(project, "d2", "y.txt"), p(project, "d2")},
					{dispatch.ActionMoveFile, move, p(project, "mv")},
					{dispatch.ActionMoveFile, move, p(project, "mv2")},
					{dispatch.ActionCreateDirectory, p(project, "k1", "new"), p(project, "k1")},
					{dispatch.ActionCreateDirectory, p(project, "k2", "new"), p(project, "k2")},
				}
			},
			wantStart: true,
		},
		{
			name: "an identical operation scope reuses the earlier decision",
			args: map[string]any{"files": pathList("b.txt", "a.txt")},
			wantPrompts: func(project string) []launchPrompt {
				return []launchPrompt{{dispatch.ActionCreateFile, p(project, "a.txt"), project}}
			},
			wantStart: true,
		},
		{
			name: "a delete of a path the child will create",
			args: map[string]any{"files": pathList("new.txt"), "files_delete": pathList("new.txt")},
			wantPrompts: func(project string) []launchPrompt {
				return []launchPrompt{
					{dispatch.ActionCreateFile, p(project, "new.txt"), project},
					{dispatch.ActionDeleteFile, p(project, "new.txt"), project},
				}
			},
			wantStart: true,
		},
		{
			name: "a delete under a missing parent",
			seed: []string{"sub/"},
			args: map[string]any{"files_delete": pathList("sub/missing/x.txt")},
			wantPrompts: func(project string) []launchPrompt {
				return []launchPrompt{{dispatch.ActionDeleteFile, p(project, "sub", "missing", "x.txt"), p(project, "sub")}}
			},
			wantStart: true,
		},
		{
			name: "a same-directory move needs one authorization",
			seed: []string{"a.txt"},
			args: map[string]any{"files_move": []any{movePair("a.txt", "b.txt")}},
			wantPrompts: func(project string) []launchPrompt {
				return []launchPrompt{{dispatch.ActionMoveFile, p(project, "a.txt") + " -> " + p(project, "b.txt"), project}}
			},
			wantStart: true,
		},
		{
			name:   "a denied move source stops before the destination",
			seed:   []string{"src/a.txt", "dst/"},
			args:   map[string]any{"files_move": []any{movePair("src/a.txt", "dst/a.txt")}},
			answer: func(int) tui.PromptOption { return tui.OptionDeny },
			wantPrompts: func(project string) []launchPrompt {
				return []launchPrompt{{dispatch.ActionMoveFile, p(project, "src", "a.txt") + " -> " + p(project, "dst", "a.txt"), p(project, "src")}}
			},
		},
		{
			name: "the second of two prompts is denied",
			seed: []string{"w1/", "w2/"},
			args: map[string]any{"files": pathList("w1/a.txt", "w2/b.txt")},
			answer: func(i int) tui.PromptOption {
				if i == 1 {
					return tui.OptionDeny
				}
				return tui.OptionAllowOnce
			},
			wantPrompts: func(project string) []launchPrompt {
				return []launchPrompt{
					{dispatch.ActionCreateFile, p(project, "w1", "a.txt"), p(project, "w1")},
					{dispatch.ActionCreateFile, p(project, "w2", "b.txt"), p(project, "w2")},
				}
			},
		},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			f := newLaunchFixture(t, launchOptions{mode: tc.mode, grants: tc.grants, answer: tc.answer})
			f.seed(t, tc.seed...)

			res := f.launch(t, tc.args)

			var want []launchPrompt
			if tc.wantPrompts != nil {
				want = tc.wantPrompts(f.project)
			}
			if got := f.launchPromptsShown(t); !slices.Equal(got, want) {
				t.Fatalf("prompts = %+v, want %+v", got, want)
			}
			wantStarts := 0
			if tc.wantStart {
				wantStarts = 1
			}
			if f.probe.started() != wantStarts {
				t.Fatalf("children started = %d, want %d (result %+v)", f.probe.started(), wantStarts, res)
			}
			if !tc.wantStart && !res.Denied {
				t.Fatalf("result = %+v, want the operation's denial", res)
			}
		})
	}
}

func TestProductionDispatcher_PlanRefusesAGeneralAgentLaunchLikeTheDirectWrite(t *testing.T) {
	f := newLaunchFixture(t, launchOptions{mode: mode.Plan})

	direct, err := f.d.Dispatch(context.Background(), structuredCall("c0", filetools.CreateToolName, map[string]any{"path": "new.txt", "content": "x"}))
	if err != nil {
		t.Fatalf("Dispatch(create) error = %v", err)
	}
	launched := f.launch(t, map[string]any{"files": pathList("new.txt")})

	for _, res := range []turn.ToolResult{direct, launched} {
		if !res.Denied || !permissions.IsModeDenyEnvelope(res.Content) {
			t.Fatalf("result = %+v, want Plan's mode denial", res)
		}
	}
	if shown := f.prompts.shown(); len(shown) != 0 {
		t.Fatalf("prompts = %+v, want none", shown)
	}
	if f.probe.started() != 0 {
		t.Fatalf("children started = %d, want 0", f.probe.started())
	}
	mustNotExist(t, filepath.Join(f.project, "new.txt"), "Plan writes nothing")
}

func TestProductionDispatcher_GuardedDeclarationsRefuseTheLaunchBeforeAnyPrompt(t *testing.T) {
	blocked := func(project string) []securitystate.LayerSnapshot {
		return []securitystate.LayerSnapshot{{
			Kind: securitystate.LayerProject, Path: projectSettingsPath(project), Present: true,
			Raw: map[string]any{"blocked_paths": []any{filepath.Join(project, "box", "secret.txt"), filepath.Join(project, "blocked.txt")}},
		}}
	}
	everything := func(project string) []any {
		var grants []any
		for _, subject := range []string{"edit", "create", "delete", "move", "mkdir"} {
			grants = append(grants, map[string]any{"kind": "tool", "subject": subject, "path_scope": "*", "grant_kind": "global"})
		}
		return grants
	}
	tests := []struct {
		name string
		args map[string]any
	}{
		{"a protected settings target after an uncovered write", map[string]any{"files": pathList("a.txt"), "files_delete": pathList(".codemeld/settings.yaml")}},
		{"a blocked write target", map[string]any{"files": pathList("blocked.txt")}},
		{"a delete of a directory holding a blocked path", map[string]any{"files_delete": pathList("box")}},
		{"a move of a directory holding a blocked path", map[string]any{"files_move": []any{movePair("box", "moved")}}},
	}
	for _, m := range []mode.Mode{mode.Build, mode.AutoEdits} {
		for _, grants := range []func(string) []any{nil, everything} {
			for _, tc := range tests {
				t.Run(fmt.Sprintf("%s/grants=%v/%s", m, grants != nil, tc.name), func(t *testing.T) {
					f := newLaunchFixture(t, launchOptions{mode: m, grants: grants, layers: blocked})
					f.seed(t, ".codemeld/settings.yaml", "box/secret.txt")

					res := f.launch(t, tc.args)

					if !res.Denied {
						t.Fatalf("result = %+v, want a guard refusal", res)
					}
					if shown := f.prompts.shown(); len(shown) != 0 {
						t.Fatalf("prompts = %+v, want none", shown)
					}
					if f.probe.started() != 0 {
						t.Fatalf("children started = %d, want 0", f.probe.started())
					}
					for _, ev := range decodePermissionMatched(t, f.store) {
						if ev.Outcome != "deny" {
							t.Fatalf("permission_matched %+v, want only the guard refusal", ev)
						}
					}
				})
			}
		}
	}
}

func TestProductionDispatcher_ALaterLaunchDenialKeepsEarlierApprovals(t *testing.T) {
	tests := []struct {
		name   string
		option tui.PromptOption
		check  func(t *testing.T, f *launchFixture, scope string)
	}{
		{"once", tui.OptionAllowOnce, func(t *testing.T, f *launchFixture, scope string) {
			req := permissions.MatchRequest{Kind: "tool", Subject: filetools.CreateToolName, PathScope: scope}
			if outcome, hit := f.turn.Lookup(req); !hit || outcome != "once" {
				t.Fatalf("turn cache = %q (hit %v), want the earlier allow-once kept", outcome, hit)
			}
		}},
		{"session", tui.OptionAllowSession, func(t *testing.T, f *launchFixture, scope string) {
			assertLaunchGrant(t, f.auth.grants.Permissions(), "session", scope)
		}},
		{"folder", tui.OptionAllowFolder, func(t *testing.T, f *launchFixture, scope string) {
			assertLaunchGrant(t, readPersistedPermissions(t, config.LocalSettingsPath(f.project), f.project), "folder", scope)
		}},
		{"global", tui.OptionAllowGlobal, func(t *testing.T, f *launchFixture, scope string) {
			assertLaunchGrant(t, readPersistedPermissions(t, SettingsPath(f.home), f.project), "global", "")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			first := tc.option
			f := newLaunchFixture(t, launchOptions{answer: func(i int) tui.PromptOption {
				if i == 0 {
					return first
				}
				return tui.OptionDeny
			}})
			f.seed(t, "w1/", "w2/old.txt")

			res := f.launch(t, map[string]any{"files": pathList("w1/a.txt"), "files_delete": pathList("w2/old.txt")})

			if !res.Denied || f.probe.started() != 0 {
				t.Fatalf("result = %+v with %d children started, want the launch refused", res, f.probe.started())
			}
			if got := len(f.launchPromptsShown(t)); got != 2 {
				t.Fatalf("prompts = %d, want 2", got)
			}
			tc.check(t, f, filepath.Join(f.project, "w1"))
		})
	}
}

func assertLaunchGrant(t *testing.T, entries []permissions.PermissionEntry, kind, scope string) {
	t.Helper()
	for _, e := range entries {
		if e.GrantKind == kind && (scope == "" || e.PathScope == scope) {
			return
		}
	}
	t.Fatalf("grants = %+v, want the earlier %s grant for %q kept", entries, kind, scope)
}

func TestProductionDispatcher_ParallelGeneralAgentLaunchesSerializeTheirPrompts(t *testing.T) {
	f := newLaunchFixture(t, launchOptions{hold: 20 * time.Millisecond})
	f.seed(t, "w1/", "w2/")
	calls := []turn.AssembledToolCall{plannedGeneralAgentCall("c1", "w1/a.txt"), plannedGeneralAgentCall("c2", "w2/b.txt")}
	plan := f.d.Plan(calls, 2)
	assertPartitionedPlan(t, plan, calls, "dd")

	var wg sync.WaitGroup
	errs := make([]error, len(plan.Units))
	for i := range plan.Units {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = plan.Units[i].Run(context.Background())
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	}

	if got := len(f.launchPromptsShown(t)); got != 2 {
		t.Fatalf("prompts = %d, want one per launch", got)
	}
	if f.prompts.overlap {
		t.Fatal("two launch prompts were active at once")
	}
	if f.probe.started() != 2 {
		t.Fatalf("children started = %d, want 2", f.probe.started())
	}
}

func TestChildCeiling_PlannedNestedGeneralAgentBuildsNoLaunchRequests(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	declared, _, err := filetools.ResolveDeclaredScopes(home, project, []string{"a.txt"}, nil)
	if err != nil {
		t.Fatalf("ResolveDeclaredScopes: %v", err)
	}
	store := mkStore(t)
	activeStore := func() *sessions.Store { return store }
	guard := mustProtectedStatePolicy(t, home, project, nil)
	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, activeStore, home, project, guard)
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}
	probe := &generalAgentProbe{}
	if err := reg.Register(tools.BuiltinSource, subagenttool.New(subagenttool.Deps{
		Home: home, LaunchDir: project, ProjectRoot: project,
		Snapshot: probe.snapshot, NewDispatcher: probe.newDispatcher, Store: activeStore,
	})); err != nil {
		t.Fatalf("Register general_agent: %v", err)
	}
	deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, activeStore, home, project, guard)
	d := deps.NewDispatcher(permissions.ModeContext{Mode: string(mode.Build), ChildAgent: true, DeclaredWrite: declared}).(*productionToolDispatcher)

	calls := []turn.AssembledToolCall{plannedGeneralAgentCall("n1", "a.txt")}
	plan := d.Plan(calls, 2)
	assertPartitionedPlan(t, plan, calls, "d")
	if _, err := plan.Units[0].Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	matched := decodePermissionMatched(t, store)
	if len(matched) != 1 || matched[0].Subject != subagenttool.ToolName || matched[0].OutcomeSource != permissions.OutcomeSourceDeclaredScope {
		t.Fatalf("permission_matched = %+v, want the one declared-scope delegate decision", matched)
	}
	if prompts := decodeStoreEvents[events.PermissionPromptShown](t, store, events.KindPermissionPromptShown); len(prompts) != 0 {
		t.Fatalf("prompts = %+v, want none", prompts)
	}
	if probe.started() != 1 {
		t.Fatalf("grandchildren started = %d, want 1", probe.started())
	}
}

func TestGeneralAgentBinding_ChildAuthorizerReadsTheLiveWritableFoldersUnderItsCeiling(t *testing.T) {
	l := gateWritableLaunch(t, declaredScopeDir(t), declaredScopeDir(t), true, declaringWritableFolder)
	cache, err := config.NewCache(l.composition.Config, l.project, l.layerPaths, l.home)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	store := mkStore(t)
	binding := generalAgentBinding{parent: &parentTurnHolder{}, notices: &recordingNotices{}, confinement: &confinement{constrained: true}}
	deps := binding.deps(tools.NewRegistry(), cache, func() *sessions.Store { return store }, l.home, l.project, mustProtectedStatePolicy(t, l.home, l.project, l.layers))
	authorize := func(state string, modeCtx permissions.ModeContext, want string) {
		t.Helper()
		d, ok := deps.NewDispatcher(modeCtx).(*productionToolDispatcher)
		if !ok {
			t.Fatal("NewDispatcher did not return a production dispatcher")
		}
		move, _ := d.authorizer.(childMoveAuthorizer)
		if _, ok := move.Authorizer.(*headlessAuthorizer); !ok {
			t.Fatalf("child authorizer = %T, want the headless authorizer behind childMoveAuthorizer", d.authorizer)
		}
		req := writableEditRequest(l)
		dec, err := d.authorizer.Authorize(context.Background(), req.Req, req.Display, req.ModeCtx)
		if err != nil || dec.Outcome != want {
			t.Fatalf("%s: decision = %+v, %v; want %s", state, dec, err, want)
		}
	}
	auto := permissions.ModeContext{Mode: string(mode.AutoEdits)}
	settings := projectSettingsPath(l.project)

	authorize("declared", auto, "once")
	rewriteSettings(t, settings, writableFoldersYAML())
	authorize("removed", auto, "deny")
	rewriteSettings(t, settings, declaringWritableFolder(l.folder))
	authorize("restored", auto, "once")

	other := filepath.Join(l.folder, "other.txt")
	authorize("outside the child's declaration", permissions.ModeContext{Mode: string(mode.AutoEdits), ChildAgent: true, DeclaredWrite: map[string]bool{other: true}}, "deny")
}

func TestRunHeadless_PlanRunsAPathFreeGeneralAgentAndDeniesAPathDeclaringOne(t *testing.T) {
	dir := declaredScopeDir(t)
	script := newGeneralAgentScript(
		func(provider.Request) []byte {
			return toolCallsChunk(toolFrag(0, "call_1", subagenttool.ToolName, `{"instructions":"count the files"}`))
		},
		finalReply("3 files"),
		func(provider.Request) []byte { return generalAgentCall("call_2", "write it", "report.txt") },
		finalReply("done"),
	)
	defer script.install()()

	driver := NewHeadlessDriver("count, then write", &bytes.Buffer{}, &bytes.Buffer{})
	result := headlessResult(t, dir, mode.NewActiveState(mode.Plan, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}
	if got := script.count(); got != 4 {
		t.Fatalf("provider rounds = %d, want 4 (parent, child, parent, parent)", got)
	}
	if names := toolNames(script.round(t, 0).Tools); !slices.Contains(names, subagenttool.ToolName) {
		t.Fatalf("Plan advertised %v, want general_agent", names)
	}
	store := reloadStore(t, result.Session)
	var launches []events.PermissionMatched
	for _, m := range decodePermissionMatched(t, store) {
		if m.Subject == subagenttool.ToolName && m.ChildInvocationID == "" {
			launches = append(launches, m)
		}
	}
	if len(launches) != 2 ||
		launches[0].OutcomeSource != "mode_auto" || launches[0].Outcome != "once" ||
		launches[1].OutcomeSource != "mode_auto" || launches[1].Outcome != "deny" {
		t.Fatalf("general_agent decisions = %+v, want mode_auto once for the path-free call then mode_auto deny", launches)
	}
	starts := decodeStoreEvents[events.ChildAgentStart](t, store, events.KindChildAgentStart)
	if len(starts) != 1 || len(starts[0].DeclaredPaths)+len(starts[0].DeclaredDeletePaths)+len(starts[0].DeclaredMovePairs)+len(starts[0].DeclaredDirs) != 0 {
		t.Fatalf("child starts = %+v, want exactly one path-free child", starts)
	}
	toolMsgs := messagesByRole(store, "tool")
	if len(toolMsgs) != 2 || !strings.Contains(toolMsgs[0].Content.Text(), "3 files") || !permissions.IsModeDenyEnvelope(toolMsgs[1].Content.Text()) {
		t.Fatalf("tool messages = %+v, want the child's report then Plan's mode denial", toolMsgs)
	}
	mustNotExist(t, filepath.Join(dir, "report.txt"), "Plan starts no path-declaring child")
}

func TestChildCeiling_APreparedEmptyCandidateIsNotReplacedByTheInheritedOne(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	declared, _, err := filetools.ResolveDeclaredScopes(home, project, []string{"a.txt"}, nil)
	if err != nil {
		t.Fatalf("ResolveDeclaredScopes: %v", err)
	}
	store := mkStore(t)
	probe := &generalAgentProbe{}
	reg := tools.NewRegistry()
	if rerr := reg.Register(tools.BuiltinSource, subagenttool.New(subagenttool.Deps{
		Home: home, LaunchDir: project, ProjectRoot: project,
		Snapshot:      probe.snapshot,
		NewDispatcher: probe.newDispatcher,
		Store:         func() *sessions.Store { return store },
	})); rerr != nil {
		t.Fatalf("Register general_agent: %v", rerr)
	}
	deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
	d := deps.NewDispatcher(permissions.ModeContext{
		Mode:                 string(mode.Build),
		ChildAgent:           true,
		DeclaredWrite:        declared,
		GeneralAgentWrite:    declared,
		GeneralAgentResolved: true,
	})

	res, derr := d.Dispatch(context.Background(), structuredCall("n1", subagenttool.ToolName, map[string]any{"instructions": "just look"}))
	if derr != nil || res.Denied {
		t.Fatalf("Dispatch = %+v, %v, want the path-free grandchild allowed", res, derr)
	}
	matched := decodePermissionMatched(t, store)
	if len(matched) != 1 || matched[0].OutcomeSource != "mode_auto" || matched[0].Outcome != "once" {
		t.Fatalf("permission_matched = %+v, want one mode_auto once, not the inherited candidate's declared_scope", matched)
	}
	if probe.started() != 1 {
		t.Fatalf("grandchild starts = %d, want 1", probe.started())
	}
	if ceilings := probe.ceilings(); len(ceilings) != 1 || len(ceilings[0]) != 0 {
		t.Fatalf("grandchild ceilings = %v, want one empty write ceiling", ceilings)
	}
}

func TestProductionDispatcher_ReadOnlyAndPathDeclaringSiblingsKeepTheirOwnToolSets(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	notes := filepath.Join(project, "notes.txt")
	if err := os.WriteFile(notes, []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	const readOnlyInstruction, writerInstruction = "READ-ONLY SIBLING", "WRITER SIBLING"
	writes := []string{
		toolFrag(0, "w0", filetools.EditToolName, `{"path":"notes.txt","old_text":"hello","new_text":"changed"}`),
		toolFrag(1, "w1", filetools.CreateToolName, `{"path":"made.txt","content":"x"}`),
		toolFrag(2, "w2", filetools.DeleteToolName, `{"path":"notes.txt"}`),
		toolFrag(3, "w3", filetools.MkdirToolName, `{"path":"newdir"}`),
		toolFrag(4, "w4", filetools.MoveToolName, `{"source":"notes.txt","destination":"moved.txt"}`),
	}
	var mu sync.Mutex
	requests := map[string][]provider.Request{}
	client := &stubTurnClient{title: streamedTitle("t"), fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		who, answered := "", false
		for _, m := range req.Messages {
			switch {
			case m.Role == "user" && strings.Contains(m.Content, readOnlyInstruction):
				who = readOnlyInstruction
			case m.Role == "user" && strings.Contains(m.Content, writerInstruction):
				who = writerInstruction
			case m.Role == "tool":
				answered = true
			}
		}
		mu.Lock()
		requests[who] = append(requests[who], req)
		mu.Unlock()
		switch {
		case answered:
			return provider.Response{Stream: newStream(contentChunk("done"))}, nil
		case who == readOnlyInstruction:
			return provider.Response{Stream: newStream(toolCallsChunk(writes...))}, nil
		default:
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "c0", filetools.CreateToolName, `{"path":"b.txt","content":"written\n"}`)))}, nil
		}
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	storeFn := func() *sessions.Store { return store }
	guard := mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil)
	reg, err := realizeToolRegistry(&toolRegistryFactory{active: nil}, cache, storeFn, home, project, guard, generalAgentTestBinding(active, modeActive))
	if err != nil {
		t.Fatalf("realizeToolRegistry: %v", err)
	}
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()}, home, project, storeFn, cache.MaxToolOutputBytes(), guard)
	calls := []turn.AssembledToolCall{
		structuredCall("ro", subagenttool.ToolName, map[string]any{"instructions": readOnlyInstruction}),
		structuredCall("wr", subagenttool.ToolName, map[string]any{"instructions": writerInstruction, "files": []any{"b.txt"}}),
	}
	plan := d.Plan(calls, len(calls))
	for i, unit := range plan.Units {
		res, rerr := unit.Run(context.Background())
		if rerr != nil || res.Denied {
			t.Fatalf("unit %d = %+v, %v, want the child run", i, res, rerr)
		}
	}

	mutating := []string{filetools.EditToolName, filetools.CreateToolName, filetools.DeleteToolName, filetools.MkdirToolName, filetools.MoveToolName}
	readOnly, writer := requests[readOnlyInstruction], requests[writerInstruction]
	if len(readOnly) != 2 || len(writer) != 2 {
		t.Fatalf("child rounds = %d read-only / %d writer, want 2 each", len(readOnly), len(writer))
	}
	for _, name := range mutating {
		if slices.Contains(toolNames(readOnly[0].Tools), name) {
			t.Errorf("read-only sibling was offered %q", name)
		}
		if !slices.Contains(toolNames(writer[0].Tools), name) {
			t.Errorf("path-declaring sibling lost %q", name)
		}
	}
	refusals := 0
	for _, m := range readOnly[1].Messages {
		if m.Role == "tool" && strings.Contains(m.Content, "not available to a read-only child agent") {
			refusals++
		}
	}
	if refusals != len(writes) {
		t.Fatalf("read-only refusals = %d, want one per attempted mutation (%d)", refusals, len(writes))
	}
	if body, rerr := os.ReadFile(notes); rerr != nil || string(body) != "hello\n" {
		t.Fatalf("notes.txt = %q (err=%v), want it untouched", body, rerr)
	}
	for _, absent := range []string{"made.txt", "newdir", "moved.txt"} {
		mustNotExist(t, filepath.Join(project, absent), "a read-only sibling changes nothing on disk")
	}
	if body, rerr := os.ReadFile(filepath.Join(project, "b.txt")); rerr != nil || string(body) != "written\n" {
		t.Fatalf("b.txt = %q (err=%v), want the path-declaring sibling's write", body, rerr)
	}
	var childWrites []events.PermissionMatched
	for _, m := range decodePermissionMatched(t, store) {
		if m.ChildInvocationID != "" {
			childWrites = append(childWrites, m)
		}
	}
	if len(childWrites) != 1 || childWrites[0].Subject != filetools.CreateToolName ||
		childWrites[0].OutcomeSource != permissions.OutcomeSourceDeclaredScope || childWrites[0].Outcome != "once" {
		t.Fatalf("child decisions = %+v, want the writer's create allowed by its own declared scope", childWrites)
	}
	if tool, _ := reg.Lookup(subagenttool.ToolName); tool.Advertise().ReadOnly {
		t.Fatal("general_agent metadata became read-only after a read-only launch")
	}
}

func TestChildCeiling_AnUnpreparedCallFallsBackToTheInheritedResolvedCandidate(t *testing.T) {
	cache, home, project, active, modeActive := generalAgentFixture(t)
	declared, _, err := filetools.ResolveDeclaredScopes(home, project, []string{"a.txt"}, nil)
	if err != nil {
		t.Fatalf("ResolveDeclaredScopes: %v", err)
	}
	for _, resolved := range []bool{false, true} {
		t.Run(fmt.Sprintf("inherited resolved %v", resolved), func(t *testing.T) {
			stub := &stubStructuredTool{name: subagenttool.ToolName, result: tools.Result{Stdout: []byte("grandchild ran\n")}}
			reg := tools.NewRegistry()
			if rerr := reg.Register(tools.BuiltinSource, stub); rerr != nil {
				t.Fatalf("Register: %v", rerr)
			}
			store := mkStore(t)
			deps := generalAgentTestBinding(active, modeActive).deps(reg, cache, func() *sessions.Store { return store }, home, project, mustProtectedStatePolicy(t, home, cache.ProjectRoot(), nil))
			d := deps.NewDispatcher(permissions.ModeContext{
				Mode:                 string(mode.Build),
				ChildAgent:           true,
				DeclaredWrite:        declared,
				GeneralAgentResolved: resolved,
			})

			res, derr := d.Dispatch(context.Background(), structuredCall("n1", subagenttool.ToolName, map[string]any{"instructions": "just look"}))
			if derr != nil {
				t.Fatalf("Dispatch error = %v, want nil", derr)
			}
			matched := decodePermissionMatched(t, store)
			if len(matched) != 1 {
				t.Fatalf("permission_matched = %+v, want exactly one decision", matched)
			}
			if resolved {
				if res.Denied || stub.callCount() != 1 || matched[0].OutcomeSource != "mode_auto" || matched[0].Outcome != "once" {
					t.Fatalf("result = %+v, calls = %d, permission_matched = %+v, want the inherited read-only candidate allowed", res, stub.callCount(), matched)
				}
				return
			}
			if !res.Denied || stub.callCount() != 0 || matched[0].OutcomeSource != permissions.OutcomeSourceDeclaredScope {
				t.Fatalf("result = %+v, calls = %d, permission_matched = %+v, want an unresolved candidate denied by declared scope", res, stub.callCount(), matched)
			}
		})
	}
}

type skillRun struct {
	home       string
	script     string
	store      *sessions.Store
	setStore   func(*sessions.Store)
	auth       *recordingAuthorizer
	dispatcher *productionToolDispatcher
}

func newSkillRun(t *testing.T, entries func(home string) []permissions.BlockedEntry) skillRun {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	global := filepath.Join(home, ".codemeld", "skills")
	writeSkill(t, global, "deploy", "description: Deploy\n")
	writeSkill(t, global, "release", "description: Release\ndisable-model-invocation: true\n")
	script := filepath.Join(global, "deploy", "scripts", "run.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(script, []byte("echo deploy\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var blocked []permissions.BlockedEntry
	if entries != nil {
		blocked = entries(home)
	}
	policy := securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, blocked)}
	result := &BootstrapResult{Home: home, ProjectRoot: project, ToolRegistry: &toolRegistryFactory{}}
	loadSkills(result, 65536)
	store := mkStore(t)
	active := store
	storeFn := func() *sessions.Store { return active }
	reg, err := realizeToolRegistry(result.ToolRegistry, emptyCache(t, project), storeFn, home, project, policy)
	if err != nil {
		t.Fatalf("realize: %v", err)
	}
	auth := &recordingAuthorizer{decision: allow()}
	return skillRun{
		home:       home,
		script:     script,
		store:      store,
		setStore:   func(s *sessions.Store) { active = s },
		auth:       auth,
		dispatcher: newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, storeFn, 65536, policy),
	}
}

func TestRealizeToolRegistry_RegistersSkillToolOnlyForLoadedSkills(t *testing.T) {
	for _, tc := range []struct {
		name   string
		set    skills.Set
		wanted bool
	}{
		{name: "empty", set: skills.Set{Skipped: []skills.Skipped{{Path: "/x", Reason: skills.BadName}}}},
		{name: "model-invocable", set: skills.Set{Loaded: []skills.Skill{{Name: "deploy", ModelInvocable: true}}}, wanted: true},
		{name: "slash-only", set: skills.Set{Loaded: []skills.Skill{{Name: "release"}}}, wanted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			factory := &toolRegistryFactory{skills: tc.set}
			reg, err := factory.realize(emptyCache(t, t.TempDir()), func() *sessions.Store { return mkStore(t) }, t.TempDir(), t.TempDir(), securitystate.Policy{})
			if err != nil {
				t.Fatalf("realize: %v", err)
			}
			tool, ok := reg.Lookup("skill")
			if ok != tc.wanted {
				t.Fatalf("skill registered = %v, want %v", ok, tc.wanted)
			}
			if ok && (!tool.Advertise().ReadOnly || !tool.Advertise().Noncredential) {
				t.Fatalf("skill metadata = %+v, want read-only and non-credential", tool.Advertise())
			}
		})
	}
}

func TestLoadSkills_AttachesTheRecordToTheToolRegistryFactory(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	writeSkill(t, filepath.Join(home, ".codemeld", "skills"), "deploy", "description: Deploy\n")
	factory := &toolRegistryFactory{}
	result := &BootstrapResult{Home: home, ProjectRoot: project, ToolRegistry: factory}

	loadSkills(result, 65536)

	if len(result.Skills.Loaded) != 1 || !reflect.DeepEqual(factory.skills, result.Skills) {
		t.Fatalf("factory skills = %+v, want the loaded record %+v", factory.skills, result.Skills)
	}
}

func TestProductionDispatcher_SkillToolReadsAGlobalSkillFileTheReadToolRefuses(t *testing.T) {
	run := newSkillRun(t, nil)

	res, err := run.dispatcher.Dispatch(context.Background(), structuredCall("c1", "skill", map[string]any{"name": "deploy", "file": "scripts/run.sh"}))
	if err != nil || res.Denied || res.Content != "echo deploy" {
		t.Fatalf("skill file read = (%+v, %v), want the script", res, err)
	}
	res, err = run.dispatcher.Dispatch(context.Background(), structuredCall("c2", "skill", map[string]any{"name": "deploy"}))
	if err != nil || res.Denied || !strings.Contains(res.Content, "SKILL-BODY-MARKER") || !strings.Contains(res.Content, "- scripts/run.sh") {
		t.Fatalf("skill body = (%+v, %v), want the body and its file list", res, err)
	}

	res, err = run.dispatcher.Dispatch(context.Background(), structuredCall("c3", filetools.ReadToolName, map[string]any{"path": run.script}))
	if err != nil || !res.Denied || strings.Contains(res.Content, "echo deploy") {
		t.Fatalf("read of the same path = (%+v, %v), want a denial", res, err)
	}
}

func TestProductionDispatcher_SkillToolBlockedReadIsARecordedGuardDenial(t *testing.T) {
	source := "/etc/codemeld-test/settings.yaml"
	var scripts string
	run := newSkillRun(t, func(home string) []permissions.BlockedEntry {
		scripts = filepath.Join(home, ".codemeld", "skills", "deploy", "scripts")
		return []permissions.BlockedEntry{{Path: scripts, Source: source}}
	})

	res, err := run.dispatcher.Dispatch(context.Background(), structuredCall("c1", "skill", map[string]any{"name": "deploy", "file": "scripts/run.sh"}))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want an in-band denial", err)
	}
	if !res.Denied || !permissions.IsModeDenyEnvelope(res.Content) || strings.Contains(res.Content, "echo deploy") {
		t.Fatalf("res = %+v, want a recoverable guard denial without the file", res)
	}
	if want := permissions.BuildBlockedPathDenyEnvelope(run.script, scripts, false); res.Content != want || strings.Contains(res.Content, source) {
		t.Fatalf("res.Content = %q, want exactly %q with no settings path", res.Content, want)
	}
	if want := blockedSourceLine(scripts, source); res.Notice != want {
		t.Fatalf("res.Notice = %q, want %q", res.Notice, want)
	}
	want := events.PermissionMatched{SubjectKind: "tool", Subject: "skill", PathScope: scripts, Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: scripts, BlockedEntrySource: source}
	if matched := decodePermissionMatched(t, reloadStore(t, run.store)); len(matched) != 1 || matched[0] != want {
		t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
	}
}

func skillDigest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func diskSkillLoads(t *testing.T, store *sessions.Store) []events.SkillLoaded {
	t.Helper()
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("flush session: %v", err)
	}
	sess := readSessionFile(t, store.Path())
	for _, r := range sess.Records {
		if ev, ok := r.(sessions.Event); ok && ev.Kind == "skill_loaded" {
			if err := events.ValidatePayload(ev.Kind, ev.Payload); err != nil {
				t.Fatalf("skill_loaded payload %s: %v", ev.Payload, err)
			}
		}
	}
	return decodeDiskEvents[events.SkillLoaded](t, sess, "skill_loaded")
}

func TestProductionDispatcher_SkillToolLoadsReachTheTurnStoreWithTheCaller(t *testing.T) {
	run := newSkillRun(t, nil)
	body := events.SkillLoaded{Name: "deploy", Layer: "global", Via: "tool", Bytes: int64(len("SKILL-BODY-MARKER\n")), SHA256: skillDigest("SKILL-BODY-MARKER\n")}
	file := events.SkillLoaded{Name: "deploy", Layer: "global", Via: "tool", File: "scripts/run.sh", Bytes: int64(len("echo deploy\n")), SHA256: skillDigest("echo deploy\n")}

	if res, err := run.dispatcher.Dispatch(context.Background(), structuredCall("c1", "skill", map[string]any{"name": "deploy"})); err != nil || res.Denied {
		t.Fatalf("body read = (%+v, %v), want success", res, err)
	}
	if got := diskSkillLoads(t, run.store); !reflect.DeepEqual(got, []events.SkillLoaded{body}) {
		t.Fatalf("first store skill_loaded = %+v, want only the body load %+v", got, body)
	}

	swapped := mkStore(t)
	run.setStore(swapped)
	file.ChildInvocationID = ids.NewV7()
	run.dispatcher.childInvocationID = file.ChildInvocationID
	if res, err := run.dispatcher.Dispatch(context.Background(), structuredCall("c2", "skill", map[string]any{"name": "deploy", "file": "scripts/run.sh"})); err != nil || res.Content != "echo deploy" {
		t.Fatalf("child file read = (%+v, %v), want the script", res, err)
	}
	if got := diskSkillLoads(t, swapped); !reflect.DeepEqual(got, []events.SkillLoaded{file}) {
		t.Fatalf("swapped store skill_loaded = %+v, want only the child file load %+v", got, file)
	}
	if got := diskSkillLoads(t, run.store); len(got) != 1 {
		t.Fatalf("first store skill_loaded = %+v, want the second load kept out of it", got)
	}
}

func TestProductionDispatcher_SkillToolWithoutAStoreStillReads(t *testing.T) {
	run := newSkillRun(t, nil)
	run.setStore(nil)

	res, err := run.dispatcher.Dispatch(context.Background(), structuredCall("c1", "skill", map[string]any{"name": "deploy", "file": "scripts/run.sh"}))
	if err != nil || res.Content != "echo deploy" {
		t.Fatalf("file read with no store = (%+v, %v), want the script", res, err)
	}
}

func TestProductionDispatcher_SkillToolLoadRecordFailureIsAnError(t *testing.T) {
	run := newSkillRun(t, nil)
	run.dispatcher.childInvocationID = "not-a-uuid"

	res, err := run.dispatcher.Dispatch(context.Background(), structuredCall("c1", "skill", map[string]any{"name": "deploy", "file": "scripts/run.sh"}))
	if err == nil || strings.Contains(res.Content, "echo deploy") {
		t.Fatalf("file read with an unrecordable load = (%+v, %v), want an error and no content", res, err)
	}
	if got := diskSkillLoads(t, run.store); len(got) != 0 {
		t.Fatalf("skill_loaded = %+v, want none", got)
	}
}

func TestProductionDispatcher_SkillToolFailuresStayInBand(t *testing.T) {
	run := newSkillRun(t, nil)
	for _, tc := range []struct {
		name string
		args map[string]any
		text string
	}{
		{name: "unknown name", args: map[string]any{"name": "nope"}, text: `no skill named "nope"; available skills: deploy`},
		{name: "invalid arguments", args: map[string]any{"file": "scripts/run.sh"}, text: `argument "name"`},
		{name: "refused body", args: map[string]any{"name": "release"}, text: "automatic loading of skill \"release\" is disabled"},
		{name: "missing file", args: map[string]any{"name": "deploy", "file": "nope.txt"}, text: `file "nope.txt" does not exist`},
	} {
		res, err := run.dispatcher.Dispatch(context.Background(), structuredCall("c", "skill", tc.args))
		if err != nil || res.Denied || !strings.Contains(res.Content, tc.text) || !strings.HasSuffix(res.Content, "exit status 1") {
			t.Fatalf("%s = (%+v, %v), want a failed in-band result naming %q", tc.name, res, err, tc.text)
		}
	}
	res, err := run.dispatcher.Dispatch(context.Background(), structuredCall("c", "skill", map[string]any{"name": "deploy", "file": "scripts/run.sh"}))
	if err != nil || res.Content != "echo deploy" {
		t.Fatalf("later call = (%+v, %v), want the dispatcher still serving", res, err)
	}
}
