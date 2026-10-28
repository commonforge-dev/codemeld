package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	cmdrunner "codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/turn"
	"codemeld.dev/codemeld/internal/vcs"
)

func TestProductionDispatcher_MalformedBashArgsNoPromptNoCrash(t *testing.T) {
	cases := []struct {
		name, args, wantSub string
	}{
		{"invalid json", `{"command":`, "invalid bash arguments"},
		{"missing command", `{}`, "missing"},
		{"blank command", `{"command":"   "}`, "missing"},
		{"empty arguments", ``, "invalid bash arguments"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := &fakeDispatchRunner{}
			auth := &recordingAuthorizer{decision: allow()}
			d := dispatcherFor(t, tools.NewRegistry(), run, auth)

			res, err := d.Dispatch(context.Background(), turn.AssembledToolCall{ID: "c1", Name: "bash", Arguments: tc.args})
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil (malformed args surface in-band)", err)
			}
			if !strings.Contains(res.Content, tc.wantSub) {
				t.Fatalf("content = %q, want it to mention %q", res.Content, tc.wantSub)
			}
			if auth.callCount() != 0 {
				t.Fatalf("authorizer calls = %d, want 0 (malformed bash args must not prompt)", auth.callCount())
			}
			if run.callCount() != 0 {
				t.Fatalf("runner Exec calls = %d, want 0 (malformed bash args must not run)", run.callCount())
			}
		})
	}
}

func TestProductionDispatcher_ShellToolHintUnsetRunsShell(t *testing.T) {
	t.Setenv(EnvShellToolHint, "")
	run := &fakeDispatchRunner{}
	auth := &recordingAuthorizer{decision: allow()}
	d := dispatcherFor(t, tools.NewRegistry(), run, auth)

	res, err := d.Dispatch(context.Background(), bashCall("c1", "grep x main.go"))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if strings.HasPrefix(res.Content, "shell-tool hint:") {
		t.Fatalf("content = %q, want no hint while %s is unset", res.Content, EnvShellToolHint)
	}
	if run.callCount()+auth.callCount() == 0 {
		t.Fatal("grep never reached DispatchShell while the hint flag is unset")
	}
}

func TestProductionDispatcher_ShellToolHintRefusesMappedPrograms(t *testing.T) {
	t.Setenv(EnvShellToolHint, "1")
	cases := []struct {
		name, command string
		want          []string
	}{
		{"single program", "grep x main.go", []string{"grep tool instead of grep"}},
		{"pipeline names both", "grep x main.go | head -n 5", []string{"grep tool instead of grep", "read tool instead of head"}},
		{"path-qualified program", "/usr/bin/find . -name '*.go'", []string{"glob tool instead of find"}},
		{"ls", "ls internal", []string{"list tool instead of ls"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := &fakeDispatchRunner{}
			auth := &recordingAuthorizer{decision: allow()}
			d := dispatcherFor(t, tools.NewRegistry(), run, auth)

			res, err := d.Dispatch(context.Background(), bashCall("c1", tc.command))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil (the hint is an in-band result)", err)
			}
			if !strings.HasPrefix(res.Content, "shell-tool hint:") {
				t.Fatalf("content = %q, want the shell-tool hint prefix", res.Content)
			}
			for _, want := range tc.want {
				if !strings.Contains(res.Content, want) {
					t.Errorf("content = %q, want it to say %q", res.Content, want)
				}
			}
			if res.Denied {
				t.Error("hint result marked Denied, want a plain tool result")
			}
			if run.callCount() != 0 || auth.callCount() != 0 {
				t.Fatalf("runner/authorizer calls = %d/%d, want 0/0 (a hinted command never runs or prompts)", run.callCount(), auth.callCount())
			}
			store := d.active()
			if n := len(kindEvents(t, store, events.KindToolExecStart)) + len(kindEvents(t, store, events.KindToolExecEnd)); n != 0 {
				t.Fatalf("tool_exec records = %d, want 0", n)
			}
		})
	}
}

func TestProductionDispatcher_ShellToolHintUnmappedRunsShell(t *testing.T) {
	t.Setenv(EnvShellToolHint, "1")
	for _, command := range []string{"hg status", "wc -l main.go", "sed -n 1p main.go"} {
		t.Run(command, func(t *testing.T) {
			run := &fakeDispatchRunner{}
			auth := &recordingAuthorizer{decision: allow()}
			d := dispatcherFor(t, tools.NewRegistry(), run, auth)

			res, err := d.Dispatch(context.Background(), bashCall("c1", command))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}
			if strings.HasPrefix(res.Content, "shell-tool hint:") {
				t.Fatalf("content = %q, want no hint for an unmapped program", res.Content)
			}
			if run.callCount() == 0 {
				t.Fatal("runner not invoked; an unmapped program must run normally")
			}
		})
	}
}

type fakePipelineDispatchRunner struct {
	fakeDispatchRunner
	preflightErr error
	preflights   int
	pipelines    int
	gotSpecs     []cmdrunner.RunSpec
	gotCap       int
	results      []cmdrunner.PipelineResult
	pipelineErr  error
}

var _ cmdrunner.PipelineRunner = (*fakePipelineDispatchRunner)(nil)

func (f *fakePipelineDispatchRunner) PreflightPipeline(context.Context, []cmdrunner.RunSpec) error {
	f.preflights++
	return f.preflightErr
}

func (f *fakePipelineDispatchRunner) Pipeline(_ context.Context, specs []cmdrunner.RunSpec, maxCapture int) ([]cmdrunner.PipelineResult, error) {
	f.pipelines++
	f.gotSpecs = specs
	f.gotCap = maxCapture
	return f.results, f.pipelineErr
}

func pipelineStageSpecs(scope string, argvs ...[]string) []cmdrunner.RunSpec {
	specs := make([]cmdrunner.RunSpec, len(argvs))
	for i, argv := range argvs {
		specs[i] = cmdrunner.RunSpec{InvocationID: ids.NewV7(), Argv: argv, Cwd: scope}
	}
	return specs
}

func TestShellEventRunner_PipelinePairsEveryStageAndReportsTrueTotals(t *testing.T) {
	store := mkStore(t)
	scope := t.TempDir()
	specs := pipelineStageSpecs(scope, []string{"alpha", "-x"}, []string{"beta"})
	inner := &fakePipelineDispatchRunner{results: []cmdrunner.PipelineResult{
		{InvocationID: specs[0].InvocationID, Stdout: []byte("AAAA"), StdoutTotal: 12, ExitCode: 0, Duration: 7 * time.Millisecond},
		{InvocationID: specs[1].InvocationID, Stdout: []byte("BB"), StdoutTotal: 2, Stderr: []byte("ee"), StderrTotal: 2, ExitCode: 5, Duration: 3 * time.Millisecond},
	}}
	r := &shellEventRunner{inner: inner, active: func() *sessions.Store { return store }, cap: 4}

	if err := r.PreflightPipeline(context.Background(), specs); err != nil {
		t.Fatalf("PreflightPipeline error = %v, want nil", err)
	}
	if got := len(kindEvents(t, store, events.KindToolExecStart)); got != 0 {
		t.Fatalf("starts appended during preflight = %d, want 0 (nothing is emitted until the pipeline runs)", got)
	}
	results, err := r.Pipeline(context.Background(), specs)
	if err != nil {
		t.Fatalf("Pipeline error = %v, want nil", err)
	}
	if len(results) != 2 || inner.gotCap != 4 {
		t.Fatalf("inner results/cap = %d/%d, want 2 results run at the decorator's cap 4", len(results), inner.gotCap)
	}

	reloaded := reloadStore(t, store)
	starts := decodeStoreEvents[events.ToolExecStart](t, reloaded, events.KindToolExecStart)
	ends := decodeStoreEvents[events.ToolExecEnd](t, reloaded, events.KindToolExecEnd)
	if len(starts) != 2 || len(ends) != 2 {
		t.Fatalf("tool_exec events = %d start/%d end, want one pair per stage", len(starts), len(ends))
	}
	wantSubjects := []string{"alpha -x", "beta"}
	for i := range starts {
		if starts[i].InvocationID != specs[i].InvocationID || ends[i].InvocationID != specs[i].InvocationID {
			t.Fatalf("stage %d ids = %q/%q, want the dispatch-minted %q on both records", i, starts[i].InvocationID, ends[i].InvocationID, specs[i].InvocationID)
		}
		if starts[i].SubjectKind != "direct" || starts[i].Subject != wantSubjects[i] {
			t.Fatalf("stage %d start subject = %q/%q, want direct/%q", i, starts[i].SubjectKind, starts[i].Subject, wantSubjects[i])
		}
		if ends[i].SubjectKind != starts[i].SubjectKind || ends[i].Subject != starts[i].Subject {
			t.Fatalf("stage %d end subject = %q/%q, want the start's %q/%q", i, ends[i].SubjectKind, ends[i].Subject, starts[i].SubjectKind, starts[i].Subject)
		}
	}
	if ends[0].DurationMs != 7 || ends[1].DurationMs != 3 {
		t.Fatalf("stage durations = %d/%d ms, want each stage's own wall time (7/3)", ends[0].DurationMs, ends[1].DurationMs)
	}
	if ends[1].ExitCode != 5 {
		t.Fatalf("stage 1 exit code = %d, want 5", ends[1].ExitCode)
	}
	if !ends[0].Truncated || ends[0].OriginalBytes == nil || ends[0].OriginalBytes.Stdout != 12 {
		t.Fatalf("stage 0 end = %+v, want truncated with original_bytes.stdout 12 (the total read, not the retained 4)", ends[0])
	}
	if ends[1].Truncated {
		t.Fatalf("stage 1 end = %+v, want truncated false (nothing was dropped)", ends[1])
	}
}

func TestShellEventRunner_PreflightFailuresEmitNothingAndStartNothing(t *testing.T) {
	boom := errors.New("boom")
	scope := t.TempDir()
	cases := []struct {
		name        string
		inner       dispatch.Runner
		active      func(*sessions.Store) func() *sessions.Store
		wantErrIs   error
		wantErrText string
	}{
		{
			name:      "inner runner lacks the capability",
			inner:     &fakeDispatchRunner{},
			wantErrIs: dispatch.ErrPipelineUnsupported,
		},
		{
			name:      "inner preflight rejects the specs",
			inner:     &fakePipelineDispatchRunner{preflightErr: boom},
			wantErrIs: boom,
		},
		{
			name:        "no active session store",
			inner:       &fakePipelineDispatchRunner{},
			active:      func(*sessions.Store) func() *sessions.Store { return func() *sessions.Store { return nil } },
			wantErrText: "no active session store",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := mkStore(t)
			active := func() *sessions.Store { return store }
			if tc.active != nil {
				active = tc.active(store)
			}
			r := &shellEventRunner{inner: tc.inner, active: active, cap: 64}
			specs := pipelineStageSpecs(scope, []string{"alpha"}, []string{"beta"})

			err := r.PreflightPipeline(context.Background(), specs)
			if err == nil {
				t.Fatalf("PreflightPipeline error = nil, want a failure before anything is started or emitted")
			}
			if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
				t.Fatalf("PreflightPipeline error = %v, want %v", err, tc.wantErrIs)
			}
			if tc.wantErrText != "" && !strings.Contains(err.Error(), tc.wantErrText) {
				t.Fatalf("PreflightPipeline error = %v, want it to mention %q", err, tc.wantErrText)
			}
			if got := len(store.Records()); got != 0 {
				t.Fatalf("records appended = %d, want 0", got)
			}
			if inner, ok := tc.inner.(*fakePipelineDispatchRunner); ok && inner.pipelines != 0 {
				t.Fatalf("inner pipeline runs = %d, want 0 (a failed preflight starts nothing)", inner.pipelines)
			}
		})
	}
}

func TestShellEventRunner_PostLaunchErrorStillPairsEveryEmittedStart(t *testing.T) {
	store := mkStore(t)
	scope := t.TempDir()
	specs := pipelineStageSpecs(scope, []string{"alpha"}, []string{"beta"})
	boom := errors.New("copy failed")
	inner := &fakePipelineDispatchRunner{
		pipelineErr: boom,
		results: []cmdrunner.PipelineResult{
			{InvocationID: specs[0].InvocationID, ExitCode: -1, PipelineErrCategory: cmdrunner.PipelineFailureCopy},
			{InvocationID: specs[1].InvocationID, ExitCode: -1, PipelineErrCategory: cmdrunner.PipelineFailureCopy},
		},
	}
	r := &shellEventRunner{inner: inner, active: func() *sessions.Store { return store }, cap: 64}

	if err := r.PreflightPipeline(context.Background(), specs); err != nil {
		t.Fatalf("PreflightPipeline error = %v, want nil", err)
	}
	_, err := r.Pipeline(context.Background(), specs)
	if !errors.Is(err, boom) {
		t.Fatalf("Pipeline error = %v, want %v", err, boom)
	}
	starts := decodeStoreEvents[events.ToolExecStart](t, store, events.KindToolExecStart)
	ends := decodeStoreEvents[events.ToolExecEnd](t, store, events.KindToolExecEnd)
	if len(starts) != 2 || len(ends) != 2 {
		t.Fatalf("tool_exec events = %d start/%d end, want the error returned only after every start is paired", len(starts), len(ends))
	}
	for i := range ends {
		if ends[i].InvocationID != starts[i].InvocationID {
			t.Fatalf("stage %d end id = %q, want the start's %q", i, ends[i].InvocationID, starts[i].InvocationID)
		}
	}
}

func TestShellEventRunner_PipelineWithoutPreflightRunsNothing(t *testing.T) {
	store := mkStore(t)
	inner := &fakePipelineDispatchRunner{}
	r := &shellEventRunner{inner: inner, active: func() *sessions.Store { return store }, cap: 64}

	_, err := r.Pipeline(context.Background(), pipelineStageSpecs(t.TempDir(), []string{"alpha"}, []string{"beta"}))
	if err == nil {
		t.Fatalf("Pipeline error = nil, want a refusal when no preflight admitted the pipeline")
	}
	if errors.Is(err, dispatch.ErrPipelineUnsupported) {
		t.Fatalf("Pipeline error = %v, want a plain failure, not the sentinel that would fall back and run the stages again", err)
	}
	if inner.pipelines != 0 || len(store.Records()) != 0 {
		t.Fatalf("inner runs = %d, records = %d, want nothing run and nothing emitted", inner.pipelines, len(store.Records()))
	}
}

func TestProductionDispatcher_BashPipelineEmitsPerStageEventsWithoutTheCapability(t *testing.T) {
	prependFixturePrograms(t, "alpha", "beta")
	store := mkStore(t)
	run := &fakeDispatchRunner{result: cmdrunner.RunResult{Stdout: []byte("piped")}}
	d := newProductionToolDispatcher(tools.NewRegistry(), run, &recordingAuthorizer{decision: allow()}, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 64, securitystate.Policy{})

	res, err := d.Dispatch(context.Background(), bashCall("c1", "alpha | beta"))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if run.callCount() != 2 {
		t.Fatalf("Exec calls = %d, want 2 (a runner without the pipeline capability keeps the sequential loop)", run.callCount())
	}
	starts := decodeStoreEvents[events.ToolExecStart](t, store, events.KindToolExecStart)
	ends := decodeStoreEvents[events.ToolExecEnd](t, store, events.KindToolExecEnd)
	if len(starts) != 2 || len(ends) != 2 {
		t.Fatalf("tool_exec events = %d start/%d end, want the same per-stage pairs as before the pipeline capability", len(starts), len(ends))
	}
	if res.Content != "piped" {
		t.Fatalf("content = %q, want the final stage's stdout", res.Content)
	}
}

func TestProductionDispatcher_BashPipelinePersistsExactlyTheModelInputBytes(t *testing.T) {
	prependFixturePrograms(t, "alpha", "beta")
	store := mkStore(t)
	const cap = 8
	retained := []byte("out\nmore\n")
	inner := &fakePipelineDispatchRunner{}
	d := newProductionToolDispatcher(tools.NewRegistry(), inner, &recordingAuthorizer{decision: allow()}, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, cap, securitystate.Policy{})
	inner.results = []cmdrunner.PipelineResult{
		{Stdout: []byte("upstream"), StdoutTotal: 8, Stderr: []byte("e1"), StderrTotal: 2},
		{Stdout: retained, StdoutTotal: 40, Stderr: []byte("e2"), StderrTotal: 2},
	}

	res, err := d.Dispatch(context.Background(), bashCall("c1", "alpha | beta"))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if inner.pipelines != 1 || inner.callCount() != 0 {
		t.Fatalf("pipeline runs = %d, Exec calls = %d, want the pipeline capability used once and no sequential rerun", inner.pipelines, inner.callCount())
	}
	ends := decodeStoreEvents[events.ToolExecEnd](t, reloadStore(t, store), events.KindToolExecEnd)
	if len(ends) != 2 {
		t.Fatalf("tool_exec_end events = %d, want one per stage", len(ends))
	}
	wantStdout, _ := events.BuildModelInputBytes(retained, nil, cap)
	if !bytes.Equal([]byte(ends[1].Stdout), wantStdout) {
		t.Fatalf("persisted final stdout = %q, want %q (byte-equal to BuildModelInputBytes on the retained prefix)", ends[1].Stdout, wantStdout)
	}
	if !ends[1].Truncated || ends[1].OriginalBytes == nil || ends[1].OriginalBytes.Stdout != 40 {
		t.Fatalf("final end = %+v, want truncated with the true 40-byte total", ends[1])
	}
	wantContent := strings.TrimRight(string(wantStdout), "\n") + "\nstderr:\ne1e2"
	if res.Content != wantContent {
		t.Fatalf("model content = %q, want %q — the persisted final stdout after the formatter's cosmetic newline trim, then every stage's stderr in order", res.Content, wantContent)
	}
}

// This is the only test that drives the whole production wiring — DirectExecRunner behind
// shellEventRunner behind DispatchShell — against real processes.
func TestProductionDispatcher_BashPipelineStreamsAndBoundsThroughTheRealRunner(t *testing.T) {
	if _, err := exec.LookPath("yes"); err != nil {
		t.Skipf("yes not available: %v", err)
	}
	if _, err := exec.LookPath("head"); err != nil {
		t.Skipf("head not available: %v", err)
	}
	store := mkStore(t)
	const cap = 4
	d := newProductionToolDispatcher(tools.NewRegistry(), cmdrunner.DirectExecRunner{}, &recordingAuthorizer{decision: allow()}, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, cap, securitystate.Policy{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		res turn.ToolResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := d.Dispatch(ctx, bashCall("c1", "yes | head -c 5000"))
		done <- outcome{res: res, err: err}
	}()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("Dispatch error = %v, want nil", got.err)
		}
		if got.res.Content != "y\ny" {
			t.Fatalf("content = %q, want the capped final stdout after the formatter's newline trim", got.res.Content)
		}
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatalf("`yes | head -c 5000` did not return within 30s")
	}

	reloaded := reloadStore(t, store)
	starts := decodeStoreEvents[events.ToolExecStart](t, reloaded, events.KindToolExecStart)
	ends := decodeStoreEvents[events.ToolExecEnd](t, reloaded, events.KindToolExecEnd)
	if len(starts) != 2 || len(ends) != 2 {
		t.Fatalf("tool_exec events = %d start/%d end, want one durable pair per stage", len(starts), len(ends))
	}
	for i := range ends {
		if ends[i].InvocationID != starts[i].InvocationID || !ids.IsValidV7(ends[i].InvocationID) {
			t.Fatalf("stage %d ids = %q/%q, want one shared UUIDv7 per stage", i, starts[i].InvocationID, ends[i].InvocationID)
		}
		if len(ends[i].Stdout) > cap {
			t.Fatalf("stage %d persisted stdout = %d bytes, want at most the %d-byte cap", i, len(ends[i].Stdout), cap)
		}
	}
	if !ends[1].Truncated || ends[1].OriginalBytes == nil || ends[1].OriginalBytes.Stdout != 5000 {
		t.Fatalf("final stage end = %+v, want truncated with the 5000 bytes it really produced", ends[1])
	}
	if ends[0].OriginalBytes != nil && ends[0].OriginalBytes.Stdout < int64(len(ends[0].Stdout)) {
		t.Fatalf("producer original_bytes = %d, want at least the captured %d", ends[0].OriginalBytes.Stdout, len(ends[0].Stdout))
	}
}

// --- dispatcher: protected-state guard --------------------------------------

type fakeBoundedDispatchRunner struct {
	fakeDispatchRunner
	bounded int
	gotCap  int
}

func (f *fakeBoundedDispatchRunner) ExecBounded(_ context.Context, _ cmdrunner.RunSpec, maxCapture int) (cmdrunner.RunResult, error) {
	f.bounded++
	f.gotCap = maxCapture
	return f.result, f.err
}

func boundedSpec(t *testing.T) cmdrunner.RunSpec {
	return cmdrunner.RunSpec{InvocationID: ids.NewV7(), Argv: []string{"sh", "-c", "yes | head"}, Cwd: t.TempDir()}
}

func TestShellEventRunner_ExecBoundedRecordsRetainedBytesAndTotals(t *testing.T) {
	store := mkStore(t)
	spec := boundedSpec(t)
	inner := &fakeBoundedDispatchRunner{fakeDispatchRunner: fakeDispatchRunner{result: cmdrunner.RunResult{
		InvocationID: spec.InvocationID,
		Stdout:       []byte("abcd"),
		StdoutTotal:  900,
		Stderr:       []byte("ee"),
		StderrTotal:  2,
		ExitCode:     2,
		Duration:     5 * time.Millisecond,
	}}}
	r := &shellEventRunner{inner: inner, active: func() *sessions.Store { return store }, cap: 64}

	res, err := r.ExecBounded(context.Background(), spec, 4)
	if err != nil {
		t.Fatalf("ExecBounded error = %v", err)
	}
	if inner.bounded != 1 || inner.gotCap != 4 || inner.callCount() != 0 {
		t.Fatalf("inner bounded/cap/exec = %d/%d/%d, want one ExecBounded at cap 4 and no Exec", inner.bounded, inner.gotCap, inner.callCount())
	}
	if res.StdoutTotal != 900 {
		t.Fatalf("returned StdoutTotal = %d, want 900", res.StdoutTotal)
	}
	reloaded := reloadStore(t, store)
	starts := decodeStoreEvents[events.ToolExecStart](t, reloaded, events.KindToolExecStart)
	ends := decodeStoreEvents[events.ToolExecEnd](t, reloaded, events.KindToolExecEnd)
	if len(starts) != 1 || len(ends) != 1 {
		t.Fatalf("tool_exec events = %d start/%d end, want one pair", len(starts), len(ends))
	}
	want := events.ToolExecEnd{
		SubjectKind:   "literal",
		Subject:       "yes | head",
		ExitCode:      2,
		DurationMs:    5,
		Stdout:        "abcd",
		Stderr:        "ee",
		Truncated:     true,
		OriginalBytes: &events.OriginalBytes{Stdout: 900, Stderr: 2},
		InvocationID:  spec.InvocationID,
	}
	if ends[0].OriginalBytes == nil || *ends[0].OriginalBytes != *want.OriginalBytes {
		t.Fatalf("original_bytes = %+v, want %+v", ends[0].OriginalBytes, want.OriginalBytes)
	}
	got := ends[0]
	got.OriginalBytes, want.OriginalBytes = nil, nil
	if got != want {
		t.Fatalf("end = %+v, want %+v", got, want)
	}
}

func TestShellEventRunner_ExecBoundedWithoutCapabilityRecordsNothing(t *testing.T) {
	store := mkStore(t)
	inner := &fakeDispatchRunner{}
	r := &shellEventRunner{inner: inner, active: func() *sessions.Store { return store }, cap: 64}

	if _, err := r.ExecBounded(context.Background(), boundedSpec(t), 4); err == nil {
		t.Fatalf("ExecBounded error = nil, want a refusal when the inner runner cannot bound output")
	}
	if inner.callCount() != 0 || len(store.Records()) != 0 {
		t.Fatalf("inner runs = %d, records = %d, want nothing run and nothing recorded", inner.callCount(), len(store.Records()))
	}
}

func TestShellEventRunner_ExecBoundedInnerErrorPairsSynthesizedEnd(t *testing.T) {
	boom := errors.New("capture failed")
	for _, endFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "end recorded", true: "end emission fails"}[endFails], func(t *testing.T) {
			store := mkStore(t)
			spec := boundedSpec(t)
			calls := 0
			active := func() *sessions.Store {
				calls++
				if endFails && calls > 1 {
					return nil
				}
				return store
			}
			inner := &fakeBoundedDispatchRunner{fakeDispatchRunner: fakeDispatchRunner{
				result: cmdrunner.RunResult{Stdout: []byte("partial"), StdoutTotal: 7, ExitCode: 0},
				err:    boom,
			}}
			childID := ids.NewV7()
			r := &shellEventRunner{inner: inner, active: active, cap: 64, childInvocationID: childID}

			_, err := r.ExecBounded(context.Background(), spec, 4)
			if !errors.Is(err, boom) {
				t.Fatalf("ExecBounded error = %v, want the runner error %v", err, boom)
			}
			starts := decodeStoreEvents[events.ToolExecStart](t, store, events.KindToolExecStart)
			ends := decodeStoreEvents[events.ToolExecEnd](t, store, events.KindToolExecEnd)
			if len(starts) != 1 {
				t.Fatalf("starts = %d, want 1", len(starts))
			}
			if endFails {
				if len(ends) != 0 || !strings.Contains(err.Error(), "nil store") {
					t.Fatalf("ends = %d, err = %v, want no end and the emission failure joined", len(ends), err)
				}
				return
			}
			want := events.ToolExecEnd{
				SubjectKind:       starts[0].SubjectKind,
				Subject:           starts[0].Subject,
				ExitCode:          -1,
				InvocationID:      spec.InvocationID,
				ChildInvocationID: childID,
			}
			if len(ends) != 1 || ends[0].OriginalBytes != nil || ends[0] != want {
				t.Fatalf("ends = %+v, want exactly one synthesized end %+v", ends, want)
			}
		})
	}
}

func TestShellEventRunner_ExecUnboundedEndUnchanged(t *testing.T) {
	store := mkStore(t)
	spec := boundedSpec(t)
	inner := &fakeDispatchRunner{result: cmdrunner.RunResult{
		InvocationID: spec.InvocationID,
		Stdout:       []byte("abcdefgh"),
		Stderr:       []byte("e"),
		ExitCode:     1,
		Duration:     3 * time.Millisecond,
	}}
	r := &shellEventRunner{inner: inner, active: func() *sessions.Store { return store }, cap: 4}

	if _, err := r.Exec(context.Background(), spec); err != nil {
		t.Fatalf("Exec error = %v", err)
	}
	ends := decodeStoreEvents[events.ToolExecEnd](t, store, events.KindToolExecEnd)
	if len(ends) != 1 {
		t.Fatalf("ends = %d, want 1", len(ends))
	}
	got := ends[0]
	if got.Stdout != "abcd" || got.Stderr != "e" || !got.Truncated || got.OriginalBytes == nil ||
		*got.OriginalBytes != (events.OriginalBytes{Stdout: 8, Stderr: 1}) || got.ExitCode != 1 || got.DurationMs != 3 {
		t.Fatalf("end = %+v (original %+v), want the full-stream derivation", got, got.OriginalBytes)
	}
}

func TestConfinedShellRunner_EventsKeepTheAsWrittenSubject(t *testing.T) {
	store := mkStore(t)
	cwd := t.TempDir()
	lookup := programDir(t, "ls")
	inner := &confineInner{}
	r := &confinedShellRunner{
		events: &shellEventRunner{inner: inner, active: func() *sessions.Store { return store }, cap: 64},
		conf:   &confinement{constrained: true, mode: fixedMode("plan"), lookupPath: lookup, blocked: testBlocked(t)},
	}

	if _, err := r.Exec(context.Background(), confinedSpec(cwd, "ls", "-la")); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	wantHelperArgv(t, inner.bounded[0].Argv, filepath.Join(lookup, "ls"), "-la")
	reloaded := reloadStore(t, store)
	starts := decodeStoreEvents[events.ToolExecStart](t, reloaded, events.KindToolExecStart)
	ends := decodeStoreEvents[events.ToolExecEnd](t, reloaded, events.KindToolExecEnd)
	if len(starts) != 1 || len(ends) != 1 {
		t.Fatalf("tool_exec events = %d start/%d end, want one pair", len(starts), len(ends))
	}
	if starts[0].SubjectKind != "direct" || starts[0].Subject != "ls -la" || ends[0].Subject != "ls -la" {
		t.Fatalf("subjects = %q/%q, want the as-written \"ls -la\"", starts[0].Subject, ends[0].Subject)
	}
}

func TestConfinedShellRunner_PipeGroupRunsAsFramedStages(t *testing.T) {
	lookup := programDir(t, "ls", "head")
	inner := &confineInner{stdout: []byte("STAGE-OUT")}
	d := dispatcherFor(t, tools.NewRegistry(), inner, &recordingAuthorizer{decision: allow()})
	d.confinement = &confinement{constrained: true, mode: fixedMode("plan"), lookupPath: lookup, blocked: testBlocked(t)}

	if _, err := d.Dispatch(context.Background(), bashCall("c1", "ls | head")); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if len(inner.preflights)+len(inner.pipelines)+len(inner.execs) != 0 || len(inner.bounded) != 2 {
		t.Fatalf("preflights/pipelines/execs/bounded = %d/%d/%d/%d, want two sequential bounded stages",
			len(inner.preflights), len(inner.pipelines), len(inner.execs), len(inner.bounded))
	}
	wantHelperArgv(t, inner.bounded[0].Argv, filepath.Join(lookup, "ls"))
	wantHelperArgv(t, inner.bounded[1].Argv, filepath.Join(lookup, "head"))
	if _, rest := decodeFrame(t, inner.bounded[0].Stdin); len(rest) != 0 {
		t.Fatalf("first stage stdin after the frame = %q, want empty", rest)
	}
	if policy, rest := decodeFrame(t, inner.bounded[1].Stdin); string(rest) != "STAGE-OUT" || policy.Mode != "plan" {
		t.Fatalf("second stage policy %+v, stdin after the frame %q, want the prior stage's stdout", policy, rest)
	}
}

func TestConfinedShellRunner_PreparationRefusalEmitsNothing(t *testing.T) {
	store := mkStore(t)
	cwd := t.TempDir()
	inner := &confineInner{}
	r := &confinedShellRunner{
		events: &shellEventRunner{inner: inner, active: func() *sessions.Store { return store }, cap: 64},
		conf:   &confinement{constrained: true, mode: fixedMode("plan"), lookupPath: t.TempDir(), blocked: testBlocked(t)},
	}
	if _, err := r.Exec(context.Background(), confinedSpec(cwd, "ls")); err == nil {
		t.Fatal("Exec error = nil, want the program lookup refusal")
	}
	if err := r.PreflightPipeline(context.Background(), []cmdrunner.RunSpec{confinedSpec(cwd, "ls"), confinedSpec(cwd, "head")}); err == nil {
		t.Fatal("PreflightPipeline error = nil, want the confined pipeline refusal")
	}
	if inner.calls() != 0 || len(store.Records()) != 0 {
		t.Fatalf("inner calls = %d, records = %d, want nothing run and nothing recorded", inner.calls(), len(store.Records()))
	}
}

const unpinnedCall = "<unpinned>"

type pinSpyAuthorizer struct {
	*productionAuthorizer
	before func(context.Context) error
	after  func(context.Context)
	mu     sync.Mutex
	pins   []string
}

func (a *pinSpyAuthorizer) enter(ctx context.Context) error {
	pin, ok := vcs.ConfinementMode(ctx)
	if !ok {
		pin = unpinnedCall
	}
	a.mu.Lock()
	a.pins = append(a.pins, pin)
	a.mu.Unlock()
	if a.before != nil {
		return a.before(ctx)
	}
	return nil
}

func (a *pinSpyAuthorizer) leave(ctx context.Context) {
	if a.after != nil {
		a.after(ctx)
	}
}

func (a *pinSpyAuthorizer) recorded() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.pins)
}

func (a *pinSpyAuthorizer) Authorize(ctx context.Context, req permissions.MatchRequest, disp dispatch.PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error) {
	if err := a.enter(ctx); err != nil {
		return permissions.Decision{}, err
	}
	defer a.leave(ctx)
	return a.productionAuthorizer.Authorize(ctx, req, disp, modeCtx)
}

func (a *pinSpyAuthorizer) AuthorizeBatch(ctx context.Context, reqs []dispatch.BatchAuthRequest) ([]permissions.Decision, error) {
	if err := a.enter(ctx); err != nil {
		return nil, err
	}
	defer a.leave(ctx)
	return a.productionAuthorizer.AuthorizeBatch(ctx, reqs)
}

func (a *pinSpyAuthorizer) AuthorizeIndependent(ctx context.Context, reqs []dispatch.IndependentAuthRequest) ([]permissions.Decision, error) {
	if err := a.enter(ctx); err != nil {
		return nil, err
	}
	defer a.leave(ctx)
	return a.productionAuthorizer.AuthorizeIndependent(ctx, reqs)
}

func liveMode(active *mode.ActiveState) func() string {
	return func() string {
		m, _ := active.Current()
		return string(m)
	}
}

type pinShellHarness struct {
	d     *productionToolDispatcher
	spy   *pinSpyAuthorizer
	inner *confineInner
	shown *[]tui.PromptRequest
}

func newPinShellHarness(t *testing.T, active *mode.ActiveState, decide func(tui.PromptRequest) tui.PromptDecision, programs ...string) pinShellHarness {
	t.Helper()
	home := t.TempDir()
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	app := tui.New(nil)
	app.SetActiveStore(mkStore(t))
	shown := &[]tui.PromptRequest{}
	show := func(pr tui.PromptRequest) (tui.PromptDecision, error) {
		*shown = append(*shown, pr)
		if decide != nil {
			return decide(pr), nil
		}
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, emptyCache(t, cwd), permissions.NewTurnCache(), newPromptGateBuilder(show), home, cwd, active)
	auth.executionConstrained = true
	spy := &pinSpyAuthorizer{productionAuthorizer: auth}
	inner := &confineInner{}
	store := mkStore(t)
	d := newProductionToolDispatcher(tools.NewRegistry(), inner, spy, home, cwd, func() *sessions.Store { return store }, 65536, securitystate.Policy{})
	d.confinement = &confinement{constrained: true, mode: liveMode(active), lookupPath: programDir(t, programs...),
		blocked: testBlocked(t), projectRoot: cwd, tmpDir: t.TempDir()}
	return pinShellHarness{d: d, spy: spy, inner: inner, shown: shown}
}

func TestProductionDispatcher_ConfinedCommandKeepsItsModeAfterASwitchToBuild(t *testing.T) {
	for _, captured := range []mode.Mode{mode.Plan, mode.AutoEdits} {
		t.Run(string(captured), func(t *testing.T) {
			active := mode.NewActiveState(captured, mode.SourceUserCommand)
			h := newPinShellHarness(t, active, nil, "ls", "head")
			h.inner.onBounded = func(cmdrunner.RunSpec) { active.ApplyUserCommand(mode.Build) }

			if _, err := h.d.Dispatch(context.Background(), bashCall("c1", "ls ; head")); err != nil {
				t.Fatalf("Dispatch: %v", err)
			}
			if live, _ := active.Current(); live != mode.Build {
				t.Fatalf("live mode = %q, want the switch to Build to have happened mid-command", live)
			}
			if len(h.inner.bounded) != 2 || len(h.inner.execs) != 0 {
				t.Fatalf("bounded/exec = %d/%d, want both stages confined", len(h.inner.bounded), len(h.inner.execs))
			}
			wantHelperArgv(t, h.inner.bounded[1].Argv, filepath.Join(h.d.confinement.lookupPath, "head"))
			if policy, _ := decodeFrame(t, h.inner.bounded[1].Stdin); policy.Mode != string(captured) {
				t.Fatalf("second stage policy mode = %q, want the captured %q", policy.Mode, captured)
			}
			if pins := h.spy.recorded(); !slices.Equal(pins, []string{string(captured)}) {
				t.Fatalf("authorization pins = %v, want one authorization under %q", pins, captured)
			}
		})
	}
}

func TestProductionDispatcher_BuildCommandKeepsBuildAfterASwitchToPlan(t *testing.T) {
	active := mode.NewActiveState(mode.Build, mode.SourceUserCommand)
	h := newPinShellHarness(t, active, nil, "ls", "head")
	h.inner.onExec = func(cmdrunner.RunSpec) { active.ApplyUserCommand(mode.Plan) }

	if _, err := h.d.Dispatch(context.Background(), bashCall("c1", "ls ; head")); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if live, _ := active.Current(); live != mode.Plan {
		t.Fatalf("live mode = %q, want the switch to Plan to have happened mid-command", live)
	}
	if len(h.inner.execs) != 2 || len(h.inner.bounded) != 0 {
		t.Fatalf("bounded/exec = %d/%d, want both stages under Build's unconfined resolution", len(h.inner.bounded), len(h.inner.execs))
	}
	if filepath.Base(h.inner.execs[1].Argv[0]) != "head" {
		t.Fatalf("second stage argv = %q, want head run directly", h.inner.execs[1].Argv)
	}
	if pins := h.spy.recorded(); !slices.Equal(pins, []string{string(mode.Build)}) {
		t.Fatalf("authorization pins = %v, want one authorization under build", pins)
	}
}

func TestProductionDispatcher_SwitchWhileThePromptIsOpenKeepsTheCapturedMode(t *testing.T) {
	for _, exitCode := range []int{0, 1} {
		t.Run(map[int]string{0: "succeeds", 1: "fails confined"}[exitCode], func(t *testing.T) {
			active := mode.NewActiveState(mode.AutoEdits, mode.SourceUserCommand)
			h := newPinShellHarness(t, active, func(tui.PromptRequest) tui.PromptDecision {
				active.ApplyUserCommand(mode.Build)
				return tui.PromptDecision{Option: tui.OptionAllowOnce}
			}, "git")
			h.inner.exitCode = exitCode
			h.inner.stderr = []byte("git: denied\n")

			res, err := h.d.Dispatch(context.Background(), bashCall("c1", "git rebase main"))
			if err != nil {
				t.Fatalf("Dispatch: %v", err)
			}
			if len(*h.shown) != 1 || (*h.shown)[0].ExceptionalAuthority != "VCS history rewrite" {
				t.Fatalf("prompts = %+v, want the one exceptional Auto history-rewrite prompt and no reauthorization", *h.shown)
			}
			if live, _ := active.Current(); live != mode.Build {
				t.Fatalf("live mode = %q, want the switch made while the prompt was open", live)
			}
			if len(h.inner.bounded) != 1 || len(h.inner.execs) != 0 {
				t.Fatalf("bounded/exec = %d/%d, want one confined run and no unconfined retry", len(h.inner.bounded), len(h.inner.execs))
			}
			if policy, _ := decodeFrame(t, h.inner.bounded[0].Stdin); policy.Mode != string(mode.AutoEdits) {
				t.Fatalf("policy mode = %q, want the captured auto_edits", policy.Mode)
			}
			if pins := h.spy.recorded(); !slices.Equal(pins, []string{string(mode.AutoEdits)}) {
				t.Fatalf("authorization pins = %v, want one authorization under auto_edits", pins)
			}
			if noted := strings.Contains(res.Content, confinedFailureNote); noted != (exitCode != 0) {
				t.Fatalf("content = %q, want the confined-failure note only when the confined run failed", res.Content)
			}
		})
	}
}

func bashCallWithTimeout(id, command string, timeout any) turn.AssembledToolCall {
	raw, _ := json.Marshal(map[string]any{"command": command, "timeout": timeout})
	return turn.AssembledToolCall{ID: id, Name: "bash", Arguments: string(raw)}
}

func TestDecodeBashCommand_Timeout(t *testing.T) {
	for _, tc := range []struct {
		args string
		want time.Duration
	}{
		{`{"command":"ls"}`, 10 * time.Minute},
		{`{"command":"ls","timeout":1}`, time.Millisecond},
		{`{"command":"ls","timeout":250}`, 250 * time.Millisecond},
		{`{"command":"ls","timeout":1800000}`, 30 * time.Minute},
	} {
		command, got, err := decodeBashCommand(tc.args)
		if err != nil || command != "ls" || got != tc.want {
			t.Errorf("decodeBashCommand(%s) = %q, %v, %v; want ls, %v", tc.args, command, got, err, tc.want)
		}
	}
	for _, timeout := range []string{"0", "-1", "1.5", `"1000"`, "null", "1800001"} {
		t.Run(timeout, func(t *testing.T) {
			run := &fakeDispatchRunner{}
			auth := &recordingAuthorizer{decision: allow()}
			d := dispatcherFor(t, tools.NewRegistry(), run, auth)
			res, err := d.Dispatch(context.Background(), turn.AssembledToolCall{ID: "c1", Name: "bash", Arguments: `{"command":"ls","timeout":` + timeout + `}`})
			if err != nil || !strings.Contains(res.Content, `"timeout"`) {
				t.Fatalf("Dispatch = %q, %v; want an in-band timeout argument error", res.Content, err)
			}
			if auth.callCount() != 0 || run.callCount() != 0 {
				t.Fatalf("authorizer/runner calls = %d/%d, want 0/0", auth.callCount(), run.callCount())
			}
		})
	}
}

func timeoutScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func scriptPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
				t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
				return pid
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no pid written to %s", path)
	return 0
}

func waitProcessGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		if time.Now().After(deadline) {
			t.Fatalf("pid %d is still alive after the timed-out call returned", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func realRunnerDispatcher(t *testing.T) (*productionToolDispatcher, *sessions.Store) {
	t.Helper()
	store := mkStore(t)
	return newProductionToolDispatcher(tools.NewRegistry(), cmdrunner.DirectExecRunner{}, &recordingAuthorizer{decision: allow()}, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 65536, securitystate.Policy{}), store
}

func wantOneTimeoutNote(t *testing.T, content string, limit time.Duration) {
	t.Helper()
	note := bashTimeoutNote(limit)
	if strings.Count(content, "timed out after") != 1 || !strings.Contains(content, note+"\nexit status -1") {
		t.Fatalf("content = %q, want one %q note followed by exit status -1", content, note)
	}
}

func TestProductionDispatcher_BashTimeoutReturnsPartialOutputAndKillsTheChild(t *testing.T) {
	d, store := realRunnerDispatcher(t)
	pidFile := filepath.Join(t.TempDir(), "child")
	script := timeoutScript(t, "printf 'printed\\n'\nsleep 30 &\necho $! > \"$1\"\nsleep 30\n")
	began := time.Now()
	res, err := d.Dispatch(context.Background(), bashCallWithTimeout("c1", "sh "+script+" "+pidFile, 500))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want a timed-out tool result", err)
	}
	if elapsed := time.Since(began); elapsed > 5*time.Second {
		t.Fatalf("Dispatch took %v, want a return within a few seconds of the 500ms limit", elapsed)
	}
	if !strings.HasPrefix(res.Content, "printed\n") {
		t.Fatalf("content = %q, want the line printed before the timeout", res.Content)
	}
	wantOneTimeoutNote(t, res.Content, 500*time.Millisecond)
	waitProcessGone(t, scriptPID(t, pidFile))
	ends := decodeStoreEvents[events.ToolExecEnd](t, reloadStore(t, store), events.KindToolExecEnd)
	if len(ends) != 1 || ends[0].ExitCode != -1 {
		t.Fatalf("tool_exec_end = %+v, want one end with exit -1", ends)
	}
}

func TestProductionDispatcher_BashTimeoutSkipsLaterGroups(t *testing.T) {
	d, store := realRunnerDispatcher(t)
	res, err := d.Dispatch(context.Background(), bashCallWithTimeout("c1", "sleep 5 ; echo after", 300))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want a timed-out tool result", err)
	}
	if slices.Contains(strings.Split(res.Content, "\n"), "after") {
		t.Fatalf("content = %q, want the group after the timeout skipped", res.Content)
	}
	wantOneTimeoutNote(t, res.Content, 300*time.Millisecond)
	reloaded := reloadStore(t, store)
	starts := decodeStoreEvents[events.ToolExecStart](t, reloaded, events.KindToolExecStart)
	ends := decodeStoreEvents[events.ToolExecEnd](t, reloaded, events.KindToolExecEnd)
	if len(starts) != 1 || len(ends) != 1 || starts[0].Subject != "sleep 5" {
		t.Fatalf("tool_exec events = %+v / %+v, want one pair for sleep and none for the skipped echo", starts, ends)
	}
}

func TestProductionDispatcher_BashTimeoutKeepsPartialPipelineOutput(t *testing.T) {
	d, store := realRunnerDispatcher(t)
	script := timeoutScript(t, "#!/bin/sh\nprintf 'partial\\n'\nsleep 30\n")
	if err := os.Chmod(script, 0o700); err != nil {
		t.Fatal(err)
	}
	res, err := d.Dispatch(context.Background(), bashCallWithTimeout("c1", script+" | cat", 500))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want a timed-out tool result", err)
	}
	if !strings.HasPrefix(res.Content, "partial\n") {
		t.Fatalf("content = %q, want the partial pipeline output", res.Content)
	}
	wantOneTimeoutNote(t, res.Content, 500*time.Millisecond)
	reloaded := reloadStore(t, store)
	starts := decodeStoreEvents[events.ToolExecStart](t, reloaded, events.KindToolExecStart)
	ends := decodeStoreEvents[events.ToolExecEnd](t, reloaded, events.KindToolExecEnd)
	if len(starts) != 2 || len(ends) != 2 {
		t.Fatalf("tool_exec events = %d start/%d end, want one pair per stage", len(starts), len(ends))
	}
}

type deadlinePipelineRunner struct {
	fakeDispatchRunner
	copyErr error
}

func (f *deadlinePipelineRunner) PreflightPipeline(context.Context, []cmdrunner.RunSpec) error {
	return nil
}

func (f *deadlinePipelineRunner) Pipeline(ctx context.Context, specs []cmdrunner.RunSpec, _ int) ([]cmdrunner.PipelineResult, error) {
	<-ctx.Done()
	results := make([]cmdrunner.PipelineResult, len(specs))
	for i, spec := range specs {
		results[i] = cmdrunner.PipelineResult{InvocationID: spec.InvocationID, ExitCode: -1, PipelineErrCategory: cmdrunner.PipelineFailureCanceled}
	}
	err := fmt.Errorf("runner: pipeline canceled: %w", ctx.Err())
	if f.copyErr != nil {
		results[0].PipelineErrCategory = cmdrunner.PipelineFailureCopy
		err = errors.Join(err, f.copyErr)
	}
	return results, err
}

func TestProductionDispatcher_BashTimeoutNeverHidesAPipelineFailure(t *testing.T) {
	prependFixturePrograms(t, "alpha", "beta")
	copyErr := errors.New("stage 0 stdout capture: broken")
	for _, tc := range []struct {
		name    string
		copyErr error
	}{{"cancellation only", nil}, {"copier failure", copyErr}} {
		t.Run(tc.name, func(t *testing.T) {
			store := mkStore(t)
			inner := &deadlinePipelineRunner{copyErr: tc.copyErr}
			d := newProductionToolDispatcher(tools.NewRegistry(), inner, &recordingAuthorizer{decision: allow()}, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 65536, securitystate.Policy{})
			res, err := d.Dispatch(context.Background(), bashCallWithTimeout("c1", "alpha | beta", 100))
			if tc.copyErr != nil {
				if !errors.Is(err, copyErr) {
					t.Fatalf("Dispatch error = %v, want the copier failure", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Dispatch error = %v, want the deadline converted to a tool result", err)
			}
			wantOneTimeoutNote(t, res.Content, 100*time.Millisecond)
			if ends := decodeStoreEvents[events.ToolExecEnd](t, reloadStore(t, store), events.KindToolExecEnd); len(ends) != 2 {
				t.Fatalf("tool_exec_end events = %d, want one per stage", len(ends))
			}
		})
	}
}

func TestProductionDispatcher_ConfinedTimeoutKeepsBothNotesWithinTheCap(t *testing.T) {
	const cap = 512
	limit := 100 * time.Millisecond
	for _, size := range []int{cap, 4 * cap} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			inner := &confineInner{exitCode: -1, stderr: bytes.Repeat([]byte("e"), size), onBounded: func(cmdrunner.RunSpec) { time.Sleep(limit + 100*time.Millisecond) }}
			d := dispatcherFor(t, tools.NewRegistry(), inner, &recordingAuthorizer{decision: allow()})
			d.outputCap = cap
			d.confinement = &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls"), blocked: testBlocked(t)}

			res, err := d.Dispatch(context.Background(), bashCallWithTimeout("c1", "ls", int(limit.Milliseconds())))
			if err != nil {
				t.Fatalf("Dispatch: %v", err)
			}
			stderr, ok := strings.CutSuffix(res.Content, "\nexit status -1")
			if !ok || len(stderr) > cap {
				t.Fatalf("content = %q (%d stderr bytes), want stderr within the %d-byte cap then exit status -1", res.Content, len(stderr), cap)
			}
			if !strings.HasSuffix(stderr, confinedFailureNote+"\n"+bashTimeoutNote(limit)) ||
				strings.Count(stderr, confinedFailureNote) != 1 || strings.Count(stderr, "timed out after") != 1 {
				t.Fatalf("stderr = %q, want the confinement note once, then the timeout note once", stderr)
			}
		})
	}
}

func TestProductionDispatcher_IncomingCancellationIsNotATimeout(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skipf("setsid not available: %v", err)
	}
	script := timeoutScript(t, "printf 'started\\n'\nsetsid sh -c 'echo $$ > \"$1\"; exec sleep 30' sh \"$1\" &\nsleep 30\n")
	for _, tc := range []struct {
		name        string
		ctx         func(t *testing.T) context.Context
		stop        func(ctl *turnController)
		wantSurface string
	}{
		{"user cancel", func(*testing.T) context.Context { return context.Background() }, func(ctl *turnController) { ctl.Cancel() }, "interrupted"},
		{"turn deadline", func(t *testing.T) context.Context {
			ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
			t.Cleanup(cancel)
			return ctx
		}, func(*turnController) {}, "turn_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var turns sync.WaitGroup
			defer swapGoTurn(waitableGoTurn(&turns))()
			pidFile := filepath.Join(t.TempDir(), "escaped")
			args, _ := json.Marshal(map[string]string{"command": "sh " + script + " " + pidFile})
			var round int32
			client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
				if atomic.AddInt32(&round, 1) == 1 {
					return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", string(args))))}, nil
				}
				return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			d, store := realRunnerDispatcher(t)
			rec := &resultRecordingDispatcher{ToolDispatcher: d}
			surface := &recordingSurface{}
			ctl := newTurnController(tc.ctx(t), surface, providerCache(t, t.TempDir()),
				turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
			ctl.setToolDispatcher(rec)
			if err := ctl.dispatch(store, time.Time{}); err != nil {
				t.Fatalf("dispatch error = %v", err)
			}
			scriptPID(t, pidFile)
			tc.stop(ctl)
			drained := make(chan struct{})
			go func() { turns.Wait(); close(drained) }()
			select {
			case <-drained:
			case <-time.After(10 * time.Second):
				t.Fatal("the turn did not end after the incoming context ended")
			}

			if len(rec.results) != 1 || rec.errs[0] != nil || rec.results[0].Content != "started\nexit status -1" {
				t.Fatalf("bash call returned %+v / %v, want only the killed command's own output and exit status -1", rec.results, rec.errs)
			}
			if got := surface.outcomeList(); !slices.Equal(got, []string{tc.wantSurface}) {
				t.Fatalf("TurnEnded outcomes = %v, want [%s]", got, tc.wantSurface)
			}
			reloaded := reloadStore(t, store)
			terminals := decodeStoreEvents[events.TurnTerminal](t, reloaded, events.KindTurnTerminal)
			if len(terminals) != 1 || terminals[0].Outcome != events.TurnOutcomeCancelled || !terminals[0].DispatchStarted {
				t.Fatalf("turn_terminal events = %+v, want one cancelled outcome after dispatch started", terminals)
			}
			if msgs := messagesByRole(reloaded, "tool"); len(msgs) != 0 {
				t.Fatalf("tool result messages = %+v, want none: the cancellation must not become a tool result", msgs)
			}
			if client.callCount() != 1 {
				t.Fatalf("provider calls = %d, want 1 (no round after the cancellation)", client.callCount())
			}
		})
	}
}

type resultRecordingDispatcher struct {
	turn.ToolDispatcher
	results []turn.ToolResult
	errs    []error
}

func (d *resultRecordingDispatcher) Plan(calls []turn.AssembledToolCall, n int) turn.ToolPlan {
	plan := d.ToolDispatcher.Plan(calls, n)
	for i := range plan.Units {
		run := plan.Units[i].Run
		plan.Units[i].Run = func(ctx context.Context) (turn.ToolResult, error) {
			res, err := run(ctx)
			d.results, d.errs = append(d.results, res), append(d.errs, err)
			return res, err
		}
	}
	return plan
}

type slowAuthorizer struct{ delay time.Duration }

func (a slowAuthorizer) Authorize(context.Context, permissions.MatchRequest, dispatch.PromptDisplay, permissions.ModeContext) (permissions.Decision, error) {
	time.Sleep(a.delay)
	return allow(), nil
}

type ctxPipelineRunner struct {
	fakePipelineDispatchRunner
	ctxErrs []error
}

func (f *ctxPipelineRunner) PreflightPipeline(ctx context.Context, specs []cmdrunner.RunSpec) error {
	f.ctxErrs = append(f.ctxErrs, ctx.Err())
	return f.fakePipelineDispatchRunner.PreflightPipeline(ctx, specs)
}

func (f *ctxPipelineRunner) Pipeline(ctx context.Context, specs []cmdrunner.RunSpec, maxCapture int) ([]cmdrunner.PipelineResult, error) {
	f.ctxErrs = append(f.ctxErrs, ctx.Err())
	return f.fakePipelineDispatchRunner.Pipeline(ctx, specs, maxCapture)
}

type sleepyRunner struct {
	fakeDispatchRunner
	delay time.Duration
}

func (r *sleepyRunner) Exec(ctx context.Context, spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
	atomic.AddInt32(&r.calls, 1)
	select {
	case <-time.After(r.delay):
		return cmdrunner.RunResult{InvocationID: spec.InvocationID, Stdout: []byte("ran\n")}, nil
	case <-ctx.Done():
		return cmdrunner.RunResult{InvocationID: spec.InvocationID, ExitCode: -1}, nil
	}
}

func TestProductionDispatcher_BashTimeoutStartsAfterAuthorizationAndIsShared(t *testing.T) {
	t.Run("builtin only", func(t *testing.T) {
		store := mkStore(t)
		d := newProductionToolDispatcher(tools.NewRegistry(), &fakeDispatchRunner{}, slowAuthorizer{300 * time.Millisecond}, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 65536, securitystate.Policy{})
		res, err := d.Dispatch(context.Background(), bashCallWithTimeout("c1", "command -v sh", 50))
		if err != nil || strings.Contains(res.Content, "timed out") || !strings.HasSuffix(res.Content, "/sh") {
			t.Fatalf("Dispatch = %q, %v; want the lookup answered with the limit unspent by authorization", res.Content, err)
		}
	})
	t.Run("first pipeline preflight", func(t *testing.T) {
		prependFixturePrograms(t, "alpha", "beta")
		store := mkStore(t)
		inner := &ctxPipelineRunner{fakePipelineDispatchRunner: fakePipelineDispatchRunner{results: []cmdrunner.PipelineResult{{}, {Stdout: []byte("piped")}}}}
		d := newProductionToolDispatcher(tools.NewRegistry(), inner, slowAuthorizer{300 * time.Millisecond}, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 65536, securitystate.Policy{})
		res, err := d.Dispatch(context.Background(), bashCallWithTimeout("c1", "alpha | beta", 100))
		if err != nil || res.Content != "piped" {
			t.Fatalf("Dispatch = %q, %v; want the pipeline result with no timeout", res.Content, err)
		}
		if !slices.Equal(inner.ctxErrs, []error{nil, nil}) {
			t.Fatalf("preflight/pipeline context errors = %v, want a live budget at both", inner.ctxErrs)
		}
	})
	t.Run("shared across stages", func(t *testing.T) {
		prependFixturePrograms(t, "alpha", "beta")
		store := mkStore(t)
		run := &sleepyRunner{delay: 300 * time.Millisecond}
		d := newProductionToolDispatcher(tools.NewRegistry(), run, &recordingAuthorizer{decision: allow()}, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 65536, securitystate.Policy{})
		res, err := d.Dispatch(context.Background(), bashCallWithTimeout("c1", "alpha ; beta", 450))
		if err != nil {
			t.Fatalf("Dispatch: %v", err)
		}
		if strings.Count(res.Content, "ran") != 1 {
			t.Fatalf("content = %q, want only the first stage finished within the shared limit", res.Content)
		}
		wantOneTimeoutNote(t, res.Content, 450*time.Millisecond)
	})
}
