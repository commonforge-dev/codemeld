// Unit tests for VCS action invocation: clean run, placeholder substitution,
// binary-not-found and cwd-escape launch failures, paired tool_exec_* events, and
// the ResolveActionCWD containment/symlink rule.
package vcs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
	cmdrunner "codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/sessions"
)

// fakeRunner is a runner.Runner stub: it mints a fixed invocation id, records the
// spec it was handed, and returns a preset RunResult so the VCS-layer logic can be
// exercised without launching real processes.
type fakeRunner struct {
	id        string
	result    cmdrunner.RunResult
	err       error
	gotSpec   cmdrunner.RunSpec
	execCalls int
}

func (f *fakeRunner) NewInvocationID() string { return f.id }

func (f *fakeRunner) Exec(_ context.Context, spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
	f.execCalls++
	f.gotSpec = spec
	res := f.result
	if res.InvocationID == "" {
		res.InvocationID = spec.InvocationID
	}
	return res, f.err
}

// capture is an EventAppender that both records the typed payloads (for field
// assertions) and runs them through the real events.Append, so an invalid payload
// shape surfaces as an append error rather than passing silently.
type capture struct {
	store    *sessions.Store
	sess     *sessions.Session
	payloads []events.EventPayload
}

func (c *capture) appendEvent(p events.EventPayload) error {
	c.payloads = append(c.payloads, p)
	_, err := events.Append(c.store, p)
	return err
}

func newCapture() *capture {
	sess := &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            ids.NewV7(),
			Folder:        "/tmp",
			StartedAt:     time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC),
			UpdatedAt:     time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC),
			SchemaVersion: 1,
		},
	}
	return &capture{store: sessions.New("unused-in-tests", sess), sess: sess}
}

// persistedEnd marshals the capture's session through the production codec,
// reloads it, validates every record through the load-time validator, and returns
// the single persisted tool_exec_end decoded from durable bytes. It reads the
// record back from the serialized store (not the in-memory payload) so over-cap
// truncation is asserted on what was actually written.
func (c *capture) persistedEnd(t *testing.T) events.ToolExecEnd {
	t.Helper()
	data, err := sessions.Marshal(c.sess)
	if err != nil {
		t.Fatalf("sessions.Marshal: %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("sessions.Unmarshal: %v", err)
	}
	var ends []events.ToolExecEnd
	for i, r := range loaded.Records {
		ev, ok := r.(sessions.Event)
		if !ok {
			t.Fatalf("reloaded record %d is %T, want sessions.Event", i, r)
		}
		if err := events.ValidatePayload(ev.Kind, ev.Payload); err != nil {
			t.Fatalf("ValidatePayload rejected persisted record %d: %v", i, err)
		}
		if ev.Kind != events.KindToolExecEnd {
			continue
		}
		var end events.ToolExecEnd
		if err := json.Unmarshal(ev.Payload, &end); err != nil {
			t.Fatalf("unmarshal persisted tool_exec_end: %v", err)
		}
		ends = append(ends, end)
	}
	if len(ends) != 1 {
		t.Fatalf("persisted %d tool_exec_end records, want exactly 1", len(ends))
	}
	return ends[0]
}

// evalSym resolves symlinks and cleans path the same way ResolveActionCWD does, so
// expectations match what the resolver produces on this OS (e.g. macOS /var ->
// /private/var).
func evalSym(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", path, err)
	}
	return filepath.Clean(resolved)
}

func startEnd(t *testing.T, c *capture) (events.ToolExecStart, events.ToolExecEnd) {
	t.Helper()
	if len(c.payloads) != 2 {
		t.Fatalf("emitted %d events, want 2 (start+end)", len(c.payloads))
	}
	start, ok := c.payloads[0].(events.ToolExecStart)
	if !ok {
		t.Fatalf("first event is %T, want events.ToolExecStart", c.payloads[0])
	}
	end, ok := c.payloads[1].(events.ToolExecEnd)
	if !ok {
		t.Fatalf("second event is %T, want events.ToolExecEnd", c.payloads[1])
	}
	return start, end
}

func TestInvoke_CleanInvocationEmitsPairedEvents(t *testing.T) {
	repo := t.TempDir()
	id := ids.NewV7()
	fr := &fakeRunner{id: id, result: cmdrunner.RunResult{ExitCode: 0, Stdout: []byte("hello\n"), Duration: 5 * time.Millisecond}}
	c := newCapture()
	action := &ActionSpec{Argv: []string{"mybin", "status"}}

	res, err := Invoke(context.Background(), "status", action, nil, repo, fr, c.appendEvent, 64)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if res.ExitCode != 0 || string(res.Stdout) != "hello\n" {
		t.Fatalf("result = %+v, want exit 0 stdout %q", res, "hello\n")
	}

	wantCwd := evalSym(t, repo)
	if got := fr.gotSpec.Argv; len(got) != 2 || got[0] != "mybin" || got[1] != "status" {
		t.Errorf("runner argv = %v, want [mybin status]", got)
	}
	if fr.gotSpec.Cwd != wantCwd {
		t.Errorf("runner cwd = %q, want %q", fr.gotSpec.Cwd, wantCwd)
	}
	if fr.gotSpec.InvocationID != id {
		t.Errorf("runner invocation id = %q, want %q", fr.gotSpec.InvocationID, id)
	}

	start, end := startEnd(t, c)
	if start.SubjectKind != "tool" || start.Subject != "vcs_status" || start.PathScope != wantCwd || start.InvocationID != id {
		t.Errorf("tool_exec_start = %+v, want subject vcs_status path %q id %q", start, wantCwd, id)
	}
	if end.Subject != "vcs_status" || end.ExitCode != 0 || end.Stdout != "hello\n" || end.InvocationID != id {
		t.Errorf("tool_exec_end = %+v, want exit 0 stdout hello id %q", end, id)
	}
	if start.InvocationID != end.InvocationID {
		t.Errorf("invocation ids unpaired: start %q end %q", start.InvocationID, end.InvocationID)
	}
}

func TestInvoke_PlaceholderSubstitution(t *testing.T) {
	repo := t.TempDir()
	fr := &fakeRunner{id: ids.NewV7(), result: cmdrunner.RunResult{ExitCode: 0}}
	c := newCapture()
	action := &ActionSpec{Argv: []string{"git", "add", "{path}"}}

	if _, err := Invoke(context.Background(), "add", action, map[string]string{"path": "src/x.go"}, repo, fr, c.appendEvent, 64); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	want := []string{"git", "add", "src/x.go"}
	if got := fr.gotSpec.Argv; len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("substituted argv = %v, want %v", got, want)
	}
}

func TestInvoke_PlaceholderRejectsUnexpectedParam(t *testing.T) {
	repo := t.TempDir()
	fr := &fakeRunner{id: ids.NewV7()}
	c := newCapture()
	action := &ActionSpec{Argv: []string{"git", "status"}}

	if _, err := Invoke(context.Background(), "status", action, map[string]string{"path": "x"}, repo, fr, c.appendEvent, 64); err == nil {
		t.Fatalf("Invoke accepted an unexpected parameter for a placeholderless action")
	}
	if fr.execCalls != 0 {
		t.Errorf("runner ran %d times on a rejected invocation, want 0", fr.execCalls)
	}
}

func TestInvoke_BinaryNotFoundLaunchFailure(t *testing.T) {
	repo := t.TempDir()
	id := ids.NewV7()
	fr := &fakeRunner{id: id, result: cmdrunner.RunResult{ExitCode: -1, LaunchErrCategory: fserrors.NotFound, Duration: 2 * time.Millisecond}}
	c := newCapture()
	action := &ActionSpec{Argv: []string{"nope-binary", "log"}}

	res, err := Invoke(context.Background(), "log", action, nil, repo, fr, c.appendEvent, 64)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	wantStderr := "codemeld: vcs_log: launch failed: nope-binary: not_found"
	if res.ExitCode != -1 || len(res.Stdout) != 0 || string(res.Stderr) != wantStderr {
		t.Fatalf("result = {exit %d stdout %q stderr %q}, want {exit -1 stdout \"\" stderr %q}", res.ExitCode, res.Stdout, res.Stderr, wantStderr)
	}
	start, end := startEnd(t, c)
	if end.ExitCode != -1 || end.Stderr != wantStderr {
		t.Errorf("tool_exec_end = %+v, want exit -1 stderr %q", end, wantStderr)
	}
	if start.InvocationID != end.InvocationID || start.InvocationID != id {
		t.Errorf("invocation ids: start %q end %q, want both %q", start.InvocationID, end.InvocationID, id)
	}
}

func TestInvoke_CwdEscapeLaunchFailure(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir() // a sibling temp dir, not under repo
	id := ids.NewV7()
	fr := &fakeRunner{id: id, result: cmdrunner.RunResult{ExitCode: 0, Stdout: []byte("should not run")}}
	c := newCapture()
	action := &ActionSpec{Argv: []string{"git", "status"}, Cwd: outside}

	// A generous cap so the synthesized stderr (which embeds a long temp path)
	// surfaces whole in the event; truncation of this path is covered separately
	// by TestInvoke_LaunchFailureTruncatesSynthesizedStderr.
	res, err := Invoke(context.Background(), "status", action, nil, repo, fr, c.appendEvent, 4096)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	wantResolved := evalSym(t, outside)
	wantStderr := "codemeld: vcs_status: cwd escapes repo root: " + wantResolved
	if res.ExitCode != -1 || len(res.Stdout) != 0 || string(res.Stderr) != wantStderr {
		t.Fatalf("result = {exit %d stdout %q stderr %q}, want {exit -1 stdout \"\" stderr %q}", res.ExitCode, res.Stdout, res.Stderr, wantStderr)
	}
	if fr.execCalls != 0 {
		t.Errorf("runner ran %d times on a cwd escape, want 0 (process must never start)", fr.execCalls)
	}
	start, end := startEnd(t, c)
	if start.PathScope != wantResolved {
		t.Errorf("tool_exec_start path_scope = %q, want the attempted (escaping) cwd %q", start.PathScope, wantResolved)
	}
	if start.InvocationID != end.InvocationID || start.InvocationID != id {
		t.Errorf("invocation ids: start %q end %q, want both %q", start.InvocationID, end.InvocationID, id)
	}
	if end.Stderr != wantStderr {
		t.Errorf("tool_exec_end stderr = %q, want %q", end.Stderr, wantStderr)
	}
}

func TestInvoke_RepoRootDisappearanceLaunchFailure(t *testing.T) {
	repo := t.TempDir()
	id := ids.NewV7()
	fr := &fakeRunner{id: id, result: cmdrunner.RunResult{ExitCode: 0, Stdout: []byte("should not run")}}
	c := newCapture()
	action := &ActionSpec{Argv: []string{"mybin", "status"}}

	// Bind the inputs, then remove the active repo root before invoking: the VCS
	// action "active repo root binding" rule requires this to surface as a per-action launch
	// failure with paired events, not a bare Go error.
	if err := os.RemoveAll(repo); err != nil {
		t.Fatalf("remove repo root: %v", err)
	}

	res, err := Invoke(context.Background(), "status", action, nil, repo, fr, c.appendEvent, 64)
	if err != nil {
		t.Fatalf("Invoke returned a Go error for a removed repo root, want a launch-failure result: %v", err)
	}
	wantStderr := "codemeld: vcs_status: launch failed: mybin: not_found"
	if res.ExitCode != -1 || len(res.Stdout) != 0 || string(res.Stderr) != wantStderr {
		t.Fatalf("result = {exit %d stdout %q stderr %q}, want {exit -1 stdout \"\" stderr %q}", res.ExitCode, res.Stdout, res.Stderr, wantStderr)
	}
	if fr.execCalls != 0 {
		t.Errorf("runner ran %d times with the repo root gone, want 0 (process must never start)", fr.execCalls)
	}
	start, end := startEnd(t, c)
	if start.PathScope != filepath.Clean(repo) {
		t.Errorf("tool_exec_start path_scope = %q, want the would-be effective cwd %q", start.PathScope, filepath.Clean(repo))
	}
	if end.Stderr != wantStderr || end.ExitCode != -1 {
		t.Errorf("tool_exec_end = %+v, want exit -1 stderr %q", end, wantStderr)
	}
	if start.InvocationID != end.InvocationID || start.InvocationID != id {
		t.Errorf("invocation ids: start %q end %q, want both %q", start.InvocationID, end.InvocationID, id)
	}
}

func TestResolveActionCWD(t *testing.T) {
	repo := t.TempDir()
	sub := filepath.Join(repo, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	wantRepo := evalSym(t, repo)
	wantSub := evalSym(t, sub)

	t.Run("omitted uses repo root", func(t *testing.T) {
		got, err := ResolveActionCWD(&ActionSpec{}, repo)
		if err != nil || got != wantRepo {
			t.Fatalf("got (%q, %v), want (%q, nil)", got, err, wantRepo)
		}
	})
	t.Run("relative joins repo root", func(t *testing.T) {
		got, err := ResolveActionCWD(&ActionSpec{Cwd: "sub"}, repo)
		if err != nil || got != wantSub {
			t.Fatalf("got (%q, %v), want (%q, nil)", got, err, wantSub)
		}
	})
	t.Run("absolute inside used as-is", func(t *testing.T) {
		got, err := ResolveActionCWD(&ActionSpec{Cwd: sub}, repo)
		if err != nil || got != wantSub {
			t.Fatalf("got (%q, %v), want (%q, nil)", got, err, wantSub)
		}
	})
	t.Run("symlink inside repo to inside dir is contained", func(t *testing.T) {
		link := filepath.Join(repo, "link")
		if err := os.Symlink(sub, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		got, err := ResolveActionCWD(&ActionSpec{Cwd: "link"}, repo)
		if err != nil || got != wantSub {
			t.Fatalf("got (%q, %v), want (%q, nil)", got, err, wantSub)
		}
	})
	t.Run("absolute outside escapes", func(t *testing.T) {
		outside := t.TempDir()
		_, err := ResolveActionCWD(&ActionSpec{Cwd: outside}, repo)
		var esc *CWDEscapeError
		if !errors.As(err, &esc) {
			t.Fatalf("err = %v, want *CWDEscapeError", err)
		}
		if esc.ResolvedCwd != evalSym(t, outside) {
			t.Errorf("ResolvedCwd = %q, want %q", esc.ResolvedCwd, evalSym(t, outside))
		}
	})
	t.Run("symlink inside repo pointing outside escapes", func(t *testing.T) {
		outside := t.TempDir()
		bad := filepath.Join(repo, "bad")
		if err := os.Symlink(outside, bad); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		_, err := ResolveActionCWD(&ActionSpec{Cwd: "bad"}, repo)
		var esc *CWDEscapeError
		if !errors.As(err, &esc) {
			t.Fatalf("err = %v, want *CWDEscapeError (symlink alias must not bypass containment)", err)
		}
		if esc.ResolvedCwd != evalSym(t, outside) {
			t.Errorf("ResolvedCwd = %q, want %q", esc.ResolvedCwd, evalSym(t, outside))
		}
	})
}

// TestInvoke_OverCapTruncatesPersistedEnd asserts an over-cap VCS run persists a
// tool_exec_end with cap-truncated stdout/stderr, truncated:true, and the correct
// pre-truncation original_bytes — read back from the serialized store, not the
// in-memory payload. The returned tools.Result keeps the raw
// streams: only the event payload is capped.
func TestInvoke_OverCapTruncatesPersistedEnd(t *testing.T) {
	repo := t.TempDir()
	id := ids.NewV7()
	rawOut := bytes.Repeat([]byte("a"), 20)
	rawErr := bytes.Repeat([]byte("b"), 30)
	fr := &fakeRunner{id: id, result: cmdrunner.RunResult{ExitCode: 0, Stdout: rawOut, Stderr: rawErr, Duration: 3 * time.Millisecond}}
	c := newCapture()
	action := &ActionSpec{Argv: []string{"mybin", "status"}}

	const cap = 4
	res, err := Invoke(context.Background(), "status", action, nil, repo, fr, c.appendEvent, cap)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	// The raw result streams are untouched — truncation applies only to the event.
	if !bytes.Equal(res.Stdout, rawOut) || !bytes.Equal(res.Stderr, rawErr) {
		t.Fatalf("result streams were modified: stdout %q stderr %q, want raw", res.Stdout, res.Stderr)
	}

	end := c.persistedEnd(t)
	if end.Stdout != "aaaa" || end.Stderr != "bbbb" {
		t.Errorf("persisted end stdout/stderr = %q/%q, want aaaa/bbbb", end.Stdout, end.Stderr)
	}
	if !end.Truncated {
		t.Error("persisted end truncated = false, want true")
	}
	if end.OriginalBytes == nil {
		t.Fatal("persisted end original_bytes is nil, want set")
	}
	if end.OriginalBytes.Stdout != 20 || end.OriginalBytes.Stderr != 30 {
		t.Errorf("original_bytes = %+v, want {20 30}", *end.OriginalBytes)
	}

	// Parity: the persisted bytes equal what BuildModelInputBytes would
	// feed the model for the same raw input and cap.
	wantOut, wantErr := events.BuildModelInputBytes(rawOut, rawErr, cap)
	if !bytes.Equal([]byte(end.Stdout), wantOut) || !bytes.Equal([]byte(end.Stderr), wantErr) {
		t.Errorf("persisted (%q/%q) != BuildModelInputBytes (%q/%q)", end.Stdout, end.Stderr, wantOut, wantErr)
	}
}

// TestInvoke_UnderCapPersistsUntruncated asserts an under-cap run persists the
// full streams with truncated:false and no original_bytes.
func TestInvoke_UnderCapPersistsUntruncated(t *testing.T) {
	repo := t.TempDir()
	fr := &fakeRunner{id: ids.NewV7(), result: cmdrunner.RunResult{ExitCode: 0, Stdout: []byte("hello"), Stderr: []byte("warn")}}
	c := newCapture()
	action := &ActionSpec{Argv: []string{"mybin", "status"}}

	if _, err := Invoke(context.Background(), "status", action, nil, repo, fr, c.appendEvent, 64); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	end := c.persistedEnd(t)
	if end.Stdout != "hello" || end.Stderr != "warn" {
		t.Errorf("persisted stdout/stderr = %q/%q, want hello/warn", end.Stdout, end.Stderr)
	}
	if end.Truncated {
		t.Error("truncated = true, want false for under-cap output")
	}
	if end.OriginalBytes != nil {
		t.Errorf("original_bytes = %+v, want nil when not truncated", *end.OriginalBytes)
	}
}

// TestInvoke_ZeroCapDropsAllOutput asserts a cap of 0 drops every non-empty
// stream and reports truncation with the raw byte counts.
func TestInvoke_ZeroCapDropsAllOutput(t *testing.T) {
	repo := t.TempDir()
	fr := &fakeRunner{id: ids.NewV7(), result: cmdrunner.RunResult{ExitCode: 0, Stdout: []byte("x"), Stderr: []byte("yy")}}
	c := newCapture()
	action := &ActionSpec{Argv: []string{"mybin", "status"}}

	if _, err := Invoke(context.Background(), "status", action, nil, repo, fr, c.appendEvent, 0); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	end := c.persistedEnd(t)
	if end.Stdout != "" || end.Stderr != "" {
		t.Errorf("persisted stdout/stderr = %q/%q, want both empty", end.Stdout, end.Stderr)
	}
	if !end.Truncated || end.OriginalBytes == nil {
		t.Fatalf("truncated/original_bytes = %v/%v, want true/non-nil", end.Truncated, end.OriginalBytes)
	}
	if end.OriginalBytes.Stdout != 1 || end.OriginalBytes.Stderr != 2 {
		t.Errorf("original_bytes = %+v, want {1 2}", *end.OriginalBytes)
	}
}

// TestInvoke_LaunchFailureTruncatesSynthesizedStderr asserts the launch-failure
// path (emitPaired) caps its synthesized stderr through the same helper and cap
// as a normal completed run. The cwd-escape branch builds a long stderr
// from the escaping path, which a small cap must shorten in the persisted event.
func TestInvoke_LaunchFailureTruncatesSynthesizedStderr(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir()
	fr := &fakeRunner{id: ids.NewV7(), result: cmdrunner.RunResult{ExitCode: 0}}
	c := newCapture()
	action := &ActionSpec{Argv: []string{"git", "status"}, Cwd: outside}

	const cap = 10
	res, err := Invoke(context.Background(), "status", action, nil, repo, fr, c.appendEvent, cap)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	// The returned result keeps the full synthesized stderr; only the event is capped.
	fullStderr := "codemeld: vcs_status: cwd escapes repo root: " + evalSym(t, outside)
	if string(res.Stderr) != fullStderr {
		t.Fatalf("result stderr = %q, want full %q (result must stay raw)", res.Stderr, fullStderr)
	}
	end := c.persistedEnd(t)
	wantErr, _ := events.BuildModelInputBytes([]byte(fullStderr), nil, cap)
	if end.Stderr != string(wantErr) {
		t.Errorf("persisted stderr = %q, want cap-truncated %q", end.Stderr, wantErr)
	}
	if !end.Truncated {
		t.Error("truncated = false, want true for over-cap synthesized stderr")
	}
	if end.OriginalBytes == nil || end.OriginalBytes.Stderr != int64(len(fullStderr)) {
		t.Errorf("original_bytes = %+v, want stderr %d", end.OriginalBytes, len(fullStderr))
	}
}

func TestInvoke_BoundedResultRecordsTotals(t *testing.T) {
	cases := []struct {
		name   string
		stdout []byte
		stderr []byte
		cap    int
	}{
		{"valid", []byte("abcdef"), []byte("warn"), 4},
		{"rune boundary", []byte("héllo"), []byte("x"), 2},
		{"invalid utf-8", []byte{0x61, 0x62, 0xff, 0x63}, []byte{0xff, 0xff}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fr := &fakeRunner{id: ids.NewV7(), result: cmdrunner.RunResult{
				ExitCode:    0,
				Stdout:      tc.stdout,
				Stderr:      tc.stderr,
				StdoutTotal: 1000,
				StderrTotal: 2000,
				Duration:    3 * time.Millisecond,
			}}
			c := newCapture()
			action := &ActionSpec{Argv: []string{"mybin", "status"}}

			if _, err := Invoke(context.Background(), "status", action, nil, t.TempDir(), fr, c.appendEvent, tc.cap); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			end := c.persistedEnd(t)
			if !end.Truncated || end.OriginalBytes == nil || *end.OriginalBytes != (events.OriginalBytes{Stdout: 1000, Stderr: 2000}) {
				t.Fatalf("end truncated=%v original=%+v, want true with the runner totals", end.Truncated, end.OriginalBytes)
			}
			wantOut, wantErr := events.BuildModelInputBytes(tc.stdout, tc.stderr, tc.cap)
			if end.Stdout != string(wantOut) || end.Stderr != string(wantErr) {
				t.Fatalf("persisted %q/%q, want BuildModelInputBytes %q/%q", end.Stdout, end.Stderr, wantOut, wantErr)
			}
		})
	}
}

func TestInvoke_RunnerErrorPairsSynthesizedEnd(t *testing.T) {
	boom := errors.New("capture failed")
	emitErr := errors.New("append failed")
	for _, endFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "end recorded", true: "end emission fails"}[endFails], func(t *testing.T) {
			id := ids.NewV7()
			fr := &fakeRunner{id: id, err: boom, result: cmdrunner.RunResult{Stdout: []byte("partial"), StdoutTotal: 7}}
			c := newCapture()
			emit := func(p events.EventPayload) error {
				if endFails && len(c.payloads) == 1 {
					return emitErr
				}
				return c.appendEvent(p)
			}
			childID := ids.NewV7()
			ctx := WithChildInvocationID(context.Background(), childID)
			action := &ActionSpec{Argv: []string{"mybin", "status"}}

			_, err := Invoke(ctx, "status", action, nil, t.TempDir(), fr, emit, 64)
			if !errors.Is(err, boom) {
				t.Fatalf("Invoke error = %v, want the runner error %v", err, boom)
			}
			if endFails {
				if !errors.Is(err, emitErr) || len(c.payloads) != 1 {
					t.Fatalf("err = %v, payloads = %d, want the emission failure joined and only the start recorded", err, len(c.payloads))
				}
				return
			}
			_, end := startEnd(t, c)
			want := events.ToolExecEnd{
				SubjectKind:       "tool",
				Subject:           "vcs_status",
				ExitCode:          -1,
				InvocationID:      id,
				ChildInvocationID: childID,
			}
			if end.OriginalBytes != nil || end != want {
				t.Fatalf("end = %+v, want synthesized %+v", end, want)
			}
			if persisted := c.persistedEnd(t); persisted.OriginalBytes != nil || persisted != want {
				t.Fatalf("persisted end = %+v, want %+v", persisted, want)
			}
		})
	}
}

type modeReadingRunner struct {
	fakeRunner
	mode  string
	found bool
}

func (r *modeReadingRunner) Exec(ctx context.Context, spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
	r.mode, r.found = ConfinementMode(ctx)
	return r.fakeRunner.Exec(ctx, spec)
}

func TestInvoke_CarriesTheConfinementModeToTheRunner(t *testing.T) {
	action := &ActionSpec{Argv: []string{"mybin", "status"}}
	emit := newCapture().appendEvent

	plain := &modeReadingRunner{fakeRunner: fakeRunner{id: ids.NewV7()}}
	if _, err := Invoke(context.Background(), "status", action, nil, t.TempDir(), plain, emit, 64); err != nil {
		t.Fatal(err)
	}
	if plain.found {
		t.Fatalf("mode = %q found without an override, want none", plain.mode)
	}

	child := &modeReadingRunner{fakeRunner: fakeRunner{id: ids.NewV7()}}
	ctx := WithConfinementMode(context.Background(), "plan")
	if _, err := Invoke(ctx, "status", action, nil, t.TempDir(), child, newCapture().appendEvent, 64); err != nil {
		t.Fatal(err)
	}
	if !child.found || child.mode != "plan" {
		t.Fatalf("mode = %q/%v, want the override plan", child.mode, child.found)
	}
}
