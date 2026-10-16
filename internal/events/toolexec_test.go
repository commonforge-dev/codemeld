// Tests for the tool_exec_* emitter helpers and the shared stdout/stderr
// truncation: per-stream cap behavior, UTF-8-safe boundary stripping, persisted
// payload readback, the model-input/persisted byte-for-byte invariant
// and start/end invocation_id pairing.
package events

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/sessions"
)

// reloadAll marshals sess through the production session codec, reloads it, and
// returns every persisted event, asserting each survives the load-time validator.
// Unlike reloadOnly it does not pin the record count, so it can read a start/end
// pair back from one store.
func reloadAll(t *testing.T, sess *sessions.Session) []sessions.Event {
	t.Helper()
	data, err := sessions.Marshal(sess)
	if err != nil {
		t.Fatalf("sessions.Marshal() error = %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("sessions.Unmarshal() error = %v", err)
	}
	out := make([]sessions.Event, len(loaded.Records))
	for i, r := range loaded.Records {
		ev, ok := r.(sessions.Event)
		if !ok {
			t.Fatalf("reloaded record %d is %T, want sessions.Event", i, r)
		}
		if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
			t.Fatalf("ValidatePayload() rejected persisted record %d: %v", i, err)
		}
		out[i] = ev
	}
	return out
}

// decodeEnd unmarshals a persisted tool_exec_end payload.
func decodeEnd(t *testing.T, ev sessions.Event) ToolExecEnd {
	t.Helper()
	if ev.Kind != KindToolExecEnd {
		t.Fatalf("kind = %q, want %q", ev.Kind, KindToolExecEnd)
	}
	var got ToolExecEnd
	if err := json.Unmarshal(ev.Payload, &got); err != nil {
		t.Fatalf("unmarshal tool_exec_end payload: %v", err)
	}
	return got
}

// TestEmitToolExecEnd_Truncation covers the per-stream cap behavior against the
// durable record: under-cap (no truncation), one stream over cap, both over cap,
// zero and negative cap on non-empty output, and UTF-8-safe boundary stripping.
func TestEmitToolExecEnd_Truncation(t *testing.T) {
	cases := []struct {
		name          string
		stdout        []byte
		stderr        []byte
		cap           int
		wantStdout    string // persisted, post-truncation/coercion
		wantStderr    string
		wantTruncated bool
		wantOrigOut   int64 // original_bytes.stdout when truncated
		wantOrigErr   int64
	}{
		{
			name:       "under-cap-no-truncation",
			stdout:     []byte("hello"),
			stderr:     []byte("warn"),
			cap:        64,
			wantStdout: "hello", wantStderr: "warn",
			wantTruncated: false,
		},
		{
			name:       "stdout-over-cap-only",
			stdout:     bytes.Repeat([]byte("a"), 20),
			stderr:     []byte("ok"),
			cap:        8,
			wantStdout: "aaaaaaaa", wantStderr: "ok",
			wantTruncated: true, wantOrigOut: 20, wantOrigErr: 2,
		},
		{
			name:       "both-over-cap",
			stdout:     bytes.Repeat([]byte("a"), 20),
			stderr:     bytes.Repeat([]byte("b"), 30),
			cap:        4,
			wantStdout: "aaaa", wantStderr: "bbbb",
			wantTruncated: true, wantOrigOut: 20, wantOrigErr: 30,
		},
		{
			name:       "zero-cap-non-empty",
			stdout:     []byte("x"),
			stderr:     []byte("yy"),
			cap:        0,
			wantStdout: "", wantStderr: "",
			wantTruncated: true, wantOrigOut: 1, wantOrigErr: 2,
		},
		{
			// A negative cap clamps to max(cap, 0) == 0, so it behaves exactly like
			// a zero cap: both non-empty streams are dropped and reported truncated,
			// with original_bytes preserving the raw pre-truncation byte counts.
			name:       "negative-cap-non-empty",
			stdout:     []byte("x"),
			stderr:     []byte("yy"),
			cap:        -1,
			wantStdout: "", wantStderr: "",
			wantTruncated: true, wantOrigOut: 1, wantOrigErr: 2,
		},
		{
			// "héllo" = h(1) + é(2: C3 A9) + llo(3) = 6 bytes. cap 2 cuts inside é,
			// so the kept bytes strip back to "h"; the partial rune is dropped.
			name:       "multibyte-boundary-safe",
			stdout:     []byte("héllo"),
			stderr:     nil,
			cap:        2,
			wantStdout: "h", wantStderr: "",
			wantTruncated: true, wantOrigOut: 6, wantOrigErr: 0,
		},
		{
			// cap equal to the full byte length keeps a whole multi-byte rune and
			// does not truncate.
			name:       "multibyte-fits-exactly",
			stdout:     []byte("aé"),
			stderr:     nil,
			cap:        3,
			wantStdout: "aé", wantStderr: "",
			wantTruncated: false,
		},
		{
			// A lone invalid byte coerces to a 3-byte U+FFFD. With cap 1 that
			// replacement cannot fit, so nothing is kept and the stream is reported
			// truncated — coercion must not expand the kept bytes past the cap.
			name:       "invalid-byte-expands-past-cap",
			stdout:     []byte{0xff},
			stderr:     nil,
			cap:        1,
			wantStdout: "", wantStderr: "",
			wantTruncated: true, wantOrigOut: 1, wantOrigErr: 0,
		},
		{
			// "ab" + invalid 0xff + "cd": at cap 3 the two ASCII bytes fit but the
			// invalid run's 3-byte replacement would land at byte 5, so it is
			// dropped and the kept bytes stop at "ab" rather than overflowing.
			name:       "invalid-run-replacement-over-boundary",
			stdout:     []byte{0x61, 0x62, 0xff, 0x63, 0x64},
			stderr:     nil,
			cap:        3,
			wantStdout: "ab", wantStderr: "",
			wantTruncated: true, wantOrigOut: 5, wantOrigErr: 0,
		},
		{
			// An invalid run whose replacement fits exactly at the cap is kept whole
			// and reports no truncation: "ab" + 0xff -> "ab" + U+FFFD = 5 bytes.
			name:       "invalid-run-replacement-fits-exactly",
			stdout:     []byte{0x61, 0x62, 0xff},
			stderr:     nil,
			cap:        5,
			wantStdout: "ab�", wantStderr: "",
			wantTruncated: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, store := emitFixture()
			if err := EmitToolExecEnd(store, goodV7, "direct", "ls -la", 0, 12, tc.stdout, tc.stderr, tc.cap, ""); err != nil {
				t.Fatalf("EmitToolExecEnd() error = %v", err)
			}
			ev := reloadOnly(t, sess)
			got := decodeEnd(t, ev)

			if got.Stdout != tc.wantStdout {
				t.Errorf("persisted stdout = %q, want %q", got.Stdout, tc.wantStdout)
			}
			if got.Stderr != tc.wantStderr {
				t.Errorf("persisted stderr = %q, want %q", got.Stderr, tc.wantStderr)
			}
			if !utf8.ValidString(got.Stdout) || !utf8.ValidString(got.Stderr) {
				t.Errorf("persisted streams are not valid UTF-8: stdout=%q stderr=%q", got.Stdout, got.Stderr)
			}
			wantMax := tc.cap
			if wantMax < 0 {
				wantMax = 0
			}
			if len(got.Stdout) > wantMax {
				t.Errorf("persisted stdout = %d bytes, exceeds cap %d (%q)", len(got.Stdout), wantMax, got.Stdout)
			}
			if len(got.Stderr) > wantMax {
				t.Errorf("persisted stderr = %d bytes, exceeds cap %d (%q)", len(got.Stderr), wantMax, got.Stderr)
			}
			if got.Truncated != tc.wantTruncated {
				t.Errorf("truncated = %v, want %v", got.Truncated, tc.wantTruncated)
			}
			if !tc.wantTruncated {
				if got.OriginalBytes != nil {
					t.Errorf("original_bytes = %#v, want nil when not truncated", got.OriginalBytes)
				}
				// omitempty must drop original_bytes/truncated:true from the bytes.
				if strings.Contains(string(ev.Payload), "original_bytes") {
					t.Errorf("non-truncated payload persisted original_bytes: %s", ev.Payload)
				}
				return
			}
			if got.OriginalBytes == nil {
				t.Fatalf("original_bytes is nil, want set when truncated")
			}
			if got.OriginalBytes.Stdout != tc.wantOrigOut {
				t.Errorf("original_bytes.stdout = %d, want %d", got.OriginalBytes.Stdout, tc.wantOrigOut)
			}
			if got.OriginalBytes.Stderr != tc.wantOrigErr {
				t.Errorf("original_bytes.stderr = %d, want %d", got.OriginalBytes.Stderr, tc.wantOrigErr)
			}
		})
	}
}

// TestTruncateToolOutput covers the exported pair helper that EmitToolExecEnd and
// the VCS emitter share: kept bytes per stream, the combined truncated
// flag, and that original is non-nil exactly when something was dropped, carrying
// both raw byte counts.
func TestTruncateToolOutput(t *testing.T) {
	t.Run("neither over cap returns nil original", func(t *testing.T) {
		keptOut, keptErr, truncated, original := TruncateToolOutput([]byte("hi"), []byte("yo"), 8)
		if string(keptOut) != "hi" || string(keptErr) != "yo" {
			t.Errorf("kept = %q/%q, want hi/yo", keptOut, keptErr)
		}
		if truncated {
			t.Error("truncated = true, want false")
		}
		if original != nil {
			t.Errorf("original = %+v, want nil when nothing dropped", original)
		}
	})

	t.Run("one stream over cap sets truncated and both raw sizes", func(t *testing.T) {
		out := bytes.Repeat([]byte("a"), 20)
		keptOut, keptErr, truncated, original := TruncateToolOutput(out, []byte("ok"), 4)
		if string(keptOut) != "aaaa" || string(keptErr) != "ok" {
			t.Errorf("kept = %q/%q, want aaaa/ok", keptOut, keptErr)
		}
		if !truncated {
			t.Error("truncated = false, want true")
		}
		if original == nil || original.Stdout != 20 || original.Stderr != 2 {
			t.Fatalf("original = %+v, want {20 2}", original)
		}
	})

	t.Run("matches per-stream truncateStream and EmitToolExecEnd", func(t *testing.T) {
		out := []byte("héllo")
		err := bytes.Repeat([]byte("b"), 30)
		const cap = 2
		keptOut, keptErr, truncated, original := TruncateToolOutput(out, err, cap)

		wantOut, wantOutTrunc, wantOutOrig := truncateStream(out, cap)
		wantErr, wantErrTrunc, wantErrOrig := truncateStream(err, cap)
		if !bytes.Equal(keptOut, wantOut) || !bytes.Equal(keptErr, wantErr) {
			t.Errorf("kept = %q/%q, want %q/%q", keptOut, keptErr, wantOut, wantErr)
		}
		if truncated != (wantOutTrunc || wantErrTrunc) {
			t.Errorf("truncated = %v, want %v", truncated, wantOutTrunc || wantErrTrunc)
		}
		if original == nil || original.Stdout != wantOutOrig || original.Stderr != wantErrOrig {
			t.Fatalf("original = %+v, want {%d %d}", original, wantOutOrig, wantErrOrig)
		}

		// The shared helper must yield exactly what EmitToolExecEnd persists.
		sess, store := emitFixture()
		if e := EmitToolExecEnd(store, goodV7, "direct", "cmd", 0, 1, out, err, cap, ""); e != nil {
			t.Fatalf("EmitToolExecEnd: %v", e)
		}
		end := decodeEnd(t, reloadOnly(t, sess))
		if end.Stdout != string(keptOut) || end.Stderr != string(keptErr) {
			t.Errorf("persisted %q/%q != helper %q/%q", end.Stdout, end.Stderr, keptOut, keptErr)
		}
		if end.Truncated != truncated {
			t.Errorf("persisted truncated %v != helper %v", end.Truncated, truncated)
		}
		if (end.OriginalBytes == nil) != (original == nil) {
			t.Errorf("persisted original_bytes %v vs helper %v", end.OriginalBytes, original)
		}
	})
}

// TestEmitToolExecEnd_OmitsEmptyKeptStreams verifies a kept-empty stream is
// dropped from the persisted bytes via omitempty, so a zero-cap or empty stream
// leaves no top-level stdout/stderr key behind. The check decodes the top-level
// object rather than substring-matching, because original_bytes carries its own
// nested stdout/stderr subkeys.
func TestEmitToolExecEnd_OmitsEmptyKeptStreams(t *testing.T) {
	sess, store := emitFixture()
	if err := EmitToolExecEnd(store, goodV7, "direct", "x", 0, 1, []byte("x"), nil, 0, ""); err != nil {
		t.Fatalf("EmitToolExecEnd() error = %v", err)
	}
	ev := reloadOnly(t, sess)
	var top map[string]json.RawMessage
	if err := json.Unmarshal(ev.Payload, &top); err != nil {
		t.Fatalf("unmarshal payload object: %v", err)
	}
	if _, ok := top["stdout"]; ok {
		t.Errorf("empty kept stdout persisted a top-level stdout key: %s", ev.Payload)
	}
	if _, ok := top["stderr"]; ok {
		t.Errorf("empty kept stderr persisted a top-level stderr key: %s", ev.Payload)
	}
}

// TestBuildModelInputBytes_RoundTrip is the invariant: the bytes fed to
// the next model turn equal the persisted tool_exec_end stdout/stderr
// byte-for-byte, across valid ASCII, multi-byte boundary, invalid-UTF-8, and
// under-cap inputs.
func TestBuildModelInputBytes_RoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		stdout []byte
		stderr []byte
		cap    int
	}{
		{"ascii-over-cap", bytes.Repeat([]byte("a"), 100), bytes.Repeat([]byte("b"), 50), 16},
		{"multibyte-boundary", []byte("héllo wörld"), []byte("café"), 5},
		{"invalid-utf8-under-cap", []byte{0x61, 0xff, 0xfe, 0x62}, []byte{0xc3, 0x28}, 64},
		{"invalid-utf8-over-cap", append(bytes.Repeat([]byte("z"), 10), 0xff, 0xff), []byte("ok"), 6},
		{"invalid-byte-cap-1", []byte{0xff}, []byte{0xfe}, 1},
		{"invalid-run-replacement-over-boundary", []byte{0x61, 0x62, 0xff, 0x63, 0x64}, []byte("ok"), 3},
		{"zero-cap", []byte("drop me"), []byte("and me"), 0},
		{"negative-cap", []byte("drop me"), []byte("and me"), -1},
		{"under-cap-clean", []byte("small"), nil, 64},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, store := emitFixture()
			if err := EmitToolExecEnd(store, goodV7, "direct", "cmd", 0, 1, tc.stdout, tc.stderr, tc.cap, ""); err != nil {
				t.Fatalf("EmitToolExecEnd() error = %v", err)
			}
			got := decodeEnd(t, reloadOnly(t, sess))

			modelStdout, modelStderr := BuildModelInputBytes(tc.stdout, tc.stderr, tc.cap)
			if !bytes.Equal(modelStdout, []byte(got.Stdout)) {
				t.Errorf("model stdout (%q) != persisted stdout (%q)", modelStdout, got.Stdout)
			}
			if !bytes.Equal(modelStderr, []byte(got.Stderr)) {
				t.Errorf("model stderr (%q) != persisted stderr (%q)", modelStderr, got.Stderr)
			}
			// Model-fed bytes must themselves be valid UTF-8.
			if !utf8.Valid(modelStdout) || !utf8.Valid(modelStderr) {
				t.Errorf("model input is not valid UTF-8: stdout=%q stderr=%q", modelStdout, modelStderr)
			}
			// ...and must honor the byte cap, even when coercing invalid UTF-8.
			wantMax := tc.cap
			if wantMax < 0 {
				wantMax = 0
			}
			if len(modelStdout) > wantMax {
				t.Errorf("model stdout = %d bytes, exceeds cap %d (%q)", len(modelStdout), wantMax, modelStdout)
			}
			if len(modelStderr) > wantMax {
				t.Errorf("model stderr = %d bytes, exceeds cap %d (%q)", len(modelStderr), wantMax, modelStderr)
			}
		})
	}
}

// TestToolExec_InvocationIDPairing verifies the persisted tool_exec_start and
// tool_exec_end carry the same caller-supplied invocation_id.
func TestToolExec_InvocationIDPairing(t *testing.T) {
	id := ids.NewV7()
	sess, store := emitFixture()
	if err := EmitToolExecStart(store, id, "tool", "Read", "/home/u/proj", ""); err != nil {
		t.Fatalf("EmitToolExecStart() error = %v", err)
	}
	if err := EmitToolExecEnd(store, id, "tool", "Read", 0, 7, []byte("contents"), nil, 64, ""); err != nil {
		t.Fatalf("EmitToolExecEnd() error = %v", err)
	}

	evs := reloadAll(t, sess)
	if len(evs) != 2 {
		t.Fatalf("persisted %d records, want 2 (start + end)", len(evs))
	}

	var startID, endID string
	for _, ev := range evs {
		switch ev.Kind {
		case KindToolExecStart:
			var p ToolExecStart
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				t.Fatalf("unmarshal tool_exec_start: %v", err)
			}
			startID = p.InvocationID
		case KindToolExecEnd:
			var p ToolExecEnd
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				t.Fatalf("unmarshal tool_exec_end: %v", err)
			}
			endID = p.InvocationID
		default:
			t.Errorf("unexpected event kind %q", ev.Kind)
		}
	}
	if startID != id {
		t.Errorf("tool_exec_start.invocation_id = %q, want %q", startID, id)
	}
	if endID != id {
		t.Errorf("tool_exec_end.invocation_id = %q, want %q", endID, id)
	}
	if startID != endID {
		t.Errorf("invocation_id mismatch: start %q != end %q", startID, endID)
	}
}

// TestEmitToolExecStart_RejectsBadInvocationID confirms the emitter validates the
// caller-supplied id through Append: a non-UUIDv7 id is rejected and nothing is
// appended.
func TestEmitToolExecStart_RejectsBadInvocationID(t *testing.T) {
	store := newStore()
	if err := EmitToolExecStart(store, "not-a-v7", "tool", "Read", "/home/u/proj", ""); err == nil {
		t.Fatal("EmitToolExecStart() accepted a non-UUIDv7 invocation id")
	}
	if got := len(store.Records()); got != 0 {
		t.Errorf("rejected emit still appended %d record(s)", got)
	}
}

// TestEmitToolExecEnd_RejectsBadInvocationID confirms the same for the end event.
func TestEmitToolExecEnd_RejectsBadInvocationID(t *testing.T) {
	store := newStore()
	if err := EmitToolExecEnd(store, "not-a-v7", "tool", "Read", 0, 1, nil, nil, 64, ""); err == nil {
		t.Fatal("EmitToolExecEnd() accepted a non-UUIDv7 invocation id")
	}
	if got := len(store.Records()); got != 0 {
		t.Errorf("rejected emit still appended %d record(s)", got)
	}
}

func TestBuildToolExecEndBounded(t *testing.T) {
	cases := []struct {
		name          string
		stdout        []byte
		stderr        []byte
		stdoutTotal   int64
		stderrTotal   int64
		cap           int
		wantStdout    string
		wantStderr    string
		wantTruncated bool
		wantOrigOut   int64
		wantOrigErr   int64
	}{
		{
			name:   "whole streams retained",
			stdout: []byte("hello"), stderr: []byte("warn"),
			stdoutTotal: 5, stderrTotal: 4, cap: 64,
			wantStdout: "hello", wantStderr: "warn",
			wantTruncated: false,
		},
		{
			// The runner retained a 4-byte prefix of a 900-byte stream: nothing is shortened here,
			// so only the total can reveal the truncation.
			name:   "capture bound reached upstream",
			stdout: []byte("aaaa"), stderr: nil,
			stdoutTotal: 900, stderrTotal: 0, cap: 4,
			wantStdout: "aaaa", wantStderr: "",
			wantTruncated: true, wantOrigOut: 900, wantOrigErr: 0,
		},
		{
			name:   "stderr alone reached the bound",
			stdout: []byte("out"), stderr: []byte("ee"),
			stdoutTotal: 3, stderrTotal: 77, cap: 8,
			wantStdout: "out", wantStderr: "ee",
			wantTruncated: true, wantOrigOut: 3, wantOrigErr: 77,
		},
		{
			// A raw retained prefix can end mid-rune: "é" is C3 A9, so a 2-byte capture bound that
			// kept only C3 leaves an invalid byte truncateStream must drop at cap 2.
			name:   "retained prefix ends mid-rune",
			stdout: []byte{0x61, 0xc3}, stderr: nil,
			stdoutTotal: 3, stderrTotal: 0, cap: 2,
			wantStdout: "a", wantStderr: "",
			wantTruncated: true, wantOrigOut: 3, wantOrigErr: 0,
		},
		{
			// Coercion expands a lone invalid byte to a 3-byte U+FFFD, so the retained bytes are
			// shortened here even though the runner read the stream to its end.
			name:   "coercion shortens a complete stream",
			stdout: []byte{0x61, 0xff}, stderr: nil,
			stdoutTotal: 2, stderrTotal: 0, cap: 2,
			wantStdout: "a", wantStderr: "",
			wantTruncated: true, wantOrigOut: 2, wantOrigErr: 0,
		},
		{
			name:   "zero cap keeps nothing",
			stdout: []byte("x"), stderr: []byte("yy"),
			stdoutTotal: 1, stderrTotal: 2, cap: 0,
			wantStdout: "", wantStderr: "",
			wantTruncated: true, wantOrigOut: 1, wantOrigErr: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, store := emitFixture()
			rec, err := BuildToolExecEndBounded(BoundedToolExec{
				InvocationID: goodV7,
				SubjectKind:  "direct",
				Subject:      "ls -la",
				ExitCode:     0,
				DurationMs:   12,
				Stdout:       tc.stdout,
				Stderr:       tc.stderr,
				StdoutTotal:  tc.stdoutTotal,
				StderrTotal:  tc.stderrTotal,
			}, tc.cap)
			if err != nil {
				t.Fatalf("BuildToolExecEndBounded() error = %v", err)
			}
			store.Append(rec)
			got := decodeEnd(t, reloadOnly(t, sess))

			if got.Stdout != tc.wantStdout || got.Stderr != tc.wantStderr {
				t.Fatalf("persisted streams = %q/%q, want %q/%q", got.Stdout, got.Stderr, tc.wantStdout, tc.wantStderr)
			}
			if !utf8.ValidString(got.Stdout) || !utf8.ValidString(got.Stderr) {
				t.Fatalf("persisted streams are not valid UTF-8: stdout=%q stderr=%q", got.Stdout, got.Stderr)
			}
			if got.Truncated != tc.wantTruncated {
				t.Fatalf("truncated = %v, want %v", got.Truncated, tc.wantTruncated)
			}
			if !tc.wantTruncated {
				if got.OriginalBytes != nil {
					t.Fatalf("original_bytes = %#v, want nil when nothing was dropped", got.OriginalBytes)
				}
				return
			}
			if got.OriginalBytes == nil {
				t.Fatalf("original_bytes is nil, want the parent-read totals")
			}
			if got.OriginalBytes.Stdout != tc.wantOrigOut || got.OriginalBytes.Stderr != tc.wantOrigErr {
				t.Fatalf("original_bytes = %+v, want stdout=%d stderr=%d (the totals, never the retained length)", *got.OriginalBytes, tc.wantOrigOut, tc.wantOrigErr)
			}
		})
	}
}

func TestBuildToolExecEndBounded_MatchesModelInputBytes(t *testing.T) {
	cases := []struct {
		name   string
		stdout []byte
		stderr []byte
		cap    int
	}{
		{"ascii", []byte("hello world"), []byte("a warning"), 6},
		{"multibyte at the boundary", []byte("héllo"), []byte("héllo"), 2},
		{"invalid byte at the boundary", []byte{0x61, 0x62, 0xff, 0x63}, []byte{0xff, 0xff}, 3},
		{"trailing newline kept", []byte("out\n"), nil, 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, store := emitFixture()
			rec, err := BuildToolExecEndBounded(BoundedToolExec{
				InvocationID: goodV7,
				SubjectKind:  "direct",
				Subject:      "cmd",
				DurationMs:   1,
				Stdout:       tc.stdout,
				Stderr:       tc.stderr,
				StdoutTotal:  int64(len(tc.stdout)) + 1,
				StderrTotal:  int64(len(tc.stderr)),
			}, tc.cap)
			if err != nil {
				t.Fatalf("BuildToolExecEndBounded() error = %v", err)
			}
			store.Append(rec)
			got := decodeEnd(t, reloadOnly(t, sess))

			wantStdout, wantStderr := BuildModelInputBytes(tc.stdout, tc.stderr, tc.cap)
			if !bytes.Equal([]byte(got.Stdout), wantStdout) {
				t.Fatalf("persisted stdout = %q, want %q (BuildModelInputBytes on the same retained prefix)", got.Stdout, wantStdout)
			}
			if !bytes.Equal([]byte(got.Stderr), wantStderr) {
				t.Fatalf("persisted stderr = %q, want %q", got.Stderr, wantStderr)
			}
		})
	}
}

func TestToolExec_ChildAttributionRoundTrip(t *testing.T) {
	sess := newSession()
	store := sessions.New("unused-in-tests", sess)
	invocation, child := ids.NewV7(), ids.NewV7()

	if err := EmitToolExecStart(store, invocation, "literal", "ls", "/home/u/proj", child); err != nil {
		t.Fatalf("EmitToolExecStart() error = %v", err)
	}
	if err := EmitToolExecEnd(store, invocation, "literal", "ls", 0, 4, nil, nil, 1024, child); err != nil {
		t.Fatalf("EmitToolExecEnd() error = %v", err)
	}
	evs := reloadAll(t, sess)
	if len(evs) != 2 {
		t.Fatalf("persisted records = %d, want 2", len(evs))
	}
	var gotStart ToolExecStart
	if err := json.Unmarshal(evs[0].Payload, &gotStart); err != nil {
		t.Fatalf("unmarshal tool_exec_start: %v", err)
	}
	if gotStart.ChildInvocationID != child {
		t.Errorf("start child_invocation_id = %q, want %q", gotStart.ChildInvocationID, child)
	}
	if got := decodeEnd(t, evs[1]); got.ChildInvocationID != child {
		t.Errorf("end child_invocation_id = %q, want %q", got.ChildInvocationID, child)
	}
}

func TestToolExec_ParentOmitsTheChildAttribution(t *testing.T) {
	sess := newSession()
	store := sessions.New("unused-in-tests", sess)
	invocation := ids.NewV7()

	if err := EmitToolExecStart(store, invocation, "literal", "ls", "/home/u/proj", ""); err != nil {
		t.Fatalf("EmitToolExecStart() error = %v", err)
	}
	if err := EmitToolExecEnd(store, invocation, "literal", "ls", 0, 4, nil, nil, 1024, ""); err != nil {
		t.Fatalf("EmitToolExecEnd() error = %v", err)
	}
	for i, ev := range reloadAll(t, sess) {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(ev.Payload, &fields); err != nil {
			t.Fatalf("unmarshal payload %d: %v", i, err)
		}
		if _, present := fields["child_invocation_id"]; present {
			t.Errorf("record %d (%s) carries child_invocation_id: %s", i, ev.Kind, ev.Payload)
		}
	}
}

func TestBuildToolExecEndBounded_CarriesTheChildAttribution(t *testing.T) {
	invocation, child := ids.NewV7(), ids.NewV7()
	rec, err := BuildToolExecEndBounded(BoundedToolExec{
		InvocationID:      invocation,
		ChildInvocationID: child,
		SubjectKind:       "literal",
		Subject:           "ls",
		DurationMs:        3,
	}, 1024)
	if err != nil {
		t.Fatalf("BuildToolExecEndBounded() error = %v", err)
	}
	if got := decodeEnd(t, rec.(sessions.Event)); got.ChildInvocationID != child {
		t.Fatalf("child_invocation_id = %q, want %q", got.ChildInvocationID, child)
	}
}

func TestToolExecEndFromBounded_MatchesBuildToolExecEndBounded(t *testing.T) {
	cases := []struct {
		name        string
		stdout      []byte
		stderr      []byte
		stdoutTotal int64
		stderrTotal int64
		cap         int
	}{
		{"whole streams", []byte("hello"), []byte("warn"), 5, 4, 64},
		{"totals larger than retained", []byte("aaaa"), nil, 900, 0, 4},
		{"rune boundary", []byte("héllo"), []byte("x"), 40, 1, 2},
		{"invalid utf-8 prefix", []byte{0x61, 0x62, 0xff, 0x63}, []byte{0xff, 0xff}, 50, 60, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exec := BoundedToolExec{
				InvocationID: goodV7,
				SubjectKind:  "tool",
				Subject:      "vcs_status",
				ExitCode:     1,
				DurationMs:   2,
				Stdout:       tc.stdout,
				Stderr:       tc.stderr,
				StdoutTotal:  tc.stdoutTotal,
				StderrTotal:  tc.stderrTotal,
			}
			sess, store := emitFixture()
			rec, err := BuildToolExecEndBounded(exec, tc.cap)
			if err != nil {
				t.Fatalf("BuildToolExecEndBounded() error = %v", err)
			}
			store.Append(rec)
			want := decodeEnd(t, reloadOnly(t, sess))

			got := ToolExecEndFromBounded(exec, tc.cap)
			if (got.OriginalBytes == nil) != (want.OriginalBytes == nil) ||
				(got.OriginalBytes != nil && *got.OriginalBytes != *want.OriginalBytes) {
				t.Fatalf("original_bytes = %+v, want %+v", got.OriginalBytes, want.OriginalBytes)
			}
			got.OriginalBytes, want.OriginalBytes = nil, nil
			if got != want {
				t.Fatalf("ToolExecEndFromBounded = %+v, want %+v", got, want)
			}
		})
	}
}
