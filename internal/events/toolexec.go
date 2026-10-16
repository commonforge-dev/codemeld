// Tool-exec event emitter helpers plus the shared stdout/stderr truncation used
// for both event persistence and the model-input feed.
package events

import (
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/sessions"
)

// EmitToolExecStart appends a tool_exec_start event recording the start of a tool
// invocation. invocationID is the runner-minted UUIDv7 for this invocation
// and is reused on the matching tool_exec_end so the pair shares
// one id; subjectKind/subject describe the dispatched command and pathScope is its
// resolved working directory (a cleaned absolute path). It validates the payload
// through Append, so a non-UUIDv7 invocationID, an unrecognized subjectKind, an
// empty subject, or a non-absolute pathScope is rejected and nothing is appended.
// It appends only; the caller owns the flush.
func EmitToolExecStart(store *sessions.Store, invocationID, subjectKind, subject, pathScope, childInvocationID string) error {
	_, err := Append(store, ToolExecStart{
		SubjectKind:       subjectKind,
		Subject:           subject,
		PathScope:         pathScope,
		InvocationID:      invocationID,
		ChildInvocationID: childInvocationID,
	})
	return err
}

// EmitToolExecEnd appends a tool_exec_end event for a completed invocation, paired
// to its start event by invocationID. Each of stdout/stderr is truncated
// independently to cap bytes at a UTF-8 rune boundary (see truncateStream);
// truncated and original_bytes are set only when at least one stream was actually
// shortened, and original_bytes then carries the pre-truncation raw byte size of
// both streams. A kept-empty stream is stored as the empty string so omitempty
// drops it from the persisted payload. It appends only; the caller owns the
// flush.
func EmitToolExecEnd(store *sessions.Store, invocationID string, subjectKind, subject string, exitCode int, durationMs int64, stdout, stderr []byte, cap int, childInvocationID string) error {
	keptOut, keptErr, truncated, original := TruncateToolOutput(stdout, stderr, cap)

	end := ToolExecEnd{
		SubjectKind:       subjectKind,
		Subject:           subject,
		ExitCode:          int64(exitCode),
		DurationMs:        durationMs,
		Stdout:            string(keptOut),
		Stderr:            string(keptErr),
		Truncated:         truncated,
		OriginalBytes:     original,
		InvocationID:      invocationID,
		ChildInvocationID: childInvocationID,
	}
	_, err := Append(store, end)
	return err
}

// BoundedToolExec is one completed invocation whose stdout/stderr were already bounded before they
// reached the event layer. Stdout/Stderr are the bytes that were retained; StdoutTotal/StderrTotal are how many bytes
// were read from each stream in full, which is what original_bytes must report.
type BoundedToolExec struct {
	InvocationID      string
	ChildInvocationID string
	SubjectKind       string
	Subject           string
	ExitCode          int
	DurationMs        int64
	Stdout            []byte
	Stderr            []byte
	StdoutTotal       int64
	StderrTotal       int64
}

// BuildToolExecEndBounded exists beside EmitToolExecEnd because that emitter derives truncated and
// original_bytes from the full streams it is handed, which would record a stage already cut short at
// capture time as complete. The retained bytes still go through truncateStream at the same cap: the
// capture bound is raw, so a retained prefix can end mid-rune or grow past the cap once invalid
// bytes become U+FFFD.
func BuildToolExecEndBounded(exec BoundedToolExec, cap int) (sessions.Record, error) {
	return Build(ToolExecEndFromBounded(exec, cap))
}

func ToolExecEndFromBounded(exec BoundedToolExec, cap int) ToolExecEnd {
	keptOut, outShortened, _ := truncateStream(exec.Stdout, cap)
	keptErr, errShortened, _ := truncateStream(exec.Stderr, cap)
	truncated := outShortened || errShortened ||
		exec.StdoutTotal > int64(len(exec.Stdout)) || exec.StderrTotal > int64(len(exec.Stderr))

	end := ToolExecEnd{
		SubjectKind:       exec.SubjectKind,
		Subject:           exec.Subject,
		ExitCode:          int64(exec.ExitCode),
		DurationMs:        exec.DurationMs,
		Stdout:            string(keptOut),
		Stderr:            string(keptErr),
		Truncated:         truncated,
		InvocationID:      exec.InvocationID,
		ChildInvocationID: exec.ChildInvocationID,
	}
	if truncated {
		end.OriginalBytes = &OriginalBytes{Stdout: exec.StdoutTotal, Stderr: exec.StderrTotal}
	}
	return end
}

// TruncateToolOutput caps a stdout/stderr pair for a tool_exec_end payload: each
// stream is independently truncated to max(cap, 0) bytes at a UTF-8 rune boundary
// (see truncateStream). truncated is true iff at least one stream was actually
// shortened, and original is non-nil exactly when truncated is true, carrying the
// pre-truncation raw byte size of both streams (so a non-truncated pair leaves
// ToolExecEnd.OriginalBytes nil, matching the absence rule). Production
// emitters — EmitToolExecEnd and the VCS invocation path — share this
// helper so their persisted bytes stay byte-for-byte identical to what
// BuildModelInputBytes feeds the model.
func TruncateToolOutput(stdout, stderr []byte, cap int) (keptOut, keptErr []byte, truncated bool, original *OriginalBytes) {
	keptOut, outTruncated, outOriginal := truncateStream(stdout, cap)
	keptErr, errTruncated, errOriginal := truncateStream(stderr, cap)
	if outTruncated || errTruncated {
		return keptOut, keptErr, true, &OriginalBytes{Stdout: outOriginal, Stderr: errOriginal}
	}
	return keptOut, keptErr, false, nil
}

// BuildModelInputBytes truncates stdout and stderr exactly as EmitToolExecEnd
// persists them, so the next model turn is fed the same bytes that were recorded
// in tool_exec_end. Because both paths go through truncateStream, the
// returned bytes are byte-for-byte identical to the persisted tool_exec_end
// stdout/stderr (after Append's UTF-8 canonicalization, which truncateStream
// already applies).
func BuildModelInputBytes(stdout, stderr []byte, cap int) (modelStdout, modelStderr []byte) {
	keptOut, _, _ := truncateStream(stdout, cap)
	keptErr, _, _ := truncateStream(stderr, cap)
	return keptOut, keptErr
}

// replacementUTF8 is the 3-byte UTF-8 encoding of U+FFFD, the rune
// strings.ToValidUTF8 (and so events.Append) substitutes for each maximal run of
// invalid bytes.
const replacementUTF8 = "�"

// truncateStream builds the kept bytes for one stream: a valid-UTF-8 prefix of
// data that is at most max(cap, 0) bytes after coercion. It scans data rune by
// rune and coerces each maximal run of invalid bytes to a single U+FFFD exactly as
// events.Append's strings.ToValidUTF8 does, but stops before any rune — or
// replacement rune — that would push the kept bytes past the cap. Enforcing the
// cap on the coerced output (rather than on the raw bytes, then coercing) is what
// keeps a lone invalid byte from expanding into a 3-byte replacement that exceeds
// the cap, so the persisted tool_exec_end bytes and the model-input bytes both
// honor max(cap, 0) and stay byte-for-byte identical. truncated reports
// whether any raw input was left out — because the cap was reached or because a
// trailing invalid run's replacement would not fit — and original is the
// pre-truncation raw byte length of data. A cap of 0 (or negative) keeps zero
// bytes, so any non-empty stream is truncated.
func truncateStream(data []byte, cap int) (kept []byte, truncated bool, original int64) {
	original = int64(len(data))
	limit := cap
	if limit < 0 {
		limit = 0
	}
	kept = make([]byte, 0, min(len(data), limit))
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			// Invalid byte: consume the whole maximal run of invalid bytes (the
			// same collapsing strings.ToValidUTF8 applies) and emit one U+FFFD, but
			// only when its 3 bytes still fit under the cap.
			j := i + 1
			for j < len(data) {
				if r2, s2 := utf8.DecodeRune(data[j:]); r2 == utf8.RuneError && s2 == 1 {
					j++
					continue
				}
				break
			}
			if len(kept)+len(replacementUTF8) > limit {
				return kept, true, original
			}
			kept = append(kept, replacementUTF8...)
			i = j
			continue
		}
		// Valid rune (including ASCII and an already-encoded U+FFFD): keep it whole
		// only when all its bytes fit.
		if len(kept)+size > limit {
			return kept, true, original
		}
		kept = append(kept, data[i:i+size]...)
		i += size
	}
	return kept, false, original
}
