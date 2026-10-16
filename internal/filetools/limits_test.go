// Unit tests for the shared read-only output-bounding helpers: exact limit constants
// numeric-argument validation including over-maximum wording, success-metadata encoding
// byte_cap-over-limit reason precedence, read-stdout-verbatim non-corruption, and survival of the
// truncation indicator through the production byte-cap renderer.
package filetools

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/events"
)

func intPtr(n int) *int { return &n }

// parseMeta strips the MetadataPrefix and trailing newline from a success result's stderr and decodes
// the JSON payload, failing the test if the line is not the expected shape.
func parseMeta(t *testing.T, stderr []byte) OutputMeta {
	t.Helper()
	if !bytes.HasPrefix(stderr, []byte(MetadataPrefix)) {
		t.Fatalf("stderr %q does not start with metadata prefix %q", stderr, MetadataPrefix)
	}
	payload := bytes.TrimSuffix(stderr[len(MetadataPrefix):], []byte("\n"))
	var meta OutputMeta
	if err := json.Unmarshal(payload, &meta); err != nil {
		t.Fatalf("metadata payload %q is not valid JSON: %v", payload, err)
	}
	return meta
}

// TestLimitConstants pins the exact default/maximum values; a drift here is a contract change.
func TestLimitConstants(t *testing.T) {
	cases := []struct {
		name           string
		got, wantValue int
	}{
		{"read default", ReadDefaultLimit, 2000},
		{"read max", ReadMaxLimit, 10000},
		{"grep default", GrepDefaultLimit, 250},
		{"grep max", GrepMaxLimit, 5000},
		{"glob default", GlobDefaultLimit, 250},
		{"glob max", GlobMaxLimit, 5000},
		{"list default", ListDefaultLimit, 250},
		{"list max", ListMaxLimit, 5000},
		{"tree default", TreeDefaultLimit, 250},
		{"tree max", TreeMaxLimit, 5000},
	}
	for _, tc := range cases {
		if tc.got != tc.wantValue {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.wantValue)
		}
	}
}

// TestValidateNumericArgs covers: each boundary is enforced, an over-maximum limit names the
// maximum, valid values pass, and a nil field is skipped — no value is ever silently clamped.
func TestValidateNumericArgs(t *testing.T) {
	cases := []struct {
		name       string
		kind       string
		args       NumericArgs
		wantErr    bool
		wantReason string // substring the *TargetError reason must contain when wantErr
	}{
		{"offset below 1", "read", NumericArgs{Offset: intPtr(0), Limit: intPtr(10), Max: ReadMaxLimit}, true, "offset must be >= 1"},
		{"offset negative", "read", NumericArgs{Offset: intPtr(-3), Max: ReadMaxLimit}, true, "offset must be >= 1"},
		{"offset 1 ok", "read", NumericArgs{Offset: intPtr(1), Limit: intPtr(10), Max: ReadMaxLimit}, false, ""},
		{"limit below 1", "grep", NumericArgs{Limit: intPtr(0), Max: GrepMaxLimit}, true, "limit must be >= 1"},
		{"limit over max names maximum", "read", NumericArgs{Limit: intPtr(10001), Max: ReadMaxLimit}, true, "exceeds the maximum of 10000"},
		{"limit at max ok", "read", NumericArgs{Limit: intPtr(ReadMaxLimit), Max: ReadMaxLimit}, false, ""},
		{"limit in range ok", "list", NumericArgs{Limit: intPtr(100), Max: ListMaxLimit}, false, ""},
		{"context negative", "grep", NumericArgs{Context: intPtr(-1), Max: GrepMaxLimit}, true, "context must be >= 0"},
		{"context zero ok", "grep", NumericArgs{Context: intPtr(0), Limit: intPtr(5), Max: GrepMaxLimit}, false, ""},
		{"depth negative", "tree", NumericArgs{Depth: intPtr(-1), Max: TreeMaxLimit}, true, "depth must be >= 0"},
		{"depth zero ok", "tree", NumericArgs{Depth: intPtr(0), Limit: intPtr(5), Max: TreeMaxLimit}, false, ""},
		{"all nil ok", "glob", NumericArgs{Max: GlobMaxLimit}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			te := ValidateNumericArgs(tc.kind, tc.args)
			if tc.wantErr {
				if te == nil {
					t.Fatalf("ValidateNumericArgs(%q, %+v) = nil, want a *TargetError", tc.kind, tc.args)
				}
				if te.Kind != tc.kind {
					t.Errorf("TargetError.Kind = %q, want %q", te.Kind, tc.kind)
				}
				if !strings.Contains(te.Reason, tc.wantReason) {
					t.Errorf("TargetError.Reason = %q, want it to contain %q", te.Reason, tc.wantReason)
				}
				return
			}
			if te != nil {
				t.Fatalf("ValidateNumericArgs(%q, %+v) = %v, want nil", tc.kind, tc.args, te)
			}
		})
	}
}

// TestBoundedResult_NotTruncated proves a within-limits, within-cap result carries truncated:false with
// no reason/hint/next_offset, leaves stdout byte-identical, and writes exactly one prefixed stderr line.
func TestBoundedResult_NotTruncated(t *testing.T) {
	stdout := []byte("line one\nline two\n")
	res := BoundedResult(stdout, false, 0, 65536)

	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (success)", res.ExitCode)
	}
	if !bytes.Equal(res.Stdout, stdout) {
		t.Fatalf("Stdout = %q, want byte-identical input %q", res.Stdout, stdout)
	}
	meta := parseMeta(t, res.Stderr)
	if meta.Truncated {
		t.Errorf("Truncated = true, want false")
	}
	if meta.TruncationReason != "" || meta.RetryHint != "" || meta.NextOffset != 0 {
		t.Errorf("non-truncated meta carried reason=%q hint=%q next_offset=%d, want all empty", meta.TruncationReason, meta.RetryHint, meta.NextOffset)
	}
	if got := string(res.Stderr); got != MetadataPrefix+`{"truncated":false}`+"\n" {
		t.Fatalf("stderr = %q, want a single %q line with {\"truncated\":false}", got, MetadataPrefix)
	}
}

// TestBoundedResult_LimitTruncationRead covers the read pagination case: a logical-limit truncation with
// more lines remaining carries reason=limit, the resume next_offset, and a read-specific retry hint.
func TestBoundedResult_LimitTruncationRead(t *testing.T) {
	res := BoundedResult([]byte("first 2000 lines...\n"), true, 2001, 65536)

	meta := parseMeta(t, res.Stderr)
	if !meta.Truncated {
		t.Fatalf("Truncated = false, want true")
	}
	if meta.TruncationReason != TruncationReasonLimit {
		t.Errorf("TruncationReason = %q, want %q", meta.TruncationReason, TruncationReasonLimit)
	}
	if meta.NextOffset != 2001 {
		t.Errorf("NextOffset = %d, want 2001", meta.NextOffset)
	}
	if meta.RetryHint == "" {
		t.Error("RetryHint is empty, want a pagination hint")
	}
}

// TestBoundedResult_LimitTruncationEntries covers the entry-listing tools: a logical-limit truncation
// with no pagination offset carries reason=limit and omits next_offset.
func TestBoundedResult_LimitTruncationEntries(t *testing.T) {
	res := BoundedResult([]byte("250 entries...\n"), true, 0, 65536)

	meta := parseMeta(t, res.Stderr)
	if !meta.Truncated || meta.TruncationReason != TruncationReasonLimit {
		t.Fatalf("meta = %+v, want truncated with reason %q", meta, TruncationReasonLimit)
	}
	if meta.NextOffset != 0 {
		t.Errorf("NextOffset = %d, want 0 (omitted for entry-listing tools)", meta.NextOffset)
	}
	if bytes.Contains(res.Stderr, []byte("next_offset")) {
		t.Errorf("stderr %q encoded next_offset, want it omitted", res.Stderr)
	}
}

// TestBoundedResult_ByteCapPrecedence pins the reason precedence: when the byte cap will trim
// stdout, the reason is byte_cap even if a per-tool limit also withheld output.
func TestBoundedResult_ByteCapPrecedence(t *testing.T) {
	stdout := bytes.Repeat([]byte("a"), 4096)
	res := BoundedResult(stdout, true, 2001, 512) // both a logical limit AND > cap

	meta := parseMeta(t, res.Stderr)
	if !meta.Truncated {
		t.Fatalf("Truncated = false, want true")
	}
	if meta.TruncationReason != TruncationReasonByteCap {
		t.Errorf("TruncationReason = %q, want %q (byte_cap takes precedence over limit)", meta.TruncationReason, TruncationReasonByteCap)
	}
}

// TestBoundedResult_ByteCapMatchesProductionForInvalidUTF8 proves the byte_cap reason is derived from the
// production cap path, not from raw length: 300 invalid bytes are far over the cap by raw length, but
// events.truncateStream collapses the whole maximal invalid run into a single 3-byte U+FFFD that fits, so
// it reports no stdout trim. The metadata must agree with that helper and not claim byte_cap.
func TestBoundedResult_ByteCapMatchesProductionForInvalidUTF8(t *testing.T) {
	const cap = 256
	stdout := bytes.Repeat([]byte{0xff}, 300) // raw length 300 > cap, but coerces to one 3-byte U+FFFD

	_, _, eventsTruncated, _ := events.TruncateToolOutput(stdout, nil, cap)
	res := BoundedResult(stdout, false, 0, cap)
	meta := parseMeta(t, res.Stderr)

	gotByteCap := meta.TruncationReason == TruncationReasonByteCap
	if gotByteCap != eventsTruncated {
		t.Fatalf("metadata byte_cap=%v but the production cap helper truncated stdout=%v; the reason must match the cap path", gotByteCap, eventsTruncated)
	}
	if !eventsTruncated && meta.Truncated {
		t.Errorf("Truncated = true, want false: the production cap did not trim stdout and no limit truncation was set")
	}
}

// TestBoundedResult_StdoutVerbatimNoMetadata proves the metadata never leaks into stdout: read's
// verbatim content is returned unchanged and carries none of the metadata prefix.
func TestBoundedResult_StdoutVerbatimNoMetadata(t *testing.T) {
	stdout := []byte("package main\n\nfunc main() {}\n")
	res := BoundedResult(stdout, true, 0, 65536)

	if !bytes.Equal(res.Stdout, stdout) {
		t.Fatalf("Stdout = %q, want byte-identical input %q", res.Stdout, stdout)
	}
	if bytes.Contains(res.Stdout, []byte(MetadataPrefix)) {
		t.Errorf("Stdout contains the metadata prefix, want metadata confined to stderr")
	}
}

// TestBoundedResult_MetadataSurvivesByteCap is the Done-when-4 proof: a result far larger than
// both the per-tool limit and the byte cap, rendered through the production byte-cap path
// (events.BuildModelInputBytes, what formatToolResult and tool_exec_end use), still carries an intact,
// parseable truncation indicator, while stdout is trimmed to a clean prefix of the original content.
func TestBoundedResult_MetadataSurvivesByteCap(t *testing.T) {
	const cap = 256
	stdout := bytes.Repeat([]byte("a"), 8192) // far larger than both the cap and any per-tool limit
	res := BoundedResult(stdout, true, 2001, cap)

	modelStdout, modelStderr := events.BuildModelInputBytes(res.Stdout, res.Stderr, cap)

	// The byte cap trims stdout to a prefix of the original verbatim content, with no metadata mixed in.
	if len(modelStdout) > cap {
		t.Fatalf("model stdout = %d bytes, want <= cap %d", len(modelStdout), cap)
	}
	if !bytes.HasPrefix(stdout, modelStdout) {
		t.Error("model stdout is not a prefix of the original stdout (verbatim content corrupted)")
	}
	if bytes.Contains(modelStdout, []byte(MetadataPrefix)) {
		t.Error("model stdout contains metadata, want it confined to stderr")
	}

	// The indicator survives the same trim on stderr and still parses to a truncated record.
	meta := parseMeta(t, modelStderr)
	if !meta.Truncated || meta.TruncationReason != TruncationReasonByteCap {
		t.Fatalf("surviving meta = %+v, want truncated with reason %q", meta, TruncationReasonByteCap)
	}
	if meta.NextOffset != 2001 {
		t.Fatalf("surviving meta next_offset = %d, want 2001", meta.NextOffset)
	}
}
