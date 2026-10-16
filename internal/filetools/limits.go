// Shared output-bounding policy for the read-only navigation tools (read, grep, glob, list, tree):
// product-default/maximum result limits, numeric-argument validation, and a byte-cap-safe truncation
// indicator. The indicator is encoded as a single, prefixed JSON line at the start
// of stderr — out of read's verbatim stdout and inside the prefix-preserving byte-cap path — so it
// survives any schema-valid sessions.max_tool_output_bytes trim regardless of per-tool limits.
package filetools

import (
	"encoding/json"
	"fmt"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/tools"
)

// Per-tool product-default and product-maximum result limits, defined as named constants
// rather than configuration. The default applies when the model omits `limit`; Max is the largest
// `limit` the model may request per call — a larger value is rejected in-band naming the maximum (see
// ValidateNumericArgs). read counts lines; grep/glob/list/tree count entries (matches/paths/names).
const (
	ReadDefaultLimit = 2000
	ReadMaxLimit     = 10000

	GrepDefaultLimit = 250
	GrepMaxLimit     = 5000

	GlobDefaultLimit = 250
	GlobMaxLimit     = 5000

	ListDefaultLimit = 250
	ListMaxLimit     = 5000

	TreeDefaultLimit = 250
	TreeMaxLimit     = 5000
)

// Truncation-reason values carried in OutputMeta.TruncationReason. ByteCap means the global
// sessions.max_tool_output_bytes cap trimmed the output; Limit means only a per-tool line/entry limit
// withheld more output. ByteCap takes precedence when both apply — the byte cap is the harder backstop.
const (
	TruncationReasonByteCap = "byte_cap"
	TruncationReasonLimit   = "limit"
)

// MetadataPrefix marks the single success-metadata line BoundedResult writes at the start of stderr. A
// stable, compact, ASCII prefix lets the model (and tests) pick the truncation indicator out
// unambiguously, and keeps the line small enough to survive a small byte cap.
const MetadataPrefix = "codemeld-tool-meta: "

// OutputMeta is the per-result truncation/continuation metadata every successful read-only tool result
// carries. BoundedResult serializes it as compact JSON on a single MetadataPrefix
// line at the start of stderr; see that helper for why it lives there rather than in stdout. Truncated
// is always emitted; the remaining fields are present only when meaningful (omitempty).
type OutputMeta struct {
	// Truncated reports whether any output was withheld, by either a per-tool limit or the byte cap.
	Truncated bool `json:"truncated"`
	// TruncationReason is byte_cap or limit when Truncated, empty otherwise.
	TruncationReason string `json:"truncation_reason,omitempty"`
	// RetryHint is a short, model-facing suggestion for narrowing or paginating, set only when Truncated.
	RetryHint string `json:"retry_hint,omitempty"`
	// NextOffset is read's 1-based line to resume from when more lines remain; 0/omitted for the
	// entry-listing tools and when no more lines remain.
	NextOffset int `json:"next_offset,omitempty"`
}

// NumericArgs carries the already-extracted numeric arguments a read-only tool wants validated together.
// A nil field means that argument is absent for this tool/call and is skipped; Max is the
// tool's product-maximum limit, consulted only when Limit is non-nil.
type NumericArgs struct {
	Offset  *int
	Limit   *int
	Context *int
	Depth   *int
	Max     int
}

// ValidateNumericArgs enforces the shared numeric contract: offset >= 1, limit in [1, Max]
// context >= 0, and depth >= 0. It returns the first violation as a *TargetError tagged with kind (the
// calling tool name) so dispatch surfaces it in-band and the model can correct it; an
// over-maximum limit names the maximum. No value is ever silently clamped, and a nil field is skipped.
// It returns nil when every present argument is in range.
func ValidateNumericArgs(kind string, a NumericArgs) *TargetError {
	if a.Offset != nil && *a.Offset < 1 {
		return &TargetError{Kind: kind, Reason: fmt.Sprintf("offset must be >= 1, got %d", *a.Offset)}
	}
	if a.Limit != nil {
		switch {
		case *a.Limit < 1:
			return &TargetError{Kind: kind, Reason: fmt.Sprintf("limit must be >= 1, got %d", *a.Limit)}
		case *a.Limit > a.Max:
			return &TargetError{Kind: kind, Reason: fmt.Sprintf("limit %d exceeds the maximum of %d", *a.Limit, a.Max)}
		}
	}
	if a.Context != nil && *a.Context < 0 {
		return &TargetError{Kind: kind, Reason: fmt.Sprintf("context must be >= 0, got %d", *a.Context)}
	}
	if a.Depth != nil && *a.Depth < 0 {
		return &TargetError{Kind: kind, Reason: fmt.Sprintf("depth must be >= 0, got %d", *a.Depth)}
	}
	return nil
}

// BoundedResult assembles the success tools.Result for a read-only tool from its already
// line/entry-limited stdout, encoding the truncation indicator as a single MetadataPrefix JSON
// line at the START of stderr. Three properties make the indicator byte-cap-safe and non-corrupting:
//
// It lives in stderr, never in stdout, so it cannot corrupt read's verbatim file content.
//   - It is the first (and only) line the helper writes to stderr, and the global byte cap
//     (events.TruncateToolOutput / events.BuildModelInputBytes) preserves a *prefix* of each stream, so
//     the indicator survives even when stdout is trimmed by any schema-valid cap.
//   - It single-sources truncation through that existing byte-cap path rather than trimming stdout
//     itself: stdout is passed through untrimmed and the helper only records whether the cap will trim
//
// it, so there is exactly one byte-truncation mechanism in the system.
//
// limitTruncated reports whether the per-tool logical limit withheld output; nextOffset is read's resume
// line (0 for the entry-listing tools and when no more lines remain). cap is the
// Cache.MaxToolOutputBytes() value, passed as an int so this package stays independent of config; when the
// production byte cap would trim stdout the reason is byte_cap, which takes precedence over a logical-limit
// truncation.
func BoundedResult(stdout []byte, limitTruncated bool, nextOffset int, cap int) tools.Result {
	// Ask the production cap path itself whether stdout would be trimmed, rather than predicting from raw
	// length: events.truncateStream coerces each maximal invalid-UTF-8 run to one U+FFFD *before* applying
	// the cap, so a raw length over cap need not mean trimming (e.g. 300 invalid bytes collapse to 3 and
	// fit). Passing a nil stderr isolates stdout's flag; the returned trimmed bytes are discarded because
	// stdout is still returned untrimmed below, keeping the byte cap the single byte-truncation mechanism.
	_, _, byteCapped, _ := events.TruncateToolOutput(stdout, nil, cap)
	limitTrunc := limitTruncated || nextOffset > 0

	meta := OutputMeta{Truncated: byteCapped || limitTrunc}
	switch {
	case byteCapped:
		meta.TruncationReason = TruncationReasonByteCap
		meta.RetryHint = "output hit the byte cap; request a smaller range"
	case limitTrunc:
		meta.TruncationReason = TruncationReasonLimit
		if nextOffset > 0 {
			meta.RetryHint = "more lines remain; retry read from next_offset"
		} else {
			meta.RetryHint = "results truncated by limit; narrow the query"
		}
	}
	if nextOffset > 0 {
		meta.NextOffset = nextOffset
	}

	payload, err := json.Marshal(meta)
	if err != nil {
		// Marshal of this fixed struct cannot fail; fall back to the minimal indicator so a success
		// result still carries an honest truncation field rather than an empty stderr.
		payload = []byte(`{"truncated":true}`)
	}
	stderr := make([]byte, 0, len(MetadataPrefix)+len(payload)+1)
	stderr = append(stderr, MetadataPrefix...)
	stderr = append(stderr, payload...)
	stderr = append(stderr, '\n') // newline matches the in-band failResult convention; rendering trims it.

	return tools.Result{ExitCode: 0, Stdout: stdout, Stderr: stderr}
}
