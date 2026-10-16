// Built-in structured read tool: verbatim, line-paginated read of a regular in-project file with no
// injected line numbers, hidden-path exempt, returning truncation/continuation metadata out-of-band
package filetools

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"codemeld.dev/codemeld/internal/tools"
)

// ReadToolName is the exact dispatch name the structured read tool registers under. Like
// `edit`/`create`/`bash` it is a fixed built-in name carrying no template namespace.
const ReadToolName = "read"

// readDefaultOffset is read's 1-based default start line when the model omits `offset`. It is
// read-specific (not one of the shared limit constants), so it lives here.
const readDefaultOffset = 1

// ReadTool is the built-in read-only read tool. It returns the verbatim contents of a
// regular in-project file, paginated by line with no injected line numbers (the exact-text contract
// shared with edit/create); pagination/truncation metadata is carried in the prefixed-stderr
// channel, never appended to the content. It is read-only (Advertise().ReadOnly == true), so it
// auto-allows without prompting in every mode. Unlike the recursive navigation tools it is
// exempt from hidden filtering — an explicit path is honored even if hidden — because it never
// routes through the hidden-filtering walker. The run-scoped home, process cwd, project root, and the
// configured tool-output byte cap are bound at construction so target resolution matches the permission
// path-scope rules and the truncation indicator survives the same byte cap as every other tool output.
type ReadTool struct {
	home        string
	processCWD  string
	projectRoot string
	outputCap   int
}

var _ tools.Tool = (*ReadTool)(nil)

// NewReadTool builds the read tool bound to the run's ~ anchor (home), the process cwd accepted for
// signature symmetry with the other file tools, the project root the target must stay within
// (via ResolveReadTarget), and the tool-output byte cap (cache.MaxToolOutputBytes()) BoundedResult uses to
// predict byte-cap truncation. The project root is symlink-resolved once here — mirroring
// NewEditTool/NewCreateTool — so a launch through a symlinked project directory does not reject valid
// in-project reads; ResolveReadTarget normalizes again, so the double normalization is idempotent.
func NewReadTool(home, processCWD, projectRoot string, outputCap int) *ReadTool {
	return &ReadTool{home: home, processCWD: processCWD, projectRoot: normalizeRoot(projectRoot), outputCap: outputCap}
}

func (t *ReadTool) Name() string { return ReadToolName }

func (t *ReadTool) SubjectKind() string { return "tool" }

// Advertise returns the read tool's advertising metadata and read-only classification.
// The parameter JSON-Schema is the OpenAI function-tool shape with additionalProperties:false so
// the advertised contract matches the decoder exactly: `path` is the only required argument; `offset`
// and `limit` are optional integers. ReadOnly is true: read never mutates, so it is advertised in Plan
// and auto-allowed in every mode.
func (t *ReadTool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description: "Read the contents of a project file, returned verbatim with no line numbers. " +
			"offset is the 1-based line to start at (default 1); limit caps the lines returned (default " +
			fmt.Sprintf("%d, max %d", ReadDefaultLimit, ReadMaxLimit) + "). When more lines remain, the " +
			"result reports the next offset to request. A binary file returns a short notice instead of " +
			"its bytes. Use to inspect a file's contents.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{
					"type":        "string",
					"description": "Path of the file to read. Relative paths resolve against the project root and read normally; an explicitly named path whose real location is outside the project is read only after you approve it at the permission prompt. An explicit hidden (dot-prefixed) path is honored.",
				},
				"offset": map[string]any{
					"type":        "integer",
					"description": "1-based line to start reading from. Default 1; must be >= 1.",
				},
				"limit": map[string]any{
					"type":        "integer",
					"description": fmt.Sprintf("Maximum number of lines to return. Default %d; must be between 1 and %d.", ReadDefaultLimit, ReadMaxLimit),
				},
			},
			"required":             []string{"path"},
			"additionalProperties": false,
		},
		ReadOnly:      true,
		Noncredential: true,
	}
}

// ResolveTarget resolves the read target from args before authorization and returns the resolved target
// path (placed in the mode-auth context) and the path scope to authorize, mirroring the edit/create
// target-scoped contract so authorization and the path actually read cannot drift. It rejects unknown
// arguments, then delegates to ResolveReadTarget in required-path mode (a missing/empty `path` is
// an in-band rejection) without rejecting directory symlinks (read targets a regular file, which
// is enforced at invocation by ResolveReadFile, not here). The directory/non-regular/missing rejection
// is deferred to InvokeWithResolvedTarget, where the read-tool symlink policy is applied to the
// resolved target immediately before the read.
func (t *ReadTool) ResolveTarget(args map[string]any) (target string, scope string, err error) {
	if verr := rejectUnknownPhase1ReadArgs(ReadToolName, args); verr != nil {
		return "", "", &TargetError{Kind: ReadToolName, Reason: verr.Error()}
	}
	return ResolveReadTarget(t.home, t.processCWD, t.projectRoot, args, ReadTargetOptions{
		RequirePath:   true,
		Kind:          ReadToolName,
		AllowExternal: true,
	})
}

// ExternalReadScope reports whether scope (the path scope ResolveTarget returned) is an explicit
// out-of-project read target — the promptable case DispatchTool routes to a permission prompt while
// bypassing the read-only mode auto-allow. It mirrors the mutating tools' OutOfRootScope but drives the
// read-only external posture, never a write grant. An in-project scope returns false, keeping in-project
// reads on their existing no-prompt auto-allow.
func (t *ReadTool) ExternalReadScope(scope string) bool {
	return isExternalReadScope(scope, t.projectRoot)
}

// InvokeWithResolvedTarget reads the target dispatch already resolved before authorization, so the
// authorized path and the path actually read cannot diverge if a symlink changes in between — the same
// reuse-at-invoke contract edit/create follow. It is the production invocation path; the registered tool
// implements it so DispatchTool reuses the authorized target.
func (t *ReadTool) InvokeWithResolvedTarget(_ context.Context, args map[string]any, resolvedTarget string) (tools.Result, error) {
	return t.read(resolvedTarget, args), nil
}

// Invoke resolves the target and reads it in one call (the standalone, non-dispatch path). Production
// dispatch instead calls ResolveTarget then InvokeWithResolvedTarget; this keeps the tool a complete unit
// for direct callers and tests. A target-resolution failure surfaces as the same in-band error result the
// dispatcher would render, so the observable outcome matches either entry.
// Standalone Invoke has no authorizer, so it must enforce the out-of-project boundary itself: an explicit
// out-of-project read target (ExternalReadScope) is reachable only by per-read approval, which only the
// dispatch path can obtain. This method refuses it in-band rather than reading; the in-project path is
// unchanged. InvokeWithResolvedTarget carries no such guard because dispatch already authorized the read.
func (t *ReadTool) Invoke(_ context.Context, args map[string]any) (tools.Result, error) {
	target, scope, err := t.ResolveTarget(args)
	if err != nil {
		return failResult(err.Error()), nil
	}
	if t.ExternalReadScope(scope) {
		return externalReadDispatchOnly(ReadToolName), nil
	}
	return t.read(target, args), nil
}

func (t *ReadTool) read(resolvedTarget string, args map[string]any) tools.Result {
	if verr := ValidatePhase1ReadArgs(ReadToolName, args); verr != nil {
		return failResult(verr.Error())
	}

	offsetPtr, _ := optionalIntArg(args, "offset")
	limitPtr, _ := optionalIntArg(args, "limit")
	offset := readDefaultOffset
	if offsetPtr != nil {
		offset = *offsetPtr
	}
	limit := ReadDefaultLimit
	if limitPtr != nil {
		limit = *limitPtr
	}

	// Apply read's follow-to-regular-file symlink policy and reject a missing path, a directory
	// or a non-regular file in-band — all surfaced as ResolveReadFile reasons. The containment
	// boundary is the project root for an in-project read, or the approved external file's own enclosing
	// directory for an authorized out-of-project read — so a post-authorization symlink swap that
	// redirected the file elsewhere is still caught against the scope the prompt approved, without the
	// project-root check rejecting the legitimately external file.
	boundary := t.projectRoot
	if t.ExternalReadScope(resolvedTarget) {
		boundary = filepath.Dir(resolvedTarget)
	}
	real, ok, reason := ResolveReadFile(resolvedTarget, boundary)
	if !ok {
		return failResult(reason)
	}
	content, rerr := os.ReadFile(real)
	if rerr != nil {
		return failResult("cannot read the target file: " + rerr.Error())
	}

	// classify the file as binary before any of its bytes reach stdout, so raw binary content is
	// never emitted — only the short notice is.
	if isBinaryContent(content) {
		notice := fmt.Sprintf("binary file, %d bytes — not shown", len(content))
		return BoundedResult([]byte(notice), false, 0, t.outputCap)
	}

	segment, nextOffset := paginateLines(content, offset, limit)
	return BoundedResult(segment, nextOffset > 0, nextOffset, t.outputCap)
}

// paginateLines returns the verbatim byte slice of content covering the limit lines starting at the
// 1-based offset, plus the 1-based next offset to request when more lines remain (0 otherwise). offset
// and limit are pre-validated (offset >= 1, limit >= 1), so the window is well-formed. The slice is a
// byte-for-byte sub-slice of content — line boundaries are cut at '\n' positions and no line numbers or
// separators are injected — so offset 1 with a limit covering the whole file returns content unchanged.
// A trailing newline does not create a phantom final empty line, and an offset past the last
// line yields an empty slice with no continuation.
func paginateLines(content []byte, offset, limit int) (segment []byte, nextOffset int) {
	starts := lineStartOffsets(content)
	total := len(starts)
	startLine := offset - 1 // 0-based index of the first line to include
	if startLine >= total {
		return content[len(content):], 0 // nothing at or past this offset; empty, no continuation
	}
	endLine := startLine + limit // 0-based exclusive index one past the last included line
	if endLine > total {
		endLine = total
	}
	startByte := starts[startLine]
	endByte := len(content)
	if endLine < total {
		endByte = starts[endLine]
		nextOffset = endLine + 1 // 1-based line after the last one returned
	}
	return content[startByte:endByte], nextOffset
}

// lineStartOffsets returns the byte offset at which each line of content begins. Line 1 begins at byte 0;
// every byte immediately after a '\n' that is not the final byte begins a new line. A trailing '\n' (the
// final byte) therefore does not start a phantom empty line, so "a\nb\n" is two lines, not three. An empty
// file has zero lines. The returned length is the file's line count.
func lineStartOffsets(content []byte) []int {
	if len(content) == 0 {
		return nil
	}
	starts := []int{0}
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' && i+1 < len(content) {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// isBinaryContent reports whether content should be treated as binary and summarized rather than emitted
// verbatim. The heuristic is the presence of a NUL byte anywhere in the file — the same
// well-understood signal git and grep use to distinguish binary from text. It is deterministic and never
// reads or returns the raw bytes for a positive match. A NUL-free file (including valid UTF-8 and legacy
// single-byte text encodings) is treated as text and returned verbatim; the model-facing byte path coerces
// any invalid UTF-8 to U+FFFD downstream, so non-NUL text never surfaces as raw uncoerced bytes.
func isBinaryContent(content []byte) bool {
	return bytes.IndexByte(content, 0) >= 0
}

// optionalIntArg pulls an optional integer argument out of the decoded tool arguments, returning nil when
// the key is absent (so the caller applies its default) and an error for a present-but-non-integer value
// so a malformed numeric argument surfaces in-band rather than being silently coerced. JSON
// numbers decode to float64, so a whole-valued float is accepted and a fractional one is rejected; a
// plain int (from a direct in-process caller or test) is accepted as-is. The numeric *range* is left to
// ValidateNumericArgs — this helper only enforces integrality.
func optionalIntArg(args map[string]any, key string) (*int, error) {
	raw, ok := args[key]
	if !ok {
		return nil, nil
	}
	switch v := raw.(type) {
	case float64:
		if v != math.Trunc(v) {
			return nil, fmt.Errorf("argument %q must be an integer, got %v", key, v)
		}
		n := int(v)
		return &n, nil
	case int:
		n := v
		return &n, nil
	default:
		return nil, fmt.Errorf("argument %q must be an integer", key)
	}
}
