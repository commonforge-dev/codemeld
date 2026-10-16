// Package tools defines the structured-tool registry, the Tool interface, and the shared
// tool-dispatch Result type.
package tools

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"
)

// Result is the shared dispatch/tool result returned by every Tool.Invoke. The direct and
// structured dispatchers and the vcs_<action> tool return Result after
// adapting any lower-level runner result; it is mapped onto the tool_exec_* events after
// stdout/stderr truncation.
type Result struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
	Duration time.Duration

	DisplayPatch string

	// ModelContextImage is the data URI a tool produces from the bytes it already captured for
	// this result, so the model context and the reported result cannot describe two different
	// reads of the same path. Empty for every tool that produces no image.
	ModelContextImage string
}

// Metadata is the advertising metadata and read-only classification a Tool exposes.
// Description is a one-line natural-language summary of what the tool does and when to use it.
// Parameters is a JSON-Schema object in the OpenAI function-tool shape describing the tool's
// arguments; it stays a provider-agnostic map so the advertised-tool assembly can translate
// it onto provider.Request without this package importing the provider. ReadOnly is the single
// read-only-vs-mutating classification that drives both Plan's advertised-tool filter and
// the mutating/edit posture; its zero value (false = mutating) is the safe default for
// sources that are not product-verified read-only code. Noncredential is the product's
// classification of the operation, not of its target: an ordinary file read stays noncredential
// for a credential-named path. Its zero value is credential-handling, so a tool that does not
// advertise the classification cannot join an authorization batch.
type Metadata struct {
	Description   string
	Parameters    map[string]any
	ReadOnly      bool
	Noncredential bool
}

// Tool is a structured tool dispatched by exact name.
type Tool interface {
	// Name is the exact dispatch name; the registry indexes tools by it.
	Name() string
	// Invoke runs the tool with decoded arguments and returns its dispatch result.
	Invoke(ctx context.Context, args map[string]any) (Result, error)
	// SubjectKind returns the permission subject kind for this tool; always "tool".
	SubjectKind() string
	// Advertise returns the tool's advertising metadata and read-only classification.
	Advertise() Metadata
}

// BuiltinSource is the stable source token built-in tools register under. Built-ins have no
// file path, so this token stands in for a <path> in the duplicate-name error line when a
// built-in/built-in collision occurs (a programmer error).
const BuiltinSource = "built-in"

// DuplicateNameError reports two tools registered under the same name from the same source —
// a programmer error. Its Error is the exact stderr line, with sources in
// first-seen-then-duplicate order so the rendered bytes are deterministic.
type DuplicateNameError struct {
	Name    string
	SourceA string
	SourceB string
}

func (e *DuplicateNameError) Error() string {
	return fmt.Sprintf("codemeld: tool registry: duplicate name %s from sources %s and %s",
		e.Name, e.SourceA, e.SourceB)
}

// entry pairs a registered tool with the source it came from, used to distinguish a
// cross-source replacement (warn) from a same-source duplicate (hard error).
type entry struct {
	tool   Tool
	source string
}

// Registry is a flat, exact-name map of tools. It performs no regex or
// shell-equivalence matching; Lookup is exact-name only.
type Registry struct {
	byName  map[string]entry
	warnOut io.Writer
}

// NewRegistry returns an empty registry that writes same-name replacement warnings to os.Stderr.
func NewRegistry() *Registry {
	return &Registry{byName: map[string]entry{}, warnOut: os.Stderr}
}

// Register adds t under its Name() from the given source. Load order is built-ins then
// per-project. A same-name registration from a *different* source replaces the prior
// tool, keeps the later registration in effect, and emits a single stderr warning naming the
// replaced tool and the winning source's path. A same-name registration from the *same* source
// is a hard error: it prints the exact duplicate line, returns a *DuplicateNameError
// and leaves the registry unchanged.
func (r *Registry) Register(source string, t Tool) error {
	name := t.Name()
	if prior, exists := r.byName[name]; exists {
		if prior.source == source {
			dup := &DuplicateNameError{Name: name, SourceA: prior.source, SourceB: source}
			_, _ = fmt.Fprintln(r.warnOut, dup.Error())
			return dup
		}
		// name the replaced tool and the winning source; wording kept consistent with
		// the duplicate-error line and the codemeld: prefix convention in internal/fserrors.
		_, _ = fmt.Fprintf(r.warnOut, "codemeld: tool registry: replacing tool %s with definition from %s\n", name, source)
	}
	r.byName[name] = entry{tool: t, source: source}
	return nil
}

// Lookup returns the tool registered under name and whether one exists. Matching is exact-name
// only; there is no pattern or shell-equivalence fallback.
func (r *Registry) Lookup(name string) (Tool, bool) {
	e, ok := r.byName[name]
	return e.tool, ok
}

// List returns every registered tool in a deterministic order (ascending by Name) so the
// advertised-tool assembly can enumerate the active registry without depending on map
// iteration order. A name registered more than once across sources appears once, as the winning
// (last-registered) tool, because a cross-source replacement overwrites the map entry and a
// same-source duplicate is rejected without changing it.
func (r *Registry) List() []Tool {
	out := make([]Tool, 0, len(r.byName))
	for _, e := range r.byName {
		out = append(out, e.tool)
	}
	slices.SortFunc(out, func(a, b Tool) int {
		return strings.Compare(a.Name(), b.Name())
	})
	return out
}
