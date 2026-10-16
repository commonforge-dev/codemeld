// Tests for the tool registry: exact-name lookup, cross-source replacement warning,
// and same-source duplicate error.
package tools

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
)

// fakeTool is a minimal Tool for registry tests; Invoke is unused here (the dispatch tests exercise it).
// id gives a fixture identity independent of name so a replacement can be distinguished from the
// tool it replaced; meta lets a listing test assert advertising metadata is carried through.
type fakeTool struct {
	name string
	id   string
	meta Metadata
}

func (f fakeTool) Name() string { return f.name }
func (f fakeTool) Invoke(context.Context, map[string]any) (Result, error) {
	return Result{}, nil
}
func (f fakeTool) SubjectKind() string { return "tool" }
func (f fakeTool) Advertise() Metadata { return f.meta }

func newTestRegistry() (*Registry, *bytes.Buffer) {
	r := NewRegistry()
	var buf bytes.Buffer
	r.warnOut = &buf
	return r, &buf
}

func TestLookupExactNameOnly(t *testing.T) {
	r, _ := newTestRegistry()
	tool := fakeTool{name: "read_file"}
	if err := r.Register(BuiltinSource, tool); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, ok := r.Lookup("read_file")
	if !ok || got.Name() != "read_file" {
		t.Fatalf("Lookup(read_file) = %v, %v; want the registered tool", got, ok)
	}

	// No regex / prefix / shell-equivalence matching: only the exact name resolves.
	for _, miss := range []string{"read_fil", "read_file ", "read_.*", "read_file2", "READ_FILE"} {
		if _, ok := r.Lookup(miss); ok {
			t.Fatalf("Lookup(%q) matched; registry must be exact-name only", miss)
		}
	}
}

func TestCrossSourceReplacementWarns(t *testing.T) {
	r, buf := newTestRegistry()
	if err := r.Register(BuiltinSource, fakeTool{name: "bash", id: "builtin"}); err != nil {
		t.Fatalf("Register built-in: %v", err)
	}
	if err := r.Register("/proj/.codemeld/tools", fakeTool{name: "bash", id: "project"}); err != nil {
		t.Fatalf("cross-source replacement must not error: %v", err)
	}

	want := "codemeld: tool registry: replacing tool bash with definition from /proj/.codemeld/tools\n"
	if buf.String() != want {
		t.Fatalf("warning = %q, want %q", buf.String(), want)
	}

	// The later registration wins: the looked-up tool must carry the replacement's
	// identity, not the built-in it replaced.
	got, ok := r.Lookup("bash")
	if !ok {
		t.Fatal("bash missing after replacement")
	}
	if got.(fakeTool).id != "project" {
		t.Fatalf("unexpected tool after replacement: %+v, want id=project", got)
	}
}

func TestSameSourceDuplicateErrorsWithExactLine(t *testing.T) {
	r, buf := newTestRegistry()
	if err := r.Register(BuiltinSource, fakeTool{name: "read_file"}); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	err := r.Register(BuiltinSource, fakeTool{name: "read_file"})
	if err == nil {
		t.Fatal("same-source duplicate must return an error")
	}
	var dup *DuplicateNameError
	if !errors.As(err, &dup) {
		t.Fatalf("error type = %T, want *DuplicateNameError", err)
	}

	want := "codemeld: tool registry: duplicate name read_file from sources built-in and built-in"
	if err.Error() != want {
		t.Fatalf("error line = %q, want %q", err.Error(), want)
	}
	if buf.String() != want+"\n" {
		t.Fatalf("stderr = %q, want %q", buf.String(), want+"\n")
	}
}

// TestListDeterministicOrderAndReplacementAppearsOnce pins the deterministic registry snapshot advertising
// enumerates: List returns tools ascending by name regardless of registration order, a cross-source
// replacement appears once as the winning tool, and advertising metadata is carried through.
func TestListDeterministicOrderAndReplacementAppearsOnce(t *testing.T) {
	r, _ := newTestRegistry()
	// Register out of sorted order so a stable List cannot be an accident of insertion order.
	if err := r.Register(BuiltinSource, fakeTool{name: "write_file", id: "builtin"}); err != nil {
		t.Fatalf("Register write_file: %v", err)
	}
	if err := r.Register(BuiltinSource, fakeTool{name: "read_file", id: "builtin", meta: Metadata{Description: "reads a file", ReadOnly: true}}); err != nil {
		t.Fatalf("Register read_file: %v", err)
	}
	if err := r.Register(BuiltinSource, fakeTool{name: "apply", id: "builtin"}); err != nil {
		t.Fatalf("Register apply: %v", err)
	}
	// Cross-source replacement: the project definition wins and must appear once in the listing.
	if err := r.Register("/proj/.codemeld/tools", fakeTool{name: "write_file", id: "project"}); err != nil {
		t.Fatalf("replace write_file: %v", err)
	}

	got := r.List()
	var names []string
	for _, tool := range got {
		names = append(names, tool.Name())
	}
	if want := []string{"apply", "read_file", "write_file"}; !slices.Equal(names, want) {
		t.Fatalf("List names = %v, want %v (ascending by name, each name once)", names, want)
	}

	idx := slices.Index(names, "write_file")
	if got[idx].(fakeTool).id != "project" {
		t.Fatalf("write_file in list = %+v, want the winning project tool", got[idx])
	}

	ri := slices.Index(names, "read_file")
	if md := got[ri].Advertise(); md.Description != "reads a file" || !md.ReadOnly {
		t.Fatalf("read_file Advertise() = %+v, want description carried and read-only", md)
	}
}

// A same-source duplicate carrying real paths renders both source paths in first-seen-then-
// duplicate order, so the line is deterministic for per-project tool sources too.
func TestSameSourceDuplicateRendersPaths(t *testing.T) {
	r, _ := newTestRegistry()
	const src = "/proj/.codemeld/tools"
	if err := r.Register(src, fakeTool{name: "fmt"}); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	err := r.Register(src, fakeTool{name: "fmt"})
	want := "codemeld: tool registry: duplicate name fmt from sources " + src + " and " + src
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func TestCredentialClassificationComesFromAdvertisedMetadata(t *testing.T) {
	r, _ := newTestRegistry()
	if err := r.Register(BuiltinSource, fakeTool{name: "read", id: "builtin", meta: Metadata{ReadOnly: true, Noncredential: true}}); err != nil {
		t.Fatalf("Register built-in: %v", err)
	}
	if err := r.Register(BuiltinSource, fakeTool{name: "unclassified", meta: Metadata{ReadOnly: true}}); err != nil {
		t.Fatalf("Register unclassified: %v", err)
	}
	if tool, _ := r.Lookup("unclassified"); tool.Advertise().Noncredential {
		t.Fatalf("a read-only tool advertising no classification reported noncredential; an unclassified operation must stay credential-handling")
	}

	// The registry keeps no classification of its own, so a replacement under a classified
	// name is only noncredential if it advertises that itself.
	if err := r.Register("/project/tools/read.yaml", fakeTool{name: "read", id: "project", meta: Metadata{ReadOnly: true}}); err != nil {
		t.Fatalf("Register replacement: %v", err)
	}
	tool, ok := r.Lookup("read")
	if !ok {
		t.Fatal("Lookup(read) found no tool after the replacement")
	}
	if tool.Advertise().Noncredential {
		t.Fatalf("a replacing tool inherited the built-in's credential classification")
	}
}
