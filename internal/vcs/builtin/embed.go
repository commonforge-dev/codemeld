// Package builtin embeds codemeld's built-in VCS templates (git, hg, jj) as copy-and-modify reference bytes.
package builtin

import (
	"bytes"
	"embed"
	"slices"
)

//go:embed git.yaml hg.yaml jj.yaml
var templates embed.FS

// builtinOrder is the canonical name order; materialization and auto-detect tie-breaking rely on it being stable.
var builtinOrder = []string{"git", "hg", "jj"}

// BuiltinNames returns the built-in VCS template names in canonical order (git, hg, jj)
// as a fresh slice the caller may retain or mutate.
func BuiltinNames() []string {
	return slices.Clone(builtinOrder)
}

// BuiltinTemplate returns a fresh copy of the embedded template bytes for name
// (git, hg, or jj); ok is false for any other name.
func BuiltinTemplate(name string) (data []byte, ok bool) {
	if !slices.Contains(builtinOrder, name) {
		return nil, false
	}
	b, err := templates.ReadFile(name + ".yaml")
	if err != nil {
		return nil, false
	}
	return bytes.Clone(b), true
}
