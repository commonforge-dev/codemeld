// Package builtin embeds codemeld's built-in VCS templates (git, hg, jj) as copy-and-modify reference bytes.
package builtin

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"slices"
)

//go:embed git.yaml hg.yaml jj.yaml
var templates embed.FS

// builtinOrder is the canonical name order; materialization and auto-detect tie-breaking rely on it being stable.
var builtinOrder = []string{"git", "hg", "jj"}

var earlierVersions = map[string][]string{
	"git": {"c8d1660ef5b7407fc8eee3ee2b3932b9fd6e2484112751b74cc060b29635d9ac"},
	"hg":  {"584ca889387964dca3d4cbe7acfec6b454be14b3ce2d7758d27b3ff7657444ed"},
	"jj":  {},
}

func IsEarlierVersion(name string, b []byte) bool {
	sum := sha256.Sum256(b)
	return slices.Contains(earlierVersions[name], hex.EncodeToString(sum[:]))
}

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
