package events

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"

	"codemeld.dev/codemeld/internal/sessions"
)

type SkillLoaded struct {
	Name              string `json:"name"`
	Layer             string `json:"layer"`
	Via               string `json:"via"`
	File              string `json:"file"`
	Bytes             int64  `json:"bytes"`
	SHA256            string `json:"sha256"`
	ChildInvocationID string `json:"child_invocation_id,omitempty"`
}

var skillNameRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func (SkillLoaded) Kind() string { return KindSkillLoaded }
func (p SkillLoaded) validate() error {
	const k = KindSkillLoaded
	if len(p.Name) > 64 || !skillNameRE.MatchString(p.Name) {
		return fmt.Errorf("%s.name: %q is not a valid skill name", k, p.Name)
	}
	if err := enum(k, "layer", p.Layer, set("global", "project")); err != nil {
		return err
	}
	if err := enum(k, "via", p.Via, set("tool", "slash")); err != nil {
		return err
	}
	if p.File != "" && (p.File == "." || path.Clean(p.File) != p.File || !filepath.IsLocal(p.File)) {
		return fmt.Errorf("%s.file: %q is not a clean relative path inside the skill folder", k, p.File)
	}
	if err := nonNegative(k, "bytes", p.Bytes); err != nil {
		return err
	}
	if !argumentHashRE.MatchString(p.SHA256) {
		return fmt.Errorf("%s.sha256: %q is not a lowercase 64-char SHA-256 hex digest", k, p.SHA256)
	}
	if err := optionalV7(k, "child_invocation_id", p.ChildInvocationID); err != nil {
		return err
	}
	if p.Via == "slash" && (p.File != "" || p.ChildInvocationID != "") {
		return fmt.Errorf("%s: a slash load carries no file or child_invocation_id", k)
	}
	return nil
}

func AppendSkillLoaded(store *sessions.Store, p SkillLoaded) error {
	_, err := Append(store, p)
	return err
}
