// Classification of the run's protected settings files and blocked paths, and the typed refusal a
// covered structured-tool call produces before it is authorized.
package securitystate

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/paths"
	"codemeld.dev/codemeld/internal/permissions"
)

const lockSuffix = ".lock"

const subjectKindTool = "tool"

const (
	sourceProtectedState = "protected_state"
	sourceBlockedPath    = "blocked_path"
)

type Policy struct {
	// Entries must be absolute: a relative entry matches no endpoint and protects nothing.
	SettingsPaths []string
	Blocked       *permissions.BlockedPaths
}

type Refusal struct {
	SubjectKind          string
	Subject              string
	PathScope            string
	Envelope             string
	Source               string
	Entry                string
	EntrySource          string
	ArgumentHash         string
	DirectRequestSubject string
}

func (r *Refusal) Error() string {
	if r.Source == sourceBlockedPath {
		return "blocked_path: " + r.Subject + " may not use a blocked path"
	}
	return "protected_state: " + r.Subject + " may not modify codemeld settings state"
}

var guardedTools = map[string]bool{
	filetools.EditToolName:   true,
	filetools.CreateToolName: true,
	filetools.DeleteToolName: true,
	filetools.MkdirToolName:  true,
	filetools.MoveToolName:   true,
}

var walkTools = map[string]bool{
	filetools.GrepToolName:      true,
	filetools.GlobToolName:      true,
	filetools.ListToolName:      true,
	filetools.TreeToolName:      true,
	filetools.FileCountToolName: true,
}

var blockedTools = map[string]bool{
	filetools.ReadToolName:      true,
	filetools.ReadImageToolName: true,
	filetools.GrepToolName:      true,
	filetools.GlobToolName:      true,
	filetools.ListToolName:      true,
	filetools.TreeToolName:      true,
	filetools.FileCountToolName: true,
	filetools.EditToolName:      true,
	filetools.CreateToolName:    true,
	filetools.DeleteToolName:    true,
	filetools.MkdirToolName:     true,
	filetools.MoveToolName:      true,
}

// RefuseNominal classifies a covered call's raw endpoint arguments, so a target an
// operation-specific resolver would reject is still refused as protected state.
func (p Policy) RefuseNominal(tool string, args map[string]any, home, baseDir string) *Refusal {
	if guardedTools[tool] {
		for _, raw := range endpointArgs(tool, args) {
			if raw == "" {
				continue
			}
			endpoint := nominalEndpoint(home, baseDir, raw)
			if endpoint != "" && p.protects(tool, endpoint) {
				return newRefusal(tool, endpoint)
			}
		}
	}
	if !blockedTools[tool] {
		return nil
	}
	for _, raw := range endpointArgs(tool, args) {
		// A relative endpoint is left to the resolved check, because read tools resolve it against the
		// project root rather than baseDir.
		if raw == "" || (raw[0] != '~' && !filepath.IsAbs(raw)) {
			continue
		}
		endpoint := nominalEndpoint(home, baseDir, raw)
		if endpoint == "" {
			continue
		}
		if entry, ok := p.Blocked.Blocking(endpoint); ok {
			return p.blockedRefusal(tool, endpoint, entry)
		}
	}
	return nil
}

func (p Policy) RefuseShell(subjectKind, subject, folder string, candidates []string) *Refusal {
	for _, target := range append([]string{folder}, candidates...) {
		entry, ok := p.Blocked.Blocking(target)
		if !ok {
			continue
		}
		home, fold := p.Blocked.Home(), p.Blocked.FoldCase()
		return &Refusal{
			SubjectKind: subjectKind,
			Subject:     subject,
			PathScope:   folder,
			Envelope:    permissions.BuildBlockedPathDenyEnvelope(underHome(home, target, fold), underHome(home, entry.Path, fold), entry.Floor()),
			Source:      sourceBlockedPath,
			Entry:       entry.Path,
			EntrySource: entry.Source,
		}
	}
	return nil
}

func (p Policy) Guards() bool { return len(p.SettingsPaths) > 0 }

func (p Policy) RefuseVCS(tool, cwd string, risky bool) *Refusal {
	if !risky || !p.Guards() {
		return nil
	}
	return &Refusal{
		SubjectKind: subjectKindTool,
		Subject:     tool,
		PathScope:   cwd,
		Envelope:    permissions.BuildGuardDenyEnvelope(),
		Source:      sourceProtectedState,
	}
}

func (p Policy) RefuseBlockedVCS(tool, cwd string, risky func(protectedIn func(root string) ([]string, error)) bool) *Refusal {
	var (
		lookedUp   bool
		lookupRoot string
		found      []permissions.RepositoryEntry
		lookupErr  error
	)
	for _, entry := range p.Blocked.Entries() {
		consulted := false
		protectedIn := func(root string) ([]string, error) {
			if !lookedUp || root != lookupRoot {
				found, lookupErr = p.Blocked.InRepository(root)
				lookedUp, lookupRoot = true, root
			}
			if err := lookupErr; err != nil {
				consulted = true
				return nil, err
			}
			for _, f := range found {
				if f.Entry == entry {
					consulted = true
					return f.Candidates, nil
				}
			}
			return nil, nil
		}
		if !risky(protectedIn) || !consulted {
			continue
		}
		home, fold := p.Blocked.Home(), p.Blocked.FoldCase()
		return &Refusal{
			SubjectKind: subjectKindTool,
			Subject:     tool,
			PathScope:   cwd,
			Envelope:    permissions.BuildBlockedPathDenyEnvelope(underHome(home, cwd, fold), underHome(home, entry.Path, fold), entry.Floor()),
			Source:      sourceBlockedPath,
			Entry:       entry.Path,
			EntrySource: entry.Source,
		}
	}
	return nil
}

// ProtectedIn returns every protected identity inside root, hardlink aliases included. A protected
// file that does not exist cannot be aliased and is skipped; any other stat or directory-read
// failure is returned, so a caller that cannot enumerate the whole set refuses rather than acting on
// a partial one.
func (p Policy) ProtectedIn(root string) ([]string, error) {
	if !p.Guards() || root == "" {
		return nil, nil
	}
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	var inside []string
	var targets []os.FileInfo
	for _, identity := range p.protectedIdentities() {
		if permissions.IsDescendantOrEqual(identity, root) {
			inside = appendUnique(inside, identity)
		}
		info, err := os.Lstat(identity)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return nil, err
		case info.Mode().IsRegular():
			targets = append(targets, info)
		}
	}
	if len(targets) == 0 {
		return inside, nil
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		for _, target := range targets {
			if os.SameFile(info, target) {
				inside = appendUnique(inside, filepath.Clean(path))
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return inside, nil
}

func (p Policy) RefuseResolved(tool string, endpoints ...string) *Refusal {
	if guardedTools[tool] {
		for _, endpoint := range endpoints {
			if endpoint == "" {
				continue
			}
			clean := filepath.Clean(endpoint)
			if p.protects(tool, clean) {
				return newRefusal(tool, clean)
			}
		}
	}
	if !blockedTools[tool] {
		return nil
	}
	containing := tool == filetools.DeleteToolName || tool == filetools.MoveToolName
	for _, endpoint := range endpoints {
		if endpoint == "" {
			continue
		}
		clean := filepath.Clean(endpoint)
		if entry, ok := p.Blocked.Blocking(clean); ok {
			return p.blockedRefusal(tool, clean, entry)
		}
		if !containing {
			continue
		}
		if entry, ok := p.Blocked.BlockedWithin(clean); ok {
			return p.blockedRefusal(tool, clean, entry)
		}
	}
	return nil
}

// protects widens to ancestor containment for move only: a move relocates whole subtrees, so an
// endpoint naming a directory that holds protected state carries it away, while the single-target
// operations act on the named entry alone.
func (p Policy) protects(tool, endpoint string) bool {
	containing := tool == filetools.MoveToolName
	candidates := pathForms(endpoint)
	for _, protected := range p.protectedIdentities() {
		for _, candidate := range candidates {
			if candidate == protected {
				return true
			}
			if containing && permissions.IsDescendantOrEqual(protected, candidate) {
				return true
			}
		}
	}
	return false
}

func (p Policy) protectedIdentities() []string {
	var identities []string
	for _, configured := range p.SettingsPaths {
		clean := filepath.Clean(configured)
		identities = append(identities, pathForms(clean)...)
		identities = append(identities, pathForms(clean+lockSuffix)...)
	}
	return identities
}

// pathForms returns the identities path can be named by. The middle form resolves the parent while
// keeping the final component literal, so a settings file reached through a symlinked directory and
// a symlink that itself names a settings file are both classified.
func pathForms(path string) []string {
	forms := []string{path}
	if parent, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		forms = appendUnique(forms, filepath.Join(parent, filepath.Base(path)))
	}
	if real, err := filepath.EvalSymlinks(path); err == nil {
		forms = appendUnique(forms, real)
	}
	return forms
}

func appendUnique(forms []string, form string) []string {
	for _, existing := range forms {
		if existing == form {
			return forms
		}
	}
	return append(forms, form)
}

func nominalEndpoint(home, baseDir, raw string) string {
	expanded, err := paths.Expand(home, raw)
	if err != nil {
		return ""
	}
	if !filepath.IsAbs(expanded) {
		expanded = filepath.Join(baseDir, expanded)
	}
	clean := filepath.Clean(expanded)
	parent, err := permissions.CleanAbsResolve(home, baseDir, filepath.Dir(clean))
	if err != nil {
		return clean
	}
	return filepath.Join(parent, filepath.Base(clean))
}

func endpointArgs(tool string, args map[string]any) []string {
	if tool == filetools.MoveToolName {
		return []string{stringArg(args, "source"), stringArg(args, "destination")}
	}
	return []string{stringArg(args, "path")}
}

func stringArg(args map[string]any, key string) string {
	s, _ := args[key].(string)
	return s
}

func newRefusal(tool, endpoint string) *Refusal {
	return &Refusal{
		SubjectKind: subjectKindTool,
		Subject:     tool,
		PathScope:   filepath.Dir(endpoint),
		Envelope:    permissions.BuildGuardDenyEnvelope(),
		Source:      sourceProtectedState,
	}
}

func (p Policy) blockedRefusal(tool, endpoint string, entry permissions.BlockedEntry) *Refusal {
	scope := filepath.Dir(endpoint)
	if walkTools[tool] {
		scope = endpoint
	}
	home, fold := p.Blocked.Home(), p.Blocked.FoldCase()
	return &Refusal{
		SubjectKind: subjectKindTool,
		Subject:     tool,
		PathScope:   scope,
		Envelope:    permissions.BuildBlockedPathDenyEnvelope(underHome(home, endpoint, fold), underHome(home, entry.Path, fold), entry.Floor()),
		Source:      sourceBlockedPath,
		Entry:       entry.Path,
		EntrySource: entry.Source,
	}
}

func underHome(home, path string, foldCase bool) string {
	if home == "" {
		return path
	}
	rel, ok := permissions.RelWithin(home, path, foldCase)
	if !ok {
		return path
	}
	return strings.TrimSuffix("~/"+rel, "/")
}
