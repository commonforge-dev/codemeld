// Production VCS detection-to-registry wiring for bootstrap steps 4-6:
// load templates, cross-reference-validate vcs.preferred, and run
// detection into the *ActiveVCS handoff the tool-registry factory (step 6c) consumes.
package bootstrap

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/vcs"
	"codemeld.dev/codemeld/internal/vcs/builtin"
)

// vcsLoaded is the production step-4 payload LoadVCSTemplates hands to ValidatePreferredVCS (step 5)
// and DetectVCS (step 6). The generic step seams carry only (composed, templates), so the
// bootstrap-local context the later steps need rides here: the merged template map (built-in base
// overlaid by the global then per-project directories), the pristine built-in detect
// markers used by the preferred walk regardless of any built-in-name override,
// the home and project roots used for source attribution and the detection walk, and step 3's
// verified project settings layer, so attribution reuses the launch's one admitted read.
type vcsLoaded struct {
	templates     map[string]*vcs.Template
	builtinDetect map[string]string
	trustedClass  map[*vcs.Template]bool
	home          string
	projectRoot   string
	projectLayer  map[string]any
}

// loadVCSTemplates is the production step-4 LoadVCSTemplates (step 4). It starts from
// the embedded built-in templates as the base map so the built-ins are present even when their
// first-run reference copies are absent (set (a)), then overlays the global
// ~/.codemeld/global/vcs/*.yaml and per-project <project-root>/.codemeld/vcs/*.yaml directories with
// the project layer winning on same-name overrides. The pristine built-in detect markers are
// captured before the overlay so a built-in-name override that omits detect cannot blank them.
// A template-validation failure is returned to abort the launch
// before the TUI starts.
//
// A project template supplies the argv a vcs_<action> tool executes, so the project folder is
// read only on a run approved is true for. An unapproved launch never opens the folder, so a
// malformed project template cannot stop it either.
func loadVCSTemplates(home, projectRoot string, projectLayer map[string]any, approved bool) (any, error) {
	base, err := vcs.LoadBuiltinTemplates()
	if err != nil {
		return nil, err
	}
	builtinDetect := make(map[string]string, len(base))
	for name, tmpl := range base {
		if tmpl.Detect != nil {
			builtinDetect[name] = tmpl.Detect.Marker
		}
	}
	trustedClass := map[*vcs.Template]bool{}
	// Overlay global first, then project, so a later layer overrides an earlier same-name template
	// and the project layer wins overall.
	if err := overlayGlobalTemplates(base, VCSTemplateDir(home), trustedClass); err != nil {
		return nil, err
	}
	if approved {
		if err := overlayProjectTemplates(base, projectRoot, trustedClass); err != nil {
			return nil, err
		}
	}
	return &vcsLoaded{templates: base, builtinDetect: builtinDetect, trustedClass: trustedClass, home: home, projectRoot: projectRoot, projectLayer: projectLayer}, nil
}

// overlayGlobalTemplates loads dir's templates (a missing dir contributes none) and copies them
// into base, replacing any same-name entry. The loaded template pointers are recorded as trusted
// for explicit action class declarations; the project overlay uses different pointers and does
// not inherit that trust.
func overlayGlobalTemplates(base map[string]*vcs.Template, dir string, trustedClass map[*vcs.Template]bool) error {
	loaded, err := vcs.LoadTemplates(dir)
	if err != nil {
		return err
	}
	for name, tmpl := range loaded {
		base[name] = tmpl
		trustedClass[tmpl] = true
	}
	return nil
}

// collectVCSCandidates is a package-local seam so a test can stage a write between the
// collection and the parse without calling the collector itself.
var collectVCSCandidates = fsutil.CollectVCSCandidates

// overlayProjectTemplates reads the project folder through the bounded, no-follow collector
// rather than vcs.LoadTemplates, which follows symlinks and enumerates without a limit, and
// parses the bytes that collection returned instead of reopening each path, so a writer that
// replaces a template between collection and parsing cannot substitute argv.
func overlayProjectTemplates(base map[string]*vcs.Template, projectRoot string, trustedClass map[*vcs.Template]bool) error {
	dir := projectVCSTemplateDir(projectRoot)
	candidates, _, failure := collectVCSCandidates(dir)
	if failure != fsutil.VCSFailureNone {
		return fmt.Errorf("vcs: cannot read project template folder %s: %s", dir, failure)
	}
	files := make([]vcs.TemplateFile, 0, len(candidates))
	for _, candidate := range candidates {
		files = append(files, vcs.TemplateFile{Path: filepath.Join(dir, candidate.Name), Bytes: candidate.Bytes})
	}
	loaded, err := vcs.LoadTemplateFiles(files)
	if err != nil {
		return err
	}
	for name, tmpl := range loaded {
		base[name] = tmpl
		trustedClass[tmpl] = false
	}
	return nil
}

// validatePreferredVCS is the production step-5 ValidatePreferredVCS (step 5). It
// resolves the effective vcs.preferred value and the settings file that set it, then cross-reference-
// validates the value against the union of the built-in names and the loaded user template names. An
// unset/empty value disables the override and validates trivially. A rejection names the
// exact source file so the CLI renders it the way it renders schema-validation failures and exits
// before the TUI.
func validatePreferredVCS(composed map[string]any, templates any) error {
	payload, ok := templates.(*vcsLoaded)
	if !ok || payload == nil {
		return nil
	}
	preferred, source := preferredOverride(composed, payload)
	if preferred == "" {
		return nil
	}
	return vcs.ValidatePreferred(preferred, builtin.BuiltinNames(), userTemplateNames(payload), source)
}

// detectVCS is the production step-6 DetectVCS (step 6). With an effective
// vcs.preferred it runs the hard-override walk, skipping vcs.priority tie-breaking and
// returning an error when the named VCS is found nowhere rather than falling back to auto-detect.
// Otherwise it auto-detects, tie-breaks same-depth matches by vcs.priority, and
// warns on ambiguity. It returns the *ActiveVCS handoff the tool-registry factory consumes — the
// selected template plus its repo root — or a literal nil when no detector matched, which the
// factory degrades to a registry with no vcs_<action> tools (step 6c). Detection warnings
// (skipped unreadable directories, ambiguity) print to stderr only; no session event is written,
// matching the bootstrap order's pre-session-start failure rule on both launch paths.
func detectVCS(cwd string, composed map[string]any, templates any, stderr io.Writer) (any, error) {
	payload, ok := templates.(*vcsLoaded)
	if !ok || payload == nil {
		return nil, nil
	}
	boundary := discoveryBoundary(composed)

	if preferred, source := preferredOverride(composed, payload); preferred != "" {
		repoRoot, err := vcs.RunPreferred(preferred, cwd, boundary, payload.projectRoot, source, payload.builtinDetect, payload.templates)
		if err != nil {
			return nil, vcsDetectError(err)
		}
		tmpl := payload.templates[preferred]
		return &ActiveVCS{Template: tmpl, RepoRoot: repoRoot, TrustedExplicitClasses: payload.trustedClass[tmpl]}, nil
	}

	matches, depth, warnings, err := vcs.AutoDetect(cwd, boundary, payload.projectRoot, payload.templates)
	for _, w := range warnings {
		_, _ = fmt.Fprintln(stderr, w)
	}
	if err != nil {
		return nil, vcsDetectError(err)
	}
	if len(matches) == 0 {
		return nil, nil
	}
	winner := vcs.TieBreak(matches, vcsPriority(composed), builtinNameSet())
	if w := vcs.AmbiguityWarning(matches, winner, false); w != "" {
		_, _ = fmt.Fprintln(stderr, w)
	}
	tmpl := payload.templates[winner]
	return &ActiveVCS{Template: tmpl, RepoRoot: ancestorAt(cwd, depth), TrustedExplicitClasses: payload.trustedClass[tmpl]}, nil
}

// preferredOverride resolves the effective vcs.preferred value and the settings file that supplied
// it (layering: the per-project layer wins over the global layer). The step seam delivers
// only the composed config, which holds the effective value but no per-layer source metadata, so the
// source is recovered by checking whether the per-project settings.yaml declares the key — the
// smallest bootstrap-local tracking that keeps errors naming the exact file. An empty
// effective value means no override is in effect.
func preferredOverride(composed map[string]any, payload *vcsLoaded) (value, source string) {
	value = nestedString(composed, "vcs", "preferred")
	if value == "" {
		return "", ""
	}
	if projectLayerSetsPreferred(payload.projectLayer) {
		return value, projectSettingsPath(payload.projectRoot)
	}
	return value, SettingsPath(payload.home)
}

// projectLayerSetsPreferred reports whether the per-project settings.yaml declares vcs.preferred,
// which decides whether the effective override is attributed to the project file or the global file.
// project is step 3's verified layer: reopening the file here would let settings replaced after
// the gate attribute an override to a layer composition already dropped.
func projectLayerSetsPreferred(project map[string]any) bool {
	sub, ok := project["vcs"].(map[string]any)
	if !ok {
		return false
	}
	_, present := sub["preferred"]
	return present
}

// vcsDetectError maps an unreadable walk-anchor failure from the VCS detection walk to the OP_FAIL
// stderr line, mirroring the project-root walk's handling (defaultResolveProjectRoot) so the
// same anchor failure reads identically wherever it surfaces. Every other detection error — an
// invalid discovery.boundary, or a preferred-detect-fails-everywhere exit — already carries
// its user-facing text and is returned unchanged.
func vcsDetectError(err error) error {
	var anchorErr *vcs.AnchorReadError
	if errors.As(err, &anchorErr) {
		return errors.New(fserrors.FormatOpFail(anchorErr.Operation, anchorErr.Anchor, anchorErr.Category))
	}
	return err
}

// userTemplateNames returns the loaded user-defined template names — the merged map minus the
// built-in names — for the vcs.preferred cross-reference check's user-template set (b).
func userTemplateNames(payload *vcsLoaded) []string {
	builtins := builtinNameSet()
	names := make([]string, 0, len(payload.templates))
	for name := range payload.templates {
		if !builtins[name] {
			names = append(names, name)
		}
	}
	return names
}

// builtinNameSet returns the built-in VCS names as a set, for tie-break ranking and the
// user-template filter.
func builtinNameSet() map[string]bool {
	set := make(map[string]bool, len(builtin.BuiltinNames()))
	for _, name := range builtin.BuiltinNames() {
		set[name] = true
	}
	return set
}

// ancestorAt returns the directory depth levels above cwd, reconstructing the repo root from the
// innermost-match depth vcs.AutoDetect reports (depth 0 is cwd itself). It mirrors the helper's own
// absolute-clean anchoring so the reconstructed path is byte-equal to the directory the walk probed.
func ancestorAt(cwd string, depth int) string {
	dir := absCleanPath(cwd)
	for i := 0; i < depth; i++ {
		dir = filepath.Dir(dir)
	}
	return dir
}

// absCleanPath normalizes a path to an absolute, cleaned form, mirroring vcs auto-detection's anchor
// handling so a reconstructed repo root matches the directory the walk reported.
func absCleanPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return filepath.Clean(path)
}

// nestedString returns composed[top][child] as a string, or "" when the parent is not a map or the
// child is absent or not a string.
func nestedString(m map[string]any, top, child string) string {
	sub, ok := m[top].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := sub[child].(string)
	return s
}

// vcsPriority returns the effective vcs.priority tie-break order from the composed config, falling
// back to the default [git, hg, jj] when absent or malformed; an explicit empty list is
// honored as configured. It mirrors config.Cache's resolution without building the cache, which is
// not available until step 8.
func vcsPriority(composed map[string]any) []string {
	sub, ok := composed["vcs"].(map[string]any)
	if !ok {
		return []string{"git", "hg", "jj"}
	}
	raw, present := sub["priority"]
	if !present {
		return []string{"git", "hg", "jj"}
	}
	list, ok := toStringList(raw)
	if !ok {
		return []string{"git", "hg", "jj"}
	}
	return list
}

// toStringList converts a decoded YAML list into a fresh []string, accepting the []any shape the YAML
// decoder produces and a native []string; it reports false for a non-list value or a non-string
// element.
func toStringList(v any) ([]string, bool) {
	switch s := v.(type) {
	case []string:
		return slices.Clone(s), true
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			str, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, str)
		}
		return out, true
	default:
		return nil, false
	}
}
