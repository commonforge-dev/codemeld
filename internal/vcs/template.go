// Loads and validates per-source VCS template files.
package vcs

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/vcs/builtin"
)

// requiredActions is the full ordered set of actions a complete template declares.
var requiredActions = []string{
	"detect", "status", "diff", "add", "commit", "log",
	"branch-current", "branch-create", "branch-switch", "restore-file",
	"is-clean", "stash", "stash-pop", "merge-status", "rebase-status",
}

// forbiddenTopLevelKeys are wrapping keys that must never appear at a template's top level.
var forbiddenTopLevelKeys = []string{"name", "kind", "version", "actions"}

// placeholderActions maps each non-detect action to the single placeholder it must accept and must contain.
var placeholderActions = map[string]string{
	"add":           "{path}",
	"restore-file":  "{path}",
	"commit":        "{message}",
	"branch-create": "{branch}",
	"branch-switch": "{branch}",
}

// recognizedPlaceholders is the closed set of placeholder literals any template may use.
var recognizedPlaceholders = map[string]bool{"{path}": true, "{message}": true, "{branch}": true}

const filenamePattern = `^[a-z][a-z0-9-]*\.yaml$`

var filenameRe = regexp.MustCompile(filenamePattern)

// placeholderRe matches a single curly-brace-delimited placeholder literal such as {path}.
var placeholderRe = regexp.MustCompile(`\{[^{}]*\}`)

// DetectSpec is the marker-based detect action body: a single filesystem entry name to probe for.
type DetectSpec struct {
	Marker string
}

// ActionClass is an optional per-action trust declaration. The zero value ClassUnset means the
// action omitted the class key and is distinct from an explicit ClassMutating, so later trust logic
// can tell default disk behavior from a user declaration.
type ActionClass string

const (
	// ClassUnset is the absent-class state (the class key was omitted).
	ClassUnset ActionClass = ""
	// ClassReadOnly declares the action does not mutate the repository.
	ClassReadOnly ActionClass = "read_only"
	// ClassMutating declares the action mutates the repository.
	ClassMutating ActionClass = "mutating"
)

// ActionSpec is a non-detect action body: the argv to run directly (no shell) and an optional working directory.
// An empty Cwd means the cwd key was absent; a present-but-empty cwd is rejected at load time.
// Class is the optional per-action trust declaration; ClassUnset means the class key was absent.
type ActionSpec struct {
	Argv  []string
	Cwd   string
	Class ActionClass
}

// Template is one loaded VCS template. Detect is nil when the file omits it (permitted only for built-in-name overrides).
// BuiltinReferenceCopy reports that the raw bytes are byte-identical to the embedded built-in of the
// same name (an unchanged first-run reference copy); it is a path-free property of the bytes, and
// trust wiring that combines it with source location lives outside this package.
type Template struct {
	Name                 string
	Detect               *DetectSpec
	Actions              map[string]ActionSpec
	Source               string
	BuiltinReferenceCopy bool
}

// ValidationError is a load-time template validation failure. It names the offending file when known.
type ValidationError struct {
	File string
	Msg  string
}

func (e *ValidationError) Error() string {
	if e.File == "" {
		return e.Msg
	}
	return fmt.Sprintf("%s: %s", e.File, e.Msg)
}

// LoadTemplates scans a single source directory for `*.yaml` VCS templates and returns them keyed by derived name.
// A missing directory is not an error and contributes no templates; any other enumeration failure is
// returned to the caller. Each file is validated; the first validation failure is returned.
func LoadTemplates(dir string) (map[string]*Template, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]*Template{}, nil
		}
		return nil, err
	}
	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		paths = append(paths, filepath.Join(dir, e.Name()))
	}
	return loadTemplatePaths(paths)
}

// loadTemplatePaths validates and loads a fixed list of template file paths. It is the testable seam beneath
// LoadTemplates for the same-source duplicate-name rule, which a real single directory cannot otherwise exercise.
func loadTemplatePaths(paths []string) (map[string]*Template, error) {
	out := map[string]*Template{}
	firstSeen := map[string]string{}
	for _, p := range paths {
		name, err := templateName(p, firstSeen)
		if err != nil {
			return nil, err
		}
		tmpl, err := parseTemplate(p, name)
		if err != nil {
			return nil, err
		}
		out[name] = tmpl
	}
	return out, nil
}

// TemplateFile is one template supplied as bytes already read from Path, which is used for
// the derived name and for validation-failure attribution.
type TemplateFile struct {
	Path  string
	Bytes []byte
}

// LoadTemplateFiles loads templates from bytes a caller already holds, under the same filename,
// duplicate-name and validation rules as LoadTemplates. It exists for a caller that must load
// exactly the bytes it inspected earlier and may not reopen the paths.
func LoadTemplateFiles(files []TemplateFile) (map[string]*Template, error) {
	out := map[string]*Template{}
	firstSeen := map[string]string{}
	for _, f := range files {
		name, err := templateName(f.Path, firstSeen)
		if err != nil {
			return nil, err
		}
		tmpl, err := parseTemplateBytes(f.Path, name, f.Bytes)
		if err != nil {
			return nil, err
		}
		out[name] = tmpl
	}
	return out, nil
}

func templateName(path string, firstSeen map[string]string) (string, error) {
	base := filepath.Base(path)
	if !filenameRe.MatchString(base) {
		return "", &ValidationError{File: path, Msg: fmt.Sprintf("filename does not match %s", filenamePattern)}
	}
	name := strings.TrimSuffix(base, ".yaml")
	if prior, dup := firstSeen[name]; dup {
		return "", &ValidationError{Msg: fmt.Sprintf("duplicate VCS template name %q declared by both %s and %s", name, prior, path)}
	}
	firstSeen[name] = path
	return name, nil
}

func parseTemplate(path, name string) (*Template, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseTemplateBytes(path, name, b)
}

// LoadBuiltinTemplates parses every embedded built-in template (git, hg, jj) into validated
// *Template values keyed by name. It is the in-memory base map a caller overlays the global and
// per-project template directories onto at bootstrap step 4, so the built-ins are always
// present even when their first-run reference copies under ~/.codemeld/global/vcs/ have been
// deleted — the union of names this base provides is part (a) of the vcs.preferred cross-reference set. Each
// Template.Source is the synthetic token "built-in:<name>" because the bytes come from the binary,
// not a file on disk.
func LoadBuiltinTemplates() (map[string]*Template, error) {
	out := make(map[string]*Template, len(builtin.BuiltinNames()))
	for _, name := range builtin.BuiltinNames() {
		data, ok := builtin.BuiltinTemplate(name)
		if !ok {
			return nil, fmt.Errorf("vcs: embedded built-in template %q not found", name)
		}
		tmpl, err := parseTemplateBytes(builtinTemplateSource(name), name, data)
		if err != nil {
			return nil, err
		}
		out[name] = tmpl
	}
	return out, nil
}

// builtinTemplateSource is the synthetic Template.Source token for an embedded built-in, standing in
// for a file path in registry source attribution since built-ins have no on-disk source.
func builtinTemplateSource(name string) string {
	return "built-in:" + name
}

// isBuiltinTemplateSource reports whether source is an embedded built-in template's synthetic Source
// token (built-in:<name>) rather than an on-disk file path. Read-only classification
// trusts the product-authored built-in action lists only for these sources; a disk template — even
// one that overrides a built-in name like git.yaml — is a user source and stays mutating by default.
// It matches against the exact built-in token set rather than a string prefix so a contrived on-disk
// path cannot masquerade as built-in.
func isBuiltinTemplateSource(source string) bool {
	for _, name := range builtin.BuiltinNames() {
		if source == builtinTemplateSource(name) {
			return true
		}
	}
	return false
}

// parseTemplateBytes validates and parses raw template bytes as the named template,
// attributing validation failures and Template.Source to source — a file path for disk
// templates or a synthetic token for embedded built-ins. It is the shared seam beneath parseTemplate
// (disk) and LoadBuiltinTemplates (embed) so both run identical validation.
func parseTemplateBytes(source, name string, b []byte) (*Template, error) {
	var root any
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, &ValidationError{File: source, Msg: config.FormatYAMLParseFailure(b, err, config.LaunchAborted)}
	}
	doc, ok := root.(map[string]any)
	if !ok {
		return nil, &ValidationError{File: source, Msg: "top-level YAML must be a map keyed by action name"}
	}

	for key := range doc {
		if slices.Contains(forbiddenTopLevelKeys, key) {
			return nil, &ValidationError{File: source, Msg: fmt.Sprintf("forbidden top-level wrapping key %q", key)}
		}
		if !slices.Contains(requiredActions, key) {
			return nil, &ValidationError{File: source, Msg: fmt.Sprintf("unknown top-level key %q is not one of the 15 VCS actions", key)}
		}
	}

	tmpl := &Template{Name: name, Actions: map[string]ActionSpec{}, Source: source}

	if raw, present := doc["detect"]; present {
		detect, err := validateDetect(source, raw)
		if err != nil {
			return nil, err
		}
		tmpl.Detect = detect
	}

	for _, action := range requiredActions {
		if action == "detect" {
			continue
		}
		raw, present := doc[action]
		if !present {
			continue
		}
		spec, err := validateActionBody(source, action, raw)
		if err != nil {
			return nil, err
		}
		tmpl.Actions[action] = spec
	}

	if err := checkCompleteness(source, name, tmpl); err != nil {
		return nil, err
	}
	tmpl.BuiltinReferenceCopy = matchesBuiltinReference(name, b)
	return tmpl, nil
}

// matchesBuiltinReference reports whether b is byte-identical to the embedded built-in template of
// the given name. It compares raw bytes — never parsed or reserialized YAML — so a semantically
// equivalent but reformatted copy is not treated as an unchanged reference. Non-built-in names never match.
func matchesBuiltinReference(name string, b []byte) bool {
	ref, ok := builtin.BuiltinTemplate(name)
	if !ok {
		return false
	}
	return bytes.Equal(ref, b)
}

func validateDetect(path string, raw any) (*DetectSpec, error) {
	body, ok := raw.(map[string]any)
	if !ok {
		return nil, &ValidationError{File: path, Msg: "detect action body must be a map"}
	}
	for key := range body {
		if key != "marker" {
			return nil, &ValidationError{File: path, Msg: fmt.Sprintf("detect action has unknown key %q (only marker is permitted)", key)}
		}
	}
	rawMarker, present := body["marker"]
	if !present {
		return nil, &ValidationError{File: path, Msg: "detect action is missing the required key marker"}
	}
	marker, ok := rawMarker.(string)
	if !ok {
		return nil, &ValidationError{File: path, Msg: "detect.marker must be a string"}
	}
	if err := validateMarker(path, marker); err != nil {
		return nil, err
	}
	return &DetectSpec{Marker: marker}, nil
}

// validateMarker enforces that marker names a single filesystem entry, not a path. It delegates to
// the shared ValidateMarker and adds the offending file context for load-time reporting.
func validateMarker(path, marker string) error {
	if err := ValidateMarker(marker); err != nil {
		return &ValidationError{File: path, Msg: fmt.Sprintf("detect.marker %q is invalid: %s", marker, err)}
	}
	return nil
}

func validateActionBody(path, action string, raw any) (ActionSpec, error) {
	body, ok := raw.(map[string]any)
	if !ok {
		return ActionSpec{}, &ValidationError{File: path, Msg: fmt.Sprintf("action %q body must be a map", action)}
	}
	for key := range body {
		if key != "argv" && key != "cwd" && key != "class" {
			return ActionSpec{}, &ValidationError{File: path, Msg: fmt.Sprintf("action %q has unknown key %q (only argv, cwd, and class are permitted)", action, key)}
		}
	}

	rawArgv, present := body["argv"]
	if !present {
		return ActionSpec{}, &ValidationError{File: path, Msg: fmt.Sprintf("action %q is missing the required key argv", action)}
	}
	argvList, ok := rawArgv.([]any)
	if !ok {
		return ActionSpec{}, &ValidationError{File: path, Msg: fmt.Sprintf("action %q argv must be a list of strings", action)}
	}
	if len(argvList) == 0 {
		return ActionSpec{}, &ValidationError{File: path, Msg: fmt.Sprintf("action %q argv must be a non-empty list", action)}
	}
	argv := make([]string, len(argvList))
	for i, elem := range argvList {
		s, ok := elem.(string)
		if !ok {
			return ActionSpec{}, &ValidationError{File: path, Msg: fmt.Sprintf("action %q argv element %d is not a string", action, i)}
		}
		argv[i] = s
	}

	spec := ActionSpec{Argv: argv}
	if rawCwd, present := body["cwd"]; present {
		cwd, ok := rawCwd.(string)
		if !ok {
			return ActionSpec{}, &ValidationError{File: path, Msg: fmt.Sprintf("action %q cwd must be a string", action)}
		}
		if cwd == "" {
			return ActionSpec{}, &ValidationError{File: path, Msg: fmt.Sprintf("action %q cwd must not be empty (omit the cwd key to use the repo root)", action)}
		}
		spec.Cwd = cwd
	}

	if rawClass, present := body["class"]; present {
		class, ok := rawClass.(string)
		if !ok {
			return ActionSpec{}, &ValidationError{File: path, Msg: fmt.Sprintf("action %q class must be a string (%q or %q)", action, ClassReadOnly, ClassMutating)}
		}
		switch ActionClass(class) {
		case ClassReadOnly, ClassMutating:
			spec.Class = ActionClass(class)
		default:
			return ActionSpec{}, &ValidationError{File: path, Msg: fmt.Sprintf("action %q has unknown class %q (only %q and %q are permitted)", action, class, ClassReadOnly, ClassMutating)}
		}
	}

	if err := validatePlaceholders(path, action, argv); err != nil {
		return ActionSpec{}, err
	}
	return spec, nil
}

// validatePlaceholders enforces the closed placeholder set and per-action placeholder rules.
// Placeholders apply only to argv elements; cwd accepts none.
func validatePlaceholders(path, action string, argv []string) error {
	accepted, accepts := placeholderActions[action]
	foundAccepted := false
	for _, elem := range argv {
		for _, ph := range placeholderRe.FindAllString(elem, -1) {
			if !recognizedPlaceholders[ph] {
				return &ValidationError{File: path, Msg: fmt.Sprintf("action %q contains unknown placeholder %s", action, ph)}
			}
			if !accepts || ph != accepted {
				return &ValidationError{File: path, Msg: fmt.Sprintf("action %q uses placeholder %s it does not accept", action, ph)}
			}
			foundAccepted = true
		}
	}
	if accepts && !foundAccepted {
		return &ValidationError{File: path, Msg: fmt.Sprintf("action %q must contain its placeholder %s", action, accepted)}
	}
	return nil
}

// checkCompleteness enforces the two regimes from: a built-in-name override may omit detect (all
// other actions required); a new VCS name must declare all 15 actions including detect.
func checkCompleteness(path, name string, tmpl *Template) error {
	isOverride := slices.Contains(builtin.BuiltinNames(), name)
	var missing []string
	for _, action := range requiredActions {
		if action == "detect" {
			if !isOverride && tmpl.Detect == nil {
				missing = append(missing, "detect")
			}
			continue
		}
		if _, ok := tmpl.Actions[action]; !ok {
			missing = append(missing, action)
		}
	}
	if len(missing) > 0 {
		return &ValidationError{File: path, Msg: "missing required actions: " + strings.Join(missing, ", ")}
	}
	return nil
}
