// Loads and validates settings/template YAML, classifying load failures.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/permissions"
)

// LoadFailure classifies a settings/template load outcome; its string values are the category tokens reported on stderr.
type LoadFailure string

const (
	LoadOK                LoadFailure = "none"
	UnreadableFile        LoadFailure = "unreadable_file"
	YAMLParseError        LoadFailure = "yaml_parse_error"
	SchemaValidationError LoadFailure = "schema_validation_error"
)

// LoadYAML reads and validates a settings or VCS-template YAML file, returning the comment-preserving AST and decoded raw map on success, or a non-LoadOK category and the underlying error on failure.
func LoadYAML(path string) (doc *ast.File, raw map[string]any, cat LoadFailure, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, UnreadableFile, err
	}
	return LoadYAMLBytes(b, path)
}

// LoadYAMLBytes validates settings or VCS-template YAML the caller has already read. path names
// the source for diagnostics only and is never opened.
func LoadYAMLBytes(b []byte, path string) (doc *ast.File, raw map[string]any, cat LoadFailure, err error) {
	doc, err = parser.ParseBytes(b, parser.ParseComments)
	if err != nil {
		return nil, nil, YAMLParseError, annotateParseError(b, err)
	}

	// Decode into any (not map[string]any) so a non-map root (sequence or scalar)
	// reaches schema validation instead of being misclassified as yaml_parse_error.
	var root any
	if err = yaml.Unmarshal(b, &root); err != nil {
		return nil, nil, YAMLParseError, annotateParseError(b, err)
	}

	// A blank/comment-only file decodes to a nil root; validate it as an empty
	// object so the schema's object root accepts it rather than rejecting a null body.
	validateBytes := b
	if root == nil {
		validateBytes = []byte("{}")
	}
	if err = Validate(validateBytes, path); err != nil {
		return nil, nil, SchemaValidationError, err
	}

	// Validation passed, so the root is an object; decode it into the raw map.
	raw = map[string]any{}
	if root != nil {
		if err = yaml.Unmarshal(b, &raw); err != nil {
			return nil, nil, YAMLParseError, annotateParseError(b, err)
		}
	}

	return doc, raw, LoadOK, nil
}

// ValidateGlobalSettingsBytes applies every global-layer rule to settings bytes the caller
// has already read under its own bound. path names the source for diagnostics only and is
// never opened, so a caller that reads through a hardened descriptor keeps that guarantee.
func ValidateGlobalSettingsBytes(b []byte, path string) (raw map[string]any, cat LoadFailure, err error) {
	_, raw, cat, err = LoadYAMLBytes(b, path)
	if cat != LoadOK {
		return nil, cat, err
	}
	if permErr := ValidatePermissionEntries(path, raw); permErr != nil {
		return nil, SchemaValidationError, permErr
	}
	if hostErr := rejectGlobalHostGrants(path, raw); hostErr != nil {
		return nil, SchemaValidationError, hostErr
	}
	if declErr := rejectGlobalDeclaredCommands(path, raw); declErr != nil {
		return nil, SchemaValidationError, declErr
	}
	if writeErr := rejectGlobalWritableFolders(path, raw); writeErr != nil {
		return nil, SchemaValidationError, writeErr
	}
	return raw, LoadOK, nil
}

func ValidateProjectSettingsBytes(b []byte, path string) (raw map[string]any, cat LoadFailure, err error) {
	_, raw, cat, err = LoadYAMLBytes(b, path)
	if cat != LoadOK {
		return nil, cat, err
	}
	if permErr := ValidatePermissionEntries(path, raw); permErr != nil {
		return nil, SchemaValidationError, permErr
	}
	if globalOnlyErr := EnforceGlobalOnly(path, raw); globalOnlyErr != nil {
		return nil, SchemaValidationError, globalOnlyErr
	}
	return raw, LoadOK, nil
}

func ValidateLocalSettingsBytes(b []byte, path string) (raw map[string]any, cat LoadFailure, err error) {
	_, raw, cat, err = LoadYAMLBytes(b, path)
	if cat != LoadOK {
		return nil, cat, err
	}
	if permErr := ValidatePermissionEntries(path, raw); permErr != nil {
		return nil, SchemaValidationError, permErr
	}
	if allowErr := enforceLocalAllowList(path, raw); allowErr != nil {
		return nil, SchemaValidationError, allowErr
	}
	if grantErr := enforceLocalGrantKinds(path, raw); grantErr != nil {
		return nil, SchemaValidationError, grantErr
	}
	return raw, LoadOK, nil
}

// ValidatePermissionEntries rejects a layer holding an entry the schema admits but
// ParseEntry does not. Cache builds its permission view from the composed config, where
// deduplication can drop an invalid layer entry behind an equivalent one from another
// layer, so the entry has to be parsed at its source to be rejected at all.
func ValidatePermissionEntries(path string, raw map[string]any) error {
	value, present := raw["permissions"]
	if !present || value == nil {
		return nil
	}
	list, ok := value.([]any)
	if !ok {
		return fmt.Errorf("%s: schema validation failed at permissions: expected a list, got %T", path, value)
	}
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: schema validation failed at permissions.%d: expected a mapping, got %T", path, i, item)
		}
		if _, err := permissions.ParseEntry(m, path, i); err != nil {
			return err
		}
	}
	return nil
}

// CopyLayer deep-copies a decoded settings layer so a snapshot retained past composition
// shares no structure with the map Compose merges.
func CopyLayer(raw map[string]any) map[string]any {
	if raw == nil {
		return nil
	}
	copied, _ := deepCopyValue(raw).(map[string]any)
	return copied
}

const globalHostGrantDetail = "host grant is project-only and must be moved to the project's .codemeld/settings.yaml"

func rejectGlobalHostGrants(path string, raw map[string]any) error {
	list, ok := raw["permissions"].([]any)
	if !ok {
		return nil
	}
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		entry, err := permissions.ParseEntry(m, path, i)
		if err != nil || entry.HostScope == "" {
			continue
		}
		return fmt.Errorf("%s: schema validation failed at permissions.%d: %s", path, i, globalHostGrantDetail)
	}
	return nil
}

const globalDeclaredCommandsDetail = "declared_commands is project-only and must be moved to the project's .codemeld/settings.yaml"

// A global declaration would be a machine-wide prompt-free execution list, so the key's presence
// is rejected whatever its value; per-entry validation never runs on a global document.
func rejectGlobalDeclaredCommands(path string, raw map[string]any) error {
	if _, ok := raw["declared_commands"]; !ok {
		return nil
	}
	return fmt.Errorf("%s: schema validation failed at declared_commands: %s", path, globalDeclaredCommandsDetail)
}

const globalWritableFoldersDetail = "writable_folders is project-only and must be moved to the project's .codemeld/settings.yaml"

func rejectGlobalWritableFolders(path string, raw map[string]any) error {
	if _, ok := raw["writable_folders"]; !ok {
		return nil
	}
	return fmt.Errorf("%s: schema validation failed at writable_folders: %s", path, globalWritableFoldersDetail)
}

// LoadConsequence states what the failure did to the run in progress. The formatter cannot
// derive it: the same category aborts a launch from one caller and is only reported by another.
type LoadConsequence string

const LaunchAborted LoadConsequence = "codemeld did not start"

const (
	unreadablePhrase = "could not be read"
	parsePhrase      = "is not valid YAML"
	schemaPhrase     = "does not match the settings schema"

	unreadableFix = "check that the file exists and that codemeld is allowed to read it, then start codemeld again"
	parseFix      = "correct the YAML at the position reported above, then start codemeld again"
	schemaFix     = "correct the setting named above, then start codemeld again"
)

// FormatLoadError renders the stderr message for a non-LoadOK category, returning "" for LoadOK.
// The category tokens are an internal classification and never appear in the result.
func FormatLoadError(path string, cat LoadFailure, err error, consequence LoadConsequence) string {
	path = fserrors.CollapseControls(path)
	switch cat {
	case UnreadableFile:
		return attribute(path, frameLoadFailure(unreadablePhrase, consequence, fserrors.CollapseControls(err.Error()), unreadableFix))
	case YAMLParseError:
		what, fix := parseFailureDetail(err)
		return attribute(path, frameLoadFailure(parsePhrase, consequence, what, fix))
	case SchemaValidationError:
		// Validate's message already opens with the path, which attribute is about to add.
		detail := strings.TrimPrefix(fserrors.CollapseControls(err.Error()), path+": ")
		return attribute(path, frameLoadFailure(schemaPhrase, consequence, detail, schemaFix))
	default:
		return ""
	}
}

// FormatYAMLParseFailure renders the same body FormatLoadError builds for a parse failure,
// without the path attribution, for a caller whose own error type supplies that attribution.
func FormatYAMLParseFailure(src []byte, err error, consequence LoadConsequence) string {
	what, fix := parseFailureDetail(annotateParseError(src, err))
	return frameLoadFailure(parsePhrase, consequence, what, fix)
}

func attribute(path, body string) string {
	return fmt.Sprintf("codemeld: %s: %s", path, body)
}

func frameLoadFailure(phrase string, consequence LoadConsequence, what, fix string) string {
	return fmt.Sprintf("%s; %s.\n  what happened: %s\n  to fix: %s", phrase, consequence, what, fix)
}

func parseFailureDetail(err error) (what, fix string) {
	var parsed *yamlParseError
	if errors.As(err, &parsed) && parsed.dup != nil {
		return parsed.dup.what(), parsed.dup.fix()
	}
	return fserrors.CollapseControls(err.Error()), parseFix
}

type duplicateKey struct {
	key       string
	line      int
	priorLine int
	entry     string
	entryKey  string
}

func (d *duplicateKey) what() string {
	what := fmt.Sprintf("the key %q is set twice in the same block, at line %d and again at line %d", d.key, d.priorLine, d.line)
	if d.entry != "" {
		what += fmt.Sprintf("; the block is the entry whose %s is %q", d.entryKey, d.entry)
	}
	return what
}

func (d *duplicateKey) fix() string {
	return fmt.Sprintf("delete one of the two %q lines, either line %d or line %d", d.key, d.priorLine, d.line)
}

// yamlParseError carries the duplicate-key remediation, which is derived here rather than in the
// formatter because the formatter holds no source bytes and must not reopen the file it reports
// on. Only the derived positions are retained, never the bytes, which hold credentials.
type yamlParseError struct {
	err error
	dup *duplicateKey
}

func (e *yamlParseError) Error() string { return e.err.Error() }

func (e *yamlParseError) Unwrap() error { return e.err }

func annotateParseError(src []byte, err error) error {
	return &yamlParseError{err: err, dup: findDuplicateKey(src, err)}
}

var duplicateKeyRe = regexp.MustCompile(`^mapping key ("(?:[^"\\]|\\.)*") already defined at \[(\d+):\d+\]$`)

func findDuplicateKey(src []byte, err error) *duplicateKey {
	var syntax *yaml.SyntaxError
	if !errors.As(err, &syntax) || syntax.Token == nil {
		return nil
	}
	fields := duplicateKeyRe.FindStringSubmatch(syntax.Message)
	if fields == nil {
		return nil
	}
	key, uerr := strconv.Unquote(fields[1])
	if uerr != nil {
		return nil
	}
	prior, cerr := strconv.Atoi(fields[2])
	if cerr != nil {
		return nil
	}
	line := syntax.Token.Position.Line
	entry, entryKey := entryLabel(src, line)
	return &duplicateKey{key: key, line: line, priorLine: prior, entry: entry, entryKey: entryKey}
}

// entryLabel names the list entry containing the given 1-based line, reading the source bytes
// because a failed parse yields no AST to walk.
func entryLabel(src []byte, line int) (label, key string) {
	lines := strings.Split(string(src), "\n")
	if line < 1 || line > len(lines) {
		return "", ""
	}
	enclosing := indentOf(lines[line-1])
	for i := line - 2; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		indent := indentOf(lines[i])
		if indent >= enclosing {
			continue
		}
		if strings.HasPrefix(strings.TrimLeft(lines[i], " "), "- ") {
			return labelWithinEntry(lines, i, indent)
		}
		enclosing = indent
	}
	return "", ""
}

func labelWithinEntry(lines []string, start, itemIndent int) (label, key string) {
	var subject, name string
	take := func(text string) {
		if v := scalarValue(text, "subject"); v != "" && subject == "" {
			subject = v
		}
		if v := scalarValue(text, "name"); v != "" && name == "" {
			name = v
		}
	}
	take(strings.TrimPrefix(strings.TrimLeft(lines[start], " "), "- "))
	for i := start + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		if indentOf(lines[i]) <= itemIndent {
			break
		}
		take(strings.TrimLeft(lines[i], " "))
	}
	if subject != "" {
		return subject, "subject"
	}
	if name != "" {
		return name, "name"
	}
	return "", ""
}

const maxEntryLabel = 120

func scalarValue(text, key string) string {
	rest, ok := strings.CutPrefix(text, key+":")
	if !ok {
		return ""
	}
	value := strings.TrimSpace(rest)
	if unquoted, uerr := strconv.Unquote(value); uerr == nil {
		value = unquoted
	} else {
		value = strings.Trim(value, "'")
	}
	if len(value) > maxEntryLabel {
		return ""
	}
	return fserrors.CollapseControls(value)
}

func indentOf(text string) int {
	return len(text) - len(strings.TrimLeft(text, " "))
}

// isWindows is a package-local seam so tests can exercise the Windows-suppression
// branch without building for GOOS=windows.
var isWindows = runtime.GOOS == "windows"

// WarnIfBroaderThan0600 emits one advisory stderr warning when the file's mode
// exposes any group/other bit. The global settings file holds plaintext
// credentials — provider API keys and, under, ChatGPT session tokens
// (auth.openai-chatgpt) — so the warning names both rather than API keys alone.
// Advisory only: the file is never rewritten or chmod'd.
// Suppressed on Windows and when the file is absent. The final component is inspected
// without following it, so a settings path that is a symbolic link — which the readers
// reject rather than follow — never produces a warning derived from its target's mode.
func WarnIfBroaderThan0600(path string) {
	if isWindows {
		return
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	perm := info.Mode().Perm()
	if perm&0o077 == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "codemeld: %s: file mode %#o is broader than 0600; API keys and ChatGPT session tokens are stored in plaintext\n", path, uint32(perm))
}
