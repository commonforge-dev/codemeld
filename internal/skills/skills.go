// Package skills discovers and parses SKILL.md skill folders in the global and project skills directories.
package skills

import (
	"cmp"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/permissions"
)

type Layer string

const (
	Global  Layer = "global"
	Project Layer = "project"
)

type Reason string

const (
	OutsideFolder       Reason = "outside_folder"
	Unreadable          Reason = "unreadable"
	TooLarge            Reason = "too_large"
	BadFrontMatter      Reason = "bad_front_matter"
	BadName             Reason = "bad_name"
	NameMismatch        Reason = "name_mismatch"
	MissingDescription  Reason = "missing_description"
	BuiltinClash        Reason = "builtin_clash"
	OverriddenByProject Reason = "overridden_by_project"
)

type Skill struct {
	Name           string
	Description    string
	Layer          Layer
	Folder         string
	Body           string
	ModelInvocable bool
}

type Skipped struct {
	Path   string
	Reason Reason
}

type Set struct {
	Loaded  []Skill
	Skipped []Skipped
}

var (
	openRoot    = os.OpenRoot
	openFile    = (*os.Root).OpenFile
	readLimited = func(f *os.File, limit int64) ([]byte, error) {
		return io.ReadAll(io.LimitReader(f, limit))
	}
)

var namePattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func RootAllowed(home, resolvedRoot string) bool {
	fold := runtime.GOOS == "darwin" || runtime.GOOS == "windows"
	state := filepath.Join(home, ".codemeld")
	if _, ok := permissions.RelWithin(resolvedRoot, state, fold); ok {
		return false
	}
	rel, ok := permissions.RelWithin(state, resolvedRoot, fold)
	if !ok {
		return true
	}
	first, _, _ := strings.Cut(rel, "/")
	return first == "skills" || fold && strings.EqualFold(first, "skills")
}

type loader struct {
	home         string
	reserved     map[string]bool
	maxFileBytes int
	loaded       map[string]Skill
	skipped      []Skipped
}

func Load(home, projectRoot string, reserved map[string]bool, maxFileBytes int) Set {
	l := &loader{home: home, reserved: reserved, maxFileBytes: maxFileBytes, loaded: map[string]Skill{}}
	globalRoot := l.scan(filepath.Join(home, ".codemeld", "skills"), Global, nil)
	l.scan(filepath.Join(projectRoot, ".codemeld", "skills"), Project, globalRoot)

	set := Set{Skipped: l.skipped}
	for _, s := range l.loaded {
		set.Loaded = append(set.Loaded, s)
	}
	slices.SortFunc(set.Loaded, func(a, b Skill) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(set.Skipped, func(a, b Skipped) int {
		return cmp.Or(
			strings.Compare(filepath.Base(a.Path), filepath.Base(b.Path)),
			strings.Compare(a.Path, b.Path),
			strings.Compare(string(a.Reason), string(b.Reason)),
		)
	})
	return set
}

func (l *loader) skip(path string, reason Reason) {
	l.skipped = append(l.skipped, Skipped{Path: path, Reason: reason})
}

func (l *loader) scan(rootPath string, layer Layer, scanned fs.FileInfo) fs.FileInfo {
	root, info, resolved := l.openRoot(rootPath)
	if root == nil {
		return nil
	}
	defer func() { _ = root.Close() }()
	if scanned != nil && os.SameFile(scanned, info) {
		return info
	}
	dir, err := root.Open(".")
	if err != nil {
		l.skip(rootPath, Unreadable)
		return info
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		l.skip(rootPath, Unreadable)
		return info
	}
	for _, e := range entries {
		l.candidate(root, resolved, rootPath, e.Name(), layer)
	}
	return info
}

func (l *loader) openRoot(path string) (*os.Root, fs.FileInfo, string) {
	resolved, err := filepath.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, ""
	}
	if err != nil {
		l.skip(path, Unreadable)
		return nil, nil, ""
	}
	validated, err := os.Lstat(resolved)
	if err != nil {
		l.skip(path, Unreadable)
		return nil, nil, ""
	}
	if !RootAllowed(l.home, resolved) {
		l.skip(path, OutsideFolder)
		return nil, nil, ""
	}
	root, err := openRoot(resolved)
	if err != nil {
		l.skip(path, Unreadable)
		return nil, nil, ""
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(validated, opened) {
		_ = root.Close()
		if err != nil {
			l.skip(path, Unreadable)
		} else {
			l.skip(path, OutsideFolder)
		}
		return nil, nil, ""
	}
	return root, validated, resolved
}

func (l *loader) candidate(root *os.Root, resolved, rootPath, name string, layer Layer) {
	folder := filepath.Join(rootPath, name)
	data, reason, ok := readSkillFile(root, resolved, filepath.Join(name, "SKILL.md"), l.maxFileBytes)
	if !ok {
		return
	}
	var skill Skill
	if reason == "" {
		skill, reason = parse(data, name)
	}
	if reason == "" && l.reserved[skill.Name] {
		reason = BuiltinClash
	}
	if reason != "" {
		l.skip(folder, reason)
		return
	}
	skill.Layer, skill.Folder = layer, folder
	if global, ok := l.loaded[skill.Name]; ok {
		l.skip(global.Folder, OverriddenByProject)
	}
	l.loaded[skill.Name] = skill
}

// os.Root refuses every absolute symlink, even one whose target lies inside it, so Within follows
// links itself and maps targets inside base back to a root-relative path for the caller to open.
func Within(root *os.Root, base, name string) (string, bool) {
	fold := runtime.GOOS == "darwin" || runtime.GOOS == "windows"
	resolved, rest := ".", strings.Split(filepath.ToSlash(name), "/")
	for hops := 0; len(rest) > 0; {
		part := rest[0]
		rest = rest[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if resolved == "." {
				return "", false
			}
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, part)
		info, err := root.Lstat(next)
		if err != nil {
			return strings.Join(append([]string{next}, rest...), string(filepath.Separator)), true
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			resolved = next
			continue
		}
		target, err := root.Readlink(next)
		if hops++; err != nil || hops > 40 {
			return "", false
		}
		if filepath.IsAbs(target) {
			rel, ok := permissions.RelWithin(base, target, fold)
			if !ok {
				return "", false
			}
			resolved, target = ".", rel
		}
		rest = append(strings.Split(filepath.ToSlash(target), "/"), rest...)
	}
	return resolved, true
}

func readSkillFile(root *os.Root, base, name string, maxFileBytes int) ([]byte, Reason, bool) {
	if rel, ok := Within(root, base, name); ok {
		name = rel
	}
	f, err := openFile(root, name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	var pathErr *fs.PathError
	switch {
	// os.Root's escape error is unexported, so its text is the only way to recognize it.
	case errors.As(err, &pathErr) && pathErr.Err.Error() == "path escapes from parent":
		return nil, OutsideFolder, true
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		return nil, "", false
	case err != nil:
		return nil, Unreadable, true
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, Unreadable, true
	}
	size := info.Size()
	if size > int64(maxFileBytes) {
		return nil, TooLarge, true
	}
	data, err := readLimited(f, size+1)
	if err != nil || int64(len(data)) != size {
		return nil, Unreadable, true
	}
	return data, "", true
}

func parse(data []byte, folder string) (Skill, Reason) {
	text := strings.ReplaceAll(strings.TrimPrefix(string(data), "\uFEFF"), "\r\n", "\n")
	rest, ok := strings.CutPrefix(text, "---\n")
	if !ok {
		return Skill{}, BadFrontMatter
	}
	off := 0
	for line := range strings.Lines(rest) {
		off += len(line)
		if strings.TrimSuffix(line, "\n") == "---" {
			return validate(rest[:off-len(line)], rest[off:], folder)
		}
	}
	return Skill{}, BadFrontMatter
}

func validate(header, body, folder string) (Skill, Reason) {
	var fields map[string]any
	if err := yaml.Unmarshal([]byte(header), &fields); err != nil {
		return Skill{}, BadFrontMatter
	}
	name, nameOK := field[string](fields, "name")
	description, descriptionOK := field[string](fields, "description")
	disabled, disabledOK := false, true
	if v, present := fields["disable-model-invocation"]; present {
		disabled, disabledOK = v.(bool)
	}
	if !nameOK || !descriptionOK || !disabledOK {
		return Skill{}, BadFrontMatter
	}
	if name == "" {
		name = folder
	}
	if len(name) > 64 || !namePattern.MatchString(name) {
		return Skill{}, BadName
	}
	if name != folder {
		return Skill{}, NameMismatch
	}
	description = strings.TrimSpace(description)
	if description == "" {
		return Skill{}, MissingDescription
	}
	if utf8.RuneCountInString(description) > 1024 {
		return Skill{}, BadFrontMatter
	}
	return Skill{Name: name, Description: description, Body: body, ModelInvocable: !disabled}, ""
}

func field[T any](fields map[string]any, key string) (T, bool) {
	v, ok := fields[key].(T)
	return v, ok || fields[key] == nil
}
