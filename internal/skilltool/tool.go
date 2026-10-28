// Package skilltool provides the skill tool, which returns a loaded skill's instructions or one of its files.
package skilltool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/skills"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/vcs"
)

const ToolName = "skill"

const maxListed = 200

const (
	listUnknownMessage = "the blocked_paths list is unavailable, so skill files cannot be read; fix your settings and restart"
	listBrokenMessage  = "the blocked_paths list is broken, so skill files outside the project cannot be read until it is fixed"
)

var (
	openRoot    = os.OpenRoot
	openFolder  = (*os.Root).OpenRoot
	openFile    = (*os.Root).OpenFile
	readLimited = func(f *os.File, limit int64) ([]byte, error) {
		return io.ReadAll(io.LimitReader(f, limit))
	}
)

type Tool struct {
	loaded       []skills.Skill
	maxFileBytes int
	home         string
	projectRoot  string
	blocked      *permissions.BlockedPaths
	store        func() *sessions.Store
}

var _ tools.Tool = (*Tool)(nil)

func New(loaded []skills.Skill, maxFileBytes int, home, projectRoot string, blocked *permissions.BlockedPaths, store func() *sessions.Store) *Tool {
	return &Tool{loaded: slices.Clone(loaded), maxFileBytes: maxFileBytes, home: home, projectRoot: projectRoot, blocked: blocked, store: store}
}

func (t *Tool) Name() string { return ToolName }

func (t *Tool) SubjectKind() string { return "tool" }

func (t *Tool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description: "Load a skill listed in the system prompt. Without file it returns the skill's instructions, " +
			"its folder (relative paths in the instructions are relative to it) and a list of its other files. " +
			"With file it returns that one file from the skill's folder. It only reads; it never runs a skill's scripts.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{
					"type":        "string",
					"description": "Name of a skill listed in the system prompt.",
				},
				"file": map[string]any{
					"type":        "string",
					"description": "Path of another file in the skill's folder, relative to that folder (for example scripts/run.sh). Omit to load the skill's instructions.",
				},
			},
			"required":             []string{"name"},
			"additionalProperties": false,
		},
		ReadOnly:      true,
		Noncredential: true,
	}
}

func (t *Tool) Invoke(ctx context.Context, args map[string]any) (tools.Result, error) {
	name, file, problem := parseArgs(args)
	if problem != "" {
		return failResult(problem), nil
	}
	i := slices.IndexFunc(t.loaded, func(s skills.Skill) bool { return s.Name == name })
	if i < 0 {
		return failResult(t.unknown(name)), nil
	}
	skill := t.loaded[i]
	folder := filepath.Join(t.skillsRoot(skill.Layer), skill.Name)
	if file != "" {
		return t.readFile(ctx, skill, folder, file)
	}
	if !skill.ModelInvocable {
		return failResult(fmt.Sprintf("automatic loading of skill %q is disabled; the user can start it with /%s in the TUI (slash commands are not available in codemeld run)", name, name)), nil
	}
	return t.record(ctx, skill, "", []byte(skill.Body), tools.Result{Stdout: []byte(t.describe(skill, folder))})
}

func (t *Tool) record(ctx context.Context, skill skills.Skill, file string, data []byte, res tools.Result) (tools.Result, error) {
	if t.store == nil {
		return res, nil
	}
	store := t.store()
	if store == nil {
		return res, nil
	}
	sum := sha256.Sum256(data)
	err := events.AppendSkillLoaded(store, events.SkillLoaded{
		Name:              skill.Name,
		Layer:             string(skill.Layer),
		Via:               "tool",
		File:              file,
		Bytes:             int64(len(data)),
		SHA256:            hex.EncodeToString(sum[:]),
		ChildInvocationID: vcs.ChildInvocationID(ctx),
	})
	if err != nil {
		return tools.Result{}, fmt.Errorf("skill %q was read, but its load record could not be saved: %w", skill.Name, err)
	}
	return res, nil
}

func parseArgs(args map[string]any) (name, file, problem string) {
	for key := range args {
		if key != "name" && key != "file" {
			return "", "", fmt.Sprintf("unknown argument %q; skill takes name and an optional file", key)
		}
	}
	name, ok := args["name"].(string)
	if !ok || name == "" {
		return "", "", `argument "name" must be the name of a skill`
	}
	if raw, present := args["file"]; present {
		if file, ok = raw.(string); !ok {
			return "", "", `argument "file" must be a path relative to the skill folder`
		}
	}
	return name, file, ""
}

func (t *Tool) unknown(name string) string {
	var names []string
	for _, s := range t.loaded {
		if s.ModelInvocable {
			names = append(names, s.Name)
		}
	}
	if len(names) == 0 {
		return fmt.Sprintf("no skill named %q is available", name)
	}
	return fmt.Sprintf("no skill named %q; available skills: %s", name, strings.Join(names, ", "))
}

func (t *Tool) skillsRoot(layer skills.Layer) string {
	base := t.home
	if layer == skills.Project {
		base = t.projectRoot
	}
	return filepath.Join(base, ".codemeld", "skills")
}

func (t *Tool) readFile(ctx context.Context, skill skills.Skill, folder, file string) (tools.Result, error) {
	if filepath.IsAbs(file) || slices.Contains(strings.Split(file, "/"), "..") {
		return failResult(fmt.Sprintf("file %q must be a path inside the skill folder, relative to it, without ..", file)), nil
	}
	target := filepath.Join(folder, file)
	snap := t.blocked.Current()
	if entry, ok := configuredBlock(snap, folder, target); ok {
		return tools.Result{}, blockedRefusal(target, entry)
	}
	if problem := liveProblem(snap, folder, target); problem != "" {
		return failResult(problem), nil
	}
	root, problem := t.acquire(folder)
	if problem != "" {
		return failResult(problem), nil
	}
	defer func() { _ = root.Close() }()
	data, problem := readBounded(root, file, t.maxFileBytes)
	if problem != "" {
		return failResult(problem), nil
	}
	return t.record(ctx, skill, path.Clean(file), data, tools.Result{Stdout: data})
}

func configuredBlock(snap *permissions.BlockedPaths, targets ...string) (permissions.BlockedEntry, bool) {
	for _, entry := range snap.Entries() {
		if entry.Floor() {
			continue
		}
		for _, target := range targets {
			if _, ok := permissions.RelWithin(entry.Path, target, snap.FoldCase()); ok {
				return entry, true
			}
		}
	}
	return permissions.BlockedEntry{}, false
}

func liveProblem(snap *permissions.BlockedPaths, targets ...string) string {
	if snap == nil {
		return listUnknownMessage
	}
	if snap.Degraded() && slices.ContainsFunc(targets, snap.OutsideProject) {
		return listBrokenMessage
	}
	return ""
}

func blockedRefusal(target string, entry permissions.BlockedEntry) *securitystate.Refusal {
	return &securitystate.Refusal{
		SubjectKind: "tool",
		Subject:     ToolName,
		PathScope:   filepath.Dir(target),
		Envelope:    permissions.BuildBlockedPathDenyEnvelope(target, entry.Path, false),
		Source:      "blocked_path",
		Entry:       entry.Path,
		EntrySource: entry.Source,
	}
}

func (t *Tool) acquire(folder string) (*os.Root, string) {
	rootPath, name := filepath.Dir(folder), filepath.Base(folder)
	resolved, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		return nil, fmt.Sprintf("the skills folder %s is missing or unreadable", rootPath)
	}
	validated, err := os.Lstat(resolved)
	if err != nil || !validated.IsDir() {
		return nil, fmt.Sprintf("the skills folder %s is not a folder", rootPath)
	}
	if !skills.RootAllowed(t.home, resolved) {
		return nil, fmt.Sprintf("the skills folder %s leads into codemeld's protected folder", rootPath)
	}
	root, err := openRoot(resolved)
	if err != nil {
		return nil, fmt.Sprintf("the skills folder %s could not be opened", rootPath)
	}
	defer func() { _ = root.Close() }()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(validated, opened) {
		return nil, fmt.Sprintf("the skills folder %s changed while it was being opened", rootPath)
	}
	if rel, ok := skills.Within(root, resolved, name); ok {
		name = rel
	}
	expected, err := root.Stat(name)
	if err != nil || !expected.IsDir() {
		return nil, fmt.Sprintf("the skill folder %s is missing or leads outside %s", folder, rootPath)
	}
	dir, err := openFolder(root, name)
	if err != nil {
		return nil, fmt.Sprintf("the skill folder %s could not be opened inside %s", folder, rootPath)
	}
	got, err := dir.Stat(".")
	if err != nil || !os.SameFile(expected, got) {
		_ = dir.Close()
		return nil, fmt.Sprintf("the skill folder %s changed while it was being opened", folder)
	}
	return dir, ""
}

func readBounded(root *os.Root, file string, limit int) ([]byte, string) {
	info, err := root.Stat(file)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Sprintf("file %q does not exist in the skill folder", file)
	case err != nil:
		return nil, fmt.Sprintf("file %q could not be read inside the skill folder", file)
	case !info.Mode().IsRegular():
		return nil, fmt.Sprintf("file %q is not a regular file", file)
	}
	f, err := openFile(root, file, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Sprintf("file %q could not be opened inside the skill folder", file)
	}
	defer func() { _ = f.Close() }()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Sprintf("file %q is not a regular file", file)
	}
	size := info.Size()
	if size > int64(limit) {
		return nil, fmt.Sprintf("file %q is %d bytes, over the %d-byte limit", file, size, limit)
	}
	data, err := readLimited(f, size+1)
	if err != nil || int64(len(data)) != size {
		return nil, fmt.Sprintf("file %q changed while it was being read", file)
	}
	return data, ""
}

func (t *Tool) describe(skill skills.Skill, folder string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Skill folder: %s\nRelative paths in this skill are relative to that folder.\n\n", folder)
	b.WriteString(skill.Body)
	if !strings.HasSuffix(skill.Body, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(t.listing(folder))
	return b.String()
}

func (t *Tool) listing(folder string) string {
	snap := t.blocked.Current()
	problem := liveProblem(snap, folder)
	if _, ok := configuredBlock(snap, folder); ok && problem == "" {
		problem = "the skill folder is blocked by a blocked_paths entry"
	}
	var root *os.Root
	if problem == "" {
		root, problem = t.acquire(folder)
	}
	if problem != "" {
		return "File list unavailable: " + problem + ".\n"
	}
	defer func() { _ = root.Close() }()
	w := walker{root: root, snap: snap, folder: folder}
	if !w.walk(".", nil) {
		return "File list unavailable: the skill folder could not be read.\n"
	}
	slices.Sort(w.files)

	var b strings.Builder
	if len(w.files) == 0 {
		b.WriteString("The skill folder has no other files.\n")
	} else {
		b.WriteString("Other files in the skill folder (read one with the file argument):\n")
		for _, f := range w.files[:min(len(w.files), maxListed)] {
			fmt.Fprintf(&b, "- %s\n", f)
		}
		if more := len(w.files) - maxListed; more > 0 {
			fmt.Fprintf(&b, "%d more files not listed.\n", more)
		}
	}
	var left []string
	if w.blocked > 0 {
		left = append(left, fmt.Sprintf("%d blocked by blocked_paths", w.blocked))
	}
	if w.outside > 0 {
		left = append(left, fmt.Sprintf("%d unreadable or leading outside the skill folder", w.outside))
	}
	if w.cycles > 0 {
		left = append(left, fmt.Sprintf("%d folder links that loop back", w.cycles))
	}
	if len(left) > 0 {
		fmt.Fprintf(&b, "Left out: %s.\n", strings.Join(left, ", "))
	}
	return b.String()
}

type walker struct {
	root                     *os.Root
	snap                     *permissions.BlockedPaths
	folder                   string
	files                    []string
	blocked, outside, cycles int
}

func (w *walker) walk(rel string, ancestors []fs.FileInfo) bool {
	dir, err := openFile(w.root, rel, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	info, err := dir.Stat()
	if err != nil || !info.IsDir() {
		_ = dir.Close()
		return false
	}
	if slices.ContainsFunc(ancestors, func(a fs.FileInfo) bool { return os.SameFile(a, info) }) {
		_ = dir.Close()
		w.cycles++
		return true
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return false
	}
	ancestors = append(ancestors, info)
	for _, e := range entries {
		child := path.Join(rel, e.Name())
		if _, ok := configuredBlock(w.snap, filepath.Join(w.folder, child)); ok {
			w.blocked++
			continue
		}
		fi, err := w.root.Stat(child)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			w.outside++
		case fi.IsDir():
			if !w.walk(child, ancestors) {
				w.outside++
			}
		case fi.Mode().IsRegular() && child != "SKILL.md":
			w.files = append(w.files, child)
		}
	}
	return true
}

func failResult(msg string) tools.Result {
	return tools.Result{ExitCode: 1, Stderr: []byte(msg + "\n")}
}
