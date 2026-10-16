package permissions

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/paths"
)

type BlockedEntry struct {
	Path   string
	Source string
}

func (e BlockedEntry) Floor() bool { return e.Source == "" }

func ExpandBlockedEntry(home, raw string) (string, error) {
	if raw == "" {
		return "", errors.New("permissions: blocked_paths entry is empty")
	}
	entry := raw
	if runtime.GOOS == "windows" && strings.HasPrefix(raw, `~\`) {
		entry = "~/" + raw[2:]
	}
	expanded, err := paths.Expand(home, entry)
	if err != nil {
		return "", fmt.Errorf("permissions: blocked_paths entry %q: %w", raw, err)
	}
	if !filepath.IsAbs(expanded) {
		return "", fmt.Errorf("permissions: blocked_paths entry %q must be absolute or start with ~/", raw)
	}
	return filepath.Clean(expanded), nil
}

type BlockedReload struct {
	Changed  bool
	Entries  []BlockedEntry
	Problems map[string]string
}

type BlockedPaths struct {
	home        string
	floor       BlockedEntry
	entries     atomic.Pointer[[]BlockedEntry]
	foldCase    bool
	projectRoot string
	reload      func() BlockedReload
	reloading   sync.Mutex
	degraded    atomic.Bool
	notice      atomic.Pointer[func(string)]
	onDegraded  atomic.Pointer[func(bool)]
	sent        map[string]string
}

func NewBlockedPaths(home string, entries []BlockedEntry) *BlockedPaths {
	return newBlockedPaths(home, entries, runtime.GOOS == "darwin" || runtime.GOOS == "windows")
}

func NewLiveBlockedPaths(home, projectRoot string, entries []BlockedEntry, reload func() BlockedReload) *BlockedPaths {
	b := NewBlockedPaths(home, entries)
	b.projectRoot = projectRoot
	b.reload = reload
	return b
}

func newBlockedPaths(home string, entries []BlockedEntry, foldCase bool) *BlockedPaths {
	b := &BlockedPaths{
		home:     home,
		floor:    BlockedEntry{Path: filepath.Join(home, ".codemeld")},
		foldCase: foldCase,
	}
	b.store(entries)
	return b
}

func (b *BlockedPaths) store(entries []BlockedEntry) {
	clone := slices.Clone(entries)
	b.entries.Store(&clone)
}

func (b *BlockedPaths) load() []BlockedEntry {
	if b.reload != nil {
		b.reloading.Lock()
		defer b.reloading.Unlock()
		b.refresh()
	}
	return *b.entries.Load()
}

func (b *BlockedPaths) refresh() {
	r := b.reload()
	if r.Changed {
		b.store(r.Entries)
	}
	degraded := len(r.Problems) > 0
	if b.degraded.Swap(degraded) != degraded {
		if changed := b.onDegraded.Load(); changed != nil {
			(*changed)(degraded)
		}
	}
	b.notify(r.Problems)
}

func (b *BlockedPaths) notify(problems map[string]string) {
	notice := b.notice.Load()
	if notice == nil {
		return
	}
	files := slices.Collect(maps.Keys(problems))
	for file := range b.sent {
		if _, ok := problems[file]; !ok {
			files = append(files, file)
		}
	}
	slices.Sort(files)
	for _, file := range files {
		reason, broken := problems[file]
		last, wasSent := b.sent[file]
		switch {
		case broken && (!wasSent || last != reason):
			(*notice)(fmt.Sprintf("blocked_paths: %s %s; reads outside the project will ask until it is fixed", fserrors.CollapseControls(file), reason))
		case !broken && wasSent:
			(*notice)(fmt.Sprintf("blocked_paths: %s can be read again", fserrors.CollapseControls(file)))
		}
	}
	b.sent = maps.Clone(problems)
}

func (b *BlockedPaths) Current() *BlockedPaths {
	if b == nil {
		return nil
	}
	c := &BlockedPaths{home: b.home, floor: b.floor, foldCase: b.foldCase, projectRoot: b.projectRoot}
	b.reloading.Lock()
	defer b.reloading.Unlock()
	if b.reload != nil {
		b.refresh()
	}
	c.entries.Store(b.entries.Load())
	c.degraded.Store(b.degraded.Load())
	return c
}

func (b *BlockedPaths) Degraded() bool { return b != nil && b.degraded.Load() }

func (b *BlockedPaths) ProjectRoot() string {
	if b == nil {
		return ""
	}
	return b.projectRoot
}

func (b *BlockedPaths) SetNotice(notice func(string)) {
	if b == nil {
		return
	}
	if notice == nil {
		b.notice.Store(nil)
		return
	}
	b.notice.Store(&notice)
}

// Holding the refresh lock makes removal wait out an in-flight refresh, so the old callback never runs after this returns.
func (b *BlockedPaths) SetOnDegradedChange(changed func(degraded bool)) {
	if b == nil {
		return
	}
	b.reloading.Lock()
	defer b.reloading.Unlock()
	if changed == nil {
		b.onDegraded.Store(nil)
		return
	}
	b.onDegraded.Store(&changed)
}

func (b *BlockedPaths) OutsideProject(path string) bool {
	if b.ProjectRoot() == "" {
		return true
	}
	if _, ok := resolveExistingPrefix(withoutDrivePrefix(path)); !ok {
		return true
	}
	roots := blockedForms(b.projectRoot)
	for _, form := range blockedForms(path) {
		if !slices.ContainsFunc(roots, func(root string) bool { return b.inside(form, root) }) {
			return true
		}
	}
	return false
}

func (b *BlockedPaths) Home() string {
	if b == nil {
		return ""
	}
	return b.home
}

func (b *BlockedPaths) FoldCase() bool { return b != nil && b.foldCase }

func RelWithin(base, path string, foldCase bool) (string, bool) {
	b := &BlockedPaths{foldCase: foldCase}
	baseForms := blockedForms(base)
	for _, pathForm := range blockedForms(path) {
		for _, baseForm := range baseForms {
			if b.inside(pathForm, baseForm) {
				return strings.Join(segments(pathForm)[len(segments(baseForm)):], "/"), true
			}
		}
	}
	return "", false
}

func (b *BlockedPaths) Blocking(target string) (BlockedEntry, bool) {
	if b == nil {
		return BlockedEntry{}, false
	}
	return b.first(slices.Concat([]BlockedEntry{b.floor}, b.load()), target, false)
}

// The floor is checked last so a configured entry, whose reason names it, is reported when both lie
// inside target.
func (b *BlockedPaths) BlockedWithin(target string) (BlockedEntry, bool) {
	if b == nil {
		return BlockedEntry{}, false
	}
	return b.first(slices.Concat(b.load(), []BlockedEntry{b.floor}), target, true)
}

type RepositoryEntry struct {
	Entry      BlockedEntry
	Candidates []string
}

func (b *BlockedPaths) Entries() []BlockedEntry {
	if b == nil {
		return nil
	}
	return slices.Concat(b.load(), []BlockedEntry{b.floor})
}

func (b *BlockedPaths) Forms() []string {
	var forms []string
	for _, e := range b.Entries() {
		for _, form := range blockedForms(e.Path) {
			if !slices.Contains(forms, form) {
				forms = append(forms, form)
			}
		}
	}
	return forms
}

func (b *BlockedPaths) InRepository(root string) ([]RepositoryEntry, error) {
	if b == nil {
		return nil, nil
	}
	entries := slices.Concat(b.load(), []BlockedEntry{b.floor})
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	exact := &BlockedPaths{}
	var found []RepositoryEntry
	for _, entry := range entries {
		forms := blockedForms(entry.Path)
		var candidates []string
		for _, form := range forms {
			if exact.inside(form, resolved) {
				candidates = append(candidates, form)
			}
		}
		containsRoot := slices.ContainsFunc(forms, func(form string) bool { return b.inside(resolved, form) })
		foldedInside := slices.ContainsFunc(forms, func(form string) bool { return b.inside(form, resolved) })
		foldedOnDisk := b.foldCase && slices.ContainsFunc(candidates, func(form string) bool { return foldedBelow(resolved, form) })
		if containsRoot || (len(candidates) == 0 && foldedInside) || foldedOnDisk {
			candidates = []string{resolved}
		}
		if len(candidates) > 0 {
			found = append(found, RepositoryEntry{Entry: entry, Candidates: candidates})
		}
	}
	return found, nil
}

func foldedBelow(root, path string) bool {
	dir := root
	for _, part := range segments(path)[len(segments(root)):] {
		f, err := os.Open(dir)
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
		if err != nil {
			return true
		}
		names, err := f.Readdirnames(-1)
		_ = f.Close()
		if err != nil {
			return true
		}
		if slices.Contains(names, part) {
			dir = filepath.Join(dir, part)
			continue
		}
		return slices.ContainsFunc(names, func(name string) bool { return strings.EqualFold(name, part) })
	}
	return false
}

func (b *BlockedPaths) first(entries []BlockedEntry, target string, entryInsideTarget bool) (BlockedEntry, bool) {
	targetForms := blockedForms(target)
	for _, entry := range entries {
		for _, entryForm := range blockedForms(entry.Path) {
			for _, targetForm := range targetForms {
				path, scope := targetForm, entryForm
				if entryInsideTarget {
					path, scope = entryForm, targetForm
				}
				if b.inside(path, scope) {
					return entry, true
				}
			}
		}
	}
	return BlockedEntry{}, false
}

func (b *BlockedPaths) inside(path, scope string) bool {
	pathParts, scopeParts := segments(path), segments(scope)
	if len(pathParts) < len(scopeParts) {
		return false
	}
	for i, part := range scopeParts {
		if part != pathParts[i] && (!b.foldCase || !strings.EqualFold(part, pathParts[i])) {
			return false
		}
	}
	return true
}

func segments(path string) []string {
	sep := string(filepath.Separator)
	return strings.Split(strings.TrimSuffix(filepath.Clean(path), sep), sep)
}

func blockedForms(path string) []string {
	written := filepath.Clean(withoutDrivePrefix(path))
	resolved, ok := resolveExistingPrefix(withoutDrivePrefix(path))
	if !ok {
		return []string{written}
	}
	if resolved = withoutDrivePrefix(resolved); resolved == written {
		return []string{written}
	}
	return []string{written, resolved}
}

// `\\?\C:\x`, `\\.\C:\x` and `\??\C:\x` are Windows spellings of `C:\x`; UNC and volume-GUID prefixes are left alone.
func withoutDrivePrefix(path string) string {
	if vol := filepath.VolumeName(path); len(vol) == 6 && vol[5] == ':' {
		return path[4:]
	}
	return path
}

func resolveExistingPrefix(path string) (string, bool) {
	prefix, rest := path, ""
	for {
		real, err := filepath.EvalSymlinks(prefix)
		if err == nil {
			return filepath.Join(real, rest), true
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", false
		}
		parent, base := filepath.Split(strings.TrimRightFunc(prefix, func(r rune) bool { return r == '/' || r == filepath.Separator }))
		if base == "" {
			return "", false
		}
		rest = filepath.Join(base, rest)
		prefix = parent
	}
}
