package bootstrap

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/locks"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/securitystate"
)

func blockedPathsFromLayers(home, projectRoot string, layers []securitystate.LayerSnapshot) (*permissions.BlockedPaths, error) {
	reread := &blockedReread{home: home, projectRoot: projectRoot}
	for _, layer := range layers {
		if layer.Ignored || !knownSettingsLayer(layer.Kind) {
			continue
		}
		file := &blockedSettingsFile{path: layer.Path, kind: layer.Kind, watched: true}
		if layer.Present {
			entries, err := blockedLayerEntries(home, layer.Path, layer.Raw)
			if err != nil {
				return nil, err
			}
			file.entries = entries
		}
		reread.files = append(reread.files, file)
	}
	return permissions.NewLiveBlockedPaths(home, projectRoot, reread.combined(), reread.reload), nil
}

func blockedEntriesFromLayers(home string, layers []securitystate.LayerSnapshot) ([]permissions.BlockedEntry, error) {
	var entries []permissions.BlockedEntry
	for _, layer := range layers {
		if !layer.Present || layer.Ignored || !knownSettingsLayer(layer.Kind) {
			continue
		}
		layerEntries, err := blockedLayerEntries(home, layer.Path, layer.Raw)
		if err != nil {
			return nil, err
		}
		entries = append(entries, layerEntries...)
	}
	return entries, nil
}

func blockedLayerEntries(home, path string, raw map[string]any) ([]permissions.BlockedEntry, error) {
	value, ok := raw["blocked_paths"]
	if !ok {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: blocked_paths must be a list, got %T", path, value)
	}
	var entries []permissions.BlockedEntry
	for i, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s: blocked_paths item %d must be a string, got %T", path, i, item)
		}
		expanded, err := permissions.ExpandBlockedEntry(home, text)
		if err != nil {
			return nil, fmt.Errorf("%s: blocked_paths item %d: %w", path, i, err)
		}
		entries = append(entries, permissions.BlockedEntry{Path: expanded, Source: path})
	}
	return entries, nil
}

type blockedReread struct {
	home        string
	projectRoot string
	files       []*blockedSettingsFile
}

type blockedSettingsFile struct {
	path     string
	kind     securitystate.LayerKind
	watched  bool
	recorded bool
	info     fs.FileInfo
	statErr  error
	entries  []permissions.BlockedEntry
	problem  string
}

func (r *blockedReread) reload() permissions.BlockedReload {
	changed := false
	for _, file := range r.files {
		if !file.watched {
			continue
		}
		info, err := os.Lstat(file.path)
		if file.recorded && file.problem == "" && sameSettingsStat(file.info, file.statErr, info, err) {
			continue
		}
		changed = true
		validate, known := settingsLayerValidator(file.kind)
		switch {
		case !known:
			file.watched = false
			file.entries = nil
			file.problem = ""
		case file.kind == securitystate.LayerGlobal:
			data, found, ok := fsutil.ReadSettingsBytes(file.path)
			r.apply(file, data, found, ok, validate)
			file.record(info, err)
		default:
			r.rereadProject(file, validate)
		}
	}
	if !changed {
		return permissions.BlockedReload{}
	}
	reload := permissions.BlockedReload{Changed: true, Entries: r.combined()}
	for _, file := range r.files {
		if file.problem != "" {
			if reload.Problems == nil {
				reload.Problems = map[string]string{}
			}
			reload.Problems[file.path] = file.problem
		}
	}
	return reload
}

func settingsLayerValidator(kind securitystate.LayerKind) (settingsValidator, bool) {
	switch kind {
	case securitystate.LayerGlobal:
		return config.ValidateGlobalSettingsBytes, true
	case securitystate.LayerProject:
		return config.ValidateProjectSettingsBytes, true
	case securitystate.LayerLocal:
		return config.ValidateLocalSettingsBytes, true
	}
	return nil, false
}

func knownSettingsLayer(kind securitystate.LayerKind) bool {
	_, known := settingsLayerValidator(kind)
	return known
}

func (r *blockedReread) rereadProject(file *blockedSettingsFile, validate settingsValidator) {
	dir, name := filepath.Dir(file.path), filepath.Base(file.path)
	parent, err := openSettingsDir(dir)
	switch {
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.ENOENT):
		before, beforeErr := os.Lstat(file.path)
		data, found, ok := fsutil.ReadSettingsBytes(file.path)
		after, afterErr := os.Lstat(file.path)
		if !sameSettingsStat(before, beforeErr, after, afterErr) {
			return
		}
		r.store(file, data, found, ok, validate)
		file.record(before, beforeErr)
		return
	case err != nil:
		return
	}
	defer func() { _ = parent.Close() }()
	release, _, err := locks.AcquireAt(parent, name+".lock", 0)
	if release == nil {
		if unsafeSettingsLock(err) {
			file.problem = "has an unsafe settings lock file"
		}
		return
	}
	defer release()
	data, info, err := readHeldSettings(parent, name)
	if errors.Is(err, errSettingsChanged) || !sameSettingsDir(parent, dir) {
		return
	}
	r.store(file, data, err == nil, err == nil || errors.Is(err, fs.ErrNotExist), validate)
	file.record(info, err)
}

func (r *blockedReread) store(file *blockedSettingsFile, data []byte, found, ok bool, validate settingsValidator) {
	switch {
	case ok && !found:
		file.problem = ""
		if file.kind == securitystate.LayerLocal {
			file.entries = nil
		}
	default:
		r.apply(file, data, found, ok, validate)
	}
}

func unsafeSettingsLock(err error) bool {
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		return false
	}
	switch pathErr.Op {
	case "openat":
		return slices.ContainsFunc([]error{unix.ELOOP, unix.EISDIR, unix.ENXIO, unix.ENODEV}, func(target error) bool { return errors.Is(pathErr.Err, target) })
	case "fstat":
		return errors.Is(pathErr.Err, unix.EINVAL)
	}
	return false
}

func openSettingsDir(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func sameSettingsDir(held *os.File, path string) bool {
	again, err := openSettingsDir(path)
	if err != nil {
		return false
	}
	defer func() { _ = again.Close() }()
	heldInfo, heldErr := held.Stat()
	againInfo, againErr := again.Stat()
	return heldErr == nil && againErr == nil && os.SameFile(heldInfo, againInfo)
}

const maxSettingsBytes = 64 * 1024

var (
	errSettingsChanged    = errors.New("settings file changed during the read")
	errSettingsUnreadable = errors.New("settings file is not a bounded regular file")

	readHeldSettings  = readSettingsAt
	readSettingsBytes = func(f *os.File, limit int64) ([]byte, error) {
		return io.ReadAll(io.LimitReader(f, limit))
	}
)

func openSettingsAt(dir *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	return os.NewFile(uintptr(fd), name), nil
}

func readSettingsAt(dir *os.File, name string) ([]byte, fs.FileInfo, error) {
	f, err := openSettingsAt(dir, name)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !opened.Mode().IsRegular() || opened.Size() > maxSettingsBytes {
		return nil, nil, errSettingsUnreadable
	}
	data, err := readSettingsBytes(f, opened.Size()+1)
	if err != nil {
		return nil, nil, err
	}
	settled, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) != opened.Size() || settled.Size() != opened.Size() || !settled.ModTime().Equal(opened.ModTime()) {
		return nil, nil, errSettingsChanged
	}
	again, err := openSettingsAt(dir, name)
	if err != nil {
		return nil, nil, errSettingsChanged
	}
	defer func() { _ = again.Close() }()
	current, err := again.Stat()
	if err != nil || !os.SameFile(current, settled) {
		return nil, nil, errSettingsChanged
	}
	return data, settled, nil
}

type settingsValidator func(b []byte, path string) (map[string]any, config.LoadFailure, error)

func (r *blockedReread) apply(file *blockedSettingsFile, data []byte, found, ok bool, validate settingsValidator) {
	entries, problem, rejected := r.parseEntries(file.path, data, found, ok, validate)
	if problem == "" || (file.kind == securitystate.LayerLocal && rejected) {
		file.entries = entries
	}
	file.problem = problem
}

// rejected separates a layer the validator refused, whose entries a local layer then drops, from a
// file that cannot be read or parsed, which keeps its last valid entries.
func (r *blockedReread) parseEntries(path string, data []byte, found, ok bool, validate settingsValidator) (entries []permissions.BlockedEntry, problem string, rejected bool) {
	switch {
	case !ok:
		return nil, "can't be read", false
	case !found:
		return nil, "is missing", false
	}
	raw, category, err := validate(data, path)
	if err != nil {
		if category == config.YAMLParseError {
			return nil, "is not valid YAML", false
		}
		return nil, "doesn't match the settings schema", true
	}
	entries, err = blockedLayerEntries(r.home, path, raw)
	if err != nil {
		return nil, "has an invalid blocked_paths item", false
	}
	return entries, "", false
}

func (r *blockedReread) combined() []permissions.BlockedEntry {
	var entries []permissions.BlockedEntry
	for _, file := range r.files {
		entries = append(entries, file.entries...)
	}
	return entries
}

func (f *blockedSettingsFile) record(info fs.FileInfo, err error) {
	f.recorded = err == nil || errors.Is(err, fs.ErrNotExist)
	f.info, f.statErr = info, err
}

func sameSettingsStat(a fs.FileInfo, aErr error, b fs.FileInfo, bErr error) bool {
	if aErr != nil || bErr != nil {
		return errors.Is(aErr, fs.ErrNotExist) && errors.Is(bErr, fs.ErrNotExist)
	}
	return a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size() && os.SameFile(a, b)
}
