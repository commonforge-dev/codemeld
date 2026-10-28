// Package agentinstr discovers and loads AGENTS.md instruction files: the global
// file followed by a farthest-first walk from the launch directory to the
// filesystem root, applying size and readability skips.
package agentinstr

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/fserrors"
)

// Layer values for a LoadEntry: the global file vs. an upward-walked
// ancestor file.
const (
	LayerGlobal = "global"
	LayerWalked = "walked"
)

// Skip reasons recorded when a located AGENTS.md is not loaded.
const (
	SkipSizeLimit  = "size_limit"
	SkipUnreadable = "unreadable"
)

// FileName is the per-directory instruction file looked up during the walk.
const FileName = "AGENTS.md"

// globalRelPath is the global AGENTS.md location relative to the user's home dir.
var globalRelPath = filepath.Join(".codemeld", "global", FileName)

// GlobalPath is the global AGENTS.md path for home, or "" when home is empty. It is the
// same lexical spelling the walk deduplicates against, so a caller classifying entries
// cannot drift from the loader's own dedup.
func GlobalPath(home string) string {
	if home == "" {
		return ""
	}
	return filepath.Join(home, globalRelPath)
}

// Package-local filesystem seams so tests can force readability, size, and
// not-exist outcomes deterministically without chmod (whose effect is
// environment-dependent), matching the seam style in internal/config/discovery.go.
var (
	readDir  = os.ReadDir
	stat     = os.Stat
	lstat    = os.Lstat
	readFile = readRegular
)

var (
	// O_NONBLOCK is what keeps a candidate replaced by a FIFO from parking the walk in
	// open(2) instead of skipping the file.
	openCandidate = func(path string) (*os.File, error) {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		return os.NewFile(uintptr(fd), path), nil
	}
	statOpened  = (*os.File).Stat
	readLimited = func(f *os.File, limit int64) ([]byte, error) {
		return io.ReadAll(io.LimitReader(f, limit))
	}
)

// errSizeLimit reports an opened target whose own size snapshot exceeds the configured
// cap, so a candidate replaced between the first stat and the open is still a size_limit
// skip rather than an unbounded read.
var errSizeLimit = errors.New("agentinstr: file exceeds max_file_bytes")

// readRegular bounds the read so no candidate can block or unbound the walk: only an
// opened regular target is read, only when its own size snapshot is within maxFileBytes,
// and only to that snapshot plus one probe byte, which turns a target that changes type
// or length under the descriptor into an error.
func readRegular(path string, maxFileBytes int) ([]byte, error) {
	f, err := openCandidate(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := statOpened(f)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, &os.PathError{Op: "read", Path: path, Err: syscall.EINVAL}
	}
	size := info.Size()
	if size > int64(maxFileBytes) {
		return nil, errSizeLimit
	}
	data, err := readLimited(f, size+1)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != size {
		return nil, &os.PathError{Op: "read", Path: path, Err: syscall.EIO}
	}
	return data, nil
}

// LoadEntry is one in-memory record of an AGENTS.md candidate that was loaded or
// skipped. The walk runs once per process launch; this record is reused for
// in-process session switches (/clear, fork, in-TUI resume) so the event stream
// can be replayed without re-walking the disk.
type LoadEntry struct {
	Path          string            // cleaned absolute path of the candidate file
	Layer         string            // LayerGlobal | LayerWalked
	LoadOrder     int               // 1-based: global is 1, walked starts at 2
	Skipped       bool              // true when the file was located but not loaded
	SkipReason    string            // SkipSizeLimit | SkipUnreadable when Skipped
	ErrorCategory fserrors.Category // set only for an unreadable skip
	ErrorDetail   string            // set only for an unreadable skip
	Content       []byte            // file bytes when loaded; nil when skipped
}

type SelectionMode int

const (
	DiscoverAll SelectionMode = iota
	DiscoverNone
	DiscoverAllButLaunchDir
	ExplicitFile
)

type Selection struct {
	Mode SelectionMode
	Path string
}

// LoadAgentInstructions performs the once-per-process discovery walk and returns
// the ordered load record. It first considers the global file at
// <home>/.codemeld/global/AGENTS.md (load_order 1 when present or skipped), then
// walks AGENTS.md files from the filesystem root down to launchDir in
// farthest-first order (load_order starting at 2). Candidates are deduplicated by
// cleaned absolute path, so a launch directory inside the global directory yields
// the global file once at load_order 1. Missing files are silently absent and do
// not consume a load_order; a located file larger than maxFileBytes is skipped as
// size_limit; any stat or read failure on a located file is skipped as unreadable
// with its error category; and an unreadable directory is skipped without
// halting the walk. The walk is independent of discovery.boundary: it
// always proceeds to the filesystem root and this function never consults that
// setting. home is the absolute home directory ("" disables the global file).
func LoadAgentInstructions(home, launchDir string, maxFileBytes int, sel Selection) ([]LoadEntry, error) {
	switch sel.Mode {
	case DiscoverAll, DiscoverAllButLaunchDir:
	case DiscoverNone:
		return nil, nil
	case ExplicitFile:
		if !filepath.IsAbs(sel.Path) {
			return nil, fmt.Errorf("agentinstr: explicit AGENTS.md path %q is not absolute", sel.Path)
		}
		if e, ok := loadCandidate(filepath.Clean(sel.Path), LayerWalked, 2, maxFileBytes); ok {
			return []LoadEntry{e}, nil
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("agentinstr: unknown AGENTS.md selection mode %d", sel.Mode)
	}

	anchor, err := filepath.Abs(launchDir)
	if err != nil {
		return nil, fmt.Errorf("agentinstr: resolve launch dir %q: %w", launchDir, err)
	}

	var entries []LoadEntry
	seen := make(map[string]bool)

	if globalPath := GlobalPath(home); globalPath != "" {
		if e, ok := loadCandidate(globalPath, LayerGlobal, 1, maxFileBytes); ok {
			entries = append(entries, e)
			seen[globalPath] = true
		}
	}

	// Ancestor directories from launchDir up to the filesystem root, then
	// reversed so the root is visited first (farthest-first).
	var dirs []string
	for dir := anchor; ; {
		dirs = append(dirs, dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	slices.Reverse(dirs)

	order := 2
	for _, dir := range dirs {
		if sel.Mode == DiscoverAllButLaunchDir && dir == anchor {
			continue
		}
		// an unreadable directory is skipped and the walk continues; no
		// file skip entry is produced for an AGENTS.md we could never have listed.
		if _, derr := readDir(dir); derr != nil {
			continue
		}
		candidate := filepath.Join(dir, FileName)
		if seen[candidate] {
			continue // already loaded via the global slot — dedup by absolute path
		}
		if e, ok := loadCandidate(candidate, LayerWalked, order, maxFileBytes); ok {
			entries = append(entries, e)
			seen[candidate] = true
			order++
		}
	}

	return entries, nil
}

// loadCandidate evaluates a single AGENTS.md path. ok is false when the file does
// not exist (silently absent: no entry, and order is left unconsumed). Otherwise
// it returns a LoadEntry that is loaded (Content set) or skipped (size_limit or
// unreadable). order is the load_order the entry occupies when present.
func loadCandidate(path, layer string, order, maxFileBytes int) (LoadEntry, bool) {
	info, err := stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if _, lerr := lstat(path); lerr != nil {
				return LoadEntry{}, false
			}
		}
		return unreadable(path, layer, order, err), true
	}
	// size > cap skips; a file exactly at the cap is allowed.
	if info.Size() > int64(maxFileBytes) {
		return sizeLimited(path, layer, order), true
	}
	content, rerr := readFile(path, maxFileBytes)
	if rerr != nil {
		if errors.Is(rerr, errSizeLimit) {
			return sizeLimited(path, layer, order), true
		}
		return unreadable(path, layer, order, rerr), true
	}
	return LoadEntry{
		Path:      path,
		Layer:     layer,
		LoadOrder: order,
		Content:   content,
	}, true
}

// sizeLimited builds a skipped LoadEntry for a located file over the configured cap.
func sizeLimited(path, layer string, order int) LoadEntry {
	return LoadEntry{
		Path:       path,
		Layer:      layer,
		LoadOrder:  order,
		Skipped:    true,
		SkipReason: SkipSizeLimit,
	}
}

// unreadable builds a skipped LoadEntry for a located file whose stat or read
// failed, carrying the error category and a one-line detail.
func unreadable(path, layer string, order int, err error) LoadEntry {
	return LoadEntry{
		Path:          path,
		Layer:         layer,
		LoadOrder:     order,
		Skipped:       true,
		SkipReason:    SkipUnreadable,
		ErrorCategory: fserrors.CategorizeErrno(err),
		ErrorDetail:   err.Error(),
	}
}
