package fsutil

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// MaxVCSEntries and MaxVCSBytes bound the inspection of a project template folder. The entry
// bound counts every directory entry examined, not only the candidates: the loader skips
// directories, so a candidate-only count is no bound at all against a root that creates
// subdirectories ahead of its first template.
const (
	MaxVCSEntries = 64
	MaxVCSBytes   = 256 * 1024
)

// VCSCandidate is one collected project template candidate. Name is an immediate directory
// entry name, never a path.
type VCSCandidate struct {
	Name  string
	Bytes []byte
}

type VCSFailure string

const (
	VCSFailureNone        VCSFailure = ""
	VCSFailureUnreadable  VCSFailure = "unreadable"
	VCSFailureUnsafeEntry VCSFailure = "unsafe_entry"
	VCSFailureEntryLimit  VCSFailure = "entry_limit"
	VCSFailureByteLimit   VCSFailure = "byte_limit"
)

// maxCoveredBytes bounds a covered file so reading terminates against a device or an endlessly
// growing file rather than reading it.
const maxCoveredBytes = 64 * 1024

// statOpened and readCoveredBytes are package-local seams so tests can force races the
// filesystem cannot stage deterministically.
var (
	statOpened       = (*os.File).Stat
	lstatPath        = os.Lstat
	readCoveredBytes = func(f *os.File, limit int64) ([]byte, error) {
		return io.ReadAll(io.LimitReader(f, limit))
	}
	// O_NOFOLLOW is what stops a settings path from redirecting the read to another file,
	// and O_NONBLOCK is what keeps a path replaced with a FIFO from parking the launch in
	// open(2) instead of failing collection.
	openCovered = func(path string) (*os.File, error) {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		return os.NewFile(uintptr(fd), path), nil
	}
	// Resolving an entry through the descriptor of the directory it was enumerated from is
	// what stops the directory pathname being swapped for a symlink after enumeration from
	// redirecting the read.
	openCoveredAt = func(dirfd int, name string) (*os.File, error) {
		fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, &os.PathError{Op: "openat", Path: name, Err: err}
		}
		return os.NewFile(uintptr(fd), name), nil
	}
	// O_DIRECTORY with O_NOFOLLOW is what stops the covered folder itself from being a
	// symlink or a regular file that redirects the enumeration somewhere else.
	openCoveredDir = func(path string) (*os.File, error) {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		return os.NewFile(uintptr(fd), path), nil
	}
)

// ReadSettingsBytes reads the covered settings file under the bound and the descriptor checks the
// trust gate itself uses, so a post-gate consumer never reads bytes the gate would have refused to
// fingerprint. found=false with ok=true is the absent state; ok=false is an inspection failure,
// which no admitted snapshot matches.
func ReadSettingsBytes(path string) (data []byte, found, ok bool) {
	return readCoveredFile(path)
}

// CollectVCSCandidates reads every immediate non-directory entry of dir under the same bounded,
// no-follow, stable-file rules ReadSettingsBytes applies per file, so a caller overlays bytes this
// call read rather than reopening the folder. present=false with no failure is the absent state.
func CollectVCSCandidates(dir string) (files []VCSCandidate, present bool, failure VCSFailure) {
	d, err := openCoveredDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false, VCSFailureNone
	case err != nil:
		return nil, false, VCSFailureUnreadable
	}
	defer func() { _ = d.Close() }()

	// Reading one entry past the bound is what separates an over-limit folder from an
	// exactly-full one, and batched ReadDir is what keeps the read itself bounded:
	// os.ReadDir materializes the entire listing before any limit could apply.
	entries, err := d.ReadDir(MaxVCSEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, VCSFailureUnreadable
	}
	if len(entries) > MaxVCSEntries {
		return nil, false, VCSFailureEntryLimit
	}

	files = make([]VCSCandidate, 0, len(entries))
	read := 0
	dirfd := int(d.Fd())
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, ok := readCoveredEntry(dirfd, entry.Name())
		if !ok {
			return nil, false, VCSFailureUnsafeEntry
		}
		read += len(data)
		if read > MaxVCSBytes {
			return nil, false, VCSFailureByteLimit
		}
		files = append(files, VCSCandidate{Name: entry.Name(), Bytes: data})
	}
	// Batched ReadDir does not sort and os.ReadDir does, so without this the loader's
	// duplicate-name and validation-error reporting would depend on filesystem order.
	slices.SortFunc(files, func(a, b VCSCandidate) int { return strings.Compare(a.Name, b.Name) })
	return files, true, VCSFailureNone
}

func readCoveredFile(path string) (data []byte, found, ok bool) {
	// The open is the only path lookup: a nofollow open rejects a final symlink, live or
	// dangling, rather than following it, and every type and size check below reads the
	// descriptor it returned, so no decision is made about a file this call never opened.
	f, err := openCovered(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false, true
	case err != nil:
		return nil, false, false
	}
	defer func() { _ = f.Close() }()

	data, settled, ok := readStable(f)
	if !ok {
		return nil, false, false
	}
	// A same-length atomic replacement leaves the descriptor untouched, so the path has to
	// be re-resolved without following it and confirmed to still name the file just read.
	current, err := lstatPath(path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(current, settled) {
		return nil, false, false
	}
	return data, true, true
}

// readCoveredEntry applies readCoveredFile's rules to one enumerated directory entry, resolving
// it only through dirfd so neither the entry nor the directory pathname is looked up again.
func readCoveredEntry(dirfd int, name string) (data []byte, ok bool) {
	f, err := openCoveredAt(dirfd, name)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()

	data, settled, ok := readStable(f)
	if !ok {
		return nil, false
	}
	// The descriptor-relative reopen stands in for readCoveredFile's lstat: it is the same
	// same-length-replacement check without a second path resolution.
	again, err := openCoveredAt(dirfd, name)
	if err != nil {
		return nil, false
	}
	defer func() { _ = again.Close() }()
	current, err := statOpened(again)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(current, settled) {
		return nil, false
	}
	return data, true
}

func readStable(f *os.File) (data []byte, settled os.FileInfo, ok bool) {
	opened, err := statOpened(f)
	if err != nil || !opened.Mode().IsRegular() || opened.Size() > maxCoveredBytes {
		return nil, nil, false
	}
	size := opened.Size()
	// Reading one byte past the snapshotted size turns a file that grew or was replaced
	// under the open descriptor into a failure instead of a fingerprint over partial bytes.
	data, err = readCoveredBytes(f, size+1)
	if err != nil || int64(len(data)) != size {
		return nil, nil, false
	}

	// A same-length rewrite in place leaves both the length and the path identity intact,
	// so the descriptor's own mutation metadata is what distinguishes it from a stable read.
	settled, err = statOpened(f)
	if err != nil || settled.Size() != size || !settled.ModTime().Equal(opened.ModTime()) {
		return nil, nil, false
	}
	return data, settled, true
}
