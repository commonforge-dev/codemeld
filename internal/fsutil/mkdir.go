// Package fsutil provides shared filesystem helpers: directory creation, atomic-write, and related primitives.
package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"codemeld.dev/codemeld/internal/fserrors"
	"golang.org/x/sys/unix"
)

// EnsureDir creates path (and any missing parents) with mode 0755 if it does not exist. The returned created reports whether the target path was absent before the call. On failure it returns the error category. Intermediate directories are not fsynced.
func EnsureDir(path string) (created bool, cat fserrors.Category, err error) {
	info, statErr := os.Stat(path)
	switch {
	case statErr == nil:
		if !info.IsDir() {
			pe := &os.PathError{Op: "mkdir", Path: path, Err: syscall.ENOTDIR}
			return false, fserrors.CategorizeErrno(pe), pe
		}
		return false, "", nil
	case errors.Is(statErr, fs.ErrNotExist):
		// fall through to MkdirAll
	default:
		return false, fserrors.CategorizeErrno(statErr), statErr
	}

	if mkErr := os.MkdirAll(path, 0o755); mkErr != nil {
		return false, fserrors.CategorizeErrno(mkErr), mkErr
	}
	return true, "", nil
}

// DirSegment reports what EnsureDirAt found or made at one attempted segment. Created is true only when
// this call's Mkdirat made the entry, and Dev/Ino identify the directory that was then re-opened
// O_NOFOLLOW. A record with Created true and a non-zero identity is the only rollback-eligible outcome:
// ownership is proved by that inode identity, never by Path, so a directory swapped in at the same name
// can never be mistaken for one this call made. Dev and Ino are zero when nothing exists to identify.
type DirSegment struct {
	Path    string
	Created bool
	Dev     uint64
	Ino     uint64
}

// DirLifecycle carries EnsureDirAt's optional per-segment hooks so a directory it creates stays
// identifiable after a crash. Intent runs before each Mkdirat; Confirm resolves that intent once the
// segment's outcome is known — with Created and an identity for a directory that now exists, or with
// Created false and a zero identity when the attempt made nothing (an existing segment, or a Mkdirat
// that failed outright). Either hook's error aborts the call the way any other failure does, except on a
// path that is already failing: there the filesystem error is what returns, so a journalling problem
// cannot mask why the descent stopped.
//
// An intent that gets no Confirm — a crash, a fsync failure, or a failure between Mkdirat and the
// re-open — is unrecovered state, not a rollback candidate, and nothing here removes it.
type DirLifecycle struct {
	Intent  func(relPath string) error
	Confirm func(seg DirSegment) error
}

// EnsureDirAt creates relPath (and any missing parent segments) under the already-open, authorized
// directory parentDir, descending one path component at a time relative to a held directory descriptor.
// It is the fd-relative, post-authorization counterpart of EnsureDir: where EnsureDir re-resolves an
// absolute path through os.MkdirAll (and so can be redirected by a symlink or rename swapped in after the
// caller authorized the location), EnsureDirAt never re-resolves by path. Each segment is created with
// unix.Mkdirat and then re-opened with O_DIRECTORY|O_NOFOLLOW before the next segment is created in it, so
// a component that is (or is swapped to) a symlink is rejected with ELOOP and a non-directory component is
// rejected with ENOTDIR — the create can never escape the authorized directory tree. The caller owns
// parentDir and must close it after this call.
//
// relPath must be a clean, relative, slash-separated path of one or more ordinary components; an empty,
// absolute, or ".", "..", empty-, or NUL-containing-segment path is rejected fail-closed with EINVAL before
// any filesystem change. Existing directories are idempotent success: created reports whether the final target segment was
// absent before the call (mirroring EnsureDir). createdDirs lists the slash-joined relative paths (under
// parentDir) of exactly the segments this call created — a segment found already present (EEXIST) is skipped,
// so a caller rolling the create back removes only directories it actually made and never a pre-existing one
// a concurrent process slipped in. It is meaningful only on a nil-error return; the order is shallowest
// first, so a rollback walks it in reverse to unlink deepest child first. Every newly created segment is made
// durable before the call descends into it: the parent directory that received the new entry is fsynced,
// mirroring WriteAtomicCreateAt's parent fsync, so a nested create never reports success with an earlier
// parent entry left unsynced. On parent-fsync failure, leave the newly created segment: unlinking by name
// could remove a concurrent replacement.
//
// hooks is at most one optional DirLifecycle; passing none runs the plain descent. It is variadic so the
// callers that predate the lifecycle hooks keep compiling unchanged.
func EnsureDirAt(parentDir *os.File, relPath string, hooks ...DirLifecycle) (created bool, createdDirs []string, cat fserrors.Category, err error) {
	var lc DirLifecycle
	if len(hooks) > 0 {
		lc = hooks[0]
	}

	segs, ok := relSegments(relPath)
	if !ok {
		e := &os.PathError{Op: "mkdirat", Path: relPath, Err: syscall.EINVAL}
		return false, nil, fserrors.CategorizeErrno(e), e
	}

	info, statErr := parentDir.Stat()
	if statErr != nil {
		return false, nil, fserrors.CategorizeErrno(statErr), statErr
	}
	if !info.IsDir() {
		e := &os.PathError{Op: "mkdirat", Path: parentDir.Name(), Err: syscall.ENOTDIR}
		return false, nil, fserrors.CategorizeErrno(e), e
	}

	cur := parentDir
	var opened []*os.File
	defer func() {
		for _, d := range opened {
			_ = d.Close() //nolint:errcheck // read-only directory descriptors opened only to descend fd-relative
		}
	}()

	for i, seg := range segs {
		dirfd := int(cur.Fd())
		segPath := strings.Join(segs[:i+1], "/")

		if lc.Intent != nil {
			if intentErr := lc.Intent(segPath); intentErr != nil {
				return false, nil, fserrors.CategorizeErrno(intentErr), intentErr
			}
		}

		madeThis := true
		if mkErr := unix.Mkdirat(dirfd, seg, 0o755); mkErr != nil {
			if !errors.Is(mkErr, fs.ErrExist) {
				e := &os.PathError{Op: "mkdirat", Path: seg, Err: mkErr}
				// Nothing was created, so the intent above resolves instead of being left for a consumer
				// to carry as unrecovered state.
				_ = confirmSegment(lc, DirSegment{Path: segPath})
				return false, nil, fserrors.CategorizeErrno(e), e
			}
			madeThis = false // already present; idempotent so long as it is a real directory (checked by the open below)
		}

		// A newly created segment is durable only once the parent that received its directory entry is
		// fsynced. Sync after every create — not only the final segment — so a nested create cannot report
		// success while an earlier parent entry is still unsynced.
		if madeThis {
			if syncErr := syncDir(cur); syncErr != nil {
				return false, nil, fserrors.CategorizeErrno(syncErr), syncErr
			}
		}

		// Re-open the segment relative to the held descriptor. O_NOFOLLOW rejects a symlink (redirection
		// resistance), O_DIRECTORY rejects a non-directory component (fail closed); both bind the next
		// step to this real inode rather than to a re-resolved path string.
		fd, oErr := unix.Openat(dirfd, seg, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if oErr != nil {
			e := &os.PathError{Op: "openat", Path: seg, Err: oErr}
			// A segment this call created but could not re-open has no confirmed identity, so its intent
			// stays open as unrecovered state. One that was already present created nothing to recover.
			if !madeThis {
				_ = confirmSegment(lc, DirSegment{Path: segPath})
			}
			return false, nil, fserrors.CategorizeErrno(e), e
		}
		next := os.NewFile(uintptr(fd), seg)
		opened = append(opened, next)

		if lc.Confirm != nil {
			var st unix.Stat_t
			if fsErr := unix.Fstat(fd, &st); fsErr != nil {
				e := &os.PathError{Op: "fstat", Path: seg, Err: fsErr}
				return false, nil, fserrors.CategorizeErrno(e), e
			}
			rec := DirSegment{Path: segPath, Created: madeThis, Dev: uint64(st.Dev), Ino: uint64(st.Ino)}
			if confErr := lc.Confirm(rec); confErr != nil {
				return false, nil, fserrors.CategorizeErrno(confErr), confErr
			}
		}

		// Record only segments this call actually created (madeThis); an EEXIST segment that a concurrent
		// process — or an earlier call — already placed must not be on the rollback list.
		if madeThis {
			createdDirs = append(createdDirs, segPath)
		}

		cur = next
		created = madeThis
	}

	return created, createdDirs, "", nil
}

func confirmSegment(lc DirLifecycle, seg DirSegment) error {
	if lc.Confirm == nil {
		return nil
	}
	return lc.Confirm(seg)
}

// relSegments splits a clean relative path into its ordinary components. It returns ok=false for an empty
// or absolute path, or any "", ".", "..", or NUL-containing segment, so EnsureDirAt fails closed before
// touching the filesystem instead of letting a traversal or invalid component reach unix.Mkdirat (a NUL
// byte would otherwise be accepted here and only rejected mid-descent by Mkdirat, after an earlier segment
// was already created).
func relSegments(relPath string) (segs []string, ok bool) {
	if relPath == "" || filepath.IsAbs(relPath) {
		return nil, false
	}
	parts := strings.Split(relPath, string(os.PathSeparator))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || strings.ContainsRune(p, 0) {
			return nil, false
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}
