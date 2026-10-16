// Persist an optional metadata.title on a session file under the sidecar lock.
package sessions

import (
	"fmt"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/locks"
)

// SetTitle sets the optional metadata.title on the session file at path and rewrites
// the file atomically. It is the persistence behind the /resume picker's rename action
// an additive metadata field whose non-empty value overrides
// the auto-derived row preview. It returns the error category and a non-nil
// error on failure, or ("", nil) on success.
//
// It takes one non-blocking attempt on the session's dedicated sidecar lock — the same
// target a live resume, an explicit delete, and the retention pruner use (ResumeLockPath) —
// so a rename can never race a resumed session's whole-file flush, another
// rename, or a delete/prune unlink. A lock held by another codemeld instance is refused
// with fserrors.InUse and the file is left unchanged; any other lock-acquire failure
// returns its categorized error.
func SetTitle(path, title string) (fserrors.Category, error) {
	release, reason, lockErr := locks.TryAcquire(ResumeLockPath(path))
	if reason != locks.ReasonNone {
		return lockContentionCategory(path, reason, lockErr)
	}
	defer release()

	sess, _, err := OpenSession(path)
	if err != nil {
		// Includes the version refusal (*VersionError, categorized io_error
		// having no errno) and a vanished/permission-denied read (categorized from the
		// errno). Either way the file is left unchanged.
		return fserrors.CategorizeErrno(err), err
	}
	sess.Metadata.Title = title
	sess.Metadata.TitleSource = userTitleSource(title)

	data, err := Marshal(sess)
	if err != nil {
		return fserrors.IOError, fmt.Errorf("marshal session: %w", err)
	}
	if _, cat, werr := fsutil.WriteAtomic(path, data, sessionFileMode); werr != nil {
		return cat, werr
	}
	return "", nil
}
