// Package permissionpersist persists permission grants.
package permissionpersist

import (
	"errors"
	"io/fs"
	"os"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// lockTimeoutDetail is the exact error_detail the permission_persist_failed
// validator pins for a lock_timeout reason (events.lockTimeoutDetail).
// config.Persist surfaces the raw context-deadline error for lock_timeout, whose
// message differs, so the event substitutes this canonical string.
const lockTimeoutDetail = "lock acquisition timed out"

// persist is a seam over config.Persist so the adapter can be exercised against
// forced reason/category/error outcomes without reproducing config.Persist's own
// filesystem failure modes. Production uses config.Persist unchanged.
var persist = config.Persist

// The created report is derived from a stat taken before the write, outside config.Persist's
// lock window, so two processes creating the file at once may both report it.
func PersistGrantReportingCreate(store *sessions.Store, ui tui.NoticeRenderer, targetPath, requestPath string, entry permissions.PermissionEntry) (permissions.PermissionEntry, bool, error) {
	_, statErr := os.Stat(targetPath)
	absent := errors.Is(statErr, fs.ErrNotExist)
	persisted, err := persistGrant(store, ui, targetPath, requestPath, entry)
	return persisted, absent && err == nil, err
}

func persistGrant(store *sessions.Store, ui tui.NoticeRenderer, targetPath, requestPath string, entry permissions.PermissionEntry) (permissions.PermissionEntry, error) {
	reason, errCat, err := persist(targetPath, config.KeyPermissions, entry)
	if err == nil {
		return entry, nil
	}

	degraded := permissions.DegradeGrant(entry, requestPath)

	subjectKind, scope := entry.Kind, ""
	switch entry.GrantKind {
	case grantKindGlobal:
		scope = requestPath
	case grantKindProject:
		subjectKind, scope = subjectKindHost, entry.HostScope
	}

	if eerr := events.EmitPersistFailed(store, targetPath, entry.GrantKind, subjectKind, entry.Subject,
		string(reason), string(errCat), persistErrorDetail(reason, err), scope); eerr != nil {
		return degraded, eerr
	}
	ui.Notice(tui.RenderPersistFailureNotice(targetPath, string(reason), errCat))
	return degraded, err
}

const (
	grantKindGlobal  = "global"
	grantKindFolder  = "folder"
	grantKindProject = "project"
	subjectKindHost  = "host"
)

// DeleteGrant removes a persisted permission grant from the settings file chosen
// by its grant kind, through the shared config.Persist chokepoint — the same
// sidecar lock, re-read-validate, and atomic replace a grant write takes. It is
// the persistence half of a revoke: the revoke seam binds it with the real
// folder/global settings paths so the grant-kind→file routing lives in one place
// and is not duplicated at the call site (mirroring how persistGrant selects the
// file for a write).
//
// A folder grant is removed from folderSettingsPath; a global grant from
// globalSettingsPath. A session grant is
// never persisted (the on-disk parser rejects session grants), so it is skipped
// with no file write and a nil error; dropping it from the in-memory cache is the
// caller's responsibility. Removing an entry that is absent from the
// target file is itself a clean no-op inside config.Persist. The returned error is
// config.Persist's, surfaced so the caller can render a notice.
func DeleteGrant(ui tui.NoticeRenderer, folderSettingsPath, globalSettingsPath string, entry permissions.PermissionEntry) error {
	var target string
	switch entry.GrantKind {
	case grantKindFolder, grantKindProject:
		target = folderSettingsPath
	case grantKindGlobal:
		target = globalSettingsPath
	default:
		return nil
	}
	_, _, err := persist(target, config.KeyPermissions, config.PermissionDelete(entry.DedupKey()))
	return err
}

// persistErrorDetail returns the event error_detail for a persist failure:
// the canonical lockTimeoutDetail for lock_timeout (whose raw config.Persist error
// message differs from what the events validator pins), and the underlying error's
// message for every other reason so the validator accepts the payload.
// A nil error (not expected on a failure path) yields an empty detail, which
// the validator then rejects rather than silently persisting an inconsistent record.
func persistErrorDetail(reason config.PersistReason, err error) string {
	if reason == config.ReasonLockTimeout {
		return lockTimeoutDetail
	}
	if err != nil {
		return err.Error()
	}
	return ""
}
