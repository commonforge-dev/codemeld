// One-line TUI failure notices with remediation hints.
// These functions return strings only and never touch the session
// record stream, so the user-facing hints stay out of the persisted transcript.
package tui

import (
	"fmt"

	"codemeld.dev/codemeld/internal/fserrors"
)

// NoticeRenderer is the one-line notice sink that surfaces persist-failure and
// session-write-failure notices. *tui.App and the TUI command host satisfy it via
// their Notice method; abstracting it keeps the failure-handling packages testable
// and independent of which surface is active.
type NoticeRenderer interface {
	Notice(text string)
}

// PersistRemediationHint returns the literal remediation hint for a persist or
// session-write failure, chosen per the table. Hints for the
// re-read/lock reasons key on reason alone; hints for the write/rename/
// parent-dir reasons key on the failure's error_category. The hint is literal
// text with no field interpolation.
func PersistRemediationHint(reason string, errCat fserrors.Category) string {
	switch reason {
	case "lock_timeout":
		return "another codemeld process may be writing this file; wait a moment and retry"
	case "lock_acquire_error":
		return "the lock syscall failed before the lock could be held; check that the target file still exists, that the process has not exhausted file descriptors, and that the kernel has free lock structures"
	case "reread_parse_error":
		return "the file's YAML is malformed; inspect and repair it before retrying — the same failure will recur until the file is fixed"
	case "reread_io_error":
		return "check the file is readable and still exists on disk, including parent-directory permissions; the file's contents could not be read after the lock was taken"
	default:
		// write_error, rename_error, parent_dir_error — and any
		// unforeseen reason — resolve their hint from the error_category.
		return categoryRemediationHint(errCat)
	}
}

// categoryRemediationHint maps an error_category to the write/rename/
// parent-dir remediation hint. Categories outside the enumerated
// set (e.g. not_found, in_use) fall to the catch-all line.
func categoryRemediationHint(errCat fserrors.Category) string {
	switch errCat {
	case fserrors.PermissionDenied:
		return "check write permission on the target file and on its parent directory"
	case fserrors.NoSpace:
		return "the target filesystem is out of space; free space and retry"
	case fserrors.ReadOnlyFS:
		return "the target filesystem is read-only; check the mount and retry"
	case fserrors.IOError:
		return "a low-level I/O error occurred; check the system log for hardware or filesystem problems"
	default:
		return "an unexpected file-system error occurred; consult the recorded session event for the underlying OS message"
	}
}

// RenderPersistFailureNotice returns the single logical line for a
// permission_persist_failed degradation: the session-only lead, the
// target path, the failure reason, and the remediation hint. The
// terminal is responsible for wrapping a line wider than its width.
func RenderPersistFailureNotice(targetPath, reason string, errCat fserrors.Category) string {
	return "session-only — failed to persist to " + fserrors.CollapseControls(targetPath) +
		": " + reason +
		" — " + PersistRemediationHint(reason, errCat)
}

// RenderSessionWriteFailedNotice returns the single logical line for a
// session_write_failed event: same shape as the persist notice with
// the "session log unwritable" lead. Only write_error/rename_error/
// parent_dir_error reasons apply to session files.
func RenderSessionWriteFailedNotice(targetPath, reason string, errCat fserrors.Category) string {
	return "session log unwritable — " + fserrors.CollapseControls(targetPath) +
		": " + reason +
		" — " + PersistRemediationHint(reason, errCat)
}

// RenderRevokeSkipNotice returns the single logical line for a grant revoke that
// was skipped because the selected writable settings file does not contain the
// grant. holding is another row with the same grant (zero when none). Unlike
// RenderPersistFailureNotice it claims no session-only degradation — nothing was
// written and the live grant is unchanged.
func RenderRevokeSkipNotice(targetPath string, holding PermissionRow) string {
	lead := "can't revoke — no matching grant in " + fserrors.CollapseControls(targetPath)
	if holding.Layer == "" {
		return lead + "; it is no longer in that file because another writer removed it"
	}
	return lead + "; it is set in the " + string(holding.Layer) + " layer (" +
		fserrors.CollapseControls(holding.Path) + ") and must be removed there"
}

// RenderLocalSettingsIgnoreNotice names the two paths and nothing else: codemeld never reads or
// writes an ignore file, so the notice is the whole mechanism.
func RenderLocalSettingsIgnoreNotice(localPath, lockPath string) string {
	return "created " + fserrors.CollapseControls(localPath) + " and its lock file " +
		fserrors.CollapseControls(lockPath) +
		" — they hold this machine's own approvals and locking state, so add both to this repository's ignore file"
}

// RenderRevokeFailedNotice returns the single logical line for a grant revoke
// whose settings-file write failed. The live grant is deliberately left in place
// so memory and disk stay consistent; the user can retry once the cause is cleared.
func RenderRevokeFailedNotice(targetPath, reason string) string {
	return "revoke failed — could not remove the grant from " + fserrors.CollapseControls(targetPath) +
		": " + fserrors.CollapseControls(reason)
}

func RenderShareRefusedNotice() string {
	return "not shared — sharing is only for a local grant in an approved project"
}

func RenderShareFailedNotice(sharedPath, reason string) string {
	return "share failed — nothing was published to " + fserrors.CollapseControls(sharedPath) +
		": " + fserrors.CollapseControls(reason) +
		"; the grant stays in your local settings and is still in force"
}

func RenderShareLocalRemovalFailedNotice(sharedPath, localPath, reason string, alreadyShared bool) string {
	lead := "shared to " + fserrors.CollapseControls(sharedPath)
	if alreadyShared {
		lead = fserrors.CollapseControls(sharedPath) + " already holds this grant"
	}
	return lead + ", but could not remove it from " + fserrors.CollapseControls(localPath) +
		": " + fserrors.CollapseControls(reason) +
		" — both files hold it and it is still in force; share it again to retry only the removal"
}

func RenderProjectRootMarkerNotice(path string) string {
	return "created " + path + " — this file now marks the launch directory as a project root"
}

// ProviderHint returns the phase-1 provider-failure remediation hint for a
// (phase, reason) pair. HTTP-phase rows additionally key on httpStatus: the
// http_no_body row matches specific 401/403/429 statuses on the event
// path, and the quota_exceeded row matches any 4xx/5xx status. The boolean
// reports whether a hint exists; ambiguous phases (empty_response, stream_drop,
// decode) and unlisted tuples return ("", false) so codemeld stays silent
// rather than guessing.
//
// The quota_exceeded row is a render-only hint reason: the HTTP-error path
// derives it live from the 4xx/5xx status and body and passes it
// straight to the renderer. It is distinct from the durable event, which the
// turn layer persists as provider_request_failed{http,http_error} carrying the
// raw body. So quota_exceeded is not a persisted event reason
// and never arrives here with httpStatus absent (decoded 0). It is keyed on a
// live 4xx/5xx status per a 2026-05-27 user decision.
func ProviderHint(phase, reason string, httpStatus int) (string, bool) {
	switch phase {
	case "http":
		switch reason {
		case "quota_exceeded":
			// Any 4xx/5xx whose body declares quota exhausted (line 120). A
			// 0/absent status is not a real quota case and resolves to no hint.
			if httpStatus >= 400 && httpStatus <= 599 {
				return "the account's provider quota is exhausted; top up the account or switch to a different provider key", true
			}
		case "http_no_body":
			switch httpStatus {
			case 401:
				return "the provider rejected the API key as unauthorized; check `provider.<name>.api_key` and any auth-header override", true
			case 403:
				return "the provider rejected the request as forbidden; the API key may lack access to this model or endpoint", true
			case 429:
				return "the provider returned a rate-limit response; wait a moment and re-issue the turn manually", true
			}
		}
	case "dial":
		switch reason {
		case "dns_error":
			return "DNS resolution for the provider host failed; check the host in `provider.<name>.base_url` and the system resolver", true
		case "connect_refused":
			return "the provider host refused the TCP connection; verify `provider.<name>.base_url` and any local proxy or firewall", true
		}
	case "tls":
		switch reason {
		case "tls_cert_invalid":
			return "the TLS handshake failed because the server certificate did not validate; check the system trust store and any pinned CA", true
		case "tls_cert_expired":
			return "the TLS handshake failed because the server certificate is expired; the server's certificate needs renewal", true
		}
	}
	return "", false
}

// RenderProviderRequestFailedNotice returns the TUI surface for a
// provider_request_failed event. Line 1 is the caller-supplied
// failure line, rendered unchanged — for an HTTP error this is the friendly
// provider message extracted from the body, not the verbatim raw body;
// for transport/body failures it is the synthetic surface. A second "→ hint: "
// line is appended only when ProviderHint matches the (phase, reason[,
// http_status]) tuple; otherwise a single line is returned.
func RenderProviderRequestFailedNotice(verbatim, phase, reason string, httpStatus int) string {
	if hint, ok := ProviderHint(phase, reason, httpStatus); ok {
		return verbatim + "\n→ hint: " + hint
	}
	return verbatim
}

// RenderProviderRequestFailedAfterAttemptsNotice returns the provider failure
// notice used after auto-retry exhausts, prefixing line 1 with the number of
// attempts while preserving the normal phase/reason hint behavior.
func RenderProviderRequestFailedAfterAttemptsNotice(verbatim, phase, reason string, httpStatus, attempts int) string {
	word := "attempts"
	if attempts == 1 {
		word = "attempt"
	}
	return RenderProviderRequestFailedNotice(fmt.Sprintf("failed after %d %s: %s", attempts, word, verbatim), phase, reason, httpStatus)
}
