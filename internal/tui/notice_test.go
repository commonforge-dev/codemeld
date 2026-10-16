// Tests for remediation-hint selection and notice rendering.
package tui

import (
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/permissions"
)

func TestPersistRemediationHint_ReasonKeyed(t *testing.T) {
	// Reasons whose hint is keyed on reason alone (error_category irrelevant).
	tests := []struct {
		reason string
		want   string
	}{
		{"lock_timeout", "another codemeld process may be writing this file; wait a moment and retry"},
		{"lock_acquire_error", "the lock syscall failed before the lock could be held; check that the target file still exists, that the process has not exhausted file descriptors, and that the kernel has free lock structures"},
		{"reread_parse_error", "the file's YAML is malformed; inspect and repair it before retrying — the same failure will recur until the file is fixed"},
		{"reread_io_error", "check the file is readable and still exists on disk, including parent-directory permissions; the file's contents could not be read after the lock was taken"},
	}
	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			// errCat is passed but must not affect these reasons.
			for _, cat := range []fserrors.Category{fserrors.PermissionDenied, fserrors.IOError, fserrors.NotFound} {
				if got := PersistRemediationHint(tt.reason, cat); got != tt.want {
					t.Fatalf("PersistRemediationHint(%q, %q) = %q, want %q", tt.reason, cat, got, tt.want)
				}
			}
		})
	}
}

func TestPersistRemediationHint_CategoryKeyed(t *testing.T) {
	catTests := []struct {
		cat  fserrors.Category
		want string
	}{
		{fserrors.PermissionDenied, "check write permission on the target file and on its parent directory"},
		{fserrors.NoSpace, "the target filesystem is out of space; free space and retry"},
		{fserrors.ReadOnlyFS, "the target filesystem is read-only; check the mount and retry"},
		{fserrors.IOError, "a low-level I/O error occurred; check the system log for hardware or filesystem problems"},
		{fserrors.NotFound, "an unexpected file-system error occurred; consult the recorded session event for the underlying OS message"},
		{fserrors.InUse, "an unexpected file-system error occurred; consult the recorded session event for the underlying OS message"},
		{fserrors.Category("bogus"), "an unexpected file-system error occurred; consult the recorded session event for the underlying OS message"},
	}
	// Every write/rename/parent-dir reason resolves its hint from error_category.
	for _, reason := range []string{"write_error", "rename_error", "parent_dir_error"} {
		for _, ct := range catTests {
			t.Run(reason+"/"+string(ct.cat), func(t *testing.T) {
				if got := PersistRemediationHint(reason, ct.cat); got != ct.want {
					t.Fatalf("PersistRemediationHint(%q, %q) = %q, want %q", reason, ct.cat, got, ct.want)
				}
			})
		}
	}
}

func TestRenderPersistFailureNotice(t *testing.T) {
	got := RenderPersistFailureNotice("/home/u/.codemeld/global/settings.yaml", "write_error", fserrors.PermissionDenied)
	want := "session-only — failed to persist to /home/u/.codemeld/global/settings.yaml: write_error — check write permission on the target file and on its parent directory"
	if got != want {
		t.Fatalf("RenderPersistFailureNotice = %q, want %q", got, want)
	}
	if strings.Contains(got, "\n") {
		t.Fatalf("persist notice must be a single logical line; got %q", got)
	}
}

func TestRenderPersistFailureNotice_CollapsesPath(t *testing.T) {
	got := RenderPersistFailureNotice("a\tb\nc", "reread_parse_error", fserrors.IOError)
	want := "session-only — failed to persist to a b c: reread_parse_error — the file's YAML is malformed; inspect and repair it before retrying — the same failure will recur until the file is fixed"
	if got != want {
		t.Fatalf("RenderPersistFailureNotice with control chars = %q, want %q", got, want)
	}
}

func TestRenderSessionWriteFailedNotice(t *testing.T) {
	got := RenderSessionWriteFailedNotice("/home/u/.codemeld/sessions/x/s.jsonl", "write_error", fserrors.PermissionDenied)
	want := "session log unwritable — /home/u/.codemeld/sessions/x/s.jsonl: write_error — check write permission on the target file and on its parent directory"
	if got != want {
		t.Fatalf("RenderSessionWriteFailedNotice = %q, want %q", got, want)
	}
	if strings.Contains(got, "\n") {
		t.Fatalf("session-write notice must be a single logical line; got %q", got)
	}
}

func TestRenderRevokeSkipNotice(t *testing.T) {
	lead := "can't revoke — no matching grant in /proj/.codemeld/settings.yaml; "
	for _, tc := range []struct {
		name    string
		holding PermissionRow
		want    string
	}{
		{"holding layer", PermissionRow{Layer: permissions.LayerLocal, Path: "/proj/.codemeld/settings.local.yaml"},
			lead + "it is set in the local layer (/proj/.codemeld/settings.local.yaml) and must be removed there"},
		{"removed by another writer", PermissionRow{},
			lead + "it is no longer in that file because another writer removed it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := RenderRevokeSkipNotice("/proj/.codemeld/settings.yaml", tc.holding)
			if got != tc.want {
				t.Fatalf("RenderRevokeSkipNotice = %q, want %q", got, tc.want)
			}
			if strings.Contains(got, "session-only") || strings.Contains(got, "\n") {
				t.Fatalf("revoke-skip notice must be one line with no session-only claim; got %q", got)
			}
		})
	}
}

func TestRenderRevokeFailedNotice(t *testing.T) {
	got := RenderRevokeFailedNotice("/proj/.codemeld/settings.yaml", "permission denied")
	want := "revoke failed — could not remove the grant from /proj/.codemeld/settings.yaml: permission denied"
	if got != want {
		t.Fatalf("RenderRevokeFailedNotice = %q, want %q", got, want)
	}
	if strings.Contains(got, "session-only") {
		t.Fatalf("revoke-failed notice must not claim session-only degradation; got %q", got)
	}
	// Control chars in the path are collapsed like the other notices.
	if got := RenderRevokeFailedNotice("a\tb\nc", "x"); strings.ContainsAny(got[:strings.Index(got, ": x")], "\t\n") {
		t.Fatalf("revoke-failed notice must collapse control chars in the path; got %q", got)
	}
	// The reason is collapsed too, so a multi-line err.Error() cannot break the single-line contract.
	if got := RenderRevokeFailedNotice("/proj/.codemeld/settings.yaml", "permission\ndenied\ttext"); strings.ContainsAny(got, "\t\n") {
		t.Fatalf("revoke-failed notice must collapse control chars in the reason; got %q", got)
	}
}

func TestRenderShareNotices(t *testing.T) {
	const shared, local = "/proj/.codemeld/settings.yaml", "/proj/.codemeld/settings.local.yaml"
	for _, tc := range []struct {
		name string
		got  string
		want string
	}{
		{
			name: "refused",
			got:  RenderShareRefusedNotice(),
			want: "not shared — sharing is only for a local grant in an approved project",
		},
		{
			name: "shared write failed",
			got:  RenderShareFailedNotice(shared, "permission denied"),
			want: "share failed — nothing was published to /proj/.codemeld/settings.yaml: permission denied; the grant stays in your local settings and is still in force",
		},
		{
			name: "local removal failed after a shared write",
			got:  RenderShareLocalRemovalFailedNotice(shared, local, "no space left on device", false),
			want: "shared to /proj/.codemeld/settings.yaml, but could not remove it from /proj/.codemeld/settings.local.yaml: no space left on device — both files hold it and it is still in force; share it again to retry only the removal",
		},
		{
			name: "local removal failed after a skipped shared write",
			got:  RenderShareLocalRemovalFailedNotice(shared, local, "no space left on device", true),
			want: "/proj/.codemeld/settings.yaml already holds this grant, but could not remove it from /proj/.codemeld/settings.local.yaml: no space left on device — both files hold it and it is still in force; share it again to retry only the removal",
		},
		{
			name: "project-root marker",
			got:  RenderProjectRootMarkerNotice(shared),
			want: "created /proj/.codemeld/settings.yaml — this file now marks the launch directory as a project root",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("notice = %q\nwant     %q", tc.got, tc.want)
			}
		})
	}
	for _, got := range []string{
		RenderShareFailedNotice("a\tb\nc", "x\ny"),
		RenderShareLocalRemovalFailedNotice("a\tb", "c\nd", "x\ny", false),
	} {
		if strings.ContainsAny(got, "\t\n") {
			t.Errorf("share notice must collapse control chars in paths and reason; got %q", got)
		}
	}
}

func TestRenderLocalSettingsIgnoreNotice(t *testing.T) {
	got := RenderLocalSettingsIgnoreNotice("/proj/.codemeld/settings.local.yaml", "/proj/.codemeld/settings.local.yaml.lock")
	for _, want := range []string{
		"/proj/.codemeld/settings.local.yaml",
		"/proj/.codemeld/settings.local.yaml.lock",
		"this machine's own approvals and locking state",
		"ignore file",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("RenderLocalSettingsIgnoreNotice = %q, want it to contain %q", got, want)
		}
	}
	if strings.Contains(got, "\n") {
		t.Fatalf("ignore notice must be a single logical line; got %q", got)
	}
	for _, name := range []string{".hgignore", ".gitignore"} {
		if strings.Contains(got, name) {
			t.Fatalf("ignore notice must name no VCS-specific file; got %q", got)
		}
	}
	if got := RenderLocalSettingsIgnoreNotice("a\tb", "c\nd"); strings.ContainsAny(got, "\t\n") {
		t.Fatalf("ignore notice must collapse control chars in both paths; got %q", got)
	}
}

func TestProviderHint(t *testing.T) {
	tests := []struct {
		name       string
		phase      string
		reason     string
		httpStatus int
		wantHint   string
		wantOK     bool
	}{
		{"http 401", "http", "http_no_body", 401, "the provider rejected the API key as unauthorized; check `provider.<name>.api_key` and any auth-header override", true},
		{"http 403", "http", "http_no_body", 403, "the provider rejected the request as forbidden; the API key may lack access to this model or endpoint", true},
		{"http 429", "http", "http_no_body", 429, "the provider returned a rate-limit response; wait a moment and re-issue the turn manually", true},
		{"http 500 no row", "http", "http_no_body", 500, "", false},
		{"dial dns", "dial", "dns_error", 0, "DNS resolution for the provider host failed; check the host in `provider.<name>.base_url` and the system resolver", true},
		{"dial refused", "dial", "connect_refused", 0, "the provider host refused the TCP connection; verify `provider.<name>.base_url` and any local proxy or firewall", true},
		{"unknown phase", "weird", "whatever", 0, "", false},
		{"empty_response no hint", "empty_response", "no_content", 0, "", false},
		{"stream_drop no hint", "stream_drop", "drop", 0, "", false},
		{"decode no hint", "decode", "bad_json", 0, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ProviderHint(tt.phase, tt.reason, tt.httpStatus)
			if got != tt.wantHint || ok != tt.wantOK {
				t.Fatalf("ProviderHint(%q,%q,%d) = (%q,%v), want (%q,%v)", tt.phase, tt.reason, tt.httpStatus, got, ok, tt.wantHint, tt.wantOK)
			}
		})
	}
}

func TestProviderHint_TLSDistinct(t *testing.T) {
	certInvalid, ok := ProviderHint("tls", "tls_cert_invalid", 0)
	if !ok || certInvalid != "the TLS handshake failed because the server certificate did not validate; check the system trust store and any pinned CA" {
		t.Fatalf("tls_cert_invalid = (%q,%v)", certInvalid, ok)
	}
	certExpired, ok := ProviderHint("tls", "tls_cert_expired", 0)
	if !ok || certExpired != "the TLS handshake failed because the server certificate is expired; the server's certificate needs renewal" {
		t.Fatalf("tls_cert_expired = (%q,%v)", certExpired, ok)
	}
	if certInvalid == certExpired {
		t.Fatalf("cert-invalid and cert-expired hints must differ")
	}
	// Generic TLS reasons carry no phase-1 hint.
	for _, r := range []string{"tls_handshake", "tls_other"} {
		if got, ok := ProviderHint("tls", r, 0); ok || got != "" {
			t.Fatalf("ProviderHint(tls,%q) = (%q,%v), want no hint", r, got, ok)
		}
	}
}

func TestProviderHint_Quota(t *testing.T) {
	const wantQuota = "the account's provider quota is exhausted; top up the account or switch to a different provider key"
	// quota_exceeded is keyed on http_status: it is fed by the
	// HTTP-error path, which always holds a live 4xx/5xx status (line 120
	// "any 4xx/5xx whose body declares quota exhausted"). Per the 2026-05-27
	// user decision it is not a provider_request_failed reason, so an absent
	// (decoded 0) status is not a real quota case.
	for _, status := range []int{400, 402, 403, 429, 500, 503, 599} {
		got, ok := ProviderHint("http", "quota_exceeded", status)
		if !ok || got != wantQuota {
			t.Fatalf("ProviderHint(http,quota_exceeded,%d) = (%q,%v), want quota hint", status, got, ok)
		}
	}
	// Statuses outside the 4xx/5xx band — including absent (0) — yield no hint.
	for _, status := range []int{0, 200, 399, 600} {
		if got, ok := ProviderHint("http", "quota_exceeded", status); ok || got != "" {
			t.Fatalf("ProviderHint(http,quota_exceeded,%d) = (%q,%v), want no hint", status, got, ok)
		}
	}
	// A non-quota status (http_no_body, 500) yields no quota hint.
	if got, ok := ProviderHint("http", "http_no_body", 500); ok || got != "" {
		t.Fatalf("ProviderHint(http,http_no_body,500) = (%q,%v), want no hint", got, ok)
	}
}

func TestRenderProviderRequestFailedNotice_TwoLines(t *testing.T) {
	verbatim := "provider error: 401 Unauthorized"
	got := RenderProviderRequestFailedNotice(verbatim, "http", "http_no_body", 401)
	want := verbatim + "\n→ hint: the provider rejected the API key as unauthorized; check `provider.<name>.api_key` and any auth-header override"
	if got != want {
		t.Fatalf("two-line notice = %q, want %q", got, want)
	}
	if lines := strings.Count(got, "\n"); lines != 1 {
		t.Fatalf("matched provider notice must have exactly two lines; got %d newlines in %q", lines, got)
	}
}

func TestRenderProviderRequestFailedNotice_OneLine(t *testing.T) {
	// Verbatim is rendered unchanged when the lookup misses (no line 2).
	verbatim := "provider error: empty response from upstream"
	got := RenderProviderRequestFailedNotice(verbatim, "empty_response", "no_content", 0)
	if got != verbatim {
		t.Fatalf("unmatched provider notice = %q, want verbatim %q", got, verbatim)
	}
	if strings.Contains(got, "\n") {
		t.Fatalf("unmatched provider notice must be one line; got %q", got)
	}
}

func TestRenderProviderRequestFailedAfterAttemptsNotice(t *testing.T) {
	verbatim := "provider error: 429 rate-limited"
	got := RenderProviderRequestFailedAfterAttemptsNotice(verbatim, "http", "http_no_body", 429, 3)
	want := "failed after 3 attempts: " + verbatim + "\n→ hint: the provider returned a rate-limit response; wait a moment and re-issue the turn manually"
	if got != want {
		t.Fatalf("retry-exhausted notice = %q, want %q", got, want)
	}

	got = RenderProviderRequestFailedAfterAttemptsNotice(verbatim, "empty_response", "no_content", 0, 1)
	want = "failed after 1 attempt: " + verbatim
	if got != want {
		t.Fatalf("singular retry-exhausted notice = %q, want %q", got, want)
	}
}
