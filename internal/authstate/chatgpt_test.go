// Tests for the OpenAI ChatGPT auth-state parser, classifier, and persistence wrappers.
package authstate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
)

// refNow is the fixed clock used to classify expiry deterministically.
var refNow = time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)

const (
	futureExpiry = "2099-01-02T03:04:05Z"
	pastExpiry   = "2000-01-01T00:00:00Z"
)

func writeSettings(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
}

// validDoc returns a settings document whose auth.openai-chatgpt session uses the
// given expiry and otherwise-valid fields.
func validDoc(expiry string) string {
	return "auth:\n  openai-chatgpt:\n" +
		"    access_token: at\n    refresh_token: rt\n" +
		"    expires_at: \"" + expiry + "\"\n    account_id: acct\n"
}

// TestLoad_Classification covers every classification branch with a fixed clock.
func TestLoad_Classification(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want Status
	}{
		{"present", validDoc(futureExpiry), StatusPresent},
		{"expired", validDoc(pastExpiry), StatusExpired},
		{"missing access_token", "auth:\n  openai-chatgpt:\n    refresh_token: rt\n    expires_at: \"" + futureExpiry + "\"\n    account_id: acct\n", StatusInvalid},
		{"missing refresh_token", "auth:\n  openai-chatgpt:\n    access_token: at\n    expires_at: \"" + futureExpiry + "\"\n    account_id: acct\n", StatusInvalid},
		{"missing expires_at", "auth:\n  openai-chatgpt:\n    access_token: at\n    refresh_token: rt\n    account_id: acct\n", StatusInvalid},
		{"missing account_id", "auth:\n  openai-chatgpt:\n    access_token: at\n    refresh_token: rt\n    expires_at: \"" + futureExpiry + "\"\n", StatusInvalid},
		{"wrong-type access_token", "auth:\n  openai-chatgpt:\n    access_token: 12345\n    refresh_token: rt\n    expires_at: \"" + futureExpiry + "\"\n    account_id: acct\n", StatusInvalid},
		{"empty access_token", "auth:\n  openai-chatgpt:\n    access_token: \"\"\n    refresh_token: rt\n    expires_at: \"" + futureExpiry + "\"\n    account_id: acct\n", StatusInvalid},
		{"non-RFC3339 expiry", "auth:\n  openai-chatgpt:\n    access_token: at\n    refresh_token: rt\n    expires_at: not-a-date\n    account_id: acct\n", StatusInvalid},
		{"date-only expiry", "auth:\n  openai-chatgpt:\n    access_token: at\n    refresh_token: rt\n    expires_at: \"2099-01-02\"\n    account_id: acct\n", StatusInvalid},
		{"unsupported extra field", "auth:\n  openai-chatgpt:\n    access_token: at\n    refresh_token: rt\n    expires_at: \"" + futureExpiry + "\"\n    account_id: acct\n    token_type: bearer\n", StatusInvalid},
		{"auth absent", "permissions: []\n", StatusNone},
		{"chatgpt absent", "auth:\n  some-other: {}\n", StatusNone},
		{"chatgpt null", "auth:\n  openai-chatgpt:\n", StatusNone},
		{"auth not a map", "auth: scalar\n", StatusInvalid},
		{"session not a map", "auth:\n  openai-chatgpt: scalar\n", StatusInvalid},
		{"corrupted yaml", "auth:\n  openai-chatgpt: {broken\n", StatusInvalid},
		{"empty file", "", StatusNone},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "settings.yaml")
			writeSettings(t, path, tc.yaml)

			sess, status, err := Load(path, refNow)
			if err != nil {
				t.Fatalf("Load err = %v, want nil", err)
			}
			if status != tc.want {
				t.Fatalf("status = %q, want %q", status, tc.want)
			}
			// Only present/expired return a populated session; everything else
			// must return a zero Session so no partial credential state escapes.
			if tc.want != StatusPresent && tc.want != StatusExpired {
				if sess != (Session{}) {
					t.Fatalf("status %q returned a non-zero session %+v, want zero", status, sess)
				}
			}
		})
	}
}

// TestLoad_PresentReturnsFields confirms the parsed session carries every field
// for a present session.
func TestLoad_PresentReturnsFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	writeSettings(t, path, validDoc(futureExpiry))

	sess, status, err := Load(path, refNow)
	if err != nil || status != StatusPresent {
		t.Fatalf("Load = (%q, %v), want (present, nil)", status, err)
	}
	want := Session{AccessToken: "at", RefreshToken: "rt", ExpiresAt: futureExpiry, AccountID: "acct"}
	if sess != want {
		t.Fatalf("session = %+v, want %+v", sess, want)
	}
}

// TestLoad_ExpiredReturnsRefreshToken confirms an expired session still returns
// the refresh token so a refresh can be attempted.
func TestLoad_ExpiredReturnsRefreshToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	writeSettings(t, path, validDoc(pastExpiry))

	sess, status, err := Load(path, refNow)
	if err != nil || status != StatusExpired {
		t.Fatalf("Load = (%q, %v), want (expired, nil)", status, err)
	}
	if sess.RefreshToken != "rt" || sess.AccountID != "acct" {
		t.Fatalf("expired session lost fields: %+v", sess)
	}
}

// TestLoad_AbsentFile treats a missing settings file as no session, not an error.
func TestLoad_AbsentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.yaml")

	sess, status, err := Load(path, refNow)
	if err != nil || status != StatusNone || sess != (Session{}) {
		t.Fatalf("Load absent = (%+v, %q, %v), want (zero, none, nil)", sess, status, err)
	}
}

// TestLoad_UnreadableFile maps a read failure to StatusInvalid and surfaces the
// OS error (which names only the path, no secrets).
func TestLoad_UnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses mode bits; read failure unobservable")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	writeSettings(t, path, validDoc(futureExpiry))
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	sess, status, err := Load(path, refNow)
	if status != StatusInvalid {
		t.Fatalf("status = %q, want %q", status, StatusInvalid)
	}
	if err == nil {
		t.Fatalf("err = nil, want the read error")
	}
	if sess != (Session{}) {
		t.Fatalf("unreadable file returned a non-zero session %+v", sess)
	}
}

// TestWriteLoad_RoundTripPreservesValues writes a session containing characters
// that force YAML quoting and proves Load reads back all four fields exactly
// (Done-when: write then read preserves every field exactly).
func TestWriteLoad_RoundTripPreservesValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	want := Session{
		AccessToken:  "sk-AB.cd_12/34+=",
		RefreshToken: "rt with spaces: and colon",
		ExpiresAt:    futureExpiry,
		AccountID:    "acct#01HXYZ",
	}

	reason, cat, err := Write(path, want)
	if err != nil || reason != config.ReasonNone || cat != "" {
		t.Fatalf("Write = (%q, %q, %v), want (none, '', nil)", reason, cat, err)
	}

	got, status, lerr := Load(path, refNow)
	if lerr != nil || status != StatusPresent {
		t.Fatalf("Load = (%q, %v), want (present, nil)", status, lerr)
	}
	if got != want {
		t.Fatalf("round-trip mismatch:\n got = %+v\nwant = %+v", got, want)
	}
}

// TestWrite_CreatesAndRewritesAt0600 pins the plaintext-credential file mode for
// auth-state writes on every POSIX target: a Write that creates the settings file
// from absence and a Write that rewrites an existing (deliberately broader-mode)
// file both leave it at exactly 0600, so a stored ChatGPT session is never left
// group/other-readable. Stat reports the recorded mode bits even
// under a root test runner, so this stays observable without a euid skip.
func TestWrite_CreatesAndRewritesAt0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	// Absent-file creation: Write must materialize settings.yaml at 0600.
	if _, _, err := Write(path, Session{AccessToken: "at", RefreshToken: "rt", ExpiresAt: futureExpiry, AccountID: "acct"}); err != nil {
		t.Fatalf("create Write: %v", err)
	}
	if mode := statMode(t, path); mode != 0o600 {
		t.Fatalf("created file mode = %o, want 600", mode)
	}

	// Loosen the mode, then rewrite: the atomic write publishes a fresh inode at
	// 0600, so the broader bits do not survive a re-login write.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod broader: %v", err)
	}
	if _, _, err := Write(path, Session{AccessToken: "at2", RefreshToken: "rt2", ExpiresAt: futureExpiry, AccountID: "acct2"}); err != nil {
		t.Fatalf("rewrite Write: %v", err)
	}
	if mode := statMode(t, path); mode != 0o600 {
		t.Fatalf("rewritten file mode = %o, want 600 (rewrite must re-tighten perms)", mode)
	}
}

func statMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

// TestApplyRefresh_MergeSemantics covers the refresh merge rule: the
// access token and expiry are always replaced; a non-empty rotated refresh token
// replaces the prior one while an empty one preserves it; account_id is preserved;
// and the receiver is not mutated.
func TestApplyRefresh_MergeSemantics(t *testing.T) {
	prior := Session{AccessToken: "old-at", RefreshToken: "old-rt", ExpiresAt: pastExpiry, AccountID: "acct"}

	rotated := prior.ApplyRefresh("new-at", "new-rt", futureExpiry)
	if want := (Session{AccessToken: "new-at", RefreshToken: "new-rt", ExpiresAt: futureExpiry, AccountID: "acct"}); rotated != want {
		t.Errorf("rotated refresh:\n got = %+v\nwant = %+v", rotated, want)
	}

	preserved := prior.ApplyRefresh("new-at", "", futureExpiry)
	if want := (Session{AccessToken: "new-at", RefreshToken: "old-rt", ExpiresAt: futureExpiry, AccountID: "acct"}); preserved != want {
		t.Errorf("non-rotated refresh:\n got = %+v\nwant = %+v", preserved, want)
	}

	if orig := (Session{AccessToken: "old-at", RefreshToken: "old-rt", ExpiresAt: pastExpiry, AccountID: "acct"}); prior != orig {
		t.Errorf("ApplyRefresh mutated its receiver: %+v", prior)
	}
}

// TestApplyRefresh_WriteRoundTripPreservesAccountAndUnrelated proves a refresh
// applied to a stored (expired) session and written back preserves account_id and
// unrelated settings while updating the token fields (Done-when: refresh success
// preserves account_id and unrelated global settings).
func TestApplyRefresh_WriteRoundTripPreservesAccountAndUnrelated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	const unrelated = "# managed settings\n" +
		"provider:\n  openai:\n    base_url: https://api.openai.com/v1\n    api_key: sk-KEEP\n" +
		"permissions: []\n"
	writeSettings(t, path, unrelated+
		"auth:\n  openai-chatgpt:\n    access_token: old-at\n    refresh_token: old-rt\n"+
		"    expires_at: \""+pastExpiry+"\"\n    account_id: acct-keep\n")

	prior, status, _ := Load(path, refNow)
	if status != StatusExpired {
		t.Fatalf("seed status = %q, want expired", status)
	}

	updated := prior.ApplyRefresh("new-at", "new-rt", futureExpiry)
	if _, _, err := Write(path, updated); err != nil {
		t.Fatalf("Write after refresh: %v", err)
	}

	got, status, _ := Load(path, refNow)
	want := Session{AccessToken: "new-at", RefreshToken: "new-rt", ExpiresAt: futureExpiry, AccountID: "acct-keep"}
	if status != StatusPresent || got != want {
		t.Fatalf("reloaded refreshed session = (%q, %+v), want (present, %+v)", status, got, want)
	}

	b, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("read after refresh: %v", rerr)
	}
	body := string(b)
	for _, keep := range []string{"# managed settings", "api_key: sk-KEEP", "permissions:", "base_url: https://api.openai.com/v1"} {
		if !strings.Contains(body, keep) {
			t.Fatalf("refresh write dropped unrelated content %q:\n%s", keep, body)
		}
	}
	if strings.Contains(body, "old-at") {
		t.Errorf("refresh write left the stale access token behind:\n%s", body)
	}
}

// TestWriteThenDelete_LoadReportsNone proves Delete removes the session so a
// subsequent Load reports no session.
func TestWriteThenDelete_LoadReportsNone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	if _, _, err := Write(path, Session{AccessToken: "at", RefreshToken: "rt", ExpiresAt: futureExpiry, AccountID: "acct"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	reason, cat, err := Delete(path)
	if err != nil || reason != config.ReasonNone || cat != "" {
		t.Fatalf("Delete = (%q, %q, %v), want (none, '', nil)", reason, cat, err)
	}

	_, status, lerr := Load(path, refNow)
	if lerr != nil || status != StatusNone {
		t.Fatalf("Load after delete = (%q, %v), want (none, nil)", status, lerr)
	}
}

// TestDelete_PreservesUnrelatedSettings proves logout removes only the
// auth.openai-chatgpt session and leaves API keys, permissions, model state, the
// leading comment, and unrelated provider settings intact (Done-when: logout
// preserves unrelated global settings content).
func TestDelete_PreservesUnrelatedSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	const unrelated = "# managed settings — do not hand-edit blindly\n" +
		"provider:\n  openai:\n    base_url: https://api.openai.com/v1\n    api_key: sk-KEEP\n" +
		"permissions: []\n" +
		"model:\n  active:\n    provider: openai\n    id: gpt-5.5\n    effort: medium\n"
	writeSettings(t, path, unrelated+
		"auth:\n  openai-chatgpt:\n    access_token: ACCESS-SECRET\n    refresh_token: REFRESH-SECRET\n"+
		"    expires_at: \""+futureExpiry+"\"\n    account_id: acct-SECRET\n")

	reason, cat, err := Delete(path)
	if err != nil || reason != config.ReasonNone || cat != "" {
		t.Fatalf("Delete = (%q, %q, %v), want (none, '', nil)", reason, cat, err)
	}

	b, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("read after delete: %v", rerr)
	}
	got := string(b)
	for _, keep := range []string{"# managed settings", "api_key: sk-KEEP", "permissions:", "model:", "active:", "id: gpt-5.5", "effort: medium"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("Delete dropped unrelated content %q:\n%s", keep, got)
		}
	}
	for _, gone := range []string{"openai-chatgpt", "access_token", "ACCESS-SECRET", "REFRESH-SECRET", "acct-SECRET"} {
		if strings.Contains(got, gone) {
			t.Fatalf("Delete left ChatGPT session content %q behind:\n%s", gone, got)
		}
	}
	if _, status, _ := Load(path, refNow); status != StatusNone {
		t.Fatalf("session still present after delete: status = %q", status)
	}
}

// TestDelete_AbsentSessionIsNoOp confirms logout with no stored session succeeds
// and creates no file (logout is idempotent).
func TestDelete_AbsentSessionIsNoOp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	reason, cat, err := Delete(path)
	if err != nil || reason != config.ReasonNone || cat != "" {
		t.Fatalf("Delete absent = (%q, %q, %v), want (none, '', nil)", reason, cat, err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Delete created a file for an absent session: %v", statErr)
	}
}

// TestWrite_FailureLeavesPriorStateUnchanged forces a temp-file fsync failure on a
// re-login write and asserts the previously stored session is unchanged
// (Done-when: failed write leaves prior auth state unchanged).
func TestWrite_FailureLeavesPriorStateUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	prior := Session{AccessToken: "old-at", RefreshToken: "old-rt", ExpiresAt: futureExpiry, AccountID: "old-acct"}
	if _, _, err := Write(path, prior); err != nil {
		t.Fatalf("seed Write: %v", err)
	}

	sentinel := errors.New("forced temp-file sync failure")
	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)

	reason, _, err := Write(path, Session{AccessToken: "new-at", RefreshToken: "new-rt", ExpiresAt: futureExpiry, AccountID: "new-acct"})
	if reason != config.ReasonWriteError {
		t.Fatalf("reason = %q, want %q", reason, config.ReasonWriteError)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel", err)
	}

	restore() // restore the real fsync so the verifying Load can re-read.
	got, status, lerr := Load(path, refNow)
	if lerr != nil || status != StatusPresent {
		t.Fatalf("Load after failed write = (%q, %v), want (present, nil)", status, lerr)
	}
	if got != prior {
		t.Fatalf("failed write changed prior state:\n got = %+v\nwant = %+v", got, prior)
	}
}

// TestWriteDelete_PropagatePersistOutcome confirms the wrappers return
// config.Persist's reason/category/error verbatim via the persist seam.
func TestWriteDelete_PropagatePersistOutcome(t *testing.T) {
	sentinel := errors.New("forced persist failure")
	orig := persist
	t.Cleanup(func() { persist = orig })

	var gotKey string
	var gotVal any
	persist = func(_ string, key string, val any) (config.PersistReason, fserrors.Category, error) {
		gotKey, gotVal = key, val
		return config.ReasonLockTimeout, "", sentinel
	}

	reason, _, err := Write("/x/settings.yaml", Session{AccessToken: "at", RefreshToken: "rt", ExpiresAt: futureExpiry, AccountID: "acct"})
	if reason != config.ReasonLockTimeout || !errors.Is(err, sentinel) {
		t.Fatalf("Write = (%q, %v), want (lock_timeout, sentinel)", reason, err)
	}
	if gotKey != config.KeyAuthOpenAIChatGPT {
		t.Fatalf("Write used key %q, want %q", gotKey, config.KeyAuthOpenAIChatGPT)
	}

	reason, _, err = Delete("/x/settings.yaml")
	if reason != config.ReasonLockTimeout || !errors.Is(err, sentinel) {
		t.Fatalf("Delete = (%q, %v), want (lock_timeout, sentinel)", reason, err)
	}
	if gotVal != config.AuthDelete {
		t.Fatalf("Delete passed val %v, want config.AuthDelete sentinel", gotVal)
	}
}
