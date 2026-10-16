// Tests for `codemeld auth login` provider routing, interactive gating, the
// store-only-on-success contract, and credential redaction.
package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/authstate"
	"codemeld.dev/codemeld/internal/bootstrap"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/openaiauth"
)

// stubInteractive forces the interactive-context decision and restores it.
func stubInteractive(t *testing.T, v bool) {
	t.Helper()
	prev := isInteractiveContext
	isInteractiveContext = func() bool { return v }
	t.Cleanup(func() { isInteractiveContext = prev })
}

// stubLoginFlow replaces the upstream login orchestration so the command can be
// exercised without real OpenAI network calls, a browser, or a loopback listener.
func stubLoginFlow(t *testing.T, fn func(context.Context, io.Writer) (openaiauth.TokenResult, error)) {
	t.Helper()
	prev := runChatGPTLoginFlow
	runChatGPTLoginFlow = fn
	t.Cleanup(func() { runChatGPTLoginFlow = prev })
}

// stubLoginHome points the home resolver at home for the login path.
func stubLoginHome(t *testing.T, home string) {
	t.Helper()
	prev := resolveHome
	resolveHome = func() (string, error) { return home, nil }
	t.Cleanup(func() { resolveHome = prev })
}

func TestAuthLogin_Success_WritesSessionAt0600(t *testing.T) {
	home := t.TempDir()
	stubLoginHome(t, home)
	stubInteractive(t, true)

	now := time.Now()
	expiry := now.Add(time.Hour).Format(time.RFC3339)
	tok := openaiauth.TokenResult{
		AccessToken:  "ACCESS-SECRET",
		RefreshToken: "REFRESH-SECRET",
		Expiry:       expiry,
		AccountID:    "acct-SECRET",
	}
	stubLoginFlow(t, func(context.Context, io.Writer) (openaiauth.TokenResult, error) {
		return tok, nil
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "login", "openai-chatgpt"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}

	path := bootstrap.SettingsPath(home)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat settings: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("settings mode = %o, want 600", perm)
	}

	sess, status, err := authstate.Load(path, now)
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if status != authstate.StatusPresent {
		t.Fatalf("status = %q, want %q", status, authstate.StatusPresent)
	}
	if sess.AccessToken != "ACCESS-SECRET" || sess.RefreshToken != "REFRESH-SECRET" ||
		sess.ExpiresAt != expiry || sess.AccountID != "acct-SECRET" {
		t.Fatalf("stored session = %+v", sess)
	}

	out := stdout.String() + stderr.String()
	for _, secret := range []string{"ACCESS-SECRET", "REFRESH-SECRET", "acct-SECRET"} {
		if strings.Contains(out, secret) {
			t.Fatalf("command output leaked secret %q:\n%s", secret, out)
		}
	}
}

func TestAuthLogin_Success_PreservesUnrelatedSettings(t *testing.T) {
	home := t.TempDir()
	stubLoginHome(t, home)
	stubInteractive(t, true)

	writeGlobalSettings(t, home,
		"provider:\n  openai:\n    base_url: https://api.openai.com/v1\n    api_key: sk-KEEP\n"+
			"permissions: []\n")

	now := time.Now()
	stubLoginFlow(t, func(context.Context, io.Writer) (openaiauth.TokenResult, error) {
		return openaiauth.TokenResult{
			AccessToken: "A", RefreshToken: "R",
			Expiry: now.Add(time.Hour).Format(time.RFC3339), AccountID: "acct",
		}, nil
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "login", "openai-chatgpt"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}

	path := bootstrap.SettingsPath(home)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if !strings.Contains(string(body), "sk-KEEP") {
		t.Fatalf("unrelated API key was dropped:\n%s", body)
	}
	if _, status, _ := authstate.Load(path, now); status != authstate.StatusPresent {
		t.Fatalf("status = %q, want present", status)
	}
}

// TestAuthLogin_StoresUnderGlobalHomeNotProjectRoot proves the login storage path
// is anchored at the home-global settings file and is never derived from the
// project root: with a project-local .codemeld/settings.yaml present in the
// working directory, a successful login writes only to bootstrap.SettingsPath(home)
// and leaves the project-local file byte-for-byte untouched
// (credentials are global-only and must not land in a project-local file).
func TestAuthLogin_StoresUnderGlobalHomeNotProjectRoot(t *testing.T) {
	home := t.TempDir()
	stubLoginHome(t, home)
	stubInteractive(t, true)

	// A separate working directory carrying a project-local settings file that
	// must never be read from or written to by the login storage path.
	projectDir := t.TempDir()
	projectSettings := filepath.Join(projectDir, ".codemeld", "settings.yaml")
	if err := os.MkdirAll(filepath.Dir(projectSettings), 0o700); err != nil {
		t.Fatalf("mkdir project .codemeld: %v", err)
	}
	const projectBody = "# project-local settings — login must not touch this file\nmodel:\n  active:\n    provider: openai\n    id: gpt-5.5\n    effort: medium\n"
	if err := os.WriteFile(projectSettings, []byte(projectBody), 0o600); err != nil {
		t.Fatalf("seed project settings: %v", err)
	}
	t.Chdir(projectDir)

	now := time.Now()
	expiry := now.Add(time.Hour).Format(time.RFC3339)
	stubLoginFlow(t, func(context.Context, io.Writer) (openaiauth.TokenResult, error) {
		return openaiauth.TokenResult{AccessToken: "A", RefreshToken: "R", Expiry: expiry, AccountID: "acct"}, nil
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "login", "openai-chatgpt"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}

	// The session landed under home, at 0600.
	globalPath := bootstrap.SettingsPath(home)
	if _, status, _ := authstate.Load(globalPath, now); status != authstate.StatusPresent {
		t.Fatalf("global session status = %q, want present", status)
	}
	if info, err := os.Stat(globalPath); err != nil {
		t.Fatalf("stat global settings: %v", err)
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("global settings mode = %o, want 600", perm)
	}

	// The project-local file was neither read into the global path nor mutated.
	after, err := os.ReadFile(projectSettings)
	if err != nil {
		t.Fatalf("read project settings after login: %v", err)
	}
	if string(after) != projectBody {
		t.Fatalf("login mutated the project-local settings file:\nbefore=%q\nafter=%q", projectBody, after)
	}
	if !strings.HasPrefix(globalPath, home) {
		t.Fatalf("global settings path %q is not under home %q", globalPath, home)
	}
}

func TestAuthLogin_Failure_LeavesPriorStateUnchanged(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"upstream", &openaiauth.Error{Kind: openaiauth.KindUpstream, Status: 400, Detail: "OpenAI auth error: invalid_grant"}},
		{"canceled", &openaiauth.Error{Kind: openaiauth.KindCanceled, Detail: "login canceled"}},
		{"timeout", &openaiauth.Error{Kind: openaiauth.KindTimeout, Detail: "login timed out"}},
		{"unsupported", &openaiauth.Error{Kind: openaiauth.KindUnsupported, Detail: "cannot bind loopback callback listener on localhost:1455"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			stubLoginHome(t, home)
			stubInteractive(t, true)

			now := time.Now()
			prior := "auth:\n  openai-chatgpt:\n    access_token: PRIOR-ACCESS\n    refresh_token: PRIOR-REFRESH\n" +
				"    expires_at: " + now.Add(time.Hour).Format(time.RFC3339) + "\n    account_id: PRIOR-ACCT\n"
			writeGlobalSettings(t, home, prior)
			path := bootstrap.SettingsPath(home)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read prior: %v", err)
			}

			stubLoginFlow(t, func(context.Context, io.Writer) (openaiauth.TokenResult, error) {
				return openaiauth.TokenResult{}, tc.err
			})

			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"codemeld", "auth", "login", "openai-chatgpt"}, &stdout, &stderr)
			if code == 0 {
				t.Fatalf("exit = 0, want non-zero")
			}

			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read after: %v", err)
			}
			if string(before) != string(after) {
				t.Fatalf("settings changed on %s failure:\nbefore=%q\nafter=%q", tc.name, before, after)
			}
			if _, status, _ := authstate.Load(path, now); status != authstate.StatusPresent {
				t.Fatalf("prior session lost: status = %q", status)
			}

			out := stdout.String() + stderr.String()
			for _, secret := range []string{"PRIOR-ACCESS", "PRIOR-REFRESH", "PRIOR-ACCT"} {
				if strings.Contains(out, secret) {
					t.Fatalf("output leaked prior secret %q:\n%s", secret, out)
				}
			}
		})
	}
}

func TestAuthLogin_NonInteractive_FailsWithoutBrowserOrDeviceFlow(t *testing.T) {
	home := t.TempDir()
	stubLoginHome(t, home)
	stubInteractive(t, false)
	stubLoginFlow(t, func(context.Context, io.Writer) (openaiauth.TokenResult, error) {
		t.Fatal("login flow started in a non-interactive context")
		return openaiauth.TokenResult{}, nil
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "login", "openai-chatgpt"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero")
	}
	if !strings.Contains(stderr.String(), "interactive terminal") {
		t.Fatalf("stderr = %q, want an actionable interactive-terminal message", stderr.String())
	}
	if _, err := os.Stat(bootstrap.SettingsPath(home)); !os.IsNotExist(err) {
		t.Fatalf("settings file should not exist after a non-interactive failure: err=%v", err)
	}
}

func TestAuthLogin_StorageFailure_ExitsNonZero(t *testing.T) {
	home := t.TempDir()
	stubLoginHome(t, home)
	stubInteractive(t, true)

	now := time.Now()
	stubLoginFlow(t, func(context.Context, io.Writer) (openaiauth.TokenResult, error) {
		return openaiauth.TokenResult{
			AccessToken: "A", RefreshToken: "R",
			Expiry: now.Add(time.Hour).Format(time.RFC3339), AccountID: "acct",
		}, nil
	})

	prev := storeChatGPTSession
	storeChatGPTSession = func(string, authstate.Session) (config.PersistReason, fserrors.Category, error) {
		return config.ReasonWriteError, "", errors.New("disk full")
	}
	t.Cleanup(func() { storeChatGPTSession = prev })

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "login", "openai-chatgpt"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero")
	}
	if !strings.Contains(stderr.String(), "could not save") {
		t.Fatalf("stderr = %q, want a save-failure message", stderr.String())
	}
}

func TestAuthLogin_OpenAI_RejectedWithoutChatGPTLogin(t *testing.T) {
	stubInteractive(t, true)
	stubLoginFlow(t, func(context.Context, io.Writer) (openaiauth.TokenResult, error) {
		t.Fatal("ChatGPT login started for the 'openai' API-key provider")
		return openaiauth.TokenResult{}, nil
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "login", "openai"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero")
	}
	// The exact rejection wording is part of this task's contract; pin the
	// full stderr, including the CLI error path's trailing newline, so it cannot drift.
	const want = "codemeld: 'openai' is the OpenAI Platform provider and uses an OpenAI API key, not a browser login. " +
		"Set OPENAI_API_KEY or configure provider.openai in ~/.codemeld/global/settings.yaml. " +
		"To sign in with a ChatGPT subscription instead, run 'codemeld auth login openai-chatgpt'.\n"
	if got := stderr.String(); got != want {
		t.Fatalf("stderr = %q, want exactly %q", got, want)
	}
}

// TestAuthUsageErrors folds the login and logout validation-error cases into one
// table. Both the login flow and the logout revocation seams are wired to t.Fatal so
// any case that slips past validation into a real auth action fails loudly. Each want
// is the full stderr (incl. the CLI error path's trailing newline) so any byte-level
// drift in the pinned per-command validation wording fails the test.
func TestAuthUsageErrors(t *testing.T) {
	stubLoginFlow(t, func(context.Context, io.Writer) (openaiauth.TokenResult, error) {
		t.Fatal("login flow started on a usage error")
		return openaiauth.TokenResult{}, nil
	})
	stubLogoutRevoke(t, func(_ context.Context, _ string) error {
		t.Fatal("revocation started on a usage error")
		return nil
	})
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"login no provider", []string{"codemeld", "auth", "login"}, "codemeld: auth login requires a provider id; use 'codemeld auth login openai-chatgpt'\n"},
		{"login unknown provider", []string{"codemeld", "auth", "login", "gemini"}, "codemeld: unknown login provider \"gemini\"; use 'codemeld auth login openai-chatgpt'\n"},
		{"login too many args", []string{"codemeld", "auth", "login", "openai-chatgpt", "extra"}, "codemeld: auth login accepts exactly one provider id; got 2 arguments\n"},
		{"logout no provider", []string{"codemeld", "auth", "logout"}, "codemeld: auth logout requires a provider id; use 'codemeld auth logout openai-chatgpt'\n"},
		{"logout unknown provider", []string{"codemeld", "auth", "logout", "gemini"}, "codemeld: unknown logout provider \"gemini\"; use 'codemeld auth logout openai-chatgpt'\n"},
		{"logout too many args", []string{"codemeld", "auth", "logout", "openai-chatgpt", "extra"}, "codemeld: auth logout accepts exactly one provider id; got 2 arguments\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), tc.args, &stdout, &stderr)
			if code == 0 {
				t.Fatalf("exit = 0, want non-zero (stderr=%q)", stderr.String())
			}
			if got := stderr.String(); got != tc.want {
				t.Fatalf("stderr = %q, want exactly %q", got, tc.want)
			}
		})
	}
}

// stubLogoutRevoke replaces the best-effort upstream revocation so logout can be
// exercised without real OpenAI network calls, and restores it.
func stubLogoutRevoke(t *testing.T, fn func(context.Context, string) error) {
	t.Helper()
	prev := revokeChatGPTSession
	revokeChatGPTSession = fn
	t.Cleanup(func() { revokeChatGPTSession = prev })
}

// chatGPTSettingsBody returns a schema-valid settings document carrying an OpenAI
// Platform API key, a permissions list, a leading comment, and an unexpired
// auth.openai-chatgpt session whose fields use the *-SECRET sentinels.
func chatGPTSettingsBody(now time.Time) string {
	return "# managed settings\n" +
		"provider:\n  openai:\n    base_url: https://api.openai.com/v1\n    api_key: sk-KEEP\n" +
		"permissions: []\n" +
		"auth:\n  openai-chatgpt:\n    access_token: ACCESS-SECRET\n    refresh_token: REFRESH-SECRET\n" +
		"    expires_at: " + now.Add(time.Hour).Format(time.RFC3339) + "\n    account_id: acct-SECRET\n"
}

func assertNoLogoutSecrets(t *testing.T, out string) {
	t.Helper()
	for _, secret := range []string{"ACCESS-SECRET", "REFRESH-SECRET", "acct-SECRET"} {
		if strings.Contains(out, secret) {
			t.Fatalf("logout output leaked secret %q:\n%s", secret, out)
		}
	}
}

func TestAuthLogout_RemovesSessionPreservesUnrelated(t *testing.T) {
	home := t.TempDir()
	stubLoginHome(t, home)
	now := time.Now()
	writeGlobalSettings(t, home, chatGPTSettingsBody(now))
	path := bootstrap.SettingsPath(home)

	revoked := false
	stubLogoutRevoke(t, func(_ context.Context, refresh string) error {
		revoked = true
		if refresh != "REFRESH-SECRET" {
			t.Errorf("revocation got refresh token %q, want the stored one", refresh)
		}
		// Revocation must run before local deletion: the session is still on disk.
		if _, status, _ := authstate.Load(path, now); status != authstate.StatusPresent {
			t.Errorf("revocation ran after local deletion: status = %q", status)
		}
		return nil
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "logout", "openai-chatgpt"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	if !revoked {
		t.Fatal("upstream revocation was not attempted before deletion")
	}

	if _, status, _ := authstate.Load(path, now); status != authstate.StatusNone {
		t.Fatalf("session not removed: status = %q", status)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	for _, keep := range []string{"sk-KEEP", "permissions:", "# managed settings"} {
		if !strings.Contains(string(body), keep) {
			t.Fatalf("logout dropped unrelated content %q:\n%s", keep, body)
		}
	}
	assertNoLogoutSecrets(t, stdout.String()+stderr.String())
}

func TestAuthLogout_NoSession_ExitsZeroReportsNoSession(t *testing.T) {
	noRevoke := func(_ context.Context, _ string) error {
		t.Fatal("revocation attempted with no local session")
		return nil
	}

	t.Run("absent file", func(t *testing.T) {
		home := t.TempDir()
		stubLoginHome(t, home)
		stubLogoutRevoke(t, noRevoke)

		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), []string{"codemeld", "auth", "logout", "openai-chatgpt"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "no local session") {
			t.Fatalf("stdout = %q, want a no-local-session report", stdout.String())
		}
		if _, err := os.Stat(bootstrap.SettingsPath(home)); !os.IsNotExist(err) {
			t.Fatalf("logout created a settings file for an absent session: err=%v", err)
		}
	})

	t.Run("file without auth block", func(t *testing.T) {
		home := t.TempDir()
		stubLoginHome(t, home)
		stubLogoutRevoke(t, noRevoke)
		writeGlobalSettings(t, home, "provider:\n  openai:\n    base_url: https://api.openai.com/v1\n    api_key: sk-KEEP\n")
		path := bootstrap.SettingsPath(home)
		before, _ := os.ReadFile(path)

		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), []string{"codemeld", "auth", "logout", "openai-chatgpt"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "no local session") {
			t.Fatalf("stdout = %q, want a no-local-session report", stdout.String())
		}
		after, _ := os.ReadFile(path)
		if string(before) != string(after) {
			t.Fatalf("no-session logout rewrote settings:\nbefore=%q\nafter=%q", before, after)
		}
	})
}

func TestAuthLogout_RevocationFailure_ReportsOnlyLocalRemoved(t *testing.T) {
	home := t.TempDir()
	stubLoginHome(t, home)
	now := time.Now()
	writeGlobalSettings(t, home, chatGPTSettingsBody(now))
	path := bootstrap.SettingsPath(home)

	stubLogoutRevoke(t, func(_ context.Context, _ string) error {
		return &openaiauth.Error{Kind: openaiauth.KindUpstream, Status: 404, Detail: "OpenAI auth request failed"}
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "logout", "openai-chatgpt"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Only local state was removed") {
		t.Fatalf("stdout = %q, want an only-local-state report", out)
	}
	if !strings.Contains(out, "chatgpt.com") || !strings.Contains(out, "platform.openai.com") {
		t.Fatalf("stdout = %q, want a pointer to OpenAI account/app-access controls", out)
	}
	if _, status, _ := authstate.Load(path, now); status != authstate.StatusNone {
		t.Fatalf("local session not removed after revocation failure: status = %q", status)
	}
	assertNoLogoutSecrets(t, stdout.String()+stderr.String())
}

func TestAuthLogout_DeletionFailure_ExitsNonZeroPreservesState(t *testing.T) {
	home := t.TempDir()
	stubLoginHome(t, home)
	now := time.Now()
	writeGlobalSettings(t, home, chatGPTSettingsBody(now))
	path := bootstrap.SettingsPath(home)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read prior: %v", err)
	}

	revoked := false
	stubLogoutRevoke(t, func(_ context.Context, _ string) error { revoked = true; return nil })

	prev := deleteChatGPTSession
	deleteChatGPTSession = func(string) (config.PersistReason, fserrors.Category, error) {
		return config.ReasonWriteError, "", errors.New("disk full")
	}
	t.Cleanup(func() { deleteChatGPTSession = prev })

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "logout", "openai-chatgpt"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero")
	}
	if !revoked {
		t.Fatal("revocation should be attempted before the failing deletion")
	}
	if !strings.Contains(stderr.String(), "could not remove") {
		t.Fatalf("stderr = %q, want a deletion-failure message", stderr.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("deletion failure changed settings:\nbefore=%q\nafter=%q", before, after)
	}
	if _, status, _ := authstate.Load(path, now); status != authstate.StatusPresent {
		t.Fatalf("prior session lost on deletion failure: status = %q", status)
	}
	assertNoLogoutSecrets(t, stdout.String()+stderr.String())
}

func TestAuthLogout_OpenAI_Rejected(t *testing.T) {
	stubLogoutRevoke(t, func(_ context.Context, _ string) error {
		t.Fatal("revocation started for the 'openai' API-key provider")
		return nil
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "logout", "openai"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero")
	}
	// The exact rejection wording is part of this task's contract; pin the
	// full stderr, including the CLI error path's trailing newline, so it cannot drift.
	const want = "codemeld: 'openai' is the OpenAI Platform provider and has no stored login session to remove; " +
		"it uses an OpenAI API key (OPENAI_API_KEY or provider.openai in ~/.codemeld/global/settings.yaml). " +
		"To remove a ChatGPT subscription session, run 'codemeld auth logout openai-chatgpt'.\n"
	if got := stderr.String(); got != want {
		t.Fatalf("stderr = %q, want exactly %q", got, want)
	}
}

// wantAuthLoginHelp byte-pins the full `auth login` help screen, shared by the
// all-forms matrix and the nested-help test so both compare against one contract.
const wantAuthLoginHelp = `NAME:
   codemeld auth login - sign in to a provider that supports browser login (openai-chatgpt)

USAGE:
   codemeld auth login openai-chatgpt

DESCRIPTION:
   Sign in to a provider that supports browser login. The only accepted
   <provider> is openai-chatgpt, which opens a browser sign-in for your own
   OpenAI ChatGPT account (codemeld is not affiliated with or endorsed by
   OpenAI). The session is saved to the global settings file and used only when
   the openai-chatgpt provider is selected.

   The openai (OpenAI Platform) provider uses an API key, not a browser login,
   so it is not a valid argument here; set OPENAI_API_KEY instead.

OPTIONS:
   --help, -h  show help

GLOBAL OPTIONS:
   --resume  resume a prior session; optionally accepts a session id as a positional argument
`

// TestAuthHelp_AllFormsAtEveryLevel proves `-h`, `--help`, and bare `help` reach
// hand-written help and exit 0 at the auth parent and at each of status, login, and
// logout, with the documented provider/flag guidance. The login flow and the
// logout revocation seams are wired to t.Fatal so a help form that accidentally ran
// an auth action (Architecture Review risk) would fail the test.
func TestAuthHelp_AllFormsAtEveryLevel(t *testing.T) {
	stubLoginFlow(t, func(context.Context, io.Writer) (openaiauth.TokenResult, error) {
		t.Fatal("help form started the login flow")
		return openaiauth.TokenResult{}, nil
	})
	stubLogoutRevoke(t, func(context.Context, string) error {
		t.Fatal("help form started upstream revocation")
		return nil
	})

	// wantLoginHelp / wantLogoutHelp byte-pin the full `auth login` / `auth logout`
	// help screen so a refactor that silently rewords or reflows Usage, UsageText,
	// ArgsUsage, or Description fails this test instead of slipping past a substring
	// check. They must equal the current intended output exactly; if a deliberate
	// help change is made, update the source command fields in auth.go and these
	// strings together (do not loosen the comparison). The trailing GLOBAL OPTIONS
	// block is the root --resume flag and is part of every subcommand's help.
	wantLoginHelp := wantAuthLoginHelp
	wantLogoutHelp := `NAME:
   codemeld auth logout - sign out of a provider that supports browser login (openai-chatgpt)

USAGE:
   codemeld auth logout openai-chatgpt

DESCRIPTION:
   Sign out of a provider that supports browser login. The only accepted
   <provider> is openai-chatgpt: it removes the locally stored ChatGPT session
   (after a best-effort upstream revocation) and leaves your API keys,
   permissions, model state, and other settings untouched. It is safe to run
   when no session is stored.

   The openai (OpenAI Platform) provider keeps no login session to remove, so
   it is not a valid argument here.

OPTIONS:
   --help, -h  show help

GLOBAL OPTIONS:
   --resume  resume a prior session; optionally accepts a session id as a positional argument
`

	levels := []struct {
		name string
		base []string
		// want lists substrings every form of this help screen must contain.
		want []string
		// wantExact, when non-empty, pins the complete stdout byte-for-byte. Used for
		// the login/logout screens whose full wording is a stability contract.
		wantExact string
	}{
		{
			name: "auth",
			base: []string{"codemeld", "auth"},
			want: []string{"Inspect and manage how codemeld authenticates", "status", "login", "logout"},
		},
		{
			name: "auth status",
			base: []string{"codemeld", "auth", "status"},
			want: []string{"Report whether codemeld can authenticate", "--json", "without any secrets"},
		},
		{
			name:      "auth login",
			base:      []string{"codemeld", "auth", "login"},
			want:      []string{"only accepted", "openai-chatgpt", "API key"},
			wantExact: wantLoginHelp,
		},
		{
			name:      "auth logout",
			base:      []string{"codemeld", "auth", "logout"},
			want:      []string{"only accepted", "openai-chatgpt", "no login session"},
			wantExact: wantLogoutHelp,
		},
	}
	for _, lvl := range levels {
		for _, flag := range []string{"-h", "--help", "help"} {
			args := append(append([]string{}, lvl.base...), flag)
			t.Run(lvl.name+" "+flag, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				code := Run(context.Background(), args, &stdout, &stderr)
				if code != 0 {
					t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
				}
				out := stdout.String()
				for _, want := range lvl.want {
					if !strings.Contains(out, want) {
						t.Fatalf("%s help missing %q:\n%s", lvl.name, want, out)
					}
				}
				if lvl.wantExact != "" && out != lvl.wantExact {
					t.Fatalf("%s %s help output drifted.\n--- got ---\n%s\n--- want ---\n%s", lvl.name, flag, out, lvl.wantExact)
				}
			})
		}
	}
}

// TestAuthRootListNamesSubcommands proves the root COMMANDS: line for auth — the
// list users actually scan — names its subcommands, and that the nested help form
// reaches an auth leaf rather than reprinting the auth parent screen.
func TestAuthRootListNamesSubcommands(t *testing.T) {
	stubNoLaunch(t)
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"codemeld", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	if want := "manage OpenAI authentication state: status, login, logout"; !strings.Contains(stdout.String(), want) {
		t.Fatalf("root help missing %q:\n%s", want, stdout.String())
	}

	stubLoginFlow(t, func(context.Context, io.Writer) (openaiauth.TokenResult, error) {
		t.Fatal("help form started the login flow")
		return openaiauth.TokenResult{}, nil
	})
	var leafOut, leafErr bytes.Buffer
	if code := Run(context.Background(), []string{"codemeld", "help", "auth", "login"}, &leafOut, &leafErr); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, leafErr.String())
	}
	if got := leafOut.String(); got != wantAuthLoginHelp {
		t.Fatalf("help auth login drifted.\n--- got ---\n%s\n--- want ---\n%s", got, wantAuthLoginHelp)
	}
}

func TestDefaultIsInteractiveContext_CISetIsNonInteractive(t *testing.T) {
	t.Setenv("CI", "true")
	if defaultIsInteractiveContext() {
		t.Fatal("CI set to a non-empty value must be treated as non-interactive")
	}
}
