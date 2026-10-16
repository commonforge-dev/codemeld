// Tests for root-command --resume dispatch and bad-argument rejection.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/bootstrap"
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/model"
)

// stubAuthStatusHome points the auth-status home resolver at home and the clock at
// a fixed instant, restoring both with t.Cleanup. The global settings file lives at
// bootstrap.SettingsPath(home).
func stubAuthStatusHome(t *testing.T, home string, now time.Time) {
	t.Helper()
	prevHome, prevNow := resolveHome, statusNow
	resolveHome = func() (string, error) { return home, nil }
	statusNow = func() time.Time { return now }
	t.Cleanup(func() { resolveHome, statusNow = prevHome, prevNow })
}

// writeGlobalSettings writes body to bootstrap.SettingsPath(home), creating parents.
func writeGlobalSettings(t *testing.T, home, body string) {
	t.Helper()
	path := bootstrap.SettingsPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write settings: %v", err)
	}
}

func TestRun_AuthStatus_Human(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	home := t.TempDir()
	now := time.Now()
	body := "provider:\n  openai:\n    base_url: https://api.openai.com/v1\n    api_key: sk-CONFIGUREDSECRET\n" +
		"auth:\n  openai-chatgpt:\n    access_token: ACCESS-SECRET\n    refresh_token: REFRESH-SECRET\n    expires_at: " +
		now.Add(time.Hour).Format(time.RFC3339) + "\n    account_id: acct-SECRET\n"
	writeGlobalSettings(t, home, body)
	stubAuthStatusHome(t, home, now)

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "status"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "OpenAI Platform: using API key (source: global settings file)") {
		t.Fatalf("platform line missing:\n%s", out)
	}
	if !strings.Contains(out, "OpenAI ChatGPT: local session present") {
		t.Fatalf("chatgpt line missing:\n%s", out)
	}
	for _, secret := range []string{"sk-CONFIGUREDSECRET", "ACCESS-SECRET", "REFRESH-SECRET", "acct-SECRET"} {
		if strings.Contains(out, secret) {
			t.Fatalf("output leaked secret %q:\n%s", secret, out)
		}
	}
}

func TestRun_AuthStatus_JSON(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-ENVSECRET")
	home := t.TempDir() // no settings file: ChatGPT none, Platform env
	now := time.Now()
	stubAuthStatusHome(t, home, now)

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "status", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "sk-ENVSECRET") {
		t.Fatalf("JSON leaked env key:\n%s", stdout.String())
	}
	var decoded struct {
		Providers []struct {
			ID, Kind, Source, State string
			Authenticated           bool
		} `json:"providers"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if len(decoded.Providers) != 2 {
		t.Fatalf("providers = %d, want 2", len(decoded.Providers))
	}
	plat := decoded.Providers[0]
	if plat.ID != "openai" || plat.Kind != "api_key" || plat.Source != "env" || plat.State != "using_api_key" || !plat.Authenticated {
		t.Fatalf("platform JSON = %+v", plat)
	}
	cg := decoded.Providers[1]
	if cg.ID != "openai-chatgpt" || cg.Kind != "chatgpt_subscription" || cg.Source != "none" || cg.State != "no_local_session" || cg.Authenticated {
		t.Fatalf("chatgpt JSON = %+v", cg)
	}
}

func TestRun_AuthStatus_InvalidSessionReported(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	home := t.TempDir()
	now := time.Now()
	// Malformed ChatGPT session (missing fields) must classify as invalid, not error.
	writeGlobalSettings(t, home, "auth:\n  openai-chatgpt:\n    access_token: ONLY-ACCESS\n")
	stubAuthStatusHome(t, home, now)

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "status"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "OpenAI ChatGPT: local session invalid") {
		t.Fatalf("want invalid session line, got:\n%s", stdout.String())
	}
}

func TestRun_AuthStatus_HomeResolveError(t *testing.T) {
	prevHome := resolveHome
	resolveHome = func() (string, error) { return "", errors.New("$HOME unset") }
	t.Cleanup(func() { resolveHome = prevHome })

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "status"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "cannot resolve home directory") {
		t.Fatalf("stderr = %q, want home-resolve line", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout non-empty on error: %q", stdout.String())
	}
}

// usageErrorCase is one CLI usage-error expectation: args that must exit non-zero
// with a stderr substring.
type usageErrorCase struct {
	name    string
	args    []string
	wantSub string
}

// runUsageErrorCases runs each case through the root command, asserting a non-zero
// exit and that stderr contains wantSub. Shared by the auth and sessions
// missing/unknown-subcommand tests (both package cli).
func runUsageErrorCases(t *testing.T, cases []usageErrorCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), tc.args, &stdout, &stderr)
			if code == 0 {
				t.Fatalf("exit = 0, want non-zero (stdout=%q stderr=%q)", stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.wantSub) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tc.wantSub)
			}
		})
	}
}

func TestRun_AuthStatus_UnknownSubcommand(t *testing.T) {
	runUsageErrorCases(t, []usageErrorCase{
		{"unknown auth subcommand", []string{"codemeld", "auth", "bogus"}, "unknown auth subcommand"},
		{"auth without subcommand", []string{"codemeld", "auth"}, "auth requires a subcommand"},
	})
}

// stubNoLaunch points all three bootstrap orchestrator seams at a t.Fatal so a test
// fails loudly if a help form ever reaches the launch/resume dispatch paths instead
// of urfave's help handling (Architecture Review risk: help must not launch).
func stubNoLaunch(t *testing.T) {
	t.Helper()
	prevFresh, prevID, prevPicker := runFreshBootstrap, runResumeWithIDBootstrap, runResumePickerBootstrap
	runFreshBootstrap = func(context.Context, string, bootstrap.FreshSteps) (*bootstrap.BootstrapResult, error) {
		t.Fatal("help form reached the fresh-launch bootstrap")
		return nil, nil
	}
	runResumeWithIDBootstrap = func(context.Context, string, string, bootstrap.ResumeSteps) (*bootstrap.BootstrapResult, error) {
		t.Fatal("help form reached the resume-with-id bootstrap")
		return nil, nil
	}
	runResumePickerBootstrap = func(context.Context, string, bootstrap.ResumeSteps) (*bootstrap.BootstrapResult, error) {
		t.Fatal("help form reached the resume-picker bootstrap")
		return nil, nil
	}
	t.Cleanup(func() {
		runFreshBootstrap, runResumeWithIDBootstrap, runResumePickerBootstrap = prevFresh, prevID, prevPicker
	})
}

// TestRun_RootHelp_AllForms proves `-h`, `--help`, and bare `help` all reach the
// custom root help (overview, launch/--resume usage, an EXAMPLES block, and a
// COMMANDS section listing auth), write it to stdout, exit 0, and never launch.
func TestRun_RootHelp_AllForms(t *testing.T) {
	for _, form := range [][]string{
		{"codemeld", "-h"},
		{"codemeld", "--help"},
		{"codemeld", "help"},
	} {
		t.Run(strings.Join(form, " "), func(t *testing.T) {
			stubNoLaunch(t)
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), form, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			out := stdout.String()
			for _, want := range []string{
				"agentic editor", // overview / NAME line
				"agentic editor: it opens an interactive", // hand-written DESCRIPTION
				"--resume",                        // launch/resume usage
				"resume a specific session by id", // EXAMPLES block
				"EXAMPLES:",
				"COMMANDS:",
				"run the agent once headlessly", // run listed under COMMANDS + EXAMPLES
				// The COMMANDS one-liners are where users actually scan for the tree,
				// so each parent names its own subcommands there.
				"manage OpenAI authentication state: status, login, logout",
				"inspect settings files: check (read-only validation)",
				"list and inspect recorded sessions: list, doctor, show, permissions, research, summary (read-only diagnostics)",
				"codemeld sessions list [--all] [--json]",
				"codemeld config check               validate the global and shared project settings files",
				"codemeld config check <path>        validate one named settings file, without project discovery",
				// The hidden `sessions show` leaf must be discoverable from root help
				// itself, not only from `codemeld sessions -h` or its own leaf -h. Pin the
				// exact invocation (not a bare "show"/"sessions") so the original regression —
				// a leaf with accurate -h text but no root/parent discovery path — cannot recur.
				"codemeld sessions show <session-id|path> [options]",
				"codemeld sessions doctor <session-id|path>",
				"codemeld sessions permissions <session-id|path>",
				// The root screen must say the permissions diagnostic reports revocations too, so a
				// user scanning for that data finds it without opening the leaf help.
				"prompts, decisions, and explicit revocation requests",
				"codemeld sessions research <session-id|path>",
				"codemeld sessions summary <session-id|path>",
				"execution records, permission path scopes, turns, and tokens",
			} {
				if !strings.Contains(out, want) {
					t.Fatalf("root help (%q) missing %q:\n%s", form, want, out)
				}
			}
			if strings.Contains(out, enforce.HelperCommand) {
				t.Fatalf("root help (%q) lists the hidden %s command:\n%s", form, enforce.HelperCommand, out)
			}
		})
	}
}

func TestRun_HiddenConfineCommandRefusesAnInvalidFrame(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdinW.WriteString("xx"); err != nil {
		t.Fatal(err)
	}
	_ = stdinW.Close()
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prevStdin, prevStderr := os.Stdin, os.Stderr
	os.Stdin, os.Stderr = stdinR, stderrW
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", enforce.HelperCommand, "/bin/true", "-h"}, &stdout, &stderr)
	os.Stdin, os.Stderr = prevStdin, prevStderr
	_ = stderrW.Close()
	written, _ := io.ReadAll(stderrR)
	_ = stdinR.Close()
	_ = stderrR.Close()

	if code != enforce.SetupFailureExitCode || !strings.HasPrefix(string(written), "codemeld confinement:") {
		t.Fatalf("exit = %d, stderr = %q, want %d and a codemeld confinement line", code, written, enforce.SetupFailureExitCode)
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatalf("HOME entries = %v (err %v), want nothing created", entries, err)
	}
}

func TestRun_ConfigHelp_AllForms(t *testing.T) {
	configWants := []string{
		"codemeld config check [path]",
		"validate settings files without starting a session",
		"A launch composes up to three settings layers, nearest last: the global file",
		"~/.codemeld/global/settings.yaml, then the project's shared",
		".codemeld/settings.yaml, then the project's .codemeld/settings.local.yaml,",
		"without a subcommand is an error.",
	}
	checkWants := []string{
		"codemeld config check [path]",
		"each layer on its own line as 'path (rules): state'",
		"A launch composes three layers, nearest last: the global file",
		"~/.codemeld/global/settings.yaml, then the project's .codemeld/settings.yaml,",
		"then the project's .codemeld/settings.local.yaml.",
		"With no argument it currently checks only the global file and the project's",
		"does not validate .codemeld/settings.local.yaml.",
		"discovery.boundary",
		"performs no project",
		"which of the two was applied",
		"'ok', 'not present', 'present, not approved', or",
		"An absent file is not a failure",
		"in a directory you have not approved yet is named as such and left unparsed",
		"exits non-zero only when a checked layer fails to load",
		"no settings are applied or cached, and checking a directory never",
		"approves it.",
	}
	type helpCase struct {
		form  []string
		wants []string
	}
	var cases []helpCase
	for _, form := range [][]string{{"codemeld", "config", "-h"}, {"codemeld", "config", "--help"}, {"codemeld", "help", "config"}} {
		cases = append(cases, helpCase{form, configWants})
	}
	for _, form := range [][]string{{"codemeld", "config", "check", "-h"}, {"codemeld", "config", "check", "--help"}, {"codemeld", "help", "config", "check"}} {
		cases = append(cases, helpCase{form, checkWants})
	}
	for _, tt := range cases {
		t.Run(strings.Join(tt.form, " "), func(t *testing.T) {
			stubNoLaunch(t)
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), tt.form, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			for _, want := range tt.wants {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("config help (%q) missing %q:\n%s", tt.form, want, stdout.String())
				}
			}
		})
	}
}

// stubFreshBootstrap overrides the fresh-launch orchestrator seam so the dispatch
// tests exercise the CLI path without running the real orchestrator or touching
// the filesystem, restoring the original with t.Cleanup.
func stubFreshBootstrap(t *testing.T, fn func(context.Context, string, bootstrap.FreshSteps) (*bootstrap.BootstrapResult, error)) {
	t.Helper()
	prev := runFreshBootstrap
	runFreshBootstrap = fn
	t.Cleanup(func() { runFreshBootstrap = prev })
}

// stubResumeWithID / stubResumePicker override the resume orchestrator seams so
// dispatch tests exercise the CLI path without running the real orchestrator,
// restoring the originals with t.Cleanup.
func stubResumeWithID(t *testing.T, fn func(context.Context, string, string, bootstrap.ResumeSteps) (*bootstrap.BootstrapResult, error)) {
	t.Helper()
	prev := runResumeWithIDBootstrap
	runResumeWithIDBootstrap = fn
	t.Cleanup(func() { runResumeWithIDBootstrap = prev })
}

func stubResumePicker(t *testing.T, fn func(context.Context, string, bootstrap.ResumeSteps) (*bootstrap.BootstrapResult, error)) {
	t.Helper()
	prev := runResumePickerBootstrap
	runResumePickerBootstrap = fn
	t.Cleanup(func() { runResumePickerBootstrap = prev })
}

// TestRun_Dispatch_ResumeWithID proves `--resume <id>` reaches the real dispatch
// and invokes the bootstrap with-id entrypoint with that id, the real cwd, and the
// production default steps — not the old print stub. The picker seam must not fire.
func TestRun_Dispatch_ResumeWithID(t *testing.T) {
	var calledWithID bool
	var gotID, gotCwd string
	var gotSteps bool
	stubResumeWithID(t, func(_ context.Context, cwd, id string, steps bootstrap.ResumeSteps) (*bootstrap.BootstrapResult, error) {
		calledWithID = true
		gotCwd = cwd
		gotID = id
		gotSteps = steps.ResolveHome != nil // DefaultResumeSteps wires every field
		return &bootstrap.BootstrapResult{}, nil
	})
	stubResumePicker(t, func(context.Context, string, bootstrap.ResumeSteps) (*bootstrap.BootstrapResult, error) {
		t.Fatal("picker seam fired on the --resume <id> form")
		return nil, nil
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "--resume", "01HXY-abc"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	if !calledWithID {
		t.Fatal("--resume <id> did not invoke the with-id bootstrap entrypoint")
	}
	if gotID != "01HXY-abc" {
		t.Fatalf("id = %q, want %q", gotID, "01HXY-abc")
	}
	if gotCwd == "" {
		t.Fatal("orchestrator received empty cwd")
	}
	if !gotSteps {
		t.Fatal("orchestrator received steps without DefaultResumeSteps wiring")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("unexpected output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

// TestRun_Dispatch_ResumePicker proves no-id `--resume` reaches the bootstrap
// picker entrypoint with the real cwd and the production default steps, and that
// the with-id seam does not fire.
func TestRun_Dispatch_ResumePicker(t *testing.T) {
	var calledPicker bool
	var gotCwd string
	var gotSteps bool
	stubResumePicker(t, func(_ context.Context, cwd string, steps bootstrap.ResumeSteps) (*bootstrap.BootstrapResult, error) {
		calledPicker = true
		gotCwd = cwd
		gotSteps = steps.ResolveHome != nil
		return &bootstrap.BootstrapResult{}, nil
	})
	stubResumeWithID(t, func(context.Context, string, string, bootstrap.ResumeSteps) (*bootstrap.BootstrapResult, error) {
		t.Fatal("with-id seam fired on the no-id --resume form")
		return nil, nil
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "--resume"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	if !calledPicker {
		t.Fatal("--resume (no id) did not invoke the picker bootstrap entrypoint")
	}
	if gotCwd == "" {
		t.Fatal("orchestrator received empty cwd")
	}
	if !gotSteps {
		t.Fatal("orchestrator received steps without DefaultResumeSteps wiring")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("unexpected output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

// TestRun_Resume_ErrorMapping proves the resume path maps orchestrator errors to
// the same exit codes and stderr line shapes as the fresh path (runFresh).
func TestRun_Resume_ErrorMapping(t *testing.T) {
	t.Run("home resolve error", func(t *testing.T) {
		stubResumeWithID(t, func(context.Context, string, string, bootstrap.ResumeSteps) (*bootstrap.BootstrapResult, error) {
			return nil, &bootstrap.HomeResolveError{Err: errors.New("$HOME unset")}
		})
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), []string{"codemeld", "--resume", "id"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		want := "codemeld: cannot resolve home directory: $HOME unset\n"
		if stderr.String() != want {
			t.Fatalf("stderr = %q, want %q", stderr.String(), want)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout non-empty on error: %q", stdout.String())
		}
	})

	t.Run("first-run failed exits quietly", func(t *testing.T) {
		stubResumePicker(t, func(context.Context, string, bootstrap.ResumeSteps) (*bootstrap.BootstrapResult, error) {
			return nil, bootstrap.ErrFirstRunFailed
		})
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), []string{"codemeld", "--resume"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty (runner already printed); got %q", stderr.String())
		}
	})

	t.Run("no-id preflight failure exits quietly", func(t *testing.T) {
		stubResumePicker(t, func(context.Context, string, bootstrap.ResumeSteps) (*bootstrap.BootstrapResult, error) {
			return nil, bootstrap.ErrResumeListPreflight
		})
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), []string{"codemeld", "--resume"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty (preflight already printed); got %q", stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout non-empty on error: %q", stdout.String())
		}
	})

	t.Run("generic bootstrap error", func(t *testing.T) {
		stubResumeWithID(t, func(context.Context, string, string, bootstrap.ResumeSteps) (*bootstrap.BootstrapResult, error) {
			return nil, errors.New("session file is corrupt")
		})
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), []string{"codemeld", "--resume", "id"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		want := "codemeld: session file is corrupt\n"
		if stderr.String() != want {
			t.Fatalf("stderr = %q, want %q", stderr.String(), want)
		}
	})
}

// TestRun_FreshLaunch_InvokesOrchestrator proves the fresh-launch path calls the
// bootstrap orchestrator (with the production default steps and the real cwd)
// and maps a successful run to exit 0, without depending on real leaf steps.
func TestRun_FreshLaunch_InvokesOrchestrator(t *testing.T) {
	var called bool
	var gotCwd string
	var gotSteps bool
	stubFreshBootstrap(t, func(_ context.Context, cwd string, steps bootstrap.FreshSteps) (*bootstrap.BootstrapResult, error) {
		called = true
		gotCwd = cwd
		gotSteps = steps.ResolveHome != nil // DefaultFreshSteps wires every field
		return &bootstrap.BootstrapResult{}, nil
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	if !called {
		t.Fatal("fresh-launch did not invoke the orchestrator")
	}
	if gotCwd == "" {
		t.Fatal("orchestrator received empty cwd")
	}
	if !gotSteps {
		t.Fatal("orchestrator received steps without DefaultFreshSteps wiring")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("unexpected output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

// TestRun_FreshLaunch_HomeResolveError maps a HomeResolveError to the
// step-0a stderr line and exit 1.
func TestRun_FreshLaunch_HomeResolveError(t *testing.T) {
	stubFreshBootstrap(t, func(context.Context, string, bootstrap.FreshSteps) (*bootstrap.BootstrapResult, error) {
		return nil, &bootstrap.HomeResolveError{Err: errors.New("$HOME unset")}
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	want := "codemeld: cannot resolve home directory: $HOME unset\n"
	if stderr.String() != want {
		t.Fatalf("stderr = %q, want %q", stderr.String(), want)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout non-empty on error: %q", stdout.String())
	}
}

// TestRun_FreshLaunch_FirstRunFailedExitsQuietly confirms ErrFirstRunFailed maps
// to exit 1 with no extra CLI stderr line, since the first-run runner already
// printed its OP_FAIL line.
func TestRun_FreshLaunch_FirstRunFailedExitsQuietly(t *testing.T) {
	stubFreshBootstrap(t, func(context.Context, string, bootstrap.FreshSteps) (*bootstrap.BootstrapResult, error) {
		return nil, bootstrap.ErrFirstRunFailed
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty (runner already printed); got %q", stderr.String())
	}
}

func TestRun_FreshLaunch_NoSelectableModelUsesExactLines(t *testing.T) {
	line := "codemeld: no providers configured — add at least one entry under provider: in /home/u/.codemeld/global/settings.yaml"
	stubFreshBootstrap(t, func(context.Context, string, bootstrap.FreshSteps) (*bootstrap.BootstrapResult, error) {
		return nil, &model.NoSelectableModelError{Lines: []string{line}}
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stderr.String() != line+"\n" {
		t.Fatalf("stderr = %q, want %q", stderr.String(), line+"\n")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout non-empty on error: %q", stdout.String())
	}
}

func TestRun_Errors(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		wantStderrSub string
	}{
		{"unknown flag", []string{"codemeld", "--bogus"}, "codemeld:"},
		{"bare positional arg", []string{"codemeld", "some-id"}, "positional arguments require --resume"},
		{"extra positional after resume id", []string{"codemeld", "--resume", "id-a", "id-b"}, "--resume accepts at most one session id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), tt.args, &stdout, &stderr)
			if code == 0 {
				t.Fatalf("exit code = 0, want non-zero (stdout=%q stderr=%q)", stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantStderrSub) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tt.wantStderrSub)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout non-empty on error: %q", stdout.String())
			}
		})
	}
}
