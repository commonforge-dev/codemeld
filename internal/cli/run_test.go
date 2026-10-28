package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/bootstrap"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/turn"
	ucli "github.com/urfave/cli/v3"
)

// stubHeadlessBootstrap overrides the headless bootstrap seam so the run tests exercise
// the CLI path without running the real one-shot bootstrap, restoring the original with
// t.Cleanup.
func stubHeadlessBootstrap(t *testing.T, fn func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error)) {
	t.Helper()
	prev := runHeadlessBootstrap
	runHeadlessBootstrap = fn
	t.Cleanup(func() { runHeadlessBootstrap = prev })
}

// stubStdinIsTerminal overrides the run command's tty seam (and swaps runStdin to an inert
// reader so no test touches real os.Stdin), restoring both with t.Cleanup.
func stubStdinIsTerminal(t *testing.T, isTTY bool) {
	t.Helper()
	prevTTY, prevStdin := stdinIsTerminal, runStdin
	stdinIsTerminal = func() bool { return isTTY }
	runStdin = strings.NewReader("")
	t.Cleanup(func() { stdinIsTerminal, runStdin = prevTTY, prevStdin })
}

// exitCodeOf extracts the exit code a ucli.Exit error carries, or -1 when err is not an
// exit coder.
func exitCodeOf(err error) int {
	var ec ucli.ExitCoder
	if errors.As(err, &ec) {
		return ec.ExitCode()
	}
	return -1
}

func TestSplitProviderModel(t *testing.T) {
	tests := []struct {
		arg          string
		provider, id string
		ok           bool
	}{
		{"openai/gpt-5.5", "openai", "gpt-5.5", true},
		{"openrouter/anthropic/claude-4", "openrouter", "anthropic/claude-4", true}, // split on the FIRST slash only
		{"nope", "", "", false},
		{"/leading", "", "", false},
		{"trailing/", "", "", false},
		{"", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			provider, id, ok := splitProviderModel(tt.arg)
			if ok != tt.ok || provider != tt.provider || id != tt.id {
				t.Fatalf("splitProviderModel(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.arg, provider, id, ok, tt.provider, tt.id, tt.ok)
			}
		})
	}
}

func TestParseModelSelection(t *testing.T) {
	t.Run("unset model returns nil selection", func(t *testing.T) {
		sel, err := parseModelSelection("", "", false)
		if err != nil || sel != nil {
			t.Fatalf("parseModelSelection(\"\", \"\") = (%v, %v), want (nil, nil)", sel, err)
		}
	})
	t.Run("provider effort tokens pass through unchanged", func(t *testing.T) {
		for _, effort := range []string{"high", "max", model.EffortDefault, model.EffortNoReasoning, "ultra"} {
			sel, err := parseModelSelection("openai/gpt-5.5", effort, true)
			if err != nil {
				t.Fatalf("parseModelSelection(_, %q) error = %v, want nil", effort, err)
			}
			if *sel != (model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: effort}) {
				t.Fatalf("selection = %+v, want effort %q preserved", *sel, effort)
			}
		}
	})
	t.Run("model without effort selects the no-reasoning sentinel", func(t *testing.T) {
		sel, err := parseModelSelection("openai/gpt-5.5", "", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sel.Effort != model.EffortNoReasoning {
			t.Fatalf("effort = %q, want %q (the provider token %q is never synthesized)",
				sel.Effort, model.EffortNoReasoning, model.EffortDefault)
		}
	})
	t.Run("explicitly blank effort is exit 2, never no-reasoning", func(t *testing.T) {
		for _, modelFlag := range []string{"openai/gpt-5.5", ""} {
			sel, err := parseModelSelection(modelFlag, "", true)
			if exitCodeOf(err) != 2 {
				t.Fatalf("parseModelSelection(%q, \"\", true) = (%+v, %v) (exit %d), want a usage error (exit 2)",
					modelFlag, sel, err, exitCodeOf(err))
			}
			if sel != nil {
				t.Fatalf("selection = %+v, want nil (a blank effort must not synthesize %q)", *sel, model.EffortNoReasoning)
			}
		}
	})
	t.Run("malformed model is exit 2", func(t *testing.T) {
		_, err := parseModelSelection("noslash", "high", true)
		if exitCodeOf(err) != 2 {
			t.Fatalf("err = %v (exit %d), want a usage error (exit 2)", err, exitCodeOf(err))
		}
	})
	t.Run("effort without model is exit 2", func(t *testing.T) {
		for _, effort := range []string{"high", "max", model.EffortNoReasoning} {
			_, err := parseModelSelection("", effort, true)
			if exitCodeOf(err) != 2 {
				t.Fatalf("parseModelSelection(\"\", %q) = %v (exit %d), want a usage error (exit 2)",
					effort, err, exitCodeOf(err))
			}
		}
	})
}

func TestRun_RunHelp_DescribesDynamicEffort(t *testing.T) {
	stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
		t.Fatal("help reached the headless bootstrap")
		return nil, nil
	})
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"codemeld", "run", "-h"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"advertises",
		"no-reasoning",
		"An omitted --effort means 'no-reasoning'",
		"an empty --effort",
		"or one the selected model does not advertise, is a usage error",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("run help missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "none|minimal|low|medium|high|xhigh|default") {
		t.Fatalf("run help still advertises the retired static effort enum:\n%s", out)
	}
}

func TestParseRunMode(t *testing.T) {
	tests := []struct {
		arg string
		key string
		ok  bool // ok=false means a usage error (exit 2)
	}{
		{"", "", true},
		{"plan", "plan", true},
		{"build", "build", true},
		{"auto-edits", "auto_edits", true}, // CLI spelling → internal key
		{"auto_edits", "", false},          // the internal key is not the accepted CLI spelling
		{"sideways", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			key, err := parseRunMode(tt.arg)
			if tt.ok {
				if err != nil || key != tt.key {
					t.Fatalf("parseRunMode(%q) = (%q, %v), want (%q, nil)", tt.arg, key, err, tt.key)
				}
				return
			}
			if exitCodeOf(err) != 2 {
				t.Fatalf("parseRunMode(%q) err = %v (exit %d), want exit 2", tt.arg, err, exitCodeOf(err))
			}
		})
	}
}

// TestRun_RunEmptyPrompt_Exit2 proves a run with no prompt is a usage error that exits 2
// and never reaches the bootstrap seam.
func TestRun_RunEmptyPrompt_Exit2(t *testing.T) {
	stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
		t.Fatal("empty prompt reached the headless bootstrap")
		return nil, nil
	})
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "run"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (usage error)", code)
	}
	if !strings.Contains(stderr.String(), "requires a prompt") {
		t.Fatalf("stderr = %q, want a prompt usage message", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty (diagnostics go to stderr)", stdout.String())
	}
}

func TestRun_RunInvalidFlags_Exit2(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"bad model", []string{"codemeld", "run", "--model", "noslash", "do it"}},
		{"effort without model", []string{"codemeld", "run", "--effort", "high", "do it"}},
		{"blank effort with model", []string{"codemeld", "run", "--model", "openai/gpt-5.5", "--effort", "", "do it"}},
		{"blank effort without model", []string{"codemeld", "run", "--effort", "", "do it"}},
		{"bad mode", []string{"codemeld", "run", "--mode", "sideways", "do it"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
				t.Fatal("invalid flags reached the headless bootstrap")
				return nil, nil
			})
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), tc.args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit = %d, want 2 (stderr=%q)", code, stderr.String())
			}
		})
	}
}

// TestRun_RunExitCodeMapping pins the headless error→exit mapping: a catalog/picker
// model problem is a usage exit 2, any other bootstrap/provider failure is exit 1, and a
// clean run is exit 0.
func TestRun_RunExitCodeMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"success", nil, 0},
		{"uncatalogued model", bootstrap.ErrModelNotInCatalog, 2},
		{"picker required", bootstrap.ErrModelPickerRequired, 2},
		{"provider failure", errors.New("provider exploded"), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
				return nil, tc.err
			})
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), []string{"codemeld", "run", "hello"}, &stdout, &stderr); code != tc.want {
				t.Fatalf("exit = %d, want %d (stderr=%q)", code, tc.want, stderr.String())
			}
		})
	}
}

func TestRun_PostPlanDispatchFailure_SafeStderrAndNonZeroExit(t *testing.T) {
	sessionID := "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01"
	underlying := errors.New("fork/exec /bin/sh: cat /etc/shadow: authorization: Bearer sk-live-abcdef")
	failure := &turn.DispatchFailure{
		Err:       underlying,
		Reason:    events.DispatchReasonToolDispatchFailed,
		Tool:      "bash",
		SessionID: sessionID,
	}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"returned as itself", failure},
		{"wrapped alongside a flush failure", fmt.Errorf("%w; tool-call failure flush: %w", failure, errors.New("session write failed"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
				return nil, tc.err
			})
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), []string{"codemeld", "run", "hello"}, &stdout, &stderr); code != 1 {
				t.Fatalf("exit = %d, want 1 (stderr=%q)", code, stderr.String())
			}
			out := stderr.String()
			for _, want := range []string{"bash", events.DispatchReasonToolDispatchFailed, "codemeld sessions doctor " + sessionID} {
				if !strings.Contains(out, want) {
					t.Fatalf("stderr missing %q:\n%s", want, out)
				}
			}
			for _, leak := range []string{"sk-live-abcdef", "/etc/shadow", "fork/exec", "session write failed"} {
				if strings.Contains(out, leak) {
					t.Fatalf("stderr leaked %q:\n%s", leak, out)
				}
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
		})
	}
}

// TestRun_RunDenialSummary proves a run that denied at least one call prints a stderr
// summary naming the denied subjects and how to authorize them — never a silent no-op,
// and never on stdout (Done-when 6).
func TestRun_RunDenialSummary(t *testing.T) {
	stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
		return []bootstrap.DeniedCall{
			{Subject: "rm -rf build", Reason: "no approval available in non-interactive run mode", Source: ""},
			{Subject: "edit /etc/hosts", Reason: "no approval available in non-interactive run mode", Source: ""},
		}, nil
	})
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "run", "clean up"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	for _, want := range []string{"denied", "rm -rf build", "edit /etc/hosts", "authorize"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("denial summary missing %q:\n%s", want, stderr.String())
		}
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty (the denial summary belongs on stderr)", stdout.String())
	}
}

// TestRun_RunThreadsParentCancellation proves the run Action derives its run context
// from the caller's context (the Ctrl-C plumbing base): a parent cancelled before the
// run reaches the bootstrap seam already cancelled.
func TestRun_RunThreadsParentCancellation(t *testing.T) {
	var seamErr error
	stubHeadlessBootstrap(t, func(ctx context.Context, _ string, _ bootstrap.FreshSteps, driver *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
		seamErr = ctx.Err()
		if driver == nil {
			t.Error("headless seam received a nil driver")
		}
		return nil, nil
	})
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if code := Run(parent, []string{"codemeld", "run", "hello"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if seamErr == nil {
		t.Fatal("the run context was not cancelled though the parent was; Ctrl-C threading is not wired through the parent context")
	}
}

type stdinTripwire struct{ t *testing.T }

func (r stdinTripwire) Read([]byte) (int, error) {
	r.t.Error("the refused run read stdin — the non-tty gate must reject before any prompt is read")
	return 0, io.EOF
}

// TestRun_PromptForApproval_NonTtyRefused proves --prompt-for-approval with a non-tty stdin
// refuses to start: exit 2 with a clear message, before the bootstrap seam (Done-when 4).
func TestRun_PromptForApproval_NonTtyRefused(t *testing.T) {
	stubStdinIsTerminal(t, false)
	stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
		t.Fatal("non-tty --prompt-for-approval reached the headless bootstrap")
		return nil, nil
	})
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "run", "--prompt-for-approval", "do it"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "terminal") || !strings.Contains(stderr.String(), "tty") {
		t.Fatalf("stderr = %q, want a clear non-tty refusal message", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRun_PromptForApproval_NonTtyRefusalPrecedesEverything(t *testing.T) {
	stubStdinIsTerminal(t, false)
	runStdin = stdinTripwire{t}
	stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
		t.Error("the refused run reached the headless bootstrap — the non-tty gate must reject before the agent starts")
		return nil, nil
	})
	prevGetwd := osGetwd
	osGetwd = func() (string, error) {
		t.Error("the refused run resolved a working directory — the non-tty gate must reject before any project path is reached")
		return "", errors.New("unreachable")
	}
	t.Cleanup(func() { osGetwd = prevGetwd })

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "run", "--prompt-for-approval", "delete my notes"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr=%q)", code, stderr.String())
	}
	for _, forbidden := range []string{"approval required", "allow once", "allow this session", "choose 1-"} {
		if strings.Contains(stderr.String(), forbidden) || strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("the refused run rendered prompt text %q:\nstdout=%q\nstderr=%q", forbidden, stdout.String(), stderr.String())
		}
	}
}

// TestRun_PromptForApproval_TtyEnablesDriver proves the flag binds interactive escalation onto
// the real driver when stdin is a terminal, and that omitting the flag leaves the run
// fail-closed (default-deny preserved) — Done-when 1 wiring and Done-when 3.
func TestRun_PromptForApproval_TtyEnablesDriver(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		wantEnabled bool
	}{
		{"flag enables", []string{"codemeld", "run", "--prompt-for-approval", "do it"}, true},
		{"no flag stays fail-closed", []string{"codemeld", "run", "do it"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubStdinIsTerminal(t, true)
			var gotEnabled bool
			stubHeadlessBootstrap(t, func(_ context.Context, _ string, _ bootstrap.FreshSteps, d *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
				if d == nil {
					t.Fatal("headless seam received a nil driver")
				}
				gotEnabled = d.PromptForApprovalEnabled()
				return nil, nil
			})
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), tc.args, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			if gotEnabled != tc.wantEnabled {
				t.Fatalf("driver PromptForApprovalEnabled = %v, want %v", gotEnabled, tc.wantEnabled)
			}
		})
	}
}

// TestRun_DevDebug_EnablesDriver proves --dev-debug binds the development trace onto the
// real headless driver, and that omitting it leaves the run trace-free.
func TestRun_DevDebug_EnablesDriver(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		wantEnabled bool
	}{
		{"flag enables", []string{"codemeld", "run", "--dev-debug", "do it"}, true},
		{"no flag stays off", []string{"codemeld", "run", "do it"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotEnabled bool
			stubHeadlessBootstrap(t, func(_ context.Context, _ string, _ bootstrap.FreshSteps, d *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
				if d == nil {
					t.Fatal("headless seam received a nil driver")
				}
				gotEnabled = d.DevDebugRequested()
				return nil, nil
			})
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), tc.args, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			if gotEnabled != tc.wantEnabled {
				t.Fatalf("driver DevDebugRequested = %v, want %v", gotEnabled, tc.wantEnabled)
			}
		})
	}
}

// TestRun_DevDebug_HelpDocuments proves the run help documents the --dev-debug flag, the
// session-event surface it produces, and the CODEMELD_DEV_DEBUG alternative.
func TestRun_DevDebug_HelpDocuments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"codemeld", "run", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		// The bracketed form appears only in the hand-written UsageText line, not the
		// generated flag table — so this assertion fails if the flag is dropped from the
		// usage line specifically (project rule: UsageText stays current with the flags).
		"[--dev-debug]",
		"suggest_followup_debug",
		"CODEMELD_DEV_DEBUG",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("run help missing %q:\n%s", want, out)
		}
	}
}

// TestRun_Title_ReachesDriverNormalized proves --title reaches the real headless driver in the
// form the session metadata stores: whitespace collapsed to single spaces, cut on a rune boundary
// at 80 runes with no trailing space, wrapping quotes kept (a name the user typed is not a model
// reply), and no name at all when the flag is omitted.
func TestRun_Title_ReachesDriverNormalized(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"plain", []string{"codemeld", "run", "--title", "review i870", "do it"}, "review i870"},
		{"collapses whitespace and newlines", []string{"codemeld", "run", "--title", "  review\n\n\tof   i870 ", "do it"}, "review of i870"},
		{"keeps wrapping quotes", []string{"codemeld", "run", "--title", `"review i870"`, "do it"}, `"review i870"`},
		{
			"truncates multi-byte on a rune boundary",
			[]string{"codemeld", "run", "--title", "é\nè " + strings.Repeat("ü", 100), "do it"},
			"é è " + strings.Repeat("ü", 76),
		},
		{
			"a cut landing on a space leaves no trailing space",
			[]string{"codemeld", "run", "--title", strings.Repeat("a ", 50), "do it"},
			strings.TrimSpace(strings.Repeat("a ", 40)),
		},
		{"absent flag names nothing", []string{"codemeld", "run", "do it"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			stubHeadlessBootstrap(t, func(_ context.Context, _ string, _ bootstrap.FreshSteps, d *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
				if d == nil {
					t.Fatal("headless seam received a nil driver")
				}
				got = d.SessionTitle()
				return nil, nil
			})
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), tc.args, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			if got != tc.want {
				t.Fatalf("driver SessionTitle = %q, want %q", got, tc.want)
			}
			if n := len([]rune(got)); n > 80 {
				t.Fatalf("driver SessionTitle is %d runes, want at most 80", n)
			}
		})
	}
}

// TestRun_Title_BlankIsUsageError proves a --title with no name left after trimming exits 2 with a
// single stderr line and starts no run, rather than silently naming the session "".
func TestRun_Title_BlankIsUsageError(t *testing.T) {
	for _, arg := range []string{"", "   ", "\n\t ", "\u00a0"} {
		t.Run(fmt.Sprintf("%q", arg), func(t *testing.T) {
			stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
				t.Fatal("a blank --title reached the headless bootstrap")
				return nil, nil
			})
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), []string{"codemeld", "run", "--title", arg, "do it"}, &stdout, &stderr); code != 2 {
				t.Fatalf("exit = %d, want 2 (stderr=%q)", code, stderr.String())
			}
			const want = "codemeld: --title needs a name; omit --title to title the session automatically"
			if got := strings.TrimRight(stderr.String(), "\n"); got != want {
				t.Fatalf("stderr = %q, want exactly %q", stderr.String(), want)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty (diagnostics go to stderr)", stdout.String())
			}
		})
	}
}

// TestRun_Title_HelpDocuments proves every help form lists --title, the picker effect it has, and
// its normalization and blank-value rules, and the automatic title used when it is omitted.
func TestRun_Title_HelpDocuments(t *testing.T) {
	for _, form := range [][]string{
		{"codemeld", "run", "-h"},
		{"codemeld", "run", "--help"},
		{"codemeld", "help", "run"},
	} {
		t.Run(strings.Join(form, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), form, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			out := stdout.String()
			for _, want := range []string{
				// The bracketed form appears only in the hand-written UsageText line, not the
				// generated flag table, so this fails if the flag is dropped from the usage line.
				"[--title <name>]",
				"--title",
				"/resume",
				"collapsed to single spaces",
				"cut at 80",
				"empty or only whitespace is a usage error",
				"an interrupted run keeps it",
				"Without --title the session is titled",
				"first 12 words, at most 80",
				"is stored as the title before the turn, and after a successful first turn",
				"replaces it with the model's title",
				"Either step is best-effort",
				"a blank --title",
				"Omit to title the session automatically from the prompt, then from the model after a successful first turn",
			} {
				if !strings.Contains(out, want) {
					t.Fatalf("run help (%q) missing %q:\n%s", form, want, out)
				}
			}
		})
	}
}

func TestRun_RefusalRepeatRule_HelpDocuments(t *testing.T) {
	for _, form := range [][]string{
		{"codemeld", "run", "-h"},
		{"codemeld", "run", "--help"},
		{"codemeld", "help", "run"},
	} {
		t.Run(strings.Join(form, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), form, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			out := stdout.String()
			for _, want := range []string{
				"told it was refused and continues",
				"Refusals of different",
				"calls do not end the run",
				"same call has been refused 5 times",
				"one final round with no tools to write its answer",
			} {
				if !strings.Contains(out, want) {
					t.Fatalf("run help (%q) missing %q:\n%s", form, want, out)
				}
			}
		})
	}
}

func TestRun_PromptForApproval_HelpDocuments(t *testing.T) {
	for _, form := range [][]string{
		{"codemeld", "run", "-h"},
		{"codemeld", "run", "--help"},
		{"codemeld", "help", "run"},
	} {
		t.Run(strings.Join(form, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), form, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			out := stdout.String()
			for _, want := range []string{
				"--prompt-for-approval",
				"allow once",
				"an identical repeat in the same run is not re-asked",
				"deny",
				"allow for this session",
				"allow in this project",
				".codemeld/settings.local.yaml",
				"The 'allow globally' option is never offered here",
				"requires an interactive terminal on stdin",
				"Without the flag the run stays fail-closed and writes no grant",
				"allow-in-this-project",
				"which command scope the grant stores",
				"one choice per argument boundary",
				"stored verbatim and only later arguments may vary",
				"needs a further confirmation against a breadth",
				"A scope answer that names none of the offered choices denies the call and",
				"names the resolved project root",
				"the absolute settings file the grant is written to",
				"Every other subject — a literal command, a structured tool, a host — keeps its fixed",
				"approved project one more choice is offered: allow in this project (record it",
				"permanently in this project's .codemeld/settings.local.yaml, exactly as the same choice",
				"project that choice is withheld: the prompt does not list it, and answering with it",
				"which command scope the grant stores. In an approved project allow in this project",
				"A permanent choice is offered only in an approved project; before it the",
				"a permanent choice at all in an approved project",
				"plus allow-in-this-project in an approved project",
			} {
				if !strings.Contains(out, want) {
					t.Fatalf("run help (%q) missing %q:\n%s", form, want, out)
				}
			}
			for _, stale := range []string{
				"settings.yaml is never written",
				"never persists a grant",
				"three options",
				"every grant is ephemeral",
				"this one call",
				"stores only the exact command requested",
				"the subject is always fixed",
				"Four options are offered",
				"records the grant, but the grant does not take effect until the project is trusted",
				"a headless run cannot write a project",
				"in a trusted project",
				"in this project's .codemeld/settings.yaml,",
			} {
				if strings.Contains(out, stale) {
					t.Fatalf("run help (%q) still claims %q:\n%s", form, stale, out)
				}
			}
		})
	}
}

// TestRun_RunHelp_AllForms proves `codemeld run -h`, `--help`, and `help run` all reach
// the hand-written run help (the fail-closed default, --mode, exit codes, and the
// resumable session), write it to stdout, exit 0, and never reach the bootstrap seam.
func TestRun_RunHelp_AllForms(t *testing.T) {
	for _, form := range [][]string{
		{"codemeld", "run", "-h"},
		{"codemeld", "run", "--help"},
		{"codemeld", "help", "run"},
	} {
		t.Run(strings.Join(form, " "), func(t *testing.T) {
			stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
				t.Fatal("help form reached the headless bootstrap")
				return nil, nil
			})
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), form, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			out := stdout.String()
			for _, want := range []string{
				"fail-closed",           // the anti-YOLO default
				"--mode",                // the mode override
				"--prompt-for-approval", // the optional terminal-approval flag (usage + body)
				"Exit codes",            // documented exit codes
				"resumable",             // the run leaves a resumable session
				"final answer to stdout, tool-round text to stderr",
				"Only the final answer, or",
				"the partial answer of an interrupted stream, goes to stdout",
				"tool-call rounds goes to stderr alongside tool activity",
				"[--no-agents | --no-dir-agent | --agents-file <absolute-path>] \"<prompt>\"",
				"--time-limit, --prompt-for-approval without a terminal on stdin, an empty or relative",
				"--agents-file, --agents-file with --no-agents or --no-dir-agent, or one of those three",
				"flags placed before 'run');",
			} {
				if !strings.Contains(out, want) {
					t.Fatalf("run help (%q) missing %q:\n%s", form, want, out)
				}
			}
			for _, want := range agentsHelpWants {
				if !strings.Contains(out, want) {
					t.Fatalf("run help (%q) missing %q:\n%s", form, want, out)
				}
			}
			// The summary no longer claims the command has no approvals (it now has the
			// optional --prompt-for-approval path).
			if strings.Contains(out, "no approvals") {
				t.Fatalf("run help (%q) still says \"no approvals\":\n%s", form, out)
			}
		})
	}
}

// TestRun_FilesAuthorized_ReachDriverUnsplit proves each repeated flag value reaches the real
// driver as its own path, and that a value containing a comma stays one path. Both flags are
// pinned independently: they are separate lists and one splitting would be a separate defect.
func TestRun_FilesAuthorized_ReachDriverUnsplit(t *testing.T) {
	var gotWrite, gotDelete []string
	stubHeadlessBootstrap(t, func(_ context.Context, _ string, _ bootstrap.FreshSteps, d *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
		if d == nil {
			t.Fatal("headless seam received a nil driver")
		}
		gotWrite, gotDelete = d.DeclaredFileScopes()
		return nil, nil
	})
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"codemeld", "run",
		"--files-authorized", "a.txt",
		"--files-authorized", "a,b.txt",
		"--files-authorized-delete", "c.txt",
		"--files-authorized-delete", "c,d.txt",
		"write it",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	if want := []string{"a.txt", "a,b.txt"}; !slices.Equal(gotWrite, want) {
		t.Fatalf("write declarations = %v, want %v (a comma is filename text, not a separator)", gotWrite, want)
	}
	if want := []string{"c.txt", "c,d.txt"}; !slices.Equal(gotDelete, want) {
		t.Fatalf("delete declarations = %v, want %v (a comma is filename text, not a separator)", gotDelete, want)
	}
}

// TestRun_FilesAuthorized_AbsentLeavesNoDeclaration proves omitting both flags binds no ceiling,
// which is what keeps an undeclared run's authorization unchanged.
func TestRun_FilesAuthorized_AbsentLeavesNoDeclaration(t *testing.T) {
	var gotWrite, gotDelete []string
	stubHeadlessBootstrap(t, func(_ context.Context, _ string, _ bootstrap.FreshSteps, d *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
		gotWrite, gotDelete = d.DeclaredFileScopes()
		return nil, nil
	})
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"codemeld", "run", "do it"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	if len(gotWrite) != 0 || len(gotDelete) != 0 {
		t.Fatalf("declarations = %v / %v, want none", gotWrite, gotDelete)
	}
}

// TestRun_DenialSummary_ScopeAwareAdvice proves the exit summary never tells a caller to add a
// grant or run interactively for a declared-scope denial, and prints the right advice for each
// denial in a run that mixed the two classes.
func TestRun_DenialSummary_ScopeAwareAdvice(t *testing.T) {
	stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
		return []bootstrap.DeniedCall{
			{Subject: "edit", Reason: "a declared-scope ceiling is active for this run", Source: "declared_scope"},
			{Subject: "rm -rf build", Reason: "no approval available in non-interactive run mode"},
		}, nil
	})
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"codemeld", "run", "--files-authorized", "a.txt", "clean up"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	out := stderr.String()

	scopeLine, ordinaryLine := lineAfter(t, out, "  - edit:"), lineAfter(t, out, "  - rm -rf build:")
	if !strings.Contains(scopeLine, "--files-authorized") || strings.Contains(scopeLine, "run codemeld interactively") {
		t.Fatalf("declared-scope advice = %q, want the flag advice and no grant/interactive advice", scopeLine)
	}
	if !strings.Contains(ordinaryLine, "permission grant") || !strings.Contains(ordinaryLine, "run codemeld interactively") {
		t.Fatalf("fail-closed advice = %q, want the grant/interactive advice", ordinaryLine)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty (the denial summary belongs on stderr)", stdout.String())
	}
}

// TestRun_DenialSummary_SameLabelMixedClasses proves two denials that share a display label but
// differ in classification both reach the summary with their own advice, so a run mixing a
// declared-scope refusal with an ordinary fail-closed one never loses a denial to its label.
func TestRun_DenialSummary_SameLabelMixedClasses(t *testing.T) {
	stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
		return []bootstrap.DeniedCall{
			{Subject: "a.txt", Reason: "a declared-scope ceiling is active for this run", Source: "declared_scope"},
			{Subject: "a.txt", Reason: "no approval available in non-interactive run mode"},
		}, nil
	})
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"codemeld", "run", "--files-authorized", "b.txt", "clean up"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	out := stderr.String()

	advice := advicesAfter(out, "  - a.txt:")
	if len(advice) != 2 {
		t.Fatalf("same-label denials = %d, want 2:\n%s", len(advice), out)
	}
	if !strings.Contains(advice[0], "--files-authorized") || strings.Contains(advice[0], "run codemeld interactively") {
		t.Fatalf("declared-scope advice = %q, want the flag advice and no grant/interactive advice", advice[0])
	}
	if !strings.Contains(advice[1], "permission grant") || !strings.Contains(advice[1], "run codemeld interactively") {
		t.Fatalf("fail-closed advice = %q, want the grant/interactive advice", advice[1])
	}
}

// advicesAfter returns the advice line printed under every denial line starting with prefix.
func advicesAfter(out, prefix string) []string {
	var got []string
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) && i+1 < len(lines) {
			got = append(got, lines[i+1])
		}
	}
	return got
}

// lineAfter returns the line following the first line that starts with prefix.
func lineAfter(t *testing.T, out, prefix string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) && i+1 < len(lines) {
			return lines[i+1]
		}
	}
	t.Fatalf("no line starting with %q followed by advice:\n%s", prefix, out)
	return ""
}

// TestRun_FilesAuthorized_HelpDocuments proves every help form states what a caller would
// otherwise get wrong about the two flags: repetition, the sole-authorization ceiling, the
// parent-directory consequence, the exact delete types, the shell exclusion, and that the
// ceiling reaches delegation — a caller who reads it as file-tools-only would not expect a
// general_agent call to be refused for declaring a path outside the list.
func TestRun_FilesAuthorized_HelpDocuments(t *testing.T) {
	for _, form := range [][]string{
		{"codemeld", "run", "-h"},
		{"codemeld", "run", "--help"},
		{"codemeld", "help", "run"},
	} {
		t.Run(strings.Join(form, " "), func(t *testing.T) {
			stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
				t.Fatal("help form reached the headless bootstrap")
				return nil, nil
			})
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), form, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			out := stdout.String()
			for _, want := range []string{
				"--files-authorized",
				"--files-authorized-delete",
				"Repeat either flag",
				"sole authorization",
				"mkdir and move are never authorized",
				"authorizes creating those parent directories",
				"file, a symlink,",
				"empty directory",
				"not a sandbox",
				"sandbox and do not authorize or confine shell writes. A shell command follows the",
				"mode's OS sandbox when one is active; where none confines it (build mode, or a failed",
				"or unsupported startup check), a shell command authorized by a grant can still write",
				"A general_agent call may declare only write paths",
				"an uncovered declaration is refused ahead",
				"nested general_agent call may declare only paths its own parent already declared",
			} {
				if !strings.Contains(out, want) {
					t.Fatalf("run help (%q) missing %q:\n%s", form, want, out)
				}
			}
			if strings.Contains(out, "exact file") {
				t.Fatalf("run help (%q) says \"exact file\"; a delete declaration also covers a symlink and an empty directory:\n%s", form, out)
			}
		})
	}
}

func TestRun_Sandbox_HelpDocuments(t *testing.T) {
	for _, form := range [][]string{
		{"codemeld", "run", "-h"},
		{"codemeld", "run", "--help"},
		{"codemeld", "help", "run"},
	} {
		t.Run(strings.Join(form, " "), func(t *testing.T) {
			stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
				t.Fatal("help form reached the headless bootstrap")
				return nil, nil
			})
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), form, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			out := stdout.String()
			for _, want := range []string{
				"denies mutating tool calls. On Linux (amd64/arm64), when codemeld's startup",
				"sandbox check passes, 'plan' and 'auto-edits' run shell commands inside an OS sandbox",
				"with filesystem and process-access restrictions, and 'build' runs them outside it; if",
				"the check fails or the platform is not supported, commands run outside the sandbox.",
				"Under 'plan', with intact settings and a passing startup check on a supported host, a",
				"shell command runs inside the sandbox, where writes and network access fail. Without",
				"the sandbox, only read-only commands run under 'plan'; any other command is denied",
				"without asking unless the opt-in System One check allows that one invocation. Broken",
				"settings remove automatic sandbox permission: an otherwise-eligible command may still",
				"get a grant-free, cache-free allow-once from the System One check; otherwise it needs",
				"approval, or is refused in a non-prompting headless run. An unknown or degraded",
				"blocked-path list makes a command ineligible for that check.",
			} {
				if !strings.Contains(out, want) {
					t.Fatalf("run help (%q) missing %q:\n%s", form, want, out)
				}
			}
			if strings.Contains(out, "mutating call is denied by the mode") {
				t.Fatalf("run help (%q) still says every mutating call is denied under 'plan':\n%s", form, out)
			}
			if strings.Contains(out, "isolat") {
				t.Fatalf("run help (%q) overclaims the sandbox as isolation:\n%s", form, out)
			}
		})
	}
}

func TestRun_TrustBoundary_HelpDocuments(t *testing.T) {
	for _, form := range [][]string{
		{"codemeld", "run", "-h"},
		{"codemeld", "run", "--help"},
		{"codemeld", "help", "run"},
	} {
		t.Run(strings.Join(form, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), form, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			out := stdout.String()
			for _, want := range []string{
				"A headless run honors the list of approved project roots but never prompts for",
				"approval, under any flag, and never adds a root to that list. An approved project",
				"contributes both its .codemeld/settings.yaml and .codemeld/settings.local.yaml",
				"layers exactly as it does interactively; a project that is not approved contributes",
				"neither. The gate covers those two settings layers and the project's VCS command",
				"templates. AGENTS.md files are outside that gate: by default they load on their",
				"ordinary discovery rules whether or not the project is approved, and the controls",
				"below suppress or replace them the same way in either case.",
				"input is often untrusted.",
			} {
				if !strings.Contains(out, want) {
					t.Fatalf("run help (%q) missing %q:\n%s", form, want, out)
				}
			}
			for _, stale := range []string{
				"project is approved: the global one, any above the project root, and the project's own.",
				"always treats the",
				"an interactive trust decision does not carry into it",
				"it never changes what a headless run",
				"untrusted unless you have already trusted it interactively",
				"then use both inputs",
				"contributes neither its .codemeld/settings.yaml layer nor any",
				"AGENTS.md file at or below its root",
				"those instructions reach no session event",
				"prompts for trust",
				"trust record",
				"trusted project",
				"trusted it",
				"fingerprint",
				"on_change",
				"record mode",
				"changed since",
			} {
				if strings.Contains(out, stale) {
					t.Fatalf("run help (%q) still claims %q, which headlessTrustGate never does:\n%s", form, stale, out)
				}
			}
		})
	}
}

func TestDenialAdvice_NamesTheLocalGrantDestination(t *testing.T) {
	got := denialAdvice(bootstrap.DeniedCall{})
	if !strings.Contains(got, "a permission grant in .codemeld/settings.local.yaml") {
		t.Fatalf("denialAdvice() = %q, want the local settings file as the grant destination", got)
	}
}

func TestRun_TimeLimit_InvalidIsUsageError(t *testing.T) {
	for _, arg := range []string{"", "soon", "0", "0s", "-5m"} {
		t.Run(fmt.Sprintf("%q", arg), func(t *testing.T) {
			stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
				t.Fatal("an invalid --time-limit reached the headless bootstrap")
				return nil, nil
			})
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), []string{"codemeld", "run", "--time-limit", arg, "do it"}, &stdout, &stderr); code != 2 {
				t.Fatalf("exit = %d, want 2 (stderr=%q)", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "--time-limit must be a positive duration") {
				t.Fatalf("stderr = %q, want a --time-limit usage message", stderr.String())
			}
		})
	}
}

func TestRun_TimeLimit_ReachesDriverAsAnAbsoluteDeadline(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		limit time.Duration
	}{
		{"set", []string{"codemeld", "run", "--time-limit", "28m", "do it"}, 28 * time.Minute},
		{"absent", []string{"codemeld", "run", "do it"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var deadline time.Time
			var limit time.Duration
			stubHeadlessBootstrap(t, func(_ context.Context, _ string, _ bootstrap.FreshSteps, d *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
				deadline, limit = d.TimeLimit()
				return nil, nil
			})
			before := time.Now()
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), tc.args, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			after := time.Now()
			if limit != tc.limit {
				t.Fatalf("limit = %v, want %v", limit, tc.limit)
			}
			if tc.limit == 0 {
				if !deadline.IsZero() {
					t.Fatalf("deadline = %v, want none without --time-limit", deadline)
				}
				return
			}
			if deadline.Before(before.Add(tc.limit)) || deadline.After(after.Add(tc.limit)) {
				t.Fatalf("deadline = %v, want the run start plus %v", deadline, tc.limit)
			}
		})
	}
}

func TestRun_TimeLimit_HelpDocuments(t *testing.T) {
	for _, form := range [][]string{
		{"codemeld", "run", "-h"},
		{"codemeld", "run", "--help"},
		{"codemeld", "help", "run"},
	} {
		t.Run(strings.Join(form, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), form, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			out := stdout.String()
			for _, want := range []string{
				"[--time-limit <duration>]",
				"28m or 1680s",
				"one final round with no",
				"recorded as cancelled",
				"Without --time-limit the run has no time limit",
				"including one ended by --time-limit",
				"an empty, malformed, zero, or negative\n   --time-limit",
				"Time spent waiting on permission prompts counts",
				"against the limit, and 'codemeld sessions summary' reports it.",
			} {
				if !strings.Contains(out, want) {
					t.Fatalf("run help (%q) missing %q:\n%s", form, want, out)
				}
			}
		})
	}
}

func TestRun_TurnLimitExitsZeroWithOneNoticeAndTheFinalAnswer(t *testing.T) {
	const removed = "; tools were removed and the model is writing its final answer. Send a new message to continue."
	for _, tc := range []struct {
		name      string
		alternate bool
		requests  int32
		notice    string
	}{
		{"round limit", true, 200, "codemeld: this turn reached its 200-round limit" + removed},
		{"repeated call", false, 4, "codemeld: this turn repeated the same tool call (" + filetools.ReadToolName + ") 3 rounds in a row" + removed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, dir := t.TempDir(), t.TempDir()
			file := filepath.Join(dir, "a.txt")
			if err := os.WriteFile(file, []byte("a\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			args, err := json.Marshal(map[string]string{"path": file})
			if err != nil {
				t.Fatal(err)
			}
			respelled := strings.Replace(string(args), `":`, `": `, 1)

			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Tools []json.RawMessage `json:"tools"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode %s request: %v", r.URL.Path, err)
				}
				n := requests.Add(1)
				delta, finish := map[string]any{"role": "assistant", "content": "final answer"}, "stop"
				if len(body.Tools) > 0 {
					call := string(args)
					if tc.alternate && n%2 == 0 {
						call = respelled
					}
					delta = map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{
						"index": 0, "id": fmt.Sprintf("call_%d", n), "type": "function",
						"function": map[string]any{"name": filetools.ReadToolName, "arguments": call},
					}}}
					finish = "tool_calls"
				}
				w.Header().Set("Content-Type", "text/event-stream")
				for _, choice := range []map[string]any{{"index": 0, "delta": delta}, {"index": 0, "delta": map[string]any{}, "finish_reason": finish}} {
					chunk, _ := json.Marshal(map[string]any{"id": "c", "object": "chat.completion.chunk", "model": "gpt-5.5", "choices": []any{choice}})
					_, _ = fmt.Fprintf(w, "data: %s\n\n", chunk)
				}
				_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
			}))
			defer srv.Close()

			if err := config.UpdateDiscoveredModelsProvider(config.DiscoveredModelsPath(bootstrap.SettingsPath(home)), "openai",
				config.DiscoveredProvider{Models: []config.DiscoveredModel{{ID: "gpt-5.5"}}}); err != nil {
				t.Fatal(err)
			}
			global := map[string]any{"provider": map[string]any{"openai": map[string]any{"base_url": srv.URL, "api_key": "sk-test"}}}
			stubHeadlessBootstrap(t, func(ctx context.Context, cwd string, steps bootstrap.FreshSteps, driver *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
				steps.ResolveHome = func() (string, error) { return home, nil }
				steps.RunFirstRun = func(string) (bool, error) { return false, nil }
				steps.LoadGlobalSettings = func(string) (map[string]any, error) { return global, nil }
				steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) { return dir, nil, nil }
				return bootstrap.RunHeadless(ctx, cwd, steps, driver)
			})
			prevGetwd := osGetwd
			osGetwd = func() (string, error) { return dir, nil }
			t.Cleanup(func() { osGetwd = prevGetwd })

			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"codemeld", "run", "--model", "openai/gpt-5.5", "--title", "limit", "survey the repo"}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			if n := requests.Load(); n != tc.requests {
				t.Fatalf("provider requests = %d, want %d", n, tc.requests)
			}
			if stdout.String() != "final answer\n" {
				t.Fatalf("stdout = %q, want only the final answer", stdout.String())
			}
			if n := strings.Count(stderr.String(), tc.notice+"\n"); n != 1 {
				t.Fatalf("stderr carries the notice %d times, want once: %q", n, stderr.String())
			}
		})
	}
}

func headlessRoute(t *testing.T, flags []string) *agentsRouteCall {
	call := &agentsRouteCall{}
	stubHeadlessBootstrap(t, func(_ context.Context, cwd string, steps bootstrap.FreshSteps, _ *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
		*call = agentsRouteCall{true, cwd, steps.LoadAgentInstructions, steps.AgentInstructionsSelection}
		return nil, nil
	})
	runAgentsRoute(t, append(append([]string{"codemeld", "run"}, flags...), "prompt"))
	return call
}

func TestRun_AgentsFlags_HeadlessReachesTheBootstrapSeam(t *testing.T) {
	checkAgentsFlagOutcomes(t, headlessRoute)
}

func TestRun_AgentsFlags_HeadlessInvalidFormsExit2BeforeBootstrap(t *testing.T) {
	for _, form := range invalidAgentsFlagForms {
		args := append(append([]string{"codemeld", "run"}, form...), "prompt")
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stubHeadlessBootstrap(t, func(context.Context, string, bootstrap.FreshSteps, *bootstrap.HeadlessDriver) ([]bootstrap.DeniedCall, error) {
				t.Fatal("invalid form reached the headless bootstrap")
				return nil, nil
			})
			stubNoGetwd(t)
			assertUsageExit2(t, args, "codemeld: --agents-file")
		})
	}
}

func TestRun_AgentsFlags_ListedOnceInRunOptions(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"codemeld", "run", "-h"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	out := stdout.String()
	_, options, ok := strings.Cut(out, "\nOPTIONS:\n")
	if !ok {
		t.Fatalf("run help has no OPTIONS section:\n%s", out)
	}
	options, global, ok := strings.Cut(options, "\nGLOBAL OPTIONS:\n")
	if !ok {
		t.Fatalf("run help has no GLOBAL OPTIONS section:\n%s", out)
	}
	count := func(section, flag string) int {
		n := 0
		for _, line := range strings.Split(section, "\n") {
			if f := strings.Fields(line); len(f) > 0 && f[0] == flag {
				n++
			}
		}
		return n
	}
	for _, flag := range []string{"--no-agents", "--no-dir-agent", "--agents-file"} {
		if n := count(options, flag); n != 1 {
			t.Fatalf("OPTIONS lists %s %d times, want once:\n%s", flag, n, options)
		}
		if strings.Contains(global, flag) {
			t.Fatalf("GLOBAL OPTIONS lists %s:\n%s", flag, global)
		}
	}
}

func TestPrintDenialSummary_AdvicePerDenialClass(t *testing.T) {
	const (
		scopeAdvice        = "    to authorize, name the path in --files-authorized or --files-authorized-delete when starting the run; a permission grant and --prompt-for-approval cannot widen a declared scope."
		ordinaryAdvice     = "    to authorize, grant the command/tool (a permission grant in .codemeld/settings.local.yaml) or run codemeld interactively."
		unattendedAdvice   = "    to authorize this exceptional action in sandboxed Auto edits, run codemeld interactively or restart with --prompt-for-approval and explicitly allow it once; saved grants are not used for this action by the current implementation."
		alreadyAskedAdvice = "    this exceptional action was denied; it requires explicit allow-once approval in sandboxed Auto edits, and saved grants are not used for it by the current implementation."
	)
	var stderr bytes.Buffer
	printDenialSummary(&stderr, []bootstrap.DeniedCall{
		{Subject: "a.txt", Reason: "declared", Source: "declared_scope", Exceptional: true},
		{Subject: "rm -rf build", Reason: "ordinary"},
		{Subject: "curl https://example.com/a", Reason: "unattended", Exceptional: true},
		{Subject: "sh -c 'curl https://example.com/a'", Reason: "asked", Exceptional: true, TerminalApprover: true},
		{Subject: "git push", Reason: "asked ordinary", TerminalApprover: true},
	})
	want := strings.Join([]string{
		"codemeld: 5 call(s) denied:",
		"  - a.txt: declared", scopeAdvice,
		"  - rm -rf build: ordinary", ordinaryAdvice,
		"  - curl https://example.com/a: unattended", unattendedAdvice,
		"  - sh -c 'curl https://example.com/a': asked", alreadyAskedAdvice,
		"  - git push: asked ordinary", ordinaryAdvice,
		"",
	}, "\n")
	if got := stderr.String(); got != want {
		t.Fatalf("summary =\n%s\nwant\n%s", got, want)
	}
}
