// Tests for RunFresh step ordering, first-run short-circuit, and the production default first-run step.
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/subagent"
	"codemeld.dev/codemeld/internal/testsupport"
	"codemeld.dev/codemeld/internal/trust"
	"codemeld.dev/codemeld/internal/tui"
)

// recordingSteps builds a FreshSteps whose every step appends its name to *order
// and returns success. Tests override individual fields to inject failures or to
// assert placement, while the rest keep recording so the full sequence is visible.
func recordingSteps(order *[]string) FreshSteps {
	rec := func(name string) { *order = append(*order, name) }
	return FreshSteps{
		ResolveHome:        func() (string, error) { rec("0a:ResolveHome"); return "/home/u", nil },
		RunFirstRun:        func(string) (bool, error) { rec("0:RunFirstRun"); return false, nil },
		LoadGlobalSettings: func(string) (map[string]any, error) { rec("1:LoadGlobalSettings"); return nil, nil },
		ResolveProjectRoot: func(string, map[string]any) (string, []string, error) {
			rec("2:ResolveProjectRoot")
			return "/proj", nil, nil
		},
		GateTrust: func(string, string, string) trust.Decision {
			rec("2b:GateTrust")
			return trust.Decision{Trusted: true, Reason: trust.ReasonTrusted, Root: "/proj"}
		},
		ScaffoldProjectIgnore: func(string) error { rec("2.5:ScaffoldProjectIgnore"); return nil },
		RecoverJournals:       func(string, string) { rec("2.6:RecoverJournals") },
		ComposeConfig: func(map[string]any, string) (ConfigComposition, error) {
			rec("3:ComposeConfig")
			return ConfigComposition{}, nil
		},
		LoadVCSTemplates: func(string, string, map[string]any, bool) (any, error) {
			rec("4:LoadVCSTemplates")
			return nil, nil
		},
		ValidatePreferredVCS: func(map[string]any, any) error { rec("5:ValidatePreferredVCS"); return nil },
		DetectVCS:            func(string, map[string]any, any) (any, error) { rec("6:DetectVCS"); return nil, nil },
		BuildToolRegistry:    func(any) (any, error) { rec("6c:BuildToolRegistry"); return nil, nil },
		DetermineModel: func(map[string]any, map[string]any, string, []string) (any, bool, error) {
			rec("7:DetermineModel")
			return nil, false, nil
		},
		EnsureFreshSession: func(string, string) (*sessions.Store, error) {
			rec("7b:EnsureFreshSession")
			return sessions.New("/fresh/session.json", &sessions.Session{Metadata: sessions.Metadata{ID: "01890000-0000-7000-8000-0000000000fe"}}), nil
		},
		AcquireLock:       func(string, string) (func(), error) { rec("7b:AcquireLock"); return func() {}, nil },
		AppendLaunchBegan: func(context.Context, *sessions.Store) error { rec("7b1:AppendLaunchBegan"); return nil },
		InitMode: func(context.Context, *sessions.Store, map[string]any, string, []string) (any, error) {
			rec("7b2:InitMode")
			return nil, nil
		},
		LoadAgentInstructions: func(context.Context, *sessions.Store, string, string, map[string]any, string, []string) ([]agentinstr.LoadEntry, error) {
			rec("7c:LoadAgentInstructions")
			return nil, nil
		},
		StartTUI: func(context.Context, *BootstrapResult) error { rec("8:StartTUI"); return nil },
	}
}

func TestRunFresh_StepOrder(t *testing.T) {
	var order []string
	res, err := RunFresh(context.Background(), "/cwd", recordingSteps(&order))
	if err != nil {
		t.Fatalf("RunFresh error: %v", err)
	}
	if res == nil {
		t.Fatal("RunFresh returned nil result on full launch")
	}

	want := []string{
		"0a:ResolveHome",
		"0:RunFirstRun",
		"1:LoadGlobalSettings",
		"2:ResolveProjectRoot",
		"2b:GateTrust",
		"2.5:ScaffoldProjectIgnore",
		"2.6:RecoverJournals",
		"3:ComposeConfig",
		"4:LoadVCSTemplates",
		"5:ValidatePreferredVCS",
		"6:DetectVCS",
		"6c:BuildToolRegistry",
		"7:DetermineModel",
		"7b:EnsureFreshSession",
		"7b:AcquireLock",
		"7b1:AppendLaunchBegan",
		"7b2:InitMode",
		"7c:LoadAgentInstructions",
		"8:StartTUI",
	}
	assertOrder(t, want, order)
}

// TestRunFresh_ConfigLayerPaths pins item 10 on the fresh path: RunFresh
// records the /status config sources global-first/project-last — the global
// settings.yaml (SettingsPath(home)) followed by the project-side layer(s)
// ResolveProjectRoot returned — and shows only the global path when no project
// settings.yaml contributed.
func TestRunFresh_ConfigLayerPaths(t *testing.T) {
	t.Run("global then project", func(t *testing.T) {
		var order []string
		steps := recordingSteps(&order)
		projectLayer := "/proj/.codemeld/settings.yaml"
		steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) {
			return "/proj", []string{projectLayer}, nil
		}

		res, err := RunFresh(context.Background(), "/cwd", steps)
		if err != nil {
			t.Fatalf("RunFresh error: %v", err)
		}
		want := []string{SettingsPath("/home/u"), projectLayer}
		if !slices.Equal(res.ConfigLayerPaths, want) {
			t.Fatalf("ConfigLayerPaths = %v, want %v (global-first, project-last)", res.ConfigLayerPaths, want)
		}
	})

	t.Run("global only when no project layer", func(t *testing.T) {
		var order []string
		// recordingSteps' default ResolveProjectRoot returns no project layers.
		res, err := RunFresh(context.Background(), "/cwd", recordingSteps(&order))
		if err != nil {
			t.Fatalf("RunFresh error: %v", err)
		}
		want := []string{SettingsPath("/home/u")}
		if !slices.Equal(res.ConfigLayerPaths, want) {
			t.Fatalf("ConfigLayerPaths = %v, want %v (global only)", res.ConfigLayerPaths, want)
		}
	})
}

// TestRunFresh_SetsBackgroundPruneMarker pins at the orchestration
// level that a completed fresh launch carries BackgroundPrune so StartTUI kicks off the
// background prune.
func TestRunFresh_SetsBackgroundPruneMarker(t *testing.T) {
	var order []string
	res, err := RunFresh(context.Background(), "/cwd", recordingSteps(&order))
	if err != nil {
		t.Fatalf("RunFresh error: %v", err)
	}
	if !res.BackgroundPrune {
		t.Fatal("fresh launch result did not set BackgroundPrune; StartTUI will not background-prune")
	}
}

// TestRunFresh_LaunchBeganBetweenSessionAndAgents pins step 7b1's neighbors so a
// future refactor cannot silently move launch_began out from between session
// creation (7b) and AGENTS.md load (7c) (step 7b1 placement).
func TestRunFresh_LaunchBeganBetweenSessionAndAgents(t *testing.T) {
	var order []string
	if _, err := RunFresh(context.Background(), "/cwd", recordingSteps(&order)); err != nil {
		t.Fatalf("RunFresh error: %v", err)
	}
	prev := slices.Index(order, "7b:EnsureFreshSession")
	began := slices.Index(order, "7b1:AppendLaunchBegan")
	next := slices.Index(order, "7c:LoadAgentInstructions")
	if prev < 0 || began < 0 || next < 0 {
		t.Fatalf("missing a step in order=%v", order)
	}
	if prev >= began || began >= next {
		t.Fatalf("launch_began not between session and agents: session=%d began=%d agents=%d", prev, began, next)
	}
}

// TestRunFresh_ShortCircuitsOnStepError walks each interior step, makes it fail,
// and asserts the failing step ran while every later step did not — proving step
// N+1 runs only when step N returns nil ("each step depends on every
// preceding step").
func TestRunFresh_ShortCircuitsOnStepError(t *testing.T) {
	sentinel := errors.New("boom")

	// One case per error-returning step, in order. lastBefore is the step
	// that must NOT run after the failing one; it is empty for the final step
	// (StartTUI), which has no successor. Step 0a (ResolveHome) is covered by
	// TestRunFresh_HomeResolveFailureWrapped, which asserts its distinct wrapping.
	cases := []struct {
		name       string
		fail       func(s *FreshSteps)
		lastBefore string // step that must NOT run (immediately after the failing one); "" for the last step
	}{
		{"step0_RunFirstRun", func(s *FreshSteps) {
			s.RunFirstRun = func(string) (bool, error) { return false, sentinel }
		}, "1:LoadGlobalSettings"},
		{"step1_LoadGlobalSettings", func(s *FreshSteps) {
			s.LoadGlobalSettings = func(string) (map[string]any, error) { return nil, sentinel }
		}, "2:ResolveProjectRoot"},
		{"step2_ResolveProjectRoot", func(s *FreshSteps) {
			s.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) { return "", nil, sentinel }
		}, "2b:GateTrust"},
		{"step2.5_ScaffoldProjectIgnore", func(s *FreshSteps) {
			s.ScaffoldProjectIgnore = func(string) error { return sentinel }
		}, "3:ComposeConfig"},
		{"step3_ComposeConfig", func(s *FreshSteps) {
			s.ComposeConfig = func(map[string]any, string) (ConfigComposition, error) {
				return ConfigComposition{}, sentinel
			}
		}, "4:LoadVCSTemplates"},
		{"step4_LoadVCSTemplates", func(s *FreshSteps) {
			s.LoadVCSTemplates = func(string, string, map[string]any, bool) (any, error) {
				return nil, sentinel
			}
		}, "5:ValidatePreferredVCS"},
		{"step5_ValidatePreferredVCS", func(s *FreshSteps) {
			s.ValidatePreferredVCS = func(map[string]any, any) error { return sentinel }
		}, "6:DetectVCS"},
		{"step6_DetectVCS", func(s *FreshSteps) {
			s.DetectVCS = func(string, map[string]any, any) (any, error) { return nil, sentinel }
		}, "6c:BuildToolRegistry"},
		{"step6c_BuildToolRegistry", func(s *FreshSteps) {
			s.BuildToolRegistry = func(any) (any, error) { return nil, sentinel }
		}, "7:DetermineModel"},
		{"step7_DetermineModel", func(s *FreshSteps) {
			s.DetermineModel = func(map[string]any, map[string]any, string, []string) (any, bool, error) { return nil, false, sentinel }
		}, "7b:EnsureFreshSession"},
		{"step7b_EnsureFreshSession", func(s *FreshSteps) {
			s.EnsureFreshSession = func(string, string) (*sessions.Store, error) { return nil, sentinel }
		}, "7b:AcquireLock"},
		{"step7b_AcquireLock", func(s *FreshSteps) {
			s.AcquireLock = func(string, string) (func(), error) { return nil, sentinel }
		}, "7b1:AppendLaunchBegan"},
		{"step7b1_AppendLaunchBegan", func(s *FreshSteps) {
			s.AppendLaunchBegan = func(context.Context, *sessions.Store) error { return sentinel }
		}, "7b2:InitMode"},
		{"step7b2_InitMode", func(s *FreshSteps) {
			s.InitMode = func(context.Context, *sessions.Store, map[string]any, string, []string) (any, error) {
				return nil, sentinel
			}
		}, "7c:LoadAgentInstructions"},
		{"step7c_LoadAgentInstructions", func(s *FreshSteps) {
			s.LoadAgentInstructions = func(context.Context, *sessions.Store, string, string, map[string]any, string, []string) ([]agentinstr.LoadEntry, error) {
				return nil, sentinel
			}
		}, "8:StartTUI"},
		{"step8_StartTUI", func(s *FreshSteps) {
			s.StartTUI = func(context.Context, *BootstrapResult) error { return sentinel }
		}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var order []string
			steps := recordingSteps(&order)
			tc.fail(&steps)

			res, err := RunFresh(context.Background(), "/cwd", steps)
			if !errors.Is(err, sentinel) {
				t.Fatalf("err = %v, want sentinel", err)
			}
			if res != nil {
				t.Fatalf("result = %v, want nil on failure", res)
			}
			if tc.lastBefore != "" && slices.Contains(order, tc.lastBefore) {
				t.Fatalf("step %q ran after a prior step failed; order=%v", tc.lastBefore, order)
			}
		})
	}
}

// TestRunFresh_DetermineModelPathFourExit proves the path-4 exit returned
// by DetermineModel (step 7a) aborts before any session work (step 7b onward).
func TestRunFresh_DetermineModelPathFourExit(t *testing.T) {
	var order []string
	steps := recordingSteps(&order)
	pathFour := errors.New("no selectable model")
	steps.DetermineModel = func(map[string]any, map[string]any, string, []string) (any, bool, error) {
		order = append(order, "7:DetermineModel")
		return nil, false, pathFour
	}

	_, err := RunFresh(context.Background(), "/cwd", steps)
	if !errors.Is(err, pathFour) {
		t.Fatalf("err = %v, want path-4 exit", err)
	}
	for _, later := range []string{"7b:EnsureFreshSession", "7b1:AppendLaunchBegan", "7b2:InitMode", "7c:LoadAgentInstructions", "8:StartTUI"} {
		if slices.Contains(order, later) {
			t.Fatalf("step %q ran after path-4 exit; order=%v", later, order)
		}
	}
}

// TestRunFresh_FirstRunShortCircuits proves step 0's first-run branch exits
// before step 1 and runs no later bootstrap step (step 0).
func TestRunFresh_FirstRunShortCircuits(t *testing.T) {
	var order []string
	steps := recordingSteps(&order)
	steps.RunFirstRun = func(string) (bool, error) {
		order = append(order, "0:RunFirstRun")
		return true, nil
	}

	res, err := RunFresh(context.Background(), "/cwd", steps)
	if err != nil {
		t.Fatalf("RunFresh error: %v", err)
	}
	if res != nil {
		t.Fatalf("result = %v, want nil on first-run branch", res)
	}
	assertOrder(t, []string{"0a:ResolveHome", "0:RunFirstRun"}, order)
}

// TestRunFreshCore_RunsStepsThroughAgentsWithoutStartTUI proves the shared bootstrap
// core (the headless run reuses it) runs steps 0a–7c in order and stops before step 8:
// StartTUI is never invoked, firstRun is false, and the assembled result is returned.
func TestRunFreshCore_RunsStepsThroughAgentsWithoutStartTUI(t *testing.T) {
	var order []string
	steps := recordingSteps(&order)
	startTUIRan := false
	steps.StartTUI = func(context.Context, *BootstrapResult) error {
		startTUIRan = true
		return nil
	}

	res, firstRun, err := runFreshCore(context.Background(), "/cwd", steps)
	if err != nil {
		t.Fatalf("runFreshCore error: %v", err)
	}
	if firstRun {
		t.Fatal("firstRun = true, want false on a full core")
	}
	if res == nil {
		t.Fatal("runFreshCore returned nil result on a full core")
	}
	if startTUIRan {
		t.Fatal("runFreshCore invoked StartTUI; step 8 must belong to RunFresh, not the core")
	}
	assertOrder(t, []string{
		"0a:ResolveHome", "0:RunFirstRun", "1:LoadGlobalSettings", "2:ResolveProjectRoot",
		"2b:GateTrust", "2.5:ScaffoldProjectIgnore", "2.6:RecoverJournals", "3:ComposeConfig", "4:LoadVCSTemplates",
		"5:ValidatePreferredVCS",
		"6:DetectVCS", "6c:BuildToolRegistry", "7:DetermineModel", "7b:EnsureFreshSession",
		"7b:AcquireLock", "7b1:AppendLaunchBegan", "7b2:InitMode", "7c:LoadAgentInstructions",
	}, order)
}

// TestRunFreshCore_FirstRunShortCircuits proves the step-0 first-run branch returns
// (nil, true, nil) without running steps 1+, so both RunFresh and RunHeadless exit 0.
func TestRunFreshCore_FirstRunShortCircuits(t *testing.T) {
	var order []string
	steps := recordingSteps(&order)
	steps.RunFirstRun = func(string) (bool, error) {
		order = append(order, "0:RunFirstRun")
		return true, nil
	}

	res, firstRun, err := runFreshCore(context.Background(), "/cwd", steps)
	if err != nil {
		t.Fatalf("runFreshCore error: %v", err)
	}
	if !firstRun {
		t.Fatal("firstRun = false, want true on the step-0 first-run branch")
	}
	if res != nil {
		t.Fatalf("result = %v, want nil on the first-run branch", res)
	}
	assertOrder(t, []string{"0a:ResolveHome", "0:RunFirstRun"}, order)
}

// TestRunFresh_HomeResolveFailureWrapped confirms a step-0a failure is wrapped as
// HomeResolveError and short-circuits before first-run.
func TestRunFresh_HomeResolveFailureWrapped(t *testing.T) {
	var order []string
	steps := recordingSteps(&order)
	homeErr := errors.New("$HOME unset")
	steps.ResolveHome = func() (string, error) {
		order = append(order, "0a:ResolveHome")
		return "", homeErr
	}

	_, err := RunFresh(context.Background(), "/cwd", steps)
	var hre *HomeResolveError
	if !errors.As(err, &hre) {
		t.Fatalf("err = %v, want *HomeResolveError", err)
	}
	if !errors.Is(err, homeErr) {
		t.Fatalf("wrapped error does not unwrap to home error: %v", err)
	}
	assertOrder(t, []string{"0a:ResolveHome"}, order)
}

func TestDefaultRunFirstRun_SettingsPresent_ProceedsNoRun(t *testing.T) {
	home := t.TempDir()
	writeSettingsFile(t, home)

	ran, err := defaultRunFirstRun(home, nil, nil)
	if err != nil {
		t.Fatalf("defaultRunFirstRun error: %v", err)
	}
	if ran {
		t.Fatal("ran = true when settings already present; want false")
	}
}

func TestDefaultRunFirstRun_SettingsAbsent_GeneratesAndReportsRan(t *testing.T) {
	home := t.TempDir()
	var stdout, stderr bytes.Buffer

	ran, err := defaultRunFirstRun(home, &stdout, &stderr)
	if err != nil {
		t.Fatalf("defaultRunFirstRun error: %v", err)
	}
	if !ran {
		t.Fatal("ran = false when settings absent; want true")
	}
	if _, statErr := os.Stat(SettingsPath(home)); statErr != nil {
		t.Fatalf("settings.yaml not generated: %v", statErr)
	}
}

// TestDefaultFreshSteps_EnsureFreshSession_CanonicalizesAndStaysFresh exercises
// the production EnsureFreshSession entry (not an injected fake) and pins it to
// canonicalize the project root, place the store under
// SessionRoot(home)/FolderDirName(canonicalRoot), record the canonical root in
// the folder file, and return an empty record stream. A non-canonical input
// ("/.") makes the test fail if CanonicalizeFolder is dropped; reverting the
// entry to a stub fails it on the nil-store/path assertions.
func TestDefaultFreshSteps_EnsureFreshSession_CanonicalizesAndStaysFresh(t *testing.T) {
	home := t.TempDir()
	projectRoot := t.TempDir()

	canonical, err := sessions.CanonicalizeFolder(projectRoot)
	if err != nil {
		t.Fatalf("CanonicalizeFolder: %v", err)
	}

	store, err := DefaultFreshSteps(io.Discard, io.Discard).EnsureFreshSession(home, projectRoot+"/.")
	if err != nil {
		t.Fatalf("EnsureFreshSession: %v", err)
	}
	if store == nil {
		t.Fatal("store = nil, want non-nil")
	}
	if got := store.Records(); len(got) != 0 {
		t.Errorf("record stream = %v, want empty fresh session", got)
	}

	wantDir := filepath.Join(sessions.SessionRoot(home), sessions.FolderDirName(canonical))
	if got := filepath.Dir(store.Path()); got != wantDir {
		t.Errorf("store dir = %q, want %q", got, wantDir)
	}

	// "folder" is the fixed folder-file name written by EnsureFolderDir; it must
	// record the canonical project root, not the raw input.
	data, err := os.ReadFile(filepath.Join(wantDir, "folder"))
	if err != nil {
		t.Fatalf("read folder file: %v", err)
	}
	if got := strings.TrimSuffix(string(data), "\n"); got != canonical {
		t.Errorf("folder file = %q, want canonical root %q", got, canonical)
	}
}

func TestDefaultFreshSteps_AppendLaunchBegan_DurableReadback(t *testing.T) {
	store := mkStore(t)
	steps := DefaultFreshSteps(io.Discard, io.Discard)

	if err := steps.AppendLaunchBegan(context.Background(), store); err != nil {
		t.Fatalf("AppendLaunchBegan: %v", err)
	}

	disk := readSessionFile(t, store.Path())
	if got, want := diskEventKinds(disk), []string{events.KindLaunchBegan}; !slices.Equal(got, want) {
		t.Fatalf("disk event kinds = %v, want %v", got, want)
	}
	if got := firstLaunchBeganSource(t, disk); got != "fresh" {
		t.Fatalf("launch_began source = %q, want fresh", got)
	}
}

// TestDefaultFreshSteps_InitMode_DurableReadback drives the production step-7b2
// adapter (not a fake): with mode.default absent it seeds the run mode at the
// default (build), records source "default", and durably appends a single
// interaction_mode{trigger:"launch"} readable back from the flushed session file.
func TestDefaultFreshSteps_InitMode_DurableReadback(t *testing.T) {
	store := mkStore(t)
	steps := DefaultFreshSteps(io.Discard, io.Discard)

	modeState, err := steps.InitMode(context.Background(), store, map[string]any{}, "/proj", []string{SettingsPath("/home/u")})
	if err != nil {
		t.Fatalf("InitMode: %v", err)
	}
	active, ok := modeState.(*mode.ActiveState)
	if !ok || active == nil {
		t.Fatalf("InitMode returned %T, want *mode.ActiveState", modeState)
	}
	if m, src := active.Current(); m != mode.Build || src != mode.SourceDefault {
		t.Fatalf("active mode = (%q, %q), want (build, default)", m, src)
	}

	disk := readSessionFile(t, store.Path())
	if got, want := diskEventKinds(disk), []string{events.KindInteractionMode}; !slices.Equal(got, want) {
		t.Fatalf("disk event kinds = %v, want %v", got, want)
	}
	im := diskInteractionMode(t, disk)
	if len(im) != 1 || im[0].Mode != "build" || im[0].Source != "default" || im[0].Trigger != "launch" {
		t.Fatalf("durable interaction_mode = %+v, want one {build, default, launch}", im)
	}
}

// TestDefaultFreshSteps_InitMode_ConfiguredSource pins the source classification: a
// present mode.default records source "config" (and the configured mode), durable on
// disk — proving the adapter threads the cache's configured flag, not a hardcoded
// "default".
func TestDefaultFreshSteps_InitMode_ConfiguredSource(t *testing.T) {
	store := mkStore(t)
	steps := DefaultFreshSteps(io.Discard, io.Discard)
	composed := map[string]any{"mode": map[string]any{"default": "plan"}}

	modeState, err := steps.InitMode(context.Background(), store, composed, "/proj", nil)
	if err != nil {
		t.Fatalf("InitMode: %v", err)
	}
	if m, src := modeState.(*mode.ActiveState).Current(); m != mode.Plan || src != mode.SourceConfig {
		t.Fatalf("active mode = (%q, %q), want (plan, config)", m, src)
	}
	im := diskInteractionMode(t, readSessionFile(t, store.Path()))
	if len(im) != 1 || im[0].Mode != "plan" || im[0].Source != "config" || im[0].Trigger != "launch" {
		t.Fatalf("durable interaction_mode = %+v, want one {plan, config, launch}", im)
	}
}

func TestDefaultFreshSteps_ConfigFeedsModelDetermination(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	settings := `provider:
  openai:
    base_url: https://api.openai.com/v1
    api_key: sk-test
`
	if err := os.MkdirAll(filepath.Dir(SettingsPath(home)), 0o755); err != nil {
		t.Fatalf("mkdir settings parent: %v", err)
	}
	if err := os.WriteFile(SettingsPath(home), []byte(settings), 0o600); err != nil {
		t.Fatalf("write settings: %v", err)
	}

	steps := DefaultFreshSteps(io.Discard, io.Discard)
	global, err := steps.LoadGlobalSettings(home)
	if err != nil {
		t.Fatalf("LoadGlobalSettings: %v", err)
	}
	root, projectLayers, err := steps.ResolveProjectRoot(cwd, global)
	if err != nil {
		t.Fatalf("ResolveProjectRoot: %v", err)
	}
	composition, err := steps.ComposeConfig(global, root)
	if err != nil {
		t.Fatalf("ComposeConfig: %v", err)
	}
	_, pickerRequired, err := steps.DetermineModel(composition.Config, global, root, append([]string{SettingsPath(home)}, projectLayers...))
	if err != nil {
		t.Fatalf("DetermineModel: %v", err)
	}
	if !pickerRequired {
		t.Fatal("pickerRequired = false, want true when configured providers have selectable models but no active selection")
	}
}

// TestDefaultFreshSteps_ComposeConfig_RejectsProjectLocalAuth pins the project-local
// global-only auth contract through the *production* loader path: ComposeConfig calls
// readAdmittedProjectSettingsLayer, which runs config.EnforceGlobalOnly after schema
// validation. A schema-valid auth block (or a bare top-level auth: {}) written into a real
// project .codemeld/settings.yaml must therefore fail composition with the deterministic
// global-only key and remediation. Asserting through ComposeConfig (not EnforceGlobalOnly
// directly) means dropping the loader's EnforceGlobalOnly call regresses this test.
func TestDefaultFreshSteps_ComposeConfig_RejectsProjectLocalAuth(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantKey string // dotted key as it appears after "schema validation failed at "
	}{
		{
			"full auth.openai-chatgpt session",
			`auth:
  openai-chatgpt:
    access_token: at
    refresh_token: rt
    expires_at: "2026-01-01T00:00:00Z"
    account_id: acct
`,
			"auth.openai-chatgpt",
		},
		{
			"bare top-level auth map",
			`auth: {}
`,
			"auth",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projectRoot := t.TempDir()
			projectPath := projectSettingsPath(projectRoot)
			if err := os.MkdirAll(filepath.Dir(projectPath), 0o755); err != nil {
				t.Fatalf("mkdir project settings parent: %v", err)
			}
			if err := os.WriteFile(projectPath, []byte(tt.yaml), 0o600); err != nil {
				t.Fatalf("write project settings: %v", err)
			}

			_, err := DefaultFreshSteps(io.Discard, io.Discard).ComposeConfig(map[string]any{}, projectRoot)
			if err == nil {
				t.Fatal("ComposeConfig() = nil error, want project-local auth rejection")
			}
			if want := "schema validation failed at " + tt.wantKey + ":"; !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not contain offending key marker %q", err.Error(), want)
			}
			if want := "moved to ~/.codemeld/global/settings.yaml"; !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not contain global-only remediation %q", err.Error(), want)
			}
		})
	}
}

func TestDefaultFreshSteps_ComposeConfig_RejectsProjectLocalFavorites(t *testing.T) {
	writeProject := func(t *testing.T, yaml string) string {
		t.Helper()
		projectRoot := t.TempDir()
		projectPath := projectSettingsPath(projectRoot)
		if err := os.MkdirAll(filepath.Dir(projectPath), 0o755); err != nil {
			t.Fatalf("mkdir project settings parent: %v", err)
		}
		if err := os.WriteFile(projectPath, []byte(yaml), 0o600); err != nil {
			t.Fatalf("write project settings: %v", err)
		}
		return projectRoot
	}

	const favoritesYAML = `model:
  active: gpt-5.5
  favorites:
    - provider: openai
      id: gpt-5.5
`
	if err := config.Validate([]byte(favoritesYAML), "settings.yaml"); err != nil {
		t.Fatalf("project fixture must be schema-valid, got %v", err)
	}

	projectRoot := writeProject(t, favoritesYAML)
	_, err := DefaultFreshSteps(io.Discard, io.Discard).ComposeConfig(map[string]any{}, projectRoot)
	if err == nil {
		t.Fatal("ComposeConfig() = nil error, want project-local model.favorites rejection")
	}
	if want := "schema validation failed at model.favorites:"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain offending key marker %q", err.Error(), want)
	}
	if want := "moved to ~/.codemeld/global/settings.yaml"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain global-only remediation %q", err.Error(), want)
	}

	activeOnly := writeProject(t, `model:
  active: gpt-5.5
`)
	composition, err := DefaultFreshSteps(io.Discard, io.Discard).ComposeConfig(map[string]any{}, activeOnly)
	if err != nil {
		t.Fatalf("ComposeConfig() with project model.active = %v, want nil", err)
	}
	model, ok := composition.Config["model"].(map[string]any)
	if !ok {
		t.Fatalf("composed model = %#v, want map", composition.Config["model"])
	}
	if model["active"] != "gpt-5.5" {
		t.Fatalf("composed model.active = %#v, want %q", model["active"], "gpt-5.5")
	}
}

// TestDefaultFreshSteps_LoadAgentInstructions_DurableAndLaunchAnchored drives the
// production step-7c adapter (not a fake) against real temp dirs and a writable
// store, then reads the session file back to prove the agent_instructions_loaded
// records are durable. It also pins the launch anchor: a sibling
// projectRoot/AGENTS.md is never loaded while launchDir/AGENTS.md is, so the walk is
// anchored on the launch directory, not the resolved project root (a test where
// cwd == projectRoot could not catch a regression that swapped the anchor back to
// projectRoot). Finally it pins the configured size cap: the launch fixture exceeds
// the composed agent_instructions.max_file_bytes value, so its durable record must
// be a size_limit skip — proving the adapter threads the configured cap rather than
// a hardcoded default.
func TestDefaultFreshSteps_LoadAgentInstructions_DurableAndLaunchAnchored(t *testing.T) {
	home := t.TempDir()
	launchDir := t.TempDir()
	projectRoot := t.TempDir() // a sibling of launchDir, deliberately not an ancestor

	const maxFileBytes = 16
	globalPath := writeGlobalAgents(t, home, "# global\n")                           // 9 bytes, within the cap → loaded
	launchPath := writeAgentsFile(t, launchDir, strings.Repeat("L", maxFileBytes+1)) // over the cap → size_limit skip
	projectPath := writeAgentsFile(t, projectRoot, "# project root — must not load\n")

	store := storeAt(t, filepath.Join(t.TempDir(), "session.json"),
		"01890000-0000-7000-8000-000000000420", projectRoot)

	composed := map[string]any{"agent_instructions": map[string]any{"max_file_bytes": maxFileBytes}}
	step := DefaultFreshSteps(io.Discard, io.Discard).LoadAgentInstructions
	entries, err := step(context.Background(), store, home, launchDir, composed, projectRoot, []string{SettingsPath(home)})
	if err != nil {
		t.Fatalf("LoadAgentInstructions: %v", err)
	}

	// In-memory record: global at load_order 1, launchDir as a later walked entry,
	// and the sibling project root's AGENTS.md absent (the anchor proof).
	global := findLoadEntry(t, entries, globalPath)
	if global.Layer != agentinstr.LayerGlobal || global.LoadOrder != 1 {
		t.Fatalf("global entry = %+v, want layer=%q load_order=1", global, agentinstr.LayerGlobal)
	}
	launch := findLoadEntry(t, entries, launchPath)
	if launch.Layer != agentinstr.LayerWalked || launch.LoadOrder <= global.LoadOrder {
		t.Fatalf("launch entry = %+v, want walked with load_order > global's", launch)
	}
	assertNoEntryPath(t, entries, projectPath, "project-root AGENTS.md loaded; walk anchored on projectRoot, not launchDir")

	// Durable record: reload the flushed session file and assert the
	// agent_instructions_loaded events landed in launch order (global before walked).
	loaded := diskAgentInstr(t, readSessionFile(t, store.Path()))
	if len(loaded) < 2 {
		t.Fatalf("durable agent_instructions_loaded count = %d, want >= 2 (global + launch)", len(loaded))
	}
	if loaded[0].Path != globalPath || loaded[0].Layer != agentinstr.LayerGlobal || loaded[0].LoadOrder != 1 {
		t.Fatalf("first durable record = %+v, want the global file at load_order 1", loaded[0])
	}
	gi, li := diskIndex(loaded, globalPath), diskIndex(loaded, launchPath)
	if li < 0 {
		t.Fatalf("launch AGENTS.md absent from durable records: %+v", loaded)
	}
	if gi >= li {
		t.Fatalf("global (idx %d) did not precede walked launch (idx %d) on disk", gi, li)
	}
	for _, p := range loaded {
		if p.Path == projectPath {
			t.Fatal("project-root AGENTS.md persisted; the anchor was projectRoot, not launchDir")
		}
	}

	// Configured cap: the over-cap launch fixture must land as a size_limit skip.
	assertConfiguredCapHonored(t, store, launchPath)
}

func TestDefaultFreshSteps_LoadAgentInstructionsWriteFailureUsesCleanShutdownProtocol(t *testing.T) {
	store := unwritableStore(t, "01890000-0000-7000-8000-000000000420", "/proj")
	step := DefaultFreshSteps(io.Discard, io.Discard).LoadAgentInstructions

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w

	_, err = step(context.Background(), store, t.TempDir(), t.TempDir(), nil, "/proj", nil)

	_ = w.Close()
	os.Stderr = oldStderr
	captured, _ := io.ReadAll(r)

	if !errors.Is(err, ErrSessionWriteOnExit) {
		t.Fatalf("LoadAgentInstructions error = %v, want ErrSessionWriteOnExit", err)
	}
	if got := string(captured); !strings.Contains(got, "codemeld: session-write-on-exit failed") {
		t.Fatalf("stderr = %q, want session-write-on-exit OP_FAIL", got)
	}
	if got := countEvents(store, events.KindSessionWriteFailed); got != 0 {
		t.Fatalf("session_write_failed events = %d, want 0 for clean-shutdown protocol", got)
	}
}

func TestRunFresh_AcquireLockFailureStartsNoRuntimeOrRecords(t *testing.T) {
	var order []string
	steps := recordingSteps(&order)
	store := unwritableStore(t, "01890000-0000-7000-8000-0000000000a1", "/proj")
	steps.EnsureFreshSession = func(string, string) (*sessions.Store, error) {
		order = append(order, "7b:EnsureFreshSession")
		return store, nil
	}
	steps.AcquireLock = sessions.AcquireResumeLock
	startedTUI := false
	steps.StartTUI = func(context.Context, *BootstrapResult) error { startedTUI = true; return nil }

	res, err := RunFresh(context.Background(), "/cwd", steps)

	var lockErr *sessions.ResumeLockError
	if !errors.As(err, &lockErr) {
		t.Fatalf("err = %v, want *sessions.ResumeLockError", err)
	}
	if res != nil {
		t.Fatalf("result = %v, want nil on acquisition failure", res)
	}
	if startedTUI {
		t.Fatal("StartTUI ran after acquisition failed; acquisition failure must start no runtime")
	}
	if got := store.Records(); len(got) != 0 {
		t.Fatalf("fresh record stream = %v, want empty (acquisition fails before launch_began)", got)
	}
	if slices.Contains(order, "7b1:AppendLaunchBegan") {
		t.Fatalf("launch_began ran after acquisition failed; order=%v", order)
	}
}

func TestRunFresh_PostAcquireFailuresReleaseExactlyOnce(t *testing.T) {
	sentinel := errors.New("post-acquire boom")
	cases := []struct {
		name string
		fail func(s *FreshSteps)
	}{
		{"AppendLaunchBegan", func(s *FreshSteps) {
			s.AppendLaunchBegan = func(context.Context, *sessions.Store) error { return sentinel }
		}},
		{"InitMode", func(s *FreshSteps) {
			s.InitMode = func(context.Context, *sessions.Store, map[string]any, string, []string) (any, error) {
				return nil, sentinel
			}
		}},
		{"LoadAgentInstructions", func(s *FreshSteps) {
			s.LoadAgentInstructions = func(context.Context, *sessions.Store, string, string, map[string]any, string, []string) ([]agentinstr.LoadEntry, error) {
				return nil, sentinel
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var order []string
			steps := recordingSteps(&order)
			store := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000f2", t.TempDir())
			steps.EnsureFreshSession = func(string, string) (*sessions.Store, error) { return store, nil }
			var releases int32
			steps.AcquireLock = countingAcquire(&releases)
			startedTUI := false
			steps.StartTUI = func(context.Context, *BootstrapResult) error { startedTUI = true; return nil }
			tc.fail(&steps)

			_, err := RunFresh(context.Background(), "/cwd", steps)
			if !errors.Is(err, sentinel) {
				t.Fatalf("err = %v, want sentinel", err)
			}
			if startedTUI {
				t.Fatal("StartTUI ran after a post-acquisition core failure")
			}
			if got := atomic.LoadInt32(&releases); got != 1 {
				t.Fatalf("physical releases = %d, want exactly 1 after a post-acquisition failure", got)
			}
			if resumeLockHeld(t, store.Path()) {
				t.Fatal("sidecar still held after a post-acquisition failure; the core did not release ownership")
			}
		})
	}
}

func TestRunFresh_HoldsLockThroughStartTUIAndReleasesExactlyOnce(t *testing.T) {
	cases := []struct {
		name   string
		runErr error
	}{
		{"normal return", nil},
		{"startup error", errors.New("tui boom")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000f3", t.TempDir())
			var order []string
			steps := recordingSteps(&order)
			steps.ResolveHome = func() (string, error) { return t.TempDir(), nil }
			steps.EnsureFreshSession = func(string, string) (*sessions.Store, error) { return store, nil }
			var releases int32
			steps.AcquireLock = countingAcquire(&releases)
			steps.StartTUI = func(ctx context.Context, res *BootstrapResult) error { return StartTUI(ctx, res, io.Discard) }

			heldInsideLoop := false
			defer swapRunApp(func(a *tui.App) error {
				heldInsideLoop = resumeLockHeld(t, store.Path())
				return tc.runErr
			})()

			_, err := RunFresh(context.Background(), "/cwd", steps)
			awaitFreshPrune(t, store.Path())
			if tc.runErr == nil && err != nil {
				t.Fatalf("RunFresh error: %v", err)
			}
			if tc.runErr != nil && !errors.Is(err, tc.runErr) {
				t.Fatalf("RunFresh err = %v, want %v", err, tc.runErr)
			}
			if !heldInsideLoop {
				t.Fatal("resume lock not contended inside StartTUI's event loop; a fresh launch must hold it through the runtime")
			}
			if resumeLockHeld(t, store.Path()) {
				t.Fatal("resume lock still held after StartTUI returned; the fresh session must be acquirable after every return path")
			}
			if got := atomic.LoadInt32(&releases); got != 1 {
				t.Fatalf("physical releases = %d, want exactly 1 across the holder and the outer fallback cleanup", got)
			}
		})
	}
}

func awaitFreshPrune(t *testing.T, sessionPath string) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if data, err := os.ReadFile(sessionPath); err == nil && bytes.Contains(data, []byte(events.KindSessionPruneSummary)) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("background prune summary never landed durably; the fresh-launch prune did not complete")
}

func countingAcquire(releases *int32) func(string, string) (func(), error) {
	return func(path, id string) (func(), error) {
		release, err := sessions.AcquireResumeLock(path, id)
		if err != nil {
			return nil, err
		}
		return func() { atomic.AddInt32(releases, 1); release() }, nil
	}
}

// --- helpers ---

// writeAgentsFile writes an AGENTS.md with content under dir and returns its path.
func writeAgentsFile(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "AGENTS.md")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// writeGlobalAgents writes the global AGENTS.md at home/.codemeld/global/AGENTS.md
// (the load_order-1 slot) and returns its path.
func writeGlobalAgents(t *testing.T, home, content string) string {
	t.Helper()
	dir := filepath.Join(home, ".codemeld", "global")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir global dir: %v", err)
	}
	return writeAgentsFile(t, dir, content)
}

// diskAgentInstr decodes the agent_instructions_loaded payloads from a disk-read
// session record stream, in stream order, so a test asserts the flushed/durable
// records rather than the in-memory store object.
func diskAgentInstr(t *testing.T, sess *sessions.Session) []events.AgentInstructionsLoaded {
	t.Helper()
	return decodeDiskEvents[events.AgentInstructionsLoaded](t, sess, events.KindAgentInstructionsLoaded)
}

// diskInteractionMode decodes the interaction_mode payloads from a disk-read session
// record stream, in stream order, so a test asserts the flushed/durable records.
func diskInteractionMode(t *testing.T, sess *sessions.Session) []events.InteractionMode {
	t.Helper()
	return decodeDiskEvents[events.InteractionMode](t, sess, events.KindInteractionMode)
}

// findLoadEntry returns the entry whose Path equals path, failing if none exists.
func findLoadEntry(t *testing.T, entries []agentinstr.LoadEntry, path string) agentinstr.LoadEntry {
	t.Helper()
	for _, e := range entries {
		if e.Path == path {
			return e
		}
	}
	t.Fatalf("no load entry for %q in %+v", path, entries)
	return agentinstr.LoadEntry{}
}

// assertNoEntryPath fails with msg when any entry carries path.
func assertNoEntryPath(t *testing.T, entries []agentinstr.LoadEntry, path, msg string) {
	t.Helper()
	for _, e := range entries {
		if e.Path == path {
			t.Fatalf("%s: %+v", msg, e)
		}
	}
}

// diskIndex returns the stream position of the durable record carrying path, or -1.
func diskIndex(loaded []events.AgentInstructionsLoaded, path string) int {
	for i, p := range loaded {
		if p.Path == path {
			return i
		}
	}
	return -1
}

// assertConfiguredCapHonored reads store's flushed session file and asserts the
// durable agent_instructions_loaded record for capExceededPath was skipped as
// size_limit. Both production-step tests call it to pin that the adapter must
// thread the composed agent_instructions.max_file_bytes cap into the walk. Were it
// to ignore the config and use a hardcoded default, that file would be loaded with
// an empty SkipReason and this assertion would fail.
func assertConfiguredCapHonored(t *testing.T, store *sessions.Store, capExceededPath string) {
	t.Helper()
	for _, p := range diskAgentInstr(t, readSessionFile(t, store.Path())) {
		if p.Path == capExceededPath {
			if p.SkipReason != agentinstr.SkipSizeLimit {
				t.Fatalf("durable record for %q SkipReason = %q, want %q (configured max_file_bytes cap not threaded through)", capExceededPath, p.SkipReason, agentinstr.SkipSizeLimit)
			}
			return
		}
	}
	t.Fatalf("no durable agent_instructions_loaded record for %q (configured-cap fixture missing)", capExceededPath)
}

func writeSettingsFile(t *testing.T, home string) {
	t.Helper()
	path := SettingsPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("model: {}\n"), 0o600); err != nil {
		t.Fatalf("write settings: %v", err)
	}
}

func assertOrder(t *testing.T, want, got []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("step count = %d, want %d\n got=%v\nwant=%v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("step %d = %q, want %q\n got=%v\nwant=%v", i, got[i], want[i], got, want)
		}
	}
}

// --- step 2b: the project trust gate ---

// trustGateFixture composes over a real temporary home and project through the production
// composition step, so an untrusted decision is proven against the path the launch runs.
func trustGateFixture(t *testing.T, order *[]string, decision trust.Decision) (FreshSteps, string, string) {
	t.Helper()
	home, projectRoot := t.TempDir(), t.TempDir()
	projectPath := projectSettingsPath(projectRoot)
	if err := os.MkdirAll(filepath.Dir(projectPath), 0o755); err != nil {
		t.Fatalf("mkdir project settings parent: %v", err)
	}
	const projectYAML = `agent:
  max_concurrency: 7
permissions:
  - kind: direct
    subject: rm
    path_scope: /
    grant_kind: folder
`
	if err := os.WriteFile(projectPath, []byte(projectYAML), 0o600); err != nil {
		t.Fatalf("write project settings: %v", err)
	}

	steps := recordingSteps(order)
	steps.ResolveHome = func() (string, error) { return home, nil }
	steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) {
		return projectRoot, []string{projectPath}, nil
	}
	steps.GateTrust = func(string, string, string) trust.Decision {
		return decision
	}
	steps.ComposeConfig = defaultComposeConfig
	return steps, home, projectRoot
}

func TestRunFresh_UntrustedProjectComposesFromTheGlobalLayerAlone(t *testing.T) {
	global := map[string]any{"agent": map[string]any{"max_concurrency": 2}}

	t.Run("untrusted", func(t *testing.T) {
		var order []string
		steps, home, projectRoot := trustGateFixture(t, &order, trust.Decision{Reason: trust.ReasonNoRecord})
		steps.LoadGlobalSettings = func(string) (map[string]any, error) { return global, nil }

		res, err := RunFresh(context.Background(), "/cwd", steps)
		if err != nil {
			t.Fatalf("RunFresh error: %v", err)
		}
		if want := []string{SettingsPath(home)}; !slices.Equal(res.ConfigLayerPaths, want) {
			t.Fatalf("ConfigLayerPaths = %v, want %v (the untrusted project path withheld)", res.ConfigLayerPaths, want)
		}
		agent, _ := res.Config["agent"].(map[string]any)
		if fmt.Sprint(agent["max_concurrency"]) != "2" {
			t.Fatalf("agent.max_concurrency = %v, want the global value 2 (no project override)", agent["max_concurrency"])
		}
		if _, ok := res.Config["permissions"]; ok {
			t.Fatalf("composed config = %#v, want no project permission entry in the effective set", res.Config)
		}
		if res.ProjectRoot != projectRoot {
			t.Fatalf("ProjectRoot = %q, want the resolved root %q to survive for session and tool scoping", res.ProjectRoot, projectRoot)
		}
	})

	t.Run("trusted", func(t *testing.T) {
		var order []string
		steps, home, projectRoot := trustGateFixture(t, &order,
			trust.Decision{Trusted: true, Reason: trust.ReasonTrusted})
		steps.LoadGlobalSettings = func(string) (map[string]any, error) { return global, nil }

		res, err := RunFresh(context.Background(), "/cwd", steps)
		if err != nil {
			t.Fatalf("RunFresh error: %v", err)
		}
		want := []string{SettingsPath(home), projectSettingsPath(projectRoot)}
		if !slices.Equal(res.ConfigLayerPaths, want) {
			t.Fatalf("ConfigLayerPaths = %v, want %v", res.ConfigLayerPaths, want)
		}
		agent, _ := res.Config["agent"].(map[string]any)
		if fmt.Sprint(agent["max_concurrency"]) != "7" {
			t.Fatalf("agent.max_concurrency = %v, want the project override 7", agent["max_concurrency"])
		}
		perms, _ := res.Config["permissions"].([]any)
		if len(perms) != 1 {
			t.Fatalf("permissions = %#v, want the project entry composed for a trusted root", res.Config["permissions"])
		}
	})
}

func TestRunFresh_RetainsTheTrustHandoff(t *testing.T) {
	for _, tc := range []struct {
		name     string
		decision trust.Decision
	}{
		{"trusted", trust.Decision{Trusted: true, Reason: trust.ReasonTrusted, Root: "/proj"}},
		{"untrusted", trust.Decision{Reason: trust.ReasonNoRecord, Root: "/proj"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var order []string
			steps := recordingSteps(&order)
			steps.GateTrust = func(string, string, string) trust.Decision {
				return tc.decision
			}

			res, err := RunFresh(context.Background(), "/cwd", steps)
			if err != nil {
				t.Fatalf("RunFresh error: %v", err)
			}
			if res.TrustDecision != tc.decision {
				t.Fatalf("TrustDecision = %#v, want %#v", res.TrustDecision, tc.decision)
			}
		})
	}
}

func TestRunFresh_GateRunsBeforeComposition(t *testing.T) {
	var order []string
	steps := recordingSteps(&order)
	var decidedBeforeCompose bool
	steps.ComposeConfig = func(map[string]any, string) (ConfigComposition, error) {
		decidedBeforeCompose = slices.Contains(order, "2b:GateTrust")
		order = append(order, "3:ComposeConfig")
		return ConfigComposition{}, nil
	}

	if _, err := RunFresh(context.Background(), "/cwd", steps); err != nil {
		t.Fatalf("RunFresh error: %v", err)
	}
	if !decidedBeforeCompose {
		t.Fatalf("ComposeConfig ran before the trust gate; order = %v", order)
	}
}

func TestDefaultFreshSteps_GateTrustDegradesWhenStdinIsNotATerminal(t *testing.T) {
	home := t.TempDir()
	projectRoot := trustProject(t, "model: {}\n")
	var stderr strings.Builder

	decision := DefaultFreshSteps(io.Discard, &stderr).GateTrust(home, projectRoot, projectRoot)

	if decision.Trusted {
		t.Fatalf("decision = %#v, want an untrusted launch", decision)
	}
	if countNotices(stderr.String()) != 1 {
		t.Fatalf("stderr = %q, want exactly one ignored-settings notice", stderr.String())
	}
	trustStoreAbsent(t, home)
}

// A candidate marker that cannot be classified must reach the gate as a failure, not as a
// fallback root whose covered set looks empty.
func TestRunFresh_DiscoveryFailureCannotBecomeVacuousTrust(t *testing.T) {
	home, base := t.TempDir(), t.TempDir()
	project := filepath.Join(base, "project")
	cwd := filepath.Join(project, "nested")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatalf("mkdir cwd: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(project, ".codemeld", "settings.yaml"), 0o755); err != nil {
		t.Fatalf("mkdir non-regular marker: %v", err)
	}
	global := map[string]any{
		"discovery": map[string]any{"boundary": "project-root"},
		"agent":     map[string]any{"max_concurrency": 2},
	}

	var stderr strings.Builder
	production := DefaultFreshSteps(io.Discard, &stderr)
	var order []string
	steps := recordingSteps(&order)
	steps.ResolveHome = func() (string, error) { return home, nil }
	steps.LoadGlobalSettings = func(string) (map[string]any, error) { return global, nil }
	steps.ResolveProjectRoot = production.ResolveProjectRoot
	steps.GateTrust = production.GateTrust
	steps.ComposeConfig = defaultComposeConfig

	res, _, err := runFreshCore(context.Background(), cwd, steps)
	if err != nil {
		t.Fatalf("runFreshCore error: %v", err)
	}
	if res.ProjectRoot != project {
		t.Fatalf("ProjectRoot = %q, want the unclassifiable candidate's directory %q", res.ProjectRoot, project)
	}
	if res.TrustDecision.Trusted || res.TrustDecision.Reason != trust.ReasonUnreadable {
		t.Fatalf("TrustDecision = %#v, want untrusted %q", res.TrustDecision, trust.ReasonUnreadable)
	}
	if want := []string{SettingsPath(home)}; !slices.Equal(res.ConfigLayerPaths, want) {
		t.Fatalf("ConfigLayerPaths = %v, want %v", res.ConfigLayerPaths, want)
	}
	if countNotices(stderr.String()) != 1 {
		t.Fatalf("stderr = %q, want exactly one ignored-settings notice", stderr.String())
	}
	if strings.Contains(stderr.String(), approvePrompt) {
		t.Fatalf("stderr = %q, want no prompt for content that could not be inspected", stderr.String())
	}
	trustStoreAbsent(t, home)
}

// The settings file is also the project-root marker, so deleting it erases the address the
// approval is filed under: a nested launch then resolves the launch anchor instead.
func TestRunFresh_RemovalKeepsTheListedRootApprovedButNotANestedLaunch(t *testing.T) {
	home, base := t.TempDir(), t.TempDir()
	project := filepath.Join(base, "project")
	nested := filepath.Join(project, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	marker := projectSettingsPath(project)
	if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
		t.Fatalf("mkdir marker parent: %v", err)
	}
	if err := os.WriteFile(marker, []byte("model: {}\n"), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	if decision := gateTrust(home, project, project, strings.NewReader("y\n"), &strings.Builder{}, true); !decision.Trusted {
		t.Fatalf("setup decision = %#v, want the project approved before removal", decision)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatalf("remove marker: %v", err)
	}

	global := map[string]any{"discovery": map[string]any{"boundary": "project-root"}}
	resolve := DefaultFreshSteps(io.Discard, io.Discard).ResolveProjectRoot

	rootFromProject, _, err := resolve(project, global)
	if err != nil {
		t.Fatalf("ResolveProjectRoot from the project root: %v", err)
	}
	var fromRoot strings.Builder
	decision := gateTrust(home, rootFromProject, rootFromProject, strings.NewReader("\n"), &fromRoot, true)
	if !decision.Trusted || decision.Reason != trust.ReasonTrusted {
		t.Fatalf("decision = %#v, want the listed root still approved", decision)
	}
	if fromRoot.Len() != 0 {
		t.Fatalf("stderr = %q, want a silent approved launch", fromRoot.String())
	}

	rootFromNested, _, err := resolve(nested, global)
	if err != nil {
		t.Fatalf("ResolveProjectRoot from a nested directory: %v", err)
	}
	if rootFromNested == rootFromProject {
		t.Fatalf("nested launch resolved %q, want the launch anchor once the sole marker is gone", rootFromNested)
	}
	var fromNested strings.Builder
	nestedDecision := gateTrust(home, rootFromNested, rootFromNested, strings.NewReader("\n"), &fromNested, true)
	if !nestedDecision.Trusted || nestedDecision.Reason != trust.ReasonNothingCovered {
		t.Fatalf("nested decision = %#v, want nothing to gate at the launch anchor", nestedDecision)
	}
	if fromNested.Len() != 0 {
		t.Fatalf("stderr = %q, want nothing printed", fromNested.String())
	}
	if !slices.Contains(trustStore(t, home).Projects, rootFromProject) {
		t.Fatal("the approval for the resolved root was deleted; the nested launch must not touch it")
	}
}

type agentsFixture struct {
	home, root, launch               string
	globalPath, abovePath            string
	rootPath, middlePath, launchPath string
}

func newAgentsFixture(t *testing.T) agentsFixture {
	t.Helper()
	home := t.TempDir()
	above := t.TempDir()
	root := mkdirAll(t, filepath.Join(above, "repo"))
	middle := mkdirAll(t, filepath.Join(root, "middle"))
	launch := mkdirAll(t, filepath.Join(middle, "launch"))

	outside := writeAgentsFile(t, t.TempDir(), "# outside the root\n")
	middlePath := filepath.Join(middle, "AGENTS.md")
	if err := os.Symlink(outside, middlePath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	return agentsFixture{
		home:       home,
		root:       root,
		launch:     launch,
		globalPath: writeGlobalAgents(t, home, "# global\n"),
		abovePath:  writeAgentsFile(t, above, "# above the root\n"),
		rootPath:   writeAgentsFile(t, root, "# root\n"),
		middlePath: middlePath,
		launchPath: writeAgentsFile(t, launch, "# launch\n"),
	}
}

func (f agentsFixture) repoFiles() []string {
	return []string{f.rootPath, f.middlePath, f.launchPath}
}

func TestDefaultFreshSteps_LoadAgentInstructions_UntrustedRepositoryFilesLoad(t *testing.T) {
	f := newAgentsFixture(t)
	store := storeAt(t, filepath.Join(t.TempDir(), "session.json"),
		"01890000-0000-7000-8000-000000002510", f.root)

	step := DefaultFreshSteps(io.Discard, io.Discard).LoadAgentInstructions
	entries, err := step(context.Background(), store, f.home, f.launch, nil, f.root, nil)
	if err != nil {
		t.Fatalf("LoadAgentInstructions: %v", err)
	}

	want := []string{f.globalPath, f.abovePath, f.rootPath, f.middlePath, f.launchPath}
	var got []string
	for i, e := range entries {
		got = append(got, e.Path)
		if e.LoadOrder != i+1 {
			t.Fatalf("entry %+v, want load_order %d", e, i+1)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("entries = %v, want every discovered file in walk order %v", got, want)
	}

	loaded := diskAgentInstr(t, readSessionFile(t, store.Path()))
	var durable []string
	for _, rec := range loaded {
		durable = append(durable, rec.Path)
	}
	if !slices.Equal(durable, want) {
		t.Fatalf("durable records = %v, want every discovered file in walk order %v", durable, want)
	}
}

// --- the check-then-load window between the gate and composition ---

const raceProjectYAML = "agent:\n  max_concurrency: 7\n"

const raceReplacementYAML = `agent:
  max_concurrency: 9
permissions:
  - kind: direct
    subject: rm
    path_scope: /
    grant_kind: folder
`

// postGateRace is one fresh launch driven through the production trust gate and the production
// step-3 adapter, with the project settings file free to change in the window between them.
type postGateRace struct {
	res          *BootstrapResult
	stderr       string
	projectLayer map[string]any
	approved     bool
}

// runPostGateRace stages the replacement in ScaffoldProjectIgnore, the one step that runs after
// the gate has decided and before composition reads anything.
func runPostGateRace(t *testing.T, home, projectRoot, answer string, afterGate func()) postGateRace {
	t.Helper()
	race, err := runPostGateRaceErr(home, projectRoot, answer, afterGate)
	if err != nil {
		t.Fatalf("runFreshCore: %v", err)
	}
	return race
}

func runPostGateRaceErr(home, projectRoot, answer string, afterGate func()) (postGateRace, error) {
	var stderr strings.Builder
	var order []string
	var layer map[string]any
	steps := recordingSteps(&order)
	steps.ResolveHome = func() (string, error) { return home, nil }
	steps.LoadGlobalSettings = func(string) (map[string]any, error) {
		return map[string]any{"agent": map[string]any{"max_concurrency": 2}}, nil
	}
	steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) {
		return projectRoot, []string{projectSettingsPath(projectRoot)}, nil
	}
	steps.GateTrust = func(home, root, launchDir string) trust.Decision {
		return gateTrust(home, root, launchDir, strings.NewReader(answer), &stderr, answer != "")
	}
	steps.ScaffoldProjectIgnore = func(string) error { afterGate(); return nil }
	steps.ComposeConfig = defaultComposeConfig
	var approved bool
	steps.LoadVCSTemplates = func(_, _ string, projectLayer map[string]any, a bool) (any, error) {
		layer, approved = projectLayer, a
		return nil, nil
	}

	res, _, err := runFreshCore(context.Background(), projectRoot, steps)
	return postGateRace{res: res, stderr: stderr.String(), projectLayer: layer, approved: approved}, err
}

// Trust by vacuity is not approval: a .codemeld/vcs folder that appears after a gate which found
// nothing to cover was approved by no record, so step 4 must not be told the launch is approved.
func TestRunFresh_VacuousTrustDoesNotApproveAPostGateVCSFolder(t *testing.T) {
	home, projectRoot := t.TempDir(), t.TempDir()

	race := runPostGateRace(t, home, projectRoot, "", func() {
		writeVCSFile(t, filepath.Join(projectVCSTemplateDir(projectRoot), "git.yaml"), "name: git\n")
	})

	if race.res.TrustDecision.Reason != trust.ReasonNothingCovered {
		t.Fatalf("TrustDecision = %#v, want the vacuous %q outcome", race.res.TrustDecision, trust.ReasonNothingCovered)
	}
	if race.approved {
		t.Fatal("step-4 approved = true, want a folder no record covers left uncollected")
	}
}

// The control for the vacuous case: a root the gate recorded still loads its project templates.
func TestRunFresh_RecordedTrustApprovesTheProjectVCSFolder(t *testing.T) {
	home := t.TempDir()
	projectRoot := trustProject(t, raceProjectYAML)
	writeVCSFile(t, filepath.Join(projectVCSTemplateDir(projectRoot), "git.yaml"), "name: git\n")

	race := runPostGateRace(t, home, projectRoot, "y\n", func() {})

	if !race.approved {
		t.Fatalf("step-4 approved = false with decision %#v, want a recorded root to load its templates", race.res.TrustDecision)
	}
}

func assertDegradedToGlobalOnly(t *testing.T, race postGateRace, home string) {
	t.Helper()
	if want := []string{SettingsPath(home)}; !slices.Equal(race.res.ConfigLayerPaths, want) {
		t.Fatalf("ConfigLayerPaths = %v, want %v (the unverified project path removed)", race.res.ConfigLayerPaths, want)
	}
	agent, _ := race.res.Config["agent"].(map[string]any)
	if fmt.Sprint(agent["max_concurrency"]) != "2" {
		t.Fatalf("agent.max_concurrency = %v, want the global value 2 with no post-gate override", agent["max_concurrency"])
	}
	if _, ok := race.res.Config["permissions"]; ok {
		t.Fatalf("composed config = %#v, want no project permission entry in the effective grant set", race.res.Config)
	}
	if race.projectLayer != nil {
		t.Fatalf("step-4 project layer = %#v, want nil so attribution cannot use the dropped layer", race.projectLayer)
	}
}

func TestRunFresh_VacuousTrustDoesNotAdmitSettingsWrittenAfterTheGate(t *testing.T) {
	home, projectRoot := t.TempDir(), t.TempDir()

	race := runPostGateRace(t, home, projectRoot, "", func() {
		writeProjectSettings(t, projectRoot, raceReplacementYAML)
	})

	if race.res.TrustDecision.Reason != trust.ReasonNothingCovered {
		t.Fatalf("TrustDecision = %#v, want the vacuous %q outcome", race.res.TrustDecision, trust.ReasonNothingCovered)
	}
	assertDegradedToGlobalOnly(t, race, home)
	trustStoreAbsent(t, home)
}

func TestRunFresh_SettingsChangedAfterTheGateComposeTheBytesOnDisk(t *testing.T) {
	home := t.TempDir()
	projectRoot := trustProject(t, raceProjectYAML)

	race := runPostGateRace(t, home, projectRoot, "y\n", func() {
		writeProjectSettings(t, projectRoot, raceReplacementYAML)
	})

	if !race.res.TrustDecision.Trusted {
		t.Fatalf("TrustDecision = %#v, want the approval to stand", race.res.TrustDecision)
	}
	agent, _ := race.res.Config["agent"].(map[string]any)
	if fmt.Sprint(agent["max_concurrency"]) != "9" {
		t.Fatalf("agent.max_concurrency = %v, want 9 from the bytes on disk at composition", agent["max_concurrency"])
	}
	if perms, _ := race.res.Config["permissions"].([]any); len(perms) != 1 {
		t.Fatalf("permissions = %#v, want the composition-time entry", race.res.Config["permissions"])
	}
	if race.projectLayer == nil {
		t.Fatal("step-4 project layer = nil, want the composed map handed to attribution")
	}
	if countNotices(race.stderr) != 0 {
		t.Fatalf("stderr = %q, want no ignored-settings notice", race.stderr)
	}
}

func TestRunFresh_UnchangedTrustedSettingsComposeAsBefore(t *testing.T) {
	home := t.TempDir()
	projectRoot := trustProject(t, raceProjectYAML)

	race := runPostGateRace(t, home, projectRoot, "y\n", func() {})

	want := []string{SettingsPath(home), projectSettingsPath(projectRoot)}
	if !slices.Equal(race.res.ConfigLayerPaths, want) {
		t.Fatalf("ConfigLayerPaths = %v, want %v", race.res.ConfigLayerPaths, want)
	}
	agent, _ := race.res.Config["agent"].(map[string]any)
	if fmt.Sprint(agent["max_concurrency"]) != "7" {
		t.Fatalf("agent.max_concurrency = %v, want the project override 7", agent["max_concurrency"])
	}
	if !race.res.TrustDecision.Trusted {
		t.Fatalf("decision = %#v, want the ordinary trusted launch intact", race.res.TrustDecision)
	}
	if race.projectLayer == nil {
		t.Fatal("step-4 project layer = nil, want the verified map handed to attribution")
	}
	if countNotices(race.stderr) != 0 {
		t.Fatalf("stderr = %q, want no ignored-settings notice for matching content", race.stderr)
	}
}

// A replacement the covered-read bound refuses — a fifo, or a file past the limit — has to fail the
// post-gate read rather than park the launch in open(2).
func TestRunFresh_UnreadableReplacementAbortsWithoutBlocking(t *testing.T) {
	for _, tt := range []struct {
		name    string
		replace func(t *testing.T, path string)
	}{
		{
			name: "fifo in place of the admitted file",
			replace: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Errorf("remove project settings: %v", err)
				}
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Errorf("replace project settings with a fifo: %v", err)
				}
			},
		},
		{
			name: "replacement past the covered-byte limit",
			replace: func(t *testing.T, path string) {
				padded := raceReplacementYAML + strings.Repeat("#", 64*1024)
				if err := os.WriteFile(path, []byte(padded), 0o600); err != nil {
					t.Errorf("grow project settings past the limit: %v", err)
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			projectRoot := trustProject(t, raceProjectYAML)

			done := make(chan error, 1)
			go func() {
				_, err := runPostGateRaceErr(home, projectRoot, "y\n", func() {
					tt.replace(t, projectSettingsPath(projectRoot))
				})
				done <- err
			}()

			path := projectSettingsPath(projectRoot)
			want := config.FormatLoadError(path, config.UnreadableFile, errUnsafeSettingsRead, config.LaunchAborted)
			select {
			case err := <-done:
				if err == nil || err.Error() != want {
					t.Fatalf("err = %v, want the unsafe-read launch abort %q", err, want)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("composition blocked on the replaced settings path instead of aborting")
			}
		})
	}
}

// A run the gate already refused must not read the project settings at all, so replacing the file
// with a directory afterwards can neither fail the launch nor raise a second notice.
func TestRunFresh_UntrustedAtTheGateNeverReadsProjectSettings(t *testing.T) {
	home := t.TempDir()
	projectRoot := trustProject(t, raceProjectYAML)

	race := runPostGateRace(t, home, projectRoot, "n\n", func() {
		path := projectSettingsPath(projectRoot)
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove project settings: %v", err)
		}
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatalf("replace project settings with a directory: %v", err)
		}
	})

	if want := []string{SettingsPath(home)}; !slices.Equal(race.res.ConfigLayerPaths, want) {
		t.Fatalf("ConfigLayerPaths = %v, want %v", race.res.ConfigLayerPaths, want)
	}
	agent, _ := race.res.Config["agent"].(map[string]any)
	if fmt.Sprint(agent["max_concurrency"]) != "2" {
		t.Fatalf("agent.max_concurrency = %v, want the global value 2", agent["max_concurrency"])
	}
	if race.res.TrustDecision.Reason != trust.ReasonNoRecord {
		t.Fatalf("TrustDecision = %#v, want the gate's own %q outcome unchanged", race.res.TrustDecision, trust.ReasonNoRecord)
	}
	if race.projectLayer != nil {
		t.Fatalf("step-4 project layer = %#v, want nil", race.projectLayer)
	}
	if countNotices(race.stderr) != 1 {
		t.Fatalf("stderr = %q, want only the existing gate notice", race.stderr)
	}
	trustStoreAbsent(t, home)
}

func writeGlobalSettings(t *testing.T, home, content string, mode os.FileMode) string {
	t.Helper()
	path := SettingsPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir settings parent: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod settings: %v", err)
	}
	return path
}

// Step 0 classifies a dangling final symlink through Stat as absence, so without an Lstat it
// would generate settings straight through the link into whatever it names.
func TestDefaultRunFirstRun_RejectsFinalSymlinkBeforeGenerating(t *testing.T) {
	for _, tc := range []struct {
		name string
		live bool
	}{{"dangling link", false}, {"live link", true}} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := SettingsPath(home)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatalf("mkdir settings parent: %v", err)
			}
			target := filepath.Join(home, "elsewhere.yaml")
			if tc.live {
				if err := os.WriteFile(target, []byte("model: {}\n"), 0o600); err != nil {
					t.Fatalf("seed link target: %v", err)
				}
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatalf("symlink: %v", err)
			}

			var stdout, stderr bytes.Buffer
			ran, err := defaultRunFirstRun(home, &stdout, &stderr)
			if err == nil || ran {
				t.Fatalf("defaultRunFirstRun = (%v, %v), want a refusal that generates nothing", ran, err)
			}
			info, lerr := os.Lstat(path)
			if lerr != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("settings path = (%v, %v), want the symlink left untouched", info, lerr)
			}
			if _, serr := os.Stat(target); tc.live != (serr == nil) {
				t.Fatalf("link target stat err = %v, want generation to have written nothing through the link", serr)
			}
		})
	}
}

// The bounded byte seam never opens the file, so the mode warning has to stay in the adapter
// that reads it.
func TestDefaultLoadGlobalSettings_PreservesBroaderThan0600Warning(t *testing.T) {
	home := t.TempDir()
	path := writeGlobalSettings(t, home, "agent:\n  max_concurrency: 2\n", 0o644)

	var raw map[string]any
	var err error
	out := testsupport.CaptureStderr(t, func() { raw, err = defaultLoadGlobalSettings(home) })
	if err != nil {
		t.Fatalf("defaultLoadGlobalSettings: %v", err)
	}
	if raw == nil {
		t.Fatal("raw = nil, want the loaded global layer")
	}
	want := "codemeld: " + path + ": file mode 0644 is broader than 0600; API keys and ChatGPT session tokens are stored in plaintext\n"
	if out != want {
		t.Fatalf("stderr = %q, want exactly one warning %q", out, want)
	}
}

func TestDefaultLoadGlobalSettings_RefusesUnsafeTargets(t *testing.T) {
	t.Run("final component symlink", func(t *testing.T) {
		home := t.TempDir()
		target := filepath.Join(home, "elsewhere.yaml")
		if err := os.WriteFile(target, []byte("model: {}\n"), 0o666); err != nil {
			t.Fatalf("seed link target: %v", err)
		}
		path := SettingsPath(home)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir settings parent: %v", err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatalf("symlink: %v", err)
		}

		var err error
		out := testsupport.CaptureStderr(t, func() { _, err = defaultLoadGlobalSettings(home) })
		if err == nil {
			t.Fatal("err = nil, want the symlinked global settings path refused")
		}
		if out != "" {
			t.Fatalf("stderr = %q, want no warning derived from the link target's mode", out)
		}
	})

	t.Run("over the shared byte cap", func(t *testing.T) {
		home := t.TempDir()
		writeGlobalSettings(t, home, "# "+strings.Repeat("x", 64*1024)+"\n", 0o600)
		if _, err := defaultLoadGlobalSettings(home); err == nil {
			t.Fatal("err = nil, want a global settings file past the 64 KiB cap refused")
		}
	})
}

func TestDefaultComposeConfig_RefusesProjectLayerPastTheByteCap(t *testing.T) {
	projectRoot := t.TempDir()
	projectPath := projectSettingsPath(projectRoot)
	if err := os.MkdirAll(filepath.Dir(projectPath), 0o755); err != nil {
		t.Fatalf("mkdir project settings parent: %v", err)
	}
	if err := os.WriteFile(projectPath, []byte("# "+strings.Repeat("x", 64*1024)+"\n"), 0o600); err != nil {
		t.Fatalf("write project settings: %v", err)
	}

	_, err := defaultComposeConfig(nil, projectRoot)
	want := config.FormatLoadError(projectPath, config.UnreadableFile, errUnsafeSettingsRead, config.LaunchAborted)
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want the over-cap project layer to abort the launch with %q", err, want)
	}
}

// Composition deduplicates permission entries, so a project entry sharing a valid global
// entry's dedup tuple never reaches the cache's own parse. The invalid entry has to be
// rejected at its own layer or it is admitted and then handed to the monitor as a baseline
// the monitor itself would call malformed.
func TestDefaultComposeConfig_RejectsDedupMaskedInvalidProjectPermission(t *testing.T) {
	const subject = "ls -la"
	globalLayer := map[string]any{"permissions": []any{map[string]any{
		"kind": "literal", "subject": subject, "path_scope": "/home/u",
		"grant_kind": "folder", "argument_hash": permissions.ComputeArgumentHash(subject),
	}}}
	projectYAML := "permissions:\n  - kind: literal\n    subject: " + subject +
		"\n    path_scope: /home/u\n    grant_kind: folder\n    argument_hash: \"" + strings.Repeat("a", 64) + "\"\n"

	projectRaw := map[string]any{"permissions": []any{map[string]any{
		"kind": "literal", "subject": subject, "path_scope": "/home/u",
		"grant_kind": "folder", "argument_hash": strings.Repeat("a", 64),
	}}}
	masked, err := config.Compose(globalLayer, projectRaw)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if _, cerr := config.NewCache(masked, "", nil); cerr != nil {
		t.Fatalf("cache over the composed layers = %v, want the invalid project entry masked by dedup", cerr)
	}

	projectRoot := t.TempDir()
	projectPath := projectSettingsPath(projectRoot)
	if err := os.MkdirAll(filepath.Dir(projectPath), 0o755); err != nil {
		t.Fatalf("mkdir project settings parent: %v", err)
	}
	if err := os.WriteFile(projectPath, []byte(projectYAML), 0o600); err != nil {
		t.Fatalf("write project settings: %v", err)
	}

	if _, err := defaultComposeConfig(globalLayer, projectRoot); err == nil {
		t.Fatal("err = nil, want the authorization-invalid project entry rejected at its own layer")
	}
}

func settingsLayer(t *testing.T, res *BootstrapResult, kind securitystate.LayerKind) securitystate.LayerSnapshot {
	t.Helper()
	for _, layer := range res.SettingsLayers {
		if layer.Kind == kind {
			return layer
		}
	}
	t.Fatalf("SettingsLayers = %#v, want a %s layer", res.SettingsLayers, kind)
	return securitystate.LayerSnapshot{}
}

func TestRunFresh_RetainsAdmittedSettingsLayerSnapshots(t *testing.T) {
	var order []string
	steps, home, projectRoot := trustGateFixture(t, &order,
		trust.Decision{Trusted: true, Reason: trust.ReasonTrusted})
	global := map[string]any{"agent": map[string]any{"max_concurrency": 2}}
	steps.LoadGlobalSettings = func(string) (map[string]any, error) { return global, nil }

	res, err := RunFresh(context.Background(), "/cwd", steps)
	if err != nil {
		t.Fatalf("RunFresh error: %v", err)
	}

	globalLayer := settingsLayer(t, res, securitystate.LayerGlobal)
	if globalLayer.Path != SettingsPath(home) || !globalLayer.Present || globalLayer.Ignored {
		t.Fatalf("global layer = %#v, want the validated layer at %q", globalLayer, SettingsPath(home))
	}
	projectLayer := settingsLayer(t, res, securitystate.LayerProject)
	if projectLayer.Path != projectSettingsPath(projectRoot) || !projectLayer.Present || projectLayer.Ignored {
		t.Fatalf("project layer = %#v, want the admitted project layer", projectLayer)
	}
	if perms, _ := projectLayer.Raw["permissions"].([]any); len(perms) != 1 {
		t.Fatalf("project layer permissions = %#v, want the project's own entry, not the composed set", projectLayer.Raw)
	}

	// Composition merges and deduplicates across layers, so the snapshot only records what
	// this layer held if it shares no structure with the composed config.
	global["agent"].(map[string]any)["max_concurrency"] = 99
	if got := globalLayer.Raw["agent"].(map[string]any)["max_concurrency"]; fmt.Sprint(got) != "2" {
		t.Fatalf("global snapshot max_concurrency = %v, want the value captured at bootstrap", got)
	}
}

func TestRunFresh_RecordsAbsentAndIgnoredProjectLayerState(t *testing.T) {
	t.Run("admitted but absent", func(t *testing.T) {
		var order []string
		steps, _, projectRoot := trustGateFixture(t, &order,
			trust.Decision{Trusted: true, Reason: trust.ReasonTrusted})
		if err := os.Remove(projectSettingsPath(projectRoot)); err != nil {
			t.Fatalf("remove project settings: %v", err)
		}
		steps.GateTrust = func(string, string, string) trust.Decision {
			return trust.Decision{Trusted: true, Reason: trust.ReasonTrusted}
		}

		res, err := RunFresh(context.Background(), "/cwd", steps)
		if err != nil {
			t.Fatalf("RunFresh error: %v", err)
		}
		layer := settingsLayer(t, res, securitystate.LayerProject)
		if layer.Present || layer.Ignored || layer.Path != projectSettingsPath(projectRoot) {
			t.Fatalf("project layer = %#v, want an admitted absent layer that keeps its configured path", layer)
		}
	})

	t.Run("ignored", func(t *testing.T) {
		var order []string
		steps, _, projectRoot := trustGateFixture(t, &order, trust.Decision{Reason: trust.ReasonNoRecord})
		res, err := RunFresh(context.Background(), "/cwd", steps)
		if err != nil {
			t.Fatalf("RunFresh error: %v", err)
		}
		layer := settingsLayer(t, res, securitystate.LayerProject)
		if !layer.Ignored || layer.Present || layer.Raw != nil {
			t.Fatalf("project layer = %#v, want explicit ignored state carrying no content", layer)
		}
		if layer.Path != projectSettingsPath(projectRoot) {
			t.Fatalf("ignored layer path = %q, want the configured project path recorded", layer.Path)
		}
		for _, result := range securitystate.NewMonitor(res.SettingsLayers).Checkpoint() {
			if result.Kind == securitystate.LayerProject {
				t.Fatalf("checkpoint result = %#v, want an ignored layer to be no target at all", result)
			}
		}
		if _, err := os.Stat(projectSettingsPath(projectRoot) + ".lock"); !os.IsNotExist(err) {
			t.Fatalf("stat ignored sidecar = %v, want the ignored path never locked", err)
		}
	})
}

// --- step 4: the trust handoff into template loading ---

func assertStep4TrustHandoff(t *testing.T, race postGateRace, projectRoot string, wantTrusted bool) {
	t.Helper()
	if race.approved != wantTrusted {
		t.Fatalf("step-4 approved = %v, want %v", race.approved, wantTrusted)
	}
	if race.approved != race.res.TrustDecision.Trusted {
		t.Fatalf("step-4 approved = %v, want the launch's final decision %#v", race.approved, race.res.TrustDecision)
	}
	payload := loadWith(t, t.TempDir(), projectRoot, race.approved)
	argv := payload.templates["git"].Actions["status"].Argv
	if admitted := len(argv) == 2 && argv[1] == "PROJECT"; admitted != wantTrusted {
		t.Fatalf("git status argv = %v, want the project override admitted=%v", argv, wantTrusted)
	}
}

func TestRunFresh_ApprovedLaunchHandsProjectTemplatesToStep4(t *testing.T) {
	home := t.TempDir()
	projectRoot := trustProject(t, raceProjectYAML)
	writeFullTemplate(t, filepath.Join(projectVCSTemplateDir(projectRoot), "git.yaml"), "git", false, "", "PROJECT")

	race := runPostGateRace(t, home, projectRoot, "y\n", func() {})

	assertStep4TrustHandoff(t, race, projectRoot, true)
	if race.res.WithheldInputs != nil {
		t.Fatalf("WithheldInputs = %#v, want nothing withheld on a trusted launch", race.res.WithheldInputs)
	}
	if _, ok := race.res.Config["permissions"]; ok {
		t.Fatalf("composed config = %#v, want the fixture's project layer without a permission entry", race.res.Config)
	}
}

func assertWithheldSummary(t *testing.T, withheld []WithheldInput, projectRoot string) {
	t.Helper()
	want := []WithheldInput{{Category: WithheldSettings, Path: projectSettingsPath(projectRoot)}}
	if !slices.Equal(withheld, want) {
		t.Fatalf("WithheldInputs = %#v, want %#v", withheld, want)
	}
}

func TestRunFresh_TrustedLaunchWithVCSTemplatesStillComposesItsProjectLayer(t *testing.T) {
	home := t.TempDir()
	projectRoot := trustProject(t, raceProjectYAML)
	writeFullTemplate(t, filepath.Join(projectVCSTemplateDir(projectRoot), "git.yaml"), "git", false, "", "PROJECT")

	race := runPostGateRace(t, home, projectRoot, "y\n", func() {})

	if !race.res.TrustDecision.Trusted {
		t.Fatalf("TrustDecision = %#v, want the launch still trusted", race.res.TrustDecision)
	}
	if countNotices(race.stderr) != 0 {
		t.Fatalf("stderr = %q, want no ignored-settings notice", race.stderr)
	}
	if race.projectLayer == nil {
		t.Fatal("step-4 project layer = nil, want the composed project settings layer")
	}
	agent, _ := race.res.Config["agent"].(map[string]any)
	if fmt.Sprint(agent["max_concurrency"]) != "7" {
		t.Fatalf("agent.max_concurrency = %v, want the project value 7", agent["max_concurrency"])
	}
}

// childJournal drives the production child-agent journal through the real edit tool, leaving the
// record this process owns on disk.
func childJournal(t *testing.T, home, project, target string) string {
	t.Helper()
	j, err := subagent.OpenJournal(subagent.JournalConfig{
		Home:        home,
		ProjectRoot: project,
		Invocation:  "01890000-0000-7000-8000-00000000abcd",
		Declared:    []string{target},
	})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	defer j.Close()

	ctx := filetools.WithWriteJournal(context.Background(), j)
	tool := filetools.NewEditTool(home, project, project)
	args := map[string]any{"path": target, "old_text": "ORIGINAL", "new_text": "CHILD"}
	if _, err := tool.InvokeWithResolvedTarget(ctx, args, target); err != nil {
		t.Fatalf("child edit: %v", err)
	}

	return j.Path()
}

// killedChildJournal rewrites a child-agent journal's owner to a process that has exited, which is
// the state a killed codemeld leaves on disk for step 2.6 to find.
func killedChildJournal(t *testing.T, home, project, target string) string {
	t.Helper()
	path := childJournal(t, home, project, target)

	record := filepath.Join(path, "journal.json")
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("read journal record: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("decode journal record: %v", err)
	}
	owner, ok := raw["owner"].(map[string]any)
	if !ok {
		t.Fatalf("journal record has no owner: %s", data)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run a short-lived process: %v", err)
	}
	owner["pid"] = cmd.ProcessState.Pid()
	patched, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("encode journal record: %v", err)
	}
	if err := os.WriteFile(record, patched, 0o600); err != nil {
		t.Fatalf("write journal record: %v", err)
	}
	return path
}

// TestDefaultFreshSteps_RecoverJournals_PutsBackAKilledChildsWrite drives the production step-2.6
// adapter end to end: the journal a killed launch left behind is found for the folder being opened,
// the file is read back from disk in its pre-run state, and the launch says so in plain terms.
func TestDefaultFreshSteps_RecoverJournals_PutsBackAKilledChildsWrite(t *testing.T) {
	home, project := realPath(t, t.TempDir()), realPath(t, t.TempDir())
	target := filepath.Join(project, "a.txt")
	if err := os.WriteFile(target, []byte("ORIGINAL\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	journal := killedChildJournal(t, home, project, target)

	var stderr strings.Builder
	DefaultFreshSteps(io.Discard, &stderr).RecoverJournals(home, project)

	if got, err := os.ReadFile(target); err != nil || string(got) != "ORIGINAL\n" {
		t.Fatalf("%s = %q (err=%v), want its pre-run bytes", target, got, err)
	}
	if _, err := os.Stat(journal); !os.IsNotExist(err) {
		t.Fatalf("stat %s: %v, want the finished journal removed", journal, err)
	}
	if !strings.Contains(stderr.String(), "put back: "+target) {
		t.Fatalf("stderr = %q, want the restored file named", stderr.String())
	}
}

// TestRecoverChildJournals_AsksOnlyWhenTheLaunchCanReachTheUser pins the two halves of the
// prompt seam: an interactive launch offers the three answers for a path changed since the crash and
// records the one it is given, and a launch with no one to ask defers instead of guessing.
func TestRecoverChildJournals_AsksOnlyWhenTheLaunchCanReachTheUser(t *testing.T) {
	changed := func(t *testing.T) (home, project, target string) {
		t.Helper()
		home, project = realPath(t, t.TempDir()), realPath(t, t.TempDir())
		target = filepath.Join(project, "a.txt")
		if err := os.WriteFile(target, []byte("ORIGINAL\n"), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
		killedChildJournal(t, home, project, target)
		if err := os.WriteFile(target, []byte("A HAND EDIT\n"), 0o644); err != nil {
			t.Fatalf("hand edit: %v", err)
		}
		return home, project, target
	}

	t.Run("an interactive launch asks and keeps the current state", func(t *testing.T) {
		home, project, target := changed(t)

		var stderr strings.Builder
		recoverChildJournals(home, project, strings.NewReader("k\n"), &stderr, true)

		if !strings.Contains(stderr.String(), "Keep, put back, or decide later?") {
			t.Fatalf("stderr = %q, want the three answers offered", stderr.String())
		}
		if got, err := os.ReadFile(target); err != nil || string(got) != "A HAND EDIT\n" {
			t.Fatalf("%s = %q (err=%v), want the kept state", target, got, err)
		}
		if !strings.Contains(stderr.String(), "kept as it is now, as you asked: "+target) {
			t.Fatalf("stderr = %q, want the kept file named", stderr.String())
		}
	})

	t.Run("a launch with no one to ask defers and says how to resolve it", func(t *testing.T) {
		home, project, target := changed(t)

		var stderr strings.Builder
		recoverChildJournals(home, project, strings.NewReader("k\n"), &stderr, false)

		if strings.Contains(stderr.String(), "Keep, put back, or decide later?") {
			t.Fatalf("stderr = %q, want no prompt with no one to answer it", stderr.String())
		}
		if got, err := os.ReadFile(target); err != nil || string(got) != "A HAND EDIT\n" {
			t.Fatalf("%s = %q (err=%v), want a deferred path left alone", target, got, err)
		}
		if !strings.Contains(stderr.String(), "not put back: "+target) ||
			!strings.Contains(stderr.String(), "the next time you start it here") {
			t.Fatalf("stderr = %q, want the file named and the next step stated", stderr.String())
		}
	})
}

func TestReportJournalRecovery_PromisesAQuestionOnlyForOrdinaryUnresolvedPaths(t *testing.T) {
	const record = "journals/run"
	const question = "codemeld asks what to do with these files the next time you start it here"
	render := func(retained subagent.RetainedJournal) string {
		var stderr strings.Builder
		reportJournalRecovery(&stderr, subagent.Report{Retained: []subagent.RetainedJournal{retained}})
		return stderr.String()
	}

	t.Run("an ordinary unresolved path", func(t *testing.T) {
		got := render(subagent.RetainedJournal{Path: record, Notes: []string{"a.txt: it was changed outside the child agent's journalled writes"}})

		if !strings.Contains(got, "not put back: a.txt") || !strings.Contains(got, question+"; its record of the run is "+record) {
			t.Fatalf("stderr = %q, want the path named and the next-launch question promised", got)
		}
	})

	t.Run("a held move", func(t *testing.T) {
		got := render(subagent.RetainedJournal{Path: record, Moves: []subagent.HeldMove{{Source: "a.txt", Destination: "b.txt", Reason: "an endpoint was changed outside the child agent's journalled writes"}}})

		if !strings.Contains(got, "a.txt -> b.txt (an endpoint was changed outside") || !strings.Contains(got, "fix them by hand") {
			t.Fatalf("stderr = %q, want the held move and its reason named as work to fix by hand", got)
		}
		if strings.Contains(got, "asks what to do") || strings.Contains(got, "next time you start it here") || !strings.Contains(got, record) {
			t.Fatalf("stderr = %q, want the record named without promising a later question or retry", got)
		}
	})

	t.Run("an interrupted move undo", func(t *testing.T) {
		got := render(subagent.RetainedJournal{Path: record, Moves: []subagent.HeldMove{{Source: "a.txt", Destination: "b.txt", Reason: "the moved entry could not be put back", Resumes: true}}})

		if !strings.Contains(got, "a.txt -> b.txt") || !strings.Contains(got, "tries again to finish undoing") {
			t.Fatalf("stderr = %q, want the interrupted move named as resumed at the next launch", got)
		}
		if strings.Contains(got, "asks what to do") || strings.Contains(got, "fix them by hand") {
			t.Fatalf("stderr = %q, want no question and no manual fix promised for a resumed undo", got)
		}
	})

	t.Run("an ordinary unresolved path beside a held move", func(t *testing.T) {
		got := render(subagent.RetainedJournal{
			Path:  record,
			Notes: []string{"a.txt: it was changed outside the child agent's journalled writes"},
			Moves: []subagent.HeldMove{{Source: "c.txt", Destination: "d.txt", Reason: "an endpoint was changed outside the child agent's journalled writes"}},
		})

		path, asks := strings.Index(got, "not put back: a.txt"), strings.Index(got, question)
		move, byHand := strings.Index(got, "c.txt -> d.txt"), strings.Index(got, "fix them by hand")
		if path < 0 || asks < path || move < asks || byHand < move || !strings.Contains(got, "its record of the run is "+record) {
			t.Fatalf("stderr = %q, want the question right after the path it covers and the manual fix after the held move", got)
		}
	})

	t.Run("a held move beside an interrupted move undo", func(t *testing.T) {
		got := render(subagent.RetainedJournal{Path: record, Moves: []subagent.HeldMove{
			{Source: "c.txt", Destination: "d.txt", Reason: "the moved entry could not be put back", Resumes: true},
			{Source: "a.txt", Destination: "b.txt", Reason: "an endpoint was changed outside the child agent's journalled writes"},
		}})

		held, byHand := strings.Index(got, "a.txt -> b.txt"), strings.Index(got, "fix them by hand")
		resumed, retry := strings.Index(got, "c.txt -> d.txt"), strings.Index(got, "tries again to finish undoing")
		if held < 0 || byHand < held || resumed < byHand || retry < resumed || strings.Contains(got, "asks what to do") {
			t.Fatalf("stderr = %q, want each move group followed by only its own instruction and no question", got)
		}
	})
}

// TestDefaultFreshSteps_RecoverJournals_NamesAJournalItLeftAlone pins the launch report for a
// journal recovery must not touch: the record belongs to a process that is still running, so the
// launch names it and says why instead of passing over it in silence.
func TestDefaultFreshSteps_RecoverJournals_NamesAJournalItLeftAlone(t *testing.T) {
	home, project := realPath(t, t.TempDir()), realPath(t, t.TempDir())
	target := filepath.Join(project, "a.txt")
	if err := os.WriteFile(target, []byte("ORIGINAL\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	journal := childJournal(t, home, project, target)

	var stderr strings.Builder
	DefaultFreshSteps(io.Discard, &stderr).RecoverJournals(home, project)

	if !strings.Contains(stderr.String(), "left alone: "+journal) {
		t.Fatalf("stderr = %q, want the untouched journal named", stderr.String())
	}
	if !strings.Contains(stderr.String(), "another codemeld may still be running") {
		t.Fatalf("stderr = %q, want a plain reason it was left alone", stderr.String())
	}
	if strings.Contains(stderr.String(), "put back") {
		t.Fatalf("stderr = %q, want nothing reported as recovered", stderr.String())
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "CHILD\n" {
		t.Fatalf("%s = %q (err=%v), want the other codemeld's file untouched", target, got, err)
	}
	if _, err := os.Stat(filepath.Join(journal, "journal.json")); err != nil {
		t.Fatalf("stat the journal record: %v, want it retained", err)
	}
}

// TestRunFreshCore_AJournalRecoveryFailureDoesNotBlockTheLaunch pins the never-block rule on the
// production step: a journal recovery cannot read is reported and the rest of the launch still runs.
func TestRunFreshCore_AJournalRecoveryFailureDoesNotBlockTheLaunch(t *testing.T) {
	home, project := realPath(t, t.TempDir()), realPath(t, t.TempDir())
	target := filepath.Join(project, "a.txt")
	if err := os.WriteFile(target, []byte("ORIGINAL\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	journal := killedChildJournal(t, home, project, target)
	if err := os.WriteFile(filepath.Join(journal, "journal.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt the record: %v", err)
	}

	var stderr strings.Builder
	var order []string
	steps := recordingSteps(&order)
	steps.ResolveHome = func() (string, error) { return home, nil }
	steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) { return project, nil, nil }
	steps.RecoverJournals = DefaultFreshSteps(io.Discard, &stderr).RecoverJournals

	res, _, err := runFreshCore(context.Background(), project, steps)

	if err != nil || res == nil {
		t.Fatalf("runFreshCore = (%v, %v), want the launch to complete past a recovery failure", res, err)
	}
	if !slices.Contains(order, "7c:LoadAgentInstructions") {
		t.Fatalf("order = %v, want the launch to reach its last step", order)
	}
	if !strings.Contains(stderr.String(), journal) {
		t.Fatalf("stderr = %q, want the unreadable journal reported", stderr.String())
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "CHILD\n" {
		t.Fatalf("%s = %q (err=%v), want an unreadable journal to change nothing", target, got, err)
	}
}

// TestRecoverChildJournals_DoesNothingWithoutAProjectOrAJournal pins the preserved no-journal
// launch: nothing is created under the codemeld home and nothing is reported.
func TestRecoverChildJournals_DoesNothingWithoutAProjectOrAJournal(t *testing.T) {
	home := realPath(t, t.TempDir())

	var stderr strings.Builder
	recoverChildJournals(home, "", strings.NewReader(""), &stderr, true)
	recoverChildJournals(home, realPath(t, t.TempDir()), strings.NewReader(""), &stderr, true)

	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want no report when there is no journal", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".codemeld")); !os.IsNotExist(err) {
		t.Fatalf("stat ~/.codemeld: %v, want recovery to create nothing", err)
	}
}

func realPath(t *testing.T, dir string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("resolve %s: %v", dir, err)
	}
	return resolved
}

const duplicateGrantKindYAML = `permissions:
  - kind: literal
    subject: "ls -la"
    path_scope: /home/u
    grant_kind: folder
    grant_kind: folder
`

// Wording that reads as "the file was skipped" would send the reader looking for a running
// codemeld that is not there.
func TestLaunchAbortingLoadFailures_SayTheLaunchStopped(t *testing.T) {
	symlinkedSettings := func(t *testing.T) string {
		t.Helper()
		home := t.TempDir()
		target := filepath.Join(home, "elsewhere.yaml")
		if err := os.WriteFile(target, []byte("model: {}\n"), 0o600); err != nil {
			t.Fatalf("seed link target: %v", err)
		}
		path := SettingsPath(home)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir settings parent: %v", err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		return home
	}

	tests := []struct {
		name string
		fail func(t *testing.T) error
	}{
		{"global settings refused as unsafe", func(t *testing.T) error {
			_, err := defaultLoadGlobalSettings(symlinkedSettings(t))
			return err
		}},
		{"global settings absent", func(t *testing.T) error {
			_, err := defaultLoadGlobalSettings(t.TempDir())
			return err
		}},
		{"global settings malformed", func(t *testing.T) error {
			home := t.TempDir()
			writeGlobalSettings(t, home, duplicateGrantKindYAML, 0o600)
			_, err := defaultLoadGlobalSettings(home)
			return err
		}},
		{"trusted project settings malformed", func(t *testing.T) error {
			projectRoot := t.TempDir()
			projectPath := projectSettingsPath(projectRoot)
			if err := os.MkdirAll(filepath.Dir(projectPath), 0o755); err != nil {
				t.Fatalf("mkdir project settings parent: %v", err)
			}
			if err := os.WriteFile(projectPath, []byte(duplicateGrantKindYAML), 0o600); err != nil {
				t.Fatalf("write project settings: %v", err)
			}
			_, _, err := readAdmittedProjectSettingsLayer(projectRoot)
			return err
		}},
		{"first run refuses a symlinked settings path", func(t *testing.T) error {
			_, err := defaultRunFirstRun(symlinkedSettings(t), io.Discard, io.Discard)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fail(t)
			if err == nil {
				t.Fatal("err = nil, want a load failure")
			}
			msg := err.Error()
			if !strings.Contains(msg, "codemeld did not start") {
				t.Fatalf("message %q does not state that the launch stopped", msg)
			}
			if !strings.Contains(msg, "\n  to fix: ") {
				t.Fatalf("message %q has no fix line", msg)
			}
			for _, token := range []string{"unreadable_file", "yaml_parse_error", "schema_validation_error"} {
				if strings.Contains(msg, token) {
					t.Fatalf("message %q leaks the internal category token %q", msg, token)
				}
			}
			for _, misleading := range []string{"ignored", "ignoring", "skipped", "default", "continuing"} {
				if strings.Contains(strings.ToLower(msg), misleading) {
					t.Fatalf("message %q suggests the launch went on without the file (%q)", msg, misleading)
				}
			}
		})
	}
}

// A richer load-failure message must not tempt anyone into parsing an untrusted layer earlier
// than the trust gate allows, so that layer still reports nothing at all.
func TestRunFresh_UntrustedProjectLayerReportsNoLoadFailure(t *testing.T) {
	var order []string
	steps, _, projectRoot := trustGateFixture(t, &order, trust.Decision{Reason: trust.ReasonNoRecord})
	writeProjectSettings(t, projectRoot, duplicateGrantKindYAML)
	steps.LoadGlobalSettings = func(string) (map[string]any, error) {
		return map[string]any{"agent": map[string]any{"max_concurrency": 2}}, nil
	}

	res, err := RunFresh(context.Background(), "/cwd", steps)
	if err != nil {
		t.Fatalf("RunFresh error = %v, want no load failure reported for a layer that was never parsed", err)
	}
	agent, _ := res.Config["agent"].(map[string]any)
	if fmt.Sprint(agent["max_concurrency"]) != "2" {
		t.Fatalf("agent.max_concurrency = %v, want the global value 2", agent["max_concurrency"])
	}
}

func TestDefaultLoadGlobalSettings_DuplicateKeyReachesTheLaunchError(t *testing.T) {
	home := t.TempDir()
	path := writeGlobalSettings(t, home, duplicateGrantKindYAML, 0o600)

	_, err := defaultLoadGlobalSettings(home)
	if err == nil {
		t.Fatal("err = nil, want the duplicated key to stop the launch")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "codemeld: "+path+": is not valid YAML; codemeld did not start.\n") {
		t.Fatalf("message %q does not name the file, the failure and the consequence", msg)
	}
	for _, part := range []string{
		`the key "grant_kind" is set twice in the same block, at line 5 and again at line 6`,
		`the entry whose subject is "ls -la"`,
		`to fix: delete one of the two "grant_kind" lines, either line 5 or line 6`,
	} {
		if !strings.Contains(msg, part) {
			t.Fatalf("message %q missing %q", msg, part)
		}
	}
}

const localFolderGrantYAML = `permissions:
  - kind: direct
    subject: ls
    path_scope: /work
    grant_kind: folder
`

// localLayerFixture drives RunFresh over a real temp project with the production trust and
// compose steps, so the assertions read the launch's own composed config.
func localLayerFixture(t *testing.T, order *[]string, trusted bool, files map[string]string) (FreshSteps, string, string) {
	t.Helper()
	home := t.TempDir()
	projectRoot, err := sessions.CanonicalizeFolder(t.TempDir())
	if err != nil {
		t.Fatalf("canonicalize project root: %v", err)
	}
	dir := filepath.Join(projectRoot, ".codemeld")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir .codemeld: %v", err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if trusted {
		approveRoot(t, home, projectRoot)
	}

	production := DefaultFreshSteps(io.Discard, io.Discard)
	steps := recordingSteps(order)
	steps.ResolveHome = func() (string, error) { return home, nil }
	steps.ResolveProjectRoot = production.ResolveProjectRoot
	steps.GateTrust = production.GateTrust
	steps.ComposeConfig = production.ComposeConfig
	return steps, home, projectRoot
}

func composedPermissionSubjects(t *testing.T, composed map[string]any) []string {
	t.Helper()
	list, ok := composed["permissions"].([]any)
	if !ok {
		return nil
	}
	subjects := make([]string, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("permissions entry = %#v, want a mapping", item)
		}
		subjects = append(subjects, fmt.Sprint(m["subject"]))
	}
	return subjects
}

func TestRunFresh_TrustedLaunchComposesTheLocalSettingsLayer(t *testing.T) {
	var order []string
	steps, _, projectRoot := localLayerFixture(t, &order, true, map[string]string{
		"settings.local.yaml": localFolderGrantYAML,
	})
	var composition ConfigComposition
	production := steps.ComposeConfig
	steps.ComposeConfig = func(global map[string]any, root string) (ConfigComposition, error) {
		c, err := production(global, root)
		composition = c
		return c, err
	}

	res, err := RunFresh(context.Background(), projectRoot, steps)
	if err != nil {
		t.Fatalf("RunFresh error: %v", err)
	}
	if !res.TrustDecision.Trusted {
		t.Fatalf("decision = %#v, want the recorded project trusted", res.TrustDecision)
	}
	if !composition.LocalPresent || composition.LocalLayer == nil {
		t.Fatalf("composition = %#v, want the local layer reported", composition)
	}
	if got := composedPermissionSubjects(t, res.Config); !slices.Equal(got, []string{"ls"}) {
		t.Fatalf("permissions = %v, want the local grant in force with settings.yaml absent", got)
	}
	if _, err := os.Stat(projectSettingsPath(projectRoot)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat settings.yaml = %v, want the shared file absent for this case", err)
	}
}

func TestRunFresh_UntrustedLaunchWithholdsTheLocalSettingsLayer(t *testing.T) {
	cases := map[string]map[string]string{
		"local file only": {"settings.local.yaml": localFolderGrantYAML},
		"both project-scope files": {
			"settings.yaml":       "agent:\n  max_concurrency: 7\n",
			"settings.local.yaml": localFolderGrantYAML,
		},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			var order []string
			steps, home, projectRoot := localLayerFixture(t, &order, false, files)
			gate := steps.GateTrust
			steps.GateTrust = func(gateHome, root, cwd string) trust.Decision {
				decision := gate(gateHome, root, cwd)
				localPath := config.LocalSettingsPath(projectRoot)
				if err := os.Remove(localPath); err != nil {
					t.Fatalf("remove local settings: %v", err)
				}
				if err := os.Mkdir(localPath, 0o755); err != nil {
					t.Fatalf("replace local settings with a directory: %v", err)
				}
				return decision
			}

			res, err := RunFresh(context.Background(), projectRoot, steps)
			if err != nil {
				t.Fatalf("RunFresh error: %v", err)
			}
			if res.TrustDecision.Trusted || res.TrustDecision.Reason != trust.ReasonNoRecord {
				t.Fatalf("decision = %#v, want the gate's refusal to stand with nothing read under the project root", res.TrustDecision)
			}
			if want := []string{SettingsPath(home)}; !slices.Equal(res.ConfigLayerPaths, want) {
				t.Fatalf("ConfigLayerPaths = %v, want %v", res.ConfigLayerPaths, want)
			}
			if _, ok := res.Config["permissions"]; ok {
				t.Fatalf("composed config = %#v, want no grant from either project-scope file", res.Config)
			}
			if _, ok := res.Config["agent"]; ok {
				t.Fatalf("composed config = %#v, want nothing read under the project root", res.Config)
			}
			if _, present := files["settings.yaml"]; present && len(res.WithheldInputs) == 0 {
				t.Fatalf("WithheldInputs = %#v, want the project's settings reported as withheld", res.WithheldInputs)
			}
		})
	}
}

func localLayerFixtureChangedAfterTheGate(t *testing.T, change func(projectRoot string)) (FreshSteps, string) {
	t.Helper()
	var order []string
	steps, _, projectRoot := localLayerFixture(t, &order, true, map[string]string{
		"settings.yaml":       "agent:\n  max_concurrency: 7\n",
		"settings.local.yaml": localFolderGrantYAML,
	})
	gate := steps.GateTrust
	steps.GateTrust = func(home, root, cwd string) trust.Decision {
		decision := gate(home, root, cwd)
		change(projectRoot)
		return decision
	}
	return steps, projectRoot
}

func TestRunFresh_LocalSettingsChangedAfterTheGateComposeTheBytesOnDisk(t *testing.T) {
	steps, projectRoot := localLayerFixtureChangedAfterTheGate(t, func(projectRoot string) {
		local := "model:\n  active:\n    provider: openai\n    id: local\n"
		if err := os.WriteFile(config.LocalSettingsPath(projectRoot), []byte(local), 0o600); err != nil {
			t.Fatalf("rewrite local settings: %v", err)
		}
	})

	res, err := RunFresh(context.Background(), projectRoot, steps)
	if err != nil {
		t.Fatalf("RunFresh error: %v", err)
	}
	if !res.TrustDecision.Trusted {
		t.Fatalf("decision = %#v, want the approval to stand", res.TrustDecision)
	}
	model, _ := res.Config["model"].(map[string]any)
	if active, _ := model["active"].(map[string]any); fmt.Sprint(active["id"]) != "local" {
		t.Fatalf("model.active = %#v, want the local bytes on disk at composition", model["active"])
	}
	if _, ok := res.Config["permissions"]; ok {
		t.Fatalf("composed config = %#v, want the replaced local grant gone", res.Config)
	}
}

func TestRunFresh_UnsafeLocalSettingsReadAbortsTheLaunch(t *testing.T) {
	steps, projectRoot := localLayerFixtureChangedAfterTheGate(t, func(projectRoot string) {
		localPath := config.LocalSettingsPath(projectRoot)
		if err := os.Remove(localPath); err != nil {
			t.Fatalf("remove local settings: %v", err)
		}
		if err := os.Mkdir(localPath, 0o755); err != nil {
			t.Fatalf("replace local settings with a directory: %v", err)
		}
	})

	_, err := RunFresh(context.Background(), projectRoot, steps)
	want := config.FormatLoadError(config.LocalSettingsPath(projectRoot), config.UnreadableFile, errUnsafeSettingsRead, config.LaunchAborted)
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want the unsafe-read launch abort %q", err, want)
	}
}

func TestDefaultFreshSteps_ComposeConfig_LocalLayerWinsOverTheSharedFile(t *testing.T) {
	projectRoot := t.TempDir()
	dir := filepath.Join(projectRoot, ".codemeld")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir .codemeld: %v", err)
	}
	shared := "model:\n  active:\n    provider: openai\n    id: shared\nagent:\n  max_concurrency: 4\n"
	local := "model:\n  active:\n    provider: openai\n    id: local\n"
	if err := os.WriteFile(filepath.Join(dir, "settings.yaml"), []byte(shared), 0o600); err != nil {
		t.Fatalf("write shared settings: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.local.yaml"), []byte(local), 0o600); err != nil {
		t.Fatalf("write local settings: %v", err)
	}

	composition, err := DefaultFreshSteps(io.Discard, io.Discard).ComposeConfig(map[string]any{}, projectRoot)
	if err != nil {
		t.Fatalf("ComposeConfig: %v", err)
	}
	model, _ := composition.Config["model"].(map[string]any)
	active, _ := model["active"].(map[string]any)
	if fmt.Sprint(active["id"]) != "local" {
		t.Fatalf("model.active = %#v, want the local file's selection", model["active"])
	}
	agent, _ := composition.Config["agent"].(map[string]any)
	if fmt.Sprint(agent["max_concurrency"]) != "4" {
		t.Fatalf("agent.max_concurrency = %v, want the shared file's value to still compose", agent["max_concurrency"])
	}
}

func TestDefaultFreshSteps_ComposeConfig_AbortsOnAnUnusableLocalFile(t *testing.T) {
	for name, content := range map[string]string{
		"malformed YAML":     "model:\n  active: [\n",
		"disallowed key":     "declared_commands: [\"ls\"]\n",
		"machine-wide grant": "permissions:\n  - kind: direct\n    subject: ls\n    path_scope: \"*\"\n    grant_kind: global\n",
	} {
		t.Run(name, func(t *testing.T) {
			projectRoot := t.TempDir()
			dir := filepath.Join(projectRoot, ".codemeld")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("mkdir .codemeld: %v", err)
			}
			localPath := filepath.Join(dir, "settings.local.yaml")
			if err := os.WriteFile(localPath, []byte(content), 0o600); err != nil {
				t.Fatalf("write local settings: %v", err)
			}

			_, err := DefaultFreshSteps(io.Discard, io.Discard).ComposeConfig(map[string]any{}, projectRoot)
			if err == nil {
				t.Fatalf("ComposeConfig succeeded, want the launch aborted")
			}
			if !strings.Contains(err.Error(), localPath) {
				t.Fatalf("error %q must name %s", err, localPath)
			}
		})
	}
}

// Project-root discovery keys on .codemeld/settings.yaml alone, so the local file must never
// turn a folder into a project root under either boundary.
func TestDefaultFreshSteps_ResolveProjectRoot_LocalFileIsNotAProjectMarker(t *testing.T) {
	nestedTree := func(t *testing.T) string {
		t.Helper()
		outer := t.TempDir()
		if err := os.MkdirAll(filepath.Join(outer, ".codemeld"), 0o755); err != nil {
			t.Fatalf("mkdir outer marker dir: %v", err)
		}
		if err := os.WriteFile(projectSettingsPath(outer), []byte("model: {}\n"), 0o600); err != nil {
			t.Fatalf("write outer settings: %v", err)
		}
		inner := filepath.Join(outer, "nested")
		if err := os.MkdirAll(inner, 0o755); err != nil {
			t.Fatalf("mkdir nested: %v", err)
		}
		return inner
	}

	steps := DefaultFreshSteps(io.Discard, io.Discard)
	for _, boundary := range []string{"launch-dir-only", "project-root"} {
		for _, tc := range []struct {
			name  string
			stage func(t *testing.T, inner string)
		}{
			{"directory only", func(t *testing.T, inner string) {
				if err := os.MkdirAll(filepath.Join(inner, ".codemeld"), 0o755); err != nil {
					t.Fatalf("mkdir nested marker dir: %v", err)
				}
			}},
			{"local file", func(t *testing.T, inner string) {
				if err := os.MkdirAll(filepath.Join(inner, ".codemeld"), 0o755); err != nil {
					t.Fatalf("mkdir nested marker dir: %v", err)
				}
				if err := os.WriteFile(filepath.Join(inner, ".codemeld", "settings.local.yaml"), []byte("model: {}\n"), 0o600); err != nil {
					t.Fatalf("write nested local settings: %v", err)
				}
			}},
		} {
			t.Run(boundary+"/"+tc.name, func(t *testing.T) {
				inner := nestedTree(t)
				global := map[string]any{"discovery": map[string]any{"boundary": boundary}}
				before, _, err := steps.ResolveProjectRoot(inner, global)
				if err != nil {
					t.Fatalf("ResolveProjectRoot: %v", err)
				}
				tc.stage(t, inner)

				after, _, err := steps.ResolveProjectRoot(inner, global)
				if err != nil {
					t.Fatalf("ResolveProjectRoot: %v", err)
				}
				if after != before {
					t.Fatalf("root = %q, want it unchanged from %q", after, before)
				}
				if boundary == "project-root" && after == inner {
					t.Fatalf("root = %q, want the nested folder not to become a project root", after)
				}
			})
		}
	}
}

func layerKinds(layers []securitystate.LayerSnapshot) []securitystate.LayerKind {
	kinds := make([]securitystate.LayerKind, 0, len(layers))
	for _, layer := range layers {
		kinds = append(kinds, layer.Kind)
	}
	return kinds
}

func TestRunFresh_AppendsTheAdmittedLocalSettingsLayer(t *testing.T) {
	var order []string
	steps, _, projectRoot := localLayerFixture(t, &order, true, map[string]string{
		"settings.local.yaml": localFolderGrantYAML,
	})

	res, err := RunFresh(context.Background(), projectRoot, steps)
	if err != nil {
		t.Fatalf("RunFresh error: %v", err)
	}

	want := []securitystate.LayerKind{securitystate.LayerGlobal, securitystate.LayerProject, securitystate.LayerLocal}
	if got := layerKinds(res.SettingsLayers); !slices.Equal(got, want) {
		t.Fatalf("layer kinds = %v, want %v", got, want)
	}
	local := settingsLayer(t, res, securitystate.LayerLocal)
	if local.Path != config.LocalSettingsPath(projectRoot) || !local.Present || local.Ignored {
		t.Fatalf("local layer = %#v, want the admitted layer at %q", local, config.LocalSettingsPath(projectRoot))
	}
	if perms, _ := local.Raw["permissions"].([]any); len(perms) != 1 {
		t.Fatalf("local layer permissions = %#v, want the local file's own entry", local.Raw)
	}
}

func TestRunFresh_RecordsAbsentAndIgnoredLocalLayerState(t *testing.T) {
	t.Run("admitted but absent", func(t *testing.T) {
		var order []string
		steps, _, projectRoot := localLayerFixture(t, &order, true, nil)

		res, err := RunFresh(context.Background(), projectRoot, steps)
		if err != nil {
			t.Fatalf("RunFresh error: %v", err)
		}
		local := settingsLayer(t, res, securitystate.LayerLocal)
		if local.Present || local.Ignored || local.Path != config.LocalSettingsPath(projectRoot) {
			t.Fatalf("local layer = %#v, want an admitted absent layer that keeps its configured path", local)
		}
	})

	t.Run("ignored", func(t *testing.T) {
		var order []string
		steps, _, projectRoot := localLayerFixture(t, &order, false, map[string]string{
			"settings.local.yaml": localFolderGrantYAML,
		})

		res, err := RunFresh(context.Background(), projectRoot, steps)
		if err != nil {
			t.Fatalf("RunFresh error: %v", err)
		}
		local := settingsLayer(t, res, securitystate.LayerLocal)
		project := settingsLayer(t, res, securitystate.LayerProject)
		if !local.Ignored || local.Present || local.Raw != nil {
			t.Fatalf("local layer = %#v, want explicit ignored state carrying no content", local)
		}
		if local.Ignored != project.Ignored || local.Present != project.Present {
			t.Fatalf("local layer = %#v, want the untrusted shape of the project layer %#v", local, project)
		}
	})
}

func TestRunResume_SuppliesTheSameSettingsLayersAsAFreshLaunch(t *testing.T) {
	var order []string
	steps, home, projectRoot := localLayerFixture(t, &order, true, map[string]string{
		"settings.local.yaml": localFolderGrantYAML,
	})
	fresh, err := RunFresh(context.Background(), projectRoot, steps)
	if err != nil {
		t.Fatalf("RunFresh error: %v", err)
	}

	production := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard)
	resumeSteps := recordingResumeSteps(&order)
	resumeSteps.ResolveHome = func() (string, error) { return home, nil }
	resumeSteps.ResolveProjectRoot = production.ResolveProjectRoot
	resumeSteps.GateTrust = production.GateTrust
	resumeSteps.ComposeConfig = production.ComposeConfig

	resumed, err := runResumeWithID(context.Background(), home, projectRoot, "the-id", resumeSteps)
	if err != nil {
		t.Fatalf("runResumeWithID error: %v", err)
	}
	if !reflect.DeepEqual(resumed.SettingsLayers, fresh.SettingsLayers) {
		t.Fatalf("resumed layers = %#v, want the fresh launch's %#v", resumed.SettingsLayers, fresh.SettingsLayers)
	}
}
