// Tests for the resume sub-sequence ordering, the no-id picker transition/dismiss,
// per-step short-circuiting, and the production DefaultResumeSteps wiring.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/trust"
	"codemeld.dev/codemeld/internal/tui"
	"golang.org/x/term"
)

// recordingResumeSteps builds a ResumeSteps whose every step appends its name to
// *order and returns success. Tests override individual fields to inject failures
// or to assert placement, while the rest keep recording so the full sequence is
// visible (mirrors recordingSteps for the fresh path).
func recordingResumeSteps(order *[]string) ResumeSteps {
	rec := func(name string) { *order = append(*order, name) }
	return ResumeSteps{
		ResolveHome:        func() (string, error) { rec("0a:ResolveHome"); return "/home/u", nil },
		RunFirstRun:        func(string) (bool, error) { rec("0:RunFirstRun"); return false, nil },
		LoadGlobalSettings: func(string) (map[string]any, error) { rec("1:LoadGlobalSettings"); return nil, nil },
		ListAndSelect: func(string, string, map[string]any) (string, bool, error) {
			rec("P:ListAndSelect")
			return "picked-id", true, nil
		},
		ResolveResume: func(string, string, string) (string, *sessions.Session, error) {
			rec("R1:ResolveResume")
			return "/sessions/folder/id.json", &sessions.Session{}, nil
		},
		AcquireLock: func(string, string) (func(), error) {
			rec("R2:AcquireLock")
			return func() {}, nil
		},
		AppendLaunchBegan: func(context.Context, *sessions.Store) error { rec("R3:AppendLaunchBegan"); return nil },
		RefreshUpdatedAt:  func(context.Context, *sessions.Store) error { rec("R4:RefreshUpdatedAt"); return nil },
		ResolveProjectRoot: func(string, map[string]any) (string, []string, error) {
			rec("2:ResolveProjectRoot")
			return "/proj", nil, nil
		},
		GateTrust: func(string, string, string) trust.Decision {
			rec("2b:GateTrust")
			return trust.Decision{Trusted: true, Reason: trust.ReasonTrusted, Root: "/proj"}
		},
		ScaffoldProjectIgnore: func(string) error { rec("2.5:ScaffoldProjectIgnore"); return nil },
		RecoverJournals:       func(string, string, map[string]any, trust.Decision) { rec("2.6:RecoverJournals") },
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
		DetermineModel: func(map[string]any, map[string]any, string, []string, *sessions.Store) (any, bool, error) {
			rec("7:DetermineModel")
			return nil, false, nil
		},
		InitMode: func(context.Context, *sessions.Store, map[string]any, string, []string) (any, error) {
			rec("7b2:InitMode")
			return nil, nil
		},
		LoadAgentInstructions: func(context.Context, *sessions.Store, string, string, map[string]any, string, []string, agentinstr.Selection) ([]agentinstr.LoadEntry, error) {
			rec("7c:LoadAgentInstructions")
			return nil, nil
		},
		StartTUI: func(context.Context, *BootstrapResult) error { rec("8:StartTUI"); return nil },
	}
}

// subsequenceOrder is the resume sub-sequence and standard-step order shared by
// both entry points. No resume path prunes, so the sub-sequence is
// identical for `--resume <id>` and the no-id picker.
func subsequenceOrder() []string {
	return []string{
		"R1:ResolveResume", "R2:AcquireLock", "R3:AppendLaunchBegan", "R4:RefreshUpdatedAt",
		"2:ResolveProjectRoot", "2b:GateTrust", "2.5:ScaffoldProjectIgnore", "2.6:RecoverJournals",
		"3:ComposeConfig", "4:LoadVCSTemplates",
		"5:ValidatePreferredVCS", "6:DetectVCS", "6c:BuildToolRegistry",
		"7:DetermineModel", "7b2:InitMode", "7c:LoadAgentInstructions", "8:StartTUI",
	}
}

func TestRunResumeWithID_StepOrder(t *testing.T) {
	var order []string
	res, err := runResumeWithID(context.Background(), "/home/u", "/cwd", "the-id", recordingResumeSteps(&order))
	if err != nil {
		t.Fatalf("runResumeWithID error: %v", err)
	}
	if res == nil {
		t.Fatal("runResumeWithID returned nil result on full launch")
	}

	want := append([]string{"0:RunFirstRun", "1:LoadGlobalSettings"}, subsequenceOrder()...)
	assertOrder(t, want, order)
}

func TestRunResumePicker_StepOrder_OnPick(t *testing.T) {
	var order []string
	res, err := runResumePicker(context.Background(), "/home/u", "/cwd", recordingResumeSteps(&order))
	if err != nil {
		t.Fatalf("runResumePicker error: %v", err)
	}
	if res == nil {
		t.Fatal("runResumePicker returned nil result after a pick")
	}

	want := append(
		[]string{"0:RunFirstRun", "1:LoadGlobalSettings", "P:ListAndSelect"},
		subsequenceOrder()...,
	)
	assertOrder(t, want, order)
}

// TestRunResume_PutsBackAKilledChildsWrite drives the production step-2.6 adapter through both
// resume entry points: a resumed launch is a launch for that project folder, so the journal a
// killed launch left behind is found and the file is read back from disk in its pre-run state.
func TestRunResume_PutsBackAKilledChildsWrite(t *testing.T) {
	launchers := map[string]func(steps ResumeSteps) (*BootstrapResult, error){
		"--resume <id>": func(steps ResumeSteps) (*BootstrapResult, error) {
			return runResumeWithID(context.Background(), "/home/u", "/cwd", "the-id", steps)
		},
		"no-id picker": func(steps ResumeSteps) (*BootstrapResult, error) {
			return runResumePicker(context.Background(), "/home/u", "/cwd", steps)
		},
	}

	for name, launch := range launchers {
		t.Run(name, func(t *testing.T) {
			home, project := realPath(t, t.TempDir()), realPath(t, t.TempDir())
			target := filepath.Join(project, "a.txt")
			if err := os.WriteFile(target, []byte("ORIGINAL\n"), 0o644); err != nil {
				t.Fatalf("seed: %v", err)
			}
			writeGlobalSettings(t, home, blockedYAML(), 0o600)
			journal := killedChildJournal(t, home, project, target)

			var stderr strings.Builder
			var order []string
			steps := recordingResumeSteps(&order)
			steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) {
				order = append(order, "2:ResolveProjectRoot")
				return project, nil, nil
			}
			steps.RecoverJournals = func(_, projectRoot string, global map[string]any, decision trust.Decision) {
				order = append(order, "2.6:RecoverJournals")
				DefaultResumeSteps(strings.NewReader(""), io.Discard, &stderr).RecoverJournals(home, projectRoot, global, decision)
			}

			res, err := launch(steps)
			if err != nil || res == nil {
				t.Fatalf("resume launch = (%v, %v), want a full launch", res, err)
			}
			if got, err := os.ReadFile(target); err != nil || string(got) != "ORIGINAL\n" {
				t.Fatalf("%s = %q (err=%v), want its pre-run bytes", target, got, err)
			}
			if _, err := os.Stat(journal); !os.IsNotExist(err) {
				t.Fatalf("stat %s: %v, want the finished journal removed", journal, err)
			}
			if !strings.Contains(stderr.String(), "put back: "+target) {
				t.Fatalf("stderr = %q, want the restored file named", stderr.String())
			}
			if !slices.Contains(order, "2.6:RecoverJournals") {
				t.Fatalf("order = %v, want the resume launch to run recovery", order)
			}
		})
	}
}

// TestRunResume_BackgroundPruneMarker pins that no resume path prunes. Both the
// direct `--resume <id>` form and the no-id picker form leave BackgroundPrune unset,
// so StartTUI never kicks off the retention pruner for a resumed run.
func TestRunResume_BackgroundPruneMarker(t *testing.T) {
	t.Run("withID leaves marker unset", func(t *testing.T) {
		var order []string
		res, err := runResumeWithID(context.Background(), "/home/u", "/cwd", "the-id", recordingResumeSteps(&order))
		if err != nil {
			t.Fatalf("runResumeWithID error: %v", err)
		}
		if res.BackgroundPrune {
			t.Fatal("--resume <id> result set BackgroundPrune; no resume path may prune (req 450)")
		}
	})

	t.Run("picker leaves marker unset", func(t *testing.T) {
		var order []string
		res, err := runResumePicker(context.Background(), "/home/u", "/cwd", recordingResumeSteps(&order))
		if err != nil {
			t.Fatalf("runResumePicker error: %v", err)
		}
		if res.BackgroundPrune {
			t.Fatal("no-id picker result set BackgroundPrune; no resume path may prune (req 450)")
		}
	})
}

// TestRunResumePicker_DismissExitsCleanly proves the no-id form exits normally when
// the user dismisses and runs no step past the listing — no prune ever runs on this
// path and the resume sub-sequence is not entered.
func TestRunResumePicker_DismissExitsCleanly(t *testing.T) {
	var order []string
	steps := recordingResumeSteps(&order)
	steps.ListAndSelect = func(string, string, map[string]any) (string, bool, error) {
		order = append(order, "P:ListAndSelect")
		return "", false, nil
	}

	res, err := runResumePicker(context.Background(), "/home/u", "/cwd", steps)
	if err != nil {
		t.Fatalf("runResumePicker error: %v", err)
	}
	if res != nil {
		t.Fatalf("result = %v, want nil when the user dismisses", res)
	}
	assertOrder(t, []string{"0:RunFirstRun", "1:LoadGlobalSettings", "P:ListAndSelect"}, order)
	if slices.Contains(order, "R1:ResolveResume") {
		t.Fatalf("resume sub-sequence entered after dismiss; order=%v", order)
	}
}

// TestRunResumeExported_ResolvesHomeAndRuns proves the exported entry points run
// step 0a (ResolveHome) and, on success, feed the resolved home into the rest of
// the sequence — mirroring RunFresh. The private helpers take an already-resolved
// home, so this coverage lives only on the exported wrappers.
func TestRunResumeExported_ResolvesHomeAndRuns(t *testing.T) {
	t.Run("withID", func(t *testing.T) {
		var order []string
		steps := recordingResumeSteps(&order)
		res, err := RunResumeWithID(context.Background(), "/cwd", "the-id", steps)
		if err != nil {
			t.Fatalf("RunResumeWithID error: %v", err)
		}
		if res == nil {
			t.Fatal("RunResumeWithID returned nil result on full launch")
		}
		if len(order) == 0 || order[0] != "0a:ResolveHome" {
			t.Fatalf("ResolveHome did not run first; order=%v", order)
		}
	})

	t.Run("picker", func(t *testing.T) {
		var order []string
		steps := recordingResumeSteps(&order)
		res, err := RunResumePicker(context.Background(), "/cwd", steps)
		if err != nil {
			t.Fatalf("RunResumePicker error: %v", err)
		}
		if res == nil {
			t.Fatal("RunResumePicker returned nil result after a pick")
		}
		if len(order) == 0 || order[0] != "0a:ResolveHome" {
			t.Fatalf("ResolveHome did not run first; order=%v", order)
		}
	})
}

// TestRunResumeExported_HomeResolveError proves a step-0a failure is wrapped in a
// HomeResolveError (carrying the underlying cause) and aborts before any later
// step runs, exactly as RunFresh wraps its step-0a failure.
func TestRunResumeExported_HomeResolveError(t *testing.T) {
	sentinel := errors.New("$HOME unset")
	assertWrapped := func(t *testing.T, err error, order []string) {
		t.Helper()
		var hre *HomeResolveError
		if !errors.As(err, &hre) {
			t.Fatalf("err = %v, want *HomeResolveError", err)
		}
		if !errors.Is(err, sentinel) {
			t.Fatalf("HomeResolveError did not wrap the cause: %v", err)
		}
		if len(order) != 0 {
			t.Fatalf("steps ran after home-resolution failed; order=%v", order)
		}
	}

	t.Run("withID", func(t *testing.T) {
		var order []string
		steps := recordingResumeSteps(&order)
		steps.ResolveHome = func() (string, error) { return "", sentinel }
		res, err := RunResumeWithID(context.Background(), "/cwd", "the-id", steps)
		if res != nil {
			t.Fatalf("result = %v, want nil on home-resolution failure", res)
		}
		assertWrapped(t, err, order)
	})

	t.Run("picker", func(t *testing.T) {
		var order []string
		steps := recordingResumeSteps(&order)
		steps.ResolveHome = func() (string, error) { return "", sentinel }
		res, err := RunResumePicker(context.Background(), "/cwd", steps)
		if res != nil {
			t.Fatalf("result = %v, want nil on home-resolution failure", res)
		}
		assertWrapped(t, err, order)
	})
}

// TestRunResume_PopulatesLaunchDir locks the item 4 / status-overlay
// contract on the resume paths: both entry points must set BootstrapResult.LaunchDir
// to the launch cwd — the same value the fresh path sets (orchestrate.go) and that
// StartTUI feeds into /status — so a resumed run shows its launch directory rather
// than an empty string.
func TestRunResume_PopulatesLaunchDir(t *testing.T) {
	const cwd = "/launch/dir"
	t.Run("withID", func(t *testing.T) {
		var order []string
		res, err := runResumeWithID(context.Background(), "/home/u", cwd, "the-id", recordingResumeSteps(&order))
		if err != nil {
			t.Fatalf("runResumeWithID error: %v", err)
		}
		if res.LaunchDir != cwd {
			t.Fatalf("LaunchDir = %q, want %q", res.LaunchDir, cwd)
		}
	})
	t.Run("picker", func(t *testing.T) {
		var order []string
		res, err := runResumePicker(context.Background(), "/home/u", cwd, recordingResumeSteps(&order))
		if err != nil {
			t.Fatalf("runResumePicker error: %v", err)
		}
		if res.LaunchDir != cwd {
			t.Fatalf("LaunchDir = %q, want %q", res.LaunchDir, cwd)
		}
	})
}

// TestRunResume_ConfigLayerPaths pins item 10 on both resume entry points:
// each records the same global-first/project-last /status config sources the fresh
// path does — the global settings.yaml (SettingsPath(home)) followed by the
// project-side layer(s) ResolveProjectRoot returned — so a resumed run shows the
// same config sources as a fresh one.
func TestRunResume_ConfigLayerPaths(t *testing.T) {
	const home = "/home/u"
	projectLayer := "/proj/.codemeld/settings.yaml"
	withProjectLayer := func(steps *ResumeSteps) {
		steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) {
			return "/proj", []string{projectLayer}, nil
		}
	}
	want := []string{SettingsPath(home), projectLayer}

	t.Run("withID", func(t *testing.T) {
		var order []string
		steps := recordingResumeSteps(&order)
		withProjectLayer(&steps)
		res, err := runResumeWithID(context.Background(), home, "/cwd", "the-id", steps)
		if err != nil {
			t.Fatalf("runResumeWithID error: %v", err)
		}
		if !slices.Equal(res.ConfigLayerPaths, want) {
			t.Fatalf("ConfigLayerPaths = %v, want %v (global-first, project-last)", res.ConfigLayerPaths, want)
		}
	})

	t.Run("picker", func(t *testing.T) {
		var order []string
		steps := recordingResumeSteps(&order)
		withProjectLayer(&steps)
		res, err := runResumePicker(context.Background(), home, "/cwd", steps)
		if err != nil {
			t.Fatalf("runResumePicker error: %v", err)
		}
		if !slices.Equal(res.ConfigLayerPaths, want) {
			t.Fatalf("ConfigLayerPaths = %v, want %v (global-first, project-last)", res.ConfigLayerPaths, want)
		}
	})

	t.Run("global only when no project layer", func(t *testing.T) {
		var order []string
		// recordingResumeSteps' default ResolveProjectRoot returns no project layers.
		res, err := runResumeWithID(context.Background(), home, "/cwd", "the-id", recordingResumeSteps(&order))
		if err != nil {
			t.Fatalf("runResumeWithID error: %v", err)
		}
		if globalOnly := []string{SettingsPath(home)}; !slices.Equal(res.ConfigLayerPaths, globalOnly) {
			t.Fatalf("ConfigLayerPaths = %v, want %v (global only)", res.ConfigLayerPaths, globalOnly)
		}
	})
}

// TestRunResume_FirstRunShortCircuits proves step 0's first-run branch exits both
// entry points before step 1 and before any listing or resolution (step 0).
func TestRunResume_FirstRunShortCircuits(t *testing.T) {
	t.Run("with-id", func(t *testing.T) {
		var order []string
		steps := recordingResumeSteps(&order)
		steps.RunFirstRun = func(string) (bool, error) { order = append(order, "0:RunFirstRun"); return true, nil }

		res, err := runResumeWithID(context.Background(), "/home/u", "/cwd", "the-id", steps)
		if err != nil {
			t.Fatalf("runResumeWithID error: %v", err)
		}
		if res != nil {
			t.Fatalf("result = %v, want nil on first-run branch", res)
		}
		assertOrder(t, []string{"0:RunFirstRun"}, order)
	})

	t.Run("no-id", func(t *testing.T) {
		var order []string
		steps := recordingResumeSteps(&order)
		steps.RunFirstRun = func(string) (bool, error) { order = append(order, "0:RunFirstRun"); return true, nil }

		res, err := runResumePicker(context.Background(), "/home/u", "/cwd", steps)
		if err != nil {
			t.Fatalf("runResumePicker error: %v", err)
		}
		if res != nil {
			t.Fatalf("result = %v, want nil on first-run branch", res)
		}
		assertOrder(t, []string{"0:RunFirstRun"}, order)
	})
}

// TestRunResumeWithID_ShortCircuitsOnStepError walks each error-returning step on
// the `--resume <id>` path, makes it fail, and asserts the failing step ran while
// the immediately following step did not — proving step N+1 runs only when step N
// returned nil ("each step depends on every preceding step").
func TestRunResumeWithID_ShortCircuitsOnStepError(t *testing.T) {
	sentinel := errors.New("boom")

	cases := []struct {
		name       string
		fail       func(s *ResumeSteps)
		lastBefore string // step that must NOT run; "" for the final step
	}{
		{"step0_RunFirstRun", func(s *ResumeSteps) {
			s.RunFirstRun = func(string) (bool, error) { return false, sentinel }
		}, "1:LoadGlobalSettings"},
		{"step1_LoadGlobalSettings", func(s *ResumeSteps) {
			s.LoadGlobalSettings = func(string) (map[string]any, error) { return nil, sentinel }
		}, "R1:ResolveResume"},
		{"resolve_ResolveResume", func(s *ResumeSteps) {
			s.ResolveResume = func(string, string, string) (string, *sessions.Session, error) { return "", nil, sentinel }
		}, "R2:AcquireLock"},
		{"lock_AcquireLock", func(s *ResumeSteps) {
			s.AcquireLock = func(string, string) (func(), error) { return nil, sentinel }
		}, "R3:AppendLaunchBegan"},
		{"launchbegan_AppendLaunchBegan", func(s *ResumeSteps) {
			s.AppendLaunchBegan = func(context.Context, *sessions.Store) error { return sentinel }
		}, "R4:RefreshUpdatedAt"},
		{"refresh_RefreshUpdatedAt", func(s *ResumeSteps) {
			s.RefreshUpdatedAt = func(context.Context, *sessions.Store) error { return sentinel }
		}, "2:ResolveProjectRoot"},
		{"step2_ResolveProjectRoot", func(s *ResumeSteps) {
			s.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) { return "", nil, sentinel }
		}, "2b:GateTrust"},
		{"step2.5_ScaffoldProjectIgnore", func(s *ResumeSteps) {
			s.ScaffoldProjectIgnore = func(string) error { return sentinel }
		}, "2.6:RecoverJournals"},
		{"step3_ComposeConfig", func(s *ResumeSteps) {
			s.ComposeConfig = func(map[string]any, string) (ConfigComposition, error) {
				return ConfigComposition{}, sentinel
			}
		}, "4:LoadVCSTemplates"},
		{"step4_LoadVCSTemplates", func(s *ResumeSteps) {
			s.LoadVCSTemplates = func(string, string, map[string]any, bool) (any, error) {
				return nil, sentinel
			}
		}, "5:ValidatePreferredVCS"},
		{"step5_ValidatePreferredVCS", func(s *ResumeSteps) {
			s.ValidatePreferredVCS = func(map[string]any, any) error { return sentinel }
		}, "6:DetectVCS"},
		{"step6_DetectVCS", func(s *ResumeSteps) {
			s.DetectVCS = func(string, map[string]any, any) (any, error) { return nil, sentinel }
		}, "6c:BuildToolRegistry"},
		{"step6c_BuildToolRegistry", func(s *ResumeSteps) {
			s.BuildToolRegistry = func(any) (any, error) { return nil, sentinel }
		}, "7:DetermineModel"},
		{"step7_DetermineModel", func(s *ResumeSteps) {
			s.DetermineModel = func(map[string]any, map[string]any, string, []string, *sessions.Store) (any, bool, error) {
				return nil, false, sentinel
			}
		}, "7b2:InitMode"},
		{"step7b2_InitMode", func(s *ResumeSteps) {
			s.InitMode = func(context.Context, *sessions.Store, map[string]any, string, []string) (any, error) {
				return nil, sentinel
			}
		}, "7c:LoadAgentInstructions"},
		{"step7c_LoadAgentInstructions", func(s *ResumeSteps) {
			s.LoadAgentInstructions = func(context.Context, *sessions.Store, string, string, map[string]any, string, []string, agentinstr.Selection) ([]agentinstr.LoadEntry, error) {
				return nil, sentinel
			}
		}, "8:StartTUI"},
		{"step8_StartTUI", func(s *ResumeSteps) {
			s.StartTUI = func(context.Context, *BootstrapResult) error { return sentinel }
		}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var order []string
			steps := recordingResumeSteps(&order)
			tc.fail(&steps)

			res, err := runResumeWithID(context.Background(), "/home/u", "/cwd", "the-id", steps)
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

// TestRunResumePicker_ShortCircuitsOnStepError covers the no-id-only step the
// with-id table cannot reach: the listing/selection step. A failure there aborts
// before the resume sub-sequence begins ("each step depends on every
// preceding step").
func TestRunResumePicker_ShortCircuitsOnStepError(t *testing.T) {
	sentinel := errors.New("boom")

	var order []string
	steps := recordingResumeSteps(&order)
	steps.ListAndSelect = func(string, string, map[string]any) (string, bool, error) {
		order = append(order, "P:ListAndSelect")
		return "", false, sentinel
	}

	res, err := runResumePicker(context.Background(), "/home/u", "/cwd", steps)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel", err)
	}
	if res != nil {
		t.Fatalf("result = %v, want nil on failure", res)
	}
	if slices.Contains(order, "R1:ResolveResume") {
		t.Fatalf("resume sub-sequence ran after the listing step failed; order=%v", order)
	}
}

// TestRunResume_ModelPathFourExitBeforeAgentsAndTUI proves a path-4 exit
// returned by DetermineModel (step 7) lands after the launch_began (resume)
// sub-step has emitted but before step 7c and step 8 run (resumed-run
// path-4 carve-out).
func TestRunResume_ModelPathFourExitBeforeAgentsAndTUI(t *testing.T) {
	var order []string
	steps := recordingResumeSteps(&order)
	pathFour := errors.New("no selectable model")
	steps.DetermineModel = func(map[string]any, map[string]any, string, []string, *sessions.Store) (any, bool, error) {
		order = append(order, "7:DetermineModel")
		return nil, false, pathFour
	}

	_, err := runResumeWithID(context.Background(), "/home/u", "/cwd", "the-id", steps)
	if !errors.Is(err, pathFour) {
		t.Fatalf("err = %v, want path-4 exit", err)
	}
	if !slices.Contains(order, "R3:AppendLaunchBegan") {
		t.Fatalf("launch_began (resume) did not emit before the path-4 exit; order=%v", order)
	}
	for _, later := range []string{"7b2:InitMode", "7c:LoadAgentInstructions", "8:StartTUI"} {
		if slices.Contains(order, later) {
			t.Fatalf("step %q ran after the path-4 exit; order=%v", later, order)
		}
	}
}

func TestRunResume_ModelPathFourFlushesRecoveryFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	var order []string
	steps := recordingResumeSteps(&order)
	steps.ResolveResume = func(string, string, string) (string, *sessions.Session, error) {
		order = append(order, "R1:ResolveResume")
		return path, &sessions.Session{Metadata: sessions.Metadata{
			ID:            "01890000-0000-7000-8000-000000000540",
			Folder:        "/cwd",
			StartedAt:     testStart,
			UpdatedAt:     testStart,
			SchemaVersion: sessions.CurrentSchemaVersion,
		}}, nil
	}
	steps.DetermineModel = func(_ map[string]any, _ map[string]any, _ string, _ []string, store *sessions.Store) (any, bool, error) {
		order = append(order, "7:DetermineModel")
		if _, err := events.Append(store, events.ModelRecoveryFailed{Reason: "validation_failed", ErrorDetail: "bad model"}); err != nil {
			t.Fatalf("append model_recovery_failed: %v", err)
		}
		return nil, false, &model.NoSelectableModelError{Lines: []string{"codemeld: no selectable model"}}
	}

	res, err := runResumeWithID(context.Background(), "/home/u", "/cwd", "the-id", steps)
	if res != nil {
		t.Fatalf("result = %v, want nil on no-selectable-model exit", res)
	}
	var noSelectable *model.NoSelectableModelError
	if !errors.As(err, &noSelectable) {
		t.Fatalf("err = %v, want *model.NoSelectableModelError", err)
	}
	disk := readSessionFile(t, path)
	if got := diskEventKinds(disk); !slices.Contains(got, events.KindModelRecoveryFailed) {
		t.Fatalf("disk event kinds = %v, want model_recovery_failed flushed before exit", got)
	}
}

func TestRunResume_PopulatesAgentInstructions(t *testing.T) {
	entry := agentinstr.LoadEntry{Path: "/proj/AGENTS.md", Layer: agentinstr.LayerWalked, LoadOrder: 2}
	var order []string
	steps := recordingResumeSteps(&order)
	steps.LoadAgentInstructions = func(context.Context, *sessions.Store, string, string, map[string]any, string, []string, agentinstr.Selection) ([]agentinstr.LoadEntry, error) {
		order = append(order, "7c:LoadAgentInstructions")
		return []agentinstr.LoadEntry{entry}, nil
	}

	res, err := runResumeWithID(context.Background(), "/home/u", "/cwd", "the-id", steps)
	if err != nil {
		t.Fatalf("runResumeWithID error: %v", err)
	}
	if len(res.AgentInstructions) != 1 || res.AgentInstructions[0].Path != entry.Path || res.AgentInstructions[0].Layer != entry.Layer || res.AgentInstructions[0].LoadOrder != entry.LoadOrder {
		t.Fatalf("AgentInstructions = %+v, want [%+v]", res.AgentInstructions, entry)
	}
}

func TestRunResume_AgentInstructionsSelectionReachesTheProductionAdapter(t *testing.T) {
	if got := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard).AgentInstructionsSelection; got != (agentinstr.Selection{}) {
		t.Fatalf("DefaultResumeSteps selection = %+v, want the zero value", got)
	}
	adapter := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard).LoadAgentInstructions
	f := newSelectionFixture(t)
	routes := map[string]func(ResumeSteps) (*BootstrapResult, error){
		"id": func(s ResumeSteps) (*BootstrapResult, error) {
			return runResumeWithID(context.Background(), f.home, f.launchDir, "the-id", s)
		},
		"picker": func(s ResumeSteps) (*BootstrapResult, error) {
			return runResumePicker(context.Background(), f.home, f.launchDir, s)
		},
	}
	for route, run := range routes {
		for name, sel := range f.selections() {
			t.Run(route+"/"+name, func(t *testing.T) {
				var order []string
				steps := recordingResumeSteps(&order)
				steps.AgentInstructionsSelection = sel
				path := filepath.Join(t.TempDir(), "session.json")
				steps.ResolveResume = func(string, string, string) (string, *sessions.Session, error) {
					order = append(order, "R1:ResolveResume")
					return path, &sessions.Session{Metadata: sessions.Metadata{
						ID:            "01890000-0000-7000-8000-000000000423",
						Folder:        f.launchDir,
						StartedAt:     testStart,
						UpdatedAt:     testStart,
						SchemaVersion: sessions.CurrentSchemaVersion,
					}}, nil
				}
				var got agentinstr.Selection
				steps.LoadAgentInstructions = func(ctx context.Context, s *sessions.Store, home, launchDir string, composed map[string]any, root string, layers []string, selection agentinstr.Selection) ([]agentinstr.LoadEntry, error) {
					order = append(order, "7c:LoadAgentInstructions")
					got = selection
					if n := countEvents(s, events.KindAgentInstructionsLoaded); n != 0 {
						t.Fatalf("agent_instructions_loaded records before step 7c = %d, want 0", n)
					}
					return adapter(ctx, s, home, launchDir, composed, root, layers, selection)
				}

				res, err := run(steps)
				if err != nil {
					t.Fatalf("resume: %v", err)
				}
				if got != sel {
					t.Fatalf("step 7c selection = %+v, want %+v", got, sel)
				}
				agents := slices.Index(order, "7c:LoadAgentInstructions")
				for _, earlier := range []string{"R4:RefreshUpdatedAt", "7b2:InitMode"} {
					if i := slices.Index(order, earlier); i < 0 || i > agents {
						t.Fatalf("%s did not run before step 7c; order=%v", earlier, order)
					}
				}
				if slices.Index(order, "8:StartTUI") < agents {
					t.Fatalf("step 8 ran before step 7c; order=%v", order)
				}
				f.assertSelectionOutcome(t, sel, res, res.Session)
			})
		}
	}
}

// TestDefaultResumeSteps_AllStepsWired guards against a forgotten field: every
// ResumeSteps func must be non-nil, or the orchestrator would panic at that step.
func TestDefaultResumeSteps_AllStepsWired(t *testing.T) {
	steps := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard)
	v := reflect.ValueOf(steps)
	for i := range v.NumField() {
		if v.Field(i).Kind() == reflect.Func && v.Field(i).IsNil() {
			t.Errorf("DefaultResumeSteps left %s nil", v.Type().Field(i).Name)
		}
	}
}

// TestDefaultResumeSteps_InitMode_DurableResumeReadback drives the production resume
// step-7b2 adapter (not a fake): a resumed launch seeds the run mode from
// mode.default and durably appends interaction_mode{trigger:"resume"} — never the
// prior session's mode — with source "config" when the key is present.
func TestDefaultResumeSteps_InitMode_DurableResumeReadback(t *testing.T) {
	store := mkStore(t)
	steps := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard)
	composed := map[string]any{"mode": map[string]any{"default": "auto_edits"}}

	modeState, err := steps.InitMode(context.Background(), store, composed, "/proj", nil)
	if err != nil {
		t.Fatalf("InitMode: %v", err)
	}
	if m, src := modeState.(*mode.ActiveState).Current(); m != mode.AutoEdits || src != mode.SourceConfig {
		t.Fatalf("active mode = (%q, %q), want (auto_edits, config)", m, src)
	}
	im := diskInteractionMode(t, readSessionFile(t, store.Path()))
	if len(im) != 1 || im[0].Mode != "auto_edits" || im[0].Source != "config" || im[0].Trigger != "resume" {
		t.Fatalf("durable interaction_mode = %+v, want one {auto_edits, config, resume}", im)
	}
}

// TestDefaultResumeSteps_StartTUI_IsRealNotNoOp proves the resume production
// default runs the real step-8 event-loop assembly, not a no-op: with the
// runApp seam swapped, invoking the default StartTUI must reach App.Run. A no-op
// stub would return nil without ever realizing the registry/dispatcher path, so
// this is the resume analogue of TestDefaultFreshSteps_StartTUI_IsRealNotNoOp.
func TestDefaultResumeSteps_StartTUI_IsRealNotNoOp(t *testing.T) {
	var ran bool
	defer swapRunApp(func(*tui.App) error { ran = true; return nil })()

	steps := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard)
	result := &BootstrapResult{Home: t.TempDir(), Session: mkStore(t)}
	if err := steps.StartTUI(context.Background(), result); err != nil {
		t.Fatalf("DefaultResumeSteps.StartTUI error: %v", err)
	}
	if !ran {
		t.Fatal("DefaultResumeSteps.StartTUI is still a no-op stub; it did not run the event loop")
	}
}

// TestDefaultResumeSteps_ResolveResumeRejectsSchemaInvalidPayload pins the
// cold-start --resume <id> wiring: DefaultResumeSteps.ResolveResume must compose
// the real events.ValidatePayload into the load path, not nil/no-op. It drives the
// production closure against a spine-valid stream_interrupted event missing the
// required content_chars and asserts the exact payload rejection — the
// closure analogue of the resumeLoader.Load terminal test, so the default closure
// proves it supplies the real validator (a nil validator would accept the file).
func TestDefaultResumeSteps_ResolveResumeRejectsSchemaInvalidPayload(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	store, err := sessions.EnsureSession(home, canonical, testStart, nil)
	if err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	mustFlush(t, store)
	id := store.SessionID()

	// Spine-valid stream_interrupted event missing the required content_chars: it
	// parses and passes, so only the per-kind validator can reject it.
	invalid := `{"type":"event","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a02",` +
		`"kind":"stream_interrupted","timestamp":"2026-05-25T12:00:00.000Z","payload":{"source":"esc"}}`
	doc := `{"type":"metadata","metadata":{"id":"` + id + `","folder":` + strconv.Quote(canonical) +
		`,"started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":1}}` + "\n" +
		invalid + "\n"
	if err := os.WriteFile(store.Path(), []byte(doc), 0o600); err != nil {
		t.Fatalf("overwrite session file: %v", err)
	}

	steps := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard)
	path, sess, rerr := steps.ResolveResume(id, cwd, home)
	if rerr == nil {
		t.Fatal("ResolveResume accepted a session with a schema-invalid event payload")
	}
	if path != "" || sess != nil {
		t.Errorf("rejection returned path=%q sess=%v, want empty/nil", path, sess)
	}
	var le *sessions.ResumeLoadError
	if !errors.As(rerr, &le) {
		t.Fatalf("error %v is not a *sessions.ResumeLoadError", rerr)
	}
	want := "codemeld: session " + id + " cannot be loaded: " +
		"records[0].payload: stream_interrupted.content_chars: required field is absent\n" +
		"run codemeld --resume with no id to list resumable sessions for the current working directory."
	if rerr.Error() != want {
		t.Errorf("Error() = %q\nwant %q", rerr.Error(), want)
	}
}

func TestDefaultResumeSteps_ResumeStreamSubstepsDurableReadback(t *testing.T) {
	store := mkStore(t)
	steps := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard)

	// The resume sub-sequence's durable stream sub-steps are launch_began (source
	// resume) followed by the updated_at refresh; no prune runs on a resumed run
	// so the launch suffix carries only the launch anchor.
	if err := steps.AppendLaunchBegan(context.Background(), store); err != nil {
		t.Fatalf("AppendLaunchBegan: %v", err)
	}
	if err := steps.RefreshUpdatedAt(context.Background(), store); err != nil {
		t.Fatalf("RefreshUpdatedAt: %v", err)
	}

	disk := readSessionFile(t, store.Path())
	if got, want := diskEventKinds(disk), []string{events.KindLaunchBegan}; !slices.Equal(got, want) {
		t.Fatalf("disk event kinds = %v, want %v (launch anchor only; no prune on resume)", got, want)
	}
	if got := firstLaunchBeganSource(t, disk); got != "resume" {
		t.Fatalf("launch_began source = %q, want resume", got)
	}
	if !disk.Metadata.UpdatedAt.After(testStart) {
		t.Fatalf("updated_at = %s, want after %s (req 450a refresh)", disk.Metadata.UpdatedAt, testStart)
	}
}

func TestDefaultResumeSteps_ResumeStreamWriteFailuresCarryForward(t *testing.T) {
	store := unwritableStore(t, "01890000-0000-7000-8000-000000000425", "/proj")
	var stderr strings.Builder
	steps := DefaultResumeSteps(strings.NewReader(""), io.Discard, &stderr)

	if err := steps.AppendLaunchBegan(context.Background(), store); err != nil {
		t.Fatalf("AppendLaunchBegan write failure should carry forward, got %v", err)
	}
	if got := countEvents(store, events.KindSessionWriteFailed); got != 1 {
		t.Fatalf("session_write_failed after launch_began = %d, want 1", got)
	}
	if err := steps.RefreshUpdatedAt(context.Background(), store); err != nil {
		t.Fatalf("RefreshUpdatedAt write failure should carry forward, got %v", err)
	}
	if got := countEvents(store, events.KindSessionWriteFailed); got != 2 {
		t.Fatalf("session_write_failed after refresh = %d, want 2", got)
	}
	if got := stderr.String(); !strings.Contains(got, "session log unwritable") {
		t.Fatalf("stderr notice = %q, want session write-failure notice", got)
	}
}

func countEvents(store *sessions.Store, kind string) int {
	count := 0
	for _, r := range store.Records() {
		if ev, ok := r.(sessions.Event); ok && ev.Kind == kind {
			count++
		}
	}
	return count
}

// TestDefaultResumeSteps_LoadAgentInstructions_DurableReplay drives the production
// resume step-7c adapter (not a fake) against real temp dirs and a resumed store,
// then reads the session file back to prove the agent_instructions_loaded records
// are durable. As on the fresh path the walk anchor is the launch directory: a
// sibling projectRoot/AGENTS.md is never replayed while launchDir/AGENTS.md is. It
// also pins the configured size cap: the launch fixture exceeds the composed
// agent_instructions.max_file_bytes value, so its durable record must be a
// size_limit skip — proving the resume adapter threads the configured cap rather
// than a hardcoded default.
func TestDefaultResumeSteps_LoadAgentInstructions_DurableReplay(t *testing.T) {
	home := t.TempDir()
	launchDir := t.TempDir()
	projectRoot := t.TempDir() // a sibling of launchDir, deliberately not an ancestor

	const maxFileBytes = 16
	globalPath := writeGlobalAgents(t, home, "# global\n")                           // 9 bytes, within the cap → loaded
	launchPath := writeAgentsFile(t, launchDir, strings.Repeat("L", maxFileBytes+1)) // over the cap → size_limit skip
	projectPath := writeAgentsFile(t, projectRoot, "# project root — must not replay\n")

	store := storeAt(t, filepath.Join(t.TempDir(), "session.json"),
		"01890000-0000-7000-8000-000000000421", projectRoot)

	composed := map[string]any{"agent_instructions": map[string]any{"max_file_bytes": maxFileBytes}}
	step := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard).LoadAgentInstructions
	entries, err := step(context.Background(), store, home, launchDir, composed, projectRoot, []string{SettingsPath(home)}, agentinstr.Selection{})
	if err != nil {
		t.Fatalf("LoadAgentInstructions: %v", err)
	}
	if findLoadEntry(t, entries, globalPath).LoadOrder != 1 {
		t.Fatalf("returned entries = %+v, want global load_order 1", entries)
	}

	loaded := diskAgentInstr(t, readSessionFile(t, store.Path()))
	if len(loaded) < 2 {
		t.Fatalf("durable agent_instructions_loaded count = %d, want >= 2 (global + launch)", len(loaded))
	}
	if loaded[0].Path != globalPath || loaded[0].Layer != agentinstr.LayerGlobal || loaded[0].LoadOrder != 1 {
		t.Fatalf("first durable record = %+v, want the global file at load_order 1", loaded[0])
	}
	gi, li := diskIndex(loaded, globalPath), diskIndex(loaded, launchPath)
	if li < 0 {
		t.Fatalf("launch AGENTS.md absent from durable resume records: %+v", loaded)
	}
	if gi >= li {
		t.Fatalf("global (idx %d) did not precede walked launch (idx %d) on disk", gi, li)
	}
	for _, p := range loaded {
		if p.Path == projectPath {
			t.Fatal("project-root AGENTS.md persisted on resume; the anchor was projectRoot, not launchDir")
		}
	}

	// Configured cap: the over-cap launch fixture must land as a size_limit skip.
	assertConfiguredCapHonored(t, store, launchPath)
}

// --- no-id ListAndSelect wiring ---

// writeListSession lands a structurally valid, schema_version-1 session for cwd's
// canonical folder so the real sessions.ListResumable surfaces it (file stem = id).
func writeListSession(t *testing.T, home, cwd, id, updatedAt string) {
	t.Helper()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize %s: %v", cwd, err)
	}
	subdir, err := sessions.EnsureFolderDir(home, canonical)
	if err != nil {
		t.Fatalf("ensure folder dir: %v", err)
	}
	// metadata.id must be a valid UUIDv7 (OpenSession enforces it); the listing id is
	// the file stem, so the stem carries the test-meaningful id while metadata.id stays
	// a fixed valid handle.
	doc := `{"type":"metadata","metadata":{"id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b","folder":` + strconv.Quote(canonical) +
		`,"started_at":"2026-05-25T12:00:00.000Z","updated_at":` + strconv.Quote(updatedAt) +
		`,"schema_version":1}}` + "\n"
	if err := os.WriteFile(filepath.Join(subdir, id+".json"), []byte(doc), 0o600); err != nil {
		t.Fatalf("write session %s: %v", id, err)
	}
}

// writeBadSession lands an unparseable candidate so ListResumable buckets it as
// skipped (no surviving entry).
func writeBadSession(t *testing.T, home, cwd, id string) {
	t.Helper()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize %s: %v", cwd, err)
	}
	subdir, err := sessions.EnsureFolderDir(home, canonical)
	if err != nil {
		t.Fatalf("ensure folder dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subdir, id+".json"), []byte("not valid json"), 0o600); err != nil {
		t.Fatalf("write bad session %s: %v", id, err)
	}
}

func listEntryIDs(entries []sessions.ListEntry) []string {
	ids := make([]string, len(entries))
	for i, e := range entries {
		ids[i] = e.ID
	}
	return ids
}

func swapResumeListPreflight(t *testing.T, fn func(io.Reader, int, io.Writer, int, []sessions.SkippedID, func(int) bool, func(io.Reader, int)) int) {
	t.Helper()
	prev := resumeListPreflight
	resumeListPreflight = fn
	t.Cleanup(func() { resumeListPreflight = prev })
}

func swapResumeColdStartSelect(t *testing.T, fn func([]sessions.ListEntry) (string, bool, error)) {
	t.Helper()
	prev := resumeColdStartSelect
	resumeColdStartSelect = fn
	t.Cleanup(func() { resumeColdStartSelect = prev })
}

// TestResumeListAndSelect_ListsCurrentFolderAndSelects drives the production
// ListAndSelect over the real sessions.ListResumable against a temp sessions dir:
// only the current folder's sessions reach the selector, ordered updated_at
// descending, and the selector's choice is returned. A session in another folder
// must not appear.
func TestResumeListAndSelect_ListsCurrentFolderAndSelects(t *testing.T) {
	home, cwd, other := t.TempDir(), t.TempDir(), t.TempDir()
	writeListSession(t, home, cwd, "aaa", "2026-05-25T12:00:01.000Z")
	writeListSession(t, home, cwd, "bbb", "2026-05-25T12:00:02.000Z") // newer → first
	writeListSession(t, home, other, "zzz", "2026-05-25T12:00:09.000Z")

	swapResumeListPreflight(t, func(io.Reader, int, io.Writer, int, []sessions.SkippedID, func(int) bool, func(io.Reader, int)) int {
		return 0
	})
	var gotEntries []sessions.ListEntry
	swapResumeColdStartSelect(t, func(entries []sessions.ListEntry) (string, bool, error) {
		gotEntries = entries
		return entries[0].ID, true, nil
	})

	steps := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard)
	id, picked, err := steps.ListAndSelect(home, cwd, nil)
	if err != nil {
		t.Fatalf("ListAndSelect error: %v", err)
	}
	if !picked || id != "bbb" {
		t.Fatalf("got (id=%q, picked=%v), want (\"bbb\", true)", id, picked)
	}
	if got, want := listEntryIDs(gotEntries), []string{"bbb", "aaa"}; !slices.Equal(got, want) {
		t.Fatalf("selector entries = %v, want %v (current folder only, updated_at desc)", got, want)
	}
}

// TestResumeListAndSelect_TransitionsIntoSubsequence proves a real-listing pick flows
// the chosen id into the resume sub-sequence: runResumePicker reaches ResolveResume
// with the selected id and runs the standard steps that follow.
func TestResumeListAndSelect_TransitionsIntoSubsequence(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	writeListSession(t, home, cwd, "aaa", "2026-05-25T12:00:01.000Z")
	writeListSession(t, home, cwd, "bbb", "2026-05-25T12:00:02.000Z")

	swapResumeListPreflight(t, func(io.Reader, int, io.Writer, int, []sessions.SkippedID, func(int) bool, func(io.Reader, int)) int {
		return 0
	})
	swapResumeColdStartSelect(t, func(entries []sessions.ListEntry) (string, bool, error) {
		return entries[0].ID, true, nil
	})

	var order []string
	steps := recordingResumeSteps(&order)
	steps.ListAndSelect = DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard).ListAndSelect
	var resolvedID string
	steps.ResolveResume = func(id, _, _ string) (string, *sessions.Session, error) {
		resolvedID = id
		order = append(order, "R1:ResolveResume")
		return "/sessions/folder/id.json", &sessions.Session{}, nil
	}

	res, err := runResumePicker(context.Background(), home, cwd, steps)
	if err != nil {
		t.Fatalf("runResumePicker error: %v", err)
	}
	if res == nil {
		t.Fatal("runResumePicker returned nil after a real-listing pick")
	}
	if resolvedID != "bbb" {
		t.Fatalf("ResolveResume received id %q, want \"bbb\"", resolvedID)
	}
	for _, step := range []string{"R1:ResolveResume", "R4:RefreshUpdatedAt", "8:StartTUI"} {
		if !slices.Contains(order, step) {
			t.Fatalf("sub-sequence step %q did not run; order=%v", step, order)
		}
	}
}

// TestResumeListAndSelect_ESCDismisses proves a dismissed selector exits the no-id
// form without entering the resume sub-sequence (no ResolveResume).
func TestResumeListAndSelect_ESCDismisses(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	writeListSession(t, home, cwd, "aaa", "2026-05-25T12:00:01.000Z")

	swapResumeListPreflight(t, func(io.Reader, int, io.Writer, int, []sessions.SkippedID, func(int) bool, func(io.Reader, int)) int {
		return 0
	})
	swapResumeColdStartSelect(t, func([]sessions.ListEntry) (string, bool, error) { return "", false, nil })

	var order []string
	steps := recordingResumeSteps(&order)
	steps.ListAndSelect = DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard).ListAndSelect

	res, err := runResumePicker(context.Background(), home, cwd, steps)
	if err != nil {
		t.Fatalf("runResumePicker error: %v", err)
	}
	if res != nil {
		t.Fatalf("result = %v, want nil on dismissal", res)
	}
	if slices.Contains(order, "R1:ResolveResume") {
		t.Fatalf("resume sub-sequence ran after dismissal; order=%v", order)
	}
}

// TestResumeListAndSelect_EmptyFolderExitsCleanly proves an empty folder returns no
// selection without ever opening the selector.
func TestResumeListAndSelect_EmptyFolderExitsCleanly(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()

	swapResumeListPreflight(t, func(io.Reader, int, io.Writer, int, []sessions.SkippedID, func(int) bool, func(io.Reader, int)) int {
		return 0
	})
	selectorCalled := false
	swapResumeColdStartSelect(t, func([]sessions.ListEntry) (string, bool, error) {
		selectorCalled = true
		return "", false, nil
	})

	steps := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard)
	id, picked, err := steps.ListAndSelect(home, cwd, nil)
	if err != nil || picked || id != "" {
		t.Fatalf("got (id=%q, picked=%v, err=%v), want (\"\", false, nil)", id, picked, err)
	}
	if selectorCalled {
		t.Fatal("selector opened for an empty folder")
	}
}

// TestResumeListAndSelect_EmptyFolderRealPreflightExitsCleanly proves the production
// boundary the seam-swapped test above cannot: with the real resumeListPreflight and
// non-tty in-memory streams (streamFd == -1), a truly empty folder returns no selection
// cleanly instead of failing the non-interactive tty gate with ErrResumeListPreflight.
func TestResumeListAndSelect_EmptyFolderRealPreflightExitsCleanly(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()

	selectorCalled := false
	swapResumeColdStartSelect(t, func([]sessions.ListEntry) (string, bool, error) {
		selectorCalled = true
		return "", false, nil
	})

	var stderr strings.Builder
	steps := DefaultResumeSteps(strings.NewReader(""), io.Discard, &stderr)
	id, picked, err := steps.ListAndSelect(home, cwd, nil)
	if err != nil || picked || id != "" {
		t.Fatalf("got (id=%q, picked=%v, err=%v), want (\"\", false, nil)", id, picked, err)
	}
	if selectorCalled {
		t.Fatal("selector opened for an empty folder")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty for a truly empty folder", stderr.String())
	}
}

// TestResumeListAndSelect_AllSkippedExitsCleanly proves a folder whose every
// candidate is skipped passes the skipped ids to the preflight, then returns no
// selection without opening the selector.
func TestResumeListAndSelect_AllSkippedExitsCleanly(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	writeBadSession(t, home, cwd, "broken")

	var gotSkipped []sessions.SkippedID
	swapResumeListPreflight(t, func(_ io.Reader, _ int, _ io.Writer, _ int, skipped []sessions.SkippedID, _ func(int) bool, _ func(io.Reader, int)) int {
		gotSkipped = skipped
		return 0
	})
	selectorCalled := false
	swapResumeColdStartSelect(t, func([]sessions.ListEntry) (string, bool, error) {
		selectorCalled = true
		return "", false, nil
	})

	steps := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard)
	id, picked, err := steps.ListAndSelect(home, cwd, nil)
	if err != nil || picked || id != "" {
		t.Fatalf("got (id=%q, picked=%v, err=%v), want (\"\", false, nil)", id, picked, err)
	}
	if selectorCalled {
		t.Fatal("selector opened when every candidate was skipped")
	}
	if got := skippedListIDs(gotSkipped); !slices.Equal(got, []string{"broken"}) {
		t.Fatalf("preflight skipped ids = %v, want [broken]", got)
	}
}

// TestResumeListAndSelect_PreflightQuietExit proves a non-tty preflight failure
// becomes ErrResumeListPreflight (the CLI maps it to a quiet status 1) and never
// opens the selector, even when survivors exist.
func TestResumeListAndSelect_PreflightQuietExit(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	writeListSession(t, home, cwd, "aaa", "2026-05-25T12:00:01.000Z")

	swapResumeListPreflight(t, func(io.Reader, int, io.Writer, int, []sessions.SkippedID, func(int) bool, func(io.Reader, int)) int {
		return 1
	})
	selectorCalled := false
	swapResumeColdStartSelect(t, func([]sessions.ListEntry) (string, bool, error) {
		selectorCalled = true
		return "", false, nil
	})

	steps := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard)
	id, picked, err := steps.ListAndSelect(home, cwd, nil)
	if !errors.Is(err, ErrResumeListPreflight) {
		t.Fatalf("err = %v, want ErrResumeListPreflight", err)
	}
	if picked || id != "" {
		t.Fatalf("got (id=%q, picked=%v), want (\"\", false)", id, picked)
	}
	if selectorCalled {
		t.Fatal("selector opened after a preflight failure")
	}
}

// TestResumeListAndSelect_EnumerateErrorPropagates proves a typed enumeration error
// from ListResumable surfaces unchanged (no preflight, no selector).
func TestResumeListAndSelect_EnumerateErrorPropagates(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("readdir permission failure is not reproducible as root")
	}
	home, cwd := t.TempDir(), t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	subdir, err := sessions.EnsureFolderDir(home, canonical)
	if err != nil {
		t.Fatalf("ensure folder dir: %v", err)
	}
	if err := os.Chmod(subdir, 0o111); err != nil { // execute-only: readdir fails EACCES
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(subdir, 0o755) })

	swapResumeListPreflight(t, func(io.Reader, int, io.Writer, int, []sessions.SkippedID, func(int) bool, func(io.Reader, int)) int {
		t.Fatal("preflight ran despite an enumeration error")
		return 0
	})
	swapResumeColdStartSelect(t, func([]sessions.ListEntry) (string, bool, error) {
		t.Fatal("selector opened despite an enumeration error")
		return "", false, nil
	})

	steps := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard)
	_, _, err = steps.ListAndSelect(home, cwd, nil)
	var ee *sessions.ResumeListEnumerateError
	if !errors.As(err, &ee) {
		t.Fatalf("err = %v, want *sessions.ResumeListEnumerateError", err)
	}
}

// TestResumeListAndSelect_RealPreflightNonTTY exercises the real
// sessions.RunResumeListPreflight (the preflight seam is NOT swapped) through the
// production ListAndSelect: with non-tty in-memory streams it prints the exact
// tty-required line once, returns ErrResumeListPreflight, and never opens the
// selector — proving the producer is genuinely wired, not stubbed.
func TestResumeListAndSelect_RealPreflightNonTTY(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	writeListSession(t, home, cwd, "aaa", "2026-05-25T12:00:01.000Z")

	swapResumeColdStartSelect(t, func([]sessions.ListEntry) (string, bool, error) {
		t.Fatal("selector opened on the non-tty preflight path")
		return "", false, nil
	})

	var stderr strings.Builder
	steps := DefaultResumeSteps(strings.NewReader(""), io.Discard, &stderr)
	id, picked, err := steps.ListAndSelect(home, cwd, nil)
	if !errors.Is(err, ErrResumeListPreflight) {
		t.Fatalf("err = %v, want ErrResumeListPreflight", err)
	}
	if picked || id != "" {
		t.Fatalf("got (id=%q, picked=%v), want (\"\", false)", id, picked)
	}
	want := "codemeld: session list: --resume without an id requires an interactive terminal\n"
	if stderr.String() != want {
		t.Fatalf("stderr = %q, want exactly %q (printed once by the real preflight)", stderr.String(), want)
	}
}

type preflightRecorder struct {
	events []string
	out    strings.Builder
	in     io.Reader
}

func (r *preflightRecorder) Write(p []byte) (int, error) {
	r.events = append(r.events, "write")
	return r.out.Write(p)
}

func (r *preflightRecorder) Read(p []byte) (int, error) {
	n, err := r.in.Read(p)
	r.events = append(r.events, "read:"+strconv.Itoa(n))
	return n, err
}

func swapResumeTerminal(t *testing.T, rec *preflightRecorder, isTTY func(int) bool, makeRawErr error) {
	t.Helper()
	prevTTY, prevRaw, prevRestore := resumeIsTerminal, resumeMakeRaw, resumeRestore
	t.Cleanup(func() { resumeIsTerminal, resumeMakeRaw, resumeRestore = prevTTY, prevRaw, prevRestore })
	resumeIsTerminal = isTTY
	resumeMakeRaw = func(int) (*term.State, error) {
		if makeRawErr != nil {
			rec.events = append(rec.events, "makeraw-failed")
			return nil, makeRawErr
		}
		rec.events = append(rec.events, "makeraw")
		return &term.State{}, nil
	}
	resumeRestore = func(int, *term.State) error {
		rec.events = append(rec.events, "restore")
		return nil
	}
}

func TestResumePreflight_WritesBeforeRawModeAndReadsOneKey(t *testing.T) {
	tests := []struct {
		name       string
		makeRawErr error
		want       []string
	}{
		{"raw mode", nil, []string{"write", "makeraw", "read:1", "restore"}},
		{"make raw fails reads cooked", errors.New("no raw"), []string{"write", "makeraw-failed", "read:1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &preflightRecorder{in: strings.NewReader("xy")}
			swapResumeTerminal(t, rec, func(int) bool { return true }, tt.makeRawErr)

			code := resumePreflight(rec, 0, rec, 2, []sessions.SkippedID{{ID: "alpha"}, {ID: "beta"}})
			if code != 0 {
				t.Fatalf("exit code = %d, want 0", code)
			}
			if !slices.Equal(rec.events, tt.want) {
				t.Fatalf("events = %v, want %v", rec.events, tt.want)
			}
			if !strings.HasSuffix(rec.out.String(), "press any key to continue\n") {
				t.Fatalf("stderr = %q, want the press-any-key prompt last", rec.out.String())
			}
		})
	}
}

func TestResumePreflight_NonTTYSkipsPromptAndRawMode(t *testing.T) {
	tests := []struct {
		name  string
		ttyFd int
	}{
		{"stdin not a tty", 2},
		{"tty stdin with non-tty stderr", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &preflightRecorder{in: strings.NewReader("x")}
			swapResumeTerminal(t, rec, func(fd int) bool { return fd == tt.ttyFd }, nil)

			code := resumePreflight(rec, 0, rec, 2, []sessions.SkippedID{{ID: "alpha"}})
			if code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			if want := []string{"write"}; !slices.Equal(rec.events, want) {
				t.Fatalf("events = %v, want %v (no raw mode, no read)", rec.events, want)
			}
			want := "codemeld: session list: --resume without an id requires an interactive terminal\n"
			if rec.out.String() != want {
				t.Fatalf("stderr = %q, want %q", rec.out.String(), want)
			}
		})
	}
}

func TestResumeRowSecondaryLocalTime(t *testing.T) {
	local := time.Local
	time.Local = time.FixedZone("UTC-4", -4*3600)
	t.Cleanup(func() { time.Local = local })

	e := sessions.ListEntry{
		ID:        "0123456789abcdef",
		StartedAt: time.Date(2026, 5, 28, 9, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 5, 28, 14, 30, 0, 0, time.UTC),
	}
	want := "89abcdef · started 2026-05-28 05:00 · updated 2026-05-28 10:30"
	if got := resumeRowSecondary(e); got != want {
		t.Errorf("resumeRowSecondary = %q, want %q", got, want)
	}
}

// TestResumeRowRendering pins the row projection: last-8-id, both
// timestamps, and the no-preview fallback to the id's last 8 characters.
func TestResumeRowRendering(t *testing.T) {
	local := time.Local
	time.Local = time.UTC
	t.Cleanup(func() { time.Local = local })

	e := sessions.ListEntry{ID: "0123456789abcdef", StartedAt: testStart, UpdatedAt: testStart}
	if got := resumeRowIDShort(e); got != "89abcdef" {
		t.Fatalf("resumeRowIDShort = %q, want 89abcdef", got)
	}
	// No preview (the path does not resolve to a session) → primary falls back to id.
	if got := resumeRowPrimary(e); got != "89abcdef" {
		t.Fatalf("resumeRowPrimary = %q, want 89abcdef (id fallback)", got)
	}
	want := "89abcdef · started 2026-05-28 09:00 · updated 2026-05-28 09:00"
	if got := resumeRowSecondary(e); got != want {
		t.Fatalf("resumeRowSecondary = %q, want %q", got, want)
	}
}

// TestResumeRowPrimaryTitleThenPreview pins the cold-start selector's branch order:
// the scan's first-user-message preview reaches resumeRowPrimary rather than the id
// fallback, and a user title set on the same session overrides that preview the way
// the in-TUI picker's resumeRowTitle does. This guards the resumeRowPrimary →
// sessions.ListResumable wiring that the in-TUI lister test (resumedeps_test.go)
// does not exercise.
func TestResumeRowPrimaryTitleThenPreview(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	userMsg := sessions.Message{
		ID:        ids.NewV7(),
		Role:      "user",
		Content:   sessions.TextContent("hello world"),
		Timestamp: testStart,
	}
	store, err := sessions.EnsureSession(home, canonical, testStart, []sessions.Record{userMsg})
	if err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	mustFlush(t, store)

	entries, _, lerr := sessions.ListResumable(home, cwd)
	if lerr != nil {
		t.Fatalf("list resumable: %v", lerr)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].ID != store.SessionID() {
		t.Fatalf("entry id = %q, want %q", entries[0].ID, store.SessionID())
	}
	if got := resumeRowPrimary(entries[0]); got != "hello world" {
		t.Fatalf("resumeRowPrimary = %q, want %q (preview branch)", got, "hello world")
	}

	if _, terr := sessions.SetTitle(entries[0].Path, "renamed by hand"); terr != nil {
		t.Fatalf("set title: %v", terr)
	}
	titled, _, lerr := sessions.ListResumable(home, cwd)
	if lerr != nil {
		t.Fatalf("list resumable: %v", lerr)
	}
	if len(titled) != 1 {
		t.Fatalf("entries = %d, want 1", len(titled))
	}
	if titled[0].Preview != "hello world" {
		t.Fatalf("Preview = %q, want %q (the title must override a different preview)", titled[0].Preview, "hello world")
	}
	if got := resumeRowPrimary(titled[0]); got != "renamed by hand" {
		t.Fatalf("resumeRowPrimary = %q, want %q (title branch)", got, "renamed by hand")
	}
}

// TestStreamFd proves fd extraction: an *os.File yields its descriptor, an in-memory
// stream yields -1 (the non-tty fallback the headless path relies on).
func TestStreamFd(t *testing.T) {
	if got, want := streamFd(os.Stdin), int(os.Stdin.Fd()); got != want {
		t.Fatalf("streamFd(os.Stdin) = %d, want %d", got, want)
	}
	if got := streamFd(strings.NewReader("")); got != -1 {
		t.Fatalf("streamFd(in-memory reader) = %d, want -1", got)
	}
}

func skippedListIDs(skips []sessions.SkippedID) []string {
	ids := make([]string, len(skips))
	for i, s := range skips {
		ids[i] = s.ID
	}
	return ids
}

func TestResumeRetentionDays(t *testing.T) {
	cases := []struct {
		name   string
		global map[string]any
		want   int
	}{
		{"nil global falls back to default", nil, defaultResumeRetentionDays},
		{"missing sessions key", map[string]any{"other": 1}, defaultResumeRetentionDays},
		{"missing retention_days key", map[string]any{"sessions": map[string]any{}}, defaultResumeRetentionDays},
		{"int value", map[string]any{"sessions": map[string]any{"retention_days": 7}}, 7},
		{"int64 value", map[string]any{"sessions": map[string]any{"retention_days": int64(9)}}, 9},
		{"uint64 value", map[string]any{"sessions": map[string]any{"retention_days": uint64(14)}}, 14},
		{"float64 value", map[string]any{"sessions": map[string]any{"retention_days": float64(14)}}, 14},
		{"wrong type falls back", map[string]any{"sessions": map[string]any{"retention_days": "30"}}, defaultResumeRetentionDays},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resumeRetentionDays(tc.global); got != tc.want {
				t.Errorf("resumeRetentionDays(%v) = %d, want %d", tc.global, got, tc.want)
			}
		})
	}
}

// --- step 2b: the project trust gate on the resume path ---

func TestRunResume_UntrustedProjectComposesFromTheGlobalLayerAlone(t *testing.T) {
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
	global := map[string]any{"agent": map[string]any{"max_concurrency": 2}}

	var order []string
	steps := recordingResumeSteps(&order)
	steps.LoadGlobalSettings = func(string) (map[string]any, error) { return global, nil }
	steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) {
		return projectRoot, []string{projectPath}, nil
	}
	steps.GateTrust = func(string, string, string) trust.Decision {
		return trust.Decision{Reason: trust.ReasonNoRecord, Root: projectRoot}
	}
	steps.ComposeConfig = defaultComposeConfig

	res, err := runResumeWithID(context.Background(), home, "/cwd", "the-id", steps)
	if err != nil {
		t.Fatalf("runResumeWithID error: %v", err)
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
}

func TestRunResume_RetainsTheTrustHandoff(t *testing.T) {
	var order []string
	steps := recordingResumeSteps(&order)
	decision := trust.Decision{Trusted: true, Reason: trust.ReasonTrusted, Root: "/proj"}
	steps.GateTrust = func(string, string, string) trust.Decision {
		return decision
	}

	res, err := runResumeWithID(context.Background(), "/home/u", "/cwd", "the-id", steps)
	if err != nil {
		t.Fatalf("runResumeWithID error: %v", err)
	}
	if res.TrustDecision != decision {
		t.Fatalf("TrustDecision = %#v, want %#v", res.TrustDecision, decision)
	}
}

func TestDefaultResumeSteps_GateTrustDegradesWhenStdinIsNotATerminal(t *testing.T) {
	home := t.TempDir()
	projectRoot := trustProject(t, "model: {}\n")
	var stderr strings.Builder

	steps := DefaultResumeSteps(strings.NewReader("y\n"), io.Discard, &stderr)
	decision := steps.GateTrust(home, projectRoot, projectRoot)

	if decision.Trusted {
		t.Fatalf("decision = %#v, want an untrusted launch", decision)
	}
	if countNotices(stderr.String()) != 1 {
		t.Fatalf("stderr = %q, want exactly one ignored-settings notice", stderr.String())
	}
	trustStoreAbsent(t, home)
}

// The resume mirror of TestRunFresh_DiscoveryFailureCannotBecomeVacuousTrust.
func TestRunResume_DiscoveryFailureCannotBecomeVacuousTrust(t *testing.T) {
	home, base := t.TempDir(), t.TempDir()
	project := filepath.Join(base, "project")
	cwd := filepath.Join(project, "nested")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatalf("mkdir cwd: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(project, ".codemeld", "settings.yaml"), 0o755); err != nil {
		t.Fatalf("mkdir non-regular marker: %v", err)
	}

	var stderr strings.Builder
	production := DefaultResumeSteps(strings.NewReader(""), io.Discard, &stderr)
	var order []string
	steps := recordingResumeSteps(&order)
	steps.LoadGlobalSettings = func(string) (map[string]any, error) {
		return map[string]any{"discovery": map[string]any{"boundary": "project-root"}}, nil
	}
	steps.ResolveProjectRoot = production.ResolveProjectRoot
	steps.GateTrust = production.GateTrust
	steps.ComposeConfig = defaultComposeConfig

	res, err := runResumeWithID(context.Background(), home, cwd, "the-id", steps)
	if err != nil {
		t.Fatalf("runResumeWithID error: %v", err)
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
	trustStoreAbsent(t, home)
}

func TestDefaultResumeSteps_LoadAgentInstructions_UntrustedRepositoryFilesLoad(t *testing.T) {
	f := newAgentsFixture(t)
	store := storeAt(t, filepath.Join(t.TempDir(), "session.json"),
		"01890000-0000-7000-8000-000000002512", f.root)

	writeProjectSettings(t, f.root, "model: {}\n")
	steps := DefaultResumeSteps(strings.NewReader(""), io.Discard, io.Discard)
	if decision := steps.GateTrust(f.home, f.root, f.launch); decision.Trusted {
		t.Fatalf("decision = %#v, want an ungranted project untrusted", decision)
	}

	entries, err := steps.LoadAgentInstructions(context.Background(), store, f.home, f.launch, nil, f.root, nil, agentinstr.Selection{})
	if err != nil {
		t.Fatalf("LoadAgentInstructions: %v", err)
	}

	for _, path := range f.repoFiles() {
		findLoadEntry(t, entries, path)
	}
	want := []string{f.globalPath, f.abovePath, f.rootPath, f.middlePath, f.launchPath}
	var durable []string
	for _, rec := range diskAgentInstr(t, readSessionFile(t, store.Path())) {
		durable = append(durable, rec.Path)
	}
	if !slices.Equal(durable, want) {
		t.Fatalf("durable records = %v, want every discovered file in walk order %v", durable, want)
	}
}

// --- the check-then-load window on the resume path ---

// runResumePostGateRace is the resume mirror of runPostGateRace: the same production gate,
// step-3 adapter, and post-gate replacement window, driven through runResumeWithID.
func runResumePostGateRace(t *testing.T, home, projectRoot, answer string, afterGate func()) postGateRace {
	t.Helper()
	var stderr strings.Builder
	var order []string
	var layer map[string]any
	steps := recordingResumeSteps(&order)
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

	res, err := runResumeWithID(context.Background(), home, projectRoot, "the-id", steps)
	if err != nil {
		t.Fatalf("runResumeWithID: %v", err)
	}
	return postGateRace{res: res, stderr: stderr.String(), projectLayer: layer, approved: approved}
}

// The resume mirror of the fresh vacuous-trust case: a post-gate .codemeld/vcs folder is not
// approved, while a recorded root still loads its templates.
func TestRunResume_VacuousTrustDoesNotApproveAPostGateVCSFolder(t *testing.T) {
	home, projectRoot := t.TempDir(), t.TempDir()

	race := runResumePostGateRace(t, home, projectRoot, "", func() {
		writeVCSFile(t, filepath.Join(projectVCSTemplateDir(projectRoot), "git.yaml"), "name: git\n")
	})

	if race.res.TrustDecision.Reason != trust.ReasonNothingCovered {
		t.Fatalf("TrustDecision = %#v, want the vacuous %q outcome", race.res.TrustDecision, trust.ReasonNothingCovered)
	}
	if race.approved {
		t.Fatal("step-4 approved = true, want a folder no record covers left uncollected")
	}
}

func TestRunResume_RecordedTrustApprovesTheProjectVCSFolder(t *testing.T) {
	home := t.TempDir()
	projectRoot := trustProject(t, raceProjectYAML)
	writeVCSFile(t, filepath.Join(projectVCSTemplateDir(projectRoot), "git.yaml"), "name: git\n")

	race := runResumePostGateRace(t, home, projectRoot, "y\n", func() {})

	if !race.approved {
		t.Fatalf("step-4 approved = false with decision %#v, want a recorded root to load its templates", race.res.TrustDecision)
	}
}

func TestRunResume_VacuousTrustDoesNotAdmitSettingsWrittenAfterTheGate(t *testing.T) {
	home, projectRoot := t.TempDir(), t.TempDir()

	race := runResumePostGateRace(t, home, projectRoot, "", func() {
		writeProjectSettings(t, projectRoot, raceReplacementYAML)
	})

	if race.res.TrustDecision.Reason != trust.ReasonNothingCovered {
		t.Fatalf("TrustDecision = %#v, want the vacuous %q outcome", race.res.TrustDecision, trust.ReasonNothingCovered)
	}
	assertDegradedToGlobalOnly(t, race, home)
	trustStoreAbsent(t, home)
}

func TestRunResume_SettingsChangedAfterTheGateComposeTheBytesOnDisk(t *testing.T) {
	home := t.TempDir()
	projectRoot := trustProject(t, raceProjectYAML)

	race := runResumePostGateRace(t, home, projectRoot, "y\n", func() {
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
	if !race.approved || race.projectLayer == nil {
		t.Fatalf("step-4 approved = %v, project layer = %#v, want the approved launch's composed layer", race.approved, race.projectLayer)
	}
	if countNotices(race.stderr) != 0 {
		t.Fatalf("stderr = %q, want no ignored-settings notice", race.stderr)
	}
}

func TestRunResume_UnchangedTrustedSettingsComposeAsBefore(t *testing.T) {
	home := t.TempDir()
	projectRoot := trustProject(t, raceProjectYAML)

	race := runResumePostGateRace(t, home, projectRoot, "y\n", func() {})

	want := []string{SettingsPath(home), projectSettingsPath(projectRoot)}
	if !slices.Equal(race.res.ConfigLayerPaths, want) {
		t.Fatalf("ConfigLayerPaths = %v, want %v", race.res.ConfigLayerPaths, want)
	}
	agent, _ := race.res.Config["agent"].(map[string]any)
	if fmt.Sprint(agent["max_concurrency"]) != "7" {
		t.Fatalf("agent.max_concurrency = %v, want the project override 7", agent["max_concurrency"])
	}
	if !race.res.TrustDecision.Trusted {
		t.Fatalf("decision = %#v, want the ordinary trusted resume intact", race.res.TrustDecision)
	}
	if race.projectLayer == nil {
		t.Fatal("step-4 project layer = nil, want the verified map handed to attribution")
	}
	if countNotices(race.stderr) != 0 {
		t.Fatalf("stderr = %q, want no ignored-settings notice for matching content", race.stderr)
	}
}

func TestRunResume_UntrustedAtTheGateNeverReadsProjectSettings(t *testing.T) {
	home := t.TempDir()
	projectRoot := trustProject(t, raceProjectYAML)

	race := runResumePostGateRace(t, home, projectRoot, "n\n", func() {
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
	if race.res.TrustDecision.Reason != trust.ReasonNoRecord {
		t.Fatalf("TrustDecision = %#v, want the gate's own %q outcome unchanged", race.res.TrustDecision, trust.ReasonNoRecord)
	}
	if race.projectLayer != nil {
		t.Fatalf("step-4 project layer = %#v, want nil", race.projectLayer)
	}
	if countNotices(race.stderr) != 1 {
		t.Fatalf("stderr = %q, want only the existing gate notice", race.stderr)
	}
}

// resumeTrustFixture stages a cold resume over a real project settings layer, so the handoff
// is built from the same production composition adapter the fresh path uses.
func resumeTrustFixture(t *testing.T, decision trust.Decision, seedProject bool) (ResumeSteps, string, string) {
	t.Helper()
	home, projectRoot := t.TempDir(), t.TempDir()
	projectPath := projectSettingsPath(projectRoot)
	if err := os.MkdirAll(filepath.Dir(projectPath), 0o755); err != nil {
		t.Fatalf("mkdir project settings parent: %v", err)
	}
	if seedProject {
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
	}

	var order []string
	steps := recordingResumeSteps(&order)
	steps.LoadGlobalSettings = func(string) (map[string]any, error) {
		return map[string]any{"agent": map[string]any{"max_concurrency": 2}}, nil
	}
	steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) {
		return projectRoot, []string{projectPath}, nil
	}
	steps.GateTrust = func(string, string, string) trust.Decision {
		return decision
	}
	steps.ComposeConfig = defaultComposeConfig
	return steps, home, projectRoot
}

func TestRunResume_RetainsAdmittedSettingsLayerSnapshots(t *testing.T) {
	steps, home, projectRoot := resumeTrustFixture(t,
		trust.Decision{Trusted: true, Reason: trust.ReasonTrusted}, true)

	res, err := runResumeWithID(context.Background(), home, "/cwd", "the-id", steps)
	if err != nil {
		t.Fatalf("runResumeWithID error: %v", err)
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
		t.Fatalf("project layer permissions = %#v, want the project's own entry", projectLayer.Raw)
	}
}

func TestRunResume_DistinguishesAbsentAndIgnoredProjectLayerState(t *testing.T) {
	t.Run("admitted but absent", func(t *testing.T) {
		steps, home, projectRoot := resumeTrustFixture(t,
			trust.Decision{Trusted: true, Reason: trust.ReasonTrusted}, false)

		res, err := runResumeWithID(context.Background(), home, "/cwd", "the-id", steps)
		if err != nil {
			t.Fatalf("runResumeWithID error: %v", err)
		}
		layer := settingsLayer(t, res, securitystate.LayerProject)
		if layer.Present || layer.Ignored || layer.Path != projectSettingsPath(projectRoot) {
			t.Fatalf("project layer = %#v, want an admitted absent layer that keeps its configured path", layer)
		}
	})

	t.Run("ignored", func(t *testing.T) {
		steps, home, projectRoot := resumeTrustFixture(t, trust.Decision{Reason: trust.ReasonNoRecord}, true)

		res, err := runResumeWithID(context.Background(), home, "/cwd", "the-id", steps)
		if err != nil {
			t.Fatalf("runResumeWithID error: %v", err)
		}
		layer := settingsLayer(t, res, securitystate.LayerProject)
		if !layer.Ignored || layer.Present || layer.Raw != nil {
			t.Fatalf("project layer = %#v, want explicit ignored state carrying no content", layer)
		}
		if _, err := os.Stat(projectSettingsPath(projectRoot) + ".lock"); !os.IsNotExist(err) {
			t.Fatalf("stat ignored sidecar = %v, want a trust-degraded resume never to lock the project path", err)
		}
	})
}

func TestRunResume_CarriesTheTrustHandoffIntoTemplateLoading(t *testing.T) {
	home := t.TempDir()
	projectRoot := trustProject(t, raceProjectYAML)
	writeFullTemplate(t, filepath.Join(projectVCSTemplateDir(projectRoot), "git.yaml"), "git", false, "", "PROJECT")

	race := runResumePostGateRace(t, home, projectRoot, "y\n", func() {})

	assertStep4TrustHandoff(t, race, projectRoot, true)
	if race.res.WithheldInputs != nil {
		t.Fatalf("WithheldInputs = %#v, want nothing withheld", race.res.WithheldInputs)
	}
}

func TestRunResume_RecoveryHonorsAGlobalBlockedPath(t *testing.T) {
	home, project := realPath(t, t.TempDir()), realPath(t, t.TempDir())
	writeGlobalSettings(t, home, blockedYAML(), 0o600)
	target := filepath.Join(project, "a.txt")
	if err := os.WriteFile(target, []byte("ORIGINAL\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	journal := killedChildJournal(t, home, project, target)
	writeGlobalSettings(t, home, blockedYAML(target), 0o600)

	var stderr strings.Builder
	var order []string
	steps := recordingResumeSteps(&order)
	steps.LoadGlobalSettings = func(string) (map[string]any, error) { return defaultLoadGlobalSettings(home) }
	steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) { return project, nil, nil }
	steps.RecoverJournals = func(_, projectRoot string, global map[string]any, decision trust.Decision) {
		DefaultResumeSteps(strings.NewReader(""), io.Discard, &stderr).RecoverJournals(home, projectRoot, global, decision)
	}

	if res, err := runResumeWithID(context.Background(), "/home/u", "/cwd", "the-id", steps); err != nil || res == nil {
		t.Fatalf("resume launch = (%v, %v), want a full launch", res, err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "CHILD\n" {
		t.Fatalf("%s = %q (err=%v), want the blocked file left alone", target, got, err)
	}
	if _, err := os.Stat(filepath.Join(journal, "journal.json")); err != nil {
		t.Fatalf("stat the journal record: %v, want it retained", err)
	}
	if !strings.Contains(stderr.String(), "a blocked path is involved: "+target) {
		t.Fatalf("stderr = %q, want the blocked reason", stderr.String())
	}
}
