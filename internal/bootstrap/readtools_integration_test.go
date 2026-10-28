// End-to-end integration tests for the read-only tools (read, glob, grep, list, tree, file_count)
// driven through the production wiring: the realized production tool registry, the
// production tool dispatcher (DispatchTool → real registry), and the production authorizer with
// the all-mode read-only posture. They pin the integration block — exact-name
// dispatch, auto-allow without a prompt or grant in Build/Auto edits/Plan,
// Plan-mode read-only advertising, the byte-cap truncation
// backstop alongside the per-tool limit, and the dispatch-level edge cases
// (empty dir, no matches, tree depth 0, codemeldignore filtering). They live in
// package bootstrap so they reuse the existing headless production harness (newProductionToolDispatcher,
// newProductionAuthorizer, newTurnController, the provider stubs, and the durable-session helpers)
// without exporting any test-only seam.
package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/turn"
	"codemeld.dev/codemeld/internal/vcs"
)

// readToolsHarness bundles the production seams one read-tools scenario drives: the realized
// production registry (read/glob/grep/list/tree/file_count alongside the built-in edit/create), the
// production dispatcher routing to the real registry, the production authorizer overlaying the
// scenario's interaction mode, the shared grant table, the durable session store the authorizer
// emits to, and a count of how many times the prompt gate was asked to show — which must stay 0
// for every read-only auto-allow.
type readToolsHarness struct {
	dispatcher *productionToolDispatcher
	cache      *config.Cache
	store      *sessions.Store
	gateCalls  *int
}

// newReadToolsHarness assembles the production dispatch+authorization path for one interaction
// mode over cache (whose ProjectRoot must be project). The registry is realized exactly as
// StartTUI realizes it, so the read-only tools are bound to the same home/process cwd/project
// root and tool-output byte cap the production launch binds; the dispatcher and the tools both read
// cache.MaxToolOutputBytes(), so the byte-cap backstop is wired end to end.
func newReadToolsHarness(t *testing.T, project, home string, m mode.Mode, cache *config.Cache) readToolsHarness {
	t.Helper()
	return newReadToolsHarnessWithGate(t, project, home, m, cache, nil)
}

// newReadToolsHarnessWithGate is newReadToolsHarness with a configurable prompt decision: decide is
// invoked for each prompt the gate is asked to show (the external-read scenarios drive both an
// approve and a deny through it), and a nil decide keeps the default allow-once the read-only auto-allow
// scenarios rely on (those never reach the gate, so the default is inert there).
func newReadToolsHarnessWithGate(t *testing.T, project, home string, m mode.Mode, cache *config.Cache, decide func() tui.PromptDecision) readToolsHarness {
	t.Helper()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	gateCalls := 0
	gate := func(tui.PromptRequest) (tui.PromptDecision, error) {
		gateCalls++
		if decide != nil {
			return decide(), nil
		}
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(gate), home, project, mode.NewActiveState(m, mode.SourceConfig))

	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, func() *sessions.Store { return store }, home, project, securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}
	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{})
	return readToolsHarness{dispatcher: d, cache: cache, store: store, gateCalls: &gateCalls}
}

var pngBytes = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDRpixels")

func readToolsProject(t *testing.T) string {
	t.Helper()
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "logo.png"), pngBytes, 0o644); err != nil {
		t.Fatalf("WriteFile png: %v", err)
	}
	return project
}

// readToolCase is one read-only tool's normal successful call against readToolsProject and a
// substring its output must carry, so a single fixture drives every read-only tool by exact name.
type readToolCase struct {
	name     string
	toolName string
	args     map[string]any
	wantSub  string
}

func readToolCases() []readToolCase {
	return []readToolCase{
		{"read", filetools.ReadToolName, map[string]any{"path": "main.go"}, "package main"},
		{"glob", filetools.GlobToolName, map[string]any{"pattern": "*.go"}, "main.go"},
		{"grep", filetools.GrepToolName, map[string]any{"pattern": "package main"}, "main.go"},
		{"list", filetools.ListToolName, map[string]any{}, "main.go"},
		{"tree", filetools.TreeToolName, map[string]any{}, "main.go"},
		{"file_count", filetools.FileCountToolName, map[string]any{}, "total:"},
		{"read_image", filetools.ReadImageToolName, map[string]any{"path": "logo.png"}, "image/png"},
	}
}

// TestReadToolsIntegration_DispatchRoundTripsByExactName pins Done-when 1: each read-only tool
// round-trips through the production dispatcher by its exact registered name and returns a result
// the model reads. A wrong name would surface no_such_tool; a non-read-only classification
// would be denied in some mode — here in Build every read-only tool returns its content.
func TestReadToolsIntegration_DispatchRoundTripsByExactName(t *testing.T) {
	project := readToolsProject(t)
	home := t.TempDir()
	h := newReadToolsHarness(t, project, home, mode.Build, emptyCache(t, project))

	for _, tc := range readToolCases() {
		t.Run(tc.name, func(t *testing.T) {
			res, err := h.dispatcher.Dispatch(context.Background(), structuredCall("c1", tc.toolName, tc.args))
			if err != nil {
				t.Fatalf("Dispatch(%s) error = %v, want nil (an in-band result, never a turn abort)", tc.toolName, err)
			}
			if res.Denied {
				t.Fatalf("Dispatch(%s) denied; content=%q (a read-only tool auto-allows)", tc.toolName, res.Content)
			}
			if !strings.Contains(res.Content, tc.wantSub) {
				t.Fatalf("Dispatch(%s) content = %q, want it to contain %q", tc.toolName, res.Content, tc.wantSub)
			}
		})
	}
}

// TestReadToolsIntegration_AutoAllowedInAllModesNoGrant pins Done-when 2: every read-only tool is
// auto-allowed without prompting and without creating a grant in Build, Auto edits, and Plan,
// recorded as a single durable permission_matched{outcome:"once", outcome_source:"mode_auto"} with
// no grant fields (read-only auto-allow applies in every mode, not only Plan).
func TestReadToolsIntegration_AutoAllowedInAllModesNoGrant(t *testing.T) {
	project := readToolsProject(t)
	home := t.TempDir()

	modes := []struct {
		name string
		m    mode.Mode
	}{
		{"build", mode.Build},
		{"auto_edits", mode.AutoEdits},
		{"plan", mode.Plan},
	}
	for _, md := range modes {
		for _, tc := range readToolCases() {
			t.Run(md.name+"/"+tc.name, func(t *testing.T) {
				h := newReadToolsHarness(t, project, home, md.m, emptyCache(t, project))

				res, err := h.dispatcher.Dispatch(context.Background(), structuredCall("c1", tc.toolName, tc.args))
				if err != nil {
					t.Fatalf("Dispatch error = %v, want nil", err)
				}
				if res.Denied {
					t.Fatalf("%s/%s denied; content=%q (read-only must auto-allow in every mode)", md.name, tc.name, res.Content)
				}
				if *h.gateCalls != 0 {
					t.Fatalf("prompt gate invoked %d times, want 0 (read-only auto-allows without prompting)", *h.gateCalls)
				}

				matched := decodePermissionMatched(t, reloadStore(t, h.store))
				if len(matched) != 1 {
					t.Fatalf("durable permission_matched events = %d, want exactly 1 (the mode auto-allow)", len(matched))
				}
				m := matched[0]
				if m.Outcome != "once" || m.OutcomeSource != "mode_auto" {
					t.Fatalf("permission_matched = %#v, want outcome once / outcome_source mode_auto", m)
				}
				if m.GrantKind != "" || m.GrantPathScope != "" {
					t.Fatalf("mode_auto allow carried grant fields: %#v", m)
				}
				if m.SubjectKind != "tool" || m.Subject != tc.toolName {
					t.Fatalf("permission_matched subject = %s/%s, want tool/%s (matching keys on the exact name)", m.SubjectKind, m.Subject, tc.toolName)
				}
				if got := len(h.cache.Permissions()); got != 0 {
					t.Fatalf("grant table holds %d entries, want 0 (a mode-auto approval creates no grant)", got)
				}
			})
		}
	}
}

// TestReadToolsIntegration_PlanAdvertisesReadOnlyToolsUnderFilter pins Done-when 3: in Plan the
// advertised set is filtered to the read-only registry tools (the navigation tools plus file_count),
// general_agent and bash, with the mutating edit/create dropped, while Build advertises every tool.
func TestReadToolsIntegration_PlanAdvertisesReadOnlyToolsUnderFilter(t *testing.T) {
	project := readToolsProject(t)
	home := t.TempDir()
	cache := emptyCache(t, project)
	store := mkStore(t)

	active := model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5"}, model.SourceProject)
	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, func() *sessions.Store { return store }, home, project, securitystate.Policy{},
		generalAgentTestBinding(active, mode.NewActiveState(mode.Build, mode.SourceDefault)))
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}

	plan := toolNames(advertisedTools(reg, mode.Plan))
	wantPlan := []string{"bash", "file_count", "general_agent", "glob", "grep", "list", "read", "read_image", "suggest_followup", "tree"}
	if !slices.Equal(plan, wantPlan) {
		t.Fatalf("Plan advertised %v, want %v (read-only filter keeps the read-only tools + general_agent + bash + suggest_followup)", plan, wantPlan)
	}
	for _, mutating := range []string{filetools.EditToolName, filetools.CreateToolName, filetools.DeleteToolName, filetools.MkdirToolName, filetools.MoveToolName} {
		if slices.Contains(plan, mutating) {
			t.Fatalf("Plan advertised mutating tool %q under the read-only filter", mutating)
		}
	}

	build := toolNames(advertisedTools(reg, mode.Build))
	wantBuild := []string{"bash", "create", "delete", "edit", "file_count", "general_agent", "glob", "grep", "list", "mkdir", "move", "read", "read_image", "suggest_followup", "tree", "web_fetch", "web_search"}
	if !slices.Equal(build, wantBuild) {
		t.Fatalf("Build advertised %v, want %v (every tool + bash + suggest_followup + the default-on web tools, no read-only filter)", build, wantBuild)
	}

	autoEdits := toolNames(advertisedTools(reg, mode.AutoEdits))
	if !slices.Equal(autoEdits, wantBuild) {
		t.Fatalf("Auto edits advertised %v, want %v (Auto edits advertises every tool like Build, including mutating move)", autoEdits, wantBuild)
	}

	for _, name := range []string{filetools.ReadToolName, filetools.ReadImageToolName, filetools.GlobToolName, filetools.GrepToolName, filetools.ListToolName, filetools.TreeToolName, filetools.FileCountToolName} {
		tool, ok := reg.Lookup(name)
		if !ok {
			t.Fatalf("%s not registered in the realized production registry", name)
		}
		if !tool.Advertise().ReadOnly {
			t.Fatalf("%s advertised mutating, want read-only (the same classification the Plan filter keys on)", name)
		}
	}
}

// TestReadToolsIntegration_ByteCapAndLimitTruncationBothEngage pins Done-when 4: a result far larger
// than the byte cap is byte-truncated yet still carries the truncation indicator intact in the
// model-facing content, and the per-tool limit backstop engages independently of the byte cap.
// The indicator is non-removable because it lives in the separate stderr stream, which the
// byte cap trims independently of stdout — so trimming stdout never strips it.
func TestReadToolsIntegration_ByteCapAndLimitTruncationBothEngage(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	home := t.TempDir()

	t.Run("byte cap backstop trims output but the indicator survives intact", func(t *testing.T) {
		const cap = 256 // the configured minimum, the hardest cap the indicator must still survive
		big := strings.Repeat("A", 2000)
		if err := os.WriteFile(filepath.Join(project, "big.txt"), []byte(big), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		cache, err := config.NewCache(map[string]any{
			"sessions": map[string]any{"max_tool_output_bytes": cap},
		}, project, nil)
		if err != nil {
			t.Fatalf("config.NewCache: %v", err)
		}
		h := newReadToolsHarness(t, project, home, mode.Build, cache)

		res, derr := h.dispatcher.Dispatch(context.Background(), structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "big.txt"}))
		if derr != nil {
			t.Fatalf("Dispatch error = %v", derr)
		}
		if res.Denied {
			t.Fatalf("read denied; content=%q", res.Content)
		}

		stdoutSeg, metaSeg, ok := strings.Cut(res.Content, "\nstderr:\n")
		if !ok {
			t.Fatalf("content = %q, want a trailing stderr metadata segment carrying the indicator", res.Content)
		}
		if len(stdoutSeg) > cap {
			t.Fatalf("model-facing stdout = %d bytes, want <= %d (the byte cap must trim it)", len(stdoutSeg), cap)
		}
		if len(stdoutSeg) >= len(big) {
			t.Fatalf("model-facing stdout = %d bytes, want far less than the %d-byte file (truncation did not engage)", len(stdoutSeg), len(big))
		}
		if !strings.HasPrefix(metaSeg, filetools.MetadataPrefix) {
			t.Fatalf("metadata segment = %q, want it to start with the intact %q indicator prefix", metaSeg, filetools.MetadataPrefix)
		}
		if !strings.Contains(metaSeg, `"truncation_reason":"`+filetools.TruncationReasonByteCap+`"`) {
			t.Fatalf("metadata segment = %q, want the byte_cap truncation reason intact (the byte cap is the harder backstop)", metaSeg)
		}
	})

	t.Run("per-tool limit backstop engages with the byte cap idle", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(project, "lines.txt"), []byte("l1\nl2\nl3\nl4\nl5\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		// Default 65536 cap: the small output never hits the byte cap, so only the per-tool line
		// limit can truncate, proving the two backstops are independent.
		h := newReadToolsHarness(t, project, home, mode.Build, emptyCache(t, project))

		res, derr := h.dispatcher.Dispatch(context.Background(), structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "lines.txt", "limit": 2}))
		if derr != nil {
			t.Fatalf("Dispatch error = %v", derr)
		}
		_, metaSeg, ok := strings.Cut(res.Content, "\nstderr:\n")
		if !ok {
			t.Fatalf("content = %q, want a trailing stderr metadata segment", res.Content)
		}
		if !strings.Contains(metaSeg, `"truncation_reason":"`+filetools.TruncationReasonLimit+`"`) {
			t.Fatalf("metadata segment = %q, want the limit truncation reason (not byte_cap)", metaSeg)
		}
		if !strings.Contains(metaSeg, `"next_offset":3`) {
			t.Fatalf("metadata segment = %q, want next_offset 3 (continuation after the 2-line limit)", metaSeg)
		}
	})
}

// TestReadToolsIntegration_DispatchEdgeCases pins Done-when 5: the cross-tool edge cases reach the
// tools through real dispatch and resolve as non-error empty successes (or correct filtering), never
// in-band rejections — an empty directory (list/tree), no matches (grep/glob), tree depth 0, and the
// codemeldignore filter excluding by default while include_ignored bypasses.
func TestReadToolsIntegration_DispatchEdgeCases(t *testing.T) {
	home := t.TempDir()

	t.Run("empty directory lists and trees as empty success", func(t *testing.T) {
		project, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		h := newReadToolsHarness(t, project, home, mode.Build, emptyCache(t, project))
		for _, name := range []string{filetools.ListToolName, filetools.TreeToolName} {
			res, derr := h.dispatcher.Dispatch(context.Background(), structuredCall("c1", name, map[string]any{}))
			if derr != nil {
				t.Fatalf("%s Dispatch error = %v", name, derr)
			}
			if res.Denied {
				t.Fatalf("%s denied on empty dir; content=%q", name, res.Content)
			}
			if strings.Contains(res.Content, "rejected") {
				t.Fatalf("%s on empty dir = %q, want a non-error empty success", name, res.Content)
			}
			if !strings.Contains(res.Content, `"truncated":false`) {
				t.Fatalf("%s on empty dir = %q, want the not-truncated metadata indicator", name, res.Content)
			}
		}
	})

	t.Run("no matches greps and globs as empty success", func(t *testing.T) {
		project, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		if err := os.WriteFile(filepath.Join(project, "a.txt"), []byte("hello\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		h := newReadToolsHarness(t, project, home, mode.Build, emptyCache(t, project))
		cases := []struct {
			name string
			args map[string]any
		}{
			{filetools.GrepToolName, map[string]any{"pattern": "no_such_text_zzz"}},
			{filetools.GlobToolName, map[string]any{"pattern": "**/*.nomatch"}},
		}
		for _, c := range cases {
			res, derr := h.dispatcher.Dispatch(context.Background(), structuredCall("c1", c.name, c.args))
			if derr != nil {
				t.Fatalf("%s Dispatch error = %v", c.name, derr)
			}
			if res.Denied {
				t.Fatalf("%s denied; content=%q", c.name, res.Content)
			}
			if strings.Contains(res.Content, "rejected") {
				t.Fatalf("%s no-match = %q, want a non-error empty success", c.name, res.Content)
			}
			if !strings.Contains(res.Content, `"truncated":false`) {
				t.Fatalf("%s no-match = %q, want the not-truncated metadata indicator", c.name, res.Content)
			}
		}
	})

	t.Run("tree depth 0 yields no entries", func(t *testing.T) {
		project, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		if err := os.WriteFile(filepath.Join(project, "a.txt"), []byte("x\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(project, "sub"), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		h := newReadToolsHarness(t, project, home, mode.Build, emptyCache(t, project))
		res, derr := h.dispatcher.Dispatch(context.Background(), structuredCall("c1", filetools.TreeToolName, map[string]any{"depth": 0}))
		if derr != nil {
			t.Fatalf("tree Dispatch error = %v", derr)
		}
		if res.Denied {
			t.Fatalf("tree depth 0 denied; content=%q", res.Content)
		}
		if strings.Contains(res.Content, "a.txt") || strings.Contains(res.Content, "sub") {
			t.Fatalf("tree depth 0 = %q, want no entries under the root", res.Content)
		}
		if !strings.Contains(res.Content, `"truncated":false`) {
			t.Fatalf("tree depth 0 = %q, want the not-truncated metadata indicator", res.Content)
		}
	})

	t.Run("codemeldignore excludes by default and include_ignored bypasses", func(t *testing.T) {
		project, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		// A separate empty home means no global codemeldignore, so only the project file contributes.
		ciHome := t.TempDir()
		if err := os.MkdirAll(filepath.Join(project, ".codemeld"), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filetools.ProjectCodemeldignorePath(project), []byte("secret.txt\n"), 0o644); err != nil {
			t.Fatalf("write codemeldignore: %v", err)
		}
		if err := os.WriteFile(filepath.Join(project, "secret.txt"), []byte("classified\n"), 0o644); err != nil {
			t.Fatalf("WriteFile secret: %v", err)
		}
		if err := os.WriteFile(filepath.Join(project, "keep.txt"), []byte("public\n"), 0o644); err != nil {
			t.Fatalf("WriteFile keep: %v", err)
		}
		h := newReadToolsHarness(t, project, ciHome, mode.Build, emptyCache(t, project))

		def, derr := h.dispatcher.Dispatch(context.Background(), structuredCall("c1", filetools.ListToolName, map[string]any{}))
		if derr != nil {
			t.Fatalf("list Dispatch error = %v", derr)
		}
		if strings.Contains(def.Content, "secret.txt") {
			t.Fatalf("list default = %q, want codemeldignore to exclude secret.txt", def.Content)
		}
		if !strings.Contains(def.Content, "keep.txt") {
			t.Fatalf("list default = %q, want the non-ignored keep.txt present", def.Content)
		}

		inc, derr := h.dispatcher.Dispatch(context.Background(), structuredCall("c2", filetools.ListToolName, map[string]any{"include_ignored": true}))
		if derr != nil {
			t.Fatalf("list include_ignored Dispatch error = %v", derr)
		}
		if !strings.Contains(inc.Content, "secret.txt") {
			t.Fatalf("list include_ignored = %q, want the ignored secret.txt surfaced", inc.Content)
		}
	})
}

// TestReadToolsIntegration_ExternalReadPromptsInEveryModeThenReads is the external-read Terminal test
// driven through the full production wiring (realized registry → production dispatcher → production
// authorizer → prompt gate): an EXPLICIT out-of-project path for each read-only tool is no longer
// refused before authorization — it reaches the permission prompt in Build, Auto edits, AND Plan, and
// only reads after approval. A denial blocks it with the standard denial result and leaks no
// out-of-project content.
func TestReadToolsIntegration_ExternalReadPromptsInEveryModeThenReads(t *testing.T) {
	project := readToolsProject(t)
	home := t.TempDir()
	ext, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ext, "ext.txt"), []byte("external-canary\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// extCase returns the registered name, the out-of-project arguments, and a substring the approved
	// output must carry for one tool. read names the external file; the directory tools name the external
	// dir (with the canary file's name as the success marker).
	extCase := func(name string) (string, map[string]any, string) {
		switch name {
		case "read":
			return filetools.ReadToolName, map[string]any{"path": filepath.Join(ext, "ext.txt")}, "external-canary"
		case "glob":
			return filetools.GlobToolName, map[string]any{"pattern": "*.txt", "path": ext}, "ext.txt"
		case "grep":
			return filetools.GrepToolName, map[string]any{"pattern": "external-canary", "path": ext}, "ext.txt"
		case "list":
			return filetools.ListToolName, map[string]any{"path": ext}, "ext.txt"
		case "file_count":
			// file_count reports a count, not file names, so the success marker is the count
			// header rather than the canary file name.
			return filetools.FileCountToolName, map[string]any{"path": ext}, "total:"
		default: // tree
			return filetools.TreeToolName, map[string]any{"path": ext}, "ext.txt"
		}
	}
	names := []string{"read", "glob", "grep", "list", "tree", "file_count"}
	modes := []struct {
		name string
		m    mode.Mode
	}{{"build", mode.Build}, {"auto_edits", mode.AutoEdits}, {"plan", mode.Plan}}

	approveOnce := func() tui.PromptDecision { return tui.PromptDecision{Option: tui.OptionAllowOnce} }
	for _, md := range modes {
		for _, tn := range names {
			t.Run("approve/"+md.name+"/"+tn, func(t *testing.T) {
				toolName, args, wantSub := extCase(tn)
				h := newReadToolsHarnessWithGate(t, project, home, md.m, emptyCache(t, project), approveOnce)
				res, derr := h.dispatcher.Dispatch(context.Background(), structuredCall("c1", toolName, args))
				if derr != nil {
					t.Fatalf("Dispatch error = %v, want nil", derr)
				}
				if *h.gateCalls != 1 {
					t.Fatalf("prompt gate calls = %d, want 1 (an explicit external read must prompt in %s)", *h.gateCalls, md.name)
				}
				if res.Denied {
					t.Fatalf("res.Denied = true after approval; content=%q", res.Content)
				}
				if !strings.Contains(res.Content, wantSub) {
					t.Fatalf("content = %q, want it to contain %q (the approved external read)", res.Content, wantSub)
				}
			})
		}
	}

	denyPrompt := func() tui.PromptDecision {
		return tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope("user denied")}
	}
	for _, tn := range names {
		t.Run("deny/"+tn, func(t *testing.T) {
			toolName, args, _ := extCase(tn)
			h := newReadToolsHarnessWithGate(t, project, home, mode.Build, emptyCache(t, project), denyPrompt)
			res, derr := h.dispatcher.Dispatch(context.Background(), structuredCall("c1", toolName, args))
			if derr != nil {
				t.Fatalf("Dispatch error = %v, want nil (a denied read is in-band)", derr)
			}
			if *h.gateCalls != 1 {
				t.Fatalf("prompt gate calls = %d, want 1 (a denied external read still prompts)", *h.gateCalls)
			}
			if !res.Denied {
				t.Fatalf("res.Denied = false, want a denied external read; content=%q", res.Content)
			}
			if strings.Contains(res.Content, "external-canary") {
				t.Fatalf("content = %q, leaked out-of-project content on denial", res.Content)
			}
		})
	}
}

// TestReadToolsIntegration_ReadCallRoundTripsThroughProductionTurn pins the production turn path:
// the model issues a read tool call, the real turn controller's loop dispatches it through the
// production dispatcher to the real read tool, records the verbatim content, and re-issues to a
// final answer — with the mode-filtered advertised set carrying the read-only tools on every
// round and the read auto-allow recorded as a single durable mode_auto/once with no grant. This is
// the end-to-end statement only fully make through newTurnController.
func TestReadToolsIntegration_ReadCallRoundTripsThroughProductionTurn(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	home := t.TempDir()

	var perRound [][]string
	var round int32
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		perRound = append(perRound, toolNames(req.Tools))
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", filetools.ReadToolName, `{"path":"main.go"}`)))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := providerCache(t, project)
	modeActive := mode.NewActiveState(mode.Build, mode.SourceDefault)

	gateCalls := 0
	gate := func(tui.PromptRequest) (tui.PromptDecision, error) {
		gateCalls++
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(gate), home, project, modeActive)
	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, func() *sessions.Store { return store }, home, project, securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}

	ctl := newTurnController(ctx, &recordingSurface{}, cache, turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, auth)
	ctl.setToolAdvertiser(newToolAdvertiser(reg, modeActive))
	ctl.setToolDispatcher(newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if gateCalls != 0 {
		t.Fatalf("prompt gate invoked %d times, want 0 (read auto-allows in Build)", gateCalls)
	}

	if len(perRound) != 2 {
		t.Fatalf("provider rounds = %d, want 2 (tool-call round + continuation)", len(perRound))
	}
	want := []string{"bash", "create", "delete", "edit", "file_count", "glob", "grep", "list", "mkdir", "move", "read", "read_image", "suggest_followup", "tree", "web_fetch", "web_search"}
	for i, got := range perRound {
		if !slices.Equal(got, want) {
			t.Fatalf("round %d advertised %v, want %v (Build advertises every tool on each round)", i, got, want)
		}
	}

	reloaded := reloadStore(t, store)
	toolMsgs := messagesByRole(reloaded, "tool")
	if len(toolMsgs) != 1 || toolMsgs[0].ToolCallID != "call_1" {
		t.Fatalf("durable tool messages = %+v, want one for call_1", toolMsgs)
	}
	if !strings.Contains(toolMsgs[0].Content.Text(), "package main") {
		t.Fatalf("tool message = %q, want the verbatim read content", toolMsgs[0].Content.Text())
	}
	asst := messagesByRole(reloaded, "assistant")
	if len(asst) == 0 || asst[len(asst)-1].Content.Text() != "done" {
		t.Fatalf("final assistant message = %+v, want the loop to re-issue to %q", asst, "done")
	}

	matched := decodePermissionMatched(t, reloaded)
	if len(matched) != 1 || matched[0].Outcome != "once" || matched[0].OutcomeSource != "mode_auto" {
		t.Fatalf("permission_matched = %+v, want exactly one mode_auto/once", matched)
	}
	if got := len(cache.Permissions()); got != 0 {
		t.Fatalf("grant table holds %d entries, want 0 (a mode-auto approval creates no grant)", got)
	}
}

func TestReadToolsIntegration_ImageReadRoundTripsThroughProductionTurn(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	project := readToolsProject(t)
	home := t.TempDir()
	wantURI := "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes)

	var round int32
	var round2Req provider.Request
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", filetools.ReadImageToolName, `{"path":"logo.png"}`)))}, nil
		}
		round2Req = req
		return provider.Response{Stream: newStream(contentChunk("seen"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := providerCache(t, project)
	modeActive := mode.NewActiveState(mode.Build, mode.SourceDefault)

	gate := func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(gate), home, project, modeActive)
	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, func() *sessions.Store { return store }, home, project, securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}

	ctl := newTurnController(ctx, &recordingSurface{}, cache, turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, auth)
	ctl.setToolAdvertiser(newToolAdvertiser(reg, modeActive))
	ctl.setToolDispatcher(newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if atomic.LoadInt32(&round) != 2 {
		t.Fatalf("provider rounds = %d, want 2 (image tool-call round + continuation)", round)
	}

	reloaded := reloadStore(t, store)

	toolMsgs := messagesByRole(reloaded, "tool")
	if len(toolMsgs) != 1 || toolMsgs[0].ToolCallID != "call_1" {
		t.Fatalf("durable tool messages = %+v, want one for call_1", toolMsgs)
	}
	if !strings.Contains(toolMsgs[0].Content.Text(), "image/png") {
		t.Fatalf("tool message = %q, want the bounded image metadata", toolMsgs[0].Content.Text())
	}
	if strings.Contains(toolMsgs[0].Content.Text(), "data:") || strings.Contains(toolMsgs[0].Content.Text(), "base64") {
		t.Fatalf("tool message = %q, leaked a data URI into normal tool stdout", toolMsgs[0].Content.Text())
	}

	mc := messagesByRole(reloaded, "model_context")
	if len(mc) != 1 || !mc[0].Content.IsList() {
		t.Fatalf("durable model_context messages = %+v, want one image_url list", mc)
	}
	parts := mc[0].Content.Parts()
	if len(parts) != 1 || parts[0].Type != "image_url" || !strings.Contains(string(parts[0].Raw), wantURI) {
		t.Fatalf("model_context parts = %+v, want one image_url part carrying the data URI", parts)
	}
	if users := messagesByRole(reloaded, "user"); len(users) != 0 {
		t.Fatalf("durable user messages = %d, want 0 (the image must not fabricate a user turn)", len(users))
	}

	var sawImage bool
	for _, m := range round2Req.Messages {
		if m.Role != "user" {
			continue
		}
		for _, p := range m.Parts {
			if p.Type == "image_url" && p.ImageURL == wantURI {
				sawImage = true
			}
		}
	}
	if !sawImage {
		t.Fatalf("follow-up request messages carried no image_url part with the selected image; messages = %+v", round2Req.Messages)
	}
}

// Delay only the invocation so overlap has a measurable interval.
type gatedReadTool struct {
	*filetools.ReadTool
	probe         *overlapProbe
	waitForPrompt <-chan struct{}
	waitForRead   <-chan struct{}
	onInvoke      func(string)
	afterInvoke   func(string, tools.Result, error)
}

func (t *gatedReadTool) InvokeWithResolvedTarget(ctx context.Context, args map[string]any, resolvedTarget string) (tools.Result, error) {
	if t.waitForPrompt != nil {
		select {
		case <-t.waitForPrompt:
		case <-ctx.Done():
			return tools.Result{}, ctx.Err()
		}
	}
	if t.onInvoke != nil {
		t.onInvoke(resolvedTarget)
	}
	if t.waitForRead != nil {
		select {
		case <-t.waitForRead:
		case <-ctx.Done():
			return tools.Result{}, ctx.Err()
		}
	}
	t.probe.enter()
	defer t.probe.exit()
	res, err := t.ReadTool.InvokeWithResolvedTarget(ctx, args, resolvedTarget)
	if t.afterInvoke != nil {
		t.afterInvoke(resolvedTarget, res, err)
	}
	return res, err
}

type probedCreateTool struct {
	*filetools.CreateTool
	probe *overlapProbe
}

func (t *probedCreateTool) InvokeWithResolvedTarget(ctx context.Context, args map[string]any, resolvedTarget string) (tools.Result, error) {
	t.probe.enter()
	defer t.probe.exit()
	return t.CreateTool.InvokeWithResolvedTarget(ctx, args, resolvedTarget)
}

// The embedded tool's own method would otherwise be promoted and dispatch would reach it directly,
// leaving the create sibling unprobed and the overlap check unable to fail.
func (t *probedCreateTool) InvokeWithAuthorizedScope(ctx context.Context, args map[string]any, resolvedTarget string, scope string, scopeIdentity filetools.ScopeIdentity) (tools.Result, error) {
	t.probe.enter()
	defer t.probe.exit()
	return t.CreateTool.InvokeWithAuthorizedScope(ctx, args, resolvedTarget, scope, scopeIdentity)
}

type probedVCSTool struct {
	*vcs.ActionTool
	probe *overlapProbe
}

func (t *probedVCSTool) InvokeWithEffectiveCWD(ctx context.Context, args map[string]any, resolvedCwd string, cwdErr error) (tools.Result, error) {
	t.probe.enter()
	defer t.probe.exit()
	return t.ActionTool.InvokeWithEffectiveCWD(ctx, args, resolvedCwd, cwdErr)
}

type promptProbe struct {
	mu    sync.Mutex
	live  int
	peak  int
	shown int

	force     map[string]bool
	store     *sessions.Store
	whileHeld func(*sessions.Store)
	opened    chan struct{}
}

func (p *promptProbe) show(tui.PromptRequest) (tui.PromptDecision, error) {
	p.mu.Lock()
	p.shown++
	p.live++
	if p.live > p.peak {
		p.peak = p.live
	}
	first := p.shown == 1
	p.mu.Unlock()
	if first && p.opened != nil {
		close(p.opened)
	}
	if first && p.whileHeld != nil {
		p.whileHeld(p.store)
	} else {
		time.Sleep(10 * time.Millisecond)
	}
	p.mu.Lock()
	p.live--
	p.mu.Unlock()
	return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
}

// Forcing the external-read posture is the only way an in-project read reaches the prompt gate,
// which the mode auto-allow would otherwise resolve without one.
type promptForcingAuthorizer struct {
	dispatch.Authorizer
	force map[string]bool
}

func (a promptForcingAuthorizer) Authorize(ctx context.Context, req permissions.MatchRequest, disp dispatch.PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error) {
	if a.force[req.Subject] {
		modeCtx.ExternalRead = true
	}
	return a.Authorizer.Authorize(ctx, req, disp, modeCtx)
}

type siblingOutcomeAuthorizer struct {
	dispatch.Authorizer
	subjectTarget     string
	siblingTarget     string
	waitForSibling    <-chan struct{}
	releaseSibling    chan<- struct{}
	err               error
	denied            bool
	siblingAuthorized atomic.Bool
}

func (a *siblingOutcomeAuthorizer) Authorize(ctx context.Context, req permissions.MatchRequest, disp dispatch.PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error) {
	if modeCtx.TargetPath == a.subjectTarget {
		select {
		case <-a.waitForSibling:
		case <-ctx.Done():
			return permissions.Decision{}, ctx.Err()
		}
		go func() {
			time.Sleep(30 * time.Millisecond)
			close(a.releaseSibling)
		}()
		if a.denied {
			return permissions.Decision{DenyEnvelope: permissions.BuildDenyEnvelope("blocked")}, nil
		}
		if a.err != nil {
			return permissions.Decision{}, a.err
		}
	}
	decision, err := a.Authorizer.Authorize(ctx, req, disp, modeCtx)
	if modeCtx.TargetPath == a.siblingTarget && err == nil && decision.DenyEnvelope == "" {
		a.siblingAuthorized.Store(true)
	}
	return decision, err
}

func (p *promptProbe) counts() (shown, peak int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.shown, p.peak
}

func concurrentReadCache(t *testing.T, projectRoot string, maxConcurrency int) *config.Cache {
	t.Helper()
	globalSettings := SettingsPath(t.TempDir())
	seedOpenAIDiscovered(t, globalSettings, "gpt-5.5", "gpt-5.5-pro")
	cache, err := config.NewCache(map[string]any{
		"provider": map[string]any{"openai": map[string]any{
			"base_url": "https://api.openai.com/v1", "api_key": "sk-test",
		}},
		"agent": map[string]any{"max_concurrency": maxConcurrency},
	}, projectRoot, []string{globalSettings})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	return cache
}

type gatedReadTurnConfig struct {
	active         any
	instrumentTool string
	wrapAuthorizer func(dispatch.Authorizer) dispatch.Authorizer
	wrapDispatcher func(turn.ToolDispatcher) turn.ToolDispatcher
	configureRead  func(*gatedReadTool)
	configureTools func(*testing.T, *tools.Registry)
	waitForRead    <-chan struct{}
}

func gatedReadRegistry(t *testing.T, cache *config.Cache, home, project string, store *sessions.Store, probe *overlapProbe, waitForPrompt <-chan struct{}, cfg gatedReadTurnConfig) *tools.Registry {
	t.Helper()
	reg, err := (&toolRegistryFactory{active: cfg.active}).realize(cache, func() *sessions.Store { return store }, home, project, securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}
	read := &gatedReadTool{ReadTool: filetools.NewReadTool(home, project, project, cache.MaxToolOutputBytes()), probe: probe, waitForPrompt: waitForPrompt, waitForRead: cfg.waitForRead}
	if cfg.configureRead != nil {
		cfg.configureRead(read)
	}
	if err := reg.Register("test-gated-read", read); err != nil {
		t.Fatalf("replace production read tool: %v", err)
	}
	if cfg.instrumentTool != "" {
		instrumentMixedBatchTool(t, reg, probe, cfg.instrumentTool)
	}
	if cfg.configureTools != nil {
		cfg.configureTools(t, reg)
	}
	return reg
}

func instrumentMixedBatchTool(t *testing.T, reg *tools.Registry, probe *overlapProbe, name string) {
	t.Helper()
	tool, ok := reg.Lookup(name)
	if !ok {
		t.Fatalf("registered %s tool missing", name)
	}

	var wrapped tools.Tool
	switch name {
	case filetools.CreateToolName:
		create, ok := tool.(*filetools.CreateTool)
		if !ok {
			t.Fatalf("registered create tool = %T, want *filetools.CreateTool", tool)
		}
		wrapped = &probedCreateTool{CreateTool: create, probe: probe}
	case "vcs_status":
		status, ok := tool.(*vcs.ActionTool)
		if !ok {
			t.Fatalf("registered vcs_status tool = %T, want *vcs.ActionTool", tool)
		}
		wrapped = &probedVCSTool{ActionTool: status, probe: probe}
	default:
		t.Fatalf("unsupported mixed-batch instrumented tool %q", name)
	}
	if err := reg.Register("test-mixed-batch-probe", wrapped); err != nil {
		t.Fatalf("replace production %s tool: %v", name, err)
	}
}

type gatedReadTurnResult struct {
	elapsed  time.Duration
	reloaded *sessions.Store
	err      error
}

func runGatedReadTurn(t *testing.T, project, home string, maxConcurrency int, probe *overlapProbe, prompts *promptProbe, frags ...string) gatedReadTurnResult {
	t.Helper()
	res := runConfiguredGatedReadTurn(t, project, home, maxConcurrency, probe, prompts, gatedReadTurnConfig{}, frags...)
	if res.err != nil {
		t.Fatalf("dispatch error = %v", res.err)
	}
	return res
}

func runConfiguredGatedReadTurn(t *testing.T, project, home string, maxConcurrency int, probe *overlapProbe, prompts *promptProbe, cfg gatedReadTurnConfig, frags ...string) gatedReadTurnResult {
	t.Helper()
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var round int32
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(frags...))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := concurrentReadCache(t, project, maxConcurrency)
	modeActive := mode.NewActiveState(mode.Build, mode.SourceDefault)
	prompts.store = store
	var auth dispatch.Authorizer = newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(prompts.show), home, project, modeActive)
	if len(prompts.force) > 0 {
		auth = promptForcingAuthorizer{Authorizer: auth, force: prompts.force}
	}
	if cfg.wrapAuthorizer != nil {
		auth = cfg.wrapAuthorizer(auth)
	}
	reg := gatedReadRegistry(t, cache, home, project, store, probe, prompts.opened, cfg)

	ctl := newTurnController(ctx, &recordingSurface{}, cache, turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, auth)
	ctl.setToolAdvertiser(newToolAdvertiser(reg, modeActive))
	var dispatcher turn.ToolDispatcher = newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{})
	if cfg.wrapDispatcher != nil {
		dispatcher = cfg.wrapDispatcher(dispatcher)
	}
	ctl.setToolDispatcher(dispatcher)

	started := time.Now()
	err := ctl.dispatch(store, time.Time{})
	turns.Wait()
	elapsed := time.Since(started)

	return gatedReadTurnResult{elapsed: elapsed, reloaded: reloadStore(t, store), err: err}
}

func readFixtures(t *testing.T, project string, n int) []string {
	t.Helper()
	return readFixturesFrom(t, project, 0, n)
}

// Assembly restores model-call order by tool-call index, so a fixture that must run after another
// call has to carry the later index — prepending its fragment is not enough.
func readFixturesFrom(t *testing.T, project string, first, n int) []string {
	t.Helper()
	frags := make([]string, n)
	for i := range n {
		name := fmt.Sprintf("f%d.go", first+i)
		if err := os.WriteFile(filepath.Join(project, name), []byte(fmt.Sprintf("package f%d\n", first+i)), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		frags[i] = toolFrag(first+i, fmt.Sprintf("call_%d", first+i), filetools.ReadToolName, fmt.Sprintf(`{"path":%q}`, name))
	}
	return frags
}

// Each bound is the appending record's own timestamp, paired by invocation id. Reconstructing the
// start as end-minus-duration_ms instead would round every span to whole milliseconds and so could
// invent or erase an overlap; duration_ms is for elapsed-time reporting only.
func structuredReadIntervals(t *testing.T, store *sessions.Store) map[string][2]time.Time {
	t.Helper()
	began := map[string]time.Time{}
	for _, ev := range kindEvents(t, store, events.KindStructuredReadStart) {
		var start events.StructuredReadStart
		if err := json.Unmarshal(ev.Payload, &start); err != nil {
			t.Fatalf("decode structured_read_start: %v", err)
		}
		began[start.InvocationID] = ev.Timestamp
	}
	out := map[string][2]time.Time{}
	for _, ev := range kindEvents(t, store, events.KindStructuredReadEnd) {
		var end events.StructuredReadEnd
		if err := json.Unmarshal(ev.Payload, &end); err != nil {
			t.Fatalf("decode structured_read_end: %v", err)
		}
		start, ok := began[end.InvocationID]
		if !ok {
			t.Fatalf("structured_read_end %q has no matching start", end.InvocationID)
		}
		out[end.InvocationID] = [2]time.Time{start, ev.Timestamp}
	}
	return out
}

func countOverlappingIntervals(intervals map[string][2]time.Time) int {
	var spans [][2]time.Time
	for _, span := range intervals {
		spans = append(spans, span)
	}
	pairs := 0
	for i := range spans {
		for j := i + 1; j < len(spans); j++ {
			if spans[i][0].Before(spans[j][1]) && spans[j][0].Before(spans[i][1]) {
				pairs++
			}
		}
	}
	return pairs
}

func structuredReadStarts(t *testing.T, store *sessions.Store) []events.StructuredReadStart {
	t.Helper()
	return decodeStoreEvents[events.StructuredReadStart](t, store, events.KindStructuredReadStart)
}

func structuredReadEnds(t *testing.T, store *sessions.Store) []events.StructuredReadEnd {
	t.Helper()
	return decodeStoreEvents[events.StructuredReadEnd](t, store, events.KindStructuredReadEnd)
}

func TestReadToolsIntegration_ConcurrentDispatchEvidence(t *testing.T) {
	project := readToolsProject(t)
	frags := readFixtures(t, project, 3)
	probe := newHoldingProbe(3, 5*time.Second, 30*time.Millisecond)
	prompts := &promptProbe{}

	res := runGatedReadTurn(t, project, t.TempDir(), 3, probe, prompts, frags...)

	if got := probe.peakLive(); got != 3 {
		t.Fatalf("peak concurrent reads = %d, want 3 (all three met inside the barrier)", got)
	}
	if shown, _ := prompts.counts(); shown != 0 {
		t.Fatalf("prompts shown = %d, want 0 (in-project reads auto-allow in Build)", shown)
	}

	toolMsgs := messagesByRole(res.reloaded, "tool")
	if len(toolMsgs) != 3 {
		t.Fatalf("durable tool messages = %d, want 3", len(toolMsgs))
	}
	for i, m := range toolMsgs {
		if want := fmt.Sprintf("call_%d", i); m.ToolCallID != want {
			t.Fatalf("tool message %d answers %q, want %q (results persist in model-call order)", i, m.ToolCallID, want)
		}
		if want := fmt.Sprintf("package f%d", i); !strings.HasPrefix(m.Content.Text(), want) {
			t.Fatalf("tool message %d = %q, want the content of %s", i, m.Content.Text(), want)
		}
	}

	starts := structuredReadStarts(t, res.reloaded)
	ends := structuredReadEnds(t, res.reloaded)
	if len(starts) != 3 || len(ends) != 3 {
		t.Fatalf("durable structured_read events = %d start/%d end, want 3/3", len(starts), len(ends))
	}
	startsByID := map[string]events.StructuredReadStart{}
	for _, start := range starts {
		if !ids.IsValidV7(start.InvocationID) {
			t.Fatalf("start invocation_id = %q, want a fresh UUIDv7 per invocation", start.InvocationID)
		}
		if _, exists := startsByID[start.InvocationID]; exists {
			t.Fatalf("duplicate start invocation_id = %q", start.InvocationID)
		}
		startsByID[start.InvocationID] = start
		if start.ToolName != filetools.ReadToolName || start.PathScope != project {
			t.Fatalf("start record = %+v, want the exact tool name and the resolved in-project scope %q", start, project)
		}
		if start.ConfiguredConcurrency != 3 {
			t.Fatalf("start configured_concurrency = %d, want the configured 3", start.ConfiguredConcurrency)
		}
	}
	endsByID := map[string]events.StructuredReadEnd{}
	for _, end := range ends {
		start, ok := startsByID[end.InvocationID]
		if !ok {
			t.Fatalf("end record %+v pairs with no start", end)
		}
		if _, exists := endsByID[end.InvocationID]; exists {
			t.Fatalf("duplicate end invocation_id = %q", end.InvocationID)
		}
		endsByID[end.InvocationID] = end
		if end.ToolName != start.ToolName {
			t.Fatalf("paired tool names = %q/%q, want identical names", start.ToolName, end.ToolName)
		}
		if end.Outcome != structuredReadOutcomeSuccess || end.DurationMs <= 0 {
			t.Fatalf("end record = %+v, want a success with a measured duration", end)
		}
	}
	if len(endsByID) != len(startsByID) {
		t.Fatalf("durable paired invocations = %d, want %d", len(endsByID), len(startsByID))
	}
	kinds := eventKinds(res.reloaded.Records())
	startsSeen := 0
	for _, kind := range kinds {
		switch kind {
		case events.KindStructuredReadStart:
			startsSeen++
		case events.KindStructuredReadEnd:
			if startsSeen != len(starts) {
				t.Fatalf("event order = %v, want every start appended before any end could be", kinds)
			}
		}
	}

	if pairs := countOverlappingIntervals(structuredReadIntervals(t, res.reloaded)); pairs != 3 {
		t.Fatalf("overlapping durable intervals = %d, want all 3 pairs to overlap", pairs)
	}
	if res.elapsed <= 0 {
		t.Fatalf("turn elapsed = %v, want a measured wall-clock total", res.elapsed)
	}
}

const (
	lifetimeEligible = "eligible"
	lifetimeExcluded = "excluded"
)

type lifetimeSpan struct {
	kind  string
	id    string
	start time.Time
	end   time.Time
}

// lifetimeProbe records each planned unit's whole Run lifetime, which starts before the delegated
// production closure reaches authorization. gatedReadTool's hold begins only after authorization,
// so it cannot show an excluded call overlapping an eligible one while it waits at a permission
// prompt; this can.
type lifetimeProbe struct {
	mu        sync.Mutex
	spans     []lifetimeSpan
	live      map[string]int
	collision string
}

func newLifetimeProbe() *lifetimeProbe {
	return &lifetimeProbe{live: map[string]int{}}
}

func (p *lifetimeProbe) enter(kind, id string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	other := lifetimeExcluded
	if kind == lifetimeExcluded {
		other = lifetimeEligible
	}
	if p.live[other] > 0 && p.collision == "" {
		p.collision = fmt.Sprintf("%s call %q started while %d %s call(s) were still running", kind, id, p.live[other], other)
	}
	p.live[kind]++
	p.spans = append(p.spans, lifetimeSpan{kind: kind, id: id, start: time.Now()})
	return len(p.spans) - 1
}

func (p *lifetimeProbe) exit(i int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.spans[i].end = time.Now()
	p.live[p.spans[i].kind]--
}

func (p *lifetimeProbe) assertNoCollision(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.collision != "" {
		t.Fatalf("excluded and eligible lifetimes overlapped: %s", p.collision)
	}
}

func (p *lifetimeProbe) span(t *testing.T, id string) lifetimeSpan {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, sp := range p.spans {
		if sp.id == id {
			return sp
		}
	}
	t.Fatalf("no recorded lifetime for call %q", id)
	return lifetimeSpan{}
}

// A resettable two-party rendezvous. Only the read tool holds under overlapProbe, so a segment's
// grep or glob sibling can finish microseconds before the read's goroutine is even scheduled; the
// pair meets here instead, making the recorded spans overlap without depending on start skew. The
// timeout keeps a genuinely serialized segment failing its assertion rather than hanging.
type segmentGate struct {
	mu      sync.Mutex
	pending chan struct{}
	timeout time.Duration
}

func (g *segmentGate) meet() {
	g.mu.Lock()
	if waiting := g.pending; waiting != nil {
		g.pending = nil
		g.mu.Unlock()
		close(waiting)
		return
	}
	mine := make(chan struct{})
	g.pending = mine
	g.mu.Unlock()
	select {
	case <-mine:
	case <-time.After(g.timeout):
		g.mu.Lock()
		if g.pending == mine {
			g.pending = nil
		}
		g.mu.Unlock()
	}
}

type lifetimeInstrumentedDispatcher struct {
	turn.ToolDispatcher
	probe *lifetimeProbe
	gate  *segmentGate
}

func (d lifetimeInstrumentedDispatcher) Plan(calls []turn.AssembledToolCall, maxConcurrency int) turn.ToolPlan {
	plan := d.ToolDispatcher.Plan(calls, maxConcurrency)
	for i := range plan.Units {
		kind := lifetimeEligible
		if slices.Contains(plan.Units[i].Targets, productionToolDispatchTarget) {
			kind = lifetimeExcluded
		}
		id, run := plan.Units[i].Call.ID, plan.Units[i].Run
		plan.Units[i].Run = func(ctx context.Context) (turn.ToolResult, error) {
			span := d.probe.enter(kind, id)
			defer d.probe.exit(span)
			if d.gate != nil && kind == lifetimeEligible {
				d.gate.meet()
			}
			return run(ctx)
		}
	}
	return plan
}

func instrumentLifetimes(probe *lifetimeProbe) func(turn.ToolDispatcher) turn.ToolDispatcher {
	return func(inner turn.ToolDispatcher) turn.ToolDispatcher {
		return lifetimeInstrumentedDispatcher{ToolDispatcher: inner, probe: probe}
	}
}

func instrumentPairedLifetimes(probe *lifetimeProbe, timeout time.Duration) func(turn.ToolDispatcher) turn.ToolDispatcher {
	gate := &segmentGate{timeout: timeout}
	return func(inner turn.ToolDispatcher) turn.ToolDispatcher {
		return lifetimeInstrumentedDispatcher{ToolDispatcher: inner, probe: probe, gate: gate}
	}
}

// The production dependency graph cannot produce a collision, so the guard's two branches are
// unreachable through a real turn and are covered here directly.
func TestLifetimeProbe_GuardRejectsEitherOrderOfCollision(t *testing.T) {
	for _, tc := range []struct{ first, second string }{
		{lifetimeExcluded, lifetimeEligible},
		{lifetimeEligible, lifetimeExcluded},
	} {
		t.Run(tc.first+" then "+tc.second, func(t *testing.T) {
			probe := newLifetimeProbe()
			held := probe.enter(tc.first, "held")
			probe.enter(tc.second, "intruder")
			probe.exit(held)
			if probe.collision == "" {
				t.Fatalf("collision = %q, want the guard to reject a %s call starting inside a live %s call", probe.collision, tc.second, tc.first)
			}
		})
	}

	probe := newLifetimeProbe()
	probe.exit(probe.enter(lifetimeEligible, "a"))
	probe.exit(probe.enter(lifetimeExcluded, "b"))
	probe.assertNoCollision(t)
}

func TestReadToolsIntegration_ExcludedCallNeverOverlapsAnEligibleSegment(t *testing.T) {
	cases := []struct {
		name           string
		excludedBefore bool
		hold           bool
	}{
		{"excluded call after the eligible segment", false, false},
		{"excluded call before the eligible segment", true, false},
		{"excluded call held at its permission prompt after the eligible segment", false, true},
		{"excluded call held at its permission prompt before the eligible segment", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project := readToolsProject(t)
			outside, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatalf("EvalSymlinks: %v", err)
			}
			external := filepath.Join(outside, "secret.txt")
			if err := os.WriteFile(external, []byte("external\n"), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			firstRead, excludedIndex := 0, 5
			if tc.excludedBefore {
				firstRead, excludedIndex = 1, 0
			}
			reads := readFixturesFrom(t, project, firstRead, 5)
			excluded := toolFrag(excludedIndex, "call_ext", filetools.ReadToolName, fmt.Sprintf(`{"path":%q}`, external))
			frags := append(reads, excluded)
			if tc.excludedBefore {
				frags = append([]string{excluded}, reads...)
			}

			probe := newHoldingProbe(5, 5*time.Second, 30*time.Millisecond)
			prompts := &promptProbe{}
			if tc.hold {
				prompts.whileHeld = func(*sessions.Store) { time.Sleep(60 * time.Millisecond) }
			}
			lifetimes := newLifetimeProbe()

			res := runConfiguredGatedReadTurn(t, project, t.TempDir(), 5, probe, prompts,
				gatedReadTurnConfig{wrapDispatcher: instrumentLifetimes(lifetimes)}, frags...)
			if res.err != nil {
				t.Fatalf("dispatch error = %v", res.err)
			}

			lifetimes.assertNoCollision(t)
			if got := probe.peakLive(); got != 5 {
				t.Fatalf("peak concurrent reads = %d, want the five eligible reads to meet inside the barrier", got)
			}
			starts := structuredReadStarts(t, res.reloaded)
			ends := structuredReadEnds(t, res.reloaded)
			if len(starts) != 5 || len(ends) != 5 {
				t.Fatalf("durable structured_read events = %d start/%d end, want 5/5 (the excluded read emits neither)", len(starts), len(ends))
			}
			refusals := decodeStoreEvents[events.StructuredReadRefused](t, res.reloaded, events.KindStructuredReadRefused)
			if len(refusals) != 1 || refusals[0].Reason != structuredReadRefusalOutOfProject {
				t.Fatalf("structured_read_refused = %#v, want one %q refusal", refusals, structuredReadRefusalOutOfProject)
			}
			if refusals[0].BatchSize != 6 {
				t.Fatalf("batch_size = %d, want the complete planned-call count 6", refusals[0].BatchSize)
			}
			if pairs := countOverlappingIntervals(structuredReadIntervals(t, res.reloaded)); pairs != 10 {
				t.Fatalf("overlapping durable intervals = %d, want all 10 pairs of the five-read segment", pairs)
			}
			if shown, _ := prompts.counts(); shown != 1 {
				t.Fatalf("prompts shown = %d, want 1 (only the out-of-project read prompts)", shown)
			}
		})
	}
}

func TestReadToolsIntegration_BarrierSeparatesEligibleSegments(t *testing.T) {
	project := readToolsProject(t)
	readFixtures(t, project, 3)
	frags := []string{
		toolFrag(0, "call_a", filetools.ReadToolName, `{"path":"f0.go"}`),
		toolFrag(1, "call_b", filetools.GrepToolName, `{"pattern":"package f1"}`),
		toolFrag(2, "call_c", filetools.EditToolName, `{"path":"f1.go","old_text":"package f1","new_text":"package f1edited"}`),
		toolFrag(3, "call_d", filetools.ReadToolName, `{"path":"f2.go"}`),
		toolFrag(4, "call_e", filetools.GlobToolName, `{"pattern":"*.go"}`),
	}
	probe := newHoldingProbe(1, time.Millisecond, 50*time.Millisecond)
	lifetimes := newLifetimeProbe()

	res := runConfiguredGatedReadTurn(t, project, t.TempDir(), 4, probe, &promptProbe{},
		gatedReadTurnConfig{wrapDispatcher: instrumentPairedLifetimes(lifetimes, 5*time.Second)}, frags...)
	if res.err != nil {
		t.Fatalf("dispatch error = %v", res.err)
	}

	lifetimes.assertNoCollision(t)
	a, b := lifetimes.span(t, "call_a"), lifetimes.span(t, "call_b")
	c := lifetimes.span(t, "call_c")
	d, e := lifetimes.span(t, "call_d"), lifetimes.span(t, "call_e")
	if !a.start.Before(b.end) || !b.start.Before(a.end) {
		t.Fatalf("read A %v-%v and grep B %v-%v did not overlap, want one concurrent segment", a.start, a.end, b.start, b.end)
	}
	if c.start.Before(a.end) || c.start.Before(b.end) {
		t.Fatalf("edit C started at %v, want it after the first segment drained (A %v, B %v)", c.start, a.end, b.end)
	}
	if d.start.Before(c.end) || e.start.Before(c.end) {
		t.Fatalf("second segment started at %v/%v, want it after edit C returned at %v", d.start, e.start, c.end)
	}
	if !d.start.Before(e.end) || !e.start.Before(d.end) {
		t.Fatalf("read D %v-%v and glob E %v-%v did not overlap, want one concurrent segment", d.start, d.end, e.start, e.end)
	}

	toolMsgs := messagesByRole(res.reloaded, "tool")
	if len(toolMsgs) != 5 {
		t.Fatalf("durable tool messages = %d, want 5", len(toolMsgs))
	}
	for i, want := range []string{"call_a", "call_b", "call_c", "call_d", "call_e"} {
		if toolMsgs[i].ToolCallID != want {
			t.Fatalf("tool message %d answers %q, want %q (results persist in model-call order)", i, toolMsgs[i].ToolCallID, want)
		}
	}
	if n := len(structuredReadStarts(t, res.reloaded)); n != 4 {
		t.Fatalf("structured_read_start events = %d, want 4 (every call but the edit)", n)
	}
}

func TestReadToolsIntegration_CapOneKeepsAPartitionedBatchSequential(t *testing.T) {
	project := readToolsProject(t)
	readFixtures(t, project, 3)
	frags := []string{
		toolFrag(0, "call_a", filetools.ReadToolName, `{"path":"f0.go"}`),
		toolFrag(1, "call_b", filetools.ReadToolName, `{"path":"f1.go"}`),
		toolFrag(2, "call_c", filetools.CreateToolName, `{"path":"made.go","content":"package made\n"}`),
		toolFrag(3, "call_d", filetools.ReadToolName, `{"path":"f2.go"}`),
	}
	probe := newHoldingProbe(2, 20*time.Millisecond, 20*time.Millisecond)
	lifetimes := newLifetimeProbe()

	res := runConfiguredGatedReadTurn(t, project, t.TempDir(), 1, probe, &promptProbe{},
		gatedReadTurnConfig{wrapDispatcher: instrumentLifetimes(lifetimes)}, frags...)
	if res.err != nil {
		t.Fatalf("dispatch error = %v", res.err)
	}

	lifetimes.assertNoCollision(t)
	if got := probe.peakLive(); got != 1 {
		t.Fatalf("peak concurrent reads at cap 1 = %d, want 1", got)
	}
	if pairs := countOverlappingIntervals(structuredReadIntervals(t, res.reloaded)); pairs != 0 {
		t.Fatalf("overlapping durable intervals at cap 1 = %d, want 0", pairs)
	}
	for _, start := range structuredReadStarts(t, res.reloaded) {
		if start.ConfiguredConcurrency != 1 {
			t.Fatalf("start configured_concurrency = %d, want 1", start.ConfiguredConcurrency)
		}
	}
}

// A create tool that also runs sideEffect, so a barrier can change what a later eligible read's
// path resolves to — the case plan-time preparation cannot see.
type mutatingBarrierCreateTool struct {
	*filetools.CreateTool
	sideEffect func()
}

func (t *mutatingBarrierCreateTool) InvokeWithResolvedTarget(ctx context.Context, args map[string]any, resolvedTarget string) (tools.Result, error) {
	res, err := t.CreateTool.InvokeWithResolvedTarget(ctx, args, resolvedTarget)
	if t.sideEffect != nil {
		t.sideEffect()
	}
	return res, err
}

// The embedded tool's own method would otherwise be promoted and dispatch would reach it directly,
// leaving the barrier's side effect unfired.
func (t *mutatingBarrierCreateTool) InvokeWithAuthorizedScope(ctx context.Context, args map[string]any, resolvedTarget string, scope string, scopeIdentity filetools.ScopeIdentity) (tools.Result, error) {
	res, err := t.CreateTool.InvokeWithAuthorizedScope(ctx, args, resolvedTarget, scope, scopeIdentity)
	if t.sideEffect != nil {
		t.sideEffect()
	}
	return res, err
}

func replaceCreateTool(sideEffect func()) func(*testing.T, *tools.Registry) {
	return func(t *testing.T, reg *tools.Registry) {
		t.Helper()
		tool, ok := reg.Lookup(filetools.CreateToolName)
		if !ok {
			t.Fatal("registered create tool missing")
		}
		create, ok := tool.(*filetools.CreateTool)
		if !ok {
			t.Fatalf("registered create tool = %T, want *filetools.CreateTool", tool)
		}
		if err := reg.Register("test-mutating-barrier", &mutatingBarrierCreateTool{CreateTool: create, sideEffect: sideEffect}); err != nil {
			t.Fatalf("replace production create tool: %v", err)
		}
	}
}

func TestReadToolsIntegration_EligibleReadResolvesAfterAMutatingBarrier(t *testing.T) {
	// The read's own path is what must be re-resolved, so each barrier changes what that path
	// resolves to rather than what the plan-time target holds: dispatching the plan-time prepared
	// target would answer the call and leave a structured_read_start behind.
	t.Run("create", func(t *testing.T) {
		project := readToolsProject(t)
		outside, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("CANARY\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		frags := []string{
			toolFrag(0, "call_create", filetools.CreateToolName, `{"path":"made.go","content":"package made\n"}`),
			toolFrag(1, "call_read", filetools.ReadToolName, `{"path":"swap.txt"}`),
		}
		created := func() {
			if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(project, "swap.txt")); err != nil {
				t.Errorf("Symlink: %v", err)
			}
		}
		res := runConfiguredGatedReadTurn(t, project, t.TempDir(), 3, newHoldingProbe(1, time.Millisecond, 0), &promptProbe{},
			gatedReadTurnConfig{configureTools: replaceCreateTool(created)}, frags...)
		assertMutatingBarrierFailsClosed(t, res, "CANARY")
	})

	t.Run("remove", func(t *testing.T) {
		project := readToolsProject(t)
		target := filepath.Join(project, "target.txt")
		if err := os.WriteFile(target, []byte("package target\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := os.Symlink(target, filepath.Join(project, "link.txt")); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		frags := []string{
			toolFrag(0, "call_create", filetools.CreateToolName, `{"path":"made.go","content":"package made\n"}`),
			toolFrag(1, "call_read", filetools.ReadToolName, `{"path":"link.txt"}`),
		}
		removed := func() {
			if err := os.Remove(target); err != nil {
				t.Errorf("Remove: %v", err)
			}
		}
		res := runConfiguredGatedReadTurn(t, project, t.TempDir(), 3, newHoldingProbe(1, time.Millisecond, 0), &promptProbe{},
			gatedReadTurnConfig{configureTools: replaceCreateTool(removed)}, frags...)
		assertMutatingBarrierFailsClosed(t, res, "package target")
	})

	t.Run("symlink retarget fails closed", func(t *testing.T) {
		project := readToolsProject(t)
		outside, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("CANARY\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		swap := filepath.Join(project, "swap.txt")
		if err := os.WriteFile(swap, []byte("in project\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		frags := []string{
			toolFrag(0, "call_create", filetools.CreateToolName, `{"path":"made.go","content":"package made\n"}`),
			toolFrag(1, "call_read", filetools.ReadToolName, `{"path":"swap.txt"}`),
		}
		retarget := func() {
			if err := os.Remove(swap); err != nil {
				t.Errorf("Remove: %v", err)
				return
			}
			if err := os.Symlink(filepath.Join(outside, "secret.txt"), swap); err != nil {
				t.Errorf("Symlink: %v", err)
			}
		}
		res := runConfiguredGatedReadTurn(t, project, t.TempDir(), 3, newHoldingProbe(1, time.Millisecond, 0), &promptProbe{},
			gatedReadTurnConfig{configureTools: replaceCreateTool(retarget)}, frags...)
		assertMutatingBarrierFailsClosed(t, res, "CANARY")
	})

	t.Run("retarget within the project resolves to the post-barrier target", func(t *testing.T) {
		project := readToolsProject(t)
		for _, dir := range []string{"before", "after"} {
			if err := os.Mkdir(filepath.Join(project, dir), 0o755); err != nil {
				t.Fatalf("Mkdir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(project, dir, "content.txt"), []byte(strings.ToUpper(dir)+" TARGET\n"), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
		}
		swap := filepath.Join(project, "swap.txt")
		if err := os.Symlink(filepath.Join(project, "before", "content.txt"), swap); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		frags := []string{
			toolFrag(0, "call_create", filetools.CreateToolName, `{"path":"made.go","content":"package made\n"}`),
			toolFrag(1, "call_read", filetools.ReadToolName, `{"path":"swap.txt"}`),
		}
		retarget := func() {
			if err := os.Remove(swap); err != nil {
				t.Errorf("Remove: %v", err)
				return
			}
			if err := os.Symlink(filepath.Join(project, "after", "content.txt"), swap); err != nil {
				t.Errorf("Symlink: %v", err)
			}
		}
		res := runConfiguredGatedReadTurn(t, project, t.TempDir(), 3, newHoldingProbe(1, time.Millisecond, 0), &promptProbe{},
			gatedReadTurnConfig{configureTools: replaceCreateTool(retarget)}, frags...)
		if res.err != nil {
			t.Fatalf("dispatch error = %v", res.err)
		}
		toolMsgs := messagesByRole(res.reloaded, "tool")
		if len(toolMsgs) != 2 || toolMsgs[1].ToolCallID != "call_read" {
			t.Fatalf("durable tool messages = %#v, want the create barrier then call_read", toolMsgs)
		}
		if got := toolMsgs[1].Content.Text(); !strings.Contains(got, "AFTER TARGET") || strings.Contains(got, "BEFORE TARGET") {
			t.Fatalf("read result = %q, want the content of the target selected after the barrier", got)
		}
		starts := structuredReadStarts(t, res.reloaded)
		if len(starts) != 1 {
			t.Fatalf("structured_read_start events = %d, want 1", len(starts))
		}
		if want := filepath.Join(project, "after"); starts[0].PathScope != want {
			t.Fatalf("structured_read_start path_scope = %q, want %q (the scope resolved after the barrier)", starts[0].PathScope, want)
		}
	})
}

func assertMutatingBarrierFailsClosed(t *testing.T, res gatedReadTurnResult, absent string) {
	t.Helper()
	terminals := decodeStoreEvents[events.TurnTerminal](t, res.reloaded, events.KindTurnTerminal)
	if len(terminals) != 1 || terminals[0].Outcome != events.TurnOutcomeDispatchFailed {
		t.Fatalf("turn_terminal = %#v, want one %q outcome (a read that no longer qualifies after the barrier must fail closed)", terminals, events.TurnOutcomeDispatchFailed)
	}
	for _, rec := range res.reloaded.Records() {
		if msg, ok := rec.(sessions.Message); ok && strings.Contains(msg.Content.Text(), absent) {
			t.Fatalf("pre-barrier content reached the session: %q", msg.Content.Text())
		}
	}
	refusals := decodeStoreEvents[events.StructuredReadRefused](t, res.reloaded, events.KindStructuredReadRefused)
	if len(refusals) != 1 || refusals[0].ToolName != filetools.CreateToolName {
		t.Fatalf("structured_read_refused = %#v, want only the planning-time refusal of the create barrier", refusals)
	}
	if n := len(structuredReadStarts(t, res.reloaded)); n != 0 {
		t.Fatalf("structured_read_start events = %d, want 0 (dispatching the plan-time prepared target would have started a read)", n)
	}
}

var cpuProbeSink atomic.Uint64

func spinCPU() {
	var acc uint64
	for i := uint64(0); i < 30_000_000; i++ {
		acc = acc*1664525 + 1013904223 + i
	}
	cpuProbeSink.Add(acc)
}

// runtime.NumCPU reports visible cores, not sustained entitlement: a throttled or contended runner
// can report four and deliver one. Timing one unit of work against four concurrent copies of the
// same unit tells those apart without depending on anything under test.
func sustainsFourWayParallelism() bool {
	start := time.Now()
	spinCPU()
	one := time.Since(start)

	start = time.Now()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); spinCPU() }()
	}
	wg.Wait()
	return time.Since(start) < 2*one
}

func grepCorpus(t *testing.T) string {
	t.Helper()
	project := readToolsProject(t)
	line := strings.Repeat("the quick brown fox jumps over the lazy dog ", 12) + "\n"
	body := strings.Repeat(line, 40)
	for i := range 250 {
		if err := os.WriteFile(filepath.Join(project, fmt.Sprintf("corpus%03d.txt", i)), []byte(body), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	return project
}

// Reads complete below the recorded millisecond resolution, so only searches can show the cap in
// wall-clock time. This corroborates the deterministic interval-overlap assertions; it never
// replaces them.
func TestReadToolsIntegration_SearchesRunFasterAtAHigherCap(t *testing.T) {
	if runtime.NumCPU() < 4 {
		t.Skip("fewer than four visible cores; a cap-4 run cannot overlap four searches here")
	}
	if !sustainsFourWayParallelism() {
		t.Skip("machine cannot sustain four concurrent CPU units; the cap comparison would measure scheduling, not overlap")
	}
	project := grepCorpus(t)
	frags := make([]string, 4)
	for i := range frags {
		frags[i] = toolFrag(i, fmt.Sprintf("call_%d", i), filetools.GrepToolName,
			fmt.Sprintf(`{"pattern":"zzz-no-match-%d"}`, i))
	}

	run := func(maxConcurrency int) time.Duration {
		probe := newHoldingProbe(1, time.Millisecond, 0)
		res := runGatedReadTurn(t, project, t.TempDir(), maxConcurrency, probe, &promptProbe{}, frags...)
		if n := len(structuredReadEnds(t, res.reloaded)); n != len(frags) {
			t.Fatalf("durable structured_read_end events at cap %d = %d, want %d", maxConcurrency, n, len(frags))
		}
		return res.elapsed
	}
	serial := run(1)
	concurrent := run(4)
	if concurrent >= serial*3/4 {
		t.Fatalf("elapsed at cap 4 = %v, want materially below the sequential %v over the same corpus", concurrent, serial)
	}
}

func TestReadToolsIntegration_MixedBatchPartitions(t *testing.T) {
	cases := []struct {
		name      string
		sibling   func(project string) string
		configure func(project string) gatedReadTurnConfig
	}{
		{"shell", func(string) string { return toolFrag(9, "call_9", "bash", `{"command":"echo hi"}`) }, nil},
		{"read_image", func(string) string {
			return toolFrag(9, "call_9", filetools.ReadImageToolName, `{"path":"logo.png"}`)
		}, nil},
		{"unknown name", func(string) string {
			return toolFrag(9, "call_9", "read_file", `{"path":"f0.go"}`)
		}, nil},
		{"malformed arguments", func(string) string {
			return toolFrag(9, "call_9", filetools.ReadToolName, `{"path":`)
		}, nil},
		{"mutating", func(string) string {
			return toolFrag(9, "call_9", filetools.CreateToolName, `{"path":"created.go","content":"package created\n"}`)
		}, func(string) gatedReadTurnConfig { return gatedReadTurnConfig{instrumentTool: filetools.CreateToolName} }},
		{"VCS", func(string) string {
			return toolFrag(9, "call_9", "vcs_status", `{}`)
		}, func(project string) gatedReadTurnConfig {
			return gatedReadTurnConfig{active: &ActiveVCS{Template: &vcs.Template{
				Name:    "git",
				Source:  "test",
				Actions: map[string]vcs.ActionSpec{"status": {Argv: []string{"printf", "vcs status"}}},
			}, RepoRoot: project}, instrumentTool: "vcs_status"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project := readToolsProject(t)
			frags := append(readFixtures(t, project, 2), tc.sibling(project))
			probe := newHoldingProbe(2, 20*time.Millisecond, 20*time.Millisecond)
			cfg := gatedReadTurnConfig{}
			if tc.configure != nil {
				cfg = tc.configure(project)
			}

			lifetimes := newLifetimeProbe()
			cfg.wrapDispatcher = instrumentLifetimes(lifetimes)

			res := runConfiguredGatedReadTurn(t, project, t.TempDir(), 3, probe, &promptProbe{}, cfg, frags...)
			if res.err != nil {
				t.Fatalf("dispatch error = %v", res.err)
			}

			lifetimes.assertNoCollision(t)
			if got := probe.peakLive(); got != 2 {
				t.Fatalf("peak concurrent calls = %d, want the two eligible reads to overlap beside a %s sibling", got, tc.name)
			}
			if n := len(structuredReadStarts(t, res.reloaded)); n != 2 {
				t.Fatalf("structured_read_start events = %d, want 2 (only the %s sibling is excluded)", n, tc.name)
			}
			if n := len(structuredReadEnds(t, res.reloaded)); n != 2 {
				t.Fatalf("structured_read_end events = %d, want 2", n)
			}
			toolMsgs := messagesByRole(res.reloaded, "tool")
			if len(toolMsgs) != 3 {
				t.Fatalf("durable tool messages = %d, want 3 (every call still answered)", len(toolMsgs))
			}
			for i, want := range []string{"call_0", "call_1", "call_9"} {
				if toolMsgs[i].ToolCallID != want {
					t.Fatalf("tool message %d answers %q, want %q (input order preserved)", i, toolMsgs[i].ToolCallID, want)
				}
			}
		})
	}
}

func TestReadToolsIntegration_ConcurrentDispatchOutcomesKeepSiblingsIndependent(t *testing.T) {
	cases := []struct {
		name        string
		subjectPath string
		err         error
		denied      bool
		outcome     string
	}{
		{"tool failure", "missing.go", nil, false, structuredReadOutcomeToolFailure},
		{"denial", "subject.go", nil, true, structuredReadOutcomeDenied},
		{"cancellation", "subject.go", context.Canceled, false, structuredReadOutcomeCancelled},
		{"internal failure", "subject.go", errors.New("prompt surface failed"), false, structuredReadOutcomeInternalFailure},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project := readToolsProject(t)
			if err := os.WriteFile(filepath.Join(project, "subject.go"), []byte("package subject\n"), 0o644); err != nil {
				t.Fatalf("WriteFile subject: %v", err)
			}
			if err := os.WriteFile(filepath.Join(project, "sibling.go"), []byte("package sibling\n"), 0o644); err != nil {
				t.Fatalf("WriteFile sibling: %v", err)
			}
			subjectTarget := filepath.Join(project, tc.subjectPath)
			siblingTarget := filepath.Join(project, "sibling.go")
			siblingStarted := make(chan struct{})
			releaseSibling := make(chan struct{})
			auth := &siblingOutcomeAuthorizer{
				subjectTarget:  subjectTarget,
				siblingTarget:  siblingTarget,
				waitForSibling: siblingStarted,
				releaseSibling: releaseSibling,
				err:            tc.err,
				denied:         tc.denied,
			}
			var siblingResult tools.Result
			var siblingErr error
			cfg := gatedReadTurnConfig{
				waitForRead: releaseSibling,
				wrapAuthorizer: func(inner dispatch.Authorizer) dispatch.Authorizer {
					auth.Authorizer = inner
					return auth
				},
				configureRead: func(read *gatedReadTool) {
					read.onInvoke = func(target string) {
						if target == siblingTarget {
							close(siblingStarted)
						}
					}
					read.afterInvoke = func(target string, result tools.Result, err error) {
						if target == siblingTarget {
							siblingResult = result
							siblingErr = err
						}
					}
				},
			}
			frags := []string{
				toolFrag(0, "call_subject", filetools.ReadToolName, fmt.Sprintf(`{"path":%q}`, tc.subjectPath)),
				toolFrag(1, "call_sibling", filetools.ReadToolName, `{"path":"sibling.go"}`),
			}
			res := runConfiguredGatedReadTurn(t, project, t.TempDir(), 2, newHoldingProbe(1, time.Second, 0), &promptProbe{}, cfg, frags...)

			if res.err != nil {
				t.Fatalf("dispatch error = %v, want nil", res.err)
			}
			if !auth.siblingAuthorized.Load() {
				t.Fatal("sibling authorization did not complete")
			}
			if siblingErr != nil || !strings.HasPrefix(string(siblingResult.Stdout), "package sibling") {
				t.Fatalf("sibling result = (%q, %v), want successful sibling content", siblingResult.Stdout, siblingErr)
			}

			starts := structuredReadStarts(t, res.reloaded)
			ends := structuredReadEnds(t, res.reloaded)
			if len(starts) != 2 || len(ends) != 2 {
				t.Fatalf("structured_read events = %d start/%d end, want 2/2", len(starts), len(ends))
			}
			startsByID := map[string]events.StructuredReadStart{}
			for _, start := range starts {
				if _, exists := startsByID[start.InvocationID]; exists {
					t.Fatalf("duplicate start invocation_id = %q", start.InvocationID)
				}
				startsByID[start.InvocationID] = start
			}
			endsByID := map[string]events.StructuredReadEnd{}
			outcomes := map[string]int{}
			for _, end := range ends {
				start, ok := startsByID[end.InvocationID]
				if !ok || start.ToolName != end.ToolName {
					t.Fatalf("end record %+v has no matching start", end)
				}
				if _, exists := endsByID[end.InvocationID]; exists {
					t.Fatalf("duplicate end invocation_id = %q", end.InvocationID)
				}
				endsByID[end.InvocationID] = end
				outcomes[end.Outcome]++
			}
			if len(endsByID) != len(startsByID) {
				t.Fatalf("paired invocation count = %d, want %d", len(endsByID), len(startsByID))
			}
			if outcomes[tc.outcome] != 1 || outcomes[structuredReadOutcomeSuccess] != 1 {
				t.Fatalf("durable outcomes = %v, want one %q and one success", outcomes, tc.outcome)
			}
		})
	}
}

func TestReadToolsIntegration_MaxConcurrencyAndElapsed(t *testing.T) {
	const hold = 200 * time.Millisecond
	elapsed := map[int]time.Duration{}
	for _, maxConcurrency := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("cap %d", maxConcurrency), func(t *testing.T) {
			project := readToolsProject(t)
			frags := readFixtures(t, project, 3)
			probe := newHoldingProbe(len(frags)+1, time.Millisecond, hold)

			res := runGatedReadTurn(t, project, t.TempDir(), maxConcurrency, probe, &promptProbe{}, frags...)
			elapsed[maxConcurrency] = res.elapsed

			if got := probe.peakLive(); got != maxConcurrency {
				t.Fatalf("peak concurrent reads = %d, want exactly the configured %d", got, maxConcurrency)
			}
			starts := structuredReadStarts(t, res.reloaded)
			if len(starts) != 3 {
				t.Fatalf("durable starts = %d, want 3", len(starts))
			}
			for _, start := range starts {
				if int(start.ConfiguredConcurrency) != maxConcurrency {
					t.Fatalf("start configured_concurrency = %d, want the configured %d", start.ConfiguredConcurrency, maxConcurrency)
				}
			}
			pairs := countOverlappingIntervals(structuredReadIntervals(t, res.reloaded))
			if maxConcurrency == 1 && pairs != 0 {
				t.Fatalf("overlapping durable intervals at cap 1 = %d, want 0 (cap 1 is sequential)", pairs)
			}
			if maxConcurrency > 1 && pairs == 0 {
				t.Fatalf("overlapping durable intervals at cap %d = 0, want the reconstructed evidence to show overlap alongside the %v elapsed", maxConcurrency, res.elapsed)
			}
		})
	}
	if elapsed[3] >= elapsed[1]/2 {
		t.Fatalf("elapsed at cap 3 = %v, want materially below the sequential %v over the same fixture", elapsed[3], elapsed[1])
	}
}

func TestReadToolsIntegration_PromptGateIsolation(t *testing.T) {
	project := readToolsProject(t)
	frags := readFixtures(t, project, 1)
	for i, name := range []string{"outside_a.txt", "outside_b.txt"} {
		// Separate directories prevent the first turn-scoped approval covering the second read.
		outside, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		path := filepath.Join(outside, name)
		if err := os.WriteFile(path, []byte("external "+name+"\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		frags = append(frags, toolFrag(i+1, fmt.Sprintf("call_ext_%d", i), filetools.ReadToolName, fmt.Sprintf(`{"path":%q}`, path)))
	}
	probe := newHoldingProbe(2, 20*time.Millisecond, 20*time.Millisecond)
	prompts := &promptProbe{}

	res := runGatedReadTurn(t, project, t.TempDir(), 3, probe, prompts, frags...)

	shown, peak := prompts.counts()
	// The instrumented read forwards the built-in tool's metadata, so both external reads are
	// authorization-eligible and are decided on the one group prompt the production path shows
	// them — one request per call, never more than one on screen.
	if shown != 2 {
		t.Fatalf("prompt requests = %d, want one attributable decision per external read in the one group", shown)
	}
	if peak != 1 {
		t.Fatalf("peak prompts on screen = %d, want 1 (the shared gate stays the sole serialization)", peak)
	}
	if got := probe.peakLive(); got != 1 {
		t.Fatalf("peak concurrent reads = %d, want 1 (each excluded read is its own barrier and the single eligible read is its own segment)", got)
	}
	toolMsgs := messagesByRole(res.reloaded, "tool")
	if len(toolMsgs) != 3 {
		t.Fatalf("durable tool messages = %d, want 3", len(toolMsgs))
	}
	if toolMsgs[0].ToolCallID != "call_0" || !strings.HasPrefix(toolMsgs[0].Content.Text(), "package f0") {
		t.Fatalf("authorized sibling result = %+v, want its own in-project read content", toolMsgs[0])
	}
	for i, want := range []string{"external outside_a.txt", "external outside_b.txt"} {
		if got := toolMsgs[i+1].Content.Text(); !strings.HasPrefix(got, want) {
			t.Fatalf("approved external read %d = %q, want %q", i, got, want)
		}
	}
	if n := len(structuredReadStarts(t, res.reloaded)); n != 1 {
		t.Fatalf("structured_read_start events = %d, want 1 (the in-project read is still admitted)", n)
	}
	refusals := decodeStoreEvents[events.StructuredReadRefused](t, res.reloaded, events.KindStructuredReadRefused)
	if len(refusals) != 2 {
		t.Fatalf("structured_read_refused events = %d, want one per external read", len(refusals))
	}
}

func waitStructuredReadEnds(store *sessions.Store, want int, timeout time.Duration) ([]events.StructuredReadEnd, error) {
	deadline := time.Now().Add(timeout)
	for {
		var ends []events.StructuredReadEnd
		for _, rec := range store.Records() {
			ev, ok := rec.(sessions.Event)
			if !ok || ev.Kind != events.KindStructuredReadEnd {
				continue
			}
			var end events.StructuredReadEnd
			if err := json.Unmarshal(ev.Payload, &end); err != nil {
				return nil, fmt.Errorf("decode structured_read_end: %w", err)
			}
			ends = append(ends, end)
		}
		if len(ends) >= want || time.Now().After(deadline) {
			return ends, nil
		}
		time.Sleep(time.Millisecond)
	}
}

func TestReadToolsIntegration_AuthorizedSiblingProceedsDuringPrompt(t *testing.T) {
	project := readToolsProject(t)
	readFixtures(t, project, 1)
	frags := []string{
		toolFrag(0, "call_grep", filetools.GrepToolName, `{"pattern":"package f0"}`),
		toolFrag(1, "call_list", filetools.ListToolName, `{}`),
		toolFrag(2, "call_read", filetools.ReadToolName, `{"path":"f0.go"}`),
	}

	prompts := &promptProbe{
		force:  map[string]bool{filetools.GrepToolName: true, filetools.ListToolName: true},
		opened: make(chan struct{}),
	}
	var heldEnds []events.StructuredReadEnd
	var heldErr error
	var heldShown int
	prompts.whileHeld = func(store *sessions.Store) {
		heldEnds, heldErr = waitStructuredReadEnds(store, 1, 5*time.Second)
		heldShown, _ = prompts.counts()
	}
	probe := newHoldingProbe(1, 20*time.Millisecond, 0)

	res := runGatedReadTurn(t, project, t.TempDir(), 3, probe, prompts, frags...)

	if heldErr != nil {
		t.Fatal(heldErr)
	}
	if len(heldEnds) != 1 {
		t.Fatalf("structured_read_end records while a prompt was on screen = %d, want exactly the authorized sibling's (%+v)", len(heldEnds), heldEnds)
	}
	if heldEnds[0].ToolName != filetools.ReadToolName || heldEnds[0].Outcome != structuredReadOutcomeSuccess {
		t.Fatalf("record completed under the held prompt = %+v, want the authorized read's success", heldEnds[0])
	}
	if heldShown != 1 {
		t.Fatalf("prompts shown while the first was on screen = %d, want 1 (the sibling waits at the gate, it does not get a second prompt)", heldShown)
	}

	shown, peak := prompts.counts()
	if shown != 2 || peak != 1 {
		t.Fatalf("prompts shown/peak = %d/%d, want 2/1 (both gated reads prompt, never at the same time)", shown, peak)
	}

	toolMsgs := messagesByRole(res.reloaded, "tool")
	if len(toolMsgs) != 3 {
		t.Fatalf("durable tool messages = %d, want 3", len(toolMsgs))
	}
	for i, want := range []struct{ id, sub string }{
		{"call_grep", "f0.go"},
		{"call_list", "f0.go"},
		{"call_read", "package f0"},
	} {
		if toolMsgs[i].ToolCallID != want.id {
			t.Fatalf("tool message %d answers %q, want %q (results persist in model-call order)", i, toolMsgs[i].ToolCallID, want.id)
		}
		if !strings.Contains(toolMsgs[i].Content.Text(), want.sub) {
			t.Fatalf("tool message %d = %q, want it to contain %q", i, toolMsgs[i].Content.Text(), want.sub)
		}
	}

	starts := structuredReadStarts(t, res.reloaded)
	ends := structuredReadEnds(t, res.reloaded)
	if len(starts) != 3 || len(ends) != 3 {
		t.Fatalf("durable structured_read events = %d start/%d end, want 3/3", len(starts), len(ends))
	}
	started := map[string]bool{}
	for _, start := range starts {
		started[start.InvocationID] = true
		if start.ConfiguredConcurrency != 3 {
			t.Fatalf("start configured_concurrency = %d, want the configured 3", start.ConfiguredConcurrency)
		}
	}
	for _, end := range ends {
		if !started[end.InvocationID] {
			t.Fatalf("end record %+v pairs with no start", end)
		}
		if end.Outcome != structuredReadOutcomeSuccess {
			t.Fatalf("end record = %+v, want a success (a pending prompt must not change a sibling's outcome)", end)
		}
	}
}
