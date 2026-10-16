// Tests for the permission-prompt UI shell: fixed option order + default
// highlight, field rendering (including no-truncation literals and the
// optional cross-mode notice), the direct-command scope sub-choice, and
// overlay attach/dismiss state restoration over the running app shell.
package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/permissions"
)

func fullPromptRequest() PromptRequest {
	return PromptRequest{
		Action:             "Run command",
		Subject:            "git log --oneline",
		Kind:               SubjectDirectCommand,
		CanonicalProgram:   "git",
		CanonicalArgs:      []string{"log", "--oneline"},
		RunFolder:          "/work/project/sub",
		ProjectRoot:        "/work/project",
		FolderSettingsPath: "/work/project/.codemeld/settings.yaml",
		FolderCoverage:     "/work/project/sub and all descendants",
		// Gate inputs that warrant the cross-mode notice: launch-dir-only mode, the
		// settings file would be newly created, and it lands at the launch directory
		// (LaunchDir == ProjectRoot here). renderPromptFacts computes the notice from these.
		LaunchDir:               "/work/project",
		Boundary:                "launch-dir-only",
		WouldCreateSettingsFile: true,
	}
}

// literalPromptSummary is the summary production builds for a literal-route shell prompt,
// so a rendering test exercises the real classifier rather than a hand-written result.
func literalPromptSummary(command string) permissions.PromptSummaryResult {
	return permissions.PromptSummary(
		permissions.MatchRequest{Kind: "literal", Subject: command},
		permissions.PromptSummaryInput{Action: "Run command", Command: command},
	)
}

func renderPromptFacts(req PromptRequest) string {
	return strings.Join(promptFactLines(req), "\n") + "\n"
}

func renderPrompt(req PromptRequest) string {
	return renderPromptPreview(req) + strings.Join(promptFixedLines(req), "\n") + "\n"
}

func TestPromptOptions_FixedOrderAndDefaultHighlight(t *testing.T) {
	wantLabels := []string{
		"allow this once",
		"deny",
		"allow for this session",
		"allow in this folder permanently",
		"allow globally permanently",
	}
	wantOptions := []PromptOption{
		OptionAllowOnce, OptionDeny, OptionAllowSession, OptionAllowFolder, OptionAllowGlobal,
	}
	if len(wantOptions) != len(wantLabels) {
		t.Fatalf("test table broken: %d expected options for %d expected labels", len(wantOptions), len(wantLabels))
	}
	if len(promptOptionsInOrder) != len(wantLabels) {
		t.Fatalf("option count = %d, want %d", len(promptOptionsInOrder), len(wantLabels))
	}
	for i, o := range promptOptionsInOrder {
		if o.Label != wantLabels[i] {
			t.Errorf("option %d label = %q, want %q", i, o.Label, wantLabels[i])
		}
		if o.Option != wantOptions[i] {
			t.Errorf("option %d value = %d, want %d", i, o.Option, wantOptions[i])
		}
	}

	a := New(nil)
	_, list := a.buildPromptOverlay(fullPromptRequest(), make(chan PromptDecision, 1))
	if got := list.GetItemCount(); got != len(wantLabels) {
		t.Fatalf("list item count = %d, want %d", got, len(wantLabels))
	}
	for i := range wantLabels {
		want := promptRowLabel(promptOptionsInOrder[i])
		if got, _ := list.GetItemText(i); got != want {
			t.Errorf("list item %d = %q, want %q", i, got, want)
		}
	}
	if got := list.GetCurrentItem(); got != 0 {
		t.Fatalf("default highlighted item = %d, want 0 (allow this once)", got)
	}
}

func TestRenderPrompt_ShowsRequiredInfo(t *testing.T) {
	out := renderPrompt(fullPromptRequest())
	wants := []string{
		"Command: git log --oneline",
		"Run folder: /work/project/sub",
		"/work/project",
		"/work/project/.codemeld/settings.yaml",
		"/work/project/sub and all descendants",
		"allow in this folder permanently",
		"allow globally permanently",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("rendered prompt missing %q\n--- got ---\n%s", w, out)
		}
	}
}

func TestRenderPrompt_ExplainsAuthorizationScopeForCreateFile(t *testing.T) {
	req := PromptRequest{
		Action:             "Create file",
		Subject:            "/data/srht/codemeld/main/system-qwen.md",
		Body:               "# Base prompt audit\n",
		Kind:               SubjectStructuredTool,
		RunFolder:          "/data/srht/codemeld/main",
		ProjectRoot:        "/data/srht/codemeld/main",
		FolderSettingsPath: "/data/srht/codemeld/main/.codemeld/settings.yaml",
		FolderCoverage:     "/data/srht/codemeld/main and its descendants",
		Summary: permissions.PromptSummary(
			permissions.MatchRequest{Kind: "tool", Subject: "create"},
			permissions.PromptSummaryInput{Action: "Create file", RequestedTarget: "/data/srht/codemeld/main/system-qwen.md", Body: "# Base prompt audit\n"},
		),
	}

	out := renderPrompt(req)
	wants := []string{
		"Create file",
		"Requested target: /data/srht/codemeld/main/system-qwen.md",
		"allow in this folder permanently — saved to /data/srht/codemeld/main/.codemeld/settings.yaml so it survives restart.",
		"Applies when run from: /data/srht/codemeld/main and its descendants.",
		"allow globally permanently — saved permanently; applies from any folder.",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("rendered prompt missing authorization scope %q\n--- got ---\n%s", w, out)
		}
	}
}

func TestRenderPrompt_FactsOnlyDurableGrants(t *testing.T) {
	facts := renderPromptFacts(fullPromptRequest())
	for _, banned := range []string{
		"Permission required",
		"allow only this one request",
		"won't ask again for this same request",
		"\"allow this once\"",
		"\"allow for this session\"",
		"\"allow in this folder permanently\"",
		"\"allow globally permanently\"",
	} {
		if strings.Contains(facts, banned) {
			t.Errorf("facts still carry retired copy %q\n--- got ---\n%s", banned, facts)
		}
	}
	for _, want := range []string{
		"Run folder: /work/project/sub",
		"allow in this folder permanently — saved to /work/project/.codemeld/settings.yaml so it survives restart.",
		"Applies when run from: /work/project/sub and all descendants.",
		"allow globally permanently — saved permanently; applies from any folder.",
	} {
		if !strings.Contains(facts, want) {
			t.Errorf("facts missing durable-grant information %q\n--- got ---\n%s", want, facts)
		}
	}
	if !strings.HasPrefix(facts, "\n") || !strings.HasSuffix(facts, "\n") {
		t.Errorf("facts block must start and end with a newline for the row count to hold\n--- got ---\n%q", facts)
	}
}

func TestRenderPrompt_ShellContextDistinguishesCases(t *testing.T) {
	const pipeline = "cat file | grep x | wc -l"

	single := PromptRequest{Action: "Run command", Subject: "ls -l", Kind: SubjectDirectCommand, RunFolder: "/work"}
	out := renderPrompt(single)
	if strings.Contains(out, "Part of pipeline") || strings.Contains(out, "Whole command approval") {
		t.Errorf("single direct command carried pipeline/whole-command framing\n%s", out)
	}

	stage := PromptRequest{Action: "Run command", Subject: "grep x", Kind: SubjectDirectCommand, RunFolder: "/work", Pipeline: pipeline}
	out = renderPrompt(stage)
	if !strings.Contains(out, "grep x") {
		t.Errorf("pipeline-stage prompt dropped the isolated stage being approved\n%s", out)
	}
	if !strings.Contains(out, "Part of pipeline: "+pipeline) {
		t.Errorf("pipeline-stage prompt missing the full pipeline context\n%s", out)
	}
	if strings.Contains(out, "Whole command approval") {
		t.Errorf("pipeline stage mislabelled as a whole-command approval\n%s", out)
	}

	whole := PromptRequest{Action: "Run command", Subject: "git status > out", Kind: SubjectLiteralCommand, RunFolder: "/work", WholeCommand: true}
	out = renderPrompt(whole)
	if !strings.Contains(out, "Whole command approval") {
		t.Errorf("literal route not labelled a whole-command approval\n%s", out)
	}
	if strings.Contains(out, "Part of pipeline") {
		t.Errorf("literal whole-command mislabelled as a pipeline stage\n%s", out)
	}
}

func TestRenderPrompt_ShellCommandFirst(t *testing.T) {
	cases := []struct {
		name string
		req  PromptRequest
	}{
		{"direct", PromptRequest{Action: "Run command", Subject: `grep -R "needle here" .`, Kind: SubjectDirectCommand, RunFolder: "/work"}},
		{"literal", PromptRequest{Action: "Run command", Subject: `psql -c 'select 1'`, Kind: SubjectLiteralCommand, RunFolder: "/work", WholeCommand: true}},
		{"pipeline stage", PromptRequest{Action: "Run command", Subject: `awk '{print $1}'`, Kind: SubjectDirectCommand, RunFolder: "/work", Pipeline: `cat f | awk '{print $1}'`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			preview := renderPromptPreview(tc.req)
			if want := "Command: " + tc.req.Subject + "\n"; !strings.HasPrefix(preview, want) {
				t.Errorf("preview must open with %q\n--- got ---\n%s", want, preview)
			}
			out := renderPrompt(tc.req)
			for _, banned := range []string{
				"was not auto-approved as read-only",
				"file paths named in the command's arguments",
			} {
				if strings.Contains(out, banned) {
					t.Errorf("shell prompt still carries retired prose %q\n--- got ---\n%s", banned, out)
				}
			}
		})
	}
}

func TestRenderPrompt_StructuredToolKeepsActionPresentation(t *testing.T) {
	tool := renderPrompt(PromptRequest{
		Action: "Create file", Subject: "provinces.md", Body: "1. Alberta\n",
		Kind: SubjectStructuredTool, RunFolder: "/work",
	})
	if !strings.HasPrefix(tool, "Create file\nprovinces.md\n") {
		t.Errorf("structured-tool prompt lost its action header over the subject\n--- got ---\n%s", tool)
	}
	if !strings.Contains(tool, "1. Alberta\n") {
		t.Errorf("structured-tool prompt dropped its verbatim payload\n--- got ---\n%s", tool)
	}
	for _, banned := range []string{
		"Command:",
		"was not auto-approved as read-only",
		"file paths named in the command's arguments",
		"Part of pipeline",
		"Whole command approval",
	} {
		if strings.Contains(tool, banned) {
			t.Errorf("structured-tool prompt inherited shell-only copy %q\n--- got ---\n%s", banned, tool)
		}
	}
}

func batchedPromptRequest() PromptRequest {
	return PromptRequest{
		Action:             "Run command",
		Kind:               SubjectDirectCommand,
		Pipeline:           "find . -name x | sed -n 1,5p | awk '{print}'",
		BatchedStages:      []string{"find . -name x", "awk '{print}'"},
		RunFolder:          "/work/project",
		ProjectRoot:        "/work/project",
		FolderSettingsPath: "/work/project/.codemeld/settings.yaml",
		FolderCoverage:     "/work/project and all descendants",
	}
}

func TestRenderPrompt_BatchedShowsPipelineAndStages(t *testing.T) {
	req := batchedPromptRequest()
	out := renderPrompt(req)
	wants := []string{
		"2 stages that need your approval", // one choice applies to all
		"one choice below applies to all",
		"find . -name x | sed -n 1,5p | awk '{print}'", // the full pipeline, verbatim
		"Stages needing approval:",
		"find . -name x", // each unsafe stage, verbatim
		"awk '{print}'",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("batched prompt missing %q\n--- got ---\n%s", w, out)
		}
	}
	if !strings.HasPrefix(out, "Run command\n") {
		t.Errorf("batched prompt lost its action header\n--- got ---\n%s", out)
	}
	withSubject := req
	withSubject.Subject = "find . -name x"
	batched := renderPromptPreview(withSubject)
	if strings.Contains(batched, "Command: ") {
		t.Errorf("batched prompt framed a singular command; it must disclose every stage\n--- got ---\n%s", batched)
	}
	for _, w := range []string{"Stages needing approval:", "awk '{print}'"} {
		if !strings.Contains(batched, w) {
			t.Errorf("Subject-bearing batch dropped %q\n--- got ---\n%s", w, batched)
		}
	}

	a := New(nil)
	_, list := a.buildPromptOverlay(req, make(chan PromptDecision, 1))
	if got := list.GetItemCount(); got != 5 {
		t.Fatalf("batched prompt option count = %d, want 5 (the fixed options apply to the whole set)", got)
	}
}

func TestRenderPrompt_BatchedShowsPerStageEscalation(t *testing.T) {
	req := batchedPromptRequest()
	// The first stage broadens an already-approved narrower folder; the second does not.
	req.BatchedEscalations = []string{"/work/project/sub", ""}
	out := renderPrompt(req)
	for _, w := range []string{
		"find . -name x",    // the affected stage
		"/work/project/sub", // the narrower already-approved scope
		"Broader than a folder you already allowed",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("batched prompt missing escalation info %q\n--- got ---\n%s", w, out)
		}
	}
}

func TestRenderPrompt_ShellBlockedPathsNotice(t *testing.T) {
	literal := PromptRequest{
		Action:      "Run command",
		Subject:     "echo hi > out.txt",
		Kind:        SubjectLiteralCommand,
		RunFolder:   "/work/project",
		ProjectRoot: "/work/project",
		Summary:     literalPromptSummary("echo hi > out.txt"),
	}
	for _, tc := range []struct {
		name string
		req  PromptRequest
		want int
	}{
		{"direct command", fullPromptRequest(), 1},
		{"literal command", literal, 1},
		{"batched stages", batchedPromptRequest(), 1},
		{"structured tool", outsideProjectToolRequest(), 0},
		{"host", hostPromptRequest(), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := renderPrompt(tc.req)
			if got := strings.Count(out, ShellBlockedPathsNotice); got != tc.want {
				t.Fatalf("notice count = %d, want %d\n--- got ---\n%s", got, tc.want, out)
			}
		})
	}
}

// TestRenderPrompt_SingleStageNoBatchedChrome proves a lone unresolved stage (N=1) renders exactly as
// the ordinary single-stage prompt: none of the batched chrome appears, and the stage is shown as the
// plain Subject with its pipeline context. A single-entry BatchedStages is treated as not batched.
func TestRenderPrompt_SingleStageNoBatchedChrome(t *testing.T) {
	single := PromptRequest{
		Action: "Run command", Subject: "find . -name x", Kind: SubjectDirectCommand,
		Pipeline: "find . -name x | grep foo", RunFolder: "/work",
	}
	out := renderPrompt(single)
	for _, banned := range []string{
		"stages that need your approval",
		"Stages needing approval:",
		"one choice below applies to all",
	} {
		if strings.Contains(out, banned) {
			t.Errorf("single-stage prompt shows batched chrome %q\n--- got ---\n%s", banned, out)
		}
	}
	if !strings.Contains(out, "Part of pipeline: find . -name x | grep foo") {
		t.Errorf("single-stage prompt lost its pipeline context\n--- got ---\n%s", out)
	}
	if !strings.Contains(out, "find . -name x\n") {
		t.Errorf("single-stage prompt did not show the stage as the plain Subject\n--- got ---\n%s", out)
	}
}

// TestPromptUser_BatchedGrantAppliesWithoutScopeChooser proves a batched grant selection finalizes
// immediately with the bare option and NO per-stage scope sub-choice (the backend stores each stage's
// own concrete subject), so the decision carries no StoredSubject and no scope page is left behind.
func TestPromptUser_BatchedGrantAppliesWithoutScopeChooser(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, batchedPromptRequest())

	// Move to "allow for this session" (index 2) and select it.
	h.down(2)
	h.key(tcell.KeyEnter)

	decision := h.await()
	if decision.Option != OptionAllowSession {
		t.Fatalf("decision option = %d, want OptionAllowSession (%d)", decision.Option, OptionAllowSession)
	}
	if decision.StoredSubject != "" {
		t.Fatalf("batched grant StoredSubject = %q, want empty (each stage stores its own concrete subject)", decision.StoredSubject)
	}
	if a.pages.HasPage(promptScopePage) {
		t.Fatal("batched grant opened the per-stage scope chooser; it must apply one choice to all stages")
	}
}

func TestRenderPromptSplit_PreviewAndFacts(t *testing.T) {
	req := fullPromptRequest()

	preview := renderPromptPreview(req)
	if !strings.Contains(preview, "Command: git log --oneline") {
		t.Errorf("preview missing the command being approved\n--- got ---\n%s", preview)
	}
	if strings.Contains(preview, "Run folder:") {
		t.Errorf("preview must not carry the facts; they belong to renderPromptFacts\n--- got ---\n%s", preview)
	}

	facts := renderPromptFacts(req)
	for _, w := range []string{
		"Run folder:",
		"/work/project/sub",
		"allow in this folder permanently",
		"allow globally permanently",
	} {
		if !strings.Contains(facts, w) {
			t.Errorf("facts missing %q\n--- got ---\n%s", w, facts)
		}
	}
	if strings.Contains(facts, "git log --oneline") {
		t.Errorf("facts must not carry the preview subject; it belongs to renderPromptPreview\n--- got ---\n%s", facts)
	}

	whole := renderPrompt(req)
	if !strings.HasPrefix(whole, preview) || !strings.HasSuffix(whole, facts) {
		t.Errorf("renderPrompt must open with the preview and close with the facts, summary between\n--- got ---\n%s", whole)
	}
}

func TestRenderPrompt_NoMatchingInternals(t *testing.T) {
	cases := []struct {
		name string
		req  PromptRequest
	}{
		{"direct", fullPromptRequest()},
		{"literal", PromptRequest{Action: "Run command", Subject: "psql -c 'select 1'", Kind: SubjectLiteralCommand, RunFolder: "/work"}},
		{"create", PromptRequest{Action: "Create file", Subject: "provinces.md", Body: "1. Alberta\n", Kind: SubjectStructuredTool, RunFolder: "/work"}},
		{"other", PromptRequest{Action: "Run tool", Subject: "read_file", Body: `read_file({"path":"x"})`, Kind: SubjectStructuredTool, RunFolder: "/work"}},
	}
	banned := []string{"Subject kind:", "Subject:", "direct-command", "structured-tool", "literal-command"}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := renderPrompt(c.req)
			for _, b := range banned {
				if strings.Contains(out, b) {
					t.Errorf("prompt still renders matching internal %q\n--- got ---\n%s", b, out)
				}
			}
		})
	}
}

func TestRenderPrompt_ActionHeaderPerKind(t *testing.T) {
	cases := []struct {
		name       string
		req        PromptRequest
		wantHeader string
		wantInBody []string
		bannedHdr  string
	}{
		{
			name:       "create shows file and content",
			req:        PromptRequest{Action: "Create file", Subject: "provinces.md", Body: "1. Alberta\n2. BC\n", Kind: SubjectStructuredTool, RunFolder: "/work"},
			wantHeader: "Create file",
			wantInBody: []string{"provinces.md", "1. Alberta\n2. BC\n"},
		},
		{
			name:       "edit shows file and old->new snippet",
			req:        PromptRequest{Action: "Edit file", Subject: "main.go", Body: "Replace:\nfoo()\nWith:\nbar()", Kind: SubjectStructuredTool, RunFolder: "/work"},
			wantHeader: "Edit file",
			wantInBody: []string{"main.go", "Replace:\nfoo()\nWith:\nbar()"},
		},
		{
			name:       "shell leads with the command",
			req:        PromptRequest{Action: "Run command", Subject: "git status", Kind: SubjectDirectCommand, RunFolder: "/work"},
			wantHeader: "Command: git status",
			bannedHdr:  "Run command",
		},
		{
			name:       "other tool shows a generic action, not the bare token",
			req:        PromptRequest{Action: "Run tool", Subject: "read_file", Body: `read_file({"path":"x"})`, Kind: SubjectStructuredTool, RunFolder: "/work"},
			wantHeader: "Run tool",
			wantInBody: []string{`read_file({"path":"x"})`},
			bannedHdr:  "read_file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := renderPrompt(tc.req)
			if !strings.HasPrefix(out, tc.wantHeader+"\n") {
				t.Errorf("rendered prompt must open with the action header %q\n--- got ---\n%s", tc.wantHeader, out)
			}
			if tc.bannedHdr != "" && strings.HasPrefix(out, tc.bannedHdr) {
				t.Errorf("action header leaked the bare token %q\n--- got ---\n%s", tc.bannedHdr, out)
			}
			for _, w := range tc.wantInBody {
				if !strings.Contains(out, w) {
					t.Errorf("rendered prompt missing %q\n--- got ---\n%s", w, out)
				}
			}
		})
	}
}

func TestRenderPrompt_OutOfRootEditCreateFolderCopy(t *testing.T) {
	req := PromptRequest{
		Action:             "Create file",
		Subject:            "/outside/tree/new.txt",
		Body:               "data\n",
		Kind:               SubjectStructuredTool,
		RunFolder:          "/outside/tree",
		ProjectRoot:        "/work/project",
		FolderSettingsPath: "/work/project/.codemeld/settings.yaml",
		FolderCoverage:     "/outside/tree and its descendants",
		OutOfRootFileWrite: true,
	}
	out := renderPrompt(req)
	if !strings.Contains(out, "/work/project/.codemeld/settings.yaml") {
		t.Errorf("folder write-target (this project's settings file) missing for an out-of-root edit/create\n%s", out)
	}
	if !strings.Contains(out, "/outside/tree and its descendants") {
		t.Errorf("folder coverage (the out-of-root folder) missing\n%s", out)
	}

	// Without the signal the same out-of-root scope hides the folder detail (the folder option is dropped).
	noSignal := req
	noSignal.OutOfRootFileWrite = false
	if strings.Contains(renderPrompt(noSignal), "/work/project/.codemeld/settings.yaml") {
		t.Errorf("folder write-target shown for an out-of-root scope without the edit/create signal\n%s", renderPrompt(noSignal))
	}
}

func TestRenderPrompt_OutOfProjectShellFolderFacts(t *testing.T) {
	cases := []struct {
		name string
		req  PromptRequest
	}{
		{"direct command", outsideProjectDirectRequest()},
		{"literal command", outsideProjectLiteralRequest()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := renderPrompt(c.req)
			if !strings.Contains(out, "saved to /work/project/.codemeld/settings.yaml") {
				t.Errorf("folder write-target missing for an out-of-project shell prompt\n%s", out)
			}
			if !strings.Contains(out, "/elsewhere/outside and all descendants") {
				t.Errorf("folder coverage missing for an out-of-project shell prompt\n%s", out)
			}
			if !strings.Contains(out, "allow globally permanently") {
				t.Errorf("global option line dropped\n%s", out)
			}
		})
	}

	tool := renderPrompt(outsideProjectToolRequest())
	if strings.Contains(tool, "saved to /work/project/.codemeld/settings.yaml") {
		t.Errorf("folder detail shown for an out-of-project prompt whose folder option is omitted\n%s", tool)
	}
}

func TestRenderPrompt_OutOfProjectShellCrossModeNotice(t *testing.T) {
	want := RenderCrossModeMarkerNotice(filepath.Join("/work/project", ".codemeld", "settings.yaml"))

	shell := outsideProjectDirectRequest()
	shell.LaunchDir = "/work/project"
	shell.Boundary = "launch-dir-only"
	shell.WouldCreateSettingsFile = true
	if out := renderPrompt(shell); !strings.Contains(out, want) {
		t.Errorf("cross-mode marker notice missing for a folder-eligible out-of-project shell prompt\n%s", out)
	}

	tool := outsideProjectToolRequest()
	tool.LaunchDir = "/work/project"
	tool.Boundary = "launch-dir-only"
	tool.WouldCreateSettingsFile = true
	if out := renderPrompt(tool); strings.Contains(out, want) {
		t.Errorf("cross-mode marker notice shown for a prompt whose folder option is omitted\n%s", out)
	}
}

func TestFolderUnavailableExplanation_NotConflating(t *testing.T) {
	if strings.Contains(folderUnavailableExplanation, "does not write permission files outside the project root") {
		t.Errorf("folder-unavailable copy still conflates file location with coverage: %q", folderUnavailableExplanation)
	}
	if !strings.Contains(folderUnavailableExplanation, "file create or edit") {
		t.Errorf("folder-unavailable copy should state the file create/edit exception: %q", folderUnavailableExplanation)
	}
	if !strings.Contains(folderUnavailableExplanation, "read-only") {
		t.Errorf("folder-unavailable copy should also name the explicit out-of-project read-only exception (g815): %q", folderUnavailableExplanation)
	}
}

func TestRenderPrompt_ProjectRootMismatchMarked(t *testing.T) {
	out := renderPrompt(fullPromptRequest())
	if !strings.Contains(out, "differs from project root") {
		t.Errorf("mismatch marker not shown when run folder != project root\n%s", out)
	}

	same := fullPromptRequest()
	same.RunFolder = "/work/project"
	same.ProjectRoot = "/work/project"
	out = renderPrompt(same)
	if strings.Contains(out, "differs from project root") {
		t.Errorf("mismatch marker shown when run folder == project root\n%s", out)
	}
	if !strings.Contains(out, "(same as run folder)") {
		t.Errorf("same-as-run-folder note missing when paths match\n%s", out)
	}
}

func TestRenderPrompt_ScopeEscalationWarned(t *testing.T) {
	const narrower = "/work/project/sub/imgdown"
	req := fullPromptRequest()
	req.ScopeEscalationNarrower = narrower
	facts := renderPromptFacts(req)
	for _, w := range []string{"Broader than a folder you already allowed", "PARENT of", narrower} {
		if !strings.Contains(facts, w) {
			t.Errorf("escalation warning missing %q\n--- got ---\n%s", w, facts)
		}
	}

	if got := renderPromptFacts(fullPromptRequest()); strings.Contains(got, "Broader than a folder you already allowed") {
		t.Errorf("escalation warning shown when ScopeEscalationNarrower unset\n--- got ---\n%s", got)
	}
}

func TestRenderPrompt_LiteralCommandNotTruncated(t *testing.T) {
	long := "psql -c " + strings.Repeat("SELECT * FROM very_long_table_name JOIN another ON id; ", 40)
	req := PromptRequest{
		Action:    "Run command",
		Subject:   long,
		Kind:      SubjectLiteralCommand,
		RunFolder: "/work",
	}
	out := renderPrompt(req)
	if !strings.Contains(out, long) {
		t.Fatalf("long literal canonical form was truncated; rendered length %d, literal length %d", len(out), len(long))
	}
}

func TestRenderPrompt_CrossModeNoticeOnlyWhenSupplied(t *testing.T) {
	const consequence = "mark the launch directory as a project root"

	// Shown: launch-dir-only, would-be-created marker landing at the launch dir.
	wantPath := filepath.Join("/work/project", ".codemeld", "settings.yaml")
	with := renderPrompt(fullPromptRequest())
	if !strings.Contains(with, RenderCrossModeMarkerNotice(wantPath)) {
		t.Errorf("cross-mode notice missing or not byte-identical to shared wording when warranted\nwant substring: %q\n--- got ---\n%s", RenderCrossModeMarkerNotice(wantPath), with)
	}

	projectRootMode := fullPromptRequest()
	projectRootMode.Boundary = "project-root"
	if out := renderPrompt(projectRootMode); strings.Contains(out, consequence) {
		t.Errorf("cross-mode notice rendered under project-root mode\n%s", out)
	}

	// Suppressed when the settings file already exists (it is already a marker).
	existingFile := fullPromptRequest()
	existingFile.WouldCreateSettingsFile = false
	if out := renderPrompt(existingFile); strings.Contains(out, consequence) {
		t.Errorf("cross-mode notice rendered when the settings file already exists\n%s", out)
	}
}

func TestIsDirectCommand_GatesF70SubChoice(t *testing.T) {
	cases := []struct {
		kind SubjectKind
		want bool
	}{
		{SubjectDirectCommand, true},
		{SubjectLiteralCommand, false},
		{SubjectStructuredTool, false},
	}
	for _, c := range cases {
		if got := (PromptRequest{Kind: c.kind}).IsDirectCommand(); got != c.want {
			t.Errorf("IsDirectCommand for %q = %v, want %v", c.kind, got, c.want)
		}
	}
}

// TestIsSimpleCompound_GatesCompoundChooser proves the simple-compound gate is
// separate from IsDirectCommand: only a literal-command subject carrying a recognized
// compound decomposition opens the per-stage chooser, while an ordinary literal
// (Compound nil) and a direct command do not — so non-simple literals keep the
// byte-exact no-chooser path.
func TestIsSimpleCompound_GatesCompoundChooser(t *testing.T) {
	if (PromptRequest{Kind: SubjectLiteralCommand}).IsSimpleCompound() {
		t.Errorf("IsSimpleCompound = true for an ordinary literal (Compound nil), want false")
	}
	if (PromptRequest{Kind: SubjectDirectCommand}).IsSimpleCompound() {
		t.Errorf("IsSimpleCompound = true for a direct command, want false")
	}
	sc := permissions.SimpleCompound{Stages: [][]string{{"go", "build"}, {"gofmt"}}, Operators: []string{"&&"}}
	if !(PromptRequest{Kind: SubjectLiteralCommand, Compound: &sc}).IsSimpleCompound() {
		t.Errorf("IsSimpleCompound = false for a recognized compound, want true")
	}
}

func TestPromptUser_EnterPicksDefaultAllowOnce(t *testing.T) {
	a := New(nil)
	a.input.SetText("typed but not submitted")
	a.Append("prior transcript line")

	h := startPrompt(t, a, fullPromptRequest())
	h.key(tcell.KeyEnter)

	decision := h.await()
	if decision.Option != OptionAllowOnce {
		t.Fatalf("decision = %d, want OptionAllowOnce (%d)", decision.Option, OptionAllowOnce)
	}

	// Overlay dismissed and prior state restored: page removed, focus
	// back on the input area, transcript and typed input untouched.
	if a.pages.HasPage(promptBasePage) {
		t.Error("prompt page not removed after dismissal")
	}
	if a.promptOpen {
		t.Error("promptOpen still set after dismissal")
	}
	if a.app.GetFocus() != a.input {
		t.Error("focus not restored to input area after dismissal")
	}
	if txt := a.input.GetText(); txt != "typed but not submitted" {
		t.Errorf("input buffer altered by prompt: %q", txt)
	}
	if !equalStrings(a.transcript.lines, []string{"prior transcript line"}) {
		t.Errorf("transcript altered by prompt: %v", a.transcript.lines)
	}
}

func TestPromptOverlay_LongLiteralCommandReachableInNarrowTerminal(t *testing.T) {
	const tail = "ENDMARKER7Z"
	long := "psql -c '" + strings.Repeat("SELECT * FROM t WHERE x = 1; ", 30) + tail + "'"
	req := PromptRequest{
		Action:    "Run command",
		Subject:   long,
		Kind:      SubjectLiteralCommand,
		RunFolder: "/work",
		Summary:   literalPromptSummary(long),
	}

	a := New(nil)
	h := startPrompt(t, a, req)

	// readScreen forces a draw, then flattens the screen on the loop goroutine so
	// the read is serialized with the draw loop (tcell's simulation screen writes
	// cells without locking, so reading from the test goroutine would race).
	readScreen := func() string { return readScreenSync(t, a, h.screen) }

	// Narrow + short terminal so the wrapped literal command overflows the
	// visible info area; the command's tail must be off-screen at open.
	h.screen.SetSize(40, 24)
	atOpen := readScreen()
	if strings.Contains(atOpen, tail) {
		a.app.Stop()
		t.Fatalf("test premise broken: command tail %q fits without scrolling; widen the literal or shrink the terminal", tail)
	}
	for _, w := range []string{"Summary:", "Request: shell command", "Run folder", "allow globally permanently", "allow this [o]nce"} {
		if !strings.Contains(atOpen, w) {
			a.app.Stop()
			t.Fatalf("fixed row %q not visible at open while the preview overflows\n%s", w, atOpen)
		}
	}

	// Scroll the preview one page at a time while the option list keeps focus; the tail
	// must show up on some page rather than only at the very bottom.
	deadline := time.Now().Add(2 * time.Second)
	found := strings.Contains(atOpen, tail)
	for i := 0; i < 60 && !found && time.Now().Before(deadline); i++ {
		h.key(tcell.KeyPgDn)
		found = strings.Contains(readScreen(), tail)
	}
	if !found {
		a.app.Stop()
		t.Fatalf("command tail %q not reachable after scrolling", tail)
	}

	afterScroll := readScreen()
	for _, w := range []string{"Summary:", "Run folder", "allow globally permanently"} {
		if !strings.Contains(afterScroll, w) {
			a.app.Stop()
			t.Fatalf("fixed row %q scrolled off screen with the preview\n%s", w, afterScroll)
		}
	}

	// The option list still has focus and remains usable after scrolling.
	focus := focusedPrimitive(h)
	if _, ok := focus.(*tview.List); !ok {
		t.Errorf("option list lost focus while scrolling the info block; focus=%T", focus)
	}

	// Dismiss via the default option so the app shuts down cleanly.
	h.key(tcell.KeyEnter)
	h.await()
}

func TestPromptOverlay_ShellBlockedPathsNoticeOnScreen(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  PromptRequest
		want bool
	}{
		{"direct shell command", fullPromptRequest(), true},
		{"structured tool", outsideProjectToolRequest(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			h := startPrompt(t, a, tc.req)
			h.screen.SetSize(200, 40)
			screen := readScreenSync(t, a, h.screen)
			if !strings.Contains(screen, "Run folder") {
				a.app.Stop()
				t.Fatalf("prompt facts not on screen\n%s", screen)
			}
			if got := strings.Contains(screen, ShellBlockedPathsNotice); got != tc.want {
				a.app.Stop()
				t.Fatalf("notice on screen = %v, want %v\n%s", got, tc.want, screen)
			}
			h.key(tcell.KeyEnter)
			h.await()
		})
	}
}

func TestPromptOverlay_MouseKeepsOptionListFocused(t *testing.T) {
	req := PromptRequest{
		Action:    "Create file",
		Subject:   "/work/project/new.md",
		Kind:      SubjectStructuredTool,
		RunFolder: "/work/project",
		Body:      strings.Repeat("long file body line\n", 80),
	}
	a := New(nil)
	decisionCh := make(chan PromptDecision, 1)
	overlay, list := a.buildPromptOverlay(req, decisionCh)
	body, ok := overlay.(*tview.Flex)
	if !ok {
		t.Fatalf("overlay is %T, want *tview.Flex", overlay)
	}
	preview, ok := body.GetItem(0).(*tview.TextView)
	if !ok {
		t.Fatalf("first overlay item is %T, want *tview.TextView", body.GetItem(0))
	}
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init: %v", err)
	}
	screen.SetSize(80, 30)
	a.app.SetScreen(screen)
	body.SetRect(0, 0, 80, 30)
	a.app.SetFocus(list)
	body.Draw(screen)

	handler := body.MouseHandler()
	setFocus := func(p tview.Primitive) { a.app.SetFocus(p) }
	px, py, _, _ := preview.GetRect()
	consumed, _ := handler(tview.MouseLeftDown, tcell.NewEventMouse(px+1, py+1, tcell.Button1, tcell.ModNone), setFocus)
	if !consumed {
		t.Fatal("preview mouse-down was not consumed")
	}
	if got := a.app.GetFocus(); got != list {
		t.Fatalf("after preview mouse-down, focus = %T, want prompt option list", got)
	}

	beforeRow, _ := preview.GetScrollOffset()
	consumed, _ = handler(tview.MouseScrollDown, tcell.NewEventMouse(px+1, py+1, tcell.WheelDown, tcell.ModNone), setFocus)
	if !consumed {
		t.Fatal("preview wheel-down was not consumed")
	}
	afterRow, _ := preview.GetScrollOffset()
	if afterRow <= beforeRow {
		t.Fatalf("preview wheel-down did not scroll preview: before row %d, after row %d", beforeRow, afterRow)
	}
	if got := a.app.GetFocus(); got != list {
		t.Fatalf("after preview wheel-down, focus = %T, want prompt option list", got)
	}
	consumed, _ = handler(tview.MouseLeftDown, tcell.NewEventMouse(px+1, py+1, tcell.Button1, tcell.ModShift), setFocus)
	if consumed {
		t.Fatal("shift mouse-down over the prompt was consumed; Shift selection must stay outside prompt focus handling")
	}
	if got := a.app.GetFocus(); got != list {
		t.Fatalf("after shift mouse-down, focus = %T, want prompt option list", got)
	}

	lx, ly, _, _ := list.GetRect()
	consumed, _ = handler(tview.MouseLeftDown, tcell.NewEventMouse(lx+1, ly+2, tcell.Button1, tcell.ModNone), setFocus)
	if !consumed {
		t.Fatal("list mouse-down was not consumed")
	}
	consumed, _ = handler(tview.MouseLeftClick, tcell.NewEventMouse(lx+1, ly+2, tcell.Button1, tcell.ModNone), setFocus)
	if !consumed {
		t.Fatal("list mouse-click was not consumed")
	}
	select {
	case decision := <-decisionCh:
		if decision.Option != OptionAllowSession {
			t.Fatalf("list click decision = %d, want OptionAllowSession", decision.Option)
		}
	default:
		t.Fatal("list mouse-click did not select an option")
	}
}

func TestPromptOverlay_LongFactValueWrapsAndStaysVisible(t *testing.T) {
	const tail = "PREVIEWEND9Q"
	anchor := strings.Repeat("grant-anchor-segment ", 8)
	longBody := strings.Repeat("preview body line that overflows the visible region\n", 40) + tail
	req := PromptRequest{
		Action:    "Run command",
		Subject:   "psql -c 'select 1'",
		Kind:      SubjectLiteralCommand,
		RunFolder: anchor,
		Body:      longBody,
		Summary:   literalPromptSummary("psql -c 'select 1'"),
	}

	a := New(nil)
	h := startPrompt(t, a, req)

	readScreen := func() string { return readScreenSync(t, a, h.screen) }

	h.screen.SetSize(40, 30)
	first := readScreen()
	if strings.Contains(first, tail) {
		a.app.Stop()
		t.Fatalf("over-cap anchor tail rendered in the fixed facts block instead of being bounded\n%s", first)
	}
	for _, w := range []string{"Run folder: grant-anchor-segment", "…"} {
		if !strings.Contains(first, w) {
			a.app.Stop()
			t.Fatalf("bounded anchor rendering missing %q\n%s", w, first)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	found := false
	for i := 0; i < 200 && !found && time.Now().Before(deadline); i++ {
		h.key(tcell.KeyPgDn)
		found = strings.Contains(readScreen(), tail)
	}
	if !found {
		a.app.Stop()
		t.Fatal("raw preview tail is not reachable in the scrollable region")
	}
	after := readScreen()
	if !strings.Contains(after, "Run folder") {
		a.app.Stop()
		t.Fatalf("facts label scrolled off with the preview\n%s", after)
	}
	focus := focusedPrimitive(h)
	if _, ok := focus.(*tview.List); !ok {
		t.Errorf("option list lost focus while scrolling; focus=%T", focus)
	}

	h.key(tcell.KeyEnter)
	h.await()
}

// TestPromptOverlay_BracketTagFactValueWrapsLiterally proves the facts row counter
// uses the same literal rendering semantics as the facts TextView. Dynamic colors
// are disabled there, so path segments that look like tview style tags (for example
// "[red]") are visible cells, not zero-width markup; the fixed facts slot must count
// them or the tail of the grant anchor can be clipped.
func TestPromptOverlay_BracketTagFactValueWrapsLiterally(t *testing.T) {
	const tail = "TAGTAIL7Z"
	anchor := strings.Repeat("[red][green][blue]tagged-segment ", 8)
	longBody := strings.Repeat("preview body line that overflows the visible region\n", 40) + tail
	req := PromptRequest{
		Action:    "Run command",
		Subject:   "psql -c 'select 1'",
		Kind:      SubjectLiteralCommand,
		RunFolder: anchor,
		Body:      longBody,
		Summary:   literalPromptSummary("psql -c 'select 1'"),
	}

	a := New(nil)
	h := startPrompt(t, a, req)

	readScreen := func() string { return readScreenSync(t, a, h.screen) }

	h.screen.SetSize(40, 30)
	first := readScreen()
	if !strings.Contains(first, "Run folder: [red][green][blue]tagged-") {
		a.app.Stop()
		t.Fatalf("bracket-tag anchor not rendered literally in the facts block\n%s", first)
	}

	deadline := time.Now().Add(2 * time.Second)
	found := false
	for i := 0; i < 200 && !found && time.Now().Before(deadline); i++ {
		h.key(tcell.KeyPgDn)
		found = strings.Contains(readScreen(), tail)
	}
	if !found {
		a.app.Stop()
		t.Fatalf("raw preview tail not reachable in the scrollable region")
	}
	if after := readScreen(); !strings.Contains(after, "Run folder") {
		a.app.Stop()
		t.Fatalf("bracket-tag facts did not stay visible after preview scroll\n%s", after)
	}
	focus := focusedPrimitive(h)
	if _, ok := focus.(*tview.List); !ok {
		t.Errorf("option list lost focus while scrolling; focus=%T", focus)
	}

	h.key(tcell.KeyEnter)
	h.await()
}

func TestPromptUser_DenyIsSingleAction(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, fullPromptRequest())

	h.down(1)             // from default "allow this once" to "deny"
	h.key(tcell.KeyEnter) // a single Enter finalizes the deny

	decision := h.await()
	if decision.Option != OptionDeny {
		t.Fatalf("decision = %d, want OptionDeny (%d)", decision.Option, OptionDeny)
	}
	if want := permissions.BuildDenyEnvelope(""); decision.DenyEnvelope != want {
		t.Fatalf("DenyEnvelope = %q, want default %q", decision.DenyEnvelope, want)
	}
	if !strings.Contains(decision.DenyEnvelope, "user denied this tool call without a reason") {
		t.Fatalf("deny did not carry the default reason text: %q", decision.DenyEnvelope)
	}
}

// promptHarness drives a live PromptUser over a simulation screen across the
// multi-step flow (option list → scope chooser → optional Program
// confirmation). Page-attach waits and page-presence reads go through QueueUpdate
// (which blocks until the closure runs on the loop goroutine) so the test never
// touches shared tview state concurrently with the draw loop.
type promptHarness struct {
	t      *testing.T
	a      *App
	screen tcell.SimulationScreen
	decc   chan PromptDecision
	errc   chan error
}

func startPromptLoop(t *testing.T, a *App) *promptHarness {
	t.Helper()
	screen := tcell.NewSimulationScreen("UTF-8")
	a.app.SetScreen(screen)

	errc := make(chan error, 1)
	go func() { errc <- a.app.Run() }()

	return &promptHarness{t: t, a: a, screen: screen, errc: errc}
}

func startPrompt(t *testing.T, a *App, req PromptRequest) *promptHarness {
	t.Helper()
	h := startPromptLoop(t, a)
	h.decc = make(chan PromptDecision, 1)
	go func() {
		d, _ := a.PromptUser(req)
		h.decc <- d
	}()

	h.waitPage(promptBasePage)
	return h
}

func (h *promptHarness) waitPage(name string) {
	h.t.Helper()
	waitOnLoop(h.t, h.a, "attach of page "+name, func() bool { return h.a.pages.HasPage(name) })
}

func (h *promptHarness) waitPageGone(name string) {
	h.t.Helper()
	waitOnLoop(h.t, h.a, "removal of page "+name, func() bool { return !h.a.pages.HasPage(name) })
}

func (h *promptHarness) hasPage(name string) bool {
	open := false
	h.a.app.QueueUpdate(func() { open = h.a.pages.HasPage(name) })
	return open
}

func (h *promptHarness) key(k tcell.Key) { h.screen.InjectKey(k, 0, tcell.ModNone) }

func (h *promptHarness) typeText(s string) { h.screen.InjectKeyBytes([]byte(s)) }

func (h *promptHarness) await() PromptDecision {
	h.t.Helper()
	var d PromptDecision
	select {
	case d = <-h.decc:
	case <-time.After(2 * time.Second):
		h.a.app.Stop()
		h.t.Fatal("PromptUser did not return a decision within 2s")
	}
	h.a.app.Stop()
	if err := <-h.errc; err != nil {
		h.t.Fatalf("app.Run returned error: %v", err)
	}
	return d
}

// down moves the focused list cursor n rows.
func (h *promptHarness) down(n int) {
	for i := 0; i < n; i++ {
		h.key(tcell.KeyDown)
	}
}

// focusedPrimitive reads the app's currently focused primitive on the loop
// goroutine, so the test never touches shared tview state concurrently with the
// draw loop.
func focusedPrimitive(h *promptHarness) tview.Primitive {
	var p tview.Primitive
	h.a.app.QueueUpdate(func() { p = h.a.app.GetFocus() })
	return p
}

func focusedListItem(h *promptHarness) (int, bool) {
	current := -1
	focused := false
	h.a.app.QueueUpdate(func() {
		list, ok := h.a.app.GetFocus().(*tview.List)
		if !ok {
			return
		}
		focused = true
		current = list.GetCurrentItem()
	})
	return current, focused
}

func TestPromptUser_SecondDecisionCannotBlockOrDoubleSend(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, fullPromptRequest())

	done := make(chan struct{})
	go func() {
		h.a.app.QueueUpdate(func() {
			ch := h.a.promptDecisionCh
			for i := 0; i < 3; i++ {
				h.a.completePrompt(ch, PromptDecision{Option: OptionAllowSession, StoredSubject: "git log :*"})
			}
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		h.a.app.Stop()
		t.Fatal("repeated prompt completions blocked the event loop; the one-send guard must drop them")
	}

	d := h.await()
	if d.Option != OptionAllowSession || d.StoredSubject != "git log :*" {
		t.Fatalf("decision = %+v, want the first completion (allow-session, git log :*)", d)
	}
	if a.promptOpen || a.promptDecisionCh != nil {
		t.Fatalf("prompt decision state not cleared: open=%v ch=%v", a.promptOpen, a.promptDecisionCh != nil)
	}
	if a.pages.HasPage(promptBasePage) {
		t.Fatal("prompt page not removed after the decision")
	}
}

func TestRestorePromptFocusOnTerminalFocus_BasePage(t *testing.T) {
	a := New(nil)
	a.promptOpen = true

	base := tview.NewBox()
	a.pages.AddPage(promptBasePage, base, true, true)
	a.app.SetFocus(a.input)
	a.restoreModalFocusOnTerminalFocus()
	if a.app.GetFocus() != base {
		t.Fatalf("focus = %T, want the base prompt page primitive", a.app.GetFocus())
	}

	other := tview.NewBox()
	a.pages.AddPage("other-overlay", other, true, true)
	a.app.SetFocus(a.input)
	a.restoreModalFocusOnTerminalFocus()
	if a.app.GetFocus() != a.input {
		t.Fatalf("focus = %T, want it unchanged for a non-prompt front page", a.app.GetFocus())
	}
}

func TestPromptUser_CleanupRemovesProgramConfirmPage(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, fullPromptRequest())

	h.down(2)
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopePage)
	h.down(1)
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopeConfirmPage)

	h.key(tcell.KeyEscape)
	if d := h.await(); d.Option != OptionDeny {
		t.Fatalf("Escape decision = %d, want OptionDeny (%d)", d.Option, OptionDeny)
	}
	if a.pages.HasPage(promptScopeConfirmPage) {
		t.Fatal("program-confirm page outlived the prompt; final cleanup must remove it")
	}
}

func TestPromptUser_CleanupRemovesScopePage(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, fullPromptRequest())

	h.down(2)
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopePage)
	if h.hasPage(promptScopeConfirmPage) {
		h.a.app.Stop()
		t.Fatal("confirm step mounted; this case must exercise the scope page alone")
	}

	h.key(tcell.KeyEscape)
	if d := h.await(); d.Option != OptionDeny {
		t.Fatalf("Escape decision = %d, want OptionDeny (%d)", d.Option, OptionDeny)
	}
	if a.pages.HasPage(promptScopePage) {
		t.Fatal("scope chooser outlived the prompt; final cleanup must remove it")
	}
}

func TestPromptUser_CleanupRemovesCompoundPage(t *testing.T) {
	sc := permissions.SimpleCompound{
		Stages:    [][]string{{"go", "build", "./..."}, {"gofmt", "-w", "a.go"}},
		Operators: []string{"&&"},
	}
	a := New(nil)
	h := startPrompt(t, a, compoundPromptRequest(sc))

	h.down(2)
	h.key(tcell.KeyEnter)
	h.waitPage(promptCompoundPage)

	h.key(tcell.KeyEscape)
	if d := h.await(); d.Option != OptionDeny {
		t.Fatalf("Escape decision = %d, want OptionDeny (%d)", d.Option, OptionDeny)
	}
	if a.pages.HasPage(promptCompoundPage) {
		t.Fatal("compound chooser outlived the prompt; final cleanup must remove it")
	}
}

func TestPromptUser_OffLoopSetupMountsBasePageThroughLoop(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, fullPromptRequest())

	if !h.hasPage(promptBasePage) {
		h.a.app.Stop()
		t.Fatal("base prompt page not mounted after the off-loop PromptUser call")
	}

	h.key(tcell.KeyEnter)
	if d := h.await(); d.Option != OptionAllowOnce {
		t.Fatalf("Option = %d, want OptionAllowOnce (%d)", d.Option, OptionAllowOnce)
	}
}

func TestPromptUser_OffLoopSetupFocusesOptionListThroughLoop(t *testing.T) {
	a := New(nil)
	a.input.SetText("typed but not submitted")
	before := a.app.GetFocus()

	h := startPrompt(t, a, fullPromptRequest())

	var label string
	var isList, unchanged bool
	h.a.app.QueueUpdate(func() {
		focused := h.a.app.GetFocus()
		unchanged = focused == before
		if list, ok := focused.(*tview.List); ok {
			isList = true
			label, _ = list.GetItemText(0)
		}
	})
	if unchanged {
		h.a.app.Stop()
		t.Fatal("focus stayed on the pre-prompt primitive; the queued setup must focus the option list")
	}
	if !isList || label != promptRowLabel(promptOptionsInOrder[0]) {
		h.a.app.Stop()
		t.Fatalf("focused primitive is not the prompt option list (list=%v first item %q)", isList, label)
	}

	h.key(tcell.KeyEnter)
	if d := h.await(); d.Option != OptionAllowOnce {
		t.Fatalf("Option = %d, want OptionAllowOnce (%d); Enter did not reach the focused option list", d.Option, OptionAllowOnce)
	}
}

func TestPromptUser_DirectCommandSessionUsesInferredPrefixDefault(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, fullPromptRequest())

	h.down(2) // allow for this session
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopePage)
	h.key(tcell.KeyEnter)

	d := h.await()
	if d.Option != OptionAllowSession {
		t.Fatalf("Option = %d, want OptionAllowSession (%d)", d.Option, OptionAllowSession)
	}
	if d.StoredSubject != "git log :*" {
		t.Fatalf("StoredSubject = %q, want %q", d.StoredSubject, "git log :*")
	}
}

// TestPromptUser_DirectCommandExactScope proves the user can override the default
// and store the full canonical token sequence with no `:*` suffix (Exact).
func TestPromptUser_DirectCommandExactScope(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, fullPromptRequest())

	h.down(3) // allow in this folder permanently
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopePage)
	h.key(tcell.KeyUp)
	h.key(tcell.KeyUp)
	h.key(tcell.KeyEnter)

	d := h.await()
	if d.Option != OptionAllowFolder {
		t.Fatalf("Option = %d, want OptionAllowFolder (%d)", d.Option, OptionAllowFolder)
	}
	if d.StoredSubject != "git log --oneline" {
		t.Fatalf("StoredSubject = %q, want %q", d.StoredSubject, "git log --oneline")
	}
}

func TestPromptUser_DirectCommandPrefixScopeStoresSelectedBoundary(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, prefixPromptRequest())

	h.down(2) // allow for this session
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopePage)
	h.down(1)
	h.key(tcell.KeyEnter)

	if h.hasPage(promptScopeConfirmPage) {
		h.a.app.Stop()
		t.Fatal("a Prefix choice opened the program-wide confirm step")
	}

	d := h.await()
	if d.Option != OptionAllowSession {
		t.Fatalf("Option = %d, want OptionAllowSession (%d)", d.Option, OptionAllowSession)
	}
	if d.StoredSubject != "prep-open-tasks.sh --only :*" {
		t.Fatalf("StoredSubject = %q, want %q", d.StoredSubject, "prep-open-tasks.sh --only :*")
	}
	if !permissions.MatchesDirectSubject([]string{"prep-open-tasks.sh", "--only", "f1090"}, nil, false, d.StoredSubject) {
		t.Errorf("stored subject %q does not authorize a different task id", d.StoredSubject)
	}
	if permissions.MatchesDirectSubject([]string{"prep-open-tasks.sh", "--all"}, nil, false, d.StoredSubject) {
		t.Errorf("stored subject %q authorized a command with a different pinned token", d.StoredSubject)
	}
}

func TestPromptUser_DirectCommandProgramConfirm(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, fullPromptRequest())

	h.down(4) // allow globally permanently
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopePage)
	h.down(1)
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopeConfirmPage)

	h.key(tcell.KeyEnter) // cursor opens on "Confirm program-wide grant": one keypress confirms

	d := h.await()
	if d.Option != OptionAllowGlobal {
		t.Fatalf("Option = %d, want OptionAllowGlobal (%d)", d.Option, OptionAllowGlobal)
	}
	if d.StoredSubject != "git :*" {
		t.Fatalf("StoredSubject = %q, want %q", d.StoredSubject, "git :*")
	}
}

func TestPromptUser_DirectCommandProgramCancel(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, fullPromptRequest())

	h.down(2) // allow for this session
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopePage)
	h.down(1)
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopeConfirmPage)

	h.down(1)             // "Confirm program-wide grant" → "Cancel"
	h.key(tcell.KeyEnter) // cancel

	// Page removal is the barrier proving the cancel handler ran, so the absence of a
	// decision can then be read off the channel without blocking.
	h.waitPageGone(promptScopeConfirmPage)
	select {
	case d := <-h.decc:
		h.a.app.Stop()
		t.Fatalf("cancelling the program confirm produced a decision: %+v", d)
	default:
	}
	if _, ok := focusedPrimitive(h).(*tview.List); !ok {
		h.a.app.Stop()
		t.Fatalf("cancel did not restore focus to the scope chooser; focus=%T", focusedPrimitive(h))
	}

	h.key(tcell.KeyUp)
	h.key(tcell.KeyUp)
	h.key(tcell.KeyUp)
	h.key(tcell.KeyEnter)
	d := h.await()
	if d.Option != OptionAllowSession {
		t.Fatalf("Option = %d, want OptionAllowSession (%d)", d.Option, OptionAllowSession)
	}
	if d.StoredSubject != "git log --oneline" {
		t.Fatalf("StoredSubject = %q, want %q (Exact after cancel)", d.StoredSubject, "git log --oneline")
	}
}

func prefixPromptRequest() PromptRequest {
	req := fullPromptRequest()
	req.Subject = "prep-open-tasks.sh --only c175 --force"
	req.CanonicalProgram = "prep-open-tasks.sh"
	req.CanonicalArgs = []string{"--only", "c175", "--force"}
	return req
}

func benignProgramRequest() PromptRequest {
	req := fullPromptRequest()
	req.Subject = "ls -la"
	req.CanonicalProgram = "ls"
	req.CanonicalArgs = []string{"-la"}
	return req
}

func TestProgramConfirm_DestructiveShowsStrongerWarning(t *testing.T) {
	a := New(nil)
	overlay, _ := a.buildProgramConfirm(fullPromptRequest(), OptionAllowGlobal, "git :*", make(chan PromptDecision, 1), tview.NewList())
	out := screenText(drawPrimitive(t, overlay, 100, 20))
	if !strings.Contains(out, "DESTRUCTIVE") {
		t.Errorf("destructive program confirm missing the stronger destructive warning\n--- got ---\n%s", out)
	}
	if !strings.Contains(out, "authorizes ANY invocation") {
		t.Errorf("destructive program confirm dropped the standard breadth warning\n--- got ---\n%s", out)
	}
}

// TestProgramConfirm_BenignKeepsStandardWarningOnly proves a benign program's Program
// confirm keeps the standard breadth warning and renders no destructive copy, drawing
// the real confirm overlay through the production classifier.
func TestProgramConfirm_BenignKeepsStandardWarningOnly(t *testing.T) {
	a := New(nil)
	overlay, _ := a.buildProgramConfirm(benignProgramRequest(), OptionAllowSession, "ls :*", make(chan PromptDecision, 1), tview.NewList())
	out := screenText(drawPrimitive(t, overlay, 100, 20))
	if !strings.Contains(out, "authorizes ANY invocation") {
		t.Errorf("benign program confirm missing the standard breadth warning\n--- got ---\n%s", out)
	}
	if strings.Contains(out, "DESTRUCTIVE") {
		t.Errorf("benign program confirm rendered destructive warning copy\n--- got ---\n%s", out)
	}
}

func TestProgramConfirm_StatesEffectiveGrantScope(t *testing.T) {
	req := benignProgramRequest()
	cases := []struct {
		name    string
		opt     PromptOption
		want    []string
		unwant  []string
		subject string
	}{
		{
			name:    "session",
			opt:     OptionAllowSession,
			subject: "ls :*",
			want:    []string{"ls :*", "direct command", "this session only", "/work/project/sub"},
			unwant:  []string{"all paths", "saved globally"},
		},
		{
			name:    "folder",
			opt:     OptionAllowFolder,
			subject: "ls :*",
			want:    []string{"ls :*", "direct command", "permanent", "/work/project/.codemeld/settings.yaml", "/work/project/sub"},
			unwant:  []string{"all paths", "this session only"},
		},
		{
			name:    "global",
			opt:     OptionAllowGlobal,
			subject: "ls :*",
			want:    []string{"ls :*", "direct command", "permanent", "saved globally", "any folder (all paths)"},
			unwant:  []string{"this session only", "/work/project/sub"},
		},
	}
	a := New(nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			overlay, _ := a.buildProgramConfirm(req, tc.opt, tc.subject, make(chan PromptDecision, 1), tview.NewList())
			out := screenText(drawPrimitive(t, overlay, 100, 24))
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("confirm copy missing %q\n--- got ---\n%s", want, out)
				}
			}
			for _, banned := range tc.unwant {
				if strings.Contains(out, banned) {
					t.Errorf("confirm copy claims %q for the %s grant\n--- got ---\n%s", banned, tc.name, out)
				}
			}
			if !strings.Contains(out, "authorizes ANY invocation") {
				t.Errorf("effective-grant statement displaced the breadth warning\n--- got ---\n%s", out)
			}
		})
	}
}

func TestProgramGrantEffect_Branches(t *testing.T) {
	for _, opt := range []PromptOption{OptionAllowOnce, OptionDeny, OptionAllowProject} {
		if got := programGrantEffect(benignProgramRequest(), opt, "ls :*"); got != "" {
			t.Errorf("programGrantEffect for option %d = %q, want empty", opt, got)
		}
	}

	bare := PromptRequest{Kind: SubjectDirectCommand, CanonicalProgram: "ls", RunFolder: "/work/project/sub"}
	folder := programGrantEffect(bare, OptionAllowFolder, "ls :*")
	if strings.Contains(folder, "saved to \n") {
		t.Errorf("folder statement trails an empty settings path: %q", folder)
	}
	if !strings.Contains(folder, "saved to this project's settings") {
		t.Errorf("folder statement drops where the grant is saved: %q", folder)
	}
	if !strings.Contains(folder, "/work/project/sub and its descendants") {
		t.Errorf("folder statement drops the run-folder coverage: %q", folder)
	}
	if session := programGrantEffect(bare, OptionAllowSession, "ls :*"); !strings.Contains(session, "/work/project/sub and its descendants") {
		t.Errorf("session statement drops the run-folder coverage: %q", session)
	}
}

func TestProgramConfirm_OutOfProjectFolderGrantCoverage(t *testing.T) {
	a := New(nil)
	overlay, _ := a.buildProgramConfirm(outsideProjectDirectRequest(), OptionAllowFolder, "git :*", make(chan PromptDecision, 1), tview.NewList())
	out := screenText(drawPrimitive(t, overlay, 100, 24))

	if !strings.Contains(out, "/elsewhere/outside and all descendants") {
		t.Errorf("folder confirm does not name the covered out-of-project folder\n--- got ---\n%s", out)
	}
	if !strings.Contains(out, "/work/project/.codemeld/settings.yaml") {
		t.Errorf("folder confirm does not name where the grant is saved\n--- got ---\n%s", out)
	}
}

func TestPromptUser_OutOfProjectShellFolderGrantReachable(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, outsideProjectDirectRequest())

	h.down(3)
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopePage)
	h.down(1)
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopeConfirmPage)
	h.key(tcell.KeyEnter)

	d := h.await()
	if d.Option != OptionAllowFolder {
		t.Fatalf("Option = %d, want OptionAllowFolder (%d)", d.Option, OptionAllowFolder)
	}
	if d.StoredSubject != "git :*" {
		t.Fatalf("StoredSubject = %q, want %q", d.StoredSubject, "git :*")
	}
}

func TestPromptUser_ProgramConfirmDestructiveWiring(t *testing.T) {
	cases := []struct {
		name        string
		req         PromptRequest
		wantSubject string
		destructive bool
		toProgram   int
	}{
		{"destructive git", fullPromptRequest(), "git :*", true, 1},
		{"benign ls", benignProgramRequest(), "ls :*", false, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			h := startPrompt(t, a, tc.req)

			h.down(2)
			h.key(tcell.KeyEnter)
			h.waitPage(promptScopePage)
			h.down(tc.toProgram)
			h.key(tcell.KeyEnter)
			h.waitPage(promptScopeConfirmPage)

			out := readScreenSync(t, h.a, h.screen)
			if got := strings.Contains(out, "DESTRUCTIVE"); got != tc.destructive {
				t.Errorf("destructive warning present = %v, want %v\n--- got ---\n%s", got, tc.destructive, out)
			}

			h.key(tcell.KeyEnter) // cursor opens on confirm: one keypress finalizes
			d := h.await()
			if d.StoredSubject != tc.wantSubject {
				t.Fatalf("StoredSubject = %q, want %q (warning copy must not change the stored subject)", d.StoredSubject, tc.wantSubject)
			}
		})
	}
}

// TestPromptUser_DirectCommandAllowOnceSkipsScopeChooser proves "allow this once"
// creates no grant and so finalizes immediately with no stored subject even for a
// direct-command subject (applies only to grant-creating options).
func TestPromptUser_DirectCommandAllowOnceSkipsScopeChooser(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, fullPromptRequest())

	h.key(tcell.KeyEnter) // allow this once (default highlight)

	d := h.await()
	if d.Option != OptionAllowOnce {
		t.Fatalf("Option = %d, want OptionAllowOnce (%d)", d.Option, OptionAllowOnce)
	}
	if d.StoredSubject != "" {
		t.Fatalf("StoredSubject = %q, want empty (no grant created)", d.StoredSubject)
	}
}

// TestScopeChooser_RendersBreadthPhrases proves the rendered scope-chooser overlay
// visibly states each row's breadth in human terms — narrow → wide — so "allow any
// invocation of git" no longer reads with the same weight as "allow this exact
// command". It draws the production buildScopeChooser primitive synchronously.
func TestScopeChooser_RendersBreadthPhrases(t *testing.T) {
	a := New(nil)
	overlay, _ := a.buildScopeChooser(fullPromptRequest(), OptionAllowSession, make(chan PromptDecision, 1))
	out := screenText(drawPrimitive(t, overlay, 100, 20))

	for _, phrase := range []string{
		"only this exact command",
		"fixed: git log; any later arguments may vary",
		"ANY invocation of git (widest)",
	} {
		if !strings.Contains(out, phrase) {
			t.Errorf("rendered scope chooser missing breadth phrase %q\n--- got ---\n%s", phrase, out)
		}
	}
}

func TestScopeChooser_RendersPrefixRowsAndContract(t *testing.T) {
	a := New(nil)
	overlay, list := a.buildScopeChooser(prefixPromptRequest(), OptionAllowSession, make(chan PromptDecision, 1))
	out := screenText(drawPrimitive(t, overlay, 160, 24))

	for _, phrase := range []string{
		"prefix: prep-open-tasks.sh --only c175 --force :*",
		"prefix: prep-open-tasks.sh --only c175 :*",
		"prefix: prep-open-tasks.sh --only :*",
		"fixed: prep-open-tasks.sh --only; any later arguments may vary",
		"exact: prep-open-tasks.sh --only c175 --force",
		"program (advanced): prep-open-tasks.sh :*",
		scopePrefixNotice,
	} {
		if !strings.Contains(out, phrase) {
			t.Errorf("rendered scope chooser missing %q\n--- got ---\n%s", phrase, out)
		}
	}
	if strings.Contains(out, "subcommand:") {
		t.Errorf("direct chooser still labels a middle row \"subcommand\"\n--- got ---\n%s", out)
	}

	current := list.GetCurrentItem()
	label, _ := list.GetItemText(current)
	if want := "prefix: prep-open-tasks.sh --only c175 :* — fixed: prep-open-tasks.sh --only c175; any later arguments may vary" + scopeRecommendedSuffix; label != want {
		t.Errorf("chooser opens on row %d (%q), want the recommended inferred prefix %q", current, label, want)
	}
	marked := 0
	for i := 0; i < list.GetItemCount(); i++ {
		if text, _ := list.GetItemText(i); strings.HasSuffix(text, scopeRecommendedSuffix) {
			marked++
		}
	}
	if marked != 1 {
		t.Errorf("%d rows carry the recommended marker, want exactly 1", marked)
	}
}

func TestRenderPrompt_CapabilityCoverageWording(t *testing.T) {
	cases := []struct {
		name    string
		subject string
		want    string
	}{
		{"write", permissions.CapabilityWrite, "writing (create + edit)"},
		{"write_tree", permissions.CapabilityWriteTree, "creating and editing files and folders (create + edit + mkdir)"},
		{"read*", permissions.CapabilityRead, "reading/searching (read + grep + glob + list + tree + file_count)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := PromptRequest{
				Action:                  "Create file",
				Subject:                 "a.go",
				Kind:                    SubjectStructuredTool,
				RunFolder:               "/work",
				CapabilityStoredSubject: tc.subject,
			}
			out := renderPrompt(req)
			if !strings.Contains(out, tc.want) {
				t.Fatalf("rendered prompt missing capability coverage %q\n--- got ---\n%s", tc.want, out)
			}
			if !strings.Contains(out, "not just this one tool") {
				t.Fatalf("rendered prompt missing the capability coverage framing\n--- got ---\n%s", out)
			}
		})
	}
	t.Run("no capability subject shows no coverage line", func(t *testing.T) {
		req := PromptRequest{Action: "Run tool", Subject: "read_file", Kind: SubjectStructuredTool, RunFolder: "/work"}
		if out := renderPrompt(req); strings.Contains(out, "not just this one tool") {
			t.Fatalf("non-capability prompt rendered a coverage line\n--- got ---\n%s", out)
		}
	})
}

func TestRenderPrompt_MergedQuestionStatesItsSharedCapabilityCoverageOnce(t *testing.T) {
	req := PromptRequest{
		Action:                  "Run tool",
		Kind:                    SubjectStructuredTool,
		RunFolder:               "/work",
		Body:                    "read({\"path\":\"/outside/a.txt\"})\nread({\"path\":\"/outside/b.txt\"})",
		CapabilityStoredSubject: permissions.CapabilityRead,
	}
	out := renderPrompt(req)
	want := "Approving a grant below allows reading/searching (read + grep + glob + list + tree + file_count) in this scope — not just this one tool."
	if !strings.Contains(out, want) {
		t.Fatalf("merged question hid its capability-wide scope\nwant %q\n--- got ---\n%s", want, out)
	}
	if n := strings.Count(out, "not just this one tool"); n != 1 {
		t.Fatalf("capability coverage stated %d times, want once for the whole question\n--- got ---\n%s", n, out)
	}
}

func TestPromptUser_StructuredToolGrantStoresCapabilitySubject(t *testing.T) {
	a := New(nil)
	req := PromptRequest{
		Action:                  "Create file",
		Subject:                 "a.go",
		Body:                    "x\n",
		Kind:                    SubjectStructuredTool,
		RunFolder:               "/work",
		CapabilityStoredSubject: permissions.CapabilityWrite,
	}
	h := startPrompt(t, a, req)

	h.down(2) // allow for this session
	h.key(tcell.KeyEnter)

	d := h.await()
	if d.Option != OptionAllowSession {
		t.Fatalf("Option = %d, want OptionAllowSession (%d)", d.Option, OptionAllowSession)
	}
	if d.StoredSubject != permissions.CapabilityWrite {
		t.Fatalf("StoredSubject = %q, want %q (a structured-tool grant stores the capability subject)", d.StoredSubject, permissions.CapabilityWrite)
	}
}

// TestPromptUser_StructuredToolAllowOnceStoresNoSubject proves allow-once on a capability-carrying
// structured-tool prompt creates no grant, so it returns no stored subject even though the request
// carries a capability stored subject (the fold applies only to grant-creating options).
func TestPromptUser_StructuredToolAllowOnceStoresNoSubject(t *testing.T) {
	a := New(nil)
	req := PromptRequest{
		Action:                  "Create file",
		Subject:                 "a.go",
		Kind:                    SubjectStructuredTool,
		RunFolder:               "/work",
		CapabilityStoredSubject: permissions.CapabilityWrite,
	}
	h := startPrompt(t, a, req)

	h.key(tcell.KeyEnter) // allow this once (default highlight)

	d := h.await()
	if d.Option != OptionAllowOnce {
		t.Fatalf("Option = %d, want OptionAllowOnce (%d)", d.Option, OptionAllowOnce)
	}
	if d.StoredSubject != "" {
		t.Fatalf("StoredSubject = %q, want empty (allow-once creates no grant)", d.StoredSubject)
	}
}

// TestPromptUser_LiteralCommandSkipsScopeChooser proves a non-direct-command
// subject offers no scope sub-choice: a grant-creating selection finalizes
// immediately with no stored subject.
func TestPromptUser_LiteralCommandSkipsScopeChooser(t *testing.T) {
	a := New(nil)
	req := PromptRequest{
		Action:    "Run command",
		Subject:   "psql -c 'select 1'",
		Kind:      SubjectLiteralCommand,
		RunFolder: "/work",
	}
	h := startPrompt(t, a, req)

	h.down(2) // allow for this session
	h.key(tcell.KeyEnter)

	d := h.await()
	if d.Option != OptionAllowSession {
		t.Fatalf("Option = %d, want OptionAllowSession (%d)", d.Option, OptionAllowSession)
	}
	if d.StoredSubject != "" {
		t.Fatalf("StoredSubject = %q, want empty (no scope sub-choice for literal command)", d.StoredSubject)
	}
}

// compoundPromptRequest builds a recognized simple-compound prompt request from a
// decomposition. Simple compounds arrive as literal-command subjects, so Kind is
// SubjectLiteralCommand and the recognized stages/operators ride on Compound; a
// session anchor is set so "allow for this session" (a grant-creating option) is
// reachable at the fixed index.
func compoundPromptRequest(sc permissions.SimpleCompound) PromptRequest {
	return PromptRequest{
		Action:    "Run command",
		Subject:   "go build ./... && gofmt -w a.go",
		Kind:      SubjectLiteralCommand,
		RunFolder: "/work",
		Compound:  &sc,
	}
}

// TestPromptUser_CompoundTwoStageDefaultsExact proves a recognized two-stage simple
// compound opens the per-stage chooser and that every stage defaults to the narrowest
// (Exact) scope: accepting both defaults stores the backend-encoded compound subject
// built from the two Exact stage subjects, not from display labels.
func TestPromptUser_CompoundTwoStageDefaultsExact(t *testing.T) {
	sc := permissions.SimpleCompound{
		Stages:    [][]string{{"go", "build", "./..."}, {"gofmt", "-w", "a.go"}},
		Operators: []string{"&&"},
	}
	a := New(nil)
	h := startPrompt(t, a, compoundPromptRequest(sc))

	h.down(2) // allow for this session
	h.key(tcell.KeyEnter)
	h.waitPage(promptCompoundPage)

	// A non-destructive stage offers a Program row, so it keeps the generic
	// Program-scope breadth warning ("authorizes ANY invocation" survives wrapping).
	if out := readScreenSync(t, h.a, h.screen); !strings.Contains(out, "authorizes ANY invocation") {
		t.Fatalf("normal compound stage missing the Program-scope warning\n--- got ---\n%s", out)
	}

	h.key(tcell.KeyEnter) // stage 1 default = Exact
	h.key(tcell.KeyEnter) // stage 2 default = Exact

	d := h.await()
	if d.Option != OptionAllowSession {
		t.Fatalf("Option = %d, want OptionAllowSession (%d)", d.Option, OptionAllowSession)
	}
	want, err := permissions.EncodeCompoundSubject(false, []string{"go build ./...", "gofmt -w a.go"}, []string{"&&"})
	if err != nil {
		t.Fatalf("encode expected subject: %v", err)
	}
	if d.StoredSubject != want {
		t.Fatalf("StoredSubject = %q, want %q (both stages Exact, backend-encoded)", d.StoredSubject, want)
	}
}

// TestPromptUser_CompoundStaleFocusKeyRestoresChooser simulates the real terminal
// blur/return failure mode: focus is stale while the compound page remains mounted,
// then the next key re-focuses the active chooser and still reaches the list.
func TestPromptUser_CompoundStaleFocusKeyRestoresChooser(t *testing.T) {
	sc := permissions.SimpleCompound{
		Stages:    [][]string{{"go", "build", "./..."}, {"gofmt", "-w", "a.go"}},
		Operators: []string{"&&"},
	}
	a := New(nil)
	h := startPrompt(t, a, compoundPromptRequest(sc))

	h.down(2) // allow for this session
	h.key(tcell.KeyEnter)
	h.waitPage(promptCompoundPage)

	// Leave focus stale on a primitive that does NOT delegate to the compound
	// chooser (the input TextArea), while the compound page stays mounted. This is
	// the real blur/return failure: a terminal that never delivers a focus-gained
	// event strands focus off the active chooser. Focusing the mounted page wrapper
	// instead would delegate straight back into the list and hide the regression.
	h.a.app.QueueUpdate(func() {
		if !h.a.pages.HasPage(promptCompoundPage) {
			h.t.Fatal("compound prompt page is not mounted")
		}
		h.a.app.SetFocus(h.a.input)
	})

	if _, isList := focusedPrimitive(h).(*tview.List); isList {
		h.t.Fatal("pre-key focus is a *tview.List; stale-focus state was not established")
	}

	h.key(tcell.KeyDown)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if current, ok := focusedListItem(h); ok && current == 1 {
			break
		}
		if time.Now().After(deadline) {
			h.a.app.Stop()
			current, ok := focusedListItem(h)
			h.t.Fatalf("Down after stale-focus restore selected row %d, focused list=%v; want row 1", current, ok)
		}
	}

	h.key(tcell.KeyEnter) // stage 1 Subcommand after Down
	h.key(tcell.KeyEnter) // stage 2 default = Exact
	d := h.await()
	want, err := permissions.EncodeCompoundSubject(false, []string{"go build :*", "gofmt -w a.go"}, []string{"&&"})
	if err != nil {
		h.t.Fatalf("encode expected subject: %v", err)
	}
	if d.StoredSubject != want {
		h.t.Fatalf("StoredSubject = %q, want %q (stage 1 Subcommand after stale-focus restore)", d.StoredSubject, want)
	}
}

// TestPromptUser_CompoundEscapeDismisses proves Escape from the compound chooser
// safely denies the prompt instead of falling through to the stale underlying focus.
func TestPromptUser_CompoundEscapeDismisses(t *testing.T) {
	sc := permissions.SimpleCompound{
		Stages:    [][]string{{"go", "build", "./..."}, {"gofmt", "-w", "a.go"}},
		Operators: []string{"&&"},
	}
	a := New(nil)
	h := startPrompt(t, a, compoundPromptRequest(sc))

	h.down(2) // allow for this session
	h.key(tcell.KeyEnter)
	h.waitPage(promptCompoundPage)
	h.key(tcell.KeyEscape)

	d := h.await()
	if d.Option != OptionDeny {
		t.Fatalf("Escape decision = %d, want OptionDeny (%d)", d.Option, OptionDeny)
	}
	if want := permissions.BuildDenyEnvelope(""); d.DenyEnvelope != want {
		t.Fatalf("Escape DenyEnvelope = %q, want default %q", d.DenyEnvelope, want)
	}
}

// TestPromptUser_CompoundProgramConfirmPerStage proves a Program choice for a
// non-destructive stage reuses the inline confirm step, and that confirming each
// stage records its Program subject: confirming Program on both stages stores the
// backend-encoded compound built from the two `<program> :*` subjects.
func TestPromptUser_CompoundProgramConfirmPerStage(t *testing.T) {
	sc := permissions.SimpleCompound{
		Stages:    [][]string{{"go", "build", "./..."}, {"gofmt", "-w", "a.go"}},
		Operators: []string{"&&"},
	}
	a := New(nil)
	h := startPrompt(t, a, compoundPromptRequest(sc))

	h.down(2) // allow for this session
	h.key(tcell.KeyEnter)
	h.waitPage(promptCompoundPage)

	// Stage 1: Exact (default) → down to Program (third row), confirm.
	h.down(2)
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopeConfirmPage)
	h.key(tcell.KeyEnter) // cursor opens on confirm

	// Stage 2: Program, confirm.
	h.down(2)
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopeConfirmPage)
	h.key(tcell.KeyEnter)

	d := h.await()
	want, err := permissions.EncodeCompoundSubject(false, []string{"go :*", "gofmt :*"}, []string{"&&"})
	if err != nil {
		t.Fatalf("encode expected subject: %v", err)
	}
	if d.StoredSubject != want {
		t.Fatalf("StoredSubject = %q, want %q (both stages Program)", d.StoredSubject, want)
	}
}

// TestPromptUser_CompoundProgramConfirmEscapeDismisses proves Escape from a
// compound Program-confirm overlay safely denies the whole permission prompt.
func TestPromptUser_CompoundProgramConfirmEscapeDismisses(t *testing.T) {
	sc := permissions.SimpleCompound{
		Stages:    [][]string{{"go", "build", "./..."}, {"gofmt", "-w", "a.go"}},
		Operators: []string{"&&"},
	}
	a := New(nil)
	h := startPrompt(t, a, compoundPromptRequest(sc))

	h.down(2) // allow for this session
	h.key(tcell.KeyEnter)
	h.waitPage(promptCompoundPage)
	h.down(2) // Program
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopeConfirmPage)
	h.key(tcell.KeyEscape)

	d := h.await()
	if d.Option != OptionDeny {
		t.Fatalf("Escape decision = %d, want OptionDeny (%d)", d.Option, OptionDeny)
	}
	if want := permissions.BuildDenyEnvelope(""); d.DenyEnvelope != want {
		t.Fatalf("Escape DenyEnvelope = %q, want default %q", d.DenyEnvelope, want)
	}
}

// TestPromptUser_CompoundProgramCancelReturnsToChooser proves cancelling a stage's
// Program confirm creates no grant and restores focus to that stage's chooser, which
// stays usable: narrowing back to Exact and finishing the remaining stage finalizes
// the compound normally.
func TestPromptUser_CompoundProgramCancelReturnsToChooser(t *testing.T) {
	sc := permissions.SimpleCompound{
		Stages:    [][]string{{"go", "build", "./..."}, {"gofmt", "-w", "a.go"}},
		Operators: []string{"&&"},
	}
	a := New(nil)
	h := startPrompt(t, a, compoundPromptRequest(sc))

	h.down(2) // allow for this session
	h.key(tcell.KeyEnter)
	h.waitPage(promptCompoundPage)

	// Stage 1: choose Program, then cancel the confirm.
	h.down(2)
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopeConfirmPage)
	h.down(1)             // "Confirm program-wide grant" → "Cancel"
	h.key(tcell.KeyEnter) // cancel

	// Page removal is the barrier proving the cancel handler ran, so the absence of a
	// decision can then be read off the channel without blocking.
	h.waitPageGone(promptScopeConfirmPage)
	select {
	case d := <-h.decc:
		h.a.app.Stop()
		t.Fatalf("cancelling the compound program confirm produced a decision: %+v", d)
	default:
	}
	if _, ok := focusedPrimitive(h).(*tview.List); !ok {
		h.a.app.Stop()
		t.Fatalf("cancel did not restore focus to the compound chooser; focus=%T", focusedPrimitive(h))
	}

	// The stage chooser is still usable: move back up to Exact and finalize, then
	// accept stage 2's Exact default.
	h.key(tcell.KeyUp) // Program → Subcommand
	h.key(tcell.KeyUp) // Subcommand → Exact
	h.key(tcell.KeyEnter)
	h.key(tcell.KeyEnter) // stage 2 default = Exact

	d := h.await()
	want, err := permissions.EncodeCompoundSubject(false, []string{"go build ./...", "gofmt -w a.go"}, []string{"&&"})
	if err != nil {
		t.Fatalf("encode expected subject: %v", err)
	}
	if d.StoredSubject != want {
		t.Fatalf("StoredSubject = %q, want %q (Exact after cancel)", d.StoredSubject, want)
	}
}

// TestPromptUser_CompoundDestructiveStageExactOnly proves a compound stage whose
// program is destructive exposes only Exact (no widening rows are reachable), and that
// because the backend refuses to generalize a compound containing a destructive stage
// the grant falls back to a byte-exact subject (empty StoredSubject) rather than the
// UI synthesizing an alternative.
func TestPromptUser_CompoundDestructiveStageExactOnly(t *testing.T) {
	// The destructive stage is first so the synced page attach lands on it and its
	// rendered rows can be read directly.
	sc := permissions.SimpleCompound{
		Stages:    [][]string{{"rm", "-rf", "build"}, {"go", "build", "./..."}},
		Operators: []string{"&&"},
	}
	a := New(nil)
	h := startPrompt(t, a, compoundPromptRequest(sc))

	h.down(2) // allow for this session
	h.key(tcell.KeyEnter)
	h.waitPage(promptCompoundPage)

	out := readScreenSync(t, h.a, h.screen)
	if !strings.Contains(out, "exact: rm -rf build") {
		t.Fatalf("destructive stage missing its Exact row\n--- got ---\n%s", out)
	}
	if strings.Contains(out, "ANY invocation of rm") {
		t.Fatalf("destructive stage offered a Program (widening) row\n--- got ---\n%s", out)
	}
	if strings.Contains(out, "any rm build") {
		t.Fatalf("destructive stage offered a Subcommand (widening) row\n--- got ---\n%s", out)
	}
	// The generic Program-scope warning must be gone (it would read as contradictory
	// when Program is not offered) and replaced by the exact-only safety explanation.
	if strings.Contains(out, "authorizes ANY invocation") {
		t.Fatalf("destructive exact-only stage still shows the generic Program-scope warning\n--- got ---\n%s", out)
	}
	if !strings.Contains(out, "Exact scope only") {
		t.Fatalf("destructive exact-only stage missing the safety explanation for unavailable broader scopes\n--- got ---\n%s", out)
	}

	h.key(tcell.KeyEnter) // only Exact is selectable for the destructive stage
	h.key(tcell.KeyEnter) // stage 2 default = Exact

	d := h.await()
	if d.Option != OptionAllowSession {
		t.Fatalf("Option = %d, want OptionAllowSession (%d)", d.Option, OptionAllowSession)
	}
	if d.StoredSubject != "" {
		t.Fatalf("StoredSubject = %q, want empty (a compound with a destructive stage is not generalized)", d.StoredSubject)
	}
}

func outsideProjectLiteralRequest() PromptRequest {
	return PromptRequest{
		Action:             "Run command",
		Subject:            "rm -rf /elsewhere/outside/build",
		Kind:               SubjectLiteralCommand,
		RunFolder:          "/elsewhere/outside",
		ProjectRoot:        "/work/project",
		FolderSettingsPath: "/work/project/.codemeld/settings.yaml",
		FolderCoverage:     "/elsewhere/outside and all descendants",
	}
}

func outsideProjectDirectRequest() PromptRequest {
	return PromptRequest{
		Action:             "Run command",
		Subject:            "git status",
		Kind:               SubjectDirectCommand,
		CanonicalProgram:   "git",
		CanonicalArgs:      []string{"status"},
		RunFolder:          "/elsewhere/outside",
		ProjectRoot:        "/work/project",
		FolderSettingsPath: "/work/project/.codemeld/settings.yaml",
		FolderCoverage:     "/elsewhere/outside and all descendants",
	}
}

func outsideProjectToolRequest() PromptRequest {
	return PromptRequest{
		Action:             "Run tool",
		Subject:            "/elsewhere/outside/data.json",
		Kind:               SubjectStructuredTool,
		RunFolder:          "/elsewhere/outside",
		ProjectRoot:        "/work/project",
		FolderSettingsPath: "/work/project/.codemeld/settings.yaml",
		FolderCoverage:     "/elsewhere/outside and all descendants",
	}
}

// TestDisplayedPromptOptions_ContainmentDrivesFolderOption proves the option
// slice that drives both rendering and the decision path includes the folder
// option when the path scope is the project root or a descendant, and
// drops only the folder option — preserving allow-once/deny/session/global in
// relative order — when it is outside.
func TestDisplayedPromptOptions_ContainmentDrivesFolderOption(t *testing.T) {
	inside := displayedPromptOptions(fullPromptRequest()) // RunFolder is a descendant of ProjectRoot
	wantInside := []PromptOption{
		OptionAllowOnce, OptionDeny, OptionAllowSession, OptionAllowFolder, OptionAllowGlobal,
	}
	if !equalOptions(inside, wantInside) {
		t.Errorf("inside-project options = %v, want %v", optionValues(inside), wantInside)
	}

	outside := displayedPromptOptions(outsideProjectToolRequest())
	wantOutside := []PromptOption{
		OptionAllowOnce, OptionDeny, OptionAllowSession, OptionAllowGlobal,
	}
	if !equalOptions(outside, wantOutside) {
		t.Errorf("outside-project options = %v, want %v", optionValues(outside), wantOutside)
	}
	for _, o := range outside {
		if o.Option == OptionAllowFolder {
			t.Fatalf("folder option present in outside-project decision path: %v", optionValues(outside))
		}
	}
}

func optionValues(rows []promptOptionRow) []PromptOption {
	out := make([]PromptOption, len(rows))
	for i, r := range rows {
		out[i] = r.Option
	}
	return out
}

func equalOptions(rows []promptOptionRow, want []PromptOption) bool {
	if len(rows) != len(want) {
		return false
	}
	for i := range rows {
		if rows[i].Option != want[i] {
			return false
		}
	}
	return true
}

// TestPromptOverlay_FolderOptionOmittedOutsideProject proves the rendered option
// list drops the folder option and keeps the remaining four in order
// when the path scope is outside the project root.
func TestPromptOverlay_FolderOptionOmittedOutsideProject(t *testing.T) {
	a := New(nil)
	_, list := a.buildPromptOverlay(outsideProjectToolRequest(), make(chan PromptDecision, 1))

	wantRows := []promptOptionRow{
		{OptionAllowOnce, "allow this once"},
		{OptionDeny, "deny"},
		{OptionAllowSession, "allow for this session"},
		{OptionAllowGlobal, "allow globally permanently"},
	}
	if got := list.GetItemCount(); got != len(wantRows) {
		t.Fatalf("list item count = %d, want %d (folder option omitted)", got, len(wantRows))
	}
	for i, row := range wantRows {
		want := promptRowLabel(row)
		if got, _ := list.GetItemText(i); got != want {
			t.Errorf("list item %d = %q, want %q", i, got, want)
		}
	}
	for i := 0; i < list.GetItemCount(); i++ {
		if got, _ := list.GetItemText(i); got == "allow in this folder permanently" {
			t.Fatalf("folder option still rendered at index %d when path scope is outside the project root", i)
		}
	}
}

// TestRenderPrompt_FolderDetailOnlyWhenOffered proves the upper info block shows
// the folder write-target detail only when the folder option is offered (path
// scope inside the project root) and never carries the unavailable
// explanation — that explanation belongs below the option list (proven by
// TestPromptOverlay_FolderUnavailableExplanationBelowList), not in this block.
func TestRenderPrompt_FolderDetailOnlyWhenOffered(t *testing.T) {
	outside := renderPrompt(outsideProjectToolRequest())
	if strings.Contains(outside, folderUnavailableExplanation) {
		t.Errorf("folder-unavailable explanation rendered in the upper info block; it must appear below the option list\n%s", outside)
	}
	if strings.Contains(outside, "writes to:") {
		t.Errorf("folder write-target detail rendered despite the folder option being omitted\n%s", outside)
	}

	inside := renderPrompt(fullPromptRequest())
	if strings.Contains(inside, folderUnavailableExplanation) {
		t.Errorf("folder-unavailable explanation shown when path scope is inside the project root\n%s", inside)
	}
	if !strings.Contains(inside, "saved to /work/project/.codemeld/settings.yaml so it survives restart") {
		t.Errorf("folder write-target detail missing when the folder option is offered\n%s", inside)
	}
}

func TestPromptOverlay_FolderUnavailableExplanationBelowList(t *testing.T) {
	a := New(nil)

	overlay, _ := a.buildPromptOverlay(outsideProjectToolRequest(), make(chan PromptDecision, 1))
	flex, ok := overlay.(*tview.Flex)
	if !ok {
		t.Fatalf("overlay is %T, want *tview.Flex", overlay)
	}

	listIdx, noteIdx := -1, -1
	for i := 0; i < flex.GetItemCount(); i++ {
		switch p := flex.GetItem(i).(type) {
		case *tview.List:
			listIdx = i
		case *tview.TextView:
			if strings.Contains(p.GetText(false), folderUnavailableExplanation) {
				noteIdx = i
			}
		}
	}
	if listIdx == -1 {
		t.Fatal("option list not found in overlay flex")
	}
	if noteIdx == -1 {
		t.Fatal("folder-unavailable explanation not rendered in the overlay")
	}
	if noteIdx <= listIdx {
		t.Errorf("explanation flex index %d must be below the option list index %d (req 275)", noteIdx, listIdx)
	}

	insideOverlay, _ := a.buildPromptOverlay(fullPromptRequest(), make(chan PromptDecision, 1))
	insideFlex, ok := insideOverlay.(*tview.Flex)
	if !ok {
		t.Fatalf("inside-project overlay is %T, want *tview.Flex", insideOverlay)
	}
	if got := insideFlex.GetItemCount(); got != 4 {
		t.Errorf("inside-project overlay has %d flex rows, want 4 (preview + divider + facts + list, no below-list explanation)", got)
	}
}

func TestPromptOverlay_DividerAboveFactsAndOptions(t *testing.T) {
	a := New(nil)
	overlay, _ := a.buildPromptOverlay(fullPromptRequest(), make(chan PromptDecision, 1))
	flex, ok := overlay.(*tview.Flex)
	if !ok {
		t.Fatalf("overlay is %T, want *tview.Flex", overlay)
	}

	previewIdx, dividerIdx, factsIdx, listIdx := -1, -1, -1, -1
	for i := 0; i < flex.GetItemCount(); i++ {
		switch p := flex.GetItem(i).(type) {
		case *tview.List:
			listIdx = i
		case *tview.TextView:
			if strings.Contains(p.GetText(false), "Run folder:") {
				factsIdx = i
			} else if previewIdx == -1 {
				previewIdx = i
			}
		case *tview.Box:
			dividerIdx = i
		}
	}
	if previewIdx == -1 || dividerIdx == -1 || factsIdx == -1 || listIdx == -1 {
		t.Fatalf("overlay rows: preview=%d divider=%d facts=%d list=%d, want all present", previewIdx, dividerIdx, factsIdx, listIdx)
	}
	if previewIdx >= dividerIdx || dividerIdx >= factsIdx || factsIdx >= listIdx {
		t.Errorf("rows must be preview(%d) < divider(%d) < facts(%d) < list(%d)", previewIdx, dividerIdx, factsIdx, listIdx)
	}
}

var promptDrawnOptionLabels = []string{
	"allow this [o]nce",
	"[d]eny",
	"allow for this [s]ession",
	"allow in this [f]older permanently",
	"allow [g]lobally permanently",
}

func TestPromptOverlay_OptionLabelsBold(t *testing.T) {
	a := New(nil)
	overlay, list := a.buildPromptOverlay(fullPromptRequest(), make(chan PromptDecision, 1))
	screen := drawPrimitive(t, overlay, 100, 30)
	cells, width, _ := screen.GetContents()

	if got := list.GetItemCount(); got != len(promptDrawnOptionLabels) {
		t.Fatalf("list item count = %d, want %d", got, len(promptDrawnOptionLabels))
	}
	if got := list.GetCurrentItem(); got != 0 {
		t.Fatalf("default highlighted item = %d, want 0 (allow this once)", got)
	}
	lx, ly, _, _ := list.GetRect()
	for i, label := range promptDrawnOptionLabels {
		row := ly + i
		for col, want := range []rune(label) {
			cell := cells[row*width+lx+col]
			if len(cell.Runes) == 0 || cell.Runes[0] != want {
				t.Fatalf("option %d cell %d = %q, want %q; the drawn row does not match the label", i, col, string(cell.Runes), string(want))
			}
			_, _, attrs := cell.Style.Decompose()
			if attrs&tcell.AttrBold == 0 {
				t.Fatalf("option %d (%q) cell %d is not bold (selected=%v)", i, label, col, i == 0)
			}
			if reversed := attrs&tcell.AttrReverse != 0; reversed != (i == 0) {
				t.Fatalf("option %d (%q) cell %d reverse-video = %v, want %v", i, label, col, reversed, i == 0)
			}
		}
	}
}

var hostDrawnOptionLabels = []string{
	"allow this [o]nce",
	"[d]eny",
	"allow for this [s]ession",
	"allow in this [p]roject",
}

func TestPromptOverlay_MnemonicLabelsAccented(t *testing.T) {
	cases := []struct {
		name string
		req  PromptRequest
		want []string
	}{
		{"direct command", fullPromptRequest(), promptDrawnOptionLabels},
		{"host", hostPromptRequest(), hostDrawnOptionLabels},
		{"host fresh confirmation", hostFreshConfirmationRequest(), hostDrawnOptionLabels[:2]},
	}
	accent := tcell.NewHexColor(0x1f9e8f)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			overlay, list := a.buildPromptOverlay(tc.req, make(chan PromptDecision, 1))
			screen := drawPrimitive(t, overlay, 100, 30)
			cells, width, _ := screen.GetContents()

			if got := list.GetItemCount(); got != len(tc.want) {
				t.Fatalf("list item count = %d, want %d", got, len(tc.want))
			}
			lx, ly, _, _ := list.GetRect()
			for i, label := range tc.want {
				open := strings.IndexByte(label, '[')
				if open < 0 {
					t.Errorf("option %d (%q) carries no bracketed mnemonic; every rendered option must have one", i, label)
				}
				for col, r := range []rune(label) {
					cell := cells[(ly+i)*width+lx+col]
					if len(cell.Runes) == 0 || cell.Runes[0] != r {
						t.Fatalf("option %d cell %d = %q, want %q", i, col, string(cell.Runes), string(r))
					}
					fg, _, _ := cell.Style.Decompose()
					inMnemonic := open >= 0 && col >= open && col <= open+2
					if inMnemonic && fg != accent {
						t.Errorf("option %d (%q) cell %d (%q) foreground = %v, want the accent %v", i, label, col, string(r), fg, accent)
					}
					if !inMnemonic && fg == accent {
						t.Errorf("option %d (%q) cell %d (%q) is accented outside the bracketed mnemonic", i, label, col, string(r))
					}
				}
			}
		})
	}
}

func TestPromptOverlay_LiteralDisplayText(t *testing.T) {
	shell := PromptRequest{
		Action:    "Run command",
		Subject:   `grep -R "[red]needle[white]" .`,
		Kind:      SubjectDirectCommand,
		RunFolder: "/work/[green]/project",
	}
	a := New(nil)
	shellOverlay, _ := a.buildPromptOverlay(shell, make(chan PromptDecision, 1))
	out := screenText(drawPrimitive(t, shellOverlay, 120, 30))
	for _, want := range []string{`Command: grep -R "[red]needle[white]" .`, "/work/[green]/project"} {
		if !strings.Contains(out, want) {
			t.Errorf("shell overlay did not render %q literally\n--- got ---\n%s", want, out)
		}
	}

	tool := PromptRequest{
		Action:    "Create file",
		Subject:   "[blue]notes.md",
		Body:      "line one [yellow]tagged[-] text",
		Kind:      SubjectStructuredTool,
		RunFolder: "/work",
	}
	toolOverlay, _ := a.buildPromptOverlay(tool, make(chan PromptDecision, 1))
	out = screenText(drawPrimitive(t, toolOverlay, 120, 30))
	for _, want := range []string{"[blue]notes.md", "line one [yellow]tagged[-] text"} {
		if !strings.Contains(out, want) {
			t.Errorf("structured-tool overlay did not render %q literally\n--- got ---\n%s", want, out)
		}
	}
}

func editPatchRequest(path, patch string) PromptRequest {
	return PromptRequest{
		Action:    "Edit file",
		Subject:   path,
		Body:      patch,
		Kind:      SubjectStructuredTool,
		RunFolder: "/work",
	}
}

func drawnCellStyle(t *testing.T, screen tcell.SimulationScreen, token string) (tcell.Style, int, int) {
	t.Helper()
	cells, width, height := screen.GetContents()
	want := []rune(token)
	for y := 0; y < height; y++ {
		row := make([]rune, width)
		for x := 0; x < width; x++ {
			if runes := cells[y*width+x].Runes; len(runes) > 0 {
				row[x] = runes[0]
			} else {
				row[x] = ' '
			}
		}
		for x := 0; x+len(want) <= width; x++ {
			if string(row[x:x+len(want)]) == token {
				return cells[y*width+x].Style, y, x
			}
		}
	}
	t.Fatalf("token %q was never drawn\n--- screen ---\n%s", token, screenText(screen))
	return tcell.StyleDefault, 0, 0
}

func TestPromptOverlay_EditPatchColorsChangedLinesOnly(t *testing.T) {
	patch := "--- /work/notes.txt\n+++ /work/notes.txt\n@@ -1,5 +1,5 @@\n ctxone\n ctxtwo\n-oldline\n+newline\n ctxthree\n"
	a := New(nil)
	overlay, _ := a.buildPromptOverlay(editPatchRequest("notes.txt", patch), make(chan PromptDecision, 1))
	screen := drawPrimitive(t, overlay, 120, 30)

	cases := []struct {
		token string
		want  tcell.Color
	}{
		{"--- /work/notes.txt", tcell.ColorDefault},
		{"+++ /work/notes.txt", tcell.ColorDefault},
		{"@@ -1,5 +1,5 @@", tcell.ColorDefault},
		{"ctxone", tcell.ColorDefault},
		{"ctxtwo", tcell.ColorDefault},
		{"ctxthree", tcell.ColorDefault},
		{"-oldline", tcell.ColorRed},
		{"+newline", tcell.ColorGreen},
	}
	for _, tc := range cases {
		style, row, col := drawnCellStyle(t, screen, tc.token)
		fg, _, _ := style.Decompose()
		if fg != tc.want {
			t.Errorf("patch line %q drawn at (%d,%d) with foreground %v, want %v", tc.token, row, col, fg, tc.want)
		}
	}

	tail, _, _ := drawnCellStyle(t, screen, "oldline")
	if fg, _, _ := tail.Decompose(); fg != tcell.ColorRed {
		t.Errorf("removed line content foreground = %v, want red across the whole line", fg)
	}
}

func TestPromptOverlay_EditPatchTagLikeTextStaysLiteral(t *testing.T) {
	patch := "--- /work/[red]notes.txt\n" +
		"+++ /work/[red]notes.txt\n" +
		"@@ -1,4 +1,4 @@\n" +
		" ctxone\n" +
		"-old [yellow]tagged[-] redzone\n" +
		"+new [\"region\"]greenzone\n" +
		" ctxtwo\n"
	a := New(nil)
	overlay, _ := a.buildPromptOverlay(editPatchRequest("[blue]notes.txt", patch), make(chan PromptDecision, 1))
	screen := drawPrimitive(t, overlay, 120, 30)
	out := screenText(screen)

	for _, want := range []string{
		"[blue]notes.txt",
		"--- /work/[red]notes.txt",
		`-old [yellow]tagged[-] redzone`,
		`+new ["region"]greenzone`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("edit overlay did not render %q literally\n--- got ---\n%s", want, out)
		}
	}

	for _, tc := range []struct {
		token string
		want  tcell.Color
	}{
		{"-old", tcell.ColorRed},
		{"redzone", tcell.ColorRed},
		{"+new", tcell.ColorGreen},
		{"greenzone", tcell.ColorGreen},
		{"ctxone", tcell.ColorDefault},
		{"ctxtwo", tcell.ColorDefault},
	} {
		style, row, col := drawnCellStyle(t, screen, tc.token)
		if fg, _, _ := style.Decompose(); fg != tc.want {
			t.Errorf("token %q at (%d,%d) foreground = %v, want %v (embedded tags must not restyle it)", tc.token, row, col, fg, tc.want)
		}
	}
}

func TestRenderPromptPreview_OnlyEditBodyIsColored(t *testing.T) {
	body := "--- \n+++ \n@@ -1 +1 @@\n-alpha\n+beta\n"

	edit := renderPromptPreview(editPatchRequest("notes.txt", body+"\\ No newline at end of file\n"))
	if !strings.Contains(edit, patchRemovedColor+"-alpha"+defaultTag) || !strings.Contains(edit, patchAddedColor+"+beta"+defaultTag) {
		t.Errorf("edit preview did not color the patch's changed lines\n--- got ---\n%s", edit)
	}
	if !strings.Contains(edit, "\n\\ No newline at end of file\n") {
		t.Errorf("edit preview colored or dropped the no-newline marker\n--- got ---\n%s", edit)
	}

	create := renderPromptPreview(PromptRequest{Action: "Create file", Subject: "notes.txt", Body: body, Kind: SubjectStructuredTool, RunFolder: "/work"})
	if !strings.Contains(create, body) {
		t.Errorf("create preview must keep its content verbatim\n--- got ---\n%s", create)
	}
	for _, tag := range []string{patchRemovedColor, patchAddedColor} {
		if strings.Contains(create, tag) {
			t.Errorf("create preview colored diff-looking content with %q\n--- got ---\n%s", tag, create)
		}
	}
}

// TestPromptUser_OmittedFolderUnreachableByIndex proves omission is not UI-only:
// the fourth (last) option in the shortened list is "allow globally permanently",
// so selecting it by navigation yields OptionAllowGlobal — the hidden folder
// option occupies no index in the decision path and can never be returned
func TestPromptUser_OmittedFolderUnreachableByIndex(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, outsideProjectToolRequest())

	h.down(3) // allow this once → deny → allow for this session → allow globally permanently
	h.key(tcell.KeyEnter)

	d := h.await()
	if d.Option != OptionAllowGlobal {
		t.Fatalf("Option = %d, want OptionAllowGlobal (%d); the 4th displayed option must be global, not folder", d.Option, OptionAllowGlobal)
	}
	if d.Option == OptionAllowFolder {
		t.Fatalf("omitted folder option was selected via index")
	}
}

func hostPromptRequest() PromptRequest {
	return PromptRequest{
		Kind:        SubjectHost,
		HostTool:    "web_fetch",
		HostRequest: "https://docs.example.com/guide?q=generics",
		Host:        "docs.example.com",
	}
}

var hostPathFacts = []string{
	"Run folder:",
	"Project root:",
	"allow in this folder permanently",
	"allow globally permanently",
	"settings.yaml",
	".codemeld",
	"descendants",
	"subject scope",
	"write",
	"read*",
	":*",
	"*",
}

func TestRenderPrompt_HostFormShowsOnlyHostFacts(t *testing.T) {
	req := hostPromptRequest()
	out := renderPromptPreview(req) + renderPromptFacts(req)

	for _, want := range []string{
		"Tool: web_fetch",
		"Request: https://docs.example.com/guide?q=generics",
		"Host: docs.example.com",
		"allow for this session",
		"allow in this project",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("host prompt missing %q\n--- got ---\n%s", want, out)
		}
	}
	for _, banned := range hostPathFacts {
		if strings.Contains(out, banned) {
			t.Errorf("host prompt renders path-scope fact %q\n--- got ---\n%s", banned, out)
		}
	}
}

func TestRenderPrompt_HostSearchFormShowsQuery(t *testing.T) {
	req := PromptRequest{
		Kind:        SubjectHost,
		HostTool:    "web_search",
		HostRequest: `golang "type parameters" tutorial`,
		Host:        "duckduckgo.com",
	}
	out := renderPromptPreview(req) + renderPromptFacts(req)
	for _, want := range []string{"Tool: web_search", `Request: golang "type parameters" tutorial`, "Host: duckduckgo.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("host search prompt missing %q\n--- got ---\n%s", want, out)
		}
	}
	if strings.Contains(out, "web_fetch") {
		t.Errorf("host search prompt names the wrong tool\n--- got ---\n%s", out)
	}
}

func TestRenderPromptFacts_HostBlockNewlineBounds(t *testing.T) {
	cases := []struct {
		name string
		req  PromptRequest
	}{
		{"normal", hostPromptRequest()},
		{"fresh", hostFreshConfirmationRequest()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts := renderPromptFacts(c.req)
			if !strings.HasPrefix(facts, "\n") || !strings.HasSuffix(facts, "\n") {
				t.Errorf("host facts must start and end with a newline\n--- got ---\n%q", facts)
			}
		})
	}
}

func hostFreshConfirmationRequest() PromptRequest {
	return PromptRequest{
		Kind:              SubjectHost,
		HostTool:          "web_fetch",
		HostRequest:       "https://docs.example.com:8443/guide",
		Host:              "docs.example.com",
		FreshConfirmation: true,
	}
}

func TestPromptOptions_HostFormOrderAndRestriction(t *testing.T) {
	hostRows := []promptOptionRow{
		{OptionAllowOnce, "allow this once"},
		{OptionDeny, "deny"},
		{OptionAllowSession, "allow for this session"},
		{OptionAllowProject, "allow in this project"},
	}
	cases := []struct {
		name     string
		req      PromptRequest
		wantOpts []PromptOption
		wantRows []promptOptionRow
	}{
		{
			name:     "normal host request",
			req:      hostPromptRequest(),
			wantOpts: []PromptOption{OptionAllowOnce, OptionDeny, OptionAllowSession, OptionAllowProject},
			wantRows: hostRows,
		},
		{
			name:     "changed-host redirect",
			req:      PromptRequest{Kind: SubjectHost, HostTool: "web_fetch", HostRequest: "https://cdn.example.net/guide", Host: "cdn.example.net"},
			wantOpts: []PromptOption{OptionAllowOnce, OptionDeny, OptionAllowSession, OptionAllowProject},
			wantRows: hostRows,
		},
		{
			name:     "fresh confirmation",
			req:      hostFreshConfirmationRequest(),
			wantOpts: []PromptOption{OptionAllowOnce, OptionDeny},
			wantRows: hostRows[:2],
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := promptOptionsFor(tc.req); !equalOptions(got, tc.wantOpts) {
				t.Fatalf("host options = %v, want %v", optionValues(got), tc.wantOpts)
			}

			if len(tc.wantRows) != len(tc.wantOpts) {
				t.Fatalf("test table broken: %d expected labels for %d expected options", len(tc.wantRows), len(tc.wantOpts))
			}

			a := New(nil)
			_, list := a.buildPromptOverlay(tc.req, make(chan PromptDecision, 1))
			if got := list.GetItemCount(); got != len(tc.wantRows) {
				t.Fatalf("list item count = %d, want %d", got, len(tc.wantRows))
			}
			for i, row := range tc.wantRows {
				want := promptRowLabel(row)
				if got, _ := list.GetItemText(i); got != want {
					t.Errorf("list item %d = %q, want %q", i, got, want)
				}
			}
			bannedRows := []promptOptionRow{
				{OptionAllowFolder, "allow in this folder permanently"},
				{OptionAllowGlobal, "allow globally permanently"},
			}
			for i := 0; i < list.GetItemCount(); i++ {
				got, _ := list.GetItemText(i)
				for _, banned := range bannedRows {
					if got == promptRowLabel(banned) {
						t.Fatalf("host prompt offers %q at index %d", banned.Label, i)
					}
				}
			}
			if got := list.GetCurrentItem(); got != 0 {
				t.Fatalf("default highlighted item = %d, want 0 (allow this once)", got)
			}
		})
	}
}

func TestPromptOptions_UntrustedHostWithholdsProjectGrant(t *testing.T) {
	req := hostPromptRequest()
	req.ProjectUntrusted = true

	opts := promptOptionsFor(req)
	want := []PromptOption{OptionAllowOnce, OptionDeny, OptionAllowSession}
	if !equalOptions(opts, want) {
		t.Fatalf("untrusted host options = %v, want %v", optionValues(opts), want)
	}
	if _, ok := promptMnemonicIndex(opts, 'p'); ok {
		t.Errorf("the project mnemonic still selects a row in an untrusted project: %v", optionValues(opts))
	}
	if len(hostOptionsInOrder) != 4 || hostOptionsInOrder[3].Option != OptionAllowProject {
		t.Fatalf("hostOptionsInOrder was mutated: %v", hostOptionsInOrder)
	}

	a := New(nil)
	_, list := a.buildPromptOverlay(req, make(chan PromptDecision, 1))
	if got := list.GetItemCount(); got != len(want) {
		t.Fatalf("list item count = %d, want %d", got, len(want))
	}
	for i, opt := range want {
		if got, _ := list.GetItemText(i); got != promptRowLabel(hostOptionsInOrder[i]) {
			t.Errorf("list item %d = %q, want the row for %v", i, got, opt)
		}
	}

	fresh := hostFreshConfirmationRequest()
	fresh.ProjectUntrusted = true
	if !equalOptions(promptOptionsFor(fresh), []PromptOption{OptionAllowOnce, OptionDeny}) {
		t.Errorf("untrusted fresh confirmation = %v, want the unchanged two-choice set", optionValues(promptOptionsFor(fresh)))
	}
}

func TestRenderPromptFacts_UntrustedHostNamesTrustCause(t *testing.T) {
	const savedProject = "allow in this project — saved in this project so it survives restart; applies to this exact host only."

	trusted := renderPromptFacts(hostPromptRequest())
	if !strings.Contains(trusted, savedProject) {
		t.Fatalf("trusted host facts lost the saved-project line\n--- got ---\n%s", trusted)
	}

	req := hostPromptRequest()
	req.ProjectUntrusted = true
	untrusted := renderPromptFacts(req)
	if strings.Contains(untrusted, savedProject) {
		t.Errorf("untrusted host facts still advertise a saved project grant\n--- got ---\n%s", untrusted)
	}
	if !strings.Contains(untrusted, untrustedProjectGrantExplanation) {
		t.Errorf("untrusted host facts do not state the trust cause\n--- got ---\n%s", untrusted)
	}
	if !strings.Contains(untrusted, "allow for this session — applies to this exact host until codemeld exits.") {
		t.Errorf("untrusted host facts dropped the session line\n--- got ---\n%s", untrusted)
	}
	if want := folderUnavailableText(FolderOptionUntrusted); want != untrustedProjectGrantExplanation {
		t.Errorf("host and folder surfaces state different trust wording: %q", want)
	}

	fresh := hostFreshConfirmationRequest()
	fresh.ProjectUntrusted = true
	if got, want := renderPromptFacts(fresh), renderPromptFacts(hostFreshConfirmationRequest()); got != want {
		t.Errorf("untrusted fresh confirmation facts changed\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderPromptFacts_UntrustedFolderPromptDropsSavedFolderAndNotice(t *testing.T) {
	trusted := renderPromptFacts(fullPromptRequest())
	marker := RenderCrossModeMarkerNotice("/work/project/.codemeld/settings.yaml")
	if !strings.Contains(trusted, "allow in this folder permanently — saved to") || !strings.Contains(trusted, marker) {
		t.Fatalf("fixture no longer shows the saved-folder line and marker notice\n--- got ---\n%s", trusted)
	}

	req := fullPromptRequest()
	req.ProjectUntrusted = true
	untrusted := renderPromptFacts(req)
	if strings.Contains(untrusted, "allow in this folder permanently") {
		t.Errorf("untrusted facts still advertise a saved folder grant\n--- got ---\n%s", untrusted)
	}
	if strings.Contains(untrusted, marker) {
		t.Errorf("untrusted facts still show the cross-mode marker notice\n--- got ---\n%s", untrusted)
	}
	if !strings.Contains(untrusted, "allow globally permanently") {
		t.Errorf("untrusted facts dropped the global line, which adr-051 leaves outside this gate\n--- got ---\n%s", untrusted)
	}
}

func TestPromptOverlay_UntrustedNoteNamesTrustCauseAndSizesToIt(t *testing.T) {
	req := fullPromptRequest()
	req.ProjectUntrusted = true

	a := New(nil)
	overlay, _ := a.buildPromptOverlay(req, make(chan PromptDecision, 1))
	flex, ok := overlay.(*tview.Flex)
	if !ok {
		t.Fatalf("overlay is %T, want *tview.Flex", overlay)
	}
	note := ""
	for i := 0; i < flex.GetItemCount(); i++ {
		tv, isText := flex.GetItem(i).(*tview.TextView)
		if !isText {
			continue
		}
		if text := tv.GetText(false); strings.Contains(text, untrustedProjectGrantExplanation) || strings.Contains(text, folderUnavailableExplanation) {
			note = text
		}
	}
	if !strings.Contains(note, untrustedProjectGrantExplanation) {
		t.Fatalf("untrusted overlay note = %q, want the trust wording", note)
	}
	if strings.Contains(note, folderUnavailableExplanation) {
		t.Errorf("untrusted overlay note reuses the out-of-root containment wording: %q", note)
	}

	// The draw hook sizes the note from the same text it renders, so an untrusted note
	// cannot be clipped against a budget computed from the longer containment wording.
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init: %v", err)
	}
	screen.SetSize(100, 40)
	a.app.SetScreen(screen)
	flex.SetRect(0, 0, 100, 40)
	flex.Draw(screen)
	rows := 0
	for i := 0; i < flex.GetItemCount(); i++ {
		if tv, isText := flex.GetItem(i).(*tview.TextView); isText && strings.Contains(tv.GetText(false), untrustedProjectGrantExplanation) {
			_, _, _, rows = tv.GetRect()
		}
	}
	if want := len(wrapRows(untrustedProjectGrantExplanation, 98)); rows != want {
		t.Errorf("untrusted note height = %d rows, want %d (sized to its own wrapped text)", rows, want)
	}
}

func TestPromptOverlay_HostFormOmitsFolderUnavailableNote(t *testing.T) {
	req := hostPromptRequest()
	req.ProjectRoot = "/work/proj"
	if !req.folderOmission().Hidden() {
		t.Fatal("fixture no longer triggers the folder-unavailable note; it cannot prove the host form suppresses it")
	}

	a := New(nil)
	overlay, _ := a.buildPromptOverlay(req, make(chan PromptDecision, 1))
	flex, ok := overlay.(*tview.Flex)
	if !ok {
		t.Fatalf("overlay is %T, want *tview.Flex", overlay)
	}
	for i := 0; i < flex.GetItemCount(); i++ {
		tv, ok := flex.GetItem(i).(*tview.TextView)
		if !ok {
			continue
		}
		if strings.Contains(tv.GetText(false), folderUnavailableExplanation) {
			t.Fatalf("host overlay renders the folder-unavailable explanation at row %d", i)
		}
	}
}

func TestRenderPromptFacts_HostFreshConfirmationRestriction(t *testing.T) {
	facts := renderPromptFacts(hostFreshConfirmationRequest())
	if !strings.Contains(facts, hostFreshConfirmationNotice) {
		t.Errorf("fresh confirmation facts do not explain the restriction\n--- got ---\n%s", facts)
	}
	for _, banned := range []string{"allow for this session", "allow in this project"} {
		if strings.Contains(facts, banned) {
			t.Errorf("fresh confirmation facts advertise durable choice %q\n--- got ---\n%s", banned, facts)
		}
	}
	for _, banned := range hostPathFacts {
		if strings.Contains(facts, banned) {
			t.Errorf("fresh confirmation facts render path-scope fact %q\n--- got ---\n%s", banned, facts)
		}
	}
}

func TestRenderPromptFacts_HostDirectHTTPDisclosure(t *testing.T) {
	directHTTP := hostPromptRequest()
	directHTTP.HostRequest = "http://docs.example.com/guide"
	directHTTP.DirectHTTPFallback = true

	searchOriginated := PromptRequest{Kind: SubjectHost, HostTool: "web_search", HostRequest: "generics", Host: "duckduckgo.com"}

	if facts := renderPromptFacts(directHTTP); !strings.Contains(facts, hostDirectHTTPDisclosure) {
		t.Errorf("direct http prompt missing the HTTPS-first disclosure\n--- got ---\n%s", facts)
	}
	cases := []struct {
		name string
		req  PromptRequest
	}{
		{"direct https", hostPromptRequest()},
		{"search originated", searchOriginated},
		{"fresh confirmation", hostFreshConfirmationRequest()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if facts := renderPromptFacts(c.req); strings.Contains(facts, hostDirectHTTPDisclosure) {
				t.Errorf("prompt discloses an HTTPS-first fallback it does not perform\n--- got ---\n%s", facts)
			}
		})
	}
}

func TestPromptUser_HostProjectSelection(t *testing.T) {
	h := startPrompt(t, New(nil), hostPromptRequest())
	h.down(3)
	h.key(tcell.KeyEnter)
	decision := h.await()

	if decision.Option != OptionAllowProject {
		t.Fatalf("decision option = %d, want OptionAllowProject (%d)", decision.Option, OptionAllowProject)
	}
	if decision.StoredSubject != "" {
		t.Errorf("host decision stored subject = %q, want empty (a host grant keys on the tool and host)", decision.StoredSubject)
	}
}

func TestPromptUser_HostFreshConfirmationCannotReachDurableOptions(t *testing.T) {
	h := startPrompt(t, New(nil), hostFreshConfirmationRequest())
	h.down(4)
	h.key(tcell.KeyEnter)
	decision := h.await()

	if decision.Option != OptionAllowOnce && decision.Option != OptionDeny {
		t.Fatalf("decision option = %d, want allow once (%d) or deny (%d) only", decision.Option, OptionAllowOnce, OptionDeny)
	}
}

func (h *promptHarness) assertRunesInert(runes string, from int) {
	h.t.Helper()
	h.typeText(runes)
	h.key(tcell.KeyDown)
	waitOnLoop(h.t, h.a, "inert runes "+runes+" reaching a list that stays open", func() bool {
		list, ok := h.a.app.GetFocus().(*tview.List)
		return ok && list.GetCurrentItem() == from+1
	})
	select {
	case d := <-h.decc:
		h.a.app.Stop()
		h.t.Fatalf("runes %q produced a decision: %+v", runes, d)
	default:
	}
	h.key(tcell.KeyUp)
}

func TestPromptUser_MnemonicAllowOnce(t *testing.T) {
	for _, key := range []string{"o", "O"} {
		t.Run(key, func(t *testing.T) {
			a := New(nil)
			h := startPrompt(t, a, fullPromptRequest())

			h.typeText(key)

			d := h.await()
			if d.Option != OptionAllowOnce {
				t.Fatalf("Option = %d, want OptionAllowOnce (%d)", d.Option, OptionAllowOnce)
			}
			if d.StoredSubject != "" {
				t.Errorf("StoredSubject = %q, want empty (allow-once creates no grant)", d.StoredSubject)
			}
			if a.pages.HasPage(promptScopePage) {
				t.Error("allow-once mnemonic opened the scope chooser")
			}
			if a.pages.HasPage(promptBasePage) {
				t.Error("prompt page not removed after the mnemonic decision")
			}
		})
	}
}

func TestPromptUser_MnemonicDeny(t *testing.T) {
	for _, key := range []string{"d", "D"} {
		t.Run(key, func(t *testing.T) {
			a := New(nil)
			h := startPrompt(t, a, fullPromptRequest())

			h.typeText(key)

			d := h.await()
			if d.Option != OptionDeny {
				t.Fatalf("Option = %d, want OptionDeny (%d)", d.Option, OptionDeny)
			}
			if want := permissions.BuildDenyEnvelope(""); d.DenyEnvelope != want {
				t.Fatalf("DenyEnvelope = %q, want the default %q", d.DenyEnvelope, want)
			}
			if a.pages.HasPage(promptBasePage) {
				t.Error("prompt page not removed after the deny mnemonic")
			}
		})
	}
}

func TestPromptUser_MnemonicSessionEntersScopeChooser(t *testing.T) {
	for _, key := range []string{"s", "S"} {
		t.Run(key, func(t *testing.T) {
			a := New(nil)
			h := startPrompt(t, a, fullPromptRequest())

			h.typeText(key)
			h.waitPage(promptScopePage)
			h.key(tcell.KeyEnter)

			d := h.await()
			if d.Option != OptionAllowSession {
				t.Fatalf("Option = %d, want OptionAllowSession (%d)", d.Option, OptionAllowSession)
			}
			if d.StoredSubject != "git log :*" {
				t.Fatalf("StoredSubject = %q, want %q", d.StoredSubject, "git log :*")
			}
		})
	}
}

func TestPromptUser_MnemonicFolderEntersScopeChooser(t *testing.T) {
	for _, key := range []string{"f", "F"} {
		t.Run(key, func(t *testing.T) {
			a := New(nil)
			h := startPrompt(t, a, fullPromptRequest())

			h.typeText(key)
			h.waitPage(promptScopePage)
			h.key(tcell.KeyEnter)

			d := h.await()
			if d.Option != OptionAllowFolder {
				t.Fatalf("Option = %d, want OptionAllowFolder (%d)", d.Option, OptionAllowFolder)
			}
			if d.StoredSubject != "git log :*" {
				t.Fatalf("StoredSubject = %q, want %q", d.StoredSubject, "git log :*")
			}
		})
	}
}

func TestPromptUser_MnemonicFolderStructuredToolSelectsImmediately(t *testing.T) {
	for _, key := range []string{"f", "F"} {
		t.Run(key, func(t *testing.T) {
			a := New(nil)
			h := startPrompt(t, a, PromptRequest{
				Action:                  "Create file",
				Subject:                 "a.go",
				Kind:                    SubjectStructuredTool,
				RunFolder:               "/work",
				ProjectRoot:             "/work",
				FolderSettingsPath:      "/work/.codemeld/settings.yaml",
				FolderCoverage:          "/work and all descendants",
				CapabilityStoredSubject: permissions.CapabilityWrite,
			})

			h.typeText(key)

			d := h.await()
			if d.Option != OptionAllowFolder {
				t.Fatalf("Option = %d, want OptionAllowFolder (%d)", d.Option, OptionAllowFolder)
			}
			if d.StoredSubject != permissions.CapabilityWrite {
				t.Fatalf("StoredSubject = %q, want %q", d.StoredSubject, permissions.CapabilityWrite)
			}
			if a.pages.HasPage(promptScopePage) {
				t.Error("a structured-tool folder mnemonic opened the direct-command scope chooser")
			}
			if a.pages.HasPage(promptBasePage) {
				t.Error("prompt page not removed after the folder mnemonic decision")
			}
		})
	}
}

func TestPromptUser_MnemonicFolderInertWhenOptionWithheld(t *testing.T) {
	h := startPrompt(t, New(nil), outsideProjectToolRequest())

	h.assertRunesInert("fF", 0)
	h.key(tcell.KeyEnter)

	d := h.await()
	if d.Option != OptionAllowOnce {
		t.Fatalf("Option = %d, want OptionAllowOnce (%d); the withheld folder row must stay unreachable", d.Option, OptionAllowOnce)
	}
}

func TestPromptUser_MnemonicProjectInertOffHostPrompt(t *testing.T) {
	h := startPrompt(t, New(nil), fullPromptRequest())

	h.assertRunesInert("pP", 0)
	h.key(tcell.KeyEnter)

	d := h.await()
	if d.Option != OptionAllowOnce {
		t.Fatalf("Option = %d, want OptionAllowOnce (%d); a non-host prompt renders no project row", d.Option, OptionAllowOnce)
	}
}

func TestPromptUser_MnemonicGlobalEntersScopeChooser(t *testing.T) {
	for _, key := range []string{"g", "G"} {
		t.Run(key, func(t *testing.T) {
			a := New(nil)
			h := startPrompt(t, a, fullPromptRequest())

			h.typeText(key)
			h.waitPage(promptScopePage)
			h.down(1)
			h.key(tcell.KeyEnter)
			h.waitPage(promptScopeConfirmPage)
			h.key(tcell.KeyEnter)

			d := h.await()
			if d.Option != OptionAllowGlobal {
				t.Fatalf("Option = %d, want OptionAllowGlobal (%d)", d.Option, OptionAllowGlobal)
			}
			if d.StoredSubject != "git :*" {
				t.Fatalf("StoredSubject = %q, want %q", d.StoredSubject, "git :*")
			}
		})
	}
}

func TestPromptUser_MnemonicStructuredToolDecisions(t *testing.T) {
	cases := []struct {
		key         string
		wantOption  PromptOption
		wantSubject string
	}{
		{"o", OptionAllowOnce, ""},
		{"O", OptionAllowOnce, ""},
		{"d", OptionDeny, ""},
		{"D", OptionDeny, ""},
		{"s", OptionAllowSession, permissions.CapabilityWrite},
		{"S", OptionAllowSession, permissions.CapabilityWrite},
		{"g", OptionAllowGlobal, permissions.CapabilityWrite},
		{"G", OptionAllowGlobal, permissions.CapabilityWrite},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			a := New(nil)
			h := startPrompt(t, a, PromptRequest{
				Action:                  "Create file",
				Subject:                 "a.go",
				Kind:                    SubjectStructuredTool,
				RunFolder:               "/work",
				CapabilityStoredSubject: permissions.CapabilityWrite,
			})

			h.typeText(tc.key)

			d := h.await()
			if d.Option != tc.wantOption {
				t.Fatalf("Option = %d, want %d", d.Option, tc.wantOption)
			}
			if d.StoredSubject != tc.wantSubject {
				t.Fatalf("StoredSubject = %q, want %q", d.StoredSubject, tc.wantSubject)
			}
			if a.pages.HasPage(promptScopePage) {
				t.Error("a structured-tool mnemonic opened the direct-command scope chooser")
			}
		})
	}
}

func TestPromptUser_MnemonicHostPrompt(t *testing.T) {
	cases := []struct {
		key        string
		wantOption PromptOption
	}{
		{"o", OptionAllowOnce},
		{"O", OptionAllowOnce},
		{"d", OptionDeny},
		{"D", OptionDeny},
		{"s", OptionAllowSession},
		{"S", OptionAllowSession},
		{"p", OptionAllowProject},
		{"P", OptionAllowProject},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			a := New(nil)
			h := startPrompt(t, a, hostPromptRequest())

			h.typeText(tc.key)

			d := h.await()
			if d.Option != tc.wantOption {
				t.Fatalf("Option = %d, want %d", d.Option, tc.wantOption)
			}
			if d.StoredSubject != "" {
				t.Errorf("host StoredSubject = %q, want empty", d.StoredSubject)
			}
			if a.pages.HasPage(promptScopePage) {
				t.Error("a host mnemonic opened the scope chooser")
			}
		})
	}
}

func TestPromptUser_MnemonicHostHasNoGlobalShortcut(t *testing.T) {
	h := startPrompt(t, New(nil), hostPromptRequest())

	h.assertRunesInert("gGfF", 0)
	h.key(tcell.KeyEnter)

	d := h.await()
	if d.Option != OptionAllowOnce {
		t.Fatalf("Option = %d, want OptionAllowOnce (%d); the cursor never left the first row", d.Option, OptionAllowOnce)
	}
}

func TestPromptUser_MnemonicHostFreshConfirmation(t *testing.T) {
	cases := []struct {
		key        string
		wantOption PromptOption
	}{
		{"o", OptionAllowOnce},
		{"O", OptionAllowOnce},
		{"d", OptionDeny},
		{"D", OptionDeny},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			h := startPrompt(t, New(nil), hostFreshConfirmationRequest())

			h.typeText(tc.key)

			d := h.await()
			if d.Option != tc.wantOption {
				t.Fatalf("Option = %d, want %d", d.Option, tc.wantOption)
			}
		})
	}
}

func TestPromptUser_MnemonicHostFreshConfirmationHasNoDurableShortcut(t *testing.T) {
	h := startPrompt(t, New(nil), hostFreshConfirmationRequest())

	h.assertRunesInert("sSgGfFpP", 0)
	h.key(tcell.KeyEnter)

	d := h.await()
	if d.Option != OptionAllowOnce {
		t.Fatalf("Option = %d, want OptionAllowOnce (%d); no durable approval may be reachable here", d.Option, OptionAllowOnce)
	}
}

func TestPromptUser_MnemonicsInertOnScopeChooser(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, fullPromptRequest())

	h.typeText("s")
	h.waitPage(promptScopePage)
	h.assertRunesInert("odsfgpODSFGP", 2)
	h.key(tcell.KeyEnter)

	d := h.await()
	if d.Option != OptionAllowSession {
		t.Fatalf("Option = %d, want OptionAllowSession (%d)", d.Option, OptionAllowSession)
	}
	if d.StoredSubject != "git log :*" {
		t.Fatalf("StoredSubject = %q, want %q", d.StoredSubject, "git log :*")
	}
}

func TestPromptUser_MnemonicsInertOnProgramConfirm(t *testing.T) {
	a := New(nil)
	h := startPrompt(t, a, fullPromptRequest())

	h.typeText("g")
	h.waitPage(promptScopePage)
	h.down(1)
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopeConfirmPage)
	h.assertRunesInert("odsfgpODSFGP", 0)
	h.key(tcell.KeyEnter)

	d := h.await()
	if d.Option != OptionAllowGlobal {
		t.Fatalf("Option = %d, want OptionAllowGlobal (%d)", d.Option, OptionAllowGlobal)
	}
	if d.StoredSubject != "git :*" {
		t.Fatalf("StoredSubject = %q, want %q", d.StoredSubject, "git :*")
	}
}

func TestPromptUser_MnemonicsInertOnCompoundStage(t *testing.T) {
	sc := permissions.SimpleCompound{
		Stages:    [][]string{{"go", "build", "./..."}, {"gofmt", "-w", "a.go"}},
		Operators: []string{"&&"},
	}
	a := New(nil)
	h := startPrompt(t, a, compoundPromptRequest(sc))

	h.typeText("s")
	h.waitPage(promptCompoundPage)
	h.assertRunesInert("odsfgpODSFGP", 0)
	h.key(tcell.KeyEnter)
	h.key(tcell.KeyEnter)

	d := h.await()
	if d.Option != OptionAllowSession {
		t.Fatalf("Option = %d, want OptionAllowSession (%d)", d.Option, OptionAllowSession)
	}
	want, err := permissions.EncodeCompoundSubject(false, []string{"go build ./...", "gofmt -w a.go"}, []string{"&&"})
	if err != nil {
		t.Fatalf("encode expected subject: %v", err)
	}
	if d.StoredSubject != want {
		t.Fatalf("StoredSubject = %q, want %q", d.StoredSubject, want)
	}
}

func TestApp_ApprovalMnemonicsAreOrdinaryInputWithoutPrompt(t *testing.T) {
	h := newAppHarness(t, 100, 30)
	defer h.stop()

	h.screen.InjectKeyBytes([]byte("odsfgpODSFGP"))

	waitOnLoop(t, h.a, "typed approval letters reaching the input area", func() bool {
		return h.a.input.GetText() == "odsfgpODSFGP"
	})
	var open, hasPage bool
	h.a.app.QueueUpdate(func() {
		open = h.a.promptOpen
		hasPage = h.a.pages.HasPage(promptBasePage)
	})
	if open || hasPage {
		t.Fatalf("typing the approval letters created prompt state: open=%v page=%v", open, hasPage)
	}
}

// livePrompt drives one PromptUser call through the real App.Run lifecycle, which
// startPrompt bypasses by installing its screen with SetScreen: the notifier's bell needs
// the screen Run stores and its escape write needs the running flag Run sets.
type livePrompt struct {
	*promptHarness
	clk    *fakeNotifyClock
	writes *recordingWriter
	screen *beepScreen
}

func startLivePrompt(t *testing.T, req PromptRequest) *livePrompt {
	t.Helper()
	a := New(nil)
	clk := newFakeNotifyClock()
	writes := &recordingWriter{}
	a.promptNotifyAfter = clk.after
	a.promptNotifyWrite = writes.write
	screen := &beepScreen{SimulationScreen: tcell.NewSimulationScreen("UTF-8")}
	a.newScreen = func() (tcell.Screen, error) { return screen, nil }

	errc := make(chan error, 1)
	go func() { errc <- a.Run() }()
	waitLoopRunning(t, a)

	decc := make(chan PromptDecision, 1)
	go func() {
		d, _ := a.PromptUser(req)
		decc <- d
	}()

	h := &promptHarness{t: t, a: a, screen: screen, decc: decc, errc: errc}
	h.waitPage(promptBasePage)
	return &livePrompt{promptHarness: h, clk: clk, writes: writes, screen: screen}
}

// alert fires the notifier's next tick and waits for the nth alert to reach the terminal.
func (p *livePrompt) alert(n int) {
	p.t.Helper()
	select {
	case p.clk.tick <- time.Time{}:
	case <-time.After(2 * time.Second):
		p.a.app.Stop()
		p.t.Fatalf("no notifier was waiting on the clock for alert %d", n)
	}
	deadline := time.Now().Add(2 * time.Second)
	for p.writes.count() < n {
		if time.Now().After(deadline) {
			p.a.app.Stop()
			p.t.Fatalf("alert %d never reached the terminal", n)
		}
		time.Sleep(time.Millisecond)
	}
}

func (p *livePrompt) assertSilentSince(want int) {
	p.t.Helper()
	p.clk.assertIdle(p.t)
	if got := p.writes.count(); got != want {
		p.t.Fatalf("%d escape sequences written after the decision, want the %d from before it", got, want)
	}
	if got := int(p.screen.beeps.Load()); got != want {
		p.t.Fatalf("%d bells rung after the decision, want the %d from before it", got, want)
	}
}

func TestPromptUser_AlertsWhileBlockedAndStopsOnAnswer(t *testing.T) {
	p := startLivePrompt(t, fullPromptRequest())

	p.alert(1)
	if got := p.writes.all(); len(got) != 1 || got[0] != PromptNotifySequence() {
		t.Fatalf("writes = %q, want exactly one %q", got, PromptNotifySequence())
	}
	if got := p.screen.beeps.Load(); got != 1 {
		t.Fatalf("bells = %d, want 1", got)
	}
	if got := p.clk.elapsed(1); got != promptNotifyDelay {
		t.Fatalf("first alert fired at %s, want %s", got, promptNotifyDelay)
	}
	p.alert(2)
	if got := p.clk.elapsed(2); got != promptNotifyDelay+promptNotifyRepeat {
		t.Fatalf("second alert fired at %s, want %s", got, promptNotifyDelay+promptNotifyRepeat)
	}

	p.key(tcell.KeyEnter)
	if d := p.await(); d.Option != OptionAllowOnce {
		t.Fatalf("decision = %d, want OptionAllowOnce (%d)", d.Option, OptionAllowOnce)
	}

	p.assertSilentSince(2)
}

// A prompt answered inside the first interval must be completely silent: the measured
// median answer time is three seconds.
func TestPromptUser_AnswerInsideTheFirstIntervalIsSilent(t *testing.T) {
	p := startLivePrompt(t, fullPromptRequest())

	p.key(tcell.KeyEnter)
	p.await()

	p.assertSilentSince(0)
	if got := p.clk.elapsed(1); got != promptNotifyDelay {
		t.Fatalf("first delay = %s, want %s", got, promptNotifyDelay)
	}
}

func TestPromptUser_AlertsStopOnDenyAndOnEscDismissal(t *testing.T) {
	t.Run("deny", func(t *testing.T) {
		p := startLivePrompt(t, fullPromptRequest())
		p.alert(1)

		p.down(1)
		p.key(tcell.KeyEnter)
		if d := p.await(); d.Option != OptionDeny {
			t.Fatalf("decision = %d, want OptionDeny (%d)", d.Option, OptionDeny)
		}

		p.assertSilentSince(1)
	})

	t.Run("esc dismissal", func(t *testing.T) {
		p := startLivePrompt(t, fullPromptRequest())
		p.alert(1)

		p.key(tcell.KeyEscape)
		if d := p.await(); d.Option != OptionDeny {
			t.Fatalf("decision = %d, want OptionDeny (%d)", d.Option, OptionDeny)
		}

		p.assertSilentSince(1)
	})
}

// The alert must stay running behind the scope chooser and the Program confirmation: the
// run is just as blocked there as it is on the option list.
func TestPromptUser_AlertsContinueThroughTheScopeAndConfirmSteps(t *testing.T) {
	p := startLivePrompt(t, fullPromptRequest())

	p.down(2)
	p.key(tcell.KeyEnter)
	p.waitPage(promptScopePage)
	p.alert(1)

	p.down(1)
	p.key(tcell.KeyEnter)
	p.waitPage(promptScopeConfirmPage)
	p.alert(2)

	p.key(tcell.KeyEnter)
	if d := p.await(); d.Option != OptionAllowSession {
		t.Fatalf("decision = %d, want OptionAllowSession (%d)", d.Option, OptionAllowSession)
	}

	p.assertSilentSince(2)
}

func benignAlertFields(req PromptRequest) PromptRequest {
	req.Subject = "git log --oneline"
	req.HostTool = "WebFetch"
	req.HostRequest = "GET https://example.com/"
	req.Host = "example.com"
	return req
}

func hostileAlertFields(req PromptRequest) PromptRequest {
	req.Subject = "git log\x07\x1b]9;stolen subject\x07\n\x9d"
	req.HostTool = "Web\x07Fetch\x1b\\"
	req.HostRequest = "GET https://evil.example/\x1b]0;title\x07\n\x9c"
	req.Host = "ev\x9dil.example\n\x1b]9;also stolen\x07"
	return req
}

func alertBytesFor(t *testing.T, req PromptRequest) []string {
	t.Helper()
	p := startLivePrompt(t, req)
	p.alert(1)
	p.key(tcell.KeyEscape)
	p.await()
	return p.writes.all()
}

// No request value is read on this path, so a hostile Subject/HostTool/HostRequest/Host
// cannot reach the terminal through it.
func TestPromptUser_HostileRequestFieldsCannotChangeTheAlertBytes(t *testing.T) {
	base := alertBytesFor(t, benignAlertFields(fullPromptRequest()))
	hostile := alertBytesFor(t, hostileAlertFields(fullPromptRequest()))

	if len(base) != 1 || base[0] != PromptNotifySequence() {
		t.Fatalf("benign alert = %q, want exactly one %q", base, PromptNotifySequence())
	}
	if !reflect.DeepEqual(base, hostile) {
		t.Fatalf("hostile alert = %q, want the benign bytes %q", hostile, base)
	}
}

func toolPromptSummaryFor(subject, action, target, body string) permissions.PromptSummaryResult {
	return permissions.PromptSummary(
		permissions.MatchRequest{Kind: "tool", Subject: subject},
		permissions.PromptSummaryInput{Action: action, RequestedTarget: target, Body: body},
	)
}

func TestPromptFixedLines_SummaryAndShapeLead(t *testing.T) {
	req := fullPromptRequest()
	req.Summary = literalPromptSummary("tee out.txt")

	lines := promptFixedLines(req)
	if len(lines) < promptSummaryKeepRows {
		t.Fatalf("fixed block = %#v, want the summary and shape rows first", lines)
	}
	if !strings.HasPrefix(lines[0], "Summary: ") {
		t.Fatalf("first fixed row = %q, want the summary sentence", lines[0])
	}
	if !strings.HasPrefix(lines[1], "Request: shell command, ") || !strings.Contains(lines[1], "effect: runs a command, writes") {
		t.Fatalf("second fixed row = %q, want the request-shape line", lines[1])
	}
	if !slicesContains(lines, "Requested target: out.txt") {
		t.Fatalf("fixed block does not name the requested target: %#v", lines)
	}
	for _, banned := range []string{"direct-command", "literal-command", "structured-tool"} {
		if strings.Contains(strings.Join(lines, "\n"), banned) {
			t.Fatalf("fixed block leaks the matching discriminator %q", banned)
		}
	}
}

func slicesContains(rows []string, want string) bool {
	for _, row := range rows {
		if row == want {
			return true
		}
	}
	return false
}

func TestPromptFixedLines_BoundsEveryVariableFact(t *testing.T) {
	long := strings.Repeat("seg/", 60)
	req := PromptRequest{
		Action:                  "Run tool",
		Subject:                 "read",
		Kind:                    SubjectStructuredTool,
		RunFolder:               long + "run",
		ProjectRoot:             long + "root",
		FolderSettingsPath:      long + "settings.yaml",
		FolderCoverage:          long + "coverage",
		ScopeEscalationNarrower: long + "narrower",
		OutOfRootReadScope:      true,
		Summary:                 toolPromptSummaryFor("read", "Run tool", "a\nb"+long, `read({"path":"x"})`),
	}
	fixed := strings.Join(promptFixedLines(req), "\n")
	if strings.ContainsAny(strings.ReplaceAll(fixed, "\n", ""), "\r\t") {
		t.Fatalf("fixed block carries a raw control byte:\n%s", fixed)
	}
	for _, exact := range []string{req.RunFolder, req.ProjectRoot, req.FolderSettingsPath, req.FolderCoverage, req.ScopeEscalationNarrower, req.Summary.Targets[0]} {
		if strings.Contains(fixed, exact) {
			t.Fatalf("fixed block rendered %q unbounded", exact)
		}
		if !strings.Contains(fixed, permissions.BoundPromptFact(exact)) {
			t.Fatalf("fixed block does not carry the bounded rendering of %q", exact)
		}
		if utf8.RuneCountInString(permissions.BoundPromptFact(exact)) != 121 {
			t.Fatalf("bounded rendering of %q is not capped at 120 code points plus the ellipsis", exact)
		}
	}
	if !strings.Contains(fixed, `a\x0Ab`) {
		t.Fatalf("newline in the requested target was not escaped as an atomic unit:\n%s", fixed)
	}

	preview := renderPromptPreview(req)
	for _, exact := range []string{long + "run", long + "settings.yaml", long + "narrower", "a\nb" + long} {
		if strings.Contains(preview, exact) {
			t.Fatalf("preview repeats authorization fact %q", exact)
		}
	}
}

// The cross-mode notice interpolates a project-root-derived settings path, so that path is a
// variable authorization fact and carries the same bounded rendering as every other one.
func TestPromptFixedLines_BoundsCrossModeNoticePath(t *testing.T) {
	root := "/work/\n\tproject" + strings.Repeat("seg/", 60)
	settings := filepath.Join(root, ".codemeld", "settings.yaml")
	req := fullPromptRequest()
	req.RunFolder = root
	req.ProjectRoot = root
	req.LaunchDir = root
	req.FolderSettingsPath = settings

	lines := promptFixedLines(req)
	notice := ""
	for _, line := range lines {
		if strings.ContainsAny(line, "\n\r\t") {
			t.Fatalf("fixed-fact row carries a raw control byte, so it can add physical rows: %q", line)
		}
		if strings.Contains(line, "mark the launch directory as a project root") {
			notice = line
		}
	}
	if notice == "" {
		t.Fatalf("cross-mode notice missing from the fixed block:\n%s", strings.Join(lines, "\n"))
	}
	if want := RenderCrossModeMarkerNotice(permissions.BoundPromptFact(settings)); notice != want {
		t.Fatalf("cross-mode notice = %q, want the shared wording over the bounded path %q", notice, want)
	}
}

func TestPromptFactLines_BoundsBatchedEscalationsAndKeepsPreviewRaw(t *testing.T) {
	narrower := "/work/\n\tproject/" + strings.Repeat("seg/", 60)
	req := batchedPromptRequest()
	req.BatchedEscalations = []string{narrower, ""}

	escalation := ""
	for _, line := range promptFactLines(req) {
		if strings.ContainsAny(line, "\n\r\t") {
			t.Fatalf("fixed-fact row carries a raw control byte, so it can add physical rows: %q", line)
		}
		if strings.Contains(line, "PARENT of") {
			escalation = line
		}
	}
	want := "Stage 1: " + scopeEscalationNotice + permissions.BoundPromptFact(narrower)
	if escalation != want {
		t.Fatalf("batched escalation row = %q, want the bounded fact %q", escalation, want)
	}
	if strings.Count(strings.Join(promptFactLines(req), "\n"), "PARENT of") != 1 {
		t.Fatalf("the empty second-stage entry must not add a row:\n%s", strings.Join(promptFactLines(req), "\n"))
	}

	preview := renderPromptPreview(req)
	if strings.Contains(preview, "PARENT of") || strings.Contains(preview, "seg/seg/") {
		t.Fatalf("the preview repeated an authorization fact instead of raw request text only:\n%s", preview)
	}
}

func TestFitPromptFixedLines_KeepsSummaryAndMarksOmission(t *testing.T) {
	lines := []string{"Summary: s", "Request: shell command, 1 lines, 5 characters, effect: unknown", "a", "b", "c", "d"}

	full, rows := fitPromptFixedLines(lines, promptSummaryKeepRows, 80, 10)
	if rows != len(lines) || strings.Contains(full, permissions.PromptFactsOverflowNotice) {
		t.Fatalf("a fitting block must not be marked as omitted: %q", full)
	}

	cut, rows := fitPromptFixedLines(lines, promptSummaryKeepRows, 80, 4)
	if rows > 4 {
		t.Fatalf("fitted block used %d rows, want at most the budget of 4", rows)
	}
	if !strings.HasPrefix(cut, "Summary: s\nRequest: shell command,") {
		t.Fatalf("summary and shape rows were dropped under budget: %q", cut)
	}
	if !strings.Contains(cut, permissions.PromptFactsOverflowNotice) {
		t.Fatalf("omitted facts are not marked for inspection: %q", cut)
	}
	if strings.Contains(cut, "\nd") {
		t.Fatalf("block exceeded its budget: %q", cut)
	}
}

// A budget smaller than the wrapped summary and request-shape rows must cut them to fit rather
// than clip either away: both rows are required on screen at every supported terminal size.
func TestFitPromptFixedLines_SqueezesRatherThanDroppingRequiredRows(t *testing.T) {
	lines := []string{
		"Summary: Creates a file at /work/project/sub/notes.md.",
		"Request: file create, 201 lines, 2211 characters, effect: writes files",
		"run folder: /work/project/sub",
	}
	for _, budget := range []int{2, 3, 4} {
		text, rows := fitPromptFixedLines(lines, promptSummaryKeepRows, 38, budget)
		if rows > budget {
			t.Fatalf("budget %d: used %d rows", budget, rows)
		}
		got := strings.Split(text, "\n")
		if len(got) < promptSummaryKeepRows {
			t.Fatalf("budget %d: required rows dropped: %q", budget, text)
		}
		if !strings.HasPrefix(got[0], "Summary: Creates") {
			t.Fatalf("budget %d: summary row missing: %q", budget, text)
		}
		if !strings.HasPrefix(got[1], "Request: file create") {
			t.Fatalf("budget %d: request-shape row missing: %q", budget, text)
		}
		physical := 0
		for _, row := range got {
			physical += len(wrapRows(row, 38))
		}
		if physical > budget {
			t.Fatalf("budget %d: block wraps to %d physical rows: %q", budget, physical, text)
		}
		// The run-folder row is omitted at every budget here, so the inspection marker must be
		// present whenever the budget can hold it beside one row for each required row.
		marker := len(wrapRows(permissions.PromptFactsOverflowNotice, 38))
		if want := budget-marker >= promptSummaryKeepRows; strings.Contains(text, permissions.PromptFactsOverflowNotice) != want {
			t.Fatalf("budget %d: overflow marker present = %v, want %v: %q",
				budget, !want, want, text)
		}
	}
}

// A short, narrow terminal must still reserve the decision rows: the summary, shape line, and
// every choice stay on screen while omitted facts and the raw tail remain reachable by scrolling.
func TestPromptOverlay_ShortTerminalReservesChoicesAndSummary(t *testing.T) {
	const tail = "SHORTTAIL4K"
	body := strings.Repeat("body line\n", 200) + tail + "\n"
	req := PromptRequest{
		Action:             "Create file",
		Subject:            "/work/project/sub/notes.md",
		Body:               body,
		Kind:               SubjectStructuredTool,
		RunFolder:          "/work/project/sub",
		ProjectRoot:        "/work/project",
		FolderSettingsPath: "/work/project/.codemeld/settings.yaml",
		FolderCoverage:     "/work/project/sub and its descendants",
		Summary:            toolPromptSummaryFor("create", "Create file", "/work/project/sub/notes.md", body),
	}

	a := New(nil)
	h := startPrompt(t, a, req)
	readScreen := func() string { return readScreenSync(t, a, h.screen) }

	// wantMarker is false only at 40x10, where the fixed block gets two rows: one for each
	// required row, leaving none for the two-row inspection marker.
	for _, size := range []struct {
		w, h       int
		wantMarker bool
	}{{40, 16, true}, {60, 14, true}, {40, 10, false}} {
		h.screen.SetSize(size.w, size.h)
		got := readScreen()
		// "Create file" is the preview's first row and appears nowhere in the fixed block, so
		// it proves a scrollable-preview row survived the budget alongside the required rows.
		want := []string{"allow this [o]nce", "[d]eny", "allow for this [s]ession", "allow [g]lobally permanently",
			"Summary:", "Request: file create", "Create file"}
		for _, w := range want {
			if !strings.Contains(got, w) {
				a.app.Stop()
				t.Fatalf("%dx%d dropped %q\n%s", size.w, size.h, w, got)
			}
		}
		// Facts are omitted at every size here, so the inspection marker must be on screen
		// wherever the row budget can hold it beside the two required rows.
		if strings.Contains(got, "additional authorization facts") != size.wantMarker {
			a.app.Stop()
			t.Fatalf("%dx%d inspection marker present = %v, want %v\n%s",
				size.w, size.h, !size.wantMarker, size.wantMarker, got)
		}
	}

	// Page to the tail at the shortest covered size, where the preview is one row: the tail
	// must stay reachable there, not only once the terminal grows back.
	h.screen.SetSize(40, 10)
	var preview *tview.TextView
	a.app.QueueUpdate(func() {
		bg, ok := a.pages.GetPage(promptBasePage).(*overlayBackground)
		if !ok {
			return
		}
		flex, ok := bg.inner.(*tview.Flex)
		if !ok {
			return
		}
		preview, _ = flex.GetItem(0).(*tview.TextView)
	})
	if preview == nil {
		a.app.Stop()
		t.Fatal("prompt base page does not expose the scrollable preview as its first overlay item")
	}
	scrollState := func() (row, height int) {
		a.app.QueueUpdate(func() {
			row, _ = preview.GetScrollOffset()
			_, _, _, height = preview.GetInnerRect()
		})
		return row, height
	}

	row, _ := scrollState()
	height, found := 0, false
	for {
		h.key(tcell.KeyPgDn)
		settleKeys(h, 0)
		got := readScreen()
		next, nextHeight := scrollState()
		height = nextHeight
		if strings.Contains(got, tail) {
			found = true
			break
		}
		if next == row {
			break
		}
		row = next
	}
	if !found {
		// tview clamps a past-the-end scroll to the drawn maximum, so scrolling to the end
		// names the offset paging should have reached before it stalled.
		a.app.QueueUpdate(func() { preview.ScrollToEnd() })
		atEnd := readScreen()
		maxRow, _ := scrollState()
		a.app.Stop()
		if maxRow != row {
			t.Fatalf("acknowledged PgDn stopped the preview at offset %d, but it scrolls to %d at 40x10 (inner height %d, %d wrapped rows)",
				row, maxRow, height, maxRow+height)
		}
		t.Fatalf("raw body tail not reachable by scrolling at 40x10, where the preview is one row (offset %d, inner height %d, %d wrapped rows)\n%s",
			row, height, maxRow+height, atEnd)
	}
	if after := readScreen(); !strings.Contains(after, "Summary:") || !strings.Contains(after, "Request: file create") || !strings.Contains(after, "allow this [o]nce") {
		a.app.Stop()
		t.Fatalf("summary, shape line, or choices scrolled away with the preview\n%s", after)
	}

	h.key(tcell.KeyEnter)
	h.await()
}

func TestPromptOverlay_OverCapTargetListReportsOmittedCount(t *testing.T) {
	req := PromptRequest{
		Action:    "Run command",
		Subject:   "touch a b c d e f g h",
		Kind:      SubjectLiteralCommand,
		RunFolder: "/work",
		Summary:   literalPromptSummary("touch a b c d e f g h"),
	}
	fixed := strings.Join(promptFixedLines(req), "\n")
	if strings.Count(fixed, "Requested target: ") != 6 {
		t.Fatalf("fixed block shows %d target rows, want the cap of 6:\n%s", strings.Count(fixed, "Requested target: "), fixed)
	}
	if !strings.Contains(fixed, "… plus 2 more requested targets; inspect the complete request") {
		t.Fatalf("omitted-target count missing:\n%s", fixed)
	}
	preview := renderPromptPreview(req)
	for _, exact := range []string{"g", "h"} {
		if strings.Contains(preview, "Requested target (exact): "+exact) {
			t.Fatalf("preview repeats capped target %q:\n%s", exact, preview)
		}
	}
}

func TestRenderHostPreview_DoesNotRepeatHostInScrollableRegion(t *testing.T) {
	long := strings.Repeat("sub.", 40) + "example.test"
	req := PromptRequest{
		Kind:        SubjectHost,
		HostTool:    "web_fetch",
		HostRequest: "https://" + long + "/a",
		Host:        long,
		Summary: permissions.PromptSummary(
			permissions.MatchRequest{Kind: "host", Subject: "web_fetch", Host: long},
			permissions.PromptSummaryInput{HostRequest: "https://" + long + "/a"},
		),
	}
	fixed := strings.Join(promptFixedLines(req), "\n")
	if strings.Contains(fixed, long) {
		t.Fatalf("fixed host facts rendered the over-cap host unbounded:\n%s", fixed)
	}
	if strings.Contains(renderPromptPreview(req), "Host (exact): "+long) {
		t.Fatalf("scrollable region repeats the host:\n%s", renderPromptPreview(req))
	}
}

func mergedQuestionPromptRequest() PromptRequest {
	return PromptRequest{
		Action:             "Run tool",
		Kind:               SubjectStructuredTool,
		Body:               "read({\"path\":\"/work/project/main.go\"})\nread({\"path\":\"/work/project/util.go\"})",
		RunFolder:          "/work/project",
		ProjectRoot:        "/work/project",
		FolderSettingsPath: "/work/project/.codemeld/settings.yaml",
		FolderCoverage:     "/work/project and its descendants",
	}
}

func TestRenderPrompt_MergedQuestionShowsOnlyItsOwnCalls(t *testing.T) {
	req := mergedQuestionPromptRequest()
	out := renderPrompt(req)
	for _, w := range []string{
		"read({\"path\":\"/work/project/main.go\"})",
		"read({\"path\":\"/work/project/util.go\"})",
		"Applies when run from: /work/project and its descendants.",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("merged question missing %q\n--- got ---\n%s", w, out)
		}
	}
	for _, banned := range []string{
		"read-only calls need your approval",
		"Calls needing approval:",
		"applies only to call",
		"stages that need your approval",
		"Stages needing approval:",
		"Pipeline:",
		"> ",
	} {
		if strings.Contains(out, banned) {
			t.Errorf("merged question rendered removed group/pipeline chrome %q\n--- got ---\n%s", banned, out)
		}
	}
}

func TestRenderPrompt_QuestionShowsItsOwnEscalationWithoutACallLabel(t *testing.T) {
	req := mergedQuestionPromptRequest()
	req.ScopeEscalationNarrower = "/work/project/assets"
	out := renderPrompt(req)
	if !strings.Contains(out, scopeEscalationNotice+"/work/project/assets") {
		t.Errorf("question dropped its own broaden warning\n--- got ---\n%s", out)
	}
	if n := strings.Count(out, scopeEscalationNotice); n != 1 {
		t.Errorf("broaden warning rendered %d times, want once for the one scope every member shares\n--- got ---\n%s", n, out)
	}
	for _, banned := range []string{"Call 1:", "Call 2:", "Stage 1:"} {
		if strings.Contains(out, banned) {
			t.Errorf("question labelled its warning as one member of a listing (%q)\n--- got ---\n%s", banned, out)
		}
	}
}

type independentHarness struct {
	*promptHarness
	decsc chan []PromptDecision
}

func startPromptIndependent(t *testing.T, a *App, reqs []PromptRequest) *independentHarness {
	t.Helper()
	h := &independentHarness{promptHarness: startPromptLoop(t, a), decsc: make(chan []PromptDecision, 1)}
	go func() {
		ds, _ := a.PromptIndependent(reqs)
		h.decsc <- ds
	}()

	h.waitPage(promptBasePage)
	return h
}

func (h *independentHarness) await() []PromptDecision {
	h.t.Helper()
	var ds []PromptDecision
	select {
	case ds = <-h.decsc:
	case <-time.After(2 * time.Second):
		h.a.app.Stop()
		h.t.Fatal("PromptIndependent did not return decisions within 2s")
	}
	h.a.app.Stop()
	if err := <-h.errc; err != nil {
		h.t.Fatalf("app.Run returned error: %v", err)
	}
	return ds
}

func independentQuestionPromptRequests() []PromptRequest {
	bodies := []string{"read({\"path\":\"/work/project/main.go\"})", "read_image({\"path\":\"/work/project/logo.png\"})"}
	reqs := make([]PromptRequest, len(bodies))
	for i, body := range bodies {
		reqs[i] = PromptRequest{
			Action:        "Run tool",
			Kind:          SubjectStructuredTool,
			Body:          body,
			RunFolder:     "/work/project",
			ApprovalIndex: i + 1,
			ApprovalTotal: len(bodies),
		}
	}
	return reqs
}

func TestPromptIndependent_LoneQuestionShowsNoApprovalCounter(t *testing.T) {
	a := New(nil)
	reqs := []PromptRequest{{
		Action:    "Run tool",
		Kind:      SubjectStructuredTool,
		Body:      "read({\"path\":\"/work/project/main.go\"})",
		RunFolder: "/work/project",
	}}
	h := startPromptIndependent(t, a, reqs)

	got := h.flatScreen()
	if strings.Contains(got, "Approval") {
		h.a.app.Stop()
		t.Fatalf("a lone question showed an approval counter\n--- screen ---\n%s", got)
	}
	if !strings.Contains(got, "main.go") {
		h.a.app.Stop()
		t.Fatalf("lone question did not render the call it decides\n--- screen ---\n%s", got)
	}

	h.key(tcell.KeyEnter)

	decisions := h.await()
	if len(decisions) != 1 || decisions[0].Option != OptionAllowOnce {
		t.Fatalf("decisions = %+v, want one allow-once for the lone question", decisions)
	}
	if a.pages.HasPage(promptBasePage) {
		t.Error("prompt page not removed after the lone question's decision")
	}
	if a.promptOpen {
		t.Error("promptOpen still set after the lone question's decision")
	}
}

func TestPromptIndependent_OneOverlayWalksEveryQuestionAndCleansUpAfterTheLast(t *testing.T) {
	a := New(nil)
	a.input.SetText("typed but not submitted")
	reqs := independentQuestionPromptRequests()
	h := startPromptIndependent(t, a, reqs)

	firstList := focusedPrimitive(h.promptHarness)
	var savedFocus tview.Primitive
	a.app.QueueUpdate(func() { savedFocus = a.promptPrev })
	got := h.flatScreen()
	if !strings.Contains(got, "Approval 1 of 2") {
		h.a.app.Stop()
		t.Fatalf("first question does not show its position in the walk\n--- screen ---\n%s", got)
	}
	if strings.Contains(got, "logo.png") {
		h.a.app.Stop()
		t.Fatalf("first question disclosed the question that follows it\n--- screen ---\n%s", got)
	}

	h.down(1) // deny question 1
	h.key(tcell.KeyEnter)
	waitOnLoop(t, a, "question 2 taking over the open prompt", func() bool {
		return a.app.GetFocus() != firstList
	})

	var (
		open      bool
		overlays  string
		stillPrev tview.Primitive
	)
	a.app.QueueUpdate(func() {
		open = a.pages.HasPage(promptBasePage)
		overlays = snapshotOverlays(a)
		stillPrev = a.promptPrev
	})
	if !open {
		t.Fatal("prompt page gone between the group's decisions; the window must stay open")
	}
	if overlays != "prompt" {
		t.Fatalf("open overlays between decisions = %q, want just the prompt", overlays)
	}
	if stillPrev != savedFocus {
		t.Error("prompt re-saved the prior focus mid-group; one focus lifecycle must span the group")
	}
	second := h.flatScreen()
	if !strings.Contains(second, "Approval 2 of 2") || !strings.Contains(second, "logo.png") {
		h.a.app.Stop()
		t.Fatalf("second question did not take over the open prompt\n--- screen ---\n%s", second)
	}
	if strings.Contains(second, "main.go") {
		h.a.app.Stop()
		t.Fatalf("second question still shows the call it is not deciding\n--- screen ---\n%s", second)
	}

	h.key(tcell.KeyEnter) // allow question 2 once

	decisions := h.await()
	if len(decisions) != len(reqs) {
		t.Fatalf("decisions = %d, want one per question (%d)", len(decisions), len(reqs))
	}
	if decisions[0].Option != OptionDeny {
		t.Errorf("question 1 decision = %d, want OptionDeny (%d)", decisions[0].Option, OptionDeny)
	}
	if decisions[1].Option != OptionAllowOnce {
		t.Errorf("question 2 decision = %d, want OptionAllowOnce (%d)", decisions[1].Option, OptionAllowOnce)
	}
	if a.pages.HasPage(promptBasePage) {
		t.Error("prompt page not removed after the walk's final decision")
	}
	if a.promptOpen {
		t.Error("promptOpen still set after the walk's final decision")
	}
	if a.app.GetFocus() != a.input {
		t.Error("focus not restored to the input area after the walk finished")
	}
	if txt := a.input.GetText(); txt != "typed but not submitted" {
		t.Errorf("input buffer altered by the approval walk: %q", txt)
	}
}

func containmentPromptRequest(entry string) PromptRequest {
	req := fullPromptRequest()
	req.Subject = "chmod +x " + entry
	req.CanonicalProgram = "chmod"
	req.CanonicalArgs = []string{"+x", entry}
	return req
}

func focusedListLabel(h *promptHarness) string {
	label := ""
	h.a.app.QueueUpdate(func() {
		list, ok := h.a.app.GetFocus().(*tview.List)
		if !ok {
			return
		}
		label, _ = list.GetItemText(list.GetCurrentItem())
	})
	return label
}

// settleKeys forces every key injected so far to have been dispatched: the list moves the
// cursor down and back, and each move is waited for on the event loop. Without it a read
// can win the race against a key the loop has not handled yet.
func settleKeys(h *promptHarness, row int) {
	h.t.Helper()
	h.key(tcell.KeyDown)
	waitRow(h, row+1)
	h.key(tcell.KeyUp)
	waitRow(h, row)
}

func waitRow(h *promptHarness, row int) {
	h.t.Helper()
	waitOnLoop(h.t, h.a, fmt.Sprintf("scope chooser cursor reaching row %d", row), func() bool {
		list, ok := h.a.app.GetFocus().(*tview.List)
		return ok && list.GetCurrentItem() == row
	})
}

func TestPromptUser_PathScopeArrowKeysAdjustTheRowInPlace(t *testing.T) {
	tree := newContainmentTree(t)
	a := New(nil)
	a.SetHome(tree.home)
	h := startPrompt(t, a, containmentPromptRequest(tree.entry))

	h.down(2) // allow for this session
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopePage)
	waitRow(h, 2)

	if label := focusedListLabel(h); !strings.Contains(label, ":under="+tree.run) {
		t.Fatalf("path row opened on %q, want the immediate parent %q", label, tree.run)
	}

	h.key(tcell.KeyRight)
	settleKeys(h, 2)
	widened := focusedListLabel(h)
	if !strings.Contains(widened, ":under="+tree.tmp) {
		t.Fatalf("after → the path row reads %q, want the widened boundary %q", widened, tree.tmp)
	}

	// The widest boundary is the last one, so a further → must leave the row where it is.
	h.key(tcell.KeyRight)
	settleKeys(h, 2)
	if label := focusedListLabel(h); label != widened {
		t.Fatalf("→ past the widest boundary changed the row to %q", label)
	}

	h.key(tcell.KeyLeft)
	settleKeys(h, 2)
	narrowed := focusedListLabel(h)
	if !strings.Contains(narrowed, ":under="+tree.run) {
		t.Fatalf("after ← the path row reads %q, want the narrower boundary %q", narrowed, tree.run)
	}

	h.key(tcell.KeyLeft)
	settleKeys(h, 2)
	if label := focusedListLabel(h); label != narrowed {
		t.Fatalf("← below the immediate parent changed the row to %q", label)
	}

	h.key(tcell.KeyRight)
	settleKeys(h, 2)
	h.key(tcell.KeyEnter)
	if h.hasPage(promptScopeConfirmPage) {
		h.a.app.Stop()
		t.Fatal("the path choice opened the program-wide confirm step")
	}

	d := h.await()
	if d.Option != OptionAllowSession {
		t.Fatalf("Option = %d, want OptionAllowSession", d.Option)
	}
	stored, err := permissions.EncodeDirectUnderSubject([]string{"chmod", "+x", tree.entry}, 2, tree.tmp, false)
	if err != nil {
		t.Fatalf("EncodeDirectUnderSubject: %v", err)
	}
	if d.StoredSubject != stored {
		t.Fatalf("StoredSubject = %q, want the displayed boundary %q", d.StoredSubject, tree.tmp)
	}
	sibling := filepath.Join(tree.tmp, "other", "id-ssh")
	if err := os.MkdirAll(filepath.Dir(sibling), 0o755); err != nil {
		t.Fatalf("mkdir sibling: %v", err)
	}
	if err := os.WriteFile(sibling, nil, 0o644); err != nil {
		t.Fatalf("write sibling: %v", err)
	}
	if !permissions.MatchesDirectSubject([]string{"chmod", "+x", sibling}, nil, false, d.StoredSubject) {
		t.Error("the stored grant does not authorize another path under the selected boundary")
	}
	if permissions.MatchesDirectSubject([]string{"chmod", "+x", filepath.Join(tree.home, "keys")}, nil, false, d.StoredSubject) {
		t.Error("the stored grant authorized a path inside home")
	}
}

func TestScopeChooser_UsesAppHomeAcrossSpellingsAndFailsClosed(t *testing.T) {
	tree := newContainmentTree(t)
	root := filepath.Dir(filepath.Dir(tree.home))
	linked := filepath.Join(root, "home-link")
	if err := os.Symlink(tree.home, linked); err != nil {
		t.Fatalf("symlink home: %v", err)
	}
	dangling := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(tree.home, "absent"), dangling); err != nil {
		t.Fatalf("dangling symlink: %v", err)
	}
	loopA, loopB := filepath.Join(root, "loop-a"), filepath.Join(root, "loop-b")
	if err := os.Symlink(loopB, loopA); err != nil {
		t.Fatalf("loop a: %v", err)
	}
	if err := os.Symlink(loopA, loopB); err != nil {
		t.Fatalf("loop b: %v", err)
	}

	// A path below home: only there can a home spelling that is not canonical make home
	// itself, or one of its ancestors, look like a selectable boundary.
	work := filepath.Join(tree.home, "work", "sub")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatalf("mkdir work: %v", err)
	}
	belowHome := filepath.Join(work, "run.sh")
	if err := os.WriteFile(belowHome, nil, 0o644); err != nil {
		t.Fatalf("write below home: %v", err)
	}
	wantBoundaries := []string{work, filepath.Join(tree.home, "work")}

	for _, home := range []string{tree.home, linked, filepath.Join(tree.home, "work", "..")} {
		a := New(nil)
		a.SetHome(home)
		_, list := a.buildScopeChooser(containmentPromptRequest(belowHome), OptionAllowSession, make(chan PromptDecision, 1))
		if list.GetItemCount() != 5 {
			t.Fatalf("home %q gave %d rows, want the ladder with a path row", home, list.GetItemCount())
		}
		var walked []string
		for _, b := range wantBoundaries {
			label, _ := list.GetItemText(2)
			if !strings.Contains(label, ":under="+b+" ") {
				t.Fatalf("home %q path row = %q, want boundary %q", home, label, b)
			}
			walked = append(walked, b)
			list.InputHandler()(tcell.NewEventKey(tcell.KeyRight, 0, tcell.ModNone), func(tview.Primitive) {})
		}
		if len(walked) != len(wantBoundaries) {
			t.Fatalf("home %q walked %v, want %v", home, walked, wantBoundaries)
		}
		last, _ := list.GetItemText(2)
		if !strings.Contains(last, ":under="+wantBoundaries[len(wantBoundaries)-1]+" ") {
			t.Fatalf("home %q stopped at %q, want the widest boundary %q", home, last, wantBoundaries[len(wantBoundaries)-1])
		}
		for i := range list.GetItemCount() {
			label, _ := list.GetItemText(i)
			for _, floor := range []string{tree.home, linked, filepath.Dir(tree.home), root} {
				if strings.Contains(label, ":under="+floor+" ") {
					t.Errorf("home %q offered %q, which is at or above canonical home", home, floor)
				}
			}
		}
	}

	insideHome := filepath.Join(tree.home, "run.sh")
	if err := os.WriteFile(insideHome, nil, 0o644); err != nil {
		t.Fatalf("write inside home: %v", err)
	}
	suppressed := []struct {
		name string
		home string
		req  PromptRequest
	}{
		{"empty home", "", containmentPromptRequest(belowHome)},
		{"relative home", "home/user", containmentPromptRequest(belowHome)},
		{"missing home", filepath.Join(tree.home, "absent"), containmentPromptRequest(belowHome)},
		{"non-directory home", tree.entry, containmentPromptRequest(belowHome)},
		{"dangling symlink home", dangling, containmentPromptRequest(belowHome)},
		{"symlink loop home", loopA, containmentPromptRequest(belowHome)},
		{"path directly inside home", tree.home, containmentPromptRequest(insideHome)},
	}
	for _, c := range suppressed {
		t.Run(c.name, func(t *testing.T) {
			a := New(nil)
			a.SetHome(c.home)
			_, list := a.buildScopeChooser(c.req, OptionAllowSession, make(chan PromptDecision, 1))
			if list.GetItemCount() != 4 {
				t.Fatalf("got %d rows, want the unchanged ladder without a path row", list.GetItemCount())
			}
			for i := range list.GetItemCount() {
				label, _ := list.GetItemText(i)
				if strings.Contains(label, ":under=") {
					t.Fatalf("row %d offered containment: %q", i, label)
				}
			}
			recommended, _ := list.GetItemText(list.GetCurrentItem())
			if !strings.HasSuffix(recommended, scopeRecommendedSuffix) {
				t.Errorf("chooser opened on %q, want the marked recommendation", recommended)
			}
		})
	}
}

func exceptionalDirectRequest() PromptRequest {
	req := fullPromptRequest()
	req.Action = "Allow network access"
	req.Subject = "curl -fsSL https://example.com/install.sh"
	req.CanonicalProgram = "curl"
	req.CanonicalArgs = []string{"-fsSL", "https://example.com/install.sh"}
	req.Pipeline = "curl -fsSL https://example.com/install.sh | wc -c"
	req.ExceptionalAuthority = "network access"
	return req
}

func exceptionalLiteralRequest() PromptRequest {
	command := "sh -c 'rm -rf build'"
	return PromptRequest{
		Action:               "Allow file deletion",
		Subject:              command,
		Kind:                 SubjectLiteralCommand,
		WholeCommand:         true,
		RunFolder:            "/elsewhere/outside",
		ProjectRoot:          "/work/project",
		FolderSettingsPath:   "/work/project/.codemeld/settings.yaml",
		FolderCoverage:       "/elsewhere/outside and all descendants",
		Summary:              literalPromptSummary(command),
		ExceptionalAuthority: "file deletion",
	}
}

func exceptionalBatchedRequest() PromptRequest {
	req := batchedPromptRequest()
	req.Action = "Allow network access"
	req.Pipeline = "rm -f out.txt | curl https://example.com"
	req.BatchedStages = []string{"rm -f out.txt", "curl https://example.com"}
	req.BatchedEscalations = []string{"/work/project/sub", ""}
	req.ExceptionalAuthority = "network access"
	return req
}

func TestRenderPrompt_ExceptionalPromptNamesTheAuthority(t *testing.T) {
	for _, tc := range []struct {
		name  string
		req   PromptRequest
		wants []string
	}{
		{"direct", exceptionalDirectRequest(), []string{
			"Allow network access\nCommand: curl -fsSL https://example.com/install.sh\n",
			"Part of pipeline: curl -fsSL https://example.com/install.sh | wc -c",
		}},
		{"literal", exceptionalLiteralRequest(), []string{
			"Allow file deletion\nCommand: sh -c 'rm -rf build'\n",
			"Whole command approval",
			"Summary: ",
		}},
		{"batched", exceptionalBatchedRequest(), []string{
			"Allow network access\nThis pipeline has 2 stages",
			"Pipeline: rm -f out.txt | curl https://example.com",
			"  rm -f out.txt\n  curl https://example.com\n",
			"Stage 1: " + scopeEscalationNotice + "/work/project/sub",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := renderPrompt(tc.req)
			notice := fmt.Sprintf(ExceptionalSandboxNotice, tc.req.ExceptionalAuthority)
			for _, want := range append(tc.wants, notice, exceptionalAllowOnceExplanation) {
				if !strings.Contains(out, want) {
					t.Errorf("rendered prompt missing %q\n--- got ---\n%s", want, out)
				}
			}
			for _, banned := range []string{
				ShellBlockedPathsNotice, "runs unchecked", "allow in this folder permanently",
				"allow globally permanently", ".codemeld/settings.yaml", "cross-mode", "launch directory",
			} {
				if strings.Contains(out, banned) {
					t.Errorf("rendered prompt contains %q\n--- got ---\n%s", banned, out)
				}
			}
		})
	}
}

func TestPromptOverlay_ExceptionalOffersOnlyAllowOnceAndDeny(t *testing.T) {
	for _, req := range []PromptRequest{exceptionalDirectRequest(), exceptionalLiteralRequest(), exceptionalBatchedRequest()} {
		if got := promptOptionsFor(req); !equalOptions(got, []PromptOption{OptionAllowOnce, OptionDeny}) {
			t.Fatalf("%s options = %v, want allow once and deny", req.Subject, optionValues(got))
		}
		overlay, list := New(nil).buildPromptOverlay(req, make(chan PromptDecision, 1))
		if list.GetItemCount() != 2 {
			t.Fatalf("%s list rows = %d, want 2", req.Subject, list.GetItemCount())
		}
		flex := overlay.(*tview.Flex)
		for i := 0; i < flex.GetItemCount(); i++ {
			if tv, ok := flex.GetItem(i).(*tview.TextView); ok {
				if text := tv.GetText(false); strings.Contains(text, folderUnavailableExplanation) || strings.Contains(text, untrustedProjectGrantExplanation) {
					t.Fatalf("%s overlay explains a saved grant: %q", req.Subject, text)
				}
			}
		}
	}
	unmarked := exceptionalDirectRequest()
	unmarked.ExceptionalAuthority = ""
	if got := promptOptionsFor(unmarked); !equalOptions(got, optionValues(promptOptionsInOrder)) {
		t.Fatalf("unmarked options = %v, want every option", optionValues(got))
	}
}

func TestPromptUser_ExceptionalHasNoGrantShortcutOrScopeChooser(t *testing.T) {
	for _, req := range []PromptRequest{exceptionalDirectRequest(), exceptionalLiteralRequest(), exceptionalBatchedRequest()} {
		t.Run(req.Subject, func(t *testing.T) {
			h := startPrompt(t, New(nil), req)
			h.assertRunesInert("sSgGfFpP", 0)
			h.down(4)
			h.key(tcell.KeyEnter)
			d := h.await()
			if (d.Option != OptionAllowOnce && d.Option != OptionDeny) || d.StoredSubject != "" {
				t.Fatalf("decision = %+v, want a bare allow once or deny", d)
			}
		})
	}
	h := startPrompt(t, New(nil), exceptionalDirectRequest())
	h.typeText("o")
	if d := h.await(); d.Option != OptionAllowOnce || d.StoredSubject != "" {
		t.Fatalf("allow once decision = %+v, want a bare allow once", d)
	}
}
