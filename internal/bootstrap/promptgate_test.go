// Tests for the gated permission-prompt adapter (promptgate.go): the
// MatchRequest+display -> tui.PromptRequest mapping (including the structured-tool
// subject/command-text split), the tui.PromptDecision -> permissions.PromptOutcome
// option mapping, the single-slot one-at-a-time guarantee, and the cancel-while-
// waiting path, all driven through a fake prompt.
package bootstrap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/netproxy"
	"codemeld.dev/codemeld/internal/permissions"
	cmdrunner "codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/tui"
)

func TestBuildPromptRequest_Mapping(t *testing.T) {
	display := PromptDisplay{
		ProjectRoot:             "/work/proj",
		LaunchDir:               "/work",
		Boundary:                "project-root",
		FolderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
		FolderCoverage:          "/work/proj and its descendants",
		WouldCreateSettingsFile: true,
	}

	cases := []struct {
		name string
		req  permissions.MatchRequest
		disp PromptDisplay // only the human-readable Action/Subject/Body vary per case
		esc  permissions.ScopeEscalation
		want tui.PromptRequest
	}{
		{
			name: "direct command derives canonical program and args from tokens",
			req: permissions.MatchRequest{
				Kind:          "direct",
				Subject:       "git log --oneline",
				SubjectTokens: []string{"git", "log", "--oneline"},
				PathScope:     "/work/proj/sub",
			},
			disp: PromptDisplay{Action: "Run command", Subject: "git log --oneline"},
			want: tui.PromptRequest{
				Action:                  "Run command",
				Subject:                 "git log --oneline",
				Kind:                    tui.SubjectDirectCommand,
				CanonicalProgram:        "git",
				CanonicalArgs:           []string{"log", "--oneline"},
				RunFolder:               "/work/proj/sub",
				ProjectRoot:             "/work/proj",
				FolderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
				FolderCoverage:          "/work/proj and its descendants",
				LaunchDir:               "/work",
				Boundary:                "project-root",
				WouldCreateSettingsFile: true,
			},
		},
		{
			name: "literal command carries no canonical tokens",
			req: permissions.MatchRequest{
				Kind:      "literal",
				Subject:   "git status > out",
				PathScope: "/work/proj",
			},
			disp: PromptDisplay{Action: "Run command", Subject: "git status > out"},
			want: tui.PromptRequest{
				Action:                  "Run command",
				Subject:                 "git status > out",
				Kind:                    tui.SubjectLiteralCommand,
				RunFolder:               "/work/proj",
				ProjectRoot:             "/work/proj",
				FolderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
				FolderCoverage:          "/work/proj and its descendants",
				LaunchDir:               "/work",
				Boundary:                "project-root",
				WouldCreateSettingsFile: true,
			},
		},
		{
			// A literal command the backend recognizes as a simple compound carries its
			// ordered stage/operator decomposition so the prompt can open the per-stage chooser. The
			// decomposition is the backend recognizer's, not a bootstrap-local parse.
			name: "recognized bare simple compound carries the backend stage decomposition",
			req: permissions.MatchRequest{
				Kind:      "literal",
				Subject:   "gofmt -w a.go && go build ./...",
				PathScope: "/work/proj",
			},
			disp: PromptDisplay{Action: "Run command", Subject: "gofmt -w a.go && go build ./..."},
			want: tui.PromptRequest{
				Action:                  "Run command",
				Subject:                 "gofmt -w a.go && go build ./...",
				Kind:                    tui.SubjectLiteralCommand,
				RunFolder:               "/work/proj",
				ProjectRoot:             "/work/proj",
				FolderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
				FolderCoverage:          "/work/proj and its descendants",
				LaunchDir:               "/work",
				Boundary:                "project-root",
				WouldCreateSettingsFile: true,
				Compound: &permissions.SimpleCompound{
					Wrapped:   false,
					Stages:    [][]string{{"gofmt", "-w", "a.go"}, {"go", "build", "./..."}},
					Operators: []string{"&&"},
				},
			},
		},
		{
			// The single accepted wrapper flavour `sh -c '<compound>'` is recognized too and records
			// Wrapped=true — this is the manual-verification command, so the mapping is proven here.
			name: "recognized wrapped simple compound records the wrapper flavour",
			req: permissions.MatchRequest{
				Kind:      "literal",
				Subject:   `sh -c 'gofmt -w a.go && go build ./...'`,
				PathScope: "/work/proj",
			},
			disp: PromptDisplay{Action: "Run command", Subject: `sh -c 'gofmt -w a.go && go build ./...'`},
			want: tui.PromptRequest{
				Action:                  "Run command",
				Subject:                 `sh -c 'gofmt -w a.go && go build ./...'`,
				Kind:                    tui.SubjectLiteralCommand,
				RunFolder:               "/work/proj",
				ProjectRoot:             "/work/proj",
				FolderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
				FolderCoverage:          "/work/proj and its descendants",
				LaunchDir:               "/work",
				Boundary:                "project-root",
				WouldCreateSettingsFile: true,
				Compound: &permissions.SimpleCompound{
					Wrapped:   true,
					Stages:    [][]string{{"gofmt", "-w", "a.go"}, {"go", "build", "./..."}},
					Operators: []string{"&&"},
				},
			},
		},
		{
			// A compound with a destructive stage (git) is still recognized here — its stages are shown
			// and, locked to exact by the chooser, the downstream EncodeCompoundSubject refuses to
			// generalize it so the grant stays byte-exact. Recognition for the prompt flow and the
			// no-widen persistence guarantee are separate concerns; promptgate does not pre-filter it.
			name: "recognized destructive-stage compound still carries the decomposition for the prompt flow",
			req: permissions.MatchRequest{
				Kind:      "literal",
				Subject:   "gofmt -w a.go && git add .",
				PathScope: "/work/proj",
			},
			disp: PromptDisplay{Action: "Run command", Subject: "gofmt -w a.go && git add ."},
			want: tui.PromptRequest{
				Action:                  "Run command",
				Subject:                 "gofmt -w a.go && git add .",
				Kind:                    tui.SubjectLiteralCommand,
				RunFolder:               "/work/proj",
				ProjectRoot:             "/work/proj",
				FolderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
				FolderCoverage:          "/work/proj and its descendants",
				LaunchDir:               "/work",
				Boundary:                "project-root",
				WouldCreateSettingsFile: true,
				Compound: &permissions.SimpleCompound{
					Wrapped:   false,
					Stages:    [][]string{{"gofmt", "-w", "a.go"}, {"git", "add", "."}},
					Operators: []string{"&&"},
				},
			},
		},
		{
			// `||` now follows the same simple-compound prompt path as `&&`: promptgate defers wholly to
			// the backend recognizer and carries its stage/operator decomposition.
			name: "recognized logical-or simple compound carries metadata",
			req: permissions.MatchRequest{
				Kind:      "literal",
				Subject:   "make build || echo failed",
				PathScope: "/work/proj",
			},
			disp: PromptDisplay{Action: "Run command", Subject: "make build || echo failed"},
			want: tui.PromptRequest{
				Action:                  "Run command",
				Subject:                 "make build || echo failed",
				Kind:                    tui.SubjectLiteralCommand,
				RunFolder:               "/work/proj",
				ProjectRoot:             "/work/proj",
				FolderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
				FolderCoverage:          "/work/proj and its descendants",
				LaunchDir:               "/work",
				Boundary:                "project-root",
				WouldCreateSettingsFile: true,
				Compound: &permissions.SimpleCompound{
					Wrapped:   false,
					Stages:    [][]string{{"make", "build"}, {"echo", "failed"}},
					Operators: []string{"||"},
				},
			},
		},
		{
			name: "eligible null-redirect literal carries stripped chooser metadata and the verbatim prompt text",
			req: permissions.MatchRequest{
				Kind:      "literal",
				Subject:   "./p.sh u.txt 2>/dev/null | sed -n 1,18p",
				PathScope: "/work/proj",
			},
			disp: PromptDisplay{Action: "Run command", Subject: "./p.sh u.txt 2>/dev/null | sed -n 1,18p"},
			want: tui.PromptRequest{
				Action:                  "Run command",
				Subject:                 "./p.sh u.txt 2>/dev/null | sed -n 1,18p",
				Kind:                    tui.SubjectLiteralCommand,
				RunFolder:               "/work/proj",
				ProjectRoot:             "/work/proj",
				FolderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
				FolderCoverage:          "/work/proj and its descendants",
				LaunchDir:               "/work",
				Boundary:                "project-root",
				WouldCreateSettingsFile: true,
				Compound: &permissions.SimpleCompound{
					Wrapped:   false,
					Stages:    [][]string{{"./p.sh", "u.txt"}, {"sed", "-n", "1,18p"}},
					Operators: []string{"|"},
				},
			},
		},
		{
			name: "ineligible redirect leaves the literal without chooser metadata",
			req: permissions.MatchRequest{
				Kind:      "literal",
				Subject:   "./p.sh u.txt 2>&1 | sed -n 1,18p",
				PathScope: "/work/proj",
			},
			disp: PromptDisplay{Action: "Run command", Subject: "./p.sh u.txt 2>&1 | sed -n 1,18p"},
			want: tui.PromptRequest{
				Action:                  "Run command",
				Subject:                 "./p.sh u.txt 2>&1 | sed -n 1,18p",
				Kind:                    tui.SubjectLiteralCommand,
				RunFolder:               "/work/proj",
				ProjectRoot:             "/work/proj",
				FolderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
				FolderCoverage:          "/work/proj and its descendants",
				LaunchDir:               "/work",
				Boundary:                "project-root",
				WouldCreateSettingsFile: true,
			},
		},
		{
			name: "structured create tool shows the file and content, not the matching subject",
			req: permissions.MatchRequest{
				Kind:      "tool",
				Subject:   "create",
				PathScope: "/work/proj",
			},
			disp: PromptDisplay{Action: "Create file", Subject: "provinces.md", Body: "1. Alberta\n"},
			want: tui.PromptRequest{
				Action:                  "Create file",
				Subject:                 "provinces.md",
				Body:                    "1. Alberta\n",
				Kind:                    tui.SubjectStructuredTool,
				RunFolder:               "/work/proj",
				ProjectRoot:             "/work/proj",
				FolderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
				FolderCoverage:          "/work/proj and its descendants",
				LaunchDir:               "/work",
				Boundary:                "project-root",
				WouldCreateSettingsFile: true,
			},
		},
		{
			// The out-of-root edit/create signal maps straight through onto the tui request, so
			// the prompt can re-enable the folder option for that write. Every other case above leaves it
			// unset, proving it defaults false for direct/literal/in-root-create kinds.
			name: "out-of-root structured edit carries the folder-grant signal",
			req: permissions.MatchRequest{
				Kind:      "tool",
				Subject:   "edit",
				PathScope: "/outside/tree",
			},
			disp: PromptDisplay{Action: "Edit file", Subject: "/outside/tree/main.go", Body: "Replace:\na\nWith:\nb", OutOfRootFileWrite: true},
			want: tui.PromptRequest{
				Action:                  "Edit file",
				Subject:                 "/outside/tree/main.go",
				Body:                    "Replace:\na\nWith:\nb",
				Kind:                    tui.SubjectStructuredTool,
				RunFolder:               "/outside/tree",
				ProjectRoot:             "/work/proj",
				FolderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
				FolderCoverage:          "/work/proj and its descendants",
				OutOfRootFileWrite:      true,
				LaunchDir:               "/work",
				Boundary:                "project-root",
				WouldCreateSettingsFile: true,
			},
		},
		{
			// The out-of-project read-only scope signal maps straight through onto the tui request, so
			// the prompt can offer the folder option for that external read. The out-of-project PathScope means
			// the test would fail if buildPromptRequest dropped the signal — the folder option would then be
			// hidden for a production external-read prompt even though dispatch flagged it. Every other case
			// leaves OutOfRootReadScope unset, proving it defaults false for direct/literal/in-root/out-of-root-write kinds.
			name: "out-of-project read-only tool carries the external-read folder signal",
			req: permissions.MatchRequest{
				Kind:      "tool",
				Subject:   "glob",
				PathScope: "/outside/tree",
			},
			disp: PromptDisplay{Action: "Run tool", Subject: "glob", Body: `glob({"path":"/outside/tree"})`, OutOfRootReadScope: true},
			want: tui.PromptRequest{
				Action:                  "Run tool",
				Subject:                 "glob",
				Body:                    `glob({"path":"/outside/tree"})`,
				Kind:                    tui.SubjectStructuredTool,
				RunFolder:               "/outside/tree",
				ProjectRoot:             "/work/proj",
				FolderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
				FolderCoverage:          "/work/proj and its descendants",
				OutOfRootReadScope:      true,
				LaunchDir:               "/work",
				Boundary:                "project-root",
				WouldCreateSettingsFile: true,
			},
		},
		{
			// The capability stored subject (write/read*) maps straight through onto the tui
			// request, so a grant-creating choice stores the folded capability rather than the concrete
			// tool name. Every other case leaves GrantStoredSubject unset, proving it defaults empty.
			name: "structured create carries the write capability stored subject",
			req:  permissions.MatchRequest{Kind: "tool", Subject: "create", PathScope: "/work/proj"},
			disp: PromptDisplay{Action: "Create file", Subject: "a.go", Body: "x\n", GrantStoredSubject: permissions.CapabilityWrite},
			want: tui.PromptRequest{
				Action:                  "Create file",
				Subject:                 "a.go",
				Body:                    "x\n",
				Kind:                    tui.SubjectStructuredTool,
				RunFolder:               "/work/proj",
				ProjectRoot:             "/work/proj",
				FolderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
				FolderCoverage:          "/work/proj and its descendants",
				CapabilityStoredSubject: permissions.CapabilityWrite,
				LaunchDir:               "/work",
				Boundary:                "project-root",
				WouldCreateSettingsFile: true,
			},
		},
		{
			// The display-only scope-escalation narrower scope maps straight through onto
			// the tui request so the prompt can warn that the request broadens an existing grant.
			// Every other case leaves esc zero, proving ScopeEscalationNarrower defaults empty.
			name: "scope escalation carries the narrower already-approved scope",
			req:  permissions.MatchRequest{Kind: "tool", Subject: "read", PathScope: "/work/proj"},
			disp: PromptDisplay{Action: "Run tool", Subject: "read", Body: `read(...)`},
			esc:  permissions.ScopeEscalation{NarrowerScope: "/work/proj/sub"},
			want: tui.PromptRequest{
				Action:                  "Run tool",
				Subject:                 "read",
				Body:                    `read(...)`,
				Kind:                    tui.SubjectStructuredTool,
				RunFolder:               "/work/proj",
				ProjectRoot:             "/work/proj",
				FolderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
				FolderCoverage:          "/work/proj and its descendants",
				LaunchDir:               "/work",
				Boundary:                "project-root",
				WouldCreateSettingsFile: true,
				ScopeEscalationNarrower: "/work/proj/sub",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := display
			d.Action = tc.disp.Action
			d.Subject = tc.disp.Subject
			d.Body = tc.disp.Body
			d.OutOfRootFileWrite = tc.disp.OutOfRootFileWrite
			d.OutOfRootReadScope = tc.disp.OutOfRootReadScope
			d.GrantStoredSubject = tc.disp.GrantStoredSubject
			got, err := buildPromptRequest(tc.req, d, tc.esc)
			if err != nil {
				t.Fatalf("buildPromptRequest returned error: %v", err)
			}
			if got.Summary.Sentence == "" || got.Summary.Effect == "" {
				t.Fatalf("mapped request carries no approval summary: %#v", got.Summary)
			}
			got.Summary = permissions.PromptSummaryResult{}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("buildPromptRequest mismatch\n got: %#v\nwant: %#v", got, tc.want)
			}
		})
	}
}

// TestBuildPromptRequest_MapsShellContext proves the shell-context carrier completion: the
// display-only shell context (the full pipeline for a direct pipeline stage, the
// whole-command marker for a literal route) maps straight from bootstrap.PromptDisplay
// onto tui.PromptRequest, and stays empty for a single direct command and a
// structured-tool prompt so no non-shell prompt inherits the shell framing.
func TestBuildPromptRequest_MapsShellContext(t *testing.T) {
	cases := []struct {
		name         string
		req          permissions.MatchRequest
		disp         PromptDisplay
		wantPipeline string
		wantWhole    bool
	}{
		{
			name:         "direct pipeline stage carries the full pipeline text",
			req:          permissions.MatchRequest{Kind: "direct", Subject: "grep x", SubjectTokens: []string{"grep", "x"}, PathScope: "/work"},
			disp:         PromptDisplay{Action: "Run command", Subject: "grep x", Pipeline: "cat file | grep x"},
			wantPipeline: "cat file | grep x",
		},
		{
			name:      "literal route marks a whole-command approval and carries no pipeline",
			req:       permissions.MatchRequest{Kind: "literal", Subject: "git status > out", PathScope: "/work"},
			disp:      PromptDisplay{Action: "Run command", Subject: "git status > out", WholeCommand: true},
			wantWhole: true,
		},
		{
			name: "single direct command carries neither field",
			req:  permissions.MatchRequest{Kind: "direct", Subject: "ls -l", SubjectTokens: []string{"ls", "-l"}, PathScope: "/work"},
			disp: PromptDisplay{Action: "Run command", Subject: "ls -l"},
		},
		{
			name: "structured tool leaves the shell context empty",
			req:  permissions.MatchRequest{Kind: "tool", Subject: "create", PathScope: "/work"},
			disp: PromptDisplay{Action: "Create file", Subject: "a.md", Body: "x\n"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildPromptRequest(tc.req, tc.disp, permissions.ScopeEscalation{})
			if err != nil {
				t.Fatalf("buildPromptRequest returned error: %v", err)
			}
			if got.Pipeline != tc.wantPipeline {
				t.Errorf("Pipeline = %q, want %q", got.Pipeline, tc.wantPipeline)
			}
			if got.WholeCommand != tc.wantWhole {
				t.Errorf("WholeCommand = %v, want %v", got.WholeCommand, tc.wantWhole)
			}
		})
	}
}

func TestBuildPromptRequest_UnknownKind(t *testing.T) {
	_, err := buildPromptRequest(permissions.MatchRequest{Kind: "mystery"}, PromptDisplay{}, permissions.ScopeEscalation{})
	if err == nil {
		t.Fatal("buildPromptRequest accepted an unknown subject kind, want error")
	}
}

// TestBuildBatchPromptRequest_CarriesPerStageEscalation proves a multi-stage batched prompt does not
// drop a stage's scope-escalation warning: buildBatchPromptRequest surfaces each stage's narrower
// already-approved scope in BatchedEscalations, index-aligned with BatchedStages, so batching cannot
// hide a broaden-of-an-already-approved-folder warning a per-stage prompt would show.
func TestBuildBatchPromptRequest_CarriesPerStageEscalation(t *testing.T) {
	prompts := []permissions.BatchPromptRequest{
		{Req: permissions.MatchRequest{Kind: "direct", Subject: "find . -name x", PathScope: "/work"},
			Escalation: permissions.ScopeEscalation{NarrowerScope: "/work/sub"}},
		{Req: permissions.MatchRequest{Kind: "direct", Subject: "grep foo", PathScope: "/work"}, Index: 1},
	}
	displays := []PromptDisplay{
		{Action: "Run command", Subject: "find . -name x"},
		{Action: "Run command", Subject: "grep foo"},
	}
	pr, err := buildBatchPromptRequest(prompts, displays, nil)
	if err != nil {
		t.Fatalf("buildBatchPromptRequest returned error: %v", err)
	}
	want := []string{"/work/sub", ""}
	if !reflect.DeepEqual(pr.BatchedEscalations, want) {
		t.Fatalf("BatchedEscalations = %#v, want %#v (per-stage narrower scope, index-aligned)", pr.BatchedEscalations, want)
	}
	if len(pr.BatchedStages) != len(pr.BatchedEscalations) {
		t.Fatalf("BatchedStages (%d) and BatchedEscalations (%d) must be index-aligned",
			len(pr.BatchedStages), len(pr.BatchedEscalations))
	}
}

func TestBuildPromptRequest_CopiesTheNoteUnchanged(t *testing.T) {
	const note = "  System One check failed: out of credits\n"
	for _, kind := range []string{"direct", "literal", "tool"} {
		pr, err := buildPromptRequest(permissions.MatchRequest{Kind: kind, Subject: "x", PathScope: "/work"}, PromptDisplay{}, permissions.ScopeEscalation{Note: note})
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if pr.Note != note {
			t.Fatalf("%s: Note = %q, want %q unchanged", kind, pr.Note, note)
		}
	}
}

func TestBuildBatchPromptRequest_CarriesPerStageNotes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		notes []string
	}{
		{"second stage only", []string{"", "out of credits"}},
		{"two distinct notes", []string{"no key", "out of credits"}},
		{"all empty", []string{"", ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prompts := []permissions.BatchPromptRequest{
				{Req: permissions.MatchRequest{Kind: "direct", Subject: "find . -name x", PathScope: "/work"},
					Escalation: permissions.ScopeEscalation{Note: tc.notes[0]}},
				{Req: permissions.MatchRequest{Kind: "direct", Subject: "grep foo", PathScope: "/work"}, Index: 1,
					Escalation: permissions.ScopeEscalation{Note: tc.notes[1]}},
			}
			displays := []PromptDisplay{
				{Action: "Run command", Subject: "find . -name x"},
				{Action: "Run command", Subject: "grep foo"},
			}
			pr, err := buildBatchPromptRequest(prompts, displays, nil)
			if err != nil {
				t.Fatalf("buildBatchPromptRequest returned error: %v", err)
			}
			if !reflect.DeepEqual(pr.BatchedNotes, tc.notes) {
				t.Fatalf("BatchedNotes = %#v, want %#v index-aligned with the stages", pr.BatchedNotes, tc.notes)
			}
			if pr.Note != "" {
				t.Fatalf("Note = %q, want empty so a batched note is not shown twice", pr.Note)
			}
		})
	}
}

func TestBuildBatchPromptRequest_ListsSourceSpellingPerStage(t *testing.T) {
	prompts := []permissions.BatchPromptRequest{
		{Req: permissions.MatchRequest{Kind: "direct", Subject: "git commit -m a b", PathScope: "/work"}, Index: 0},
		{Req: permissions.MatchRequest{Kind: "direct", Subject: "git commit -m a b", PathScope: "/work"}, Index: 1},
		{Req: permissions.MatchRequest{Kind: "direct", Subject: "tee out.txt", PathScope: "/work"}, Index: 2},
	}
	displays := []PromptDisplay{
		{Action: "Run command", Subject: `git commit -m "a b"`},
		{Action: "Run command", Subject: `git commit -m 'a b'`},
		{Action: "Run command", Subject: "tee out.txt"},
	}
	pr, err := buildBatchPromptRequest(prompts, displays, nil)
	if err != nil {
		t.Fatalf("buildBatchPromptRequest returned error: %v", err)
	}
	want := []string{`git commit -m "a b"`, `git commit -m 'a b'`, "tee out.txt"}
	if !reflect.DeepEqual(pr.BatchedStages, want) {
		t.Fatalf("BatchedStages = %#v, want %#v (each stage's source spelling, not the canonical subject)", pr.BatchedStages, want)
	}
	for i, p := range prompts {
		if p.Req.Subject != []string{"git commit -m a b", "git commit -m a b", "tee out.txt"}[i] {
			t.Errorf("stage %d request subject = %q, want it left canonical", i, p.Req.Subject)
		}
	}
}

// TestBuildBatchPromptRequest_SingleStageUsesOrdinaryPrompt proves the N=1 batched seam renders as the
// ordinary single-stage prompt: buildBatchPromptRequest with exactly one unresolved stage takes its
// len(prompts)==1 branch and returns the plain buildPromptRequest shape — original Subject, Pipeline,
// scope escalation, and canonical command preserved, with no batched chrome — so a single-unresolved
// pipeline stage never grows batched fields the per-stage prompt would not show.
func TestBuildBatchPromptRequest_SingleStageUsesOrdinaryPrompt(t *testing.T) {
	prompts := []permissions.BatchPromptRequest{
		{Req: permissions.MatchRequest{Kind: "direct", Subject: "find . -name x",
			SubjectTokens: []string{"find", ".", "-name", "x"}, PathScope: "/work"},
			Escalation: permissions.ScopeEscalation{NarrowerScope: "/work/sub", Note: "System One check: no Venice API key"}},
	}
	displays := []PromptDisplay{
		{Action: "Run command", Subject: "find . -name x", Pipeline: "cat file | find x"},
	}
	pr, err := buildBatchPromptRequest(prompts, displays, nil)
	if err != nil {
		t.Fatalf("buildBatchPromptRequest returned error: %v", err)
	}
	if pr.Subject != "find . -name x" {
		t.Errorf("Subject = %q, want the original single-stage subject (batched fallthrough would clear it)", pr.Subject)
	}
	if pr.Pipeline != "cat file | find x" {
		t.Errorf("Pipeline = %q, want the stage's pipeline text", pr.Pipeline)
	}
	if pr.ScopeEscalationNarrower != "/work/sub" {
		t.Errorf("ScopeEscalationNarrower = %q, want %q", pr.ScopeEscalationNarrower, "/work/sub")
	}
	if pr.CanonicalProgram != "find" || !reflect.DeepEqual(pr.CanonicalArgs, []string{".", "-name", "x"}) {
		t.Errorf("canonical command = %q %#v, want find [. -name x]", pr.CanonicalProgram, pr.CanonicalArgs)
	}
	if len(pr.BatchedStages) != 0 || len(pr.BatchedEscalations) != 0 || len(pr.BatchedNotes) != 0 {
		t.Errorf("BatchedStages=%#v BatchedEscalations=%#v BatchedNotes=%#v, want all empty for an N=1 batch",
			pr.BatchedStages, pr.BatchedEscalations, pr.BatchedNotes)
	}
	if pr.Note != "System One check: no Venice API key" {
		t.Errorf("Note = %q, want the single stage's own note", pr.Note)
	}
}

// TestApplyShellContext_CarriesDispatchShellContext proves the dispatch->bootstrap carry of the
// display-only shell scope/pipeline context: a direct pipeline stage carries the full pipeline
// text, a literal route marks a whole-command approval, a single direct command carries neither, and a
// structured-tool prompt leaves both empty — while every other field of the bootstrap display is
// preserved. The fields are not yet mapped onto tui.PromptRequest (that is the later TUI slice), so
// this carrier is where the mirror is asserted.
func TestApplyShellContext_CarriesDispatchShellContext(t *testing.T) {
	cases := []struct {
		name         string
		disp         dispatch.PromptDisplay
		wantPipeline string
		wantWhole    bool
	}{
		{
			name:         "direct pipeline stage carries the full pipeline and no whole-command marker",
			disp:         dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: "grep x", Pipeline: "cat file | grep x"},
			wantPipeline: "cat file | grep x",
		},
		{
			name:      "literal route marks a whole-command approval and carries no pipeline",
			disp:      dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: "git status > out", WholeCommand: true},
			wantWhole: true,
		},
		{
			name: "single direct command carries neither field",
			disp: dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: "ls -l"},
		},
		{
			name: "structured-tool prompt leaves the shell context fields empty",
			disp: dispatch.PromptDisplay{Action: dispatch.ActionCreateFile, Subject: "a.md", Body: "x\n", GrantStoredSubject: permissions.CapabilityWrite},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// a non-empty base display proves the carry mirrors only the two shell fields and
			// preserves everything else already resolved on the bootstrap display.
			base := PromptDisplay{Action: tc.disp.Action, Subject: tc.disp.Subject, Body: tc.disp.Body, ProjectRoot: "/work/proj"}
			got := applyShellContext(base, tc.disp)
			if got.Pipeline != tc.wantPipeline {
				t.Errorf("Pipeline = %q, want %q", got.Pipeline, tc.wantPipeline)
			}
			if got.WholeCommand != tc.wantWhole {
				t.Errorf("WholeCommand = %v, want %v", got.WholeCommand, tc.wantWhole)
			}
			base.Pipeline, base.WholeCommand = tc.wantPipeline, tc.wantWhole
			if got != base {
				t.Errorf("applyShellContext altered a field other than the shell context: got %#v, want %#v", got, base)
			}
		})
	}
}

func TestMapOutcome(t *testing.T) {
	cases := []struct {
		name string
		in   tui.PromptDecision
		want permissions.PromptOutcome
	}{
		{
			name: "allow once",
			in:   tui.PromptDecision{Option: tui.OptionAllowOnce},
			want: permissions.PromptOutcome{Choice: permissions.PromptAllowOnce},
		},
		{
			name: "deny copies envelope",
			in:   tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: "denied: not allowed"},
			want: permissions.PromptOutcome{Choice: permissions.PromptDeny, DenyEnvelope: "denied: not allowed"},
		},
		{
			name: "deny never carries a stored subject",
			in:   tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: "denied", StoredSubject: "git log :*"},
			want: permissions.PromptOutcome{Choice: permissions.PromptDeny, DenyEnvelope: "denied"},
		},
		{
			name: "session grant preserves direct-command stored subject",
			in:   tui.PromptDecision{Option: tui.OptionAllowSession, StoredSubject: "git log :*"},
			want: permissions.PromptOutcome{Choice: permissions.PromptAllowSession, StoredSubject: "git log :*"},
		},
		{
			name: "folder grant preserves stored subject",
			in:   tui.PromptDecision{Option: tui.OptionAllowFolder, StoredSubject: "make :*"},
			want: permissions.PromptOutcome{Choice: permissions.PromptAllowFolder, StoredSubject: "make :*"},
		},
		{
			name: "folder grant preserves the tool capability stored subject",
			in:   tui.PromptDecision{Option: tui.OptionAllowFolder, StoredSubject: permissions.CapabilityWrite},
			want: permissions.PromptOutcome{Choice: permissions.PromptAllowFolder, StoredSubject: permissions.CapabilityWrite},
		},
		{
			name: "global grant preserves stored subject",
			in:   tui.PromptDecision{Option: tui.OptionAllowGlobal, StoredSubject: "ls -la /tmp"},
			want: permissions.PromptOutcome{Choice: permissions.PromptAllowGlobal, StoredSubject: "ls -la /tmp"},
		},
		{
			name: "grant on a non-direct subject stores no subject",
			in:   tui.PromptDecision{Option: tui.OptionAllowSession},
			want: permissions.PromptOutcome{Choice: permissions.PromptAllowSession},
		},
		{
			// The backend generalized compound subject the chooser encoded survives to the
			// permissions outcome for a grant-creating choice, unchanged — mapOutcome treats it like
			// any other stored subject, so no compound-specific wiring is needed on this seam.
			name: "session grant preserves the generalized compound stored subject",
			in:   tui.PromptDecision{Option: tui.OptionAllowSession, StoredSubject: "compound/v1 W gofmt :* && go build :*"},
			want: permissions.PromptOutcome{Choice: permissions.PromptAllowSession, StoredSubject: "compound/v1 W gofmt :* && go build :*"},
		},
		{
			name: "folder grant preserves the generalized compound stored subject",
			in:   tui.PromptDecision{Option: tui.OptionAllowFolder, StoredSubject: "compound/v1 B gofmt :* && go build :*"},
			want: permissions.PromptOutcome{Choice: permissions.PromptAllowFolder, StoredSubject: "compound/v1 B gofmt :* && go build :*"},
		},
		{
			// allow-once creates no grant, so even a populated stored subject is dropped — the same
			// guarantee the deny case proves, on the non-persisting allow path.
			name: "allow-once drops any stored subject",
			in:   tui.PromptDecision{Option: tui.OptionAllowOnce, StoredSubject: "compound/v1 W gofmt :* && go build :*"},
			want: permissions.PromptOutcome{Choice: permissions.PromptAllowOnce},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mapOutcome(tc.in)
			if err != nil {
				t.Fatalf("mapOutcome returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("mapOutcome = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestMapOutcome_UnknownOption(t *testing.T) {
	_, err := mapOutcome(tui.PromptDecision{Option: tui.PromptOption(99)})
	if err == nil {
		t.Fatal("mapOutcome accepted an unknown prompt option, want error")
	}
}

// TestGatedPrompt_StructuredToolEndToEnd drives the whole adapter through a fake
// prompt: the closure must hand the prompt the human-readable action/subject/body
// display — not the matching subject, which stays on MatchRequest for
// grants/events — and map the returned decision back to a permissions.PromptOutcome.
// It also confirms the closure satisfies permissions.AuthorizeDeps.Prompt.
func TestGatedPrompt_StructuredToolEndToEnd(t *testing.T) {
	var got tui.PromptRequest
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		got = req
		return tui.PromptDecision{Option: tui.OptionAllowGlobal, StoredSubject: ""}, nil
	}
	b := newPromptGateBuilder(show)

	req := permissions.MatchRequest{Kind: "tool", Subject: "Read", PathScope: "/work/proj"}
	display := PromptDisplay{
		Action:      "Run tool",
		Subject:     "Read",
		Body:        `Read({"path":"/work/proj/main.go"})`,
		ProjectRoot: "/work/proj",
		LaunchDir:   "/work/proj",
		Boundary:    "project-root",
	}

	// The builder's product must be usable as AuthorizeDeps.Prompt.
	deps := permissions.AuthorizeDeps{Prompt: b.Build(req, display)}
	outcome, err := deps.Prompt(context.Background(), permissions.ScopeEscalation{})
	if err != nil {
		t.Fatalf("prompt closure returned error: %v", err)
	}

	if got.Action != "Run tool" {
		t.Errorf("prompt Action = %q, want the human action header %q", got.Action, "Run tool")
	}
	if got.Subject != "Read" {
		t.Errorf("prompt Subject = %q, want the display subject %q", got.Subject, "Read")
	}
	if got.Body != `Read({"path":"/work/proj/main.go"})` {
		t.Errorf("prompt Body = %q, want the full structured-tool call", got.Body)
	}
	if got.Kind != tui.SubjectStructuredTool {
		t.Errorf("prompt Kind = %q, want %q", got.Kind, tui.SubjectStructuredTool)
	}
	if got.CanonicalProgram != "" || got.CanonicalArgs != nil {
		t.Errorf("structured tool carried canonical tokens: program=%q args=%v", got.CanonicalProgram, got.CanonicalArgs)
	}
	if outcome.Choice != permissions.PromptAllowGlobal {
		t.Errorf("outcome Choice = %v, want PromptAllowGlobal", outcome.Choice)
	}
}

func exactCompoundGrant(sc permissions.SimpleCompound) (string, error) {
	stageSubjects := make([]string, len(sc.Stages))
	for i, stage := range sc.Stages {
		ss, err := permissions.CompoundStageScopeSubject(sc, i, permissions.ExactSubject(stage[0], stage[1:]))
		if err != nil {
			return "", err
		}
		stageSubjects[i] = ss
	}
	return permissions.EncodeCompoundSubject(sc.Wrapped, stageSubjects, sc.Operators)
}

func TestGatedPrompt_LiteralHomeCompoundCarriesProofAndStoredSubject(t *testing.T) {
	const command = `sh -c "mv x '~/t' && true"`
	canonical, err := permissions.CanonicalLiteralForm(command)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm: %v", err)
	}
	var stored string
	show := func(req tui.PromptRequest) (tui.PromptDecision, error) {
		if req.Compound == nil {
			return tui.PromptDecision{}, errors.New("literal compound prompt carries no decomposition")
		}
		subject, err := exactCompoundGrant(*req.Compound)
		if err != nil {
			return tui.PromptDecision{}, err
		}
		stored = subject
		return tui.PromptDecision{Option: tui.OptionAllowFolder, StoredSubject: subject}, nil
	}
	req := permissions.MatchRequest{Kind: "literal", Subject: canonical, PathScope: "/work/proj"}
	display := PromptDisplay{Action: "Run command", Subject: command, ProjectRoot: "/work/proj", LaunchDir: "/work/proj"}

	outcome, err := newPromptGateBuilder(show).Build(req, display)(context.Background(), permissions.ScopeEscalation{})
	if err != nil {
		t.Fatalf("prompt closure: %v", err)
	}
	if !strings.HasPrefix(stored, "compound/v2 W ") {
		t.Fatalf("chooser subject = %q, want the state-aware wrapped compound form", stored)
	}
	if outcome.Choice != permissions.PromptAllowFolder || outcome.StoredSubject != stored {
		t.Fatalf("outcome = %+v, want PromptAllowFolder carrying %q", outcome, stored)
	}
}

// TestPromptGate_SerializesConcurrentPrompts fires N prompts concurrently through
// one shared gate and asserts only one is ever on screen at a time, resolving one
// after another.
func TestPromptGate_SerializesConcurrentPrompts(t *testing.T) {
	const n = 6
	var (
		mu        sync.Mutex
		active    int
		maxActive int
	)
	entered := make(chan struct{})
	proceed := make(chan struct{})
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		entered <- struct{}{}
		<-proceed
		mu.Lock()
		active--
		mu.Unlock()
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	b := newPromptGateBuilder(show)
	req := permissions.MatchRequest{Kind: "tool", Subject: "Read", PathScope: "/work"}
	display := PromptDisplay{Action: "Run tool", Subject: "Read", Body: "Read(...)"}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = b.Build(req, display)(context.Background(), permissions.ScopeEscalation{})
		}()
	}

	for i := 0; i < n; i++ {
		<-entered
		mu.Lock()
		got := active
		mu.Unlock()
		if got != 1 {
			t.Fatalf("prompt %d: %d prompts active at once, want exactly 1", i, got)
		}
		proceed <- struct{}{}
	}
	wg.Wait()

	if maxActive != 1 {
		t.Fatalf("peak concurrent prompts = %d, want 1", maxActive)
	}
}

// TestPromptGate_CancelWhileWaiting holds the single slot with one prompt, then
// cancels a second caller that is waiting for the slot: it must return
// context.Canceled without showing a prompt, and the gate must remain usable once
// the first prompt releases the slot.
func TestPromptGate_CancelWhileWaiting(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		calls.Add(1)
		entered <- struct{}{}
		<-release
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	b := newPromptGateBuilder(show)
	req := permissions.MatchRequest{Kind: "tool", Subject: "Read", PathScope: "/work"}
	display := PromptDisplay{Action: "Run tool", Subject: "Read", Body: "Read(...)"}

	// First caller occupies the single slot and parks inside the prompt.
	firstDone := make(chan struct{})
	go func() {
		_, _ = b.Build(req, display)(context.Background(), permissions.ScopeEscalation{})
		close(firstDone)
	}()
	<-entered // the gate slot is now held

	// Second caller waits for the slot; cancelling its ctx must drop the pending
	// prompt without ever showing it.
	ctx, cancel := context.WithCancel(context.Background())
	waiterErr := make(chan error, 1)
	go func() {
		_, err := b.Build(req, display)(ctx, permissions.ScopeEscalation{})
		waiterErr <- err
	}()
	cancel()
	if err := <-waiterErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter returned %v, want context.Canceled", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("show called %d times; a cancelled waiter must not show a prompt", got)
	}

	// Release the first prompt; the freed gate must serve a fresh prompt.
	close(release)
	<-firstDone
	out, err := b.Build(req, display)(context.Background(), permissions.ScopeEscalation{})
	if err != nil {
		t.Fatalf("post-cancel prompt returned error: %v", err)
	}
	if out.Choice != permissions.PromptAllowOnce {
		t.Fatalf("post-cancel outcome Choice = %v, want PromptAllowOnce", out.Choice)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("show called %d times total; want 2 (first + reuse), cancelled waiter excluded", got)
	}
}

func hostPathDisplay(hostRequest string, directHTTP bool) PromptDisplay {
	return PromptDisplay{
		Action:                  "Run tool",
		Subject:                 "web_fetch",
		Body:                    `web_fetch({"url":"https://docs.example.com/a"})`,
		OutOfRootFileWrite:      true,
		OutOfRootReadScope:      true,
		GrantStoredSubject:      permissions.CapabilityWrite,
		Pipeline:                "curl x | grep y",
		WholeCommand:            true,
		ProjectRoot:             "/work/proj",
		LaunchDir:               "/work",
		Boundary:                "launch-dir-only",
		FolderSettingsPath:      "/work/proj/.codemeld/settings.yaml",
		FolderCoverage:          "/work/proj and its descendants",
		WouldCreateSettingsFile: true,
		HostRequest:             hostRequest,
		DirectHTTPFallback:      directHTTP,
	}
}

func TestBuildPromptRequest_HostForm(t *testing.T) {
	cases := []struct {
		name string
		req  permissions.MatchRequest
		disp PromptDisplay
		esc  permissions.ScopeEscalation
		want tui.PromptRequest
	}{
		{
			name: "search request carries the tool, literal query, and canonical host",
			req:  permissions.MatchRequest{Kind: "host", Subject: "web_search", Host: "duckduckgo.com"},
			disp: hostPathDisplay("golang generics tutorial", false),
			want: tui.PromptRequest{
				Kind:        tui.SubjectHost,
				HostTool:    "web_search",
				HostRequest: "golang generics tutorial",
				Host:        "duckduckgo.com",
			},
		},
		{
			name: "direct https fetch carries the URL and no fallback disclosure",
			req:  permissions.MatchRequest{Kind: "host", Subject: "web_fetch", Host: "docs.example.com"},
			disp: hostPathDisplay("https://docs.example.com/a", false),
			want: tui.PromptRequest{
				Kind:        tui.SubjectHost,
				HostTool:    "web_fetch",
				HostRequest: "https://docs.example.com/a",
				Host:        "docs.example.com",
			},
		},
		{
			name: "direct http fetch carries the HTTPS-first fallback marker",
			req:  permissions.MatchRequest{Kind: "host", Subject: "web_fetch", Host: "docs.example.com"},
			disp: hostPathDisplay("http://docs.example.com/a", true),
			want: tui.PromptRequest{
				Kind:               tui.SubjectHost,
				HostTool:           "web_fetch",
				HostRequest:        "http://docs.example.com/a",
				Host:               "docs.example.com",
				DirectHTTPFallback: true,
			},
		},
		{
			name: "fresh confirmation marker survives to the prompt",
			req:  permissions.MatchRequest{Kind: "host", Subject: "web_fetch", Host: "docs.example.com", FreshConfirmation: true},
			disp: hostPathDisplay("https://docs.example.com:8443/a", false),
			want: tui.PromptRequest{
				Kind:              tui.SubjectHost,
				HostTool:          "web_fetch",
				HostRequest:       "https://docs.example.com:8443/a",
				Host:              "docs.example.com",
				FreshConfirmation: true,
			},
		},
		{
			name: "scope escalation is not carried onto a host prompt",
			req:  permissions.MatchRequest{Kind: "host", Subject: "web_fetch", Host: "docs.example.com"},
			disp: hostPathDisplay("https://docs.example.com/a", false),
			esc:  permissions.ScopeEscalation{NarrowerScope: "/work/proj/sub"},
			want: tui.PromptRequest{
				Kind:        tui.SubjectHost,
				HostTool:    "web_fetch",
				HostRequest: "https://docs.example.com/a",
				Host:        "docs.example.com",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildPromptRequest(tc.req, tc.disp, tc.esc)
			if err != nil {
				t.Fatalf("buildPromptRequest returned error: %v", err)
			}
			if got.Summary.Effect != "contacts a host" {
				t.Fatalf("host prompt summary effect = %q, want the network effect", got.Summary.Effect)
			}
			got.Summary = permissions.PromptSummaryResult{}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("host prompt request mismatch\n got: %#v\nwant: %#v", got, tc.want)
			}
		})
	}
}

func TestBuildPromptRequest_CarriesProjectUntrustedToBothPromptKinds(t *testing.T) {
	for _, untrusted := range []bool{false, true} {
		host := hostPathDisplay("https://docs.example.com/a", false)
		host.ProjectUntrusted = untrusted
		got, err := buildPromptRequest(permissions.MatchRequest{Kind: "host", Subject: "web_fetch", Host: "docs.example.com"}, host, permissions.ScopeEscalation{})
		if err != nil {
			t.Fatalf("buildPromptRequest (host): %v", err)
		}
		if got.ProjectUntrusted != untrusted {
			t.Errorf("host prompt ProjectUntrusted = %v, want %v", got.ProjectUntrusted, untrusted)
		}

		folder := PromptDisplay{Action: "Run command", Subject: "rm x", ProjectRoot: "/work/proj", ProjectUntrusted: untrusted}
		got, err = buildPromptRequest(permissions.MatchRequest{Kind: "direct", Subject: "rm x", PathScope: "/work/proj", SubjectTokens: []string{"rm", "x"}}, folder, permissions.ScopeEscalation{})
		if err != nil {
			t.Fatalf("buildPromptRequest (direct): %v", err)
		}
		if got.ProjectUntrusted != untrusted {
			t.Errorf("folder prompt ProjectUntrusted = %v, want %v", got.ProjectUntrusted, untrusted)
		}
	}
}

func TestBuildPromptRequest_HostCarrierEmptyOnPathPrompts(t *testing.T) {
	req := permissions.MatchRequest{Kind: "tool", Subject: "read_file", PathScope: "/work/proj"}
	disp := PromptDisplay{Action: "Run tool", Subject: "read_file", HostRequest: "https://example.com", DirectHTTPFallback: true}
	got, err := buildPromptRequest(req, disp, permissions.ScopeEscalation{})
	if err != nil {
		t.Fatalf("buildPromptRequest returned error: %v", err)
	}
	if got.Kind != tui.SubjectStructuredTool {
		t.Fatalf("Kind = %q, want the structured-tool form", got.Kind)
	}
	if got.HostTool != "" || got.HostRequest != "" || got.Host != "" || got.FreshConfirmation || got.DirectHTTPFallback {
		t.Fatalf("path prompt picked up host display data: %#v", got)
	}
}

func TestMapOutcome_HostProjectOption(t *testing.T) {
	got, err := mapOutcome(tui.PromptDecision{Option: tui.OptionAllowProject})
	if err != nil {
		t.Fatalf("mapOutcome returned error: %v", err)
	}
	want := permissions.PromptOutcome{Choice: permissions.PromptAllowProject}
	if got != want {
		t.Fatalf("mapOutcome = %#v, want %#v", got, want)
	}

	got, err = mapOutcome(tui.PromptDecision{Option: tui.OptionAllowProject, StoredSubject: "web_fetch :*"})
	if err != nil {
		t.Fatalf("mapOutcome returned error: %v", err)
	}
	if got != want {
		t.Fatalf("project outcome = %#v, want no stored subject: %#v", got, want)
	}
}

func TestPromptGate_SerializesHostWithPathPrompts(t *testing.T) {
	var (
		mu        sync.Mutex
		active    int
		maxActive int
	)
	entered := make(chan struct{})
	proceed := make(chan struct{})
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		entered <- struct{}{}
		<-proceed
		mu.Lock()
		active--
		mu.Unlock()
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	}
	b := newPromptGateBuilder(show)

	prompts := []func() (permissions.PromptOutcome, error){
		func() (permissions.PromptOutcome, error) {
			req := permissions.MatchRequest{Kind: "host", Subject: "web_fetch", Host: "docs.example.com"}
			return b.Build(req, PromptDisplay{HostRequest: "https://docs.example.com/a"})(context.Background(), permissions.ScopeEscalation{})
		},
		func() (permissions.PromptOutcome, error) {
			req := permissions.MatchRequest{Kind: "host", Subject: "web_search", Host: "duckduckgo.com", FreshConfirmation: true}
			return b.Build(req, PromptDisplay{HostRequest: "generics"})(context.Background(), permissions.ScopeEscalation{})
		},
		func() (permissions.PromptOutcome, error) {
			req := permissions.MatchRequest{Kind: "tool", Subject: "read_file", PathScope: "/work"}
			return b.Build(req, PromptDisplay{Action: "Run tool", Subject: "read_file"})(context.Background(), permissions.ScopeEscalation{})
		},
	}

	var wg sync.WaitGroup
	for _, p := range prompts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p()
		}()
	}
	for i := range prompts {
		<-entered
		mu.Lock()
		got := active
		mu.Unlock()
		if got != 1 {
			t.Fatalf("prompt %d: %d prompts active at once, want exactly 1", i, got)
		}
		proceed <- struct{}{}
	}
	wg.Wait()

	if maxActive != 1 {
		t.Fatalf("peak concurrent prompts = %d, want 1", maxActive)
	}
}

// The summary is an addition to the prompt payload, so it must not restate the matching
// discriminator or the registered matching subject the prompt deliberately keeps off screen, and
// it must leave the request it was computed from untouched.
func TestBuildPromptRequest_SummaryIsPresentationOnly(t *testing.T) {
	cases := []struct {
		name string
		req  permissions.MatchRequest
		disp PromptDisplay
	}{
		{"direct", permissions.MatchRequest{Kind: "direct", Subject: "git status", SubjectTokens: []string{"git", "status"}, PathScope: "/work"},
			PromptDisplay{Action: "Run command", Subject: "git status"}},
		{"literal", permissions.MatchRequest{Kind: "literal", Subject: "tee out.txt", PathScope: "/work"},
			PromptDisplay{Action: "Run command", Subject: "tee out.txt", WholeCommand: true}},
		{"tool", permissions.MatchRequest{Kind: "tool", Subject: "read", PathScope: "/outside"},
			PromptDisplay{Action: "Run tool", Subject: "read", RequestedTarget: "/outside/a.txt", Body: `read({"path":"/outside/a.txt"})`}},
		{"host", permissions.MatchRequest{Kind: "host", Subject: "web_fetch", Host: "docs.example.test"},
			PromptDisplay{HostRequest: "https://docs.example.test/a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.req
			got, err := buildPromptRequest(tc.req, tc.disp, permissions.ScopeEscalation{})
			if err != nil {
				t.Fatalf("buildPromptRequest: %v", err)
			}
			if !reflect.DeepEqual(tc.req, before) {
				t.Fatalf("summary mutated the matching request: %#v", tc.req)
			}
			rows := strings.Join(got.Summary.DisplayRows(), "\n")
			for _, banned := range []string{"direct-command", "literal-command", "structured-tool", "Kind: " + tc.req.Kind} {
				if strings.Contains(rows, banned) {
					t.Fatalf("summary rows leak the matching discriminator %q:\n%s", banned, rows)
				}
			}
			if got.Summary.Sentence == "" {
				t.Fatal("prompt renders with no plain-language explanation")
			}
		})
	}
}

// A grant-creating choice keeps mapping to the same stored subject and outcome with the summary
// in place, so nothing on the summary path can authorize a different call.
func TestBuildPromptRequest_SummaryDoesNotChangeOutcomeMapping(t *testing.T) {
	req := permissions.MatchRequest{Kind: "tool", Subject: "create", PathScope: "/work"}
	pr, err := buildPromptRequest(req, PromptDisplay{
		Action:             "Create file",
		Subject:            "a.md",
		RequestedTarget:    "a.md",
		Body:               "x\n",
		GrantStoredSubject: permissions.CapabilityWrite,
	}, permissions.ScopeEscalation{})
	if err != nil {
		t.Fatalf("buildPromptRequest: %v", err)
	}
	if pr.CapabilityStoredSubject != permissions.CapabilityWrite {
		t.Fatalf("capability stored subject = %q, want the dispatch value", pr.CapabilityStoredSubject)
	}
	out, err := mapOutcome(tui.PromptDecision{Option: tui.OptionAllowSession, StoredSubject: pr.CapabilityStoredSubject})
	if err != nil {
		t.Fatalf("mapOutcome: %v", err)
	}
	if out.Choice != permissions.PromptAllowSession || out.StoredSubject != permissions.CapabilityWrite {
		t.Fatalf("outcome = %#v, want an unchanged session grant on the capability subject", out)
	}
}

func TestMapOutcomeFor_BindsTheStoredSubjectToItsOwnCall(t *testing.T) {
	external := PromptDisplay{GrantStoredSubject: permissions.CapabilityRead}
	inProject := PromptDisplay{}

	cases := []struct {
		name    string
		in      tui.PromptDecision
		display PromptDisplay
		want    permissions.PromptOutcome
	}{
		{
			name:    "grant folds only the capability of the call it applies to",
			in:      tui.PromptDecision{Option: tui.OptionAllowSession},
			display: external,
			want:    permissions.PromptOutcome{Choice: permissions.PromptAllowSession, StoredSubject: permissions.CapabilityRead},
		},
		{
			name:    "a sibling without a capability stores its concrete subject",
			in:      tui.PromptDecision{Option: tui.OptionAllowSession},
			display: inProject,
			want:    permissions.PromptOutcome{Choice: permissions.PromptAllowSession},
		},
		{
			name:    "a group decision cannot leak one call's capability onto another",
			in:      tui.PromptDecision{Option: tui.OptionAllowFolder, StoredSubject: permissions.CapabilityRead},
			display: inProject,
			want:    permissions.PromptOutcome{Choice: permissions.PromptAllowFolder},
		},
		{
			name:    "allow once creates no grant and stores nothing",
			in:      tui.PromptDecision{Option: tui.OptionAllowOnce},
			display: external,
			want:    permissions.PromptOutcome{Choice: permissions.PromptAllowOnce},
		},
		{
			name:    "deny keeps its own envelope",
			in:      tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: "denied: no"},
			display: external,
			want:    permissions.PromptOutcome{Choice: permissions.PromptDeny, DenyEnvelope: "denied: no"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mapOutcomeFor(tc.in, tc.display)
			if err != nil {
				t.Fatalf("mapOutcomeFor error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("outcome = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestMapOutcomeFor_UnknownOption(t *testing.T) {
	if _, err := mapOutcomeFor(tui.PromptDecision{Option: tui.PromptOption(99)}, PromptDisplay{}); err == nil {
		t.Fatal("mapOutcomeFor accepted an unknown prompt option, want error")
	}
}

func constrainedAutoStage(source string) (permissions.BatchPromptRequest, PromptDisplay, permissions.ModeContext) {
	tokens := strings.Fields(source)
	req := permissions.MatchRequest{Kind: matchKindDirect, Subject: source, SubjectTokens: tokens, PathScope: "/work"}
	mc := permissions.ModeContext{
		Mode:                 "auto_edits",
		ExecutionConstrained: true,
		Stages:               []permissions.StageNormalization{{Tokens: tokens, Source: source}},
	}
	disp := markExceptional(dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: source, Pipeline: "p"}, req, mc)
	return permissions.BatchPromptRequest{Req: req}, PromptDisplay{
		Action: disp.Action, Subject: disp.Subject, Pipeline: disp.Pipeline, ExceptionalAuthority: disp.ExceptionalAuthority,
	}, mc
}

func constrainedAutoBatch(sources ...string) ([]permissions.BatchPromptRequest, []PromptDisplay, []permissions.ModeContext) {
	prompts := make([]permissions.BatchPromptRequest, len(sources))
	displays := make([]PromptDisplay, len(sources))
	modeCtxs := make([]permissions.ModeContext, len(sources))
	for i, source := range sources {
		prompts[i], displays[i], modeCtxs[i] = constrainedAutoStage(source)
		prompts[i].Index = i
	}
	return prompts, displays, modeCtxs
}

func TestBuildBatchPromptRequest_ExceptionalBatchNamesThePrecedenceAuthority(t *testing.T) {
	for _, tc := range []struct {
		name      string
		stages    []string
		authority string
	}{
		{"network after deletion", []string{"rm -f out.txt", "curl https://example.com"}, "network access"},
		{"network before deletion", []string{"curl https://example.com", "rm -f out.txt"}, "network access"},
		{"exceptional stage not first", []string{"sort data.txt", "curl https://example.com", "rm -f out.txt"}, "network access"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prompts, displays, modeCtxs := brokenSettingsAutoBatch(tc.stages...)
			pr, err := buildBatchPromptRequest(prompts, displays, modeCtxs)
			if err != nil {
				t.Fatalf("buildBatchPromptRequest: %v", err)
			}
			if pr.Action != "Allow "+tc.authority || pr.ExceptionalAuthority != tc.authority {
				t.Fatalf("Action = %q, marker = %q; want the %q authority", pr.Action, pr.ExceptionalAuthority, tc.authority)
			}
			if !reflect.DeepEqual(pr.BatchedStages, tc.stages) || pr.Subject != "" || pr.Body != "" || pr.Pipeline != "p" {
				t.Fatalf("batch = %+v, want every stage verbatim in order with the pipeline", pr)
			}
		})
	}

	prompts, displays, modeCtxs := brokenSettingsAutoBatch("curl https://example.com")
	pr, err := buildBatchPromptRequest(prompts, displays, modeCtxs)
	if err != nil {
		t.Fatalf("buildBatchPromptRequest: %v", err)
	}
	if pr.Action != "Allow network access" || pr.ExceptionalAuthority != "network access" || pr.Subject != "curl https://example.com" || pr.BatchedStages != nil {
		t.Fatalf("one-stage batch = %+v, want the single-request shape naming network access", pr)
	}

	for _, stages := range [][]string{{"sort data.txt", "tee out.txt"}, {"sort data.txt", "hg strip tip"}, {"rm -f out.txt", "curl https://example.com"}} {
		prompts, displays, modeCtxs = constrainedAutoBatch(stages...)
		pr, err = buildBatchPromptRequest(prompts, displays, modeCtxs)
		if err != nil {
			t.Fatalf("buildBatchPromptRequest: %v", err)
		}
		if pr.Action != dispatch.ActionRunCommand || pr.ExceptionalAuthority != "" {
			t.Fatalf("ordinary batch %q = %+v, want today's action and no marker", stages, pr)
		}
	}
}

func TestExceptionalAuthority_OnlyConstrainedAutoEditsShell(t *testing.T) {
	stage := []permissions.StageNormalization{{Tokens: []string{"curl", "https://example.com"}}}
	direct := permissions.MatchRequest{Kind: matchKindDirect, Subject: "curl https://example.com"}
	literal := permissions.MatchRequest{Kind: matchKindLiteral, Subject: "sh -c 'curl https://example.com'"}
	for _, tc := range []struct {
		name string
		req  permissions.MatchRequest
		mc   permissions.ModeContext
		want string
	}{
		{"broken settings auto direct", direct, permissions.ModeContext{Mode: "auto_edits", ExecutionConstrained: true, SettingsBroken: true, Stages: stage}, "network access"},
		{"broken settings auto literal", literal, permissions.ModeContext{Mode: "auto_edits", ExecutionConstrained: true, SettingsBroken: true}, "network access"},
		{"valid settings auto direct", direct, permissions.ModeContext{Mode: "auto_edits", ExecutionConstrained: true, Stages: stage}, ""},
		{"valid settings auto literal", literal, permissions.ModeContext{Mode: "auto_edits", ExecutionConstrained: true}, ""},
		{"unconstrained auto", direct, permissions.ModeContext{Mode: "auto_edits", Stages: stage}, ""},
		{"build", direct, permissions.ModeContext{Mode: "build", ExecutionConstrained: true, Stages: stage}, ""},
		{"plan", direct, permissions.ModeContext{Mode: "plan", ExecutionConstrained: true, Stages: stage}, ""},
		{"unset mode", direct, permissions.ModeContext{ExecutionConstrained: true, Stages: stage}, ""},
		{"host", hostRequest("web_fetch", "example.com"), permissions.ModeContext{Mode: "auto_edits", ExecutionConstrained: true}, ""},
		{"tool", permissions.MatchRequest{Kind: matchKindTool, Subject: "create"}, permissions.ModeContext{Mode: "auto_edits", ExecutionConstrained: true}, ""},
		{"unclassifiable literal", permissions.MatchRequest{Kind: matchKindLiteral, Subject: "for f in *; do rm $f; done"}, permissions.ModeContext{Mode: "auto_edits", ExecutionConstrained: true}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disp := dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: tc.req.Subject}
			got := markExceptional(disp, tc.req, tc.mc)
			if got.ExceptionalAuthority != tc.want {
				t.Fatalf("marker = %q, want %q", got.ExceptionalAuthority, tc.want)
			}
			if tc.want == "" && got != disp {
				t.Fatalf("display = %+v, want it unchanged", got)
			}
			if tc.want != "" && (got.Action != "Allow "+tc.want || got.Subject != tc.req.Subject || got.Body != "") {
				t.Fatalf("display = %+v, want the authority header over the whole command", got)
			}
		})
	}
}

func TestPromptGate_ExceptionalPromptRejectsGrantChoices(t *testing.T) {
	_, displays, _ := brokenSettingsAutoBatch("curl https://example.com")
	display := displays[0]
	req := permissions.MatchRequest{Kind: matchKindDirect, Subject: "curl https://example.com", SubjectTokens: []string{"curl", "https://example.com"}}
	for _, option := range []tui.PromptOption{tui.OptionAllowSession, tui.OptionAllowFolder, tui.OptionAllowGlobal, tui.OptionAllowProject} {
		show := func(tui.PromptRequest) (tui.PromptDecision, error) {
			return tui.PromptDecision{Option: option, StoredSubject: "curl :*"}, nil
		}
		if out, err := newPromptGateBuilder(show).Build(req, display)(context.Background(), permissions.ScopeEscalation{}); err == nil {
			t.Fatalf("option %d mapped to %+v, want an error", option, out)
		}
		auth := &productionAuthorizer{prompts: newPromptGateBuilder(show)}
		prompts, displays, modeCtxs := brokenSettingsAutoBatch("rm -f out.txt", "curl https://example.com")
		if out, err := auth.buildBatchPrompt(displays, modeCtxs)(context.Background(), prompts); err == nil {
			t.Fatalf("batch option %d mapped to %+v, want an error", option, out)
		}
	}
	for _, option := range []tui.PromptOption{tui.OptionAllowOnce, tui.OptionDeny} {
		show := func(tui.PromptRequest) (tui.PromptDecision, error) { return tui.PromptDecision{Option: option}, nil }
		out, err := newPromptGateBuilder(show).Build(req, display)(context.Background(), permissions.ScopeEscalation{})
		if err != nil || out.StoredSubject != "" {
			t.Fatalf("option %d = %+v, %v; want a bare outcome", option, out, err)
		}
	}
	unmarked := display
	unmarked.ExceptionalAuthority = ""
	show := func(tui.PromptRequest) (tui.PromptDecision, error) {
		return tui.PromptDecision{Option: tui.OptionAllowSession, StoredSubject: "curl :*"}, nil
	}
	if out, err := newPromptGateBuilder(show).Build(req, unmarked)(context.Background(), permissions.ScopeEscalation{}); err != nil || out.Choice != permissions.PromptAllowSession {
		t.Fatalf("unmarked session = %+v, %v; want the grant choice kept", out, err)
	}
}

func sandboxedAutoShell(t *testing.T, input string, broken bool) (permissions.MatchRequest, permissions.ModeContext) {
	t.Helper()
	split, err := permissions.SplitCommand(input)
	if err != nil {
		t.Fatalf("SplitCommand(%q): %v", input, err)
	}
	mc := permissions.ModeContext{
		Mode: "auto_edits", ExecutionConstrained: true, SettingsBroken: broken,
		Stages: split.Stages, LiteralRoute: split.LiteralRoute,
	}
	if split.LiteralRoute {
		canonical, err := permissions.CanonicalLiteralForm(split.LiteralInput)
		if err != nil {
			t.Fatalf("CanonicalLiteralForm(%q): %v", split.LiteralInput, err)
		}
		return permissions.MatchRequest{Kind: matchKindLiteral, Subject: canonical}, mc
	}
	tokens := split.Stages[0].Tokens
	return permissions.MatchRequest{Kind: matchKindDirect, Subject: strings.Join(tokens, " "), SubjectTokens: tokens}, mc
}

func TestExceptionalAuthority_SandboxedAutoEditsNamesWhatStillAsks(t *testing.T) {
	const deletion, network, history = "file deletion", "network access", "VCS history rewrite"
	for _, tc := range []struct{ command, broken string }{
		{`rm -rf build`, deletion},
		{`git clean -fdx`, deletion},
		{`which -a x; file "$(which x)"`, ""},
		{`git rebase main`, history},
		{`rm x && git rebase main`, deletion},
		{`git rebase main; rm x`, deletion},
		{`rm x | hg strip .`, deletion},
		{`rm x; curl y`, network},
		{`git reset --hard && git push`, network},
		{`rm x && command git push`, network},
		{`rm x && nice git push`, network},
		{`rm x | xargs git push`, network},
		{`rm x; bash -c 'git push'`, network},
		{`rm x && git commit --amend`, deletion},
	} {
		for _, broken := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/broken=%v", tc.command, broken), func(t *testing.T) {
				req, mc := sandboxedAutoShell(t, tc.command, broken)
				want := ""
				if broken {
					want = tc.broken
				}
				got := markExceptional(dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: tc.command}, req, mc)
				if got.ExceptionalAuthority != want || want != "" && got.Action != "Allow "+want {
					t.Fatalf("display = %+v, want authority %q", got, want)
				}
			})
		}
	}
}

func brokenSettingsAutoBatch(sources ...string) ([]permissions.BatchPromptRequest, []PromptDisplay, []permissions.ModeContext) {
	prompts, displays, modeCtxs := constrainedAutoBatch(sources...)
	for i := range modeCtxs {
		modeCtxs[i].SettingsBroken = true
		disp := markExceptional(dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: sources[i], Pipeline: "p"}, prompts[i].Req, modeCtxs[i])
		displays[i].Action, displays[i].ExceptionalAuthority = disp.Action, disp.ExceptionalAuthority
	}
	return prompts, displays, modeCtxs
}

func TestPromptGate_BrokenSettingsDeletionKeepsAllowOnceOrDeny(t *testing.T) {
	grantOptions := []tui.PromptOption{tui.OptionAllowSession, tui.OptionAllowFolder, tui.OptionAllowGlobal, tui.OptionAllowProject}
	choose := func(option tui.PromptOption, shown *[]tui.PromptRequest) promptShower {
		return func(pr tui.PromptRequest) (tui.PromptDecision, error) {
			*shown = append(*shown, pr)
			return tui.PromptDecision{Option: option, StoredSubject: "rm :*"}, nil
		}
	}
	for _, sources := range [][]string{{"rm -f out.txt"}, {"sort data.txt", "rm -f out.txt"}} {
		name := strings.Join(sources, " | ")
		t.Run("single "+name, func(t *testing.T) {
			prompts, displays, _ := brokenSettingsAutoBatch(sources...)
			last := len(sources) - 1
			if displays[last].ExceptionalAuthority != "file deletion" || displays[last].Action != "Allow file deletion" {
				t.Fatalf("broken-settings display = %+v, want the file deletion marker", displays[last])
			}
			for _, option := range grantOptions {
				var shown []tui.PromptRequest
				if out, err := newPromptGateBuilder(choose(option, &shown)).Build(prompts[last].Req, displays[last])(context.Background(), permissions.ScopeEscalation{}); err == nil {
					t.Fatalf("option %d mapped to %+v, want an error", option, out)
				}
			}
			_, valid, _ := constrainedAutoBatch(sources...)
			var shown []tui.PromptRequest
			out, err := newPromptGateBuilder(choose(tui.OptionAllowSession, &shown)).Build(prompts[last].Req, valid[last])(context.Background(), permissions.ScopeEscalation{})
			if err != nil || out.Choice != permissions.PromptAllowSession || valid[last].ExceptionalAuthority != "" {
				t.Fatalf("valid-settings session = %+v, %v (marker %q); want no deletion marker", out, err, valid[last].ExceptionalAuthority)
			}
		})
		t.Run("batched "+name, func(t *testing.T) {
			prompts, displays, modeCtxs := brokenSettingsAutoBatch(sources...)
			for _, option := range grantOptions {
				var shown []tui.PromptRequest
				auth := &productionAuthorizer{prompts: newPromptGateBuilder(choose(option, &shown))}
				if out, err := auth.buildBatchPrompt(displays, modeCtxs)(context.Background(), prompts); err == nil {
					t.Fatalf("batch option %d mapped to %+v, want an error", option, out)
				}
				if len(shown) != 1 || shown[0].ExceptionalAuthority != "file deletion" {
					t.Fatalf("shown = %+v, want one prompt marked file deletion", shown)
				}
			}
			for _, option := range []tui.PromptOption{tui.OptionAllowOnce, tui.OptionDeny} {
				var shown []tui.PromptRequest
				auth := &productionAuthorizer{prompts: newPromptGateBuilder(choose(option, &shown))}
				if _, err := auth.buildBatchPrompt(displays, modeCtxs)(context.Background(), prompts); err != nil {
					t.Fatalf("batch option %d: %v", option, err)
				}
			}
		})
	}
}

type recordingShellRunner struct {
	mu    sync.Mutex
	specs []cmdrunner.RunSpec
}

func (r *recordingShellRunner) NewInvocationID() string { return ids.NewV7() }

func (r *recordingShellRunner) Exec(_ context.Context, spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.specs = append(r.specs, spec)
	return cmdrunner.RunResult{}, nil
}

func (r *recordingShellRunner) PreflightPipeline(context.Context, []cmdrunner.RunSpec) error {
	return nil
}

func (r *recordingShellRunner) Pipeline(_ context.Context, specs []cmdrunner.RunSpec) ([]cmdrunner.PipelineResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.specs = append(r.specs, specs...)
	results := make([]cmdrunner.PipelineResult, len(specs))
	for i, spec := range specs {
		results[i].InvocationID = spec.InvocationID
	}
	return results, nil
}

type requestRecordingAuthorizer struct {
	*productionAuthorizer
	mu   sync.Mutex
	reqs []permissions.MatchRequest
}

func (a *requestRecordingAuthorizer) Authorize(ctx context.Context, req permissions.MatchRequest, disp dispatch.PromptDisplay, mc permissions.ModeContext) (permissions.Decision, error) {
	a.mu.Lock()
	a.reqs = append(a.reqs, req)
	a.mu.Unlock()
	return a.productionAuthorizer.Authorize(ctx, req, disp, mc)
}

func (a *requestRecordingAuthorizer) AuthorizeBatch(ctx context.Context, reqs []dispatch.BatchAuthRequest) ([]permissions.Decision, error) {
	a.mu.Lock()
	for _, r := range reqs {
		a.reqs = append(a.reqs, r.Req)
	}
	a.mu.Unlock()
	return a.productionAuthorizer.AuthorizeBatch(ctx, reqs)
}

func TestDispatchShell_SandboxedAutoEditsRunsEveryCommandOnTheProxyRoute(t *testing.T) {
	const network = "network access"
	for _, tc := range []struct {
		command        string
		stages         int
		networkProgram string
	}{
		{`rm -rf build`, 1, ""},
		{`which -a ls; file "$(which ls)"`, 1, ""},
		{`git rebase main`, 1, ""},
		{`sh -c 'git rebase main'`, 1, ""},
		{`rm x && git rebase main`, 2, ""},
		{`rm x | hg strip .`, 2, ""},
		{`rm x; curl https://example.com`, 2, "curl"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			f := newS1Fixture(t, jevName)
			prependFixturePrograms(t, "git", "hg", "curl")
			auth, _, _ := f.production(t, mode.AutoEdits, mkStore(t))
			auth.executionConstrained = true
			var shown []tui.PromptRequest
			auth.prompts = newPromptGateBuilder(func(pr tui.PromptRequest) (tui.PromptDecision, error) {
				shown = append(shown, pr)
				return tui.PromptDecision{Option: tui.OptionDeny}, nil
			})
			rec := &requestRecordingAuthorizer{productionAuthorizer: auth}
			run := &recordingShellRunner{}

			if _, err := dispatch.DispatchShell(context.Background(), tc.command, f.home, f.project, rec, run); err != nil {
				t.Fatalf("DispatchShell = %v", err)
			}
			if len(shown) != 0 {
				t.Fatalf("prompts = %+v, want none", shown)
			}
			if len(run.specs) != tc.stages {
				t.Fatalf("executed %d specs %+v, want %d", len(run.specs), run.specs, tc.stages)
			}
			conf := &confinement{constrained: true, mode: fixedMode(string(mode.AutoEdits)), tmpDir: t.TempDir(), projectRoot: f.project, blocked: testBlocked(t), broker: "slice"}
			for _, spec := range run.specs {
				wantNetwork := tc.networkProgram != "" && filepath.Base(spec.Argv[0]) == tc.networkProgram
				if (spec.ExceptionalAuthority == network) != wantNetwork {
					t.Fatalf("spec %q authority = %q, want network authority only on %q", spec.Argv, spec.ExceptionalAuthority, tc.networkProgram)
				}
				policy, err := conf.policy(string(mode.AutoEdits), conf.tmpDir, conf.blocked.Current(), false)
				if err != nil {
					t.Fatalf("policy: %v", err)
				}
				if policy.ExceptionalAuthority != "" || policy.Broker != "slice" {
					t.Fatalf("spec %q confinement authority = %q broker = %q, want the slice broker and no authority", spec.Argv, policy.ExceptionalAuthority, policy.Broker)
				}
			}
			if got := f.server.requests(); len(got) != 0 {
				t.Fatalf("System One requests = %+v, want none", got)
			}
			if grants := auth.grants.Permissions(); len(grants) != 0 {
				t.Fatalf("stored grants %+v, want none", grants)
			}
			for _, req := range rec.reqs {
				if outcome, hit := auth.grants.turn.Lookup(req); hit {
					t.Fatalf("automatic allowance cached %q for %+v", outcome, req)
				}
			}
		})
	}
}

type proxyCall struct {
	conn    net.Conn
	refused chan string
}

func startTestProxy(t *testing.T) (*netproxy.Server, string) {
	t.Helper()
	server, err := netproxy.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := server.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)
	return server, endpoint
}

func sendProxyRequest(t *testing.T, endpoint string, owner *netproxy.Owner, host string) *proxyCall {
	t.Helper()
	c, err := net.Dial("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := owner.Register(c.LocalAddr().(*net.TCPAddr).AddrPort()); err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.WriteString(c, "GET http://"+host+":9/ HTTP/1.1\r\nHost: "+host+":9\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	refused := make(chan string, 1)
	go func() {
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			refused <- "no response: " + err.Error()
			return
		}
		_ = resp.Body.Close()
		refused <- resp.Header.Get("X-Proxy-Refused")
	}()
	return &proxyCall{conn: c, refused: refused}
}

func (p *proxyCall) await(t *testing.T) string {
	t.Helper()
	select {
	case got := <-p.refused:
		return got
	case <-time.After(10 * time.Second):
		t.Fatal("the proxy request got no response within 10s")
		return ""
	}
}

func waitRefusal(t *testing.T, server *netproxy.Server, host string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range server.Refusals() {
			if r.Host == host {
				return r.Reason
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no refusal for %s within 10s: %+v", host, server.Refusals())
	return ""
}

func waitSlotFree(t *testing.T, b *PromptGateBuilder) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for len(b.gate.slot) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the prompt slot was not released within 10s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func startLiveTUI(t *testing.T) (*tui.App, tcell.SimulationScreen) {
	t.Helper()
	app := tui.New(nil)
	screen := tcell.NewSimulationScreen("UTF-8")
	app.SetScreenFactoryForTest(func() (tcell.Screen, error) { return screen, nil })
	errc := make(chan error, 1)
	go func() { errc <- app.Run() }()
	t.Cleanup(func() {
		app.Stop()
		<-errc
	})
	onEventLoop(t, app, func() {})
	return app, screen
}

func waitScreen(t *testing.T, app *tui.App, screen tcell.SimulationScreen, want string, shown bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var text string
		onEventLoop(t, app, func() { text = simScreenText(screen) })
		if strings.Contains(text, want) == shown {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("screen shown=%v for %q not reached within 5s:\n%s", shown, want, text)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func blockTUILoop(app *tui.App) (release func()) {
	entered, done := make(chan struct{}), make(chan struct{})
	go app.RunOnEventLoopForTest(func() {
		close(entered)
		<-done
	})
	<-entered
	return func() { close(done) }
}

func TestPromptGateNetworkAsker_AllowOnceAdmitsOneRequestAndAsksAgain(t *testing.T) {
	answers := []tui.PromptOption{tui.OptionAllowOnce, tui.OptionAllowOnce, tui.OptionDeny, tui.PromptOption(99)}
	var asked atomic.Int32
	b := newPromptGateBuilder(nil)
	b.showNetwork = func(_ context.Context, host, port string, _ bool) (tui.PromptOption, error) {
		if host != "127.0.0.1" || port != "9" {
			t.Errorf("asked for %s:%s, want 127.0.0.1:9", host, port)
		}
		return answers[asked.Add(1)-1], nil
	}
	server, endpoint := startTestProxy(t)
	for i, want := range []string{"not public", "not public", "not approved (denied)", "not approved (prompt failed)"} {
		owner := server.NewOwner(b.AskNetwork)
		t.Cleanup(owner.Close)
		if got := sendProxyRequest(t, endpoint, owner, "127.0.0.1").await(t); got != want {
			t.Fatalf("request %d refused %q, want %q", i+1, got, want)
		}
		if got := asked.Load(); got != int32(i+1) {
			t.Fatalf("after request %d the asker showed %d prompts, want one per request", i+1, got)
		}
	}
}

func TestPromptGateNetworkAsker_WaitsWhileAPermissionPromptHoldsTheSlot(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	b := newPromptGateBuilder(func(tui.PromptRequest) (tui.PromptDecision, error) {
		close(entered)
		<-release
		return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
	})
	var asked atomic.Int32
	b.showNetwork = func(context.Context, string, string, bool) (tui.PromptOption, error) {
		asked.Add(1)
		return tui.OptionAllowOnce, nil
	}
	permissionDone := make(chan struct{})
	go func() {
		defer close(permissionDone)
		req := permissions.MatchRequest{Kind: "tool", Subject: "Read", PathScope: "/work"}
		_, _ = b.Build(req, PromptDisplay{Action: "Run tool", Subject: "Read"})(context.Background(), permissions.ScopeEscalation{})
	}()
	<-entered

	server, endpoint := startTestProxy(t)
	owner := server.NewOwner(b.AskNetwork)
	t.Cleanup(owner.Close)
	call := sendProxyRequest(t, endpoint, owner, "127.0.0.1")
	select {
	case got := <-call.refused:
		t.Fatalf("the network request finished (%q) while a permission prompt held the slot", got)
	case <-time.After(100 * time.Millisecond):
	}
	if got := asked.Load(); got != 0 {
		t.Fatalf("a network prompt was shown %d times while a permission prompt held the slot", got)
	}
	close(release)
	<-permissionDone
	if got := call.await(t); got != "not public" || asked.Load() != 1 {
		t.Fatalf("after the permission prompt: refused %q, asked %d; want the request asked once and admitted", got, asked.Load())
	}
}

func TestPromptGateNetworkAsker_SessionAnswerIsAcceptedBeforeTheSlotIsReleased(t *testing.T) {
	b := newPromptGateBuilder(nil)
	entered, release := make(chan struct{}, 2), make(chan struct{})
	var asked atomic.Int32
	b.showNetwork = func(context.Context, string, string, bool) (tui.PromptOption, error) {
		asked.Add(1)
		entered <- struct{}{}
		<-release
		return tui.OptionAllowSession, nil
	}
	arrived := make(chan struct{}, 2)
	var accepts, acceptsWhileHeld atomic.Int32
	ask := func(ctx context.Context, host, port string, covered func() bool, accept func(netproxy.Decision) bool) (netproxy.Decision, error) {
		arrived <- struct{}{}
		return b.AskNetwork(ctx, host, port, covered, func(d netproxy.Decision) bool {
			accepts.Add(1)
			if len(b.gate.slot) == 1 {
				acceptsWhileHeld.Add(1)
			}
			return accept(d)
		})
	}
	server, endpoint := startTestProxy(t)
	first := server.NewOwner(ask)
	t.Cleanup(first.Close)
	firstCall := sendProxyRequest(t, endpoint, first, "127.0.0.1")
	<-entered
	second := server.NewOwner(ask)
	t.Cleanup(second.Close)
	secondCall := sendProxyRequest(t, endpoint, second, "127.0.0.1")
	<-arrived
	<-arrived
	close(release)

	for i, call := range []*proxyCall{firstCall, secondCall} {
		if got := call.await(t); got != "not public" {
			t.Fatalf("request %d refused %q, want it admitted", i+1, got)
		}
	}
	if got := asked.Load(); got != 1 {
		t.Fatalf("prompts shown = %d, want exactly one for two same-host requests after a session answer", got)
	}
	if accepts.Load() != 1 || acceptsWhileHeld.Load() != 1 {
		t.Fatalf("accept calls = %d, while the slot was held = %d; want one accept before the slot was released", accepts.Load(), acceptsWhileHeld.Load())
	}
}

func TestPromptGateNetworkAsker_CancellationWithdrawsOnlyItsPromptAfterTheUIAcknowledges(t *testing.T) {
	app, screen := startLiveTUI(t)
	b := NewPromptGateBuilder(app)
	server, endpoint := startTestProxy(t)
	first := sendProxyRequest(t, endpoint, server.NewOwner(b.AskNetwork), "127.0.0.2")
	waitScreen(t, app, screen, "127.0.0.2", true)

	queued := sendProxyRequest(t, endpoint, server.NewOwner(b.AskNetwork), "127.0.0.3")
	_ = queued.conn.Close()
	if got := waitRefusal(t, server, "127.0.0.3"); got != "not approved (command ended)" {
		t.Fatalf("queued request refused %q, want not approved (command ended)", got)
	}
	waitScreen(t, app, screen, "127.0.0.2", true)

	release := blockTUILoop(app)
	_ = first.conn.Close()
	time.Sleep(100 * time.Millisecond)
	if len(b.gate.slot) != 1 {
		release()
		t.Fatal("the prompt slot was released before the UI acknowledged the withdrawal")
	}
	release()
	if got := waitRefusal(t, server, "127.0.0.2"); got != "not approved (command ended)" {
		t.Fatalf("cancelled request refused %q, want not approved (command ended)", got)
	}
	waitSlotFree(t, b)
	waitScreen(t, app, screen, "network access", false)
}

func TestPromptGateNetworkAsker_ShutdownFreesTheSlotWithoutDrainingTheUI(t *testing.T) {
	for _, tc := range []string{"before the acknowledgment wait", "during the acknowledgment wait"} {
		t.Run(tc, func(t *testing.T) {
			app, screen := startLiveTUI(t)
			b := NewPromptGateBuilder(app)
			server, endpoint := startTestProxy(t)
			call := sendProxyRequest(t, endpoint, server.NewOwner(b.AskNetwork), "127.0.0.2")
			waitScreen(t, app, screen, "127.0.0.2", true)

			release := blockTUILoop(app)
			want := "not approved (prompt failed)"
			if tc == "during the acknowledgment wait" {
				_ = call.conn.Close()
				time.Sleep(50 * time.Millisecond)
				want = "not approved (command ended)"
			}
			app.BeginShutdown()
			waitSlotFree(t, b)
			got := waitRefusal(t, server, "127.0.0.2")
			release()
			if got != want {
				t.Fatalf("request refused %q, want %q", got, want)
			}

			screen.InjectKey(tcell.KeyRune, 's', tcell.ModNone)
			onEventLoop(t, app, func() {})
			var asked atomic.Int32
			probe := server.NewOwner(func(context.Context, string, string, func() bool, func(netproxy.Decision) bool) (netproxy.Decision, error) {
				asked.Add(1)
				return netproxy.DecisionDeny, nil
			})
			t.Cleanup(probe.Close)
			if got := sendProxyRequest(t, endpoint, probe, "127.0.0.2").await(t); got != "not approved (denied)" || asked.Load() != 1 {
				t.Fatalf("later request refused %q after %d asks; want it asked again because no approval was stored", got, asked.Load())
			}
		})
	}
}

func TestPromptGateNetworkAsker_ShutdownBetweenTheAnswerAndItsAcceptanceStoresNoGrant(t *testing.T) {
	app := tui.New(nil)
	b := newPromptGateBuilder(nil)
	b.showNetwork = func(context.Context, string, string, bool) (tui.PromptOption, error) {
		return tui.OptionAllowSession, nil
	}
	answered, resume := make(chan struct{}), make(chan struct{})
	b.whileRunning = func(f func()) bool {
		close(answered)
		<-resume
		return app.WhileRunning(f)
	}
	server, endpoint := startTestProxy(t)
	owner := server.NewOwner(b.AskNetwork)
	t.Cleanup(owner.Close)
	call := sendProxyRequest(t, endpoint, owner, "127.0.0.2")
	<-answered
	app.BeginShutdown()
	close(resume)
	if got := call.await(t); got != "not approved (prompt failed)" {
		t.Fatalf("request refused %q, want not approved (prompt failed)", got)
	}

	var asked atomic.Int32
	probe := server.NewOwner(func(context.Context, string, string, func() bool, func(netproxy.Decision) bool) (netproxy.Decision, error) {
		asked.Add(1)
		return netproxy.DecisionDeny, nil
	})
	t.Cleanup(probe.Close)
	if got := sendProxyRequest(t, endpoint, probe, "127.0.0.2").await(t); got != "not approved (denied)" || asked.Load() != 1 {
		t.Fatalf("later request refused %q after %d asks; want it asked again because no session grant was stored", got, asked.Load())
	}
}

func TestPromptGateNetworkAsker_AppEndRefusesRequestsQueuedBehindAPermissionPrompt(t *testing.T) {
	for _, tc := range []string{"shutdown", "event loop return"} {
		t.Run(tc, func(t *testing.T) {
			app, screen := startLiveTUI(t)
			b := NewPromptGateBuilder(app)
			entered, release := make(chan struct{}), make(chan struct{})
			b.show = func(tui.PromptRequest) (tui.PromptDecision, error) {
				close(entered)
				<-release
				return tui.PromptDecision{Option: tui.OptionDeny}, nil
			}
			permissionDone := make(chan struct{})
			go func() {
				defer close(permissionDone)
				req := permissions.MatchRequest{Kind: "tool", Subject: "Read", PathScope: "/work"}
				_, _ = b.Build(req, PromptDisplay{Action: "Run tool", Subject: "Read"})(context.Background(), permissions.ScopeEscalation{})
			}()
			t.Cleanup(func() {
				close(release)
				<-permissionDone
			})
			<-entered

			server, endpoint := startTestProxy(t)
			owner := server.NewOwner(b.AskNetwork)
			t.Cleanup(owner.Close)
			queued := sendProxyRequest(t, endpoint, owner, "127.0.0.2")
			select {
			case got := <-queued.refused:
				t.Fatalf("the network request finished (%q) before the app ended", got)
			case <-time.After(100 * time.Millisecond):
			}

			if tc == "shutdown" {
				app.BeginShutdown()
			} else if err := screen.PostEvent(tcell.NewEventError(errors.New("terminal lost"))); err != nil {
				t.Fatal(err)
			}
			if got := queued.await(t); got != "not approved (prompt failed)" {
				t.Fatalf("queued request refused %q, want not approved (prompt failed)", got)
			}
			if got := sendProxyRequest(t, endpoint, owner, "127.0.0.2").await(t); got != "not approved (prompt failed)" {
				t.Fatalf("request after the app ended refused %q, want not approved (prompt failed)", got)
			}
			select {
			case <-permissionDone:
				t.Fatal("the permission prompt was released")
			default:
			}

			var asked atomic.Int32
			probe := server.NewOwner(func(context.Context, string, string, func() bool, func(netproxy.Decision) bool) (netproxy.Decision, error) {
				asked.Add(1)
				return netproxy.DecisionDeny, nil
			})
			t.Cleanup(probe.Close)
			if got := sendProxyRequest(t, endpoint, probe, "127.0.0.2").await(t); got != "not approved (denied)" || asked.Load() != 1 {
				t.Fatalf("later request refused %q after %d asks; want it asked again because no approval was stored", got, asked.Load())
			}
		})
	}
}

func reloadDomainGrants(t *testing.T, home, projectRoot string) []string {
	t.Helper()
	global := map[string]any{}
	if _, err := os.Stat(SettingsPath(home)); err == nil {
		if global, err = defaultLoadGlobalSettings(home); err != nil {
			t.Fatalf("load global settings: %v", err)
		}
	}
	composition, err := defaultComposeConfig(global, projectRoot)
	if err != nil {
		t.Fatalf("compose settings: %v", err)
	}
	cache, err := config.NewCache(composition.Config, projectRoot, nil, home)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	return cache.DomainGrants()
}

type acceptCounts struct {
	calls, whileHeld atomic.Int32
	arrived          chan context.Context
}

func countAccepts(ask netproxy.Asker, slot chan struct{}) (netproxy.Asker, *acceptCounts) {
	c := &acceptCounts{arrived: make(chan context.Context, 8)}
	return func(ctx context.Context, host, port string, covered func() bool, accept func(netproxy.Decision) bool) (netproxy.Decision, error) {
		c.arrived <- ctx
		return ask(ctx, host, port, covered, func(d netproxy.Decision) bool {
			c.calls.Add(1)
			if d == netproxy.DecisionSession && len(slot) == 1 {
				c.whileHeld.Add(1)
			}
			return accept(d)
		})
	}, c
}

func requireAskedAgain(t *testing.T, server *netproxy.Server, endpoint, host string) {
	t.Helper()
	var asked atomic.Int32
	probe := server.NewOwner(func(context.Context, string, string, func() bool, func(netproxy.Decision) bool) (netproxy.Decision, error) {
		asked.Add(1)
		return netproxy.DecisionDeny, nil
	})
	t.Cleanup(probe.Close)
	if got := sendProxyRequest(t, endpoint, probe, host).await(t); got != "not approved (denied)" || asked.Load() != 1 {
		t.Fatalf("later request refused %q after %d asks; want it asked again because no approval was stored", got, asked.Load())
	}
}

func savedAnswerBuilder(t *testing.T, b *PromptGateBuilder, trusted bool) (home, root string) {
	t.Helper()
	home, root = t.TempDir(), t.TempDir()
	b.projectTrusted = trusted
	b.projectRoot = root
	b.globalSettingsPath = SettingsPath(home)
	return home, root
}

func savedTarget(opt tui.PromptOption, home, root string) (target, other string) {
	if opt == tui.OptionAllowGlobal {
		return filepath.Join(home, ".codemeld", "global", "settings.yaml"), filepath.Join(root, ".codemeld", "settings.local.yaml")
	}
	return filepath.Join(root, ".codemeld", "settings.local.yaml"), filepath.Join(home, ".codemeld", "global", "settings.yaml")
}

func TestPromptGateNetworkAsker_SavedAnswersPersistAndCoverTheQueuedRequest(t *testing.T) {
	for _, opt := range []tui.PromptOption{tui.OptionAllowProject, tui.OptionAllowGlobal} {
		t.Run(fmt.Sprint(opt), func(t *testing.T) {
			b := newPromptGateBuilder(nil)
			home, root := savedAnswerBuilder(t, b, true)
			entered, release := make(chan struct{}, 2), make(chan struct{})
			var asked atomic.Int32
			b.showNetwork = func(_ context.Context, _, _ string, projectChoice bool) (tui.PromptOption, error) {
				if !projectChoice {
					t.Error("a trusted run's network prompt was not offered the project choice")
				}
				asked.Add(1)
				entered <- struct{}{}
				<-release
				return opt, nil
			}
			ask, counts := countAccepts(b.AskNetwork, b.gate.slot)
			server, endpoint := startTestProxy(t)
			first, second := server.NewOwner(ask), server.NewOwner(ask)
			t.Cleanup(first.Close)
			t.Cleanup(second.Close)
			firstCall := sendProxyRequest(t, endpoint, first, "127.0.0.1")
			<-entered
			secondCall := sendProxyRequest(t, endpoint, second, "127.0.0.1")
			<-counts.arrived
			<-counts.arrived
			close(release)
			for i, call := range []*proxyCall{firstCall, secondCall} {
				if got := call.await(t); got != "not public" {
					t.Fatalf("request %d refused %q, want it admitted", i+1, got)
				}
			}
			if asked.Load() != 1 || counts.calls.Load() != 1 || counts.whileHeld.Load() != 1 {
				t.Fatalf("prompts %d, accepts %d, session accepts while the slot was held %d; want 1, 1, 1",
					asked.Load(), counts.calls.Load(), counts.whileHeld.Load())
			}
			if got := reloadDomainGrants(t, home, root); !slices.Equal(got, []string{"127.0.0.1:9"}) {
				t.Fatalf("a new session's DomainGrants() = %q, want the saved 127.0.0.1:9", got)
			}
			if _, other := savedTarget(opt, home, root); fileExists(other) {
				t.Fatalf("the answer also wrote %s", other)
			}
		})
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestPromptGateNetworkAsker_HiddenProjectAnswerInAnUntrustedRunFails(t *testing.T) {
	b := newPromptGateBuilder(nil)
	home, root := savedAnswerBuilder(t, b, false)
	b.showNetwork = func(_ context.Context, _, _ string, projectChoice bool) (tui.PromptOption, error) {
		if projectChoice {
			t.Error("an untrusted run's network prompt was offered the project choice")
		}
		return tui.OptionAllowProject, nil
	}
	ask, counts := countAccepts(b.AskNetwork, b.gate.slot)
	server, endpoint := startTestProxy(t)
	owner := server.NewOwner(ask)
	t.Cleanup(owner.Close)
	if got := sendProxyRequest(t, endpoint, owner, "127.0.0.1").await(t); got != "not approved (prompt failed)" {
		t.Fatalf("request refused %q, want not approved (prompt failed)", got)
	}
	if counts.calls.Load() != 0 {
		t.Fatalf("accept called %d times for a hidden answer", counts.calls.Load())
	}
	for _, path := range []string{filepath.Join(root, ".codemeld", "settings.local.yaml"), filepath.Join(home, ".codemeld", "global", "settings.yaml")} {
		if fileExists(path) {
			t.Fatalf("a hidden answer wrote %s", path)
		}
	}
	requireAskedAgain(t, server, endpoint, "127.0.0.1")
}

func TestPromptGateNetworkAsker_SavedAnswerPersistenceFailureApprovesNothing(t *testing.T) {
	const seed = "domain_grants:\n  - host: seed.example\n    port: 443\n"
	for _, opt := range []tui.PromptOption{tui.OptionAllowProject, tui.OptionAllowGlobal} {
		for _, failure := range []string{"persist seam", "pre-replacement write"} {
			t.Run(fmt.Sprint(opt)+"/"+failure, func(t *testing.T) {
				b := newPromptGateBuilder(nil)
				home, root := savedAnswerBuilder(t, b, true)
				target, _ := savedTarget(opt, home, root)
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, []byte(seed), 0o600); err != nil {
					t.Fatal(err)
				}
				if failure == "persist seam" {
					b.persistGrant = func(bool, config.DomainGrant) error { return errors.New("disk full") }
				} else {
					t.Cleanup(fsutil.SetSyncFileForTest(func(*os.File) error { return errors.New("forced sync failure") }))
				}
				b.showNetwork = func(context.Context, string, string, bool) (tui.PromptOption, error) { return opt, nil }
				ask, counts := countAccepts(b.AskNetwork, b.gate.slot)
				server, endpoint := startTestProxy(t)
				owner := server.NewOwner(ask)
				t.Cleanup(owner.Close)
				if got := sendProxyRequest(t, endpoint, owner, "127.0.0.1").await(t); got != "not approved (prompt failed)" {
					t.Fatalf("request refused %q, want not approved (prompt failed)", got)
				}
				if counts.calls.Load() != 0 {
					t.Fatalf("accept called %d times on a failed write", counts.calls.Load())
				}
				if got, err := os.ReadFile(target); err != nil || string(got) != seed {
					t.Fatalf("target = %q, %v; want it unchanged", got, err)
				}
				requireAskedAgain(t, server, endpoint, "127.0.0.1")
			})
		}
	}
}

func pausePersistence(b *PromptGateBuilder) (entered, resume chan struct{}) {
	entered, resume = make(chan struct{}), make(chan struct{})
	persist := b.persistGrant
	b.persistGrant = func(global bool, g config.DomainGrant) error {
		close(entered)
		<-resume
		return persist(global, g)
	}
	return entered, resume
}

func TestPromptGateNetworkAsker_RequestCancelledDuringASavedWriteIsNotAccepted(t *testing.T) {
	b := newPromptGateBuilder(nil)
	home, root := savedAnswerBuilder(t, b, true)
	b.showNetwork = func(context.Context, string, string, bool) (tui.PromptOption, error) {
		return tui.OptionAllowProject, nil
	}
	entered, resume := pausePersistence(b)
	ask, counts := countAccepts(b.AskNetwork, b.gate.slot)
	server, endpoint := startTestProxy(t)
	owner := server.NewOwner(ask)
	t.Cleanup(owner.Close)
	call := sendProxyRequest(t, endpoint, owner, "127.0.0.1")
	reqCtx := <-counts.arrived
	<-entered
	_ = call.conn.Close()
	select {
	case <-reqCtx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("closing the client did not cancel the request")
	}
	close(resume)
	if got := waitRefusal(t, server, "127.0.0.1"); got != "not approved (command ended)" {
		t.Fatalf("request refused %q, want not approved (command ended)", got)
	}
	waitSlotFree(t, b)
	if counts.calls.Load() != 0 {
		t.Fatalf("accept called %d times after the request was cancelled", counts.calls.Load())
	}
	if got := reloadDomainGrants(t, home, root); !slices.Equal(got, []string{"127.0.0.1:9"}) {
		t.Fatalf("DomainGrants() = %q, want the grant the write already published", got)
	}
	requireAskedAgain(t, server, endpoint, "127.0.0.1")
}

func TestPromptGateNetworkAsker_ShutdownDuringASavedWriteReturnsAndIsNotAccepted(t *testing.T) {
	app := tui.New(nil)
	b := NewPromptGateBuilder(app)
	home, root := savedAnswerBuilder(t, b, true)
	b.showNetwork = func(context.Context, string, string, bool) (tui.PromptOption, error) {
		return tui.OptionAllowGlobal, nil
	}
	entered, resume := pausePersistence(b)
	ask, counts := countAccepts(b.AskNetwork, b.gate.slot)
	server, endpoint := startTestProxy(t)
	owner := server.NewOwner(ask)
	t.Cleanup(owner.Close)
	call := sendProxyRequest(t, endpoint, owner, "127.0.0.1")
	<-entered
	shut := make(chan struct{})
	go func() {
		app.BeginShutdown()
		close(shut)
	}()
	select {
	case <-shut:
	case <-time.After(2 * time.Second):
		close(resume)
		t.Fatal("BeginShutdown waited on the paused settings write")
	}
	if len(b.gate.slot) != 1 {
		close(resume)
		t.Fatal("the prompt slot was released before the settings write finished")
	}
	close(resume)
	if got := call.await(t); got != "not approved (prompt failed)" {
		t.Fatalf("request refused %q, want not approved (prompt failed)", got)
	}
	waitSlotFree(t, b)
	if counts.calls.Load() != 0 {
		t.Fatalf("accept called %d times after shutdown began", counts.calls.Load())
	}
	if got := reloadDomainGrants(t, home, root); !slices.Equal(got, []string{"127.0.0.1:9"}) {
		t.Fatalf("DomainGrants() = %q, want the grant the write already published", got)
	}
	requireAskedAgain(t, server, endpoint, "127.0.0.1")
}

func connectGateConfinement(b *PromptGateBuilder) *confinement {
	return &confinement{connectAsker: b.AskConnect, approvals: &connectApprovals{held: map[any]*os.File{}}}
}

type connectResult struct{ step, reason string }

func connectLive() bool { return true }

func TestPromptGateConnectAsker_AnswerForADeadRequestIsNotStored(t *testing.T) {
	key := netip.MustParseAddrPort("127.0.0.1:5432")
	answers := []tui.PromptOption{tui.OptionAllowSession, tui.OptionAllowOnce}
	shown := 0
	b := newPromptGateBuilder(nil)
	b.showConnect = func(context.Context, string) (tui.PromptOption, error) {
		shown++
		return answers[shown-1], nil
	}
	c := connectGateConfinement(b)
	if step, _ := c.answerConnect(context.Background(), func() bool { return false }, key, key.String(), nil); step != "" {
		t.Errorf("session answer for a request that ended: admitted by %q, want refused", step)
	}
	if c.approvals.covers(key) {
		t.Error("the session answer for a request that ended was stored")
	}
	step, reason := c.answerConnect(context.Background(), connectLive, key, key.String(), nil)
	if got := (connectResult{step, reason}); got != (connectResult{"prompt once", ""}) || shown != 2 {
		t.Errorf("next connect after the late answer: %+v after %d prompts, want asked again and admitted once", got, shown)
	}
}

func TestPromptGateConnectAsker_AnswersBehaveAsNamed(t *testing.T) {
	db, cache := netip.MustParseAddrPort("127.0.0.1:5432"), netip.MustParseAddrPort("[::1]:6379")
	answers := []struct {
		opt tui.PromptOption
		err error
	}{{tui.OptionAllowOnce, nil}, {tui.OptionAllowSession, nil}, {tui.OptionDeny, nil}, {tui.OptionDeny, errors.New("boom")}, {tui.OptionAllowProject, nil}}
	var shown []string
	b := newPromptGateBuilder(nil)
	b.showConnect = func(_ context.Context, dest string) (tui.PromptOption, error) {
		if len(shown) == len(answers) {
			t.Fatalf("asked for %s after the scripted answers ran out", dest)
		}
		shown = append(shown, dest)
		return answers[len(shown)-1].opt, answers[len(shown)-1].err
	}
	c := connectGateConfinement(b)
	handle, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	holds := 0
	hold := func() (*os.File, error) { holds++; return handle, nil }
	for i, tc := range []struct {
		key  netip.AddrPort
		want connectResult
	}{
		{db, connectResult{"prompt once", ""}},
		{db, connectResult{"prompt session", ""}},
		{db, connectResult{"session approval", ""}},
		{cache, connectResult{"", "not approved (denied)"}},
		{cache, connectResult{"", "not approved (prompt failed)"}},
		{cache, connectResult{"", "not approved (prompt failed)"}},
	} {
		step, reason := c.answerConnect(context.Background(), connectLive, tc.key, tc.key.String(), hold)
		if got := (connectResult{step, reason}); got != tc.want {
			t.Errorf("connect %d to %s: got %+v, want %+v", i+1, tc.key, got, tc.want)
		}
	}
	if want := []string{"127.0.0.1:5432", "127.0.0.1:5432", "[::1]:6379", "[::1]:6379", "[::1]:6379"}; !slices.Equal(shown, want) {
		t.Errorf("prompts shown for %q, want %q", shown, want)
	}
	if holds != 1 {
		t.Errorf("handles held %d times, want once for the session answer", holds)
	}
	if err := c.cleanupAll(); err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("after session cleanup closing the held handle returned %v, want it already closed", err)
	}
}

func TestPromptGateConnectAsker_PromptsWaitTheirTurnWhileAdmittedConnectsProceed(t *testing.T) {
	db, cache, approved := netip.MustParseAddrPort("127.0.0.1:5432"), netip.MustParseAddrPort("127.0.0.1:6379"), netip.MustParseAddrPort("127.0.0.1:8080")
	entered, release := make(chan string, 3), make(chan struct{})
	b := newPromptGateBuilder(nil)
	b.showConnect = func(_ context.Context, dest string) (tui.PromptOption, error) {
		entered <- dest
		<-release
		if dest == db.String() {
			return tui.OptionAllowSession, nil
		}
		return tui.OptionAllowOnce, nil
	}
	c := connectGateConfinement(b)
	c.approvals.add(approved, nil)
	connect := func(key netip.AddrPort) <-chan connectResult {
		out := make(chan connectResult, 1)
		go func() {
			step, reason := c.answerConnect(context.Background(), connectLive, key, key.String(), nil)
			out <- connectResult{step, reason}
		}()
		return out
	}
	await := func(what string, ch <-chan connectResult) connectResult {
		t.Helper()
		select {
		case r := <-ch:
			return r
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not finish", what)
		}
		return connectResult{}
	}
	first := connect(db)
	if got := <-entered; got != db.String() {
		t.Fatalf("first prompt for %s, want %s", got, db)
	}
	queuedSame, queuedOther := connect(db), connect(cache)
	if got := await("the session-approved connect", connect(approved)); got != (connectResult{"session approval", ""}) {
		t.Errorf("session-approved connect while a prompt waits: %+v, want admitted by session approval", got)
	}
	select {
	case dest := <-entered:
		t.Fatalf("a second prompt for %s was shown while the first was pending", dest)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	for what, tc := range map[string]struct {
		ch   <-chan connectResult
		want connectResult
	}{
		"first":                        {first, connectResult{"prompt session", ""}},
		"queued same destination":      {queuedSame, connectResult{"session approval", ""}},
		"queued different destination": {queuedOther, connectResult{"prompt once", ""}},
	} {
		if got := await(what, tc.ch); got != tc.want {
			t.Errorf("%s: %+v, want %+v", what, got, tc.want)
		}
	}
	if got := <-entered; got != cache.String() || len(entered) != 0 {
		t.Errorf("second prompt for %s with %d more, want exactly one more prompt for %s", got, len(entered), cache)
	}
}

func TestPromptGateConnectAsker_WithdrawnPromptsRefuseWithTheirReason(t *testing.T) {
	key := netip.MustParseAddrPort("127.0.0.1:5432")
	t.Run("command ended", func(t *testing.T) {
		entered := make(chan struct{})
		b := newPromptGateBuilder(nil)
		b.showConnect = func(ctx context.Context, _ string) (tui.PromptOption, error) {
			close(entered)
			<-ctx.Done()
			return tui.OptionDeny, ctx.Err()
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan connectResult, 1)
		go func() {
			step, reason := connectGateConfinement(b).answerConnect(ctx, connectLive, key, key.String(), nil)
			done <- connectResult{step, reason}
		}()
		<-entered
		cancel()
		if got := <-done; got != (connectResult{"", "not approved (command ended)"}) {
			t.Errorf("withdrawn prompt: %+v, want not approved (command ended)", got)
		}
		waitSlotFree(t, b)
	})
	t.Run("session ended", func(t *testing.T) {
		b := newPromptGateBuilder(nil)
		b.showConnect = func(context.Context, string) (tui.PromptOption, error) {
			t.Error("prompted after the session ended")
			return tui.OptionAllowOnce, nil
		}
		ended := make(chan struct{})
		close(ended)
		b.ended = ended
		if step, reason := connectGateConfinement(b).answerConnect(context.Background(), connectLive, key, key.String(), nil); step != "" || reason != "not approved (session ended)" {
			t.Errorf("connect after the session ended: step %q reason %q, want not approved (session ended)", step, reason)
		}
	})
}
