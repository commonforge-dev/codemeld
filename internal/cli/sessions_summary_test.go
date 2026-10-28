package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

const summaryFixturePath = "testdata/sessions-summary.json"

func runSummary(t *testing.T, target string, extra ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	args := append([]string{"codemeld", "sessions", "summary", target}, extra...)
	if code := Run(context.Background(), args, &stdout, &stderr); code != 0 {
		t.Fatalf("summary exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	return stdout.String()
}

type summaryJSON struct {
	Session   string `json:"session"`
	Folder    string `json:"folder"`
	ShellExec []struct {
		SubjectKind string `json:"subject_kind"`
		Subject     string `json:"subject"`
		Invocations int    `json:"invocations"`
		Failures    int    `json:"failures"`
		DurationMs  int64  `json:"duration_ms"`
	} `json:"shell_exec"`
	StructuredReads []struct {
		ToolName    string `json:"tool_name"`
		Invocations int    `json:"invocations"`
		NonSuccess  int    `json:"non_success"`
		Outcomes    []struct {
			Outcome string `json:"outcome"`
			Count   int    `json:"count"`
		} `json:"outcomes"`
		DurationMs int64 `json:"duration_ms"`
	} `json:"structured_reads"`
	PathScopes []struct {
		PathScope string   `json:"path_scope"`
		Starts    int      `json:"starts"`
		UsedBy    []string `json:"used_by"`
	} `json:"path_scopes"`
	Totals struct {
		IdentifiedTurns  int   `json:"identified_turns"`
		IdentifiedRounds int   `json:"identified_rounds"`
		TerminatedRounds int   `json:"terminated_rounds"`
		IncompleteRounds int   `json:"incomplete_rounds"`
		RoundTrips       int   `json:"round_trips"`
		LegacyRoundTrips int   `json:"legacy_round_trips"`
		ProviderWallMs   int64 `json:"provider_wall_ms"`
		ProviderModels   []struct {
			Provider string `json:"provider"`
			ModelID  string `json:"model_id"`
		} `json:"provider_models"`
		ModelResponses    int   `json:"model_responses"`
		InputTokens       int64 `json:"input_tokens"`
		OutputTokens      int64 `json:"output_tokens"`
		CachedInputTokens struct {
			Availability      string `json:"availability"`
			Tokens            *int64 `json:"tokens"`
			ReportedResponses int    `json:"reported_responses"`
			PartialResponses  int    `json:"partial_responses"`
			OmittedResponses  int    `json:"omitted_responses"`
		} `json:"cached_input_tokens"`
		CostUSD struct {
			Availability      string   `json:"availability"`
			USD               *float64 `json:"usd"`
			ReportedResponses int      `json:"reported_responses"`
			PartialResponses  int      `json:"partial_responses"`
			OmittedResponses  int      `json:"omitted_responses"`
		} `json:"cost_usd"`
	} `json:"totals"`
}

func summaryJSONOf(t *testing.T, target string) summaryJSON {
	t.Helper()
	var report summaryJSON
	if err := json.Unmarshal([]byte(runSummary(t, target, "--json")), &report); err != nil {
		t.Fatalf("summary --json is not one JSON document: %v", err)
	}
	return report
}

func cachedTokens(n int64) *int64 { return &n }

func TestSessionsSummary_Fixture_ExecutionRecordTables(t *testing.T) {
	out := runSummary(t, summaryFixturePath)

	tests := []struct {
		name string
		want string
	}{
		{"shell header counts subjects and invocations", "shell and vcs execution records (tool_exec_end): 4 subjects, 5 invocations"},
		{"the most-invoked subject sorts first", "  1. direct  git status  invocations=2  failed=0  duration_ms=100"},
		{"a non-zero exit is a failure", "  2. direct  git commit  invocations=1  failed=1  duration_ms=90"},
		{"an equal count breaks the tie on subject", "  3. direct  git diff  invocations=1  failed=0  duration_ms=20"},
		{"an equal count breaks the tie on subject_kind first", "  4. tool  bash  invocations=1  failed=0  duration_ms=50"},
		{"reads are a separate table", "allowlisted structured read execution records (structured_read_end): 3 tools, 5 invocations"},
		{"a read's outcomes are broken out, not scored as exit codes", "  1. read  invocations=3  non_success=1  outcomes=success:2,denied:1  duration_ms=15"},
		{"equal read counts sort by tool name", "  2. glob  invocations=1  non_success=0  outcomes=success:1  duration_ms=4"},
		{"a failed read is a non-success outcome", "  3. grep  invocations=1  non_success=1  outcomes=tool_failure:1  duration_ms=12"},
		{"the read table names its own vocabulary", "a read records a closed outcome, never an exit code"},
		{
			"the durable-evidence boundary is stated",
			"other structured tool calls record no durable start/end pair, so they are absent from both",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(out, tt.want) {
				t.Fatalf("summary output missing %q:\n%s", tt.want, out)
			}
		})
	}

	if strings.Contains(out, "grep  invocations=1  non_success=1  outcomes=exit") {
		t.Fatalf("a structured read was scored with exit-code vocabulary:\n%s", out)
	}
}

func TestSessionsSummary_Fixture_PathScopesAreNotEditedFiles(t *testing.T) {
	out := runSummary(t, summaryFixturePath)

	tests := []struct {
		name string
		want string
	}{
		{"both start kinds feed one scope table", "permission path scopes (tool_exec_start and structured_read_start): 2 scopes, 11 starts"},
		{"a scope lists the subjects and tool names that used it", "  1. /proj  starts=6  used_by=git commit,git diff,git status,read"},
		{"a second scope is reported separately", "  2. /proj/sub  starts=5  used_by=bash,git push,glob,grep,read"},
		{
			"the table is labelled as authorization, not as edited files",
			"these are the directory scopes those execution records were authorized against, not the files",
		},
		{"the session's lack of an edited-file list is stated", "the session changed: a session records no edited-file list."},
		{
			"the start/end difference is explained",
			"a scope's start count can exceed the matching table's invocation count: the start is recorded",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(out, tt.want) {
				t.Fatalf("summary output missing %q:\n%s", tt.want, out)
			}
		})
	}

	report := summaryJSONOf(t, summaryFixturePath)
	starts := 0
	for _, s := range report.PathScopes {
		starts += s.Starts
	}
	ends := 0
	for _, r := range report.ShellExec {
		ends += r.Invocations
	}
	for _, r := range report.StructuredReads {
		ends += r.Invocations
	}
	if starts != 11 || ends != 10 {
		t.Fatalf("starts = %d, completed executions = %d; want 11 and 10 so the interrupted start is scope-only", starts, ends)
	}
	var pushed bool
	for _, s := range report.PathScopes {
		for _, u := range s.UsedBy {
			if u == "git push" {
				pushed = true
			}
		}
	}
	if !pushed {
		t.Fatalf("the start with no end is missing from the scope table: %+v", report.PathScopes)
	}
	for _, r := range report.ShellExec {
		if r.Subject == "git push" {
			t.Fatalf("a start with no end was counted as a completed execution: %+v", r)
		}
	}
}

func TestSessionsSummary_Fixture_LifecycleAndTokenTotals(t *testing.T) {
	out := runSummary(t, summaryFixturePath)

	tests := []struct {
		name string
		want string
	}{
		{"turns are the union of the identified turn ids", "  identified turns: 2"},
		{"a cancelled terminal still closes its round", "  identified rounds: 3 (terminated: 2, incomplete: 1)"},
		{"a legacy round trip is excluded from the round count", "  provider round trips: 4 (legacy, without turn/round ids: 1)"},
		{"a legacy round trip still contributes its duration", "  provider wall time: 2700 ms"},
		{
			"pairs come from round trips and responses alike",
			"  provider/model pairs: anthropic/claude-opus-5, openai/gpt-5.1-legacy, openai/gpt-5.5",
		},
		{"input tokens are summed", "  input tokens: 1750"},
		{"output tokens are summed", "  output tokens: 350"},
		{
			"a partial and an omitted count make the cached total a lower bound",
			"  cached input tokens: >= 1100 (lower bound; reported exact by 1, partial by 1, not reported by 1)",
		},
		{"terminated is not read as successful", "provider-failed round is terminated too, so closure is not success."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(out, tt.want) {
				t.Fatalf("summary output missing %q:\n%s", tt.want, out)
			}
		})
	}

	report := summaryJSONOf(t, summaryFixturePath)
	if report.Session != summaryFixturePath {
		t.Fatalf("session = %q, want the resolved path %q", report.Session, summaryFixturePath)
	}
	if report.Folder != "/proj" {
		t.Fatalf("folder = %q, want /proj", report.Folder)
	}
	tot := report.Totals
	if tot.IdentifiedTurns != 2 || tot.IdentifiedRounds != 3 || tot.TerminatedRounds != 2 || tot.IncompleteRounds != 1 {
		t.Fatalf("lifecycle totals = %+v", tot)
	}
	if tot.RoundTrips != 4 || tot.LegacyRoundTrips != 1 || tot.ProviderWallMs != 2700 {
		t.Fatalf("round-trip totals = %+v", tot)
	}
	if len(tot.ProviderModels) != 3 ||
		tot.ProviderModels[0].Provider != "anthropic" || tot.ProviderModels[0].ModelID != "claude-opus-5" ||
		tot.ProviderModels[1].ModelID != "gpt-5.1-legacy" || tot.ProviderModels[2].ModelID != "gpt-5.5" {
		t.Fatalf("provider/model pairs = %+v", tot.ProviderModels)
	}
	c := tot.CachedInputTokens
	if c.Availability != "lower_bound" || c.Tokens == nil || *c.Tokens != 1100 ||
		c.ReportedResponses != 1 || c.PartialResponses != 1 || c.OmittedResponses != 1 {
		t.Fatalf("cached total = %+v", c)
	}
}

// Asserted through the command rather than buildSummaryReport, so the legacy shapes are
// proven to survive the shared validated load path.
func TestSessionsSummary_Fixture_LegacyRecordsSurvive(t *testing.T) {
	report := summaryJSONOf(t, summaryFixturePath)

	var responseOnly, legacyRoundTrip bool
	for _, p := range report.Totals.ProviderModels {
		switch {
		case p.Provider == "anthropic" && p.ModelID == "claude-opus-5":
			responseOnly = true
		case p.Provider == "openai" && p.ModelID == "gpt-5.1-legacy":
			legacyRoundTrip = true
		}
	}
	if !responseOnly {
		t.Fatalf("a model_response with no round trip lost its provider/model pair: %+v", report.Totals.ProviderModels)
	}
	if !legacyRoundTrip {
		t.Fatalf("an identity-less round trip lost its provider/model pair: %+v", report.Totals.ProviderModels)
	}
	if report.Totals.IdentifiedRounds != 3 {
		t.Fatalf("identified rounds = %d; the identity-less round trip must not be counted", report.Totals.IdentifiedRounds)
	}
}

func TestSessionsSummary_CachedTokenAvailability(t *testing.T) {
	response := func(cached *int64, partial bool) sessions.Event {
		return eventRecord(events.KindModelResponse, events.ModelResponse{
			Provider: "openai", ModelID: "gpt-5.5", InputTokens: 10, OutputTokens: 5,
			CachedInputTokens: cached, CachedInputTokensPartial: partial, Anomaly: []string{},
		})
	}

	tests := []struct {
		name    string
		records []sessions.Record
		want    string
	}{
		{
			name:    "no response reports cached usage",
			records: []sessions.Record{response(nil, false), response(nil, false)},
			want:    "cached input tokens: unavailable (no model_response reported cached usage)",
		},
		{
			name:    "every response reports an exact value",
			records: []sessions.Record{response(cachedTokens(40), false), response(cachedTokens(60), false)},
			want:    "cached input tokens: 100 (exact; every one of the 2 responses reported a value)",
		},
		{
			name:    "a reported zero is still exact",
			records: []sessions.Record{response(cachedTokens(0), false)},
			want:    "cached input tokens: 0 (exact; every one of the 1 responses reported a value)",
		},
		{
			name:    "one omitted value makes the total a lower bound",
			records: []sessions.Record{response(cachedTokens(80), false), response(nil, false)},
			want:    "cached input tokens: >= 80 (lower bound; reported exact by 1, partial by 0, not reported by 1)",
		},
		{
			name:    "an explicitly partial value makes the total a lower bound",
			records: []sessions.Record{response(cachedTokens(80), true)},
			want:    "cached input tokens: >= 80 (lower bound; reported exact by 0, partial by 1, not reported by 0)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runSummary(t, writeSession(t, "cached", tt.records))
			if !strings.Contains(out, tt.want) {
				t.Fatalf("summary output missing %q:\n%s", tt.want, out)
			}
		})
	}
}

func TestSessionsSummary_CostAvailability(t *testing.T) {
	response := func(cost *float64, partial bool) sessions.Record {
		return eventRecord(events.KindModelResponse, events.ModelResponse{
			Provider: "openrouter", ModelID: "m", InputTokens: 10, OutputTokens: 5,
			CostUSD: cost, CostUSDPartial: partial, Anomaly: []string{},
		})
	}
	usd := func(v float64) *float64 { return &v }

	tests := []struct {
		name         string
		records      []sessions.Record
		wantText     string
		availability string
		wantUSD      *float64
		counts       [3]int
	}{
		{
			name:         "no model responses",
			records:      []sessions.Record{textMsg("user", "hello")},
			wantText:     "  cost (provider-reported, USD): unavailable (no model_response reported cost)",
			availability: "unavailable",
		},
		{
			name:         "no response reports cost",
			records:      []sessions.Record{response(nil, false), response(nil, false)},
			wantText:     "  cost (provider-reported, USD): unavailable (no model_response reported cost)",
			availability: "unavailable",
			counts:       [3]int{0, 0, 2},
		},
		{
			name:         "every response reports a cost",
			records:      []sessions.Record{response(usd(0.25), false), response(usd(0.5), false)},
			wantText:     "  cost (provider-reported, USD): 0.75 (exact; every one of the 2 recorded responses reported a non-partial cost)",
			availability: "exact",
			wantUSD:      usd(0.75),
			counts:       [3]int{2, 0, 0},
		},
		{
			name:         "a reported zero stays present",
			records:      []sessions.Record{response(usd(0), false)},
			wantText:     "  cost (provider-reported, USD): 0 (exact; every one of the 1 recorded responses reported a non-partial cost)",
			availability: "exact",
			wantUSD:      usd(0),
			counts:       [3]int{1, 0, 0},
		},
		{
			name:         "one omitted cost makes the total a lower bound",
			records:      []sessions.Record{response(usd(0.25), false), response(nil, false)},
			wantText:     "  cost (provider-reported, USD): >= 0.25 (lower bound; of the recorded responses, reported exact by 1, partial by 0, not reported by 1)",
			availability: "lower_bound",
			wantUSD:      usd(0.25),
			counts:       [3]int{1, 0, 1},
		},
		{
			name:         "a partial cost makes the total a lower bound",
			records:      []sessions.Record{response(usd(0.25), true)},
			wantText:     "  cost (provider-reported, USD): >= 0.25 (lower bound; of the recorded responses, reported exact by 0, partial by 1, not reported by 0)",
			availability: "lower_bound",
			wantUSD:      usd(0.25),
			counts:       [3]int{0, 1, 0},
		},
		{
			name:         "an overflowing addition is skipped and counted partial",
			records:      []sessions.Record{response(usd(1.7e308), false), response(usd(1.7e308), false)},
			wantText:     "  cost (provider-reported, USD): >= 1.7e+308 (lower bound; of the recorded responses, reported exact by 1, partial by 1, not reported by 0)",
			availability: "lower_bound",
			wantUSD:      usd(1.7e308),
			counts:       [3]int{1, 1, 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeSession(t, "cost", tt.records)
			if out := runSummary(t, path); !strings.Contains(out, tt.wantText) {
				t.Fatalf("summary output missing %q:\n%s", tt.wantText, out)
			}
			c := summaryJSONOf(t, path).Totals.CostUSD
			gotCounts := [3]int{c.ReportedResponses, c.PartialResponses, c.OmittedResponses}
			if c.Availability != tt.availability || gotCounts != tt.counts {
				t.Fatalf("cost_usd = %+v, want availability %q counts %v", c, tt.availability, tt.counts)
			}
			if (c.USD == nil) != (tt.wantUSD == nil) || (c.USD != nil && *c.USD != *tt.wantUSD) {
				t.Fatalf("cost_usd.usd = %v, want %v", c.USD, tt.wantUSD)
			}
		})
	}
}

func TestSessionsSummary_SparseValidSession(t *testing.T) {
	path := writeSession(t, "sparse", []sessions.Record{
		textMsg("user", "hello"),
		textMsg("assistant", "hi"),
	})
	out := runSummary(t, path)

	for _, want := range []string{
		"shell and vcs execution records (tool_exec_end): 0 subjects, 0 invocations",
		"  (none)  invocations=0  failed=0  duration_ms=0",
		"  note: this session recorded no tool_exec_end records.",
		"allowlisted structured read execution records (structured_read_end): 0 tools, 0 invocations",
		"  note: this session recorded no structured_read_end records.",
		"permission path scopes (tool_exec_start and structured_read_start): 0 scopes, 0 starts",
		"  (none)  starts=0",
		"  note: this session recorded no tool_exec_start or structured_read_start records.",
		"  identified turns: 0",
		"  identified rounds: 0 (terminated: 0, incomplete: 0)",
		"  provider round trips: 0 (legacy, without turn/round ids: 0)",
		"  provider wall time: 0 ms",
		"  provider/model pairs: none recorded",
		"  model responses: 0",
		"  input tokens: 0",
		"  output tokens: 0",
		"  cached input tokens: unavailable (no model_response reported cached usage)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("sparse summary missing %q:\n%s", want, out)
		}
	}

	report := summaryJSONOf(t, path)
	if report.ShellExec == nil || report.StructuredReads == nil || report.PathScopes == nil {
		t.Fatalf("an empty section must serialize as [] rather than null: %s", runSummary(t, path, "--json"))
	}
	if len(report.ShellExec) != 0 || len(report.StructuredReads) != 0 || len(report.PathScopes) != 0 {
		t.Fatalf("sparse report is not empty: %+v", report)
	}
	if report.Totals.ProviderModels == nil {
		t.Fatalf("provider_models must serialize as [] rather than null: %s", runSummary(t, path, "--json"))
	}
}

func TestSessionsSummary_ReadsWithoutWriting(t *testing.T) {
	before, err := os.ReadFile(summaryFixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	dirBefore, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	runSummary(t, summaryFixturePath)
	runSummary(t, summaryFixturePath, "--json")

	after, err := os.ReadFile(summaryFixturePath)
	if err != nil {
		t.Fatalf("re-read fixture: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("summary modified the session file")
	}
	dirAfter, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("re-read testdata: %v", err)
	}
	if len(dirBefore) != len(dirAfter) {
		t.Fatalf("summary left a sidecar: %d entries before, %d after", len(dirBefore), len(dirAfter))
	}
}

func TestSessionsSummary_UsageErrors(t *testing.T) {
	runUsageErrorCases(t, []usageErrorCase{
		{"summary no target", []string{"codemeld", "sessions", "summary"}, "sessions summary requires a session id or file path"},
		{
			"summary two targets",
			[]string{"codemeld", "sessions", "summary", "a.json", "b.json"},
			"accepts exactly one session id or file path",
		},
		{"summary unreadable target", []string{"codemeld", "sessions", "summary", "testdata/does-not-exist.json"}, "does-not-exist.json"},
		{
			"summary is named when the subcommand is missing",
			[]string{"codemeld", "sessions"},
			"'codemeld sessions summary'",
		},
		{
			"summary is named when the subcommand is unknown",
			[]string{"codemeld", "sessions", "bogus"},
			"'codemeld sessions summary'",
		},
	})
}

func TestSessionsSummaryHelp(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"sessions summary -h", []string{"codemeld", "sessions", "summary", "-h"}},
		{"sessions summary --help", []string{"codemeld", "sessions", "summary", "--help"}},
		{"help sessions summary", []string{"codemeld", "help", "sessions", "summary"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubNoLaunch(t)
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), tt.args, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			out := stdout.String()
			for _, want := range []string{
				"codemeld sessions summary <session-id|path> [--json]",
				"--json",
				"execution-record summary, not a complete",
				"records no durable start/end pair at all",
				"A session does NOT record which files",
				"never as 'these files changed'",
				"exceed the matching execution table's invocation count",
				"so terminated is not a success count",
				"reason=incomplete_round",
				"contributes only its duration and provider/model pair",
				"a lower bound when any",
				"unavailable when none reported it",
				"Provider-reported cost (cost_usd) is summed and reported the same way, scoped to",
				"Cost is assumed to be USD, following OpenRouter's convention;",
				"nor converted.",
				"current execution capability",
				"refused with its refusal",
				"reason, or not recorded",
				"constrained means the startup sandbox check passed, so plan and auto-edits shell",
				"commands could run sandboxed with fewer prompts; refused carries the reason they",
				"could not. A refusal for a broken settings file after a passed check still kept plan",
				"and auto-edits commands sandboxed but made every command ask; a failed or unsupported",
				"check ran them outside the sandbox with ordinary prompts. Neither value describes",
				"build mode, which always runs commands outside the sandbox.",
				"The approval_* totals measure time spent waiting on permission prompts",
				"so overlapping waits are counted once, not summed.",
				"count of questions shown, since one question can cover several requests.",
				"totals and have no separate failure count, so a wait that was not cancelled was",
			} {
				if !strings.Contains(out, want) {
					t.Fatalf("summary help missing %q:\n%s", want, out)
				}
			}
		})
	}
}

func TestSessionsSummary_ExecutionCapability(t *testing.T) {
	refused := eventRecord(events.KindExecutionCapability, events.ExecutionCapability{
		Capability: "refused", Reason: "linux: not yet supported",
	})
	constrained := eventRecord(events.KindExecutionCapability, events.ExecutionCapability{
		Capability: "constrained",
		Legs:       []events.ExecutionCapabilityLeg{{Name: "write_outside_root", Observed: "denied"}},
	})
	tests := []struct {
		name     string
		records  []sessions.Record
		wantLine string
		wantJSON string
	}{
		{"refused", []sessions.Record{refused}, "Execution: refused (linux: not yet supported)",
			`{"capability":"refused","reason":"linux: not yet supported"}`},
		{"last event wins", []sessions.Record{refused, constrained}, "Execution: constrained",
			`{"capability":"constrained"}`},
		{"not recorded", []sessions.Record{textMsg("user", "hello")}, "Execution: not recorded", `null`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeSession(t, "execution", tt.records)
			if out := runSummary(t, path); !strings.Contains(out, "folder: /some/folder\n"+tt.wantLine+"\n") {
				t.Fatalf("summary missing %q after the folder line:\n%s", tt.wantLine, out)
			}
			var report struct {
				Execution json.RawMessage `json:"execution"`
			}
			if err := json.Unmarshal([]byte(runSummary(t, path, "--json")), &report); err != nil {
				t.Fatalf("summary --json is not one JSON document: %v", err)
			}
			var compact bytes.Buffer
			if err := json.Compact(&compact, report.Execution); err != nil {
				t.Fatalf("compact execution: %v", err)
			}
			if got := compact.String(); got != tt.wantJSON {
				t.Fatalf("execution = %s, want %s", got, tt.wantJSON)
			}
		})
	}
}

func promptWait(endMs, waitedMs int64, prompts int, ended string) sessions.Event {
	ev := eventRecord(events.KindPermissionPromptWait, events.PermissionPromptWait{
		WaitedMs: waitedMs, Prompts: prompts, Ended: ended,
	})
	ev.Timestamp = fixtureTime.Add(time.Duration(endMs) * time.Millisecond)
	return ev
}

func approvalTotals(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	var report struct {
		Totals map[string]json.RawMessage `json:"totals"`
	}
	if err := json.Unmarshal([]byte(runSummary(t, path, "--json")), &report); err != nil {
		t.Fatalf("summary --json is not one JSON document: %v", err)
	}
	return report.Totals
}

func TestSessionsSummary_ApprovalWaitIsTheUnionOfIntervals(t *testing.T) {
	path := writeSession(t, "waits", []sessions.Record{
		promptWait(1000, 200, 1, "cancelled"),
		promptWait(1200, 1000, 3, "answered"),
		promptWait(5000, 300, 2, "failed"),
	})

	totals := approvalTotals(t, path)
	for field, want := range map[string]string{
		"approval_wait_ms":         "1300",
		"approval_requests":        "6",
		"approval_waits_cancelled": "1",
	} {
		if got := string(totals[field]); got != want {
			t.Fatalf("%s = %s, want %s (totals=%v)", field, got, want, totals)
		}
	}

	out := runSummary(t, path)
	want := "  permission-prompt wait: 1300 ms across 6 requests (1 waits cancelled)\n"
	if !strings.Contains(out, want) {
		t.Fatalf("summary output missing %q:\n%s", want, out)
	}
	if !strings.Contains(out, "  cost (provider-reported, USD): unavailable (no model_response reported cost)\n"+want) {
		t.Fatalf("permission-prompt wait line is not right after the cost line:\n%s", out)
	}
}

func TestSessionsSummary_ZeroDurationWaitStillShowsTheLine(t *testing.T) {
	out := runSummary(t, writeSession(t, "zero-wait", []sessions.Record{
		promptWait(1000, 0, 1, "answered"),
	}))
	want := "  permission-prompt wait: 0 ms across 1 requests (0 waits cancelled)\n"
	if !strings.Contains(out, want) {
		t.Fatalf("summary output missing %q:\n%s", want, out)
	}
}

func TestSessionsSummary_NoWaitRecordsReportZeroAndNoLine(t *testing.T) {
	shown := eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
		SubjectKind: "tool", Subject: "Bash", PathScope: "/proj",
	})
	tests := []struct {
		name    string
		records []sessions.Record
	}{
		{"no permission records", []sessions.Record{textMsg("user", "hello")}},
		{"legacy prompt shown without waits", []sessions.Record{textMsg("user", "hello"), shown}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeSession(t, "no-waits", tt.records)
			totals := approvalTotals(t, path)
			for _, field := range []string{"approval_wait_ms", "approval_requests", "approval_waits_cancelled"} {
				if got := string(totals[field]); got != "0" {
					t.Fatalf("%s = %q, want 0 present (totals=%v)", field, got, totals)
				}
			}
			if out := runSummary(t, path); strings.Contains(out, "permission-prompt wait") {
				t.Fatalf("summary printed a permission-prompt wait line with no wait records:\n%s", out)
			}
		})
	}
}

func TestSessionsSummary_ApprovalWaitOutOfRangeIsAnError(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()
	wait := func(ts time.Time, waitedMs int64, prompts int) sessions.Record {
		ev := promptWait(0, waitedMs, prompts, "answered")
		ev.Timestamp = ts
		return ev
	}
	tests := []struct {
		name    string
		records []sessions.Record
	}{
		{"union and request sum overflow", []sessions.Record{
			wait(epoch, math.MaxInt64, math.MaxInt),
			wait(epoch.Add(time.Millisecond), math.MaxInt64, 1),
		}},
		{"union overflow only", []sessions.Record{
			wait(epoch, math.MaxInt64, 1),
			wait(epoch.Add(time.Millisecond), math.MaxInt64, 1),
		}},
		{"request sum overflow only", []sessions.Record{
			wait(epoch, 0, math.MaxInt),
			wait(epoch, 0, 1),
		}},
		{"interval start underflow", []sessions.Record{
			wait(epoch.Add(-2*time.Millisecond), math.MaxInt64, 1),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeSession(t, "overflow", tt.records)
			for _, extra := range [][]string{nil, {"--json"}} {
				var stdout, stderr bytes.Buffer
				args := append([]string{"codemeld", "sessions", "summary", path}, extra...)
				if code := Run(context.Background(), args, &stdout, &stderr); code != 1 {
					t.Fatalf("%v: exit = %d, want 1 (stdout=%q stderr=%q)", extra, code, stdout.String(), stderr.String())
				}
				if !strings.Contains(stderr.String(), "permission-prompt wait totals exceed the representable range") {
					t.Fatalf("%v: stderr = %q, want the range error", extra, stderr.String())
				}
				if stdout.Len() != 0 {
					t.Fatalf("%v: stdout = %q, want no report", extra, stdout.String())
				}
			}
		})
	}
}

func TestSessionsSummary_ApprovalWaitAtTheRangeLimitIsExact(t *testing.T) {
	ev := promptWait(0, math.MaxInt64, math.MaxInt, "answered")
	ev.Timestamp = time.Unix(0, 0).UTC().Add(-time.Millisecond)
	totals := approvalTotals(t, writeSession(t, "limit", []sessions.Record{ev}))
	for field, want := range map[string]string{
		"approval_wait_ms":  strconv.FormatInt(math.MaxInt64, 10),
		"approval_requests": strconv.Itoa(math.MaxInt),
	} {
		if got := string(totals[field]); got != want {
			t.Fatalf("%s = %s, want %s (totals=%v)", field, got, want, totals)
		}
	}
}
