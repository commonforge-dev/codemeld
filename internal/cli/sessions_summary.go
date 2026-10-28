package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"

	ucli "github.com/urfave/cli/v3"
)

const (
	cachedUnavailable = "unavailable"
	cachedExact       = "exact"
	cachedLowerBound  = "lower_bound"
)

const structuredReadSuccess = "success"

const promptWaitCancelled = "cancelled"

type shellExecRow struct {
	SubjectKind string `json:"subject_kind"`
	Subject     string `json:"subject"`
	Invocations int    `json:"invocations"`
	Failures    int    `json:"failures"`
	DurationMs  int64  `json:"duration_ms"`
}

type outcomeCount struct {
	Outcome string `json:"outcome"`
	Count   int    `json:"count"`
}

type structuredReadRow struct {
	ToolName    string         `json:"tool_name"`
	Invocations int            `json:"invocations"`
	NonSuccess  int            `json:"non_success"`
	Outcomes    []outcomeCount `json:"outcomes"`
	DurationMs  int64          `json:"duration_ms"`
}

type pathScopeRow struct {
	PathScope string   `json:"path_scope"`
	Starts    int      `json:"starts"`
	UsedBy    []string `json:"used_by"`
}

type providerModelPair struct {
	Provider string `json:"provider"`
	ModelID  string `json:"model_id"`
}

type cachedTokenTotal struct {
	Availability      string `json:"availability"`
	Tokens            *int64 `json:"tokens,omitempty"`
	ReportedResponses int    `json:"reported_responses"`
	PartialResponses  int    `json:"partial_responses"`
	OmittedResponses  int    `json:"omitted_responses"`
}

type costTotal struct {
	Availability      string   `json:"availability"`
	USD               *float64 `json:"usd,omitempty"`
	ReportedResponses int      `json:"reported_responses"`
	PartialResponses  int      `json:"partial_responses"`
	OmittedResponses  int      `json:"omitted_responses"`
}

type summaryTotals struct {
	IdentifiedTurns   int                 `json:"identified_turns"`
	IdentifiedRounds  int                 `json:"identified_rounds"`
	TerminatedRounds  int                 `json:"terminated_rounds"`
	IncompleteRounds  int                 `json:"incomplete_rounds"`
	RoundTrips        int                 `json:"round_trips"`
	LegacyRoundTrips  int                 `json:"legacy_round_trips"`
	ProviderWallMs    int64               `json:"provider_wall_ms"`
	ProviderModels    []providerModelPair `json:"provider_models"`
	ModelResponses    int                 `json:"model_responses"`
	InputTokens       int64               `json:"input_tokens"`
	OutputTokens      int64               `json:"output_tokens"`
	CachedInputTokens cachedTokenTotal    `json:"cached_input_tokens"`
	CostUSD           costTotal           `json:"cost_usd"`

	ApprovalWaitMs         int64 `json:"approval_wait_ms"`
	ApprovalRequests       int   `json:"approval_requests"`
	ApprovalWaitsCancelled int   `json:"approval_waits_cancelled"`
	approvalWaitEvents     int
}

type executionRow struct {
	Capability string `json:"capability"`
	Reason     string `json:"reason,omitempty"`
}

type summaryReport struct {
	Session         string              `json:"session"`
	Folder          string              `json:"folder"`
	Execution       *executionRow       `json:"execution"`
	ShellExec       []shellExecRow      `json:"shell_exec"`
	StructuredReads []structuredReadRow `json:"structured_reads"`
	PathScopes      []pathScopeRow      `json:"path_scopes"`
	Totals          summaryTotals       `json:"totals"`
}

type waitInterval struct {
	start, end int64
}

type execKey struct {
	subjectKind string
	subject     string
}

type shellExecAgg struct {
	invocations int
	failures    int
	durationMs  int64
}

type structuredReadAgg struct {
	invocations int
	nonSuccess  int
	durationMs  int64
	outcomes    map[string]int
}

type pathScopeAgg struct {
	starts int
	usedBy map[string]bool
}

type cachedAccumulator struct {
	tokens   int64
	reported int
	partial  int
	omitted  int
}

func (c *cachedAccumulator) add(p events.ModelResponse) {
	if p.CachedInputTokens == nil {
		c.omitted++
		return
	}
	c.tokens += *p.CachedInputTokens
	if p.CachedInputTokensPartial {
		c.partial++
		return
	}
	c.reported++
}

func (c *cachedAccumulator) total() cachedTokenTotal {
	t := cachedTokenTotal{
		ReportedResponses: c.reported,
		PartialResponses:  c.partial,
		OmittedResponses:  c.omitted,
	}
	if c.reported == 0 && c.partial == 0 {
		t.Availability = cachedUnavailable
		return t
	}
	tokens := c.tokens
	t.Tokens = &tokens
	if c.partial == 0 && c.omitted == 0 {
		t.Availability = cachedExact
		return t
	}
	t.Availability = cachedLowerBound
	return t
}

type costAccumulator struct {
	usd      float64
	reported int
	partial  int
	omitted  int
}

func (c *costAccumulator) add(p events.ModelResponse) {
	if p.CostUSD == nil {
		c.omitted++
		return
	}
	if math.IsInf(c.usd+*p.CostUSD, 0) {
		c.partial++
		return
	}
	c.usd += *p.CostUSD
	if p.CostUSDPartial {
		c.partial++
		return
	}
	c.reported++
}

func (c *costAccumulator) total() costTotal {
	t := costTotal{
		ReportedResponses: c.reported,
		PartialResponses:  c.partial,
		OmittedResponses:  c.omitted,
	}
	if c.reported == 0 && c.partial == 0 {
		t.Availability = cachedUnavailable
		return t
	}
	usd := c.usd
	t.USD = &usd
	if c.partial == 0 && c.omitted == 0 {
		t.Availability = cachedExact
		return t
	}
	t.Availability = cachedLowerBound
	return t
}

func runSessionsSummary(args []string, asJSON bool, stdout io.Writer) error {
	target, err := singleTarget(args, "summary")
	if err != nil {
		return err
	}
	path, sess, err := resolveSession(target)
	if err != nil {
		return err
	}
	report, err := buildSummaryReport(path, sess)
	if err != nil {
		return ucli.Exit(fmt.Sprintf("codemeld: sessions summary: %s: %s", path, err), 1)
	}
	if asJSON {
		return renderJSON(stdout, report)
	}
	renderSummaryHuman(stdout, report)
	return nil
}

func buildSummaryReport(path string, sess *sessions.Session) (summaryReport, error) {
	shell := map[execKey]*shellExecAgg{}
	reads := map[string]*structuredReadAgg{}
	scopes := map[string]*pathScopeAgg{}
	pairs := map[providerModelPair]bool{}
	turnIDs := map[string]bool{}
	roundIDs := map[roundKey]bool{}
	cached := &cachedAccumulator{}
	cost := &costAccumulator{}
	totals := summaryTotals{}
	var execution *executionRow
	var waits []waitInterval

	for _, rec := range sess.Records {
		ev, ok := rec.(sessions.Event)
		if !ok {
			continue
		}
		switch ev.Kind {
		case events.KindToolExecEnd:
			var p events.ToolExecEnd
			if json.Unmarshal(ev.Payload, &p) != nil {
				continue
			}
			key := execKey{p.SubjectKind, p.Subject}
			agg := shell[key]
			if agg == nil {
				agg = &shellExecAgg{}
				shell[key] = agg
			}
			agg.invocations++
			agg.durationMs += p.DurationMs
			if p.ExitCode != 0 {
				agg.failures++
			}
		case events.KindStructuredReadEnd:
			var p events.StructuredReadEnd
			if json.Unmarshal(ev.Payload, &p) != nil {
				continue
			}
			agg := reads[p.ToolName]
			if agg == nil {
				agg = &structuredReadAgg{outcomes: map[string]int{}}
				reads[p.ToolName] = agg
			}
			agg.invocations++
			agg.durationMs += p.DurationMs
			agg.outcomes[p.Outcome]++
			if p.Outcome != structuredReadSuccess {
				agg.nonSuccess++
			}
		case events.KindToolExecStart:
			var p events.ToolExecStart
			if json.Unmarshal(ev.Payload, &p) != nil {
				continue
			}
			addScopeStart(scopes, p.PathScope, p.Subject)
		case events.KindStructuredReadStart:
			var p events.StructuredReadStart
			if json.Unmarshal(ev.Payload, &p) != nil {
				continue
			}
			addScopeStart(scopes, p.PathScope, p.ToolName)
		case events.KindProviderRoundTrip:
			var p events.ProviderRoundTrip
			if json.Unmarshal(ev.Payload, &p) != nil {
				continue
			}
			totals.RoundTrips++
			totals.ProviderWallMs += p.DurationMs
			pairs[providerModelPair{p.Provider, p.ModelID}] = true
			if p.TurnID == "" || p.RoundID == "" {
				totals.LegacyRoundTrips++
				continue
			}
			turnIDs[p.TurnID] = true
			roundIDs[roundKey{p.TurnID, p.RoundID}] = true
		case events.KindTurnTerminal:
			var p events.TurnTerminal
			if json.Unmarshal(ev.Payload, &p) != nil {
				continue
			}
			if p.TurnID != "" {
				turnIDs[p.TurnID] = true
			}
		case events.KindModelResponse:
			var p events.ModelResponse
			if json.Unmarshal(ev.Payload, &p) != nil {
				continue
			}
			totals.ModelResponses++
			totals.InputTokens += p.InputTokens
			totals.OutputTokens += p.OutputTokens
			pairs[providerModelPair{p.Provider, p.ModelID}] = true
			cached.add(p)
			cost.add(p)
		case events.KindExecutionCapability:
			var p events.ExecutionCapability
			if json.Unmarshal(ev.Payload, &p) != nil {
				continue
			}
			execution = &executionRow{Capability: p.Capability, Reason: p.Reason}
		case events.KindPermissionPromptWait:
			var p events.PermissionPromptWait
			if json.Unmarshal(ev.Payload, &p) != nil {
				continue
			}
			end := ev.Timestamp.UnixMilli()
			if end < math.MinInt64+p.WaitedMs {
				return summaryReport{}, errApprovalWaitRange
			}
			waits = append(waits, waitInterval{start: end - p.WaitedMs, end: end})
			if totals.ApprovalRequests > math.MaxInt-p.Prompts {
				return summaryReport{}, errApprovalWaitRange
			}
			totals.ApprovalRequests += p.Prompts
			if p.Ended == promptWaitCancelled {
				totals.ApprovalWaitsCancelled++
			}
		}
	}

	terminated := terminatedRounds(sess)
	for key := range roundIDs {
		if terminated[key] {
			totals.TerminatedRounds++
		}
	}
	totals.IdentifiedTurns = len(turnIDs)
	totals.IdentifiedRounds = len(roundIDs)
	totals.IncompleteRounds = totals.IdentifiedRounds - totals.TerminatedRounds
	totals.ProviderModels = sortedProviderModels(pairs)
	totals.CachedInputTokens = cached.total()
	totals.CostUSD = cost.total()
	waitMs, ok := unionMs(waits)
	if !ok {
		return summaryReport{}, errApprovalWaitRange
	}
	totals.ApprovalWaitMs = waitMs
	totals.approvalWaitEvents = len(waits)

	return summaryReport{
		Session:         path,
		Folder:          sess.Metadata.Folder,
		Execution:       execution,
		ShellExec:       shellExecRows(shell),
		StructuredReads: structuredReadRows(reads),
		PathScopes:      pathScopeRows(scopes),
		Totals:          totals,
	}, nil
}

var errApprovalWaitRange = errors.New("permission-prompt wait totals exceed the representable range")

func unionMs(spans []waitInterval) (int64, bool) {
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var total, covered int64
	for i, s := range spans {
		var add int64
		switch {
		case i == 0 || s.start > covered:
			add = s.end - s.start
		case s.end > covered:
			add = s.end - covered
		default:
			continue
		}
		if total > math.MaxInt64-add {
			return 0, false
		}
		total += add
		covered = s.end
	}
	return total, true
}

func addScopeStart(scopes map[string]*pathScopeAgg, scope, usedBy string) {
	agg := scopes[scope]
	if agg == nil {
		agg = &pathScopeAgg{usedBy: map[string]bool{}}
		scopes[scope] = agg
	}
	agg.starts++
	agg.usedBy[usedBy] = true
}

func shellExecRows(shell map[execKey]*shellExecAgg) []shellExecRow {
	rows := make([]shellExecRow, 0, len(shell))
	for key, agg := range shell {
		rows = append(rows, shellExecRow{
			SubjectKind: key.subjectKind,
			Subject:     key.subject,
			Invocations: agg.invocations,
			Failures:    agg.failures,
			DurationMs:  agg.durationMs,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Invocations != b.Invocations {
			return a.Invocations > b.Invocations
		}
		if a.SubjectKind != b.SubjectKind {
			return a.SubjectKind < b.SubjectKind
		}
		return a.Subject < b.Subject
	})
	return rows
}

func structuredReadRows(reads map[string]*structuredReadAgg) []structuredReadRow {
	rows := make([]structuredReadRow, 0, len(reads))
	for tool, agg := range reads {
		rows = append(rows, structuredReadRow{
			ToolName:    tool,
			Invocations: agg.invocations,
			NonSuccess:  agg.nonSuccess,
			Outcomes:    outcomeCounts(agg.outcomes),
			DurationMs:  agg.durationMs,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Invocations != b.Invocations {
			return a.Invocations > b.Invocations
		}
		return a.ToolName < b.ToolName
	})
	return rows
}

func outcomeCounts(counts map[string]int) []outcomeCount {
	out := make([]outcomeCount, 0, len(counts))
	for outcome, n := range counts {
		out = append(out, outcomeCount{Outcome: outcome, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Outcome < out[j].Outcome
	})
	return out
}

func pathScopeRows(scopes map[string]*pathScopeAgg) []pathScopeRow {
	rows := make([]pathScopeRow, 0, len(scopes))
	for scope, agg := range scopes {
		usedBy := make([]string, 0, len(agg.usedBy))
		for s := range agg.usedBy {
			usedBy = append(usedBy, s)
		}
		sort.Strings(usedBy)
		rows = append(rows, pathScopeRow{PathScope: scope, Starts: agg.starts, UsedBy: usedBy})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Starts != rows[j].Starts {
			return rows[i].Starts > rows[j].Starts
		}
		return rows[i].PathScope < rows[j].PathScope
	})
	return rows
}

func sortedProviderModels(pairs map[providerModelPair]bool) []providerModelPair {
	out := make([]providerModelPair, 0, len(pairs))
	for p := range pairs {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].ModelID < out[j].ModelID
	})
	return out
}

func renderSummaryHuman(w io.Writer, r summaryReport) {
	fmt.Fprintf(w, "session: %s\n", r.Session)
	fmt.Fprintf(w, "folder: %s\n", r.Folder)
	fmt.Fprintf(w, "Execution: %s\n", formatExecution(r.Execution))
	renderShellExec(w, r.ShellExec)
	renderStructuredReads(w, r.StructuredReads)
	fmt.Fprintln(w, "\nother structured tool calls record no durable start/end pair, so they are absent from both")
	fmt.Fprintln(w, "tables rather than counted as zero.")
	renderPathScopes(w, r.PathScopes)
	renderSummaryTotals(w, r.Totals)
}

func formatExecution(e *executionRow) string {
	if e == nil {
		return "not recorded"
	}
	if e.Reason != "" {
		return fmt.Sprintf("%s (%s)", e.Capability, e.Reason)
	}
	return e.Capability
}

func renderShellExec(w io.Writer, rows []shellExecRow) {
	invocations, failures, duration := 0, 0, int64(0)
	for _, row := range rows {
		invocations += row.Invocations
		failures += row.Failures
		duration += row.DurationMs
	}
	fmt.Fprintf(w, "\nshell and vcs execution records (tool_exec_end): %d subjects, %d invocations\n", len(rows), invocations)
	if len(rows) == 0 {
		fmt.Fprintln(w, "  (none)  invocations=0  failed=0  duration_ms=0")
		fmt.Fprintln(w, "  note: this session recorded no tool_exec_end records.")
		return
	}
	for i, row := range rows {
		fmt.Fprintf(w, "  %d. %s  %s  invocations=%d  failed=%d  duration_ms=%d\n",
			i+1, row.SubjectKind, row.Subject, row.Invocations, row.Failures, row.DurationMs)
	}
	fmt.Fprintf(w, "  totals: invocations=%d  failed=%d  duration_ms=%d (failed means a non-zero exit code)\n",
		invocations, failures, duration)
}

func renderStructuredReads(w io.Writer, rows []structuredReadRow) {
	invocations, nonSuccess, duration := 0, 0, int64(0)
	for _, row := range rows {
		invocations += row.Invocations
		nonSuccess += row.NonSuccess
		duration += row.DurationMs
	}
	fmt.Fprintf(w, "\nallowlisted structured read execution records (structured_read_end): %d tools, %d invocations\n",
		len(rows), invocations)
	if len(rows) == 0 {
		fmt.Fprintln(w, "  (none)  invocations=0  non_success=0  duration_ms=0")
		fmt.Fprintln(w, "  note: this session recorded no structured_read_end records.")
		return
	}
	for i, row := range rows {
		fmt.Fprintf(w, "  %d. %s  invocations=%d  non_success=%d  outcomes=%s  duration_ms=%d\n",
			i+1, row.ToolName, row.Invocations, row.NonSuccess, formatOutcomes(row.Outcomes), row.DurationMs)
	}
	fmt.Fprintf(w, "  totals: invocations=%d  non_success=%d  duration_ms=%d (a read records a closed outcome, never an exit code)\n",
		invocations, nonSuccess, duration)
}

func formatOutcomes(outcomes []outcomeCount) string {
	parts := make([]string, 0, len(outcomes))
	for _, o := range outcomes {
		parts = append(parts, fmt.Sprintf("%s:%d", o.Outcome, o.Count))
	}
	return strings.Join(parts, ",")
}

func renderPathScopes(w io.Writer, rows []pathScopeRow) {
	starts := 0
	for _, row := range rows {
		starts += row.Starts
	}
	fmt.Fprintf(w, "\npermission path scopes (tool_exec_start and structured_read_start): %d scopes, %d starts\n",
		len(rows), starts)
	fmt.Fprintln(w, "these are the directory scopes those execution records were authorized against, not the files")
	fmt.Fprintln(w, "the session changed: a session records no edited-file list.")
	if len(rows) == 0 {
		fmt.Fprintln(w, "  (none)  starts=0")
		fmt.Fprintln(w, "  note: this session recorded no tool_exec_start or structured_read_start records.")
		return
	}
	for i, row := range rows {
		fmt.Fprintf(w, "  %d. %s  starts=%d  used_by=%s\n", i+1, row.PathScope, row.Starts, strings.Join(row.UsedBy, ","))
	}
	fmt.Fprintln(w, "  a scope's start count can exceed the matching table's invocation count: the start is recorded")
	fmt.Fprintln(w, "  before the call runs, so a process that stopped mid-call leaves a start with no end.")
}

func renderSummaryTotals(w io.Writer, t summaryTotals) {
	fmt.Fprintln(w, "\ntotals:")
	fmt.Fprintf(w, "  identified turns: %d\n", t.IdentifiedTurns)
	fmt.Fprintf(w, "  identified rounds: %d (terminated: %d, incomplete: %d)\n",
		t.IdentifiedRounds, t.TerminatedRounds, t.IncompleteRounds)
	fmt.Fprintf(w, "  provider round trips: %d (legacy, without turn/round ids: %d)\n", t.RoundTrips, t.LegacyRoundTrips)
	fmt.Fprintf(w, "  provider wall time: %d ms\n", t.ProviderWallMs)
	fmt.Fprintf(w, "  provider/model pairs: %s\n", formatProviderModels(t.ProviderModels))
	fmt.Fprintf(w, "  model responses: %d\n", t.ModelResponses)
	fmt.Fprintf(w, "  input tokens: %d\n", t.InputTokens)
	fmt.Fprintf(w, "  output tokens: %d\n", t.OutputTokens)
	fmt.Fprintf(w, "  cached input tokens: %s\n", formatCached(t.CachedInputTokens))
	fmt.Fprintf(w, "  cost (provider-reported, USD): %s\n", formatCost(t.CostUSD))
	if t.approvalWaitEvents > 0 {
		fmt.Fprintf(w, "  permission-prompt wait: %d ms across %d requests (%d waits cancelled)\n",
			t.ApprovalWaitMs, t.ApprovalRequests, t.ApprovalWaitsCancelled)
	}
	fmt.Fprintln(w, "\na terminated round is one a turn_terminal closed, whatever that outcome was — a cancelled or")
	fmt.Fprintln(w, "provider-failed round is terminated too, so closure is not success. An incomplete round recorded")
	fmt.Fprintln(w, "its timing and never recorded how it ended; sessions doctor reports the same rounds as")
	fmt.Fprintln(w, "reason=incomplete_round. Legacy round trips carrying neither id are counted in neither, and")
	fmt.Fprintln(w, "contribute only their duration and provider/model pair.")
}

func formatProviderModels(pairs []providerModelPair) string {
	if len(pairs) == 0 {
		return "none recorded"
	}
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, p.Provider+"/"+p.ModelID)
	}
	return strings.Join(parts, ", ")
}

func formatCached(c cachedTokenTotal) string {
	switch c.Availability {
	case cachedUnavailable:
		return "unavailable (no model_response reported cached usage)"
	case cachedExact:
		return fmt.Sprintf("%d (exact; every one of the %d responses reported a value)", *c.Tokens, c.ReportedResponses)
	default:
		return fmt.Sprintf(">= %d (lower bound; reported exact by %d, partial by %d, not reported by %d)",
			*c.Tokens, c.ReportedResponses, c.PartialResponses, c.OmittedResponses)
	}
}

func formatCost(c costTotal) string {
	switch c.Availability {
	case cachedUnavailable:
		return "unavailable (no model_response reported cost)"
	case cachedExact:
		return fmt.Sprintf("%s (exact; every one of the %d recorded responses reported a non-partial cost)",
			strconv.FormatFloat(*c.USD, 'g', -1, 64), c.ReportedResponses)
	default:
		return fmt.Sprintf(">= %s (lower bound; of the recorded responses, reported exact by %d, partial by %d, not reported by %d)",
			strconv.FormatFloat(*c.USD, 'g', -1, 64), c.ReportedResponses, c.PartialResponses, c.OmittedResponses)
	}
}
