// Tests for the read-only `codemeld sessions` doctor/show diagnostics command:
// fixture-based reporting, id/path resolution, load-error surfacing, JSON output,
// and help output, all driven through the real root command.
package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/sessions"
)

// fixtureTime is the canonical timestamp stamped on every fixture record.
var fixtureTime = time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)

func ptrInt64(v int64) *int64 { return &v }

// rawFn / rawToolCall mirror the persisted tool-call entry shape
// {"id","type":"function","function":{"name","arguments"}} so a fixture can carry
// a verbatim escaped arguments string exactly as production stores it.
type rawFn struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}
type rawToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function rawFn  `json:"function"`
}

func toolCallRaw(id, name, args string) json.RawMessage {
	b, _ := json.Marshal(rawToolCall{ID: id, Type: "function", Function: rawFn{Name: name, Arguments: args}})
	return b
}

func textMsg(role, content string) sessions.Message {
	return sessions.Message{ID: ids.NewV7(), Role: role, Content: sessions.TextContent(content), Timestamp: fixtureTime}
}

func toolMsg(callID, content string) sessions.Message {
	return sessions.Message{
		ID: ids.NewV7(), Role: "tool", Content: sessions.TextContent(content),
		Timestamp: fixtureTime, ToolCallID: callID,
	}
}

func asstToolCall(id, name, args string) sessions.Message {
	return sessions.Message{
		ID: ids.NewV7(), Role: "assistant", Content: sessions.TextContent(""), Timestamp: fixtureTime,
		ToolCalls: []sessions.ToolCall{{ID: id, Type: "function", Raw: toolCallRaw(id, name, args)}},
	}
}

// asstToolCallFunction carries a verbatim `function` object so a fixture can
// persist arguments the contract's escaped-string form cannot express.
func asstToolCallFunction(id, function string) sessions.Message {
	return sessions.Message{
		ID: ids.NewV7(), Role: "assistant", Content: sessions.TextContent(""), Timestamp: fixtureTime,
		ToolCalls: []sessions.ToolCall{{
			ID: id, Type: "function",
			Raw: json.RawMessage(`{"id":"` + id + `","type":"function","function":` + function + `}`),
		}},
	}
}

func eventRecord(kind string, payload any) sessions.Event {
	b, _ := json.Marshal(payload)
	return sessions.Event{ID: ids.NewV7(), Kind: kind, Timestamp: fixtureTime, Payload: b}
}

// buildFixtureSession assembles a session carrying one of every error/anomaly kind
// the doctor reports (plus a zero-exit tool_exec_end and a successful slash_command
// that must NOT be findings), and two assistant tool calls: one with valid JSON
// arguments and one with malformed arguments for the show command. It passes both
// the record-stream validation and per-kind payload validation.
func buildFixtureSession(folder string) *sessions.Session {
	io := string(fserrors.IOError)
	records := []sessions.Record{
		textMsg("user", "summarize the file"),
		asstToolCall("call_1", "read_file", `{"path":"/etc/hosts"}`),
		toolMsg("call_1", "127.0.0.1 localhost"),
		asstToolCall("call_2", "write_file", `{not valid json`),
		toolMsg("call_2", "ok"),

		// errors
		eventRecord(events.KindProviderRequestFailed, events.ProviderRequestFailed{
			Provider: "openai", ModelID: "gpt-5.5", Phase: "http", Reason: "http_error",
			HTTPStatus: ptrInt64(500), ErrorDetail: "bad gateway",
		}),
		eventRecord(events.KindSessionWriteFailed, events.SessionWriteFailed{
			TargetPath: "/var/data/session.json", Reason: "write_error", ErrorCategory: io, ErrorDetail: "disk error",
		}),
		eventRecord(events.KindPermissionPersistFailed, events.PermissionPersistFailed{
			TargetPath: "/var/data/settings.yaml", GrantKind: "folder", SubjectKind: "tool",
			Subject: "Bash", Reason: "write_error", ErrorCategory: io, ErrorDetail: "perm write failed",
		}),
		eventRecord(events.KindModelRecoveryFailed, events.ModelRecoveryFailed{
			Reason: "validation_failed", ErrorDetail: "bad model state",
		}),
		eventRecord(events.KindModelPersistFailed, events.ModelPersistFailed{
			TargetPath: "/proj/.codemeld/model.yaml", Provider: "openai", ModelID: "gpt-5.5",
			Effort: "high", Reason: "write_error", ErrorCategory: io, ErrorDetail: "write failed",
		}),
		eventRecord(events.KindModelGlobalMirrorFailed, events.ModelGlobalMirrorFailed{
			TargetPath: "/home/u/.codemeld/global/model.yaml", Provider: "openai", ModelID: "gpt-5.5",
			Effort: "high", Reason: "write_error", ErrorCategory: io, ErrorDetail: "mirror failed",
		}),
		eventRecord(events.KindToolExecEnd, events.ToolExecEnd{
			SubjectKind: "tool", Subject: "Bash", ExitCode: 1, DurationMs: 5, InvocationID: ids.NewV7(),
		}),

		// not a finding: zero-exit tool_exec_end
		eventRecord(events.KindToolExecEnd, events.ToolExecEnd{
			SubjectKind: "tool", Subject: "Bash", ExitCode: 0, DurationMs: 3, InvocationID: ids.NewV7(),
		}),

		// warnings
		eventRecord(events.KindModelEffortUnsupported, events.ModelEffortUnsupported{
			Provider: "openai", ModelID: "gpt-5.5", ConfiguredEffort: "high",
		}),
		eventRecord(events.KindModelResponse, events.ModelResponse{
			Provider: "openai", ModelID: "gpt-5.5", InputTokens: 10, OutputTokens: 5, Anomaly: []string{"usage_missing"},
		}),
		eventRecord(events.KindSlashCommand, events.SlashCommand{
			Name: "resume", Args: []string{"01abc"}, Outcome: "error", ErrorDetail: "no such session",
		}),

		// not a finding: successful slash_command
		eventRecord(events.KindSlashCommand, events.SlashCommand{
			Name: "help", Args: []string{}, Outcome: "success",
		}),

		// info
		eventRecord(events.KindStreamInterrupted, events.StreamInterrupted{Source: "esc", ContentChars: 12}),
	}
	return &sessions.Session{
		Metadata: sessions.Metadata{
			ID: ids.NewV7(), Folder: folder, StartedAt: fixtureTime, UpdatedAt: fixtureTime, SchemaVersion: 1,
		},
		Records: records,
	}
}

func writeFixture(t *testing.T, path, folder string) {
	t.Helper()
	writeFixtureSession(t, path, buildFixtureSession(folder))
}

func writeFixtureSession(t *testing.T, path string, sess *sessions.Session) {
	t.Helper()
	b, err := sessions.Marshal(sess)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

// stubHomeAndCwd points the home and working-directory seams at fixed values so an
// id-based resolution test can stand up an isolated sessions tree without touching
// the real environment.
func stubHomeAndCwd(t *testing.T, home, cwd string) {
	t.Helper()
	prevHome, prevCwd := resolveHome, osGetwd
	resolveHome = func() (string, error) { return home, nil }
	osGetwd = func() (string, error) { return cwd, nil }
	t.Cleanup(func() { resolveHome, osGetwd = prevHome, prevCwd })
}

func TestSessionsDoctor_Path_ReportsAllFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.json")
	writeFixture(t, path, "/some/folder")

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "sessions", "doctor", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	out := stdout.String()

	for _, want := range []string{
		"findings: 11 (error: 7, warning: 3, info: 1)",
		"[error] provider_request_failed", "phase=http", "reason=http_error", "http_status=500",
		"[error] session_write_failed", "error_category=io_error",
		"[error] permission_persist_failed",
		"[error] model_recovery_failed",
		"[error] model_persist_failed",
		"[error] model_global_mirror_failed",
		"[error] tool_exec_end", "exit_code=1",
		"[warning] model_effort_unsupported",
		"[warning] model_response", "anomaly=usage_missing",
		"[warning] slash_command", `error_detail="no such session"`,
		"[info] stream_interrupted", "source=esc",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, out)
		}
	}
}

func TestSessionsDoctor_Path_JSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.json")
	writeFixture(t, path, "/some/folder")

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "sessions", "doctor", path, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}

	var report struct {
		Session  string `json:"session"`
		Findings []struct {
			Kind        string   `json:"kind"`
			Severity    string   `json:"severity"`
			Phase       string   `json:"phase"`
			HTTPStatus  *int64   `json:"http_status"`
			ExitCode    *int64   `json:"exit_code"`
			Anomalies   []string `json:"anomalies"`
			ErrorDetail string   `json:"error_detail"`
		} `json:"findings"`
		Summary struct {
			Error   int `json:"error"`
			Warning int `json:"warning"`
			Info    int `json:"info"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if report.Summary.Error != 7 || report.Summary.Warning != 3 || report.Summary.Info != 1 {
		t.Fatalf("summary = %+v, want error:7 warning:3 info:1", report.Summary)
	}
	if len(report.Findings) != 11 {
		t.Fatalf("findings = %d, want 11", len(report.Findings))
	}

	var sawProvider, sawToolExit, sawAnomaly bool
	for _, f := range report.Findings {
		switch f.Kind {
		case "provider_request_failed":
			sawProvider = true
			if f.Severity != "error" || f.HTTPStatus == nil || *f.HTTPStatus != 500 || f.Phase != "http" {
				t.Fatalf("provider finding = %+v", f)
			}
		case "tool_exec_end":
			sawToolExit = true
			if f.Severity != "error" || f.ExitCode == nil || *f.ExitCode != 1 {
				t.Fatalf("tool_exec_end finding = %+v", f)
			}
		case "model_response":
			sawAnomaly = true
			if f.Severity != "warning" || len(f.Anomalies) != 1 || f.Anomalies[0] != "usage_missing" {
				t.Fatalf("model_response finding = %+v", f)
			}
		}
	}
	if !sawProvider || !sawToolExit || !sawAnomaly {
		t.Fatalf("missing typed findings: provider=%v toolExit=%v anomaly=%v", sawProvider, sawToolExit, sawAnomaly)
	}
}

// Latency-event tolerance: a session carrying the additive turn_latency and
// provider_round_trip events loads cleanly, the doctor treats them as non-findings
// (healthy timing is not an error/warning/anomaly), and `show` surfaces them in the
// record stream. This pins the diagnostics command's "tolerates latency events" contract
// now that latency recording produces them.
func TestSessions_ToleratesAndSurfacesLatencyEvents(t *testing.T) {
	sess := &sessions.Session{
		Metadata: sessions.Metadata{
			ID: ids.NewV7(), Folder: "/some/folder", StartedAt: fixtureTime, UpdatedAt: fixtureTime, SchemaVersion: 1,
		},
		Records: []sessions.Record{
			textMsg("user", "hello"),
			textMsg("assistant", "hi there"),
			eventRecord(events.KindProviderRoundTrip, events.ProviderRoundTrip{Provider: "openai", ModelID: "gpt-5.5", DurationMs: 820}),
			eventRecord(events.KindTurnLatency, events.TurnLatency{Provider: "openai", ModelID: "gpt-5.5", DurationMs: 1500}),
		},
	}
	b, err := sessions.Marshal(sess)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// doctor: the session loads (exit 0) and neither latency event is a finding.
	var dOut, dErr bytes.Buffer
	if code := Run(context.Background(), []string{"codemeld", "sessions", "doctor", path}, &dOut, &dErr); code != 0 {
		t.Fatalf("doctor exit = %d, want 0 (stderr=%q)", code, dErr.String())
	}
	if got := dOut.String(); !strings.Contains(got, "no errors, failures, or anomalies found") {
		t.Fatalf("doctor classified a latency event as a finding:\n%s", got)
	}

	// show: the latency events are rendered (surfaced) in the record stream.
	var sOut, sErr bytes.Buffer
	if code := Run(context.Background(), []string{"codemeld", "sessions", "show", path}, &sOut, &sErr); code != 0 {
		t.Fatalf("show exit = %d, want 0 (stderr=%q)", code, sErr.String())
	}
	for _, want := range []string{"kind=turn_latency", "kind=provider_round_trip", `"duration_ms": 1500`, `"duration_ms": 820`} {
		if !strings.Contains(sOut.String(), want) {
			t.Fatalf("show output missing %q:\n%s", want, sOut.String())
		}
	}
}

func TestSessionsShow_ModelResponseUpstreamProvider(t *testing.T) {
	const upstream = "Groq\nkind=forged\r\tx"
	const escaped = `Groq\nkind=forged\r\tx`
	legacy := json.RawMessage(`{"provider":"openai","model_id":"gpt-5.5","input_tokens":1,"output_tokens":2,"anomaly":[]}`)
	path := writeSession(t, "upstream", []sessions.Record{
		textMsg("user", "hello"),
		textMsg("assistant", "hi there"),
		eventRecord(events.KindModelResponse, events.ModelResponse{Provider: "openrouter", ModelID: "m", Anomaly: []string{}, UpstreamProvider: upstream}),
		sessions.Event{ID: ids.NewV7(), Kind: events.KindModelResponse, Timestamp: fixtureTime, Payload: legacy},
	})

	var legacyPretty bytes.Buffer
	if err := json.Indent(&legacyPretty, legacy, "    ", "  "); err != nil {
		t.Fatalf("indent legacy payload: %v", err)
	}
	printed := runShow(t, path)
	if !strings.Contains(printed, `"upstream_provider": "`+escaped+`"`) {
		t.Fatalf("printed show lacks the escaped upstream_provider:\n%s", printed)
	}
	if !strings.Contains(printed, "    "+legacyPretty.String()) {
		t.Fatalf("printed show changed the legacy payload, want\n%s\ngot\n%s", legacyPretty.String(), printed)
	}

	report, out := showJSON(t, path)
	if !strings.Contains(out, escaped) {
		t.Fatalf("--json lacks the escaped upstream_provider:\n%s", out)
	}
	var payloads []json.RawMessage
	for _, e := range report.Entries {
		if e.Kind == events.KindModelResponse {
			payloads = append(payloads, e.Payload)
		}
	}
	if len(payloads) != 2 {
		t.Fatalf("model_response entries = %d, want 2", len(payloads))
	}
	var got events.ModelResponse
	if err := json.Unmarshal(payloads[0], &got); err != nil || got.UpstreamProvider != upstream {
		t.Fatalf("--json upstream_provider = %q (err %v), want %q", got.UpstreamProvider, err, upstream)
	}
	var legacyOut bytes.Buffer
	if err := json.Compact(&legacyOut, payloads[1]); err != nil || legacyOut.String() != string(legacy) {
		t.Fatalf("--json legacy payload = %s (err %v), want %s", payloads[1], err, legacy)
	}

	for name, s := range map[string]string{"printed": printed, "--json": out} {
		if strings.ContainsAny(s, "\r\t") || strings.Contains(s, "\nkind=forged") {
			t.Errorf("%s show emitted raw control characters from upstream_provider:\n%q", name, s)
		}
		if n := strings.Count(s, "upstream_provider"); n != 1 {
			t.Errorf("%s show has %d upstream_provider keys, want 1 (the legacy record has none)", name, n)
		}
	}
}

func roundTripEvent(turnID, roundID string) sessions.Event {
	return eventRecord(events.KindProviderRoundTrip, events.ProviderRoundTrip{
		Provider: "openai", ModelID: "gpt-5.5", DurationMs: 820, TurnID: turnID, RoundID: roundID,
	})
}

func terminalEvent(turnID, roundID, outcome, failurePhase string, dispatchStarted bool) sessions.Event {
	return eventRecord(events.KindTurnTerminal, events.TurnTerminal{
		TurnID: turnID, RoundID: roundID, Outcome: outcome,
		FailurePhase: failurePhase, DispatchStarted: dispatchStarted,
	})
}

func writeSession(t *testing.T, name string, records []sessions.Record) string {
	t.Helper()
	b, err := sessions.Marshal(&sessions.Session{
		Metadata: sessions.Metadata{
			ID: ids.NewV7(), Folder: "/some/folder", StartedAt: fixtureTime, UpdatedAt: fixtureTime, SchemaVersion: 1,
		},
		Records: records,
	})
	if err != nil {
		t.Fatalf("marshal %s fixture: %v", name, err)
	}
	path := filepath.Join(t.TempDir(), name+".json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s fixture: %v", name, err)
	}
	return path
}

func runDoctor(t *testing.T, target string, extra ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	args := append([]string{"codemeld", "sessions", "doctor", target}, extra...)
	if code := Run(context.Background(), args, &stdout, &stderr); code != 0 {
		t.Fatalf("doctor exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	return stdout.String()
}

type doctorFindings struct {
	Findings []struct {
		Kind           string `json:"kind"`
		Severity       string `json:"severity"`
		Reason         string `json:"reason"`
		Outcome        string `json:"outcome"`
		FailurePhase   string `json:"failure_phase"`
		FailureReason  string `json:"failure_reason"`
		FailedTool     string `json:"failed_tool"`
		TurnID         string `json:"turn_id"`
		RoundID        string `json:"round_id"`
		Path           string `json:"path"`
		DetectionPoint string `json:"detection_point"`
	} `json:"findings"`
	Summary struct {
		Error   int `json:"error"`
		Warning int `json:"warning"`
		Info    int `json:"info"`
	} `json:"summary"`
}

func doctorJSON(t *testing.T, target string) doctorFindings {
	t.Helper()
	var report doctorFindings
	out := runDoctor(t, target, "--json")
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	return report
}

func TestSessionsDoctor_TurnLifecycleFindings(t *testing.T) {
	turn := ids.NewV7()
	okRound, cancelledRound, failedRound, orphanRound := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	path := writeSession(t, "lifecycle", []sessions.Record{
		textMsg("user", "do the thing"),

		roundTripEvent(turn, okRound),
		terminalEvent(turn, okRound, events.TurnOutcomeCompleted, "", true),

		roundTripEvent(turn, cancelledRound),
		terminalEvent(turn, cancelledRound, events.TurnOutcomeCancelled, "", false),

		eventRecord(events.KindProviderRoundTrip, events.ProviderRoundTrip{
			Provider: "openai", ModelID: "gpt-5.5", DurationMs: 640,
		}),

		roundTripEvent(turn, failedRound),
		terminalEvent(turn, failedRound, events.TurnOutcomeProviderFailed, "stream_drop", false),

		roundTripEvent(turn, orphanRound),
	})

	out := runDoctor(t, path)
	for _, want := range []string{
		"findings: 2 (error: 2, warning: 0, info: 0)",
		"[error] turn_terminal",
		"outcome=provider_failed",
		"failure_phase=stream_drop",
		"turn_id=" + turn,
		"round_id=" + failedRound,
		"[error] provider_round_trip",
		"reason=incomplete_round",
		"round_id=" + orphanRound,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, out)
		}
	}
	for _, notWant := range []string{okRound, cancelledRound, "outcome=completed", "outcome=cancelled"} {
		if strings.Contains(out, notWant) {
			t.Fatalf("doctor reported a healthy round (%q):\n%s", notWant, out)
		}
	}

	report := doctorJSON(t, path)
	if report.Summary.Error != 2 || len(report.Findings) != 2 {
		t.Fatalf("JSON summary = %+v with %d findings, want 2 errors", report.Summary, len(report.Findings))
	}
	var sawTerminal, sawIncomplete bool
	for _, f := range report.Findings {
		switch f.Kind {
		case "turn_terminal":
			sawTerminal = true
			if f.Severity != "error" || f.Outcome != events.TurnOutcomeProviderFailed ||
				f.FailurePhase != "stream_drop" || f.TurnID != turn || f.RoundID != failedRound {
				t.Fatalf("turn_terminal finding = %+v", f)
			}
		case "provider_round_trip":
			sawIncomplete = true
			if f.Severity != "error" || f.Reason != "incomplete_round" ||
				f.TurnID != turn || f.RoundID != orphanRound {
				t.Fatalf("incomplete-round finding = %+v", f)
			}
		}
	}
	if !sawTerminal || !sawIncomplete {
		t.Fatalf("JSON missing findings: terminal=%v incomplete=%v", sawTerminal, sawIncomplete)
	}
}

func TestSessionsDoctor_EveryTerminalFailureOutcomeReported(t *testing.T) {
	turn := ids.NewV7()
	outcomes := []string{
		events.TurnOutcomeProviderFailed,
		events.TurnOutcomeInvalidResponse,
		events.TurnOutcomeToolAssemblyFailed,
		events.TurnOutcomeToolPlanInvalid,
		events.TurnOutcomeDispatchFailed,
		events.TurnOutcomeContinuationFailed,
	}
	rounds := make([]string, len(outcomes))
	records := []sessions.Record{}
	for i, outcome := range outcomes {
		rounds[i] = ids.NewV7()
		records = append(records, terminalEvent(turn, rounds[i], outcome, "", outcome == events.TurnOutcomeDispatchFailed))
	}
	path := writeSession(t, "outcomes", records)

	out := runDoctor(t, path)
	if !strings.Contains(out, "findings: 6 (error: 6, warning: 0, info: 0)") {
		t.Fatalf("doctor output = %s, want 6 errors", out)
	}
	for i, outcome := range outcomes {
		if !strings.Contains(out, "outcome="+outcome+" turn_id="+turn+" round_id="+rounds[i]) {
			t.Fatalf("doctor output missing outcome %q with its own round %s:\n%s", outcome, rounds[i], out)
		}
	}
}

func TestSessionsDoctor_ReportsPersistedDispatchFailure(t *testing.T) {
	turnID := ids.NewV7()
	namedRound, genericRound := ids.NewV7(), ids.NewV7()
	path := writeSession(t, "dispatch", []sessions.Record{
		textMsg("user", "run the command"),
		eventRecord(events.KindStructuredReadRefused, events.StructuredReadRefused{
			ToolName: "bash", Reason: "not_allowlisted", BatchSize: 1,
		}),
		eventRecord(events.KindTurnTerminal, events.TurnTerminal{
			TurnID: turnID, RoundID: namedRound, Outcome: events.TurnOutcomeDispatchFailed,
			DispatchStarted: true, FailureReason: events.DispatchReasonToolDispatchFailed, FailedTool: "bash",
		}),
		eventRecord(events.KindTurnTerminal, events.TurnTerminal{
			TurnID: turnID, RoundID: genericRound, Outcome: events.TurnOutcomeDispatchFailed,
			DispatchStarted: true, FailureReason: events.DispatchReasonPostPlanFailed,
		}),
	})

	out := runDoctor(t, path)
	for _, want := range []string{
		"outcome=dispatch_failed failure_reason=tool_dispatch_failed failed_tool=bash turn_id=" + turnID + " round_id=" + namedRound,
		"outcome=dispatch_failed failure_reason=post_plan_failed turn_id=" + turnID + " round_id=" + genericRound,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "not_allowlisted") {
		t.Fatalf("doctor reported the structured-read refusal as the terminal failure reason:\n%s", out)
	}

	report := doctorJSON(t, path)
	var named, generic bool
	for _, f := range report.Findings {
		if f.Kind != "turn_terminal" {
			continue
		}
		switch f.RoundID {
		case namedRound:
			named = f.FailureReason == events.DispatchReasonToolDispatchFailed && f.FailedTool == "bash"
		case genericRound:
			generic = f.FailureReason == events.DispatchReasonPostPlanFailed && f.FailedTool == ""
		}
	}
	if !named || !generic {
		t.Fatalf("JSON findings = %+v, want both the named and the generic dispatch failure", report.Findings)
	}
}

// A terminal record from a build before these fields existed, and every non-dispatch
// outcome, must keep reporting exactly what they did.
func TestSessionsDoctor_OmitsDispatchFieldsForOtherOutcomes(t *testing.T) {
	turnID := ids.NewV7()
	path := writeSession(t, "no-dispatch-fields", []sessions.Record{
		terminalEvent(turnID, ids.NewV7(), events.TurnOutcomeProviderFailed, "stream_drop", false),
		terminalEvent(turnID, ids.NewV7(), events.TurnOutcomeDispatchFailed, "", true),
	})

	out := runDoctor(t, path)
	for _, notWant := range []string{"failure_reason=", "failed_tool="} {
		if strings.Contains(out, notWant) {
			t.Fatalf("doctor output carried %q for a record without the fields:\n%s", notWant, out)
		}
	}
}

func TestSessionsDoctor_ActiveRequestIsNotAFinding(t *testing.T) {
	path := writeSession(t, "active", []sessions.Record{
		textMsg("user", "do the thing"),
		eventRecord(events.KindProviderStreamIdle, events.ProviderStreamIdle{
			Provider: "openai", ModelID: "gpt-5.5", RoundElapsedMs: 95_000, IdleMs: 92_000,
		}),
	})

	if out := runDoctor(t, path); !strings.Contains(out, "no errors, failures, or anomalies found") {
		t.Fatalf("doctor diagnosed an in-flight request:\n%s", out)
	}
	if report := doctorJSON(t, path); len(report.Findings) != 0 {
		t.Fatalf("JSON findings = %d, want 0", len(report.Findings))
	}
}

func TestSessionsDoctor_PartialCorrelationPairRejectedOnLoad(t *testing.T) {
	b, err := sessions.Marshal(&sessions.Session{
		Metadata: sessions.Metadata{
			ID: ids.NewV7(), Folder: "/some/folder", StartedAt: fixtureTime, UpdatedAt: fixtureTime, SchemaVersion: 1,
		},
		Records: []sessions.Record{eventRecord(events.KindProviderRoundTrip, map[string]any{
			"provider": "openai", "model_id": "gpt-5.5", "duration_ms": 820, "turn_id": ids.NewV7(),
		})},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "partial.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"codemeld", "sessions", "doctor", path}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "turn_id and round_id must be both present or both absent") {
		t.Fatalf("stderr = %q, want the correlation-pair validation error", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout non-empty on load error: %q", stdout.String())
	}
}

func TestSessionsShow_Path_UnescapesArguments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.json")
	writeFixture(t, path, "/some/folder")

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "sessions", "show", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	out := stdout.String()

	// Records render in order.
	iUser := strings.Index(out, "role=user")
	iCall1 := strings.Index(out, "tool_call call_1")
	iCall2 := strings.Index(out, "tool_call call_2")
	iEvent := strings.Index(out, "kind=provider_request_failed")
	if iUser < 0 || iCall1 < 0 || iCall2 < 0 || iEvent < 0 {
		t.Fatalf("missing expected records in show output:\n%s", out)
	}
	if iUser >= iCall1 || iCall1 >= iCall2 || iCall2 >= iEvent {
		t.Fatalf("records out of order (user=%d call1=%d call2=%d event=%d):\n%s", iUser, iCall1, iCall2, iEvent, out)
	}

	// call_1 arguments are unescaped and indented for display; the escaped on-disk
	// form must not survive into the output.
	if !strings.Contains(out, `"path"`) || !strings.Contains(out, "/etc/hosts") {
		t.Fatalf("unescaped arguments missing:\n%s", out)
	}
	if strings.Contains(out, `\"path\"`) {
		t.Fatalf("arguments were not unescaped (escaped form present):\n%s", out)
	}
	if !strings.Contains(out, "{\n") {
		t.Fatalf("arguments were not pretty-printed across lines:\n%s", out)
	}

	// call_2 has malformed arguments: shown raw and flagged, not fatal.
	if !strings.Contains(out, "[invalid JSON arguments]") || !strings.Contains(out, "{not valid json") {
		t.Fatalf("malformed arguments not shown/flagged:\n%s", out)
	}
}

func buildCompactedFixture(folder, parentSessionID, parentRecordID string) *sessions.Session {
	return &sessions.Session{
		Metadata: sessions.Metadata{
			ID: ids.NewV7(), Folder: folder, StartedAt: fixtureTime, UpdatedAt: fixtureTime, SchemaVersion: 1,
			ForkedFrom: &sessions.ForkOrigin{SessionID: parentSessionID, RecordID: parentRecordID},
		},
		Records: []sessions.Record{
			sessions.Compaction{
				ID:        ids.NewV7(),
				Summary:   "goal: summarize the hosts file\nread /etc/hosts via read_file\nnext: report the localhost entries",
				Timestamp: fixtureTime, Provider: "openai", ModelID: "gpt-5.5", ParentID: parentRecordID,
			},
			eventRecord(events.KindLaunchBegan, events.LaunchBegan{Source: "resume"}),
			textMsg("user", "continue from the summary"),
		},
	}
}

func writeCompactedFixture(t *testing.T, path, folder, parentSessionID, parentRecordID string) {
	t.Helper()
	b, err := sessions.Marshal(buildCompactedFixture(folder, parentSessionID, parentRecordID))
	if err != nil {
		t.Fatalf("marshal compacted fixture: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write compacted fixture: %v", err)
	}
}

func TestSessionsShow_CompactedChild(t *testing.T) {
	parentSession, parentRecord := ids.NewV7(), ids.NewV7()
	path := filepath.Join(t.TempDir(), "compacted.json")
	writeCompactedFixture(t, path, "/some/folder", parentSession, parentRecord)

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "sessions", "show", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	out := stdout.String()

	for _, want := range []string{
		"forked_from: session=" + parentSession + " record=" + parentRecord,
		"1. compaction  2026-05-25T12:00:00.000Z",
		"generated by: provider=openai model=gpt-5.5",
		"source record: parent_id=" + parentRecord,
		"goal: summarize the hosts file",
		"read /etc/hosts via read_file",
		"next: report the localhost entries",
		"2. event  kind=launch_began",
		"3. message  role=user",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("show output missing %q:\n%s", want, out)
		}
	}

	iComp := strings.Index(out, "1. compaction")
	iLaunch := strings.Index(out, "2. event  kind=launch_began")
	iUser := strings.Index(out, "3. message  role=user")
	if iComp < 0 || iLaunch < 0 || iUser < 0 || iComp >= iLaunch || iLaunch >= iUser {
		t.Fatalf("records out of order (compaction=%d launch=%d user=%d):\n%s", iComp, iLaunch, iUser, out)
	}
}

func runShow(t *testing.T, target string, extra ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	args := append([]string{"codemeld", "sessions", "show", target}, extra...)
	if code := Run(context.Background(), args, &stdout, &stderr); code != 0 {
		t.Fatalf("show %v exit = %d, want 0 (stderr=%q)", extra, code, stderr.String())
	}
	return stdout.String()
}

func recordNumbers(out string) []int {
	var nums []int
	for _, line := range strings.Split(out, "\n") {
		dot := strings.Index(line, ". ")
		if dot <= 0 {
			continue
		}
		n, err := strconv.Atoi(line[:dot])
		if err != nil {
			continue
		}
		nums = append(nums, n)
	}
	return nums
}

// Turn A spans records 1-6 and turn B records 7-9, but only the round-trip and
// terminal records carry a turn id, so a range can only be reconstructed around
// those.
func turnFixture(t *testing.T) (path, turnA, turnB string) {
	t.Helper()
	turnA, turnB = ids.NewV7(), ids.NewV7()
	roundA, roundB := ids.NewV7(), ids.NewV7()
	path = writeSession(t, "turns", []sessions.Record{
		textMsg("user", "first question"),
		roundTripEvent(turnA, roundA),
		asstToolCall("call_a", "read", `{"path":"/etc/hosts"}`),
		toolMsg("call_a", "127.0.0.1 localhost"),
		eventRecord(events.KindToolExecEnd, events.ToolExecEnd{
			SubjectKind: "tool", Subject: "read", ExitCode: 0, DurationMs: 3, InvocationID: ids.NewV7(),
		}),
		terminalEvent(turnA, roundA, events.TurnOutcomeCompleted, "", true),
		textMsg("user", "second question"),
		roundTripEvent(turnB, roundB),
		terminalEvent(turnB, roundB, events.TurnOutcomeCompleted, "", true),
	})
	return path, turnA, turnB
}

// showFixtureNoFlagsGolden is the complete no-flags `sessions show` rendering of
// the doctor fixture. Only the session path and the two per-run tool_exec_end
// invocation ids vary between runs, so they appear as placeholders.
const showFixtureNoFlagsGolden = `session: <SESSION_PATH>
folder: /some/folder
records: 18

1. message  role=user  2026-05-25T12:00:00.000Z
    summarize the file

2. message  role=assistant  2026-05-25T12:00:00.000Z
    tool_call call_1  read_file
      {
        "path": "/etc/hosts"
      }

3. message  role=tool  2026-05-25T12:00:00.000Z  answers tool_call call_1
    127.0.0.1 localhost

4. message  role=assistant  2026-05-25T12:00:00.000Z
    tool_call call_2  write_file  [invalid JSON arguments]
      {not valid json

5. message  role=tool  2026-05-25T12:00:00.000Z  answers tool_call call_2
    ok

6. event  kind=provider_request_failed  2026-05-25T12:00:00.000Z
    {
      "provider": "openai",
      "model_id": "gpt-5.5",
      "phase": "http",
      "http_status": 500,
      "partial_response_chars": 0,
      "reason": "http_error",
      "error_detail": "bad gateway"
    }

7. event  kind=session_write_failed  2026-05-25T12:00:00.000Z
    {
      "target_path": "/var/data/session.json",
      "reason": "write_error",
      "error_category": "io_error",
      "error_detail": "disk error"
    }

8. event  kind=permission_persist_failed  2026-05-25T12:00:00.000Z
    {
      "target_path": "/var/data/settings.yaml",
      "grant_kind": "folder",
      "subject_kind": "tool",
      "subject": "Bash",
      "reason": "write_error",
      "error_category": "io_error",
      "error_detail": "perm write failed"
    }

9. event  kind=model_recovery_failed  2026-05-25T12:00:00.000Z
    {
      "reason": "validation_failed",
      "error_detail": "bad model state"
    }

10. event  kind=model_persist_failed  2026-05-25T12:00:00.000Z
    {
      "target_path": "/proj/.codemeld/model.yaml",
      "provider": "openai",
      "model_id": "gpt-5.5",
      "effort": "high",
      "reason": "write_error",
      "error_category": "io_error",
      "error_detail": "write failed"
    }

11. event  kind=model_global_mirror_failed  2026-05-25T12:00:00.000Z
    {
      "target_path": "/home/u/.codemeld/global/model.yaml",
      "provider": "openai",
      "model_id": "gpt-5.5",
      "effort": "high",
      "reason": "write_error",
      "error_category": "io_error",
      "error_detail": "mirror failed"
    }

12. event  kind=tool_exec_end  2026-05-25T12:00:00.000Z
    {
      "subject_kind": "tool",
      "subject": "Bash",
      "exit_code": 1,
      "duration_ms": 5,
      "truncated": false,
      "invocation_id": "<INVOCATION_1>"
    }

13. event  kind=tool_exec_end  2026-05-25T12:00:00.000Z
    {
      "subject_kind": "tool",
      "subject": "Bash",
      "exit_code": 0,
      "duration_ms": 3,
      "truncated": false,
      "invocation_id": "<INVOCATION_2>"
    }

14. event  kind=model_effort_unsupported  2026-05-25T12:00:00.000Z
    {
      "provider": "openai",
      "model_id": "gpt-5.5",
      "configured_effort": "high"
    }

15. event  kind=model_response  2026-05-25T12:00:00.000Z
    {
      "provider": "openai",
      "model_id": "gpt-5.5",
      "input_tokens": 10,
      "output_tokens": 5,
      "anomaly": [
        "usage_missing"
      ]
    }

16. event  kind=slash_command  2026-05-25T12:00:00.000Z
    {
      "name": "resume",
      "args": [
        "01abc"
      ],
      "outcome": "error",
      "error_detail": "no such session"
    }

17. event  kind=slash_command  2026-05-25T12:00:00.000Z
    {
      "name": "help",
      "args": [],
      "outcome": "success"
    }

18. event  kind=stream_interrupted  2026-05-25T12:00:00.000Z
    {
      "source": "esc",
      "content_chars": 12
    }

`

func toolExecInvocationIDs(t *testing.T, sess *sessions.Session) []string {
	t.Helper()
	var ids []string
	for _, rec := range sess.Records {
		ev, ok := rec.(sessions.Event)
		if !ok || ev.Kind != events.KindToolExecEnd {
			continue
		}
		var payload events.ToolExecEnd
		if err := json.Unmarshal(ev.Payload, &payload); err != nil {
			t.Fatalf("unmarshal tool_exec_end payload: %v", err)
		}
		ids = append(ids, payload.InvocationID)
	}
	return ids
}

func TestSessionsShow_NoFlags_HeaderAndRecordsUnfiltered(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.json")
	sess := buildFixtureSession("/some/folder")
	writeFixtureSession(t, path, sess)

	invocations := toolExecInvocationIDs(t, sess)
	if len(invocations) != 2 {
		t.Fatalf("fixture has %d tool_exec_end records, want 2", len(invocations))
	}
	want := strings.NewReplacer(
		"<SESSION_PATH>", path,
		"<INVOCATION_1>", invocations[0],
		"<INVOCATION_2>", invocations[1],
	).Replace(showFixtureNoFlagsGolden)

	if got := runShow(t, path); got != want {
		t.Fatalf("no-flags show output changed:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestSessionsShow_KindFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.json")
	writeFixture(t, path, "/some/folder")
	total := strconv.Itoa(len(buildFixtureSession("/some/folder").Records))

	single := runShow(t, path, "--kind", "tool_exec_end")
	if !strings.Contains(single, "records: 2 of "+total) {
		t.Fatalf("--kind header wrong:\n%s", single)
	}
	if got := strings.Count(single, "kind=tool_exec_end"); got != 2 {
		t.Fatalf("tool_exec_end records = %d, want 2:\n%s", got, single)
	}
	for _, unwanted := range []string{"role=user", "role=assistant", "kind=slash_command"} {
		if strings.Contains(single, unwanted) {
			t.Fatalf("--kind tool_exec_end kept %q:\n%s", unwanted, single)
		}
	}

	union := runShow(t, path, "--kind", "tool_exec_end", "--kind", "slash_command")
	if !strings.Contains(union, "records: 4 of "+total) {
		t.Fatalf("repeated --kind did not union its values:\n%s", union)
	}
	if !strings.Contains(union, "kind=slash_command") || !strings.Contains(union, "kind=tool_exec_end") {
		t.Fatalf("repeated --kind dropped one of its kinds:\n%s", union)
	}
}

func TestSessionsShow_KindFilterSelectsSkillLoads(t *testing.T) {
	const emptyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	const abcDigest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	path := filepath.Join(t.TempDir(), "fixture.json")
	sess := buildFixtureSession("/some/folder")
	sess.Records = append(sess.Records,
		eventRecord("skill_loaded", map[string]any{
			"name": "my-skill", "layer": "project", "via": "slash", "file": "", "bytes": 0, "sha256": emptyDigest,
		}),
		eventRecord("skill_loaded", map[string]any{
			"name": "7zip", "layer": "global", "via": "tool", "file": "refs/guide.md", "bytes": 3, "sha256": abcDigest,
		}),
	)
	writeFixtureSession(t, path, sess)

	out := runShow(t, path, "--kind", "skill_loaded")
	if !strings.Contains(out, "records: 2 of "+strconv.Itoa(len(sess.Records))) {
		t.Fatalf("--kind skill_loaded header wrong:\n%s", out)
	}
	if got := strings.Count(out, "kind=skill_loaded"); got != 2 {
		t.Fatalf("skill_loaded records = %d, want 2:\n%s", got, out)
	}
	for _, want := range []string{
		`"name": "my-skill"`, `"via": "slash"`, `"file": ""`, `"sha256": "` + emptyDigest + `"`,
		`"name": "7zip"`, `"layer": "global"`, `"via": "tool"`, `"file": "refs/guide.md"`, `"bytes": 3`, `"sha256": "` + abcDigest + `"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("--kind skill_loaded output missing %s:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"kind=slash_command", "kind=tool_exec_end", "role=user"} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("--kind skill_loaded kept %q:\n%s", unwanted, out)
		}
	}
}

func TestSessionsShow_TurnFilter(t *testing.T) {
	path, turnA, turnB := turnFixture(t)

	first := runShow(t, path, "--turn", turnA)
	if !strings.Contains(first, "records: 6 of 9") {
		t.Fatalf("--turn header wrong:\n%s", first)
	}
	if got := recordNumbers(first); !reflect.DeepEqual(got, []int{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("turn A range = %v, want records 1-6:\n%s", got, first)
	}
	// The turn's messages and tool activity ride along even though they carry no turn id.
	for _, want := range []string{"first question", "tool_call call_a", "kind=tool_exec_end", "kind=turn_terminal"} {
		if !strings.Contains(first, want) {
			t.Fatalf("turn A range missing %q:\n%s", want, first)
		}
	}
	if strings.Contains(first, "second question") {
		t.Fatalf("turn A range leaked the next turn:\n%s", first)
	}

	second := runShow(t, path, "--turn", turnB)
	if got := recordNumbers(second); !reflect.DeepEqual(got, []int{7, 8, 9}) {
		t.Fatalf("turn B range = %v, want records 7-9:\n%s", got, second)
	}
}

func TestSessionsShow_TurnAbsentFromSessionSelectsNothing(t *testing.T) {
	path, _, _ := turnFixture(t)

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "sessions", "show", path, "--turn", ids.NewV7()}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 for a filter that matched nothing (stderr=%q)", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "records: 0 of 9") {
		t.Fatalf("empty selection is not reported as a filter result:\n%s", out)
	}
	if nums := recordNumbers(out); len(nums) != 0 {
		t.Fatalf("records %v rendered for an absent turn:\n%s", nums, out)
	}
}

func TestSessionsShow_TurnWithNoPrecedingUserMessage(t *testing.T) {
	turn, round := ids.NewV7(), ids.NewV7()
	path := writeSession(t, "headless-turn", []sessions.Record{
		roundTripEvent(turn, round),
		terminalEvent(turn, round, events.TurnOutcomeCompleted, "", true),
	})

	out := runShow(t, path, "--turn", turn)
	if !strings.Contains(out, "records: 2 of 2") {
		t.Fatalf("range without an opening user message wrong:\n%s", out)
	}
	if got := recordNumbers(out); !reflect.DeepEqual(got, []int{1, 2}) {
		t.Fatalf("range = %v, want records 1-2:\n%s", got, out)
	}
}

// A turn_terminal closes one round, not the turn: an agentic turn writes one per
// round, and doctor reports a later round that recorded its provider_round_trip and
// then died before its terminal as incomplete_round. That round has to stay inside
// the range, so the range ends at the turn's last lifecycle record.
func TestSessionsShow_TurnKeepsARoundLeftOpenAfterAnEarlierTerminal(t *testing.T) {
	turn, roundA, roundB := ids.NewV7(), ids.NewV7(), ids.NewV7()
	path := writeSession(t, "multi-round-turn", []sessions.Record{
		textMsg("user", "first question"),
		roundTripEvent(turn, roundA),
		terminalEvent(turn, roundA, events.TurnOutcomeCompleted, "", true),
		roundTripEvent(turn, roundB),
		textMsg("user", "second question"),
	})

	if got := runDoctor(t, path); !strings.Contains(got, reasonIncompleteRound) {
		t.Fatalf("fixture does not produce the incomplete_round finding --turn has to show:\n%s", got)
	}
	out := runShow(t, path, "--turn", turn)
	if got := recordNumbers(out); !reflect.DeepEqual(got, []int{1, 2, 3, 4}) {
		t.Fatalf("range = %v, want records 1-4: the round left open after an earlier round's terminal stays in the range:\n%s", got, out)
	}
	if strings.Contains(out, "second question") {
		t.Fatalf("range leaked the next turn:\n%s", out)
	}
}

// The turn loop records turn_terminal before it commits the provider_request_failed
// that says why the turn failed, and that record carries no turn id -- so a range
// stopping at the terminal would hide from --turn the very diagnostic doctor points
// the reader at.
func TestSessionsShow_TurnKeepsFailureRecordsAfterItsTerminal(t *testing.T) {
	turn, round := ids.NewV7(), ids.NewV7()
	status := int64(502)
	path := writeSession(t, "failed-turn", []sessions.Record{
		textMsg("user", "first question"),
		roundTripEvent(turn, round),
		terminalEvent(turn, round, events.TurnOutcomeProviderFailed, "http", false),
		eventRecord(events.KindProviderRequestFailed, events.ProviderRequestFailed{
			Provider: "openai", ModelID: "gpt-5.5", Phase: "http", HTTPStatus: &status,
			Reason: "http_error", ErrorDetail: "502 bad gateway",
		}),
		textMsg("user", "second question"),
	})

	out := runShow(t, path, "--turn", turn)
	if got := recordNumbers(out); !reflect.DeepEqual(got, []int{1, 2, 3, 4}) {
		t.Fatalf("range = %v, want records 1-4: the failure record written after the terminal belongs to the turn:\n%s", got, out)
	}
	if !strings.Contains(out, "kind=provider_request_failed") {
		t.Fatalf("--turn dropped the failure record that closed the turn:\n%s", out)
	}
	if strings.Contains(out, "second question") {
		t.Fatalf("the tail scan leaked into the next turn:\n%s", out)
	}
}

// The tail after a turn's last lifecycle record is a closed set of failure/retry
// kinds, not "everything unclaimed": what the user does between turns -- here a
// /model run -- is not part of the turn that preceded it.
func TestSessionsShow_TurnStopsAtWhatTheUserDidAfterIt(t *testing.T) {
	turn, round := ids.NewV7(), ids.NewV7()
	path := writeSession(t, "turn-then-slash", []sessions.Record{
		textMsg("user", "first question"),
		roundTripEvent(turn, round),
		terminalEvent(turn, round, events.TurnOutcomeCompleted, "", true),
		eventRecord(events.KindSlashCommand, events.SlashCommand{Name: "model", Args: []string{}, Outcome: "success"}),
	})

	out := runShow(t, path, "--turn", turn)
	if got := recordNumbers(out); !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Fatalf("range = %v, want records 1-3: a slash command run after the turn is not part of it:\n%s", got, out)
	}
}

// doctor reports a round that no turn_terminal ever closed; the turn it names has
// to stay readable, so the range ends at the turn's last lifecycle record.
func TestSessionsShow_TurnWithNoTerminal(t *testing.T) {
	turn, round := ids.NewV7(), ids.NewV7()
	path := writeSession(t, "incomplete-turn", []sessions.Record{
		textMsg("user", "first question"),
		roundTripEvent(turn, round),
		roundTripEvent(turn, round),
		textMsg("user", "second question"),
	})

	out := runShow(t, path, "--turn", turn)
	if !strings.Contains(out, "records: 3 of 4") {
		t.Fatalf("incomplete turn header wrong:\n%s", out)
	}
	if got := recordNumbers(out); !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Fatalf("range = %v, want records 1-3:\n%s", got, out)
	}
}

func TestSessionsShow_LastKeepsFinalRecords(t *testing.T) {
	path, _, _ := turnFixture(t)

	out := runShow(t, path, "--last", "2")
	if !strings.Contains(out, "records: 2 of 9") {
		t.Fatalf("--last header wrong:\n%s", out)
	}
	if got := recordNumbers(out); !reflect.DeepEqual(got, []int{8, 9}) {
		t.Fatalf("--last 2 kept %v, want the final records 8-9:\n%s", got, out)
	}
	if all := runShow(t, path, "--last", "50"); !strings.Contains(all, "records: 9 of 9") {
		t.Fatalf("--last beyond the session did not keep every record:\n%s", all)
	}
}

func TestSessionsShow_FiltersCompose(t *testing.T) {
	path, turnA, _ := turnFixture(t)

	both := runShow(t, path, "--turn", turnA, "--kind", "tool_exec_end", "--kind", "provider_round_trip")
	if got := recordNumbers(both); !reflect.DeepEqual(got, []int{2, 5}) {
		t.Fatalf("--turn with --kind = %v, want records 2 and 5:\n%s", got, both)
	}

	all := runShow(t, path, "--turn", turnA, "--kind", "tool_exec_end", "--kind", "provider_round_trip", "--last", "1")
	if !strings.Contains(all, "records: 1 of 9") {
		t.Fatalf("composed header wrong:\n%s", all)
	}
	if got := recordNumbers(all); !reflect.DeepEqual(got, []int{5}) {
		t.Fatalf("composed filters kept %v, want record 5:\n%s", got, all)
	}
}

func TestSessionsShow_InvalidSelectionIsUsageError(t *testing.T) {
	path, turn, _ := turnFixture(t)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"unknown kind", []string{"--kind", "tool_exec_finished"}, `--kind "tool_exec_finished" is not a recorded event kind`},
		{"unknown kind among valid ones", []string{"--kind", "tool_exec_end", "--kind", "nope"}, `--kind "nope" is not a recorded event kind`},
		{"turn is not a uuidv7", []string{"--turn", "turn-3"}, `--turn "turn-3" is not a valid turn id`},
		{"empty turn", []string{"--turn", ""}, `--turn "" is not a valid turn id`},
		{"zero last", []string{"--last", "0"}, "--last must be greater than zero; got 0"},
		{"negative last", []string{"--last", "-3"}, "--last must be greater than zero; got -3"},
		{"valid turn with invalid last", []string{"--turn", turn, "--last", "0"}, "--last must be greater than zero"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"codemeld", "sessions", "show", path}, tt.args...)
			code := Run(context.Background(), args, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("exit = %d, want 2 (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("stderr = %q, want it to name %q", stderr.String(), tt.want)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout non-empty on a usage error: %q", stdout.String())
			}
		})
	}

	var stdout, stderr bytes.Buffer
	Run(context.Background(), []string{"codemeld", "sessions", "show", path, "--kind", "nope"}, &stdout, &stderr)
	for _, want := range []string{"valid kinds: ", "tool_exec_end", "turn_terminal", "launch_began"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("the rejection does not list the valid kinds (%q missing): %q", want, stderr.String())
		}
	}
	if lines := strings.Count(strings.TrimSuffix(stderr.String(), "\n"), "\n"); lines != 0 {
		t.Fatalf("rejection spans %d extra lines, want one: %q", lines, stderr.String())
	}
}

type showJSONReport struct {
	Session  string `json:"session"`
	Folder   string `json:"folder"`
	Records  int    `json:"records"`
	Selected int    `json:"selected"`
	Filtered bool   `json:"filtered"`
	Entries  []struct {
		Number    int             `json:"number"`
		Type      string          `json:"type"`
		Role      string          `json:"role"`
		Content   string          `json:"content"`
		Kind      string          `json:"kind"`
		Payload   json.RawMessage `json:"payload"`
		ToolCalls []struct {
			ID           string          `json:"id"`
			Name         string          `json:"name"`
			Arguments    json.RawMessage `json:"arguments"`
			RawArguments string          `json:"raw_arguments"`
			InvalidJSON  bool            `json:"invalid_json_arguments"`
		} `json:"tool_calls"`
	} `json:"entries"`
}

func showJSON(t *testing.T, target string, extra ...string) (showJSONReport, string) {
	t.Helper()
	out := runShow(t, target, append([]string{"--json"}, extra...)...)
	var report showJSONReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	return report, out
}

func TestSessionsShow_JSON_UnescapesToolCallArguments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.json")
	writeFixture(t, path, "/some/folder")
	total := len(buildFixtureSession("/some/folder").Records)

	report, raw := showJSON(t, path)
	if report.Session != path || report.Folder != "/some/folder" {
		t.Fatalf("header = session %q folder %q, want %q and /some/folder", report.Session, report.Folder, path)
	}
	if report.Records != total || report.Selected != total || report.Filtered {
		t.Fatalf("unfiltered counts = %d of %d (filtered=%v), want %d of %d",
			report.Selected, report.Records, report.Filtered, total, total)
	}
	if len(report.Entries) != total {
		t.Fatalf("entries = %d, want %d", len(report.Entries), total)
	}
	// The stored form is a provider-facing escaped string; a JSON consumer must get a value.
	if strings.Contains(raw, `\"path\"`) {
		t.Fatalf("arguments were emitted in their escaped stored form:\n%s", raw)
	}

	var valid, invalid int
	for _, e := range report.Entries {
		for _, tc := range e.ToolCalls {
			switch tc.ID {
			case "call_1":
				valid++
				if tc.Name != "read_file" || tc.InvalidJSON || tc.RawArguments != "" {
					t.Fatalf("call_1 = %+v, want a valid read_file call", tc)
				}
				var args struct {
					Path string `json:"path"`
				}
				if err := json.Unmarshal(tc.Arguments, &args); err != nil {
					t.Fatalf("call_1 arguments are not a JSON value: %v (%s)", err, tc.Arguments)
				}
				if args.Path != "/etc/hosts" {
					t.Fatalf("call_1 path = %q, want /etc/hosts", args.Path)
				}
			case "call_2":
				invalid++
				if !tc.InvalidJSON {
					t.Fatalf("call_2 = %+v, want the invalid-arguments flag", tc)
				}
				if tc.RawArguments != "{not valid json" {
					t.Fatalf("call_2 raw_arguments = %q, want the stored text carried verbatim", tc.RawArguments)
				}
				if len(tc.Arguments) != 0 {
					t.Fatalf("call_2 arguments = %s, want none for unparseable text", tc.Arguments)
				}
			}
		}
	}
	if valid != 1 || invalid != 1 {
		t.Fatalf("tool calls found: %d valid, %d invalid; want one of each", valid, invalid)
	}
}

func TestSessionsShow_JSON_ReportsSelection(t *testing.T) {
	path, turnA, _ := turnFixture(t)

	report, _ := showJSON(t, path, "--turn", turnA)
	if report.Records != 9 || report.Selected != 6 || !report.Filtered {
		t.Fatalf("counts = %d of %d (filtered=%v), want 6 of 9 filtered", report.Selected, report.Records, report.Filtered)
	}
	var numbers []int
	for _, e := range report.Entries {
		numbers = append(numbers, e.Number)
	}
	if !reflect.DeepEqual(numbers, []int{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("entry numbers = %v, want the turn's file positions 1-6", numbers)
	}
	if report.Entries[0].Type != "message" || report.Entries[0].Role != "user" || report.Entries[0].Content != "first question" {
		t.Fatalf("first entry = %+v, want the opening user message", report.Entries[0])
	}
	if report.Entries[1].Type != "event" || report.Entries[1].Kind != events.KindProviderRoundTrip {
		t.Fatalf("second entry = %+v, want the round-trip event", report.Entries[1])
	}
	var payload struct {
		TurnID string `json:"turn_id"`
	}
	if err := json.Unmarshal(report.Entries[1].Payload, &payload); err != nil {
		t.Fatalf("event payload is not a JSON value: %v (%s)", err, report.Entries[1].Payload)
	}
	if payload.TurnID != turnA {
		t.Fatalf("payload turn_id = %q, want %q", payload.TurnID, turnA)
	}

	empty, _ := showJSON(t, path, "--turn", ids.NewV7())
	if empty.Selected != 0 || !empty.Filtered || len(empty.Entries) != 0 {
		t.Fatalf("absent turn = %d entries (filtered=%v), want an empty filtered report", len(empty.Entries), empty.Filtered)
	}
}

func TestSessionsShow_JSON_CompactionAndListContent(t *testing.T) {
	parentSession, parentRecord := ids.NewV7(), ids.NewV7()
	path := filepath.Join(t.TempDir(), "compacted.json")
	writeCompactedFixture(t, path, "/some/folder", parentSession, parentRecord)

	var report struct {
		ForkedFrom struct {
			SessionID string `json:"session_id"`
			RecordID  string `json:"record_id"`
		} `json:"forked_from"`
		Entries []struct {
			Type     string `json:"type"`
			Summary  string `json:"summary"`
			Provider string `json:"provider"`
			ModelID  string `json:"model_id"`
			ParentID string `json:"parent_id"`
		} `json:"entries"`
	}
	out := runShow(t, path, "--json")
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if report.ForkedFrom.SessionID != parentSession || report.ForkedFrom.RecordID != parentRecord {
		t.Fatalf("forked_from = %+v, want the fork origin the header prints", report.ForkedFrom)
	}
	first := report.Entries[0]
	if first.Type != "compaction" || first.Provider != "openai" || first.ModelID != "gpt-5.5" || first.ParentID != parentRecord {
		t.Fatalf("first entry = %+v, want the compaction record", first)
	}
	if !strings.Contains(first.Summary, "goal: summarize the hosts file") {
		t.Fatalf("compaction summary = %q, want the stored summary", first.Summary)
	}

	partsPath := writeSession(t, "parts", []sessions.Record{
		sessions.Message{
			ID: ids.NewV7(), Role: "user", Timestamp: fixtureTime,
			Content: sessions.PartsContent([]sessions.ContentPart{
				{Type: "text", Raw: json.RawMessage(`{"type":"text","text":"look at this"}`)},
			}),
		},
	})
	var parts struct {
		Entries []struct {
			Content      string            `json:"content"`
			ContentParts []json.RawMessage `json:"content_parts"`
		} `json:"entries"`
	}
	partsOut := runShow(t, partsPath, "--json")
	if err := json.Unmarshal([]byte(partsOut), &parts); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, partsOut)
	}
	if len(parts.Entries) != 1 || len(parts.Entries[0].ContentParts) != 1 {
		t.Fatalf("list content did not survive as parts:\n%s", partsOut)
	}
	if parts.Entries[0].Content != "" {
		t.Fatalf("content = %q, want list content reported only as parts", parts.Entries[0].Content)
	}
	if !strings.Contains(string(parts.Entries[0].ContentParts[0]), `"look at this"`) {
		t.Fatalf("content part = %s, want the stored part verbatim", parts.Entries[0].ContentParts[0])
	}
}

func showJSONEntries(t *testing.T, out string) []map[string]json.RawMessage {
	t.Helper()
	var report struct {
		Entries []map[string]json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	return report.Entries
}

func TestSessionsShow_JSON_KeepsEmptyContentAndArgumentShapes(t *testing.T) {
	path := writeSession(t, "empties", []sessions.Record{
		textMsg("user", ""),
		sessions.Message{
			ID: ids.NewV7(), Role: "user", Timestamp: fixtureTime,
			Content: sessions.PartsContent([]sessions.ContentPart{}),
		},
		asstToolCall("call_empty", "read_file", ""),
		toolMsg("call_empty", "ok"),
	})

	entries := showJSONEntries(t, runShow(t, path, "--json"))
	if len(entries) != 4 {
		t.Fatalf("entries = %d, want the four stored records", len(entries))
	}

	text, ok := entries[0]["content"]
	if !ok || string(text) != `""` {
		t.Fatalf("empty text content = %s (present=%v), want a present empty string", text, ok)
	}
	if _, ok := entries[0]["content_parts"]; ok {
		t.Fatalf("text content also reported content_parts: %v", entries[0])
	}

	parts, ok := entries[1]["content_parts"]
	if !ok || string(parts) != `[]` {
		t.Fatalf("empty list content = %s (present=%v), want a present empty list", parts, ok)
	}
	if _, ok := entries[1]["content"]; ok {
		t.Fatalf("list content also reported content: %v", entries[1])
	}

	var calls []map[string]json.RawMessage
	if err := json.Unmarshal(entries[2]["tool_calls"], &calls); err != nil {
		t.Fatalf("tool_calls is not a list: %v (%s)", err, entries[2]["tool_calls"])
	}
	if len(calls) != 1 {
		t.Fatalf("tool_calls = %d, want the one stored call", len(calls))
	}
	raw, ok := calls[0]["raw_arguments"]
	if !ok || string(raw) != `""` {
		t.Fatalf("empty invalid raw_arguments = %s (present=%v), want a present empty string", raw, ok)
	}
	if string(calls[0]["invalid_json_arguments"]) != "true" {
		t.Fatalf("invalid_json_arguments = %s, want true alongside the raw value", calls[0]["invalid_json_arguments"])
	}
	if _, ok := calls[0]["arguments"]; ok {
		t.Fatalf("invalid arguments were also reported as a JSON value: %v", calls[0])
	}
}

// showKinds is a hand-written copy because internal/events publishes no
// enumeration of its kind constants; this pins the copy to that source.
func TestSessionsShow_KindListMatchesEventsPackage(t *testing.T) {
	const payloadsPath = "../events/payloads.go"
	file, err := parser.ParseFile(token.NewFileSet(), payloadsPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", payloadsPath, err)
	}
	declared := map[string]bool{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "Kind") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				value, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					t.Fatalf("unquote %s: %v", name.Name, uerr)
				}
				declared[value] = true
			}
		}
	}
	if len(declared) == 0 {
		t.Fatalf("no Kind… constants found in %s", payloadsPath)
	}
	accepted := map[string]bool{}
	for _, k := range showKinds {
		accepted[k] = true
	}
	for k := range declared {
		if !accepted[k] {
			t.Errorf("--kind rejects recorded event kind %q; add it to showKinds", k)
		}
	}
	for k := range accepted {
		if !declared[k] {
			t.Errorf("--kind accepts %q, which %s does not declare", k, payloadsPath)
		}
	}
}

func TestSessionsDoctor_CompactedChild_NotAFinding(t *testing.T) {
	parentSession, parentRecord := ids.NewV7(), ids.NewV7()
	path := filepath.Join(t.TempDir(), "compacted.json")
	writeCompactedFixture(t, path, "/some/folder", parentSession, parentRecord)

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "sessions", "doctor", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, "no errors, failures, or anomalies found") {
		t.Fatalf("doctor classified the compaction as a finding:\n%s", got)
	}

	var jsonOut, jsonErr bytes.Buffer
	code = Run(context.Background(), []string{"codemeld", "sessions", "doctor", path, "--json"}, &jsonOut, &jsonErr)
	if code != 0 {
		t.Fatalf("doctor --json exit = %d, want 0 (stderr=%q)", code, jsonErr.String())
	}
	var report struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(jsonOut.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, jsonOut.String())
	}
	if len(report.Findings) != 0 {
		t.Fatalf("findings = %d, want 0:\n%s", len(report.Findings), jsonOut.String())
	}
	if strings.Contains(jsonOut.String(), "compaction") {
		t.Fatalf("doctor JSON mentions compaction:\n%s", jsonOut.String())
	}
}

func TestSessions_MalformedCompactionProvenanceRejected(t *testing.T) {
	parentSession, parentRecord := ids.NewV7(), ids.NewV7()
	b, err := sessions.Marshal(buildCompactedFixture("/some/folder", parentSession, parentRecord))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	mutated := strings.Replace(string(b), parentRecord, ids.NewV7(), 1)
	path := filepath.Join(t.TempDir(), "malformed.json")
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	for _, sub := range []string{"show", "doctor"} {
		t.Run(sub, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"codemeld", "sessions", sub, path}, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), "does not match metadata.forked_from.record_id") {
				t.Fatalf("stderr = %q, want provenance mismatch error", stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout non-empty on load error: %q", stdout.String())
			}
		})
	}
}

func TestSessionsDoctor_ResolvesByID(t *testing.T) {
	home := t.TempDir()
	rawCWD := t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(rawCWD)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	dir := filepath.Join(sessions.SessionRoot(home), sessions.FolderDirName(canonical))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	id := ids.NewV7()
	writeFixture(t, filepath.Join(dir, id+".json"), canonical)
	if err := os.WriteFile(filepath.Join(dir, "folder"), []byte(canonical+"\n"), 0o644); err != nil {
		t.Fatalf("write folder file: %v", err)
	}
	stubHomeAndCwd(t, home, rawCWD)

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "sessions", "doctor", id}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "findings: 11") {
		t.Fatalf("id-resolved doctor output missing findings:\n%s", stdout.String())
	}
}

func writeFolderFile(t *testing.T, dir, folder string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "folder"), []byte(folder+"\n"), 0o644); err != nil {
		t.Fatalf("write folder file in %s: %v", dir, err)
	}
}

// crossFolderEnv stands up an isolated home holding two per-folder session
// subdirectories and writes the fixture into the one that is not the working
// directory, so a bare id only resolves if the reader looks past its own folder.
func crossFolderEnv(t *testing.T) (id, recorded string) {
	t.Helper()
	home, rawCWD := t.TempDir(), t.TempDir()
	canonicalCWD, err := sessions.CanonicalizeFolder(rawCWD)
	if err != nil {
		t.Fatalf("canonicalize cwd: %v", err)
	}
	recorded, err = sessions.CanonicalizeFolder(t.TempDir())
	if err != nil {
		t.Fatalf("canonicalize recorded folder: %v", err)
	}
	root := sessions.SessionRoot(home)
	recordedDir := filepath.Join(root, sessions.FolderDirName(recorded))
	writeFolderFile(t, filepath.Join(root, sessions.FolderDirName(canonicalCWD)), canonicalCWD)
	writeFolderFile(t, recordedDir, recorded)
	id = ids.NewV7()
	writeFixture(t, filepath.Join(recordedDir, id+".json"), recorded)
	stubHomeAndCwd(t, home, rawCWD)
	return id, recorded
}

func TestSessions_ResolveIDRecordedInAnotherFolder(t *testing.T) {
	tests := []struct {
		sub  string
		want string
	}{
		{"doctor", "findings: 11"},
		{"show", "records: "},
		{"permissions", "prompts shown: 0"},
		{"research", "web research calls: 0"},
	}
	for _, tt := range tests {
		t.Run(tt.sub, func(t *testing.T) {
			id, recorded := crossFolderEnv(t)

			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"codemeld", "sessions", tt.sub, id}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			out := stdout.String()
			if !strings.Contains(out, tt.want) {
				t.Fatalf("%s output missing %q:\n%s", tt.sub, tt.want, out)
			}
			if !strings.Contains(out, "folder: "+recorded) {
				t.Fatalf("%s output does not name the recorded folder %q:\n%s", tt.sub, recorded, out)
			}
		})
	}
}

func TestSessions_JSONReportsNameTheRecordedFolder(t *testing.T) {
	for _, sub := range []string{"doctor", "permissions", "research", "show"} {
		t.Run(sub, func(t *testing.T) {
			id, recorded := crossFolderEnv(t)

			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"codemeld", "sessions", sub, id, "--json"}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			var report struct {
				Session string `json:"session"`
				Folder  string `json:"folder"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
			}
			if report.Folder != recorded {
				t.Fatalf("folder = %q, want %q", report.Folder, recorded)
			}
			if !strings.HasSuffix(report.Session, id+".json") {
				t.Fatalf("session = %q, want the located %s.json", report.Session, id)
			}
		})
	}
}

// The hash-collision case: the id sits in the current folder's own subdirectory
// while the session records a different folder, so the resolver refuses on the
// CWD check rather than the sibling scan.
func TestSessionsDoctor_ResolvesIDWhoseSubdirectoryRecordsAnotherFolder(t *testing.T) {
	home, rawCWD := t.TempDir(), t.TempDir()
	canonicalCWD, err := sessions.CanonicalizeFolder(rawCWD)
	if err != nil {
		t.Fatalf("canonicalize cwd: %v", err)
	}
	const recorded = "/recorded/elsewhere"
	dir := filepath.Join(sessions.SessionRoot(home), sessions.FolderDirName(canonicalCWD))
	writeFolderFile(t, dir, recorded)
	id := ids.NewV7()
	writeFixture(t, filepath.Join(dir, id+".json"), recorded)
	stubHomeAndCwd(t, home, rawCWD)

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "sessions", "doctor", id}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "findings: 11") || !strings.Contains(out, "folder: "+recorded) {
		t.Fatalf("doctor output missing findings or the recorded folder:\n%s", out)
	}
}

func metadataLine(folder, schemaVersion string) string {
	return `{"type":"metadata","metadata":{"id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b","folder":"` + folder +
		`","started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":` +
		schemaVersion + `}}` + "\n"
}

const (
	loneToolRecordLine = `{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01",` +
		`"role":"tool","content":"r","timestamp":"2026-05-25T12:00:00.000Z","tool_call_id":"call_x"}` + "\n"
	badPayloadRecordLine = `{"type":"event","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a02",` +
		`"kind":"stream_interrupted","timestamp":"2026-05-25T12:00:00.000Z","payload":{"source":"bogus"}}` + "\n"
)

// Each case plants a readable copy of the same id in a sibling folder, so a
// fallback to path-form loading or a second sibling lookup would print a report
// instead of the resolver's own message.
func TestSessions_NonMismatchIDFailuresStayTerminal(t *testing.T) {
	tests := []struct {
		name    string
		body    func(folder string) string // nil → write no expected-path file at all
		wantSub string
	}{
		{"missing id", nil, "not found in any session directory"},
		{
			"unparseable file",
			func(string) string { return "this is not valid json" },
			"cannot be parsed",
		},
		{
			"failed record validation",
			func(folder string) string { return metadataLine(folder, "1") + loneToolRecordLine },
			"cannot be loaded",
		},
		{
			"failed payload validation",
			func(folder string) string { return metadataLine(folder, "1") + badPayloadRecordLine },
			"cannot be loaded",
		},
		{
			"version refused",
			func(folder string) string { return metadataLine(folder, "2") },
			"newer than this build supports",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home, rawCWD := t.TempDir(), t.TempDir()
			canonicalCWD, err := sessions.CanonicalizeFolder(rawCWD)
			if err != nil {
				t.Fatalf("canonicalize cwd: %v", err)
			}
			sibling, err := sessions.CanonicalizeFolder(t.TempDir())
			if err != nil {
				t.Fatalf("canonicalize sibling folder: %v", err)
			}
			root := sessions.SessionRoot(home)
			dir := filepath.Join(root, sessions.FolderDirName(canonicalCWD))
			siblingDir := filepath.Join(root, sessions.FolderDirName(sibling))
			writeFolderFile(t, dir, canonicalCWD)
			writeFolderFile(t, siblingDir, sibling)
			id := ids.NewV7()

			if tt.body != nil {
				if err := os.WriteFile(filepath.Join(dir, id+".json"), []byte(tt.body(canonicalCWD)), 0o600); err != nil {
					t.Fatalf("write expected-path session: %v", err)
				}
				writeFixture(t, filepath.Join(siblingDir, id+".json"), sibling)
			}
			stubHomeAndCwd(t, home, rawCWD)

			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"codemeld", "sessions", "doctor", id}, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantSub) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tt.wantSub)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout non-empty on a terminal resolve failure: %q", stdout.String())
			}
		})
	}
}

func TestSessionsDoctor_LoadErrors(t *testing.T) {
	dir := t.TempDir()

	newer := filepath.Join(dir, "newer.json")
	if err := os.WriteFile(newer, []byte(`{"type":"metadata","metadata":{"id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b","folder":"/f","started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":2}}`+"\n"), 0o600); err != nil {
		t.Fatalf("write newer: %v", err)
	}
	garbage := filepath.Join(dir, "garbage.json")
	if err := os.WriteFile(garbage, []byte("not a json object"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	tests := []struct {
		name    string
		target  string
		wantSub string
	}{
		{"not found", filepath.Join(dir, "missing.json"), "not found"},
		{"newer schema_version", newer, "newer than this build supports"},
		{"parse failure", garbage, "cannot be parsed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"codemeld", "sessions", "doctor", tt.target}, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantSub) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tt.wantSub)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout non-empty on error: %q", stdout.String())
			}
		})
	}
}

// Distinctive strings planted in the parts of a tool_exec_end that doctor must
// never print: a direct subject's arguments, an sh -c script body, and both
// captured streams.
const (
	directArgMarker    = "ZZ-DIRECT-ARG-ZZ"
	literalTokenMarker = "ZZ-LITERAL-TOKEN-ZZ"
	stdoutMarker       = "ZZ-STDOUT-ZZ"
	stderrMarker       = "ZZ-STDERR-ZZ"
)

func failedToolEvent(subjectKind, subject, invocationID string) sessions.Event {
	return eventRecord(events.KindToolExecEnd, events.ToolExecEnd{
		SubjectKind: subjectKind, Subject: subject, ExitCode: 3, DurationMs: 42,
		Stdout: stdoutMarker, Stderr: stderrMarker, InvocationID: invocationID,
	})
}

func failedToolSession(t *testing.T) (path string, direct, literal, tool string) {
	t.Helper()
	direct, literal, tool = ids.NewV7(), ids.NewV7(), ids.NewV7()
	path = writeSession(t, "failed-tools", []sessions.Record{
		failedToolEvent("direct", "curl --header AUTH="+directArgMarker, direct),
		failedToolEvent("literal", "TOKEN="+literalTokenMarker+" curl https://example.test | sh", literal),
		failedToolEvent("tool", "vcs_commit", tool),
		eventRecord(events.KindToolExecEnd, events.ToolExecEnd{
			SubjectKind: "direct", Subject: "git status", ExitCode: 0, DurationMs: 7, InvocationID: ids.NewV7(),
		}),
	})
	return path, direct, literal, tool
}

func TestSessionsDoctor_FailedToolIdentityIsBoundedInHumanOutput(t *testing.T) {
	path, direct, literal, tool := failedToolSession(t)
	out := runDoctor(t, path)

	if !strings.Contains(out, "findings: 3 (error: 3, warning: 0, info: 0)") {
		t.Fatalf("a zero-exit tool call became a finding:\n%s", out)
	}
	tests := []struct {
		name         string
		invocationID string
		wants        []string
		notWants     []string
	}{
		{
			name: "direct names only the program", invocationID: direct,
			wants: []string{"failed_tool=curl", "subject_kind=direct", "duration_ms=42", "exit_code=3"},
		},
		{
			name: "tool names the tool verbatim", invocationID: tool,
			wants: []string{"failed_tool=vcs_commit", "subject_kind=tool", "duration_ms=42", "exit_code=3"},
		},
		{
			name: "literal names no tool at all", invocationID: literal,
			wants:    []string{"subject_kind=literal", "duration_ms=42", "exit_code=3"},
			notWants: []string{"failed_tool="},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := lineContaining(t, out, "invocation_id="+tt.invocationID)
			for _, want := range tt.wants {
				if !strings.Contains(line, want) {
					t.Fatalf("finding line missing %q:\n%s", want, line)
				}
			}
			for _, notWant := range tt.notWants {
				if strings.Contains(line, notWant) {
					t.Fatalf("finding line unexpectedly contains %q:\n%s", notWant, line)
				}
			}
		})
	}
}

func TestSessionsDoctor_FailedToolIdentityIsBoundedInJSON(t *testing.T) {
	path, direct, literal, tool := failedToolSession(t)

	var report struct {
		Findings []map[string]any `json:"findings"`
	}
	out := runDoctor(t, path, "--json")
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(report.Findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(report.Findings))
	}

	byInvocation := map[string]map[string]any{}
	for _, f := range report.Findings {
		id, _ := f["invocation_id"].(string)
		byInvocation[id] = f
		if _, present := f["subject"]; present {
			t.Fatalf("finding carries a subject field: %+v", f)
		}
	}
	tests := []struct {
		name           string
		invocationID   string
		wantFailedTool string // "" → the field must be absent
		wantSubjectKnd string
	}{
		{"direct", direct, "curl", "direct"},
		{"literal", literal, "", "literal"},
		{"tool", tool, "vcs_commit", "tool"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, ok := byInvocation[tt.invocationID]
			if !ok {
				t.Fatalf("no finding for invocation %s:\n%s", tt.invocationID, out)
			}
			if f["subject_kind"] != tt.wantSubjectKnd {
				t.Fatalf("subject_kind = %v, want %q", f["subject_kind"], tt.wantSubjectKnd)
			}
			if f["duration_ms"] != float64(42) || f["exit_code"] != float64(3) {
				t.Fatalf("duration_ms/exit_code = %v/%v, want 42/3", f["duration_ms"], f["exit_code"])
			}
			got, present := f["failed_tool"]
			if tt.wantFailedTool == "" {
				if present {
					t.Fatalf("failed_tool = %v, want the field absent", got)
				}
				return
			}
			if got != tt.wantFailedTool {
				t.Fatalf("failed_tool = %v, want %q", got, tt.wantFailedTool)
			}
		})
	}
}

func TestSessionsDoctor_OmitsSubjectArgumentsAndCapturedOutput(t *testing.T) {
	path, _, _, _ := failedToolSession(t)

	for _, form := range []struct {
		name  string
		extra []string
	}{
		{"human", nil},
		{"json", []string{"--json"}},
	} {
		t.Run(form.name, func(t *testing.T) {
			out := runDoctor(t, path, form.extra...)
			for _, secret := range []string{directArgMarker, literalTokenMarker, stdoutMarker, stderrMarker} {
				if strings.Contains(out, secret) {
					t.Fatalf("doctor output leaked %q:\n%s", secret, out)
				}
			}
			if !strings.Contains(out, "curl") {
				t.Fatalf("bounded identity is missing, so the omission proves nothing:\n%s", out)
			}
		})
	}
}

func TestSessionsUsageErrors(t *testing.T) {
	runUsageErrorCases(t, []usageErrorCase{
		{"no subcommand", []string{"codemeld", "sessions"}, "sessions requires a subcommand"},
		{"unknown subcommand", []string{"codemeld", "sessions", "bogus"}, "unknown sessions subcommand"},
		{"list named when unknown", []string{"codemeld", "sessions", "bogus"}, "'codemeld sessions list'"},
		{"list named when missing", []string{"codemeld", "sessions"}, "'codemeld sessions list'"},
		{"doctor no target", []string{"codemeld", "sessions", "doctor"}, "requires a session id or file path"},
		{"show no target", []string{"codemeld", "sessions", "show"}, "requires a session id or file path"},
		{"permissions no target", []string{"codemeld", "sessions", "permissions"}, "requires a session id or file path"},
		{
			"permissions two targets",
			[]string{"codemeld", "sessions", "permissions", "a.json", "b.json"},
			"accepts exactly one session id or file path",
		},
		{"research no target", []string{"codemeld", "sessions", "research"}, "requires a session id or file path"},
		{
			"research two targets",
			[]string{"codemeld", "sessions", "research", "a.json", "b.json"},
			"accepts exactly one session id or file path",
		},
	})
}

// buildPermissionsFixture assembles a session whose permission events exercise
// every correlation rule the report must honor, in one deliberate order:
// a decision that precedes any matching prompt (stale), two identical prompts
// answered in order (FIFO), a prompt whose only later decision names a different
// scope (pending), a host prompt scoped by host_scope, and the three
// permission_matched sources that must stay out of the prompt rows. Subject
// "Ripgrep" is used only by matched events, so its absence from the output proves
// the exclusion.
func buildPermissionsFixture(folder string) *sessions.Session {
	records := []sessions.Record{
		eventRecord(events.KindPermissionDecision, events.PermissionDecision{
			SubjectKind: "tool", Subject: "Curl", PathScope: "/proj", Outcome: "granted",
		}),
		eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
			SubjectKind: "tool", Subject: "Bash", PathScope: "/proj",
		}),
		eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
			SubjectKind: "tool", Subject: "Bash", PathScope: "/proj",
		}),
		eventRecord(events.KindPermissionDecision, events.PermissionDecision{
			SubjectKind: "tool", Subject: "Bash", PathScope: "/proj", Outcome: "granted",
		}),
		eventRecord(events.KindPermissionDecision, events.PermissionDecision{
			SubjectKind: "tool", Subject: "Bash", PathScope: "/proj", Outcome: "denied",
		}),
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "Ripgrep", PathScope: "/proj",
			GrantKind: "session", GrantPathScope: "/proj", Outcome: "session_grant", OutcomeSource: "grant",
		}),
		eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
			SubjectKind: "tool", Subject: "Curl", PathScope: "/proj",
		}),
		eventRecord(events.KindPermissionDecision, events.PermissionDecision{
			SubjectKind: "tool", Subject: "Curl", PathScope: "/other", Outcome: "granted",
		}),
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "Ripgrep", PathScope: "/proj", Outcome: "deny", OutcomeSource: "cache",
		}),
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "Ripgrep", PathScope: "/proj", Outcome: "deny", OutcomeSource: "mode_auto",
		}),
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "direct", Subject: "Ripgrep", PathScope: "/proj/a", Outcome: "once", OutcomeSource: "mode_auto",
		}),
		eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
			SubjectKind: "host", Subject: "web_search", HostScope: "example.com",
		}),
		eventRecord(events.KindPermissionDecision, events.PermissionDecision{
			SubjectKind: "host", Subject: "web_search", HostScope: "example.com", Outcome: "granted",
		}),
	}
	return &sessions.Session{
		Metadata: sessions.Metadata{
			ID: ids.NewV7(), Folder: folder, StartedAt: fixtureTime, UpdatedAt: fixtureTime, SchemaVersion: 1,
		},
		Records: records,
	}
}

func writePermissionsFixture(t *testing.T, path, folder string) {
	t.Helper()
	b, err := sessions.Marshal(buildPermissionsFixture(folder))
	if err != nil {
		t.Fatalf("marshal permissions fixture: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write permissions fixture: %v", err)
	}
}

func runPermissions(t *testing.T, target string, extra ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	args := append([]string{"codemeld", "sessions", "permissions", target}, extra...)
	code := Run(context.Background(), args, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	return stdout.String()
}

func TestSessionsPermissions_Path_Report(t *testing.T) {
	path := filepath.Join(t.TempDir(), "permissions.json")
	writePermissionsFixture(t, path, "/some/folder")
	out := runPermissions(t, path)

	tests := []struct {
		name string
		want string
	}{
		{"summary counts", "prompts shown: 4 (granted: 2, denied: 1, pending: 1)"},
		{"first identical prompt takes the first decision", "1. [granted] tool  Bash  scope=/proj"},
		{"second identical prompt takes the second decision", "2. [denied] tool  Bash  scope=/proj"},
		{"a stale decision and a mismatched scope leave the prompt pending", "3. [pending] tool  Curl  scope=/proj"},
		{"a host prompt is scoped by host_scope", "4. [granted] host  web_search  scope=example.com"},
		{"the tally counts every non-prompted source", "non-prompted authorizations: 4 (grant: 1, cache: 1, mode_auto: 2, declared_scope: 0, declared_command: 0, open_read: 0, confined: 0, system_one_check: 0)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(out, tt.want) {
				t.Fatalf("permissions output missing %q:\n%s", tt.want, out)
			}
		})
	}

	// permission_matched never becomes a prompt row, whatever its outcome_source.
	if strings.Contains(out, "Ripgrep") {
		t.Fatalf("a non-prompted authorization was rendered as a prompt row:\n%s", out)
	}
	// Rows render in record order.
	iBash, iCurl, iHost := strings.Index(out, "Bash"), strings.Index(out, "Curl"), strings.Index(out, "web_search")
	if iBash < 0 || iCurl < 0 || iHost < 0 || iBash >= iCurl || iCurl >= iHost {
		t.Fatalf("prompt rows out of record order (bash=%d curl=%d host=%d):\n%s", iBash, iCurl, iHost, out)
	}
}

// A NUL byte is legal in both subject and a cleaned absolute path_scope, so two
// schema-valid tuples can differ only in where the NUL falls. They must stay
// distinct: the decision belongs to the second prompt, leaving the first pending.
func TestSessionsPermissions_NULBearingTuplesStayDistinct(t *testing.T) {
	sess := &sessions.Session{
		Metadata: sessions.Metadata{
			ID: ids.NewV7(), Folder: "/some/folder", StartedAt: fixtureTime, UpdatedAt: fixtureTime, SchemaVersion: 1,
		},
		Records: []sessions.Record{
			eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
				SubjectKind: "tool", Subject: "alpha", PathScope: "/one\x00/two",
			}),
			eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
				SubjectKind: "tool", Subject: "alpha\x00/one", PathScope: "/two",
			}),
			eventRecord(events.KindPermissionDecision, events.PermissionDecision{
				SubjectKind: "tool", Subject: "alpha\x00/one", PathScope: "/two", Outcome: "granted",
			}),
		},
	}
	b, err := sessions.Marshal(sess)
	if err != nil {
		t.Fatalf("marshal collision fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "permissions.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write collision fixture: %v", err)
	}

	out := runPermissions(t, path)
	for _, want := range []string{
		"prompts shown: 2 (granted: 1, denied: 0, pending: 1)",
		"1. [pending] tool  alpha  scope=/one\x00/two",
		"2. [granted] tool  alpha\x00/one  scope=/two",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("permissions output missing %q:\n%q", want, out)
		}
	}
}

// A session with no permission events still reports the tally, so a zero prompt
// count is readable as "nothing was authorized" rather than an empty report.
func TestSessionsPermissions_NoPermissionEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.json")
	writeFixture(t, path, "/some/folder")
	out := runPermissions(t, path)

	for _, want := range []string{
		"prompts shown: 0",
		"non-prompted authorizations: 0 (grant: 0, cache: 0, mode_auto: 0, declared_scope: 0, declared_command: 0, open_read: 0, confined: 0, system_one_check: 0)",
		"skipped by reason: paused: 0, text: 0, blocked_paths_unavailable: 0, substitution: 0, blocked_path: 0, wrapper: 0, program_location: 0, shell_shape: 0\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("permissions output missing %q:\n%s", want, out)
		}
	}
	report := decodeSystemOnePermissions(t, path)
	wantSkipped := map[string]int{"paused": 0, "text": 0, "blocked_paths_unavailable": 0, "substitution": 0, "blocked_path": 0, "wrapper": 0, "program_location": 0, "shell_shape": 0}
	if !reflect.DeepEqual(report.SystemOne.SkippedReasons, wantSkipped) {
		t.Fatalf("system_one.skipped_reasons = %v, want all zeros %v", report.SystemOne.SkippedReasons, wantSkipped)
	}
}

func TestSessionsPermissions_UnknownSkippedReasonFailsTheLoad(t *testing.T) {
	path := writeSession(t, "unknown-skipped", []sessions.Record{
		eventRecord(events.KindPermissionSystemOneCheck, systemOneCheck("literal", "ls", "openrouter", "jev/jev-1", "skipped", "teapot", "", 0, 0)),
	})
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"codemeld", "sessions", "permissions", path}, &stdout, &stderr); code == 0 {
		t.Fatalf("exit = 0, want a load failure (stdout=%q)", stdout.String())
	}
	if !strings.Contains(stderr.String(), "cannot be loaded") || stdout.Len() != 0 {
		t.Fatalf("stderr = %q, stdout = %q; want only the cannot be loaded failure", stderr.String(), stdout.String())
	}
}

func TestSessionsPermissions_ResolvesByID(t *testing.T) {
	home := t.TempDir()
	rawCWD := t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(rawCWD)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	dir := filepath.Join(sessions.SessionRoot(home), sessions.FolderDirName(canonical))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	id := ids.NewV7()
	writePermissionsFixture(t, filepath.Join(dir, id+".json"), canonical)
	if err := os.WriteFile(filepath.Join(dir, "folder"), []byte(canonical+"\n"), 0o644); err != nil {
		t.Fatalf("write folder file: %v", err)
	}
	stubHomeAndCwd(t, home, rawCWD)

	if out := runPermissions(t, id); !strings.Contains(out, "prompts shown: 4") {
		t.Fatalf("id-resolved permissions output missing the report:\n%s", out)
	}
}

// A non-v7 argument is one explicit path, never a glob: a target naming a file
// that does not exist fails as that literal path instead of matching a sibling.
func TestSessionsPermissions_NonIDTargetIsOneExplicitPath(t *testing.T) {
	dir := t.TempDir()
	writePermissionsFixture(t, filepath.Join(dir, "permissions.json"), "/some/folder")
	missing := filepath.Join(dir, "*.json")

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "sessions", "permissions", missing}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stderr.String(), missing) || !strings.Contains(stderr.String(), "not found") {
		t.Fatalf("stderr = %q, want a not-found error naming the literal target", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout non-empty on error: %q", stdout.String())
	}
}

const (
	auditProj    = "/proj"
	auditSub     = "/proj/sub"
	auditDeep    = "/proj/sub/deep"
	auditSibling = "/proj/a"
	auditSibDeep = "/proj/b/deep"
)

func directTokens(tokens ...string) *[]string { return &tokens }

func fixtureIdentity(subjectKind string, tokens []string) string {
	if subjectKind != "direct" || len(tokens) == 0 {
		return ""
	}
	return permissions.ExactSubject(tokens[0], tokens[1:])
}

func promptEvent(subjectKind, subject, pathScope string, tokens *[]string) sessions.Event {
	p := events.PermissionPromptShown{
		SubjectKind: subjectKind, Subject: subject, PathScope: pathScope, DirectTokens: tokens,
	}
	if tokens != nil {
		p.DirectCommandSubject = fixtureIdentity(subjectKind, *tokens)
		p.DirectRequestSubject = p.DirectCommandSubject
	}
	return eventRecord(events.KindPermissionPromptShown, p)
}

func grantEvent(subjectKind, subject, pathScope, grantKind, grantPathScope, grantSubject string, tokens ...string) sessions.Event {
	identity := fixtureIdentity(subjectKind, tokens)
	return eventRecord(events.KindPermissionDecision, events.PermissionDecision{
		SubjectKind: subjectKind, Subject: subject, PathScope: pathScope, Outcome: "granted",
		GrantKind: grantKind, GrantPathScope: grantPathScope, GrantSubject: grantSubject,
		DirectCommandSubject: identity, DirectRequestSubject: identity,
	})
}

func buildAuditRecords() []sessions.Record {
	return []sessions.Record{
		promptEvent("direct", "git commit -m First task", auditSub,
			directTokens("git", "commit", "-m", "First task")),
		grantEvent("direct", "git commit -m First task", auditSub, "folder", auditSub,
			`git commit -m "First task"`, "git", "commit", "-m", "First task"),

		promptEvent("direct", "git commit -m First task", auditProj,
			directTokens("git", "commit", "-m", "First task")),
		eventRecord(events.KindPermissionDecision, events.PermissionDecision{
			SubjectKind: "direct", Subject: "git commit -m First task", PathScope: auditProj, Outcome: "granted",
			DirectCommandSubject: `git commit -m 'First task'`, DirectRequestSubject: `git commit -m 'First task'`,
		}),

		promptEvent("tool", "edit", auditSub, nil),
		grantEvent("tool", "edit", auditSub, "folder", auditSub, "write"),

		promptEvent("tool", "create", auditProj, nil),
		grantEvent("tool", "create", auditProj, "global", "*", "write"),

		eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
			SubjectKind: "host", Subject: "web_search", HostScope: "example.com",
		}),
		eventRecord(events.KindPermissionDecision, events.PermissionDecision{
			SubjectKind: "host", Subject: "web_search", HostScope: "example.com", Outcome: "granted",
			GrantKind: "project", GrantHostScope: "example.com", GrantSubject: "web_search",
		}),

		promptEvent("tool", "Bash", auditProj, nil),
		eventRecord(events.KindPermissionDecision, events.PermissionDecision{
			SubjectKind: "tool", Subject: "Bash", PathScope: auditProj, Outcome: "denied",
		}),

		promptEvent("literal", `sh -c "echo hi"`, auditProj, nil),

		promptEvent("tool", "read", "/other", nil),
		grantEvent("tool", "read", "/other", "session", "/other", "read*"),

		eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
			SubjectKind: "host", Subject: "web_fetch", HostScope: "docs.example.com",
		}),
		eventRecord(events.KindPermissionDecision, events.PermissionDecision{
			SubjectKind: "host", Subject: "web_fetch", HostScope: "docs.example.com", Outcome: "granted",
			GrantKind: "session", GrantHostScope: "docs.example.com", GrantSubject: "web_fetch",
		}),

		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "Ripgrep", PathScope: auditProj,
			GrantKind: "session", GrantPathScope: auditProj, Outcome: "session_grant", OutcomeSource: "grant",
		}),
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "Ripgrep", PathScope: auditProj, Outcome: "once", OutcomeSource: "cache",
		}),
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "Ripgrep", PathScope: auditProj, Outcome: "once", OutcomeSource: "mode_auto",
		}),

		eventRecord(events.KindPermissionRevokeRequested, events.PermissionRevokeRequested{
			EntryKind: "tool", Subject: "edit", PathScope: auditSub, GrantKind: "folder",
			Source: events.RevokeSourcePermissionsUI,
		}),
		eventRecord(events.KindPermissionRevokeRequested, events.PermissionRevokeRequested{
			EntryKind: "tool", Subject: "web_fetch", HostScope: "docs.example.com", GrantKind: "session",
			Source: events.RevokeSourcePermissionsUI,
		}),
	}
}

func TestSessionsPermissions_ClassifiesGrantsAndEscalations(t *testing.T) {
	out := runPermissions(t, writeSession(t, "audit", buildAuditRecords()))

	tests := []struct {
		name string
		want string
	}{
		{
			"a stored folder grant names its kind, folder, and the raw stored subject",
			`1. [granted] direct  git commit -m First task  scope=/proj/sub  ` +
				`grant=folder grant_scope=/proj/sub grant_subject="git commit -m \"First task\""`,
		},
		{
			"a broader direct prompt escalates the narrower stored grant, and allow-once stored nothing",
			`2. [granted] direct  git commit -m First task  scope=/proj  grant=allow_once ` +
				`escalates_grant_scope=/proj/sub escalates_grant_subject="git commit -m \"First task\""`,
		},
		{
			"a capability grant records the wider stored subject",
			`3. [granted] tool  edit  scope=/proj/sub  grant=folder grant_scope=/proj/sub grant_subject="write"`,
		},
		{
			"a global grant is named by kind alone and escalates the narrower capability grant",
			`4. [granted] tool  create  scope=/proj  grant=global grant_subject="write" ` +
				`escalates_grant_scope=/proj/sub escalates_grant_subject="write"`,
		},
		{
			"a host grant names its host scope",
			`5. [granted] host  web_search  scope=example.com  grant=project grant_host=example.com grant_subject="web_search"`,
		},
		{"a denied prompt stored nothing", "6. [denied] tool  Bash  scope=/proj\n"},
		{"an unanswered prompt stays pending", `7. [pending] literal  sh -c "echo hi"  scope=/proj` + "\n"},
		{
			"a session-scoped path grant names its folder",
			`8. [granted] tool  read  scope=/other  grant=session grant_scope=/other grant_subject="read*"`,
		},
		{
			"a session-scoped host grant names its host",
			`9. [granted] host  web_fetch  scope=docs.example.com  ` +
				`grant=session grant_host=docs.example.com grant_subject="web_fetch"`,
		},
		{"summary counts", "prompts shown: 9 (granted: 7, denied: 1, pending: 1)"},
		{"the tally counts every non-prompted source", "non-prompted authorizations: 3 (grant: 1, cache: 1, mode_auto: 1, declared_scope: 0, declared_command: 0, open_read: 0, confined: 0, system_one_check: 0)"},
		{"explicit revocations are listed and counted apart from the prompts", "explicit revocation requests: 2"},
		{
			"a path revocation names the stored grant's own identity and its source",
			"1. [permissions_ui] tool  edit  scope=/proj/sub  grant=folder\n",
		},
		{
			"a host revocation is scoped by host",
			"2. [permissions_ui] tool  web_fetch  scope=docs.example.com  grant=session\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(out, tt.want) {
				t.Fatalf("permissions output missing %q:\n%s", tt.want, out)
			}
		})
	}

	if strings.Contains(out, "grant_scope=*") {
		t.Fatalf("the all-paths sentinel was rendered as a folder:\n%s", out)
	}
	if hostLine := lineContaining(t, out, "web_search"); strings.Contains(hostLine, "grant_scope=") {
		t.Fatalf("a host row carries a path field: %q", hostLine)
	}
}

func lineContaining(t *testing.T, out, sub string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, sub) {
			return line
		}
	}
	t.Fatalf("no output line contains %q:\n%s", sub, out)
	return ""
}

const (
	goldenPermissionsPath  = "testdata/sessions-permissions.json"
	sessionPathPlaceholder = "<session>"
)

func TestSessionsPermissions_JSONMatchesGolden(t *testing.T) {
	path := writeSession(t, "audit", buildAuditRecords())
	out := runPermissions(t, path, "--json")

	var doc any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("--json output is not one valid JSON document: %v\n%s", err, out)
	}
	got := strings.ReplaceAll(out, path, sessionPathPlaceholder)
	want, err := os.ReadFile(goldenPermissionsPath)
	if err != nil {
		t.Fatalf("read golden %s: %v", goldenPermissionsPath, err)
	}
	if got != string(want) {
		t.Fatalf("--json report does not match %s\n--- got ---\n%s\n--- want ---\n%s", goldenPermissionsPath, got, want)
	}
}

func TestSessionsPermissions_NoEscalationMarked(t *testing.T) {
	gitTokens := directTokens("git", "status")
	tests := []struct {
		name    string
		records []sessions.Record
	}{
		{"equal scope", []sessions.Record{
			promptEvent("direct", "git status", auditSub, directTokens("git", "status")),
			grantEvent("direct", "git status", auditSub, "folder", auditSub, "git :*", "git", "status"),
			promptEvent("direct", "git status", auditSub, directTokens("git", "status")),
		}},
		{"descendant scope", []sessions.Record{
			promptEvent("direct", "git status", auditProj, directTokens("git", "status")),
			grantEvent("direct", "git status", auditProj, "folder", auditProj, "git :*", "git", "status"),
			promptEvent("direct", "git status", auditSub, directTokens("git", "status")),
		}},
		{"sibling scope", []sessions.Record{
			promptEvent("direct", "git status", auditSub, directTokens("git", "status")),
			grantEvent("direct", "git status", auditSub, "folder", auditSub, "git :*", "git", "status"),
			promptEvent("direct", "git status", "/other", directTokens("git", "status")),
		}},
		{"earlier prompt denied", []sessions.Record{
			promptEvent("direct", "git status", auditSub, directTokens("git", "status")),
			eventRecord(events.KindPermissionDecision, events.PermissionDecision{
				SubjectKind: "direct", Subject: "git status", PathScope: auditSub, Outcome: "denied",
			}),
			promptEvent("direct", "git status", auditProj, gitTokens),
		}},
		{"earlier approval was allow-once", []sessions.Record{
			promptEvent("direct", "git status", auditSub, directTokens("git", "status")),
			eventRecord(events.KindPermissionDecision, events.PermissionDecision{
				SubjectKind: "direct", Subject: "git status", PathScope: auditSub, Outcome: "granted",
			}),
			promptEvent("direct", "git status", auditProj, gitTokens),
		}},
		{"earlier grant is global", []sessions.Record{
			promptEvent("direct", "git status", auditSub, directTokens("git", "status")),
			grantEvent("direct", "git status", auditSub, "global", "*", "git :*", "git", "status"),
			promptEvent("direct", "git status", auditProj, gitTokens),
		}},
		{"earlier grant is a host grant", []sessions.Record{
			eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
				SubjectKind: "host", Subject: "web_search", HostScope: "example.com",
			}),
			eventRecord(events.KindPermissionDecision, events.PermissionDecision{
				SubjectKind: "host", Subject: "web_search", HostScope: "example.com", Outcome: "granted",
				GrantKind: "project", GrantHostScope: "example.com", GrantSubject: "web_search",
			}),
			promptEvent("direct", "git status", auditProj, gitTokens),
		}},
		{"stored subject does not cover the request", []sessions.Record{
			promptEvent("direct", "npm test", auditSub, directTokens("npm", "test")),
			grantEvent("direct", "npm test", auditSub, "folder", auditSub, "npm :*", "npm", "test"),
			promptEvent("direct", "git status", auditProj, gitTokens),
		}},
		{"stored subject kind differs", []sessions.Record{
			promptEvent("literal", "git status", auditSub, nil),
			grantEvent("literal", "git status", auditSub, "folder", auditSub, "git status"),
			promptEvent("direct", "git status", auditProj, gitTokens),
		}},
		{"stored grant has no grant_subject", []sessions.Record{
			promptEvent("direct", "git status", auditSub, directTokens("git", "status")),
			grantEvent("direct", "git status", auditSub, "folder", auditSub, "", "git", "status"),
			promptEvent("direct", "git status", auditProj, gitTokens),
		}},
		{"direct prompt has no recorded tokens", []sessions.Record{
			promptEvent("direct", "git status", auditSub, directTokens("git", "status")),
			grantEvent("direct", "git status", auditSub, "folder", auditSub, "git :*", "git", "status"),
			promptEvent("direct", "git status", auditProj, nil),
		}},
		{"stored wildcard prefix crosses a token boundary", []sessions.Record{
			promptEvent("direct", "git lo", auditSub, directTokens("git", "lo")),
			grantEvent("direct", "git lo", auditSub, "folder", auditSub, "git lo :*", "git", "lo"),
			promptEvent("direct", "git log --oneline", auditProj, directTokens("git", "log", "--oneline")),
		}},
		{"pinned quoted argument differs", []sessions.Record{
			promptEvent("direct", "git commit -m First task", auditSub,
				directTokens("git", "commit", "-m", "First task")),
			grantEvent("direct", "git commit -m First task", auditSub, "folder", auditSub,
				`git commit -m "First task"`, "git", "commit", "-m", "First task"),
			promptEvent("direct", "git commit -m Second task", auditProj,
				directTokens("git", "commit", "-m", "Second task")),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runPermissions(t, writeSession(t, "no-escalation", tt.records))
			if strings.Contains(out, "escalates_grant_scope=") {
				t.Fatalf("an escalation was claimed without evidence:\n%s", out)
			}
		})
	}
}

func TestSessionsPermissions_NarrowestEscalationWins(t *testing.T) {
	subGrant := []sessions.Record{
		promptEvent("direct", "git status", auditSub, directTokens("git", "status")),
		grantEvent("direct", "git status", auditSub, "folder", auditSub, "git :*", "git", "status"),
	}
	deepGrant := []sessions.Record{
		promptEvent("direct", "git status", auditDeep, directTokens("git", "status")),
		grantEvent("direct", "git status", auditDeep, "folder", auditDeep, "git :*", "git", "status"),
	}
	siblingGrant := []sessions.Record{
		promptEvent("direct", "git status", auditSibling, directTokens("git", "status")),
		grantEvent("direct", "git status", auditSibling, "folder", auditSibling, "git :*", "git", "status"),
	}
	siblingDeepGrant := []sessions.Record{
		promptEvent("direct", "git status", auditSibDeep, directTokens("git", "status")),
		grantEvent("direct", "git status", auditSibDeep, "folder", auditSibDeep, "git :*", "git", "status"),
	}
	broader := promptEvent("direct", "git status -s", auditProj, directTokens("git", "status", "-s"))
	records := func(grants ...[]sessions.Record) []sessions.Record {
		out := []sessions.Record{}
		for _, g := range grants {
			out = append(out, g...)
		}
		return append(out, broader)
	}

	for _, tt := range []struct {
		name    string
		records []sessions.Record
		want    string
	}{
		{"narrower grant recorded first", records(deepGrant, subGrant), auditDeep},
		{"narrower grant recorded last", records(subGrant, deepGrant), auditDeep},
		{"deeper incomparable sibling recorded first", records(siblingDeepGrant, siblingGrant), auditSibDeep},
		{"deeper incomparable sibling recorded last", records(siblingGrant, siblingDeepGrant), auditSibDeep},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out := runPermissions(t, writeSession(t, "narrowest", tt.records))
			want := `3. [pending] direct  git status -s  scope=/proj  ` +
				`escalates_grant_scope=` + tt.want + ` escalates_grant_subject="git :*"`
			if !strings.Contains(out, want) {
				t.Fatalf("permissions output missing %q:\n%s", want, out)
			}
		})
	}
}

const researchFixturePath = "testdata/sessions-research.json"

func runResearch(t *testing.T, target string, extra ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	args := append([]string{"codemeld", "sessions", "research", target}, extra...)
	if code := Run(context.Background(), args, &stdout, &stderr); code != 0 {
		t.Fatalf("research exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	return stdout.String()
}

func TestSessionsResearch_Fixture_HumanReport(t *testing.T) {
	out := runResearch(t, researchFixturePath)

	tests := []struct {
		name string
		want string
	}{
		{"header counts every web call", "web research calls: 8 (searches: 4, fetches: 4)"},
		{
			"a candidate-first search records its query and candidates",
			`  1. record 3  web_search  call_search_1  shape=candidate_search  query="go 1.26 release notes"`,
		},
		{
			"a candidate a later fetch read and a later answer named",
			"       https://go.dev/doc/go1.26  cited=https://go.dev/doc/go1.26  stages=candidate,selected,cited",
		},
		{"a candidate read but never named", "       https://blog.example.com/go126  stages=candidate,selected"},
		{"a candidate no later call or answer touched", "       https://uncited.example.com/notes  stages=candidate\n"},
		{"the search's omitted count survives", "       omitted candidates: 1"},
		{
			"an explicit fetch of an earlier candidate is selected and retrieved",
			"       https://go.dev/doc/go1.26  final_url=https://go.dev/doc/go1.26/  outcome=ok" +
				"  cited=https://go.dev/doc/go1.26  stages=selected,retrieved,cited",
		},
		{"a failed fetch is failed, not retrieved", "       https://blog.example.com/go126  outcome=request_failed  stages=selected,failed"},
		{
			"a candidate offered only after the fetch is not a selection",
			"  4. record 13  web_search  call_search_2  shape=candidate_search  query=\"go 1.26 release notes\"\n" +
				"       https://go.dev/doc/go1.26  stages=candidate\n",
		},
		{"a legacy bundle is labelled as such", "  5. record 15  web_search  call_search_3  shape=legacy_auto_fetch  query=\"legacy bundle\""},
		{
			"a legacy source keeps its recorded outcome",
			"       https://legacy.example.com/a  final_url=https://legacy.example.com/a  outcome=ok" +
				"  cited=https://legacy.example.com/a  stages=candidate,retrieved,cited",
		},
		{"a failed legacy source", "       https://legacy.example.com/b  outcome=request_failed  stages=candidate,failed"},
		{
			"unreadable arguments and result are named, not guessed",
			"  6. record 19  web_search  call_search_4  shape=unclassified  unclassified=arguments,result\n",
		},
		{
			"a fetch of an address no search offered is not a selection",
			"       https://direct.example.com/page  final_url=https://direct.example.com/page  outcome=ok  stages=retrieved",
		},
		{
			"a web call is matched to its own result inside a mixed response group",
			"  8. record 27  web_fetch  call_fetch_4  shape=fetch\n" +
				"       https://parallel.example.com/x  outcome=unsupported_content  stages=failed",
		},
		{"searches split legacy from the rest", "  searches: 4 (legacy auto-fetch: 1)"},
		{"a repeated query is counted once as unique", "  queries: 3 total, 2 unique (1 repeated)"},
		{"a repeated candidate URL is counted once as unique", "  candidate urls: 6 total, 5 unique (1 repeated)"},
		{"only candidates a later fetch asked for", "  candidates a later fetch selected: 2"},
		{"fetch outcomes", "  explicit fetches: 4 (retrieved: 2, failed: 2)"},
		{"legacy outcomes stay separate from explicit fetches", "  legacy auto-fetches: 2 (retrieved: 1, failed: 1)"},
		{"only exact addresses in a later answer", "  urls cited in a later answer: 2"},
		{"web host prompts, total and distinct hosts", "  web host prompts: 5 shown, 4 unique hosts"},
		{"unclassified evidence is counted", "  calls with unclassified evidence: 1"},
		{"the limit of the evidence is stated", "uncited does not mean unused:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(out, tt.want) {
				t.Fatalf("research output missing %q:\n%s", tt.want, out)
			}
		})
	}

	for _, notWant := range []string{"call_bash", "main.go", "Bash"} {
		if strings.Contains(out, notWant) {
			t.Fatalf("research output contains %q:\n%s", notWant, out)
		}
	}
	allowed := map[string]bool{"candidate": true, "selected": true, "retrieved": true, "failed": true, "cited": true}
	for _, line := range strings.Split(out, "\n") {
		_, labels, found := strings.Cut(line, "stages=")
		if !found {
			continue
		}
		for _, label := range strings.Split(labels, ",") {
			if !allowed[label] {
				t.Fatalf("address carries the label %q, outside the evidence-backed set: %q", label, line)
			}
		}
	}
	iFirst, iLegacy, iLast := strings.Index(out, "call_search_1"), strings.Index(out, "call_search_3"), strings.Index(out, "call_fetch_4")
	if iFirst < 0 || iLegacy < 0 || iLast < 0 || iFirst >= iLegacy || iLegacy >= iLast {
		t.Fatalf("calls out of record order (first=%d legacy=%d last=%d):\n%s", iFirst, iLegacy, iLast, out)
	}
}

type researchJSON struct {
	Session string `json:"session"`
	Calls   []struct {
		Record  int    `json:"record"`
		CallID  string `json:"call_id"`
		Tool    string `json:"tool"`
		Shape   string `json:"shape"`
		Query   string `json:"query"`
		Omitted int    `json:"omitted"`
		Sources []struct {
			URL      string   `json:"url"`
			FinalURL string   `json:"final_url"`
			Outcome  string   `json:"outcome"`
			Cited    []string `json:"cited"`
			Stages   []string `json:"stages"`
		} `json:"sources"`
		Unclassified []string `json:"unclassified"`
	} `json:"calls"`
	Summary struct {
		Searches            int `json:"searches"`
		LegacySearches      int `json:"legacy_searches"`
		Fetches             int `json:"fetches"`
		Queries             int `json:"queries"`
		UniqueQueries       int `json:"unique_queries"`
		CandidateURLs       int `json:"candidate_urls"`
		UniqueCandidateURLs int `json:"unique_candidate_urls"`
		SelectedCandidates  int `json:"selected_candidates"`
		FetchRetrieved      int `json:"fetch_retrieved"`
		FetchFailed         int `json:"fetch_failed"`
		LegacyAutoFetches   int `json:"legacy_auto_fetches"`
		LegacyRetrieved     int `json:"legacy_retrieved"`
		LegacyFailed        int `json:"legacy_failed"`
		CitedURLs           int `json:"cited_urls"`
		HostPrompts         int `json:"host_prompts"`
		UniquePromptedHosts int `json:"unique_prompted_hosts"`
		UnclassifiedCalls   int `json:"unclassified_calls"`
	} `json:"summary"`
}

func researchJSONReport(t *testing.T, target string) researchJSON {
	t.Helper()
	out := runResearch(t, target, "--json")
	if !strings.HasPrefix(out, "{") {
		t.Fatalf("--json output has a non-JSON prefix:\n%s", out)
	}
	var report researchJSON
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("--json output is not one valid JSON document: %v\n%s", err, out)
	}
	return report
}

func TestSessionsResearch_Fixture_JSONCarriesTheSameFacts(t *testing.T) {
	report := researchJSONReport(t, researchFixturePath)

	if report.Session != researchFixturePath {
		t.Fatalf("session = %q, want %q", report.Session, researchFixturePath)
	}
	if len(report.Calls) != 8 {
		t.Fatalf("calls = %d, want 8", len(report.Calls))
	}
	s := report.Summary
	wantSummary := map[string]int{
		"searches": 4, "legacy_searches": 1, "fetches": 4,
		"queries": 3, "unique_queries": 2,
		"candidate_urls": 6, "unique_candidate_urls": 5, "selected_candidates": 2,
		"fetch_retrieved": 2, "fetch_failed": 2,
		"legacy_auto_fetches": 2, "legacy_retrieved": 1, "legacy_failed": 1,
		"cited_urls": 2, "host_prompts": 5, "unique_prompted_hosts": 4, "unclassified_calls": 1,
	}
	gotSummary := map[string]int{
		"searches": s.Searches, "legacy_searches": s.LegacySearches, "fetches": s.Fetches,
		"queries": s.Queries, "unique_queries": s.UniqueQueries,
		"candidate_urls": s.CandidateURLs, "unique_candidate_urls": s.UniqueCandidateURLs,
		"selected_candidates": s.SelectedCandidates,
		"fetch_retrieved":     s.FetchRetrieved, "fetch_failed": s.FetchFailed,
		"legacy_auto_fetches": s.LegacyAutoFetches, "legacy_retrieved": s.LegacyRetrieved,
		"legacy_failed": s.LegacyFailed,
		"cited_urls":    s.CitedURLs, "host_prompts": s.HostPrompts,
		"unique_prompted_hosts": s.UniquePromptedHosts, "unclassified_calls": s.UnclassifiedCalls,
	}
	for field, want := range wantSummary {
		if gotSummary[field] != want {
			t.Fatalf("summary %s = %d, want %d", field, gotSummary[field], want)
		}
	}

	first := report.Calls[0]
	if first.Record != 3 || first.CallID != "call_search_1" || first.Tool != "web_search" ||
		first.Shape != "candidate_search" || first.Query != "go 1.26 release notes" || first.Omitted != 1 {
		t.Fatalf("first call = %+v", first)
	}
	if len(first.Sources) != 3 {
		t.Fatalf("first call sources = %d, want 3", len(first.Sources))
	}
	if got := strings.Join(first.Sources[0].Stages, ","); got != "candidate,selected,cited" {
		t.Fatalf("cited candidate stages = %q", got)
	}
	if got := strings.Join(first.Sources[2].Stages, ","); got != "candidate" {
		t.Fatalf("uncited candidate stages = %q, want candidate alone", got)
	}
	legacy := report.Calls[4]
	if legacy.Shape != "legacy_auto_fetch" || len(legacy.Sources) != 2 || legacy.Sources[0].Outcome != "ok" {
		t.Fatalf("legacy call = %+v", legacy)
	}
	unreadable := report.Calls[5]
	if unreadable.Shape != "unclassified" || unreadable.Query != "" || len(unreadable.Sources) != 0 ||
		strings.Join(unreadable.Unclassified, ",") != "arguments,result" {
		t.Fatalf("unclassified call = %+v", unreadable)
	}
	raw := runResearch(t, researchFixturePath, "--json")
	for _, forbidden := range []string{"unused", "influence", "intent"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("--json report claims %q:\n%s", forbidden, raw)
		}
	}
}

func buildResearchRecords() []sessions.Record {
	return []sessions.Record{
		textMsg("user", "look it up"),
		eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
			SubjectKind: "host", Subject: "web_search", HostScope: "mcp.exa.ai",
		}),
		asstToolCall("call_s", "web_search", `{"query":"one question"}`),
		toolMsg("call_s", `{"candidates":[{"url":"https://ex.example.com/page"}]}`),
		asstToolCall("call_f", "web_fetch", `{"url":"https://ex.example.com/page"}`),
		toolMsg("call_f", `{"final_url":"https://ex.example.com/page","content":"text","outcome":"ok"}`),
		textMsg("assistant", "See https://ex.example.com/page for the detail."),
	}
}

func TestSessionsResearch_ResolvesByID(t *testing.T) {
	home := t.TempDir()
	rawCWD := t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(rawCWD)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	dir := filepath.Join(sessions.SessionRoot(home), sessions.FolderDirName(canonical))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	b, err := sessions.Marshal(&sessions.Session{
		Metadata: sessions.Metadata{
			ID: ids.NewV7(), Folder: canonical, StartedAt: fixtureTime, UpdatedAt: fixtureTime, SchemaVersion: 1,
		},
		Records: buildResearchRecords(),
	})
	if err != nil {
		t.Fatalf("marshal research fixture: %v", err)
	}
	id := ids.NewV7()
	if err := os.WriteFile(filepath.Join(dir, id+".json"), b, 0o600); err != nil {
		t.Fatalf("write research fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "folder"), []byte(canonical+"\n"), 0o644); err != nil {
		t.Fatalf("write folder file: %v", err)
	}
	stubHomeAndCwd(t, home, rawCWD)

	out := runResearch(t, id)
	for _, want := range []string{
		"web research calls: 2 (searches: 1, fetches: 1)",
		"https://ex.example.com/page  cited=https://ex.example.com/page  stages=candidate,selected,cited",
		"  urls cited in a later answer: 1",
		"  web host prompts: 1 shown, 1 unique hosts",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("id-resolved research output missing %q:\n%s", want, out)
		}
	}
}

func TestSessionsResearch_LoadErrors(t *testing.T) {
	dir := t.TempDir()
	newer := filepath.Join(dir, "newer.json")
	if err := os.WriteFile(newer, []byte(`{"type":"metadata","metadata":{"id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b","folder":"/f","started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":2}}`+"\n"), 0o600); err != nil {
		t.Fatalf("write newer: %v", err)
	}
	garbage := filepath.Join(dir, "garbage.json")
	if err := os.WriteFile(garbage, []byte("not a json object"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	orphanTool := writeSession(t, "orphan-tool", []sessions.Record{
		toolMsg("call_s", `{"candidates":[]}`),
	})
	badPayload := writeSession(t, "bad-payload", []sessions.Record{
		eventRecord(events.KindPermissionPromptShown, map[string]any{
			"subject_kind": "host", "subject": "web_search",
		}),
	})

	tests := []struct {
		name    string
		target  string
		wantSub string
	}{
		{"not found", filepath.Join(dir, "missing.json"), "not found"},
		{"newer schema_version", newer, "newer than this build supports"},
		{"parse failure", garbage, "cannot be parsed"},
		{"record stream failure", orphanTool, "no preceding assistant message with tool_calls"},
		{"event payload failure", badPayload, "host_scope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"codemeld", "sessions", "research", tt.target}, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantSub) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tt.wantSub)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout non-empty on load error: %q", stdout.String())
			}
		})
	}
}

func TestSessionsResearch_WebFreeSessionReportsAZeroFunnel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.json")
	writeFixture(t, path, "/some/folder")
	out := runResearch(t, path)

	for _, want := range []string{
		"web research calls: 0 (searches: 0, fetches: 0)",
		"  queries: 0 total, 0 unique (0 repeated)",
		"  candidate urls: 0 total, 0 unique (0 repeated)",
		"  web host prompts: 0 shown, 0 unique hosts",
		"uncited does not mean unused:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("web-free research output missing %q:\n%s", want, out)
		}
	}
	if report := researchJSONReport(t, path); len(report.Calls) != 0 || report.Summary.Searches != 0 {
		t.Fatalf("web-free JSON report = %+v, want no calls and no searches", report)
	}
}

func TestSessionsResearch_CitationNeedsAnExactLaterAnswer(t *testing.T) {
	const url = "https://ex.example.com/page"
	search := []sessions.Record{
		asstToolCall("call_s", "web_search", `{"query":"one question"}`),
		toolMsg("call_s", `{"candidates":[{"url":"`+url+`"}]}`),
	}
	withAnswer := func(answer string) []sessions.Record {
		return append(append([]sessions.Record{}, search...), textMsg("assistant", answer))
	}

	tests := []struct {
		name      string
		records   []sessions.Record
		wantCited bool
	}{
		{"the exact address in a later answer", withAnswer("Read " + url + " for detail."), true},
		{"the address ending a sentence", withAnswer("It is all in " + url + "."), true},
		{"the address inside parentheses", withAnswer("It is documented (" + url + ") already."), true},
		{"the address as a markdown link target", withAnswer("Read [the page](" + url + ") for detail."), true},
		{"only part of the address", withAnswer("Read https://ex.example.com/pa for detail."), false},
		{"the address inside another address's path", withAnswer("Read https://archive.example/2026/" + url + " instead."), false},
		{"the address inside another address's query", withAnswer("Read https://proxy.example/?u=" + url + " instead."), false},
		{"a longer path that begins with the address", withAnswer("Read " + url + "-2 for detail."), false},
		{"a longer path segment", withAnswer("Read " + url + "/section for detail."), false},
		{"the address extended by a file suffix", withAnswer("Read " + url + ".html for detail."), false},
		{"the address extended by a query", withAnswer("Read " + url + "?ref=1 for detail."), false},
		{"the address extended by a fragment", withAnswer("Read " + url + "#top for detail."), false},
		{"an answer that came before the search", append(
			[]sessions.Record{textMsg("assistant", "I already know about "+url+".")}, search...), false},
		{"the address only in the user's own prompt", append(
			append([]sessions.Record{}, search...), textMsg("user", "what about "+url+"?")), false},
		{"the address only in a later tool result", append(append([]sessions.Record{}, search...),
			asstToolCall("call_f", "web_fetch", `{"url":"https://other.example.com/x"}`),
			toolMsg("call_f", `{"content":"see `+url+`","outcome":"ok"}`)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runResearch(t, writeSession(t, "citation", tt.records))
			cited := strings.Contains(out, "stages=candidate,cited") || strings.Contains(out, "urls cited in a later answer: 1")
			if cited != tt.wantCited {
				t.Fatalf("cited = %v, want %v:\n%s", cited, tt.wantCited, out)
			}
		})
	}
}

func TestSessionsResearch_RedirectCitationNamesTheAddressTheAnswerRepeated(t *testing.T) {
	const requested = "https://ex.example.com/page"
	const final = "https://cdn.example.net/page-v2"
	out := runResearch(t, writeSession(t, "redirect", []sessions.Record{
		asstToolCall("call_f", "web_fetch", `{"url":"`+requested+`"}`),
		toolMsg("call_f", `{"final_url":"`+final+`","content":"text","outcome":"ok"}`),
		textMsg("assistant", "The detail is at "+final+"."),
	}))

	for _, want := range []string{
		"       " + requested + "  final_url=" + final + "  outcome=ok  cited=" + final + "  stages=retrieved,cited\n",
		"  urls cited in a later answer: 1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("redirect research output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "cited="+requested) {
		t.Fatalf("the requested address was reported as cited though only the final address was in the answer:\n%s", out)
	}
}

func TestSessionsResearch_RedirectCitationJSONCountsTheMatchedAddress(t *testing.T) {
	const requested = "https://ex.example.com/page"
	const finalA = "https://cdn.example.net/page-a"
	const finalB = "https://cdn.example.net/page-b"
	report := researchJSONReport(t, writeSession(t, "redirect-json", []sessions.Record{
		asstToolCall("call_f1", "web_fetch", `{"url":"`+requested+`"}`),
		toolMsg("call_f1", `{"final_url":"`+finalA+`","content":"text","outcome":"ok"}`),
		asstToolCall("call_f2", "web_fetch", `{"url":"`+requested+`"}`),
		toolMsg("call_f2", `{"final_url":"`+finalB+`","content":"text","outcome":"ok"}`),
		textMsg("assistant", "Both "+finalA+" and "+finalB+" say so."),
	}))

	if got := strings.Join(report.Calls[0].Sources[0].Cited, ","); got != finalA {
		t.Fatalf("first fetch cited = %q, want the final address alone", got)
	}
	if got := strings.Join(report.Calls[1].Sources[0].Cited, ","); got != finalB {
		t.Fatalf("second fetch cited = %q, want the final address alone", got)
	}
	if report.Summary.CitedURLs != 2 {
		t.Fatalf("cited_urls = %d, want 2 — two redirect destinations of one requested address", report.Summary.CitedURLs)
	}
}

func TestSessionsResearch_SelectionRequiresTheSearchToComeFirst(t *testing.T) {
	const url = "https://ex.example.com/page"
	out := runResearch(t, writeSession(t, "order", []sessions.Record{
		asstToolCall("call_f", "web_fetch", `{"url":"`+url+`"}`),
		toolMsg("call_f", `{"content":"text","outcome":"ok"}`),
		asstToolCall("call_s", "web_search", `{"query":"one question"}`),
		toolMsg("call_s", `{"candidates":[{"url":"`+url+`"}]}`),
	}))

	for _, want := range []string{
		"       " + url + "  outcome=ok  stages=retrieved\n",
		"       " + url + "  stages=candidate\n",
		"  candidates a later fetch selected: 0",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("research output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "selected") && !strings.Contains(out, "later fetch selected: 0") {
		t.Fatalf("a fetch issued before the search was reported as a selection:\n%s", out)
	}
}

func TestSessionsResearch_SchemaValidButUnreadablePayloads(t *testing.T) {
	tests := []struct {
		name         string
		records      []sessions.Record
		wantShape    string
		wantEvidence string
		wantSources  int
	}{
		{
			"candidates is not a list",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":"oops"}`),
			},
			"candidate_search", "unclassified=result", 0,
		},
		{
			"a candidate carries no address",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":[{"title":"no address"},{"url":"https://ok.example.com/a"}]}`),
			},
			"candidate_search", "unclassified=result", 1,
		},
		{
			"a candidate address that is only whitespace",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":[{"url":"   "}]}`),
			},
			"candidate_search", "unclassified=result", 0,
		},
		{
			"a candidate address the fetch path would refuse",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":[{"url":"http://example.test/a"}]}`),
			},
			"candidate_search", "unclassified=result", 0,
		},
		{
			"a candidate address in a non-canonical spelling",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":[{"url":"HTTPS://OK.Example.COM/a"}]}`),
			},
			"candidate_search", "unclassified=result", 0,
		},
		{
			"a candidate title that is not a string",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":[{"url":"https://ok.example.com/a","title":7}]}`),
			},
			"candidate_search", "unclassified=result", 1,
		},
		{
			"a candidate snippet that is null",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":[{"url":"https://ok.example.com/a","snippet":null}]}`),
			},
			"candidate_search", "unclassified=result", 1,
		},
		{
			"a candidate published date that is not a string",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":[{"url":"https://ok.example.com/a","published_date":[]}]}`),
			},
			"candidate_search", "unclassified=result", 1,
		},
		{
			"a candidate address longer than the producer stores",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":[{"url":"https://ok.example.com/`+strings.Repeat("a", 2048)+`"}]}`),
			},
			"candidate_search", "unclassified=result", 0,
		},
		{
			"a candidate title longer than the producer stores",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":[{"url":"https://ok.example.com/a","title":"`+
					strings.Repeat("t", 513)+`"}]}`),
			},
			"candidate_search", "unclassified=result", 1,
		},
		{
			"a candidate snippet longer than the producer stores",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":[{"url":"https://ok.example.com/a","snippet":"`+
					strings.Repeat("s", 4097)+`"}]}`),
			},
			"candidate_search", "unclassified=result", 1,
		},
		{
			"a candidate published date longer than the producer stores",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":[{"url":"https://ok.example.com/a","published_date":"`+
					strings.Repeat("d", 513)+`"}]}`),
			},
			"candidate_search", "unclassified=result", 1,
		},
		{
			"omitted is not a number",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":[],"omitted":"lots"}`),
			},
			"candidate_search", "unclassified=result", 0,
		},
		{
			"omitted is negative",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":[],"omitted":-1}`),
			},
			"candidate_search", "unclassified=result", 0,
		},
		{
			"a legacy source carries no address",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"sources":[{"outcome":"ok"}]}`),
			},
			"legacy_auto_fetch", "unclassified=result", 0,
		},
		{
			"a legacy source carries no outcome",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"sources":[{"url":"https://legacy.example.com/a"}]}`),
			},
			"legacy_auto_fetch", "unclassified=result", 1,
		},
		{
			"a legacy source title that is not a string",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"sources":[{"url":"https://legacy.example.com/a","title":7,"outcome":"request_failed"}]}`),
			},
			"legacy_auto_fetch", "unclassified=result", 1,
		},
		{
			"legacy source content that is null",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"sources":[{"url":"https://legacy.example.com/a","content":null,"outcome":"request_failed"}]}`),
			},
			"legacy_auto_fetch", "unclassified=result", 1,
		},
		{
			"a result object with neither shape",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"note":"something else"}`),
			},
			"unclassified", "unclassified=result", 0,
		},
		{
			"the candidate collection is null",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":null}`),
			},
			"candidate_search", "unclassified=result", 0,
		},
		{
			"the legacy collection is null",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"sources":null}`),
			},
			"legacy_auto_fetch", "unclassified=result", 0,
		},
		{
			"a result carrying both the current and the legacy shape",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"candidates":[{"url":"https://a.example.com/1"}],`+
					`"sources":[{"url":"https://b.example.com/2","outcome":"ok"}]}`),
			},
			"unclassified", "unclassified=result", 0,
		},
		{
			"search arguments that are not a JSON string",
			[]sessions.Record{
				asstToolCallFunction("call_s", `{"name":"web_search","arguments":{"query":"q"}}`),
				toolMsg("call_s", `{"candidates":[]}`),
			},
			"candidate_search", "unclassified=arguments", 0,
		},
		{
			"search arguments that are null",
			[]sessions.Record{
				asstToolCallFunction("call_s", `{"name":"web_search","arguments":null}`),
				toolMsg("call_s", `{"candidates":[]}`),
			},
			"candidate_search", "unclassified=arguments", 0,
		},
		{
			"search arguments that are absent",
			[]sessions.Record{
				asstToolCallFunction("call_s", `{"name":"web_search"}`),
				toolMsg("call_s", `{"candidates":[]}`),
			},
			"candidate_search", "unclassified=arguments", 0,
		},
		{
			"fetch arguments that are not a JSON string",
			[]sessions.Record{
				asstToolCallFunction("call_f", `{"name":"web_fetch","arguments":{"url":"https://ok.example.com/a"}}`),
				toolMsg("call_f", `{"outcome":"request_failed"}`),
			},
			"fetch", "unclassified=arguments", 0,
		},
		{
			"fetch arguments that are absent",
			[]sessions.Record{
				asstToolCallFunction("call_f", `{"name":"web_fetch"}`),
				toolMsg("call_f", `{"outcome":"request_failed"}`),
			},
			"fetch", "unclassified=arguments", 0,
		},
		{
			"a whitespace-only search query",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"   "}`),
				toolMsg("call_s", `{"candidates":[]}`),
			},
			"candidate_search", "unclassified=arguments", 0,
		},
		{
			"a whitespace-only fetch address",
			[]sessions.Record{
				asstToolCall("call_f", "web_fetch", `{"url":"\t "}`),
				toolMsg("call_f", `{"outcome":"ok"}`),
			},
			"fetch", "unclassified=arguments", 0,
		},
		{
			"a search argument object without a query",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"limit":5}`),
				toolMsg("call_s", `{"candidates":[]}`),
			},
			"candidate_search", "unclassified=arguments", 0,
		},
		{
			"a fetch result with no outcome",
			[]sessions.Record{
				asstToolCall("call_f", "web_fetch", `{"url":"https://ok.example.com/a"}`),
				toolMsg("call_f", `{"final_url":"https://ok.example.com/a"}`),
			},
			"fetch", "unclassified=result", 1,
		},
		{
			"a fetch result whose outcome is not a string",
			[]sessions.Record{
				asstToolCall("call_f", "web_fetch", `{"url":"https://ok.example.com/a"}`),
				toolMsg("call_f", `{"outcome":404}`),
			},
			"fetch", "unclassified=result", 1,
		},
		{
			"a fetch with an empty address",
			[]sessions.Record{
				asstToolCall("call_f", "web_fetch", `{"url":""}`),
				toolMsg("call_f", `{"outcome":"ok"}`),
			},
			"fetch", "unclassified=arguments", 0,
		},
		{
			"a denial envelope in place of a result",
			[]sessions.Record{
				asstToolCall("call_f", "web_fetch", `{"url":"https://ok.example.com/a"}`),
				toolMsg("call_f", "permission denied for host ok.example.com"),
			},
			"fetch", "unclassified=result", 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runResearch(t, writeSession(t, "unreadable", tt.records))
			for _, want := range []string{"shape=" + tt.wantShape, tt.wantEvidence, "calls with unclassified evidence: 1"} {
				if !strings.Contains(out, want) {
					t.Fatalf("research output missing %q:\n%s", want, out)
				}
			}
			if got := strings.Count(out, "  stages="); got != tt.wantSources {
				t.Fatalf("addresses reported = %d, want %d:\n%s", got, tt.wantSources, out)
			}
			for _, guessed := range []string{"stages=candidate,selected", "cited", "retrieved"} {
				if strings.Contains(out, guessed+"\n") {
					t.Fatalf("an unreadable payload produced the stage %q:\n%s", guessed, out)
				}
			}
		})
	}
}

func TestSessionsResearch_CandidateURLsOutsideTheContractAreNotFunnelFacts(t *testing.T) {
	const persisted = "https://ok.example.com/a"
	rejected := []string{"http://example.test/a", "HTTPS://OK.Example.COM/a"}
	path := writeSession(t, "candidate-contract", []sessions.Record{
		asstToolCall("call_s", "web_search", `{"query":"q"}`),
		toolMsg("call_s", `{"candidates":[{"url":"   "},{"url":"`+rejected[0]+`"},`+
			`{"url":"`+rejected[1]+`"},{"url":"`+persisted+`"}]}`),
	})

	out := runResearch(t, path)
	for _, want := range []string{
		`shape=candidate_search  query="q"  unclassified=result`,
		"  candidate urls: 1 total, 1 unique (0 repeated)",
		"  calls with unclassified evidence: 1",
		"       " + persisted + "  stages=candidate\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("research output missing %q:\n%s", want, out)
		}
	}
	for _, address := range rejected {
		if strings.Contains(out, address) {
			t.Fatalf("out-of-contract candidate %q was reported as evidence:\n%s", address, out)
		}
	}
	if got := strings.Count(out, "  stages="); got != 1 {
		t.Fatalf("addresses reported = %d, want 1:\n%s", got, out)
	}

	report := researchJSONReport(t, path)
	if len(report.Calls) != 1 {
		t.Fatalf("json calls = %d, want 1", len(report.Calls))
	}
	call := report.Calls[0]
	if len(call.Sources) != 1 || call.Sources[0].URL != persisted {
		t.Fatalf("json sources = %+v, want only %q", call.Sources, persisted)
	}
	if len(call.Sources[0].Stages) != 1 || call.Sources[0].Stages[0] != "candidate" {
		t.Fatalf("json stages = %v, want [candidate]", call.Sources[0].Stages)
	}
	if len(call.Unclassified) != 1 || call.Unclassified[0] != "result" {
		t.Fatalf("json unclassified = %v, want [result]", call.Unclassified)
	}
	if report.Summary.CandidateURLs != 1 || report.Summary.UnclassifiedCalls != 1 {
		t.Fatalf("candidate urls = %d, unclassified calls = %d, want 1 and 1",
			report.Summary.CandidateURLs, report.Summary.UnclassifiedCalls)
	}
}

func TestSessionsResearch_MoreCandidatesThanTheProducerStoresAreNotFunnelFacts(t *testing.T) {
	const excluded = "https://ok.example.com/6"
	path := writeSession(t, "candidate-count", []sessions.Record{
		asstToolCall("call_s", "web_search", `{"query":"q"}`),
		toolMsg("call_s", `{"candidates":[{"url":"https://ok.example.com/1"},{"url":"https://ok.example.com/2"},`+
			`{"url":"https://ok.example.com/3"},{"url":"https://ok.example.com/4"},`+
			`{"url":"https://ok.example.com/5"},{"url":"`+excluded+`"}]}`),
	})

	out := runResearch(t, path)
	for _, want := range []string{
		`shape=candidate_search  query="q"  unclassified=result`,
		"  candidate urls: 5 total, 5 unique (0 repeated)",
		"  calls with unclassified evidence: 1",
		"       https://ok.example.com/1  stages=candidate\n",
		"       https://ok.example.com/5  stages=candidate\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("research output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, excluded) {
		t.Fatalf("a candidate past the producer's collection bound was reported:\n%s", out)
	}
	if got := strings.Count(out, "  stages="); got != 5 {
		t.Fatalf("addresses reported = %d, want 5:\n%s", got, out)
	}

	report := researchJSONReport(t, path)
	if len(report.Calls) != 1 || len(report.Calls[0].Sources) != 5 {
		t.Fatalf("json calls = %+v, want one call with 5 sources", report.Calls)
	}
	if len(report.Calls[0].Unclassified) != 1 || report.Calls[0].Unclassified[0] != "result" {
		t.Fatalf("json unclassified = %v, want [result]", report.Calls[0].Unclassified)
	}
	if report.Summary.CandidateURLs != 5 || report.Summary.UnclassifiedCalls != 1 {
		t.Fatalf("candidate urls = %d, unclassified calls = %d, want 5 and 1",
			report.Summary.CandidateURLs, report.Summary.UnclassifiedCalls)
	}
}

func TestSessionsResearch_FinalURLOutsideTheFetchContractIsUnclassifiedResult(t *testing.T) {
	const requested = "https://ok.example.com/a"
	const forged = "https://forged.example/result"
	overlong := "https://ok.example.com/" + strings.Repeat("a", 2048)
	tests := []struct {
		name    string
		records []sessions.Record
		want    []string
	}{
		{
			"an explicit-fetch final address that is not an address",
			[]sessions.Record{
				asstToolCall("call_f", "web_fetch", `{"url":"`+requested+`"}`),
				toolMsg("call_f", `{"outcome":"ok","final_url":"not-a-url"}`),
			},
			[]string{"shape=fetch", "       " + requested + "  outcome=ok  stages=retrieved\n"},
		},
		{
			"an explicit-fetch final address longer than the producer stores",
			[]sessions.Record{
				asstToolCall("call_f", "web_fetch", `{"url":"`+requested+`"}`),
				toolMsg("call_f", `{"outcome":"ok","final_url":"`+overlong+`"}`),
			},
			[]string{"shape=fetch", "       " + requested + "  outcome=ok  stages=retrieved\n"},
		},
		{
			"an explicit-fetch final address on a failed outcome",
			[]sessions.Record{
				asstToolCall("call_f", "web_fetch", `{"url":"`+requested+`"}`),
				toolMsg("call_f", `{"outcome":"request_failed","final_url":"`+forged+`"}`),
			},
			[]string{"shape=fetch", "       " + requested + "  outcome=request_failed  stages=failed\n"},
		},
		{
			"a legacy final address that is not an address",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"legacy bundle"}`),
				toolMsg("call_s", `{"sources":[{"url":"`+requested+`","final_url":"not-a-url","outcome":"ok"}]}`),
			},
			[]string{
				"shape=legacy_auto_fetch",
				"       " + requested + "  outcome=ok  stages=candidate,retrieved\n",
			},
		},
		{
			"a legacy final address on a failed outcome",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"legacy bundle"}`),
				toolMsg("call_s", `{"sources":[{"url":"`+requested+`","final_url":"`+forged+
					`","outcome":"request_failed"}]}`),
			},
			[]string{
				"shape=legacy_auto_fetch",
				"       " + requested + "  outcome=request_failed  stages=candidate,failed\n",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runResearch(t, writeSession(t, "final-url-contract", tt.records))
			for _, want := range append(tt.want, "unclassified=result", "  calls with unclassified evidence: 1") {
				if !strings.Contains(out, want) {
					t.Fatalf("research output missing %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, "final_url=") {
				t.Fatalf("a final address outside the fetch contract was reported:\n%s", out)
			}
			if strings.Contains(out, forged) || strings.Contains(out, overlong) {
				t.Fatalf("an out-of-contract final address reached the report:\n%s", out)
			}
		})
	}
}

func TestSessionsResearch_FinalURLOutsideTheFetchContractIsNeverCited(t *testing.T) {
	const requested = "https://ok.example.com/a"
	const forged = "https://forged.example/result"
	path := writeSession(t, "final-url-citation", []sessions.Record{
		asstToolCall("call_f", "web_fetch", `{"url":"`+requested+`"}`),
		toolMsg("call_f", `{"outcome":"request_failed","final_url":"`+forged+`"}`),
		textMsg("assistant", "the answer is at "+forged+" as recorded."),
	})

	out := runResearch(t, path)
	for _, unwanted := range []string{"cited=", forged} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("a final address outside the fetch contract was cited (%q present):\n%s", unwanted, out)
		}
	}
	if !strings.Contains(out, "  urls cited in a later answer: 0") {
		t.Fatalf("research output missing a zero citation count:\n%s", out)
	}

	report := researchJSONReport(t, path)
	if report.Summary.CitedURLs != 0 {
		t.Fatalf("cited_urls = %d, want 0", report.Summary.CitedURLs)
	}
	if len(report.Calls) != 1 || len(report.Calls[0].Sources) != 1 {
		t.Fatalf("json calls = %+v, want one call with one source", report.Calls)
	}
	src := report.Calls[0].Sources[0]
	if src.FinalURL != "" || len(src.Cited) != 0 {
		t.Fatalf("json source = %+v, want no final_url and no citation", src)
	}
}

func TestSessionsResearch_WhitespaceArgumentsAreNotFunnelFacts(t *testing.T) {
	out := runResearch(t, writeSession(t, "whitespace", []sessions.Record{
		asstToolCall("call_s", "web_search", `{"query":"  "}`),
		toolMsg("call_s", `{"candidates":[{"url":"https://ok.example.com/a"}]}`),
		asstToolCall("call_f", "web_fetch", `{"url":"   "}`),
		toolMsg("call_f", `{"outcome":"ok"}`),
	}))

	for _, want := range []string{
		"  queries: 0 total, 0 unique (0 repeated)",
		"  candidate urls: 1 total, 1 unique (0 repeated)",
		"  candidates a later fetch selected: 0",
		"  explicit fetches: 1 (retrieved: 0, failed: 0)",
		"  urls cited in a later answer: 0",
		"  calls with unclassified evidence: 2",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("research output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "query=") {
		t.Fatalf("a whitespace-only query was reported as a query:\n%s", out)
	}
	if got := strings.Count(out, "  stages="); got != 1 {
		t.Fatalf("addresses reported = %d, want 1 — the whitespace fetch address is not a source:\n%s", got, out)
	}
}

func TestSessionsResearch_DuplicateCallIDsShareNoResult(t *testing.T) {
	const first = "https://dup.example.com/a"
	const second = "https://dup.example.com/b"
	group := sessions.Message{
		ID: ids.NewV7(), Role: "assistant", Content: sessions.TextContent(""), Timestamp: fixtureTime,
		ToolCalls: []sessions.ToolCall{
			{ID: "call_d", Type: "function", Raw: toolCallRaw("call_d", "web_fetch", `{"url":"`+first+`"}`)},
			{ID: "call_d", Type: "function", Raw: toolCallRaw("call_d", "web_fetch", `{"url":"`+second+`"}`)},
		},
	}
	path := writeSession(t, "duplicate-ids", []sessions.Record{
		group,
		toolMsg("call_d", `{"outcome":"ok","final_url":"`+first+`"}`),
	})
	out := runResearch(t, path)

	for _, want := range []string{
		"       " + first + "  stages=none\n",
		"       " + second + "  stages=none\n",
		"  explicit fetches: 2 (retrieved: 0, failed: 0)",
		"  calls with unclassified evidence: 2",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("research output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "outcome=ok") || strings.Contains(out, "final_url=") {
		t.Fatalf("one response was attached to a duplicate-id call:\n%s", out)
	}
	report := researchJSONReport(t, path)
	if len(report.Calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(report.Calls))
	}
	for i, c := range report.Calls {
		if len(c.Sources) != 1 || c.Sources[0].Outcome != "" || len(c.Sources[0].Stages) != 0 {
			t.Fatalf("call %d reported result evidence from a shared response: %+v", i, c.Sources)
		}
	}
}

func TestSessionsResearch_LegacySourceRefetchedLaterIsNotSelected(t *testing.T) {
	const address = "https://legacy.example.com/a"
	path := writeSession(t, "legacy-refetched", []sessions.Record{
		asstToolCall("call_s", "web_search", `{"query":"legacy bundle"}`),
		toolMsg("call_s", `{"sources":[{"url":"`+address+`","outcome":"ok"}]}`),
		asstToolCall("call_f", "web_fetch", `{"url":"`+address+`"}`),
		toolMsg("call_f", `{"outcome":"ok"}`),
	})
	out := runResearch(t, path)

	for _, want := range []string{
		"shape=legacy_auto_fetch",
		"       " + address + "  outcome=ok  stages=candidate,retrieved\n",
		"       " + address + "  outcome=ok  stages=selected,retrieved\n",
		"  searches: 1 (legacy auto-fetch: 1)",
		"  candidates a later fetch selected: 0",
		"  explicit fetches: 1 (retrieved: 1, failed: 0)",
		"  legacy auto-fetches: 1 (retrieved: 1, failed: 0)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("research output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "stages=candidate,selected") {
		t.Fatalf("a later fetch made a legacy auto-fetch an explicit selection:\n%s", out)
	}

	report := researchJSONReport(t, path)
	if len(report.Calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(report.Calls))
	}
	legacy := report.Calls[0]
	if legacy.Shape != "legacy_auto_fetch" || len(legacy.Sources) != 1 {
		t.Fatalf("legacy call = %+v", legacy)
	}
	for _, stage := range legacy.Sources[0].Stages {
		if stage == "selected" {
			t.Fatalf("legacy source stages = %v, want no selected", legacy.Sources[0].Stages)
		}
	}
	if report.Summary.SelectedCandidates != 0 {
		t.Fatalf("selected_candidates = %d, want 0", report.Summary.SelectedCandidates)
	}
}

func TestSessionsResearch_UnreadableFinalURLIsUnclassifiedResult(t *testing.T) {
	const requested = "https://ok.example.com/a"
	out := runResearch(t, writeSession(t, "final-url", []sessions.Record{
		asstToolCall("call_f", "web_fetch", `{"url":"`+requested+`"}`),
		toolMsg("call_f", `{"outcome":"ok","final_url":7}`),
	}))

	for _, want := range []string{
		"shape=fetch",
		"unclassified=result",
		"       " + requested + "  outcome=ok  stages=retrieved\n",
		"  calls with unclassified evidence: 1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("research output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "final_url=") {
		t.Fatalf("an unreadable final address was reported as a redirect destination:\n%s", out)
	}
}

func TestSessionsResearch_UnreadableFetchContentIsUnclassifiedResult(t *testing.T) {
	const requested = "https://ok.example.com/a"
	out := runResearch(t, writeSession(t, "fetch-content", []sessions.Record{
		asstToolCall("call_f", "web_fetch", `{"url":"`+requested+`"}`),
		toolMsg("call_f", `{"content":7,"outcome":"ok"}`),
	}))

	for _, want := range []string{
		"shape=fetch",
		"unclassified=result",
		"       " + requested + "  outcome=ok  stages=retrieved\n",
		"  calls with unclassified evidence: 1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("research output missing %q:\n%s", want, out)
		}
	}
}

func TestSessionsResearch_NullResultFieldsAreUnclassifiedResult(t *testing.T) {
	const requested = "https://ok.example.com/a"
	tests := []struct {
		name    string
		records []sessions.Record
		want    []string
		notWant string
	}{
		{
			"a null omitted count is not a confirmed zero",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"one question"}`),
				toolMsg("call_s", `{"candidates":[{"url":"`+requested+`"}],"omitted":null}`),
			},
			[]string{"shape=candidate_search", "unclassified=result", "       " + requested + "  stages=candidate\n"},
			"omitted candidates:",
		},
		{
			"a null explicit-fetch final address is not an absent one",
			[]sessions.Record{
				asstToolCall("call_f", "web_fetch", `{"url":"`+requested+`"}`),
				toolMsg("call_f", `{"outcome":"ok","final_url":null}`),
			},
			[]string{"shape=fetch", "unclassified=result", "       " + requested + "  outcome=ok  stages=retrieved\n"},
			"final_url=",
		},
		{
			"a null legacy final address is not an absent one",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"legacy bundle"}`),
				toolMsg("call_s", `{"sources":[{"url":"`+requested+`","final_url":null,"outcome":"ok"}]}`),
			},
			[]string{
				"shape=legacy_auto_fetch", "unclassified=result",
				"       " + requested + "  outcome=ok  stages=candidate,retrieved\n",
			},
			"final_url=",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runResearch(t, writeSession(t, "null-field", tt.records))
			for _, want := range append(tt.want, "  calls with unclassified evidence: 1") {
				if !strings.Contains(out, want) {
					t.Fatalf("research output missing %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, tt.notWant) {
				t.Fatalf("a null field was reported as a value (%q present):\n%s", tt.notWant, out)
			}
		})
	}
}

func TestSessionsResearch_BlankFinalURLIsUnclassifiedResult(t *testing.T) {
	const requested = "https://ok.example.com/a"
	tests := []struct {
		name    string
		records []sessions.Record
		want    []string
	}{
		{
			"an empty explicit-fetch final address",
			[]sessions.Record{
				asstToolCall("call_f", "web_fetch", `{"url":"`+requested+`"}`),
				toolMsg("call_f", `{"outcome":"ok","final_url":""}`),
			},
			[]string{"shape=fetch", "       " + requested + "  outcome=ok  stages=retrieved\n"},
		},
		{
			"a whitespace-only explicit-fetch final address",
			[]sessions.Record{
				asstToolCall("call_f", "web_fetch", `{"url":"`+requested+`"}`),
				toolMsg("call_f", `{"outcome":"ok","final_url":"   "}`),
			},
			[]string{"shape=fetch", "       " + requested + "  outcome=ok  stages=retrieved\n"},
		},
		{
			"an empty legacy final address",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"legacy bundle"}`),
				toolMsg("call_s", `{"sources":[{"url":"`+requested+`","final_url":"","outcome":"ok"}]}`),
			},
			[]string{
				"shape=legacy_auto_fetch",
				"       " + requested + "  outcome=ok  stages=candidate,retrieved\n",
			},
		},
		{
			"a whitespace-only legacy final address",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"legacy bundle"}`),
				toolMsg("call_s", `{"sources":[{"url":"`+requested+`","final_url":"  ","outcome":"ok"}]}`),
			},
			[]string{
				"shape=legacy_auto_fetch",
				"       " + requested + "  outcome=ok  stages=candidate,retrieved\n",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runResearch(t, writeSession(t, "blank-final-url", tt.records))
			for _, want := range append(tt.want, "unclassified=result", "  calls with unclassified evidence: 1") {
				if !strings.Contains(out, want) {
					t.Fatalf("research output missing %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, "final_url=") {
				t.Fatalf("a blank final address was reported as a redirect destination:\n%s", out)
			}
		})
	}
}

func TestSessionsResearch_OutcomeOutsideThePersistedSetIsNotAFailure(t *testing.T) {
	tests := []struct {
		name    string
		records []sessions.Record
		want    []string
	}{
		{
			"an explicit fetch outcome the contract never emits",
			[]sessions.Record{
				asstToolCall("call_f", "web_fetch", `{"url":"https://ok.example.com/a"}`),
				toolMsg("call_f", `{"outcome":"future_value"}`),
			},
			[]string{
				"shape=fetch  unclassified=result",
				"       https://ok.example.com/a  outcome=future_value  stages=none\n",
				"  explicit fetches: 1 (retrieved: 0, failed: 0)",
				"  calls with unclassified evidence: 1",
			},
		},
		{
			"a legacy bundle outcome the contract never emits",
			[]sessions.Record{
				asstToolCall("call_s", "web_search", `{"query":"q"}`),
				toolMsg("call_s", `{"sources":[{"url":"https://legacy.example.com/a","outcome":"future_value"}]}`),
			},
			[]string{
				"shape=legacy_auto_fetch",
				"unclassified=result",
				"       https://legacy.example.com/a  outcome=future_value  stages=candidate\n",
				"  legacy auto-fetches: 1 (retrieved: 0, failed: 0)",
				"  calls with unclassified evidence: 1",
			},
		},
		{
			"every outcome the contract does emit still carries a stage",
			[]sessions.Record{
				asstToolCall("call_1", "web_fetch", `{"url":"https://ok.example.com/1"}`),
				toolMsg("call_1", `{"outcome":"ok"}`),
				asstToolCall("call_2", "web_fetch", `{"url":"https://ok.example.com/2"}`),
				toolMsg("call_2", `{"outcome":"request_failed"}`),
				asstToolCall("call_3", "web_fetch", `{"url":"https://ok.example.com/3"}`),
				toolMsg("call_3", `{"outcome":"response_too_large"}`),
				asstToolCall("call_4", "web_fetch", `{"url":"https://ok.example.com/4"}`),
				toolMsg("call_4", `{"outcome":"unsupported_content"}`),
				asstToolCall("call_5", "web_fetch", `{"url":"https://ok.example.com/5"}`),
				toolMsg("call_5", `{"outcome":"extraction_failed"}`),
			},
			[]string{
				"  explicit fetches: 5 (retrieved: 1, failed: 4)",
				"  calls with unclassified evidence: 0",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runResearch(t, writeSession(t, "outcome", tt.records))
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Fatalf("research output missing %q:\n%s", want, out)
				}
			}
		})
	}
}

func TestSessionsResearch_LeavesTheSessionUnchanged(t *testing.T) {
	before, err := os.ReadFile(researchFixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	runResearch(t, researchFixturePath)
	runResearch(t, researchFixturePath, "--json")

	after, err := os.ReadFile(researchFixturePath)
	if err != nil {
		t.Fatalf("re-read fixture: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("the research report modified %s", researchFixturePath)
	}
	entries, err := os.ReadDir(filepath.Dir(researchFixturePath))
	if err != nil {
		t.Fatalf("read testdata dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "sessions-research.json.") {
			t.Fatalf("the research report wrote a sidecar file: %s", e.Name())
		}
	}
}

func TestSessionsHelp(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		wants []string
		// notWants pins text that only the parent screen carries, so a nested help
		// form that silently falls back to the parent fails instead of passing on
		// the substrings the two screens share.
		notWants []string
	}{
		{
			name: "sessions -h",
			args: []string{"codemeld", "sessions", "-h"},
			// Parent help must clearly list EVERY leaf with its accepted
			// target form and distinct purpose, not just the bare subcommand names,
			// so a user can discover `show` without already knowing it exists. Pin the
			// exact invocations (not bare "show"/"sessions") to lock the discovery path.
			wants: []string{
				"list and inspect recorded sessions: list, doctor, show, permissions, research, summary (read-only diagnostics)",
				"codemeld sessions list [--all] [--json]",
				"list recorded sessions for the current folder, or every recorded folder with --all",
				"codemeld sessions doctor <session-id|path>",
				"codemeld sessions show <session-id|path> [options]",
				"codemeld sessions permissions <session-id|path>",
				"codemeld sessions research <session-id|path>",
				"codemeld sessions summary <session-id|path>",
				"report a session's recorded errors, failures, and anomalies",
				"render a session's message, event, and compaction records in order",
				"list the permission prompts a human was shown, their decisions, and the explicit revocation requests",
				"report the web searches, the sources fetched, and which of them a later answer cited",
				"report a session's execution records, permission path scopes, turns, and tokens",
				"prompts a human was shown with their decisions and the explicit revocation",
				"codemeld sessions permissions <session-id|path>  list the permission prompts shown, their decisions, and explicit revocation requests",
				"An id is found no matter which directory you run from:",
				"which refuses a session recorded in another",
				"these commands only read, so they report the session and name the folder it was",
				"narrowed with --kind, --turn, and --last, or",
			},
		},
		{
			name: "sessions research -h",
			args: []string{"codemeld", "sessions", "research", "-h"},
			wants: []string{
				"codemeld sessions research <session-id|path> [--json]",
				"--json",
				"'candidate'",
				"'selected'",
				"Uncited does not",
				"mean unused",
				"is NOT evidence that the model",
				"legacy auto-fetches",
			},
		},
		{
			name: "help sessions research",
			args: []string{"codemeld", "help", "sessions", "research"},
			wants: []string{
				"codemeld sessions research <session-id|path> [--json]",
				"mean unused",
				"is NOT evidence that the model",
			},
			notWants: []string{"codemeld sessions doctor", "inspect recorded sessions"},
		},
		{
			name: "sessions permissions -h",
			args: []string{"codemeld", "sessions", "permissions", "-h"},
			wants: []string{
				"codemeld sessions permissions <session-id|path> [--json]",
				"granted, denied, or pending",
				"never reached a human",
				"declared_scope",
				"declared_command",
				"open_read",
				"confined",
				"system_one_check",
				"System One checks",
				"skipped checks by reason too: paused",
				"structural reason (text, blocked_paths_unavailable, substitution, blocked_path,",
				"wrapper, program_location, shell_shape) when the command could not qualify and",
				"no model was asked",
				"t_read_only",
				"blocked_path",
				"protected_state",
				"--json",
				"grant=allow_once",
				"scope escalation",
				"explicit revocation requests",
				"never inferred from a settings file",
				"not proof that this run is what",
				"through the /settings revoke control",
				"A recorded request means /settings saw",
			},
			notWants: []string{"/permissions"},
		},
		{
			name: "help sessions permissions",
			args: []string{"codemeld", "help", "sessions", "permissions"},
			wants: []string{
				"codemeld sessions permissions <session-id|path> [--json]",
				"granted, denied, or pending",
				"scope escalation",
				"System One checks",
				"explicit revocation requests",
			},
			notWants: []string{"codemeld sessions doctor", "inspect recorded sessions"},
		},
		{
			name: "sessions doctor -h",
			args: []string{"codemeld", "sessions", "doctor", "-h"},
			wants: []string{
				"codemeld sessions doctor", "--json", "report a session's recorded errors",
				"reason=incomplete_round", "Neither is replayed or repaired",
				"names its subject_kind, invocation_id, and duration_ms,",
				"identifies the tool as failed_tool by program name only: the executable for",
				"a direct run, the tool name for a structured or vcs_* run, and nothing at all",
				"for an 'sh -c' literal, whose script cannot be reduced to a safe name",
				"recorded command's arguments and its captured stdout and stderr are never",
				"security_state_halted, and a non-zero tool exit code are errors",
				"A security_state_halted finding names the protected settings file and the point",
				"halt has no turn or round to close, so it is reported on its own",
			},
		},
		{
			name: "sessions show -h",
			args: []string{"codemeld", "sessions", "show", "-h"},
			// Pin the exact UsageText and every flag: a selection flag that ships
			// undocumented has to fail here rather than reach a user.
			wants: []string{
				"codemeld sessions show <session-id|path> [options]",
				"Tool-call", "message, event, and compaction records", "compaction record",
				"--kind", "--turn", "--last", "--json",
				"records: <selected> of <total>",
				"Each skill load is a skill_loaded event",
				"--kind skill_loaded lists only the skill loads.",
			},
		},
		{
			name: "sessions show --help",
			args: []string{"codemeld", "sessions", "show", "--help"},
			wants: []string{
				"codemeld sessions show <session-id|path> [options]",
				"--kind", "--turn", "--last", "--json",
			},
		},
		{
			// The nested `help` form must reach the leaf, not silently print the
			// parent screen with the trailing topic dropped.
			name: "help sessions show",
			args: []string{"codemeld", "help", "sessions", "show"},
			wants: []string{
				"codemeld sessions show <session-id|path> [options]",
				"Tool-call", "message, event, and compaction records", "compaction record",
				"--kind", "--turn", "--last", "--json",
			},
			notWants: []string{"codemeld sessions doctor", "inspect recorded sessions"},
		},
		{
			name:     "help sessions doctor",
			args:     []string{"codemeld", "help", "sessions", "doctor"},
			wants:    []string{"codemeld sessions doctor", "--json", "report a session's recorded errors"},
			notWants: []string{"codemeld sessions show", "inspect recorded sessions"},
		},
		{
			// A single topic keeps the library's own help path.
			name: "help sessions",
			args: []string{"codemeld", "help", "sessions"},
			wants: []string{
				"list and inspect recorded sessions: list, doctor, show, permissions, research, summary (read-only diagnostics)",
				"codemeld sessions list [--all] [--json]",
				"codemeld sessions show <session-id|path> [options]",
				"narrowed with --kind, --turn, and --last, or",
				"emitted machine-readably with --json",
				"codemeld sessions permissions <session-id|path>",
				"codemeld sessions research <session-id|path>",
				"codemeld sessions summary <session-id|path>",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubNoLaunch(t)
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), tt.args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
			}
			out := stdout.String()
			for _, want := range tt.wants {
				if !strings.Contains(out, want) {
					t.Fatalf("help (%v) missing %q:\n%s", tt.args, want, out)
				}
			}
			for _, notWant := range tt.notWants {
				if strings.Contains(out, notWant) {
					t.Fatalf("help (%v) unexpectedly contains %q (parent help?):\n%s", tt.args, notWant, out)
				}
			}
		})
	}
}

// TestSessionsPermissions_RevocationsComeOnlyFromRecords proves the report never invents a
// revocation. A session that recorded none — a legacy session, or one where a grant simply vanished
// from a settings file — reports zero, in the text tally and as an empty JSON list.
func TestSessionsPermissions_RevocationsComeOnlyFromRecords(t *testing.T) {
	records := []sessions.Record{
		promptEvent("tool", "edit", auditSub, nil),
		grantEvent("tool", "edit", auditSub, "folder", auditSub, "write"),
	}
	path := writeSession(t, "no-revocations", records)

	text := runPermissions(t, path)
	if want := "explicit revocation requests: 0"; !strings.Contains(text, want) {
		t.Fatalf("permissions text missing %q:\n%s", want, text)
	}
	if strings.Contains(text, "[permissions_ui]") {
		t.Fatalf("a revocation was reported for a session that recorded none:\n%s", text)
	}

	var report struct {
		Revocations []map[string]any `json:"revocation_requests"`
	}
	out := runPermissions(t, path, "--json")
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("--json output is not one valid JSON document: %v\n%s", err, out)
	}
	if len(report.Revocations) != 0 {
		t.Fatalf("revocation_requests = %v, want an empty list:\n%s", report.Revocations, out)
	}
	if !strings.Contains(out, `"revocation_requests": []`) {
		t.Fatalf("--json omitted revocation_requests instead of reporting zero:\n%s", out)
	}
}

// TestSessionsPermissions_RevocationsKeepRecordOrderAndLiteralIdentity proves both output modes
// follow record order and carry a literal grant's argument hash, so a reader can match a revocation
// to the exact pinned command rather than to any subject that merely looks like it. The fixture is
// deliberately in reverse lexical order by subject and by scope, so a report that sorted or dropped
// a recorded identity field fails here instead of passing by coincidence.
func TestSessionsPermissions_RevocationsKeepRecordOrderAndLiteralIdentity(t *testing.T) {
	const literal = `sh -c "echo hi"`
	hash := permissions.ComputeArgumentHash(literal)
	records := []sessions.Record{
		eventRecord(events.KindPermissionRevokeRequested, events.PermissionRevokeRequested{
			EntryKind: "literal", Subject: literal, PathScope: auditSub, GrantKind: "folder",
			ArgumentHash: hash, Source: events.RevokeSourcePermissionsUI,
		}),
		eventRecord(events.KindPermissionRevokeRequested, events.PermissionRevokeRequested{
			EntryKind: "direct", Subject: "git :*", PathScope: "*", GrantKind: "global",
			Source: events.RevokeSourcePermissionsUI,
		}),
	}
	path := writeSession(t, "revocations", records)
	out := runPermissions(t, path)

	if want := "explicit revocation requests: 2"; !strings.Contains(out, want) {
		t.Fatalf("permissions text missing %q:\n%s", want, out)
	}
	first := "1. [permissions_ui] literal  " + literal + "  scope=" + auditSub + "  grant=folder  argument_hash=" + hash + "\n"
	if !strings.Contains(out, first) {
		t.Fatalf("permissions text missing %q:\n%s", first, out)
	}
	second := "2. [permissions_ui] direct  git :*  scope=*  grant=global\n"
	if !strings.Contains(out, second) {
		t.Fatalf("permissions text missing %q:\n%s", second, out)
	}
	if strings.Index(out, first) > strings.Index(out, second) {
		t.Fatalf("text report sorted the revocations instead of keeping record order:\n%s", out)
	}
	if want := "prompts shown: 0"; !strings.Contains(out, want) {
		t.Fatalf("a revocation was counted as a prompt; output missing %q:\n%s", want, out)
	}

	type jsonRevocation struct {
		Kind         string `json:"kind"`
		Subject      string `json:"subject"`
		Scope        string `json:"scope"`
		GrantKind    string `json:"grant_kind"`
		Source       string `json:"source"`
		ArgumentHash string `json:"argument_hash"`
	}
	var report struct {
		Revocations []jsonRevocation `json:"revocation_requests"`
	}
	jsonOut := runPermissions(t, path, "--json")
	if err := json.Unmarshal([]byte(jsonOut), &report); err != nil {
		t.Fatalf("--json output is not one valid JSON document: %v\n%s", err, jsonOut)
	}
	want := []jsonRevocation{
		{Kind: "literal", Subject: literal, Scope: auditSub, GrantKind: "folder", Source: events.RevokeSourcePermissionsUI, ArgumentHash: hash},
		{Kind: "direct", Subject: "git :*", Scope: "*", GrantKind: "global", Source: events.RevokeSourcePermissionsUI},
	}
	if !reflect.DeepEqual(report.Revocations, want) {
		t.Fatalf("--json revocation_requests = %+v, want %+v in record order with every identity field:\n%s", report.Revocations, want, jsonOut)
	}
}

// TestSessionsPermissions_CountsDeclaredScope proves a caller's declared file scope is reported as
// its own non-prompted source, in the text tally and the JSON report, and is included in the
// denominator the prompt count is read against.
func TestSessionsPermissions_CountsDeclaredScope(t *testing.T) {
	records := []sessions.Record{
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "create", PathScope: auditProj, Outcome: "once", OutcomeSource: "declared_scope",
		}),
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "edit", PathScope: auditProj, Outcome: "deny", OutcomeSource: "declared_scope",
		}),
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "Ripgrep", PathScope: auditProj, Outcome: "once", OutcomeSource: "cache",
		}),
	}
	path := writeSession(t, "declared", records)

	text := runPermissions(t, path)
	if want := "non-prompted authorizations: 3 (grant: 0, cache: 1, mode_auto: 0, declared_scope: 2, declared_command: 0, open_read: 0, confined: 0, system_one_check: 0)"; !strings.Contains(text, want) {
		t.Fatalf("permissions text missing %q:\n%s", want, text)
	}

	var report struct {
		NonPrompted struct {
			DeclaredScope int `json:"declared_scope"`
		} `json:"non_prompted"`
	}
	out := runPermissions(t, path, "--json")
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("--json output is not one valid JSON document: %v\n%s", err, out)
	}
	if report.NonPrompted.DeclaredScope != 2 {
		t.Fatalf("non_prompted.declared_scope = %d, want 2:\n%s", report.NonPrompted.DeclaredScope, out)
	}
}

func TestSessionsPermissions_CountsDeclaredCommand(t *testing.T) {
	records := []sessions.Record{
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "direct", Subject: "prep-open-tasks.sh --only i425", PathScope: auditProj, Outcome: "once", OutcomeSource: "declared_command",
		}),
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "direct", Subject: "prep-open-tasks.sh --only i425 --force", PathScope: auditProj, Outcome: "once", OutcomeSource: "declared_command",
		}),
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "Ripgrep", PathScope: auditProj, Outcome: "once", OutcomeSource: "cache",
		}),
	}
	path := writeSession(t, "declared-command", records)

	text := runPermissions(t, path)
	if want := "non-prompted authorizations: 3 (grant: 0, cache: 1, mode_auto: 0, declared_scope: 0, declared_command: 2, open_read: 0, confined: 0, system_one_check: 0)"; !strings.Contains(text, want) {
		t.Fatalf("permissions text missing %q:\n%s", want, text)
	}

	var report struct {
		NonPrompted struct {
			DeclaredCommand int `json:"declared_command"`
		} `json:"non_prompted"`
	}
	out := runPermissions(t, path, "--json")
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("--json output is not one valid JSON document: %v\n%s", err, out)
	}
	if report.NonPrompted.DeclaredCommand != 2 {
		t.Fatalf("non_prompted.declared_command = %d, want 2:\n%s", report.NonPrompted.DeclaredCommand, out)
	}
}

func TestSessionsPermissions_CountsOpenRead(t *testing.T) {
	records := []sessions.Record{
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "read", PathScope: "/home/u/notes", Outcome: "once", OutcomeSource: "open_read",
		}),
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "grep", PathScope: "/home/u/src", Outcome: "once", OutcomeSource: "open_read",
		}),
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "Ripgrep", PathScope: auditProj, Outcome: "once", OutcomeSource: "cache",
		}),
	}
	path := writeSession(t, "open-read", records)

	text := runPermissions(t, path)
	if want := "non-prompted authorizations: 3 (grant: 0, cache: 1, mode_auto: 0, declared_scope: 0, declared_command: 0, open_read: 2, confined: 0, system_one_check: 0)"; !strings.Contains(text, want) {
		t.Fatalf("permissions text missing %q:\n%s", want, text)
	}

	var report struct {
		NonPrompted struct {
			OpenRead int `json:"open_read"`
		} `json:"non_prompted"`
	}
	out := runPermissions(t, path, "--json")
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("--json output is not one valid JSON document: %v\n%s", err, out)
	}
	if report.NonPrompted.OpenRead != 2 {
		t.Fatalf("non_prompted.open_read = %d, want 2:\n%s", report.NonPrompted.OpenRead, out)
	}
}

func TestSessionsPermissions_CountsConfined(t *testing.T) {
	var records []sessions.Record
	for _, subject := range []string{"touch a", "rm b", "make"} {
		records = append(records, eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "direct", Subject: subject, PathScope: auditProj, Outcome: "once", OutcomeSource: "confined",
		}))
	}
	path := writeSession(t, "confined", records)

	text := runPermissions(t, path)
	if want := "non-prompted authorizations: 3 (grant: 0, cache: 0, mode_auto: 0, declared_scope: 0, declared_command: 0, open_read: 0, confined: 3, system_one_check: 0)"; !strings.Contains(text, want) {
		t.Fatalf("permissions text missing %q:\n%s", want, text)
	}

	var report struct {
		NonPrompted struct {
			Confined int `json:"confined"`
		} `json:"non_prompted"`
	}
	out := runPermissions(t, path, "--json")
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("--json output is not one valid JSON document: %v\n%s", err, out)
	}
	if report.NonPrompted.Confined != 3 {
		t.Fatalf("non_prompted.confined = %d, want 3:\n%s", report.NonPrompted.Confined, out)
	}
}

func TestSessionsPermissions_CountsRefusals(t *testing.T) {
	records := []sessions.Record{
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "read", PathScope: "/home/u/.ssh", Outcome: "deny", OutcomeSource: "blocked_path",
			BlockedEntry: "/home/u/.ssh", BlockedEntrySource: "/home/u/.codemeld/global/settings.yaml",
		}),
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "read", PathScope: "/home/u/.ssh", Outcome: "deny", OutcomeSource: "blocked_path",
		}),
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "edit", PathScope: "/proj/.codemeld", Outcome: "deny", OutcomeSource: "protected_state",
		}),
		eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "tool", Subject: "Ripgrep", PathScope: auditProj, Outcome: "once", OutcomeSource: "cache",
		}),
	}
	path := writeSession(t, "refusals", records)

	text := runPermissions(t, path)
	for _, want := range []string{
		"non-prompted authorizations: 1 (grant: 0, cache: 1, mode_auto: 0, declared_scope: 0, declared_command: 0, open_read: 0, confined: 0, system_one_check: 0)",
		"refused before approval: 3 (blocked_path: 2, protected_state: 1)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("permissions text missing %q:\n%s", want, text)
		}
	}

	var report struct {
		Refused struct {
			BlockedPath    int `json:"blocked_path"`
			ProtectedState int `json:"protected_state"`
		} `json:"refused"`
	}
	out := runPermissions(t, path, "--json")
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("--json output is not one valid JSON document: %v\n%s", err, out)
	}
	if report.Refused.BlockedPath != 2 || report.Refused.ProtectedState != 1 {
		t.Fatalf("refused = %+v, want blocked_path 2 and protected_state 1:\n%s", report.Refused, out)
	}
}

func mustDirectEnvSubject(t *testing.T, assignments []string, subject string) string {
	t.Helper()
	encoded, err := permissions.EncodeDirectEnvSubject(assignments, false, subject)
	if err != nil {
		t.Fatalf("EncodeDirectEnvSubject(%v, %q): %v", assignments, subject, err)
	}
	return encoded
}

func envPromptEvent(t *testing.T, assignments []string, pathScope string, tokens ...string) sessions.Event {
	t.Helper()
	command := permissions.ExactSubject(tokens[0], tokens[1:])
	return eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
		SubjectKind: "direct", Subject: strings.Join(tokens, " "), PathScope: pathScope,
		DirectTokens:         directTokens(tokens...),
		DirectCommandSubject: command,
		DirectRequestSubject: mustDirectEnvSubject(t, assignments, command),
	})
}

func envDecisionEvent(t *testing.T, assignments []string, pathScope, outcome, grantKind, grantSubject string, tokens ...string) sessions.Event {
	t.Helper()
	command := permissions.ExactSubject(tokens[0], tokens[1:])
	p := events.PermissionDecision{
		SubjectKind: "direct", Subject: strings.Join(tokens, " "), PathScope: pathScope, Outcome: outcome,
		DirectCommandSubject: command,
		DirectRequestSubject: mustDirectEnvSubject(t, assignments, command),
	}
	if grantKind != "" {
		p.GrantKind, p.GrantPathScope, p.GrantSubject = grantKind, pathScope, grantSubject
	}
	return eventRecord(events.KindPermissionDecision, p)
}

func TestSessionsPermissions_DirectV1PromptsPairWithTheirOwnDecisions(t *testing.T) {
	records := []sessions.Record{
		envPromptEvent(t, []string{"FOO=a"}, auditProj, "hg", "status"),
		envPromptEvent(t, []string{"FOO=b"}, auditProj, "hg", "status"),
		envDecisionEvent(t, []string{"FOO=b"}, auditProj, "denied", "", "", "hg", "status"),
		envDecisionEvent(t, []string{"FOO=a"}, auditProj, "granted", "folder",
			mustDirectEnvSubject(t, []string{"FOO=a"}, "hg :*"), "hg", "status"),
	}
	out := runPermissions(t, writeSession(t, "direct-v1-pairing", records))
	if !strings.Contains(out, "1. [granted] direct  hg status") {
		t.Fatalf("the FOO=a prompt did not take its own granted decision:\n%s", out)
	}
	if !strings.Contains(out, "2. [denied] direct  hg status") {
		t.Fatalf("the FOO=b prompt did not take its own denied decision:\n%s", out)
	}
}

func legacyDirectPrompt(subject, pathScope string, tokens ...string) sessions.Event {
	return eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
		SubjectKind: "direct", Subject: subject, PathScope: pathScope,
		DirectTokens: directTokens(tokens...),
	})
}

func legacyDirectDecision(subject, pathScope, outcome string) sessions.Event {
	return eventRecord(events.KindPermissionDecision, events.PermissionDecision{
		SubjectKind: "direct", Subject: subject, PathScope: pathScope, Outcome: outcome,
	})
}

func malformedDirectPrompt(subject, pathScope string, tokens ...string) sessions.Event {
	return eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
		SubjectKind: "direct", Subject: subject, PathScope: pathScope,
		DirectTokens:         directTokens(tokens...),
		DirectCommandSubject: subject, DirectRequestSubject: "'direct-env/v1 !!not-base64",
	})
}

func malformedDirectDecision(subject, pathScope, outcome string) sessions.Event {
	return eventRecord(events.KindPermissionDecision, events.PermissionDecision{
		SubjectKind: "direct", Subject: subject, PathScope: pathScope, Outcome: outcome,
		DirectCommandSubject: subject, DirectRequestSubject: "'direct-env/v1 !!not-base64",
	})
}

// An assignment-free identity is byte-equal to the joined subject for an unquoted command, so
// nothing but the identity state itself keeps a legacy record from consuming an identity-bearing
// decision — or a malformed record from consuming either.
func TestSessionsPermissions_DirectRecordsPairOnlyWithinTheirIdentityState(t *testing.T) {
	tests := []struct {
		name    string
		records []sessions.Record
		want    string
	}{
		{
			name: "two legacy records still pair",
			records: []sessions.Record{
				legacyDirectPrompt("hg status", auditProj, "hg", "status"),
				legacyDirectDecision("hg status", auditProj, "granted"),
			},
			want: "1. [granted] direct  hg status",
		},
		{
			name: "a legacy prompt does not take an identity-bearing decision",
			records: []sessions.Record{
				legacyDirectPrompt("hg status", auditProj, "hg", "status"),
				grantEvent("direct", "hg status", auditProj, "folder", auditProj, "hg :*", "hg", "status"),
			},
			want: "1. [pending] direct  hg status",
		},
		{
			name: "an identity-bearing prompt does not take a legacy decision",
			records: []sessions.Record{
				promptEvent("direct", "hg status", auditProj, directTokens("hg", "status")),
				legacyDirectDecision("hg status", auditProj, "granted"),
			},
			want: "1. [pending] direct  hg status",
		},
		{
			name: "a malformed prompt does not take a legacy decision",
			records: []sessions.Record{
				malformedDirectPrompt("hg status", auditProj, "hg", "status"),
				legacyDirectDecision("hg status", auditProj, "granted"),
			},
			want: "1. [pending] direct  hg status",
		},
		{
			name: "a legacy prompt does not take a malformed decision",
			records: []sessions.Record{
				legacyDirectPrompt("hg status", auditProj, "hg", "status"),
				malformedDirectDecision("hg status", auditProj, "granted"),
			},
			want: "1. [pending] direct  hg status",
		},
		{
			name: "two malformed records do not pair with each other",
			records: []sessions.Record{
				malformedDirectPrompt("hg status", auditProj, "hg", "status"),
				malformedDirectDecision("hg status", auditProj, "granted"),
			},
			want: "1. [pending] direct  hg status",
		},
		{
			name: "an assignment-bearing prompt does not take an assignment-free decision",
			records: []sessions.Record{
				envPromptEvent(t, []string{"FOO=a"}, auditProj, "hg", "status"),
				grantEvent("direct", "hg status", auditProj, "folder", auditProj, "hg :*", "hg", "status"),
			},
			want: "1. [pending] direct  hg status",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runPermissions(t, writeSession(t, "identity-state", tt.records))
			if !strings.Contains(out, tt.want) {
				t.Fatalf("permissions output missing %q:\n%s", tt.want, out)
			}
		})
	}
}

func TestSessionsPermissions_DirectV1EscalationReplay(t *testing.T) {
	narrower := mustDirectEnvSubject(t, []string{"FOO=a"}, "hg :*")
	grantedWithIdentity := func(commandSubject, requestSubject string) sessions.Event {
		return eventRecord(events.KindPermissionDecision, events.PermissionDecision{
			SubjectKind: "direct", Subject: "hg status", PathScope: auditSub, Outcome: "granted",
			GrantKind: "folder", GrantPathScope: auditSub, GrantSubject: narrower,
			DirectCommandSubject: commandSubject, DirectRequestSubject: requestSubject,
		})
	}
	validPrompt := func(t *testing.T) sessions.Event {
		return envPromptEvent(t, []string{"FOO=a"}, auditProj, "hg", "log")
	}
	tests := []struct {
		name     string
		decision func(*testing.T) sessions.Event
		prompt   func(*testing.T) sessions.Event
		wantEsc  bool
	}{
		{
			name:    "same ordered assignments escalate the narrower grant",
			prompt:  validPrompt,
			wantEsc: true,
		},
		{
			name:     "an identity-less prior grant is not a candidate",
			decision: func(*testing.T) sessions.Event { return grantedWithIdentity("", "") },
			prompt:   validPrompt,
		},
		{
			name: "a malformed prior grant is not a candidate",
			decision: func(*testing.T) sessions.Event {
				return grantedWithIdentity("hg status", "'direct-env/v1 !!not-base64")
			},
			prompt: validPrompt,
		},
		{
			name:   "different assignments do not match",
			prompt: func(t *testing.T) sessions.Event { return envPromptEvent(t, []string{"FOO=b"}, auditProj, "hg", "log") },
		},
		{
			name: "an assignment-free exact identity does not match",
			prompt: func(t *testing.T) sessions.Event {
				return promptEvent("direct", "hg log", auditProj, directTokens("hg", "log"))
			},
		},
		{
			name: "a malformed request identity is omitted",
			prompt: func(t *testing.T) sessions.Event {
				return eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
					SubjectKind: "direct", Subject: "hg log", PathScope: auditProj,
					DirectTokens:         directTokens("hg", "log"),
					DirectCommandSubject: "hg log", DirectRequestSubject: "'direct-env/v1 !!not-base64",
				})
			},
		},
		{
			name: "an identity-less legacy record is omitted",
			prompt: func(t *testing.T) sessions.Event {
				return eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
					SubjectKind: "direct", Subject: "hg log", PathScope: auditProj,
					DirectTokens: directTokens("hg", "log"),
				})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := tt.decision
			if decision == nil {
				decision = func(t *testing.T) sessions.Event {
					return envDecisionEvent(t, []string{"FOO=a"}, auditSub, "granted", "folder", narrower, "hg", "status")
				}
			}
			records := []sessions.Record{
				envPromptEvent(t, []string{"FOO=a"}, auditSub, "hg", "status"),
				decision(t),
				tt.prompt(t),
			}
			out := runPermissions(t, writeSession(t, "direct-v1-escalation", records))
			if got := strings.Contains(out, "escalates_grant_scope="); got != tt.wantEsc {
				t.Fatalf("escalation reported = %v, want %v:\n%s", got, tt.wantEsc, out)
			}
		})
	}
}

func mustClearDirectEnvSubject(t *testing.T, assignments []string, subject string) string {
	t.Helper()
	encoded, err := permissions.EncodeDirectEnvSubject(assignments, true, subject)
	if err != nil {
		t.Fatalf("EncodeDirectEnvSubject(%v, true, %q): %v", assignments, subject, err)
	}
	return encoded
}

func clearEnvPromptEvent(t *testing.T, assignments []string, pathScope string, tokens ...string) sessions.Event {
	t.Helper()
	command := permissions.ExactSubject(tokens[0], tokens[1:])
	return eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
		SubjectKind: "direct", Subject: strings.Join(tokens, " "), PathScope: pathScope,
		DirectTokens:         directTokens(tokens...),
		DirectCommandSubject: command,
		DirectRequestSubject: mustClearDirectEnvSubject(t, assignments, command),
	})
}

func clearEnvDecisionEvent(t *testing.T, assignments []string, pathScope, outcome, grantKind, grantSubject string, tokens ...string) sessions.Event {
	t.Helper()
	command := permissions.ExactSubject(tokens[0], tokens[1:])
	p := events.PermissionDecision{
		SubjectKind: "direct", Subject: strings.Join(tokens, " "), PathScope: pathScope, Outcome: outcome,
		DirectCommandSubject: command,
		DirectRequestSubject: mustClearDirectEnvSubject(t, assignments, command),
	}
	if grantKind != "" {
		p.GrantKind, p.GrantPathScope, p.GrantSubject = grantKind, pathScope, grantSubject
	}
	return eventRecord(events.KindPermissionDecision, p)
}

func TestSessionsPermissions_DirectV2PairsOnlyWithItsOwnDecision(t *testing.T) {
	assignments := []string{"PATH=/usr/bin"}
	tests := []struct {
		name    string
		records []sessions.Record
		want    string
	}{
		{
			name: "a v2 prompt takes its own v2 decision",
			records: []sessions.Record{
				clearEnvPromptEvent(t, assignments, auditProj, "hg", "status"),
				clearEnvDecisionEvent(t, assignments, auditProj, "granted", "folder",
					mustClearDirectEnvSubject(t, assignments, "hg :*"), "hg", "status"),
			},
			want: "1. [granted] direct  hg status",
		},
		{
			name: "a v2 prompt does not take a v1 decision",
			records: []sessions.Record{
				clearEnvPromptEvent(t, assignments, auditProj, "hg", "status"),
				envDecisionEvent(t, assignments, auditProj, "granted", "folder",
					mustDirectEnvSubject(t, assignments, "hg :*"), "hg", "status"),
			},
			want: "1. [pending] direct  hg status",
		},
		{
			name: "a v1 prompt does not take a v2 decision",
			records: []sessions.Record{
				envPromptEvent(t, assignments, auditProj, "hg", "status"),
				clearEnvDecisionEvent(t, assignments, auditProj, "granted", "folder",
					mustClearDirectEnvSubject(t, assignments, "hg :*"), "hg", "status"),
			},
			want: "1. [pending] direct  hg status",
		},
		{
			name: "a malformed v2 identity stays unmatched",
			records: []sessions.Record{
				eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
					SubjectKind: "direct", Subject: "hg status", PathScope: auditProj,
					DirectTokens:         directTokens("hg", "status"),
					DirectCommandSubject: "hg status", DirectRequestSubject: "'direct-env/v2 !!not-base64",
				}),
				clearEnvDecisionEvent(t, assignments, auditProj, "granted", "", "", "hg", "status"),
			},
			want: "1. [pending] direct  hg status",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runPermissions(t, writeSession(t, "direct-v2-pairing", tt.records))
			if !strings.Contains(out, tt.want) {
				t.Fatalf("permissions output missing %q:\n%s", tt.want, out)
			}
		})
	}
}

func TestSessionsPermissions_DirectV2NeverEscalatesAV1OrLegacyGrant(t *testing.T) {
	assignments := []string{"PATH=/usr/bin"}
	clearNarrower := mustClearDirectEnvSubject(t, assignments, "hg :*")
	envNarrower := mustDirectEnvSubject(t, assignments, "hg :*")
	tests := []struct {
		name     string
		priorSet []sessions.Record
		wantEsc  bool
	}{
		{
			name: "a v2 prior grant escalates",
			priorSet: []sessions.Record{
				clearEnvPromptEvent(t, assignments, auditSub, "hg", "status"),
				clearEnvDecisionEvent(t, assignments, auditSub, "granted", "folder", clearNarrower, "hg", "status"),
			},
			wantEsc: true,
		},
		{
			name: "a v1 prior grant does not escalate a v2 prompt",
			priorSet: []sessions.Record{
				envPromptEvent(t, assignments, auditSub, "hg", "status"),
				envDecisionEvent(t, assignments, auditSub, "granted", "folder", envNarrower, "hg", "status"),
			},
		},
		{
			name: "a legacy prior grant does not escalate a v2 prompt",
			priorSet: []sessions.Record{
				promptEvent("direct", "hg status", auditSub, directTokens("hg", "status")),
				grantEvent("direct", "hg status", auditSub, "folder", auditSub, "hg :*", "hg", "status"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records := append(append([]sessions.Record{}, tt.priorSet...),
				clearEnvPromptEvent(t, assignments, auditProj, "hg", "log"))
			out := runPermissions(t, writeSession(t, "direct-v2-escalation", records))
			if got := strings.Contains(out, "escalates_grant_scope="); got != tt.wantEsc {
				t.Fatalf("escalation reported = %v, want %v:\n%s", got, tt.wantEsc, out)
			}
		})
	}
}

var homeTargetTokens = []string{"mv", "x", "~/target"}

const homeTargetCommand = "mv x '~/target'"

func homeStateEnvelope(t *testing.T, scope string, expanding, literal []int) string {
	t.Helper()
	payload, err := json.Marshal(struct {
		Subject   string `json:"subject"`
		Expanding []int  `json:"expanding"`
		Literal   []int  `json:"literal"`
	}{scope, expanding, literal})
	if err != nil {
		t.Fatalf("marshal direct-home payload: %v", err)
	}
	return "'direct-home/v1 " + base64.RawURLEncoding.EncodeToString(payload)
}

func stageIdentity(t *testing.T, assignments []string, clearEnvironment bool, expands ...bool) string {
	t.Helper()
	subject, err := permissions.DirectStageRequestSubject(homeTargetTokens, assignments, clearEnvironment, expands)
	if err != nil {
		t.Fatalf("DirectStageRequestSubject(%v, %v, %v): %v", assignments, clearEnvironment, expands, err)
	}
	return subject
}

func identityPromptEvent(requestSubject, pathScope string) sessions.Event {
	return eventRecord(events.KindPermissionPromptShown, events.PermissionPromptShown{
		SubjectKind: "direct", Subject: strings.Join(homeTargetTokens, " "), PathScope: pathScope,
		DirectTokens:         directTokens(homeTargetTokens...),
		DirectCommandSubject: homeTargetCommand, DirectRequestSubject: requestSubject,
	})
}

func identityDecisionEvent(requestSubject, pathScope, outcome, grantSubject string) sessions.Event {
	p := events.PermissionDecision{
		SubjectKind: "direct", Subject: strings.Join(homeTargetTokens, " "), PathScope: pathScope, Outcome: outcome,
		DirectCommandSubject: homeTargetCommand, DirectRequestSubject: requestSubject,
	}
	if grantSubject != "" {
		p.GrantKind, p.GrantPathScope, p.GrantSubject = "folder", pathScope, grantSubject
	}
	return eventRecord(events.KindPermissionDecision, p)
}

func TestSessionsPermissions_HomeStateVariantsPairWithTheirOwnDecisions(t *testing.T) {
	tests := []struct {
		name        string
		assignments []string
		clear       bool
	}{
		{name: "inherited environment"},
		{name: "assigned and cleared environment", assignments: []string{"PATH=/usr/bin"}, clear: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expanding := stageIdentity(t, tt.assignments, tt.clear, false, false, true)
			literal := stageIdentity(t, tt.assignments, tt.clear, false, false, false)
			records := []sessions.Record{
				identityPromptEvent(expanding, auditProj),
				identityPromptEvent(literal, auditProj),
				identityDecisionEvent(literal, auditProj, "denied", ""),
				identityDecisionEvent(expanding, auditProj, "granted", expanding),
			}
			out := runPermissions(t, writeSession(t, "home-state-pairing", records))
			if !strings.Contains(out, "1. [granted] direct  mv x ~/target") {
				t.Fatalf("the expanding prompt did not take its own granted decision:\n%s", out)
			}
			if !strings.Contains(out, "2. [denied] direct  mv x ~/target") {
				t.Fatalf("the literal prompt did not take its own denied decision:\n%s", out)
			}
		})
	}
}

func TestSessionsPermissions_HomeStateRecordsWithoutValidStateDoNotPair(t *testing.T) {
	tests := []struct {
		name             string
		prompt, decision string
	}{
		{
			name:     "a token-only identity does not take a literal decision",
			prompt:   homeTargetCommand,
			decision: homeStateEnvelope(t, homeTargetCommand, []int{}, []int{2}),
		},
		{
			name:     "a token-only identity does not take an expanding decision",
			prompt:   homeTargetCommand,
			decision: homeStateEnvelope(t, homeTargetCommand, []int{2}, []int{}),
		},
		{
			name:     "two malformed home identities do not pair",
			prompt:   "'direct-home/v1 !!not-base64",
			decision: "'direct-home/v1 !!not-base64",
		},
		{
			name:     "two home identities missing the pinned position's state do not pair",
			prompt:   homeStateEnvelope(t, homeTargetCommand, []int{}, []int{}),
			decision: homeStateEnvelope(t, homeTargetCommand, []int{}, []int{}),
		},
		{
			name:     "two home identities naming another command do not pair",
			prompt:   homeStateEnvelope(t, "mv x '~/other'", []int{2}, []int{}),
			decision: homeStateEnvelope(t, "mv x '~/other'", []int{2}, []int{}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records := []sessions.Record{
				identityPromptEvent(tt.prompt, auditProj),
				identityDecisionEvent(tt.decision, auditProj, "granted", ""),
			}
			out := runPermissions(t, writeSession(t, "home-state-unpaired", records))
			if !strings.Contains(out, "1. [pending] direct  mv x ~/target") {
				t.Fatalf("a prompt without matching valid home state took a decision:\n%s", out)
			}
		})
	}
}

func TestSessionsPermissions_HomeStateEscalationReplay(t *testing.T) {
	envAssignments := []string{"PATH=/usr/bin"}
	expandingGrant := homeStateEnvelope(t, homeTargetCommand, []int{2}, []int{})
	literalGrant := homeStateEnvelope(t, homeTargetCommand, []int{}, []int{2})
	clearExpandingGrant, err := permissions.EncodeDirectEnvSubject(envAssignments, true, expandingGrant)
	if err != nil {
		t.Fatalf("EncodeDirectEnvSubject: %v", err)
	}
	expanding := stageIdentity(t, nil, false, false, false, true)
	literal := stageIdentity(t, nil, false, false, false, false)
	clearExpanding := stageIdentity(t, envAssignments, true, false, false, true)
	clearLiteral := stageIdentity(t, envAssignments, true, false, false, false)
	envExpanding := stageIdentity(t, envAssignments, false, false, false, true)
	tests := []struct {
		name                 string
		priorIdentity, grant string
		later                sessions.Event
		wantEsc              bool
	}{
		{
			name: "an expanding grant escalates an expanding prompt", priorIdentity: expanding, grant: expandingGrant,
			later: identityPromptEvent(expanding, auditProj), wantEsc: true,
		},
		{
			name: "an expanding grant does not escalate a literal prompt", priorIdentity: expanding, grant: expandingGrant,
			later: identityPromptEvent(literal, auditProj),
		},
		{
			name: "a literal grant escalates a literal prompt", priorIdentity: literal, grant: literalGrant,
			later: identityPromptEvent(literal, auditProj), wantEsc: true,
		},
		{
			name: "a literal grant does not escalate an expanding prompt", priorIdentity: literal, grant: literalGrant,
			later: identityPromptEvent(expanding, auditProj),
		},
		{
			name: "a cleared assigned expanding grant escalates the same request", priorIdentity: clearExpanding, grant: clearExpandingGrant,
			later: identityPromptEvent(clearExpanding, auditProj), wantEsc: true,
		},
		{
			name: "a cleared assigned expanding grant does not escalate its literal request", priorIdentity: clearExpanding, grant: clearExpandingGrant,
			later: identityPromptEvent(clearLiteral, auditProj),
		},
		{
			name: "a cleared assigned expanding grant does not escalate an inherited-environment request", priorIdentity: clearExpanding, grant: clearExpandingGrant,
			later: identityPromptEvent(envExpanding, auditProj),
		},
		{
			name: "a token-only identity gets no state invented against an expanding grant", priorIdentity: expanding, grant: expandingGrant,
			later: identityPromptEvent(homeTargetCommand, auditProj),
		},
		{
			name: "a token-only identity gets no state invented against a literal grant", priorIdentity: literal, grant: literalGrant,
			later: identityPromptEvent(homeTargetCommand, auditProj),
		},
		{
			name: "a malformed home identity is omitted", priorIdentity: expanding, grant: expandingGrant,
			later: identityPromptEvent("'direct-home/v1 !!not-base64", auditProj),
		},
		{
			name: "an identity-less legacy record is omitted", priorIdentity: expanding, grant: expandingGrant,
			later: legacyDirectPrompt("mv x ~/target", auditProj, homeTargetTokens...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records := []sessions.Record{
				identityPromptEvent(tt.priorIdentity, auditSub),
				identityDecisionEvent(tt.priorIdentity, auditSub, "granted", tt.grant),
				tt.later,
			}
			out := runPermissions(t, writeSession(t, "home-state-escalation", records))
			if got := strings.Contains(out, "escalates_grant_scope="); got != tt.wantEsc {
				t.Fatalf("escalation reported = %v, want %v:\n%s", got, tt.wantEsc, out)
			}
		})
	}
}

// A settings-drift halt is reported as an error from both records it can produce: the
// standalone startup event, which closes no round, and the in-turn pair whose security_halted
// terminal does. The startup event must not leave its round looking unclosed either, because
// it never opened one.
func TestSessionsDoctor_SecurityStateHaltFindings(t *testing.T) {
	turn := ids.NewV7()
	haltedRound, okRound := ids.NewV7(), ids.NewV7()
	path := writeSession(t, "securityhalt", []sessions.Record{
		eventRecord(events.KindSecurityStateHalted, events.SecurityStateHalted{
			Path: "/home/u/.codemeld/settings.yaml", DetectionPoint: events.SecurityDetectionStartup,
			UnavailableReason: "lock_timeout",
		}),
		roundTripEvent(turn, okRound),
		terminalEvent(turn, okRound, events.TurnOutcomeCompleted, "", true),
		roundTripEvent(turn, haltedRound),
		eventRecord(events.KindSecurityStateHalted, events.SecurityStateHalted{
			Path: "/home/u/proj/.codemeld/settings.yaml", DetectionPoint: events.SecurityDetectionBeforeMutatingCall,
			Sections: []string{"permissions"}, Labels: []string{"added"},
		}),
		terminalEvent(turn, haltedRound, events.TurnOutcomeSecurityHalted, "", true),
	})

	out := runDoctor(t, path)
	for _, want := range []string{
		"findings: 3 (error: 3, warning: 0, info: 0)",
		"[error] security_state_halted", "path=/home/u/.codemeld/settings.yaml", "detection_point=startup",
		"path=/home/u/proj/.codemeld/settings.yaml", "detection_point=before_mutating_call",
		"[error] turn_terminal", "outcome=security_halted",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, reasonIncompleteRound) {
		t.Errorf("a startup halt was mistaken for an unclosed round:\n%s", out)
	}

	report := doctorJSON(t, path)
	if report.Summary.Error != 3 || len(report.Findings) != 3 {
		t.Fatalf("json summary = %+v with %d findings, want 3 errors", report.Summary, len(report.Findings))
	}
	if got := report.Findings[0]; got.Kind != events.KindSecurityStateHalted || got.Severity != "error" ||
		got.DetectionPoint != events.SecurityDetectionStartup || got.TurnID != "" || got.RoundID != "" {
		t.Errorf("startup finding = %+v, want a round-less security_state_halted error", got)
	}
	if got := report.Findings[2]; got.Kind != events.KindTurnTerminal || got.Severity != "error" ||
		got.Outcome != events.TurnOutcomeSecurityHalted || got.RoundID != haltedRound {
		t.Errorf("terminal finding = %+v, want a security_halted error on the halted round", got)
	}
}

// The settings path is the one free-form value a halt record carries, and the human report is
// line-oriented, so a path with control characters cannot forge extra finding lines.
func TestSessionsDoctor_SecurityHaltPathCannotForgeLines(t *testing.T) {
	path := writeSession(t, "haltpath", []sessions.Record{
		eventRecord(events.KindSecurityStateHalted, events.SecurityStateHalted{
			Path:           "/home/u/\n  [error] forged\r\tsettings.yaml",
			DetectionPoint: events.SecurityDetectionStartup,
			Labels:         []string{"missing"},
		}),
	})

	out := runDoctor(t, path)
	findingLines := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "[error]") {
			findingLines++
		}
	}
	if findingLines != 1 {
		t.Fatalf("halt path produced %d finding lines, want 1:\n%s", findingLines, out)
	}
}

type listFixture struct {
	home, cwd, canonical, root string
}

func newListFixture(t *testing.T) listFixture {
	t.Helper()
	home, cwd := t.TempDir(), t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	stubHomeAndCwd(t, home, cwd)
	return listFixture{home: home, cwd: cwd, canonical: canonical, root: sessions.SessionRoot(home)}
}

func (f listFixture) folderDir(t *testing.T, dirName, folder string) string {
	t.Helper()
	dir := filepath.Join(f.root, dirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "folder"), []byte(folder+"\n"), 0o600); err != nil {
		t.Fatalf("write folder file: %v", err)
	}
	return dir
}

func (f listFixture) currentDir(t *testing.T) string {
	return f.folderDir(t, sessions.FolderDirName(f.canonical), f.canonical)
}

func writeListSession(t *testing.T, dir, id, folder, updatedAt, title, prompt string) {
	t.Helper()
	meta := map[string]any{
		"id": ids.NewV7(), "folder": folder, "started_at": "2026-05-25T09:00:00.000Z",
		"updated_at": updatedAt, "schema_version": 1,
	}
	if title != "" {
		meta["title"], meta["title_source"] = title, "user"
	}
	metaLine, _ := json.Marshal(map[string]any{"type": "metadata", "metadata": meta})
	msgLine, _ := json.Marshal(map[string]any{
		"type": "message", "id": ids.NewV7(), "role": "user", "content": prompt,
		"timestamp": "2026-05-25T09:00:00.000Z",
	})
	doc := string(metaLine) + "\n" + string(msgLine) + "\n"
	if err := os.WriteFile(filepath.Join(dir, id+".json"), []byte(doc), 0o600); err != nil {
		t.Fatalf("write session: %v", err)
	}
}

func runList(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), append([]string{"codemeld", "sessions", "list"}, args...), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestSessionsList_CurrentFolderAndAll(t *testing.T) {
	f := newListFixture(t)
	cur := f.currentDir(t)
	other := f.folderDir(t, "0000-other", "/proj/other")
	controlPreview := "line one\n\tline two \x1b[31mred"
	writeListSession(t, cur, "s-titled", f.canonical, "2026-05-25T12:00:01.000Z", "ppr g3910 R2", "ignored prompt")
	writeListSession(t, cur, "s-preview", f.canonical, "2026-05-25T12:00:03.000Z", "", controlPreview)
	writeListSession(t, other, "s-other", "/proj/other", "2026-05-25T12:00:02.000Z", "ppr g3910 integrator", "x")
	if err := os.WriteFile(filepath.Join(cur, "broken.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := treeSnapshot(t, f.home)

	code, out, errOut := runList(t)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
	want := strconv.Quote(controlPreview) + "  s-preview  folder=" + strconv.Quote(f.canonical) +
		"  started=2026-05-25T09:00:00.000Z  updated=2026-05-25T12:00:03.000Z\n" +
		`"ppr g3910 R2"  s-titled  folder=` + strconv.Quote(f.canonical) +
		"  started=2026-05-25T09:00:00.000Z  updated=2026-05-25T12:00:01.000Z\n"
	if out != want {
		t.Errorf("stdout =\n%s\nwant\n%s", out, want)
	}
	wantWarn := "codemeld: sessions list: skipped session \"broken\" in folder " + strconv.Quote(f.canonical) +
		" (unreadable or unparseable)\n"
	if errOut != wantWarn {
		t.Errorf("stderr = %q, want %q", errOut, wantWarn)
	}

	code, out, errOut = runList(t, "--all")
	if code != 0 {
		t.Fatalf("--all exit = %d, stderr = %q", code, errOut)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], "s-preview") ||
		lines[1] != `"ppr g3910 integrator"  s-other  folder="/proj/other"  started=2026-05-25T09:00:00.000Z  updated=2026-05-25T12:00:02.000Z` ||
		!strings.Contains(lines[2], "s-titled") {
		t.Errorf("--all stdout =\n%s", out)
	}
	if !strings.Contains(errOut, `skipped session "broken"`) || strings.Contains(out, "codemeld:") {
		t.Errorf("--all stderr = %q stdout = %q, want the warning on stderr only", errOut, out)
	}

	code, out, _ = runList(t, "--all", "--json")
	if code != 0 {
		t.Fatalf("--json exit = %d", code)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("stdout is not a JSON array: %v\n%s", err, out)
	}
	wantRows := []map[string]any{
		{"name": controlPreview, "id": "s-preview", "folder": f.canonical, "started_at": "2026-05-25T09:00:00.000Z", "updated_at": "2026-05-25T12:00:03.000Z"},
		{"name": "ppr g3910 integrator", "id": "s-other", "folder": "/proj/other", "started_at": "2026-05-25T09:00:00.000Z", "updated_at": "2026-05-25T12:00:02.000Z"},
		{"name": "ppr g3910 R2", "id": "s-titled", "folder": f.canonical, "started_at": "2026-05-25T09:00:00.000Z", "updated_at": "2026-05-25T12:00:01.000Z"},
	}
	if !reflect.DeepEqual(rows, wantRows) {
		t.Errorf("JSON rows = %v\nwant %v", rows, wantRows)
	}

	if after := treeSnapshot(t, f.home); before != after {
		t.Errorf("sessions list changed the sessions tree")
	}
}

func TestSessionsList_ShowsGeneratedTitleFromDisk(t *testing.T) {
	f := newListFixture(t)
	store, err := sessions.EnsureSession(f.home, f.canonical, fixtureTime, []sessions.Record{textMsg("user", "first prompt")})
	if err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	if _, _, err := store.FlushGeneratedTitle(context.Background(), "Auto title"); err != nil {
		t.Fatalf("flush generated title: %v", err)
	}
	id := store.SessionID()

	code, out, errOut := runList(t)
	if code != 0 || !strings.HasPrefix(out, `"Auto title"  `+id+"  folder=") || strings.Contains(out, "first prompt") {
		t.Errorf("exit = %d stdout = %q stderr = %q, want the generated title as the row name", code, out, errOut)
	}

	code, out, errOut = runList(t, "--json")
	var rows []listRow
	if code != 0 || json.Unmarshal([]byte(out), &rows) != nil || len(rows) != 1 {
		t.Fatalf("--json exit = %d stdout = %q stderr = %q", code, out, errOut)
	}
	if rows[0].Name != "Auto title" || rows[0].ID != id {
		t.Errorf("JSON row = %+v, want name %q for id %q", rows[0], "Auto title", id)
	}
}

func TestSessionsList_AllDeduplicatesAndSkipsFolders(t *testing.T) {
	f := newListFixture(t)
	a := f.folderDir(t, "zzz-a", "/proj/a")
	b := f.folderDir(t, "aaa-b", "/proj/b")
	if err := os.MkdirAll(filepath.Join(f.root, "no-folder-file"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeListSession(t, b, "dup", "/proj/b", "2026-05-25T12:00:05.000Z", "newest copy", "")
	writeListSession(t, a, "dup", "/proj/a", "2026-05-25T12:00:01.000Z", "older copy", "")
	writeListSession(t, a, "solo", "/proj/a", "2026-05-25T12:00:02.000Z", "solo", "")

	code, out, errOut := runList(t, "--all")
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
	want := `"newest copy"  dup  folder="/proj/b"  started=2026-05-25T09:00:00.000Z  updated=2026-05-25T12:00:05.000Z` + "\n" +
		`"solo"  solo  folder="/proj/a"  started=2026-05-25T09:00:00.000Z  updated=2026-05-25T12:00:02.000Z` + "\n"
	if out != want {
		t.Errorf("stdout =\n%s\nwant\n%s", out, want)
	}
	wantErr := "codemeld: sessions list: skipped folder \"no-folder-file\" (unreadable)\n" +
		"codemeld: sessions list: discarded duplicate session \"dup\" from folder \"/proj/a\"\n"
	if errOut != wantErr {
		t.Errorf("stderr = %q, want %q", errOut, wantErr)
	}

	code, out, _ = runList(t, "--all", "--json")
	var rows []map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &rows) != nil || len(rows) != 2 || rows[0]["folder"] != "/proj/b" {
		t.Errorf("--json exit = %d stdout = %s", code, out)
	}
}

func TestSessionsList_ControlCharactersInFilenameID(t *testing.T) {
	f := newListFixture(t)
	cur := f.currentDir(t)
	stems := []string{"a\nb", "a\tb", "a\rb", "a\x1b[31mb"}
	for i, stem := range stems {
		writeListSession(t, cur, stem, f.canonical, fmt.Sprintf("2026-05-25T12:00:0%d.000Z", i+1), "t", "")
	}
	uuid := ids.NewV7()
	writeListSession(t, cur, uuid, f.canonical, "2026-05-25T12:00:09.000Z", "t", "")

	for _, args := range [][]string{nil, {"--all"}} {
		code, out, errOut := runList(t, args...)
		if code != 0 {
			t.Fatalf("%v: exit = %d, stderr = %q", args, code, errOut)
		}
		lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		if len(lines) != len(stems)+1 || strings.ContainsAny(out, "\t\r\x1b") {
			t.Fatalf("%v: stdout = %q, want one control-free row per session", args, out)
		}
		if !strings.HasPrefix(lines[0], `"t"  `+uuid+"  folder=") {
			t.Errorf("%v: UUID row = %q, want the ID unquoted", args, lines[0])
		}
		for i, stem := range stems {
			if !strings.HasPrefix(lines[len(stems)-i], `"t"  `+strconv.Quote(stem)+"  folder=") {
				t.Errorf("%v: row %d = %q, want ID %s", args, len(stems)-i, lines[len(stems)-i], strconv.Quote(stem))
			}
		}
	}

	code, out, _ := runList(t, "--all", "--json")
	var rows []listRow
	if code != 0 || json.Unmarshal([]byte(out), &rows) != nil || len(rows) != len(stems)+1 {
		t.Fatalf("--json exit = %d stdout = %s", code, out)
	}
	for i, stem := range stems {
		if rows[len(stems)-i].ID != stem {
			t.Errorf("JSON row %d ID = %q, want %q", len(stems)-i, rows[len(stems)-i].ID, stem)
		}
	}
}

func TestSessionsList_AllEmptyStemCandidateKeepsFolder(t *testing.T) {
	f := newListFixture(t)
	a := f.folderDir(t, "aaa-a", "/proj/a")
	writeListSession(t, a, "kept", "/proj/a", "2026-05-25T12:00:01.000Z", "kept", "")
	if err := os.WriteFile(filepath.Join(a, ".json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := f.folderDir(t, "zzz-empty", "")
	if err := os.WriteFile(filepath.Join(empty, "folder"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := "codemeld: sessions list: skipped session \"\" in folder \"/proj/a\" (unreadable or unparseable)\n" +
		"codemeld: sessions list: skipped folder \"zzz-empty\" (unreadable)\n"

	for _, args := range [][]string{{"--all"}, {"--all", "--json"}} {
		code, out, errOut := runList(t, args...)
		if code != 0 || !strings.Contains(out, "kept") || errOut != wantErr {
			t.Errorf("%v: exit = %d stdout = %q stderr = %q, want stderr %q", args, code, out, errOut, wantErr)
		}
	}
}

func TestSessionsList_EmptyResults(t *testing.T) {
	newListFixture(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "no sessions found for this folder\n"},
		{[]string{"--all"}, "no sessions found\n"},
		{[]string{"--json"}, "[]\n"},
		{[]string{"--all", "--json"}, "[]\n"},
	} {
		code, out, errOut := runList(t, tc.args...)
		if code != 0 || out != tc.want || errOut != "" {
			t.Errorf("%v: exit = %d stdout = %q stderr = %q, want 0 %q", tc.args, code, out, errOut, tc.want)
		}
	}
}

func TestSessionsList_EnumerationFailures(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("readdir permission failure is not reproducible as root")
	}
	f := newListFixture(t)
	cur := f.currentDir(t)
	other := f.folderDir(t, "other", "/proj/other")
	writeListSession(t, other, "s-other", "/proj/other", "2026-05-25T12:00:00.000Z", "kept", "")

	if err := os.Chmod(cur, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cur, 0o755) })
	code, out, errOut := runList(t)
	want := "codemeld: session list: cannot enumerate " + cur + ": permission_denied\n"
	if code != 1 || out != "" || errOut != want {
		t.Errorf("current folder: exit = %d stdout = %q stderr = %q, want 1 and %q", code, out, errOut, want)
	}

	code, out, errOut = runList(t, "--all", "--json")
	if code != 0 || !strings.Contains(out, `"s-other"`) ||
		errOut != "codemeld: sessions list: skipped folder "+strconv.Quote(filepath.Base(cur))+" (unreadable)\n" {
		t.Errorf("--all per-folder failure: exit = %d stdout = %q stderr = %q", code, out, errOut)
	}

	if err := os.Chmod(f.root, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.root, 0o755) })
	code, out, errOut = runList(t, "--all")
	want = "codemeld: session list: cannot enumerate " + f.root + ": permission_denied\n"
	if code != 1 || out != "" || errOut != want {
		t.Errorf("--all root: exit = %d stdout = %q stderr = %q, want 1 and %q", code, out, errOut, want)
	}
}

func TestSessionsList_UsageErrors(t *testing.T) {
	newListFixture(t)
	code, out, errOut := runList(t, "extra")
	if code != 2 || out != "" || errOut != "codemeld: sessions list accepts no arguments; got 1\n" {
		t.Errorf("positional: exit = %d stdout = %q stderr = %q, want a usage error", code, out, errOut)
	}
	for _, args := range [][]string{{"--all=maybe"}, {"--json=maybe"}, {"--bogus"}} {
		code, _, errOut := runList(t, args...)
		if code == 0 || !strings.Contains(errOut, "Incorrect Usage") {
			t.Errorf("%v: exit = %d stderr = %q, want a usage error", args, code, errOut)
		}
	}
}

func TestSessionsListHelp(t *testing.T) {
	for _, args := range [][]string{
		{"codemeld", "sessions", "list", "-h"},
		{"codemeld", "sessions", "list", "--help"},
		{"codemeld", "help", "sessions", "list"},
	} {
		stubNoLaunch(t)
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), args, &stdout, &stderr); code != 0 {
			t.Fatalf("%v: exit = %d stderr = %q", args, code, stderr.String())
		}
		out := stdout.String()
		for _, want := range []string{
			"codemeld sessions list [--all] [--json]", "--all", "--json", "every", "never writes, locks",
			"stored title, whether you set it or it was generated",
			"or its first message when it has no title (an empty name when it has neither)",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%v help missing %q:\n%s", args, want, out)
			}
		}
		if strings.Contains(out, "codemeld sessions doctor <session-id|path>  ") {
			t.Errorf("%v printed the parent help:\n%s", args, out)
		}
	}
}

func systemOneFloat(v float64) *float64 { return &v }

func systemOneCheck(subjectKind, subject, provider, model, outcome, reason, effect string, pReadOnly, tReadOnly float64) events.PermissionSystemOneCheck {
	p := events.PermissionSystemOneCheck{
		SubjectKind: subjectKind, Subject: subject, PathScope: auditProj,
		Provider: provider, ModelID: model, Outcome: outcome, Reason: reason, Effect: effect, DurationMs: 300,
	}
	if outcome == "allowed" || outcome == "declined" {
		p.PReadOnly, p.PSecrets, p.PCode = systemOneFloat(pReadOnly), systemOneFloat(0), systemOneFloat(0.01)
		p.TReadOnly, p.TSecrets, p.TCode = systemOneFloat(tReadOnly), systemOneFloat(0.5), systemOneFloat(0)
	}
	return p
}

type systemOnePermissionsJSON struct {
	NonPrompted map[string]int `json:"non_prompted"`
	SystemOne   struct {
		Outcomes       map[string]int `json:"outcomes"`
		FailureReasons map[string]int `json:"failure_reasons"`
		SkippedReasons map[string]int `json:"skipped_reasons"`
		Allowed        []struct {
			Subject   string  `json:"subject"`
			ModelID   string  `json:"model_id"`
			PReadOnly float64 `json:"p_read_only"`
			TReadOnly float64 `json:"t_read_only"`
		} `json:"allowed"`
	} `json:"system_one"`
}

func decodeSystemOnePermissions(t *testing.T, path string) systemOnePermissionsJSON {
	t.Helper()
	out := runPermissions(t, path, "--json")
	var report systemOnePermissionsJSON
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("--json output is not one valid JSON document: %v\n%s", err, out)
	}
	return report
}

func TestSessionsPermissions_SystemOneChecksFromSessionFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "system-one.json")
	store := sessions.New(path, &sessions.Session{Metadata: sessions.Metadata{
		ID: ids.NewV7(), Folder: "/some/folder", StartedAt: fixtureTime, UpdatedAt: fixtureTime, SchemaVersion: 1,
	}})
	checks := []events.PermissionSystemOneCheck{
		systemOneCheck("direct", "git status", "openrouter", "jev/jev-1", "allowed", "", "read_only", 0.97, 0.9),
		systemOneCheck("direct", "rm -rf build", "venice", "jev/jev-2", "declined", "", "deletes", 0.1, 0.8),
		systemOneCheck("literal", "ls | wc -l", "openrouter", "jev/jev-1", "failed", "timeout", "", 0, 0),
		systemOneCheck("direct", "make", "openrouter", "jev/jev-1", "skipped", "paused", "", 0, 0),
		systemOneCheck("literal", "bash --version | head -1", "openrouter", "jev/jev-1", "skipped", "wrapper", "", 0, 0),
		systemOneCheck("literal", "type jq bats | head", "openrouter", "jev/jev-1", "skipped", "wrapper", "", 0, 0),
		systemOneCheck("literal", "echo $(id)", "openrouter", "jev/jev-1", "skipped", "substitution", "", 0, 0),
		systemOneCheck("direct", "nosuchprogram x", "openrouter", "jev/jev-1", "skipped", "program_location", "", 0, 0),
	}
	for _, p := range checks {
		if err := events.EmitSystemOneCheckAttributed(store, p, ""); err != nil {
			t.Fatalf("EmitSystemOneCheckAttributed(%s) error = %v", p.Outcome, err)
		}
	}
	if err := events.EmitMatchedIdentity(store, "direct", "git status", auditProj, "", "", "once", "system_one_check", "", ""); err != nil {
		t.Fatalf("EmitMatchedIdentity() error = %v", err)
	}
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	text := runPermissions(t, path)
	for _, want := range []string{
		"non-prompted authorizations: 1 (grant: 0, cache: 0, mode_auto: 0, declared_scope: 0, declared_command: 0, open_read: 0, confined: 0, system_one_check: 1)",
		"System One checks: 8 (allowed: 1, declined: 1, failed: 1, skipped: 5)",
		"failed by reason: credits: 0, auth: 0, rate_limited: 0, timeout: 1, server: 0, network: 0, malformed: 0, no_key: 0\n" +
			"skipped by reason: paused: 1, text: 0, blocked_paths_unavailable: 0, substitution: 1, blocked_path: 0, wrapper: 2, program_location: 1, shell_shape: 0\n",
		"  1. [allowed] \"git status\"  model=\"jev/jev-1\"  p_read_only=0.97  t_read_only=0.9\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("permissions text missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "rm -rf build") || strings.Contains(text, "  2. [allowed]") {
		t.Fatalf("a check that was not allowed was listed as allowed:\n%s", text)
	}

	report := decodeSystemOnePermissions(t, path)
	total := 0
	for _, n := range report.NonPrompted {
		total += n
	}
	if report.NonPrompted["system_one_check"] != 1 || total != 1 {
		t.Fatalf("non_prompted = %v, want exactly one system_one_check authorization", report.NonPrompted)
	}
	wantOutcomes := map[string]int{"allowed": 1, "declined": 1, "failed": 1, "skipped": 5}
	if !reflect.DeepEqual(report.SystemOne.Outcomes, wantOutcomes) {
		t.Fatalf("system_one.outcomes = %v, want %v", report.SystemOne.Outcomes, wantOutcomes)
	}
	wantReasons := map[string]int{"credits": 0, "auth": 0, "rate_limited": 0, "timeout": 1, "server": 0, "network": 0, "malformed": 0, "no_key": 0}
	if !reflect.DeepEqual(report.SystemOne.FailureReasons, wantReasons) {
		t.Fatalf("system_one.failure_reasons = %v, want %v", report.SystemOne.FailureReasons, wantReasons)
	}
	wantSkipped := map[string]int{"paused": 1, "text": 0, "blocked_paths_unavailable": 0, "substitution": 1, "blocked_path": 0, "wrapper": 2, "program_location": 1, "shell_shape": 0}
	if !reflect.DeepEqual(report.SystemOne.SkippedReasons, wantSkipped) {
		t.Fatalf("system_one.skipped_reasons = %v, want %v", report.SystemOne.SkippedReasons, wantSkipped)
	}
	allowed := report.SystemOne.Allowed
	if len(allowed) != 1 || allowed[0].Subject != "git status" || allowed[0].ModelID != "jev/jev-1" ||
		allowed[0].PReadOnly != 0.97 || allowed[0].TReadOnly != 0.9 {
		t.Fatalf("system_one.allowed = %+v, want the one allowed git status check", allowed)
	}
}

func TestSessionsPermissions_SystemOneChecksAreNotPairedWithMatches(t *testing.T) {
	matched := func() sessions.Record {
		return eventRecord(events.KindPermissionMatched, events.PermissionMatched{
			SubjectKind: "direct", Subject: "git status", PathScope: auditProj, Outcome: "once", OutcomeSource: "system_one_check",
		})
	}
	path := writeSession(t, "system-one-interleaved", []sessions.Record{
		eventRecord(events.KindPermissionSystemOneCheck, systemOneCheck("direct", "git status", "openrouter", "jev/jev-1", "allowed", "", "read_only", 0.95, 0.9)),
		eventRecord(events.KindPermissionSystemOneCheck, systemOneCheck("direct", "git status", "venice", "jev/jev-2", "allowed", "", "read_only", 0.99, 0.97)),
		eventRecord(events.KindPermissionSystemOneCheck, systemOneCheck("direct", "curl x", "openrouter", "jev/jev-1", "declined", "", "network", 0.2, 0.9)),
		matched(),
		eventRecord(events.KindPermissionSystemOneCheck, systemOneCheck("direct", "ls", "openrouter", "jev/jev-1", "failed", "network", "", 0, 0)),
		matched(),
		eventRecord(events.KindPermissionSystemOneCheck, systemOneCheck("direct", "ls", "openrouter", "jev/jev-1", "skipped", "paused", "", 0, 0)),
	})

	text := runPermissions(t, path)
	first := strings.Index(text, "  1. [allowed] \"git status\"  model=\"jev/jev-1\"  p_read_only=0.95  t_read_only=0.9\n")
	second := strings.Index(text, "  2. [allowed] \"git status\"  model=\"jev/jev-2\"  p_read_only=0.99  t_read_only=0.97\n")
	if first < 0 || second < first {
		t.Fatalf("allowed rows missing or out of record order:\n%s", text)
	}
	if want := "confined: 0, system_one_check: 2)"; !strings.Contains(text, want) {
		t.Fatalf("permissions text missing %q:\n%s", want, text)
	}

	report := decodeSystemOnePermissions(t, path)
	if report.NonPrompted["system_one_check"] != 2 {
		t.Fatalf("non_prompted.system_one_check = %d, want 2", report.NonPrompted["system_one_check"])
	}
	if got := report.SystemOne.Allowed; len(got) != 2 || got[0].ModelID != "jev/jev-1" || got[1].ModelID != "jev/jev-2" {
		t.Fatalf("system_one.allowed = %+v, want both git status rows in record order", got)
	}
}

func TestSessionsPermissions_SystemOneAllowedRowEscapesControls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "system-one-controls.json")
	store := sessions.New(path, &sessions.Session{Metadata: sessions.Metadata{
		ID: ids.NewV7(), Folder: "/some/folder", StartedAt: fixtureTime, UpdatedAt: fixtureTime, SchemaVersion: 1,
	}})
	subject, model := "git status\nprintf done", "jev/\x1b[2Jjev-1"
	if err := events.EmitSystemOneCheckAttributed(store, systemOneCheck("direct", subject, "openrouter", model, "allowed", "", "read_only", 0.97, 0.9), ""); err != nil {
		t.Fatalf("EmitSystemOneCheckAttributed() error = %v", err)
	}
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	text := runPermissions(t, path)
	if want := `  1. [allowed] "git status\nprintf done"  model="jev/\x1b[2Jjev-1"  p_read_only=0.97  t_read_only=0.9` + "\n"; !strings.Contains(text, want) {
		t.Fatalf("permissions text missing one escaped allowed line %q:\n%s", want, text)
	}
	if strings.Contains(text, "\x1b") || strings.Contains(text, "\nprintf done") {
		t.Fatalf("permissions text carries a raw control from the allowed row:\n%q", text)
	}

	allowed := decodeSystemOnePermissions(t, path).SystemOne.Allowed
	if len(allowed) != 1 || allowed[0].Subject != subject || allowed[0].ModelID != model {
		t.Fatalf("system_one.allowed = %+v, want the original subject and model_id", allowed)
	}
}
