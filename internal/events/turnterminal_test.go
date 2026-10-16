package events

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/sessions"
)

const (
	testTurnID  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01"
	testRoundID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a02"
)

func TestTurnTerminal_AcceptsEveryOutcome(t *testing.T) {
	cases := []struct {
		name    string
		payload TurnTerminal
	}{
		{"completed", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeCompleted}},
		{"completed after dispatch", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeCompleted, DispatchStarted: true}},
		{"cancelled", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeCancelled}},
		{"cancelled mid-dispatch", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeCancelled, DispatchStarted: true}},
		{"provider failed with phase", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeProviderFailed, FailurePhase: "stream_drop"}},
		{"provider failed without phase", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeProviderFailed}},
		{"invalid response", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeInvalidResponse}},
		{"tool assembly failed", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeToolAssemblyFailed}},
		{"tool plan invalid", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeToolPlanInvalid}},
		{"dispatch failed", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed, DispatchStarted: true}},
		{"dispatch failed with a safe tool", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed, DispatchStarted: true, FailureReason: DispatchReasonToolDispatchFailed, FailedTool: "bash"}},
		{"dispatch failed with no identifiable tool", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed, DispatchStarted: true, FailureReason: DispatchReasonPostPlanFailed}},
		{"continuation failed", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeContinuationFailed, DispatchStarted: true}},
		{"security halted before dispatch", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeSecurityHalted}},
		{"security halted mid-dispatch", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeSecurityHalted, DispatchStarted: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := Append(newStore(), tc.payload)
			if err != nil {
				t.Fatalf("Append(%+v) error = %v, want nil", tc.payload, err)
			}
			ev, ok := rec.(sessions.Event)
			if !ok || ev.Kind != KindTurnTerminal {
				t.Fatalf("record = %T kind %q, want sessions.Event %q", rec, ev.Kind, KindTurnTerminal)
			}
			if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
				t.Fatalf("ValidatePayload of an emitted record = %v, want nil", err)
			}
		})
	}
}

func TestTurnTerminal_RejectsRecordsOutsideTheContract(t *testing.T) {
	cases := []struct {
		name    string
		payload TurnTerminal
	}{
		{"no turn id", TurnTerminal{RoundID: testRoundID, Outcome: TurnOutcomeCompleted}},
		{"no round id", TurnTerminal{TurnID: testTurnID, Outcome: TurnOutcomeCompleted}},
		{"turn id not a uuidv7", TurnTerminal{TurnID: "turn-1", RoundID: testRoundID, Outcome: TurnOutcomeCompleted}},
		{"round id not a uuidv7", TurnTerminal{TurnID: testTurnID, RoundID: "round-1", Outcome: TurnOutcomeCompleted}},
		{"no outcome", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID}},
		{"unknown outcome", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: "finished"}},
		{"response text smuggled as an outcome", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: "the model replied: hello"}},
		{"tool arguments smuggled as a phase", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeProviderFailed, FailurePhase: `{"path":"/etc/passwd"}`}},
		{"unknown phase", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeProviderFailed, FailurePhase: "tool_handoff"}},
		{"phase on a non-provider outcome", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed, FailurePhase: "http", DispatchStarted: true}},
		{"dispatch started on an assembly failure", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeToolAssemblyFailed, DispatchStarted: true}},
		{"dispatch started on an invalid plan", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeToolPlanInvalid, DispatchStarted: true}},
		{"dispatch started on a provider failure", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeProviderFailed, FailurePhase: "http", DispatchStarted: true}},
		{"dispatch failure that never dispatched", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed}},
		{"unknown failure reason", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed, DispatchStarted: true, FailureReason: "shell exited 1", FailedTool: "bash"}},
		{"raw error smuggled as a failure reason", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed, DispatchStarted: true, FailureReason: "fork/exec /bin/sh: no such file"}},
		{"failed tool without a reason", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed, DispatchStarted: true, FailedTool: "bash"}},
		{"reason without the required failed tool", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed, DispatchStarted: true, FailureReason: DispatchReasonToolDispatchFailed}},
		{"failed tool alongside the generic reason", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed, DispatchStarted: true, FailureReason: DispatchReasonPostPlanFailed, FailedTool: "bash"}},
		{"unbounded failed tool", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed, DispatchStarted: true, FailureReason: DispatchReasonToolDispatchFailed, FailedTool: strings.Repeat("a", 33)}},
		{"command text smuggled as a failed tool", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed, DispatchStarted: true, FailureReason: DispatchReasonToolDispatchFailed, FailedTool: "cat /etc/passwd"}},
		{"uppercase failed tool", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed, DispatchStarted: true, FailureReason: DispatchReasonToolDispatchFailed, FailedTool: "Bash"}},
		{"credential smuggled as a bounded lowercase failed tool", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed, DispatchStarted: true, FailureReason: DispatchReasonToolDispatchFailed, FailedTool: "sk_live_abcdef0123456789"}},
		{"non-built-in failed tool", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed, DispatchStarted: true, FailureReason: DispatchReasonToolDispatchFailed, FailedTool: "not_a_tool"}},
		{"dispatch diagnostic on a completed turn", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeCompleted, DispatchStarted: true, FailureReason: DispatchReasonPostPlanFailed}},
		{"dispatch diagnostic on a continuation failure", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeContinuationFailed, DispatchStarted: true, FailureReason: DispatchReasonToolDispatchFailed, FailedTool: "bash"}},
		{"dispatch diagnostic on a cancellation", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeCancelled, DispatchStarted: true, FailureReason: DispatchReasonPostPlanFailed}},
		{"security halt with a failure phase", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeSecurityHalted, FailurePhase: "http"}},
		{"security halt with a failed tool", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeSecurityHalted, DispatchStarted: true, FailureReason: DispatchReasonToolDispatchFailed, FailedTool: "bash"}},
		{"security halt with a failure reason", TurnTerminal{TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeSecurityHalted, DispatchStarted: true, FailureReason: DispatchReasonPostPlanFailed}},
		{"security halt without a real turn", TurnTerminal{RoundID: testRoundID, Outcome: TurnOutcomeSecurityHalted}},
		{"security halt without a real round", TurnTerminal{TurnID: testTurnID, Outcome: TurnOutcomeSecurityHalted}},
		{"security halt with a sentinel round", TurnTerminal{TurnID: testTurnID, RoundID: "NA-startup", Outcome: TurnOutcomeSecurityHalted}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore()
			if _, err := Append(store, tc.payload); err == nil {
				t.Fatalf("Append(%+v) accepted an invalid record", tc.payload)
			}
			if got := len(store.Records()); got != 0 {
				t.Fatalf("rejected payload appended %d record(s), want 0", got)
			}
			raw, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			if err := ValidatePayload(KindTurnTerminal, raw); err == nil {
				t.Fatalf("ValidatePayload(%s) accepted an invalid record", raw)
			}
		})
	}
}

func TestSafeFailedTool_AdmitsOnlyBuiltinAdvertisedNames(t *testing.T) {
	for _, name := range []string{"bash", "read", "edit", "ask_user", "web_fetch", "vcs_commit", "file_count"} {
		if !SafeFailedTool(name) {
			t.Errorf("SafeFailedTool(%q) = false, want true (it is a built-in advertised tool)", name)
		}
	}
	for _, name := range []string{"", "Bash", "BashTool", strings.Repeat("a", 33), "cat /etc/passwd", "ACCESSKEYEXAMPLE1234", "_private", "vcs.commit", "not_a_tool"} {
		if SafeFailedTool(name) {
			t.Errorf("SafeFailedTool(%q) = true, want false", name)
		}
	}
}

func TestTurnTerminal_DispatchDiagnosticSurvivesReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())

	if err := EmitTurnTerminal(context.Background(), store, TurnTerminal{
		TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed,
		DispatchStarted: true, FailureReason: DispatchReasonToolDispatchFailed, FailedTool: "bash",
	}, nil); err != nil {
		t.Fatalf("EmitTurnTerminal error = %v", err)
	}

	got := onlyTurnTerminal(t, path)
	if got.FailureReason != DispatchReasonToolDispatchFailed || got.FailedTool != "bash" {
		t.Fatalf("(failure_reason, failed_tool) = (%q, %q), want (%q, \"bash\")", got.FailureReason, got.FailedTool, DispatchReasonToolDispatchFailed)
	}
}

// A record written before these fields existed must still load.
func TestTurnTerminal_LegacyDispatchRecordLoads(t *testing.T) {
	raw := json.RawMessage(`{"turn_id":"` + testTurnID + `","round_id":"` + testRoundID + `","outcome":"dispatch_failed","dispatch_started":true}`)
	if err := ValidatePayload(KindTurnTerminal, raw); err != nil {
		t.Fatalf("ValidatePayload(%s) rejected a record without the new fields: %v", raw, err)
	}
}

func TestTurnTerminal_RejectsContentFields(t *testing.T) {
	for _, field := range []string{"response_text", "tool_arguments", "secret"} {
		t.Run(field, func(t *testing.T) {
			raw := json.RawMessage(`{"turn_id":"` + testTurnID + `","round_id":"` + testRoundID + `","outcome":"completed","dispatch_started":false,"` + field + `":"private"}`)
			if err := ValidatePayload(KindTurnTerminal, raw); err == nil {
				t.Fatalf("ValidatePayload(%s) accepted an unknown content field", raw)
			}
		})
	}
}

func TestTurnTerminal_AcceptsFutureOptionalFields(t *testing.T) {
	raw := json.RawMessage(`{"turn_id":"` + testTurnID + `","round_id":"` + testRoundID + `","outcome":"completed","dispatch_started":false,"future_field":true}`)
	if err := ValidatePayload(KindTurnTerminal, raw); err != nil {
		t.Fatalf("ValidatePayload(%s) rejected a future optional field: %v", raw, err)
	}
}

func TestTurnTerminal_WireFormCarriesNoContentFields(t *testing.T) {
	rec, err := Append(newStore(), TurnTerminal{
		TurnID:          testTurnID,
		RoundID:         testRoundID,
		Outcome:         TurnOutcomeProviderFailed,
		FailurePhase:    "http",
		DispatchStarted: false,
	})
	if err != nil {
		t.Fatalf("Append error = %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rec.(sessions.Event).Payload, &fields); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	got := make([]string, 0, len(fields))
	for name := range fields {
		got = append(got, name)
	}
	slices.Sort(got)
	want := []string{"dispatch_started", "failure_phase", "outcome", "round_id", "turn_id"}
	if !slices.Equal(got, want) {
		t.Fatalf("payload fields = %v, want exactly %v", got, want)
	}
}

func TestEmitTurnTerminal_RealStoreSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())

	if err := EmitTurnTerminal(context.Background(), store, TurnTerminal{
		TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeDispatchFailed, DispatchStarted: true,
	}, nil); err != nil {
		t.Fatalf("EmitTurnTerminal error = %v", err)
	}

	got := onlyTurnTerminal(t, path)
	if got.TurnID != testTurnID || got.RoundID != testRoundID {
		t.Errorf("(turn_id, round_id) = (%q, %q), want (%q, %q)", got.TurnID, got.RoundID, testTurnID, testRoundID)
	}
	if got.Outcome != TurnOutcomeDispatchFailed || !got.DispatchStarted {
		t.Errorf("(outcome, dispatch_started) = (%q, %t), want (%q, true)", got.Outcome, got.DispatchStarted, TurnOutcomeDispatchFailed)
	}
}

func TestEmitTurnTerminal_PersistsAfterContextCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := EmitTurnTerminal(ctx, store, TurnTerminal{
		TurnID: testTurnID, RoundID: testRoundID, Outcome: TurnOutcomeCancelled,
	}, nil); err != nil {
		t.Fatalf("EmitTurnTerminal error = %v, want nil despite a cancelled context", err)
	}
	if got := onlyTurnTerminal(t, path).Outcome; got != TurnOutcomeCancelled {
		t.Fatalf("persisted outcome = %q, want %q", got, TurnOutcomeCancelled)
	}
}

func TestEmitTurnTerminal_InvalidPayloadSkipsFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())

	if err := EmitTurnTerminal(context.Background(), store, TurnTerminal{
		TurnID: testTurnID, RoundID: testRoundID, Outcome: "finished",
	}, nil); err == nil {
		t.Fatal("EmitTurnTerminal accepted an unknown outcome")
	}
	if got := len(store.Records()); got != 0 {
		t.Errorf("invalid payload appended %d record(s), want 0", got)
	}
	if _, err := os.ReadFile(path); err == nil {
		t.Error("session file written after a rejected append")
	}
}

func TestProviderRoundTrip_CorrelationPairing(t *testing.T) {
	cases := []struct {
		name    string
		payload ProviderRoundTrip
		wantErr bool
	}{
		{"legacy record without the pair", ProviderRoundTrip{Provider: "openai", ModelID: "gpt-x", DurationMs: 40}, false},
		{"new record with the pair", ProviderRoundTrip{Provider: "openai", ModelID: "gpt-x", DurationMs: 40, TurnID: testTurnID, RoundID: testRoundID}, false},
		{"turn id only", ProviderRoundTrip{Provider: "openai", ModelID: "gpt-x", DurationMs: 40, TurnID: testTurnID}, true},
		{"round id only", ProviderRoundTrip{Provider: "openai", ModelID: "gpt-x", DurationMs: 40, RoundID: testRoundID}, true},
		{"non-uuidv7 pair", ProviderRoundTrip{Provider: "openai", ModelID: "gpt-x", DurationMs: 40, TurnID: "turn-1", RoundID: "round-1"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := Append(newStore(), tc.payload)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Append(%+v) accepted a half-formed correlation", tc.payload)
				}
				return
			}
			if err != nil {
				t.Fatalf("Append(%+v) error = %v, want nil", tc.payload, err)
			}
			ev := rec.(sessions.Event)
			if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
				t.Fatalf("ValidatePayload of an emitted record = %v, want nil", err)
			}
			var got ProviderRoundTrip
			if err := json.Unmarshal(ev.Payload, &got); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			if got.TurnID != tc.payload.TurnID || got.RoundID != tc.payload.RoundID {
				t.Fatalf("reloaded correlation = (%q, %q), want (%q, %q)",
					got.TurnID, got.RoundID, tc.payload.TurnID, tc.payload.RoundID)
			}
		})
	}
}

func TestToolHandoffPhase_ExtendsOnlyTheRetryVocabulary(t *testing.T) {
	retry := ProviderRequestRetry{
		Provider: "openai", ModelID: "gpt-x", Attempt: 1,
		Phase: RetryPhaseToolHandoff, Reason: RetryReasonAssemblyFailed, DelayMs: 10,
	}
	if _, err := Append(newStore(), retry); err != nil {
		t.Fatalf("provider_request_retry rejected the tool_handoff phase: %v", err)
	}
	skipped := ProviderRequestRetrySkipped{
		Provider: "openai", ModelID: "gpt-x", Attempt: 2,
		Phase: RetryPhaseToolHandoff, Reason: RetryReasonInvalidPlan, SkipReason: "max_attempts_reached",
	}
	if _, err := Append(newStore(), skipped); err != nil {
		t.Fatalf("provider_request_retry_skipped rejected the tool_handoff phase: %v", err)
	}
	crossed := ProviderRequestRetry{
		Provider: "openai", ModelID: "gpt-x", Attempt: 1,
		Phase: RetryPhaseToolHandoff, Reason: "stream_eof", DelayMs: 10,
	}
	if _, err := Append(newStore(), crossed); err == nil {
		t.Fatal("provider_request_retry accepted a provider reason under the tool_handoff phase")
	}
	failed := ProviderRequestFailed{
		Provider: "openai", ModelID: "gpt-x",
		Phase: RetryPhaseToolHandoff, Reason: RetryReasonAssemblyFailed, ErrorDetail: "no id",
	}
	if _, err := Append(newStore(), failed); err == nil {
		t.Fatal("provider_request_failed accepted the tool_handoff phase; its taxonomy must be unchanged")
	}
}

func onlyTurnTerminal(t *testing.T, path string) TurnTerminal {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("session file not written (flush did not run): %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse written session: %v", err)
	}
	if len(loaded.Records) != 1 {
		t.Fatalf("persisted records = %d, want 1", len(loaded.Records))
	}
	ev, ok := loaded.Records[0].(sessions.Event)
	if !ok || ev.Kind != KindTurnTerminal {
		t.Fatalf("record = %T kind %q, want sessions.Event %q", loaded.Records[0], ev.Kind, KindTurnTerminal)
	}
	if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
		t.Fatalf("persisted record fails load validation: %v", err)
	}
	var got TurnTerminal
	if err := json.Unmarshal(ev.Payload, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return got
}
