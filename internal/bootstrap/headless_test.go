// Headless one-shot run tests: the fail-closed default-deny posture, the
// active-mode overlay (read-only auto-allow, Plan mutating deny), one-turn
// turn.NewToolLoop wiring through stub provider clients, durable/resumable session
// persistence, and the RunHeadless short-circuits (first-run, picker-required). These
// drive the real production seams the headless driver assembles — the production tool
// dispatcher, the fail-closed headless authorizer, and turn.NewToolLoop — with no
// network, reading the durable record stream back from the session file.
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/subagent"
	"codemeld.dev/codemeld/internal/trust"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/turn"
)

// headlessProviderConfig is a composed-config map exposing the openai provider
// credentials without a settings models list, so the configured selectable IDs
// derive solely from the seeded discovered-model store beside ConfigLayerPaths.
func headlessProviderConfig() map[string]any {
	return map[string]any{
		"provider": map[string]any{
			"openai": map[string]any{
				"base_url": "https://api.openai.com/v1",
				"api_key":  "sk-test",
			},
		},
	}
}

// headlessResult builds a BootstrapResult the driver can run a turn over: an
// openai/gpt-5.5 selection against the discovered-model catalog, a writable session
// store, a real (built-in-tools) registry factory, and the given active mode.
func headlessResult(t *testing.T, dir string, m *mode.ActiveState) *BootstrapResult {
	t.Helper()
	home := t.TempDir()
	settings := SettingsPath(home)
	seedOpenAIDiscovered(t, settings, "gpt-5.5")
	return &BootstrapResult{
		Home:             home,
		LaunchDir:        dir,
		ProjectRoot:      dir,
		Session:          storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000aa", dir),
		Model:            model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config:           headlessProviderConfig(),
		ConfigLayerPaths: []string{settings},
		Mode:             m,
		ToolRegistry:     &toolRegistryFactory{active: nil},
		// dir carries no project settings, which the real gate decides is trusted by
		// vacuity; a zero Decision would stand in for a refusal these fixtures never made.
		TrustDecision: trust.Decision{Trusted: true, Reason: trust.ReasonNothingCovered, Root: mustCanonical(t, dir)},
	}
}

// TestRunHeadless_DefaultDenyMutatingShellInBand pins the anti-YOLO default: in Build,
// a mutating shell call with no grant is denied (the run-mode deny envelope is persisted
// as an in-band tool message), nothing executes on disk, the denied subject is tracked for
// the summary, and the session records a durable permission_decision{denied}. With no
// approver the refusal is unattended rather than a user refusal, so the run recovers and
// still answers on stdout instead of exiting empty-handed.
func TestRunHeadless_DefaultDenyMutatingShellInBand(t *testing.T) {
	dir := t.TempDir()
	notes := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notes, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed notes.txt: %v", err)
	}

	client := toolThenContentClient(nil, "bash", `{"command":"rm notes.txt"}`, "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("delete my notes", &stdout, &stderr)
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	// Fail-closed: the denied mutating command never executed, so the file survives.
	if _, err := os.Stat(notes); err != nil {
		t.Fatalf("notes.txt missing — a denied mutating command must change nothing on disk: %v", err)
	}
	if got := driver.DeniedSubjects(); len(got) != 1 || got[0].Subject != "rm notes.txt" {
		t.Fatalf("DeniedSubjects = %v, want [\"rm notes.txt\"]", got)
	}

	reloaded := reloadStore(t, result.Session)
	toolMsgs := messagesByRole(reloaded, "tool")
	if len(toolMsgs) != 1 || !strings.Contains(toolMsgs[0].Content.Text(), "no approval available in non-interactive run mode") {
		t.Fatalf("tool messages = %+v, want one run-mode deny envelope", toolMsgs)
	}
	if !strings.Contains(toolMsgs[0].Content.Text(), `"denied_by":"unattended"`) {
		t.Fatalf("deny envelope = %s, want denied_by unattended — no human refused it", toolMsgs[0].Content.Text())
	}
	decisions := decodeStoreEvents[events.PermissionDecision](t, reloaded, events.KindPermissionDecision)
	if len(decisions) != 1 || decisions[0].Outcome != "denied" || decisions[0].Subject != "rm notes.txt" {
		t.Fatalf("permission_decision events = %+v, want one denied for \"rm notes.txt\"", decisions)
	}

	if stdout.String() != "ok\n" {
		t.Fatalf("stdout = %q, want the model's reply after it recovers from an unattended denial", stdout.String())
	}
	if strings.Contains(stdout.String(), "rm notes.txt") || strings.Contains(stdout.String(), "denied") {
		t.Fatalf("stdout leaked a diagnostic line:\n%s", stdout.String())
	}
}

func envelopeReason(t *testing.T, envelope string) string {
	t.Helper()
	var env struct {
		DeniedBy string `json:"denied_by"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(envelope), &env); err != nil {
		t.Fatalf("decode envelope %q: %v", envelope, err)
	}
	if env.DeniedBy != "unattended" {
		t.Fatalf("envelope = %s, want denied_by unattended", envelope)
	}
	return env.Reason
}

func runDeniedShellHeadless(t *testing.T, command string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	client := toolThenContentClient(nil, bashToolName, toolArgs(t, map[string]any{"command": command}), "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stderr bytes.Buffer
	driver := NewHeadlessDriver("look around", &bytes.Buffer{}, &stderr)
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}
	toolMsgs := messagesByRole(reloadStore(t, result.Session), "tool")
	if len(toolMsgs) != 1 {
		t.Fatalf("tool messages = %+v, want exactly one", toolMsgs)
	}
	if got := driver.DeniedSubjects(); len(got) != 1 || got[0].Subject != command || got[0].Reason != headlessDenyReason {
		t.Fatalf("DeniedSubjects = %+v, want one %q entry whose summary reason has no hint", got, command)
	}
	return envelopeReason(t, toolMsgs[0].Content.Text()), stderr.String()
}

const wantReadHint = "If you intended only to read, use a structured read tool or a simpler read-only command instead."

func TestRunHeadless_UnattendedShellDenialCarriesReadHint(t *testing.T) {
	cases := []struct {
		name, command, want string
	}{
		{
			name:    "mapped program",
			command: "rg needle *.md 2>/dev/null",
			want:    headlessDenyReason + " " + wantReadHint + " use the grep tool instead of rg.",
		},
		{
			name:    "no mapped program",
			command: "rm -rf build",
			want:    headlessDenyReason + " " + wantReadHint,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, stderr := runDeniedShellHeadless(t, tc.command)
			if reason != tc.want {
				t.Fatalf("envelope reason = %q, want %q", reason, tc.want)
			}
			if !strings.Contains(stderr, "Denied Run: "+tc.command) || !strings.Contains(stderr, wantReadHint) {
				t.Fatalf("stderr = %q, want a Denied Run line for %q carrying the hint", stderr, tc.command)
			}
		})
	}
}

func TestRunHeadless_LongMappedCompoundKeepsReadHintAfterCap(t *testing.T) {
	command := "rg a *.md; grep b *.md; egrep c *.md; fgrep d *.md; cat *.md; head *.md; tail *.md; find *.md; ls *.md; rm *.md 2>/dev/null"
	advice, ok := shellToolAdvice(command)
	if !ok {
		t.Fatalf("shellToolAdvice(%q) found no mapped program", command)
	}
	full := headlessDenyReason + " " + wantReadHint + " " + advice + "."
	if len(full) <= 512 {
		t.Fatalf("uncapped reason is %d bytes, want over the 512-byte envelope cap", len(full))
	}

	reason, _ := runDeniedShellHeadless(t, command)
	if !strings.HasPrefix(reason, headlessDenyReason+" "+wantReadHint) {
		t.Fatalf("envelope reason = %q, want the fixed hint to survive the cap", reason)
	}
	if len(reason) > 512 {
		t.Fatalf("envelope reason is %d bytes, want at most 512", len(reason))
	}
}

func TestShellToolAdvice_IsTheUnprefixedSeamOfShellToolHint(t *testing.T) {
	command := "grep x main.go | head -n 5"
	advice, ok := shellToolAdvice(command)
	wantAdvice := "use the grep tool instead of grep; use the read tool instead of head (offset/limit for a range)"
	if !ok || advice != wantAdvice {
		t.Fatalf("shellToolAdvice = %q, %v; want %q, true", advice, ok, wantAdvice)
	}
	hint, ok := shellToolHint(command)
	if want := "shell-tool hint: this command was not run; " + wantAdvice + "."; !ok || hint != want {
		t.Fatalf("shellToolHint = %q, %v; want %q, true", hint, ok, want)
	}
	if _, ok := shellToolAdvice("rm -rf build"); ok {
		t.Fatal("shellToolAdvice(rm -rf build) reported advice, want none")
	}
}

func TestRunHeadless_UnpromptedRunNeverPromptsOrPersists(t *testing.T) {
	dir := t.TempDir()
	notes := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notes, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed notes.txt: %v", err)
	}

	client := toolThenContentClient(nil, "bash", `{"command":"rm notes.txt"}`, "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("delete my notes", &stdout, &stderr)
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := driver.DeniedSubjects(); len(got) != 1 || got[0].Subject != "rm notes.txt" {
		t.Fatalf("DeniedSubjects = %v, want [\"rm notes.txt\"] (an unprompted run must deny the mutating call)", got)
	}
	for _, forbidden := range []string{"approval required", "allow once", "allow this session", "choose 1-"} {
		if strings.Contains(stderr.String(), forbidden) || strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("an unprompted run rendered prompt text %q:\nstdout=%q\nstderr=%q", forbidden, stdout.String(), stderr.String())
		}
	}
	for _, p := range []string{
		filepath.Join(dir, ".codemeld", "settings.yaml"),
		filepath.Join(result.Home, ".codemeld", "global", "settings.yaml"),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("settings file %s exists — an unprompted run must write no permission entry (stat err = %v)", p, err)
		}
	}
}

// TestRunHeadless_DefaultDenyAdversarialShellForms pins that the default-deny resolves
// to a deny for every form of a mutating command — a bare command, an env-prefixed
// command, a quoted argument, and a sh -c wrapper — none of which executes (Done-when 3
// adversarial table).
func TestRunHeadless_DefaultDenyAdversarialShellForms(t *testing.T) {
	forms := []struct {
		name    string
		command string
	}{
		{"bare", "rm guarded.txt"},
		{"env-prefixed", "FORCE=1 rm guarded.txt"},
		{"quoted argument", `rm "guarded.txt"`},
		{"sh -c wrapper", `sh -c 'rm guarded.txt'`},
	}
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			dir := t.TempDir()
			guarded := filepath.Join(dir, "guarded.txt")
			if err := os.WriteFile(guarded, []byte("keep\n"), 0o644); err != nil {
				t.Fatalf("seed: %v", err)
			}
			args := `{"command":` + mustJSONString(f.command) + `}`
			client := toolThenContentClient(nil, "bash", args, "ok")
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			driver := NewHeadlessDriver("p", &bytes.Buffer{}, &bytes.Buffer{})
			result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}
			if len(driver.DeniedSubjects()) == 0 {
				t.Fatalf("form %q produced no denial, want a fail-closed deny", f.command)
			}
			if _, err := os.Stat(guarded); err != nil {
				t.Fatalf("form %q executed — guarded.txt was removed: %v", f.command, err)
			}
			reloaded := reloadStore(t, result.Session)
			toolMsgs := messagesByRole(reloaded, "tool")
			if len(toolMsgs) != 1 || !strings.Contains(toolMsgs[0].Content.Text(), `"denied_by"`) {
				t.Fatalf("form %q tool messages = %+v, want one deny envelope", f.command, toolMsgs)
			}
		})
	}
}

// TestRunHeadless_ReadOnlyAutoAllows proves the mode overlay is wired and not
// over-restrictive: a read-only shell call auto-allows under the active mode (no grant,
// no denial) and runs, recorded as permission_matched{once, mode_auto} (Done-when 4).
func TestRunHeadless_ReadOnlyAutoAllows(t *testing.T) {
	dir := t.TempDir()
	client := toolThenContentClient(nil, "bash", `{"command":"ls"}`, "done")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("list the files", &bytes.Buffer{}, &bytes.Buffer{})
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %v, want none (a read-only ls auto-allows)", got)
	}
	reloaded := reloadStore(t, result.Session)
	matched := decodePermissionMatched(t, reloaded)
	if len(matched) != 1 || matched[0].Outcome != "once" || matched[0].OutcomeSource != "mode_auto" {
		t.Fatalf("permission_matched = %+v, want one once/mode_auto (read-only auto-allow)", matched)
	}
	toolMsgs := messagesByRole(reloaded, "tool")
	if len(toolMsgs) != 1 || strings.Contains(toolMsgs[0].Content.Text(), `"denied_by"`) {
		t.Fatalf("tool messages = %+v, want one executed (non-deny) result", toolMsgs)
	}
}

// TestRunHeadless_PlanModeDeniesMutating pins --mode plan: a mutating call is denied by the mode
// itself (a mode_auto deny carrying a denied_by:"mode" envelope), not by the default-deny prompt, and
// never executes. Because the denial is a mode-policy refusal, the turn does NOT halt like a
// user denial: the deny envelope is surfaced as a friendly stderr line, the model is re-issued with
// the refusal in context, and its recovery/final text streams to stdout — while stdout never carries
// the raw diagnostic. The default-deny (user-envelope) headless halt is covered separately by
// TestRunHeadless_DefaultDenyMutatingShellInBand.
func TestRunHeadless_PlanModeDeniesMutating(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(target, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	client := toolThenContentClient(nil, "bash", `{"command":"rm x.txt"}`, "reading it instead")
	client.title = streamedTitle("Model title")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("remove x", &stdout, &stderr)
	result := headlessResult(t, dir, mode.NewActiveState(mode.Plan, mode.SourceConfig))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if _, err := os.Stat(target); err != nil {
		t.Fatalf("x.txt missing — Plan must deny the mutating command without executing: %v", err)
	}
	// A recoverable Plan/mode-posture denial must NOT reach the CLI's fail-closed summary:
	// the model continues and answers, and a grant would not authorize the command while the
	// run stays in Plan, so the no-approval/grant summary would mislead. DeniedSubjects stays
	// empty for a mode-only denial; only terminal user refusals are summarized.
	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %v, want none (a Plan mode denial is recoverable, not a no-approval denial)", got)
	}
	// A mode-policy denial continues: the provider is called twice and the model's final text lands.
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (a mode-policy denial re-issues the model)", client.callCount())
	}
	if stdout.String() != "reading it instead\n" {
		t.Fatalf("stdout = %q, want the model's recovery reply after the mode-denial continuation", stdout.String())
	}
	// The refusal is a friendly stderr line naming the command; the raw JSON never reaches stdout.
	if !strings.Contains(stderr.String(), "Denied") || !strings.Contains(stderr.String(), "rm x.txt") {
		t.Fatalf("stderr = %q, want a friendly denial line naming the refused command", stderr.String())
	}
	if strings.Contains(stdout.String(), "denied_by") || strings.Contains(stdout.String(), "Denied") {
		t.Fatalf("stdout leaked a denial diagnostic:\n%s", stdout.String())
	}
	// The recoverable Plan denial must not be dressed up as a missing-approval refusal:
	// neither the no-approval wording nor the grant instruction may appear on stderr.
	if strings.Contains(stderr.String(), "no approval available") || strings.Contains(stderr.String(), "to authorize, grant") {
		t.Fatalf("stderr = %q, want no no-approval/grant summary for a recoverable mode denial", stderr.String())
	}

	reloaded := reloadStore(t, result.Session)
	matched := decodePermissionMatched(t, reloaded)
	if len(matched) != 1 || matched[0].Outcome != "deny" || matched[0].OutcomeSource != "mode_auto" {
		t.Fatalf("permission_matched = %+v, want one deny/mode_auto (Plan mode deny)", matched)
	}
	toolMsgs := messagesByRole(reloaded, "tool")
	if len(toolMsgs) != 1 || !strings.Contains(toolMsgs[0].Content.Text(), `"denied_by":"mode"`) {
		t.Fatalf("tool messages = %+v, want one denied_by:\"mode\" policy envelope", toolMsgs)
	}
	if strings.Contains(toolMsgs[0].Content.Text(), headlessReadOnlyHint) {
		t.Fatalf("mode envelope = %s, want no unattended read hint", toolMsgs[0].Content.Text())
	}
}

// TestRunHeadless_PlainTurnStreamsToStdoutAndPersists covers the one-turn
// turn.NewToolLoop wiring and session durability: a plain (no tool-call) reply streams
// to stdout with no diagnostics on either stream, and the run leaves a durable,
// resumable session whose record stream carries the prompt and the final reply
// (Done-when 1/2/7).
func TestRunHeadless_PlainTurnStreamsToStdoutAndPersists(t *testing.T) {
	dir := t.TempDir()
	client := &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("hello "), contentChunk("world"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("greet me", &stdout, &stderr)
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if stdout.String() != "hello world\n" {
		t.Fatalf("stdout = %q, want %q (streamed reply + terminating newline)", stdout.String(), "hello world\n")
	}
	if stderr.String() != launchLabelLine {
		t.Fatalf("stderr = %q, want empty on a clean run", stderr.String())
	}

	reloaded := reloadStore(t, result.Session)
	user := messagesByRole(reloaded, "user")
	if len(user) != 1 || user[0].Content.Text() != "greet me" {
		t.Fatalf("durable user messages = %+v, want one carrying the prompt", user)
	}
	asst := messagesByRole(reloaded, "assistant")
	if len(asst) != 1 || asst[0].Content.Text() != "hello world" {
		t.Fatalf("durable assistant messages = %+v, want one final reply", asst)
	}
	if reloaded.MetadataSnapshot().ID != result.Session.MetadataSnapshot().ID {
		t.Fatal("reloaded session id differs; the run did not persist a normal resumable session")
	}
}

// TestRunHeadless_PartialDropRetryStreamsOnlyRegeneratedAnswer pins the partial-drop retry fix on the
// real headless production surface: when a partial stream_drop is auto-retried,
// the surface buffers the failed attempt's deltas and RollbackPartial discards them before
// they reach stdout, so stdout carries only the regenerated answer — never the
// failed-then-recovered concatenation. The durable provider_request_retry still lands on
// the store. Fails if RollbackPartial reverts to a no-op or AppendStreamDelta writes
// straight to stdout.
func TestRunHeadless_PartialDropRetryStreamsOnlyRegeneratedAnswer(t *testing.T) {
	dir := t.TempDir()
	var round int32
	client := &stubTurnClient{title: streamedTitle("Model title"), fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: dropStream(contentChunk("Par"), io.ErrUnexpectedEOF)}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("Recovered"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("retry me", &stdout, &stderr)
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	result.Config = map[string]any{
		"provider": map[string]any{
			"retry": map[string]any{
				"enabled": true, "max_attempts": int64(4), "base_delay_ms": int64(0), "max_delay_ms": int64(0),
			},
			"openai": map[string]any{
				"base_url": "https://api.openai.com/v1",
				"api_key":  "sk-test",
			},
		},
	}
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (the wired retry policy must re-issue the dropped round)", client.callCount())
	}
	if stdout.String() != "Recovered\n" {
		t.Fatalf("stdout = %q, want %q (the failed partial must not concatenate with the regenerated answer)", stdout.String(), "Recovered\n")
	}

	reloaded := reloadStore(t, result.Session)
	if !slices.Contains(eventKinds(reloaded.Records()), events.KindProviderRequestRetry) {
		t.Fatalf("store missing provider_request_retry; kinds = %v", eventKinds(reloaded.Records()))
	}
}

func TestRunHeadless_UnavailableUpstreamIsIgnoredWithOneNotice(t *testing.T) {
	var ignoreLists [][]string
	client := unavailableUpstreamClient(&ignoreLists)
	client.title = streamedTitle("Model title")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("retry me", &stdout, &stderr)
	result := headlessOpenRouterResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault), toolfulModelID)
	result.Config["provider"].(map[string]any)["retry"] = map[string]any{
		"enabled": true, "max_attempts": int64(4), "base_delay_ms": int64(0), "max_delay_ms": int64(0),
	}
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	want := [][]string{nil, {"together"}}
	if !slices.EqualFunc(ignoreLists, want, slices.Equal[[]string]) {
		t.Fatalf("request ignore lists = %v, want %v", ignoreLists, want)
	}
	notices := 0
	for _, line := range strings.Split(stderr.String(), "\n") {
		if line == togetherIgnoredNotice {
			notices++
		}
	}
	if notices != 1 {
		t.Fatalf("stderr = %q, want the line %q exactly once", stderr.String(), togetherIgnoredNotice)
	}
	if stdout.String() != "Recovered\n" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), "Recovered\n")
	}
}

// TestRunHeadless_FirstRunShortCircuits proves the step-0 first-run branch returns
// (nil, nil) and never runs the turn driver — the run completes like the interactive
// first-run path and exits 0.
func TestRunHeadless_FirstRunShortCircuits(t *testing.T) {
	var order []string
	steps := recordingSteps(&order)
	steps.RunFirstRun = func(string) (bool, error) { return true, nil }

	driver := NewHeadlessDriver("anything", &bytes.Buffer{}, &bytes.Buffer{})
	denied, err := RunHeadless(context.Background(), "/cwd", steps, driver)
	if err != nil || denied != nil {
		t.Fatalf("RunHeadless first-run = (%v, %v), want (nil, nil)", denied, err)
	}
}

// TestRunHeadless_PickerRequiredIsUsageError proves the path-4 picker-required
// outcome (no model determined, no --model) is surfaced as ErrModelPickerRequired so
// the CLI can map it to a usage exit 2, rather than opening a picker a headless run
// cannot show (Architecture Review).
func TestRunHeadless_PickerRequiredIsUsageError(t *testing.T) {
	var order []string
	steps := recordingSteps(&order)
	steps.DetermineModel = func(map[string]any, map[string]any, string, []string) (any, bool, error) {
		return model.NewActiveState(nil, ""), true, nil
	}

	driver := NewHeadlessDriver("anything", &bytes.Buffer{}, &bytes.Buffer{})
	if _, err := RunHeadless(context.Background(), "/cwd", steps, driver); !errors.Is(err, ErrModelPickerRequired) {
		t.Fatalf("RunHeadless picker-required err = %v, want ErrModelPickerRequired", err)
	}
}

// TestRunHeadless_EndToEndReturnsDeniedSubjects proves the full RunHeadless path —
// runFreshCore then the one-shot driver — returns the subjects the turn denied, so the
// CLI can render the fail-closed summary (Done-when 6). It drives runFreshCore through
// injected steps that produce a real session + provider catalog + Build mode, then a
// stub provider that issues one mutating call.
func TestRunHeadless_EndToEndReturnsDeniedSubjects(t *testing.T) {
	dir := t.TempDir()
	store := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000bb", dir)
	home := t.TempDir()
	settings := SettingsPath(home)
	seedOpenAIDiscovered(t, settings, "gpt-5.5")

	var order []string
	steps := recordingSteps(&order)
	steps.ResolveHome = func() (string, error) { return home, nil }
	steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) { return dir, nil, nil }
	steps.ComposeConfig = func(map[string]any, string) (ConfigComposition, error) {
		return ConfigComposition{Config: headlessProviderConfig()}, nil
	}
	steps.BuildToolRegistry = func(any) (any, error) { return &toolRegistryFactory{active: nil}, nil }
	steps.DetermineModel = func(map[string]any, map[string]any, string, []string) (any, bool, error) {
		return model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject), false, nil
	}
	steps.EnsureFreshSession = func(string, string) (*sessions.Store, error) { return store, nil }
	steps.InitMode = func(context.Context, *sessions.Store, map[string]any, string, []string) (any, error) {
		return mode.NewActiveState(mode.Build, mode.SourceDefault), nil
	}

	client := toolThenContentClient(nil, "bash", `{"command":"rm gone.txt"}`, "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("delete things", &bytes.Buffer{}, &bytes.Buffer{})
	denied, err := RunHeadless(context.Background(), dir, steps, driver)
	if err != nil {
		t.Fatalf("RunHeadless: %v", err)
	}
	if len(denied) != 1 || denied[0].Subject != "rm gone.txt" {
		t.Fatalf("RunHeadless denials = %v, want [\"rm gone.txt\"]", denied)
	}
}

// TestHeadlessFreshSteps_ModeOverrideRecordsInteractionMode proves the --mode override
// step pins the run's interaction mode and records it durably as
// interaction_mode{plan, user_command, launch}, overriding mode.default (Done-when 5).
func TestHeadlessFreshSteps_ModeOverrideRecordsInteractionMode(t *testing.T) {
	dir := t.TempDir()
	store := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000cc", dir)
	steps := HeadlessFreshSteps(&bytes.Buffer{}, nil, "plan")

	got, err := steps.InitMode(context.Background(), store, nil, dir, nil)
	if err != nil {
		t.Fatalf("InitMode override: %v", err)
	}
	active, ok := got.(*mode.ActiveState)
	if !ok {
		t.Fatalf("InitMode returned %T, want *mode.ActiveState", got)
	}
	if m, src := active.Current(); m != mode.Plan || src != mode.SourceUserCommand {
		t.Fatalf("active mode = (%v, %v), want (plan, user_command)", m, src)
	}
	im := decodeInteractionMode(t, reloadStore(t, store))
	if len(im) != 1 || im[0].Mode != "plan" || im[0].Trigger != "launch" || im[0].Source != "user_command" {
		t.Fatalf("interaction_mode = %+v, want one {plan, user_command, launch}", im)
	}
}

func TestHeadlessFreshSteps_ModelOverrideValidatesCatalog(t *testing.T) {
	t.Run("in-catalog selection builds active state", func(t *testing.T) {
		for _, effort := range []string{"high", model.EffortNoReasoning} {
			t.Run(effort, func(t *testing.T) {
				home := t.TempDir()
				settings := SettingsPath(home)
				seedOpenAIDiscovered(t, settings, "gpt-5.5")
				steps := HeadlessFreshSteps(&bytes.Buffer{}, &model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: effort}, "")
				got, picker, err := steps.DetermineModel(headlessProviderConfig(), nil, t.TempDir(), []string{settings})
				if err != nil || picker {
					t.Fatalf("DetermineModel = (_, %v, %v), want (state, false, nil)", picker, err)
				}
				active, ok := got.(*model.ActiveState)
				if !ok {
					t.Fatalf("DetermineModel returned %T, want *model.ActiveState", got)
				}
				sel, _, ok := active.Current()
				if !ok || sel.ID != "gpt-5.5" {
					t.Fatalf("selection = %+v (ok=%v), want gpt-5.5", sel, ok)
				}
				if sel.Effort != effort {
					t.Fatalf("active effort = %q, want the validated %q", sel.Effort, effort)
				}
			})
		}
	})
	t.Run("uncatalogued selection is ErrModelNotInCatalog", func(t *testing.T) {
		home := t.TempDir()
		settings := SettingsPath(home)
		seedOpenAIDiscovered(t, settings, "gpt-5.5")
		steps := HeadlessFreshSteps(&bytes.Buffer{}, &model.Selection{Provider: "openai", ID: "ghost-model", Effort: "high"}, "")
		if _, _, err := steps.DetermineModel(headlessProviderConfig(), nil, t.TempDir(), []string{settings}); !errors.Is(err, ErrModelNotInCatalog) {
			t.Fatalf("err = %v, want ErrModelNotInCatalog", err)
		}
	})
	t.Run("unadvertised effort is ErrModelNotInCatalog", func(t *testing.T) {
		for _, effort := range []string{"max", model.EffortDefault} {
			t.Run(effort, func(t *testing.T) {
				home := t.TempDir()
				settings := SettingsPath(home)
				seedOpenAIDiscovered(t, settings, "gpt-5.5")
				steps := HeadlessFreshSteps(&bytes.Buffer{}, &model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: effort}, "")
				_, _, err := steps.DetermineModel(headlessProviderConfig(), nil, t.TempDir(), []string{settings})
				if !errors.Is(err, ErrModelNotInCatalog) {
					t.Fatalf("err = %v, want ErrModelNotInCatalog for the unadvertised effort %q", err, effort)
				}
				if !strings.Contains(err.Error(), string(model.CategoryEffortNotAdvertised)) {
					t.Fatalf("err = %v, want it to name the effort rejection %q", err, model.CategoryEffortNotAdvertised)
				}
			})
		}
	})
	t.Run("advertised effort outside the retired enum is accepted", func(t *testing.T) {
		home := t.TempDir()
		settings := SettingsPath(home)
		seedOpenAIDiscoveredWithEfforts(t, settings, []string{"max"}, "gpt-5.5")
		steps := HeadlessFreshSteps(&bytes.Buffer{}, &model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: "max"}, "")
		got, _, err := steps.DetermineModel(headlessProviderConfig(), nil, t.TempDir(), []string{settings})
		if err != nil {
			t.Fatalf("DetermineModel(effort=max) error = %v, want nil when the model advertises max", err)
		}
		active, ok := got.(*model.ActiveState)
		if !ok {
			t.Fatalf("DetermineModel returned %T, want *model.ActiveState", got)
		}
		if sel, _, ok := active.Current(); !ok || sel.Effort != "max" {
			t.Fatalf("active effort = %+v (ok=%v), want max", sel, ok)
		}
	})
}

// TestRunHeadless_FinalFlushFailureSurfacesOnCancel pins the Step-7 durability
// contract: when the run context is cancelled before the pre-turn boundary can
// flush (so PersistUserInputThenIssue retains the user message without dispatching) and
// the final WithoutCancel flush then fails, Run must surface the durability failure —
// returning a non-nil error and rendering the write-failure notice to stderr — instead
// of converting the cancellation into a clean (exit-0) run. Otherwise a Ctrl-C on an
// unwritable session log would exit 0 leaving the run not durably resumable.
func TestRunHeadless_FinalFlushFailureSurfacesOnCancel(t *testing.T) {
	dir := t.TempDir()
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	// Every flush against this store fails with a real write reason, so the final
	// WithoutCancel flush cannot persist the retained pre-turn message.
	result.Session = unwritableStore(t, "01890000-0000-7000-8000-0000000000dd", dir)

	// Cancel before Run so the pre-turn flush is skipped (returns context.Canceled with
	// no dispatch) and no provider turn ever issues.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("do work", &stdout, &stderr)
	err := driver.Run(ctx, result)
	if err == nil {
		t.Fatal("driver.Run = nil; a failed final durability flush after cancel must surface an error, not exit clean")
	}
	if !strings.Contains(stderr.String(), "session log unwritable") {
		t.Fatalf("stderr = %q, want a session-write-failure notice (req-400a)", stderr.String())
	}
}

// titledHeadlessSteps drives a full RunHeadless over the given store. Title tests must run the
// whole launch path: the name is written as a step of runFreshCore, and every record after
// session creation — launch_began, the launch interaction_mode, the AGENTS.md loads — is
// appended before the driver runs at all, so driver.Run alone cannot see that window.
func titledHeadlessSteps(t *testing.T, dir string, store *sessions.Store) FreshSteps {
	t.Helper()
	home := t.TempDir()
	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")

	var order []string
	steps := recordingSteps(&order)
	steps.ResolveHome = func() (string, error) { return home, nil }
	steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) { return dir, nil, nil }
	steps.ComposeConfig = func(map[string]any, string) (ConfigComposition, error) {
		return ConfigComposition{Config: headlessProviderConfig()}, nil
	}
	steps.BuildToolRegistry = func(any) (any, error) { return &toolRegistryFactory{active: nil}, nil }
	steps.DetermineModel = func(map[string]any, map[string]any, string, []string) (any, bool, error) {
		return model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject), false, nil
	}
	steps.EnsureFreshSession = func(string, string) (*sessions.Store, error) { return store, nil }
	steps.InitMode = func(context.Context, *sessions.Store, map[string]any, string, []string) (any, error) {
		return mode.NewActiveState(mode.Build, mode.SourceDefault), nil
	}
	return steps
}

// TestRunHeadless_SessionTitleIsPersistedWithTheUserSource proves a driver-supplied name reaches
// the session file as metadata.title with the user title source — read back from disk, not from
// the in-memory store — and survives the run's own later flushes.
func TestRunHeadless_SessionTitleIsPersistedWithTheUserSource(t *testing.T) {
	dir := t.TempDir()
	store := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000ac", dir)
	client := &stubTurnClient{title: streamedTitle("Model title"), fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("hello"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("greet me", &stdout, &stderr)
	driver.SetSessionTitle("review i870")
	if _, err := RunHeadless(context.Background(), dir, titledHeadlessSteps(t, dir, store), driver); err != nil {
		t.Fatalf("RunHeadless: %v", err)
	}
	if stderr.String() != launchLabelLine {
		t.Fatalf("stderr = %q, want empty on a clean named run", stderr.String())
	}
	if n := client.titleCallCount(); n != 0 {
		t.Fatalf("title requests = %d, want 0 for a run named with --title", n)
	}

	onDisk := readSessionFile(t, store.Path())
	if onDisk.Metadata.Title != "review i870" {
		t.Fatalf("persisted title = %q, want %q", onDisk.Metadata.Title, "review i870")
	}
	if onDisk.Metadata.TitleSource != sessions.TitleSourceUser {
		t.Fatalf("persisted title_source = %q, want %q — a generated title must never replace a supplied name",
			onDisk.Metadata.TitleSource, sessions.TitleSourceUser)
	}
}

// TestRunHeadless_SessionTitleSurvivesABootstrapFailureAfterSessionCreation covers the window a
// driver.Run-only test cannot reach: the session file exists and runFreshCore has begun writing to
// it, but the run dies before the driver is ever built. The name must already be on disk.
func TestRunHeadless_SessionTitleSurvivesABootstrapFailureAfterSessionCreation(t *testing.T) {
	for _, step := range []string{"AppendLaunchBegan", "InitMode", "LoadAgentInstructions"} {
		t.Run(step, func(t *testing.T) {
			dir := t.TempDir()
			store := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000ad", dir)
			boom := errors.New("bootstrap died after the session existed")

			steps := titledHeadlessSteps(t, dir, store)
			switch step {
			case "AppendLaunchBegan":
				steps.AppendLaunchBegan = func(context.Context, *sessions.Store) error { return boom }
			case "InitMode":
				steps.InitMode = func(context.Context, *sessions.Store, map[string]any, string, []string) (any, error) {
					return nil, boom
				}
			case "LoadAgentInstructions":
				steps.LoadAgentInstructions = func(context.Context, *sessions.Store, string, string, map[string]any, string, []string, agentinstr.Selection) ([]agentinstr.LoadEntry, error) {
					return nil, boom
				}
			}

			driver := NewHeadlessDriver("greet me", &bytes.Buffer{}, &bytes.Buffer{})
			driver.SetSessionTitle("review i870")
			if _, err := RunHeadless(context.Background(), dir, steps, driver); !errors.Is(err, boom) {
				t.Fatalf("RunHeadless = %v, want the seeded %s failure", err, step)
			}

			onDisk := readSessionFile(t, store.Path())
			if onDisk.Metadata.Title != "review i870" || onDisk.Metadata.TitleSource != sessions.TitleSourceUser {
				t.Fatalf("persisted title/source = %q/%q, want %q/%q — the name must land before any launch record",
					onDisk.Metadata.Title, onDisk.Metadata.TitleSource, "review i870", sessions.TitleSourceUser)
			}
		})
	}
}

// TestRunHeadless_SessionTitleSurvivesAnInterruptBeforeTheFirstTurn proves the name is on disk even
// when the run is cancelled before its first turn completes: the write is detached from the run
// context, so it cannot be beaten by the cancellation the batch caller sends.
func TestRunHeadless_SessionTitleSurvivesAnInterruptBeforeTheFirstTurn(t *testing.T) {
	dir := t.TempDir()
	store := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000ae", dir)
	client := &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		t.Error("a cancelled run issued a provider request")
		return provider.Response{}, errors.New("unreachable")
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("greet me", &stdout, &stderr)
	driver.SetSessionTitle("review i870")
	if _, err := RunHeadless(ctx, dir, titledHeadlessSteps(t, dir, store), driver); err != nil {
		t.Fatalf("RunHeadless after cancel = %v, want nil (a clean interrupt)", err)
	}

	onDisk := readSessionFile(t, store.Path())
	if onDisk.Metadata.Title != "review i870" || onDisk.Metadata.TitleSource != sessions.TitleSourceUser {
		t.Fatalf("persisted title/source = %q/%q, want %q/%q after an interrupt",
			onDisk.Metadata.Title, onDisk.Metadata.TitleSource, "review i870", sessions.TitleSourceUser)
	}
}

func TestRunHeadless_UnnamedRunStoresFirstPromptFallbackBeforeTheRequest(t *testing.T) {
	dir := t.TempDir()
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	var atRequest sessions.Metadata
	client := &stubTurnClient{title: streamedTitle("Model title"), fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		atRequest = readSessionFile(t, result.Session.Path()).Metadata
		return provider.Response{}, errors.New("provider boom")
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	const want = "greet me and review the login flow"
	driver := NewHeadlessDriver("  greet me\n and   review the login flow ", &bytes.Buffer{}, &bytes.Buffer{})
	_ = driver.Run(context.Background(), result)

	if client.callCount() == 0 {
		t.Fatal("no provider request was issued")
	}
	if n := client.titleCallCount(); n != 0 {
		t.Fatalf("title requests = %d, want 0 after a failed turn", n)
	}
	if atRequest.Title != want || atRequest.TitleSource != sessions.TitleSourceGenerated {
		t.Fatalf("title/source on disk at the provider request = %q/%q, want %q/%q",
			atRequest.Title, atRequest.TitleSource, want, sessions.TitleSourceGenerated)
	}
	onDisk := readSessionFile(t, result.Session.Path()).Metadata
	if onDisk.Title != want || onDisk.TitleSource != sessions.TitleSourceGenerated {
		t.Fatalf("title/source on disk after the provider failure = %q/%q, want %q/%q",
			onDisk.Title, onDisk.TitleSource, want, sessions.TitleSourceGenerated)
	}
}

func helloClient() *stubTurnClient {
	return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("hello"), finishChunk("stop"))}, nil
	}}
}

func requireDiskTitle(t *testing.T, store *sessions.Store, title, source string) {
	t.Helper()
	onDisk := readSessionFile(t, store.Path()).Metadata
	if onDisk.Title != title || onDisk.TitleSource != source {
		t.Fatalf("title/source on disk = %q/%q, want %q/%q", onDisk.Title, onDisk.TitleSource, title, source)
	}
}

func TestRunHeadless_SuccessfulTurnStoresTheModelTitle(t *testing.T) {
	result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))
	var turnReq, titleReq provider.Request
	client := &stubTurnClient{
		fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
			turnReq = req
			return provider.Response{Stream: newStream(contentChunk("hello"), finishChunk("stop"))}, nil
		},
		title: func(_ context.Context, req provider.Request) (provider.Response, error) {
			titleReq = req
			return titleCompletion("Greeting the user"), nil
		},
	}
	var built atomic.Int32
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { built.Add(1); return client })()

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("greet me", &stdout, &stderr)
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if stdout.String() != "hello\n" || stderr.String() != launchLabelLine {
		t.Fatalf("stdout = %q, stderr = %q, want only the reply and the launch label", stdout.String(), stderr.String())
	}
	if built.Load() != 1 || client.callCount() != 1 || client.titleCallCount() != 1 {
		t.Fatalf("clients built = %d, turn requests = %d, title requests = %d, want 1 each: the title reuses the turn's client",
			built.Load(), client.callCount(), client.titleCallCount())
	}
	if turnReq.Model != "gpt-5.5" || titleReq.Model != turnReq.Model {
		t.Fatalf("title request model = %q, turn model = %q, want both gpt-5.5", titleReq.Model, turnReq.Model)
	}
	if got := titleReq.Messages[len(titleReq.Messages)-1].Content; got != "User: greet me\nAssistant: hello" {
		t.Fatalf("title request exchange = %q, want the first prompt and its reply", got)
	}
	requireDiskTitle(t, result.Session, "Greeting the user", sessions.TitleSourceGenerated)
}

func TestRunHeadless_EmptyResponseTurnMakesNoTitleRequest(t *testing.T) {
	const verbatim = "provider openai request to model gpt-5.5 failed (empty_response/zero_delta_stream): provider stream closed without any assistant content delta"
	tests := []struct {
		name       string
		retry      map[string]any
		turnCalls  int
		wantNotice string
	}{
		{"retry disabled", map[string]any{"enabled": false}, 1, verbatim},
		{
			"retry exhausted",
			map[string]any{"enabled": true, "max_attempts": int64(2), "base_delay_ms": int64(0), "max_delay_ms": int64(0)},
			2, "failed after 2 attempts: " + verbatim,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))
			result.Config["provider"].(map[string]any)["retry"] = tt.retry
			client := &stubTurnClient{title: streamedTitle("Model title"), fn: func(context.Context, provider.Request) (provider.Response, error) {
				return provider.Response{Stream: newStream(finishChunk("stop"))}, nil
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			var stdout, stderr bytes.Buffer
			driver := NewHeadlessDriver("greet me", &stdout, &stderr)
			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run = %v, want nil", err)
			}
			if stdout.Len() != 0 || stderr.String() != launchLabelLine+tt.wantNotice+"\n" {
				t.Fatalf("stdout = %q, stderr = %q, want no reply and only the launch label and %q",
					stdout.String(), stderr.String(), tt.wantNotice)
			}
			if client.callCount() != tt.turnCalls || client.titleCallCount() != 0 {
				t.Fatalf("turn requests = %d, title requests = %d, want %d and 0 after an empty response",
					client.callCount(), client.titleCallCount(), tt.turnCalls)
			}
			var outcomes []string
			for _, r := range reloadStore(t, result.Session).Records() {
				ev, ok := r.(sessions.Event)
				if !ok || ev.Kind != events.KindTurnTerminal {
					continue
				}
				var p events.TurnTerminal
				if err := json.Unmarshal(ev.Payload, &p); err != nil {
					t.Fatalf("decode turn_terminal: %v", err)
				}
				outcomes = append(outcomes, p.Outcome)
			}
			if len(outcomes) != tt.turnCalls || slices.ContainsFunc(outcomes, func(o string) bool { return o != events.TurnOutcomeProviderFailed }) {
				t.Fatalf("turn_terminal outcomes = %v, want %d of %q", outcomes, tt.turnCalls, events.TurnOutcomeProviderFailed)
			}
			requireDiskTitle(t, result.Session, "greet me", sessions.TitleSourceGenerated)
		})
	}
}

func TestRunHeadless_FailedTitleRequestKeepsTheFallbackAndOutput(t *testing.T) {
	cases := map[string]func(context.Context, provider.Request) (provider.Response, error){
		"request error": func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, errors.New("title boom")
		},
		"failed stream": func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{Stream: dropStream(contentChunk("Partial title"), errors.New("connection reset"))}, nil
		},
	}
	for name, title := range cases {
		t.Run(name, func(t *testing.T) {
			result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))
			client := helloClient()
			client.title = title
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			var stdout, stderr bytes.Buffer
			driver := NewHeadlessDriver("greet me", &stdout, &stderr)
			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run = %v, want nil: a failed title request must not change the exit", err)
			}
			if stdout.String() != "hello\n" || stderr.String() != launchLabelLine {
				t.Fatalf("stdout = %q, stderr = %q, want only the reply and the launch label", stdout.String(), stderr.String())
			}
			if n := client.titleCallCount(); n != 1 {
				t.Fatalf("title requests = %d, want 1", n)
			}
			requireDiskTitle(t, result.Session, "greet me", sessions.TitleSourceGenerated)
		})
	}
}

func TestRunHeadless_InterruptedTurnMakesNoTitleRequest(t *testing.T) {
	cases := map[string]func() (context.Context, context.CancelFunc){
		"cancellation": func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
		"deadline": func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 200*time.Millisecond)
		},
	}
	for name, runCtx := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := runCtx()
			defer cancel()
			result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))
			client := &stubTurnClient{title: streamedTitle("Model title"), fn: func(reqCtx context.Context, _ provider.Request) (provider.Response, error) {
				ready := make(chan struct{})
				if name == "cancellation" {
					go func() { <-ready; cancel() }()
				}
				return provider.Response{Stream: blockingStream(reqCtx, contentChunk("Half"), ready)}, nil
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			driver := NewHeadlessDriver("greet me", &bytes.Buffer{}, &bytes.Buffer{})
			if err := driver.Run(ctx, result); err != nil {
				t.Fatalf("driver.Run = %v, want nil (a clean interrupt)", err)
			}
			if n := client.titleCallCount(); n != 0 {
				t.Fatalf("title requests = %d, want 0 after an interrupted turn", n)
			}
			requireDiskTitle(t, result.Session, "greet me", sessions.TitleSourceGenerated)
		})
	}
}

func TestRunHeadless_NoTurnLoopMakesNoTitleRequest(t *testing.T) {
	result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))
	result.Config = map[string]any{}
	client := helloClient()
	client.title = streamedTitle("Model title")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout bytes.Buffer
	driver := NewHeadlessDriver("greet me", &stdout, &bytes.Buffer{})
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}
	if client.callCount() != 0 || client.titleCallCount() != 0 || stdout.Len() != 0 {
		t.Fatalf("turn requests = %d, title requests = %d, stdout = %q, want none when no provider client is built",
			client.callCount(), client.titleCallCount(), stdout.String())
	}
	requireDiskTitle(t, result.Session, "greet me", sessions.TitleSourceGenerated)
}

func TestRunHeadless_CancelDuringTitleGenerationReturnsPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))
	client := helloClient()
	client.title = func(titleCtx context.Context, _ provider.Request) (provider.Response, error) {
		cancel()
		<-titleCtx.Done()
		return provider.Response{}, titleCtx.Err()
	}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout bytes.Buffer
	driver := NewHeadlessDriver("greet me", &stdout, &bytes.Buffer{})
	start := time.Now()
	err := driver.Run(ctx, result)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("driver.Run took %v after the run was cancelled, want it to stop without waiting for the title timeout", elapsed)
	}
	if err != nil {
		t.Fatalf("driver.Run = %v, want nil: the turn had already completed", err)
	}
	if client.titleCallCount() != 1 || stdout.String() != "hello\n" {
		t.Fatalf("title requests = %d, stdout = %q, want 1 and the reply", client.titleCallCount(), stdout.String())
	}
	requireDiskTitle(t, result.Session, "greet me", sessions.TitleSourceGenerated)
}

// TestRunHeadless_SessionTitleWriteFailureIsDiscardedAndSetupContinues proves a failed name write
// never becomes the run's outcome: the notice renders to stderr, and the run goes on to fail on the
// unresolvable declaration it would have failed on anyway rather than on the title write.
func TestRunHeadless_SessionTitleWriteFailureIsDiscardedAndSetupContinues(t *testing.T) {
	dir := t.TempDir()
	store := unwritableStore(t, "01890000-0000-7000-8000-0000000000ab", dir)

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("greet me", &stdout, &stderr)
	driver.SetSessionTitle("review i870")
	driver.SetDeclaredFileScopes([]string{"~someone/gone.txt"}, nil)

	_, err := RunHeadless(context.Background(), dir, titledHeadlessSteps(t, dir, store), driver)
	if err == nil || !strings.Contains(err.Error(), "headless declared file scope") {
		t.Fatalf("RunHeadless = %v, want the declared-scope failure — the title write must not decide the run's outcome", err)
	}
	if !strings.Contains(stderr.String(), "session log unwritable") {
		t.Fatalf("stderr = %q, want a session-write-failure notice for the dropped title", stderr.String())
	}
}

// TestRunHeadless_PromptApprovalAllowOnceRunsCall proves that with --prompt-for-approval, an
// otherwise-denied mutating call that the user allows-once at the terminal executes: the file is
// removed, nothing is recorded as denied, and the tool result is the executed output rather than
// a deny envelope (Done-when 1).
func TestRunHeadless_PromptApprovalAllowOnceRunsCall(t *testing.T) {
	dir := t.TempDir()
	notes := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notes, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client := toolThenContentClient(nil, "bash", `{"command":"rm notes.txt"}`, "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("delete my notes", &bytes.Buffer{}, &bytes.Buffer{})
	driver.EnablePromptForApproval(strings.NewReader("1\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if _, err := os.Stat(notes); !os.IsNotExist(err) {
		t.Fatalf("notes.txt still present — allow-once must run the call: stat err = %v", err)
	}
	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %v, want none (the call was allowed once)", got)
	}
	reloaded := reloadStore(t, result.Session)
	toolMsgs := messagesByRole(reloaded, "tool")
	if len(toolMsgs) != 1 || strings.Contains(toolMsgs[0].Content.Text(), `"denied_by"`) {
		t.Fatalf("tool messages = %+v, want one executed (non-deny) result", toolMsgs)
	}
}

func TestRunHeadless_PromptApprovalShellPromptWarnsBlockedPathsUnenforced(t *testing.T) {
	t.Run("shell command", func(t *testing.T) {
		dir := t.TempDir()
		notes := filepath.Join(dir, "notes.txt")
		if err := os.WriteFile(notes, []byte("keep\n"), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
		client := toolThenContentClient(nil, "bash", `{"command":"rm notes.txt"}`, "ok")
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		var stderr bytes.Buffer
		driver := NewHeadlessDriver("delete my notes", &bytes.Buffer{}, &stderr)
		driver.EnablePromptForApproval(strings.NewReader("1\n"))
		result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
		if err := driver.Run(context.Background(), result); err != nil {
			t.Fatalf("driver.Run: %v", err)
		}

		out := stderr.String()
		if n := strings.Count(out, tui.ShellBlockedPathsNotice); n != 1 {
			t.Fatalf("notice printed %d times, want 1:\n%s", n, out)
		}
		if at, opt := strings.Index(out, tui.ShellBlockedPathsNotice), strings.Index(out, "[1] allow once"); opt < 0 || at > opt {
			t.Fatalf("notice not printed before [1] allow once:\n%s", out)
		}
		if _, err := os.Stat(notes); !os.IsNotExist(err) {
			t.Fatalf("notes.txt still present — allow-once must run the call: stat err = %v", err)
		}
	})

	t.Run("structured create", func(t *testing.T) {
		dir := t.TempDir()
		client := toolThenContentClient(nil, "create", `{"path":"a.txt","content":"x\n"}`, "ok")
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		var stderr bytes.Buffer
		driver := NewHeadlessDriver("make a file", &bytes.Buffer{}, &stderr)
		driver.EnablePromptForApproval(strings.NewReader("2\n"))
		result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
		if err := driver.Run(context.Background(), result); err != nil {
			t.Fatalf("driver.Run: %v", err)
		}

		out := stderr.String()
		if !strings.Contains(out, "approval required") {
			t.Fatalf("structured create did not prompt:\n%s", out)
		}
		if strings.Contains(out, tui.ShellBlockedPathsNotice) {
			t.Fatalf("structured tool prompt printed the shell notice:\n%s", out)
		}
	})
}

// TestRunHeadless_PromptApprovalDenyBlocksInBand proves a terminal deny blocks the call in-band:
// the command never runs, the subject is tracked for the summary, and the agent receives a
// user deny envelope. A human answered here, so the refusal keeps the halt semantics an
// approver-less run's automatic refusal does not — the turn stops and stdout stays empty.
func TestRunHeadless_PromptApprovalDenyBlocksInBand(t *testing.T) {
	dir := t.TempDir()
	notes := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notes, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client := toolThenContentClient(nil, "bash", `{"command":"rm notes.txt"}`, "ok")
	client.title = streamedTitle("Model title")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout bytes.Buffer
	driver := NewHeadlessDriver("delete my notes", &stdout, &bytes.Buffer{})
	driver.EnablePromptForApproval(strings.NewReader("2\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if _, err := os.Stat(notes); err != nil {
		t.Fatalf("notes.txt missing — a denied call must change nothing: %v", err)
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (a human refusal halts the turn)", client.callCount())
	}
	if n := client.titleCallCount(); n != 0 {
		t.Fatalf("title requests = %d, want 0 after a human refusal", n)
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty — the model never runs a continuation round", stdout.String())
	}
	if got := driver.DeniedSubjects(); len(got) != 1 || got[0].Subject != "rm notes.txt" {
		t.Fatalf("DeniedSubjects = %v, want [\"rm notes.txt\"]", got)
	}
	reloaded := reloadStore(t, result.Session)
	toolMsgs := messagesByRole(reloaded, "tool")
	if len(toolMsgs) != 1 || !strings.Contains(toolMsgs[0].Content.Text(), `"denied_by":"user"`) {
		t.Fatalf("tool messages = %+v, want one user deny envelope", toolMsgs)
	}
	if strings.Contains(toolMsgs[0].Content.Text(), headlessReadOnlyHint) {
		t.Fatalf("deny envelope = %s, want no unattended read hint on a terminal refusal", toolMsgs[0].Content.Text())
	}
}

// TestRunHeadless_PromptApprovalSessionGrantAuthorizesRestOfRun proves allow-for-this-session
// authorizes matching later calls without re-prompting and never persists a grant: the agent
// issues the same mutating command twice, the user answers once (allow-session), and the second
// call is authorized from the in-memory grant (neither call is denied), while no settings.yaml is
// written for the project or globally (Done-when 1 and 2).
func TestRunHeadless_PromptApprovalSessionGrantAuthorizesRestOfRun(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "twice.txt")
	if err := os.WriteFile(target, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Two identical mutating tool calls, then a final content reply.
	var round int32
	client := &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) <= 2 {
			frag := toolFrag(0, fmt.Sprintf("call_%d", round), "bash", `{"command":"rm twice.txt"}`)
			return provider.Response{Stream: newStream(toolCallsChunk(frag))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("clean up", &bytes.Buffer{}, &bytes.Buffer{})
	// Only one lifetime-plus-scope answer is supplied; a second prompt would read EOF and deny.
	driver.EnablePromptForApproval(strings.NewReader("3\n1\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	// Neither call denied: the session grant authorized the second without a second prompt.
	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %v, want none (the session grant authorizes the rest of the run)", got)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("twice.txt still present — the first authorized call must run: stat err = %v", err)
	}
	reloaded := reloadStore(t, result.Session)
	toolMsgs := messagesByRole(reloaded, "tool")
	if len(toolMsgs) != 2 {
		t.Fatalf("tool messages = %d, want 2 (both calls authorized)", len(toolMsgs))
	}
	for i, m := range toolMsgs {
		if strings.Contains(m.Content.Text(), `"denied_by"`) {
			t.Fatalf("tool message %d is a deny envelope: %q", i, m.Content.Text())
		}
	}

	for _, p := range []string{
		filepath.Join(dir, ".codemeld", "settings.yaml"),
		filepath.Join(result.Home, ".codemeld", "global", "settings.yaml"),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("settings file %s exists — a session grant must not persist (stat err = %v)", p, err)
		}
	}
}

func TestRunHeadless_PromptApprovalProjectGrantPersists(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "twice.txt")
	if err := os.WriteFile(target, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var round int32
	client := &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) <= 2 {
			frag := toolFrag(0, fmt.Sprintf("call_%d", round), "bash", `{"command":"rm twice.txt"}`)
			return provider.Response{Stream: newStream(toolCallsChunk(frag))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stderr bytes.Buffer
	driver := NewHeadlessDriver("clean up", &bytes.Buffer{}, &stderr)
	driver.EnablePromptForApproval(strings.NewReader("4\n1\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	result.TrustDecision = HeadlessFreshSteps(&bytes.Buffer{}, nil, "").GateTrust(result.Home, dir, dir)
	if result.TrustDecision.Reason != trust.ReasonNothingCovered {
		t.Fatalf("gate = %#v, want an admission by vacuity", result.TrustDecision)
	}
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %v, want none (the project grant authorizes the rest of the run)", got)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("twice.txt still present — the authorized call must run: stat err = %v", err)
	}

	entries := readPersistedPermissions(t, config.LocalSettingsPath(dir), dir)
	if len(entries) != 1 {
		t.Fatalf("project settings hold %d permission entries, want 1: %+v", len(entries), entries)
	}
	got := entries[0]
	if got.GrantKind != "folder" || got.Subject != "rm twice.txt" || got.PathScope != dir {
		t.Fatalf("persisted entry = %+v, want a folder grant for \"rm twice.txt\" scoped to %s", got, dir)
	}
	if raw, want := mustReadFile(t, config.LocalSettingsPath(dir)), fmt.Sprintf("permissions:\n  - kind: direct\n    subject: rm twice.txt\n    path_scope: %s\n    grant_kind: folder\n", dir); raw != want {
		t.Fatalf("local settings file = %q, want the fixed bytes %q", raw, want)
	}
	if _, err := os.Stat(filepath.Join(result.Home, ".codemeld", "global", "settings.yaml")); !os.IsNotExist(err) {
		t.Fatalf("global settings written — a headless run must never grant machine-wide (stat err = %v)", err)
	}
	if strings.Contains(stderr.String(), "could not be saved") {
		t.Fatalf("stderr reports a persist failure:\n%s", stderr.String())
	}
	if n := strings.Count(stderr.String(), "approval required"); n != 1 {
		t.Fatalf("terminal rendered %d prompts, want 1 (the persisted grant must authorize the repeat):\n%s", n, stderr.String())
	}
}

// The prompter is built and filled by HeadlessDriver.Run, so this proves the withholding
// through the production assembly rather than through a flag the test set itself.
func TestRunHeadless_UntrustedProjectWithholdsTheProjectChoice(t *testing.T) {
	dir := trustProject(t, "model: {}\n")
	sharedBefore := mustReadFile(t, projectSettingsPath(dir))
	target := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(target, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client := toolThenContentClient(nil, "bash", `{"command":"rm notes.txt"}`, "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stderr bytes.Buffer
	driver := NewHeadlessDriver("clean up", &bytes.Buffer{}, &stderr)
	driver.EnablePromptForApproval(strings.NewReader("4\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	// The decision the real headless gate reaches for a covered project with no record.
	result.TrustDecision = HeadlessFreshSteps(&bytes.Buffer{}, nil, "").GateTrust(result.Home, dir, dir)
	if result.TrustDecision.Trusted {
		t.Fatalf("fixture is trusted (%#v); it cannot prove the untrusted arm", result.TrustDecision)
	}
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if _, err := os.Stat(target); err != nil {
		t.Fatalf("notes.txt stat = %v, want the denied call not to run", err)
	}
	if got := driver.DeniedSubjects(); len(got) != 1 {
		t.Fatalf("DeniedSubjects = %v, want the withheld project choice to deny the call", got)
	}
	out := stderr.String()
	for _, banned := range []string{"[4]", "allow in this project", "applies when run from:", "choose 1-4"} {
		if strings.Contains(out, banned) {
			t.Fatalf("untrusted headless prompt still shows %q:\n%s", banned, out)
		}
	}
	if !strings.Contains(out, "codemeld: choose 1-3 (a machine-wide/global grant is not offered here): ") {
		t.Fatalf("untrusted headless prompt does not read choose 1-3:\n%s", out)
	}
	entries := readPersistedPermissions(t, projectSettingsPath(dir), dir)
	if len(entries) != 0 {
		t.Fatalf("project settings gained %d permission entries in an untrusted run: %+v", len(entries), entries)
	}
	trustStoreAbsent(t, result.Home)
	requireSharedProjectSettingsUnchanged(t, dir, sharedBefore, "an untrusted headless run")
	mustNotExist(t, config.LocalSettingsPath(dir), "an untrusted headless run must not write a project grant")

	var next bytes.Buffer
	if again := gateTrust(result.Home, dir, dir, strings.NewReader(""), &next, true); again.Trusted || !strings.Contains(next.String(), approvePrompt) {
		t.Fatalf("next interactive launch = %#v, stderr = %q, want it asked again", again, next.String())
	}
	trustStoreAbsent(t, result.Home)
}

func TestRunHeadless_ApprovedRootOffersTheProjectChoice(t *testing.T) {
	processHome := t.TempDir()
	t.Setenv("HOME", processHome)
	dir := trustProject(t, "model: {}\n")
	target := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(target, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client := toolThenContentClient(nil, "bash", `{"command":"rm notes.txt"}`, "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stderr bytes.Buffer
	driver := NewHeadlessDriver("clean up", &bytes.Buffer{}, &stderr)
	// Project choice, then the exact scope the second question collects.
	driver.EnablePromptForApproval(strings.NewReader("4\n1\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	storeUnchanged := approvedRootsUnchanged(t, result.Home, dir)
	result.TrustDecision = HeadlessFreshSteps(&bytes.Buffer{}, nil, "").GateTrust(result.Home, dir, dir)
	if !result.TrustDecision.Trusted {
		t.Fatalf("decision = %#v, want the listed root honored", result.TrustDecision)
	}
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	out := stderr.String()
	for _, want := range []string{
		"  [4] allow in this project — remember this permanently in " + projectSettingsPath(dir),
		"codemeld: choose 1-4 (a machine-wide/global grant is not offered here): ",
		"codemeld: this grant stores a command subject — choose its scope",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("trusted headless prompt missing %q:\n%s", want, out)
		}
	}
	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %v, want none", got)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("notes.txt stat = %v, want the authorized call to have run", err)
	}
	entries := readPersistedPermissions(t, config.LocalSettingsPath(dir), dir)
	if len(entries) != 1 {
		t.Fatalf("project settings hold %d permission entries, want the written grant: %+v", len(entries), entries)
	}
	if got := entries[0]; got.GrantKind != "folder" || got.Subject != "rm notes.txt" || got.PathScope != dir {
		t.Fatalf("persisted entry = %+v, want a folder grant for \"rm notes.txt\" scoped to %s", got, dir)
	}
	requireSharedProjectSettingsUnchanged(t, dir, "model: {}\n", "a headless project grant")

	trustStoreAbsent(t, processHome)
	storeUnchanged()
	if got := trustStore(t, result.Home).Projects; !slices.Equal(got, []string{mustCanonical(t, dir)}) {
		t.Fatalf("approved roots after the run = %v, want the listed root kept", got)
	}
}

func TestRunHeadless_SecondLaunchHonorsALocalGrantWithoutAPrompt(t *testing.T) {
	dir := mustCanonical(t, t.TempDir())
	target := filepath.Join(dir, "twice.txt")
	seed := func() {
		t.Helper()
		if err := os.WriteFile(target, []byte("keep\n"), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	home := t.TempDir()
	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")
	storeUnchanged := approvedRootsUnchanged(t, home, dir)
	launch := func(sessionID, answers string) (*HeadlessDriver, string) {
		t.Helper()
		seed()
		client := toolThenContentClient(nil, "bash", `{"command":"rm twice.txt"}`, "done")
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		var order []string
		var stderr bytes.Buffer
		hermetic := recordingSteps(&order)
		steps := HeadlessFreshSteps(&stderr, nil, "")
		steps.ResolveHome = func() (string, error) { return home, nil }
		steps.RunFirstRun = hermetic.RunFirstRun
		steps.LoadGlobalSettings = func(string) (map[string]any, error) { return headlessProviderConfig(), nil }
		steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) { return dir, nil, nil }
		steps.RecoverJournals = hermetic.RecoverJournals
		steps.LoadVCSTemplates = hermetic.LoadVCSTemplates
		steps.ValidatePreferredVCS = hermetic.ValidatePreferredVCS
		steps.DetectVCS = hermetic.DetectVCS
		steps.BuildToolRegistry = func(any) (any, error) { return &toolRegistryFactory{active: nil}, nil }
		steps.DetermineModel = func(map[string]any, map[string]any, string, []string) (any, bool, error) {
			return model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject), false, nil
		}
		steps.EnsureFreshSession = func(string, string) (*sessions.Store, error) {
			return storeAt(t, filepath.Join(t.TempDir(), "session.json"), sessionID, dir), nil
		}
		steps.AcquireLock = hermetic.AcquireLock
		steps.AppendLaunchBegan = hermetic.AppendLaunchBegan
		steps.InitMode = func(context.Context, *sessions.Store, map[string]any, string, []string) (any, error) {
			return mode.NewActiveState(mode.Build, mode.SourceDefault), nil
		}
		steps.LoadAgentInstructions = hermetic.LoadAgentInstructions

		driver := NewHeadlessDriver("clean up", &bytes.Buffer{}, &stderr)
		driver.EnablePromptForApproval(strings.NewReader(answers))
		if _, err := RunHeadless(context.Background(), dir, steps, driver); err != nil {
			t.Fatalf("launch %s: %v", sessionID, err)
		}
		return driver, stderr.String()
	}

	_, firstErr := launch("01890000-0000-7000-8000-0000000000d2", "4\n1\n")
	if n := strings.Count(firstErr, "approval required"); n != 1 {
		t.Fatalf("first launch rendered %d prompts, want 1:\n%s", n, firstErr)
	}
	if entries := readPersistedPermissions(t, config.LocalSettingsPath(dir), dir); len(entries) != 1 || entries[0].Subject != "rm twice.txt" {
		t.Fatalf("local settings after the first launch = %+v, want the one project grant", entries)
	}
	mustNotExist(t, projectSettingsPath(dir), "a project grant must not create the shared settings file")
	storeUnchanged()

	second, secondErr := launch("01890000-0000-7000-8000-0000000000d3", "")
	if strings.Contains(secondErr, "approval required") {
		t.Fatalf("second launch prompted, want the local grant to authorize:\n%s", secondErr)
	}
	if got := second.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %v, want none", got)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("twice.txt stat = %v, want the authorized call to have run", err)
	}
	mustNotExist(t, projectSettingsPath(dir), "the second launch must not create the shared settings file")
	storeUnchanged()
}

func TestRunHeadless_PromptApprovalProjectGrantPersistFailureDegrades(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(target, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".codemeld"), []byte("not a directory\n"), 0o644); err != nil {
		t.Fatalf("seed .codemeld file: %v", err)
	}

	client := toolThenContentClient(nil, "bash", `{"command":"rm notes.txt"}`, "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stderr bytes.Buffer
	driver := NewHeadlessDriver("clean up", &bytes.Buffer{}, &stderr)
	driver.EnablePromptForApproval(strings.NewReader("4\n1\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %v, want none (a failed persist must not deny the call)", got)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("notes.txt still present — the authorized call must run: stat err = %v", err)
	}
	failures := decodeStoreEvents[events.PermissionPersistFailed](t, reloadStore(t, result.Session), events.KindPermissionPersistFailed)
	if len(failures) != 1 || failures[0].GrantKind != "folder" {
		t.Fatalf("permission_persist_failed events = %+v, want one for a folder grant", failures)
	}
	if !strings.Contains(stderr.String(), "session-only — failed to persist to") {
		t.Fatalf("stderr = %q, want the persist-failure notice", stderr.String())
	}
}

func headlessPersistAuthorizer(t *testing.T, dir string, store *sessions.Store) (*headlessAuthorizer, *recordingNotices) {
	t.Helper()
	notices := &recordingNotices{}
	auth := newHeadlessAuthorizer(emptyCache(t, dir), func() *sessions.Store { return store },
		mode.NewActiveState(mode.Build, mode.SourceDefault), nil, notices)
	return auth, notices
}

func TestHeadlessAuthorizer_PersistGrantRefusesUnsupportedKinds(t *testing.T) {
	cases := []struct {
		name  string
		entry permissions.PermissionEntry
	}{
		{"global", permissions.PermissionEntry{Kind: "shell", Subject: "rm", PathScope: "*", GrantKind: "global"}},
		{"unknown", permissions.PermissionEntry{Kind: "shell", Subject: "rm", PathScope: "/tmp", GrantKind: "machine"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store := mkStore(t)
			auth, notices := headlessPersistAuthorizer(t, dir, store)

			got, err := auth.persistGrant(store, dir)(tc.entry)
			if err == nil {
				t.Fatalf("a %s grant persisted from a headless run — it must be refused", tc.entry.GrantKind)
			}
			if got.GrantKind != "session" {
				t.Fatalf("refused entry = %+v, want it degraded to a session grant", got)
			}
			mustNotExist(t, filepath.Join(dir, ".codemeld", "settings.yaml"),
				"a refused grant kind must be rejected before any settings write")
			mustNotExist(t, config.LocalSettingsPath(dir),
				"a refused grant kind must be rejected before any write to the local settings file")
			if n := countPermissionEvents(store, events.KindPermissionPersistFailed); n != 0 {
				t.Fatalf("permission_persist_failed events = %d, want 0 (no write was attempted)", n)
			}
			if len(notices.texts) != 0 {
				t.Fatalf("notices = %v, want none for a refused grant kind", notices.texts)
			}
		})
	}
}

func TestHeadlessAuthorizer_PersistGrantProjectHostWritesProjectSettings(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	auth, notices := headlessPersistAuthorizer(t, dir, store)

	entry := projectHostGrant("web_fetch", "docs.example.com")
	got, err := auth.persistGrant(store, "")(entry)
	if err != nil {
		t.Fatalf("persistGrant project host: %v", err)
	}
	if got != entry {
		t.Fatalf("effective entry = %+v, want the approved grant %+v unchanged on a clean persist", got, entry)
	}

	projectTarget := config.LocalSettingsPath(dir)
	entries := readPersistedPermissions(t, projectTarget, dir)
	if len(entries) != 1 {
		t.Fatalf("project settings hold %d entries, want exactly the approved host grant: %+v", len(entries), entries)
	}
	if persisted := findGrant(t, entries, "web_fetch"); persisted != entry {
		t.Fatalf("entry read back from %q = %+v, want %+v (exact host, no path scope, no sibling host)", projectTarget, persisted, entry)
	}
	mustNotExist(t, SettingsPath(home), "a headless project host grant must never be written machine-wide")
	if n := countPermissionEvents(store, events.KindPermissionPersistFailed); n != 0 {
		t.Fatalf("permission_persist_failed events = %d, want 0 on a clean persist", n)
	}
	want := tui.RenderLocalSettingsIgnoreNotice(config.LocalSettingsPath(dir), config.LocalSettingsLockPath(dir))
	if len(notices.texts) != 1 || notices.texts[0] != want {
		t.Fatalf("notices = %v, want exactly the ignore notice %q", notices.texts, want)
	}
}

func TestHeadlessAuthorizer_PersistGrantProjectHostFailureDegrades(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	if err := os.WriteFile(filepath.Join(dir, ".codemeld"), []byte("not a directory\n"), 0o600); err != nil {
		t.Fatalf("seed project settings parent as a file: %v", err)
	}
	auth, notices := headlessPersistAuthorizer(t, dir, store)

	entry := projectHostGrant("web_search", "mcp.exa.ai")
	got, err := auth.persistGrant(store, "")(entry)
	if err == nil {
		t.Fatal("persistGrant error = nil, want the surfaced project host persist failure")
	}
	want := permissions.PermissionEntry{Kind: "tool", Subject: "web_search", HostScope: "mcp.exa.ai", GrantKind: "session"}
	if got != want {
		t.Fatalf("degraded entry = %+v, want %+v (same tool and host, session lifetime)", got, want)
	}

	projectTarget := config.LocalSettingsPath(dir)
	mustNotExist(t, SettingsPath(home), "a failed project host persist must not fall back to the global settings file")

	var p events.PermissionPersistFailed
	if err := json.Unmarshal(firstEvent(t, store, events.KindPermissionPersistFailed).Payload, &p); err != nil {
		t.Fatalf("unmarshal permission_persist_failed: %v", err)
	}
	if p.SubjectKind != "host" || p.GrantKind != "project" || p.HostScope != "mcp.exa.ai" || p.TargetPath != projectTarget {
		t.Fatalf("event subject_kind/grant_kind/host_scope/target_path = %q/%q/%q/%q, want host/project/mcp.exa.ai/%s",
			p.SubjectKind, p.GrantKind, p.HostScope, p.TargetPath, projectTarget)
	}
	if n := countPermissionEvents(store, events.KindPermissionPersistFailed); n != 1 {
		t.Fatalf("permission_persist_failed events = %d, want exactly 1 (the write is never retried)", n)
	}
	if len(notices.texts) != 1 {
		t.Fatalf("notices = %v, want exactly one persist-failure notice", notices.texts)
	}
}

func TestHeadlessAuthorizer_PersistGrantFolderRouteUnchanged(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	auth, _ := headlessPersistAuthorizer(t, dir, store)

	entry := permissions.PermissionEntry{Kind: "direct", Subject: "rm notes.txt", PathScope: dir, GrantKind: "folder"}
	got, err := auth.persistGrant(store, dir)(entry)
	if err != nil {
		t.Fatalf("persistGrant folder: %v", err)
	}
	if got != entry {
		t.Fatalf("effective entry = %+v, want the folder grant %+v unchanged", got, entry)
	}
	projectTarget := config.LocalSettingsPath(dir)
	persisted := readPersistedPermissions(t, projectTarget, dir)
	if len(persisted) != 1 || persisted[0] != entry {
		t.Fatalf("entries read back from %q = %+v, want exactly %+v", projectTarget, persisted, entry)
	}
	mustNotExist(t, SettingsPath(home), "a folder grant must never be written machine-wide")
}

func TestHeadlessAuthorizer_RepeatedLocalCreationAnnouncesOnce(t *testing.T) {
	dir := mustCanonical(t, t.TempDir())
	store := mkStore(t)
	auth, notices := headlessPersistAuthorizer(t, dir, store)
	local := config.LocalSettingsPath(dir)

	persist := auth.persistGrant(store, dir)
	for _, subject := range []string{"read_file", "list_files"} {
		entry := permissions.PermissionEntry{Kind: "tool", Subject: subject, PathScope: dir, GrantKind: "folder"}
		if _, err := persist(entry); err != nil {
			t.Fatalf("persistGrant %s: %v", subject, err)
		}
		if _, err := os.Stat(local); err != nil {
			t.Fatalf("the %s grant did not create %q: %v", subject, local, err)
		}
		if err := os.Remove(local); err != nil {
			t.Fatalf("remove %q between writes: %v", local, err)
		}
	}

	want := tui.RenderLocalSettingsIgnoreNotice(local, config.LocalSettingsLockPath(dir))
	if len(notices.texts) != 1 || notices.texts[0] != want {
		t.Fatalf("notices after two writes that each created the local file = %v, want exactly one ignore notice %q", notices.texts, want)
	}
}

func TestHeadlessAuthorizer_ConcurrentLocalCreationAnnouncesOnce(t *testing.T) {
	dir := mustCanonical(t, t.TempDir())
	store := mkStore(t)
	auth, notices := headlessPersistAuthorizer(t, dir, store)

	var start, done sync.WaitGroup
	start.Add(1)
	for range 8 {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			auth.announceLocalSettings()
		}()
	}
	start.Done()
	done.Wait()

	want := tui.RenderLocalSettingsIgnoreNotice(config.LocalSettingsPath(dir), config.LocalSettingsLockPath(dir))
	if len(notices.texts) != 1 || notices.texts[0] != want {
		t.Fatalf("notices from 8 concurrent created reports = %v, want exactly one ignore notice %q", notices.texts, want)
	}
}

func TestHeadlessAuthorizer_LocalGrantLeavesSharedProjectSettingsByteIdentical(t *testing.T) {
	dir := mustCanonical(t, t.TempDir())
	store := mkStore(t)
	shared := seedSharedProjectSettings(t, dir, permissions.PermissionEntry{
		Kind: "tool", Subject: "list_files", PathScope: dir, GrantKind: "folder",
	})
	home := t.TempDir()
	storeUnchanged := approvedRootsUnchanged(t, home, dir)
	terminal := newTerminalPrompter(strings.NewReader(""), io.Discard)
	terminal.home = home
	auth := newHeadlessAuthorizer(emptyCache(t, dir), func() *sessions.Store { return store },
		mode.NewActiveState(mode.Build, mode.SourceDefault), terminal, &recordingNotices{})

	folder := permissions.PermissionEntry{Kind: "tool", Subject: "read_file", PathScope: dir, GrantKind: "folder"}
	host := projectHostGrant("web_fetch", "docs.example.com")
	for _, entry := range []permissions.PermissionEntry{folder, host} {
		if _, err := auth.persistGrant(store, dir)(entry); err != nil {
			t.Fatalf("persistGrant %+v: %v", entry, err)
		}
		requireSharedProjectSettingsUnchanged(t, dir, shared, "a headless local grant write")
		storeUnchanged()
	}

	localTarget := config.LocalSettingsPath(dir)
	entries := readPersistedPermissions(t, localTarget, dir)
	if len(entries) != 2 {
		t.Fatalf("%q holds %+v, want exactly the two local grants (the shared file's grant must not be copied in)", localTarget, entries)
	}
	if got := findGrant(t, entries, "read_file"); got != folder {
		t.Fatalf("folder grant read back from %q = %+v, want %+v", localTarget, got, folder)
	}
	if got := findGrant(t, entries, "web_fetch"); got != host {
		t.Fatalf("project host grant read back from %q = %+v, want %+v", localTarget, got, host)
	}
}

func headlessLifetimeSteps(home, dir string, store *sessions.Store, releases *int32) FreshSteps {
	steps := recordingSteps(new([]string))
	steps.ResolveHome = func() (string, error) { return home, nil }
	steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) { return dir, nil, nil }
	steps.ComposeConfig = func(map[string]any, string) (ConfigComposition, error) {
		return ConfigComposition{Config: headlessProviderConfig()}, nil
	}
	steps.BuildToolRegistry = func(any) (any, error) { return &toolRegistryFactory{active: nil}, nil }
	steps.DetermineModel = func(map[string]any, map[string]any, string, []string) (any, bool, error) {
		return model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject), false, nil
	}
	steps.EnsureFreshSession = func(string, string) (*sessions.Store, error) { return store, nil }
	steps.AcquireLock = countingAcquire(releases)
	steps.InitMode = func(context.Context, *sessions.Store, map[string]any, string, []string) (any, error) {
		return mode.NewActiveState(mode.Build, mode.SourceDefault), nil
	}
	return steps
}

func TestRunHeadless_HoldsLockThroughDriverTerminalPaths(t *testing.T) {
	providerErr := errors.New("provider boom")
	cases := []struct {
		name    string
		client  func(t *testing.T, store *sessions.Store, held *bool, cancel context.CancelFunc) *stubTurnClient
		wantErr func(t *testing.T, err error)
	}{
		{
			name: "success",
			client: func(t *testing.T, store *sessions.Store, held *bool, _ context.CancelFunc) *stubTurnClient {
				return &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
					if !isTitleRequest(req) {
						*held = resumeLockHeld(t, store.Path())
					}
					return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
				}}
			},
			wantErr: func(t *testing.T, err error) {
				if err != nil {
					t.Fatalf("RunHeadless err = %v, want nil on a clean success", err)
				}
			},
		},
		{
			name: "provider failure",
			client: func(t *testing.T, store *sessions.Store, held *bool, _ context.CancelFunc) *stubTurnClient {
				return &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
					*held = resumeLockHeld(t, store.Path())
					return provider.Response{}, providerErr
				}}
			},
			wantErr: func(t *testing.T, err error) {
				if err == nil {
					t.Fatal("RunHeadless err = nil, want the provider failure surfaced")
				}
			},
		},
		{
			name: "cancellation",
			client: func(t *testing.T, store *sessions.Store, held *bool, cancel context.CancelFunc) *stubTurnClient {
				return &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
					*held = resumeLockHeld(t, store.Path())
					cancel()
					return provider.Response{}, context.Canceled
				}}
			},
			wantErr: func(t *testing.T, err error) {
				if err != nil {
					t.Fatalf("RunHeadless err = %v, want nil (a clean cancel with a durable final flush)", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			home := t.TempDir()
			seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")
			store := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000b1", dir)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var releases int32
			var heldDuringProvider bool
			client := tc.client(t, store, &heldDuringProvider, cancel)
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			steps := headlessLifetimeSteps(home, dir, store, &releases)
			driver := NewHeadlessDriver("do the thing", &bytes.Buffer{}, &bytes.Buffer{})
			_, err := RunHeadless(ctx, dir, steps, driver)
			tc.wantErr(t, err)

			if !heldDuringProvider {
				t.Fatal("resume lock not contended during the driver's provider turn; the headless run must hold it through the runtime")
			}
			if got := atomic.LoadInt32(&releases); got != 1 {
				t.Fatalf("physical releases = %d, want exactly 1 on the %s terminal path", got, tc.name)
			}
			if resumeLockHeld(t, store.Path()) {
				t.Fatalf("sidecar still held after the %s terminal path; the session must be acquirable again", tc.name)
			}
		})
	}
}

func TestRunHeadless_ReleasesLockOnPickerRequiredAndAcquireFailure(t *testing.T) {
	t.Run("picker required releases", func(t *testing.T) {
		var order []string
		steps := recordingSteps(&order)
		store := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000c1", t.TempDir())
		steps.EnsureFreshSession = func(string, string) (*sessions.Store, error) { return store, nil }
		var releases int32
		steps.AcquireLock = countingAcquire(&releases)
		steps.DetermineModel = func(map[string]any, map[string]any, string, []string) (any, bool, error) {
			return model.NewActiveState(nil, ""), true, nil
		}

		driver := NewHeadlessDriver("anything", &bytes.Buffer{}, &bytes.Buffer{})
		denied, err := RunHeadless(context.Background(), "/cwd", steps, driver)
		if !errors.Is(err, ErrModelPickerRequired) {
			t.Fatalf("err = %v, want ErrModelPickerRequired", err)
		}
		if denied != nil {
			t.Fatalf("denied = %v, want nil on a picker-required exit", denied)
		}
		if got := atomic.LoadInt32(&releases); got != 1 {
			t.Fatalf("physical releases = %d, want exactly 1 after a picker-required exit", got)
		}
		if resumeLockHeld(t, store.Path()) {
			t.Fatal("sidecar still held after a picker-required exit")
		}
	})

	t.Run("acquire failure starts no driver", func(t *testing.T) {
		var order []string
		steps := recordingSteps(&order)
		store := unwritableStore(t, "01890000-0000-7000-8000-0000000000c2", "/proj")
		steps.EnsureFreshSession = func(string, string) (*sessions.Store, error) { return store, nil }
		steps.AcquireLock = sessions.AcquireResumeLock
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
			t.Fatal("provider built after acquisition failure; the headless driver must not run")
			return nil
		})()

		driver := NewHeadlessDriver("anything", &bytes.Buffer{}, &bytes.Buffer{})
		denied, err := RunHeadless(context.Background(), "/cwd", steps, driver)
		var lockErr *sessions.ResumeLockError
		if !errors.As(err, &lockErr) {
			t.Fatalf("err = %v, want *sessions.ResumeLockError", err)
		}
		if denied != nil {
			t.Fatalf("denied = %v, want nil on acquisition failure", denied)
		}
		if got := store.Records(); len(got) != 0 {
			t.Fatalf("record stream = %v, want empty on acquisition failure", got)
		}
	})
}

// mustJSONString renders s as a JSON string literal (with surrounding quotes) for
// embedding in a tool-call arguments fixture, so a command carrying quotes survives
// into the {"command":...} arguments unescaped-at-the-shell.
func mustJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func headlessEffortSteps(home, dir string, store *sessions.Store, sel model.Selection) FreshSteps {
	var releases int32
	steps := headlessLifetimeSteps(home, dir, store, &releases)
	steps.DetermineModel = HeadlessFreshSteps(&bytes.Buffer{}, &sel, "").DetermineModel
	return steps
}

func TestRunHeadless_CatalogAdvertisedEffortReachesProviderRequest(t *testing.T) {
	advertised := []string{"max", "ultra", model.EffortDefault}
	for _, effort := range advertised {
		t.Run(effort, func(t *testing.T) {
			home, dir := t.TempDir(), t.TempDir()
			seedOpenAIDiscoveredWithEfforts(t, SettingsPath(home), advertised, "gpt-5.5")
			store := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000b7", dir)

			var captured provider.Request
			var calls int32
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
				return &stubTurnClient{title: streamedTitle("Model title"), fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
					atomic.AddInt32(&calls, 1)
					captured = req
					return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
				}}
			})()

			steps := headlessEffortSteps(home, dir, store, model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: effort})
			var stderr bytes.Buffer
			driver := NewHeadlessDriver("hello", &bytes.Buffer{}, &stderr)
			if _, err := RunHeadless(context.Background(), dir, steps, driver); err != nil {
				t.Fatalf("RunHeadless(--effort %s) error = %v, want nil for a catalog-advertised effort", effort, err)
			}
			if atomic.LoadInt32(&calls) == 0 {
				t.Fatalf("provider never received a request — the headless turn did not reach the provider (stderr: %s)", stderr.String())
			}
			if captured.Effort != effort {
				t.Fatalf("provider request Effort = %q, want the accepted %q carried from headless startup to the wire", captured.Effort, effort)
			}
		})
	}

	t.Run("unavailable effort is rejected before any provider call", func(t *testing.T) {
		home, dir := t.TempDir(), t.TempDir()
		seedOpenAIDiscoveredWithEfforts(t, SettingsPath(home), []string{"max"}, "gpt-5.5")
		store := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000b8", dir)
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
			t.Fatal("provider client built for a rejected --effort; headless startup must fail before the turn")
			return nil
		})()

		steps := headlessEffortSteps(home, dir, store, model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: "ultra"})
		driver := NewHeadlessDriver("hello", &bytes.Buffer{}, &bytes.Buffer{})
		denied, err := RunHeadless(context.Background(), dir, steps, driver)
		if !errors.Is(err, ErrModelNotInCatalog) {
			t.Fatalf("err = %v, want ErrModelNotInCatalog for an effort the model does not advertise", err)
		}
		if !strings.Contains(err.Error(), string(model.CategoryEffortNotAdvertised)) {
			t.Fatalf("err = %v, want it to name the effort rejection %q", err, model.CategoryEffortNotAdvertised)
		}
		if denied != nil {
			t.Fatalf("denied = %v, want nil on a rejected startup selection", denied)
		}
		if got := store.Records(); len(got) != 0 {
			t.Fatalf("record stream = %v, want empty when startup rejects the effort", got)
		}
	})
}

func TestRunHeadless_DiscoveredChatGPTEffortReachesProviderRequest(t *testing.T) {
	home := t.TempDir()
	// A non-expired stored ChatGPT session lets the real openaiauth flow resolve offline,
	// so the headless ChatGPT client reaches its stubbed inner adapter with no network.
	writeChatGPTSession(t, home, "stored-access", "stored-acct")
	seedChatGPTDiscovered(t, SettingsPath(home), "gpt-5.6", "low", "high", "xhigh")

	var captured provider.Request
	var calls int32
	defer swapChatGPTProviderClient(func(provider.ChatGPTClientConfig) provider.Client {
		return &stubTurnClient{title: streamedTitle("Model title"), fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
			atomic.AddInt32(&calls, 1)
			captured = req
			return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
		}}
	})()
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
		t.Fatal("OpenAI Platform client built for an openai-chatgpt headless turn (silent provider switch)")
		return nil
	})()

	dir := t.TempDir()
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        dir,
		ProjectRoot:      dir,
		Session:          storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000ef", dir),
		Model:            model.NewActiveState(&model.Selection{Provider: "openai-chatgpt", ID: "gpt-5.6", Effort: provider.EffortXHigh}, model.SourceProject),
		Config:           map[string]any{},
		ConfigLayerPaths: []string{SettingsPath(home)},
		Mode:             mode.NewActiveState(mode.Build, mode.SourceDefault),
		ToolRegistry:     &toolRegistryFactory{active: nil},
	}

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("hello", &stdout, &stderr)
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if atomic.LoadInt32(&calls) == 0 {
		t.Fatalf("ChatGPT adapter never received a request — the headless turn did not reach the provider (stderr: %s)", stderr.String())
	}
	if captured.Effort != provider.EffortXHigh {
		t.Fatalf("provider request Effort = %q, want %q — the headless turn must carry the run-scoped discovered effort, not drop it via the cacheless fallback", captured.Effort, provider.EffortXHigh)
	}
}

func TestRunHeadless_PromptApprovalPersistsDirectTokens(t *testing.T) {
	dir := t.TempDir()
	notes := filepath.Join(dir, "my notes.txt")
	if err := os.WriteFile(notes, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client := toolThenContentClient(nil, "bash", "{\"command\":\"rm \\\"my notes.txt\\\"\"}", "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("delete my notes", &bytes.Buffer{}, &bytes.Buffer{})
	driver.EnablePromptForApproval(strings.NewReader("1\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if _, err := os.Stat(notes); !os.IsNotExist(err) {
		t.Fatalf("%q still present — allow-once must run the call: stat err = %v", notes, err)
	}
	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %v, want none (the call was allowed once)", got)
	}

	prompts := decodeStoreEvents[events.PermissionPromptShown](t, reloadStore(t, result.Session), events.KindPermissionPromptShown)
	if len(prompts) != 1 {
		t.Fatalf("persisted %d permission_prompt_shown events, want 1", len(prompts))
	}
	if prompts[0].SubjectKind != "direct" || prompts[0].Subject != "rm my notes.txt" {
		t.Fatalf("persisted prompt = %#v, want the direct flattened subject", prompts[0])
	}
	if prompts[0].DirectTokens == nil {
		t.Fatal("persisted prompt carries no direct_tokens")
	}
	if want := []string{"rm", "my notes.txt"}; !slices.Equal(*prompts[0].DirectTokens, want) {
		t.Fatalf("direct_tokens = %q, want %q", *prompts[0].DirectTokens, want)
	}
}

func TestRunHeadless_PromptDenialStillPersistsDirectTokens(t *testing.T) {
	dir := t.TempDir()
	notes := filepath.Join(dir, "my notes.txt")
	if err := os.WriteFile(notes, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client := toolThenContentClient(nil, "bash", "{\"command\":\"rm \\\"my notes.txt\\\"\"}", "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("delete my notes", &bytes.Buffer{}, &bytes.Buffer{})
	driver.EnablePromptForApproval(strings.NewReader("2\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if _, err := os.Stat(notes); err != nil {
		t.Fatalf("%q missing — a denied call must change nothing: %v", notes, err)
	}
	if got := driver.DeniedSubjects(); len(got) != 1 {
		t.Fatalf("DeniedSubjects = %v, want exactly one denied subject", got)
	}

	prompts := decodeStoreEvents[events.PermissionPromptShown](t, reloadStore(t, result.Session), events.KindPermissionPromptShown)
	if len(prompts) != 1 {
		t.Fatalf("persisted %d permission_prompt_shown events, want 1", len(prompts))
	}
	if prompts[0].DirectTokens == nil {
		t.Fatal("denied prompt carries no direct_tokens")
	}
	if want := []string{"rm", "my notes.txt"}; !slices.Equal(*prompts[0].DirectTokens, want) {
		t.Fatalf("direct_tokens = %q, want %q", *prompts[0].DirectTokens, want)
	}
}

func todoPlanDefinition() provider.ToolDefinition {
	return provider.ToolDefinition{
		Name:        "todo_plan",
		Description: "Record the plan for this request.",
		Parameters: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []any{"plan_version", "items"},
			"properties": map[string]any{
				"plan_version": map[string]any{"type": "string"},
				"items":        map[string]any{"type": "array"},
			},
		},
	}
}

func TestHeadlessExperiment_ExtraToolReachesOnlyTheConfiguredRun(t *testing.T) {
	const args = `{"plan_version":"E2-PLAN@r1","items":[]}`

	var rounds [][]string
	client := toolThenContentClient(&rounds, "todo_plan", args, "done")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var handled []string
	driver := NewHeadlessDriver("plan it", &bytes.Buffer{}, &bytes.Buffer{})
	if err := driver.EnableExperiment(HeadlessExperiment{ExtraTools: []HeadlessExtraTool{{
		Definition: todoPlanDefinition(),
		Handle: func(_ context.Context, arguments string) (turn.ToolResult, error) {
			handled = append(handled, arguments)
			return turn.ToolResult{Content: "recorded"}, nil
		},
	}}}); err != nil {
		t.Fatalf("EnableExperiment: %v", err)
	}
	if driver.experiment == nil {
		t.Fatal("a successful binding was not applied to the driver")
	}
	if err := driver.Run(context.Background(), headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if len(rounds) == 0 || !slices.Contains(rounds[0], "todo_plan") {
		t.Fatalf("advertised %v, want the experiment definition on the request", rounds)
	}
	if !slices.IsSorted(rounds[0]) {
		t.Fatalf("advertised %v, want the name-sorted order the shipped advertiser produces", rounds[0])
	}
	if !slices.Equal(handled, []string{args}) {
		t.Fatalf("handler saw %v, want the decoded call arguments once", handled)
	}

	var plain [][]string
	plainClient := toolThenContentClient(&plain, "read", `{"path":"nothing.txt"}`, "done")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return plainClient })()
	unconfigured := NewHeadlessDriver("plan it", &bytes.Buffer{}, &bytes.Buffer{})
	if unconfigured.experiment != nil {
		t.Fatal("a driver built the shipped way carries an experiment")
	}
	if err := unconfigured.Run(context.Background(), headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))); err != nil {
		t.Fatalf("unconfigured driver.Run: %v", err)
	}
	if len(plain) == 0 || slices.Contains(plain[0], "todo_plan") {
		t.Fatalf("unconfigured run advertised %v, want the shipped set with no experiment tool", plain)
	}
	if want := toolNames(advertisedTools(advRegistry(t), mode.Build)); slices.Contains(want, "todo_plan") {
		t.Fatalf("the shipped advertiser offers %v — the experiment leaked into the product surface", want)
	}
}

func TestHeadlessExperiment_RejectsBindingsThatCouldReplaceAShippedTool(t *testing.T) {
	handle := func(context.Context, string) (turn.ToolResult, error) { return turn.ToolResult{}, nil }
	extra := func(name string, h func(context.Context, string) (turn.ToolResult, error)) HeadlessExtraTool {
		return HeadlessExtraTool{Definition: provider.ToolDefinition{Name: name}, Handle: h}
	}

	for _, tc := range []struct {
		name  string
		tools []HeadlessExtraTool
	}{
		{"nameless", []HeadlessExtraTool{extra("", handle)}},
		{"handlerless", []HeadlessExtraTool{extra("todo_plan", nil)}},
		{"duplicate", []HeadlessExtraTool{extra("todo_plan", handle), extra("todo_plan", handle)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			driver := NewHeadlessDriver("plan it", &bytes.Buffer{}, &bytes.Buffer{})
			err := driver.EnableExperiment(HeadlessExperiment{ExtraTools: tc.tools})
			if !errors.Is(err, ErrHeadlessExperiment) {
				t.Fatalf("EnableExperiment = %v, want ErrHeadlessExperiment", err)
			}
			if driver.experiment != nil {
				t.Fatal("a refused binding was applied anyway")
			}
		})
	}

	t.Run("shipped name", func(t *testing.T) {
		var calls int32
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
			return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
				atomic.AddInt32(&calls, 1)
				return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
			}}
		})()
		driver := NewHeadlessDriver("plan it", &bytes.Buffer{}, &bytes.Buffer{})
		if err := driver.EnableExperiment(HeadlessExperiment{ExtraTools: []HeadlessExtraTool{extra("bash", handle)}}); err != nil {
			t.Fatalf("EnableExperiment: %v", err)
		}
		err := driver.Run(context.Background(), headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault)))
		if !errors.Is(err, ErrHeadlessExperiment) {
			t.Fatalf("driver.Run = %v, want ErrHeadlessExperiment for a shipped name", err)
		}
		if atomic.LoadInt32(&calls) != 0 {
			t.Fatalf("the refused run still issued %d provider request(s)", calls)
		}
	})
}

func TestHeadlessExperiment_DenyCallRefusesOnlyItsTargetAndLetsTheTurnContinue(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "charlie.txt"), []byte("CHARLIE_TOKEN=fenlight\n"), 0o600); err != nil {
		t.Fatalf("seed charlie: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "alpha.txt"), []byte("ALPHA_TOKEN=quartzine\n"), 0o600); err != nil {
		t.Fatalf("seed alpha: %v", err)
	}

	var round int32
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(
				toolFrag(0, "call_1", "read", `{"path":"alpha.txt"}`),
				toolFrag(1, "call_2", "read", `{"path":"charlie.txt"}`),
			))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("quartzine"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("read both", &bytes.Buffer{}, &bytes.Buffer{})
	if err := driver.EnableExperiment(HeadlessExperiment{DenyCall: func(call turn.AssembledToolCall) (string, bool) {
		return "E2 pinned denial", strings.Contains(call.Arguments, "charlie.txt")
	}}); err != nil {
		t.Fatalf("EnableExperiment: %v", err)
	}
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if client.callCount() < 2 {
		t.Fatalf("provider called %d time(s) — a pinned denial must stay recoverable so the turn continues", client.callCount())
	}
	tools := messagesByRole(reloadStore(t, result.Session), "tool")
	if len(tools) != 2 {
		t.Fatalf("persisted %d tool results, want one per call", len(tools))
	}
	var denied, read int
	for _, msg := range tools {
		switch text := msg.Content.Text(); {
		case permissions.IsModeDenyEnvelope(text):
			denied++
			if strings.Contains(text, "fenlight") {
				t.Fatalf("the denied call still returned file content: %s", text)
			}
		case strings.Contains(text, "quartzine"):
			read++
		default:
			t.Fatalf("unexpected tool result %q", text)
		}
	}
	if denied != 1 || read != 1 {
		t.Fatalf("denied=%d read=%d, want the gate to refuse only its own target", denied, read)
	}
}

// --- declared write scopes ---

type declaredToolCall struct{ name, args string }

// declaredScopeClient answers each provider round with the next tool call, then a final answer,
// so one test can drive an ordered sequence such as create-then-edit through the real dispatcher.
func declaredScopeClient(calls ...declaredToolCall) *stubTurnClient {
	var round int32
	return &stubTurnClient{title: streamedTitle("Model title"), fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		i := int(atomic.AddInt32(&round, 1)) - 1
		if i < len(calls) {
			return provider.Response{Stream: newStream(toolCallsChunk(
				toolFrag(0, fmt.Sprintf("call_%d", i+1), calls[i].name, calls[i].args),
			))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	}}
}

func declaredScopeDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return dir
}

func declaredDenyText(t *testing.T, result *BootstrapResult) string {
	t.Helper()
	toolMsgs := messagesByRole(reloadStore(t, result.Session), "tool")
	if len(toolMsgs) != 1 {
		t.Fatalf("tool messages = %+v, want exactly one", toolMsgs)
	}
	return toolMsgs[0].Content.Text()
}

func assertDeclaredDenial(t *testing.T, driver *HeadlessDriver, result *BootstrapResult, subject string) {
	t.Helper()
	assertDeclaredDenialBy(t, driver, result, subject, "unattended")
}

func assertDeclaredDenialBy(t *testing.T, driver *HeadlessDriver, result *BootstrapResult, subject, deniedBy string) {
	t.Helper()
	text := declaredDenyText(t, result)
	if !strings.Contains(text, `"denied_by":"`+deniedBy+`"`) {
		t.Fatalf("deny envelope = %s, want denied_by %s", text, deniedBy)
	}
	if !strings.Contains(text, "declared-scope ceiling is active") {
		t.Fatalf("deny envelope = %s, want the scope-specific reason", text)
	}
	if strings.Contains(text, "grant") {
		t.Fatalf("deny envelope = %s, want no suggestion to add a grant", text)
	}
	if strings.Contains(text, headlessReadOnlyHint) {
		t.Fatalf("deny envelope = %s, want the declared-scope reason without the unattended read hint", text)
	}
	got := driver.DeniedSubjects()
	if len(got) != 1 || got[0].Subject != subject {
		t.Fatalf("DeniedSubjects = %+v, want one entry for %q", got, subject)
	}
	if !got[0].DeclaredScope() {
		t.Fatalf("denial %+v is not classified as a declared-scope denial", got[0])
	}
}

// TestRunHeadless_DeclaredWriteScopeAllowsCreateThenEdit proves a run declaring one path can
// create it and then edit it with no prompt and no grant, through the real dispatcher — including
// the case where the declared path's parent directories do not exist yet, which create builds
// inside its own authorization with no separate mkdir call.
func TestRunHeadless_DeclaredWriteScopeAllowsCreateThenEdit(t *testing.T) {
	for _, decl := range []string{"a.txt", "dir/sub/a.txt"} {
		t.Run(decl, func(t *testing.T) {
			dir := declaredScopeDir(t)
			client := declaredScopeClient(
				declaredToolCall{"create", `{"path":"` + decl + `","content":"first\n"}`},
				declaredToolCall{"edit", `{"path":"` + decl + `","old_text":"first","new_text":"second"}`},
			)
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			driver := NewHeadlessDriver("write the file", &bytes.Buffer{}, &bytes.Buffer{})
			driver.SetDeclaredFileScopes([]string{decl}, nil)
			result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}

			if got := mustReadFile(t, filepath.Join(dir, filepath.FromSlash(decl))); got != "second\n" {
				t.Fatalf("file = %q, want %q (create then edit both authorized by the declaration)", got, "second\n")
			}
			if got := driver.DeniedSubjects(); len(got) != 0 {
				t.Fatalf("DeniedSubjects = %+v, want none", got)
			}
			matched := decodePermissionMatched(t, reloadStore(t, result.Session))
			if len(matched) != 2 {
				t.Fatalf("permission_matched events = %+v, want two", matched)
			}
			for _, m := range matched {
				if m.OutcomeSource != permissions.OutcomeSourceDeclaredScope || m.Outcome != "once" {
					t.Fatalf("event = %+v, want declared_scope/once", m)
				}
				if m.GrantKind != "" || m.GrantPathScope != "" {
					t.Fatalf("declared-scope event carried grant fields: %+v", m)
				}
			}
			mustNotExist(t, filepath.Join(dir, ".codemeld", "settings.yaml"), "a declared decision persists no grant")
			mustNotExist(t, filepath.Join(result.Home, ".codemeld", "global", "settings.yaml"), "a declared decision persists no grant")
		})
	}
}

// TestRunHeadless_DeclaredWriteScopeDeniesAnUndeclaredSibling proves an undeclared target is a
// terminal, scope-specific denial the caller sees in the run's summary — and that the turn loop
// does not re-issue it.
func TestRunHeadless_DeclaredWriteScopeDeniesAnUndeclaredSibling(t *testing.T) {
	dir := declaredScopeDir(t)
	sibling := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(sibling, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed b.txt: %v", err)
	}

	client := declaredScopeClient(declaredToolCall{"edit", `{"path":"b.txt","old_text":"keep","new_text":"changed"}`})
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("edit the sibling", &bytes.Buffer{}, &bytes.Buffer{})
	driver.SetDeclaredFileScopes([]string{"a.txt"}, nil)
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := mustReadFile(t, sibling); got != "keep\n" {
		t.Fatalf("b.txt = %q, want it unchanged by a denied edit", got)
	}
	assertDeclaredDenial(t, driver, result, "b.txt")
	if client.callCount() != 2 {
		t.Fatalf("provider rounds = %d, want 2 (an unattended declared-scope denial re-issues)", client.callCount())
	}
}

// --- top-level delegate under the run's declared write ceiling ---

func generalAgentToolCall(t *testing.T, files ...string) declaredToolCall {
	t.Helper()
	encoded, err := json.Marshal(files)
	if err != nil {
		t.Fatalf("marshal files: %v", err)
	}
	return declaredToolCall{"general_agent", `{"instructions":"do it","files":` + string(encoded) + `}`}
}

func runGeneralAgentHeadless(t *testing.T, dir string, m mode.Mode, write, remove []string, call declaredToolCall) (*HeadlessDriver, *BootstrapResult, *stubTurnClient) {
	t.Helper()
	client := declaredScopeClient(call)
	t.Cleanup(swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client }))

	driver := NewHeadlessDriver("delegate the work", &bytes.Buffer{}, &bytes.Buffer{})
	driver.SetDeclaredFileScopes(write, remove)
	result := headlessResult(t, dir, mode.NewActiveState(m, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}
	return driver, result, client
}

func TestRunHeadless_TopLevelGeneralAgentOutsideTheRunCeilingStartsNoChild(t *testing.T) {
	tests := []struct {
		name  string
		grant func(result *BootstrapResult, dir string)
	}{
		{name: "with no grant at all", grant: func(*BootstrapResult, string) {}},
		{
			name: "with a folder grant for delegate",
			grant: func(result *BootstrapResult, dir string) {
				result.Config["permissions"] = []any{map[string]any{
					"kind": "tool", "subject": "general_agent", "path_scope": dir, "grant_kind": "folder",
				}}
			},
		},
		{
			name: "with a global grant for delegate",
			grant: func(result *BootstrapResult, _ string) {
				result.Config["permissions"] = []any{map[string]any{
					"kind": "tool", "subject": "general_agent", "path_scope": "*", "grant_kind": "global",
				}}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := declaredScopeDir(t)
			client := declaredScopeClient(generalAgentToolCall(t, "other.txt"))
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			driver := NewHeadlessDriver("delegate the work", &bytes.Buffer{}, &bytes.Buffer{})
			driver.SetDeclaredFileScopes([]string{"allowed.txt"}, nil)
			result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
			tc.grant(result, dir)
			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}

			assertDeclaredDenial(t, driver, result, "general_agent")
			if client.callCount() != 2 {
				t.Fatalf("provider rounds = %d, want 2 — no child ran and the refusal re-issues", client.callCount())
			}
			matched := decodePermissionMatched(t, reloadStore(t, result.Session))
			if len(matched) != 1 || matched[0].OutcomeSource != permissions.OutcomeSourceDeclaredScope || matched[0].Outcome != "deny" {
				t.Fatalf("permission_matched = %+v, want exactly one declared_scope deny", matched)
			}
			text := declaredDenyText(t, result)
			if !strings.Contains(text, "undeclared=") || !strings.Contains(text, filepath.Join(dir, "other.txt")) {
				t.Fatalf("deny envelope = %s, want it to name the missing child write declaration", text)
			}
			mustNotExist(t, filepath.Join(dir, "other.txt"), "a refused delegate call starts no child")
		})
	}
}

func TestRunHeadless_TopLevelGeneralAgentInsideTheRunCeilingLaunchesByDeclaredScope(t *testing.T) {
	dir := declaredScopeDir(t)
	driver, result, client := runGeneralAgentHeadless(t, dir, mode.Build, []string{"allowed.txt"}, nil,
		generalAgentToolCall(t, "allowed.txt"))

	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %+v, want none — declared scope covers the launch", got)
	}
	if text := declaredDenyText(t, result); !strings.Contains(text, "child agent") {
		t.Fatalf("tool message = %q, want the child agent's own report", text)
	}
	if client.callCount() != 3 {
		t.Fatalf("provider rounds = %d, want 3 — the parent's call, the child's round, and the parent's follow-up", client.callCount())
	}
	store := reloadStore(t, result.Session)
	if prompts := decodeStoreEvents[events.PermissionPromptShown](t, store, events.KindPermissionPromptShown); len(prompts) != 0 {
		t.Fatalf("permission prompts = %+v, want none", prompts)
	}
	var launch []events.PermissionMatched
	for _, m := range decodePermissionMatched(t, store) {
		if m.Subject == "general_agent" {
			t.Fatalf("event %+v decided the tool general_agent, want only its declared operations", m)
		}
		if m.ChildInvocationID == "" {
			launch = append(launch, m)
		}
	}
	if len(launch) != 1 || launch[0].Subject != "create" || launch[0].PathScope != dir ||
		launch[0].OutcomeSource != permissions.OutcomeSourceDeclaredScope || launch[0].Outcome != "once" {
		t.Fatalf("launch decisions = %+v, want one declared_scope once for create in %s", launch, dir)
	}
}

func TestRunHeadless_PlanDecidesTopLevelGeneralAgentOnItsOwnPosture(t *testing.T) {
	for _, candidate := range []string{"allowed.txt", "other.txt"} {
		t.Run(candidate, func(t *testing.T) {
			dir := declaredScopeDir(t)
			driver, result, _ := runGeneralAgentHeadless(t, dir, mode.Plan, []string{"allowed.txt"}, nil,
				generalAgentToolCall(t, candidate))

			text := declaredDenyText(t, result)
			if !permissions.IsModeDenyEnvelope(text) {
				t.Fatalf("deny envelope = %s, want Plan's mode denial", text)
			}
			matched := decodePermissionMatched(t, reloadStore(t, result.Session))
			if len(matched) != 1 || matched[0].OutcomeSource != "mode_auto" {
				t.Fatalf("permission_matched = %+v, want exactly one mode_auto decision", matched)
			}
			if got := driver.DeniedSubjects(); len(got) != 0 {
				t.Fatalf("DeniedSubjects = %+v, want none — a Plan denial is recoverable", got)
			}
			mustNotExist(t, filepath.Join(dir, candidate), "Plan starts no child")
		})
	}
}

func TestRunHeadless_TopLevelGeneralAgentReadsAnAbsentWriteListAsEmpty(t *testing.T) {
	t.Run("a delete-only ceiling refuses every child write declaration", func(t *testing.T) {
		dir := declaredScopeDir(t)
		driver, result, client := runGeneralAgentHeadless(t, dir, mode.Build, nil, []string{"doomed.txt"},
			generalAgentToolCall(t, "allowed.txt"))

		assertDeclaredDenial(t, driver, result, "general_agent")
		if text := declaredDenyText(t, result); !strings.Contains(text, "--files-authorized was not supplied") {
			t.Fatalf("deny envelope = %s, want it to name the absent write list", text)
		}
		if client.callCount() != 2 {
			t.Fatalf("provider rounds = %d, want 2 — no child ran", client.callCount())
		}
	})

	t.Run("neither flag leaves each declared operation to ordinary authorization", func(t *testing.T) {
		dir := declaredScopeDir(t)
		driver, result, _ := runGeneralAgentHeadless(t, dir, mode.Build, nil, nil, generalAgentToolCall(t, "other.txt"))

		if got := driver.DeniedSubjects(); len(got) != 1 || got[0].Subject != filepath.Join(dir, "other.txt") || got[0].DeclaredScope() {
			t.Fatalf("DeniedSubjects = %+v, want the ordinary refusal of the declared create", got)
		}

		if text := declaredDenyText(t, result); strings.Contains(text, "declared-scope ceiling is active") {
			t.Fatalf("deny envelope = %s, want the ordinary fail-closed refusal with no ceiling active", text)
		}
		for _, m := range decodePermissionMatched(t, reloadStore(t, result.Session)) {
			if m.OutcomeSource == permissions.OutcomeSourceDeclaredScope {
				t.Fatalf("event %+v applied a ceiling this run never declared", m)
			}
		}
	})
}

func TestRunHeadless_TopLevelGeneralAgentComparesCanonicalPaths(t *testing.T) {
	seed := func(t *testing.T) string {
		t.Helper()
		dir := declaredScopeDir(t)
		if err := os.MkdirAll(filepath.Join(dir, "real"), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "real", "notes.txt"), []byte("body\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "linkdir")); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		return dir
	}

	t.Run("a candidate resolving into the ceiling is covered", func(t *testing.T) {
		dir := seed(t)
		_, result, _ := runGeneralAgentHeadless(t, dir, mode.Build, []string{"linkdir/notes.txt"}, nil,
			generalAgentToolCall(t, "real/notes.txt"))

		if text := declaredDenyText(t, result); strings.Contains(text, "declared-scope ceiling is active") {
			t.Fatalf("deny envelope = %s, want the symlinked declaration to cover the same real path", text)
		}
	})

	t.Run("a symlinked spelling of an out-of-ceiling path is refused", func(t *testing.T) {
		dir := seed(t)
		driver, result, _ := runGeneralAgentHeadless(t, dir, mode.Build, []string{"linkdir/notes.txt"}, nil,
			generalAgentToolCall(t, "linkdir/other.txt"))

		assertDeclaredDenial(t, driver, result, "general_agent")
		if text := declaredDenyText(t, result); !strings.Contains(text, filepath.Join(dir, "real", "other.txt")) {
			t.Fatalf("deny envelope = %s, want the canonical resolved path rather than the symlinked spelling", text)
		}
	})

	t.Run("a ~-prefixed parent declaration covers nothing in the project", func(t *testing.T) {
		dir := seed(t)
		driver, result, _ := runGeneralAgentHeadless(t, dir, mode.Build, []string{"~/elsewhere.txt", "real/notes.txt"}, nil,
			generalAgentToolCall(t, "other.txt"))

		assertDeclaredDenial(t, driver, result, "general_agent")
		if text := declaredDenyText(t, result); !strings.Contains(text, filepath.Join(dir, "other.txt")) {
			t.Fatalf("deny envelope = %s, want the canonical candidate named", text)
		}
	})
}

// A call refused on its declaration is a corrective the model can act on, not a denial or an abort.
func TestRunHeadless_MalformedTopLevelGeneralAgentKeepsTheTurnGoing(t *testing.T) {
	dir := declaredScopeDir(t)
	driver, result, client := runGeneralAgentHeadless(t, dir, mode.Build, []string{"allowed.txt"}, nil,
		declaredToolCall{"general_agent", `{"instructions":"do it","files":[" "]}`})

	text := declaredDenyText(t, result)
	if !strings.Contains(text, "general_agent: ") || !strings.Contains(text, "must not be empty") {
		t.Fatalf("tool message = %q, want the tool's own corrective", text)
	}
	if strings.Contains(text, `"denied_by"`) {
		t.Fatalf("tool message = %q, want a corrective rather than a deny envelope", text)
	}
	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %+v, want none — the call never reached authorization", got)
	}
	if matched := decodePermissionMatched(t, reloadStore(t, result.Session)); len(matched) != 0 {
		t.Fatalf("permission_matched = %+v, want none", matched)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider rounds = %d, want 2 — the turn continues after a corrective", client.callCount())
	}
}

// TestRunHeadless_DeclaredScopeListsAreIndependent proves the write list never authorizes a
// delete and that naming the same path in the delete list does, through the real delete tool.
func TestRunHeadless_DeclaredScopeListsAreIndependent(t *testing.T) {
	tests := []struct {
		name           string
		write, deletes []string
		wantRemoved    bool
	}{
		{"write-only declaration cannot delete", []string{"doomed.txt"}, nil, false},
		{"delete declaration removes it", []string{"doomed.txt"}, []string{"doomed.txt"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := declaredScopeDir(t)
			doomed := filepath.Join(dir, "doomed.txt")
			if err := os.WriteFile(doomed, []byte("bye\n"), 0o644); err != nil {
				t.Fatalf("seed: %v", err)
			}

			client := declaredScopeClient(declaredToolCall{"delete", `{"path":"doomed.txt"}`})
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			driver := NewHeadlessDriver("remove it", &bytes.Buffer{}, &bytes.Buffer{})
			driver.SetDeclaredFileScopes(tc.write, tc.deletes)
			result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}

			_, statErr := os.Stat(doomed)
			if tc.wantRemoved && statErr == nil {
				t.Fatalf("doomed.txt survived a declared delete")
			}
			if !tc.wantRemoved {
				if statErr != nil {
					t.Fatalf("doomed.txt removed by a write-only declaration: %v", statErr)
				}
				assertDeclaredDenial(t, driver, result, "doomed.txt")
			}
		})
	}
}

// TestRunHeadless_DeclaredDeleteCoversAnEmptyDirectoryOnly proves a delete declaration authorizes
// the exact path whatever its type — here an empty directory — while a non-empty directory is
// still refused in-band by the delete tool's own AT_REMOVEDIR guarantee, not by the ceiling.
func TestRunHeadless_DeclaredDeleteCoversAnEmptyDirectoryOnly(t *testing.T) {
	tests := []struct {
		name        string
		seed        func(t *testing.T, dir string)
		wantRemoved bool
	}{
		{
			name:        "empty directory",
			seed:        func(t *testing.T, dir string) { mustMkdir(t, filepath.Join(dir, "target")) },
			wantRemoved: true,
		},
		{
			name: "non-empty directory",
			seed: func(t *testing.T, dir string) {
				mustMkdir(t, filepath.Join(dir, "target"))
				if err := os.WriteFile(filepath.Join(dir, "target", "child.txt"), []byte("x\n"), 0o644); err != nil {
					t.Fatalf("seed child: %v", err)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := declaredScopeDir(t)
			tc.seed(t, dir)

			client := declaredScopeClient(declaredToolCall{"delete", `{"path":"target"}`})
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			driver := NewHeadlessDriver("remove the directory", &bytes.Buffer{}, &bytes.Buffer{})
			driver.SetDeclaredFileScopes(nil, []string{"target"})
			result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}

			_, statErr := os.Stat(filepath.Join(dir, "target"))
			if tc.wantRemoved != (statErr != nil) {
				t.Fatalf("directory removal = %v, want removed = %v", statErr == nil, tc.wantRemoved)
			}
			if tc.wantRemoved {
				return
			}
			if got := driver.DeniedSubjects(); len(got) != 0 {
				t.Fatalf("DeniedSubjects = %+v, want none (the refusal is the tool's, not the ceiling's)", got)
			}
			if text := declaredDenyText(t, result); strings.Contains(text, `"denied_by"`) {
				t.Fatalf("tool message = %s, want the delete tool's own in-band refusal", text)
			}
		})
	}
}

// TestRunHeadless_DeclaredScopeDeniesMkdirAndMove proves neither list can authorize a mkdir or a
// move, with every relevant path declared in both lists.
func TestRunHeadless_DeclaredScopeDeniesMkdirAndMove(t *testing.T) {
	tests := []struct {
		name, tool, args, subject string
	}{
		{"mkdir", "mkdir", `{"path":"newdir"}`, "newdir"},
		{"move", "move", `{"source":"from.txt","destination":"to.txt"}`, "from.txt -> to.txt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := declaredScopeDir(t)
			if err := os.WriteFile(filepath.Join(dir, "from.txt"), []byte("x\n"), 0o644); err != nil {
				t.Fatalf("seed: %v", err)
			}
			declared := []string{"newdir", "from.txt", "to.txt"}

			client := declaredScopeClient(declaredToolCall{tc.tool, tc.args})
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			driver := NewHeadlessDriver("restructure", &bytes.Buffer{}, &bytes.Buffer{})
			driver.SetDeclaredFileScopes(declared, declared)
			result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}

			if _, err := os.Stat(filepath.Join(dir, "newdir")); err == nil {
				t.Fatal("newdir was created despite mkdir never being authorized by a declaration")
			}
			if _, err := os.Stat(filepath.Join(dir, "from.txt")); err != nil {
				t.Fatalf("from.txt moved despite move never being authorized by a declaration: %v", err)
			}
			assertDeclaredDenial(t, driver, result, tc.subject)
		})
	}
}

// TestRunHeadless_DeclaredScopeSurvivesPromptForApproval proves --prompt-for-approval cannot widen
// the ceiling: the undeclared write is denied without the terminal prompter ever being consulted,
// so the tripwire stdin is never read.
func TestRunHeadless_DeclaredScopeSurvivesPromptForApproval(t *testing.T) {
	dir := declaredScopeDir(t)
	sibling := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(sibling, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client := declaredScopeClient(declaredToolCall{"edit", `{"path":"b.txt","old_text":"keep","new_text":"changed"}`})
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stderr bytes.Buffer
	driver := NewHeadlessDriver("edit the sibling", &bytes.Buffer{}, &stderr)
	driver.SetDeclaredFileScopes([]string{"a.txt"}, nil)
	reads := 0
	driver.EnablePromptForApproval(readerFunc(func([]byte) (int, error) {
		reads++
		return 0, io.EOF
	}))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if reads != 0 {
		t.Fatalf("terminal prompt read stdin %d time(s); a declared-scope denial must never prompt", reads)
	}
	if got := mustReadFile(t, sibling); got != "keep\n" {
		t.Fatalf("b.txt = %q, want it unchanged", got)
	}
	assertDeclaredDenialBy(t, driver, result, "b.txt", "user")
	prompts := decodeStoreEvents[events.PermissionPromptShown](t, reloadStore(t, result.Session), events.KindPermissionPromptShown)
	if len(prompts) != 0 {
		t.Fatalf("permission_prompt_shown events = %+v, want none", prompts)
	}
}

// TestRunHeadless_DeclaredScopeLeavesShellAuthorizationAlone proves the ceiling binds the file
// tools only: a shell grant still authorizes its command in the same run.
func TestRunHeadless_DeclaredScopeLeavesShellAuthorizationAlone(t *testing.T) {
	dir := declaredScopeDir(t)
	marker := filepath.Join(dir, "shell-ran.txt")

	client := declaredScopeClient(declaredToolCall{"bash", `{"command":"touch shell-ran.txt"}`})
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("run the build", &bytes.Buffer{}, &bytes.Buffer{})
	driver.SetDeclaredFileScopes([]string{"a.txt"}, []string{"a.txt"})
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	composed := headlessProviderConfig()
	composed["permissions"] = []any{map[string]any{
		"kind": "direct", "subject": "touch :*", "path_scope": dir, "grant_kind": "folder",
	}}
	result.Config = composed
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the granted shell command did not run under an active ceiling: %v", err)
	}
	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %+v, want none (shell keeps its ordinary authorization)", got)
	}
}

// TestRunHeadless_DeclaredScopeFailsClosedOnAMidRunSwap proves the declaration does not follow a
// path replaced after it resolved: the edit's own target no longer equals the stored declaration,
// so it is denied rather than redirected to the link's target.
func TestRunHeadless_DeclaredScopeFailsClosedOnAMidRunSwap(t *testing.T) {
	dir := declaredScopeDir(t)
	outside := declaredScopeDir(t)
	outsideFile := filepath.Join(outside, "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed outside: %v", err)
	}
	declared := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(declared, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed a.txt: %v", err)
	}

	client := declaredScopeClient(
		declaredToolCall{"swap_declared_path", `{}`},
		declaredToolCall{"edit", `{"path":"a.txt","old_text":"keep","new_text":"changed"}`},
	)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("edit the declared file", &bytes.Buffer{}, &bytes.Buffer{})
	driver.SetDeclaredFileScopes([]string{"a.txt"}, nil)
	if err := driver.EnableExperiment(HeadlessExperiment{ExtraTools: []HeadlessExtraTool{{
		Definition: provider.ToolDefinition{
			Name:        "swap_declared_path",
			Description: "Replace the declared path with a symlink to a file outside the project.",
			Parameters: map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties":           map[string]any{},
			},
		},
		Handle: func(context.Context, string) (turn.ToolResult, error) {
			if err := os.Remove(declared); err != nil {
				return turn.ToolResult{}, err
			}
			if err := os.Symlink(outsideFile, declared); err != nil {
				return turn.ToolResult{}, err
			}
			return turn.ToolResult{Content: "swapped"}, nil
		},
	}}}); err != nil {
		t.Fatalf("EnableExperiment: %v", err)
	}
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := mustReadFile(t, outsideFile); got != "keep\n" {
		t.Fatalf("the link's target = %q, want it unchanged — the declaration must not follow a mid-run swap", got)
	}
	if got := driver.DeniedSubjects(); len(got) != 1 || got[0].Subject != "a.txt" || !got[0].DeclaredScope() {
		t.Fatalf("DeniedSubjects = %+v, want one declared-scope denial of a.txt", got)
	}
}

// TestRunHeadless_DeclaredDeleteFailsClosedOnAnIntermediateSymlink proves the delete list's
// fail-closed guarantee end to end. A declaration whose parent does not exist yet resolves through
// the deepest existing ancestor; once an intervening segment is created as a symlink the tool's
// runtime target is a different file, so the call is denied by the ceiling and the file behind the
// link is never removed.
func TestRunHeadless_DeclaredDeleteFailsClosedOnAnIntermediateSymlink(t *testing.T) {
	dir := declaredScopeDir(t)
	elsewhere := filepath.Join(dir, "elsewhere")
	mustMkdir(t, elsewhere)
	hidden := filepath.Join(elsewhere, "doomed.txt")

	client := declaredScopeClient(
		declaredToolCall{"swap_declared_parent", `{}`},
		declaredToolCall{"delete", `{"path":"dir/doomed.txt"}`},
	)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("remove the declared file", &bytes.Buffer{}, &bytes.Buffer{})
	driver.SetDeclaredFileScopes(nil, []string{"dir/doomed.txt"})
	if err := driver.EnableExperiment(HeadlessExperiment{ExtraTools: []HeadlessExtraTool{{
		Definition: provider.ToolDefinition{
			Name:        "swap_declared_parent",
			Description: "Create the declaration's missing parent segment as a symlink to another directory.",
			Parameters: map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties":           map[string]any{},
			},
		},
		Handle: func(context.Context, string) (turn.ToolResult, error) {
			if err := os.Symlink(elsewhere, filepath.Join(dir, "dir")); err != nil {
				return turn.ToolResult{}, err
			}
			if err := os.WriteFile(hidden, []byte("keep\n"), 0o644); err != nil {
				return turn.ToolResult{}, err
			}
			return turn.ToolResult{Content: "swapped"}, nil
		},
	}}}); err != nil {
		t.Fatalf("EnableExperiment: %v", err)
	}
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := mustReadFile(t, hidden); got != "keep\n" {
		t.Fatalf("the link's target = %q, want it intact — a declared delete must not follow an intermediate symlink", got)
	}
	if got := driver.DeniedSubjects(); len(got) != 1 || got[0].Subject != "dir/doomed.txt" || !got[0].DeclaredScope() {
		t.Fatalf("DeniedSubjects = %+v, want one declared-scope denial of dir/doomed.txt", got)
	}
}

// TestHeadlessAuthorizer_RecordDeniedKeepsEachDistinctClassification proves a run that mixes a
// declared-scope denial with an ordinary fail-closed denial of the same display label reports both:
// the CLI picks each denial's advice from its reason and source, so collapsing them by label alone
// would drop one refusal or advise it wrongly. An identical repeat is still collapsed.
func TestHeadlessAuthorizer_RecordDeniedKeepsEachDistinctClassification(t *testing.T) {
	a := &headlessAuthorizer{seen: map[DeniedCall]bool{}}
	scope := DeniedCall{
		Subject: "a.txt",
		Reason:  "a declared-scope ceiling is active for this run",
		Source:  permissions.OutcomeSourceDeclaredScope,
	}
	ordinary := DeniedCall{Subject: "a.txt", Reason: headlessDenyReason}

	a.recordDenied(scope)
	a.recordDenied(ordinary)
	a.recordDenied(scope)

	got := a.deniedSubjects()
	if want := []DeniedCall{scope, ordinary}; !slices.Equal(got, want) {
		t.Fatalf("deniedSubjects() = %+v, want %+v", got, want)
	}
}

// TestHeadlessAuthorizer_SameCallRefusalsWrapUpAtTheCap drives one refused edit through the real
// permission path. Only the first refusal reaches the fail-closed prompt; the repeats come back from
// the turn cache, and each still counts toward the per-call cap.
func TestHeadlessAuthorizer_SameCallRefusalsWrapUpAtTheCap(t *testing.T) {
	dir := declaredScopeDir(t)
	store := mkStore(t)
	notices := &recordingNotices{}
	auth := newHeadlessAuthorizer(emptyCache(t, dir), func() *sessions.Store { return store },
		mode.NewActiveState(mode.Build, mode.SourceDefault), nil, notices)
	edit := func(name string) permissions.Decision {
		t.Helper()
		target := filepath.Join(dir, name)
		dec, err := auth.Authorize(context.Background(),
			permissions.MatchRequest{Kind: "tool", Subject: filetools.EditToolName, PathScope: target},
			dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: filetools.EditToolName},
			permissions.ModeContext{Class: permissions.ClassMutating, ToolName: filetools.EditToolName, TargetPath: target})
		if err != nil {
			t.Fatalf("Authorize(%s) error = %v, want nil", name, err)
		}
		if got := envelopeReason(t, dec.DenyEnvelope); got != headlessDenyReason {
			t.Fatalf("Authorize(%s) envelope reason = %q, want exactly the unattended no-approver refusal", name, got)
		}
		return dec
	}

	for i := 1; i < maxRefusalsPerCall; i++ {
		if edit("a.txt").WrapUp {
			t.Fatalf("refusal %d of a.txt carries WrapUp, want it only at refusal %d", i, maxRefusalsPerCall)
		}
		if edit(fmt.Sprintf("other-%d.txt", i)).WrapUp {
			t.Fatalf("first refusal of other-%d.txt carries WrapUp, want different calls to have no limit", i)
		}
	}
	if len(notices.texts) != 0 {
		t.Fatalf("notices = %v before any call reached the cap, want none", notices.texts)
	}
	if !edit("a.txt").WrapUp {
		t.Fatalf("refusal %d of a.txt has no WrapUp, want the cap to mark it", maxRefusalsPerCall)
	}
	want := "codemeld: edit was refused 5 times; the run ended with a final answer and no further tool use"
	if !slices.Equal(notices.texts, []string{want}) {
		t.Fatalf("notices = %q, want exactly %q", notices.texts, want)
	}

	var cached int
	for _, m := range decodePermissionMatched(t, store) {
		if m.OutcomeSource == "cache" && m.PathScope == filepath.Join(dir, "a.txt") {
			cached++
		}
	}
	if cached != maxRefusalsPerCall-1 {
		t.Fatalf("cached repeats of a.txt = %d, want %d — the repeats must exercise the turn-cache path", cached, maxRefusalsPerCall-1)
	}
}

// TestHeadlessAuthorizer_HostRefusalsCountPerHost proves two hosts of one web tool are different
// calls, and that the cap notice names the host.
func TestHeadlessAuthorizer_HostRefusalsCountPerHost(t *testing.T) {
	dir := t.TempDir()
	store := mkStore(t)
	notices := &recordingNotices{}
	auth := newHeadlessAuthorizer(emptyCache(t, dir), func() *sessions.Store { return store },
		mode.NewActiveState(mode.Build, mode.SourceDefault), nil, notices)
	fetch := func(host string) permissions.Decision {
		t.Helper()
		dec, err := auth.Authorize(context.Background(),
			permissions.MatchRequest{Kind: matchKindHost, Subject: webFetchToolName, Host: host},
			dispatch.PromptDisplay{HostRequest: "https://" + host + "/"},
			permissions.ModeContext{Class: permissions.ClassMutating, ToolName: webFetchToolName, NetworkEgress: true})
		if err != nil || dec.DenyEnvelope == "" {
			t.Fatalf("Authorize(%s) = %+v, %v, want a refusal", host, dec, err)
		}
		return dec
	}

	for i := 1; i < maxRefusalsPerCall; i++ {
		if fetch("one.test").WrapUp || fetch("two.test").WrapUp {
			t.Fatalf("refusal %d carries WrapUp, want each host counted separately", i)
		}
	}
	if !fetch("one.test").WrapUp {
		t.Fatal("refusal 5 of one.test has no WrapUp")
	}
	want := "codemeld: web_fetch (host one.test) was refused 5 times; the run ended with a final answer and no further tool use"
	if !slices.Equal(notices.texts, []string{want}) {
		t.Fatalf("notices = %q, want exactly %q", notices.texts, want)
	}
}

type scriptedToolCall struct{ name, args string }

// refusedCallsClient answers one tool call per round from calls, then final on every later round,
// recording each request so a test can read the advertised tools and messages back.
func refusedCallsClient(calls []scriptedToolCall, final string, requests *[]provider.Request) *stubTurnClient {
	var mu sync.Mutex
	return &stubTurnClient{title: streamedTitle("Model title"), fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		mu.Lock()
		*requests = append(*requests, req)
		round := len(*requests)
		mu.Unlock()
		if round <= len(calls) {
			c := calls[round-1]
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, fmt.Sprintf("call_%d", round), c.name, c.args)))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk(final), finishChunk("stop"))}, nil
	}}
}

func webResearchHeadlessResult(t *testing.T, dir string) *BootstrapResult {
	t.Helper()
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	result.Config["web_research"] = map[string]any{"enabled": true, "timeout_seconds": 5}
	return result
}

func fetchArgs(url string) string { return fmt.Sprintf(`{"url":%q}`, url) }

// TestRunHeadless_DifferentRefusedCallsNeverEndTheRun covers the many-refusals shape: seven different refused
// calls, two of them the same web tool on different hosts, and the model still answers.
func TestRunHeadless_DifferentRefusedCallsNeverEndTheRun(t *testing.T) {
	calls := []scriptedToolCall{
		{"bash", `{"command":"rm a.txt"}`},
		{"bash", `{"command":"rm b.txt"}`},
		{"bash", `{"command":"rm c.txt"}`},
		{"bash", `{"command":"rm d.txt"}`},
		{"bash", `{"command":"rm e.txt"}`},
		{webFetchToolName, fetchArgs("https://docs.example.com/page")},
		{webFetchToolName, fetchArgs("https://api.example.org/page")},
	}
	var requests []provider.Request
	client := refusedCallsClient(calls, "answer after seven refusals", &requests)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("clean up", &stdout, &stderr)
	result := webResearchHeadlessResult(t, t.TempDir())
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if stdout.String() != "answer after seven refusals\n" {
		t.Fatalf("stdout = %q, want the final answer", stdout.String())
	}
	if len(requests) != len(calls)+1 {
		t.Fatalf("provider requests = %d, want %d", len(requests), len(calls)+1)
	}
	for i, req := range requests {
		if len(req.Tools) == 0 {
			t.Fatalf("request %d advertised no tools, want no wrap-up for different calls", i+1)
		}
	}
	if strings.Contains(stderr.String(), "was refused") {
		t.Fatalf("stderr = %q, want no wrap-up notice", stderr.String())
	}
	toolMsgs := messagesByRole(reloadStore(t, result.Session), "tool")
	if len(toolMsgs) != len(calls) {
		t.Fatalf("tool messages = %d, want %d", len(toolMsgs), len(calls))
	}
	for i, m := range toolMsgs {
		if !strings.Contains(m.Content.Text(), `"denied_by":"unattended"`) {
			t.Fatalf("tool message %d = %s, want an unattended refusal", i+1, m.Content.Text())
		}
	}
}

// TestRunHeadless_SameCallRefusedFiveTimesEndsWithAFinalAnswer covers the shell path and the web
// fetch path, whose refusal skips the dispatch DeniedError chain.
func TestRunHeadless_SameCallRefusedFiveTimesEndsWithAFinalAnswer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		call  scriptedToolCall
		label string
	}{
		{"shell command", scriptedToolCall{"bash", `{"command":"rm notes.txt"}`}, "rm notes.txt"},
		{"web fetch", scriptedToolCall{webFetchToolName, fetchArgs("https://docs.example.com/page")}, "web_fetch (host docs.example.com)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests []provider.Request
			// Byte-identical consecutive calls would trip the turn's repeat check before the refusal cap.
			respelled := scriptedToolCall{tc.call.name, strings.Replace(tc.call.args, `":`, `": `, 1)}
			calls := []scriptedToolCall{tc.call, respelled, tc.call, respelled, tc.call}
			client := refusedCallsClient(calls, "what I found so far", &requests)
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			var stdout, stderr bytes.Buffer
			driver := NewHeadlessDriver("clean up", &stdout, &stderr)
			result := webResearchHeadlessResult(t, t.TempDir())
			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}

			if stdout.String() != "what I found so far\n" {
				t.Fatalf("stdout = %q, want the wrap-up answer", stdout.String())
			}
			if len(requests) != maxRefusalsPerCall+1 {
				t.Fatalf("provider requests = %d, want %d refused rounds and one wrap-up", len(requests), maxRefusalsPerCall+1)
			}
			for i, req := range requests[:maxRefusalsPerCall] {
				if len(req.Tools) == 0 {
					t.Fatalf("request %d advertised no tools before the cap", i+1)
				}
			}
			wrap := requests[maxRefusalsPerCall]
			if len(wrap.Tools) != 0 {
				t.Fatalf("wrap-up request advertised %d tools, want none", len(wrap.Tools))
			}
			if last := wrap.Messages[len(wrap.Messages)-1]; last.Role != "system" || !strings.Contains(last.Content, "tools are no longer available") {
				t.Fatalf("wrap-up request ends with %+v, want the wrap-up instruction", last)
			}
			want := "codemeld: " + tc.label + " was refused 5 times; the run ended with a final answer and no further tool use"
			if strings.Count(stderr.String(), want) != 1 {
				t.Fatalf("stderr = %q, want the notice %q once", stderr.String(), want)
			}
			if strings.Contains(stdout.String(), "was refused") {
				t.Fatalf("stdout leaked the wrap-up notice: %q", stdout.String())
			}
			reloaded := reloadStore(t, result.Session)
			toolMsgs := messagesByRole(reloaded, "tool")
			if len(toolMsgs) != maxRefusalsPerCall {
				t.Fatalf("tool messages = %d, want %d", len(toolMsgs), maxRefusalsPerCall)
			}
			for i, m := range toolMsgs {
				if !strings.Contains(m.Content.Text(), `"denied_by":"unattended"`) {
					t.Fatalf("tool message %d = %s, want an unattended refusal", i+1, m.Content.Text())
				}
			}
			if system := messagesByRole(reloaded, "system"); len(system) != 1 {
				t.Fatalf("durable system messages = %d, want the one wrap-up instruction", len(system))
			}
		})
	}
}

// TestRunHeadless_InvalidDeclarationFailsAfterBootstrapBeforeTheFirstTurn proves an unresolvable
// declaration ends a configured run as a driver/configuration failure naming the path — after the
// session was created and before any turn — rather than as a denied tool call.
func TestRunHeadless_InvalidDeclarationFailsAfterBootstrapBeforeTheFirstTurn(t *testing.T) {
	cases := []struct {
		name string
		decl string
	}{
		{"empty", ""},
		{"whitespace only", "   \t "},
		{"unsupported ~user form", "~someone/gone.txt"},
		{"existing non-directory mid component", "seed.txt/child.txt"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := declaredScopeDir(t)
			if err := os.WriteFile(filepath.Join(dir, "seed.txt"), []byte("x\n"), 0o644); err != nil {
				t.Fatalf("seed: %v", err)
			}
			home := t.TempDir()
			seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")
			store := storeAt(t, filepath.Join(t.TempDir(), "session.json"),
				fmt.Sprintf("01890000-0000-7000-8000-0000000000c%d", i), dir)

			client := declaredScopeClient(declaredToolCall{"create", `{"path":"a.txt","content":"x\n"}`})
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			driver := NewHeadlessDriver("write it", &bytes.Buffer{}, &bytes.Buffer{})
			driver.SetDeclaredFileScopes([]string{"a.txt"}, []string{tc.decl})

			denied, err := RunHeadless(context.Background(), dir, declaredScopeSteps(t, home, dir, store), driver)
			if err == nil {
				t.Fatalf("RunHeadless accepted the unresolvable declaration %q", tc.decl)
			}
			if !strings.Contains(err.Error(), strconv.Quote(tc.decl)) {
				t.Fatalf("error = %v, want it to name the offending declaration %q", err, tc.decl)
			}
			if len(denied) != 0 {
				t.Fatalf("denials = %+v, want none (an invalid declaration is not a denied tool call)", denied)
			}
			if client.callCount() != 0 {
				t.Fatalf("provider rounds = %d, want 0 (no turn may start)", client.callCount())
			}
			if msgs := messagesByRole(store, "user"); len(msgs) != 0 {
				t.Fatalf("session messages = %+v, want an empty launch session with no turn", msgs)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "a.txt")); statErr == nil {
				t.Fatal("a.txt exists; neither list may be partially resolved and no turn may run")
			}
		})
	}
}

// TestRunHeadless_FirstRunExitsBeforeDeclarationResolution proves the first-run settings branch
// never validates declarations — it has no project root, session, or turn — while the configured
// run that follows rejects the same invalid declaration before its first turn.
func TestRunHeadless_FirstRunExitsBeforeDeclarationResolution(t *testing.T) {
	var order []string
	steps := recordingSteps(&order)
	steps.RunFirstRun = func(string) (bool, error) { return true, nil }

	driver := NewHeadlessDriver("anything", &bytes.Buffer{}, &bytes.Buffer{})
	driver.SetDeclaredFileScopes([]string{"~someone/gone.txt"}, nil)
	denied, err := RunHeadless(context.Background(), "/cwd", steps, driver)
	if err != nil || denied != nil {
		t.Fatalf("RunHeadless first-run = (%+v, %v), want (nil, nil) with declarations unresolved", denied, err)
	}

	dir := declaredScopeDir(t)
	home := t.TempDir()
	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")
	store := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000ce", dir)
	configured := NewHeadlessDriver("anything", &bytes.Buffer{}, &bytes.Buffer{})
	configured.SetDeclaredFileScopes([]string{"~someone/gone.txt"}, nil)
	if _, err := RunHeadless(context.Background(), dir, declaredScopeSteps(t, home, dir, store), configured); err == nil {
		t.Fatal("the configured run accepted an unresolvable declaration")
	}
}

// declaredScopeSteps builds the injected fresh-launch step set for a configured run: a real
// session, project root, and provider catalog, with Build as the active mode.
func declaredScopeSteps(t *testing.T, home, dir string, store *sessions.Store) FreshSteps {
	t.Helper()
	var order []string
	steps := recordingSteps(&order)
	steps.ResolveHome = func() (string, error) { return home, nil }
	steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) { return dir, nil, nil }
	steps.ComposeConfig = func(map[string]any, string) (ConfigComposition, error) {
		return ConfigComposition{Config: headlessProviderConfig()}, nil
	}
	steps.BuildToolRegistry = func(any) (any, error) { return &toolRegistryFactory{active: nil}, nil }
	steps.DetermineModel = func(map[string]any, map[string]any, string, []string) (any, bool, error) {
		return model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject), false, nil
	}
	steps.EnsureFreshSession = func(string, string) (*sessions.Store, error) { return store, nil }
	steps.InitMode = func(context.Context, *sessions.Store, map[string]any, string, []string) (any, error) {
		return mode.NewActiveState(mode.Build, mode.SourceDefault), nil
	}
	return steps
}

// TestRunHeadless_DeclaredScopeHoldsOnTheRealDefaultMode proves the ceiling decides on the mode a
// production headless run actually reaches — Build, installed by the driver when the bootstrap
// supplies none — not only on an explicitly pinned one.
func TestRunHeadless_DeclaredScopeHoldsOnTheRealDefaultMode(t *testing.T) {
	dir := declaredScopeDir(t)
	sibling := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(sibling, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client := declaredScopeClient(declaredToolCall{"edit", `{"path":"b.txt","old_text":"keep","new_text":"changed"}`})
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("edit the sibling", &bytes.Buffer{}, &bytes.Buffer{})
	driver.SetDeclaredFileScopes([]string{"a.txt"}, nil)
	result := headlessResult(t, dir, nil)
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := mustReadFile(t, sibling); got != "keep\n" {
		t.Fatalf("b.txt = %q, want it unchanged", got)
	}
	assertDeclaredDenial(t, driver, result, "b.txt")
}

// TestRunHeadless_DeclaredOutOfRootPathIsWrittenWithoutAPrompt proves a declared path outside the
// project root is written with no prompt, while an undeclared out-of-root path is terminally
// denied by the ceiling before the out-of-root folder approval route is reached.
func TestRunHeadless_DeclaredOutOfRootPathIsWrittenWithoutAPrompt(t *testing.T) {
	dir := declaredScopeDir(t)
	outside := declaredScopeDir(t)
	declared := filepath.Join(outside, "declared.txt")
	undeclared := filepath.Join(outside, "undeclared.txt")

	t.Run("declared out-of-root path is created", func(t *testing.T) {
		client := declaredScopeClient(declaredToolCall{"create", `{"path":"` + declared + `","content":"x\n"}`})
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		driver := NewHeadlessDriver("write outside", &bytes.Buffer{}, &bytes.Buffer{})
		driver.SetDeclaredFileScopes([]string{declared}, nil)
		result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
		if err := driver.Run(context.Background(), result); err != nil {
			t.Fatalf("driver.Run: %v", err)
		}
		if got := mustReadFile(t, declared); got != "x\n" {
			t.Fatalf("declared out-of-root file = %q, want it created with no prompt", got)
		}
	})

	t.Run("undeclared out-of-root path is denied", func(t *testing.T) {
		client := declaredScopeClient(declaredToolCall{"create", `{"path":"` + undeclared + `","content":"x\n"}`})
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		driver := NewHeadlessDriver("write outside", &bytes.Buffer{}, &bytes.Buffer{})
		driver.SetDeclaredFileScopes([]string{declared}, nil)
		result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
		if err := driver.Run(context.Background(), result); err != nil {
			t.Fatalf("driver.Run: %v", err)
		}
		if _, statErr := os.Stat(undeclared); statErr == nil {
			t.Fatal("an undeclared out-of-root path was created")
		}
		assertDeclaredDenial(t, driver, result, undeclared)
	})
}

// TestRunHeadless_DeclaredScopeDeniesInPlanWithPlansOwnEnvelope proves Plan stays the sole
// authority: a write declared in both lists is still denied there, with Plan's own recoverable
// mode envelope rather than a declared-scope one.
func TestRunHeadless_DeclaredScopeDeniesInPlanWithPlansOwnEnvelope(t *testing.T) {
	dir := declaredScopeDir(t)
	target := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(target, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client := declaredScopeClient(declaredToolCall{"edit", `{"path":"a.txt","old_text":"keep","new_text":"changed"}`})
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("edit it", &bytes.Buffer{}, &bytes.Buffer{})
	driver.SetDeclaredFileScopes([]string{"a.txt"}, []string{"a.txt"})
	result := headlessResult(t, dir, mode.NewActiveState(mode.Plan, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := mustReadFile(t, target); got != "keep\n" {
		t.Fatalf("a.txt = %q, want Plan to deny a declared write", got)
	}
	text := declaredDenyText(t, result)
	if !permissions.IsModeDenyEnvelope(text) {
		t.Fatalf("deny envelope = %s, want Plan's own mode envelope", text)
	}
	if strings.Contains(text, "declared-scope ceiling") {
		t.Fatalf("deny envelope = %s, want Plan's unchanged deny reason", text)
	}
	matched := decodePermissionMatched(t, reloadStore(t, result.Session))
	if len(matched) != 1 || matched[0].OutcomeSource != "mode_auto" || matched[0].Outcome != "deny" {
		t.Fatalf("permission_matched events = %+v, want one mode_auto deny", matched)
	}
}

// TestRunHeadless_NoDeclarationLeavesAuthorizationUnchanged proves an undeclared run emits no
// declared-scope record and keeps its fail-closed refusal.
func TestRunHeadless_NoDeclarationLeavesAuthorizationUnchanged(t *testing.T) {
	dir := declaredScopeDir(t)
	target := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(target, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client := declaredScopeClient(declaredToolCall{"edit", `{"path":"a.txt","old_text":"keep","new_text":"changed"}`})
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("edit it", &bytes.Buffer{}, &bytes.Buffer{})
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := mustReadFile(t, target); got != "keep\n" {
		t.Fatalf("a.txt = %q, want the fail-closed refusal to leave it unchanged", got)
	}
	text := declaredDenyText(t, result)
	if !strings.Contains(text, "no approval available in non-interactive run mode") {
		t.Fatalf("deny envelope = %s, want the unchanged fail-closed reason", text)
	}
	for _, m := range decodePermissionMatched(t, reloadStore(t, result.Session)) {
		if m.OutcomeSource == permissions.OutcomeSourceDeclaredScope {
			t.Fatalf("an undeclared run emitted a declared_scope record: %+v", m)
		}
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

// Without the guard the fail-closed headless authorizer would refuse this edit terminally and
// summarize it, so an empty summary plus a second provider round is what proves the refusal came
// from the pre-authorization guard.
func TestRunHeadless_ProtectedSettingsMutationIsRefusedAndTheTurnReIssues(t *testing.T) {
	cases := []struct {
		name   string
		target func(project string, result *BootstrapResult) string
	}{
		{
			name:   "project settings file",
			target: func(project string, _ *BootstrapResult) string { return projectSettingsPath(project) },
		},
		{
			name:   "global settings file",
			target: func(_ string, result *BootstrapResult) string { return SettingsPath(result.Home) },
		},
		{
			name:   "trust record",
			target: func(_ string, result *BootstrapResult) string { return trust.StorePath(result.Home) },
		},
		{
			name:   "trust record lock sidecar",
			target: func(_ string, result *BootstrapResult) string { return trust.StorePath(result.Home) + ".lock" },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project := declaredScopeDir(t)
			result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
			// The launch directory is a different tree, so a policy built from it would protect nothing.
			result.LaunchDir = declaredScopeDir(t)
			settings := projectSettingsPath(project)
			global := SettingsPath(result.Home)
			trustRecord := trust.StorePath(result.Home)
			trustLock := trustRecord + ".lock"
			seedProtectedSettings(t, settings)
			seedProtectedSettings(t, global)
			seedProtectedSettings(t, trustRecord)
			seedProtectedSettings(t, trustLock)
			target := tc.target(project, result)
			wantScope, err := filepath.EvalSymlinks(filepath.Dir(target))
			if err != nil {
				t.Fatalf("EvalSymlinks: %v", err)
			}

			client := toolThenContentClient(nil, filetools.EditToolName, removeGrantsArgs(t, target), guardRecoveryAnswer)
			client.title = streamedTitle("Model title")
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			var stdout, stderr bytes.Buffer
			driver := NewHeadlessDriver("clear my grants", &stdout, &stderr)
			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}

			for _, path := range []string{settings, global, trustRecord, trustLock} {
				if got := mustReadFile(t, path); got != sevenGrantSettings {
					t.Fatalf("protected file %q = %q, want its bytes untouched", path, got)
				}
			}
			if got := driver.DeniedSubjects(); len(got) != 0 {
				t.Fatalf("DeniedSubjects = %v, want none (a guard refusal never reaches the authorizer that records the summary)", got)
			}
			if client.callCount() != 2 {
				t.Fatalf("provider calls = %d, want 2 (a guard denial re-issues rather than halting the run)", client.callCount())
			}
			if stdout.String() != guardRecoveryAnswer+"\n" {
				t.Fatalf("stdout = %q, want the model's recovery reply after the guard continuation", stdout.String())
			}
			if strings.Contains(stderr.String(), headlessDenyReason) {
				t.Fatalf("stderr = %q, want no no-approval summary for a recoverable guard denial", stderr.String())
			}

			durable := sessions.New(result.Session.Path(), readSessionFile(t, result.Session.Path()))
			matched := decodePermissionMatched(t, durable)
			want := events.PermissionMatched{
				SubjectKind:   "tool",
				Subject:       filetools.EditToolName,
				PathScope:     wantScope,
				Outcome:       "deny",
				OutcomeSource: "protected_state",
			}
			if len(matched) != 1 || matched[0] != want {
				t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
			}
			toolMsgs := messagesByRole(durable, "tool")
			if len(toolMsgs) != 1 || toolMsgs[0].Content.Text() != permissions.BuildGuardDenyEnvelope() {
				t.Fatalf("durable tool messages = %+v, want the one guard deny envelope", toolMsgs)
			}
		})
	}
}

func TestRunHeadless_BlockedPathReadIsRefusedAndTheTurnReIssues(t *testing.T) {
	project := declaredScopeDir(t)
	result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
	file := seedBlockedSecret(t, project)
	result.SettingsLayers = blockedGlobalLayers(t, result.Home, project, filepath.Dir(file))

	client, sent := requestRecordingClient(filetools.ReadToolName, toolArgs(t, map[string]any{"path": file}))
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("show me the token", &stdout, &stderr)
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if client.callCount() != 3 || stdout.String() != guardRecoveryAnswer+"\n" {
		t.Fatalf("provider calls = %d, stdout = %q; want 3 (two turn rounds and the title request) and the model's recovery reply", client.callCount(), stdout.String())
	}
	if strings.Contains(sent(), blockedSecret) {
		t.Fatal("a model request carried the blocked file's content")
	}
	if strings.Contains(sent(), SettingsPath(result.Home)) {
		t.Fatal("a model request carried the settings file path")
	}
	if n := strings.Count(stderr.String(), blockedSourceLine(filepath.Dir(file), SettingsPath(result.Home))); n != 1 {
		t.Fatalf("stderr = %q carries the source line %d times, want once", stderr.String(), n)
	}
	durable := sessions.New(result.Session.Path(), readSessionFile(t, result.Session.Path()))
	want := blockedPathDenial(filetools.ReadToolName, filepath.Dir(file), SettingsPath(result.Home))
	if matched := decodePermissionMatched(t, durable); len(matched) != 1 || matched[0] != want {
		t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
	}
}

func TestRunHeadless_BrokenGlobalSettingsDenyOutsideReadsUntilFixed(t *testing.T) {
	project := declaredScopeDir(t)
	result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
	file := seedBlockedSecret(t, project)
	settings := SettingsPath(result.Home)
	result.SettingsLayers = blockedGlobalLayers(t, result.Home, project, filepath.Dir(file))
	_, first, second := headlessExternalReads(t)
	const broken = "blocked_paths: [\n"

	client := settingsEditingClient(t,
		settingsRound{edit: settingsEdit(settings, broken), call: readCall(t, file)},
		settingsRound{edit: settingsEdit(settings, blockedYAML(filepath.Dir(file))), call: readCall(t, first)},
		settingsRound{edit: settingsEdit(settings, broken), call: readCall(t, second)},
	)
	client.title = streamedTitle("Model title")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("read them", &bytes.Buffer{}, &bytes.Buffer{})
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if client.callCount() != 4 {
		t.Fatalf("provider calls = %d, want 4 (the denied outside read re-issues the model)", client.callCount())
	}
	if denied := driver.DeniedSubjects(); len(denied) != 1 {
		t.Fatalf("DeniedSubjects = %+v, want only the outside read made while the file was broken", denied)
	}
	store := reloadStore(t, result.Session)
	results := messagesByRole(store, "tool")
	if len(results) != 3 || strings.Contains(results[0].Content.Text(), blockedSecret) ||
		!strings.Contains(results[1].Content.Text(), "OUTSIDE A") || strings.Contains(results[2].Content.Text(), "OUTSIDE B") {
		t.Fatalf("tool messages = %+v, want the blocked read refused, the first outside read answered and the second denied", results)
	}
	var refused, opened []events.PermissionMatched
	for _, m := range decodePermissionMatched(t, store) {
		switch m.OutcomeSource {
		case "blocked_path":
			refused = append(refused, m)
		case "open_read":
			opened = append(opened, m)
		}
	}
	if want := blockedPathDenial(filetools.ReadToolName, filepath.Dir(file), settings); len(refused) != 1 || refused[0] != want {
		t.Fatalf("blocked_path records = %#v, want exactly one %#v", refused, want)
	}
	if len(opened) != 1 || opened[0].PathScope != filepath.Dir(first) {
		t.Fatalf("open_read records = %#v, want one for %q", opened, filepath.Dir(first))
	}
}

func TestRunHeadless_BrokenGlobalSettingsDenyOutsideShellReads(t *testing.T) {
	project := declaredScopeDir(t)
	result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
	file := seedBlockedSecret(t, declaredScopeDir(t))
	settings := SettingsPath(result.Home)
	result.SettingsLayers = blockedGlobalLayers(t, result.Home, project, filepath.Dir(file))
	_, first, second := headlessExternalReads(t)
	bash := func(command string) declaredToolCall {
		return declaredToolCall{name: bashToolName, args: toolArgs(t, map[string]any{"command": command})}
	}

	client := settingsEditingClient(t,
		settingsRound{edit: settingsEdit(settings, "blocked_paths: [\n"), call: bash("cat " + file)},
		settingsRound{edit: settingsEdit(settings, blockedYAML(filepath.Dir(file))), call: bash("cat " + first)},
		settingsRound{edit: settingsEdit(settings, blockedYAML("relative/dir")), call: bash("cat " + second)},
	)
	client.title = streamedTitle("Model title")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stderr bytes.Buffer
	driver := NewHeadlessDriver("read them", &bytes.Buffer{}, &stderr)
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if client.callCount() != 4 {
		t.Fatalf("provider calls = %d, want 4 (the denied outside read re-issues the model)", client.callCount())
	}
	if denied := driver.DeniedSubjects(); len(denied) != 1 || denied[0].Subject != "cat "+second {
		t.Fatalf("DeniedSubjects = %+v, want only %q", denied, "cat "+second)
	}
	results := messagesByRole(reloadStore(t, result.Session), "tool")
	if len(results) != 3 || strings.Contains(results[0].Content.Text(), blockedSecret) ||
		!strings.Contains(results[1].Content.Text(), "OUTSIDE A") || strings.Contains(results[2].Content.Text(), "OUTSIDE B") {
		t.Fatalf("tool messages = %+v, want the blocked read refused, the first outside read answered and the second denied", results)
	}
	for _, line := range []string{problemNotice(settings, "is not valid YAML"), fixedNotice(settings)} {
		if n := strings.Count(stderr.String(), line+"\n"); n != 1 {
			t.Fatalf("stderr = %q carries %q %d times, want once", stderr.String(), line, n)
		}
	}
}

func TestRunHeadless_BlockedPathAddedMidRunIsRefusedAtTheNextRead(t *testing.T) {
	project := declaredScopeDir(t)
	result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
	file := seedBlockedSecret(t, project)
	result.SettingsLayers = blockedGlobalLayers(t, result.Home, project)

	client := midRunBlockedClient(t, SettingsPath(result.Home), file)
	client.title = streamedTitle("Model title")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("show me the token", &bytes.Buffer{}, &bytes.Buffer{})
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	requireMidRunBlockedReads(t, client, reloadStore(t, result.Session), file, SettingsPath(result.Home))
}

func TestRunHeadless_BlockedPathShellReadIsRefusedAndTheTurnReIssues(t *testing.T) {
	project := declaredScopeDir(t)
	result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
	file := seedBlockedSecret(t, project)
	result.SettingsLayers = blockedGlobalLayers(t, result.Home, project, filepath.Dir(file))

	client, sent := requestRecordingClient(bashToolName, toolArgs(t, map[string]any{"command": "cat " + file}))
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("show me the token", &stdout, &stderr)
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if client.callCount() != 3 || stdout.String() != guardRecoveryAnswer+"\n" {
		t.Fatalf("provider calls = %d, stdout = %q; want 3 (two turn rounds and the title request) and the model's recovery reply", client.callCount(), stdout.String())
	}
	if strings.Contains(sent(), blockedSecret) {
		t.Fatal("a model request carried the blocked file's content")
	}
	if strings.Contains(sent(), SettingsPath(result.Home)) {
		t.Fatal("a model request carried the settings file path")
	}
	if n := strings.Count(stderr.String(), blockedSourceLine(filepath.Dir(file), SettingsPath(result.Home))); n != 1 {
		t.Fatalf("stderr = %q carries the source line %d times, want once", stderr.String(), n)
	}
	requestSubject, err := permissions.DirectRequestSubject([]string{"cat", file}, nil, false)
	if err != nil {
		t.Fatalf("DirectRequestSubject: %v", err)
	}
	want := events.PermissionMatched{SubjectKind: "direct", Subject: "cat " + file, PathScope: project, Outcome: "deny", OutcomeSource: "blocked_path", DirectRequestSubject: requestSubject, BlockedEntry: filepath.Dir(file), BlockedEntrySource: SettingsPath(result.Home)}
	durable := sessions.New(result.Session.Path(), readSessionFile(t, result.Session.Path()))
	if matched := decodePermissionMatched(t, durable); len(matched) != 1 || matched[0] != want {
		t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
	}
}

func TestRunHeadless_ShellCommandAboveABlockedPathIsDeniedWithoutATerminal(t *testing.T) {
	project := declaredScopeDir(t)
	result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
	file := seedBlockedSecret(t, project)
	result.SettingsLayers = blockedGlobalLayers(t, result.Home, project, filepath.Dir(file))
	const marker = "home-listing-marker"
	if err := os.WriteFile(filepath.Join(result.Home, marker), nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	command := "ls " + result.Home

	client, sent := requestRecordingClient(bashToolName, toolArgs(t, map[string]any{"command": command}))
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("list my home folder", &bytes.Buffer{}, &bytes.Buffer{})
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := driver.DeniedSubjects(); len(got) != 1 || got[0].Subject != command {
		t.Fatalf("DeniedSubjects = %+v, want one entry for %q", got, command)
	}
	if strings.Contains(sent(), marker) {
		t.Fatal("a model request carried the home listing")
	}
	durable := sessions.New(result.Session.Path(), readSessionFile(t, result.Session.Path()))
	for _, matched := range decodePermissionMatched(t, durable) {
		if matched.OutcomeSource == "mode_auto" {
			t.Fatalf("permission_matched = %+v, want no mode_auto allow for the asking command", matched)
		}
	}
}

func TestRunHeadless_InvalidBlockedPathsEntryStopsTheRun(t *testing.T) {
	project := declaredScopeDir(t)
	result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
	entry := "vault/x"
	result.SettingsLayers = blockedGlobalLayers(t, result.Home, project, "~/vault")
	result.SettingsLayers[0].Raw["blocked_paths"] = []any{entry}

	client := toolThenContentClient(nil, filetools.ReadToolName, `{}`, guardRecoveryAnswer)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout bytes.Buffer
	driver := NewHeadlessDriver("show me the token", &stdout, &bytes.Buffer{})
	err := driver.Run(context.Background(), result)
	if err == nil || client.callCount() != 0 || stdout.Len() != 0 {
		t.Fatalf("driver.Run error = %v, provider calls = %d, stdout = %q; want a failed run that never starts the turn", err, client.callCount(), stdout.String())
	}
	for _, want := range []string{"bootstrap: headless build blocked paths:", SettingsPath(result.Home), strconv.Quote(entry)} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("driver.Run error = %q, want it to contain %q", err, want)
		}
	}
}

func TestRunHeadless_BigBlockedPathsEntryWarnsOnStderr(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry string
		warns bool
	}{
		{"system folder", "/etc", true},
		{"ssh folder", "~/.ssh", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project := declaredScopeDir(t)
			result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
			result.SettingsLayers = blockedGlobalLayers(t, result.Home, project, tc.entry)

			client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
				return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			var stdout, stderr bytes.Buffer
			driver := NewHeadlessDriver("hello", &stdout, &stderr)
			if err := driver.Run(context.Background(), result); err != nil || stdout.String() != "done\n" {
				t.Fatalf("driver.Run error = %v, stdout = %q; want a completed run", err, stdout.String())
			}

			warning := "warning: blocked_paths entry /etc in " + SettingsPath(result.Home) + " covers /etc; programs need these to start, so most commands will fail\n"
			if tc.warns && strings.Count(stderr.String(), warning) != 1 {
				t.Fatalf("stderr = %q, want the warning once", stderr.String())
			}
			if !tc.warns && strings.Contains(stderr.String(), "warning: blocked_paths") {
				t.Fatalf("stderr = %q, want no blocked_paths warning", stderr.String())
			}
		})
	}
}

func TestRunHeadless_SkippedSkillsWarnOnStderrOnEveryStart(t *testing.T) {
	for start := range 2 {
		t.Run(fmt.Sprintf("start=%d", start), func(t *testing.T) {
			project := declaredScopeDir(t)
			result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
			warnings := seedStartupSkills(t, result.Home, project)

			var system string
			client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
				if !isTitleRequest(req) && len(req.Messages) > 0 && req.Messages[0].Role == "system" {
					system = req.Messages[0].Content
				}
				return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			var stdout, stderr bytes.Buffer
			driver := NewHeadlessDriver("hello", &stdout, &stderr)
			if err := driver.Run(context.Background(), result); err != nil || stdout.String() != "done\n" {
				t.Fatalf("driver.Run error = %v, stdout = %q; want a completed run", err, stdout.String())
			}

			lines := strings.Split(stderr.String(), "\n")
			for _, w := range warnings {
				if n := slices.Index(lines, w); n < 0 || slices.Index(lines[n+1:], w) >= 0 {
					t.Fatalf("stderr has warning line %q at %d, want exactly once\n--- stderr ---\n%s", w, n, stderr.String())
				}
			}
			if got := len(result.Skills.Skipped); got != len(warnings) {
				t.Fatalf("run record holds %d skipped skills, want %d", got, len(warnings))
			}
			assertStartupSkillsPrompt(t, system)
		})
	}
}

func TestRunHeadless_ProjectBlockedPathCountsOnlyInATrustedProject(t *testing.T) {
	for _, tc := range []struct {
		name     string
		decision trust.Decision
		refused  bool
	}{
		{"trusted", trust.Decision{Trusted: true, Reason: trust.ReasonTrusted}, true},
		{"untrusted", trust.Decision{Reason: trust.ReasonNoRecord}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var order []string
			steps, _, projectRoot := trustGateFixture(t, &order, tc.decision)
			file := seedBlockedSecret(t, projectRoot)
			if err := os.WriteFile(projectSettingsPath(projectRoot), []byte("blocked_paths:\n  - "+filepath.Dir(file)+"\n"), 0o600); err != nil {
				t.Fatalf("write project settings: %v", err)
			}
			launched, err := RunFresh(context.Background(), projectRoot, steps)
			if err != nil {
				t.Fatalf("RunFresh error: %v", err)
			}
			result := headlessResult(t, projectRoot, mode.NewActiveState(mode.Build, mode.SourceConfig))
			result.SettingsLayers = launched.SettingsLayers

			client, sent := requestRecordingClient(filetools.ReadToolName, toolArgs(t, map[string]any{"path": file}))
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()
			driver := NewHeadlessDriver("show me the token", &bytes.Buffer{}, &bytes.Buffer{})
			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}

			var blocked []events.PermissionMatched
			for _, m := range decodePermissionMatched(t, sessions.New(result.Session.Path(), readSessionFile(t, result.Session.Path()))) {
				if m.OutcomeSource == "blocked_path" {
					blocked = append(blocked, m)
				}
			}
			leaked := strings.Contains(sent(), blockedSecret)
			if !tc.refused {
				if len(blocked) != 0 || !leaked {
					t.Fatalf("blocked_path records = %#v, content read = %v; want the untrusted layer ignored and the read served", blocked, leaked)
				}
				return
			}
			want := blockedPathDenial(filetools.ReadToolName, filepath.Dir(file), projectSettingsPath(projectRoot))
			if len(blocked) != 1 || blocked[0] != want || leaked {
				t.Fatalf("blocked_path records = %#v, content read = %v; want exactly one %#v and no content", blocked, leaked, want)
			}
		})
	}
}

func headlessOpenRouterResult(t *testing.T, dir string, m *mode.ActiveState, modelID string) *BootstrapResult {
	t.Helper()
	home := t.TempDir()
	settings := SettingsPath(home)
	seedOpenRouterDiscoveredModels(t, settings, toolGateModels())
	return &BootstrapResult{
		Home:        home,
		LaunchDir:   dir,
		ProjectRoot: dir,
		Session:     storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000ab", dir),
		Model:       toolGateActive(modelID),
		Config: map[string]any{"provider": map[string]any{
			"openrouter": map[string]any{"base_url": "https://openrouter.ai/api/v1", "api_key": "sk-or-test"},
		}},
		ConfigLayerPaths: []string{settings},
		Mode:             m,
		ToolRegistry:     &toolRegistryFactory{active: nil},
	}
}

func TestHeadlessExperiment_ToolLessModelSuppressesShippedAndExtraTools(t *testing.T) {
	for _, tc := range []struct {
		name    string
		modelID string
		capable bool
	}{
		{"tool-less", toolLessModelID, false},
		{"capable", toolfulModelID, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rounds [][]string
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
				return &stubTurnClient{title: streamedTitle("Model title"), fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
					rounds = append(rounds, toolNames(req.Tools))
					return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
				}}
			})()

			driver := NewHeadlessDriver("plan it", &bytes.Buffer{}, &bytes.Buffer{})
			if err := driver.EnableExperiment(HeadlessExperiment{ExtraTools: []HeadlessExtraTool{{
				Definition: todoPlanDefinition(),
				Handle: func(context.Context, string) (turn.ToolResult, error) {
					return turn.ToolResult{Content: "recorded"}, nil
				},
			}}}); err != nil {
				t.Fatalf("EnableExperiment: %v", err)
			}
			result := headlessOpenRouterResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault), tc.modelID)
			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}

			if len(rounds) != 1 {
				t.Fatalf("provider rounds = %d, want exactly one", len(rounds))
			}
			if !tc.capable {
				if len(rounds[0]) != 0 {
					t.Fatalf("tool-less model advertised %v, want nothing — the gate must cover experiment tools too", rounds[0])
				}
				return
			}
			for _, want := range []string{"todo_plan", "bash"} {
				if !slices.Contains(rounds[0], want) {
					t.Fatalf("capable model advertised %v, want %q among the shipped set plus extras", rounds[0], want)
				}
			}
		})
	}
}

func TestHeadlessExperiment_ToolLessModelStillRejectsAShippedNameCollision(t *testing.T) {
	var calls int32
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
		return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			atomic.AddInt32(&calls, 1)
			return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
		}}
	})()

	driver := NewHeadlessDriver("plan it", &bytes.Buffer{}, &bytes.Buffer{})
	if err := driver.EnableExperiment(HeadlessExperiment{ExtraTools: []HeadlessExtraTool{{
		Definition: provider.ToolDefinition{Name: "bash"},
		Handle: func(context.Context, string) (turn.ToolResult, error) {
			return turn.ToolResult{}, nil
		},
	}}}); err != nil {
		t.Fatalf("EnableExperiment: %v", err)
	}
	result := headlessOpenRouterResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault), toolLessModelID)
	if err := driver.Run(context.Background(), result); !errors.Is(err, ErrHeadlessExperiment) {
		t.Fatalf("driver.Run = %v, want ErrHeadlessExperiment for a shipped-name collision", err)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("the refused run still issued %d provider request(s)", calls)
	}
}

// The headless dispatcher is built with the run's protected-state policy; this proves that policy
// reaches VCS dispatch too, against a real repository whose committed settings differ from the
// approved bytes on disk.
func TestRunHeadless_ProtectedSettingsVCSMutationIsRefusedAndTheTurnReIssues(t *testing.T) {
	project := declaredScopeDir(t)
	seedGitRepo(t, project)
	result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
	result.ToolRegistry = &toolRegistryFactory{active: activeBuiltinVCS(t, "git", project)}
	settings := projectSettingsPath(project)
	seedProtectedSettings(t, settings)

	client := toolThenContentClient(nil, "vcs_restore_file", `{"path":".codemeld/settings.yaml"}`, guardRecoveryAnswer)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("discard my policy changes", &stdout, &stderr)
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := mustReadFile(t, settings); got != sevenGrantSettings {
		t.Fatalf("settings file = %q, want the seven grants untouched by the restore", got)
	}
	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %v, want none (a guard refusal never reaches the authorizer that records the summary)", got)
	}
	if stdout.String() != guardRecoveryAnswer+"\n" {
		t.Fatalf("stdout = %q, want the model's recovery reply after the guard continuation", stdout.String())
	}

	durable := sessions.New(result.Session.Path(), readSessionFile(t, result.Session.Path()))
	matched := decodePermissionMatched(t, durable)
	want := events.PermissionMatched{
		SubjectKind:   "tool",
		Subject:       "vcs_restore_file",
		PathScope:     project,
		Outcome:       "deny",
		OutcomeSource: "protected_state",
	}
	if len(matched) != 1 || matched[0] != want {
		t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
	}
	toolMsgs := messagesByRole(durable, "tool")
	if len(toolMsgs) != 1 || toolMsgs[0].Content.Text() != permissions.BuildGuardDenyEnvelope() {
		t.Fatalf("durable tool messages = %+v, want the one guard deny envelope", toolMsgs)
	}
}

func TestRunHeadless_BlockedEntryVCSRestoreIsRefusedAndTheTurnReIssues(t *testing.T) {
	project := declaredScopeDir(t)
	seedBlockedGitRepo(t, project)
	result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
	result.ToolRegistry = &toolRegistryFactory{active: activeBuiltinVCS(t, "git", project)}
	secrets := filepath.Join(project, "secrets")
	result.SettingsLayers = blockedGlobalLayers(t, result.Home, project, secrets)

	client := toolThenContentClient(nil, "vcs_restore_file", `{"path":"secrets/k"}`, guardRecoveryAnswer)
	client.title = streamedTitle("Model title")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout bytes.Buffer
	driver := NewHeadlessDriver("discard my secret changes", &stdout, &bytes.Buffer{})
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if client.callCount() != 2 || stdout.String() != guardRecoveryAnswer+"\n" {
		t.Fatalf("provider calls = %d, stdout = %q; want 2 and the model's recovery reply", client.callCount(), stdout.String())
	}
	if got := mustReadFile(t, filepath.Join(secrets, "k")); got != modifiedSecret {
		t.Fatalf("blocked file = %q, want its modified bytes %q", got, modifiedSecret)
	}
	durable := sessions.New(result.Session.Path(), readSessionFile(t, result.Session.Path()))
	want := events.PermissionMatched{SubjectKind: "tool", Subject: "vcs_restore_file", PathScope: project, Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: secrets, BlockedEntrySource: SettingsPath(result.Home)}
	if matched := decodePermissionMatched(t, durable); len(matched) != 1 || matched[0] != want {
		t.Fatalf("durable permission_matched = %#v, want exactly one %#v", matched, want)
	}
}

// dispatchStore is the store the dispatcher emits structured-read evidence to; a nil one makes
// every eligible read fail closed on its unrecordable start event. The authorizer keeps a real
// store either way, so that failure is the read's and not the permission path's.
func experimentPlanHarness(t *testing.T, dispatchStore *sessions.Store) (*headlessExperimentDispatcher, *int32) {
	t.Helper()
	project := readToolsProject(t)
	home := t.TempDir()
	cache := emptyCache(t, project)
	app := tui.New(nil)
	app.SetActiveStore(mkStore(t))
	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, func() *sessions.Store { return dispatchStore }, home, project, securitystate.Policy{})
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(),
		newPromptGateBuilder(func(tui.PromptRequest) (tui.PromptDecision, error) {
			return tui.PromptDecision{Option: tui.OptionAllowOnce}, nil
		}), home, project, mode.NewActiveState(mode.Build, mode.SourceDefault))
	inner := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return dispatchStore }, 65536, securitystate.Policy{})

	var handled int32
	d := newHeadlessExperimentDispatcher(inner, HeadlessExperiment{ExtraTools: []HeadlessExtraTool{{
		Definition: todoPlanDefinition(),
		Handle: func(context.Context, string) (turn.ToolResult, error) {
			atomic.AddInt32(&handled, 1)
			return turn.ToolResult{Content: "recorded"}, nil
		},
	}}})
	return d, &handled
}

func TestHeadlessExperiment_ExtraToolIsABarrierBetweenEligibleSegments(t *testing.T) {
	store := mkStore(t)
	d, handled := experimentPlanHarness(t, store)
	calls := []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "main.go"}),
		structuredCall("c2", "todo_plan", map[string]any{}),
		structuredCall("c3", filetools.GrepToolName, map[string]any{"pattern": "func"}),
	}

	plan := d.Plan(calls, 3)
	assertPartitionedPlan(t, plan, calls, "exe")

	run, err := schedulePlan(plan, 3, nil)
	if err != nil {
		t.Fatalf("Schedule: %v", err)
	}
	if want := []string{"c1", "c2", "c3"}; !slices.Equal(run.ids(), want) {
		t.Fatalf("execution order = %v, want %v (the extra is a barrier, not a collapse)", run.ids(), want)
	}
	if atomic.LoadInt32(handled) != 1 {
		t.Fatalf("extra handler invoked %d times, want 1", atomic.LoadInt32(handled))
	}
	if n := len(decodeStoreEvents[events.StructuredReadStart](t, reloadStore(t, store), events.KindStructuredReadStart)); n != 2 {
		t.Fatalf("structured_read_start events = %d, want 2 (both eligible reads still take the prepared path)", n)
	}
}

func TestHeadlessExperiment_FailingEligibleReadSkipsTheExtraAndLaterRead(t *testing.T) {
	d, handled := experimentPlanHarness(t, nil)
	calls := []turn.AssembledToolCall{
		structuredCall("c1", filetools.ReadToolName, map[string]any{"path": "main.go"}),
		structuredCall("c2", "todo_plan", map[string]any{}),
		structuredCall("c3", filetools.GrepToolName, map[string]any{"pattern": "func"}),
	}

	plan := d.Plan(calls, 3)
	assertPartitionedPlan(t, plan, calls, "exe")

	run, err := schedulePlan(plan, 3, nil)
	if err == nil {
		t.Fatal("Schedule error = nil, want the eligible read's internal failure")
	}
	if !slices.Equal(run.ids(), []string{"c1"}) {
		t.Fatalf("executed = %v, want only the failing eligible read (the retained pre-run guard stops the rest)", run.ids())
	}
	if atomic.LoadInt32(handled) != 0 {
		t.Fatalf("extra handler invoked %d times, want 0", atomic.LoadInt32(handled))
	}
}

func TestRunHeadless_PromptApprovalSessionScopeCoversLaterArgumentVariant(t *testing.T) {
	dir := t.TempDir()

	var round int32
	client := &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		n := atomic.AddInt32(&round, 1)
		if n > 2 {
			return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
		}
		target := "first/nested"
		if n == 2 {
			target = "second/nested"
		}
		frag := toolFrag(0, fmt.Sprintf("call_%d", n), "bash", fmt.Sprintf(`{"command":"mkdir -p %s"}`, target))
		return provider.Response{Stream: newStream(toolCallsChunk(frag))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stderr bytes.Buffer
	driver := NewHeadlessDriver("make folders", &bytes.Buffer{}, &stderr)
	// Session lifetime, then scope choice 3 — the `mkdir -p :*` prefix. Only one answer set is
	// supplied, so a second prompt would read EOF and deny.
	driver.EnablePromptForApproval(strings.NewReader("3\n3\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %v, want none (the prefix scope covers the later argument)", got)
	}
	if n := strings.Count(stderr.String(), "approval required"); n != 1 {
		t.Fatalf("terminal rendered %d prompts, want 1:\n%s", n, stderr.String())
	}
	toolMsgs := messagesByRole(reloadStore(t, result.Session), "tool")
	if len(toolMsgs) != 2 {
		t.Fatalf("tool messages = %d, want 2 (both calls authorized)", len(toolMsgs))
	}
	for i, m := range toolMsgs {
		if strings.Contains(m.Content.Text(), `"denied_by"`) {
			t.Fatalf("tool message %d is a deny envelope: %q", i, m.Content.Text())
		}
	}
	for _, p := range []string{
		filepath.Join(dir, ".codemeld", "settings.yaml"),
		filepath.Join(result.Home, ".codemeld", "global", "settings.yaml"),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("settings file %s exists — a session grant must not persist (stat err = %v)", p, err)
		}
	}
}

func TestRunHeadless_PromptApprovalFolderProgramScopePersistsAndDiscloses(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"one.txt", "two.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	var round int32
	client := &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		n := atomic.AddInt32(&round, 1)
		if n > 2 {
			return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
		}
		file := "one.txt"
		if n == 2 {
			file = "two.txt"
		}
		frag := toolFrag(0, fmt.Sprintf("call_%d", n), "bash", fmt.Sprintf(`{"command":"rm %s"}`, file))
		return provider.Response{Stream: newStream(toolCallsChunk(frag))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stderr bytes.Buffer
	driver := NewHeadlessDriver("clean up", &bytes.Buffer{}, &stderr)
	// Folder lifetime, then scope choice 3 — the `rm :*` Program row — then its confirmation.
	driver.EnablePromptForApproval(strings.NewReader("4\n3\n1\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %v, want none", got)
	}
	for _, name := range []string{"one.txt", "two.txt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s still present — the program-scope grant must authorize both calls: stat err = %v", name, err)
		}
	}
	if n := strings.Count(stderr.String(), "approval required"); n != 1 {
		t.Fatalf("terminal rendered %d prompts, want 1:\n%s", n, stderr.String())
	}

	settings := config.LocalSettingsPath(dir)
	entries := readPersistedPermissions(t, settings, dir)
	if len(entries) != 1 {
		t.Fatalf("project settings hold %d permission entries, want 1: %+v", len(entries), entries)
	}
	if got := entries[0]; got.GrantKind != "folder" || got.Subject != "rm :*" || got.PathScope != dir {
		t.Fatalf("persisted entry = %+v, want a folder grant for %q scoped to %s", got, "rm :*", dir)
	}
	if _, err := os.Stat(filepath.Join(result.Home, ".codemeld", "global", "settings.yaml")); !os.IsNotExist(err) {
		t.Fatalf("global settings written — a headless run must never grant machine-wide (stat err = %v)", err)
	}

	out := stderr.String()
	for _, want := range []string{
		"project root: " + dir,
		"saved to: " + projectSettingsPath(dir),
		"applies to: " + dir + " and its descendants",
		"canonical command: rm one.txt",
		"subject kind: direct-command",
		scopeDestructiveProgramWarning,
		"effective grant: rm :* (direct command)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("terminal disclosure missing %q:\n%s", want, out)
		}
	}
	if strings.Index(out, scopeDestructiveProgramWarning) > strings.LastIndex(out, scopeProgramWarning) {
		t.Fatalf("destructive advisory is not above the breadth warning:\n%s", out)
	}
}

func TestRunHeadless_MatchedPersistsDirectEnvIdentity(t *testing.T) {
	dir := t.TempDir()
	notes := filepath.Join(dir, "my notes.txt")
	if err := os.WriteFile(notes, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var round int32
	client := &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		n := atomic.AddInt32(&round, 1)
		if n > 2 {
			return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
		}
		frag := toolFrag(0, fmt.Sprintf("call_%d", n), "bash", `{"command":"FOO=bar cat \"my notes.txt\""}`)
		return provider.Response{Stream: newStream(toolCallsChunk(frag))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stderr bytes.Buffer
	driver := NewHeadlessDriver("read my notes twice", &bytes.Buffer{}, &stderr)
	// Session lifetime, then scope choice 1 — the exact command. Only one answer set is
	// supplied, so a second prompt would read EOF and deny.
	driver.EnablePromptForApproval(strings.NewReader("3\n1\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %v, want none (the session grant covers the repeat)", got)
	}
	if n := strings.Count(stderr.String(), "approval required"); n != 1 {
		t.Fatalf("terminal rendered %d prompts, want 1:\n%s", n, stderr.String())
	}

	wantCommand := permissions.ExactSubject("cat", []string{"my notes.txt"})
	wantRequest, err := permissions.DirectRequestSubject([]string{"cat", "my notes.txt"}, []string{"FOO=bar"}, false)
	if err != nil {
		t.Fatalf("DirectRequestSubject: %v", err)
	}

	store := reloadStore(t, result.Session)
	if prompts := decodeStoreEvents[events.PermissionPromptShown](t, store, events.KindPermissionPromptShown); len(prompts) != 1 {
		t.Fatalf("persisted %d permission_prompt_shown events, want 1", len(prompts))
	}
	decisions := decodeStoreEvents[events.PermissionDecision](t, store, events.KindPermissionDecision)
	if len(decisions) != 1 {
		t.Fatalf("persisted %d permission_decision events, want 1", len(decisions))
	}
	if got, _, ok := permissions.DecodeDirectRequestSubject(decisions[0].GrantSubject, wantCommand); !ok || !slices.Equal(got, []string{"FOO=bar"}) {
		t.Fatalf("stored grant subject %q does not carry the request's assignments", decisions[0].GrantSubject)
	}

	matched := decodeStoreEvents[events.PermissionMatched](t, store, events.KindPermissionMatched)
	var direct []events.PermissionMatched
	for _, m := range matched {
		if m.SubjectKind == "direct" {
			direct = append(direct, m)
		}
	}
	if len(direct) != 1 {
		t.Fatalf("persisted %d direct permission_matched events, want 1: %+v", len(direct), direct)
	}
	if direct[0].Subject != "cat my notes.txt" || direct[0].DirectRequestSubject != wantRequest {
		t.Fatalf("permission_matched = %#v, want subject %q and request identity %q",
			direct[0], "cat my notes.txt", wantRequest)
	}
	if direct[0].OutcomeSource != "grant" || direct[0].Outcome != "session_grant" {
		t.Fatalf("permission_matched = %#v, want the repeat resolved through the stored session grant", direct[0])
	}
}

func TestRunHeadless_PromptPersistsDirectEnvIdentity(t *testing.T) {
	dir := t.TempDir()
	notes := filepath.Join(dir, "my notes.txt")
	if err := os.WriteFile(notes, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client := toolThenContentClient(nil, "bash", "{\"command\":\"FOO=bar rm \\\"my notes.txt\\\"\"}", "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	driver := NewHeadlessDriver("delete my notes", &bytes.Buffer{}, &bytes.Buffer{})
	driver.EnablePromptForApproval(strings.NewReader("1\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	wantCommand := permissions.ExactSubject("rm", []string{"my notes.txt"})
	wantRequest, err := permissions.DirectRequestSubject([]string{"rm", "my notes.txt"}, []string{"FOO=bar"}, false)
	if err != nil {
		t.Fatalf("DirectRequestSubject: %v", err)
	}

	store := reloadStore(t, result.Session)
	prompts := decodeStoreEvents[events.PermissionPromptShown](t, store, events.KindPermissionPromptShown)
	if len(prompts) != 1 {
		t.Fatalf("persisted %d permission_prompt_shown events, want 1", len(prompts))
	}
	if prompts[0].Subject != "rm my notes.txt" || prompts[0].DirectTokens == nil {
		t.Fatalf("persisted prompt = %#v, want the joined direct subject and its tokens", prompts[0])
	}
	if prompts[0].DirectCommandSubject != wantCommand || prompts[0].DirectRequestSubject != wantRequest {
		t.Fatalf("prompt identities = %q/%q, want %q/%q",
			prompts[0].DirectCommandSubject, prompts[0].DirectRequestSubject, wantCommand, wantRequest)
	}

	decisions := decodeStoreEvents[events.PermissionDecision](t, store, events.KindPermissionDecision)
	if len(decisions) != 1 {
		t.Fatalf("persisted %d permission_decision events, want 1", len(decisions))
	}
	if decisions[0].DirectCommandSubject != wantCommand || decisions[0].DirectRequestSubject != wantRequest {
		t.Fatalf("decision identities = %q/%q, want %q/%q",
			decisions[0].DirectCommandSubject, decisions[0].DirectRequestSubject, wantCommand, wantRequest)
	}
}

// --- step 2b: the headless trust posture ---

// TestRunHeadless_ApprovalPromptingNeverTrustsTheProject drives one real RunHeadless launch —
// the production headless gate and composer, an approval-armed driver — against a covered
// project no record answers for. Arming approval is a per-call escalation inside the run, so it
// may not stand in for the trust decision the user never made.
func TestRunHeadless_ApprovalPromptingNeverTrustsTheProject(t *testing.T) {
	home := t.TempDir()
	projectRoot := trustProject(t, `agent:
  max_concurrency: 7
permissions:
  - kind: direct
    subject: rm
    path_scope: /
    grant_kind: folder
`)

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	global := headlessProviderConfig()
	global["agent"] = map[string]any{"max_concurrency": 2}
	session := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000d1", projectRoot)

	var order []string
	var stdout, stderr bytes.Buffer
	var composed map[string]any
	var layerPaths []string

	hermetic := recordingSteps(&order)
	steps := HeadlessFreshSteps(&stderr, nil, "")
	steps.ResolveHome = func() (string, error) { return home, nil }
	steps.RunFirstRun = hermetic.RunFirstRun
	steps.LoadGlobalSettings = func(string) (map[string]any, error) { return global, nil }
	steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) {
		return projectRoot, []string{projectSettingsPath(projectRoot)}, nil
	}
	steps.LoadVCSTemplates = hermetic.LoadVCSTemplates
	steps.ValidatePreferredVCS = hermetic.ValidatePreferredVCS
	steps.DetectVCS = hermetic.DetectVCS
	steps.BuildToolRegistry = func(any) (any, error) { return &toolRegistryFactory{active: nil}, nil }
	steps.DetermineModel = func(c, _ map[string]any, _ string, paths []string) (any, bool, error) {
		composed, layerPaths = c, paths
		return model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject), false, nil
	}
	steps.EnsureFreshSession = func(string, string) (*sessions.Store, error) { return session, nil }
	steps.AcquireLock = hermetic.AcquireLock
	steps.AppendLaunchBegan = hermetic.AppendLaunchBegan
	steps.InitMode = func(context.Context, *sessions.Store, map[string]any, string, []string) (any, error) {
		return mode.NewActiveState(mode.Build, mode.SourceDefault), nil
	}
	steps.LoadAgentInstructions = hermetic.LoadAgentInstructions

	driver := NewHeadlessDriver("anything", &stdout, &stderr)
	driver.EnablePromptForApproval(strings.NewReader("1\n"))
	if !driver.PromptForApprovalEnabled() {
		t.Fatal("EnablePromptForApproval did not arm the driver")
	}

	if _, err := RunHeadless(context.Background(), projectRoot, steps, driver); err != nil {
		t.Fatalf("RunHeadless: %v", err)
	}

	if want := []string{SettingsPath(home)}; !slices.Equal(layerPaths, want) {
		t.Fatalf("config layer paths = %v, want %v (the project layer withheld)", layerPaths, want)
	}
	agent, _ := composed["agent"].(map[string]any)
	if fmt.Sprint(agent["max_concurrency"]) != "2" {
		t.Fatalf("composed agent = %#v, want the global value with no project override", composed["agent"])
	}
	if _, ok := composed["permissions"]; ok {
		t.Fatalf("composed config = %#v, want no project permission entry in the effective set", composed)
	}
	if strings.Contains(stderr.String(), approvePrompt) {
		t.Fatalf("stderr = %q, want no approval prompt on a headless run", stderr.String())
	}
	if countNotices(stderr.String()) != 1 {
		t.Fatalf("stderr = %q, want exactly one ignored-settings notice", stderr.String())
	}
	trustStoreAbsent(t, home)
}

func TestHeadlessFreshSteps_EmptyCoverageIsNonDegradedAndSilent(t *testing.T) {
	var stderr bytes.Buffer
	home, launchDir := t.TempDir(), t.TempDir()
	decision := HeadlessFreshSteps(&stderr, nil, "").GateTrust(home, launchDir, launchDir)
	if !decision.Trusted || decision.Reason != trust.ReasonNothingCovered {
		t.Fatalf("decision = %#v, want a project with nothing covered trusted by vacuity", decision)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want no ignored-settings notice when nothing is withheld", stderr.String())
	}
	trustStoreAbsent(t, home)
}

// TestHeadlessFreshSteps_RecoverJournals_NeverAsksAndNeverBlocks pins the never-block rule on a
// run with nobody watching: even with a terminal on stdin, the headless step-2.6 offers no answers,
// leaves the changed path alone, says how to resolve it, and lets the launch reach its last step.
func TestHeadlessFreshSteps_RecoverJournals_NeverAsksAndNeverBlocks(t *testing.T) {
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	prevStdin, prevIsTerminal := os.Stdin, stdinIsTerminal
	os.Stdin, stdinIsTerminal = devnull, func(io.Reader) bool { return true }
	t.Cleanup(func() {
		os.Stdin, stdinIsTerminal = prevStdin, prevIsTerminal
		_ = devnull.Close()
	})

	home, project := realPath(t, t.TempDir()), realPath(t, t.TempDir())
	target := filepath.Join(project, "a.txt")
	if err := os.WriteFile(target, []byte("ORIGINAL\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	writeGlobalSettings(t, home, blockedYAML(), 0o600)
	journal := killedChildJournal(t, home, project, target)
	if err := os.WriteFile(target, []byte("A HAND EDIT\n"), 0o644); err != nil {
		t.Fatalf("hand edit: %v", err)
	}

	var stderr bytes.Buffer
	var order []string
	steps := recordingSteps(&order)
	steps.ResolveHome = func() (string, error) { return home, nil }
	steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) { return project, nil, nil }
	steps.RecoverJournals = HeadlessFreshSteps(&stderr, nil, "").RecoverJournals

	res, _, err := runFreshCore(context.Background(), project, steps)

	if err != nil || res == nil {
		t.Fatalf("runFreshCore = (%v, %v), want the headless launch to complete", res, err)
	}
	if !slices.Contains(order, "7c:LoadAgentInstructions") {
		t.Fatalf("order = %v, want the launch to reach its last step", order)
	}
	if strings.Contains(stderr.String(), "Keep, put back, or decide later?") {
		t.Fatalf("stderr = %q, want no prompt on a run with nobody to answer it", stderr.String())
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "A HAND EDIT\n" {
		t.Fatalf("%s = %q (err=%v), want a deferred path left alone", target, got, err)
	}
	if _, err := os.Stat(journal); err != nil {
		t.Fatalf("stat %s: %v, want the journal retained for a launch that can ask", journal, err)
	}
	if !strings.Contains(stderr.String(), "not put back: \""+target) ||
		!strings.Contains(stderr.String(), "the next time you start it here") {
		t.Fatalf("stderr = %q, want the file named and the next step stated", stderr.String())
	}
}

func TestRunHeadless_ProjectSettingsFollowTheApprovalList(t *testing.T) {
	for _, tc := range []struct {
		name           string
		listed         bool
		editAfter      bool
		wantLayer      bool
		wantConcurrent string
		wantNotices    int
	}{
		{name: "unlisted root withholds the layer", wantConcurrent: "2", wantNotices: 1},
		{name: "listed root composes the layer", listed: true, wantLayer: true, wantConcurrent: "7"},
		{name: "listed root composes a changed layer", listed: true, editAfter: true, wantLayer: true, wantConcurrent: "9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			project := trustProject(t, "agent:\n  max_concurrency: 7\n")
			var before string
			if tc.listed {
				approveRoot(t, home, project)
				before = readTrustStoreBytes(t, home)
			}
			if tc.editAfter {
				writeProjectSettings(t, project, "agent:\n  max_concurrency: 9\n")
			}

			var stderr bytes.Buffer
			production := HeadlessFreshSteps(&stderr, nil, "")
			var order []string
			steps := recordingSteps(&order)
			steps.ResolveHome = func() (string, error) { return home, nil }
			steps.LoadGlobalSettings = func(string) (map[string]any, error) {
				return map[string]any{"agent": map[string]any{"max_concurrency": 2}}, nil
			}
			steps.ResolveProjectRoot = func(string, map[string]any) (string, []string, error) {
				return project, []string{projectSettingsPath(project)}, nil
			}
			steps.GateTrust = production.GateTrust
			steps.ComposeConfig = defaultComposeConfig

			res, _, err := runFreshCore(context.Background(), project, steps)
			if err != nil {
				t.Fatalf("runFreshCore: %v", err)
			}
			want := []string{SettingsPath(home)}
			if tc.wantLayer {
				want = append(want, projectSettingsPath(project))
			}
			if !slices.Equal(res.ConfigLayerPaths, want) {
				t.Fatalf("ConfigLayerPaths = %v, want %v", res.ConfigLayerPaths, want)
			}
			agent, _ := res.Config["agent"].(map[string]any)
			if fmt.Sprint(agent["max_concurrency"]) != tc.wantConcurrent {
				t.Fatalf("agent.max_concurrency = %v, want %s", agent["max_concurrency"], tc.wantConcurrent)
			}
			if countNotices(stderr.String()) != tc.wantNotices {
				t.Fatalf("stderr = %q, want %d ignored-settings notices", stderr.String(), tc.wantNotices)
			}
			if !tc.listed {
				trustStoreAbsent(t, home)
				return
			}
			if after := readTrustStoreBytes(t, home); after != before {
				t.Fatalf("store = %q, want it unchanged by a headless run", after)
			}
		})
	}
}

// twoExternalReadClient issues both external reads in one assembled response, then finishes, so the
// headless run sees the shape the interactive path would batch.
func twoExternalReadClient(first, second string) *stubTurnClient {
	var round int32
	return &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(
				toolFrag(0, "call_a", filetools.ReadToolName, fmt.Sprintf(`{"path":%q}`, first)),
				toolFrag(1, "call_b", filetools.ReadToolName, fmt.Sprintf(`{"path":%q}`, second)),
			))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	}}
}

func headlessExternalReads(t *testing.T) (project, first, second string) {
	t.Helper()
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	// Separate directories: allow-once is remembered for an identical repeat, so two reads under
	// one scope would collapse into a single authorization and prove nothing about per-call
	// prompting.
	firstDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	secondDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	first, second = filepath.Join(firstDir, "a.txt"), filepath.Join(secondDir, "b.txt")
	if err := os.WriteFile(first, []byte("OUTSIDE A\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(second, []byte("OUTSIDE B\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return project, first, second
}

func TestRunHeadless_ExplicitExternalReadsOpenWithoutApproval(t *testing.T) {
	project, first, second := headlessExternalReads(t)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return twoExternalReadClient(first, second) })()

	var stderr bytes.Buffer
	driver := NewHeadlessDriver("read both", &bytes.Buffer{}, &stderr)
	result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if denied := driver.DeniedSubjects(); len(denied) != 0 {
		t.Fatalf("DeniedSubjects = %+v, want none", denied)
	}
	if strings.Contains(stderr.String(), "approval required") {
		t.Fatalf("a run without --prompt-for-approval asked for approval:\n%s", stderr.String())
	}
	reloaded := reloadStore(t, result.Session)
	toolMsgs := messagesByRole(reloaded, "tool")
	if len(toolMsgs) != 2 {
		t.Fatalf("tool messages = %d, want both reads answered", len(toolMsgs))
	}
	for i, want := range []string{"OUTSIDE A", "OUTSIDE B"} {
		if got := toolMsgs[i].Content.Text(); !strings.Contains(got, want) {
			t.Fatalf("tool message %d = %q, want the outside file's content %q", i, got, want)
		}
	}
	var openReads []string
	for _, m := range decodePermissionMatched(t, reloaded) {
		if m.OutcomeSource != "open_read" {
			continue
		}
		if m.SubjectKind != "tool" || m.Subject != filetools.ReadToolName || m.Outcome != "once" || m.GrantKind != "" || m.GrantPathScope != "" {
			t.Fatalf("open_read record = %#v, want a read allowed once with no grant", m)
		}
		openReads = append(openReads, m.PathScope)
	}
	if want := []string{filepath.Dir(first), filepath.Dir(second)}; !slices.Equal(openReads, want) {
		t.Fatalf("open_read scopes = %v, want %v", openReads, want)
	}
}

func TestRunHeadless_PromptApprovalDoesNotAskForExplicitExternalReads(t *testing.T) {
	project, first, second := headlessExternalReads(t)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return twoExternalReadClient(first, second) })()

	var stderr bytes.Buffer
	driver := NewHeadlessDriver("read both", &bytes.Buffer{}, &stderr)
	driver.EnablePromptForApproval(strings.NewReader("1\n1\n"))
	result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := driver.DeniedSubjects(); len(got) != 0 {
		t.Fatalf("DeniedSubjects = %+v, want none", got)
	}
	if n := strings.Count(stderr.String(), "approval required"); n != 0 {
		t.Fatalf("terminal prompts = %d, want 0:\n%s", n, stderr.String())
	}
	toolMsgs := messagesByRole(reloadStore(t, result.Session), "tool")
	if len(toolMsgs) != 2 {
		t.Fatalf("tool messages = %d, want both reads answered", len(toolMsgs))
	}
	for i, want := range []string{"OUTSIDE A", "OUTSIDE B"} {
		if got := toolMsgs[i].Content.Text(); !strings.Contains(got, want) {
			t.Fatalf("tool message %d = %q, want the approved read's own content %q", i, got, want)
		}
	}
}

// --- delegate (child agent) --------------------------------------------------

func generalAgentCall(id, instructions string, files ...string) []byte {
	args, err := json.Marshal(map[string]any{"instructions": instructions, "files": files})
	if err != nil {
		panic(err)
	}
	return toolCallsChunk(toolFrag(0, id, "general_agent", string(args)))
}

// lastToolText lets a scripted parent answer from what its child actually returned, so the
// assertion proves the child's result reached the parent's context.
func lastToolText(req provider.Request) string {
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "tool" {
			return req.Messages[i].Content
		}
	}
	return "(no tool result)"
}

// generalAgentScript scripts each provider round in order and keeps every request. One client
// serves parent and child alike because both resolve theirs through buildTurnClient.
type generalAgentScript struct {
	client   *stubTurnClient
	mu       sync.Mutex
	requests []provider.Request
}

func newGeneralAgentScript(rounds ...func(provider.Request) []byte) *generalAgentScript {
	s := &generalAgentScript{}
	s.client = &stubTurnClient{title: streamedTitle("Model title"), fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		s.mu.Lock()
		s.requests = append(s.requests, req)
		i := len(s.requests) - 1
		s.mu.Unlock()
		if i < len(rounds) {
			return provider.Response{Stream: newStream(rounds[i](req))}, nil
		}
		return provider.Response{}, fmt.Errorf("unscripted provider round %d", i+1)
	}}
	return s
}

func (s *generalAgentScript) install() func() {
	return swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return s.client })
}

func (s *generalAgentScript) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func (s *generalAgentScript) round(t *testing.T, i int) provider.Request {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if i >= len(s.requests) {
		t.Fatalf("provider round %d never ran; %d rounds issued", i+1, len(s.requests))
	}
	return s.requests[i]
}

func finalReply(text string) func(provider.Request) []byte {
	return func(provider.Request) []byte { return contentChunk(text) }
}

// TestRunHeadless_GeneralAgentChildResultReachesTheParentReply drives a real child end to end
// with no double at the subagent.Run seam: the parent answers with a fact that exists only in
// the child's result, the instruction survives byte-identical because no shell is in the
// path, and the child sees only its pinned tools.
func TestRunHeadless_GeneralAgentChildResultReachesTheParentReply(t *testing.T) {
	dir := declaredScopeDir(t)
	instruction := "report the build id: `id` $(whoami) \"quoted\"\nsecond line"
	script := newGeneralAgentScript(
		func(provider.Request) []byte { return generalAgentCall("call_1", instruction, "report.txt") },
		finalReply("the build id is BUILDID-7788"),
		func(req provider.Request) []byte { return contentChunk(lastToolText(req)) },
	)
	defer script.install()()

	var stdout bytes.Buffer
	driver := NewHeadlessDriver("hand this off", &stdout, &bytes.Buffer{})
	driver.EnablePromptForApproval(strings.NewReader("1\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if !strings.Contains(stdout.String(), "BUILDID-7788") {
		t.Fatalf("stdout = %q, want the fact only the child produced", stdout.String())
	}
	if got := script.count(); got != 3 {
		t.Fatalf("provider rounds = %d, want 3 (parent, child, parent)", got)
	}

	child := script.round(t, 1)
	if len(child.Messages) != 2 || child.Messages[1].Role != "user" {
		t.Fatalf("child's first round = %+v, want a system prompt and one user message", child.Messages)
	}
	if child.Messages[1].Content != instruction+subagent.InstructionSuffix {
		t.Fatalf("child instruction = %q, want the tool argument byte for byte %q followed by the fixed suffix", child.Messages[1].Content, instruction)
	}
	if child.Messages[0].Content != script.round(t, 0).Messages[0].Content {
		t.Fatalf("child system prompt differs from the parent's assembled prompt:\n%s", child.Messages[0].Content)
	}
	got := toolNames(child.Tools)
	slices.Sort(got)
	want := []string{"create", "delete", "edit", "file_count", "general_agent", "glob", "grep", "list", "mkdir",
		"move", "read", "read_image", "tree"}
	if !slices.Equal(got, want) {
		t.Fatalf("child tools = %v, want exactly the pinned set %v", got, want)
	}
	assertOnlyLaunchPromptFor(t, result, "create", filepath.Join(dir, "report.txt"))
}

func assertOnlyLaunchPromptFor(t *testing.T, result *BootstrapResult, subject, target string) {
	t.Helper()
	prompts := decodeStoreEvents[events.PermissionPromptShown](t, reloadStore(t, result.Session), events.KindPermissionPromptShown)
	if len(prompts) != 1 || prompts[0].Subject != subject || prompts[0].PathScope != filepath.Dir(target) || prompts[0].ChildInvocationID != "" {
		t.Fatalf("permission prompts = %+v, want only the parent's %s prompt for %s", prompts, subject, target)
	}
}

// TestRunHeadless_GeneralAgentChildReadOnlyVCSFactReachesTheParentReply is the terminal proof that
// the production registry, delegate tool, child dispatcher, and shared VCS dispatch path are
// connected: with no double at the subagent.Run seam, the parent answers with a fact only the
// child's read-only VCS action produced, while the mutating action of the same template is
// refused before it can run and no second approval is asked of anyone.
func TestRunHeadless_GeneralAgentChildReadOnlyVCSFactReachesTheParentReply(t *testing.T) {
	const fact = "CHILD-VCS-FACT-4711"
	dir := declaredScopeDir(t)
	script := newGeneralAgentScript(
		func(provider.Request) []byte { return generalAgentCall("call_1", "report the status", "report.txt") },
		func(provider.Request) []byte {
			return toolCallsChunk(toolFrag(0, "child_1", "vcs_commit", `{"message":"take the repo"}`))
		},
		func(provider.Request) []byte { return toolCallsChunk(toolFrag(0, "child_2", "vcs_status", `{}`)) },
		func(req provider.Request) []byte { return contentChunk(lastToolText(req)) },
		func(req provider.Request) []byte { return contentChunk(lastToolText(req)) },
	)
	defer script.install()()

	var stdout bytes.Buffer
	driver := NewHeadlessDriver("hand this off", &stdout, &bytes.Buffer{})
	driver.EnablePromptForApproval(strings.NewReader("1\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	stubVCSActionRunner(t, fact)
	result.ToolRegistry = &toolRegistryFactory{
		active: &ActiveVCS{Template: productVettedGitTemplate(t), RepoRoot: dir},
	}
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if !strings.Contains(stdout.String(), fact) {
		t.Fatalf("stdout = %q, want the fact only the child's VCS action produced", stdout.String())
	}
	if got := script.count(); got != 5 {
		t.Fatalf("provider rounds = %d, want 5 (parent, refused mutation, read-only action, child reply, parent)", got)
	}

	got := toolNames(script.round(t, 1).Tools)
	slices.Sort(got)
	want := []string{"create", "delete", "edit", "file_count", "general_agent", "glob", "grep", "list", "mkdir",
		"move", "read", "read_image", "tree", "vcs_diff", "vcs_status"}
	if !slices.Equal(got, want) {
		t.Fatalf("child tools = %v, want exactly the pinned set plus the read-only VCS actions %v", got, want)
	}
	if refusal := lastToolText(script.round(t, 2)); !strings.Contains(refusal, "not available to a child agent") {
		t.Fatalf("child's vcs_commit result = %q, want an in-band refusal", refusal)
	}

	reloaded := reloadStore(t, result.Session)
	var executed []string
	for _, e := range decodeStoreEvents[events.ToolExecStart](t, reloaded, events.KindToolExecStart) {
		executed = append(executed, e.Subject)
	}
	if !slices.Equal(executed, []string{"vcs_status"}) {
		t.Fatalf("executed VCS actions = %v, want only the read-only one", executed)
	}
	var autoAllowed []events.PermissionMatched
	for _, m := range decodePermissionMatched(t, reloaded) {
		if m.OutcomeSource == "mode_auto" {
			autoAllowed = append(autoAllowed, m)
		}
	}
	if len(autoAllowed) != 1 || autoAllowed[0].Subject != "vcs_status" || autoAllowed[0].PathScope != dir {
		t.Fatalf("mode_auto decisions = %+v, want one for vcs_status scoped to the repo root %s", autoAllowed, dir)
	}
	assertOnlyLaunchPromptFor(t, result, "create", filepath.Join(dir, "report.txt"))
}

// TestRunHeadless_GeneralAgentIsNotAdvertisedOrAutoApprovedWithoutApproval covers the parent-side
// authorization contract: Plan advertises delegate beside only read-only tools, Build with no approver denies the declared
// operation before any child starts, and Auto edits approves an in-project declared operation.
func TestRunHeadless_GeneralAgentIsNotAdvertisedOrAutoApprovedWithoutApproval(t *testing.T) {
	t.Run("plan advertises it as the only mutating tool", func(t *testing.T) {
		dir := declaredScopeDir(t)
		script := newGeneralAgentScript(finalReply("planned"))
		defer script.install()()

		driver := NewHeadlessDriver("plan it", &bytes.Buffer{}, &bytes.Buffer{})
		result := headlessResult(t, dir, mode.NewActiveState(mode.Plan, mode.SourceDefault))
		if err := driver.Run(context.Background(), result); err != nil {
			t.Fatalf("driver.Run: %v", err)
		}
		names := toolNames(script.round(t, 0).Tools)
		if !slices.Contains(names, "general_agent") {
			t.Fatalf("Plan advertised %v, want general_agent offered for its read-only form", names)
		}
		for _, mutating := range []string{"edit", "create", "delete", "mkdir", "move"} {
			if slices.Contains(names, mutating) {
				t.Fatalf("Plan advertised %v, want %s filtered out", names, mutating)
			}
		}
	})

	t.Run("build denies the declared operation without an approver", func(t *testing.T) {
		dir := declaredScopeDir(t)
		script := newGeneralAgentScript(
			func(provider.Request) []byte { return generalAgentCall("call_1", "do it", "report.txt") },
			finalReply("cannot delegate"),
		)
		defer script.install()()

		driver := NewHeadlessDriver("hand this off", &bytes.Buffer{}, &bytes.Buffer{})
		result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
		if err := driver.Run(context.Background(), result); err != nil {
			t.Fatalf("driver.Run: %v", err)
		}
		if got := script.count(); got != 2 {
			t.Fatalf("provider rounds = %d, want 2 — the denial must start no child", got)
		}
		if names := toolNames(script.round(t, 0).Tools); !slices.Contains(names, "general_agent") {
			t.Fatalf("Build advertised %v, want general_agent offered so the denial is an authorization decision", names)
		}
		text := declaredDenyText(t, result)
		if !strings.Contains(text, `"denied_by":"unattended"`) {
			t.Fatalf("tool result = %s, want an unattended denial", text)
		}
		if got := driver.DeniedSubjects(); len(got) != 1 || got[0].Subject != filepath.Join(dir, "report.txt") {
			t.Fatalf("DeniedSubjects = %+v, want one entry for the declared create, never delegate", got)
		}
	})

	t.Run("auto edits approves an in-project declared operation", func(t *testing.T) {
		dir := declaredScopeDir(t)
		script := newGeneralAgentScript(
			func(provider.Request) []byte { return generalAgentCall("call_1", "do it", "report.txt") },
			finalReply("child done"),
			func(req provider.Request) []byte { return contentChunk(lastToolText(req)) },
		)
		defer script.install()()

		driver := NewHeadlessDriver("hand this off", &bytes.Buffer{}, &bytes.Buffer{})
		result := headlessResult(t, dir, mode.NewActiveState(mode.AutoEdits, mode.SourceDefault))
		if err := driver.Run(context.Background(), result); err != nil {
			t.Fatalf("driver.Run: %v", err)
		}
		if got := script.count(); got != 3 {
			t.Fatalf("provider rounds = %d, want 3 (parent, child, parent)", got)
		}
		if got := driver.DeniedSubjects(); len(got) != 0 {
			t.Fatalf("DeniedSubjects = %+v, want none", got)
		}
		var launch []events.PermissionMatched
		for _, m := range decodePermissionMatched(t, reloadStore(t, result.Session)) {
			if m.Subject == "general_agent" {
				t.Fatalf("event %+v decided the tool general_agent, want only its declared operations", m)
			}
			if m.ChildInvocationID == "" {
				launch = append(launch, m)
			}
		}
		if len(launch) != 1 || launch[0].Subject != "create" || launch[0].OutcomeSource != "mode_auto" || launch[0].Outcome != "once" {
			t.Fatalf("launch decisions = %+v, want one mode_auto once for the declared create", launch)
		}
	})
}

// TestRunHeadless_GeneralAgentChildWritesOnlyItsDeclaredFiles proves the declared-scope ceiling
// reaches the child: the declared path is written through the shared dispatch/permission
// route, and the undeclared write is refused. The child has no approver, so that refusal is
// recoverable — it adapts and finishes rather than dying, and its declared write stands.
func TestRunHeadless_GeneralAgentChildWritesOnlyItsDeclaredFiles(t *testing.T) {
	dir := declaredScopeDir(t)
	script := newGeneralAgentScript(
		func(provider.Request) []byte { return generalAgentCall("call_1", "write the report", "allowed.txt") },
		func(provider.Request) []byte {
			return toolCallsChunk(toolFrag(0, "child_1", "create", `{"path":"allowed.txt","content":"written\n"}`))
		},
		func(provider.Request) []byte {
			return toolCallsChunk(toolFrag(0, "child_2", "create", `{"path":"undeclared.txt","content":"sneak\n"}`))
		},
		finalReply("wrote allowed.txt only"),
		func(req provider.Request) []byte { return contentChunk(lastToolText(req)) },
	)
	defer script.install()()

	var stdout bytes.Buffer
	driver := NewHeadlessDriver("hand this off", &stdout, &bytes.Buffer{})
	driver.EnablePromptForApproval(strings.NewReader("1\n"))
	result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := mustReadFile(t, filepath.Join(dir, "allowed.txt")); got != "written\n" {
		t.Fatalf("allowed.txt = %q, want the child's declared write to stand", got)
	}
	mustNotExist(t, filepath.Join(dir, "undeclared.txt"), "an undeclared child write must not land")
	if got := script.count(); got != 5 {
		t.Fatalf("provider rounds = %d, want 5 (parent, three child rounds, parent) — the child recovers from its ceiling refusal", got)
	}
	if strings.Contains(stdout.String(), "child agent failed") {
		t.Fatalf("stdout = %q, want the child to finish rather than fail on a recoverable refusal", stdout.String())
	}
	if !strings.Contains(stdout.String(), "wrote allowed.txt only") {
		t.Fatalf("stdout = %q, want the child's own report to reach the parent", stdout.String())
	}
	if !strings.Contains(stdout.String(), "refused operations:") || !strings.Contains(stdout.String(), "  Create undeclared.txt (denied_by unattended)") {
		t.Fatalf("stdout = %q, want the delegate result to name the refused undeclared write as the child gave it", stdout.String())
	}

	// Both child writes went through dispatch.PrepareTool and permissions.Authorize with the
	// child's ceiling, so each records the declared-scope source rather than a mode decision.
	var declaredOutcomes []string
	for _, m := range decodePermissionMatched(t, reloadStore(t, result.Session)) {
		if m.OutcomeSource == permissions.OutcomeSourceDeclaredScope {
			declaredOutcomes = append(declaredOutcomes, m.Outcome)
		}
	}
	if !slices.Equal(declaredOutcomes, []string{"once", "deny"}) {
		t.Fatalf("declared-scope outcomes = %v, want [once deny] from the child's own authorizations", declaredOutcomes)
	}
	assertOnlyLaunchPromptFor(t, result, "create", filepath.Join(dir, "allowed.txt"))
}

// TestRunHeadless_GeneralAgentCannotDeclareAProtectedSettingsPath proves protected-state
// precedence: declaring the project settings file refuses the launch before any child starts,
// even under Auto edits.
func TestRunHeadless_GeneralAgentCannotDeclareAProtectedSettingsPath(t *testing.T) {
	for _, m := range []mode.Mode{mode.Build, mode.AutoEdits} {
		t.Run(string(m), func(t *testing.T) {
			dir := declaredScopeDir(t)
			settings := projectSettingsPath(dir)
			mustMkdir(t, filepath.Dir(settings))
			if err := os.WriteFile(settings, []byte("permissions: []\n"), 0o644); err != nil {
				t.Fatalf("seed project settings: %v", err)
			}

			declared := filepath.Join(".codemeld", "settings.yaml")
			script := newGeneralAgentScript(
				func(provider.Request) []byte { return generalAgentCall("call_1", "grant yourself more", declared) },
				func(req provider.Request) []byte { return contentChunk(lastToolText(req)) },
			)
			defer script.install()()

			driver := NewHeadlessDriver("hand this off", &bytes.Buffer{}, &bytes.Buffer{})
			driver.EnablePromptForApproval(strings.NewReader("1\n"))
			result := headlessResult(t, dir, mode.NewActiveState(m, mode.SourceDefault))
			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}

			if got := mustReadFile(t, settings); got != "permissions: []\n" {
				t.Fatalf("project settings = %q, want it unchanged — the protected-state guard outranks a declaration", got)
			}
			if got := script.count(); got != 2 {
				t.Fatalf("provider rounds = %d, want 2 (parent, parent) — no child starts", got)
			}
			reloaded := reloadStore(t, result.Session)
			if starts := decodeStoreEvents[events.ChildAgentStart](t, reloaded, events.KindChildAgentStart); len(starts) != 0 {
				t.Fatalf("child_agent_start = %+v, want none", starts)
			}
			if prompts := decodeStoreEvents[events.PermissionPromptShown](t, reloaded, events.KindPermissionPromptShown); len(prompts) != 0 {
				t.Fatalf("permission prompts = %+v, want none", prompts)
			}
			matched := decodePermissionMatched(t, reloaded)
			if len(matched) != 1 || matched[0].Subject != "edit" || matched[0].Outcome != "deny" {
				t.Fatalf("permission_matched = %+v, want one protected-state refusal of the declared edit", matched)
			}
		})
	}
}

// TestRunHeadless_PromptApprovalCarriesBootstrapHomeToThePathScope proves the containment
// floor reaches the headless prompt through the production assembly: only HeadlessDriver.Run
// gives the prompter BootstrapResult.Home, and with none supplied the row is not offered
// rather than falling back to another home lookup.
func TestRunHeadless_PromptApprovalCarriesBootstrapHomeToThePathScope(t *testing.T) {
	run := func(t *testing.T, home func(string) string) (string, string) {
		t.Helper()
		dir := t.TempDir()
		nested := filepath.Join(dir, "nested")
		if err := os.MkdirAll(nested, 0o755); err != nil {
			t.Fatalf("mkdir nested: %v", err)
		}
		target := filepath.Join(nested, "tool.sh")
		if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o644); err != nil {
			t.Fatalf("seed target: %v", err)
		}

		client := toolThenContentClient(nil, "bash", fmt.Sprintf(`{"command":"chmod +x %s"}`, target), "ok")
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		var stderr bytes.Buffer
		driver := NewHeadlessDriver("mark it executable", &bytes.Buffer{}, &stderr)
		// Session lifetime, then scope choice 3 — the path row when it is offered.
		driver.EnablePromptForApproval(strings.NewReader("3\n3\n"))
		result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
		result.Home = home(result.Home)
		if err := driver.Run(context.Background(), result); err != nil {
			t.Fatalf("driver.Run: %v", err)
		}
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			t.Fatalf("resolve dir: %v", err)
		}
		return stderr.String(), resolved
	}

	spellings := []struct {
		name string
		home func(string) string
	}{
		{"canonical home", func(home string) string { return home }},
		{"dot-segment home", func(home string) string { return filepath.Join(home, "..", filepath.Base(home)) }},
		{"symlinked home", func(home string) string {
			link := filepath.Join(filepath.Dir(home), "home-link")
			if err := os.Symlink(home, link); err != nil {
				t.Fatalf("symlink home: %v", err)
			}
			return link
		}},
	}
	for _, c := range spellings {
		t.Run(c.name, func(t *testing.T) {
			out, dir := run(t, c.home)
			if !strings.Contains(out, "path: chmod +x :under="+dir+" ") {
				t.Fatalf("headless prompt did not offer the path row at %q:\n%s", dir, out)
			}
			if !strings.Contains(out, "The path choice is fixed at "+dir) {
				t.Fatalf("headless help does not name the fixed boundary %q:\n%s", dir, out)
			}
		})
	}

	t.Run("no home supplied", func(t *testing.T) {
		out, _ := run(t, func(string) string { return "" })
		if strings.Contains(out, ":under=") {
			t.Fatalf("headless prompt offered containment without a bootstrap home:\n%s", out)
		}
		if !strings.Contains(out, "codemeld: choose 1-4: ") {
			t.Fatalf("ladder changed shape without a bootstrap home:\n%s", out)
		}
	})
}

const timeLimitNotice = "codemeld: time limit 28m0s reached; the run ended with a final answer and no further tool use\n"

type timeLimitScript struct {
	mu       sync.Mutex
	requests []provider.Request
	rounds   []func(ctx context.Context) provider.Response
	client   *stubTurnClient
}

func (s *timeLimitScript) install(t *testing.T) {
	t.Helper()
	client := &stubTurnClient{title: streamedTitle("Model title"), fn: func(ctx context.Context, req provider.Request) (provider.Response, error) {
		s.mu.Lock()
		i := len(s.requests)
		s.requests = append(s.requests, req)
		s.mu.Unlock()
		if i >= len(s.rounds) {
			t.Errorf("unexpected provider request %d", i+1)
			return provider.Response{}, errors.New("unexpected request")
		}
		return s.rounds[i](ctx), nil
	}}
	s.client = client
	t.Cleanup(swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client }))
}

func timeLimitAnswer(text string) func(context.Context) provider.Response {
	return func(context.Context) provider.Response {
		return provider.Response{Stream: newStream(contentChunk(text), finishChunk("stop"))}
	}
}

func TestRunHeadless_TimeLimitElapsedBeforeFirstRoundEndsWithOneFinalAnswer(t *testing.T) {
	script := &timeLimitScript{rounds: []func(context.Context) provider.Response{timeLimitAnswer("what I know so far")}}
	script.install(t)
	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("survey the repo", &stdout, &stderr)
	driver.SetTimeLimit(time.Now().Add(-time.Second), 28*time.Minute)
	result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))

	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}
	if len(script.requests) != 1 || len(script.requests[0].Tools) != 0 {
		t.Fatalf("requests = %d (tools %d), want one tool-less final request", len(script.requests), len(script.requests[0].Tools))
	}
	if stdout.String() != "what I know so far\n" {
		t.Fatalf("stdout = %q, want only the final answer", stdout.String())
	}
	if stderr.String() != launchLabelLine+timeLimitNotice {
		t.Fatalf("stderr = %q, want the time-limit notice", stderr.String())
	}
	if n := script.client.titleCallCount(); n != 0 {
		t.Fatalf("title requests = %d, want 0 after a time-limit stop", n)
	}
	if asst := messagesByRole(reloadStore(t, result.Session), "assistant"); len(asst) != 1 || asst[0].Content.Text() != "what I know so far" {
		t.Fatalf("durable assistant messages = %+v, want the final answer", asst)
	}
}

func TestRunHeadless_TimeLimitDuringStreamPrintsOnlyTheFinalAnswer(t *testing.T) {
	for _, tc := range []struct{ name, partial string }{
		{"ordinary prose", "Half an answer"},
		{"held text tool call", `{"name":"grep"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var loop *turn.ToolLoop
			t.Cleanup(swapToolLoop(func(deps turn.Deps, d turn.ToolDispatcher, n int) *turn.ToolLoop {
				loop = turn.NewToolLoop(deps, d, n)
				return loop
			}))
			script := &timeLimitScript{rounds: []func(context.Context) provider.Response{
				func(ctx context.Context) provider.Response {
					ready := make(chan struct{})
					go func() {
						<-ready
						loop.Expire()
					}()
					return provider.Response{Stream: blockingStream(ctx, contentChunk(tc.partial), ready)}
				},
				timeLimitAnswer("final answer"),
			}}
			script.install(t)
			var stdout, stderr bytes.Buffer
			driver := NewHeadlessDriver("survey the repo", &stdout, &stderr)
			driver.SetTimeLimit(time.Now().Add(time.Hour), 28*time.Minute)
			result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))

			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}
			if len(script.requests) != 2 || len(script.requests[0].Tools) == 0 || len(script.requests[1].Tools) != 0 {
				t.Fatalf("requests = %d, want a tool round then one tool-less final request", len(script.requests))
			}
			if stdout.String() != "final answer\n" {
				t.Fatalf("stdout = %q, want only the final answer", stdout.String())
			}
			if stderr.String() != launchLabelLine+timeLimitNotice {
				t.Fatalf("stderr = %q, want only the time-limit notice", stderr.String())
			}
			if n := script.client.titleCallCount(); n != 0 {
				t.Fatalf("title requests = %d, want 0 after a time-limit stop", n)
			}
		})
	}
}

type expiringDispatcher struct {
	turn.ToolDispatcher
	expire func()
}

func (d expiringDispatcher) Plan(calls []turn.AssembledToolCall, n int) turn.ToolPlan {
	plan := d.ToolDispatcher.Plan(calls, n)
	for i := range plan.Units {
		plan.Units[i].PreRun = nil
		plan.Units[i].Run = func(ctx context.Context) (turn.ToolResult, error) {
			d.expire()
			<-ctx.Done()
			return turn.ToolResult{}, ctx.Err()
		}
	}
	return plan
}

func TestRunHeadless_TimeLimitDuringDispatchDiscardsTheToolRoundPreamble(t *testing.T) {
	var loop *turn.ToolLoop
	t.Cleanup(swapToolLoop(func(deps turn.Deps, d turn.ToolDispatcher, n int) *turn.ToolLoop {
		loop = turn.NewToolLoop(deps, expiringDispatcher{ToolDispatcher: d, expire: func() { loop.Expire() }}, n)
		return loop
	}))
	script := &timeLimitScript{rounds: []func(context.Context) provider.Response{
		func(context.Context) provider.Response {
			return provider.Response{Stream: newStream(
				contentChunk("Let me read main.go first."),
				toolCallsChunk(toolFrag(0, "call_1", filetools.ReadToolName, `{"path":"main.go"}`)),
			)}
		},
		timeLimitAnswer("final answer"),
	}}
	script.install(t)
	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("survey the repo", &stdout, &stderr)
	driver.SetTimeLimit(time.Now().Add(time.Hour), 28*time.Minute)
	result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))

	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}
	if len(script.requests) != 2 || len(script.requests[0].Tools) == 0 || len(script.requests[1].Tools) != 0 {
		t.Fatalf("requests = %d, want a tool round then one tool-less final request", len(script.requests))
	}
	if stdout.String() != "final answer\n" {
		t.Fatalf("stdout = %q, want only the final answer", stdout.String())
	}
	errOut := stderr.String()
	if !strings.HasSuffix(errOut, timeLimitNotice) || !strings.Contains(strings.TrimSuffix(errOut, timeLimitNotice), "main.go") {
		t.Fatalf("stderr = %q, want the tool activity line then the time-limit notice", errOut)
	}
	if strings.Contains(errOut, "Let me read main.go first.") {
		t.Fatalf("stderr = %q, want the discarded tool-round preamble absent", errOut)
	}
	if n := script.client.titleCallCount(); n != 0 {
		t.Fatalf("title requests = %d, want 0 after a time-limit stop", n)
	}
	tools := messagesByRole(reloadStore(t, result.Session), "tool")
	if len(tools) != 1 || !strings.HasPrefix(tools[0].Content.Text(), "tool call cancelled: the run's time limit") {
		t.Fatalf("durable tool results = %+v, want the synthetic cancelled result", tools)
	}
}

func TestRunHeadless_TurnLimitEndsWithOneNoticeAndTheFinalAnswer(t *testing.T) {
	const removed = "; tools were removed and the model is writing its final answer. Send a new message to continue."
	for _, tc := range []struct {
		name      string
		alternate bool
		requests  int
		notice    string
	}{
		{"round limit", true, 200, "codemeld: this turn reached its 200-round limit" + removed},
		{"repeated call", false, 4, "codemeld: this turn repeated the same tool call (" + filetools.ReadToolName + ") 3 rounds in a row" + removed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			read := projectReadCall(t, dir)
			respelled := declaredToolCall{read.name, strings.Replace(read.args, `":`, `": `, 1)}
			var round int32
			client := &stubTurnClient{title: streamedTitle("Model title"), fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
				n := int(atomic.AddInt32(&round, 1))
				if len(req.Tools) == 0 {
					return provider.Response{Stream: newStream(contentChunk("final answer"), finishChunk("stop"))}, nil
				}
				call := read
				if tc.alternate && n%2 == 0 {
					call = respelled
				}
				return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, fmt.Sprintf("call_%d", n), call.name, call.args)))}, nil
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			var stdout, stderr bytes.Buffer
			driver := NewHeadlessDriver("survey the repo", &stdout, &stderr)
			result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}
			if n := client.callCount(); n != tc.requests {
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

func narratedToolRound(context.Context) provider.Response {
	return provider.Response{Stream: newStream(
		contentChunk("Let me read main.go first."),
		toolCallsChunk(toolFrag(0, "call_1", filetools.ReadToolName, `{"path":"main.go"}`)),
	)}
}

func TestRunHeadless_ToolRoundNarrationGoesToStderr(t *testing.T) {
	for _, tc := range []struct {
		name          string
		deadline      time.Time
		activityFirst bool
	}{
		{"no time limit", time.Time{}, false},
		{"time limit not reached", time.Now().Add(time.Hour), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := &timeLimitScript{rounds: []func(context.Context) provider.Response{narratedToolRound, timeLimitAnswer("final answer")}}
			script.install(t)
			var stdout, stderr bytes.Buffer
			driver := NewHeadlessDriver("survey the repo", &stdout, &stderr)
			if !tc.deadline.IsZero() {
				driver.SetTimeLimit(tc.deadline, 28*time.Minute)
			}
			result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))

			if err := driver.Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}
			if stdout.String() != "final answer\n" {
				t.Fatalf("stdout = %q, want only the final answer", stdout.String())
			}
			errOut := stderr.String()
			lines := strings.Split(errOut, "\n")
			narration := slices.Index(lines, "Let me read main.go first.")
			activity := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, "main.go") && l != "Let me read main.go first." })
			if narration < 0 || activity < 0 {
				t.Fatalf("stderr = %q, want the narration on its own line and the tool activity line", errOut)
			}
			if tc.activityFirst != (activity < narration) {
				t.Fatalf("stderr = %q, narration line %d, activity line %d, want activity first = %v", errOut, narration, activity, tc.activityFirst)
			}

			store := reloadStore(t, result.Session)
			asst := messagesByRole(store, "assistant")
			if len(asst) != 2 {
				t.Fatalf("durable assistant messages = %+v, want the tool-call round and the final answer", asst)
			}
			if asst[0].Content.Text() != "Let me read main.go first." || len(asst[0].ToolCalls) != 1 || asst[0].ToolCalls[0].ID != "call_1" {
				t.Fatalf("tool-call message = %+v, want the narration and call_1", asst[0])
			}
			if asst[1].Content.Text() != "final answer" || len(asst[1].ToolCalls) != 0 {
				t.Fatalf("final message = %+v, want the final answer", asst[1])
			}
		})
	}
}

func TestRunHeadless_FinalOnlyRunWritesReplyAndOneNewline(t *testing.T) {
	script := &timeLimitScript{rounds: []func(context.Context) provider.Response{timeLimitAnswer("final answer")}}
	script.install(t)
	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("survey the repo", &stdout, &stderr)

	if err := driver.Run(context.Background(), headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}
	if stdout.String() != "final answer\n" || stderr.String() != launchLabelLine {
		t.Fatalf("stdout = %q, stderr = %q, want only the reply and one newline on stdout", stdout.String(), stderr.String())
	}
}

func TestHeadlessSurface_SealToolRoundReplyTerminatesTheLineOnce(t *testing.T) {
	for _, text := range []string{"Checking.", "Checking.\n"} {
		var stdout, stderr bytes.Buffer
		surface := newHeadlessSurface(&stdout, &stderr)
		surface.AppendStreamDelta(text)
		surface.sealToolRoundReply()
		surface.sealToolRoundReply()
		surface.AppendStreamDelta("done")
		surface.FinalizeStream()
		if stderr.String() != "Checking.\n" || stdout.String() != "done\n" {
			t.Fatalf("text %q: stderr = %q, stdout = %q", text, stderr.String(), stdout.String())
		}
	}
}

func TestHeadlessSurface_MarkStreamInterruptedCommitsToStdout(t *testing.T) {
	for _, tc := range []struct {
		name, preamble, partial, wantStdout, wantStderr string
	}{
		{"buffered partial", "", "Half an answer", "Half an answer\n", ""},
		{"after a sealed tool round", "Checking.", "", "\n", "Checking.\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			surface := newHeadlessSurface(&stdout, &stderr)
			if tc.preamble != "" {
				surface.AppendStreamDelta(tc.preamble)
				surface.sealToolRoundReply()
			}
			surface.AppendStreamDelta(tc.partial)
			surface.MarkStreamInterrupted()
			if stdout.String() != tc.wantStdout || stderr.String() != tc.wantStderr {
				t.Fatalf("stdout = %q, stderr = %q; want %q, %q", stdout.String(), stderr.String(), tc.wantStdout, tc.wantStderr)
			}
		})
	}
}

type failingWriter struct{ short bool }

func (w failingWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) / 2, nil
	}
	return 0, errors.New("stdout closed")
}

func TestRunHeadless_TimeLimitFinalAnswerWriteFailureIsNotSuccess(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  failingWriter
	}{
		{"failing", failingWriter{}},
		{"short", failingWriter{short: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := &timeLimitScript{rounds: []func(context.Context) provider.Response{timeLimitAnswer("final answer")}}
			script.install(t)
			var stderr bytes.Buffer
			driver := NewHeadlessDriver("survey the repo", tc.out, &stderr)
			driver.SetTimeLimit(time.Now().Add(-time.Second), 28*time.Minute)

			if err := driver.Run(context.Background(), headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))); err == nil {
				t.Fatal("driver.Run succeeded although the final answer never reached stdout")
			}
			if strings.Contains(stderr.String(), "time limit") {
				t.Fatalf("stderr = %q, want no time-limit success notice", stderr.String())
			}
			if n := script.client.titleCallCount(); n != 0 {
				t.Fatalf("title requests = %d, want 0 after a failed run", n)
			}
		})
	}
}

func TestRunHeadless_TimeLimitEmptyFinalResponseIsNotSuccess(t *testing.T) {
	script := &timeLimitScript{}
	for range 10 {
		script.rounds = append(script.rounds, func(context.Context) provider.Response {
			return provider.Response{Stream: newStream(finishChunk("stop"))}
		})
	}
	script.install(t)
	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("survey the repo", &stdout, &stderr)
	driver.SetTimeLimit(time.Now().Add(-time.Second), 28*time.Minute)

	if err := driver.Run(context.Background(), headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))); err == nil {
		t.Fatal("driver.Run succeeded although the final request produced no answer")
	}
	for i, req := range script.requests {
		if len(req.Tools) != 0 {
			t.Fatalf("request %d advertised %d tools, want only tool-less final-request attempts", i+1, len(req.Tools))
		}
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want nothing", stdout.String())
	}
	if strings.Contains(stderr.String(), "time limit") {
		t.Fatalf("stderr = %q, want no time-limit success notice", stderr.String())
	}
	if n := script.client.titleCallCount(); n != 0 {
		t.Fatalf("title requests = %d, want 0 after a failed run", n)
	}
}

var testExecutionResolution = enforce.Resolution{Capability: enforce.Refused, Reason: "test: resolver stubbed"}

const launchLabelLine = "sandbox: unavailable (test: resolver stubbed)\n"

func TestMain(m *testing.M) {
	resolveExecutionCapability = func(enforce.ResolveInput) enforce.Resolution { return testExecutionResolution }
	os.Exit(m.Run())
}

func runHeadlessCapturingDispatcher(t *testing.T, result *BootstrapResult) (*productionToolDispatcher, string) {
	t.Helper()
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()
	var captured *productionToolDispatcher
	defer swapToolLoop(func(deps turn.Deps, d turn.ToolDispatcher, n int) *turn.ToolLoop {
		captured, _ = d.(*productionToolDispatcher)
		return turn.NewToolLoop(deps, d, n)
	})()
	var stdout, stderr bytes.Buffer
	if err := NewHeadlessDriver("hi", &stdout, &stderr).Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}
	if captured == nil {
		t.Fatal("the turn ran without the production dispatcher")
	}
	return captured, stderr.String()
}

func TestRunHeadless_PrintsTheInjectedLabelAndRecordsTheCapability(t *testing.T) {
	resolution := injectedResolution
	resolution.SelfTestPassed = true
	calls := swapResolveExecutionCapability(t, resolution)
	result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))
	d, stderr := runHeadlessCapturingDispatcher(t, result)

	if *calls != 1 {
		t.Fatalf("Resolve calls = %d, want 1", *calls)
	}
	if d.confinement == nil || !d.confinement.constrained {
		t.Fatalf("confinement = %+v, want constrained from the passed self-test despite the refused label", d.confinement)
	}
	if n := strings.Count(stderr, "sandbox: unavailable (test: injected refusal)"); n != 1 {
		t.Fatalf("stderr = %q, want the injected label exactly once", stderr)
	}
	caps := decodeDiskEvents[events.ExecutionCapability](t, readSessionFile(t, result.Session.Path()), events.KindExecutionCapability)
	if len(caps) != 1 || !reflect.DeepEqual(caps[0], injectedCapability) {
		t.Fatalf("execution_capability on disk = %+v, want exactly %+v", caps, injectedCapability)
	}
}

func TestRunHeadless_LaunchConfinementIsSharedWithTheVCSRunners(t *testing.T) {
	calls := swapResolveExecutionCapability(t, enforce.Resolution{
		Capability:     enforce.Constrained,
		Legs:           []enforce.Leg{{Name: "test-write", Observed: "denied"}},
		SelfTestPassed: true,
	})
	project := t.TempDir()
	result := headlessResult(t, project, mode.NewActiveState(mode.Plan, mode.SourceDefault))
	result.ToolRegistry = &toolRegistryFactory{active: &ActiveVCS{Template: productVettedGitTemplate(t), RepoRoot: project}}
	inner := &confineInner{}
	prev := newVCSActionRunner
	newVCSActionRunner = func() runner.Runner { return inner }
	t.Cleanup(func() { newVCSActionRunner = prev })
	launchPath := t.TempDir()
	t.Setenv("PATH", launchPath)
	t.Setenv("MISE_DATA_DIR", "/launch/mise")
	t.Setenv("GITHUB_TOKEN", "launch-secret")

	d, _ := runHeadlessCapturingDispatcher(t, result)
	conf := d.confinement
	if *calls != 1 || conf == nil {
		t.Fatalf("Resolve calls = %d, confinement = %+v; want one call and a launch confinement", *calls, conf)
	}
	if !conf.constrained || conf.home != result.Home || conf.projectRoot != project || conf.lookupPath != launchPath || conf.mode() != string(mode.Plan) {
		t.Fatalf("confinement = %+v, want constrained with the launch home, project root, PATH and mode", *conf)
	}
	if conf.blocked == nil || conf.blocked != d.guard.Blocked {
		t.Fatalf("blocked = %p, want the launch guard's %p", conf.blocked, d.guard.Blocked)
	}
	if !slices.Contains(conf.inherited, "MISE_DATA_DIR=/launch/mise") || slices.ContainsFunc(conf.inherited, func(e string) bool {
		return strings.HasPrefix(e, "GITHUB_TOKEN=")
	}) {
		t.Fatalf("inherited = %q, want the launch MISE_DATA_DIR and no GITHUB_TOKEN", conf.inherited)
	}
	if _, err := os.Stat(conf.tmpDir); conf.tmpDir == "" || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("tmpDir %q stat = %v, want a folder removed when the run returned", conf.tmpDir, err)
	}

	conf.lookupPath = programDir(t, "git")
	if _, err := d.Dispatch(context.Background(), structuredCall("c1", "vcs_status", map[string]any{})); err != nil {
		t.Fatalf("Dispatch error = %v", err)
	}
	if len(inner.bounded) != 1 {
		t.Fatalf("vcs runs = %+v, want one confined run", inner.bounded)
	}
	got := inner.bounded[0]
	if !slices.Contains(got.Env, "MISE_DATA_DIR=/launch/mise") {
		t.Fatalf("vcs env = %q, want the launch snapshot's MISE_DATA_DIR", got.Env)
	}
	if len(got.Argv) < 3 || got.Argv[0] != "/proc/self/exe" || got.Argv[1] != enforce.HelperCommand || got.Argv[2] != filepath.Join(conf.lookupPath, "git") {
		t.Fatalf("vcs argv = %q, want the helper prefix and git from the shared confinement's lookup path", got.Argv)
	}
	if policy, _ := decodeFrame(t, got.Stdin); policy.Mode != string(mode.Plan) {
		t.Fatalf("policy = %+v, want the plan launch mode", policy)
	}
}

func TestRunHeadless_EmptyLaunchPATHRefusesFixedPATHPrograms(t *testing.T) {
	if _, err := runner.ResolveOnPath("git", runner.FixedPATH); err != nil {
		t.Skip("git is not on FixedPATH")
	}
	swapResolveExecutionCapability(t, enforce.Resolution{
		Capability:     enforce.Constrained,
		Legs:           []enforce.Leg{{Name: "test-write", Observed: "denied"}},
		SelfTestPassed: true,
	})
	project := t.TempDir()
	result := headlessResult(t, project, mode.NewActiveState(mode.Plan, mode.SourceDefault))
	result.ToolRegistry = &toolRegistryFactory{active: &ActiveVCS{Template: productVettedGitTemplate(t), RepoRoot: project}}
	inner := &confineInner{}
	prev := newVCSActionRunner
	newVCSActionRunner = func() runner.Runner { return inner }
	t.Cleanup(func() { newVCSActionRunner = prev })
	t.Setenv("PATH", "")

	d, _ := runHeadlessCapturingDispatcher(t, result)
	if d.confinement == nil || d.confinement.lookupPath != "" {
		t.Fatalf("confinement = %+v, want the empty launch PATH", d.confinement)
	}
	_, _ = d.Dispatch(context.Background(), structuredCall("c1", "vcs_status", map[string]any{}))
	if inner.calls() != 0 {
		t.Fatalf("inner calls = %d, want git refused under the empty launch PATH", inner.calls())
	}
}

func TestRunHeadless_LookupPathFollowsProgramLookup(t *testing.T) {
	launchPath := t.TempDir()
	for _, tc := range []struct {
		name, setting, want string
	}{
		{"absent", "", launchPath},
		{"friendly", "friendly", launchPath},
		{"strict", "strict", runner.FixedPATH},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))
			if tc.setting != "" {
				result.Config["confinement"] = map[string]any{"program_lookup": tc.setting}
			}
			t.Setenv("PATH", launchPath)
			d, _ := runHeadlessCapturingDispatcher(t, result)
			if d.confinement == nil || d.confinement.lookupPath != tc.want || d.confinement.constrained {
				t.Fatalf("confinement = %+v, want lookupPath %q and not constrained", d.confinement, tc.want)
			}
		})
	}
}

var constrainedResolution = enforce.Resolution{
	Capability:     enforce.Constrained,
	Legs:           []enforce.Leg{{Name: "test-write", Observed: "denied"}},
	SelfTestPassed: true,
}

var selfTestCases = []struct {
	name       string
	resolution enforce.Resolution
	want       bool
}{
	{"constrained", constrainedResolution, true},
	{"refused after a passed self-test", enforce.Resolution{Capability: enforce.Refused, Reason: "test: settings broken", SelfTestPassed: true}, true},
	{"refused", enforce.Resolution{Capability: enforce.Refused, Reason: "test: no self-test"}, false},
}

func runHeadlessShell(t *testing.T, result *BootstrapResult, run runner.Runner, command string) *productionToolDispatcher {
	t.Helper()
	prev := newShellRunner
	newShellRunner = func() runner.Runner { return run }
	defer func() { newShellRunner = prev }()
	client := toolThenContentClient(nil, bashToolName, toolArgs(t, map[string]any{"command": command}), "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()
	var captured *productionToolDispatcher
	defer swapToolLoop(func(deps turn.Deps, d turn.ToolDispatcher, n int) *turn.ToolLoop {
		captured, _ = d.(*productionToolDispatcher)
		return turn.NewToolLoop(deps, d, n)
	})()
	if err := NewHeadlessDriver("run it", &bytes.Buffer{}, &bytes.Buffer{}).Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}
	if captured == nil {
		t.Fatal("the turn ran without the production dispatcher")
	}
	return captured
}

func TestRunHeadless_AuthorizerCarriesTheSelfTestResult(t *testing.T) {
	for _, tc := range selfTestCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			swapResolveExecutionCapability(t, tc.resolution)
			inner := &confineInner{}
			result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Plan, mode.SourceDefault))
			d := runHeadlessShell(t, result, inner, "touch x")

			auth, _ := d.authorizer.(*headlessAuthorizer)
			if auth == nil || auth.executionConstrained != tc.want || auth.blocked == nil || d.confinement == nil || d.confinement.constrained != tc.want {
				t.Fatalf("authorizer = %+v, confinement = %+v; want both constrained = %v and the live blocked list", auth, d.confinement, tc.want)
			}
			reloaded := reloadStore(t, result.Session)
			matched := decodeStoreEvents[events.PermissionMatched](t, reloaded, events.KindPermissionMatched)
			if !tc.want {
				toolMsgs := messagesByRole(reloaded, "tool")
				if len(toolMsgs) != 1 || !strings.Contains(toolMsgs[0].Content.Text(), `"denied_by":"mode"`) {
					t.Fatalf("tool messages = %+v, want one mode deny envelope", toolMsgs)
				}
				if inner.calls() != 0 {
					t.Fatalf("runner calls = %d, want none", inner.calls())
				}
				return
			}
			if len(matched) != 1 || matched[0].OutcomeSource != permissions.OutcomeSourceConfined {
				t.Fatalf("permission_matched = %+v, want one confined match", matched)
			}
			if inner.calls() != 1 || len(inner.bounded) != 1 || inner.bounded[0].Argv[0] != "/proc/self/exe" || inner.bounded[0].Argv[1] != enforce.HelperCommand {
				t.Fatalf("runner bounded = %+v, calls = %d; want one run through the helper", inner.bounded, inner.calls())
			}
		})
	}
}

func TestRunHeadless_BuildShellUnderConstrainedLaunchKeepsTheGrantPath(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	dir := t.TempDir()
	run := func(resolution enforce.Resolution) (*confineInner, []events.PermissionMatched) {
		swapResolveExecutionCapability(t, resolution)
		result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
		result.Config["permissions"] = []any{map[string]any{
			"kind": "direct", "subject": "touch :*", "path_scope": dir, "grant_kind": "folder",
		}}
		inner := &confineInner{}
		runHeadlessShell(t, result, inner, "touch shell-ran.txt")
		if inner.calls() != 1 {
			t.Fatalf("runner calls = %d, want 1", inner.calls())
		}
		for _, spec := range append(slices.Clone(inner.execs), inner.bounded...) {
			if spec.InvocationID == "" {
				t.Fatalf("spec %+v carries no invocation id", spec)
			}
		}
		return inner, decodeStoreEvents[events.PermissionMatched](t, reloadStore(t, result.Session), events.KindPermissionMatched)
	}
	unconfined, _ := run(enforce.Resolution{Capability: enforce.Refused, Reason: "test: no self-test"})
	constrained, matched := run(constrainedResolution)

	if len(matched) != 1 || matched[0].OutcomeSource != "grant" {
		t.Fatalf("permission_matched = %+v, want the folder grant", matched)
	}
	strip := func(specs []runner.RunSpec) []runner.RunSpec {
		out := cloneSpecs(specs)
		for i := range out {
			out[i].InvocationID = ""
		}
		return out
	}
	if !reflect.DeepEqual(strip(constrained.execs), strip(unconfined.execs)) || !reflect.DeepEqual(strip(constrained.bounded), strip(unconfined.bounded)) {
		t.Fatalf("constrained launch runs exec %+v bounded %+v, want the unconfined exec %+v bounded %+v",
			constrained.execs, constrained.bounded, unconfined.execs, unconfined.bounded)
	}
	for _, spec := range append(slices.Clone(constrained.execs), constrained.bounded...) {
		if spec.Argv[0] == "/proc/self/exe" || len(spec.Stdin) != 0 {
			t.Fatalf("build spec = %+v, want no helper prefix or policy frame", spec)
		}
	}
}

func literalShellAuthRequest(t *testing.T, command, scope string) dispatch.BatchAuthRequest {
	t.Helper()
	split, err := permissions.SplitCommand(command)
	if err != nil || !split.LiteralRoute {
		t.Fatalf("SplitCommand(%q) = %+v, %v; want the literal route", command, split, err)
	}
	canonical, err := permissions.CanonicalLiteralForm(split.LiteralInput)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm(%q): %v", split.LiteralInput, err)
	}
	return dispatch.BatchAuthRequest{
		Req:     permissions.MatchRequest{Kind: "literal", Subject: canonical, PathScope: scope},
		Display: dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: command, WholeCommand: true},
		ModeCtx: permissions.ModeContext{Class: permissions.ClassMutating, Stages: split.Stages, LiteralRoute: true},
	}
}

var headlessShellRequests = map[string]func(t *testing.T, scope string) dispatch.BatchAuthRequest{
	"direct stage": func(_ *testing.T, scope string) dispatch.BatchAuthRequest {
		return directShellAuthRequest("touch x", scope)
	},
	"literal": func(t *testing.T, scope string) dispatch.BatchAuthRequest {
		return literalShellAuthRequest(t, "sh -c 'touch x'", scope)
	},
}

func TestHeadlessAuthorizer_BrokenSettingsAsksBeforeConstrainedShellUntilFixed(t *testing.T) {
	for kind, build := range headlessShellRequests {
		for _, m := range []mode.Mode{mode.Plan, mode.AutoEdits} {
			for _, approver := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%s/approver=%v", kind, m, approver), func(t *testing.T) {
					f := newRereadFixture(t)
					f.writeGlobal(t, "a")
					var out bytes.Buffer
					var terminal *terminalPrompter
					if approver {
						terminal = newTerminalPrompter(strings.NewReader("1\n"), &out)
					}
					store := mkStore(t)
					auth := newHeadlessAuthorizer(emptyCache(t, f.project), func() *sessions.Store { return store },
						mode.NewActiveState(m, mode.SourceDefault), terminal, &recordingNotices{})
					auth.executionConstrained = true
					auth.blocked = f.blocked(t, true)
					req := build(t, f.project)
					step := func(state, outcome string, prompts int) {
						t.Helper()
						dec, err := auth.Authorize(context.Background(), req.Req, req.Display, req.ModeCtx)
						if err != nil || dec.Outcome != outcome || dec.WrapUp {
							t.Fatalf("%s: decision = %+v, %v; want %s", state, dec, err, outcome)
						}
						if outcome == "deny" && !strings.HasPrefix(envelopeReason(t, dec.DenyEnvelope), headlessDenyReason) {
							t.Fatalf("%s: envelope = %s, want the unattended no-approver refusal", state, dec.DenyEnvelope)
						}
						if got := strings.Count(out.String(), "approval required"); got != prompts {
							t.Fatalf("%s: terminal prompts = %d, want %d", state, got, prompts)
						}
					}
					step("valid", "once", 0)
					rewriteSettings(t, f.global, "blocked_paths: [\n")
					broken, prompts := "deny", 0
					if approver {
						broken, prompts = "once", 1
					}
					step("broken", broken, prompts)
					f.editGlobal(t, "a")
					step("fixed", "once", prompts)
				})
			}
		}
	}
}

func TestHeadlessAuthorizer_BrokenSettingsLeavesUnconstrainedShellUnchanged(t *testing.T) {
	f := newRereadFixture(t)
	f.writeGlobal(t, "a")
	blocked := f.blocked(t, true)
	rewriteSettings(t, f.global, "blocked_paths: [\n")
	for _, tc := range []struct {
		m        mode.Mode
		command  string
		outcome  string
		readOnly bool
	}{
		{mode.Plan, "touch x", "deny", false},
		{mode.Plan, "ls", "once", true},
		{mode.AutoEdits, "ls", "once", true},
	} {
		store := mkStore(t)
		auth := newHeadlessAuthorizer(emptyCache(t, f.project), func() *sessions.Store { return store },
			mode.NewActiveState(tc.m, mode.SourceDefault), nil, &recordingNotices{})
		auth.blocked = blocked
		req := directShellAuthRequest(tc.command, f.project)
		dec, err := auth.Authorize(context.Background(), req.Req, req.Display, req.ModeCtx)
		if err != nil || dec.Outcome != tc.outcome || dec.ReadOnlyAuto != tc.readOnly {
			t.Fatalf("%s %q = %+v, %v; want %s", tc.m, tc.command, dec, err, tc.outcome)
		}
		if !blocked.Current().Degraded() {
			t.Fatal("the blocked list is not degraded over a broken settings file")
		}
	}

	store := mkStore(t)
	auth := newHeadlessAuthorizer(emptyCache(t, f.project), func() *sessions.Store { return store },
		mode.NewActiveState(mode.Plan, mode.SourceDefault), nil, &recordingNotices{})
	auth.executionConstrained = true
	req := directShellAuthRequest("touch x", f.project)
	if dec, err := auth.Authorize(context.Background(), req.Req, req.Display, req.ModeCtx); err != nil || dec.Outcome != "once" {
		t.Fatalf("constrained shell with no blocked list = %+v, %v; want an allow", dec, err)
	}
}

type helperForwardingRunner struct {
	bin   string
	mu    sync.Mutex
	specs []runner.RunSpec
}

func (r *helperForwardingRunner) NewInvocationID() string {
	return runner.DirectExecRunner{}.NewInvocationID()
}

func (r *helperForwardingRunner) Exec(ctx context.Context, spec runner.RunSpec) (runner.RunResult, error) {
	return runner.DirectExecRunner{}.Exec(ctx, r.forward(spec))
}

func (r *helperForwardingRunner) ExecBounded(ctx context.Context, spec runner.RunSpec, maxCapture int) (runner.RunResult, error) {
	return runner.DirectExecRunner{}.ExecBounded(ctx, r.forward(spec), maxCapture)
}

func (r *helperForwardingRunner) forward(spec runner.RunSpec) runner.RunSpec {
	r.mu.Lock()
	r.specs = append(r.specs, cloneSpec(spec))
	r.mu.Unlock()
	if len(spec.Argv) > 0 && spec.Argv[0] == "/proc/self/exe" {
		spec.Argv = append([]string{r.bin}, spec.Argv[1:]...)
	}
	return spec
}

func missingHostPrimitive(res enforce.Resolution) string {
	if strings.HasPrefix(res.Reason, "linux/") && strings.HasSuffix(res.Reason, ": not supported") {
		return res.Reason
	}
	details := []string{res.Reason}
	for _, l := range res.Legs {
		details = append(details, l.Diagnostic)
	}
	for _, d := range details {
		if strings.Contains(d, "landlock ABI") {
			return d
		}
	}
	return ""
}

func TestMissingHostPrimitive(t *testing.T) {
	for _, tc := range []struct {
		res  enforce.Resolution
		want bool
	}{
		{enforce.Resolution{Reason: "linux/riscv64: not supported"}, true},
		{enforce.Resolution{Reason: "linux: self-test leg write-outside observed failed: codemeld confinement: landlock: landlock ABI 2 < 3"}, true},
		{enforce.Resolution{Reason: "linux: self-test leg write-outside observed failed: codemeld confinement: landlock: landlock ABI probe: function not implemented"}, true},
		{enforce.Resolution{Reason: "linux: self-test leg socket-inet observed allowed"}, false},
		{enforce.Resolution{Reason: "linux: self-test leg write-outside observed failed: exec format error"}, false},
		{enforce.Resolution{Reason: "linux: invalid home: path must be absolute"}, false},
	} {
		if got := missingHostPrimitive(tc.res) != ""; got != tc.want {
			t.Errorf("%q: skip %v, want %v", tc.res.Reason, got, tc.want)
		}
	}
}

func realConfinementHost(t *testing.T) (home, project, bin string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("%s: confinement needs linux", runtime.GOOS)
	}
	base, err := os.MkdirTemp("/var/tmp", "codemeld-confine-")
	if err != nil {
		base = t.TempDir()
	} else {
		t.Cleanup(func() { _ = os.RemoveAll(base) })
	}
	home, project = filepath.Join(base, "home"), filepath.Join(base, "project")
	if err := os.MkdirAll(filepath.Dir(SettingsPath(home)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(SettingsPath(home), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	bin = filepath.Join(t.TempDir(), "codemeld")
	build := exec.Command("go", "build", "-o", bin, "codemeld.dev/codemeld/cmd/codemeld")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cgo-free codemeld: %v\n%s", err, out)
	}
	res := enforce.Resolve(enforce.ResolveInput{Home: home, HelperExecutable: bin})
	if !res.SelfTestPassed {
		if missing := missingHostPrimitive(res); missing != "" {
			t.Skipf("host lacks a confinement primitive: %s", missing)
		}
		t.Fatalf("self-test through %s refused: %+v", bin, res)
	}
	swapResolveExecutionCapability(t, res)
	return home, project, bin
}

func TestRunHeadless_ConfinedPlanShellThroughTheRealHelper(t *testing.T) {
	home, project, bin := realConfinementHost(t)
	const probe = "/tmp/codemeld-confine-probe"
	fixture := SettingsPath(home)
	for _, tc := range []struct {
		name, program, command, wantErr string
	}{
		{"socket", "python3", `python3 -c 'import socket; socket.socket()'`, "PermissionError"},
		{"write outside", "sh", "sh -c 'echo hi > " + probe + "'", "Permission denied"},
		{"write TMPDIR", "sh", `sh -c 'echo hi > "$TMPDIR/x"'`, "Permission denied"},
		{"read home settings", "sh", "sh -c 'cat " + fixture + "; touch read-probe'", fixture + ": Permission denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := runner.ResolveOnPath(tc.program, runner.FixedPATH); err != nil {
				t.Skipf("%s absent from %s: %v", tc.program, runner.FixedPATH, err)
			}
			if _, err := os.Lstat(probe); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("fixture: %s must be absent before the run, stat = %v", probe, err)
			}
			run := &helperForwardingRunner{bin: bin}
			result := headlessResult(t, project, mode.NewActiveState(mode.Plan, mode.SourceDefault))
			result.Home, result.ConfigLayerPaths = home, []string{fixture}
			result.Config["confinement"] = map[string]any{"program_lookup": "strict"}
			d := runHeadlessShell(t, result, run, tc.command)

			if len(run.specs) != 1 || run.specs[0].Argv[0] != "/proc/self/exe" || run.specs[0].Argv[1] != enforce.HelperCommand {
				t.Fatalf("inner runs = %+v, want exactly one through the helper", run.specs)
			}
			disk := readSessionFile(t, result.Session.Path())
			ends := decodeDiskEvents[events.ToolExecEnd](t, disk, events.KindToolExecEnd)
			if len(ends) != 1 || ends[0].ExitCode == 0 || !strings.Contains(ends[0].Stdout+ends[0].Stderr, tc.wantErr) {
				t.Fatalf("tool_exec_end = %+v, want one non-zero exit showing %q", ends, tc.wantErr)
			}
			var permission []string
			for _, kind := range eventKinds(disk.Records) {
				if strings.HasPrefix(kind, "permission_") {
					permission = append(permission, kind)
				}
			}
			matched := decodeDiskEvents[events.PermissionMatched](t, disk, events.KindPermissionMatched)
			if !slices.Equal(permission, []string{events.KindPermissionMatched}) || matched[0].OutcomeSource != permissions.OutcomeSourceConfined {
				t.Fatalf("permission events = %v, matched = %+v; want one confined match and no prompt", permission, matched)
			}
			auth := d.authorizer.(*headlessAuthorizer)
			if grants := auth.grants.Permissions(); len(grants) != 0 {
				t.Fatalf("grants = %+v, want none", grants)
			}
			if n := reflect.ValueOf(auth.grants.turn).Elem().FieldByName("entries").Len(); n != 0 {
				t.Fatalf("turn cache entries = %d, want none", n)
			}
			if _, err := os.Lstat(probe); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("%s stat = %v, want it still absent", probe, err)
			}
		})
	}
}

func TestHeadlessAuthorizer_UnattendedExceptionalDenialNamesTheAuthority(t *testing.T) {
	prependFixturePrograms(t, "curl")
	const want = "no approval available in non-interactive run mode for an exceptional action that adds network access"
	for _, command := range []string{"curl https://example.com/a", "sh -c 'curl https://example.com/a'"} {
		t.Run(command, func(t *testing.T) {
			auth, cwd := exceptionalHeadlessAuthorizer(t, "", nil)
			var notices bytes.Buffer
			auth.notices = stderrNoticeRenderer{w: &notices}
			run := &fakeDispatchRunner{}
			_, err := dispatch.DispatchShell(context.Background(), command, t.TempDir(), cwd, auth, run)
			var denied *dispatch.DeniedError
			if !errors.As(err, &denied) || denied.Envelope != permissions.BuildUnattendedDenyEnvelope(want) {
				t.Fatalf("DispatchShell err = %v, want the unattended envelope carrying %q", err, want)
			}
			if strings.Contains(denied.Envelope, headlessReadOnlyHint) || run.callCount() != 0 || notices.Len() != 0 {
				t.Fatalf("envelope %q, runs %d, notices %q; want no hint, no run, nothing written", denied.Envelope, run.callCount(), notices.String())
			}
			calls := auth.deniedSubjects()
			if len(calls) != 1 || calls[0].Reason != want {
				t.Fatalf("recorded denials = %+v, want one with reason %q", calls, want)
			}
		})
	}
}

const (
	constrainedBuildLabel = "sandbox: off"
	brokenLaunchLabel     = "sandbox: unavailable (settings file is broken)"
)

const brokenSettings = "blocked_paths: [\n"

func doneClient() *stubTurnClient {
	return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	}}
}

func constrainedSettingsRun(t *testing.T) (*BootstrapResult, string) {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	project := declaredScopeDir(t)
	result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
	result.SettingsLayers = blockedGlobalLayers(t, result.Home, project)
	return result, SettingsPath(result.Home)
}

func projectReadCall(t *testing.T, project string) declaredToolCall {
	t.Helper()
	file := filepath.Join(project, "a.txt")
	if err := os.WriteFile(file, []byte("a\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", file, err)
	}
	return readCall(t, file)
}

func brokenThenFixedClient(t *testing.T, settings, project string) *stubTurnClient {
	t.Helper()
	read := projectReadCall(t, project)
	return settingsEditingClient(t,
		settingsRound{edit: settingsEdit(settings, brokenSettings), call: read},
		settingsRound{edit: settingsEdit(settings, blockedYAML()), call: read},
	)
}

func capabilityLines(out string) []string {
	var lines []string
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, "sandbox:") {
			lines = append(lines, line)
		}
	}
	return lines
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type sessionDirSwitch struct{ dir string }

func newSessionDirSwitch(t *testing.T) sessionDirSwitch {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "sessions")
	mustMkdir(t, dir)
	return sessionDirSwitch{dir: dir}
}

func (s sessionDirSwitch) block() error {
	if err := os.Rename(s.dir, s.dir+".held"); err != nil {
		return err
	}
	return os.WriteFile(s.dir, nil, 0o600)
}

func (s sessionDirSwitch) unblock() error {
	if err := os.Remove(s.dir); err != nil {
		return err
	}
	return os.Rename(s.dir+".held", s.dir)
}

func waitForDeliveryStop() error {
	buf := make([]byte, 1<<20)
	deadline := time.Now().Add(5 * time.Second)
	for {
		for g := range strings.SplitSeq(string(buf[:runtime.Stack(buf, true)]), "\n\n") {
			if strings.Contains(g, "deliverCapabilityChanges") && strings.Contains(g, "(*HeadlessDriver).Run(") {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return errors.New("Run did not wait on capability delivery within 5s")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRunHeadless_BrokenSettingsFileRecordsAndPrintsEachCapabilityChange(t *testing.T) {
	for _, tc := range []struct {
		mode    mode.Mode
		healthy string
	}{
		{mode.Build, constrainedBuildLabel},
		{mode.Plan, "sandbox: on"},
		{mode.AutoEdits, "sandbox: on"},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			swapResolveExecutionCapability(t, constrainedLaunch)
			result, settings := constrainedSettingsRun(t)
			result.Mode = mode.NewActiveState(tc.mode, mode.SourceConfig)
			client := brokenThenFixedClient(t, settings, result.ProjectRoot)
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			var stdout, stderr bytes.Buffer
			if err := NewHeadlessDriver("read it", &stdout, &stderr).Run(context.Background(), result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}

			requireDiskCapabilities(t, result.Session, constrainedCapability, brokenCapability, constrainedCapability)
			want := []string{tc.healthy, brokenLaunchLabel, tc.healthy}
			if got := capabilityLines(stderr.String()); !slices.Equal(got, want) {
				t.Fatalf("capability lines = %q, want %q\n--- stderr ---\n%s", got, want, stderr.String())
			}
			if stdout.String() != "done\n" {
				t.Fatalf("stdout = %q, want only the final reply", stdout.String())
			}
		})
	}
}

func TestRunHeadless_SandboxLabelFollowsTheRunMode(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mode       mode.Mode
		resolution enforce.Resolution
		want       string
	}{
		{"build passed", mode.Build, constrainedLaunch, "sandbox: off"},
		{"plan passed", mode.Plan, constrainedLaunch, "sandbox: on"},
		{"plan refused", mode.Plan, injectedResolution, "sandbox: unavailable (test: injected refusal)"},
		{"build refused", mode.Build, injectedResolution, "sandbox: unavailable (test: injected refusal)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swapResolveExecutionCapability(t, tc.resolution)
			_, stderr := runHeadlessCapturingDispatcher(t, headlessResult(t, t.TempDir(), mode.NewActiveState(tc.mode, mode.SourceDefault)))
			if got := capabilityLines(stderr); !slices.Equal(got, []string{tc.want}) {
				t.Fatalf("capability lines = %q, want %q\n--- stderr ---\n%s", got, tc.want, stderr)
			}
		})
	}
}

func TestRunHeadless_SettingsFileBrokenBeforeTheFirstRecordStartsRefused(t *testing.T) {
	swapResolveExecutionCapability(t, constrainedLaunch)
	result, settings := constrainedSettingsRun(t)
	rewriteSettings(t, settings, brokenSettings)
	client := doneClient()
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stderr bytes.Buffer
	if err := NewHeadlessDriver("hi", &bytes.Buffer{}, &stderr).Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	requireDiskCapabilities(t, result.Session, brokenCapability)
	if got := capabilityLines(stderr.String()); !slices.Equal(got, []string{brokenLaunchLabel}) {
		t.Fatalf("capability lines = %q, want only %q", got, brokenLaunchLabel)
	}
}

func TestRunHeadless_RefusedLaunchKeepsItsReasonWhileTheSettingsFileIsBroken(t *testing.T) {
	swapResolveExecutionCapability(t, injectedResolution)
	result, settings := constrainedSettingsRun(t)
	client := brokenThenFixedClient(t, settings, result.ProjectRoot)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stderr bytes.Buffer
	driver := NewHeadlessDriver("read it", &bytes.Buffer{}, &stderr)
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}
	for _, line := range []string{problemNotice(settings, "is not valid YAML"), fixedNotice(settings)} {
		if !strings.Contains(stderr.String(), line+"\n") {
			t.Fatalf("stderr = %q, want %q: the run's consumers must have seen the file broken and fixed", stderr.String(), line)
		}
	}
	rewriteSettings(t, settings, brokenSettings)
	refreshWithin(t, driver.authorizer.blocked)

	requireDiskCapabilities(t, result.Session, injectedCapability)
	if want := "sandbox: unavailable (test: injected refusal)"; !slices.Equal(capabilityLines(stderr.String()), []string{want}) {
		t.Fatalf("capability lines = %q, want only the launch label %q", capabilityLines(stderr.String()), want)
	}
}

func TestRunHeadless_QueuedCapabilityChangeIsDrainedBeforeTheFinalFlush(t *testing.T) {
	for _, recovers := range []bool{true, false} {
		t.Run(fmt.Sprintf("recovers=%v", recovers), func(t *testing.T) {
			swapResolveExecutionCapability(t, constrainedLaunch)
			result, settings := constrainedSettingsRun(t)
			sessionDir := newSessionDirSwitch(t)
			result.Session = storeAt(t, filepath.Join(sessionDir.dir, "session.json"), "01890000-0000-7000-8000-0000000000ac", result.ProjectRoot)
			hold := newRecordHold(t)
			var records atomic.Int32
			orig := recordExecutionCapability
			recordExecutionCapability = func(ctx context.Context, store *sessions.Store, resolution enforce.Resolution, notices tui.NoticeRenderer) error {
				switch records.Add(1) {
				case 2:
					hold.block()
				case 3:
					if err := sessionDir.block(); err != nil {
						t.Errorf("block session writes: %v", err)
					}
					err := orig(ctx, store, resolution, notices)
					if recovers {
						if uerr := sessionDir.unblock(); uerr != nil {
							t.Errorf("unblock session writes: %v", uerr)
						}
					}
					return err
				}
				return orig(ctx, store, resolution, notices)
			}
			t.Cleanup(func() { recordExecutionCapability = orig })

			var driver *HeadlessDriver
			client := &stubTurnClient{title: streamedTitle("Model title"), fn: func(context.Context, provider.Request) (provider.Response, error) {
				blocked := driver.authorizer.blocked
				if err := bumpSettings(settings, brokenSettings); err != nil {
					t.Errorf("break settings: %v", err)
				}
				blocked.Current()
				select {
				case <-hold.entered:
				case <-time.After(5 * time.Second):
					t.Error("the refused transition never reached the recorder")
				}
				if err := bumpSettings(settings, blockedYAML()); err != nil {
					t.Errorf("fix settings: %v", err)
				}
				blocked.Current()
				go func() {
					if err := waitForDeliveryStop(); err != nil {
						t.Error(err)
					}
					hold.open()
				}()
				return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			var stderr bytes.Buffer
			driver = NewHeadlessDriver("hi", &bytes.Buffer{}, &stderr)
			err := driver.Run(context.Background(), result)

			if !strings.Contains(stderr.String(), "session log unwritable") {
				t.Fatalf("stderr = %q, want the write-failure notice for the queued record", stderr.String())
			}
			want := []string{constrainedBuildLabel, brokenLaunchLabel, constrainedBuildLabel}
			if got := capabilityLines(stderr.String()); !slices.Equal(got, want) {
				t.Fatalf("capability lines = %q, want %q", got, want)
			}
			if !recovers {
				if err == nil {
					t.Fatal("driver.Run = nil, want the final flush failure")
				}
				if n := client.titleCallCount(); n != 0 {
					t.Fatalf("title requests = %d, want 0 after a failed final flush", n)
				}
				return
			}
			if err != nil {
				t.Fatalf("driver.Run: %v", err)
			}
			requireDiskCapabilities(t, result.Session, constrainedCapability, brokenCapability, constrainedCapability)

			rewriteSettings(t, settings, brokenSettings)
			refreshWithin(t, driver.authorizer.blocked)
			if n := records.Load(); n != 3 {
				t.Fatalf("capability records = %d after Run returned, want 3: the callback must be cleared", n)
			}
			requireDiskCapabilities(t, result.Session, constrainedCapability, brokenCapability, constrainedCapability)
		})
	}
}

func TestRunHeadless_CapabilityLinesStayWholeBesideConcurrentStderr(t *testing.T) {
	swapResolveExecutionCapability(t, constrainedLaunch)
	result, settings := constrainedSettingsRun(t)
	const rounds = 6
	read := projectReadCall(t, result.ProjectRoot)
	respelled := declaredToolCall{read.name, strings.Replace(read.args, `":`, `": `, 1)}
	inner := declaredScopeClient(slices.Repeat([]declaredToolCall{read, respelled}, rounds/2)...)
	toggled := make(chan struct{})
	var driver *HeadlessDriver
	var round atomic.Int32
	client := &stubTurnClient{fn: func(ctx context.Context, req provider.Request) (provider.Response, error) {
		switch round.Add(1) {
		case 1:
			blocked := driver.authorizer.blocked
			go func() {
				defer close(toggled)
				for i := range 20 {
					content := blockedYAML()
					if i%2 == 0 {
						content = brokenSettings
					}
					if err := bumpSettings(settings, content); err != nil {
						t.Errorf("toggle settings: %v", err)
						return
					}
					blocked.Current()
				}
			}()
		case rounds + 1:
			<-toggled
		}
		return inner.fn(ctx, req)
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout, stderr bytes.Buffer
	driver = NewHeadlessDriver("read it", &stdout, &stderr)
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}
	<-toggled

	caps := decodeDiskEvents[events.ExecutionCapability](t, readSessionFile(t, result.Session.Path()), events.KindExecutionCapability)
	if len(caps) < 3 || len(caps)%2 == 0 {
		t.Fatalf("execution_capability on disk = %+v, want alternating records ending constrained", caps)
	}
	lines := capabilityLines(stderr.String())
	if len(lines) != len(caps) {
		t.Fatalf("capability lines = %q, want one per record (%d)\n--- stderr ---\n%s", lines, len(caps), stderr.String())
	}
	for i := range caps {
		wantCap, wantLine := constrainedCapability, constrainedBuildLabel
		if i%2 == 1 {
			wantCap, wantLine = brokenCapability, brokenLaunchLabel
		}
		if !reflect.DeepEqual(caps[i], wantCap) || lines[i] != wantLine {
			t.Fatalf("record %d = %+v with line %q, want %+v with %q", i, caps[i], lines[i], wantCap, wantLine)
		}
	}
	for line := range strings.SplitSeq(stderr.String(), "\n") {
		if strings.Contains(line, "blocked_paths:") && !strings.HasPrefix(line, "blocked_paths:") {
			t.Fatalf("notice line %q was split by another write", line)
		}
	}
	if stdout.String() != "done\n" {
		t.Fatalf("stdout = %q, want only the final reply", stdout.String())
	}
}

func TestRunHeadless_CapabilityChangeIsDeliveredWhileATerminalPromptWaits(t *testing.T) {
	swapResolveExecutionCapability(t, constrainedLaunch)
	result, settings := constrainedSettingsRun(t)
	client := toolThenContentClient(nil, "create", `{"path":"a.txt","content":"x\n"}`, "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	stderr := &lockedBuffer{}
	driver := NewHeadlessDriver("make a file", &bytes.Buffer{}, stderr)
	var asked atomic.Bool
	driver.EnablePromptForApproval(readerFunc(func(p []byte) (int, error) {
		if asked.Swap(true) {
			return 0, io.EOF
		}
		if err := bumpSettings(settings, brokenSettings); err != nil {
			t.Errorf("break settings: %v", err)
		}
		driver.authorizer.blocked.Current()
		deadline := time.Now().Add(5 * time.Second)
		for {
			out := stderr.String()
			if prompt := strings.Index(out, "choose 1-4"); prompt >= 0 && strings.Contains(out[prompt:], "\n"+brokenLaunchLabel+"\n") {
				break
			}
			if time.Now().After(deadline) {
				t.Errorf("stderr = %q, want the capability line on its own line below the waiting prompt", stderr.String())
				break
			}
			time.Sleep(time.Millisecond)
		}
		return copy(p, "2\n"), nil
	}))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	requireDiskCapabilities(t, result.Session, constrainedCapability, brokenCapability)
}

func TestHeadlessStderr_LineStartsBelowAnUnterminatedPrompt(t *testing.T) {
	var out bytes.Buffer
	w := &headlessStderr{w: &out}
	w.line("first")
	_, _ = fmt.Fprint(w, "codemeld: choose 1-2: ")
	w.line("second")
	if want := "first\ncodemeld: choose 1-2: \nsecond\n"; out.String() != want {
		t.Fatalf("stderr = %q, want %q", out.String(), want)
	}
}

func TestRunHeadless_PromptDetectsTheTerminalOnTheOriginalStderr(t *testing.T) {
	tty, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	defer func() { _ = tty.Close() }()
	if !tui.PromptNotifyTTY(tty) {
		t.Skip("the pseudo-terminal master is not a terminal on this system")
	}
	client := doneClient()
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var stdout bytes.Buffer
	driver := NewHeadlessDriver("hi", &stdout, tty)
	driver.EnablePromptForApproval(strings.NewReader(""))
	if err := driver.Run(context.Background(), headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	terminal := driver.authorizer.terminal
	serialized, ok := terminal.out.(*headlessStderr)
	if !terminal.notifyTTY || !ok || serialized.w != io.Writer(tty) {
		t.Fatalf("prompter notifyTTY = %v, out = %T; want terminal detection on the raw stderr and output through the serialized writer", terminal.notifyTTY, terminal.out)
	}
	if notices, ok := driver.authorizer.notices.(stderrNoticeRenderer); !ok || notices.w != io.Writer(serialized) {
		t.Fatalf("authorizer notices = %#v, want the same serialized writer", driver.authorizer.notices)
	}
	if stdout.String() != "done\n" {
		t.Fatalf("stdout = %q, want only the final reply", stdout.String())
	}
}

func TestRunHeadless_InitialCapabilityFlushFailureDoesNotStopTheRun(t *testing.T) {
	t.Run("a later boundary persists the retained record", func(t *testing.T) {
		dir := t.TempDir()
		result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
		sessionDir := newSessionDirSwitch(t)
		result.Session = storeAt(t, filepath.Join(sessionDir.dir, "session.json"), "01890000-0000-7000-8000-0000000000ab", dir)
		orig := recordExecutionCapability
		recordExecutionCapability = func(ctx context.Context, store *sessions.Store, resolution enforce.Resolution, notices tui.NoticeRenderer) error {
			if err := sessionDir.block(); err != nil {
				t.Errorf("block session writes: %v", err)
			}
			defer func() {
				if err := sessionDir.unblock(); err != nil {
					t.Errorf("unblock session writes: %v", err)
				}
			}()
			return orig(ctx, store, resolution, notices)
		}
		t.Cleanup(func() { recordExecutionCapability = orig })
		client := doneClient()
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		var stdout, stderr bytes.Buffer
		if err := NewHeadlessDriver("hi", &stdout, &stderr).Run(context.Background(), result); err != nil {
			t.Fatalf("driver.Run: %v", err)
		}

		if !strings.Contains(stderr.String(), "session log unwritable") || !strings.Contains(stderr.String(), launchLabelLine) {
			t.Fatalf("stderr = %q, want the write-failure notice and the launch label", stderr.String())
		}
		want := events.ExecutionCapability{Capability: string(testExecutionResolution.Capability), Reason: testExecutionResolution.Reason}
		requireDiskCapabilities(t, result.Session, want)
		if users := messagesByRole(reloadStore(t, result.Session), "user"); len(users) != 1 || stdout.String() != "done\n" {
			t.Fatalf("user messages = %+v, stdout = %q; want the turn to run and persist", users, stdout.String())
		}
	})

	t.Run("a pre-turn flush failure still surfaces", func(t *testing.T) {
		dir := t.TempDir()
		result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
		result.Session = unwritableStore(t, "01890000-0000-7000-8000-0000000000ad", dir)
		client := doneClient()
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		var stderr bytes.Buffer
		err := NewHeadlessDriver("hi", &bytes.Buffer{}, &stderr).Run(context.Background(), result)
		if err == nil || client.callCount() != 0 {
			t.Fatalf("driver.Run error = %v, provider calls = %d; want the pre-turn flush failure before any request", err, client.callCount())
		}
		if !strings.Contains(stderr.String(), launchLabelLine) {
			t.Fatalf("stderr = %q, want startup to have continued past the failed capability flush", stderr.String())
		}
	})
}

func TestRunHeadless_CapabilityIsRecordedOnlyAfterTheBlockedListIsBuilt(t *testing.T) {
	t.Run("construction failure", func(t *testing.T) {
		project := declaredScopeDir(t)
		result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
		result.SettingsLayers = blockedGlobalLayers(t, result.Home, project, "~/vault")
		result.SettingsLayers[0].Raw["blocked_paths"] = []any{"vault/x"}

		var stderr bytes.Buffer
		err := NewHeadlessDriver("hi", &bytes.Buffer{}, &stderr).Run(context.Background(), result)
		if err == nil || !strings.Contains(err.Error(), "bootstrap: headless build blocked paths:") {
			t.Fatalf("driver.Run error = %v, want the blocked-list construction error", err)
		}
		if lines := capabilityLines(stderr.String()); len(lines) != 0 {
			t.Fatalf("stderr = %q, want no capability label", stderr.String())
		}
		if caps := decodeStoreEvents[events.ExecutionCapability](t, result.Session, events.KindExecutionCapability); len(caps) != 0 {
			t.Fatalf("execution_capability = %+v, want none", caps)
		}
	})

	t.Run("label before big-entry warnings", func(t *testing.T) {
		project := declaredScopeDir(t)
		result := headlessResult(t, project, mode.NewActiveState(mode.Build, mode.SourceConfig))
		result.SettingsLayers = blockedGlobalLayers(t, result.Home, project, "/etc")
		client := doneClient()
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		var stderr bytes.Buffer
		if err := NewHeadlessDriver("hi", &bytes.Buffer{}, &stderr).Run(context.Background(), result); err != nil {
			t.Fatalf("driver.Run: %v", err)
		}
		label, warning := strings.Index(stderr.String(), launchLabelLine), strings.Index(stderr.String(), "warning: blocked_paths entry /etc")
		if label < 0 || warning < 0 || label > warning {
			t.Fatalf("stderr = %q, want the capability label before the blocked-entry warning", stderr.String())
		}
	})
}

func TestHeadlessAuthorizer_EntryPinOutlivesASwitchBeforeAuthorization(t *testing.T) {
	for _, tc := range modeSwitchCases {
		t.Run(tc.name(), func(t *testing.T) {
			cwd := t.TempDir()
			active := mode.NewActiveState(tc.start, mode.SourceUserCommand)
			store := mkStore(t)
			auth := newHeadlessAuthorizer(emptyCache(t, cwd), func() *sessions.Store { return store }, active, nil, stderrNoticeRenderer{w: &bytes.Buffer{}})
			auth.executionConstrained = true
			active.ApplyUserCommand(tc.switched)

			req := directShellAuthRequest("touch x", cwd)
			dec, err := auth.Authorize(tc.ctx(), req.Req, req.Display, req.ModeCtx)
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			want := "once"
			if tc.decidingMode() == mode.Build {
				want = "deny"
			}
			if dec.Outcome != want {
				t.Fatalf("decision = %+v, want %s — the mutation must be decided under %q", dec, want, tc.decidingMode())
			}
		})
	}
}

func writableHeadlessRun(t *testing.T, approved bool, projectYAML func(string) string, resolution enforce.Resolution) (*BootstrapResult, writableLaunch) {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	swapResolveExecutionCapability(t, resolution)
	project := declaredScopeDir(t)
	result := headlessResult(t, project, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))
	l := gateWritableLaunch(t, result.Home, project, approved, projectYAML)
	maps.Copy(result.Config, l.composition.Config)
	result.ConfigLayerPaths = l.layerPaths
	result.SettingsLayers = l.layers
	result.TrustDecision = l.decision
	if err := os.WriteFile(l.target, []byte("old\n"), 0o600); err != nil {
		t.Fatalf("seed %s: %v", l.target, err)
	}
	return result, l
}

func writableEditCall(t *testing.T, target, from, to string) declaredToolCall {
	return declaredToolCall{name: filetools.EditToolName, args: toolArgs(t, map[string]any{"path": target, "old_text": from, "new_text": to})}
}

func runWritableHeadless(t *testing.T, result *BootstrapResult, client *stubTurnClient) (*HeadlessDriver, string) {
	t.Helper()
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()
	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("edit the notes", &stdout, &stderr)
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}
	return driver, stderr.String()
}

func diskModeAutoAllows(t *testing.T, result *BootstrapResult) []events.PermissionMatched {
	t.Helper()
	var out []events.PermissionMatched
	for _, m := range decodeDiskEvents[events.PermissionMatched](t, readSessionFile(t, result.Session.Path()), events.KindPermissionMatched) {
		if m.OutcomeSource == "mode_auto" {
			out = append(out, m)
		}
	}
	return out
}

func requireWritableEditDenied(t *testing.T, result *BootstrapResult, l writableLaunch, driver *HeadlessDriver) {
	t.Helper()
	if got := mustReadFile(t, l.target); got != "old\n" {
		t.Fatalf("%s = %q, want it untouched", l.target, got)
	}
	if denied := driver.DeniedSubjects(); len(denied) != 1 {
		t.Fatalf("DeniedSubjects = %+v, want the one edit", denied)
	}
	if allows := diskModeAutoAllows(t, result); len(allows) != 0 {
		t.Fatalf("mode_auto matches on disk = %+v, want none", allows)
	}
}

func TestRunHeadless_WritableFolderEditIsAutoAllowedUnderAConstrainedLaunch(t *testing.T) {
	result, l := writableHeadlessRun(t, true, declaringWritableFolder, constrainedLaunch)
	driver, _ := runWritableHeadless(t, result, declaredScopeClient(writableEditCall(t, l.target, "old", "new")))

	if got := mustReadFile(t, l.target); got != "new\n" {
		t.Fatalf("%s = %q, want the edit applied", l.target, got)
	}
	if denied := driver.DeniedSubjects(); len(denied) != 0 {
		t.Fatalf("DeniedSubjects = %+v, want none", denied)
	}
	want := events.PermissionMatched{SubjectKind: "tool", Subject: filetools.EditToolName, PathScope: l.folder, Outcome: "once", OutcomeSource: "mode_auto"}
	if allows := diskModeAutoAllows(t, result); len(allows) != 1 || allows[0] != want {
		t.Fatalf("mode_auto matches on disk = %+v, want exactly %+v", allows, want)
	}
}

func TestRunHeadless_WritableFolderEditIsDeniedWithoutAPassedSelfTest(t *testing.T) {
	result, l := writableHeadlessRun(t, true, declaringWritableFolder, failedSelfTest)
	driver, _ := runWritableHeadless(t, result, declaredScopeClient(writableEditCall(t, l.target, "old", "new")))

	requireWritableEditDenied(t, result, l, driver)
}

func TestRunHeadless_WritableFolderEditFollowsBrokenSettingsUntilFixed(t *testing.T) {
	result, l := writableHeadlessRun(t, true, declaringWritableFolder, constrainedLaunch)
	global := SettingsPath(result.Home)
	client := settingsEditingClient(t,
		settingsRound{call: writableEditCall(t, l.target, "old", "mid")},
		settingsRound{edit: settingsEdit(global, brokenSettings), call: writableEditCall(t, l.target, "mid", "new")},
		settingsRound{edit: settingsEdit(global, blockedYAML()), call: writableEditCall(t, l.target, "mid", "new")},
	)
	driver, stderr := runWritableHeadless(t, result, client)

	requireDiskCapabilities(t, result.Session, constrainedCapability, brokenCapability, constrainedCapability)
	if got, want := capabilityLines(stderr), []string{"sandbox: on", brokenLaunchLabel, "sandbox: on"}; !slices.Equal(got, want) {
		t.Fatalf("capability lines = %q, want %q", got, want)
	}
	if got := mustReadFile(t, l.target); got != "new\n" {
		t.Fatalf("%s = %q, want the first and recovered edits applied", l.target, got)
	}
	if denied := driver.DeniedSubjects(); len(denied) != 1 {
		t.Fatalf("DeniedSubjects = %+v, want only the edit made while the settings were broken", denied)
	}
	if allows := diskModeAutoAllows(t, result); len(allows) != 2 {
		t.Fatalf("mode_auto matches on disk = %+v, want the valid and recovered edits only", allows)
	}
	toolMsgs := messagesByRole(sessions.New(result.Session.Path(), readSessionFile(t, result.Session.Path())), "tool")
	if len(toolMsgs) != 3 || !strings.Contains(toolMsgs[1].Content.Text(), headlessDenyReason) {
		t.Fatalf("tool messages = %+v, want the broken-settings edit denied", toolMsgs)
	}
}

func TestRunHeadless_AbsentOrEmptyWritableFoldersKeepTheOutOfRootDenial(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml func(string) string
	}{
		{"absent", func(string) string { return blockedYAML() }},
		{"empty", func(string) string { return writableFoldersYAML() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, l := writableHeadlessRun(t, true, tc.yaml, constrainedLaunch)
			driver, _ := runWritableHeadless(t, result, declaredScopeClient(writableEditCall(t, l.target, "old", "new")))

			if !l.decision.Trusted || len(driver.authorizer.writable.current()) != 0 {
				t.Fatalf("decision = %+v, live folders = %v; want a trusted project with none", l.decision, driver.authorizer.writable.current())
			}
			requireWritableEditDenied(t, result, l, driver)
		})
	}
}

func TestRunHeadless_UnapprovedProjectWritableFoldersHaveNoEffect(t *testing.T) {
	result, l := writableHeadlessRun(t, false, declaringWritableFolder, constrainedLaunch)
	cache, err := config.NewCache(l.composition.Config, l.project, l.layerPaths, l.home)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	requireUnapprovedLaunchWithholdsFolders(t, l, cache)

	driver, _ := runWritableHeadless(t, result, declaredScopeClient(writableEditCall(t, l.target, "old", "new")))

	if got := driver.authorizer.writable.current(); len(got) != 0 {
		t.Fatalf("live folders = %v, want none", got)
	}
	requireWritableEditDenied(t, result, l, driver)
}

func TestRunHeadless_SavedAllowGrantsOnlyThePrivateTempFolder(t *testing.T) {
	launchTmp := canonicalTempDir(t)
	t.Setenv("TMPDIR", launchTmp)
	swapResolveExecutionCapability(t, constrainedLaunch)
	project := declaredScopeDir(t)
	result := headlessResult(t, project, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig))
	global := writeGlobalSettings(t, result.Home, "confinement:\n  shared_temp_folders: allow\n", 0o600)
	maps.Copy(result.Config, savedGlobalConfig(t, result.Home))
	before := settingsBytes(t, global)

	d, _ := runHeadlessCapturingDispatcher(t, result)

	requirePrivateTempOnly(t, d.confinement, project, launchTmp)
	if got := settingsBytes(t, global); got != before {
		t.Fatalf("global settings = %q, want %q unchanged", got, before)
	}
}

func TestHeadlessFreshSteps_RecoverJournals_HonorsABlockedPathWithoutAsking(t *testing.T) {
	prevIsTerminal := stdinIsTerminal
	stdinIsTerminal = func(io.Reader) bool { return true }
	t.Cleanup(func() { stdinIsTerminal = prevIsTerminal })
	home, project := realPath(t, t.TempDir()), realPath(t, t.TempDir())
	writeGlobalSettings(t, home, blockedYAML(), 0o600)
	target := filepath.Join(project, "a.txt")
	if err := os.WriteFile(target, []byte("ORIGINAL\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	journal := killedChildJournal(t, home, project, target)
	writeLocalProjectSettings(t, project, blockedYAML(target))

	var stderr bytes.Buffer
	HeadlessFreshSteps(&stderr, nil, "").RecoverJournals(home, project, map[string]any{}, trust.Decision{Trusted: true, Reason: trust.ReasonTrusted, Root: project})

	if strings.Contains(stderr.String(), "Keep, put back, or decide later?") {
		t.Fatalf("stderr = %q, want no prompt on a headless run", stderr.String())
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "CHILD\n" {
		t.Fatalf("%s = %q (err=%v), want the blocked file left alone", target, got, err)
	}
	if _, err := os.Stat(filepath.Join(journal, "journal.json")); err != nil {
		t.Fatalf("stat the journal record: %v, want it retained", err)
	}
	if !strings.Contains(stderr.String(), "a blocked path is involved: "+target) || strings.Contains(stderr.String(), "asks what to do") {
		t.Fatalf("stderr = %q, want the blocked reason and no promised question", stderr.String())
	}
}

func TestRunHeadless_AFolderRemovedMidRunDeniesTheNextEdit(t *testing.T) {
	result, l := writableHeadlessRun(t, true, declaringWritableFolder, constrainedLaunch)
	client := settingsEditingClient(t,
		settingsRound{call: writableEditCall(t, l.target, "old", "mid")},
		settingsRound{edit: settingsEdit(projectSettingsPath(l.project), writableFoldersYAML()), call: writableEditCall(t, l.target, "mid", "new")},
	)
	driver, _ := runWritableHeadless(t, result, client)

	if got := mustReadFile(t, l.target); got != "mid\n" {
		t.Fatalf("%s = %q, want only the edit made before the removal", l.target, got)
	}
	if denied := driver.DeniedSubjects(); len(denied) != 1 {
		t.Fatalf("DeniedSubjects = %+v, want the edit made after the removal", denied)
	}
	if allows := diskModeAutoAllows(t, result); len(allows) != 1 {
		t.Fatalf("mode_auto matches on disk = %+v, want only the edit made before the removal", allows)
	}
}

func TestRunHeadless_AFolderAddedMidRunAllowsTheNextEdit(t *testing.T) {
	result, l := writableHeadlessRun(t, true, func(string) string { return writableFoldersYAML() }, constrainedLaunch)
	client := settingsEditingClient(t,
		settingsRound{call: writableEditCall(t, l.target, "old", "mid")},
		settingsRound{edit: settingsEdit(projectSettingsPath(l.project), declaringWritableFolder(l.folder)), call: writableEditCall(t, l.target, "old", "new")},
	)
	driver, _ := runWritableHeadless(t, result, client)

	if got := mustReadFile(t, l.target); got != "new\n" {
		t.Fatalf("%s = %q, want only the edit made after the addition", l.target, got)
	}
	if denied := driver.DeniedSubjects(); len(denied) != 1 {
		t.Fatalf("DeniedSubjects = %+v, want the edit made before the addition", denied)
	}
	want := events.PermissionMatched{SubjectKind: "tool", Subject: filetools.EditToolName, PathScope: l.folder, Outcome: "once", OutcomeSource: "mode_auto"}
	if allows := diskModeAutoAllows(t, result); len(allows) != 1 || allows[0] != want {
		t.Fatalf("mode_auto matches on disk = %+v, want exactly %+v", allows, want)
	}
}

func TestRunHeadless_ADeletedProjectSettingsFileWithdrawsFoldersButKeepsBlockedEntries(t *testing.T) {
	secret := filepath.Join(declaredScopeDir(t), "secret.txt")
	result, l := writableHeadlessRun(t, true, func(folder string) string { return blockedYAML(secret) + writableFoldersYAML(folder) }, constrainedLaunch)
	file := projectSettingsPath(l.project)
	content := mustReadFile(t, file)
	client := settingsEditingClient(t,
		settingsRound{call: writableEditCall(t, l.target, "old", "mid")},
		settingsRound{edit: func() error { return os.Remove(file) }, call: writableEditCall(t, l.target, "mid", "new")},
		settingsRound{edit: func() error { return os.WriteFile(file, []byte(content), 0o600) }, call: writableEditCall(t, l.target, "mid", "new")},
	)
	driver, stderr := runWritableHeadless(t, result, client)

	if got, want := capabilityLines(stderr), []string{"sandbox: on"}; !slices.Equal(got, want) {
		t.Fatalf("capability lines = %q, want %q: deleting a healthy file must not mark the settings broken", got, want)
	}
	if !slices.ContainsFunc(driver.authorizer.blocked.Entries(), func(e permissions.BlockedEntry) bool { return e.Path == secret }) {
		t.Fatalf("blocked entries = %+v, want %s kept", driver.authorizer.blocked.Entries(), secret)
	}
	if got := mustReadFile(t, l.target); got != "new\n" {
		t.Fatalf("%s = %q, want the first and restored edits applied", l.target, got)
	}
	if denied := driver.DeniedSubjects(); len(denied) != 1 {
		t.Fatalf("DeniedSubjects = %+v, want only the edit made while the file was deleted", denied)
	}
	if allows := diskModeAutoAllows(t, result); len(allows) != 2 {
		t.Fatalf("mode_auto matches on disk = %+v, want the edits before the deletion and after the restore", allows)
	}
}

func TestHeadlessAuthorizer_ConcurrentDistinctAuthorizationsShareTheLiveReader(t *testing.T) {
	l := gateWritableLaunch(t, declaredScopeDir(t), declaredScopeDir(t), true, declaringWritableFolder)
	cache, err := config.NewCache(l.composition.Config, l.project, l.layerPaths, l.home)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	store := mkStore(t)
	auth := newHeadlessAuthorizer(cache, func() *sessions.Store { return store }, mode.NewActiveState(mode.AutoEdits, mode.SourceConfig), nil, &recordingNotices{})
	auth.executionConstrained = true
	auth.blocked = mustProtectedStatePolicy(t, l.home, l.project, l.layers).Blocked
	var wg sync.WaitGroup
	for i, req := range distinctWritableRequests(t, l, 8) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if dec, err := auth.Authorize(context.Background(), req.Req, req.Display, req.ModeCtx); err != nil || dec.Outcome != "once" {
				t.Errorf("authorization %d = %+v, %v; want an allow", i, dec, err)
			}
		}()
	}
	wg.Wait()
}

func recordGroupAnswer(t *testing.T, journal string, choice subagent.Choice, adopted map[string]map[string]any) {
	t.Helper()
	record := filepath.Join(journal, "journal.json")
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("read the journal record: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var rec map[string]any
	if err := dec.Decode(&rec); err != nil {
		t.Fatalf("decode the journal record: %v", err)
	}
	move := rec["moves"].([]any)[0].(map[string]any)
	endpoints := []any{move["source"], move["destination"]}
	answer := map[string]any{"members": []any{move["id"]}, "endpoints": endpoints, "choice": choice}
	if adopted != nil {
		var states []any
		for _, path := range endpoints {
			state := adopted[path.(string)]
			states = append(states, map[string]any{"path": path, "state": state})
			for _, pr := range rec["paths"].([]any) {
				if pr := pr.(map[string]any); pr["path"] == path {
					pr["last_known"] = state
				}
			}
		}
		answer["adopted"] = states
	}
	rec["answers"] = []any{answer}
	out, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("encode the journal record: %v", err)
	}
	if err := os.WriteFile(record, out, 0o600); err != nil {
		t.Fatalf("write the journal record: %v", err)
	}
}

func TestHeadlessFreshSteps_RecoverJournals_HoldsAnUnansweredGroupAndReplaysARecordedAnswer(t *testing.T) {
	prevStdin, prevIsTerminal := os.Stdin, stdinIsTerminal
	stdinIsTerminal = func(io.Reader) bool { return true }
	t.Cleanup(func() { os.Stdin, stdinIsTerminal = prevStdin, prevIsTerminal })
	launch := func(t *testing.T, home, project string) string {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		defer r.Close() //nolint:errcheck // test pipe
		if _, err := w.WriteString("k\n"); err != nil {
			t.Fatalf("stage stdin: %v", err)
		}
		_ = w.Close()
		os.Stdin = r

		var stderr bytes.Buffer
		HeadlessFreshSteps(&stderr, nil, "").RecoverJournals(home, project, map[string]any{}, trust.Decision{})

		if rest, err := io.ReadAll(r); err != nil || string(rest) != "k\n" {
			t.Fatalf("stdin left = %q (err=%v), want a headless launch to read none of it", rest, err)
		}
		if strings.Contains(stderr.String(), "decide later?") {
			t.Fatalf("stderr = %q, want no question on a headless launch", stderr.String())
		}
		return stderr.String()
	}
	staged := func(t *testing.T) (home, project, a, b, journal string) {
		t.Helper()
		home, project = realPath(t, t.TempDir()), realPath(t, t.TempDir())
		writeGlobalSettings(t, home, blockedYAML(), 0o600)
		a, b = filepath.Join(project, "a.txt"), filepath.Join(project, "b.txt")
		if err := os.WriteFile(a, []byte("ORIGINAL\n"), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
		journal = orphanedMoveJournal(t, home, project, nil, permissions.MovePair{Source: a, Destination: b})
		if err := os.WriteFile(b, []byte("A THIRD WRITER\n"), 0o644); err != nil {
			t.Fatalf("change the destination: %v", err)
		}
		return home, project, a, b, journal
	}
	journalKept := func(t *testing.T, journal string, want bool) {
		t.Helper()
		if _, err := os.Stat(journal); (err == nil) != want {
			t.Fatalf("stat %s: %v, want the journal kept = %v", journal, err, want)
		}
	}

	t.Run("an unanswered group stays held", func(t *testing.T) {
		home, project, a, b, journal := staged(t)

		stderr := launch(t, home, project)

		assertFileContent(t, a, "")
		assertFileContent(t, b, "A THIRD WRITER\n")
		journalKept(t, journal, true)
		if !strings.Contains(stderr, "move not undone: "+a+" -> "+b+" (") || !strings.Contains(stderr, "codemeld asks what to do with these moves the next time you start it here interactively") {
			t.Fatalf("stderr = %q, want the held moves reported for an interactive launch", stderr)
		}
	})

	t.Run("a recorded keep is finished", func(t *testing.T) {
		home, project, a, b, journal := staged(t)
		recordGroupAnswer(t, journal, subagent.ChoiceKeep, nil)

		launch(t, home, project)

		assertFileContent(t, a, "")
		assertFileContent(t, b, "A THIRD WRITER\n")
		journalKept(t, journal, false)
	})

	t.Run("a recorded restore waits for policy and is then finished", func(t *testing.T) {
		home, project, a, b, journal := staged(t)
		recordGroupAnswer(t, journal, subagent.ChoiceRestore, map[string]map[string]any{
			a: {"exists": false},
			b: {"exists": true, "data": []byte("A THIRD WRITER\n"), "mode": os.FileMode(0o644)},
		})
		writeGlobalSettings(t, home, blockedYAML(b), 0o600)

		stderr := launch(t, home, project)

		assertFileContent(t, a, "")
		assertFileContent(t, b, "A THIRD WRITER\n")
		journalKept(t, journal, true)
		if !strings.Contains(stderr, "a blocked path is involved: "+b) {
			t.Fatalf("stderr = %q, want the block named", stderr)
		}
		writeGlobalSettings(t, home, blockedYAML(), 0o600)

		stderr = launch(t, home, project)

		assertFileContent(t, a, "ORIGINAL\n")
		assertFileContent(t, b, "")
		journalKept(t, journal, false)
		if !strings.Contains(stderr, "put back: "+a+"\n") {
			t.Fatalf("stderr = %q, want the restored path named", stderr)
		}
	})
}

func TestHeadlessAuthorizer_DeniedCallRecordsExceptional(t *testing.T) {
	cases := []struct {
		name        string
		configure   func(*headlessAuthorizer)
		exceptional bool
	}{
		{"constrained auto edits", func(*headlessAuthorizer) {}, true},
		{"build", func(a *headlessAuthorizer) { a.modeActive.ApplyUserCommand(mode.Build) }, false},
		{"unconstrained auto edits", func(a *headlessAuthorizer) { a.executionConstrained = false }, false},
	}
	for _, tc := range cases {
		for _, name := range []string{"direct", "literal"} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				auth, cwd := exceptionalHeadlessAuthorizer(t, "", nil)
				tc.configure(auth)
				call := exceptionalCalls(cwd)[name]
				dec, err := auth.Authorize(context.Background(), call.req, call.disp, call.modeCtx)
				if err != nil || dec.DenyEnvelope == "" {
					t.Fatalf("Authorize = %+v, %v; want a deny", dec, err)
				}
				denied := auth.deniedSubjects()
				if len(denied) != 1 {
					t.Fatalf("denied = %+v, want one record", denied)
				}
				if denied[0].Exceptional != tc.exceptional || denied[0].TerminalApprover {
					t.Fatalf("denied = %+v, want Exceptional=%v and no terminal approver", denied[0], tc.exceptional)
				}
			})
		}
	}
}

func TestHeadlessAuthorizer_TerminalDeniedExceptionalRecordsApprover(t *testing.T) {
	for _, name := range []string{"direct", "literal"} {
		t.Run(name, func(t *testing.T) {
			auth, cwd := exceptionalHeadlessAuthorizer(t, "2\n", &bytes.Buffer{})
			call := exceptionalCalls(cwd)[name]
			dec, err := auth.Authorize(context.Background(), call.req, call.disp, call.modeCtx)
			if err != nil || dec.DenyEnvelope == "" {
				t.Fatalf("Authorize = %+v, %v; want a deny", dec, err)
			}
			denied := auth.deniedSubjects()
			if len(denied) != 1 || !denied[0].Exceptional || !denied[0].TerminalApprover {
				t.Fatalf("denied = %+v, want one exceptional record with a terminal approver", denied)
			}
		})
	}
}

func gatedStdin() (in io.Reader, reading chan struct{}, answers chan string) {
	reading = make(chan struct{}, 8)
	answers = make(chan string)
	in = readerFunc(func(p []byte) (int, error) {
		reading <- struct{}{}
		line, ok := <-answers
		if !ok {
			return 0, io.EOF
		}
		return copy(p, line), nil
	})
	return in, reading, answers
}

func promptWaitRunHeadless(t *testing.T, ctx context.Context, stdin io.Reader) (*sessions.Store, string, error) {
	t.Helper()
	dir := t.TempDir()
	notes := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notes, []byte("keep\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-0000000000b7", dir)
	client := toolThenContentClient(nil, "bash", `{"command":"rm notes.txt"}`, "ok")
	t.Cleanup(swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client }))

	driver := NewHeadlessDriver("delete my notes", &bytes.Buffer{}, &bytes.Buffer{})
	driver.SetSessionTitle("prompt wait")
	driver.EnablePromptForApproval(stdin)
	_, err := RunHeadless(ctx, dir, titledHeadlessSteps(t, dir, store), driver)
	return store, notes, err
}

func TestRunHeadless_PromptApprovalRecordsTheWaitOnDisk(t *testing.T) {
	store, notes, err := promptWaitRunHeadless(t, context.Background(), strings.NewReader("1\n"))
	if err != nil {
		t.Fatalf("RunHeadless: %v", err)
	}
	if _, err := os.Stat(notes); !os.IsNotExist(err) {
		t.Fatalf("notes.txt still present after allow once: stat err = %v", err)
	}
	waits := decodeDiskEvents[events.PermissionPromptWait](t, readSessionFile(t, store.Path()), events.KindPermissionPromptWait)
	if len(waits) != 1 || waits[0].Ended != "answered" || waits[0].Prompts != 1 {
		t.Fatalf("persisted prompt waits = %+v, want one answered wait for one request", waits)
	}
}

func TestRunHeadless_CancelledTerminalPromptWaitSurvivesTheFinalFlush(t *testing.T) {
	stdin, reading, answers := gatedStdin()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-reading
		cancel()
		answers <- "1\n"
	}()
	store, notes, err := promptWaitRunHeadless(t, ctx, stdin)
	if err != nil {
		t.Fatalf("RunHeadless: %v, want a clean interrupt after the final flush", err)
	}
	if _, statErr := os.Stat(notes); statErr != nil {
		t.Fatalf("notes.txt was removed by an answer read after cancellation: %v", statErr)
	}
	waits := decodeDiskEvents[events.PermissionPromptWait](t, readSessionFile(t, store.Path()), events.KindPermissionPromptWait)
	if len(waits) != 1 || waits[0].Ended != "cancelled" || waits[0].Prompts != 1 {
		t.Fatalf("persisted prompt waits = %+v, want one cancelled wait", waits)
	}
}

func editAuthorize(ctx context.Context, auth *headlessAuthorizer, target string) (permissions.Decision, error) {
	return auth.Authorize(ctx,
		permissions.MatchRequest{Kind: "tool", Subject: filetools.EditToolName, PathScope: target},
		dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: filetools.EditToolName},
		permissions.ModeContext{Class: permissions.ClassMutating, ToolName: filetools.EditToolName, TargetPath: target})
}

func TestHeadlessAuthorizer_QueuedPromptCancelRecordsItsOwnWait(t *testing.T) {
	dir := t.TempDir()
	store := mkStore(t)
	stdin, reading, answers := gatedStdin()
	auth := newHeadlessAuthorizer(emptyCache(t, dir), func() *sessions.Store { return store },
		mode.NewActiveState(mode.Build, mode.SourceDefault), newTerminalPrompter(stdin, &bytes.Buffer{}), &recordingNotices{})

	type result struct {
		dec permissions.Decision
		err error
	}
	authorize := func(ctx context.Context, name string) chan result {
		out := make(chan result, 1)
		go func() {
			dec, err := editAuthorize(ctx, auth, filepath.Join(dir, name))
			out <- result{dec, err}
		}()
		return out
	}
	waits := func() []events.PermissionPromptWait {
		return decodeStoreEvents[events.PermissionPromptWait](t, store, events.KindPermissionPromptWait)
	}

	first := authorize(context.Background(), "a.txt")
	<-reading
	queuedCtx, cancelQueued := context.WithCancel(context.Background())
	defer cancelQueued()
	queued := authorize(queuedCtx, "b.txt")
	waitForPromptShown(store, 2, 5*time.Second)
	if n := countPermissionEvents(store, events.KindPermissionPromptShown); n != 2 {
		t.Fatalf("permission_prompt_shown = %d, want the queued request to have reached its prompt", n)
	}
	cancelQueued()
	if r := <-queued; !errors.Is(r.err, context.Canceled) {
		t.Fatalf("queued request err = %v, want context.Canceled", r.err)
	}
	if len(reading) != 0 {
		t.Fatal("the cancelled queued request read stdin")
	}
	if w := waits(); len(w) != 1 || w[0].Ended != "cancelled" || w[0].Prompts != 1 {
		t.Fatalf("waits after the queued cancel = %+v, want one cancelled wait", w)
	}
	if n := countPermissionEvents(store, events.KindPermissionDecision); n != 0 {
		t.Fatalf("permission_decision = %d while the first prompt is open, want none", n)
	}

	answers <- "1\n"
	if r := <-first; r.err != nil || r.dec.DenyEnvelope != "" {
		t.Fatalf("first request = %+v / %v, want allowed", r.dec, r.err)
	}
	w := waits()
	if len(w) != 2 || w[1].Ended != "answered" || w[1].Prompts != 1 {
		t.Fatalf("waits after the first answer = %+v, want the cancelled wait then one answered wait", w)
	}

	third := authorize(context.Background(), "c.txt")
	<-reading
	answers <- "1\n"
	if r := <-third; r.err != nil || r.dec.DenyEnvelope != "" {
		t.Fatalf("request after the cancel = %+v / %v, want the gate usable and the call allowed", r.dec, r.err)
	}
	if n := countPermissionEvents(store, events.KindPermissionDecision); n != 2 {
		t.Fatalf("permission_decision = %d, want one per answered request and none for the cancelled one", n)
	}
}

func TestHeadlessAuthorizer_UnattendedDenyRecordsNoWait(t *testing.T) {
	for _, child := range []bool{false, true} {
		t.Run(fmt.Sprintf("child=%v", child), func(t *testing.T) {
			dir := t.TempDir()
			store := mkStore(t)
			auth := newHeadlessAuthorizer(emptyCache(t, dir), func() *sessions.Store { return store },
				mode.NewActiveState(mode.Build, mode.SourceDefault), nil, &recordingNotices{})
			if child {
				auth.childAgent = true
				auth.childInvocationID = "01890000-0000-7000-8000-0000000000c1"
			}
			dec, err := auth.Authorize(context.Background(),
				permissions.MatchRequest{Kind: "direct", Subject: "rm", SubjectTokens: []string{"rm"}, PathScope: dir},
				dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: "rm"},
				permissions.ModeContext{Class: permissions.ClassMutating})
			if err != nil || dec.DenyEnvelope == "" {
				t.Fatalf("Authorize = %+v / %v, want an unattended deny", dec, err)
			}
			kinds := permissionEventKinds(store)
			if !slices.Equal(kinds, []string{events.KindPermissionPromptShown, events.KindPermissionDecision}) {
				t.Fatalf("event stream = %v, want prompt_shown and decision with no prompt wait", kinds)
			}
		})
	}
}
