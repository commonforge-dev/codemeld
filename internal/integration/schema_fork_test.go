// Integration test for the older-schema /resume → read-only + text-only fork flow:
// it drives the landed /resume handler over an older-schema
// selection and wires its OlderSchemaForker seam to the real fork primitive,
// agent-instruction replay, and the in-memory model carry-forward, asserting
// the in-process switch ordering, file writes, event replay, and model-state
// carry-forward compose correctly across packages.
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/locks"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/sessionfork"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// Valid UUIDv7 ids for the older-schema fixture. The fork copies message ids
// verbatim, so they must round-trip the spine validation when the forked
// file is read back.
const (
	activeID   = "0190c0de-0000-7000-8000-0000000000e0"
	fixtureID  = "0190c0de-0000-7000-8000-0000000000f1"
	idUser     = "0190c0de-0000-7000-8000-0000000000f2"
	idAsst     = "0190c0de-0000-7000-8000-0000000000f3"
	idTool     = "0190c0de-0000-7000-8000-0000000000f4"
	idSystem   = "0190c0de-0000-7000-8000-0000000000f5"
	idAsstBare = "0190c0de-0000-7000-8000-0000000000f6"
	idEvent    = "0190c0de-0000-7000-8000-0000000000f7"
)

const (
	// olderSchemaVersion is the fixture's metadata.schema_version: a parseable
	// integer >= 1 (values < 1, including 0, classify as unparseable —
	// NOT fork-eligible). Production ReaderSupportedVersion is still 1, so no
	// on-disk value classifies as older through the public reader; the fixture
	// stands in for an older file under a notional reader supporting
	// notionalSupported, and the older-fork-eligible classification is supplied
	// through the TargetLoader seam rather than by changing the
	// production constant.
	olderSchemaVersion = 1
	notionalSupported  = 2
)

var (
	fixtureFolder    = "/proj/demo"
	fixtureStartedAt = time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC)
	// originalModel is the originally-active run's in-memory model selection. The
	// fork carries it forward unchanged (no run-start model recovery on the
	// text-only file).
	originalModel = model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: "medium"}
)

// --- older-schema fixture ---------------------------------------------------

func textPart(s string) sessions.ContentPart {
	return sessions.ContentPart{Type: "text", Raw: json.RawMessage(`{"type":"text","text":"` + s + `"}`)}
}

func imagePart() sessions.ContentPart {
	return sessions.ContentPart{Type: "image_url", Raw: json.RawMessage(`{"type":"image_url","image_url":{"url":"http://x"}}`)}
}

// olderSession builds the older-schema fixture carrying every record shape a fork
// must filter (task step 1): user/assistant/system text, an assistant turn with
// tool_calls, a tool message, a list with a non-text part, and an event.
func olderSession() *sessions.Session {
	ts := func(sec int) time.Time { return fixtureStartedAt.Add(time.Duration(sec) * time.Second) }
	return &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            fixtureID,
			Folder:        fixtureFolder,
			StartedAt:     fixtureStartedAt,
			UpdatedAt:     fixtureStartedAt,
			SchemaVersion: olderSchemaVersion,
		},
		Records: []sessions.Record{
			sessions.Message{ID: idUser, Role: "user", Content: sessions.TextContent("hi"), Timestamp: ts(0)},
			sessions.Message{
				ID:        idAsst,
				Role:      "assistant",
				Content:   sessions.PartsContent([]sessions.ContentPart{textPart("hello"), imagePart()}),
				Timestamp: ts(1),
				ToolCalls: []sessions.ToolCall{{ID: "call_1", Type: "function", Raw: json.RawMessage(`{"id":"call_1","type":"function","function":{"name":"ls","arguments":"{}"}}`)}},
			},
			sessions.Message{ID: idTool, Role: "tool", Content: sessions.TextContent("result"), Timestamp: ts(2), ToolCallID: "call_1"},
			sessions.Message{ID: idSystem, Role: "system", Content: sessions.TextContent("sys"), Timestamp: ts(3)},
			sessions.Message{
				ID:        idAsstBare,
				Role:      "assistant",
				Content:   sessions.PartsContent([]sessions.ContentPart{imagePart()}),
				Timestamp: ts(4),
			},
			sessions.Event{ID: idEvent, Kind: events.KindLaunchBegan, Timestamp: ts(5), Payload: json.RawMessage(`{"source":"fresh"}`)},
		},
	}
}

// --- ResumeDeps fakes (the /resume seam) -----------------------------------
//
// All of the /resume handler's injectable capabilities are stubbed here except OlderSchemaForker,
// which is wired to the real fork composition. The counting stubs let the test
// prove the older-schema path bypasses the equal-schema switch sub-sequence:
// stream cancel, lock handoff, updated_at refresh, and
// model recovery must never run against the older file.

type stubLister struct{ entries []tui.ResumeEntry }

func (l stubLister) List() ([]tui.ResumeEntry, []sessions.SkippedID, error) {
	return l.entries, nil, nil
}

// stubPicker drives the /resume continuation synchronously: Present invokes the result
// callback immediately with the preset choice, so the on-selection switch sequence
// runs during dispatch and the test can assert its effects right after.
type stubPicker struct {
	result    tui.PickerResult
	presented int
}

func (p *stubPicker) Present(entries []tui.ResumeEntry, onResult func(tui.PickerResult), _ tui.ResumeActions) {
	p.presented++
	onResult(p.result)
}

func (p *stubPicker) PresentEmpty(message string, onDismiss func()) { onDismiss() }

type countStream struct{ calls int }

func (s *countStream) Cancel() (int, bool) { s.calls++; return 0, false }

type stubLoader struct {
	target *sessions.Store
	older  bool
	calls  int
}

func (l *stubLoader) Load(entry tui.ResumeEntry) (*sessions.Store, bool, fserrors.Category, error) {
	l.calls++
	return l.target, l.older, "", nil
}

type countSwitch struct {
	calls         int
	activateCalls int
}

func (s *countSwitch) Switch(target, prior *sessions.Store) error { s.calls++; return nil }

func (s *countSwitch) Activate(target *sessions.Store) (string, error) {
	s.activateCalls++
	return "", nil
}

type countRefresher struct{ calls int }

func (r *countRefresher) Refresh(_ context.Context, target *sessions.Store) error {
	r.calls++
	return nil
}

type countRecoverer struct{ calls int }

func (m *countRecoverer) Recover(target *sessions.Store) error { m.calls++; return nil }

type countReplayer struct{ calls int }

func (a *countReplayer) Replay(target *sessions.Store) error { a.calls++; return nil }

type countWriteFailure struct{ calls int }

func (w *countWriteFailure) Handle(reason sessions.WriteReason, cat fserrors.Category, path string, detail error, store *sessions.Store) error {
	w.calls++
	return nil
}

// forkOrchestrator is the integration's OlderSchemaForker: it presents the
// read-only view from the older session's stable spine, then runs the one-shot
// fork by composing the landed primitives — ForkSession (text-only copy +
// launch_began{fork} + session_forked + seal), agent-instruction replay from
// the in-memory load record, and the in-memory model carry-forward (no
// recovery on the text-only file). The production wiring of this seam is deferred
// (as the equal-schema resume path's wiring was); this test verifies the
// primitives compose into the fork behavior.
type forkOrchestrator struct {
	ctx      context.Context
	home     string
	original *sessions.Session
	entries  []agentinstr.LoadEntry
	active   *model.ActiveState

	offered  bool
	view     sessions.MetadataSnapshot
	newStore *sessions.Store
	err      error
	wfCalls  int
}

func (o *forkOrchestrator) recordWriteFailure(_ fserrors.Category, _ sessions.WriteReason, _ error) {
	o.wfCalls++
}

func (o *forkOrchestrator) OfferFork(target *sessions.Store) error {
	// (step 2) The read-only view is built from the older session's stable spine
	// fields (id, folder, started_at), never from a lock acquisition or a write.
	o.offered = true
	o.view = target.MetadataSnapshot()

	// (step 3) Trigger the fork. ForkSession filters to text-only records, creates
	// the new current-schema file, emits launch_began{fork}, then appends
	// session_forked to the original and seals it. On a pre-create/flush failure it
	// returns the error unchanged with the original left open, so the user stays on
	// the read-only view with the fork action still available.
	newStore, err := sessionfork.ForkSession(o.ctx, o.home, o.original, target, o.recordWriteFailure)
	if err != nil {
		o.err = err
		return err
	}
	o.newStore = newStore

	// Replay the in-memory AGENTS.md load record as fresh agent_instructions_loaded
	// events on the new session, after launch_began{fork} (no disk
	// re-walk).
	if err := agentinstr.Replay(newStore, o.entries); err != nil {
		o.err = err
		return err
	}

	// Carry the originally-active model selection forward; the text-only fork does
	// not run recovery (its record stream has no model history).
	o.active.CarryForward()

	// Make the replayed records durable before returning control.
	if _, _, err := newStore.Flush(o.ctx); err != nil {
		o.err = err
		return err
	}
	return nil
}

// --- CommandHost ------------------------------------------------------------

// forkHost is the /resume CommandHost: it exposes the originally-active session store
// and a notice sink, and flushes the active session for the command-
// event flush. ShowPanel/ShowStatus are unused by /resume.
type forkHost struct {
	store   *sessions.Store
	notices []string
}

func (h *forkHost) Notice(text string)     { h.notices = append(h.notices, text) }
func (h *forkHost) Store() *sessions.Store { return h.store }
func (h *forkHost) ShowPanel(string)       {}
func (h *forkHost) ShowStatus(string)      {}
func (h *forkHost) FlushActive() error {
	_, _, err := h.store.Flush(context.Background())
	return err
}

// --- world setup ------------------------------------------------------------

type forkWorld struct {
	home    string
	older   *sessions.Session
	target  *sessions.Store // the older session selected for fork ("original" of the fork)
	prior   *sessions.Store // the originally-active session
	active  *model.ActiveState
	host    *forkHost
	orch    *forkOrchestrator
	stream  *countStream
	loader  *stubLoader
	sw      *countSwitch
	refresh *countRefresher
	recover *countRecoverer
	replay  *countReplayer
	wf      *countWriteFailure
	deps    tui.ResumeDeps
}

// newForkWorld wires the older-schema fixture, the originally-active session, the
// in-memory model state and AGENTS.md record, and the /resume ResumeDeps with the real
// fork orchestrator. home locates the new forked file; pass a broken home to drive
// the fork-failure path.
func newForkWorld(t *testing.T, home string) *forkWorld {
	t.Helper()

	older := olderSession()
	// The target store wraps the same *Session the orchestrator forks, so the
	// session_forked append and seal land on exactly the selected file.
	target := sessions.New(filepath.Join(t.TempDir(), "older.json"), older)
	// Persist the older fixture file so it exists on disk before the fork and the
	// on-disk session_forked marker is observable afterward (task step 1).
	if _, _, err := target.Flush(context.Background()); err != nil {
		t.Fatalf("flush older fixture: %v", err)
	}

	prior := sessions.New(filepath.Join(t.TempDir(), "active.json"), &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            activeID,
			Folder:        fixtureFolder,
			StartedAt:     fixtureStartedAt,
			UpdatedAt:     fixtureStartedAt,
			SchemaVersion: sessions.CurrentSchemaVersion,
		},
	})

	active := model.NewActiveState(&originalModel, model.SourceResume)

	host := &forkHost{store: prior}
	orch := &forkOrchestrator{
		ctx:      context.Background(),
		home:     home,
		original: older,
		entries:  []agentinstr.LoadEntry{{Path: "/g/AGENTS.md", Layer: agentinstr.LayerGlobal, LoadOrder: 1, Content: []byte("be helpful")}},
		active:   active,
	}

	w := &forkWorld{
		home:    home,
		older:   older,
		target:  target,
		prior:   prior,
		active:  active,
		host:    host,
		orch:    orch,
		stream:  &countStream{},
		loader:  &stubLoader{target: target, older: true},
		sw:      &countSwitch{},
		refresh: &countRefresher{},
		recover: &countRecoverer{},
		replay:  &countReplayer{},
		wf:      &countWriteFailure{},
	}
	w.deps = tui.ResumeDeps{
		Lister:       stubLister{entries: []tui.ResumeEntry{{ID: fixtureID, Preview: "older session"}}},
		Picker:       &stubPicker{result: tui.PickerResult{Selected: true, Index: 0}},
		Stream:       w.stream,
		Loader:       w.loader,
		Switch:       w.sw,
		Refresh:      w.refresh,
		Model:        w.recover,
		Agents:       w.replay,
		Fork:         w.orch,
		WriteFailure: w.wf,
	}
	return w
}

// dispatch runs "/resume" through a registry bound to the real handler.
func (w *forkWorld) dispatch(t *testing.T) tui.DispatchResult {
	t.Helper()
	reg, err := tui.NewRegistry([]tui.Command{{
		Name:        "resume",
		Description: "Open the session picker to resume a session",
		ArgSig:      tui.ArgNone,
		Phase:       tui.PhaseOne,
		Handler:     tui.NewResumeHandler(w.deps),
	}})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return reg.DispatchSlashInput("/resume", w.host)
}

// --- tests ------------------------------------------------------------------

// TestSchemaFork_OlderResumeRoutesReadOnlyThenForks covers task steps 2 and 3:
// selecting an older-schema session in the /resume picker routes to the read-only
// view + fork action (bypassing the lock handoff, updated_at refresh, model
// recovery, and stream cancellation) while the originally-active session stays
// active, then the fork produces the text-only copy with the required metadata,
// dropped records, event order, session_forked marker, and model carry-forward.
func TestSchemaFork_OlderResumeRoutesReadOnlyThenForks(t *testing.T) {
	w := newForkWorld(t, t.TempDir())
	beforeSel, beforeSrc, beforeOK := w.active.Current()

	res := w.dispatch(t)
	if res.Status != tui.StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /resume = %+v, want Handled/nil-err", res)
	}

	// (step 2) The older selection was classified, then routed to the read-only +
	// fork affordance.
	if w.loader.calls != 1 {
		t.Errorf("loader calls = %d, want 1 (target classified before any switch)", w.loader.calls)
	}
	if !w.orch.offered {
		t.Fatal("the read-only + fork affordance was not offered for an older-schema selection")
	}
	// (step 2) The read-only view is built from the older session's stable spine.
	if w.orch.view.ID != fixtureID || w.orch.view.Folder != fixtureFolder || !w.orch.view.StartedAt.Equal(fixtureStartedAt) {
		t.Errorf("read-only view spine = %+v, want id=%s folder=%s started_at=%s",
			w.orch.view, fixtureID, fixtureFolder, fixtureStartedAt)
	}
	// (step 2) No lock acquisition, updated_at refresh, model recovery, or stream
	// cancellation runs against the older file (bypasses that sub-sequence).
	if w.sw.calls != 0 || w.refresh.calls != 0 || w.recover.calls != 0 || w.stream.calls != 0 {
		t.Errorf("equal-schema sub-sequence ran for an older selection: switch=%d refresh=%d recover=%d streamCancel=%d",
			w.sw.calls, w.refresh.calls, w.recover.calls, w.stream.calls)
	}
	if w.replay.calls != 0 {
		t.Errorf("resume-path agent replayer ran for an older selection: %d", w.replay.calls)
	}
	// (step 2) The originally-active session stays active in the background and
	// still accepts appends.
	if w.host.Store() != w.prior {
		t.Error("active store changed for an older-schema selection")
	}
	assertAppendable(t, w.prior, "originally-active session")

	// (step 3) The fork created a new session file.
	if w.orch.newStore == nil {
		t.Fatal("fork produced no new session store")
	}
	forked := readSession(t, w.orch.newStore.Path())

	// (step 3) Metadata: fresh UUIDv7 id, copied folder + started_at, fresh
	// updated_at, current schema version.
	newID := w.orch.newStore.SessionID()
	if newID == fixtureID {
		t.Errorf("forked id %q equals the original id, want a fresh id", newID)
	}
	if forked.Metadata.ID != newID {
		t.Errorf("forked file id = %q, want %q", forked.Metadata.ID, newID)
	}
	if forked.Metadata.Folder != fixtureFolder {
		t.Errorf("forked folder = %q, want copied %q", forked.Metadata.Folder, fixtureFolder)
	}
	if !forked.Metadata.StartedAt.Equal(fixtureStartedAt) {
		t.Errorf("forked started_at = %s, want copied %s", forked.Metadata.StartedAt, fixtureStartedAt)
	}
	if forked.Metadata.SchemaVersion != sessions.CurrentSchemaVersion {
		t.Errorf("forked schema_version = %d, want %d", forked.Metadata.SchemaVersion, sessions.CurrentSchemaVersion)
	}
	if !forked.Metadata.UpdatedAt.After(fixtureStartedAt) {
		t.Errorf("forked updated_at = %s, want refreshed past started_at %s", forked.Metadata.UpdatedAt, fixtureStartedAt)
	}

	// (step 3) Content: only user/assistant/system text messages survive — tool
	// messages, copied events, tool_calls/tool_call_id, and non-text parts are
	// dropped.
	msgs, evs := splitRecords(t, forked.Records)
	wantMsgIDs := []string{idUser, idAsst, idSystem, idAsstBare}
	if len(msgs) != len(wantMsgIDs) {
		t.Fatalf("forked messages = %d, want %d (text messages only)", len(msgs), len(wantMsgIDs))
	}
	for i, want := range wantMsgIDs {
		m := msgs[i]
		if m.ID != want {
			t.Errorf("forked message %d id = %q, want %q", i, m.ID, want)
		}
		if m.Role == "tool" {
			t.Errorf("forked message %d kept a tool role", i)
		}
		if len(m.ToolCalls) != 0 || m.ToolCallID != "" {
			t.Errorf("forked message %d kept tool_calls/tool_call_id, want stripped", i)
		}
		if m.Content.IsList() {
			for _, p := range m.Content.Parts() {
				if p.Type != "text" {
					t.Errorf("forked message %d kept a non-text part %q", i, p.Type)
				}
			}
		}
	}
	// The text-and-image assistant turn keeps its single text part; the image-only
	// assistant turn stays an empty list (its content shape survives).
	if got := msgs[1].Content; !got.IsList() || len(got.Parts()) != 1 {
		t.Errorf("assistant content = %+v, want a one-part text list", got)
	}
	if got := msgs[3].Content; !got.IsList() || len(got.Parts()) != 0 {
		t.Errorf("image-only assistant content = %+v, want an empty list", got)
	}

	// (step 3) Events: exactly launch_began{fork} then agent_instructions_loaded,
	// in that order. The copied launch_began{fresh} event was dropped.
	if len(evs) != 2 {
		t.Fatalf("forked events = %d (%s), want 2 [launch_began, agent_instructions_loaded]", len(evs), eventKinds(evs))
	}
	if evs[0].Kind != events.KindLaunchBegan || evs[1].Kind != events.KindAgentInstructionsLoaded {
		t.Fatalf("forked event order = %v, want [launch_began, agent_instructions_loaded]", eventKinds(evs))
	}
	var lb events.LaunchBegan
	decodePayload(t, evs[0], &lb)
	if lb.Source != "fork" {
		t.Errorf("launch_began source = %q, want fork", lb.Source)
	}
	var ail events.AgentInstructionsLoaded
	decodePayload(t, evs[1], &ail)
	if ail.Path != "/g/AGENTS.md" || ail.Layer != "global" || ail.LoadOrder != 1 {
		t.Errorf("agent_instructions_loaded = %+v, want the in-memory global record", ail)
	}

	// (step 3) The original gains session_forked{to_session_id=new} as its final
	// record (in memory and on disk) and is sealed against further appends.
	assertSessionForked(t, w.target.Records(), newID, "original (in memory)")
	onDisk := readSession(t, w.target.Path())
	assertSessionForked(t, onDisk.Records, newID, "original (on disk)")
	assertSealed(t, w.target)

	// (step 3) The model selection carried forward unchanged; no recovery
	// ran on the text-only file (asserted above via recover.calls == 0).
	afterSel, afterSrc, afterOK := w.active.Current()
	if !beforeOK || !afterOK || afterSel != beforeSel || afterSrc != beforeSrc {
		t.Errorf("model state = (%+v, %q, %v), want carried forward (%+v, %q, %v)",
			afterSel, afterSrc, afterOK, beforeSel, beforeSrc, beforeOK)
	}
	if afterSel != originalModel || afterSrc != model.SourceResume {
		t.Errorf("carried-forward model = (%+v, %q), want the original (%+v, %q)",
			afterSel, afterSrc, originalModel, model.SourceResume)
	}

	// The fork success path drove no write-failure handler.
	if w.orch.wfCalls != 0 {
		t.Errorf("fork write-failure handler ran %d times on the success path", w.orch.wfCalls)
	}

	rel, reason, err := locks.TryAcquire(sessions.ResumeLockPath(w.orch.newStore.Path()))
	if err != nil {
		t.Fatalf("probe forked child sidecar: %v", err)
	}
	if reason != locks.ReasonNone || rel == nil {
		if rel != nil {
			rel()
		}
		t.Fatalf("forked child sidecar reason = %q, want released (%q)", reason, locks.ReasonNone)
	}
	rel()
}

// TestSchemaFork_ForkFailureKeepsReadOnlyView covers task step 4: a fork that
// cannot create the new file leaves the user on the read-only view with the fork
// action still available, appends no session_forked to the original, and creates
// no durable new-session file. The failure is induced by a fake filesystem fixture
// (a regular file where the sessions root must be a directory) so it is observable
// even when the test runs as root — unlike the chmod-based write-failure path,
// which sessionfork's own fork_test already covers and skips under root.
func TestSchemaFork_ForkFailureKeepsReadOnlyView(t *testing.T) {
	home := t.TempDir()
	// Block the sessions root: ~/.codemeld is a regular file, so EnsureFolderDir
	// cannot create <home>/.codemeld/sessions and ForkSession fails before any new
	// file or session_forked append.
	if err := os.WriteFile(filepath.Join(home, ".codemeld"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocking ~/.codemeld file: %v", err)
	}

	w := newForkWorld(t, home)

	res := w.dispatch(t)
	// The switch runs in the picker continuation, so the residual fork error is
	// surfaced as a notice rather than returned to dispatch.
	if res.Status != tui.StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /resume = %+v, want Handled/nil-err", res)
	}

	// The read-only + fork affordance was offered, then the fork failed.
	if !w.orch.offered {
		t.Fatal("the read-only view was not offered before the failing fork")
	}
	var fde *sessions.FolderDirError
	if !errors.As(w.orch.err, &fde) {
		t.Fatalf("fork error = %v, want a *sessions.FolderDirError (pre-create failure)", w.orch.err)
	}
	if w.orch.newStore != nil {
		t.Error("a new session store was produced despite the fork failure")
	}
	// The residual error is surfaced to the user (they stay on the read-only view).
	if len(w.host.notices) == 0 || w.host.notices[len(w.host.notices)-1] != w.orch.err.Error() {
		t.Errorf("notices = %v, want last to surface the fork failure %q", w.host.notices, w.orch.err)
	}

	// No durable new-session file: the sessions root was never created.
	if _, err := os.Stat(sessions.SessionRoot(home)); err == nil {
		t.Errorf("a sessions root was created under a blocked home, want none")
	}

	// The original gained no session_forked event and is still appendable, so the
	// fork action remains available.
	for _, rec := range w.target.Records() {
		if ev, ok := rec.(sessions.Event); ok && ev.Kind == events.KindSessionForked {
			t.Fatal("original gained a session_forked event after a failed fork")
		}
	}
	assertAppendable(t, w.target, "original after failed fork")

	// The originally-active session is untouched and still active.
	if w.host.Store() != w.prior {
		t.Error("active store changed after a failed fork")
	}
	assertAppendable(t, w.prior, "originally-active session after failed fork")

	// No equal-schema sub-sequence ran (the failure is in the fork, not a switch).
	if w.sw.calls != 0 || w.refresh.calls != 0 || w.recover.calls != 0 {
		t.Errorf("equal-schema sub-sequence ran on the older path: switch=%d refresh=%d recover=%d",
			w.sw.calls, w.refresh.calls, w.recover.calls)
	}
}

// TestSchemaFork_OlderFixtureVersionIsParseableNotZero covers Done-when item 1:
// the older-schema fixture uses a parseable version >= 1, never schema_version 0.
// It pins the premise against the real ClassifyVersion contract rather than
// just the fixture literal.
func TestSchemaFork_OlderFixtureVersionIsParseableNotZero(t *testing.T) {
	if olderSchemaVersion < 1 {
		t.Fatalf("fixture schema_version %d is < 1; req 420 treats that as unparseable", olderSchemaVersion)
	}
	if got, err := sessions.ClassifyVersion(olderSchemaVersion); err != nil || got == sessions.StatusUnparseable {
		t.Fatalf("ClassifyVersion(%d) = (%q, %v), want a parseable status", olderSchemaVersion, got, err)
	}
	// schema_version 0 is exactly the value the fixture must avoid.
	if got, _ := sessions.ClassifyVersion(0); got != sessions.StatusUnparseable {
		t.Fatalf("ClassifyVersion(0) = %q, want unparseable (the reason the fixture must not use 0)", got)
	}
	// The fixture is lower than the notional reader the TargetLoader seam stands in for.
	if olderSchemaVersion >= notionalSupported {
		t.Fatalf("fixture schema_version %d is not lower than the notional supported %d", olderSchemaVersion, notionalSupported)
	}
}

// --- assertion helpers ------------------------------------------------------

func readSession(t *testing.T, path string) *sessions.Session {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read session %s: %v", path, err)
	}
	s, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse session %s: %v", path, err)
	}
	return s
}

func splitRecords(t *testing.T, recs []sessions.Record) (msgs []sessions.Message, evs []sessions.Event) {
	t.Helper()
	for _, r := range recs {
		switch v := r.(type) {
		case sessions.Message:
			msgs = append(msgs, v)
		case sessions.Event:
			evs = append(evs, v)
		default:
			t.Fatalf("unexpected record type %T", r)
		}
	}
	return msgs, evs
}

func eventKinds(evs []sessions.Event) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.Kind
	}
	return out
}

func decodePayload(t *testing.T, ev sessions.Event, v any) {
	t.Helper()
	if err := json.Unmarshal(ev.Payload, v); err != nil {
		t.Fatalf("decode %s payload: %v", ev.Kind, err)
	}
}

func assertSessionForked(t *testing.T, recs []sessions.Record, wantTo, where string) {
	t.Helper()
	if len(recs) == 0 {
		t.Fatalf("%s: no records, want a trailing session_forked", where)
	}
	last, ok := recs[len(recs)-1].(sessions.Event)
	if !ok || last.Kind != events.KindSessionForked {
		t.Fatalf("%s: last record = %T, want a session_forked event", where, recs[len(recs)-1])
	}
	var sf events.SessionForked
	decodePayload(t, last, &sf)
	if sf.ToSessionID != wantTo {
		t.Errorf("%s: session_forked.to_session_id = %q, want %q", where, sf.ToSessionID, wantTo)
	}
}

// assertSealed verifies a store refuses further appends (the fork sealed it).
func assertSealed(t *testing.T, store *sessions.Store) {
	t.Helper()
	before := len(store.Records())
	store.Append(sessions.Message{ID: idUser, Role: "user", Content: sessions.TextContent("after"), Timestamp: fixtureStartedAt})
	if after := len(store.Records()); after != before {
		t.Errorf("sealed store accepted an append: %d -> %d", before, after)
	}
}

// assertAppendable verifies a store still accepts appends (it is active/open).
func assertAppendable(t *testing.T, store *sessions.Store, what string) {
	t.Helper()
	before := len(store.Records())
	store.Append(sessions.Message{ID: idUser, Role: "user", Content: sessions.TextContent("still open"), Timestamp: fixtureStartedAt})
	if after := len(store.Records()); after != before+1 {
		t.Errorf("%s did not accept an append (it was sealed): %d -> %d", what, before, after)
	}
}
