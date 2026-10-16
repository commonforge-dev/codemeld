package tui

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
)

const (
	compactMetaID = "0190c0de-0000-7000-8000-000000000201"
	compactIDUser = "0190c0de-0000-7000-8000-0000000002a1"
	compactIDAsst = "0190c0de-0000-7000-8000-0000000002a2"
	compactIDEvt  = "0190c0de-0000-7000-8000-0000000002a3"
	compactIDLate = "0190c0de-0000-7000-8000-0000000002a4"
)

var compactTS = time.Date(2026, 6, 12, 8, 30, 0, 0, time.UTC)

// compactSentinelRequest is the whole request the fake factory returns; the
// handler must forward it unchanged. Its exact non-streaming/no-tools
// construction is proven by the request builder's own tests, not here.
var compactSentinelRequest = provider.Request{
	Model:  "sentinel-model",
	Stream: false,
	Messages: []provider.Message{
		{Role: "system", Content: "summarize this conversation"},
		{Role: "user", Content: "hi"},
	},
	PromptCacheKey: "sentinel-cache-key",
}

func compactableSession(title string) *sessions.Session {
	return &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            compactMetaID,
			Folder:        "/proj/demo",
			Title:         title,
			StartedAt:     compactTS,
			UpdatedAt:     compactTS,
			SchemaVersion: sessions.CurrentSchemaVersion,
		},
		Records: []sessions.Record{
			sessions.Message{ID: compactIDUser, Role: "user", Content: sessions.TextContent("hi"), Timestamp: compactTS},
			sessions.Message{ID: compactIDAsst, Role: "assistant", Content: sessions.TextContent("hello"), Timestamp: compactTS.Add(time.Second)},
			sessions.Event{ID: compactIDEvt, Kind: "launch_began", Timestamp: compactTS.Add(2 * time.Second), Payload: json.RawMessage(`{"source":"fresh"}`)},
		},
	}
}

func compactStore(t *testing.T, session *sessions.Session) *sessions.Store {
	t.Helper()
	return sessions.New(filepath.Join(t.TempDir(), "parent.json"), session)
}

func flushCompactParent(store *sessions.Store) error {
	_, _, err := store.Flush(context.Background())
	return err
}

func persistedCompactEvents(t *testing.T, store *sessions.Store) []sessions.Event {
	t.Helper()
	session, _, err := sessions.OpenSession(store.Path())
	if err != nil {
		t.Fatalf("open flushed parent session: %v", err)
	}
	var out []sessions.Event
	for _, record := range session.Records {
		if event, ok := record.(sessions.Event); ok && event.Kind == events.KindSlashCommand {
			out = append(out, event)
		}
	}
	return out
}

type compactCounts struct {
	request    int
	client     int
	chat       int
	flush      int
	acquire    int
	background int
	prepare    int
	activate   int
	release    int
}

func compactCompletion(content string) provider.Response {
	return provider.Response{Completion: &openai.ChatCompletion{
		Choices: []openai.ChatCompletionChoice{{Message: openai.ChatCompletionMessage{Content: content}}},
	}}
}

type fakeCompactClient struct {
	counts   *compactCounts
	response provider.Response
	err      error
	request  provider.Request
}

func (c *fakeCompactClient) ChatCompletion(_ context.Context, req provider.Request) (provider.Response, error) {
	c.counts.chat++
	c.request = req
	return c.response, c.err
}

type compactCancelContext struct {
	context.Context
	cancelAtCheck int
	checks        int
}

func (c *compactCancelContext) Err() error {
	c.checks++
	if c.checks >= c.cancelAtCheck {
		return context.Canceled
	}
	return nil
}

type compactSeams struct {
	counts     compactCounts
	ctx        context.Context
	turnActive bool
	requestOK  bool
	clientOK   bool
	acquireOK  bool
	client     *fakeCompactClient
	flushErr   error
	prepareErr error
	onFlush    func(store *sessions.Store)
	onRelease  func()
	onActivate func()
	work       func() error
	complete   func(error)

	preparedParent *sessions.Store
	preparedTitle  string
	preparedChild  []sessions.Record
	preparedFinal  []sessions.Record
}

func newCompactSeams() *compactSeams {
	s := &compactSeams{ctx: context.Background(), requestOK: true, clientOK: true, acquireOK: true}
	s.client = &fakeCompactClient{counts: &s.counts, response: compactCompletion("summarized history")}
	return s
}

func (s *compactSeams) deps() CompactDeps {
	return CompactDeps{
		Context:    s.ctx,
		TurnActive: func() bool { return s.turnActive },
		SummaryRequest: func([]sessions.Record) (provider.Request, string, string, bool) {
			s.counts.request++
			return compactSentinelRequest, "openai", "gpt-5", s.requestOK
		},
		Client: func(string, string) (provider.Client, bool) {
			s.counts.client++
			return s.client, s.clientOK
		},
		FlushParent: func(store *sessions.Store) error {
			s.counts.flush++
			if s.onFlush != nil {
				s.onFlush(store)
			}
			if s.flushErr != nil {
				return s.flushErr
			}
			return flushCompactParent(store)
		},
		AcquireExclusive: func() (func(), bool) {
			s.counts.acquire++
			if !s.acquireOK {
				return nil, false
			}
			return func() {
				s.counts.release++
				if s.onRelease != nil {
					s.onRelease()
				}
			}, true
		},
		RunBackground: func(work func() error, complete func(error)) {
			s.counts.background++
			s.work, s.complete = work, complete
		},
		PrepareChild: func(parent *sessions.Store, title string, childRecords, finalParentRecords []sessions.Record) (func(), error) {
			s.counts.prepare++
			s.preparedParent, s.preparedTitle = parent, title
			s.preparedChild, s.preparedFinal = childRecords, finalParentRecords
			if s.prepareErr != nil {
				return nil, s.prepareErr
			}
			return func() {
				s.counts.activate++
				if s.onActivate != nil {
					s.onActivate()
				}
			}, nil
		},
	}
}

func compactRegistry(t *testing.T, deps CompactDeps) *Registry {
	t.Helper()
	reg, err := NewRegistry([]Command{
		{Name: "compact", Description: "Compact the current session", ArgSig: ArgNone, Phase: PhaseTwo, Handler: NewCompactHandler(deps)},
	})
	if err != nil {
		t.Fatalf("build compact registry: %v", err)
	}
	return reg
}

func expectStrictCompactFlush(t *testing.T, host *fakeHost, seams *compactSeams, wantDetail string) {
	t.Helper()
	seams.onFlush = func(store *sessions.Store) {
		if store != host.store {
			t.Error("FlushParent got a different store than the parent captured at admission")
		}
		if len(host.notices) != 0 {
			t.Errorf("notices before the strict flush = %v, want none", host.notices)
		}
		evs := slashEvents(store)
		if len(evs) != 1 {
			t.Fatalf("at flush time the store holds %d slash_command events, want 1", len(evs))
		}
		if p := decodeSlash(t, evs[0]); p.Name != "compact" || p.Outcome != "error" || p.ErrorDetail != wantDetail {
			t.Errorf("event at flush time = %+v, want name=compact outcome=error detail=%q", p, wantDetail)
		}
	}
}

func acceptCompactDispatch(t *testing.T, host *fakeHost, seams *compactSeams) {
	t.Helper()
	res := compactRegistry(t, seams.deps()).DispatchSlashInput("/compact", host)
	if res.Status != StatusHandled || res.Err != nil || res.RetainInput {
		t.Fatalf("dispatch /compact = %+v, want accepted Handled/nil-err without retention", res)
	}
	if seams.work == nil || seams.complete == nil {
		t.Fatal("dispatch handed no deferred work to RunBackground")
	}
}

func runCompactTerminalError(t *testing.T, host *fakeHost, seams *compactSeams, want error, wantPrepare int) {
	t.Helper()
	err := seams.work()
	if !errors.Is(err, want) {
		t.Fatalf("deferred work = %v, want %v", err, want)
	}
	if len(host.notices) != 0 {
		t.Errorf("notices = %v, want none until completion runs on the event loop", host.notices)
	}
	if seams.counts.flush != 1 {
		t.Errorf("FlushParent called %d times, want exactly 1", seams.counts.flush)
	}
	if seams.counts.prepare != wantPrepare {
		t.Errorf("PrepareChild called %d times, want %d", seams.counts.prepare, wantPrepare)
	}
	if seams.counts.activate != 0 {
		t.Errorf("activation ran %d times on a terminal failure, want 0", seams.counts.activate)
	}
	if seams.counts.release != 0 {
		t.Errorf("lease released %d times before the terminal notice, want 0", seams.counts.release)
	}

	seams.onRelease = func() {
		if len(host.notices) == 0 {
			t.Error("lease released before the terminal notice reached the user")
		}
	}
	seams.complete(err)

	if len(host.notices) != 1 || host.notices[0] != want.Error() {
		t.Fatalf("notices = %v, want exactly [%q]", host.notices, want.Error())
	}
	if seams.counts.release != 1 {
		t.Errorf("lease released %d times after the terminal notice, want exactly 1", seams.counts.release)
	}
	if seams.counts.activate != 0 {
		t.Errorf("activation ran %d times after a terminal notice, want 0", seams.counts.activate)
	}
	persisted := persistedCompactEvents(t, host.store)
	if len(persisted) != 1 {
		t.Fatalf("persisted slash_command events = %d, want exactly 1", len(persisted))
	}
	if p := decodeSlash(t, persisted[0]); p.Name != "compact" || p.Outcome != "error" || p.ErrorDetail != want.Error() {
		t.Errorf("persisted event = %+v, want name=compact outcome=error detail=%q", p, want.Error())
	}
}

func TestCompactHandler_AdmissionRefusalsPersistCapturedParentError(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(*compactSeams)
		wantNotice string
	}{
		{"active turn", func(s *compactSeams) { s.turnActive = true }, "compact unavailable while a turn is active"},
		{"missing model", func(s *compactSeams) { s.requestOK = false }, "compaction failed: no model is selected"},
		{"missing client", func(s *compactSeams) { s.clientOK = false }, "compaction failed: the selected provider is unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := &fakeHost{store: compactStore(t, compactableSession("Refactor plan"))}
			seams := newCompactSeams()
			tc.setup(seams)
			expectStrictCompactFlush(t, host, seams, tc.wantNotice)

			res := compactRegistry(t, seams.deps()).DispatchSlashInput("/compact", host)

			if res.Status != StatusHandled || res.Canonical != "compact" || res.Err != nil {
				t.Fatalf("dispatch /compact = %+v, want Handled/compact/nil-err", res)
			}
			if !res.RetainInput {
				t.Error("admission refusal did not retain the typed input")
			}
			if len(host.notices) != 1 || host.notices[0] != tc.wantNotice {
				t.Fatalf("notices = %v, want exactly [%q]", host.notices, tc.wantNotice)
			}
			if seams.counts.flush != 1 {
				t.Errorf("FlushParent called %d times, want 1", seams.counts.flush)
			}
			if seams.counts.acquire != 0 || seams.counts.background != 0 || seams.counts.prepare != 0 || seams.counts.chat != 0 || seams.counts.release != 0 {
				t.Errorf("seam calls = %+v, want no lease, deferred, preparation, or provider work on a refusal", seams.counts)
			}
			persisted := persistedCompactEvents(t, host.store)
			if len(persisted) != 1 {
				t.Fatalf("persisted slash_command events = %d, want exactly 1", len(persisted))
			}
			if p := decodeSlash(t, persisted[0]); p.Name != "compact" || p.Outcome != "error" || p.ErrorDetail != tc.wantNotice {
				t.Errorf("persisted event = %+v, want name=compact outcome=error detail=%q", p, tc.wantNotice)
			}
		})
	}
}

func TestCompactHandler_RefusalStopsOnAFailedStrictFlush(t *testing.T) {
	host := &fakeHost{store: compactStore(t, compactableSession("Refactor plan"))}
	flushErr := errors.New("session write failed persisting compact refusal")
	seams := newCompactSeams()
	seams.turnActive = true
	seams.flushErr = flushErr

	res := compactRegistry(t, seams.deps()).DispatchSlashInput("/compact", host)

	if res.Status != StatusHandled || !errors.Is(res.Err, flushErr) {
		t.Fatalf("dispatch /compact = %+v, want Handled with the flush error", res)
	}
	if len(host.notices) != 0 {
		t.Errorf("notices = %v, want none: the refusal is not durable yet", host.notices)
	}
	if seams.counts.acquire != 0 || seams.counts.background != 0 {
		t.Errorf("seam calls = %+v, want no lease or deferred work after a failed strict flush", seams.counts)
	}
}

func TestCompactHandler_FailedAcquireRetainsWithoutDurableWork(t *testing.T) {
	host := &fakeHost{store: compactStore(t, compactableSession("Refactor plan"))}
	beforeRecords := host.store.Records()
	beforeTitle := host.store.Title()
	seams := newCompactSeams()
	seams.acquireOK = false

	res := compactRegistry(t, seams.deps()).DispatchSlashInput("/compact", host)

	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /compact = %+v, want Handled/nil-err", res)
	}
	if !res.RetainInput {
		t.Error("lost acquisition did not retain the typed input")
	}
	want := "compaction is already running"
	if len(host.notices) != 1 || host.notices[0] != want {
		t.Fatalf("notices = %v, want exactly [%q]", host.notices, want)
	}
	if seams.counts.acquire != 1 {
		t.Errorf("AcquireExclusive called %d times, want exactly 1", seams.counts.acquire)
	}
	if seams.counts.release != 0 {
		t.Errorf("released a lease %d times after a failed acquire, want 0", seams.counts.release)
	}
	if seams.counts.flush != 0 || seams.counts.background != 0 || seams.counts.prepare != 0 || seams.counts.chat != 0 {
		t.Errorf("seam calls = %+v, want no durable, deferred, preparation, or provider work", seams.counts)
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("appended %d slash_command events on a failed acquire, want 0 (the running compaction owns the parent)", len(evs))
	}
	if !reflect.DeepEqual(host.store.Records(), beforeRecords) {
		t.Error("failed acquire mutated the parent records")
	}
	if host.store.Title() != beforeTitle {
		t.Errorf("parent title = %q, want unchanged %q", host.store.Title(), beforeTitle)
	}
}

func TestCompactHandler_AcceptedDispatchPreparesDetachedRecordsThenActivates(t *testing.T) {
	host := &fakeHost{store: compactStore(t, compactableSession("Refactor plan"))}
	beforeRecords := host.store.Records()
	seams := newCompactSeams()

	res := compactRegistry(t, seams.deps()).DispatchSlashInput("/compact", host)

	if res.Status != StatusHandled || res.Err != nil || res.RetainInput {
		t.Fatalf("dispatch /compact = %+v, want accepted Handled/nil-err without retention", res)
	}
	if seams.counts.acquire != 1 || seams.counts.background != 1 {
		t.Fatalf("seam calls = %+v, want exactly one acquire and one deferred schedule", seams.counts)
	}
	if seams.work == nil || seams.complete == nil {
		t.Fatal("dispatch handed no deferred work to RunBackground")
	}
	if seams.counts.chat != 0 || seams.counts.prepare != 0 || seams.counts.release != 0 || seams.counts.flush != 0 {
		t.Errorf("seam calls = %+v, want no provider, preparation, release, or flush work on the dispatch goroutine", seams.counts)
	}
	if len(host.notices) != 0 {
		t.Errorf("notices = %v, want none before the held worker runs", host.notices)
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("appended %d slash_command events at dispatch, want 0", len(evs))
	}
	if !reflect.DeepEqual(host.store.Records(), beforeRecords) {
		t.Error("dispatch mutated the parent records before its deferred work ran")
	}

	host.store.Append(sessions.Message{ID: compactIDLate, Role: "user", Content: sessions.TextContent("after dispatch"), Timestamp: compactTS.Add(3 * time.Second)})
	if _, _, err := host.store.FlushTitle(context.Background(), "Renamed after dispatch"); err != nil {
		t.Fatalf("rename parent after dispatch: %v", err)
	}

	if err := seams.work(); err != nil {
		t.Fatalf("deferred work = %v, want nil", err)
	}
	if seams.counts.prepare != 1 {
		t.Fatalf("PrepareChild called %d times, want exactly 1", seams.counts.prepare)
	}
	if seams.counts.activate != 0 || seams.counts.release != 0 {
		t.Errorf("seam calls = %+v, want no activation or release before completion runs on the event loop", seams.counts)
	}

	seams.onRelease = func() {
		if seams.counts.activate != 1 {
			t.Error("lease released before the prepared child was activated")
		}
	}
	seams.complete(nil)

	if seams.counts.activate != 1 {
		t.Fatalf("activation ran %d times, want exactly 1", seams.counts.activate)
	}
	if seams.counts.release != 1 {
		t.Errorf("lease released %d times after completion, want exactly 1", seams.counts.release)
	}
	if seams.counts.chat != 1 {
		t.Errorf("ChatCompletion called %d times, want exactly 1", seams.counts.chat)
	}
	if !reflect.DeepEqual(seams.client.request, compactSentinelRequest) {
		t.Errorf("provider request = %+v, want the one resolved at admission %+v", seams.client.request, compactSentinelRequest)
	}
	if seams.counts.flush != 0 {
		t.Errorf("FlushParent called %d times on a usable summary, want 0", seams.counts.flush)
	}
	if len(host.notices) != 0 {
		t.Errorf("notices = %v, want none on the success path", host.notices)
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("appended %d slash_command events on the validated-summary path, want 0", len(evs))
	}
	if seams.preparedParent != host.store {
		t.Error("preparation got a different parent than the store captured at admission")
	}
	if want := "Refactor plan (compacted)"; seams.preparedTitle != want {
		t.Errorf("prepared title = %q, want the admission snapshot %q", seams.preparedTitle, want)
	}

	if len(seams.preparedChild) != 1 {
		t.Fatalf("child records = %d, want exactly one compaction", len(seams.preparedChild))
	}
	compaction, ok := seams.preparedChild[0].(sessions.Compaction)
	if !ok {
		t.Fatalf("child record = %T, want sessions.Compaction", seams.preparedChild[0])
	}
	if compaction.ParentID != "" {
		t.Errorf("compaction parent_id = %q, want empty so EnsureChildSession stamps it", compaction.ParentID)
	}
	if want := "summarized history"; compaction.Summary != want {
		t.Errorf("compaction summary = %q, want the validated %q", compaction.Summary, want)
	}
	if compaction.Provider != "openai" || compaction.ModelID != "gpt-5" {
		t.Errorf("compaction identity = %q/%q, want the openai/gpt-5 the request was built from", compaction.Provider, compaction.ModelID)
	}
	if !ids.IsValidV7(compaction.ID) {
		t.Errorf("compaction id = %q, want a valid v7 id", compaction.ID)
	}
	if compaction.Timestamp.IsZero() {
		t.Error("compaction timestamp is zero")
	}

	if len(seams.preparedFinal) != 1 {
		t.Fatalf("final parent records = %d, want exactly one compact success", len(seams.preparedFinal))
	}
	final, ok := seams.preparedFinal[0].(sessions.Event)
	if !ok {
		t.Fatalf("final parent record = %T, want sessions.Event", seams.preparedFinal[0])
	}
	if final.Kind != events.KindSlashCommand {
		t.Fatalf("final parent record kind = %q, want %q", final.Kind, events.KindSlashCommand)
	}
	if p := decodeSlash(t, final); p.Name != "compact" || p.Outcome != "success" || p.ErrorDetail != "" {
		t.Errorf("final parent event = %+v, want name=compact outcome=success without a detail", p)
	}
	if persisted := persistedCompactEvents(t, host.store); len(persisted) != 0 {
		t.Errorf("parent file holds %d slash_command events, want 0: only preparation makes the success durable", len(persisted))
	}
}

func TestCompactHandler_PreparationFailurePersistsConservativeError(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"child write or lock", errors.New("child session /sessions/child.json was not written")},
		{"final parent batch", errors.New("commit final records: session write failed")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := &fakeHost{store: compactStore(t, compactableSession("Refactor plan"))}
			seams := newCompactSeams()
			seams.prepareErr = tc.err
			expectStrictCompactFlush(t, host, seams, errCompactChildMayRemain.Error())

			acceptCompactDispatch(t, host, seams)
			runCompactTerminalError(t, host, seams, errCompactChildMayRemain, 1)

			for _, text := range []string{host.notices[0], errCompactChildMayRemain.Error()} {
				if strings.Contains(text, tc.err.Error()) {
					t.Errorf("rendered the raw preparation error %q", text)
				}
			}
		})
	}
}

func TestCompactHandler_PostPreparationCancellationStillActivates(t *testing.T) {
	host := &fakeHost{store: compactStore(t, compactableSession("Refactor plan"))}
	seams := newCompactSeams()
	cancelCtx := &compactCancelContext{Context: context.Background(), cancelAtCheck: 3}
	seams.ctx = cancelCtx

	acceptCompactDispatch(t, host, seams)

	if err := seams.work(); err != nil {
		t.Fatalf("deferred work = %v, want nil: preparation succeeded before any later cancellation", err)
	}
	seams.complete(nil)

	if cancelCtx.checks != 2 {
		t.Errorf("cancellation observed %d times, want the 2 pre-preparation checks: the parent is sealed afterwards", cancelCtx.checks)
	}
	if seams.counts.prepare != 1 || seams.counts.activate != 1 || seams.counts.release != 1 {
		t.Fatalf("seam calls = %+v, want one preparation, one activation, and one release", seams.counts)
	}
	if seams.counts.flush != 0 {
		t.Errorf("FlushParent called %d times after successful preparation, want 0", seams.counts.flush)
	}
	if len(host.notices) != 0 {
		t.Errorf("notices = %v, want none after successful preparation", host.notices)
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("appended %d slash_command events after successful preparation, want 0", len(evs))
	}
}

func TestCompactHandler_ProviderFailuresPersistCapturedParentError(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*compactSeams)
		want  error
	}{
		{"provider error", func(s *compactSeams) {
			s.client.response, s.client.err = provider.Response{}, errors.New("401 unauthorized for key sk-live-leaked")
		}, errCompactSummaryRequest},
		{"nil completion", func(s *compactSeams) { s.client.response = provider.Response{} }, errCompactNoSummary},
		{"no choices", func(s *compactSeams) {
			s.client.response = provider.Response{Completion: &openai.ChatCompletion{}}
		}, errCompactNoSummary},
		{"blank summary", func(s *compactSeams) { s.client.response = compactCompletion(" \n\t ") }, errCompactNoSummary},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := &fakeHost{store: compactStore(t, compactableSession("Refactor plan"))}
			seams := newCompactSeams()
			tc.setup(seams)
			expectStrictCompactFlush(t, host, seams, tc.want.Error())

			acceptCompactDispatch(t, host, seams)
			runCompactTerminalError(t, host, seams, tc.want, 0)

			if seams.counts.chat != 1 {
				t.Errorf("ChatCompletion called %d times, want exactly 1", seams.counts.chat)
			}
			persisted := persistedCompactEvents(t, host.store)
			for _, text := range []string{host.notices[0], decodeSlash(t, persisted[0]).ErrorDetail} {
				if strings.Contains(text, "sk-live-leaked") || strings.Contains(text, "401") {
					t.Errorf("rendered provider error content %q", text)
				}
			}
		})
	}
}

func TestCompactHandler_PreFinalizationCancellationPersistsCapturedParentError(t *testing.T) {
	cases := []struct {
		name       string
		checkpoint int
		response   provider.Response
	}{
		{"after provider return", 1, provider.Response{}},
		{"immediately before preparation", 2, compactCompletion("summarized history")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := &fakeHost{store: compactStore(t, compactableSession("Refactor plan"))}
			seams := newCompactSeams()
			seams.client.response = tc.response
			cancelCtx := &compactCancelContext{Context: context.Background(), cancelAtCheck: tc.checkpoint}
			seams.ctx = cancelCtx
			expectStrictCompactFlush(t, host, seams, errCompactCancelled.Error())

			acceptCompactDispatch(t, host, seams)
			runCompactTerminalError(t, host, seams, errCompactCancelled, 0)

			if seams.counts.chat != 1 {
				t.Errorf("ChatCompletion called %d times, want exactly 1", seams.counts.chat)
			}
			if cancelCtx.checks != tc.checkpoint {
				t.Errorf("cancellation observed at check %d, want the failure to stop at checkpoint %d", cancelCtx.checks, tc.checkpoint)
			}
		})
	}
}

func TestCompactHandler_TerminalFailureStopsOnAFailedStrictFlush(t *testing.T) {
	host := &fakeHost{store: compactStore(t, compactableSession("Refactor plan"))}
	if err := flushCompactParent(host.store); err != nil {
		t.Fatalf("seed the parent file: %v", err)
	}
	flushErr := errors.New("session write failed persisting the compact error")
	seams := newCompactSeams()
	seams.client.response, seams.client.err = provider.Response{}, errors.New("401 unauthorized for key sk-live-leaked")
	seams.flushErr = flushErr

	acceptCompactDispatch(t, host, seams)

	err := seams.work()
	if !errors.Is(err, flushErr) {
		t.Fatalf("deferred work = %v, want the strict flush error", err)
	}
	seams.complete(err)

	if len(host.notices) != 0 {
		t.Errorf("notices = %v, want none: the compact error never became durable", host.notices)
	}
	if seams.counts.release != 1 {
		t.Errorf("lease released %d times, want exactly 1", seams.counts.release)
	}
	if persisted := persistedCompactEvents(t, host.store); len(persisted) != 0 {
		t.Errorf("reopened parent holds %d slash_command events, want 0", len(persisted))
	}
	if seams.counts.prepare != 0 || seams.counts.activate != 0 {
		t.Errorf("seam calls = %+v, want no preparation or activation after a failed strict flush", seams.counts)
	}
}

func TestDeriveCompactTitle(t *testing.T) {
	cases := []struct {
		name   string
		parent string
		want   string
	}{
		{"titled parent", "Refactor plan", "Refactor plan (compacted)"},
		{"untitled parent", "", "Compacted session"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveCompactTitle(tc.parent); got != tc.want {
				t.Errorf("deriveCompactTitle(%q) = %q, want %q", tc.parent, got, tc.want)
			}
		})
	}
}
