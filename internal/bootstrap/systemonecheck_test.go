package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/systemone"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/turn"
	"codemeld.dev/codemeld/schemas"
)

const (
	jevName     = "openrouter:typesafe/jev-1.13"
	liquidName  = "openrouter:liquid/d1"
	jevSnapshot = "typesafe/jev-1.13-20260917"
)

type s1Got struct{ Model, State string }

type s1Reply struct {
	status int
	body   string
	hold   chan struct{}
}

type s1Server struct {
	*httptest.Server
	mu      sync.Mutex
	got     []s1Got
	reply   func(state string) s1Reply
	arrived chan string
}

func s1Answer(snapshot string, readOnly, secrets, code float64) string {
	raw, _ := json.Marshal(map[string]any{
		"model": snapshot,
		"answers": map[string]any{
			"effect":  map[string]any{"type": "choice", "choice": "read_only", "probabilities": map[string]float64{"read_only": readOnly}},
			"secrets": map[string]any{"type": "noul", "noul": secrets},
			"code":    map[string]any{"type": "noul", "noul": code},
		},
	})
	return string(raw)
}

func passing() s1Reply { return s1Reply{status: 200, body: s1Answer(jevSnapshot, 0.95, 0.1, 0.05)} }

func newS1Server(t *testing.T) *s1Server {
	t.Helper()
	s := &s1Server{reply: func(string) s1Reply { return passing() }, arrived: make(chan string, 64)}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Model, State string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		s.got = append(s.got, s1Got{body.Model, body.State})
		reply := s.reply
		s.mu.Unlock()
		rp := reply(body.State)
		s.arrived <- body.State
		if rp.hold != nil {
			<-rp.hold
		}
		w.WriteHeader(rp.status)
		_, _ = io.WriteString(w, rp.body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *s1Server) setReply(f func(state string) s1Reply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reply = f
}

func (s *s1Server) status(code int) {
	s.setReply(func(string) s1Reply { return s1Reply{status: code} })
}

func (s *s1Server) requests() []s1Got {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.got)
}

func (s *s1Server) states() []string {
	var out []string
	for _, g := range s.requests() {
		out = append(out, g.State)
	}
	return out
}

type s1Fixture struct {
	project, home string
	server        *s1Server
	blocked       *permissions.BlockedPaths
	cache         *config.Cache
	check         *systemOneCheck
}

func newS1Fixture(t *testing.T, systemOne string) *s1Fixture {
	t.Helper()
	prependFixturePrograms(t, "s1probe", "s1other", "s1third")
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	f := &s1Fixture{project: project, home: t.TempDir(), server: newS1Server(t)}
	f.blocked = mustProtectedStatePolicy(t, f.home, project, nil).Blocked
	f.use(t, s1Config(f.server.URL, systemOne, "or-key"))
	return f
}

func s1Config(url, systemOne, key string) map[string]any {
	return map[string]any{
		"system_one": systemOne,
		"provider": map[string]any{
			"openrouter": map[string]any{"base_url": url, "api_key": key},
		},
	}
}

func (f *s1Fixture) use(t *testing.T, cfg map[string]any) {
	t.Helper()
	cache, err := config.NewCache(cfg, f.project, nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	f.cache = cache
	f.check = newSystemOneCheck(cache, f.blocked)
}

type s1Prompts struct {
	mu    sync.Mutex
	notes []string
}

func (p *s1Prompts) show(req tui.PromptRequest) (tui.PromptDecision, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.notes = append(p.notes, req.Note)
	return tui.PromptDecision{Option: tui.OptionDeny}, nil
}

func (p *s1Prompts) shown() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.notes)
}

func (f *s1Fixture) production(t *testing.T, m mode.Mode, store *sessions.Store) (*productionAuthorizer, *tui.App, *s1Prompts) {
	t.Helper()
	app := tui.New(nil)
	app.SetActiveStore(store)
	prompts := &s1Prompts{}
	auth := newProductionAuthorizer(app, f.cache, permissions.NewTurnCache(), newPromptGateBuilder(prompts.show), f.home, f.project, mode.NewActiveState(m, mode.SourceConfig))
	auth.blocked = f.blocked
	auth.systemOne = f.check
	return auth, app, prompts
}

func (f *s1Fixture) headless(m mode.Mode, store *sessions.Store, child string) *headlessAuthorizer {
	auth := newHeadlessAuthorizer(f.cache, func() *sessions.Store { return store }, mode.NewActiveState(m, mode.SourceDefault), nil, stderrNoticeRenderer{w: io.Discard})
	auth.blocked = f.blocked
	auth.systemOne = f.check
	auth.childInvocationID = child
	return auth
}

func (f *s1Fixture) shell(t *testing.T, auth dispatch.Authorizer, command string) (ran bool, envelope string) {
	t.Helper()
	run := &fakeDispatchRunner{}
	_, err := dispatch.DispatchShell(context.Background(), command, f.home, f.project, auth, run)
	var denied *dispatch.DeniedError
	switch {
	case errors.As(err, &denied):
		return false, denied.Envelope
	case err != nil:
		t.Fatalf("DispatchShell(%q): %v", command, err)
	}
	return run.callCount() == 1, ""
}

func (f *s1Fixture) direct(t *testing.T, command string, m mode.Mode) (permissions.MatchRequest, permissions.ModeContext) {
	t.Helper()
	split, err := permissions.SplitCommand(command)
	if err != nil || split.LiteralRoute || len(split.Stages) != 1 {
		t.Fatalf("SplitCommand(%q) = %+v, %v; want one direct stage", command, split, err)
	}
	stage := split.Stages[0]
	subject, err := permissions.DirectRequestSubject(stage.Tokens, stage.Assignments, stage.ClearEnvironment)
	if err != nil {
		t.Fatalf("DirectRequestSubject: %v", err)
	}
	return permissions.MatchRequest{
			Kind: "direct", Subject: subject, SubjectTokens: stage.Tokens, Assignments: stage.Assignments,
			ClearEnvironment: stage.ClearEnvironment, PathScope: f.project,
		}, permissions.ModeContext{
			Mode: string(m), Class: permissions.ClassMutating, ProjectRoot: f.project,
			Stages: []permissions.StageNormalization{stage},
		}
}

func (f *s1Fixture) literal(command string, m mode.Mode) (permissions.MatchRequest, permissions.ModeContext) {
	return permissions.MatchRequest{Kind: "literal", Subject: command, PathScope: f.project},
		permissions.ModeContext{Mode: string(m), Class: permissions.ClassMutating, ProjectRoot: f.project, LiteralRoute: true}
}

func s1Records(t *testing.T, store *sessions.Store) []events.PermissionSystemOneCheck {
	t.Helper()
	return decodeStoreEvents[events.PermissionSystemOneCheck](t, reloadStore(t, store), events.KindPermissionSystemOneCheck)
}

func s1RawRecords(t *testing.T, store *sessions.Store) []map[string]any {
	t.Helper()
	return decodeStoreEvents[map[string]any](t, reloadStore(t, store), events.KindPermissionSystemOneCheck)
}

func s1Reason(t *testing.T, envelope string) string {
	t.Helper()
	var env struct {
		DeniedBy string `json:"denied_by"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(envelope), &env); err != nil {
		t.Fatalf("deny envelope %q: %v", envelope, err)
	}
	return env.Reason
}

func ptr(v float64) *float64 { return &v }

func wantAllowed(t *testing.T, got events.PermissionSystemOneCheck, subject, scope, modelID, child string, tRead float64) {
	t.Helper()
	want := events.PermissionSystemOneCheck{
		SubjectKind: "direct", Subject: subject, PathScope: scope, Provider: "openrouter", ModelID: modelID,
		Outcome: "allowed", Effect: "read_only", PReadOnly: ptr(0.95), PSecrets: ptr(0.1), PCode: ptr(0.05),
		TReadOnly: ptr(tRead), TSecrets: ptr(0.3), TCode: ptr(0.2), DurationMs: got.DurationMs, ChildInvocationID: child,
	}
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if !bytes.Equal(gotJSON, wantJSON) || got.DurationMs < 0 {
		t.Fatalf("system one record = %s, want %s", gotJSON, wantJSON)
	}
}

func systemOneMatches(t *testing.T, store *sessions.Store) []events.PermissionMatched {
	t.Helper()
	var out []events.PermissionMatched
	for _, m := range decodePermissionMatched(t, reloadStore(t, store)) {
		if m.OutcomeSource == "system_one_check" {
			out = append(out, m)
		}
	}
	return out
}

func TestSystemOneCheck_ProductionAutoEditsAllowsAnEligibleCommandWithoutPrompting(t *testing.T) {
	f := newS1Fixture(t, jevName)
	store := mkStore(t)
	auth, _, prompts := f.production(t, mode.AutoEdits, store)

	if ran, env := f.shell(t, auth, "s1probe a.txt"); !ran {
		t.Fatalf("command did not run (envelope %q)", env)
	}
	if got := prompts.shown(); len(got) != 0 {
		t.Fatalf("prompts = %q, want none", got)
	}
	if got := f.server.requests(); len(got) != 1 || got[0] != (s1Got{"typesafe/jev-1.13", "s1probe a.txt"}) {
		t.Fatalf("server requests = %+v, want one for typesafe/jev-1.13 with the command text", got)
	}
	recs := s1Records(t, store)
	if len(recs) != 1 {
		t.Fatalf("system one records = %+v, want 1", recs)
	}
	wantAllowed(t, recs[0], "s1probe a.txt", f.project, jevSnapshot, "", 0.9)
	if m := systemOneMatches(t, store); len(m) != 1 || m[0].Outcome != "once" || m[0].Subject != "s1probe a.txt" {
		t.Fatalf("system_one_check matches = %+v, want one once", m)
	}
}

func TestSystemOneCheck_UnattendedHeadlessPlanAllowsAnUnclassifiedReadOnlyCommand(t *testing.T) {
	f := newS1Fixture(t, jevName)
	store := mkStore(t)

	if ran, env := f.shell(t, f.headless(mode.Plan, store, ""), "s1probe a.txt"); !ran {
		t.Fatalf("command did not run (envelope %q)", env)
	}
	recs := s1Records(t, store)
	if len(recs) != 1 {
		t.Fatalf("system one records = %+v, want 1", recs)
	}
	wantAllowed(t, recs[0], "s1probe a.txt", f.project, jevSnapshot, "", 0.9)
	if m := systemOneMatches(t, store); len(m) != 1 {
		t.Fatalf("system_one_check matches = %+v, want one", m)
	}
}

func TestSystemOneCheck_EachEntryAppliesItsOwnThresholdsAndModel(t *testing.T) {
	f := newS1Fixture(t, jevName)
	f.server.setReply(func(string) s1Reply { return s1Reply{status: 200, body: s1Answer("snap", 0.85, 0.1, 0.05)} })
	for _, tc := range []struct {
		name, modelID, outcome string
		ran                    bool
	}{
		{jevName, "typesafe/jev-1.13", "declined", false},
		{liquidName, "liquid/d1", "allowed", true},
	} {
		f.use(t, s1Config(f.server.URL, tc.name, "or-key"))
		store := mkStore(t)
		auth, _, prompts := f.production(t, mode.AutoEdits, store)
		ran, _ := f.shell(t, auth, "s1probe a.txt")
		if ran != tc.ran {
			t.Fatalf("%s: ran = %v, want %v", tc.name, ran, tc.ran)
		}
		if got := prompts.shown(); tc.ran != (len(got) == 0) || (len(got) == 1 && got[0] != "") {
			t.Fatalf("%s: prompts = %q", tc.name, got)
		}
		reqs := f.server.requests()
		if last := reqs[len(reqs)-1]; last.Model != tc.modelID {
			t.Fatalf("%s: request model = %q, want %q", tc.name, last.Model, tc.modelID)
		}
		if recs := s1Records(t, store); len(recs) != 1 || recs[0].Outcome != tc.outcome || recs[0].ModelID != "snap" {
			t.Fatalf("%s: records = %+v, want one %s", tc.name, recs, tc.outcome)
		}
	}
}

func TestSystemOneCheck_ExcludedRequestsSendNothing(t *testing.T) {
	for _, tc := range []struct {
		name, setting, command string
		mode                   mode.Mode
	}{
		{"build mode", jevName, "s1probe a.txt", mode.Build},
		{"setting off", "off", "s1probe a.txt", mode.AutoEdits},
		{"unknown setting", "openrouter:other", "s1probe a.txt", mode.AutoEdits},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newS1Fixture(t, tc.setting)
			store := mkStore(t)
			auth, _, prompts := f.production(t, tc.mode, store)
			if ran, _ := f.shell(t, auth, tc.command); ran {
				t.Fatal("command ran, want today's prompt")
			}
			if got := prompts.shown(); len(got) != 1 || got[0] != "" {
				t.Fatalf("prompts = %q, want one with no note", got)
			}
			headlessMode := mode.Plan
			if tc.mode == mode.Build {
				headlessMode = mode.Build
			}
			if _, env := f.shell(t, f.headless(headlessMode, store, ""), tc.command); env == "" || strings.Contains(env, "System One") {
				t.Fatalf("headless %s envelope = %q, want today's deny", headlessMode, env)
			}
			if got := f.server.requests(); len(got) != 0 {
				t.Fatalf("server requests = %+v, want none", got)
			}
			if recs := s1Records(t, store); len(recs) != 0 {
				t.Fatalf("records = %+v, want none", recs)
			}
		})
	}
}

func TestSystemOneCheck_ExcludedSubstitutionIsRecordedAsSkipped(t *testing.T) {
	f := newS1Fixture(t, jevName)
	store := mkStore(t)
	command := `bash -c 'echo $(id)'`
	auth, _, prompts := f.production(t, mode.AutoEdits, store)
	if ran, _ := f.shell(t, auth, command); ran {
		t.Fatal("command ran, want today's prompt")
	}
	if got := prompts.shown(); len(got) != 1 || got[0] != "" {
		t.Fatalf("prompts = %q, want one with no note", got)
	}
	if _, env := f.shell(t, f.headless(mode.Plan, store, ""), command); env == "" || strings.Contains(env, "System One") {
		t.Fatalf("headless plan envelope = %q, want today's deny", env)
	}
	if got := f.server.requests(); len(got) != 0 {
		t.Fatalf("server requests = %+v, want none", got)
	}
	want := events.PermissionSystemOneCheck{
		SubjectKind: "literal", Subject: command, PathScope: f.project, Provider: "openrouter",
		ModelID: "typesafe/jev-1.13", Outcome: "skipped", Reason: "substitution",
	}
	if recs := s1Records(t, store); len(recs) != 2 || recs[0] != want || recs[1] != want {
		t.Fatalf("records = %+v, want two skipped/substitution records", recs)
	}
}

func TestSystemOneCheck_CreditAndAuthFailuresPauseTheSession(t *testing.T) {
	for _, tc := range []struct {
		status        int
		reason, notes string
	}{
		{http.StatusPaymentRequired, "credits", "out of credits on openrouter"},
		{http.StatusUnauthorized, "auth", "authentication failed on openrouter"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			f := newS1Fixture(t, jevName)
			store := mkStore(t)
			auth, _, prompts := f.production(t, mode.AutoEdits, store)
			if got := f.check.status(store); got != "" {
				t.Fatalf("status before a failure = %q, want empty", got)
			}
			f.server.status(tc.status)

			f.shell(t, auth, "s1probe a.txt")
			f.shell(t, auth, "s1other b.txt")
			f.shell(t, auth, `bash -c 'echo $(id)'`)

			want := []string{
				"System One check failed: " + tc.notes + " — asking you; paused for this session",
				"System One check paused for this session: " + tc.notes,
				"",
			}
			if got := prompts.shown(); !slices.Equal(got, want) {
				t.Fatalf("prompt notes = %q, want %q", got, want)
			}
			if got := f.server.states(); !slices.Equal(got, []string{"s1probe a.txt"}) {
				t.Fatalf("server requests = %q, want only the first", got)
			}
			recs := s1Records(t, store)
			if len(recs) != 3 || recs[0].Outcome != "failed" || recs[0].Reason != tc.reason || recs[0].ModelID != "typesafe/jev-1.13" ||
				recs[1].Outcome != "skipped" || recs[1].Reason != "paused" || recs[1].Subject != "s1other b.txt" ||
				recs[2].Outcome != "skipped" || recs[2].Reason != "substitution" || recs[2].Subject != `bash -c 'echo $(id)'` {
				t.Fatalf("records = %+v, want failed/%s, skipped/paused, then skipped/substitution", recs, tc.reason)
			}
			if got, want := f.check.status(store), "System One check paused for this session: "+tc.notes; got != want {
				t.Fatalf("status = %q, want %q", got, want)
			}
		})
	}
}

func TestSystemOneCheck_UnrecordableChecksAreNotAllowed(t *testing.T) {
	f := newS1Fixture(t, jevName)
	req, mc := f.direct(t, "s1probe a.txt", mode.AutoEdits)
	for _, tc := range []struct {
		name    string
		store   *sessions.Store
		child   string
		calls   int
		records bool
	}{
		{"nil store", nil, "", 0, false},
		{"empty session id", storeAt(t, filepath.Join(t.TempDir(), "s.json"), "", "/proj"), "", 0, false},
		{"emitter error", mkStore(t), "not-a-v7", 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(f.server.requests())
			mc := mc
			mc.ChildInvocationID = tc.child
			got := f.check.bind(tc.store, systemOneLiteralTexts{})(context.Background(), req, mc)
			if got.Allow || got.Note != "System One check could not be recorded — asking you" {
				t.Fatalf("result = %+v, want not allowed with the unrecorded note", got)
			}
			if calls := len(f.server.requests()) - before; calls != tc.calls {
				t.Fatalf("server requests = %d, want %d", calls, tc.calls)
			}
			if tc.records {
				if recs := s1Records(t, tc.store); len(recs) != 0 {
					t.Fatalf("records = %+v, want none", recs)
				}
			}
		})
	}
}

func TestSystemOneCheck_UnrecordableExcludedChecksStaySilent(t *testing.T) {
	f := newS1Fixture(t, jevName)
	command := "bash --version | head -1"
	req, mc := f.literal(command, mode.AutoEdits)
	store := mkStore(t)
	for _, tc := range []struct {
		name  string
		store *sessions.Store
		child string
	}{
		{"nil store", nil, ""},
		{"empty session id", storeAt(t, filepath.Join(t.TempDir(), "s.json"), "", "/proj"), ""},
		{"emitter error", store, "not-a-v7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mc := mc
			mc.ChildInvocationID = tc.child
			if got := f.check.check(context.Background(), tc.store, command, req, mc); got != (permissions.PrePromptResult{}) {
				t.Fatalf("result = %+v, want empty", got)
			}
		})
	}
	if got := f.server.requests(); len(got) != 0 {
		t.Fatalf("server requests = %+v, want none", got)
	}
	if recs := s1Records(t, store); len(recs) != 0 {
		t.Fatalf("records = %+v, want none", recs)
	}
}

func TestSystemOneCheck_StructuralSkipIsWrittenToTheSessionFile(t *testing.T) {
	f := newS1Fixture(t, jevName)
	store := mkStore(t)
	auth, _, prompts := f.production(t, mode.AutoEdits, store)
	command := "bash --version | head -1"
	if ran, _ := f.shell(t, auth, command); ran {
		t.Fatal("command ran, want today's prompt")
	}
	if got := prompts.shown(); len(got) != 1 || got[0] != "" {
		t.Fatalf("prompts = %q, want one with no note", got)
	}
	if got := f.server.requests(); len(got) != 0 {
		t.Fatalf("server requests = %+v, want none", got)
	}
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	disk := decodeStoreEvents[map[string]any](t, sessions.New(store.Path(), readSessionFile(t, store.Path())), events.KindPermissionSystemOneCheck)
	want := map[string]any{
		"subject_kind": "literal", "subject": command, "path_scope": f.project, "provider": "openrouter",
		"model_id": "typesafe/jev-1.13", "outcome": "skipped", "reason": "wrapper", "duration_ms": float64(0),
	}
	if len(disk) != 1 || !reflect.DeepEqual(disk[0], want) {
		t.Fatalf("records on disk = %v, want exactly %v", disk, want)
	}
}

func TestSystemOneCheck_OffAndEmptyTextStayUnrecorded(t *testing.T) {
	command := "bash --version | head -1"
	f := newS1Fixture(t, "off")
	store := mkStore(t)
	auth, _, _ := f.production(t, mode.AutoEdits, store)
	f.shell(t, auth, command)
	if recs := s1Records(t, store); len(recs) != 0 {
		t.Fatalf("System One off: records = %+v, want none", recs)
	}

	f = newS1Fixture(t, jevName)
	store = mkStore(t)
	req, mc := f.literal(command, mode.AutoEdits)
	if got := f.check.check(context.Background(), store, "", req, mc); got != (permissions.PrePromptResult{}) {
		t.Fatalf("empty text: result = %+v, want empty", got)
	}
	if recs := s1Records(t, store); len(recs) != 0 {
		t.Fatalf("empty text: records = %+v, want none", recs)
	}

	auth, _, _ = f.production(t, mode.AutoEdits, store)
	if ran, env := f.shell(t, auth, "s1probe a.txt"); !ran {
		t.Fatalf("eligible command did not run (envelope %q)", env)
	}
	if recs := s1Records(t, store); len(recs) != 1 || recs[0].Outcome != "allowed" {
		t.Fatalf("eligible command: records = %+v, want one allowed", recs)
	}
}

func TestSystemOneCheck_ConcurrentStructuralSkipsKeepBothRecords(t *testing.T) {
	f := newS1Fixture(t, jevName)
	store := mkStore(t)
	cases := []struct{ command, reason, child string }{
		{"bash --version | head -1", "wrapper", ids.NewV7()},
		{"echo $(id)", "substitution", ids.NewV7()},
	}
	results := make([]permissions.PrePromptResult, len(cases))
	var wg sync.WaitGroup
	for i, tc := range cases {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, mc := f.literal(tc.command, mode.AutoEdits)
			mc.ChildInvocationID = tc.child
			results[i] = f.check.check(context.Background(), store, tc.command, req, mc)
		}()
	}
	wg.Wait()
	for i, got := range results {
		if got != (permissions.PrePromptResult{}) {
			t.Fatalf("result %d = %+v, want empty", i, got)
		}
	}
	if got := f.server.requests(); len(got) != 0 {
		t.Fatalf("server requests = %+v, want none", got)
	}
	var got []string
	for _, r := range s1Records(t, store) {
		got = append(got, r.Subject+"/"+r.Outcome+"/"+r.Reason+"/"+r.ChildInvocationID)
	}
	slices.Sort(got)
	var want []string
	for _, tc := range cases {
		want = append(want, tc.command+"/skipped/"+tc.reason+"/"+tc.child)
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("records = %q, want %q", got, want)
	}
}

func TestSystemOneCheck_OtherFailuresRetryAndMissingKeysAreRecorded(t *testing.T) {
	f := newS1Fixture(t, jevName)
	store := mkStore(t)
	auth, _, prompts := f.production(t, mode.AutoEdits, store)
	f.server.status(http.StatusInternalServerError)
	f.shell(t, auth, "s1probe a.txt")
	f.shell(t, auth, "s1other b.txt")
	note := "System One check failed (server) — asking you"
	if got := prompts.shown(); !slices.Equal(got, []string{note, note}) {
		t.Fatalf("prompt notes = %q", got)
	}
	if got := f.server.states(); len(got) != 2 {
		t.Fatalf("server requests = %q, want a retry", got)
	}

	f.use(t, s1Config(f.server.URL, jevName, ""))
	store = mkStore(t)
	auth, _, prompts = f.production(t, mode.AutoEdits, store)
	f.shell(t, auth, "s1probe a.txt")
	if got := prompts.shown(); !slices.Equal(got, []string{"System One check: no openrouter API key — run /connect openrouter"}) {
		t.Fatalf("prompt notes = %q", got)
	}
	if got := f.server.states(); len(got) != 2 {
		t.Fatalf("server requests = %q, want none for a missing key", got)
	}
	if recs := s1Records(t, store); len(recs) != 1 || recs[0].Outcome != "failed" || recs[0].Reason != "no_key" || recs[0].DurationMs != 0 {
		t.Fatalf("records = %+v, want failed/no_key", recs)
	}
}

func TestSystemOneCheck_UnattendedDenyReasonsCarryTheirOwnNote(t *testing.T) {
	credits := "System One check failed: out of credits on openrouter — asking you; paused for this session"
	for _, m := range []mode.Mode{mode.Plan, mode.AutoEdits} {
		t.Run(string(m), func(t *testing.T) {
			f := newS1Fixture(t, jevName)
			f.server.status(http.StatusPaymentRequired)
			_, env := f.shell(t, f.headless(m, mkStore(t), ""), "s1probe a.txt")
			if reason := s1Reason(t, env); !strings.Contains(reason, credits) {
				t.Fatalf("deny reason = %q, want the credits note", reason)
			}
		})
	}

	f := newS1Fixture(t, jevName)
	release := make(chan struct{})
	f.server.setReply(func(state string) s1Reply {
		if strings.Contains(state, "a.txt") {
			return s1Reply{status: http.StatusInternalServerError, hold: release}
		}
		return s1Reply{status: http.StatusTooManyRequests, hold: release}
	})
	auth := f.headless(mode.AutoEdits, mkStore(t), "")
	envs := make([]string, 2)
	var wg sync.WaitGroup
	for i, cmd := range []string{"s1probe a.txt", "s1other b.txt"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, envs[i] = f.shell(t, auth, cmd)
		}()
	}
	<-f.server.arrived
	<-f.server.arrived
	close(release)
	wg.Wait()
	for i, own := range []string{"(server)", "(rate_limited)"} {
		other := []string{"(rate_limited)", "(server)"}[i]
		reason := s1Reason(t, envs[i])
		if !strings.Contains(reason, "System One check failed "+own) || strings.Contains(reason, other) {
			t.Fatalf("deny reason %d = %q, want only its own %s note", i, reason, own)
		}
		if !strings.HasPrefix(reason, headlessDenyReason) {
			t.Fatalf("deny reason %d = %q, want the no-approver refusal first", i, reason)
		}
	}
	_, env := f.shell(t, auth, "s1probe a.txt")
	if reason := s1Reason(t, env); !strings.HasPrefix(reason, headlessDenyReason) || strings.Contains(reason, "System One") {
		t.Fatalf("cached deny reason = %q, want the no-approver refusal with no note", reason)
	}
}

func TestSystemOneCheck_PausedIneligibleCommandsGetTodaysDecision(t *testing.T) {
	f := newS1Fixture(t, jevName)
	store := mkStore(t)
	auth := f.headless(mode.Plan, store, "")
	f.server.status(http.StatusPaymentRequired)
	f.shell(t, auth, "s1probe a.txt")
	_, env := f.shell(t, auth, `bash -c 'echo $(id)'`)
	if reason := s1Reason(t, env); !permissions.IsModeDenyEnvelope(env) || strings.Contains(reason, "System One") {
		t.Fatalf("envelope = %q, want Plan's deny with no System One note", env)
	}
	if got := f.server.states(); len(got) != 1 {
		t.Fatalf("server requests = %q, want only the first", got)
	}
	recs := s1Records(t, store)
	if len(recs) != 2 || recs[0].Outcome != "failed" || recs[0].Reason != "credits" ||
		recs[1].Outcome != "skipped" || recs[1].Reason != "substitution" || recs[1].Subject != `bash -c 'echo $(id)'` {
		t.Fatalf("records = %+v, want the credits failure then skipped/substitution", recs)
	}
}

func TestSystemOneCheck_ChildDispatchersPauseIndependently(t *testing.T) {
	f := newS1Fixture(t, jevName)
	store := mkStore(t)
	turnStore := func() *sessions.Store { return store }
	deps := generalAgentBinding{parent: &parentTurnHolder{}, notices: &recordingNotices{}, systemOne: f.check}.
		deps(tools.NewRegistry(), f.cache, turnStore, f.home, f.project, mustProtectedStatePolicy(t, f.home, f.project, nil))
	childA, childB := ids.NewV7(), ids.NewV7()
	runChild := func(child, command string) turn.ToolResult {
		t.Helper()
		d := deps.NewDispatcher(permissions.ModeContext{Mode: string(mode.AutoEdits), ChildAgent: true, ChildInvocationID: child})
		unit := d.Plan([]turn.AssembledToolCall{bashCall("c1", command)}, 1).Units[0]
		res, err := unit.Run(context.Background())
		if err != nil {
			t.Fatalf("child %s run %q: %v", child, command, err)
		}
		return res
	}

	f.server.status(http.StatusPaymentRequired)
	if res := runChild(childA, "s1probe a.txt"); !res.Denied || !strings.Contains(res.Content, "out of credits on openrouter") {
		t.Fatalf("child A first result = %+v, want a deny carrying the credits note", res)
	}
	f.server.setReply(func(string) s1Reply { return passing() })
	if res := runChild(childA, "s1other b.txt"); !res.Denied || !strings.Contains(res.Content, "System One check paused for this session") {
		t.Fatalf("child A second result = %+v, want a paused deny", res)
	}
	if res := runChild(childB, "s1other b.txt"); res.Denied {
		t.Fatalf("sibling result = %+v, want allowed", res)
	}
	if ran, env := f.shell(t, f.headless(mode.AutoEdits, store, ""), "s1other b.txt"); !ran {
		t.Fatalf("parent denied (%q), want allowed", env)
	}
	if got := f.server.states(); !slices.Equal(got, []string{"s1probe a.txt", "s1other b.txt", "s1other b.txt"}) {
		t.Fatalf("server requests = %q", got)
	}
	var got []string
	for _, r := range s1Records(t, store) {
		got = append(got, r.ChildInvocationID+"/"+r.Outcome+"/"+r.Reason)
	}
	want := []string{childA + "/failed/credits", childA + "/skipped/paused", childB + "/allowed/", "/allowed/"}
	if !slices.Equal(got, want) {
		t.Fatalf("records = %q, want %q", got, want)
	}
	if f.check.status(store) != "" {
		t.Fatalf("parent status = %q, want unpaused", f.check.status(store))
	}
}

func TestSystemOneCheck_StoreSwitchesKeepPausesWithTheirActivation(t *testing.T) {
	for _, reloadA := range []bool{false, true} {
		t.Run(map[bool]string{false: "new session", true: "reloaded session"}[reloadA], func(t *testing.T) {
			f := newS1Fixture(t, jevName)
			storeA := mkStore(t)
			auth, app, _ := f.production(t, mode.AutoEdits, storeA)
			release := make(chan struct{})
			holdStatus := http.StatusOK
			if reloadA {
				holdStatus = http.StatusPaymentRequired
			}
			f.server.setReply(func(state string) s1Reply {
				switch state {
				case "s1probe hold.txt":
					if holdStatus == http.StatusOK {
						return s1Reply{status: 200, body: s1Answer(jevSnapshot, 0.95, 0.1, 0.05), hold: release}
					}
					return s1Reply{status: holdStatus, hold: release}
				case "s1probe pay.txt":
					return s1Reply{status: http.StatusPaymentRequired}
				}
				return passing()
			})

			done := make(chan struct{})
			go func() {
				defer close(done)
				f.shell(t, auth, "s1probe hold.txt")
			}()
			<-f.server.arrived

			storeB := mkStore(t)
			if reloadA {
				storeB = reloadStore(t, storeA)
			}
			app.SetActiveStore(storeB)
			f.shell(t, auth, "s1probe pay.txt")
			<-f.server.arrived
			wantB := "System One check paused for this session: out of credits on openrouter"
			stop := make(chan struct{})
			var statusReads sync.WaitGroup
			statusReads.Add(1)
			go func() {
				defer statusReads.Done()
				for {
					select {
					case <-stop:
						return
					default:
						if got := f.check.status(app.ActiveStore()); got != wantB {
							t.Errorf("status during completion = %q, want %q", got, wantB)
							return
						}
					}
				}
			}()
			close(release)
			<-done
			close(stop)
			statusReads.Wait()

			if got := f.check.status(app.ActiveStore()); got != wantB {
				t.Fatalf("status = %q, want B's pause", got)
			}
			a := s1Records(t, storeA)
			if len(a) != 1 || a[0].Subject != "s1probe hold.txt" {
				t.Fatalf("store A records = %+v, want only its own late completion", a)
			}
			b := s1Records(t, storeB)
			if n := len(b); b[n-1].Subject != "s1probe pay.txt" || b[n-1].Reason != "credits" {
				t.Fatalf("store B records = %+v, want its credits failure last", b)
			}

			fresh := reloadStore(t, storeA)
			app.SetActiveStore(fresh)
			if got := f.check.status(fresh); got != "" {
				t.Fatalf("status for a newly loaded store = %q, want unpaused", got)
			}
			f.shell(t, auth, "s1other c.txt")
			if recs := s1Records(t, fresh); recs[len(recs)-1].Outcome != "allowed" {
				t.Fatalf("fresh store records = %+v, want the next check allowed", recs)
			}
		})
	}
}

func TestSystemOneCheck_OverlappingFailureAndSuccessKeepThePause(t *testing.T) {
	for _, tc := range []struct {
		status int
		reason string
	}{{http.StatusPaymentRequired, "credits"}, {http.StatusUnauthorized, "auth"}} {
		t.Run(tc.reason, func(t *testing.T) {
			f := newS1Fixture(t, jevName)
			store := mkStore(t)
			release := make(chan struct{})
			f.server.setReply(func(state string) s1Reply {
				switch state {
				case "s1probe ok.txt":
					return s1Reply{status: 200, body: s1Answer(jevSnapshot, 0.95, 0.1, 0.05), hold: release}
				case "s1probe fail.txt":
					return s1Reply{status: tc.status}
				}
				return passing()
			})
			auth := f.headless(mode.AutoEdits, store, "")
			sibling := ids.NewV7()

			done := make(chan bool)
			go func() {
				ran, _ := f.shell(t, auth, "s1probe ok.txt")
				done <- ran
			}()
			<-f.server.arrived
			f.shell(t, auth, "s1probe fail.txt")
			<-f.server.arrived
			stop := make(chan struct{})
			var reads sync.WaitGroup
			reads.Add(1)
			go func() {
				defer reads.Done()
				for {
					select {
					case <-stop:
						return
					default:
						_ = f.check.status(store)
					}
				}
			}()
			close(release)
			if !<-done {
				t.Fatal("the admitted success was not allowed")
			}
			close(stop)
			reads.Wait()

			before := len(f.server.requests())
			f.shell(t, auth, "s1other third.txt")
			if got := len(f.server.requests()); got != before {
				t.Fatalf("third check sent a request (%d → %d)", before, got)
			}
			if ran, _ := f.shell(t, f.headless(mode.AutoEdits, store, sibling), "s1other third.txt"); !ran {
				t.Fatal("sibling was paused by the parent")
			}
			var got []string
			for _, r := range s1Records(t, store) {
				got = append(got, r.Subject+"/"+r.Outcome+"/"+r.Reason)
			}
			want := []string{"s1probe fail.txt/failed/" + tc.reason, "s1probe ok.txt/allowed/", "s1other third.txt/skipped/paused", "s1other third.txt/allowed/"}
			if !slices.Equal(got, want) {
				t.Fatalf("records = %q, want %q", got, want)
			}
		})
	}
}

func TestSystemOneCheck_SendsEachRequestsOwnCommandText(t *testing.T) {
	f := newS1Fixture(t, jevName)
	store := mkStore(t)
	auth, _, _ := f.production(t, mode.AutoEdits, store)

	quoted := `FOO="a b" s1probe 'x y'`
	f.shell(t, auth, quoted)
	f.shell(t, auth, "s1probe a.txt 2>/dev/null")
	if got := f.server.states(); !slices.Equal(got, []string{quoted, "s1probe a.txt 2>/dev/null"}) {
		t.Fatalf("server states = %q", got)
	}
	recs := s1Records(t, store)
	if len(recs) != 2 || recs[0].Subject != "s1probe x y" || recs[1].SubjectKind != "literal" {
		t.Fatalf("records = %+v, want the direct event subject then a literal record", recs)
	}

	req, mc := f.direct(t, "s1probe a.txt", mode.AutoEdits)
	check := f.check.bind(store, systemOneLiteralTexts{})
	sourced := mc
	sourced.Stages = []permissions.StageNormalization{mc.Stages[0]}
	sourced.Stages[0].Source = "s1probe $(id)"
	unsourced := mc
	unsourced.Stages = nil
	for _, m := range []permissions.ModeContext{sourced, unsourced} {
		if got := check(context.Background(), req, m); got != (permissions.PrePromptResult{}) {
			t.Fatalf("result = %+v, want not allowed with no note", got)
		}
	}
	if got := len(f.server.requests()); got != 2 {
		t.Fatalf("server requests = %d, want no new request", got)
	}
}

func TestSystemOneCheck_GroupedAuthorizersBindEachMembersText(t *testing.T) {
	f := newS1Fixture(t, jevName)
	readOnly, readOnlyCtx := f.direct(t, "ls", mode.AutoEdits)
	second, secondCtx := f.direct(t, "s1probe a.txt", mode.AutoEdits)
	third, thirdCtx := f.literal("s1other b.txt 2>/dev/null", mode.AutoEdits)
	conflict, conflictCtx := f.literal("s1third c.txt 2>/dev/null", mode.AutoEdits)
	display := func(s string) dispatch.PromptDisplay {
		return dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: s}
	}
	members := []dispatch.BatchAuthRequest{
		{Req: readOnly, Display: display("ls"), ModeCtx: readOnlyCtx},
		{Req: second, Display: display("s1probe a.txt"), ModeCtx: secondCtx},
		{Req: third, Display: display("s1other b.txt 2>/dev/null"), ModeCtx: thirdCtx},
		{Req: conflict, Display: display("s1third c.txt 2>/dev/null"), ModeCtx: conflictCtx},
		{Req: conflict, Display: display("s1third other.txt 2>/dev/null"), ModeCtx: conflictCtx},
	}
	want := []string{"s1probe a.txt", "s1other b.txt 2>/dev/null"}

	auth, _, _ := f.production(t, mode.AutoEdits, mkStore(t))
	if _, err := auth.AuthorizeBatch(context.Background(), members); err != nil {
		t.Fatalf("AuthorizeBatch: %v", err)
	}
	if got := f.server.states(); !slices.Equal(got, want) {
		t.Fatalf("batch server states = %q, want %q", got, want)
	}

	f.server.setReply(func(string) s1Reply { return passing() })
	f.server.mu.Lock()
	f.server.got = nil
	f.server.mu.Unlock()
	independent := make([]dispatch.IndependentAuthRequest, len(members))
	for i, m := range members {
		independent[i] = dispatch.IndependentAuthRequest{Req: m.Req, Display: m.Display, ModeCtx: m.ModeCtx}
	}
	auth, _, _ = f.production(t, mode.AutoEdits, mkStore(t))
	if _, err := auth.AuthorizeIndependent(context.Background(), independent); err != nil {
		t.Fatalf("AuthorizeIndependent: %v", err)
	}
	if got := f.server.states(); !slices.Equal(got, want) {
		t.Fatalf("independent server states = %q, want %q", got, want)
	}
}

func TestSystemOneCheck_RecordFieldMatrix(t *testing.T) {
	f := newS1Fixture(t, jevName)
	store := mkStore(t)
	child := ids.NewV7()
	auth := f.headless(mode.AutoEdits, store, child)
	f.server.setReply(func(state string) s1Reply {
		switch state {
		case "s1probe declined.txt":
			return s1Reply{status: 200, body: s1Answer("snap-2", 0.5, 0.1, 0.05)}
		case "s1probe failed.txt":
			return s1Reply{status: http.StatusPaymentRequired}
		}
		return passing()
	})
	for _, cmd := range []string{"s1probe allowed.txt", "s1probe declined.txt", "s1probe failed.txt", "s1probe skipped.txt"} {
		f.shell(t, auth, cmd)
	}
	scored := []string{"effect", "p_read_only", "p_secrets", "p_code", "t_read_only", "t_secrets", "t_code"}
	for i, tc := range []struct {
		outcome, reason, model string
	}{
		{"allowed", "", jevSnapshot},
		{"declined", "", "snap-2"},
		{"failed", "credits", "typesafe/jev-1.13"},
		{"skipped", "paused", "typesafe/jev-1.13"},
	} {
		rec := s1RawRecords(t, store)[i]
		if rec["outcome"] != tc.outcome || rec["model_id"] != tc.model || rec["provider"] != "openrouter" ||
			rec["subject_kind"] != "direct" || rec["path_scope"] != f.project || rec["child_invocation_id"] != child {
			t.Fatalf("record %d = %v, want %s with model %s", i, rec, tc.outcome, tc.model)
		}
		if _, ok := rec["duration_ms"]; !ok {
			t.Fatalf("record %d has no duration_ms", i)
		}
		reason, hasReason := rec["reason"]
		if (tc.reason == "") == hasReason || (hasReason && reason != tc.reason) {
			t.Fatalf("record %d reason = %v, want %q", i, reason, tc.reason)
		}
		for _, k := range scored {
			if _, ok := rec[k]; ok != (tc.reason == "") {
				t.Fatalf("record %d field %s present = %v", i, k, ok)
			}
		}
	}
	if rec := s1RawRecords(t, store)[1]; rec["t_read_only"] != 0.9 || rec["p_read_only"] != 0.5 {
		t.Fatalf("declined record = %v, want its own answer and the entry's thresholds", rec)
	}
}

func TestSystemOneCheck_SchemaEnumMatchesTheValidatedList(t *testing.T) {
	var doc struct {
		Properties map[string]struct {
			Enum []string `json:"enum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schemas.SettingsSchema, &doc); err != nil {
		t.Fatalf("parse settings schema: %v", err)
	}
	want := []string{"off"}
	for _, m := range systemone.Models {
		want = append(want, m.Name)
	}
	if got := doc.Properties["system_one"].Enum; !slices.Equal(got, want) {
		t.Fatalf("system_one enum = %q, want %q", got, want)
	}
}

func TestSystemOneCheck_TUILaunchSharesTheCheckWithTheStatusLine(t *testing.T) {
	f := newS1Fixture(t, jevName)
	f.server.status(http.StatusPaymentRequired)
	var auth *productionAuthorizer
	prev := newSettingsDeps
	newSettingsDeps = func(app *tui.App, cache *config.Cache, active *model.ActiveState, a *productionAuthorizer) tui.SettingsDeps {
		auth = a
		return prev(app, cache, active, a)
	}
	t.Cleanup(func() { newSettingsDeps = prev })

	store := mkStore(t)
	result := &BootstrapResult{
		Home: f.home, LaunchDir: f.project, ProjectRoot: f.project, Session: store,
		Config: s1Config(f.server.URL, jevName, "or-key"),
		Mode:   mode.NewActiveState(mode.Plan, mode.SourceConfig),
	}
	app, restore := startCaptured(t, context.Background(), result, io.Discard)
	t.Cleanup(restore)
	if auth == nil || auth.systemOne == nil {
		t.Fatal("StartTUI did not give the authorizer a System One check")
	}
	if _, env := f.shell(t, auth, "s1probe a.txt"); !strings.Contains(s1Reason(t, env), "out of credits on openrouter") {
		t.Fatalf("envelope = %q, want the credits note", env)
	}
	app.SubmitInput("/systemone")
	if got := app.SystemOnePickerStatusText(); !strings.HasSuffix(got, "; System One check paused for this session: out of credits on openrouter") {
		t.Fatalf("/systemone header = %q, want the pause line", got)
	}
	app.HandleEsc()
}

func TestSystemOneCheck_HeadlessLaunchWiresTheCheck(t *testing.T) {
	f := newS1Fixture(t, jevName)
	client := declaredScopeClient(declaredToolCall{"bash", `{"command":"s1probe a.txt"}`})
	t.Cleanup(swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client }))

	driver := NewHeadlessDriver("check", &bytes.Buffer{}, &bytes.Buffer{})
	result := headlessResult(t, f.project, mode.NewActiveState(mode.AutoEdits, mode.SourceDefault))
	result.Config["provider"].(map[string]any)["openrouter"] = map[string]any{"base_url": f.server.URL, "api_key": "or-key"}
	result.Config["system_one"] = jevName
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := f.server.states(); !slices.Equal(got, []string{"s1probe a.txt"}) {
		t.Fatalf("server states = %q, want the run's command", got)
	}
	if recs := s1Records(t, result.Session); len(recs) != 1 || recs[0].Outcome != "allowed" {
		t.Fatalf("records = %+v, want one allowed record", recs)
	}
	if m := systemOneMatches(t, result.Session); len(m) != 1 {
		t.Fatalf("system_one_check matches = %+v, want one", m)
	}
}

func TestSystemOneCheck_FirstPublishedPauseReasonWins(t *testing.T) {
	c := newSystemOneCheck(nil, nil)
	store := mkStore(t)
	c.pause(store, "", "out of credits on openrouter")
	c.pause(store, "", "authentication failed on openrouter")
	if got, want := c.status(store), "System One check paused for this session: out of credits on openrouter"; got != want {
		t.Fatalf("status = %q, want %q", got, want)
	}
}
