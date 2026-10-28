package permissions

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

type checkSpy struct {
	calls   []string
	results map[string]PrePromptResult
}

func (s *checkSpy) hook(_ context.Context, req MatchRequest, _ ModeContext) PrePromptResult {
	s.calls = append(s.calls, req.Subject)
	return s.results[req.Subject]
}

type preFixture struct {
	*orchFixture
	check  *checkSpy
	choice PromptOutcome
	escs   []ScopeEscalation
	groups [][]BatchPromptRequest
}

func newPreFixture(choice PromptChoice, results map[string]PrePromptResult) *preFixture {
	p := &preFixture{check: &checkSpy{results: results}, choice: PromptOutcome{Choice: choice}}
	p.orchFixture = newFixture(func(_ context.Context, esc ScopeEscalation) (PromptOutcome, error) {
		p.escs = append(p.escs, esc)
		return p.choice, nil
	}, nil)
	p.deps.PromptBatch = func(_ context.Context, rs []BatchPromptRequest) (PromptOutcome, error) {
		p.cap.prompts++
		p.groups = append(p.groups, rs)
		return p.choice, nil
	}
	p.deps.PromptIndependent = func(_ context.Context, rs []BatchPromptRequest) ([]PromptOutcome, error) {
		p.cap.prompts++
		p.groups = append(p.groups, rs)
		out := make([]PromptOutcome, len(rs))
		for i := range out {
			out[i] = p.choice
		}
		return out, nil
	}
	p.deps.PrePromptCheck = p.check.hook
	return p
}

func (p *preFixture) run(ctx context.Context, path string, reqs []BatchRequest) ([]Decision, error) {
	switch path {
	case "batch":
		return AuthorizeBatch(ctx, reqs, p.deps)
	case "independent":
		return AuthorizeIndependent(ctx, reqs, p.deps)
	}
	var decs []Decision
	for _, r := range reqs {
		d, err := Authorize(ctx, r.Req, r.ModeCtx, p.deps)
		if err != nil {
			return nil, err
		}
		decs = append(decs, d)
	}
	return decs, nil
}

func (p *preFixture) mustRun(t *testing.T, path string, reqs ...BatchRequest) []Decision {
	t.Helper()
	decs, err := p.run(context.Background(), path, reqs)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return decs
}

func (p *preFixture) eventsWithSource(src string) []orchEmitted {
	var out []orchEmitted
	for _, e := range p.cap.events {
		if e.outcomeSource == src {
			out = append(out, e)
		}
	}
	return out
}

func (p *preFixture) promptShown() int {
	n := 0
	for _, e := range p.cap.events {
		if e.kind == "permission_prompt_shown" {
			n++
		}
	}
	return n
}

func shellBatchReq(t *testing.T, mode, input string) BatchRequest {
	t.Helper()
	req, mc := shellReqCtxFor(t, mode, input)
	return BatchRequest{Req: req, ModeCtx: mc}
}

func allow() PrePromptResult { return PrePromptResult{Allow: true} }

func decline(note string) PrePromptResult { return PrePromptResult{Note: note} }

func TestPrePromptCheck_AutoEditsAllowSkipsThePromptAndAsksAgain(t *testing.T) {
	for _, path := range authorizePaths {
		t.Run(path, func(t *testing.T) {
			p := newPreFixture(PromptDeny, map[string]PrePromptResult{"touch a": allow()})
			r := shellBatchReq(t, modeAutoEdits, "touch a")

			for round := 1; round <= 2; round++ {
				decs := p.mustRun(t, path, r)
				if d := decs[0]; !reflect.DeepEqual(d, Decision{Outcome: "once"}) {
					t.Fatalf("round %d decision = %+v, want a bare allow once", round, d)
				}
				if len(p.check.calls) != round {
					t.Fatalf("round %d check calls = %v, want one per request", round, p.check.calls)
				}
			}
			if p.cap.prompts != 0 || len(p.escs) != 0 || p.promptShown() != 0 {
				t.Fatalf("prompts = %d/%d, prompt_shown = %d, want none", p.cap.prompts, len(p.escs), p.promptShown())
			}
			wantKinds(t, p.cap.kinds(), []string{"permission_matched", "permission_matched"})
			if got := p.eventsWithSource("system_one_check"); len(got) != 2 || got[0].outcome != "once" {
				t.Fatalf("events = %+v, want two system_one_check once records", p.cap.events)
			}
			if len(p.cap.records) != 0 || len(p.cap.appends) != 0 {
				t.Fatalf("records = %v appends = %v, want no turn-cache entry or grant", p.cap.records, p.cap.appends)
			}
		})
	}
}

func TestPrePromptCheck_DeclineCarriesItsNoteToThePrompt(t *testing.T) {
	for _, path := range authorizePaths {
		t.Run(path, func(t *testing.T) {
			p := newPreFixture(PromptAllowOnce, map[string]PrePromptResult{"touch a": decline("  writes a file ")})
			decs := p.mustRun(t, path, shellBatchReq(t, modeAutoEdits, "touch a"))

			var notes []string
			for _, e := range p.escs {
				notes = append(notes, e.Note)
			}
			for _, g := range p.groups {
				for _, r := range g {
					notes = append(notes, r.Escalation.Note)
				}
			}
			if !slices.Equal(notes, []string{"  writes a file "}) {
				t.Fatalf("prompt notes = %q, want the check's note unchanged", notes)
			}
			if decs[0].Outcome != "once" || p.promptShown() != 1 {
				t.Fatalf("decision = %+v prompt_shown = %d, want the prompted allow", decs[0], p.promptShown())
			}
			if len(p.eventsWithSource("system_one_check")) != 0 {
				t.Fatalf("a declined check recorded an allow: %+v", p.cap.events)
			}
		})
	}
}

func TestPrePromptCheck_GroupedMembersResolveByTheirOwnIndex(t *testing.T) {
	inputs := []string{"touch a", "touch b", "touch c", "touch d"}
	results := map[string]PrePromptResult{
		"touch a": decline("note a"), "touch b": allow(), "touch c": decline("note c"), "touch d": allow(),
	}
	for _, path := range []string{"batch", "independent"} {
		t.Run(path+"/mixed", func(t *testing.T) {
			p := newPreFixture(PromptDeny, results)
			var reqs []BatchRequest
			for _, in := range inputs {
				reqs = append(reqs, shellBatchReq(t, modeAutoEdits, in))
			}
			decs := p.mustRun(t, path, reqs...)

			if !slices.Equal(p.check.calls, inputs) {
				t.Fatalf("check calls = %v, want each member once in input order", p.check.calls)
			}
			if len(p.groups) != 1 {
				t.Fatalf("group prompts = %d, want 1", len(p.groups))
			}
			var idx []int
			var notes []string
			for _, r := range p.groups[0] {
				idx = append(idx, r.Index)
				notes = append(notes, r.Escalation.Note)
			}
			if !slices.Equal(idx, []int{0, 2}) || !slices.Equal(notes, []string{"note a", "note c"}) {
				t.Fatalf("prompted indexes %v notes %q, want [0 2] [note a note c]", idx, notes)
			}
			var outcomes []string
			for _, d := range decs {
				outcomes = append(outcomes, d.Outcome)
			}
			if !slices.Equal(outcomes, []string{"deny", "once", "deny", "once"}) {
				t.Fatalf("outcomes = %v, want the human deny only on the prompted members", outcomes)
			}
			var recorded []string
			for _, r := range p.cap.records {
				recorded = append(recorded, r.req.Subject+"="+r.outcome)
			}
			if !slices.Equal(recorded, []string{"touch a=deny", "touch c=deny"}) {
				t.Fatalf("cache records = %v, want only the prompted members' denials", recorded)
			}
			if p.promptShown() != 2 {
				t.Fatalf("prompt_shown = %d, want 2", p.promptShown())
			}
		})
		t.Run(path+"/all allowed", func(t *testing.T) {
			p := newPreFixture(PromptDeny, results)
			decs := p.mustRun(t, path, shellBatchReq(t, modeAutoEdits, "touch b"), shellBatchReq(t, modeAutoEdits, "touch d"))
			if len(p.groups) != 0 || p.promptShown() != 0 {
				t.Fatalf("groups = %d prompt_shown = %d, want no group prompt", len(p.groups), p.promptShown())
			}
			if decs[0].Outcome != "once" || decs[1].Outcome != "once" {
				t.Fatalf("decisions = %+v, want both allowed", decs)
			}
		})
	}

	t.Run("independent persistence uses the input index", func(t *testing.T) {
		p := newPreFixture(PromptAllowFolder, results)
		var persisted []int
		p.deps.PersistGrantAt = func(i int) func(PermissionEntry) (PermissionEntry, error) {
			return func(e PermissionEntry) (PermissionEntry, error) {
				persisted = append(persisted, i)
				return e, nil
			}
		}
		p.mustRun(t, "independent", shellBatchReq(t, modeAutoEdits, "touch b"), shellBatchReq(t, modeAutoEdits, "touch a"),
			shellBatchReq(t, modeAutoEdits, "touch d"), shellBatchReq(t, modeAutoEdits, "touch c"))
		if !slices.Equal(persisted, []int{1, 3}) {
			t.Fatalf("persisted for indexes %v, want [1 3]", persisted)
		}
	})

	t.Run("batch keeps the scope chosen for a lone prompted stage", func(t *testing.T) {
		p := newPreFixture(PromptAllowFolder, results)
		p.choice.StoredSubject = "touch :*"
		p.mustRun(t, "batch", shellBatchReq(t, modeAutoEdits, "touch b"), shellBatchReq(t, modeAutoEdits, "touch a"))
		if len(p.cap.appends) != 1 || p.cap.appends[0].Subject != "touch :*" {
			t.Fatalf("appended = %+v, want the prompt-selected subject", p.cap.appends)
		}
	})
}

func TestPrePromptCheck_GroupedPlanChecksRunInInputOrder(t *testing.T) {
	reqs := func(t *testing.T) []BatchRequest {
		promptPoint := shellBatchReq(t, modePlan, "touch a")
		promptPoint.ModeCtx.ShellPathAsk = true
		return []BatchRequest{promptPoint, shellBatchReq(t, modePlan, "touch b")}
	}
	for _, path := range []string{"batch", "independent"} {
		t.Run(path, func(t *testing.T) {
			p := newPreFixture(PromptAllowOnce, map[string]PrePromptResult{"touch a": decline("n"), "touch b": allow()})
			decs := p.mustRun(t, path, reqs(t)...)
			if !slices.Equal(p.check.calls, []string{"touch a", "touch b"}) {
				t.Fatalf("check calls = %v, want each member once in input order", p.check.calls)
			}
			if len(p.groups) != 1 || len(p.groups[0]) != 1 || p.groups[0][0].Index != 0 || p.groups[0][0].Escalation.Note != "n" {
				t.Fatalf("groups = %+v, want only the prompt-point member prompted with its note", p.groups)
			}
			if decs[0].Outcome != "once" || !reflect.DeepEqual(decs[1], Decision{Outcome: "once"}) {
				t.Fatalf("decisions = %+v, want the prompted allow and the check's allow", decs)
			}
		})
		t.Run(path+"/cancelled by the earlier member", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := newPreFixture(PromptAllowOnce, nil)
			var calls []string
			p.deps.PrePromptCheck = func(_ context.Context, req MatchRequest, _ ModeContext) PrePromptResult {
				calls = append(calls, req.Subject)
				cancel()
				return decline("n")
			}
			decs, err := p.run(ctx, path, reqs(t))
			if !errors.Is(err, context.Canceled) || decs != nil {
				t.Fatalf("decisions = %+v err = %v, want only the context error", decs, err)
			}
			if !slices.Equal(calls, []string{"touch a"}) || p.cap.prompts != 0 {
				t.Fatalf("check calls = %v prompts = %d, want only the earlier member consulted and no prompt", calls, p.cap.prompts)
			}
		})
	}
}

func TestPrePromptCheck_PlanAllowRecordsTheRequest(t *testing.T) {
	for _, tc := range []struct{ input, platform string }{
		{"touch a", "linux"}, {"ls > out.txt", "linux"}, {"hg update", "linux"}, {"ps -o pid", "darwin"},
	} {
		input := tc.input
		t.Run(input, func(t *testing.T) {
			withShellPlatform(t, tc.platform)
			r := shellBatchReq(t, modePlan, input)
			base := newPreFixture(PromptDeny, nil)
			base.deps.PrePromptCheck = nil
			if d := base.mustRun(t, "single", r)[0]; d.DenialSource != outcomeSourceModeAuto {
				t.Fatalf("without the check %q = %+v, want the Plan denial", input, d)
			}

			p := newPreFixture(PromptDeny, map[string]PrePromptResult{r.Req.Subject: allow()})
			d := p.mustRun(t, "single", r)[0]
			if d.Outcome != "once" || d.Grant != nil || d.ReadOnlyAuto || d.DenyEnvelope != "" {
				t.Fatalf("decision = %+v, want allow once without grant or ReadOnlyAuto", d)
			}
			wantKinds(t, p.cap.kinds(), []string{"permission_matched"})
			want := orchEmitted{kind: "permission_matched", subjectKind: r.Req.Kind, subject: input, pathScope: scopeProj,
				outcome: "once", outcomeSource: "system_one_check"}
			if r.Req.Kind == subjectKindLiteral {
				want.argHash = ComputeArgumentHash(input)
			} else {
				want.subject = strings.Join(r.Req.SubjectTokens, " ")
				want.directRequestSubject = r.Req.Subject
			}
			if got := p.cap.events[0]; !reflect.DeepEqual(got, want) {
				t.Fatalf("event = %+v\nwant  %+v", got, want)
			}

			real := newPreFixture(PromptDeny, map[string]PrePromptResult{r.Req.Subject: allow()})
			store := newStore()
			withRealEmitters(real.orchFixture, store)
			real.mustRun(t, "single", r)
			wantKinds(t, storeEventKinds(t, store), []string{"permission_matched"})
		})
	}
}

func TestPrePromptCheck_PlanDeclineAppendsTheNoteAndAsksAgain(t *testing.T) {
	r := shellBatchReq(t, modePlan, "touch a")
	base := newPreFixture(PromptDeny, nil)
	base.deps.PrePromptCheck = nil
	baseDec := base.mustRun(t, "single", r)[0]

	p := newPreFixture(PromptDeny, map[string]PrePromptResult{"touch a": decline(" use the edit tool\n")})
	for round := 1; round <= 2; round++ {
		d := p.mustRun(t, "single", r)[0]
		want := baseDec.DenyReason + "; use the edit tool"
		deniedBy, reason := decodeDenyFields(t, d.DenyEnvelope)
		if d.Outcome != "deny" || deniedBy != "mode" || reason != want || d.DenyReason != want || d.DenialSource != outcomeSourceModeAuto {
			t.Fatalf("round %d decision = %+v (envelope %s/%q), want the mode deny with reason %q", round, d, deniedBy, reason, want)
		}
		if len(p.check.calls) != round {
			t.Fatalf("round %d check calls = %d, want a consultation per denial", round, len(p.check.calls))
		}
	}
	if len(p.cap.records) != 0 || p.cap.prompts != 0 {
		t.Fatalf("records = %v prompts = %d, want neither", p.cap.records, p.cap.prompts)
	}
	if got := p.eventsWithSource(outcomeSourceModeAuto); len(got) != 2 || got[0].outcome != "deny" {
		t.Fatalf("events = %+v, want today's mode_auto deny records", p.cap.events)
	}
}

func TestPrePromptCheck_PlanDenyNoteBounds(t *testing.T) {
	r := shellBatchReq(t, modePlan, "touch a")
	base := newPreFixture(PromptDeny, nil)
	base.deps.PrePromptCheck = nil
	baseDec := base.mustRun(t, "single", r)[0]

	for _, note := range []string{"", " \t\n "} {
		p := newPreFixture(PromptDeny, map[string]PrePromptResult{"touch a": decline(note)})
		if d := p.mustRun(t, "single", r)[0]; !reflect.DeepEqual(d, baseDec) {
			t.Fatalf("note %q decision = %+v, want today's %+v", note, d, baseDec)
		}
	}

	cases := []struct{ name, note, wantNote string }{
		{"multibyte note capped on a rune boundary", strings.Repeat("€", 200), strings.Repeat("€", 85)},
		{"invalid UTF-8 replaced", "bad \xff byte", "bad � byte"},
		{"whitespace exposed by the cap trimmed", strings.Repeat("a", 255) + "  b", strings.Repeat("a", 255)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPreFixture(PromptDeny, map[string]PrePromptResult{"touch a": decline(tc.note)})
			d := p.mustRun(t, "single", r)[0]
			deniedBy, reason := decodeDenyFields(t, d.DenyEnvelope)
			if want := baseDec.DenyReason + "; " + tc.wantNote; reason != want || d.DenyReason != want || deniedBy != "mode" {
				t.Fatalf("reason = %q DenyReason = %q denied_by = %s, want %q", reason, d.DenyReason, deniedBy, want)
			}
		})
	}

	got := withDenyNote(strings.Repeat("ü", 400), strings.Repeat("€", 200))
	if want := strings.Repeat("ü", 127) + "; " + strings.Repeat("€", 85); got != want || len(got) > 512 || !utf8.ValidString(got) {
		t.Fatalf("withDenyNote long reason = %q (%d bytes), want %q", got, len(got), want)
	}
}

func TestPrePromptCheck_NotConsulted(t *testing.T) {
	read := shellBatchReq(t, modePlan, "ls")
	cases := []struct {
		name string
		r    BatchRequest
	}{
		{"build", shellBatchReq(t, "build", "touch a")},
		{"tool subject", BatchRequest{Req: toolReq(), ModeCtx: ModeContext{Mode: modeAutoEdits, Class: ClassMutating}}},
		{"host", BatchRequest{Req: hostReq("web_fetch", "docs.example.com"), ModeCtx: func() ModeContext {
			mc := hostModeCtx("web_fetch")
			mc.Mode = modeAutoEdits
			return mc
		}()}},
		{"plan read-only", read},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPreFixture(PromptAllowOnce, map[string]PrePromptResult{tc.r.Req.Subject: allow()})
			p.mustRun(t, "single", tc.r)
			if len(p.check.calls) != 0 {
				t.Fatalf("check calls = %v, want none", p.check.calls)
			}
		})
	}
}

func TestPrePromptCheck_ExceptionalActionsKeepTodaysAnswer(t *testing.T) {
	for _, input := range []string{"rm x", "git push"} {
		for _, constrained := range []bool{false, true} {
			for _, path := range authorizePaths {
				t.Run(input+"/"+path+"/constrained="+map[bool]string{false: "no", true: "yes"}[constrained], func(t *testing.T) {
					r := shellBatchReq(t, modeAutoEdits, input)
					r.ModeCtx.ExecutionConstrained = constrained
					p := newPreFixture(PromptAllowOnce, map[string]PrePromptResult{r.Req.Subject: allow()})
					decs := p.mustRun(t, path, r)
					wantPrompts := 1
					if constrained && input == "rm x" {
						wantPrompts = 0
					}
					if len(p.check.calls) != 0 || p.promptShown() != wantPrompts || decs[0].Outcome != "once" {
						t.Fatalf("check calls = %v prompt_shown = %d decision = %+v, want %d prompts and no check", p.check.calls, p.promptShown(), decs[0], wantPrompts)
					}
				})
			}
		}
		t.Run(input+"/plan", func(t *testing.T) {
			r := shellBatchReq(t, modePlan, input)
			p := newPreFixture(PromptAllowOnce, map[string]PrePromptResult{r.Req.Subject: decline("n")})
			d := p.mustRun(t, "single", r)[0]
			if len(p.check.calls) != 0 || d.DenialSource != outcomeSourceModeAuto || strings.HasSuffix(d.DenyReason, "; n") {
				t.Fatalf("check calls = %v decision = %+v, want today's Plan denial", p.check.calls, d)
			}
		})
	}

	const unresolved = "for f in a; do echo $f; done"
	for _, mode := range []string{modeAutoEdits, modePlan} {
		t.Run("unresolved literal/"+mode, func(t *testing.T) {
			r := shellBatchReq(t, mode, unresolved)
			if authority, ok := ClassifyExceptional(r.Req, r.ModeCtx); r.Req.Kind != subjectKindLiteral || authority != "" || ok {
				t.Fatalf("%q = %s, authority %q classifiable %v; want an unclassifiable literal", unresolved, r.Req.Kind, authority, ok)
			}
			p := newPreFixture(PromptDeny, map[string]PrePromptResult{r.Req.Subject: allow()})
			if d := p.mustRun(t, "single", r)[0]; len(p.check.calls) != 1 || d.Outcome != "once" {
				t.Fatalf("check calls = %v decision = %+v, want the check consulted and allowing", p.check.calls, d)
			}
		})
	}
}

func TestPrePromptCheck_BrokenSettingsConfinedShell(t *testing.T) {
	for _, mode := range []string{modePlan, modeAutoEdits} {
		for _, path := range authorizePaths {
			t.Run(mode+"/"+path, func(t *testing.T) {
				r := shellBatchReq(t, mode, "touch a")
				r.ModeCtx.ExecutionConstrained, r.ModeCtx.SettingsBroken = true, true

				p := newPreFixture(PromptDeny, map[string]PrePromptResult{"touch a": allow()})
				if d := p.mustRun(t, path, r)[0]; len(p.check.calls) != 1 || d.Outcome != "once" || p.cap.prompts+len(p.escs) != 0 {
					t.Fatalf("cache miss: check calls = %v decision = %+v, want the check to allow without a prompt", p.check.calls, d)
				}

				p = newPreFixture(PromptDeny, map[string]PrePromptResult{"touch a": allow()})
				p.cache.hits[turnCacheKeyOf(r.Req)] = outcomeDeny
				if d := p.mustRun(t, path, r)[0]; len(p.check.calls) != 0 || d.DenialSource != outcomeSourceCache {
					t.Fatalf("cached deny: check calls = %v decision = %+v, want the cached denial", p.check.calls, d)
				}
			})
		}
	}
}

func TestPrePromptCheck_Precedence(t *testing.T) {
	auto := func(mut func(*orchFixture, *BatchRequest)) func(t *testing.T) (*preFixture, BatchRequest) {
		return func(t *testing.T) (*preFixture, BatchRequest) {
			r := shellBatchReq(t, modeAutoEdits, "touch a")
			p := newPreFixture(PromptAllowOnce, map[string]PrePromptResult{"touch a": allow(), "edit": allow()})
			mut(p.orchFixture, &r)
			return p, r
		}
	}
	bypass := []struct {
		name   string
		setup  func(t *testing.T) (*preFixture, BatchRequest)
		prompt bool
	}{
		{"grant", auto(func(f *orchFixture, r *BatchRequest) {
			f.grants.entries = []PermissionEntry{directGrant(r.Req.Subject, scopeProj, grantKindFolder)}
		}), false},
		{"cache", auto(func(f *orchFixture, r *BatchRequest) { f.cache.hits[turnCacheKeyOf(r.Req)] = outcomeOnce }), false},
		{"open read", auto(func(_ *orchFixture, r *BatchRequest) { r.ModeCtx.OpenRead = true }), false},
		{"confined", auto(func(_ *orchFixture, r *BatchRequest) { r.ModeCtx.ExecutionConstrained = true }), false},
		{"network egress", auto(func(_ *orchFixture, r *BatchRequest) { r.ModeCtx.NetworkEgress = true }), true},
		{"external read", auto(func(_ *orchFixture, r *BatchRequest) { r.ModeCtx.ExternalRead = true }), true},
		{"file request", auto(func(_ *orchFixture, r *BatchRequest) {
			r.Req = MatchRequest{Kind: subjectKindTool, Subject: "edit", PathScope: scopeProj}
			r.ModeCtx = ModeContext{Mode: modeAutoEdits, Class: ClassMutating, ToolName: toolNameEdit, TargetPath: "/elsewhere/x", ProjectRoot: scopeProj}
		}), true},
	}
	for _, tc := range bypass {
		t.Run(tc.name, func(t *testing.T) {
			p, r := tc.setup(t)
			p.mustRun(t, "single", r)
			if len(p.check.calls) != 0 || (len(p.escs) == 1) != tc.prompt {
				t.Fatalf("check calls = %v prompts = %d, want no check and prompt=%v", p.check.calls, len(p.escs), tc.prompt)
			}
		})
	}

	for name, mut := range map[string]func(*orchFixture, MatchRequest){
		"grant": func(f *orchFixture, req MatchRequest) {
			f.grants.entries = []PermissionEntry{directGrant(req.Subject, scopeProj, grantKindFolder)}
		},
		"cached deny": func(f *orchFixture, req MatchRequest) { f.cache.hits[turnCacheKeyOf(req)] = outcomeDeny },
	} {
		t.Run("plan posture before "+name, func(t *testing.T) {
			r := shellBatchReq(t, modePlan, "touch a")
			p := newPreFixture(PromptDeny, map[string]PrePromptResult{"touch a": allow()})
			mut(p.orchFixture, r.Req)
			d := p.mustRun(t, "single", r)[0]
			if len(p.check.calls) != 1 || d.Grant != nil || len(p.eventsWithSource("system_one_check")) != 1 {
				t.Fatalf("check calls = %v decision = %+v events = %+v, want the posture's check to decide", p.check.calls, d, p.cap.events)
			}
		})
	}
}

type callerKey struct{}

func TestPrePromptCheck_CancellationReturnsTheContextError(t *testing.T) {
	cases := []struct{ path, mode string }{
		{"single", modeAutoEdits}, {"batch", modeAutoEdits}, {"independent", modeAutoEdits}, {"single", modePlan},
	}
	for _, tc := range cases {
		t.Run(tc.path+"/"+tc.mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), callerKey{}, "caller"))
			defer cancel()
			p := newPreFixture(PromptAllowOnce, nil)
			observed := false
			p.deps.PrePromptCheck = func(hookCtx context.Context, _ MatchRequest, _ ModeContext) PrePromptResult {
				cancel()
				observed = hookCtx.Value(callerKey{}) == "caller" && hookCtx.Err() != nil
				return allow()
			}
			decs, err := p.run(ctx, tc.path, []BatchRequest{shellBatchReq(t, tc.mode, "touch a"), shellBatchReq(t, tc.mode, "touch b")})
			if !errors.Is(err, context.Canceled) || decs != nil {
				t.Fatalf("decisions = %+v err = %v, want only the context error", decs, err)
			}
			if !observed {
				t.Fatal("the check did not observe the caller's context and its cancellation")
			}
			if p.cap.prompts+len(p.escs) != 0 || len(p.cap.events) != 0 {
				t.Fatalf("prompts = %d events = %+v, want neither", p.cap.prompts+len(p.escs), p.cap.events)
			}
		})
	}
}

func TestPrePromptCheck_MatchedAppendFailure(t *testing.T) {
	appendErr := errors.New("append failed")
	cases := []struct{ path, mode string }{
		{"single", modeAutoEdits}, {"batch", modeAutoEdits}, {"independent", modeAutoEdits}, {"single", modePlan},
	}
	for _, tc := range cases {
		t.Run(tc.path+"/"+tc.mode, func(t *testing.T) {
			p := newPreFixture(PromptAllowOnce, map[string]PrePromptResult{"touch a": decline("n"), "touch b": allow()})
			p.deps.EmitMatched = func(_, _, _, _, _, _, src, _, _ string) error {
				if src == "system_one_check" {
					return appendErr
				}
				return nil
			}
			reqs := []BatchRequest{shellBatchReq(t, tc.mode, "touch b")}
			if tc.path != "single" {
				reqs = []BatchRequest{shellBatchReq(t, tc.mode, "touch a"), shellBatchReq(t, tc.mode, "touch b")}
			}
			decs, err := p.run(context.Background(), tc.path, reqs)
			if !errors.Is(err, appendErr) || decs != nil {
				t.Fatalf("decisions = %+v err = %v, want the append error and no decisions", decs, err)
			}
			if p.cap.prompts+len(p.escs) != 0 || p.promptShown() != 0 || len(p.cap.records) != 0 || len(p.cap.appends) != 0 {
				t.Fatalf("prompts = %d records = %v appends = %v, want no fallback", p.cap.prompts+len(p.escs), p.cap.records, p.cap.appends)
			}
		})
	}
}
