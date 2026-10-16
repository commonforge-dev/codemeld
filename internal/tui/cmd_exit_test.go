// Tests for the /exit clean-shutdown handler: slash + alias + bare-synonym
// routing through dispatch, event-before-flush ordering, the success resume-hint
// + exit-0 path, and the second-failure exit-1 path.
package tui

import (
	"errors"
	"testing"

	"codemeld.dev/codemeld/internal/sessions"
)

// fakeExitController is an in-memory ExitController. It records the flush and
// Finish calls and, so the event-before-flush ordering can be asserted, counts
// the slash_command events present in the bound store at the moment FlushOnExit
// runs. flushErr drives the success vs. second-failure path.
type fakeExitController struct {
	sessionID string
	flushErr  error
	store     *sessions.Store

	flushCalls         int
	slashEventsAtFlush int
	finishCalled       bool
	finishCode         int
	finishHint         string
}

func (c *fakeExitController) SessionID() string { return c.sessionID }

func (c *fakeExitController) FlushOnExit() error {
	c.flushCalls++
	if c.store != nil {
		c.slashEventsAtFlush = len(slashEvents(c.store))
	}
	return c.flushErr
}

func (c *fakeExitController) Finish(code int, hint string) {
	c.finishCalled = true
	c.finishCode = code
	c.finishHint = hint
}

// exitRegistry builds a one-command registry whose /exit (alias /quit) entry is
// bound to ctrl, mirroring the production registry binding.
func exitRegistry(t *testing.T, ctrl ExitController) *Registry {
	t.Helper()
	r, err := NewRegistry([]Command{
		{Name: "exit", Aliases: []string{"quit"}, Description: "Exit codemeld", ArgSig: ArgNone, Phase: PhaseOne, Handler: NewExitHandler(ctrl)},
	})
	if err != nil {
		t.Fatalf("build exit registry: %v", err)
	}
	return r
}

func TestResumeHint(t *testing.T) {
	const id = "0190aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee"
	want := "to resume this session run: codemeld --resume " + id
	if got := ResumeHint(id); got != want {
		t.Errorf("ResumeHint(%q) = %q, want %q", id, got, want)
	}
}

// TestExit_RoutingReachesHandler asserts every spelling of the exit command —
// /exit, /quit, bare exit/quit, and case-insensitive bare forms — reaches the
// same handler through registry dispatch and records the canonical slash_command
// event.
func TestExit_RoutingReachesHandler(t *testing.T) {
	for _, in := range []string{"/exit", "/quit", "exit", "quit", "EXIT", "Quit", "  exit  "} {
		t.Run(in, func(t *testing.T) {
			host := newFakeHost()
			ctrl := &fakeExitController{sessionID: "sess-1", store: host.store}
			res := exitRegistry(t, ctrl).DispatchSlashInput(in, host)

			if res.Status != StatusHandled || res.Canonical != "exit" {
				t.Fatalf("dispatch %q = %+v, want Handled/exit", in, res)
			}
			if res.Err != nil {
				t.Fatalf("dispatch %q returned err %v, want nil", in, res.Err)
			}
			if !ctrl.finishCalled {
				t.Fatal("Finish was not called: handler did not run the exit sequence")
			}
			evs := host.events()
			if len(evs) != 1 {
				t.Fatalf("appended %d slash_command events, want 1", len(evs))
			}
			p := decodeSlash(t, evs[0])
			if p.Name != "exit" {
				t.Errorf("event name = %q, want canonical %q", p.Name, "exit")
			}
			if p.Outcome != "success" {
				t.Errorf("event outcome = %q, want success", p.Outcome)
			}
			if len(p.Args) != 0 {
				t.Errorf("event args = %v, want empty", p.Args)
			}
		})
	}
}

// TestExit_EventAppendedBeforeFlush asserts the slash_command event is in the
// in-memory stream before the clean-shutdown flush runs (step 1 before
// step 2).
func TestExit_EventAppendedBeforeFlush(t *testing.T) {
	host := newFakeHost()
	ctrl := &fakeExitController{sessionID: "sess-1", store: host.store}

	exitRegistry(t, ctrl).DispatchSlashInput("/exit", host)

	if ctrl.flushCalls != 1 {
		t.Fatalf("FlushOnExit called %d times, want 1", ctrl.flushCalls)
	}
	if ctrl.slashEventsAtFlush != 1 {
		t.Errorf("slash_command events present at flush = %d, want 1 (event must precede the flush)", ctrl.slashEventsAtFlush)
	}
}

// TestExit_FlushSuccess asserts the success path: resume hint printed and exit 0
// (step 3).
func TestExit_FlushSuccess(t *testing.T) {
	host := newFakeHost()
	ctrl := &fakeExitController{sessionID: "sess-42", store: host.store}

	res := exitRegistry(t, ctrl).DispatchSlashInput("/exit", host)

	if res.Err != nil {
		t.Fatalf("handler returned err %v, want nil on success", res.Err)
	}
	if ctrl.flushCalls != 1 {
		t.Errorf("FlushOnExit called %d times, want 1", ctrl.flushCalls)
	}
	if !ctrl.finishCalled || ctrl.finishCode != 0 {
		t.Fatalf("Finish(code=%d, called=%v), want code 0", ctrl.finishCode, ctrl.finishCalled)
	}
	if want := ResumeHint("sess-42"); ctrl.finishHint != want {
		t.Errorf("Finish hint = %q, want %q", ctrl.finishHint, want)
	}
}

// TestBuildRegistry_ExitDispatchesToHandler pins the production dispatch wiring:
// /exit and its synonyms go through NewExitHandler(exit) — not recordHandler — so
// dispatch runs the clean-shutdown sequence (flush then Finish with exit 0 +
// resume hint) instead of a generic recordHandler success that skips the flush
// and exit-code propagation.
// If the exit entry were left on recordHandler, FlushOnExit/Finish would never run
// and every assertion below would fail.
func TestBuildRegistry_ExitDispatchesToHandler(t *testing.T) {
	// /status, /effort, and /model are not dispatched here, so the zero-value
	// StatusState/EffortDeps/ModelDeps are never exercised.
	for _, in := range []string{"/exit", "/quit", "exit"} {
		t.Run(in, func(t *testing.T) {
			host := newFakeHost()
			ctrl := &fakeExitController{sessionID: "sess-prod", store: host.store}
			reg := BuildRegistry(map[string]HandlerFunc{"exit": NewExitHandler(ctrl)})

			res := reg.DispatchSlashInput(in, host)
			if res.Status != StatusHandled || res.Canonical != "exit" || res.Err != nil {
				t.Fatalf("dispatch %q = %+v, want Handled/exit/nil-err", in, res)
			}
			if ctrl.flushCalls != 1 {
				t.Errorf("FlushOnExit called %d times, want 1 (recordHandler would call 0)", ctrl.flushCalls)
			}
			if !ctrl.finishCalled || ctrl.finishCode != 0 {
				t.Fatalf("Finish(code=%d, called=%v), want code 0", ctrl.finishCode, ctrl.finishCalled)
			}
			if want := ResumeHint("sess-prod"); ctrl.finishHint != want {
				t.Errorf("Finish hint = %q, want %q", ctrl.finishHint, want)
			}
			evs := host.events()
			if len(evs) != 1 {
				t.Fatalf("appended %d slash_command events, want 1", len(evs))
			}
			if p := decodeSlash(t, evs[0]); p.Name != "exit" || p.Outcome != "success" || len(p.Args) != 0 {
				t.Errorf("event = %+v, want name=exit args=[] outcome=success", p)
			}
		})
	}
}

// TestExit_FlushSecondFailure asserts the second-failure path: exit 1
// with no resume hint, the slash_command event still recorded (it is lost only
// because the flush never reaches disk), and the flush error propagated.
func TestExit_FlushSecondFailure(t *testing.T) {
	host := newFakeHost()
	flushErr := errors.New("session write failed on exit after retry")
	ctrl := &fakeExitController{sessionID: "sess-7", store: host.store, flushErr: flushErr}

	res := exitRegistry(t, ctrl).DispatchSlashInput("/exit", host)

	if !errors.Is(res.Err, flushErr) {
		t.Fatalf("handler err = %v, want the flush error", res.Err)
	}
	if !ctrl.finishCalled || ctrl.finishCode != 1 {
		t.Fatalf("Finish(code=%d, called=%v), want code 1", ctrl.finishCode, ctrl.finishCalled)
	}
	if ctrl.finishHint != "" {
		t.Errorf("Finish hint = %q, want empty on the second-failure path", ctrl.finishHint)
	}
	// The event was appended before the flush; it is lost with the unflushed tail
	// only because the write never lands, not because the handler skipped it.
	if evs := host.events(); len(evs) != 1 {
		t.Errorf("appended %d slash_command events, want 1", len(evs))
	}
}
