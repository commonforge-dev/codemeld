package netproxy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func newApprovals() *approvals {
	return &approvals{session: map[string]bool{}}
}

func TestSessionApprovalMatchesOnlyTheNormalizedTarget(t *testing.T) {
	cases := []struct {
		approved, host, port string
		covered              bool
	}{
		{"example.com", "example.com", "443", true},
		{"example.com", "EXAMPLE.com.", "443", true},
		{"example.com", "example.com", "0443", true},
		{"example.com", "sub.example.com", "443", false},
		{"example.com", "example.com", "8443", false},
		{"example.com", "example.com.evil", "443", false},
		{"example.com", "com", "443", false},
		{"2001:DB8::1", "2001:db8:0::1", "443", true},
		{"2001:DB8::1", "2001:db8::2", "443", false},
		{"::ffff:1.2.3.4", "::ffff:1.2.3.4", "443", true},
		{"::ffff:1.2.3.4", "1.2.3.4", "443", false},
		{"1.2.3.4", "::ffff:1.2.3.4", "443", false},
	}
	for _, tc := range cases {
		a := newApprovals()
		a.commit(context.Background(), tc.approved, "443", true)
		if got := a.covers(tc.host, tc.port); got != tc.covered {
			t.Errorf("after approving %s:443, covers(%s, %s) = %v, want %v", tc.approved, tc.host, tc.port, got, tc.covered)
		}
		approvedKey, _ := targetKey(tc.approved, "443")
		key, ok := targetKey(tc.host, tc.port)
		if agree := ok && key == approvedKey; agree != tc.covered {
			t.Errorf("targetKey(%s, %s) = %q, approved key %q: disagrees with covers", tc.host, tc.port, key, approvedKey)
		}
	}
}

func TestSessionApprovalRejectsZonedAndInvalidTargets(t *testing.T) {
	for _, target := range [][2]string{{"2001:db8::1%eth0", "443"}, {"fe80::1%25eth0", "443"}, {"example.com", "0"}, {"example.com", "https"}, {"exa mple.com", "443"}} {
		a := newApprovals()
		a.commit(context.Background(), target[0], target[1], true)
		if len(a.session) != 0 {
			t.Errorf("allow(%s, %s) stored %v", target[0], target[1], a.session)
		}
		if _, ok := targetKey(target[0], target[1]); ok {
			t.Errorf("targetKey accepted %s %s", target[0], target[1])
		}
	}
	a := newApprovals()
	a.commit(context.Background(), "2001:db8::1", "443", true)
	if a.covers("2001:db8::1%eth0", "443") {
		t.Error("a zoned literal is covered by the unzoned approval")
	}
}

type askCall struct {
	ctx     context.Context
	host    string
	port    string
	covered func() bool
	answer  chan askAnswer
}

type askAnswer struct {
	d   Decision
	err error
}

func gatedAsker(t *testing.T) (Asker, chan askCall) {
	calls, abandoned := make(chan askCall, 8), make(chan struct{})
	t.Cleanup(func() { close(abandoned) })
	return func(ctx context.Context, host, port string, covered func() bool, _ func(Decision) bool) (Decision, error) {
		c := askCall{ctx: ctx, host: host, port: port, covered: covered, answer: make(chan askAnswer, 1)}
		calls <- c
		select {
		case a := <-c.answer:
			return a.d, a.err
		case <-abandoned:
			return DecisionDeny, errors.New("the test ended without answering")
		}
	}, calls
}

func nextAsk(t *testing.T, calls chan askCall) askCall {
	t.Helper()
	select {
	case c := <-calls:
		return c
	case <-time.After(testWait):
		t.Fatal("the asker was never called")
		return askCall{}
	}
}

func approveAsync(s *Server, ctx context.Context, o *Owner, host, port string) chan string {
	done := make(chan string, 1)
	go func() { done <- s.approve(ctx, o, host, port) }()
	return done
}

func result(t *testing.T, done chan string) string {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(testWait):
		t.Fatal("approve never returned")
		return ""
	}
}

func newAskingServer(t *testing.T, ask Asker) (*Server, *Owner) {
	t.Helper()
	s, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	o := s.NewOwner(ask)
	t.Cleanup(o.Close)
	return s, o
}

func TestConcurrentAllowOnceAnswersStayWithTheirRequest(t *testing.T) {
	ask, calls := gatedAsker(t)
	s, o := newAskingServer(t, ask)
	first := approveAsync(s, context.Background(), o, "example.com", "443")
	a := nextAsk(t, calls)
	second := approveAsync(s, context.Background(), o, "example.com", "443")
	b := nextAsk(t, calls)
	b.answer <- askAnswer{d: DecisionDeny}
	if got := result(t, second); got != "not approved (denied)" {
		t.Fatalf("denied request: %q, want not approved (denied)", got)
	}
	a.answer <- askAnswer{d: DecisionOnce}
	if got := result(t, first); got != "" {
		t.Fatalf("allowed-once request: %q, want admitted", got)
	}
	if s.approvals.covers("example.com", "443") {
		t.Fatal("allow once stored a session approval")
	}
}

func TestSessionAnswerAdmitsAQueuedRequestThroughTheRecheck(t *testing.T) {
	entered, turn, prompts, answers := make(chan struct{}, 1), make(chan struct{}), make(chan string), make(chan Decision)
	s, o := newAskingServer(t, func(ctx context.Context, host, port string, covered func() bool, _ func(Decision) bool) (Decision, error) {
		entered <- struct{}{}
		<-turn
		if covered() {
			return DecisionOnce, nil
		}
		select {
		case prompts <- host + ":" + port:
			return <-answers, nil
		case <-ctx.Done():
			return DecisionDeny, ctx.Err()
		}
	})
	first := approveAsync(s, context.Background(), o, "example.com", "443")
	<-entered
	turn <- struct{}{}
	<-prompts
	queued := approveAsync(s, context.Background(), o, "EXAMPLE.com.", "443")
	<-entered
	answers <- DecisionSession
	if got := result(t, first); got != "" {
		t.Fatalf("session-approved request: %q", got)
	}
	turn <- struct{}{}
	if got := result(t, queued); got != "" {
		t.Fatalf("queued request: %q, want admitted by the recheck", got)
	}
	if len(s.approvals.session) != 1 {
		t.Fatalf("session approvals %v, want only the answered one", s.approvals.session)
	}
	for _, target := range [][2]string{{"sub.example.com", "443"}, {"example.com", "8443"}, {"example.com.evil", "443"}} {
		other := approveAsync(s, context.Background(), o, target[0], target[1])
		<-entered
		turn <- struct{}{}
		if got := <-prompts; got != target[0]+":"+target[1] {
			t.Fatalf("prompted for %s, want %s:%s", got, target[0], target[1])
		}
		answers <- DecisionDeny
		if got := result(t, other); got != "not approved (denied)" {
			t.Fatalf("%s:%s: %q", target[0], target[1], got)
		}
	}
}

func TestLateAnswerAfterCancellationRefusesAsCommandEnded(t *testing.T) {
	for _, late := range []askAnswer{{d: DecisionSession}, {d: DecisionDeny, err: context.Canceled}} {
		ask, calls := gatedAsker(t)
		s, o := newAskingServer(t, ask)
		ctx, cancel := context.WithCancel(context.Background())
		done := approveAsync(s, ctx, o, "example.com", "443")
		c := nextAsk(t, calls)
		cancel()
		<-c.ctx.Done()
		c.answer <- late
		if got := result(t, done); got != "not approved (command ended)" {
			t.Fatalf("late answer %+v: %q, want not approved (command ended)", late, got)
		}
		if s.approvals.covers("example.com", "443") {
			t.Fatalf("late answer %+v stored a session approval", late)
		}
	}
}

func TestCancellationAndSessionAnswerHaveOneWinner(t *testing.T) {
	ask, calls := gatedAsker(t)
	s, o := newAskingServer(t, ask)

	done := approveAsync(s, o.ctx, o, "example.com", "443")
	call := nextAsk(t, calls)
	o.Close()
	call.answer <- askAnswer{d: DecisionSession}
	if got := result(t, done); got != "not approved (command ended)" {
		t.Errorf("session answer after the owner was cancelled = %q, want command ended", got)
	}
	if s.approvals.covers("example.com", "443") {
		t.Fatal("a cancelled request stored a session approval")
	}

	o = s.NewOwner(ask)
	defer o.Close()
	done = approveAsync(s, o.ctx, o, "example.com", "443")
	call = nextAsk(t, calls)
	call.answer <- askAnswer{d: DecisionSession}
	if got := result(t, done); got != "" {
		t.Fatalf("session answer before cancellation = %q, want admitted", got)
	}
	o.Close()
	if !s.approvals.covers("example.com", "443") {
		t.Fatal("cancelling after acceptance removed the session approval")
	}
	other := s.NewOwner(ask)
	defer other.Close()
	if got := s.approve(other.ctx, other, "example.com", "443"); got != "" {
		t.Errorf("same target after an accepted session answer = %q, want admitted without asking", got)
	}
	select {
	case <-calls:
		t.Error("the accepted session approval asked again")
	default:
	}
}

func TestAnOwnerWithNoAskerIsRefusedUnlessASessionAnswerCoversTheTarget(t *testing.T) {
	s, asking := newAskingServer(t, answering(DecisionSession, nil))
	silent := s.NewOwner(nil)
	defer silent.Close()
	if got := s.approve(silent.ctx, silent, "example.com", "443"); got != "not approved (no one to ask)" {
		t.Fatalf("uncovered request with no asker = %q, want not approved (no one to ask)", got)
	}
	if got := s.approve(asking.ctx, asking, "example.com", "443"); got != "" {
		t.Fatalf("session answer from the asking owner = %q, want admitted", got)
	}
	if got := s.approve(silent.ctx, silent, "EXAMPLE.com.", "443"); got != "" {
		t.Errorf("target another owner approved for the session = %q, want admitted", got)
	}
	if got := s.approve(silent.ctx, silent, "example.com", "8443"); got != "not approved (no one to ask)" {
		t.Errorf("other port with no asker = %q, want not approved (no one to ask)", got)
	}
}

type slotPrompt struct {
	ctx     context.Context
	target  string
	accept  func(Decision) bool
	release func()
	answer  chan askAnswer
}

type promptSlot struct {
	slot    chan struct{}
	entered chan string
	prompts chan slotPrompt
}

func newPromptSlot() *promptSlot {
	return &promptSlot{slot: make(chan struct{}, 1), entered: make(chan string, 16), prompts: make(chan slotPrompt, 16)}
}

func (ps *promptSlot) asker(t *testing.T) Asker {
	abandoned := make(chan struct{})
	t.Cleanup(func() { close(abandoned) })
	return func(ctx context.Context, host, port string, covered func() bool, accept func(Decision) bool) (Decision, error) {
		ps.entered <- net.JoinHostPort(host, port)
		select {
		case ps.slot <- struct{}{}:
		case <-ctx.Done():
			return DecisionDeny, ctx.Err()
		}
		var once sync.Once
		release := func() { once.Do(func() { <-ps.slot }) }
		defer release()
		if covered() {
			return DecisionOnce, nil
		}
		p := slotPrompt{ctx: ctx, target: net.JoinHostPort(host, port), accept: accept, release: release, answer: make(chan askAnswer, 1)}
		ps.prompts <- p
		select {
		case a := <-p.answer:
			return a.d, a.err
		case <-abandoned:
		case <-ctx.Done():
			select {
			case a := <-p.answer:
				return a.d, a.err
			case <-abandoned:
			case <-time.After(testWait):
			}
		}
		return DecisionDeny, errors.New("the test ended without answering")
	}
}

func (ps *promptSlot) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-ps.entered:
	case <-time.After(testWait):
		t.Fatal("the asker was never called")
	}
}

func (ps *promptSlot) next(t *testing.T, target string) slotPrompt {
	t.Helper()
	select {
	case p := <-ps.prompts:
		if p.target != target {
			t.Fatalf("prompted for %s, want %s", p.target, target)
		}
		return p
	case <-time.After(testWait):
		t.Fatalf("no prompt for %s", target)
		return slotPrompt{}
	}
}

func (ps *promptSlot) noPrompt(t *testing.T) {
	t.Helper()
	select {
	case p := <-ps.prompts:
		t.Fatalf("a second prompt was shown for %s", p.target)
	default:
	}
}

func slotProxy(t *testing.T) (*Server, string, chan net.Conn) {
	t.Helper()
	up, conns := listenUpstream(t)
	s, endpoint := startProxy(t, &fakeNet{upstream: up, names: map[string][]netip.Addr{"example.com": {testPublic}}})
	return s, endpoint, conns
}

func connectTo(authority string) string {
	return "CONNECT " + authority + " HTTP/1.1\r\n\r\n"
}

func status(t *testing.T, br *bufio.Reader) (int, string) {
	t.Helper()
	resp := response(t, br, http.MethodConnect)
	return resp.StatusCode, resp.Header.Get("X-Proxy-Refused")
}

func TestAcceptedSessionAnswerCoversAQueuedRequestBeforeTheAskerReturns(t *testing.T) {
	s, _, conns := slotProxy(t)
	ps := newPromptSlot()
	ask := ps.asker(t)
	_, first := send(t, s, ask, connectTo("example.com:443"))
	ps.waitEntered(t)
	p := ps.next(t, "example.com:443")
	_, queued := send(t, s, ask, connectTo("EXAMPLE.com.:443"))
	ps.waitEntered(t)
	if !p.accept(DecisionSession) {
		t.Fatal("accept(DecisionSession) on a live request = false")
	}
	p.release()
	if code, reason := status(t, queued); code != http.StatusOK {
		t.Fatalf("queued request: %d %q, want admitted while the first asker has not returned", code, reason)
	}
	accepted(t, conns)
	ps.noPrompt(t)

	_, other := send(t, s, ask, connectTo("example.com:8443"))
	ps.waitEntered(t)
	ps.next(t, "example.com:8443").answer <- askAnswer{d: DecisionDeny}
	if code, reason := status(t, other); reason != "not approved (denied)" {
		t.Fatalf("other port: %d %q, want asked and denied", code, reason)
	}

	p.answer <- askAnswer{d: DecisionSession}
	if code, reason := status(t, first); code != http.StatusOK {
		t.Fatalf("first request: %d %q", code, reason)
	}
	accepted(t, conns)
	if len(s.approvals.session) != 1 {
		t.Fatalf("session approvals %v, want only the accepted one", s.approvals.session)
	}
}

func TestAcceptedOnceAnswerDoesNotCoverAQueuedRequest(t *testing.T) {
	s, _, conns := slotProxy(t)
	ps := newPromptSlot()
	ask := ps.asker(t)
	_, first := send(t, s, ask, connectTo("example.com:443"))
	ps.waitEntered(t)
	p := ps.next(t, "example.com:443")
	_, queued := send(t, s, ask, connectTo("example.com:443"))
	ps.waitEntered(t)
	if !p.accept(DecisionOnce) {
		t.Fatal("accept(DecisionOnce) on a live request = false")
	}
	p.release()
	ps.next(t, "example.com:443").answer <- askAnswer{d: DecisionDeny}
	if code, reason := status(t, queued); reason != "not approved (denied)" {
		t.Fatalf("queued request: %d %q, want prompted and denied", code, reason)
	}
	p.answer <- askAnswer{d: DecisionOnce}
	if code, reason := status(t, first); code != http.StatusOK {
		t.Fatalf("first request: %d %q", code, reason)
	}
	accepted(t, conns)
	if len(s.approvals.session) != 0 {
		t.Fatalf("allow once stored %v", s.approvals.session)
	}
}

type endRequest func(s *Server, o *Owner, c net.Conn) <-chan struct{}

func clientDisconnects(_ *Server, _ *Owner, c net.Conn) <-chan struct{} {
	_ = c.Close()
	return nil
}

func ownerCloses(_ *Server, o *Owner, _ net.Conn) <-chan struct{} { return closeOwner(o) }

func sessionStops(s *Server, _ *Owner, _ net.Conn) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		s.Stop()
		close(done)
	}()
	return done
}

func askerCancelled(t *testing.T, p slotPrompt) {
	t.Helper()
	select {
	case <-p.ctx.Done():
	case <-time.After(testWait):
		t.Fatal("the asker's context was not cancelled")
	}
}

func TestCancellationBeforeAcceptStoresNothing(t *testing.T) {
	cases := map[string]struct {
		end  endRequest
		want string
	}{
		"owner close":       {ownerCloses, "not approved (command ended)"},
		"client disconnect": {clientDisconnects, "not approved (command ended)"},
		"session stop":      {sessionStops, "not approved (session ended)"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, endpoint, _ := slotProxy(t)
			ps := newPromptSlot()
			o := s.NewOwner(ps.asker(t))
			t.Cleanup(o.Close)
			c := dialOwned(t, o, endpoint)
			write(t, c, connectTo("example.com:443"))
			p := ps.next(t, "example.com:443")
			ended := tc.end(s, o, c)
			askerCancelled(t, p)
			if p.accept(DecisionSession) {
				t.Fatal("accept after cancellation = true")
			}
			if s.approvals.covers("example.com", "443") {
				t.Fatal("accept after cancellation stored a session approval")
			}
			p.release()
			p.answer <- askAnswer{d: DecisionSession}
			if ended != nil {
				joined(t, ended, name)
			}
			handlersDone(t, s)
			if r := s.Refusals(); len(r) != 1 || r[0] != (Refusal{Host: "example.com", Port: "443", Reason: tc.want}) {
				t.Fatalf("refusals %+v, want only %q", r, tc.want)
			}
			if len(s.approvals.session) != 0 {
				t.Fatalf("session approvals %v, want none", s.approvals.session)
			}
		})
	}
}

func TestCancellationAfterAcceptEndsTheRequestButKeepsTheSessionAnswer(t *testing.T) {
	for name, end := range map[string]endRequest{"owner close": ownerCloses, "client disconnect": clientDisconnects} {
		t.Run(name, func(t *testing.T) {
			s, endpoint, conns := slotProxy(t)
			ps := newPromptSlot()
			ask := ps.asker(t)
			o := s.NewOwner(ask)
			t.Cleanup(o.Close)
			c := dialOwned(t, o, endpoint)
			write(t, c, connectTo("example.com:443"))
			p := ps.next(t, "example.com:443")
			if !p.accept(DecisionSession) {
				t.Fatal("accept(DecisionSession) on a live request = false")
			}
			ended := end(s, o, c)
			askerCancelled(t, p)
			for _, other := range []Asker{nil, ask} {
				if code, reason := connectStatus(t, s, other, "example.com:443"); code != http.StatusOK {
					t.Fatalf("another live owner (asker %v): %d %q, want admitted by the session answer", other != nil, code, reason)
				}
				accepted(t, conns)
			}
			ps.noPrompt(t)
			p.release()
			p.answer <- askAnswer{d: DecisionSession}
			if ended != nil {
				joined(t, ended, name)
			}
			waitFor(t, "the first request's refusal", func() bool { return len(s.Refusals()) == 1 })
			if r := s.Refusals(); r[0] != (Refusal{Host: "example.com", Port: "443", Reason: "not approved (command ended)"}) {
				t.Fatalf("refusals %+v, want only command ended", r)
			}
			if !s.approvals.covers("example.com", "443") {
				t.Fatal("cancellation after acceptance removed the session approval")
			}
		})
	}
	t.Run("session stop", func(t *testing.T) {
		s, endpoint, conns := slotProxy(t)
		ps := newPromptSlot()
		o := s.NewOwner(ps.asker(t))
		t.Cleanup(o.Close)
		c := dialOwned(t, o, endpoint)
		write(t, c, connectTo("example.com:443"))
		p := ps.next(t, "example.com:443")
		if !p.accept(DecisionSession) {
			t.Fatal("accept(DecisionSession) on a live request = false")
		}
		ended := sessionStops(s, o, c)
		askerCancelled(t, p)
		p.release()
		p.answer <- askAnswer{d: DecisionSession}
		joined(t, ended, "session stop")
		handlersDone(t, s)
		if r := s.Refusals(); len(r) != 1 || r[0] != (Refusal{Host: "example.com", Port: "443", Reason: "not approved (session ended)"}) {
			t.Fatalf("refusals %+v, want only session ended", r)
		}
		select {
		case <-conns:
			t.Fatal("the request cancelled by session stop reached the upstream server")
		default:
		}
		if !s.approvals.covers("example.com", "443") {
			t.Fatal("session stop after acceptance removed the session approval")
		}
	})
}

func TestAcceptRejectsInvalidAndWideningAnswers(t *testing.T) {
	s, _, conns := slotProxy(t)
	ps := newPromptSlot()
	ask := ps.asker(t)
	_, br := send(t, s, ask, connectTo("example.com:443"))
	p := ps.next(t, "example.com:443")
	for _, d := range []Decision{DecisionDeny, Decision(-1), Decision(3)} {
		if p.accept(d) {
			t.Errorf("accept(%d) = true, want false", d)
		}
	}
	if len(s.approvals.session) != 0 {
		t.Fatalf("invalid acceptance stored %v", s.approvals.session)
	}
	for range 2 {
		if !p.accept(DecisionOnce) {
			t.Fatal("accepting the same once answer twice was refused")
		}
	}
	if p.accept(DecisionSession) {
		t.Error("accept(DecisionSession) after an accepted once answer = true")
	}
	p.release()
	p.answer <- askAnswer{d: DecisionSession}
	if code, reason := status(t, br); code != http.StatusOK {
		t.Fatalf("accepted once answer: %d %q, want admitted", code, reason)
	}
	accepted(t, conns)
	if len(s.approvals.session) != 0 {
		t.Fatalf("a once answer became session authority: %v", s.approvals.session)
	}

	_, br = send(t, s, ask, connectTo("example.com:443"))
	p = ps.next(t, "example.com:443")
	if !p.accept(DecisionSession) {
		t.Fatal("accept(DecisionSession) on a live request = false")
	}
	p.release()
	p.answer <- askAnswer{d: DecisionDeny, err: errors.New("prompt broke after acceptance")}
	if code, reason := status(t, br); code != http.StatusOK {
		t.Fatalf("accepted session answer then a prompt error: %d %q, want admitted", code, reason)
	}
	accepted(t, conns)
	if !s.approvals.covers("example.com", "443") {
		t.Fatal("a prompt error after acceptance revoked the session answer")
	}
}

func TestAcceptAfterTheAskerReturnedStoresNothing(t *testing.T) {
	s, _, conns := slotProxy(t)
	leaked := make(chan func(Decision) bool, 1)
	ask := func(_ context.Context, _, _ string, _ func() bool, accept func(Decision) bool) (Decision, error) {
		leaked <- accept
		return DecisionOnce, nil
	}
	if code, reason := connectStatus(t, s, ask, "example.com:443"); code != http.StatusOK {
		t.Fatalf("once answer without accept: %d %q, want admitted by the fallback", code, reason)
	}
	accepted(t, conns)
	if (<-leaked)(DecisionSession) || s.approvals.covers("example.com", "443") {
		t.Fatal("accept called after the asker returned stored a session approval")
	}
}
