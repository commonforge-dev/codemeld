// Package bootstrap assembles codemeld's runtime dependencies.
package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

func hostRequest(subject, host string) permissions.MatchRequest {
	return permissions.MatchRequest{Kind: matchKindHost, Subject: subject, Host: host}
}

func freshHostRequest(subject, host string) permissions.MatchRequest {
	req := hostRequest(subject, host)
	req.FreshConfirmation = true
	return req
}

func promptHost(t *testing.T, input string, req permissions.MatchRequest, disp dispatch.PromptDisplay) (string, permissions.PromptOutcome) {
	t.Helper()
	var out bytes.Buffer
	p := newTerminalPrompter(strings.NewReader(input), &out)
	outcome, err := p.build(req, disp)(context.Background(), permissions.ScopeEscalation{NarrowerScope: "/proj/sub/imgdown"})
	if err != nil {
		t.Fatalf("host prompt: %v", err)
	}
	return out.String(), outcome
}

func TestTerminalPrompter_ChoiceParsing(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantChoice permissions.PromptChoice
		wantDeny   bool
	}{
		{"digit allow-once", "1\n", permissions.PromptAllowOnce, false},
		{"no trailing newline", "1", permissions.PromptAllowOnce, false},
		{"trimmed whitespace", "  1  \n", permissions.PromptAllowOnce, false},
		{"word once", "once\n", permissions.PromptAllowOnce, false},
		{"alias o", "o\n", permissions.PromptAllowOnce, false},
		{"digit deny", "2\n", permissions.PromptDeny, true},
		{"word deny", "deny\n", permissions.PromptDeny, true},
		{"alias n", "n\n", permissions.PromptDeny, true},
		{"digit session", "3\n", permissions.PromptAllowSession, false},
		{"word session", "session\n", permissions.PromptAllowSession, false},
		{"alias s", "s\n", permissions.PromptAllowSession, false},
		{"digit project", "4\n", permissions.PromptAllowFolder, false},
		{"word project", "project\n", permissions.PromptAllowFolder, false},
		{"alias p", "p\n", permissions.PromptAllowFolder, false},
		{"eof closed stdin", "", permissions.PromptDeny, true},
		{"malformed", "maybe\n", permissions.PromptDeny, true},
		{"empty line", "\n", permissions.PromptDeny, true},
		{"global option not offered", "5\n", permissions.PromptDeny, true},
		{"global word not offered", "global\n", permissions.PromptDeny, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTerminalPrompter(strings.NewReader(tc.input), &bytes.Buffer{})
			out, err := p.build(permissions.MatchRequest{}, dispatch.PromptDisplay{})(context.Background(), permissions.ScopeEscalation{})
			if err != nil {
				t.Fatalf("prompt returned error: %v", err)
			}
			if out.Choice != tc.wantChoice {
				t.Fatalf("choice = %d, want %d", out.Choice, tc.wantChoice)
			}
			if tc.wantDeny {
				if out.Choice != permissions.PromptDeny {
					t.Fatalf("expected a deny for input %q", tc.input)
				}
				if want := permissions.BuildDenyEnvelope(""); out.DenyEnvelope != want {
					t.Fatalf("deny envelope = %q, want %q", out.DenyEnvelope, want)
				}
			} else if out.DenyEnvelope != "" {
				t.Fatalf("non-deny outcome carried a deny envelope: %q", out.DenyEnvelope)
			}
		})
	}
}

func TestTerminalPrompter_NeverReturnsGlobalGrant(t *testing.T) {
	for _, input := range []string{
		"1\n", "2\n", "3\n", "4\n", "5\n", "5", "  5  \n",
		"global\n", "GLOBAL\n", "allow-global\n", "g\n", "always\n", "everywhere\n",
		"folder\n", "project\n", "p\n", "", "\n",
	} {
		p := newTerminalPrompter(strings.NewReader(input), &bytes.Buffer{})
		out, err := p.build(permissions.MatchRequest{}, dispatch.PromptDisplay{})(context.Background(), permissions.ScopeEscalation{})
		if err != nil {
			t.Fatalf("input %q: %v", input, err)
		}
		if out.Choice == permissions.PromptAllowGlobal {
			t.Fatalf("input %q resolved to a global grant — a headless run must never grant machine-wide", input)
		}
	}
}

func TestTerminalPrompter_RendersRequestAndOptions(t *testing.T) {
	var out bytes.Buffer
	p := newTerminalPrompter(strings.NewReader("1\n"), &out)
	req := permissions.MatchRequest{PathScope: "/proj/sub"}
	disp := dispatch.PromptDisplay{Action: "Create file", Subject: "notes.md", Body: "hello world"}
	if _, err := p.build(req, disp)(context.Background(), permissions.ScopeEscalation{}); err != nil {
		t.Fatalf("prompt: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"approval required",
		"Create file: notes.md",
		"hello world",
		"path: /proj/sub",
		"[1]", "allow once",
		"an identical repeat in this run is not re-asked",
		"[2]", "deny",
		"[3]", "allow this session",
		"[4]", "allow in this project",
		".codemeld/settings.yaml",
		"global grant is not offered here",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("prompt render missing %q:\n%s", want, got)
		}
	}
	for _, absent := range []string{"[5]", "only this call", "no persisted folder/global grant is offered", "never written"} {
		if strings.Contains(got, absent) {
			t.Fatalf("prompt render contained forbidden text %q:\n%s", absent, got)
		}
	}
	last := -1
	for _, tag := range []string{"[1]", "[2]", "[3]", "[4]"} {
		at := strings.Index(got, tag)
		if at <= last {
			t.Fatalf("option %s is out of the TUI's order:\n%s", tag, got)
		}
		last = at
	}
}

// TestTerminalPrompter_RendersScopeEscalation: when the orchestrator passes a narrower
// already-approved scope, the terminal prompt warns that the request broadens it and names
// the scope; with no escalation the warning is absent.
func TestTerminalPrompter_RendersScopeEscalation(t *testing.T) {
	const narrower = "/proj/sub/imgdown"
	req := permissions.MatchRequest{PathScope: "/proj/sub"}
	disp := dispatch.PromptDisplay{Action: "Run tool", Subject: "read"}

	var warned bytes.Buffer
	p := newTerminalPrompter(strings.NewReader("1\n"), &warned)
	if _, err := p.build(req, disp)(context.Background(), permissions.ScopeEscalation{NarrowerScope: narrower}); err != nil {
		t.Fatalf("prompt: %v", err)
	}
	for _, want := range []string{"broader than a folder you already allowed", "PARENT of", narrower} {
		if !strings.Contains(warned.String(), want) {
			t.Fatalf("escalation render missing %q:\n%s", want, warned.String())
		}
	}

	var quiet bytes.Buffer
	p2 := newTerminalPrompter(strings.NewReader("1\n"), &quiet)
	if _, err := p2.build(req, disp)(context.Background(), permissions.ScopeEscalation{}); err != nil {
		t.Fatalf("prompt: %v", err)
	}
	if strings.Contains(quiet.String(), "broader than a folder you already allowed") {
		t.Fatalf("escalation warning shown with no escalation:\n%s", quiet.String())
	}
}

func TestTerminalPrompter_ShellBlockedPathsNotice(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  permissions.MatchRequest
		disp dispatch.PromptDisplay
		want int
	}{
		{"direct", permissions.MatchRequest{Kind: matchKindDirect, Subject: "rm x", PathScope: "/proj"}, dispatch.PromptDisplay{Action: "Run command", Subject: "rm x"}, 1},
		{"literal", permissions.MatchRequest{Kind: matchKindLiteral, Subject: "echo hi > out.txt", PathScope: "/proj"}, dispatch.PromptDisplay{Action: "Run command", Subject: "echo hi > out.txt"}, 1},
		{"tool", permissions.MatchRequest{Kind: matchKindTool, Subject: "create", PathScope: "/proj"}, dispatch.PromptDisplay{Action: "Create file", Subject: "notes.md"}, 0},
		{"host", hostRequest("web_fetch", "docs.example.com"), dispatch.PromptDisplay{HostRequest: "https://docs.example.com/guide"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			p := newTerminalPrompter(strings.NewReader("1\n"), &out)
			if _, err := p.build(tc.req, tc.disp)(context.Background(), permissions.ScopeEscalation{}); err != nil {
				t.Fatalf("prompt: %v", err)
			}
			got := out.String()
			if n := strings.Count(got, tui.ShellBlockedPathsNotice); n != tc.want {
				t.Fatalf("notice count = %d, want %d:\n%s", n, tc.want, got)
			}
			if tc.want == 1 && strings.Index(got, tui.ShellBlockedPathsNotice) > strings.Index(got, "[1]") {
				t.Fatalf("notice printed after the options:\n%s", got)
			}
		})
	}
}

// gateProbeWriter blocks the first Write until release is closed, signaling entered when that
// first Write arrives. It lets a test park one prompt mid-render (holding the gate) and prove a
// second concurrent prompt cannot proceed until the first releases.
type gateProbeWriter struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	entered chan struct{}
	release chan struct{}
	blocked bool
}

func (w *gateProbeWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	if !w.blocked {
		w.blocked = true
		w.mu.Unlock()
		close(w.entered)
		<-w.release
		w.mu.Lock()
	}
	n, err := w.buf.Write(p)
	w.mu.Unlock()
	return n, err
}

// TestTerminalPrompter_SerializesConcurrentPrompts proves two concurrent authorizations cannot
// interleave their terminal prompts: while the first holds the single-slot gate (parked inside
// render), the second blocks and produces no outcome; once the first releases, both complete,
// the first reading the first stdin line and the second the next (Done-when 5).
func TestTerminalPrompter_SerializesConcurrentPrompts(t *testing.T) {
	w := &gateProbeWriter{entered: make(chan struct{}), release: make(chan struct{})}
	p := newTerminalPrompter(strings.NewReader("1\n3\n"), w)
	req := permissions.MatchRequest{}
	disp := dispatch.PromptDisplay{Action: "Run command", Subject: "ls"}

	aDone := make(chan permissions.PromptOutcome, 1)
	go func() {
		out, _ := p.build(req, disp)(context.Background(), permissions.ScopeEscalation{})
		aDone <- out
	}()
	<-w.entered // A holds the gate, parked in its first Write.

	bDone := make(chan permissions.PromptOutcome, 1)
	go func() {
		out, _ := p.build(req, disp)(context.Background(), permissions.ScopeEscalation{})
		bDone <- out
	}()

	select {
	case <-bDone:
		t.Fatal("second prompt completed while the first held the gate — prompts are not serialized")
	case <-time.After(50 * time.Millisecond):
	}

	close(w.release) // let A finish; B then acquires the gate.

	first := <-aDone
	second := <-bDone
	if first.Choice != permissions.PromptAllowOnce {
		t.Fatalf("first prompt choice = %d, want allow-once", first.Choice)
	}
	if second.Choice != permissions.PromptAllowSession {
		t.Fatalf("second prompt choice = %d, want allow-session", second.Choice)
	}

	rendered := w.buf.String()
	if n := strings.Count(rendered, "approval required"); n != 2 {
		t.Fatalf("stderr holds %d prompt headers, want 2:\n%s", n, rendered)
	}
	firstTail := strings.Index(rendered, "codemeld: choose 1-")
	secondHead := strings.LastIndex(rendered, "approval required")
	if firstTail < 0 || secondHead < firstTail {
		t.Fatalf("the two prompts interleaved on stderr — the second began before the first finished rendering:\n%s", rendered)
	}
}

// TestHeadlessAuthorizer_ConcurrentIdenticalPromptsAuthorizeFromFirstGrant drives two concurrent
// authorizations of the *exact same* request through one --prompt-for-approval headlessAuthorizer.
// The first is parked at the terminal prompt — holding both the prompt gate and the per-identity
// in-flight lock — while the second races in; only one terminal answer (allow-for-this-session) is
// supplied. Without the in-flight lock the second would pass the not-yet-recorded grant/cache check,
// queue its own prompt, read EOF, and deny — breaking "allow-for-this-session authorizes it for the
// rest of the run" under concurrent dispatch. With it the second parks before any lookup until the
// first records its session grant, then resolves by matching that grant: exactly one prompt is
// rendered, exactly one grant is recorded, and both decisions are authorized with no deny envelope.
func TestHeadlessAuthorizer_ConcurrentIdenticalPromptsAuthorizeFromFirstGrant(t *testing.T) {
	cwd := t.TempDir()
	store := mkStore(t)
	cache := emptyCache(t, cwd)

	w := &gateProbeWriter{entered: make(chan struct{}), release: make(chan struct{})}
	// Only one answer is supplied; a second prompt would read EOF and deny.
	terminal := newTerminalPrompter(strings.NewReader("3\n"), w)
	auth := newHeadlessAuthorizer(cache, func() *sessions.Store { return store }, mode.NewActiveState(mode.Build, mode.SourceDefault), terminal, stderrNoticeRenderer{w: &bytes.Buffer{}})

	req := permissions.MatchRequest{Kind: "tool", Subject: "read_file", PathScope: cwd}
	disp := dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: "read_file"}

	aDone := make(chan permissions.Decision, 1)
	go func() {
		d, _ := auth.Authorize(context.Background(), req, disp, permissions.ModeContext{})
		aDone <- d
	}()
	<-w.entered // first authorization is parked in render, holding the gate and the in-flight lock.

	bDone := make(chan permissions.Decision, 1)
	go func() {
		d, _ := auth.Authorize(context.Background(), req, disp, permissions.ModeContext{})
		bDone <- d
	}()

	// While the first holds the in-flight lock the second must not complete: it parks before any
	// grant/cache lookup, so it neither renders a prompt nor resolves an outcome yet.
	select {
	case <-bDone:
		t.Fatal("second authorization completed while the first held the in-flight lock — identical requests are not serialized")
	case <-time.After(50 * time.Millisecond):
	}

	close(w.release) // let the first finish: it reads "3", grants allow-for-this-session, records it.

	first := <-aDone
	second := <-bDone
	if first.DenyEnvelope != "" {
		t.Fatalf("first decision carried a deny envelope %q, want an allow-for-this-session grant", first.DenyEnvelope)
	}
	if second.DenyEnvelope != "" {
		t.Fatalf("second decision carried a deny envelope %q — it re-prompted and hit EOF instead of matching the first's session grant", second.DenyEnvelope)
	}
	if shown := strings.Count(w.buf.String(), "approval required"); shown != 1 {
		t.Fatalf("terminal rendered %d prompts for two concurrent identical requests, want exactly 1", shown)
	}
	if n := len(cache.Permissions()); n != 1 {
		t.Fatalf("grant table holds %d entries, want 1 (the duplicate request must not record a second grant)", n)
	}
}

func TestTerminalPrompter_RendersHostFactsAndOptions(t *testing.T) {
	cases := []struct {
		name    string
		subject string
		host    string
		request string
	}{
		{"search", "web_search", "mcp.exa.ai", "golang error wrapping"},
		{"fetch", "web_fetch", "docs.example.com", "https://docs.example.com/guide"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := hostRequest(tc.subject, tc.host)
			req.PathScope = "/proj/sub"
			disp := dispatch.PromptDisplay{
				Action:             dispatch.ActionRunTool,
				Subject:            tc.subject,
				Body:               `{"url":"https://docs.example.com/guide"}`,
				HostRequest:        tc.request,
				GrantStoredSubject: permissions.CapabilityRead,
			}
			got, _ := promptHost(t, "1\n", req, disp)

			for _, want := range []string{
				"approval required",
				"tool: " + tc.subject,
				"request: " + tc.request,
				"host: " + tc.host,
				"[1]", "allow this once",
				"[2]", "deny",
				"[3]", "allow for this session",
				"[4]", "allow in this project",
				"this exact host",
			} {
				if !strings.Contains(got, want) {
					t.Fatalf("host prompt missing %q:\n%s", want, got)
				}
			}
			for _, absent := range []string{
				"path:", "/proj/sub", "folder", "global", "machine-wide", "*",
				"settings.yaml", "Run tool", disp.Body, "[5]",
				"broader than a folder you already allowed",
			} {
				if strings.Contains(got, absent) {
					t.Fatalf("host prompt disclosed forbidden text %q:\n%s", absent, got)
				}
			}
			last := -1
			for _, tag := range []string{"[1]", "[2]", "[3]", "[4]"} {
				at := strings.Index(got, tag)
				if at <= last {
					t.Fatalf("host option %s is out of the web prompt's order:\n%s", tag, got)
				}
				last = at
			}
		})
	}
}

func TestTerminalPrompter_HostDirectHTTPDisclosure(t *testing.T) {
	cases := []struct {
		name    string
		subject string
		request string
		direct  bool
		want    bool
	}{
		{"direct http", "web_fetch", "http://docs.example.com/guide", true, true},
		{"direct https", "web_fetch", "https://docs.example.com/guide", false, false},
		{"search originated", "web_search", "golang error wrapping", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			disp := dispatch.PromptDisplay{HostRequest: tc.request, DirectHTTPFallback: tc.direct}
			got, _ := promptHost(t, "1\n", hostRequest(tc.subject, "docs.example.com"), disp)
			if strings.Contains(got, hostDirectHTTPDisclosure) != tc.want {
				t.Fatalf("HTTPS-first disclosure present = %v, want %v:\n%s", !tc.want, tc.want, got)
			}
		})
	}
}

func TestTerminalPrompter_HostProjectChoiceIsProjectHostOutcome(t *testing.T) {
	cases := []struct {
		input string
		want  permissions.PromptChoice
	}{
		{"4\n", permissions.PromptAllowProject},
		{"project\n", permissions.PromptAllowProject},
		{"allow-project\n", permissions.PromptAllowProject},
		{"p\n", permissions.PromptAllowProject},
		{"  4  ", permissions.PromptAllowProject},
		{"1\n", permissions.PromptAllowOnce},
		{"2\n", permissions.PromptDeny},
		{"3\n", permissions.PromptAllowSession},
	}
	for _, tc := range cases {
		t.Run(strings.TrimSpace(tc.input), func(t *testing.T) {
			_, outcome := promptHost(t, tc.input, hostRequest("web_fetch", "docs.example.com"), dispatch.PromptDisplay{})
			if outcome.Choice != tc.want {
				t.Fatalf("host choice for %q = %d, want %d", tc.input, outcome.Choice, tc.want)
			}
		})
	}
}

func TestTerminalPrompter_HostNeverReachesFolderOrGlobalGrant(t *testing.T) {
	for _, input := range []string{
		"1\n", "2\n", "3\n", "4\n", "5\n", "5", "  5  \n", "6\n",
		"global\n", "GLOBAL\n", "allow-global\n", "g\n", "always\n", "everywhere\n",
		"folder\n", "allow-folder\n", "f\n", "", "\n", "maybe\n",
	} {
		_, outcome := promptHost(t, input, hostRequest("web_search", "mcp.exa.ai"), dispatch.PromptDisplay{})
		if outcome.Choice == permissions.PromptAllowGlobal {
			t.Fatalf("input %q resolved to a global grant — adr-040 forbids a machine-wide network grant", input)
		}
		if outcome.Choice == permissions.PromptAllowFolder {
			t.Fatalf("input %q resolved to a folder grant — a web prompt's project scope is a host, not a folder", input)
		}
	}
	for _, input := range []string{"5\n", "global\n", "allow-global\n", "g\n", "folder\n", "", "maybe\n"} {
		_, outcome := promptHost(t, input, hostRequest("web_search", "mcp.exa.ai"), dispatch.PromptDisplay{})
		if outcome.Choice != permissions.PromptDeny {
			t.Fatalf("input %q = %d, want the default deny", input, outcome.Choice)
		}
		if want := permissions.BuildDenyEnvelope(""); outcome.DenyEnvelope != want {
			t.Fatalf("input %q deny envelope = %q, want %q", input, outcome.DenyEnvelope, want)
		}
	}
}

func TestTerminalPrompter_NonHostFourthChoiceStaysFolder(t *testing.T) {
	for _, kind := range []string{matchKindDirect, matchKindLiteral, matchKindTool, ""} {
		for _, input := range []string{"4\n", "project\n", "allow-project\n", "p\n"} {
			req := permissions.MatchRequest{Kind: kind, Subject: "rm notes.txt", PathScope: "/proj/sub"}
			p := newTerminalPrompter(strings.NewReader(input), &bytes.Buffer{})
			outcome, err := p.build(req, dispatch.PromptDisplay{Action: "Run command", Subject: "rm notes.txt"})(context.Background(), permissions.ScopeEscalation{})
			if err != nil {
				t.Fatalf("kind %q input %q: %v", kind, input, err)
			}
			if outcome.Choice != permissions.PromptAllowFolder {
				t.Fatalf("kind %q input %q = %d, want the unchanged folder grant", kind, input, outcome.Choice)
			}
		}
	}
}

func TestTerminalPrompter_ChangedHostRedirectGetsANewFullHostPrompt(t *testing.T) {
	var out bytes.Buffer
	p := newTerminalPrompter(strings.NewReader("4\n2\n"), &out)

	firstOutcome, err := p.build(hostRequest("web_fetch", "docs.example.com"),
		dispatch.PromptDisplay{HostRequest: "https://docs.example.com/guide"})(context.Background(), permissions.ScopeEscalation{})
	if err != nil {
		t.Fatalf("first host prompt: %v", err)
	}
	if firstOutcome.Choice != permissions.PromptAllowProject {
		t.Fatalf("first host choice = %d, want the project host grant", firstOutcome.Choice)
	}
	firstLen := out.Len()

	secondOutcome, err := p.build(hostRequest("web_fetch", "cdn.other.example"),
		dispatch.PromptDisplay{HostRequest: "https://cdn.other.example/guide"})(context.Background(), permissions.ScopeEscalation{})
	if err != nil {
		t.Fatalf("redirect host prompt: %v", err)
	}
	if secondOutcome.Choice != permissions.PromptDeny {
		t.Fatalf("redirect choice = %d, want the deny the redirect prompt was answered with", secondOutcome.Choice)
	}
	if want := permissions.BuildDenyEnvelope(""); secondOutcome.DenyEnvelope != want {
		t.Fatalf("redirect deny envelope = %q, want %q", secondOutcome.DenyEnvelope, want)
	}

	redirect := out.String()[firstLen:]
	for _, want := range []string{
		"approval required",
		"tool: web_fetch",
		"request: https://cdn.other.example/guide",
		"host: cdn.other.example",
		"[1]", "[2]", "[3]", "[4]",
		"allow for this session", "allow in this project",
		"codemeld: choose 1-4",
	} {
		if !strings.Contains(redirect, want) {
			t.Fatalf("changed-host redirect prompt missing %q:\n%s", want, redirect)
		}
	}
	for _, absent := range []string{"docs.example.com", hostFreshConfirmationNotice, "choose 1-2"} {
		if strings.Contains(redirect, absent) {
			t.Fatalf("changed-host redirect prompt carried %q from the previous host:\n%s", absent, redirect)
		}
	}
}

func TestTerminalPrompter_SchemeOrPortConfirmationOffersOnlyOnceOrDeny(t *testing.T) {
	req := freshHostRequest("web_fetch", "docs.example.com")
	disp := dispatch.PromptDisplay{HostRequest: "https://docs.example.com:8443/guide"}
	got, outcome := promptHost(t, "1\n", req, disp)
	if outcome.Choice != permissions.PromptAllowOnce {
		t.Fatalf("confirmation choice = %d, want allow-once", outcome.Choice)
	}
	for _, want := range []string{
		"approval required",
		"tool: web_fetch",
		"request: https://docs.example.com:8443/guide",
		"host: docs.example.com",
		hostFreshConfirmationNotice,
		"[1]", "allow this once",
		"[2]", "deny",
		"codemeld: choose 1-2",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("scheme/port confirmation missing %q:\n%s", want, got)
		}
	}
	for _, absent := range []string{
		"[3]", "[4]", "session", "project", "settings.yaml", "global", "folder", "path:",
		"an identical repeat in this run is not re-asked", "choose 1-4",
	} {
		if strings.Contains(got, absent) {
			t.Fatalf("scheme/port confirmation offered forbidden text %q:\n%s", absent, got)
		}
	}
}

func TestTerminalPrompter_SchemeOrPortConfirmationRejectsSessionAndProject(t *testing.T) {
	for _, input := range []string{"1\n", "1", "  1  \n", "allow\n", "allow-once\n", "once\n", "o\n"} {
		_, outcome := promptHost(t, input, freshHostRequest("web_fetch", "docs.example.com"), dispatch.PromptDisplay{})
		if outcome.Choice != permissions.PromptAllowOnce {
			t.Fatalf("confirmation input %q = %d, want allow-once", input, outcome.Choice)
		}
		if outcome.DenyEnvelope != "" {
			t.Fatalf("confirmation input %q carried a deny envelope: %q", input, outcome.DenyEnvelope)
		}
	}
	for _, input := range []string{
		"2\n", "deny\n", "3\n", "session\n", "allow-session\n", "s\n",
		"4\n", "project\n", "allow-project\n", "p\n", "  4  ",
		"folder\n", "allow-folder\n", "f\n", "5\n", "global\n", "g\n",
		"", "\n", "maybe\n",
	} {
		_, outcome := promptHost(t, input, freshHostRequest("web_search", "mcp.exa.ai"), dispatch.PromptDisplay{})
		if outcome.Choice != permissions.PromptDeny {
			t.Fatalf("confirmation input %q = %d, want the deny a scheme/port confirmation gives every non-once answer", input, outcome.Choice)
		}
		if want := permissions.BuildDenyEnvelope(""); outcome.DenyEnvelope != want {
			t.Fatalf("confirmation input %q deny envelope = %q, want %q", input, outcome.DenyEnvelope, want)
		}
	}
}

func TestHeadlessAuthorizer_SchemePortConfirmationIsNotSatisfiedByAProjectHostGrant(t *testing.T) {
	dir := t.TempDir()
	cache, err := config.NewCache(map[string]any{
		"permissions": []any{
			map[string]any{"kind": "tool", "subject": "web_fetch", "host_scope": "docs.example.com", "grant_kind": "project"},
		},
	}, dir, nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	var out bytes.Buffer
	terminal := newTerminalPrompter(strings.NewReader("4\n"), &out)
	auth := newHeadlessAuthorizer(cache, func() *sessions.Store { return mkStore(t) },
		mode.NewActiveState(mode.Build, mode.SourceDefault), terminal, stderrNoticeRenderer{w: &bytes.Buffer{}})

	dec, err := auth.Authorize(context.Background(), freshHostRequest("web_fetch", "docs.example.com"),
		dispatch.PromptDisplay{HostRequest: "https://docs.example.com:8443/guide"}, permissions.ModeContext{NetworkEgress: true, ToolName: "web_fetch"})
	if err != nil {
		t.Fatalf("authorize scheme/port confirmation: %v", err)
	}
	if !strings.Contains(out.String(), hostFreshConfirmationNotice) {
		t.Fatalf("the stored project host grant suppressed the confirmation prompt:\n%s", out.String())
	}
	if want := permissions.BuildDenyEnvelope(""); dec.DenyEnvelope != want {
		t.Fatalf("decision deny envelope = %q, want %q — the project answer must deny on a confirmation", dec.DenyEnvelope, want)
	}
	if dec.Grant != nil {
		t.Fatalf("confirmation recorded a grant %+v, want none", dec.Grant)
	}
	if n := len(cache.Permissions()); n != 1 {
		t.Fatalf("grant table holds %d entries, want only the pre-existing project host grant", n)
	}
	projectTarget := config.LocalSettingsPath(dir)
	if _, err := os.Stat(projectTarget); !os.IsNotExist(err) {
		t.Fatalf("confirmation wrote %q (stat err = %v), want nothing persisted", projectTarget, err)
	}
}

func TestTerminalPrompter_SerializesConcurrentRedirectPrompts(t *testing.T) {
	w := &gateProbeWriter{entered: make(chan struct{}), release: make(chan struct{})}
	p := newTerminalPrompter(strings.NewReader("1\n1\n"), w)

	aDone := make(chan permissions.PromptOutcome, 1)
	go func() {
		out, _ := p.build(freshHostRequest("web_fetch", "docs.example.com"),
			dispatch.PromptDisplay{HostRequest: "https://docs.example.com:8443/guide"})(context.Background(), permissions.ScopeEscalation{})
		aDone <- out
	}()
	<-w.entered

	bDone := make(chan permissions.PromptOutcome, 1)
	go func() {
		out, _ := p.build(hostRequest("web_fetch", "cdn.other.example"),
			dispatch.PromptDisplay{HostRequest: "https://cdn.other.example/guide"})(context.Background(), permissions.ScopeEscalation{})
		bDone <- out
	}()

	select {
	case <-bDone:
		t.Fatal("the changed-host redirect completed while the confirmation held the gate — redirect prompts are not serialized")
	case <-time.After(50 * time.Millisecond):
	}

	close(w.release)

	if first := <-aDone; first.Choice != permissions.PromptAllowOnce {
		t.Fatalf("confirmation choice = %d, want allow-once", first.Choice)
	}
	if second := <-bDone; second.Choice != permissions.PromptAllowOnce {
		t.Fatalf("changed-host redirect choice = %d, want allow-once", second.Choice)
	}

	rendered := w.buf.String()
	if n := strings.Count(rendered, "approval required"); n != 2 {
		t.Fatalf("stderr holds %d prompt headers, want 2:\n%s", n, rendered)
	}
	firstTail := strings.Index(rendered, "codemeld: choose 1-2")
	secondHead := strings.LastIndex(rendered, "approval required")
	if firstTail < 0 || secondHead < firstTail {
		t.Fatalf("the two redirect prompts interleaved on stderr:\n%s", rendered)
	}
}

func TestHeadlessAuthorizer_HostProjectChoicePersistsProjectHostGrant(t *testing.T) {
	dir := t.TempDir()
	store := mkStore(t)
	terminal := newTerminalPrompter(strings.NewReader("4\n"), &bytes.Buffer{})
	auth := newHeadlessAuthorizer(emptyCache(t, dir), func() *sessions.Store { return store },
		mode.NewActiveState(mode.Build, mode.SourceDefault), terminal, stderrNoticeRenderer{w: &bytes.Buffer{}})

	req := hostRequest("web_fetch", "docs.example.com")
	disp := dispatch.PromptDisplay{HostRequest: "https://docs.example.com/guide"}
	dec, err := auth.Authorize(context.Background(), req, disp, permissions.ModeContext{NetworkEgress: true, ToolName: "web_fetch"})
	if err != nil {
		t.Fatalf("authorize host prompt: %v", err)
	}
	if dec.PersistErr != nil {
		t.Fatalf("persist error: %v", dec.PersistErr)
	}
	want := permissions.PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "docs.example.com", GrantKind: "project"}
	if dec.Grant == nil || *dec.Grant != want {
		t.Fatalf("decision grant = %+v, want %+v", dec.Grant, want)
	}

	projectTarget := config.LocalSettingsPath(dir)
	entries := readPersistedPermissions(t, projectTarget, dir)
	if len(entries) != 1 {
		t.Fatalf("project settings hold %d entries, want exactly the approved host grant: %+v", len(entries), entries)
	}
	if persisted := findGrant(t, entries, "web_fetch"); persisted != want {
		t.Fatalf("entry read back from %q = %+v, want %+v (exact host, no path scope)", projectTarget, persisted, want)
	}
}

func directRequest(pathScope string, tokens ...string) permissions.MatchRequest {
	return permissions.MatchRequest{
		Kind:          matchKindDirect,
		Subject:       permissions.ExactSubject(tokens[0], tokens[1:]),
		SubjectTokens: tokens,
		PathScope:     pathScope,
	}
}

func promptDirect(t *testing.T, input string, req permissions.MatchRequest, d terminalDisclosure) (string, permissions.PromptOutcome) {
	t.Helper()
	var out bytes.Buffer
	p := newTerminalPrompter(strings.NewReader(input), &out)
	p.disclosure = d
	outcome, err := p.build(req, dispatch.PromptDisplay{Action: "Run command", Subject: req.Subject})(context.Background(), permissions.ScopeEscalation{})
	if err != nil {
		t.Fatalf("direct prompt: %v", err)
	}
	return out.String(), outcome
}

func projectDisclosure(root string) terminalDisclosure {
	return terminalDisclosure{
		projectRoot:        root,
		launchDir:          root,
		boundary:           "project-root",
		folderSettingsPath: filepath.Join(root, ".codemeld", "settings.yaml"),
	}
}

func TestTerminalPrompter_DirectSessionChoiceStoresSelectedScope(t *testing.T) {
	req := directRequest("/proj", "git", "log", "--oneline")
	root := "/proj"
	got, outcome := promptDirect(t, "3\n3\n", req, projectDisclosure(root))

	if outcome.Choice != permissions.PromptAllowSession {
		t.Fatalf("choice = %d, want PromptAllowSession", outcome.Choice)
	}
	if outcome.StoredSubject != "git log :*" {
		t.Fatalf("stored subject = %q, want %q", outcome.StoredSubject, "git log :*")
	}
	for _, want := range []string{
		"choose its scope",
		"subject kind: direct-command",
		"canonical command: git log --oneline",
		"run folder: /proj",
		"[1] exact: git log --oneline",
		"[2] prefix: git log --oneline :*",
		"[3] prefix: git log :* — fixed: git log; any later arguments may vary [recommended]",
		"[4] program (advanced): git :*",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("scope render missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "saved to:") {
		t.Fatalf("session scope decision claimed a persistence target:\n%s", got)
	}
}

// The headless chooser takes no declared-list input and must never grow one: a declaration changes
// Auto posture, never what the prompt recommends.
func TestTerminalPrompter_DirectScopeUnaffectedByDeclaredCommandList(t *testing.T) {
	req := directRequest("/proj", "prep-open-tasks.sh", "--only", "i425")
	got, outcome := promptDirect(t, "3\n2\n", req, projectDisclosure("/proj"))

	if outcome.Choice != permissions.PromptAllowSession {
		t.Fatalf("choice = %d, want PromptAllowSession", outcome.Choice)
	}
	if outcome.StoredSubject != "prep-open-tasks.sh --only i425 :*" {
		t.Fatalf("stored subject = %q, want %q", outcome.StoredSubject, "prep-open-tasks.sh --only i425 :*")
	}
	for _, want := range []string{
		"[1] exact: prep-open-tasks.sh --only i425",
		"[2] prefix: prep-open-tasks.sh --only i425 :* — fixed: prep-open-tasks.sh --only i425; any later arguments may vary [recommended]",
		"[3] prefix: prep-open-tasks.sh --only :*",
		"[4] program (advanced): prep-open-tasks.sh :*",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("scope render missing %q:\n%s", want, got)
		}
	}
}

func TestTerminalPrompter_DirectFolderChoiceDisclosesPersistedDecision(t *testing.T) {
	req := directRequest("/proj/sub", "git", "log", "--oneline")
	d := projectDisclosure("/proj")
	got, outcome := promptDirect(t, "4\n2\n", req, d)

	if outcome.Choice != permissions.PromptAllowFolder {
		t.Fatalf("choice = %d, want PromptAllowFolder", outcome.Choice)
	}
	if outcome.StoredSubject != "git log --oneline :*" {
		t.Fatalf("stored subject = %q, want %q", outcome.StoredSubject, "git log --oneline :*")
	}
	scope := got[strings.Index(got, "choose its scope"):]
	for _, want := range []string{
		"project root: /proj",
		"⚠ run folder differs from project root",
		"saved to: " + filepath.Join("/proj", ".codemeld", "settings.yaml"),
		"applies to: /proj/sub and its descendants",
	} {
		if !strings.Contains(scope, want) {
			t.Fatalf("persisted-folder disclosure missing %q:\n%s", want, scope)
		}
	}
}

// promptUntrusted puts the prompter in the state HeadlessDriver.Run gives it for a run whose
// trust decision is untrusted.
func promptUntrusted(t *testing.T, input string, req permissions.MatchRequest, d terminalDisclosure) (string, permissions.PromptOutcome) {
	t.Helper()
	var out bytes.Buffer
	p := newTerminalPrompter(strings.NewReader(input), &out)
	p.disclosure = d
	p.projectUntrusted = true
	disp := dispatch.PromptDisplay{Action: "Run command", Subject: req.Subject}
	outcome, err := p.build(req, disp)(context.Background(), permissions.ScopeEscalation{})
	if err != nil {
		t.Fatalf("untrusted prompt: %v", err)
	}
	return out.String(), outcome
}

func TestTerminalPrompter_UntrustedWithholdsProjectChoice(t *testing.T) {
	req := directRequest("/proj", "git", "log")
	settings := filepath.Join("/proj", ".codemeld", "settings.yaml")
	d := terminalDisclosure{
		projectRoot:             "/proj",
		launchDir:               "/proj",
		boundary:                "launch-dir-only",
		folderSettingsPath:      settings,
		wouldCreateSettingsFile: true,
	}

	for _, spelling := range []string{"4", "project", "allow-project", "p"} {
		t.Run(spelling, func(t *testing.T) {
			got, outcome := promptUntrusted(t, spelling+"\n", req, d)
			if outcome.Choice != permissions.PromptDeny {
				t.Fatalf("choice = %d for %q, want a deny rather than a fall-through to another option", outcome.Choice, spelling)
			}
			if want := permissions.BuildDenyEnvelope(""); outcome.DenyEnvelope != want {
				t.Fatalf("deny envelope = %q, want %q", outcome.DenyEnvelope, want)
			}
			if outcome.StoredSubject != "" {
				t.Fatalf("denied outcome stored subject %q", outcome.StoredSubject)
			}
			if strings.Contains(got, "choose its scope") {
				t.Fatalf("a withheld project choice opened the scope question:\n%s", got)
			}
			for _, banned := range []string{"[4]", "allow in this project", "applies when run from:", tui.RenderCrossModeMarkerNotice(settings)} {
				if strings.Contains(got, banned) {
					t.Fatalf("untrusted prompt still shows %q:\n%s", banned, got)
				}
			}
			if !strings.Contains(got, "codemeld: choose 1-3 (a machine-wide/global grant is not offered here): ") {
				t.Fatalf("untrusted prompt does not read choose 1-3:\n%s", got)
			}
		})
	}

	t.Run("session choice survives and still asks for scope", func(t *testing.T) {
		got, outcome := promptUntrusted(t, "3\n1\n", req, d)
		if outcome.Choice != permissions.PromptAllowSession {
			t.Fatalf("choice = %d, want PromptAllowSession", outcome.Choice)
		}
		if outcome.StoredSubject != permissions.ExactSubject("git", []string{"log"}) {
			t.Fatalf("stored subject = %q, want the exact scope the second question collected", outcome.StoredSubject)
		}
		if !strings.Contains(got, "choose its scope") {
			t.Fatalf("session choice did not open the direct-command scope question:\n%s", got)
		}
		if strings.Contains(got, "saved to:") || strings.Contains(got, "lifetime: permanent") {
			t.Fatalf("session scope decision disclosed a permanent target:\n%s", got)
		}
	})

	t.Run("the same run trusted keeps all four choices", func(t *testing.T) {
		got, outcome := promptDirect(t, "4\n1\n", req, d)
		if outcome.Choice != permissions.PromptAllowFolder {
			t.Fatalf("choice = %d, want PromptAllowFolder for a trusted run", outcome.Choice)
		}
		for _, want := range []string{
			"  [4] allow in this project — remember this permanently in " + settings,
			"      applies when run from: /proj and its descendants",
			tui.RenderCrossModeMarkerNotice(settings),
			"codemeld: choose 1-4 (a machine-wide/global grant is not offered here): ",
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("trusted prompt missing %q:\n%s", want, got)
			}
		}
	})
}

func TestTerminalPrompter_UntrustedHostWithholdsProjectChoice(t *testing.T) {
	req := hostRequest("web_fetch", "docs.example.com")

	for _, spelling := range []string{"4", "project", "allow-project", "p"} {
		got, outcome := promptUntrusted(t, spelling+"\n", req, terminalDisclosure{projectRoot: "/proj"})
		if outcome.Choice != permissions.PromptDeny {
			t.Fatalf("host choice = %d for %q, want a deny", outcome.Choice, spelling)
		}
		if strings.Contains(got, "allow in this project") {
			t.Fatalf("untrusted host prompt still offers the project row:\n%s", got)
		}
		if !strings.Contains(got, "codemeld: choose 1-3: ") {
			t.Fatalf("untrusted host prompt does not read choose 1-3:\n%s", got)
		}
	}

	if _, outcome := promptUntrusted(t, "3\n", req, terminalDisclosure{projectRoot: "/proj"}); outcome.Choice != permissions.PromptAllowSession {
		t.Fatalf("host session choice = %d, want PromptAllowSession in an untrusted project", outcome.Choice)
	}

	fresh, outcome := promptUntrusted(t, "1\n", freshHostRequest("web_fetch", "docs.example.com"), terminalDisclosure{projectRoot: "/proj"})
	if outcome.Choice != permissions.PromptAllowOnce {
		t.Fatalf("fresh host choice = %d, want PromptAllowOnce", outcome.Choice)
	}
	if !strings.Contains(fresh, "codemeld: choose 1-2: ") {
		t.Fatalf("untrusted fresh host confirmation does not read choose 1-2:\n%s", fresh)
	}
}

func TestTerminalPrompter_DirectFolderChoiceShowsCrossModeMarkerNotice(t *testing.T) {
	req := directRequest("/proj", "git", "log")
	settings := filepath.Join("/proj", ".codemeld", "settings.yaml")
	d := terminalDisclosure{
		projectRoot:             "/proj",
		launchDir:               "/proj",
		boundary:                "launch-dir-only",
		folderSettingsPath:      settings,
		wouldCreateSettingsFile: true,
	}

	got, _ := promptDirect(t, "4\n1\n", req, d)
	notice := tui.RenderCrossModeMarkerNotice(settings)
	if !strings.Contains(got, notice) {
		t.Fatalf("cross-mode marker notice missing:\n%s", got)
	}
	if strings.Count(got, notice) < 2 {
		t.Fatalf("notice shown %d times, want it on both the option list and the persisted scope decision:\n%s", strings.Count(got, notice), got)
	}

	d.wouldCreateSettingsFile = false
	quiet, _ := promptDirect(t, "4\n1\n", req, d)
	if strings.Contains(quiet, notice) {
		t.Fatalf("cross-mode marker notice shown for an existing settings file:\n%s", quiet)
	}
}

func TestTerminalPrompter_DirectProgramScopeNeedsDistinctConfirmation(t *testing.T) {
	d := projectDisclosure("/proj")

	benign := directRequest("/proj", "ls", "-la")
	got, outcome := promptDirect(t, "3\n3\n1\n", benign, d)
	if outcome.Choice != permissions.PromptAllowSession || outcome.StoredSubject != "ls :*" {
		t.Fatalf("outcome = %+v, want a session grant storing %q", outcome, "ls :*")
	}
	confirm := got[strings.LastIndex(got, scopeProgramWarning):]
	if !strings.Contains(confirm, "effective grant: ls :* (direct command)") {
		t.Fatalf("confirm did not restate the effective grant:\n%s", confirm)
	}
	if !strings.Contains(confirm, "confirm program-wide grant") {
		t.Fatalf("confirm is not a distinct acknowledgement choice:\n%s", confirm)
	}
	if strings.Contains(got, scopeDestructiveProgramWarning) {
		t.Fatalf("non-destructive program carried the destructive advisory:\n%s", got)
	}
	if strings.Contains(confirm, "saved to:") {
		t.Fatalf("session Program confirmation claimed a persistence target:\n%s", confirm)
	}

	destructive := directRequest("/proj", "rm", "notes.txt")
	loud, outcome := promptDirect(t, "4\n3\n1\n", destructive, d)
	if outcome.Choice != permissions.PromptAllowFolder || outcome.StoredSubject != "rm :*" {
		t.Fatalf("outcome = %+v, want a folder grant storing %q", outcome, "rm :*")
	}
	tail := loud[strings.LastIndex(loud, scopeDestructiveProgramWarning):]
	if !strings.Contains(tail, scopeProgramWarning) {
		t.Fatalf("destructive advisory replaced the breadth warning instead of preceding it:\n%s", tail)
	}
	if strings.Index(loud, scopeDestructiveProgramWarning) > strings.LastIndex(loud, scopeProgramWarning) {
		t.Fatalf("destructive advisory is not above the breadth warning:\n%s", loud)
	}
	for _, want := range []string{
		"effective grant: rm :* (direct command)",
		"saved to: " + filepath.Join("/proj", ".codemeld", "settings.yaml"),
		"applies to: /proj and its descendants",
	} {
		if !strings.Contains(tail, want) {
			t.Fatalf("folder Program confirmation missing %q:\n%s", want, tail)
		}
	}

	_, declined := promptDirect(t, "4\n3\n2\n", destructive, d)
	if declined.Choice != permissions.PromptDeny || declined.StoredSubject != "" {
		t.Fatalf("declined confirm = %+v, want a deny with no stored subject", declined)
	}
}

func TestTerminalPrompter_InvalidDirectScopeInputDenies(t *testing.T) {
	req := directRequest("/proj", "git", "log")
	d := projectDisclosure("/proj")
	cases := []struct {
		name  string
		input string
	}{
		{"empty scope line", "3\n\n"},
		{"malformed scope", "3\nprefix\n"},
		{"scope eof", "3\n"},
		{"scope above range", "3\n9\n"},
		{"scope zero", "3\n0\n"},
		{"scope negative", "3\n-1\n"},
		{"folder scope eof", "4\n"},
		{"folder malformed scope", "4\nexact\n"},
		{"confirm eof", "3\n3\n"},
		{"confirm malformed", "3\n3\nyes\n"},
		{"confirm out of range", "4\n3\n7\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, outcome := promptDirect(t, c.input, req, d)
			if outcome.Choice != permissions.PromptDeny {
				t.Fatalf("choice = %d, want PromptDeny", outcome.Choice)
			}
			if outcome.StoredSubject != "" {
				t.Fatalf("denied outcome carried stored subject %q", outcome.StoredSubject)
			}
			if want := permissions.BuildDenyEnvelope(""); outcome.DenyEnvelope != want {
				t.Fatalf("deny envelope = %q, want %q", outcome.DenyEnvelope, want)
			}
		})
	}
}

func TestTerminalPrompter_FixedSubjectPathsAskNoScope(t *testing.T) {
	d := projectDisclosure("/proj")
	cases := []struct {
		name string
		req  permissions.MatchRequest
	}{
		{"literal command", permissions.MatchRequest{Kind: matchKindLiteral, Subject: "git log | wc -l", PathScope: "/proj"}},
		{"structured tool", permissions.MatchRequest{Kind: matchKindTool, Subject: "read", PathScope: "/proj"}},
		{"host", hostRequest("web_fetch", "example.com")},
	}
	for _, c := range cases {
		for _, lifetime := range []string{"3", "4"} {
			t.Run(c.name+" choice "+lifetime, func(t *testing.T) {
				got, outcome := promptDirect(t, lifetime+"\n", c.req, d)
				if outcome.Choice == permissions.PromptDeny {
					t.Fatalf("a fixed-subject grant choice was denied: %+v", outcome)
				}
				if outcome.StoredSubject != "" {
					t.Fatalf("fixed subject replaced by %q", outcome.StoredSubject)
				}
				if strings.Contains(got, "choose its scope") {
					t.Fatalf("scope chooser rendered for a fixed subject:\n%s", got)
				}
			})
		}
	}

	tokenless := permissions.MatchRequest{Kind: matchKindDirect, Subject: "git log", PathScope: "/proj"}
	got, outcome := promptDirect(t, "4\n", tokenless, d)
	if outcome.Choice != permissions.PromptAllowFolder || outcome.StoredSubject != "" {
		t.Fatalf("tokenless direct outcome = %+v, want a folder grant on the concrete request subject", outcome)
	}
	if strings.Contains(got, "choose its scope") {
		t.Fatalf("scope chooser rendered for a direct request carrying no canonical tokens:\n%s", got)
	}

	req := directRequest("/proj", "git", "log")
	for _, lifetime := range []string{"1", "2"} {
		got, outcome := promptDirect(t, lifetime+"\n", req, d)
		if outcome.StoredSubject != "" {
			t.Fatalf("non-grant choice %q stored subject %q", lifetime, outcome.StoredSubject)
		}
		if strings.Contains(got, "choose its scope") {
			t.Fatalf("scope chooser rendered for non-grant choice %q:\n%s", lifetime, got)
		}
	}
}

// The second prompt proving a deny is the assertion: it sees the one line the first prompt
// did not consume, so the first held the permit across all three of its reads.
func TestTerminalPrompter_DirectScopeIsReadUnderOneGatePermit(t *testing.T) {
	req := directRequest("/proj", "git", "log")
	var out bytes.Buffer
	p := newTerminalPrompter(strings.NewReader("3\n3\n1\n2\n"), &out)
	p.disclosure = projectDisclosure("/proj")

	first, err := p.build(req, dispatch.PromptDisplay{})(context.Background(), permissions.ScopeEscalation{})
	if err != nil {
		t.Fatalf("first prompt: %v", err)
	}
	if first.StoredSubject != "git :*" {
		t.Fatalf("first outcome = %+v, want the confirmed program subject", first)
	}
	second, err := p.build(req, dispatch.PromptDisplay{})(context.Background(), permissions.ScopeEscalation{})
	if err != nil {
		t.Fatalf("second prompt: %v", err)
	}
	if second.Choice != permissions.PromptDeny {
		t.Fatalf("second outcome = %+v; the first prompt consumed input past its own reads", second)
	}
}

// headlessAlert is the exact byte sequence the blocked-prompt notifier writes to stderr:
// the terminal bell (the headless seam has no tcell screen to ring) then the OSC 9
// notification.
var headlessAlert = "\a" + tui.PromptNotifySequence()

// fakeAlertClock replaces time.After with a hand-fired channel. tick is unbuffered, so a
// send completes only once the notifier is waiting on it.
type fakeAlertClock struct {
	tick chan time.Time
}

func newFakeAlertClock() *fakeAlertClock {
	return &fakeAlertClock{tick: make(chan time.Time)}
}

func (c *fakeAlertClock) after(time.Duration) <-chan time.Time { return c.tick }

// steppedReader releases one line per call to release, so a test can hold the prompt at
// whichever read it wants for as long as it wants.
type steppedReader struct {
	lines []string
	next  chan struct{}
	i     int
}

func newSteppedReader(lines ...string) *steppedReader {
	return &steppedReader{lines: lines, next: make(chan struct{})}
}

func (r *steppedReader) Read(p []byte) (int, error) {
	<-r.next
	if r.i >= len(r.lines) {
		return 0, io.EOF
	}
	n := copy(p, r.lines[r.i])
	r.i++
	return n, nil
}

func (r *steppedReader) release() { r.next <- struct{}{} }

// promptOutput reads out under the prompter's own writer lock, which is the only safe way
// to look at it while the notifier's goroutine may be writing.
func promptOutput(p *terminalPrompter, out *bytes.Buffer) string {
	p.outMu.Lock()
	defer p.outMu.Unlock()
	return out.String()
}

func waitForOutput(t *testing.T, p *terminalPrompter, out *bytes.Buffer, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(promptOutput(p, out), want) {
		if time.Now().After(deadline) {
			t.Fatalf("stderr never carried %q:\n%s", want, promptOutput(p, out))
		}
		time.Sleep(time.Millisecond)
	}
}

// fireAlert fires the notifier's next tick and waits for the nth alert to land on stderr.
func fireAlert(t *testing.T, c *fakeAlertClock, p *terminalPrompter, out *bytes.Buffer, n int) {
	t.Helper()
	select {
	case c.tick <- time.Time{}:
	case <-time.After(2 * time.Second):
		t.Fatalf("no notifier was waiting on the clock for alert %d", n)
	}
	deadline := time.Now().Add(2 * time.Second)
	for strings.Count(promptOutput(p, out), headlessAlert) < n {
		if time.Now().After(deadline) {
			t.Fatalf("alert %d never reached stderr", n)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertClockIdle(t *testing.T, c *fakeAlertClock) {
	t.Helper()
	select {
	case c.tick <- time.Time{}:
		t.Fatal("a notifier is still waiting on its clock")
	case <-time.After(100 * time.Millisecond):
	}
}

// newAlertingPrompter builds a prompter whose stderr is treated as a terminal and whose
// notifier runs on a hand-fired clock.
func newAlertingPrompter(in io.Reader, out io.Writer) (*terminalPrompter, *fakeAlertClock) {
	p := newTerminalPrompter(in, out)
	p.notifyTTY = true
	clk := newFakeAlertClock()
	p.after = clk.after
	return p, clk
}

// A direct-command grant is blocked at readChoice, then readDirectScope, then the Program
// confirmation; the run is halted at each, so one notifier must span all three.
func TestTerminalPrompter_AlertsThroughEveryBlockedRead(t *testing.T) {
	var out bytes.Buffer
	in := newSteppedReader("3\n", "3\n", "1\n")
	p, clk := newAlertingPrompter(in, &out)
	p.disclosure = projectDisclosure("/proj")

	done := make(chan permissions.PromptOutcome, 1)
	go func() {
		outcome, err := p.build(directRequest("/proj", "git", "log"), dispatch.PromptDisplay{})(context.Background(), permissions.ScopeEscalation{})
		if err != nil {
			panic(err)
		}
		done <- outcome
	}()

	waitForOutput(t, p, &out, "choose 1-4")
	fireAlert(t, clk, p, &out, 1)

	in.release()
	waitForOutput(t, p, &out, "choose its scope")
	fireAlert(t, clk, p, &out, 2)

	in.release()
	waitForOutput(t, p, &out, "confirm program-wide grant")
	fireAlert(t, clk, p, &out, 3)

	in.release()
	outcome := <-done
	if outcome.StoredSubject != "git :*" {
		t.Fatalf("outcome = %+v, want the confirmed program subject", outcome)
	}

	assertClockIdle(t, clk)
	if got := strings.Count(promptOutput(p, &out), headlessAlert); got != 3 {
		t.Fatalf("%d alerts written, want the 3 fired before the outcome", got)
	}
}

func TestTerminalPrompter_AnswerInsideTheFirstIntervalIsSilent(t *testing.T) {
	var out bytes.Buffer
	p, clk := newAlertingPrompter(strings.NewReader("2\n"), &out)

	outcome, err := p.build(hostRequest("WebFetch", "example.com"), dispatch.PromptDisplay{})(context.Background(), permissions.ScopeEscalation{})
	if err != nil {
		t.Fatalf("prompt: %v", err)
	}
	if outcome.Choice != permissions.PromptDeny {
		t.Fatalf("outcome = %+v, want a deny", outcome)
	}

	assertClockIdle(t, clk)
	if got := promptOutput(p, &out); strings.Contains(got, "\x1b]9;") || strings.Contains(got, "\a") {
		t.Fatalf("a prompt answered inside the first interval still alerted:\n%q", got)
	}
}

// The prompt reads block on stdin, which no cancellation interrupts, so the notifier has
// to watch the context itself.
func TestTerminalPrompter_CancelledContextStopsTheAlerts(t *testing.T) {
	var out bytes.Buffer
	in := newSteppedReader("1\n")
	p, clk := newAlertingPrompter(in, &out)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		_, _ = p.build(hostRequest("WebFetch", "example.com"), dispatch.PromptDisplay{})(ctx, permissions.ScopeEscalation{})
		in.release()
	}()

	waitForOutput(t, p, &out, "choose 1-4")
	fireAlert(t, clk, p, &out, 1)

	cancel()
	// The prompt is still blocked on stdin, so only the cancellation can end the notifier.
	time.Sleep(100 * time.Millisecond)
	assertClockIdle(t, clk)
	if got := strings.Count(promptOutput(p, &out), headlessAlert); got != 1 {
		t.Fatalf("%d alerts written, want only the one fired before cancellation", got)
	}

	in.release()
}

// gateWriter holds the first write containing trigger until release is closed, so a test
// can fire an alert while a prompt render is half-written.
type gateWriter struct {
	buf     *bytes.Buffer
	trigger string
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newGateWriter(buf *bytes.Buffer, trigger string) *gateWriter {
	return &gateWriter{buf: buf, trigger: trigger, entered: make(chan struct{}), release: make(chan struct{})}
}

func (w *gateWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.trigger) {
		w.once.Do(func() {
			close(w.entered)
			<-w.release
		})
	}
	return w.buf.Write(p)
}

func TestTerminalPrompter_AlertNeverInterleavesWithARender(t *testing.T) {
	const scopeHeader = "codemeld: this grant stores a command subject — choose its scope"
	var buf bytes.Buffer
	gate := newGateWriter(&buf, scopeHeader)
	in := newSteppedReader("3\n", "1\n")
	p, clk := newAlertingPrompter(in, gate)
	p.disclosure = projectDisclosure("/proj")

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = p.build(directRequest("/proj", "git", "log"), dispatch.PromptDisplay{})(context.Background(), permissions.ScopeEscalation{})
	}()

	in.release()
	<-gate.entered

	// The scope render holds the writer lock; the alert must queue behind it rather than
	// splice itself into the half-written block.
	alerted := make(chan struct{})
	go func() { defer close(alerted); clk.tick <- time.Time{} }()
	close(gate.release)
	<-alerted
	waitForOutput(t, p, &buf, headlessAlert)

	in.release()
	<-done

	got := promptOutput(p, &buf)
	if !strings.Contains(got, headlessAlert) {
		t.Fatalf("no alert reached stderr:\n%q", got)
	}
	start := strings.Index(got, scopeHeader)
	end := strings.Index(got[start:], "codemeld: choose 1-") + start
	if strings.Contains(got[start:end], headlessAlert) {
		t.Fatalf("the alert spliced itself into the scope render:\n%q", got[start:end])
	}
}

// The prompter is handed the run's stderr and nothing else, so no alert byte can reach
// stdout, which stays model-only.
func TestTerminalPrompter_AlertsReachStderrOnly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	in := newSteppedReader("2\n")
	p, clk := newAlertingPrompter(in, &stderr)

	if p.out != io.Writer(&stderr) {
		t.Fatal("the prompter writes somewhere other than the stderr it was given")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = p.build(hostRequest("WebFetch", "example.com"), dispatch.PromptDisplay{})(context.Background(), permissions.ScopeEscalation{})
	}()

	waitForOutput(t, p, &stderr, "choose 1-4")
	fireAlert(t, clk, p, &stderr, 1)
	in.release()
	<-done

	if stdout.Len() != 0 {
		t.Fatalf("stdout received %q", stdout.String())
	}
	if got := strings.Count(promptOutput(p, &stderr), headlessAlert); got != 1 {
		t.Fatalf("%d alerts on stderr, want 1", got)
	}
}

func TestTerminalPrompter_NonTerminalStderrIsNeverAlerted(t *testing.T) {
	var out bytes.Buffer
	in := newSteppedReader("2\n")
	p := newTerminalPrompter(in, &out)
	clk := newFakeAlertClock()
	p.after = clk.after

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = p.build(hostRequest("WebFetch", "example.com"), dispatch.PromptDisplay{})(context.Background(), permissions.ScopeEscalation{})
	}()

	waitForOutput(t, p, &out, "choose 1-4")
	clk.tick <- time.Time{}
	in.release()
	<-done

	if got := promptOutput(p, &out); strings.Contains(got, "\x1b]9;") || strings.Contains(got, "\a") {
		t.Fatalf("a redirected stderr received notifier control bytes:\n%q", got)
	}
}

// writeLog keeps every Write to the prompter's stderr as its own entry. bytes.Buffer is a
// named field, not embedded: a promoted WriteString would let io.WriteString bypass Write
// and drop the notifier's entry.
type writeLog struct {
	buf    bytes.Buffer
	writes []string
}

func (w *writeLog) Write(p []byte) (int, error) {
	w.writes = append(w.writes, string(p))
	return w.buf.Write(p)
}

func writesSince(p *terminalPrompter, out *writeLog, n int) []string {
	p.outMu.Lock()
	defer p.outMu.Unlock()
	return append([]string(nil), out.writes[n:]...)
}

// notifierWrites returns only the writes the notifier made: the prompt goroutine is parked
// in the stepped reader from the render's last write until release, so every entry appended
// in that window came from the notifier.
func notifierWrites(t *testing.T, req permissions.MatchRequest, disp dispatch.PromptDisplay) []string {
	t.Helper()
	var out writeLog
	in := newSteppedReader("2\n")
	p, clk := newAlertingPrompter(in, &out)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = p.build(req, disp)(context.Background(), permissions.ScopeEscalation{})
	}()

	waitForOutput(t, p, &out.buf, "choose 1-4")
	rendered := len(writesSince(p, &out, 0))
	fireAlert(t, clk, p, &out.buf, 1)
	in.release()
	<-done
	return writesSince(p, &out, rendered)
}

// No request value is read on the notifier's path, so a hostile Subject, Host, or
// HostRequest cannot reach a desktop notification through it.
func TestTerminalPrompter_HostileRequestFieldsCannotChangeTheAlertBytes(t *testing.T) {
	benign := notifierWrites(t,
		hostRequest("WebFetch", "example.com"),
		dispatch.PromptDisplay{Action: "Run tool", Subject: "WebFetch", HostRequest: "GET https://example.com/"})
	hostile := notifierWrites(t,
		hostRequest("Web\aFetch\x1b\\", "ev\x9dil.example\n"),
		dispatch.PromptDisplay{Action: "Run\atool", Subject: "Web\aFetch\x1b\\", HostRequest: "GET https://evil.example/\x1b]0;title\a\n\x9c"})

	for name, got := range map[string][]string{"benign": benign, "hostile": hostile} {
		if len(got) != 1 {
			t.Fatalf("%s notifier made %d writes, want exactly 1: %q", name, len(got), got)
		}
		if got[0] != headlessAlert {
			t.Fatalf("%s notifier wrote %q, want exactly %q", name, got[0], headlessAlert)
		}
	}
	if hostile[0] != benign[0] {
		t.Fatalf("hostile alert %q differs from the benign alert %q", hostile[0], benign[0])
	}
}

func terminalPromptOutput(t *testing.T, req permissions.MatchRequest, disp dispatch.PromptDisplay) string {
	t.Helper()
	var out bytes.Buffer
	p := newTerminalPrompter(strings.NewReader("2\n"), &out)
	if _, err := p.build(req, disp)(context.Background(), permissions.ScopeEscalation{}); err != nil {
		t.Fatalf("terminal prompt: %v", err)
	}
	return out.String()
}

func TestTerminalPrompter_SummaryPrecedesChoicesAndKeepsFullRequest(t *testing.T) {
	const tail = "TAILMARKER5X"
	command := "python3 -c '" + strings.Repeat("payload ", 200) + tail + "'"
	got := terminalPromptOutput(t,
		permissions.MatchRequest{Kind: matchKindLiteral, Subject: command, PathScope: "/work"},
		dispatch.PromptDisplay{Action: "Run command", Subject: command, WholeCommand: true},
	)

	summaryAt := strings.Index(got, "Summary: ")
	shapeAt := strings.Index(got, "Request: shell command,")
	choiceAt := strings.Index(got, "[1] allow once")
	if summaryAt < 0 || shapeAt < 0 || choiceAt < 0 {
		t.Fatalf("terminal prompt is missing the summary, shape line, or choices:\n%s", got)
	}
	if summaryAt >= shapeAt || shapeAt >= choiceAt {
		t.Fatalf("summary(%d) and shape(%d) must precede the choices(%d):\n%s", summaryAt, shapeAt, choiceAt, got)
	}
	if !strings.Contains(got, command) {
		t.Fatal("terminal prompt no longer prints the complete raw command")
	}
	if !strings.Contains(got, tail) {
		t.Fatal("terminal prompt truncated the request tail")
	}
	if !strings.Contains(got, "effect: unknown") {
		t.Fatalf("an interpreter with inline source must report the unknown fallback:\n%s", got)
	}
}

func TestTerminalPrompter_SummaryNamesKnownWriteTarget(t *testing.T) {
	got := terminalPromptOutput(t,
		permissions.MatchRequest{Kind: matchKindLiteral, Subject: "tee out.txt", PathScope: "/work"},
		dispatch.PromptDisplay{Action: "Run command", Subject: "tee out.txt", WholeCommand: true},
	)
	for _, want := range []string{"Requested target: out.txt", "effect: runs a command, writes"} {
		if !strings.Contains(got, want) {
			t.Fatalf("terminal summary missing %q:\n%s", want, got)
		}
	}
}

func TestTerminalPrompter_SummaryUsesLexicalToolTarget(t *testing.T) {
	cases := []struct {
		tool   string
		target string
		body   string
		kind   string
	}{
		{"read", "/outside/a.txt", `read({"path":"/outside/a.txt"})`, "Request: file read,"},
		{"file_count", "/outside/dir", `file_count({"path":"/outside/dir"})`, "Request: file count,"},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			got := terminalPromptOutput(t,
				permissions.MatchRequest{Kind: matchKindTool, Subject: tc.tool, PathScope: "/outside"},
				dispatch.PromptDisplay{Action: "Run tool", Subject: tc.tool, RequestedTarget: tc.target, Body: tc.body},
			)
			for _, want := range []string{"Requested target: " + tc.target, tc.kind, "effect: reads"} {
				if !strings.Contains(got, want) {
					t.Fatalf("terminal summary missing %q:\n%s", want, got)
				}
			}
			for _, banned := range []string{"structured-tool", "literal-command", "direct-command"} {
				if strings.Contains(got, banned) {
					t.Fatalf("terminal prompt leaked the matching discriminator %q:\n%s", banned, got)
				}
			}
		})
	}
}

func TestTerminalPrompter_HostSummaryBeforeChoices(t *testing.T) {
	got := terminalPromptOutput(t,
		hostRequest("web_fetch", "docs.example.test"),
		dispatch.PromptDisplay{HostRequest: "https://docs.example.test/a"},
	)
	summaryAt := strings.Index(got, "Summary: ")
	choiceAt := strings.Index(got, "[1] allow this once")
	if summaryAt < 0 || choiceAt < 0 || summaryAt > choiceAt {
		t.Fatalf("host summary must precede the choices:\n%s", got)
	}
	for _, want := range []string{"Requested target: docs.example.test", "Request: host request,", "effect: contacts a host"} {
		if !strings.Contains(got, want) {
			t.Fatalf("host summary missing %q:\n%s", want, got)
		}
	}
}

// Both surfaces build their rows from the same permissions owner, so a payload with a trailing
// newline and a multi-byte character must count identically in the terminal and the TUI.
func TestTerminalPrompter_ShapeCountsMatchInteractiveSurface(t *testing.T) {
	cases := []struct {
		name string
		req  permissions.MatchRequest
		disp dispatch.PromptDisplay
	}{
		{"trailing newline", permissions.MatchRequest{Kind: matchKindTool, Subject: "create", PathScope: "/work"},
			dispatch.PromptDisplay{Action: "Create file", Subject: "a.md", RequestedTarget: "a.md", Body: "one\ntwo\n"}},
		{"multi-byte content", permissions.MatchRequest{Kind: matchKindTool, Subject: "create", PathScope: "/work"},
			dispatch.PromptDisplay{Action: "Create file", Subject: "a.md", RequestedTarget: "a.md", Body: "héllo 日本語"}},
		{"empty payload", permissions.MatchRequest{Kind: matchKindTool, Subject: "delete", PathScope: "/work"},
			dispatch.PromptDisplay{Action: "Delete file", Subject: "a.md", RequestedTarget: "a.md"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			terminal := terminalPromptOutput(t, tc.req, tc.disp)
			interactive, err := buildPromptRequest(tc.req, PromptDisplay{
				Action:          tc.disp.Action,
				Subject:         tc.disp.Subject,
				Body:            tc.disp.Body,
				RequestedTarget: tc.disp.RequestedTarget,
			}, permissions.ScopeEscalation{})
			if err != nil {
				t.Fatalf("buildPromptRequest: %v", err)
			}
			shape := interactive.Summary.DisplayRows()[1]
			if !strings.Contains(terminal, shape) {
				t.Fatalf("terminal shape line differs from the interactive one\ninteractive: %q\nterminal:\n%s", shape, terminal)
			}
		})
	}
}

// TestTerminalPrompter_EscapesControlBytesInUntrustedRequestText: a prompted request carrying
// conceal, screen-clearing, or line-control sequences cannot hide the summary and choices the
// user decides from. The bytes are escaped losslessly, so the request stays inspectable.
func TestTerminalPrompter_EscapesControlBytesInUntrustedRequestText(t *testing.T) {
	hostile := map[string]string{
		"conceal":      "\x1b[8m",
		"clear screen": "\x1b[2J",
		"line control": "\rerased\x1b[1A\x1b[K",
		"delete":       "\x7f",
	}
	for name, seq := range hostile {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			p := newTerminalPrompter(strings.NewReader("1\n"), &out)
			req := permissions.MatchRequest{PathScope: "/proj/sub"}
			disp := dispatch.PromptDisplay{
				Action:  "Create file",
				Subject: "notes" + seq + ".md",
				Body:    "line one\n" + seq + "line two",
			}
			if _, err := p.build(req, disp)(context.Background(), permissions.ScopeEscalation{}); err != nil {
				t.Fatalf("prompt: %v", err)
			}
			got := out.String()
			if strings.ContainsAny(got, "\x1b\r\x7f") {
				t.Fatalf("terminal prompt emitted raw control bytes for %s:\n%q", name, got)
			}
			for _, want := range []string{"Summary:", "Request: ", "[1]", "[2]", "[3]", "[4]"} {
				if !strings.Contains(got, want) {
					t.Fatalf("%s hid %q from the prompt:\n%q", name, want, got)
				}
			}
			for _, want := range []string{"notes", ".md", "line one", "line two"} {
				if !strings.Contains(got, want) {
					t.Fatalf("%s dropped request text %q:\n%q", name, want, got)
				}
			}
			if !strings.Contains(got, `\x1B`) && !strings.Contains(got, `\x0D`) && !strings.Contains(got, `\x7F`) {
				t.Fatalf("%s was not rendered as a visible escape:\n%q", name, got)
			}
		})
	}
}

// TestTerminalPrompter_EscapesControlBytesInHostRequest: the same protection on the host prompt,
// whose request text and canonical host are equally untrusted.
func TestTerminalPrompter_EscapesControlBytesInHostRequest(t *testing.T) {
	req := hostRequest("web_fetch", "docs.example.com\x1b[2J")
	disp := dispatch.PromptDisplay{
		Action:      dispatch.ActionRunTool,
		Subject:     "web_fetch",
		HostRequest: "https://docs.example.com/\x1b[8mguide",
	}
	got, _ := promptHost(t, "1\n", req, disp)
	if strings.ContainsAny(got, "\x1b\r\x7f") {
		t.Fatalf("host prompt emitted raw control bytes:\n%q", got)
	}
	for _, want := range []string{"Summary:", "Request: ", "[1]", "[2]", `\x1B`, "docs.example.com", "guide"} {
		if !strings.Contains(got, want) {
			t.Fatalf("host prompt missing %q:\n%q", want, got)
		}
	}
}

// The host prompt's tool and host are authorization facts and are bounded, while its request
// text is the complete payload and stays lossless.
func TestTerminalPrompter_BoundsHostFacts(t *testing.T) {
	long := strings.Repeat("sub.", 60)
	req := hostRequest("web_fetch\ntool", long+"example.test")
	disp := dispatch.PromptDisplay{
		Action:      dispatch.ActionRunTool,
		Subject:     "web_fetch",
		HostRequest: "https://" + long + "example.test/guide",
	}
	got, _ := promptHost(t, "1\n", req, disp)
	for _, want := range []string{
		"  tool: " + permissions.BoundPromptFact(req.Subject) + "\n",
		"  host: " + permissions.BoundPromptFact(req.Host) + "\n",
		"  request: " + disp.HostRequest + "\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("host prompt missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "  host: "+req.Host+"\n") {
		t.Fatalf("host rendered without the 120-code-point bound:\n%s", got)
	}
}

// Every variable authorization fact on the terminal prompt carries the interactive prompt's
// bounded contract: a newline- or tab-bearing value adds no physical row ahead of the choices,
// and an over-cap value is cut at 120 code points.
func TestTerminalPrompter_BoundsVariableFixedFacts(t *testing.T) {
	render := func(t *testing.T, root string) string {
		t.Helper()
		scope := root + "/sub"
		var out bytes.Buffer
		p := newTerminalPrompter(strings.NewReader("1\n"), &out)
		p.disclosure = terminalDisclosure{
			projectRoot:             root,
			launchDir:               root,
			boundary:                "launch-dir-only",
			folderSettingsPath:      filepath.Join(root, ".codemeld", "settings.yaml"),
			wouldCreateSettingsFile: true,
		}
		req := permissions.MatchRequest{PathScope: scope}
		disp := dispatch.PromptDisplay{Action: "Create file", Subject: "notes.md"}
		esc := permissions.ScopeEscalation{NarrowerScope: scope + "/deeper"}
		if _, err := p.build(req, disp)(context.Background(), esc); err != nil {
			t.Fatalf("prompt: %v", err)
		}
		return out.String()
	}

	root := "/proj/\n\t\x1b[2Jrow" + strings.Repeat("seg/", 60)
	scope := root + "/sub"
	settings := filepath.Join(root, ".codemeld", "settings.yaml")
	got := render(t, root)

	if strings.ContainsAny(got, "\x1b\r\x7f\t") {
		t.Fatalf("terminal prompt emitted a raw control byte:\n%q", got)
	}
	if rows, want := strings.Count(got, "\n"), strings.Count(render(t, "/proj/row"), "\n"); rows != want {
		t.Fatalf("hostile fact values added physical rows: %d, want %d\n%s", rows, want, got)
	}
	for _, unbounded := range []string{scope, root, settings, scope + "/deeper"} {
		if strings.Contains(got, permissions.VisibleControlEscape(unbounded)) {
			t.Fatalf("fact rendered without the 120-code-point bound: %q\n%s", unbounded, got)
		}
	}
	for _, want := range []string{
		"  path: " + permissions.BoundPromptFact(scope),
		"  project root: " + permissions.BoundPromptFact(root),
		"PARENT of " + permissions.BoundPromptFact(scope+"/deeper"),
		"permanently in " + permissions.BoundPromptFact(settings),
		"applies when run from: " + permissions.BoundPromptFact(scope) + " and its descendants",
		tui.RenderCrossModeMarkerNotice(permissions.BoundPromptFact(settings)),
		"Summary:", "Request: ", "[1]", "[2]", "[3]", "[4]",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("terminal prompt missing %q:\n%s", want, got)
		}
	}
}

func TestHeadlessAuthorizer_AutoDeclaredCommandRunsWithoutPrompt(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	var rendered bytes.Buffer
	cache := declaredCommandCache(t, cwd, "git push")
	auth := newHeadlessAuthorizer(cache, func() *sessions.Store { return store },
		mode.NewActiveState(mode.AutoEdits, mode.SourceConfig),
		newTerminalPrompter(strings.NewReader(""), &rendered), stderrNoticeRenderer{w: &bytes.Buffer{}})

	run := &fakeDispatchRunner{}
	for _, cmd := range []string{"git push origin main", "git push origin release"} {
		if _, err := dispatch.DispatchShell(context.Background(), cmd, home, cwd, auth, run); err != nil {
			t.Fatalf("DispatchShell(%q): %v", cmd, err)
		}
	}

	if run.callCount() != 2 {
		t.Fatalf("runner Exec calls = %d, want 2", run.callCount())
	}
	if strings.Contains(rendered.String(), "approval required") {
		t.Fatalf("a declared command prompted in a headless run: %q", rendered.String())
	}
	kinds := permissionEventKinds(store)
	if len(kinds) != 2 || kinds[0] != events.KindPermissionMatched || kinds[1] != events.KindPermissionMatched {
		t.Fatalf("permission event stream = %v, want two permission_matched records and nothing else", kinds)
	}
	matched := decodeStoreEvents[events.PermissionMatched](t, store, events.KindPermissionMatched)
	want := events.PermissionMatched{
		SubjectKind:          "direct",
		Subject:              "git push origin main",
		PathScope:            cwd,
		Outcome:              "once",
		OutcomeSource:        "declared_command",
		DirectRequestSubject: "git push origin main",
	}
	if matched[0] != want {
		t.Fatalf("permission_matched = %#v, want %#v", matched[0], want)
	}
	if got := len(cache.Permissions()); got != 0 {
		t.Fatalf("grant table holds %d entries, want 0", got)
	}
	if _, hit := auth.grants.Lookup(directRequest(cwd, "git", "push", "origin", "main")); hit {
		t.Fatalf("a declared-list hit must not write a turn-cache entry")
	}
	if _, err := os.Stat(filepath.Join(cwd, ".codemeld", "settings.yaml")); !os.IsNotExist(err) {
		t.Fatalf("os.Stat(project settings) = %v, want the file never written", err)
	}
	if denied := auth.deniedSubjects(); len(denied) != 0 {
		t.Fatalf("denied calls = %v, want none", denied)
	}
}

// headlessContainmentTree lays home and a scratch directory out as siblings, so the walk up
// from a path under the scratch directory stops at home's parent.
type headlessContainmentTree struct {
	home  string
	tmp   string
	run   string
	entry string
}

func newHeadlessContainmentTree(t *testing.T) headlessContainmentTree {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp root: %v", err)
	}
	tree := headlessContainmentTree{home: filepath.Join(root, "home", "user"), tmp: filepath.Join(root, "tmp")}
	tree.run = filepath.Join(tree.tmp, "codemeld-g2430-audit.RtAY58")
	tree.entry = filepath.Join(tree.run, "id-ssh")
	if err := os.MkdirAll(tree.home, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	if err := os.MkdirAll(tree.run, 0o755); err != nil {
		t.Fatalf("mkdir run: %v", err)
	}
	if err := os.WriteFile(tree.entry, nil, 0o644); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	return tree
}

func promptDirectWithHome(t *testing.T, input, home string, req permissions.MatchRequest) (string, permissions.PromptOutcome) {
	t.Helper()
	var out bytes.Buffer
	p := newTerminalPrompter(strings.NewReader(input), &out)
	p.disclosure = projectDisclosure("/proj")
	p.home = home
	outcome, err := p.build(req, dispatch.PromptDisplay{Action: "Run command", Subject: req.Subject})(context.Background(), permissions.ScopeEscalation{})
	if err != nil {
		t.Fatalf("direct prompt: %v", err)
	}
	return out.String(), outcome
}

func TestTerminalPrompter_PathScopeIsFixedAtTheWidestBoundary(t *testing.T) {
	tree := newHeadlessContainmentTree(t)
	req := directRequest("/proj", "chmod", "+x", tree.entry)
	got, outcome := promptDirectWithHome(t, "3\n3\n", tree.home, req)

	if outcome.Choice != permissions.PromptAllowSession {
		t.Fatalf("choice = %d, want PromptAllowSession", outcome.Choice)
	}
	want, err := permissions.EncodeDirectUnderSubject([]string{"chmod", "+x", tree.entry}, 2, tree.tmp, false)
	if err != nil {
		t.Fatalf("EncodeDirectUnderSubject: %v", err)
	}
	if outcome.StoredSubject != want {
		t.Fatalf("stored subject = %q, want the widest boundary %q", outcome.StoredSubject, tree.tmp)
	}
	for _, phrase := range []string{
		"[3] path: chmod +x :under=" + tree.tmp + " — chmod +x against any path resolving under " + tree.tmp + ", checked when permission is decided [recommended]",
		"[2] prefix: chmod +x " + tree.entry + " :*",
		"[4] prefix: chmod +x :*",
		"[5] program (advanced): chmod :*",
		"The path choice is fixed at " + tree.tmp,
		"the interactive prompt can walk that boundary with ← and →, this one reads a single number and cannot",
		"resolved and checked against that boundary at the moment permission is decided",
		"not an execution-time sandbox",
		"codemeld: choose 1-5: ",
	} {
		if !strings.Contains(got, phrase) {
			t.Fatalf("scope render missing %q:\n%s", phrase, got)
		}
	}
	if strings.Contains(got, "'direct-under/v1 ") {
		t.Fatalf("scope render leaked the stored envelope:\n%s", got)
	}
	if strings.Contains(got, ":under="+tree.run) {
		t.Fatalf("headless render offered the immediate parent instead of the widest boundary:\n%s", got)
	}
	for _, banned := range []string{"confines what", "cannot escape", "prevents the program", "restricted to"} {
		if strings.Contains(strings.ToLower(got), banned) {
			t.Fatalf("scope render promises execution-time confinement (%q):\n%s", banned, got)
		}
	}
}

func TestTerminalPrompter_PathScopeCanonicalizesHomeAndFailsClosed(t *testing.T) {
	tree := newHeadlessContainmentTree(t)
	root := filepath.Dir(filepath.Dir(tree.home))
	linked := filepath.Join(root, "home-link")
	if err := os.Symlink(tree.home, linked); err != nil {
		t.Fatalf("symlink home: %v", err)
	}
	dangling := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(tree.home, "absent"), dangling); err != nil {
		t.Fatalf("dangling symlink: %v", err)
	}
	loopA, loopB := filepath.Join(root, "loop-a"), filepath.Join(root, "loop-b")
	if err := os.Symlink(loopB, loopA); err != nil {
		t.Fatalf("loop a: %v", err)
	}
	if err := os.Symlink(loopA, loopB); err != nil {
		t.Fatalf("loop b: %v", err)
	}
	insideHome := filepath.Join(tree.home, "run.sh")
	if err := os.WriteFile(insideHome, nil, 0o644); err != nil {
		t.Fatalf("write inside home: %v", err)
	}

	// A path below home: only there can a home spelling that is not canonical make home
	// itself, or one of its ancestors, look like a selectable boundary.
	work := filepath.Join(tree.home, "work", "sub")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatalf("mkdir work: %v", err)
	}
	belowHome := filepath.Join(work, "run.sh")
	if err := os.WriteFile(belowHome, nil, 0o644); err != nil {
		t.Fatalf("write below home: %v", err)
	}
	widest := filepath.Join(tree.home, "work")
	req := directRequest("/proj", "chmod", "+x", belowHome)
	want, err := permissions.EncodeDirectUnderSubject([]string{"chmod", "+x", belowHome}, 2, widest, false)
	if err != nil {
		t.Fatalf("EncodeDirectUnderSubject: %v", err)
	}
	for _, home := range []string{tree.home, linked, filepath.Join(tree.home, "work", "..")} {
		got, outcome := promptDirectWithHome(t, "3\n3\n", home, req)
		if outcome.StoredSubject != want {
			t.Errorf("home %q stored %q, want the canonical widest boundary %q", home, outcome.StoredSubject, widest)
		}
		for _, floor := range []string{tree.home, linked, filepath.Dir(tree.home), root} {
			if strings.Contains(got, ":under="+floor+" ") {
				t.Errorf("home %q offered %q, which is at or above canonical home:\n%s", home, floor, got)
			}
		}
	}

	// The chooser is given home; a HOME assignment on the request must not become one.
	assigned := req
	assigned.Assignments = []string{"HOME=" + tree.home}
	if got, outcome := promptDirectWithHome(t, "3\n3\n", "", assigned); strings.Contains(got, ":under=") || outcome.StoredSubject == want {
		t.Errorf("containment was inferred from the command environment:\n%s", got)
	}

	suppressed := []struct {
		name string
		home string
		req  permissions.MatchRequest
	}{
		{"empty home", "", req},
		{"relative home", "home/user", req},
		{"missing home", filepath.Join(tree.home, "absent"), req},
		{"non-directory home", tree.entry, req},
		{"dangling symlink home", dangling, req},
		{"symlink loop home", loopA, req},
		{"path directly inside home", tree.home, directRequest("/proj", "chmod", "+x", insideHome)},
	}
	for _, c := range suppressed {
		t.Run(c.name, func(t *testing.T) {
			got, outcome := promptDirectWithHome(t, "3\n3\n", c.home, c.req)
			if strings.Contains(got, ":under=") {
				t.Fatalf("containment was offered:\n%s", got)
			}
			if !strings.Contains(got, "codemeld: choose 1-4: ") {
				t.Fatalf("ladder changed shape:\n%s", got)
			}
			if outcome.StoredSubject != permissions.PrefixSubject(c.req.SubjectTokens[0], c.req.SubjectTokens[1:2]) {
				t.Fatalf("stored subject = %q, want the unchanged third row", outcome.StoredSubject)
			}
		})
	}
}

func TestTerminalPrompter_PathScopeWildcardsATailAndNeedsNoConfirmation(t *testing.T) {
	tree := newHeadlessContainmentTree(t)
	repo := filepath.Join(tree.run, "subprobe", "sub")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	req := directRequest("/proj", "git", "-C", repo, "add", "a")
	got, outcome := promptDirectWithHome(t, "3\n5\n", tree.home, req)

	want, err := permissions.EncodeDirectUnderSubject([]string{"git", "-C", repo, "add", "a"}, 2, tree.tmp, true)
	if err != nil {
		t.Fatalf("EncodeDirectUnderSubject: %v", err)
	}
	if outcome.StoredSubject != want {
		t.Fatalf("stored subject = %q, want the tail-wildcard grant at %q", outcome.StoredSubject, tree.tmp)
	}
	if !strings.Contains(got, "[5] path: git -C :under="+tree.tmp+" :*") {
		t.Fatalf("scope render missing the tail-wildcard path row:\n%s", got)
	}
	if !strings.Contains(got, "any later arguments may vary") {
		t.Fatalf("path row does not say the tail is free:\n%s", got)
	}
	if strings.Contains(got, "confirm program-wide grant") {
		t.Fatalf("the path choice was confirm-gated:\n%s", got)
	}
	if !permissions.MatchesDirectSubject([]string{"git", "-C", repo, "rev-parse", "HEAD"}, nil, false, outcome.StoredSubject) {
		t.Error("the stored grant does not authorize the same command with a different tail")
	}
}

func promptTool(t *testing.T, input string, req permissions.MatchRequest, disp dispatch.PromptDisplay) (string, permissions.PromptOutcome) {
	t.Helper()
	var out bytes.Buffer
	p := newTerminalPrompter(strings.NewReader(input), &out)
	outcome, err := p.build(req, disp)(context.Background(), permissions.ScopeEscalation{})
	if err != nil {
		t.Fatalf("tool prompt: %v", err)
	}
	return out.String(), outcome
}

func capabilityToolPrompt(tool, capability string) (permissions.MatchRequest, dispatch.PromptDisplay) {
	req := permissions.MatchRequest{Kind: matchKindTool, Subject: tool, PathScope: "/outside"}
	disp := dispatch.PromptDisplay{Action: "Run tool", Subject: tool, GrantStoredSubject: capability}
	return req, disp
}

func TestTerminalPrompter_ToolGrantStoresDispatchCapability(t *testing.T) {
	lifetimes := []struct {
		input  string
		choice permissions.PromptChoice
	}{
		{"3\n", permissions.PromptAllowSession},
		{"4\n", permissions.PromptAllowFolder},
	}
	folded := []struct {
		tool string
		want string
	}{
		{"read", permissions.CapabilityRead},
		{"grep", permissions.CapabilityRead},
		{"create", permissions.CapabilityWriteTree},
		{"edit", permissions.CapabilityWriteTree},
		{"mkdir", permissions.CapabilityWriteTree},
	}
	for _, tc := range folded {
		t.Run(tc.tool, func(t *testing.T) {
			for _, lt := range lifetimes {
				req, disp := capabilityToolPrompt(tc.tool, tc.want)
				_, outcome := promptTool(t, lt.input, req, disp)
				if outcome.Choice != lt.choice {
					t.Fatalf("input %q choice = %d, want %d", lt.input, outcome.Choice, lt.choice)
				}
				if outcome.StoredSubject != tc.want {
					t.Fatalf("input %q stored subject = %q, want the folded capability %q", lt.input, outcome.StoredSubject, tc.want)
				}
			}
		})
	}
}

func TestTerminalPrompter_ToolGrantWithoutCapabilityKeepsConcreteSubject(t *testing.T) {
	for _, input := range []string{"3\n", "4\n"} {
		req, disp := capabilityToolPrompt("delete", "")
		_, outcome := promptTool(t, input, req, disp)
		if outcome.StoredSubject != "" {
			t.Fatalf("input %q stored subject = %q, want empty so the grant keeps the concrete request subject", input, outcome.StoredSubject)
		}
	}
}

func TestTerminalPrompter_AllowOnceAndDenyStoreNoCapability(t *testing.T) {
	for _, input := range []string{"1\n", "2\n"} {
		req, disp := capabilityToolPrompt("read", permissions.CapabilityRead)
		_, outcome := promptTool(t, input, req, disp)
		if outcome.StoredSubject != "" {
			t.Fatalf("input %q stored subject = %q, want empty — neither allow-once nor deny creates a grant", input, outcome.StoredSubject)
		}
	}
}

func TestTerminalPrompter_HostGrantIgnoresDisplayCapability(t *testing.T) {
	for _, input := range []string{"3\n", "4\n"} {
		disp := dispatch.PromptDisplay{
			Action:             dispatch.ActionRunTool,
			Subject:            "web_fetch",
			HostRequest:        "https://docs.example.com/guide",
			GrantStoredSubject: permissions.CapabilityRead,
		}
		_, outcome := promptHost(t, input, hostRequest("web_fetch", "docs.example.com"), disp)
		if outcome.StoredSubject != "" {
			t.Fatalf("input %q stored subject = %q, want empty — a host grant keeps its own host subject", input, outcome.StoredSubject)
		}
	}
}

func TestTerminalPrompter_CapabilityCoverageFramesOnlyCapabilityToolChoices(t *testing.T) {
	sentence := tui.CapabilityCoverageSentence(permissions.CapabilityRead)
	if sentence == "" {
		t.Fatal("tui.CapabilityCoverageSentence(read*) is empty, so the prompt has no coverage wording to render")
	}

	req, disp := capabilityToolPrompt("read", permissions.CapabilityRead)
	got := terminalPromptOutput(t, req, disp)
	coverageAt := strings.Index(got, sentence)
	choiceAt := strings.Index(got, "[1] allow once")
	if coverageAt < 0 {
		t.Fatalf("capability tool prompt is missing the coverage sentence %q:\n%s", sentence, got)
	}
	if choiceAt < 0 || coverageAt > choiceAt {
		t.Fatalf("the coverage sentence must frame the option list, not follow it:\n%s", got)
	}

	writeSentence := tui.CapabilityCoverageSentence(permissions.CapabilityWriteTree)
	wreq, wdisp := capabilityToolPrompt("create", permissions.CapabilityWriteTree)
	if out := terminalPromptOutput(t, wreq, wdisp); !strings.Contains(out, writeSentence) {
		t.Fatalf("write_tree tool prompt is missing the coverage sentence %q:\n%s", writeSentence, out)
	}

	silent := []struct {
		name string
		req  permissions.MatchRequest
		disp dispatch.PromptDisplay
	}{
		{"tool without a capability", permissions.MatchRequest{Kind: matchKindTool, Subject: "delete", PathScope: "/outside"},
			dispatch.PromptDisplay{Action: "Run tool", Subject: "delete"}},
		{"direct command", directRequest("/proj", "rm", "notes.txt"),
			dispatch.PromptDisplay{Action: "Run command", Subject: "rm notes.txt", GrantStoredSubject: permissions.CapabilityRead}},
		{"literal command", permissions.MatchRequest{Kind: matchKindLiteral, Subject: "tee out.txt", PathScope: "/work"},
			dispatch.PromptDisplay{Action: "Run command", Subject: "tee out.txt", GrantStoredSubject: permissions.CapabilityRead}},
		{"host request", hostRequest("web_fetch", "docs.example.com"),
			dispatch.PromptDisplay{Action: dispatch.ActionRunTool, Subject: "web_fetch", HostRequest: "https://docs.example.com/guide", GrantStoredSubject: permissions.CapabilityRead}},
	}
	for _, tc := range silent {
		t.Run(tc.name, func(t *testing.T) {
			out := terminalPromptOutput(t, tc.req, tc.disp)
			if strings.Contains(out, tui.CapabilityCoveragePhrase(permissions.CapabilityRead)) {
				t.Fatalf("prompt disclosed capability coverage it does not store:\n%s", out)
			}
			if strings.Contains(out, "Approving a grant below allows") {
				t.Fatalf("prompt rendered a coverage sentence:\n%s", out)
			}
		})
	}
}

func TestTerminalPrompter_AnswerAfterCancellationAuthorizesNothing(t *testing.T) {
	for _, tc := range []struct {
		name     string
		req      permissions.MatchRequest
		cancelOn int
		answers  []string
	}{
		{"project grant", permissions.MatchRequest{}, 1, []string{"4\n"}},
		{"direct command before its scope read", directRequest("/proj", "git", "status"), 1, []string{"4\n", "1\n"}},
		{"direct command scope", directRequest("/proj", "git", "status"), 2, []string{"4\n", "1\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads := 0
			stdin := readerFunc(func(b []byte) (int, error) {
				if reads >= len(tc.answers) {
					return 0, io.EOF
				}
				reads++
				if reads == tc.cancelOn {
					cancel()
				}
				return copy(b, tc.answers[reads-1]), nil
			})
			p := newTerminalPrompter(stdin, &bytes.Buffer{})

			outcome, err := p.build(tc.req, dispatch.PromptDisplay{Action: "Run command"})(ctx, permissions.ScopeEscalation{})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
			if outcome != (permissions.PromptOutcome{}) {
				t.Fatalf("outcome = %+v, want none", outcome)
			}
			if reads != tc.cancelOn {
				t.Fatalf("stdin reads = %d, want %d (no further prompt after cancellation)", reads, tc.cancelOn)
			}
		})
	}
}

func exceptionalHeadlessAuthorizer(t *testing.T, input string, out io.Writer) (*headlessAuthorizer, string) {
	t.Helper()
	cwd := t.TempDir()
	modeActive := mode.NewActiveState(mode.AutoEdits, mode.SourceUserCommand)
	var terminal *terminalPrompter
	if out != nil {
		terminal = newTerminalPrompter(strings.NewReader(input), out)
	}
	store := mkStore(t)
	auth := newHeadlessAuthorizer(emptyCache(t, cwd), func() *sessions.Store { return store }, modeActive, terminal, stderrNoticeRenderer{w: &bytes.Buffer{}})
	auth.executionConstrained = true
	return auth, cwd
}

type exceptionalCall struct {
	req     permissions.MatchRequest
	disp    dispatch.PromptDisplay
	modeCtx permissions.ModeContext
}

func exceptionalCalls(cwd string) map[string]exceptionalCall {
	tokens := []string{"curl", "https://example.com/a"}
	return map[string]exceptionalCall{
		"direct": {
			permissions.MatchRequest{Kind: matchKindDirect, Subject: "curl https://example.com/a", SubjectTokens: tokens, PathScope: cwd},
			dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: "curl https://example.com/a"},
			permissions.ModeContext{Class: permissions.ClassMutating, Stages: []permissions.StageNormalization{{Tokens: tokens, Source: "curl https://example.com/a"}}},
		},
		"literal": {
			permissions.MatchRequest{Kind: matchKindLiteral, Subject: "sh -c 'curl https://example.com/a'", PathScope: cwd},
			dispatch.PromptDisplay{Action: dispatch.ActionRunCommand, Subject: "sh -c 'curl https://example.com/a'", WholeCommand: true},
			permissions.ModeContext{Class: permissions.ClassMutating, LiteralRoute: true},
		},
	}
}

func TestHeadlessAuthorizer_ExceptionalPromptOffersOnlyAllowOnceAndDeny(t *testing.T) {
	notice := fmt.Sprintf(tui.ExceptionalSandboxNotice, "network access")
	for _, name := range []string{"direct", "literal"} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			auth, cwd := exceptionalHeadlessAuthorizer(t, "1\n1\n", &out)
			call := exceptionalCalls(cwd)[name]
			for i := range 2 {
				dec, err := auth.Authorize(context.Background(), call.req, call.disp, call.modeCtx)
				if err != nil || dec.DenyEnvelope != "" || dec.Grant != nil {
					t.Fatalf("allow once %d = %+v, %v; want an allow with no grant", i, dec, err)
				}
			}
			got := out.String()
			if n := strings.Count(got, "approval required"); n != 2 {
				t.Fatalf("identical exceptional repeat rendered %d prompts, want 2:\n%s", n, got)
			}
			for _, want := range []string{"Allow network access: " + call.disp.Subject, notice, "[1] allow this once", "a repeat asks again", "[2] deny", "codemeld: choose 1-2: "} {
				if !strings.Contains(got, want) {
					t.Fatalf("prompt missing %q:\n%s", want, got)
				}
			}
			for _, banned := range []string{"[3]", "[4]", tui.ShellBlockedPathsNotice, "settings.yaml", "choose 1-3", "choose 1-4", "choose its scope"} {
				if strings.Contains(got, banned) {
					t.Fatalf("prompt contains %q:\n%s", banned, got)
				}
			}
			if grants := auth.grants.Permissions(); len(grants) != 0 {
				t.Fatalf("grants = %+v, want none", grants)
			}
		})
	}
}

func TestHeadlessAuthorizer_ExceptionalGrantInputsDeny(t *testing.T) {
	for _, input := range []string{"3\n", "session\n", "s\n", "allow-session\n", "4\n", "project\n", "p\n", "allow-project\n", "5\n", "global\n"} {
		var out bytes.Buffer
		auth, cwd := exceptionalHeadlessAuthorizer(t, input+"1\n", &out)
		call := exceptionalCalls(cwd)["direct"]
		dec, err := auth.Authorize(context.Background(), call.req, call.disp, call.modeCtx)
		if err != nil || dec.DenyEnvelope == "" {
			t.Fatalf("input %q = %+v, %v; want a deny", input, dec, err)
		}
		if grants := auth.grants.Permissions(); len(grants) != 0 {
			t.Fatalf("input %q stored grants %+v", input, grants)
		}
		if strings.Contains(out.String(), "choose its scope") {
			t.Fatalf("input %q opened the scope chooser:\n%s", input, out.String())
		}
	}
}
