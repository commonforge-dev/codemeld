package bootstrap

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// titleResult builds a BootstrapResult wired to dispatch a real openai turn against the
// injected stub client. launchDir doubles as the project root so a typed image
// reference under it is attached through the production path (the non-text-prompt test).
func titleResult(t *testing.T, store *sessions.Store, launchDir string) *BootstrapResult {
	t.Helper()
	return &BootstrapResult{
		Home:        t.TempDir(),
		LaunchDir:   launchDir,
		ProjectRoot: launchDir,
		Session:     store,
		Model:       model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{
					"base_url": "https://api.openai.com/v1",
					"api_key":  "sk-test",
					"models":   []string{"gpt-5.5"},
				},
			},
		},
	}
}

// isTitleRequest recognizes the narrow title request, whose user message is the rendered
// opening exchange; a turn request can share its two-message shape, so the count cannot tell them apart.
func isTitleRequest(req provider.Request) bool {
	n := len(req.Messages)
	return n > 0 && req.Messages[n-1].Role == "user" && strings.HasPrefix(req.Messages[n-1].Content, "User: ")
}

func titleCompletion(content string) provider.Response {
	return provider.Response{Stream: newStream(contentChunk(content), finishChunk("stop"))}
}

func streamedTitle(content string) func(context.Context, provider.Request) (provider.Response, error) {
	return func(context.Context, provider.Request) (provider.Response, error) {
		return titleCompletion(content), nil
	}
}

// TestTitleGen_FirstTurnPersistsGeneratedTitle: a successful first turn generates a
// title from a second streamed provider call on the same client and persists it
// to disk, and title generation appends no model_turn / model_response records.
func TestTitleGen_FirstTurnPersistsGeneratedTitle(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if !isTitleRequest(req) {
			return provider.Response{Stream: newStream(contentChunk("Hello"), finishChunk("stop"))}, nil
		}
		return titleCompletion("Refactor login flow"), nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	if err := StartTUI(context.Background(), titleResult(t, store, t.TempDir()), io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop")
	}

	if !ran.SubmitInput("help me refactor login") {
		t.Fatal("plain prompt rejected; the wired turn path is broken")
	}
	turns.Wait()

	if got := client.callCount(); got != 2 {
		t.Fatalf("provider calls = %d, want 2 (the streamed turn plus one title request)", got)
	}
	persisted := readSessionFile(t, store.Path()).Metadata
	if persisted.Title != "Refactor login flow" {
		t.Fatalf("persisted title = %q, want %q", persisted.Title, "Refactor login flow")
	}
	if persisted.TitleSource != sessions.TitleSourceGenerated {
		t.Fatalf("persisted title_source = %q, want %q", persisted.TitleSource, sessions.TitleSourceGenerated)
	}
	if got := ran.SessionBadgeText(); !strings.Contains(got, "Refactor login flow") {
		t.Fatalf("badge = %q, want the generated title", got)
	}
	// Event hygiene: the title request contributes no conversation records.
	if n := len(kindEvents(t, store, "model_turn")); n != 1 {
		t.Fatalf("model_turn events = %d, want 1 (title generation must add none)", n)
	}
	if n := len(kindEvents(t, store, "model_response")); n != 1 {
		t.Fatalf("model_response events = %d, want 1 (title generation must add none)", n)
	}
}

// TestTitleGen_ProviderFailureKeepsFallbackTitle: a provider error, an empty candidate or a failed stream
// leaves the first-prompt fallback title in place while the user turn still completes.
func TestTitleGen_ProviderFailureKeepsFallbackTitle(t *testing.T) {
	cases := map[string]func() (provider.Response, error){
		"provider error": func() (provider.Response, error) {
			return provider.Response{}, errors.New("boom")
		},
		"empty candidate": func() (provider.Response, error) {
			return titleCompletion(""), nil
		},
		"failed stream": func() (provider.Response, error) {
			return provider.Response{Stream: dropStream(contentChunk("Partial title"), errors.New("connection reset"))}, nil
		},
	}
	for name, titleResp := range cases {
		t.Run(name, func(t *testing.T) {
			var ran *tui.App
			defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()
			var turns sync.WaitGroup
			defer swapGoTurn(waitableGoTurn(&turns))()

			client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
				if !isTitleRequest(req) {
					return provider.Response{Stream: newStream(contentChunk("Hello"), finishChunk("stop"))}, nil
				}
				return titleResp()
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			store := mkStore(t)
			if err := StartTUI(context.Background(), titleResult(t, store, t.TempDir()), io.Discard); err != nil {
				t.Fatalf("StartTUI error: %v", err)
			}
			if ran == nil {
				t.Fatal("StartTUI did not run the event loop")
			}

			if !ran.SubmitInput("help me refactor login") {
				t.Fatal("plain prompt rejected")
			}
			turns.Wait()

			persisted := readSessionFile(t, store.Path()).Metadata
			if persisted.Title != "help me refactor login" || persisted.TitleSource != sessions.TitleSourceGenerated {
				t.Fatalf("title/source = %q/%q, want the fallback %q/%q after a failed title generation",
					persisted.Title, persisted.TitleSource, "help me refactor login", sessions.TitleSourceGenerated)
			}
			// The user turn itself still succeeded: its message and reply are durable.
			if got := userMessageCount(store); got != 1 {
				t.Fatalf("user messages = %d, want 1 (the user turn must still succeed)", got)
			}
			if n := len(kindEvents(t, store, "model_response")); n != 1 {
				t.Fatalf("model_response events = %d, want 1 (the turn completed normally)", n)
			}
		})
	}
}

// TestTitleGen_PreRenamedFirstTurnSkipsProviderCall: a session the user already
// named before the first prompt is not eligible for title generation, so no
// title request is made after that first turn completes.
func TestTitleGen_PreRenamedFirstTurnSkipsProviderCall(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if isTitleRequest(req) {
			t.Errorf("unexpected title request after manual rename")
		}
		return provider.Response{Stream: newStream(contentChunk("Hello"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	if err := StartTUI(context.Background(), titleResult(t, store, t.TempDir()), io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop")
	}

	if !ran.SubmitInput("/rename Manual title") {
		t.Fatal("/rename rejected")
	}
	if got := readSessionFile(t, store.Path()).Metadata.Title; got != "Manual title" {
		t.Fatalf("title after /rename = %q, want %q", got, "Manual title")
	}
	if !ran.SubmitInput("help me refactor login") {
		t.Fatal("plain prompt rejected")
	}
	turns.Wait()

	if got := client.callCount(); got != 1 {
		t.Fatalf("provider calls = %d, want 1 (the streamed turn only)", got)
	}
	persisted := readSessionFile(t, store.Path()).Metadata
	if persisted.Title != "Manual title" {
		t.Fatalf("title after first turn = %q, want %q", persisted.Title, "Manual title")
	}
	if persisted.TitleSource != sessions.TitleSourceUser {
		t.Fatalf("title_source after first turn = %q, want %q (the manual rename keeps its provenance)", persisted.TitleSource, sessions.TitleSourceUser)
	}
	if got := ran.SessionBadgeText(); !strings.Contains(got, "Manual title") {
		t.Fatalf("badge = %q, want the session-name badge to survive the first turn", got)
	}
}

func heldTitleClient(title string) (client *stubTurnClient, started, release chan struct{}) {
	started, release = make(chan struct{}), make(chan struct{})
	client = &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if !isTitleRequest(req) {
			return provider.Response{Stream: newStream(contentChunk("Hello"), finishChunk("stop"))}, nil
		}
		close(started)
		<-release
		return titleCompletion(title), nil
	}}
	return client, started, release
}

// waitTitleBackgroundDone waits until no RunBackgroundAfterDraw goroutine is left. That
// goroutine queues its completion with a QueueUpdate that returns only after the event loop
// ran it, so once the goroutine is gone the completion has run or been dropped.
func waitTitleBackgroundDone(t *testing.T) {
	t.Helper()
	buf := make([]byte, 1<<20)
	deadline := time.Now().Add(5 * time.Second)
	for strings.Contains(string(buf[:runtime.Stack(buf, true)]), "(*App).RunBackgroundAfterDraw.func") {
		if time.Now().After(deadline) {
			t.Fatal("title generation's background work did not finish within 5s")
		}
		time.Sleep(time.Millisecond)
	}
}

func badgeOnEventLoop(t *testing.T, app *tui.App) string {
	t.Helper()
	var badge string
	onEventLoop(t, app, func() { badge = app.SessionBadgeText() })
	return badge
}

func TestTitleGen_LiveModelTitleReplacesFallbackAndBadge(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()
	client, started, release := heldTitleClient("Refactor login flow")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	var held, final sessions.Metadata
	var badge string
	var activeAfter *sessions.Store
	defer runLiveApp(t, tcell.NewSimulationScreen("UTF-8"), func(app *tui.App) {
		if !submitOnEventLoop(t, app, "help me refactor login") {
			t.Fatal("plain prompt rejected")
		}
		<-started
		held = readSessionFile(t, store.Path()).Metadata
		close(release)
		turns.Wait()
		waitTitleBackgroundDone(t)
		final = readSessionFile(t, store.Path()).Metadata
		badge = badgeOnEventLoop(t, app)
		activeAfter = app.ActiveStore()
	})()
	if err := StartTUI(context.Background(), titleResult(t, store, t.TempDir()), io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}

	if held.Title != "help me refactor login" || held.TitleSource != sessions.TitleSourceGenerated {
		t.Fatalf("title/source during generation = %q/%q, want the fallback %q/%q", held.Title, held.TitleSource, "help me refactor login", sessions.TitleSourceGenerated)
	}
	if final.Title != "Refactor login flow" || final.TitleSource != sessions.TitleSourceGenerated {
		t.Fatalf("title/source after completion = %q/%q, want %q/%q", final.Title, final.TitleSource, "Refactor login flow", sessions.TitleSourceGenerated)
	}
	if !strings.Contains(badge, "Refactor login flow") {
		t.Fatalf("badge = %q, want the model title", badge)
	}
	if activeAfter != store {
		t.Fatal("the active store changed; the badge must refresh without a store swap")
	}
}

// TestTitleGen_ManualRenameWinsOverAsyncTitle: a /rename that lands while generation is in
// flight wins; the completion on the event loop leaves the user title and its source alone.
func TestTitleGen_ManualRenameWinsOverAsyncTitle(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()
	client, started, release := heldTitleClient("Generated title")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	var final sessions.Metadata
	var badge string
	defer runLiveApp(t, tcell.NewSimulationScreen("UTF-8"), func(app *tui.App) {
		if !submitOnEventLoop(t, app, "help me refactor login") {
			t.Fatal("plain prompt rejected")
		}
		<-started
		if !submitOnEventLoop(t, app, "/rename Manual title") {
			t.Fatal("/rename rejected")
		}
		close(release)
		turns.Wait()
		waitTitleBackgroundDone(t)
		final = readSessionFile(t, store.Path()).Metadata
		badge = badgeOnEventLoop(t, app)
	})()
	if err := StartTUI(context.Background(), titleResult(t, store, t.TempDir()), io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}

	if final.Title != "Manual title" || final.TitleSource != sessions.TitleSourceUser {
		t.Fatalf("title/source = %q/%q, want %q/%q (a manual rename must win over async generation)", final.Title, final.TitleSource, "Manual title", sessions.TitleSourceUser)
	}
	if !strings.Contains(badge, "Manual title") {
		t.Fatalf("badge = %q, want the manual title", badge)
	}
}

// TestTitleGen_ActiveStoreSwapDropsStaleTitle: a /clear while generation is in flight leaves
// the departed session's file byte-for-byte unchanged and the new session untitled.
func TestTitleGen_ActiveStoreSwapDropsStaleTitle(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()
	client, started, release := heldTitleClient("Generated title")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	var atSwitch, atCompletion string
	var fresh *sessions.Store
	var badge string
	defer runLiveApp(t, tcell.NewSimulationScreen("UTF-8"), func(app *tui.App) {
		if !submitOnEventLoop(t, app, "help me refactor login") {
			t.Fatal("plain prompt rejected")
		}
		<-started
		if !submitOnEventLoop(t, app, "/clear") {
			t.Fatal("/clear rejected")
		}
		fresh = app.ActiveStore()
		atSwitch = mustReadFile(t, store.Path())
		close(release)
		turns.Wait()
		waitTitleBackgroundDone(t)
		atCompletion = mustReadFile(t, store.Path())
		badge = badgeOnEventLoop(t, app)
	})()
	if err := StartTUI(context.Background(), titleResult(t, store, t.TempDir()), io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}

	if fresh == store {
		t.Fatal("/clear did not swap to a fresh active session")
	}
	if atCompletion != atSwitch {
		t.Fatalf("departed session file changed after the switch:\nat switch:\n%s\nat completion:\n%s", atSwitch, atCompletion)
	}
	if got := fresh.Title(); got != "" {
		t.Fatalf("new session title = %q, want empty (stale generation must be dropped)", got)
	}
	if strings.Contains(badge, "Generated title") {
		t.Fatalf("badge = %q, want no stale generated title", badge)
	}
}

// TestTitleGen_IneligibleBeforeWorkSkipsTitleRequest holds the event loop from before the hook
// schedules its background work until a /rename or /clear has run, so the source turns ineligible
// after the hook's first check but before generation starts.
func TestTitleGen_IneligibleBeforeWorkSkipsTitleRequest(t *testing.T) {
	cases := map[string]string{"rename": "/rename Manual title", "store switch": "/clear"}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			var titleRequests atomic.Int32
			client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
				if isTitleRequest(req) {
					titleRequests.Add(1)
					return titleCompletion("Generated title"), nil
				}
				return provider.Response{Stream: newStream(contentChunk("Hello"), finishChunk("stop"))}, nil
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			store := mkStore(t)
			var live *tui.App
			var turns sync.WaitGroup
			var calls atomic.Int32
			turnDone := make(chan struct{})
			var badgeAtChange, departedAtChange string
			var fresh *sessions.Store
			defer swapGoTurn(func(fn func()) {
				turns.Add(1)
				if calls.Add(1) == 1 {
					go func() { defer turns.Done(); defer close(turnDone); fn() }()
					return
				}
				go func() {
					defer turns.Done()
					<-turnDone
					held, scheduled := make(chan struct{}), make(chan struct{})
					go live.RunOnEventLoopForTest(func() {
						close(held)
						<-scheduled
						if !live.SubmitInput(cmd) {
							t.Errorf("%s rejected", cmd)
						}
						fresh = live.ActiveStore()
						badgeAtChange = live.SessionBadgeText()
						data, err := os.ReadFile(store.Path())
						if err != nil {
							t.Errorf("read departed session file: %v", err)
						}
						departedAtChange = string(data)
					})
					<-held
					fn()
					close(scheduled)
				}()
			})()

			var final sessions.Metadata
			var departedAfter, badge string
			defer runLiveApp(t, tcell.NewSimulationScreen("UTF-8"), func(app *tui.App) {
				live = app
				if !submitOnEventLoop(t, app, "help me refactor login") {
					t.Fatal("plain prompt rejected")
				}
				turns.Wait()
				waitTitleBackgroundDone(t)
				final = readSessionFile(t, store.Path()).Metadata
				departedAfter = mustReadFile(t, store.Path())
				badge = badgeOnEventLoop(t, app)
			})()
			if err := StartTUI(context.Background(), titleResult(t, store, t.TempDir()), io.Discard); err != nil {
				t.Fatalf("StartTUI error: %v", err)
			}

			if got := titleRequests.Load(); got != 0 {
				t.Fatalf("title requests = %d, want 0 once the source is ineligible before generation starts", got)
			}
			if badge != badgeAtChange {
				t.Fatalf("badge = %q, want it unchanged at %q", badge, badgeAtChange)
			}
			if cmd == "/clear" {
				if fresh == store {
					t.Fatal("/clear did not swap to a fresh active session")
				}
				if departedAfter != departedAtChange {
					t.Fatalf("departed session file changed after the switch:\nat switch:\n%s\nafter:\n%s", departedAtChange, departedAfter)
				}
				return
			}
			if final.Title != "Manual title" || final.TitleSource != sessions.TitleSourceUser {
				t.Fatalf("title/source = %q/%q, want %q/%q", final.Title, final.TitleSource, "Manual title", sessions.TitleSourceUser)
			}
		})
	}
}

func TestTitleGen_ShutdownBeforeCompletionWritesNothing(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()
	client, started, release := heldTitleClient("Generated title")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	var atShutdown, atCompletion string
	defer runLiveApp(t, tcell.NewSimulationScreen("UTF-8"), func(app *tui.App) {
		if !submitOnEventLoop(t, app, "help me refactor login") {
			t.Fatal("plain prompt rejected")
		}
		<-started
		app.BeginShutdown()
		atShutdown = mustReadFile(t, store.Path())
		close(release)
		turns.Wait()
		waitTitleBackgroundDone(t)
		atCompletion = mustReadFile(t, store.Path())
	})()
	if err := StartTUI(context.Background(), titleResult(t, store, t.TempDir()), io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}

	if atCompletion != atShutdown {
		t.Fatalf("session file changed after shutdown began:\nat shutdown:\n%s\nat completion:\n%s", atShutdown, atCompletion)
	}
	if got := readSessionFile(t, store.Path()).Metadata.Title; got != "help me refactor login" {
		t.Fatalf("title = %q, want the fallback kept after shutdown", got)
	}
}

func TestTitleOnComplete_InactiveStoreChangesNothing(t *testing.T) {
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return titleCompletion("Stale title"), nil
	}}
	active := mkStore(t)
	if _, _, err := active.FlushTitle(context.Background(), "Current session"); err != nil {
		t.Fatalf("seed active title: %v", err)
	}
	departed := mkStore(t)
	departed.Append(sessions.Message{Role: "user", Content: sessions.TextContent("hi"), Timestamp: testStart})
	mustFlush(t, departed)
	before := mustReadFile(t, departed.Path())

	app := tui.New(nil)
	app.SetActiveStore(active)
	badge := app.SessionBadgeText()
	sel := model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}
	newTitleOnComplete(app, nil)(context.Background(), client, sel, departed, "hi", "a plan")

	if got := client.callCount(); got != 0 {
		t.Fatalf("provider calls = %d, want 0 for an inactive store", got)
	}
	if app.ActiveStore() != active {
		t.Fatal("the hook changed the active store")
	}
	if got := app.SessionBadgeText(); got != badge {
		t.Fatalf("badge = %q, want it unchanged at %q", got, badge)
	}
	if after := mustReadFile(t, departed.Path()); after != before {
		t.Fatalf("departed session file changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestTitleGen_ChildSessionsKeepDerivedTitleOnContinuedTurns(t *testing.T) {
	forkedUser := sessions.Message{ID: "01890000-0000-7000-8000-0000000f0005", Role: "user", Content: sessions.TextContent("plan the work"), Timestamp: testStart, ParentID: childOriginRecordID}
	answer := sessions.Message{ID: "01890000-0000-7000-8000-0000000f0006", Role: "assistant", Content: sessions.TextContent("here is the plan"), Timestamp: testStart}
	cases := []struct {
		name    string
		title   string
		records []sessions.Record
	}{
		{"fork child", "Refactor plan (forked)", []sessions.Record{forkedUser, answer}},
		{"summary-only compact child", "Refactor plan (compacted)", []sessions.Record{
			sessions.Compaction{ID: "01890000-0000-7000-8000-0000000f0004", Summary: "the plan, summarized", Provider: "openai", ModelID: "gpt-5.5", Timestamp: testStart, ParentID: childOriginRecordID},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ran *tui.App
			defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()
			var turns sync.WaitGroup
			defer swapGoTurn(waitableGoTurn(&turns))()
			client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
				if isTitleRequest(req) {
					t.Errorf("unexpected title request for a child session")
				}
				return provider.Response{Stream: newStream(contentChunk("Hello"), finishChunk("stop"))}, nil
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			store := childStore(t, tc.title, tc.records...)
			if err := StartTUI(context.Background(), titleResult(t, store, t.TempDir()), io.Discard); err != nil {
				t.Fatalf("StartTUI error: %v", err)
			}
			if !ran.SubmitInput("now add tests") {
				t.Fatal("plain prompt rejected")
			}
			turns.Wait()

			if got := client.callCount(); got != 1 {
				t.Fatalf("provider calls = %d, want 1 (the streamed turn only)", got)
			}
			persisted := readSessionFile(t, store.Path()).Metadata
			if persisted.Title != tc.title || persisted.TitleSource != sessions.TitleSourceGenerated {
				t.Fatalf("title/source = %q/%q, want the derived %q/%q", persisted.Title, persisted.TitleSource, tc.title, sessions.TitleSourceGenerated)
			}
		})
	}
}

// TestTitleGen_NonTextFirstPromptSkips: an image/content-part first prompt is not a
// titleable first turn, so no title request is made and the session stays untitled.
func TestTitleGen_NonTextFirstPromptSkips(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if isTitleRequest(req) {
			t.Errorf("unexpected title request for a content-part first prompt")
		}
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	projectRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectRoot, "diagram.png"), []byte("\x89PNG\r\n\x1a\nDATA"), 0o644); err != nil {
		t.Fatalf("write image: %v", err)
	}
	store := mkStore(t)
	if err := StartTUI(context.Background(), titleResult(t, store, projectRoot), io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop")
	}

	if !ran.SubmitInput("look at this diagram.png") {
		t.Fatal("image prompt rejected; the wired attach path is broken")
	}
	turns.Wait()

	if !lastStoredUserMessage(t, store.Records()).Content.IsList() {
		t.Fatal("first user message is not a content-part list; the test premise is invalid")
	}
	if got := client.callCount(); got != 1 {
		t.Fatalf("provider calls = %d, want 1 (no title request for a non-text first prompt)", got)
	}
	if got := readSessionFile(t, store.Path()).Metadata.Title; got != "" {
		t.Fatalf("title = %q, want empty (a non-text first prompt is not titled)", got)
	}
}

func TestTitleOnCompletePassesRunScopedEffortLookup(t *testing.T) {
	sel := model.Selection{Provider: "openai", ID: "gpt-5.5-pro", Effort: model.EffortDefault}

	cases := []struct {
		name       string
		supported  []string
		wantEffort string
	}{
		{"run-scoped supports low", []string{provider.EffortLow}, provider.EffortLow},
		{"run-scoped omits low", []string{provider.EffortHigh}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got provider.Request
			client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
				got = req
				return titleCompletion("Some title"), nil
			}}

			store := mkStore(t)
			store.Append(sessions.Message{Role: "user", Content: sessions.TextContent("hi"), Timestamp: testStart})
			store.Append(sessions.Message{Role: "assistant", Content: sessions.TextContent("a plan"), Timestamp: testStart})

			app := tui.New(nil)
			app.SetActiveStore(store)

			var asked bool
			lookup := func(providerID, modelID string) []string {
				asked = true
				return tc.supported
			}
			newTitleOnComplete(app, lookup)(context.Background(), client, sel, store, "hi", "a plan")

			if !asked {
				t.Fatal("title hook never consulted the run-scoped supported-effort lookup")
			}
			if got.Effort != tc.wantEffort {
				t.Fatalf("title request Effort = %q, want %q", got.Effort, tc.wantEffort)
			}
		})
	}
}

// TestTitleGen_GeneratesAtMostOncePerSession: the first turn titles the session; a
// second turn in the same session makes no further title request and does not retitle.
func TestTitleGen_GeneratesAtMostOncePerSession(t *testing.T) {
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var titleCalls atomic.Int32
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if !isTitleRequest(req) {
			return provider.Response{Stream: newStream(contentChunk("Hello"), finishChunk("stop"))}, nil
		}
		titleCalls.Add(1)
		return titleCompletion("First title"), nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	if err := StartTUI(context.Background(), titleResult(t, store, t.TempDir()), io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop")
	}

	if !ran.SubmitInput("help me refactor login") {
		t.Fatal("first prompt rejected")
	}
	turns.Wait()
	if !ran.SubmitInput("and now add tests") {
		t.Fatal("second prompt rejected")
	}
	turns.Wait()

	if got := titleCalls.Load(); got != 1 {
		t.Fatalf("title requests = %d, want 1 (generation runs at most once per session)", got)
	}
	if got := readSessionFile(t, store.Path()).Metadata.Title; got != "First title" {
		t.Fatalf("title = %q, want %q (later turns must not retitle)", got, "First title")
	}
}
