package tui

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/sessions"
)

// Append adds one line to the transcript pane, escaping it so any "[...]" in the
// text renders literally rather than being parsed as a tview style tag now that
// the transcript has dynamic colors enabled. All ordinary callers
// (command output, model-picker disclosure) go through here; the launch banner is
// the one intentional styled producer and uses AppendBanner instead.
func (a *App) Append(line string) {
	a.transcript.append(tview.Escape(line))
}

// AppendStyled adds one pre-styled line to the transcript without escaping, so
// intentional tview style/color tags are parsed by dynamic colors — e.g. the launch
// banner's "[::b]…[::-]" bold. (Mode switches no longer append here: their colored
// hint renders into the persistent mode-hint row instead.) It is the single raw
// append seam: callers must pass only controlled,
// non-user text (a closed set of literals), since nothing here escapes "[...]"
// against style-tag injection; every other transcript string is escaped via Append.
func (a *App) AppendStyled(line string) {
	a.transcript.append(line)
}

// LaunchBannerBar renders the launch banner's name line as a teal-filled bar:
// "◆ codemeld" in bold white, then "<version>" immediately after it in a
// dim, non-bold teal-tinted white (bannerVersionText) so the version is easy to find next to
// the wordmark instead of being lost at the right edge on a wide terminal; the remainder of
// the row is padded with spaces so the teal fill still spans the full terminal width. The
// fills paint a background — the chrome exception scoped to chrome (see colors.go).
// width is the terminal width at append time; the bar is not re-filled on a later resize
// (acceptable for launch-only branding, since the banner scrolls away as the
// conversation grows). The version is tview.Escape'd defensively, though it is a build
// constant. A width too small to hold the wordmark + version keeps them adjacent with no
// trailing pad. The caller passes the result as the first AppendBanner line; the bg/fg/bold
// tags are live markup that AppendBanner's raw styled-append seam renders.
func LaunchBannerBar(version string, width int) string {
	wordmark := "◆ codemeld"
	ver := tview.Escape(version)
	// wordmark + one space + version sit together at the left; the rest of the row is pad
	// so the teal fill reaches the terminal edge.
	pad := width - tview.TaggedStringWidth(wordmark) - 1 - tview.TaggedStringWidth(ver)
	if pad < 0 {
		pad = 0
	}
	return fmt.Sprintf("[%s:%s:b]%s [%s:%s:-]%s%s[-:-:-]",
		chromeOnFillText, accentTealHex, wordmark,
		bannerVersionText, accentTealHex, ver,
		strings.Repeat(" ", pad))
}

// LaunchBannerMeta renders the launch banner's metadata subtitle as the single line under
// the teal name bar: the active provider · model · effort · launch-dir segments
// joined by " · ", each in a fixed cool blue-grey that lightens left→right (bannerMeta* in
// colors.go) so the line reads as one dim secondary ramp matching the design sample rather
// than a flat run. When no model is selected (model == ""), provider and effort are empty,
// so the line collapses to "no model selected · <dir>". Every segment value is tview.Escape'd
// because the banner is appended through the raw AppendStyled seam (AppendBanner): only the
// color tags are intentional markup, so a path or model id carrying "[tag]"-like text must
// render literally. The caller passes the result as a banner line; the fg tags are
// live markup that AppendBanner's styled-append seam renders.
func LaunchBannerMeta(provider, model, effort, dir string) string {
	seg := func(color, text string) string {
		return fmt.Sprintf("[%s]%s[-]", color, tview.Escape(permissions.SingleLineControlEscape(text)))
	}
	sep := fmt.Sprintf("[%s] · [-]", bannerMetaSeparator)

	var parts []string
	if model == "" {
		parts = append(parts, seg(bannerMetaModel, "no model selected"))
	} else {
		parts = append(parts,
			seg(bannerMetaProvider, provider),
			seg(bannerMetaModel, model),
			seg(bannerMetaEffort, effort+" effort"),
		)
	}
	parts = append(parts, seg(bannerMetaDir, dir))
	return strings.Join(parts, sep)
}

// AppendBanner adds the launch banner as one multi-line transcript block through the raw
// styled-append seam (AppendStyled): the banner's intentional tags are parsed by dynamic
// colors — the teal-filled name bar's "[fg:bg:b]…[-:-:-]" fill (LaunchBannerBar) and
// any styling on the remaining lines. The banner's display lines are joined with a single
// newline and committed as one entry so they stay adjacent — the transcript's block
// separator (one blank line) is inserted only between entries, never inside this one,
// keeping the banner a tight header. Used by the bootstrap banner (StartTUI and /clear's
// transcript reset).
func (a *App) AppendBanner(lines ...string) {
	a.AppendStyled(strings.Join(lines, "\n"))
}

// Notice shows a one-line user-facing notice beneath the transcript. It is for
// callers already running on the tview event-loop goroutine; off-loop callers
// must use NoticeFromBackground.
func (a *App) Notice(text string) {
	a.noticeSeq.Add(1)
	a.invalidateStreamRender()
	a.transcript.setNotice(text)
}

// NoticeFromBackground shows a one-line notice from an off-event-loop caller,
// marshaling the transcript mutation through the tview queue while Run is active.
func (a *App) NoticeFromBackground(text string) {
	a.streamUpdate(func() { a.Notice(text) })
}

func (a *App) RunBackgroundAfterDraw(work func() error, complete func(error)) {
	if a.stopping.Load() {
		return
	}
	if !a.running.Load() {
		complete(work())
		return
	}
	go func() {
		a.streamUpdate(func() {})
		if a.stopping.Load() {
			return
		}
		err := work()
		a.streamUpdate(func() {
			if a.stopping.Load() {
				return
			}
			complete(err)
		})
	}()
}

// SetScreenFactoryForTest replaces the screen constructor Run uses, so a test can
// start the real app lifecycle against a simulation screen instead of a terminal.
// Test-only; it must be called before Run.
func (a *App) SetScreenFactoryForTest(factory func() (tcell.Screen, error)) {
	a.newScreen = factory
}

// RunOnEventLoopForTest runs fn on the tview event-loop goroutine and waits for the
// redraw, so a test driving a running app can touch shared tview state without
// racing the draw loop. Test-only; it deadlocks if called from the loop goroutine.
func (a *App) RunOnEventLoopForTest(fn func()) {
	a.app.QueueUpdateDraw(fn)
}

// CommitProviderError commits a provider/turn request failure as a permanent
// in-place transcript line (escaped) tied to the turn that produced it, so the
// error scrolls with history rather than re-pinning below later turns the way the
// single bottom notice did. The provider-turn runtime calls it off
// the tview event-loop goroutine, so it marshals through the tview queue while Run
// is active and mutates directly before Run — exactly like AppendStreamDelta,
// FinalizeStream, and NoticeFromBackground. Ordering is preserved automatically:
// committing appends after whatever finalize/markInterrupted already sealed (a
// pre-stream failure lands after the submitted prompt; a post-seal failure after
// the sealed turn output).
func (a *App) CommitProviderError(text string) {
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.commitError(text)
	})
}

// ClearNotice clears the one-line transient notice without touching committed
// transcript history. submitCurrent calls it as a new submission is accepted, and
// the model-change paths (the CTRL-M/picker confirm and /model) call it on a
// successful apply, so a prior turn's notice cannot linger pinned below later
// output. It is for callers on the tview event-loop goroutine (like Notice);
// it never affects committed lines (t.lines).
func (a *App) ClearNotice() {
	a.invalidateStreamRender()
	a.transcript.clearNotice()
}

// SetActiveStore installs s as the session the app records into. The production
// bootstrap sets it once before Run, and /clear's session swap (SessionSwapper)
// replaces it with the fresh same-folder store so subsequent commands and the
// exit hint observe the new session.
func (a *App) SetActiveStore(s *sessions.Store) {
	a.activeMu.Lock()
	a.activeStore = s
	a.activeMu.Unlock()
	a.RefreshSessionBadge(s)
}

// ActiveStore returns the session store the app is currently recording into,
// reflecting any /clear swap. It may be nil before SetActiveStore is called.
func (a *App) ActiveStore() *sessions.Store {
	a.activeMu.Lock()
	defer a.activeMu.Unlock()
	return a.activeStore
}

// Store satisfies CommandHost: dispatch appends each command's slash_command
// event to whichever session is active at invocation time, which is exactly the
// active-store reference ActiveStore returns.
func (a *App) Store() *sessions.Store { return a.ActiveStore() }

// SetCommandFlush installs the command-event flush hook bootstrap
// builds over the active session + sessionfailures. It is set once before Run,
// alongside SetActiveStore and SetSubmit.
func (a *App) SetCommandFlush(fn func() error) { a.commandFlush = fn }

// FlushActive satisfies CommandHost: it runs the injected command-event flush
// hook so a /status, /help, or placeholder command makes its slash_command record
// durable. With no hook installed (unit tests) it is a no-op.
func (a *App) FlushActive() error {
	if a.commandFlush == nil {
		return nil
	}
	return a.commandFlush()
}

// SetStreamCanceller installs the provider-turn cancellation handle the ESC /
// CTRL-C handlers reach to abort an in-flight streamed reply. The
// production handle is injected by the turn wiring; with none installed
// StreamCanceller returns nil and the surface stays inert (nothing to cancel).
// It is set once before Run, alongside the other injected hooks.
func (a *App) SetStreamCanceller(c StreamCanceller) { a.streamCanceller = c }

// StreamCanceller returns the installed cancellation handle so the ESC / CTRL-C
// key handlers can call Cancel() on it. It is nil until
// SetStreamCanceller is called (and in unit tests), where the caller treats the
// stream surface as inert and cancels nothing.
func (a *App) StreamCanceller() StreamCanceller { return a.streamCanceller }

// AppendStreamDelta accumulates one incremental chunk of the in-progress assistant
// reply. While Run is active the mutation is marshaled through the tview queue
// without a draw and a single timer renders the accumulated text; before Run it
// renders on arrival. It returns once the delta has been applied but, unlike the
// per-delta render it replaces, not once it has been drawn. Like PromptUser it must
// not be called from a tview event-loop callback while the loop is running.
func (a *App) AppendStreamDelta(delta string) {
	if a.stopping.Load() {
		return
	}
	if !a.running.Load() {
		a.transcript.appendDelta(delta)
		return
	}
	a.app.QueueUpdate(func() {
		if a.stopping.Load() {
			return
		}
		a.transcript.bufferDelta(delta)
		a.armStreamRender()
	})
}

const streamRenderInterval = 50 * time.Millisecond

func (a *App) armStreamRender() {
	if a.streamRenderPending {
		return
	}
	a.streamRenderPending = true
	gen := a.streamRenderGen
	a.afterFunc(streamRenderInterval, func() {
		if a.stopping.Load() || !a.running.Load() {
			return
		}
		// Not QueueUpdateDraw: a callback invalidated by a boundary still runs, and
		// QueueUpdateDraw would draw after it even though the generation check made
		// it a no-op. Only a current callback renders, and it draws explicitly.
		a.app.QueueUpdate(func() {
			if a.stopping.Load() || a.streamRenderGen != gen {
				return
			}
			a.streamRenderPending = false
			a.transcript.render()
			if a.draw != nil {
				a.draw()
			}
		})
	})
}

func (a *App) invalidateStreamRender() {
	a.streamRenderPending = false
	a.streamRenderGen++
}

// MarkStreamInterrupted closes the in-progress assistant reply with the
// interrupted marker (a no-op when no reply is streaming), so a cancelled stream
// is sealed as interrupted. It is the cross-package finalizer the provider-turn
// runtime calls when it observes the cancellation, and like
// AppendStreamDelta it marshals through the tview queue while Run is active and so
// must be driven off the event-loop goroutine. It also hides the in-flight
// indicator on the same off-loop path (idempotent with the turnController.run
// backstop) so the indicator never outlives the sealed stream.
func (a *App) MarkStreamInterrupted() {
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.markInterrupted()
	})
	a.ClearIndicator()
}

// SecurityHalt seals any partial reply as interrupted output and pins the persistent
// protected-settings halt element beneath the transcript. Like MarkStreamInterrupted it must
// be driven off the event-loop goroutine; unlike it, the seal records nothing, so a security
// halt never writes a stream_interrupted event.
func (a *App) SecurityHalt(records []events.SecurityStateHalted) {
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.setSecurityHalt(records)
	})
	a.ClearIndicator()
}

// MarkStreamInterruptedFromCommand seals a slash-command-cancelled stream from a
// command handler that is already running on the tview event-loop goroutine, and
// hides the in-flight indicator on that same loop path so /clear and /resume
// drop the indicator as soon as they record the interruption.
func (a *App) MarkStreamInterruptedFromCommand() {
	a.invalidateStreamRender()
	a.transcript.markInterrupted()
	a.clearIndicatorDirect()
}

// ResetTranscript wipes the transcript pane — committed lines, any in-progress
// streamed line, and the notice — re-renders it empty, and suppresses the single
// accepted-submit echo submitCurrent would otherwise append for the command that
// triggered the reset. /clear calls it (through the injected ClearDeps.Transcript
// capability) after the session swap commits, so the fresh same-folder session opens
// on a blank pane instead of the prior conversation and without a leftover "> /clear"
// line (visible-screen reset). It is called from the command handler, which
// runs on the tview event-loop goroutine, so it mutates the view directly like
// MarkStreamInterruptedFromCommand rather than marshaling through QueueUpdateDraw
// (which would deadlock the loop from inside a handler).
func (a *App) ResetTranscript() {
	a.invalidateStreamRender()
	a.transcript.reset()
	a.suppressNextEcho = true
}

// FinalizeStream closes a naturally completed streamed assistant reply,
// committing the in-progress line into the transcript (a no-op when no reply is
// streaming) so the next streamed reply starts a fresh buffer instead of merging
// onto the completed one. It is the cross-package finalizer the provider-turn
// runtime calls when a turn ends without cancellation, and like
// AppendStreamDelta it marshals through the tview queue while Run is active and so
// must be driven off the event-loop goroutine.
func (a *App) FinalizeStream() {
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.finalize()
	})
}

// AppendToolActivity renders one tool-call round's about-to-run calls inline in the
// transcript, just before the calls are dispatched, so a multi-step turn shows
// what is about to run (e.g. "Edit path", "Run: go build") instead of going silent. It
// first finalizes any in-progress assistant reply so the model's pre-tool text commits
// above the activity block, then appends the escaped lines as one transcript entry. Like
// the other stream-surface methods it is the cross-package entry point the provider-turn
// runtime calls off the tview event-loop goroutine, so it marshals through
// streamUpdate while Run is active and mutates directly before Run. Tool activity is
// display-only and never recorded.
func (a *App) AppendToolActivity(lines []string) {
	if len(lines) == 0 {
		return
	}
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.finalize()
		a.transcript.appendToolActivity(lines)
	})
}

func (a *App) AppendEditPatch(patch string) {
	if patch == "" {
		return
	}
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.finalize()
		a.transcript.appendEditPatch(patch)
	})
}

// ChildAgentStarted, ChildAgentCalls, and ChildAgentEnded are the live child-agent surface
// the delegate tool drives from the child's own goroutine, so — like AppendToolActivity —
// they marshal through streamUpdate while Run is active and mutate directly before it. The
// block is display-only: the durable record is the child_agent_start/end pair the delegate
// already appends.
func (a *App) ChildAgentStarted(start events.ChildAgentStart) {
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.finalize()
		a.transcript.openChildAgent(start)
	})
}

func (a *App) ChildAgentCalls(invocation string, lines []string) {
	if len(lines) == 0 {
		return
	}
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.updateChildAgent(invocation, lines)
	})
}

func (a *App) ChildAgentEnded(end events.ChildAgentEnd) {
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.closeChildAgent(end)
	})
}

// RollbackPartial removes the un-sealed in-progress reply before a
// discard-and-restart retry of a partial stream_drop, so the regenerated answer
// does not stack on the discarded partial. It is the cross-package surface seam the
// provider-turn runtime calls off the tview event-loop goroutine before
// re-issuing (turndeps.go binds it onto turn.Deps).
func (a *App) RollbackPartial() {
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.rollbackPartial()
	})
}

// CommitRetryRecovered commits a faint transcript breadcrumb after an auto-retry
// succeeds, so the user can see that a transient provider hiccup recovered without
// reading provider_request_retry events. It is called off the event-loop goroutine.
func (a *App) CommitRetryRecovered(retries int) {
	a.streamUpdate(func() { a.transcript.commitRetryRecovered(retries) })
}

// SuggestFollowup receives an intercepted suggest_followup tool call: label is
// the imperative the agent proposes and prompt is the text to prefill when the user
// accepts with Tab. It is the cross-package surface seam the provider-turn runtime calls
// when the tool loop intercepts the call (turndeps.go binds it onto turn.Deps).
//
// It stores prompt as the pending acceptance and shows label as dim ghost text in the
// empty input. The tool loop runs off the tview event-loop goroutine, so — like the
// other provider-runtime surface methods — it marshals the widget mutation through
// streamUpdate: QueueUpdateDraw while the loop is running (so the ghost text is drawn), or
// a direct mutation before Run / in unit tests where the queue is never drained. The next
// buffer change clears both the ghost text and the pending prompt (onInputChanged), so the
// suggestion never survives typing or submit.
func (a *App) SuggestFollowup(label, prompt string) {
	a.streamUpdate(func() {
		// record that the surface was reached and with what lengths, before any
		// accept/reject decision, so the trace shows the suggestion arrived at the UI.
		labelLen := utf8.RuneCountInString(label)
		promptLen := utf8.RuneCountInString(prompt)
		a.emitFollowupDebug(events.SuggestFollowupStageSurfaceCalled, "", labelLen, promptLen)
		// A schema-valid call can still carry a blank label or prompt (both are only
		// typed as required strings — internal/provider/tooldefs.go). pendingFollowup ==
		// "" is handleInputKey's sentinel for "nothing pending", so an empty prompt would
		// render a ⇥ Tab ghost that Tab can never accept or clear. Reject either
		// blank field: drop any prior pending suggestion and show no cue. resetPendingFollowup
		// clears without logging, then the explicit ghost_cleared below records the drop.
		if strings.TrimSpace(label) == "" || strings.TrimSpace(prompt) == "" {
			a.resetPendingFollowup()
			a.emitFollowupDebug(events.SuggestFollowupStageGhostCleared, "blank_fields", labelLen, promptLen)
			return
		}
		// The ghost cue only paints over an empty buffer, but pendingFollowup would still
		// arm Tab. handleInputKey accepts any non-empty pendingFollowup before slash
		// completion (app.go:1154), so arming it behind a non-empty draft would let Tab
		// silently replace the user's in-progress text with the hidden prompt instead of
		// completing it. Offer the suggestion only in the empty input: drop it
		// otherwise so Tab keeps its existing behavior for the draft.
		if a.input.GetText() != "" {
			a.resetPendingFollowup()
			a.emitFollowupDebug(events.SuggestFollowupStageGhostCleared, "input_occupied", labelLen, promptLen)
			return
		}
		a.pendingFollowup = prompt
		a.input.SetGhostText(label)
		a.emitFollowupDebug(events.SuggestFollowupStageGhostSet, "", labelLen, promptLen)
	})
}

// streamUpdate applies a transcript mutation safely for the off-event-loop
// provider-runtime callers. While the event loop is running the mutation is
// queued through QueueUpdateDraw (serialized with the draw loop, then redrawn);
// before Run — unit tests and pre-Run wiring — the queue is never drained, so the
// mutation runs directly rather than blocking forever on an undrained queue.
//
// Once shutdown has begun the mutation is dropped rather than queued, matching
// AppendStreamDelta: the shutdown sequence blocks the event-loop goroutine while it
// drains the cancelled turn, so a queued mutation from that draining turn would wait
// on a loop that is itself waiting on the turn.
func (a *App) streamUpdate(f func()) {
	if a.stopping.Load() {
		return
	}
	if a.running.Load() {
		a.app.QueueUpdateDraw(f)
		return
	}
	f()
}
