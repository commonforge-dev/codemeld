package tui

import (
	"fmt"
	"slices"
	"strings"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

const (
	turnOutcomeCompleted   = "completed"
	turnOutcomeInterrupted = "interrupted"
	turnOutcomeTurnFailed  = "turn_failed"
)

const (
	queuedRowPrefix  = "queued: "
	sendingRowPrefix = "sending: "
	neverSentPrefix  = "not sent: "
	queuedPromptHint = "↑ to edit the newest queued prompt"
)

type queuedPrompt struct {
	text            string
	parts           []sessions.ContentPart
	draft           inputDraft
	store           *sessions.Store
	discardAppended bool
	sending         bool
}

type unsentBatch struct {
	store       *sessions.Store
	n, recorded int
	stale       bool
}

func (a *App) EnqueuePrompt(text string, parts ...sessions.ContentPart) {
	a.holdPrompt(text, parts, false)
}

func (a *App) SendingPrompt(text string, parts ...sessions.ContentPart) {
	a.holdPrompt(text, parts, true)
}

func (a *App) holdPrompt(text string, parts []sessions.ContentPart, sending bool) {
	if strings.TrimSpace(text) == "" && len(parts) == 0 {
		return
	}
	a.queued = append(a.queued, queuedPrompt{
		text:    text,
		parts:   append([]sessions.ContentPart(nil), parts...),
		draft:   a.input.snapshotDraft(),
		store:   a.ActiveStore(),
		sending: sending,
	})
	a.suppressNextEcho = true
	a.renderQueue()
}

func (a *App) HasQueuedPrompt() bool {
	if a.newestQueued() >= 0 {
		return true
	}
	a.unsentMu.Lock()
	defer a.unsentMu.Unlock()
	return slices.ContainsFunc(a.unsent, func(b *unsentBatch) bool { return b.n > 0 && !b.stale })
}

func (a *App) TurnEndPending() bool {
	a.unsentMu.Lock()
	defer a.unsentMu.Unlock()
	return slices.ContainsFunc(a.unsent, func(b *unsentBatch) bool { return !b.stale })
}

func (a *App) newestQueued() int {
	for i := len(a.queued) - 1; i >= 0; i-- {
		if !a.queued[i].sending {
			return i
		}
	}
	return -1
}

func (a *App) oldestSending(store *sessions.Store) int {
	for i, p := range a.queued {
		if p.sending && p.store == store {
			return i
		}
	}
	return -1
}

// UserMessageAdded stops waiting for the event loop once abort closes, because the
// loop may be blocked in a /clear or /resume that is waiting for this turn to drain.
func (a *App) UserMessageAdded(abort <-chan struct{}, store *sessions.Store, text string, parts []sessions.ContentPart) {
	f := func() {
		if i := a.oldestSending(store); i >= 0 {
			a.queued = slices.Delete(a.queued, i, i+1)
			a.renderQueue()
		}
		if store != a.ActiveStore() {
			return
		}
		a.invalidateStreamRender()
		a.transcript.finalize()
		a.transcript.append(userBlockLines(text, parts))
	}
	if a.stopping.Load() || !a.running.Load() {
		a.streamUpdate(f)
		return
	}
	done := make(chan struct{})
	go func() {
		a.app.QueueUpdateDraw(f)
		close(done)
	}()
	select {
	case <-done:
	case <-abort:
	}
}

func (a *App) UserMessagesUnsent(store *sessions.Store, n, recorded int, outcome string) func() {
	b := &unsentBatch{store: store, n: n, recorded: recorded}
	a.unsentMu.Lock()
	a.unsent = append(a.unsent, b)
	a.unsentMu.Unlock()
	return func() {
		a.streamUpdate(func() {
			a.unsentMu.Lock()
			a.unsent = slices.DeleteFunc(a.unsent, func(p *unsentBatch) bool { return p == b })
			stale := b.stale
			a.unsentMu.Unlock()
			if stale {
				return
			}
			a.applyUnsent(b)
			a.renderQueue()
			a.turnEnded(outcome)
		})
	}
}

func (a *App) TurnEnded(outcome string) {
	a.streamUpdate(func() { a.turnEnded(outcome) })
}

// applyUnsent flips the newest sending rows because, after a drain, older sending
// rows can be messages the turn already added whose update has not run yet.
func (a *App) applyUnsent(b *unsentBatch) {
	var rows []int
	for i := len(a.queued) - 1; i >= 0 && len(rows) < b.n; i-- {
		if a.queued[i].sending && a.queued[i].store == b.store {
			rows = append(rows, i)
		}
	}
	slices.Reverse(rows)
	for k, i := range rows {
		a.queued[i].sending = false
		a.queued[i].discardAppended = k < b.recorded
	}
}

func (a *App) DiscardHeldPrompts() {
	store := a.ActiveStore()
	a.unsentMu.Lock()
	for _, b := range a.unsent {
		if !b.stale {
			a.applyUnsent(b)
			b.stale = true
		}
	}
	a.unsentMu.Unlock()
	if len(a.queued) == 0 {
		return
	}
	kept := a.queued[:0]
	for _, p := range a.queued {
		if p.store != store {
			kept = append(kept, p)
			continue
		}
		if p.sending || p.discardAppended {
			continue
		}
		if _, err := events.Append(store, events.QueuedPromptDiscarded{
			Text:       p.text,
			ImageCount: int64(len(p.parts)),
			Reason:     turnOutcomeInterrupted,
		}); err != nil {
			a.Notice(fmt.Sprintf("could not record the discarded queued prompt: %v", err))
		}
	}
	a.queued = kept
	a.renderQueue()
}

func (a *App) turnEnded(outcome string) {
	if len(a.queued) == 0 {
		return
	}
	if outcome == turnOutcomeCompleted {
		a.dispatchQueuedFront()
		return
	}
	a.discardQueued(outcome)
}

func (a *App) dispatchQueuedFront() {
	if a.submit == nil {
		return
	}
	front := a.queued[0]
	a.suppressNextEcho = false
	accepted := a.submit(front.text, front.parts...)
	suppress := a.suppressNextEcho
	a.suppressNextEcho = false
	if !accepted {
		return
	}
	a.queued = a.queued[1:]
	a.renderQueue()
	if !suppress {
		a.transcript.append(userBlockLines(front.text, front.parts))
	}
}

func (a *App) discardQueued(reason string) {
	for len(a.queued) > 0 {
		p := a.queued[0]
		var err error
		if !p.discardAppended {
			_, err = events.Append(a.ActiveStore(), events.QueuedPromptDiscarded{
				Text:       p.text,
				ImageCount: int64(len(p.parts)),
				Reason:     reason,
			})
			if err == nil {
				a.queued[0].discardAppended = true
			}
		}
		if err == nil {
			err = a.FlushActive()
		}
		if err != nil {
			a.Notice(fmt.Sprintf("could not record the discarded queued prompt: %v", err))
			break
		}
		a.queued = a.queued[1:]
		a.Append(neverSentPrefix + queuedPromptSummary(p))
	}
	a.renderQueue()
}

func (a *App) recallQueuedPrompt() bool {
	last := a.newestQueued()
	if last < 0 || a.input.GetText() != "" {
		return false
	}
	p := a.queued[last]
	a.queued = slices.Delete(a.queued, last, last+1)
	a.input.restoreDraft(p.draft)
	a.renderQueue()
	return true
}

func (a *App) renderQueue() {
	rows := make([]string, len(a.queued))
	for i, p := range a.queued {
		prefix := queuedRowPrefix
		if p.sending {
			prefix = sendingRowPrefix
		}
		rows[i] = prefix + queuedPromptSummary(p)
	}
	a.queueRows.SetText(strings.Join(rows, "\n"))
	a.root.ResizeItem(a.queueRows, len(a.queued), 0)
	hint := ""
	if a.newestQueued() >= 0 {
		hint = queuedPromptHint
	}
	a.input.setQueueHint(hint)
}

func queuedPromptSummary(p queuedPrompt) string {
	summary := strings.Join(strings.Fields(p.text), " ")
	if len(p.parts) == 0 {
		return summary
	}
	images := fmt.Sprintf("[%d images]", len(p.parts))
	if len(p.parts) == 1 {
		images = "[1 image]"
	}
	if summary == "" {
		return images
	}
	return summary + " " + images
}
