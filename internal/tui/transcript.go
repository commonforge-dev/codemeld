// Transcript pane: the ordered lines and one-line notice rendered above input.
package tui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
)

// streamInterruptedMarker is the suffix appended to a streamed assistant
// message that markInterrupted closes, so a cancelled (ESC/CTRL-C) reply renders
// with a stable, asserted form that distinguishes it from a completed reply.
const streamInterruptedMarker = " [interrupted]"

const retryBreadcrumbPrefix = "· recovered after "

const responseCopyControl = "[Copy response]"

// appendResponseControl closes a sealed assistant block with its own copy control over
// payload, the renderer's display projection of that one response. Only the sealing paths
// (finalize, markInterrupted, and replay) may call it: a live reply is still growing, so
// arming its control would expose a payload the next delta changes.
func appendResponseControl(rendered string, controls []codeControl, payload string) (string, []codeControl) {
	if len(controls) == 1 {
		inner, closed := strings.CutSuffix(controls[0].body, "\n")
		if closed && strings.TrimSpace(inner[strings.LastIndex(inner, "\n")+1:]) != "" && inner == payload {
			return rendered, controls
		}
	}
	line := strings.Count(rendered, "\n") + 1
	rendered += "\n" + codeControlIndent + statusCopyControlTag + tview.Escape(responseCopyControl) + defaultTag + underlineOffTag
	return rendered, append(controls, codeControl{line: line, body: payload, response: true})
}

// transcript holds the ordered transcript lines, an optional in-progress
// streamed assistant message, and an optional one-line notice, rendering them
// into a tview.TextView. It keeps its own state so the app's state transitions
// can be asserted in tests without a terminal screen.
type transcript struct {
	mu     sync.Mutex
	view   *transcriptView
	lines  []string
	notice string

	// securityHalt is the protected-settings halt element, kept separate from notice
	// because clearNotice, a new submission, and a model change all clear the transient
	// notice. Nothing clears this one — including reset: a halt is terminal, and the
	// settings on disk stay drifted across a transcript wipe.
	securityHalt string

	// codeControls parallels lines: entry i holds, in document order, the generated copy
	// controls of block i, each carrying its line within that block's own rendered text.
	// Both slices must stay the same length, so every commit goes through commitLocked.
	codeControls [][]codeControl

	// childAgents indexes each child-agent block by its invocation id, which is the only
	// thing that routes a child's activity to its block — overlapping children would
	// otherwise mix. An entry stays after its block closes, so a payload arriving after its
	// own end record is dropped instead of reopening the block or landing in another one.
	childAgents map[string]*childAgentBlock

	// controls are the click regions valid only for the text the last renderLocked
	// installed; it rebuilds them because SetText makes the prior render's offsets stale.
	controls clickRegions

	// streaming reports whether an in-progress assistant message buffer is open;
	// streamBuf is its accumulated delta text. While open the buffer renders as a
	// live block below the committed transcript and above the notice; finalize and
	// markInterrupted commit it into lines and close the buffer. streamBuf is kept
	// raw (unescaped) so the live render can split it into completed markdown blocks
	// (rendered through renderMarkdown) plus a still-growing trailing fragment (held
	// tview.Escape'd) — keeping the source raw lets escaping span the whole accumulated
	// reply, so a tag split across two deltas (e.g. "[re" then "d]" reassembling into
	// "[red]") cannot leak a live tag, and lets finalize re-render the full buffer.
	streaming bool
	streamBuf string

	countWidth int

	// following reports whether the view auto-scrolls to the newest output.
	// It starts true so a fresh transcript pins the bottom like before. While true,
	// renderLocked calls ScrollToEnd so streamed deltas/appends/notices keep the
	// latest line visible; once the user scrolls up (scrollBy) it goes false and
	// renderLocked instead restores the saved offset, so new output no longer yanks
	// the view down. A downward scroll that reaches the last row flips it back true.
	following bool

	// App-owned mouse selection state. selecting reports whether a plain
	// left-button drag is currently in progress; selStart/selEnd are the ordered
	// byte offsets of the selected range into the *stripped* displayed text
	// (GetText(true)); selAnchor is the byte offset the drag began at, so dragging
	// back past the anchor reverses the range. selStart == selEnd means no selection
	// is highlighted. The range survives scrolling (offsets are absolute into the
	// displayed text, and drawSelectionHighlight re-projects them through the live
	// scroll offset) but is cleared whenever the displayed text changes, so a stale
	// highlight can never land on shifted content. All fields are read/written only
	// on the tview event-loop goroutine (the mouse capture and Draw), but are guarded
	// by mu alongside the rest of the transcript state.
	selecting bool
	selAnchor int
	selStart  int
	selEnd    int
}

func newTranscript() *transcript {
	t := &transcript{following: true}
	// view wraps tview.TextView so its Draw can overlay the app-owned selection
	// highlight after the text is drawn, without changing the committed lines.
	t.view = &transcriptView{TextView: tview.NewTextView(), paint: tview.NewTextView(), owner: t}
	// Dynamic colors let the launch banner render its name in bold. Every
	// non-banner string appended to the transcript is therefore escaped (user echo
	// at the submitCurrent call site, streamed deltas and notices here) so user or
	// model text containing "[...]" renders literally and cannot inject styling.
	t.view.SetDynamicColors(true)
	t.view.paint.SetDynamicColors(true)
	return t
}

// reset wipes all transcript state — the committed lines, any in-progress streamed
// message, and the one-line notice — and re-renders the now-empty view. It backs
// clear's visible-screen reset: the fresh same-folder session must start
// on a blank pane rather than the prior conversation. Like every other mutation it
// takes the transcript mutex before touching state.
func (t *transcript) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lines, t.codeControls = nil, nil
	t.childAgents = nil
	t.streamBuf = ""
	t.streaming = false
	t.notice = ""
	// A wiped pane has nothing earlier to read, so resume auto-follow: the fresh
	// same-folder session (/clear) must open pinned to the bottom.
	t.following = true
	t.renderLocked()
}

// append adds one line to the transcript and re-renders the view.
func (t *transcript) append(line string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.commitLocked(line, nil)
	t.renderLocked()
}

// commitLocked is the single seam that appends a committed block, so its fenced-block
// bodies stay index-aligned with it.
func (t *transcript) commitLocked(line string, controls []codeControl) {
	t.lines = append(t.lines, line)
	t.codeControls = append(t.codeControls, controls)
}

// replayBlock is one already-rendered transcript block plus the copy controls the
// renderer generated inside it.
type replayBlock struct {
	text     string
	controls []codeControl
}

// replayBlocks appends already-rendered transcript blocks in order, keeping only the
// most recent maxBlocks of them and prepending a single escaped omission marker when
// older blocks are dropped, then re-renders once (/resume replay). Each block is
// committed verbatim into t.lines exactly as the live paths store theirs — a user echo
// is pre-escaped and an assistant reply has already been through renderMarkdown — so
// the producer (replaySessionBlocks) owns escaping/markdown and this primitive only
// bounds and commits. maxBlocks <= 0 drops every block but still emits the marker, so a
// degenerate cap cannot silently render a partial history as if it were complete.
func (t *transcript) replayBlocks(blocks []replayBlock, maxBlocks int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if maxBlocks < 0 {
		maxBlocks = 0
	}
	if len(blocks) > maxBlocks {
		dropped := len(blocks) - maxBlocks
		blocks = blocks[dropped:]
		t.commitLocked(tview.Escape(replayOmissionMarker(dropped)), nil)
	}
	for _, block := range blocks {
		t.commitLocked(block.text, block.controls)
	}
	t.renderLocked()
}

// setNotice replaces the current one-line notice and re-renders the view. The
// text is escaped because notices carry user- or environment-derived strings
// (errors, hints, paths) that must not be parsed as style tags now that the
// transcript view has dynamic colors enabled.
func (t *transcript) setNotice(text string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.notice = tview.Escape(text)
	t.renderLocked()
}

// clearNotice clears the one-line transient notice and re-renders, leaving the
// committed lines and any in-progress stream untouched. It backs the
// clear-on-new-turn / clear-on-model-change so a stale pinned notice cannot
// re-render below later output, while committed history (t.lines) is preserved.
func (t *transcript) clearNotice() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.notice = ""
	t.renderLocked()
}

// commitError appends an error as a permanent transcript line — committed into
// t.lines like append/finalize do — so a provider/turn failure scrolls with
// history tied to the turn that produced it, instead of re-rendering as the single
// bottom-pinned notice did on every later draw. The text is escaped on the
// way in (like finalize/markInterrupted) because it carries provider JSON and
// "[...]" sequences that must render literally under the transcript's dynamic
// colors. The block separator places it as its own block, one blank
// line below the prior turn output.
func (t *transcript) commitError(text string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.commitLocked(tview.Escape(text), nil)
	t.renderLocked()
}

// appendToolActivity commits one tool-call round's activity lines as a single
// permanent transcript block. Each line is escaped on the way in — they carry
// file paths and shell commands whose "[...]" must render literally under the
// transcript's dynamic colors, never as a style tag — and the escaped lines are
// joined with newlines so the whole round renders as one block, not one
// blank-gapped entry per call (the block separator only goes between entries).
// Tool activity is display-only and never recorded.
func (t *transcript) appendToolActivity(lines []string) {
	if len(lines) == 0 {
		return
	}
	escaped := make([]string, len(lines))
	for i, line := range lines {
		escaped[i] = tview.Escape(line)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.commitLocked(strings.Join(escaped, "\n"), nil)
	t.renderLocked()
}

func (t *transcript) appendEditPatch(patch string) {
	body := strings.TrimRight(patch, "\n")
	if body == "" {
		return
	}
	rendered := renderPatchBody(body)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.commitLocked(rendered, nil)
	t.renderLocked()
}

// childAgentBlock is one child agent's transcript block. index is its position in t.lines,
// which stays valid because commitLocked only appends and reset clears both together.
type childAgentBlock struct {
	index int
	start events.ChildAgentStart
	calls []string
	end   *events.ChildAgentEnd
}

func (t *transcript) openChildAgent(start events.ChildAgentStart) {
	if start.InvocationID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, open := t.childAgents[start.InvocationID]; open {
		return
	}
	if t.childAgents == nil {
		t.childAgents = make(map[string]*childAgentBlock)
	}
	block := &childAgentBlock{index: len(t.lines), start: start}
	t.childAgents[start.InvocationID] = block
	t.commitLocked(childAgentBlockText(block.start, block.calls, block.end, true), nil)
	t.renderLocked()
}

func (t *transcript) updateChildAgent(invocation string, lines []string) {
	if len(lines) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	block, open := t.childAgents[invocation]
	if !open || block.end != nil {
		return
	}
	block.calls = append(block.calls, lines...)
	t.lines[block.index] = childAgentBlockText(block.start, block.calls, block.end, true)
	t.renderLocked()
}

func (t *transcript) closeChildAgent(end events.ChildAgentEnd) {
	t.mu.Lock()
	defer t.mu.Unlock()
	block, open := t.childAgents[end.InvocationID]
	if !open || block.end != nil {
		return
	}
	block.end = &end
	t.lines[block.index] = childAgentBlockText(block.start, block.calls, block.end, false)
	t.renderLocked()
}

const (
	childAgentIndent          = "  "
	childAgentPathIndent      = "    "
	childAgentDeclaredHeading = "may write:"
	childAgentDeleteHeading   = "may delete:"
	childAgentMoveHeading     = "may move:"
	childAgentDirsHeading     = "may create directories:"
	childAgentNoFilesLine     = "changed no files"
	childAgentRunningHeading  = "⋯ Child agent running"
	childAgentUnclosedHeading = "⚠ Child agent — no outcome was recorded"
)

// maxChildAgentPaths bounds each path list the block prints. events.ChildAgentEnd keeps only
// the first paths of each list plus its true total once a child outgrows the record's own limit,
// so printing a bounded prefix and that total is what keeps a live block and its replayed
// twin identical.
const maxChildAgentPaths = 12

// childAgentBlockText renders one child agent's whole block. Both the live path and /resume
// replay build their text here, so a reloaded block matches the one rendered live. open
// separates a child still running from one whose end record never arrived; calls are the
// child's own tool rounds, which only the live path observes.
func childAgentBlockText(start events.ChildAgentStart, calls []string, end *events.ChildAgentEnd, open bool) string {
	lines := []string{childAgentHeading(end, open)}
	lines = append(lines, childAgentDeclaredLines(childAgentDeclaredHeading, start.DeclaredPaths)...)
	lines = append(lines, childAgentDeclaredLines(childAgentDeleteHeading, start.DeclaredDeletePaths)...)
	lines = append(lines, childAgentDeclaredLines(childAgentMoveHeading, childAgentPairLines(start.DeclaredMovePairs))...)
	lines = append(lines, childAgentDeclaredLines(childAgentDirsHeading, start.DeclaredDirs)...)
	for _, call := range calls {
		lines = append(lines, childAgentIndent+call)
	}
	if end != nil {
		lines = append(lines, childAgentIndent+fmt.Sprintf("%d provider request(s)", end.Steps))
		lines = append(lines, childAgentChangedLines(*end)...)
	}
	for i, line := range lines {
		lines[i] = tview.Escape(line)
	}
	prefix, suffix := childAgentHeadingStyle(end, open)
	lines[0] = prefix + lines[0] + suffix
	return strings.Join(lines, "\n")
}

func childAgentHeading(end *events.ChildAgentEnd, open bool) string {
	switch {
	case open:
		return childAgentRunningHeading
	case end == nil:
		return childAgentUnclosedHeading
	case end.Reason == events.ChildAgentReasonCompleted:
		return "✓ Child agent completed"
	case end.Reason == events.ChildAgentReasonCancelled:
		return "⚠ Child agent cancelled"
	case end.Reason == events.ChildAgentReasonStepCap:
		return "⚠ Child agent stopped at its step cap"
	case end.Reason == events.ChildAgentReasonFailed:
		return "⚠ Child agent failed"
	}
	return "⚠ Child agent ended: " + end.Reason
}

func childAgentHeadingStyle(end *events.ChildAgentEnd, open bool) (string, string) {
	switch {
	case open:
		return "[::d]", "[::-]"
	case end != nil && end.Reason == events.ChildAgentReasonCompleted:
		return "", ""
	}
	return "[::b]", "[::-]"
}

func childAgentDeclaredLines(heading string, paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	return append([]string{childAgentIndent + heading}, childAgentPathLines(paths, int64(len(paths)))...)
}

func childAgentChangedLines(end events.ChildAgentEnd) []string {
	written := childAgentPathTotal(end.WrittenPaths, end.WrittenPathsTotal)
	deleted := childAgentPathTotal(end.DeletedPaths, end.DeletedPathsTotal)
	moved := int64(len(end.MovedPairs))
	if written == 0 && deleted == 0 && moved == 0 {
		line := childAgentNoFilesLine
		switch end.RollbackOutcome {
		case events.ChildRollbackNotNeeded:
			line += ", so nothing needed undoing"
		case events.ChildRollbackRolledBack:
			line += ", and its rollback completed"
		case events.ChildRollbackUnrecovered:
			line += ", and its rollback did not complete"
		}
		return []string{childAgentIndent + line}
	}
	var lines []string
	if written > 0 {
		lines = append(lines, childAgentOutcomeLines("changed", written, "are still in the worktree", end.RollbackOutcome, end.WrittenPaths)...)
	}
	if deleted > 0 {
		lines = append(lines, childAgentOutcomeLines("deleted", deleted, "are still missing from the worktree", end.RollbackOutcome, end.DeletedPaths)...)
	}
	if moved > 0 {
		lines = append(lines, childAgentOutcomeLines("moved", moved, "are still at their new paths", end.RollbackOutcome, childAgentPairLines(end.MovedPairs))...)
	}
	return lines
}

func childAgentPairLines(pairs []events.ChildMovePair) []string {
	lines := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		lines = append(lines, pair.Source+" -> "+pair.Destination)
	}
	return lines
}

func childAgentPathTotal(paths []string, bounded int64) int64 {
	if bounded == 0 {
		return int64(len(paths))
	}
	return bounded
}

func childAgentOutcomeLines(verb string, total int64, unrecovered, rollback string, paths []string) []string {
	heading := fmt.Sprintf("%s %d file(s)", verb, total)
	switch rollback {
	case events.ChildRollbackNotNeeded:
		heading += ", none undone:"
	case events.ChildRollbackRolledBack:
		heading += ", since undone:"
	case events.ChildRollbackUnrecovered:
		heading += ", which could not be undone and " + unrecovered + ":"
	default:
		heading += ":"
	}
	return append([]string{childAgentIndent + heading}, childAgentPathLines(paths, total)...)
}

func childAgentPathLines(paths []string, total int64) []string {
	shown := paths
	if len(shown) > maxChildAgentPaths {
		shown = shown[:maxChildAgentPaths]
	}
	lines := make([]string, 0, len(shown)+1)
	for _, path := range shown {
		lines = append(lines, childAgentPathIndent+path)
	}
	if remaining := total - int64(len(shown)); remaining > 0 {
		lines = append(lines, childAgentPathIndent+fmt.Sprintf("… and %d more", remaining))
	}
	return lines
}

// appendDelta accumulates one streamed chunk onto the in-progress assistant
// message, opening the buffer on the first delta, and re-renders so the live
// line grows incrementally.
func (t *transcript) appendDelta(delta string) {
	t.bufferDelta(delta)
	t.render()
}

func (t *transcript) bufferDelta(delta string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.streaming = true
	t.streamBuf += delta
}

func (t *transcript) render() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.renderLocked()
}

// rollbackPartial drops the unsealed streaming buffer before an auto-retry
// re-issues a partial stream_drop, leaving committed history untouched.
func (t *transcript) rollbackPartial() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.streaming {
		return
	}
	t.streamBuf = ""
	t.streaming = false
	t.renderLocked()
}

func (t *transcript) commitRetryRecovered(retries int) {
	if retries <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.commitLocked("[::d]"+tview.Escape(retryRecoveredText(retries))+"[::-]", nil)
	t.renderLocked()
}

func retryRecoveredText(retries int) string {
	word := "retries"
	if retries == 1 {
		word = "retry"
	}
	return fmt.Sprintf("%s%d %s", retryBreadcrumbPrefix, retries, word)
}

// completionFooterSep joins the provider, model, duration, and completion-time segments
// of the assistant-completion footer shown after a finished reply.
const completionFooterSep = " - "

// completionFooterBlock renders the completion footer as a teal transcript metadata
// block: the visible text is exactly "provider - model - duration - HH:MM", escaped so a
// provider/model string carrying "[...]" renders literally under dynamic colors, then
// wrapped in the shared accentTeal accent so it reads as chrome rather than
// assistant prose. Teal (not the dim attribute) because dim renders near-invisible on
// light terminals, and teal is the one accent chosen to stay legible on both backgrounds. It is committed as its own transcript
// block through the ordinary append path and is never recorded, so it stays
// transcript-only UI and cannot become model input or a durable message.
func completionFooterBlock(provider, model, duration string, completedAt time.Time) string {
	text := provider + completionFooterSep + model + completionFooterSep + duration + completionFooterSep + completedAt.Local().Format("15:04")
	return "[" + accentTealHex + "]" + tview.Escape(text) + "[-]"
}

// finalize commits the in-progress assistant message as a permanent transcript
// line and closes the buffer. It is a no-op when no message is streaming. The
// accumulated reply is rendered through renderMarkdown on the way into the
// committed lines, so the model's inline markdown (bold, italic, inline code)
// renders with real styling while literal text is escaped internally — the
// result already carries intentional tags and must not be re-escaped.
func (t *transcript) finalize() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.streaming {
		return
	}
	rendered, controls, payload := renderMarkdown(t.streamBuf)
	if strings.TrimSpace(t.streamBuf) != "" {
		rendered, controls = appendResponseControl(rendered, controls, payload)
	}
	t.commitLocked(rendered, controls)
	t.streamBuf = ""
	t.streaming = false
	t.renderLocked()
}

// markInterrupted commits the in-progress assistant message with the interrupted
// marker and closes the buffer, so a cancelled reply is sealed as interrupted.
// It is a no-op when no message is streaming. The reply body is rendered through
// renderMarkdown (inline markdown styled, literal text escaped internally);
// the marker is escaped separately and appended, so its own "[interrupted]"
// brackets render literally rather than being parsed as an (invalid) style tag
// under dynamic colors — and the rendered body is not re-escaped.
func (t *transcript) markInterrupted() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sealInterruptedLocked()
	t.renderLocked()
}

func (t *transcript) sealInterruptedLocked() {
	if !t.streaming {
		return
	}
	rendered, controls, payload := renderMarkdown(t.streamBuf)
	rendered += tview.Escape(streamInterruptedMarker)
	if strings.TrimSpace(t.streamBuf) != "" {
		rendered, controls = appendResponseControl(rendered, controls, payload)
	}
	t.commitLocked(rendered, controls)
	t.streamBuf = ""
	t.streaming = false
}

func (t *transcript) setSecurityHalt(records []events.SecurityStateHalted) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sealInterruptedLocked()
	t.securityHalt = securityHaltText(records)
	t.renderLocked()
}

const (
	securityHaltHeading     = "⚠ Stopped: protected settings could not be confirmed unchanged."
	securityHaltUninspected = "protected settings could not be inspected or classified"
	securityHaltAction      = "Review the file(s) above, then restart codemeld to continue."
)

// securityHaltText renders one bounded element over every affected layer. A layer the
// checkpoint could not inspect or project names its file and says so rather than naming an
// invented section, and each path is collapsed so an affected file cannot forge extra lines.
func securityHaltText(records []events.SecurityStateHalted) string {
	lines := make([]string, 0, len(records)+2)
	lines = append(lines, securityHaltHeading)
	for _, record := range records {
		detail := securityHaltUninspected
		if len(record.Sections) > 0 {
			detail = strings.Join(record.Sections, ", ")
		}
		lines = append(lines, "  "+fserrors.CollapseControls(record.Path)+": "+detail)
	}
	lines = append(lines, securityHaltAction)
	for i, line := range lines {
		lines[i] = tview.Escape(line)
	}
	return "[::b]" + strings.Join(lines, "\n") + "[::-]"
}

func (t *transcript) text(stripAll bool) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.view.GetText(stripAll)
}

// render writes the transcript lines, then the in-progress streamed line if a
// message is open, then the notice if present, into the view as its full text.
// The streamed line sits above the notice because the notice is always the last
// rendered line. While following, it re-asserts ScrollToEnd so the next draw
// follows the newest line: SetText resets the line index, and growing/streamed
// output would otherwise stay pinned at the top. When the user has scrolled up
// (following=false) it instead re-pins the saved offset so a streamed delta
// or notice cannot yank the view off the older content being read — SetText clears
// the wrap index, so the row is captured before SetText and restored with ScrollTo
// after. Scroll positioning is done synchronously here (not via SetChangedFunc,
// which tview fires on a background goroutine) so the follow/hold behavior is
// deterministic and race-free. The panel/status views keep their own
// ScrollToBeginning and are not affected.
func (t *transcript) renderLocked() {
	// Any change to the displayed text invalidates an app-owned mouse selection: its
	// byte offsets index the previous text, so drop the highlight rather than let it
	// land on shifted content. scrollBy/scrollPage do not call renderLocked, so
	// a completed selection still survives wheel and keyboard scrolling.
	t.selecting = false
	t.selAnchor, t.selStart, t.selEnd = 0, 0, 0
	// Blocks (committed entries, the live stream, the notice) are separated by one
	// blank line — "\n\n" — so the conversation is scannable, while the internal
	// newlines of any single block (e.g. a multi-line model reply) stay adjacent
	// because each block is one entry and the gap is inserted only between entries.
	// The separator is only added when output already exists above, so the first
	// block renders flush to the top and an empty transcript stays empty.
	const blockGap = "\n\n"
	out := strings.Join(t.lines, blockGap)
	// A control's line is relative to its own block, so joining shifts it by the lines
	// every earlier block occupies plus the blank line each gap adds.
	var controls []codeControl
	base := 0
	for i, block := range t.lines {
		for _, c := range t.codeControls[i] {
			c.line += base
			controls = append(controls, c)
		}
		base += strings.Count(block, "\n") + 2
	}
	if t.streaming {
		if out != "" {
			out += blockGap
		}
		// Render the in-progress reply live: completed markdown blocks render through
		// renderMarkdown so styling appears as the reply streams, while the still-growing
		// trailing block is held tview.Escape'd so incomplete syntax (an unclosed **, a
		// half-open code fence, or a tag split across deltas like "[re"+"d]") stays literal
		// and cannot leak a style tag or restyle later text. finalize/markInterrupted
		// re-render the full raw buffer authoritatively at commit.
		streamed, streamControls := renderStreamMarkdown(t.streamBuf)
		base = strings.Count(out, "\n")
		for _, c := range streamControls {
			c.line += base
			controls = append(controls, c)
		}
		out += streamed
	}
	if t.notice != "" {
		if out != "" {
			out += blockGap
		}
		out += t.notice
	}
	if t.securityHalt != "" {
		if out != "" {
			out += blockGap
		}
		out += t.securityHalt
	}
	// Capture the manual scroll row before SetText (which rebuilds the wrap index)
	// so a non-following render can re-pin exactly where the user left the view.
	row, _ := t.view.GetScrollOffset()
	t.view.SetText(out)
	t.view.setPaintText(out, t.countWidth)
	t.controls.set(codeControlRegions(t.view.GetText(true), controls))
	if t.following {
		t.view.ScrollToEnd()
		return
	}
	t.view.ScrollTo(row, 0)
}

// pendingControl reports the control a release would fire without consuming the press, so
// the caller can tell a whole-reply control from a fenced-block one while activateControl
// still owns the press/release decision.
func (t *transcript) pendingControl() clickRegion {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.controls.pending()
}

// codeControlRegions turns the renderer's generated controls into click regions over the
// displayed text. Each control names the line it was written to, so model content that
// reads exactly like a control — in a fenced body or in prose — neither gains a region nor
// cancels the real ones. The control ends the line it owns, after any blockquote/list
// prefix and before the interrupted marker markInterrupted appends to it.
func codeControlRegions(text string, controls []codeControl) []clickRegion {
	if len(controls) == 0 {
		return nil
	}
	lines := strings.SplitAfter(text, "\n")
	starts := make([]int, len(lines))
	offset := 0
	for i, line := range lines {
		starts[i] = offset
		offset += len(line)
	}
	regions := make([]clickRegion, 0, len(controls))
	for _, c := range controls {
		if c.line < 0 || c.line >= len(lines) {
			continue
		}
		label := statusCopyControl
		if c.response {
			label = responseCopyControl
		}
		line := strings.TrimSuffix(strings.TrimSuffix(lines[c.line], "\n"), streamInterruptedMarker)
		if !strings.HasSuffix(line, label) {
			continue
		}
		regions = append(regions, clickRegion{
			start:    starts[c.line] + len(line) - len(label),
			end:      starts[c.line] + len(line),
			payload:  c.body,
			response: c.response,
		})
	}
	return regions
}

// scrollBy moves the transcript by delta wrapped rows: a negative delta scrolls
// toward older output and turns auto-follow off, a positive delta scrolls toward
// newer output. Auto-follow is re-enabled only when a downward scroll reaches the
// last visible row, so subsequent streamed output resumes pinning the bottom.
// It reads the drawn geometry (GetInnerRect height and the wrapped-line
// count), so before the first draw — when there is no viewport — it clamps to the
// top and stays following. It runs on the tview event-loop goroutine (the wheel and
// key handlers), like the draw it reads from, and takes the transcript mutex so it
// does not race an off-loop streamed append marshaled through the queue.
func (t *transcript) scrollBy(delta int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, _, _, height := t.view.GetInnerRect()
	maxRow := t.view.GetWrappedLineCount() - height
	if maxRow < 0 {
		maxRow = 0
	}
	row, _ := t.view.GetScrollOffset()
	row += delta
	switch {
	case row < 0:
		row = 0
	case row >= maxRow:
		// At or past the last row: clamp to the bottom and resume auto-follow so the
		// next streamed delta keeps the newest line visible.
		row = maxRow
		t.following = true
	}
	if row < maxRow {
		t.following = false
	}
	t.view.ScrollTo(row, 0)
}

// scrollPage scrolls the transcript by one viewport height in dir (-1 up, +1
// down) for the PageUp/PageDown keyboard fallback. It keeps one row of
// context across the jump, like a pager, and floors the step at one row so a
// collapsed/undrawn pane still scrolls. The actual offset change and follow-mode
// update happen in scrollBy.
func (t *transcript) scrollPage(dir int) {
	_, _, _, height := t.view.GetInnerRect()
	step := height - 1
	if step < 1 {
		step = 1
	}
	t.scrollBy(dir * step)
}

func (t *transcript) wrappedLineCount(width int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if width <= 0 {
		return 0
	}
	t.view.SetSize(0, width)
	if width != t.countWidth {
		t.countWidth = width
		t.renderLocked()
	}
	return t.view.GetWrappedLineCount()
}
