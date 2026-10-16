// /status command: builds a single in-memory snapshot of session state at open
// time and renders the 11-item overlay.
package tui

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/trust"
)

// statusTimestampLayout is the RFC 3339 form item 3 specifies for the
// session start timestamp. It matches the canonical session timestamp form
// (UTC, millisecond precision, trailing Z) used by the on-disk session codec,
// so the overlay quotes the same string that started_at carries in the file.
const statusTimestampLayout = "2006-01-02T15:04:05.000Z"

// StatusState is the in-memory state surface the /status snapshot reads at
// open time ("single snapshot... no auto-refresh"). Every method
// must return without touching disk — the snapshot is built entirely from
// caller-supplied in-memory state so the overlay's no-disk-at-open invariant
// is enforced by the boundary rather than by the body.
//
// It is deliberately retained as the one in-memory status source shared by all
// four readers — the /status overlay (BuildStatusSnapshot), the launch banner,
// the persistent status line (RenderStatusLine), and the file-reference picker's
// project-root lookup — so those surfaces cannot drift apart. Keeping it an
// interface here also keeps this package from importing the bootstrap/model/config
// packages that assemble the concrete state; collapsing it into those concrete
// types would pull that dependency edge into internal/tui, so the seam stays.
type StatusState interface {
	// Version is the codemeld build version (item 1).
	Version() string
	// LaunchDir is the absolute launch directory (item 4).
	LaunchDir() string
	// ProjectRoot is the resolved project root (item 5).
	ProjectRoot() string
	// Layers is the settings layers that composed the session config, global first
	// and local last (item 10).
	Layers() []StatusLayer
	// Selection is the active provider/model_id/effort triple (items
	// 6-8).
	Selection() (provider, modelID, effort string)
	// AgentInstructions is the in-memory AGENTS.md load record (item 9)
	// already in the load_order produced by agentinstr.LoadAgentInstructions.
	AgentInstructions() []agentinstr.LoadEntry
	// SessionID is the active session's UUIDv7 id (item 2).
	SessionID() string
	// SessionStartedAt is the active session's start timestamp (item 3).
	SessionStartedAt() time.Time
	// Records is a snapshot of the active session's in-memory record stream,
	// used to sum token usage and detect anomalies (item 11).
	Records() []sessions.Record
	WebResearch() bool
	// Approval is the approval gate's decision as it was fixed at launch; it is never
	// recomputed from the files it covers.
	Approval() ApprovalDisclosure
	SandboxStatus() (state, reason, modeKey string)
}

type StatusLayer struct {
	Kind string
	Path string
}

// ApprovalDisclosure.Withheld carries the launch notice's own wording for each input, so
// the two surfaces cannot describe the same launch differently.
type ApprovalDisclosure struct {
	Approved bool
	Reason   trust.Reason
	Withheld []string
}

const exaSearchHost = "mcp.exa.ai"

// statusSessionPrefix opens the session-id line; App.armStatusCopy locates the copy
// control by it in the panel's visible text.
const statusSessionPrefix = "Session: "

// statusCopyControl must be escaped like the layer kind labels below, or the
// dynamic-color status view swallows it as a color tag and draws nothing.
const statusCopyControl = "[click to copy]"

// statusCopyControlTag is written raw on both surfaces while the label above it stays
// escaped: an escaped tag would draw literally instead of styling anything.
const statusCopyControlTag = "[" + accentTealHex + "::u]"

const statusCopyNotice = "Session ID copied"

// StatusSnapshot is the resolved, render-ready /status state captured at the
// moment the overlay opens. Once built it is immutable; the overlay shows this
// frozen snapshot until ESC is pressed ("no auto-refresh").
type StatusSnapshot struct {
	Version            string
	SessionID          string
	StartedAt          time.Time
	LaunchDir          string
	ProjectRoot        string
	ProjectMatchLaunch bool
	Provider           string
	ModelID            string
	Effort             string
	AgentEntries       []agentinstr.LoadEntry
	Layers             []StatusLayer
	InputTokens        int64
	OutputTokens       int64
	FullyAttestable    bool
	WebResearchEnabled bool
	Approval           ApprovalDisclosure
	SandboxState       string
	SandboxReason      string
	SandboxMode        string
}

// BuildStatusSnapshot resolves state into a StatusSnapshot. Token totals are
// summed across every model_response event in the record stream, and the
// attestability flag flips off as soon as any model_response carries a
// non-empty anomaly list (item 11).
func BuildStatusSnapshot(state StatusState) StatusSnapshot {
	provider, modelID, effort := state.Selection()
	launchDir := state.LaunchDir()
	projectRoot := state.ProjectRoot()
	approval := state.Approval()
	approval.Withheld = slices.Clone(approval.Withheld)
	sandboxState, sandboxReason, sandboxMode := state.SandboxStatus()
	snap := StatusSnapshot{
		Version:            state.Version(),
		SessionID:          state.SessionID(),
		StartedAt:          state.SessionStartedAt(),
		LaunchDir:          launchDir,
		ProjectRoot:        projectRoot,
		ProjectMatchLaunch: projectRoot != "" && projectRoot == launchDir,
		Provider:           provider,
		ModelID:            modelID,
		Effort:             effort,
		AgentEntries:       state.AgentInstructions(),
		Layers:             slices.Clone(state.Layers()),
		FullyAttestable:    true,
		WebResearchEnabled: state.WebResearch(),
		Approval:           approval,
		SandboxState:       sandboxState,
		SandboxReason:      sandboxReason,
		SandboxMode:        sandboxMode,
	}

	for _, rec := range state.Records() {
		ev, ok := rec.(sessions.Event)
		if !ok || ev.Kind != events.KindModelResponse {
			continue
		}
		var p events.ModelResponse
		// A canonicalized model_response payload is always parseable; an
		// unparseable record came from outside Append and is dropped from the
		// totals rather than panicking the overlay.
		if json.Unmarshal(ev.Payload, &p) != nil {
			continue
		}
		snap.InputTokens += p.InputTokens
		snap.OutputTokens += p.OutputTokens
		if len(p.Anomaly) > 0 {
			snap.FullyAttestable = false
		}
	}
	return snap
}

// statusSectionTitle wraps a section title in tview bold markup. The status
// TextView has dynamic colors enabled, so [::b]Title[::-] renders as a
// bold heading instead of printing the tags literally. Every runtime data value
// is escaped (see RenderStatus) so only these fixed title tags are parsed.
func statusSectionTitle(title string) string {
	return "[::b]" + title + "[::-]"
}

// RenderStatus returns the deterministic, line-broken text of the /status
// overlay. The fixed 11-item order is preserved but the items are
// grouped under bold section titles with a blank line between sections for
// readability: Session (version, id, started), Location (launch dir,
// project root), Model (provider, model, effort), Context (AGENTS.md files,
// config layer sources), Usage (token totals + any incomplete notice). The
// project-root line carries the "(same as launch dir)" suffix when ProjectRoot
// matches LaunchDir; config layer sources are rendered farthest-first with
// their [global]/[project]/[local] kind labels. Because the
// status view has dynamic colors enabled, every runtime/data value —
// paths, ids, provider/model/effort, version, AGENTS.md paths — is escaped with
// tview.Escape so a value that happens to contain a [tag]-like sequence renders
// literally instead of being swallowed as color markup; only the fixed section
// titles are left as live markup.
func RenderStatus(snap StatusSnapshot) string {
	var b strings.Builder
	esc := tview.Escape

	// Session: version (1), id (2), started (3).
	b.WriteString(statusSectionTitle("Session") + "\n")
	fmt.Fprintf(&b, "codemeld %s\n", esc(snap.Version))
	fmt.Fprintf(&b, "%s%s %s%s%s%s\n", statusSessionPrefix, esc(snap.SessionID), statusCopyControlTag, esc(statusCopyControl), defaultTag, underlineOffTag)
	fmt.Fprintf(&b, "Started: %s\n", esc(snap.StartedAt.UTC().Truncate(time.Millisecond).Format(statusTimestampLayout)))
	b.WriteString(sandboxLine(esc, snap) + "\n")

	// Location: launch directory (4), project root (5) with the "(same as launch
	// dir)" suffix when equal.
	b.WriteString("\n" + statusSectionTitle("Location") + "\n")
	fmt.Fprintf(&b, "Launch dir: %s\n", esc(snap.LaunchDir))
	if snap.ProjectMatchLaunch {
		fmt.Fprintf(&b, "Project root: %s (same as launch dir)\n", esc(snap.ProjectRoot))
	} else {
		fmt.Fprintf(&b, "Project root: %s\n", esc(snap.ProjectRoot))
	}

	// Model: provider (6), model id (7), effort (8).
	b.WriteString("\n" + statusSectionTitle("Model") + "\n")
	fmt.Fprintf(&b, "Provider: %s\n", esc(snap.Provider))
	fmt.Fprintf(&b, "Model: %s\n", esc(snap.ModelID))
	fmt.Fprintf(&b, "Effort: %s\n", esc(snap.Effort))

	// Context: loaded AGENTS.md files (9), config layer sources (10).
	b.WriteString("\n" + statusSectionTitle("Context") + "\n")
	// Loaded AGENTS.md files — absolute path, layer, load order. Skipped
	// candidates (oversize, unreadable) are filtered out: item 9 lists
	// "loaded" files, and showing a skipped entry as if it were loaded would
	// misreport the session instruction context. If no candidates loaded, the
	// (none) placeholder is rendered so the item order is preserved.
	b.WriteString("AGENTS.md files:\n")
	loaded := 0
	for _, e := range snap.AgentEntries {
		if e.Skipped {
			continue
		}
		fmt.Fprintf(&b, "  %s [%s, load_order=%d]\n", esc(e.Path), esc(e.Layer), e.LoadOrder)
		loaded++
	}
	if loaded == 0 {
		b.WriteString("  (none)\n")
	}
	// The bare-word bracket labels would otherwise be swallowed as color tags by the
	// dynamic-color TextView, so they are escaped to render literally.
	b.WriteString("Config layer sources:\n")
	if len(snap.Layers) == 0 {
		b.WriteString("  (none)\n")
	}
	for _, layer := range snap.Layers {
		fmt.Fprintf(&b, "  %s %s\n", esc(layer.Path), esc("["+layer.Kind+"]"))
	}
	writeApprovalLine(&b, esc, snap.Approval)
	b.WriteString(webResearchLine(snap.WebResearchEnabled) + "\n")

	// Usage: session token totals (11). The always-on attestability indicator is
	// superseded: instead of a "fully attestable" line on every open, a
	// single incomplete-counts line follows the token usage only when some turn did
	// not report usage (FullyAttestable is false). A fully attestable session shows
	// nothing extra — the section ends at the Token usage line.
	b.WriteString("\n" + statusSectionTitle("Usage") + "\n")
	fmt.Fprintf(&b, "Token usage: %d input, %d output\n", snap.InputTokens, snap.OutputTokens)
	if !snap.FullyAttestable {
		b.WriteString("Token counts: incomplete (some turns did not report usage)\n")
	}

	return b.String()
}

// writeApprovalLine names only the gated inputs rather than "project inputs" as a whole:
// an unapproved project still loads its AGENTS.md files, which this same overlay lists a
// few lines above.
func writeApprovalLine(b *strings.Builder, esc func(string) string, approval ApprovalDisclosure) {
	switch {
	case approval.Reason == trust.ReasonNothingCovered:
		b.WriteString("Project approval: nothing to approve\n")
	case approval.Approved:
		b.WriteString("Project approval: approved\n")
	case len(approval.Withheld) > 0:
		escaped := make([]string, len(approval.Withheld))
		for i, input := range approval.Withheld {
			escaped[i] = esc(input)
		}
		fmt.Fprintf(b, "Project approval: not approved — ignoring %s\n", strings.Join(escaped, " and "))
	default:
		b.WriteString("Project approval: not approved\n")
	}
}

func sandboxLine(esc func(string) string, snap StatusSnapshot) string {
	switch snap.SandboxState {
	case "on":
		line := "Sandbox: on — commands run with OS-enforced filesystem and process-access restrictions"
		if snap.SandboxMode == modeKeyAutoEdits {
			line += "; fewer permission prompts"
		}
		return line
	case "off":
		return "Sandbox: off — build mode runs commands outside the sandbox"
	}
	if snap.SandboxReason == "" {
		return "Sandbox: unavailable — automatic command authorization is unavailable"
	}
	return "Sandbox: unavailable (" + esc(snap.SandboxReason) + ") — automatic command authorization is unavailable"
}

func webResearchLine(enabled bool) string {
	if !enabled {
		return "web research: off"
	}
	return "web research: on — " + exaSearchHost
}

// RenderStatusLine returns the segment portion of the persistent bottom bar:
// provider / model / effort / launch-dir / sandbox state as two-tone
// filled rectangular segments — a darker leading cap then a lighter body — in a cooler slate ramp. The mode
// pill and the shift+tab hint now live on a separate second footer row composed by the App
// (RefreshModeHint), so this renders only the segment group. It reads the same StatusState
// the /status overlay and the launch banner read, so the bar never drifts from them. When no
// model is selected it renders an explicit "no model selected" segment followed by the
// launch dir and sandbox state, rather than blank fields.
//
// The segment fills paint backgrounds — a scoped exception to the terminal-default
// theme limited to chrome (see colors.go). Every runtime value is tview.Escape'd before it
// enters the dynamic-color string so a launch dir, model id, or provider containing a
// "[tag]"-like sequence renders literally instead of being swallowed as color markup; only
// the fixed fill tags are live markup.
func RenderStatusLine(state StatusState) string {
	esc := tview.Escape
	sandbox, _, _ := state.SandboxStatus()
	tail := statusSegment(statusSegmentCap4, statusSegmentBody4, esc(state.LaunchDir())) +
		statusSegment(statusSegmentCap5, statusSegmentBody5, "sandbox: "+esc(sandbox))
	provider, modelID, effort := state.Selection()
	// Segments are concatenated with no separator so the filled pills butt directly against
	// one another as one continuous slate bar: the earlier single-space
	// joiner painted a default-background gap between every pill. The darker leading cap of
	// each segment is what keeps adjacent pills visually distinct without that gap.
	if modelID == "" {
		return statusSegment(statusSegmentCap1, statusSegmentBody1, "no model selected") + tail
	}
	return statusSegment(statusSegmentCap1, statusSegmentBody1, esc(provider)) +
		statusSegment(statusSegmentCap2, statusSegmentBody2, esc(modelID)) +
		statusSegment(statusSegmentCap3, statusSegmentBody3, esc(effort)) +
		tail
}

// statusSegment renders one status field as a two-tone filled rectangular segment: a
// darker one-character leading cap (capBg) immediately before a lighter body (bodyBg)
// carrying white text padded with one space on each side, so each pill reads as a "stub +
// body" block rather than one flat fill. The cap cell is a single space, so its
// foreground is irrelevant and it uses the default fg; the body keeps white
// (chromeOnFillText) over its fill so it stays legible independent of the terminal palette.
// text must already be tview.Escape'd by the caller — the fixed fg:bg tags are the only
// live markup. The fills are the chrome exception (colors.go).
func statusSegment(capBg, bodyBg, text string) string {
	return fmt.Sprintf("[-:%s] [%s:%s] %s [-:-]", capBg, chromeOnFillText, bodyBg, text)
}

// NewStatusHandler returns the /status handler bound to an in-memory state
// source. Dispatch order: record the canonical slash_command success event
// then snapshot in-memory state and open the overlay.
// Snapshotting after the event append is intentional — the
// slash_command record is itself a model_response-irrelevant event, so the
// snapshot order is observable only through its no-disk and ordering
// behavior, and the order keeps the handler symmetric with /help.
func NewStatusHandler(state StatusState) HandlerFunc {
	return func(ctx CommandContext, _ []string) error {
		if err := ctx.AppendSlashCommand(OutcomeSuccess, ""); err != nil {
			return err
		}
		// the slash_command append must be durable before the next
		// non-append step (opening the overlay). This flushes only the appended
		// record; the snapshot itself is still built from in-memory state with no
		// disk read (item 11).
		if err := ctx.FlushActive(); err != nil {
			return err
		}
		snap := BuildStatusSnapshot(state)
		ctx.ShowStatus(RenderStatus(snap))
		return nil
	}
}
