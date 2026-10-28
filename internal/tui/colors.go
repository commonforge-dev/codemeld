// Central palette of the TUI's intentional fixed-color accents. These are the only
// deliberate overrides of the terminal-default theme; every other primitive stays
// tcell.ColorDefault so it inherits the user's terminal palette. Do NOT add ColorDefault
// values here — a value belongs in this file only because it is a fixed accent that
// overrides the terminal default on purpose.
package tui

import "github.com/gdamore/tcell/v2"

// Markup-string accents — used inside tview color tags ("[#4e9a06]…[-]") and SetLabel
// markup, so they are kept as tview color strings rather than tcell.Color values.
const (
	// codeColor is the foreground for inline code spans and fenced code blocks. It is an
	// intentional readability accent overriding the terminal-default theme so code
	// reads distinctly from surrounding prose; it is a fixed hex value, not derived from
	// the terminal palette.
	codeColor = "#4e9a06"

	codeBlockText = "#8ae234"
	codeBlockFill = "#2f343f"

	toolActivityColor = "#6b7480"

	// colorMode* are the per-mode fills of the bottom bar's filled mode pill: each
	// is used as the pill BACKGROUND, with white (chromeOnFillText) text over it, so the
	// active mode reads as a solid colored rectangle rather than bare colored text. plan is
	// a dark blue rather than cyan — cyan renders near-black on some terminals, making plan
	// indistinguishable from black while build/auto read fine; build is a
	// softer green than pure terminal green so the fill is not over-saturated; auto-edits
	// keeps the muted amber/golden hex that reads closer to Claude Code's golden
	// yellow without the glare of bright yellow. All three stay distinct as fills: blue
	// (plan) / green (build) / amber (auto).
	colorModePlan  = "#2456b8"
	colorModeBuild = "#4a9d6b"
	colorModeAuto  = "#b8860b"
)

// accentTealHex is the single brand accent, shared by the launch banner
// bar, the status-bar mode pill, the input prompt glyph, and the user-input rail. It is
// kept as one hex source so the tview-markup form (accentTealHex, used in dynamic-color
// tags) and the tcell.Color form (accentTeal, used in SetLabelStyle) can never drift.
const accentTealHex = "#1f9e8f"

// accentTeal is the tcell.Color form of accentTealHex, used where a color tag cannot be
// (the prompt label is styled via SetLabelStyle). tcell.NewHexColor parses the same
// 0xRRGGBB value accentTealHex names.
var accentTeal = tcell.NewHexColor(0x1f9e8f)

// Filled-chrome tokens. The launch banner bar and the bottom status-bar segments
// deliberately paint BACKGROUNDS — a scoped exception to the terminal-default
// theme, which otherwise keeps every primitive at tcell.ColorDefault (see this file's
// header). Each bar supplies its own foreground+background, so it stays legible on both
// light and dark terminals independent of the inherited terminal background, which is
// what makes filled chrome more robust here than a foreground-only accent. The user-input
// rail is the one accent that stays within the terminal-default theme: it is a
// foreground-only teal bar (accentTealHex) drawn over the unchanged transcript background.
const (
	// chromeOnFillText is the foreground for text on the filled banner/status chrome:
	// bright white, which reads on both the teal banner and the slate segment fills.
	chromeOnFillText = "#ffffff"
	// statusSegmentBody* are the cooler slate segment-body fills of the bottom status bar,
	// lightening left→right so the provider/model/effort/dir segments read as distinct
	// filled rectangles rather than one flat run (earlier flat neutral greys were replaced
	// with this cooler slate ramp to match the design sample). The values are a four-step
	// ramp from the sample's darkest pill (#46505d, provider) to its lightest (#8a96a3, the
	// effort pill — the lightest fill the sample uses behind white text), plus a fifth step
	// (#a0acb9, the execution-capability pill) continuing the ramp; the first tuning
	// (#2b303b → #4b5160) was both too dark and too compressed to read as a ramp at all, so
	// the pills looked like one flat near-black run. The fifth step is lighter than any pill in
	// the sample, so white (chromeOnFillText) legibility on it needs checking in a real terminal.
	statusSegmentBody1 = "#46505d"
	statusSegmentBody2 = "#5d6774"
	statusSegmentBody3 = "#737f8c"
	statusSegmentBody4 = "#8a96a3"
	statusSegmentBody5 = "#a0acb9"
	// statusSegmentCap* are the darker leading-cap fills — about one ramp half-step darker
	// than the body in the same column — that paint a one-character "stub" before each
	// segment body, so every pill reads as a two-tone block (a darker cap + a lighter body)
	// as in the design sample.
	statusSegmentCap1 = "#36404d"
	statusSegmentCap2 = "#4d5764"
	statusSegmentCap3 = "#636f7c"
	statusSegmentCap4 = "#7a8693"
	statusSegmentCap5 = "#909ca9"
	// bannerVersionText is the dim, soft teal-tinted white the launch banner draws the
	// "v<version>" in, immediately after the bold-white "◆ codemeld" wordmark, so the
	// version reads as secondary text on the teal bar rather than competing with the wordmark.
	bannerVersionText = "#bfe6df"
	// bannerMeta* are the foreground greys of the launch banner's metadata subtitle line
	// (LaunchBannerMeta) — provider · model · effort · dir. Unlike the bottom status bar's
	// filled pills, this is a foreground-only accent over the unchanged transcript
	// background, anchored on the design sample's cool blue-grey (≈ #8a929b) and ramped so
	// the segments lighten left→right (provider darkest → dir lightest), reading as one dim
	// secondary ramp rather than a flat run. bannerMetaSeparator is the mid grey of the
	// " · " dividers, kept constant so the dots recede while the segments carry the ramp.
	// Fixed accents scoped to the banner chrome (the same exception above).
	bannerMetaProvider  = "#5b6470"
	bannerMetaModel     = "#6f7884"
	bannerMetaEffort    = "#838c98"
	bannerMetaDir       = "#97a0ac"
	bannerMetaSeparator = "#838c98"
)

// promptLabelColor is the foreground of the "› " prompt label. It is a tcell.Color (not a
// markup string) because it is applied via SetLabelStyle, not a color tag. It is the teal
// brand accent, replacing the earlier hardcoded black: a filled-chrome glyph that
// supplies its own color rather than relying on the terminal default, so it reads on both
// light and dark terminals (the earlier black-for-light-terminal trade-off no longer applies).
var promptLabelColor = accentTeal

// inputAccentPalette is the closed six-name palette a run-scoped input accent may select
// from: the fixed tcell named colors, kept intentionally small and non-configurable — no hex
// parsing, aliases, or a seventh name. tcell names magenta "Fuchsia" and cyan "Aqua", so those
// two constants back "magenta"/"cyan". The accent is applied only to the input's prompt glyph
// and rules for the running session and is never persisted; promptLabelColor stays the
// fresh-session default until an accent overrides it.
var inputAccentPalette = map[string]tcell.Color{
	"red":     tcell.ColorRed,
	"green":   tcell.ColorGreen,
	"yellow":  tcell.ColorYellow,
	"blue":    tcell.ColorBlue,
	"magenta": tcell.ColorFuchsia,
	"cyan":    tcell.ColorAqua,
}

// ghostTextColor is the foreground of the follow-up suggestion ghost text drawn in the
// empty input. It is a fixed grey accent overriding the
// terminal-default theme so the suggestion reads as dim, secondary text rather than a
// real draft. Accessibility: the dim color is paired with a
// theme-independent "⇥ Tab: " prefix on the label, so the affordance is legible even
// where the terminal renders grey/dim indistinctly from normal text.
var ghostTextColor = tcell.ColorGray
