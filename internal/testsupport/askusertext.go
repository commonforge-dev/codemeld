package testsupport

// AskUserTextCase is one value of the ask_user displayed-text rule with the verdict each
// layer must reach on it: Valid is what the authoritative renderability rule decides, and
// Pattern is what the advertised schema class can express on its own.
type AskUserTextCase struct {
	Text    string
	Valid   bool
	Pattern bool
}

// AskUserTextCases is asserted by both the provider schema test and the bootstrap decoder
// test. The rule is shared here rather than restated in each package because the schema and
// the decoder previously enforced two defensible blank-text rules that disagreed on values a
// model can actually send. Where they still differ the schema must be the looser of the two,
// so every Valid case is also a Pattern case: a value the form can show must never be one the
// advertised schema refuses. The six Valid=false/Pattern=true values are examples,
// not a list — the provider sweep test bounds that difference over every code point.
var AskUserTextCases = []AskUserTextCase{
	{"x", true, true},
	{"", false, false},
	{" ", false, false},
	{"\t\n\r\f\v ", false, false},
	{"   \t  ", false, false},
	{" x ", true, true},
	{string(rune(0x00A0)), false, false},
	{string(rune(0x0085)), false, false},
	{string(rune(0xFEFF)), false, false},
	{string(rune(0x200B)), false, false},
	{string(rune(0x754C)), true, true},
	{"e" + string(rune(0x0301)), true, true},
	{"a" + string(rune(0x200B)) + "b", false, false},
	// Visible text carrying one control character. The terminal cannot draw the control, and
	// the form measures wrapped text at the width it renders it at, which a tab TextView
	// later expands to a tab stop breaks.
	{"Yes\tNo", false, false},
	{"Choose\nnow", false, false},
	{"Choose\rnow", false, false},
	{"Choose\fnow", false, false},
	{"Choose\vnow", false, false},
	{"Choose" + string(rune(0x0085)) + "now", false, false},
	{"Choose" + string(rune(0x2028)) + "now", false, false},
	// Visible text carrying one non-printing character from each of the other classes the
	// terminal cannot draw: a bidi override, an invisible mathematical operator, an annotation
	// anchor, a Mongolian vowel separator, and a private-use code point whose glyph is
	// whatever the reader's font happens to assign it.
	{"Choose" + string(rune(0x202E)) + "now", false, false},
	{"Choose" + string(rune(0x2061)) + "now", false, false},
	{"Choose" + string(rune(0xFFF9)) + "now", false, false},
	{"Choose" + string(rune(0x180E)) + "now", false, false},
	{"Choose" + string(rune(0xE000)) + "now", false, false},
	// Graphic characters that draw no ink. Unicode calls them letters and symbols, so nothing
	// in the printable/whitespace rule catches them: the braille blank, the three Hangul
	// fillers and the halfwidth filler each mount a row that reads as empty, alone or beside
	// text. The neighbours a code point away do draw and stay valid, which is what keeps the
	// rule to the characters that are actually blank.
	{string(rune(0x2800)), false, false},
	{string(rune(0x3164)), false, false},
	{string(rune(0x115F)), false, false},
	{string(rune(0x1160)), false, false},
	{string(rune(0xFFA0)), false, false},
	{"Choose" + string(rune(0x2800)) + "now", false, false},
	{"Choose" + string(rune(0x3164)) + "now", false, false},
	{string(rune(0x2801)), true, true},
	{string(rune(0xFFA1)), true, true},
	// The enclosing mark on its own encloses nothing, so the row is a bare circle with no
	// answer in it; attached to a letter it is the glyph the user reads. Both are needed
	// because the provider sweep prefixes every code point with a letter and so can only see
	// the attached case.
	{string(rune(0x20DD)), false, true},
	{"a" + string(rune(0x20DD)), true, true},
	// The values a JSON Schema pattern cannot follow the renderable rule onto. It can require
	// that a visible character appear but not that any grapheme occupy a cell, so
	// combining-mark-only text still matches; it cannot name a code point Unicode has not
	// assigned yet; it cannot name one outside the BMP, because an ECMA-262 engine without the
	// `u` flag reads an astral range as a surrogate-code-unit range in the wrong order and
	// refuses to compile the pattern at all; and it must not name U+0000, which some provider
	// regex engines read as the end of the pattern, so a NUL alone or beside text still
	// matches. The decoder refuses all of them.
	{string(rune(0x0301)), false, true},
	{"Choose" + string(rune(0x0378)) + "now", false, true},
	{"Choose" + string(rune(0xE0020)) + "now", false, true},
	{"Yes\x00", false, true},
	{"\x00", false, true},
}
