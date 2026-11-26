package tui

import (
	"unicode"
	"unicode/utf8"
)

// detectAtTrigger reports whether cur is prev with exactly one '@' rune inserted at a word
// boundary — the file-reference picker trigger — and returns the byte offset of the
// inserted '@' in cur. A word boundary is the start of the buffer or a position whose
// preceding rune is whitespace, so a '@' typed inside a word (an email local part, say)
// never triggers. Because '@' is a single byte, a one-character insertion makes
// len(cur) == len(prev)+1; any larger delta — a multi-rune bracketed paste, including one
// that contains '@' — fails the length test and never triggers. A deletion, a
// replacement, or a multi-rune programmatic SetText fail the same test. The trailing-bytes
// equality check rejects a same-length coincidental edit that is not a clean single insert.
// A bracketed paste of exactly one '@' has the same one-byte delta as a typed '@' and is not
// separable here; App.onInputChanged suppresses that case upstream via inputField.pasting.
func detectAtTrigger(prev, cur string) (int, bool) {
	if len(cur) != len(prev)+1 { // '@' is one byte: only a single-char insertion can match
		return 0, false
	}
	i := 0
	for i < len(prev) && prev[i] == cur[i] {
		i++
	}
	if cur[i] != '@' {
		return 0, false
	}
	if cur[i+1:] != prev[i:] {
		return 0, false // the rest must be unchanged, so the edit is exactly one inserted '@'
	}
	if i == 0 {
		return i, true // start of buffer is a word boundary
	}
	r, _ := utf8.DecodeLastRuneInString(cur[:i])
	if unicode.IsSpace(r) {
		return i, true
	}
	return 0, false
}

// detectSlashTrigger reports whether cur is prev with exactly one '/' rune inserted as the
// first non-whitespace character of the buffer — the live slash-command picker trigger — and
// returns the byte offset of the inserted '/' in cur. A slash command is only valid as the
// whole line, so the '/' fires only when every byte before it is space or tab: a '/' after any
// non-whitespace text, after a newline, or inside a word never triggers. Like detectAtTrigger,
// '/' is a single byte so a one-character insertion makes len(cur) == len(prev)+1; a multi-rune
// bracketed paste fails the length test, and a paste of exactly '/' is suppressed upstream by
// App.onInputChanged via inputField.pasting.
func detectSlashTrigger(prev, cur string) (int, bool) {
	if len(cur) != len(prev)+1 { // '/' is one byte: only a single-char insertion can match
		return 0, false
	}
	i := 0
	for i < len(prev) && prev[i] == cur[i] {
		i++
	}
	if cur[i] != '/' {
		return 0, false
	}
	if cur[i+1:] != prev[i:] {
		return 0, false // the rest must be unchanged, so the edit is exactly one inserted '/'
	}
	for _, r := range cur[:i] { // everything before the '/' must be leading space/tab, no newline
		if r != ' ' && r != '\t' {
			return 0, false
		}
	}
	return i, true
}

// fileRefTokenEnd returns the byte offset at which the file-reference token beginning with
// the '@' at atByte ends: the first whitespace byte at or after atByte+1, or the end of
// text. The token is "@" plus the run of non-whitespace runes after it, so selecting a
// candidate replaces the whole run (any query text following '@') as a unit. atByte
// must index the '@'; an out-of-range offset is returned unchanged.
func fileRefTokenEnd(text string, atByte int) int {
	if atByte < 0 || atByte >= len(text) {
		return atByte
	}
	for i := atByte + 1; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if unicode.IsSpace(r) {
			return i
		}
		i += size
	}
	return len(text)
}
