// Tests for the TUI shell: submit accept/reject, input clearing, transcript
// append, notice state, and a simulation-screen launch/render check.
package tui

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/sessions"
)

// recordingPartsHook is a SubmitFunc that records the text and image content parts of
// each submission, returning a fixed accept/reject verdict.
func recordingPartsHook(accept bool, gotText *[]string, gotParts *[][]sessions.ContentPart) SubmitFunc {
	return func(input string, imageParts ...sessions.ContentPart) bool {
		*gotText = append(*gotText, input)
		*gotParts = append(*gotParts, imageParts)
		return accept
	}
}

// testImageAttachment builds a pending attachment whose data URI encodes size zero
// bytes, so its derived placeholder size is deterministic without touching disk.
func testImageAttachment(name string, size int) imageAttachment {
	return imageAttachment{
		path:      name,
		mime:      "image/png",
		sizeBytes: int64(size),
		dataURI:   "data:image/png;base64," + base64.StdEncoding.EncodeToString(make([]byte, size)),
	}
}

// Keep root and home separate so out-of-root image paths can be tested.
func newImagePathApp(t *testing.T, gotText *[]string, gotParts *[][]sessions.ContentPart) (*App, string) {
	t.Helper()
	a := New(recordingPartsHook(true, gotText, gotParts))
	root := t.TempDir()
	a.statusLineState = &statusStateFake{projectRoot: root}
	a.SetHome(t.TempDir())
	return a, root
}

func TestSubmitCurrent_AttachmentReachesHookEchoedAndCleared(t *testing.T) {
	var gotText []string
	var gotParts [][]sessions.ContentPart
	a := New(recordingPartsHook(true, &gotText, &gotParts))
	a.input.SetText("look at this")
	att := testImageAttachment("docs/diagram.png", 2048)
	a.input.addAttachment(att, "diagram.png")

	if !a.submitCurrent() {
		t.Fatal("submitCurrent returned false for an accepted text+image submission")
	}
	if len(gotText) != 1 || gotText[0] != "look at this" {
		t.Fatalf("hook text = %v, want [look at this]", gotText)
	}
	if len(gotParts) != 1 || len(gotParts[0]) != 1 || gotParts[0][0].Type != "image_url" {
		t.Fatalf("hook image parts = %v, want one image_url part", gotParts)
	}
	if got := a.input.GetText(); got != "" {
		t.Errorf("input buffer = %q, want cleared on accept", got)
	}
	if n := len(a.input.imageAttachments()); n != 0 {
		t.Errorf("attachments = %d, want cleared on accept", n)
	}
	// The transcript echoes the teal-railed prompt line plus one railed placeholder, never
	// the image bytes ("▌ " is the tag-stripped rail prefix).
	if got, want := a.TranscriptText(), "▌ look at this\n▌ [image: diagram.png (2 KB)]"; got != want {
		t.Errorf("transcript = %q, want %q", got, want)
	}
}

func TestSubmitCurrent_ImageOnlyAccepted(t *testing.T) {
	var gotText []string
	var gotParts [][]sessions.ContentPart
	a := New(recordingPartsHook(true, &gotText, &gotParts))
	a.input.addAttachment(testImageAttachment("a.png", 1024), "a.png") // no typed text

	if !a.submitCurrent() {
		t.Fatal("submitCurrent rejected an image-only submission; it must be accepted when an attachment is pending")
	}
	if len(gotText) != 1 || gotText[0] != "" {
		t.Fatalf("hook text = %v, want one empty-string submission", gotText)
	}
	if len(gotParts) != 1 || len(gotParts[0]) != 1 {
		t.Fatalf("hook image parts = %v, want one image part", gotParts)
	}
	// No text line — only the railed placeholder ("▌ " is the tag-stripped rail prefix).
	if got, want := a.TranscriptText(), "▌ [image: a.png (1 KB)]"; got != want {
		t.Errorf("transcript = %q, want %q (image-only, no empty prompt line)", got, want)
	}
}

// TestSubmitCurrent_TokenPartsInBufferOrder proves the submitted image parts follow the
// tokens' order in the buffer (not insertion order), each token is stripped from the prompt
// text, and the surrounding text survives.
func TestSubmitCurrent_TokenPartsInBufferOrder(t *testing.T) {
	var gotText []string
	var gotParts [][]sessions.ContentPart
	a := New(recordingPartsHook(true, &gotText, &gotParts))

	// Build "a [first.png] b [second.png]" by typing text around two inserted tokens.
	a.input.SetText("a  b ")
	a.input.Select(len("a "), len("a "))
	a.input.addAttachment(testImageAttachment("first.png", 16), "first.png")
	a.input.Select(len(a.input.GetText()), len(a.input.GetText()))
	a.input.addAttachment(testImageAttachment("second.png", 16), "second.png")

	if !a.submitCurrent() {
		t.Fatal("submitCurrent rejected a text+two-image submission")
	}
	if len(gotText) != 1 || gotText[0] != "a  b" {
		t.Fatalf("submitted text = %q, want the tokens stripped leaving %q", gotText, "a  b")
	}
	if len(gotParts) != 1 || len(gotParts[0]) != 2 {
		t.Fatalf("submitted parts = %v, want two image parts", gotParts)
	}
	// Buffer order: first.png precedes second.png; assert via the persisted "name".
	if !strings.Contains(string(gotParts[0][0].Raw), "first.png") ||
		!strings.Contains(string(gotParts[0][1].Raw), "second.png") {
		t.Errorf("image parts out of buffer order: %s | %s", gotParts[0][0].Raw, gotParts[0][1].Raw)
	}
}

// TestSubmitCurrent_DeletedTokenSendsNoPart proves a token deleted before submit contributes
// no image part: only the surviving token is sent.
func TestSubmitCurrent_DeletedTokenSendsNoPart(t *testing.T) {
	var gotText []string
	var gotParts [][]sessions.ContentPart
	a := New(recordingPartsHook(true, &gotText, &gotParts))

	a.input.SetText("keep ")
	a.input.Select(len("keep "), len("keep "))
	a.input.addAttachment(testImageAttachment("gone.png", 16), "gone.png")
	a.input.Replace(len(a.input.GetText()), len(a.input.GetText()), " ") // separator
	a.input.Select(len(a.input.GetText()), len(a.input.GetText()))
	a.input.addAttachment(testImageAttachment("stay.png", 16), "stay.png")

	// Delete the first token's range ("keep [gone.png] [stay.png]" → "keep  [stay.png]").
	tok := "[gone.png]"
	start := len("keep ")
	a.input.Replace(start, start+len(tok), "")

	if !a.submitCurrent() {
		t.Fatal("submitCurrent rejected the surviving-token submission")
	}
	if len(gotParts) != 1 || len(gotParts[0]) != 1 {
		t.Fatalf("submitted parts = %v, want exactly the one surviving image part", gotParts)
	}
	if !strings.Contains(string(gotParts[0][0].Raw), "stay.png") {
		t.Errorf("surviving part = %s, want stay.png", gotParts[0][0].Raw)
	}
}

func TestSubmitCurrent_RejectRetainsAttachments(t *testing.T) {
	var gotText []string
	var gotParts [][]sessions.ContentPart
	a := New(recordingPartsHook(false, &gotText, &gotParts))
	a.input.SetText("keep me")
	a.input.addAttachment(testImageAttachment("a.png", 16), "a.png")

	if a.submitCurrent() {
		t.Fatal("submitCurrent returned true for a rejected submission")
	}
	// A rejected submit leaves the buffer — including the image token — editable for retry.
	if got := a.input.GetText(); got != "keep me[a.png]" {
		t.Errorf("input buffer = %q, want the text and image token retained on reject", got)
	}
	if n := len(a.input.imageAttachments()); n != 1 {
		t.Errorf("attachments = %d, want 1 retained on reject so the user can retry without re-attaching", n)
	}
}

// TestSubmitCurrent_RecognizesTypedImagePath proves a typed filesystem path to an
// in-root image is recognized only at submit, removed from the prompt text, and carried
// as an image attachment.
func TestSubmitCurrent_RecognizesTypedImagePath(t *testing.T) {
	var gotText []string
	var gotParts [][]sessions.ContentPart
	a, root := newImagePathApp(t, &gotText, &gotParts)
	writeFile(t, filepath.Join(root, "diagram.png"), pngMagic+"data")

	a.input.SetText("see diagram.png please")
	if n := len(a.input.imageAttachments()); n != 0 {
		t.Fatalf("attachments before Enter = %d, want 0 (typed paths validate only on submit)", n)
	}
	if !a.submitCurrent() {
		t.Fatal("submitCurrent rejected a prompt with a typed image path")
	}
	if len(gotText) != 1 || gotText[0] != "see please" {
		t.Fatalf("submitted text = %v, want [\"see please\"] (the path token recognized and removed)", gotText)
	}
	if len(gotParts) != 1 || len(gotParts[0]) != 1 || gotParts[0][0].Type != "image_url" {
		t.Fatalf("submitted parts = %v, want one image_url part for the typed path", gotParts)
	}
}

// TestPasteImagePathAddsPendingAttachmentBeforeSubmit proves a pasted image path is
// treated as an explicit reference: it is validated immediately, removed from the buffer,
// and shown as a pending attachment before Enter.
func TestPasteImagePathAddsPendingAttachmentBeforeSubmit(t *testing.T) {
	var gotText []string
	var gotParts [][]sessions.ContentPart
	a, root := newImagePathApp(t, &gotText, &gotParts)
	writeFile(t, filepath.Join(root, "diagram.png"), pngMagic+"data")

	pasteInto(a.input, "diagram.png")

	// The pasted path becomes a removable "[diagram.png]" token, not bare prose.
	if got := a.input.GetText(); got != "[diagram.png]" {
		t.Fatalf("input after pasted image path = %q, want a [diagram.png] token before submit", got)
	}
	if len(gotText) != 0 {
		t.Fatalf("submit hook called during paste: %v", gotText)
	}
	atts := a.input.imageAttachments()
	if len(atts) != 1 || atts[0].path != "diagram.png" {
		t.Fatalf("pending attachments = %+v, want diagram.png before submit", atts)
	}
	if a.transcript.notice == "" {
		t.Fatal("pasted image path left no visible attachment notice")
	}
	if !a.submitCurrent() {
		t.Fatal("submitCurrent rejected pasted image attachment")
	}
	if len(gotText) != 1 || gotText[0] != "" {
		t.Fatalf("submitted text = %v, want one image-only submission", gotText)
	}
	if len(gotParts) != 1 || len(gotParts[0]) != 1 || gotParts[0][0].Type != "image_url" {
		t.Fatalf("submitted parts = %v, want one image_url part", gotParts)
	}
}

// TestPasteMixedTextImagePathKeepsTokenInPlace proves a pasted image path embedded in
// surrounding text becomes a removable token at the path's original position — not appended at
// the end of the paste — so the buffer order matches what the user pasted, the token is
// removable, and submit strips it while sending one image part.
func TestPasteMixedTextImagePathKeepsTokenInPlace(t *testing.T) {
	var gotText []string
	var gotParts [][]sessions.ContentPart
	a, root := newImagePathApp(t, &gotText, &gotParts)
	writeFile(t, filepath.Join(root, "diagram.png"), pngMagic+"data")

	pasteInto(a.input, "look diagram.png please")

	if got := a.input.GetText(); got != "look [diagram.png] please" {
		t.Fatalf("input after mixed paste = %q, want %q", got, "look [diagram.png] please")
	}
	if len(gotText) != 0 {
		t.Fatalf("submit hook called during paste: %v", gotText)
	}
	atts := a.input.imageAttachments()
	if len(atts) != 1 || atts[0].path != "diagram.png" {
		t.Fatalf("pending attachments = %+v, want one diagram.png before submit", atts)
	}

	// Backspacing into the token removes the attachment: delete one byte inside "[diagram.png]".
	tokenStart := len("look ")
	a.input.Replace(tokenStart, tokenStart+1, "")
	if n := len(a.input.imageAttachments()); n != 0 {
		t.Fatalf("editing the token left %d pending attachments, want 0", n)
	}

	// Re-paste a clean mixed block, then submit: the token is stripped and one image part is sent.
	a.input.SetText("")
	pasteInto(a.input, "look diagram.png please")
	if !a.submitCurrent() {
		t.Fatal("submitCurrent rejected the pasted mixed image attachment")
	}
	// The token is stripped exactly, leaving the spaces that flanked it — the same
	// strip-in-place contract TestSubmitCurrent_TokenPartsInBufferOrder pins ("a  b"),
	// distinct from the typed-path extraction that drops a leading separator.
	if len(gotText) != 1 || gotText[0] != "look  please" {
		t.Fatalf("submitted text = %v, want one %q submission", gotText, "look  please")
	}
	if len(gotParts) != 1 || len(gotParts[0]) != 1 || gotParts[0][0].Type != "image_url" {
		t.Fatalf("submitted parts = %v, want one image_url part", gotParts)
	}
}

// TestPasteOutOfRootImagePathBlocked proves a pasted image path that escapes the project
// root (here an in-root symlink to an out-of-root file) is a concrete rejection at the paste
// boundary: nothing is attached, the pasted text is left editable, a notice is shown, and a
// subsequent submit is blocked rather than sending the rejected path as prose.
func TestPasteOutOfRootImagePathBlocked(t *testing.T) {
	var gotText []string
	var gotParts [][]sessions.ContentPart
	a, root := newImagePathApp(t, &gotText, &gotParts)
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.png"), pngMagic+"data")
	if err := os.Symlink(filepath.Join(outside, "secret.png"), filepath.Join(root, "link.png")); err != nil {
		t.Fatalf("symlink setup: %v", err)
	}

	pasteInto(a.input, "link.png")

	if n := len(a.input.imageAttachments()); n != 0 {
		t.Fatalf("pending attachments = %d, want 0 for an out-of-root pasted path", n)
	}
	if got := a.input.GetText(); got != "link.png" {
		t.Fatalf("input after rejected paste = %q, want the path retained for editing", got)
	}
	if a.transcript.notice == "" {
		t.Fatal("rejected pasted image path left no friendly notice")
	}
	if a.submitCurrent() {
		t.Fatal("submitCurrent accepted a rejected pasted image reference")
	}
	if len(gotText) != 0 || len(gotParts) != 0 {
		t.Fatalf("submit hook called with text=%v parts=%v, want no submission", gotText, gotParts)
	}
}

// TestSubmitCurrent_BlocksConcreteImagePathRejections proves an image-like typed path
// that resolves to a concrete rejected image reference does not silently become prose.
func TestSubmitCurrent_BlocksConcreteImagePathRejections(t *testing.T) {
	cases := []struct {
		name string
		// setup writes any fixtures under root and returns the token to type. Returning
		// the token lets a case build an absolute out-of-root path or an in-root symlink
		// whose name is not known until the temp dirs exist.
		setup func(t *testing.T, root string) string
	}{
		{
			name: "invalid image bytes",
			setup: func(t *testing.T, root string) string {
				writeFile(t, filepath.Join(root, "fake.png"), "not a png")
				return "fake.png"
			},
		},
		{
			name: "oversize image",
			setup: func(t *testing.T, root string) string {
				writeFile(t, filepath.Join(root, "big.png"), pngMagic+strings.Repeat("\x00", maxImageBytes+1-len(pngMagic)))
				return "big.png"
			},
		},
		{
			name: "ignored image",
			setup: func(t *testing.T, root string) string {
				writeFile(t, filepath.Join(root, "secrets", "key.png"), pngMagic+"data")
				writeFile(t, filetools.ProjectCodemeldignorePath(root), "secrets\n")
				return "secrets/key.png"
			},
		},
		{
			name: "absolute out-of-root png",
			setup: func(t *testing.T, root string) string {
				outside := t.TempDir()
				token := filepath.Join(outside, "secret.png")
				writeFile(t, token, pngMagic+"data")
				return token
			},
		},
		{
			name: "in-root symlink to out-of-root png",
			setup: func(t *testing.T, root string) string {
				outside := t.TempDir()
				writeFile(t, filepath.Join(outside, "secret.png"), pngMagic+"data")
				if err := os.Symlink(filepath.Join(outside, "secret.png"), filepath.Join(root, "link.png")); err != nil {
					t.Fatalf("symlink setup: %v", err)
				}
				return "link.png"
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotText []string
			var gotParts [][]sessions.ContentPart
			a, root := newImagePathApp(t, &gotText, &gotParts)
			token := tc.setup(t, root)
			input := "look at " + token
			a.input.SetText(input)

			if a.submitCurrent() {
				t.Fatal("submitCurrent accepted a rejected typed image reference")
			}
			if len(gotText) != 0 || len(gotParts) != 0 {
				t.Fatalf("submit hook called with text=%v parts=%v, want no submission", gotText, gotParts)
			}
			if got := a.input.GetText(); got != input {
				t.Fatalf("input after rejection = %q, want retained %q", got, input)
			}
			if a.transcript.notice == "" {
				t.Fatal("rejected image path left no friendly notice")
			}
		})
	}
}

// TestSubmitCurrent_LeavesUnresolvedImagePathAsText proves recognition is conservative:
// an image-extension token that does not resolve to an in-root image stays in the prompt
// as ordinary prose and attaches nothing.
func TestSubmitCurrent_LeavesUnresolvedImagePathAsText(t *testing.T) {
	var gotText []string
	var gotParts [][]sessions.ContentPart
	a, _ := newImagePathApp(t, &gotText, &gotParts)

	a.input.SetText("look at missing.png")
	if !a.submitCurrent() {
		t.Fatal("submitCurrent rejected a plain prompt")
	}
	if len(gotText) != 1 || gotText[0] != "look at missing.png" {
		t.Fatalf("submitted text = %v, want the unresolved path left as prose", gotText)
	}
	if len(gotParts) != 1 || len(gotParts[0]) != 0 {
		t.Fatalf("submitted parts = %v, want none for an unresolved path", gotParts)
	}
}

// TestSubmitCurrent_SlashCommandKeepsImagePathArg proves slash dispatch stays
// text-only: an image-path argument to a slash command is not extracted into an
// attachment and the command's argument text is preserved.
func TestSubmitCurrent_SlashCommandKeepsImagePathArg(t *testing.T) {
	var gotText []string
	var gotParts [][]sessions.ContentPart
	a, root := newImagePathApp(t, &gotText, &gotParts)
	writeFile(t, filepath.Join(root, "diagram.png"), pngMagic+"data")

	a.input.SetText("/cmd diagram.png")
	if !a.submitCurrent() {
		t.Fatal("submitCurrent rejected a slash command")
	}
	if len(gotText) != 1 || gotText[0] != "/cmd diagram.png" {
		t.Fatalf("slash text = %v, want the argument preserved (no image extraction)", gotText)
	}
	if len(gotParts) != 1 || len(gotParts[0]) != 0 {
		t.Fatalf("slash parts = %v, want none (slash dispatch is text-only)", gotParts)
	}
}

func TestSubmitCurrent_DropsFileRefAt(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		want      string
		wantParts int
	}{
		{name: "picker refs", input: "see @notes.md and @data/", want: "see notes.md and data/"},
		{name: "missing path", input: "@missing.txt", want: "missing.txt"},
		{name: "absolute path", input: "@/etc/hosts", want: "/etc/hosts"},
		{name: "parent path", input: "@../x", want: "../x"},
		{name: "entry named with at", input: "read @name", want: "read @name"},
		{name: "whitespace kept", input: "a\t@x\n\n@y", want: "a\tx\n\ny"},
		{name: "email", input: "mail a@b.com", want: "mail a@b.com"},
		{name: "lone at", input: "x @ y", want: "x @ y"},
		{name: "slash command", input: "/rename @notes.md", want: "/rename @notes.md"},
		{name: "in-root image", input: "see @diagram.png please", want: "see please", wantParts: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotText []string
			var gotParts [][]sessions.ContentPart
			a, root := newImagePathApp(t, &gotText, &gotParts)
			writeFile(t, filepath.Join(root, "@name"), "x")
			writeFile(t, filepath.Join(root, "diagram.png"), pngMagic+"data")

			a.input.SetText(tc.input)
			if !a.submitCurrent() {
				t.Fatal("submitCurrent rejected the prompt")
			}
			if len(gotText) != 1 || gotText[0] != tc.want {
				t.Fatalf("submitted text = %q, want %q", gotText, tc.want)
			}
			if len(gotParts[0]) != tc.wantParts {
				t.Fatalf("submitted parts = %d, want %d", len(gotParts[0]), tc.wantParts)
			}
		})
	}
}

func TestSubmitCurrent_FileRefAtOutOfRootImageBlocked(t *testing.T) {
	var gotText []string
	var gotParts [][]sessions.ContentPart
	a, root := newImagePathApp(t, &gotText, &gotParts)
	writeFile(t, filepath.Join(root, "..", "outside.png"), pngMagic+"data")

	a.input.SetText("look at ../outside.png")
	if a.submitCurrent() {
		t.Fatal("submitCurrent accepted an out-of-root image path")
	}
	want := a.transcript.notice
	if want == "" {
		t.Fatal("out-of-root image path left no notice")
	}
	a.ClearNotice()

	a.input.SetText("look at @../outside.png")
	if a.submitCurrent() {
		t.Fatal("submitCurrent accepted an out-of-root @ image path")
	}
	if len(gotText) != 0 {
		t.Fatalf("submit hook called with %q, want no submission", gotText)
	}
	if got := a.transcript.notice; got != want {
		t.Fatalf("notice = %q, want %q", got, want)
	}
}

func TestSubmitCurrent_EmptyWithNoAttachmentsRejected(t *testing.T) {
	var gotText []string
	var gotParts [][]sessions.ContentPart
	a := New(recordingPartsHook(true, &gotText, &gotParts))

	if a.submitCurrent() {
		t.Fatal("submitCurrent accepted an empty submission with no attachments")
	}
	if len(gotText) != 0 {
		t.Fatalf("hook called %d times for an empty submission, want 0", len(gotText))
	}
}

// recordingHook is a stub SubmitFunc that records the inputs it received and
// returns a fixed accept/reject verdict.
func recordingHook(accept bool, got *[]string) SubmitFunc {
	return func(input string, _ ...sessions.ContentPart) bool {
		*got = append(*got, input)
		return accept
	}
}

func newRecordingApp(accept bool, got *[]string, text string) *App {
	a := New(recordingHook(accept, got))
	a.input.SetText(text)
	return a
}

func TestSubmitCurrent_AcceptClearsField(t *testing.T) {
	var got []string
	a := newRecordingApp(true, &got, "hello")

	if !a.submitCurrent() {
		t.Fatal("submitCurrent returned false for an accepted submission")
	}
	if len(got) != 1 || got[0] != "hello" {
		t.Fatalf("hook received %v, want [hello]", got)
	}
	if txt := a.input.GetText(); txt != "" {
		t.Fatalf("field not cleared on accept: %q", txt)
	}
}

func TestSubmitCurrent_RejectRetainsField(t *testing.T) {
	var got []string
	a := newRecordingApp(false, &got, "keep me")

	if a.submitCurrent() {
		t.Fatal("submitCurrent returned true for a rejected submission")
	}
	if len(got) != 1 || got[0] != "keep me" {
		t.Fatalf("hook received %v, want [keep me]", got)
	}
	if txt := a.input.GetText(); txt != "keep me" {
		t.Fatalf("field not retained on reject: %q", txt)
	}
}

func TestSubmitCurrent_AcceptEchoesPromptToTranscript(t *testing.T) {
	var got []string
	a := newRecordingApp(true, &got, "how much is 5+5?")

	if !a.submitCurrent() {
		t.Fatal("submitCurrent returned false for an accepted submission")
	}
	// The accepted prompt is echoed as a committed transcript line carrying the teal user
	// rail; the raw committed line keeps the live rail color tags (GetText(false)).
	const railed = "[#1f9e8f]▌[-] how much is 5+5?"
	if got := a.transcript.view.GetText(false); got != railed {
		t.Fatalf("transcript after accept = %q, want %q", got, railed)
	}
	if len(a.transcript.lines) != 1 || a.transcript.lines[0] != railed {
		t.Fatalf("transcript lines = %v, want [%q]", a.transcript.lines, railed)
	}
}

func TestSubmitCurrent_RejectDoesNotEchoPrompt(t *testing.T) {
	var got []string
	a := newRecordingApp(false, &got, "/bogus")

	if a.submitCurrent() {
		t.Fatal("submitCurrent returned true for a rejected submission")
	}
	// Rejected/retained input must not be echoed (honors the slash-command retain-typed-input contract).
	if len(a.transcript.lines) != 0 {
		t.Fatalf("transcript lines = %v, want empty (rejected input not echoed)", a.transcript.lines)
	}
	if got := a.transcript.view.GetText(false); got != "" {
		t.Fatalf("transcript after reject = %q, want empty", got)
	}
}

func TestSubmitCurrent_TrimsInput(t *testing.T) {
	var got []string
	a := newRecordingApp(true, &got, "  spaced  ")

	if !a.submitCurrent() {
		t.Fatal("submitCurrent returned false for a trimmable submission")
	}
	if len(got) != 1 || got[0] != "spaced" {
		t.Fatalf("hook received %v, want [spaced]", got)
	}
}

func TestSubmitCurrent_IgnoresWhitespaceOnly(t *testing.T) {
	var got []string
	a := newRecordingApp(true, &got, "   ")

	if a.submitCurrent() {
		t.Fatal("submitCurrent returned true for whitespace-only input")
	}
	if len(got) != 0 {
		t.Fatalf("hook called for whitespace-only input: %v", got)
	}
	if txt := a.input.GetText(); txt != "   " {
		t.Fatalf("whitespace input altered: %q", txt)
	}
}

func TestSubmitCurrent_NilHookIsNoOp(t *testing.T) {
	a := New(nil)
	a.input.SetText("text")

	if a.submitCurrent() {
		t.Fatal("submitCurrent returned true with a nil hook")
	}
	if txt := a.input.GetText(); txt != "text" {
		t.Fatalf("field altered with nil hook: %q", txt)
	}
}

// TestSubmitCurrent_LongPasteSubmitsFullContent pins the long-paste submit contract: a
// long bracketed paste shows the placeholder in the visible buffer, but an accepted
// submit sends the full pasted content to the hook and clears both the visible text and
// the hidden paste state.
func TestSubmitCurrent_LongPasteSubmitsFullContent(t *testing.T) {
	var got []string
	a := New(recordingHook(true, &got))
	full := "f1\nf2\nf3\nf4\nf5\nf6"
	pasteInto(a.input, full)

	if vis := a.input.GetText(); vis != "[Pasted 6 lines — paste again to expand]" {
		t.Fatalf("visible buffer before submit = %q, want placeholder", vis)
	}
	if !a.submitCurrent() {
		t.Fatal("submitCurrent returned false for an accepted submission")
	}
	if len(got) != 1 || got[0] != full {
		t.Fatalf("hook received %v, want [%q] (full pasted content)", got, full)
	}
	if vis := a.input.GetText(); vis != "" {
		t.Fatalf("field not cleared on accept: %q", vis)
	}
	if len(a.input.pastes) != 0 {
		t.Fatalf("hidden paste state not cleared on accept: %d segments", len(a.input.pastes))
	}
}

// TestSubmitCurrent_RejectRetainsExpandablePaste pins the long-paste reject path: a rejected submit
// still hands the full content to the hook but leaves the visible placeholder and its
// hidden paste state intact, so the draft stays editable and re-submittable.
func TestSubmitCurrent_RejectRetainsExpandablePaste(t *testing.T) {
	var got []string
	a := New(recordingHook(false, &got))
	full := "r1\nr2\nr3\nr4\nr5\nr6"
	pasteInto(a.input, full)

	if a.submitCurrent() {
		t.Fatal("submitCurrent returned true for a rejected submission")
	}
	if len(got) != 1 || got[0] != full {
		t.Fatalf("hook received %v, want [%q] (full content even on reject)", got, full)
	}
	if vis := a.input.GetText(); vis != "[Pasted 6 lines — paste again to expand]" {
		t.Fatalf("visible buffer retained on reject = %q, want placeholder", vis)
	}
	if exp := submitTextOf(a.input); exp != full {
		t.Fatalf("hidden paste state lost on reject: expandedText() = %q, want %q", exp, full)
	}
}

// TestInputRows_GrowsWithScreenHeight pins the screen-height input cap: the input's text-row cap
// is computed from the live terminal height (not a fixed 8), so a buffer taller than
// any cap grows the input toward a taller screen — while every height still reserves at
// least minTranscriptRows for the conversation above.
func TestInputRows_GrowsWithScreenHeight(t *testing.T) {
	a := New(nil)
	const width = 80
	a.input.SetText(strings.Repeat("x\n", 200)) // far more rows than any cap under test

	short := a.inputRows(width, 24)
	tall := a.inputRows(width, 60)
	if tall <= short {
		t.Fatalf("input did not grow with screen height: 24-row screen = %d, 60-row screen = %d", short, tall)
	}

	// At the cap the transcript reservation is exactly minTranscriptRows: the cap
	// subtracts the same non-input chrome chromeRows adds back.
	for _, h := range []int{24, 40, 60} {
		avail := h - a.chromeRows(width, h)
		if avail != minTranscriptRows {
			t.Fatalf("screen height %d: transcript reservation = %d, want minTranscriptRows %d", h, avail, minTranscriptRows)
		}
	}
}

// TestInputRows_ExpandedPasteGrowsBox pins the screen-height input cap end-to-end: a collapsed
// paste keeps the one-line placeholder footprint, and re-pasting it (which expands the
// placeholder to the full text in place) grows the input row count well past it, up
// toward the available height.
func TestInputRows_ExpandedPasteGrowsBox(t *testing.T) {
	a := New(nil)
	const width, height = 80, 60
	full := strings.Repeat("line\n", 30) + "last" // 31 logical lines

	pasteInto(a.input, full) // first paste collapses to the one-line placeholder
	collapsed := a.inputRows(width, height)
	if collapsed != 1+inputChromeRows {
		t.Fatalf("collapsed-paste input height = %d, want one placeholder row + chrome %d", collapsed, 1+inputChromeRows)
	}

	pasteInto(a.input, full) // re-paste expands the placeholder back to full text
	expanded := a.inputRows(width, height)
	if expanded <= collapsed {
		t.Fatalf("expanded paste did not grow the input: collapsed = %d, expanded = %d", collapsed, expanded)
	}
}

func TestAppend_AccumulatesTranscriptLines(t *testing.T) {
	a := New(nil)
	a.Append("first")
	a.Append("second")

	if want := []string{"first", "second"}; !equalStrings(a.transcript.lines, want) {
		t.Fatalf("transcript lines = %v, want %v", a.transcript.lines, want)
	}
	if got := a.transcript.view.GetText(false); got != "first\n\nsecond" {
		t.Fatalf("rendered transcript = %q, want %q", got, "first\n\nsecond")
	}
}

func TestNotice_SetsAndRendersBelowTranscript(t *testing.T) {
	a := New(nil)
	a.Append("line")
	a.Notice("a notice")

	if a.transcript.notice != "a notice" {
		t.Fatalf("notice state = %q, want %q", a.transcript.notice, "a notice")
	}
	if got := a.transcript.view.GetText(false); got != "line\n\na notice" {
		t.Fatalf("rendered = %q, want %q", got, "line\n\na notice")
	}

	a.Notice("")
	if got := a.transcript.view.GetText(false); got != "line" {
		t.Fatalf("rendered after clearing notice = %q, want %q", got, "line")
	}
}

// TestSubmitCurrent_AcceptedClearsPinnedNoticeKeepsHistory proves an accepted
// submission clears any pinned transient notice before the new turn's output is
// shown, while the committed transcript history (a prior reply, the echoed prompt)
// is preserved — the notice is the only thing wiped.
func TestSubmitCurrent_AcceptedClearsPinnedNoticeKeepsHistory(t *testing.T) {
	var got []string
	a := New(recordingHook(true, &got))
	// A prior turn's committed reply plus a stale pinned notice (e.g. a leftover
	// transient hint) sit in the transcript when the next prompt is entered.
	a.Append("prior reply")
	a.Notice("stale pinned notice")
	a.input.SetText("next prompt")

	if !a.submitCurrent() {
		t.Fatal("submitCurrent returned false for an accepted submission")
	}
	if a.transcript.notice != "" {
		t.Errorf("notice = %q, want it cleared as the new submission was accepted", a.transcript.notice)
	}
	// Committed history is preserved: the prior reply and the freshly echoed prompt
	// remain as committed lines, separated by the block gap. Nothing is dropped.
	want := []string{"prior reply", "[#1f9e8f]▌[-] next prompt"}
	if !equalStrings(a.transcript.lines, want) {
		t.Fatalf("committed lines = %v, want %v (clear must not drop history)", a.transcript.lines, want)
	}
	if rendered := a.transcript.view.GetText(false); rendered != "prior reply\n\n[#1f9e8f]▌[-] next prompt" {
		t.Fatalf("rendered = %q, want the history with the notice gone", rendered)
	}
}

// TestSubmitCurrent_ClearBeforeDispatchLetsHandlerSetFreshNotice proves the
// notice clear runs before the submit hook dispatches, so a notice the handler
// itself sets during this submission survives (e.g. /model's marker disclosure or
// a validation error). A post-dispatch clear would wipe it.
func TestSubmitCurrent_ClearBeforeDispatchLetsHandlerSetFreshNotice(t *testing.T) {
	a := New(nil)
	a.Notice("stale notice from a prior turn")
	// The hook stands in for a command handler that sets its own notice during
	// dispatch and accepts the submission.
	a.SetSubmit(func(string, ...sessions.ContentPart) bool {
		a.Notice("this submission's own notice")
		return true
	})
	a.input.SetText("/somecmd")

	if !a.submitCurrent() {
		t.Fatal("submitCurrent returned false for an accepted submission")
	}
	if a.transcript.notice != "this submission's own notice" {
		t.Errorf("notice = %q, want the handler's fresh notice to survive the pre-dispatch clear", a.transcript.notice)
	}
}

// TestRun_LaunchesAndRoutesEnter starts the event loop against a simulation
// screen, confirms the input area renders, then injects text + Enter and
// verifies the keystrokes reach the submit hook and the field clears — proving
// keyboard-only operation through the real loop.
func TestRun_LaunchesAndRoutesEnter(t *testing.T) {
	submitted := make(chan string, 1)
	a := New(func(input string, _ ...sessions.ContentPart) bool {
		submitted <- input
		return true
	})

	h := newAppHarnessFor(t, a, 80, 25)

	// Read the rendered screen on the event-loop goroutine (screenTextSync) so
	// the read cannot run concurrently with the draw's screen.Show(): the
	// harness's afterDraw signal fires before Show(), so reading the screen here
	// directly both races Show()'s write to the cell buffer and can observe the
	// pre-Show (empty) front buffer that GetContents returns.
	if text := screenTextSync(a, h.screen); !strings.Contains(text, "›") {
		a.app.Stop()
		t.Fatalf("input prompt not rendered; screen = %q", text)
	}

	h.screen.InjectKeyBytes([]byte("hi"))
	h.screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)

	select {
	case got := <-submitted:
		if got != "hi" {
			t.Fatalf("hook received %q, want %q", got, "hi")
		}
	case <-time.After(2 * time.Second):
		a.app.Stop()
		t.Fatal("Enter did not reach the submit hook within 2s")
	}

	h.stop()
	if txt := a.input.GetText(); txt != "" {
		t.Fatalf("field not cleared after accepted submit: %q", txt)
	}
}

// TestRun_BracketedPasteInsertsWithoutSubmitting pins bracketed-paste insertion: a pasted
// block is buffered between EventPaste start/end markers and
// inserted into the focused prompt verbatim (newlines preserved) without ever
// reaching submitCurrent. A multi-line paste must NOT submit at its first line
// break — the bug bracketed paste fixes — and a single-line paste inserts normally and does
// not submit. The block is delivered the way tview's Run loop receives a real
// terminal paste: EventPaste(true), the pasted key events (a newline arrives as
// KeyEnter, which the loop converts to "\n" while pasting), then EventPaste(false),
// all through QueueEvent. This exercises the EnablePaste(true) gate — with paste
// mode off the Run loop drops the EventPaste markers and nothing inserts — so the
// test fails if the EnablePaste(true) call in New is missing.
func TestRun_BracketedPasteInsertsWithoutSubmitting(t *testing.T) {
	for _, tc := range []struct {
		name  string
		paste string
	}{
		{"multi-line", "line1\nline2"},
		{"single-line", "just one line"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var submissions []string
			a := New(recordingHook(true, &submissions))

			h := newAppHarnessFor(t, a, 80, 25)

			a.app.QueueEvent(tcell.NewEventPaste(true))
			for _, r := range tc.paste {
				if r == '\n' {
					a.app.QueueEvent(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone))
					continue
				}
				a.app.QueueEvent(tcell.NewEventKey(tcell.KeyRune, r, tcell.ModNone))
			}
			a.app.QueueEvent(tcell.NewEventPaste(false))

			// The end marker triggers the PasteHandler insert and a redraw; poll the
			// buffer (read on the event-loop goroutine) until it shows the pasted text.
			deadline := time.After(2 * time.Second)
			for inputTextSync(a) != tc.paste {
				select {
				case <-h.drawn:
				case <-deadline:
					got := inputTextSync(a)
					a.app.Stop()
					t.Fatalf("paste not inserted within 2s; buffer = %q, want %q", got, tc.paste)
				}
			}

			h.stop()
			if len(submissions) != 0 {
				t.Fatalf("paste submitted %v, want nothing submitted", submissions)
			}
		})
	}
}

// TestCompleteName_CursorOnNameTokenWithArgs proves the production Tab path honors
// the real cursor: with "/eff high" in the buffer and the cursor moved back onto
// the "/eff" name token (arguments already following), Tab completes the name to
// "/effort high". Keys are driven through the registered TextArea handler so the
// caret moves through the widget's own cursor exactly as it does at runtime, and
// inputField.Cursor reads it back as a rune offset. This fails against a completion
// that passes the buffer end as the cursor (the old len([]rune(text)) wiring),
// which would read the cursor as being in the argument region and no-op.
func TestCompleteName_CursorOnNameTokenWithArgs(t *testing.T) {
	a := New(nil)
	a.SetRegistry(tabTestRegistry(t))

	handler := a.input.InputHandler()
	noFocus := func(tview.Primitive) {}
	send := func(key tcell.Key) {
		handler(tcell.NewEventKey(key, 0, tcell.ModNone), noFocus)
	}

	a.input.SetText("/eff high") // cursor parks at the end (offset 9)
	// Walk the cursor left off the argument and back onto the "/eff" token.
	for i := 0; i < 6; i++ {
		send(tcell.KeyLeft) // 9 -> 3, inside "/eff"
	}
	if c := a.input.Cursor(); c != 3 {
		t.Fatalf("cursor after 6 Left = %d, want 3 (inside the name token)", c)
	}

	send(tcell.KeyTab)
	if txt := a.input.GetText(); txt != "/effort high" {
		t.Fatalf("Tab on the name token = %q, want %q", txt, "/effort high")
	}
}

// TestCompleteName_NonExtendablePrefixRendersMatchList proves the app-level Tab
// handler renders the candidate list for a non-extendable multi-match prefix:
// with "/e" in the buffer — which matches both "effort" and "exit"
// and cannot extend further — Tab leaves the input untouched and shows the two
// names on the one-line notice. Keys go through the registered InputField handler
// so the real handleInputKey → completeName → Notice path runs as at runtime. It
// fails if the tabList branch stops rendering the list (e.g. becomes a no-op).
func TestCompleteName_NonExtendablePrefixRendersMatchList(t *testing.T) {
	a := New(nil)
	a.SetRegistry(tabTestRegistry(t))

	handler := a.input.InputHandler()
	a.input.SetText("/e")
	handler(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone), func(tview.Primitive) {})

	if txt := a.input.GetText(); txt != "/e" {
		t.Fatalf("Tab on a non-extendable prefix changed the input to %q, want %q unchanged", txt, "/e")
	}
	if got := a.transcript.notice; got != "/effort  /exit" {
		t.Fatalf("match-list notice = %q, want %q", got, "/effort  /exit")
	}
}

// TestHandleInputKey_NewlineChordInsertsWithoutSubmitting pins the newline chord: typing
// "line1", the newline chord, then "line2" leaves the buffer
// "line1\nline2" and submits nothing. Both chords are covered — Ctrl+J (the
// guaranteed-everywhere fallback) and Ctrl+Enter (KeyEnter + ModCtrl, where the
// terminal reports the modifier). Keys go through the registered TextArea handler so
// the real handleInputKey → insertNewline path runs as at runtime.
func TestHandleInputKey_NewlineChordInsertsWithoutSubmitting(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chord *tcell.EventKey
	}{
		{"Ctrl+J", tcell.NewEventKey(tcell.KeyCtrlJ, 0, tcell.ModNone)},
		{"Ctrl+Enter", tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModCtrl)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			a := New(recordingHook(true, &got))
			handler := a.input.InputHandler()
			noFocus := func(tview.Primitive) {}
			send := func(ev *tcell.EventKey) { handler(ev, noFocus) }
			typeRunes := func(s string) {
				for _, r := range s {
					send(tcell.NewEventKey(tcell.KeyRune, r, tcell.ModNone))
				}
			}

			typeRunes("line1")
			send(tc.chord)
			typeRunes("line2")

			if txt := a.input.GetText(); txt != "line1\nline2" {
				t.Fatalf("buffer after %s = %q, want %q", tc.name, txt, "line1\nline2")
			}
			if len(got) != 0 {
				t.Fatalf("%s submitted %v, want nothing sent", tc.name, got)
			}
		})
	}
}

// TestHandleInputKey_PlainEnterSubmitsMultiLineBuffer pins the Enter-submits rule:
// plain Enter (no Ctrl) submits the whole multi-line buffer to the submit hook and
// clears the field on accept — the unchanged trim/history/echo/clear contract,
// applied to a buffer that now may contain newlines.
func TestHandleInputKey_PlainEnterSubmitsMultiLineBuffer(t *testing.T) {
	var got []string
	a := newRecordingApp(true, &got, "line1\nline2")
	handler := a.input.InputHandler()
	handler(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})

	if len(got) != 1 || got[0] != "line1\nline2" {
		t.Fatalf("plain Enter submitted %v, want one multi-line entry", got)
	}
	if txt := a.input.GetText(); txt != "" {
		t.Fatalf("field not cleared after accepted multi-line submit: %q", txt)
	}
}

// TestHandleInputKey_MultiLineArrowsRespectLineEdges pins multi-line history navigation: ↑
// on the first line and ↓ on the last line drive input history, while ↑/↓ on an
// interior position of a multi-line draft fall through to caret movement and leave
// the buffer (and history) untouched.
func TestHandleInputKey_MultiLineArrowsRespectLineEdges(t *testing.T) {
	var got []string
	a := newRecordingApp(true, &got, "recalled")
	a.submitCurrent() // history now holds "recalled"

	a.input.SetText("alpha\nbravo") // caret parks at the end -> last line
	handler := a.input.InputHandler()
	noFocus := func(tview.Primitive) {}
	key := func(k tcell.Key) *tcell.EventKey { return tcell.NewEventKey(k, 0, tcell.ModNone) }

	// Caret on the last line, above the first: ↑ is interior cursor movement, so it
	// falls through (non-nil) and must not load history.
	if ev := a.handleInputKey(key(tcell.KeyUp)); ev == nil {
		t.Fatal("↑ between lines should fall through to cursor movement, not history")
	}
	if txt := a.input.GetText(); txt != "alpha\nbravo" {
		t.Fatalf("↑ between lines changed the buffer to %q, want it unchanged", txt)
	}
	// ↓ on the last line with no navigation underway is consumed (history edge) and
	// leaves the live draft untouched.
	if ev := a.handleInputKey(key(tcell.KeyDown)); ev != nil {
		t.Fatal("↓ on the last line should be consumed at the history edge, not fall through")
	}
	if txt := a.input.GetText(); txt != "alpha\nbravo" {
		t.Fatalf("↓ on the last line clobbered the draft: %q", txt)
	}

	// Walk the caret back onto the first line (past the newline), then ↑ navigates
	// history: it saves the draft and loads the recalled entry.
	for i := 0; i < 6; i++ {
		handler(key(tcell.KeyLeft), noFocus) // end of "bravo" (11) -> end of "alpha" (5)
	}
	if c := a.input.Cursor(); c != 5 {
		t.Fatalf("cursor after 6 Left = %d, want 5 (end of the first line)", c)
	}
	if ev := a.handleInputKey(key(tcell.KeyUp)); ev != nil {
		t.Fatal("↑ on the first line should be consumed as history navigation")
	}
	if txt := a.input.GetText(); txt != "recalled" {
		t.Fatalf("↑ on the first line = %q, want the recalled history entry", txt)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func badgeSession(title, source string) *sessions.Session {
	return &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
			Folder:        "/home/u/proj",
			StartedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			UpdatedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			SchemaVersion: 1,
			Title:         title,
			TitleSource:   source,
		},
	}
}

func TestSessionBadge_ShowsStoredTitleReadFromDisk(t *testing.T) {
	cases := []struct {
		name   string
		title  string
		source string
	}{
		{"user_set", "My session", sessions.TitleSourceUser},
		{"generated", "Auto title", sessions.TitleSourceGenerated},
		{"legacy_no_provenance", "Legacy name", ""},
		{"untitled", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "session.json")
			data, err := sessions.Marshal(badgeSession(tc.title, tc.source))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatalf("write session: %v", err)
			}
			sess, _, err := sessions.OpenSession(path)
			if err != nil {
				t.Fatalf("open session: %v", err)
			}
			if sess.Metadata.TitleSource != tc.source {
				t.Fatalf("title_source read back = %q, want %q", sess.Metadata.TitleSource, tc.source)
			}
			a := New(nil)
			a.SetActiveStore(sessions.New(path, sess))

			if badge := a.SessionBadgeText(); badge != tc.title {
				t.Errorf("badge = %q, want the stored title %q", badge, tc.title)
			}
			row := a.ModeHintText()
			if tc.title != "" && strings.Contains(row, tc.title) {
				t.Errorf("mode row = %q, want the session name off the footer", row)
			}
			if !strings.Contains(row, "• plan") || !strings.Contains(row, statusBarHint) {
				t.Errorf("mode row = %q, want only the mode pill and shift+tab hint", row)
			}
		})
	}
}

func TestSessionBadge_TracksActiveStoreReplacement(t *testing.T) {
	a := New(nil)
	named := sessions.New("", badgeSession("My session", sessions.TitleSourceUser))
	generated := sessions.New("", badgeSession("Auto title", sessions.TitleSourceGenerated))

	a.SetActiveStore(named)
	if got := a.SessionBadgeText(); got != "My session" {
		t.Fatalf("badge = %q, want the user-set name after installing the named session", got)
	}

	a.SetActiveStore(generated)
	if got := a.SessionBadgeText(); got != "Auto title" {
		t.Fatalf("badge = %q, want the replacement store's generated title", got)
	}

	a.SetActiveStore(named)
	if got := a.SessionBadgeText(); got != "My session" {
		t.Errorf("badge = %q, want the name restored after switching back", got)
	}
}

// TestSessionBadge_ActiveStoreSwapRepaintsWhileRunning drives the swap on the event-loop
// goroutine — where every production SetActiveStore caller (/clear, /resume, /fork,
// /compact) runs — and reads the screen without forcing a draw, so the badge can only be
// there if the refresh repainted. QueueUpdate rather than QueueUpdateDraw: the latter would
// draw for us and prove nothing.
func TestSessionBadge_ActiveStoreSwapRepaintsWhileRunning(t *testing.T) {
	h := newAppHarness(t, 80, 24)
	defer h.stop()
	// The harness drives a.app.Run directly, so mirror the running flag App.Run would
	// have set: it is what routes streamUpdate-style helpers onto QueueUpdateDraw, and a
	// refresh that took that route from the loop goroutine would hang instead of repaint.
	h.a.running.Store(true)
	defer h.a.running.Store(false)

	swapped := make(chan struct{})
	go func() {
		h.a.app.QueueUpdate(func() {
			h.a.SetActiveStore(sessions.New("", badgeSession("My session", sessions.TitleSourceUser)))
		})
		close(swapped)
	}()
	select {
	case <-swapped:
	case <-time.After(2 * time.Second):
		h.a.app.Stop()
		t.Fatal("SetActiveStore did not return within 2s: the badge refresh blocked the event loop it runs on")
	}

	deadline := time.Now().Add(2 * time.Second)
	for got := screenTextSync(h.a, h.screen); !strings.Contains(got, "My session"); got = screenTextSync(h.a, h.screen) {
		if time.Now().After(deadline) {
			t.Fatalf("screen = %q, want the swapped-in name drawn by the refresh's queued redraw, with no later UI event", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRefreshSessionBadge_NonActiveStoreChangesNothing(t *testing.T) {
	a := New(nil)
	active := sessions.New("", badgeSession("Active", sessions.TitleSourceUser))
	other := sessions.New("", badgeSession("Other", sessions.TitleSourceGenerated))
	a.SetActiveStore(active)

	for _, store := range []*sessions.Store{other, nil} {
		a.RefreshSessionBadge(store)
		if got := a.SessionBadgeText(); got != "Active" {
			t.Errorf("badge after refreshing %p = %q, want the active store's title", store, got)
		}
		if a.ActiveStore() != active {
			t.Errorf("refreshing %p replaced the active store", store)
		}
	}
}

func TestSessionBadge_SetActiveStoreNilClearsBadge(t *testing.T) {
	a := New(nil)
	a.SetActiveStore(sessions.New("", badgeSession("My session", sessions.TitleSourceUser)))
	a.SetActiveStore(nil)
	if got := a.SessionBadgeText(); got != "" {
		t.Errorf("badge = %q, want it cleared with no active store", got)
	}
	if a.ActiveStore() != nil {
		t.Error("active store is not nil after SetActiveStore(nil)")
	}
}

func TestRefreshSessionBadge_BackgroundRefreshRacingReplacementEndsOnNewStore(t *testing.T) {
	a, stop := newRunningApp(t)
	defer stop()
	old := sessions.New("", badgeSession("Old", sessions.TitleSourceGenerated))
	replacement := sessions.New("", badgeSession("New", sessions.TitleSourceGenerated))

	for i := range 200 {
		a.SetActiveStore(old)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); a.RefreshSessionBadge(old) }()
		go func() { defer wg.Done(); a.SetActiveStore(replacement) }()
		wg.Wait()
		if got := a.SessionBadgeText(); got != "New" {
			t.Fatalf("iteration %d: badge = %q, want the replacement store's title", i, got)
		}
		if a.ActiveStore() != replacement {
			t.Fatalf("iteration %d: the background refresh changed the active store", i)
		}
	}
}

func TestRefreshSessionBadge_FromEventLoopRedrawsOnLoopWithoutDeadlock(t *testing.T) {
	a, stop := newRunningApp(t)
	defer stop()
	var loopBusy, drewOffLoop atomic.Bool
	drawn := make(chan struct{}, 1)
	a.draw = func() {
		if loopBusy.Load() {
			drewOffLoop.Store(true)
		}
		select {
		case drawn <- struct{}{}:
		default:
		}
	}

	returned := make(chan struct{})
	go a.app.QueueUpdate(func() {
		loopBusy.Store(true)
		a.SetActiveStore(sessions.New("", badgeSession("Auto title", sessions.TitleSourceGenerated)))
		close(returned)
		time.Sleep(50 * time.Millisecond)
		loopBusy.Store(false)
	})
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		a.app.Stop()
		t.Fatal("refresh called on the event loop did not return within 2s")
	}
	select {
	case <-drawn:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh on a running app queued no redraw")
	}
	if drewOffLoop.Load() {
		t.Error("redraw ran while the event loop was busy, so not on the event loop")
	}
	if got := a.SessionBadgeText(); got != "Auto title" {
		t.Errorf("badge = %q, want the refreshed title", got)
	}
}

func TestRefreshSessionBadge_AfterShutdownBeginsUpdatesTextWithoutRedraw(t *testing.T) {
	a, stop := newRunningApp(t)
	defer func() {
		a.app.Stop()
		stop()
	}()
	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), badgeSession("Before", sessions.TitleSourceUser))
	var draws atomic.Int32
	a.draw = func() { draws.Add(1) }
	a.SetActiveStore(store)
	deadline := time.Now().Add(2 * time.Second)
	for draws.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("SetActiveStore on a running app queued no redraw")
		}
		time.Sleep(5 * time.Millisecond)
	}
	draws.Store(0)

	a.BeginShutdown()
	if _, _, err := store.FlushTitle(context.Background(), "After"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	returned := make(chan struct{})
	go func() {
		a.RefreshSessionBadge(store)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh after shutdown began did not return")
	}
	a.app.QueueUpdate(func() {})
	if got := a.SessionBadgeText(); got != "After" {
		t.Errorf("badge = %q, want the text still updated after shutdown began", got)
	}
	if n := draws.Load(); n != 0 {
		t.Errorf("draws after shutdown began = %d, want 0", n)
	}
}

func TestRunBackgroundAfterDraw_CompletionQueuedBeforeShutdownIsDropped(t *testing.T) {
	a, stop := newRunningApp(t)
	defer func() {
		a.app.Stop()
		stop()
	}()
	workStarted, releaseWork, workDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	completed := make(chan struct{})
	a.RunBackgroundAfterDraw(func() error {
		close(workStarted)
		<-releaseWork
		close(workDone)
		return nil
	}, func(error) { close(completed) })
	<-workStarted

	releaseLoop := make(chan struct{})
	loopHeld := make(chan struct{})
	go a.app.QueueUpdate(func() {
		close(loopHeld)
		<-releaseLoop
	})
	<-loopHeld
	close(releaseWork)
	<-workDone
	time.Sleep(50 * time.Millisecond)
	a.BeginShutdown()
	close(releaseLoop)

	select {
	case <-completed:
		t.Fatal("completion ran after shutdown began")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestRunBackgroundAfterDraw_AfterRunEndsRunsNothing(t *testing.T) {
	a, stop := newRunningApp(t)
	a.Stop()
	stop()

	var ran atomic.Bool
	a.RunBackgroundAfterDraw(func() error {
		ran.Store(true)
		return nil
	}, func(error) { ran.Store(true) })
	if ran.Load() {
		t.Error("work or completion ran after shutdown with Run no longer active")
	}
}

func TestRunBackgroundAfterDraw_BeforeRunRunsDirectly(t *testing.T) {
	a := New(nil)
	want := errors.New("work failed")
	var got error
	completed := false
	a.RunBackgroundAfterDraw(func() error { return want }, func(err error) {
		got, completed = err, true
	})
	if !completed || got != want {
		t.Errorf("completed = %v with %v, want a direct completion with %v", completed, got, want)
	}
}

func TestFitSessionBadge_FitsTheRuleWidth(t *testing.T) {
	// 40 columns leave the badge 28 cells: the 2-column right margin, the 8-column
	// left-rule reserve, and its own two padding spaces come off first.
	const width = 40

	if got, want := fitSessionBadge("My session", width), " My session "; got != want {
		t.Errorf("fitSessionBadge(short) = %q, want %q", got, want)
	}
	if got := fitSessionBadge("", width); got != "" {
		t.Errorf("fitSessionBadge(no name) = %q, want empty", got)
	}

	long := fitSessionBadge(strings.Repeat("n", 60), width)
	if want := " " + strings.Repeat("n", 27) + "… "; long != want {
		t.Errorf("fitSessionBadge(long) = %q, want %q", long, want)
	}

	wide := fitSessionBadge(strings.Repeat("界", 30), width)
	if want := " " + strings.Repeat("界", 13) + "… "; wide != want {
		t.Errorf("fitSessionBadge(wide runes) = %q, want %q", wide, want)
	}

	for _, width := range []int{12, 13} {
		if got := fitSessionBadge("My session", width); got != "" {
			t.Errorf("fitSessionBadge at width %d = %q, want the badge dropped so 8 rule columns survive", width, got)
		}
	}
	if got := fitSessionBadge("My session", 14); got != " M… " {
		t.Errorf("fitSessionBadge at the narrowest fitting width = %q, want %q", got, " M… ")
	}
}

func TestSessionBadge_OnlyAnAcceptedSubmitRefreshesIt(t *testing.T) {
	renameApp := func(store *sessions.Store) *App {
		a := New(func(input string, _ ...sessions.ContentPart) bool {
			name := strings.TrimPrefix(input, "/rename ")
			_, _, err := store.FlushTitle(context.Background(), name)
			return err == nil
		})
		a.SetActiveStore(store)
		return a
	}

	t.Run("persisted", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "session.json")
		a := renameApp(sessions.New(path, badgeSession("", "")))
		if !a.SubmitInput("/rename My session") {
			t.Fatal("submit rejected a rename whose write succeeded")
		}
		if got := a.SessionBadgeText(); got != "My session" {
			t.Errorf("badge = %q, want the persisted name after a rename", got)
		}
	})

	t.Run("write_failed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "no-such-subdir", "session.json")
		store := sessions.New(path, badgeSession("", ""))
		a := renameApp(store)
		if a.SubmitInput("/rename My session") {
			t.Fatal("submit accepted a rename whose write failed")
		}
		if got := store.Title(); got != "" {
			t.Fatalf("in-memory title = %q, want the prior empty title restored", got)
		}
		if got := a.SessionBadgeText(); got != "" {
			t.Errorf("badge = %q, want none past a failed durability boundary", got)
		}

		a.SetSubmit(func(string, ...sessions.ContentPart) bool { return true })
		if !a.SubmitInput("continue") {
			t.Fatal("later ordinary submission was rejected")
		}
		if got := a.SessionBadgeText(); got != "" {
			t.Errorf("badge = %q, want no failed-rename badge after a later accepted submit", got)
		}
	})
}

// screenTextSync returns the rendered simulation screen text, read on the
// application's event-loop goroutine via QueueUpdate. Reading there serializes
// the read with the draws that mutate the screen through screen.Show(), so the
// race detector observes no concurrent access to the cell buffer that
// GetContents returns, and the read happens only after Show() has populated the
// front buffer.
func screenTextSync(a *App, s tcell.SimulationScreen) string {
	var text string
	a.app.QueueUpdate(func() {
		text = screenText(s)
	})
	return text
}

// inputTextSync reads the input buffer on the application's event-loop goroutine
// via QueueUpdate (which returns only after the function has executed), so the read
// is serialized with the paste insert and draw that mutate the buffer and never
// races them.
func inputTextSync(a *App) string {
	var text string
	a.app.QueueUpdate(func() { text = a.input.GetText() })
	return text
}

func TestCloseOverlayPage_RestoresCapturedFocusAndClearsField(t *testing.T) {
	a := New(nil)
	captured := tview.NewBox()
	prev := tview.Primitive(captured)
	a.pages.AddPage("probe-overlay", wrapOverlayPage(tview.NewBox()), true, true)
	a.app.SetFocus(tview.NewBox())

	a.closeOverlayPage("probe-overlay", &prev)

	if a.pages.HasPage("probe-overlay") {
		t.Error("overlay page still mounted after the shared teardown")
	}
	if a.app.GetFocus() != captured {
		t.Errorf("focus = %T, want the captured prior primitive", a.app.GetFocus())
	}
	if prev != nil {
		t.Error("prior-focus field not cleared; a repeated dismissal would restore stale focus")
	}
}

func TestCloseOverlayPage_NilCapturedFocusFallsBackToInput(t *testing.T) {
	a := New(nil)
	var prev tview.Primitive
	a.pages.AddPage("probe-overlay", wrapOverlayPage(tview.NewBox()), true, true)
	a.app.SetFocus(tview.NewBox())

	a.closeOverlayPage("probe-overlay", &prev)

	if a.app.GetFocus() != a.input {
		t.Errorf("focus = %T, want the input area when nothing was captured", a.app.GetFocus())
	}
	if prev != nil {
		t.Error("prior-focus field set by a nil-capture teardown")
	}
}

func TestCloseOverlayPage_LeavesOtherPagesMounted(t *testing.T) {
	a := New(nil)
	var prev tview.Primitive
	a.pages.AddPage("probe-overlay", wrapOverlayPage(tview.NewBox()), true, true)
	a.pages.AddPage("other-overlay", wrapOverlayPage(tview.NewBox()), true, false)

	a.closeOverlayPage("probe-overlay", &prev)

	if !a.pages.HasPage("other-overlay") {
		t.Error("shared teardown removed a page it was not given")
	}
}

// drawPrimitive lays out and draws p at a w×h rect on a fresh simulation screen,
// then flips it to the front buffer so GetContents reflects the rendered cells. It
// runs no event loop — the primitive's own Draw assigns its children's rects — so a
// test can inspect rendered geometry and per-cell style synchronously.
func drawPrimitive(t *testing.T, p tview.Primitive, w, h int) tcell.SimulationScreen {
	t.Helper()
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init: %v", err)
	}
	screen.SetSize(w, h)
	p.SetRect(0, 0, w, h)
	p.Draw(screen)
	screen.Show()
	return screen
}

// screenText flattens the simulation screen's cell contents into a string so a
// test can assert that expected glyphs were rendered.
func screenText(s tcell.SimulationScreen) string {
	cells, width, height := s.GetContents()
	var b strings.Builder
	for row := 0; row < height; row++ {
		for col := 0; col < width; col++ {
			runes := cells[row*width+col].Runes
			if len(runes) == 0 {
				b.WriteRune(' ')
				continue
			}
			b.WriteString(string(runes))
		}
	}
	return b.String()
}

func semanticSecurityHalt() events.SecurityStateHalted {
	return events.SecurityStateHalted{
		Path:           "/home/u/.codemeld/settings.yaml",
		DetectionPoint: events.SecurityDetectionBeforeMutatingCall,
		Sections:       []string{"permissions", "provider_credential"},
	}
}

// The halt element is what tells a user their protected settings are no longer what the
// session started with, so none of the ordinary paths that take the transient notice down
// may take it with them.
func TestSecurityHalt_SurvivesSubmitModelChangeAndClearNotice(t *testing.T) {
	var got []string
	var parts [][]sessions.ContentPart
	a := New(recordingPartsHook(true, &got, &parts))
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: selectedModelCatalog(), Applier: &providerModelApplierFake{}})
	a.SecurityHalt([]events.SecurityStateHalted{semanticSecurityHalt()})

	stillPinned := func(t *testing.T, after string) {
		t.Helper()
		if !strings.Contains(a.TranscriptText(), securityHaltHeading) {
			t.Fatalf("the security halt element is gone after %s:\n%s", after, a.TranscriptText())
		}
	}
	stillPinned(t, "the halt itself")

	a.Notice("a transient notice")
	stillPinned(t, "a transient notice")
	if a.NoticeText() == "" {
		t.Fatal("the transient notice was swallowed by the halt element")
	}

	a.ClearNotice()
	stillPinned(t, "ClearNotice")
	if a.NoticeText() != "" {
		t.Fatalf("transient notice = %q, want it cleared", a.NoticeText())
	}

	a.input.SetText("next prompt")
	if !a.submitCurrent() {
		t.Fatal("submitCurrent rejected the prompt")
	}
	stillPinned(t, "a submission")

	a.confirmModelSelection(ProviderModel{Provider: "anthropic", ModelID: "claude-x"}, "default")
	stillPinned(t, "a model change")
}

// The notice repeats only what the checkpoint reported: the affected file, and the sections
// only when it could classify them. It never invents a section, and never says a grant was
// revoked — the settings changed underneath the session, which is a different claim.
func TestSecurityHalt_NamesSectionsOnlyWhenTheCheckpointSuppliedThem(t *testing.T) {
	for _, tc := range []struct {
		name     string
		records  []events.SecurityStateHalted
		wants    []string
		notWants []string
	}{
		{
			name:    "semantic drift",
			records: []events.SecurityStateHalted{semanticSecurityHalt()},
			wants: []string{
				securityHaltHeading,
				"/home/u/.codemeld/settings.yaml: permissions, provider_credential",
				securityHaltAction,
			},
			notWants: []string{securityHaltUninspected},
		},
		{
			name: "malformed",
			records: []events.SecurityStateHalted{{
				Path: "/home/u/proj/.codemeld/settings.yaml", DetectionPoint: events.SecurityDetectionStartup,
				Labels: []string{"malformed"},
			}},
			wants:    []string{"/home/u/proj/.codemeld/settings.yaml: " + securityHaltUninspected},
			notWants: []string{"permissions", "auth", "malformed"},
		},
		{
			name: "unavailable",
			records: []events.SecurityStateHalted{{
				Path: "/home/u/proj/.codemeld/settings.yaml", DetectionPoint: events.SecurityDetectionStartup,
				UnavailableReason: "lock_timeout",
			}},
			wants:    []string{"/home/u/proj/.codemeld/settings.yaml: " + securityHaltUninspected},
			notWants: []string{"permissions", "lock_timeout"},
		},
		{
			name: "both layers at once",
			records: []events.SecurityStateHalted{
				semanticSecurityHalt(),
				{
					Path: "/home/u/proj/.codemeld/settings.yaml", DetectionPoint: events.SecurityDetectionBeforeMutatingCall,
					UnavailableReason: "lock_acquire_error",
				},
			},
			wants: []string{
				"/home/u/.codemeld/settings.yaml: permissions, provider_credential",
				"/home/u/proj/.codemeld/settings.yaml: " + securityHaltUninspected,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.SecurityHalt(tc.records)
			text := a.TranscriptText()
			for _, want := range tc.wants {
				if !strings.Contains(text, want) {
					t.Errorf("halt element missing %q:\n%s", want, text)
				}
			}
			for _, notWant := range tc.notWants {
				if strings.Contains(text, notWant) {
					t.Errorf("halt element unexpectedly contains %q:\n%s", notWant, text)
				}
			}
			for _, forbidden := range []string{"revoke", "revoked", "openai", "sk_live", "api_key"} {
				if strings.Contains(text, forbidden) {
					t.Errorf("halt element leaks or overclaims with %q:\n%s", forbidden, text)
				}
			}
		})
	}
}

// A settings path is a filesystem name, so it can carry a newline, a carriage return, or a
// tab. Collapsing them is what keeps one affected file to one line of the element instead of
// letting it forge extra ones.
func TestSecurityHalt_CollapsesControlCharactersInThePath(t *testing.T) {
	a := New(nil)
	a.SecurityHalt([]events.SecurityStateHalted{{
		Path:           "/home/u/\nfake heading\r\tproj/.codemeld/settings.yaml",
		DetectionPoint: events.SecurityDetectionStartup,
		Labels:         []string{"missing"},
	}})

	text := a.TranscriptText()
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("halt element rendered %d lines, want heading + one file + action:\n%s", len(lines), text)
	}
	if strings.Contains(lines[1], "\r") || strings.Contains(lines[1], "\t") {
		t.Errorf("file line kept a control character: %q", lines[1])
	}
}

// A halt during a stream leaves the partial reply visible and marked interrupted, but it is
// never committed as a finished reply and nothing at all is recorded from this seam — the
// stream_interrupted vocabulary stays reserved for a user-initiated stop.
func TestSecurityHalt_SealsPartialStreamWithoutCommittingAReply(t *testing.T) {
	a := New(nil)
	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), &sessions.Session{})
	a.SetActiveStore(store)
	a.AppendStreamDelta("partial")

	a.SecurityHalt([]events.SecurityStateHalted{semanticSecurityHalt()})

	text := a.TranscriptText()
	if !strings.Contains(text, "partial"+streamInterruptedMarker) {
		t.Fatalf("partial reply was not sealed as interrupted:\n%s", text)
	}
	if !strings.Contains(text, securityHaltHeading) {
		t.Fatalf("halt element is missing after sealing the stream:\n%s", text)
	}
	if a.transcript.streaming {
		t.Error("the stream buffer stayed open after the halt")
	}
	if n := len(store.Records()); n != 0 {
		t.Fatalf("the halt seam recorded %d record(s), want 0", n)
	}
}

func TestRefreshStatusLineFromBackground_BeforeRunWhileRunningAndAfterShutdown(t *testing.T) {
	state := &statusStateFake{launchDir: "/work", sandbox: "on"}
	a := New(nil)
	a.SetStatusLineState(state)
	state.sandbox = "unavailable"
	a.RefreshStatusLineFromBackground()
	if got := a.StatusLineText(); !strings.Contains(got, "sandbox: unavailable") {
		t.Fatalf("status line before Run = %q, want sandbox: unavailable", got)
	}

	screen := tcell.NewSimulationScreen("UTF-8")
	a.newScreen = func() (tcell.Screen, error) { return screen, nil }
	errC := make(chan error, 1)
	go func() { errC <- a.Run() }()
	waitLoopRunning(t, a)
	defer func() {
		a.Stop()
		if err := <-errC; err != nil {
			t.Errorf("App.Run: %v", err)
		}
	}()
	statusLine := func() (text string, hits int) {
		a.app.QueueUpdate(func() { text, hits = a.StatusLineText(), state.capHits })
		return text, hits
	}

	state.sandbox = "on"
	a.RefreshStatusLineFromBackground()
	got, hits := statusLine()
	if !strings.Contains(got, "sandbox: on") {
		t.Fatalf("status line on the running loop = %q, want sandbox: on", got)
	}

	a.BeginShutdown()
	state.sandbox = "unavailable"
	returned := make(chan struct{})
	go func() {
		a.RefreshStatusLineFromBackground()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("a background refresh after shutdown began did not return")
	}
	if after, afterHits := statusLine(); after != got || afterHits != hits {
		t.Fatalf("status line after shutdown = %q (%d reads), want %q unchanged (%d reads)", after, afterHits, got, hits)
	}
}
