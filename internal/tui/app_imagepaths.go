package tui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// noClipboardHelperNotice is the friendly one-line message shown when CTRL-V finds no
// clipboard-image helper installed for this platform/session. It names the
// optional helpers so the user knows what to install.
const noClipboardHelperNotice = "no clipboard image helper found; install wl-paste, xclip, xsel, or pngpaste"

// handleClipboardImage is the CTRL-V clipboard-image action: it reads an
// image off the OS clipboard through the installed reader and, on success, adds it as a
// pending image token that submits through the content-part path unchanged (the same
// addAttachment → submitText → submit→persist flow the '@' picker uses). Every
// failure mode — no helper installed, clipboard holds no image, a helper error or
// timeout, or bytes that are not a supported image — yields a friendly one-line notice
// and adds nothing; it never panics. It is inert while an overlay is open and
// while no reader is wired. The read is bounded by clipboardReadTimeout so a stuck
// helper cannot freeze the event loop.
func (a *App) handleClipboardImage() {
	if a.anyOverlayOpen() || a.clipboard == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), clipboardReadTimeout)
	defer cancel()
	_, data, ok, err := a.clipboard.ReadImage(ctx)
	switch {
	case errors.Is(err, errNoClipboardHelper):
		a.Notice(noClipboardHelperNotice)
		return
	case errors.Is(err, errClipboardTimeout):
		a.Notice("clipboard read timed out")
		return
	case err != nil:
		a.Notice("could not read an image from the clipboard")
		return
	case !ok:
		a.Notice("no image found in the clipboard")
		return
	}
	// The reader's claimed mime is ignored: newClipboardAttachment re-sniffs the bytes
	// and enforces the size cap, so a clipboard image meets the exact same constraints
	// as an attached file.
	att, err := newClipboardAttachment(data)
	if err != nil {
		a.Notice(imageAttachErrorNotice("clipboard image", err))
		return
	}
	// The clipboard carries no filename, so the input field assigns the per-prompt "Image N"
	// label only now that the read succeeded (a failed read above consumes no counter value);
	// stamp it on the attachment too so the notice and transcript placeholder read it.
	label := a.input.nextClipboardLabel()
	att.name = label
	a.input.addAttachment(att, label)
	a.Notice(attachedImageNotice(att))
}

// imagePathRejection identifies an image-like path that resolved far enough to be a
// concrete attachment rejection. Missing files remain prose; known image failures do not
// silently get sent to the model as text.
type imagePathRejection struct {
	path string
	err  error
}

// extractImagePathAttachments scans text for whitespace-delimited tokens that resolve to
// supported in-root images, returning the text with those tokens removed and the resolved
// attachments. It is used at submit for typed paths and after short pastes for
// pasted paths. Only tokens with an image extension touch the filesystem. Missing/unresolved
// names stay prose, while concrete image-reference rejections (oversize, ignored, existing
// file with non-image bytes) are reported so callers can show a notice and avoid silently
// sending them as text.
func (a *App) extractImagePathAttachments(text string) (string, []imageAttachment, *imagePathRejection) {
	projectRoot := a.refProjectRoot()
	if projectRoot == "" || a.home == "" || text == "" {
		return text, nil, nil
	}
	var atts []imageAttachment
	var rejection *imagePathRejection
	var b strings.Builder
	for i := 0; i < len(text); {
		// One segment is the leading whitespace run plus the token after it. Dropping a
		// recognized image path removes its whole segment (its leading separator too), so
		// "see foo.png please" collapses to "see please" rather than leaving a double space.
		segStart := i
		for i < len(text) && isInputSpace(text[i]) {
			i++
		}
		tokenStart := i
		for i < len(text) && !isInputSpace(text[i]) {
			i++
		}
		token := text[tokenStart:i]
		if token != "" && isImageExtension(token) {
			if att, err := resolveImageAttachment(projectRoot, a.home, token); err == nil {
				atts = append(atts, att)
				continue // drop the recognized path segment from the prompt text
			} else if rejection == nil && isConcreteImageRejection(err) {
				rejection = &imagePathRejection{path: token, err: err}
			}
		}
		b.WriteString(text[segStart:i])
	}
	return strings.TrimSpace(b.String()), atts, rejection
}

// pastedImagePath is one recognized image path found in a short paste: the [start,end) byte
// range it occupies within the pasted text, the resolved attachment, and the basename label its
// "[<basename>]" token will show. attachPastedImagePaths uses these to replace each path with a
// removable token at its original position instead of stripping it and appending tokens at the
// end.
type pastedImagePath struct {
	start, end int
	att        imageAttachment
	label      string
}

// scanPastedImagePaths finds the whitespace-delimited image paths in a short paste that resolve
// to supported in-root images, returning each one's in-text range, attachment, and basename
// label, plus the first concrete rejection (oversize/ignored/non-image/out-of-root) so the
// caller can show a notice. It shares extractImagePathAttachments' tokenizer and resolution
// rules but keeps positions so the pasted-path promotion can place tokens in place rather than
// collapse them out of the text.
func (a *App) scanPastedImagePaths(text string) ([]pastedImagePath, *imagePathRejection) {
	projectRoot := a.refProjectRoot()
	if projectRoot == "" || a.home == "" || text == "" {
		return nil, nil
	}
	var paths []pastedImagePath
	var rejection *imagePathRejection
	for i := 0; i < len(text); {
		for i < len(text) && isInputSpace(text[i]) {
			i++
		}
		tokenStart := i
		for i < len(text) && !isInputSpace(text[i]) {
			i++
		}
		token := text[tokenStart:i]
		if token == "" || !isImageExtension(token) {
			continue
		}
		if att, err := resolveImageAttachment(projectRoot, a.home, token); err == nil {
			paths = append(paths, pastedImagePath{start: tokenStart, end: i, att: att, label: filepath.Base(att.path)})
		} else if rejection == nil && isConcreteImageRejection(err) {
			rejection = &imagePathRejection{path: token, err: err}
		}
	}
	return paths, rejection
}

// isConcreteImageRejection reports whether err means the token identified a file that
// should have been an attachment but cannot be sent. A missing relative name is left as
// prose; these errors must surface to the user instead of silently becoming prompt text.
// errImageOutsideRoot covers an explicit out-of-root or symlink-escaping reference: the
// read is refused, and the UI must block it with a notice rather than send the rejected
// path as text.
func isConcreteImageRejection(err error) bool {
	return errors.Is(err, errNotAnImage) || errors.Is(err, errImageTooLarge) ||
		errors.Is(err, errImageIgnored) || errors.Is(err, errImageOutsideRoot)
}

// attachPastedImagePaths promotes supported image paths in a short paste to pending
// attachments immediately. Invalid concrete image references leave the pasted text editable
// and show a notice; submitCurrent will block them if the user presses Enter unchanged.
func (a *App) attachPastedImagePaths(pasted string, start, end int) {
	if strings.HasPrefix(strings.TrimSpace(a.input.GetText()), "/") {
		return
	}
	text := a.input.GetText()
	if start < 0 || end < start || end > len(text) || text[start:end] != pasted {
		return
	}
	paths, rejection := a.scanPastedImagePaths(pasted)
	if len(paths) == 0 && rejection == nil {
		return
	}
	// Replace each recognized image path with a removable "[<basename>]" token at its original
	// position inside the pasted text: the token stands where the user pasted the path —
	// "look diagram.png please" becomes "look [diagram.png] please" — so the buffer order matches
	// what the user sees, and backspacing the token drops the image (the '@'-picker model). delta
	// tracks the running length change so each later path's range stays correct as earlier paths
	// become tokens. Selecting the path's range makes addAttachment replace exactly that path.
	delta := 0
	for _, p := range paths {
		a.input.Select(start+p.start+delta, start+p.end+delta)
		a.input.addAttachment(p.att, p.label)
		a.Notice(attachedImageNotice(p.att))
		delta += len(imageTokenLabel(p.label)) - (p.end - p.start)
	}
	if rejection != nil {
		a.Notice(imageAttachErrorNotice(rejection.path, rejection.err))
	}
}

func (a *App) dropFileRefAt(text string) string {
	projectRoot := a.refProjectRoot()
	if projectRoot == "" {
		return text
	}
	var b strings.Builder
	for i := 0; i < len(text); {
		start := i
		for i < len(text) && !isInputSpace(text[i]) {
			i++
		}
		word := text[start:i]
		if len(word) > 1 && word[0] == '@' {
			if _, err := os.Lstat(filepath.Join(projectRoot, filepath.FromSlash(word))); err != nil {
				word = word[1:]
			}
		}
		b.WriteString(word)
		for i < len(text) && isInputSpace(text[i]) {
			b.WriteByte(text[i])
			i++
		}
	}
	return b.String()
}

// isInputSpace reports whether b is an ASCII whitespace byte, the token separator
// extractImagePathAttachments splits on (space/tab/newline/carriage-return/
// form-feed/vertical-tab).
func isInputSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	}
	return false
}

// refProjectRoot returns the active project root for file-reference resolution, or
// "" when no StatusState is installed (unit-test construction), in which case the
// image-attachment paths stay inert.
func (a *App) refProjectRoot() string {
	if a.statusLineState != nil {
		return a.statusLineState.ProjectRoot()
	}
	return ""
}
