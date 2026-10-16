package tui

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/filetools"
)

// filePickerPage is the Pages name the file-reference picker overlay is mounted under while
// open, removed when it dismisses.
const filePickerPage = "file-picker"

// fileRefLabel is the picker query field's label and the literal token prefix. It mirrors
// the '@' the user typed so the field reads as a continuation of the token being built and
// the inserted/left-literal token begins with it.
const fileRefLabel = "@"

const (
	fileRefIdleGuidance = "type to search project files"
	fileRefSearchingRow = "searching..."
	fileRefFailedRow    = "search failed"
	fileRefNoMatchRow   = "no matches"
)

type fileRefSearchFunc func(ctx context.Context, query string, emit func(path string)) error

type filePickerSession struct {
	atByte           int
	projectRoot      string
	home             string
	query            string
	shown            []string
	list             *tview.List
	searchGeneration uint64
	searchCancel     context.CancelFunc
	search           fileRefSearchFunc
}

// SetHome installs the bootstrap-resolved home directory the file-reference picker uses to
// locate the global ~/.codemeld/global/codemeldignore file. Production wiring
// (StartTUI) passes BootstrapResult.Home; with none installed the '@' trigger stays inert, so
// App can be constructed in unit tests without bootstrap state. Set once before Run.
func (a *App) SetHome(home string) { a.home = home }

func (a *App) openFilePicker(atByte int) {
	if a.anyOverlayOpen() {
		return
	}
	projectRoot := ""
	if a.statusLineState != nil {
		projectRoot = a.statusLineState.ProjectRoot()
	}
	if projectRoot == "" || a.home == "" {
		return // no production sources installed: the trigger is inert
	}
	sess := &filePickerSession{atByte: atByte, projectRoot: projectRoot, home: a.home}
	sess.search = func(ctx context.Context, query string, emit func(path string)) error {
		return searchFileRefs(ctx, sess.projectRoot, sess.home, query, emit)
	}
	overlay, field := a.buildFilePicker(sess)
	a.filePicker = sess
	a.filePickerOpen = true
	a.filePickerPrev = a.app.GetFocus()
	a.pages.AddPage(filePickerPage, wrapOverlayPage(centeredModal(overlay)), true, true)
	a.app.SetFocus(field)
}

// FilePickerOpen reports whether the file-reference picker overlay is currently mounted. It
// mirrors EffortPickerOpen/ModelPickerOpen as the observable a simulation test reads to prove
// a typed '@' opened (or a paste did not open) the picker; production drives it through the
// change hook and key paths and never polls this.
func (a *App) FilePickerOpen() bool { return a.filePickerOpen }

func (a *App) buildFilePicker(sess *filePickerSession) (tview.Primitive, *tview.InputField) {
	list := tview.NewList()
	list.ShowSecondaryText(false)
	applyPickerListColors(list)
	sess.list = list
	a.renderFileRefPlaceholder(sess, fileRefIdleGuidance)
	// Fires on a mouse click of a row (the field keeps keyboard focus, so Enter is routed
	// through filePickerFieldKeys); kept so the picker is usable with the mouse too.
	list.SetSelectedFunc(func(int, string, string, rune) { a.confirmFileRef() })

	field := tview.NewInputField()
	field.SetLabel(fileRefLabel)
	// No accent on the '@' label — inherit the terminal default instead of tview's built-in
	// yellow, consistent with the terminal-default theme.
	field.SetLabelStyle(tcell.StyleDefault.Foreground(tcell.ColorDefault).Background(tcell.ColorDefault))
	field.SetChangedFunc(func(text string) { a.onFileRefQueryChanged(sess, text) })
	field.SetInputCapture(a.filePickerFieldKeys)

	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(field, 1, 0, true).
		AddItem(list, 0, 1, false)
	body.SetBorder(true)
	body.SetTitle(" file reference ")
	return body, field
}

// filePickerFieldKeys is the query field's key handler: ESC dismisses leaving the literal,
// Enter confirms the highlighted candidate, ↑/↓ move the list selection (the field keeps
// focus so typing continues to narrow). Every other key falls through to the field so the
// user can edit the query.
func (a *App) filePickerFieldKeys(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyEscape:
		a.dismissFilePicker(true)
		return nil
	case tcell.KeyEnter:
		a.confirmFileRef()
		return nil
	case tcell.KeyUp:
		a.moveFilePickerSelection(-1)
		return nil
	case tcell.KeyDown:
		a.moveFilePickerSelection(1)
		return nil
	}
	return ev
}

// moveFilePickerSelection moves the list cursor by delta, clamped to the current shown range
// (no wraparound), so ↑/↓ in the query field drive the list without moving the field caret.
// It is a no-op when the list is empty.
func (a *App) moveFilePickerSelection(delta int) {
	sess := a.filePicker
	if sess == nil || sess.list == nil || len(sess.shown) == 0 {
		return
	}
	i := sess.list.GetCurrentItem() + delta
	if i < 0 {
		i = 0
	}
	if i >= len(sess.shown) {
		i = len(sess.shown) - 1
	}
	sess.list.SetCurrentItem(i)
}

func (a *App) onFileRefQueryChanged(sess *filePickerSession, query string) {
	sess.query = query
	if query == "" {
		a.invalidateFileRefSearch(sess)
		a.renderFileRefPlaceholder(sess, fileRefIdleGuidance)
		return
	}
	a.renderFileRefPlaceholder(sess, fileRefSearchingRow)
	a.scheduleFileRefSearch(sess, query, func(gen uint64) {
		a.startFileRefSearch(sess, gen, query)
	})
}

func (a *App) renderFileRefPlaceholder(sess *filePickerSession, text string) {
	sess.shown = nil
	sess.list.Clear()
	sess.list.AddItem(text, "", 0, nil)
}

func (a *App) startFileRefSearch(sess *filePickerSession, gen uint64, query string) {
	ctx, cancel := context.WithCancel(context.Background())
	sess.searchCancel = cancel
	search := sess.search
	go func() {
		defer cancel()
		err := search(ctx, query, func(path string) {
			a.streamUpdate(func() { a.applyFileRefSearchRow(sess, gen, path) })
		})
		a.streamUpdate(func() { a.applyFileRefSearchFinal(sess, gen, err) })
	}()
}

func (a *App) applyFileRefSearchRow(sess *filePickerSession, gen uint64, path string) {
	if !a.ownsFileRefSearch(sess, gen) {
		return
	}
	if len(sess.shown) >= fileRefSearchLimit {
		return
	}
	if len(sess.shown) == 0 {
		sess.list.Clear()
	}
	sess.shown = append(sess.shown, path)
	sess.list.AddItem(path, "", 0, nil)
}

func (a *App) applyFileRefSearchFinal(sess *filePickerSession, gen uint64, err error) {
	if !a.ownsFileRefSearch(sess, gen) {
		return
	}
	sess.searchCancel = nil
	switch {
	case errors.Is(err, context.Canceled):
		return
	case err != nil:
		a.Notice(err.Error())
		if len(sess.shown) == 0 {
			a.renderFileRefPlaceholder(sess, fileRefFailedRow)
		}
	case len(sess.shown) == 0:
		a.renderFileRefPlaceholder(sess, fileRefNoMatchRow)
	}
}

// confirmFileRef handles Enter: a non-image candidate is inserted as the plain
// '@'+path token (a directory keeps its trailing '/') exactly as before (Step 4) — the
// agent resolves it with its read-only tools, nothing is attached. A candidate that is
// a supported image instead becomes a pending image attachment: its '@'-token
// is removed from the buffer (its bytes are never inlined as text) and the resolved
// data-URI attachment is added, with a one-line notice naming the attached file. A
// candidate whose extension looks like an image but whose bytes are not one falls back
// to the plain-text insertion; any other resolution failure (oversize, excluded,
// unreadable) drops the token and shows a friendly notice without attaching. With no
// candidate (an empty or no-match list) it dismisses leaving the typed '@'+query literal.
func (a *App) confirmFileRef() {
	sess := a.filePicker
	if sess == nil {
		return
	}
	idx := sess.list.GetCurrentItem()
	if len(sess.shown) == 0 || idx < 0 || idx >= len(sess.shown) {
		a.dismissFilePicker(true)
		return
	}
	path := sess.shown[idx]
	atByte := sess.atByte
	projectRoot := a.refProjectRoot()
	a.dismissFilePicker(false)
	text := a.input.GetText()
	if atByte < 0 || atByte >= len(text) {
		return
	}
	end := fileRefTokenEnd(text, atByte)
	if isImageExtension(path) && projectRoot != "" && a.home != "" {
		att, err := resolveImageAttachment(projectRoot, a.home, path)
		switch {
		case err == nil:
			// Replace the '@token' with a removable "[<basename>]" image token (its image bytes
			// are never inlined): drop the '@token' first, then addAttachment inserts the token at
			// that caret and pins the attachment to it, so backspacing the token drops the image.
			a.input.Replace(atByte, end, "")
			a.input.addAttachment(att, filepath.Base(att.path))
			a.Notice(attachedImageNotice(att))
			return
		case errors.Is(err, errNotAnImage):
			// Looked like an image by extension but the bytes are not: inline as plain text.
		default:
			a.input.Replace(atByte, end, "") // drop the token; nothing is attached
			a.Notice(imageAttachErrorNotice(path, err))
			return
		}
	}
	a.input.Replace(atByte, end, fileRefLabel+path)
}

// attachedImageNotice is the one-line confirmation shown when a referenced image is
// added as a pending attachment, so the attachment is visible before submit.
func attachedImageNotice(att imageAttachment) string {
	return fmt.Sprintf("attached image: %s (%s)", att.displayName(), humanBytes(att.sizeBytes))
}

// dismissFilePicker closes the picker overlay and restores focus to whatever held it when the
// picker opened (the input area in production). When leaveLiteral is true (ESC, or Enter with
// no selectable candidate) it splices the typed query into the prompt buffer right after the
// triggering '@', so the '@'+query text is left literal (Step 4) — the '@' itself is never
// consumed. When false the caller (confirmFileRef) performs the token replacement. It is
// idempotent.
func (a *App) dismissFilePicker(leaveLiteral bool) {
	if !a.filePickerOpen {
		return
	}
	sess := a.filePicker
	a.invalidateFileRefSearch(sess)
	a.filePickerOpen = false
	a.closeOverlayPage(filePickerPage, &a.filePickerPrev)
	a.filePicker = nil
	if leaveLiteral && sess != nil && sess.query != "" {
		text := a.input.GetText()
		insertAt := sess.atByte + len(fileRefLabel) // right after the '@'
		if insertAt <= len(text) {
			a.input.Replace(insertAt, insertAt, sess.query)
		}
	}
}

const fileRefSearchLimit = 50

func walkFileRefPaths(ctx context.Context, projectRoot, home string, visit func(path string) error) error {
	matcher, err := filetools.LoadCodemeldignoreMatcher(projectRoot, home)
	if err != nil {
		return err
	}
	var ignore []filetools.IgnoreMatcher
	if matcher != nil {
		ignore = []filetools.IgnoreMatcher{matcher}
	}
	return filetools.WalkContext(ctx, filetools.WalkOptions{
		Root:           projectRoot,
		ProjectRoot:    projectRoot,
		IncludeIgnored: false,
		Ignore:         ignore,
	}, func(e filetools.WalkEntry) error {
		path := e.RelPath
		if e.Kind == filetools.EntryDir {
			path += "/"
		}
		return visit(path)
	})
}

func searchFileRefs(ctx context.Context, projectRoot, home, query string, emit func(path string)) error {
	q := strings.ToLower(query)
	var matches []string
	err := walkFileRefPaths(ctx, projectRoot, home, func(path string) error {
		if matchesFileRefQuery(path, q) {
			matches = append(matches, path)
		}
		return nil
	})
	if errors.Is(err, context.Canceled) {
		return err
	}
	rankFileRefMatches(matches, q)
	for _, path := range matches[:min(len(matches), fileRefSearchLimit)] {
		emit(path)
	}
	return err
}

func rankFileRefMatches(paths []string, loweredQuery string) {
	type ranked struct {
		path        string
		rank, depth int
	}
	rs := make([]ranked, len(paths))
	for i, path := range paths {
		p := strings.ToLower(path)
		trimmed := strings.TrimSuffix(p, "/")
		r := ranked{path: path, rank: 3, depth: strings.Count(trimmed, "/")}
		switch {
		case p == loweredQuery || p == loweredQuery+"/":
			r.rank = 0
		case strings.HasPrefix(p, loweredQuery):
			r.rank = 1
		case strings.HasPrefix(p[strings.LastIndex(trimmed, "/")+1:], loweredQuery):
			r.rank = 2
		}
		rs[i] = r
	}
	slices.SortStableFunc(rs, func(a, b ranked) int {
		return cmp.Or(cmp.Compare(a.rank, b.rank), cmp.Compare(a.depth, b.depth))
	})
	for i, r := range rs {
		paths[i] = r.path
	}
}

const (
	fileRefDebounceFirstRune = 400 * time.Millisecond
	fileRefDebounceMoreRunes = 250 * time.Millisecond
)

func fileRefDebounceDelay(query string) (time.Duration, bool) {
	switch utf8.RuneCountInString(query) {
	case 0:
		return 0, false
	case 1:
		return fileRefDebounceFirstRune, true
	default:
		return fileRefDebounceMoreRunes, true
	}
}

func (a *App) invalidateFileRefSearch(sess *filePickerSession) {
	if sess == nil {
		return
	}
	sess.searchGeneration++
	cancel := sess.searchCancel
	sess.searchCancel = nil
	if cancel != nil {
		cancel()
	}
}

func (a *App) ownsFileRefSearch(sess *filePickerSession, gen uint64) bool {
	return sess != nil && a.filePicker == sess && sess.searchGeneration == gen
}

func (a *App) scheduleFileRefSearch(sess *filePickerSession, query string, start func(gen uint64)) bool {
	if sess == nil {
		return false
	}
	delay, ok := fileRefDebounceDelay(query)
	if !ok {
		return false
	}
	a.invalidateFileRefSearch(sess)
	gen := sess.searchGeneration
	a.afterFunc(delay, func() {
		a.streamUpdate(func() {
			if !a.ownsFileRefSearch(sess, gen) {
				return
			}
			if start != nil {
				start(gen)
			}
		})
	})
	return true
}

func matchesFileRefQuery(path, loweredQuery string) bool {
	if loweredQuery == "" {
		return true
	}
	return strings.Contains(strings.ToLower(path), loweredQuery)
}
