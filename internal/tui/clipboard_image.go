// OS-clipboard image source for the prompt: a small reader interface and
// its default platform-helper implementation that shells out to wl-paste / xclip /
// xsel / pngpaste to read an image off the system clipboard, feeding the
// pending-attachment pipeline via the CTRL-V key. A terminal cannot deliver image
// bytes through bracketed paste (it carries only text) and reading the OS image
// clipboard portably in pure Go is impractical under the no-CGO / single-binary
// posture, so this uses an optional local subprocess — the same shell-out posture
// codemeld already uses for VCS tools, within the no-extra-egress constraint.
package tui

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// clipboardReadTimeout bounds the helper subprocess so a stuck helper cannot freeze
// the TUI: the read runs on the event-loop goroutine off the CTRL-V key, so an
// unbounded wait would hang the whole interface. A timeout surfaces as a friendly
// notice like any other helper failure.
const clipboardReadTimeout = 3 * time.Second

// errNoClipboardHelper means no supported clipboard-image helper binary was found on
// PATH for this platform/session. It is distinct from "a helper ran but the clipboard
// holds no image" so the action can advise installing one.
var errNoClipboardHelper = errors.New("no clipboard image helper found")

// errClipboardTimeout means the helper did not finish within clipboardReadTimeout.
var errClipboardTimeout = errors.New("clipboard read timed out")

// clipboardReader reads an image off the OS clipboard. ReadImage returns the image's
// mime and bytes with ok=true on success; ok=false with a nil error when the clipboard
// holds no image; and a non-nil error for a missing helper (errNoClipboardHelper), a
// timeout (errClipboardTimeout), or an unexpected helper failure. It is an interface
// so tests inject a fake — the real implementation spawns a subprocess and is never
// run in CI.
type clipboardReader interface {
	ReadImage(ctx context.Context) (mime string, data []byte, ok bool, err error)
}

// helperCommand is one clipboard-helper invocation: the binary name (looked up on
// PATH) and its argv, plus the mime the requested output carries.
type helperCommand struct {
	name string
	args []string
	mime string
}

// clipboardHelperCandidates returns the ordered helper commands to try for goos and
// the session environment, most-preferred first. It is pure (no PATH lookup, no
// spawning) so the platform/session selection is unit-testable: macOS uses pngpaste;
// a Wayland session prefers wl-paste and falls back to the X11 helpers (XWayland); a
// plain X11 session uses xclip then xsel; a session with no display server yields no
// candidates (the caller then reports errNoClipboardHelper).
func clipboardHelperCandidates(goos string, env func(string) string) []helperCommand {
	if goos == "darwin" {
		return []helperCommand{{name: "pngpaste", args: []string{"-"}, mime: "image/png"}}
	}
	x11 := []helperCommand{
		{name: "xclip", args: []string{"-selection", "clipboard", "-t", "image/png", "-o"}, mime: "image/png"},
		{name: "xsel", args: []string{"--clipboard", "--output"}, mime: "image/png"},
	}
	switch {
	case env("WAYLAND_DISPLAY") != "":
		return append([]helperCommand{{name: "wl-paste", args: []string{"--type", "image/png"}, mime: "image/png"}}, x11...)
	case env("DISPLAY") != "":
		return x11
	default:
		return nil
	}
}

// execClipboardReader is the production clipboardReader: it picks the first installed
// helper for the platform/session and runs it under a context so a stuck helper times
// out. The lookPath/run seams are injected so the selection and result classification
// are testable without spawning a real helper binary.
type execClipboardReader struct {
	goos     string
	getenv   func(string) string
	lookPath func(string) (string, error)
	run      func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// newClipboardReader builds the default reader wired to the real os/exec seams.
func newClipboardReader() *execClipboardReader {
	return &execClipboardReader{
		goos:     runtime.GOOS,
		getenv:   os.Getenv,
		lookPath: exec.LookPath,
		run:      runClipboardHelper,
	}
}

// runClipboardHelper runs name with args under ctx and returns its stdout. stderr is
// discarded — a non-zero exit is classified by the caller, not surfaced verbatim, so
// helper chatter never reaches the user.
func runClipboardHelper(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// ReadImage finds the first installed helper for the platform/session and runs it. No
// installed helper → errNoClipboardHelper. A helper that exits non-zero or prints
// nothing is treated as "clipboard holds no image" (ok=false, nil error) — the common
// case when nothing image-shaped is on the clipboard (wl-paste/pngpaste exit non-zero
// then). A context timeout → errClipboardTimeout; any other run failure is returned
// as-is. The returned mime is the requested type; the caller re-sniffs the bytes
// before trusting them.
func (r *execClipboardReader) ReadImage(ctx context.Context) (string, []byte, bool, error) {
	var chosen *helperCommand
	for _, c := range clipboardHelperCandidates(r.goos, r.getenv) {
		if _, err := r.lookPath(c.name); err == nil {
			cc := c
			chosen = &cc
			break
		}
	}
	if chosen == nil {
		return "", nil, false, errNoClipboardHelper
	}
	data, err := r.run(ctx, chosen.name, chosen.args...)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", nil, false, errClipboardTimeout
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			// The helper ran and exited non-zero — the wl-paste/pngpaste "no image of the
			// requested type on the clipboard" signal. Treat as no image, not an error.
			return "", nil, false, nil
		}
		return "", nil, false, err
	}
	if len(data) == 0 {
		return "", nil, false, nil
	}
	return chosen.mime, data, true, nil
}
