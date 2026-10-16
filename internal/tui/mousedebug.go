// Mouse-drag diagnostic logging, gated by the CODEMELD_MOUSE_DEBUG env var (a file
// path). Off by default and zero-cost when off; when set, it records the mouse/drag/
// auto-scroll events the SimulationScreen test harness cannot reproduce, so a capture
// from a real terminal shows which pane owns a drag and why a scroll did or did not fire.
// See docs/tui-mouse-debugging.md and docs/environment-variables.md.
package tui

import (
	"fmt"
	"os"
	"sync"
)

const mouseDebugEnv = "CODEMELD_MOUSE_DEBUG"

var (
	mouseDebugOnce sync.Once
	mouseDebugFile *os.File
)

// mouseDebugEnabled reports whether CODEMELD_MOUSE_DEBUG named a writable log path,
// opening the file once on first use. Callers gate any expensive log-arg computation on
// it so the diagnostic costs nothing when off.
func mouseDebugEnabled() bool {
	mouseDebugOnce.Do(func() {
		if path := os.Getenv(mouseDebugEnv); path != "" {
			mouseDebugFile, _ = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		}
	})
	return mouseDebugFile != nil
}

// mouseDebugf appends a line to the CODEMELD_MOUSE_DEBUG file when logging is enabled;
// otherwise it is a cheap no-op. It never disrupts the TUI: an open failure silently
// disables logging.
func mouseDebugf(format string, args ...any) {
	if !mouseDebugEnabled() {
		return
	}
	_, _ = fmt.Fprintf(mouseDebugFile, format+"\n", args...)
}
