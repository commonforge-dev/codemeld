// OP_FAIL formatting, control-character collapse, and the stderr fallback channel for un-renderable errors.
package fserrors

import (
	"fmt"
	"os"
	"strings"
)

// CollapseControls replaces newlines, carriage returns, and tabs with single spaces, then collapses runs of spaces to one, yielding a single line.
func CollapseControls(s string) string {
	replacer := strings.NewReplacer("\n", " ", "\r", " ", "\t", " ")
	s = replacer.Replace(s)
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	return s
}

// FormatOpFail returns the canonical OP_FAIL line:
//
//	codemeld: <operation> failed: <target_path>: <error_category>
//
// operation and targetPath are run through CollapseControls; the result has no trailing newline.
func FormatOpFail(operation, targetPath string, cat Category) string {
	return fmt.Sprintf("codemeld: %s failed: %s: %s",
		CollapseControls(operation),
		CollapseControls(targetPath),
		cat,
	)
}

// WriteToStderr is the single chokepoint for errors that cannot be rendered in the TUI. It writes the OP_FAIL line and an optional collapsed detail continuation to os.Stderr. It does not call os.Exit, so the caller chooses the exit code.
func WriteToStderr(operation, targetPath string, cat Category, detail string) {
	fmt.Fprintln(os.Stderr, FormatOpFail(operation, targetPath, cat))
	if detail != "" {
		fmt.Fprintln(os.Stderr, "detail: "+CollapseControls(detail))
	}
}
