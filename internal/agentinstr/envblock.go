// Formats the always-present environment context block (date, working directory,
// OS, project name, VCS) placed between the mode base prompt and AGENTS.md in the
// assembled system message. Side-effect-free and cache-stable:
// it makes no outbound calls and includes no per-turn-volatile state.
package agentinstr

import (
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// EnvironmentInputs are the deterministic inputs to EnvironmentBlock. The
// production caller supplies the system clock value (already in the host's local
// timezone) and the detected VCS name; tests pass fixed values. This package
// stays independent of internal/bootstrap, so the caller adapts bootstrap's active-VCS
// handoff into VCSName at the assembly edge rather than this builder importing it.
type EnvironmentInputs struct {
	// Now is the clock value, in the host's local timezone, rendered at day
	// granularity (no clock time) so the block stays prompt-cache stable within a day.
	Now time.Time
	// WorkingDir is the current working directory as an absolute path.
	WorkingDir string
	// ProjectRoot is the absolute project root; its basename is the project name.
	ProjectRoot string
	// RepoRoot is the absolute repository root, empty when no VCS was detected.
	RepoRoot string
	// VCSName is the detected version-control template name. Built-in ids (git, hg,
	// jj) render as Git, Mercurial, Jujutsu; any other non-empty value renders
	// verbatim; an empty value renders as "no version control detected".
	VCSName string
}

// noVCSText is the explicit slice value when VCS detection yielded no match.
const noVCSText = "no version control detected"

// vcsDisplayNames maps built-in VCS template ids to their user-facing display names.
// Names outside this set are custom templates and render verbatim.
var vcsDisplayNames = map[string]string{
	"git": "Git",
	"hg":  "Mercurial",
	"jj":  "Jujutsu",
}

// EnvironmentBlock formats the environment context block from deterministic inputs.
// It states the current date at day granularity in the supplied
// timezone, the absolute working directory, the operating system from runtime.GOOS,
// the project name (basename of ProjectRoot), and the VCS name (or the explicit
// no-VCS text). It deliberately excludes
// per-turn-volatile or large state — no
// branch/head, dirty status, or directory listing — and performs no I/O
// so it adds no outbound network calls.
func EnvironmentBlock(in EnvironmentInputs) string {
	var b strings.Builder
	b.WriteString("Environment:\n")
	b.WriteString("- Date: " + in.Now.Format("2006-01-02") + "\n")
	b.WriteString("- Working directory: " + in.WorkingDir + "\n")
	b.WriteString("- Operating system: " + runtime.GOOS + "\n")
	b.WriteString("- Project: " + filepath.Base(in.ProjectRoot) + "\n")
	if in.RepoRoot != "" {
		b.WriteString("- Repository root: " + in.RepoRoot + "\n")
	}
	b.WriteString("- Version control: " + vcsDisplay(in.VCSName))
	return b.String()
}

// vcsDisplay maps a detected VCS name to its rendered value: the no-VCS text for an
// empty name, the user-facing name for a built-in id, or the name verbatim otherwise.
func vcsDisplay(name string) string {
	if name == "" {
		return noVCSText
	}
	if display, ok := vcsDisplayNames[name]; ok {
		return display
	}
	return name
}
