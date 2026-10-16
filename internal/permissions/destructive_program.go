// Destructive program-of-concern classification: the product-authored set of programs whose
// `<program> :*` Program-scope grant authorizes known destructive subcommands, and the advisory
// predicate that lets the program-scope confirm warn more strongly. The signal
// is advisory only — it never blocks or alters a grant; a program absent from the set is treated as
// non-destructive for display purposes (allow-list of concern, not of safety).
//
// The same predicate has a second, load-time use: a bare declared_commands entry naming
// a flagged program is rejected. That reuse does not make it a safety allowlist — a bare entry for
// an unlisted destructive-capable program (bash, sed, find, mv, curl, …) is still accepted.
package permissions

// destructivePrograms is the product-authored set of programs that carry known destructive
// subcommands, so a Program-scope grant (`<program> :*`, any invocation with any arguments) deserves a
// stronger breadth warning than a benign one. Classification is by program name only, because the
// grant being warned about is program-wide: it authorizes every subcommand at once, so the presence of
// any destructive subcommand makes the whole program a concern. Arguments and subcommands are not
// inspected here. The set is intentionally incomplete — seed only high-signal programs; a destructive
// program not listed simply shows the standard breadth warning until added. Each entry
// carries the destructive subcommands that motivate it:
var destructivePrograms = map[string]struct{}{
	"rm":    {}, // deletes files and directories (`rm -rf`); the grant authorizes any deletion
	"rmdir": {}, // removes directories; the grant authorizes any directory removal
	"hg":    {}, // Mercurial: `hg push` publishes, `hg debugstrip` rewrites history
	"git":   {}, // Git: `git push` publishes, `git reset --hard`/`git clean` discard, history-rewriting subcommands
}

// IsDestructiveProgram reports whether granting a direct-command Program scope (`<program> :*`) for the
// given program should get the stronger destructive-breadth warning. It is advisory only:
// pure and side-effect-free, with no filesystem lookups, no argument or subcommand parsing, and no
// grant blocking — it informs warning copy and decides nothing.
//
// The argument must be a canonical direct-command program token (the bare program name produced by
// direct-command normalization, e.g. PromptRequest.CanonicalProgram). It is matched exactly, so a
// path-like or otherwise non-canonical token such as `/tmp/rm` does not match by basename: the
// predicate derives no basename and only program tokens already canonicalized upstream can match.
func IsDestructiveProgram(program string) bool {
	_, ok := destructivePrograms[program]
	return ok
}
