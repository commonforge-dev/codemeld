// Dev-debug gate: a development-only switch that turns on the ordered
// suggest_followup trace (events.SuggestFollowupDebug). Off by default and never on in a
// normal session, so normal sessions stay byte-free of the debug events.
package bootstrap

import "os"

// EnvDevDebug enables the suggest_followup development trace when set to "1". It is
// documented in docs/environment-variables.md and the TUI /help panel; the headless
// `codemeld run` also accepts a --dev-debug flag that ORs with it.
const EnvDevDebug = "CODEMELD_DEV_DEBUG"

// devDebugEnabled reports whether the dev-debug gate is on: either the launch flag
// (`codemeld run --dev-debug`) or CODEMELD_DEV_DEBUG=1. The interactive launch has no
// flag and passes false, so there it is env-only; the headless run ORs the flag in.
func devDebugEnabled(flag bool) bool {
	return flag || os.Getenv(EnvDevDebug) == "1"
}
