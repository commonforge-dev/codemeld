// Tests for the dev-debug gate (devdebug.go): the CODEMELD_DEV_DEBUG=1 env path —
// the interactive TUI's only enablement, which passes flag=false — and the explicit
// launch flag, which turns the trace on regardless of the env var.
package bootstrap

import "testing"

// TestDevDebugEnabled pins both inputs of the gate: the documented CODEMELD_DEV_DEBUG=1
// env value (off for unset/non-"1"), and the launch flag, which forces it on without the
// env var. It fails if the os.Getenv(EnvDevDebug) == "1" branch is removed.
func TestDevDebugEnabled(t *testing.T) {
	tests := []struct {
		name string
		env  string // value to set CODEMELD_DEV_DEBUG to ("" is unset for os.Getenv's purposes)
		flag bool
		want bool
	}{
		{name: "unset env, flag off", env: "", flag: false, want: false},
		{name: "non-1 env, flag off", env: "0", flag: false, want: false},
		{name: "env 1, flag off (interactive env-only path)", env: "1", flag: false, want: true},
		{name: "unset env, flag on (explicit --dev-debug)", env: "", flag: true, want: true},
		{name: "env 1, flag on", env: "1", flag: true, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvDevDebug, tt.env)
			if got := devDebugEnabled(tt.flag); got != tt.want {
				t.Fatalf("devDebugEnabled(%v) with %s=%q = %v, want %v", tt.flag, EnvDevDebug, tt.env, got, tt.want)
			}
		})
	}
}

// TestEnvDevDebugName pins the documented variable name so a rename can't silently break
// the gate documented in docs/environment-variables.md and the TUI /help panel.
func TestEnvDevDebugName(t *testing.T) {
	if EnvDevDebug != "CODEMELD_DEV_DEBUG" {
		t.Fatalf("EnvDevDebug = %q, want CODEMELD_DEV_DEBUG (documented in docs/environment-variables.md and the TUI /help panel)", EnvDevDebug)
	}
}
