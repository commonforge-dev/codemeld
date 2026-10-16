// Package enforce reports the session-level execution capability.
package enforce

import (
	"cmp"
	"path/filepath"
	"runtime"

	"codemeld.dev/codemeld/internal/mode"
)

type Capability string

const (
	Constrained Capability = "constrained"
	Refused     Capability = "refused"
)

type Leg struct {
	Name       string
	Observed   string
	Diagnostic string
}

type Resolution struct {
	Capability     Capability
	Reason         string
	Legs           []Leg
	SelfTestPassed bool
}

type ResolveInput struct {
	Home             string
	HelperExecutable string
}

var goarch = runtime.GOARCH

func Resolve(in ResolveInput) Resolution {
	return resolveFor(runtime.GOOS, in)
}

func resolveFor(goos string, in ResolveInput) Resolution {
	switch goos {
	case "linux":
		return resolveLinux(in)
	case "darwin", "freebsd":
		return Resolution{Capability: Refused, Reason: goos + ": not yet supported"}
	default:
		return Resolution{Capability: Refused, Reason: goos + ": not supported"}
	}
}

func resolveLinux(in ResolveInput) Resolution {
	if goarch != "amd64" && goarch != "arm64" {
		return Resolution{Capability: Refused, Reason: "linux/" + goarch + ": not supported"}
	}
	if !filepath.IsAbs(in.Home) {
		return Resolution{Capability: Refused, Reason: "linux: invalid home: path must be absolute"}
	}
	results := runSelfTestLegs(filepath.Clean(in.Home), cmp.Or(in.HelperExecutable, helperExecutable))
	r := Resolution{Capability: Refused}
	for _, l := range results {
		r.Legs = append(r.Legs, Leg{Name: l.Name, Observed: l.Observed, Diagnostic: l.Diagnostic})
	}
	for _, l := range results {
		if l.Observed == l.Expected || (l.Observed == observedHeldByHost && l.Expected == observedDenied) {
			continue
		}
		r.Reason = "linux: self-test leg " + l.Name + " observed " + l.Observed
		for _, detail := range []string{l.SetupStderr, l.Diagnostic} {
			if detail != "" {
				r.Reason += ": " + detail
			}
		}
		return r
	}
	r.Capability, r.SelfTestPassed = Constrained, true
	return r
}

func (r Resolution) SandboxState(modeKey string) string {
	if r.Capability != Constrained {
		return "unavailable"
	}
	switch mode.Mode(modeKey) {
	case mode.Plan, mode.AutoEdits:
		return "on"
	case mode.Build:
		return "off"
	}
	return "unavailable"
}

func (r Resolution) SandboxLabel(modeKey string) string {
	state := r.SandboxState(modeKey)
	if state == "unavailable" && r.Reason != "" {
		return "sandbox: " + state + " (" + r.Reason + ")"
	}
	return "sandbox: " + state
}
