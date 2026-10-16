package enforce

import (
	"bytes"
	"cmp"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type helperCall struct {
	mode, leg string
	argv, env []string
	dir       string
	policy    Policy
}

func withArch(t *testing.T, arch string) {
	t.Helper()
	old := goarch
	t.Cleanup(func() { goarch = old })
	goarch = arch
}

func legForCall(probe string, p Policy) string {
	for _, l := range selfTestLegs {
		if cmp.Or(l.probe, l.name) == probe && l.auto == (p.Mode == ModeAutoEdits) {
			return l.name
		}
	}
	return probe
}

func stubStarter(t *testing.T, result func(mode, leg string) helperExit) *[]helperCall {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	old := startHelper
	t.Cleanup(func() { startHelper = old })
	var calls []helperCall
	startHelper = func(_ context.Context, argv, env []string, dir string, frame []byte) helperExit {
		p, err := ReadPolicyFrame(bytes.NewReader(frame))
		if err != nil {
			t.Errorf("frame: %v", err)
		}
		c := helperCall{mode: argv[2], leg: legForCall(argv[3], p), argv: argv, env: env, dir: dir, policy: p}
		calls = append(calls, c)
		return result(c.mode, c.leg)
	}
	return &calls
}

func expectedExit(mode, leg string) helperExit {
	if mode == ProbeArg && slices.ContainsFunc(selfTestLegs, func(l selfTestLeg) bool { return l.name == leg && l.expected == observedDenied }) {
		return helperExit{code: probeDenied}
	}
	return helperExit{code: probeAllowed}
}

func homeWithCodemeld(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".codemeld"), 0o700); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestResolveForRefusesEveryPlatform(t *testing.T) {
	cases := map[string]string{
		"darwin":  "darwin: not yet supported",
		"freebsd": "freebsd: not yet supported",
		"windows": "windows: not supported",
		"plan9":   "plan9: not supported",
	}
	for goos, reason := range cases {
		got := resolveFor(goos, ResolveInput{Home: t.TempDir()})
		if got.Capability != Refused || got.Reason != reason || got.SelfTestPassed || got.Legs != nil {
			t.Errorf("resolveFor(%q) = %+v, want Refused with reason %q and no self-test", goos, got, reason)
		}
	}
}

func TestSandboxStateAndLabel(t *testing.T) {
	withArch(t, "amd64")
	constrained := Resolution{Capability: Constrained, SelfTestPassed: true}
	refused := resolveFor("linux", ResolveInput{})
	broken := Resolution{Capability: Refused, Reason: "settings file is broken", SelfTestPassed: true}
	for _, tc := range []struct {
		name      string
		r         Resolution
		modeKey   string
		wantState string
		wantLabel string
	}{
		{"constrained plan", constrained, "plan", "on", "sandbox: on"},
		{"constrained auto_edits", constrained, "auto_edits", "on", "sandbox: on"},
		{"constrained build", constrained, "build", "off", "sandbox: off"},
		{"refused plan", refused, "plan", "unavailable", "sandbox: unavailable (linux: invalid home: path must be absolute)"},
		{"refused auto_edits", refused, "auto_edits", "unavailable", "sandbox: unavailable (linux: invalid home: path must be absolute)"},
		{"refused build", refused, "build", "unavailable", "sandbox: unavailable (linux: invalid home: path must be absolute)"},
		{"broken plan", broken, "plan", "unavailable", "sandbox: unavailable (settings file is broken)"},
		{"broken auto_edits", broken, "auto_edits", "unavailable", "sandbox: unavailable (settings file is broken)"},
		{"broken build", broken, "build", "unavailable", "sandbox: unavailable (settings file is broken)"},
		{"refused empty reason", Resolution{Capability: Refused}, "plan", "unavailable", "sandbox: unavailable"},
		{"empty capability", Resolution{}, "plan", "unavailable", "sandbox: unavailable"},
		{"unknown capability", Resolution{Capability: "maybe"}, "auto_edits", "unavailable", "sandbox: unavailable"},
		{"empty mode", constrained, "", "unavailable", "sandbox: unavailable"},
		{"unknown mode", constrained, "turbo", "unavailable", "sandbox: unavailable"},
	} {
		if got := tc.r.SandboxState(tc.modeKey); got != tc.wantState {
			t.Errorf("%s: SandboxState(%q) = %q, want %q", tc.name, tc.modeKey, got, tc.wantState)
		}
		if got := tc.r.SandboxLabel(tc.modeKey); got != tc.wantLabel {
			t.Errorf("%s: SandboxLabel(%q) = %q, want %q", tc.name, tc.modeKey, got, tc.wantLabel)
		}
	}
}

func TestResolveOnHostNeverSelectsConfinedRunner(t *testing.T) {
	old := startHelper
	t.Cleanup(func() { startHelper = old })
	startHelper = func(context.Context, []string, []string, string, []byte) helperExit {
		return helperExit{code: probeAllowed}
	}
	got := Resolve(ResolveInput{Home: t.TempDir()})
	if got.Capability != Refused || got.SelfTestPassed {
		t.Errorf("Resolve() = %+v, want Refused with SelfTestPassed false", got)
	}
}

func TestResolveExpectedLegsResolveConstrained(t *testing.T) {
	withArch(t, "amd64")
	stubStarter(t, expectedExit)
	got := resolveFor("linux", ResolveInput{Home: homeWithCodemeld(t)})
	if got.Capability != Constrained || got.Reason != "" || !got.SelfTestPassed {
		t.Errorf("Resolve() = %+v", got)
	}
	want := []Leg{
		{Name: "write-outside", Observed: "denied"}, {Name: "truncate-read-root", Observed: "denied"},
		{Name: "read-protected", Observed: "denied"}, {Name: "read-read-root", Observed: "allowed"},
		{Name: "write-tmp", Observed: "allowed"}, {Name: "rlimits", Observed: "allowed"},
		{Name: "socket-unix", Observed: "denied"}, {Name: "socket-inet", Observed: "denied"},
		{Name: "socketpair", Observed: "denied"}, {Name: "io-uring-setup", Observed: "denied"},
		{Name: "shmget", Observed: "denied"}, {Name: "msgget", Observed: "denied"}, {Name: "semget", Observed: "denied"},
		{Name: "mq-open", Observed: "denied"}, {Name: "shm-open", Observed: "denied"},
		{Name: "ptrace-parent", Observed: "denied"}, {Name: "environ-parent", Observed: "denied"},
		{Name: "clone-newuser", Observed: "denied"}, {Name: "mount", Observed: "denied"}, {Name: "chroot", Observed: "denied"},
		{Name: "chmod", Observed: "denied"}, {Name: "ioctl-setflags", Observed: "denied"},
		{Name: "no-new-privs", Observed: "allowed"}, {Name: "environment", Observed: "allowed"},
		{Name: "environment-auto", Observed: "allowed"}, {Name: "chmod-auto", Observed: "allowed"},
		{Name: "ioctl-setflags-auto", Observed: "allowed"},
		{Name: "x32-syscall", Observed: "denied"}, {Name: "i386-syscall", Observed: "denied"},
		{Name: "arm32-syscall", Observed: "not_run"},
	}
	if !reflect.DeepEqual(got.Legs, want) {
		t.Errorf("legs = %v, want %v", got.Legs, want)
	}
}

func TestResolveRefusesAnyFlippedLeg(t *testing.T) {
	withArch(t, "amd64")
	for _, leg := range selfTestLegs {
		if leg.arch != "" && leg.arch != "amd64" {
			continue
		}
		flips := map[int]string{probeFailed: observedFailed}
		if leg.expected == observedDenied {
			flips[probeAllowed] = observedAllowed
		} else {
			flips[probeDenied] = observedDenied
		}
		for code, observed := range flips {
			stubStarter(t, func(mode, name string) helperExit {
				if mode == ProbeArg && name == leg.name {
					return helperExit{code: code}
				}
				return expectedExit(mode, name)
			})
			got := resolveFor("linux", ResolveInput{Home: homeWithCodemeld(t)})
			want := "linux: self-test leg " + leg.name + " observed " + observed
			if got.Capability != Refused || got.Reason != want {
				t.Errorf("%s exit %d: Resolve() = %+v, want reason %q", leg.name, code, got, want)
			}
		}
	}
}

func TestResolveRefusesUnsupportedArchitectureBeforeAnyHelper(t *testing.T) {
	withArch(t, "riscv64")
	calls := stubStarter(t, expectedExit)
	for _, home := range []string{homeWithCodemeld(t), ""} {
		got := resolveFor("linux", ResolveInput{Home: home})
		if got.Capability != Refused || got.Reason != "linux/riscv64: not supported" || got.Legs != nil {
			t.Errorf("home %q: Resolve() = %+v", home, got)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("started %d helpers", len(*calls))
	}
	if entries, _ := os.ReadDir(os.TempDir()); len(entries) != 0 {
		t.Errorf("fixtures created: %v", entries)
	}
}

func TestResolveArm64Legs(t *testing.T) {
	withArch(t, "arm64")
	stubStarter(t, expectedExit)
	got := resolveFor("linux", ResolveInput{Home: homeWithCodemeld(t)})
	if got.Capability != Constrained || got.Reason != "" {
		t.Fatalf("Resolve() = %+v", got)
	}
	observed := map[string]string{}
	for _, l := range got.Legs {
		observed[l.Name] = l.Observed
	}
	if observed["x32-syscall"] != observedNotRun || observed["i386-syscall"] != observedNotRun || observed["arm32-syscall"] != observedDenied {
		t.Errorf("non-native legs = %v", observed)
	}

	stubStarter(t, func(mode, leg string) helperExit {
		if leg == "arm32-syscall" && mode == ControlArg {
			return helperExit{code: probeUnsupported}
		}
		return expectedExit(mode, leg)
	})
	got = resolveFor("linux", ResolveInput{Home: homeWithCodemeld(t)})
	if got.Capability != Constrained || got.Reason != "" {
		t.Fatalf("unsupported arm32: Resolve() = %+v", got)
	}
	i := slices.IndexFunc(got.Legs, func(l Leg) bool { return l.Name == "arm32-syscall" })
	if l := got.Legs[i]; l.Observed != observedNotRun || !strings.Contains(l.Diagnostic, "32-bit ARM executables unsupported") {
		t.Errorf("unsupported arm32 leg = %+v", l)
	}
}

func TestResolveHelperExecutable(t *testing.T) {
	withArch(t, "amd64")
	for _, tc := range []struct{ explicit, want string }{
		{"", "/proc/self/exe"},
		{"/opt/codemeld/bin/codemeld", "/opt/codemeld/bin/codemeld"},
	} {
		calls := stubStarter(t, expectedExit)
		got := resolveFor("linux", ResolveInput{Home: homeWithCodemeld(t), HelperExecutable: tc.explicit})
		if got.Capability != Constrained {
			t.Fatalf("helper %q: Resolve() = %+v", tc.explicit, got)
		}
		legs := map[string]bool{}
		for _, c := range *calls {
			legs[c.leg] = true
			if c.argv[0] != tc.want {
				t.Errorf("helper %q: %s %s argv[0] = %q, want %q", tc.explicit, c.mode, c.leg, c.argv[0], tc.want)
			}
		}
		for _, l := range selfTestLegs {
			if l.arch != "arm64" && !legs[l.name] {
				t.Errorf("helper %q: leg %s never started", tc.explicit, l.name)
			}
		}
		if helperExecutable != "/proc/self/exe" {
			t.Errorf("helper %q: global routing changed to %q", tc.explicit, helperExecutable)
		}
	}
}

func TestResolveUnsupportedIoctlRefusesWithDiagnostic(t *testing.T) {
	withArch(t, "amd64")
	const diag = "FS_IOC_SETFLAGS: reading flags of /tmp/f/tmp/m: inappropriate ioctl for device"
	stubStarter(t, func(mode, leg string) helperExit {
		if leg == "ioctl-setflags-auto" {
			return helperExit{code: probeFailed, stderr: diag}
		}
		return expectedExit(mode, leg)
	})
	got := resolveFor("linux", ResolveInput{Home: homeWithCodemeld(t)})
	if got.Capability != Refused || got.Reason != "linux: self-test leg ioctl-setflags-auto observed failed: "+diag {
		t.Errorf("Resolve() = %+v", got)
	}
}
