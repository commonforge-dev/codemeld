//go:build !linux

package enforce

import (
	"runtime"
	"testing"
)

func TestResolveRefusedOnUnsupportedPlatform(t *testing.T) {
	got := Resolve(ResolveInput{Home: "/home/u"})
	if got.Capability != Refused {
		t.Fatalf("Resolve() = %+v, want Refused", got)
	}
	want := runtime.GOOS + ": not supported"
	switch runtime.GOOS {
	case "darwin", "freebsd":
		want = runtime.GOOS + ": not yet supported"
	}
	if got.Reason != want {
		t.Errorf("reason = %q, want %q", got.Reason, want)
	}
	if got.Legs != nil || got.SelfTestPassed {
		t.Errorf("unsupported platform ran self-test legs: %+v", got)
	}
}

func TestRunHelperRefusedOnUnsupportedPlatform(t *testing.T) {
	if got := RunHelper([]string{"/bin/true"}); got != SetupFailureExitCode {
		t.Errorf("RunHelper = %d, want %d", got, SetupFailureExitCode)
	}
}
