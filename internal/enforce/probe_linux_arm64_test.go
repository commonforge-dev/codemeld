package enforce

import (
	"bytes"
	"debug/elf"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestArm32FixtureIsA32BitARMExecutable(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "read"), 0o700); err != nil {
		t.Fatal(err)
	}
	path, err := writeArm32Fixture(root)
	if err != nil || path != filepath.Join(root, "read", "arm32") {
		t.Fatalf("writeArm32Fixture = %q, %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("fixture %v, %v", info, err)
	}
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if f.Class != elf.ELFCLASS32 || f.Machine != elf.EM_ARM || f.Type != elf.ET_EXEC {
		t.Errorf("fixture is %v %v %v", f.Class, f.Machine, f.Type)
	}
}

func TestArm32ProbeOutcomes(t *testing.T) {
	old := selfTestTimeout
	t.Cleanup(func() { selfTestTimeout = old })
	selfTestTimeout = 400 * time.Millisecond
	dir := t.TempDir()
	write := func(name string, body []byte, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, body, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	script := func(name, body string) string { return write(name, []byte("#!/bin/sh\n"+body+"\n"), 0o700) }
	cases := []struct {
		name string
		path string
		want int
	}{
		{"child SIGSYS", script("sys", "kill -SYS $$"), probeDenied},
		{"child success", script("ok", "exit 0"), probeAllowed},
		{"child exit status", script("fail", "exit 3"), probeFailed},
		{"unrelated signal", script("term", "kill -TERM $$"), probeFailed},
		{"unsupported form", write("garbage", bytes.Repeat([]byte{0xff}, 64), 0o700), probeUnsupported},
		{"not executable", write("noexec", []byte("x"), 0o600), probeFailed},
		{"missing", filepath.Join(dir, "missing"), probeFailed},
		{"timeout", script("slow", "exec sleep 10"), probeFailed},
	}
	for _, tc := range cases {
		start := time.Now()
		if got := runProbe(&helperState{}, []string{"arm32-syscall", tc.path}); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.name, got, tc.want)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("%s: probe took %v", tc.name, elapsed)
		}
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "read"), 0o700); err != nil {
		t.Fatal(err)
	}
	path, err := writeArm32Fixture(root)
	if err != nil {
		t.Fatal(err)
	}
	switch got := runProbe(&helperState{}, []string{"arm32-syscall", path}); got {
	case probeAllowed:
	case probeUnsupported:
		t.Logf("host runs no 32-bit ARM executables: the self-test records arm32-syscall as an optional not_run leg")
	default:
		t.Errorf("embedded fixture: exit %d, want 0 on a compat host or %d without compat support", got, probeUnsupported)
	}
}
