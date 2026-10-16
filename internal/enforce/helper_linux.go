package enforce

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	allThreadsSyscall = syscall.AllThreadsSyscall
	lockOSThread      = runtime.LockOSThread
)

type helperState struct {
	args   []string
	policy Policy
	nproc  uint64
}

type helperStep struct {
	name string
	run  func(*helperState) error
}

var helperSteps = []helperStep{
	{"lock thread", func(*helperState) error { lockOSThread(); return nil }},
	{"policy frame", func(s *helperState) (err error) { s.policy, err = ReadPolicyFrame(os.Stdin); return err }},
	{"rlimits", func(s *helperState) (err error) { s.nproc, err = applyRlimits(); return err }},
	{"no_new_privs", func(*helperState) error {
		if _, _, errno := allThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
			return errno
		}
		return nil
	}},
	{"landlock", func(s *helperState) error { return applyLandlock(s.policy) }},
	{"seccomp", func(s *helperState) error { return installSeccomp(s.policy) }},
}

var execStep = helperStep{"exec", func(s *helperState) error { return syscall.Exec(s.args[0], s.args, os.Environ()) }}

func RunHelper(args []string) int {
	if len(args) == 0 {
		return helperFailure("target", errors.New("no command to run"))
	}
	mode, steps := args[0], helperSteps
	switch mode {
	case ProbeArg:
		args = args[1:]
	case ControlArg:
		args = args[1:]
		steps = slices.DeleteFunc(slices.Clone(helperSteps), func(st helperStep) bool { return st.name != "policy frame" })
	}
	s := &helperState{args: args}
	for _, step := range steps {
		if err := step.run(s); err != nil {
			return helperFailure(step.name, err)
		}
	}
	if mode == ProbeArg || mode == ControlArg {
		return runProbe(s, args)
	}
	if err := execStep.run(s); err != nil {
		return helperFailure(execStep.name, err)
	}
	return 0
}

func helperFailure(step string, err error) int {
	fmt.Fprintf(os.Stderr, "codemeld confinement: %s: %v\n", step, err)
	return SetupFailureExitCode
}
