package dispatch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/runner"
)

// resolveArgv0FromChildPath pins Argv[0] to the executable the stage's own PATH selects, because the
// runner's exec resolves a bare argv against codemeld's PATH — the wrong environment for a stage that
// cleared it or set its own. Only a stage that clears the environment or assigns PATH is resolved,
// and only over the absolute entries of the computed child PATH in order: a relative entry would be
// resolved against the run directory, so one grant would authorize a different file at every
// descendant of its path scope. A stage whose program cannot be found there fails here rather than
// falling back to codemeld's PATH.
func resolveArgv0FromChildPath(spec *runner.RunSpec, stage permissions.StageNormalization) error {
	if !stage.ClearEnvironment && !assignsPath(stage.Assignments) {
		return nil
	}
	program := spec.Argv[0]
	if filepath.Base(program) != program {
		return nil
	}
	resolved, ok := lookPathEntries(childEnvValue(spec.Env, "PATH"), program)
	if !ok {
		return fmt.Errorf("dispatch: %q not found in the requested PATH", program)
	}
	argv := slices.Clone(spec.Argv)
	argv[0] = resolved
	spec.Argv = argv
	return nil
}

func lookPathEntries(pathValue string, program string) (string, bool) {
	for _, dir := range strings.Split(pathValue, string(os.PathListSeparator)) {
		if !filepath.IsAbs(dir) {
			continue
		}
		if resolved, err := exec.LookPath(filepath.Join(dir, program)); err == nil {
			return resolved, true
		}
	}
	return "", false
}

func verifyStagePrograms(stages []permissions.StageNormalization, scope string, home string) error {
	for i, stage := range stages {
		if _, answered := builtinLookupResult(stage); answered {
			continue
		}
		program := execArgv(stage, home)[0]
		if !stageProgramResolves(stage, program, scope) {
			return &MalformedCommandError{Err: fmt.Errorf("shell stage %d: program %q not found", i, program)}
		}
	}
	return nil
}

// stageProgramResolves mirrors how the runner launches argv[0]: a separator-bearing name is opened
// relative to the stage's working directory with no PATH search, and a bare name is searched on the
// PATH the stage runs with.
func stageProgramResolves(stage permissions.StageNormalization, program string, scope string) bool {
	if stage.ProgramUnescapedSeparator {
		return true
	}
	if filepath.Base(program) != program {
		if !filepath.IsAbs(program) {
			program = filepath.Join(scope, program)
		}
		info, err := os.Stat(program)
		return err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0
	}
	if stage.ClearEnvironment || assignsPath(stage.Assignments) {
		_, ok := lookPathEntries(childEnvValue(stage.Assignments, "PATH"), program)
		return ok
	}
	_, err := exec.LookPath(program)
	return err == nil
}

func resolveStagePrograms(stages []permissions.StageNormalization, scope string) {
	for i := range stages {
		stage := &stages[i]
		if len(stage.Tokens) == 0 {
			continue
		}
		resolved := permissions.ResolveRelativeProgram(stage.Tokens[0], scope, stage.ClearEnvironment || assignsPath(stage.Assignments))
		if resolved != stage.Tokens[0] {
			stage.ExecProgram = stage.Tokens[0]
			stage.Tokens[0] = resolved
		}
	}
}

func assignsPath(assignments []string) bool {
	return slices.ContainsFunc(assignments, func(a string) bool { return strings.HasPrefix(a, "PATH=") })
}

// childEnvValue reports the value the child process sees for name. The last entry wins, matching how
// exec resolves a duplicated variable.
func childEnvValue(env []string, name string) string {
	value := ""
	for _, entry := range env {
		if rest, ok := strings.CutPrefix(entry, name+"="); ok {
			value = rest
		}
	}
	return value
}

// ripgrepConfigEnv names the file ripgrep reads extra options from. Those options include
// `--pre=COMMAND`, so an inherited value runs a program the authorized argv never named.
const ripgrepConfigEnv = "RIPGREP_CONFIG_PATH"

// psEncoderPathEnv names the FreeBSD libxo encoder search path. An inherited value can make an
// otherwise automatic ps invocation load an encoder absent from the authorized argv.
const psEncoderPathEnv = "XO_ENCODER_PATH"

func stageRunsRipgrep(stage permissions.StageNormalization) bool {
	return len(stage.Tokens) > 0 && stage.Tokens[0] == "rg"
}

func stageRunsPS(stage permissions.StageNormalization) bool {
	return len(stage.Tokens) > 0 && stage.Tokens[0] == "ps"
}

// Under Go's default GOTOOLCHAIN=auto, even `go version` inside a module that asks for a newer Go
// downloads and runs that toolchain.
const goToolchainEnv = "GOTOOLCHAIN"

func stageRunsGoProbe(stage permissions.StageNormalization) bool {
	return len(stage.Tokens) > 0 && stage.Tokens[0] == "go" && permissions.ProbeStageReadOnly(stage.Tokens)
}

// `mise version` checks online for a newer mise about once a day unless it runs offline.
const miseOfflineEnv = "MISE_OFFLINE"

func stageRunsMiseProbe(stage permissions.StageNormalization) bool {
	return len(stage.Tokens) > 0 && stage.Tokens[0] == "mise" && permissions.ProbeStageReadOnly(stage.Tokens)
}

func probeEnvPin(stage permissions.StageNormalization) (name string, assignment string) {
	switch {
	case stageRunsGoProbe(stage):
		name, assignment = goToolchainEnv, goToolchainEnv+"=local"
	case stageRunsMiseProbe(stage):
		name, assignment = miseOfflineEnv, miseOfflineEnv+"=1"
	default:
		return "", ""
	}
	if slices.ContainsFunc(stage.Assignments, func(a string) bool { return strings.HasPrefix(a, name+"=") }) {
		return "", ""
	}
	return name, assignment
}

func stageRunsHg(stage permissions.StageNormalization) bool {
	return len(stage.Tokens) > 0 && stage.Tokens[0] == "hg"
}

// hgAutoEnv is the whole environment a mode-auto-allowed Mercurial process runs with. hg reads
// aliases, hooks, defaults, and extensions from configuration the approved argv never names, and
// HGPLAIN alone does not stop them, so nothing ambient survives: HGRCPATH and HGRCSKIPREPO drop the
// user and repository hgrc files, and PATH is preserved only so executables still resolve.
func hgAutoEnv() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HGRCPATH=" + os.DevNull,
		"HGRCSKIPREPO=1",
		"HGPLAIN=+strictflags",
	}
}

func stageRunsJJ(stage permissions.StageNormalization) bool {
	return len(stage.Tokens) > 0 && stage.Tokens[0] == "jj"
}

// jjAutoEnv is the whole environment a mode-auto-allowed Jujutsu process runs with: JJ_CONFIG= drops
// the user and system configuration files, JJ_PAGER cannot reach the child at all, and PATH is
// preserved only so executables still resolve. No environment variable disables jj's repository or
// workspace configuration, so jjAutoFlags carries the rest.
func jjAutoEnv() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"JJ_CONFIG=",
	}
}

// jjAutoFlags is the isolation jjAutoEnv cannot express. A command-line --config outranks every
// configuration file, which is the only way to stop a repository-configured ui.pager or
// ui.diff-formatter from launching a program; --ignore-working-copy keeps the read from writing a
// working-copy commit or an operation.
var jjAutoFlags = []string{
	"--no-pager",
	"--config", "ui.paginate=never",
	"--config", `ui.diff-formatter=":color-words"`,
	"--ignore-working-copy",
}

func jjAutoArgv(argv []string) []string {
	prefixed := make([]string, 0, len(argv)+len(jjAutoFlags))
	prefixed = append(prefixed, argv[0])
	prefixed = append(prefixed, jjAutoFlags...)
	return append(prefixed, argv[1:]...)
}

func stageRunsGit(stage permissions.StageNormalization) bool {
	return len(stage.Tokens) > 0 && stage.Tokens[0] == "git"
}

var gitAutoFlags = []string{"-c", "core.fsmonitor=false", "-c", "core.pager=cat", "--no-pager"}

func gitAutoArgv(argv []string) []string {
	out := append(append([]string{argv[0]}, gitAutoFlags...), argv[1:]...)
	at := 1 + len(gitAutoFlags)
	for at < len(out) {
		if out[at] == "-C" {
			at += 2
		} else if strings.HasPrefix(out[at], "-C=") {
			at++
		} else {
			break
		}
	}
	if at < len(out) && (out[at] == "diff" || out[at] == "log" || out[at] == "show") {
		out = slices.Insert(out, at+1, "--no-ext-diff", "--no-textconv")
	}
	return out
}

func execEnvWithout(assignments []string, excluded ...string) []string {
	env := os.Environ()
	kept := env[:0]
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if slices.Contains(excluded, name) {
			continue
		}
		kept = append(kept, entry)
	}
	return append(kept, assignments...)
}
