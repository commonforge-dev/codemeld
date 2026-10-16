package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

const FixedPATH = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"

type EnvAssignmentError struct {
	Name string
}

func (e *EnvAssignmentError) Error() string {
	return fmt.Sprintf("environment assignment to %q is not allowed", e.Name)
}

type ExecutableNotFoundError struct {
	Name string
}

func (e *ExecutableNotFoundError) Error() string {
	return fmt.Sprintf("executable %q not found on the lookup path", e.Name)
}

var (
	withheldEnvNames = []string{
		"PATH", "HOME", "PWD", "TMPDIR", "SHELL", "TERM", "LANG", "LC_ALL", "GOCACHE",
		"NODE_OPTIONS", "BASH_ENV", "ENV", "IFS", "SHELLOPTS", "RIPGREP_CONFIG_PATH", "DOCKER_HOST",
	}
	withheldEnvPrefixes = []string{"LD_", "DYLD_", "PYTHON", "PERL5", "GIT_", "HG", "SSH_", "DBUS_", "XDG_"}
)

func FixedEnvironment(home, cwd, tmpDir, lookupPath string, assignments []string) ([]string, error) {
	env := []string{"PATH=" + lookupPath, "HOME=" + home, "PWD=" + cwd}
	if tmpDir != "" {
		env = append(env, "TMPDIR="+tmpDir, "GOCACHE="+filepath.Join(tmpDir, "go-build"))
	}
	env = append(env, "SHELL=/bin/sh", "TERM=dumb", "LANG=C.UTF-8", "LC_ALL=C.UTF-8")
	block := len(env)
	for _, a := range assignments {
		name, _, ok := strings.Cut(a, "=")
		if !ok || name == "" || envNameWithheld(name) {
			return nil, &EnvAssignmentError{Name: name}
		}
		if i := slices.IndexFunc(env[block:], func(e string) bool { return strings.HasPrefix(e, name+"=") }); i >= 0 {
			env[block+i] = a
			continue
		}
		env = append(env, a)
	}
	return env, nil
}

func envNameWithheld(name string) bool {
	if slices.Contains(withheldEnvNames, name) || strings.HasSuffix(strings.ToUpper(name), "_PROXY") {
		return true
	}
	return slices.ContainsFunc(withheldEnvPrefixes, func(p string) bool { return strings.HasPrefix(name, p) })
}

func ResolveOnPath(name, lookupPath string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	if name != "" {
		for dir := range strings.SplitSeq(lookupPath, string(os.PathListSeparator)) {
			if !filepath.IsAbs(dir) {
				continue
			}
			resolved, err := exec.LookPath(filepath.Join(dir, name))
			if err != nil {
				continue
			}
			if info, err := os.Stat(resolved); err == nil && info.Mode().IsRegular() {
				return resolved, nil
			}
		}
	}
	return "", &ExecutableNotFoundError{Name: name}
}
