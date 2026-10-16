package bootstrap

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"

	"golang.org/x/term"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/trust"
)

const trustPrompt = `codemeld: %s has not been approved yet.
Until you approve it, codemeld ignores %s.
Approve this project? [y/N] `

type WithheldCategory string

const (
	WithheldSettings     WithheldCategory = "settings"
	WithheldVCSTemplates WithheldCategory = "vcs_templates"
)

type WithheldInput struct {
	Category WithheldCategory
	Path     string
}

func interactiveTrustGate(stdin io.Reader, stderr io.Writer) func(home, projectRoot, launchDir string) trust.Decision {
	return func(home, projectRoot, launchDir string) trust.Decision {
		return gateTrust(home, projectRoot, launchDir, stdin, stderr, term.IsTerminal(streamFd(stdin)))
	}
}

func gateTrust(home, projectRoot, launchDir string, stdin io.Reader, stderr io.Writer, interactive bool) trust.Decision {
	decision := trust.Lookup(home, projectRoot)
	if decision.Trusted || decision.Root == "" {
		return decision
	}

	present, determinate := presentGatedPaths(projectRoot)
	switch {
	case !determinate:
		decision = trust.Decision{Reason: trust.ReasonUnreadable, Root: decision.Root}
	case len(present) == 0 && decision.Reason == trust.ReasonNoRecord:
		return trust.Decision{Trusted: true, Reason: trust.ReasonNothingCovered, Root: decision.Root}
	case len(present) == 0:
		return decision
	case interactive && askTrust(stdin, stderr, projectRoot, present):
		err := trust.Record(home, decision.Root)
		if err == nil {
			return trust.Decision{Trusted: true, Reason: trust.ReasonTrusted, Root: decision.Root}
		}
		_, _ = fmt.Fprintf(stderr, "codemeld: could not record approval of %s, project stays unapproved: %v\n", projectRoot, err)
	}

	noticeUntrustedProject(stderr, projectRoot, withheldInputs(projectRoot, false))
	return decision
}

// presentGatedPaths inspects only metadata, so an unapproved project has none of its bytes read.
// Anything but a plain absence, a regular settings file or a real template directory is
// indeterminate.
func presentGatedPaths(projectRoot string) ([]string, bool) {
	vcsDir := projectVCSTemplateDir(projectRoot)
	var present []string
	for _, path := range []string{projectSettingsPath(projectRoot), config.LocalSettingsPath(projectRoot), vcsDir} {
		info, err := os.Lstat(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return nil, false
		case path == vcsDir && !info.IsDir(), path != vcsDir && !info.Mode().IsRegular():
			return nil, false
		}
		present = append(present, path)
	}
	return present, true
}

func headlessTrustGate(stderr io.Writer) func(home, projectRoot, launchDir string) trust.Decision {
	return func(home, projectRoot, launchDir string) trust.Decision {
		return gateTrust(home, projectRoot, launchDir, nil, stderr, false)
	}
}

func askTrust(stdin io.Reader, stderr io.Writer, projectRoot string, present []string) bool {
	_, _ = fmt.Fprintf(stderr, trustPrompt, projectRoot, coveredInputs(projectRoot, present))
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

// protectedStatePolicy is the protected set both tool dispatchers bind. The approved-project
// store is in it so a model cannot approve the repository it is running in through the file tools.
func protectedStatePolicy(home, projectRoot string, layers []securitystate.LayerSnapshot) (securitystate.Policy, error) {
	blocked, err := blockedPathsFromLayers(home, projectRoot, layers)
	if err != nil {
		return securitystate.Policy{}, err
	}
	settingsPaths := []string{projectSettingsPath(projectRoot)}
	if local := config.LocalSettingsPath(projectRoot); local != "" {
		settingsPaths = append(settingsPaths, local)
	}
	settingsPaths = append(settingsPaths, SettingsPath(home), trust.StorePath(home))
	return securitystate.Policy{
		SettingsPaths: settingsPaths,
		Blocked:       blocked,
	}, nil
}

// coveredInputs describes VCS templates as commands because approving them approves argv the
// launch executes, which the word "templates" alone does not disclose.
func coveredInputs(projectRoot string, present []string) string {
	vcsDir := projectVCSTemplateDir(projectRoot)
	settings := slices.DeleteFunc(slices.Clone(present), func(path string) bool { return path == vcsDir })
	var parts []string
	if len(settings) > 0 {
		parts = append(parts, fmt.Sprintf("its project settings (%s)", strings.Join(settings, " and ")))
	}
	if len(settings) < len(present) {
		parts = append(parts, fmt.Sprintf("its VCS command templates (%s), which supply the commands codemeld runs for version control", vcsDir))
	}
	return strings.Join(parts, " and ")
}

// withheldInputs is the run-fixed record of what a degraded launch did not load. Both the
// launch notice and status reporting render this value, so neither parses the other's text.
// Like presentGatedPaths, it treats anything but a plain absence as present.
func withheldInputs(projectRoot string, trusted bool) []WithheldInput {
	if trusted || projectRoot == "" {
		return nil
	}
	vcsDir := projectVCSTemplateDir(projectRoot)
	var withheld []WithheldInput
	for _, path := range []string{projectSettingsPath(projectRoot), config.LocalSettingsPath(projectRoot), vcsDir} {
		if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		category := WithheldSettings
		if path == vcsDir {
			category = WithheldVCSTemplates
		}
		withheld = append(withheld, WithheldInput{Category: category, Path: path})
	}
	return withheld
}

func noticeUntrustedProject(stderr io.Writer, projectRoot string, withheld []WithheldInput) {
	if len(withheld) == 0 {
		return
	}
	parts := make([]string, 0, len(withheld))
	for _, input := range withheld {
		parts = append(parts, withheldLabel(input.Category)+" "+input.Path)
	}
	_, _ = fmt.Fprintf(stderr, "codemeld: unapproved project %s: ignoring %s\n", projectRoot, strings.Join(parts, " and "))
}

func withheldLabel(category WithheldCategory) string {
	if category == WithheldVCSTemplates {
		return "VCS command templates"
	}
	return "project settings"
}
