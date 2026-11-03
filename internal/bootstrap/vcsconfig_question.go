package bootstrap

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/permissions"
)

var (
	persistVCSUserConfig = config.Persist
	reloadVCSUserConfig  = defaultLoadGlobalSettings
)

var vcsUserConfigFiles = []struct {
	entry string
	git   bool
}{
	{"~/.hgrc", false},
	{"~/.config/hg/hgrc", false},
	{"~/.gitconfig", true},
	{"~/.config/git/config", true},
}

func askVCSUserConfig(home string, global map[string]any, stdin io.Reader, stderr io.Writer) (persisted bool) {
	if confinement, ok := global["confinement"].(map[string]any); ok {
		if _, set := confinement["vcs_user_config"]; set {
			return false
		}
	}
	entries := globalBlockedLiterals(home, global)
	var listed, extra, targets []string
	git := false
	for _, f := range vcsUserConfigFiles {
		path, err := permissions.ExpandBlockedEntry(home, f.entry)
		if err != nil || len(entries[path]) == 0 {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			continue
		}
		listed = append(listed, entries[path][0])
		targets = append(targets, path)
		git = git || f.git
	}
	if len(listed) == 0 || !stdinIsTerminal(stdin) {
		return false
	}
	if git {
		for _, f := range vcsUserConfigFiles {
			path, err := permissions.ExpandBlockedEntry(home, f.entry)
			if !f.git || err != nil || len(entries[path]) == 0 || slices.Contains(targets, path) {
				continue
			}
			extra = append(extra, entries[path][0])
			targets = append(targets, path)
		}
	}

	settings := SettingsPath(home)
	_, _ = fmt.Fprint(stderr, vcsUserConfigPrompt(settings, listed, extra))
	line, err := bufio.NewReader(stdin).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	if err != nil || (answer != "y" && answer != "yes") {
		recordVCSUserConfig(settings, "block", stderr)
		return true
	}

	for _, path := range targets {
		for range len(entries[path]) {
			if reason, _, err := persistVCSUserConfig(settings, "blocked_paths", config.BlockedPathRemove(home, path, 0)); err != nil {
				_, _ = fmt.Fprintf(stderr, "codemeld: couldn't update %s: %s\n", fserrors.CollapseControls(settings), reason)
				return true
			}
		}
	}
	reloaded, err := reloadVCSUserConfig(home)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "codemeld: couldn't check %s after removing blocked_paths entries: %s\n", fserrors.CollapseControls(settings), permissions.SingleLineControlEscape(err.Error()))
		return true
	}
	remaining := globalBlockedLiterals(home, reloaded)
	for _, path := range targets {
		if len(remaining[path]) > 0 {
			_, _ = fmt.Fprintf(stderr, "codemeld: couldn't update %s: blocked_paths still lists %s\n", fserrors.CollapseControls(settings), fserrors.CollapseControls(remaining[path][0]))
			return true
		}
	}
	recordVCSUserConfig(settings, "allow", stderr)
	return true
}

func globalBlockedLiterals(home string, global map[string]any) map[string][]string {
	items, _ := global["blocked_paths"].([]any)
	literals := map[string][]string{}
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			continue
		}
		if path, err := permissions.ExpandBlockedEntry(home, text); err == nil {
			literals[path] = append(literals[path], text)
		}
	}
	return literals
}

func recordVCSUserConfig(settings, answer string, stderr io.Writer) {
	if reason, _, err := persistVCSUserConfig(settings, config.KeyVCSUserConfig, answer); err != nil {
		_, _ = fmt.Fprintf(stderr, "codemeld: couldn't record %s: %s in %s: %s\n", config.KeyVCSUserConfig, answer, fserrors.CollapseControls(settings), reason)
	}
}

func vcsUserConfigPrompt(settings string, listed, extra []string) string {
	var b strings.Builder
	b.WriteString("codemeld: sandboxed hg and git can't read these config files of yours, so your settings in them are ignored:\n")
	for _, entry := range listed {
		fmt.Fprintf(&b, "  %s\n", fserrors.CollapseControls(entry))
	}
	fmt.Fprintf(&b, "Allow removes their blocked_paths entries from %s.\n", fserrors.CollapseControls(settings))
	for _, entry := range extra {
		fmt.Fprintf(&b, "It also removes the git entry %s, because git ignores both git files while either is blocked.\n", fserrors.CollapseControls(entry))
	}
	b.WriteString("Once allowed, every command and the model can read these files, so any password in them becomes visible.\n")
	b.WriteString("Allow? [y/N] ")
	return b.String()
}
