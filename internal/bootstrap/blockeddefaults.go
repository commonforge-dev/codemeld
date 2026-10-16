package bootstrap

import (
	"fmt"
	"strings"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/permissions"
)

type blockedDefaultGroup struct {
	heading string
	paths   []string
}

var recommendedBlockedPaths = []blockedDefaultGroup{
	{"Keys and passwords", []string{
		"~/.ssh",
		"~/.gnupg",
		"~/.password-store",
		"~/.local/share/keyrings",
		"~/.local/share/kwalletd",
		"~/Library/Keychains",
	}},
	{"Cloud and cluster logins", []string{
		"~/.aws",
		"~/.azure",
		"~/.config/gcloud",
		"~/AppData/Roaming/gcloud",
		"~/.kube",
		"~/.docker/config.json",
	}},
	{"Infrastructure tokens", []string{
		"~/.terraform.d/credentials.tfrc.json",
		"~/AppData/Roaming/terraform.d/credentials.tfrc.json",
		"~/.vault-token",
	}},
	{"Version-control config and tokens", []string{
		"~/.hgrc",
		"~/.config/hg/hgrc",
		"~/Mercurial.ini",
		"~/.gitconfig",
		"~/.config/git/config",
		"~/.git-credentials",
		"~/.config/git/credentials",
		"~/.config/gh",
		"~/AppData/Roaming/GitHub CLI",
		"~/.netrc",
		"~/_netrc",
	}},
	{"Package tokens", []string{
		"~/.npmrc",
		"~/.pypirc",
		"~/.config/pip/pip.conf",
		"~/.pip/pip.conf",
		"~/Library/Application Support/pip/pip.conf",
		"~/AppData/Roaming/pip/pip.ini",
		"~/.cargo/credentials.toml",
		"~/.cargo/credentials",
		"~/.gem/credentials",
		"~/.local/share/gem/credentials",
	}},
	{"Java build settings", []string{
		"~/.m2/settings.xml",
		"~/.m2/settings-security.xml",
		"~/.gradle/gradle.properties",
	}},
	{"Other AI coding tools' logins", []string{
		"~/.claude/.credentials.json",
		"~/.codex/auth.json",
		"~/.local/share/opencode/auth.json",
	}},
	{"Shell history", []string{
		"~/.bash_history",
		"~/.zsh_history",
		"~/.local/share/fish/fish_history",
		"~/.sh_history",
		"~/.history",
	}},
	{"Browser profiles", []string{
		"~/.mozilla/firefox",
		"~/.config/mozilla/firefox",
		"~/.config/google-chrome",
		"~/.config/chromium",
		"~/snap/firefox/common/.mozilla/firefox",
		"~/snap/chromium/common/chromium",
		"~/.var/app/org.mozilla.firefox/.mozilla/firefox",
		"~/.var/app/com.google.Chrome/config/google-chrome",
		"~/.var/app/org.chromium.Chromium/config/chromium",
		"~/Library/Application Support/Firefox/Profiles",
		"~/Library/Application Support/Google/Chrome",
		"~/Library/Application Support/Chromium",
		"~/AppData/Roaming/Mozilla/Firefox/Profiles",
		"~/AppData/Local/Google/Chrome/User Data",
		"~/AppData/Local/Chromium/User Data",
	}},
}

const blockedPathsIntro = `# blocked_paths: the agent's tools and read-only commands can never read or
# change these paths. codemeld wrote these recommended entries once, on first
# start, and never adds more. They are not a complete list of your secrets.
# Remove an entry to let the agent use it, or add your own absolute or ~/ paths.
`

func renderBlockedPathsBlock() string {
	var b strings.Builder
	b.WriteString(blockedPathsIntro)
	b.WriteString("blocked_paths:\n")
	for _, group := range recommendedBlockedPaths {
		fmt.Fprintf(&b, "  # %s\n", group.heading)
		for _, path := range group.paths {
			fmt.Fprintf(&b, "  - %q\n", path)
		}
	}
	return b.String()
}

func bigBlockedEntryWarnings(home string, entries []permissions.BlockedEntry, foldCase bool) []string {
	var warnings []string
	for _, entry := range entries {
		var covered []string
		for _, folder := range []string{"/", "/usr", "/lib", "/etc", home} {
			if _, ok := permissions.RelWithin(entry.Path, folder, foldCase); !ok {
				continue
			}
			if folder == home {
				folder = "your home folder (" + fserrors.CollapseControls(home) + ")"
			}
			covered = append(covered, folder)
		}
		if len(covered) == 0 {
			continue
		}
		warnings = append(warnings, fmt.Sprintf(
			"warning: blocked_paths entry %s in %s covers %s; programs need these to start, so most commands will fail",
			fserrors.CollapseControls(entry.Path), fserrors.CollapseControls(entry.Source), strings.Join(covered, ", ")))
	}
	return warnings
}
