package bootstrap

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/iotest"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/fserrors"
)

const vcsQuestionWarning = "every command and the model can read these files, so any password in them becomes visible"

func vcsQuestionHome(t *testing.T, settings string, files ...string) string {
	t.Helper()
	home := realPath(t, t.TempDir())
	writeGlobalSettings(t, home, settings, 0o600)
	for _, rel := range files {
		path := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte("[ui]\nusername = u\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return home
}

func forceStdinTerminal(t *testing.T, on bool) {
	t.Helper()
	prev := stdinIsTerminal
	stdinIsTerminal = func(io.Reader) bool { return on }
	t.Cleanup(func() { stdinIsTerminal = prev })
}

func swapVCSPersist(t *testing.T, fn func(path, key string, value any) (config.PersistReason, fserrors.Category, error)) {
	t.Helper()
	prev := persistVCSUserConfig
	persistVCSUserConfig = fn
	t.Cleanup(func() { persistVCSUserConfig = prev })
}

func askVCSQuestion(t *testing.T, home string, stdin io.Reader) (bool, string) {
	t.Helper()
	global, err := defaultLoadGlobalSettings(home)
	if err != nil {
		t.Fatalf("load global settings: %v", err)
	}
	var stderr strings.Builder
	persisted := askVCSUserConfig(home, global, stdin, &stderr)
	return persisted, stderr.String()
}

func diskGlobal(t *testing.T, home string) (blocked []string, answer string, set bool) {
	t.Helper()
	global, err := defaultLoadGlobalSettings(home)
	if err != nil {
		t.Fatalf("reload global settings: %v", err)
	}
	items, _ := global["blocked_paths"].([]any)
	for _, item := range items {
		blocked = append(blocked, item.(string))
	}
	confinement, _ := global["confinement"].(map[string]any)
	value, set := confinement["vcs_user_config"]
	answer, _ = value.(string)
	return blocked, answer, set
}

func wantBlocked(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("blocked_paths = %q, want %q", got, want)
	}
}

func vcsQuestionEligible(t *testing.T, home string) bool {
	t.Helper()
	_, stderr := askVCSQuestion(t, home, strings.NewReader(""))
	return strings.Contains(stderr, "Allow? [y/N]")
}

func stageOSStdin(t *testing.T, input string) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := w.WriteString(input); err != nil {
		t.Fatalf("stage stdin: %v", err)
	}
	_ = w.Close()
	prev := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = prev
		_ = r.Close()
	})
	return r
}

func requireVCSAllowed(t *testing.T, step string, global map[string]any, blocked ...string) {
	t.Helper()
	var got []string
	items, _ := global["blocked_paths"].([]any)
	for _, item := range items {
		got = append(got, item.(string))
	}
	confinement, _ := global["confinement"].(map[string]any)
	if !slices.Equal(got, blocked) || confinement["vcs_user_config"] != "allow" {
		t.Fatalf("%s saw blocked_paths %q and confinement %v, want %q and vcs_user_config allow", step, got, confinement, blocked)
	}
}

type noReadStdin struct{ t *testing.T }

func (r noReadStdin) Read([]byte) (int, error) {
	r.t.Fatal("stdin was read")
	return 0, io.EOF
}

func TestAskVCSUserConfig_AllowRemovesTheHgEntryAndRecordsAllow(t *testing.T) {
	forceStdinTerminal(t, true)
	home := vcsQuestionHome(t, "# mine\nblocked_paths:\n  - ~/.hgrc\n  - ~/.ssh\n  - ~/.gitconfig\nattribution: true # keep\n", ".hgrc")

	persisted, stderr := askVCSQuestion(t, home, strings.NewReader("YES\n"))

	if !persisted {
		t.Fatal("persisted = false, want true after an answer")
	}
	if !strings.Contains(stderr, "  ~/.hgrc\n") || !strings.Contains(stderr, vcsQuestionWarning) {
		t.Fatalf("question = %q, want it to name ~/.hgrc and warn that the model can read it", stderr)
	}
	if strings.Contains(stderr, "~/.gitconfig") {
		t.Fatalf("question = %q, want no git entry named when no git file exists", stderr)
	}
	blocked, answer, _ := diskGlobal(t, home)
	wantBlocked(t, blocked, "~/.ssh", "~/.gitconfig")
	if answer != "allow" {
		t.Fatalf("vcs_user_config = %q, want allow", answer)
	}
	if data := settingsBytes(t, SettingsPath(home)); !strings.Contains(data, "# mine\n") || !strings.Contains(data, "attribution: true # keep\n") {
		t.Fatalf("settings = %q, want the comments and sibling keys kept", data)
	}

	if reason, _, err := config.Persist(SettingsPath(home), config.KeyRetentionDays, 14); err != nil {
		t.Fatalf("a later settings edit failed: %s %v", reason, err)
	}
	global, err := defaultLoadGlobalSettings(home)
	if err != nil {
		t.Fatalf("reload after the later edit: %v", err)
	}
	if sessions, _ := global["sessions"].(map[string]any); fmt.Sprint(sessions["retention_days"]) != "14" {
		t.Fatalf("sessions = %#v, want retention_days 14", global["sessions"])
	}
	if _, answer, _ := diskGlobal(t, home); answer != "allow" {
		t.Fatalf("vcs_user_config = %q after the later edit, want allow", answer)
	}
}

func TestAskVCSUserConfig_AllowingOneGitFileRemovesBothGitEntries(t *testing.T) {
	forceStdinTerminal(t, true)
	home := vcsQuestionHome(t, blockedYAML("~/.gitconfig", "~/.hgrc", "~/.config/git/config"), ".gitconfig")

	_, stderr := askVCSQuestion(t, home, strings.NewReader("y\n"))

	if !strings.Contains(stderr, "  ~/.gitconfig\n") || !strings.Contains(stderr, "also removes the git entry ~/.config/git/config") {
		t.Fatalf("question = %q, want ~/.gitconfig listed and ~/.config/git/config named as the extra removal", stderr)
	}
	if strings.Contains(stderr, "  ~/.config/git/config\n") || strings.Contains(stderr, "~/.hgrc") {
		t.Fatalf("question = %q, want only existing candidates in the file list", stderr)
	}
	blocked, answer, _ := diskGlobal(t, home)
	wantBlocked(t, blocked, "~/.hgrc")
	if answer != "allow" {
		t.Fatalf("vcs_user_config = %q, want allow", answer)
	}
}

func TestAskVCSUserConfig_AllowRemovesEveryEquivalentSpellingAndNothingElse(t *testing.T) {
	forceStdinTerminal(t, true)
	home := realPath(t, t.TempDir())
	settings := blockedYAML("~/.hgrc", home+"/.hgrc", "~/.config/hg", "~/./.hgrc", "~/.ssh", home+"//.hgrc")
	writeGlobalSettings(t, home, settings, 0o600)
	if err := os.WriteFile(filepath.Join(home, ".hgrc"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(home, "project")
	writeProjectSettings(t, project, blockedYAML("~/.hgrc"))
	projectSettings := projectSettingsPath(project)
	projectBefore := settingsBytes(t, projectSettings)

	askVCSQuestion(t, home, strings.NewReader("y\n"))

	blocked, answer, _ := diskGlobal(t, home)
	wantBlocked(t, blocked, "~/.config/hg", "~/.ssh")
	if answer != "allow" {
		t.Fatalf("vcs_user_config = %q, want allow", answer)
	}
	if got := settingsBytes(t, projectSettings); got != projectBefore {
		t.Fatalf("project settings = %q, want %q untouched", got, projectBefore)
	}
}

func TestAskVCSUserConfig_KeepBlockedRecordsBlockAndChangesNothingElse(t *testing.T) {
	forceStdinTerminal(t, true)
	home := vcsQuestionHome(t, blockedYAML("~/.hgrc", "~/.gitconfig", "~/.config/git/config"), ".hgrc", ".gitconfig")

	persisted, _ := askVCSQuestion(t, home, strings.NewReader("no\n"))

	if !persisted {
		t.Fatal("persisted = false, want true after recording the answer")
	}
	blocked, answer, _ := diskGlobal(t, home)
	wantBlocked(t, blocked, "~/.hgrc", "~/.gitconfig", "~/.config/git/config")
	if answer != "block" {
		t.Fatalf("vcs_user_config = %q, want block", answer)
	}
	if vcsQuestionEligible(t, home) {
		t.Fatal("asked again while the answer is recorded")
	}
}

func TestAskVCSUserConfig_NoQuestion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		settings string
		files    []string
		terminal bool
	}{
		{"answer allow recorded", blockedYAML("~/.hgrc") + "confinement:\n  vcs_user_config: allow\n", []string{".hgrc"}, true},
		{"answer block recorded", blockedYAML("~/.hgrc") + "confinement:\n  vcs_user_config: block\n", []string{".hgrc"}, true},
		{"unknown answer recorded", blockedYAML("~/.hgrc") + "confinement:\n  vcs_user_config: later\n", []string{".hgrc"}, true},
		{"no listed file exists", blockedYAML("~/.hgrc", "~/.gitconfig"), nil, true},
		{"stdin is not a terminal", blockedYAML("~/.hgrc"), []string{".hgrc"}, false},
		{"only a project settings entry blocks it", blockedYAML("~/.ssh"), []string{".hgrc"}, true},
		{"only a parent folder entry blocks it", blockedYAML("~/.config/hg"), []string{".config/hg/hgrc"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forceStdinTerminal(t, tc.terminal)
			home := vcsQuestionHome(t, tc.settings, tc.files...)
			project := filepath.Join(home, "project")
			writeProjectSettings(t, project, blockedYAML("~/.hgrc"))
			before := settingsBytes(t, SettingsPath(home))

			persisted, stderr := askVCSQuestion(t, home, noReadStdin{t})

			if persisted || stderr != "" {
				t.Fatalf("(persisted, stderr) = (%v, %q), want no question", persisted, stderr)
			}
			if got := settingsBytes(t, SettingsPath(home)); got != before {
				t.Fatalf("settings = %q, want %q unchanged", got, before)
			}
		})
	}
}

func TestAskVCSUserConfig_IncompleteOrFailedInputNeverAllows(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stdin io.Reader
	}{
		{"EOF", strings.NewReader("")},
		{"yes without a line end", strings.NewReader("yes")},
		{"read error after partial yes", io.MultiReader(strings.NewReader("yes"), iotest.ErrReader(errors.New("tty gone")))},
		{"other answer", strings.NewReader("yess\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forceStdinTerminal(t, true)
			home := vcsQuestionHome(t, blockedYAML("~/.hgrc"), ".hgrc")

			askVCSQuestion(t, home, tc.stdin)

			blocked, answer, _ := diskGlobal(t, home)
			wantBlocked(t, blocked, "~/.hgrc")
			if answer != "block" {
				t.Fatalf("vcs_user_config = %q, want block", answer)
			}
		})
	}
}

type persistMode int

const (
	persistReal persistMode = iota
	persistFail
	persistPublishThenFail
	persistSkip
)

func failingVCSPersist(mode func(key string, call int) persistMode) func(string, string, any) (config.PersistReason, fserrors.Category, error) {
	calls := map[string]int{}
	return func(path, key string, value any) (config.PersistReason, fserrors.Category, error) {
		calls[key]++
		switch mode(key, calls[key]) {
		case persistFail:
			return config.ReasonWriteError, fserrors.IOError, errors.New("disk full")
		case persistSkip:
			return config.ReasonNone, "", nil
		case persistPublishThenFail:
			if reason, cat, err := config.Persist(path, key, value); err != nil {
				return reason, cat, err
			}
			return config.ReasonParentDirError, fserrors.IOError, errors.New("fsync parent")
		}
		return config.Persist(path, key, value)
	}
}

func failOn(key string, mode persistMode) func(string, int) persistMode {
	return func(k string, _ int) persistMode {
		if k == key {
			return mode
		}
		return persistReal
	}
}

func TestAskVCSUserConfig_Failures(t *testing.T) {
	const twoHg = "blocked_paths:\n  - ~/.hgrc\n  - ~/.config/hg/hgrc\n"
	for _, tc := range []struct {
		name        string
		settings    string
		files       []string
		answer      string
		fail        func(key string, call int) persistMode
		reload      func(string) (map[string]any, error)
		wantBlocked []string
		wantAnswer  string
		wantStderr  string
		eligible    bool
	}{
		{
			name:     "second removal fails after the first succeeded",
			settings: twoHg, files: []string{".hgrc", ".config/hg/hgrc"}, answer: "y\n",
			fail: func(key string, call int) persistMode {
				if key == "blocked_paths" && call == 2 {
					return persistFail
				}
				return persistReal
			},
			wantBlocked: []string{"~/.config/hg/hgrc"},
			wantStderr:  "couldn't update %s: write_error",
			eligible:    true,
		},
		{
			name:     "first removal publishes and then reports failure",
			settings: blockedYAML("~/.hgrc"), files: []string{".hgrc"}, answer: "y\n",
			fail:       failOn("blocked_paths", persistPublishThenFail),
			wantStderr: "couldn't update %s: parent_dir_error",
		},
		{
			name:     "removal reports success but the entry is still listed",
			settings: blockedYAML("~/.hgrc"), files: []string{".hgrc"}, answer: "y\n",
			fail:        failOn("blocked_paths", persistSkip),
			wantBlocked: []string{"~/.hgrc"},
			wantStderr:  "couldn't update %s: blocked_paths still lists ~/.hgrc",
			eligible:    true,
		},
		{
			name:     "verification cannot read the settings",
			settings: blockedYAML("~/.hgrc"), files: []string{".hgrc"}, answer: "y\n",
			fail:       failOn("", persistReal),
			reload:     func(string) (map[string]any, error) { return nil, errors.New("settings unreadable") },
			wantStderr: "couldn't check %s after removing blocked_paths entries: settings unreadable",
		},
		{
			name:     "keep blocked answer fails to write",
			settings: blockedYAML("~/.hgrc"), files: []string{".hgrc"}, answer: "n\n",
			fail:        failOn(config.KeyVCSUserConfig, persistFail),
			wantBlocked: []string{"~/.hgrc"},
			wantStderr:  "couldn't record confinement.vcs_user_config: block in %s: write_error",
			eligible:    true,
		},
		{
			name:     "allow answer fails before publication after every removal",
			settings: twoHg, files: []string{".hgrc", ".config/hg/hgrc"}, answer: "y\n",
			fail:       failOn(config.KeyVCSUserConfig, persistFail),
			wantStderr: "couldn't record confinement.vcs_user_config: allow in %s: write_error",
		},
		{
			name:     "allow answer publishes and then reports failure",
			settings: blockedYAML("~/.hgrc"), files: []string{".hgrc"}, answer: "y\n",
			fail:       failOn(config.KeyVCSUserConfig, persistPublishThenFail),
			wantAnswer: "allow",
			wantStderr: "couldn't record confinement.vcs_user_config: allow in %s: parent_dir_error",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forceStdinTerminal(t, true)
			home := vcsQuestionHome(t, tc.settings, tc.files...)
			swapVCSPersist(t, failingVCSPersist(tc.fail))
			if tc.reload != nil {
				prev := reloadVCSUserConfig
				reloadVCSUserConfig = tc.reload
				t.Cleanup(func() { reloadVCSUserConfig = prev })
			}

			persisted, stderr := askVCSQuestion(t, home, strings.NewReader(tc.answer))

			if !persisted {
				t.Fatal("persisted = false, want true so the launch reloads its settings")
			}
			want := "codemeld: " + strings.Replace(tc.wantStderr, "%s", SettingsPath(home), 1) + "\n"
			if !strings.HasSuffix(stderr, want) {
				t.Fatalf("stderr = %q, want it to end with %q", stderr, want)
			}
			blocked, answer, set := diskGlobal(t, home)
			wantBlocked(t, blocked, tc.wantBlocked...)
			if answer != tc.wantAnswer || set != (tc.wantAnswer != "") {
				t.Fatalf("vcs_user_config = (%q, set=%v), want %q", answer, set, tc.wantAnswer)
			}
			persistVCSUserConfig = config.Persist
			reloadVCSUserConfig = defaultLoadGlobalSettings
			if got := vcsQuestionEligible(t, home); got != tc.eligible {
				t.Fatalf("next launch asks = %v, want %v", got, tc.eligible)
			}
		})
	}
}
