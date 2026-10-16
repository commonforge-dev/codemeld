// Tests for folder-option containment (OmitFolderOption) and the
// launch-dir-only cross-mode marker applicability/text (CrossModeMarkerNotice).
package tui

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestOmitFolderOption_ContainmentRule(t *testing.T) {
	const root = "/work/project"
	cases := []struct {
		name                         string
		pathScope                    string
		folderGrantEligibleOutOfRoot bool
		projectUntrusted             bool
		want                         FolderOmission
	}{
		{"project root itself", "/work/project", false, false, FolderOptionOffered},
		{"direct descendant", "/work/project/sub", false, false, FolderOptionOffered},
		{"deep descendant", "/work/project/a/b/c", false, false, FolderOptionOffered},
		{"sibling sharing prefix", "/work/projectfoo", false, false, FolderOptionOutOfRoot},
		{"ancestor", "/work", false, false, FolderOptionOutOfRoot},
		{"unrelated tree", "/tmp/elsewhere", false, false, FolderOptionOutOfRoot},
		{"out-of-root eligible scope offers folder", "/tmp/elsewhere", true, false, FolderOptionOffered},
		{"out-of-root eligible sibling offers folder", "/work/projectfoo", true, false, FolderOptionOffered},
		// The signal never matters for an in-root scope: the folder option is already offered there.
		{"in-root scope with signal still offered", "/work/project/sub", true, false, FolderOptionOffered},
		{"untrusted in-root scope", "/work/project/sub", false, true, FolderOptionUntrusted},
		{"untrusted project root itself", "/work/project", false, true, FolderOptionUntrusted},
		{"untrusted out-of-root eligible scope", "/tmp/elsewhere", true, true, FolderOptionUntrusted},
		{"untrusted out-of-root scope", "/tmp/elsewhere", false, true, FolderOptionUntrusted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := OmitFolderOption(c.pathScope, root, c.folderGrantEligibleOutOfRoot, c.projectUntrusted)
			if got != c.want {
				t.Errorf("OmitFolderOption(%q, %q, %v, %v) = %v, want %v",
					c.pathScope, root, c.folderGrantEligibleOutOfRoot, c.projectUntrusted, got, c.want)
			}
			if got.Hidden() != (c.want != FolderOptionOffered) {
				t.Errorf("Hidden() = %v for %v", got.Hidden(), got)
			}
			if want := folderUnavailableText(c.want); c.want == FolderOptionUntrusted && want != untrustedProjectGrantExplanation {
				t.Errorf("untrusted explanation = %q, want the shared trust wording", want)
			}
		})
	}
}

func TestDisplayedPromptOptions_UntrustedProjectHidesFolderOption(t *testing.T) {
	trusted := PromptRequest{RunFolder: "/work/project/sub", ProjectRoot: "/work/project"}
	if !containsOption(displayedPromptOptions(trusted), OptionAllowFolder) {
		t.Fatalf("folder option hidden for a trusted in-root prompt; want offered")
	}

	untrusted := trusted
	untrusted.ProjectUntrusted = true
	shown := displayedPromptOptions(untrusted)
	if containsOption(shown, OptionAllowFolder) {
		t.Fatalf("folder option offered in an untrusted project: %v", shown)
	}
	if len(shown) != len(promptOptionsInOrder)-1 {
		t.Fatalf("displayed options = %d, want %d", len(shown), len(promptOptionsInOrder)-1)
	}
	if _, ok := promptMnemonicIndex(shown, 'f'); ok {
		t.Errorf("folder mnemonic still selects a row in an untrusted project: %v", shown)
	}
	if _, ok := promptMnemonicIndex(shown, 'g'); !ok {
		t.Errorf("global mnemonic lost: adr-051 leaves the global grant outside this gate")
	}

	outOfRoot := PromptRequest{RunFolder: "/outside/tree", ProjectRoot: "/work/project", OutOfRootFileWrite: true, ProjectUntrusted: true}
	if containsOption(displayedPromptOptions(outOfRoot), OptionAllowFolder) {
		t.Fatalf("an out-of-root edit/create re-enabled the folder option in an untrusted project")
	}
}

// TestDisplayedPromptOptions_OutOfRootEditCreateOffersFolder pins the folder option end-to-end at the
// option-list layer: an out-of-root structured edit/create (OutOfRootFileWrite) keeps the "allow in this
// folder permanently" option, while the same out-of-root scope without the signal drops it. Because
// displayedPromptOptions drives both the rendered list and the index→option mapping, this is the gate
// that makes the folder grant reachable (or not) — not merely visible.
func TestDisplayedPromptOptions_OutOfRootEditCreateOffersFolder(t *testing.T) {
	base := PromptRequest{RunFolder: "/outside/tree", ProjectRoot: "/work/project"}

	hidden := displayedPromptOptions(base)
	if containsOption(hidden, OptionAllowFolder) {
		t.Fatalf("folder option present for a non-edit/create out-of-root prompt; want hidden")
	}

	withSignal := base
	withSignal.OutOfRootFileWrite = true
	shown := displayedPromptOptions(withSignal)
	if !containsOption(shown, OptionAllowFolder) {
		t.Fatalf("folder option hidden for an out-of-root edit/create; want offered (adr-017)")
	}
	if len(shown) != len(promptOptionsInOrder) {
		t.Fatalf("displayed options = %d, want all %d when the folder option is offered", len(shown), len(promptOptionsInOrder))
	}
}

// TestDisplayedPromptOptions_OutOfRootReadOffersFolder pins reads at the option-list layer: an explicit
// out-of-project read-only scope (OutOfRootReadScope) re-enables the "allow in this folder permanently"
// option just as an out-of-root edit/create (OutOfRootFileWrite) does, so a read-only folder grant is
// reachable; with neither signal the same out-of-root scope drops it.
func TestDisplayedPromptOptions_OutOfRootReadOffersFolder(t *testing.T) {
	base := PromptRequest{RunFolder: "/outside/tree", ProjectRoot: "/work/project"}

	if containsOption(displayedPromptOptions(base), OptionAllowFolder) {
		t.Fatalf("folder option present for a plain out-of-root prompt; want hidden")
	}

	withRead := base
	withRead.OutOfRootReadScope = true
	shown := displayedPromptOptions(withRead)
	if !containsOption(shown, OptionAllowFolder) {
		t.Fatalf("folder option hidden for an out-of-project read; want offered (g815)")
	}
	if len(shown) != len(promptOptionsInOrder) {
		t.Fatalf("displayed options = %d, want all %d when the folder option is offered", len(shown), len(promptOptionsInOrder))
	}
}

func TestDisplayedPromptOptions_OutOfProjectShellOffersFolder(t *testing.T) {
	cases := []struct {
		name string
		req  PromptRequest
	}{
		{"direct command", outsideProjectDirectRequest()},
		{"literal command", outsideProjectLiteralRequest()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			shown := displayedPromptOptions(c.req)
			if !containsOption(shown, OptionAllowFolder) {
				t.Fatalf("folder option hidden for an out-of-project shell request; want offered")
			}
			if len(shown) != len(promptOptionsInOrder) {
				t.Fatalf("displayed options = %d, want all %d when the folder option is offered", len(shown), len(promptOptionsInOrder))
			}
			for i, row := range shown {
				if row.Option != promptOptionsInOrder[i].Option {
					t.Fatalf("option %d = %v, want %v (fixed order must not change)", i, row.Option, promptOptionsInOrder[i].Option)
				}
			}
			if optionIndex(shown, OptionAllowFolder) > optionIndex(shown, OptionAllowGlobal) {
				t.Errorf("folder option listed after the global option: %v", shown)
			}

			inProject := c.req
			inProject.RunFolder = "/work/project/sub"
			if !containsOption(displayedPromptOptions(inProject), OptionAllowFolder) {
				t.Errorf("folder option hidden for an in-project shell request")
			}
		})
	}
}

func TestDisplayedPromptOptions_NonShellOutOfProjectUnchanged(t *testing.T) {
	base := outsideProjectToolRequest()
	if containsOption(displayedPromptOptions(base), OptionAllowFolder) {
		t.Fatalf("folder option offered for an out-of-project structured tool with no exception signal")
	}

	write := base
	write.OutOfRootFileWrite = true
	if !containsOption(displayedPromptOptions(write), OptionAllowFolder) {
		t.Errorf("out-of-root edit/create lost its folder option (adr-017)")
	}

	read := base
	read.OutOfRootReadScope = true
	if !containsOption(displayedPromptOptions(read), OptionAllowFolder) {
		t.Errorf("out-of-project read-only scope lost its folder option")
	}
}

func optionIndex(rows []promptOptionRow, opt PromptOption) int {
	for i, r := range rows {
		if r.Option == opt {
			return i
		}
	}
	return -1
}

func containsOption(rows []promptOptionRow, opt PromptOption) bool {
	for _, r := range rows {
		if r.Option == opt {
			return true
		}
	}
	return false
}

func TestCrossModeMarkerNotice_ShownUnderLaunchDirOnlyWhenFileWouldBeCreated(t *testing.T) {
	const dir = "/launch/here"
	notice, show := CrossModeMarkerNotice(dir, dir, dir, "launch-dir-only", true, FolderOptionOffered)
	if !show {
		t.Fatalf("show = false, want true under launch-dir-only with a would-be-created marker at launch dir")
	}

	wantPath := filepath.Join(dir, ".codemeld", "settings.yaml")
	if notice != RenderCrossModeMarkerNotice(wantPath) {
		t.Errorf("notice = %q, want shared RenderCrossModeMarkerNotice wording %q", notice, RenderCrossModeMarkerNotice(wantPath))
	}
	if !strings.Contains(notice, wantPath) {
		t.Errorf("notice does not name the absolute settings path %q: %q", wantPath, notice)
	}
	if !strings.Contains(notice, "mark the launch directory as a project root") {
		t.Errorf("notice missing the cross-mode consequence: %q", notice)
	}
}

func TestCrossModeMarkerNotice_ShownForOutOfRootEditCreate(t *testing.T) {
	const launch = "/launch/here"
	outside := "/outside/tree"
	notice, show := CrossModeMarkerNotice(launch, launch, outside, "launch-dir-only", true, FolderOptionOffered)
	if !show {
		t.Fatalf("show = false, want true for an out-of-root edit/create folder grant under launch-dir-only")
	}
	wantPath := filepath.Join(launch, ".codemeld", "settings.yaml")
	if notice != RenderCrossModeMarkerNotice(wantPath) {
		t.Errorf("notice = %q, want shared wording %q", notice, RenderCrossModeMarkerNotice(wantPath))
	}
}

func TestCrossModeMarkerNotice_Suppressed(t *testing.T) {
	const dir = "/launch/here"
	cases := []struct {
		name            string
		launchDir       string
		projectRoot     string
		runFolder       string
		boundary        string
		wouldCreateFile bool
		omission        FolderOmission
	}{
		{"project-root mode never warns", dir, dir, dir, "project-root", true, FolderOptionOffered},
		{"existing file is not a new marker", dir, dir, dir, "launch-dir-only", false, FolderOptionOffered},
		{"path does not land at launch dir", dir, "/somewhere/else", "/somewhere/else", "launch-dir-only", true, FolderOptionOffered},
		{"relative project root is not absolute", "relative/launch", "relative/launch", "relative/launch", "launch-dir-only", true, FolderOptionOffered},
		// The notice describes the folder option, so any reason for hiding that option
		// suppresses it even when the launch-dir-only + would-create conditions hold.
		{"run folder outside project root hides folder option", dir, dir, "/outside/tree", "launch-dir-only", true, FolderOptionOutOfRoot},
		{"untrusted project hides folder option", dir, dir, dir, "launch-dir-only", true, FolderOptionUntrusted},
		// Even an out-of-root edit/create (folder option offered) is suppressed under
		// project-root mode — the carve-out still applies regardless of the new signal.
		{"out-of-root edit/create still suppressed under project-root mode", dir, dir, "/outside/tree", "project-root", true, FolderOptionOffered},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			notice, show := CrossModeMarkerNotice(c.launchDir, c.projectRoot, c.runFolder, c.boundary, c.wouldCreateFile, c.omission)
			if show {
				t.Errorf("show = true, want false (%s); notice=%q", c.name, notice)
			}
			if notice != "" {
				t.Errorf("notice = %q, want empty when suppressed", notice)
			}
		})
	}
}
