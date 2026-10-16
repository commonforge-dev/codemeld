// Folder-option containment and cross-mode marker applicability for the
// permission prompt.
package tui

import (
	"path/filepath"

	"codemeld.dev/codemeld/internal/permissions"
)

const folderUnavailableExplanation = "\"allow in this folder permanently\" is unavailable here: a permanent folder grant outside the project root is offered only for a file create or edit, for explicit out-of-project read-only tool access, or for a command run outside the project, not for this action."

// untrustedProjectGrantExplanation is worded for both the folder option and the host
// project option, which the two prompt surfaces label differently.
const untrustedProjectGrantExplanation = "A permanent project grant is unavailable here: this project is not trusted, so codemeld ignores its .codemeld/settings.yaml and a grant saved there would have no effect."

// promptOptionRow pairs a grant option with the label rendered for it. The fixed
// list promptOptionsInOrder is built from it, and displayedPromptOptions returns
// a filtered copy so the rendered list and the selection callback share one
// ordering — a hidden option can never be reached by index or key.
type promptOptionRow struct {
	Option PromptOption
	Label  string
}

// FolderOmission is why the folder-grant option is hidden, or that it is offered. The
// prompt's explanation, facts, marker notice and option list all read this one value, so
// they cannot disagree about whether the option exists or misreport the cause.
type FolderOmission int

const (
	FolderOptionOffered FolderOmission = iota
	FolderOptionOutOfRoot
	FolderOptionUntrusted
)

func (o FolderOmission) Hidden() bool { return o != FolderOptionOffered }

// OmitFolderOption fails closed: an untrusted project hides the folder option outright,
// and an out-of-root path scope hides it unless folderGrantEligibleOutOfRoot explicitly
// opts it in, since offering a folder grant outside the project root is the authorization
// hazard this guards against. Trust is reported ahead of containment because it holds for
// every scope in the run, so the containment wording would misstate the cause.
// pathScope and projectRoot must already be cleaned, absolute and symlink-resolved.
func OmitFolderOption(pathScope, projectRoot string, folderGrantEligibleOutOfRoot, projectUntrusted bool) FolderOmission {
	if projectUntrusted {
		return FolderOptionUntrusted
	}
	if permissions.IsDescendantOrEqual(pathScope, projectRoot) || folderGrantEligibleOutOfRoot {
		return FolderOptionOffered
	}
	return FolderOptionOutOfRoot
}

// folderUnavailableText names the real cause so an untrusted prompt does not borrow the
// containment wording, which would imply a create or edit could re-enable the option.
func folderUnavailableText(o FolderOmission) string {
	if o == FolderOptionUntrusted {
		return untrustedProjectGrantExplanation
	}
	return folderUnavailableExplanation
}

// displayedPromptOptions returns the prompt options in their fixed order,
// dropping the folder option when the containment rule hides it. The remaining
// four keep their relative order — allow this once, deny, allow for this session,
// allow globally permanently. The returned
// slice drives both the rendered list and the index→option mapping in
// buildPromptOverlay, so omission is never UI-only: a hidden option is absent
// from the decision path entirely.
func displayedPromptOptions(req PromptRequest) []promptOptionRow {
	if !req.folderOmission().Hidden() {
		return promptOptionsInOrder
	}
	out := make([]promptOptionRow, 0, len(promptOptionsInOrder))
	for _, o := range promptOptionsInOrder {
		if o.Option == OptionAllowFolder {
			continue
		}
		out = append(out, o)
	}
	return out
}

// CrossModeMarkerNotice computes the launch-dir-only cross-mode marker
// disclosure for the folder option. It returns the one-line notice and whether to
// show it. The notice is shown only when all of:
//   - omission reports the folder option offered, since the notice describes that option;
//   - boundary == "launch-dir-only", the only mode that can plant a new marker;
//   - wouldCreateFile is true (the file did not exist before — an existing file
//     is already a marker, so no new cross-mode surprise); and
//   - <projectRoot>/.codemeld/settings.yaml is an absolute path that lands at the
//     launch directory (<launchDir>/.codemeld/settings.yaml), i.e. the project
//     root has collapsed onto the launch dir.
//
// Otherwise it returns ("", false). The wording reuses the shared
// RenderCrossModeMarkerNotice helper so the prompt, the model picker, and the
// /effort and /model commands stay byte-identical (no duplicate string).
// launchDir, projectRoot, and runFolder are already-resolved absolute paths
// supplied by the caller; this function does not resolve or stat anything.
func CrossModeMarkerNotice(launchDir, projectRoot, runFolder, boundary string, wouldCreateFile bool, omission FolderOmission) (notice string, show bool) {
	if omission.Hidden() {
		return "", false
	}
	if boundary != "launch-dir-only" || !wouldCreateFile {
		return "", false
	}
	settingsPath := filepath.Join(projectRoot, ".codemeld", "settings.yaml")
	if !filepath.IsAbs(settingsPath) {
		return "", false
	}
	if settingsPath != filepath.Join(launchDir, ".codemeld", "settings.yaml") {
		return "", false
	}
	// The path is derived from the project root, so it is a variable authorization fact: it
	// carries the same bounded rendering as every other one before it reaches a fixed block.
	return RenderCrossModeMarkerNotice(permissions.BoundPromptFact(settingsPath)), true
}
