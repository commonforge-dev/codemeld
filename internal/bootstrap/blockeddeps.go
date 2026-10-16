package bootstrap

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tui"
)

func removeBlockedEntry(blocked *permissions.BlockedPaths, home string, row tui.BlockedRow) string {
	global := SettingsPath(home)
	projectRoot := blocked.ProjectRoot()
	local := config.LocalSettingsPath(projectRoot)
	shared := sharedBlockedSettingsPath(projectRoot)

	var problem string
	switch {
	case row.Kind == tui.BlockedRowGlobal && row.Source == global:
		problem = persistBlockedPaths(global, config.BlockedPathRemove(home, row.Path, row.Occurrence))
	case row.Kind == tui.BlockedRowLocal && local != "" && row.Source == local:
		problem = removeLocalBlockedEntry(projectRoot, home, row)
	case row.Kind == tui.BlockedRowShared && shared != "" && row.Source == shared:
		problem = persistBlockedPaths(shared, config.BlockedPathRemove(home, row.Path, row.Occurrence))
	default:
		return fmt.Sprintf("only entries in %s can be removed here", removableBlockedFiles(global, local, shared))
	}
	if problem != "" {
		return problem
	}
	return stillBlockedReport(blocked, row.Path)
}

func removeLocalBlockedEntry(projectRoot, home string, row tui.BlockedRow) (problem string) {
	local := config.LocalSettingsPath(projectRoot)
	_, reason, _, err := config.PersistLocal(projectRoot, "blocked_paths", config.BlockedPathRemove(home, row.Path, row.Occurrence))
	if err != nil {
		return fmt.Sprintf("couldn't update %s: %s", fserrors.CollapseControls(local), reason)
	}
	return ""
}

func sharedBlockedSettingsPath(projectRoot string) string {
	if projectRoot == "" {
		return ""
	}
	return projectSettingsPath(projectRoot)
}

func removableBlockedFiles(paths ...string) string {
	var names []string
	for _, path := range paths {
		if path != "" {
			names = append(names, fserrors.CollapseControls(path))
		}
	}
	if len(names) == 1 {
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

func stillBlockedReport(blocked *permissions.BlockedPaths, path string) string {
	entry, ok := blocked.Current().Blocking(path)
	switch {
	case !ok:
		return ""
	case entry.Floor():
		return fmt.Sprintf("%s is still blocked: it is inside codemeld's own folder %s", fserrors.CollapseControls(path), fserrors.CollapseControls(entry.Path))
	default:
		return fmt.Sprintf("%s is still blocked by the blocked_paths entry %s in %s", fserrors.CollapseControls(path), fserrors.CollapseControls(entry.Path), fserrors.CollapseControls(entry.Source))
	}
}

func addRecommendedEntry(home string, row tui.BlockedRow) string {
	if row.Kind != tui.BlockedRowMissing {
		return "only recommended entries can be added here"
	}
	return persistBlockedPaths(SettingsPath(home), config.BlockedPathAdd(home, row.Path, row.Group))
}

const (
	blockedProjectUnavailable = "refused: project settings are not available for this launch (no approved project root); nothing written"
	blockedUnknownDestination = "refused: unknown /blocked destination; nothing written"
)

func addUserEntry(blocked *permissions.BlockedPaths, home, raw string, dest tui.BlockedDestination, projectAllowed bool, boundary string) string {
	projectRoot := blocked.ProjectRoot()
	switch dest {
	case tui.BlockedGlobal:
	case tui.BlockedProjectShared, tui.BlockedProjectLocal:
		if !projectAllowed || projectRoot == "" {
			return blockedProjectUnavailable
		}
	default:
		return blockedUnknownDestination
	}
	expanded, err := permissions.ExpandBlockedEntry(home, raw)
	if err != nil {
		return fserrors.CollapseControls(err.Error())
	}
	current := blocked.Current()
	if entry, ok := current.Blocking(expanded); ok {
		if entry.Floor() {
			return fmt.Sprintf("%s is already blocked: it is inside codemeld's own folder %s", fserrors.CollapseControls(raw), fserrors.CollapseControls(entry.Path))
		}
		return fmt.Sprintf("%s is already blocked by the blocked_paths entry %s in %s", fserrors.CollapseControls(raw), fserrors.CollapseControls(entry.Path), fserrors.CollapseControls(entry.Source))
	}
	target, created, problem := persistUserEntry(home, projectRoot, raw, dest, boundary)
	if problem != "" {
		return problem
	}
	msg := fmt.Sprintf("%s is now blocked (added to %s)", fserrors.CollapseControls(raw), fserrors.CollapseControls(target))
	for _, warning := range bigBlockedEntryWarnings(home, []permissions.BlockedEntry{{Path: expanded, Source: target}}, current.FoldCase()) {
		msg += "; " + warning
	}
	if created != "" {
		msg += "\n" + created
	}
	return msg
}

func persistUserEntry(home, projectRoot, raw string, dest tui.BlockedDestination, boundary string) (target, created, problem string) {
	payload := config.BlockedPathAdd(home, raw, "")
	switch dest {
	case tui.BlockedProjectShared:
		target = projectSettingsPath(projectRoot)
		_, statErr := os.Stat(target)
		if problem = persistBlockedPaths(target, payload); problem != "" || !errors.Is(statErr, fs.ErrNotExist) {
			return target, "", problem
		}
		if _, err := os.Stat(target); err != nil {
			return target, "", ""
		}
		shown := permissions.BoundPromptFact(target)
		if boundary == discoveryLaunchDirOnly {
			return target, tui.RenderCrossModeMarkerNotice(shown), ""
		}
		return target, tui.RenderProjectRootMarkerNotice(shown), ""
	case tui.BlockedProjectLocal:
		target = config.LocalSettingsPath(projectRoot)
		isNew, reason, _, err := config.PersistLocal(projectRoot, "blocked_paths", payload)
		switch {
		case err != nil:
			return target, "", fmt.Sprintf("couldn't update %s: %s", fserrors.CollapseControls(target), reason)
		case isNew:
			return target, tui.RenderLocalSettingsIgnoreNotice(target, config.LocalSettingsLockPath(projectRoot)), ""
		}
		return target, "", ""
	}
	target = SettingsPath(home)
	return target, "", persistBlockedPaths(target, payload)
}

func addAllRecommended(home string, rows []tui.BlockedRow) string {
	for i, row := range rows {
		if problem := addRecommendedEntry(home, row); problem != "" {
			return fmt.Sprintf("processed %d of %d; stopped at %s: %s", i, len(rows), fserrors.CollapseControls(row.Path), problem)
		}
	}
	return fmt.Sprintf("processed %d recommended entries in %s (already-present entries left unchanged)", len(rows), fserrors.CollapseControls(SettingsPath(home)))
}

func persistBlockedPaths(global string, payload any) string {
	if reason, _, err := config.Persist(global, "blocked_paths", payload); err != nil {
		return fmt.Sprintf("couldn't update %s: %s", fserrors.CollapseControls(global), reason)
	}
	return ""
}

type sourcedBlockedPath struct{ source, path string }

func blockedRows(blocked *permissions.BlockedPaths, home, globalPath string) []tui.BlockedRow {
	current := blocked.Current()
	projectRoot := blocked.ProjectRoot()
	return blockedRowsFrom(current.Entries(), home, globalPath, config.LocalSettingsPath(projectRoot), sharedBlockedSettingsPath(projectRoot), current.FoldCase())
}

func blockedRowsFrom(entries []permissions.BlockedEntry, home, globalPath, localPath, sharedPath string, foldCase bool) []tui.BlockedRow {
	configured := slices.DeleteFunc(slices.Clone(entries), permissions.BlockedEntry.Floor)
	var rows []tui.BlockedRow
	for _, warning := range bigBlockedEntryWarnings(home, configured, foldCase) {
		rows = append(rows, tui.BlockedRow{Kind: tui.BlockedRowWarning, Text: warning})
	}
	var global []string
	// Occurrence indexes within the file a removal rewrites, so the counter is keyed per source.
	seen := map[sourcedBlockedPath]int{}
	for _, entry := range entries {
		key := sourcedBlockedPath{source: entry.Source, path: entry.Path}
		switch {
		case entry.Floor():
			rows = append(rows, tui.BlockedRow{Kind: tui.BlockedRowFloor, Path: entry.Path})
		case entry.Source == globalPath:
			rows = append(rows, tui.BlockedRow{Kind: tui.BlockedRowGlobal, Path: entry.Path, Source: entry.Source, Occurrence: seen[key]})
			seen[key]++
			global = append(global, entry.Path)
		case localPath != "" && entry.Source == localPath:
			rows = append(rows, tui.BlockedRow{Kind: tui.BlockedRowLocal, Path: entry.Path, Source: entry.Source, Occurrence: seen[key]})
			seen[key]++
		case sharedPath != "" && entry.Source == sharedPath:
			rows = append(rows, tui.BlockedRow{Kind: tui.BlockedRowShared, Path: entry.Path, Source: entry.Source, Occurrence: seen[key]})
			seen[key]++
		default:
			rows = append(rows, tui.BlockedRow{Kind: tui.BlockedRowProject, Path: entry.Path, Source: entry.Source})
		}
	}
	for _, group := range recommendedBlockedPaths {
		var missing []tui.BlockedRow
		for _, path := range group.paths {
			expanded, err := permissions.ExpandBlockedEntry(home, path)
			if err != nil || slices.ContainsFunc(global, func(entry string) bool {
				_, ok := permissions.RelWithin(entry, expanded, foldCase)
				return ok
			}) {
				continue
			}
			missing = append(missing, tui.BlockedRow{Kind: tui.BlockedRowMissing, Path: path, Group: group.heading})
		}
		if len(missing) > 0 {
			rows = append(rows, tui.BlockedRow{Kind: tui.BlockedRowGroup, Text: group.heading})
			rows = append(rows, missing...)
		}
	}
	return rows
}
