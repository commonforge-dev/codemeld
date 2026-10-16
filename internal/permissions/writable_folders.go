package permissions

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"codemeld.dev/codemeld/internal/paths"
)

const writableHomeImpact = "confined Auto commands and in-process edits may write under the home directory, except protected and blocked paths"

func ParseWritableFolders(raw any, home, projectRoot string) (folders []string, notices []string, err error) {
	return parseWritableFolders(raw, home, projectRoot, runtime.GOOS == "darwin" || runtime.GOOS == "windows")
}

func parseWritableFolders(raw any, home, projectRoot string, foldCase bool) (folders []string, notices []string, err error) {
	if raw == nil {
		return nil, nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, nil, fmt.Errorf("must be a list, got %T", raw)
	}
	entries := make([]string, 0, len(list))
	for i, item := range list {
		entry, ok := item.(string)
		if !ok {
			return nil, nil, fmt.Errorf("entry %d must be a string, got %T", i, item)
		}
		entries = append(entries, entry)
	}
	floors := newBlockedPaths(home, []BlockedEntry{{Path: filepath.Join(projectRoot, ".codemeld"), Source: "project"}}, foldCase)
	for _, entry := range entries {
		folder, reason := resolveWritableFolder(entry, home, floors)
		if reason != "" {
			notices = append(notices, fmt.Sprintf("writable_folders: entry %q: %s", entry, reason))
			continue
		}
		if slices.ContainsFunc(folders, func(kept string) bool {
			return kept == folder || (foldCase && strings.EqualFold(kept, folder))
		}) {
			continue
		}
		folders = append(folders, folder)
		if _, ok := RelWithin(folder, home, foldCase); ok {
			notices = append(notices, fmt.Sprintf("writable_folders: entry %q: %s", entry, writableHomeImpact))
		}
	}
	return folders, notices, nil
}

func resolveWritableFolder(entry, home string, floors *BlockedPaths) (string, string) {
	spelled := entry
	if runtime.GOOS == "windows" && strings.HasPrefix(entry, `~\`) {
		spelled = "~/" + entry[2:]
	}
	expanded, err := paths.Expand(home, spelled)
	if err != nil || !filepath.IsAbs(expanded) {
		return "", "must be an absolute path or start with ~/"
	}
	cleaned := filepath.Clean(expanded)
	if isFilesystemRoot(cleaned) {
		return "", "the filesystem root cannot be a writable folder"
	}
	if floor, blocked := floors.Blocking(cleaned); blocked {
		return "", protectedFloorReason(floor)
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", "the folder does not exist or cannot be resolved"
	}
	if isFilesystemRoot(resolved) {
		return "", "the filesystem root cannot be a writable folder"
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", "the folder does not exist or cannot be resolved"
	}
	if !info.IsDir() {
		return "", "not a directory"
	}
	return resolved, ""
}

func isFilesystemRoot(path string) bool {
	return filepath.Dir(path) == path
}

func protectedFloorReason(floor BlockedEntry) string {
	if floor.Floor() {
		return fmt.Sprintf("inside codemeld's protected home folder %s", floor.Path)
	}
	return fmt.Sprintf("inside the project's protected codemeld folder %s", floor.Path)
}
