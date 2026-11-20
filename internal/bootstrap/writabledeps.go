package bootstrap

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tui"
)

type writableFolders struct {
	home, projectRoot string
	allowed           bool
}

func newWritableFolders(home, projectRoot string, allowed bool) writableFolders {
	return writableFolders{home: home, projectRoot: projectRoot, allowed: allowed}
}

func (w writableFolders) deps(cache *config.Cache, authorizer *productionAuthorizer) tui.WritableFolderDeps {
	return tui.WritableFolderDeps{
		List: func() tui.WritableFoldersView {
			rows, unreadable := w.list()
			m, _ := callMode(context.Background(), authorizer.modeActive)
			return tui.WritableFoldersView{
				Rows:          rows,
				Unreadable:    unreadable,
				Mode:          m,
				Sandboxed:     authorizer.executionConstrained,
				Degraded:      authorizer.settingsBroken(),
				LayerAdmitted: w.projectRoot != "" && slices.Contains(cache.LayerPaths(), projectSettingsPath(w.projectRoot)),
			}
		},
		Add:    w.add,
		Remove: w.remove,
	}
}

func (w writableFolders) entries() ([]string, error) {
	if w.projectRoot == "" {
		return nil, nil
	}
	path := projectSettingsPath(w.projectRoot)
	data, found, ok := fsutil.ReadSettingsBytes(path)
	if !ok {
		return nil, fmt.Errorf("%s: %w", path, errSettingsUnreadable)
	}
	if !found {
		return nil, nil
	}
	raw, _, err := config.ValidateProjectSettingsBytes(data, path)
	if err != nil {
		return nil, err
	}
	value := raw[config.KeyWritableFolders]
	if value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: writable_folders must be a list, got %T", path, value)
	}
	entries := make([]string, len(items))
	for i, item := range items {
		if entries[i], ok = item.(string); !ok {
			return nil, fmt.Errorf("%s: writable_folders entry %d must be a string, got %T", path, i, item)
		}
	}
	return entries, nil
}

func (w writableFolders) list() ([]tui.WritableFolderRow, string) {
	entries, err := w.entries()
	if err != nil {
		return nil, fserrors.CollapseControls(err.Error())
	}
	rows := make([]tui.WritableFolderRow, len(entries))
	for i, entry := range entries {
		rows[i].Entry = entry
		if folders, notices, _ := permissions.ParseWritableFolders([]any{entry}, w.home, w.projectRoot); len(folders) == 0 {
			rows[i].Invalid = strings.Join(notices, "; ")
		}
	}
	return rows, ""
}

func (w writableFolders) add(entry string) string {
	if !w.allowed || w.projectRoot == "" {
		return blockedProjectUnavailable
	}
	folders, notices, err := permissions.ParseWritableFolders([]any{entry}, w.home, w.projectRoot)
	switch {
	case err != nil:
		return fserrors.CollapseControls(err.Error())
	case len(folders) == 0:
		return fserrors.CollapseControls(strings.Join(notices, "; ")) + "; nothing written"
	}
	path := projectSettingsPath(w.projectRoot)
	if current, err := w.entries(); err == nil && slices.Contains(current, entry) {
		return fmt.Sprintf("%s is already in writable_folders in %s; nothing written", fserrors.CollapseControls(entry), fserrors.CollapseControls(path))
	}
	if problem := persistWritableFolder(path, config.WritableFolderAdd(entry)); problem != "" {
		return problem
	}
	msg := fmt.Sprintf("%s added to writable_folders in %s", fserrors.CollapseControls(entry), fserrors.CollapseControls(path))
	for _, notice := range notices {
		msg += "; " + fserrors.CollapseControls(notice)
	}
	return msg
}

func (w writableFolders) remove(entry string) string {
	if !w.allowed || w.projectRoot == "" {
		return blockedProjectUnavailable
	}
	path := projectSettingsPath(w.projectRoot)
	if problem := persistWritableFolder(path, config.WritableFolderRemove(entry)); problem != "" {
		return problem
	}
	return fmt.Sprintf("%s removed from writable_folders in %s", fserrors.CollapseControls(entry), fserrors.CollapseControls(path))
}

func persistWritableFolder(path string, payload any) string {
	if reason, _, err := config.Persist(path, config.KeyWritableFolders, payload); err != nil {
		return fmt.Sprintf("couldn't update %s: %s", fserrors.CollapseControls(path), reason)
	}
	return ""
}
