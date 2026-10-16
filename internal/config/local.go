// Derives and validates <project>/.codemeld/settings.local.yaml, the per-user layer codemeld writes.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"codemeld.dev/codemeld/internal/fserrors"
)

const localSettingsName = "settings.local.yaml"

// localKeyDetail is the remediation for a key the local layer does not accept but the
// project layer does, so the message points at the shared file rather than at the global one.
const localKeyDetail = "key belongs in the project's .codemeld/settings.yaml"

const localGlobalGrantDetail = "grant_kind global is a machine-wide grant and must be written to ~/.codemeld/global/settings.yaml"

var localAllowedKeys = map[string]bool{
	"model":         true,
	"permissions":   true,
	blockedPathsKey: true,
}

var localAllowedModelSubkeys = map[string]bool{"active": true}

// LocalSettingsPath returns the per-user settings file inside the project root the active
// discovery.boundary already resolved. It stats nothing and never walks.
func LocalSettingsPath(projectRoot string) string {
	if projectRoot == "" {
		return ""
	}
	return filepath.Join(projectRoot, ".codemeld", localSettingsName)
}

func LocalSettingsLockPath(projectRoot string) string {
	path := LocalSettingsPath(projectRoot)
	if path == "" {
		return ""
	}
	return path + lockSuffix
}

// PersistLocal is the single write path into the local settings file. created reports a write
// that made the file, derived from stats taken either side of the write rather than from inside
// Persist's lock window, so two processes creating it at once may both report it.
func PersistLocal(projectRoot, key string, newValue any) (created bool, reason PersistReason, errCat fserrors.Category, err error) {
	path := LocalSettingsPath(projectRoot)
	_, statErr := os.Stat(path)
	absent := errors.Is(statErr, fs.ErrNotExist)
	reason, errCat, err = Persist(path, key, newValue)
	if absent && reason == ReasonNone {
		_, postErr := os.Stat(path)
		created = postErr == nil
	}
	return created, reason, errCat, err
}

func enforceLocalAllowList(path string, raw map[string]any) error {
	if err := EnforceGlobalOnly(path, raw); err != nil {
		return err
	}
	if key, ok := firstDisallowed(raw, localAllowedKeys); ok {
		return fmt.Errorf("%s: schema validation failed at %s: %s", path, key, localKeyDetail)
	}
	model, ok := raw["model"].(map[string]any)
	if !ok {
		return nil
	}
	if key, ok := firstDisallowed(model, localAllowedModelSubkeys); ok {
		return fmt.Errorf("%s: schema validation failed at model.%s: %s", path, key, localKeyDetail)
	}
	return nil
}

func firstDisallowed(m map[string]any, allowed map[string]bool) (string, bool) {
	var bad []string
	for k := range m {
		if !allowed[k] {
			bad = append(bad, k)
		}
	}
	if len(bad) == 0 {
		return "", false
	}
	sort.Strings(bad)
	return bad[0], true
}

// enforceLocalGrantKinds runs after ValidatePermissionEntries, so every entry already parsed;
// only the local layer's extra rule — no machine-wide grant — is applied here.
func enforceLocalGrantKinds(path string, raw map[string]any) error {
	list, ok := raw["permissions"].([]any)
	if !ok {
		return nil
	}
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if m["grant_kind"] == "global" {
			return fmt.Errorf("%s: schema validation failed at permissions.%d: %s", path, i, localGlobalGrantDetail)
		}
	}
	return nil
}
