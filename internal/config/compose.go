// Composes the global and per-project settings layers into one effective config (95).
package config

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"

	"codemeld.dev/codemeld/internal/permissions"
)

const declaredCommandsKey = "declared_commands"

const blockedPathsKey = "blocked_paths"

const writableFoldersKey = "writable_folders"

// composeMergeMapKeys are the top-level keys whose values are merged by subkey
// (nearest-wins per subkey). Every other top-level key is replaced
// wholesale by the nearer layer, and `permissions`, `declared_commands`,
// `blocked_paths` and `writable_folders` have their own carve-outs.
var composeMergeMapKeys = map[string]bool{
	"discovery":          true,
	"agent":              true,
	"agent_instructions": true,
	"sessions":           true,
	"vcs":                true,
	"model":              true,
	"mode":               true,
	"provider":           true,
}

// localLayer is optional so the one production caller can adopt the third layer without
// changing shape; passing none composes exactly what two layers composed before.
func Compose(globalLayer, projectLayer map[string]any, localLayer ...map[string]any) (map[string]any, error) {
	var local map[string]any
	if len(localLayer) > 0 {
		local = localLayer[0]
	}
	layers := []map[string]any{globalLayer, projectLayer, local}
	composed := map[string]any{}

	if err := composePermissions(layers, composed); err != nil {
		return nil, err
	}
	composeDeclaredCommands(projectLayer, composed)
	composeWritableFolders(projectLayer, composed)
	if err := composeBlockedPaths(layers, composed); err != nil {
		return nil, err
	}

	for _, k := range unionKeys(layers) {
		if k == "permissions" {
			continue // handled by composePermissions
		}
		if k == declaredCommandsKey {
			continue // handled by composeDeclaredCommands
		}
		if k == blockedPathsKey || k == writableFoldersKey {
			continue
		}
		var current any
		held := false
		for _, layer := range layers {
			v, has := layer[k]
			if !has {
				continue
			}
			cm, currentIsMap := current.(map[string]any)
			vm, valueIsMap := v.(map[string]any)
			if held && composeMergeMapKeys[k] && currentIsMap && valueIsMap {
				current = mergeMapOneLevel(cm, vm)
				continue
			}
			// List replace, scalar override, and unknown keys present in more than one
			// layer: the nearer layer wins wholesale.
			current, held = deepCopyValue(v), true
		}
		if held {
			composed[k] = current
		}
	}

	return composed, nil
}

// LayerPermissions stamps provenance as the layer is read — before anything is concatenated or
// deduplicated — so it can never be claimed by the file's own content.
func LayerPermissions(raw map[string]any, kind permissions.LayerKind) ([]permissions.PermissionEntry, error) {
	list, _, err := layerList(raw, "permissions")
	if err != nil {
		return nil, err
	}
	source := string(kind) + " settings"
	out := make([]permissions.PermissionEntry, 0, len(list))
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("compose: permissions.%d is not a mapping, got %T", i, item)
		}
		entry, perr := permissions.ParseEntry(m, source, i)
		if perr != nil {
			return nil, perr
		}
		entry.Layer = kind
		out = append(out, entry)
	}
	return out, nil
}

// composeDeclaredCommands copies the declared command list from the project
// layer only: a machine-wide prompt-free execution list is not a thing a global
// layer may declare, so a global value is dropped rather than merged.
func composeDeclaredCommands(projectLayer, composed map[string]any) {
	if v, ok := projectLayer[declaredCommandsKey]; ok {
		composed[declaredCommandsKey] = deepCopyValue(v)
	}
}

func composeWritableFolders(projectLayer, composed map[string]any) {
	if v, ok := projectLayer[writableFoldersKey]; ok {
		composed[writableFoldersKey] = deepCopyValue(v)
	}
}

// A nearer list adds to the farther ones rather than replacing them, so no settings file can
// remove another's blocked entries.
func composeBlockedPaths(layers []map[string]any, composed map[string]any) error {
	var concat []any
	present := false
	for _, layer := range layers {
		list, has, err := layerList(layer, blockedPathsKey)
		if err != nil {
			return err
		}
		present = present || has
		concat = slices.Concat(concat, list)
	}
	if present {
		composed[blockedPathsKey] = deepCopyValue(concat)
	}
	return nil
}

// mergeMapOneLevel returns a one-level merge of two map values: every global
// subkey is carried over, then each project subkey overrides it wholesale
// (nearest-wins). Subkey values are deep-copied so the result aliases
// neither input. The merge is intentionally one level deep — a provider entry or
// model.active value is replaced as a whole rather than merged field-by-field.
func mergeMapOneLevel(global, project map[string]any) map[string]any {
	merged := make(map[string]any, len(global)+len(project))
	for k, v := range global {
		merged[k] = deepCopyValue(v)
	}
	for k, v := range project {
		merged[k] = deepCopyValue(v)
	}
	return merged
}

// composePermissions applies the concatenate-merge carve-out and writes
// the deduplicated list to composed under "permissions". It sets the key only
// when at least one layer contributes entries: a project layer whose
// `permissions` list is explicitly empty is treated as absent, so it
// neither revokes global grants nor forces an empty list into the result.
func composePermissions(layers []map[string]any, composed map[string]any) error {
	globalList, globalHas, err := layerList(layers[0], "permissions")
	if err != nil {
		return err
	}
	concat := slices.Clone(globalList) // global first, then project, then local (ordering)
	contributes := globalHas
	for _, layer := range layers[1:] {
		list, has, lerr := layerList(layer, "permissions")
		if lerr != nil {
			return lerr
		}
		// an explicit empty permissions list in a project-scope layer behaves
		// the same as omitting the key, so only a non-empty list contributes.
		if !has || len(list) == 0 {
			continue
		}
		concat, contributes = append(concat, list...), true
	}
	if !contributes {
		return nil // omit permissions entirely
	}

	deduped, err := dedupPermissions(concat)
	if err != nil {
		return err
	}
	composed["permissions"] = deduped
	return nil
}

// layerList returns the layer's value for key as a list, whether it was
// present, and an error if the value is present but not a list. A present nil
// value (key set to null) is rejected as malformed, since a schema-valid
// list setting is always a list, never null.
func layerList(layer map[string]any, key string) (list []any, present bool, err error) {
	v, ok := layer[key]
	if !ok {
		return nil, false, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, true, fmt.Errorf("compose: %s must be a list, got %T", key, v)
	}
	return l, true, nil
}

func dedupPermissions(entries []any) ([]any, error) {
	result := make([]any, 0, len(entries))
	seen := make(map[permissions.DedupKey]bool, len(entries))
	for i, raw := range entries {
		key, err := dedupKeyOf(raw, i)
		if err != nil {
			return nil, err
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, deepCopyValue(raw))
	}
	return result, nil
}

func dedupKeyOf(raw any, index int) (permissions.DedupKey, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return permissions.DedupKey{}, fmt.Errorf("compose: permissions.%d is not a mapping, got %T", index, raw)
	}
	kind, err := tupleField(m, "kind", index)
	if err != nil {
		return permissions.DedupKey{}, err
	}
	subject, err := tupleField(m, "subject", index)
	if err != nil {
		return permissions.DedupKey{}, err
	}
	if _, isHost := m["host_scope"]; isHost {
		return hostDedupKey(m, kind, subject, index)
	}
	pathScope, err := tupleField(m, "path_scope", index)
	if err != nil {
		return permissions.DedupKey{}, err
	}
	grantKind, err := tupleField(m, "grant_kind", index)
	if err != nil {
		return permissions.DedupKey{}, err
	}
	return permissions.DedupKey{Kind: kind, Subject: subject, PathScope: pathScope, GrantKind: grantKind}, nil
}

func hostDedupKey(m map[string]any, kind, subject string, index int) (permissions.DedupKey, error) {
	hostScope, err := tupleField(m, "host_scope", index)
	if err != nil {
		return permissions.DedupKey{}, err
	}
	grantKind, err := tupleField(m, "grant_kind", index)
	if err != nil {
		return permissions.DedupKey{}, err
	}
	if canonical, cErr := permissions.CanonicalHost(hostScope); cErr == nil {
		hostScope = canonical
	}
	return permissions.DedupKey{Kind: kind, Subject: subject, HostScope: hostScope, GrantKind: grantKind}, nil
}

// tupleField reads a required string field from a permission entry mapping.
func tupleField(m map[string]any, field string, index int) (string, error) {
	v, ok := m[field]
	if !ok {
		return "", fmt.Errorf("compose: permissions.%d missing %q", index, field)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("compose: permissions.%d field %q must be a string, got %T", index, field, v)
	}
	return s, nil
}

// unionKeys returns the sorted union of every layer's keys; sorting keeps
// composition deterministic for debugging and snapshot stability.
func unionKeys(layers []map[string]any) []string {
	set := map[string]bool{}
	for _, layer := range layers {
		for k := range layer {
			set[k] = true
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// deepCopyValue returns a copy of a decoded YAML value (map[string]any, []any,
// or an immutable scalar) that shares no mutable structure with the original.
// Caller-supplied raw model values can use other native map/slice shapes (for
// example map[string][]string), so any map or slice that is not one of the
// fast-path cases is copied recursively via reflection.
func deepCopyValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, val := range t {
			m[k] = deepCopyValue(val)
		}
		return m
	case []any:
		s := make([]any, len(t))
		for i, val := range t {
			s[i] = deepCopyValue(val)
		}
		return s
	case []string:
		return slices.Clone(t)
	case map[string]string:
		return maps.Clone(t)
	default:
		return deepCopyReflect(v)
	}
}

// deepCopyReflect recursively copies arbitrary map and slice values; scalars and
// other immutable values are returned unchanged. It is the reflection fallback
// for shapes deepCopyValue does not handle with a concrete fast path.
func deepCopyReflect(v any) any {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		if rv.IsNil() {
			return v
		}
		elemType := rv.Type().Elem()
		out := reflect.MakeMapWithSize(rv.Type(), rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			out.SetMapIndex(iter.Key(), copyReflectElem(iter.Value().Interface(), elemType))
		}
		return out.Interface()
	case reflect.Slice:
		if rv.IsNil() {
			return v
		}
		elemType := rv.Type().Elem()
		out := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		for i := range rv.Len() {
			out.Index(i).Set(copyReflectElem(rv.Index(i).Interface(), elemType))
		}
		return out.Interface()
	default:
		return v // scalars (string, int, float, bool, nil) are immutable
	}
}

// copyReflectElem deep-copies one container element and returns it as a value
// assignable to elemType, substituting the zero value for a nil element so a
// nil interface does not delete a map key or panic on a slice assignment.
func copyReflectElem(v any, elemType reflect.Type) reflect.Value {
	copied := deepCopyValue(v)
	if copied == nil {
		return reflect.Zero(elemType)
	}
	return reflect.ValueOf(copied)
}
