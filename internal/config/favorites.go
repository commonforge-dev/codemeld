package config

import (
	"fmt"
	"slices"

	"codemeld.dev/codemeld/internal/fserrors"
)

// Favorite is one favorited provider/model pair as stored in ordered
// model.favorites entries. Identity is exact string equality on both fields, so
// the same model ID offered by two providers stays two distinct favorites.
type Favorite struct {
	Provider string
	ID       string
}

// applyFavorite returns a fresh ordered list with target favorited (want true)
// or unfavorited (want false). Adding an already-present pair leaves the order
// unchanged; removing drops every exact occurrence, which matters because a
// hand-edited settings file may hold duplicates. The result never aliases
// existing.
func applyFavorite(existing []Favorite, target Favorite, want bool) []Favorite {
	out := slices.Clone(existing)
	if !want {
		return slices.DeleteFunc(out, func(f Favorite) bool { return f == target })
	}
	if slices.Contains(out, target) {
		return out
	}
	return append(out, target)
}

type favoriteToggleValue struct {
	target   Favorite
	want     bool
	prepared bool
	source   []Favorite
	next     []Favorite
}

func (op *favoriteToggleValue) prepare(raw map[string]any) error {
	current, err := favoritesFromRaw(raw)
	if err != nil {
		return err
	}
	op.source = current
	op.next = applyFavorite(current, op.target, op.want)
	op.prepared = true
	return nil
}

func favoritesFromRaw(raw map[string]any) ([]Favorite, error) {
	modelRaw, ok := raw["model"]
	if !ok || modelRaw == nil {
		return nil, nil
	}
	modelMap, ok := toStringMap(modelRaw)
	if !ok {
		return nil, fmt.Errorf("config: model is not a mapping (got %T)", modelRaw)
	}
	listRaw, ok := modelMap["favorites"]
	if !ok || listRaw == nil {
		return nil, nil
	}
	list, ok := listRaw.([]any)
	if !ok {
		return nil, fmt.Errorf("config: model.favorites is not a list (got %T)", listRaw)
	}
	out := make([]Favorite, 0, len(list))
	for i, item := range list {
		m, ok := toStringMap(item)
		if !ok {
			return nil, fmt.Errorf("config: model.favorites[%d] is not a mapping (got %T)", i, item)
		}
		p, pOK := m["provider"].(string)
		id, idOK := m["id"].(string)
		if !pOK || !idOK || p == "" || id == "" {
			return nil, fmt.Errorf("config: model.favorites[%d] needs non-empty string provider and id", i)
		}
		out = append(out, Favorite{Provider: p, ID: id})
	}
	return out, nil
}

func (c *Cache) ToggleFavorite(target Favorite, want bool) ([]Favorite, PersistReason, fserrors.Category, error) {
	if len(c.layerPaths) == 0 || c.layerPaths[0] == "" {
		return nil, ReasonRereadParseError, "", fmt.Errorf("config.ToggleFavorite: no global settings layer path configured")
	}
	list, reason, cat, err := persistFavorite(c.layerPaths[0], target, want)
	if reason != ReasonNone || err != nil {
		return nil, reason, cat, err
	}
	c.favorites = slices.Clone(list)
	return slices.Clone(list), ReasonNone, "", nil
}

func persistFavorite(targetPath string, target Favorite, want bool) ([]Favorite, PersistReason, fserrors.Category, error) {
	if target.Provider == "" || target.ID == "" {
		return nil, ReasonRereadParseError, "", fmt.Errorf("config.persistFavorite: favorite needs a non-empty provider and id, got %+v", target)
	}
	op := &favoriteToggleValue{target: target, want: want}
	reason, cat, err := Persist(targetPath, keyModelFavorites, op)
	if reason != ReasonNone || err != nil {
		return nil, reason, cat, err
	}
	return slices.Clone(op.next), ReasonNone, "", nil
}
