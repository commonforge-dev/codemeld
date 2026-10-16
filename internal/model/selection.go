// Parses model.active / model.last_used values and runs the shape and cross-reference checks.
package model

import (
	"fmt"
	"slices"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/provider"
)

// EffortDefault is a provider-advertised token, not the no-parameter choice.
const EffortDefault = "default"

// EffortNoReasoning is accepted independently of what any provider advertises.
const EffortNoReasoning = provider.EffortNoReasoning

// Selection is a parsed model.active or model.last_used value: the chosen
// provider name, model id, and reasoning effort. All three are required string
// subfields. The on-disk field is id; model is never accepted as an
// alias for it.
type Selection struct {
	Provider string
	ID       string
	Effort   string
}

// Category names a shape- or cross-reference-check failure. The set is
// closed so bootstrap and picker/warning callers can branch
// on the exact rejection reason and name the offending field and value.
type Category string

const (
	// CategoryNotObject: the value is null or a non-object scalar/list rather than a mapping.
	CategoryNotObject Category = "value not an object"
	// CategoryMissingField: a required subfield (provider, id, or effort) is absent.
	CategoryMissingField Category = "required subfield missing"
	// CategoryWrongType: a required subfield is present but not a string.
	CategoryWrongType           Category = "subfield wrong type"
	CategoryEffortInvalid       Category = "effort empty"
	CategoryEffortNotAdvertised Category = "effort not advertised for the selected model"
	// CategoryProviderUnknown: provider is not an entry in the selectable-provider
	// catalog (configured providers plus built-in providers outside the provider: map).
	CategoryProviderUnknown Category = "provider not in selectable catalog"
	// CategoryModelNotAllowed: id is not in the selected provider's catalog models allowlist.
	CategoryModelNotAllowed Category = "id not in provider's models allowlist"
)

// ShapeError reports a single shape or cross-reference failure. Field
// names the offending subfield (provider, id, or effort), empty for a
// whole-value failure such as CategoryNotObject. Value carries the offending
// value or, for CategoryWrongType, the Go type that was found, so and
// callers can quote it in their messages.
type ShapeError struct {
	Category Category
	Field    string
	Value    string
}

func (e *ShapeError) Error() string {
	switch e.Category {
	case CategoryNotObject:
		return fmt.Sprintf("model selection: %s (got %s)", e.Category, e.Value)
	case CategoryMissingField:
		return fmt.Sprintf("model selection: %s: %s", e.Category, e.Field)
	case CategoryWrongType:
		return fmt.Sprintf("model selection: %s: %s (got %s)", e.Category, e.Field, e.Value)
	default:
		return fmt.Sprintf("model selection: %s: %s=%q", e.Category, e.Field, e.Value)
	}
}

// ParseSelection defers provider-effort validation to the active catalog.
func ParseSelection(raw any) (*Selection, *ShapeError) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, &ShapeError{Category: CategoryNotObject, Value: fmt.Sprintf("%T", raw)}
	}
	providerID, serr := stringField(m, "provider")
	if serr != nil {
		return nil, serr
	}
	id, serr := stringField(m, "id")
	if serr != nil {
		return nil, serr
	}
	effort, serr := stringField(m, "effort")
	if serr != nil {
		return nil, serr
	}
	if effort == "" {
		return nil, &ShapeError{Category: CategoryEffortInvalid, Field: "effort", Value: effort}
	}
	return &Selection{Provider: providerID, ID: id, Effort: effort}, nil
}

// stringField returns the required string subfield at key, distinguishing an
// absent key (CategoryMissingField) from a present non-string value, including
// an explicit null (CategoryWrongType).
func stringField(m map[string]any, key string) (string, *ShapeError) {
	v, ok := m[key]
	if !ok {
		return "", &ShapeError{Category: CategoryMissingField, Field: key}
	}
	s, ok := v.(string)
	if !ok {
		return "", &ShapeError{Category: CategoryWrongType, Field: key, Value: fmt.Sprintf("%T", v)}
	}
	return s, nil
}

// Validate treats a built-in provider that declares selectable models outside the
// provider: map as a catalog entry, so the same model id can appear under two
// provider ids, disambiguated by provider.
func Validate(sel *Selection, composedConfig *config.Cache) *ShapeError {
	entry, ok := composedConfig.SelectableCatalog().Entry(sel.Provider)
	if !ok {
		return &ShapeError{Category: CategoryProviderUnknown, Field: "provider", Value: sel.Provider}
	}
	if !slices.Contains(entry.Models, sel.ID) {
		return &ShapeError{Category: CategoryModelNotAllowed, Field: "id", Value: sel.ID}
	}
	return validateEffort(sel, composedConfig)
}

// EffortNoReasoning bypasses catalog support checks; other tokens require catalog support.
func validateEffort(sel *Selection, composedConfig *config.Cache) *ShapeError {
	if sel.Effort == EffortNoReasoning {
		return nil
	}
	if slices.Contains(composedConfig.SelectableCatalog().SupportedEffort(sel.Provider, sel.ID), sel.Effort) {
		return nil
	}
	return &ShapeError{Category: CategoryEffortNotAdvertised, Field: "effort", Value: sel.Effort}
}
