// Resolves the initial active model/effort across the resume and fresh-launch paths.
package model

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

// Source identifies which path supplied the active selection. Its domain
// is the model_turn.source enum. DetermineSelection returns
// SourceProject, SourceGlobalFallback, or SourceResume alongside a selection, or
// SourcePicker with a nil selection when the picker must run. SourcePickerDegraded
// belongs to the enum for the post-persist degraded turn but is never
// returned here; degradation is decided later, after a picker write fails.
type Source string

const (
	SourceProject        Source = "project"
	SourceGlobalFallback Source = "global_fallback"
	SourceResume         Source = "resume"
	SourcePicker         Source = "picker"
	SourcePickerDegraded Source = "picker_degraded"
)

type ProviderDiagnostic struct {
	Name             string
	Models           []string
	ModelsSourcePath string
}

// Context carries everything DetermineSelection reads. Config is the composed
// session cache (paths 2-3 inputs and cross-reference source). On a resume
// run Resume is true and ResumeRecords/Store carry the loaded record stream to
// scan and the store to append model_recovery_failed to; Warn receives the
// one-line recovery warning. GlobalSettingsPath and Providers feed the path-4
// stderr lines (the global settings absolute path and the ordered provider
// diagnostics, respectively).
type Context struct {
	Config             *config.Cache
	Resume             bool
	ResumeRecords      []sessions.Record
	Store              *sessions.Store
	Warn               io.Writer
	GlobalSettingsPath string
	Providers          []ProviderDiagnostic
}

// NoSelectableModelError is the typed path-4 outcome returned when the
// picker would have to open but no model is selectable. Lines holds the exact
// stderr lines the launch caller writes (one "no providers" line for an empty
// provider map, otherwise one line per empty-allowlist provider in configured
// order) before flushing where required and exiting with status 1. Returning it
// rather than calling os.Exit keeps resume-run flush/exit ownership with the
// bootstrap caller.
type NoSelectableModelError struct {
	Lines []string
}

func (e *NoSelectableModelError) Error() string {
	return strings.Join(e.Lines, "\n")
}

// DetermineSelection resolves the initial active model/effort. It
// returns a non-nil *Selection with SourceProject, SourceGlobalFallback, or
// SourceResume when one of paths 1-3 supplies a value; a nil *Selection with
// SourcePicker when path 4 requires the picker and at least one model is
// selectable; or a nil *Selection and a *NoSelectableModelError when path 4 finds
// no selectable model. The returned Source is meaningful only when the error is
// nil. DetermineSelection never calls os.Exit and, apart from the resume-recovery
// model_recovery_failed append, never flushes; the caller owns stderr rendering,
// opening the picker, flushing, and exiting.
func DetermineSelection(ctx Context) (*Selection, Source, error) {
	if ctx.Config == nil {
		return nil, "", fmt.Errorf("model.DetermineSelection: nil config cache")
	}
	if ctx.Resume {
		sel, outcome, err := ctx.recoverFromResume()
		if err != nil {
			return nil, "", err
		}
		if outcome == RecoveryClean {
			return sel, SourceResume, nil
		}
		// No model_turn, or recovery failed: fall through to the fresh paths 2-4,
		// which on a resume walk from the session's recorded folder.
	}
	return ctx.freshSelection()
}

// RecoveryOutcome classifies a step-1 recovery attempt against a loaded
// resume record stream. DetermineSelection only needs to know whether recovery
// produced a clean selection, but the in-TUI /resume seam (RecoverActiveSelection)
// must branch on all three outcomes: a clean recovery adopts the selection, a
// failure clears the active selection and opens the model picker, and no model_turn
// leaves the active selection unchanged.
type RecoveryOutcome int

const (
	// RecoveryNoModelTurn: the stream carried no model_turn, so there was nothing to
	// recover. Not a failure — no model_recovery_failed is appended.
	RecoveryNoModelTurn RecoveryOutcome = iota
	// RecoveryClean: the most recent model_turn passed the shape and checks
	// and was restored; the returned *Selection is non-nil.
	RecoveryClean
	// RecoveryFailed: the most recent model_turn failed the shape or validation
	// check; exactly one model_recovery_failed was appended and *Selection is nil.
	RecoveryFailed
)

// RecoverActiveSelection runs only step 1 against the loaded resume record
// stream, for the in-TUI /resume seam. Unlike DetermineSelection it does not
// fall through to the config paths after a no-model_turn or a recovery failure: it
// reports the RecoveryOutcome so the caller can adopt a clean recovery, clear the
// active selection and open the model picker on a failure, or leave the active
// selection unchanged when there was no model_turn. It reuses the same recovery
// parsing, validation, and model_recovery_failed append as the launch path
// so a failure appends exactly one model_recovery_failed to ctx.Store. It returns a
// non-nil error only for an internal failure (a nil config cache, or an inability to
// append the model_recovery_failed event); the outcome is meaningful only when err
// is nil. ctx.Warn is normally left nil here so a TUI failure routes through the
// picker rather than the CLI stderr surface.
func RecoverActiveSelection(ctx Context) (*Selection, RecoveryOutcome, error) {
	if ctx.Config == nil {
		return nil, RecoveryNoModelTurn, fmt.Errorf("model.RecoverActiveSelection: nil config cache")
	}
	return ctx.recoverFromResume()
}

// recoverFromResume runs step 1: scan the loaded record stream for the most
// recent model_turn and try to restore it. It returns (sel, RecoveryClean, nil) on a
// clean recovery. A stream with no model_turn returns (nil, RecoveryNoModelTurn, nil)
// and emits nothing — that is not a recovery failure. A shape-check or validation
// failure warns on ctx.Warn (when set), appends one model_recovery_failed event, and
// returns (nil, RecoveryFailed, nil) so the launch caller continues to step 2. A
// non-nil error signals an internal failure to record the recovery event.
func (ctx Context) recoverFromResume() (sel *Selection, outcome RecoveryOutcome, err error) {
	raw := mostRecentModelTurn(ctx.ResumeRecords)
	if raw == nil {
		return nil, RecoveryNoModelTurn, nil
	}
	sel, reason, detail := ctx.parseRecoveredTurn(raw)
	if sel != nil {
		return sel, RecoveryClean, nil
	}
	if ctx.Warn != nil {
		_, _ = fmt.Fprintf(ctx.Warn, "codemeld: cannot recover model from resumed session: %s\n", detail)
	}
	if ctx.Store == nil {
		return nil, RecoveryFailed, fmt.Errorf("model: resume recovery requires a session store")
	}
	if _, aerr := events.Append(ctx.Store, events.ModelRecoveryFailed{Reason: reason, ErrorDetail: detail}); aerr != nil {
		return nil, RecoveryFailed, fmt.Errorf("model: append model_recovery_failed: %w", aerr)
	}
	return nil, RecoveryFailed, nil
}

// mostRecentModelTurn returns the raw payload of the last model_turn event in
// records, or nil when there is none.
func mostRecentModelTurn(records []sessions.Record) json.RawMessage {
	for i := len(records) - 1; i >= 0; i-- {
		if ev, ok := records[i].(sessions.Event); ok && ev.Kind == events.KindModelTurn {
			return ev.Payload
		}
	}
	return nil
}

// parseRecoveredTurn applies the step 1 shape check and
// validation to a recovered model_turn payload. On success it returns the
// restored selection and empty reason/detail. On failure it returns a nil
// selection, the model_recovery_failed reason (shape_check_failed for the
// present/string shape rules, validation_failed for the provider/model/effort
// cross-reference rules), and a one-line detail naming the offending field or the
// rejected selection. The on-wire field is model_id; it maps to Selection.ID.
func (ctx Context) parseRecoveredTurn(raw json.RawMessage) (*Selection, string, string) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, "shape_check_failed", fmt.Sprintf("model_turn payload is not a JSON object: %v", err)
	}
	provider, detail := recoveredString(m, "provider")
	if detail != "" {
		return nil, "shape_check_failed", detail
	}
	modelID, detail := recoveredString(m, "model_id")
	if detail != "" {
		return nil, "shape_check_failed", detail
	}
	effort, detail := recoveredString(m, "effort")
	if detail != "" {
		return nil, "shape_check_failed", detail
	}
	sel := &Selection{Provider: provider, ID: modelID, Effort: effort}
	if verr := Validate(sel, ctx.Config); verr != nil {
		return nil, "validation_failed", describeRejectedSelection(sel, verr)
	}
	if verr := validateEffort(sel, ctx.Config); verr != nil {
		return nil, "validation_failed", describeRejectedSelection(sel, verr)
	}
	return sel, "", ""
}

// recoveredString reads a required string subfield of a recovered model_turn
// payload, returning the value or a shape-check detail. Task step 2 requires each
// field to be a non-empty string, so an absent field, a non-string value, and an
// empty string are all shape-check failures reported before validation.
func recoveredString(m map[string]any, field string) (value, detail string) {
	v, ok := m[field]
	if !ok {
		return "", fmt.Sprintf("model_turn payload field %q is absent", field)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Sprintf("model_turn payload field %q is not a string (got %T)", field, v)
	}
	if s == "" {
		return "", fmt.Sprintf("model_turn payload field %q is empty", field)
	}
	return s, ""
}

// describeRejectedSelection names the rejected recovered selection and the
// reason, for both the stderr warning and the model_recovery_failed error_detail.
func describeRejectedSelection(sel *Selection, serr *ShapeError) string {
	return fmt.Sprintf("recovered selection {provider=%q, model_id=%q, effort=%q} rejected: %s",
		sel.Provider, sel.ID, sel.Effort, serr.Error())
}

// freshSelection runs steps 2-4. A present per-project model.active is
// used when valid and otherwise routes straight to path 4 — model.last_used is
// not consulted on the invalid-model.active branch (step 3). With no
// per-project model.active, a valid global model.last_used is the fallback; an
// invalid one is suppressed and also routes to path 4.
func (ctx Context) freshSelection() (*Selection, Source, error) {
	if raw, ok := ctx.Config.ModelActiveRaw(); ok {
		if sel := parseAndValidate(raw, ctx.Config); sel != nil {
			return sel, SourceProject, nil
		}
		return ctx.pickerRequired()
	}
	if raw, ok := ctx.Config.ModelLastUsedRaw(); ok {
		if sel := parseAndValidate(raw, ctx.Config); sel != nil {
			return sel, SourceGlobalFallback, nil
		}
	}
	return ctx.pickerRequired()
}

// Invalid stored selections remain on disk.
func parseAndValidate(raw any, cache *config.Cache) *Selection {
	sel, serr := ParseSelection(raw)
	if serr != nil {
		return nil
	}
	if verr := Validate(sel, cache); verr != nil {
		return nil
	}
	if verr := validateEffort(sel, cache); verr != nil {
		return nil
	}
	return sel
}

// pickerRequired runs the path-4 selectable-model gate: it returns
// SourcePicker with a nil selection when a selectable model exists (the caller
// opens the picker), or a *NoSelectableModelError carrying the stderr
// lines when none does.
func (ctx Context) pickerRequired() (*Selection, Source, error) {
	if hasSelectableModel(ctx.Providers) {
		return nil, SourcePicker, nil
	}
	return nil, SourcePicker, &NoSelectableModelError{Lines: ctx.noSelectableLines()}
}

// hasSelectableModel reports whether any provider exposes a non-empty models
// allowlist; a model is selectable only when it appears in some allowlist.
func hasSelectableModel(providers []ProviderDiagnostic) bool {
	for _, p := range providers {
		if len(p.Models) > 0 {
			return true
		}
	}
	return false
}

func (ctx Context) noSelectableLines() []string {
	if len(ctx.Providers) == 0 {
		return []string{fmt.Sprintf(
			"codemeld: no providers configured — add at least one entry under provider: in %s",
			ctx.GlobalSettingsPath)}
	}
	var lines []string
	for _, p := range ctx.Providers {
		if len(p.Models) == 0 {
			lines = append(lines, fmt.Sprintf(
				"codemeld: no models for provider.%s — refresh the provider catalog before retrying",
				p.Name))
		}
	}
	return lines
}
