// /model <id> command: validate the supplied model id against the active
// provider's models allowlist, recompute the effort per the fallback rule,
// then apply the change through the same persistence/event flow as
// /effort — refusing when no model is selected and recording a command-level
// error (with the typed input retained) on an unsupported id
package tui

import (
	"fmt"
	"slices"
	"strings"

	"codemeld.dev/codemeld/internal/sessions"
)

// ModelCatalog is the in-memory active-model surface /model reads. It extends
// EffortModel with the active provider's configured model allowlist so
// /model can validate the supplied id and recompute the effort, without
// internal/tui importing internal/model or internal/provider (which would
// re-introduce the model→tui import cycle). The production implementation wraps
// *model.ActiveState and the composed provider config. This seam is deliberate
// rather than removable indirection: collapsing it into the concrete model read
// would pull internal/model and internal/provider into internal/tui, breaching
// the package boundary the interface exists to hold.
type ModelCatalog interface {
	EffortModel
	// Models returns the active provider's configured model id allowlist
	// in declaration order. It is both the set the supplied id must belong to
	// and the set named in the unsupported-model error.
	Models(provider string) []string
}

// ModelApplier runs the persistence/event transaction for a new model id
// and effort on the active provider and updates the run's model_turn source. It
// mirrors EffortApplier; the production implementation lives outside internal/tui
// so it can call model.PersistPickerSelection and
// model.ActiveState.ApplyUserSelection without the import cycle. /model calls
// Apply only after validation passes. This seam is deliberate rather than
// removable indirection: collapsing the durable settings write, provider lookup,
// and session-failure events it reaches into internal/tui would breach the
// package boundary the interface holds.
type ModelApplier interface {
	// Apply persists Selection{active provider, modelID, effort} as model.active
	// — append model_changed (only new_model_id and possibly
	// new_effort differing from the prior selection), flush, write
	// model.active via the shared persistence function, then mirror model.last_used
	// only after the active write succeeds — emitting model_persist_failed /
	// model_global_mirror_failed and the persist-failure notice as
	// prescribed, and setting the next model_turn source to picker or
	// picker_degraded (ending any resume carve-out). A non-nil error is
	// reserved for an internal append/flush failure the handler must surface;
	// persistence failures are not reported as errors here.
	Apply(modelID, effort string) (ModelApplyResult, error)
}

// ModelApplyResult mirrors EffortApplyResult: MarkerCreated is true only under
// launch-dir-only mode when the model.active write created a .codemeld/settings.yaml that did not
// exist before, and MarkerPath is that file's absolute path, named in the
// cross-mode marker disclosure. The persist-failure
// notice and the source-state update are already handled inside Apply.
type ModelApplyResult struct {
	MarkerCreated bool
	MarkerPath    string
}

// ModelDeps gathers the injectable capabilities NewModelHandler closes over, so
// the handler can be driven end-to-end with fakes (mirroring EffortDeps); the
// production wiring supplies the implementations bound to the running app +
// bootstrap result. ModelDeps stays the command-only dependency bundle,
// deliberately separate from the provider-aware ModelPickerDeps: /model validates
// against and applies on the active provider only, while the CTRL-M picker spans
// the provider×model cross-product and may switch providers, so merging the two
// into one applier would make /model inherit provider switching.
type ModelDeps struct {
	Model   ModelCatalog
	Applier ModelApplier
	// OpenPicker, when non-nil, opens the model picker for a bare (zero-argument)
	// /model — the same overlay CTRL-M opens, wired in production to
	// App.OpenModelPicker. Like CTRL-M it opens even when no model is selected (it is
	// how the first model is chosen) and is a no-op while another overlay is open, so
	// the no-arg handler path delegates to it without recording a slash_command. nil
	// in unit tests and before the production wiring installs the opener, in which
	// case a bare /model is inert (no panic, no event, no input retention).
	OpenPicker func()
	// Refresh, when non-nil, is called after a successful /model apply so the
	// persistent status-line footer live-updates to the new model/effort. It
	// is not called on validation failures or apply errors. nil in unit tests and
	// before the production wiring installs App.RefreshStatusLine.
	Refresh func()
	// ClearNotice, when non-nil, clears any pinned transient notice after a successful
	// /model apply, so a stale notice (e.g. a prior validation error or a
	// session-write hint) cannot linger pinned below the model change. It is not called
	// on the bare picker path, validation failures, or apply errors — those must keep
	// their notice. nil in unit tests and before the production wiring installs
	// App.ClearNotice, where the clear is a no-op (the submitCurrent clear still runs
	// in production for the /model command path).
	ClearNotice func()
	// NoticeSeq, when non-nil, reports the count of notices emitted so far so the handler
	// can tell a stale pre-apply notice from one the apply itself emitted (the
	// local-settings ignore notice, or the degraded active-write failure) and clear only
	// the former, even when the apply repeats the previous notice verbatim.
	// nil in unit tests, where the clear stays unconditional.
	NoticeSeq func() uint64
}

// NewModelHandler returns the /model handler. It refuses with the one-line
// no-model-selected error when no model is selected, rejects an id outside the
// active provider's models allowlist (retaining the typed input and recording
// slash_command{outcome:error} with the same text), and on a
// valid id recomputes the effort per the fallback rule, records
// slash_command{outcome:success}, and runs the apply transaction. The active
// provider is never changed; /model validates only against that provider's allowlist.
func NewModelHandler(deps ModelDeps) HandlerFunc {
	return func(ctx CommandContext, args []string) error {
		// Dispatch enforces ArgOneOptional, so there are zero or one arguments. A
		// bare /model opens the picker (the same overlay CTRL-M opens) and records no
		// slash_command — matching the CTRL-M key path, which never appends a
		// slash_command. A nil opener leaves the path inert: no panic, no
		// event, no input retention.
		if len(args) == 0 {
			if deps.OpenPicker != nil {
				deps.OpenPicker()
			}
			return nil
		}
		id := args[0]

		provider, _, effort, ok := deps.Model.ActiveSelection()
		if !ok {
			return rejectModel(ctx, noModelSelectedNotice)
		}

		allowlist := deps.Model.Models(provider)
		if !slices.Contains(allowlist, id) {
			return rejectModel(ctx, unsupportedModelNotice(id, allowlist))
		}

		newEffort := effort
		supported := deps.Model.SupportedEfforts(provider, id)
		if !effortValid(effort, supported) {
			newEffort = modelSelectionEffortFallback(supported)
		}

		// The command is recognized and the id is valid, so it succeeds as a
		// command regardless of whether persistence later degrades to
		// session-only. Recording slash_command before the apply mirrors /effort;
		// only pins model_changed (appended inside Apply) ahead of the
		// persist-failure events, which Apply preserves.
		if err := ctx.AppendSlashCommand(OutcomeSuccess, ""); err != nil {
			return err
		}
		var seq uint64
		if deps.NoticeSeq != nil {
			seq = deps.NoticeSeq()
		}
		if _, err := deps.Applier.Apply(id, newEffort); err != nil {
			return err
		}
		// Clear any stale pinned notice now that the model change has applied,
		// only on this success path — never on the validation/error paths, which keep
		// their notice (rejectModel). An apply that emitted a notice of its own keeps it,
		// including when it repeats the previous notice verbatim.
		emitted := false
		if deps.NoticeSeq != nil {
			emitted = deps.NoticeSeq() != seq
		}
		if deps.ClearNotice != nil && !emitted {
			deps.ClearNotice()
		}
		// Live-update the persistent status-line footer to the new model/effort,
		// only after the apply succeeded — never on the validation/error paths.
		if deps.Refresh != nil {
			deps.Refresh()
		}
		return nil
	}
}

// rejectModel renders the one-line TUI error, retains the typed input so the
// user can edit and retry, records the recognized command with outcome:error
// carrying the same text as error_detail, and flushes that record
// so the error event is durable before the handler returns —
// validation rejects before the apply transaction, so there is no later
// flush to make it durable. It mirrors /effort's rejectEffort.
func rejectModel(ctx CommandContext, notice string) error {
	ctx.Notice(notice)
	ctx.RetainInput()
	if err := ctx.AppendSlashCommand(OutcomeError, notice); err != nil {
		return err
	}
	return ctx.FlushActive()
}

// unsupportedModelNotice renders the pinned one-line error for an id the active
// provider does not list: "unsupported model <supplied>; supported
// models: <comma-separated active-provider allowlist>". The allowlist is rendered
// in the order Models returned it.
func unsupportedModelNotice(id string, allowlist []string) string {
	return fmt.Sprintf("unsupported model %s; supported models: %s", id, strings.Join(allowlist, ", "))
}

// ProviderModel is one selectable (provider, model id) row in the CTRL-M model
// picker's provider×model cross-product. The picker spans every selectable
// provider's models allowlist: the active provider is a chosen, validated field
// the picker may switch — unlike /model, which never changes the provider.
//
// Provider is the stable provider id persisted in model.active / model.last_used,
// emitted in events, and used for apply and disambiguation; DisplayName is the
// presentation-only group-header label (e.g. "OpenAI ChatGPT" for the openai-chatgpt
// built-in, "OpenAI Platform" for openai). They differ for built-in providers, so the
// header reads the display name while persistence keeps the id. A row with an
// empty DisplayName falls back to the provider id for its header.
type ProviderModel struct {
	Provider    string
	DisplayName string
	ModelID     string
}

type ModelSettingsTarget struct {
	SettingsPath string
	LaunchDir    string
	ProjectRoot  string
}

// ProviderModelCatalog is the provider-aware surface the CTRL-M model picker reads.
// It is additive to (not a widening of) ModelCatalog/ModelApplier so the existing
// production structs keep satisfying those interfaces and internal/bootstrap still
// compiles; the production implementation lives outside internal/tui and is wired
// onto the app there. internal/tui still imports neither internal/model nor
// internal/provider (which would re-introduce the model→tui import cycle).
type ProviderModelCatalog interface {
	// ActiveSelection returns the current provider/model/effort and whether a model
	// is selected in memory. Unlike the effort picker, the model picker opens even
	// when ok is false — it is how the first model is chosen — so ok only governs the
	// initial highlight and whether the apply's model_changed carries prior fields.
	ActiveSelection() (provider, modelID, effort string, ok bool)
	// ProviderModels returns the selectable (provider, model id) cross-product in
	// display order (configured provider/model order, or a deterministic sort over
	// map config). A provider with an empty models allowlist contributes no rows.
	ProviderModels() []ProviderModel
	// ConfiguredProviders returns one row per configured (non-builtin) provider,
	// including those whose model allowlist is empty (ModelID == ""). ProviderModels
	// omits empty providers, so the picker uses this to request a non-forced refresh
	// for configured providers whose cache has no rows when it opens.
	ConfiguredProviders() []ProviderModel
	// SupportedEfforts returns cached efforts, or only effortNoReasoning when
	// capability metadata is absent.
	SupportedEfforts(provider, modelID string) []string
	SettingsTarget() ModelSettingsTarget
}

// ProviderModelApplier runs the persistence/event transaction for a chosen
// provider+model+effort and updates the run's model_turn source. It mirrors
// ModelApplier but switches the provider too (the picker spans the provider×model
// cross-product), so it cannot reuse ModelApplier.Apply, which is model-only.
// The production implementation reuses the shared
// picker-apply transaction: append model_changed before WriteActive, flush,
// mirror model.last_used only after the active write succeeds, emit
// model_persist_failed / model_global_mirror_failed and the notice as
// prescribed, and set the next source to picker / picker_degraded. It must not
// dispatch /model and must not append a slash_command event.
type ProviderModelApplier interface {
	// ApplyProviderModel persists Selection{provider, modelID, effort} as
	// model.active and returns the cross-mode marker outcome the
	// picker must disclose. A non-nil error is reserved for an internal append/flush
	// failure the picker must surface; persistence failures are not reported as
	// errors here.
	ApplyProviderModel(provider, modelID, effort string) (ModelApplyResult, error)
}

type ModelRefreshOutcome int

const (
	ModelRefreshNoChange ModelRefreshOutcome = iota
	ModelRefreshUpdated
	ModelRefreshFailed
	ModelRefreshCredentialUnavailable
)

type ModelRefreshResult struct {
	Provider string
	Outcome  ModelRefreshOutcome
}

type ModelFavorite struct {
	Provider string
	ModelID  string
}

// ModelPickerDeps gathers the provider-aware capabilities the CTRL-M picker closes
// over, so it can be driven end-to-end with fakes (mirroring EffortDeps/ModelDeps).
// The production wiring supplies the implementations bound to the running app +
// bootstrap result; with none set the picker stays inert (CTRL-M is a no-op).
type ModelPickerDeps struct {
	Catalog ProviderModelCatalog
	Applier ProviderModelApplier
	// Refresh, when non-nil, is called after a successful CTRL-M apply so the
	// persistent status-line footer live-updates to the new provider/model/effort.
	// It is not called on apply errors. nil in unit tests and before the
	// production wiring installs App.RefreshStatusLine.
	Refresh func()
	// onComplete runs off the TUI event loop and must be marshaled back before UI access.
	RefreshCatalog func(providerID string, force bool, onComplete func(ModelRefreshResult))
	// FlushRefresh durably records a forced refresh. Unlike the general command flush,
	// it returns an atomic-write failure after routing it through the session-write
	// failure protocol: the picker must not claim the refresh was recorded until it
	// is on disk. Nil in unit tests falls back to the general command flush.
	FlushRefresh   func(*sessions.Store) error
	Favorites      func() []ModelFavorite
	ToggleFavorite func(provider, modelID string) ([]ModelFavorite, error)
}

func modelSelectionEffortFallback(supported []string) string {
	if len(supported) == 0 {
		return effortNoReasoning
	}
	return supported[0]
}
