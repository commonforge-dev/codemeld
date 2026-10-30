// /settings command: open the read-only overlay listing the stored permission
// grants for this run. The command behaviour lives behind a
// SettingsDeps dependency-injection seam (mirroring /resume's ResumeDeps) so it
// is driven end-to-end with fakes and no real terminal. This slice ships the handler,
// its list surface, and the overlay unregistered: the production BuildRegistry
// wiring and the revoke control ship separately.
package tui

import (
	"codemeld.dev/codemeld/internal/permissions"
)

// PermissionLister returns the stored permission grants to display. The production
// implementation wraps config.Cache.Permissions(); tests inject a fake.
type PermissionLister interface {
	List() []permissions.PermissionEntry
}

// SettingsPicker presents the stored grants in the overlay and returns immediately. It
// re-reads deps.Rows after a revoke or share so the rows reflect what the seam changed.
type SettingsPicker interface {
	Present(rows []PermissionRow, deps SettingsDeps)
}

// PermissionRow is one management copy of a grant. Layer and Path are empty for a session
// grant, whatever Entry.Layer says.
type PermissionRow struct {
	Entry permissions.PermissionEntry
	Layer permissions.LayerKind
	Path  string
}

type ShareResult struct {
	Refused       bool
	SharedPath    string
	LocalPath     string
	SharedSkipped bool
	SharedCreated bool
	SharedErr     error
	LocalErr      error
}

// SettingsDeps is the /settings handler's dependency surface. A nil Revoke leaves the
// overlay read-only and a nil Share leaves it without a share action. Approved is the run's
// explicit root approval, never inferred from the loaded rows, and Boundary is
// discovery.boundary.
type SettingsDeps struct {
	Lister   PermissionLister
	Picker   SettingsPicker
	Rows     func() []PermissionRow
	Revoke   func(PermissionRow)
	Share    func(PermissionRow) ShareResult
	Approved bool
	Boundary string
	tab      int
}

// NewSettingsHandler returns the /settings handler bound to deps. It records the
// picker-open slash_command{success} and flushes it durable before opening the overlay
// and returning to dispatch — the same crash-safe ordering /resume uses, so an accepted
// /settings audit event is on disk before control returns to the event loop.
func NewSettingsHandler(deps SettingsDeps) HandlerFunc {
	if deps.Rows == nil {
		lister := deps.Lister
		deps.Rows = func() []PermissionRow { return unlayeredPermissionRows(lister.List()) }
	}
	return func(ctx CommandContext, _ []string) error {
		rows := deps.Rows()
		if err := ctx.AppendSlashCommand(OutcomeSuccess, ""); err != nil {
			return err
		}
		if err := ctx.FlushActive(); err != nil {
			return err
		}
		deps.Picker.Present(rows, deps)
		return nil
	}
}

func NewOpenRouterHandler(deps SettingsDeps) HandlerFunc {
	deps.tab = permTabIndexOpenRouter
	return NewSettingsHandler(deps)
}

func unlayeredPermissionRows(entries []permissions.PermissionEntry) []PermissionRow {
	rows := make([]PermissionRow, len(entries))
	for i, e := range entries {
		rows[i] = PermissionRow{Entry: e}
	}
	return rows
}
