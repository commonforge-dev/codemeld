// Package permissionpersist persists permission grants.
package permissionpersist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// Synthetic cleaned absolute paths reused across cases; nothing touches the
// filesystem (config.Persist is replaced by the persist seam).
const (
	scopeProj   = "/home/u/proj"
	scopeSub    = "/home/u/proj/sub"
	scopeUp     = "/home/u"
	scopeOther  = "/home/u/other"
	scopePrefix = "/home/u/projapp" // string-prefix-only, not a descendant of scopeProj
	targetPath  = "/home/u/proj/.codemeld/settings.yaml"
)

// recordingUI captures the one-line notices the adapter renders so tests can
// assert which failures surface to the user and which stay silent.
type recordingUI struct{ notices []string }

func (r *recordingUI) Notice(text string) { r.notices = append(r.notices, text) }

// setPersist swaps the config.Persist seam for the duration of a test.
func setPersist(t *testing.T, fn func(string, string, any) (config.PersistReason, fserrors.Category, error)) {
	t.Helper()
	orig := persist
	persist = fn
	t.Cleanup(func() { persist = orig })
}

// failPersist forces every persist call to return the given reason/category/error.
func failPersist(t *testing.T, reason config.PersistReason, cat fserrors.Category, err error) {
	t.Helper()
	setPersist(t, func(string, string, any) (config.PersistReason, fserrors.Category, error) {
		return reason, cat, err
	})
}

func newStore() *sessions.Store {
	return sessions.New("/unused/session.json", &sessions.Session{
		Metadata: sessions.Metadata{ID: ids.NewV7(), Folder: scopeProj, SchemaVersion: sessions.CurrentSchemaVersion},
	})
}

func toolEntry(scope, grantKind string) permissions.PermissionEntry {
	return permissions.PermissionEntry{Kind: "tool", Subject: "vcs_commit", PathScope: scope, GrantKind: grantKind}
}

func hostEntry(subject, host string) permissions.PermissionEntry {
	return permissions.PermissionEntry{Kind: "tool", Subject: subject, HostScope: host, GrantKind: "project"}
}

func kindEvents(t *testing.T, store *sessions.Store, kind string) []sessions.Event {
	t.Helper()
	var evs []sessions.Event
	for _, r := range store.Records() {
		ev, ok := r.(sessions.Event)
		if !ok {
			t.Fatalf("record %T is not a sessions.Event", r)
		}
		if ev.Kind == kind {
			evs = append(evs, ev)
		}
	}
	return evs
}

func decodePersistFailed(t *testing.T, ev sessions.Event) events.PermissionPersistFailed {
	t.Helper()
	var p events.PermissionPersistFailed
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatalf("decode permission_persist_failed payload: %v", err)
	}
	return p
}

func TestPersistGrant_CleanSuccessNoEventNoNotice(t *testing.T) {
	failPersist(t, config.ReasonNone, "", nil) // a nil error is the success contract
	store := newStore()
	ui := &recordingUI{}
	entry := toolEntry(scopeProj, "folder")

	got, err := persistGrantForTest(store, ui, targetPath, scopeProj, entry)
	if err != nil {
		t.Fatalf("persistGrantForTest() error = %v, want nil on success", err)
	}
	if got != entry {
		t.Fatalf("effective entry = %+v, want the original %+v unchanged on success", got, entry)
	}
	if len(store.Records()) != 0 {
		t.Fatalf("success appended %d records, want 0", len(store.Records()))
	}
	if len(ui.notices) != 0 {
		t.Fatalf("success rendered notices %v, want none", ui.notices)
	}
}

func TestPersistGrant_FolderFailureDegradesPathScopeUnchanged(t *testing.T) {
	boom := errors.New("boom")
	setPersist(t, func(string, string, any) (config.PersistReason, fserrors.Category, error) {
		return config.ReasonWriteError, fserrors.PermissionDenied, boom
	})
	store := newStore()
	ui := &recordingUI{}

	got, err := persistGrantForTest(store, ui, targetPath, scopeProj, toolEntry(scopeProj, "folder"))
	if !errors.Is(err, boom) {
		t.Fatalf("persistGrantForTest() error = %v, want the surfaced persist error %v", err, boom)
	}

	// In-memory grant: grant_kind becomes session, path_scope unchanged.
	want := permissions.PermissionEntry{Kind: "tool", Subject: "vcs_commit", PathScope: scopeProj, GrantKind: "session"}
	if got != want {
		t.Fatalf("degraded folder entry = %+v, want %+v", got, want)
	}

	evs := kindEvents(t, store, events.KindPermissionPersistFailed)
	if len(evs) != 1 {
		t.Fatalf("permission_persist_failed events = %d, want exactly 1", len(evs))
	}
	p := decodePersistFailed(t, evs[0])
	if p.GrantKind != "folder" {
		t.Fatalf("event grant_kind = %q, want the user's chosen %q", p.GrantKind, "folder")
	}
	if p.DegradedToPathScope != "" {
		t.Fatalf("event degraded_to_path_scope = %q, want absent for a folder grant", p.DegradedToPathScope)
	}
	if p.SubjectKind != "tool" || p.Subject != "vcs_commit" || p.TargetPath != targetPath {
		t.Fatalf("event subject/target fields = %+v, want tool/vcs_commit/%s", p, targetPath)
	}
	if p.Reason != string(config.ReasonWriteError) || p.ErrorCategory != string(fserrors.PermissionDenied) {
		t.Fatalf("event reason/category = %q/%q, want %q/%q", p.Reason, p.ErrorCategory, config.ReasonWriteError, fserrors.PermissionDenied)
	}
	// A non-lock_timeout failure carries the underlying error's message verbatim.
	if p.ErrorDetail != boom.Error() {
		t.Fatalf("event error_detail = %q, want the underlying error %q", p.ErrorDetail, boom.Error())
	}
	if len(ui.notices) != 1 {
		t.Fatalf("notices = %v, want exactly one persist-failure notice", ui.notices)
	}
	// The surfaced notice is exactly the TUI's rendering for this target/reason/category.
	if want := tui.RenderPersistFailureNotice(targetPath, string(config.ReasonWriteError), fserrors.PermissionDenied); ui.notices[0] != want {
		t.Fatalf("notice = %q, want f85's RenderPersistFailureNotice %q", ui.notices[0], want)
	}
}

func TestPersistGrant_GlobalFailureRewritesScopeAndRecordsDegradedPath(t *testing.T) {
	noSpace := errors.New("no space")
	failPersist(t, config.ReasonWriteError, fserrors.NoSpace, noSpace)
	store := newStore()
	ui := &recordingUI{}

	got, _ := persistGrantForTest(store, ui, targetPath, scopeProj, toolEntry("*", "global"))

	// A degraded global grant must be rescoped from "*" to the request path.
	want := permissions.PermissionEntry{Kind: "tool", Subject: "vcs_commit", PathScope: scopeProj, GrantKind: "session"}
	if got != want {
		t.Fatalf("degraded global entry = %+v, want %+v", got, want)
	}
	if got.PathScope == "*" {
		t.Fatalf("degraded global entry kept the all-paths sentinel in memory")
	}

	evs := kindEvents(t, store, events.KindPermissionPersistFailed)
	if len(evs) != 1 {
		t.Fatalf("permission_persist_failed events = %d, want exactly 1", len(evs))
	}
	p := decodePersistFailed(t, evs[0])
	if p.GrantKind != "global" {
		t.Fatalf("event grant_kind = %q, want the user's chosen %q", p.GrantKind, "global")
	}
	if p.DegradedToPathScope != scopeProj {
		t.Fatalf("event degraded_to_path_scope = %q, want the rewritten request path %q", p.DegradedToPathScope, scopeProj)
	}
	// A non-lock_timeout failure carries the underlying error's message verbatim.
	if p.ErrorDetail != noSpace.Error() {
		t.Fatalf("event error_detail = %q, want the underlying error %q", p.ErrorDetail, noSpace.Error())
	}
	if len(ui.notices) != 1 {
		t.Fatalf("notices = %v, want exactly one persist-failure notice", ui.notices)
	}
	// The surfaced notice is exactly the TUI's rendering for this target/reason/category.
	if want := tui.RenderPersistFailureNotice(targetPath, string(config.ReasonWriteError), fserrors.NoSpace); ui.notices[0] != want {
		t.Fatalf("notice = %q, want f85's RenderPersistFailureNotice %q", ui.notices[0], want)
	}
}

func TestPersistGrant_ProjectHostFailureDegradesToSessionHostGrant(t *testing.T) {
	boom := errors.New("read-only file system")
	calls := 0
	setPersist(t, func(path, key string, _ any) (config.PersistReason, fserrors.Category, error) {
		calls++
		if path != targetPath || key != config.KeyPermissions {
			t.Errorf("persist(%q, %q), want the project settings file %q under %q", path, key, targetPath, config.KeyPermissions)
		}
		return config.ReasonWriteError, fserrors.PermissionDenied, boom
	})
	store := newStore()
	ui := &recordingUI{}
	entry := hostEntry("web_fetch", "docs.example.com")

	got, err := persistGrantForTest(store, ui, targetPath, scopeProj, entry)
	if !errors.Is(err, boom) {
		t.Fatalf("persistGrantForTest() error = %v, want the surfaced persist error %v (a valid host event keeps the persist error)", err, boom)
	}
	want := permissions.PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "docs.example.com", GrantKind: "session"}
	if got != want {
		t.Fatalf("degraded project host entry = %+v, want %+v (only the lifetime changes)", got, want)
	}
	if got.PathScope != "" {
		t.Fatalf("degraded project host entry gained path_scope %q, want a host-only grant", got.PathScope)
	}
	if calls != 1 {
		t.Fatalf("persist attempts = %d, want exactly 1 (a failed host write is never retried)", calls)
	}

	evs := kindEvents(t, store, events.KindPermissionPersistFailed)
	if len(evs) != 1 {
		t.Fatalf("permission_persist_failed events = %d, want exactly 1", len(evs))
	}
	p := decodePersistFailed(t, evs[0])
	if p.SubjectKind != "host" || p.Subject != "web_fetch" {
		t.Fatalf("event subject_kind/subject = %q/%q, want host/web_fetch", p.SubjectKind, p.Subject)
	}
	if p.GrantKind != "project" {
		t.Fatalf("event grant_kind = %q, want the user's chosen %q", p.GrantKind, "project")
	}
	if p.HostScope != "docs.example.com" {
		t.Fatalf("event host_scope = %q, want the canonical host %q", p.HostScope, "docs.example.com")
	}
	if p.DegradedToPathScope != "" {
		t.Fatalf("event degraded_to_path_scope = %q, want absent for a host grant", p.DegradedToPathScope)
	}
	if p.TargetPath != targetPath {
		t.Fatalf("event target_path = %q, want the project settings file %q", p.TargetPath, targetPath)
	}
	if p.Reason != string(config.ReasonWriteError) || p.ErrorCategory != string(fserrors.PermissionDenied) || p.ErrorDetail != boom.Error() {
		t.Fatalf("event reason/category/detail = %q/%q/%q, want %q/%q/%q", p.Reason, p.ErrorCategory, p.ErrorDetail,
			config.ReasonWriteError, fserrors.PermissionDenied, boom.Error())
	}
	if len(ui.notices) != 1 {
		t.Fatalf("notices = %v, want exactly one persist-failure notice", ui.notices)
	}
	if want := tui.RenderPersistFailureNotice(targetPath, string(config.ReasonWriteError), fserrors.PermissionDenied); ui.notices[0] != want {
		t.Fatalf("notice = %q, want f85's RenderPersistFailureNotice %q", ui.notices[0], want)
	}
}

func TestPersistGrant_LockTimeoutCanonicalDetailAndCategoryOmitted(t *testing.T) {
	// config.Persist surfaces the raw context-deadline error for lock_timeout and an
	// empty category; the event must carry the canonical detail and omit category.
	failPersist(t, config.ReasonLockTimeout, "", errors.New("context deadline exceeded"))
	store := newStore()
	ui := &recordingUI{}

	if _, _ = persistGrantForTest(store, ui, targetPath, scopeProj, toolEntry(scopeProj, "folder")); len(ui.notices) != 1 {
		t.Fatalf("notices = %v, want exactly one", ui.notices)
	}
	// The notice is the TUI's rendering with the empty category (lock_timeout omits it).
	if want := tui.RenderPersistFailureNotice(targetPath, string(config.ReasonLockTimeout), ""); ui.notices[0] != want {
		t.Fatalf("notice = %q, want f85's RenderPersistFailureNotice %q", ui.notices[0], want)
	}
	p := decodePersistFailed(t, kindEvents(t, store, events.KindPermissionPersistFailed)[0])
	if p.ErrorDetail != lockTimeoutDetail {
		t.Fatalf("error_detail = %q, want canonical %q", p.ErrorDetail, lockTimeoutDetail)
	}
	if p.ErrorCategory != "" {
		t.Fatalf("error_category = %q, want omitted for lock_timeout", p.ErrorCategory)
	}
	if p.Reason != string(config.ReasonLockTimeout) {
		t.Fatalf("reason = %q, want %q", p.Reason, config.ReasonLockTimeout)
	}
}

const (
	deleteFolderPath = "/home/u/proj/.codemeld/settings.yaml"
	deleteGlobalPath = "/home/u/.codemeld/global/settings.yaml"
)

// captureDeletePersist swaps the persist seam to record the (path, key) of each
// call and how many calls were made, returning the recorder for assertions.
type deleteRecorder struct {
	calls int
	path  string
	key   string
	value any
}

func captureDeletePersist(t *testing.T, ret error) *deleteRecorder {
	t.Helper()
	rec := &deleteRecorder{}
	setPersist(t, func(path, key string, value any) (config.PersistReason, fserrors.Category, error) {
		rec.calls++
		rec.path = path
		rec.key = key
		rec.value = value
		if ret != nil {
			return config.ReasonWriteError, fserrors.IOError, ret
		}
		return config.ReasonNone, "", nil
	})
	return rec
}

// TestDeleteGrant_FolderTargetsFolderPath asserts a folder grant delete persists
// only to the folder settings path, under KeyPermissions.
func TestDeleteGrant_FolderTargetsFolderPath(t *testing.T) {
	rec := captureDeletePersist(t, nil)

	if err := DeleteGrant(&recordingUI{}, deleteFolderPath, deleteGlobalPath, toolEntry(scopeProj, "folder")); err != nil {
		t.Fatalf("DeleteGrant folder: %v", err)
	}
	if rec.calls != 1 {
		t.Fatalf("persist calls = %d, want 1", rec.calls)
	}
	if rec.path != deleteFolderPath {
		t.Fatalf("target path = %q, want folder %q", rec.path, deleteFolderPath)
	}
	if rec.key != config.KeyPermissions {
		t.Fatalf("key = %q, want %q", rec.key, config.KeyPermissions)
	}
}

// TestDeleteGrant_GlobalTargetsGlobalPath asserts a global grant delete persists
// only to the global settings path.
func TestDeleteGrant_GlobalTargetsGlobalPath(t *testing.T) {
	rec := captureDeletePersist(t, nil)

	if err := DeleteGrant(&recordingUI{}, deleteFolderPath, deleteGlobalPath, toolEntry("*", "global")); err != nil {
		t.Fatalf("DeleteGrant global: %v", err)
	}
	if rec.calls != 1 {
		t.Fatalf("persist calls = %d, want 1", rec.calls)
	}
	if rec.path != deleteGlobalPath {
		t.Fatalf("target path = %q, want global %q", rec.path, deleteGlobalPath)
	}
}

func TestDeleteGrant_ProjectHostTargetsProjectSettingsByHostKey(t *testing.T) {
	rec := captureDeletePersist(t, nil)
	entry := hostEntry("web_fetch", "docs.example.com")

	if err := DeleteGrant(&recordingUI{}, deleteFolderPath, deleteGlobalPath, entry); err != nil {
		t.Fatalf("DeleteGrant project host: %v", err)
	}
	if rec.calls != 1 {
		t.Fatalf("persist calls = %d, want 1", rec.calls)
	}
	if rec.path != deleteFolderPath {
		t.Fatalf("target path = %q, want the project settings file %q (a host grant is never global)", rec.path, deleteFolderPath)
	}
	if rec.key != config.KeyPermissions {
		t.Fatalf("key = %q, want %q", rec.key, config.KeyPermissions)
	}
	if rec.value != config.PermissionDelete(entry.DedupKey()) {
		t.Fatalf("delete payload = %#v, want the exact host DedupKey %#v", rec.value, entry.DedupKey())
	}
	for _, other := range []permissions.PermissionEntry{
		hostEntry("web_fetch", "api.example.com"),
		hostEntry("web_search", "docs.example.com"),
		toolEntry(scopeProj, "folder"),
	} {
		if rec.value == config.PermissionDelete(other.DedupKey()) {
			t.Fatalf("delete payload also matches %+v, want only the exact host entry removed", other)
		}
	}
}

// TestDeleteGrant_SessionSkippedNoPersist asserts a session grant is never written
// to disk — the on-disk parser rejects session grants, so DeleteGrant skips the
// persist call entirely and returns nil (the revoke path drops it from memory).
func TestDeleteGrant_SessionSkippedNoPersist(t *testing.T) {
	rec := captureDeletePersist(t, nil)

	if err := DeleteGrant(&recordingUI{}, deleteFolderPath, deleteGlobalPath, toolEntry(scopeProj, "session")); err != nil {
		t.Fatalf("DeleteGrant session: %v", err)
	}
	if rec.calls != 0 {
		t.Fatalf("persist calls = %d, want 0 for a session grant", rec.calls)
	}
}

// TestDeleteGrant_PropagatesPersistError asserts the underlying config.Persist
// error is surfaced to the caller (for the revoke notice).
func TestDeleteGrant_PropagatesPersistError(t *testing.T) {
	boom := errors.New("forced delete write failure")
	captureDeletePersist(t, boom)

	err := DeleteGrant(&recordingUI{}, deleteFolderPath, deleteGlobalPath, toolEntry(scopeProj, "folder"))
	if !errors.Is(err, boom) {
		t.Fatalf("DeleteGrant err = %v, want %v", err, boom)
	}
}

// --- Authorize integration -----------------------------------------------------

// stubGrants is the in-memory grant table seam (the production *config.Cache role).
type stubGrants struct{ entries []permissions.PermissionEntry }

func (g *stubGrants) Permissions() []permissions.PermissionEntry { return g.entries }
func (g *stubGrants) AppendPermission(e permissions.PermissionEntry) {
	g.entries = append(g.entries, e)
}

// missCache always misses and records nothing: a real grant added by the first
// authorize is found by Match before the cache is consulted on later calls.
type missCache struct{}

func (missCache) Lookup(permissions.MatchRequest) (string, bool) { return "", false }
func (missCache) Record(permissions.MatchRequest, string)        {}

// TestPersistGrant_ThroughAuthorize drives the real permission-prompt orchestrator with the real
// adapter bound to PersistGrant. It asserts (1) permission_decision is emitted with
// the user's chosen global values before the permission_persist_failed rewrite,
// (2) the degraded session grant is the entry made effective, (3) a later in-scope
// request matches it without re-prompting, and (4) sibling, parent, prefix-only, and
// cleaned-traversal out-of-scope requests each fall through to a fresh prompt.
func TestPersistGrant_ThroughAuthorize(t *testing.T) {
	failPersist(t, config.ReasonWriteError, fserrors.PermissionDenied, errors.New("disk full"))
	store := newStore()
	ui := &recordingUI{}
	grants := &stubGrants{}

	prompts := 0
	var promptChoice permissions.PromptChoice
	deps := permissions.AuthorizeDeps{
		Grants: grants,
		Cache:  missCache{},
		Prompt: func(context.Context, permissions.ScopeEscalation) (permissions.PromptOutcome, error) {
			prompts++
			return permissions.PromptOutcome{Choice: promptChoice}, nil
		},
		PersistGrant: func(e permissions.PermissionEntry) (permissions.PermissionEntry, error) {
			return persistGrantForTest(store, ui, targetPath, scopeProj, e)
		},
		EmitPromptShown: func(sk, s, ps string, dt []string, id permissions.DirectIdentity) error {
			return events.EmitPromptShown(store, sk, s, ps, dt, id.CommandSubject, id.RequestSubject)
		},
		EmitDecision: func(sk, s, ps, o, gk, gps string, id permissions.DirectIdentity) error {
			return events.EmitDecision(store, sk, s, ps, o, gk, gps, id.CommandSubject, id.RequestSubject)
		},
		EmitDecisionGrant: func(sk, s, ps, gk, gps, gs string, id permissions.DirectIdentity) error {
			return events.EmitDecisionGrant(store, sk, s, ps, gk, gps, gs, id.CommandSubject, id.RequestSubject)
		},
		EmitMatched: func(sk, s, ps, gk, gps, o, src, ah, drs string) error {
			return events.EmitMatchedIdentity(store, sk, s, ps, gk, gps, o, src, ah, drs)
		},
	}

	inScope := permissions.MatchRequest{Kind: "tool", Subject: "vcs_commit", PathScope: scopeProj}

	// (1) Approve a global grant; persistence fails and degrades.
	promptChoice = permissions.PromptAllowGlobal
	d, err := permissions.Authorize(context.Background(), inScope, permissions.ModeContext{}, deps)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if d.PersistErr == nil {
		t.Fatalf("Decision.PersistErr = nil, want the surfaced persist failure")
	}

	// Event order: permission_decision is emitted before permission_persist_failed,
	// so the decision records the chosen (pre-degrade) values.
	decisionIdx := recordIndex(t, store, events.KindPermissionDecision)
	failedIdx := recordIndex(t, store, events.KindPermissionPersistFailed)
	if decisionIdx < 0 || failedIdx < 0 || decisionIdx > failedIdx {
		t.Fatalf("event order: decision at %d, persist_failed at %d; want decision strictly before", decisionIdx, failedIdx)
	}
	dec := decodeDecision(t, kindEvents(t, store, events.KindPermissionDecision)[0])
	if dec.GrantKind != "global" || dec.GrantPathScope != "*" {
		t.Fatalf("decision recorded grant_kind/scope = %q/%q, want the chosen global/*", dec.GrantKind, dec.GrantPathScope)
	}

	// (2) The effective in-memory entry is the degraded session grant, not the global one.
	if len(grants.entries) != 1 {
		t.Fatalf("grant table has %d entries, want exactly the degraded one", len(grants.entries))
	}
	if g := grants.entries[0]; g.GrantKind != "session" || g.PathScope != scopeProj {
		t.Fatalf("effective entry = %+v, want a session grant scoped to %s", g, scopeProj)
	}
	if len(ui.notices) != 1 {
		t.Fatalf("notices = %v, want exactly one after the failed persist", ui.notices)
	}

	// (3) A later in-scope request matches the degraded grant without re-prompting.
	promptChoice = permissions.PromptDeny // would fire if it fell through; it must not
	before := prompts
	d2, err := permissions.Authorize(context.Background(), inScope, permissions.ModeContext{}, deps)
	if err != nil {
		t.Fatalf("Authorize() in-scope re-check error = %v", err)
	}
	if prompts != before {
		t.Fatalf("in-scope re-check prompted %d extra times, want 0 (matched the degraded grant)", prompts-before)
	}
	if d2.Outcome != "session_grant" || d2.Grant == nil || d2.Grant.GrantKind != "session" {
		t.Fatalf("in-scope re-check = %+v, want a session-grant match", d2)
	}

	// (4) Out-of-scope requests fall through to a fresh prompt (deny here).
	for _, tc := range []struct {
		name string
		path string
	}{
		{"sibling directory", scopeOther},
		{"parent directory", scopeUp},
		{"string-prefix-only non-descendant", scopePrefix},
		// A request scope reaching Authorize is already cleaned by the producer
		// (DerivePathScope -> CleanAbsResolve), and permission_prompt_shown rejects
		// an un-cleaned path (events.absCleanPath), so the traversal arrives here in
		// its cleaned form "/home/u/secret". The raw "/../" handling is covered at
		// the Match layer by permissions.TestDegradeGrant_DegradedGlobalMatchBoundary.
		{"cleaned traversal escaping scope", filepath.Clean(scopeProj + "/../secret")},
	} {
		t.Run("out-of-scope "+tc.name, func(t *testing.T) {
			promptChoice = permissions.PromptDeny
			before := prompts
			req := permissions.MatchRequest{Kind: "tool", Subject: "vcs_commit", PathScope: tc.path}
			d3, err := permissions.Authorize(context.Background(), req, permissions.ModeContext{}, deps)
			if err != nil {
				t.Fatalf("Authorize() %s error = %v", tc.name, err)
			}
			if prompts != before+1 {
				t.Fatalf("%s prompted %d times, want exactly 1 (degraded grant must not authorize it)", tc.name, prompts-before)
			}
			if d3.Outcome != "deny" {
				t.Fatalf("%s outcome = %q, want deny from the fresh prompt", tc.name, d3.Outcome)
			}
		})
	}

	// Across the whole flow exactly one persist-failure event and one notice were produced.
	if got := kindEvents(t, store, events.KindPermissionPersistFailed); len(got) != 1 {
		t.Fatalf("permission_persist_failed events across the flow = %d, want exactly 1", len(got))
	}
	if len(ui.notices) != 1 {
		t.Fatalf("notices across the flow = %v, want exactly 1", ui.notices)
	}
}

// recordIndex returns the position of the first record of kind in the store's
// record stream, or -1 if absent.
func recordIndex(t *testing.T, store *sessions.Store, kind string) int {
	t.Helper()
	for i, r := range store.Records() {
		ev, ok := r.(sessions.Event)
		if !ok {
			t.Fatalf("record %T is not a sessions.Event", r)
		}
		if ev.Kind == kind {
			return i
		}
	}
	return -1
}

func decodeDecision(t *testing.T, ev sessions.Event) events.PermissionDecision {
	t.Helper()
	var p events.PermissionDecision
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatalf("decode permission_decision payload: %v", err)
	}
	return p
}

// The versioned direct subject starts with an unmatched single quote, which YAML would misread as an
// opening quote if it were emitted bare, so the on-disk round trip is pinned here.
func TestVersionedDirectSubjectSurvivesTheOnDiskRoundTrip(t *testing.T) {
	stored, err := permissions.EncodeDirectEnvSubject([]string{"FOO=a b", "BAR=2"}, false, "hg :*")
	if err != nil {
		t.Fatalf("EncodeDirectEnvSubject: %v", err)
	}
	entry := permissions.PermissionEntry{Kind: "direct", Subject: stored, PathScope: scopeProj, GrantKind: "folder"}

	data, err := permissions.MarshalEntry(entry)
	if err != nil {
		t.Fatalf("MarshalEntry: %v", err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("yaml.Unmarshal(%q): %v", data, err)
	}
	got, err := permissions.ParseEntry(raw, "settings.yaml", 0)
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	if got != entry {
		t.Fatalf("round-tripped entry = %+v, want %+v", got, entry)
	}
	if !permissions.MatchesDirectSubject([]string{"hg", "status"}, []string{"FOO=a b", "BAR=2"}, false, got.Subject) {
		t.Fatal("the reloaded grant no longer authorizes the request that created it")
	}
	if permissions.MatchesDirectSubject([]string{"hg", "status"}, nil, false, got.Subject) {
		t.Fatal("the reloaded grant authorized the bare command")
	}
}

func TestPersistGrantReportingCreate_ReportsTheWriteThatMadeTheFile(t *testing.T) {
	project := t.TempDir()
	local := config.LocalSettingsPath(project)
	ui := &recordingUI{}

	_, created, err := PersistGrantReportingCreate(newStore(), ui, local, scopeProj, toolEntry(project, "folder"))
	if err != nil {
		t.Fatalf("first grant: %v", err)
	}
	if !created {
		t.Fatalf("created = false, want true for the grant that made %s", local)
	}
	if _, statErr := os.Stat(local); statErr != nil {
		t.Fatalf("stat %s: %v", local, statErr)
	}

	_, created, err = PersistGrantReportingCreate(newStore(), ui, local, scopeProj, toolEntry(scopeSub, "folder"))
	if err != nil {
		t.Fatalf("second grant: %v", err)
	}
	if created {
		t.Fatalf("created = true, want false once the file exists")
	}
}

func TestPersistGrantReportingCreate_ReportsNoCreationWhenTheWriteFails(t *testing.T) {
	failPersist(t, config.ReasonLockTimeout, "", errors.New("forced"))
	_, created, err := PersistGrantReportingCreate(newStore(), &recordingUI{}, filepath.Join(t.TempDir(), "settings.local.yaml"), scopeProj, toolEntry(scopeProj, "folder"))
	if err == nil {
		t.Fatalf("err = nil, want the forced failure")
	}
	if created {
		t.Fatalf("created = true, want false when nothing was written")
	}
}

func TestPersistGrantReportingCreate_WritesTheFixedGrantBytes(t *testing.T) {
	project := t.TempDir()
	local := config.LocalSettingsPath(project)

	if _, _, err := PersistGrantReportingCreate(newStore(), &recordingUI{}, local, project, toolEntry(project, "folder")); err != nil {
		t.Fatalf("grant: %v", err)
	}

	want := fmt.Sprintf("permissions:\n  - kind: tool\n    subject: vcs_commit\n    path_scope: %s\n    grant_kind: folder\n", project)
	if got := readSettingsFile(t, local); got != want {
		t.Fatalf("local settings file = %q, want the fixed bytes %q", got, want)
	}
}

func TestDeleteGrant_RemovesTheGrantFromTheRealFolderFile(t *testing.T) {
	project := t.TempDir()
	local := config.LocalSettingsPath(project)
	global := filepath.Join(t.TempDir(), "global", "settings.yaml")
	entry := toolEntry(project, "folder")

	if _, _, err := PersistGrantReportingCreate(newStore(), &recordingUI{}, local, project, entry); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	if err := DeleteGrant(&recordingUI{}, local, global, entry); err != nil {
		t.Fatalf("DeleteGrant: %v", err)
	}

	if got := readSettingsFile(t, local); got != "" {
		t.Fatalf("local settings file after revoke = %q, want the empty document a revoke of its only grant leaves", got)
	}
	if _, err := os.Stat(global); !os.IsNotExist(err) {
		t.Fatalf("stat %q = %v, want the global file untouched by a folder revoke", global, err)
	}
}

func readSettingsFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	return string(b)
}

func persistGrantForTest(store *sessions.Store, ui tui.NoticeRenderer, targetPath, requestPath string, entry permissions.PermissionEntry) (permissions.PermissionEntry, error) {
	persisted, _, err := PersistGrantReportingCreate(store, ui, targetPath, requestPath, entry)
	return persisted, err
}
