package securitystate

import (
	"maps"
	"slices"
	"sync"
	"time"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/locks"
	"codemeld.dev/codemeld/internal/permissions"
)

type LayerKind string

const (
	LayerGlobal  LayerKind = "global"
	LayerProject LayerKind = "project"
	LayerLocal   LayerKind = "local"
)

// LayerSnapshot is one settings layer as bootstrap admitted it, handed to a monitor so the
// baseline is the content the launch actually loaded rather than a later re-read. Ignored
// carries a configured project path the trust gate refused: it is retained so the launch can
// state what it is not watching, and the monitor never opens or locks it.
type LayerSnapshot struct {
	Kind    LayerKind
	Path    string
	Ignored bool
	Present bool
	Raw     map[string]any
}

// Section names a protected area of a settings layer. The vocabulary is closed and never
// carries a configured provider name, which is unbounded user text.
type Section string

const (
	SectionPermissions           Section = "permissions"
	SectionAuth                  Section = "auth"
	SectionProviderDestination   Section = "provider_destination"
	SectionProviderCredential    Section = "provider_credential"
	SectionProviderAuthHeader    Section = "provider_auth_header"
	SectionWebResearchCredential Section = "web_research_credential"
	SectionDeclaredCommands      Section = "declared_commands"
	SectionBlockedPaths          Section = "blocked_paths"
	SectionWritableFolders       Section = "writable_folders"
)

var sectionOrder = []Section{
	SectionPermissions,
	SectionAuth,
	SectionProviderDestination,
	SectionProviderCredential,
	SectionProviderAuthHeader,
	SectionWebResearchCredential,
	SectionDeclaredCommands,
	SectionBlockedPaths,
	SectionWritableFolders,
}

type Label string

const (
	LabelAdded      Label = "added"
	LabelRemoved    Label = "removed"
	LabelChanged    Label = "changed"
	LabelMalformed  Label = "malformed"
	LabelUnreadable Label = "unreadable"
	LabelMissing    Label = "missing"
)

var labelOrder = []Label{
	LabelAdded,
	LabelRemoved,
	LabelChanged,
	LabelMalformed,
	LabelUnreadable,
	LabelMissing,
}

// Result is one layer's checkpoint outcome. It is metadata only: no settings content,
// permission argument, credential, token, account identifier, or provider name reaches it.
// Unavailable means the layer could not be inspected under its lock and carries no labels,
// which is distinct from inspecting it and finding it unreadable.
type Result struct {
	Kind        LayerKind
	Path        string
	Unavailable bool
	Reason      locks.LockReason
	Sections    []Section
	Labels      []Label
}

// checkpointLockTimeout is the sidecar-lock protocol every protected writer uses; a
// checkpoint has to serialize against a publication rather than read across one.
const checkpointLockTimeout = 2 * time.Second

// projectionSource is the diagnostic name given to entries parsed for comparison. Parse
// errors are discarded here because validation already ran, so the name never reaches output.
const projectionSource = "settings"

// readSettings is a package-local seam so a test can observe the critical section the
// checkpoint holds around its read.
var readSettings = fsutil.ReadSettingsBytes

var acquireLock = locks.Acquire

type providerFields struct {
	destination string
	credential  string
	headerName  string
	headerValue string
	hasHeader   bool
}

// Projection is the protected view of one settings layer. It holds credentials in memory and
// is only ever compared against another projection — never rendered, logged, hashed, or
// persisted.
type Projection struct {
	permissions      []permissions.PermissionEntry
	declaredCommands []string
	blockedPaths     []string
	writableFolders  []string
	auth             map[string]map[string]string
	providers        map[string]providerFields
	webKey           string
	webKeySet        bool
}

// Project builds the protected view of an already-validated settings layer.
func Project(raw map[string]any) Projection {
	p := Projection{
		auth:      map[string]map[string]string{},
		providers: map[string]providerFields{},
	}
	list, _ := raw["permissions"].([]any)
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		entry, err := permissions.ParseEntry(m, projectionSource, i)
		if err != nil {
			continue
		}
		p.permissions = append(p.permissions, entry)
	}
	// The declared entries are projected as written rather than as parsed subjects: an edit that
	// turns a live entry into one the loader rejects changes what is authorized, and the parsed
	// list drops it without a trace.
	declared, _ := raw["declared_commands"].([]any)
	for _, item := range declared {
		text, ok := item.(string)
		if !ok {
			continue
		}
		p.declaredCommands = append(p.declaredCommands, text)
	}
	blocked, _ := raw["blocked_paths"].([]any)
	for _, item := range blocked {
		text, ok := item.(string)
		if !ok {
			continue
		}
		p.blockedPaths = append(p.blockedPaths, text)
	}
	writable, _ := raw["writable_folders"].([]any)
	for _, item := range writable {
		text, ok := item.(string)
		if !ok {
			continue
		}
		p.writableFolders = append(p.writableFolders, text)
	}
	auth, _ := raw["auth"].(map[string]any)
	for name, record := range auth {
		fields, ok := record.(map[string]any)
		if !ok {
			continue
		}
		p.auth[name] = stringFields(fields)
	}
	providers, _ := raw["provider"].(map[string]any)
	for name, entry := range providers {
		// retry is shared connection tuning under the same key, not a configured provider.
		if name == "retry" {
			continue
		}
		fields, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		projected := providerFields{
			destination: stringAt(fields, "base_url"),
			credential:  stringAt(fields, "api_key"),
		}
		if header, ok := fields["auth_header"].(map[string]any); ok {
			projected.hasHeader = true
			projected.headerName = stringAt(header, "name")
			projected.headerValue = stringAt(header, "value")
		}
		p.providers[name] = projected
	}
	web, _ := raw["web_research"].(map[string]any)
	p.webKey, p.webKeySet = web["api_key"].(string)
	return p
}

func stringFields(m map[string]any) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

func stringAt(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

type target struct {
	kind     LayerKind
	path     string
	baseline Projection
	present  bool
}

// Monitor holds a runtime-local baseline of the protected settings the launch admitted and
// compares later checkpoint reads against it. It never touches the live authorization or
// configuration cache: a checkpoint reports what changed on disk and changes nothing.
type Monitor struct {
	mu          sync.Mutex
	targets     []*target
	lockTimeout time.Duration
}

func NewMonitor(layers []LayerSnapshot) *Monitor {
	m := &Monitor{lockTimeout: checkpointLockTimeout}
	for _, layer := range layers {
		if layer.Ignored || layer.Path == "" {
			continue
		}
		t := &target{kind: layer.Kind, path: layer.Path, present: layer.Present}
		if layer.Present {
			t.baseline = Project(layer.Raw)
		}
		m.targets = append(m.targets, t)
	}
	return m
}

// Checkpoint compares every admitted layer against its baseline and returns one result per
// affected layer, in the order the layers were admitted (global first). A layer that matches
// its baseline — including an admitted path that was absent and still is — yields no result.
func (m *Monitor) Checkpoint() []Result {
	var results []Result
	for _, t := range m.targets {
		if result, affected := m.check(t); affected {
			results = append(results, result)
		}
	}
	return results
}

func (m *Monitor) check(t *target) (Result, bool) {
	result := Result{Kind: t.kind, Path: t.path}

	release, reason, _ := acquireLock(t.path+lockSuffix, m.lockTimeout)
	if reason != locks.ReasonNone {
		result.Unavailable = true
		result.Reason = reason
		return result, true
	}
	// The lock spans the baseline read through the comparison so a publication cannot land
	// between them, and m.mu nests inside it because a publishing writer calls AdvanceBaseline
	// while holding the same lock.
	defer release()

	m.mu.Lock()
	baseline, present := t.baseline, t.present
	m.mu.Unlock()

	data, found, ok := readSettings(t.path)
	switch {
	case !ok:
		result.Labels = []Label{LabelUnreadable}
		return result, true
	case !found && !present:
		return Result{}, false
	case !found:
		result.Labels = []Label{LabelMissing}
		return result, true
	}

	raw, cat, _ := validate(t.kind, data, t.path)
	if cat != config.LoadOK {
		result.Labels = []Label{LabelMalformed}
		return result, true
	}

	sections, labels := compare(baseline, Project(raw))
	if len(labels) == 0 {
		return Result{}, false
	}
	result.Sections, result.Labels = sections, labels
	return result, true
}

// validate applies the same source-layer rules bootstrap applied, so a file bootstrap would
// have refused is malformed rather than semantic drift.
func validate(kind LayerKind, data []byte, path string) (map[string]any, config.LoadFailure, error) {
	switch kind {
	case LayerProject:
		return config.ValidateProjectSettingsBytes(data, path)
	case LayerLocal:
		return config.ValidateLocalSettingsBytes(data, path)
	}
	return config.ValidateGlobalSettingsBytes(data, path)
}

// AdvanceBaseline replaces the baseline for path when prior still matches the retained one,
// so a confirmed publication only advances the state it was computed against. A caller whose
// prior no longer matches has raced another writer and its change stays visible as drift.
func (m *Monitor) AdvanceBaseline(path string, prior, next Projection) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, t := range m.targets {
		if t.path != path {
			continue
		}
		if _, labels := compare(t.baseline, prior); len(labels) != 0 {
			return false
		}
		t.baseline, t.present = next, true
		return true
	}
	return false
}

func compare(before, after Projection) ([]Section, []Label) {
	sections := map[Section]bool{}
	labels := map[Label]bool{}

	for _, label := range comparePermissions(before.permissions, after.permissions) {
		sections[SectionPermissions] = true
		labels[label] = true
	}
	for _, label := range compareStringEntries(before.declaredCommands, after.declaredCommands) {
		sections[SectionDeclaredCommands] = true
		labels[label] = true
	}
	for _, label := range compareStringEntries(before.blockedPaths, after.blockedPaths) {
		sections[SectionBlockedPaths] = true
		labels[label] = true
	}
	for _, label := range compareStringEntries(before.writableFolders, after.writableFolders) {
		sections[SectionWritableFolders] = true
		labels[label] = true
	}
	for _, label := range compareAuth(before.auth, after.auth) {
		sections[SectionAuth] = true
		labels[label] = true
	}
	compareProviders(before.providers, after.providers, sections, labels)
	if label, changed := compareWebKey(before, after); changed {
		sections[SectionWebResearchCredential] = true
		labels[label] = true
	}

	return fixedOrder(sectionOrder, sections), fixedOrder(labelOrder, labels)
}

func fixedOrder[T comparable](order []T, present map[T]bool) []T {
	var out []T
	for _, item := range order {
		if present[item] {
			out = append(out, item)
		}
	}
	return out
}

// comparePermissions corresponds two entries only when every authorization-bearing field is
// equal, so replacing a field is a removal plus an addition rather than a guessed edit. Entry
// order is authorization-bearing too — Match returns the first matching entry — so a reorder
// of the entries common to both lists is a change.
func comparePermissions(before, after []permissions.PermissionEntry) []Label {
	common := map[permissions.PermissionEntry]int{}
	afterCounts := counts(after)
	for entry, n := range counts(before) {
		common[entry] = min(n, afterCounts[entry])
	}
	keptBefore := takeCommon(before, maps.Clone(common))
	keptAfter := takeCommon(after, maps.Clone(common))

	var labels []Label
	if len(keptAfter) < len(after) {
		labels = append(labels, LabelAdded)
	}
	if len(keptBefore) < len(before) {
		labels = append(labels, LabelRemoved)
	}
	if !slices.Equal(keptBefore, keptAfter) {
		labels = append(labels, LabelChanged)
	}
	return labels
}

// Every declared entry, blocked path, and writable folder applies, so their order authorizes
// nothing and only the multiset is compared; an edited entry is a removal plus an addition, as it
// is for a permission entry.
func compareStringEntries(before, after []string) []Label {
	unmatched := map[string]int{}
	for _, entry := range before {
		unmatched[entry]++
	}
	added := false
	for _, entry := range after {
		if unmatched[entry] > 0 {
			unmatched[entry]--
			continue
		}
		added = true
	}
	var labels []Label
	if added {
		labels = append(labels, LabelAdded)
	}
	for _, n := range unmatched {
		if n > 0 {
			labels = append(labels, LabelRemoved)
			break
		}
	}
	return labels
}

func counts(entries []permissions.PermissionEntry) map[permissions.PermissionEntry]int {
	out := map[permissions.PermissionEntry]int{}
	for _, entry := range entries {
		out[entry]++
	}
	return out
}

func takeCommon(entries []permissions.PermissionEntry, budget map[permissions.PermissionEntry]int) []permissions.PermissionEntry {
	var kept []permissions.PermissionEntry
	for _, entry := range entries {
		if budget[entry] > 0 {
			budget[entry]--
			kept = append(kept, entry)
		}
	}
	return kept
}

func compareAuth(before, after map[string]map[string]string) []Label {
	var labels []Label
	for name, record := range after {
		prior, existed := before[name]
		switch {
		case !existed:
			labels = append(labels, LabelAdded)
		case !maps.Equal(prior, record):
			labels = append(labels, LabelChanged)
		}
	}
	for name := range before {
		if _, existed := after[name]; !existed {
			labels = append(labels, LabelRemoved)
		}
	}
	return labels
}

// compareProviders corresponds entries only by unchanged map key, so a rename is a removal
// plus an addition; the key itself is never reported.
func compareProviders(before, after map[string]providerFields, sections map[Section]bool, labels map[Label]bool) {
	for name, entry := range after {
		prior, existed := before[name]
		if !existed {
			labels[LabelAdded] = true
			markProviderSections(entry, sections)
			continue
		}
		if entry.destination != prior.destination {
			labels[LabelChanged] = true
			sections[SectionProviderDestination] = true
		}
		if entry.credential != prior.credential {
			labels[LabelChanged] = true
			sections[SectionProviderCredential] = true
		}
		if entry.hasHeader != prior.hasHeader || entry.headerName != prior.headerName || entry.headerValue != prior.headerValue {
			labels[LabelChanged] = true
			sections[SectionProviderAuthHeader] = true
		}
	}
	for name, entry := range before {
		if _, existed := after[name]; !existed {
			labels[LabelRemoved] = true
			markProviderSections(entry, sections)
		}
	}
}

func markProviderSections(entry providerFields, sections map[Section]bool) {
	sections[SectionProviderDestination] = true
	sections[SectionProviderCredential] = true
	if entry.hasHeader {
		sections[SectionProviderAuthHeader] = true
	}
}

func compareWebKey(before, after Projection) (Label, bool) {
	switch {
	case !before.webKeySet && after.webKeySet:
		return LabelAdded, true
	case before.webKeySet && !after.webKeySet:
		return LabelRemoved, true
	case before.webKey != after.webKey:
		return LabelChanged, true
	default:
		return "", false
	}
}
