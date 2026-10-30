// Session-lifetime composed-config cache: the single read source for one run.
package config

import (
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
)

// Hard-coded runtime defaults applied when a config key is omitted.
const (
	defaultDiscoveryBoundary      = "launch-dir-only"
	defaultAgentMaxConcurrency    = 3
	defaultAgentInstrMaxFileBytes = 65536
	defaultRetentionDays          = 30
	minMaxToolOutputBytes         = 256
	defaultMaxToolOutputBytes     = 65536
	// defaultMode is the launch default interaction mode applied when
	// mode.default is omitted.
	defaultMode = "build"
	// provider.retry defaults: auto-retry is on out of the box with 4 total
	// attempts (3 retries), a ~500ms exponential base, and an ~8s cap.
	defaultRetryEnabled              = true
	defaultRetryMaxAttempts          = 4
	defaultRetryBaseDelayMs          = 500
	defaultRetryMaxDelayMs           = 8000
	defaultAttribution               = true
	defaultWebResearchEnabled        = true
	defaultWebResearchMaxResults     = 6
	defaultWebResearchTimeoutSeconds = 20
)

// RetrySettings is the resolved provider.retry auto-retry configuration:
// whether auto-retry is enabled, the total attempt cap (including the first), and
// the exponential-backoff base and cap in milliseconds. The per-turn retry
// wall-clock budget is not a settings knob — it has a fixed default applied at the
// turn layer.
type RetrySettings struct {
	Enabled     bool
	MaxAttempts int
	BaseDelayMs int
	MaxDelayMs  int
}

// WebResearchSettings excludes the API key so formatted settings cannot disclose it.
type WebResearchSettings struct {
	Enabled        bool
	MaxResults     int
	TimeoutSeconds int
}

// defaultVCSPriority is the tie-break order used when vcs.priority is
// omitted. Returned copies never alias this package-level slice.
var defaultVCSPriority = []string{"git", "hg", "jj"}

// composedSource labels permission-parse errors that originate from the
// already-composed config rather than a single on-disk settings file.
const composedSource = "composed config"

// Cache is the single, session-lifetime read source for composed configuration.
// It is built once from the composed config and never re-reads files
// so external edits to the on-disk YAML are deliberately invisible for the run
// (Non-Goals: "no live config reload during a running session").
// In-process permission grants and model selections made via the write-back
// methods are visible to subsequent reads immediately but are not persisted to
// disk by those methods, and there is no general reload API.
//
// ToggleFavorite, SetAttribution and SetSystemOne are the exceptions: they durably write the
// global settings layer through the locked writer and replace the cached value
// only from that write's confirmed result.
type Cache struct {
	projectRoot string
	layerPaths  []string
	launchHome  string

	discoveryBoundary      string
	agentMaxConcurrency    int
	agentInstrMaxFileBytes int
	retentionDays          int
	maxToolOutputBytes     int
	vcsPriority            []string
	vcsPreferred           string
	modeDefault            string
	modeConfigured         bool
	attribution            bool
	programLookup          string

	retry RetrySettings

	webResearch       WebResearchSettings
	webResearchAPIKey string

	// mu guards the live-mutable provider set, selectable catalog and discovered
	// context windows only (providers, catalog, discoveredWindows) against
	// concurrent SetProvider writes and the background reads that resolve models
	// mid-turn. The rest of the struct is built once in NewCache; the permission
	// and model fields keep their existing external-serialization contract
	// (bootstrap's syncGrants / the picker apply) and are deliberately not covered
	// here.
	mu                sync.RWMutex
	providers         map[string]provider.ProviderEntry
	catalog           provider.Catalog
	discoveredWindows map[string]map[string]int64
	permissions       []permissions.PermissionEntry

	layeredPermissions []permissions.PermissionEntry

	declaredCommands []permissions.DeclaredCommand

	writableFolders []string

	modelActive      any
	hasModelActive   bool
	modelLastUsed    any
	hasModelLastUsed bool

	favorites []Favorite

	systemOneMu sync.RWMutex
	systemOne   string
}

func NewCache(composed map[string]any, projectRoot string, layerPaths []string, home ...string) (*Cache, error) {
	providers, err := provider.ParseProviders(composed)
	if err != nil {
		return nil, err
	}
	perms, err := parsePermissions(composed)
	if err != nil {
		return nil, err
	}
	declaredCommands, err := parseDeclaredCommands(composed)
	if err != nil {
		return nil, err
	}
	maxToolOutputBytes, err := resolveMaxToolOutputBytes(composed)
	if err != nil {
		return nil, err
	}
	retentionDays, err := resolveRetentionDays(composed)
	if err != nil {
		return nil, err
	}
	favorites, err := favoritesFromRaw(composed)
	if err != nil {
		return nil, err
	}

	c := &Cache{
		projectRoot:            projectRoot,
		layerPaths:             slices.Clone(layerPaths),
		discoveryBoundary:      nestedStringOr(composed, "discovery", "boundary", defaultDiscoveryBoundary),
		agentMaxConcurrency:    nestedIntOr(composed, "agent", "max_concurrency", defaultAgentMaxConcurrency),
		agentInstrMaxFileBytes: nestedIntOr(composed, "agent_instructions", "max_file_bytes", defaultAgentInstrMaxFileBytes),
		retentionDays:          retentionDays,
		maxToolOutputBytes:     maxToolOutputBytes,
		vcsPriority:            vcsPriorityOr(composed),
		vcsPreferred:           nestedStringOr(composed, "vcs", "preferred", ""),
		providers:              providers,
		permissions:            perms,
		favorites:              favorites,
		webResearch:            resolveWebResearch(composed),
		webResearchAPIKey:      nestedStringOr(composed, "web_research", "api_key", ""),
		programLookup:          nestedStringOr(composed, "confinement", "program_lookup", "friendly"),
		declaredCommands:       declaredCommands,
		writableFolders:        parseWritableFolders(composed, projectRoot, home),
	}
	if len(home) > 0 {
		c.launchHome = home[0]
	}
	c.rebuildCatalogLocked()
	c.modeDefault, c.modeConfigured = resolveModeDefault(composed)
	c.retry = resolveRetry(composed)
	c.attribution = defaultAttribution
	if b, ok := composed["attribution"].(bool); ok {
		c.attribution = b
	}
	c.systemOne = "off"
	if s, ok := composed[KeySystemOne].(string); ok {
		c.systemOne = s
	}

	rawActive, hasActive := nestedRaw(composed, "model", "active")
	rawLastUsed, hasLastUsed := nestedRaw(composed, "model", "last_used")
	c.modelActive, c.hasModelActive = deepCopyValue(rawActive), hasActive
	c.modelLastUsed, c.hasModelLastUsed = deepCopyValue(rawLastUsed), hasLastUsed

	return c, nil
}

// discoveredModelsBasename is the on-disk name of the shared, system-owned
// discovered-model store. It lives beside the global settings file and holds the
// provider-keyed model lists refreshed from providers — cache data, never
// user-editable settings content.
const discoveredModelsBasename = "models.yaml"

// DiscoveredModelsPath returns the path of the shared discovered-model store for the
// given global settings file. The store sits beside settings.yaml in the global config
// directory. An empty settings path yields "" so a caller with no known settings
// location skips the store. The path is local only — reading or writing it performs no
// network I/O; writer and reader derive their target from this same helper so they
// cannot drift.
func DiscoveredModelsPath(globalSettingsPath string) string {
	if globalSettingsPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(globalSettingsPath), discoveredModelsBasename)
}

// discoveredModelsPath returns the shared models.yaml store path for the composed
// layer set (layerPaths[0] is the global settings file, and the models.yaml store lives
// beside it), or "" when no layer is known.
func discoveredModelsPath(layerPaths []string) string {
	if len(layerPaths) == 0 {
		return ""
	}
	return DiscoveredModelsPath(layerPaths[0])
}

func discoveredConfiguredModels(store DiscoveredModelsStore) map[string][]provider.DiscoveredConfiguredModel {
	if len(store.Providers) == 0 {
		return nil
	}
	out := make(map[string][]provider.DiscoveredConfiguredModel, len(store.Providers))
	for id, prov := range store.Providers {
		models := make([]provider.DiscoveredConfiguredModel, 0, len(prov.Models))
		for _, m := range prov.Models {
			if m.ID != "" {
				models = append(models, provider.DiscoveredConfiguredModel{ID: m.ID, InputModalities: m.InputModalities, Capabilities: m.Capabilities})
			}
		}
		if len(models) > 0 {
			out[id] = models
		}
	}
	return out
}

// discoveredChatGPTStoreModels adapts the openai-chatgpt entry of the shared, system-owned
// discovered-model store (models.yaml) into the provider package's neutral discovered-model
// records, so [provider.BuildCatalog] can extend the built-in ChatGPT row with locally
// discovered ids and their cached effort metadata. A missing, empty, or malformed store — or
// no openai-chatgpt entry — yields nil, leaving only the compiled ChatGPT seed selectable.
func discoveredChatGPTStoreModels(store DiscoveredModelsStore) []provider.ChatGPTStoreModel {
	prov, ok := store.Providers[provider.ChatGPTProviderID]
	if !ok || len(prov.Models) == 0 {
		return nil
	}
	out := make([]provider.ChatGPTStoreModel, 0, len(prov.Models))
	for _, m := range prov.Models {
		if m.ID == "" {
			continue
		}
		out = append(out, provider.ChatGPTStoreModel{
			ID:              m.ID,
			DisplayName:     m.DisplayName,
			ContextWindow:   m.ContextWindow,
			InputModalities: m.InputModalities,
			Capabilities:    m.Capabilities,
		})
	}
	return out
}

// ProjectRoot returns the resolved project root used for this session.
func (c *Cache) ProjectRoot() string { return c.projectRoot }

func (c *Cache) LaunchHome() string { return c.launchHome }

// LayerPaths returns a copy of the ordered settings-layer paths that composed
// the session config; mutating it does not change the cache.
func (c *Cache) LayerPaths() []string { return slices.Clone(c.layerPaths) }

// Discovery returns the discovery.boundary mode (default
// launch-dir-only when omitted).
func (c *Cache) Discovery() string { return c.discoveryBoundary }

// AgentMaxConcurrency returns agent.max_concurrency (default 3).
func (c *Cache) AgentMaxConcurrency() int { return c.agentMaxConcurrency }

// AgentInstructionsMaxFileBytes returns agent_instructions.max_file_bytes
// (default 65536).
func (c *Cache) AgentInstructionsMaxFileBytes() int { return c.agentInstrMaxFileBytes }

// RetentionDays returns sessions.retention_days (default 30).
func (c *Cache) RetentionDays() int { return c.retentionDays }

func (c *Cache) SetRetentionDays(days int) (PersistReason, fserrors.Category, error) {
	if days < 1 {
		return ReasonRereadParseError, "", fmt.Errorf("config.SetRetentionDays: days must be >= 1, got %d", days)
	}
	if len(c.layerPaths) == 0 || c.layerPaths[0] == "" {
		return ReasonRereadParseError, "", fmt.Errorf("config.SetRetentionDays: no global settings layer path configured")
	}
	reason, cat, err := Persist(c.layerPaths[0], KeyRetentionDays, days)
	if reason != ReasonNone || err != nil {
		return reason, cat, err
	}
	c.retentionDays = days
	return ReasonNone, "", nil
}

// MaxToolOutputBytes returns sessions.max_tool_output_bytes (default
// 65536, minimum 256).
func (c *Cache) MaxToolOutputBytes() int { return c.maxToolOutputBytes }

// VCSPriority returns a copy of the vcs.priority tie-break order
// (default [git, hg, jj]); mutating it does not change the cache.
func (c *Cache) VCSPriority() []string { return slices.Clone(c.vcsPriority) }

// VCSPreferred returns vcs.preferred, or "" when unset.
func (c *Cache) VCSPreferred() string { return c.vcsPreferred }

// ProviderRetry returns the resolved provider.retry auto-retry settings,
// filled with the hard-coded defaults for any omitted key. Enum/range validity is
// enforced upstream by the settings schema; this mirrors the other accessors'
// "return the configured value or the default" contract.
func (c *Cache) ProviderRetry() RetrySettings { return c.retry }

func (c *Cache) Attribution() bool { return c.attribution }

// SetAttribution writes attribution to the global settings layer and, only once that
// write has succeeded, updates the session value Attribution reports. attribution is
// global-only (see firstGlobalOnlyViolation), so layerPaths[0] is both the sole source
// and the sole write target.
func (c *Cache) SetAttribution(on bool) (PersistReason, fserrors.Category, error) {
	if len(c.layerPaths) == 0 || c.layerPaths[0] == "" {
		return ReasonRereadParseError, "", fmt.Errorf("config.SetAttribution: no global settings layer path configured")
	}
	reason, cat, err := Persist(c.layerPaths[0], KeyAttribution, on)
	if reason != ReasonNone || err != nil {
		return reason, cat, err
	}
	c.attribution = on
	return ReasonNone, "", nil
}

func (c *Cache) SystemOne() string {
	c.systemOneMu.RLock()
	defer c.systemOneMu.RUnlock()
	return c.systemOne
}

var beforeSystemOnePublish = func(string) {}

func (c *Cache) SetSystemOne(name string) (PersistReason, fserrors.Category, error) {
	if len(c.layerPaths) == 0 || c.layerPaths[0] == "" {
		return ReasonRereadParseError, "", fmt.Errorf("config.SetSystemOne: no global settings layer path configured")
	}
	c.systemOneMu.Lock()
	defer c.systemOneMu.Unlock()
	reason, cat, err := Persist(c.layerPaths[0], KeySystemOne, name)
	if reason != ReasonNone || err != nil {
		return reason, cat, err
	}
	beforeSystemOnePublish(name)
	c.systemOne = name
	return ReasonNone, "", nil
}

func (c *Cache) ProgramLookup() string { return c.programLookup }

func (c *Cache) OpenRouterDataCollection() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if v := c.providers[openRouterProviderID].Routing.DataCollection; v != "" {
		return v
	}
	return "allow"
}

func (c *Cache) SetOpenRouterDataCollection(v string) (PersistReason, fserrors.Category, error) {
	if v != "allow" && v != "deny" {
		return ReasonRereadParseError, "", fmt.Errorf("config.SetOpenRouterDataCollection: %q is not allow or deny", v)
	}
	return c.setOpenRouterRouting(KeyOpenRouterRoutingDataCollection, v, func(r *provider.Routing) { r.DataCollection = v })
}

func (c *Cache) OpenRouterSort() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if v := c.providers[openRouterProviderID].Routing.Sort; v != "" {
		return v
	}
	return routingSortDefault
}

// The cache never holds "default": the client sends any non-empty Sort as provider.sort.
func (c *Cache) SetOpenRouterSort(v string) (PersistReason, fserrors.Category, error) {
	cached := v
	switch v {
	case routingSortDefault:
		cached = ""
	case "throughput", "best_value":
	default:
		return ReasonRereadParseError, "", fmt.Errorf("config.SetOpenRouterSort: %q is not default, throughput, or best_value", v)
	}
	return c.setOpenRouterRouting(KeyOpenRouterRoutingSort, v, func(r *provider.Routing) { r.Sort = cached })
}

func (c *Cache) OpenRouterMaxPrice(model string) (provider.MaxPrice, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	p, ok := c.providers[openRouterProviderID].Routing.MaxPrice[model]
	return p, ok
}

func (c *Cache) SetOpenRouterMaxPrice(model string, p provider.MaxPrice) (PersistReason, fserrors.Category, error) {
	if model == "" {
		return ReasonRereadParseError, "", fmt.Errorf("config.SetOpenRouterMaxPrice: empty model id")
	}
	if (p.HasPrompt && !validMaxPrice(p.Prompt)) || (p.HasCompletion && !validMaxPrice(p.Completion)) {
		return ReasonRereadParseError, "", fmt.Errorf("config.SetOpenRouterMaxPrice: prices must be finite and not negative")
	}
	return c.setOpenRouterRouting(KeyOpenRouterRoutingMaxPrice, OpenRouterMaxPrice{Model: model, Price: p}, func(r *provider.Routing) {
		if !p.HasPrompt && !p.HasCompletion {
			delete(r.MaxPrice, model)
			return
		}
		if r.MaxPrice == nil {
			r.MaxPrice = map[string]provider.MaxPrice{}
		}
		r.MaxPrice[model] = p
	})
}

func (c *Cache) OpenRouterQuantizations() []OpenRouterQuantization {
	c.mu.RLock()
	defer c.mu.RUnlock()
	quants := c.providers[openRouterProviderID].Routing.Quantizations
	out := make([]OpenRouterQuantization, 0, len(quants))
	for model, q := range quants {
		q.Levels = slices.Clone(q.Levels)
		out = append(out, OpenRouterQuantization{Model: model, Quantization: q})
	}
	slices.SortFunc(out, func(x, y OpenRouterQuantization) int { return strings.Compare(x.Model, y.Model) })
	return out
}

func (c *Cache) SetOpenRouterQuantization(model string, q provider.Quantization) (PersistReason, fserrors.Category, error) {
	if model == "" {
		return ReasonRereadParseError, "", fmt.Errorf("config.SetOpenRouterQuantization: empty model id")
	}
	if err := provider.ValidateQuantizationLevels(q.Levels); err != nil {
		return ReasonRereadParseError, "", fmt.Errorf("config.SetOpenRouterQuantization: %w", err)
	}
	if q.Mode != "preferred" && q.Mode != "required" {
		return ReasonRereadParseError, "", fmt.Errorf("config.SetOpenRouterQuantization: mode %q is not preferred or required", q.Mode)
	}
	q.Levels = slices.Clone(q.Levels)
	return c.setOpenRouterRouting(KeyOpenRouterRoutingQuantizations, OpenRouterQuantization{Model: model, Quantization: q}, func(r *provider.Routing) {
		if r.Quantizations == nil {
			r.Quantizations = map[string]provider.Quantization{}
		}
		r.Quantizations[model] = q
	})
}

func (c *Cache) DeleteOpenRouterQuantization(model string) (PersistReason, fserrors.Category, error) {
	if model == "" {
		return ReasonRereadParseError, "", fmt.Errorf("config.DeleteOpenRouterQuantization: empty model id")
	}
	return c.setOpenRouterRouting(KeyOpenRouterRoutingQuantizations, OpenRouterQuantization{Model: model, Delete: true}, func(r *provider.Routing) {
		delete(r.Quantizations, model)
	})
}

func validMaxPrice(v float64) bool {
	return v >= 0 && !math.IsInf(v, 1)
}

func (c *Cache) setOpenRouterRouting(key string, v any, apply func(*provider.Routing)) (PersistReason, fserrors.Category, error) {
	if _, ok := c.Provider(openRouterProviderID); !ok {
		return ReasonRereadParseError, "", fmt.Errorf("config: %s needs a configured provider.openrouter entry", key)
	}
	if len(c.layerPaths) == 0 || c.layerPaths[0] == "" {
		return ReasonRereadParseError, "", fmt.Errorf("config: %s: no global settings layer path configured", key)
	}
	reason, cat, err := Persist(c.layerPaths[0], key, v)
	if reason != ReasonNone || err != nil {
		return reason, cat, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := copyProviderEntry(c.providers[openRouterProviderID])
	apply(&entry.Routing)
	c.providers[openRouterProviderID] = entry
	return ReasonNone, "", nil
}

func (c *Cache) WebResearch() WebResearchSettings { return c.webResearch }

// The API key must not be logged, emitted, or included in errors or tool results.
func (c *Cache) WebResearchAPIKey() string { return c.webResearchAPIKey }

// ModeDefault returns the resolved launch default interaction mode (mode.default)
// and whether the key was present in the composed config. When the
// key is absent or not a string the mode falls back to "build" with configured=false;
// callers map the boolean to the interaction_mode source (false -> "default", true ->
// "config"). Enum validity of the value is enforced upstream by the settings schema
// and downstream by the interaction_mode event, mirroring how Discovery returns the
// raw boundary string without re-validating the enum.
func (c *Cache) ModeDefault() (mode string, configured bool) {
	return c.modeDefault, c.modeConfigured
}

// Provider returns a copy of the named provider entry and whether it is
// configured. The boolean distinguishes a missing provider from one configured
// with empty values, which model validation relies on.
func (c *Cache) Provider(name string) (provider.ProviderEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.providers[name]
	if !ok {
		return provider.ProviderEntry{}, false
	}
	return copyProviderEntry(e), true
}

// Providers returns a copy of every configured provider entry keyed by name;
// mutating the returned map or its entries does not change the cache.
func (c *Cache) Providers() map[string]provider.ProviderEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]provider.ProviderEntry, len(c.providers))
	for name, e := range c.providers {
		out[name] = copyProviderEntry(e)
	}
	return out
}

// SelectableCatalog returns the merged selectable-provider catalog for this run:
// the configured provider.<name> entries plus the built-in providers that declare
// selectable models outside the provider: map (the OpenAI ChatGPT provider). It is
// the single cross-reference source for model validation, resume recovery, and
// no-selectable diagnostics, so a provider: openai-chatgpt selection validates
// against the built-in catalog rather than provider.openai-chatgpt.models. The
// returned catalog's accessors copy their entries, so the cached session view
// cannot be mutated through it.
func (c *Cache) SelectableCatalog() provider.Catalog {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.catalog
}

// SetProvider adds or replaces one composed provider entry and rebuilds the
// selectable catalog from the updated set, so a provider connected mid-session
// (via /connect, after its durable settings write) becomes selectable through the
// existing catalog surfaces — the model picker and /model — without a restart. It
// is the single-entry analogue of what NewCache does for the whole provider block:
// the rebuild runs through the same provider.BuildCatalog path, so a built-in
// selectable id (openai-chatgpt) still wins over a settings-shaped entry of the same
// name, and a configured provider with no settings model list picks up the ids
// discovered into the system-owned models.yaml store — so a /connect that writes
// models.yaml before this call makes those ids selectable now, with no restart. This does
// not persist anything — durable writes stay in config.Persist.
func (c *Cache) SetProvider(id string, entry provider.ProviderEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.storeProviderLocked(id, copyProviderEntry(entry))
}

func (c *Cache) SetOpenRouterConnection(baseURL, apiKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := copyProviderEntry(c.providers[openRouterProviderID])
	entry.BaseURL, entry.APIKey = baseURL, apiKey
	c.storeProviderLocked(openRouterProviderID, entry)
}

func (c *Cache) storeProviderLocked(id string, entry provider.ProviderEntry) {
	// providers is always non-nil for a NewCache-built cache (ParseProviders returns
	// an initialized map, or NewCache fails), so this first entry never hits a nil map.
	c.providers[id] = entry
	c.rebuildCatalogLocked()
}

func (c *Cache) ReloadDiscoveredCatalog() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rebuildCatalogLocked()
}

func (c *Cache) rebuildCatalogLocked() {
	store, _ := ReadDiscoveredModels(discoveredModelsPath(c.layerPaths))
	c.catalog = provider.BuildCatalog(c.providers, discoveredChatGPTStoreModels(store), discoveredConfiguredModels(store))
	c.discoveredWindows = discoveredContextWindows(store)
}

func discoveredContextWindows(store DiscoveredModelsStore) map[string]map[string]int64 {
	out := map[string]map[string]int64{}
	for id, prov := range store.Providers {
		for _, m := range prov.Models {
			if m.ContextWindow <= 0 {
				continue
			}
			if out[id] == nil {
				out[id] = map[string]int64{}
			}
			out[id][m.ID] = m.ContextWindow
		}
	}
	return out
}

func (c *Cache) ContextWindow(providerID, modelID string) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if w := c.providers[providerID].ContextWindows[modelID]; w > 0 {
		return w
	}
	return c.discoveredWindows[providerID][modelID]
}

// Permissions returns a copy of the in-memory permission list (composed on-disk
// grants plus any session grants appended this run); mutating it does not change
// the cache.
func (c *Cache) Permissions() []permissions.PermissionEntry {
	return slices.Clone(c.permissions)
}

// SetLayeredPermissions labels each effective grant with the nearest layer holding it, which is
// not the surviving copy's layer: deduplication keeps the farthest one. A session grant appended
// later carries no layer.
func (c *Cache) SetLayeredPermissions(entries []permissions.PermissionEntry) {
	c.layeredPermissions = slices.Clone(entries)
	nearest := make(map[permissions.DedupKey]permissions.LayerKind, len(entries))
	for _, e := range entries {
		key := e.DedupKey()
		if held, ok := nearest[key]; !ok || layerRank(e.Layer) > layerRank(held) {
			nearest[key] = e.Layer
		}
	}
	for i := range c.permissions {
		if kind, ok := nearest[c.permissions[i].DedupKey()]; ok {
			c.permissions[i].Layer = kind
		}
	}
}

func (c *Cache) LayeredPermissions() []permissions.PermissionEntry {
	return slices.Clone(c.layeredPermissions)
}

func layerRank(kind permissions.LayerKind) int {
	switch kind {
	case permissions.LayerLocal:
		return 3
	case permissions.LayerProject:
		return 2
	case permissions.LayerGlobal:
		return 1
	default:
		return 0
	}
}

// AppendPermission adds an in-memory permission grant so it is visible
// to subsequent Permissions reads without re-reading config. The entry is taken
// already-typed: session-scoped grants that the on-disk parser rejects
// are stored here directly rather than round-tripped through it.
func (c *Cache) AppendPermission(e permissions.PermissionEntry) {
	c.permissions = append(c.permissions, e)
}

// RemovePermission drops the first in-memory permission grant whose identity
// (DedupKey) matches e — the in-memory half of a grant revoke and the counterpart
// of AppendPermission — and reports whether it removed one. A caller that records a
// revoke needs that result: a false means the table never held the grant (a stale or
// duplicate request), so nothing was revoked to record. It matches a session grant the
// same way (the DedupKey carries grant_kind). Like
// AppendPermission it takes no lock of its own: a production caller mutating the
// live grant table must serialize this through the same holder that guards
// AppendPermission (bootstrap's syncGrants) so a concurrent prompt-gate append
// cannot race the removal. Previously returned Permissions slices are unaffected
// because Permissions clones before returning.
func (c *Cache) RemovePermission(e permissions.PermissionEntry) bool {
	key := e.DedupKey()
	for i, existing := range c.permissions {
		if existing.DedupKey() == key {
			c.permissions = append(c.permissions[:i], c.permissions[i+1:]...)
			return true
		}
	}
	return false
}

// ModelActiveRaw returns a copy of the raw model.active value and whether it is
// set. The value is left unvalidated for the model package's shape and cross-reference checks.
func (c *Cache) ModelActiveRaw() (any, bool) {
	return deepCopyValue(c.modelActive), c.hasModelActive
}

// ModelLastUsedRaw returns a copy of the raw model.last_used value and whether
// it is set, left unvalidated for the model package's checks.
func (c *Cache) ModelLastUsedRaw() (any, bool) {
	return deepCopyValue(c.modelLastUsed), c.hasModelLastUsed
}

// SetModelActiveRaw replaces the cached raw model.active value so
// later reads see the new selection immediately. It updates only this value;
// shape validation stays in the model package and persistence in the shared persistence path.
func (c *Cache) SetModelActiveRaw(v any) {
	c.modelActive, c.hasModelActive = deepCopyValue(v), true
}

// SetModelLastUsedRaw replaces the cached raw model.last_used value
// visible to later reads immediately; validation and persistence stay elsewhere.
func (c *Cache) SetModelLastUsedRaw(v any) {
	c.modelLastUsed, c.hasModelLastUsed = deepCopyValue(v), true
}

func (c *Cache) Favorites() []Favorite {
	return slices.Clone(c.favorites)
}

func (c *Cache) DeclaredCommands() []permissions.DeclaredCommand {
	return slices.Clone(c.declaredCommands)
}

// parsePermissions parses the composed permissions list into typed entries via
// permissions.ParseEntry. An absent or null permissions key yields no entries; a
// non-list value or a malformed entry returns an error so the cache is never
// built over a permission view it cannot interpret.
func parsePermissions(composed map[string]any) ([]permissions.PermissionEntry, error) {
	raw, ok := composed["permissions"]
	if !ok || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("config: permissions must be a list, got %T", raw)
	}
	out := make([]permissions.PermissionEntry, 0, len(list))
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("config: permissions.%d is not a mapping, got %T", i, item)
		}
		entry, err := permissions.ParseEntry(m, composedSource, i)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

// A rejected entry is advisory: it is noticed on stderr and skipped, so one bad entry never fails
// the load. Only a shape the settings schema should already have rejected is an error.
func parseDeclaredCommands(composed map[string]any) ([]permissions.DeclaredCommand, error) {
	entries, notices, err := permissions.ParseDeclaredCommands(composed["declared_commands"])
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	for _, notice := range notices {
		fmt.Fprintf(os.Stderr, "codemeld: %s\n", notice)
	}
	return entries, nil
}

// Never fall back to the ambient home: the floor and ~ expansion must match the launch's resolved home.
func parseWritableFolders(composed map[string]any, projectRoot string, home []string) []string {
	raw, ok := composed[writableFoldersKey]
	if !ok {
		return nil
	}
	if len(home) == 0 || home[0] == "" {
		return nil
	}
	folders, notices, err := permissions.ParseWritableFolders(raw, home[0], projectRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "codemeld: writable_folders: %v; no writable folders apply\n", err)
		return nil
	}
	for _, notice := range notices {
		fmt.Fprintf(os.Stderr, "codemeld: %s\n", notice)
	}
	return folders
}

func copyProviderEntry(e provider.ProviderEntry) provider.ProviderEntry {
	cp := e
	if e.AuthHeader != nil {
		h := *e.AuthHeader
		cp.AuthHeader = &h
	}
	cp.Routing.MaxPrice = maps.Clone(e.Routing.MaxPrice)
	if e.Routing.Quantizations != nil {
		cp.Routing.Quantizations = make(map[string]provider.Quantization, len(e.Routing.Quantizations))
		for model, q := range e.Routing.Quantizations {
			q.Levels = slices.Clone(q.Levels)
			cp.Routing.Quantizations[model] = q
		}
	}
	cp.ContextWindows = maps.Clone(e.ContextWindows)
	return cp
}

// resolveModeDefault reads mode.default from the composed config, returning the
// configured mode and configured=true when the key is present as a string, or the
// hard-coded default ("build") with configured=false when it is absent or not a
// string. Enum validity is not re-checked here — the schema rejects an
// out-of-enum value at load and the interaction_mode event rejects it at append, so
// this mirrors nestedStringOr's "return the raw string or the default" contract.
func resolveModeDefault(m map[string]any) (mode string, configured bool) {
	raw, ok := nestedRaw(m, "mode", "default")
	if !ok {
		return defaultMode, false
	}
	s, ok := raw.(string)
	if !ok {
		return defaultMode, false
	}
	return s, true
}

// resolveRetry reads the provider.retry block, falling back to the
// hard-coded defaults for an absent block or any omitted key. It lives under the
// `provider` object but is reserved config, not a provider entry
// (provider.RetryConfigKey); ParseProviders skips it so it is never selectable.
func resolveRetry(m map[string]any) RetrySettings {
	r := RetrySettings{
		Enabled:     defaultRetryEnabled,
		MaxAttempts: defaultRetryMaxAttempts,
		BaseDelayMs: defaultRetryBaseDelayMs,
		MaxDelayMs:  defaultRetryMaxDelayMs,
	}
	prov, ok := m["provider"].(map[string]any)
	if !ok {
		return r
	}
	retry, ok := prov[provider.RetryConfigKey].(map[string]any)
	if !ok {
		return r
	}
	if v, ok := retry["enabled"].(bool); ok {
		r.Enabled = v
	}
	if n, ok := asInt(retry["max_attempts"]); ok {
		r.MaxAttempts = n
	}
	if n, ok := asInt(retry["base_delay_ms"]); ok {
		r.BaseDelayMs = n
	}
	if n, ok := asInt(retry["max_delay_ms"]); ok {
		r.MaxDelayMs = n
	}
	return r
}

func resolveWebResearch(m map[string]any) WebResearchSettings {
	s := WebResearchSettings{
		Enabled:        defaultWebResearchEnabled,
		MaxResults:     nestedIntOr(m, "web_research", "max_results", defaultWebResearchMaxResults),
		TimeoutSeconds: nestedIntOr(m, "web_research", "timeout_seconds", defaultWebResearchTimeoutSeconds),
	}
	if raw, ok := nestedRaw(m, "web_research", "enabled"); ok {
		if b, ok := raw.(bool); ok {
			s.Enabled = b
		}
	}
	return s
}

func resolveRetentionDays(m map[string]any) (int, error) {
	n := nestedIntOr(m, "sessions", "retention_days", defaultRetentionDays)
	if n < 1 {
		return 0, fmt.Errorf("sessions.retention_days must be >= 1, got %d", n)
	}
	return n, nil
}

func resolveMaxToolOutputBytes(m map[string]any) (int, error) {
	n := nestedIntOr(m, "sessions", "max_tool_output_bytes", defaultMaxToolOutputBytes)
	if n < minMaxToolOutputBytes {
		return 0, fmt.Errorf("sessions.max_tool_output_bytes must be >= %d, got %d", minMaxToolOutputBytes, n)
	}
	return n, nil
}

// nestedStringOr returns m[top][child] as a string, or def when the parent is
// not a map or the child is absent or not a string.
func nestedStringOr(m map[string]any, top, child, def string) string {
	sub, ok := m[top].(map[string]any)
	if !ok {
		return def
	}
	s, ok := sub[child].(string)
	if !ok {
		return def
	}
	return s
}

// nestedIntOr returns m[top][child] coerced to int, or def when the parent is
// not a map or the child is absent or not numeric. Decoded YAML integers arrive
// as uint64/int64/float64; Go-constructed maps use int, so all are accepted.
func nestedIntOr(m map[string]any, top, child string, def int) int {
	sub, ok := m[top].(map[string]any)
	if !ok {
		return def
	}
	if n, ok := asInt(sub[child]); ok {
		return n
	}
	return def
}

// nestedRaw returns the raw m[top][child] value and whether it is present.
func nestedRaw(m map[string]any, top, child string) (any, bool) {
	sub, ok := m[top].(map[string]any)
	if !ok {
		return nil, false
	}
	v, ok := sub[child]
	return v, ok
}

// vcsPriorityOr returns a fresh copy of vcs.priority as []string, falling back
// to a copy of the default when the key is absent or not a string list.
// An explicitly empty list is honored as configured, not replaced by the default.
func vcsPriorityOr(m map[string]any) []string {
	sub, ok := m["vcs"].(map[string]any)
	if !ok {
		return slices.Clone(defaultVCSPriority)
	}
	raw, ok := sub["priority"]
	if !ok {
		return slices.Clone(defaultVCSPriority)
	}
	list, ok := toStrings(raw)
	if !ok {
		return slices.Clone(defaultVCSPriority)
	}
	return list
}

// asInt coerces a decoded numeric value to int, reporting false for non-numeric
// kinds.
func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case uint64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}

// toStrings converts a decoded list value into a fresh []string, accepting the
// []any shape goccy/go-yaml produces and a native []string. It reports false if
// the value is not a list or holds a non-string element.
func toStrings(v any) ([]string, bool) {
	switch s := v.(type) {
	case []string:
		return slices.Clone(s), true
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			str, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, str)
		}
		return out, true
	default:
		return nil, false
	}
}
