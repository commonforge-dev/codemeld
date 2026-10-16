// Tests for the selectable-provider catalog: configured/built-in merge order,
// defensive copies, duplicate model ids across providers, configured-provider
// preservation, auth-kind derivation, and the OPENAI_API_KEY Platform-key helper.
package provider

import (
	"reflect"
	"strings"
	"testing"
)

func configuredEntry() ProviderEntry {
	return ProviderEntry{
		BaseURL: "https://example.test/v1",
		APIKey:  "sk-test",
	}
}

func entryByID(t *testing.T, cat Catalog, id string) CatalogEntry {
	t.Helper()
	e, ok := cat.Entry(id)
	if !ok {
		t.Fatalf("Entry(%q) not found in catalog", id)
	}
	return e
}

// TestBuildCatalog_MergeOrderAndBuiltin pins that configured providers come first
// in sorted id order, followed by the built-in OpenAI ChatGPT provider, and that
// the built-in is always present even with no configured providers.
func TestBuildCatalog_MergeOrderAndBuiltin(t *testing.T) {
	cat := BuildCatalog(map[string]ProviderEntry{
		"zzz":    configuredEntry(),
		"openai": configuredEntry(),
	}, nil, nil)
	var ids []string
	for _, e := range cat.Entries() {
		ids = append(ids, e.ID)
	}
	want := []string{"openai", "zzz", ChatGPTProviderID}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("catalog ids = %v, want %v (configured sorted, then built-in)", ids, want)
	}

	empty := BuildCatalog(nil, nil, nil)
	emptyIDs := []string{}
	for _, e := range empty.Entries() {
		emptyIDs = append(emptyIDs, e.ID)
	}
	if !reflect.DeepEqual(emptyIDs, []string{ChatGPTProviderID}) {
		t.Fatalf("empty-config catalog ids = %v, want just the built-in %q", emptyIDs, ChatGPTProviderID)
	}
}

func TestBuildCatalog_ConfiguredProviderPreserved(t *testing.T) {
	cat := BuildCatalog(
		map[string]ProviderEntry{"openrouter": {BaseURL: "https://openrouter.ai/api/v1", APIKey: "sk-or-test"}},
		nil,
		map[string][]DiscoveredConfiguredModel{"openrouter": discoveredIDModels("openai/gpt-5.5", "z-ai/glm-5.1")},
	)
	e := entryByID(t, cat, "openrouter")
	if e.AuthKind != AuthKindConfigured {
		t.Errorf("openrouter AuthKind = %q, want %q", e.AuthKind, AuthKindConfigured)
	}
	if e.Builtin {
		t.Error("openrouter Builtin = true, want false for a configured provider")
	}
	if e.Origin != OriginNone {
		t.Errorf("openrouter Origin = %q, want none", e.Origin)
	}
	if !reflect.DeepEqual(e.Models, []string{"openai/gpt-5.5", "z-ai/glm-5.1"}) {
		t.Errorf("openrouter Models = %v, want discovery order preserved", e.Models)
	}
}

// TestBuildCatalog_DiscoveredModelsForConfiguredProvider pins that a configured
// provider shipping no user-owned models list (settings key/base_url only, as /connect
// writes) draws its selectable ids from the discovered store map (models.yaml).
func TestBuildCatalog_DiscoveredModelsForConfiguredProvider(t *testing.T) {
	cat := BuildCatalog(
		map[string]ProviderEntry{"venice": {BaseURL: "https://api.venice.ai/api/v1", APIKey: "sk-test"}},
		nil,
		map[string][]DiscoveredConfiguredModel{"venice": discoveredIDModels("venice-uncensored", "qwen-2.5")},
	)
	e := entryByID(t, cat, "venice")
	if !reflect.DeepEqual(e.Models, []string{"venice-uncensored", "qwen-2.5"}) {
		t.Fatalf("venice Models = %v, want the discovered store ids", e.Models)
	}
}

func TestBuildCatalog_EmptyDiscoveredModelsDoNotFallbackToSettings(t *testing.T) {
	settings := map[string]ProviderEntry{"venice": configuredEntry()}
	cases := []struct {
		name       string
		discovered map[string][]DiscoveredConfiguredModel
	}{
		{"nil discovered map", nil},
		{"absent provider key", map[string][]DiscoveredConfiguredModel{"other": discoveredIDModels("x")}},
		{"empty discovered slice", map[string][]DiscoveredConfiguredModel{"venice": {}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := entryByID(t, BuildCatalog(settings, nil, tc.discovered), "venice")
			if len(e.Models) != 0 {
				t.Fatalf("venice Models = %v, want empty (no discovered data, no settings fallback)", e.Models)
			}
		})
	}
}

func TestBuildCatalog_PlatformDiscoveredRetainsEveryModel(t *testing.T) {
	ids := []string{"text-embedding-3-large", "gpt-5.5", "some-unknown-id", "gpt-5.5-pro"}
	cat := BuildCatalog(
		map[string]ProviderEntry{PlatformProviderID: configuredEntry()},
		nil,
		map[string][]DiscoveredConfiguredModel{PlatformProviderID: discoveredIDModels(ids...)},
	)
	e := entryByID(t, cat, PlatformProviderID)
	if !reflect.DeepEqual(e.Models, ids) {
		t.Fatalf("openai Models = %v, want every sanitized discovered id in discovery order %v", e.Models, ids)
	}
}

// TestBuildCatalog_DiscoveredIgnoredForUnconfiguredProvider pins that the discovered
// store only fills providers that are configured: an id present in the store but not in
// settings never becomes a catalog entry on its own. This keeps an orphan models.yaml
// row (the residue of a settings-write failure) inert.
func TestBuildCatalog_DiscoveredIgnoredForUnconfiguredProvider(t *testing.T) {
	cat := BuildCatalog(nil, nil, map[string][]DiscoveredConfiguredModel{"venice": discoveredIDModels("venice-uncensored")})
	if _, ok := cat.Entry("venice"); ok {
		t.Error("venice present in catalog with no configured entry; the discovered store must not create providers")
	}
}

// TestBuildCatalog_PlatformAuthKindAndDisplayName pins the OpenAI Platform provider
// id resolves to AuthKindPlatform with the ADR display name.
func TestBuildCatalog_PlatformAuthKindAndDisplayName(t *testing.T) {
	cat := BuildCatalog(map[string]ProviderEntry{
		PlatformProviderID: configuredEntry(),
	}, nil, nil)
	e := entryByID(t, cat, PlatformProviderID)
	if e.AuthKind != AuthKindPlatform {
		t.Errorf("openai AuthKind = %q, want %q", e.AuthKind, AuthKindPlatform)
	}
	if e.DisplayName != "OpenAI Platform" {
		t.Errorf("openai DisplayName = %q, want %q", e.DisplayName, "OpenAI Platform")
	}
	if e.Builtin {
		t.Error("openai Builtin = true, want false (the Platform provider is configured)")
	}
}

// TestBuildCatalog_ChatGPTBuiltinMetadata pins the built-in OpenAI ChatGPT row: its
// models come from the built-in list (not settings), its display name, origin, and
// auth kind, and that it is marked built-in.
func TestBuildCatalog_ChatGPTBuiltinMetadata(t *testing.T) {
	cat := BuildCatalog(nil, nil, nil)
	e := entryByID(t, cat, ChatGPTProviderID)
	if e.DisplayName != "OpenAI ChatGPT" {
		t.Errorf("openai-chatgpt DisplayName = %q, want %q", e.DisplayName, "OpenAI ChatGPT")
	}
	if e.AuthKind != AuthKindChatGPTSession {
		t.Errorf("openai-chatgpt AuthKind = %q, want %q", e.AuthKind, AuthKindChatGPTSession)
	}
	if e.Origin != OriginChatGPTCodex {
		t.Errorf("openai-chatgpt Origin = %q, want %q", e.Origin, OriginChatGPTCodex)
	}
	if !e.Builtin {
		t.Error("openai-chatgpt Builtin = false, want true")
	}
	wantModels := []string{"gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex-spark"}
	if !reflect.DeepEqual(e.Models, wantModels) {
		t.Errorf("openai-chatgpt Models = %v, want the built-in list", e.Models)
	}
	if contains(e.Models, "gpt-5.5-pro") {
		t.Errorf("openai-chatgpt Models = %v, must not include gpt-5.5-pro", e.Models)
	}
}

// TestBuildCatalog_DuplicateModelIDDisambiguatedByProvider pins that the same model
// id can appear under both openai and openai-chatgpt and remains addressable by
// provider id (Done-when 2).
func TestBuildCatalog_DuplicateModelIDDisambiguatedByProvider(t *testing.T) {
	cat := BuildCatalog(
		map[string]ProviderEntry{PlatformProviderID: {BaseURL: "https://api.openai.com/v1", APIKey: "sk-test"}},
		nil,
		map[string][]DiscoveredConfiguredModel{PlatformProviderID: discoveredIDModels("gpt-5.5")},
	)
	platform := entryByID(t, cat, PlatformProviderID)
	chatgpt := entryByID(t, cat, ChatGPTProviderID)
	if !contains(platform.Models, "gpt-5.5") {
		t.Error("openai catalog entry missing gpt-5.5")
	}
	if !contains(chatgpt.Models, "gpt-5.5") {
		t.Error("openai-chatgpt catalog entry missing gpt-5.5")
	}
	if platform.AuthKind == chatgpt.AuthKind {
		t.Errorf("openai and openai-chatgpt share AuthKind %q; they must stay distinct", platform.AuthKind)
	}
}

// TestBuildCatalog_ReservedIDNotReadFromSettings pins that a (defensively handled)
// configured provider.openai-chatgpt entry never supplies the built-in row's models
// or downgrades its auth kind — the built-in declaration wins, and settings models
// are ignored. In production settings loading rejects this entry; this guards the merge
// itself.
func TestBuildCatalog_ReservedIDNotReadFromSettings(t *testing.T) {
	cat := BuildCatalog(map[string]ProviderEntry{
		ChatGPTProviderID: configuredEntry(),
	}, nil, nil)
	e := entryByID(t, cat, ChatGPTProviderID)
	if contains(e.Models, "smuggled-model") {
		t.Errorf("openai-chatgpt Models = %v, must not read models from settings", e.Models)
	}
	// The built-in declaration wins wholesale: a smuggled configured entry cannot
	// downgrade the ChatGPT-session auth kind or its built-in/origin provenance, so
	// settings can never route a configured credential through the reserved id
	// (Done-when: a configured provider.openai-chatgpt never
	// supplies or downgrades ChatGPT credential routing).
	if e.AuthKind != AuthKindChatGPTSession {
		t.Errorf("openai-chatgpt AuthKind = %q, want %q (settings must not downgrade it)", e.AuthKind, AuthKindChatGPTSession)
	}
	if !e.Builtin {
		t.Error("openai-chatgpt Builtin = false, want true (the built-in row, not the configured entry, survives)")
	}
	if e.Origin != OriginChatGPTCodex {
		t.Errorf("openai-chatgpt Origin = %q, want %q", e.Origin, OriginChatGPTCodex)
	}
	// Entry() keys by id and would mask a duplicate: if BuildCatalog stopped
	// dropping the reserved configured row it would still be overwritten in byID
	// by the built-in, so Entry() keeps returning the built-in while Entries()
	// carries two openai-chatgpt rows. Assert catalog order holds exactly one
	// openai-chatgpt row and it is the built-in, so a configured/reserved row can
	// never reach the selectable order.
	var chatgpt []CatalogEntry
	for _, entry := range cat.Entries() {
		if entry.ID == ChatGPTProviderID {
			chatgpt = append(chatgpt, entry)
		}
	}
	if len(chatgpt) != 1 {
		t.Fatalf("Entries() has %d openai-chatgpt rows, want exactly 1 (configured reserved row must be dropped)", len(chatgpt))
	}
	if got := chatgpt[0]; !got.Builtin || got.AuthKind != AuthKindChatGPTSession ||
		got.Origin != OriginChatGPTCodex || contains(got.Models, "smuggled-model") {
		t.Errorf("sole openai-chatgpt row = %+v, want the built-in row (Builtin, AuthKindChatGPTSession, OriginChatGPTCodex, no smuggled-model)", got)
	}
}

// TestCatalog_EntryAndEntriesDefensiveCopy pins that mutating a returned entry's
// model slice does not change the catalog (mirrors the config cache isolation).
func TestCatalog_EntryAndEntriesDefensiveCopy(t *testing.T) {
	cat := BuildCatalog(
		map[string]ProviderEntry{PlatformProviderID: {BaseURL: "https://api.openai.com/v1", APIKey: "sk-test"}},
		nil,
		map[string][]DiscoveredConfiguredModel{PlatformProviderID: discoveredIDModels("gpt-5.5", "gpt-5.5-pro")},
	)

	e, _ := cat.Entry(PlatformProviderID)
	e.Models[0] = "tampered"
	if again := entryByID(t, cat, PlatformProviderID); again.Models[0] != "gpt-5.5" {
		t.Errorf("catalog entry mutated via Entry() return: Models[0] = %q", again.Models[0])
	}

	entries := cat.Entries()
	entries[0].Models[0] = "tampered"
	if again := entryByID(t, cat, PlatformProviderID); again.Models[0] != "gpt-5.5" {
		t.Errorf("catalog entry mutated via Entries() return: Models[0] = %q", again.Models[0])
	}
}

func TestCatalog_EntryUnknownProvider(t *testing.T) {
	cat := BuildCatalog(nil, nil, nil)
	if _, ok := cat.Entry("anthropic"); ok {
		t.Error("Entry(anthropic) reported present, want absent")
	}
}

func TestOpenAIChatGPT_BuiltinRetainsIdentityMetadata(t *testing.T) {
	b, ok := builtinSelectable[ChatGPTProviderID]
	if !ok {
		t.Fatalf("%q absent from builtinSelectable", ChatGPTProviderID)
	}
	if b.displayName != chatGPTDisplayName {
		t.Errorf("displayName = %q, want %q", b.displayName, chatGPTDisplayName)
	}
	if !reflect.DeepEqual(b.models, chatGPTSeed) {
		t.Errorf("models = %v, want the compiled seed %v", b.models, chatGPTSeed)
	}
	if b.authKind != AuthKindChatGPTSession {
		t.Errorf("authKind = %q, want %q", b.authKind, AuthKindChatGPTSession)
	}
	if b.origin != OriginChatGPTCodex {
		t.Errorf("origin = %q, want %q", b.origin, OriginChatGPTCodex)
	}
}

// TestResolvePlatformAPIKey pins the Platform API key precedence: a non-empty
// OPENAI_API_KEY wins over the configured key; an empty/unset env falls back to the
// configured key. The helper is Platform-only — the catalog gives
// the ChatGPT provider AuthKindChatGPTSession, which never calls it.
func TestResolvePlatformAPIKey(t *testing.T) {
	t.Run("env set wins", func(t *testing.T) {
		t.Setenv("OPENAI_API_KEY", "env-key")
		if got := ResolvePlatformAPIKey("configured-key"); got != "env-key" {
			t.Fatalf("ResolvePlatformAPIKey = %q, want env-key", got)
		}
	})
	t.Run("env empty falls back", func(t *testing.T) {
		t.Setenv("OPENAI_API_KEY", "")
		if got := ResolvePlatformAPIKey("configured-key"); got != "configured-key" {
			t.Fatalf("ResolvePlatformAPIKey = %q, want configured-key", got)
		}
	})
}

// chatGPTSeed is the compiled built-in ChatGPT model list — the offline/initial
// fallback that a discovered cache extends but never replaces.
var chatGPTSeed = []string{"gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex-spark"}

// chatGPTDiscovered builds neutral discovered ChatGPT records for the given slugs (no
// cached effort metadata), the shape config adapts out of the models.yaml store and
// hands BuildCatalog, so a test can exercise the merge path without the live discovery
// trigger or any on-disk file.
func chatGPTDiscovered(slugs ...string) []ChatGPTStoreModel {
	models := make([]ChatGPTStoreModel, 0, len(slugs))
	for _, s := range slugs {
		models = append(models, ChatGPTStoreModel{ID: s})
	}
	return models
}

// TestBuildCatalog_ChatGPTDiscoveredModelsSelectable pins that ids from the locally
// discovered records are merged into the built-in ChatGPT row — appended after the
// compiled seed, de-duplicated against it — and become selectable through the
// catalog, without changing the row's built-in provenance.
func TestBuildCatalog_ChatGPTDiscoveredModelsSelectable(t *testing.T) {
	// gpt-5.5 duplicates the seed and must not appear twice.
	cat := BuildCatalog(nil, chatGPTDiscovered("gpt-5.6", "gpt-5.5"), nil)
	e := entryByID(t, cat, ChatGPTProviderID)

	want := []string{"gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex-spark", "gpt-5.6"}
	if !reflect.DeepEqual(e.Models, want) {
		t.Fatalf("openai-chatgpt Models = %v, want seed then discovered %v", e.Models, want)
	}
	if !e.Builtin || e.AuthKind != AuthKindChatGPTSession || e.Origin != OriginChatGPTCodex {
		t.Errorf("discovered merge altered ChatGPT provenance: %+v", e)
	}
}

func TestBuildCatalog_ChatGPTDiscoveredNoReasoningOnly(t *testing.T) {
	cat := BuildCatalog(nil, chatGPTDiscovered("gpt-5.6"), nil)
	if e := entryByID(t, cat, ChatGPTProviderID); !contains(e.Models, "gpt-5.6") {
		t.Fatalf("discovered id gpt-5.6 not selectable: %v", e.Models)
	}
	want := []string{EffortNoReasoning}
	for _, id := range []string{"gpt-5.6", "gpt-5.5"} {
		if got := cat.SupportedEffort(ChatGPTProviderID, id); !reflect.DeepEqual(got, want) {
			t.Errorf("catalog SupportedEffort(%q) = %v, want %v", id, got, want)
		}
	}
}

// TestBuildCatalog_ChatGPTDiscoveredFallback pins that no discovered records (nil or an
// empty slice — what config passes for an absent or malformed store) leave exactly the
// compiled seed selectable: a read failure never empties the ChatGPT row.
func TestBuildCatalog_ChatGPTDiscoveredFallback(t *testing.T) {
	t.Run("nil discovered", func(t *testing.T) {
		e := entryByID(t, BuildCatalog(nil, nil, nil), ChatGPTProviderID)
		if !reflect.DeepEqual(e.Models, chatGPTSeed) {
			t.Fatalf("Models = %v, want compiled seed %v", e.Models, chatGPTSeed)
		}
	})
	t.Run("empty discovered", func(t *testing.T) {
		e := entryByID(t, BuildCatalog(nil, []ChatGPTStoreModel{}, nil), ChatGPTProviderID)
		if !reflect.DeepEqual(e.Models, chatGPTSeed) {
			t.Fatalf("Models = %v, want compiled seed %v", e.Models, chatGPTSeed)
		}
	})
}

// discoveredWithLevels builds one neutral discovered ChatGPT record with the given slug
// and cached reasoning levels stored under capabilities.supported_reasoning_levels — the
// shape config adapts out of the models.yaml store into BuildCatalog, an array of objects
// with the current "effort" member (e.g. [{"effort":"low"},{"effort":"high"}]).
func discoveredWithLevels(slug string, levels ...string) ChatGPTStoreModel {
	objs := make([]any, len(levels))
	for i, l := range levels {
		objs[i] = map[string]any{"effort": l}
	}
	return ChatGPTStoreModel{ID: slug, Capabilities: map[string]any{"supported_reasoning_levels": objs}}
}

// discoveredWithLegacyLevels builds the same record using the legacy "level" member that
// caches written before the writer switched keys still carry (e.g. [{"level":"low"}]).
func discoveredWithLegacyLevels(slug string, levels ...string) ChatGPTStoreModel {
	objs := make([]any, len(levels))
	for i, l := range levels {
		objs[i] = map[string]any{"level": l}
	}
	return ChatGPTStoreModel{ID: slug, Capabilities: map[string]any{"supported_reasoning_levels": objs}}
}

func TestChatGPTDiscoveredEffortsCatalogSelectable(t *testing.T) {
	cat := BuildCatalog(nil, []ChatGPTStoreModel{discoveredWithLevels("gpt-5.6", "max", "ultra", "default")}, nil)
	if e := entryByID(t, cat, ChatGPTProviderID); !contains(e.Models, "gpt-5.6") {
		t.Fatalf("discovered id gpt-5.6 not selectable: %v", e.Models)
	}
	want := []string{"max", "ultra", "default"}
	if got := cat.SupportedEffort(ChatGPTProviderID, "gpt-5.6"); !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog SupportedEffort(gpt-5.6) = %v, want advertised values in advertised order %v", got, want)
	}
}

func TestChatGPTDiscoveredEffortsPreserveOrderAndDedup(t *testing.T) {
	cat := BuildCatalog(nil, []ChatGPTStoreModel{
		discoveredWithLevels("gpt-5.6", "ultra", "low", "ultra", "minimal", "xhigh", "low"),
	}, nil)
	want := []string{"ultra", EffortLow, EffortMinimal, EffortXHigh}
	if got := cat.SupportedEffort(ChatGPTProviderID, "gpt-5.6"); !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog SupportedEffort(gpt-5.6) = %v, want deduped advertised order %v", got, want)
	}
}

func TestChatGPTDiscoveredEffortsFallback(t *testing.T) {
	assertNoReasoningOnly := func(t *testing.T, m ChatGPTStoreModel) {
		t.Helper()
		cat := BuildCatalog(nil, []ChatGPTStoreModel{m}, nil)
		if !contains(entryByID(t, cat, ChatGPTProviderID).Models, m.ID) {
			t.Fatalf("discovered id %s not selectable", m.ID)
		}
		if got := cat.SupportedEffort(ChatGPTProviderID, m.ID); !reflect.DeepEqual(got, []string{EffortNoReasoning}) {
			t.Fatalf("%s = %v, want no-reasoning only", m.ID, got)
		}
	}
	t.Run("absent metadata", func(t *testing.T) {
		assertNoReasoningOnly(t, ChatGPTStoreModel{ID: "gpt-5.6"})
	})
	t.Run("non-array metadata", func(t *testing.T) {
		assertNoReasoningOnly(t, ChatGPTStoreModel{ID: "gpt-5.6", Capabilities: map[string]any{"supported_reasoning_levels": map[string]any{"oops": true}}})
	})
	t.Run("object without effort or level member", func(t *testing.T) {
		assertNoReasoningOnly(t, ChatGPTStoreModel{ID: "gpt-5.6", Capabilities: map[string]any{"supported_reasoning_levels": []any{map[string]any{"description": "max"}}}})
	})
	t.Run("non-object array entry", func(t *testing.T) {
		assertNoReasoningOnly(t, ChatGPTStoreModel{ID: "gpt-5.6", Capabilities: map[string]any{"supported_reasoning_levels": []any{"low"}}})
	})
	t.Run("non-string effort", func(t *testing.T) {
		assertNoReasoningOnly(t, ChatGPTStoreModel{ID: "gpt-5.6", Capabilities: map[string]any{"supported_reasoning_levels": []any{map[string]any{"effort": 123}}}})
	})
	t.Run("blank effort", func(t *testing.T) {
		assertNoReasoningOnly(t, ChatGPTStoreModel{ID: "gpt-5.6", Capabilities: map[string]any{"supported_reasoning_levels": []any{map[string]any{"effort": "   "}}}})
	})
	t.Run("malformed effort token", func(t *testing.T) {
		assertNoReasoningOnly(t, ChatGPTStoreModel{ID: "gpt-5.6", Capabilities: map[string]any{"supported_reasoning_levels": []any{map[string]any{"effort": "very high"}}}})
	})
	t.Run("oversized effort token", func(t *testing.T) {
		blob := strings.Repeat("a", maxEffortOptionLength+1)
		assertNoReasoningOnly(t, ChatGPTStoreModel{ID: "gpt-5.6", Capabilities: map[string]any{"supported_reasoning_levels": []any{map[string]any{"effort": blob}}}})
	})
	t.Run("no cache", func(t *testing.T) {
		cat := BuildCatalog(nil, nil, nil)
		if got := cat.SupportedEffort(ChatGPTProviderID, "gpt-5.6"); !reflect.DeepEqual(got, []string{EffortNoReasoning}) {
			t.Fatalf("no-cache gpt-5.6 = %v, want no-reasoning only", got)
		}
	})
}

// TestChatGPTDiscoveredEffortsLegacyLevelKey pins that a cache written before the writer
// switched to the "effort" key — carrying the legacy "level" member — stays selectable
// with the same filtering, order, and de-duplication as the current shape.
func TestChatGPTDiscoveredEffortsLegacyLevelKey(t *testing.T) {
	cat := BuildCatalog(nil, []ChatGPTStoreModel{discoveredWithLegacyLevels("gpt-5.6", "low", "high", "low", "xhigh")}, nil)
	want := []string{EffortLow, EffortHigh, EffortXHigh}
	if got := cat.SupportedEffort(ChatGPTProviderID, "gpt-5.6"); !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy-key gpt-5.6 = %v, want deduped ordered %v", got, want)
	}
}

func TestChatGPTDiscoveredEffortsPreferEffortKey(t *testing.T) {
	cases := []struct {
		name  string
		entry map[string]any
		want  []string
	}{
		{"current wins", map[string]any{"effort": "high", "level": "low"}, []string{EffortHigh}},
		{"unknown current still wins", map[string]any{"effort": "max", "level": "high"}, []string{"max"}},
		{"blank current falls back", map[string]any{"effort": "", "level": "high"}, []string{EffortHigh}},
		{"non-string current falls back", map[string]any{"effort": 123, "level": "high"}, []string{EffortHigh}},
		{"malformed current falls back", map[string]any{"effort": "very high", "level": "ultra"}, []string{"ultra"}},
		{"both unusable drops", map[string]any{"effort": "very high", "level": ""}, []string{EffortNoReasoning}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := ChatGPTStoreModel{ID: "gpt-5.6", Capabilities: map[string]any{"supported_reasoning_levels": []any{tc.entry}}}
			cat := BuildCatalog(nil, []ChatGPTStoreModel{m}, nil)
			if got := cat.SupportedEffort(ChatGPTProviderID, "gpt-5.6"); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("mixed-key %q gpt-5.6 = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestChatGPTDiscoveredEffortsIgnoreUnrelatedCachedKeys(t *testing.T) {
	m := ChatGPTStoreModel{ID: "gpt-5.6", Capabilities: map[string]any{
		"description":             "unrelated cached text",
		"max_context_window":      float64(400000),
		"default_reasoning_level": "high",
		"supported_reasoning_levels": []any{
			map[string]any{"effort": "low", "description": "unrelated"},
			map[string]any{"level": "high"},
		},
	}}
	cat := BuildCatalog(nil, []ChatGPTStoreModel{m}, nil)
	want := []string{EffortLow, EffortHigh}
	if got := cat.SupportedEffort(ChatGPTProviderID, "gpt-5.6"); !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog SupportedEffort(gpt-5.6) = %v, want %v from the level members alone", got, want)
	}
}

func TestCatalogEffortIsCacheOnly(t *testing.T) {
	cat := BuildCatalog(nil, []ChatGPTStoreModel{discoveredWithLevels("gpt-5.5", "low")}, nil)
	if got := cat.SupportedEffort(ChatGPTProviderID, "gpt-5.5"); !reflect.DeepEqual(got, []string{EffortLow}) {
		t.Fatalf("seed gpt-5.5 catalog SupportedEffort = %v, want the cached [low] (nothing may widen it)", got)
	}

	uncached := BuildCatalog(nil, nil, nil)
	if got := uncached.SupportedEffort(ChatGPTProviderID, "gpt-5.5"); !reflect.DeepEqual(got, []string{EffortNoReasoning}) {
		t.Fatalf("uncached seed gpt-5.5 = %v, want no-reasoning only", got)
	}
	if got := uncached.SupportedEffort("openrouter", "openai/gpt-5.5"); !reflect.DeepEqual(got, []string{EffortNoReasoning}) {
		t.Fatalf("uncached adapter model = %v, want no-reasoning only", got)
	}
}

// discoveredIDModels wraps ids-only discovery records (no effort capabilities), the
// per-provider value of BuildCatalog's discoveredConfigured argument.
func discoveredIDModels(ids ...string) []DiscoveredConfiguredModel {
	out := make([]DiscoveredConfiguredModel, len(ids))
	for i, id := range ids {
		out[i] = DiscoveredConfiguredModel{ID: id}
	}
	return out
}

// veniceDiscovered builds one configured-provider discovered record carrying
// Venice-style reasoning-effort capabilities (supportsReasoningEffort + the given
// reasoningEffortOptions), the shape config adapts out of the models.yaml store into
// BuildCatalog. Options are []any to match the post-round-trip store shape.
func veniceDiscovered(id string, options ...string) DiscoveredConfiguredModel {
	opts := make([]any, len(options))
	for i, o := range options {
		opts[i] = o
	}
	return DiscoveredConfiguredModel{ID: id, Capabilities: map[string]any{
		configuredSupportsReasoningEffortCapKey: true,
		configuredReasoningEffortOptionsCapKey:  opts,
	}}
}

func TestBuildCatalog_ConfiguredDiscoveredEffortsCatalogSelectable(t *testing.T) {
	cat := BuildCatalog(
		map[string]ProviderEntry{"venice": {BaseURL: "https://api.venice.ai/api/v1", APIKey: "sk-test"}},
		nil,
		map[string][]DiscoveredConfiguredModel{"venice": {veniceDiscovered("claude-opus-4-8", "max", "ultra", "default")}},
	)
	if e := entryByID(t, cat, "venice"); !contains(e.Models, "claude-opus-4-8") {
		t.Fatalf("discovered venice id not selectable: %v", e.Models)
	}
	want := []string{"max", "ultra", "default"}
	if got := cat.SupportedEffort("venice", "claude-opus-4-8"); !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog SupportedEffort(venice, claude-opus-4-8) = %v, want advertised order %v", got, want)
	}
}

func TestBuildCatalog_ConfiguredDiscoveredEffortsPreserveOrderAndDedup(t *testing.T) {
	venice := map[string]ProviderEntry{"venice": {BaseURL: "https://api.venice.ai/api/v1", APIKey: "sk-test"}}
	cat := BuildCatalog(venice, nil,
		map[string][]DiscoveredConfiguredModel{"venice": {veniceDiscovered("claude-opus-4-8", "max", "low", "max", "high")}})
	want := []string{"max", EffortLow, EffortHigh}
	if got := cat.SupportedEffort("venice", "claude-opus-4-8"); !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog SupportedEffort = %v, want deduped advertised order %v", got, want)
	}
}

func TestBuildCatalog_ConfiguredDiscoveredEffortsFallback(t *testing.T) {
	venice := map[string]ProviderEntry{"venice": {BaseURL: "https://api.venice.ai/api/v1", APIKey: "sk-test"}}
	assertNoReasoningOnly := func(t *testing.T, m DiscoveredConfiguredModel) {
		t.Helper()
		cat := BuildCatalog(venice, nil, map[string][]DiscoveredConfiguredModel{"venice": {m}})
		if !contains(entryByID(t, cat, "venice").Models, m.ID) {
			t.Fatalf("discovered id %s not selectable", m.ID)
		}
		if got := cat.SupportedEffort("venice", m.ID); !reflect.DeepEqual(got, []string{EffortNoReasoning}) {
			t.Fatalf("%s = %v, want no-reasoning only", m.ID, got)
		}
	}
	t.Run("absent capabilities", func(t *testing.T) {
		assertNoReasoningOnly(t, DiscoveredConfiguredModel{ID: "m-absent"})
	})
	t.Run("supportsReasoningEffort false", func(t *testing.T) {
		assertNoReasoningOnly(t, DiscoveredConfiguredModel{ID: "m-unsupported", Capabilities: map[string]any{
			configuredSupportsReasoningEffortCapKey: false,
			configuredReasoningEffortOptionsCapKey:  []any{"low", "high"},
		}})
	})
	t.Run("non-array options", func(t *testing.T) {
		assertNoReasoningOnly(t, DiscoveredConfiguredModel{ID: "m-nonarray", Capabilities: map[string]any{
			configuredSupportsReasoningEffortCapKey: true,
			configuredReasoningEffortOptionsCapKey:  "low",
		}})
	})
	t.Run("non-string option elements", func(t *testing.T) {
		assertNoReasoningOnly(t, DiscoveredConfiguredModel{ID: "m-nonstring", Capabilities: map[string]any{
			configuredSupportsReasoningEffortCapKey: true,
			configuredReasoningEffortOptionsCapKey:  []any{123, true},
		}})
	})
	t.Run("blank and malformed options", func(t *testing.T) {
		assertNoReasoningOnly(t, DiscoveredConfiguredModel{ID: "m-blank", Capabilities: map[string]any{
			configuredSupportsReasoningEffortCapKey: true,
			configuredReasoningEffortOptionsCapKey:  []any{"", "   ", "very high"},
		}})
	})
	t.Run("oversized option", func(t *testing.T) {
		assertNoReasoningOnly(t, DiscoveredConfiguredModel{ID: "m-oversized", Capabilities: map[string]any{
			configuredSupportsReasoningEffortCapKey: true,
			configuredReasoningEffortOptionsCapKey:  []any{strings.Repeat("a", maxEffortOptionLength+1)},
		}})
	})
}

func TestBuildCatalog_ConfiguredDiscoveredIsOnlyEffortSource(t *testing.T) {
	openrouter := map[string]ProviderEntry{"openrouter": {BaseURL: "https://openrouter.ai/api/v1", APIKey: "sk-or-test"}}
	cat := BuildCatalog(openrouter, nil,
		map[string][]DiscoveredConfiguredModel{"openrouter": {veniceDiscovered("openai/gpt-5.5", "low")}})
	if got := cat.SupportedEffort("openrouter", "openai/gpt-5.5"); !reflect.DeepEqual(got, []string{EffortLow}) {
		t.Fatalf("catalog SupportedEffort = %v, want the cached [low]", got)
	}
	uncached := BuildCatalog(openrouter, nil,
		map[string][]DiscoveredConfiguredModel{"openrouter": discoveredIDModels("openai/gpt-5.5")})
	if got := uncached.SupportedEffort("openrouter", "openai/gpt-5.5"); !reflect.DeepEqual(got, []string{EffortNoReasoning}) {
		t.Fatalf("SupportedEffort without cached capability metadata = %v, want no-reasoning only", got)
	}
}

func TestBuildCatalog_RecordsOnlyExplicitToolUnsupportedResults(t *testing.T) {
	configured := map[string]ProviderEntry{
		"openrouter": {BaseURL: "https://openrouter.ai/api/v1", APIKey: "sk-or-test"},
		"venice":     {BaseURL: "https://api.venice.ai/api/v1", APIKey: "vk-test"},
	}
	cat := BuildCatalog(configured, []ChatGPTStoreModel{{ID: "gpt-5.5-codex"}}, map[string][]DiscoveredConfiguredModel{
		"openrouter": {
			{ID: "tencent/hy-mt2-30b-a3b", Capabilities: map[string]any{
				configuredSupportedParametersCapKey: []any{"max_tokens", "top_p"},
			}},
			{ID: "openai/gpt-5.5", Capabilities: map[string]any{
				configuredSupportedParametersCapKey: []any{"max_tokens", "tools"},
			}},
			{ID: "vendor/empty-params", Capabilities: map[string]any{
				configuredSupportedParametersEmptyCapKey: true,
			}},
			{ID: "vendor/legacy-record"},
		},
		"venice": {
			{ID: "venice-translate", Capabilities: map[string]any{configuredSupportsFunctionCallingCapKey: false}},
			{ID: "venice-uncensored", Capabilities: map[string]any{configuredSupportsFunctionCallingCapKey: true}},
		},
	})

	for _, tc := range []struct {
		providerID, modelID string
		want                bool
	}{
		{"openrouter", "tencent/hy-mt2-30b-a3b", false},
		{"openrouter", "openai/gpt-5.5", true},
		{"openrouter", "vendor/empty-params", false},
		{"openrouter", "vendor/legacy-record", true},
		{"venice", "venice-translate", false},
		{"venice", "venice-uncensored", true},
		{"openrouter", "never/discovered", true},
		{"groq", "tencent/hy-mt2-30b-a3b", true},
		{ChatGPTProviderID, "gpt-5.5-codex", true},
	} {
		if got := cat.SupportsTools(tc.providerID, tc.modelID); got != tc.want {
			t.Errorf("SupportsTools(%s, %s) = %v, want %v", tc.providerID, tc.modelID, got, tc.want)
		}
	}
}

func TestCatalog_SupportsToolsDefaultsTrueForAnEmptyCatalog(t *testing.T) {
	var cat Catalog
	if !cat.SupportsTools("openrouter", "tencent/hy-mt2-30b-a3b") {
		t.Error("zero-value catalog reports unsupported, want the supported default")
	}
	built := BuildCatalog(nil, nil, nil)
	if !built.SupportsTools("", "") {
		t.Error("empty catalog reports unsupported for an unknown provider/model, want supported")
	}
}
