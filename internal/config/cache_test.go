// Tests for the session-lifetime composed-config cache: accessors, defaults, in-memory write-backs, and copy isolation.
package config

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/testsupport"
)

// fullComposed returns a composed config exercising every accessor, shaped like
// real Compose output (string lists as []any, scalars present).
func fullComposed() map[string]any {
	return map[string]any{
		"discovery":          map[string]any{"boundary": "project-root"},
		"agent":              map[string]any{"max_concurrency": 7},
		"agent_instructions": map[string]any{"max_file_bytes": 4096},
		"sessions":           map[string]any{"retention_days": 90, "max_tool_output_bytes": 2048},
		"vcs":                map[string]any{"priority": []any{"hg", "git", "jj"}, "preferred": "hg"},
		"mode":               map[string]any{"default": "plan"},
		"attribution":        false,
		"provider": map[string]any{
			"openai": map[string]any{
				"base_url": "https://api.openai.com/v1",
				"api_key":  "sk-test",
			},
			// Reserved config under `provider`: must resolve as retry settings,
			// not as a selectable provider (Providers() stays length 1 below).
			"retry": map[string]any{
				"enabled":       false,
				"max_attempts":  int64(6),
				"base_delay_ms": int64(250),
				"max_delay_ms":  int64(4000),
			},
		},
		"permissions": []any{
			map[string]any{"kind": "direct", "subject": "ls", "path_scope": "/home/x", "grant_kind": "folder"},
			map[string]any{"kind": "tool", "subject": "Read", "path_scope": "*", "grant_kind": "global"},
		},
		"model": map[string]any{
			"active":    map[string]any{"provider": "openai", "model": "gpt-5.5"},
			"last_used": map[string]any{"provider": "openai", "model": "gpt-5.5-pro"},
		},
		"web_research": map[string]any{
			"enabled":         true,
			"api_key":         webResearchKeySentinel,
			"max_results":     int64(12),
			"timeout_seconds": int64(45),
		},
	}
}

const webResearchKeySentinel = "exa-secret-sentinel"

func newCacheOrFatal(t *testing.T, composed map[string]any, root string, layers []string) *Cache {
	t.Helper()
	c, err := NewCache(composed, root, layers)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	return c
}

func TestCacheAccessors(t *testing.T) {
	layers := []string{"/global/settings.yaml", "/proj/.codemeld/settings.yaml"}
	c := newCacheOrFatal(t, fullComposed(), "/proj", layers)

	if got := c.ProjectRoot(); got != "/proj" {
		t.Errorf("ProjectRoot() = %q, want /proj", got)
	}
	if got := c.LayerPaths(); !reflect.DeepEqual(got, layers) {
		t.Errorf("LayerPaths() = %v, want %v", got, layers)
	}
	if got := c.Discovery(); got != "project-root" {
		t.Errorf("Discovery() = %q, want project-root", got)
	}
	if got := c.AgentMaxConcurrency(); got != 7 {
		t.Errorf("AgentMaxConcurrency() = %d, want 7", got)
	}
	if got := c.AgentInstructionsMaxFileBytes(); got != 4096 {
		t.Errorf("AgentInstructionsMaxFileBytes() = %d, want 4096", got)
	}
	if got := c.RetentionDays(); got != 90 {
		t.Errorf("RetentionDays() = %d, want 90", got)
	}
	if got := c.MaxToolOutputBytes(); got != 2048 {
		t.Errorf("MaxToolOutputBytes() = %d, want 2048", got)
	}
	if got := c.VCSPriority(); !reflect.DeepEqual(got, []string{"hg", "git", "jj"}) {
		t.Errorf("VCSPriority() = %v, want [hg git jj]", got)
	}
	if got := c.VCSPreferred(); got != "hg" {
		t.Errorf("VCSPreferred() = %q, want hg", got)
	}
	if mode, configured := c.ModeDefault(); mode != "plan" || !configured {
		t.Errorf("ModeDefault() = (%q, %v), want (plan, true)", mode, configured)
	}
	if got := c.Attribution(); got {
		t.Errorf("Attribution() = %v, want false for an explicit opt-out", got)
	}

	openai, ok := c.Provider("openai")
	if !ok {
		t.Fatal("Provider(openai) not found")
	}
	if openai.BaseURL != "https://api.openai.com/v1" || openai.APIKey != "sk-test" {
		t.Errorf("Provider(openai) = %+v, unexpected base_url/api_key", openai)
	}
	if openai.AuthHeader == nil || openai.AuthHeader.Name != "Authorization" || openai.AuthHeader.Value != "Bearer {api_key}" {
		t.Errorf("Provider(openai).AuthHeader = %+v, want the Bearer default", openai.AuthHeader)
	}
	if _, ok := c.Provider("missing"); ok {
		t.Error("Provider(missing) reported present")
	}
	if got := c.Providers(); len(got) != 1 {
		t.Errorf("Providers() len = %d, want 1 (provider.retry is config, not a provider)", len(got))
	}
	if _, ok := c.Provider("retry"); ok {
		t.Error("Provider(retry) reported present; provider.retry must not be a selectable provider")
	}
	if got := c.ProviderRetry(); got != (RetrySettings{Enabled: false, MaxAttempts: 6, BaseDelayMs: 250, MaxDelayMs: 4000}) {
		t.Errorf("ProviderRetry() = %+v, want the configured override", got)
	}
	if got := c.WebResearch(); got != (WebResearchSettings{Enabled: true, MaxResults: 12, TimeoutSeconds: 45}) {
		t.Errorf("WebResearch() = %+v, want the configured values", got)
	}
	if got := c.WebResearchAPIKey(); got != webResearchKeySentinel {
		t.Errorf("WebResearchAPIKey() = %q, want the configured key", got)
	}
	if formatted := fmt.Sprintf("%+v", c.WebResearch()); strings.Contains(formatted, webResearchKeySentinel) {
		t.Errorf("WebResearch() formatted as %q, which discloses the api_key", formatted)
	}

	perms := c.Permissions()
	want := []permissions.PermissionEntry{
		{Kind: "direct", Subject: "ls", PathScope: "/home/x", GrantKind: "folder"},
		{Kind: "tool", Subject: "Read", PathScope: "*", GrantKind: "global"},
	}
	if !reflect.DeepEqual(perms, want) {
		t.Errorf("Permissions() = %+v, want %+v", perms, want)
	}

	active, ok := c.ModelActiveRaw()
	if !ok || !reflect.DeepEqual(active, map[string]any{"provider": "openai", "model": "gpt-5.5"}) {
		t.Errorf("ModelActiveRaw() = %v, %v", active, ok)
	}
	lastUsed, ok := c.ModelLastUsedRaw()
	if !ok || !reflect.DeepEqual(lastUsed, map[string]any{"provider": "openai", "model": "gpt-5.5-pro"}) {
		t.Errorf("ModelLastUsedRaw() = %v, %v", lastUsed, ok)
	}
}

func TestCacheDefaults(t *testing.T) {
	c := newCacheOrFatal(t, map[string]any{}, "/root", nil)

	if got := c.Discovery(); got != "launch-dir-only" {
		t.Errorf("Discovery() default = %q, want launch-dir-only", got)
	}
	if got := c.AgentMaxConcurrency(); got != 3 {
		t.Errorf("AgentMaxConcurrency() default = %d, want 3", got)
	}
	if got := c.AgentInstructionsMaxFileBytes(); got != 65536 {
		t.Errorf("AgentInstructionsMaxFileBytes() default = %d, want 65536", got)
	}
	if got := c.RetentionDays(); got != 30 {
		t.Errorf("RetentionDays() default = %d, want 30", got)
	}
	if got := c.MaxToolOutputBytes(); got != 65536 {
		t.Errorf("MaxToolOutputBytes() default = %d, want 65536", got)
	}
	if got := c.VCSPriority(); !reflect.DeepEqual(got, []string{"git", "hg", "jj"}) {
		t.Errorf("VCSPriority() default = %v, want [git hg jj]", got)
	}
	if got := c.VCSPreferred(); got != "" {
		t.Errorf("VCSPreferred() default = %q, want empty", got)
	}
	if mode, configured := c.ModeDefault(); mode != "build" || configured {
		t.Errorf("ModeDefault() default = (%q, %v), want (build, false)", mode, configured)
	}
	if got := c.Attribution(); !got {
		t.Errorf("Attribution() default = %v, want true for an absent key", got)
	}
	if got := c.Providers(); len(got) != 0 {
		t.Errorf("Providers() default len = %d, want 0", len(got))
	}
	if got := c.ProviderRetry(); got != (RetrySettings{Enabled: true, MaxAttempts: 4, BaseDelayMs: 500, MaxDelayMs: 8000}) {
		t.Errorf("ProviderRetry() defaults = %+v, want adr-021 on/4/500/8000", got)
	}
	if got := c.WebResearch(); got != (WebResearchSettings{Enabled: true, MaxResults: 6, TimeoutSeconds: 20}) {
		t.Errorf("WebResearch() defaults = %+v, want on/6/20", got)
	}
	if got := c.WebResearchAPIKey(); got != "" {
		t.Errorf("WebResearchAPIKey() default = %q, want empty", got)
	}
	if got := c.Permissions(); len(got) != 0 {
		t.Errorf("Permissions() default len = %d, want 0", len(got))
	}
	if v, ok := c.ModelActiveRaw(); ok || v != nil {
		t.Errorf("ModelActiveRaw() default = %v, %v, want nil, false", v, ok)
	}
	if v, ok := c.ModelLastUsedRaw(); ok || v != nil {
		t.Errorf("ModelLastUsedRaw() default = %v, %v, want nil, false", v, ok)
	}
}

func TestCacheRejectsMaxToolOutputBytesBelowMinimum(t *testing.T) {
	_, err := NewCache(map[string]any{
		"sessions": map[string]any{"max_tool_output_bytes": 255},
	}, "/root", nil)
	if err == nil {
		t.Fatal("NewCache() = nil error, want sessions.max_tool_output_bytes minimum error")
	}
	if !strings.Contains(err.Error(), "sessions.max_tool_output_bytes must be >= 256") {
		t.Fatalf("error = %q, want minimum message", err.Error())
	}
}

func TestCacheRejectsRetentionDaysBelowOne(t *testing.T) {
	for _, v := range []any{0, -1, 0.5} {
		_, err := NewCache(map[string]any{
			"sessions": map[string]any{"retention_days": v},
		}, "/root", nil)
		if err == nil || !strings.Contains(err.Error(), "sessions.retention_days must be >= 1") {
			t.Errorf("NewCache(retention_days=%v) error = %v, want minimum error", v, err)
		}
	}
}

func TestCacheRetentionDaysAtMinimumAndDefault(t *testing.T) {
	c := newCacheOrFatal(t, map[string]any{
		"sessions": map[string]any{"retention_days": 1},
	}, "/root", nil)
	if got := c.RetentionDays(); got != 1 {
		t.Errorf("RetentionDays() = %d, want 1", got)
	}
	c = newCacheOrFatal(t, map[string]any{}, "/root", nil)
	if got := c.RetentionDays(); got != defaultRetentionDays {
		t.Errorf("RetentionDays() default = %d, want %d", got, defaultRetentionDays)
	}
}

func TestCacheAcceptsMaxToolOutputBytesAtMinimum(t *testing.T) {
	c := newCacheOrFatal(t, map[string]any{
		"sessions": map[string]any{"max_tool_output_bytes": 256},
	}, "/root", nil)
	if got := c.MaxToolOutputBytes(); got != 256 {
		t.Errorf("MaxToolOutputBytes() = %d, want 256", got)
	}
}

// TestCacheModeDefault covers mode.default resolution and its source
// classification: each configured mode value resolves as configured=true (recorded
// as source "config"), an absent or non-string value falls back to "build" with
// configured=false (recorded as source "default"), and a project-layer value present
// in the composed map is honored (the cache resolves from the post-Compose result).
func TestCacheModeDefault(t *testing.T) {
	cases := []struct {
		name           string
		composed       map[string]any
		wantMode       string
		wantConfigured bool
	}{
		{"absent", map[string]any{}, "build", false},
		{"absent mode object", map[string]any{"mode": map[string]any{}}, "build", false},
		{"configured plan", map[string]any{"mode": map[string]any{"default": "plan"}}, "plan", true},
		{"configured build", map[string]any{"mode": map[string]any{"default": "build"}}, "build", true},
		{"configured auto_edits", map[string]any{"mode": map[string]any{"default": "auto_edits"}}, "auto_edits", true},
		{"non-string falls back", map[string]any{"mode": map[string]any{"default": 5}}, "build", false},
		// A composed map already carrying the project layer's value (Compose put it
		// here) resolves as configured, so a project override flows through.
		{"project-layer override", map[string]any{"mode": map[string]any{"default": "auto_edits"}}, "auto_edits", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCacheOrFatal(t, tc.composed, "/r", nil)
			mode, configured := c.ModeDefault()
			if mode != tc.wantMode || configured != tc.wantConfigured {
				t.Errorf("ModeDefault() = (%q, %v), want (%q, %v)", mode, configured, tc.wantMode, tc.wantConfigured)
			}
		})
	}
}

func TestCacheWebResearch(t *testing.T) {
	cases := []struct {
		name     string
		composed map[string]any
		want     WebResearchSettings
		wantKey  string
	}{
		{"absent block", map[string]any{}, WebResearchSettings{Enabled: true, MaxResults: 6, TimeoutSeconds: 20}, ""},
		{"empty block", map[string]any{"web_research": map[string]any{}}, WebResearchSettings{Enabled: true, MaxResults: 6, TimeoutSeconds: 20}, ""},
		{
			"enabled only",
			map[string]any{"web_research": map[string]any{"enabled": true}},
			WebResearchSettings{Enabled: true, MaxResults: 6, TimeoutSeconds: 20},
			"",
		},
		{
			"key only leaves the defaults alone",
			map[string]any{"web_research": map[string]any{"api_key": webResearchKeySentinel}},
			WebResearchSettings{Enabled: true, MaxResults: 6, TimeoutSeconds: 20},
			webResearchKeySentinel,
		},
		{
			"range endpoints honored",
			map[string]any{"web_research": map[string]any{"max_results": uint64(25), "timeout_seconds": float64(1)}},
			WebResearchSettings{Enabled: true, MaxResults: 25, TimeoutSeconds: 1},
			"",
		},
		{
			"explicitly disabled",
			map[string]any{"web_research": map[string]any{"enabled": false, "max_results": 5}},
			WebResearchSettings{MaxResults: 5, TimeoutSeconds: 20},
			"",
		},
		{
			"non-map block",
			map[string]any{"web_research": "on"},
			WebResearchSettings{Enabled: true, MaxResults: 6, TimeoutSeconds: 20},
			"",
		},
		{
			"wrong-typed values fall back",
			map[string]any{"web_research": map[string]any{"enabled": "true", "api_key": 7, "max_results": "12"}},
			WebResearchSettings{Enabled: true, MaxResults: 6, TimeoutSeconds: 20},
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCacheOrFatal(t, tc.composed, "/r", nil)
			if got := c.WebResearch(); got != tc.want {
				t.Errorf("WebResearch() = %+v, want %+v", got, tc.want)
			}
			if got := c.WebResearchAPIKey(); got != tc.wantKey {
				t.Errorf("WebResearchAPIKey() = %q, want %q", got, tc.wantKey)
			}
		})
	}
}

// TestCacheIntCoercion confirms integer accessors accept every numeric kind a
// decoded or constructed config can carry (keys are integers).
func TestCacheIntCoercion(t *testing.T) {
	for _, tc := range []struct {
		name string
		val  any
	}{
		{"int", int(11)},
		{"int64", int64(11)},
		{"uint64", uint64(11)},
		{"float64", float64(11)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCacheOrFatal(t, map[string]any{"agent": map[string]any{"max_concurrency": tc.val}}, "/r", nil)
			if got := c.AgentMaxConcurrency(); got != 11 {
				t.Errorf("AgentMaxConcurrency() = %d, want 11", got)
			}
		})
	}
}

func TestCacheAppendPermissionVisible(t *testing.T) {
	c := newCacheOrFatal(t, map[string]any{}, "/r", nil)

	// a session grant the on-disk parser would reject is stored directly.
	session := permissions.PermissionEntry{Kind: "direct", Subject: "rm", PathScope: "/tmp", GrantKind: "session"}
	c.AppendPermission(session)

	perms := c.Permissions()
	if len(perms) != 1 || perms[0] != session {
		t.Fatalf("Permissions() after append = %+v, want [%+v]", perms, session)
	}
}

// TestCacheRemovePermission covers the in-memory revoke half: a matching grant is
// dropped and reported true, a non-matching remove is a no-op reported false, and a
// slice handed out before the removal is unaffected (Permissions clones, so callers
// keep their snapshot).
func TestCacheRemovePermission(t *testing.T) {
	c := newCacheOrFatal(t, map[string]any{}, "/r", nil)

	ls := permissions.PermissionEntry{Kind: "direct", Subject: "ls", PathScope: "*", GrantKind: "global"}
	pwd := permissions.PermissionEntry{Kind: "direct", Subject: "pwd", PathScope: "*", GrantKind: "global"}
	session := permissions.PermissionEntry{Kind: "direct", Subject: "rm", PathScope: "/tmp", GrantKind: "session"}
	c.AppendPermission(ls)
	c.AppendPermission(pwd)
	c.AppendPermission(session)

	// A snapshot taken before removal must stay intact afterward.
	before := c.Permissions()

	if !c.RemovePermission(pwd) {
		t.Fatalf("RemovePermission(pwd) = false, want true for a grant the table holds")
	}
	got := c.Permissions()
	if len(got) != 2 || got[0] != ls || got[1] != session {
		t.Fatalf("after removing pwd, Permissions() = %+v, want [%+v %+v]", got, ls, session)
	}
	if len(before) != 3 || before[1] != pwd {
		t.Fatalf("pre-removal snapshot was mutated: %+v", before)
	}

	// Removing a grant that is not present is a no-op, and says so.
	if c.RemovePermission(permissions.PermissionEntry{Kind: "direct", Subject: "absent", PathScope: "*", GrantKind: "global"}) {
		t.Fatalf("RemovePermission(absent) = true, want false when nothing matched")
	}
	if got := c.Permissions(); len(got) != 2 {
		t.Fatalf("no-op remove changed the list: %+v", got)
	}

	// A repeat of an already-removed grant is the duplicate-request case: false, list unchanged.
	if c.RemovePermission(pwd) {
		t.Fatalf("second RemovePermission(pwd) = true, want false — the grant was already gone")
	}
	if got := c.Permissions(); len(got) != 2 || got[0] != ls || got[1] != session {
		t.Fatalf("duplicate remove changed the list: %+v", got)
	}

	// A session grant (matched by its grant_kind in the DedupKey) is removable.
	if !c.RemovePermission(session) {
		t.Fatalf("RemovePermission(session) = false, want true for a session grant the table holds")
	}
	if got := c.Permissions(); len(got) != 1 || got[0] != ls {
		t.Fatalf("after removing session grant, Permissions() = %+v, want [%+v]", got, ls)
	}
}

func TestCacheModelRawUpdatesVisible(t *testing.T) {
	c := newCacheOrFatal(t, fullComposed(), "/r", nil)

	c.SetModelActiveRaw(map[string]any{"provider": "openrouter", "model": "anthropic/claude-opus-4.7"})
	c.SetModelLastUsedRaw("gpt-5.5-pro")

	active, ok := c.ModelActiveRaw()
	if !ok || !reflect.DeepEqual(active, map[string]any{"provider": "openrouter", "model": "anthropic/claude-opus-4.7"}) {
		t.Errorf("ModelActiveRaw() after set = %v, %v", active, ok)
	}
	lastUsed, ok := c.ModelLastUsedRaw()
	if !ok || lastUsed != "gpt-5.5-pro" {
		t.Errorf("ModelLastUsedRaw() after set = %v, %v", lastUsed, ok)
	}
}

// TestCacheExternalEditsInvisible covers the Non-Goals guarantee that
// mutating the source config after construction does not change the session view
// (there is no reload path in phase 1).
func TestCacheExternalEditsInvisible(t *testing.T) {
	composed := fullComposed()
	layers := []string{"/global/settings.yaml"}
	c := newCacheOrFatal(t, composed, "/proj", layers)

	composed["agent"].(map[string]any)["max_concurrency"] = 99
	composed["vcs"].(map[string]any)["priority"] = []any{"jj"}
	composed["vcs"].(map[string]any)["preferred"] = "git"
	composed["model"].(map[string]any)["active"].(map[string]any)["model"] = "tampered"
	composed["provider"].(map[string]any)["openai"].(map[string]any)["api_key"] = "leaked"
	composed["web_research"].(map[string]any)["enabled"] = false
	composed["web_research"].(map[string]any)["max_results"] = int64(25)
	composed["web_research"].(map[string]any)["timeout_seconds"] = int64(120)
	composed["web_research"].(map[string]any)["api_key"] = "rotated"
	composed["permissions"] = append(composed["permissions"].([]any),
		map[string]any{"kind": "tool", "subject": "Write", "path_scope": "*", "grant_kind": "global"})
	layers[0] = "/tampered"

	if got := c.AgentMaxConcurrency(); got != 7 {
		t.Errorf("AgentMaxConcurrency() = %d, want 7 (source edit leaked)", got)
	}
	if got := c.VCSPriority(); !reflect.DeepEqual(got, []string{"hg", "git", "jj"}) {
		t.Errorf("VCSPriority() = %v (source edit leaked)", got)
	}
	if got := c.VCSPreferred(); got != "hg" {
		t.Errorf("VCSPreferred() = %q (source edit leaked)", got)
	}
	if openai, _ := c.Provider("openai"); openai.APIKey != "sk-test" {
		t.Errorf("Provider(openai).APIKey = %q (source edit leaked)", openai.APIKey)
	}
	if active, _ := c.ModelActiveRaw(); !reflect.DeepEqual(active, map[string]any{"provider": "openai", "model": "gpt-5.5"}) {
		t.Errorf("ModelActiveRaw() = %v (source edit leaked)", active)
	}
	if got := c.Permissions(); len(got) != 2 {
		t.Errorf("Permissions() len = %d, want 2 (source edit leaked)", len(got))
	}
	if got := c.LayerPaths(); got[0] != "/global/settings.yaml" {
		t.Errorf("LayerPaths()[0] = %q (source edit leaked)", got[0])
	}
	if got := c.WebResearch(); got != (WebResearchSettings{Enabled: true, MaxResults: 12, TimeoutSeconds: 45}) {
		t.Errorf("WebResearch() = %+v (source edit leaked)", got)
	}
	if got := c.WebResearchAPIKey(); got != webResearchKeySentinel {
		t.Errorf("WebResearchAPIKey() = %q (source edit leaked)", got)
	}
}

func resolvedTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return dir
}

func writableCache(t *testing.T, composed map[string]any, projectRoot string, home ...string) (*Cache, string) {
	t.Helper()
	var c *Cache
	var err error
	out := testsupport.CaptureStderr(t, func() { c, err = NewCache(composed, projectRoot, nil, home...) })
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	return c, out
}

func TestNewCache_WritableFoldersGlobalOnlyHasNoEffect(t *testing.T) {
	composed, err := Compose(map[string]any{writableFoldersKey: []any{resolvedTempDir(t)}}, nil)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	c, out := writableCache(t, composed, "", resolvedTempDir(t))
	if len(c.writableFolders) != 0 || out != "" {
		t.Fatalf("writableFolders = %q, stderr = %q; want none", c.writableFolders, out)
	}
}

func TestNewCache_WritableFoldersResolvedInOrder(t *testing.T) {
	first, second := resolvedTempDir(t), resolvedTempDir(t)
	composed, err := Compose(nil, map[string]any{writableFoldersKey: []any{second, first}})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	c, out := writableCache(t, composed, resolvedTempDir(t), resolvedTempDir(t))
	if !reflect.DeepEqual(c.writableFolders, []string{second, first}) || out != "" {
		t.Fatalf("writableFolders = %q, stderr = %q; want %q in order", c.writableFolders, out, []string{second, first})
	}
}

func TestNewCache_WritableFoldersProjectFloorNoticed(t *testing.T) {
	projectRoot := resolvedTempDir(t)
	floor := filepath.Join(projectRoot, ".codemeld")
	if err := os.MkdirAll(floor, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	composed, err := Compose(nil, map[string]any{writableFoldersKey: []any{floor}})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	c, out := writableCache(t, composed, projectRoot, resolvedTempDir(t))
	if len(c.writableFolders) != 0 {
		t.Fatalf("writableFolders = %q, want the project floor excluded", c.writableFolders)
	}
	line := strings.TrimSpace(out)
	if !strings.Contains(line, "codemeld: writable_folders") || !strings.Contains(line, floor) || strings.Count(line, "writable_folders:") != 1 || strings.Count(line, "\n") != 0 {
		t.Fatalf("stderr = %q, want one notice naming %q with the key once", out, floor)
	}
}

func TestNewCache_WritableFoldersAbsentNeedsNoHome(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "missing"))
	composed, err := Compose(map[string]any{"agent": map[string]any{"max_concurrency": 1}}, nil)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	c, out := writableCache(t, composed, "")
	if len(c.writableFolders) != 0 || strings.Contains(out, "writable_folders") {
		t.Fatalf("writableFolders = %q, stderr = %q; want none and no notice", c.writableFolders, out)
	}
}

func TestNewCache_WritableFoldersUseOnlyTheSuppliedHome(t *testing.T) {
	home, ambient := resolvedTempDir(t), resolvedTempDir(t)
	for _, h := range []string{home, ambient} {
		if err := os.MkdirAll(filepath.Join(h, "w"), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(h, ".codemeld"), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	t.Setenv("HOME", ambient)
	composed, err := Compose(nil, map[string]any{writableFoldersKey: []any{"~/w", "~/", "~/.codemeld", "relative"}})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	for _, omitted := range [][]string{nil, {""}} {
		c, out := writableCache(t, composed, "/proj", omitted...)
		if len(c.writableFolders) != 0 || strings.Contains(out, "writable_folders") {
			t.Fatalf("home %q: writableFolders = %q, stderr = %q; want none and no notice", omitted, c.writableFolders, out)
		}
	}

	c, out := writableCache(t, composed, "/proj", home)
	if want := []string{filepath.Join(home, "w"), home}; !reflect.DeepEqual(c.writableFolders, want) {
		t.Fatalf("writableFolders = %q, want only the supplied home's %q", c.writableFolders, want)
	}
	if strings.Count(out, "codemeld: writable_folders:") != 3 || !strings.Contains(out, `"~/": confined Auto commands`) ||
		!strings.Contains(out, filepath.Join(home, ".codemeld")) || !strings.Contains(out, `"relative": must be an absolute path`) || strings.Contains(out, ambient) {
		t.Fatalf("stderr = %q, want the home-impact, protected-path and malformed-entry notices for the supplied home and the ambient home never", out)
	}
}

func TestCache_LaunchHomeIsOnlyTheSuppliedHome(t *testing.T) {
	home := resolvedTempDir(t)
	t.Setenv("HOME", resolvedTempDir(t))
	for _, tc := range []struct {
		supplied []string
		want     string
	}{{nil, ""}, {[]string{""}, ""}, {[]string{home}, home}} {
		c, _ := writableCache(t, map[string]any{}, "/proj", tc.supplied...)
		if got := c.LaunchHome(); got != tc.want {
			t.Fatalf("supplied %q: LaunchHome() = %q, want %q", tc.supplied, got, tc.want)
		}
	}
}

func TestNewCache_WritableFoldersMalformedListDiscarded(t *testing.T) {
	for _, raw := range []any{"/data/x", []any{"/data/x", 3}} {
		c, out := writableCache(t, map[string]any{writableFoldersKey: raw}, "/proj", resolvedTempDir(t))
		if len(c.writableFolders) != 0 || strings.Count(out, "codemeld: writable_folders:") != 1 {
			t.Fatalf("%#v: writableFolders = %q, stderr = %q; want none and one key-prefixed notice", raw, c.writableFolders, out)
		}
	}
}

func TestNewCache_WritableFoldersFrozenAtConstruction(t *testing.T) {
	home, before, after := resolvedTempDir(t), resolvedTempDir(t), resolvedTempDir(t)
	projectRoot := resolvedTempDir(t)
	settings := filepath.Join(projectRoot, "settings.yaml")
	build := func() *Cache {
		t.Helper()
		_, raw, cat, err := LoadYAML(settings)
		if cat != LoadOK || err != nil {
			t.Fatalf("LoadYAML cat = %q, err = %v", cat, err)
		}
		composed, err := Compose(nil, raw)
		if err != nil {
			t.Fatalf("Compose: %v", err)
		}
		c, _ := writableCache(t, composed, projectRoot, home)
		return c
	}
	write := func(folder string) {
		t.Helper()
		if err := os.WriteFile(settings, []byte("writable_folders: [\""+folder+"\"]\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	write(before)
	c := build()
	write(after)
	if !reflect.DeepEqual(c.writableFolders, []string{before}) {
		t.Fatalf("writableFolders = %q after an edit, want the launch value %q", c.writableFolders, before)
	}
	if got := build().writableFolders; !reflect.DeepEqual(got, []string{after}) {
		t.Fatalf("new cache writableFolders = %q, want the edited %q", got, after)
	}
}

func TestNewCache_DeclaredCommandsAbsent(t *testing.T) {
	c := newCacheOrFatal(t, map[string]any{}, "/proj", nil)
	if got := c.DeclaredCommands(); len(got) != 0 {
		t.Fatalf("DeclaredCommands() = %v, want none for a composed config with no key", got)
	}
}

func TestNewCache_DeclaredCommandsAccepted(t *testing.T) {
	composed := map[string]any{"declared_commands": []any{"prep-open-tasks.sh --only", "sed -n"}}
	var c *Cache
	out := testsupport.CaptureStderr(t, func() { c = newCacheOrFatal(t, composed, "/proj", nil) })
	if out != "" {
		t.Fatalf("stderr = %q, want no notices for two accepted entries", out)
	}
	got := c.DeclaredCommands()
	want := []permissions.DeclaredCommand{{Subject: "prep-open-tasks.sh --only :*"}, {Subject: "sed -n :*"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DeclaredCommands() = %+v, want %+v", got, want)
	}
}

func TestNewCache_DeclaredCommandsRejectedEntryNoticedNotFatal(t *testing.T) {
	composed := map[string]any{"declared_commands": []any{"rm", "ls"}}
	var c *Cache
	out := testsupport.CaptureStderr(t, func() { c = newCacheOrFatal(t, composed, "/proj", nil) })
	if !strings.Contains(out, "declared_commands.0") {
		t.Fatalf("stderr = %q, want a notice naming the rejected bare rm entry", out)
	}
	got := c.DeclaredCommands()
	if len(got) != 1 || got[0].Subject != "ls :*" {
		t.Fatalf("DeclaredCommands() = %+v, want only the accepted ls entry", got)
	}
}

// An untrusted project contributes no settings layer at all, so the trust boundary is proved
// through ordinary composition rather than a code path of its own.
func TestNewCache_DeclaredCommandsUntrustedProjectHasNoEffect(t *testing.T) {
	global := map[string]any{"agent": map[string]any{"max_concurrency": 1}}

	untrusted, err := Compose(global, nil)
	if err != nil {
		t.Fatalf("Compose() error = %v", err)
	}
	c := newCacheOrFatal(t, untrusted, "/proj", nil)
	if got := c.DeclaredCommands(); len(got) != 0 {
		t.Fatalf("DeclaredCommands() = %v, want none: an untrusted project's list must never surface", got)
	}

	trusted, err := Compose(global, map[string]any{"declared_commands": []any{"prep-open-tasks.sh --only"}})
	if err != nil {
		t.Fatalf("Compose() error = %v", err)
	}
	c2 := newCacheOrFatal(t, trusted, "/proj", nil)
	if got := c2.DeclaredCommands(); len(got) != 1 || got[0].Subject != "prep-open-tasks.sh --only :*" {
		t.Fatalf("DeclaredCommands() = %+v, want the one trusted-project entry", got)
	}
}

func TestNewCache_DeclaredCommandsReturnedSliceCannotMutate(t *testing.T) {
	c := newCacheOrFatal(t, map[string]any{"declared_commands": []any{"ls"}}, "/proj", nil)
	c.DeclaredCommands()[0].Subject = "x"
	if got := c.DeclaredCommands()[0].Subject; got != "ls :*" {
		t.Fatalf("DeclaredCommands()[0].Subject mutated to %q", got)
	}
}

// TestCacheReturnedValuesCannotMutate covers the guarantee that mutating
// any returned slice or map leaves the cached session view unchanged.
func TestCacheReturnedValuesCannotMutate(t *testing.T) {
	c := newCacheOrFatal(t, fullComposed(), "/proj", []string{"/a", "/b"})

	c.LayerPaths()[0] = "x"
	c.VCSPriority()[0] = "x"
	c.Permissions()[0].Subject = "x"

	provs := c.Providers()
	if e, ok := provs["openai"]; ok {
		e.AuthHeader.Name = "x"
		provs["openai"] = e
	}
	delete(provs, "openai")
	if e, ok := c.Provider("openai"); ok {
		e.AuthHeader.Name = "x"
	}
	if active, _ := c.ModelActiveRaw(); active != nil {
		active.(map[string]any)["model"] = "x"
	}

	if got := c.LayerPaths(); !reflect.DeepEqual(got, []string{"/a", "/b"}) {
		t.Errorf("LayerPaths() mutated to %v", got)
	}
	if got := c.VCSPriority(); !reflect.DeepEqual(got, []string{"hg", "git", "jj"}) {
		t.Errorf("VCSPriority() mutated to %v", got)
	}
	if got := c.Permissions()[0].Subject; got != "ls" {
		t.Errorf("Permissions()[0].Subject mutated to %q", got)
	}
	if _, ok := c.Provider("openai"); !ok {
		t.Error("Providers() map mutation removed cached openai entry")
	}
	if e, _ := c.Provider("openai"); e.AuthHeader.Name != "Authorization" || e.APIKey != "sk-test" {
		t.Errorf("Provider(openai) mutated: AuthHeader.Name=%q APIKey=%q", e.AuthHeader.Name, e.APIKey)
	}
	if active, _ := c.ModelActiveRaw(); !reflect.DeepEqual(active, map[string]any{"provider": "openai", "model": "gpt-5.5"}) {
		t.Errorf("ModelActiveRaw() mutated to %v", active)
	}
}

func TestCacheNativeShapesCannotAlias(t *testing.T) {
	t.Run("native raw model setter input", func(t *testing.T) {
		c := newCacheOrFatal(t, map[string]any{}, "/r", nil)

		activeSlice := []string{"openai", "gpt-5.5"}
		lastUsedMap := map[string]string{"provider": "openai", "model": "gpt-5.5-pro"}
		c.SetModelActiveRaw(activeSlice)
		c.SetModelLastUsedRaw(lastUsedMap)

		// Mutating the caller-owned inputs after setting must not leak in.
		activeSlice[0] = "tampered"
		lastUsedMap["provider"] = "tampered"

		if active, _ := c.ModelActiveRaw(); !reflect.DeepEqual(active, []string{"openai", "gpt-5.5"}) {
			t.Errorf("ModelActiveRaw() = %v (native setter input leaked)", active)
		}
		if lastUsed, _ := c.ModelLastUsedRaw(); !reflect.DeepEqual(lastUsed, map[string]string{"provider": "openai", "model": "gpt-5.5-pro"}) {
			t.Errorf("ModelLastUsedRaw() = %v (native setter input leaked)", lastUsed)
		}
	})

	t.Run("native raw model accessor return values", func(t *testing.T) {
		c := newCacheOrFatal(t, map[string]any{}, "/r", nil)
		c.SetModelActiveRaw([]string{"openai", "gpt-5.5"})
		c.SetModelLastUsedRaw(map[string]string{"provider": "openai", "model": "gpt-5.5-pro"})

		// Mutating returned values must not change the cached session view.
		if active, _ := c.ModelActiveRaw(); active != nil {
			active.([]string)[0] = "tampered"
		}
		if lastUsed, _ := c.ModelLastUsedRaw(); lastUsed != nil {
			lastUsed.(map[string]string)["provider"] = "tampered"
		}

		if active, _ := c.ModelActiveRaw(); !reflect.DeepEqual(active, []string{"openai", "gpt-5.5"}) {
			t.Errorf("ModelActiveRaw() mutated to %v", active)
		}
		if lastUsed, _ := c.ModelLastUsedRaw(); !reflect.DeepEqual(lastUsed, map[string]string{"provider": "openai", "model": "gpt-5.5-pro"}) {
			t.Errorf("ModelLastUsedRaw() mutated to %v", lastUsed)
		}
	})

	t.Run("nested native map/slice raw shapes", func(t *testing.T) {
		c := newCacheOrFatal(t, map[string]any{}, "/r", nil)

		// Shapes deepCopyValue has no concrete fast path for: a map whose values
		// are slices, and a slice of maps. Both must be copied recursively.
		activeMap := map[string][]string{"provider": {"openai"}}
		lastUsedSlice := []map[string]string{{"provider": "openai"}}
		c.SetModelActiveRaw(activeMap)
		c.SetModelLastUsedRaw(lastUsedSlice)

		// Mutating the caller-owned nested inputs after setting must not leak in.
		activeMap["provider"][0] = "tampered"
		lastUsedSlice[0]["provider"] = "tampered"

		if active, _ := c.ModelActiveRaw(); !reflect.DeepEqual(active, map[string][]string{"provider": {"openai"}}) {
			t.Errorf("ModelActiveRaw() = %v (nested native setter input leaked)", active)
		}
		if lastUsed, _ := c.ModelLastUsedRaw(); !reflect.DeepEqual(lastUsed, []map[string]string{{"provider": "openai"}}) {
			t.Errorf("ModelLastUsedRaw() = %v (nested native setter input leaked)", lastUsed)
		}

		// Mutating the returned nested values must not change the cached view.
		if active, _ := c.ModelActiveRaw(); active != nil {
			active.(map[string][]string)["provider"][0] = "tampered"
		}
		if lastUsed, _ := c.ModelLastUsedRaw(); lastUsed != nil {
			lastUsed.([]map[string]string)[0]["provider"] = "tampered"
		}

		if active, _ := c.ModelActiveRaw(); !reflect.DeepEqual(active, map[string][]string{"provider": {"openai"}}) {
			t.Errorf("ModelActiveRaw() mutated to %v (nested return value leaked)", active)
		}
		if lastUsed, _ := c.ModelLastUsedRaw(); !reflect.DeepEqual(lastUsed, []map[string]string{{"provider": "openai"}}) {
			t.Errorf("ModelLastUsedRaw() mutated to %v (nested return value leaked)", lastUsed)
		}
	})
}

func discoveredOpenAICache(t *testing.T) *Cache {
	t.Helper()
	globalPath := filepath.Join(t.TempDir(), "settings.yaml")
	if err := UpdateDiscoveredModelsProvider(DiscoveredModelsPath(globalPath), "openai", DiscoveredProvider{
		Models: []DiscoveredModel{{ID: "gpt-5.5"}, {ID: "gpt-5.5-pro"}},
	}); err != nil {
		t.Fatalf("seed discovered OpenAI models: %v", err)
	}
	return newCacheOrFatal(t, fullComposed(), t.TempDir(), []string{globalPath})
}

func TestCacheSelectableCatalog(t *testing.T) {
	c := discoveredOpenAICache(t)
	cat := c.SelectableCatalog()

	openai, ok := cat.Entry("openai")
	if !ok {
		t.Fatal("SelectableCatalog missing configured openai entry")
	}
	if openai.AuthKind != provider.AuthKindPlatform {
		t.Errorf("openai AuthKind = %q, want %q", openai.AuthKind, provider.AuthKindPlatform)
	}
	if !reflect.DeepEqual(openai.Models, []string{"gpt-5.5", "gpt-5.5-pro"}) {
		t.Errorf("openai catalog Models = %v, want discovered catalog models", openai.Models)
	}

	chatgpt, ok := cat.Entry("openai-chatgpt")
	if !ok {
		t.Fatal("SelectableCatalog missing built-in openai-chatgpt entry")
	}
	if chatgpt.AuthKind != provider.AuthKindChatGPTSession || !chatgpt.Builtin {
		t.Errorf("openai-chatgpt entry = %+v, want chatgpt_session auth kind and Builtin=true", chatgpt)
	}

	// Built-in present even with no configured providers.
	empty := newCacheOrFatal(t, map[string]any{}, "/r", nil)
	if _, ok := empty.SelectableCatalog().Entry("openai-chatgpt"); !ok {
		t.Error("SelectableCatalog with no providers missing the always-present built-in openai-chatgpt")
	}
}

func TestCacheSelectableCatalogCopyIsolation(t *testing.T) {
	c := discoveredOpenAICache(t)

	e, _ := c.SelectableCatalog().Entry("openai")
	e.Models[0] = "tampered"

	if again, _ := c.SelectableCatalog().Entry("openai"); again.Models[0] != "gpt-5.5" {
		t.Errorf("catalog entry mutated through returned Models slice: Models[0] = %q", again.Models[0])
	}
}

func TestDiscoveredConfiguredModelsReconstructsModalities(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "settings.yaml")
	modelsPath := DiscoveredModelsPath(settings)
	if err := UpdateDiscoveredModelsProvider(modelsPath, "venice", DiscoveredProvider{
		Models: []DiscoveredModel{
			{ID: "venice-vision", InputModalities: []string{"image"}, Capabilities: map[string]any{
				"supportsMultipleImages": true, "maxImages": 4,
			}},
			{ID: "venice-text", Capabilities: map[string]any{"supportsReasoningEffort": true}},
			{ID: ""},
		},
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	store, err := ReadDiscoveredModels(modelsPath)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	got := discoveredConfiguredModels(store)
	venice := got["venice"]
	if len(venice) != 2 {
		t.Fatalf("venice models = %+v, want two (blank id skipped)", venice)
	}
	if venice[0].ID != "venice-vision" || !reflect.DeepEqual(venice[0].InputModalities, []string{"image"}) {
		t.Errorf("first model = %+v, want venice-vision with [image] modalities", venice[0])
	}
	if venice[0].Capabilities["supportsMultipleImages"] != true || len(venice[0].Capabilities) != 2 {
		t.Errorf("first model capabilities = %v, want exactly {supportsMultipleImages:true, maxImages:4}", venice[0].Capabilities)
	}
	if got := fmt.Sprint(venice[0].Capabilities["maxImages"]); got != "4" {
		t.Errorf("first model maxImages = %v, want 4 reconstructed from the store", venice[0].Capabilities["maxImages"])
	}
	if venice[1].ID != "venice-text" || venice[1].InputModalities != nil {
		t.Errorf("second model = %+v, want venice-text with no modality claim", venice[1])
	}
	if venice[1].Capabilities["supportsReasoningEffort"] != true || len(venice[1].Capabilities) != 1 {
		t.Errorf("second model capabilities = %v, want exactly {supportsReasoningEffort:true} preserved", venice[1].Capabilities)
	}

	venice[0].InputModalities[0] = "tampered"
	again, err := ReadDiscoveredModels(modelsPath)
	if err != nil {
		t.Fatalf("re-read store: %v", err)
	}
	fresh := discoveredConfiguredModels(again)
	if m := fresh["venice"][0].InputModalities[0]; m != "image" {
		t.Errorf("fresh read modality = %q, want image (returned slice aliased the store)", m)
	}
}

func TestCacheReloadDiscoveredCatalog(t *testing.T) {
	globalPath := filepath.Join(t.TempDir(), "settings.yaml")
	storePath := DiscoveredModelsPath(globalPath)
	if err := UpdateDiscoveredModelsProvider(storePath, "venice", DiscoveredProvider{
		Models: []DiscoveredModel{{ID: "venice-old", Capabilities: map[string]any{
			"supportsReasoningEffort": true,
			"reasoningEffortOptions":  []any{"low"},
		}}},
	}); err != nil {
		t.Fatalf("seed old store: %v", err)
	}

	composed := map[string]any{"provider": map[string]any{
		"venice": map[string]any{"base_url": "https://api.venice.ai/v1", "api_key": "vk-test"},
	}}
	c := newCacheOrFatal(t, composed, t.TempDir(), []string{globalPath})

	if before, _ := c.SelectableCatalog().Entry("venice"); !reflect.DeepEqual(before.Models, []string{"venice-old"}) {
		t.Fatalf("pre-reload venice models = %v, want [venice-old]", before.Models)
	}
	if got := c.SelectableCatalog().SupportedEffort("venice", "venice-old"); !reflect.DeepEqual(got, []string{"low"}) {
		t.Fatalf("pre-reload venice-old effort = %v, want [low]", got)
	}

	if err := UpdateDiscoveredModelsProvider(storePath, "venice", DiscoveredProvider{
		Models: []DiscoveredModel{{ID: "venice-new", Capabilities: map[string]any{
			"supportsReasoningEffort": true,
			"reasoningEffortOptions":  []any{"low", "high"},
		}}},
	}); err != nil {
		t.Fatalf("replace store: %v", err)
	}

	if stale, _ := c.SelectableCatalog().Entry("venice"); !reflect.DeepEqual(stale.Models, []string{"venice-old"}) {
		t.Fatalf("catalog changed before reload = %v, want still [venice-old] (no reload called yet)", stale.Models)
	}

	c.ReloadDiscoveredCatalog()

	after, ok := c.SelectableCatalog().Entry("venice")
	if !ok {
		t.Fatal("post-reload catalog missing venice entry")
	}
	if !reflect.DeepEqual(after.Models, []string{"venice-new"}) {
		t.Errorf("post-reload venice models = %v, want [venice-new] (replacement live, old id gone)", after.Models)
	}
	if got := c.SelectableCatalog().SupportedEffort("venice", "venice-new"); !reflect.DeepEqual(got, []string{"low", "high"}) {
		t.Errorf("post-reload venice-new effort = %v, want [low high] (replacement capabilities live)", got)
	}
}

func TestCacheReloadDiscoveredCatalogPreservesProviderState(t *testing.T) {
	c := discoveredOpenAICache(t)

	before, ok := c.Provider("openai")
	if !ok {
		t.Fatal("Provider(openai) missing before reload")
	}

	c.ReloadDiscoveredCatalog()

	after, ok := c.Provider("openai")
	if !ok {
		t.Fatal("Provider(openai) missing after reload")
	}
	if after.BaseURL != before.BaseURL || after.APIKey != before.APIKey {
		t.Errorf("connection data changed across reload: before=%+v after=%+v", before, after)
	}
	if after.AuthHeader == nil || before.AuthHeader == nil || *after.AuthHeader != *before.AuthHeader {
		t.Errorf("auth header changed across reload: before=%+v after=%+v", before.AuthHeader, after.AuthHeader)
	}

	after.AuthHeader.Name = "tampered"
	if again, _ := c.Provider("openai"); again.AuthHeader.Name != "Authorization" {
		t.Errorf("Provider(openai).AuthHeader mutated through returned copy: Name=%q", again.AuthHeader.Name)
	}
}

func TestCacheProviderMaxPriceIsolated(t *testing.T) {
	c := newCacheOrFatal(t, map[string]any{}, t.TempDir(), nil)
	want := map[string]provider.MaxPrice{"m": {Prompt: 1, HasPrompt: true}}
	supplied := map[string]provider.MaxPrice{"m": {Prompt: 1, HasPrompt: true}}
	c.SetProvider("openrouter", provider.ProviderEntry{BaseURL: "u", APIKey: "k", Routing: provider.Routing{MaxPrice: supplied}})

	supplied["m"] = provider.MaxPrice{Prompt: 99, HasPrompt: true}
	supplied["x"] = provider.MaxPrice{}
	got, _ := c.Provider("openrouter")
	if !reflect.DeepEqual(got.Routing.MaxPrice, want) {
		t.Fatalf("after mutating the SetProvider input, MaxPrice = %+v, want %+v", got.Routing.MaxPrice, want)
	}

	got.Routing.MaxPrice["m"] = provider.MaxPrice{Prompt: 99, HasPrompt: true}
	got.Routing.MaxPrice["x"] = provider.MaxPrice{}
	again, _ := c.Provider("openrouter")
	if !reflect.DeepEqual(again.Routing.MaxPrice, want) {
		t.Fatalf("after mutating the Provider result, MaxPrice = %+v, want %+v", again.Routing.MaxPrice, want)
	}

	all := c.Providers()
	all["openrouter"].Routing.MaxPrice["m"] = provider.MaxPrice{Prompt: 99, HasPrompt: true}
	all["openrouter"].Routing.MaxPrice["x"] = provider.MaxPrice{}
	again, _ = c.Provider("openrouter")
	if !reflect.DeepEqual(again.Routing.MaxPrice, want) {
		t.Fatalf("after mutating the Providers result, MaxPrice = %+v, want %+v", again.Routing.MaxPrice, want)
	}
}

func TestCacheProviderQuantizationsIsolated(t *testing.T) {
	c := newCacheOrFatal(t, map[string]any{}, t.TempDir(), nil)
	want := map[string]provider.Quantization{"m": {Levels: []string{"fp8", "fp4"}, Mode: "required"}}
	supplied := map[string]provider.Quantization{"m": {Levels: []string{"fp8", "fp4"}, Mode: "required"}}
	c.SetProvider("openrouter", provider.ProviderEntry{BaseURL: "u", APIKey: "k", Routing: provider.Routing{Quantizations: supplied}})

	supplied["m"].Levels[0] = "int4"
	supplied["x"] = provider.Quantization{}
	got, _ := c.Provider("openrouter")
	if !reflect.DeepEqual(got.Routing.Quantizations, want) {
		t.Fatalf("after mutating the SetProvider input, Quantizations = %+v, want %+v", got.Routing.Quantizations, want)
	}

	all := c.Providers()
	got.Routing.Quantizations["m"].Levels[0] = "int4"
	got.Routing.Quantizations["m"] = provider.Quantization{Levels: []string{"bf16"}, Mode: "preferred"}
	got.Routing.Quantizations["x"] = provider.Quantization{}
	again, _ := c.Provider("openrouter")
	if !reflect.DeepEqual(again.Routing.Quantizations, want) {
		t.Fatalf("after mutating the Provider result, Quantizations = %+v, want %+v", again.Routing.Quantizations, want)
	}
	if !reflect.DeepEqual(all["openrouter"].Routing.Quantizations, want) {
		t.Fatalf("after mutating the Provider result, retained Providers snapshot = %+v, want %+v", all["openrouter"].Routing.Quantizations, want)
	}

	all["openrouter"].Routing.Quantizations["m"].Levels[1] = "int8"
	all["openrouter"].Routing.Quantizations["x"] = provider.Quantization{}
	again2, _ := c.Provider("openrouter")
	if !reflect.DeepEqual(again2.Routing.Quantizations, want) {
		t.Fatalf("after mutating the Providers result, Quantizations = %+v, want %+v", again2.Routing.Quantizations, want)
	}
	if !reflect.DeepEqual(again.Routing.Quantizations, want) {
		t.Fatalf("after mutating the Providers result, retained Provider snapshot = %+v, want %+v", again.Routing.Quantizations, want)
	}
}

func TestCacheReloadDiscoveredCatalogRetainsCatalogInvariants(t *testing.T) {
	globalPath := filepath.Join(t.TempDir(), "settings.yaml")
	if err := UpdateDiscoveredModelsProvider(DiscoveredModelsPath(globalPath), "openai", DiscoveredProvider{
		Models: []DiscoveredModel{{ID: "gpt-5.5"}, {ID: "gpt-secret"}},
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	c := newCacheOrFatal(t, fullComposed(), t.TempDir(), []string{globalPath})

	c.ReloadDiscoveredCatalog()

	cat := c.SelectableCatalog()
	openai, ok := cat.Entry("openai")
	if !ok {
		t.Fatal("post-reload catalog missing openai entry")
	}
	if want := []string{"gpt-5.5", "gpt-secret"}; !reflect.DeepEqual(openai.Models, want) {
		t.Errorf("post-reload openai models = %v, want %v (Platform retains every sanitized cached id)", openai.Models, want)
	}
	chatgpt, ok := cat.Entry("openai-chatgpt")
	if !ok {
		t.Fatal("post-reload catalog missing built-in openai-chatgpt fallback")
	}
	if !chatgpt.Builtin || chatgpt.AuthKind != provider.AuthKindChatGPTSession {
		t.Errorf("post-reload openai-chatgpt = %+v, want built-in chatgpt_session fallback", chatgpt)
	}
}

func TestCacheReloadDiscoveredCatalogRaceSafe(t *testing.T) {
	c := discoveredOpenAICache(t)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = c.SelectableCatalog()
				_, _ = c.Provider("openai")
				_ = c.Providers()
			}
		}()
	}
	for i := 0; i < 50; i++ {
		c.ReloadDiscoveredCatalog()
	}
	wg.Wait()
}

func TestNewCacheParseErrors(t *testing.T) {
	tests := []struct {
		name     string
		composed map[string]any
	}{
		{
			name:     "bad provider shape",
			composed: map[string]any{"provider": map[string]any{"openai": map[string]any{"base_url": 123}}},
		},
		{
			name:     "permissions not a list",
			composed: map[string]any{"permissions": map[string]any{"kind": "tool"}},
		},
		{
			name: "malformed permission entry",
			composed: map[string]any{"permissions": []any{
				map[string]any{"kind": "bogus", "subject": "x", "path_scope": "*", "grant_kind": "global"},
			}},
		},
		{
			name: "malformed favorite entry",
			composed: map[string]any{"model": map[string]any{"favorites": []any{
				map[string]any{"provider": "openai"},
			}}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewCache(tc.composed, "/r", nil); err == nil {
				t.Fatal("NewCache: expected error, got nil")
			}
		})
	}
}

func TestNewCache_Favorites(t *testing.T) {
	t.Run("ordered valid list", func(t *testing.T) {
		composed := map[string]any{"model": map[string]any{"favorites": []any{
			map[string]any{"provider": "openai", "id": "gpt-5"},
			map[string]any{"provider": "anthropic", "id": "opus"},
		}}}
		c := newCacheOrFatal(t, composed, "/r", nil)
		want := []Favorite{{Provider: "openai", ID: "gpt-5"}, {Provider: "anthropic", ID: "opus"}}
		if got := c.Favorites(); !reflect.DeepEqual(got, want) {
			t.Fatalf("Favorites() = %v, want %v", got, want)
		}
	})

	t.Run("absent key yields empty snapshot", func(t *testing.T) {
		c := newCacheOrFatal(t, map[string]any{}, "/r", nil)
		if got := c.Favorites(); len(got) != 0 {
			t.Fatalf("Favorites() = %v, want empty", got)
		}
	})

	t.Run("malformed direct-construction shape errors", func(t *testing.T) {
		composed := map[string]any{"model": map[string]any{"favorites": []any{
			map[string]any{"provider": "openai", "id": ""},
		}}}
		if _, err := NewCache(composed, "/r", nil); err == nil {
			t.Fatal("NewCache: expected error for empty favorite id, got nil")
		}
	})
}

func TestCacheSetAttribution_WritesGlobalLayerAndPublishesToSession(t *testing.T) {
	dir := t.TempDir()
	global := filepath.Join(dir, "global", "settings.yaml")
	project := filepath.Join(dir, "project-settings.yaml")
	writeAt(t, project, "model:\n  active:\n    provider: openai\n    id: gpt-5\n")
	projectBefore := readAt(t, project)

	c := newCacheOrFatal(t, map[string]any{}, "/r", []string{global, project})
	if !c.Attribution() {
		t.Fatalf("precondition: Attribution() = false, want the on-by-default state")
	}

	if reason, cat, err := c.SetAttribution(false); reason != ReasonNone || err != nil {
		t.Fatalf("SetAttribution(false) = (%q, %q, %v), want success", reason, cat, err)
	}
	if c.Attribution() {
		t.Error("Attribution() = true after a successful opt-out write")
	}
	if got := readAt(t, global); got != "attribution: false\n" {
		t.Errorf("global settings = %q, want the durable opt-out", got)
	}
	if after := readAt(t, project); after != projectBefore {
		t.Errorf("project layer changed by a global-only write:\n%q\nwant\n%q", after, projectBefore)
	}

	if reason, cat, err := c.SetAttribution(true); reason != ReasonNone || err != nil {
		t.Fatalf("SetAttribution(true) = (%q, %q, %v), want success", reason, cat, err)
	}
	if !c.Attribution() {
		t.Error("Attribution() = false after a successful opt-in write")
	}
	if got := readAt(t, global); got != "attribution: true\n" {
		t.Errorf("global settings = %q, want the durable opt-in", got)
	}
}

func TestCacheSetAttribution_NoGlobalLayerFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		layers []string
	}{
		{"no layers", nil},
		{"empty first layer", []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCacheOrFatal(t, map[string]any{}, "/r", tc.layers)
			reason, cat, err := c.SetAttribution(false)
			if reason != ReasonRereadParseError || cat != "" || err == nil {
				t.Fatalf("= (%q, %q, %v), want (reread_parse_error, \"\", error)", reason, cat, err)
			}
			if !c.Attribution() {
				t.Error("cached attribution changed on a fail-closed write")
			}
		})
	}
}

func TestCacheSetAttribution_WriteFailureLeavesDiskAndSessionUnchanged(t *testing.T) {
	dir := t.TempDir()
	global := filepath.Join(dir, "settings.yaml")
	const seed = "# keep me\nattribution: true\n"
	writeAt(t, global, seed)

	c := newCacheOrFatal(t, map[string]any{"attribution": true}, "/r", []string{global})

	sentinel := errors.New("forced temp-file sync failure")
	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)

	reason, cat, err := c.SetAttribution(false)
	if reason != ReasonWriteError || cat != fserrors.IOError || !errors.Is(err, sentinel) {
		t.Fatalf("= (%q, %q, %v), want (write_error, io_error, wrap of sentinel)", reason, cat, err)
	}
	restore()

	if !c.Attribution() {
		t.Error("cached attribution changed on a failed write")
	}
	if after := readAt(t, global); after != seed {
		t.Errorf("failed write changed bytes:\n%q\nwant\n%q", after, seed)
	}
}

var validatedSystemOneNames = []string{"openrouter:typesafe/jev-1.13", "venice:jev-latest", "openrouter:liquid/d1"}

func systemOneOnDisk(t *testing.T, path string) any {
	t.Helper()
	_, raw, cat, err := LoadYAML(path)
	if cat != LoadOK || err != nil {
		t.Fatalf("LoadYAML(%s) = (%q, %v)", path, cat, err)
	}
	return raw[KeySystemOne]
}

func TestCacheSystemOne_LoadsFromGlobalFile(t *testing.T) {
	for _, name := range append([]string{"off"}, validatedSystemOneNames...) {
		t.Run(name, func(t *testing.T) {
			global := filepath.Join(t.TempDir(), "settings.yaml")
			writeAt(t, global, fmt.Sprintf("system_one: %q\n", name))
			_, raw, cat, err := LoadYAML(global)
			if cat != LoadOK || err != nil {
				t.Fatalf("LoadYAML = (%q, %v)", cat, err)
			}
			if got := newCacheOrFatal(t, raw, "/r", []string{global}).SystemOne(); got != name {
				t.Errorf("SystemOne() = %q, want %q", got, name)
			}
		})
	}
	if got := newCacheOrFatal(t, map[string]any{}, "/r", nil).SystemOne(); got != "off" {
		t.Errorf("SystemOne() with the key absent = %q, want off", got)
	}
}

func TestCacheSetSystemOne_WritesGlobalLayerAndPublishesToSession(t *testing.T) {
	dir := t.TempDir()
	global := filepath.Join(dir, "settings.yaml")
	project := filepath.Join(dir, "project-settings.yaml")
	writeAt(t, project, "model:\n  active:\n    provider: openai\n    id: gpt-5\n")
	projectBefore := readAt(t, project)
	const seed = "# keep me\nattribution: false # trailing note\n"
	writeAt(t, global, seed)

	c := newCacheOrFatal(t, map[string]any{}, "/r", []string{global, project})
	other := newCacheOrFatal(t, map[string]any{}, "/r", []string{global, project})

	for _, name := range append(validatedSystemOneNames, "off") {
		if reason, cat, err := c.SetSystemOne(name); reason != ReasonNone || err != nil {
			t.Fatalf("SetSystemOne(%q) = (%q, %q, %v), want success", name, reason, cat, err)
		}
		if got := c.SystemOne(); got != name {
			t.Errorf("SystemOne() after SetSystemOne(%q) = %q", name, got)
		}
		if got := systemOneOnDisk(t, global); got != name {
			t.Errorf("system_one on disk = %#v, want %q", got, name)
		}
		if after := readAt(t, global); !strings.HasPrefix(after, seed) {
			t.Errorf("unrelated bytes changed:\n%q\nwant prefix\n%q", after, seed)
		}
	}
	if after := readAt(t, project); after != projectBefore {
		t.Errorf("project layer changed by a global-only write:\n%q\nwant\n%q", after, projectBefore)
	}
	if reason, _, err := c.SetSystemOne("venice:jev-latest"); reason != ReasonNone || err != nil {
		t.Fatalf("SetSystemOne = (%q, %v)", reason, err)
	}
	if got := other.SystemOne(); got != "off" {
		t.Errorf("a second cache sharing the global file reloaded the write: %q", got)
	}
}

func TestCacheSetSystemOne_NoGlobalLayerFailsClosed(t *testing.T) {
	for _, layers := range [][]string{nil, {""}} {
		c := newCacheOrFatal(t, map[string]any{}, "/r", layers)
		reason, cat, err := c.SetSystemOne("venice:jev-latest")
		if reason != ReasonRereadParseError || cat != "" || err == nil {
			t.Fatalf("layers %q: = (%q, %q, %v), want (reread_parse_error, \"\", error)", layers, reason, cat, err)
		}
		if got := c.SystemOne(); got != "off" {
			t.Errorf("layers %q: cached selection changed on a fail-closed write: %q", layers, got)
		}
	}
}

func TestCacheSetSystemOne_ConcurrentGetAndSet(t *testing.T) {
	global := filepath.Join(t.TempDir(), "settings.yaml")
	c := newCacheOrFatal(t, map[string]any{}, "/r", []string{global})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if reason, _, err := c.SetSystemOne(validatedSystemOneNames[i%len(validatedSystemOneNames)]); reason != ReasonNone || err != nil {
				t.Errorf("SetSystemOne = (%q, %v)", reason, err)
			}
		}()
		go func() {
			defer wg.Done()
			_ = c.SystemOne()
		}()
	}
	wg.Wait()
	if got := c.SystemOne(); got != systemOneOnDisk(t, global) {
		t.Errorf("SystemOne() = %q, disk = %#v", got, systemOneOnDisk(t, global))
	}
}

func TestCacheSetSystemOne_SecondSetterCannotOvertakeFirst(t *testing.T) {
	global := filepath.Join(t.TempDir(), "settings.yaml")
	c := newCacheOrFatal(t, map[string]any{}, "/r", []string{global})

	const first = "venice:jev-latest"
	paused, release, secondPersisting := make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseFirst := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseFirst)
	orig := beforeSystemOnePublish
	t.Cleanup(func() { beforeSystemOnePublish = orig })
	beforeSystemOnePublish = func(name string) {
		if name == first {
			close(paused)
			<-release
		}
	}
	setMergeWrite(t, func(dir *os.File, path string, source fsutil.FileSnapshot, key string, v any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
		if v == "off" {
			close(secondPersisting)
		}
		return rewriteKeyAt(dir, path, source, key, v)
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		if reason, _, err := c.SetSystemOne(first); reason != ReasonNone || err != nil {
			t.Errorf("first SetSystemOne = (%q, %v)", reason, err)
		}
	}()
	<-paused
	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		if reason, _, err := c.SetSystemOne("off"); reason != ReasonNone || err != nil {
			t.Errorf("second SetSystemOne = (%q, %v)", reason, err)
		}
	}()
	select {
	case <-secondPersisting:
		t.Error("second setter entered persistence while the first was paused between Persist and publication")
	case <-time.After(50 * time.Millisecond):
	}
	releaseFirst()
	<-done
	<-secondDone

	if got := c.SystemOne(); got != "off" {
		t.Errorf("SystemOne() = %q, want the second selection", got)
	}
	if got := systemOneOnDisk(t, global); got != "off" {
		t.Errorf("system_one on disk = %#v, want the second selection", got)
	}
}

func TestCacheSetSystemOne_PrePublicationFailureLeavesDiskAndSessionUnchanged(t *testing.T) {
	global := filepath.Join(t.TempDir(), "settings.yaml")
	const seed = "# keep me\nsystem_one: \"openrouter:liquid/d1\"\n"
	writeAt(t, global, seed)
	c := newCacheOrFatal(t, map[string]any{KeySystemOne: "openrouter:liquid/d1"}, "/r", []string{global})

	sentinel := errors.New("forced temp-file sync failure")
	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)
	reason, cat, err := c.SetSystemOne("off")
	restore()
	if reason != ReasonWriteError || cat != fserrors.IOError || !errors.Is(err, sentinel) {
		t.Fatalf("= (%q, %q, %v), want (write_error, io_error, wrap of sentinel)", reason, cat, err)
	}
	if got := c.SystemOne(); got != "openrouter:liquid/d1" {
		t.Errorf("cached selection changed on a failed write: %q", got)
	}
	if after := readAt(t, global); after != seed {
		t.Errorf("failed write changed bytes:\n%q\nwant\n%q", after, seed)
	}
}

func TestCacheSetSystemOne_DirSyncFailureKeepsOldSessionSelection(t *testing.T) {
	global := filepath.Join(t.TempDir(), "settings.yaml")
	writeAt(t, global, "system_one: \"off\"\n")
	c := newCacheOrFatal(t, map[string]any{KeySystemOne: "off"}, "/r", []string{global})

	sentinel := errors.New("forced parent dir sync failure")
	restore := fsutil.SetSyncDirForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)
	reason, cat, err := c.SetSystemOne("venice:jev-latest")
	restore()
	if reason != ReasonParentDirError || cat != fserrors.IOError || !errors.Is(err, sentinel) {
		t.Fatalf("= (%q, %q, %v), want (parent_dir_error, io_error, wrap of sentinel)", reason, cat, err)
	}
	if got := c.SystemOne(); got != "off" {
		t.Errorf("cached selection changed on a parent-sync failure: %q", got)
	}
	if got := systemOneOnDisk(t, global); got != "venice:jev-latest" {
		t.Errorf("system_one on disk = %#v, want the already-published bytes", got)
	}
}

func TestCacheSetSystemOne_InvalidValueLeavesDiskAndSessionUnchanged(t *testing.T) {
	for _, value := range []string{
		"openrouter:typesafe/jev-1.12",
		"openrouter",
		"",
		"off\nattribution: false",
		"venice:jev-latest # note",
		"{system_one: off}",
	} {
		t.Run(value, func(t *testing.T) {
			dir := t.TempDir()
			existing := filepath.Join(dir, "settings.yaml")
			const seed = "# keep me\nattribution: true\n"
			writeAt(t, existing, seed)
			absent := filepath.Join(dir, "absent", "settings.yaml")

			for _, global := range []string{existing, absent} {
				c := newCacheOrFatal(t, map[string]any{}, "/r", []string{global})
				reason, _, err := c.SetSystemOne(value)
				if reason != ReasonRereadParseError || err == nil {
					t.Fatalf("%s: = (%q, %v), want (reread_parse_error, error)", global, reason, err)
				}
				if got := c.SystemOne(); got != "off" {
					t.Errorf("%s: cached selection changed: %q", global, got)
				}
			}
			if after := readAt(t, existing); after != seed {
				t.Errorf("invalid value changed bytes:\n%q\nwant\n%q", after, seed)
			}
			if _, err := os.Stat(absent); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("invalid value created the absent global file: %v", err)
			}
		})
	}
}

func TestCacheConfinementAccessors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		composed   map[string]any
		wantLookup string
	}{
		{"absent", map[string]any{}, "friendly"},
		{"strict", map[string]any{"confinement": map[string]any{"program_lookup": "strict"}}, "strict"},
		{"friendly", map[string]any{"confinement": map[string]any{"program_lookup": "friendly"}}, "friendly"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCacheOrFatal(t, tc.composed, "/r", nil)
			if got := c.ProgramLookup(); got != tc.wantLookup {
				t.Errorf("ProgramLookup() = %q, want %q", got, tc.wantLookup)
			}
		})
	}
}

func TestCacheConfinement_FromGlobalFile(t *testing.T) {
	global := filepath.Join(t.TempDir(), "settings.yaml")
	writeAt(t, global, "confinement:\n  program_lookup: strict\n")
	_, raw, cat, err := LoadYAML(global)
	if cat != LoadOK || err != nil {
		t.Fatalf("LoadYAML = (%q, %v)", cat, err)
	}
	c := newCacheOrFatal(t, raw, "/r", []string{global})
	if got := c.ProgramLookup(); got != "strict" {
		t.Errorf("ProgramLookup() = %q, want strict", got)
	}
}

func TestCacheSetRetentionDays_WritesGlobalLayerAndPublishesToSession(t *testing.T) {
	dir := t.TempDir()
	global := filepath.Join(dir, "global", "settings.yaml")
	project := filepath.Join(dir, "project-settings.yaml")
	local := filepath.Join(dir, "local-settings.yaml")
	writeAt(t, project, "attribution: false\n")
	writeAt(t, local, "vcs:\n  preferred: hg\n")

	c := newCacheOrFatal(t, map[string]any{}, "/r", []string{global, project, local})

	if reason, cat, err := c.SetRetentionDays(14); reason != ReasonNone || cat != "" || err != nil {
		t.Fatalf("SetRetentionDays(14) = (%q, %q, %v), want success", reason, cat, err)
	}
	if got := c.RetentionDays(); got != 14 {
		t.Errorf("RetentionDays() = %d, want 14", got)
	}
	if got := readAt(t, global); got != "sessions:\n  retention_days: 14\n" {
		t.Errorf("global settings = %q, want sessions.retention_days: 14", got)
	}
	if got := readAt(t, project); got != "attribution: false\n" {
		t.Errorf("project layer changed by a global-only write: %q", got)
	}
	if got := readAt(t, local); got != "vcs:\n  preferred: hg\n" {
		t.Errorf("local layer changed by a global-only write: %q", got)
	}
}

func TestCacheSetRetentionDays_RejectsBelowOneBeforeWriting(t *testing.T) {
	global := filepath.Join(t.TempDir(), "settings.yaml")
	const seed = "sessions:\n  retention_days: 30\n"
	writeAt(t, global, seed)
	c := newCacheOrFatal(t, map[string]any{"sessions": map[string]any{"retention_days": 30}}, "/r", []string{global})

	for _, days := range []int{0, -1} {
		reason, cat, err := c.SetRetentionDays(days)
		if reason != ReasonRereadParseError || cat != "" || err == nil {
			t.Fatalf("SetRetentionDays(%d) = (%q, %q, %v), want (reread_parse_error, \"\", error)", days, reason, cat, err)
		}
		if got := c.RetentionDays(); got != 30 {
			t.Errorf("RetentionDays() = %d after SetRetentionDays(%d), want 30", got, days)
		}
		if got := readAt(t, global); got != seed {
			t.Errorf("SetRetentionDays(%d) changed bytes: %q", days, got)
		}
	}
}

func TestCacheSetRetentionDays_NoGlobalLayerFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		layers []string
	}{
		{"missing", nil},
		{"empty", []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCacheOrFatal(t, map[string]any{}, "/r", tc.layers)
			reason, cat, err := c.SetRetentionDays(14)
			if reason != ReasonRereadParseError || cat != "" || err == nil {
				t.Fatalf("= (%q, %q, %v), want (reread_parse_error, \"\", error)", reason, cat, err)
			}
			if got := c.RetentionDays(); got != defaultRetentionDays {
				t.Errorf("RetentionDays() = %d on a fail-closed write, want %d", got, defaultRetentionDays)
			}
		})
	}
}

func TestCacheSetRetentionDays_MalformedGlobalLeavesDiskAndSessionUnchanged(t *testing.T) {
	dir := t.TempDir()
	global := filepath.Join(dir, "settings.yaml")
	project := filepath.Join(dir, "project-settings.yaml")
	const seed = "sessions: [unterminated\n"
	writeAt(t, global, seed)
	writeAt(t, project, "attribution: false\n")
	c := newCacheOrFatal(t, map[string]any{}, "/r", []string{global, project})

	reason, cat, err := c.SetRetentionDays(14)
	if reason != ReasonRereadParseError || cat != "" || err == nil {
		t.Fatalf("= (%q, %q, %v), want (reread_parse_error, \"\", error)", reason, cat, err)
	}
	if got := c.RetentionDays(); got != defaultRetentionDays {
		t.Errorf("RetentionDays() = %d after a failed write, want %d", got, defaultRetentionDays)
	}
	if got := readAt(t, global); got != seed {
		t.Errorf("failed write changed bytes: %q", got)
	}
	if got := readAt(t, project); got != "attribution: false\n" {
		t.Errorf("project layer changed: %q", got)
	}
}

func TestCacheSetRetentionDays_WriteFailureLeavesDiskAndSessionUnchanged(t *testing.T) {
	dir := t.TempDir()
	global := filepath.Join(dir, "settings.yaml")
	project := filepath.Join(dir, "project-settings.yaml")
	const seed = "# keep me\nsessions:\n  retention_days: 30\n"
	writeAt(t, global, seed)
	writeAt(t, project, "attribution: false\n")
	c := newCacheOrFatal(t, map[string]any{"sessions": map[string]any{"retention_days": 30}}, "/r", []string{global, project})

	sentinel := errors.New("forced temp-file sync failure")
	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)

	reason, cat, err := c.SetRetentionDays(14)
	if reason != ReasonWriteError || cat != fserrors.IOError || !errors.Is(err, sentinel) {
		t.Fatalf("= (%q, %q, %v), want (write_error, io_error, wrap of sentinel)", reason, cat, err)
	}
	restore()

	if got := c.RetentionDays(); got != 30 {
		t.Errorf("RetentionDays() = %d after a failed write, want 30", got)
	}
	if got := readAt(t, global); got != seed {
		t.Errorf("failed write changed bytes:\n%q\nwant\n%q", got, seed)
	}
	if got := readAt(t, project); got != "attribution: false\n" {
		t.Errorf("project layer changed: %q", got)
	}
}

func TestCacheFavorites_DefensiveCopies(t *testing.T) {
	favMap := map[string]any{"provider": "openai", "id": "gpt-5"}
	list := []any{favMap, map[string]any{"provider": "anthropic", "id": "opus"}}
	composed := map[string]any{"model": map[string]any{"favorites": list}}
	c := newCacheOrFatal(t, composed, "/r", nil)

	want := []Favorite{{Provider: "openai", ID: "gpt-5"}, {Provider: "anthropic", ID: "opus"}}

	favMap["id"] = "mutated"
	list[1] = map[string]any{"provider": "evil", "id": "evil"}
	if got := c.Favorites(); !reflect.DeepEqual(got, want) {
		t.Fatalf("mutating the composed input changed the cache: %v, want %v", got, want)
	}

	snap := c.Favorites()
	snap[0] = Favorite{Provider: "tampered", ID: "tampered"}
	if got := c.Favorites(); !reflect.DeepEqual(got, want) {
		t.Fatalf("mutating a returned snapshot changed the cache: %v, want %v", got, want)
	}
}

func TestCacheSelectableCatalogToolSupportFromStore(t *testing.T) {
	globalPath := filepath.Join(t.TempDir(), "settings.yaml")
	storePath := DiscoveredModelsPath(globalPath)
	if err := UpdateDiscoveredModelsProvider(storePath, "openrouter", DiscoveredProvider{
		Models: []DiscoveredModel{
			{ID: "tencent/hy-mt2-30b-a3b", Capabilities: map[string]any{
				"supportedParameters": []any{"max_tokens", "top_p"},
			}},
			{ID: "vendor/empty-params", Capabilities: map[string]any{
				"supportedParametersEmpty": true,
			}},
			{ID: "openai/gpt-5.5", Capabilities: map[string]any{
				"supportedParameters": []any{"max_tokens", "tools"},
			}},
			{ID: "vendor/legacy-record"},
		},
	}); err != nil {
		t.Fatalf("seed openrouter store: %v", err)
	}
	if err := UpdateDiscoveredModelsProvider(storePath, "venice", DiscoveredProvider{
		Models: []DiscoveredModel{
			{ID: "venice-translate", Capabilities: map[string]any{"supportsFunctionCalling": false}},
			{ID: "venice-uncensored", Capabilities: map[string]any{"supportsFunctionCalling": true}},
		},
	}); err != nil {
		t.Fatalf("seed venice store: %v", err)
	}

	composed := map[string]any{"provider": map[string]any{
		"openrouter": map[string]any{"base_url": "https://openrouter.ai/api/v1", "api_key": "sk-or-test"},
		"venice":     map[string]any{"base_url": "https://api.venice.ai/v1", "api_key": "vk-test"},
	}}
	c := newCacheOrFatal(t, composed, t.TempDir(), []string{globalPath})

	for _, tc := range []struct {
		providerID, modelID string
		want                bool
	}{
		{"openrouter", "tencent/hy-mt2-30b-a3b", false},
		{"openrouter", "vendor/empty-params", false},
		{"openrouter", "openai/gpt-5.5", true},
		{"openrouter", "vendor/legacy-record", true},
		{"venice", "venice-translate", false},
		{"venice", "venice-uncensored", true},
	} {
		if got := c.SelectableCatalog().SupportsTools(tc.providerID, tc.modelID); got != tc.want {
			t.Errorf("SupportsTools(%s, %s) = %v, want %v", tc.providerID, tc.modelID, got, tc.want)
		}
	}

	if err := UpdateDiscoveredModelsProvider(storePath, "openrouter", DiscoveredProvider{
		Models: []DiscoveredModel{{ID: "tencent/hy-mt2-30b-a3b", Capabilities: map[string]any{
			"supportedParameters": []any{"max_tokens", "tools"},
		}}},
	}); err != nil {
		t.Fatalf("replace openrouter store: %v", err)
	}
	if c.SelectableCatalog().SupportsTools("openrouter", "tencent/hy-mt2-30b-a3b") {
		t.Fatal("catalog changed before reload, want the seeded unsupported result until ReloadDiscoveredCatalog")
	}

	c.ReloadDiscoveredCatalog()

	if !c.SelectableCatalog().SupportsTools("openrouter", "tencent/hy-mt2-30b-a3b") {
		t.Error("post-reload SupportsTools = false, want the refreshed metadata to restore tool support")
	}
}

func TestCacheLayeredPermissions(t *testing.T) {
	shared := map[string]any{"kind": "direct", "subject": "ls", "path_scope": "/proj", "grant_kind": "folder"}
	globalOnly := map[string]any{"kind": "direct", "subject": "cat", "path_scope": "*", "grant_kind": "global"}
	c, err := NewCache(map[string]any{"permissions": []any{globalOnly, shared}}, "/proj", nil)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	before := c.Permissions()

	globalEntries, err := LayerPermissions(map[string]any{"permissions": []any{globalOnly}}, permissions.LayerGlobal)
	if err != nil {
		t.Fatalf("LayerPermissions global: %v", err)
	}
	projectEntries, err := LayerPermissions(map[string]any{"permissions": []any{shared}}, permissions.LayerProject)
	if err != nil {
		t.Fatalf("LayerPermissions project: %v", err)
	}
	localEntries, err := LayerPermissions(map[string]any{"permissions": []any{shared}}, permissions.LayerLocal)
	if err != nil {
		t.Fatalf("LayerPermissions local: %v", err)
	}
	c.SetLayeredPermissions(append(append(globalEntries, projectEntries...), localEntries...))

	layered := c.LayeredPermissions()
	if len(layered) != 3 {
		t.Fatalf("layered = %+v, want one line per layer copy", layered)
	}
	seen := map[permissions.LayerKind]int{}
	for _, e := range layered {
		seen[e.Layer]++
	}
	if seen[permissions.LayerGlobal] != 1 || seen[permissions.LayerProject] != 1 || seen[permissions.LayerLocal] != 1 {
		t.Fatalf("layered = %+v, want one entry per layer", layered)
	}

	after := c.Permissions()
	if len(after) != len(before) {
		t.Fatalf("Permissions() = %+v, want the same entries as before (%+v)", after, before)
	}
	for i := range after {
		if after[i].DedupKey() != before[i].DedupKey() {
			t.Fatalf("Permissions()[%d] = %+v, want the order and contents unchanged", i, after[i])
		}
	}
	if after[0].Layer != permissions.LayerGlobal {
		t.Fatalf("global-only grant labelled %q, want %q", after[0].Layer, permissions.LayerGlobal)
	}
	// The surviving copy came from the project layer, but the nearest layer holding it is local.
	if after[1].Layer != permissions.LayerLocal {
		t.Fatalf("shared grant labelled %q, want %q", after[1].Layer, permissions.LayerLocal)
	}
}

func TestCacheAppendPermissionCarriesNoLayer(t *testing.T) {
	c, err := NewCache(map[string]any{}, "/proj", nil)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	c.SetLayeredPermissions(nil)
	c.AppendPermission(permissions.PermissionEntry{Kind: "direct", Subject: "ls", PathScope: "/proj", GrantKind: "session"})
	got := c.Permissions()
	if len(got) != 1 || got[0].Layer != "" {
		t.Fatalf("permissions = %+v, want one session grant with no layer", got)
	}
	if len(c.LayeredPermissions()) != 0 {
		t.Fatalf("layered = %+v, want a session grant to stay out of the layered view", c.LayeredPermissions())
	}
}

func openRouterSettingsCache(t *testing.T, seed string) (*Cache, string) {
	t.Helper()
	global := filepath.Join(t.TempDir(), "settings.yaml")
	writeAt(t, global, seed)
	_, raw, _, err := LoadYAML(global)
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	return newCacheOrFatal(t, raw, "/r", []string{global}), global
}

const openRouterRoutingSeed = "provider:\n  openrouter:\n    base_url: u\n    api_key: k\n    routing:\n      require_parameters: true\n      data_collection: deny\n      max_price: {a/m: {prompt: 1}}\n"

func TestCacheOpenRouterRouting_GettersDefault(t *testing.T) {
	for _, tc := range []struct {
		name, seed     string
		wantDC, wantSo string
	}{
		{"no openrouter entry", "attribution: true\n", "allow", "default"},
		{"no routing", "provider:\n  openrouter:\n    base_url: u\n    api_key: k\n", "allow", "default"},
		{"configured", "provider:\n  openrouter:\n    base_url: u\n    api_key: k\n    routing: {sort: latency, data_collection: deny}\n", "deny", "latency"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := openRouterSettingsCache(t, tc.seed)
			if got := c.OpenRouterDataCollection(); got != tc.wantDC {
				t.Errorf("OpenRouterDataCollection() = %q, want %q", got, tc.wantDC)
			}
			if got := c.OpenRouterSort(); got != tc.wantSo {
				t.Errorf("OpenRouterSort() = %q, want %q", got, tc.wantSo)
			}
		})
	}
}

func TestCacheOpenRouterRouting_SettersPersistThenPreserveSiblings(t *testing.T) {
	c, global := openRouterSettingsCache(t, openRouterRoutingSeed)
	want := provider.Routing{RequireParameters: true, DataCollection: "deny", MaxPrice: map[string]provider.MaxPrice{"a/m": {Prompt: 1, HasPrompt: true}}}

	if reason, cat, err := c.SetOpenRouterSort("best_value"); reason != ReasonNone || err != nil {
		t.Fatalf("SetOpenRouterSort(best_value) = (%q, %q, %v), want success", reason, cat, err)
	}
	want.Sort = "best_value"
	assertOpenRouterRouting(t, c, want)
	if got := readAt(t, global); got != openRouterRoutingSeed+"      sort: best_value\n" {
		t.Fatalf("settings after sort = %q", got)
	}

	if reason, cat, err := c.SetOpenRouterDataCollection("allow"); reason != ReasonNone || err != nil {
		t.Fatalf("SetOpenRouterDataCollection(allow) = (%q, %q, %v), want success", reason, cat, err)
	}
	want.DataCollection = "allow"
	assertOpenRouterRouting(t, c, want)

	if reason, cat, err := c.SetOpenRouterSort("default"); reason != ReasonNone || err != nil {
		t.Fatalf("SetOpenRouterSort(default) = (%q, %q, %v), want success", reason, cat, err)
	}
	want.Sort = ""
	assertOpenRouterRouting(t, c, want)
	if got := c.OpenRouterSort(); got != "default" {
		t.Fatalf("OpenRouterSort() = %q, want default", got)
	}
	if got, wantFile := readAt(t, global), strings.Replace(openRouterRoutingSeed, "deny", "allow", 1); got != wantFile {
		t.Fatalf("settings after default = %q, want %q", got, wantFile)
	}
}

func TestCacheOpenRouterMaxPrice_SetThenRemove(t *testing.T) {
	const id = "x-ai/grok-4.1:free"
	c, global := openRouterSettingsCache(t, openRouterRoutingSeed)
	cachedBefore := c.providers["openrouter"].Routing.MaxPrice
	if _, ok := c.OpenRouterMaxPrice(id); ok {
		t.Fatalf("OpenRouterMaxPrice(%q) found an entry before any set", id)
	}

	set := provider.MaxPrice{Prompt: 1.5, Completion: 2, HasPrompt: true, HasCompletion: true}
	if reason, cat, err := c.SetOpenRouterMaxPrice(id, set); reason != ReasonNone || err != nil {
		t.Fatalf("SetOpenRouterMaxPrice = (%q, %q, %v), want success", reason, cat, err)
	}
	if got, ok := c.OpenRouterMaxPrice(id); !ok || got != set {
		t.Fatalf("OpenRouterMaxPrice after set = %+v (ok=%v), want %+v", got, ok, set)
	}
	if got := readAt(t, global); got != strings.Replace(openRouterRoutingSeed, "{prompt: 1}}", `{prompt: 1}, "`+id+`": {prompt: 1.5, completion: 2}}`, 1) {
		t.Fatalf("settings after set = %q", got)
	}
	if len(cachedBefore) != 1 {
		t.Fatalf("set mutated the previously cached max_price map in place: %+v", cachedBefore)
	}

	if reason, cat, err := c.SetOpenRouterMaxPrice(id, provider.MaxPrice{}); reason != ReasonNone || err != nil {
		t.Fatalf("SetOpenRouterMaxPrice(remove) = (%q, %q, %v), want success", reason, cat, err)
	}
	if got, ok := c.OpenRouterMaxPrice(id); ok {
		t.Fatalf("OpenRouterMaxPrice after remove = %+v, want no entry", got)
	}
	assertOpenRouterRouting(t, c, provider.Routing{RequireParameters: true, DataCollection: "deny", MaxPrice: map[string]provider.MaxPrice{"a/m": {Prompt: 1, HasPrompt: true}}})
	if got := readAt(t, global); got != openRouterRoutingSeed {
		t.Fatalf("settings after remove = %q, want the seed back", got)
	}
}

func TestCacheOpenRouterQuantizations_SetDeleteAndSnapshot(t *testing.T) {
	c, global := openRouterSettingsCache(t, openRouterRoutingSeed)
	if got := c.OpenRouterQuantizations(); len(got) != 0 {
		t.Fatalf("OpenRouterQuantizations() before any set = %+v, want none", got)
	}

	levels := []string{"fp8", "fp4"}
	if reason, cat, err := c.SetOpenRouterQuantization("z/m", provider.Quantization{Levels: levels, Mode: "required"}); reason != ReasonNone || err != nil {
		t.Fatalf("SetOpenRouterQuantization(z/m) = (%q, %q, %v), want success", reason, cat, err)
	}
	levels[0] = "int4"
	if reason, cat, err := c.SetOpenRouterQuantization("a/m", provider.Quantization{Levels: []string{"unknown"}, Mode: "preferred"}); reason != ReasonNone || err != nil {
		t.Fatalf("SetOpenRouterQuantization(a/m) = (%q, %q, %v), want success", reason, cat, err)
	}
	want := []OpenRouterQuantization{
		{Model: "a/m", Quantization: provider.Quantization{Levels: []string{"unknown"}, Mode: "preferred"}},
		{Model: "z/m", Quantization: provider.Quantization{Levels: []string{"fp8", "fp4"}, Mode: "required"}},
	}
	snap := c.OpenRouterQuantizations()
	if !reflect.DeepEqual(snap, want) {
		t.Fatalf("OpenRouterQuantizations() = %+v, want %+v", snap, want)
	}
	snap[1].Quantization.Levels[0] = "bf16"
	snap[0].Quantization.Mode = "required"
	if got := c.OpenRouterQuantizations(); !reflect.DeepEqual(got, want) {
		t.Fatalf("mutating the snapshot changed the cache: %+v, want %+v", got, want)
	}
	wantFile := openRouterRoutingSeed + "      quantizations:\n        \"z/m\": {levels: [fp8, fp4], mode: required}\n        \"a/m\": {levels: [unknown], mode: preferred}\n"
	if got := readAt(t, global); got != wantFile {
		t.Fatalf("settings after set = %q, want %q", got, wantFile)
	}

	for _, model := range []string{"z/m", "a/m"} {
		if reason, cat, err := c.DeleteOpenRouterQuantization(model); reason != ReasonNone || err != nil {
			t.Fatalf("DeleteOpenRouterQuantization(%s) = (%q, %q, %v), want success", model, reason, cat, err)
		}
	}
	if got := c.OpenRouterQuantizations(); len(got) != 0 {
		t.Fatalf("OpenRouterQuantizations() after delete = %+v, want none", got)
	}
	if got := readAt(t, global); got != openRouterRoutingSeed {
		t.Fatalf("settings after delete = %q, want the seed back", got)
	}
	if reason, cat, err := c.DeleteOpenRouterQuantization("never/set"); reason != ReasonNone || err != nil {
		t.Fatalf("DeleteOpenRouterQuantization(absent) = (%q, %q, %v), want a successful no-op", reason, cat, err)
	}
}

func TestCacheOpenRouterQuantization_RejectsBeforePersisting(t *testing.T) {
	c, _ := openRouterSettingsCache(t, openRouterRoutingSeed)
	for name, tc := range map[string]struct {
		prefix string
		write  func() (PersistReason, fserrors.Category, error)
	}{
		"empty model": {"config.SetOpenRouterQuantization: ", func() (PersistReason, fserrors.Category, error) {
			return c.SetOpenRouterQuantization("", provider.Quantization{Levels: []string{"fp8"}, Mode: "preferred"})
		}},
		"empty model delete": {"config.DeleteOpenRouterQuantization: ", func() (PersistReason, fserrors.Category, error) { return c.DeleteOpenRouterQuantization("") }},
		"no levels": {"config.SetOpenRouterQuantization: ", func() (PersistReason, fserrors.Category, error) {
			return c.SetOpenRouterQuantization("a/m", provider.Quantization{Mode: "preferred"})
		}},
		"unknown level": {"config.SetOpenRouterQuantization: ", func() (PersistReason, fserrors.Category, error) {
			return c.SetOpenRouterQuantization("a/m", provider.Quantization{Levels: []string{"fp9"}, Mode: "preferred"})
		}},
		"invalid mode": {"config.SetOpenRouterQuantization: ", func() (PersistReason, fserrors.Category, error) {
			return c.SetOpenRouterQuantization("a/m", provider.Quantization{Levels: []string{"fp8"}, Mode: ""})
		}},
	} {
		reason, _, err := tc.write()
		if reason != ReasonRereadParseError || err == nil || !strings.HasPrefix(err.Error(), tc.prefix) {
			t.Errorf("%s = (%q, %v), want a %q refusal before Persist", name, reason, err, tc.prefix)
		}
	}
}

func TestCacheOpenRouterQuantization_PersistFailureLeavesCache(t *testing.T) {
	c, global := openRouterSettingsCache(t, openRouterRoutingSeed+"      quantizations: {a/m: {levels: [fp8], mode: preferred}}\n")
	const external = "provider:\n  venice:\n    base_url: v\n    api_key: k\n"
	writeAt(t, global, external)
	before := c.OpenRouterQuantizations()
	for name, write := range map[string]func() (PersistReason, fserrors.Category, error){
		"set": func() (PersistReason, fserrors.Category, error) {
			return c.SetOpenRouterQuantization("b/m", provider.Quantization{Levels: []string{"fp4"}, Mode: "required"})
		},
		"delete": func() (PersistReason, fserrors.Category, error) { return c.DeleteOpenRouterQuantization("a/m") },
	} {
		if _, _, err := write(); err == nil {
			t.Fatalf("%s succeeded against a file without provider.openrouter", name)
		}
		if got := c.OpenRouterQuantizations(); !reflect.DeepEqual(got, before) {
			t.Fatalf("failed %s changed the cache: %+v, want %+v", name, got, before)
		}
		if got := readAt(t, global); got != external {
			t.Fatalf("failed %s changed the file: %q", name, got)
		}
	}
}

func assertOpenRouterRouting(t *testing.T, c *Cache, want provider.Routing) {
	t.Helper()
	entry, ok := c.Provider("openrouter")
	if !ok || entry.BaseURL != "u" || entry.APIKey != "k" || !reflect.DeepEqual(entry.Routing, want) {
		t.Fatalf("cached openrouter = %+v (ok=%v), want routing %+v", entry, ok, want)
	}
}

func TestCacheOpenRouterRouting_SettersRefuseWithoutChanges(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed string
		set  func(*Cache) (PersistReason, fserrors.Category, error)
	}{
		{"missing openrouter entry", "provider:\n  venice:\n    base_url: v\n    api_key: k\n", func(c *Cache) (PersistReason, fserrors.Category, error) { return c.SetOpenRouterSort("throughput") }},
		{"missing openrouter entry for data_collection", "attribution: true\n", func(c *Cache) (PersistReason, fserrors.Category, error) { return c.SetOpenRouterDataCollection("deny") }},
		{"out-of-set sort", openRouterRoutingSeed, func(c *Cache) (PersistReason, fserrors.Category, error) { return c.SetOpenRouterSort("price") }},
		{"latency sort", openRouterRoutingSeed, func(c *Cache) (PersistReason, fserrors.Category, error) { return c.SetOpenRouterSort("latency") }},
		{"out-of-set data_collection", openRouterRoutingSeed, func(c *Cache) (PersistReason, fserrors.Category, error) { return c.SetOpenRouterDataCollection("") }},
		{"missing openrouter entry for max_price", "attribution: true\n", func(c *Cache) (PersistReason, fserrors.Category, error) {
			return c.SetOpenRouterMaxPrice("a/m", provider.MaxPrice{Prompt: 1, HasPrompt: true})
		}},
		{"negative max_price", openRouterRoutingSeed, func(c *Cache) (PersistReason, fserrors.Category, error) {
			return c.SetOpenRouterMaxPrice("a/m", provider.MaxPrice{Completion: -0.5, HasCompletion: true})
		}},
		{"not-a-number max_price", openRouterRoutingSeed, func(c *Cache) (PersistReason, fserrors.Category, error) {
			return c.SetOpenRouterMaxPrice("a/m", provider.MaxPrice{Prompt: math.NaN(), HasPrompt: true})
		}},
		{"infinite max_price", openRouterRoutingSeed, func(c *Cache) (PersistReason, fserrors.Category, error) {
			return c.SetOpenRouterMaxPrice("a/m", provider.MaxPrice{Prompt: math.Inf(1), HasPrompt: true})
		}},
		{"empty max_price model id", openRouterRoutingSeed, func(c *Cache) (PersistReason, fserrors.Category, error) {
			return c.SetOpenRouterMaxPrice("", provider.MaxPrice{Prompt: 1, HasPrompt: true})
		}},
		{"empty quantizations model id", openRouterRoutingSeed, func(c *Cache) (PersistReason, fserrors.Category, error) {
			return c.SetOpenRouterQuantization("", provider.Quantization{Levels: []string{"fp8"}, Mode: "preferred"})
		}},
		{"empty quantizations model id on delete", openRouterRoutingSeed, func(c *Cache) (PersistReason, fserrors.Category, error) {
			return c.DeleteOpenRouterQuantization("")
		}},
		{"empty quantizations levels", openRouterRoutingSeed, func(c *Cache) (PersistReason, fserrors.Category, error) {
			return c.SetOpenRouterQuantization("a/m", provider.Quantization{Levels: []string{}, Mode: "preferred"})
		}},
		{"unknown quantizations level", openRouterRoutingSeed, func(c *Cache) (PersistReason, fserrors.Category, error) {
			return c.SetOpenRouterQuantization("a/m", provider.Quantization{Levels: []string{"fp8", "fp9"}, Mode: "preferred"})
		}},
		{"duplicate quantizations level", openRouterRoutingSeed, func(c *Cache) (PersistReason, fserrors.Category, error) {
			return c.SetOpenRouterQuantization("a/m", provider.Quantization{Levels: []string{"fp8", "fp8"}, Mode: "required"})
		}},
		{"invalid quantizations mode", openRouterRoutingSeed, func(c *Cache) (PersistReason, fserrors.Category, error) {
			return c.SetOpenRouterQuantization("a/m", provider.Quantization{Levels: []string{"fp8"}, Mode: "strict"})
		}},
		{"missing openrouter entry for quantizations", "attribution: true\n", func(c *Cache) (PersistReason, fserrors.Category, error) {
			return c.DeleteOpenRouterQuantization("a/m")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, global := openRouterSettingsCache(t, tc.seed)
			before := c.Providers()
			reason, cat, err := tc.set(c)
			if reason != ReasonRereadParseError || cat != "" || err == nil {
				t.Fatalf("= (%q, %q, %v), want (reread_parse_error, \"\", error)", reason, cat, err)
			}
			if got := readAt(t, global); got != tc.seed {
				t.Errorf("refused setter changed the file:\n%s", got)
			}
			if after := c.Providers(); !reflect.DeepEqual(after, before) {
				t.Errorf("refused setter changed the cache: %+v, want %+v", after, before)
			}
		})
	}
}

func TestCacheSetOpenRouterConnection_KeepsRoutingAndAuthHeader(t *testing.T) {
	c, _ := openRouterSettingsCache(t, "provider:\n  openrouter:\n    base_url: u\n    api_key: k\n    auth_header: {name: X-Key, value: \"{api_key}\"}\n    routing:\n      require_parameters: true\n      max_price: {a/m: {prompt: 1}}\n")
	if reason, cat, err := c.SetOpenRouterSort("best_value"); reason != ReasonNone || err != nil {
		t.Fatalf("SetOpenRouterSort = (%q, %q, %v)", reason, cat, err)
	}
	if reason, cat, err := c.SetOpenRouterDataCollection("deny"); reason != ReasonNone || err != nil {
		t.Fatalf("SetOpenRouterDataCollection = (%q, %q, %v)", reason, cat, err)
	}

	c.SetOpenRouterConnection("u2", "k2")

	want := provider.ProviderEntry{BaseURL: "u2", APIKey: "k2", AuthHeader: &provider.AuthHeader{Name: "X-Key", Value: "{api_key}"}, Routing: provider.Routing{
		Sort: "best_value", DataCollection: "deny", RequireParameters: true,
		MaxPrice: map[string]provider.MaxPrice{"a/m": {Prompt: 1, HasPrompt: true}},
	}}
	if got, ok := c.Provider("openrouter"); !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("openrouter = %+v (ok=%v), want %+v", got, ok, want)
	}
}

func TestCacheOpenRouterRouting_WriteFailureLeavesCacheUnchanged(t *testing.T) {
	seed := openRouterRoutingSeed + "      sort: latency\n"
	c, global := openRouterSettingsCache(t, seed)
	want, _ := c.Provider("openrouter")
	wantRouting := provider.Routing{
		Sort: "latency", DataCollection: "deny", RequireParameters: true,
		MaxPrice: map[string]provider.MaxPrice{"a/m": {Prompt: 1, HasPrompt: true}},
	}
	if want.BaseURL != "u" || want.APIKey != "k" || !reflect.DeepEqual(want.Routing, wantRouting) {
		t.Fatalf("seeded openrouter = %+v, want connection u/k and routing %+v", want, wantRouting)
	}
	sentinel := errors.New("forced temp-file sync failure")
	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)

	reason, cat, err := c.SetOpenRouterSort("throughput")
	if reason != ReasonWriteError || cat != fserrors.IOError || !errors.Is(err, sentinel) {
		t.Fatalf("= (%q, %q, %v), want (write_error, io_error, wrap of sentinel)", reason, cat, err)
	}
	restore()

	if after, ok := c.Provider("openrouter"); !ok || !reflect.DeepEqual(after, want) {
		t.Errorf("openrouter after a failed write = %+v (ok=%v), want %+v", after, ok, want)
	}
	if got := readAt(t, global); got != seed {
		t.Errorf("failed write changed bytes:\n%s", got)
	}
}

func seedVeniceWindows(t *testing.T, storePath string, models ...DiscoveredModel) {
	t.Helper()
	if err := UpdateDiscoveredModelsProvider(storePath, "venice", DiscoveredProvider{Models: models}); err != nil {
		t.Fatalf("seed venice store: %v", err)
	}
}

func veniceComposed(windows map[string]any) map[string]any {
	entry := map[string]any{"base_url": "https://api.venice.ai/v1", "api_key": "vk-test"}
	if windows != nil {
		entry["context_windows"] = windows
	}
	return map[string]any{"provider": map[string]any{
		"venice": entry,
		"other":  map[string]any{"base_url": "https://other.example/v1", "api_key": "ok-test"},
	}}
}

func TestCacheContextWindowLookup(t *testing.T) {
	globalPath := filepath.Join(t.TempDir(), "settings.yaml")
	storePath := DiscoveredModelsPath(globalPath)
	if err := UpdateDiscoveredModelsProvider(storePath, provider.ChatGPTProviderID, DiscoveredProvider{
		Models: []DiscoveredModel{{ID: "gpt-chat", ContextWindow: 400000}},
	}); err != nil {
		t.Fatalf("seed chatgpt store: %v", err)
	}
	seedVeniceWindows(t, storePath,
		DiscoveredModel{ID: "v-disc", ContextWindow: 32768},
		DiscoveredModel{ID: "v-zero"},
		DiscoveredModel{ID: "v-neg", ContextWindow: -5},
		DiscoveredModel{ID: "v-both", ContextWindow: 1000},
	)
	c := newCacheOrFatal(t, veniceComposed(map[string]any{
		"v-conf": uint64(8192),
		"v-both": uint64(4096),
	}), t.TempDir(), []string{globalPath})

	cases := []struct {
		provider, model string
		want            int64
	}{
		{provider.ChatGPTProviderID, "gpt-chat", 400000},
		{"venice", "v-disc", 32768},
		{"venice", "v-conf", 8192},
		{"venice", "v-both", 4096},
		{"venice", "v-zero", 0},
		{"venice", "v-neg", 0},
		{"venice", "v-missing", 0},
		{"missing", "v-conf", 0},
		{"other", "v-conf", 0},
		{"other", "v-disc", 0},
		{"venice", "gpt-chat", 0},
		{provider.ChatGPTProviderID, "v-disc", 0},
	}
	for _, tc := range cases {
		if got := c.ContextWindow(tc.provider, tc.model); got != tc.want {
			t.Errorf("ContextWindow(%q, %q) = %d, want %d", tc.provider, tc.model, got, tc.want)
		}
	}

	venice, ok := c.SelectableCatalog().Entry("venice")
	if !ok {
		t.Fatal("catalog missing venice")
	}
	if want := []string{"v-disc", "v-zero", "v-neg", "v-both"}; !reflect.DeepEqual(venice.Models, want) {
		t.Errorf("venice catalog models = %v, want %v (window declarations add no model)", venice.Models, want)
	}
}

func TestCacheContextWindowRebuilds(t *testing.T) {
	globalPath := filepath.Join(t.TempDir(), "settings.yaml")
	storePath := DiscoveredModelsPath(globalPath)
	c := newCacheOrFatal(t, veniceComposed(nil), t.TempDir(), []string{globalPath})

	seedVeniceWindows(t, storePath, DiscoveredModel{ID: "m1", ContextWindow: 2048})
	if got := c.ContextWindow("venice", "m1"); got != 0 {
		t.Fatalf("before reload ContextWindow = %d, want 0 (store read only on rebuild)", got)
	}
	c.ReloadDiscoveredCatalog()
	if got := c.ContextWindow("venice", "m1"); got != 2048 {
		t.Fatalf("after ReloadDiscoveredCatalog ContextWindow = %d, want 2048", got)
	}

	seedVeniceWindows(t, storePath, DiscoveredModel{ID: "m1", ContextWindow: 3072})
	c.SetProvider("venice", provider.ProviderEntry{BaseURL: "u", APIKey: "k", ContextWindows: map[string]int64{"m2": 5000}})
	if got := c.ContextWindow("venice", "m1"); got != 3072 {
		t.Errorf("after SetProvider ContextWindow(m1) = %d, want 3072 re-read from the store", got)
	}
	if got := c.ContextWindow("venice", "m2"); got != 5000 {
		t.Errorf("after SetProvider ContextWindow(m2) = %d, want the declared 5000", got)
	}
}

func TestCacheContextWindowsIsolated(t *testing.T) {
	c := newCacheOrFatal(t, map[string]any{}, t.TempDir(), nil)
	want := map[string]int64{"m": 1000}
	supplied := map[string]int64{"m": 1000}
	c.SetProvider("venice", provider.ProviderEntry{BaseURL: "u", APIKey: "k", ContextWindows: supplied})

	supplied["m"] = 99
	supplied["x"] = 7
	got, _ := c.Provider("venice")
	if !reflect.DeepEqual(got.ContextWindows, want) || c.ContextWindow("venice", "m") != 1000 || c.ContextWindow("venice", "x") != 0 {
		t.Fatalf("after mutating the SetProvider input, ContextWindows = %v, want %v", got.ContextWindows, want)
	}

	got.ContextWindows["m"] = 99
	got.ContextWindows["x"] = 7
	if again, _ := c.Provider("venice"); !reflect.DeepEqual(again.ContextWindows, want) {
		t.Fatalf("after mutating the Provider result, ContextWindows = %v, want %v", again.ContextWindows, want)
	}

	all := c.Providers()
	all["venice"].ContextWindows["m"] = 99
	all["venice"].ContextWindows["x"] = 7
	if again, _ := c.Provider("venice"); !reflect.DeepEqual(again.ContextWindows, want) {
		t.Fatalf("after mutating the Providers result, ContextWindows = %v, want %v", again.ContextWindows, want)
	}
}

func TestCacheContextWindowStoreFallback(t *testing.T) {
	breakers := map[string]func(t *testing.T, path string){
		"missing": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		},
		"malformed": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("providers: [unclosed"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"unreadable": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, breakStore := range breakers {
		t.Run(name, func(t *testing.T) {
			globalPath := filepath.Join(t.TempDir(), "settings.yaml")
			storePath := DiscoveredModelsPath(globalPath)
			seedVeniceWindows(t, storePath, DiscoveredModel{ID: "m1", ContextWindow: 2048})
			c := newCacheOrFatal(t, veniceComposed(map[string]any{"m2": uint64(4096)}), t.TempDir(), []string{globalPath})
			if got := c.ContextWindow("venice", "m1"); got != 2048 {
				t.Fatalf("seeded ContextWindow = %d, want 2048", got)
			}

			breakStore(t, storePath)
			c.ReloadDiscoveredCatalog()
			if got := c.ContextWindow("venice", "m1"); got != 0 {
				t.Errorf("after reload of a %s store ContextWindow(m1) = %d, want 0", name, got)
			}
			if got := c.ContextWindow("venice", "m2"); got != 4096 {
				t.Errorf("after reload of a %s store ContextWindow(m2) = %d, want the declared 4096", name, got)
			}
			cat := c.SelectableCatalog()
			if venice, _ := cat.Entry("venice"); len(venice.Models) != 0 {
				t.Errorf("after reload of a %s store venice models = %v, want none", name, venice.Models)
			}
			if chatgpt, ok := cat.Entry(provider.ChatGPTProviderID); !ok || !chatgpt.Builtin {
				t.Errorf("after reload of a %s store the built-in ChatGPT row = %+v, %v, want present", name, chatgpt, ok)
			}

			fresh := newCacheOrFatal(t, veniceComposed(nil), t.TempDir(), []string{globalPath})
			if got := fresh.ContextWindow("venice", "m1"); got != 0 {
				t.Errorf("NewCache over a %s store ContextWindow(m1) = %d, want 0", name, got)
			}
		})
	}
}

func TestCacheRebuildUsesOneStoreSnapshot(t *testing.T) {
	globalPath := filepath.Join(t.TempDir(), "settings.yaml")
	storePath := DiscoveredModelsPath(globalPath)
	seedVeniceWindows(t, storePath, DiscoveredModel{ID: "a", ContextWindow: 1000})
	c := newCacheOrFatal(t, veniceComposed(nil), t.TempDir(), []string{globalPath})

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			m := DiscoveredModel{ID: "a", ContextWindow: 1000}
			if i%2 == 0 {
				m = DiscoveredModel{ID: "b", ContextWindow: 2000}
			}
			if err := UpdateDiscoveredModelsProvider(storePath, "venice", DiscoveredProvider{Models: []DiscoveredModel{m}}); err != nil {
				t.Errorf("rewrite store: %v", err)
				return
			}
		}
	}()
	defer func() {
		close(done)
		wg.Wait()
	}()

	want := map[string]int64{"a": 1000, "b": 2000}
	for i := 0; i < 300; i++ {
		c.ReloadDiscoveredCatalog()
		venice, _ := c.SelectableCatalog().Entry("venice")
		if len(venice.Models) != 1 {
			t.Fatalf("reload %d: venice models = %v, want exactly one", i, venice.Models)
		}
		listed := venice.Models[0]
		for id, w := range want {
			expect := int64(0)
			if id == listed {
				expect = w
			}
			if got := c.ContextWindow("venice", id); got != expect {
				t.Fatalf("reload %d: catalog lists %q but ContextWindow(%q) = %d, want %d (catalog and windows from different store reads)", i, listed, id, got, expect)
			}
		}
	}
}

func TestCacheContextWindowRaceSafe(t *testing.T) {
	globalPath := filepath.Join(t.TempDir(), "settings.yaml")
	seedVeniceWindows(t, DiscoveredModelsPath(globalPath), DiscoveredModel{ID: "m1", ContextWindow: 2048})
	c := newCacheOrFatal(t, veniceComposed(map[string]any{"m2": uint64(4096)}), t.TempDir(), []string{globalPath})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if got := c.ContextWindow("venice", "m1"); got != 2048 {
					t.Errorf("concurrent ContextWindow(m1) = %d, want 2048", got)
					return
				}
				_ = c.ContextWindow("venice", "m2")
			}
		}()
	}
	for i := 0; i < 50; i++ {
		c.SetProvider("venice", provider.ProviderEntry{BaseURL: "u", APIKey: "k", ContextWindows: map[string]int64{"m2": int64(4096 + i)}})
		c.ReloadDiscoveredCatalog()
	}
	wg.Wait()
}
