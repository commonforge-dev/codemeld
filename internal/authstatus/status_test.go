// Tests for the offline OpenAI auth-status collector and renderers: state
// classification, JSON shape/order, redaction, project-local isolation, and the
// offline (no provider client) guarantee.
package authstatus

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// secret fragments that must never appear in any rendered status output.
const (
	secretAPIKey  = "sk-SECRETPLATFORMKEY"
	secretAccess  = "SECRET-ACCESS-TOKEN-VALUE"
	secretRefresh = "SECRET-REFRESH-TOKEN-VALUE"
	secretAccount = "acct-SECRET-9999"
)

func writeSettings(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	return path
}

// chatGPTBlock renders an auth.openai-chatgpt block with the given expiry.
func chatGPTBlock(expiresAt string) string {
	return "auth:\n" +
		"  openai-chatgpt:\n" +
		"    access_token: " + secretAccess + "\n" +
		"    refresh_token: " + secretRefresh + "\n" +
		"    expires_at: " + expiresAt + "\n" +
		"    account_id: " + secretAccount + "\n"
}

func platformBlock(key string) string {
	return "provider:\n" +
		"  openai:\n" +
		"    base_url: https://api.openai.com/v1\n" +
		"    api_key: " + key + "\n"
}

// clearOpenAIEnv removes OPENAI_API_KEY for tests that exercise the configured /
// none Platform paths (t.Setenv restores it afterward).
func clearOpenAIEnv(t *testing.T) {
	t.Helper()
	t.Setenv(openAIAPIKeyEnv, "")
}

func findProvider(t *testing.T, r Report, id string) ProviderStatus {
	t.Helper()
	for _, p := range r.Providers {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("provider %q not in report %+v", id, r.Providers)
	return ProviderStatus{}
}

func TestCollect_Platform(t *testing.T) {
	now := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	future := now.Add(24 * time.Hour).Format(time.RFC3339)

	t.Run("env wins and source is env", func(t *testing.T) {
		t.Setenv(openAIAPIKeyEnv, secretAPIKey)
		// A configured key is also present; env must still win and not be revealed.
		path := writeSettings(t, platformBlock("CONFIGURED-KEY-IGNORED"))
		r, err := Collect(path, now)
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		p := findProvider(t, r, "openai")
		if p.Source != SourceEnv || p.State != StateUsingAPIKey || !p.Authenticated {
			t.Fatalf("platform = %+v, want env/using_api_key/authenticated", p)
		}
	})

	t.Run("configured key resolves to global_settings", func(t *testing.T) {
		clearOpenAIEnv(t)
		path := writeSettings(t, platformBlock(secretAPIKey))
		r, err := Collect(path, now)
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		p := findProvider(t, r, "openai")
		if p.Source != SourceGlobalSettings || p.State != StateUsingAPIKey || !p.Authenticated {
			t.Fatalf("platform = %+v, want global_settings/using_api_key/authenticated", p)
		}
	})

	t.Run("empty configured key is no_api_key", func(t *testing.T) {
		clearOpenAIEnv(t)
		path := writeSettings(t, platformBlock(`""`)+chatGPTBlock(future))
		r, err := Collect(path, now)
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		p := findProvider(t, r, "openai")
		if p.Source != SourceNone || p.State != StateNoAPIKey || p.Authenticated {
			t.Fatalf("platform = %+v, want none/no_api_key/unauthenticated", p)
		}
	})

	t.Run("absent settings file is no_api_key", func(t *testing.T) {
		clearOpenAIEnv(t)
		r, err := Collect(filepath.Join(t.TempDir(), "missing.yaml"), now)
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		p := findProvider(t, r, "openai")
		if p.Source != SourceNone || p.State != StateNoAPIKey {
			t.Fatalf("platform = %+v, want none/no_api_key", p)
		}
	})
}

func TestCollect_ChatGPT(t *testing.T) {
	now := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	future := now.Add(24 * time.Hour).Format(time.RFC3339)
	past := now.Add(-24 * time.Hour).Format(time.RFC3339)
	clearOpenAIEnv(t)

	cases := []struct {
		name      string
		body      string
		wantState State
		wantAuth  bool
		wantSrc   Source
	}{
		{"present", chatGPTBlock(future), StateLocalSessionPresent, true, SourceGlobalSettings},
		{"expired", chatGPTBlock(past), StateLocalSessionExpired, false, SourceGlobalSettings},
		{"invalid missing field", "auth:\n  openai-chatgpt:\n    access_token: " + secretAccess + "\n", StateLocalSessionInvalid, false, SourceGlobalSettings},
		{"invalid extra field", chatGPTBlock(future) + "    extra: x\n", StateLocalSessionInvalid, false, SourceGlobalSettings},
		{"none", platformBlock(`""`), StateNoLocalSession, false, SourceNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeSettings(t, tc.body)
			r, err := Collect(path, now)
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}
			p := findProvider(t, r, "openai-chatgpt")
			if p.State != tc.wantState || p.Authenticated != tc.wantAuth || p.Source != tc.wantSrc {
				t.Fatalf("chatgpt = %+v, want state=%s auth=%v src=%s", p, tc.wantState, tc.wantAuth, tc.wantSrc)
			}
			if p.Kind != KindChatGPTSubscription {
				t.Fatalf("chatgpt kind = %q, want chatgpt_subscription", p.Kind)
			}
		})
	}
}

func TestCollect_OrderAndKinds(t *testing.T) {
	clearOpenAIEnv(t)
	now := time.Now()
	path := writeSettings(t, platformBlock(secretAPIKey)+chatGPTBlock(now.Add(time.Hour).Format(time.RFC3339)))
	r, err := Collect(path, now)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(r.Providers) != 2 {
		t.Fatalf("providers len = %d, want 2", len(r.Providers))
	}
	if r.Providers[0].ID != "openai" || r.Providers[1].ID != "openai-chatgpt" {
		t.Fatalf("order = %q,%q, want openai,openai-chatgpt", r.Providers[0].ID, r.Providers[1].ID)
	}
	if r.Providers[0].Kind != KindAPIKey || r.Providers[1].Kind != KindChatGPTSubscription {
		t.Fatalf("kinds = %q,%q", r.Providers[0].Kind, r.Providers[1].Kind)
	}
}

func TestCollect_CorruptFileErrors(t *testing.T) {
	clearOpenAIEnv(t)
	path := writeSettings(t, "provider: [this is not a mapping\n")
	if _, err := Collect(path, time.Now()); err == nil {
		t.Fatal("Collect on corrupt YAML returned nil error, want error")
	}
}

// TestCollect_SchemaInvalidErrors proves a non-ChatGPT schema violation in the
// global settings fails status (CLI error), rather than being silently ignored and
// reported as unauthenticated. The ChatGPT-session exception is verified separately
// by the "invalid" cases in TestCollect_ChatGPT, which stay schema-valid here.
func TestCollect_SchemaInvalidErrors(t *testing.T) {
	clearOpenAIEnv(t)
	cases := []struct {
		name string
		body string
	}{
		{"agent.max_concurrency wrong type", "agent:\n  max_concurrency: \"three\"\n"},
		{"discovery.boundary not in enum", "discovery:\n  boundary: nonsense\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeSettings(t, tc.body)
			if _, err := Collect(path, time.Now()); err == nil {
				t.Fatalf("Collect on schema-invalid settings (%s) returned nil error, want error", tc.name)
			}
		})
	}
}

// TestCollect_EmptyFileIsSourceNone proves a boundary-valid empty settings file
// passes schema validation and reports both providers as unauthenticated with
// source none, rather than failing the command.
func TestCollect_EmptyFileIsSourceNone(t *testing.T) {
	clearOpenAIEnv(t)
	path := writeSettings(t, "")
	r, err := Collect(path, time.Now())
	if err != nil {
		t.Fatalf("Collect on empty settings: %v", err)
	}
	plat := findProvider(t, r, "openai")
	cg := findProvider(t, r, "openai-chatgpt")
	if plat.Source != SourceNone || plat.State != StateNoAPIKey {
		t.Fatalf("platform = %+v, want none/no_api_key", plat)
	}
	if cg.Source != SourceNone || cg.State != StateNoLocalSession {
		t.Fatalf("chatgpt = %+v, want none/no_local_session", cg)
	}
}

// TestCollect_ProjectLocalIsolation proves that a project-local settings file in the
// working directory cannot influence status: only the explicit global path is read.
func TestCollect_ProjectLocalIsolation(t *testing.T) {
	clearOpenAIEnv(t)
	now := time.Now()

	// A project-local settings file with a key and a session, placed where a
	// compose step would find it; status must ignore it entirely.
	projDir := t.TempDir()
	projSettings := filepath.Join(projDir, ".codemeld")
	if err := os.MkdirAll(projSettings, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projSettings, "settings.yaml"),
		[]byte(platformBlock(secretAPIKey)+chatGPTBlock(now.Add(time.Hour).Format(time.RFC3339))), 0o600); err != nil {
		t.Fatalf("write project settings: %v", err)
	}
	cwd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(projDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	// Global settings: empty. Status reads only this path.
	globalPath := writeSettings(t, "")
	r, err := Collect(globalPath, now)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	plat := findProvider(t, r, "openai")
	cg := findProvider(t, r, "openai-chatgpt")
	if plat.State != StateNoAPIKey || cg.State != StateNoLocalSession {
		t.Fatalf("project-local settings leaked into status: platform=%+v chatgpt=%+v", plat, cg)
	}
}

// TestRender_Redaction asserts no key, token, or account identifier appears in
// either human or JSON output even when every credential is populated.
func TestRender_Redaction(t *testing.T) {
	t.Setenv(openAIAPIKeyEnv, secretAPIKey)
	now := time.Now()
	path := writeSettings(t, platformBlock(secretAPIKey)+chatGPTBlock(now.Add(time.Hour).Format(time.RFC3339)))
	r, err := Collect(path, now)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	secrets := []string{secretAPIKey, secretAccess, secretRefresh, secretAccount}
	for _, asJSON := range []bool{false, true} {
		var buf bytes.Buffer
		if err := Render(&buf, r, asJSON); err != nil {
			t.Fatalf("Render(json=%v): %v", asJSON, err)
		}
		out := buf.String()
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Fatalf("render(json=%v) leaked secret %q in:\n%s", asJSON, s, out)
			}
		}
	}
}

func TestRenderHuman_Wording(t *testing.T) {
	clearOpenAIEnv(t)
	now := time.Now()
	path := writeSettings(t, platformBlock(secretAPIKey)+chatGPTBlock(now.Add(time.Hour).Format(time.RFC3339)))
	r, err := Collect(path, now)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var buf bytes.Buffer
	if err := RenderHuman(&buf, r); err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"OpenAI Platform: using API key (source: global settings file)",
		"OpenAI ChatGPT: local session present — ChatGPT subscription access may be used where upstream entitlement and access policy allow it",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("human output missing %q, got:\n%s", want, out)
		}
	}
}

func TestRenderHuman_EnvSourceLabel(t *testing.T) {
	t.Setenv(openAIAPIKeyEnv, secretAPIKey)
	r, err := Collect(filepath.Join(t.TempDir(), "missing.yaml"), time.Now())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var buf bytes.Buffer
	if err := RenderHuman(&buf, r); err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	if !strings.Contains(buf.String(), "OpenAI Platform: using API key (source: env)") {
		t.Fatalf("missing env source label, got:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), secretAPIKey) {
		t.Fatalf("env source label leaked the API key, got:\n%s", buf.String())
	}
}

func TestRenderJSON_Shape(t *testing.T) {
	clearOpenAIEnv(t)
	now := time.Now()
	path := writeSettings(t, platformBlock(secretAPIKey)+chatGPTBlock(now.Add(time.Hour).Format(time.RFC3339)))
	r, err := Collect(path, now)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, r); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	var decoded struct {
		Providers []map[string]any `json:"providers"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(decoded.Providers) != 2 {
		t.Fatalf("providers len = %d, want 2", len(decoded.Providers))
	}
	first := decoded.Providers[0]
	for _, k := range []string{"id", "kind", "authenticated", "source", "state"} {
		if _, ok := first[k]; !ok {
			t.Fatalf("provider element missing key %q: %v", k, first)
		}
	}
	if first["id"] != "openai" || first["kind"] != "api_key" || first["source"] != "global_settings" || first["state"] != "using_api_key" {
		t.Fatalf("platform JSON = %v", first)
	}
	if decoded.Providers[1]["kind"] != "chatgpt_subscription" {
		t.Fatalf("chatgpt kind = %v", decoded.Providers[1]["kind"])
	}
}

// TestOffline_NoProviderClientImports proves the package cannot dial the network:
// it imports neither net/http nor the provider client constructor surface. Status
// is a local-state report only.
func TestOffline_NoProviderClientImports(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	forbidden := map[string]bool{`"net/http"`: true, `"net"`: true}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			if forbidden[imp.Path.Value] {
				t.Fatalf("%s imports %s; status must stay offline", name, imp.Path.Value)
			}
		}
	}
}

// TestOffline_NoDiscoveryConstruction proves auth status never constructs a ChatGPT
// discovery client or triggers a discovery refresh. The package may import provider for
// ids and settings parsing, but referencing provider.NewChatGPTClient or
// provider.RefreshChatGPTModelCache would route a network call through provider and
// break the offline guarantee (status never discovers) — the net/http import
// ban above cannot catch that, so scan the AST for the discovery surface directly.
func TestOffline_NoDiscoveryConstruction(t *testing.T) {
	forbidden := map[string]bool{
		"NewChatGPTClient":         true,
		"RefreshChatGPTModelCache": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if ok && pkg.Name == "provider" && forbidden[sel.Sel.Name] {
				t.Fatalf("%s references provider.%s; auth status must not construct a discovery client or discover", name, sel.Sel.Name)
			}
			return true
		})
	}
}
