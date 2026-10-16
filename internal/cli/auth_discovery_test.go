// Tests that `codemeld auth login` (connect) fires ChatGPT model discovery on a
// successful connect only, targets the shared cache path with the session credentials,
// and degrades gracefully when discovery fails — without letting any cli unit test reach
// the real discovery network.
package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/authstate"
	"codemeld.dev/codemeld/internal/bootstrap"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/openaiauth"
	"codemeld.dev/codemeld/internal/provider"
)

// TestMain neuters the discovery seam by default so no cli unit test dials the real
// ChatGPT endpoint; tests that exercise the connect->discovery wiring install their own
// stub below, and the discovery transport itself is covered in the provider package.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == enforce.HelperCommand {
		os.Exit(Run(context.Background(), os.Args, os.Stdout, os.Stderr))
	}
	refreshChatGPTModels = func(context.Context, provider.ChatGPTClientConfig, string) error {
		return nil
	}
	os.Exit(m.Run())
}

// stubRefreshDiscovery installs fn as the discovery seam for one test and restores it.
func stubRefreshDiscovery(t *testing.T, fn func(context.Context, provider.ChatGPTClientConfig, string) error) {
	t.Helper()
	prev := refreshChatGPTModels
	refreshChatGPTModels = fn
	t.Cleanup(func() { refreshChatGPTModels = prev })
}

func TestChatGPTConnectTriggersDiscovery(t *testing.T) {
	home := t.TempDir()
	stubLoginHome(t, home)
	stubInteractive(t, true)

	tok := openaiauth.TokenResult{
		AccessToken:  "ACCESS-SECRET",
		RefreshToken: "REFRESH-SECRET",
		Expiry:       time.Now().Add(time.Hour).Format(time.RFC3339),
		AccountID:    "acct-SECRET",
	}
	stubLoginFlow(t, func(context.Context, io.Writer) (openaiauth.TokenResult, error) {
		return tok, nil
	})

	var gotCfg provider.ChatGPTClientConfig
	var gotPath string
	calls := 0
	stubRefreshDiscovery(t, func(ctx context.Context, cfg provider.ChatGPTClientConfig, path string) error {
		calls++
		gotCfg, gotPath = cfg, path
		if _, ok := ctx.Deadline(); !ok {
			t.Errorf("discovery ctx has no deadline; connect discovery must be bounded")
		}
		return nil
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "login", "openai-chatgpt"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	if calls != 1 {
		t.Fatalf("discovery called %d times, want exactly 1", calls)
	}
	// discovery gets only the access token and account id, never the refresh token.
	if gotCfg.AccessToken != tok.AccessToken || gotCfg.AccountID != tok.AccountID {
		t.Fatalf("discovery cfg = %+v, want access/account from the fresh token", gotCfg)
	}
	// the writer must target the shared models.yaml store beside global settings, the same
	// path the catalog reader derives, so the discovered entry is read back.
	wantPath := config.DiscoveredModelsPath(bootstrap.SettingsPath(home))
	if gotPath != wantPath {
		t.Fatalf("discovery store path = %q, want %q", gotPath, wantPath)
	}
}

// The production write half — chatGPTDiscoveredProvider adapting into the shared store,
// then config.UpdateDiscoveredModelsProvider persisting it — must land an openai-chatgpt
// entry in models.yaml holding only sanitized selection metadata, owner-only, and must
// never let a prompt-bearing or secret-shaped field reach disk.
func TestChatGPTDiscoveredProviderWritesSanitizedStore(t *testing.T) {
	modelsPath := config.DiscoveredModelsPath(bootstrap.SettingsPath(t.TempDir()))

	entry := chatGPTDiscoveredProvider([]provider.ChatGPTStoreModel{{
		ID:            "gpt-5.6",
		DisplayName:   "GPT-5.6",
		ContextWindow: 400000,
		Capabilities: map[string]any{
			"supported_reasoning_levels": []any{"low", "high", "xhigh"},
			// A stray secret-shaped field must be redacted by the store write backstop.
			"api_key": "sk-should-not-persist",
		},
	}})
	if err := config.UpdateDiscoveredModelsProvider(modelsPath, chatGPTProviderID, entry); err != nil {
		t.Fatalf("UpdateDiscoveredModelsProvider() error = %v", err)
	}

	store, err := config.ReadDiscoveredModels(modelsPath)
	if err != nil {
		t.Fatalf("ReadDiscoveredModels() error = %v", err)
	}
	prov, ok := store.Providers[chatGPTProviderID]
	if !ok {
		t.Fatalf("store has no %q entry: %+v", chatGPTProviderID, store.Providers)
	}
	if len(prov.Models) != 1 || prov.Models[0].ID != "gpt-5.6" || prov.Models[0].DisplayName != "GPT-5.6" {
		t.Fatalf("persisted models = %+v, want one gpt-5.6/GPT-5.6", prov.Models)
	}

	raw, err := os.ReadFile(modelsPath)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	for _, forbidden := range []string{"api_key", "sk-should-not-persist"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("store leaked secret-shaped %q:\n%s", forbidden, raw)
		}
	}
	if !strings.Contains(string(raw), "xhigh") {
		t.Fatalf("store dropped whitelisted reasoning levels:\n%s", raw)
	}

	info, err := os.Stat(modelsPath)
	if err != nil {
		t.Fatalf("stat store: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("store mode = %o, want 0600 (account-linked availability stays owner-only)", perm)
	}
}

// roundTripFunc adapts a function to http.RoundTripper so a test can inject a
// no-network discovery transport into provider.ChatGPTClientConfig.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestLiveRefreshChatGPTModelsWritesStore pins the production discovery-to-store
// composition: liveRefreshChatGPTModels must run RefreshChatGPTModelCache with the
// session credentials and persist the sanitized result into the real models.yaml store
// under the openai-chatgpt entry. Injecting a fake transport (not the seam stub) means
// the test fails if the closure stops calling config.UpdateDiscoveredModelsProvider,
// writes the wrong provider id, or lets a token/account/prompt-bearing field reach disk.
func TestLiveRefreshChatGPTModelsWritesStore(t *testing.T) {
	body := `{"models":[{"slug":"gpt-5.6","display_name":"GPT-5.6","context_window":400000,` +
		`"input_modalities":["text"],"supported_reasoning_levels":["low","high","xhigh"],` +
		`"base_instructions":"SECRET-PROMPT-LEAK","model_messages":["SECRET-MSG"]}]}`
	stub := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})}

	modelsPath := config.DiscoveredModelsPath(bootstrap.SettingsPath(t.TempDir()))
	cfg := provider.ChatGPTClientConfig{AccessToken: "ACCESS-SECRET", AccountID: "acct-SECRET", HTTPClient: stub}
	if err := liveRefreshChatGPTModels(context.Background(), cfg, modelsPath); err != nil {
		t.Fatalf("liveRefreshChatGPTModels() error = %v", err)
	}

	store, err := config.ReadDiscoveredModels(modelsPath)
	if err != nil {
		t.Fatalf("ReadDiscoveredModels() error = %v", err)
	}
	prov, ok := store.Providers[chatGPTProviderID]
	if !ok {
		t.Fatalf("store has no %q entry: %+v", chatGPTProviderID, store.Providers)
	}
	if prov.Source != chatGPTDiscoverSource {
		t.Fatalf("store source = %q, want %q", prov.Source, chatGPTDiscoverSource)
	}
	if len(prov.Models) != 1 {
		t.Fatalf("persisted models = %+v, want exactly one", prov.Models)
	}
	m := prov.Models[0]
	if m.ID != "gpt-5.6" || m.DisplayName != "GPT-5.6" || m.ContextWindow != 400000 {
		t.Fatalf("persisted model = %+v, want gpt-5.6/GPT-5.6/400000", m)
	}

	raw, err := os.ReadFile(modelsPath)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	for _, leak := range []string{"ACCESS-SECRET", "acct-SECRET", "base_instructions", "SECRET-PROMPT-LEAK", "model_messages", "SECRET-MSG"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("store leaked %q:\n%s", leak, raw)
		}
	}
	if !strings.Contains(string(raw), "xhigh") {
		t.Fatalf("store dropped whitelisted reasoning levels:\n%s", raw)
	}
}

func TestChatGPTConnectDiscoveryFailureDegrades(t *testing.T) {
	home := t.TempDir()
	stubLoginHome(t, home)
	stubInteractive(t, true)

	now := time.Now()
	expiry := now.Add(time.Hour).Format(time.RFC3339)
	tok := openaiauth.TokenResult{
		AccessToken:  "ACCESS-SECRET",
		RefreshToken: "REFRESH-SECRET",
		Expiry:       expiry,
		AccountID:    "acct-SECRET",
	}
	stubLoginFlow(t, func(context.Context, io.Writer) (openaiauth.TokenResult, error) {
		return tok, nil
	})
	stubRefreshDiscovery(t, func(context.Context, provider.ChatGPTClientConfig, string) error {
		return errors.New("discovery boom")
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "login", "openai-chatgpt"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("discovery failure broke login: exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}

	// login still persisted the session despite the discovery failure.
	path := bootstrap.SettingsPath(home)
	_, status, err := authstate.Load(path, now)
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if status != authstate.StatusPresent {
		t.Fatalf("status = %q, want %q (session must persist despite discovery failure)", status, authstate.StatusPresent)
	}

	out := stdout.String() + stderr.String()
	for _, leak := range []string{"discovery boom", "ACCESS-SECRET", "REFRESH-SECRET", "acct-SECRET"} {
		if strings.Contains(out, leak) {
			t.Fatalf("login output leaked %q on discovery failure:\n%s", leak, out)
		}
	}
}

func TestChatGPTConnectFailureSkipsDiscovery(t *testing.T) {
	stubLoginHome(t, t.TempDir())
	stubInteractive(t, true)
	stubLoginFlow(t, func(context.Context, io.Writer) (openaiauth.TokenResult, error) {
		return openaiauth.TokenResult{}, errors.New("login denied")
	})

	called := false
	stubRefreshDiscovery(t, func(context.Context, provider.ChatGPTClientConfig, string) error {
		called = true
		return nil
	})

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"codemeld", "auth", "login", "openai-chatgpt"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero on login failure")
	}
	if called {
		t.Fatalf("discovery fired on a failed login; it must run only on a successful connect")
	}
}
