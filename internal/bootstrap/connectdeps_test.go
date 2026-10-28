package bootstrap

import (
	"os"
	"reflect"
	"testing"
)

func TestConnectDeps_ReconnectKeepsSessionContextWindows(t *testing.T) {
	const (
		veniceURL     = "https://api.venice.ai/api/v1"
		openRouterURL = "https://openrouter.ai/api/v1"
		venice        = "  venice:\n    base_url: " + veniceURL + "\n    api_key: k\n"
	)
	entry := func(id, url, key, windows string) string {
		return "  " + id + ":\n    base_url: " + url + "\n    api_key: " + key + "\n" + windows
	}
	const (
		sessionWindows = "    context_windows:\n      z/m:free: 2048\n      a/m: 4096\n"
		diskWindows    = "    context_windows:\n      disk/only: 1\n"
		wantWindows    = "    context_windows:\n      a/m: 4096\n      z/m:free: 2048\n"
	)
	session := map[string]int64{"a/m": 4096, "z/m:free": 2048}
	cases := []struct {
		name, id, seed, edited, want string
		wantLive                     map[string]int64
	}{
		{
			name:     "venice replaces a disk edit with the session map",
			id:       "venice",
			seed:     "provider:\n" + entry("venice", veniceURL, "sk-prior", sessionWindows),
			edited:   "provider:\n" + entry("venice", veniceURL, "sk-prior", diskWindows),
			want:     "provider:\n" + entry("venice", veniceURL, "sk-reconnected", wantWindows),
			wantLive: session,
		},
		{
			name:   "venice with no session map drops a declaration added after startup",
			id:     "venice",
			seed:   "provider:\n" + entry("venice", veniceURL, "sk-prior", ""),
			edited: "provider:\n" + entry("venice", veniceURL, "sk-prior", diskWindows),
			want:   "provider:\n" + entry("venice", veniceURL, "sk-reconnected", ""),
		},
		{
			name:     "openrouter replaces a disk edit with the session map",
			id:       "openrouter",
			seed:     "provider:\n" + entry("openrouter", openRouterURL, "sk-prior", sessionWindows) + "    routing:\n      sort: latency\n",
			edited:   "provider:\n" + entry("openrouter", openRouterURL, "sk-prior", diskWindows) + "    routing:\n      sort: latency\n",
			want:     "provider:\n" + entry("openrouter", openRouterURL, "sk-reconnected", wantWindows) + "    routing:\n      sort: latency\n",
			wantLive: session,
		},
		{
			name:     "openrouter inserts the session map when the disk entry has none",
			id:       "openrouter",
			seed:     "provider:\n" + entry("openrouter", openRouterURL, "sk-prior", sessionWindows),
			edited:   "provider:\n" + entry("openrouter", openRouterURL, "sk-prior", ""),
			want:     "provider:\n" + entry("openrouter", openRouterURL, "sk-reconnected", wantWindows),
			wantLive: session,
		},
		{
			name:     "openrouter recreates a deleted entry with the session map",
			id:       "openrouter",
			seed:     "provider:\n" + entry("openrouter", openRouterURL, "sk-prior", sessionWindows) + venice,
			edited:   "provider:\n" + venice,
			want:     "provider:\n" + venice + entry("openrouter", openRouterURL, "sk-reconnected", wantWindows),
			wantLive: session,
		},
		{
			name:   "openrouter with no session map removes a declaration added after startup",
			id:     "openrouter",
			seed:   "provider:\n" + entry("openrouter", openRouterURL, "sk-prior", ""),
			edited: "provider:\n" + entry("openrouter", openRouterURL, "sk-prior", diskWindows),
			want:   "provider:\n" + entry("openrouter", openRouterURL, "sk-reconnected", ""),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			cache, settings := openRouterRoutingCache(t, home, tc.seed)
			writeGlobalSettings(t, home, tc.edited, 0o600)

			for range 2 {
				reconnectProvider(t, home, cache, tc.id)
				if got, _ := os.ReadFile(settings); string(got) != tc.want {
					t.Fatalf("persisted settings:\n%s\nwant:\n%s", got, tc.want)
				}
				if live, _ := cache.Provider(tc.id); !reflect.DeepEqual(live.ContextWindows, tc.wantLive) {
					t.Fatalf("live context windows = %v, want %v", live.ContextWindows, tc.wantLive)
				}
			}
		})
	}
}
