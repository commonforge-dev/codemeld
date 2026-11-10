package enforce_test

import (
	"testing"

	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/permissions"
)

func TestProxyRouteClassification(t *testing.T) {
	for _, tc := range []struct {
		name          string
		tokens        []string
		route, direct string
	}{
		{"recognized network command", []string{"curl", "https://plain.proxy-fixture.test/"}, "broad", "0"},
		{"unrecognized command", []string{"go", "mod", "download"}, "proxy", "EPERM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authority, _ := permissions.ExceptionalAuthority(tc.tokens)
			route, direct, viaProxy := enforce.ProxyRouteRun(t, authority)
			if route != tc.route || direct != tc.direct || viaProxy != "200 plain plain.proxy-fixture.test" {
				t.Errorf("%q classified %q: route %q, direct loopback connect %q, request through the proxy %q; want route %q, direct %q, and the proxy request served",
					tc.tokens, authority, route, direct, viaProxy, tc.route, tc.direct)
			}
		})
	}
}
