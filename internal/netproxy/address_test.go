package netproxy

import (
	"errors"
	"net/http"
	"net/netip"
	"testing"
)

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func TestAddressCheck(t *testing.T) {
	own := func() ([]netip.Addr, error) {
		return addrs("::ffff:9.9.9.10", "2606:4700::10%eth0"), nil
	}
	refused := map[string]string{
		"loopback v4":               "127.0.0.1",
		"loopback v6":               "::1",
		"link-local v4":             "169.254.1.1",
		"link-local v6":             "fe80::1",
		"multicast v4":              "224.0.0.1",
		"multicast v6":              "ff02::1",
		"unspecified v4":            "0.0.0.0",
		"unspecified v6":            "::",
		"broadcast":                 "255.255.255.255",
		"10/8":                      "10.1.2.3",
		"172.16/12":                 "172.31.255.255",
		"192.168/16":                "192.168.1.1",
		"fc00::/7":                  "fd12::1",
		"100.64/10":                 "100.127.255.255",
		"this network":              "0.1.2.3",
		"reserved 240/4":            "240.0.0.1",
		"IPv4-compatible":           "::9.9.9.9",
		"local-use NAT64":           "64:ff9b:1::909:909",
		"site-local":                "fec0::1",
		"mapped loopback":           "::ffff:127.0.0.1",
		"own public via mapped own": "9.9.9.10",
		"own public mapped":         "::ffff:9.9.9.10",
		"own v6 via zoned own":      "2606:4700::10",
		"own v6 with zone":          "2606:4700::10%eth1",
		"NAT64 private":             "64:ff9b::a00:1",
		"NAT64 loopback":            "64:ff9b::7f00:1",
		"NAT64 own":                 "64:ff9b::909:90a",
		"6to4 private":              "2002:a00:1::1",
		"6to4 loopback":             "2002:7f00:1::1",
		"6to4 own":                  "2002:909:90a::1",
		"NAT64 CGNAT":               "64:ff9b::6440:1",
		"6to4 link-local":           "2002:a9fe:101::1",
	}
	for name, a := range refused {
		if got, reason := choose(addrs(a), own); reason != "not public" {
			t.Errorf("%s %s: accepted as %v", name, a, got)
		}
	}
	accepted := map[string]string{
		"9.9.9.9":          "9.9.9.9",
		"::ffff:9.9.9.9":   "9.9.9.9",
		"2606:4700::1111":  "2606:4700::1111",
		"64:ff9b::909:909": "64:ff9b::909:909",
		"2002:909:909::1":  "2002:909:909::1",
	}
	for a, want := range accepted {
		got, reason := choose(addrs("127.0.0.1", a), own)
		if reason != "" || got != netip.MustParseAddr(want) {
			t.Errorf("%s: got %v %q, want %s", a, got, reason, want)
		}
	}
}

func TestOwnAddressFailureRefuses(t *testing.T) {
	f := &fakeNet{names: map[string][]netip.Addr{"example.com": {testPublic}}, ownErr: errors.New("no interfaces")}
	s, _ := startProxy(t, f, "example.com:443")
	_, br := send(t, s, f.ask, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	resp := response(t, br, http.MethodConnect)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Proxy-Refused") != "own addresses unknown" {
		t.Fatalf("got %s %q", resp.Status, resp.Header.Get("X-Proxy-Refused"))
	}
	if r := s.Refusals(); len(r) != 1 || r[0] != (Refusal{Host: "example.com", Port: "443", Reason: "own addresses unknown"}) {
		t.Fatalf("refusals %+v", r)
	}
	if _, dials := f.calls(); len(dials) != 0 {
		t.Fatalf("dials %q", dials)
	}
}
