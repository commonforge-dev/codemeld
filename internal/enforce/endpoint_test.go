package enforce

import (
	"net/netip"
	"testing"
)

func TestTCPEndpointComparesWholeEndpoints(t *testing.T) {
	v4 := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	mapped := netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: 127, 15: 1})
	if tcpEndpoint(mapped, 8080) != tcpEndpoint(v4, 8080) {
		t.Errorf("%v and %v on one port differ, want equal", mapped, v4)
	}
	for _, tc := range []struct {
		addr netip.Addr
		port uint16
	}{
		{v4, 8081},
		{mapped, 8081},
		{netip.AddrFrom4([4]byte{127, 0, 0, 2}), 8080},
		{netip.AddrFrom16([16]byte{15: 1}), 8080},
		{netip.AddrFrom16([16]byte{12: 127, 15: 1}), 8080},
	} {
		if tcpEndpoint(tc.addr, tc.port) == tcpEndpoint(v4, 8080) {
			t.Errorf("%v port %d equals 127.0.0.1:8080", tc.addr, tc.port)
		}
	}
}
