package enforce

import "net/netip"

func tcpEndpoint(addr netip.Addr, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(addr.Unmap(), port)
}
