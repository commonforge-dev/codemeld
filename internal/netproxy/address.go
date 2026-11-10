package netproxy

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
)

var refusedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("fec0::/10"),
}

var (
	nat64  = netip.MustParsePrefix("64:ff9b::/96")
	sixTo4 = netip.MustParsePrefix("2002::/16")
)

func normalize(a netip.Addr) netip.Addr {
	return a.Unmap().WithZone("")
}

func public(a netip.Addr, own []netip.Addr) bool {
	a = normalize(a)
	if !a.IsGlobalUnicast() || a.IsPrivate() || slices.Contains(own, a) ||
		slices.ContainsFunc(refusedPrefixes, func(p netip.Prefix) bool { return p.Contains(a) }) {
		return false
	}
	b := a.As16()
	switch {
	case nat64.Contains(a):
		return public(netip.AddrFrom4([4]byte(b[12:16])), own)
	case sixTo4.Contains(a):
		return public(netip.AddrFrom4([4]byte(b[2:6])), own)
	}
	return true
}

func choose(addrs []netip.Addr, ownAddrs func() ([]netip.Addr, error)) (netip.Addr, string) {
	own, err := ownAddrs()
	if err != nil {
		return netip.Addr{}, "own addresses unknown"
	}
	for i, a := range own {
		own[i] = normalize(a)
	}
	for _, a := range addrs {
		if public(a, own) {
			return normalize(a), ""
		}
	}
	return netip.Addr{}, "not public"
}

func interfaceAddrs() ([]netip.Addr, error) {
	ifaddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	own := make([]netip.Addr, 0, len(ifaddrs))
	for _, ia := range ifaddrs {
		var ip net.IP
		switch v := ia.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, fmt.Errorf("unreadable interface address %q", ia.String())
		}
		own = append(own, a)
	}
	return own, nil
}
