package webresearch

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

var (
	thisNetwork  = netip.MustParsePrefix("0.0.0.0/8")
	carrierGrade = netip.MustParsePrefix("100.64.0.0/10")
	benchmarking = netip.MustParsePrefix("198.18.0.0/15")
	reserved     = netip.MustParsePrefix("240.0.0.0/4")
)

var errBlockedAddress = errors.New("webresearch: destination address is not permitted")

func mustNotDial(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr.IsMulticast() {
		return true
	}
	return thisNetwork.Contains(addr) || carrierGrade.Contains(addr) ||
		benchmarking.Contains(addr) || reserved.Contains(addr)
}

// Control runs after resolution with the address that will actually be connected, so this
// covers every DNS result and every redirect hop without per-hop bookkeeping.
func guardDial(_, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil || mustNotDial(addrPort.Addr()) {
		return errBlockedAddress
	}
	return nil
}

var guardedDialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
	Control:   guardDial,
}

func GuardedDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return guardedDialer.DialContext(ctx, network, address)
}
