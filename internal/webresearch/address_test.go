// Tests for the connection-time egress boundary: which concrete addresses the
// fetch dialer must refuse, and that the Control hook classifies each dial from
// the address it is handed rather than from the host that produced it.
package webresearch

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestMustNotDial_RefusesEveryNonPublicAddressClass(t *testing.T) {
	refused := map[string]string{
		"loopback ipv4":             "127.0.0.1",
		"loopback ipv4 range":       "127.255.255.254",
		"loopback ipv6":             "::1",
		"mapped loopback":           "::ffff:127.0.0.1",
		"unspecified ipv4":          "0.0.0.0",
		"this network nonzero":      "0.0.0.1",
		"this network upper":        "0.255.255.255",
		"mapped this network":       "::ffff:0.0.0.1",
		"unspecified ipv6":          "::",
		"link-local ipv4":           "169.254.1.1",
		"link-local ipv6":           "fe80::1",
		"link-local multicast ipv4": "224.0.0.1",
		"link-local multicast ipv6": "ff02::1",
		"interface-local multicast": "ff01::1",
		"global multicast":          "233.0.0.1",
		"broadcast":                 "255.255.255.255",
		"private 10":                "10.0.0.1",
		"private 172":               "172.16.0.1",
		"private 192":               "192.168.0.1",
		"mapped private":            "::ffff:192.168.0.1",
		"unique local":              "fc00::1",
		"unique local upper half":   "fd12:3456::1",
		"carrier-grade nat":         "100.64.0.1",
		"carrier-grade nat upper":   "100.127.255.255",
		"benchmarking":              "198.18.0.1",
		"benchmarking upper":        "198.19.255.255",
		"reserved":                  "240.0.0.1",
		"metadata ec2 and gcp":      "169.254.169.254",
		"metadata ecs task":         "169.254.170.2",
		"metadata alibaba":          "100.100.100.200",
		"mapped metadata":           "::ffff:169.254.169.254",
	}
	for name, raw := range refused {
		t.Run(name, func(t *testing.T) {
			if !mustNotDial(netip.MustParseAddr(raw)) {
				t.Fatalf("mustNotDial(%s) = false, want a refusal", raw)
			}
		})
	}

	allowed := map[string]string{
		"public ipv4":               "93.184.216.34",
		"public ipv4 below cgnat":   "100.63.255.255",
		"public ipv4 above cgnat":   "100.128.0.0",
		"public ipv4 below 172.16":  "172.15.255.255",
		"public ipv4 above 172.31":  "172.32.0.1",
		"public ipv4 below 198.18":  "198.17.255.255",
		"public ipv4 above 198.19":  "198.20.0.1",
		"public ipv4 below 1.0.0.0": "1.0.0.1",
		"public ipv6":               "2001:db8::1",
		"public ipv6 below fc00":    "fbff::1",
		"public ipv6 above fdff":    "fe00::1",
		"mapped public ipv4":        "::ffff:93.184.216.34",
	}
	for name, raw := range allowed {
		t.Run(name, func(t *testing.T) {
			if mustNotDial(netip.MustParseAddr(raw)) {
				t.Fatalf("mustNotDial(%s) = true, want an ordinary public address to be dialable", raw)
			}
		})
	}

	if !mustNotDial(netip.Addr{}) {
		t.Fatal("mustNotDial(invalid) = false, want an unparsed address to fail closed")
	}
}

func TestGuardDial_RefusesTheConcreteAddressItIsHanded(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network string
		address string
		want    bool
	}{
		{"loopback", "tcp4", "127.0.0.1:80", true},
		{"loopback ipv6", "tcp6", "[::1]:443", true},
		{"mapped loopback", "tcp6", "[::ffff:127.0.0.1]:443", true},
		{"unspecified", "tcp4", "0.0.0.0:80", true},
		{"this network nonzero", "tcp4", "0.0.0.1:80", true},
		{"metadata", "tcp4", "169.254.169.254:80", true},
		{"ecs metadata", "tcp4", "169.254.170.2:80", true},
		{"alibaba metadata", "tcp4", "100.100.100.200:80", true},
		{"private", "tcp4", "10.0.0.1:8080", true},
		{"unique local", "tcp6", "[fc00::1]:443", true},
		{"carrier-grade nat", "tcp4", "100.64.0.1:443", true},
		{"reserved", "tcp4", "240.0.0.1:443", true},
		{"hostname instead of an address", "tcp", "docs.example.com:443", true},
		{"no port", "tcp4", "93.184.216.34", true},
		{"empty", "tcp", "", true},
		{"unix socket path", "unix", "/var/run/docker.sock", true},
		{"port out of range", "tcp4", "93.184.216.34:99999", true},
		{"zone-qualified link-local", "tcp6", "[fe80::1%eth0]:80", true},
		{"public ipv4", "tcp4", "93.184.216.34:443", false},
		{"public ipv6", "tcp6", "[2001:db8::1]:443", false},
		{"mapped public ipv4", "tcp6", "[::ffff:93.184.216.34]:443", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := guardDial(tc.network, tc.address, nil)
			if got := err != nil; got != tc.want {
				t.Fatalf("guardDial(%q, %q) error = %v, want refusal = %v", tc.network, tc.address, err, tc.want)
			}
		})
	}
}

// The hook holds no state, so a name that answers public once and private on the
// connection actually dialed is refused on that second address.
func TestGuardDial_ClassifiesEachDialIndependently(t *testing.T) {
	for i, step := range []struct {
		address string
		want    bool
	}{
		{"93.184.216.34:443", false},
		{"169.254.169.254:80", true},
		{"93.184.216.34:443", false},
		{"10.0.0.1:80", true},
		{"93.184.216.34:443", false},
	} {
		err := guardDial("tcp4", step.address, nil)
		if got := err != nil; got != step.want {
			t.Fatalf("dial %d to %q: error = %v, want refusal = %v", i, step.address, err, step.want)
		}
	}
}

func TestGuardedDialContext_RefusesALoopbackListenerBeforeConnecting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	conn, err := GuardedDialContext(context.Background(), "tcp", listener.Addr().String())
	if err == nil {
		_ = conn.Close()
		t.Fatal("GuardedDialContext connected to a loopback listener, want a refusal")
	}
	select {
	case <-accepted:
		t.Fatal("the loopback listener accepted a connection, want the guard to refuse before connecting")
	default:
	}
}
