package netproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const testWait = 5 * time.Second

var testPublic = netip.MustParseAddr("9.9.9.9")

type fakeNet struct {
	t        *testing.T
	upstream string
	names    map[string][]netip.Addr
	own      []netip.Addr
	ownErr   error
	stall    chan string
	stallCtx chan context.Context
	hold     chan struct{}
	wait     time.Duration
	ask      Asker

	mu      sync.Mutex
	lookups []string
	dials   []string
}

func (f *fakeNet) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	f.lookups = append(f.lookups, host)
	f.mu.Unlock()
	if f.stall != nil && host == "stall-lookup.test" {
		f.stall <- "lookup"
		if f.stallCtx != nil {
			f.stallCtx <- ctx
		}
		if f.hold != nil {
			<-f.hold
			return f.names[host], ctx.Err()
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if addrs, ok := f.names[host]; ok {
		return addrs, nil
	}
	return nil, errors.New("no such host")
}

func (f *fakeNet) dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, address)
	f.mu.Unlock()
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		f.t.Errorf("the dialer was given %q, not an address", address)
		return nil, err
	}
	if f.stall != nil && ap.Addr() == netip.MustParseAddr("9.9.9.7") {
		f.stall <- "dial"
		if f.stallCtx != nil {
			f.stallCtx <- ctx
		}
		if f.hold != nil {
			<-f.hold
			return (&net.Dialer{}).Dial(network, f.upstream)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if ap.Addr() != testPublic {
		return nil, errors.New("unreachable")
	}
	return (&net.Dialer{}).DialContext(ctx, network, f.upstream)
}

func (f *fakeNet) ownAddrs() ([]netip.Addr, error) {
	return slices.Clone(f.own), f.ownErr
}

func (f *fakeNet) calls() ([]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.lookups), slices.Clone(f.dials)
}

func startProxy(t *testing.T, f *fakeNet, allow ...string) (*Server, string) {
	t.Helper()
	f.t = t
	s, err := New(allow)
	if err != nil {
		t.Fatal(err)
	}
	s.resolve, s.dial, s.ownAddrs = f.resolve, f.dial, f.ownAddrs
	if f.wait != 0 {
		s.registerWait = f.wait
	}
	endpoint, err := s.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return s, endpoint
}

func listenUpstream(t *testing.T) (string, chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	conns := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(testWait))
			t.Cleanup(func() { _ = c.Close() })
			conns <- c
		}
	}()
	return ln.Addr().String(), conns
}

func accepted(t *testing.T, conns chan net.Conn) net.Conn {
	t.Helper()
	select {
	case c := <-conns:
		return c
	case <-time.After(testWait):
		t.Fatal("the upstream server was never reached")
		return nil
	}
}

func send(t *testing.T, s *Server, ask Asker, raw string) (net.Conn, *bufio.Reader) {
	t.Helper()
	o := s.NewOwner(ask)
	t.Cleanup(o.Close)
	c := dialOwned(t, o, s.ln.Addr().String())
	_ = c.SetDeadline(time.Now().Add(testWait))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	return c, bufio.NewReader(c)
}

func dialOwned(t *testing.T, o *Owner, endpoint string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := o.Register(localEndpoint(c)); err != nil {
		t.Fatal(err)
	}
	return c
}

func localEndpoint(c net.Conn) netip.AddrPort {
	return c.LocalAddr().(*net.TCPAddr).AddrPort()
}

func response(t *testing.T, br *bufio.Reader, method string) *http.Response {
	t.Helper()
	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readFull(t *testing.T, r io.Reader, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func expectEOF(t *testing.T, r io.Reader, who string) {
	t.Helper()
	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("%s: want EOF, got %v", who, err)
	}
	if len(rest) != 0 {
		t.Fatalf("%s: want no more bytes, got %q", who, rest)
	}
}

func handlersDone(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(testWait)
	for {
		s.mu.Lock()
		n := len(s.conns)
		s.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d connections still open", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func stopWithin(t *testing.T, s *Server) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		s.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(testWait):
		t.Fatal("Stop did not return")
	}
}

func openTunnel(t *testing.T) (*Server, *fakeNet, net.Conn, *bufio.Reader, net.Conn) {
	t.Helper()
	up, conns := listenUpstream(t)
	f := &fakeNet{upstream: up, names: map[string][]netip.Addr{"example.com": {testPublic}}}
	s, _ := startProxy(t, f, "example.com:443")
	c, br := send(t, s, f.ask, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nearly")
	resp := response(t, br, http.MethodConnect)
	if resp.Status != "200 Connection Established" {
		t.Fatalf("status %q", resp.Status)
	}
	uc := accepted(t, conns)
	if got := readFull(t, uc, len("early")); got != "early" {
		t.Fatalf("upstream got %q, want the bytes buffered after CONNECT", got)
	}
	return s, f, c, br, uc
}

func TestConnectRelaysToApprovedAddress(t *testing.T) {
	_, f, c, br, uc := openTunnel(t)
	if _, err := io.WriteString(uc, "reply"); err != nil {
		t.Fatal(err)
	}
	if got := readFull(t, br, len("reply")); got != "reply" {
		t.Fatalf("client got %q", got)
	}
	if _, err := io.WriteString(c, "more"); err != nil {
		t.Fatal(err)
	}
	if got := readFull(t, uc, len("more")); got != "more" {
		t.Fatalf("upstream got %q", got)
	}
	lookups, dials := f.calls()
	if !slices.Equal(lookups, []string{"example.com"}) || !slices.Equal(dials, []string{"9.9.9.9:443"}) {
		t.Fatalf("lookups %q dials %q", lookups, dials)
	}
}

func TestConnectClientCloseClosesUpstream(t *testing.T) {
	s, _, c, _, uc := openTunnel(t)
	_ = c.Close()
	expectEOF(t, uc, "upstream")
	handlersDone(t, s)
}

func TestConnectUpstreamCloseClosesClient(t *testing.T) {
	s, _, _, br, uc := openTunnel(t)
	_ = uc.Close()
	expectEOF(t, br, "client")
	handlersDone(t, s)
}

func TestStopClosesTunnel(t *testing.T) {
	s, _, _, br, uc := openTunnel(t)
	stopWithin(t, s)
	expectEOF(t, br, "client")
	expectEOF(t, uc, "upstream")
}

func TestStopCancelsStalledLookupAndDial(t *testing.T) {
	for _, host := range []string{"stall-lookup.test", "stall-dial.test"} {
		t.Run(host, func(t *testing.T) {
			f := &fakeNet{stall: make(chan string, 1), names: map[string][]netip.Addr{
				"stall-dial.test": {netip.MustParseAddr("9.9.9.7")},
			}}
			s, _ := startProxy(t, f, host+":443")
			_, br := send(t, s, f.ask, "CONNECT "+host+":443 HTTP/1.1\r\n\r\n")
			select {
			case <-f.stall:
			case <-time.After(testWait):
				t.Fatal("the request never stalled")
			}
			stopWithin(t, s)
			_, _ = io.ReadAll(br)
		})
	}
}

func TestPlainHTTPForwardsOneApprovedRequest(t *testing.T) {
	up, conns := listenUpstream(t)
	f := &fakeNet{upstream: up, names: map[string][]netip.Addr{"example.com": {testPublic}}}
	s, _ := startProxy(t, f, "example.com:80")
	_, br := send(t, s, f.ask, "GET http://example.com/path?q=1 HTTP/1.1\r\n"+
		"Host: evil.test\r\nProxy-Authorization: Basic eDp5\r\nProxy-Connection: keep-alive\r\n"+
		"Connection: X-Secret, keep-alive\r\nX-Secret: 1\r\nKeep-Alive: 5\r\nTE: trailers\r\nTrailer: X-T\r\n"+
		"Upgrade: h2c\r\nX-Keep: yes\r\n\r\n"+
		"GET http://example.com/second HTTP/1.1\r\nHost: example.com\r\n\r\n")

	uc := accepted(t, conns)
	ubr := bufio.NewReader(uc)
	got, err := http.ReadRequest(ubr)
	if err != nil {
		t.Fatal(err)
	}
	if got.RequestURI != "/path?q=1" || got.Host != "example.com" {
		t.Fatalf("upstream got %s %s with Host %q", got.Method, got.RequestURI, got.Host)
	}
	for _, h := range []string{"Proxy-Authorization", "Proxy-Connection", "X-Secret", "Keep-Alive", "TE", "Trailer", "Upgrade"} {
		if v := got.Header.Values(h); len(v) != 0 {
			t.Errorf("upstream got %s: %q", h, v)
		}
	}
	if got.Header.Get("X-Keep") != "yes" || got.Header.Get("Connection") != "close" {
		t.Errorf("upstream headers %v", got.Header)
	}
	if _, err := io.WriteString(uc, "HTTP/1.1 302 Found\r\nLocation: http://other.test/\r\n"+
		"Connection: X-Up\r\nX-Up: 1\r\nKeep-Alive: 5\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, ubr, "upstream after the first request")

	resp := response(t, br, http.MethodGet)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "http://other.test/" {
		t.Fatalf("client got %s Location %q", resp.Status, resp.Header.Get("Location"))
	}
	if resp.Header.Get("X-Up") != "" || resp.Header.Get("Keep-Alive") != "" {
		t.Errorf("client got hop-by-hop headers %v", resp.Header)
	}
	expectEOF(t, br, "client after one response")
	select {
	case <-conns:
		t.Fatal("a second upstream connection was opened")
	default:
	}
	lookups, dials := f.calls()
	if !slices.Equal(lookups, []string{"example.com"}) || !slices.Equal(dials, []string{"9.9.9.9:80"}) {
		t.Fatalf("lookups %q dials %q", lookups, dials)
	}
}

func TestPlainHTTPStripsHopByHopTrailers(t *testing.T) {
	up, conns := listenUpstream(t)
	f := &fakeNet{upstream: up, names: map[string][]netip.Addr{"example.com": {testPublic}}}
	s, _ := startProxy(t, f, "example.com:80")
	_, br := send(t, s, f.ask, "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"+
		"Connection: X-Secret\r\nTrailer: Proxy-Authorization, X-Secret, X-End\r\nTransfer-Encoding: chunked\r\n\r\n"+
		"4\r\nbody\r\n0\r\nProxy-Authorization: Basic eDp5\r\nX-Secret: 1\r\nKeep-Alive: 5\r\nX-End: ok\r\n\r\n")

	uc := accepted(t, conns)
	ubr := bufio.NewReader(uc)
	got, err := http.ReadRequest(ubr)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(got.Body); err != nil || string(b) != "body" {
		t.Fatalf("upstream body %q, %v", b, err)
	}
	for _, h := range []string{"Proxy-Authorization", "X-Secret", "Keep-Alive"} {
		if _, ok := got.Trailer[h]; ok {
			t.Errorf("upstream got trailer %s: %q", h, got.Trailer[h])
		}
	}
	if got.Trailer.Get("X-End") != "ok" {
		t.Errorf("upstream trailers %v", got.Trailer)
	}

	if _, err := io.WriteString(uc, "HTTP/1.1 200 OK\r\nConnection: X-Up\r\n"+
		"Trailer: Proxy-Authenticate, X-Up, X-Done\r\nTransfer-Encoding: chunked\r\n\r\n"+
		"2\r\nok\r\n0\r\nProxy-Authenticate: Basic\r\nX-Up: 1\r\nUpgrade: h2c\r\nX-Done: yes\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp := response(t, br, http.MethodPost)
	if b, err := io.ReadAll(resp.Body); err != nil || string(b) != "ok" {
		t.Fatalf("client body %q, %v", b, err)
	}
	for _, h := range []string{"Proxy-Authenticate", "X-Up", "Upgrade"} {
		if _, ok := resp.Trailer[h]; ok {
			t.Errorf("client got trailer %s: %q", h, resp.Trailer[h])
		}
	}
	if resp.Trailer.Get("X-Done") != "yes" {
		t.Errorf("client trailers %v", resp.Trailer)
	}
}

func TestPlainHTTPSwitchingProtocolsOpensNoTunnel(t *testing.T) {
	up, conns := listenUpstream(t)
	f := &fakeNet{upstream: up, names: map[string][]netip.Addr{"example.com": {testPublic}}}
	s, _ := startProxy(t, f, "example.com:80")
	c, br := send(t, s, f.ask, "GET http://example.com/ws HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	uc := accepted(t, conns)
	ubr := bufio.NewReader(uc)
	if _, err := http.ReadRequest(ubr); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(uc, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if resp := response(t, br, http.MethodGet); resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("client got %s", resp.Status)
	}
	_, _ = io.WriteString(c, "after-upgrade")
	expectEOF(t, ubr, "upstream after 101")
	if rest, err := io.ReadAll(br); len(rest) != 0 || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("client after 101: got %q, %v; want the connection closed", rest, err)
	}
}

func TestRefusals(t *testing.T) {
	up, _ := listenUpstream(t)
	f := &fakeNet{upstream: up, names: map[string][]netip.Addr{
		"example.com":      {testPublic},
		"rebind.test":      {netip.MustParseAddr("127.0.0.1")},
		"unreachable.test": {netip.MustParseAddr("9.9.9.8")},
	}}
	s, _ := startProxy(t, f, "example.com:443", "rebind.test:443", "nxdomain.test:443", "unreachable.test:443", "9.9.9.9:443")
	cases := []struct {
		authority, host, port, reason string
		dial                          string
	}{
		{"sub.example.com:443", "sub.example.com", "443", "not approved (no one to ask)", ""},
		{"example.com:8443", "example.com", "8443", "not approved (no one to ask)", ""},
		{"[::ffff:9.9.9.9]:443", "::ffff:9.9.9.9", "443", "not approved (no one to ask)", ""},
		{"rebind.test:443", "rebind.test", "443", "not public", ""},
		{"nxdomain.test:443", "nxdomain.test", "443", "lookup failed", ""},
		{"unreachable.test:443", "unreachable.test", "443", "dial failed", "9.9.9.8:443"},
	}
	for _, tc := range cases {
		t.Run(tc.authority, func(t *testing.T) {
			_, dialsBefore := f.calls()
			o := s.NewOwner(f.ask)
			t.Cleanup(o.Close)
			c := dialOwned(t, o, s.ln.Addr().String())
			write(t, c, "CONNECT "+tc.authority+" HTTP/1.1\r\n\r\n")
			resp := response(t, bufio.NewReader(c), http.MethodConnect)
			if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Proxy-Refused") != tc.reason {
				t.Fatalf("got %s %q, want 403 %q", resp.Status, resp.Header.Get("X-Proxy-Refused"), tc.reason)
			}
			refusals := s.Refusals()
			want := Refusal{Host: tc.host, Port: tc.port, Reason: tc.reason}
			if len(refusals) == 0 || refusals[len(refusals)-1] != want {
				t.Fatalf("refusals %+v, want last %+v", refusals, want)
			}
			if got := o.Refusals(); !slices.Equal(got, []Refusal{want}) {
				t.Fatalf("owner refusals %+v, want only %+v", got, want)
			}
			_, dials := f.calls()
			if newDials := dials[len(dialsBefore):]; tc.dial == "" && len(newDials) != 0 ||
				tc.dial != "" && !slices.Equal(newDials, []string{tc.dial}) {
				t.Fatalf("dials %q, want %q", newDials, tc.dial)
			}
		})
	}
}

func TestMalformedRequests(t *testing.T) {
	f := &fakeNet{names: map[string][]netip.Addr{"example.com": {testPublic}}}
	s, _ := startProxy(t, f, "example.com:443", "example.com:80", "[::1]:443")
	cases := []struct {
		name, raw string
		want      Refusal
	}{
		{"connect without port", "CONNECT example.com HTTP/1.1\r\n\r\n", Refusal{}},
		{"port 0", "CONNECT example.com:0 HTTP/1.1\r\n\r\n", Refusal{Host: "example.com", Port: "0"}},
		{"port 65536", "CONNECT example.com:65536 HTTP/1.1\r\n\r\n", Refusal{Host: "example.com", Port: "65536"}},
		{"non-numeric port", "CONNECT example.com:https HTTP/1.1\r\n\r\n", Refusal{}},
		{"unbracketed IPv6", "CONNECT ::1:443 HTTP/1.1\r\n\r\n", Refusal{}},
		{"zoned IPv6 literal", "GET http://[2606:4700::1%25eth0]/ HTTP/1.1\r\n\r\n", Refusal{Host: "2606:4700::1%eth0", Port: "80"}},
		{"empty host", "CONNECT :443 HTTP/1.1\r\n\r\n", Refusal{Port: "443"}},
		{"connect path form", "CONNECT /example.com:443 HTTP/1.1\r\n\r\n", Refusal{}},
		{"connect authority with path", "CONNECT example.com:443/x HTTP/1.1\r\n\r\n", Refusal{}},
		{"connect userinfo", "CONNECT u@example.com:443 HTTP/1.1\r\n\r\n", Refusal{}},
		{"https scheme", "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", Refusal{}},
		{"origin form", "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", Refusal{}},
		{"unparsable", "NOT AN HTTP REQUEST\r\n\r\n", Refusal{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := s.NewOwner(f.ask)
			t.Cleanup(o.Close)
			c := dialOwned(t, o, s.ln.Addr().String())
			write(t, c, tc.raw)
			resp := response(t, bufio.NewReader(c), http.MethodGet)
			if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("X-Proxy-Refused") != "bad request" {
				t.Fatalf("got %s %q", resp.Status, resp.Header.Get("X-Proxy-Refused"))
			}
			if got, want := o.Refusals(), []Refusal{{Reason: "bad request"}}; !slices.Equal(got, want) {
				t.Fatalf("owner refusals %+v, want %+v: a malformed request has no destination", got, want)
			}
			refusals := s.Refusals()
			tc.want.Reason = "bad request"
			if len(refusals) == 0 || refusals[len(refusals)-1] != tc.want {
				t.Fatalf("refusals %+v, want last %+v", refusals, tc.want)
			}
			if lookups, dials := f.calls(); len(lookups)+len(dials) != 0 {
				t.Fatalf("lookups %q dials %q", lookups, dials)
			}
		})
	}
	if n := len(s.Refusals()); n != len(cases) {
		t.Fatalf("%d refusals recorded, want %d", n, len(cases))
	}
}

func TestConcurrentRefusalsAndSnapshots(t *testing.T) {
	const n = 20
	f := &fakeNet{}
	s, endpoint := startProxy(t, f)
	o := s.NewOwner(f.ask)
	t.Cleanup(o.Close)
	stop := make(chan struct{})
	var reader sync.WaitGroup
	reader.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.Refusals()
			}
		}
	})
	var clients sync.WaitGroup
	for i := range n {
		clients.Go(func() {
			c, err := net.Dial("tcp", endpoint)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			if err := o.Register(localEndpoint(c)); err != nil {
				t.Error(err)
				return
			}
			_ = c.SetDeadline(time.Now().Add(testWait))
			_, _ = fmt.Fprintf(c, "CONNECT h%d.test:443 HTTP/1.1\r\n\r\n", i)
			resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
			if err != nil || resp.StatusCode != http.StatusForbidden {
				t.Errorf("client %d: %v %v", i, resp, err)
			}
		})
	}
	clients.Wait()
	close(stop)
	reader.Wait()
	var hosts []string
	for _, r := range s.Refusals() {
		hosts = append(hosts, r.Host)
	}
	slices.Sort(hosts)
	var want []string
	for i := range n {
		want = append(want, fmt.Sprintf("h%d.test", i))
	}
	slices.Sort(want)
	if !slices.Equal(hosts, want) {
		t.Fatalf("recorded hosts %q, want %q", hosts, want)
	}
}

func TestOwnerRefusalsStayWithTheirOwner(t *testing.T) {
	const n = 20
	f := &fakeNet{}
	s, endpoint := startProxy(t, f)
	owners := map[string]*Owner{"a": s.NewOwner(f.ask), "b": s.NewOwner(f.ask)}
	stop := make(chan struct{})
	var reader sync.WaitGroup
	reader.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				if got := owners["a"].Refusals(); len(got) > 0 {
					got[0].Host = "changed"
				}
			}
		}
	})
	var clients sync.WaitGroup
	for name, o := range owners {
		for i := range n {
			clients.Go(func() {
				c, err := net.Dial("tcp", endpoint)
				if err != nil {
					t.Error(err)
					return
				}
				defer c.Close()
				if err := o.Register(localEndpoint(c)); err != nil {
					t.Error(err)
					return
				}
				_ = c.SetDeadline(time.Now().Add(testWait))
				_, _ = fmt.Fprintf(c, "CONNECT %s%d.test:443 HTTP/1.1\r\n\r\n", name, i)
				resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
				if err != nil || resp.StatusCode != http.StatusForbidden {
					t.Errorf("client %s%d: %v %v", name, i, resp, err)
				}
			})
		}
	}
	clients.Wait()
	close(stop)
	reader.Wait()
	cleaned := closeOwner(owners["a"])
	stopped := make(chan struct{})
	go func() {
		s.Stop()
		close(stopped)
	}()
	joined(t, cleaned, "owner cleanup")
	owners["b"].Close()
	joined(t, stopped, "Stop")
	for name, o := range owners {
		first := o.Refusals()
		var want []Refusal
		for i := range n {
			want = append(want, Refusal{Host: fmt.Sprintf("%s%d.test", name, i), Port: "443", Reason: "not approved (no one to ask)"})
		}
		got := slices.Clone(first)
		byHost := func(x, y Refusal) int { return strings.Compare(x.Host, y.Host) }
		slices.SortFunc(got, byHost)
		slices.SortFunc(want, byHost)
		if !slices.Equal(got, want) {
			t.Errorf("owner %s refusals %+v, want %+v", name, got, want)
		}
		if again := o.Refusals(); !slices.Equal(again, first) {
			t.Errorf("owner %s: a repeated read after cleanup changed: %+v, then %+v", name, first, again)
		}
	}
}

func connectWith(t *testing.T, s *Server, ask Asker, authority string) *http.Response {
	t.Helper()
	o := s.NewOwner(ask)
	t.Cleanup(o.Close)
	c := dialOwned(t, o, s.ln.Addr().String())
	write(t, c, "CONNECT "+authority+" HTTP/1.1\r\n\r\n")
	return response(t, bufio.NewReader(c), http.MethodConnect)
}

func neverAsk(t *testing.T) Asker {
	return func(_ context.Context, host, port string, _ func() bool, _ func(Decision) bool) (Decision, error) {
		t.Errorf("asked for %s:%s", host, port)
		return DecisionDeny, nil
	}
}

func TestSavedGrantAdmitsOnlyItsHostAndPort(t *testing.T) {
	up, _ := listenUpstream(t)
	f := &fakeNet{upstream: up, names: map[string][]netip.Addr{
		"example.com": {testPublic}, "sub.example.com": {testPublic},
	}}
	s, _ := startProxy(t, f, "example.com:443")
	if resp := connectWith(t, s, neverAsk(t), "EXAMPLE.com.:443"); resp.StatusCode != http.StatusOK {
		t.Fatalf("EXAMPLE.com.:443 got %s %q, want admitted by the saved grant", resp.Status, resp.Header.Get("X-Proxy-Refused"))
	}
	for _, authority := range []string{"sub.example.com:443", "example.com:8443"} {
		var asked []string
		ask := func(_ context.Context, host, port string, _ func() bool, _ func(Decision) bool) (Decision, error) {
			asked = append(asked, host+":"+port)
			return DecisionDeny, nil
		}
		resp := connectWith(t, s, ask, authority)
		if resp.StatusCode != http.StatusForbidden || !slices.Equal(asked, []string{authority}) {
			t.Errorf("%s: got %s after asking %q, want a denied prompt", authority, resp.Status, asked)
		}
	}
}

func TestNewDropsUnusableEntries(t *testing.T) {
	for _, entry := range []string{
		"[fe80::1%eth0]:443", "example.org", "*.example.com:443", "[[::1]]:443",
		"/example.com:443", "exa mple.com:443", "a..b:443", "u@example.com:443",
	} {
		t.Run(entry, func(t *testing.T) {
			up, _ := listenUpstream(t)
			f := &fakeNet{upstream: up, names: map[string][]netip.Addr{"example.com": {testPublic}}}
			s, _ := startProxy(t, f, entry, "example.com:443")
			if len(s.allow) != 1 || !s.allow["example.com:443"] {
				t.Fatalf("allow list %v, want only example.com:443", s.allow)
			}
			if resp := connectWith(t, s, neverAsk(t), "example.com:443"); resp.StatusCode != http.StatusOK {
				t.Fatalf("got %s %q, want the valid entry to admit", resp.Status, resp.Header.Get("X-Proxy-Refused"))
			}
		})
	}
}

func TestSavedGrantNeverDialsPrivateOrOwnAddresses(t *testing.T) {
	own := netip.MustParseAddr("9.9.9.10")
	f := &fakeNet{own: []netip.Addr{own}, names: map[string][]netip.Addr{
		"private.test": {netip.MustParseAddr("10.1.2.3")},
	}}
	targets := []string{"127.0.0.1:443", "10.0.0.1:443", "[::1]:443", net.JoinHostPort(own.String(), "443"), "private.test:443"}
	s, _ := startProxy(t, f, targets...)
	for _, authority := range targets {
		resp := connectWith(t, s, neverAsk(t), authority)
		if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Proxy-Refused") != "not public" {
			t.Errorf("%s: got %s %q, want refused as not public", authority, resp.Status, resp.Header.Get("X-Proxy-Refused"))
		}
	}
	if _, dials := f.calls(); len(dials) != 0 {
		t.Fatalf("dials %q, want none", dials)
	}
}

func TestPlainHTTPReturnsResponseBeforeUpload(t *testing.T) {
	for reply, code := range map[string]int{
		"HTTP/1.1 100 Continue\r\n\r\n":                                  http.StatusContinue,
		"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n": http.StatusExpectationFailed,
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			up, conns := listenUpstream(t)
			f := &fakeNet{upstream: up, names: map[string][]netip.Addr{"example.com": {testPublic}}}
			s, _ := startProxy(t, f, "example.com:80")
			_, br := send(t, s, f.ask, "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"+
				"Content-Length: 1\r\nExpect: 100-continue\r\n\r\n")
			uc := accepted(t, conns)
			if _, err := http.ReadRequest(bufio.NewReader(uc)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(uc, reply); err != nil {
				t.Fatal(err)
			}
			if resp := response(t, br, http.MethodPost); resp.StatusCode != code {
				t.Fatalf("client got %s", resp.Status)
			}
			expectEOF(t, br, "client after the first response")
			handlersDone(t, s)
		})
	}
}

func TestPlainHTTPAbandonedResponseClosesUpstream(t *testing.T) {
	up, conns := listenUpstream(t)
	f := &fakeNet{upstream: up, names: map[string][]netip.Addr{"example.com": {testPublic}}}
	s, _ := startProxy(t, f, "example.com:80")
	c, br := send(t, s, f.ask, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	uc := accepted(t, conns)
	if _, err := http.ReadRequest(bufio.NewReader(uc)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(uc, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nstart"); err != nil {
		t.Fatal(err)
	}
	response(t, br, http.MethodGet)
	_ = c.(*net.TCPConn).SetLinger(0)
	_ = c.Close()
	_, _ = uc.Write(make([]byte, 256<<10))
	if _, err := io.ReadAll(uc); errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("the proxy kept the upstream connection open after the client went away")
	}
	handlersDone(t, s)
}

func dialFrom(t *testing.T, local netip.AddrPort, endpoint string) net.Conn {
	t.Helper()
	c, err := (&net.Dialer{LocalAddr: net.TCPAddrFromAddrPort(local)}).Dial("tcp4", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func freeLocal(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

func abort(c net.Conn) {
	_ = c.(*net.TCPConn).SetLinger(0)
	_ = c.Close()
}

func write(t *testing.T, c net.Conn, raw string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(testWait))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
}

func expectClosedUnanswered(t *testing.T, c net.Conn, within time.Duration) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(within))
	if b, err := io.ReadAll(c); len(b) != 0 || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("got %q, %v; want the connection closed unanswered within %v", b, err, within)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func stalled(t *testing.T, f *fakeNet, want string) {
	t.Helper()
	select {
	case got := <-f.stall:
		if got != want {
			t.Fatalf("stalled in %s, want %s", got, want)
		}
	case <-time.After(testWait):
		t.Fatalf("the request never stalled in %s", want)
	}
}

func closeOwner(o *Owner) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		o.Close()
		close(done)
	}()
	return done
}

func joined(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(testWait):
		t.Fatalf("%s did not return", what)
	}
}

func ownerClosed(s *Server, o *Owner) func() bool {
	return func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return o.closed
	}
}

func requireUntouched(t *testing.T, s *Server, f *fakeNet) {
	t.Helper()
	if lookups, dials := f.calls(); len(lookups)+len(dials) != 0 {
		t.Fatalf("lookups %q dials %q, want none without an owner", lookups, dials)
	}
	if r := s.Refusals(); len(r) != 0 {
		t.Fatalf("refusals %+v, want none: no request was parsed", r)
	}
}

func waitUntilWaiting(t *testing.T, s *Server, c net.Conn) {
	t.Helper()
	waitFor(t, "the accepted connection to wait for its owner", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.waiting[localEndpoint(c)] != nil
	})
}

func registerWhenWaiting(t *testing.T, s *Server, o *Owner, c net.Conn) {
	t.Helper()
	waitUntilWaiting(t, s, c)
	if err := o.Register(localEndpoint(c)); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationAfterAcceptAdmitsTheConnection(t *testing.T) {
	up, conns := listenUpstream(t)
	f := &fakeNet{upstream: up, names: map[string][]netip.Addr{"example.com": {testPublic}}}
	s, endpoint := startProxy(t, f, "example.com:443")
	o := s.NewOwner(f.ask)
	t.Cleanup(o.Close)
	c := dialFrom(t, freeLocal(t), endpoint)
	write(t, c, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	waitUntilWaiting(t, s, c)
	requireUntouched(t, s, f)
	if err := o.Register(localEndpoint(c)); err != nil {
		t.Fatal(err)
	}
	if resp := response(t, bufio.NewReader(c), http.MethodConnect); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %q", resp.Status)
	}
	accepted(t, conns)
}

func TestClientClosedBeforeRegistrationGetsNoOwner(t *testing.T) {
	const request = "CONNECT example.com:443 HTTP/1.1\r\n\r\n"
	up, conns := listenUpstream(t)
	var mu sync.Mutex
	var asked []string
	f := &fakeNet{upstream: up, wait: 2 * testWait, names: map[string][]netip.Addr{"example.com": {testPublic}},
		ask: func(_ context.Context, host, port string, _ func() bool, _ func(Decision) bool) (Decision, error) {
			mu.Lock()
			defer mu.Unlock()
			asked = append(asked, net.JoinHostPort(host, port))
			return DecisionOnce, nil
		}}
	s, endpoint := startProxy(t, f)
	untouched := func() {
		t.Helper()
		requireUntouched(t, s, f)
		mu.Lock()
		defer mu.Unlock()
		if len(asked) != 0 {
			t.Fatalf("asked %q, want nothing asked without an owner", asked)
		}
	}

	local := freeLocal(t)
	c := dialFrom(t, local, endpoint)
	write(t, c, request)
	waitUntilWaiting(t, s, c)
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the closed connection's waiter to be retired", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.waiting[local] == nil && s.quarantined[local]
	})
	late := s.NewOwner(f.ask)
	t.Cleanup(late.Close)
	if err := late.Register(local); err == nil {
		t.Fatal("a registration after the client closed attached an owner")
	}
	expectClosedUnanswered(t, c, testWait)
	next := s.NewOwner(f.ask)
	t.Cleanup(next.Close)
	if err := next.Register(local); err == nil {
		t.Fatal("another owner registered the closed connection's endpoint")
	}
	untouched()

	fresh := dialFrom(t, freeLocal(t), endpoint)
	write(t, fresh, request)
	registerWhenWaiting(t, s, next, fresh)
	if resp := response(t, bufio.NewReader(fresh), http.MethodConnect); resp.StatusCode != http.StatusOK {
		t.Fatalf("fresh endpoint: status %q", resp.Status)
	}
	accepted(t, conns)
}

func TestConnectionsWithoutAnOwnerNeverReachResolutionOrDial(t *testing.T) {
	const wait = 200 * time.Millisecond
	request := "CONNECT example.com:443 HTTP/1.1\r\n\r\n"
	cases := map[string]func(t *testing.T, s *Server, endpoint string){
		"no registration": func(t *testing.T, s *Server, endpoint string) {
			c := dialFrom(t, freeLocal(t), endpoint)
			write(t, c, request)
			expectClosedUnanswered(t, c, 10*wait)
		},
		"owner already cancelled": func(t *testing.T, s *Server, endpoint string) {
			o := s.NewOwner(nil)
			o.Close()
			c := dialFrom(t, freeLocal(t), endpoint)
			if err := o.Register(localEndpoint(c)); err == nil {
				t.Fatal("a cancelled owner registered a connection")
			}
			write(t, c, request)
			expectClosedUnanswered(t, c, 10*wait)
		},
		"registration on a different peer endpoint": func(t *testing.T, s *Server, endpoint string) {
			o := s.NewOwner(nil)
			t.Cleanup(o.Close)
			if err := o.Register(freeLocal(t)); err != nil {
				t.Fatal(err)
			}
			c := dialFrom(t, freeLocal(t), endpoint)
			write(t, c, request)
			expectClosedUnanswered(t, c, 10*wait)
		},
		"timeout, late registration, then endpoint reuse": func(t *testing.T, s *Server, endpoint string) {
			local := freeLocal(t)
			first := dialFrom(t, local, endpoint)
			write(t, first, request)
			expectClosedUnanswered(t, first, 10*wait)
			late := s.NewOwner(nil)
			t.Cleanup(late.Close)
			if err := late.Register(local); err == nil {
				t.Fatal("a registration after the timeout was accepted")
			}
			abort(first)
			reuse := dialFrom(t, local, endpoint)
			next := s.NewOwner(nil)
			t.Cleanup(next.Close)
			if err := next.Register(local); err == nil {
				t.Fatal("a new connection on a timed-out endpoint registered an owner")
			}
			write(t, reuse, request)
			expectClosedUnanswered(t, reuse, 10*wait)
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeNet{wait: wait, names: map[string][]netip.Addr{"example.com": {testPublic}}}
			s, endpoint := startProxy(t, f, "example.com:443")
			run(t, s, endpoint)
			requireUntouched(t, s, f)
			handlersDone(t, s)
		})
	}
}

func TestLateHandlerAfterPeerEndpointReuseLeavesTheNewConnectionUnowned(t *testing.T) {
	up, conns := listenUpstream(t)
	f := &fakeNet{upstream: up, stall: make(chan string, 1), hold: make(chan struct{}),
		names: map[string][]netip.Addr{"stall-dial.test": {netip.MustParseAddr("9.9.9.7")}}}
	s, endpoint := startProxy(t, f, "stall-dial.test:443")
	local := freeLocal(t)
	o := s.NewOwner(f.ask)
	t.Cleanup(o.Close)
	if err := o.Register(local); err != nil {
		t.Fatal(err)
	}
	first := dialFrom(t, local, endpoint)
	write(t, first, "CONNECT stall-dial.test:443 HTTP/1.1\r\n\r\n")
	stalled(t, f, "dial")
	abort(first)

	reuse := dialFrom(t, local, endpoint)
	other := s.NewOwner(f.ask)
	t.Cleanup(other.Close)
	if err := other.Register(local); err == nil {
		t.Fatal("the reused endpoint registered a second owner")
	}
	write(t, reuse, "CONNECT stall-dial.test:443 HTTP/1.1\r\n\r\n")
	expectClosedUnanswered(t, reuse, testWait)

	close(f.hold)
	expectEOF(t, accepted(t, conns), "upstream dialed for the closed client")
	joined(t, closeOwner(o), "owner cleanup")
	if _, dials := f.calls(); len(dials) != 1 {
		t.Fatalf("dials %q, want only the first connection's", dials)
	}
	handlersDone(t, s)
}

func TestOwnerCleanupRacingRegistrationAndDialAdmitsNothing(t *testing.T) {
	up, conns := listenUpstream(t)
	f := &fakeNet{upstream: up, stall: make(chan string, 1), hold: make(chan struct{}), wait: 2 * time.Second, names: map[string][]netip.Addr{
		"example.com":     {testPublic},
		"stall-dial.test": {netip.MustParseAddr("9.9.9.7")},
	}}
	s, endpoint := startProxy(t, f, "example.com:443", "stall-dial.test:443")
	o := s.NewOwner(f.ask)
	c := dialOwned(t, o, endpoint)
	write(t, c, "CONNECT stall-dial.test:443 HTTP/1.1\r\n\r\nearly")
	stalled(t, f, "dial")
	unmatched := freeLocal(t)
	if err := o.Register(unmatched); err != nil {
		t.Fatal(err)
	}

	cleaned := closeOwner(o)
	waitFor(t, "owner cleanup to begin", ownerClosed(s, o))
	fresh := dialFrom(t, freeLocal(t), endpoint)
	if err := o.Register(localEndpoint(fresh)); err == nil {
		t.Fatal("a cancelled owner registered a new connection")
	}
	pending := dialFrom(t, freeLocal(t), endpoint)
	_, br := send(t, s, f.ask, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	if resp := response(t, br, http.MethodConnect); resp.StatusCode != http.StatusOK {
		t.Fatalf("another owner's request during the stalled cleanup: %s", resp.Status)
	}
	uc := accepted(t, conns)
	if _, err := io.WriteString(uc, "reply"); err != nil {
		t.Fatal(err)
	}
	if got := readFull(t, br, len("reply")); got != "reply" {
		t.Fatalf("another owner's tunnel got %q", got)
	}
	select {
	case <-cleaned:
		t.Fatal("owner cleanup returned before its stalled handler was joined")
	default:
	}

	close(f.hold)
	expectEOF(t, accepted(t, conns), "upstream dialed after cancellation")
	joined(t, cleaned, "owner cleanup")
	expectClosedUnanswered(t, c, testWait)
	for _, local := range []net.Conn{dialFrom(t, unmatched, endpoint), fresh} {
		write(t, local, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
		expectClosedUnanswered(t, local, testWait)
	}
	_ = pending.Close()
}

func TestCancelledOwnerBeforeCleanupAdmitsNothing(t *testing.T) {
	const wait = 200 * time.Millisecond
	request := "CONNECT example.com:443 HTTP/1.1\r\n\r\n"
	cases := map[string]func(t *testing.T, s *Server, o *Owner, endpoint string){
		"accepted connection waiting": func(t *testing.T, s *Server, o *Owner, endpoint string) {
			c := dialFrom(t, freeLocal(t), endpoint)
			write(t, c, request)
			waitUntilWaiting(t, s, c)
			o.cancel()
			if err := o.Register(localEndpoint(c)); err == nil {
				t.Fatal("a cancelled owner registered a waiting connection")
			}
			expectClosedUnanswered(t, c, 10*wait)
		},
		"pending registration": func(t *testing.T, s *Server, o *Owner, endpoint string) {
			local := freeLocal(t)
			if err := o.Register(local); err != nil {
				t.Fatal(err)
			}
			o.cancel()
			c := dialFrom(t, local, endpoint)
			write(t, c, request)
			expectClosedUnanswered(t, c, 10*wait)
			s.mu.Lock()
			defer s.mu.Unlock()
			if len(s.pending) != 0 || len(o.regs) != 0 || !s.quarantined[local] {
				t.Fatalf("pending %v regs %v quarantined %v; want the registration retired", s.pending, o.regs, s.quarantined[local])
			}
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeNet{wait: wait, names: map[string][]netip.Addr{"example.com": {testPublic}}}
			s, endpoint := startProxy(t, f, "example.com:443")
			o := s.NewOwner(f.ask)
			run(t, s, o, endpoint)
			if ownerClosed(s, o)() {
				t.Fatal("the owner was marked closed; the case must run before cleanup")
			}
			requireUntouched(t, s, f)
			joined(t, closeOwner(o), "owner cleanup")
			handlersDone(t, s)
		})
	}
}

func TestOwnerCleanupClosesAndJoinsBlockedTransfers(t *testing.T) {
	cases := map[string]struct {
		allow, raw string
		upstream   func(t *testing.T, uc net.Conn)
	}{
		"incomplete request body": {"example.com:80", "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n\r\npartial", func(t *testing.T, uc net.Conn) {
			ubr := bufio.NewReader(uc)
			req, err := http.ReadRequest(ubr)
			if err != nil {
				t.Fatal(err)
			}
			if got := readFull(t, req.Body, len("partial")); got != "partial" {
				t.Fatalf("upstream body %q", got)
			}
		}},
		"stalled response": {"example.com:80", "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", func(t *testing.T, uc net.Conn) {
			if _, err := http.ReadRequest(bufio.NewReader(uc)); err != nil {
				t.Fatal(err)
			}
		}},
		"connect relay": {"example.com:443", "CONNECT example.com:443 HTTP/1.1\r\n\r\nearly", func(t *testing.T, uc net.Conn) {
			if got := readFull(t, uc, len("early")); got != "early" {
				t.Fatalf("upstream got %q", got)
			}
			if _, err := io.WriteString(uc, "reply"); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			up, conns := listenUpstream(t)
			f := &fakeNet{upstream: up, names: map[string][]netip.Addr{"example.com": {testPublic}}}
			s, endpoint := startProxy(t, f, tc.allow)
			o := s.NewOwner(f.ask)
			c := dialOwned(t, o, endpoint)
			write(t, c, tc.raw)
			uc := accepted(t, conns)
			tc.upstream(t, uc)
			joined(t, closeOwner(o), "owner cleanup")
			_ = c.SetReadDeadline(time.Now().Add(testWait))
			if _, err := io.ReadAll(c); errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("the client connection stayed open after owner cleanup")
			}
			if _, err := io.ReadAll(uc); errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("the upstream connection stayed open after owner cleanup")
			}
			s.mu.Lock()
			n := len(s.conns)
			s.mu.Unlock()
			if n != 0 {
				t.Fatalf("%d connections still tracked after owner cleanup returned", n)
			}
		})
	}
}

func TestClientCloseCancelsStalledLookupAndDial(t *testing.T) {
	for host, step := range map[string]string{"stall-lookup.test": "lookup", "stall-dial.test": "dial"} {
		t.Run(host, func(t *testing.T) {
			f := &fakeNet{stall: make(chan string, 1), names: map[string][]netip.Addr{
				"stall-dial.test": {netip.MustParseAddr("9.9.9.7")},
			}}
			s, _ := startProxy(t, f, host+":443")
			c, _ := send(t, s, f.ask, "CONNECT "+host+":443 HTTP/1.1\r\n\r\n"+strings.Repeat("e", 32<<10))
			stalled(t, f, step)
			_ = c.Close()
			handlersDone(t, s)
		})
	}
}

var stallSteps = map[string]string{"stall-lookup.test": "lookup", "stall-dial.test": "dial"}

func heldNet(t *testing.T, ask Asker) (*fakeNet, chan net.Conn) {
	up, conns := listenUpstream(t)
	return &fakeNet{upstream: up, ask: ask, stall: make(chan string, 1), stallCtx: make(chan context.Context, 1),
		hold: make(chan struct{}), names: map[string][]netip.Addr{
			"stall-lookup.test": {testPublic},
			"stall-dial.test":   {netip.MustParseAddr("9.9.9.7")},
		}}, conns
}

func cancelled(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(testWait):
		t.Fatal("the stalled request was not cancelled")
	}
}

func TestStalledSetupKeepsBufferedClientPayload(t *testing.T) {
	for host, step := range stallSteps {
		t.Run(step, func(t *testing.T) {
			f, conns := heldNet(t, nil)
			s, _ := startProxy(t, f, host+":443")
			early, more := strings.Repeat("e", 16<<10), strings.Repeat("m", 16<<10)
			c, br := send(t, s, f.ask, "CONNECT "+host+":443 HTTP/1.1\r\n\r\n"+early)
			stalled(t, f, step)
			<-f.stallCtx
			write(t, c, more)
			close(f.hold)
			if resp := response(t, br, http.MethodConnect); resp.StatusCode != http.StatusOK {
				t.Fatalf("status %q", resp.Status)
			}
			if got := readFull(t, accepted(t, conns), len(early+more)); got != early+more {
				t.Fatalf("upstream got %d different bytes, want every byte sent while the %s stalled", len(got), step)
			}
		})
	}
}

func TestEarlyPayloadFillingTheBufferDuringAStallRefuses(t *testing.T) {
	for host, step := range stallSteps {
		t.Run(step, func(t *testing.T) {
			f, conns := heldNet(t, nil)
			s, _ := startProxy(t, f, host+":443")
			c, _ := send(t, s, f.ask, "CONNECT "+host+":443 HTTP/1.1\r\n\r\n")
			stalled(t, f, step)
			ctx := <-f.stallCtx
			write(t, c, strings.Repeat("x", 65<<10))
			cancelled(t, ctx)
			close(f.hold)
			handlersDone(t, s)
			want := Refusal{Host: host, Port: "443", Reason: "not approved (command ended)"}
			if r := s.Refusals(); len(r) != 1 || r[0] != want {
				t.Fatalf("refusals %+v, want only %+v", r, want)
			}
			if _, dials := f.calls(); step == "lookup" && len(dials) != 0 {
				t.Fatalf("dials %q, want none", dials)
			}
			if step == "dial" {
				expectEOF(t, accepted(t, conns), "upstream")
			}
		})
	}
}

func goroutineIn(frame string) func() bool {
	return func() bool {
		buf := make([]byte, 1<<20)
		return strings.Contains(string(buf[:runtime.Stack(buf, true)]), frame)
	}
}

func TestBufferFullAfterUpstreamTrackedRefusesWithoutRelay(t *testing.T) {
	f, conns := heldNet(t, nil)
	s, _ := startProxy(t, f, "stall-dial.test:443")
	c, _ := send(t, s, f.ask, "CONNECT stall-dial.test:443 HTTP/1.1\r\n\r\n")
	stalled(t, f, "dial")
	<-f.stallCtx
	s.approvals.mu.Lock()
	locked := true
	defer func() {
		if locked {
			s.approvals.mu.Unlock()
		}
	}()
	write(t, c, strings.Repeat("x", 65<<10))
	waitFor(t, "the client watcher to begin cancelling", goroutineIn("netproxy.(*approvals).end"))
	close(f.hold)
	up := accepted(t, conns)
	waitFor(t, "the upstream to be tracked", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.conns) == 2
	})
	locked = false
	s.approvals.mu.Unlock()
	handlersDone(t, s)
	want := Refusal{Host: "stall-dial.test", Port: "443", Reason: "not approved (command ended)"}
	if r := s.Refusals(); len(r) != 1 || r[0] != want {
		t.Fatalf("refusals %+v, want only %+v", r, want)
	}
	if got, _ := io.ReadAll(c); strings.HasPrefix(string(got), "HTTP/1.1 200") {
		t.Fatalf("the cancelled request got %q", got)
	}
	expectEOF(t, up, "upstream")
}

func TestDuplicateRegistrationsCannotChangeAnOwner(t *testing.T) {
	up, conns := listenUpstream(t)
	f := &fakeNet{upstream: up, names: map[string][]netip.Addr{"example.com": {testPublic}}}
	s, endpoint := startProxy(t, f, "example.com:443")
	a, b := s.NewOwner(f.ask), s.NewOwner(f.ask)
	t.Cleanup(a.Close)
	c := dialFrom(t, freeLocal(t), endpoint)
	write(t, c, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	registerWhenWaiting(t, s, a, c)
	br := bufio.NewReader(c)
	if resp := response(t, br, http.MethodConnect); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %q", resp.Status)
	}
	uc := accepted(t, conns)
	local := localEndpoint(c)
	for name, o := range map[string]*Owner{"same owner": a, "other owner": b} {
		if err := o.Register(local); err == nil {
			t.Fatalf("%s re-registered a matched endpoint", name)
		}
	}
	joined(t, closeOwner(b), "the other owner's cleanup")
	if _, err := io.WriteString(uc, "still"); err != nil {
		t.Fatal(err)
	}
	if got := readFull(t, br, len("still")); got != "still" {
		t.Fatalf("tunnel after the other owner's cleanup got %q", got)
	}

	pending := freeLocal(t)
	if err := a.Register(pending); err != nil {
		t.Fatal(err)
	}
	if err := s.NewOwner(f.ask).Register(pending); err == nil {
		t.Fatal("a conflicting registration was accepted")
	}
	conflicted := dialFrom(t, pending, endpoint)
	write(t, conflicted, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	expectClosedUnanswered(t, conflicted, testWait)

	joined(t, closeOwner(a), "owner cleanup")
	expectEOF(t, uc, "upstream after owner cleanup")
	abort(c)
	after := s.NewOwner(f.ask)
	t.Cleanup(after.Close)
	if err := after.Register(local); err == nil {
		t.Fatal("a retired owner's endpoint registered again")
	}
	reuse := dialFrom(t, local, endpoint)
	write(t, reuse, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	expectClosedUnanswered(t, reuse, testWait)
	_, fresh := send(t, s, f.ask, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	if resp := response(t, fresh, http.MethodConnect); resp.StatusCode != http.StatusOK {
		t.Fatalf("fresh endpoint: status %q", resp.Status)
	}
}

func TestStopRacingOwnerCleanupJoinsBoth(t *testing.T) {
	f := &fakeNet{stall: make(chan string, 1), hold: make(chan struct{}),
		names: map[string][]netip.Addr{"stall-dial.test": {netip.MustParseAddr("9.9.9.7")}}}
	up, _ := listenUpstream(t)
	f.upstream = up
	s, endpoint := startProxy(t, f, "stall-dial.test:443")
	o := s.NewOwner(f.ask)
	c := dialOwned(t, o, endpoint)
	write(t, c, "CONNECT stall-dial.test:443 HTTP/1.1\r\n\r\n")
	stalled(t, f, "dial")
	cleaned := closeOwner(o)
	stopped := make(chan struct{})
	go func() {
		s.Stop()
		close(stopped)
	}()
	waitFor(t, "owner cleanup to begin", ownerClosed(s, o))
	waitFor(t, "stop to begin", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.stopped
	})
	select {
	case <-cleaned:
		t.Fatal("owner cleanup returned before its stalled handler was joined")
	case <-stopped:
		t.Fatal("Stop returned before the stalled handler was joined")
	default:
	}
	close(f.hold)
	joined(t, cleaned, "owner cleanup")
	joined(t, stopped, "Stop")
	expectClosedUnanswered(t, c, testWait)
}

func TestAskOutcomesRefuseWithTheirReason(t *testing.T) {
	cases := []struct {
		name string
		ask  Asker
		want string
	}{
		{"no asker", nil, "not approved (no one to ask)"},
		{"denied", answering(DecisionDeny, nil), "not approved (denied)"},
		{"deny with error", answering(DecisionDeny, errors.New("broken")), "not approved (prompt failed)"},
		{"once with error", answering(DecisionOnce, errors.New("broken")), "not approved (prompt failed)"},
		{"session with error", answering(DecisionSession, errors.New("broken")), "not approved (prompt failed)"},
		{"decision -1", answering(Decision(-1), nil), "not approved (prompt failed)"},
		{"decision 3", answering(Decision(3), nil), "not approved (prompt failed)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeNet{ask: tc.ask, names: map[string][]netip.Addr{"example.com": {testPublic}}}
			s, _ := startProxy(t, f)
			_, br := send(t, s, f.ask, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
			resp := response(t, br, http.MethodConnect)
			if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Proxy-Refused") != tc.want {
				t.Fatalf("got %s %q, want 403 %q", resp.Status, resp.Header.Get("X-Proxy-Refused"), tc.want)
			}
			if b, _ := io.ReadAll(resp.Body); len(b) != 0 {
				t.Fatalf("refusal body %q, want empty", b)
			}
			if r := s.Refusals(); len(r) != 1 || r[0] != (Refusal{Host: "example.com", Port: "443", Reason: tc.want}) {
				t.Fatalf("refusals %+v", r)
			}
			requireNoApprovalOrUpstream(t, s, f)
		})
	}
}

func answering(d Decision, err error) Asker {
	return func(context.Context, string, string, func() bool, func(Decision) bool) (Decision, error) { return d, err }
}

func requireNoApprovalOrUpstream(t *testing.T, s *Server, f *fakeNet) {
	t.Helper()
	if len(s.approvals.session) != 0 {
		t.Fatalf("session approvals %v, want none", s.approvals.session)
	}
	if lookups, dials := f.calls(); len(lookups)+len(dials) != 0 {
		t.Fatalf("lookups %q dials %q, want none", lookups, dials)
	}
}

func countingAsker(answers ...Decision) (Asker, func() []string) {
	var mu sync.Mutex
	var asked []string
	return func(_ context.Context, host, port string, _ func() bool, _ func(Decision) bool) (Decision, error) {
			mu.Lock()
			defer mu.Unlock()
			asked = append(asked, net.JoinHostPort(host, port))
			return answers[min(len(asked), len(answers))-1], nil
		}, func() []string {
			mu.Lock()
			defer mu.Unlock()
			return slices.Clone(asked)
		}
}

func connectStatus(t *testing.T, s *Server, ask Asker, authority string) (int, string) {
	t.Helper()
	_, br := send(t, s, ask, "CONNECT "+authority+" HTTP/1.1\r\n\r\n")
	resp := response(t, br, http.MethodConnect)
	return resp.StatusCode, resp.Header.Get("X-Proxy-Refused")
}

func TestAllowOnceAdmitsOneRequestAndAsksAgain(t *testing.T) {
	up, conns := listenUpstream(t)
	ask, asked := countingAsker(DecisionOnce)
	f := &fakeNet{upstream: up, ask: ask, names: map[string][]netip.Addr{"example.com": {testPublic}}}
	s, _ := startProxy(t, f)
	for i := range 2 {
		if code, reason := connectStatus(t, s, f.ask, "example.com:443"); code != http.StatusOK {
			t.Fatalf("request %d: %d %q", i, code, reason)
		}
		accepted(t, conns)
	}
	if got := asked(); !slices.Equal(got, []string{"example.com:443", "example.com:443"}) {
		t.Fatalf("asked %q, want every request asked", got)
	}
	if len(s.approvals.session) != 0 {
		t.Fatalf("allow once stored %v", s.approvals.session)
	}
}

func TestAllowForSessionAsksOnlyForANewHostOrPort(t *testing.T) {
	up, conns := listenUpstream(t)
	ask, asked := countingAsker(DecisionSession, DecisionDeny)
	f := &fakeNet{upstream: up, ask: ask, names: map[string][]netip.Addr{"example.com": {testPublic}}}
	s, _ := startProxy(t, f)
	for _, authority := range []string{"example.com:443", "EXAMPLE.com.:443"} {
		if code, reason := connectStatus(t, s, f.ask, authority); code != http.StatusOK {
			t.Fatalf("%s: %d %q", authority, code, reason)
		}
		accepted(t, conns)
	}
	if code, reason := connectStatus(t, s, f.ask, "example.com:8443"); code != http.StatusForbidden || reason != "not approved (denied)" {
		t.Fatalf("other port: %d %q, want asked and denied", code, reason)
	}
	if got := asked(); !slices.Equal(got, []string{"example.com:443", "example.com:8443"}) {
		t.Fatalf("asked %q", got)
	}
}

func TestRecheckHitAdmitsAQueuedRequestWithoutPrompting(t *testing.T) {
	up, conns := listenUpstream(t)
	entered, turn, prompts, answers := make(chan struct{}, 2), make(chan struct{}), make(chan struct{}), make(chan Decision)
	f := &fakeNet{upstream: up, names: map[string][]netip.Addr{"example.com": {testPublic}},
		ask: func(ctx context.Context, _, _ string, covered func() bool, _ func(Decision) bool) (Decision, error) {
			entered <- struct{}{}
			select {
			case <-turn:
			case <-ctx.Done():
				return DecisionDeny, ctx.Err()
			}
			if covered() {
				return DecisionOnce, nil
			}
			select {
			case prompts <- struct{}{}:
				return <-answers, nil
			case <-ctx.Done():
				return DecisionDeny, ctx.Err()
			}
		}}
	s, _ := startProxy(t, f)
	_, first := send(t, s, f.ask, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	<-entered
	turn <- struct{}{}
	<-prompts
	_, queued := send(t, s, f.ask, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	<-entered
	answers <- DecisionSession
	if resp := response(t, first, http.MethodConnect); resp.StatusCode != http.StatusOK {
		t.Fatalf("answered request: %s", resp.Status)
	}
	accepted(t, conns)
	turn <- struct{}{}
	if resp := response(t, queued, http.MethodConnect); resp.StatusCode != http.StatusOK {
		t.Fatalf("queued request: %s", resp.Status)
	}
	accepted(t, conns)
	if len(s.approvals.session) != 1 {
		t.Fatalf("session approvals %v, want only the answered one", s.approvals.session)
	}
}

func TestEndingTheRequestWhileAskingRefusesAndStoresNothing(t *testing.T) {
	cases := map[string]struct {
		end  func(s *Server, o *Owner, c net.Conn) <-chan struct{}
		want string
	}{
		"client closes": {func(s *Server, _ *Owner, c net.Conn) <-chan struct{} {
			_ = c.Close()
			return nil
		}, "not approved (command ended)"},
		"owner cancelled": {func(_ *Server, o *Owner, _ net.Conn) <-chan struct{} {
			return closeOwner(o)
		}, "not approved (command ended)"},
		"session proxy stopped": {func(s *Server, _ *Owner, _ net.Conn) <-chan struct{} {
			done := make(chan struct{})
			go func() {
				s.Stop()
				close(done)
			}()
			return done
		}, "not approved (session ended)"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ask, calls := gatedAsker(t)
			f := &fakeNet{ask: ask, names: map[string][]netip.Addr{"example.com": {testPublic}}}
			s, endpoint := startProxy(t, f)
			o := s.NewOwner(f.ask)
			t.Cleanup(o.Close)
			c := dialOwned(t, o, endpoint)
			write(t, c, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
			call := nextAsk(t, calls)
			ended := tc.end(s, o, c)
			select {
			case <-call.ctx.Done():
			case <-time.After(testWait):
				t.Fatal("the asker's context was not cancelled")
			}
			call.answer <- askAnswer{d: DecisionSession}
			if ended != nil {
				joined(t, ended, name)
			}
			handlersDone(t, s)
			if r := s.Refusals(); len(r) != 1 || r[0] != (Refusal{Host: "example.com", Port: "443", Reason: tc.want}) {
				t.Fatalf("refusals %+v, want only %q", r, tc.want)
			}
			requireNoApprovalOrUpstream(t, s, f)
			if ended != nil {
				_ = c.SetReadDeadline(time.Now().Add(testWait))
				if _, err := io.ReadAll(c); errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatal("the client connection stayed open")
				}
			}
		})
	}
}

func TestCancellingAnApprovedRequestDuringSetupKeepsTheFirstCause(t *testing.T) {
	type end func(s *Server, o *Owner, c net.Conn) <-chan struct{}
	clientCloses := func(_ *Server, _ *Owner, c net.Conn) <-chan struct{} {
		_ = c.Close()
		return nil
	}
	ownerCancelled := func(_ *Server, o *Owner, _ net.Conn) <-chan struct{} { return closeOwner(o) }
	sessionStops := func(s *Server, _ *Owner, _ net.Conn) <-chan struct{} {
		done := make(chan struct{})
		go func() {
			s.Stop()
			close(done)
		}()
		return done
	}
	cases := []struct {
		name         string
		first, later end
		want         string
	}{
		{"client close then session stop", clientCloses, sessionStops, "not approved (command ended)"},
		{"owner cancel then session stop", ownerCancelled, sessionStops, "not approved (command ended)"},
		{"session stop then owner cancel", sessionStops, ownerCancelled, "not approved (session ended)"},
		{"session stop then client close", sessionStops, clientCloses, "not approved (session ended)"},
	}
	for host, step := range stallSteps {
		for _, tc := range cases {
			t.Run(step+"/"+tc.name, func(t *testing.T) {
				f, conns := heldNet(t, answering(DecisionOnce, nil))
				s, endpoint := startProxy(t, f)
				o := s.NewOwner(f.ask)
				t.Cleanup(o.Close)
				c := dialOwned(t, o, endpoint)
				write(t, c, "CONNECT "+host+":443 HTTP/1.1\r\n\r\n")
				stalled(t, f, step)
				ctx := <-f.stallCtx
				first := tc.first(s, o, c)
				cancelled(t, ctx)
				later := tc.later(s, o, c)
				close(f.hold)
				for _, done := range []<-chan struct{}{first, later} {
					if done != nil {
						joined(t, done, tc.name)
					}
				}
				handlersDone(t, s)
				want := Refusal{Host: host, Port: "443", Reason: tc.want}
				if r := s.Refusals(); len(r) != 1 || r[0] != want {
					t.Fatalf("refusals %+v, want only %+v", r, want)
				}
				if step == "dial" {
					expectEOF(t, accepted(t, conns), "upstream")
				}
			})
		}
	}
}

func TestApprovedRequestsKeepTheirSetupFailureReasons(t *testing.T) {
	f := &fakeNet{ask: answering(DecisionOnce, nil), names: map[string][]netip.Addr{
		"rebind.test":      {netip.MustParseAddr("127.0.0.1")},
		"unreachable.test": {netip.MustParseAddr("9.9.9.8")},
	}}
	s, _ := startProxy(t, f)
	for authority, want := range map[string]string{
		"nxdomain.test:443":    "lookup failed",
		"rebind.test:443":      "not public",
		"unreachable.test:443": "dial failed",
	} {
		if code, reason := connectStatus(t, s, f.ask, authority); code != http.StatusForbidden || reason != want {
			t.Fatalf("%s: %d %q, want 403 %q", authority, code, reason, want)
		}
	}
}
