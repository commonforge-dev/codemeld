package enforce

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/runner"
)

const (
	proxyChildEnv   = "CODEMELD_TEST_PROXY_CHILD"
	proxyPolicyEnv  = "CODEMELD_TEST_PROXY_POLICY"
	proxyRouteBroad = "broad"
	proxyRouteSlice = "proxy"
	proxyBigSize    = 4 << 20
	proxyBigCount   = 5
	proxyKcmpFiles  = 2
)

// The one test-only exception to the public-internet check: these names reach the fixture servers on
// loopback because the prototype must not use the internet.
var proxyFixtureNames = map[string]string{
	"tls.proxy-fixture.test":    "tls",
	"vcs.proxy-fixture.test":    "tls",
	"git.proxy-fixture.test":    "tls",
	"denied.proxy-fixture.test": "tls",
	"plain.proxy-fixture.test":  "plain",
}

var (
	proxyOwnPublic = netip.MustParseAddr("198.51.100.7")
	proxyRebind    = map[string]netip.Addr{
		"rebind.proxy-fixture.test": netip.MustParseAddr("127.0.0.1"),
		"own.proxy-fixture.test":    proxyOwnPublic,
	}
	proxyPublicOnlyHosts = []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost", "10.0.0.1", "rebind.proxy-fixture.test",
		proxyOwnPublic.String(), "own.proxy-fixture.test"}
	proxyCGNAT = netip.MustParsePrefix("100.64.0.0/10")

	proxyToolConfigPrefixes = []string{"CURL_", "PIP_", "GIT_", "HG", "NPM_CONFIG_"}
	proxyToolConfigNames    = []string{"GOPROXY", "GONOPROXY", "GOPRIVATE", "GONOSUMDB", "GOSUMDB", "GOINSECURE",
		"GOFLAGS", "GOENV", "GOVCS", "GOAUTH", "GOTOOLCHAIN"}
)

type proxyEvent struct{ method, host, outcome string }

func (e proxyEvent) String() string { return e.method + " " + e.host + " -> " + e.outcome }

type proxyServer struct {
	addr     netip.AddrPort
	allow    map[string]bool
	fixtures map[string]netip.AddrPort
	resolve  func(ctx context.Context, host string) ([]netip.Addr, error)
	own      func() ([]netip.Addr, error)
	dial     func(network, address string, timeout time.Duration) (net.Conn, error)

	mu     sync.Mutex
	events []proxyEvent
}

func proxyPublic(a netip.Addr, own []netip.Addr) bool {
	a = a.Unmap().WithZone("")
	return a.IsGlobalUnicast() && !a.IsPrivate() && !proxyCGNAT.Contains(a) && !slices.Contains(own, a)
}

func proxyOwnAddrs() ([]netip.Addr, error) {
	ifaddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var own []netip.Addr
	for _, a := range ifaddrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			own = append(own, p.Addr().Unmap())
		}
	}
	return own, nil
}

func (p *proxyServer) decide(ctx context.Context, host, port string) (netip.AddrPort, string) {
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	if !p.allow[name] {
		return netip.AddrPort{}, "not approved"
	}
	if ap, ok := p.fixtures[name]; ok {
		return ap, ""
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, "bad port"
	}
	addrs := []netip.Addr{}
	if a, err := netip.ParseAddr(name); err == nil {
		addrs = append(addrs, a)
	} else if addrs, err = p.resolve(ctx, name); err != nil {
		return netip.AddrPort{}, "unresolved"
	}
	own, err := p.own()
	if err != nil {
		return netip.AddrPort{}, "own addresses unknown"
	}
	for _, a := range addrs {
		if proxyPublic(a, own) {
			return netip.AddrPortFrom(a.Unmap(), uint16(n)), ""
		}
	}
	return netip.AddrPort{}, "not public"
}

func (p *proxyServer) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	port := req.URL.Port()
	if port == "" {
		port = "80"
	}
	target, refused := p.decide(req.Context(), req.URL.Hostname(), port)
	var up net.Conn
	if refused == "" {
		if up, err = p.dial("tcp", target.String(), 10*time.Second); err != nil {
			refused = "dial failed"
		}
	}
	outcome := refused
	if outcome == "" {
		outcome = "ok"
	}
	p.mu.Lock()
	p.events = append(p.events, proxyEvent{req.Method, req.URL.Hostname(), outcome})
	p.mu.Unlock()
	if refused != "" {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nX-Proxy-Refused: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", refused)
		return
	}
	defer up.Close()
	if req.Method == http.MethodConnect {
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			return
		}
		go func() {
			_, _ = io.Copy(up, br)
			_ = up.(*net.TCPConn).CloseWrite()
		}()
	} else {
		req.Header.Del("Proxy-Connection")
		req.Header.Del("Proxy-Authorization")
		req.Close = true
		if err := req.Write(up); err != nil {
			return
		}
	}
	_, _ = io.Copy(conn, up)
}

func (p *proxyServer) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.events)
}

func (p *proxyServer) since(n int) []proxyEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.events[n:])
}

func proxyHas(events []proxyEvent, method, host, outcome string) bool {
	return slices.ContainsFunc(events, func(e proxyEvent) bool {
		return e.method == method && e.host == host && (outcome == "" || e.outcome == outcome)
	})
}

type proxyFixture struct {
	proxy     *proxyServer
	certFile  string
	roots     *x509.CertPool
	tlsAddr   netip.AddrPort
	plainAddr netip.AddrPort

	loopbackName       string
	loopbackUnverified string

	mu   sync.Mutex
	hits []string
}

func proxyCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "codemeld proxy fixture CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "*.proxy-fixture.test"}, DNSNames: []string{"*.proxy-fixture.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

// The name must resolve from /etc/hosts alone so that neither the child nor the proxy can reach DNS.
func proxyLoopbackName() (string, []netip.Addr, string) {
	ns, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		return "", nil, err.Error()
	}
	filesFirst := false
	for line := range strings.SplitSeq(string(ns), "\n") {
		if f := strings.Fields(line); len(f) > 1 && f[0] == "hosts:" {
			filesFirst = f[1] == "files"
		}
	}
	if !filesFirst {
		return "", nil, "/etc/nsswitch.conf does not look names up in /etc/hosts first"
	}
	hosts, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return "", nil, err.Error()
	}
	addrs := map[string][]netip.Addr{}
	var names []string
	for line := range strings.SplitSeq(string(hosts), "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		a, _ := netip.ParseAddr(f[0])
		for _, name := range f[1:] {
			name = strings.ToLower(name)
			if _, seen := addrs[name]; !seen {
				names = append(names, name)
			}
			addrs[name] = append(addrs[name], a)
		}
	}
	for _, name := range names {
		if name == "localhost" || proxyFixtureNames[name] != "" {
			continue
		}
		if !slices.ContainsFunc(addrs[name], func(a netip.Addr) bool { return !a.Unmap().IsLoopback() }) {
			return name, addrs[name], ""
		}
	}
	return "", nil, "/etc/hosts maps no name but localhost to loopback addresses only"
}

func proxyNewFixture(t *testing.T) *proxyFixture {
	t.Helper()
	fx := &proxyFixture{}
	cert, caPEM := proxyCert(t)
	fx.certFile = filepath.Join(proxyTempDir(t), "ca.pem")
	if err := os.WriteFile(fx.certFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	fx.roots = x509.NewCertPool()
	fx.roots.AppendCertsFromPEM(caPEM)
	tlsSrv := httptest.NewUnstartedServer(fx.handler("tls"))
	tlsSrv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	tlsSrv.StartTLS()
	t.Cleanup(tlsSrv.Close)
	plainSrv := httptest.NewServer(fx.handler("plain"))
	t.Cleanup(plainSrv.Close)
	fx.tlsAddr = netip.MustParseAddrPort(tlsSrv.Listener.Addr().String())
	fx.plainAddr = netip.MustParseAddrPort(plainSrv.Listener.Addr().String())
	var loopbackAddrs []netip.Addr
	fx.loopbackName, loopbackAddrs, fx.loopbackUnverified = proxyLoopbackName()

	allow := map[string]bool{}
	if fx.loopbackName != "" {
		allow[fx.loopbackName] = true
	}
	fixtures := map[string]netip.AddrPort{}
	for name, label := range proxyFixtureNames {
		fixtures[name] = fx.plainAddr
		if label == "tls" {
			fixtures[name] = fx.tlsAddr
		}
		allow[name] = name != "denied.proxy-fixture.test"
	}
	for _, h := range proxyPublicOnlyHosts {
		allow[h] = true
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closed(t, "the proxy listener", ln.Close()) })
	fx.proxy = &proxyServer{
		addr:     netip.MustParseAddrPort(ln.Addr().String()),
		allow:    allow,
		fixtures: fixtures,
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			if a, ok := proxyRebind[host]; ok {
				return []netip.Addr{a}, nil
			}
			if host == fx.loopbackName {
				return loopbackAddrs, nil
			}
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		own: func() ([]netip.Addr, error) {
			own, err := proxyOwnAddrs()
			return append(own, proxyOwnPublic), err
		},
		dial: func(network, address string, timeout time.Duration) (net.Conn, error) {
			if ap, err := netip.ParseAddrPort(address); err != nil || !ap.Addr().IsLoopback() {
				return nil, fmt.Errorf("the fixture proxy dials loopback only, not %s", address)
			}
			return net.DialTimeout(network, address, timeout)
		},
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go fx.proxy.serve(conn)
		}
	}()
	return fx
}

func (fx *proxyFixture) handler(label string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fx.mu.Lock()
		fx.hits = append(fx.hits, label+" "+r.Host+" "+r.URL.Path)
		fx.mu.Unlock()
		switch {
		case r.URL.Query().Get("go-get") == "1":
			_, _ = fmt.Fprintf(w, `<meta name="go-import" content="%s/m git https://git.proxy-fixture.test/m.git">`, r.Host)
		case r.URL.Path == "/big":
			_, _ = w.Write(make([]byte, proxyBigSize))
		case strings.HasPrefix(r.URL.Path, "/mod/mod.test/m/@v/"):
			proxyServeModule(w, path.Base(r.URL.Path))
		default:
			_, _ = fmt.Fprintf(w, "%s %s", label, r.Host)
		}
	})
}

func proxyServeModule(w http.ResponseWriter, file string) {
	const gomod = "module mod.test/m\n"
	switch file {
	case "list":
		_, _ = io.WriteString(w, "v1.0.0\n")
	case "v1.0.0.info":
		_, _ = io.WriteString(w, `{"Version":"v1.0.0"}`)
	case "v1.0.0.mod":
		_, _ = io.WriteString(w, gomod)
	case "v1.0.0.zip":
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		f, err := zw.Create("mod.test/m@v1.0.0/go.mod")
		if err == nil {
			_, err = io.WriteString(f, gomod)
		}
		if err == nil {
			err = zw.Close()
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(buf.Bytes())
	default:
		http.NotFound(w, nil)
	}
}

func (fx *proxyFixture) hitCount() int {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return len(fx.hits)
}

func (fx *proxyFixture) hitsSince(n int) []string {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return slices.Clone(fx.hits[n:])
}

func (fx *proxyFixture) env(extra ...string) []string {
	env := slices.DeleteFunc(os.Environ(), func(e string) bool {
		name, _, _ := strings.Cut(e, "=")
		name = strings.ToUpper(name)
		return strings.HasSuffix(name, "_PROXY") || slices.Contains(proxyToolConfigNames, name) ||
			slices.ContainsFunc(proxyToolConfigPrefixes, func(p string) bool { return strings.HasPrefix(name, p) })
	})
	u := "http://" + fx.proxy.addr.String()
	env = append(env, "HTTP_PROXY="+u, "HTTPS_PROXY="+u, "http_proxy="+u, "https_proxy="+u,
		"SSL_CERT_FILE="+fx.certFile, "CURL_CA_BUNDLE="+fx.certFile, "GIT_SSL_CAINFO="+fx.certFile,
		"NODE_EXTRA_CA_CERTS="+fx.certFile, "npm_config_cafile="+fx.certFile, "PIP_CERT="+fx.certFile,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
		"HGRCPATH=", "HGPLAIN=1", "PIP_CONFIG_FILE=/dev/null", "npm_config_userconfig=/dev/null", "npm_config_update_notifier=false")
	return append(env, extra...)
}

func proxyClient(tr *http.Transport) *http.Client {
	tr.DisableKeepAlives = true
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
}

func proxyGet(c *http.Client, u string) string {
	resp, err := c.Get(u)
	if err != nil {
		return "error: " + err.Error()
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "error: " + err.Error()
	}
	return strconv.Itoa(resp.StatusCode) + " " + string(body)
}

func proxyFetchBig(c *http.Client, u string) (time.Duration, error) {
	start := time.Now()
	for range proxyBigCount {
		resp, err := c.Get(u)
		if err != nil {
			return 0, err
		}
		n, err := io.Copy(io.Discard, resp.Body)
		closeErr := resp.Body.Close()
		if err == nil && n != proxyBigSize {
			err = fmt.Errorf("read %d bytes, want %d", n, proxyBigSize)
		}
		if err = errors.Join(err, closeErr); err != nil {
			return 0, err
		}
	}
	return time.Since(start), nil
}

func proxyRouteFor(p Policy) string {
	if p.ExceptionalAuthority == NetworkAccessAuthority {
		return proxyRouteBroad
	}
	return proxyRouteSlice
}

func proxyInstallSlice() (int, error) {
	info, err := nativeSeccompArch()
	if err != nil {
		return -1, err
	}
	eperm := bpf.RetConstant{Val: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)}
	allow := bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW}
	loadNr := bpf.LoadAbsolute{Off: seccompNrOffset, Size: 4}
	prog := []bpf.Instruction{
		bpf.LoadAbsolute{Off: seccompArchOffset, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(info.ID), SkipTrue: 1},
		bpf.RetConstant{Val: unix.SECCOMP_RET_KILL_PROCESS},
		loadNr,
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: unix.SYS_SOCKET, SkipTrue: 11},
		loadArg(0),
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.AF_INET, SkipTrue: 1},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: unix.AF_INET6, SkipTrue: 6},
		loadArg(1),
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: ^uint32(unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC)},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: unix.SOCK_STREAM, SkipTrue: 3},
		loadArg(2),
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_TCP, SkipTrue: 1},
		eperm,
		allow,
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: unix.SYS_CONNECT, SkipTrue: 1},
		bpf.RetConstant{Val: unix.SECCOMP_RET_USER_NOTIF},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: unix.SYS_BIND, SkipTrue: 1},
		eperm,
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: unix.SYS_LISTEN, SkipTrue: 1},
		eperm,
	}
	for _, call := range [][2]uint32{{unix.SYS_SENDTO, 3}, {unix.SYS_SENDMSG, 2}, {unix.SYS_SENDMMSG, 3}} {
		prog = append(prog,
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: call[0], SkipTrue: 3},
			loadArg(call[1]),
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: unix.MSG_FASTOPEN, SkipFalse: 1},
			eperm,
			loadNr)
	}
	raw, err := bpf.Assemble(append(prog, allow))
	if err != nil {
		return -1, err
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		filter[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	fd, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER|unix.SECCOMP_FILTER_FLAG_TSYNC|unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH,
		uintptr(unsafe.Pointer(&fprog)))
	if e != 0 {
		return -1, e
	}
	return int(fd), nil
}

func proxyConfine(p Policy, route string, beforeSeccomp func() error) (int, string, error) {
	if err := applyLandlock(p); err != nil {
		return -1, "landlock", err
	}
	if err := beforeSeccomp(); err != nil {
		return -1, "separate file table thread", err
	}
	base := p
	if route == proxyRouteSlice {
		base.ExceptionalAuthority = NetworkAccessAuthority
	}
	if err := installSeccomp(base); err != nil {
		return -1, "seccomp", err
	}
	if route == proxyRouteBroad {
		return -1, "", nil
	}
	fd, err := proxyInstallSlice()
	return fd, "listener filter", err
}

func proxySockaddr(b []byte) (netip.AddrPort, bool) {
	if len(b) < 2 {
		return netip.AddrPort{}, false
	}
	switch binary.NativeEndian.Uint16(b) {
	case unix.AF_INET:
		if len(b) >= unix.SizeofSockaddrInet4 {
			return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[4:8])), binary.BigEndian.Uint16(b[2:4])), true
		}
	case unix.AF_INET6:
		if len(b) >= unix.SizeofSockaddrInet6 {
			return netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[8:24])), binary.BigEndian.Uint16(b[2:4])), true
		}
	}
	return netip.AddrPort{}, false
}

func proxyTgid(tid uint32) (int, error) {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "Tgid:"); ok {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return 0, errors.New("no Tgid line")
}

func proxyBrokerConnect(listener int, n seccompNotif, proxy netip.AddrPort) (entry string) {
	result := error(unix.EPERM)
	defer func() {
		resp := seccompNotifResp{ID: n.ID}
		var e unix.Errno
		if errors.As(result, &e) {
			resp.Error = -int32(e)
		} else if result != nil {
			resp.Error = -int32(unix.EPERM)
		}
		if err := ioctlPtr(listener, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&resp)); err != nil {
			entry += "; reply " + errName(err)
		}
	}()
	live := func() error { return ioctlPtr(listener, unix.SECCOMP_IOCTL_NOTIF_ID_VALID, unsafe.Pointer(&n.ID)) }
	if n.Args[2] == 0 || n.Args[2] > unix.SizeofSockaddrAny {
		return "deny address length " + strconv.FormatUint(n.Args[2], 10)
	}
	tgid, err := proxyTgid(n.Pid)
	if err != nil {
		return "error: tgid " + err.Error()
	}
	pidfd, err := unix.PidfdOpen(tgid, 0)
	if err != nil {
		return "error: pidfd_open " + errName(err)
	}
	defer func() { _ = unix.Close(pidfd) }()
	if tgid != int(n.Pid) {
		r, _, e := unix.Syscall6(unix.SYS_KCMP, uintptr(n.Pid), uintptr(tgid), proxyKcmpFiles, 0, 0, 0)
		if e != 0 {
			return "deny kcmp " + errName(e)
		}
		if r != 0 {
			return "deny thread file table differs from its process's"
		}
	}
	if err := live(); err != nil {
		return "error: notification gone " + errName(err)
	}
	addr := make([]byte, n.Args[2])
	local := []unix.Iovec{{Base: &addr[0]}}
	local[0].SetLen(len(addr))
	if _, err := unix.ProcessVMReadv(int(n.Pid), local, []unix.RemoteIovec{{Base: uintptr(n.Args[1]), Len: len(addr)}}, 0); err != nil {
		return "error: process_vm_readv " + errName(err)
	}
	sock, err := unix.PidfdGetfd(pidfd, int(n.Args[0]), 0)
	if err != nil {
		return "error: pidfd_getfd " + errName(err)
	}
	defer func() { _ = unix.Close(sock) }()
	ap, ok := proxySockaddr(addr)
	if !ok {
		return "deny non-TCP address"
	}
	if netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()) != proxy {
		return "deny " + ap.String()
	}
	if err := live(); err != nil {
		return "error: notification gone " + errName(err)
	}
	result = rawSockaddrCall(unix.SYS_CONNECT, sock, addr)
	return "admit " + ap.String()
}

func proxyBroker(listener int, proxy netip.AddrPort, stop <-chan struct{}) (log []string) {
	for {
		select {
		case <-stop:
			return log
		default:
		}
		revents, err := pollFD(listener, unix.POLLIN, 100*time.Millisecond)
		if err != nil {
			return append(log, "error: poll "+errName(err))
		}
		if revents&unix.POLLHUP != 0 {
			<-stop
			return log
		}
		if revents&unix.POLLIN == 0 {
			continue
		}
		var n seccompNotif
		if err := ioctlPtr(listener, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&n)); err != nil {
			if err == unix.ENOENT {
				continue
			}
			return append(log, "error: recv "+errName(err))
		}
		log = append(log, proxyBrokerConnect(listener, n, proxy))
	}
}

type proxyRun struct {
	route   string
	results map[string]string
	broker  []string
	out     string
	err     error
}

// Building Landlock rules opens every entry beside a blocked path, so the busy shared temp folder is
// blocked whole and the child's folders and the fixture CA live outside it.
func proxyTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/var/tmp", "codemeld-proxy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("fixture: removing %s: %v", dir, err)
		}
	})
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func proxyRunChild(t *testing.T, fx *proxyFixture, authority, mode string, env []string, argv ...string) proxyRun {
	t.Helper()
	if abi, err := landlockABI(); err != nil || abi < 3 {
		t.Skipf("Landlock ABI 3 unavailable: ABI %d, %v", abi, err)
	}
	dir := proxyTempDir(t)
	sharedTmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{
		Mode: ModeAutoEdits, ExceptionalAuthority: authority,
		BlockedPaths: []string{sharedTmp}, WriteRoots: []string{filepath.Join(dir, "work")}, TmpDir: filepath.Join(dir, "tmp"),
	}
	for _, d := range []string{p.WriteRoots[0], p.TmpDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	policy, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parentEnd, childEnd := os.NewFile(uintptr(fds[0]), "proxy-ctl"), os.NewFile(uintptr(fds[1]), "proxy-child-ctl")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	args := append([]string{"-test.run=^TestProxyProtoChild$", "--",
		strconv.Itoa(int(fx.proxy.addr.Port())), strconv.Itoa(int(fx.plainAddr.Port())), fx.loopbackName}, argv...)
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append(fx.env(env...), proxyChildEnv+"="+mode, proxyPolicyEnv+"="+string(policy))
	cmd.Dir = p.WriteRoots[0]
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.ExtraFiles = []*os.File{childEnd}
	err = cmd.Start()
	closed(t, "the child's control end", childEnd.Close())
	if err != nil {
		closed(t, "the parent's control end", parentEnd.Close())
		cancel()
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	fail := func(format string, a ...any) {
		cancel()
		<-done
		t.Fatalf(format+"\nchild (%v) output:\n%s", append(a, waitErr, out.String())...)
	}
	conn, err := net.FileConn(parentEnd)
	closed(t, "the parent's control end", parentEnd.Close())
	if err != nil {
		fail("control socket: %v", err)
	}
	ctl := conn.(*net.UnixConn)
	defer ctl.Close()
	deadline, _ := ctx.Deadline()
	if err := ctl.SetReadDeadline(deadline); err != nil {
		fail("%v", err)
	}
	b, oob := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := ctl.ReadMsgUnix(b, oob)
	if err != nil || n != 1 {
		fail("no confinement message from the child: %v", err)
	}
	lines := bufio.NewReader(ctl)
	run := proxyRun{route: proxyRouteBroad, results: map[string]string{}}
	listener := -1
	switch b[0] {
	case 'E':
		line, _ := lines.ReadString('\n')
		if strings.HasPrefix(line, "listener filter=") {
			t.Skipf("inconclusive: seccomp user notification refused: %s", line)
		}
		fail("child confinement failed: %s", line)
	case 'L':
		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil || len(msgs) != 1 {
			fail("listener message: %v", err)
		}
		rights, err := unix.ParseUnixRights(&msgs[0])
		if err != nil || len(rights) != 1 {
			fail("listener rights: %v", err)
		}
		listener, run.route = rights[0], proxyRouteSlice
		if line, err := lines.ReadString('\n'); err != nil || line != "closed=1\n" {
			fail("child did not close its listener: %q %v", line, err)
		}
	}
	var brokerDone chan []string
	stop := make(chan struct{})
	if listener >= 0 {
		defer func() { closed(t, "the listener", unix.Close(listener)) }()
		if got := notifyListeners(t, strconv.Itoa(cmd.Process.Pid)); got != 0 {
			fail("child still holds %d listener descriptors", got)
		}
		pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
		if err == nil {
			var probe int
			if probe, err = unix.PidfdGetfd(pidfd, 3, 0); err == nil {
				closed(t, "the pidfd_getfd probe", unix.Close(probe))
			}
			closed(t, "the probe pidfd", unix.Close(pidfd))
		}
		if err != nil {
			t.Skipf("inconclusive at kernel.yama.ptrace_scope=%s: socket copy refused: %s", sysctl("/proc/sys/kernel/yama/ptrace_scope"), errName(err))
		}
		brokerDone = make(chan []string, 1)
		go func() { brokerDone <- proxyBroker(listener, fx.proxy.addr, stop) }()
	}
	if _, err := ctl.Write([]byte("go\n")); err != nil {
		fail("send go: %v", err)
	}
	for {
		line, err := lines.ReadString('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				fail("reading child results: %v", err)
			}
			break
		}
		k, v, _ := strings.Cut(strings.TrimSuffix(line, "\n"), "=")
		run.results[k] = v
	}
	select {
	case <-done:
	case <-ctx.Done():
		fail("child did not exit")
	}
	close(stop)
	if brokerDone != nil {
		run.broker = <-brokerDone
	}
	run.out, run.err = out.String(), waitErr
	if mode != "exec" && waitErr != nil {
		fail("child failed")
	}
	return run
}

func ProxyRouteRun(t *testing.T, authority string) (route, direct, viaProxy string) {
	t.Helper()
	fx := proxyNewFixture(t)
	run := proxyRunChild(t, fx, authority, "route", nil)
	return run.route, run.results["direct"], run.results["via proxy"]
}

func TestProxyProtoChild(t *testing.T) {
	mode := os.Getenv(proxyChildEnv)
	if mode == "" {
		t.Skip("runs only as the disposable child of the proxy prototype tests")
	}
	args := flag.Args()
	ctl := os.NewFile(3, "ctl")
	report := func(key, val string) {
		if _, err := fmt.Fprintf(ctl, "%s=%s\n", key, strings.ReplaceAll(val, "\n", " ")); err != nil {
			panic(fmt.Sprintf("fixture: reporting %s: %v", key, err))
		}
	}
	var p Policy
	if err := json.Unmarshal([]byte(os.Getenv(proxyPolicyEnv)), &p); err != nil {
		t.Fatal(err)
	}
	route := proxyRouteFor(p)
	var separate func(func())
	// Landlock applies its ruleset descriptor on every thread and seccomp denies unshare, so the
	// separate-table thread is made between the two.
	listener, step, err := proxyConfine(p, route, func() (err error) {
		if mode == "confined" {
			separate, err = proxyThread(true)
		}
		return err
	})
	switch {
	case err != nil:
		if _, werr := ctl.Write([]byte("E")); werr != nil {
			t.Fatal(werr)
		}
		report(step, errName(err))
		return
	case route == proxyRouteBroad:
		if _, err := ctl.Write([]byte("N")); err != nil {
			t.Fatal(err)
		}
	default:
		if err := unix.Sendmsg(3, []byte("L"), unix.UnixRights(listener), nil, 0); err != nil {
			t.Fatal(err)
		}
		// The kernel fails paused calls when the broker stops only if the broker holds the last listener reference.
		if err := unix.Close(listener); err != nil {
			t.Fatal(err)
		}
		if _, err := ctl.Write([]byte("closed=1\n")); err != nil {
			t.Fatal(err)
		}
	}
	if line, err := bufio.NewReader(ctl).ReadString('\n'); err != nil || line != "go\n" {
		t.Fatalf("waiting for go: %q %v", line, err)
	}
	proxyPort, plainPort, loopbackName := args[0], args[1], args[2]
	client := proxyClient(http.DefaultTransport.(*http.Transport).Clone())
	switch mode {
	case "exec":
		if _, err := unix.FcntlInt(3, unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		t.Fatal(syscall.Exec(args[3], args[3:], os.Environ()))
	case "route":
		lp, err := strconv.Atoi(plainPort)
		if err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		report("direct", errName(unix.Connect(fd, loopback4(lp))))
		if err := unix.Close(fd); err != nil {
			t.Fatal(err)
		}
		report("via proxy", proxyGet(client, "http://plain.proxy-fixture.test/"))
	case "confined":
		proxyConfinedActions(t, report, client, separate, proxyPort, plainPort, loopbackName)
	}
}

// Two goroutines hold their threads at once so that at least one is off the main thread.
func proxyThread(unshareFiles bool) (func(func()), error) {
	work := make(chan func())
	errc := make(chan error, 1)
	picked := make(chan struct{})
	var once sync.Once
	for range 2 {
		go func() {
			runtime.LockOSThread()
			won := false
			if unix.Gettid() != unix.Getpid() {
				once.Do(func() { won = true })
			}
			if !won {
				<-picked
				runtime.UnlockOSThread()
				return
			}
			close(picked)
			if unshareFiles {
				if err := unix.Unshare(unix.CLONE_FILES); err != nil {
					errc <- err
					return
				}
			}
			errc <- nil
			for f := range work {
				f()
			}
		}()
	}
	if err := <-errc; err != nil {
		return nil, err
	}
	return func(f func()) {
		done := make(chan struct{})
		work <- func() { f(); close(done) }
		<-done
	}, nil
}

func proxyConfinedActions(t *testing.T, report func(key, val string), client *http.Client, separate func(func()), proxyPort, plainPort, loopbackName string) {
	report("allowed https", proxyGet(client, "https://tls.proxy-fixture.test/"))
	report("allowed http", proxyGet(client, "http://plain.proxy-fixture.test/"))
	report("not approved https", proxyGet(client, "https://denied.proxy-fixture.test/"))
	report("not approved http", proxyGet(client, "http://denied.proxy-fixture.test/"))
	report("subdomain https", proxyGet(client, "https://sub.tls.proxy-fixture.test/"))
	for _, host := range proxyPublicOnlyHosts {
		target := net.JoinHostPort(host, plainPort)
		status := "error: no response"
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", proxyPort), 10*time.Second); err != nil {
			status = "error: " + err.Error()
		} else {
			if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
				t.Fatal(err)
			}
			if resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect}); err == nil {
				status = resp.Status + " " + resp.Header.Get("X-Proxy-Refused")
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
		}
		report("public only "+host, status)
	}
	bypass := []string{"127.0.0.1", "::1", "localhost"}
	if loopbackName != "" {
		bypass = append(bypass, loopbackName)
	}
	for _, host := range bypass {
		report("bypass "+host, proxyGet(client, "http://"+net.JoinHostPort(host, plainPort)+"/"))
	}

	pp, err := strconv.Atoi(proxyPort)
	if err != nil {
		t.Fatal(err)
	}
	lp, err := strconv.Atoi(plainPort)
	if err != nil {
		t.Fatal(err)
	}
	try := func(key string, domain int, call func(fd int) error) {
		fd, err := unix.Socket(domain, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			report(key, "socket "+errName(err))
			return
		}
		report(key, errName(call(fd)))
		if err := unix.Close(fd); err != nil {
			t.Fatal(err)
		}
	}
	payload := []byte("x")
	try("direct loopback", unix.AF_INET, func(fd int) error { return unix.Connect(fd, loopback4(lp)) })
	try("direct other address at the proxy port", unix.AF_INET, func(fd int) error {
		return unix.Connect(fd, &unix.SockaddrInet4{Port: pp, Addr: [4]byte{192, 0, 2, 1}})
	})
	try("v4-mapped proxy endpoint", unix.AF_INET6, func(fd int) error {
		return unix.Connect(fd, &unix.SockaddrInet6{Port: pp, Addr: netip.MustParseAddr("::ffff:127.0.0.1").As16()})
	})
	try("bind loopback", unix.AF_INET, func(fd int) error { return unix.Bind(fd, loopback4(0)) })
	try("bind any", unix.AF_INET, func(fd int) error { return unix.Bind(fd, &unix.SockaddrInet4{}) })
	try("listen unbound", unix.AF_INET, func(fd int) error { return unix.Listen(fd, 8) })
	try("fastopen sendto", unix.AF_INET, func(fd int) error { return unix.Sendto(fd, payload, unix.MSG_FASTOPEN, loopback4(lp)) })
	try("fastopen sendmsg", unix.AF_INET, func(fd int) error {
		_, err := unix.SendmsgN(fd, payload, nil, loopback4(lp), unix.MSG_FASTOPEN)
		return err
	})
	try("fastopen sendmmsg", unix.AF_INET, func(fd int) error {
		rsa := unix.RawSockaddrInet4{Family: unix.AF_INET, Addr: [4]byte{127, 0, 0, 1}}
		setRawPort(&rsa, lp)
		iov := unix.Iovec{Base: &payload[0]}
		iov.SetLen(len(payload))
		var m unix.Mmsghdr
		m.Hdr.Name = (*byte)(unsafe.Pointer(&rsa))
		m.Hdr.Namelen = uint32(unsafe.Sizeof(rsa))
		m.Hdr.Iov = &iov
		m.Hdr.SetIovlen(1)
		_, _, e := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&m)), 1, unix.MSG_FASTOPEN, 0, 0)
		return errnoErr(e)
	})
	proxyEndpoint := &unix.SockaddrInet4{Port: pp, Addr: [4]byte{127, 0, 0, 1}}
	other, err := proxyThread(false)
	if err != nil {
		t.Fatal(err)
	}
	var otherErr error
	other(func() {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			err = unix.Connect(fd, proxyEndpoint)
			_ = unix.Close(fd)
		}
		otherErr = err
	})
	report("other thread proxy connect", errName(otherErr))
	leaderSock, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var separateErr error
	separate(func() {
		own, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			err = unix.Dup3(own, leaderSock, unix.O_CLOEXEC)
			_ = unix.Close(own)
		}
		if err == nil {
			err = unix.Connect(leaderSock, proxyEndpoint)
			_ = unix.Close(leaderSock)
		}
		separateErr = err
	})
	report("separate file table proxy connect", errName(separateErr))
	_, err = unix.Getpeername(leaderSock)
	report("leader socket after separate connect", errName(err))
	if err := unix.Close(leaderSock); err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct {
		key          string
		domain, kind int
	}{{"udp socket", unix.AF_INET, unix.SOCK_DGRAM}, {"unix socket", unix.AF_UNIX, unix.SOCK_STREAM}} {
		fd, err := unix.Socket(s.domain, s.kind|unix.SOCK_CLOEXEC, 0)
		report(s.key, errName(err))
		if err == nil {
			if err := unix.Close(fd); err != nil {
				t.Fatal(err)
			}
		}
	}

	if d, err := proxyFetchBig(client, "https://tls.proxy-fixture.test/big"); err != nil {
		report("cost", "error: "+err.Error())
	} else {
		report("cost", strconv.FormatInt(d.Milliseconds(), 10))
	}
}

func TestProxyProtoPublicOnly(t *testing.T) {
	own := []netip.Addr{netip.MustParseAddr("203.0.113.7")}
	for _, tc := range []struct {
		addr   string
		public bool
	}{
		{"127.0.0.1", false}, {"127.1.2.3", false}, {"::1", false}, {"::ffff:127.0.0.1", false},
		{"10.0.0.1", false}, {"172.16.0.1", false}, {"192.168.1.1", false}, {"fd00::1", false}, {"::ffff:10.0.0.1", false},
		{"169.254.169.254", false}, {"fe80::1", false}, {"fe80::1%lo", false},
		{"100.64.0.1", false}, {"100.127.255.254", false},
		{"224.0.0.1", false}, {"ff02::1", false}, {"255.255.255.255", false},
		{"0.0.0.0", false}, {"::", false},
		{"203.0.113.7", false}, {"::ffff:203.0.113.7", false},
		{"198.51.100.1", true}, {"100.128.0.1", true}, {"2001:db8::1", true}, {"::ffff:198.51.100.1", true},
	} {
		if got := proxyPublic(netip.MustParseAddr(tc.addr), own); got != tc.public {
			t.Errorf("public(%s) = %v, want %v", tc.addr, got, tc.public)
		}
	}
}

func TestProxyProtoSandboxedChild(t *testing.T) {
	fx := proxyNewFixture(t)
	run := proxyRunChild(t, fx, "", "confined", nil)
	if run.route != proxyRouteSlice {
		t.Fatalf("route %q, want the proxy route", run.route)
	}
	events := fx.proxy.since(0)
	r := run.results
	for key, want := range map[string]string{
		"allowed https": "200 tls tls.proxy-fixture.test",
		"allowed http":  "200 plain plain.proxy-fixture.test",
	} {
		if r[key] != want {
			t.Errorf("%s: %q, want %q", key, r[key], want)
		}
	}
	for _, key := range []string{"not approved https", "not approved http", "subdomain https"} {
		if strings.HasPrefix(r[key], "200 ") {
			t.Errorf("%s reached the server: %q", key, r[key])
		}
	}
	for _, e := range []proxyEvent{
		{http.MethodConnect, "denied.proxy-fixture.test", "not approved"},
		{http.MethodGet, "denied.proxy-fixture.test", "not approved"},
		{http.MethodConnect, "sub.tls.proxy-fixture.test", "not approved"},
	} {
		if !proxyHas(events, e.method, e.host, e.outcome) {
			t.Errorf("proxy did not record %s", e)
		}
	}
	for _, host := range proxyPublicOnlyHosts {
		if got := r["public only "+host]; got != "403 Forbidden not public" {
			t.Errorf("CONNECT %s through the proxy: %q, want refused as not public", host, got)
		}
	}
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		got := r["bypass "+host]
		if !strings.Contains(got, "operation not permitted") || proxyHas(events, http.MethodGet, host, "") {
			t.Errorf("Go client request to %s: %q, proxy saw it=%v; want a direct attempt the broker refuses", host, got, proxyHas(events, http.MethodGet, host, ""))
		}
	}
	t.Run("loopback name", func(t *testing.T) {
		if fx.loopbackName == "" {
			t.Skip("unverified: " + fx.loopbackUnverified)
		}
		got := r["bypass "+fx.loopbackName]
		if !strings.HasPrefix(got, "403 ") || !proxyHas(events, http.MethodGet, fx.loopbackName, "not public") {
			t.Errorf("Go client request to the loopback name %s: %q; want the proxy to refuse it as not public", fx.loopbackName, got)
		}
		t.Logf("loopback name %s through the proxy: client %q, proxy %v", fx.loopbackName, got,
			slices.DeleteFunc(slices.Clone(events), func(e proxyEvent) bool { return e.host != fx.loopbackName }))
	})
	for key, want := range map[string]string{
		"direct loopback":                        "EPERM",
		"direct other address at the proxy port": "EPERM",
		"v4-mapped proxy endpoint":               "0",
		"bind loopback":                          "EPERM",
		"bind any":                               "EPERM",
		"listen unbound":                         "EPERM",
		"fastopen sendto":                        "EPERM",
		"fastopen sendmsg":                       "EPERM",
		"fastopen sendmmsg":                      "EPERM",
		"udp socket":                             "EPERM",
		"unix socket":                            "EPERM",
		"other thread proxy connect":             "0",
		"separate file table proxy connect":      "EPERM",
		"leader socket after separate connect":   "ENOTCONN",
	} {
		if r[key] != want {
			t.Errorf("%s: %q, want %q", key, r[key], want)
		}
	}
	admitted := 0
	for _, entry := range run.broker {
		target, isAdmit := strings.CutPrefix(entry, "admit ")
		if isAdmit {
			admitted++
		}
		if strings.HasPrefix(entry, "error") || isAdmit && target != fx.proxy.addr.String() && target != "[::ffff:127.0.0.1]:"+strconv.Itoa(int(fx.proxy.addr.Port())) {
			t.Errorf("broker: %s", entry)
		}
	}
	plain := strconv.Itoa(int(fx.plainAddr.Port()))
	for _, want := range []string{"deny 127.0.0.1:" + plain, "deny 192.0.2.1:" + strconv.Itoa(int(fx.proxy.addr.Port())),
		"deny thread file table differs from its process's"} {
		if !slices.Contains(run.broker, want) {
			t.Errorf("broker log lacks %q: %q", want, run.broker)
		}
	}
	if admitted == 0 {
		t.Errorf("broker admitted nothing: %q", run.broker)
	}
	t.Logf("broker: %q", run.broker)
	t.Logf("proxy: %v", events)

	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: fx.roots}}
	direct := tr.Clone()
	direct.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", fx.tlsAddr.String())
	}
	viaProxy := tr.Clone()
	viaProxy.Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: fx.proxy.addr.String()})
	directTime, err := proxyFetchBig(proxyClient(direct), "https://tls.proxy-fixture.test/big")
	if err != nil {
		t.Fatal(err)
	}
	proxyTime, err := proxyFetchBig(proxyClient(viaProxy), "https://tls.proxy-fixture.test/big")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cost of %d x %d MiB over TLS, new connection each: direct %dms; through the proxy %dms; sandboxed child through broker and proxy %sms",
		proxyBigCount, proxyBigSize>>20, directTime.Milliseconds(), proxyTime.Milliseconds(), r["cost"])
}

type proxyObservation struct {
	exit   string
	proxy  []proxyEvent
	server []string
	output string
}

func (fx *proxyFixture) observe(t *testing.T, env []string, argv ...string) proxyObservation {
	t.Helper()
	p0, s0 := fx.proxy.count(), fx.hitCount()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if filepath.Base(argv[0]) == "curl" {
		argv = slices.Insert(argv, 1, "-q")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Dir = t.TempDir()
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	exit := "ok"
	if err != nil {
		exit = err.Error()
	}
	output := strings.Join(strings.Fields(string(out)), " ")
	if len(output) > 300 {
		output = output[:300] + "..."
	}
	return proxyObservation{exit, fx.proxy.since(p0), fx.hitsSince(s0), output}
}

func TestProxyProtoToolsHonorProxy(t *testing.T) {
	fx := proxyNewFixture(t)
	plain := strconv.Itoa(int(fx.plainAddr.Port()))
	bases := []string{"https://tls.proxy-fixture.test", "http://plain.proxy-fixture.test",
		"http://127.0.0.1:" + plain, "http://[::1]:" + plain, "http://localhost:" + plain}
	goEnv := func(dir, goproxy string, extra []string) []string {
		return fx.env(append(extra, "GOPROXY="+goproxy, "GOMODCACHE="+filepath.Join(dir, "modcache"), "GOPATH="+filepath.Join(dir, "gopath"),
			"GOFLAGS=-modcacherw", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOENV=off", "GONOPROXY=", "GOPRIVATE=", "GONOSUMDB=", "GOINSECURE=")...)
	}
	tools := []struct {
		name string
		run  func(t *testing.T, bin, base string, extra []string) proxyObservation
	}{
		{"go", func(t *testing.T, bin, base string, extra []string) proxyObservation {
			return fx.observe(t, goEnv(t.TempDir(), base+"/mod", extra), bin, "mod", "download", "-json", "mod.test/m@v1.0.0")
		}},
		{"curl", func(t *testing.T, bin, base string, extra []string) proxyObservation {
			return fx.observe(t, fx.env(extra...), bin, "-sS", "-o", "/dev/null", "--max-time", "10", base+"/")
		}},
		{"git", func(t *testing.T, bin, base string, extra []string) proxyObservation {
			return fx.observe(t, fx.env(extra...), bin, "ls-remote", base+"/r.git")
		}},
		{"hg", func(t *testing.T, bin, base string, extra []string) proxyObservation {
			return fx.observe(t, fx.env(extra...), bin, "--config", "web.cacerts="+fx.certFile, "identify", base+"/r")
		}},
		{"npm", func(t *testing.T, bin, base string, extra []string) proxyObservation {
			return fx.observe(t, fx.env(append(extra, "npm_config_cache="+t.TempDir())...), bin, "ping", "--registry="+base+"/npm/", "--fetch-retries=0", "--fetch-timeout=10000")
		}},
		{"pip", func(t *testing.T, bin, base string, extra []string) proxyObservation {
			u, err := url.Parse(base)
			if err != nil {
				t.Fatal(err)
			}
			return fx.observe(t, fx.env(extra...), bin, "download", "--no-deps", "--no-cache-dir", "--retries", "0", "--timeout", "10",
				"--trusted-host", u.Hostname(), "-d", t.TempDir(), "--index-url", base+"/simple/", "proxyfixturepkg")
		}},
	}
	for _, tool := range tools {
		t.Run(tool.name, func(t *testing.T) {
			bin, err := exec.LookPath(tool.name)
			if err != nil {
				if tool.name == "go" {
					t.Fatal(err)
				}
				t.Skipf("unverified: %v", err)
			}
			for _, base := range bases {
				obs := tool.run(t, bin, base, nil)
				t.Logf("%s %s: exit %s; proxy %v; server %q; output %q", tool.name, base, obs.exit, obs.proxy, obs.server, obs.output)
				if tool.name != "go" {
					continue
				}
				u, err := url.Parse(base)
				if err != nil {
					t.Fatal(err)
				}
				host := u.Hostname()
				switch {
				case u.Scheme == "https":
					if obs.exit != "ok" || !proxyHas(obs.proxy, http.MethodConnect, host, "ok") {
						t.Errorf("go mod download through %s: exit %s, proxy %v; want a download through the proxy", base, obs.exit, obs.proxy)
					}
				case strings.HasSuffix(host, ".proxy-fixture.test"):
					if obs.exit != "ok" || !proxyHas(obs.proxy, http.MethodGet, host, "ok") {
						t.Errorf("go mod download through %s: exit %s, proxy %v; want a download through the proxy", base, obs.exit, obs.proxy)
					}
				default:
					if len(obs.proxy) != 0 {
						t.Errorf("go mod download from %s went to the proxy: %v", base, obs.proxy)
					}
					if host == "127.0.0.1" && !slices.ContainsFunc(obs.server, func(h string) bool { return strings.HasPrefix(h, "plain 127.0.0.1:"+plain+" /mod/") }) {
						t.Errorf("go mod download from %s did not reach the server directly: %q", base, obs.server)
					}
				}
			}
			t.Run("loopback name", func(t *testing.T) {
				if fx.loopbackName == "" {
					t.Skip("unverified: " + fx.loopbackUnverified)
				}
				base := "http://" + net.JoinHostPort(fx.loopbackName, plain)
				obs := tool.run(t, bin, base, nil)
				t.Logf("%s %s: exit %s; proxy %v; server %q; output %q", tool.name, base, obs.exit, obs.proxy, obs.server, obs.output)
				if tool.name == "go" && (obs.exit == "ok" || !proxyHas(obs.proxy, http.MethodGet, fx.loopbackName, "not public")) {
					t.Errorf("go mod download from %s: exit %s, proxy %v; want a failure the proxy refused as not public", base, obs.exit, obs.proxy)
				}
			})
			noProxy := []string{"NO_PROXY=localhost,127.0.0.1,::1", "no_proxy=localhost,127.0.0.1,::1"}
			for _, base := range bases[2:5] {
				obs := tool.run(t, bin, base, noProxy)
				t.Logf("%s %s with NO_PROXY: exit %s; proxy %v; server %q; output %q", tool.name, base, obs.exit, obs.proxy, obs.server, obs.output)
			}
			t.Run("ambient config", func(t *testing.T) {
				want := tool.run(t, bin, bases[0], nil)
				rc := t.TempDir()
				if err := os.WriteFile(filepath.Join(rc, ".curlrc"), []byte("url = \"http://192.0.2.1/escaped\"\nnoproxy = \"*\"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				for k, v := range map[string]string{
					"CURL_HOME": rc, "npm_config_noproxy": "proxy-fixture.test", "GONOPROXY": "*",
					"PIP_EXTRA_INDEX_URL": "https://192.0.2.1/simple/", "PIP_FIND_LINKS": "https://192.0.2.1/links/",
					"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "url.http://192.0.2.1/.insteadOf", "GIT_CONFIG_VALUE_0": bases[0] + "/",
				} {
					t.Setenv(k, v)
				}
				got := tool.run(t, bin, bases[0], nil)
				if got.exit != want.exit || !slices.Equal(got.proxy, want.proxy) || !slices.Equal(got.server, want.server) {
					t.Errorf("%s with hostile ambient config: exit %s, proxy %v, server %q; want exit %s, proxy %v, server %q",
						tool.name, got.exit, got.proxy, got.server, want.exit, want.proxy, want.server)
				}
			})
			if tool.name == "go" {
				obs := fx.observe(t, goEnv(t.TempDir(), "direct", nil), bin, "mod", "download", "-json", "vcs.proxy-fixture.test/m@v1.0.0")
				t.Logf("go direct VCS fetch: exit %s; proxy %v; output %q", obs.exit, obs.proxy, obs.output)
				if !proxyHas(obs.proxy, http.MethodConnect, "vcs.proxy-fixture.test", "ok") {
					t.Errorf("go direct fetch did not look up the import path through the proxy: %v", obs.proxy)
				}
			}
		})
	}
}

func TestProxyProtoSandboxedTools(t *testing.T) {
	fx := proxyNewFixture(t)
	plain := strconv.Itoa(int(fx.plainAddr.Port()))
	sshOpts := []string{"-F", "/dev/null", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"}
	cases := []struct {
		name, tool string
		env        []string
		args       []string
		check      func(t *testing.T, run proxyRun, events []proxyEvent)
	}{
		{"curl through the proxy", "curl", nil, []string{"-sS", "--max-time", "10", "https://tls.proxy-fixture.test/"},
			func(t *testing.T, run proxyRun, events []proxyEvent) {
				if run.err != nil || run.out != "tls tls.proxy-fixture.test" || !proxyHas(events, http.MethodConnect, "tls.proxy-fixture.test", "ok") {
					t.Errorf("sandboxed curl: %v %q, proxy %v", run.err, run.out, events)
				}
			}},
		{"ssh to a loopback port", "ssh", nil, append(append([]string{"-p", plain}, sshOpts...), "127.0.0.1", "true"),
			func(t *testing.T, run proxyRun, _ []proxyEvent) {
				if run.err == nil || !slices.Contains(run.broker, "deny 127.0.0.1:"+plain) {
					t.Errorf("sandboxed ssh: %v, broker %q", run.err, run.broker)
				}
			}},
		{"ssh to a name", "ssh", nil, append(sshOpts, "nohost.proxy-fixture.test", "true"),
			func(t *testing.T, run proxyRun, _ []proxyEvent) {
				if run.err == nil {
					t.Errorf("sandboxed ssh to a name succeeded: %q", run.out)
				}
			}},
		{"git over ssh", "git", []string{"GIT_SSH_COMMAND=ssh " + strings.Join(sshOpts, " ")}, []string{"ls-remote", "ssh://127.0.0.1:" + plain + "/r"},
			func(t *testing.T, run proxyRun, _ []proxyEvent) {
				if run.err == nil || !slices.Contains(run.broker, "deny 127.0.0.1:"+plain) {
					t.Errorf("sandboxed git over ssh: %v, broker %q", run.err, run.broker)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, err := exec.LookPath(tc.tool)
			if err != nil {
				t.Skipf("unverified: %v", err)
			}
			p0 := fx.proxy.count()
			run := proxyRunChild(t, fx, "", "exec", tc.env, append([]string{bin}, tc.args...)...)
			events := fx.proxy.since(p0)
			t.Logf("exit %v; output %q; broker %q; proxy %v", run.err, strings.TrimSpace(run.out), run.broker, events)
			tc.check(t, run, events)
		})
	}
}

func TestProxyProtoEnvironmentDelivery(t *testing.T) {
	launch := []string{
		"HTTPS_PROXY=http://proxy.example:3128", "https_proxy=http://proxy.example:3128", "HTTP_PROXY=http://proxy.example:3128",
		"NO_PROXY=localhost,127.0.0.1", "ALL_PROXY=socks5://proxy.example:1080", "http_proxy=http://user:secret@proxy.example:3128",
	}
	inherited, withheld := runner.InheritedEnvironment(launch)
	t.Logf("current inheritance of a launch environment with proxy settings: inherited %q; withheld %q", inherited, withheld)
	_, err := runner.FixedEnvironment("/home/user", "/work", "/tmp/session", runner.FixedPATH, []string{"HTTPS_PROXY=http://127.0.0.1:1"})
	t.Logf("command-supplied HTTPS_PROXY assignment: %v", err)
}
