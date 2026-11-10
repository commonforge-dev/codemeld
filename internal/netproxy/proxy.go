// Package netproxy is the HTTP proxy that gives sandboxed commands network access to approved
// hosts and ports on public internet addresses that are not this machine's own.
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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Refusal struct {
	Host   string
	Port   string
	Reason string
}

type Decision int

const (
	DecisionDeny Decision = iota
	DecisionOnce
	DecisionSession
)

type Asker func(ctx context.Context, host, port string, covered func() bool, accept func(Decision) bool) (Decision, error)

type Server struct {
	allow        map[string]bool
	approvals    approvals
	resolve      func(ctx context.Context, host string) ([]netip.Addr, error)
	dial         func(ctx context.Context, network, address string) (net.Conn, error)
	ownAddrs     func() ([]netip.Addr, error)
	registerWait time.Duration

	ctx    context.Context
	cancel context.CancelCauseFunc
	ln     net.Listener
	wg     sync.WaitGroup

	mu       sync.Mutex
	stopped  bool
	conns    map[net.Conn]struct{}
	refusals []Refusal
	pending  map[netip.AddrPort]*registration
	waiting  map[netip.AddrPort]*waiter
	// Endpoints stay quarantined for the server's lifetime: a late registration and a new connection
	// reusing the same peer endpoint are indistinguishable, so neither may inherit an owner.
	quarantined map[netip.AddrPort]bool
}

type Owner struct {
	s        *Server
	ask      Asker
	ctx      context.Context
	cancel   context.CancelFunc
	closed   bool
	conns    map[net.Conn]struct{}
	regs     map[*registration]struct{}
	refusals []Refusal
	handlers sync.WaitGroup
	once     sync.Once
}

type registration struct {
	owner *Owner
	peer  netip.AddrPort
	timer *time.Timer
}

type waiter struct {
	conn    net.Conn
	matched chan *Owner
}

var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"TE", "Trailer", "Transfer-Encoding", "Upgrade",
}

func New(allow []string) (*Server, error) {
	s := &Server{
		allow:     map[string]bool{},
		approvals: approvals{session: map[string]bool{}},
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		dial:         (&net.Dialer{}).DialContext,
		ownAddrs:     interfaceAddrs,
		registerWait: 5 * time.Second,
		conns:        map[net.Conn]struct{}{},
		pending:      map[netip.AddrPort]*registration{},
		waiting:      map[netip.AddrPort]*waiter{},
		quarantined:  map[netip.AddrPort]bool{},
	}
	for _, entry := range allow {
		host, port, err := net.SplitHostPort(entry)
		if err != nil {
			continue
		}
		if key, ok := targetKey(host, port); ok {
			s.allow[key] = true
		}
	}
	s.ctx, s.cancel = context.WithCancelCause(context.Background())
	return s, nil
}

func (s *Server) Start() (string, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	s.ln = ln
	s.wg.Go(s.acceptLoop)
	return ln.Addr().String(), nil
}

func (s *Server) Stop() {
	s.approvals.end(func() { s.cancel(errSessionEnded) })
	if s.ln != nil {
		_ = s.ln.Close()
	}
	s.mu.Lock()
	s.stopped = true
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()
	for c := range conns {
		_ = c.Close()
	}
	s.wg.Wait()
}

func (s *Server) NewOwner(ask Asker) *Owner {
	o := &Owner{s: s, ask: ask, conns: map[net.Conn]struct{}{}, regs: map[*registration]struct{}{}}
	o.ctx, o.cancel = context.WithCancel(s.ctx)
	return o
}

func (o *Owner) Register(local netip.AddrPort) error {
	peer := canonical(local)
	s := o.s
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case o.closed || s.stopped || o.ctx.Err() != nil:
		return errors.New("netproxy: the connection owner has ended")
	case s.quarantined[peer]:
		return fmt.Errorf("netproxy: peer endpoint %s was already used", peer)
	}
	if w := s.waiting[peer]; w != nil {
		delete(s.waiting, peer)
		s.quarantined[peer] = true
		o.attach(w.conn)
		w.matched <- o
		return nil
	}
	if old := s.pending[peer]; old != nil {
		s.retire(old)
		return fmt.Errorf("netproxy: peer endpoint %s registered twice", peer)
	}
	r := &registration{owner: o, peer: peer}
	s.pending[peer] = r
	o.regs[r] = struct{}{}
	r.timer = time.AfterFunc(s.registerWait, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.pending[peer] == r {
			s.retire(r)
		}
	})
	return nil
}

func (o *Owner) Close() {
	o.once.Do(func() {
		s := o.s
		s.approvals.end(o.cancel)
		s.mu.Lock()
		o.closed = true
		for r := range o.regs {
			s.retire(r)
		}
		conns := o.conns
		o.conns = nil
		s.mu.Unlock()
		for c := range conns {
			_ = c.Close()
		}
		o.handlers.Wait()
	})
}

func (o *Owner) Refusals() []Refusal {
	o.s.mu.Lock()
	defer o.s.mu.Unlock()
	return slices.Clone(o.refusals)
}

func (o *Owner) attach(c net.Conn) {
	o.handlers.Add(1)
	o.conns[c] = struct{}{}
}

func (s *Server) retire(r *registration) {
	r.timer.Stop()
	delete(s.pending, r.peer)
	delete(r.owner.regs, r)
	s.quarantined[r.peer] = true
}

func canonical(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(normalize(ap.Addr()), ap.Port())
}

func (s *Server) claim(c net.Conn, br *bufio.Reader) *Owner {
	addr, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	peer := canonical(addr.AddrPort())
	s.mu.Lock()
	if s.stopped || s.quarantined[peer] || s.waiting[peer] != nil {
		s.mu.Unlock()
		return nil
	}
	if r := s.pending[peer]; r != nil {
		s.retire(r)
		if r.owner.ctx.Err() != nil {
			s.mu.Unlock()
			return nil
		}
		r.owner.attach(c)
		s.mu.Unlock()
		return r.owner
	}
	w := &waiter{conn: c, matched: make(chan *Owner, 1)}
	s.waiting[peer] = w
	s.mu.Unlock()
	defer watchClient(c, br, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.expire(peer, w)
	})()
	timer := time.NewTimer(s.registerWait)
	defer timer.Stop()
	select {
	case o := <-w.matched:
		return o
	case <-timer.C:
	case <-s.ctx.Done():
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(peer, w)
	return <-w.matched
}

func (s *Server) expire(peer netip.AddrPort, w *waiter) {
	if s.waiting[peer] == w {
		delete(s.waiting, peer)
		s.quarantined[peer] = true
		w.matched <- nil
	}
}

func (s *Server) Refusals() []Refusal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.refusals)
}

func (s *Server) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		if s.track(c) {
			s.wg.Go(func() { s.handle(c) })
		}
	}
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		_ = c.Close()
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(o *Owner, c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	if o != nil {
		delete(o.conns, c)
	}
	s.mu.Unlock()
	_ = c.Close()
}

func (s *Server) handle(c net.Conn) {
	br := bufio.NewReaderSize(c, 64<<10)
	o := s.claim(c, br)
	if o == nil {
		s.untrack(nil, c)
		return
	}
	defer o.handlers.Done()
	defer s.untrack(o, c)
	ctx, cancel := context.WithCancel(o.ctx)
	defer cancel()
	req, err := http.ReadRequest(br)
	if err != nil {
		if ctx.Err() == nil {
			s.refuse(c, o, "", "", http.StatusBadRequest, "bad request")
		}
		return
	}
	host, port, ok := requestTarget(req)
	if !ok {
		s.refuse(c, o, host, port, http.StatusBadRequest, "bad request")
		return
	}
	stopWatch := watchClient(c, br, func() { s.approvals.end(cancel) })
	up, reason := s.connect(ctx, o, host, port)
	stopWatch()
	if ctx.Err() != nil {
		if up != nil {
			s.untrack(o, up)
		}
		reason = ended(ctx)
	}
	if reason != "" {
		s.refuse(c, o, host, port, http.StatusForbidden, reason)
		return
	}
	defer s.untrack(o, up)
	if req.Method == http.MethodConnect {
		tunnel(c, br, up)
		return
	}
	forward(c, req, up)
}

func watchClient(c net.Conn, br *bufio.Reader, cancel context.CancelFunc) (stop func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, err := br.Peek(br.Buffered() + 1)
			if err == nil {
				continue
			}
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				cancel()
			}
			return
		}
	}()
	return func() {
		_ = c.SetReadDeadline(time.Unix(1, 0))
		<-done
		_ = c.SetReadDeadline(time.Time{})
	}
}

func requestTarget(req *http.Request) (string, string, bool) {
	authority, defaultPort := req.URL.Host, ""
	if req.Method == http.MethodConnect {
		if authority != req.RequestURI {
			return "", "", false
		}
	} else {
		if req.URL.Scheme != "http" || req.URL.Host == "" {
			return "", "", false
		}
		authority, defaultPort = req.URL.Host, "80"
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		if defaultPort == "" {
			return "", "", false
		}
		if host, port, err = net.SplitHostPort(authority + ":" + defaultPort); err != nil {
			return "", "", false
		}
	}
	key, ok := targetKey(host, port)
	if !ok {
		return host, port, false
	}
	host, port, _ = net.SplitHostPort(key)
	return host, port, true
}

func targetKey(host, port string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" {
			return "", false
		}
		host = a.String()
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if !validHost(host) || err != nil || n == 0 {
		return "", false
	}
	return net.JoinHostPort(host, strconv.FormatUint(n, 10)), true
}

func validHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > 63 || strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			return false
		}
	}
	return true
}

func (s *Server) connect(ctx context.Context, o *Owner, host, port string) (net.Conn, string) {
	if reason := s.approve(ctx, o, host, port); reason != "" {
		return nil, reason
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else if addrs, err = s.resolve(ctx, host); err != nil || len(addrs) == 0 {
		return nil, "lookup failed"
	}
	addr, reason := choose(addrs, s.ownAddrs)
	if reason != "" {
		return nil, reason
	}
	up, err := s.dial(ctx, "tcp", net.JoinHostPort(addr.String(), port))
	if err != nil {
		return nil, "dial failed"
	}
	if !s.trackUpstream(ctx, o, up) {
		return nil, "dial failed"
	}
	return up, ""
}

func (s *Server) trackUpstream(ctx context.Context, o *Owner, up net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || o.closed || ctx.Err() != nil {
		_ = up.Close()
		return false
	}
	s.conns[up] = struct{}{}
	o.conns[up] = struct{}{}
	return true
}

func (s *Server) refuse(c net.Conn, o *Owner, host, port string, status int, reason string) {
	mine := Refusal{Host: host, Port: port, Reason: reason}
	if status == http.StatusBadRequest {
		mine.Host, mine.Port = "", ""
	}
	s.mu.Lock()
	s.refusals = append(s.refusals, Refusal{Host: host, Port: port, Reason: reason})
	o.refusals = append(o.refusals, mine)
	s.mu.Unlock()
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nX-Proxy-Refused: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		status, http.StatusText(status), reason)
}

func tunnel(c net.Conn, br *bufio.Reader, up net.Conn) {
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	var wg sync.WaitGroup
	relay := func(dst io.Writer, src io.Reader) {
		_, _ = io.Copy(dst, src)
		_ = c.Close()
		_ = up.Close()
	}
	wg.Go(func() { relay(up, br) })
	wg.Go(func() { relay(c, up) })
	wg.Wait()
}

func forward(c net.Conn, req *http.Request, up net.Conn) {
	req.Body = stripHopByHop(req.Header, req.Trailer, req.Body)
	req.Close = true
	var upload sync.WaitGroup
	defer upload.Wait()
	defer func() {
		_ = c.Close()
		_ = up.Close()
	}()
	upload.Go(func() {
		if req.Write(up) != nil {
			if cw, ok := up.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		}
	})
	resp, err := http.ReadResponse(bufio.NewReader(up), req)
	if err != nil {
		return
	}
	resp.Body = closeConnFirst{stripHopByHop(resp.Header, resp.Trailer, resp.Body), up}
	defer func() { _ = resp.Body.Close() }()
	resp.Close = true
	_ = resp.Write(c)
}

// closeConnFirst closes the upstream connection before the body, because net/http's body Close
// drains a persistent response to EOF and would block on a stalled upstream.
type closeConnFirst struct {
	io.ReadCloser
	conn net.Conn
}

func (b closeConnFirst) Close() error {
	_ = b.conn.Close()
	return b.ReadCloser.Close()
}

// stripHopByHop returns body wrapped so that trailer fields, which net/http merges into trailer
// when body reaches EOF and writes after it, are stripped before they are serialized.
func stripHopByHop(h, trailer http.Header, body io.ReadCloser) io.ReadCloser {
	names := slices.Clone(hopByHop)
	for _, v := range h.Values("Connection") {
		for name := range strings.SplitSeq(v, ",") {
			names = append(names, strings.TrimSpace(name))
		}
	}
	for _, name := range names {
		h.Del(name)
		trailer.Del(name)
	}
	if trailer == nil || body == nil {
		return body
	}
	return &trailerStripper{ReadCloser: body, trailer: trailer, names: names}
}

type trailerStripper struct {
	io.ReadCloser
	trailer http.Header
	names   []string
}

func (s *trailerStripper) Read(p []byte) (int, error) {
	n, err := s.ReadCloser.Read(p)
	if err == io.EOF {
		for _, name := range s.names {
			s.trailer.Del(name)
		}
	}
	return n, err
}
