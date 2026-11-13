package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/netproxy"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/vcs"
)

type confinement struct {
	constrained   bool
	mode          func() string
	home          string
	projectRoot   string
	writable      *writableFoldersReader
	blocked       *permissions.BlockedPaths
	lookupPath    string
	lookupSet     bool
	tmpDir        string
	owned         *ownedTempDirs
	inherited     []string
	warning       string
	broker        string
	decide        func(netip.AddrPort) bool
	proxy         *sessionProxy
	proxyAsker    netproxy.Asker
	connectAsker  connectAsker
	grants        []string
	connectGrants []string
	deny          *sessionDenyList
	approvals     *connectApprovals
}

type connectAsker func(ctx context.Context, dest string, covered func() bool, accept func(netproxy.Decision) bool) (netproxy.Decision, error)

const (
	connectSessionApproval = "session approval"
	connectPromptOnce      = "prompt once"
	connectPromptSession   = "prompt session"
	connectDenied          = "not approved (denied)"
)

type connectApprovals struct {
	mu     sync.Mutex
	closed bool
	held   map[any]*os.File
}

func (a *connectApprovals) covers(key any) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.held[key]
	return ok
}

func (a *connectApprovals) add(key any, hold func() (*os.File, error)) bool {
	var f *os.File
	if hold != nil {
		var err error
		if f, err = hold(); err != nil {
			return false
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.held[key]; ok || a.closed {
		if f != nil {
			_ = f.Close()
		}
		return !a.closed
	}
	a.held[key] = f
	return true
}

func (a *connectApprovals) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	for _, f := range a.held {
		if f != nil {
			_ = f.Close()
		}
	}
	a.held = nil
}

func (c *confinement) answerConnect(ctx context.Context, live func() bool, key any, dest string, hold func() (*os.File, error)) (step, reason string) {
	if c.approvals.covers(key) {
		return connectSessionApproval, ""
	}
	if c.connectAsker == nil {
		return "", ""
	}
	var mu sync.Mutex
	covered, returned, accepted := false, false, netproxy.DecisionDeny
	accept := func(d netproxy.Decision) bool {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case returned || ctx.Err() != nil || !live() || (d != netproxy.DecisionOnce && d != netproxy.DecisionSession):
			return false
		case accepted != netproxy.DecisionDeny:
			return d == accepted
		case d == netproxy.DecisionSession && !c.approvals.add(key, hold):
			return false
		}
		accepted = d
		return true
	}
	d, err := c.connectAsker(ctx, dest, func() bool {
		mu.Lock()
		defer mu.Unlock()
		covered = covered || c.approvals.covers(key)
		return covered
	}, accept)
	mu.Lock()
	defer mu.Unlock()
	returned = true
	switch {
	case accepted == netproxy.DecisionSession:
		return connectPromptSession, ""
	case accepted == netproxy.DecisionOnce:
		return connectPromptOnce, ""
	case covered:
		return connectSessionApproval, ""
	case ctx.Err() != nil:
		return "", "not approved (command ended)"
	case errors.Is(err, errAppShuttingDown):
		return "", "not approved (session ended)"
	case err == nil && d == netproxy.DecisionDeny:
		return "", connectDenied
	}
	return "", "not approved (prompt failed)"
}

type proxyState int

const (
	proxyIdle proxyState = iota
	proxyStarting
	proxyRunning
	proxyFailed
)

type sessionProxy struct {
	mu       sync.Mutex
	changed  *sync.Cond
	state    proxyState
	closed   bool
	server   *netproxy.Server
	endpoint netip.AddrPort
	err      error
	launches map[launchStopper]struct{}
	allow    []string
}

type launchStopper interface{ stopBroker() }

var errSessionProxyStopped = errors.New("codemeld confinement: the session network proxy has stopped")

var startSessionProxy = func(allow []string) (*netproxy.Server, string, error) {
	server, err := netproxy.New(allow)
	if err != nil {
		return nil, "", err
	}
	addr, err := server.Start()
	if err != nil {
		server.Stop()
		return nil, "", err
	}
	return server, addr, nil
}

func newSessionProxy(allow []string) *sessionProxy {
	p := &sessionProxy{allow: allow}
	p.changed = sync.NewCond(&p.mu)
	return p
}

func (p *sessionProxy) start() (netip.AddrPort, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.state == proxyStarting {
		p.changed.Wait()
	}
	switch {
	case p.closed:
		return netip.AddrPort{}, errSessionProxyStopped
	case p.state == proxyRunning:
		return p.endpoint, nil
	case p.state == proxyFailed:
		return netip.AddrPort{}, p.err
	}
	p.state = proxyStarting
	p.mu.Unlock()
	server, addr, err := startSessionProxy(p.allow)
	var endpoint netip.AddrPort
	if err == nil {
		if endpoint, err = netip.ParseAddrPort(addr); err != nil {
			server.Stop()
		}
	}
	p.mu.Lock()
	defer p.changed.Broadcast()
	if err != nil {
		p.state, p.err = proxyFailed, fmt.Errorf("codemeld confinement: start the session network proxy: %w", err)
		return netip.AddrPort{}, p.err
	}
	p.state, p.server, p.endpoint = proxyRunning, server, endpoint
	if p.closed {
		return netip.AddrPort{}, errSessionProxyStopped
	}
	return endpoint, nil
}

func (p *sessionProxy) admits(dest netip.AddrPort) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state == proxyRunning && !p.closed && dest == p.endpoint
}

func (p *sessionProxy) running() *netproxy.Server {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != proxyRunning || p.closed {
		return nil
	}
	return p.server
}

func (p *sessionProxy) track(l launchStopper) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errSessionProxyStopped
	}
	if p.launches == nil {
		p.launches = map[launchStopper]struct{}{}
	}
	p.launches[l] = struct{}{}
	return nil
}

func (p *sessionProxy) untrack(l launchStopper) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.launches, l)
}

func (p *sessionProxy) stop() {
	p.mu.Lock()
	p.closed = true
	for p.state == proxyStarting {
		p.changed.Wait()
	}
	server := p.server
	p.server = nil
	launches := p.launches
	p.launches = nil
	p.mu.Unlock()
	// The listener must outlive every broker that may still connect to an endpoint it admitted.
	for l := range launches {
		l.stopBroker()
	}
	if server != nil {
		server.Stop()
	}
}

type ownedTempDirs struct {
	mu   sync.Mutex
	dirs map[string]*sessionTempDir
}

func (c *confinement) own(dir *sessionTempDir) {
	if c.proxy == nil {
		c.proxy = newSessionProxy(c.grants)
		c.decide = c.proxy.admits
		if c.broker == enforce.BrokerConnect || c.broker == enforce.BrokerFull {
			c.deny = newSessionDenyList()
			c.approvals = &connectApprovals{held: map[any]*os.File{}}
		}
	}
	if dir == nil {
		return
	}
	if c.owned == nil {
		c.owned = &ownedTempDirs{dirs: map[string]*sessionTempDir{}}
	}
	c.owned.mu.Lock()
	defer c.owned.mu.Unlock()
	c.owned.dirs[dir.path] = dir
}

func (c *confinement) release(dir *sessionTempDir) error {
	if c.owned == nil || dir == nil {
		return nil
	}
	c.owned.mu.Lock()
	defer c.owned.mu.Unlock()
	if c.owned.dirs[dir.path] != dir {
		return nil
	}
	if err := dir.remove(); err != nil {
		return err
	}
	delete(c.owned.dirs, dir.path)
	return nil
}

func (c *confinement) ownerOf(path string) *sessionTempDir {
	if c.owned == nil {
		return nil
	}
	c.owned.mu.Lock()
	defer c.owned.mu.Unlock()
	return c.owned.dirs[path]
}

func (c *confinement) prepareReplacement() (folder string, rollback func() error, err error) {
	if c == nil || c.tmpDir == "" {
		return "", func() error { return nil }, nil
	}
	dir, err := newSessionTempDir()
	c.own(dir)
	if err != nil {
		return "", func() error { return nil }, err
	}
	return dir.path, sync.OnceValue(func() error { return c.release(dir) }), nil
}

func (c *confinement) commitReplacement(folder string) {
	if c == nil || folder == "" {
		return
	}
	old := c.tmpDir
	c.tmpDir = folder
	if err := c.release(c.ownerOf(old)); err != nil {
		c.warning = fmt.Sprintf("can't remove private temp folder %s: %v; codemeld retries when it exits", old, err)
	}
}

func (c *confinement) takeCleanupWarning() string {
	if c == nil {
		return ""
	}
	warning := c.warning
	c.warning = ""
	return warning
}

func (c *confinement) cleanupAll() error {
	if c.proxy != nil {
		c.proxy.stop()
	}
	if c.deny != nil {
		c.deny.Close()
	}
	if c.approvals != nil {
		c.approvals.close()
	}
	if c.owned == nil {
		return nil
	}
	c.owned.mu.Lock()
	defer c.owned.mu.Unlock()
	var errs []error
	for _, path := range slices.Sorted(maps.Keys(c.owned.dirs)) {
		errs = append(errs, c.owned.dirs[path].removeAndRelease())
		delete(c.owned.dirs, path)
	}
	return errors.Join(errs...)
}

var confinementProbePins = []string{"GOTOOLCHAIN=local", "MISE_OFFLINE=1"}

func (c *confinement) resolve(ctx context.Context) (current, tmpDir string, confined bool, err error) {
	if c == nil || !c.constrained {
		return "", "", false, nil
	}
	current, ok := vcs.ConfinementMode(ctx)
	if !ok && c.mode != nil {
		current = c.mode()
	}
	switch mode.Mode(current) {
	case mode.Build:
		return current, "", false, nil
	case mode.Plan, mode.AutoEdits:
		if c.tmpDir == "" {
			return current, "", true, fmt.Errorf("bootstrap: confined %s run has no private temporary folder", current)
		}
		return current, c.tmpDir, true, nil
	}
	return current, "", true, fmt.Errorf("bootstrap: confined run refused for unrecognized mode %q", current)
}

func (c *confinement) prepare(spec runner.RunSpec, tmpDir string, blocked *permissions.BlockedPaths, proxyURL string) (runner.RunSpec, error) {
	home := c.home
	if home == "" {
		home = blocked.Home()
	}
	lookup := c.lookupPath
	if lookup == "" && !c.lookupSet {
		lookup = runner.FixedPATH
	}
	assignments := slices.Clone(spec.Assignments)
	for _, pin := range confinementProbePins {
		if slices.Contains(spec.Env, pin) {
			assignments = append(assignments, pin)
		}
	}
	env, err := runner.FixedEnvironment(home, spec.Cwd, tmpDir, lookup, assignments)
	if err != nil {
		return runner.RunSpec{}, err
	}
	if proxyURL != "" {
		env = append(env, "HTTPS_PROXY="+proxyURL, "HTTP_PROXY="+proxyURL, "https_proxy="+proxyURL, "http_proxy="+proxyURL,
			"NO_PROXY=localhost,127.0.0.1,::1", "no_proxy=localhost,127.0.0.1,::1")
	}
	set := make(map[string]bool, len(env))
	for _, e := range env {
		name, _, _ := strings.Cut(e, "=")
		set[name] = true
	}
	if proxyURL != "" {
		set["ALL_PROXY"], set["all_proxy"] = true, true
	}
	var launchTemp string
	if tmpDir != "" {
		if abs, err := unresolvedAbs(os.TempDir()); err == nil {
			launchTemp, _ = reachableDir(abs)
		}
	}
	gitBlocked := gitGlobalConfigBlocked(home, blocked)
	set["GIT_CONFIG_GLOBAL"] = set["GIT_CONFIG_GLOBAL"] || gitBlocked
	merged := make([]string, 0, len(c.inherited)+len(env)+1)
	for _, e := range c.inherited {
		if name, value, _ := strings.Cut(e, "="); !set[name] {
			if launchTemp != "" && namesFolder(value, spec.Cwd, launchTemp) {
				e = name + "=" + tmpDir
			}
			merged = append(merged, e)
		}
	}
	env = append(merged, env...)
	if gitBlocked {
		env = append(env, "GIT_CONFIG_GLOBAL=/dev/null")
	}
	prepared := cloneSpec(spec)
	prepared.Env = env
	if len(prepared.Argv) > 0 {
		if prepared.Argv[0], err = runner.ResolveOnPath(prepared.Argv[0], lookup); err != nil {
			return runner.RunSpec{}, err
		}
	}
	return prepared, nil
}

func namesFolder(value, cwd, folder string) bool {
	if value == "" {
		return false
	}
	if !filepath.IsAbs(value) {
		if !filepath.IsAbs(cwd) {
			return false
		}
		// filepath.Join would clean "link/.." lexically before the link is resolved.
		value = cwd + string(filepath.Separator) + value
	}
	resolved, ok := reachableDir(value)
	return ok && resolved == folder
}

// EvalSymlinks can drop "dir/.." as text without the search permission the kernel needs on dir.
func reachableDir(path string) (string, bool) {
	original, err := os.Stat(path)
	if err != nil || !original.IsDir() {
		return "", false
	}
	resolved, isDir, err := resolvedDir(path)
	if err != nil || !isDir {
		return "", false
	}
	info, err := os.Stat(resolved)
	if err != nil || !os.SameFile(original, info) {
		return "", false
	}
	return resolved, true
}

func unresolvedAbs(path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return wd + string(filepath.Separator) + path, nil
}

func gitGlobalConfigBlocked(home string, blocked *permissions.BlockedPaths) bool {
	if home == "" {
		return false
	}
	_, global := blocked.Blocking(filepath.Join(home, ".gitconfig"))
	_, xdg := blocked.Blocking(filepath.Join(home, ".config", "git", "config"))
	return global || xdg
}

func (c *confinement) confine(ctx context.Context, spec runner.RunSpec, current, tmpDir string, storesWritable bool) (runner.RunSpec, bool, error) {
	// A child's VCS actions run through the parent's registered runner and confinement, so only the call can say it is a child's.
	if (c.proxyAsker != nil || c.connectAsker != nil) && vcs.ChildInvocationID(ctx) != "" {
		child := *c
		child.proxyAsker, child.connectAsker = nil, nil
		c = &child
	}
	blocked := c.blocked.Current()
	policy, err := c.policy(current, tmpDir, blocked, storesWritable)
	if err != nil {
		return runner.RunSpec{}, false, err
	}
	proxyRoute := policy.Broker != enforce.BrokerNone
	var proxyURL string
	if proxyRoute {
		if c.proxy == nil {
			return runner.RunSpec{}, false, errors.New("codemeld confinement: no session network proxy for this run")
		}
		endpoint, err := c.proxy.start()
		if err != nil {
			return runner.RunSpec{}, false, err
		}
		proxyURL = "http://" + endpoint.String()
	}
	prepared, err := c.prepare(spec, tmpDir, blocked, proxyURL)
	if err != nil {
		return runner.RunSpec{}, false, err
	}
	// The helper is this binary, whose package init resolves TERM through infocmp on the unconfined launch PATH; RunHelper restores TERM=dumb.
	if i := slices.Index(prepared.Env, "TERM=dumb"); i >= 0 {
		prepared.Env[i] = "TERM="
	}
	var frame bytes.Buffer
	if err := enforce.WritePolicyFrame(&frame, policy); err != nil {
		return runner.RunSpec{}, false, fmt.Errorf("codemeld confinement: policy frame: %w", err)
	}
	prepared.Argv = append([]string{"/proc/self/exe", enforce.HelperCommand}, prepared.Argv...)
	prepared.Stdin = append(frame.Bytes(), prepared.Stdin...)
	if policy.Broker != enforce.BrokerNone {
		if err := c.attachBroker(&prepared, policy); err != nil {
			return runner.RunSpec{}, false, err
		}
	}
	return prepared, proxyRoute, nil
}

func (c *confinement) policy(current, tmpDir string, blocked *permissions.BlockedPaths, storesWritable bool) (enforce.Policy, error) {
	p := enforce.Policy{Mode: current, BlockedPaths: blocked.Forms()}
	skills, err := c.skillsReadRoots(blocked)
	if err != nil {
		return enforce.Policy{}, err
	}
	p.ReadRoots = skills
	if mode.Mode(current) == mode.Plan {
		dir := c.ownerOf(tmpDir)
		if dir == nil {
			return enforce.Policy{}, fmt.Errorf("bootstrap: confined plan run has no private temporary folder handle for %s", tmpDir)
		}
		if p.TmpDirDev, p.TmpDirIno, err = dir.identity(); err != nil {
			return enforce.Policy{}, err
		}
		p.TmpDir = tmpDir
		if c.broker != enforce.BrokerNone {
			p.Broker = enforce.BrokerSlice
		}
		return p, nil
	}
	if mode.Mode(current) != mode.AutoEdits {
		return p, nil
	}
	if c.projectRoot == "" {
		return enforce.Policy{}, errors.New("bootstrap: confined auto_edits run has no project root")
	}
	root, err := filepath.EvalSymlinks(c.projectRoot)
	if err != nil {
		return enforce.Policy{}, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return enforce.Policy{}, err
	}
	p.NoWritePaths = []string{filepath.Join(root, ".codemeld")}
	if candidate, ok := c.skillsCandidate(blocked); ok {
		resolved, ok, err := resolvedDir(candidate)
		if err != nil {
			return enforce.Policy{}, err
		}
		if ok {
			p.NoWritePaths = append(p.NoWritePaths, resolved)
		}
	}
	for _, e := range entries {
		if e.Name() == ".codemeld" {
			continue
		}
		target, err := filepath.EvalSymlinks(filepath.Join(root, e.Name()))
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(root, target)
		first, _, _ := strings.Cut(filepath.ToSlash(rel), "/")
		if err != nil || first == "." || first == ".." || first == ".codemeld" || slices.Contains(p.WriteRoots, target) {
			continue
		}
		p.WriteRoots = append(p.WriteRoots, target)
	}
	repos := []string{root}
	if c.writable != nil && !blocked.Degraded() {
		for _, folder := range c.writable.current() {
			repos = append(repos, folder)
			if !slices.Contains(p.WriteRoots, folder) {
				p.WriteRoots = append(p.WriteRoots, folder)
			}
		}
	}
	p.TmpDir = tmpDir
	if !storesWritable {
		if p.NoWritePaths, err = withHistoryStores(p.NoWritePaths, repos, p.WriteRoots, tmpDir); err != nil {
			return enforce.Policy{}, err
		}
	}
	p.Broker = c.broker
	return p, nil
}

func withHistoryStores(noWrite, repos, writeRoots []string, tmpDir string) ([]string, error) {
	writable := append(slices.Clone(writeRoots), tmpDir)
	for _, repo := range repos {
		stores, err := permissions.HistoryStores(repo)
		if err != nil {
			return nil, err
		}
		for _, store := range stores {
			if slices.ContainsFunc(writable, func(w string) bool { return resolvedWithin(store, w) || resolvedWithin(w, store) }) {
				noWrite = append(noWrite, store)
			}
		}
	}
	return noWrite, nil
}

func (c *confinement) skillsReadRoots(blocked *permissions.BlockedPaths) ([]string, error) {
	if blocked.Degraded() {
		return nil, nil
	}
	candidate, ok := c.skillsCandidate(blocked)
	if !ok {
		return nil, nil
	}
	fold := blocked.FoldCase()
	var floor string
	for _, entry := range blocked.Entries() {
		if entry.Floor() {
			floor = entry.Path
			continue
		}
		if _, ok := permissions.RelWithin(entry.Path, candidate, fold); ok {
			return nil, nil
		}
		if _, ok := permissions.RelWithin(candidate, entry.Path, fold); ok {
			return nil, nil
		}
	}
	resolved, ok, err := resolvedDir(candidate)
	if !ok || err != nil {
		return nil, err
	}
	floorReal, ok, err := resolvedDir(floor)
	if !ok || err != nil {
		return nil, err
	}
	if !resolvedWithin(resolved, filepath.Join(floorReal, "skills")) && (resolvedWithin(resolved, floorReal) || resolvedWithin(floorReal, resolved)) {
		return nil, nil
	}
	return []string{resolved}, nil
}

func (c *confinement) skillsCandidate(blocked *permissions.BlockedPaths) (string, bool) {
	home := c.home
	if home == "" {
		home = blocked.Home()
	}
	if !filepath.IsAbs(home) {
		return "", false
	}
	return filepath.Join(home, ".codemeld", "skills"), true
}

func resolvedWithin(path, base string) bool {
	rel, err := filepath.Rel(base, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

func resolvedDir(path string) (string, bool, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		var info os.FileInfo
		if info, err = os.Stat(resolved); err == nil {
			return resolved, info.IsDir(), nil
		}
	}
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return "", false, nil
	}
	return "", false, err
}

func cloneSpecs(specs []runner.RunSpec) []runner.RunSpec {
	cloned := make([]runner.RunSpec, len(specs))
	for i, spec := range specs {
		cloned[i] = cloneSpec(spec)
	}
	return cloned
}

func cloneSpec(spec runner.RunSpec) runner.RunSpec {
	spec.Argv = slices.Clone(spec.Argv)
	spec.Env = slices.Clone(spec.Env)
	spec.Assignments = slices.Clone(spec.Assignments)
	spec.Stdin = slices.Clone(spec.Stdin)
	return spec
}

type confinedRunner struct {
	inner          runner.Runner
	conf           *confinement
	cap            int
	storesWritable bool
	mu             sync.Mutex
	pending        map[string][]runner.RunSpec
}

var (
	_ runner.Runner         = (*confinedRunner)(nil)
	_ runner.PipelineRunner = (*confinedRunner)(nil)
)

func (r *confinedRunner) NewInvocationID() string { return r.inner.NewInvocationID() }

func (r *confinedRunner) Exec(ctx context.Context, spec runner.RunSpec) (runner.RunResult, error) {
	current, tmpDir, confined, err := r.conf.resolve(ctx)
	if err != nil {
		return runner.RunResult{}, err
	}
	if !confined {
		return r.inner.Exec(ctx, spec)
	}
	bounded, ok := r.inner.(runner.BoundedExecRunner)
	if !ok {
		return runner.RunResult{}, errors.New("bootstrap: inner runner cannot bound command output")
	}
	prepared, proxyRoute, err := r.conf.confine(ctx, spec, current, tmpDir, r.storesWritable)
	if err != nil {
		return runner.RunResult{}, err
	}
	if prepared.Helper != nil {
		defer prepared.Helper.Close()
	}
	res, err := bounded.ExecBounded(ctx, prepared, r.cap)
	if err != nil {
		return res, err
	}
	return noteConfinedFailure(res, r.cap, confinedFailureOf(res, proxyRoute, prepared.Helper)), nil
}

const confinedFailureNote = "codemeld: this command ran inside the confinement boundary; a failure may be a boundary denial and may have left partial changes; codemeld did not re-run it outside the boundary."

func confinedRunFailed(res runner.RunResult) bool {
	return res.ExitCode != 0 && res.LaunchErrCategory == ""
}

const proxyRouteNote = "codemeld: this command ran on the proxy route; tools that do not use HTTPS_PROXY/HTTP_PROXY, including ssh, scp and SSH URLs, get no network; use Build mode for those."

type confinedFailure struct {
	proxyRoute bool
	lines      []string
}

type refusal struct {
	Host, Port, Path, Reason string
}

var invocationRefusals = func(helper runner.HelperLaunch) []refusal {
	h, ok := helper.(interface{ refusals() []refusal })
	if !ok {
		return nil
	}
	helper.Close()
	return h.refusals()
}

func confinedFailureOf(res runner.RunResult, proxyRoute bool, helper runner.HelperLaunch) *confinedFailure {
	if !confinedRunFailed(res) {
		return nil
	}
	f := &confinedFailure{proxyRoute: proxyRoute}
	if !proxyRoute {
		return f
	}
	for _, r := range invocationRefusals(helper) {
		dest := r.Path
		if r.Host != "" && r.Port != "" {
			dest = net.JoinHostPort(r.Host, r.Port)
		}
		if dest != "" {
			f.addLine(strings.ToValidUTF8(fmt.Sprintf("codemeld: network refused: %s (%s)", dest, r.Reason), "\uFFFD"))
		}
	}
	return f
}

func (f *confinedFailure) addLine(line string) {
	if !slices.Contains(f.lines, line) {
		f.lines = append(f.lines, line)
	}
}

func (f *confinedFailure) merge(g *confinedFailure) {
	f.proxyRoute = f.proxyRoute || g.proxyRoute
	for _, line := range g.lines {
		f.addLine(line)
	}
}

func (f *confinedFailure) additions(room int) string {
	if len(f.lines) == 0 {
		if f.proxyRoute && len(proxyRouteNote)+1 <= room {
			return proxyRouteNote + "\n"
		}
		return ""
	}
	var b strings.Builder
	shown := 0
	for _, line := range f.lines {
		if b.Len()+len(line)+1 > room {
			break
		}
		b.WriteString(line + "\n")
		shown++
	}
	if omitted := len(f.lines) - shown; omitted > 0 {
		if marker := fmt.Sprintf("codemeld: %d more network refusals omitted.\n", omitted); b.Len()+len(marker) <= room {
			b.WriteString(marker)
		}
	}
	return b.String()
}

func noteConfinedFailure(res runner.RunResult, cap int, f *confinedFailure) runner.RunResult {
	if f == nil {
		return res
	}
	total := max(res.StderrTotal, int64(len(res.Stderr)))
	var kept int
	res.Stderr, kept = withConfinedFailure(res.Stderr, cap, f)
	res.StderrTotal = total + int64(len(res.Stderr)-kept)
	return res
}

func withConfinedFailure(stderr []byte, cap int, f *confinedFailure) ([]byte, int) {
	avail := cap - len("\n"+confinedFailureNote)
	minKeep := 0
	if len(rawPrefixWithin(stderr, avail)) > 0 {
		for len(rawPrefixWithin(stderr, minKeep)) == 0 {
			minKeep++
		}
	}
	add := f.additions(avail - minKeep)
	kept := rawPrefixWithin(stderr, avail-len(add))
	out := slices.Clip(kept)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(append(out, add...), confinedFailureNote...), len(kept)
}

// rawPrefixWithin keeps raw bytes rather than their model-input form so that a dropped tail still
// shows as a total larger than the kept length when invalid UTF-8 expands under normalization.
func rawPrefixWithin(b []byte, budget int) []byte {
	n := sort.Search(len(b)+1, func(n int) bool {
		_, normalized := events.BuildModelInputBytes(nil, b[:n], 3*n)
		return len(normalized) > budget
	}) - 1
	for n > 0 && n < len(b) && !utf8.RuneStart(b[n]) {
		n--
	}
	return b[:max(n, 0)]
}

func (r *confinedRunner) PreflightPipeline(ctx context.Context, specs []runner.RunSpec) error {
	if _, _, confined, _ := r.conf.resolve(ctx); confined {
		return runner.ErrPipelineUnsupported
	}
	inner, ok := r.inner.(runner.PipelineRunner)
	if !ok {
		return runner.ErrPipelineUnsupported
	}
	if len(specs) == 0 {
		return inner.PreflightPipeline(ctx, specs)
	}
	prepared := cloneSpecs(specs)
	if err := inner.PreflightPipeline(ctx, prepared); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		r.pending = map[string][]runner.RunSpec{}
	}
	r.pending[specs[0].InvocationID] = prepared
	return nil
}

func (r *confinedRunner) Pipeline(ctx context.Context, specs []runner.RunSpec, maxCapture int) ([]runner.PipelineResult, error) {
	inner, ok := r.inner.(runner.PipelineRunner)
	if !ok || len(specs) == 0 {
		return nil, errors.New("bootstrap: pipeline run without a successful preflight")
	}
	r.mu.Lock()
	prepared, found := r.pending[specs[0].InvocationID]
	delete(r.pending, specs[0].InvocationID)
	r.mu.Unlock()
	if !found {
		return nil, errors.New("bootstrap: pipeline run without a successful preflight")
	}
	return inner.Pipeline(ctx, prepared, maxCapture)
}

type confinedShellRunner struct {
	events  *shellEventRunner
	conf    *confinement
	pending *confinedPipeline
	failure *confinedFailure
}

type confinedPipeline struct {
	subjects []runner.RunSpec
	specs    []runner.RunSpec
}

func (r *confinedShellRunner) NewInvocationID() string { return r.events.NewInvocationID() }

func (r *confinedShellRunner) Confined(ctx context.Context) (bool, error) {
	_, _, confined, err := r.conf.resolve(ctx)
	return confined, err
}

func (r *confinedShellRunner) Exec(ctx context.Context, spec runner.RunSpec) (runner.RunResult, error) {
	current, tmpDir, confined, err := r.conf.resolve(ctx)
	if err != nil {
		return runner.RunResult{}, err
	}
	if !confined {
		return r.events.Exec(ctx, spec)
	}
	prepared, proxyRoute, err := r.conf.confine(ctx, spec, current, tmpDir, false)
	if err != nil {
		return runner.RunResult{}, err
	}
	if prepared.Helper != nil {
		defer prepared.Helper.Close()
	}
	res, failure, err := r.events.execBoundedPrepared(ctx, spec, prepared, r.events.cap, func(res runner.RunResult) *confinedFailure {
		return confinedFailureOf(res, proxyRoute, prepared.Helper)
	})
	if err == nil && failure != nil {
		if r.failure == nil {
			r.failure = &confinedFailure{}
		}
		r.failure.merge(failure)
	}
	if recErr := r.recordConnectDecisions(prepared.Helper); recErr != nil {
		err = errors.Join(err, recErr)
	}
	return res, err
}

func (r *confinedShellRunner) recordConnectDecisions(helper runner.HelperLaunch) error {
	h, ok := helper.(interface {
		connectDecisions() []events.ConnectDecision
	})
	if !ok || r.events.active == nil {
		return nil
	}
	store := r.events.active()
	if store == nil {
		return nil
	}
	helper.Close()
	var errs []error
	for _, d := range h.connectDecisions() {
		if _, err := events.Append(store, d); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (r *confinedShellRunner) PreflightPipeline(ctx context.Context, specs []runner.RunSpec) error {
	r.pending = nil
	if _, _, confined, _ := r.conf.resolve(ctx); confined {
		return runner.ErrPipelineUnsupported
	}
	prepared := cloneSpecs(specs)
	subjects := cloneSpecs(specs)
	if err := r.events.preflightPrepared(ctx, subjects, prepared); err != nil {
		return err
	}
	r.pending = &confinedPipeline{subjects: subjects, specs: prepared}
	return nil
}

func (r *confinedShellRunner) Pipeline(ctx context.Context, _ []runner.RunSpec) ([]runner.PipelineResult, error) {
	pending := r.pending
	r.pending = nil
	if pending == nil {
		return nil, errors.New("bootstrap: pipeline run without a successful preflight")
	}
	return r.events.pipelinePrepared(ctx, pending.subjects, pending.specs)
}
