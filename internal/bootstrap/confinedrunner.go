package bootstrap

import (
	"bytes"
	"cmp"
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

	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/netproxy"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/sessions"
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
	outside       *outsideSubjects
	writes        *writeRefusalReports
	pipeBytes     int
}

type writeRefusalReports struct {
	mu     sync.Mutex
	seen   map[string]bool
	notice func(string)
}

func (w *writeRefusalReports) fresh(refused []refusal) []refusal {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.seen == nil {
		w.seen = map[string]bool{}
	}
	var out []refusal
	for _, r := range refused {
		key := cmp.Or(r.Candidate, filepath.Dir(r.Path)+"\x00"+r.Reason)
		if w.seen[key] {
			continue
		}
		w.seen[key] = true
		out = append(out, r)
		if w.notice != nil {
			w.notice(writeRefusalNotice(r))
		}
	}
	return out
}

func (w *writeRefusalReports) setNotice(notice func(string)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.notice = notice
}

func (w *writeRefusalReports) reset() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seen = nil
}

func writeRefusalNotice(r refusal) string {
	if r.Candidate == "" {
		return permissions.SingleLineControlEscape(fmt.Sprintf("sandbox likely blocked writes to %s: %s", r.Path, cmp.Or(r.Reason, "not grantable")))
	}
	return permissions.SingleLineControlEscape(fmt.Sprintf("sandbox likely blocked writes to %s; commands that write there fail. To allow it: /settings, folders tab, press a", suggestedFolder(r)))
}

func suggestedFolder(r refusal) string {
	if r.Var == "" {
		return r.Candidate
	}
	return r.Candidate + " (" + r.Var + ")"
}

func (c *confinement) widen(env []string, cwd string) func(refusal) refusal {
	return func(r refusal) refusal {
		if r.Candidate != "" {
			blocked := c.blocked.Current()
			home := cmp.Or(c.home, blocked.Home())
			var reason string
			if r.Candidate, r.Var, reason = widenedFolder(r.Candidate, env, home, []string{c.projectRoot, cwd}, blocked); reason != "" {
				r.Reason = reason
			}
		}
		return r
	}
}

func widenedFolder(candidate string, env []string, home string, projects []string, blocked *permissions.BlockedPaths) (folder, variable, reason string) {
	home = resolvedOrClean(home)
	projects = slices.Clone(projects)
	for i, p := range projects {
		projects[i] = resolvedOrClean(p)
	}
	if reason := unsuitableFolder(candidate, home, projects, blocked); reason != "" {
		return "", "", reason
	}
	for _, e := range env {
		name, value, _ := strings.Cut(e, "=")
		if !filepath.IsAbs(value) || slices.Contains(strings.Split(value, string(filepath.Separator)), "..") {
			continue
		}
		value, err := filepath.EvalSymlinks(value)
		if err != nil {
			continue
		}
		if len(value) <= len(folder) || !pathWithin(candidate, value) || unsuitableFolder(value, home, projects, blocked) != "" {
			continue
		}
		folder, variable = value, name
	}
	if folder == "" {
		return candidate, "", ""
	}
	return folder, variable, ""
}

func resolvedOrClean(path string) string {
	if path == "" {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return filepath.Clean(path)
}

func unsuitableFolder(folder, home string, projects []string, blocked *permissions.BlockedPaths) string {
	switch {
	case filepath.Dir(folder) == folder:
		return "the filesystem root cannot be a writable folder"
	case home != "" && pathWithin(filepath.Clean(home), folder):
		return folder + " holds the home folder"
	}
	for _, p := range projects {
		if p != "" && pathWithin(filepath.Clean(p), folder) {
			return folder + " holds the project folder"
		}
	}
	if _, holds := blocked.BlockedWithin(folder); holds {
		return folder + " holds a blocked path"
	}
	return ""
}

func pathWithin(path, base string) bool {
	return path == base || strings.HasPrefix(path, base+string(filepath.Separator))
}

type outsideSubjects struct {
	mu       sync.Mutex
	subjects map[string][]string
}

func (o *outsideSubjects) add(subject string, reasons []string) bool {
	if o == nil || subject == "" {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.subjects == nil {
		o.subjects = map[string][]string{}
	}
	o.subjects[subject] = slices.Clone(reasons)
	return true
}

func (o *outsideSubjects) has(subject string) bool {
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	_, ok := o.subjects[subject]
	return ok
}

func (o *outsideSubjects) reasons(subject string) []string {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.subjects[subject])
}

func (o *outsideSubjects) remove(subject string) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.subjects, subject)
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
	if c == nil {
		return
	}
	c.writes.reset()
	if folder == "" {
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
	current, tmpDir, confined, _, err = c.resolveOutside(ctx, runner.RunSpec{})
	return current, tmpDir, confined, err
}

func (c *confinement) resolveOutside(ctx context.Context, spec runner.RunSpec) (current, tmpDir string, confined bool, matched map[string]string, err error) {
	if c == nil || !c.constrained {
		return "", "", false, nil, nil
	}
	current = c.currentMode(ctx)
	switch mode.Mode(current) {
	case mode.Plan, mode.AutoEdits, mode.Build:
		if mode.Mode(current) == mode.Build {
			if matched := c.savedOutside(ctx); matched != nil {
				return current, "", false, matched, nil
			}
			entry, sameProgram := c.savedHead(ctx, spec)
			once := dispatch.TakeRunOutside(ctx)
			if sameProgram || (once && entry == "") {
				subject := dispatch.ShellSubject(ctx)
				if once {
					c.outside.remove(subject)
				}
				if sameProgram {
					dispatch.MarkPipeHeadOutside(ctx)
					matched = map[string]string{subject: entry}
				}
				return current, "", false, matched, nil
			}
		}
		if c.tmpDir == "" {
			return current, "", true, nil, fmt.Errorf("bootstrap: confined %s run has no private temporary folder", current)
		}
		return current, c.tmpDir, true, nil, nil
	}
	return current, "", true, nil, fmt.Errorf("bootstrap: confined run refused for unrecognized mode %q", current)
}

func (c *confinement) currentMode(ctx context.Context) string {
	current, ok := vcs.ConfinementMode(ctx)
	if !ok && c.mode != nil {
		current = c.mode()
	}
	return current
}

func (c *confinement) savedOutside(ctx context.Context) map[string]string {
	reqs := dispatch.ShellRequests(ctx)
	if len(reqs) == 0 {
		return nil
	}
	entries := c.writable.outsideSandboxEntries()
	if len(entries) == 0 {
		return nil
	}
	matched := make(map[string]string, len(reqs))
	for _, req := range reqs {
		result := permissions.Match(req, entries)
		if !result.Matched {
			return nil
		}
		matched[req.Subject] = result.Grant.Subject
	}
	return matched
}

func (c *confinement) savedHead(ctx context.Context, spec runner.RunSpec) (entry string, sameProgram bool) {
	if !dispatch.IsPipeHead(ctx) || len(spec.Argv) == 0 {
		return "", false
	}
	subject := dispatch.ShellSubject(ctx)
	entries := c.writable.outsideSandboxEntries()
	var req permissions.MatchRequest
	for _, r := range dispatch.ShellRequests(ctx) {
		if r.Subject != subject {
			continue
		}
		// ShellQuote replaces invalid bytes, so different argvs can share one subject.
		result := permissions.Match(r, entries)
		if r.Kind != matchKindDirect || !result.Matched {
			return "", false
		}
		req, entry = r, result.Grant.Subject
	}
	if entry == "" {
		return "", false
	}
	program := spec.Argv[0]
	if filepath.IsAbs(program) || !strings.Contains(program, "/") {
		return entry, true
	}
	// An earlier sandboxed stage can repoint a folder in a relative program's path.
	keepAbsolute := req.ClearEnvironment || slices.ContainsFunc(req.Assignments, func(a string) bool { return strings.HasPrefix(a, "PATH=") })
	return entry, permissions.ResolveRelativeProgram(program, spec.Cwd, keepAbsolute) == req.SubjectTokens[0]
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

func (c *confinement) prepareBuild(spec runner.RunSpec, tmpDir string, blocked *permissions.BlockedPaths, proxyURL string) (runner.RunSpec, error) {
	base := spec.Env
	if base == nil {
		base = os.Environ()
	}
	home := c.home
	if home == "" {
		home = blocked.Home()
	}
	overrides := []string{"TERM=dumb"}
	if proxyURL != "" {
		overrides = append(overrides, "HTTPS_PROXY="+proxyURL, "HTTP_PROXY="+proxyURL, "https_proxy="+proxyURL, "http_proxy="+proxyURL,
			"NO_PROXY=localhost,127.0.0.1,::1", "no_proxy=localhost,127.0.0.1,::1")
	}
	if gitGlobalConfigBlocked(home, blocked) {
		overrides = append(overrides, "GIT_CONFIG_GLOBAL=/dev/null")
	}
	drop := make(map[string]bool, len(overrides)+2)
	for _, e := range overrides {
		name, _, _ := strings.Cut(e, "=")
		drop[name] = true
	}
	if proxyURL != "" {
		drop["ALL_PROXY"], drop["all_proxy"] = true, true
	}
	var launchTemp string
	if abs, err := unresolvedAbs(os.TempDir()); err == nil {
		launchTemp, _ = reachableDir(abs)
	}
	env := make([]string, 0, len(base)+len(overrides)+1)
	var tmpVar, path string
	for _, e := range base {
		name, value, _ := strings.Cut(e, "=")
		if drop[name] {
			continue
		}
		if launchTemp != "" && namesFolder(value, spec.Cwd, launchTemp) {
			value = tmpDir
			e = name + "=" + value
		}
		switch name {
		case "TMPDIR":
			tmpVar = value
		case "PATH":
			path = value
		}
		env = append(env, e)
	}
	if tmpVar == "" {
		env = append(env, "TMPDIR="+tmpDir)
	}
	prepared := cloneSpec(spec)
	prepared.Env = append(env, overrides...)
	if len(prepared.Argv) > 0 {
		var err error
		if prepared.Argv[0], err = runner.ResolveOnPath(prepared.Argv[0], path); err != nil {
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
	prepare := c.prepare
	if mode.Mode(current) == mode.Build {
		prepare = c.prepareBuild
	}
	prepared, err := prepare(spec, tmpDir, blocked, proxyURL)
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
	if mode.Mode(current) == mode.Build {
		current = enforce.ModeAutoEdits
	}
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
	active         func() *sessions.Store
	mu             sync.Mutex
	pending        map[string][]runner.RunSpec
}

var (
	_ runner.Runner         = (*confinedRunner)(nil)
	_ runner.PipelineRunner = (*confinedRunner)(nil)

	_ dispatch.OutsideEntryMatcher = (*confinedShellRunner)(nil)
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
	if err == nil {
		failure := confinedFailureOf(res, proxyRoute, prepared.Helper, r.conf.widen(prepared.Env, spec.Cwd))
		if failure != nil && !failure.plan {
			err = recordWriteRefusals(r.active, r.conf.writes.fresh(failure.refused))
		}
		res = noteConfinedFailure(res, r.cap, failure)
	}
	if recErr := recordConnectDecisions(r.active, prepared.Helper); recErr != nil {
		err = errors.Join(err, recErr)
	}
	return res, err
}

const confinedFailureNote = "codemeld: this command ran inside the confinement boundary; a failure may be a boundary denial and may have left partial changes; codemeld did not re-run it outside the boundary."

func confinedRunFailed(res runner.RunResult) bool {
	return res.ExitCode != 0 && res.LaunchErrCategory == ""
}

const proxyRouteNote = "codemeld: this command ran on the proxy route; tools that do not use HTTPS_PROXY/HTTP_PROXY, including ssh, scp and SSH URLs, get no network; ask the user to run those."

const (
	fileRefusalsClosing = "codemeld: these are predictions and may be wrong; a listed refusal may not be what made the command fail, " +
		"and more may appear after a folder is allowed. To allow a folder for later runs, add it to writable_folders."
	planFileRefusalsClosing = "codemeld: these are predictions and may be wrong; a listed refusal may not be what made the command fail. " +
		"Plan allows writes only in its temporary folder, and writable_folders does not change Plan."
)

type confinedFailure struct {
	proxyRoute bool
	lines      []string
	files      []string
	refused    []refusal
	unjudged   int
	plan       bool
	outside    bool
	remembered *outsideSubjects
	subjects   []string
}

type refusal struct {
	Host, Port, Path, Reason string
	File                     bool
	Process, Candidate, Var  string
}

var invocationRefusals = func(helper runner.HelperLaunch) []refusal {
	h, ok := helper.(interface{ refusals() []refusal })
	if !ok {
		return nil
	}
	helper.Close()
	return h.refusals()
}

func confinedFailureOf(res runner.RunResult, proxyRoute bool, helper runner.HelperLaunch, widen func(refusal) refusal) *confinedFailure {
	if !confinedRunFailed(res) {
		return nil
	}
	f := &confinedFailure{proxyRoute: proxyRoute}
	if !proxyRoute {
		return f
	}
	for _, r := range invocationRefusals(helper) {
		if r.File {
			if widen != nil {
				r = widen(r)
			}
			f.files = appendNew(f.files, fileRefusalLine(r))
			f.refused = append(f.refused, r)
			continue
		}
		dest := r.Path
		if r.Host != "" && r.Port != "" {
			dest = net.JoinHostPort(r.Host, r.Port)
		}
		if dest != "" {
			f.lines = appendNew(f.lines, strings.ToValidUTF8(fmt.Sprintf("codemeld: network refused: %s (%s)", dest, r.Reason), "\uFFFD"))
		}
	}
	if h, ok := helper.(interface{ fileReport() (int, bool) }); ok {
		f.unjudged, f.plan = h.fileReport()
	}
	return f
}

func fileRefusalLine(r refusal) string {
	detail := cmp.Or(r.Process, "unknown process")
	if r.Candidate != "" {
		return permissions.SingleLineControlEscape(fmt.Sprintf("codemeld: sandbox likely refused write: %s (%s; to allow, add the writable folder %s in /settings, folders tab, key a)",
			r.Path, detail, suggestedFolder(r)))
	}
	if r.Reason != "" {
		detail += "; not grantable: " + r.Reason
	}
	return permissions.SingleLineControlEscape(fmt.Sprintf("codemeld: sandbox probably refused write: %s (%s)", r.Path, detail))
}

func appendNew(lines []string, line string) []string {
	if slices.Contains(lines, line) {
		return lines
	}
	return append(lines, line)
}

func (f *confinedFailure) merge(g *confinedFailure) {
	f.proxyRoute = f.proxyRoute || g.proxyRoute
	f.plan = f.plan || g.plan
	f.outside = f.outside || g.outside
	f.remembered = cmp.Or(f.remembered, g.remembered)
	for _, s := range g.subjects {
		f.subjects = appendNew(f.subjects, s)
	}
	f.unjudged += g.unjudged
	for _, line := range g.lines {
		f.lines = appendNew(f.lines, line)
	}
	for _, line := range g.files {
		f.files = appendNew(f.files, line)
	}
}

func (f *confinedFailure) additions(room int) string {
	var out string
	if len(f.lines) == 0 {
		if f.proxyRoute && len(proxyRouteNote)+1 <= room {
			out = proxyRouteNote + "\n"
		}
	} else {
		out = linesWithin(f.lines, room, "network refusals")
	}
	if len(f.files) == 0 && f.unjudged == 0 {
		return out
	}
	tail := fileRefusalsClosing + "\n"
	if f.plan {
		tail = planFileRefusalsClosing + "\n"
	}
	if f.unjudged > 0 {
		tail = fmt.Sprintf("codemeld: %d file calls could not be judged\n", f.unjudged) + tail
	}
	if rest := room - len(out) - len(tail); rest >= 0 {
		out += linesWithin(f.files, rest, "file refusals") + tail
	}
	return out
}

func linesWithin(lines []string, room int, what string) string {
	var b strings.Builder
	shown := 0
	for _, line := range lines {
		if b.Len()+len(line)+1 > room {
			break
		}
		b.WriteString(line + "\n")
		shown++
	}
	if omitted := len(lines) - shown; omitted > 0 {
		if marker := fmt.Sprintf("codemeld: %d more %s omitted.\n", omitted, what); b.Len()+len(marker) <= room {
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
	out, kept, add := renderConfinedFailure(stderr, cap, f)
	if f.outside && !f.listsRefusal(add) {
		f.forget()
		f.outside = false
		out, kept, _ = renderConfinedFailure(stderr, cap, f)
	}
	return out, kept
}

func (f *confinedFailure) forget() {
	if f == nil {
		return
	}
	for _, s := range f.subjects {
		f.remembered.remove(s)
	}
	f.subjects = nil
}

func (f *confinedFailure) listsRefusal(add string) bool {
	return slices.ContainsFunc(strings.Split(add, "\n"), func(line string) bool {
		return slices.Contains(f.lines, line) || slices.Contains(f.files, line)
	})
}

func renderConfinedFailure(stderr []byte, cap int, f *confinedFailure) ([]byte, int, string) {
	note := confinedFailureNote
	if f.outside && len(f.additions(cap-len("\n"+note))) < len(f.additions(cap-1)) {
		note = ""
	}
	avail := cap - len("\n"+note)
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
	return append(append(out, add...), note...), len(kept), add
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
	entries  []string
}

func (r *confinedShellRunner) NewInvocationID() string { return r.events.NewInvocationID() }

func (r *confinedShellRunner) Confined(ctx context.Context) (bool, error) {
	current, _, confined, err := r.conf.resolve(ctx)
	if mode.Mode(current) == mode.Build {
		return false, nil
	}
	return confined, err
}

func (r *confinedShellRunner) MatchOutsideEntry(ctx context.Context, req permissions.MatchRequest) (entry string, ok bool) {
	c := r.conf
	if c == nil || !c.constrained || mode.Mode(c.currentMode(ctx)) != mode.Build {
		return "", false
	}
	result := permissions.Match(req, c.writable.outsideSandboxEntries())
	if !result.Matched {
		return "", false
	}
	return result.Grant.Subject, true
}

func (r *confinedShellRunner) Exec(ctx context.Context, spec runner.RunSpec) (runner.RunResult, error) {
	current, tmpDir, confined, matched, err := r.conf.resolveOutside(ctx, spec)
	if err != nil {
		return runner.RunResult{}, err
	}
	if !confined {
		return r.events.Exec(withOutsideEntries(ctx, matched[dispatch.ShellSubject(ctx)]), spec)
	}
	prepared, proxyRoute, err := r.conf.confine(ctx, spec, current, tmpDir, false)
	if err != nil {
		return runner.RunResult{}, err
	}
	if prepared.Helper != nil {
		defer prepared.Helper.Close()
	}
	if dispatch.FeedsPipe(ctx) {
		prepared.StdoutCapture = r.conf.pipeBytes
	}
	res, failure, err := r.events.execBoundedPrepared(ctx, spec, prepared, r.events.cap, func(res runner.RunResult) *confinedFailure {
		f := confinedFailureOf(res, proxyRoute, prepared.Helper, r.conf.widen(prepared.Env, spec.Cwd))
		if f != nil && mode.Mode(current) == mode.Build && len(f.lines)+len(f.files) > 0 {
			subject := dispatch.ShellSubject(ctx)
			var reasons []string
			for _, line := range slices.Concat(f.files, f.lines) {
				reasons = append(reasons, strings.TrimPrefix(line, "codemeld: "))
			}
			if f.outside = r.conf.outside.add(subject, reasons); f.outside {
				f.remembered, f.subjects = r.conf.outside, []string{subject}
			}
		}
		return f
	})
	if err == nil && failure != nil {
		if r.failure == nil {
			r.failure = &confinedFailure{}
		}
		r.failure.merge(failure)
		if !failure.plan {
			err = recordWriteRefusals(r.events.active, r.conf.writes.fresh(failure.refused))
		}
	}
	if recErr := recordConnectDecisions(r.events.active, prepared.Helper); recErr != nil {
		err = errors.Join(err, recErr)
	}
	return res, err
}

func recordWriteRefusals(active func() *sessions.Store, refused []refusal) error {
	if len(refused) == 0 || active == nil {
		return nil
	}
	store := active()
	if store == nil {
		return nil
	}
	var errs []error
	for _, w := range refused {
		if _, err := events.Append(store, events.SandboxWriteRefused{Path: w.Path, Process: w.Process, Folder: w.Candidate, Variable: w.Var, Reason: w.Reason}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func recordConnectDecisions(active func() *sessions.Store, helper runner.HelperLaunch) error {
	h, ok := helper.(interface {
		connectDecisions() []events.ConnectDecision
	})
	if !ok || active == nil {
		return nil
	}
	store := active()
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
	_, _, confined, matched, _ := r.conf.resolveOutside(ctx, runner.RunSpec{})
	if confined {
		return runner.ErrPipelineUnsupported
	}
	prepared := cloneSpecs(specs)
	subjects := cloneSpecs(specs)
	if err := r.events.preflightPrepared(ctx, subjects, prepared); err != nil {
		return err
	}
	var entries []string
	if matched != nil {
		for _, subject := range dispatch.ShellStageSubjects(ctx) {
			entries = append(entries, matched[subject])
		}
	}
	r.pending = &confinedPipeline{subjects: subjects, specs: prepared, entries: entries}
	return nil
}

func (r *confinedShellRunner) Pipeline(ctx context.Context, _ []runner.RunSpec) ([]runner.PipelineResult, error) {
	pending := r.pending
	r.pending = nil
	if pending == nil {
		return nil, errors.New("bootstrap: pipeline run without a successful preflight")
	}
	return r.events.pipelinePrepared(withOutsideEntries(ctx, pending.entries...), pending.subjects, pending.specs)
}
