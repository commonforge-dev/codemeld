package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/vcs"
)

type confinement struct {
	constrained bool
	mode        func() string
	home        string
	projectRoot string
	blocked     *permissions.BlockedPaths
	lookupPath  string
	lookupSet   bool
	tmpDir      string
	retryPaths  []string
	warning     string
}

func (c *confinement) prepareReplacement() (folder string, rollback func() error, err error) {
	if c == nil || c.tmpDir == "" {
		return "", func() error { return nil }, nil
	}
	folder, err = newSessionTempDir()
	if err != nil {
		return "", func() error { return nil }, err
	}
	return folder, sync.OnceValue(func() error { return removeSessionTempDir(folder) }), nil
}

func (c *confinement) commitReplacement(folder string) {
	if c == nil || folder == "" {
		return
	}
	old := c.tmpDir
	c.tmpDir = folder
	if err := removeSessionTempDir(old); err != nil {
		c.retryPaths = append(c.retryPaths, old)
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
	var errs []error
	for _, path := range append([]string{c.tmpDir}, c.retryPaths...) {
		if path != "" {
			errs = append(errs, removeSessionTempDir(path))
		}
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
	case mode.Plan:
		return current, "", true, nil
	case mode.AutoEdits:
		if c.tmpDir == "" {
			return current, "", true, errors.New("bootstrap: confined auto_edits run has no private temporary folder")
		}
		return current, c.tmpDir, true, nil
	}
	return current, "", true, fmt.Errorf("bootstrap: confined run refused for unrecognized mode %q", current)
}

func (c *confinement) prepare(spec runner.RunSpec, tmpDir string) (runner.RunSpec, error) {
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
	env, err := runner.FixedEnvironment(c.home, spec.Cwd, tmpDir, lookup, assignments)
	if err != nil {
		return runner.RunSpec{}, err
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

func (c *confinement) confine(spec runner.RunSpec, current, tmpDir string) (runner.RunSpec, error) {
	prepared, err := c.prepare(spec, tmpDir)
	if err != nil {
		return runner.RunSpec{}, err
	}
	policy, err := c.policy(current, tmpDir, spec.ExceptionalAuthority)
	if err != nil {
		return runner.RunSpec{}, err
	}
	var frame bytes.Buffer
	if err := enforce.WritePolicyFrame(&frame, policy); err != nil {
		return runner.RunSpec{}, fmt.Errorf("codemeld confinement: policy frame: %w", err)
	}
	prepared.Argv = append([]string{"/proc/self/exe", enforce.HelperCommand}, prepared.Argv...)
	prepared.Stdin = append(frame.Bytes(), prepared.Stdin...)
	return prepared, nil
}

func (c *confinement) policy(current, tmpDir, authority string) (enforce.Policy, error) {
	p := enforce.Policy{Mode: current, BlockedPaths: c.blocked.Current().Forms()}
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
	p.TmpDir = tmpDir
	if authority == enforce.NetworkAccessAuthority {
		p.ExceptionalAuthority = authority
	}
	return p, nil
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
	inner   runner.Runner
	conf    *confinement
	cap     int
	mu      sync.Mutex
	pending map[string][]runner.RunSpec
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
	prepared, err := r.conf.confine(spec, current, tmpDir)
	if err != nil {
		return runner.RunResult{}, err
	}
	res, err := bounded.ExecBounded(ctx, prepared, r.cap)
	if err != nil {
		return res, err
	}
	return noteConfinedFailure(res, r.cap), nil
}

const confinedFailureNote = "codemeld: this command ran inside the confinement boundary; a failure may be a boundary denial and may have left partial changes; codemeld did not re-run it outside the boundary."

func confinedRunFailed(res runner.RunResult) bool {
	return res.ExitCode != 0 && res.LaunchErrCategory == ""
}

func noteConfinedFailure(res runner.RunResult, cap int) runner.RunResult {
	if !confinedRunFailed(res) {
		return res
	}
	total := max(res.StderrTotal, int64(len(res.Stderr)))
	kept := rawPrefixWithin(res.Stderr, cap-len("\n"+confinedFailureNote))
	res.Stderr = withConfinedFailureNote(kept)
	res.StderrTotal = total + int64(len(res.Stderr)-len(kept))
	return res
}

func keepConfinedFailureNote(stderr []byte, cap int) []byte {
	if len(rawPrefixWithin(stderr, cap)) == len(stderr) {
		return stderr
	}
	return withConfinedFailureNote(rawPrefixWithin(stderr, cap-len("\n"+confinedFailureNote)))
}

func withConfinedFailureNote(kept []byte) []byte {
	if len(kept) > 0 && kept[len(kept)-1] != '\n' {
		kept = append(slices.Clip(kept), '\n')
	}
	return append(slices.Clip(kept), confinedFailureNote...)
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
	events       *shellEventRunner
	conf         *confinement
	pending      *confinedPipeline
	failureNoted bool
}

type confinedPipeline struct {
	subjects []runner.RunSpec
	specs    []runner.RunSpec
}

func (r *confinedShellRunner) NewInvocationID() string { return r.events.NewInvocationID() }

func (r *confinedShellRunner) Exec(ctx context.Context, spec runner.RunSpec) (runner.RunResult, error) {
	current, tmpDir, confined, err := r.conf.resolve(ctx)
	if err != nil {
		return runner.RunResult{}, err
	}
	if !confined {
		return r.events.Exec(ctx, spec)
	}
	prepared, err := r.conf.confine(spec, current, tmpDir)
	if err != nil {
		return runner.RunResult{}, err
	}
	res, err := r.events.execBoundedPrepared(ctx, spec, prepared, r.events.cap, true)
	if err == nil && confinedRunFailed(res) {
		r.failureNoted = true
	}
	return res, err
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
