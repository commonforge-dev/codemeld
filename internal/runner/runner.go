// Package runner is the single internal command runner every tool invocation routes through.
// Phase 1 executes commands directly via os/exec with no sandboxing, so a later
// sandbox can be added behind this seam without changing callers.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
)

// RunSpec is the caller-supplied input for one command invocation.
type RunSpec struct {
	// InvocationID is the UUIDv7 the caller minted via Runner.NewInvocationID at invocation
	// start — the single source of the paired tool_exec_start/tool_exec_end id.
	// Exec validates it and echoes it verbatim into RunResult.InvocationID.
	InvocationID string
	// Argv is the command and its arguments; Argv[0] is the binary, run directly with no shell
	// interpretation. It must be non-empty.
	Argv []string
	// Cwd, when non-empty, sets the process working directory (exec.Cmd.Dir). Callers own path
	// validation and resolution; the runner passes it through unchanged.
	Cwd string
	// Env is an optional complete environment block: nil inherits the parent process environment,
	// non-nil is passed to exec.Cmd.Env as-is.
	Env         []string
	Assignments []string
	// Stdin is fed to the process standard input; nil or empty means the process gets no input.
	Stdin                []byte
	ExceptionalAuthority string
}

// RunResult is the outcome of a completed invocation, including launch failures. A non-nil Exec
// error is reserved for invalid input or internal failures where no reliable result exists; a
// non-zero process exit or a launch failure is reported here, not as an error.
type RunResult struct {
	// InvocationID echoes RunSpec.InvocationID verbatim for every produced result, so the paired
	// tool_exec_start/tool_exec_end events share one id.
	InvocationID string
	// Stdout and Stderr are empty on a launch failure because the process never ran.
	Stdout []byte
	Stderr []byte
	// ExitCode is the process exit status, or -1 when the process failed to launch.
	ExitCode int
	// Duration is the wall-clock time spent in cmd.Run.
	Duration time.Duration
	// LaunchErrCategory is set only when the process failed to launch before starting; it is empty
	// on normal completion, including a non-zero exit.
	LaunchErrCategory fserrors.Category
	StdoutTotal       int64
	StderrTotal       int64
}

// Runner is the shared command-runner seam every tool invocation path depends on.
type Runner interface {
	// NewInvocationID mints a fresh UUIDv7 invocation id. The caller calls this at invocation
	// start, emits tool_exec_start with it, then passes it back in RunSpec.InvocationID.
	NewInvocationID() string
	// Exec runs spec directly with no shell interpretation and returns a RunResult. It returns a
	// non-nil error only for invalid input (empty or malformed InvocationID, empty Argv) or
	// internal failures; non-zero exits and launch failures are carried on RunResult.
	Exec(ctx context.Context, spec RunSpec) (RunResult, error)
}

// ErrPipelineUnsupported reports that a runner cannot execute a set of specs as one pipeline. Only
// PreflightPipeline may return it; a caller that sees it runs the stages sequentially through Exec.
var ErrPipelineUnsupported = errors.New("runner: pipeline execution unsupported")

// PipelineStageFailure classifies a pipeline failure that happened after the stages were launched.
type PipelineStageFailure string

const (
	PipelineFailureCopy     PipelineStageFailure = "copy_failed"
	PipelineFailureCanceled PipelineStageFailure = "canceled"
	PipelineFailureInternal PipelineStageFailure = "internal"
)

// PipelineResult is the outcome of one stage of a pipeline.
type PipelineResult struct {
	// InvocationID echoes the stage's RunSpec.InvocationID verbatim for every produced result.
	InvocationID string
	// Stdout and Stderr are the first maxCapture bytes the parent read from that stream.
	Stdout []byte
	Stderr []byte
	// ExitCode is the process exit status, or -1 when the stage failed to launch or never ran.
	ExitCode int
	// Duration is that stage's own wall-clock time from launch to exit; stages overlap, so summing
	// these across a pipeline overstates the elapsed time.
	Duration time.Duration
	// LaunchErrCategory is set only for a stage that failed to launch, matching Exec.
	LaunchErrCategory fserrors.Category
	// StdoutTotal and StderrTotal count every byte the parent read from that stream, including the
	// bytes past maxCapture that were counted but not retained. A pipeline stage can be ended before
	// it finishes producing — a downstream exit closes the upstream read end so the producer takes
	// SIGPIPE — so a total counts what was captured, not what the stage would have gone on to emit.
	StdoutTotal int64
	StderrTotal int64
	// PipelineErrCategory is set only for a stage affected by a post-launch copier, collector,
	// internal, or cancellation failure, which Pipeline also reports as its returned error.
	PipelineErrCategory PipelineStageFailure
}

// PipelineRunner is the optional capability a Runner may also implement to run several specs as one
// concurrent pipeline over OS pipes. It is discovered by type assertion rather than added to Runner,
// so a runner that executes single commands needs no multi-process orchestration.
//
// Only specs[0].Stdin is honored: every later stage takes stdin from the upstream stage's pipe and
// any Stdin set on it is ignored.
type PipelineRunner interface {
	// PreflightPipeline validates every spec and decides capability support before any process
	// starts. It returns ErrPipelineUnsupported only when this runner cannot run a pipeline at all,
	// and any other non-nil error means nothing was started.
	PreflightPipeline(ctx context.Context, specs []RunSpec) error
	// Pipeline runs the ordered specs as one pipeline after a successful preflight, bounding each
	// captured stream to maxCapture bytes. It never returns ErrPipelineUnsupported. A non-nil error
	// is returned only once there is one PipelineResult per input spec and every started process,
	// copier, and collector has been joined.
	Pipeline(ctx context.Context, specs []RunSpec, maxCapture int) ([]PipelineResult, error)
}

type BoundedExecRunner interface {
	ExecBounded(ctx context.Context, spec RunSpec, maxCapture int) (RunResult, error)
}

// DirectExecRunner is the phase-1 Runner: it runs commands directly via os/exec with no
// sandboxing and no shell interpretation.
type DirectExecRunner struct{}

var (
	_ Runner            = DirectExecRunner{}
	_ PipelineRunner    = DirectExecRunner{}
	_ BoundedExecRunner = DirectExecRunner{}
)

// NewInvocationID returns a freshly minted UUIDv7 via ids.NewV7.
func (DirectExecRunner) NewInvocationID() string {
	return ids.NewV7()
}

// Exec runs spec.Argv directly (no shell) and reports the outcome. Normal completion — including
// a non-zero exit status — returns a RunResult with the captured streams, the process exit code,
// an empty LaunchErrCategory, and a nil error. A launch failure before the process starts returns
// ExitCode -1, empty streams, and a LaunchErrCategory classified from the OS error. A non-nil
// error is returned only for invalid input, in which case the RunResult is unusable.
func (DirectExecRunner) Exec(ctx context.Context, spec RunSpec) (RunResult, error) {
	if !ids.IsValidV7(spec.InvocationID) {
		return RunResult{}, fmt.Errorf("runner: invalid invocation id %q", spec.InvocationID)
	}
	if len(spec.Argv) == 0 {
		return RunResult{}, errors.New("runner: empty argv")
	}

	cmd := exec.CommandContext(ctx, spec.Argv[0], spec.Argv[1:]...)
	killGroupOnCancel(cmd)
	if spec.Cwd != "" {
		cmd.Dir = spec.Cwd
	}
	if spec.Env != nil {
		cmd.Env = spec.Env
	}
	if len(spec.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(spec.Stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	res := RunResult{
		InvocationID: spec.InvocationID,
		Stdout:       stdout.Bytes(),
		Stderr:       stderr.Bytes(),
		Duration:     duration,
	}

	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
		return res, nil
	}

	// Launch failure before the process started: no usable streams or exit code, only a category.
	res.ExitCode = -1
	res.Stdout = nil
	res.Stderr = nil
	res.LaunchErrCategory = classifyLaunchErr(err)
	return res, nil
}

func (DirectExecRunner) ExecBounded(ctx context.Context, spec RunSpec, maxCapture int) (RunResult, error) {
	if !ids.IsValidV7(spec.InvocationID) {
		return RunResult{}, fmt.Errorf("runner: invalid invocation id %q", spec.InvocationID)
	}
	if len(spec.Argv) == 0 {
		return RunResult{}, errors.New("runner: empty argv")
	}

	cmd := exec.CommandContext(ctx, spec.Argv[0], spec.Argv[1:]...)
	killGroupOnCancel(cmd)
	if spec.Cwd != "" {
		cmd.Dir = spec.Cwd
	}
	if spec.Env != nil {
		cmd.Env = spec.Env
	}
	if len(spec.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(spec.Stdin)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		return RunResult{}, fmt.Errorf("runner: capture setup: %w", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		_ = outR.Close()
		_ = outW.Close()
		return RunResult{}, fmt.Errorf("runner: capture setup: %w", err)
	}
	cmd.Stdout = outW
	cmd.Stderr = errW

	start := time.Now()
	startErr := cmd.Start()
	_ = outW.Close()
	_ = errW.Close()
	if startErr != nil {
		_ = outR.Close()
		_ = errR.Close()
		return RunResult{
			InvocationID:      spec.InvocationID,
			ExitCode:          -1,
			Duration:          time.Since(start),
			LaunchErrCategory: classifyLaunchErr(startErr),
		}, nil
	}

	var stdoutCap, stderrCap capture
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		stdoutCap = drainStream(outR, maxCapture)
	}()
	go func() {
		defer wg.Done()
		stderrCap = drainStream(errR, maxCapture)
	}()
	waitErr := cmd.Wait()
	wg.Wait()
	duration := time.Since(start)

	if stdoutCap.err != nil || stderrCap.err != nil {
		return RunResult{}, fmt.Errorf("runner: output capture: %w", errors.Join(stdoutCap.err, stderrCap.err))
	}
	return RunResult{
		InvocationID: spec.InvocationID,
		Stdout:       stdoutCap.kept,
		Stderr:       stderrCap.kept,
		ExitCode:     exitCodeAfterWait(cmd, waitErr),
		Duration:     duration,
		StdoutTotal:  stdoutCap.total,
		StderrTotal:  stderrCap.total,
	}, nil
}

// PreflightPipeline validates every spec before any process starts. DirectExecRunner supports every
// pipeline, so it never returns ErrPipelineUnsupported.
func (DirectExecRunner) PreflightPipeline(_ context.Context, specs []RunSpec) error {
	return validatePipelineSpecs(specs)
}

// Pipeline launches every spec as a concurrent stage joined by OS pipes. Capture goes through parent
// copiers and collectors rather than an opaque writer so a bound can be applied while the stream
// keeps being consumed — a child must never block on a full pipe. A stage that fails to launch is
// handled as a stage that exited immediately: its pipe ends close, so the upstream stage takes
// SIGPIPE and the downstream stage sees EOF on stdin and still runs. Every started process is waited
// on and every goroutine joined before returning, on every path.
func (DirectExecRunner) Pipeline(ctx context.Context, specs []RunSpec, maxCapture int) ([]PipelineResult, error) {
	if err := validatePipelineSpecs(specs); err != nil {
		return nil, err
	}
	n := len(specs)
	results := make([]PipelineResult, n)
	for i := range results {
		results[i] = PipelineResult{InvocationID: specs[i].InvocationID, ExitCode: -1}
	}

	pipes, err := newStagePipes(n)
	if err != nil {
		for i := range results {
			results[i].PipelineErrCategory = PipelineFailureInternal
		}
		return results, fmt.Errorf("runner: pipeline setup: %w", err)
	}

	cmds := make([]*exec.Cmd, n)
	starts := make([]time.Time, n)
	for i, spec := range specs {
		cmd := exec.CommandContext(ctx, spec.Argv[0], spec.Argv[1:]...)
		killGroupOnCancel(cmd)
		if spec.Cwd != "" {
			cmd.Dir = spec.Cwd
		}
		if spec.Env != nil {
			cmd.Env = spec.Env
		}
		if i == 0 {
			if len(spec.Stdin) > 0 {
				cmd.Stdin = bytes.NewReader(spec.Stdin)
			}
		} else {
			cmd.Stdin = pipes[i].inR
		}
		cmd.Stdout = pipes[i].outW
		cmd.Stderr = pipes[i].errW

		starts[i] = time.Now()
		if err := cmd.Start(); err != nil {
			results[i].LaunchErrCategory = classifyLaunchErr(err)
		} else {
			cmds[i] = cmd
		}
		// The parent's copies of the ends the child now owns must go immediately: while the parent
		// holds a write end no reader ever sees EOF, and a failed launch only hands the upstream
		// stage EPIPE and the downstream stage EOF once these are closed.
		_ = pipes[i].outW.Close()
		_ = pipes[i].errW.Close()
		if pipes[i].inR != nil {
			_ = pipes[i].inR.Close()
		}
	}

	stdoutCap := make([]capture, n)
	stderrCap := make([]capture, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(2)
		go func() {
			defer wg.Done()
			stderrCap[i] = drainStream(pipes[i].errR, maxCapture)
		}()
		go func() {
			defer wg.Done()
			if i == n-1 {
				stdoutCap[i] = drainStream(pipes[i].out, maxCapture)
				return
			}
			stdoutCap[i] = linkStream(pipes[i].out, pipes[i+1].inW, maxCapture)
		}()
		if cmds[i] == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			waitErr := cmds[i].Wait()
			results[i].Duration = time.Since(starts[i])
			results[i].ExitCode = exitCodeAfterWait(cmds[i], waitErr)
		}()
	}
	wg.Wait()

	for i := range results {
		if results[i].LaunchErrCategory != "" {
			continue
		}
		results[i].Stdout = stdoutCap[i].kept
		results[i].StdoutTotal = stdoutCap[i].total
		results[i].Stderr = stderrCap[i].kept
		results[i].StderrTotal = stderrCap[i].total
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		for i := range results {
			results[i].PipelineErrCategory = PipelineFailureCanceled
		}
		return results, fmt.Errorf("runner: pipeline canceled: %w", ctxErr)
	}

	var pipelineErr error
	for i := range results {
		if stderrCap[i].err != nil {
			results[i].PipelineErrCategory = PipelineFailureCopy
			pipelineErr = errors.Join(pipelineErr, fmt.Errorf("runner: stage %d stderr capture: %w", i, stderrCap[i].err))
		}
		if stdoutCap[i].err != nil {
			results[i].PipelineErrCategory = PipelineFailureCopy
			if i+1 < n {
				results[i+1].PipelineErrCategory = PipelineFailureCopy
			}
			pipelineErr = errors.Join(pipelineErr, fmt.Errorf("runner: stage %d stdout capture: %w", i, stdoutCap[i].err))
		}
	}
	return results, pipelineErr
}

func validatePipelineSpecs(specs []RunSpec) error {
	if len(specs) == 0 {
		return errors.New("runner: empty pipeline")
	}
	for i, spec := range specs {
		if !ids.IsValidV7(spec.InvocationID) {
			return fmt.Errorf("runner: pipeline stage %d invalid invocation id %q", i, spec.InvocationID)
		}
		if len(spec.Argv) == 0 {
			return fmt.Errorf("runner: pipeline stage %d empty argv", i)
		}
	}
	return nil
}

// stagePipes holds one stage's OS pipes. out/errR are the parent's read ends; outW/errW are the
// child's write ends; inR is the child's stdin read end and inW the parent copier's write end, both
// nil for the first stage, which takes RunSpec.Stdin instead.
type stagePipes struct {
	out  *os.File
	outW *os.File
	errR *os.File
	errW *os.File
	inR  *os.File
	inW  *os.File
}

func newStagePipes(n int) ([]stagePipes, error) {
	pipes := make([]stagePipes, n)
	closeAll := func() {
		for _, p := range pipes {
			for _, f := range []*os.File{p.out, p.outW, p.errR, p.errW, p.inR, p.inW} {
				if f != nil {
					_ = f.Close()
				}
			}
		}
	}
	for i := range n {
		r, w, err := os.Pipe()
		if err != nil {
			closeAll()
			return nil, err
		}
		pipes[i].out, pipes[i].outW = r, w
		r, w, err = os.Pipe()
		if err != nil {
			closeAll()
			return nil, err
		}
		pipes[i].errR, pipes[i].errW = r, w
		if i > 0 {
			r, w, err = os.Pipe()
			if err != nil {
				closeAll()
				return nil, err
			}
			pipes[i].inR, pipes[i].inW = r, w
		}
	}
	return pipes, nil
}

// capture is one drained stream; err holds a read/write failure, never the terminating EOF.
type capture struct {
	kept  []byte
	total int64
	err   error
}

const streamChunk = 32 * 1024

func drainStream(src *os.File, maxCapture int) capture {
	defer func() { _ = src.Close() }()
	var c capture
	buf := make([]byte, streamChunk)
	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			c.total += int64(nr)
			c.kept = appendCapped(c.kept, buf[:nr], maxCapture)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				c.err = err
			}
			return c
		}
	}
}

// linkStream copies src into dst with the same bounded capture as drainStream. A write failing with
// EPIPE means the downstream stage already exited, so src is closed and the upstream producer takes
// SIGPIPE instead of writing forever into a stream nobody reads.
func linkStream(src, dst *os.File, maxCapture int) capture {
	defer func() { _ = dst.Close() }()
	defer func() { _ = src.Close() }()
	var c capture
	buf := make([]byte, streamChunk)
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			c.total += int64(nr)
			c.kept = appendCapped(c.kept, buf[:nr], maxCapture)
			if _, werr := dst.Write(buf[:nr]); werr != nil {
				if !errors.Is(werr, syscall.EPIPE) && !errors.Is(werr, io.ErrClosedPipe) {
					c.err = werr
				}
				return c
			}
		}
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) {
				c.err = rerr
			}
			return c
		}
	}
}

func appendCapped(kept, chunk []byte, maxCapture int) []byte {
	room := maxCapture - len(kept)
	if room <= 0 {
		return kept
	}
	if len(chunk) > room {
		chunk = chunk[:room]
	}
	return append(kept, chunk...)
}

func killGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}

func exitCodeAfterWait(cmd *exec.Cmd, waitErr error) int {
	if cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode()
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

// classifyLaunchErr maps an os/exec launch failure to an fserrors.Category. exec.ErrNotFound is a
// sentinel rather than an errno-backed error, so CategorizeErrno alone would mislabel a missing
// binary as io_error; it is mapped to NotFound explicitly before the errno fallback handles
// permission-denied and other errno-backed failures (launch-failure path).
func classifyLaunchErr(err error) fserrors.Category {
	if errors.Is(err, exec.ErrNotFound) {
		return fserrors.NotFound
	}
	return fserrors.CategorizeErrno(err)
}
