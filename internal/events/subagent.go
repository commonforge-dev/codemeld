// Child-agent lifecycle payloads and their emitters: one start/end pair per
// delegate call, linked by a stable invocation id, recorded in the parent's own
// session so a reader can see what was delegated, what it changed, and how it ended.
package events

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"codemeld.dev/codemeld/internal/sessions"
)

// Terminal reasons for a child agent, mirroring internal/subagent's Reason values.
const (
	ChildAgentReasonCompleted = "completed"
	ChildAgentReasonCancelled = "cancelled"
	ChildAgentReasonStepCap   = "step_cap"
	ChildAgentReasonFailed    = "failed"
)

const (
	ChildRollbackNotNeeded   = "not_needed"
	ChildRollbackRolledBack  = "rolled_back"
	ChildRollbackUnrecovered = "unrecovered"
)

var childAgentReasons = set(
	ChildAgentReasonCompleted,
	ChildAgentReasonCancelled,
	ChildAgentReasonStepCap,
	ChildAgentReasonFailed,
)

var childRollbackOutcomes = set(
	ChildRollbackNotNeeded,
	ChildRollbackRolledBack,
	ChildRollbackUnrecovered,
)

// maxChildDeclaredPaths matches the declared-scope limit internal/subagent's journal refuses
// past, so an over-limit declaration fails here before any snapshot is taken. Written paths get
// their own, larger limit because one declared directory can hold many files.
const (
	maxChildDeclaredPaths = 32
	maxChildWrittenPaths  = 256
	maxChildDeletedPaths  = 256
	// maxChildMovePairs is the most pairs maxChildDeclaredPaths endpoints can form when no path is both
	// a source and a destination.
	maxChildMovePairs = (maxChildDeclaredPaths / 2) * (maxChildDeclaredPaths / 2)
)

type ChildMovePair struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

// ChildAgentStart records a child agent about to run. The instruction is reduced to its
// length and digest so the record stays bounded and carries no delegated text.
type ChildAgentStart struct {
	InvocationID      string   `json:"invocation_id"`
	ProviderID        string   `json:"provider_id"`
	ModelID           string   `json:"model_id"`
	DeclaredPaths     []string `json:"declared_paths"`
	StepCap           int64    `json:"step_cap"`
	InstructionBytes  int64    `json:"instruction_bytes"`
	InstructionDigest string   `json:"instruction_digest"`

	DeclaredDeletePaths []string        `json:"declared_delete_paths,omitempty"`
	DeclaredMovePairs   []ChildMovePair `json:"declared_move_pairs,omitempty"`
	DeclaredDirs        []string        `json:"declared_dirs,omitempty"`
}

func (ChildAgentStart) Kind() string { return KindChildAgentStart }

func (p ChildAgentStart) validate() error {
	const k = KindChildAgentStart
	if err := validV7(k, "invocation_id", p.InvocationID); err != nil {
		return err
	}
	if err := required(k, "provider_id", p.ProviderID); err != nil {
		return err
	}
	if err := required(k, "model_id", p.ModelID); err != nil {
		return err
	}
	if err := childPathList(k, "declared_paths", p.DeclaredPaths, maxChildDeclaredPaths); err != nil {
		return err
	}
	if err := childPathList(k, "declared_delete_paths", p.DeclaredDeletePaths, maxChildDeclaredPaths); err != nil {
		return err
	}
	if err := childPairList(k, "declared_move_pairs", p.DeclaredMovePairs); err != nil {
		return err
	}
	if err := childPathList(k, "declared_dirs", p.DeclaredDirs, maxChildDeclaredPaths); err != nil {
		return err
	}
	if n := distinctPaths(p.DeclaredPaths, p.DeclaredDeletePaths, pairEndpoints(p.DeclaredMovePairs), p.DeclaredDirs); n > maxChildDeclaredPaths {
		return fmt.Errorf("%s: %d distinct paths across declared_paths, declared_delete_paths, declared_move_pairs and declared_dirs exceeds the limit of %d", k, n, maxChildDeclaredPaths)
	}
	if p.StepCap < 1 {
		return fmt.Errorf("%s.step_cap: must be >= 1, got %d", k, p.StepCap)
	}
	if p.InstructionBytes < 1 {
		return fmt.Errorf("%s.instruction_bytes: must be >= 1, got %d", k, p.InstructionBytes)
	}
	if !argumentHashRE.MatchString(p.InstructionDigest) {
		return fmt.Errorf("%s.instruction_digest: %q is not a lowercase 64-char SHA-256 hex digest", k, p.InstructionDigest)
	}
	return nil
}

// ChildAgentEnd records how a child agent ended. RollbackOutcome is a third outcome
// alongside a clean finish and a clean undo: "unrecovered" says the child's writes are
// still on disk after a failed restore, so it must never be reported as "rolled_back".
type ChildAgentEnd struct {
	InvocationID    string   `json:"invocation_id"`
	Reason          string   `json:"reason"`
	Steps           int64    `json:"steps"`
	WrittenPaths    []string `json:"written_paths"`
	RollbackOutcome string   `json:"rollback_outcome"`
	DurationMs      int64    `json:"duration_ms"`
	ReplyTruncated  bool     `json:"reply_truncated"`
	// WrittenPathsTotal is the child's true distinct-write count, present only when the list
	// above was bounded to fit the record.
	WrittenPathsTotal int64 `json:"written_paths_total,omitempty"`

	DeletedPaths      []string `json:"deleted_paths,omitempty"`
	DeletedPathsTotal int64    `json:"deleted_paths_total,omitempty"`

	// MovedPairs needs no total: a child moves only pairs it declared, so the distinct list never
	// outgrows the declaration's own limit.
	MovedPairs []ChildMovePair `json:"moved_pairs,omitempty"`
}

func (ChildAgentEnd) Kind() string { return KindChildAgentEnd }

func (p ChildAgentEnd) validate() error {
	const k = KindChildAgentEnd
	if err := validV7(k, "invocation_id", p.InvocationID); err != nil {
		return err
	}
	if err := enum(k, "reason", p.Reason, childAgentReasons); err != nil {
		return err
	}
	if err := nonNegative(k, "steps", p.Steps); err != nil {
		return err
	}
	if err := childPathList(k, "written_paths", p.WrittenPaths, maxChildWrittenPaths); err != nil {
		return err
	}
	if err := childPathTotal(k, "written_paths_total", p.WrittenPathsTotal, len(p.WrittenPaths)); err != nil {
		return err
	}
	if err := childPathList(k, "deleted_paths", p.DeletedPaths, maxChildDeletedPaths); err != nil {
		return err
	}
	if err := childPathTotal(k, "deleted_paths_total", p.DeletedPathsTotal, len(p.DeletedPaths)); err != nil {
		return err
	}
	if err := childPairList(k, "moved_pairs", p.MovedPairs); err != nil {
		return err
	}
	if err := enum(k, "rollback_outcome", p.RollbackOutcome, childRollbackOutcomes); err != nil {
		return err
	}
	return nonNegative(k, "duration_ms", p.DurationMs)
}

func childPathTotal(kind, field string, total int64, recorded int) error {
	if total != 0 && total <= int64(recorded) {
		return fmt.Errorf("%s.%s: %d does not exceed the %d recorded paths, so nothing was bounded", kind, field, total, recorded)
	}
	return nil
}

func distinctPaths(lists ...[]string) int {
	seen := make(map[string]bool)
	for _, list := range lists {
		for _, path := range list {
			seen[path] = true
		}
	}
	return len(seen)
}

func childPathList(kind, field string, paths []string, limit int) error {
	if len(paths) > limit {
		return fmt.Errorf("%s.%s: %d paths exceeds the limit of %d", kind, field, len(paths), limit)
	}
	for i, path := range paths {
		if err := absCleanPath(kind, fmt.Sprintf("%s[%d]", field, i), path); err != nil {
			return err
		}
	}
	return nil
}

func childPairList(kind, field string, pairs []ChildMovePair) error {
	if len(pairs) > maxChildMovePairs {
		return fmt.Errorf("%s.%s: %d pairs exceeds the limit of %d", kind, field, len(pairs), maxChildMovePairs)
	}
	for i, pair := range pairs {
		if err := absCleanPath(kind, fmt.Sprintf("%s[%d].source", field, i), pair.Source); err != nil {
			return err
		}
		if err := absCleanPath(kind, fmt.Sprintf("%s[%d].destination", field, i), pair.Destination); err != nil {
			return err
		}
	}
	return nil
}

func pairEndpoints(pairs []ChildMovePair) []string {
	out := make([]string, 0, 2*len(pairs))
	for _, pair := range pairs {
		out = append(out, pair.Source, pair.Destination)
	}
	return out
}

// EmitChildAgentStart appends child_agent_start. It refuses a declared path outside
// projectRoot, so a start-append failure — which keeps the child from beginning its first
// provider round — is also what stops a path from outside the project reaching the record.
func EmitChildAgentStart(store *sessions.Store, projectRoot string, payload ChildAgentStart) error {
	if err := withinProjectRoot(KindChildAgentStart, "declared_paths", projectRoot, payload.DeclaredPaths); err != nil {
		return err
	}
	if err := withinProjectRoot(KindChildAgentStart, "declared_delete_paths", projectRoot, payload.DeclaredDeletePaths); err != nil {
		return err
	}
	if err := withinProjectRoot(KindChildAgentStart, "declared_move_pairs", projectRoot, pairEndpoints(payload.DeclaredMovePairs)); err != nil {
		return err
	}
	if err := withinProjectRoot(KindChildAgentStart, "declared_dirs", projectRoot, payload.DeclaredDirs); err != nil {
		return err
	}
	_, err := Append(store, payload)
	return err
}

// A terminal record that cannot be appended leaves its child_agent_start unclosed, so the one
// bound a well-behaved child can still exceed — a declared directory holding more distinct files
// than the record carries — is applied here rather than refused, exactly as EmitToolExecEnd
// bounds a stream it is handed. A path outside the project root is refused instead: the child
// ceiling should have made it impossible, so it is a confinement breach, not a size.
func EmitChildAgentEnd(store *sessions.Store, projectRoot string, payload ChildAgentEnd) error {
	if err := withinProjectRoot(KindChildAgentEnd, "written_paths", projectRoot, payload.WrittenPaths); err != nil {
		return err
	}
	if err := withinProjectRoot(KindChildAgentEnd, "deleted_paths", projectRoot, payload.DeletedPaths); err != nil {
		return err
	}
	if err := withinProjectRoot(KindChildAgentEnd, "moved_pairs", projectRoot, pairEndpoints(payload.MovedPairs)); err != nil {
		return err
	}
	payload.WrittenPaths, payload.WrittenPathsTotal = boundChildPaths(payload.WrittenPaths, maxChildWrittenPaths)
	payload.DeletedPaths, payload.DeletedPathsTotal = boundChildPaths(payload.DeletedPaths, maxChildDeletedPaths)
	_, err := Append(store, payload)
	return err
}

func boundChildPaths(paths []string, limit int) ([]string, int64) {
	if len(paths) <= limit {
		return paths, 0
	}
	return paths[:limit], int64(len(paths))
}

func withinProjectRoot(kind, field, projectRoot string, paths []string) error {
	if err := absCleanPath(kind, "project_root", projectRoot); err != nil {
		return err
	}
	prefix := projectRoot + string(filepath.Separator)
	for i, path := range paths {
		if path != projectRoot && !strings.HasPrefix(path, prefix) {
			return fmt.Errorf("%s.%s[%d]: %q is outside the project root %q", kind, field, i, path, projectRoot)
		}
	}
	return nil
}

// ChildInstructionDigest lives beside the validator that pins the digest format so a caller
// hands the instruction to nothing but this function.
func ChildInstructionDigest(instruction string) string {
	sum := sha256.Sum256([]byte(instruction))
	return hex.EncodeToString(sum[:])
}
