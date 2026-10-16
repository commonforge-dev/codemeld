package subagent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/procowner"
	"codemeld.dev/codemeld/internal/sessions"
)

// The five caps are fixed rather than configured. maxStateBytesPerPath deliberately equals
// maxSnapshotBytesPerFile so a child can never write a file larger than the pre-state that would have
// to replace it. maxJournalBytes is sized from the rest: one pre-state and one post-state per path at
// encoding/json's 4/3 base64 expansion (2 x 128 MiB x 4/3 = 341 MiB) plus a 16 MiB envelope for paths,
// modes, identities, owner, and punctuation, rounded up. Every cap is inclusive.
const (
	maxDeclaredPaths        = 32
	maxSnapshotBytesPerFile = 10 << 20
	maxSnapshotBytesTotal   = 128 << 20
	maxStateBytesPerPath    = 10 << 20
)

// maxJournalBytes is a variable only so a test can pin the inclusive boundary without building a
// 384 MiB record; production never changes it.
var maxJournalBytes = 384 << 20

const journalSchemaVersion = 1

// journalDeleteSchemaVersion is written only by a journal holding a declared delete path, so a reader
// that knows only regular-file states refuses the record instead of misreading its entry kinds.
const journalDeleteSchemaVersion = 2

// journalMoveSchemaVersion is written only by a journal holding a declared move pair, so a reader that
// knows no moves refuses the record instead of restoring a moved entry's endpoints one at a time.
const journalMoveSchemaVersion = 3

const journalRecordName = "journal.json"

const (
	journalRecordMode os.FileMode = 0o600
	journalDirMode    os.FileMode = 0o700
)

type lifecycleState string

const (
	lifecycleActive        lifecycleState = "active"
	lifecycleTransferReady lifecycleState = "transfer_ready"
	lifecycleCommitted     lifecycleState = "committed"
)

type rollbackProgress string

const (
	rollbackUnresolved rollbackProgress = "unresolved"
	rollbackRestoring  rollbackProgress = "restoring"
	rollbackRestored   rollbackProgress = "restored"
)

type entryKind string

const (
	kindSymlink entryKind = "symlink"
	kindDir     entryKind = "dir"
)

// An empty Kind is a regular file, the only kind a schema-1 record holds.
type fileState struct {
	Exists bool        `json:"exists"`
	Kind   entryKind   `json:"kind,omitempty"`
	Data   []byte      `json:"data,omitempty"`
	Link   string      `json:"link,omitempty"`
	Mode   os.FileMode `json:"mode,omitempty"`
	Dev    uint64      `json:"dev,omitempty"`
	Ino    uint64      `json:"ino,omitempty"`
}

type pendingMutation struct {
	State fileState `json:"state"`
	// NeedsParentSync starts true for every pending record and is cleared only by a successful fsync
	// of the target parent, because a crash between a publish helper's return and the record rewrite
	// would otherwise leave a pending transition that looks durable from visibility alone.
	NeedsParentSync bool `json:"needs_parent_sync"`
}

type dirRecord struct {
	Rel       string           `json:"rel"`
	Confirmed bool             `json:"confirmed"`
	Created   bool             `json:"created"`
	Dev       uint64           `json:"dev,omitempty"`
	Ino       uint64           `json:"ino,omitempty"`
	Progress  rollbackProgress `json:"progress"`
}

type pathRecord struct {
	Path      string           `json:"path"`
	Ancestor  string           `json:"ancestor"`
	Suffix    []string         `json:"suffix"`
	ParentDev uint64           `json:"parent_dev"`
	ParentIno uint64           `json:"parent_ino"`
	Pre       fileState        `json:"pre"`
	LastKnown fileState        `json:"last_known"`
	Pending   *pendingMutation `json:"pending,omitempty"`
	Progress  rollbackProgress `json:"progress"`
	Dirs      []dirRecord      `json:"dirs,omitempty"`
	// KeptByUser records that the user chose to keep the state a path holds now rather than have it
	// put back. It is durable so an answered path is neither restored nor reported again.
	KeptByUser bool `json:"kept_by_user,omitempty"`
	Delete     bool `json:"delete,omitempty"`
	Move       bool `json:"move,omitempty"`
	// ReplacementDev and ReplacementIno name the entry a rollback published for this path, the only
	// same-content entry a resumed restore may accept as its own; for a recreated directory it is also
	// the only directory besides the snapshotted one a descent may pass through here.
	ReplacementDev uint64 `json:"replacement_dev,omitempty"`
	ReplacementIno uint64 `json:"replacement_ino,omitempty"`
}

func (pr *pathRecord) anyKind() bool { return pr.Delete || pr.Move }

type childLink struct {
	Dir           string `json:"dir"`
	Depth         int    `json:"depth"`
	TransferReady bool   `json:"transfer_ready"`
	Absorbed      bool   `json:"absorbed"`
}

type movePair struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

type moveState string

const (
	movePending   moveState = "pending"
	moveCompleted moveState = "completed"
	moveUndoing   moveState = "undoing"
	moveUndone    moveState = "undone"
)

type moveRecord struct {
	movePair
	State moveState `json:"state"`
}

type journalRecord struct {
	SchemaVersion int             `json:"schema_version"`
	Owner         procowner.Owner `json:"owner"`
	Invocation    string          `json:"invocation"`
	Depth         int             `json:"depth"`
	Lifecycle     lifecycleState  `json:"lifecycle"`
	DirDev        uint64          `json:"dir_dev"`
	DirIno        uint64          `json:"dir_ino"`
	Paths         []pathRecord    `json:"paths"`
	MovePairs     []movePair      `json:"move_pairs,omitempty"`
	// Moves holds every move this child made, in the order it made them.
	Moves       []moveRecord `json:"moves,omitempty"`
	Children    []childLink  `json:"children,omitempty"`
	Unrecovered []string     `json:"unrecovered,omitempty"`
	// Retained holds the failures a resumed terminal pass must not re-derive away. Every other
	// unrecovered note is re-established from the current filesystem state at Finish; a required
	// durability retry that failed cannot be, because a later successful sync would otherwise turn the
	// transaction into a clean commit or a clean rollback.
	Retained []string `json:"retained,omitempty"`
}

// Journal is the durable all-or-nothing record of one child agent's declared scope. It
// holds the dedicated journal directory open for the whole transaction: every record rewrite, every
// rollback step, and the final cleanup unlink run relative to that descriptor, so a directory swapped in
// at the path after the child was dispatched can neither redirect an update nor suppress one.
type Journal struct {
	mu          sync.Mutex
	holder      *os.File
	dir         *os.File
	dirName     string
	path        string
	projectRoot string
	rec         journalRecord
	index       map[string]int
	parent      *Journal
	children    []*Journal
	written     bool
	gone        bool
}

var _ filetools.WriteJournal = (*Journal)(nil)

// Declared, DeclaredDelete, and DeclaredMoves must be the canonical scopes resolved before dispatch, not
// the incomplete record of what a run turned out to touch.
type JournalConfig struct {
	Home           string
	ProjectRoot    string
	Invocation     string
	Declared       []string
	DeclaredDelete []string
	DeclaredMoves  []permissions.MovePair
	Parent         *Journal
}

// JournalOutcome is what a terminal transaction did. Unrecovered is an outcome in its own right,
// distinct from both a clean commit and a clean rollback: the named paths are left as they are and the
// journal survives for recovery or the user to resolve.
type JournalOutcome struct {
	Restored    []string
	Unrecovered []string
	JournalPath string
	HeldMoves   []HeldMove
}

// Resumes marks a move whose linked undo had already begun, so a later recovery continues it rather than
// leaving it to be fixed by hand.
type HeldMove struct {
	Source      string
	Destination string
	Reason      string
	Resumes     bool
}

func (h HeldMove) note() string { return h.Source + " -> " + h.Destination + ": " + h.Reason }

// beforeJournalStep is the test seam that stands in for a crash: it fires at each labelled durable
// boundary of the journal's lifecycle, and an error returned from it aborts that step exactly as a
// killed process would leave it. Production runs the no-op.
var beforeJournalStep = func(string) error { return nil }

// syncTargetParent is the fsync every pending resolution and every rollback act is gated on. It is a
// variable so a test can fail it; production always runs the real fsync.
var syncTargetParent = (*os.File).Sync

// OpenJournal snapshots every declared path and writes the transaction's intent to disk before the
// caller dispatches the child, so a parent that dies without unwinding still leaves a recoverable
// record. Every refusal here — an unsafe journal location, a path of a kind its declaration cannot
// restore, or any of the fixed caps — happens before both the child and the journal storage exist.
func OpenJournal(cfg JournalConfig) (*Journal, error) {
	deletable := make(map[string]bool, len(cfg.DeclaredDelete))
	for _, target := range cfg.DeclaredDelete {
		deletable[target] = true
	}
	movable := make(map[string]bool, 2*len(cfg.DeclaredMoves))
	pairs := make([]movePair, 0, len(cfg.DeclaredMoves))
	for _, pair := range cfg.DeclaredMoves {
		pairs = append(pairs, movePair{Source: pair.Source, Destination: pair.Destination})
		movable[pair.Source], movable[pair.Destination] = true, true
	}
	declared := unionPaths(cfg.Declared, cfg.DeclaredDelete, slices.Collect(maps.Keys(movable)))
	if len(declared) == 0 {
		return nil, errors.New("subagent: a child agent journal needs at least one declared path")
	}
	if len(declared) > maxDeclaredPaths {
		return nil, fmt.Errorf("subagent: %d declared paths exceeds the %d a child agent journal can snapshot", len(declared), maxDeclaredPaths)
	}

	// The layout is derived from the sessions one, but the journal tree is a sibling of the sessions
	// tree rather than a subdirectory of it: sessions.Prune walks every directory under SessionRoot as
	// a per-folder session directory.
	codemeldHome := filepath.Base(filepath.Dir(sessions.SessionRoot(cfg.Home)))
	folderDir := sessions.FolderDirName(cfg.ProjectRoot)
	components := []string{codemeldHome, journalsDirName, folderDir, cfg.Invocation}
	dirPath := filepath.Join(append([]string{cfg.Home}, components...)...)
	if err := refuseUnsafeJournalLocation(dirPath, cfg.ProjectRoot, declared); err != nil {
		return nil, err
	}

	paths, err := snapshotDeclared(cfg.ProjectRoot, declared, deletable, movable)
	if err != nil {
		return nil, err
	}

	owner, err := procowner.Capture()
	if err != nil {
		return nil, fmt.Errorf("subagent: cannot record the journal's owning process: %w", err)
	}

	version := journalSchemaVersion
	switch {
	case len(pairs) > 0:
		version = journalMoveSchemaVersion
	case len(deletable) > 0:
		version = journalDeleteSchemaVersion
	}
	j := &Journal{
		dirName:     cfg.Invocation,
		path:        dirPath,
		projectRoot: cfg.ProjectRoot,
		index:       make(map[string]int, len(paths)),
		parent:      cfg.Parent,
		rec: journalRecord{
			SchemaVersion: version,
			Owner:         owner,
			Invocation:    cfg.Invocation,
			Lifecycle:     lifecycleActive,
			Paths:         paths,
			MovePairs:     pairs,
		},
	}
	if cfg.Parent != nil {
		j.rec.Depth = cfg.Parent.rec.Depth + 1
	}
	for i := range paths {
		j.index[paths[i].Path] = i
	}
	if _, err := j.marshal(); err != nil {
		return nil, err
	}

	holder, dir, err := createJournalStorage(cfg.Home, components)
	if err != nil {
		return nil, err
	}
	j.holder, j.dir = holder, dir
	if j.rec.DirDev, j.rec.DirIno, err = descriptorIdentity(dir); err != nil {
		j.Close()
		return nil, err
	}
	if err := j.flush(); err != nil {
		j.removeStorage()
		j.Close()
		return nil, err
	}
	if cfg.Parent != nil {
		if err := cfg.Parent.link(j); err != nil {
			j.removeStorage()
			j.Close()
			return nil, err
		}
		cfg.Parent.children = append(cfg.Parent.children, j)
	}
	return j, nil
}

const journalsDirName = "journals"

func unionPaths(lists ...[]string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, list := range lists {
		for _, path := range list {
			if !seen[path] {
				seen[path] = true
				out = append(out, path)
			}
		}
	}
	sort.Strings(out)
	return out
}

// refuseUnsafeJournalLocation rejects a delegation whose journal would live inside the working copy —
// a project that is the user's home, or one that already contains the codemeld home — before any
// journal storage is created. A declared write target that equals or contains the journal directory is
// refused for the same reason: the child could then rewrite its own rollback record.
func refuseUnsafeJournalLocation(dirPath, projectRoot string, declared []string) error {
	if permissions.IsDescendantOrEqual(dirPath, projectRoot) {
		return fmt.Errorf("subagent: the child agent journal directory %s is inside the project, so a rollback record cannot be kept out of the working copy", dirPath)
	}
	for _, target := range declared {
		if permissions.IsDescendantOrEqual(dirPath, target) {
			return fmt.Errorf("subagent: declared path %s can contain the child agent journal directory %s", target, dirPath)
		}
	}
	return nil
}

// snapshotDeclared refuses rather than truncates at a cap: a snapshot cut short would restore a
// corrupted file.
func snapshotDeclared(projectRoot string, declared []string, deletable, movable map[string]bool) ([]pathRecord, error) {
	var total int64
	out := make([]pathRecord, 0, len(declared))
	for _, target := range declared {
		dir, ancestor, suffix, err := openDeepestExisting(projectRoot, target)
		if err != nil {
			return nil, err
		}
		rec := pathRecord{Path: target, Ancestor: ancestor, Suffix: suffix, Progress: rollbackUnresolved, Delete: deletable[target], Move: movable[target]}
		rec.ParentDev, rec.ParentIno, err = descriptorIdentity(dir)
		if err == nil {
			rec.Pre, err = snapshotUnder(dir, suffix, target, rec.anyKind())
		}
		_ = dir.Close() //nolint:errcheck // read-only descriptor held only for the snapshot
		if err != nil {
			return nil, err
		}
		total += int64(len(rec.Pre.Data) + len(rec.Pre.Link))
		if total > maxSnapshotBytesTotal {
			return nil, fmt.Errorf("subagent: the declared paths hold more than the %d bytes a child agent journal can snapshot in total", int64(maxSnapshotBytesTotal))
		}
		rec.LastKnown = rec.Pre
		out = append(out, rec)
	}
	return out, nil
}

// snapshotUnder establishes absence by descriptor traversal when the immediate parent is itself
// missing, because SnapshotFileAt takes one path component and cannot be handed the whole suffix.
func snapshotUnder(dir *os.File, suffix []string, target string, anyKind bool) (fileState, error) {
	if len(suffix) > 1 {
		var st unix.Stat_t
		err := unix.Fstatat(int(dir.Fd()), suffix[0], &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			return fileState{}, fmt.Errorf("subagent: %s reappeared under the snapshot's deepest existing ancestor", filepath.Join(target))
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return fileState{}, fmt.Errorf("subagent: cannot establish that %s is absent: %w", target, err)
		}
		return fileState{}, nil
	}
	read := regularState
	if anyKind {
		read = readEntryState
	}
	state, err := read(dir, suffix[0])
	switch {
	case err == nil:
		return state, nil
	case errors.Is(err, fsutil.ErrSnapshotNotRegular):
		return fileState{}, fmt.Errorf("subagent: declared path %s is not a regular file, so a child agent's writes to it cannot be rolled back", target)
	case errors.Is(err, errUnsupportedKind):
		return fileState{}, fmt.Errorf("subagent: declared path %s is not a regular file, symlink, or directory, so a child agent's deletion of it cannot be rolled back", target)
	case errors.Is(err, fsutil.ErrSnapshotTooLarge):
		return fileState{}, fmt.Errorf("subagent: declared path %s is larger than the %d bytes a child agent journal can snapshot", target, int64(maxSnapshotBytesPerFile))
	default:
		return fileState{}, fmt.Errorf("subagent: cannot snapshot declared path %s: %w", target, err)
	}
}

var (
	errUnsupportedKind = errors.New("subagent: the entry is not a regular file, symlink, or directory")
	errEntryChanged    = errors.New("subagent: the entry changed while it was read")
)

const maxLinkBytes = 4096

func regularState(dir *os.File, name string) (fileState, error) {
	snap, err := fsutil.SnapshotFileAt(dir, name, maxSnapshotBytesPerFile)
	if err != nil {
		return fileState{}, err
	}
	return fileState{Exists: snap.Exists, Data: snap.Data, Mode: snap.Mode, Dev: snap.Dev, Ino: snap.Ino}, nil
}

func readEntryState(dir *os.File, name string) (fileState, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fileState{}, nil
		}
		return fileState{}, &os.PathError{Op: "fstatat", Path: name, Err: err}
	}
	dev, ino := uint64(st.Dev), uint64(st.Ino)
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		return regularState(dir, name)
	case unix.S_IFDIR:
		return fileState{Exists: true, Kind: kindDir, Mode: os.FileMode(st.Mode).Perm(), Dev: dev, Ino: ino}, nil
	case unix.S_IFLNK:
		buf := make([]byte, maxLinkBytes)
		n, err := unix.Readlinkat(int(dir.Fd()), name, buf)
		if err != nil {
			return fileState{}, &os.PathError{Op: "readlinkat", Path: name, Err: err}
		}
		if n == len(buf) {
			return fileState{}, &os.PathError{Op: "readlinkat", Path: name, Err: fsutil.ErrSnapshotTooLarge}
		}
		// readlinkat resolves the name again, so the target counts only while that name still holds the
		// inode stated above.
		if aDev, aIno, aErr := entryIdentity(dir, name); aErr != nil || aDev != dev || aIno != ino {
			return fileState{}, &os.PathError{Op: "readlinkat", Path: name, Err: errEntryChanged}
		}
		return fileState{Exists: true, Kind: kindSymlink, Link: string(buf[:n]), Dev: dev, Ino: ino}, nil
	default:
		return fileState{}, &os.PathError{Op: "fstatat", Path: name, Err: errUnsupportedKind}
	}
}

// openDeepestExisting descends from the authorized project root one component at a time, each opened
// O_DIRECTORY|O_NOFOLLOW from the descriptor above it, and returns the deepest existing directory's
// held descriptor, its path, and the components missing beneath it, leaf last. Resolving the ancestor
// by pathname instead would let a component swapped for a symlink after the walk redirect the snapshot
// outside the root.
func openDeepestExisting(projectRoot, target string) (*os.File, string, []string, error) {
	rel, err := filepath.Rel(projectRoot, target)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, "", nil, fmt.Errorf("subagent: declared path %s is not inside the project directory %s", target, projectRoot)
	}
	segs := strings.Split(rel, string(filepath.Separator))
	dir, err := openDirNoFollow(projectRoot)
	if err != nil {
		return nil, "", nil, fmt.Errorf("subagent: cannot open %s to snapshot %s: %w", projectRoot, target, err)
	}
	ancestor := projectRoot
	for i := range segs[:len(segs)-1] {
		next, oErr := openSubdirNoFollow(dir, segs[i])
		if oErr == nil {
			_ = dir.Close() //nolint:errcheck // read-only intermediate descriptor; the descent holds the next one
			dir, ancestor = next, filepath.Join(ancestor, segs[i])
			continue
		}
		if errors.Is(oErr, fs.ErrNotExist) {
			return dir, ancestor, segs[i:], nil
		}
		_ = dir.Close() //nolint:errcheck // read-only descriptor abandoned on the failing descent
		component := filepath.Join(ancestor, segs[i])
		switch {
		case errors.Is(oErr, syscall.ELOOP):
			return nil, "", nil, fmt.Errorf("subagent: %s on the way to declared path %s is a symlink, so it cannot be snapshotted safely", component, target)
		case errors.Is(oErr, syscall.ENOTDIR):
			return nil, "", nil, fmt.Errorf("subagent: %s is not a directory, so declared path %s has no parent to snapshot under", component, target)
		default:
			return nil, "", nil, fmt.Errorf("subagent: cannot resolve a parent directory for declared path %s: %w", target, oErr)
		}
	}
	return dir, ancestor, segs[len(segs)-1:], nil
}

// createJournalStorage builds the whole chain under home one component at a time, each created
// relative to the descriptor of the component above it and re-opened O_DIRECTORY|O_NOFOLLOW. The
// parent that received a new entry is fsynced before the descent continues, so the directory the
// child's first write depends on is durable before that write is dispatched. It returns the
// second-to-last directory as well, because cleanup unlinks the dedicated directory from it.
func createJournalStorage(home string, components []string) (holder, dir *os.File, err error) {
	cur, err := openDirNoFollow(home)
	if err != nil {
		return nil, nil, fmt.Errorf("subagent: cannot open %s to place the child agent journal: %w", home, err)
	}
	for i, name := range components {
		last := i == len(components)-1
		next, cerr := ensureDirComponent(cur, name, last)
		if cerr != nil {
			if cur != nil {
				_ = cur.Close() //nolint:errcheck // read-only descriptor abandoned on the failing descent
			}
			return nil, nil, cerr
		}
		if last {
			return cur, next, nil
		}
		_ = cur.Close() //nolint:errcheck // read-only intermediate descriptor; the descent holds the next one
		cur = next
	}
	return nil, nil, errors.New("subagent: the child agent journal has no storage components")
}

// ensureDirComponent creates name under parent and returns it open. exclusive is set for the
// dedicated per-invocation directory, which must not already exist: reusing one would mean two
// transactions sharing a rollback record.
func ensureDirComponent(parent *os.File, name string, exclusive bool) (*os.File, error) {
	created := true
	if mkErr := unix.Mkdirat(int(parent.Fd()), name, uint32(journalDirMode)); mkErr != nil {
		if exclusive || !errors.Is(mkErr, fs.ErrExist) {
			return nil, fmt.Errorf("subagent: cannot create the child agent journal directory %s: %w", name, mkErr)
		}
		created = false
	}
	if created {
		if err := parent.Sync(); err != nil {
			return nil, fmt.Errorf("subagent: cannot make the child agent journal directory %s durable: %w", name, err)
		}
	}
	fd, oErr := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if oErr != nil {
		return nil, fmt.Errorf("subagent: cannot open the child agent journal directory %s: %w", name, oErr)
	}
	if created {
		if cErr := unix.Fchmod(fd, uint32(journalDirMode)); cErr != nil {
			_ = unix.Close(fd) //nolint:errcheck // the directory is abandoned along with the descriptor
			return nil, fmt.Errorf("subagent: cannot restrict the child agent journal directory %s: %w", name, cErr)
		}
	}
	return os.NewFile(uintptr(fd), name), nil
}

func openDirNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
}

func openSubdirNoFollow(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	return os.NewFile(uintptr(fd), name), nil
}

func descriptorIdentity(dir *os.File) (dev, ino uint64, err error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		return 0, 0, &os.PathError{Op: "fstat", Path: dir.Name(), Err: err}
	}
	return uint64(st.Dev), uint64(st.Ino), nil
}

func entryIdentity(dir *os.File, name string) (dev, ino uint64, err error) {
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return 0, 0, &os.PathError{Op: "fstatat", Path: name, Err: err}
	}
	return uint64(st.Dev), uint64(st.Ino), nil
}

func (j *Journal) Path() string { return j.path }

// Close removes nothing: a journal is deleted only by a committed or fully rolled-back outcome.
func (j *Journal) Close() {
	if j.dir != nil {
		_ = j.dir.Close() //nolint:errcheck // read-only directory descriptor
		j.dir = nil
	}
	if j.holder != nil {
		_ = j.holder.Close() //nolint:errcheck // read-only directory descriptor
		j.holder = nil
	}
}

func (j *Journal) marshal() ([]byte, error) {
	data, err := json.Marshal(&j.rec)
	if err != nil {
		return nil, fmt.Errorf("subagent: cannot serialize the child agent journal: %w", err)
	}
	if len(data) > maxJournalBytes {
		return nil, fmt.Errorf("subagent: the child agent journal record is %d bytes, over the %d-byte limit", len(data), int64(maxJournalBytes))
	}
	return data, nil
}

// flush replaces the record through the retained journal-directory descriptor and returns only once
// both the bytes and the directory entry are durable.
func (j *Journal) flush() error {
	if j.gone {
		return errors.New("subagent: the child agent journal has already been removed")
	}
	data, err := j.marshal()
	if err != nil {
		return err
	}
	if !j.written {
		if _, _, _, werr := fsutil.WriteAtomicCreateAt(j.dir, journalRecordName, data, journalRecordMode); werr != nil {
			return fmt.Errorf("subagent: cannot write the child agent journal: %w", werr)
		}
		j.written = true
		return nil
	}
	if _, _, _, werr := fsutil.WriteAtomicReplaceAt(j.dir, journalRecordName, data, journalRecordMode, nil, nil); werr != nil {
		return fmt.Errorf("subagent: cannot update the child agent journal: %w", werr)
	}
	return nil
}

func (j *Journal) step(label string) error {
	if err := beforeJournalStep(label); err != nil {
		return err
	}
	return j.flush()
}

func (j *Journal) Covers(target string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	_, ok := j.index[target]
	return ok
}

func (j *Journal) MaxStateBytes() int64 { return maxStateBytesPerPath }

func (j *Journal) BeginMutation(target string, observed, next filetools.JournalState) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	pr := j.record(target)
	if pr == nil {
		return nil
	}
	if int64(len(next.Data)) > maxStateBytesPerPath {
		return fmt.Errorf("subagent: %s would hold %d bytes, over the %d-byte limit a child agent journal records for one path", target, len(next.Data), int64(maxStateBytesPerPath))
	}
	if !sameState(fromToolState(observed), pr.LastKnown) {
		return fmt.Errorf("subagent: %s changed outside the child agent since it was snapshotted", target)
	}
	pr.Pending = &pendingMutation{State: fromToolState(next), NeedsParentSync: true}
	if err := j.step("pending"); err != nil {
		pr.Pending = nil
		return err
	}
	return nil
}

func (j *Journal) BeginDelete(target string, parentDir *os.File) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	pr := j.record(target)
	if pr == nil {
		return nil
	}
	if !pr.Delete {
		return fmt.Errorf("subagent: %s is not a declared delete path, so its removal cannot be rolled back", target)
	}
	current, err := readEntryState(parentDir, filepath.Base(target))
	if err != nil {
		return fmt.Errorf("subagent: cannot read %s before deleting it: %w", target, err)
	}
	if !sameState(current, pr.LastKnown) {
		return fmt.Errorf("subagent: %s changed outside the child agent since it was snapshotted", target)
	}
	pr.Pending = &pendingMutation{NeedsParentSync: true}
	if err := j.step("pending"); err != nil {
		pr.Pending = nil
		return err
	}
	return nil
}

// ResolveMutation settles the pending record against what the publish actually left. published names
// the inode the caller put at the path, or is the zero value when it has none to name. A pending
// record is written before publication and so cannot name the inode it will create; adopting the
// caller's is what keeps a byte-identical file another writer put at the name in the publish-to-
// reconcile window from being read as this child's own work. Recovery, which arrives after a crash
// with no such identity to offer, still falls back to comparing content alone.
func (j *Journal) ResolveMutation(target string, parentDir *os.File, published filetools.JournalState) {
	j.mu.Lock()
	defer j.mu.Unlock()
	pr := j.record(target)
	if pr == nil || pr.Pending == nil {
		return
	}
	if published.Ino != 0 {
		pr.Pending.State.Dev, pr.Pending.State.Ino = published.Dev, published.Ino
	}
	j.reconcile(pr, parentDir)
}

// AbandonMutation resolves a pending record whose publication never happened. The pending state is
// then a state no one published, so a file holding it is another writer's — content equality cannot
// stand in for ownership here the way it can after a real publish, and absorbing it would let the
// rollback restore over, or remove, a file this child never wrote. Only the durable last-known state
// clears the record; anything else is reported rather than claimed.
func (j *Journal) AbandonMutation(target string, parentDir *os.File) {
	j.mu.Lock()
	defer j.mu.Unlock()
	pr := j.record(target)
	if pr == nil || pr.Pending == nil {
		return
	}
	// The pending state is dropped rather than compared against, and dropped first: no namespace
	// change was published, so there is none to make durable, and a record left pending would be
	// reconciled later by the terminal pass or by recovery — both of which read pending bytes as the
	// child's own work.
	pr.Pending = nil
	if err := j.step("reconciled"); err != nil {
		j.note(pr.Path + ": the resolved state could not be recorded: " + err.Error())
	}
	current, err := j.currentState(pr, parentDir)
	switch {
	case err != nil:
		j.markUnrecovered(pr, "the current state could not be read: "+err.Error())
	case !sameState(current, pr.LastKnown):
		j.markUnrecovered(pr, "it was changed outside the child agent's journalled writes while a refused write was outstanding")
	}
}

func (j *Journal) MoveLifecycle(source, destination string) fsutil.MoveLifecycle {
	pair := movePair{Source: source, Destination: destination}
	return fsutil.MoveLifecycle{
		BeforeRename: func(sourceParent, destinationParent *os.File) error {
			return j.beginMove(pair, sourceParent, destinationParent)
		},
		AfterRename: func(sourceParent, destinationParent *os.File) {
			j.resolveMove(pair, sourceParent, destinationParent)
		},
	}
}

// A rename keeps the inode, so the destination's pending state carries the source's identity.
func (j *Journal) beginMove(pair movePair, sourceParent, destinationParent *os.File) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !slices.Contains(j.rec.MovePairs, pair) {
		return fmt.Errorf("subagent: %s -> %s is not a declared move pair, so the move cannot be rolled back", pair.Source, pair.Destination)
	}
	src, dst := j.record(pair.Source), j.record(pair.Destination)
	if src.Pending != nil || dst.Pending != nil {
		return fmt.Errorf("subagent: %s -> %s has an earlier change to an endpoint that was never resolved", pair.Source, pair.Destination)
	}
	source, err := readEntryState(sourceParent, filepath.Base(pair.Source))
	if err != nil {
		return fmt.Errorf("subagent: cannot read %s before moving it: %w", pair.Source, err)
	}
	destination, err := readEntryState(destinationParent, filepath.Base(pair.Destination))
	if err != nil {
		return fmt.Errorf("subagent: cannot read %s before moving onto it: %w", pair.Destination, err)
	}
	if !sameState(source, src.LastKnown) || !sameState(destination, dst.LastKnown) {
		return fmt.Errorf("subagent: %s -> %s changed outside the child agent since it was snapshotted", pair.Source, pair.Destination)
	}
	src.Pending = &pendingMutation{NeedsParentSync: true}
	dst.Pending = &pendingMutation{State: source, NeedsParentSync: true}
	j.rec.Moves = append(j.rec.Moves, moveRecord{movePair: pair, State: movePending})
	if err := j.step("move_pending"); err != nil {
		src.Pending, dst.Pending = nil, nil
		j.rec.Moves = j.rec.Moves[:len(j.rec.Moves)-1]
		return err
	}
	return nil
}

func (j *Journal) resolveMove(pair movePair, sourceParent, destinationParent *os.File) {
	j.mu.Lock()
	defer j.mu.Unlock()
	i := slices.IndexFunc(j.rec.Moves, func(m moveRecord) bool { return m.movePair == pair && m.State == movePending })
	if i < 0 {
		return
	}
	j.reconcileMove(i, sourceParent, destinationParent)
}

// A pending move this cannot resolve is left pending without a note of its own: the rollback holds it
// and reports it as a move, which is the only report that does not promise a question about its paths.
func (j *Journal) reconcilePendingMove(i int) {
	m := j.rec.Moves[i]
	src, dst := j.record(m.Source), j.record(m.Destination)
	if src == nil || dst == nil {
		return
	}
	srcDir, err := j.openTargetParent(src)
	if err != nil {
		return
	}
	defer srcDir.Close() //nolint:errcheck // read-only directory descriptor
	dstDir, err := j.openTargetParent(dst)
	if err != nil {
		return
	}
	defer dstDir.Close() //nolint:errcheck // read-only directory descriptor
	j.reconcileMove(i, srcDir, dstDir)
}

// reconcileMove settles a pending move from both endpoints together: either endpoint read alone can
// match a move that never happened just as well as one whose other endpoint was changed from outside.
func (j *Journal) reconcileMove(i int, sourceParent, destinationParent *os.File) {
	m := j.rec.Moves[i]
	src, dst := j.record(m.Source), j.record(m.Destination)
	for _, end := range []struct {
		pr  *pathRecord
		dir *os.File
	}{{src, sourceParent}, {dst, destinationParent}} {
		if end.pr.Pending == nil || !end.pr.Pending.NeedsParentSync {
			continue
		}
		if err := syncTargetParent(end.dir); err != nil {
			reason := "the target's parent directory could not be made durable: " + err.Error()
			j.retainDurable(end.pr.Path + ": " + reason)
			j.markUnrecovered(end.pr, reason)
			return
		}
		end.pr.Pending.NeedsParentSync = false
	}
	source, serr := readEntryState(sourceParent, filepath.Base(m.Source))
	destination, derr := readEntryState(destinationParent, filepath.Base(m.Destination))
	if serr != nil || derr != nil {
		return
	}
	step := "move_completed"
	switch {
	case !destination.Exists && !dst.LastKnown.Exists && sameState(source, src.LastKnown):
		j.rec.Moves = slices.Delete(j.rec.Moves, i, i+1)
		step = "move_abandoned"
	case !source.Exists && destination.Exists && dst.Pending != nil && sameState(destination, dst.Pending.State):
		src.LastKnown, dst.LastKnown = source, destination
		j.rec.Moves[i].State = moveCompleted
	default:
		return
	}
	src.Pending, dst.Pending = nil, nil
	if err := j.step(step); err != nil {
		j.note(m.Source + " -> " + m.Destination + ": the resolved move could not be recorded: " + err.Error())
	}
}

func (j *Journal) RemovePublished(target string, parentDir *os.File, published filetools.JournalState) {
	j.mu.Lock()
	defer j.mu.Unlock()
	pr := j.record(target)
	if pr == nil {
		return
	}
	leaf := filepath.Base(target)
	dev, ino, err := entryIdentity(parentDir, leaf)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil || dev != published.Dev || ino != published.Ino || published.Ino == 0:
		j.markUnrecovered(pr, "another writer replaced the created file before it could be taken back")
		return
	default:
		if uErr := unix.Unlinkat(int(parentDir.Fd()), leaf, 0); uErr != nil {
			j.markUnrecovered(pr, "the created file could not be removed: "+uErr.Error())
			return
		}
	}
	j.reconcile(pr, parentDir)
}

// DirLifecycle records each segment against the path's snapshotted ancestor, which rollback descends
// from. EnsureDirAt names segments from ancestor, the directory the create started in, and that is
// deeper than the snapshotted one once an earlier act made or moved in a directory above the target.
func (j *Journal) DirLifecycle(target, ancestor string) fsutil.DirLifecycle {
	recordedRel := func(pr *pathRecord, rel string) (string, error) {
		r, err := filepath.Rel(pr.Ancestor, filepath.Join(ancestor, filepath.FromSlash(rel)))
		if err != nil || r == "." || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("subagent: %s is not beneath the snapshotted directory %s", rel, pr.Ancestor)
		}
		return filepath.ToSlash(r), nil
	}
	return fsutil.DirLifecycle{
		Intent: func(segPath string) error {
			j.mu.Lock()
			defer j.mu.Unlock()
			pr := j.record(target)
			if pr == nil {
				return nil
			}
			rel, err := recordedRel(pr, segPath)
			if err != nil {
				return err
			}
			for i := range pr.Dirs {
				if pr.Dirs[i].Rel == rel {
					return nil
				}
			}
			pr.Dirs = append(pr.Dirs, dirRecord{Rel: rel, Progress: rollbackUnresolved})
			if err := j.step("dir_intent"); err != nil {
				pr.Dirs = pr.Dirs[:len(pr.Dirs)-1]
				return err
			}
			return nil
		},
		Confirm: func(seg fsutil.DirSegment) error {
			j.mu.Lock()
			defer j.mu.Unlock()
			pr := j.record(target)
			if pr == nil {
				return nil
			}
			rel, err := recordedRel(pr, seg.Path)
			if err != nil {
				return err
			}
			for i := range pr.Dirs {
				if pr.Dirs[i].Rel != rel || pr.Dirs[i].Confirmed {
					continue
				}
				prior := pr.Dirs[i]
				pr.Dirs[i].Confirmed = true
				pr.Dirs[i].Created = seg.Created
				pr.Dirs[i].Dev, pr.Dirs[i].Ino = seg.Dev, seg.Ino
				if err := j.step("dir_confirm"); err != nil {
					pr.Dirs[i] = prior
					return err
				}
				return nil
			}
			return nil
		},
	}
}

func (j *Journal) record(target string) *pathRecord {
	i, ok := j.index[target]
	if !ok {
		return nil
	}
	return &j.rec.Paths[i]
}

// ReconcilePending resolves every outstanding pending mutation without a live publish in hand. It is
// the entry point recovery must run before it compares any unresolved path: only this comparison can
// tell a crash before publication from a crash after it. Each path's captured target parent is
// reopened and identity-verified before it is synced and read.
func (j *Journal) ReconcilePending() {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := len(j.rec.Moves) - 1; i >= 0; i-- {
		if j.rec.Moves[i].State == movePending {
			j.reconcilePendingMove(i)
		}
	}
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		if pr.Pending == nil || j.endpointOf(pr.Path, func(s moveState) bool { return s == movePending }) {
			continue
		}
		dir, err := j.openTargetParent(pr)
		if errors.Is(err, errSuffixAbsent) {
			if pr.LastKnown.Exists {
				j.markUnrecovered(pr, "the directories holding it are gone, so the write cannot be resolved")
				continue
			}
			pr.Pending = nil
			if fErr := j.step("reconciled"); fErr != nil {
				j.note(pr.Path + ": the resolved state could not be recorded: " + fErr.Error())
			}
			continue
		}
		if err != nil {
			j.markUnrecovered(pr, "the target's parent directory could not be safely reopened: "+err.Error())
			continue
		}
		j.reconcile(pr, dir)
		_ = dir.Close() //nolint:errcheck // read-only directory descriptor
	}
}

// reconcile is the one prior/pending/third-state contract, shared by live terminal handling and
// recovery. Visibility alone never settles a pending record: the target parent is fsynced first, so a
// publish or compensation that reported a parent-sync failure — or a crash between the helper's return
// and this record's rewrite — cannot leave the namespace less durable than the journal claims.
func (j *Journal) reconcile(pr *pathRecord, parentDir *os.File) {
	if pr.Pending == nil {
		return
	}
	if pr.Pending.NeedsParentSync {
		if err := syncTargetParent(parentDir); err != nil {
			reason := "the target's parent directory could not be made durable: " + err.Error()
			j.retainDurable(pr.Path + ": " + reason)
			j.markUnrecovered(pr, reason)
			return
		}
		pr.Pending.NeedsParentSync = false
	}
	current, err := j.currentState(pr, parentDir)
	if err != nil {
		j.markUnrecovered(pr, "the current state could not be read: "+err.Error())
		return
	}
	pending := pr.Pending.State
	switch {
	case sameState(current, pr.LastKnown):
		pr.Pending = nil
	case sameState(current, pending):
		pr.LastKnown = current
		pr.Pending = nil
	default:
		j.markUnrecovered(pr, "the file holds neither the state before the write nor the state the write was to publish")
		return
	}
	if err := j.step("reconciled"); err != nil {
		j.note(pr.Path + ": the resolved state could not be recorded: " + err.Error())
	}
}

func (j *Journal) currentState(pr *pathRecord, parentDir *os.File) (fileState, error) {
	if pr.anyKind() {
		return readEntryState(parentDir, filepath.Base(pr.Path))
	}
	return regularState(parentDir, filepath.Base(pr.Path))
}

func (j *Journal) markUnrecovered(pr *pathRecord, reason string) {
	j.note(pr.Path + ": " + reason)
	_ = j.flush() //nolint:errcheck // the in-memory outcome is already unrecovered; a failed flush cannot make it worse
}

func (j *Journal) note(msg string) {
	for _, existing := range j.rec.Unrecovered {
		if existing == msg {
			return
		}
	}
	j.rec.Unrecovered = append(j.rec.Unrecovered, msg)
}

func (j *Journal) retainDurable(msg string) {
	for _, existing := range j.rec.Retained {
		if existing == msg {
			return
		}
	}
	j.rec.Retained = append(j.rec.Retained, msg)
}

func (j *Journal) hasDurableFailure() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.rec.Retained) > 0
}

// retainedOutcome reports the transaction as unrecovered without re-deriving it from what the
// filesystem now holds.
func (j *Journal) retainedOutcome() JournalOutcome {
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = j.flush() //nolint:errcheck // the journal is retained either way
	return JournalOutcome{Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path}
}

// link records a nested delegate's journal on this one before that child runs, so a parent's stale
// last-known state can never be compared without first accounting for the descendant that owns the
// visible mutation.
func (j *Journal) link(child *Journal) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.rec.Children = append(j.rec.Children, childLink{Dir: child.dirName, Depth: child.rec.Depth})
	if err := j.step("link_child"); err != nil {
		j.rec.Children = j.rec.Children[:len(j.rec.Children)-1]
		return err
	}
	return nil
}

// MarkTransferReady hands a completed nested child's journal to its parent. The child never deletes
// its own journal on completion: until the parent has durably absorbed it, it is the only record of
// which writes belong to the child rather than to an outside writer.
func (j *Journal) MarkTransferReady() error {
	j.mu.Lock()
	j.rec.Lifecycle = lifecycleTransferReady
	err := j.step("transfer_ready")
	j.mu.Unlock()
	if err != nil {
		return err
	}
	if j.parent == nil {
		return nil
	}
	return j.parent.setChildTransferReady(j.dirName)
}

func (j *Journal) setChildTransferReady(dir string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.rec.Children {
		if j.rec.Children[i].Dir == dir {
			j.rec.Children[i].TransferReady = true
			return j.step("child_transfer_ready")
		}
	}
	return nil
}

// Absorb folds a transfer-ready descendant's state into this journal and then deletes it. The parent
// takes over the child's last-known states and created directories so its own comparison reads the
// grandchild's writes as child-owned rather than as an external edit.
func (j *Journal) Absorb(child *Journal) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.absorbLocked(child)
}

func (j *Journal) absorbLocked(child *Journal) error {
	if child.gone {
		j.dropChild(child)
		return j.step("child_absorbed")
	}
	child.mu.Lock()
	for i := range child.rec.Paths {
		cp := &child.rec.Paths[i]
		pp := j.record(cp.Path)
		if pp == nil {
			continue
		}
		pp.LastKnown = cp.LastKnown
		pp.Pending = cp.Pending
		pp.Dirs = append(pp.Dirs, cp.Dirs...)
	}
	j.rec.Moves = append(j.rec.Moves, child.rec.Moves...)
	for _, note := range child.rec.Unrecovered {
		j.note(note)
	}
	child.mu.Unlock()

	for i := range j.rec.Children {
		if j.rec.Children[i].Dir == child.dirName {
			j.rec.Children[i].Absorbed = true
		}
	}
	if err := j.step("child_absorbed"); err != nil {
		return err
	}
	if err := child.remove(); err != nil {
		return err
	}
	j.dropChild(child)
	return j.step("child_dropped")
}

func (j *Journal) dropChild(child *Journal) {
	kept := j.rec.Children[:0]
	for _, link := range j.rec.Children {
		if link.Dir != child.dirName {
			kept = append(kept, link)
		}
	}
	j.rec.Children = kept
	live := j.children[:0]
	for _, c := range j.children {
		if c != child {
			live = append(live, c)
		}
	}
	j.children = live
}

// Finish resolves the transaction. A completed child's work stands only when every unresolved
// declared path still matches the durable last-known child state; every other terminal reason puts
// the declared scope back as the child found it. A path that matches neither is a third outcome: it
// is left alone and the journal survives naming it.
func (j *Journal) Finish(reason Reason) JournalOutcome {
	j.resetNotes()
	j.mu.Lock()
	committed := j.rec.Lifecycle == lifecycleCommitted
	j.mu.Unlock()
	// A durable committed marker outranks the terminal reason: the child's work already stood, so a
	// survivor is cleanup and never a restore.
	if committed {
		return j.cleanUpCommitted()
	}
	j.absorbTransferReady()
	j.ReconcilePending()
	if reason != ReasonCompleted {
		return j.rollback()
	}
	if j.hasDurableFailure() {
		return j.retainedOutcome()
	}
	if j.parent == nil {
		return j.commit()
	}
	if err := j.MarkTransferReady(); err != nil {
		return j.retain("the completed nested journal could not be handed to its parent: " + err.Error())
	}
	if err := j.parent.Absorb(j); err != nil {
		j.parent.retain("a nested child agent's journal could not be absorbed: " + err.Error())
		return j.retain("its parent could not absorb it: " + err.Error())
	}
	return JournalOutcome{}
}

// resetNotes clears what a terminal pass re-derives from the current state, so notes left by an
// attempt that was interrupted cannot outlive the condition that produced them. A retained durability
// failure is re-noted: it cannot be re-derived, and a later successful sync would otherwise turn the
// transaction into a clean outcome.
func (j *Journal) resetNotes() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.rec.Unrecovered = nil
	for _, msg := range j.rec.Retained {
		j.note(msg)
	}
}

func (j *Journal) retain(reason string) JournalOutcome {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.note(reason)
	_ = j.flush() //nolint:errcheck // the journal is retained either way
	return JournalOutcome{Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path}
}

// absorbTransferReady processes still-linked descendants deepest-first, so a grandchild's journal is
// folded into its own parent before that parent is folded into this one.
func (j *Journal) absorbTransferReady() {
	j.mu.Lock()
	children := append([]*Journal(nil), j.children...)
	j.mu.Unlock()
	sort.SliceStable(children, func(a, b int) bool { return children[a].rec.Depth > children[b].rec.Depth })
	for _, child := range children {
		child.absorbTransferReady()
		if !child.transferReady() {
			continue
		}
		j.mu.Lock()
		err := j.absorbLocked(child)
		j.mu.Unlock()
		if err != nil {
			j.mu.Lock()
			j.note(child.path + ": the nested child agent's journal could not be absorbed: " + err.Error())
			_ = j.flush() //nolint:errcheck // the outcome is already unrecovered
			j.mu.Unlock()
		}
	}
}

func (j *Journal) transferReady() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.rec.Lifecycle == lifecycleTransferReady
}

func (j *Journal) commit() JournalOutcome {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		for _, dir := range pr.Dirs {
			if !dir.Confirmed {
				j.note(pr.Path + ": a parent directory the child agent started to create was never confirmed")
			}
		}
		if pr.Pending != nil {
			j.note(pr.Path + ": a write the child agent started was never resolved")
			continue
		}
		var current fileState
		var cerr error
		dir, err := j.openTargetParent(pr)
		switch {
		case errors.Is(err, errSuffixAbsent):
		case err != nil:
			j.note(pr.Path + ": the target's parent directory could not be safely reopened: " + err.Error())
			continue
		default:
			current, cerr = j.currentState(pr, dir)
			_ = dir.Close() //nolint:errcheck // read-only directory descriptor
		}
		switch {
		case cerr != nil:
			j.note(pr.Path + ": the current state could not be read: " + cerr.Error())
		case !sameState(current, pr.LastKnown):
			j.note(pr.Path + ": it was changed outside the child agent's journalled writes")
		}
	}
	if len(j.rec.Unrecovered) > 0 {
		_ = j.flush() //nolint:errcheck // the journal is retained either way; a failed flush is reported by its survival
		return JournalOutcome{Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path}
	}
	j.rec.Lifecycle = lifecycleCommitted
	if err := j.step("committed"); err != nil {
		j.note("the committed state could not be recorded: " + err.Error())
		return JournalOutcome{Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path}
	}
	return j.removeCommitted()
}

func (j *Journal) cleanUpCommitted() JournalOutcome {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.removeCommitted()
}

func (j *Journal) removeCommitted() JournalOutcome {
	if err := j.remove(); err != nil {
		j.note("the committed journal could not be removed: " + err.Error())
		_ = j.flush() //nolint:errcheck // the journal survives either way; its survival is the report
		return JournalOutcome{Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path}
	}
	return JournalOutcome{}
}

func (j *Journal) rollback() JournalOutcome {
	j.mu.Lock()
	defer j.mu.Unlock()
	// A path declared beneath a moved entry is reachable only where the move left it, so what the child
	// changed there, and the directories it made there, are put back before the undo carries that entry
	// home. An untouched path still holds what the move carried in and settles once the move is undone.
	inside := j.insideMovedEntries()
	early := make(map[string]bool, len(inside))
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		early[pr.Path] = inside[pr.Path] && (pr.Pending != nil || !sameState(pr.LastKnown, pr.Pre))
	}
	restored := j.restorePaths(nil, func(path string) bool { return early[path] })
	j.removeCreatedDirs(func(path string) bool { return inside[path] })
	undone, held, heldMoves := j.undoMoves(func(destination string) bool {
		return slices.ContainsFunc(j.rec.Paths, func(pr pathRecord) bool {
			return early[pr.Path] && pr.Progress != rollbackRestored && strings.HasPrefix(pr.Path, destination+string(filepath.Separator))
		})
	})
	for _, path := range undone {
		if !slices.Contains(restored, path) {
			restored = append(restored, path)
		}
	}
	// Paths are recorded sorted, so a deleted directory is recreated before anything declared beneath it.
	restored = j.restorePaths(restored, func(path string) bool { return !early[path] && !held[path] })
	j.removeCreatedDirs(func(path string) bool { return !inside[path] })
	if len(j.rec.Unrecovered) > 0 {
		_ = j.flush() //nolint:errcheck // the journal is retained either way
		return JournalOutcome{Restored: restored, Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path, HeldMoves: heldMoves}
	}
	if err := j.remove(); err != nil {
		j.note("the rolled-back journal could not be removed: " + err.Error())
		return JournalOutcome{Restored: restored, Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path}
	}
	return JournalOutcome{Restored: restored}
}

// undoMoves puts every moved entry back whole, newest move first, before any endpoint is restored by
// kind, which would recreate a moved directory empty and strand its contents. Linked moves are undone
// or held together, and a group is held before its first act unless its whole undo can be simulated.
func (j *Journal) undoMoves(unrestoredBeneath func(destination string) bool) (restored []string, held map[string]bool, heldMoves []HeldMove) {
	held = make(map[string]bool)
	groups := j.moveGroups()
	slices.SortFunc(groups, func(a, b []int) int { return b[len(b)-1] - a[len(a)-1] })
	for _, group := range groups {
		members := slices.DeleteFunc(slices.Clone(group), func(i int) bool { return j.rec.Moves[i].State == moveUndone })
		if len(members) == 0 {
			continue
		}
		failed, err := -1, error(nil)
		if k := slices.IndexFunc(members, func(i int) bool { return unrestoredBeneath(j.rec.Moves[i].Destination) }); k >= 0 {
			failed, err = members[k], errors.New("a path the child agent changed inside the moved entry could not be put back first")
		} else {
			failed, err = j.preflightUndo(members)
		}
		for k := len(members) - 1; err == nil && k >= 0; k-- {
			m := &j.rec.Moves[members[k]]
			var changed bool
			if changed, err = j.undoMove(m); err != nil {
				failed = members[k]
				continue
			}
			for _, path := range []string{m.Source, m.Destination} {
				if changed && !slices.Contains(restored, path) {
					restored = append(restored, path)
				}
			}
		}
		if err == nil {
			continue
		}
		resumes := undoBegun(j.rec.Moves, group)
		for _, i := range members {
			m := j.rec.Moves[i]
			if m.State == moveUndone {
				continue
			}
			h := HeldMove{Source: m.Source, Destination: m.Destination, Reason: "a linked move could not be undone, so this one was left in place", Resumes: resumes}
			if i == failed {
				h.Reason = err.Error()
			}
			j.note(h.note())
			heldMoves = append(heldMoves, h)
			held[m.Source], held[m.Destination] = true, true
		}
	}
	return restored, held, heldMoves
}

func undoBegun(moves []moveRecord, group []int) bool {
	var undone, open bool
	for _, i := range group {
		switch moves[i].State {
		case moveUndoing:
			return true
		case moveUndone:
			undone = true
		default:
			open = true
		}
	}
	return undone && open
}

func (j *Journal) moveGroups() [][]int {
	root := make([]int, len(j.rec.Moves))
	for i := range root {
		root[i] = i
	}
	find := func(i int) int {
		for root[i] != i {
			i = root[i]
		}
		return i
	}
	for i := range j.rec.Moves {
		for k := i + 1; k < len(j.rec.Moves); k++ {
			if movesLinked(j.rec.Moves[i].movePair, j.rec.Moves[k].movePair) {
				root[find(k)] = find(i)
			}
		}
	}
	var groups [][]int
	slot := make(map[int]int)
	for i := range j.rec.Moves {
		r := find(i)
		g, ok := slot[r]
		if !ok {
			g = len(groups)
			slot[r] = g
			groups = append(groups, nil)
		}
		groups[g] = append(groups[g], i)
	}
	return groups
}

func movesLinked(a, b movePair) bool {
	for _, p := range []string{a.Source, a.Destination} {
		for _, q := range []string{b.Source, b.Destination} {
			if permissions.IsDescendantOrEqual(p, q) || permissions.IsDescendantOrEqual(q, p) {
				return true
			}
		}
	}
	return false
}

func (j *Journal) endpointOf(path string, include func(moveState) bool) bool {
	return slices.ContainsFunc(j.rec.Moves, func(m moveRecord) bool {
		return include(m.State) && (m.Source == path || m.Destination == path)
	})
}

type moveUndoAct int

const (
	undoRename moveUndoAct = iota
	undoRenamed
	undoSettle
	undoSkip
)

// planMoveUndo must stay the only undo decision: preflight passes it projected states, so an undo that
// decided on its own could start an act its group's preflight never checked.
func planMoveUndo(m *moveRecord, src, dst *pathRecord, srcLast, dstLast, source, destination fileState) (act moveUndoAct, clear bool, err error) {
	undoing := m.State == moveUndoing
	switch {
	case undoing && dstLast.Exists && !destination.Exists && sameState(source, dstLast):
		return undoRenamed, false, nil
	case sameState(source, src.Pre) && sameState(destination, dst.Pre):
		return undoSettle, false, nil
	case !dstLast.Exists && !destination.Exists && sameState(source, srcLast):
		// A later journalled delete of the destination already took the moved entry, so there is nothing to
		// rename back and the source is left to its snapshot restore.
		return undoSkip, false, nil
	case destination.Exists && sameState(destination, dstLast):
		if !source.Exists && (undoing || !srcLast.Exists) {
			return undoRename, false, nil
		}
		if source.Exists && srcLast.Ino != 0 && sameState(source, srcLast) {
			return undoRename, true, nil
		}
	}
	return undoRename, false, errors.New("an endpoint was changed outside the child agent's journalled writes, so the move cannot be undone")
}

func (j *Journal) moveEndpoints(m *moveRecord) (src, dst *pathRecord, err error) {
	if m.State == movePending {
		return nil, nil, errors.New("a move the child agent started was never resolved")
	}
	src, dst = j.record(m.Source), j.record(m.Destination)
	if src == nil || dst == nil {
		return nil, nil, errors.New("the move names a path this journal does not hold")
	}
	return src, dst, nil
}

type projectedEntry struct {
	state fileState
	pr    *pathRecord
	at    string
}

// preflightUndo runs a group's undo newest move first without touching an endpoint. Each simulated
// rename is carried into the older moves' checks: the endpoints it would swap take their projected
// states, and a path beneath the entry it would carry home is read where that entry still is.
func (j *Journal) preflightUndo(members []int) (failed int, err error) {
	entries := make(map[string]projectedEntry)
	last := make(map[string]fileState)
	var renames []movePair
	read := func(pr *pathRecord) (projectedEntry, error) {
		if e, ok := entries[pr.Path]; ok {
			return e, nil
		}
		at := relocate(pr.Ancestor, renames)
		dir, err := j.openTargetParentAt(pr, at)
		if err != nil {
			return projectedEntry{}, errors.New("the parent directory of " + pr.Path + " could not be safely reopened: " + err.Error())
		}
		defer dir.Close() //nolint:errcheck // read-only directory descriptor
		state, err := readEntryState(dir, filepath.Base(pr.Path))
		if err != nil {
			return projectedEntry{}, errors.New("the endpoints could not be read: " + err.Error())
		}
		return projectedEntry{state: state, pr: pr, at: at}, nil
	}
	lastKnown := func(pr *pathRecord) fileState {
		if state, ok := last[pr.Path]; ok {
			return state
		}
		return pr.LastKnown
	}
	for k := len(members) - 1; k >= 0; k-- {
		m := &j.rec.Moves[members[k]]
		src, dst, err := j.moveEndpoints(m)
		if err != nil {
			return members[k], err
		}
		source, err := read(src)
		if err != nil {
			return members[k], err
		}
		destination, err := read(dst)
		if err != nil {
			return members[k], err
		}
		srcLast, dstLast := lastKnown(src), lastKnown(dst)
		act, clear, err := planMoveUndo(m, src, dst, srcLast, dstLast, source.state, destination.state)
		if err != nil {
			return members[k], err
		}
		switch act {
		case undoSettle:
			last[src.Path], last[dst.Path] = source.state, destination.state
		case undoRenamed:
			last[src.Path], last[dst.Path] = dstLast, fileState{}
		case undoRename:
			if clear && source.state.Kind == kindDir {
				if err := j.clearableDir(source); err != nil {
					return members[k], err
				}
			}
			entries[src.Path], entries[dst.Path] = destination, projectedEntry{}
			last[src.Path], last[dst.Path] = dstLast, fileState{}
			renames = append([]movePair{m.movePair}, renames...)
		}
	}
	return -1, nil
}

func (j *Journal) clearableDir(e projectedEntry) error {
	dir, err := j.openTargetParentAt(e.pr, e.at)
	if err != nil {
		return errors.New("the source's parent directory could not be safely reopened: " + err.Error())
	}
	defer dir.Close() //nolint:errcheck // read-only directory descriptor
	empty, err := dirIsEmpty(dir, filepath.Base(e.pr.Path))
	switch {
	case err != nil:
		return errors.New("the directory the child agent left at the source could not be read: " + err.Error())
	case !empty:
		return errors.New("the directory the child agent left at the source now holds entries, so it cannot be removed to undo the move")
	}
	return nil
}

// relocate maps a path named before renames happened to where it is now, applying them oldest first.
func relocate(path string, renames []movePair) string {
	for _, r := range renames {
		if permissions.IsDescendantOrEqual(path, r.Source) {
			path = r.Destination + strings.TrimPrefix(path, r.Source)
		}
	}
	return path
}

func (j *Journal) undoMove(m *moveRecord) (changed bool, err error) {
	src, dst, err := j.moveEndpoints(m)
	if err != nil {
		return false, err
	}
	srcDir, err := j.openTargetParent(src)
	if err != nil {
		return false, errors.New("the source's parent directory could not be safely reopened: " + err.Error())
	}
	defer srcDir.Close() //nolint:errcheck // read-only directory descriptor
	dstDir, err := j.openTargetParent(dst)
	if err != nil {
		return false, errors.New("the destination's parent directory could not be safely reopened: " + err.Error())
	}
	defer dstDir.Close() //nolint:errcheck // read-only directory descriptor

	source, serr := readEntryState(srcDir, filepath.Base(m.Source))
	destination, derr := readEntryState(dstDir, filepath.Base(m.Destination))
	if err := errors.Join(serr, derr); err != nil {
		return false, errors.New("the endpoints could not be read: " + err.Error())
	}
	act, clear, err := planMoveUndo(m, src, dst, src.LastKnown, dst.LastKnown, source, destination)
	if err != nil {
		return false, err
	}
	priorState, priorSrc, priorDst := m.State, src.LastKnown, dst.LastKnown
	if act == undoSettle || act == undoSkip {
		if act == undoSettle {
			src.LastKnown, dst.LastKnown = source, destination
		}
		m.State = moveUndone
		if err := j.step("move_undone"); err != nil {
			m.State, src.LastKnown, dst.LastKnown = priorState, priorSrc, priorDst
			return false, errors.New("the undone move could not be recorded: " + err.Error())
		}
		return act == undoSkip, nil
	}
	if act == undoRename {
		if m.State != moveUndoing {
			m.State = moveUndoing
			if err := j.step("move_undoing"); err != nil {
				return false, errors.New("the undo could not be recorded before it began: " + err.Error())
			}
		}
		if clear {
			if err := removeEntry(srcDir, filepath.Base(m.Source), src.LastKnown); err != nil {
				return false, err
			}
			if parentMoved(srcDir, func() (*os.File, error) { return j.openTargetParent(src) }) {
				return false, errParentMoved
			}
		}
		// An absent source the child last left in place was cleared by an earlier pass that may have
		// stopped before its unlink became durable.
		if clear || (!source.Exists && src.LastKnown.Exists) {
			if err := syncTargetParent(srcDir); err != nil {
				return false, errors.New("the cleared source could not be made durable: " + err.Error())
			}
		}
		if err := fsutil.RenameNoReplaceAt(dstDir, filepath.Base(m.Destination), srcDir, filepath.Base(m.Source)); err != nil {
			return false, errors.New("the moved entry could not be put back: " + err.Error())
		}
		if parentMoved(srcDir, func() (*os.File, error) { return j.openTargetParent(src) }) || parentMoved(dstDir, func() (*os.File, error) { return j.openTargetParent(dst) }) {
			if err := fsutil.RenameNoReplaceAt(srcDir, filepath.Base(m.Source), dstDir, filepath.Base(m.Destination)); err != nil {
				return false, errors.New(errParentMoved.Error() + ", and the undo could not be reversed: " + err.Error())
			}
			return false, errParentMoved
		}
	}
	if err := syncTargetParent(dstDir); err != nil {
		return false, errors.New("the undone move could not be made durable: " + err.Error())
	}
	if err := syncTargetParent(srcDir); err != nil {
		return false, errors.New("the undone move could not be made durable: " + err.Error())
	}
	src.LastKnown, dst.LastKnown = dst.LastKnown, fileState{}
	m.State = moveUndone
	if err := j.step("move_undone"); err != nil {
		m.State, src.LastKnown, dst.LastKnown = moveUndoing, priorSrc, priorDst
		return false, errors.New("the undone move could not be recorded: " + err.Error())
	}
	return true, nil
}

// restorePath puts one declared path back as its captured kind. The three-state progress is written
// around the filesystem act, not after it, so a crash on either side of the act resumes: a resumed
// restore accepts either the state the child left or the captured pre-state as a valid starting point.
func (j *Journal) restorePath(pr *pathRecord) (changed bool, err error) {
	dir, err := j.openTargetParent(pr)
	if err != nil {
		if errors.Is(err, errSuffixAbsent) {
			if pr.Pre.Exists || pr.LastKnown.Exists {
				return false, errors.New("the directories holding it are gone, so it cannot be put back")
			}
			pr.Progress = rollbackRestored
			return false, j.step("restored")
		}
		return false, errors.New("the target's parent directory could not be safely reopened: " + err.Error())
	}
	defer dir.Close() //nolint:errcheck // read-only directory descriptor

	current, cerr := j.currentState(pr, dir)
	if cerr != nil {
		return false, errors.New("the current state could not be read: " + cerr.Error())
	}
	// A restore publishes a new inode, so a resumed pass accepts the pre-run state only under the identity
	// an earlier pass durably recorded publishing; a same-content entry under any other identity is a
	// third party's, and an act whose identity never became durable cannot be told apart from one.
	resumed := pr.Progress == rollbackRestoring
	published := resumed && pr.ReplacementIno != 0 && current.Dev == pr.ReplacementDev && current.Ino == pr.ReplacementIno
	if sameContent(current, pr.Pre) && (published || sameState(current, pr.LastKnown) || resumed && !current.Exists) {
		// Reaching the pre-run state from `restoring` means an earlier pass performed the act but
		// never proved its directory entry durable, so the fsync that pass owed is retried here. The
		// bytes alone cannot stand in for it: a namespace change the filesystem can still lose would
		// otherwise be recorded as finished.
		if resumed {
			if sErr := syncTargetParent(dir); sErr != nil {
				return false, errors.New("the restored directory entry could not be made durable: " + sErr.Error())
			}
		}
		pr.Progress = rollbackRestored
		return false, j.step("restored")
	}
	// A delete-declared path whose entry kind changed is put back by removing the entry and then
	// recreating the pre-state, so a pass interrupted between the two acts leaves the slot empty.
	resumedEmpty := pr.anyKind() && resumed && !current.Exists
	if !resumedEmpty && !sameState(current, pr.LastKnown) {
		return false, errors.New("it was changed outside the child agent's journalled writes")
	}

	pr.Progress = rollbackRestoring
	if err := j.step("restoring"); err != nil {
		return false, errors.New("the rollback could not be recorded before it began: " + err.Error())
	}
	if err := j.putBack(pr, dir, current); err != nil {
		return false, err
	}
	if parentMoved(dir, func() (*os.File, error) { return j.openTargetParent(pr) }) {
		return false, errParentMoved
	}
	// The namespace change has to be durable before the record says so, or a resumed rollback would
	// read a restore that the filesystem can still lose as finished.
	if sErr := syncTargetParent(dir); sErr != nil {
		return false, errors.New("the restored directory entry could not be made durable: " + sErr.Error())
	}
	pr.Progress = rollbackRestored
	if err := j.step("restored"); err != nil {
		return true, errors.New("the completed rollback could not be recorded: " + err.Error())
	}
	return true, nil
}

func (j *Journal) putBack(pr *pathRecord, dir *os.File, current fileState) error {
	leaf := filepath.Base(pr.Path)
	if pr.Pre.Exists && pr.Pre.Kind == "" && current.Exists && current.Kind == "" {
		planned, sErr := statEntry(dir, leaf)
		if sErr != nil {
			return errors.New("the file to restore could not be identified: " + sErr.Error())
		}
		_, _, published, wErr := fsutil.WriteAtomicReplaceAt(dir, leaf, pr.Pre.Data, pr.Pre.Mode, planned, nil)
		if published == nil {
			return errors.New("the original contents could not be put back: " + wErr.Error())
		}
		return j.recordPublished(pr, published)
	}
	if current.Exists {
		if err := removeEntry(dir, leaf, current); err != nil {
			return err
		}
	}
	if !pr.Pre.Exists {
		return nil
	}
	switch pr.Pre.Kind {
	case kindSymlink:
		if err := unix.Symlinkat(pr.Pre.Link, int(dir.Fd()), leaf); err != nil {
			return errors.New("the original symlink could not be put back: " + err.Error())
		}
		made, err := readEntryState(dir, leaf)
		if err != nil {
			return errors.New("the restored symlink could not be identified: " + err.Error())
		}
		if !sameContent(made, pr.Pre) {
			return errors.New("another writer replaced the restored symlink before it could be recorded")
		}
		return j.recordRestored(pr, made.Dev, made.Ino)
	case kindDir:
		return j.recreateDir(pr, dir, leaf)
	default:
		// A create whose own parent sync failed may already have unlinked what it published, so only a
		// clean return names an entry this journal can claim.
		_, _, published, wErr := fsutil.WriteAtomicCreateAt(dir, leaf, pr.Pre.Data, pr.Pre.Mode)
		if wErr != nil {
			return errors.New("the original contents could not be put back: " + wErr.Error())
		}
		return j.recordPublished(pr, published)
	}
}

func (j *Journal) recordPublished(pr *pathRecord, published os.FileInfo) error {
	st, ok := published.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("the restored file could not be identified")
	}
	return j.recordRestored(pr, uint64(st.Dev), uint64(st.Ino))
}

func (j *Journal) recordRestored(pr *pathRecord, dev, ino uint64) error {
	pr.ReplacementDev, pr.ReplacementIno = dev, ino
	if err := j.step("restore_published"); err != nil {
		pr.ReplacementDev, pr.ReplacementIno = 0, 0
		return errors.New("the restored entry could not be recorded: " + err.Error())
	}
	return nil
}

func removeEntry(dir *os.File, leaf string, current fileState) error {
	dev, ino, iErr := entryIdentity(dir, leaf)
	switch {
	case errors.Is(iErr, fs.ErrNotExist):
		return nil
	case iErr != nil:
		return errors.New("the created file could not be identified: " + iErr.Error())
	case dev != current.Dev || ino != current.Ino:
		return errors.New("another writer replaced the created file before it could be removed")
	}
	flag := 0
	if current.Kind == kindDir {
		flag = unix.AT_REMOVEDIR
	}
	if uErr := unix.Unlinkat(int(dir.Fd()), leaf, flag); uErr != nil {
		return errors.New("the created file could not be removed: " + uErr.Error())
	}
	return nil
}

// afterRecreateMkdir is the test seam for the window between creating a directory and opening it.
var afterRecreateMkdir = func() {}

// recreateDir records the replacement's identity durably before returning, because the paths declared
// beneath it are reopened only through the directory that identity names.
func (j *Journal) recreateDir(pr *pathRecord, dir *os.File, leaf string) error {
	mode := uint32(pr.Pre.Mode.Perm())
	if err := unix.Mkdirat(int(dir.Fd()), leaf, mode); err != nil {
		return errors.New("the original directory could not be put back: " + err.Error())
	}
	afterRecreateMkdir()
	made, err := openSubdirNoFollow(dir, leaf)
	if err != nil {
		return errors.New("the recreated directory could not be opened: " + err.Error())
	}
	defer made.Close() //nolint:errcheck // read-only directory descriptor
	if err := checkFreshlyMade(made, mode); err != nil {
		return errors.New("the opened directory is not the one the rollback recreated: " + err.Error())
	}
	if err := unix.Fchmod(int(made.Fd()), mode); err != nil {
		return errors.New("the recreated directory's mode could not be applied: " + err.Error())
	}
	if err := syncTargetParent(made); err != nil {
		return errors.New("the recreated directory could not be made durable: " + err.Error())
	}
	if pr.ReplacementDev, pr.ReplacementIno, err = descriptorIdentity(made); err != nil {
		return errors.New("the recreated directory could not be identified: " + err.Error())
	}
	if err := j.step("dir_recreated"); err != nil {
		pr.ReplacementDev, pr.ReplacementIno = 0, 0
		return errors.New("the recreated directory could not be recorded: " + err.Error())
	}
	return nil
}

// checkFreshlyMade stands in for the identity mkdir cannot return: a directory swapped in before the open
// is refused unless it is indistinguishable from one just made — empty, owned by this process, and
// granting nothing beyond the requested mode (the umask or a default ACL may grant less).
func checkFreshlyMade(made *os.File, mode uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(made.Fd()), &st); err != nil {
		return &os.PathError{Op: "fstat", Path: made.Name(), Err: err}
	}
	if int(st.Uid) != os.Geteuid() {
		return errors.New("it is owned by another user")
	}
	if uint32(st.Mode)&0o777&^mode != 0 {
		return errors.New("it grants permissions the original did not")
	}
	names, err := made.Readdirnames(1)
	if len(names) > 0 {
		return errors.New("it already holds entries")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

var errSuffixAbsent = errors.New("subagent: a directory on the way to the declared path is absent")

// openTargetParent reopens the directory the declared path lives in, starting from the captured
// deepest existing ancestor and verifying its identity before descending. Only directories this child
// confirmed creating are walked through: a component that appeared from somewhere else is refused
// rather than treated as part of the child's own chain.
func (j *Journal) openTargetParent(pr *pathRecord) (*os.File, error) {
	return j.openTargetParentAt(pr, pr.Ancestor)
}

func (j *Journal) openTargetParentAt(pr *pathRecord, location string) (*os.File, error) {
	dir, err := j.openAncestorAt(pr, location)
	if err != nil {
		return nil, err
	}
	for i, seg := range pr.Suffix[:len(pr.Suffix)-1] {
		rel := strings.Join(pr.Suffix[:i+1], "/")
		next, oErr := openSubdirNoFollow(dir, seg)
		if oErr != nil {
			_ = dir.Close() //nolint:errcheck // read-only directory descriptor
			if errors.Is(oErr, fs.ErrNotExist) {
				return nil, errSuffixAbsent
			}
			return nil, oErr
		}
		nDev, nIno, iErr := descriptorIdentity(next)
		_ = dir.Close() //nolint:errcheck // read-only directory descriptor
		if iErr != nil || (!j.confirmedDir(nDev, nIno) && !j.movedInAt(filepath.Join(pr.Ancestor, rel), nDev, nIno)) {
			_ = next.Close() //nolint:errcheck // read-only directory descriptor
			return nil, fmt.Errorf("subagent: %s is not the directory the child agent created", rel)
		}
		dir = next
	}
	return dir, nil
}

// movedInAt reports whether dev/ino is the directory a completed, not yet undone, move put at path, so a
// path declared beneath a moved directory can be restored through it before the move is undone.
func (j *Journal) movedInAt(path string, dev, ino uint64) bool {
	for _, m := range j.rec.Moves {
		if m.State != moveCompleted || m.Destination != path {
			continue
		}
		if dst := j.record(path); dst != nil && dst.LastKnown.Kind == kindDir && dst.LastKnown.Dev == dev && dst.LastKnown.Ino == ino {
			return true
		}
	}
	return false
}

// confirmedDir finds the record of a directory this child confirmed on the way to any of its declared
// paths, by the identity that confirmation captured. A confirmation is recorded against the one
// declared path whose create materialized the directory, but declared siblings share ancestors: the
// directory made for made/a.txt is the same directory made/b.txt must be traversed through, so an
// untouched sibling has no record of its own to match. Identity is what the check is really after —
// a component that appeared from somewhere else still matches no confirmation.
func (j *Journal) confirmedDir(dev, ino uint64) bool {
	for i := range j.rec.Paths {
		dirs := j.rec.Paths[i].Dirs
		for k := range dirs {
			if dirs[k].Confirmed && dirs[k].Dev == dev && dirs[k].Ino == ino {
				return true
			}
		}
	}
	return false
}

func (j *Journal) restorePaths(restored []string, include func(path string) bool) []string {
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		if pr.Progress == rollbackRestored || pr.KeptByUser || !include(pr.Path) {
			continue
		}
		changed, err := j.restorePath(pr)
		if err != nil {
			j.note(pr.Path + ": " + err.Error())
			continue
		}
		if changed && !slices.Contains(restored, pr.Path) {
			restored = append(restored, pr.Path)
		}
	}
	return restored
}

// insideMovedEntries names the declared paths beneath the destination of a move not yet undone. Move
// endpoints are left out: a moved entry goes back whole through its own undo.
func (j *Journal) insideMovedEntries() map[string]bool {
	inside := make(map[string]bool)
	for i := range j.rec.Paths {
		path := j.rec.Paths[i].Path
		endpoint, beneath := false, false
		for _, m := range j.rec.Moves {
			endpoint = endpoint || path == m.Source || path == m.Destination
			beneath = beneath || (m.State != moveUndone && strings.HasPrefix(path, m.Destination+string(filepath.Separator)))
		}
		if beneath && !endpoint {
			inside[path] = true
		}
	}
	return inside
}

// removeCreatedDirs unlinks the directories the child materialized, deepest first, each only while it
// still holds the recorded inode and only while it is empty. A directory holding anything else is
// left in place: its contents are not this transaction's to delete.
func (j *Journal) removeCreatedDirs(include func(path string) bool) {
	type candidate struct {
		pr  *pathRecord
		dir *dirRecord
	}
	var all []candidate
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		if !include(pr.Path) {
			continue
		}
		for k := range pr.Dirs {
			all = append(all, candidate{pr: pr, dir: &pr.Dirs[k]})
		}
	}
	sort.SliceStable(all, func(a, b int) bool {
		return strings.Count(all[a].dir.Rel, "/") > strings.Count(all[b].dir.Rel, "/")
	})
	for _, c := range all {
		if c.dir.Progress == rollbackRestored {
			continue
		}
		if !c.dir.Confirmed {
			j.note(c.pr.Path + ": a parent directory the child agent started to create was never confirmed, so it was left in place")
			continue
		}
		if !c.dir.Created {
			c.dir.Progress = rollbackRestored
			continue
		}
		if err := j.removeCreatedDir(c.pr, c.dir); err != nil {
			j.note(c.pr.Path + ": " + err.Error())
		}
	}
	_ = j.flush() //nolint:errcheck // every step above already flushed its own transition
}

func (j *Journal) removeCreatedDir(pr *pathRecord, dr *dirRecord) error {
	segs := strings.Split(dr.Rel, "/")
	dir, err := j.openDirChain(pr, segs[:len(segs)-1])
	if err != nil {
		if errors.Is(err, errSuffixAbsent) {
			dr.Progress = rollbackRestored
			return j.step("dir_restored")
		}
		return errors.New("the created directory's parent could not be safely reopened: " + err.Error())
	}
	defer dir.Close() //nolint:errcheck // read-only directory descriptor

	name := segs[len(segs)-1]
	dev, ino, iErr := entryIdentity(dir, name)
	if errors.Is(iErr, fs.ErrNotExist) {
		// An absent directory under `dir_restoring` is this transaction's own unlink resumed, so it
		// owes the same parent sync the interrupted pass could not complete.
		if dr.Progress == rollbackRestoring {
			if sErr := syncTargetParent(dir); sErr != nil {
				return errors.New("the removed directory entry could not be made durable: " + sErr.Error())
			}
		}
		dr.Progress = rollbackRestored
		return j.step("dir_restored")
	}
	if iErr != nil {
		return errors.New("the created directory could not be identified: " + iErr.Error())
	}
	if dev != dr.Dev || ino != dr.Ino {
		return errors.New("another writer replaced the created directory " + dr.Rel)
	}
	empty, eErr := dirIsEmpty(dir, name)
	if eErr != nil {
		return errors.New("the created directory could not be read: " + eErr.Error())
	}
	if !empty {
		dr.Progress = rollbackRestored
		return j.step("dir_restored")
	}

	dr.Progress = rollbackRestoring
	if err := j.step("dir_restoring"); err != nil {
		return errors.New("the directory rollback could not be recorded before it began: " + err.Error())
	}
	if uErr := unix.Unlinkat(int(dir.Fd()), name, unix.AT_REMOVEDIR); uErr != nil {
		return errors.New("the created directory could not be removed: " + uErr.Error())
	}
	if parentMoved(dir, func() (*os.File, error) { return j.openDirChain(pr, segs[:len(segs)-1]) }) {
		return errParentMoved
	}
	if sErr := syncTargetParent(dir); sErr != nil {
		return errors.New("the removed directory entry could not be made durable: " + sErr.Error())
	}
	dr.Progress = rollbackRestored
	return j.step("dir_restored")
}

var errParentMoved = errors.New("a parent directory was moved while the rollback acted through it, so the result is not at the path it was recorded for")

// parentMoved reports whether a rollback act through held may have landed outside the project: a held
// descriptor follows its directory wherever it is renamed, so only a fresh descent from the project root
// reaching the same directory confirms the act happened at the recorded path.
func parentMoved(held *os.File, reopen func() (*os.File, error)) bool {
	fresh, err := reopen()
	if err != nil {
		return true
	}
	defer fresh.Close() //nolint:errcheck // read-only directory descriptor
	hDev, hIno, hErr := descriptorIdentity(held)
	fDev, fIno, fErr := descriptorIdentity(fresh)
	return hErr != nil || fErr != nil || hDev != fDev || hIno != fIno
}

// An ancestor gone because the child deleted a declared directory at or above it is an absent suffix:
// nothing beneath it can exist either. The ancestor is reached from the project root rather than by its
// recorded pathname, which would follow an intermediate symlink to a directory that still carries the
// recorded identity outside the project.
func (j *Journal) openAncestor(pr *pathRecord) (*os.File, error) {
	return j.openAncestorAt(pr, pr.Ancestor)
}

func (j *Journal) openAncestorAt(pr *pathRecord, location string) (*os.File, error) {
	rel, err := filepath.Rel(j.projectRoot, location)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("subagent: %s is not inside the project directory %s", location, j.projectRoot)
	}
	dir, err := openDirNoFollow(j.projectRoot)
	if err != nil {
		return nil, err
	}
	if rel != "." {
		for _, seg := range strings.Split(rel, string(filepath.Separator)) {
			next, oErr := openSubdirNoFollow(dir, seg)
			_ = dir.Close() //nolint:errcheck // read-only intermediate descriptor; the descent holds the next one
			if oErr != nil {
				if errors.Is(oErr, fs.ErrNotExist) && j.deletedByChild(pr.Ancestor) {
					return nil, errSuffixAbsent
				}
				return nil, oErr
			}
			dir = next
		}
	}
	dev, ino, err := descriptorIdentity(dir)
	if err != nil {
		_ = dir.Close() //nolint:errcheck // read-only directory descriptor
		return nil, err
	}
	if (dev != pr.ParentDev || ino != pr.ParentIno) && !j.recreatedAt(pr.Ancestor, dev, ino) {
		_ = dir.Close() //nolint:errcheck // read-only directory descriptor
		return nil, fmt.Errorf("subagent: %s is no longer the directory that was snapshotted", pr.Ancestor)
	}
	return dir, nil
}

func (j *Journal) deletedByChild(path string) bool {
	for i := range j.rec.Paths {
		p := &j.rec.Paths[i]
		if p.Delete && p.Pre.Kind == kindDir && !p.LastKnown.Exists && permissions.IsDescendantOrEqual(path, p.Path) {
			return true
		}
	}
	return false
}

func (j *Journal) recreatedAt(path string, dev, ino uint64) bool {
	for i := range j.rec.Paths {
		p := &j.rec.Paths[i]
		if p.Path == path && p.ReplacementIno != 0 && p.ReplacementDev == dev && p.ReplacementIno == ino {
			return true
		}
	}
	return false
}

func (j *Journal) openDirChain(pr *pathRecord, segs []string) (*os.File, error) {
	dir, err := j.openAncestor(pr)
	if err != nil {
		return nil, err
	}
	for i, seg := range segs {
		rel := strings.Join(segs[:i+1], "/")
		next, oErr := openSubdirNoFollow(dir, seg)
		if oErr != nil {
			_ = dir.Close() //nolint:errcheck // read-only directory descriptor
			if errors.Is(oErr, fs.ErrNotExist) {
				return nil, errSuffixAbsent
			}
			return nil, oErr
		}
		nDev, nIno, iErr := descriptorIdentity(next)
		_ = dir.Close() //nolint:errcheck // read-only directory descriptor
		if iErr != nil || (!j.confirmedDir(nDev, nIno) && !j.movedInAt(filepath.Join(pr.Ancestor, rel), nDev, nIno)) {
			_ = next.Close() //nolint:errcheck // read-only directory descriptor
			return nil, fmt.Errorf("subagent: %s is not the directory the child agent created", rel)
		}
		dir = next
	}
	return dir, nil
}

func dirIsEmpty(parent *os.File, name string) (bool, error) {
	dir, err := openSubdirNoFollow(parent, name)
	if err != nil {
		return false, err
	}
	defer dir.Close() //nolint:errcheck // read-only directory descriptor
	names, rErr := dir.Readdirnames(1)
	if rErr != nil && !errors.Is(rErr, io.EOF) {
		return false, rErr
	}
	return len(names) == 0, nil
}

func statEntry(parent *os.File, name string) (os.FileInfo, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close() //nolint:errcheck // read-only descriptor opened only to read the entry's identity
	return f.Stat()
}

// remove deletes the journal after its terminal state is durable, through the retained descriptors, so
// a directory swapped in at the path cannot make cleanup unlink something else. The record goes
// through the descriptor holding the journal directory itself, which no rename can redirect. The
// directory's own removal cannot: it is an unlink of a name in the holder above it, resolved at the
// instant the kernel reads it. So that name is checked against the identity recorded at creation, and
// a name that leads anywhere else is left alone — removing it would delete a stranger's directory and
// still leave this one behind. The journal is done either way: everything it owns is gone, and what
// survives is an empty directory answering to no record.
func (j *Journal) remove() error {
	if j.gone {
		return nil
	}
	dev, ino, iErr := entryIdentity(j.holder, j.dirName)
	if iErr != nil && !errors.Is(iErr, fs.ErrNotExist) {
		return iErr
	}
	stillOurs := iErr == nil && dev == j.rec.DirDev && ino == j.rec.DirIno
	if j.written {
		if err := unix.Unlinkat(int(j.dir.Fd()), journalRecordName, 0); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := j.dir.Sync(); err != nil {
			return err
		}
	}
	if stillOurs {
		if err := unix.Unlinkat(int(j.holder.Fd()), j.dirName, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := j.holder.Sync(); err != nil {
		return err
	}
	j.gone = true
	return nil
}

func (j *Journal) removeStorage() {
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = j.remove() //nolint:errcheck // the journal never became usable; nothing depends on the cleanup
}

func fromToolState(s filetools.JournalState) fileState {
	return fileState{Exists: s.Exists, Data: s.Data, Mode: s.Mode, Dev: s.Dev, Ino: s.Ino}
}

// sameState compares two observations of one path. Identity is compared only when both sides know it,
// because a pending record is written before publication and so cannot name the inode it will create.
func sameState(a, b fileState) bool {
	if !sameContent(a, b) {
		return false
	}
	if a.Exists && a.Ino != 0 && b.Ino != 0 {
		return a.Dev == b.Dev && a.Ino == b.Ino
	}
	return true
}

func sameContent(a, b fileState) bool {
	if a.Exists != b.Exists {
		return false
	}
	if !a.Exists {
		return true
	}
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case kindSymlink:
		return a.Link == b.Link
	case kindDir:
		return a.Mode.Perm() == b.Mode.Perm()
	default:
		return bytes.Equal(a.Data, b.Data) && a.Mode.Perm() == b.Mode.Perm()
	}
}
