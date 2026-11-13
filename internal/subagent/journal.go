package subagent

import (
	"encoding/json"
	"errors"
	"fmt"
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
	"codemeld.dev/codemeld/internal/sessions"
)

// The five caps are fixed rather than configured. maxStateBytesPerPath deliberately equals
// maxSnapshotBytesPerFile so a child can never write a file larger than the pre-state that would have
// to replace it. maxJournalBytes is sized from the rest: one pre-state and one post-state per path at
// encoding/json's 4/3 base64 expansion (2 x 128 MiB x 4/3 = 341 MiB) plus a 16 MiB envelope for paths,
// modes, identities, and punctuation, rounded up. Every cap is inclusive.
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

const journalDirSchemaVersion = 4

const journalAnswerSchemaVersion = 5

const journalCompletedSchemaVersion = 6

const (
	journalRecordName = "journal.json"
	journalLockName   = "journal.lock"
)

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
	Rel        string           `json:"rel"`
	Confirmed  bool             `json:"confirmed"`
	Created    bool             `json:"created"`
	Dev        uint64           `json:"dev,omitempty"`
	Ino        uint64           `json:"ino,omitempty"`
	Progress   rollbackProgress `json:"progress"`
	Mkdir      bool             `json:"mkdir,omitempty"`
	Seq        uint64           `json:"seq,omitempty"`
	KeptByUser bool             `json:"kept_by_user,omitempty"`
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
	Mkdir      bool `json:"mkdir,omitempty"`
	// ReplacementDev and ReplacementIno name the entry a rollback published for this path, the only
	// same-content entry a resumed restore may accept as its own; for a recreated directory it is also
	// the only directory besides the snapshotted one a descent may pass through here.
	ReplacementDev uint64 `json:"replacement_dev,omitempty"`
	ReplacementIno uint64 `json:"replacement_ino,omitempty"`
}

func (pr *pathRecord) anyKind() bool { return pr.Delete || pr.Move || pr.Mkdir }

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

type moveID struct {
	Invocation string `json:"invocation"`
	Seq        uint64 `json:"seq"`
}

type moveRecord struct {
	movePair
	State moveState `json:"state"`
	ID    moveID    `json:"id,omitzero"`
}

type groupAnswer struct {
	Members   []moveID       `json:"members"`
	Endpoints []string       `json:"endpoints"`
	Choice    Choice         `json:"choice"`
	Adopted   []adoptedState `json:"adopted,omitempty"`
}

type adoptedState struct {
	Path  string    `json:"path"`
	State fileState `json:"state"`
}

type journalRecord struct {
	SchemaVersion int            `json:"schema_version"`
	Invocation    string         `json:"invocation"`
	Depth         int            `json:"depth"`
	Lifecycle     lifecycleState `json:"lifecycle"`
	Completed     bool           `json:"completed,omitempty"`
	DirDev        uint64         `json:"dir_dev"`
	DirIno        uint64         `json:"dir_ino"`
	Paths         []pathRecord   `json:"paths"`
	MovePairs     []movePair     `json:"move_pairs,omitempty"`
	// Moves holds every move this child made, in the order it made them.
	Moves       []moveRecord  `json:"moves,omitempty"`
	MoveSeq     uint64        `json:"move_seq,omitempty"`
	Answers     []groupAnswer `json:"answers,omitempty"`
	Children    []childLink   `json:"children,omitempty"`
	Unrecovered []string      `json:"unrecovered,omitempty"`
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
	mu           sync.Mutex
	holder       *os.File
	dir          *os.File
	dirName      string
	path         string
	projectRoot  string
	rec          journalRecord
	index        map[string]int
	parent       *Journal
	children     []*Journal
	written      bool
	gone         bool
	retainedDirs []string
	writerLock   heldLock
	recoveryLock heldLock
	// recordUnlinked stops every later flush from republishing a record whose lock may already be gone.
	recordUnlinked bool
	gate           *recoveryGate
	policyRoots    map[string]string
	policyNotes    []string
}

// heldLock keeps a flock descriptor as a raw number, never an *os.File, whose finalizer would close it
// and release the lock while the journal is still in use.
type heldLock struct {
	fd   int
	held bool
}

func (l *heldLock) close() {
	if !l.held {
		return
	}
	fd := l.fd
	*l = heldLock{}
	_ = unix.Close(fd) //nolint:errcheck // closing releases the lock; there is nothing to retry
}

var _ filetools.WriteJournal = (*Journal)(nil)

// Declared, DeclaredDelete, DeclaredMoves, and DeclaredDirs must be the canonical scopes resolved before
// dispatch, not the incomplete record of what a run turned out to touch.
type JournalConfig struct {
	Home           string
	ProjectRoot    string
	Invocation     string
	Declared       []string
	DeclaredDelete []string
	DeclaredMoves  []permissions.MovePair
	DeclaredDirs   []string
	Parent         *Journal
}

// JournalOutcome is what a terminal transaction did. Unrecovered is an outcome in its own right,
// distinct from both a clean commit and a clean rollback: the named paths are left as they are and the
// journal survives for recovery or the user to resolve.
type JournalOutcome struct {
	Restored     []string
	Unrecovered  []string
	JournalPath  string
	HeldMoves    []HeldMove
	RetainedDirs []string
	heldAt       map[int]HeldMove
}

// Resumes marks a move whose linked undo had already begun, so a later recovery continues it rather than
// asking about it.
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
	mkdirable := make(map[string]bool, len(cfg.DeclaredDirs))
	for _, target := range cfg.DeclaredDirs {
		mkdirable[target] = true
	}
	declared := unionPaths(cfg.Declared, cfg.DeclaredDelete, slices.Collect(maps.Keys(movable)), cfg.DeclaredDirs)
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

	paths, err := snapshotDeclared(cfg.ProjectRoot, declared, deletable, movable, mkdirable)
	if err != nil {
		return nil, err
	}

	version := journalSchemaVersion
	switch {
	case len(mkdirable) > 0:
		version = journalDirSchemaVersion
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
	if err := j.lockForWriter(); err != nil {
		j.abandon()
		return nil, err
	}
	if err := j.flush(); err != nil {
		j.abandon()
		return nil, err
	}
	if cfg.Parent != nil {
		if err := cfg.Parent.link(j); err != nil {
			j.abandon()
			return nil, err
		}
		cfg.Parent.children = append(cfg.Parent.children, j)
	}
	return j, nil
}

const journalsDirName = "journals"

// openJournalLock is a variable only so a test can fail the writer's lock setup; production always
// runs the real openat.
var openJournalLock = unix.Openat

func (j *Journal) lockForWriter() error {
	fd, err := openJournalLock(int(j.dir.Fd()), journalLockName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(journalRecordMode))
	if err != nil {
		return fmt.Errorf("subagent: cannot create the child agent journal lock: %w", err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd) //nolint:errcheck // the lock was never taken
		return fmt.Errorf("subagent: cannot take the child agent journal lock: %w", err)
	}
	j.writerLock = heldLock{fd: fd, held: true}
	return nil
}

func (j *Journal) abandon() {
	j.removeStorage()
	j.writerLock.close()
	j.Close()
}

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
func snapshotDeclared(projectRoot string, declared []string, deletable, movable, mkdirable map[string]bool) ([]pathRecord, error) {
	var total int64
	out := make([]pathRecord, 0, len(declared))
	for _, target := range declared {
		dir, ancestor, suffix, err := openDeepestExisting(projectRoot, target)
		if err != nil {
			return nil, err
		}
		rec := pathRecord{Path: target, Ancestor: ancestor, Suffix: suffix, Progress: rollbackUnresolved, Delete: deletable[target], Move: movable[target], Mkdir: mkdirable[target]}
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

// Close removes nothing: a journal is deleted only by a committed or fully rolled-back outcome. It
// never releases a writer lock, so a retained journal stays visibly owned until this process exits.
func (j *Journal) Close() {
	j.recoveryLock.close()
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
	if j.gone || j.recordUnlinked {
		return errors.New("subagent: the child agent journal has already been removed")
	}
	if j.gate != nil && !j.gate.allows() {
		return errRecoveryStopped
	}
	j.promote()
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

// promote never lowers the version, so a journal that once carried move identities or answers is
// never written where a reader that knows neither could act on it.
func (j *Journal) promote() {
	if j.rec.SchemaVersion < journalAnswerSchemaVersion && carriesAnswerState(&j.rec) {
		j.rec.SchemaVersion = journalAnswerSchemaVersion
	}
	if j.rec.Completed && j.rec.SchemaVersion < journalCompletedSchemaVersion {
		j.rec.SchemaVersion = journalCompletedSchemaVersion
	}
}

func carriesAnswerState(rec *journalRecord) bool {
	if rec.MoveSeq > 0 || len(rec.Answers) > 0 || slices.ContainsFunc(rec.Moves, func(m moveRecord) bool { return m.ID != moveID{} }) {
		return true
	}
	return slices.ContainsFunc(rec.Paths, func(pr pathRecord) bool {
		return slices.ContainsFunc(pr.Dirs, func(d dirRecord) bool { return d.KeptByUser })
	})
}

func (j *Journal) newMoveID() moveID {
	j.rec.MoveSeq++
	return moveID{Invocation: j.rec.Invocation, Seq: j.rec.MoveSeq}
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
