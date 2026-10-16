// Package trust records which project roots the user approved to contribute their own settings
// layer to a run.
package trust

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/locks"
	"codemeld.dev/codemeld/internal/sessions"
	"golang.org/x/sys/unix"
)

// Version is the store schema version. An unrecognized version is unreadable rather than
// upgradable, so a later format change never has to guess whether an old file is safe.
const Version = 1

const (
	storePerm   os.FileMode = 0o600
	lockSuffix              = ".lock"
	lockTimeout             = 2 * time.Second
)

type Store struct {
	Version  int      `yaml:"version"`
	Projects []string `yaml:"projects"`
}

type Reason string

const (
	ReasonTrusted        Reason = "trusted"
	ReasonNothingCovered Reason = "nothing_covered"
	ReasonNoRecord       Reason = "no_record"
	ReasonUnreadable     Reason = "unreadable_store"
	ReasonUnresolvedRoot Reason = "unresolved_root"
)

type Decision struct {
	Trusted bool
	Reason  Reason
	Root    string
}

func StorePath(home string) string {
	return filepath.Join(home, ".codemeld", "global", "approved-projects.yaml")
}

func Lookup(home, projectRoot string) Decision {
	root, err := sessions.CanonicalizeFolder(projectRoot)
	if projectRoot == "" || err != nil {
		return Decision{Reason: ReasonUnresolvedRoot}
	}
	store, ok := loadStore(StorePath(home))
	switch {
	case !ok:
		return Decision{Reason: ReasonUnreadable, Root: root}
	case slices.Contains(store.Projects, root):
		return Decision{Trusted: true, Reason: ReasonTrusted, Root: root}
	default:
		return Decision{Reason: ReasonNoRecord, Root: root}
	}
}

func Record(home, root string) error {
	canonical, err := sessions.CanonicalizeFolder(root)
	if root == "" || err != nil {
		return fmt.Errorf("trust: unresolved root %q", root)
	}

	path := StorePath(home)
	if _, _, err := fsutil.EnsureDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("trust: ensure store directory: %w", err)
	}
	release, reason, lockErr := locks.Acquire(path+lockSuffix, lockTimeout)
	if reason != locks.ReasonNone {
		return fmt.Errorf("trust: lock store: %w", lockErr)
	}
	defer release()

	store, ok := loadStore(path)
	if !ok {
		return errors.New("trust: store is unreadable or malformed")
	}
	if slices.Contains(store.Projects, canonical) {
		return nil
	}
	store.Projects = append(store.Projects, canonical)
	if step, err := writeStore(path, store); err != nil {
		return fmt.Errorf("trust: write store (%s): %w", step, err)
	}
	return nil
}

// valid rejects any store this build could not have written in full, so one bad entry makes the
// whole file unreadable rather than authorization input or bytes to republish.
func (s Store) valid() bool {
	if s.Version != Version {
		return false
	}
	seen := make(map[string]bool, len(s.Projects))
	for _, root := range s.Projects {
		if seen[root] || !canonicalKey(root) {
			return false
		}
		seen[root] = true
	}
	return true
}

func canonicalKey(root string) bool {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return false
	}
	resolved, err := sessions.CanonicalizeFolder(root)
	// A key that no longer resolves cannot be an alias of a live root and cannot match any
	// launch, so an unresolvable key is a dead entry rather than a second spelling.
	return err != nil || resolved == root
}

// loadStore reports ok=false for anything it cannot interpret, so a malformed store fails closed
// instead of degrading to an empty list. A store that does not exist yet is readable and empty.
func loadStore(path string) (Store, bool) {
	f, err := openStore(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Store{Version: Version}, true
	case err != nil:
		return Store{}, false
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != storePerm {
		return Store{}, false
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return Store{}, false
	}
	var store Store
	if err := yaml.Unmarshal(data, &store); err != nil || !store.valid() {
		return Store{}, false
	}
	return store, true
}

var openStore = func(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func writeStore(path string, store Store) (fsutil.AtomicWriteStep, error) {
	store.Version = Version
	data, err := yaml.Marshal(store)
	if err != nil {
		return fsutil.LoadStep, err
	}
	step, _, werr := fsutil.WriteAtomic(path, data, storePerm)
	return step, werr
}
