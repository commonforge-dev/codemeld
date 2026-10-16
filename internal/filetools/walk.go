// Shared directory walker for the recursive read-only navigation tools (grep, glob, list, tree):
// ordered, hidden-filtered, symlink-no-follow traversal with a pluggable ignore filter seam that the
// codemeldignore matcher registers into.
package filetools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tools"
)

// IgnoreMatcher is one pluggable ignore filter the walker consults before an entry is emitted or a
// directory is descended into. The codemeldignore matcher registers into a Walk call's ordered
// WalkOptions.Ignore set; the set is empty by default, so include_ignored is a no-op when no matcher is
// supplied. The walker owns only this seam — it implements no ignore syntax itself.
type IgnoreMatcher interface {
	// ShouldSkip reports whether the entry at relPath (project-root-relative, slash-separated) of the
	// given kind must be excluded from the walk. Returning true for a directory both drops it from the
	// results and prunes its whole subtree, because the walker consults the matcher before it descends —
	// so a pruned directory's children are never enumerated or passed to any matcher.
	ShouldSkip(relPath string, kind EntryKind) bool
}

// WalkOptions configures a single Walk traversal. Root and ProjectRoot are absolute: Root is the
// already-resolved subtree to traverse (normally ResolveReadTarget's result) and is not itself emitted,
// while ProjectRoot anchors the project-relative paths used for ordering, matcher input, and output. The
// two differ when a tool is invoked on a subdirectory of the project (RelPath stays project-root-relative,
// so the codemeldignore matcher sees repo-root-relative paths regardless of the traversal root).
type WalkOptions struct {
	// Root is the absolute, already-resolved directory to traverse. It is not emitted; its entries are.
	Root string
	// ProjectRoot is the absolute project root each emitted entry's RelPath is computed against.
	ProjectRoot string
	// Limit caps the number of entries emitted; a value <= 0 means unbounded. When more entries exist
	// than the limit admits, Walk emits exactly Limit of them and reports truncated=true.
	Limit int
	// MaxDepth caps how deep below Root the walk descends: 0 means unlimited, 1 means immediate children
	// only (the non-recursive list tool), N means down to depth N. A directory at the depth cap is still
	// emitted as an entry but not descended into.
	MaxDepth int
	// IncludeHidden, when true, disables the default dot-entry filter so dot-prefixed files and
	// directories are emitted and descended into.
	IncludeHidden bool
	// IncludeIgnored, when true, disables the ignore filters by not consulting Ignore at all — a
	// no-op while Ignore is empty, the disable switch once the codemeldignore matcher is registered.
	IncludeIgnored bool
	// Ignore is the ordered set of ignore matchers, empty by default. The codemeldignore matcher populates
	// it; matchers run in order and the first to skip an entry wins.
	Ignore []IgnoreMatcher

	Blocked   *permissions.BlockedPaths
	OnBlocked func(absPath string)
}

const leftOutDisplayCap = 20

func withLeftOut(res tools.Result, leftOut []string, projectRoot, home string, foldCase bool, outputCap int) tools.Result {
	if len(leftOut) == 0 {
		return res
	}
	shown := leftOut
	if len(shown) > leftOutDisplayCap {
		shown = shown[:leftOutDisplayCap]
	}
	line := leftOutLine(shown, len(leftOut), projectRoot, home, foldCase, outputCap-min(len(res.Stderr), outputCap/2))
	if _, _, cut, _ := events.TruncateToolOutput(nil, res.Stderr, outputCap-len(line)); cut {
		_, kept, _, _ := events.TruncateToolOutput(nil, res.Stderr, outputCap-len(line)-1)
		res.Stderr = append(kept, '\n')
	}
	res.Stderr = append(res.Stderr, line...)
	return res
}

func leftOutLine(shown []string, total int, projectRoot, home string, foldCase bool, room int) string {
	line := "left out (blocked): "
	n := 0
	for _, p := range shown {
		name := oneLine(leftOutDisplay(p, projectRoot, home, foldCase))
		sep := ""
		if n > 0 {
			sep = ", "
		}
		if len(line)+len(sep)+len(name)+len(andMore(total-n-1))+1 > room {
			break
		}
		line += sep + name
		n++
	}
	if n == 0 {
		return line + strconv.Itoa(total) + " (paths too long to show)\n"
	}
	return line + andMore(total-n) + "\n"
}

func andMore(more int) string {
	if more == 0 {
		return ""
	}
	return " and " + strconv.Itoa(more) + " more"
}

func oneLine(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return !unicode.IsGraphic(r) }) {
		return s
	}
	return strconv.QuoteToGraphic(s)
}

func leftOutDisplay(p, projectRoot, home string, foldCase bool) string {
	if rel, ok := permissions.RelWithin(projectRoot, p, foldCase); ok {
		if rel == "" {
			return "."
		}
		return rel
	}
	if home != "" {
		if rel, ok := permissions.RelWithin(home, p, foldCase); ok {
			return strings.TrimSuffix("~/"+rel, "/")
		}
	}
	return p
}

// WalkEntry is one traversed filesystem entry, classified without following symlinks.
type WalkEntry struct {
	// RelPath is the entry's project-root-relative, slash-separated path. It is the deterministic
	// ordering key and the stable identifier consumer tools format and matchers filter on.
	RelPath string
	// AbsPath is the entry's absolute filesystem path.
	AbsPath string
	// Kind is the entry's own type (file / dir / symlink / other), classified by an lstat-equivalent that
	// never resolves a symlink to its target, mirroring ClassifyEntry.
	Kind EntryKind
	// Depth is the entry's depth below Root; Root's immediate children are depth 1.
	Depth int
}

// errWalkLimit is the internal sentinel that unwinds the recursion once Limit entries have been emitted
// and one more entry wants to be emitted. It never escapes Walk: it is translated into truncated=true.
var errWalkLimit = errors.New("filetools: walk entry limit reached")

// Walk traverses opts.Root depth-first and returns its entries in deterministic order — each directory's
// children ascending by name, every directory emitted before its descendants — classified without
// following symlinks. It skips dot-prefixed (hidden) entries, and does not descend hidden
// directories, unless opts.IncludeHidden. Unless opts.IncludeIgnored, it consults the
// ordered opts.Ignore matchers before emitting or descending into each entry, so a matcher can both drop
// an entry and prune a directory subtree; with no matchers registered this is a no-op. A symlink
// is always reported as an EntrySymlink entry and never descended into, so a directory symlink cannot
// redirect a recursive walk.
//
// Output is bounded by opts.Limit: when more entries exist than the limit admits, Walk emits exactly Limit
// of them in order and returns truncated=true, so the caller can surface the truncation signal —
// Walk reports only this logical-limit fact and does not format any metadata itself (that is the
// BoundedResult helper's job; the global byte cap is applied separately downstream). A directory that
// cannot be read (including a non-existent or non-directory Root) aborts the walk and is returned as the
// error value, so a consumer surfaces it in-band and model-correctable rather than aborting the turn.
func Walk(opts WalkOptions) (entries []WalkEntry, truncated bool, err error) {
	werr := WalkContext(context.Background(), opts, func(e WalkEntry) error {
		if opts.Limit > 0 && len(entries) >= opts.Limit {
			return errWalkLimit
		}
		entries = append(entries, e)
		return nil
	})
	if werr != nil {
		if errors.Is(werr, errWalkLimit) {
			return entries, true, nil
		}
		return nil, false, werr
	}
	return entries, false, nil
}

type WalkVisitor func(WalkEntry) error

func WalkContext(ctx context.Context, opts WalkOptions, visit WalkVisitor) error {
	opts.Blocked = opts.Blocked.Current()
	skipByIgnore := func(rel string, kind EntryKind) bool {
		if opts.IncludeIgnored {
			return false
		}
		for _, m := range opts.Ignore {
			if m.ShouldSkip(rel, kind) {
				return true
			}
		}
		return false
	}

	var descend func(dir string, depth int) error
	descend = func(dir string, depth int) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		// os.ReadDir returns entries already sorted ascending by name, which — composed with depth-first
		// pre-order descent — yields the deterministic "directory before its descendants, siblings
		// ascending" order. This is a component-wise ordering, not a byte-sort of
		// the full slash-joined paths (where '/' would sort after '.'), so the hierarchical tree order the
		// tree tool needs is preserved.
		dirents, rerr := os.ReadDir(dir)
		if rerr != nil {
			return rerr
		}
		for _, de := range dirents {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			name := de.Name()
			if !opts.IncludeHidden && strings.HasPrefix(name, ".") {
				continue // hidden: not emitted and, for a directory, not descended
			}
			abs := filepath.Join(dir, name)
			rel, relErr := filepath.Rel(opts.ProjectRoot, abs)
			if relErr != nil {
				return relErr
			}
			rel = filepath.ToSlash(rel)
			kind, kerr := classifyDirEntry(de)
			if kerr != nil {
				return kerr // a metadata lookup for an unknown-type entry failed: surface it in-band
			}

			if skipByIgnore(rel, kind) {
				continue // ignored: dropped before emit/descent, so a skipped directory subtree is pruned
			}
			if _, blocked := opts.Blocked.Blocking(abs); blocked {
				if opts.OnBlocked != nil {
					opts.OnBlocked(abs)
				}
				continue
			}
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			if verr := visit(WalkEntry{RelPath: rel, AbsPath: abs, Kind: kind, Depth: depth}); verr != nil {
				return verr
			}

			// Descend only into a real directory (never a symlink) and only while under the depth
			// cap; a directory at the cap is emitted above but its children are not enumerated.
			if kind == EntryDir && (opts.MaxDepth == 0 || depth < opts.MaxDepth) {
				if derr := descend(abs, depth+1); derr != nil {
					return derr
				}
			}
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		return nil
	}

	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}

	// Check the traversal root itself against the ignore set before descending. Walk only consults the
	// matchers on entries it reads from opts.Root, so a directory named directly as the tool path (the
	// resolved user `path` the four consumers pass as Root) would otherwise be entered and its children
	// emitted even when an ignore pattern matches that directory — bypassing the "a matched directory
	// prunes its subtree" guarantee. The project root itself is the traversal anchor, never a filterable
	// entry, so a Root equal to ProjectRoot (rel "." or empty) is exempt.
	if !opts.IncludeIgnored {
		if rel, relErr := filepath.Rel(opts.ProjectRoot, opts.Root); relErr == nil {
			rel = filepath.ToSlash(rel)
			if rel != "." && rel != "" && skipByIgnore(rel, EntryDir) {
				if cerr := ctx.Err(); cerr != nil {
					return cerr
				}
				return nil
			}
		}
	}

	if _, blocked := opts.Blocked.Blocking(opts.Root); blocked {
		if opts.OnBlocked != nil {
			opts.OnBlocked(opts.Root)
		}
		return nil
	}
	return descend(opts.Root, 1)
}

// classifyDirEntry maps an os.DirEntry to its EntryKind by the entry's own type, never following a symlink
// to its target: a symlink is EntrySymlink even when it points at a directory, so the walker
// classifies a directory symlink as a symlink and refuses to descend it. When os.DirEntry.Type positively
// identifies a symlink, directory, or other non-regular typed entry, that fast path is used directly. A
// zero type is ambiguous — a regular file, or an entry the filesystem reported with no type bits (unknown
// d_type) — so it is resolved through os.DirEntry.Info, which is an lstat-equivalent that classifies the
// entry by its own mode without resolving the link. This keeps an unknown-type directory classified as
// EntryDir (and therefore descended) instead of being silently emitted as a file. Info errors are returned.
func classifyDirEntry(d os.DirEntry) (EntryKind, error) {
	t := d.Type()
	switch {
	case t&os.ModeSymlink != 0:
		return EntrySymlink, nil
	case t.IsDir():
		return EntryDir, nil
	case t != 0:
		return EntryOther, nil // a positively-typed non-regular entry (socket, device, pipe, …)
	}
	// t == 0: resolve the regular/unknown ambiguity with a non-following metadata lookup, mapping the mode
	// with the same rules as ClassifyEntry so the classification matches the list tool's lstat path.
	info, err := d.Info()
	if err != nil {
		return "", err
	}
	m := info.Mode()
	switch {
	case m&os.ModeSymlink != 0:
		return EntrySymlink, nil
	case m.IsDir():
		return EntryDir, nil
	case m.IsRegular():
		return EntryFile, nil
	default:
		return EntryOther, nil
	}
}
