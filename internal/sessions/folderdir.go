// Per-folder session subdirectory derivation and the folder-file policy.
package sessions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
)

// folderFileName is the fixed name of the one-line file recording a session
// directory's canonical launch folder.
const folderFileName = "folder"

// asciiWhitespace is the cutset used to detect the empty-after-trim case of a
// folder file. Only ASCII whitespace is trimmed; equality comparison
// strips at most one trailing LF instead.
const asciiWhitespace = " \t\n\r\v\f"

// FolderDirError categorizes a filesystem failure from EnsureFolderDir so the
// runner (and tests) can render an OP_FAIL line without parsing message text.
// Op is the operation token used in that line.
type FolderDirError struct {
	Op   string
	Path string
	Cat  fserrors.Category
	Err  error
}

func (e *FolderDirError) Error() string {
	return fserrors.FormatOpFail(e.Op, e.Path, e.Cat)
}

func (e *FolderDirError) Unwrap() error { return e.Err }

// CollisionError reports that two distinct canonical folders hash to the same
// <folder-dir>. It is not a filesystem failure: the recorded folder file is
// intact and readable, but its contents disagree with the folder being
// launched.
type CollisionError struct {
	Folder         string // canonical folder being launched
	RecordedFolder string // canonical folder already recorded in the folder file
	FolderDir      string // the colliding <folder-dir> name
}

func (e *CollisionError) Error() string {
	return fmt.Sprintf("codemeld: session-folder hash collision: %s and %s map to %s",
		e.Folder, e.RecordedFolder, e.FolderDir)
}

// CanonicalizeFolder resolves path to the canonical absolute folder path used by
// metadata.folder, <folder-dir> hashing, and resume CWD checks. It
// makes the path absolute, resolves symlinks, and removes trailing slashes and
// "."/".." segments. The path must exist, since symlink resolution reads it.
func CanonicalizeFolder(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(abs))
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

// FolderDirName returns the per-folder directory name <hash>-<basename> for a
// canonical folder path. <hash> is the first 16 bytes of the
// SHA-256 of the path, lowercase hex (32 chars); <basename> is the final path
// component with bytes outside [A-Za-z0-9_.-] replaced by "_" and capped at 32
// characters, or "root" for the filesystem root.
func FolderDirName(canonicalFolder string) string {
	sum := sha256.Sum256([]byte(canonicalFolder))
	hash := hex.EncodeToString(sum[:16])
	return hash + "-" + sanitizeBasename(canonicalFolder)
}

// sanitizeBasename derives the <basename> segment from a canonical folder path.
func sanitizeBasename(canonicalFolder string) string {
	base := filepath.Base(canonicalFolder)
	// Root must be detected before sanitization: filepath.Base("/") returns the
	// separator, and a Clean'd "." can only appear for an empty/relative input.
	if base == string(filepath.Separator) || base == "." {
		return "root"
	}

	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '_', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	sanitized := b.String()
	if len(sanitized) > 32 {
		sanitized = sanitized[:32]
	}
	return sanitized
}

// SessionRoot returns the sessions root directory ~/.codemeld/sessions for the
// given home directory.
func SessionRoot(home string) string {
	return filepath.Join(home, ".codemeld", "sessions")
}

// EnsureFolderDir creates ~/.codemeld/sessions and the per-folder subdirectory
// for canonicalFolder, then ensures the subdirectory's folder file records that
// canonical path. It returns the per-folder subdirectory path. The
// call is idempotent: when the folder file already records canonicalFolder it is
// left untouched. A folder file recording a different folder yields a
// *CollisionError; filesystem failures yield a *FolderDirError carrying the
// operation token, path, and category for the runner to render. It never prints
// or exits.
func EnsureFolderDir(home, canonicalFolder string) (subdirPath string, err error) {
	root := SessionRoot(home)
	if _, cat, derr := fsutil.EnsureDir(root); derr != nil {
		return "", &FolderDirError{Op: "create-sessions-dir", Path: root, Cat: cat, Err: derr}
	}

	dirName := FolderDirName(canonicalFolder)
	subdirPath = filepath.Join(root, dirName)
	if _, cat, derr := fsutil.EnsureDir(subdirPath); derr != nil {
		return "", &FolderDirError{Op: "create-sessions-dir", Path: subdirPath, Cat: cat, Err: derr}
	}

	folderPath := filepath.Join(subdirPath, folderFileName)
	recorded, present, rerr := readFolderFile(folderPath)
	if rerr != nil {
		return subdirPath, &FolderDirError{
			Op:   "read-folder-file",
			Path: folderPath,
			Cat:  fserrors.CategorizeErrno(rerr),
			Err:  rerr,
		}
	}
	if present {
		if recorded == canonicalFolder {
			return subdirPath, nil
		}
		return subdirPath, &CollisionError{
			Folder:         canonicalFolder,
			RecordedFolder: recorded,
			FolderDir:      dirName,
		}
	}

	// Folder mode 0644: the path is non-secret and readers in other processes
	// (resume CWD checks) only need to read it.
	if _, cat, werr := fsutil.WriteAtomic(folderPath, []byte(canonicalFolder+"\n"), 0o644); werr != nil {
		return subdirPath, &FolderDirError{Op: "write-folder-file", Path: folderPath, Cat: cat, Err: werr}
	}
	return subdirPath, nil
}

// readFolderFile reads the folder file at path. A missing file or a file that is
// empty after ASCII-whitespace trimming both mean "no recorded folder"
// (present=false, no error). For a recorded folder, at most one trailing LF is
// stripped so both LF-terminated and unterminated forms compare equal. A read
// error on an existing file is surfaced (never treated as a collision).
func readFolderFile(path string) (recorded string, present bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	if strings.Trim(string(data), asciiWhitespace) == "" {
		return "", false, nil
	}
	return strings.TrimSuffix(string(data), "\n"), true, nil
}
