// --resume <id> resolver: expected-path load, sibling scan, and the exact
// resume error contracts.
package sessions

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"codemeld.dev/codemeld/internal/fserrors"
)

// resumeNoIDHint is the closing line appends to the parse/validation and
// miss errors, pointing the user at the no-id listing form.
const resumeNoIDHint = "run codemeld --resume with no id to list resumable sessions for the current working directory."

// ResumeLoadError reports that the expected session file was present but could
// not be loaded. Verb is "parsed" when the file is not valid JSON or
// does not match the top-level session schema, or "loaded" when it parsed but
// failed record-stream validation. Its message ends with the
// no-id listing hint.
type ResumeLoadError struct {
	ID     string
	Verb   string // "parsed" or "loaded"
	Detail string
}

func (e *ResumeLoadError) Error() string {
	return fmt.Sprintf("codemeld: session %s cannot be %s: %s\n%s", e.ID, e.Verb, e.Detail, resumeNoIDHint)
}

// ResumeVersionError wraps a *VersionError from OpenSession (a newer-than-supported
// or unparseable schema_version) so a resume probe of a version-refused file exits
// with the VersionError's clear version message plus the no-id listing hint.
// The underlying *VersionError remains reachable via errors.As.
type ResumeVersionError struct {
	Err *VersionError
}

func (e *ResumeVersionError) Error() string {
	return e.Err.Error() + "\n" + resumeNoIDHint
}

func (e *ResumeVersionError) Unwrap() error { return e.Err }

// ResumeFolderMismatchError reports: the loaded metadata.folder is not
// byte-equal to the contents of the expected subdirectory's folder file (a single
// trailing newline stripped). It is a single-line "cannot be loaded" error,
// distinct from the validation form and from the CWD-match error.
type ResumeFolderMismatchError struct {
	ID             string
	MetadataFolder string
	FolderFile     string
}

func (e *ResumeFolderMismatchError) Error() string {
	return fmt.Sprintf("codemeld: session %s cannot be loaded: metadata.folder %s does not match folder file %s",
		e.ID, e.MetadataFolder, e.FolderFile)
}

// ResumeCWDMismatchError reports the CWD-match failure: the
// canonical working directory is not byte-equal to the loaded session's
// metadata.folder. This surfaces a hash-collision resume target (a session that
// hashes into the current folder's subdirectory but was recorded for a different
// folder).
type ResumeCWDMismatchError struct {
	ID             string
	MetadataFolder string
	Path           string
}

func (e *ResumeCWDMismatchError) Error() string {
	return fmt.Sprintf("codemeld: --resume %s: session was recorded at %s; cd there to resume", e.ID, e.MetadataFolder)
}

// ResumeWrongFolderError reports a hit in a sibling subdirectory: the id
// exists, but under a different folder. Folder is read from that subdirectory's
// folder file.
type ResumeWrongFolderError struct {
	ID     string
	Folder string
	Path   string
}

func (e *ResumeWrongFolderError) Error() string {
	return fmt.Sprintf("codemeld: session %s was started in %s; cd into that directory and re-run codemeld --resume %s",
		e.ID, e.Folder, e.ID)
}

// ResumeFolderFileError reports: a sibling subdirectory holds <id>.json
// but its folder file is missing, empty after trimming, or unreadable, so the
// wrong-folder message cannot be constructed. For the missing and empty-after-trim
// cases Category is not_found; otherwise it is the syscall's category.
type ResumeFolderFileError struct {
	ID       string
	Subdir   string
	Category fserrors.Category
}

func (e *ResumeFolderFileError) Error() string {
	return fmt.Sprintf("codemeld: --resume %s: session subdirectory %s is missing or has unreadable folder file: %s",
		e.ID, e.Subdir, e.Category)
}

// ResumeEnumerateError reports: readdir on the sessions root itself
// failed (a non-absent failure, e.g. permission denied), so the sibling scan
// cannot run at all.
type ResumeEnumerateError struct {
	Category fserrors.Category
}

func (e *ResumeEnumerateError) Error() string {
	return fmt.Sprintf("codemeld: session lookup: cannot enumerate ~/.codemeld/sessions/: %s", e.Category)
}

// ResumeNotFoundError reports a miss: the id was not found in the expected
// subdirectory or any sibling. When Skipped > 0 (per-subdirectory readdir
// failures), its message prepends a single warning line naming the count and the
// distinct error categories encountered, before the miss line.
type ResumeNotFoundError struct {
	ID         string
	Skipped    int
	Categories []fserrors.Category
}

func (e *ResumeNotFoundError) Error() string {
	miss := fmt.Sprintf("codemeld: session %s not found in any session directory; %s", e.ID, resumeNoIDHint)
	if e.Skipped > 0 {
		warn := fmt.Sprintf("codemeld: session lookup: %d session subdirectories could not be inspected (%s)",
			e.Skipped, joinCategories(e.Categories))
		return warn + "\n" + miss
	}
	return miss
}

// ResolveResumeID resolves a --resume <id> request to its session file.
// It probes the expected path ~/.codemeld/sessions/<folder-dir>/<id>.json for the
// current canonical folder; on a present file it loads (OpenSession), validates
// the record stream (ValidateRecordStream), checks metadata.folder
// against the folder file, then checks the canonical CWD against
// metadata.folder. On an absent expected file it scans sibling
// subdirectories for <id>.json (enumeration handling), returning a
// wrong-folder error on a hit or a miss error otherwise.
//
// On success it returns the resolved session file path and the parsed session.
// Every failure is returned as a typed error from this package whose Error() is
// the exact stderr text the caller prints before exiting with status 1; the
// resolver itself writes nothing and acquires no lock.
//
// validatePayload is the per-kind event-payload validator (events.ValidatePayload,
// supplied by production wiring that can import internal/events); it runs after
// ValidateRecordStream so a schema-invalid payload is reported in the same
// "loaded" bucket. A nil validatePayload skips that check (see ValidateEventPayloads).
func ResolveResumeID(id, cwd, home string, validatePayload PayloadValidator) (sessionPath string, sess *Session, err error) {
	canonicalCWD, err := CanonicalizeFolder(cwd)
	if err != nil {
		return "", nil, fmt.Errorf("codemeld: --resume %s: cannot resolve working directory %s: %w", id, cwd, err)
	}

	root := SessionRoot(home)
	folderDir := FolderDirName(canonicalCWD)
	expectedPath := filepath.Join(root, folderDir, id+".json")

	loaded, lerr := openExpected(id, expectedPath, validatePayload)
	if lerr != nil {
		// An absent expected file is the only signal to fall through to the
		// sibling scan; every other load failure is terminal.
		if errors.Is(lerr, errExpectedAbsent) {
			return scanSiblings(id, root, folderDir)
		}
		return "", nil, lerr
	}

	// metadata.folder must match the expected subdirectory's folder
	// file. Run before the CWD-match check so corrupted per-folder metadata
	// surfaces as the prescribed load failure rather than the resume-anchor path.
	if ferr := checkFolderFileMatch(id, filepath.Join(root, folderDir, folderFileName), loaded.Metadata.Folder); ferr != nil {
		return "", nil, ferr
	}

	// the canonical CWD must equal the recorded folder.
	if canonicalCWD != loaded.Metadata.Folder {
		return "", nil, &ResumeCWDMismatchError{ID: id, MetadataFolder: loaded.Metadata.Folder, Path: expectedPath}
	}

	return expectedPath, loaded, nil
}

// errExpectedAbsent is the sentinel openExpected returns when the expected file
// does not exist, so ResolveResumeID can distinguish "scan siblings" from a real
// load failure without inspecting raw filesystem errors at the call site.
var errExpectedAbsent = errors.New("expected session file absent")

// openExpected loads and validates the expected session file. A missing file
// yields errExpectedAbsent; any other failure yields the terminal error.
// validatePayload runs per-kind event-payload validation after the
// record-stream check, both surfacing as the "loaded" bucket.
func openExpected(id, path string, validatePayload PayloadValidator) (*Session, error) {
	s, _, err := OpenSession(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errExpectedAbsent
		}
		var ve *VersionError
		if errors.As(err, &ve) {
			return nil, &ResumeVersionError{Err: ve}
		}
		// Not valid JSON, not a session object, an Unmarshal schema failure, or a
		// read fault on a present file: all are "cannot be parsed".
		return nil, &ResumeLoadError{ID: id, Verb: "parsed", Detail: err.Error()}
	}
	if verr := ValidateRecordStream(s.Records); verr != nil {
		return nil, &ResumeLoadError{ID: id, Verb: "loaded", Detail: verr.Error()}
	}
	if perr := ValidateEventPayloads(s.Records, validatePayload); perr != nil {
		return nil, &ResumeLoadError{ID: id, Verb: "loaded", Detail: perr.Error()}
	}
	return s, nil
}

// checkFolderFileMatch implements: metadata.folder must be byte-equal to
// the folder file's contents (a single trailing newline stripped by
// readFolderFile). A missing or empty-after-trim folder file reads as empty, so
// it fails the match against a non-empty metadata.folder. A read fault is
// surfaced rather than silently passing the check.
func checkFolderFileMatch(id, folderPath, metadataFolder string) error {
	recorded, _, err := readFolderFile(folderPath)
	if err != nil {
		return &ResumeLoadError{ID: id, Verb: "loaded", Detail: fmt.Sprintf("cannot read folder file %s: %s", folderPath, fserrors.CategorizeErrno(err))}
	}
	if metadataFolder != recorded {
		return &ResumeFolderMismatchError{ID: id, MetadataFolder: metadataFolder, FolderFile: recorded}
	}
	return nil
}

// scanSiblings implements the sibling scan and its enumeration
// handling. selfDir is the current folder's subdirectory, already probed via the
// expected path and skipped here so a TOCTOU appearance there cannot masquerade
// as a wrong-folder hit.
func scanSiblings(id, root, selfDir string) (string, *Session, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		// A non-existent root means no sessions exist at all — a clean miss, not
		// the enumeration failure (which is reserved for real readdir
		// faults such as permission denied).
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil, &ResumeNotFoundError{ID: id}
		}
		return "", nil, &ResumeEnumerateError{Category: fserrors.CategorizeErrno(err)}
	}

	target := id + ".json"
	var skipped int
	var cats []fserrors.Category
	for _, e := range entries {
		if !e.IsDir() || e.Name() == selfDir {
			continue
		}
		subdir := filepath.Join(root, e.Name())
		hit, rerr := subdirHasFile(subdir, target)
		if rerr != nil {
			// a per-subdirectory readdir fault skips that subdirectory
			// and is retained only for the post-scan warning.
			skipped++
			cats = appendDistinctCategory(cats, fserrors.CategorizeErrno(rerr))
			continue
		}
		if hit {
			return "", nil, wrongFolderError(id, subdir)
		}
	}

	// skipped subdirectories warn only when the scan ends without a hit.
	return "", nil, &ResumeNotFoundError{ID: id, Skipped: skipped, Categories: cats}
}

// subdirHasFile reports whether subdir contains a non-directory entry named
// target, surfacing any readdir fault to the caller for handling.
func subdirHasFile(subdir, target string) (bool, error) {
	entries, err := os.ReadDir(subdir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.Name() == target && !e.IsDir() {
			return true, nil
		}
	}
	return false, nil
}

// wrongFolderError builds the hit error for a sibling subdirectory,
// reading its folder file. A missing, empty-after-trim, or unreadable
// folder file yields the folder-file error (not_found for the missing and
// empty cases); otherwise the wrong-folder message names the recorded folder.
func wrongFolderError(id, subdir string) error {
	recorded, present, err := readFolderFile(filepath.Join(subdir, folderFileName))
	if err != nil {
		return &ResumeFolderFileError{ID: id, Subdir: subdir, Category: fserrors.CategorizeErrno(err)}
	}
	if !present {
		return &ResumeFolderFileError{ID: id, Subdir: subdir, Category: fserrors.NotFound}
	}
	return &ResumeWrongFolderError{ID: id, Folder: recorded, Path: filepath.Join(subdir, id+".json")}
}

// appendDistinctCategory appends c to cats only if absent, preserving
// first-encounter order for the warning's category list.
func appendDistinctCategory(cats []fserrors.Category, c fserrors.Category) []fserrors.Category {
	if slices.Contains(cats, c) {
		return cats
	}
	return append(cats, c)
}

// joinCategories renders distinct categories as the comma-separated list used in
// the warning.
func joinCategories(cats []fserrors.Category) string {
	parts := make([]string, len(cats))
	for i, c := range cats {
		parts[i] = string(c)
	}
	return strings.Join(parts, ", ")
}
