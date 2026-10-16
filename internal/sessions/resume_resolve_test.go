// Tests for the --resume <id> resolver: expected-path load, sibling scan, and
// the exact resume error contracts.
package sessions

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/fserrors"
)

// sessionDoc builds a structurally valid, schema_version-1 JSONL session with the
// given metadata.folder and raw comma-separated record body (empty body -> no records).
func sessionDoc(folder, records string) string {
	doc := `{"type":"metadata","metadata":{"id":"` + testMetaID + `","folder":` + strconv.Quote(folder) +
		`,"started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":1}}` + "\n"
	if strings.TrimSpace(records) == "" {
		return doc
	}
	var elems []json.RawMessage
	if err := json.Unmarshal([]byte("["+records+"]"), &elems); err != nil {
		panic(err)
	}
	for _, elem := range elems {
		doc += string(elem) + "\n"
	}
	return doc
}

// loneToolRecord parses as a valid spine but fails record-stream
// validation: a tool message with no preceding assistant carrying tool_calls.
const loneToolRecord = `{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01",` +
	`"role":"tool","content":"r","timestamp":"2026-05-25T12:00:00.000Z","tool_call_id":"call_x"}`

// streamInterruptedRecord builds a spine-valid stream_interrupted event record
// (parses and passes) whose payload is the given object body, so the
// load-path per-kind payload validator (ValidateEventPayloads) is what decides it.
func streamInterruptedRecord(payload string) string {
	return `{"type":"event","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a02",` +
		`"kind":"stream_interrupted","timestamp":"2026-05-25T12:00:00.000Z","payload":` + payload + `}`
}

// resumeEnv sets up an isolated home (with its sessions root) and a real,
// canonicalized working directory, returning the pieces the resolver derives.
func resumeEnv(t *testing.T) (home, root, rawCWD, canonical, folderDir string) {
	t.Helper()
	home = t.TempDir()
	root = SessionRoot(home)
	rawCWD = t.TempDir()
	c, err := CanonicalizeFolder(rawCWD)
	if err != nil {
		t.Fatalf("canonicalize cwd: %v", err)
	}
	return home, root, rawCWD, c, FolderDirName(c)
}

func mkdir(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	return path
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestResolveResumeID_CleanResolve(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	id := "sess-clean"
	writeFile(t, filepath.Join(dir, id+".json"), sessionDoc(canonical, ""))
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	path, sess, err := ResolveResumeID(id, rawCWD, home, nil)
	if err != nil {
		t.Fatalf("ResolveResumeID() error = %v", err)
	}
	if want := filepath.Join(dir, id+".json"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if sess == nil || sess.Metadata.Folder != canonical {
		t.Fatalf("session = %+v, want metadata.folder %q", sess, canonical)
	}
}

func TestResolveResumeID_ParseFailure(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	id := "sess-parse"
	writeFile(t, filepath.Join(dir, id+".json"), "this is not valid json")
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	_, _, err := ResolveResumeID(id, rawCWD, home, nil)
	var le *ResumeLoadError
	if !errors.As(err, &le) {
		t.Fatalf("error %v is not a *ResumeLoadError", err)
	}
	if le.Verb != "parsed" {
		t.Errorf("Verb = %q, want %q", le.Verb, "parsed")
	}
	want := "codemeld: session sess-parse cannot be parsed: metadata line: must be a JSON object\n" + resumeNoIDHint
	if err.Error() != want {
		t.Errorf("Error() = %q\nwant %q", err.Error(), want)
	}
}

func TestResolveResumeID_ValidationFailure(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	id := "sess-validate"
	writeFile(t, filepath.Join(dir, id+".json"), sessionDoc(canonical, loneToolRecord))
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	_, _, err := ResolveResumeID(id, rawCWD, home, nil)
	var le *ResumeLoadError
	if !errors.As(err, &le) {
		t.Fatalf("error %v is not a *ResumeLoadError", err)
	}
	if le.Verb != "loaded" {
		t.Errorf("Verb = %q, want %q", le.Verb, "loaded")
	}
	want := "codemeld: session sess-validate cannot be loaded: " +
		"records[0]: tool message has no preceding assistant message with tool_calls\n" + resumeNoIDHint
	if err.Error() != want {
		t.Errorf("Error() = %q\nwant %q", err.Error(), want)
	}
}

// A spine-valid record whose per-kind event payload fails validation is a
// "loaded" failure, located by record index as records[N].payload: <detail> — the
// payload validator composes into the same load bucket as ValidateRecordStream.
func TestResolveResumeID_PayloadValidationFailure(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	id := "sess-payload"
	writeFile(t, filepath.Join(dir, id+".json"), sessionDoc(canonical, streamInterruptedRecord(`{"source":"esc"}`)))
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	validate := func(kind string, _ json.RawMessage) error {
		return fmt.Errorf("%s: content_chars: required field is absent", kind)
	}
	_, _, err := ResolveResumeID(id, rawCWD, home, validate)
	var le *ResumeLoadError
	if !errors.As(err, &le) {
		t.Fatalf("error %v is not a *ResumeLoadError", err)
	}
	if le.Verb != "loaded" {
		t.Errorf("Verb = %q, want %q", le.Verb, "loaded")
	}
	want := "codemeld: session sess-payload cannot be loaded: " +
		"records[0].payload: stream_interrupted: content_chars: required field is absent\n" + resumeNoIDHint
	if err.Error() != want {
		t.Errorf("Error() = %q\nwant %q", err.Error(), want)
	}
}

// A supplied payload validator is actually invoked over each event record on the
// load path; when it accepts, the session resolves cleanly. Pins that the wiring
// is live (an accepted payload round-trips), not a skipped no-op.
func TestResolveResumeID_PayloadValidatorInvokedAndAccepts(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	id := "sess-payload-ok"
	writeFile(t, filepath.Join(dir, id+".json"), sessionDoc(canonical, streamInterruptedRecord(`{"source":"esc","content_chars":3}`)))
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	var seen []string
	validate := func(kind string, _ json.RawMessage) error {
		seen = append(seen, kind)
		return nil
	}
	_, sess, err := ResolveResumeID(id, rawCWD, home, validate)
	if err != nil {
		t.Fatalf("ResolveResumeID() error = %v", err)
	}
	if sess == nil {
		t.Fatal("session is nil on a clean payload-validated resolve")
	}
	if len(seen) != 1 || seen[0] != "stream_interrupted" {
		t.Errorf("validator invoked with %v, want exactly [stream_interrupted]", seen)
	}
}

// A version-refused expected file (schema_version newer than supported) surfaces
// the VersionError's version message plus the hint, with the *VersionError reachable.
func TestResolveResumeID_VersionRefusal(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	id := "sess-newer"
	newerDoc := `{"type":"metadata","metadata":{"id":"` + testMetaID + `","folder":` + strconv.Quote(canonical) +
		`,"started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":2}}` + "\n"
	writeFile(t, filepath.Join(dir, id+".json"), newerDoc)
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	_, _, err := ResolveResumeID(id, rawCWD, home, nil)
	var rve *ResumeVersionError
	if !errors.As(err, &rve) {
		t.Fatalf("error %v is not a *ResumeVersionError", err)
	}
	var ve *VersionError
	if !errors.As(err, &ve) || ve.Status != StatusNewer {
		t.Fatalf("underlying error %v is not a newer *VersionError", err)
	}
}

func TestResolveResumeID_FolderFileMismatch(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	id := "sess-440d"
	writeFile(t, filepath.Join(dir, id+".json"), sessionDoc(canonical, ""))
	writeFile(t, filepath.Join(dir, folderFileName), "/different/folder\n")

	_, _, err := ResolveResumeID(id, rawCWD, home, nil)
	var me *ResumeFolderMismatchError
	if !errors.As(err, &me) {
		t.Fatalf("error %v is not a *ResumeFolderMismatchError", err)
	}
	want := "codemeld: session sess-440d cannot be loaded: metadata.folder " + canonical +
		" does not match folder file /different/folder"
	if err.Error() != want {
		t.Errorf("Error() = %q\nwant %q", err.Error(), want)
	}
}

// The CWD-match check fires when metadata.folder matches its own
// folder file (440d passes) but differs from the canonical CWD — the hash-collision
// resume target. The recorded folder need not exist; it is only metadata here.
func TestResolveResumeID_CWDMismatch(t *testing.T) {
	home, root, rawCWD, _, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	id := "sess-cwd"
	const recorded = "/recorded/elsewhere"
	writeFile(t, filepath.Join(dir, id+".json"), sessionDoc(recorded, ""))
	writeFile(t, filepath.Join(dir, folderFileName), recorded+"\n")

	_, _, err := ResolveResumeID(id, rawCWD, home, nil)
	var ce *ResumeCWDMismatchError
	if !errors.As(err, &ce) {
		t.Fatalf("error %v is not a *ResumeCWDMismatchError", err)
	}
	want := "codemeld: --resume sess-cwd: session was recorded at " + recorded + "; cd there to resume"
	if err.Error() != want {
		t.Errorf("Error() = %q\nwant %q", err.Error(), want)
	}
	if wantPath := filepath.Join(dir, id+".json"); ce.Path != wantPath {
		t.Errorf("Path = %q, want %q", ce.Path, wantPath)
	}
}

// otherFolderEnv builds a sibling per-folder subdirectory for a distinct, real
// folder under the same root and returns its subdir path and canonical folder.
func otherFolderEnv(t *testing.T, root string) (subdir, canonical string) {
	t.Helper()
	other := t.TempDir()
	c, err := CanonicalizeFolder(other)
	if err != nil {
		t.Fatalf("canonicalize other: %v", err)
	}
	return mkdir(t, filepath.Join(root, FolderDirName(c))), c
}

func TestResolveResumeID_FoundInSibling(t *testing.T) {
	home, root, rawCWD, _, _ := resumeEnv(t)
	sib, otherCanonical := otherFolderEnv(t, root)
	id := "sess-elsewhere"
	writeFile(t, filepath.Join(sib, id+".json"), sessionDoc(otherCanonical, ""))
	writeFile(t, filepath.Join(sib, folderFileName), otherCanonical+"\n")

	_, _, err := ResolveResumeID(id, rawCWD, home, nil)
	var we *ResumeWrongFolderError
	if !errors.As(err, &we) {
		t.Fatalf("error %v is not a *ResumeWrongFolderError", err)
	}
	if we.Folder != otherCanonical {
		t.Errorf("Folder = %q, want %q", we.Folder, otherCanonical)
	}
	want := "codemeld: session " + id + " was started in " + otherCanonical +
		"; cd into that directory and re-run codemeld --resume " + id
	if err.Error() != want {
		t.Errorf("Error() = %q\nwant %q", err.Error(), want)
	}
	if wantPath := filepath.Join(sib, id+".json"); we.Path != wantPath {
		t.Errorf("Path = %q, want %q", we.Path, wantPath)
	}
}

// a sibling hit whose folder file is missing or empty-after-trim yields
// the folder-file error with category not_found.
func TestResolveResumeID_SiblingHitMissingFolderFile(t *testing.T) {
	tests := []struct {
		name          string
		folderContent string // "" → do not write the file at all
		write         bool
	}{
		{"missing folder file", "", false},
		{"empty after trim", "   \n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home, root, rawCWD, _, _ := resumeEnv(t)
			sib, otherCanonical := otherFolderEnv(t, root)
			id := "sess-440e"
			writeFile(t, filepath.Join(sib, id+".json"), sessionDoc(otherCanonical, ""))
			if tt.write {
				writeFile(t, filepath.Join(sib, folderFileName), tt.folderContent)
			}

			_, _, err := ResolveResumeID(id, rawCWD, home, nil)
			var fe *ResumeFolderFileError
			if !errors.As(err, &fe) {
				t.Fatalf("error %v is not a *ResumeFolderFileError", err)
			}
			if fe.Category != fserrors.NotFound {
				t.Errorf("Category = %q, want %q", fe.Category, fserrors.NotFound)
			}
			want := "codemeld: --resume " + id + ": session subdirectory " + sib +
				" is missing or has unreadable folder file: not_found"
			if err.Error() != want {
				t.Errorf("Error() = %q\nwant %q", err.Error(), want)
			}
		})
	}
}

func TestResolveResumeID_MissNoSibling(t *testing.T) {
	home, root, rawCWD, _, _ := resumeEnv(t)
	// A sibling dir exists but does not contain the id, so the scan runs and misses.
	sib, otherCanonical := otherFolderEnv(t, root)
	writeFile(t, filepath.Join(sib, "some-other-id.json"), sessionDoc(otherCanonical, ""))
	id := "sess-missing"

	_, _, err := ResolveResumeID(id, rawCWD, home, nil)
	var nf *ResumeNotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("error %v is not a *ResumeNotFoundError", err)
	}
	if nf.Skipped != 0 {
		t.Errorf("Skipped = %d, want 0", nf.Skipped)
	}
	want := "codemeld: session " + id + " not found in any session directory; " + resumeNoIDHint
	if err.Error() != want {
		t.Errorf("Error() = %q\nwant %q", err.Error(), want)
	}
}

// A non-existent sessions root means no sessions exist anywhere: a clean miss,
// not a enumeration failure.
func TestResolveResumeID_MissNoRoot(t *testing.T) {
	home, _, rawCWD, _, _ := resumeEnv(t)
	id := "sess-fresh"

	_, _, err := ResolveResumeID(id, rawCWD, home, nil)
	var nf *ResumeNotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("error %v is not a *ResumeNotFoundError", err)
	}
	if nf.Skipped != 0 {
		t.Errorf("Skipped = %d, want 0", nf.Skipped)
	}
}

// a per-subdirectory readdir fault skips that subdirectory and, when the
// scan ends without a hit, prepends the warning line naming the count and category.
func TestResolveResumeID_PerSubdirReaddirSkipWarns(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("readdir permission failure is not reproducible as root")
	}
	home, root, rawCWD, _, _ := resumeEnv(t)
	mkdir(t, root)
	// An unreadable sibling (execute-only) is listed by the root readdir but its own
	// readdir fails with EACCES, so it is skipped and retained for the warning.
	blocked := mkdir(t, filepath.Join(root, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-blocked"))
	if err := os.Chmod(blocked, 0o111); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
	id := "sess-skip"

	_, _, err := ResolveResumeID(id, rawCWD, home, nil)
	var nf *ResumeNotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("error %v is not a *ResumeNotFoundError", err)
	}
	if nf.Skipped != 1 || len(nf.Categories) != 1 || nf.Categories[0] != fserrors.PermissionDenied {
		t.Fatalf("Skipped=%d Categories=%v, want 1 skip with permission_denied", nf.Skipped, nf.Categories)
	}
	miss := "codemeld: session " + id + " not found in any session directory; " + resumeNoIDHint
	want := "codemeld: session lookup: 1 session subdirectories could not be inspected (permission_denied)\n" + miss
	if err.Error() != want {
		t.Errorf("Error() = %q\nwant %q", err.Error(), want)
	}
}

// line 1110: a hit suppresses the skipped-subdirectory warning. The
// blocked subdir sorts before the hit subdir so it is skipped first, proving the
// suppression is not merely an ordering artifact.
func TestResolveResumeID_HitSuppressesSkipWarning(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("readdir permission failure is not reproducible as root")
	}
	home, root, rawCWD, _, _ := resumeEnv(t)
	mkdir(t, root)
	blocked := mkdir(t, filepath.Join(root, "0000000000000000000000000000000a-blocked"))
	if err := os.Chmod(blocked, 0o111); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })

	hit := mkdir(t, filepath.Join(root, "ffffffffffffffffffffffffffffffff-hit"))
	id := "sess-hit"
	const recorded = "/recorded/hit/folder"
	writeFile(t, filepath.Join(hit, id+".json"), sessionDoc(recorded, ""))
	writeFile(t, filepath.Join(hit, folderFileName), recorded+"\n")

	_, _, err := ResolveResumeID(id, rawCWD, home, nil)
	var we *ResumeWrongFolderError
	if !errors.As(err, &we) {
		t.Fatalf("error %v is not a *ResumeWrongFolderError (warning must be suppressed on a hit)", err)
	}
	if we.Folder != recorded {
		t.Errorf("Folder = %q, want %q", we.Folder, recorded)
	}
}

// a readdir fault on the sessions root itself (not absence) is fatal —
// the resolver cannot scan, so it exits with the enumerate error. Root is
// execute-only so the expected-path probe still resolves to absent (triggering the
// scan) while the scan's readdir on root fails with EACCES.
func TestResolveResumeID_RootReaddirFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("readdir permission failure is not reproducible as root")
	}
	home, root, rawCWD, _, _ := resumeEnv(t)
	mkdir(t, root)
	if err := os.Chmod(root, 0o111); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })
	id := "sess-enum"

	_, _, err := ResolveResumeID(id, rawCWD, home, nil)
	var ee *ResumeEnumerateError
	if !errors.As(err, &ee) {
		t.Fatalf("error %v is not a *ResumeEnumerateError", err)
	}
	if ee.Category != fserrors.PermissionDenied {
		t.Errorf("Category = %q, want %q", ee.Category, fserrors.PermissionDenied)
	}
	want := "codemeld: session lookup: cannot enumerate ~/.codemeld/sessions/: permission_denied"
	if err.Error() != want {
		t.Errorf("Error() = %q\nwant %q", err.Error(), want)
	}
}
